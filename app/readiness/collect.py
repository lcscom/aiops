"""Redfish → 정규화된 호스트 dict (평가·보고서·저장은 이 dict 만 쓴다 — BMC 원본 응답은 보관하지 않음)

DMTF 표준 스키마를 기본으로 읽고, 벤더 OEM 확장은 '있으면' 보완한다(없으면 미확인으로 남김 — 지어내지 않음).
  Dell iDRAC : Oem.Dell(컨트롤러 모드·DellSwitchConnections LLDP·SEL), HPE iLO : Oem.Hpe(IML), Lenovo XCC, Cisco CIMC, Supermicro, 일반 Redfish
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from .rfclient import RfClient

LOG_SEV = {"critical": "critical", "warning": "warning", "ok": "info"}


def _s(v) -> str:
    return "" if v is None else str(v).strip()


def _i(v) -> int | None:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _f(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _hx(v) -> str:
    """'0x144D' · '144d' · 5197 → '144d'"""
    if v is None or v == "":
        return ""
    if isinstance(v, int):
        return f"{v:04x}"
    s = str(v).strip().lower()
    s = s[2:] if s.startswith("0x") else s
    return s.zfill(4) if re.fullmatch(r"[0-9a-f]{1,4}", s) else ""


def _state(st: dict | None) -> str:
    return _s((st or {}).get("State"))


def _health(st: dict | None) -> str:
    st = st or {}
    return _s(st.get("HealthRollup") or st.get("Health"))


def vendor_of(root: dict, system: dict, manager: dict) -> str:
    t = " ".join([_s(root.get("Vendor")), " ".join((root.get("Oem") or {}).keys()), _s(system.get("Manufacturer")), _s(manager.get("Model"))]).lower()
    for k, v in (("dell", "dell"), ("hpe", "hpe"), ("hewlett", "hpe"), ("lenovo", "lenovo"), ("cisco", "cisco"), ("supermicro", "supermicro"),
                 ("quanta", "quanta"), ("qct", "quanta"), ("gigabyte", "gigabyte"), ("fujitsu", "fujitsu"), ("inspur", "inspur")):
        if k in t:
            return v
    return "generic"


async def collect(c: RfClient, *, sel_limit: int = 200, profile: str = "full") -> dict[str, Any]:
    root = c.cache.get("/redfish/v1") or await c.get("/redfish/v1")
    systems = await c.members(c.link(root, "Systems") or "/redfish/v1/Systems", 8)
    sysj = next((s for s in systems if _s(s.get("SystemType", "Physical")) in ("Physical", "")), systems[0] if systems else {})
    chassis = await c.members(c.link(root, "Chassis") or "/redfish/v1/Chassis", 16)
    managers = await c.members(c.link(root, "Managers") or "/redfish/v1/Managers", 4)
    mgr = next((m for m in managers if _s(m.get("ManagerType")) in ("BMC", "")), managers[0] if managers else {})
    vendor = vendor_of(root, sysj, mgr)
    h: dict[str, Any] = {"vendor": vendor, "redfish_version": _s(root.get("RedfishVersion")), "errors": {}}
    h["system"] = {
        "manufacturer": _s(sysj.get("Manufacturer")), "model": _s(sysj.get("Model")), "sku": _s(sysj.get("SKU")), "serial": _s(sysj.get("SerialNumber")),
        "uuid": _s(sysj.get("UUID")).lower(), "bios_version": _s(sysj.get("BiosVersion")), "power": _s(sysj.get("PowerState")),
        "health": _health(sysj.get("Status")), "hostname": _s(sysj.get("HostName")),
        "boot_mode": _s((sysj.get("Boot") or {}).get("BootSourceOverrideMode")),
        "cpu_count": _i((sysj.get("ProcessorSummary") or {}).get("Count")), "mem_gib": _f((sysj.get("MemorySummary") or {}).get("TotalSystemMemoryGiB")),
    }
    tpm = [t for t in (sysj.get("TrustedModules") or []) if isinstance(t, dict)]
    h["tpm"] = [{"type": _s(t.get("InterfaceType") or t.get("ModuleType")), "fw": _s(t.get("FirmwareVersion")), "state": _state(t.get("Status")),
                 "health": _health(t.get("Status"))} for t in tpm]
    jobs = {
        "cpus": _cpus(c, sysj), "dimms": _dimms(c, sysj), "storage": _storage(c, sysj, chassis, vendor), "pcie": _pcie(c, sysj, chassis),
        "nics": _nics(c, sysj, chassis, vendor), "power": _power(c, chassis), "thermal": _thermal(c, chassis),
        "bios": _bios(c, sysj, vendor), "secureboot": _secureboot(c, sysj), "bmc": _bmc(c, root, mgr, vendor),
        "firmware": _firmware(c, root) if profile == "full" else _none(),
        "sel": _sel(c, sysj, mgr, vendor, sel_limit),
    }
    res = await asyncio.gather(*jobs.values(), return_exceptions=True)
    for k, v in zip(jobs, res):
        if isinstance(v, Exception):
            h[k] = [] if k not in ("bios", "secureboot", "bmc", "power", "thermal") else {}
            h["errors"][k] = f"{type(v).__name__}: {v}"[:200]
        else:
            h[k] = v
    if h["system"]["boot_mode"] == "" and isinstance(h.get("bios"), dict):
        bm = (h["bios"].get("attributes") or {})
        for key in ("BootMode", "BootModeSetting", "BootModeSelect", "SystemBootMode"):
            if key in bm:
                h["system"]["boot_mode"] = _s(bm[key])
                break
    h["chassis"] = [{"id": _s(x.get("Id")), "type": _s(x.get("ChassisType")), "model": _s(x.get("Model")), "serial": _s(x.get("SerialNumber")),
                     "part": _s(x.get("PartNumber")), "location": _s(((x.get("Location") or {}).get("PartLocation") or {}).get("ServiceLabel"))} for x in chassis[:4]]
    h["errors"].update({k: v for k, v in list(c.errors.items())[:30]})
    h["requests"] = c.count
    return h


async def _none():
    return []


async def _cpus(c: RfClient, s: dict) -> list[dict]:
    out = []
    for p in await c.members(c.link(s, "Processors"), 16):
        if _s(p.get("ProcessorType") or "CPU") not in ("CPU", "") or _state(p.get("Status")) == "Absent":
            continue
        pid = p.get("ProcessorId") or {}
        out.append({"socket": _s(p.get("Socket") or p.get("Id")), "model": _s(p.get("Model")), "manufacturer": _s(p.get("Manufacturer")),
                    "cores": _i(p.get("TotalCores")), "threads": _i(p.get("TotalThreads")), "max_mhz": _i(p.get("MaxSpeedMHz")),
                    "family": _s(pid.get("EffectiveFamily")), "model_id": _s(pid.get("EffectiveModel")), "step": _s(pid.get("Step")),
                    "health": _health(p.get("Status"))})
    return out


def _dimm_loc(m: dict) -> dict:
    loc = m.get("MemoryLocation") or {}
    dl = _s(m.get("DeviceLocator") or m.get("Name") or m.get("Id"))
    sock, ch, slot = _i(loc.get("Socket")), _s(loc.get("Channel")), _s(loc.get("Slot"))
    if sock is None:                                     # 'CPU1_DIMM_A1' · 'DIMM.Socket.A1' · 'PROC 1 DIMM 3'
        mm = re.search(r"(?:CPU|PROC|P)\s*_?(\d+)", dl, re.I)
        sock = int(mm.group(1)) if mm else None
        if sock is None:
            mm = re.search(r"Socket\.([A-Z])(\d+)", dl)
            if mm:
                sock = ord(mm.group(1)) - 64
    if not ch:
        mm = re.search(r"DIMM[_ .-]?([A-P])(\d+)", dl, re.I) or re.search(r"\.([A-P])(\d+)$", dl)
        if mm:
            ch, slot = mm.group(1).upper(), slot or mm.group(2)
    return {"socket": sock, "channel": ch, "slot": slot, "controller": _s(loc.get("MemoryController")), "locator": dl}


async def _dimms(c: RfClient, s: dict) -> list[dict]:
    out = []
    for m in await c.members(c.link(s, "Memory"), 96):
        absent = _state(m.get("Status")) == "Absent" or not (m.get("CapacityMiB") or 0)
        allowed = [x for x in (m.get("AllowedSpeedsMHz") or []) if isinstance(x, (int, float))]
        rated = max(allowed) if allowed else None
        out.append({**_dimm_loc(m), "present": not absent, "size_gib": round((m.get("CapacityMiB") or 0) / 1024, 1),
                    "type": _s(m.get("MemoryDeviceType")), "speed": _i(m.get("OperatingSpeedMhz")), "rated": rated, "ranks": _i(m.get("RankCount")),
                    "manufacturer": _s(m.get("Manufacturer")), "part": _s(m.get("PartNumber")).strip(), "ecc": _s(m.get("ErrorCorrection")),
                    "health": _health(m.get("Status"))})
    return out


def _ctrl_mode(sc: dict, st: dict, vendor: str) -> str:
    dell = ((st.get("Oem") or {}).get("Dell") or {}).get("DellController") or ((sc.get("Oem") or {}).get("Dell") or {}).get("DellController") or {}
    m = _s(dell.get("CurrentControllerMode") or dell.get("PersonalityMode"))
    if m:
        return m
    hpe = (sc.get("Oem") or {}).get("Hpe") or {}
    if hpe.get("ControllerMode"):
        return _s(hpe["ControllerMode"])
    model = (_s(sc.get("Model")) + " " + _s(st.get("Name"))).lower()
    if re.search(r"\bhba\b|hba3|hba4|hba5|pass-?through|it mode|\bahci\b", model):
        return "HBA"
    if re.search(r"perc|smart ?array|raid|megaraid|mr9|9[0-9]{3}-\d+i", model):
        return "RAID"
    return ""


async def _storage(c: RfClient, s: dict, chassis: list[dict], vendor: str) -> dict:
    ctrls, drives = [], []
    for st in await c.members(c.link(s, "Storage"), 24):
        scs = list(st.get("StorageControllers") or [])
        if not scs and c.link(st, "Controllers"):
            scs = await c.members(c.link(st, "Controllers"), 8)
        for sc in scs[:4]:
            pci = sc.get("PCIeInterface") or {}
            ctrls.append({"id": _s(st.get("Id")), "name": _s(sc.get("Name") or st.get("Name")), "model": _s(sc.get("Model")),
                          "fw": _s(sc.get("FirmwareVersion")), "protocols": [_s(x) for x in sc.get("SupportedDeviceProtocols") or sc.get("SupportedControllerProtocols") or []],
                          "mode": _ctrl_mode(sc, st, vendor), "speed_gbps": _f(sc.get("SpeedGbps")), "pcie_lanes": _i(pci.get("LanesInUse")),
                          "health": _health(sc.get("Status") or st.get("Status"))})
        for d in await asyncio.gather(*(c.get(r.get("@odata.id")) for r in (st.get("Drives") or [])[:64] if isinstance(r, dict))):
            if not d or _state(d.get("Status")) == "Absent":
                continue
            ids = {}
            fns = ((d.get("Links") or {}).get("PCIeFunctions") or [])
            if fns:
                f = await c.get(fns[0].get("@odata.id"))
                ids = {"vid": _hx(f.get("VendorId")), "did": _hx(f.get("DeviceId")), "svid": _hx(f.get("SubsystemVendorId")), "ssid": _hx(f.get("SubsystemId"))}
            life = d.get("PredictedMediaLifeLeftPercent")
            drives.append({"ctrl": _s(st.get("Id")), "name": _s(d.get("Name") or d.get("Id")), "model": _s(d.get("Model")), "manufacturer": _s(d.get("Manufacturer")),
                           "serial": _s(d.get("SerialNumber")), "fw": _s(d.get("Revision") or d.get("FirmwareVersion")),
                           "protocol": _s(d.get("Protocol")), "media": _s(d.get("MediaType")), "capacity_gb": round((d.get("CapacityBytes") or 0) / 1e9, 1),
                           "life_left": _f(life), "endurance": _s(((d.get("Oem") or {}).get("Dell") or {}).get("DellPhysicalDisk", {}).get("EnduranceRating") or ""),
                           "form": _s(d.get("FormFactor")), "health": _health(d.get("Status")), "failure_predicted": bool(d.get("FailurePredicted")), **ids})
    return {"controllers": ctrls, "drives": drives}


async def _pcie(c: RfClient, s: dict, chassis: list[dict]) -> list[dict]:
    refs = list(s.get("PCIeDevices") or [])
    if not refs:
        for ch in chassis[:2]:
            refs += (await c.get(c.link(ch, "PCIeDevices"))).get("Members") or []
    out, seen = [], set()
    for ref in refs[:80]:
        dev = await c.get(ref.get("@odata.id") if isinstance(ref, dict) else None)
        if not dev:
            continue
        fns = []
        fl = (dev.get("PCIeFunctions") or {})
        if isinstance(fl, dict) and fl.get("@odata.id"):
            fns = await c.members(fl["@odata.id"], 8)
        else:
            for fr in ((dev.get("Links") or {}).get("PCIeFunctions") or [])[:8]:
                fj = await c.get(fr.get("@odata.id"))
                if fj:
                    fns.append(fj)
        iface = dev.get("PCIeInterface") or {}
        for f in fns[:1] or [{}]:
            key = (_s(dev.get("Id")), _s(f.get("Id")))
            if key in seen:
                continue
            seen.add(key)
            out.append({"id": _s(dev.get("Id")), "name": _s(dev.get("Name")), "model": _s(dev.get("Model")), "manufacturer": _s(dev.get("Manufacturer")),
                        "fw": _s(dev.get("FirmwareVersion")), "class": _s(f.get("DeviceClass")), "vid": _hx(f.get("VendorId")), "did": _hx(f.get("DeviceId")),
                        "svid": _hx(f.get("SubsystemVendorId")), "ssid": _hx(f.get("SubsystemId")), "slot": _s(((dev.get("Slot") or {}).get("Location") or {}).get("PartLocation", {}).get("ServiceLabel") if isinstance(dev.get("Slot"), dict) else ""),
                        "gen": _s(iface.get("PCIeType")), "lanes": _i(iface.get("LanesInUse")), "max_lanes": _i(iface.get("MaxLanes")),
                        "health": _health(dev.get("Status"))})
    return out


async def _nics(c: RfClient, s: dict, chassis: list[dict], vendor: str) -> list[dict]:
    """NetworkAdapters(Ports·NetworkPorts) + LLDP(Port.Ethernet.LLDPReceive / Dell DellSwitchConnections)"""
    ports: list[dict] = []
    for ch in chassis[:2]:
        for ad in await c.members(c.link(ch, "NetworkAdapters"), 16):
            ctl = (ad.get("Controllers") or [{}])[0] if ad.get("Controllers") else {}
            base = {"adapter": _s(ad.get("Id")), "model": _s(ad.get("Model") or ad.get("Name")), "manufacturer": _s(ad.get("Manufacturer")),
                    "fw": _s(ctl.get("FirmwarePackageVersion")), "part": _s(ad.get("PartNumber"))}
            plist = await c.members(c.link(ad, "Ports"), 16) if c.link(ad, "Ports") else []
            if plist:
                for p in plist:
                    eth = p.get("Ethernet") or {}
                    lldp = eth.get("LLDPReceive") or {}
                    sp = _f(p.get("CurrentSpeedGbps"))
                    mx = _f(p.get("MaxSpeedGbps"))
                    ports.append({**base, "port": _s(p.get("Id")), "link": _s(p.get("LinkStatus")), "speed_gbps": sp, "max_gbps": mx,
                                  "mac": _s((eth.get("AssociatedMACAddresses") or [""])[0]), "medium": _s(p.get("PortMedium")),
                                  "lldp": _lldp(lldp)})
            else:
                for p in await c.members(c.link(ad, "NetworkPorts"), 16):
                    sp = _f(p.get("CurrentLinkSpeedMbps"))
                    caps = [_f(x.get("LinkSpeedMbps")) for x in p.get("SupportedLinkCapabilities") or [] if isinstance(x, dict)]
                    caps = [x for x in caps if x]
                    ports.append({**base, "port": _s(p.get("PhysicalPortNumber") or p.get("Id")), "link": _s(p.get("LinkStatus")),
                                  "speed_gbps": sp / 1000 if sp else None, "max_gbps": max(caps) / 1000 if caps else None,
                                  "mac": _s((p.get("AssociatedNetworkAddresses") or [""])[0]), "medium": "", "lldp": {}, "fqdd": _s(p.get("Id"))})
    if vendor == "dell":                             # iDRAC: LLDP 이웃 = DellSwitchConnections(FQDD 로 포트 연결)
        sid = _s(s.get("Id")) or "System.Embedded.1"
        sw = await c.members(f"/redfish/v1/Systems/{sid}/NetworkPorts/Oem/Dell/DellSwitchConnections", 64)
        by = {}
        for x in sw:
            fq = _s(x.get("FQDD") or x.get("Id"))
            if _s(x.get("SwitchConnectionID")) not in ("", "No Link", "Not Supported"):
                by[fq] = {"chassis_id": _s(x.get("SwitchConnectionID")), "port_id": _s(x.get("SwitchPortConnectionID")), "system_name": "", "mgmt_ip": ""}
        for p in ports:
            fq = p.get("fqdd") or ""
            for k, v in by.items():
                if k and (k == fq or k.startswith(p["adapter"]) and k.endswith(f"-{p['port']}") or k.endswith(f"{p['adapter']}-{p['port']}-1")):
                    p["lldp"] = p["lldp"] or v
    if not ports:                                    # NetworkAdapters 미지원 → EthernetInterfaces(속도·링크만)
        for e in await c.members(c.link(s, "EthernetInterfaces"), 32):
            sp = _f(e.get("SpeedMbps"))
            ports.append({"adapter": _s(e.get("Id")), "model": _s(e.get("Name")), "manufacturer": "", "fw": "", "part": "", "port": _s(e.get("Id")),
                          "link": _s(e.get("LinkStatus")), "speed_gbps": sp / 1000 if sp else None, "max_gbps": None, "mac": _s(e.get("MACAddress")),
                          "medium": "", "lldp": {}})
    return ports


def _lldp(l: dict) -> dict:
    if not l:
        return {}
    d = {"chassis_id": _s(l.get("ChassisId")), "port_id": _s(l.get("PortId")), "system_name": _s(l.get("SystemName")),
         "mgmt_ip": _s(l.get("ManagementAddressIPv4") or l.get("ManagementAddressIPv6")), "vlan": _i(l.get("ManagementVlanId"))}
    return d if (d["chassis_id"] or d["system_name"]) else {}


async def _power(c: RfClient, chassis: list[dict]) -> dict:
    psus, consumed, cap, redund = [], None, None, ""
    for ch in chassis[:2]:
        pw = await c.get(c.link(ch, "Power"))
        if pw:
            for p in pw.get("PowerSupplies") or []:
                if _state(p.get("Status")) == "Absent":
                    continue
                psus.append({"name": _s(p.get("Name") or p.get("MemberId")), "watts": _f(p.get("PowerCapacityWatts")), "model": _s(p.get("Model")),
                             "fw": _s(p.get("FirmwareVersion")), "health": _health(p.get("Status")), "input_v": _f(p.get("LineInputVoltage"))})
            for pc in pw.get("PowerControl") or []:
                consumed = consumed if consumed is not None else _f(pc.get("PowerConsumedWatts"))
                lim = (pc.get("PowerLimit") or {}).get("LimitInWatts")
                cap = cap if cap is not None else _f(lim)
            for r in pw.get("Redundancy") or []:
                redund = redund or f"{_s(r.get('Mode'))} {_health(r.get('Status'))}".strip()
        elif c.link(ch, "PowerSubsystem"):
            ps = await c.get(c.link(ch, "PowerSubsystem"))
            for p in await c.members(c.link(ps, "PowerSupplies"), 8):
                psus.append({"name": _s(p.get("Name") or p.get("Id")), "watts": _f(p.get("PowerCapacityWatts")), "model": _s(p.get("Model")),
                             "fw": _s(p.get("FirmwareVersion")), "health": _health(p.get("Status")), "input_v": None})
            for r in ps.get("PowerSupplyRedundancy") or []:
                redund = redund or f"{_s(r.get('RedundancyType'))} {_health(r.get('Status'))}".strip()
        if psus:
            break
    return {"psus": psus, "consumed_w": consumed, "cap_w": cap, "redundancy": redund}


async def _thermal(c: RfClient, chassis: list[dict]) -> dict:
    temps, fans = [], []
    for ch in chassis[:1]:
        th = await c.get(c.link(ch, "Thermal"))
        for t in th.get("Temperatures") or []:
            if _state(t.get("Status")) in ("Absent", "Disabled") or t.get("ReadingCelsius") is None:
                continue
            temps.append({"name": _s(t.get("Name")), "c": _f(t.get("ReadingCelsius")), "warn": _f(t.get("UpperThresholdNonCritical")),
                          "crit": _f(t.get("UpperThresholdCritical")), "health": _health(t.get("Status"))})
        for f in th.get("Fans") or []:
            if _state(f.get("Status")) == "Absent":
                continue
            fans.append({"name": _s(f.get("Name") or f.get("FanName")), "rpm": _f(f.get("Reading")), "health": _health(f.get("Status"))})
    return {"temps": temps[:40], "fans": fans[:24]}


async def _bios(c: RfClient, s: dict, vendor: str) -> dict:
    b = await c.get(c.link(s, "Bios"))
    attrs = {k: v for k, v in (b.get("Attributes") or {}).items() if isinstance(v, (str, int, float, bool)) and not re.search(r"(?i)pass(word)?|pwd|secret|key$", k)}
    return {"attributes": attrs, "registry": _s(b.get("AttributeRegistry"))}


async def _secureboot(c: RfClient, s: dict) -> dict:
    sb = await c.get(c.link(s, "SecureBoot"))
    if not sb:
        return {}
    return {"enable": sb.get("SecureBootEnable"), "current": _s(sb.get("SecureBootCurrentBoot")), "mode": _s(sb.get("SecureBootMode"))}


async def _bmc(c: RfClient, root: dict, mgr: dict, vendor: str) -> dict:
    np_ = await c.get(c.link(mgr, "NetworkProtocol"))
    proto = {}
    for k in ("HTTP", "HTTPS", "IPMI", "SSH", "Telnet", "SNMP", "SSDP", "KVMIP", "VirtualMedia", "NTP", "DHCP", "RDP", "RFB"):
        v = np_.get(k)
        if isinstance(v, dict):
            proto[k] = {"enabled": v.get("ProtocolEnabled"), "port": _i(v.get("Port"))}
    snmp = np_.get("SNMP") or {}
    ntp = np_.get("NTP") or {}
    acc = await c.get(c.link(root, "AccountService") or "/redfish/v1/AccountService")
    accounts = []
    for a in await c.members(c.link(acc, "Accounts"), 32):
        un = _s(a.get("UserName"))
        if not un and not a.get("Enabled"):
            continue
        accounts.append({"user": un, "enabled": a.get("Enabled"), "role": _s(a.get("RoleId")), "locked": a.get("Locked"),
                         "password_change_required": a.get("PasswordChangeRequired"), "types": a.get("AccountTypes") or []})
    ss = await c.get(c.link(root, "SessionService") or "/redfish/v1/SessionService")
    certs = []
    cs = await c.get(c.link(root, "CertificateService"))
    if cs:
        loc = await c.get(c.link(cs, "CertificateLocations"))
        for ref in ((loc.get("Links") or {}).get("Certificates") or [])[:6]:
            cj = await c.get(ref.get("@odata.id"))
            if cj:
                certs.append({"subject": (cj.get("Subject") or {}).get("CommonName", ""), "issuer": (cj.get("Issuer") or {}).get("CommonName", ""),
                              "not_after": _s(cj.get("ValidNotAfter")), "key_usage": cj.get("KeyUsage") or [],
                              "self_signed": (cj.get("Subject") or {}) == (cj.get("Issuer") or {}) and bool(cj.get("Subject"))})
    ifaces = await c.members(c.link(mgr, "EthernetInterfaces"), 4)
    lic = []
    if vendor == "dell":
        for l in await c.members("/redfish/v1/LicenseService/Licenses", 8):
            lic.append(_s(l.get("Description") or l.get("Name")))
    dell_attrs = {}
    if vendor == "dell":
        a = await c.get(f"{(mgr.get('@odata.id') or '/redfish/v1/Managers/iDRAC.Embedded.1')}/Attributes")
        keep = ("IPMILan.1.Enable", "IPMILan.1.EncryptionKey", "SSH.1.Enable", "Telnet.1.Enable", "WebServer.1.TLSProtocol", "WebServer.1.SSLEncryptionBitLength",
                "Lockdown.1.SystemLockdown", "RACADM.1.Enable", "SNMP.1.AgentEnable", "SNMP.1.SNMPProtocol", "Users.2.UserName", "IPBlocking.1.BlockEnable",
                "WebServer.1.HostHeaderCheck", "SerialRedirection.1.Enable", "VNCServer.1.Enable", "Security.1.PasswordMinimumLength", "OS-BMC.1.AdminState",
                "IPv4.1.DHCPEnable", "Time.1.Timezone", "WebServer.1.HttpsRedirection", "NIC.1.Selection", "NIC.1.VLanEnable", "NIC.1.VLanID", "NTPConfigGroup.1.NTPEnable", "SysLog.1.SysLogEnable", "RemoteHosts.1.SMTPServerIPAddress")
        dell_attrs = {k: v for k, v in (a.get("Attributes") or {}).items() if k in keep and k != "IPMILan.1.EncryptionKey"}
        if (a.get("Attributes") or {}).get("IPMILan.1.EncryptionKey") is not None:
            dell_attrs["IPMILan.1.EncryptionKeyDefault"] = str((a.get("Attributes") or {}).get("IPMILan.1.EncryptionKey", "")).strip("0") == ""
    return {"model": _s(mgr.get("Model")), "fw": _s(mgr.get("FirmwareVersion")), "health": _health(mgr.get("Status")),
            "datetime": _s(mgr.get("DateTime")), "protocols": proto,
            "snmp": {"v1": snmp.get("EnableSNMPv1"), "v2c": snmp.get("EnableSNMPv2c"), "v3": snmp.get("EnableSNMPv3"),
                     "community_default": snmp.get("CommunityAccessMode") in ("Full",) or None},
            "ntp_servers": [x for x in (ntp.get("NTPServers") or []) if x], "accounts": accounts,
            "policy": {"min_pw": _i(acc.get("MinPasswordLength")), "max_pw": _i(acc.get("MaxPasswordLength")), "lockout_threshold": _i(acc.get("AccountLockoutThreshold")),
                       "lockout_duration": _i(acc.get("AccountLockoutDuration")), "ldap": bool((acc.get("LDAP") or {}).get("ServiceEnabled")),
                       "ad": bool((acc.get("ActiveDirectory") or {}).get("ServiceEnabled")),
                       "mfa": any(bool((v or {}).get("Enabled")) for v in (acc.get("MultiFactorAuth") or {}).values() if isinstance(v, dict)),
                       "pw_expiry_days": _i(acc.get("PasswordExpirationDays"))},
            "session_timeout": _i(ss.get("SessionTimeout")), "certificates": certs,
            "ifaces": [{"mac": _s(i.get("MACAddress")), "dhcp": ((i.get("DHCPv4") or {}).get("DHCPEnabled")),
                        "ipv4": [_s(a.get("Address")) for a in i.get("IPv4Addresses") or [] if isinstance(a, dict)], "vlan": (i.get("VLAN") or {}).get("VLANEnable"),
                        "speed": _i(i.get("SpeedMbps"))} for i in ifaces],
            "licenses": lic, "oem": dell_attrs}


async def _firmware(c: RfClient, root: dict) -> list[dict]:
    us = await c.get(c.link(root, "UpdateService") or "/redfish/v1/UpdateService")
    out = []
    for f in await c.members(c.link(us, "FirmwareInventory"), 200):
        if _state(f.get("Status")) == "Absent":
            continue
        nm = _s(f.get("Name") or f.get("Id"))
        if re.match(r"(?i)^(previous|installed)-", _s(f.get("Id"))) and _s(f.get("Id")).lower().startswith("previous"):
            continue
        out.append({"name": nm, "version": _s(f.get("Version")), "updateable": f.get("Updateable"), "date": _s(f.get("ReleaseDate"))})
    return out


async def _sel(c: RfClient, s: dict, mgr: dict, vendor: str, limit: int) -> list[dict]:
    """SEL·IML·Lifecycle 로그 — 최근 limit 건(경고·위험 우선은 평가에서)"""
    svcs = []
    for parent in (mgr, s):
        for ls in await c.members(c.link(parent, "LogServices"), 8):
            nm = (_s(ls.get("Id")) + " " + _s(ls.get("Name"))).lower()
            if any(k in nm for k in ("sel", "iml", "event", "lclog", "audit", "log1", "faultlist")):
                svcs.append(ls)
    out = []
    for ls in svcs[:3]:
        ent = await c.get(c.link(ls, "Entries"))
        for e in (ent.get("Members") or [])[:limit]:
            if not isinstance(e, dict):
                continue
            sev = _s(e.get("Severity") or e.get("MessageSeverity")).lower()
            out.append({"svc": _s(ls.get("Id")), "id": _s(e.get("Id")), "ts": _s(e.get("Created")), "severity": LOG_SEV.get(sev, sev or "info"),
                        "message": _s(e.get("Message"))[:400], "message_id": _s(e.get("MessageId")), "sensor": _s(e.get("SensorType")),
                        "code": _s(((e.get("Oem") or {}).get("Hpe") or {}).get("Code") or "")})
    out.sort(key=lambda x: x["ts"], reverse=True)
    return out[:limit]
