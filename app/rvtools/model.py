"""RVTools 시트 → 정규화 인벤토리 + 기존 엔진 입력 형식으로 변환

변환 대상(기존 로직 그대로 재사용)
  · vCenter 커넥터 topology  → stack.build(물리→논리 구성도)
  · vcheck 스냅숏            → vcheck.evaluate(인프라 상세 점검 Compute·Storage·Network·Hardware)
  · 보안 판독 inventory      → assess.hardening(KISA 하이퍼바이저 항목) + assess.evaluate(VMSA 빌드 판정)
RVTools 에 없는 값(서비스 상태·고급 설정·잠금 모드·센서 등)은 비워 두어 기존 규칙이 '미수집(MANUAL)'으로 처리하게 한다 — 지어내지 않는다.
여러 vCenter 를 한 파일에 내보낸 경우 VI SDK Server 기준으로 나눈다.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

SHEETS_REQUIRED = {"vInfo", "vHost"}


def b(v) -> bool | None:
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    return True if s in ("true", "yes", "1") else (False if s in ("false", "no", "0") else None)


def n(v, default=None):
    if v is None or v == "":
        return default
    if isinstance(v, (int, float)):
        return v
    try:
        x = float(str(v).replace(",", ""))
        return int(x) if x.is_integer() else x
    except ValueError:
        return default


def ts(v) -> float | None:
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, str) and re.match(r"\d{4}-\d\d-\d\d", v):
        try:
            return datetime.fromisoformat(v.replace("/", "-")[:19]).timestamp()
        except ValueError:
            return None
    return None


def s(v) -> str:
    return "" if v is None else (v.strftime("%Y-%m-%d %H:%M") if isinstance(v, datetime) else str(v).strip())


def vc_of(r: dict) -> str:
    return s(r.get("VI SDK Server")) or "vcenter"


def normalize(sh: dict[str, list[dict]]) -> dict[str, Any]:
    missing = SHEETS_REQUIRED - set(sh)
    if missing:
        raise ValueError(f"RVTools 시트가 없습니다: {', '.join(sorted(missing))} — RVTools 'Export all to xlsx' 파일인지 확인")
    meta = (sh.get("vMetaData") or [{}])[0]
    inv: dict[str, Any] = {"meta": {"rvtools": s(meta.get("RVTools version")), "exported": ts(meta.get("xlsx creation datetime")),
                                    "server": s(meta.get("Server"))},
                           "vcenters": {}, "clusters": {}, "hosts": {}, "vms": {}, "datastores": {}, "networks": {}, "dvswitches": {},
                           "vswitches": [], "portgroups": [], "vmks": [], "pnics": [], "hbas": [], "paths": [], "licenses": [], "health": [],
                           "snapshots": [], "partitions": [], "disks": [], "cds": [], "rps": []}
    for r in sh.get("vSource") or []:
        inv["vcenters"][vc_of(r)] = {"name": vc_of(r), "fullname": s(r.get("Fullname")), "version": s(r.get("Version")), "build": s(r.get("Build")),
                                     "api": s(r.get("API version")), "patch": s(r.get("Patch level"))}
    for r in sh.get("vCluster") or []:
        inv["clusters"][s(r.get("Name"))] = {
            "name": s(r.get("Name")), "vcenter": vc_of(r), "status": s(r.get("OverallStatus")), "hosts": n(r.get("NumHosts"), 0), "eff_hosts": n(r.get("numEffectiveHosts"), 0),
            "cores": n(r.get("NumCpuCores"), 0), "threads": n(r.get("NumCpuThreads"), 0), "cpu_mhz": n(r.get("TotalCpu"), 0), "eff_cpu_mhz": n(r.get("Effective Cpu"), 0),
            "mem_mb": n(r.get("TotalMemory"), 0), "eff_mem_mb": n(r.get("Effective Memory"), 0), "ha": b(r.get("HA enabled")), "ha_admission": b(r.get("AdmissionControlEnabled")),
            "ha_failover_level": n(r.get("Failover Level"), 0), "host_monitoring": s(r.get("Host monitoring")), "isolation": s(r.get("Isolation Response")),
            "vm_monitoring": s(r.get("VM Monitoring")), "drs": b(r.get("DRS enabled")), "drs_behavior": s(r.get("DRS default VM behavior")),
            "dpm": b(r.get("DPM enabled")), "vmotions": n(r.get("Num VMotions"), 0)}
    for r in sh.get("vHost") or []:
        hn = s(r.get("Host"))
        ver = s(r.get("ESX Version"))
        m = re.search(r"(\d+\.\d+\.\d+)\s+build-(\d+)", ver)
        inv["hosts"][hn] = {
            "name": hn, "vcenter": vc_of(r), "datacenter": s(r.get("Datacenter")), "cluster": s(r.get("Cluster")), "status": s(r.get("Config status")),
            "maintenance": b(r.get("in Maintenance Mode")), "quarantine": b(r.get("in Quarantine Mode")), "cpu_model": s(r.get("CPU Model")),
            "cpu_mhz": n(r.get("Speed"), 0), "ht_available": b(r.get("HT Available")), "ht_active": b(r.get("HT Active")), "sockets": n(r.get("# CPU"), 0),
            "cores_per_cpu": n(r.get("Cores per CPU"), 0), "cores": n(r.get("# Cores"), 0) or (n(r.get("# CPU"), 0) * n(r.get("Cores per CPU"), 0)),
            "cpu_pct": n(r.get("CPU usage %")), "mem_mb": n(r.get("# Memory"), 0), "mem_pct": n(r.get("Memory usage %")), "nics": n(r.get("# NICs"), 0),
            "hba_count": n(r.get("# HBAs"), 0), "vms": n(r.get("# VMs"), 0), "vms_total": n(r.get("# VMs total"), 0), "vcpus": n(r.get("# vCPUs"), 0),
            "vcpu_per_core": n(r.get("vCPUs per Core")), "vram_mb": n(r.get("vRAM"), 0), "swapped": n(r.get("VM Memory Swapped"), 0),
            "ballooned": n(r.get("VM Memory Ballooned"), 0), "evc": s(r.get("Current EVC")), "max_evc": s(r.get("Max EVC")),
            "license": s(r.get("Assigned License(s)")), "power_policy": s(r.get("Host Power Policy")) or s(r.get("Current CPU power man. policy")),
            "esx": ver, "version": m.group(1) if m else "", "build": m.group(2) if m else "", "boot_time": ts(r.get("Boot time")),
            "dns": s(r.get("DNS Servers")), "ntp": [x.strip() for x in s(r.get("NTP Server(s)")).split(",") if x.strip()], "ntpd": b(r.get("NTPD running")),
            "timezone": s(r.get("Time Zone Name")), "vendor": s(r.get("Vendor")), "model": s(r.get("Model")), "serial": s(r.get("Serial number")),
            "service_tag": s(r.get("Service tag")), "bios_vendor": s(r.get("BIOS Vendor")), "bios": s(r.get("BIOS Version")), "bios_date": s(r.get("BIOS Date"))[:10],
            "cert_issuer": s(r.get("Certificate Issuer")), "cert_expiry": ts(r.get("Certificate Expiry Date")), "cert_status": s(r.get("Certificate Status")),
            "uuid": s(r.get("UUID")).lower(), "vsan_fd": s(r.get("vSAN Fault Domain Name"))}
    tools = {(vc_of(r), s(r.get("VM"))): r for r in sh.get("vTools") or []}
    cpu = {(vc_of(r), s(r.get("VM"))): r for r in sh.get("vCPU") or []}
    mem = {(vc_of(r), s(r.get("VM"))): r for r in sh.get("vMemory") or []}
    for r in sh.get("vInfo") or []:
        vn = s(r.get("VM"))
        k = (vc_of(r), vn)
        t, c, me = tools.get(k, {}), cpu.get(k, {}), mem.get(k, {})
        nets = [s(r.get(f"Network #{i}")) for i in range(1, 9) if s(r.get(f"Network #{i}"))]
        inv["vms"][vn if vn not in inv["vms"] else f"{vn} ({vc_of(r)})"] = {
            "name": vn, "vcenter": vc_of(r), "datacenter": s(r.get("Datacenter")), "cluster": s(r.get("Cluster")), "host": s(r.get("Host")),
            "folder": s(r.get("Folder")), "rp": s(r.get("Resource pool")), "power": s(r.get("Powerstate")), "template": bool(b(r.get("Template"))),
            "srm_placeholder": bool(b(r.get("SRM Placeholder"))), "status": s(r.get("Config status")), "guest_state": s(r.get("Guest state")),
            "heartbeat": s(r.get("Heartbeat")), "consolidation": bool(b(r.get("Consolidation Needed"))), "power_on": ts(r.get("PowerOn")),
            "created": ts(r.get("Creation date")), "vcpu": n(r.get("CPUs"), 0), "cpu_ready": n(r.get("Overall Cpu Readiness")), "mem_mb": n(r.get("Memory"), 0),
            "active_mem_mb": n(r.get("Active Memory")), "nics": n(r.get("NICs"), 0), "disks": n(r.get("Disks"), 0),
            "disk_mib": n(r.get("Total disk capacity MiB"), 0), "prov_mib": n(r.get("Provisioned MiB"), 0), "used_mib": n(r.get("In Use MiB"), 0),
            "ip": s(r.get("Primary IP Address")), "dns": s(r.get("DNS Name")), "networks": nets, "ha_priority": s(r.get("HA Restart Priority")),
            "ft": s(r.get("FT State")), "cbt": b(r.get("CBT")), "secure_boot": b(r.get("EFI Secure boot")), "firmware": s(r.get("Firmware")),
            "hw": s(r.get("HW version")) or s(t.get("VM Version")), "hw_upgrade": s(r.get("HW upgrade status")), "evc_req": s(r.get("min Required EVC Mode Key")),
            "latency": s(r.get("Latency Sensitivity")), "os_cfg": s(r.get("OS according to the configuration file")),
            "os_tools": s(r.get("OS according to the VMware Tools")), "annotation": s(r.get("Annotation"))[:200], "uuid": s(r.get("VM UUID")),
            "moid": s(r.get("VM ID")), "path": s(r.get("Path")), "backup": s(r.get("NB_LAST_BACKUP")),
            "tools": s(t.get("Tools")), "tools_ver": s(t.get("Tools Version")), "tools_req": s(t.get("Required Version")), "tools_upgradeable": b(t.get("Upgradeable")),
            "tools_policy": s(t.get("Upgrade Policy")), "tools_sync": b(t.get("Sync time")),
            "sockets": n(c.get("Sockets")), "cores_ps": n(c.get("Cores p/s")), "cpu_limit": n(c.get("Limit")), "cpu_res": n(c.get("Reservation")),
            "cpu_hotadd": b(c.get("Hot Add")), "mem_limit": n(me.get("Limit")), "mem_res": n(me.get("Reservation")), "mem_hotadd": b(me.get("Hot Add")),
            "ballooned": n(me.get("Ballooned"), 0), "swapped": n(me.get("Swapped"), 0), "consumed_mb": n(me.get("Consumed")), "mem_active_mb": n(me.get("Active"))}
    for r in sh.get("vDatastore") or []:
        dn = s(r.get("Name"))
        inv["datastores"][dn] = {
            "name": dn, "vcenter": vc_of(r), "type": s(r.get("Type")), "accessible": b(r.get("Accessible")), "status": s(r.get("Config status")),
            "cap_mib": n(r.get("Capacity MiB"), 0), "prov_mib": n(r.get("Provisioned MiB"), 0), "used_mib": n(r.get("In Use MiB"), 0), "free_mib": n(r.get("Free MiB"), 0),
            "free_pct": n(r.get("Free %")), "vms": n(r.get("# VMs"), 0), "hosts": [x.strip() for x in s(r.get("Hosts")).split(",") if x.strip()],
            "cluster": s(r.get("Cluster name")), "version": s(r.get("Version")), "vmfs_upgradeable": b(r.get("VMFS Upgradeable")), "mha": b(r.get("MHA")),
            "sioc": b(r.get("SIOC enabled")), "address": s(r.get("Address")), "url": s(r.get("URL")), "extents": n(r.get("# Extents"), 0)}
    for r in sh.get("dvSwitch") or []:
        inv["dvswitches"][s(r.get("Switch"))] = {"name": s(r.get("Switch")), "vcenter": vc_of(r), "datacenter": s(r.get("Datacenter")), "version": s(r.get("Version")),
                                                 "mtu": n(r.get("Max MTU")), "ports": n(r.get("# Ports")), "vms": n(r.get("# VMs")),
                                                 "hosts": [x.strip() for x in s(r.get("Host members")).split(",") if x.strip()],
                                                 "lacp": s(r.get("LACP Mode")), "discovery": s(r.get("CDP Type")), "discovery_op": s(r.get("CDP Operation"))}
    for r in sh.get("dvPort") or []:
        nm = s(r.get("Port"))
        if not nm:
            continue
        inv["networks"][nm] = {"name": nm, "kind": "dvportgroup", "dvs": s(r.get("Switch")), "vlan": s(r.get("VLAN")), "ports": n(r.get("# Ports")),
                               "promiscuous": bool(b(r.get("Allow Promiscuous"))), "mac_changes": bool(b(r.get("Mac Changes"))), "forged": bool(b(r.get("Forged Transmits"))),
                               "active": s(r.get("Active Uplink")), "standby": s(r.get("Standby Uplink")), "policy": s(r.get("Policy")), "vcenter": vc_of(r),
                               "uplink_pg": "uplink" in s(r.get("Type")).lower() or "uplink" in nm.lower()}
    for r in sh.get("vSwitch") or []:
        inv["vswitches"].append({"host": s(r.get("Host")), "name": s(r.get("Switch")), "mtu": n(r.get("MTU")), "ports": n(r.get("# Ports")),
                                 "promiscuous": bool(b(r.get("Promiscuous Mode"))), "mac_changes": bool(b(r.get("Mac Changes"))), "forged": bool(b(r.get("Forged Transmits"))),
                                 "policy": s(r.get("Policy"))})
    for r in sh.get("vPort") or []:
        pg = {"host": s(r.get("Host")), "name": s(r.get("Port Group")), "switch": s(r.get("Switch")), "vlan": s(r.get("VLAN")),
              "promiscuous": bool(b(r.get("Promiscuous Mode"))), "mac_changes": bool(b(r.get("Mac Changes"))), "forged": bool(b(r.get("Forged Transmits")))}
        inv["portgroups"].append(pg)
        inv["networks"].setdefault(pg["name"], {"name": pg["name"], "kind": "portgroup", "vlan": pg["vlan"], "vswitch": pg["switch"], "vcenter": vc_of(r)})
    for r in sh.get("vSC_VMK") or []:
        pg = s(r.get("Port Group")).lower()
        svc = [k for k, rx in (("management", r"mgmt|management|관리"), ("vmotion", r"vmotion"), ("vsan", r"vsan"), ("nfs", r"nfs|storage|iscsi"),
                               ("backup", r"backup"), ("vSphereReplication", r"replication|vr\b")) if re.search(rx, pg)]
        inv["vmks"].append({"host": s(r.get("Host")), "device": s(r.get("Device")), "portgroup": s(r.get("Port Group")), "ip": s(r.get("IP Address")),
                            "mask": s(r.get("Subnet mask")), "gateway": s(r.get("Gateway")), "mtu": n(r.get("MTU")), "dhcp": b(r.get("DHCP")), "services": svc})
    for r in sh.get("vNIC") or []:
        sp = n(r.get("Speed"))
        inv["pnics"].append({"host": s(r.get("Host")), "device": s(r.get("Network Device")), "driver": s(r.get("Driver")), "speed": sp or 0,
                             "duplex": s(r.get("Duplex")), "mac": s(r.get("MAC")).lower(), "switch": s(r.get("Switch")), "uplink": s(r.get("Uplink port")), "pci": s(r.get("PCI"))})
    for r in sh.get("vHBA") or []:
        inv["hbas"].append({"host": s(r.get("Host")), "device": s(r.get("Device")), "type": s(r.get("Type")), "status": s(r.get("Status")), "driver": s(r.get("Driver")),
                            "model": s(r.get("Model")), "wwn": s(r.get("WWN")), "pci": s(r.get("Pci"))})
    for r in sh.get("vMultiPath") or []:
        paths = [(s(r.get(f"Path {i}")), s(r.get(f"Path {i} state"))) for i in range(1, 9) if s(r.get(f"Path {i}"))]
        inv["paths"].append({"host": s(r.get("Host")), "datastore": s(r.get("Datastore")), "disk": s(r.get("Disk")), "policy": s(r.get("Policy")),
                             "state": s(r.get("Oper. State")), "paths": len(paths), "active": sum(1 for _, st in paths if st.lower() == "active"),
                             "dead": sum(1 for _, st in paths if st.lower() == "dead"), "hbas": sorted({p for p, _ in paths}), "vendor": s(r.get("Vendor")),
                             "model": s(r.get("Model")), "queue": s(r.get("Queue depth"))})
    for r in sh.get("vLicense") or []:
        inv["licenses"].append({"name": s(r.get("Name")), "total": n(r.get("Total")), "used": n(r.get("Used")), "unit": s(r.get("Cost Unit")),
                                "expires": ts(r.get("Expiration Date")), "expires_raw": s(r.get("Expiration Date")), "key_tail": s(r.get("Key"))[-5:],
                                "key": s(r.get("Key")),   # 라이선스 관리(2.16) 키 매칭용 — 화면·API 에서는 가림
                                "vcenter": vc_of(r)})
    for r in sh.get("vHealth") or []:
        inv["health"].append({"name": s(r.get("Name")), "message": s(r.get("Message"))[:400], "type": s(r.get("Message type"))})
    for r in sh.get("vSnapshot") or []:
        inv["snapshots"].append({"vm": s(r.get("VM")), "name": s(r.get("Name")), "created": ts(r.get("Date / time")), "size_mib": n(r.get("Size MiB (total)"), 0),
                                 "quiesced": b(r.get("Quiesced")), "desc": s(r.get("Description"))[:120]})
    for r in sh.get("vPartition") or []:
        inv["partitions"].append({"vm": s(r.get("VM")), "disk": s(r.get("Disk")), "cap_mib": n(r.get("Capacity MiB"), 0), "free_mib": n(r.get("Free MiB"), 0),
                                  "free_pct": n(r.get("Free %"))})
    for r in sh.get("vDisk") or []:
        inv["disks"].append({"vm": s(r.get("VM")), "disk": s(r.get("Disk")), "cap_mib": n(r.get("Capacity MiB"), 0), "thin": b(r.get("Thin")), "raw": b(r.get("Raw")),
                             "mode": s(r.get("Disk Mode")), "sharing": s(r.get("Sharing mode")), "path": s(r.get("Path")), "controller": s(r.get("Controller"))})
    for r in sh.get("vCD") or []:
        inv["cds"].append({"vm": s(r.get("VM")), "connected": b(r.get("Connected")), "starts": b(r.get("Starts Connected")), "type": s(r.get("Device Type"))[:80],
                           "power": s(r.get("Powerstate"))})
    for r in sh.get("vRP") or []:
        inv["rps"].append({"name": s(r.get("Resource Pool name")), "path": s(r.get("Resource Pool path")), "vms": n(r.get("# VMs"), 0),
                           "cpu_limit": n(r.get("CPU limit")), "cpu_res": n(r.get("CPU reservation")), "mem_limit": n(r.get("Mem limit")),
                           "mem_res": n(r.get("Mem reservation")), "status": s(r.get("Status"))})
    # VM 이 붙은 포트그룹 수
    use = Counter(x for v in inv["vms"].values() for x in v["networks"])
    for nm, c in use.items():
        inv["networks"].setdefault(nm, {"name": nm, "kind": "network", "vcenter": ""})["vm_count"] = c
    for nm, x in inv["networks"].items():
        x.setdefault("vm_count", use.get(nm, 0))
    if not inv["vcenters"]:
        for h in inv["hosts"].values():
            inv["vcenters"].setdefault(h["vcenter"], {"name": h["vcenter"], "fullname": "", "version": "", "build": ""})
    return inv


# ------------------------------------------------------------------------------------------------ 기존 엔진 입력 형식
def vc_topology(inv: dict, vc: str) -> dict:
    """vCenter 커넥터의 topology 와 같은 모양(stack.build 입력)"""
    hosts, vms, nets, dss, cls = {}, {}, {}, {}, {}
    pn_by: dict[str, list[dict]] = defaultdict(list)
    for p in inv["pnics"]:
        pn_by[p["host"]].append(p)
    for hn, h in inv["hosts"].items():
        if h["vcenter"] != vc:
            continue
        pnics = [{"name": p["device"], "mac": p["mac"], "speed": p["speed"], "up": bool(p["speed"]), "driver": p["driver"], "vswitch": p["switch"]}
                 for p in pn_by.get(hn, [])]
        sws: dict[str, dict] = {}
        for p in pn_by.get(hn, []):
            if p["switch"]:
                sw = sws.setdefault(p["switch"], {"name": p["switch"], "kind": "vds" if p["switch"] in inv["dvswitches"] else "vss", "uplinks": []})
                sw["uplinks"].append(p["device"])
        for x in inv["vswitches"]:
            if x["host"] == hn:
                sws.setdefault(x["name"], {"name": x["name"], "kind": "vss", "uplinks": []})
        for d in inv["dvswitches"].values():
            if hn in d["hosts"] or any(_short(hn) == _short(m) for m in d["hosts"]):
                sws.setdefault(d["name"], {"name": d["name"], "kind": "vds", "uplinks": []})
        st = {"green": "green", "yellow": "yellow", "red": "red"}.get(h["status"], "gray")
        hosts[hn] = {"moid": "", "cluster": h["cluster"], "conn": "connected", "maintenance": bool(h["maintenance"]), "status": st, "vms": h["vms"],
                     "datastores": [d for d, x in inv["datastores"].items() if hn in x["hosts"]], "cpu_mhz": (h["cpu_mhz"] or 0) * (h["cores"] or 0),
                     "core_mhz": h["cpu_mhz"], "mem_mb": h["mem_mb"], "cpu_used_mhz": round((h["cpu_pct"] or 0) / 100 * (h["cpu_mhz"] or 0) * (h["cores"] or 0)),
                     "mem_used_mb": round((h["mem_pct"] or 0) / 100 * (h["mem_mb"] or 0)), "uuid": h["uuid"], "serial": h["serial"] or h["service_tag"],
                     "hw_vendor": h["vendor"], "hw_model": h["model"], "pnics": pnics[:16], "switches": list(sws.values())[:12],
                     "esx_version": h["version"], "esx_build": h["build"]}
    for key, v in inv["vms"].items():
        if v["vcenter"] != vc or v["template"]:
            continue
        vms[key] = {"moid": v["moid"], "host": v["host"], "cluster": v["cluster"], "power": v["power"], "consolidation": v["consolidation"], "vcpu": v["vcpu"],
                    "mem_mb": v["mem_mb"], "os": v["os_cfg"], "hw": v["hw"], "uuid": v["uuid"], "ips": [v["ip"]] if v["ip"] else [], "hostname": v["dns"],
                    "tools": {"toolsOk": "guestToolsRunning", "toolsOld": "guestToolsRunning"}.get(v["tools"], v["tools"]), "disk_gb": round(v["used_mib"] / 1024, 1),
                    "prov_gb": round(v["prov_mib"] / 1024, 1), "networks": v["networks"], "status": v["status"], "folder": v["folder"], "datacenter": v["datacenter"],
                    "snapshots": sum(1 for x in inv["snapshots"] if x["vm"] == v["name"])}
    for nm, x in inv["networks"].items():
        if x.get("vcenter") in (vc, ""):
            nets[nm] = {"kind": x.get("kind", "portgroup"), "vlan": x.get("vlan", ""), "dvs": x.get("dvs", ""), "accessible": True, "vms": x.get("vm_count", 0)}
    for dn, d in inv["datastores"].items():
        if d["vcenter"] != vc:
            continue
        cap = d["cap_mib"] or 0
        dss[dn] = {"capacity_gb": round(cap / 1024, 1), "free_gb": round(d["free_mib"] / 1024, 1), "used_pct": round((1 - d["free_mib"] / cap) * 100, 1) if cap else None,
                   "type": d["type"], "hosts": d["hosts"], "accessible": d["accessible"], "vms": d["vms"]}
    for cn, c in inv["clusters"].items():
        if c["vcenter"] == vc:
            cls[cn] = {"hosts": [h for h, x in hosts.items() if x["cluster"] == cn], "drs": c["drs"], "ha": c["ha"]}
    return {"hosts": hosts, "vms": vms, "datastores": dss, "clusters": cls, "networks": nets, "vcenter": vc}


def _short(h: str) -> str:
    return str(h or "").split(".")[0].lower()


def vcheck_snap(inv: dict) -> dict:
    """vcheck.evaluate 입력 — 수집 안 되는 값(센서·서비스·구성 문제)은 넣지 않음"""
    hosts = {}
    vmk_by: dict[str, list] = defaultdict(list)
    for k in inv["vmks"]:
        sw = next((p.get("dvs") or p.get("vswitch") for nm, p in inv["networks"].items() if nm == k["portgroup"]), "")
        vmk_by[k["host"]].append({"device": k["device"], "switch": sw, "mtu": k["mtu"], "services": k["services"]})
    path_by: dict[str, dict] = defaultdict(lambda: {"dead": 0, "single": [], "dead_luns": []})
    san = {(a["host"], a["device"]) for a in inv["hbas"] if a["type"].lower().startswith(("fibre", "fc", "iscsi", "nvme"))}
    used = {(p["host"], hb) for p in inv["paths"] for hb in p["hbas"]}
    for p in inv["paths"]:
        x = path_by[p["host"]]
        if p["dead"]:
            x["dead"] += p["dead"]
            x["dead_luns"].append(p["datastore"] or p["disk"])
        if p["paths"] == 1 and any((p["host"], hb) in san for hb in p["hbas"]):       # 로컬 컨트롤러(부트·로컬 디스크)는 제외
            x["single"].append(p["datastore"] or p["disk"])
    for hn, h in inv["hosts"].items():
        nics = [{"device": p["device"], "speed": p["speed"], "driver": p["driver"], "mac": p["mac"],
                 "duplex": None if not p["speed"] else ("half" not in p["duplex"].lower())} for p in inv["pnics"] if p["host"] == hn]
        sws: dict[str, dict] = {}
        for p in inv["pnics"]:
            if p["host"] == hn and p["switch"]:
                sw = sws.setdefault(p["switch"], {"name": p["switch"], "uplinks": [], "mtu": (inv["dvswitches"].get(p["switch"]) or {}).get("mtu")})
                sw["uplinks"].append(p["device"])
        for x in inv["vswitches"]:
            if x["host"] == hn:
                sws.setdefault(x["name"], {"name": x["name"], "uplinks": [], "mtu": x["mtu"]})["mtu"] = x["mtu"]
        hosts[hn] = {"conn": "connected", "maintenance": bool(h["maintenance"]), "cluster": h["cluster"], "mem_mb": h["mem_mb"],
                     "mem_used_mb": round((h["mem_pct"] or 0) / 100 * (h["mem_mb"] or 0)), "boot_time": h["boot_time"], "version": h["version"], "build": h["build"],
                     "ht_available": h["ht_available"], "ht_active": h["ht_active"], "ntp_servers": h["ntp"], "services": ({"ntpd": h["ntpd"]} if h["ntpd"] is not None else {}),
                     "cpu_model": h["cpu_model"], "cores": h["cores"], "vcpus": h["vcpus"], "paths": dict(path_by.get(hn) or {}),
                     "hbas": [{"device": a["device"], "status": a["status"], "model": a["model"], "driver": a["driver"]} for a in inv["hbas"]
                              if a["host"] == hn and a["type"].lower().startswith(("fibre", "fc")) and (a["status"].lower() == "online" or (hn, a["device"]) in used)],
                     "nics": nics, "vswitches": list(sws.values()), "vmks": vmk_by.get(hn, []), "vendor": h["vendor"], "model": h["model"],
                     "bios": h["bios"], "bios_date": h["bios_date"], "serial": h["serial"]}
    clusters = {cn: {"ha": c["ha"], "ha_admission": c["ha_admission"], "drs": c["drs"], "drs_behavior": c["drs_behavior"],
                     "evc": next((h["evc"] for h in inv["hosts"].values() if h["cluster"] == cn and h["evc"]), "")} for cn, c in inv["clusters"].items()}
    dss = {dn: {"capacity": d["cap_mib"] * 2**20, "free": d["free_mib"] * 2**20, "accessible": d["accessible"], "type": d["type"],
                "uncommitted": max(0, (d["prov_mib"] - d["used_mib"])) * 2**20, "hosts": d["hosts"], "local": len(d["hosts"]) == 1}
           for dn, d in inv["datastores"].items()}
    snaps: dict[str, list] = defaultdict(list)
    for x in inv["snapshots"]:
        snaps[x["vm"]].append({"created": x["created"], "name": x["name"]})
    vms = [{"name": v["name"], "snapshots": snaps.get(v["name"], []), "consolidation": v["consolidation"]} for v in inv["vms"].values() if not v["template"]]
    return {"hosts": hosts, "clusters": clusters, "datastores": dss, "vms": vms, "bmc": {}}


def hardening_inv(inv: dict, vc: str) -> dict:
    """assess.hardening 입력 — 고급 설정·서비스·방화벽·잠금 모드는 RVTools 에 없어 비움(→ MANUAL)"""
    snap_old: dict[str, float] = {}
    for x in inv["snapshots"]:
        if x["created"]:
            snap_old[x["vm"]] = min(snap_old.get(x["vm"], x["created"]), x["created"])
    hosts = [{"name": hn, "conn": "connected", "version": h["version"], "build": h["build"], "adv": {}, "services": {}, "ntp": h["ntp"], "firewall": {},
              "lockdown": "", "vswitch": [{"name": f"{x['name']}", "promiscuous": x["promiscuous"], "mac_changes": x["mac_changes"], "forged": x["forged"]}
                                          for x in inv["vswitches"] if x["host"] == hn] +
                                         [{"name": f"{x['name']}(PG)", "promiscuous": x["promiscuous"], "mac_changes": x["mac_changes"], "forged": x["forged"]}
                                          for x in inv["portgroups"] if x["host"] == hn]}
             for hn, h in inv["hosts"].items() if h["vcenter"] == vc]
    dvpg = [{"name": nm, "promiscuous": x["promiscuous"], "mac_changes": x["mac_changes"], "forged": x["forged"]}
            for nm, x in inv["networks"].items() if x.get("kind") == "dvportgroup" and x.get("vcenter") == vc and not x.get("uplink_pg")]
    vms = [{"name": v["name"], "power": v["power"], "tools": "guestToolsRunning" if v["tools"] in ("toolsOk", "toolsOld") else v["tools"],
            "oldest_snapshot": snap_old.get(v["name"]), "adv": {}} for v in inv["vms"].values() if v["vcenter"] == vc and not v["template"]]
    vcd = inv["vcenters"].get(vc) or {}
    return {"vcenter": {"name": vc, "host": vc, "version": vcd.get("version", ""), "build": vcd.get("build", "")}, "hosts": hosts, "dvpg": dvpg, "vms": vms}
