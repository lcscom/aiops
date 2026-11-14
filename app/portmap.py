"""장비별 포트맵(2.3) — 스위치 전면 포트 ↔ ESXi vmnic 연결표와 이중화·속도·LLDP 불일치 점검.

자료
  스위치: NetDevice.snapshot() — 인터페이스(상태·속도·설명·VLAN) + LLDP/CDP 이웃(사라진 이웃 포함)
  ESXi : vCenter 토폴로지 hosts[].pnics — 이름·MAC·속도·링크·소속 가상 스위치(vSS/vDS)
         + ESXi 쪽 LLDP/CDP(HostNetworkSystem.QueryNetworkHint, 15분) → pnics[].peer
  양쪽에서 같은 연결을 보면 한 줄로 합치고, 서로 다르게 보이면 '불일치' 로 표시한다.

점검(findings)
  · 가상 스위치 업링크가 모두 같은 물리 스위치 한 대에 연결 → 스위치 이중화 없음(warn)
  · 가상 스위치 업링크 중 링크 다운 vmnic(down) · 같은 가상 스위치 업링크 속도 불일치(warn)
  · ESXi LLDP 와 스위치 LLDP 가 가리키는 상대가 다름(warn) · 스위치 포트 속도 ≠ vmnic 속도(warn)
  · 연결 정보 없음(info — vDS LLDP 'Both' 또는 스위치 LLDP 확인)
  · 스위치: 설명·이웃이 있는데 다운인 포트(down) · 사라진 이웃(warn)
"""
from __future__ import annotations

import re
import time
from typing import Any

from . import netconfig as NC
from .connectors.network import NetDevice, if_short, short

PHYS = re.compile(r"^(ethernet|eth|gigabitethernet|tengigabitethernet|twentyfivegige|fortygigabitethernet|hundredgige|fastethernet|"
                  r"twogigabitethernet|fivegigabitethernet|appgigabitethernet|gi|te|fo|hu|twe|tw|xe|ge|et|fa|port)\s*\d", re.I)
LAG = re.compile(r"^(port-channel|po|bundle-ether|ae)\s*\d", re.I)
MGMT = re.compile(r"^(management|mgmt|ma)\s*\d", re.I)


def nkey(name: str) -> list:
    """Ethernet1/10 > Ethernet1/9 정렬용"""
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", str(name or ""))]


def port_kind(name: str) -> str:
    n = str(name or "").strip()
    if LAG.match(n):
        return "lag"
    if MGMT.match(n):
        return "mgmt"
    if PHYS.match(n):
        return "phys"
    return "logical"


def _speed_txt(mb: Any) -> str:
    try:
        v = float(mb)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    return f"{v / 1000:g}G" if v >= 1000 else f"{v:g}M"


def build(engine) -> dict[str, Any]:
    snaps = [c.snapshot() for c in getattr(engine, "connectors", []) if isinstance(c, NetDevice) and getattr(c, "enabled", True)]
    snaps = [s for s in snaps if s.get("updated")]
    sw_by_short = {short(s["name"]): s for s in snaps}
    hosts: dict[str, dict] = {}
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") != "vcenter":
            continue
        for hn, h in ((getattr(c, "topology", {}) or {}).get("hosts", {}) or {}).items():
            nets = (getattr(c, "topology", {}) or {}).get("networks", {}) or {}
            vds = {sw.get("name") for sw in (h.get("switches") or []) if sw.get("kind") in ("vds", "dvs")}
            need = {}
            for nn, ni in nets.items():                               # 이 호스트의 vDS 포트그룹이 쓰는 VLAN
                v = ni.get("vlan")
                if ni.get("dvs") in vds and isinstance(v, int) and 0 < v < 4095:
                    need.setdefault(v, []).append(nn)
            hosts[short(hn)] = {"name": hn, "cluster": h.get("cluster", ""), "vcenter": c.name, "conn": h.get("conn", ""),
                                "maintenance": bool(h.get("maintenance")), "pnics": h.get("pnics") or [], "switches": h.get("switches") or [],
                                "model": f"{h.get('hw_vendor', '')} {h.get('hw_model', '')}".strip(), "need_vlans": need}
    # 스위치 쪽 LLDP 로 본 호스트 연결: (호스트, vmnic) → (스위치, 포트, 상태)
    from_sw: dict[tuple[str, str], dict] = {}
    for s in snaps:
        for n in s.get("neighbors") or []:
            rs = short(n.get("remote", ""))
            if rs in hosts:
                from_sw[(rs, str(n.get("remote_port", "")).strip().lower())] = {"switch": s["name"], "port": n.get("local", ""), "proto": n.get("proto", "lldp"),
                                                                              "lost": n.get("state") == "lost"}
    findings: list[dict] = []
    cfg_by = {(short(sw["name"]), if_short(k)): v for sw in snaps for k, v in (sw.get("port_cfg") or {}).items()}
    vlan_names = {short(sw["name"]): {int(k): v for k, v in (sw.get("vlans") or {}).items()} for sw in snaps}
    # ---------------------------------------------------------------- ESXi
    host_out = []
    host_peer_of_port: dict[tuple[str, str], tuple[str, str]] = {}      # (스위치 short, 포트 short) → (호스트, vmnic) — ESXi 쪽에서만 보이는 연결
    for hs, h in sorted(hosts.items()):
        nics = []
        for p in sorted(h["pnics"], key=lambda x: nkey(x.get("name", ""))):
            nm = p.get("name", "")
            ss = from_sw.get((hs, nm.lower()))
            es = p.get("peer") or {}
            peer, src, mism = {}, [], ""
            if ss:
                peer = {"switch": ss["switch"], "port": ss["port"], "proto": ss["proto"]}
                src.append("switch")
            if es.get("switch") or es.get("port"):
                src.append("esxi")
                if not peer:
                    peer = {"switch": es.get("switch", ""), "port": es.get("port", ""), "proto": es.get("proto", "lldp")}
                elif short(es.get("switch", "")) != short(peer["switch"]) or if_short(es.get("port", "")) != if_short(peer["port"]):
                    mism = f"ESXi 는 {es.get('switch', '')} {es.get('port', '')}, 스위치는 {peer['switch']} {peer['port']} 로 봄"
            sp_sw = None
            if peer:
                sws = sw_by_short.get(short(peer["switch"]))
                if sws:
                    peer["collected"] = True
                    ifx = next((i for i in sws.get("ifaces") or [] if if_short(i["name"]) == if_short(peer["port"])), None)
                    if ifx:
                        peer["port_state"] = ifx.get("state")
                        sp_sw = ifx.get("speed")
                    host_peer_of_port[(short(sws["name"]), if_short(peer["port"]))] = (h["name"], nm)
            st = "up" if p.get("up") else "down"
            if ss and ss.get("lost"):
                st = "down"
            n = {"name": nm, "mac": p.get("mac", ""), "speed": p.get("speed") or 0, "speed_txt": _speed_txt(p.get("speed")), "state": st,
                 "vswitch": p.get("vswitch", ""), "driver": p.get("driver", ""), "peer": peer, "source": src, "mismatch": mism,
                 "switch_speed": sp_sw}
            pc = cfg_by.get((short(peer.get("switch", "")), if_short(peer.get("port", "")))) if peer else None
            if pc:
                n["switch_cfg"] = {"mode": pc.get("mode") or ("routed" if pc.get("routed") else ""), "vlans": pc.get("trunk_vlans") or pc.get("access_vlan"),
                                   "native": pc.get("native_vlan"), "mtu": pc.get("mtu"), "channel": pc.get("channel_group")}
                if p.get("vswitch") and h["need_vlans"]:
                    allowed = NC.vlan_list(pc.get("trunk_vlans")) if (pc.get("mode") == "trunk" or pc.get("trunk_vlans")) else \
                        ({pc["access_vlan"]} if pc.get("access_vlan") else set())
                    miss = sorted(v for v in h["need_vlans"] if allowed is not None and v not in allowed)
                    if miss:
                        vn = vlan_names.get(short(peer["switch"]), {})
                        findings.append({"sev": "warn", "device": h["name"], "port": nm, "kind": "vlan-missing",
                                         "text": f"{nm} → {peer['switch']} {peer['port']}: 스위치 포트에 VLAN {', '.join(str(v) + (f'({vn[v]})' if vn.get(v) else '') for v in miss[:8])} 없음"
                                                 f" — 포트그룹 {', '.join(sorted({x for v in miss for x in h['need_vlans'][v]})[:4])} 의 VM 이 이 업링크로 나가면 통신 불가"})
                    if pc.get("mode") == "access" and len(h["need_vlans"]) > 1:
                        findings.append({"sev": "info", "device": h["name"], "port": nm, "kind": "access-to-esxi",
                                         "text": f"{nm} → {peer['switch']} {peer['port']} 가 access 포트(VLAN {pc.get('access_vlan')}) — vDS 포트그룹 VLAN {len(h['need_vlans'])}개는 trunk 필요"})
            nics.append(n)
            if mism:
                findings.append({"sev": "warn", "device": h["name"], "port": nm, "kind": "lldp-mismatch", "text": f"{nm}: 연결 정보 불일치 — {mism}"})
            if p.get("up") and sp_sw and p.get("speed") and abs(float(sp_sw) - float(p["speed"])) > 1:
                findings.append({"sev": "warn", "device": h["name"], "port": nm, "kind": "speed",
                                 "text": f"{nm} {_speed_txt(p['speed'])} ↔ {peer['switch']} {peer['port']} {_speed_txt(sp_sw)} — 속도 불일치"})
        # 가상 스위치 단위 점검
        vsw: dict[str, list[dict]] = {}
        for n in nics:
            if n["vswitch"]:
                vsw.setdefault(n["vswitch"], []).append(n)
        for sw_name, ups in vsw.items():
            downs = [u["name"] for u in ups if u["state"] == "down"]
            if downs:
                findings.append({"sev": "down", "device": h["name"], "port": ",".join(downs), "kind": "uplink-down",
                                 "text": f"{sw_name} 업링크 {', '.join(downs)} 다운 — 남은 업링크 {len(ups) - len(downs)}개"})
            peers = {short(u["peer"]["switch"]) for u in ups if u["peer"].get("switch") and u["state"] == "up"}
            if len([u for u in ups if u["state"] == "up"]) >= 2 and len(peers) == 1:
                findings.append({"sev": "warn", "device": h["name"], "port": ",".join(u["name"] for u in ups), "kind": "redundancy",
                                 "text": f"{sw_name} 업링크 {len(ups)}개가 모두 {next(iter(peers))} 한 대에 연결 — 스위치 이중화 없음"})
            sps = {u["speed"] for u in ups if u["state"] == "up" and u["speed"]}
            if len(sps) > 1:
                findings.append({"sev": "warn", "device": h["name"], "port": ",".join(u["name"] for u in ups), "kind": "speed",
                                 "text": f"{sw_name} 업링크 속도가 섞임({', '.join(_speed_txt(x) for x in sorted(sps))}) — 부하 분산·장애 조치 시 성능 차이"})
        unknown = [n["name"] for n in nics if n["state"] == "up" and not n["peer"]]
        if unknown and (snaps or any(n["peer"] for n in nics)):
            findings.append({"sev": "info", "device": h["name"], "port": ",".join(unknown), "kind": "no-lldp",
                             "text": f"{', '.join(unknown)}: 연결된 스위치 포트를 모름 — vDS LLDP 'Both' 또는 스위치 LLDP 를 켜면 표시"})
        hst = "down" if h["conn"] not in ("connected", "") else "maint" if h["maintenance"] else \
            "warn" if any(f["device"] == h["name"] and f["sev"] in ("down", "warn") for f in findings) else "ok"
        host_out.append({"name": h["name"], "cluster": h["cluster"], "vcenter": h["vcenter"], "model": h["model"], "state": hst, "nics": nics,
                         "vswitches": [{"name": k, "uplinks": [u["name"] for u in v]} for k, v in vsw.items()],
                         "connected": sum(1 for n in nics if n["peer"]), "up": sum(1 for n in nics if n["state"] == "up")})
    # ---------------------------------------------------------------- 스위치
    sw_out = []
    for s in sorted(snaps, key=lambda x: nkey(x["name"])):
        nb = {if_short(n.get("local", "")): n for n in s.get("neighbors") or []}
        ports = []
        for i in s.get("ifaces") or []:
            kind = port_kind(i["name"])
            if kind == "logical":
                continue
            n = nb.get(if_short(i["name"]))
            peer = {}
            if n:
                rs = short(n.get("remote", ""))
                pk = "switch" if rs in sw_by_short else "host" if rs in hosts else "device"
                peer = {"name": n.get("remote", ""), "short": rs, "port": n.get("remote_port", ""), "kind": pk, "proto": n.get("proto", "lldp"),
                        "lost": n.get("state") == "lost"}
            else:
                hp = host_peer_of_port.get((short(s["name"]), if_short(i["name"])))
                if hp:
                    peer = {"name": hp[0], "short": short(hp[0]), "port": hp[1], "kind": "host", "proto": "esxi-lldp", "lost": False}
            st = i.get("state") or "unknown"
            pc = cfg_by.get((short(s["name"]), if_short(i["name"])))
            if pc and pc.get("shutdown") and st != "up":
                st = "disabled"
            desc = i.get("desc") or (pc or {}).get("desc", "")
            cls = ("disabled" if st == "disabled" else
                   "alert" if st != "up" and (peer or desc) else
                   "down" if st != "up" else "peer" if peer else "up")
            usage = NC.port_usage(st, i.get("raw", ""), pc, bool(peer))
            cfgv = {}
            if pc:
                cfgv = {"mode": pc.get("mode") or ("routed" if pc.get("routed") else ""), "access_vlan": pc.get("access_vlan"), "trunk_vlans": pc.get("trunk_vlans"),
                        "native": pc.get("native_vlan"), "channel": pc.get("channel_group"), "lacp": pc.get("lacp_mode"), "ip": pc.get("ip"), "vrf": pc.get("vrf"),
                        "mtu": pc.get("mtu"), "shutdown": pc.get("shutdown"), "portfast": pc.get("portfast")}
            ports.append({"name": i["name"], "short": if_short(i["name"]), "kind": kind, "state": st, "cls": cls, "usage": usage, "raw": i.get("raw", ""),
                          "desc": desc, "speed": i.get("speed"), "speed_txt": _speed_txt(i.get("speed")), "vlan": i.get("vlan"), "peer": peer, "cfg": cfgv})
            if usage == "err":
                findings.append({"sev": "down", "device": s["name"], "port": i["name"], "kind": "err-disabled", "text": f"{i['name']} err-disabled — 원인 해결 후 shutdown/no shutdown"})
            if peer and desc and peer.get("kind") in ("host", "switch"):
                toks = {short(t) for t in re.split(r"[\s,;:/()\[\]]+", desc.lower()) if t}
                known = set(hosts) | set(sw_by_short)
                if toks & known and peer["short"] not in toks:
                    findings.append({"sev": "warn", "device": s["name"], "port": i["name"], "kind": "desc-mismatch",
                                     "text": f"{i['name']} 설명 '{desc}' 와 실제 연결({peer['name']} {peer.get('port', '')})이 다름 — 결선 또는 설명 갱신 확인"})
            if cls == "alert":
                findings.append({"sev": "down", "device": s["name"], "port": i["name"], "kind": "port-down",
                                 "text": f"{i['name']} 다운({i.get('raw') or st})" + (f" — {peer['name']} {peer.get('port', '')}" if peer else f" — {i.get('desc')}")})
            elif peer.get("lost"):
                findings.append({"sev": "warn", "device": s["name"], "port": i["name"], "kind": "lost", "text": f"{i['name']} 이웃 사라짐 — {peer['name']} {peer.get('port', '')}"})
        ports.sort(key=lambda p: (["phys", "lag", "mgmt"].index(p["kind"]), nkey(p["name"])))
        phys = [p for p in ports if p["kind"] == "phys"]
        if s.get("port_cfg"):
            opened = [p["name"] for p in phys if p["usage"] == "open"]
            if opened:
                findings.append({"sev": "info", "device": s["name"], "port": ",".join(opened[:40]), "kind": "unused-open",
                                 "text": f"미사용 포트 {len(opened)}개가 열려 있음(no shutdown·설명 없음) — 보안상 shutdown 권장: {', '.join(p for p in opened[:10])}{' …' if len(opened) > 10 else ''}"})
            lag: dict[str, list[dict]] = {}
            for p in phys:
                if p["cfg"].get("channel"):
                    lag.setdefault(p["cfg"]["channel"], []).append(p)
            for ch, mem in lag.items():
                sig = {(m["cfg"].get("mode"), str(m["cfg"].get("trunk_vlans") or m["cfg"].get("access_vlan")), m["cfg"].get("mtu")) for m in mem}
                if len(sig) > 1:
                    findings.append({"sev": "warn", "device": s["name"], "port": ",".join(m["name"] for m in mem), "kind": "lag-inconsistent",
                                     "text": f"Port-Channel {ch} 멤버 구성이 서로 다름(모드·VLAN·MTU) — {', '.join(m['name'] for m in mem)}"})
        for p in phys:                                                  # 스위치 ↔ 스위치 MTU 불일치(양쪽 구성 수집 시, 한 번만)
            pr = p["peer"]
            if pr.get("kind") == "switch" and p["cfg"].get("mtu") and nkey(s["name"]) < nkey(pr["name"]):
                oc = cfg_by.get((pr["short"], if_short(pr.get("port", ""))))
                if oc and oc.get("mtu") and oc["mtu"] != p["cfg"]["mtu"]:
                    findings.append({"sev": "warn", "device": s["name"], "port": p["name"], "kind": "mtu-mismatch",
                                     "text": f"{p['name']} MTU {p['cfg']['mtu']} ↔ {pr['name']} {pr.get('port', '')} MTU {oc['mtu']} — 불일치(OSPF/BGP·점보 프레임 장애 원인)"})
        sw_out.append({"name": s["name"], "vendor": s["vendor"], "model": s["model"], "os": s["os"], "version": s["version"], "mgmt": s["mgmt"],
                       "state": s["state"], "role": s.get("role", ""), "mlag": s.get("mlag") or {}, "ports": ports,
                       "config": s.get("config") or {}, "cfg_global": s.get("cfg_global") or {}, "vlans": s.get("vlans") or {},
                       "usage": {k: sum(1 for p in phys if p["usage"] == k) for k in NC.USAGE},
                       "counts": {"phys": len(phys), "up": sum(1 for p in phys if p["state"] == "up"), "peer": sum(1 for p in phys if p["peer"]),
                                  "alert": sum(1 for p in phys if p["cls"] == "alert"), "free": sum(1 for p in phys if p["cls"] == "down"),
                                  "hosts": len({p["peer"]["short"] for p in phys if p["peer"].get("kind") == "host"})}})
    rank = {"down": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: (rank.get(f["sev"], 3), nkey(f["device"]), nkey(f["port"])))
    sevr = {"down": 0, "warn": 1}
    host_out.sort(key=lambda h: (h["connected"] == 0, min([sevr.get(f["sev"], 2) for f in findings if f["device"] == h["name"]] or [3]), nkey(h["name"])))
    return {"generated": time.time(), "switches": sw_out, "hosts": host_out[:1000], "findings": findings[:2000],
            "summary": {"switches": len(sw_out), "hosts": len(host_out), "ports": sum(x["counts"]["phys"] for x in sw_out),
                        "ports_used": sum(x["counts"]["peer"] for x in sw_out), "ports_free": sum(x["counts"]["free"] for x in sw_out),
                        "down": sum(1 for f in findings if f["sev"] == "down"), "warn": sum(1 for f in findings if f["sev"] == "warn"),
                        "info": sum(1 for f in findings if f["sev"] == "info"),
                        "no_redundancy": sum(1 for f in findings if f["kind"] == "redundancy"),
                        "esxi_lldp": sum(1 for h in host_out for n in h["nics"] if "esxi" in n["source"])}}
