"""물리 계층 스냅숏(2.41.0) — 장애 시뮬레이터가 스위치·방화벽·라우터·외부 스토리지·물리 서버까지 영향을 계산할 수 있게
이미 수집된 자료만 모아 한 덩어리로 만든다(읽기 전용, 새 조회 없음).

  스위치·결선   portmap.build — 스위치 포트 ↔ ESXi vmnic(LLDP/CDP 양쪽), 스위치 ↔ 스위치, 스위치 ↔ 기타 장비, MLAG/vPC, 현재 링크 상태
  방화벽·라우터 스위치 LLDP 이웃 중 스위치·호스트가 아닌 장비 — 이름(fw·fortigate·palo·asa·srx / border·rtr·wan·isp)과 FortiGate 커넥터로 분류
  NSX BGP       netmap.build 의 T0 BGP 세션(Edge ↔ 물리 스위치)
  물리 서버     엔진 bmc_inventory(Redfish·CIMC·UCS) + vCenter 호스트 하드웨어(제조사·모델·S/N)
  외부 스토리지 vCenter 데이터스토어 백엔드(NFS 서버 · VMFS LUN 의 제조사/모델) — 같은 NFS 서버·같은 어레이 모델을 한 대로 묶음(모델이 같은 어레이가 여러 대면 '추정')
  수동 보정     설정 checkbot.external: [{name, kind: storage|firewall|router, datastores: [...], switches: [...]}] — 자동으로 못 찾는 장비를 직접 지정
"""
from __future__ import annotations

import re
import time
from typing import Any

FW_RX = re.compile(r"(^|[-_.])(fw|firewall|fg|fgt|fortigate|forti|palo|pa|asa|srx|chkp|checkpoint|ngfw)(\d|[-_.]|$)", re.I)
RTR_RX = re.compile(r"(^|[-_.])(border|bdr|rtr|router|wan|isp|inet|internet|ce|pe|edge-?rtr|gw)(\d|[-_.]|$)", re.I)


def _short(n: str) -> str:
    return str(n or "").split(".")[0].split("(")[0].strip().lower()


def build(engine) -> dict[str, Any]:
    out: dict[str, Any] = {"switches": {}, "devices": {}, "hosts": {}, "bgp": [], "servers": {}, "storage": {}, "collected": {}, "ts": time.time()}
    conns = list(getattr(engine, "connectors", []) or [])
    # ---------------------------------------------------------------- 스위치·결선
    pm = None
    try:
        from . import portmap as PM
        pm = PM.build(engine)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"포트맵: {type(e).__name__}"
    fg = {_short(getattr(c, "name", "")) for c in conns if getattr(c, "type", "") == "fortigate"}
    fg |= {_short((getattr(c, "device", None) or {}).get("hostname", "")) for c in conns if getattr(c, "type", "") == "fortigate"}
    if pm:
        for s in pm.get("switches", []):
            sn = s["name"]
            out["switches"][sn] = {"name": sn, "role": s.get("role", ""), "vendor": s.get("vendor", ""), "model": s.get("model", ""), "state": s.get("state", ""),
                                   "mlag": str((s.get("mlag") or {}).get("domain", "") or ""), "links": []}
            for p in s.get("ports", []):
                pr = p.get("peer") or {}
                if not pr.get("name"):
                    continue
                up = p.get("state") == "up" and not pr.get("lost")
                if pr.get("kind") == "switch":
                    out["switches"][sn]["links"].append({"to": pr["name"], "kind": "switch", "port": p["name"], "up": up})
                elif pr.get("kind") == "device":
                    dn = pr["name"].split("(")[0]
                    k = "firewall" if FW_RX.search(dn) or _short(dn) in fg else "router" if RTR_RX.search(dn) else "device"
                    d = out["devices"].setdefault(dn, {"name": dn, "kind": k, "switches": [], "source": "lldp"})
                    if sn not in d["switches"]:
                        d["switches"].append(sn)
                    out["switches"][sn]["links"].append({"to": dn, "kind": "device", "port": p["name"], "up": up})
        # 스위치 이름 정규화(LLDP 이웃은 FQDN·짧은 이름이 섞임)
        by_short = {_short(n): n for n in out["switches"]}
        for s in out["switches"].values():
            for l in s["links"]:
                if l["kind"] == "switch":
                    l["to"] = by_short.get(_short(l["to"]), l["to"])
        for h in pm.get("hosts", []):
            out["hosts"][h["name"]] = {"vcenter": h.get("vcenter", ""), "cluster": h.get("cluster", ""),
                                       "nics": {n["name"]: {"up": n.get("state") == "up", "switch": by_short.get(_short((n.get("peer") or {}).get("switch", "")), (n.get("peer") or {}).get("switch", "")),
                                                            "port": (n.get("peer") or {}).get("port", ""), "vswitch": n.get("vswitch", "")} for n in h.get("nics", [])},
                                       "vswitches": {v["name"]: v.get("uplinks", []) for v in h.get("vswitches", [])}}
        out["collected"]["network"] = pm.get("generated")
    try:
        if out["switches"]:
            from . import netmap as NM
            out["bgp"] = [{k: b.get(k) for k in ("tier0", "edge", "edge_cluster", "switch", "state", "neighbor")} for b in NM.build(engine, include_hosts=False).get("bgp", [])]
    except Exception:  # noqa: BLE001
        pass
    # ---------------------------------------------------------------- 물리 서버
    bmc = {}
    try:
        bmc = engine.bmc_inventory() if hasattr(engine, "bmc_inventory") else {}
    except Exception:  # noqa: BLE001
        bmc = {}
    for c in conns:
        if getattr(c, "type", "") != "vcenter" or not getattr(c, "topology", None):
            continue
        out["collected"].setdefault("vcenter", {})[c.name] = (c.topology or {}).get("updated")
        for hn, h in (c.topology.get("hosts") or {}).items():
            b = bmc.get(hn) or {}
            out["servers"][hn] = {"vcenter": c.name, "vendor": h.get("vendor") or h.get("hw_vendor", ""), "model": b.get("model") or h.get("model") or h.get("hw_model", ""),
                                  "serial": b.get("serial") or h.get("serial", ""), "bmc": b.get("bmc", ""), "bmc_connector": b.get("connector", ""), "health": b.get("health", "")}
        # ------------------------------------------------------------ 외부 스토리지(데이터스토어 백엔드)
        lunv = getattr(c, "_lunv", None) or {}                  # 인프라 점검 수집이 본 LUN → '제조사 모델'
        for dn, d in (c.topology.get("datastores") or {}).items():
            arr = d.get("array") or next((lunv[x] for x in d.get("extents") or [] if lunv.get(x)), "")
            bk = {"server": str(d.get("remote") or "").split(":")[0], "array": arr}
            t = str(d.get("type", "")).lower()
            if t == "vsan" or d.get("local") is True:
                continue
            if bk.get("server") or t.startswith("nfs"):
                name, kind, note = (bk.get("server") or "NFS 서버(주소 모름)"), "nfs", "" if bk.get("server") else "추정"
            elif bk.get("array"):
                name, kind, note = bk["array"], "san", "추정" if not bk.get("exact") else ""
            elif t in ("vmfs", "vvol"):
                name, kind, note = "SAN 어레이(모델 모름)", "san", "추정"
            else:
                continue
            a = out["storage"].setdefault(name, {"name": name, "kind": kind, "datastores": [], "note": note, "source": "vcenter"})
            a["datastores"].append({"vcenter": c.name, "name": dn})
    # ---------------------------------------------------------------- 수동 보정(설정)
    cfg = (getattr(engine, "cfg", None) or {})
    ext = ((cfg.get("checkbot") or {}) if isinstance(cfg, dict) else {}).get("external") or []
    for x in ext if isinstance(ext, list) else []:
        if not isinstance(x, dict) or not x.get("name"):
            continue
        k = str(x.get("kind", "device")).lower()
        if k == "storage":
            a = out["storage"].setdefault(x["name"], {"name": x["name"], "kind": x.get("protocol", "san"), "datastores": [], "note": "", "source": "설정"})
            a["source"], a["note"] = "설정", ""
            for dn in x.get("datastores") or []:
                for s in out["storage"].values():                   # 자동으로 묶인 곳에서 빼서 지정한 어레이로
                    if s is not a:
                        s["datastores"] = [y for y in s["datastores"] if y["name"] != dn]
                vcn = next((c.name for c in conns if getattr(c, "type", "") == "vcenter" and dn in ((getattr(c, "topology", None) or {}).get("datastores") or {})), "")
                if vcn and not any(y["name"] == dn for y in a["datastores"]):
                    a["datastores"].append({"vcenter": vcn, "name": dn})
        elif k in ("firewall", "router", "device"):
            d = out["devices"].setdefault(x["name"], {"name": x["name"], "kind": k, "switches": [], "source": "설정"})
            d["kind"], d["source"] = k, "설정"
            for sw in x.get("switches") or []:
                if sw in out["switches"] and sw not in d["switches"]:
                    d["switches"].append(sw)
                    out["switches"][sw]["links"].append({"to": x["name"], "kind": "device", "port": "", "up": True})
    out["storage"] = {k: v for k, v in out["storage"].items() if v["datastores"]}
    return out


# ------------------------------------------------------------------ 네트워크 영향 계산(순수 함수)
def border_nodes(phys: dict) -> set[str]:
    b = {n for n, d in phys["devices"].items() if d["kind"] in ("firewall", "router")}
    b |= {n for n, s in phys["switches"].items() if str(s.get("role", "")).lower() in ("border", "edge", "wan", "external")}
    return b


def reach(phys: dict, dead: set[str]) -> tuple[set[str], bool]:
    """외부(방화벽·라우터·보더)에서 시작해 살아 있는 링크로 닿는 스위치 집합. 외부 장비를 모르면 (빈 집합, False)"""
    borders = border_nodes(phys) - dead
    known = bool(border_nodes(phys))
    adj: dict[str, set[str]] = {}
    for sn, s in phys["switches"].items():
        if sn in dead:
            continue
        for l in s["links"]:
            if l["up"] and l["to"] not in dead:
                adj.setdefault(sn, set()).add(l["to"])
                adj.setdefault(l["to"], set()).add(sn)
    seen, todo = set(borders), list(borders)
    while todo:
        n = todo.pop()
        for m in adj.get(n, ()):
            if m not in seen:
                seen.add(m)
                todo.append(m)
    return {n for n in seen if n in phys["switches"]}, known


def host_paths(phys: dict, host: str, dead: set[str], dead_nics: set[tuple[str, str]], ext_ok: set[str], ext_known: bool) -> dict[str, dict]:
    """가상 스위치마다 지금(가정 반영) 살아 있는 업링크 수와 외부까지 가는 업링크 수"""
    h = phys["hosts"].get(host)
    if not h:
        return {}
    out = {}
    for vs, ups in h["vswitches"].items():
        live, ext, base = [], [], []
        for u in ups:
            n = h["nics"].get(u) or {}
            if not n:
                continue
            if n.get("up"):
                base.append(u)
            ok = n.get("up") and (host, u) not in dead_nics and (not n.get("switch") or n["switch"] not in dead)
            if ok:
                live.append(u)
                if not ext_known or not n.get("switch") or n["switch"] in ext_ok:
                    ext.append(u)
        out[vs] = {"uplinks": ups, "now": base, "live": live, "ext": ext, "switches": sorted({(h["nics"].get(u) or {}).get("switch", "") for u in ups} - {""})}
    return out
