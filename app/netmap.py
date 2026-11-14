"""전체 네트워크 구성도(2.2) — 스위치(Arista·Cisco·SNMP) LLDP/CDP 이웃 + vCenter ESXi + UCS/BMC 서버 + NSX Edge·Avi SE 를 하나의 그래프로.

노드: switch(수집 장비) · external-switch(이웃으로만 보이는 스위치·라우터) · host(ESXi) · server(UCS FI·BMC) · device(기타)
링크: 수집 장비 A 의 로컬 포트 ↔ 이웃 B 의 포트. 양쪽 모두 수집 장비면 한 줄로 합침. 상태 = 로컬 인터페이스 상태(up·down) + 사라진 이웃(lost)
계층(tier): 0 외부·업링크 · 1 스파인/코어 · 2 리프/ToR · 3 호스트·서버 · 4 NSX Edge(T0) — 커넥터 role 설정 > 이름 힌트(spine·core·leaf·tor) > 이웃 구성으로 추정
2.3: NSX T0 BGP 세션(Edge ↔ 물리 스위치) — 링크 kind=bgp. 매칭 = 스위치 BGP 피어 주소 == Edge 업링크(source_address) > 스위치 관리 주소 == neighbor_address.
     물리 스위치가 수집되지 않으면 'BGP 피어 <주소>' 외부 노드. Edge VM 이 올라간 ESXi 는 kind=placement 점선.
"""
from __future__ import annotations

import re
import time
from typing import Any

from .connectors.network import NetDevice, if_short, short

NAME_TIER = [(re.compile(r"(^|[-_.])(border|edge-?rtr|wan|inet|isp|fw|firewall|uplink)", re.I), 0),
             (re.compile(r"(^|[-_.])(spine|core|agg|aggr|dist|sp\d)", re.I), 1),
             (re.compile(r"(^|[-_.])(leaf|tor|access|acc|lf\d|bl\d|sw)", re.I), 2)]
ROLE_TIER = {"border": 0, "edge": 0, "wan": 0, "external": 0, "spine": 1, "core": 1, "aggregation": 1, "distribution": 1,
             "leaf": 2, "tor": 2, "access": 2, "server": 3, "host": 3}


def _desc_kind(desc: str, port: str) -> str:
    d = f"{desc} {port}".lower()
    if "vmware esx" in d or "vmnic" in d or "esxi" in d:
        return "host"
    if any(k in d for k in ("arista", "nx-os", "nexus", "ios-xe", "ios xe", "catalyst", "cisco ios", "junos", "dell os", "sonic", "cumulus")):
        return "external-switch"
    if "ucs" in d and ("fabric" in d or "fi-" in d):
        return "server"
    if "linux" in d or "windows" in d or "ubuntu" in d:
        return "device"
    return "device"


TIER_NAMES = ["외부·업링크", "스파인·코어", "리프·ToR", "ESXi·서버", "Edge·Avi SE·컨트롤러", "Edge 클러스터·SE 그룹·관리", "Tier-0·VPC 프로젝트·Avi VS",
              "Tier-1·VPC", "세그먼트·포트그룹·VPC 서브넷", "VM", "Pod"]
LOGICAL = {"nsx", "avi", "vpc", "vm", "pod"}


def build(engine, include_hosts: bool = True, layers: set[str] | None = None, vm_limit: int = 12, pod_limit: int = 8) -> dict[str, Any]:
    nodes: dict[str, dict] = {}
    links: dict[tuple, dict] = {}
    conns = [c for c in getattr(engine, "connectors", []) if isinstance(c, NetDevice) and getattr(c, "enabled", True)]
    # ESXi·서버 이름 사전
    hosts: dict[str, dict] = {}
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") == "vcenter":
            for hn, h in ((getattr(c, "topology", {}) or {}).get("hosts", {}) or {}).items():
                hosts[short(hn)] = {"name": hn, "cluster": h.get("cluster", ""), "state": "down" if h.get("conn") not in ("connected", "") else
                                    "maint" if h.get("maintenance") else "ok", "vcenter": c.name, "moid": h.get("moid", "")}
    servers: dict[str, dict] = {}
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") in ("ucsm", "redfish"):
            for e in (c.entities() if hasattr(c, "entities") else [])[:200]:
                if e.get("name"):
                    servers[short(e["name"])] = {"name": e["name"], "state": e.get("state", "unknown"), "kind": e.get("kind", "")}

    def node(nid: str, **kw) -> dict:
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "ports": 0, **kw}
        else:
            for k, v in kw.items():
                if v not in (None, "", []) and (n.get(k) in (None, "", [], "unknown") or k in ("kind", "state") and n.get("kind") != "switch"):
                    n[k] = v
        return n

    snaps = []
    for c in conns:
        s = c.snapshot()
        if not s.get("updated") and not s.get("error"):
            continue
        snaps.append(s)
        node(f"sw:{short(s['name'])}", label=s["name"], kind="switch", vendor=s["vendor"], model=s["model"], os=s["os"], version=s["version"],
             mgmt=s["mgmt"], state=s["state"], role=s["role"], site=s["site"], connector=s["connector"], ifs_up=s["ifs_up"], ifs_total=s["ifs_total"],
             ifs_down=len(s["ifs_down_important"]), mlag=s["mlag"], bgp_total=len(s["bgp"]),
             bgp_up=sum(1 for b in s["bgp"] if str(b.get("state", "")).lower() == "established"), error=s.get("error", ""), updated=s.get("updated"))
    sw_ids = {nid for nid, n in nodes.items() if n["kind"] == "switch"}
    for s in snaps:
        a = f"sw:{short(s['name'])}"
        ifst = {if_short(i["name"]): i for i in s["ifaces"]}
        for n in s["neighbors"]:
            rname = n.get("remote") or ""
            if not rname:
                continue
            rs = short(rname)
            if f"sw:{rs}" in sw_ids:
                b = f"sw:{rs}"
            elif rs in hosts:
                if not include_hosts:
                    continue
                h = hosts[rs]
                b = f"host:{rs}"
                node(b, label=h["name"], kind="host", state=h["state"], cluster=h["cluster"], vcenter=h["vcenter"])
            elif rs in servers:
                b = f"srv:{rs}"
                node(b, label=servers[rs]["name"], kind="server", state=servers[rs]["state"], detail=servers[rs]["kind"])
            else:
                kind = _desc_kind(n.get("remote_desc", ""), n.get("remote_port", ""))
                if kind == "host" and not include_hosts:
                    continue
                b = f"{'host' if kind == 'host' else 'ext'}:{rs}"
                node(b, label=rname.split("(")[0], kind=kind, state="unknown", detail=str(n.get("remote_desc", ""))[:160], mgmt=n.get("remote_mgmt", ""))
            li = ifst.get(if_short(n.get("local", ""))) or {}
            st = "down" if n.get("state") == "lost" else li.get("state") or "up"
            st = {"disabled": "down", "unknown": "up"}.get(st, st)
            lp, rp = n.get("local", ""), n.get("remote_port", "")
            if b in sw_ids:                               # 스위치 ↔ 스위치: 양쪽에서 보이므로 정규화한 키로 한 번만
                key = tuple(sorted([(a, if_short(lp)), (b, if_short(rp))]))
                cur = links.get(key)
                if cur:
                    cur["state"] = "down" if "down" in (cur["state"], st) else cur["state"]
                    cur["seen_both"] = True
                    continue
                links[key] = {"a": a, "b": b, "a_port": lp, "b_port": rp, "a_s": if_short(lp), "b_s": if_short(rp), "state": st, "proto": n.get("proto", "lldp"),
                              "speed": li.get("speed"), "desc": li.get("desc", ""), "seen_both": False}
            else:
                links[(a, if_short(lp), b, if_short(rp))] = {"a": a, "b": b, "a_port": lp, "b_port": rp, "a_s": if_short(lp), "b_s": if_short(rp), "state": st, "proto": n.get("proto", "lldp"),
                                                             "speed": li.get("speed"), "desc": li.get("desc", "")}
            nodes[a]["ports"] += 1
            nodes[b]["ports"] = nodes[b].get("ports", 0) + 1
    # 스위치 전면 포트 패널(2.4) — 포트별 사용 구분(구성 포함)
    for sn in snaps:
        nid = f"sw:{short(sn['name'])}"
        if nid in nodes:
            nodes[nid]["panel"] = panel(sn)
            nodes[nid]["usage"] = {k: sum(1 for p in nodes[nid]["panel"] if p["u"] == k) for k in ("in_use", "configured", "shut", "open", "err")}
            nodes[nid]["config_at"] = (sn.get("config") or {}).get("updated")
    # NSX Edge ↔ 물리 스위치 BGP(2.3)
    bgp_sessions = edge_bgp(engine, snaps, nodes, links, hosts, include_hosts, node)
    # NSX·Avi·VM·Pod 논리 계층(2.4)
    lay = LOGICAL if layers is None else set(layers)
    if lay and include_hosts:
        logical(engine, nodes, links, node, lay, vm_limit, pod_limit)
    # 계층
    adj: dict[str, set[str]] = {}
    for l in links.values():
        if l.get("kind") in ("bgp", "placement", "logical", "mgmt", "pool", "vnic", "pod"):
            continue
        adj.setdefault(l["a"], set()).add(l["b"])
        adj.setdefault(l["b"], set()).add(l["a"])
    for nid, n in nodes.items():
        if n.get("tier") is not None and n["kind"] not in ("switch", "external-switch", "device", "host", "server"):
            continue                                          # 논리 계층은 logical() 이 정함
        if n["kind"] == "edge":
            n["tier"] = 4
            continue
        if n["kind"] == "bgp-peer":
            n["tier"] = 2
            continue
        if n["kind"] in ("host", "server"):
            n["tier"] = 3
            continue
        if n.get("role") and n["role"].lower() in ROLE_TIER:
            n["tier"] = ROLE_TIER[n["role"].lower()]
            continue
        hint = next((t for rx, t in NAME_TIER if rx.search(n.get("label", ""))), None)
        if hint is not None:
            n["tier"] = hint
            continue
        nb = adj.get(nid, set())
        has_host = any(nodes[x]["kind"] in ("host", "server") for x in nb)
        if n["kind"] == "switch":
            n["tier"] = 2 if has_host else 1
        elif n["kind"] == "external-switch":
            n["tier"] = 2 if has_host else 0
        else:
            n["tier"] = 3 if all(nodes[x].get("tier", 2) >= 2 for x in nb if x in nodes and "tier" in nodes[x]) else 0
    # 고립 링크가 없는 외부 장치(관리망 등)는 그대로 둠 · 집계
    down = [l for l in links.values() if l["state"] == "down" and l.get("kind") in (None, "phys", "bgp")]
    summary = {"switches": len(sw_ids), "hosts": sum(1 for n in nodes.values() if n["kind"] == "host"),
               "servers": sum(1 for n in nodes.values() if n["kind"] == "server"),
               "external": sum(1 for n in nodes.values() if n["kind"] in ("external-switch", "device", "bgp-peer")),
               "edges": sum(1 for n in nodes.values() if n["kind"] == "edge"),
               "logical": {k: sum(1 for n in nodes.values() if n["kind"] in ks) for k, ks in
                           (("t0", ("t0",)), ("t1", ("t1",)), ("segment", ("segment", "portgroup", "vpc-subnet")), ("vpc", ("vpc",)), ("vm", ("vm", "vmgroup", "k8s-node")),
                            ("pod", ("pod", "podgroup")), ("se", ("se",)), ("vs", ("vs",)), ("controller", ("avi-ctrl",)))},
               "bgp_sessions": len(bgp_sessions), "bgp_down": sum(1 for b in bgp_sessions if b["state"] != "ESTABLISHED"),
               "links": sum(1 for l in links.values() if l.get("kind", "phys") == "phys"), "links_down": len(down), "switches_down": sum(1 for i in sw_ids if nodes[i]["state"] == "down"),
               "switches_warn": sum(1 for i in sw_ids if nodes[i]["state"] == "warn"),
               "vendors": sorted({n.get("vendor") for n in nodes.values() if n.get("vendor")}),
               "collectors": [{"name": c.name, "type": c.type, "state": c.state().get("state"), "error": c.state().get("last_error", "")[:160]} for c in conns]}
    return {"generated": time.time(), "nodes": sorted(nodes.values(), key=lambda n: (n.get("tier", 9), n.get("label", ""))),
            "links": list(links.values()), "summary": summary, "bgp": bgp_sessions, "tiers": TIER_NAMES, "layers": sorted(lay)}


def panel(sn: dict) -> list[dict]:
    """스위치 스냅샷 → 전면 패널 포트 목록 [{n 이름, s 짧은 이름, u 사용 구분, st 링크, p 상대, sp 속도, m 모드/VLAN}] (물리 포트만, 자연 정렬)"""
    from . import netconfig as NC
    from .portmap import nkey, port_kind
    nb = {if_short(n.get("local", "")): n for n in sn.get("neighbors") or []}
    pc = {if_short(k): v for k, v in (sn.get("port_cfg") or {}).items()}
    out = []
    for i in sn.get("ifaces") or []:
        if port_kind(i["name"]) != "phys":
            continue
        k = if_short(i["name"])
        n, c = nb.get(k), pc.get(k)
        st = i.get("state") or "unknown"
        if c and c.get("shutdown") and st != "up":
            st = "disabled"
        mode = ""
        if c:
            mode = ("routed " + (c.get("ip") or "")).strip() if c.get("routed") else \
                f"trunk {c.get('trunk_vlans') or 'all'}" if c.get("mode") == "trunk" else f"access {c.get('access_vlan') or 1}" if c.get("mode") == "access" or c.get("access_vlan") else ""
            if c.get("channel_group"):
                mode += f" · Po{c['channel_group']}"
        out.append({"n": i["name"], "s": k, "u": NC.port_usage(st, i.get("raw", ""), c, bool(n)), "st": st,
                    "p": f"{n.get('remote', '')} {n.get('remote_port', '')}".strip() if n else "", "lost": bool(n and n.get("state") == "lost"),
                    "sp": i.get("speed"), "d": i.get("desc") or (c or {}).get("desc", ""), "m": mode.strip()})
    out.sort(key=lambda p: nkey(p["n"]))
    return out[:256]


STACK_TIER = {"edge": 4, "se": 4, "edge-cluster": 5, "se-group": 5, "nsx-manager": 5, "t0": 6, "vs": 6, "t1": 7, "segment": 8, "portgroup": 8,
              "vm": 9, "vmgroup": 9, "k8s-node": 9, "pod": 10, "podgroup": 10}
LAYER_OF = {"edge": "nsx", "edge-cluster": "nsx", "nsx-manager": "nsx", "t0": "nsx", "t1": "nsx", "segment": "nsx", "portgroup": "vm",
            "se": "avi", "se-group": "avi", "vs": "avi", "vm": "vm", "vmgroup": "vm", "k8s-node": "vm", "pod": "pod", "podgroup": "pod"}


def logical(engine, nodes: dict, links: dict, node, lay: set[str], vm_limit: int, pod_limit: int) -> None:
    """stack.build(물리 → 논리) 결과를 구성도 노드·링크로 옮기고 VPC·Avi 컨트롤러·VS → 풀 멤버를 더한다."""
    from . import stack as ST
    try:
        g = ST.build(engine, vm_limit=vm_limit, pod_limit=pod_limit, vms="vm" in lay, pods="pod" in lay)
    except Exception:  # noqa: BLE001  (논리 계층 실패는 물리 구성도에 영향 주지 않음)
        return
    idmap: dict[str, str] = {}
    for n in g["nodes"]:
        k = n["kind"]
        if k == "esxi":
            hid = f"host:{short(n['label'])}"
            node(hid, label=n["label"], kind="host", state=n.get("state", "unknown"), cluster=n.get("group", ""), vcenter=n.get("vcenter", ""))
            idmap[n["id"]] = hid
            continue
        if k not in STACK_TIER or LAYER_OF.get(k) not in lay:
            continue
        if k == "edge":
            nid = f"edge:{short(n['label'])}"
        elif k == "se":
            nid = f"se:{short(n['label'])}"
        else:
            nid = "lg:" + n["id"]
        x = node(nid, label=n["label"], kind=k, state=n.get("state", "unknown"), detail=n.get("sub", ""), group=n.get("group", ""))
        x["tier"] = STACK_TIER[k]
        for f in ("ips", "os", "power", "host", "vcpu", "mem_gb", "ns", "ip", "node_name", "k8s_cluster", "networks"):
            if n.get(f) not in (None, "", []):
                x[f] = n[f]
        idmap[n["id"]] = nid
    for l in g["links"]:
        a, b = idmap.get(l["s"]), idmap.get(l["t"])
        if not a or not b or a == b:
            continue
        ka, kb = nodes[a]["kind"], nodes[b]["kind"]
        kind = "placement" if ka == "host" else "vnic" if kb in ("segment", "portgroup") or ka in ("segment", "portgroup") else "pod" if kb in ("pod", "podgroup") else "logical"
        links.setdefault((a, kind, b), {"a": a, "b": b, "a_port": "", "b_port": l.get("k", ""), "state": "up", "kind": kind, "proto": l.get("k", "")})
    conns = [c for c in getattr(engine, "connectors", []) if getattr(c, "enabled", True)]
    # ---- NSX VPC: 프로젝트(5) → VPC(7) ← T0(6), VPC → 서브넷(8) → VM(9)
    if "vpc" in lay or "nsx" in lay:
        vm_ids = {nodes[v]["label"].lower(): v for v in nodes if nodes[v]["kind"] in ("vm", "k8s-node")}
        for c in conns:
            if getattr(c, "type", "") != "nsx":
                continue
            inv = getattr(c, "inv", {}) or {}
            t0_ids = {nodes[x]["label"]: x for x in nodes if nodes[x]["kind"] == "t0"}
            t0_by_id = {t.get("id"): t.get("name") for t in inv.get("tier0", [])}
            for v in inv.get("vpcs", [])[:300]:
                pid = f"lg:proj:{c.name}:{v['project']}"
                x = node(pid, label=f"프로젝트 {v.get('project_name') or v['project']}", kind="vpc-project", state="ok", detail="NSX 프로젝트")
                x["tier"] = 5
                vid = f"lg:vpc:{c.name}:{v['project']}:{v['id']}"
                x = node(vid, label=v["name"], kind="vpc", state="ok", detail=f"VPC {v.get('short_id') or ''} {v.get('private') or ''}".strip())
                x["tier"] = 7
                links.setdefault((pid, "logical", vid), {"a": pid, "b": vid, "a_port": "", "b_port": "", "state": "up", "kind": "logical", "proto": "프로젝트"})
                t0 = t0_ids.get(t0_by_id.get(v.get("tier0"), "")) or t0_ids.get(v.get("tier0", ""))
                if t0:
                    links.setdefault((t0, "logical", vid), {"a": t0, "b": vid, "a_port": "", "b_port": "", "state": "up", "kind": "logical", "proto": "VPC 게이트웨이"})
                sub_ids = {}
                for sb in v.get("subnets", [])[:40]:
                    sid = f"lg:vpcsub:{c.name}:{v['id']}:{sb['id']}"
                    x = node(sid, label=sb["name"], kind="vpc-subnet", state="ok", detail=f"{sb.get('access', '')} {sb.get('cidr', '')}".strip())
                    x["tier"] = 8
                    sub_ids[sb["name"].lower()] = sid
                    links.setdefault((vid, "logical", sid), {"a": vid, "b": sid, "a_port": "", "b_port": "", "state": "up", "kind": "logical", "proto": "서브넷"})
                for vmn in v.get("vms", [])[:200]:
                    vmid = vm_ids.get(vmn.lower())
                    if not vmid:
                        continue
                    nets = [str(x).lower() for x in nodes[vmid].get("networks") or []]
                    tgt = next((sub_ids[nn] for nn in nets if nn in sub_ids), vid)
                    links.setdefault((tgt, "vnic", vmid), {"a": tgt, "b": vmid, "a_port": "", "b_port": "vNIC", "state": "up", "kind": "vnic", "proto": "VPC"})
    # ---- Avi: 컨트롤러(4) → SE 그룹·SE (관리), VS(6) → 풀 멤버 VM·Pod(9·10)
    if "avi" in lay:
        ipx = ST._ip_index(conns)
        lab = {nodes[x]["label"].lower(): x for x in nodes if nodes[x]["kind"] in ("vm", "k8s-node", "pod")}
        for c in conns:
            if getattr(c, "type", "") != "avi":
                continue
            ct = getattr(c, "controllers", None) or {}
            cid = f"avic:{c.name}"
            stt = "down" if c.state().get("state") == "down" else ("ok" if str(ct.get("state", "CLUSTER_UP")).startswith("CLUSTER_UP") else "warn")
            nds = ct.get("nodes") or []
            x = node(cid, label=f"Avi Controller {c.host.split(':')[0]}", kind="avi-ctrl", state=stt,
                     detail=f"{ct.get('state', '') or '클러스터 상태 미수집'} · 노드 {len(nds) or 1}" + (f" · {getattr(c, 'version', '')}" if getattr(c, "version", "") else ""),
                     nodes_detail=[f"{n.get('name')} {n.get('role', '').replace('CLUSTER_', '')} {n.get('state', '').replace('CLUSTER_', '')}" for n in nds])
            x["tier"] = 4
            for nid in [n for n in nodes if nodes[n]["kind"] in ("se-group",) or (nodes[n]["kind"] == "se" and not any(
                    l["a"] == n and nodes.get(l["b"], {}).get("kind") == "se-group" for l in links.values()))]:
                links.setdefault((cid, "mgmt", nid), {"a": cid, "b": nid, "a_port": "", "b_port": "", "state": "up", "kind": "mgmt", "proto": "관리"})
            vs_ids = {nodes[x]["label"]: x for x in nodes if nodes[x]["kind"] == "vs"}
            for v in (c.vips() if hasattr(c, "vips") else [])[:300]:
                vsid = vs_ids.get(v["name"])
                if not vsid:
                    continue
                mem = v.get("members") or [dict(x, pool=pl.get("name", "")) for pl in (getattr(c, "pools", None) or [])
                                           if pl.get("name") and pl["name"] in str(v.get("pool", "")).split(", ") for x in (pl.get("members") or [])]
                for m in mem[:64]:
                    hit = ipx.get(m.get("ip", ""))
                    tgt = lab.get(str((hit or {}).get("name", "")).lower()) if hit else None
                    if tgt:
                        links.setdefault((vsid, "pool", tgt), {"a": vsid, "b": tgt, "a_port": "", "b_port": f"{m.get('ip')}:{m.get('port', '')}", "state": "up",
                                                               "kind": "pool", "proto": f"풀 {m.get('pool', '')}"})


def _ip(a: str) -> str:
    return str(a or "").split("/")[0].strip().lower()


def edge_bgp(engine, snaps: list[dict], nodes: dict, links: dict, hosts: dict, include_hosts: bool, node) -> list[dict]:
    """NSX 커넥터 routing(T0 BGP 세션) → Edge 노드·BGP 링크. 세션 목록(표 화면용)을 돌려준다."""
    peer_idx: dict[str, tuple[dict, dict]] = {}          # 스위치가 보는 BGP 피어 주소 → (스위치 스냅샷, 피어 항목)
    mgmt_idx: dict[str, dict] = {}
    for s in snaps:
        for b in s.get("bgp") or []:
            peer_idx[_ip(b.get("peer"))] = (s, b)
        mgmt_idx[_ip(str(s.get("mgmt", "")).split(":")[0])] = s
        for a in s.get("addresses") or []:
            mgmt_idx[_ip(a)] = s
    by_moid = {h.get("moid"): (k, h) for k, h in hosts.items() if h.get("moid")}
    out: list[dict] = []
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") != "nsx" or not getattr(c, "enabled", True):
            continue
        rt = getattr(c, "routing", None) or {}
        if not rt.get("tier0"):
            continue
        estate = {}
        for e in (c.entities() if hasattr(c, "entities") else []):
            if e.get("kind") == "edge":
                estate[e.get("name")] = e.get("state", "unknown")
        info_by_name = {v.get("name"): v for v in (getattr(c, "edge_info", {}) or {}).values()}
        for g in rt["tier0"]:
            upl = {}
            for i in g.get("interfaces") or []:
                for ip in i.get("ips") or []:
                    upl[_ip(ip)] = i
            for s in g.get("sessions") or []:
                en = s.get("edge") or "edge"
                eid = f"edge:{short(en)}"
                ei = info_by_name.get(en, {})
                node(eid, label=en, kind="edge", state=estate.get(en, "unknown"), tier0=g["name"], local_as=g.get("local_as", ""),
                     edge_cluster=ei.get("edge_cluster", ""), mgmt=ei.get("mgmt_ip", ""), connector=c.name, detail=f"T0 {g['name']} · AS {g.get('local_as') or '-'}")
                if include_hosts and ei.get("host_moid") in by_moid:          # Edge VM 배치(ESXi)
                    hk, h = by_moid[ei["host_moid"]]
                    hid = f"host:{hk}"
                    node(hid, label=h["name"], kind="host", state=h["state"], cluster=h["cluster"], vcenter=h["vcenter"])
                    links.setdefault((eid, "placement", hid), {"a": hid, "b": eid, "a_port": "", "b_port": "VM", "state": "up", "kind": "placement", "proto": "vm"})
                src, nbr = _ip(s.get("source")), _ip(s.get("neighbor"))
                sw, sb = peer_idx.get(src, (None, None))
                how = "bgp-peer" if sw else ""
                if not sw and nbr in mgmt_idx:
                    sw, how = mgmt_idx[nbr], "mgmt"
                if sw:
                    pid = f"sw:{short(sw['name'])}"
                else:
                    pid = f"bgp:{nbr}"
                    node(pid, label=f"BGP {nbr}", kind="bgp-peer", state="unknown", detail=f"AS {s.get('remote_as') or '-'} · 수집 안 된 피어(스위치 커넥터를 추가하면 장비로 표시)")
                nst = s.get("state", "UNKNOWN")
                sst = str((sb or {}).get("state", "")).lower()
                st = "up" if nst == "ESTABLISHED" and (not sb or sst == "established") else "down"
                itf = upl.get(src) or {}
                key = (pid, "bgp", eid, nbr, src)
                links[key] = {"a": pid, "b": eid, "a_port": nbr, "b_port": src, "state": st, "kind": "bgp", "proto": "bgp",
                              "remote_as": s.get("remote_as", ""), "local_as": g.get("local_as", ""), "vlan": itf.get("vlan", ""), "segment": itf.get("segment", "")}
                out.append({"tier0": g["name"], "edge": en, "edge_state": estate.get(en, "unknown"), "edge_cluster": ei.get("edge_cluster", ""),
                            "local_as": g.get("local_as", ""), "source": s.get("source", ""), "uplink": itf.get("name", ""), "vlan": itf.get("vlan", ""),
                            "segment": itf.get("segment", ""), "neighbor": s.get("neighbor", ""), "remote_as": s.get("remote_as", ""),
                            "state": nst, "uptime_s": s.get("uptime_s"), "in_prefix": s.get("in_prefix"), "out_prefix": s.get("out_prefix"),
                            "drops": s.get("drops"), "switch": sw["name"] if sw else "", "switch_state": (sb or {}).get("state", ""),
                            "switch_vrf": (sb or {}).get("vrf", ""), "match": how, "nsx": c.name,
                            "mismatch": bool(sb) and (nst == "ESTABLISHED") != (sst == "established")})
    out.sort(key=lambda x: (x["state"] == "ESTABLISHED", x["tier0"], x["edge"], x["neighbor"]))
    return out


def device_rows(engine) -> list[dict]:
    out = []
    for c in getattr(engine, "connectors", []):
        if isinstance(c, NetDevice) and getattr(c, "enabled", True):
            s = c.snapshot()
            out.append({"state": s["state"], "name": s["name"], "vendor": s["vendor"], "model": s["model"], "os": f"{s['os']} {s['version']}".strip(),
                        "mgmt": s["mgmt"], "ports": f"{s['ifs_up']}/{s['ifs_total']}", "down": ", ".join(s["ifs_down_important"][:6]),
                        "nb": len(s["neighbors"]), "mlag": f"{s['mlag'].get('kind', '')} {s['mlag'].get('state', '')}".strip() if s["mlag"] else "",
                        "bgp": f"{sum(1 for b in s['bgp'] if str(b.get('state', '')).lower() == 'established')}/{len(s['bgp'])}" if s["bgp"] else "",
                        "conn": s["connector"], "error": s.get("error", "")})
    return out


def iface_down_rows(engine) -> list[dict]:
    out = []
    for c in getattr(engine, "connectors", []):
        if isinstance(c, NetDevice):
            s = c.snapshot()
            kl = {if_short(n.get("local", "")): n for n in s["neighbors"]}
            for i in s["ifaces"]:
                nb = kl.get(if_short(i["name"]))
                if i.get("state") == "down" and (i.get("desc") or nb):
                    out.append({"state": "down", "device": s["name"], "iface": i["name"], "raw": i.get("raw", ""), "desc": i.get("desc", ""),
                                "peer": f"{nb['remote']} {nb.get('remote_port', '')}".strip() if nb else ""})
            for n in s["neighbors"]:
                if n.get("state") == "lost" and not any(r["device"] == s["name"] and if_short(r["iface"]) == if_short(n.get("local", "")) for r in out):
                    out.append({"state": "warn", "device": s["name"], "iface": n.get("local", ""), "raw": "이웃 사라짐", "desc": "",
                                "peer": f"{n.get('remote', '')} {n.get('remote_port', '')}".strip()})
    return out


def _dur(sec) -> str:
    try:
        s = int(sec)
    except (TypeError, ValueError):
        return ""
    return f"{s // 86400}일 {s % 86400 // 3600}시간" if s >= 86400 else f"{s // 3600}시간 {s % 3600 // 60}분" if s >= 3600 else f"{s // 60}분"


def bgp_rows(engine) -> list[dict]:
    """관제 패널용 — NSX T0 BGP 세션(Edge ↔ 스위치)"""
    try:
        sess = build(engine, include_hosts=False).get("bgp", [])
    except Exception:  # noqa: BLE001
        return []
    return [{"state": "ok" if b["state"] == "ESTABLISHED" and not b["mismatch"] else "down" if b["state"] != "ESTABLISHED" else "warn",
             "tier0": b["tier0"], "edge": b["edge"], "source": f"{b['source']}{' · VLAN ' + str(b['vlan']) if b.get('vlan') else ''}",
             "neighbor": b["neighbor"], "remote_as": b["remote_as"], "switch": b["switch"] or "(미수집)",
             "sess": f"{b['state']}{' / ' + str(b['switch_state']) if b.get('switch_state') else ''}",
             "pfx": f"{b.get('in_prefix') if b.get('in_prefix') is not None else '-'} / {b.get('out_prefix') if b.get('out_prefix') is not None else '-'}",
             "up": _dur(b.get("uptime_s")) if b["state"] == "ESTABLISHED" else ""} for b in sess]
