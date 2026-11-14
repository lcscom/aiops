"""고객 환경 토폴로지 — 지금 연결된 커넥터가 실제로 본 것만으로 VCF 구성을 조립(정적 그림 아님).

  VCF 인스턴스(SDDC Manager) ─ 워크로드 도메인(관리·VI) ─ vCenter ─ 클러스터 ─ ESXi 호스트 ─ 서버 BMC(Redfish·CIMC)
                                                       └ NSX Manager ─ Edge        └ 데이터스토어   └ VM 에이전트 수
                                                       └ Supervisor ─ VKS 워크로드 클러스터 ─ 노드·파드
  NSX ALB(Avi) 컨트롤러 ─ Service Engine · 가상 서비스(VIP)
  관리·운영: VCF Operations · Operations for logs · VCF Automation · SRM
SDDC Manager 커넥터가 없으면 vCenter·NSX 를 커넥터 이름·환경(environment)으로 묶은 '추정 도메인'으로 보여 준다.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any

MGMT_TYPES = {"vcfops": "VCF Operations", "vcflogs": "Operations for logs", "vcfa": "VCF Automation", "srm": "Live Site Recovery(SRM)"}
SEV_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}


def _short(h: str) -> str:
    h = str(h or "").split(":")[0].lower()
    return h if re.fullmatch(r"[\d.]+", h) else h.split(".")[0]


def _conn_state(c) -> dict[str, Any]:
    s = c.state()
    return {"connector": c.name, "type": c.type, "target": s.get("target") or c.host, "state": s.get("state", "init"),
            "error": (s.get("last_error") or "")[:200], "last_ok": s.get("last_ok"), "latency_ms": s.get("latency_ms")}


def _host_state(h: dict) -> str:
    conn, ov = h.get("conn", ""), h.get("status", "")
    if conn not in ("connected", ""):
        return "down"
    if h.get("maintenance"):
        return "maint"
    return {"red": "down", "yellow": "warn"}.get(ov, "ok" if ov in ("green", "gray", "") else "unknown")


def build(engine) -> dict[str, Any]:
    conns = [c for c in engine.connectors if c.enabled and c.type not in ("demo", "syslog", "snmp")]
    bmc = engine.bmc_inventory() if hasattr(engine, "bmc_inventory") else {}
    bmc_by_short = {_short(k): v for k, v in bmc.items()}
    agents = getattr(engine.agents, "items", {}) if getattr(engine, "agents", None) else {}
    agent_by_host = {k.lower(): v for k, v in agents.items()} if isinstance(agents, dict) else {}

    # 커넥터 상태 기반 개체 상태 판정 보조
    redfish_state = {}
    for c in conns:
        if c.type == "redfish":
            for e in c.entities():
                redfish_state[_short(c.cfg.get("esxi_host") or getattr(c, "display", ""))] = e.get("state", "unknown")

    vcenters, by_fqdn = [], {}
    for c in [c for c in conns if c.type == "vcenter"]:
        t = getattr(c, "topology", {}) or {}
        hf = (getattr(c, "health", {}) or {}).get("findings", [])
        fcount: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "error": 0, "warning": 0})
        for f in hf:
            if f["severity"] in ("critical", "error", "warning"):
                ent = f["entity"].split("/")[0]
                fcount[ent][f["severity"]] += 1
        vms_by_host: dict[str, list[str]] = defaultdict(list)
        for vn, v in (t.get("vms") or {}).items():
            if v.get("power") == "poweredOn":
                vms_by_host[v.get("host", "")].append(vn)
        clusters = []
        for cn, cl in sorted((t.get("clusters") or {}).items()):
            hosts = []
            for hn in sorted(cl.get("hosts", [])):
                h = t["hosts"].get(hn, {})
                b = bmc.get(hn) or bmc_by_short.get(_short(hn))
                vml = vms_by_host.get(hn, [])
                ag = sum(1 for v in vml if v.lower() in agent_by_host or _short(v) in agent_by_host)
                hosts.append({"name": hn, "state": _host_state(h), "conn": h.get("conn", ""), "maint": bool(h.get("maintenance")),
                              "vms": len(vml), "agents": ag,
                              "cpu_pct": round(h["cpu_used_mhz"] / h["cpu_mhz"] * 100) if h.get("cpu_mhz") else None,
                              "mem_pct": round(h["mem_used_mb"] / h["mem_mb"] * 100) if h.get("mem_mb") else None,
                              "bmc": {"connector": b["connector"], "state": redfish_state.get(_short(hn), "unknown"), "health": b.get("health", ""),
                                      "fw": b.get("bmc_fw", "")} if b else None,
                              "findings": fcount.get(hn) or None})
            hs = set(cl.get("hosts", []))
            dss = sorted(({"name": dn, "used_pct": d.get("used_pct"), "type": d.get("type", ""), "cap_gb": d.get("capacity_gb")}
                          for dn, d in (t.get("datastores") or {}).items() if hs and len(hs & set(d.get("hosts", []))) >= max(1, len(hs) // 2)),
                         key=lambda x: -(x["used_pct"] or 0))
            sup = next((s for s in (getattr(c, "vks", {}) or {}).get("supervisors", []) if s.get("name") == cn), None)
            clusters.append({"name": cn, "ha": cl.get("ha"), "drs": cl.get("drs"), "vsan": cl.get("vsan"), "hosts": hosts,
                             "datastores": dss[:12], "datastores_total": len(dss),
                             "supervisor": {"endpoint": sup.get("endpoint", ""), "status": sup.get("config_status", ""),
                                            "k8s": sup.get("kubernetes_status", ""), "namespaces": len(sup.get("namespaces") or [])} if sup else None,
                             "findings": fcount.get(cn) or None,
                             "state": "down" if any(x["state"] == "down" for x in hosts) else "warn" if any(x["state"] in ("warn", "maint") for x in hosts) else "ok"})
        vc = {**_conn_state(c), "id": f"vc:{c.name}", "name": c.host.split(":")[0], "environment": c.cfg.get("environment", ""),
              "clusters": clusters, "hosts": len(t.get("hosts") or {}), "vms": len(t.get("vms") or {}),
              "topology_at": t.get("updated", 0), "health_at": (getattr(c, "health", {}) or {}).get("updated", 0)}
        vcenters.append(vc)
        by_fqdn[c.host.split(":")[0].lower()] = vc["id"]
        by_fqdn[_short(c.host)] = vc["id"]

    nsx = []
    for c in [c for c in conns if c.type == "nsx"]:
        ents = c.entities()
        nsx.append({**_conn_state(c), "id": f"nsx:{c.name}", "name": c.host.split(":")[0],
                    "managers": [e for e in ents if e.get("kind") == "manager"], "edges": [e for e in ents if e.get("kind") == "edge"][:60],
                    "environment": c.cfg.get("environment", "")})
        by_fqdn[c.host.split(":")[0].lower()] = f"nsx:{c.name}"
        by_fqdn[_short(c.host)] = f"nsx:{c.name}"

    avi = []
    for c in [c for c in conns if c.type == "avi"]:
        vips = c.vips() if hasattr(c, "vips") else []
        ents = c.entities()
        avi.append({**_conn_state(c), "id": f"avi:{c.name}", "name": c.host.split(":")[0],
                    "se": [e for e in ents if e.get("kind") == "SE"][:40],
                    "vs": [{k: v.get(k) for k in ("name", "state", "vips", "health", "last", "uuid")} for v in vips][:80],
                    "vs_total": len(vips) or len([e for e in ents if e.get("kind") == "VS"])})

    vks = []
    for c in [c for c in conns if c.type == "vks"]:
        inv = getattr(c, "inv", {}) or {}
        pods = inv.get("pods", [])
        bad = [p for p in pods if p.get("reason") or p.get("phase") not in ("Running", "Succeeded")]
        nodes = inv.get("nodes", [])
        vks.append({**_conn_state(c), "id": f"vks:{c.name}", "name": getattr(c, "cluster_label", c.name), "role": getattr(c, "role", "workload"),
                    "discovered_by": getattr(c, "discovered_by", ""), "supervisor": c.cfg.get("supervisor", ""),
                    "nodes": [{"name": n.get("name"), "ready": n.get("ready"), "roles": n.get("roles", [])} for n in nodes][:60],
                    "nodes_ready": sum(1 for n in nodes if str(n.get("ready")) in ("True", "true", "Ready")), "nodes_total": len(nodes),
                    "pods_total": len(pods), "pods_problem": len(bad),
                    "problem_pods": [f"{p['ns']}/{p['name']} {p.get('reason', '')}".strip() for p in bad][:8],
                    "clusters": inv.get("clusters", [])[:40]})

    mgmt = [{**_conn_state(c), "id": f"{c.type}:{c.name}", "label": MGMT_TYPES[c.type], "name": c.host.split(":")[0]}
            for c in conns if c.type in MGMT_TYPES]
    bmcs = [{**_conn_state(c), "id": f"bmc:{c.name}", "name": getattr(c, "display", c.name), "esxi": c.cfg.get("esxi_host", ""),
             "vendor": getattr(c, "vendor", ""), "model": (getattr(c, "server", {}) or {}).get("model", ""),
             "linked": bool(c.cfg.get("esxi_host")) and any(_short(c.cfg.get("esxi_host")) == _short(h["name"]) for v in vcenters for cl in v["clusters"] for h in cl["hosts"])}
            for c in conns if c.type == "redfish"]

    # 도메인: SDDC Manager 가 알려 준 것 우선, 없으면 environment/이름 기준 추정
    domains, used = [], set()
    sddc = []
    for c in [c for c in conns if c.type == "sddc"]:
        doms = []
        for d in getattr(c, "domains", []) or []:
            vcs = [by_fqdn.get(f.lower()) or by_fqdn.get(_short(f)) for f in d.get("vcenters", [])]
            nx = by_fqdn.get(str(d.get("nsx", "")).lower()) or by_fqdn.get(_short(d.get("nsx", "")))
            ids = [x for x in vcs if x] + ([nx] if nx else [])
            used.update(ids)
            doms.append({"name": d["name"], "type": d.get("type", ""), "status": d.get("status", ""), "members": ids,
                         "vcenter_fqdns": d.get("vcenters", []), "nsx_fqdn": d.get("nsx", ""), "clusters": d.get("clusters", 0), "source": "sddc"})
        sddc.append({**_conn_state(c), "id": f"sddc:{c.name}", "name": c.host.split(":")[0], "domains": doms})
        domains += doms
    rest = defaultdict(list)
    for x in vcenters + nsx:
        if x["id"] not in used:
            rest[x.get("environment") or "기타"].append(x["id"])
    for env, ids in rest.items():
        domains.append({"name": env if env != "기타" else "SDDC Manager 미연결", "type": "추정", "status": "", "members": ids, "source": "inferred"})

    agent_total = len(agent_by_host)
    agent_ok = sum(1 for a in agent_by_host.values() if isinstance(a, dict) and a.get("state") in ("ok", "healthy", "new"))
    counts = {"vcenters": len(vcenters), "clusters": sum(len(v["clusters"]) for v in vcenters),
              "hosts": sum(v["hosts"] for v in vcenters), "vms": sum(v["vms"] for v in vcenters), "nsx": len(nsx),
              "edges": sum(len(n["edges"]) for n in nsx), "avi": len(avi), "vips": sum(a["vs_total"] for a in avi),
              "vks": len([v for v in vks if v["role"] != "supervisor"]), "supervisors": len([v for v in vks if v["role"] == "supervisor"]),
              "bmc": len(bmcs), "agents": agent_total, "agents_ok": agent_ok}
    return {"updated": time.time(), "counts": counts, "sddc": sddc, "domains": domains, "vcenters": vcenters, "nsx": nsx,
            "avi": avi, "vks": vks, "mgmt": mgmt, "bmc": bmcs,
            "empty": not (vcenters or nsx or avi or vks or mgmt or bmcs or sddc)}
