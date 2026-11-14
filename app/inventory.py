"""전체 인벤토리 — 연결된 커넥터가 수집한 모든 개체를 한 표 형식(kind·name·state·connector·parent·필드)으로 모은다.

  vCenter : VM · ESXi 호스트 · 클러스터 · 데이터스토어 · 네트워크(포트그룹·분산 포트그룹)
  NSX     : Manager · Edge · Edge 클러스터 · Tier-0 · Tier-1 · 세그먼트 (Policy API, 10분)
  NSX ALB : 가상 서비스(VIP) · 서비스 엔진 · 풀
  VKS     : 클러스터(Supervisor·워크로드) · 노드 · 파드
  서버 BMC: 서버(모델·S/N·BIOS·BMC 펌웨어·전원·상태)
  에이전트: VM 게스트·물리 서버 OS(Fluent Bit·rsyslog)
  구성요소: 커넥터 자체(SDDC Manager·vCenter·NSX·ALB·Ops·logs·Automation·SRM…)
"""
from __future__ import annotations

import csv
import io
import time
from typing import Any

KINDS: dict[str, dict[str, Any]] = {
    "vm": {"label": "VM", "group": "vSphere", "cols": [("power", "전원"), ("host", "호스트"), ("cluster", "클러스터"), ("os", "게스트 OS"),
                                                     ("ips", "IP"), ("vcpu", "vCPU"), ("mem_gb", "메모리(GB)"), ("disk_gb", "사용(GB)"),
                                                     ("prov_gb", "할당(GB)"), ("tools", "VMware Tools"), ("snapshots", "스냅숏"), ("networks", "네트워크"),
                                                     ("datastores", "데이터스토어"), ("hw", "HW 버전")]},
    "host": {"label": "ESXi 호스트", "group": "vSphere", "cols": [("cluster", "클러스터"), ("conn", "연결"), ("maint", "유지보수"), ("vendor", "제조사"),
                                                              ("model", "모델"), ("serial", "S/N"), ("esxi", "ESXi"), ("bios", "BIOS"), ("cpu", "CPU"),
                                                              ("cores", "코어"), ("mem_gb", "메모리(GB)"), ("cpu_pct", "CPU%"), ("mem_pct", "메모리%"),
                                                              ("vms", "VM"), ("bmc", "BMC")]},
    "cluster": {"label": "클러스터", "group": "vSphere", "cols": [("hosts", "호스트"), ("vms", "VM"), ("ha", "HA"), ("drs", "DRS"), ("vsan", "vSAN"),
                                                             ("cpu_ghz", "CPU(GHz)"), ("mem_gb", "메모리(GB)"), ("cpu_pct", "CPU%"), ("mem_pct", "메모리%")]},
    "datastore": {"label": "데이터스토어", "group": "vSphere", "cols": [("type", "유형"), ("capacity_gb", "용량(GB)"), ("free_gb", "여유(GB)"),
                                                                  ("used_pct", "사용률%"), ("hosts", "호스트 수"), ("vms", "VM 수")]},
    "network": {"label": "네트워크", "group": "vSphere", "cols": [("type", "유형"), ("dvs", "분산 스위치"), ("vlan", "VLAN"), ("hosts", "호스트 수"), ("vms", "VM 수")]},
    "nsx-manager": {"label": "NSX Manager", "group": "NSX", "cols": [("detail", "상태")]},
    "nsx-edge": {"label": "NSX Edge", "group": "NSX", "cols": [("detail", "상태"), ("edge_cluster", "Edge 클러스터"), ("esxi", "실행 호스트"), ("mgmt_ip", "관리 IP"), ("form", "크기")]},
    "nsx-edge-cluster": {"label": "Edge 클러스터", "group": "NSX", "cols": [("members", "멤버")]},
    "nsx-t0": {"label": "Tier-0", "group": "NSX", "cols": [("ha_mode", "HA 모드"), ("failover", "페일오버")]},
    "nsx-t1": {"label": "Tier-1", "group": "NSX", "cols": [("tier0", "연결 Tier-0"), ("edge_cluster", "서비스(Edge)")]},
    "nsx-segment": {"label": "세그먼트", "group": "NSX", "cols": [("type", "유형"), ("connected_to", "연결 게이트웨이"), ("gateway", "게이트웨이 주소"),
                                                              ("vlan", "VLAN"), ("tz", "전송 영역"), ("admin", "관리 상태")]},
    "avi-vs": {"label": "가상 서비스(VIP)", "group": "NSX ALB", "cols": [("vips", "VIP"), ("ports", "포트"), ("health", "Health"), ("bw", "대역폭(bps)"),
                                                                    ("rps", "요청/초"), ("pool", "풀"), ("se_group", "SE 그룹")]},
    "avi-se": {"label": "서비스 엔진", "group": "NSX ALB", "cols": [("detail", "상태"), ("se_group", "SE 그룹"), ("esxi", "실행 호스트"), ("mgmt_ip", "관리 IP"), ("vs", "가상 서비스")]},
    "avi-pool": {"label": "풀", "group": "NSX ALB", "cols": [("servers", "서버"), ("up", "정상 서버"), ("health", "Health")]},
    "vks-cluster": {"label": "VKS 클러스터", "group": "VKS", "cols": [("role", "역할"), ("nodes", "노드"), ("ready", "Ready"), ("pods", "파드"), ("problem", "문제 파드")]},
    "k8s-node": {"label": "노드", "group": "VKS", "cols": [("cluster", "클러스터"), ("roles", "역할"), ("ready", "Ready")]},
    "pod": {"label": "파드", "group": "VKS", "cols": [("cluster", "클러스터"), ("ns", "네임스페이스"), ("node", "노드"), ("phase", "상태"),
                                                  ("ready_c", "Ready"), ("restarts", "재시작"), ("reason", "사유"), ("owner", "소유자")]},
    "server": {"label": "서버(BMC)", "group": "서버", "cols": [("esxi", "ESXi"), ("vendor", "제조사"), ("model", "모델"), ("serial", "S/N"), ("bios", "BIOS"),
                                                          ("bmc_fw", "BMC 펌웨어"), ("power", "전원"), ("health", "Health"), ("bmc", "BMC 주소")]},
    "ucs-fi": {"label": "UCS 패브릭 인터커넥트", "group": "서버", "cols": [("domain", "UCS 도메인"), ("model", "모델"), ("serial", "S/N"), ("ip", "관리 IP"), ("leadership", "리더십"), ("oper", "상태")]},
    "ucs-chassis": {"label": "UCS 섀시", "group": "서버", "cols": [("domain", "UCS 도메인"), ("model", "모델"), ("serial", "S/N"), ("oper", "상태"), ("power", "전원")]},
    "agent": {"label": "에이전트", "group": "서버", "cols": [("type", "대상"), ("os", "OS"), ("distro", "배포판"), ("agent", "에이전트"), ("role", "역할"),
                                                         ("last", "마지막 수신")]},
    "component": {"label": "구성요소(커넥터)", "group": "구성요소", "cols": [("type", "제품"), ("target", "대상"), ("latency_ms", "지연(ms)"),
                                                                     ("last_ok", "마지막 성공"), ("error", "오류")]},
}
STATE_OF_CONN = {"ok": "ok", "degraded": "warn", "down": "down", "init": "unknown", "disabled": "maint"}


def _pct(a, b):
    return round(a / b * 100) if b else None


def _host_state(h: dict) -> str:
    conn, ov = h.get("conn", ""), h.get("status", "")
    if conn not in ("connected", ""):
        return "down"
    if h.get("maintenance"):
        return "maint"
    return {"red": "down", "yellow": "warn"}.get(ov, "ok")


def build(engine) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    add = lambda kind_, name_, state_, conn_, parent_="", **f: rows.append(  # noqa: E731
        {"kind": kind_, "name": str(name_), "state": state_, "connector": conn_, "parent": parent_, **f})
    bmc = engine.bmc_inventory() if hasattr(engine, "bmc_inventory") else {}
    for c in [c for c in engine.connectors if c.enabled and c.type not in ("demo",)]:
        st = c.state() if hasattr(c, "state") else {}
        if c.type not in ("syslog", "snmp"):
            add("component", c.name, STATE_OF_CONN.get(st.get("state", ""), "unknown"), c.name, "",
                type=c.type, target=st.get("target") or c.host, latency_ms=st.get("latency_ms"), last_ok=st.get("last_ok"),
                error=(st.get("last_error") or "")[:200])
        if c.type == "vcenter":
            t = getattr(c, "topology", {}) or {}
            snap = (getattr(c, "health_snap", {}) or {}).get("hosts", {})
            vms_on_ds: dict[str, int] = {}
            vm_per_cl: dict[str, int] = {}
            for vn, v in (t.get("vms") or {}).items():
                for d in v.get("datastores", []):
                    vms_on_ds[d] = vms_on_ds.get(d, 0) + 1
                vm_per_cl[v.get("cluster", "")] = vm_per_cl.get(v.get("cluster", ""), 0) + 1
                pw = v.get("power", "")
                add("vm", vn, "ok" if pw == "poweredOn" else ("maint" if pw == "suspended" else "off"), c.name, v.get("host", ""),
                    power={"poweredOn": "켜짐", "poweredOff": "꺼짐", "suspended": "일시 중지"}.get(pw, pw), host=v.get("host", ""),
                    cluster=v.get("cluster", ""), os=v.get("os", ""), ips=", ".join(v.get("ips", [])), vcpu=v.get("vcpu"),
                    mem_gb=round((v.get("mem_mb") or 0) / 1024, 1) if v.get("mem_mb") else None, disk_gb=v.get("disk_gb"), prov_gb=v.get("prov_gb"),
                    tools=v.get("tools", "").replace("guestTools", ""), snapshots=v.get("snapshots"), networks=", ".join(v.get("networks", [])),
                    datastores=", ".join(v.get("datastores", [])), hw=v.get("hw", ""), hostname=v.get("hostname", ""), uuid=v.get("uuid", ""),
                    vcenter=c.host)
            for hn, h in (t.get("hosts") or {}).items():
                hs = snap.get(hn, {})
                b = bmc.get(hn) or next((x for k, x in bmc.items() if k.split(".")[0].lower() == hn.split(".")[0].lower()), None)
                add("host", hn, _host_state(h), c.name, h.get("cluster", ""), cluster=h.get("cluster", ""), conn=h.get("conn", ""),
                    maint="예" if h.get("maintenance") else "", vendor=hs.get("vendor", ""), model=hs.get("model", ""), serial=hs.get("serial", ""),
                    esxi=f"{hs.get('version', '')} ({hs.get('build', '')})" if hs.get("build") else "", bios=hs.get("bios", ""),
                    cpu=hs.get("cpu_model", ""), cores=hs.get("cores"), mem_gb=round((h.get("mem_mb") or 0) / 1024),
                    cpu_pct=_pct(h.get("cpu_used_mhz") or 0, h.get("cpu_mhz") or 0), mem_pct=_pct(h.get("mem_used_mb") or 0, h.get("mem_mb") or 0),
                    vms=h.get("vms"), bmc=(b or {}).get("connector", ""), vcenter=c.host)
            for cn, cl in (t.get("clusters") or {}).items():
                hl = [t["hosts"].get(x, {}) for x in cl.get("hosts", [])]
                cap = sum(x.get("cpu_mhz") or 0 for x in hl)
                mem = sum(x.get("mem_mb") or 0 for x in hl)
                bad = any(_host_state(x) == "down" for x in hl)
                add("cluster", cn, "down" if bad else "warn" if any(_host_state(x) in ("warn", "maint") for x in hl) else "ok", c.name, c.host,
                    hosts=len(hl), vms=vm_per_cl.get(cn, 0), ha="예" if cl.get("ha") else ("" if cl.get("ha") is None else "아니오"),
                    drs="예" if cl.get("drs") else ("" if cl.get("drs") is None else "아니오"), vsan="예" if cl.get("vsan") else "",
                    cpu_ghz=round(cap / 1000, 1), mem_gb=round(mem / 1024), cpu_pct=_pct(sum(x.get("cpu_used_mhz") or 0 for x in hl), cap),
                    mem_pct=_pct(sum(x.get("mem_used_mb") or 0 for x in hl), mem))
            for dn, d in (t.get("datastores") or {}).items():
                u = d.get("used_pct") or 0
                add("datastore", dn, "down" if u >= 95 else "warn" if u >= 85 else "ok", c.name, c.host, type=d.get("type", ""),
                    capacity_gb=d.get("capacity_gb"), free_gb=d.get("free_gb"), used_pct=d.get("used_pct"),
                    hosts=len(d.get("hosts") or []), vms=vms_on_ds.get(dn, 0))
            for nn, n in (t.get("networks") or {}).items():
                add("network", nn, "ok" if n.get("accessible") is not False else "warn", c.name, c.host,
                    type={"dvportgroup": "분산 포트그룹", "portgroup": "표준 포트그룹", "opaque": "NSX 세그먼트"}.get(n.get("kind"), n.get("kind")),
                    dvs=n.get("dvs", ""), vlan=n.get("vlan", ""), hosts=n.get("hosts"), vms=n.get("vms"))
        elif c.type == "nsx":
            hmo = {h.get("moid"): hn for vc in engine.connectors if getattr(vc, "type", "") == "vcenter" for hn, h in (getattr(vc, "topology", {}) or {}).get("hosts", {}).items()}
            ei = {v.get("name"): v for v in (getattr(c, "edge_info", {}) or {}).values()}
            for e in c.entities():
                k = "nsx-manager" if e.get("kind") == "manager" else "nsx-edge" if e.get("kind") == "edge" else None
                if k:
                    x = ei.get(e["name"], {}) if k == "nsx-edge" else {}
                    add(k, e["name"], e.get("state", "unknown"), c.name, c.host, detail=e.get("detail", "").split(" · ")[0],
                        edge_cluster=x.get("edge_cluster", ""), esxi=hmo.get(x.get("host_moid"), ""), mgmt_ip=x.get("mgmt_ip", ""), form=x.get("form", ""))
            inv = getattr(c, "inv", {}) or {}
            for x in inv.get("edge_clusters", []):
                add("nsx-edge-cluster", x["name"], "ok", c.name, c.host, members=x.get("members"))
            for x in inv.get("tier0", []):
                add("nsx-t0", x["name"], "ok", c.name, c.host, ha_mode=x.get("ha_mode", ""), failover=x.get("failover", ""))
            for x in inv.get("tier1", []):
                add("nsx-t1", x["name"], "ok", c.name, x.get("tier0", ""), tier0=x.get("tier0", ""), edge_cluster="예" if x.get("edge_cluster") else "")
            for x in inv.get("segments", []):
                add("nsx-segment", x["name"], "maint" if str(x.get("admin", "")).upper() == "DOWN" else "ok", c.name, x.get("connected_to", ""),
                    type=x.get("type", ""), connected_to=x.get("connected_to", ""), gateway=x.get("gateway", ""), vlan=x.get("vlan", ""),
                    tz=x.get("tz", ""), admin=x.get("admin", ""))
        elif c.type == "avi":
            vips = c.vips() if hasattr(c, "vips") else []
            seen = set()
            for v in vips:
                seen.add(v["name"])
                L = v.get("last") or {}
                add("avi-vs", v["name"], "ok" if v.get("state") == "OPER_UP" else ("unknown" if not v.get("state") else "down"), c.name, c.host,
                    vips=", ".join(v.get("vips") or []), ports=", ".join(str(p) for p in v.get("ports") or []), health=v.get("health"),
                    bw=L.get("bw"), rps=L.get("rps"), pool=v.get("pool", ""), se_group=v.get("se_group", ""))
            for e in c.entities():
                if e.get("kind") == "SE":
                    se = (getattr(c, "se", {}) or {}).get(e["name"], {})
                    add("avi-se", e["name"], e.get("state", "unknown"), c.name, se.get("host") or c.host, detail=e.get("detail", ""),
                        se_group=se.get("se_group", ""), esxi=se.get("host", ""), mgmt_ip=se.get("mgmt_ip", ""), vs=", ".join(se.get("vs", [])[:8]))
                elif e.get("kind") == "VS" and e["name"] not in seen:
                    add("avi-vs", e["name"], e.get("state", "unknown"), c.name, c.host)
            for p in getattr(c, "pools", []) or []:
                add("avi-pool", p["name"], "ok" if p.get("state") == "OPER_UP" else ("unknown" if not p.get("state") else "down"), c.name, c.host,
                    servers=p.get("servers"), up=p.get("up"), health=p.get("health"))
        elif c.type == "vks":
            inv = getattr(c, "inv", {}) or {}
            label = getattr(c, "cluster_label", c.name)
            nodes, pods = inv.get("nodes", []), inv.get("pods", [])
            bad = [p for p in pods if p.get("reason") or p.get("phase") not in ("Running", "Succeeded")]
            rdy = sum(1 for n in nodes if str(n.get("ready")) in ("True", "true"))
            add("vks-cluster", label, "down" if nodes and rdy < len(nodes) else "warn" if bad else STATE_OF_CONN.get(st.get("state", ""), "unknown"),
                c.name, c.cfg.get("supervisor", ""), role="Supervisor" if getattr(c, "role", "") == "supervisor" else "워크로드",
                nodes=len(nodes), ready=rdy, pods=len(pods), problem=len(bad))
            for n in nodes:
                add("k8s-node", n.get("name", ""), "ok" if str(n.get("ready")) in ("True", "true") else "down", c.name, label,
                    cluster=label, roles=", ".join(n.get("roles") or []), ready=n.get("ready"))
            for p in pods:
                pb = p.get("reason") or p.get("phase") not in ("Running", "Succeeded")
                add("pod", p.get("name", ""), "down" if p.get("phase") == "Failed" else "warn" if pb else "ok", c.name, label,
                    cluster=label, ns=p.get("ns", ""), node=p.get("node", ""), phase=p.get("phase", ""), ready_c=p.get("ready", ""),
                    restarts=p.get("restarts"), reason=p.get("reason", ""), owner=p.get("owner", ""))
        elif c.type == "ucsm":
            u = getattr(c, "ucs", {}) or {}
            dom = (u.get("system") or {}).get("name") or c.name
            for f in u.get("fis", []):
                add("ucs-fi", f"{dom} FI-{f['id']}", f.get("state", "unknown"), c.name, dom, domain=dom, model=f.get("model", ""), serial=f.get("serial", ""),
                    ip=f.get("ip", ""), leadership=f.get("leadership", ""), oper=f.get("oper", ""))
            for ch in u.get("chassis", []):
                add("ucs-chassis", f"{dom} chassis-{ch['id']}", ch.get("state", "unknown"), c.name, dom, domain=dom, model=ch.get("model", ""),
                    serial=ch.get("serial", ""), oper=ch.get("oper", ""), power=ch.get("power", ""))
            for b in c.servers():
                from .stack import host_for_hw
                esx = host_for_hw(engine.connectors, b.get("uuid", ""), b.get("serial", ""))
                add("server", b.get("profile") or b["dn"], b.get("state", "unknown"), c.name, esx or b.get("profile", ""), esxi=esx,
                    vendor=f"Cisco UCS ({b['dn'].replace('sys/', '')})", model=b.get("model", ""), serial=b.get("serial", ""), power=b.get("power", ""),
                    health=b.get("oper", ""), bmc=f"UCSM {c.host}")
        elif c.type == "redfish":
            s = getattr(c, "server", {}) or {}
            h = s.get("health", "")
            add("server", getattr(c, "display", c.name), "down" if h == "Critical" or s.get("power") in ("Off", "off") else "warn" if h == "Warning" else
                ("ok" if s else "unknown"), c.name, c.cfg.get("esxi_host", ""), esxi=c.cfg.get("esxi_host", ""), vendor=s.get("manufacturer") or getattr(c, "vendor", ""),
                model=s.get("model", ""), serial=s.get("serial", ""), bios=s.get("bios", ""), bmc_fw=s.get("bmc_fw", ""), power=s.get("power", ""),
                health=h, bmc=c.host)
    ag = getattr(getattr(engine, "agents", None), "items", None)
    if isinstance(ag, dict):
        for it in ag.values():
            if not isinstance(it, dict) or it.get("retired"):
                continue
            last = max(it.get("last_seen") or 0, it.get("last_hb") or 0)
            stv = it.get("state", "unknown")
            add("agent", it.get("host", "?"), {"ok": "ok", "healthy": "ok", "new": "ok", "stale": "down", "silent": "down", "warn": "warn"}.get(stv, "unknown"),
                "agent", it.get("vm", ""), type="물리 서버" if it.get("kind") == "baremetal" else "VM", os=it.get("os", ""),
                distro=(it.get("info") or {}).get("distro", ""), agent=it.get("agent", ""), role=it.get("role", ""), last=last or None)
    return rows


def query(rows: list[dict], kind: str = "", q: str = "", state: str = "", connector: str = "", sort: str = "name", desc: bool = False,
          offset: int = 0, limit: int = 500) -> dict[str, Any]:
    counts: dict[str, int] = {}
    states: dict[str, int] = {}
    for r in rows:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
    sel = [r for r in rows if (not kind or r["kind"] == kind)]
    if connector:
        sel = [r for r in sel if r["connector"] == connector]
    if q:
        terms = q.lower().split()
        sel = [r for r in sel if all(t in " ".join(str(v) for v in r.values() if v is not None).lower() for t in terms)]
    for r in sel:
        states[r["state"]] = states.get(r["state"], 0) + 1
    if state:
        sel = [r for r in sel if r["state"] in state.split(",")]
    order = {"down": 0, "warn": 1, "unknown": 2, "maint": 3, "off": 4, "ok": 5}

    def val(r):
        return order.get(r["state"], 9) if sort == "state" else r.get(sort)
    have = [r for r in sel if val(r) not in (None, "")]
    have.sort(key=lambda r: (0, val(r), "") if isinstance(val(r), (int, float)) else (1, 0, str(val(r)).lower()), reverse=desc)
    sel = have + [r for r in sel if val(r) in (None, "")]            # 빈 값은 항상 뒤로
    return {"total": len(sel), "counts": counts, "states": states, "items": sel[offset:offset + limit],
            "kinds": {k: {"label": v["label"], "group": v["group"], "cols": v["cols"]} for k, v in KINDS.items()}}


def to_csv(rows: list[dict], kind: str) -> str:
    cols = [("name", "이름"), ("state", "상태")] + (KINDS[kind]["cols"] if kind in KINDS else [("kind", "종류")]) + [("connector", "커넥터")]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([label for _, label in cols])
    for r in rows:
        w.writerow([("" if r.get(k) is None else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r[k])) if k in ("last", "last_ok") and r.get(k) else r.get(k))
                    for k, _ in cols])
    return "﻿" + buf.getvalue()
