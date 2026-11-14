"""AI 체크봇(2.38.0) — 장애·작업 시나리오를 대량으로 만들어 지금 인프라에 대고 계속 검증한다(읽기 전용, 아무것도 바꾸지 않음).

시나리오 만들기
  · 규칙(전수)  인벤토리를 훑어 모든 대상에 대해 만든다 — 호스트마다 ESXi 장애·네트워크 업링크 장애, 클러스터마다 롤링 유지보수·클러스터 전체 장애·
                 유지보수 중 다른 호스트 장애(복합), 공유 데이터스토어마다 APD/PDL·가득 참, vCenter 마다 업그레이드(중단), NSX Edge 클러스터·
                 VKS 클러스터 고립, 만료 임박 인증서
  · 이력        이 포털이 실제로 본 이상징후(최근 30일)를 유형별로 세어 '자주 나는 문제'에 가중치
  · AI          (선택) LLM 이 인벤토리 요약·이력을 보고 복합 시나리오(예: 유지보수 중 다른 호스트 장애 + 데이터스토어 APD)를 JSON 으로 제안 →
                 엔진이 같은 규칙으로 검증. 실행 요약(가장 위험한 것·먼저 할 일)도 LLM 이 쓴다. 외부 공급자면 이름 가명화
검증(시나리오마다)
  · 영향받는 리소스 목록 — VM(켜짐·꺼짐·사유), 호스트, 관리 VM(vCenter·NSX·SDDC·Avi·VCF Ops), NSX Edge, Avi SE, VKS 노드·파드·네임스페이스
  · 판정 근거 — HA 꺼짐, HA 재시작 용량 부족(가정 분석 엔진), 로컬 디스크·PCI 패스스루·USB 로 다른 호스트에서 못 켜는 VM, vMotion 을 막는 CD-ROM 연결,
                 DRS 수동, vSAN 호스트 수 부족, 같은 묶음(VKS 컨트롤 플레인·Edge 클러스터·Avi SE)이 한 호스트에 몰림, SRM 보호 밖 VM,
                 vCenter 백업 없음·인증서 임박·버전 지원 종료
  · 판정 fail(실제로 서비스가 멈춤) · warn(멈추지는 않지만 위험) · pass
연속 실행: 기본 6시간마다 + 인벤토리가 바뀌면 다음 주기에 반영. 새로 fail 이 된 시나리오는 이상징후로 알림.
"""
from __future__ import annotations

import asyncio
import inspect
import copy
import json
import re
import time
from typing import Any

from . import whatif as W

TYPES = {
    "host_down": ("ESXi 호스트 장애", "PSOD·전원·하드웨어로 호스트가 꺼짐 — HA 가 다른 호스트에서 VM 을 다시 켬", 0.30),
    "host_maint": ("롤링 패치·유지보수", "호스트를 한 대씩 유지보수 모드로 — vMotion·vSAN 데이터 이동", 1.00),
    "maint_plus_fail": ("유지보수 중 다른 호스트 장애", "한 대를 유지보수로 뺀 사이 다른 한 대가 장애", 0.08),
    "cluster_down": ("클러스터 전체 장애", "전원·네트워크·스토리지 공통 장애로 클러스터가 통째로 멈춤", 0.02),
    "ds_apd": ("데이터스토어 APD/PDL", "스토리지 경로 전부 끊김(APD) 또는 장치 영구 손실(PDL)", 0.15),
    "ds_full": ("데이터스토어 가득 참", "사용률 85% 이상이거나 90일 안에 90%에 닿음 — 공간이 차서 씬 디스크·스냅숏·스왑을 못 씀 — VM 이 멈춤", 0.20),
    "uplink_loss": ("업링크(물리 NIC) 장애", "호스트의 물리 NIC·케이블·스위치 포트 하나가 끊김", 0.20),
    "vcenter_upgrade": ("vCenter 업그레이드·중단", "업그레이드·재부팅 동안 vCenter 가 멈춤 — 관리·자동화가 멈춤", 0.50),
    "edge_down": ("NSX Edge 장애", "Edge 노드가 있는 호스트가 꺼지거나 Edge 가 멈춤 — 북남 트래픽·서비스", 0.10),
    "cert_expire": ("인증서 만료", "인증서가 만료돼 연결·관리가 끊김", 0.25),
    "switch_down": ("물리 스위치 장애", "ToR·스파인 스위치(또는 MLAG/vPC 한 쌍)가 멈춤 — 그 스위치에 연결된 ESXi 업링크·NSX BGP 세션이 끊김", 0.08),
    "device_down": ("방화벽·라우터 장애", "외부로 나가는 방화벽·라우터가 멈춤 — 북남(외부) 통신 경로", 0.08),
    "storage_down": ("외부 스토리지 장애", "NFS 서버·SAN 어레이가 멈춤 — 그 장비의 데이터스토어 전부 APD/PDL", 0.05),
    "compound": ("복합 장애", "여러 장애가 겹칠 때 — 규칙(가장 붐비는 호스트+데이터스토어) 또는 AI 가 제안", 0.05),
}
HIST_RX = {
    "host_down": ["not responding", "disconnected", "psod", "purple", "연결 끊김", "hostconnectionlost", "host connection"],
    "ds_apd": ["apd", "pdl", "all paths down", "permanent device loss", "path dead", "경로"],
    "ds_full": ["out of disk", "running out", "공간 부족", "disk space", "datastore usage", "no space"],
    "uplink_loss": ["vmnic", "link down", "redundancy", "이중화", "uplink"],
    "cert_expire": ["certificate", "인증서", "cert "],
    "host_maint": ["maintenance mode", "vmotion", "migrate", "유지보수"],
    "edge_down": ["edge", "bgp"],
    "switch_down": ["lldp", "이웃 사라짐", "mlag", "vpc", "peer-link", "interface ethernet", "인터페이스"],
    "device_down": ["fortigate", "firewall", "방화벽", "ha state"],
    "vcenter_upgrade": ["vpxd", "vcenter server", "vapi"],
}
MGMT_RX = re.compile(r"(^|[-_.])(vc|vcsa|vcenter|nsx|nsxt|nsx-mgr|nsxmgr|sddc|sddc-?manager|avi|alb|vcf-?ops|vrops|ops|vrli|vcf-?logs|loginsight|vcfa|vra|"
                     r"srm|vr|vrms|hcx|vlcm|nsx-?edge|edge)\d*($|[-_.\d])", re.I)
SEV = {"fail": 3, "warn": 2, "pass": 1}


# ------------------------------------------------------------------ 세계(인벤토리 스냅숏) 만들기 — 엔진 밖 순수 자료라 시험이 쉽다
def build_world(engine) -> dict[str, Any]:
    vcs, vks, edges, ses, prot, certs, avis = [], [], [], [], set(), [], []
    appl: dict[str, dict] = {}
    for c in getattr(engine, "connectors", []):
        if not getattr(c, "enabled", True):
            continue
        t = getattr(c, "type", "")
        if t == "vcenter" and getattr(c, "topology", None):
            hs = getattr(c, "health_snap", None) or {}
            vcs.append({"name": c.name, "host": getattr(c, "host", ""), "about": getattr(c, "about", {}) or {}, "topo": c.topology,
                        "health": hs.get("hosts") or {}, "hclusters": hs.get("clusters") or {}, "bp": {v["name"]: v for v in (hs.get("bp_vms") or {}).get("vms") or []},
                        "supervisors": ((getattr(c, "vks", None) or {}).get("supervisors") or [])})
        elif t == "vks":
            inv = getattr(c, "inv", None) or {}
            vks.append({"name": c.name, "cluster": getattr(c, "cluster_label", c.name), "role": getattr(c, "role", "workload"),
                        "nodes": inv.get("nodes") or [], "pods": inv.get("pods") or []})
        elif t == "nsx":
            for tid, e in (getattr(c, "edge_info", None) or {}).items():
                edges.append({"nsx": c.name, "id": tid, "name": e.get("name", tid), "host_moid": e.get("host_moid", ""), "edge_cluster": e.get("edge_cluster", "")})
        elif t == "avi":
            for n, s in (getattr(c, "se", None) or {}).items():
                ses.append({"avi": c.name, "name": s.get("name", n), "host": s.get("host", ""), "group": s.get("se_group", "")})
            # 2.46.0 What-If 플랫폼 — 컨트롤러 클러스터·SE·가상 서비스 배치
            avis.append({"name": c.name, "controllers": getattr(c, "controllers", None) or {},
                         "se": [{"name": s.get("name", n), "host": s.get("host", ""), "group": s.get("se_group", ""), "state": s.get("state", ""), "vs": list(s.get("vs") or [])}
                                for n, s in (getattr(c, "se", None) or {}).items()],
                         "vs": [{"name": v.get("name", ""), "ses": list(v.get("ses") or []), "vips": list(v.get("vips") or []), "state": v.get("state", "")}
                                for v in (getattr(c, "vs", None) or {}).values() if v.get("name")]})
        elif t == "srm":
            prot |= {str(v.get("name", "")).lower() for v in (getattr(c, "protection", None) or {}).get("vms") or [] if v.get("name")}
        p = getattr(c, "protection", None)
        if isinstance(p, dict) and p.get("kind") == "appliance_backup":
            appl[c.name] = p
    cs = getattr(getattr(engine, "certs", None), "last", None) or {}
    certs = [x for x in cs.get("items") or [] if x.get("band") in ("expired", "crit", "warn")]
    try:                                                         # 2.41.0 물리 계층(스위치·방화벽·라우터·외부 스토리지·물리 서버) — 이미 수집된 자료만
        from . import physmap as PH
        phys = PH.build(engine)
    except Exception:  # noqa: BLE001
        phys = {"switches": {}, "devices": {}, "hosts": {}, "bgp": [], "servers": {}, "storage": {}, "collected": {}}
    # 커넥터가 들고 있는 수집 자료를 깊은 복사한 스냅숏 — 시나리오·시뮬레이터 계산이 무엇을 하든 커넥터·실제 인프라에 닿지 않는다
    return copy.deepcopy({"vcenters": vcs, "vks": vks, "edges": edges, "avi_se": ses, "avi": avis, "srm_protected": prot, "srm_on": any(getattr(c, "type", "") == "srm" for c in getattr(engine, "connectors", [])),
            "certs": certs, "appliance_backup": appl, "phys": phys, "ts": time.time()})


async def history_counts(store, days: int = 30) -> dict[str, int]:
    """최근 이상징후(제목·메시지)에서 유형별 발생 수 — '이 환경에서 실제로 자주 나는 문제'"""
    out = {k: 0 for k in HIST_RX}
    try:
        rows = await store.q("SELECT body FROM anomalies WHERE created >= ? ORDER BY created DESC LIMIT 5000", (time.time() - days * 86400,))
    except Exception:  # noqa: BLE001
        return out
    for r in rows:
        try:
            b = json.loads(r["body"])
        except (TypeError, ValueError):
            continue
        txt = (str(b.get("title", "")) + " " + str((b.get("event") or {}).get("message", ""))).lower()
        for k, pats in HIST_RX.items():
            if any(p in txt for p in pats):
                out[k] += 1
    return out


# ------------------------------------------------------------------ 시나리오 만들기(규칙 전수)
def _shared(topo: dict, hosts: list[str]) -> set[str]:
    H = topo.get("hosts") or {}
    D = topo.get("datastores") or {}
    if not hosts:
        return set()
    return {dn for dn, d in D.items() if (d.get("capacity_gb") or 0) and d.get("local") is not True and all(dn in (H.get(h, {}).get("datastores") or []) for h in hosts)}


def _used_pct(d: dict) -> float:
    c = d.get("capacity_gb") or 0
    return round((1 - (d.get("free_gb") or 0) / c) * 100, 1) if c else 0.0


def generate(world: dict, cap: dict | None = None) -> list[dict]:
    """모든 대상에 대해 시나리오 스펙 — {id, type, vcenter, target, title}"""
    out: list[dict] = []
    cap = cap or {}
    for vc in world["vcenters"]:
        T, V = vc["topo"], vc["name"]
        H = T.get("hosts") or {}
        cls = T.get("clusters") or {}
        for cn, c in sorted(cls.items()):
            live = [h for h in c.get("hosts", []) if h in H and str(H[h].get("conn", "connected")) in ("connected", "") and not H[h].get("maintenance")]
            for h in live:
                out.append({"type": "host_down", "vcenter": V, "cluster": cn, "target": h})
                out.append({"type": "uplink_loss", "vcenter": V, "cluster": cn, "target": h})
            if len(live) >= 2:
                out.append({"type": "host_maint", "vcenter": V, "cluster": cn, "target": cn})
                big = sorted(live, key=lambda h: -(H[h].get("mem_mb") or 0))
                out.append({"type": "maint_plus_fail", "vcenter": V, "cluster": cn, "target": f"{big[0]} + {big[1]}", "hosts": big[:2]})
            out.append({"type": "cluster_down", "vcenter": V, "cluster": cn, "target": cn})
        D = T.get("datastores") or {}
        for dn, d in sorted(D.items()):
            if not (d.get("capacity_gb") or 0) or d.get("local") is True:
                continue
            out.append({"type": "ds_apd", "vcenter": V, "target": dn})
            fc = cap.get((V, dn))
            up = _used_pct(d)
            if (fc is not None and fc <= 90) or up >= 85:
                out.append({"type": "ds_full", "vcenter": V, "target": dn, "days": fc, "used_pct": up})
        out.append({"type": "vcenter_upgrade", "vcenter": V, "target": vc.get("host") or V})
    for ec in sorted({e["edge_cluster"] for e in world["edges"] if e.get("edge_cluster")}):
        out.append({"type": "edge_down", "target": ec})
    ph = world.get("phys") or {}
    for sn in sorted((ph.get("switches") or {})):
        out.append({"type": "switch_down", "target": sn, "switches": [sn]})
    pairs: dict[str, list] = {}
    for sn, sw in (ph.get("switches") or {}).items():
        if sw.get("mlag"):
            pairs.setdefault(sw["mlag"], []).append(sn)
    for dom, mem in sorted(pairs.items()):
        if len(mem) >= 2:
            out.append({"type": "switch_down", "target": " + ".join(sorted(mem)), "switches": sorted(mem), "pair": dom})
    for dn, d in sorted((ph.get("devices") or {}).items()):
        if d["kind"] in ("firewall", "router"):
            out.append({"type": "device_down", "target": dn, "devices": [dn]})
    for an in sorted((ph.get("storage") or {})):
        out.append({"type": "storage_down", "target": an})
    for x in world["certs"]:
        out.append({"type": "cert_expire", "target": f"{x['system']} · {x['kind']} · {x['name']}", "cert": x})
    for i, s in enumerate(out):
        s["id"] = f"{s['type']}:{s.get('vcenter', '')}:{s['target']}"[:200]
        s["origin"] = s.get("origin", "rule")
    return out


# ------------------------------------------------------------------ 검증
def _vc(world: dict, name: str) -> dict | None:
    return next((v for v in world["vcenters"] if v["name"] == name), None)


def _vm_row(n: str, v: dict, reason: str, bp: dict | None = None) -> dict:
    return {"name": n, "power": "on" if "poweredOn" in str(v.get("power")) else "off", "host": v.get("host", ""), "cluster": v.get("cluster", ""),
            "vcpu": int(v.get("vcpu") or 0), "mem_gb": round(int(v.get("mem_mb") or 0) / 1024, 1), "reason": reason}


def _mgmt_kind(n: str, world: dict) -> str | None:
    low = n.lower()
    if any(e["name"].lower() == low for e in world["edges"]):
        return "NSX Edge"
    if any(s["name"].lower() == low for s in world["avi_se"]):
        return "Avi SE"
    m = MGMT_RX.search(low)
    if m:
        k = m.group(2).lower()
        return ("vCenter" if k.startswith("vc") else "NSX Manager" if k.startswith("nsx") and "edge" not in k else "NSX Edge" if "edge" in k else
                "SDDC Manager" if k.startswith("sddc") else "Avi Controller" if k in ("avi", "alb") else "VCF Operations" if k in ("vcf-ops", "vcfops", "vrops", "ops") else
                "VCF Logs" if k in ("vrli", "vcf-logs", "vcflogs", "loginsight") else "VCF Automation" if k in ("vcfa", "vra") else "SRM·복제" if k in ("srm", "vr", "vrms") else
                "HCX" if k == "hcx" else "관리 VM")
    return None


def _vks_impact(world: dict, nodes: set[str]) -> dict[str, Any]:
    """잃는 VM 중 VKS 노드 → 클러스터별 노드·컨트롤 플레인·파드·네임스페이스"""
    out = []
    for k in world["vks"]:
        names = {n.get("name") for n in k["nodes"]}
        hit = names & nodes
        if not hit:
            continue
        cp = [n.get("name") for n in k["nodes"] if n.get("name") in hit and any(r in ("control-plane", "master") for r in n.get("roles") or [])]
        cp_all = [n.get("name") for n in k["nodes"] if any(r in ("control-plane", "master") for r in n.get("roles") or [])]
        pods = [p for p in k["pods"] if p.get("node") in hit]
        out.append({"cluster": k["cluster"], "nodes": sorted(hit), "nodes_total": len(names), "control_plane_lost": cp, "control_plane_total": len(cp_all),
                    "pods": len(pods), "namespaces": sorted({p.get("ns", "") for p in pods})[:30], "pod_list": [f"{p.get('ns')}/{p.get('name')}" for p in pods][:100]})
    return {"clusters": out}


def _capacity(vc: dict, cluster: str, remove: list[str], consume_ha: bool) -> dict[str, Any] | None:
    class C:
        topology = vc["topo"]
    base = W.cluster_base(C, cluster)
    if not base or not base["hosts"]:
        return None
    rm = [h for h in remove if h in {x["name"] for x in base["hosts"]}]
    if len(rm) >= len(base["hosts"]):
        return {"verdict": "bad", "why": "남는 호스트가 없습니다"}
    try:
        r = W.simulate(base, {"remove_names": rm, "consume_ha": consume_ha, "add_hosts": 0})
    except ValueError as e:
        return {"verdict": "bad", "why": str(e)}
    a = r["after"]
    return {"verdict": a["verdict"], "cpu_pct": a["cpu"]["pct_usable"], "mem_pct": a["mem"]["pct_usable"], "hosts_left": a["hosts"], "ha_after": r["inputs"]["ha_after"],
            "hosts_needed": r["hosts_needed"], "limit": r["limit"]}


def _cl_info(vc: dict, cluster: str) -> dict:
    return {**((vc["topo"].get("clusters") or {}).get(cluster) or {}), **(vc["hclusters"].get(cluster) or {})}


def _colocated(world: dict, vc: dict, hosts: set[str]) -> list[str]:
    """한 호스트에 몰려 있어 같이 죽는 이중화 묶음"""
    out = []
    T = vc["topo"]
    V = T.get("vms") or {}
    for k in world["vks"]:
        cp = [n.get("name") for n in k["nodes"] if any(r in ("control-plane", "master") for r in n.get("roles") or [])]
        if len(cp) >= 2:
            on = [n for n in cp if (V.get(n) or {}).get("host") in hosts]
            if len(on) >= 2 or (len(on) >= max(1, len(cp) // 2 + 1)):
                out.append(f"VKS '{k['cluster']}' 컨트롤 플레인 {len(on)}/{len(cp)}대가 함께 꺼짐 — 과반을 잃어 API 가 멈춥니다(호스트 분산 규칙 확인)")
    moid = {h.get("moid"): n for n, h in (T.get("hosts") or {}).items()}
    by: dict[str, list] = {}
    for e in world["edges"]:
        by.setdefault(e["edge_cluster"], []).append(moid.get(e["host_moid"], ""))
    for ec, hs in by.items():
        if len(hs) >= 2 and all(h in hosts for h in hs if h) and any(hs):
            out.append(f"NSX Edge 클러스터 '{ec}' 의 Edge {len(hs)}대가 모두 꺼짐 — 북남 트래픽·게이트웨이 서비스가 멈춥니다")
    sg: dict[str, list] = {}
    for s in world["avi_se"]:
        sg.setdefault(s["group"], []).append(s["host"])
    for g, hs in sg.items():
        if len(hs) >= 2 and all(h in hosts for h in hs):
            out.append(f"Avi SE 그룹 '{g}' 의 SE 가 모두 꺼짐 — 가상 서비스(VIP)가 멈춥니다")
    return out


def _vm_vswitches(topo: dict, host_vs: dict, v: dict) -> set[str]:
    """VM 네트워크 → 이 호스트의 가상 스위치 후보(분산 스위치 이름이 맞으면 그것, 아니면 VM 트래픽을 나르는 스위치 전부)"""
    nets = topo.get("networks") or {}
    out = set()
    for n in v.get("networks") or []:
        d = (nets.get(n) or {}).get("dvs")
        if d in host_vs:
            out.add(d)
    return out or set(host_vs)


def _eval_net(world: dict, s: dict, res: dict, find) -> None:
    """물리 스위치·방화벽·라우터 장애 — 가정 반영 뒤 호스트 가상 스위치마다 살아 있는 업링크·외부 경로, 관리·vSAN VMkernel, NSX BGP"""
    from . import physmap as PH
    ph = world.get("phys") or {}
    dead = set(s.get("switches") or []) | set(s.get("devices") or [])
    if s["type"] == "switch_down" and not s.get("switches"):
        dead.add(s["target"])
    if s["type"] == "device_down" and not s.get("devices"):
        dead.add(s["target"])
    if not ph.get("hosts"):
        find("warn", "물리 결선 정보(스위치 LLDP/CDP·ESXi 업링크)가 없어 영향을 계산하지 못했습니다 — 네트워크 커넥터·vDS LLDP 를 확인하세요")
        return
    ext_ok, known = PH.reach(ph, dead)
    res["services"] = [{"name": n, "kind": "물리 스위치" if n in ph["switches"] else {"firewall": "방화벽", "router": "라우터"}.get(ph["devices"].get(n, {}).get("kind"), "장비"),
                        "impact": "멈춤"} for n in sorted(dead)]
    iso, degr, vsanp, vmot, spof = [], [], [], [], []
    hm: dict[str, str] = {}
    for vc in world["vcenters"]:
        T = vc["topo"]
        V = T.get("vms") or {}
        for hn in T.get("hosts") or {}:
            paths = PH.host_paths(ph, hn, dead, set(), ext_ok, known)
            if not paths:
                continue
            lost = {vs for vs, p in paths.items() if p["now"] and not p["live"]}
            nox = {vs for vs, p in paths.items() if p["live"] and not p["ext"]}
            half = [vs for vs, p in paths.items() if len(p["now"]) >= 2 and len(p["live"]) == 1]
            if not (lost or nox or half):
                continue
            hv = (vc["health"].get(hn) or {}).get("vmks") or []
            svc = {x for k in hv if k.get("switch") in lost for x in k.get("services") or []}
            if lost:
                hm[f"{vc['name']}/{hn}"] = "isolated"
                already = sorted({u for vs in lost for u in paths[vs]["uplinks"] if u not in paths[vs]["now"]})
                if already:
                    spof.append(f"{hn}({', '.join(already)})")
                if "management" in svc or not hv:
                    iso.append(hn)
                if "vsan" in svc:
                    vsanp.append(hn)
                if "vmotion" in svc:
                    vmot.append(hn)
            elif nox:
                hm[f"{vc['name']}/{hn}"] = "extlost"
            else:
                hm[f"{vc['name']}/{hn}"] = "degraded"
                degr.append(hn)
            vsan_ds = {dn for dn, d in (T.get("datastores") or {}).items() if str(d.get("type", "")).lower() == "vsan"}
            for n, v in V.items():
                if v.get("host") != hn or "poweredOn" not in str(v.get("power")):
                    continue
                cand = _vm_vswitches(T, paths, v)
                if cand <= lost:
                    row = _vm_row(n, v, f"물리 업링크 모두 끊김({', '.join(sorted({sw for vs in cand for sw in paths[vs]['switches']}))})")
                    row["state"] = "net"
                elif hn in vsanp and set(v.get("datastores") or []) & vsan_ds:
                    row = _vm_row(n, v, "vSAN 네트워크가 끊겨 이 호스트가 vSAN 클러스터에서 분리됨 — 디스크 접근 불가 가능")
                    row["state"] = "io"
                elif cand <= lost | nox:
                    row = _vm_row(n, v, "외부(방화벽·라우터)로 가는 경로 끊김 — 같은 구간 내부 통신만 가능")
                    row["state"] = "ext"
                else:
                    continue
                res["vms"].append(row)
    res["hosts"] = sorted({h.split("/", 1)[1] for h in hm})
    res["host_marks"] = hm
    if iso:
        find("fail", f"호스트 {len(iso)}대의 관리망 업링크가 모두 끊김({', '.join(iso[:6])}) — vCenter 연결이 끊기고 HA 는 격리로 판단합니다(격리 대응 설정에 따라 VM 이 다른 호스트에서 재시작)")
    if vsanp:
        find("fail", f"호스트 {len(vsanp)}대의 vSAN 네트워크가 끊김 — vSAN 클러스터에서 분리돼 그 호스트의 VM 이 디스크를 잃을 수 있습니다")
    if vmot:
        find("warn", f"호스트 {len(vmot)}대의 vMotion 네트워크가 끊김 — 그 호스트로·에서 VM 을 옮길 수 없습니다")
    nets = sum(1 for v in res["vms"] if v.get("state") == "net")
    if nets:
        find("fail", f"켜진 VM {nets}대의 네트워크가 끊깁니다(그 호스트의 업링크가 모두 이 장비에 연결)")
    exts = sum(1 for v in res["vms"] if v.get("state") == "ext")
    if exts:
        find("fail", f"켜진 VM {exts}대가 외부와 통신하지 못합니다 — 남은 경로에 방화벽·라우터가 없음")
    if spof:
        find("fail", f"지금 이미 링크가 내려가 있는 업링크 때문에 단일 장애점이 된 호스트: {', '.join(spof[:6])} — 이 장비 하나로 통신이 끊깁니다")
    if degr:
        find("warn", f"호스트 {len(degr)}대는 업링크가 1개만 남아 이중화가 없습니다({', '.join(degr[:6])})")
    if not (iso or nets or exts or degr or vsanp):
        find("pass", "모든 호스트가 다른 스위치·경로로 통신을 이어 갑니다" + ("" if known else " (외부 방화벽·라우터 정보가 없어 북남 경로는 판단하지 않음)"))
    bg = [b for b in ph.get("bgp") or [] if b.get("switch")]
    if bg:
        t0s: dict[str, list] = {}
        for b in bg:
            t0s.setdefault(b.get("tier0") or "T0", []).append(b)
        for t0, ss in t0s.items():
            gone = [b for b in ss if b["switch"] in dead or b["switch"] not in ext_ok and known]
            alive = [b for b in ss if b not in gone and str(b.get("state", "")).upper() == "ESTABLISHED"]
            if gone and not alive:
                find("fail", f"NSX {t0} BGP 세션 {len(ss)}개 모두 피어 스위치가 멈추거나 외부 경로를 잃음 — 오버레이 워크로드의 북남(외부) 통신이 멈춥니다")
                res["services"].append({"name": t0, "kind": "NSX Tier-0", "impact": "BGP 전부 끊김 — 북남 통신 멈춤"})
            elif gone:
                find("warn", f"NSX {t0} BGP 세션 {len(gone)}/{len(ss)}개가 끊김 — 남은 세션 {len(alive)}개(지금 ESTABLISHED)로 북남 통신")
    if known and s["type"] == "device_down":
        left = PH.border_nodes(ph) - dead
        if not left:
            find("fail", "남은 방화벽·라우터가 없습니다 — 모든 외부 통신이 끊깁니다")
        else:
            find("pass", f"다른 외부 장비로 우회할 수 있습니다: {', '.join(sorted(left)[:4])} (그 장비의 정책·세션 동기화는 따로 확인)")


def evaluate(world: dict, s: dict) -> dict[str, Any]:
    t = s["type"]
    res: dict[str, Any] = {**{k: v for k, v in s.items() if k != "cert"}, "kind": TYPES[t][0], "verdict": "pass", "findings": [], "vms": [], "hosts": [], "services": [],
                           "vks": {"clusters": []}, "actions": []}
    F = res["findings"]

    def find(sev: str, text: str):
        F.append({"sev": sev, "text": text})

    vc = _vc(world, s.get("vcenter", "")) if s.get("vcenter") else None
    if t in ("host_down", "host_maint", "maint_plus_fail", "cluster_down", "uplink_loss") and vc:
        T = vc["topo"]
        H, V, cl = T.get("hosts") or {}, T.get("vms") or {}, s.get("cluster", "")
        info = _cl_info(vc, cl)
        members = [h for h in info.get("hosts", []) if h in H]
        if t == "host_down":
            lost = {s["target"]}
        elif t == "maint_plus_fail":
            lost = set(s.get("hosts") or [])
        elif t == "cluster_down":
            lost = set(members)
        elif t == "uplink_loss":
            lost = set()
        else:
            lost = set()
        res["hosts"] = sorted(lost) if t != "host_maint" else sorted(members)
        shared = _shared(T, [h for h in members if h not in lost])
        vms = [(n, v) for n, v in V.items() if v.get("host") in lost]
        on = [(n, v) for n, v in vms if "poweredOn" in str(v.get("power"))]
        if t in ("host_down", "maint_plus_fail", "cluster_down"):
            for n, v in on:
                bp = vc["bp"].get(n) or {}
                why = []
                if t != "cluster_down":
                    if not set(v.get("datastores") or []) <= shared:
                        why.append("남는 호스트가 못 보는 데이터스토어(로컬 등)")
                    if bp.get("passthru"):
                        why.append("PCI 패스스루·vGPU")
                    if bp.get("usb"):
                        why.append("호스트 USB 연결")
                    if not info.get("ha"):
                        why.append("HA 꺼짐")
                res["vms"].append(_vm_row(n, v, " · ".join(why) if why else ("클러스터와 함께 멈춤" if t == "cluster_down" else "HA 가 다른 호스트에서 다시 켬(재부팅)"), bp))
            stuck = [x for x in res["vms"] if x["reason"] not in ("HA 가 다른 호스트에서 다시 켬(재부팅)", "클러스터와 함께 멈춤")]
            if t == "cluster_down":
                find("warn", f"켜진 VM {len(on)}대가 모두 멈춥니다 — 다른 사이트 복구(SRM)·백업으로만 되살립니다")
                if world["srm_on"]:
                    nop = [x["name"] for x in res["vms"] if x["name"].lower() not in world["srm_protected"]]
                    if nop:
                        find("fail", f"SRM 보호 밖 VM {len(nop)}대 — 다른 사이트에서 복구할 수 없습니다")
                        for x in res["vms"]:
                            if x["name"] in nop:
                                x["reason"] = "SRM 보호 밖"
                    else:
                        find("pass", "켜진 VM 이 모두 SRM 보호 그룹에 있습니다")
                else:
                    find("warn", "SRM 커넥터가 없어 DR 보호 여부를 확인하지 못했습니다")
            else:
                if not info.get("ha"):
                    if on:
                        find("fail", f"클러스터 HA 가 꺼져 있어 VM {len(on)}대가 자동으로 다시 켜지지 않습니다")
                    else:
                        find("warn", "지금 켜진 VM 은 없지만 클러스터 HA 가 꺼져 있어 이 호스트로 옮겨 오는 VM 은 보호받지 못합니다")
                elif stuck:
                    find("fail", f"VM {len(stuck)}대는 다른 호스트에서 다시 켤 수 없습니다(로컬 디스크·패스스루·USB)")
                cap = _capacity(vc, cl, sorted(lost), consume_ha=True)
                if cap:
                    res["capacity"] = cap
                    if cap.get("why"):
                        find("fail", f"다시 켤 곳이 없습니다 — {cap['why']}")
                    elif cap["verdict"] == "bad":
                        find("fail", f"남은 호스트 {cap.get('hosts_left', '')}대로는 다시 켤 용량이 모자랍니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%"
                                     + (f", 같은 사양 {cap['hosts_needed']}대 부족" if cap.get("hosts_needed") else "") + ")")
                    elif cap["verdict"] == "warn":
                        find("warn", f"다시 켜지만 남은 용량이 빠듯합니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%)")
                    else:
                        find("pass", f"남은 호스트가 받아냅니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%)")
                if info.get("vsan") and len(members) - len(lost) < 3:
                    find("fail", f"vSAN 호스트가 {len(members) - len(lost)}대만 남아 FTT=1 객체를 다시 만들 수 없고 다음 장애에 데이터 접근을 잃습니다")
                elif info.get("vsan") and len(members) - len(lost) == 3:
                    find("warn", "vSAN 이 3대로 줄어 재구축할 여유 호스트가 없습니다(FTT=1 이 복구되지 않은 상태로 운영)")
        elif t == "host_maint":
            only = s.get("host")                                 # 시뮬레이터: 호스트 한 대만 유지보수
            if only:
                res["hosts"] = [only]
            bl = []
            for n, v in V.items():
                if v.get("cluster") != cl or "poweredOn" not in str(v.get("power")) or (only and v.get("host") != only):
                    continue
                bp = vc["bp"].get(n) or {}
                why = []
                if not set(v.get("datastores") or []) <= _shared(T, members):
                    why.append("로컬 디스크")
                if bp.get("cdrom_connected"):
                    why.append("CD-ROM 연결(호스트 장치·ISO)")
                if bp.get("passthru"):
                    why.append("PCI 패스스루·vGPU")
                if bp.get("usb"):
                    why.append("호스트 USB")
                if why:
                    row = _vm_row(n, v, "vMotion 불가 — " + ", ".join(why), bp)
                    row["hard"] = any(w for w in why if not w.startswith("CD-ROM"))
                    bl.append(row)
            res["vms"] = bl
            hard = [x for x in bl if x.pop("hard")]
            if hard:
                find("fail", f"vMotion 으로 옮길 수 없는 VM {len(hard)}대(로컬 디스크·패스스루·USB) — 그 호스트를 패치하는 동안 이 VM 들은 멈춥니다")
            if len(bl) > len(hard):
                find("warn", f"CD-ROM·ISO 가 연결된 VM {len(bl) - len(hard)}대 — 유지보수 진입이 걸릴 수 있어 미리 연결을 끊어야 합니다")
            if not info.get("drs") or str(info.get("drs_behavior", "")).lower() not in ("fullyautomated", ""):
                find("warn", f"DRS 가 {'꺼져' if not info.get('drs') else '완전 자동이 아니어서'} 유지보수 모드 진입 때 VM 을 손으로 옮겨야 합니다")
            big = [only] if only else sorted(members, key=lambda h: -(H[h].get("mem_mb") or 0))[:1]
            cap = _capacity(vc, cl, big, consume_ha=False)
            if cap:
                res["capacity"] = cap
                if cap.get("why"):
                    find("fail", f"유지보수로 뺄 수 없습니다 — {cap['why']}")
                elif cap["verdict"] == "bad":
                    find("fail", f"{'이 호스트를' if only else '가장 큰 호스트를'} 빼면 HA 여유를 남기고는 용량이 모자랍니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%) — 유지보수 중에는 HA 를 보장할 수 없습니다")
                elif cap["verdict"] == "warn":
                    find("warn", f"{'이 호스트를' if only else '한 대를'} 빼면 HA 여유를 남기고 빠듯합니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%)")
                else:
                    find("pass", "이 호스트를 빼도 HA 여유를 남기고 받아냅니다" if only else "한 대씩 빼도 HA 여유를 남기고 받아냅니다")
            if info.get("vsan"):
                vs = [d for dn, d in (T.get("datastores") or {}).items() if str(d.get("type", "")).lower() == "vsan" and dn in _shared(T, members)]
                if vs:
                    tot = sum(d.get("capacity_gb") or 0 for d in vs)
                    used = tot - sum(d.get("free_gb") or 0 for d in vs)
                    left = tot * (len(members) - 1) / len(members) if members else 0
                    if left and used / left > 0.9:
                        find("fail", f"vSAN '전체 데이터 이동' 모드로는 한 대 몫({tot / len(members) / 1000:.1f} TB)을 옮길 공간이 없습니다(남는 용량의 {used / left * 100:.0f}%) — '접근성 보장' 모드만 가능")
                    elif left and used / left > 0.7:
                        find("warn", f"vSAN 전체 데이터 이동 시 남는 용량의 {used / left * 100:.0f}%까지 찹니다")
                if len(members) <= 3:
                    find("warn", f"vSAN 호스트 {len(members)}대 — 유지보수 동안 FTT=1 객체의 중복성이 없습니다")
        elif t == "uplink_loss":
            hh = vc["health"].get(s["target"]) or {}
            single = [w["name"] for w in hh.get("vswitches") or [] if len(w.get("uplinks") or []) == 1]
            none = [w["name"] for w in hh.get("vswitches") or [] if "uplinks" in w and not w["uplinks"]]
            res["hosts"] = [s["target"]]
            known = [w for w in hh.get("vswitches") or [] if "uplinks" in w]
            if not hh or not known:
                find("warn", "인프라 점검 스냅숏에 업링크 정보가 없어 확인하지 못했습니다")
            elif single:
                vms_on = [(n, v) for n, v in V.items() if v.get("host") == s["target"] and "poweredOn" in str(v.get("power"))]
                res["vms"] = [_vm_row(n, v, "단일 업링크 스위치 — 네트워크 끊김") for n, v in vms_on]
                vmk = [k for k in hh.get("vmks") or [] if k.get("switch") in single]
                svc = sorted({x for k in vmk for x in k.get("services") or []})
                find("fail", f"업링크가 1개뿐인 스위치 {', '.join(single)} — NIC 하나가 끊기면 이 호스트의 VM {len(vms_on)}대"
                             + (f"와 VMkernel 서비스({', '.join(svc)})" if svc else "") + " 통신이 끊깁니다"
                             + (" — 관리망이면 HA 격리 응답이 일어납니다" if "management" in svc else ""))
            else:
                find("pass", f"모든 스위치에 업링크가 2개 이상입니다({len(known)}개)")
            if none:
                find("warn", f"업링크가 없는 스위치: {', '.join(none)}")
        if t != "uplink_loss":
            lost_vms = {n for n, v in vms} if t != "host_maint" else set()
            k = _vks_impact(world, lost_vms)
            res["vks"] = k
            for c in k["clusters"]:
                if c["control_plane_lost"] and len(c["control_plane_lost"]) * 2 >= c["control_plane_total"]:
                    find("fail", f"VKS '{c['cluster']}' 컨트롤 플레인 {len(c['control_plane_lost'])}/{c['control_plane_total']}대를 잃습니다 — 클러스터 API 가 멈춥니다")
                if c["pods"]:
                    find("warn", f"VKS '{c['cluster']}' 노드 {len(c['nodes'])}대의 파드 {c['pods']}개가 다른 노드로 다시 뜹니다(네임스페이스 {', '.join(c['namespaces'][:5])})")
            for n, v in vms:
                mk = _mgmt_kind(n, world)
                if mk:
                    res["services"].append({"name": n, "kind": mk, "impact": "관리 기능 일시 중단(HA 재시작까지)" if t != "cluster_down" else "멈춤"})
            if res["services"] and t != "host_maint":
                find("warn", "관리 구성요소가 함께 영향받습니다: " + ", ".join(f"{x['kind']} {x['name']}" for x in res["services"][:6]))
            cp_said = any("컨트롤 플레인" in f["text"] for f in F)
            for x in _colocated(world, vc, lost if t != "host_maint" else set()):
                if not (cp_said and x.startswith("VKS")):
                    find("fail", x)
    elif t == "ds_apd" and vc:
        T = vc["topo"]
        V = T.get("vms") or {}
        d = (T.get("datastores") or {}).get(s["target"], {})
        hits = [(n, v) for n, v in V.items() if s["target"] in (v.get("datastores") or [])]
        on = [(n, v) for n, v in hits if "poweredOn" in str(v.get("power"))]
        res["vms"] = [_vm_row(n, v, "디스크가 이 데이터스토어에 있음 — I/O 멈춤") for n, v in hits]
        res["hosts"] = sorted(h for h, x in (T.get("hosts") or {}).items() if s["target"] in (x.get("datastores") or []))
        if on:
            find("fail", f"켜진 VM {len(on)}대의 디스크 I/O 가 멈춥니다(호스트 {len(res['hosts'])}대가 마운트)")
        else:
            find("pass", "이 데이터스토어를 쓰는 켜진 VM 이 없습니다")
        mg = [(n, _mgmt_kind(n, world)) for n, v in on if _mgmt_kind(n, world)]
        res["services"] = [{"name": n, "kind": k, "impact": "멈춤"} for n, k in mg]
        if mg:
            find("fail", "관리 구성요소가 이 데이터스토어에 있습니다: " + ", ".join(f"{k} {n}" for n, k in mg[:6]) + " — 장애 대응 도구가 같이 멈춥니다")
        clusters = sorted({v.get("cluster") for n, v in on if v.get("cluster")})
        for cl in clusters:
            hi = _cl_info(vc, cl)
            if hi.get("ha") is False:
                find("warn", f"클러스터 {cl} 의 HA 가 꺼져 있어 APD/PDL 뒤 VM 을 자동으로 다시 켜지 않습니다")
        if str(d.get("type", "")).lower() == "vsan":
            find("warn", "vSAN 데이터스토어 — APD/PDL 대신 호스트·디스크 장애로 나타납니다. 이 결과는 데이터스토어 전체를 잃는 최악의 경우입니다")
        k = _vks_impact(world, {n for n, v in on})
        res["vks"] = k
        for c in k["clusters"]:
            find("warn", f"VKS '{c['cluster']}' 노드 {len(c['nodes'])}/{c['nodes_total']}대가 이 데이터스토어에 있습니다")
    elif t == "ds_full" and vc:
        T = vc["topo"]
        V = T.get("vms") or {}
        d = (T.get("datastores") or {}).get(s["target"], {})
        hits = [(n, v) for n, v in V.items() if s["target"] in (v.get("datastores") or []) and "poweredOn" in str(v.get("power"))]
        res["vms"] = [_vm_row(n, v, "쓰기 공간 없음 — 멈춤(질문 대기) 가능") for n, v in hits]
        days = s.get("days")
        up = _used_pct(d)
        find("fail" if up >= 95 or (days is not None and days <= 14) else "warn",
             f"사용률 {up}%" + (f" — 추세로 {days}일 뒤 90%에 닿습니다" if days is not None else "") + f", 켜진 VM {len(hits)}대가 영향받습니다")
        snaps = [x for x in vc["bp"].values() if x.get("snapshots") and x["name"] in {n for n, _ in hits}]
        if snaps:
            find("warn", f"이 데이터스토어의 VM {len(snaps)}대에 스냅숏이 있습니다 — 스냅숏 델타가 계속 커집니다")
    elif t == "vcenter_upgrade" and vc:
        T = vc["topo"]
        cls = T.get("clusters") or {}
        res["hosts"] = []
        drs = [cn for cn, c in cls.items() if c.get("drs")]
        res["services"] = [{"name": cn, "kind": "DRS", "impact": "부하 분산·초기 배치 멈춤(실행 중 VM 은 그대로)"} for cn in drs]
        res["services"] += [{"name": x.get("name", ""), "kind": "VKS Supervisor", "impact": "네임스페이스·클러스터 생성·변경 불가(실행 중 워크로드는 그대로)"} for x in vc["supervisors"]]
        if world["srm_on"]:
            res["services"].append({"name": "SRM", "kind": "SRM", "impact": "복구 계획 실행·테스트 불가"})
        res["services"] += [{"name": "백업(VADP)", "kind": "백업", "impact": "vCenter 를 거치는 백업 작업 실패 — 백업 창을 피해서"},
                            {"name": "vMotion·복제·프로비저닝", "kind": "운영", "impact": "멈춤"},
                            {"name": "VCF AIops 수집", "kind": "관제", "impact": "vCenter 이벤트·성능 수집 공백(호스트 syslog 는 계속)"}]
        find("pass", f"HA 는 vCenter 없이도 동작합니다 — 업그레이드 중 호스트 장애가 나도 VM 은 다시 켜집니다(클러스터 {len([c for c in cls.values() if c.get('ha')])}개 HA 켬)")
        bk = world["appliance_backup"].get(vc["name"])
        if not bk:
            find("warn", "vCenter 파일 기반 백업 상태를 모릅니다(이 커넥터에 백업 일정 정보 없음) — 업그레이드 전 백업을 확인하세요")
        else:
            last = bk.get("last_success")
            if not bk.get("configured"):
                find("fail", "vCenter 파일 기반 백업이 설정돼 있지 않습니다 — 업그레이드 실패 시 되돌릴 수 없습니다")
            elif not last or time.time() - float(last) > 2 * 86400:
                find("warn", "마지막 성공 백업이 48시간보다 오래됐습니다 — 업그레이드 직전 수동 백업을 하세요")
            else:
                find("pass", "48시간 안에 성공한 vCenter 백업이 있습니다")
        cv = [x for x in world["certs"] if x.get("system") == vc["name"] and x.get("band") in ("expired", "crit")]
        if cv:
            find("fail", f"만료됐거나 임박한 인증서 {len(cv)}개 — 업그레이드 사전 점검에서 막힐 수 있습니다")
        hv = sorted({h.get("version", "") for h in vc["health"].values() if h.get("version")})
        if len(hv) > 1:
            find("warn", f"ESXi 버전이 섞여 있습니다({', '.join(hv)}) — 대상 vCenter 버전이 모든 ESXi 를 지원하는지 Interoperability Matrix 로 확인")
        snap_vc = [x for x in vc["bp"].values() if _mgmt_kind(x["name"], world) == "vCenter" and x.get("snapshots")]
        if snap_vc:
            find("warn", "vCenter VM 에 스냅숏이 남아 있습니다 — 업그레이드 전 정리하고 새로 만드세요")
        res["actions"] = ["vCenter 파일 기반 백업 + VM 스냅숏(가능하면 전원 끈 상태)", "대상 버전 Interoperability Matrix(ESXi·NSX·VKS·백업 SW) 확인", "백업 창·DRS 의존 작업을 피한 시간대",
                          "업그레이드 뒤 이 포털의 수집 현황에서 vCenter 커넥터 재연결 확인"]
    elif t == "edge_down":
        es = [e for e in world["edges"] if e["edge_cluster"] == s["target"]]
        res["services"] = [{"name": e["name"], "kind": "NSX Edge", "impact": "한 대씩 장애 시 다른 Edge 로 넘어감"} for e in es]
        if len(es) < 2:
            find("fail", f"Edge 클러스터 '{s['target']}' 에 Edge 가 {len(es)}대 — Edge 장애 시 북남 트래픽이 멈춥니다")
        else:
            hosts = {}
            for vc_ in world["vcenters"]:
                hosts |= {h.get("moid"): n for n, h in (vc_["topo"].get("hosts") or {}).items()}
            hs = [hosts.get(e["host_moid"], e["host_moid"]) for e in es]
            res["hosts"] = sorted(set(hs))
            if len(set(hs)) < len(hs):
                find("fail", f"Edge {len(es)}대 중 일부가 같은 호스트에 있습니다({', '.join(hs)}) — 그 호스트 하나로 Edge 이중화가 깨집니다(DRS 반선호도 규칙)")
            else:
                find("pass", f"Edge {len(es)}대가 서로 다른 호스트에 있습니다")
    elif t in ("switch_down", "device_down"):
        _eval_net(world, s, res, find)
    elif t == "storage_down":
        arr = ((world.get("phys") or {}).get("storage") or {}).get(s["target"]) or {}
        res["services"] = [{"name": s["target"], "kind": "외부 스토리지", "impact": "멈춤"}]
        if arr.get("note"):
            find("warn", f"'{s['target']}' 는 데이터스토어 백엔드로 묶은 추정 장비입니다(같은 모델 어레이가 여러 대면 설정 checkbot.external 로 지정)")
        seen = set()
        for d in arr.get("datastores") or []:
            sub = evaluate(world, {"type": "ds_apd", "vcenter": d["vcenter"], "target": d["name"], "id": ""})
            for f in sub["findings"]:
                find(f["sev"], f"[{d['name']}] {f['text']}")
            for v in sub["vms"]:
                if v["name"] not in seen:
                    seen.add(v["name"])
                    res["vms"].append({**v, "state": "io", "reason": f"{d['name']} 가 이 장비에 있음 — I/O 멈춤"})
            res["hosts"] = sorted(set(res["hosts"]) | set(sub["hosts"]))
            res["services"] += [x for x in sub["services"] if x not in res["services"]]
            for c in sub["vks"]["clusters"]:
                res["vks"]["clusters"].append(c)
        if not arr.get("datastores"):
            find("warn", "이 장비의 데이터스토어를 찾지 못했습니다")
    elif t == "cert_expire":
        x = s.get("cert") or {}
        d = x.get("days_left")
        find("fail" if x.get("band") in ("expired", "crit") else "warn",
             f"{x.get('kind')} {x.get('name')} — " + (f"{-d}일 전 만료됨" if d is not None and d < 0 else f"{d}일 뒤 만료"))
        impact = {"API 서버": "kubectl·컨트롤러가 API 서버에 붙지 못해 클러스터 관리가 멈춤", "컨트롤 플레인(kubeadm)": "컨트롤 플레인 구성요소 사이 통신 실패 — 클러스터 관리 불가",
                  "kubelet 서빙": "로그·exec·메트릭 수집 실패", "cert-manager": "그 인증서를 쓰는 인그레스·웹훅의 TLS 실패", "ESXi 호스트": "vCenter 와의 연결·vMotion·HA 구성 실패 가능",
                  "vCenter 머신 SSL": "vSphere Client·API·연동 솔루션(NSX·백업·SRM) 연결 실패", "NSX 인증서": "NSX Manager·Edge·연동 연결 실패"}.get(x.get("kind"), "그 서비스로의 TLS 연결 실패")
        res["services"] = [{"name": x.get("name", ""), "kind": x.get("kind", ""), "impact": impact}]
        if x.get("renew"):
            res["actions"] = [x["renew"]]
    elif t == "compound":
        res = evaluate_compound(world, s)
        return res
    else:
        find("warn", "대상을 인벤토리에서 찾지 못했습니다")
    sev = max((SEV.get(f["sev"], 1) for f in F), default=1)
    res["verdict"] = {3: "fail", 2: "warn", 1: "pass"}[sev]
    res["impact"] = {"vms": len(res["vms"]), "vms_on": sum(1 for v in res["vms"] if v["power"] == "on"), "hosts": len(res["hosts"]), "services": len(res["services"]),
                     "pods": sum(c["pods"] for c in res["vks"]["clusters"])}
    if not res["actions"]:
        res["actions"] = _actions(res)
    return res


def _actions(res: dict) -> list[str]:
    a = []
    txt = " ".join(f["text"] for f in res["findings"])
    if "HA 가 꺼져" in txt:
        a.append("클러스터 HA 를 켜고 승인 제어로 호스트 장애 1대 여유를 남기세요")
    if "로컬 디스크" in txt or "못 보는 데이터스토어" in txt or "다시 켤 수 없습니다" in txt:
        a.append("다시 켤 수 없는 VM 은 공유 데이터스토어로 옮기거나(스토리지 vMotion) 애플리케이션 이중화로 보완하세요")
    if "용량이 모자랍니다" in txt or "빠듯합니다" in txt:
        a.append("가정 분석에서 필요한 서버 수를 확인하고, 적정화로 돌려받을 자원을 먼저 정리하세요")
    if "컨트롤 플레인" in txt:
        a.append("VKS 컨트롤 플레인 노드가 서로 다른 호스트에 있도록 VM-호스트 반선호도(또는 vSphere Zone)를 확인하세요")
    if "Edge" in txt and "같은 호스트" in txt:
        a.append("NSX Edge VM 에 DRS 반선호도 규칙을 걸어 서로 다른 호스트에 두세요")
    if "업링크가 1개" in txt:
        a.append("스위치마다 물리 NIC 2개 이상(서로 다른 스위치로)을 연결하세요")
    if "vMotion 으로 옮길 수 없는" in txt or "CD-ROM" in txt:
        a.append("유지보수 전 CD-ROM·ISO 연결을 끊고, 패스스루·USB VM 은 작업 창에 맞춰 전원을 끄도록 계획하세요")
    if "DRS" in txt and "자동" in txt:
        a.append("유지보수 창에는 DRS 를 완전 자동으로 두거나 옮길 VM 목록을 미리 준비하세요")
    if "SRM 보호 밖" in txt:
        a.append("업무 중요도에 따라 보호 밖 VM 을 SRM 보호 그룹에 넣으세요")
    if "업링크가 모두 끊김" in txt or "업링크가 1개만" in txt or "네트워크가 끊깁니다" in txt:
        a.append("호스트 업링크를 MLAG/vPC 양쪽 스위치에 나눠 연결하고, 링크가 내려가 있는 vmnic 부터 복구하세요")
    if "외부와 통신하지" in txt or "남은 방화벽" in txt or "BGP 세션" in txt:
        a.append("외부 경로(방화벽·라우터·BGP 피어)를 서로 다른 스위치·장비로 이중화하세요")
    if "관리 구성요소" in txt:
        a.append("관리 VM(vCenter·NSX·SDDC 등)은 관리 도메인·서로 다른 호스트·다른 데이터스토어에 두세요")
    return a[:6]


def evaluate_compound(world: dict, s: dict) -> dict[str, Any]:
    """AI 제안 복합 시나리오 — steps 를 하나씩 검증하고 영향 리소스를 합친다. 같은 클러스터의 호스트 장애는 한꺼번에 용량 계산"""
    steps = s.get("steps") or []
    parts = []
    host_by_cl: dict[tuple, set] = {}
    for st in steps[:6]:
        typ = st.get("type")
        if typ not in TYPES or typ == "compound":
            continue
        sp = {**st, "id": "", "origin": "ai"}
        if typ in ("host_down",) and st.get("vcenter"):
            vc = _vc(world, st["vcenter"])
            h = (vc or {}).get("topo", {}).get("hosts", {}).get(st.get("target", "")) if vc else None
            if h:
                sp["cluster"] = h.get("cluster", "")
                host_by_cl.setdefault((st["vcenter"], sp["cluster"]), set()).add(st["target"])
        parts.append(evaluate(world, sp))
    for (vcn, cl), hs in host_by_cl.items():
        if len(hs) >= 2:
            parts.append(evaluate(world, {"type": "maint_plus_fail", "vcenter": vcn, "cluster": cl, "target": " + ".join(sorted(hs)), "hosts": sorted(hs), "id": ""}))
    F = [{"sev": f["sev"], "text": f"[{p['kind']} · {p['target']}] {f['text']}"} for p in parts for f in p["findings"]]
    vms: dict[str, dict] = {}
    for p in parts:
        for v in p["vms"]:
            vms.setdefault(v["name"], v)
    res = {**{k: v for k, v in s.items()}, "kind": TYPES["compound"][0], "findings": F, "vms": list(vms.values()), "hosts": sorted({h for p in parts for h in p["hosts"]}),
           "services": [x for p in parts for x in p["services"]][:100], "vks": {"clusters": [c for p in parts for c in p["vks"]["clusters"]]}, "actions": []}
    sev = max((SEV.get(f["sev"], 1) for f in F), default=1)
    res["verdict"] = {3: "fail", 2: "warn", 1: "pass"}[sev] if parts else "warn"
    if not parts:
        res["findings"] = [{"sev": "warn", "text": "AI 가 제안한 단계의 대상을 인벤토리에서 찾지 못했습니다"}]
    res["impact"] = {"vms": len(res["vms"]), "vms_on": sum(1 for v in res["vms"] if v["power"] == "on"), "hosts": len(res["hosts"]), "services": len(res["services"]),
                     "pods": sum(c["pods"] for c in res["vks"]["clusters"])}
    res["actions"] = _actions(res)
    return res


def score(r: dict, hist: dict[str, int]) -> float:
    """우선순위 — 판정 × (영향 규모) × (발생 가능성: 유형 기본값 + 이 환경 이력)"""
    base = TYPES[r["type"]][2]
    h = hist.get(r["type"], 0)
    like = min(1.0, base + 0.05 * h)
    imp = 1 + r["impact"]["vms_on"] + 5 * r["impact"]["services"] + 0.2 * r["impact"]["pods"]
    return round({"fail": 100, "warn": 30, "pass": 1}[r["verdict"]] * like * (1 + imp ** 0.5), 1)


# ------------------------------------------------------------------ AI
AI_SYS = ("너는 VMware VCF(vSphere·vSAN·NSX·VKS) 운영 SRE 다. 주어진 인벤토리 요약과 최근 장애 이력을 보고, 아직 검증하지 않았지만 실제로 일어날 법한 '복합 장애·작업' 시나리오를 제안한다.\n"
          "반드시 JSON 배열만 출력한다. 각 원소: {\"title\": 짧은 한국어 제목, \"why\": 이 환경에서 위험한 이유 1문장, \"steps\": [{\"type\": T, \"vcenter\": 이름, \"target\": 이름}]}\n"
          "T 는 host_down · ds_apd · uplink_loss · edge_down 중 하나. vcenter·target 은 요약에 있는 이름 그대로. steps 는 2~4개. 최대 8개 시나리오. 설명·코드 블록 금지.")
SUM_SYS = ("너는 VMware VCF 운영 SRE 다. AI 체크봇이 장애·작업 시나리오를 검증한 결과(JSON)를 보고 한국어로 짧게 쓴다.\n"
           "형식: **가장 위험한 것** — 3~5개, 각 1줄(시나리오·영향 VM 수·왜). **먼저 할 일** — 번호 목록 3~5개, 구체적 설정·작업. **잘 돼 있는 것** — 1~2줄.\n"
           "결과에 없는 사실은 쓰지 않는다. 수치는 결과 그대로.")


def inventory_brief(world: dict, hist: dict) -> tuple[dict, list[str]]:
    names: list[str] = []
    out = {"vcenters": [], "history_30d": hist}
    for vc in world["vcenters"]:
        T = vc["topo"]
        names.append(vc["name"])
        cl = []
        for cn, c in (T.get("clusters") or {}).items():
            names.append(cn)
            hs = [h for h in c.get("hosts", [])]
            names += hs
            cl.append({"cluster": cn, "hosts": hs[:16], "ha": c.get("ha"), "drs": c.get("drs"), "vsan": c.get("vsan"),
                       "vms_on": sum(1 for v in (T.get("vms") or {}).values() if v.get("cluster") == cn and "poweredOn" in str(v.get("power")))})
        ds = [dn for dn, d in (T.get("datastores") or {}).items() if (d.get("capacity_gb") or 0) and d.get("local") is not True][:20]
        names += ds
        out["vcenters"].append({"vcenter": vc["name"], "clusters": cl, "shared_datastores": ds})
    out["edge_clusters"] = sorted({e["edge_cluster"] for e in world["edges"]})
    return out, names


def parse_ai(text: str, world: dict) -> list[dict]:
    m = re.search(r"\[.*\]", text or "", re.S)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except ValueError:
        return []
    vcs = {v["name"]: v for v in world["vcenters"]}
    out = []
    for x in arr[:8] if isinstance(arr, list) else []:
        if not isinstance(x, dict):
            continue
        steps = []
        for st in (x.get("steps") or [])[:4]:
            if not isinstance(st, dict) or st.get("type") not in ("host_down", "ds_apd", "uplink_loss", "edge_down"):
                continue
            t, vcn, tg = st["type"], str(st.get("vcenter") or ""), str(st.get("target") or "")
            if t == "edge_down":
                if tg in {e["edge_cluster"] for e in world["edges"]}:
                    steps.append({"type": t, "target": tg})
                continue
            vc = vcs.get(vcn)
            if not vc:
                continue
            T = vc["topo"]
            if t in ("host_down", "uplink_loss") and tg in (T.get("hosts") or {}):
                steps.append({"type": t, "vcenter": vcn, "target": tg, "cluster": (T["hosts"][tg] or {}).get("cluster", "")})
            elif t == "ds_apd" and tg in (T.get("datastores") or {}):
                steps.append({"type": t, "vcenter": vcn, "target": tg})
        if len(steps) >= 2:
            title = " ".join(str(x.get("title") or "").split())[:120] or " + ".join(f"{TYPES[s['type']][0]}({s['target']})" for s in steps)
            out.append({"type": "compound", "target": title, "steps": steps, "why": " ".join(str(x.get("why") or "").split())[:300], "origin": "ai",
                        "id": "compound:" + "|".join(f"{s['type']}:{s['target']}" for s in steps)[:190]})
    return out


def rule_compounds(world: dict, results: list[dict]) -> list[dict]:
    """AI 가 없을 때의 복합 시나리오 — 가장 위험한 호스트 장애 + 그 호스트가 쓰는 가장 붐비는 공유 데이터스토어 APD"""
    out = []
    hd = sorted([r for r in results if r["type"] == "host_down"], key=lambda r: -r["impact"]["vms_on"])[:3]
    for r in hd:
        vc = _vc(world, r.get("vcenter", ""))
        if not vc:
            continue
        T = vc["topo"]
        dss = [d for d in (T.get("hosts", {}).get(r["target"], {}).get("datastores") or []) if (T.get("datastores") or {}).get(d, {}).get("local") is not True]
        if not dss:
            continue
        busy = max(dss, key=lambda d: sum(1 for v in (T.get("vms") or {}).values() if d in (v.get("datastores") or [])))
        steps = [{"type": "host_down", "vcenter": vc["name"], "target": r["target"], "cluster": r.get("cluster", "")}, {"type": "ds_apd", "vcenter": vc["name"], "target": busy}]
        out.append({"type": "compound", "target": f"{r['target']} 장애 + {busy} APD", "steps": steps, "origin": "rule",
                    "why": "가장 많은 VM 이 있는 호스트와 그 호스트가 쓰는 가장 붐비는 데이터스토어가 함께 문제일 때", "id": f"compound:rule:{r['target']}:{busy}"[:190]})
    return out


# ------------------------------------------------------------------ 실행·저장·알림
SCHEMA = ("""CREATE TABLE IF NOT EXISTS checkbot_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, by TEXT, summary TEXT, results TEXT, ai TEXT)""",)


class CheckBot:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = {"interval_h": 6, "ai": True, "keep_runs": 60, **(cfg or {})}
        self.last: dict[str, Any] | None = None
        self._ready = False
        self._busy = False
        self.ai_extra: list[dict] = []          # AI 가 제안해 둔 복합 시나리오 — 다음 실행에도 계속 검증
        self.state: dict[str, Any] = {"running": False, "error": "", "last": 0}

    async def ensure(self) -> None:
        if not self._ready:
            for q in SCHEMA:
                await self.e.store.x(q)
            r = await self.e.store.q1("SELECT ai FROM checkbot_runs WHERE ai IS NOT NULL AND ai != '' ORDER BY id DESC LIMIT 1")
            if r:
                try:
                    self.ai_extra = json.loads(r["ai"]).get("scenarios") or []
                except (TypeError, ValueError):
                    self.ai_extra = []
            self._ready = True

    def _llm_ok(self) -> bool:
        llm = getattr(self.e, "llm", None)
        try:
            return bool(llm and self.cfg.get("ai") and llm.order("report"))
        except Exception:  # noqa: BLE001
            return False

    async def run(self, by: str = "schedule", ai: bool | None = None) -> dict[str, Any]:
        if self._busy:
            return self.last or {}
        self._busy = True
        self.state["running"] = True
        try:
            await self.ensure()
            world = build_world(self.e)
            hist = await history_counts(self.e.store)
            capd = {}
            try:
                ov = await self.e.capacity.overview()
                for x in ov.get("items", []):
                    if x["kind"] == "datastore":
                        capd[(x["vcenter"], x["name"])] = ((x.get("forecast") or {}).get("days_to") or {}).get("90")
            except Exception:  # noqa: BLE001
                pass
            specs = generate(world, capd)
            results = [evaluate(world, s) for s in specs]
            results += [evaluate(world, s) for s in rule_compounds(world, results)]
            use_ai = self._llm_ok() if ai is None else (ai and self._llm_ok())
            ai_note = {}
            if use_ai:
                try:
                    brief, names = inventory_brief(world, hist)
                    txt = await asyncio.wait_for(self.e.llm.complete(AI_SYS, json.dumps(brief, ensure_ascii=False)[:12000], max_tokens=1600, task="report", names=names), 120)
                    new = parse_ai(txt, world)
                    known = {x["id"] for x in self.ai_extra}
                    self.ai_extra = (self.ai_extra + [x for x in new if x["id"] not in known])[-30:]
                    ai_note["proposed"] = len(new)
                except Exception as ex:  # noqa: BLE001
                    ai_note["error"] = f"시나리오 제안 실패: {type(ex).__name__}"
            results += [evaluate_compound(world, s) for s in self.ai_extra]
            for r in results:
                r["score"] = score(r, hist)
                r["history"] = hist.get(r["type"], 0)
            results.sort(key=lambda r: -r["score"])
            summ = {"ts": time.time(), "by": by, "scenarios": len(results), "by_verdict": {v: sum(1 for r in results if r["verdict"] == v) for v in ("fail", "warn", "pass")},
                    "by_type": {t: {"n": sum(1 for r in results if r["type"] == t), "fail": sum(1 for r in results if r["type"] == t and r["verdict"] == "fail")}
                                for t in TYPES if any(r["type"] == t for r in results)},
                    "history": hist, "ai": bool(use_ai), "vcenters": len(world["vcenters"]), "ai_scenarios": len(self.ai_extra)}
            if use_ai:
                try:
                    top = [{k: r[k] for k in ("kind", "target", "verdict", "impact")} | {"findings": [f["text"] for f in r["findings"] if f["sev"] != "pass"][:4]}
                           for r in results if r["verdict"] != "pass"][:25]
                    _, names = inventory_brief(world, hist)
                    ai_note["summary"] = await asyncio.wait_for(self.e.llm.complete(SUM_SYS, json.dumps({"summary": summ, "top": top}, ensure_ascii=False)[:14000],
                                                                                    max_tokens=1200, task="report", names=names), 120)
                except Exception as ex:  # noqa: BLE001
                    ai_note["error"] = (ai_note.get("error", "") + f" 요약 실패: {type(ex).__name__}").strip()
            prev = {r["id"]: r["verdict"] for r in (self.last or {}).get("results", [])}
            if not prev:
                pr = await self.e.store.q1("SELECT results FROM checkbot_runs ORDER BY id DESC LIMIT 1")
                if pr:
                    try:
                        prev = {r["id"]: r["verdict"] for r in json.loads(pr["results"])}
                    except (TypeError, ValueError, KeyError):
                        prev = {}
            summ["ai"] = bool(use_ai) and not ai_note.get("error")
            newly = [r for r in results if r["verdict"] == "fail" and prev and prev.get(r["id"]) not in ("fail", None)]
            fixed = [r for r in results if r["verdict"] != "fail" and prev.get(r["id"]) == "fail"]
            summ["new_fail"], summ["fixed"] = len(newly), len(fixed)
            self.last = {"summary": summ, "results": results, "ai": ai_note, "new_fail": [r["id"] for r in newly], "fixed": [r["id"] for r in fixed]}
            await self.e.store.x("INSERT INTO checkbot_runs(ts, by, summary, results, ai) VALUES(?,?,?,?,?)",
                                 (summ["ts"], by, json.dumps(summ, ensure_ascii=False), json.dumps(results, ensure_ascii=False, default=str),
                                  json.dumps({**ai_note, "scenarios": self.ai_extra}, ensure_ascii=False)))
            await self.e.store.x("DELETE FROM checkbot_runs WHERE id NOT IN (SELECT id FROM checkbot_runs ORDER BY id DESC LIMIT ?)", (int(self.cfg["keep_runs"]),))
            await self._events(newly)
            self.state.update(last=summ["ts"], error="")
            return self.last
        except Exception as ex:  # noqa: BLE001
            self.state["error"] = f"{type(ex).__name__}: {ex}"[:200]
            raise
        finally:
            self._busy = False
            self.state["running"] = False

    async def _events(self, newly: list[dict]) -> None:
        ingest = getattr(self.e, "ingest", None)
        if not ingest or not newly:
            return
        from .models import LogEvent
        for r in newly[:20]:
            msg = f"AI 체크봇: {r['kind']}({r['target']}) 검증 실패 — " + "; ".join(f["text"] for f in r["findings"] if f["sev"] == "fail")[:300]
            ev = LogEvent(source="aiops", connector="checkbot", message=msg, severity="warning", host="", entity=str(r["target"])[:120], kind="health",
                          attrs={"app": "checkbot", "scenario": r["id"], "type": r["type"]})
            ingest(ev) if not inspect.iscoroutinefunction(ingest) else await ingest(ev)

    async def latest(self) -> dict[str, Any] | None:
        if self.last:
            return self.last
        await self.ensure()
        r = await self.e.store.q1("SELECT summary, results, ai FROM checkbot_runs ORDER BY id DESC LIMIT 1")
        if not r:
            return None
        ai = json.loads(r["ai"] or "{}")
        self.last = {"summary": json.loads(r["summary"]), "results": json.loads(r["results"]), "ai": {k: v for k, v in ai.items() if k != "scenarios"},
                     "new_fail": [], "fixed": []}
        return self.last

    async def history(self, n: int = 60) -> list[dict]:
        await self.ensure()
        return [json.loads(r["summary"]) for r in await self.e.store.q("SELECT summary FROM checkbot_runs ORDER BY id DESC LIMIT ?", (n,))][::-1]

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(300)                                 # 첫 인프라 점검·토폴로지가 모인 뒤
        while True:
            beat()
            try:
                last = (self.last or {}).get("summary", {}).get("ts") or (await self.latest() or {}).get("summary", {}).get("ts") or 0
                if time.time() - last > float(self.cfg["interval_h"]) * 3600:
                    await self.run("schedule")
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(600)
