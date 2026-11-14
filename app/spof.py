"""단일 장애점 순위(2.48.0) — 객체 하나씩 '혼자 고장 나면'을 모두 계산해 피해가 큰 순으로

대상: ESXi 호스트 · 공유 데이터스토어 · 스위치 · 방화벽·라우터 · 스토리지 장비 · Edge 클러스터 · Supervisor · VKS 노드 · Avi 컨트롤러 노드 · Avi SE
점수 = 서비스 중단 VM(고장 낸 객체 자신 제외) ×10 + 재시작 불확실 VM ×5 + HA 재시작 VM ×1 + 중단 워크로드·VIP ×8 + 잠깐 중단 워크로드·VIP ×2 + 다시 배치 못 하는 Pod ×1
읽기 전용 — simulator.simulate 를 객체마다 부를 뿐 명령은 없다.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from . import platsim as PS
from . import simulator as SIM

MAX_OBJ = 400


def candidates(W: dict) -> list[tuple[str, str, dict]]:
    out: list[tuple[str, str, dict]] = []
    for vc in W["vcenters"]:
        T = vc["topo"]
        for h in sorted(T.get("hosts") or {}):
            out.append(("ESXi 호스트", h, {"type": "host_down", "vcenter": vc["name"], "target": h}))
        for dn, d in sorted((T.get("datastores") or {}).items()):
            if d.get("local") is not True and d.get("capacity_gb"):
                out.append(("데이터스토어", dn, {"type": "ds_apd", "vcenter": vc["name"], "target": dn}))
    ph = W.get("phys") or {}
    for n in sorted(ph.get("switches") or {}):
        out.append(("스위치", n, {"type": "switch_down", "vcenter": "", "target": n}))
    for n in sorted(ph.get("devices") or {}):
        out.append(("방화벽·라우터", n, {"type": "device_down", "vcenter": "", "target": n}))
    for n in sorted(ph.get("storage") or {}):
        out.append(("스토리지 장비", n, {"type": "storage_down", "vcenter": "", "target": n}))
    for ec in sorted({e["edge_cluster"] for e in W.get("edges") or [] if e.get("edge_cluster")}):
        out.append(("Edge 클러스터", ec, {"type": "edge_down", "vcenter": "", "target": ec}))
    P = PS.build(W)
    for s in P["supervisors"]:
        out.append(("Supervisor", s["name"], {"type": "sup_down", "vcenter": s["vcenter"], "target": s["name"]}))
    for k in P["vks"]:
        for n in k["nodes"]:
            out.append(("VKS 노드", n["name"], {"type": "node_down", "vcenter": "", "target": f"{k['cluster']}/{n['name']}"}))
    for a in P["avi"]:
        for c in a["controllers"]:
            out.append(("Avi 컨트롤러", c["name"], {"type": "avi_ctrl_down", "vcenter": "", "target": f"{a['name']}/{c['name']}"}))
        for s in a["se"]:
            out.append(("Avi SE", s["name"], {"type": "avi_se_down", "vcenter": "", "target": f"{a['name']}/{s['name']}"}))
    return out[:MAX_OBJ]


def score(r: dict, self_name: str = "") -> tuple[int, dict]:
    """고장 낸 객체 자신(SE·컨트롤러·노드·컨트롤 플레인 VM)은 '중단 VM' 에서 뺀다 — 그 객체가 멈추는 건 가정 그 자체"""
    own = {x["name"] for x in r.get("vms") or [] if x["name"] == self_name or (x.get("by") and all("(가정)" in b for b in x["by"]))}
    c = Counter(x["state"] for x in r.get("vms") or [] if x["name"] not in own)
    pc = (r.get("platform") or {}).get("counts") or {}
    pods = (r.get("platform") or {}).get("pod_counts") or {}
    d = {"stop": sum(c.get(k, 0) for k in ("down", "io", "net", "ext")), "maybe": c.get("maybe", 0), "restart": c.get("restart", 0),
         "pstop": pc.get("stop", 0), "pboot": pc.get("boot", 0), "pods": pods.get("stuck", 0) + pods.get("unsure", 0)}
    s = d["stop"] * 10 + d["maybe"] * 5 + d["restart"] + d["pstop"] * 8 + d["pboot"] * 2 + d["pods"]
    return s, d


def scan(W: dict, top: int = 40) -> dict[str, Any]:
    rows = []
    for kind, name, f in candidates(W):
        try:
            r = SIM.simulate(W, [f])
        except Exception as e:  # noqa: BLE001
            rows.append({"kind": kind, "name": name, "failure": f, "score": -1, "error": f"{type(e).__name__}"})
            continue
        s, d = score(r, name)
        why = next((x["text"] for x in r["findings"] if x["sev"] == "fail"), "") or next((x["text"] for x in r["findings"] if x["sev"] == "warn"), "")
        rows.append({"kind": kind, "name": name, "failure": f, "score": s, "verdict": r["verdict"], **d, "why": why[:220],
                     "downtime": (r.get("timeline") or {}).get("vm_minutes")})
    rows.sort(key=lambda x: (-x["score"], x["kind"], x["name"]))
    by_kind: dict[str, int] = {}
    for x in rows:
        by_kind[x["kind"]] = by_kind.get(x["kind"], 0) + 1
    spof = [x for x in rows if x.get("stop") or x.get("pstop")]
    return {"scanned": len(rows), "by_kind": by_kind, "spof": len(spof), "top": rows[:top],
            "rule": "점수 = 중단 VM(고장 낸 객체 자신 제외)×10 + 재시작 불확실 VM×5 + HA 재시작 VM×1 + 중단 워크로드·VIP×8 + 잠깐 중단×2 + 다시 배치 못 하는 Pod×1"}
