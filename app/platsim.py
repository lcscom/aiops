"""What-If 플랫폼 계층(2.46.0) — Supervisor · VKS(컨트롤 플레인·워커 노드·워크로드) · vSphere Pod · Avi(컨트롤러·SE·가상 서비스)

장애 시뮬레이터가 VM·호스트 수준으로 계산한 결과(잃는 VM)에 더해, 그 위에서 도는 플랫폼이 어떻게 되는지를 계산한다.
  · 직접 가정: Supervisor 장애·업그레이드, VKS 컨트롤 플레인 장애·롤링 업그레이드, VKS 노드 장애, Avi 컨트롤러 노드 장애, Avi SE 장애
  · 간접: 호스트·클러스터·스토리지·스위치 장애로 잃은 VM 이 Supervisor 컨트롤 플레인 VM·VKS 노드·Avi 컨트롤러·SE 이면 같은 규칙으로
판정 규칙(일반 동작 기준 — 버전·설정에 따라 다를 수 있음):
  · 컨트롤 플레인(Supervisor·VKS·Avi 컨트롤러) 3대 중 과반(2대)을 잃으면 쿼럼 상실 → API·구성 변경 멈춤. 1대는 이중화로 버팀
  · Supervisor 가 멈춰도 VKS 워크로드·vSphere Pod 는 계속 돈다. 대신 노드 자동 복구·확장·생성·업그레이드(Cluster API)와 새 Pod 배치가 멈춤
  · VKS 컨트롤 플레인 쿼럼 상실 → 이미 뜬 Pod 는 계속, 노드가 죽어도 다른 노드로 다시 배치 못 함
  · 워크로드(Deployment·StatefulSet 추정)의 Pod 가 모두 잃는 노드에 있으면 중단, 1개뿐이면 다른 노드에서 다시 뜰 때까지(수 분) 중단, 일부면 남은 Pod 로 계속
  · Avi SE 를 잃으면 그 SE 에 놓인 가상 서비스는 다른 SE 가 있으면 계속, 없으면 컨트롤러가 SE 그룹에 다시 배치할 때까지 중단(컨트롤러도 멈췄으면 복구 전까지)
  · Avi 컨트롤러 쿼럼 상실 → SE 는 마지막 구성으로 트래픽을 계속 처리(headless), 구성 변경·SE 재배치·자동 확장·분석이 멈춤
읽기 전용 — 수집 자료의 복사본으로 계산만 한다.
"""
from __future__ import annotations

import re
from typing import Any

TYPES = {
    "sup_down": ("Supervisor 장애", "Supervisor 컨트롤 플레인 VM 이 멈춤 — VKS·vSphere Pod 는 계속 돌지만 생성·복구·확장이 멈춤"),
    "sup_upgrade": ("Supervisor 업그레이드", "컨트롤 플레인 VM 을 한 대씩 교체 — Supervisor API 가 잠깐씩 끊김"),
    "vks_cp_down": ("VKS 컨트롤 플레인 장애", "VKS 클러스터의 컨트롤 플레인 노드가 모두 멈춤 — kube API 중단"),
    "vks_upgrade": ("VKS 롤링 업그레이드", "노드를 한 대씩 새 노드로 교체 — 노드마다 Pod 가 다른 노드로 옮겨 감"),
    "node_down": ("VKS 노드 장애", "노드 VM 이 멈춤 — 그 노드의 Pod 를 잃음"),
    "avi_ctrl_down": ("Avi 컨트롤러 노드 장애", "컨트롤러 클러스터 노드 하나가 멈춤"),
    "avi_se_down": ("Avi SE 장애", "Service Engine 이 멈춤 — 그 SE 의 가상 서비스(VIP)"),
}
ACTIONS = {
    "supervisor": [("sup_down", "컨트롤 플레인 장애"), ("sup_upgrade", "업그레이드(롤링)")],
    "vks": [("vks_cp_down", "컨트롤 플레인 장애"), ("vks_upgrade", "롤링 업그레이드")],
    "vksnode": [("node_down", "노드 장애")],
    "avictrl": [("avi_ctrl_down", "노드 장애")],
    "avise": [("avi_se_down", "SE 장애")],
}
LOST = {"down", "io", "net", "maybe", "restart"}                 # 시뮬레이터 VM 상태 중 '그 VM 이 (잠시라도) 멈춤'
CP_ROLES = ("control-plane", "master")


def owner(pod: str, node: str = "") -> tuple[str, str]:
    """Pod 이름 → (워크로드 이름, 종류 추정). 노드 이름으로 끝나면 정적 Pod(노드마다 하나)"""
    if node and pod.endswith("-" + node):
        return pod[: -len(node) - 1], "static"
    m = re.match(r"^(.+)-[a-z0-9]{6,10}-[a-z0-9]{5}$", pod)
    if m:
        return m.group(1), "deploy"
    m = re.match(r"^(.+)-\d+$", pod)
    if m:
        return m.group(1), "sts"
    m = re.match(r"^(.+)-[a-z0-9]{5}$", pod)
    if m:
        return m.group(1), "ds"
    return pod, "pod"


def _vm_index(world: dict) -> dict[str, tuple[str, dict]]:
    return {n: (vc["name"], v) for vc in world["vcenters"] for n, v in (vc["topo"].get("vms") or {}).items()}


def build(world: dict) -> dict[str, Any]:
    """world → 플랫폼 인벤토리(Supervisor·VKS·Avi)"""
    V = _vm_index(world)
    vks = []
    for k in world.get("vks") or []:
        nodes = []
        for n in k.get("nodes") or []:
            nm = n.get("name", "")
            vc, v = V.get(nm, ("", {}))
            nodes.append({"name": nm, "cp": any(r in CP_ROLES for r in n.get("roles") or []), "vcenter": vc, "host": v.get("host", ""), "cluster": v.get("cluster", ""),
                          "vm": bool(v), "pods": sum(1 for p in k.get("pods") or [] if p.get("node") == nm)})
        wl: dict[tuple, dict] = {}
        for p in k.get("pods") or []:
            o, kind = owner(str(p.get("name", "")), str(p.get("node", "")))
            w = wl.setdefault((p.get("ns", ""), o), {"ns": p.get("ns", ""), "name": o, "kind": kind, "pods": []})
            w["pods"].append({"name": p.get("name", ""), "node": p.get("node", "")})
        for w in wl.values():                                      # 노드마다 하나씩 → DaemonSet 류
            nn = [x["node"] for x in w["pods"]]
            if w["kind"] in ("ds", "static") or (len(nn) >= 2 and len(set(nn)) == len(nn) == len(nodes) > 1 and w["kind"] != "sts"):
                w["kind"] = "static" if w["kind"] == "static" else "ds"
        vks.append({"cluster": k["cluster"], "name": k.get("name", ""), "role": k.get("role", ""), "nodes": nodes,
                    "workloads": sorted(wl.values(), key=lambda w: (w["ns"], w["name"])),
                    "vcenter": next((n["vcenter"] for n in nodes if n["vcenter"]), ""), "vsphere_cluster": next((n["cluster"] for n in nodes if n["cluster"]), "")})
    sups = []
    for vc in world["vcenters"]:
        T = vc["topo"].get("vms") or {}
        for s in vc.get("supervisors") or []:
            cl = s.get("name", "")
            cps = sorted(n for n, v in T.items() if n.lower().startswith("supervisorcontrolplanevm") and (v.get("cluster") == cl or not cl))
            pods = sorted(n for n, v in T.items() if "crx" in str(v.get("os", "")).lower() and v.get("cluster") == cl)
            sups.append({"vcenter": vc["name"], "name": cl, "endpoint": s.get("endpoint", ""), "namespaces": s.get("namespaces") or [],
                         "cp": [{"name": n, "host": T[n].get("host", "")} for n in cps], "pods": [{"name": n, "host": T[n].get("host", "")} for n in pods],
                         "vks": [k["cluster"] for k in vks if k["vsphere_cluster"] == cl and k["vcenter"] == vc["name"]]})
    avis = []
    for a in world.get("avi") or []:
        ctrl = []
        for n in (a.get("controllers") or {}).get("nodes") or []:
            vm = next((x for x, (_, v) in V.items() if x.lower() == str(n.get("name", "")).lower() or (n.get("ip") and n.get("ip") in (v.get("ips") or []))), "")
            vc, v = V.get(vm, ("", {}))
            ctrl.append({"name": n.get("name", ""), "ip": n.get("ip", ""), "role": n.get("role", ""), "vm": vm, "vcenter": vc, "host": v.get("host", "")})
        ses = []
        for s in a.get("se") or []:
            vm = s["name"] if s["name"] in V else ""
            ses.append({**s, "vm": vm, "vcenter": V.get(vm, ("", {}))[0] if vm else ""})
        avis.append({"name": a["name"], "state": (a.get("controllers") or {}).get("state", ""), "controllers": ctrl, "se": ses, "vs": a.get("vs") or []})
    return {"supervisors": sups, "vks": vks, "avi": avis}


def norm(P: dict, f: dict) -> dict | None:
    t, tg, vcn = f.get("type"), str(f.get("target") or ""), str(f.get("vcenter") or "")
    if t in ("sup_down", "sup_upgrade"):
        return {"type": t, "vcenter": vcn, "target": tg} if any(s["vcenter"] == vcn and s["name"] == tg for s in P["supervisors"]) else None
    if t in ("vks_cp_down", "vks_upgrade"):
        return {"type": t, "target": tg} if any(k["cluster"] == tg for k in P["vks"]) else None
    if t == "node_down":
        c, _, n = tg.rpartition("/")
        return {"type": t, "target": tg} if any(k["cluster"] == c and any(x["name"] == n for x in k["nodes"]) for k in P["vks"]) else None
    if t in ("avi_ctrl_down", "avi_se_down"):
        a, _, n = tg.partition("/")
        for x in P["avi"]:
            if x["name"] == a and any(y["name"] == n for y in (x["controllers"] if t == "avi_ctrl_down" else x["se"])):
                return {"type": t, "target": tg}
    return None


def evaluate(P: dict, fs: list[dict], vm_states: dict[tuple, str], lost_hosts: set[tuple]) -> dict[str, Any]:
    """fs = 플랫폼 가정(norm 거친 것) · vm_states = {(vcenter, vm): 시뮬레이터 상태} · lost_hosts = {(vcenter, host)} 꺼진 호스트
    → {findings, items, marks, vms(직접 가정으로 멈추는 VM), actions}"""
    F: list[dict] = []
    items: list[dict] = []
    pods: list[dict] = []                           # 2.47.0 영향받는 Pod 하나하나 — {cluster, ns, pod, node, workload, kind, state, text}
    marks: dict[str, str] = {}
    vm_hits: list[tuple] = []                       # (vcenter, vm, state, reason)
    actions: list[str] = []
    T = {f["type"]: [] for f in fs}
    for f in fs:
        T[f["type"]].append(f)

    def vm_lost(vc: str, vm: str, host: str = "") -> bool:
        return bool(vm) and (vm_states.get((vc, vm)) in LOST or (vc, host) in lost_hosts)

    def back(vc: str, vm: str) -> bool:
        """HA 가 다른 호스트에서 다시 켜 주는 VM — 잠깐(수 분) 멈췄다 돌아옴"""
        return vm_states.get((vc, vm)) == "restart"

    def item(kind: str, name: str, state: str, text: str, scope: str = ""):
        items.append({"kind": kind, "name": name, "state": state, "text": text, "scope": scope})

    # ---------------------------------------------------------------- Supervisor
    sup_dead: set[tuple] = set()
    for s in P["supervisors"]:
        key = (s["vcenter"], s["name"])
        direct = next((f for f in fs if f["type"] in ("sup_down", "sup_upgrade") and (f["vcenter"], f["target"]) == key), None)
        lost = [c["name"] for c in s["cp"] if vm_lost(s["vcenter"], c["name"], c["host"])]
        tot = len(s["cp"]) or 3
        tag = f"Supervisor · {s['name']}"
        temp = not direct and lost and all(back(s["vcenter"], n) for n in lost)
        if direct and direct["type"] == "sup_down" or len(lost) * 2 > tot:
            sup_dead.add(key)
            marks[f"sup:{s['vcenter']}/{s['name']}"] = "failed"
            why = "가정" if direct else f"컨트롤 플레인 VM {len(lost)}/{tot}대를 잃음({', '.join(lost)})" + (" — HA 가 다시 켜는 수 분 동안" if temp else "")
            F.append({"sev": "fail", "text": f"[{tag}] Supervisor API 가 멈춥니다({why}) — 네임스페이스·VM 서비스·VKS 생성·확장·업그레이드, 새 vSphere Pod 배치가 멈춥니다"})
            for c in s["cp"]:
                if direct:
                    vm_hits.append((s["vcenter"], c["name"], "down", "Supervisor 컨트롤 플레인 장애(가정)"))
            for k in s["vks"]:
                item("VKS 클러스터", k, "risk", f"워크로드는 계속 돎 · Supervisor 가 멈춘 동안 노드 자동 복구·확장·업그레이드(Cluster API) 안 됨")
                for kk in P["vks"]:
                    if kk["cluster"] == k:
                        for w in kk["workloads"]:
                            for p in w["pods"]:
                                pods.append({"cluster": k, "ns": w["ns"], "pod": p["name"], "node": p["node"], "workload": w["name"], "kind": w["kind"], "state": "frozen",
                                             "text": "계속 돎 — 노드가 죽으면 새 노드가 만들어지지 않음(Supervisor 복구 전까지)"})
            for p in s["pods"]:
                item("vSphere Pod", p["name"], "risk", "실행 중인 Pod 는 계속 · 멈추면 다시 뜨지 못함(Supervisor 복구 전까지)")
                pods.append({"cluster": f"Supervisor {s['name']}", "ns": "", "pod": p["name"], "node": p["host"], "workload": "vSphere Pod", "kind": "vsphere-pod", "state": "frozen",
                             "text": "실행 중이면 계속 — 멈추면 다시 뜨지 못함"})
            for n in s["namespaces"]:
                item("vSphere 네임스페이스", n, "risk", "셀프서비스(VM·클러스터·Pod 만들기) 불가")
            actions.append(f"Supervisor '{s['name']}' 컨트롤 플레인 VM 3대를 서로 다른 호스트에 두고(vSphere 기본 반선호도) 호스트 2대 동시 장애에 대비한 여유를 두세요")
        elif direct and direct["type"] == "sup_upgrade":
            marks[f"sup:{s['vcenter']}/{s['name']}"] = "maint"
            F.append({"sev": "warn", "text": f"[{tag}] 업그레이드 중 컨트롤 플레인 VM 을 한 대씩 교체 — Supervisor API 가 잠깐씩 끊기고 그동안 변경 작업이 실패할 수 있습니다. VKS 클러스터·vSphere Pod 워크로드는 계속 돕니다"})
            F.append({"sev": "warn", "text": f"[{tag}] ESXi 의 Supervisor 구성요소(spherelet)도 바뀌면 호스트별로 vSphere Pod {len(s['pods'])}개가 다시 시작될 수 있습니다 — 업무 외 시간에"})
            if s["vks"]:
                F.append({"sev": "pass", "text": f"[{tag}] VKS 클러스터 {len(s['vks'])}개는 자동으로 업그레이드되지 않습니다 — 지원 버전 범위 안인지 먼저 확인하세요"})
            actions.append("Supervisor 업그레이드 전: 지원되는 VKS(Kubernetes) 버전 범위·컨트롤 플레인 VM 용 여유 자원(새 VM 1대)·vCenter 백업 확인")
        elif lost:
            marks[f"sup:{s['vcenter']}/{s['name']}"] = "degraded"
            F.append({"sev": "warn", "text": f"[{tag}] 컨트롤 플레인 VM {len(lost)}/{tot}대를 잃음 — 과반이 남아 API 는 계속, 하나 더 잃으면 멈춥니다"})

    # ---------------------------------------------------------------- VKS
    for k in P["vks"]:
        ck = k["cluster"]
        tag = f"VKS · {ck}"
        sup_down = any((k["vcenter"], s["name"]) in sup_dead and ck in s["vks"] for s in P["supervisors"])
        cp_direct = any(f["type"] == "vks_cp_down" and f["target"] == ck for f in fs)
        upg = any(f["type"] == "vks_upgrade" and f["target"] == ck for f in fs)
        lost_nodes = set()
        for n in k["nodes"]:
            d = any(f["type"] == "node_down" and f["target"] == f"{ck}/{n['name']}" for f in fs)
            if d or vm_lost(n["vcenter"], n["name"], n["host"]) or (cp_direct and n["cp"]):
                lost_nodes.add(n["name"])
                marks[f"vksnode:/{ck}/{n['name']}"] = "failed"
                if d and n["vm"]:
                    vm_hits.append((n["vcenter"], n["name"], "down", f"VKS 노드 장애(가정) — {ck}"))
                if cp_direct and n["cp"] and n["vm"]:
                    vm_hits.append((n["vcenter"], n["name"], "down", f"VKS 컨트롤 플레인 장애(가정) — {ck}"))
        cps = [n for n in k["nodes"] if n["cp"]]
        cp_lost = [n["name"] for n in cps if n["name"] in lost_nodes]
        quorum = not cps or len(cp_lost) * 2 < len(cps)
        ret = {n["name"] for n in k["nodes"] if n["name"] in lost_nodes and back(n["vcenter"], n["name"]) and not (cp_direct and n["cp"])}
        unsure = {n["name"] for n in k["nodes"] if n["name"] in lost_nodes and vm_states.get((n["vcenter"], n["name"])) == "maybe"}   # HA 재시작이 용량 때문에 불확실
        cp_temp = bool(cp_lost) and all(x in ret for x in cp_lost)
        workers = [n for n in k["nodes"] if not n["cp"]]
        if upg:
            marks[f"vks:/{ck}"] = "maint"
            single = [w for w in k["workloads"] if w["kind"] in ("deploy", "sts", "pod") and len(w["pods"]) == 1]
            F.append({"sev": "warn" if single else "pass", "text": f"[{tag}] 롤링 업그레이드 — 노드 {len(k['nodes'])}대를 한 대씩 새 노드로 바꿉니다. Pod 가 하나뿐인 워크로드 {len(single)}개는 옮겨 가는 동안 잠깐 멈춥니다"
                      + (f"({', '.join(w['ns'] + '/' + w['name'] for w in single[:5])})" if single else "")})
            F.append({"sev": "warn", "text": f"[{tag}] 새 노드 VM 을 먼저 만들고 옛 노드를 지우므로 노드 1대 분량 여유 자원이 vSphere 클러스터에 있어야 합니다. PodDisruptionBudget 이 너무 빡빡하면 노드 비우기에서 멈춥니다"})
            for w in single:
                item("VKS 워크로드", f"{w['ns']}/{w['name']}", "boot", "Pod 1개 — 노드 교체 때 다른 노드에서 다시 뜸(수 분)", ck)
            actions.append(f"VKS '{ck}' 업그레이드 전: 단일 Pod 워크로드에 replicas ≥ 2·PDB, 노드 1대 분량 여유, Supervisor 지원 버전 확인")
            if sup_down:
                F.append({"sev": "fail", "text": f"[{tag}] Supervisor 가 멈춘 상태에서는 업그레이드(Cluster API)가 진행되지 않습니다"})
        if not lost_nodes and not sup_down and not cp_direct:
            continue
        if not lost_nodes and sup_down:
            continue
        marks.setdefault(f"vks:/{ck}", "failed" if not quorum else "degraded")
        if cps and not quorum:
            F.append({"sev": "fail", "text": f"[{tag}] 컨트롤 플레인 {len(cp_lost)}/{len(cps)}대를 잃어 쿼럼 상실 — kube API·스케줄링이 멈춥니다"
                      + (" (HA 가 노드 VM 을 다시 켜는 수 분 동안)" if cp_temp else "") + ". 이미 떠 있는 Pod 는 계속 돌지만 죽은 노드의 Pod 를 다시 배치하지 못합니다"})
        elif cp_lost:
            F.append({"sev": "warn", "text": f"[{tag}] 컨트롤 플레인 {len(cp_lost)}/{len(cps)}대를 잃음 — 과반이 남아 API 는 계속"})
        lost_w = [n for n in workers if n["name"] in lost_nodes]
        if workers and len(lost_w) == len(workers):
            F.append({"sev": "fail", "text": f"[{tag}] 워커 노드 {len(workers)}대를 모두 잃음 — 일반 워크로드가 갈 곳이 없습니다"})
        can_reschedule = quorum and len(lost_w) < len(workers)
        if can_reschedule and lost_w and not sup_down:
            F.append({"sev": "pass", "text": f"[{tag}] 워커 {len(lost_w)}대를 잃음 — 쿠버네티스가 Pod 를 남은 노드로 다시 배치하고 Cluster API 가 새 노드를 만듭니다(남은 노드 자원이 충분해야 함)"})
        elif lost_w and sup_down:
            F.append({"sev": "warn", "text": f"[{tag}] Supervisor 가 멈춰 잃은 노드를 새로 만들지 못합니다 — 남은 노드로만 버팁니다"})
        for w in k["workloads"]:
            on = [p for p in w["pods"] if p["node"] in lost_nodes]
            if not on:
                continue
            nm = f"{w['ns']}/{w['name']}"
            for p in w["pods"]:                                      # Pod 하나하나
                lost = p["node"] in lost_nodes
                if w["kind"] in ("ds", "static"):
                    pst, ptx = ("gone", "노드마다 하나(DaemonSet·정적 Pod) — 노드와 함께 멈췄다 노드가 돌아오면 같이") if lost else ("", "")
                elif not lost:
                    pst, ptx = "kept", "다른 노드 — 계속"
                elif p["node"] in ret:
                    pst, ptx = "back", "노드 VM 이 HA 로 다시 켜지면 같이 돌아옴(수 분)"
                elif can_reschedule:
                    pst, ptx = "resched", "다른 노드에 다시 배치(수 분)"
                elif p["node"] in unsure:
                    pst, ptx = "unsure", "노드가 HA 로 다시 켜지지 못할 수 있음(용량 부족)"
                else:
                    pst, ptx = "stuck", "다시 배치 못 함(컨트롤 플레인·남은 노드 없음)"
                if pst:
                    pods.append({"cluster": ck, "ns": w["ns"], "pod": p["name"], "node": p["node"], "workload": w["name"], "kind": w["kind"], "state": pst, "text": ptx})
            if w["kind"] in ("ds", "static"):
                continue                                             # 노드마다 하나 — 노드와 함께 사라짐(서비스 영향 아님)
            if len(on) == len(w["pods"]):
                if all(p["node"] in ret for p in on):
                    item("VKS 워크로드", nm, "boot", f"Pod {len(on)}개가 모두 잃는 노드에 있음 — HA 가 노드 VM 을 다시 켜면 함께 돌아옴(수 분 중단)", ck)
                elif not can_reschedule and all(p["node"] in ret | unsure for p in on):
                    item("VKS 워크로드", nm, "risk", f"Pod {len(on)}개가 모두 잃는 노드에 있음 — 노드 VM 이 HA 로 다시 켜지면 돌아오지만 용량 부족으로 못 켜질 수 있음(그러면 복구 전까지 중단)", ck)
                elif can_reschedule:
                    item("VKS 워크로드", nm, "boot", f"Pod {len(on)}개가 모두 잃는 노드에 있음 — 다른 노드에서 다시 뜰 때까지 중단(보통 수 분)", ck)
                else:
                    item("VKS 워크로드", nm, "stop", f"Pod {len(on)}개 모두 잃음 — 다시 배치할 곳·컨트롤 플레인이 없어 복구 전까지 중단", ck)
            else:
                item("VKS 워크로드", nm, "ok" if can_reschedule or all(p["node"] in ret for p in on) else "risk",
                     f"Pod {len(w['pods'])}개 중 {len(on)}개 잃음 — 남은 {len(w['pods']) - len(on)}개로 계속"
                     + ("" if can_reschedule else " · 노드가 HA 로 돌아올 때까지 줄어든 상태" if all(p["node"] in ret for p in on) else " · 다시 채우지 못함(용량 줄어든 상태)"), ck)
        stop = [i for i in items if i["kind"] == "VKS 워크로드" and i["state"] == "stop" and i["scope"] == ck]
        if stop:
            F.append({"sev": "fail", "text": f"[{tag}] 워크로드 {len(stop)}개가 멈춥니다 — {', '.join(i['name'] for i in stop[:5])}"})
        one = [w for w in k["workloads"] if w["kind"] in ("deploy", "sts", "pod") and len(w["pods"]) == 1 and w["pods"][0]["node"] in lost_nodes]
        if one:
            actions.append(f"VKS '{ck}': Pod 가 하나뿐인 워크로드({', '.join(w['ns'] + '/' + w['name'] for w in one[:3])})는 replicas ≥ 2 와 노드 분산(topologySpreadConstraints)을")
        cph = {}
        for n in cps:
            cph.setdefault(n["host"], []).append(n["name"])
        if any(len(v) >= 2 for h, v in cph.items() if h):
            actions.append(f"VKS '{ck}' 컨트롤 플레인 노드 여러 대가 같은 ESXi 에 있습니다 — 호스트 분산(vSphere Zone·DRS 반선호도)을 확인하세요")

    # ---------------------------------------------------------------- Avi
    for a in P["avi"]:
        tag = f"Avi · {a['name']}"
        cl = [c for c in a["controllers"] if any(f["type"] == "avi_ctrl_down" and f["target"] == f"{a['name']}/{c['name']}" for f in fs)
              or vm_lost(c["vcenter"], c["vm"], c["host"])]
        for c in cl:
            marks[f"avictrl:/{a['name']}/{c['name']}"] = "failed"
            if c["vm"] and any(f["type"] == "avi_ctrl_down" and f["target"] == f"{a['name']}/{c['name']}" for f in fs):
                vm_hits.append((c["vcenter"], c["vm"], "down", "Avi 컨트롤러 노드 장애(가정)"))
        nct = len(a["controllers"])
        ctrl_down = bool(nct) and len(cl) * 2 > nct if nct > 1 else bool(cl)
        ctemp = bool(cl) and all(c["vm"] and back(c["vcenter"], c["vm"]) for c in cl)
        if ctrl_down:
            F.append({"sev": "fail", "text": f"[{tag}] 컨트롤러 {len(cl)}/{nct}대를 잃어 클러스터가 멈춥니다" + (" (HA 가 다시 켜는 수 분 동안)" if ctemp else "") + " — SE 는 마지막 구성으로 트래픽을 계속 처리하지만 구성 변경·SE 재배치·자동 확장·분석·AKO 연동이 멈춥니다"})
            item("Avi 컨트롤러", a["name"], "risk", "구성 변경·SE 장애 복구 불가(데이터 경로는 계속)")
        elif cl:
            F.append({"sev": "warn", "text": f"[{tag}] 컨트롤러 {len(cl)}/{nct}대를 잃음 — 과반이 남아 계속, 리더가 바뀌는 동안(수십 초) 관리 화면·API 가 끊길 수 있습니다"})
        if nct >= 2:
            ch = {}
            for c in a["controllers"]:
                if c["host"]:
                    ch.setdefault(c["host"], []).append(c["name"])
            if any(len(v) >= 2 for v in ch.values()):
                actions.append(f"Avi '{a['name']}' 컨트롤러 노드가 같은 ESXi 에 겹쳐 있습니다 — 반선호도 규칙으로 나누세요")
        se_lost = set()
        for s in a["se"]:
            d = any(f["type"] == "avi_se_down" and f["target"] == f"{a['name']}/{s['name']}" for f in fs)
            if d or vm_lost(s["vcenter"], s["vm"], "") or any(h == s.get("host") for _, h in lost_hosts):
                se_lost.add(s["name"])
                marks[f"avise:/{a['name']}/{s['name']}"] = "failed"
                if d and s["vm"]:
                    vm_hits.append((s["vcenter"], s["vm"], "down", "Avi SE 장애(가정)"))
        if not se_lost:
            continue
        vs = a["vs"] or [{"name": n, "ses": [s["name"]]} for s in a["se"] for n in s.get("vs") or []]
        seen = set()
        hit = 0
        for v in vs:
            if v["name"] in seen:
                continue
            seen.add(v["name"])
            ses = v.get("ses") or []
            on = [x for x in ses if x in se_lost]
            if not on:
                continue
            hit += 1
            left = [x for x in ses if x not in se_lost]
            if left:
                item("가상 서비스", v["name"], "ok", f"SE {len(ses)}개 중 {len(on)}개 잃음 — {', '.join(left)} 로 계속(액티브·스탠바이면 전환 수 초)")
            elif not ctrl_down:
                item("가상 서비스", v["name"], "boot", f"놓인 SE({', '.join(on)})를 모두 잃음 — 컨트롤러가 SE 그룹의 다른 SE·새 SE 에 다시 놓을 때까지 중단(수 분)")
            else:
                item("가상 서비스", v["name"], "stop", f"놓인 SE 를 모두 잃었고 컨트롤러도 멈춤 — 복구 전까지 VIP 중단")
        if hit:
            g = {}
            for s in a["se"]:
                g.setdefault(s.get("group", ""), []).append(s["name"])
            whole = [gn for gn, lst in g.items() if lst and all(x in se_lost for x in lst)]
            F.append({"sev": "fail" if whole or ctrl_down else "warn",
                      "text": f"[{tag}] SE {len(se_lost)}개를 잃음({', '.join(sorted(se_lost))}) — 가상 서비스 {hit}개 영향" + (f" · SE 그룹 {', '.join(whole)} 전체" if whole else "")})
            if whole:
                actions.append(f"Avi SE 그룹 {', '.join(whole)}: SE 를 서로 다른 호스트·클러스터에 두고, 고가용성 모드(Active/Active·N+M)와 버퍼 SE 를 확인하세요")
    # vSphere Pod 가 있는 호스트·VM 이 멈추면 그 Pod 도
    for s in P["supervisors"]:
        if (s["vcenter"], s["name"]) in sup_dead:
            continue
        for p in s["pods"]:
            if vm_lost(s["vcenter"], p["name"], p["host"]):
                ok = back(s["vcenter"], p["name"])
                pods.append({"cluster": f"Supervisor {s['name']}", "ns": "", "pod": p["name"], "node": p["host"], "workload": "vSphere Pod", "kind": "vsphere-pod",
                             "state": "back" if ok else "stuck", "text": "HA 가 다시 켬(수 분)" if ok else "호스트와 함께 멈춤 — Supervisor 가 다시 배치(대개 수 분)"})
                item("vSphere Pod", p["name"], "boot", "호스트와 함께 멈춤 — 다시 뜰 때까지 중단")
    return {"findings": F, "items": items, "marks": marks, "vms": vm_hits, "actions": actions, "pods": pods}
