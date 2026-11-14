"""VKS 구성도(2.9.0 · 2.10.0 상태·영향 전파) — Supervisor·워크로드 클러스터 Kubernetes 리소스를 관계 그래프로

참고: Awesome-Kubernetes-Architecture-Diagrams(CC0-1.0) 의 도구들(KubeDiagrams·k8sviz 등)이 쓰는 관례 —
네임스페이스로 묶고, Ingress → Service → 워크로드(Deployment·StatefulSet·DaemonSet·Job) → Pod → PVC → PV → StorageClass,
HPA·ConfigMap·Secret·ServiceAccount 를 워크로드에 붙여 그린다. 아이콘은 Kubernetes Icons Set 의 '파란 다각형 + 약어' 형태를 본떠 직접 그림(이미지 미포함).
VCF 확장: LoadBalancer VIP ↔ Avi 가상 서비스, 노드 ↔ vSphere VM ↔ ESXi 호스트, PV(CSI) ↔ vSphere 스토리지 정책, Supervisor ↔ vSphere 네임스페이스 ↔ VKS 클러스터·VM Service VM.
"""
from __future__ import annotations

import re
import time
import zlib
from typing import Any

SYSTEM_NS = re.compile(r"^(kube-|vmware-system-|tkg-|tanzu-|svc-|avi-system$|cert-manager$|secretgen-controller$|kapp-controller$|"
                       r"capi-|capv-|capw-|vmop-|vmware-|antrea-|calico-|tigera-|gatekeeper-|kube$)")
ABBR = {"Namespace": "ns", "Ingress": "ing", "Service": "svc", "Deployment": "deploy", "StatefulSet": "sts", "DaemonSet": "ds", "Job": "job",
        "CronJob": "cj", "Pod": "pod", "PersistentVolumeClaim": "pvc", "PersistentVolume": "pv", "StorageClass": "sc", "HorizontalPodAutoscaler": "hpa",
        "Node": "node", "VIP": "vip", "Supervisor": "sup", "VKSCluster": "k8s", "vSphereNamespace": "vns", "VirtualMachine": "vm", "ESXi": "esx"}


def _subset(a: dict, b: dict) -> bool:
    return bool(a) and all(b.get(k) == v for k, v in a.items())


def _vks(engine) -> list:
    return [c for c in getattr(engine, "connectors", []) if getattr(c, "type", "") == "vks"]


def _vm_index(engine) -> dict[str, dict]:
    out = {}
    for c in getattr(engine, "connectors", []):
        for n, v in ((getattr(c, "topology", None) or {}).get("vms") or {}).items():
            out[n] = {"host": v.get("host", ""), "cluster": v.get("cluster", ""), "power": v.get("power", ""), "vcenter": c.name}
    return out


def _avi_index(engine) -> dict[str, dict]:
    out = {}
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") != "avi":
            continue
        for v in (getattr(c, "vs", None) or {}).values():
            for ip in v.get("vips") or []:
                st = str(v.get("state") or "")
                out[str(ip)] = {"label": f"{v.get('name', '')}" + (f" ({st})" if st else ""), "state": st, "name": v.get("name", "")}
    return out


def overview(engine) -> dict[str, Any]:
    """Supervisor → vSphere 네임스페이스 → VKS 클러스터(CAPI·TKC)·VM Service VM, 각 워크로드 클러스터 커넥터 상태"""
    conns = _vks(engine)
    wl = {getattr(c, "cluster_label", c.name): c for c in conns if getattr(c, "role", "") != "supervisor"}
    used = set()
    sups = []
    for c in conns:
        if getattr(c, "role", "") != "supervisor":
            continue
        inv = getattr(c, "inv", {}) or {}
        topo = inv.get("topo") or {}
        nss: dict[str, dict] = {}
        for k in inv.get("clusters") or []:
            n = nss.setdefault(k["ns"], {"name": k["ns"], "clusters": [], "vms": []})
            w = wl.get(k["name"])
            if w:
                used.add(k["name"])
            winv = (getattr(w, "inv", {}) or {}) if w else {}
            pods = winv.get("pods") or []
            n["clusters"].append({**k, "connector": w.name if w else "", "nodes": len(winv.get("nodes") or []),
                                  "nodes_ready": sum(1 for x in winv.get("nodes") or [] if x.get("ready") == "True"),
                                  "pods": len(pods), "pods_bad": sum(1 for p in pods if p.get("phase") not in ("Running", "Succeeded"))})
        for t in topo.get("tkcs") or []:
            n = nss.setdefault(t["ns"], {"name": t["ns"], "clusters": [], "vms": []})
            if not any(x["name"] == t["name"] for x in n["clusters"]):
                n["clusters"].append({"ns": t["ns"], "name": t["name"], "phase": t.get("phase", ""), "version": t.get("version", ""), "connector": ""})
        for v in topo.get("vms") or []:
            nss.setdefault(v["ns"], {"name": v["ns"], "clusters": [], "vms": []})["vms"].append(v)
        for ns in topo.get("namespaces") or []:                       # 클러스터·VM 없는 vSphere 네임스페이스도
            if not SYSTEM_NS.match(ns["name"]) and ns["name"] not in ("default",):
                nss.setdefault(ns["name"], {"name": ns["name"], "clusters": [], "vms": []})
        sups.append({"connector": c.name, "label": getattr(c, "cluster_label", c.name), "target": getattr(c, "base_url", ""),
                     "nodes": len(inv.get("nodes") or []), "namespaces": sorted(nss.values(), key=lambda x: x["name"]),
                     "updated": inv.get("topo_updated") or inv.get("updated") or None, "errors": inv.get("topo_errors") or {}})
    orphans = [{"connector": w.name, "name": n, "nodes": len((getattr(w, "inv", {}) or {}).get("nodes") or [])} for n, w in wl.items() if n not in used]
    return {"supervisors": sups, "standalone": orphans, "generated": time.time()}




WL_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob")
POD_BAD = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "CreateContainerError", "RunContainerError",
           "InvalidImageName", "OOMKilled", "Error", "Evicted", "ContainerStatusUnknown"}
RANK = {"ok": 0, "idle": 0, "warn": 1, "down": 2}


def pod_state(p: dict) -> str:
    """파드 한 개 → ok / warn / down / done(Succeeded)"""
    ph = p.get("phase", "")
    if ph == "Succeeded":
        return "done"
    if ph == "Failed" or p.get("reason") in POD_BAD:
        return "down"
    rd = str(p.get("ready", "0/0")).split("/")
    if ph == "Running" and rd[0] == rd[-1]:
        return "ok"
    return "warn"                                     # Pending · 준비 안 됨 · Unknown


def _worst(*xs: str) -> str:
    return max(xs, key=lambda x: RANK.get(x, 0)) if xs else "ok"


def cluster_graph(engine, name: str, ns: str = "", system: bool = False, q: str = "", max_nodes: int = 600,
                  evc: dict | None = None, recent: dict | None = None) -> dict[str, Any]:
    """evc: 최근 경고 이벤트 수 {entity('Pod/ns/x'·'Deployment/ns/x'·'Node/x'): n}, recent: 최근 변경 {node id: {n, restart, last}}"""
    c = next((x for x in _vks(engine) if x.name == name), None)
    if not c:
        raise KeyError(name)
    inv = getattr(c, "inv", {}) or {}
    topo = inv.get("topo") or {}
    pods = inv.get("pods") or []
    evc = evc or {}
    recent = recent or {}
    ql = (q or "").lower()
    keep_ns = lambda n: (not ns or n == ns) and (system or ns == n or not SYSTEM_NS.match(n or ""))   # noqa: E731
    rs_owner = {(r["ns"], r["name"]): r.get("owner", "") for r in topo.get("replicasets") or []}
    job_owner = {(j["ns"], j["name"]): j.get("owner", "") for j in topo.get("jobs") or []}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    pod_wid: dict[str, str] = {}                       # 'ns/pod' → 워크로드 노드 id(이벤트·변경 이력 귀속)

    def add(kind, nsn, nm, **kw):
        nid = f"{kind}:{nsn}/{nm}"
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "abbr": ABBR.get(kind, kind[:3].lower()), "ns": nsn, "name": nm, **kw}
        else:
            nodes[nid].update({k: v for k, v in kw.items() if v not in (None, "", [], {})})
        return nid

    def link(a, b, kind=""):
        if a in nodes and b in nodes and not any(e["from"] == a and e["to"] == b for e in edges):
            edges.append({"from": a, "to": b, "kind": kind})

    # 워크로드
    for key, kind in (("deployments", "Deployment"), ("statefulsets", "StatefulSet"), ("daemonsets", "DaemonSet")):
        for w in topo.get(key) or []:
            if keep_ns(w["ns"]):
                add(kind, w["ns"], w["name"], status="ok", detail=f"{w.get('ready', 0)}/{w.get('want', 0)} 준비", images=w.get("images") or [],
                    sa=w.get("sa", ""), cms=w.get("cms") or [], secrets=w.get("secrets") or [], selector=w.get("selector") or {},
                    want=w.get("want", 0), ready=w.get("ready", 0), updated=w.get("updated", w.get("want", 0)), rev=w.get("rev", ""),
                    paused=w.get("paused", False), gen_lag=w.get("gen_lag", False), cond=w.get("cond", ""))
    cj = {(x["ns"], x["name"]): x for x in topo.get("cronjobs") or []}
    last_job: dict[tuple, dict] = {}
    for j in topo.get("jobs") or []:
        if j.get("owner"):
            k = (j["ns"], j["owner"])
            if j["name"] > last_job.get(k, {}).get("name", ""):        # CronJob Job 이름 접미사 = 예약 시각(분) → 사전순 = 시간순
                last_job[k] = j
    # 파드 → 워크로드(묶음)
    groups: dict[str, dict] = {}
    for p in pods:
        if not keep_ns(p["ns"]):
            continue
        ok, on = p.get("owner", ""), p.get("owner_name", "")
        if ok == "ReplicaSet":
            dep = rs_owner.get((p["ns"], on))
            wid = f"Deployment:{p['ns']}/{dep}" if dep else f"ReplicaSet:{p['ns']}/{on}"
        elif ok in ("StatefulSet", "DaemonSet"):
            wid = f"{ok}:{p['ns']}/{on}"
        elif ok == "Job":
            cron = job_owner.get((p["ns"], on))
            wid = f"CronJob:{p['ns']}/{cron}" if cron else f"Job:{p['ns']}/{on}"
            kind_, nm_ = wid.split(":", 1)[0], wid.split("/", 1)[1]
            c0 = cj.get((p["ns"], nm_)) if kind_ == "CronJob" else None
            add(kind_, p["ns"], nm_, status="ok", detail=(c0 or {}).get("schedule", ""), suspend=(c0 or {}).get("suspend", False))
        else:
            wid = f"Pod:{p['ns']}/{p['name']}"                              # 독립 파드
            add("Pod", p["ns"], p["name"], status="ok", detail=p.get("phase", ""))
        if wid.startswith("ReplicaSet:"):
            add("Deployment", p["ns"], on, status="ok", detail="ReplicaSet")
            wid = f"Deployment:{p['ns']}/{on}"
        pod_wid[f"{p['ns']}/{p['name']}"] = wid
        g = groups.setdefault(wid, {"total": 0, "ready": 0, "bad": 0, "restarts": 0, "nodes": set(), "pvcs": set(), "cms": set(), "secrets": set(),
                                    "labels": [], "sa": "", "list": []})
        ps = pod_state(p)
        g["total"] += 1
        g["ready"] += ps in ("ok", "done")
        g["bad"] += ps in ("warn", "down")
        g["restarts"] += int(p.get("restarts") or 0)
        if p.get("node"):
            g["nodes"].add(p["node"])
        g["pvcs"].update(p.get("pvcs") or [])
        g["cms"].update(p.get("cms") or [])
        g["secrets"].update(p.get("secrets") or [])
        g["labels"].append(p.get("labels") or {})
        g["sa"] = g["sa"] or p.get("sa", "")
        g["list"].append({"name": p["name"], "st": ps, "phase": p.get("phase", ""), "reason": p.get("reason", ""), "ready": p.get("ready", ""),
                          "restarts": int(p.get("restarts") or 0), "node": p.get("node", ""), "containers": p.get("containers") or [],
                          "msg": p.get("msg", ""), "last_term": p.get("last_term"), "age": p.get("age")})
    for wid, g in groups.items():
        if wid not in nodes:
            continue
        n = nodes[wid]
        g["list"].sort(key=lambda x: (-RANK.get(x["st"], 0), x["name"]))
        n.update(pods=g["total"], pods_ready=g["ready"], pods_bad=g["bad"], restarts=g["restarts"], on_nodes=sorted(g["nodes"])[:20],
                 cms=sorted(set(n.get("cms") or []) | g["cms"]), secrets=sorted(set(n.get("secrets") or []) | g["secrets"]), sa=n.get("sa") or g["sa"],
                 podlist=g["list"][:60])
        n["_labels"] = g["labels"]
        for pv in g["pvcs"]:
            add("PersistentVolumeClaim", n["ns"], pv, status="ok")
            link(wid, f"PersistentVolumeClaim:{n['ns']}/{pv}", "mount")
    for (nsn, cname), j in last_job.items():
        nid = f"CronJob:{nsn}/{cname}"
        if nid in nodes:
            nodes[nid]["last_job"] = {"name": j["name"], "succeeded": j.get("succeeded", 0), "failed": j.get("failed", 0)}
    # 서비스 → 워크로드
    avi = _avi_index(engine)
    for s in topo.get("services") or []:
        if not keep_ns(s["ns"]) or (s["name"] == "kubernetes" and s["ns"] == "default"):
            continue
        sid = add("Service", s["ns"], s["name"], status="ok", detail=f"{s.get('type')} {s.get('cluster_ip', '')} {' '.join(s.get('ports') or [])}".strip(),
                  svc_type=s.get("type"), lb=s.get("lb") or [], svc_selector=s.get("selector") or {}, ports=s.get("ports") or [])
        for nid, n in list(nodes.items()):
            if n["ns"] != s["ns"] or n["kind"] not in WL_KINDS:
                continue
            if any(_subset(s.get("selector") or {}, lb) for lb in n.get("_labels") or []) or _subset(s.get("selector") or {}, n.get("selector") or {}):
                link(sid, nid, "select")
        for ip in s.get("lb") or []:
            a = avi.get(ip) or {}
            vid = add("VIP", s["ns"], ip, status="ok", detail=("Avi VS " + a["label"]) if a else "LoadBalancer VIP", avi=a.get("label", ""), avi_state=a.get("state", ""))
            link(vid, sid, "lb")
    for i in topo.get("ingresses") or []:
        if not keep_ns(i["ns"]):
            continue
        iid = add("Ingress", i["ns"], i["name"], status="ok", detail=" ".join(i.get("hosts") or []) or (i.get("class") or ""), lb=i.get("lb") or [],
                  hosts=i.get("hosts") or [], ing_class=i.get("class", ""))
        miss = []
        for sv in i.get("services") or []:
            if f"Service:{i['ns']}/{sv}" in nodes:
                link(iid, f"Service:{i['ns']}/{sv}", "route")
            else:
                miss.append(sv)
        nodes[iid]["missing_backends"] = miss
        for ip in i.get("lb") or []:
            a = avi.get(ip) or {}
            vid = add("VIP", i["ns"], ip, status="ok", detail=("Avi VS " + a["label"]) if a else "Ingress VIP", avi=a.get("label", ""), avi_state=a.get("state", ""))
            link(vid, iid, "lb")
    for h in topo.get("hpas") or []:
        if not keep_ns(h["ns"]):
            continue
        tgt = f"{h.get('target_kind')}:{h['ns']}/{h.get('target')}"
        if tgt in nodes:
            nodes[tgt]["hpa"] = f"{h.get('min')}–{h.get('max')} (현재 {h.get('current')})"
            nodes[tgt]["hpa_max"] = bool(h.get("max")) and int(h.get("current") or 0) >= int(h.get("max") or 0)
    # PVC → PV → StorageClass
    pvcs = {(p["ns"], p["name"]): p for p in topo.get("pvcs") or []}
    for p in topo.get("pvcs") or []:
        if keep_ns(p["ns"]) and (ns or system or f"PersistentVolumeClaim:{p['ns']}/{p['name']}" in nodes or not SYSTEM_NS.match(p["ns"])):
            add("PersistentVolumeClaim", p["ns"], p["name"], status="ok", detail=f"{p.get('size', '')} {p.get('phase', '')}".strip())
    pvs = {v["name"]: v for v in topo.get("pvs") or []}
    scs = {s["name"]: s for s in topo.get("storageclasses") or []}
    for nid, n in list(nodes.items()):
        if n["kind"] != "PersistentVolumeClaim":
            continue
        p = pvcs.get((n["ns"], n["name"])) or {}
        if p:
            n.update(phase=p.get("phase", ""), detail=f"{p.get('size', '')} {p.get('phase', '')}".strip(), sc=p.get("sc", ""), size=p.get("size", ""))
        if p.get("volume"):
            v = pvs.get(p["volume"], {})
            pid = add("PersistentVolume", "", p["volume"], status="ok", phase=v.get("phase", ""), detail=f"{v.get('size', '')} {v.get('driver', '')}".strip(),
                      handle=v.get("handle", ""))
            link(nid, pid, "bind")
            sc = p.get("sc") or v.get("sc")
            if sc:
                s = scs.get(sc, {})
                sid = add("StorageClass", "", sc, status="ok", detail=(f"정책 {s['policy']}" if s.get("policy") else s.get("provisioner", "")) + (" · 기본" if s.get("default") else ""),
                          policy=s.get("policy", ""))
                link(pid, sid, "class")
    # 노드 ↔ vSphere VM ↔ ESXi
    vmi = _vm_index(engine)
    knodes = []
    for kn in inv.get("nodes") or []:
        vm = vmi.get(kn["name"]) or {}
        iss = []
        if kn.get("ready") != "True":
            iss.append({"sev": "error", "text": f"NotReady (Ready={kn.get('ready')})"})
        for pr in kn.get("pressure") or []:
            iss.append({"sev": "warn", "text": pr})
        if kn.get("unschedulable"):
            iss.append({"sev": "warn", "text": "스케줄 불가(cordon)"})
        if vm and vm.get("power") and not str(vm["power"]).lower().endswith(("on", "poweredon")):
            iss.append({"sev": "error", "text": f"vSphere VM 전원 {vm['power']}"})
        npods = [p for p in pods if p.get("node") == kn["name"]]
        bad = sum(1 for p in npods if pod_state(p) in ("warn", "down"))
        st = "down" if any(i["sev"] == "error" for i in iss) else ("warn" if iss else "ok")
        knodes.append({**kn, "vm": bool(vm), "esxi": vm.get("host", ""), "vsphere_cluster": vm.get("cluster", ""), "vm_power": vm.get("power", ""),
                       "vcenter": vm.get("vcenter", ""), "pods": len(npods), "pods_bad": bad, "status": st, "issues": iss,
                       "events": int(evc.get(f"Node/{kn['name']}", 0)), "recent": recent.get(f"Node:/{kn['name']}")})
    _health(nodes, edges, evc, recent, pod_wid)
    # 검색 — 이름이 맞는 노드와 이웃만
    if ql:
        hit = {nid for nid, n in nodes.items() if ql in n["name"].lower()}
        nb = set(hit)
        for e in edges:
            if e["from"] in hit or e["to"] in hit:
                nb |= {e["from"], e["to"]}
        nodes = {k: v for k, v in nodes.items() if k in nb}
        edges = [e for e in edges if e["from"] in nodes and e["to"] in nodes]
    for n in nodes.values():
        n.pop("_labels", None)
    truncated = len(nodes) > max_nodes
    if truncated:                                     # 문제 노드 우선 보존
        order = sorted(nodes, key=lambda k: -RANK.get(nodes[k]["status"], 0))
        keep = set(order[:max_nodes])
        nodes = {k: v for k, v in nodes.items() if k in keep}
        edges = [e for e in edges if e["from"] in keep and e["to"] in keep]
    all_ns = sorted({x["name"] for x in topo.get("namespaces") or []} | {p["ns"] for p in pods})
    vals = list(nodes.values())
    summary = {"ok": sum(1 for n in vals if n["status"] in ("ok", "idle")), "warn": sum(1 for n in vals if n["own"] == "warn"),
               "down": sum(1 for n in vals if n["own"] == "down"), "impacted": sum(1 for n in vals if n.get("impact")),
               "events": sum(n.get("events", 0) for n in vals), "changed": sum(1 for n in vals if n.get("recent")),
               "nodes_bad": sum(1 for k in knodes if k["status"] != "ok")}
    problems = sorted(({"id": n["id"], "kind": n["kind"], "ns": n["ns"], "name": n["name"], "status": n["own"],
                        "text": (n["issues"][0]["text"] if n["issues"] else "")} for n in vals if n["own"] in ("warn", "down")),
                      key=lambda x: (-RANK[x["status"]], x["kind"], x["name"]))
    problems += [{"id": f"Node:/{k['name']}", "kind": "Node", "ns": "", "name": k["name"], "status": k["status"], "text": k["issues"][0]["text"]}
                 for k in knodes if k["status"] != "ok"]
    return {"connector": c.name, "cluster": getattr(c, "cluster_label", c.name), "role": getattr(c, "role", ""),
            "nodes": vals, "edges": edges, "k8s_nodes": knodes, "namespaces": all_ns,
            "system_ns": [n for n in all_ns if SYSTEM_NS.match(n)], "truncated": truncated,
            "errors": inv.get("topo_errors") or {}, "updated": inv.get("topo_updated") or None, "pods_updated": inv.get("updated") or None,
            "ns": ns, "system": system, "counts": {k: sum(1 for n in vals if n["kind"] == k) for k in ABBR},
            "summary": summary, "problems": problems[:60], "pod_wid": pod_wid}


def _health(nodes: dict, edges: list, evc: dict, recent: dict, pod_wid: dict) -> None:
    """개체별 자체 상태(own)·문제(issues) → 하류 장애의 상류 전파(impact). 순서: PV → PVC → 워크로드 → Service → Ingress → VIP"""
    for n in nodes.values():
        iss: list[dict] = []
        k = n["kind"]
        if k in ("Deployment", "StatefulSet", "DaemonSet"):
            want, ready = int(n.get("want") or 0), int(n.get("ready") or 0)
            if want == 0 and not n.get("pods"):
                n["idle"] = True
                iss.append({"sev": "info", "text": "레플리카 0 (중지됨)"})
            elif ready == 0:
                iss.append({"sev": "error", "text": f"준비된 파드 없음 (0/{want})"})
            elif ready < want:
                iss.append({"sev": "warn", "text": f"준비 {ready}/{want}"})
            if want and int(n.get("updated") or 0) < want and not n.get("cond"):
                iss.append({"sev": "warn", "text": f"롤아웃 진행 중 — 새 버전 {n.get('updated', 0)}/{want}"})
            if n.get("cond"):
                iss.append({"sev": "error", "text": "롤아웃 실패 — " + n["cond"]})
            if n.get("paused"):
                iss.append({"sev": "info", "text": "롤아웃 일시 중지(paused)"})
        if k in WL_KINDS:
            by: dict[str, list] = {}
            for p in n.get("podlist") or []:
                if p["st"] in ("warn", "down"):
                    by.setdefault(p["reason"] or p["phase"] or "NotReady", []).append(p["name"])
            for r, names in sorted(by.items(), key=lambda x: -len(x[1])):
                sev = "error" if (r in POD_BAD or r == "Failed") and not n.get("pods_ready") else "warn"     # 일부라도 준비돼 있으면 저하(주의)
                iss.append({"sev": sev, "text": f"{r} {len(names)}개 — {', '.join(names[:3])}{' …' if len(names) > 3 else ''}"})
            if n.get("pods") and not n.get("pods_ready") and k not in ("Job", "CronJob") and not any(i["sev"] == "error" for i in iss):
                iss.append({"sev": "error", "text": "실행 중인 파드 없음"})
            if n.get("hpa_max"):
                iss.append({"sev": "warn", "text": f"HPA 최대 레플리카 도달 ({n.get('hpa')})"})
            lj = n.get("last_job") or {}
            if lj.get("failed"):
                iss.append({"sev": "warn", "text": f"마지막 Job {lj.get('name')} 실패 {lj.get('failed')}회"})
            if n.get("suspend"):
                iss.append({"sev": "info", "text": "CronJob 일시 중지(suspend)"})
            rc = (recent.get(n["id"]) or {}).get("restart", 0)
            if rc:
                iss.append({"sev": "warn", "text": f"최근 1시간 컨테이너 재시작 +{rc}"})
        elif k == "Service":
            if n.get("svc_type") == "LoadBalancer" and not n.get("lb"):
                iss.append({"sev": "warn", "text": "외부 IP 할당 대기(LoadBalancer Pending)"})
            if n.get("svc_selector") and not any(e["from"] == n["id"] and e["kind"] == "select" for e in edges):
                iss.append({"sev": "warn", "text": "셀렉터와 일치하는 파드 없음 — 엔드포인트 0"})
        elif k == "Ingress":
            if n.get("missing_backends"):
                iss.append({"sev": "warn", "text": "백엔드 Service 없음: " + ", ".join(n["missing_backends"][:4])})
            if not n.get("lb"):
                iss.append({"sev": "info", "text": "주소(VIP) 미할당"})
        elif k == "VIP":
            s = str(n.get("avi_state") or "").upper()
            if s and ("DOWN" in s or "FAIL" in s):
                iss.append({"sev": "error", "text": f"Avi 가상 서비스 {s}"})
            elif s and "UP" not in s:
                iss.append({"sev": "warn", "text": f"Avi 가상 서비스 {s}"})
        elif k == "PersistentVolumeClaim":
            ph = n.get("phase", "")
            if ph == "Lost":
                iss.append({"sev": "error", "text": "PVC Lost — 볼륨 유실"})
            elif ph and ph != "Bound":
                iss.append({"sev": "warn", "text": f"PVC {ph} — 바인딩 대기"})
        elif k == "PersistentVolume":
            ph = n.get("phase", "")
            if ph == "Failed":
                iss.append({"sev": "error", "text": "PV Failed"})
            elif ph == "Released":
                iss.append({"sev": "warn", "text": "PV Released(회수 대기)"})
        # 경고 이벤트(최근 1시간) — 개체 자신 + 소속 파드
        ev = 0
        if k in WL_KINDS or k in ("Service", "Ingress", "PersistentVolumeClaim", "HorizontalPodAutoscaler"):
            ev += int(evc.get(f"{k}/{n['ns']}/{n['name']}", 0))
        elif k == "PersistentVolume":
            ev += int(evc.get(f"PersistentVolume/{n['name']}", 0))
        n["events"] = ev
        n["recent"] = recent.get(n["id"])
        n["issues"] = iss
        n["own"] = "down" if any(i["sev"] == "error" for i in iss) else ("warn" if any(i["sev"] == "warn" for i in iss) else ("idle" if n.get("idle") else "ok"))
    for ent, cnt in evc.items():                      # 파드·ReplicaSet 이벤트 → 워크로드
        parts = ent.split("/", 2)
        if len(parts) == 3 and parts[0] in ("Pod", "ReplicaSet"):
            wid = pod_wid.get(f"{parts[1]}/{parts[2]}")
            if not wid and parts[0] == "ReplicaSet":
                wid = next((x for x in nodes if x.startswith(f"Deployment:{parts[1]}/") and parts[2].startswith(x.split("/", 1)[1] + "-")), None)
            if wid in nodes:
                nodes[wid]["events"] = nodes[wid].get("events", 0) + int(cnt)
    # 전파: 하류 상태가 상류에 영향
    down_of: dict[str, list] = {}
    for e in edges:
        down_of.setdefault(e["from"], []).append(e["to"])
    order = ["PersistentVolume", "PersistentVolumeClaim", "Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob", "Service", "Ingress", "VIP", "StorageClass"]
    for n in nodes.values():
        n["status"] = n["own"]
    for k in order:
        for n in nodes.values():
            if n["kind"] != k:
                continue
            kids = [nodes[x] for x in down_of.get(n["id"], []) if x in nodes and nodes[x]["kind"] != "StorageClass"]
            if k in ("PersistentVolume",):
                kids = []
            if k in WL_KINDS:
                kids = [x for x in kids if x["kind"] == "PersistentVolumeClaim"]
            if not kids:
                continue
            bad = [x for x in kids if RANK.get(x["status"], 0) > 0]
            if not bad:
                continue
            if k in ("Service", "Ingress", "VIP") and all(x["status"] == "down" for x in kids):
                imp = "down"
                txt = "모든 백엔드 장애 → 요청 실패 가능"
            elif k in WL_KINDS:
                imp = "down" if any(x["status"] == "down" for x in bad) else "warn"
                txt = "볼륨 문제: " + ", ".join(x["name"] for x in bad[:3])
            else:
                imp = "warn"
                txt = f"백엔드 {len(bad)}/{len(kids)} 저하: " + ", ".join(x["name"] for x in bad[:3])
            if RANK[imp] > RANK.get(n["own"], 0):
                n["impact"] = True
            n["impact_from"] = [x["id"] for x in bad[:6]]
            n["issues"].append({"sev": "impact", "text": txt})
            n["status"] = _worst(n["status"], imp)
    for e in edges:
        t = nodes.get(e["to"])
        if t:
            e["st"] = t["status"] if t["status"] in ("warn", "down") else "ok"


def mermaid(g: dict) -> str:
    """구성도 → Mermaid flowchart(네임스페이스 subgraph) — 문서·위키 붙여넣기용"""
    def mid(s):
        return "n" + re.sub(r"[^A-Za-z0-9]", "_", s)[:60] + "_" + format(zlib.crc32(s.encode()), "x")
    ids = {n["id"]: mid(n["id"]) for n in g["nodes"]}
    lines = ["flowchart LR"]
    by: dict[str, list] = {}
    for n in g["nodes"]:
        by.setdefault(n["ns"] or "(cluster)", []).append(n)
    for nsn, xs in sorted(by.items()):
        lines.append(f'  subgraph {mid("ns:" + nsn)}["{nsn}"]')
        for n in xs:
            lab = f'{n["abbr"]}: {n["name"]}'.replace('"', "'")
            lines.append(f'    {ids[n["id"]]}["{lab}"]')
        lines.append("  end")
    for e in g["edges"]:
        if e["from"] in ids and e["to"] in ids:
            lines.append(f'  {ids[e["from"]]} -->{"|" + e["kind"] + "|" if e["kind"] else ""} {ids[e["to"]]}')
    lines += ["  classDef warn fill:#fff6db,stroke:#e0a800,stroke-width:2px", "  classDef down fill:#fde8e4,stroke:#c21d00,stroke-width:2px",
              "  classDef impact stroke:#c21d00,stroke-dasharray:5 3"]
    for cls in ("warn", "down"):
        xs = [ids[n["id"]] for n in g["nodes"] if n.get("own") == cls]
        if xs:
            lines.append(f"  class {','.join(xs)} {cls}")
    xs = [ids[n["id"]] for n in g["nodes"] if n.get("impact")]
    if xs:
        lines.append(f"  class {','.join(xs)} impact")
    return "\n".join(lines) + "\n"
