"""2.10.0 VKS 구성도 상태·관측 — 자체 상태·영향 전파 · 변경 이력(구성·파드·노드 비교) · 개체 상세(이벤트·로그·변경·연관) · 로그 가림"""
import asyncio
import copy
import time
from types import SimpleNamespace as NS

from app import vksmap, vksobs
from app.connectors.kubernetes import _compact


def _pod(name, phase="Running", ready="1/1", reason="", restarts=0, node="np-1", owner_name="api-6f", labels=None, pvcs=None, ns="pay"):
    return {"ns": ns, "name": name, "node": node, "phase": phase, "ready": ready, "reason": reason, "restarts": restarts, "owner": "ReplicaSet",
            "owner_name": owner_name, "labels": labels or {"app": "api"}, "pvcs": pvcs or [], "cms": [], "secrets": [], "sa": "", "containers": ["api"]}


def _topo(api_ready=2, worker_ready=0, pvc_phase="Bound"):
    return {"namespaces": [{"name": "pay"}],
            "deployments": [{"ns": "pay", "name": "api", "kind": "Deployment", "want": 2, "ready": api_ready, "updated": 2, "rev": "3", "images": ["api:1.4"],
                             "selector": {"app": "api"}, "cms": [], "secrets": []},
                            {"ns": "pay", "name": "worker", "kind": "Deployment", "want": 1, "ready": worker_ready, "updated": 1, "rev": "1", "images": ["w:1"],
                             "selector": {"app": "worker"}, "cms": [], "secrets": []}],
            "replicasets": [{"ns": "pay", "name": "api-6f", "owner": "api"}, {"ns": "pay", "name": "worker-1a", "owner": "worker"}],
            "services": [{"ns": "pay", "name": "api", "type": "LoadBalancer", "selector": {"app": "api"}, "lb": ["10.0.0.5"], "ports": ["443/TCP"]},
                         {"ns": "pay", "name": "worker", "type": "ClusterIP", "selector": {"app": "worker"}, "lb": [], "ports": ["9100/TCP"]},
                         {"ns": "pay", "name": "ghost", "type": "ClusterIP", "selector": {"app": "nothing"}, "lb": [], "ports": ["80/TCP"]}],
            "ingresses": [{"ns": "pay", "name": "pay", "services": ["worker", "missing"], "hosts": ["pay.corp"], "lb": ["10.0.0.6"]}],
            "pvcs": [{"ns": "pay", "name": "data", "volume": "pv-1", "sc": "vsan", "phase": pvc_phase, "size": "10Gi"}],
            "pvs": [{"name": "pv-1", "sc": "vsan", "phase": "Bound"}], "storageclasses": [{"name": "vsan", "policy": "vSAN Default"}],
            "hpas": [{"ns": "pay", "name": "api", "target_kind": "Deployment", "target": "api", "min": 1, "max": 2, "current": 2}]}


def _pods(bad=True):
    ps = [_pod("api-6f-a", pvcs=["data"]), _pod("api-6f-b", pvcs=["data"])]
    ps.append(_pod("worker-1a-x", ready="0/1" if bad else "1/1", reason="CrashLoopBackOff" if bad else "", restarts=7, owner_name="worker-1a", labels={"app": "worker"}))
    return ps


class FakeConn:
    type = "vks"

    def __init__(self, topo, pods):
        self.name, self.role, self.cluster_label = "tkc1", "workload", "tkc1"
        self.inv = {"topo": topo, "pods": pods, "nodes": [{"name": "np-1", "ready": "True", "roles": ["worker"]}, {"name": "np-2", "ready": "False", "roles": ["worker"]}],
                    "topo_updated": 1.0, "updated": 1.0}
        self.asked = []

    async def object_events(self, ns, names, kinds=None, limit=200):
        self.asked.append((ns, set(names)))
        return [{"ts": time.time(), "type": "Normal", "reason": "ScalingReplicaSet", "kind": "Deployment", "name": "worker", "message": "Scaled up", "count": 1},
                {"ts": time.time(), "type": "Warning", "reason": "BackOff", "kind": "Pod", "name": "worker-1a-x", "message": "Back-off restarting", "count": 9}]


def _eng(tmp_path, conn):
    from app.config import DEFAULTS, _merge
    from app.engine import Engine
    e = Engine(_merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}}))
    vc = NS(type="vcenter", name="vc", topology={"vms": {"np-1": {"host": "esx01.lab", "cluster": "CL1", "power": "poweredOn"},
                                                         "np-2": {"host": "esx02.lab", "cluster": "CL1", "power": "poweredOff"}}})
    avi = NS(type="avi", name="avi", vs={"u": {"name": "pay-ing", "state": "OPER_DOWN", "vips": ["10.0.0.6"]}})
    e.connectors = [conn, vc, avi]
    return e


def test_health_and_impact():
    conn = FakeConn(_topo(), _pods())
    vc = NS(type="vcenter", name="vc", topology={"vms": {"np-2": {"host": "esx02.lab", "power": "poweredOff"}}})
    eng = NS(connectors=[conn, vc, NS(type="avi", name="avi", vs={"u": {"name": "pay-ing", "state": "OPER_DOWN", "vips": ["10.0.0.6"]}})])
    g = vksmap.cluster_graph(eng, "tkc1", evc={"Pod/pay/worker-1a-x": 3, "Deployment/pay/api": 1, "Node/np-2": 2},
                             recent={"Deployment:pay/worker": {"n": 2, "restart": 4}})
    n = {x["id"]: x for x in g["nodes"]}
    w = n["Deployment:pay/worker"]
    assert w["own"] == "down" and any("CrashLoopBackOff 1개" in i["text"] for i in w["issues"]) and any("재시작 +4" in i["text"] for i in w["issues"])
    assert w["events"] == 3 and w["podlist"][0]["st"] == "down"
    api = n["Deployment:pay/api"]
    assert api["own"] == "warn" and any("HPA 최대" in i["text"] for i in api["issues"]) and api["events"] == 1
    sw = n["Service:pay/worker"]                                         # 하류 전부 장애 → 서비스 장애(영향)
    assert sw["own"] == "ok" and sw["status"] == "down" and sw["impact"] and sw["impact_from"] == ["Deployment:pay/worker"]
    ing = n["Ingress:pay/pay"]
    assert ing["own"] == "warn" and any("missing" in i["text"] for i in ing["issues"]) and ing["status"] == "down"
    assert n["VIP:pay/10.0.0.6"]["own"] == "down"                         # Avi OPER_DOWN
    assert any("엔드포인트 0" in i["text"] for i in n["Service:pay/ghost"]["issues"])
    assert n["Service:pay/api"]["status"] == "warn" and n["Service:pay/api"]["own"] == "ok"
    assert {e["st"] for e in g["edges"] if e["to"] == "Deployment:pay/worker"} == {"down"}
    kn = {k["name"]: k for k in g["k8s_nodes"]}
    assert kn["np-2"]["status"] == "down" and kn["np-2"]["events"] == 2 and any("전원" in i["text"] for i in kn["np-2"]["issues"])
    s = g["summary"]
    assert s["down"] >= 2 and s["impacted"] >= 1 and s["events"] >= 4 and s["nodes_bad"] == 1
    assert g["problems"][0]["status"] == "down" and any(p["kind"] == "Node" for p in g["problems"])
    mmd = vksmap.mermaid(g)
    assert "classDef down" in mmd and " down" in mmd.splitlines()[-2] + mmd.splitlines()[-1] + mmd
    # PVC Lost → 마운트한 워크로드 영향
    g2 = vksmap.cluster_graph(NS(connectors=[FakeConn(_topo(pvc_phase="Lost"), _pods(False))]), "tkc1")
    n2 = {x["id"]: x for x in g2["nodes"]}
    assert n2["PersistentVolumeClaim:pay/data"]["own"] == "down" and n2["Deployment:pay/api"]["status"] == "down"


def test_compact_rollout_fields():
    d = _compact("deployments", {"metadata": {"namespace": "a", "name": "b", "generation": 5, "annotations": {"deployment.kubernetes.io/revision": "7"}},
                                 "spec": {"replicas": 3, "template": {"spec": {"containers": [{"image": "x:2"}]}}},
                                 "status": {"readyReplicas": 3, "updatedReplicas": 1, "observedGeneration": 4,
                                            "conditions": [{"type": "Progressing", "reason": "ProgressDeadlineExceeded", "message": "timed out"}]}})
    assert d["updated"] == 1 and d["rev"] == "7" and d["gen_lag"] and "ProgressDeadlineExceeded" in d["cond"]
    g = vksmap.cluster_graph(NS(connectors=[FakeConn({"deployments": [{**d, "selector": {}}]}, [])]), "tkc1", ns="a")
    x = g["nodes"][0]
    assert x["own"] == "down" and any("롤아웃 실패" in i["text"] for i in x["issues"])


def test_diffs():
    a, b = _topo(), copy.deepcopy(_topo())
    b["deployments"][0].update(images=["api:1.5"], rev="4", want=4)
    b["services"][0]["lb"] = []
    b["pvcs"][0]["size"] = "20Gi"
    b["hpas"][0]["current"] = 1
    b["deployments"].append({"ns": "pay", "name": "new", "want": 1, "images": ["n:1"]})
    b["services"] = [s for s in b["services"] if s["name"] != "ghost"]
    rows = vksobs.diff_topo(a, b)
    txt = {(r["kind"], r["name"], r["action"]): r for r in rows}
    assert "api:1.4 → api:1.5" in txt[("Deployment", "api", "rollout")]["detail"] and "리비전 3 → 4" in txt[("Deployment", "api", "rollout")]["detail"]
    assert txt[("Deployment", "api", "scale")]["detail"] == "레플리카 2 → 4"
    assert txt[("Service", "api", "network")]["sev"] == "warn" and ("Service", "ghost", "deleted") in txt and ("Deployment", "new", "created") in txt
    assert "20Gi" in txt[("PersistentVolumeClaim", "data", "storage")]["detail"] and "HPA api 레플리카 2 → 1" in txt[("Deployment", "api", "hpa")]["detail"]
    assert vksobs.diff_topo({"deployments": []}, {}) == []                      # 한쪽 누락(권한) → 비교 안 함
    p0 = _pods(False)
    p1 = _pods(True)
    p1[2]["restarts"] = 9
    p1[2]["last_term"] = {"reason": "OOMKilled", "exit": 137}
    p1 = [p for p in p1 if p["name"] != "api-6f-b"] + [_pod("api-6f-c")]
    p1[0]["node"] = "np-2"
    pr = vksobs.diff_pods(p0, p1, _topo())
    acts = {(r["name"], r["action"]): r for r in pr}
    assert acts[("worker", "restart")]["sev"] == "error" and "+2" in acts[("worker", "restart")]["detail"] and "OOMKilled" in acts[("worker", "restart")]["detail"]
    assert acts[("worker", "pod_bad")]["sev"] == "error" and "CrashLoopBackOff" in acts[("worker", "pod_bad")]["detail"]
    rep = [r for r in pr if r["name"] == "api" and r["action"] == "pod_replace"]
    assert any("생성 1 · 삭제 1" in r["detail"] for r in rep) and any("np-1 → np-2" in r["detail"] for r in rep)
    nd = vksobs.diff_nodes([{"name": "np-1", "ready": "True"}, {"name": "old", "ready": "True"}], [{"name": "np-1", "ready": "False"}, {"name": "np-3", "ready": "True", "roles": ["worker"]}])
    assert {r["detail"].split(" ")[0] for r in nd} == {"Ready", "노드"} and len(nd) == 3


def test_mask_log():
    m = vksobs.mask_log
    assert "<가림>" in m("connecting password=Sup3rS3cret! user=x") and "Sup3rS3cret" not in m("password=Sup3rS3cret!")
    assert "abc.def" not in m("Authorization: Bearer abcdefghijkl.def") and "<가림>" in m('{"api_key": "AK1234567"}')
    assert m("jdbc://app:pw123@db:5432") == "jdbc://app:<가림>@db:5432"
    assert "<JWT 가림>" in m("tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N")
    assert m("GET /healthz 200 12ms") == "GET /healthz 200 12ms"


def test_tracker_and_detail(tmp_path):
    async def main():
        conn = FakeConn(_topo(), _pods(False))
        e = _eng(tmp_path, conn)
        ob = e.vksobs
        assert await ob.tick() == 0                                              # 기준 스냅숏
        conn.inv["pods"] = _pods(True)
        conn.inv["pods"][2]["restarts"] = 10
        conn.inv["updated"] = 2.0
        t2 = copy.deepcopy(_topo())
        t2["deployments"][1]["images"] = ["w:2"]
        conn.inv["topo"], conn.inv["topo_updated"] = t2, 2.0
        n = await ob.tick()
        assert n >= 3 and await ob.tick() == 0                                   # 같은 스냅숏 → 기록 없음
        ri = ob.recent_index("tkc1")
        assert ri["Deployment:pay/worker"]["restart"] == 3 and ri["Deployment:pay/worker"]["n"] >= 2
        await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("l1", time.time(), "vks", "tkc1", "error", "np-1", "Pod/pay/worker-1a-x", "k8s-pod", "CrashLoopBackOff", 0, "", "{}"))
        await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("l2", time.time(), "vks", "tkc1", "error", "np-1", "Pod/pay/worker-1a-x", "k8s-log", "db password=hunter22 refused", 0, "", "{}"))
        g = await ob.graph("tkc1")
        w = next(x for x in g["nodes"] if x["id"] == "Deployment:pay/worker")
        assert w["events"] == 1 and w["recent"]["n"] >= 2
        d = await ob.detail("tkc1", "Deployment", "pay", "worker")
        assert d["node"]["own"] == "down" and d["pods"][0]["name"] == "worker-1a-x"
        assert {x["reason"] for x in d["events"]} == {"ScalingReplicaSet", "BackOff"} and "worker-1a" in conn.asked[-1][1]
        assert d["stored_events"][0]["message"] == "CrashLoopBackOff" and "hunter22" not in d["logs"][0]["message"]
        assert {r["action"] for r in d["activity"]} >= {"rollout", "restart"}
        assert d["infra"][0]["esxi"] == "esx01.lab"
        s = await ob.detail("tkc1", "Service", "pay", "worker")                  # 서비스 → 하류 워크로드 파드·변경
        assert s["pods"][0]["workload"] == "worker" and any(r.get("via") == "worker" for r in s["activity"])
        nd = await ob.detail("tkc1", "Node", "", "np-2")
        assert nd["node"]["status"] == "down" and nd["infra"][0]["vm_power"] == "poweredOff"
        try:
            await ob.detail("tkc1", "Deployment", "pay", "nope")
            raise AssertionError
        except LookupError:
            pass
        q = await ob.query("tkc1", ns="pay")
        assert q and all("label" in r for r in q)
    asyncio.run(main())


def test_recent_seed_after_restart(tmp_path):
    async def main():
        conn = FakeConn(_topo(), _pods(False))
        e = _eng(tmp_path, conn)
        await e.vksobs.record([{"ts": time.time() - 60, "connector": "tkc1", "kind": "Deployment", "ns": "pay", "name": "worker", "action": "restart",
                                "detail": "파드 worker-1a-x 재시작 +3 (누적 10)", "sev": "warn", "pod": "worker-1a-x"}])
        ob2 = vksobs.VksObserver(e)                                              # 재기동 — 메모리 비어 있음
        assert ob2.recent_index("tkc1") == {}
        await ob2.tick()
        assert ob2.recent_index("tkc1")["Deployment:pay/worker"]["restart"] == 3
    asyncio.run(main())
