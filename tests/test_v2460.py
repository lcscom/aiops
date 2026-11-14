"""2.46.0 — What-If 플랫폼: Supervisor · VKS(컨트롤 플레인·워커·워크로드) · vSphere Pod · Avi(컨트롤러·SE·가상 서비스)"""
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from app import platsim as PS
from app import simulator as SIM
from tests.test_v2380 import _vm, _world_conns

ROOT = Path(__file__).resolve().parents[1]


def _world():
    conns = _world_conns()
    vc, vks = conns[0], conns[1]
    V = vc.topology["vms"]
    for i, h in enumerate(("h0", "h1", "h2")):
        V[f"SupervisorControlPlaneVM ({i + 1})"] = _vm(h, ["ds1"])
    V["pod-a"] = {**_vm("h3", ["ds1"]), "os": "CRX Pod 1"}
    for n, h in (("ctl-1", "h0"), ("ctl-2", "h1"), ("ctl-3", "h1"), ("se-1", "h2"), ("se-2", "h3")):
        V[n] = _vm(h, ["ds1"])
    vc.vks = {"supervisors": [{"name": "c1", "endpoint": "10.0.0.1", "namespaces": ["pay"]}]}
    # cp-1·cp-2(h2) · cp-3·w-1(h3) — 기존 VKS 커넥터. 워크로드 추가
    vks.inv["pods"] += [{"ns": "pay", "name": "web-6d8f7c9b4-ab12c", "node": "w-1"}, {"ns": "pay", "name": "web-6d8f7c9b4-cd34e", "node": "cp-3"},
                        {"ns": "pay", "name": "db-0", "node": "w-1"}]
    avi = NS(name="avi1", type="avi", enabled=True, controllers={"state": "CLUSTER_UP_HA_ACTIVE", "nodes": [{"name": f"ctl-{k}", "role": "", "ip": ""} for k in (1, 2, 3)]},
             se={"se-1": {"name": "se-1", "host": "h2", "se_group": "g1", "vs": ["vs-a", "vs-b"]}, "se-2": {"name": "se-2", "host": "h3", "se_group": "g1", "vs": ["vs-b"]}},
             vs={"u1": {"name": "vs-a", "ses": ["se-1"]}, "u2": {"name": "vs-b", "ses": ["se-1", "se-2"]}})
    return CB.build_world(NS(connectors=conns + [avi], certs=NS(last={})))


def test_owner_and_build():
    assert PS.owner("web-6d8f7c9b4-ab12c") == ("web", "deploy") and PS.owner("db-0") == ("db", "sts")
    assert PS.owner("etcd-cp-1", "cp-1") == ("etcd", "static") and PS.owner("antrea-agent-x7k2p") == ("antrea-agent", "ds")
    P = PS.build(_world())
    s = P["supervisors"][0]
    assert [c["name"] for c in s["cp"]] == [f"SupervisorControlPlaneVM ({i})" for i in (1, 2, 3)] and [p["name"] for p in s["pods"]] == ["pod-a"] and s["vks"] == ["pay"]
    k = P["vks"][0]
    assert {n["name"]: (n["cp"], n["host"]) for n in k["nodes"]} == {"cp-1": (True, "h2"), "cp-2": (True, "h2"), "cp-3": (True, "h3"), "w-1": (False, "h3")}
    w = {x["name"]: (x["kind"], len(x["pods"])) for x in k["workloads"]}
    assert w["web"] == ("deploy", 2) and w["db"] == ("sts", 1) and w["etcd"] == ("static", 2)
    a = P["avi"][0]
    assert [(c["name"], c["host"]) for c in a["controllers"]] == [("ctl-1", "h0"), ("ctl-2", "h1"), ("ctl-3", "h1")] and {x["name"] for x in a["vs"]} == {"vs-a", "vs-b"}
    inv = SIM.inventory(_world())
    assert inv["platform"]["vks"][0]["cluster"] == "pay" and {"supervisor", "vks", "vksnode", "avictrl", "avise"} <= set(inv["actions"])


def _sim(fs):
    return SIM.simulate(_world(), fs)


def _items(r):
    return {i["name"]: i["state"] for i in r["platform"]["items"]}


def test_supervisor():
    r = _sim([{"type": "sup_down", "vcenter": "vc1", "target": "c1"}])
    assert r["verdict"] == "fail" and r["marks"]["sup:vc1/c1"] == "failed" and any("Supervisor API 가 멈춥니다" in f["text"] for f in r["findings"])
    assert _items(r) == {"pay": "risk", "pod-a": "risk"} and {v["name"] for v in r["vms"] if v["state"] == "down"} >= {"SupervisorControlPlaneVM (1)"}
    u = _sim([{"type": "sup_upgrade", "vcenter": "vc1", "target": "c1"}])
    assert u["verdict"] == "warn" and u["marks"]["sup:vc1/c1"] == "maint" and not u["vms"]
    assert _sim([{"type": "sup_down", "vcenter": "vc1", "target": "없음"}])["verdict"] == "none"            # 없는 대상은 무시
    # 호스트 2대가 같이 죽으면 Supervisor CP 2/3 → 쿼럼 상실
    h = _sim([{"type": "host_down", "vcenter": "vc1", "target": "h0"}, {"type": "host_down", "vcenter": "vc1", "target": "h1"}])
    assert any("[Supervisor · c1] Supervisor API 가 멈춥니다" in f["text"] for f in h["findings"])
    one = _sim([{"type": "host_down", "vcenter": "vc1", "target": "h0"}])
    assert any("컨트롤 플레인 VM 1/3대를 잃음" in f["text"] for f in one["findings"]) and one["marks"]["sup:vc1/c1"] == "degraded"


def test_vks_nodes_and_workloads():
    r = _sim([{"type": "node_down", "target": "pay/w-1"}])
    it = _items(r)
    # 워커가 w-1 하나뿐 → 잃으면 다시 배치할 곳 없음: web 은 cp-3 에 하나 남아 줄어든 채 계속(위험), db 는 하나뿐 → 중단
    assert it["pay/web"] == "risk" and it["pay/db"] == "stop" and r["marks"]["vksnode:/pay/w-1"] == "failed"
    assert any("워커 노드 1대를 모두 잃음" in f["text"] for f in r["findings"])
    assert any(v["name"] == "w-1" and v["state"] == "down" for v in r["vms"])
    # h2 호스트 장애 → CP 2/3(cp-1·cp-2) → 쿼럼 상실
    h = _sim([{"type": "host_down", "vcenter": "vc1", "target": "h2"}])
    assert any("[VKS · pay] 컨트롤 플레인 2/3대를 잃어 쿼럼 상실" in f["text"] for f in h["findings"])
    assert any("같은 ESXi" in a for a in h["actions"])
    cp = _sim([{"type": "vks_cp_down", "target": "pay"}])
    assert any("쿼럼 상실" in f["text"] for f in cp["findings"]) and cp["marks"]["vks:/pay"] == "failed"
    # 워커를 하나 더 두면(w-2) 다시 배치 가능 → web 계속, db 는 수 분 뒤 다시 뜸
    w = _world()
    w["vks"][0]["nodes"].append({"name": "w-2", "roles": []})
    w["vcenters"][0]["topo"]["vms"]["w-2"] = _vm("h0", ["ds1"])
    it2 = {i["name"]: i["state"] for i in SIM.simulate(w, [{"type": "node_down", "target": "pay/w-1"}])["platform"]["items"]}
    assert it2["pay/web"] == "ok" and it2["pay/db"] == "boot"
    up = _sim([{"type": "vks_upgrade", "target": "pay"}])
    assert up["verdict"] == "warn" and _items(up).get("pay/db") == "boot" and up["marks"]["vks:/pay"] == "maint"
    # 노드 둘(w-1, cp-3) + CP 쿼럼 상실(cp-1·cp-2 h2) → 다시 배치 못 함 → web 중단
    x = _sim([{"type": "node_down", "target": "pay/w-1"}, {"type": "node_down", "target": "pay/cp-3"}, {"type": "vks_cp_down", "target": "pay"}])
    assert _items(x)["pay/web"] == "stop"


def test_avi():
    r = _sim([{"type": "avi_se_down", "target": "avi1/se-1"}])
    assert _items(r) == {"vs-a": "boot", "vs-b": "ok"} and r["verdict"] == "warn" and r["marks"]["avise:/avi1/se-1"] == "failed"
    c = _sim([{"type": "avi_ctrl_down", "target": "avi1/ctl-1"}])
    assert c["verdict"] == "warn" and any("과반이 남아" in f["text"] for f in c["findings"])
    # h1 에 컨트롤러 2대 → 호스트 하나로 컨트롤러 클러스터 멈춤 + 반선호도 권고
    h = _sim([{"type": "host_down", "vcenter": "vc1", "target": "h1"}])
    assert any("[Avi · avi1] 컨트롤러 2/3대를 잃어 클러스터가 멈춥니다" in f["text"] for f in h["findings"]) and any("Avi 'avi1' 컨트롤러" in a for a in h["actions"])
    # 컨트롤러가 멈춘 상태에서 SE 를 잃으면 SE 하나뿐인 VS 는 중단
    both = _sim([{"type": "host_down", "vcenter": "vc1", "target": "h1"}, {"type": "avi_se_down", "target": "avi1/se-1"}])
    assert _items(both)["vs-a"] == "stop" and both["verdict"] == "fail"


def test_safety_and_ui():
    src = (ROOT / "app" / "platsim.py").read_text(encoding="utf-8")
    for bad in ("requests", "httpx", "subprocess", "PowerOff", "Reconfig", "kubectl", ".post("):
        assert bad not in src                                                               # 계산만
    js = (ROOT / "app" / "static" / "sim.js").read_text(encoding="utf-8")
    assert 'treePlat()' in js and '"VKS·Avi"' in js and "sm-plat" in js
    subprocess.run(["node", "--check", str(ROOT / "app" / "static" / "sim.js")], check=True)
