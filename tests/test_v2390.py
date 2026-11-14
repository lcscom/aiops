"""2.39.0 — 장애 시뮬레이터: 인벤토리 트리, 객체 장애 겹치기 → 영향 리소스·트리 표시 즉시 계산"""
from pathlib import Path
from types import SimpleNamespace as NS

from app import simulator as SIM
from tests.test_v2380 import _world, _world_conns

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def test_inventory_tree():
    inv = SIM.inventory(_world())
    v = inv["vcenters"][0]
    c = v["datacenters"][0]["clusters"][0]
    assert v["name"] == "vc1" and c["name"] == "c1" and [h["name"] for h in c["hosts"]] == ["h0", "h1", "h2", "h3"]
    h0 = {x["name"]: x for x in c["hosts"][0]["vms"]}
    assert h0["vcsa01"]["mgmt"] == "vCenter" and h0["db-local"]["on"]
    assert {x["name"]: x for x in c["hosts"][2]["vms"]}["cp-1"]["vks"] == "pay"
    ds = {d["name"]: d for d in v["datastores"]}
    assert ds["local-h0"]["local"] and ds["ds1"]["vms"] == 9 and ds["ds1"]["used_pct"] == 96.0
    assert inv["edge_clusters"] == [{"name": "ec1", "edges": [{"name": "edge-01", "host": "h3"}, {"name": "edge-02", "host": "h3"}]}]
    assert {a["type"] for a in inv["actions"]["host"]} == {"host_down", "host_maint", "uplink_loss"}


def test_simulate_overlap_states_marks():
    w = _world()
    r = SIM.simulate(w, [{"type": "host_down", "vcenter": "vc1", "target": "h0"}, {"type": "host_maint", "vcenter": "vc1", "target": "h1"},
                         {"type": "nope"}, {"type": "host_down", "vcenter": "vc1", "target": "ghost"}, {"type": "host_down", "vcenter": "vc1", "target": "h0"}])
    assert [f["target"] for f in r["failures"]] == ["h0", "h1"]                      # 잘못된·중복 장애는 버림
    st = {v["name"]: v["state"] for v in r["vms"]}
    assert st["db-local"] == "down" and st["vcsa01"] == "restart" and st["gpu-vm"] == "blocked" and st["iso-vm"] == "blocked"
    assert "off-vm" not in st                                                       # 꺼진 VM 은 호스트 장애 영향 아님
    assert r["marks"]["host:vc1/h0"] == "failed" and r["marks"]["host:vc1/h1"] == "maint" and r["marks"]["cluster:vc1/c1"] == "degraded"
    assert r["marks"]["vm:vc1/db-local"] == "down" and any("합산 · 빠지는 호스트 2대" in f["text"] for f in r["findings"])
    assert any(f["text"].startswith("[호스트 유지보수 · h1]") for f in r["findings"])
    # 같은 호스트에 APD 를 겹치면 I/O 멈춤이 재시작보다 우선
    r2 = SIM.simulate(w, [{"type": "host_down", "vcenter": "vc1", "target": "h0"}, {"type": "ds_apd", "vcenter": "vc1", "target": "ds1"}])
    st2 = {v["name"]: v for v in r2["vms"]}
    assert st2["vcsa01"]["state"] == "io" and len(st2["vcsa01"]["by"]) == 2 and st2["db-local"]["state"] == "down" and st2["off-vm"]["state"] == "offline"
    assert r2["marks"]["ds:vc1/ds1"] == "failed" and r2["marks"]["host:vc1/h1"] == "affected" and r2["counts"]["io"] == 8


def test_simulate_combined_capacity_vks_cluster():
    # 작은 호스트로 바꿔 두 대가 빠지면 용량 부족 → HA 재시작 VM 은 '재시작 못할 수 있음'
    conns = _world_conns()
    for h in conns[0].topology["hosts"].values():
        h.update(cpu_mhz=40000, mem_mb=160000, cpu_used_mhz=20000, mem_used_mb=100000)
    w = NS(connectors=conns, certs=NS(last={}))
    from app import checkbot as CB
    world = CB.build_world(w)
    r = SIM.simulate(world, [{"type": "host_down", "vcenter": "vc1", "target": "h2"}, {"type": "host_down", "vcenter": "vc1", "target": "h3"}])
    st = {v["name"]: v["state"] for v in r["vms"]}
    assert r["verdict"] == "fail" and set(st.values()) == {"maybe"}
    assert any("[겹친 장애] VKS 'pay' 컨트롤 플레인 3/3" in f["text"] for f in r["findings"])
    assert r["vks"]["clusters"][0]["control_plane_lost"] == ["cp-1", "cp-2", "cp-3"] and r["vks"]["clusters"][0]["pods"] == 3
    # 클러스터 전체 장애에 포함된 호스트 장애는 따로 계산하지 않음
    r2 = SIM.simulate(world, [{"type": "cluster_down", "vcenter": "vc1", "target": "c1"}, {"type": "host_down", "vcenter": "vc1", "target": "h0"},
                              {"type": "edge_down", "target": "ec1"}, {"type": "vcenter_upgrade", "vcenter": "vc1"}])
    assert [f["skipped"] for f in r2["failures"]] == [False, True, False, False]
    assert r2["marks"]["cluster:vc1/c1"] == "failed" and r2["marks"]["host:vc1/h3"] == "failed" and r2["marks"]["edge:/ec1"] == "failed" and r2["marks"]["vc:vc1/vc1"] == "failed"
    assert all(v["state"] == "down" for v in r2["vms"]) and any(s["kind"] == "VKS Supervisor" for s in r2["services"])
    assert SIM.simulate(world, [])["verdict"] == "none"
    assert len(SIM.simulate(world, [{"type": "uplink_loss", "vcenter": "vc1", "target": f"h{i % 4}"} for i in range(40)])["failures"]) == 4


def test_api_and_ui(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app import checkbot as CB
    from app.api_checkbot import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    eng = NS(store=e.store, connectors=_world_conns(), certs=NS(last={}), llm=None)

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(eng, CB.CheckBot(eng, {"ai": False}), lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        assert cl.get("/api/checkbot/inventory").json()["vcenters"][0]["name"] == "vc1"
        r = cl.post("/api/checkbot/simulate", json={"failures": [{"type": "host_down", "vcenter": "vc1", "target": "h0", "label": "x"}]}).json()
        assert r["verdict"] == "fail" and r["marks"]["host:vc1/h0"] == "failed"
        assert cl.post("/api/checkbot/simulate", json={"x": 1}).status_code == 400
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/checkbot/simulate$", "view"' in auth
    js = (S / "sim.js").read_text(encoding="utf-8")
    for k in ("/api/checkbot/inventory", "/api/checkbot/simulate", "data-hit", "aiops.sim", "AIOPS_SIM"):
        assert k in js
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'data-cbmode="sim"' in html and 'id="sm-body"' in html and html.index("/static/sim.js") < html.index("/static/checkbot.js")
    assert "시뮬레이터에서 열기" in (S / "checkbot.js").read_text(encoding="utf-8")
    import subprocess
    for f in ("sim.js", "checkbot.js", "i18n-en.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
