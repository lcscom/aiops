"""2.41.0 — 물리 계층(스위치·방화벽·라우터·외부 스토리지·물리 서버)을 시뮬레이터·체크봇에 넣고, 초기화 = 현재 구성 다시 받기"""
import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from app import physmap as PH
from app import simulator as SIM
from tests.test_v2380 import _world_conns

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _phys():
    """leaf-a·leaf-b(MLAG) ← spine-1·spine-2 ← fw-01·border-rtr. h0~h3 vmnic0→leaf-a, vmnic1→leaf-b. h0 vmnic1 은 지금 다운"""
    sw = {n: {"name": n, "role": r, "vendor": "", "model": "", "state": "", "mlag": m, "links": []} for n, r, m in
          [("leaf-a", "leaf", "pair1"), ("leaf-b", "leaf", "pair1"), ("spine-1", "spine", ""), ("spine-2", "spine", "")]}
    for lf in ("leaf-a", "leaf-b"):
        for sp in ("spine-1", "spine-2"):
            sw[lf]["links"].append({"to": sp, "kind": "switch", "port": "", "up": True})
            sw[sp]["links"].append({"to": lf, "kind": "switch", "port": "", "up": True})
    for sp in ("spine-1", "spine-2"):
        for d in ("fw-01", "border-rtr"):
            sw[sp]["links"].append({"to": d, "kind": "device", "port": "", "up": True})
    hosts = {f"h{i}": {"vcenter": "vc1", "cluster": "c1", "vswitches": {"vds": ["vmnic0", "vmnic1"]},
                       "nics": {"vmnic0": {"up": True, "switch": "leaf-a", "port": f"Eth{i}", "vswitch": "vds"},
                                "vmnic1": {"up": i != 0, "switch": "leaf-b", "port": f"Eth{i}", "vswitch": "vds"}}} for i in range(4)}
    return {"switches": sw, "devices": {"fw-01": {"name": "fw-01", "kind": "firewall", "switches": ["spine-1", "spine-2"]},
                                        "border-rtr": {"name": "border-rtr", "kind": "router", "switches": ["spine-1", "spine-2"]}},
            "hosts": hosts, "bgp": [{"tier0": "t0", "edge": "e1", "switch": "leaf-a", "state": "ESTABLISHED"}, {"tier0": "t0", "edge": "e2", "switch": "leaf-b", "state": "ESTABLISHED"}],
            "servers": {"h0": {"vcenter": "vc1", "vendor": "HPE", "model": "DL380", "serial": "SN0", "bmc": "10.0.0.10"}},
            "storage": {"NETAPP AFF": {"name": "NETAPP AFF", "kind": "san", "datastores": [{"vcenter": "vc1", "name": "ds1"}], "note": "추정"}}, "collected": {}}


def _world():
    conns = _world_conns(single_uplink=False)
    for i in range(4):
        conns[0].health_snap["hosts"][f"h{i}"]["vswitches"] = [{"name": "vds", "kind": "dvs", "uplinks": ["vmnic0", "vmnic1"]}]
        conns[0].health_snap["hosts"][f"h{i}"]["vmks"] = [{"device": "vmk0", "services": ["management"], "switch": "vds"},
                                                          {"device": "vmk2", "services": ["vsan"], "switch": "vds"}]
    w = CB.build_world(NS(connectors=conns, certs=NS(last={})))
    w["phys"] = _phys()
    return w


def test_reach_and_paths():
    p = _phys()
    ok, known = PH.reach(p, set())
    assert known and ok == {"leaf-a", "leaf-b", "spine-1", "spine-2"}
    assert PH.reach(p, {"spine-1", "spine-2"})[0] == set()                        # 스파인 둘 다 → 리프는 외부로 못 감
    assert PH.reach(p, {"fw-01"})[0] == ok                                         # 라우터로 우회
    hp = PH.host_paths(p, "h0", {"leaf-a"}, set(), ok, True)["vds"]
    assert hp["now"] == ["vmnic0"] and hp["live"] == []                            # h0 는 vmnic1 이 이미 다운 → leaf-a 하나로 끊김
    assert PH.host_paths(p, "h1", {"leaf-a"}, set(), ok, True)["vds"]["live"] == ["vmnic1"]


def test_switch_device_storage_scenarios():
    w = _world()
    r = CB.evaluate(w, {"type": "switch_down", "target": "leaf-a", "switches": ["leaf-a"], "id": "x"})
    st = {v["name"]: v.get("state") for v in r["vms"]}
    assert r["verdict"] == "fail" and st == {"vcsa01": "net", "db-local": "net"}       # h0 의 켜진 VM
    txt = " ".join(f["text"] for f in r["findings"])
    assert "관리망 업링크가 모두 끊김(h0)" in txt and "vSAN 네트워크" in txt and "단일 장애점이 된 호스트: h0(vmnic1)" in txt and "업링크가 1개만 남아" in txt
    assert "t0 BGP 세션 1/2개가 끊김" in txt and r["host_marks"]["vc1/h0"] == "isolated" and r["host_marks"]["vc1/h1"] == "degraded"
    r2 = CB.evaluate(w, {"type": "switch_down", "target": "spine-1 + spine-2", "switches": ["spine-1", "spine-2"], "id": "y"})
    assert {v.get("state") for v in r2["vms"]} == {"ext"} and len(r2["vms"]) == 9
    assert any("BGP 세션 2개 모두" in f["text"] for f in r2["findings"]) and any(s["kind"] == "NSX Tier-0" for s in r2["services"])
    r3 = CB.evaluate(w, {"type": "device_down", "target": "fw-01", "devices": ["fw-01"], "id": "z"})
    assert r3["verdict"] == "pass" and any("border-rtr" in f["text"] for f in r3["findings"])
    r4 = CB.evaluate(w, {"type": "device_down", "target": "both", "devices": ["fw-01", "border-rtr"], "id": "z2"})
    assert r4["verdict"] == "fail" and any("남은 방화벽·라우터가 없습니다" in f["text"] for f in r4["findings"])
    r5 = CB.evaluate(w, {"type": "storage_down", "target": "NETAPP AFF", "id": "s"})
    assert r5["verdict"] == "fail" and {v["state"] for v in r5["vms"]} == {"io"} and len(r5["vms"]) == 9 and any("추정 장비" in f["text"] for f in r5["findings"])
    # 결선 정보가 없으면 판단하지 않고 알림
    w2 = copy.deepcopy(w)
    w2["phys"]["hosts"] = {}
    assert any("물리 결선 정보" in f["text"] for f in CB.evaluate(w2, {"type": "switch_down", "target": "leaf-a", "id": "q"})["findings"])
    # 체크봇이 물리 시나리오도 만든다
    types = [(s["type"], s["target"]) for s in CB.generate(w)]
    assert ("switch_down", "leaf-a + leaf-b") in types and ("device_down", "fw-01") in types and ("storage_down", "NETAPP AFF") in types and ("switch_down", "spine-2") in types


def test_simulator_phys():
    w = _world()
    inv = SIM.inventory(w)["phys"]
    assert [d["name"] for d in inv["devices"]] == ["fw-01", "border-rtr"] and [s["name"] for s in inv["switches"]][:2] == ["spine-1", "spine-2"]
    leaf = next(s for s in inv["switches"] if s["name"] == "leaf-a")
    assert leaf["uplinks"] == ["spine-1", "spine-2"] and len(leaf["hosts"]) == 4 and inv["servers"]["h0"]["bmc"] == "10.0.0.10"
    r = SIM.simulate(w, [{"type": "switch_down", "target": "leaf-a"}, {"type": "switch_down", "target": "leaf-b"}, {"type": "host_down", "vcenter": "vc1", "target": "h3"},
                         {"type": "switch_down", "target": "ghost"}])
    assert [f["target"] for f in r["failures"]] == ["leaf-a", "leaf-b", "h3"]
    assert r["marks"]["switch:/leaf-a"] == "failed" and r["marks"]["host:vc1/h1"] == "isolated" and r["marks"]["host:vc1/h3"] == "failed"
    st = {v["name"]: v["state"] for v in r["vms"]}
    assert st["vcsa01"] == "net" and st["cp-3"] == "net"                            # 네트워크 끊김이 HA 재시작보다 우선
    assert r["counts"].get("net") == 9
    r2 = SIM.simulate(w, [{"type": "storage_down", "target": "NETAPP AFF"}])
    assert r2["marks"]["storage:/NETAPP AFF"] == "failed" and r2["marks"]["ds:vc1/ds1"] == "failed" and r2["counts"] == {"io": 8, "offline": 1}


def test_physmap_storage_and_manual(tmp_path):
    conns = _world_conns()
    conns[0].topology["datastores"]["ds1"].update(type="VMFS", extents=["naa.1"])
    conns[0].topology["datastores"]["nfs1"] = {"capacity_gb": 100, "free_gb": 50, "type": "NFS", "remote": "nas01:/vol/a"}
    conns[0]._lunv = {"naa.1": "PURE FlashArray"}
    eng = NS(connectors=conns, cfg={"checkbot": {"external": [{"name": "fw-x", "kind": "firewall"}, {"name": "array-2", "kind": "storage", "datastores": ["nfs1"]}]}})
    p = PH.build(eng)
    assert set(p["storage"]) == {"PURE FlashArray", "array-2"} and p["storage"]["array-2"]["source"] == "설정"
    assert p["devices"]["fw-x"]["kind"] == "firewall" and p["servers"]["h0"]["vcenter"] == "vc1"


def test_refresh_reset_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_checkbot import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    kicked = []

    class VC:
        type, enabled, name = "vcenter", True, "vcX"
        _last_topo = _last_health = 999.0
        topology = {}

        def _kick_heavy(self):
            kicked.append((self._last_topo, self._last_health))
    eng = NS(store=e.store, connectors=_world_conns() + [VC()], certs=NS(last={}), llm=None)

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(eng, CB.CheckBot(eng, {"ai": False}), lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        t0 = cl.get("/api/checkbot/inventory").json()["snapshot_ts"]
        r = cl.post("/api/checkbot/refresh").json()
        assert r["requested"] == ["vcX"] and kicked == [(0.0, 0.0)]                 # 다음 수집 시각을 지금으로 → 읽기 전용 재수집 시작
        assert cl.post("/api/checkbot/refresh").json()["throttled"] is True and len(kicked) == 1
        assert cl.get("/api/checkbot/inventory").json()["snapshot_ts"] >= t0
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/checkbot/refresh$", "view"' in auth
    js = (S / "sim.js").read_text(encoding="utf-8")
    for k in ("sm-reset", "/api/checkbot/refresh", "treeNet", "외부 스토리지", "물리 스위치", "외부 장비(방화벽·라우터)", "switch_down", "storage_down", "data-top"):
        assert k in js, k
    import subprocess
    subprocess.run(["node", "--check", str(S / "sim.js")], check=True)
    asyncio.new_event_loop().close()
