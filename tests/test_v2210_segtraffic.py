"""2.21.0 VM 네트워크 트래픽(NSX·VDS·표준 vSwitch·Avi 가상 서비스) — 세그먼트·vNIC 합산, NSX 메타·포트 DFW 차단 병합, 이력 저장, API·권한·CSV·AI, vcsim 실조회(모든 포트그룹)"""
import asyncio
import json
import time

import pytest

from app.connectors.demo import demo_seg_vnics, demo_segment_ports, demo_topology, demo_vips, demo_vnic_traffic
from app.segtraffic.manager import SegTraffic, _down, _sum_series
from tests.test_v2110_support import _engine


class FakeVC:
    type = "vcenter"
    name = "lab-vc"
    enabled = True

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = 0

    def segment_vnics(self, scope="nsx"):
        if self.fail:
            raise RuntimeError("boom")
        self.calls += 1
        return demo_seg_vnics(scope)

    def vnic_traffic(self, vnics, samples=15):
        return demo_vnic_traffic(vnics, samples)

    def vm_net_history(self, moid, hours=24):
        from app.connectors.demo import demo_vm_net_history
        return demo_vm_net_history(moid, hours)


class FakeNSX:
    type = "nsx"
    name = "lab-nsx"
    enabled = True
    inv = {"segments": [{"name": f"seg-{n}", "id": f"seg-{n}", "type": "ROUTED", "connected_to": f"t1-{n}", "gateway": f"10.30.{i}.1/24", "tz": "overlay-tz",
                         "admin": "UP"} for i, n in enumerate(("web", "app", "db"))]}
    segment_ports = staticmethod(demo_segment_ports)


class FakeAvi:
    type = "avi"
    name = "lab-avi"
    enabled = True

    def __init__(self):
        ips = [v["ips"][0] for v in demo_topology()["vms"].values()]
        self.pools = [{"name": f"pool-{n}", "members": [{"ip": ips[(i * 3 + k) % len(ips)], "port": 8443} for k in range(3)]}
                      for i, n in enumerate(("mobile-api", "card-auth", "core-bank", "hr-web", "openbank"))]
        self.pools[4]["members"] = [{"ip": "192.168.50.10", "port": 8080}]

    def vips(self):
        return demo_vips()


def test_scopes_and_avi(tmp_path):
    e = _engine(tmp_path)
    e.connectors = [FakeVC(), FakeNSX(), FakeAvi()]
    e.avi_vips = lambda: [x for c in e.connectors if c.type == "avi" for x in c.vips()]
    M = SegTraffic(e, {})

    async def main():
        vds = await M.overview(300, "vds")
        assert [s["name"] for s in vds["segments"]] == ["pg-backup"] and vds["segments"][0]["kind"] == "dvpg" and vds["totals"]["vnics"] == 3
        std = await M.overview(300, "std")
        assert std["segments"][0]["key"] == "std:VM Network" and std["segments"][0]["kind"] == "std"
        assert std["segments"][0]["has_data"] and std["totals"]["no_data"] == 0           # vNIC 수가 같은 VDS 결과 캐시를 재사용하지 않음
        assert (await M.overview(300, "vds"))["segments"][0]["has_data"]
        await M.sample()
        hn = (await M.history("", 24, "nsx"))["points"][0]["rx_bps"]
        ha = (await M.history("", 24, "all"))["points"][0]["rx_bps"]
        assert hn < ha and (await M.history("", 24, "avi"))["points"] == []                # 추세는 범위의 네트워크만
        allp = await M.overview(300, "all")
        assert allp["totals"]["segments"] == 5 and allp["totals"]["vnics"] == 35
        nsx = await M.overview(300, "nsx")
        tagged = [v for v in nsx["vnics"] if v["avi"]]
        assert tagged and all(a["vs"].startswith("vs-") for v in tagged for a in v["avi"])      # Avi 뒤 VM 표시
        av = await M.overview(300, "avi")
        g = {s["name"]: s for s in av["segments"]}
        assert len(g) == 5 and g["vs-mobile-api"]["vms"] == 3 and g["vs-mobile-api"]["avi"]["bw"] > 0 and g["vs-mobile-api"]["kind"] == "avi"
        assert g["vs-openbank"]["vms"] == 0 and g["vs-openbank"]["avi"]["external"] == [{"ip": "192.168.50.10", "port": 8080, "pool": "pool-openbank"}]
        assert av["totals"]["avi_bw"] > 0 and all(v["segment"].startswith("avi:") and v["pool"] for v in av["vnics"])
        sg = await M.segment(g["vs-card-auth"]["key"], 300, "avi")
        assert sg["segment"]["name"] == "vs-card-auth" and len(sg["vnics"]) == 3 and len(sg["chart"]["rx_bps"]) == 15
        assert av["sources"]["avi"] == ["demo-avi"]
    asyncio.run(main())


def test_vm_view(tmp_path):
    e = _engine(tmp_path)
    e.connectors = [FakeVC(), FakeNSX(), FakeAvi()]
    e.avi_vips = lambda: [x for c in e.connectors if c.type == "avi" for x in c.vips()]
    M = SegTraffic(e, {})

    async def main():
        ov = await M.overview(300, "all")
        vl = M.vm_list(ov)
        assert len(vl) == 26 and vl == sorted(vl, key=lambda r: -(r["rx_bps"] + r["tx_bps"]))
        db = next(r for r in vl if r["vm"] == "core-bank-db01")
        assert db["vnics"] == 2 and db["kinds"] == ["nsx"] and db["drops"] > 0
        d = await M.vm("core-bank-was02", 300)
        assert [v["device"] for v in d["vnics"]] == sorted(v["device"] for v in d["vnics"])        # 장치 순서
        assert (await M.vm("core-bank-was02", 300, vcenter="lab-vc"))["vm"] == "core-bank-was02"
        with __import__("pytest").raises(KeyError):
            await M.vm("core-bank-was02", 300, vcenter="other-vc")
        kinds = sorted((v["net"]["kind"] for v in d["vnics"]))
        assert kinds == ["dvpg", "nsx"] and len(d["chart"]["rx_bps"]) == 15                 # NSX + VDS vNIC 한 VM 에
        assert abs(d["totals"]["rx_bps"] - sum(v["rx_bps"] for v in d["vnics"])) < 1
        h = await M.vm("hr-web-01", 300)
        assert h["totals"]["dfw"] == 340 and h["avi"] and h["avi"][0]["vs"].startswith("vs-")    # NSX DFW 차단·Avi 가상 서비스
        hist = await M.vm_history("hr-web-01", 24)
        assert len(hist["ts"]) == 288 and hist["interval"] == 300 and len(hist["series"]["usage_bps"]) == 288
        assert (await M.vm_history("hr-web-01", 168))["interval"] == 1800
        import pytest as _p
        with _p.raises(KeyError):
            await M.vm("nope")
        with _p.raises(KeyError):
            await M.vm_history("nope")
    asyncio.run(main())


def test_vm_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_segtraffic import build_router
    e = _engine(tmp_path)
    e.connectors = [FakeVC(), FakeNSX()]
    e.segtraffic = SegTraffic(e, {})

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda r: {"user": "v", "role": "viewer"}, audit))
    with TestClient(app) as cl:
        assert len(cl.get("/api/segtraffic/vms").json()["items"]) == 26
        assert cl.get("/api/segtraffic/vm?name=core-bank-db01").json()["vm"] == "core-bank-db01"
        assert cl.get("/api/segtraffic/vm?name=x").status_code == 404
        assert len(cl.get("/api/segtraffic/vm/history?name=core-bank-db01&hours=24").json()["ts"]) == 288
        rows = cl.get("/api/segtraffic.csv?vm=core-bank-db01").content.decode("utf-8-sig").splitlines()
        assert len(rows) == 3 and all(",core-bank-db01," in r for r in rows[1:])
        assert cl.get("/api/segtraffic.csv?vm=x").status_code == 404


def test_helpers():
    assert _sum_series([[1, 2, 3], [10, 20]]) == [1, 12, 23] and _sum_series([]) == []
    assert len(_down(list(range(600)), 60)) == 60 and _down([1.234, 2.0]) == [1.2, 2.0]


def test_overview_segment_history(tmp_path):
    e = _engine(tmp_path)
    vc = FakeVC()
    e.connectors = [vc, FakeNSX()]
    M = SegTraffic(e, {})

    async def main():
        ov = await M.overview(300)
        t = ov["totals"]
        assert t["segments"] == 3 and t["vnics"] == 29 and t["vms"] == 26 and t["rx_bps"] > 0 and t["drops"] > 0
        segs = {s["name"]: s for s in ov["segments"]}
        db = segs["seg-db"]
        assert db["gateway"] == "10.30.2.1/24" and db["connected_to"] == "t1-db" and db["nsx"] == "lab-nsx" and db["segment_id"] == "seg-db"
        assert db["drops"] > 0 and db["vms"] == 3 and db["vnics"] == 6 and len(db["spark"]) > 1
        assert abs(sum(s["rx_bps"] for s in ov["segments"]) - t["rx_bps"]) < 1
        assert ov["segments"] == sorted(ov["segments"], key=lambda s: -(s["rx_bps"] + s["tx_bps"]))
        off = [v for v in ov["vnics"] if v["power"] != "poweredOn"]
        assert off and not off[0]["has_data"] and t["no_data"] == 0          # 꺼진 VM 은 '카운터 없음'에 넣지 않음
        n = vc.calls
        await M.overview(900)
        assert vc.calls == n                                                    # vNIC 목록 캐시
        sg = await M.segment("/infra/segments/seg-web", 300)
        assert sg["segment"]["name"] == "seg-web" and all(v["segment"].endswith("seg-web") for v in sg["vnics"])
        assert len(sg["chart"]["rx_bps"]) == 15 and len(sg["chart"]["ts"]) == 15
        hr = next(v for v in sg["vnics"] if v["vm"].startswith("hr-web"))
        assert hr["nsx"]["dfw_drop"] == 340                                     # NSX 포트 통계(DFW 차단) 병합
        with pytest.raises(KeyError):
            await M.segment("/infra/segments/none")
        assert await M.sample() == 5                                            # NSX 3 + VDS 1 + 표준 vSwitch 1
        h = await M.history("/infra/segments/seg-db", 24)
        assert len(h["points"]) == 1 and h["points"][0]["rx_bps"] > 0
        one = (await M.history("", 24))["points"][0]                            # 표본 1개일 때 전체(NSX+VDS+표준) 합
        await M.sample()                                                        # 같은 5분 구간에 표본이 둘이어도
        allp = (await M.history("", 24))["points"]
        assert len(allp) == 1 and allp[0]["rx_bps"] < one["rx_bps"] * 1.6 and allp[0]["vms"] == one["vms"]   # 두 배로 합치지 않음(구간 평균)
        c = M.csv(ov, "/infra/segments/seg-db").decode("utf-8-sig").splitlines()
        assert c[0].startswith("segment,vm,vnic") and len(c) == 7 and all(r.startswith("seg-db,") for r in c[1:])
    asyncio.run(main())


def test_failure_is_reported(tmp_path):
    e = _engine(tmp_path)
    e.connectors = [FakeVC(fail=True)]
    ov = asyncio.run(SegTraffic(e, {}).overview(300))
    assert ov["totals"]["segments"] == 0 and any("boom" in x for x in ov["errors"])


def test_api_and_perms(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_segtraffic import build_router
    from app.security.auth import AuthManager
    e = _engine(tmp_path)
    e.connectors = [FakeVC(), FakeNSX()]
    e.segtraffic = SegTraffic(e, {})

    class FakeLLM:
        seen = {}

        async def complete(self, system, user, max_tokens=0, task="", names=None):
            self.seen.update(system=system, user=user, task=task, names=names)
            return "## 결론\nseg-app 트래픽 집중"
    e.llm = FakeLLM()
    logs = []

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append(action)
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda r: {"user": "op", "role": "operator"}, audit))
    with TestClient(app) as cl:
        o = cl.get("/api/segtraffic?window=900").json()
        assert o["window"] == 900 and o["vnics_total"] == 29 and "_series" not in o
        assert cl.get("/api/segtraffic?window=7").json()["window"] == 300
        s = cl.get("/api/segtraffic/segment", params={"key": "/infra/segments/seg-app"}).json()
        assert s["segment"]["name"] == "seg-app"
        assert cl.get("/api/segtraffic/segment", params={"key": "x"}).status_code == 404
        r = cl.get("/api/segtraffic.csv?key=/infra/segments/seg-web")
        assert r.status_code == 200 and "filename*=" in r.headers["content-disposition"] and "segtraffic.export" in logs
        rows = r.content.decode("utf-8-sig").splitlines()
        assert any(x.split(",")[-2] == "340" for x in rows[1:])                # 세그먼트 CSV 에 NSX DFW 차단 포함
        assert cl.get("/api/segtraffic.csv?key=nope").status_code == 404
        assert cl.post("/api/segtraffic/ai", json={"window": "abc"}).status_code == 400
        assert cl.post("/api/segtraffic/ai", json={"key": "nope"}).status_code == 404
        a = cl.post("/api/segtraffic/ai", json={"window": 300}).json()
        assert "seg-app" in a["report"] and FakeLLM.seen["task"] == "report" and "core-bank-db01" in FakeLLM.seen["names"]
        assert json.loads(FakeLLM.seen["user"])["합계"]["세그먼트"] == 3
        assert cl.get("/api/segtraffic/history?hours=24").json()["points"] == []
    rp = AuthManager.required_perm
    assert rp("GET", "/api/segtraffic") == "view" and rp("GET", "/api/segtraffic.csv") == "view" and rp("POST", "/api/segtraffic/ai") == "operate"


def test_ui_wired():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app" / "static"
    idx = (root / "index.html").read_text()
    assert 'data-nav="st"' in idx and 'id="drawer-st"' in idx and idx.index("segtraffic.js") < idx.index("layout.js")
    assert '"st"' in (root / "navgroup.js").read_text()
    js = (root / "segtraffic.js").read_text()
    assert "AIOPS_SEGTRAFFIC" in js and "/api/segtraffic/segment" in js


def test_vcsim_segment_vnics():
    """실제 pyVmomi 경로(vcsim) — vcsim 에는 NSX 포트그룹이 없어 nsx 범위는 비고, '모든 포트그룹'은 vNIC·성능 카운터를 읽음"""
    import socket
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "sim", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, lambda e: None)
    c.topology = {"hosts": {}}
    try:
        nsx = c.segment_vnics("nsx")
    except Exception as ex:  # noqa: BLE001
        pytest.skip(f"vcsim 접속 불가: {type(ex).__name__}")
    assert nsx["vnics"] == [] and nsx["segments"] == {}
    allp = c.segment_vnics("all")
    assert allp["vnics"] and all(v["device"] >= 4000 and v["segment"] for v in allp["vnics"])
    tr = c.vnic_traffic(allp["vnics"][:5], 3)
    assert isinstance(tr["series"], dict) and tr["interval"] == 20
    assert time.time() > 0
