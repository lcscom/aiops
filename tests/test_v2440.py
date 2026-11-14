"""2.44.0 — 비용 절감 찾기 · AI 변경 사전 검토"""
import datetime as dt
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from app import practice as PR
from tests.test_v2380 import _world_conns
from tests.test_v2410 import _phys

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _world():
    c = _world_conns()
    for h in c[0].topology["hosts"].values():
        h.update(cores=32, sockets=2, cpu_used_mhz=20000, mem_used_mb=200000)
    w = CB.build_world(NS(connectors=c, certs=NS(last={})))
    w["phys"] = _phys()
    return w


def test_consolidation_and_opportunities():
    w = _world()
    assert PR.hosts_needed(100, 100, 160, 1000, False) == 2 and PR.hosts_needed(300, 100, 160, 1000, True) == 4     # ceil(300/128)=3 +1
    cons = PR.consolidation(w, {}, [{"cluster": "c1", "reclaim_mem_gb": 100}])
    c = cons[0]
    # 4대 · 호스트당 160 GHz·1 TB · 사용 80 GHz·800 GB(−70 GB 회수) → max(1, 1)+1 = 2대 필요 → 2대 줄임
    assert c["hosts"] == 4 and c["needed"] == 2 and c["removable"] == 2 and c["lic_cores_per_host"] == 32 and c["basis"] == "현재값"
    rs = {"summary": {"powered_off": 3, "reclaim_disk_gb": 2000, "reclaim_vcpu": 8, "reclaim_mem_gb": 100}, "thresholds": {"off_days": 7}}
    # 단가 없으면 금액 없음(가격을 지어내지 않음)
    r0 = PR.opportunities(cons, rs, {"over72": 2}, None, dict(PR.DEFAULT_PRICES), 128)
    assert r0["total_year"] is None and all(o["amount"] is None for o in r0["ops"])
    assert "호스트 2대 · VCF 코어 64개" in next(o for o in r0["ops"] if o["id"] == "hosts")["qty"]
    p = dict(PR.DEFAULT_PRICES, vcf_core_year=100, kwh=100, hw_host_year=1000, storage_tb_year=10, owned_cores=200)
    r = PR.opportunities(cons, rs, {"over72": 2}, None, p, 128)
    h = next(o for o in r["ops"] if o["id"] == "hosts")
    kwh = 600 * 24 * 365 * 1.5 / 1000
    assert abs(h["amount"] - (64 * 100 + 2 * kwh * 100 + 2 * 1000)) < 1
    assert next(o for o in r["ops"] if o["id"] == "poweroff")["amount"] == 20                 # 2 TB × 10
    lic = next(o for o in r["ops"] if o["id"] == "license")
    assert "필요 64" in lic["qty"] and "여유 136" in lic["qty"] and lic["amount"] == 136 * 100   # 128 − 64(줄인 호스트) = 64 필요
    assert r["ops"][0]["amount"] == max(o["amount"] or 0 for o in r["ops"]) and r["total_year"] == sum(o["amount"] for o in r["ops"] if o["amount"])
    esa = {"now_tb": 10, "existing": [{"possible": True, "addon_tib": 5, "drives_per_host": 2, "hosts": 4, "name": "c1"}], "new_cluster": {"addon_tib": 9}}
    r2 = PR.opportunities(cons, rs, {}, esa, dict(p, vsan_tib_year=2, nvme_price=50, nvme_years=5), 128)
    e = next(o for o in r2["ops"] if o["id"] == "esa")
    assert e["amount"] == 10 * 10 - (5 * 2 + 8 * 50 / 5)


def test_parse_change_and_when():
    w = _world()
    p = PR.parse_change("11/20 새벽 2시 h0 BIOS 업데이트 후 재부팅, h1 도 순차 진행", w)
    assert [(f["type"], f["target"]) for f in p["failures"]] == [("host_maint", "h0"), ("host_maint", "h1")] and p["mode"] == "sequential"
    assert PR.parse_change("h2 메모리 교체로 전원 차단", w)["failures"][0]["type"] == "host_down"
    q = PR.parse_change("leaf-a NX-OS 업그레이드, fw-01 펌웨어, NETAPP AFF 컨트롤러 펌웨어, ds1 언마운트", w)
    assert {f["type"] for f in q["failures"]} == {"switch_down", "device_down", "storage_down", "ds_apd"}
    assert PR.parse_change("c1 롤링 패치", w)["failures"][0] == {**PR.parse_change("c1 롤링 패치", w)["failures"][0], "type": "host_maint", "target": "c1"}
    assert PR.parse_change("vcenter 업그레이드", w)["failures"][0]["type"] == "vcenter_upgrade"      # vCenter 하나면 일반 낱말로도
    w2 = _world()
    w2["vcenters"].append({**w2["vcenters"][0], "name": "vc2", "host": "vc2.x"})
    r = PR.parse_change("vcenter 업그레이드", w2)
    assert not r["failures"] and "vCenter 가 여러 개" in r["hint"]
    assert PR.parse_change("h10 재부팅", w)["failures"] == []                                       # h1 이 h10 에 걸리지 않음
    n = dt.datetime(2026, 11, 12, 7, 0)
    assert PR.parse_when("다음주 토요일 밤 10시", n)["iso"] == "2026-11-21T22:00"
    assert PR.parse_when("2026-12-01 01:30 작업", n)["iso"] == "2026-12-01T01:30"
    assert PR.parse_when("내일 오후 3시", n)["iso"] == "2026-11-13T15:00"
    assert PR.parse_when("1/5 02시", n)["iso"] == "2027-01-05T02:00"                                 # 지난 날짜면 내년
    assert PR.parse_when("esx01 재부팅", n) is None


def test_windows_and_mop():
    base = dt.datetime(2026, 11, 2, 0, 0)                                                       # 월요일
    rows = []
    for d in range(14):
        for h in range(24):
            t = base + dt.timedelta(days=d, hours=h)
            load = 20 if 2 <= h < 5 and t.weekday() == 5 else 60                                   # 토요일 02~05시가 가장 한가함
            rows.append((t.timestamp(), load, load - 5))
    wv = PR.windows(rows, 3, now=dt.datetime(2026, 11, 16, 12, 0))
    assert wv["days"] == 14 and wv["best"][0]["start"] == "2026-11-21T02:00" and wv["best"][0]["avg_pct"] == 20
    assert PR.windows([], 3)["best"] == []
    m = PR.mop({"host_maint", "vcenter_upgrade"})
    assert m["사전"][0].startswith("vCenter 파일 기반 백업") and any("유지보수 모드 진입" in x for x in m["작업"]) and m["되돌리기"]


def test_api_review_savings(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_practice import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    conns = _world_conns()

    class Cap:
        async def overview(self):
            return {"items": []}

        async def rightsizing(self):
            return {"summary": {}, "clusters": []}
    eng = NS(store=e.store, connectors=conns, certs=NS(last={}), capacity=Cap(), llm=None)
    pr = PR.Practice(eng)

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(eng, pr, lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        d = cl.get("/api/savings").json()
        assert d["total_year"] is None and d["prices"]["host_watt"] == 600 and d["total_cores"] > 0
        assert cl.put("/api/savings/prices", json={"vcf_core_year": "-1"}).status_code == 400
        assert cl.put("/api/savings/prices", json={"vcf_core_year": "350000", "currency": "KRW"}).json()["vcf_core_year"] == 350000
        assert cl.get("/api/savings").json()["currency"] == "KRW"
        assert cl.get("/api/savings.csv").content.decode("utf-8-sig").startswith("절감 기회,")
        assert cl.post("/api/change/review", json={"text": ""}).status_code == 400
        r = cl.post("/api/change/review", json={"text": "11/20 02시 h0 재부팅", "ai": False}).json()
        assert [f["target"] for f in r["failures"]] == ["h0"] and r["when"]["iso"].endswith("T02:00") and r["verdict"]["key"] in ("go", "cond", "hold")
        assert "# 변경 사전 검토" in r["markdown"] and "- [ ] " in r["markdown"] and "실제 인프라에는 아무것도 하지 않았습니다" in r["markdown"]
        assert {c["name"] for c in r["checks"]} >= {"관련 인증서", "최근 7일 구성 변경(대상 호스트)"}
        r2 = cl.post("/api/change/review", json={"text": "h0 재부팅", "ai": False, "failures": [{"type": "host_down", "vcenter": "vc1", "target": "h1", "kind": "host"}]}).json()
        assert [f["target"] for f in r2["failures"]] == ["h1"]                                 # 사용자가 고친 대상으로 다시 검토
        assert cl.post("/api/change/review", json={"text": "없는 장비 작업", "ai": False}).json()["verdict"]["key"] == "none"
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/savings/prices$", "operate"' in auth and 'r"^/api/change/review$", "view"' in auth
    html = (S / "index.html").read_text(encoding="utf-8")
    for k in ('id="nav-save"', 'id="nav-chg"', 'id="drawer-save"', 'id="drawer-chg"', "/static/save.js", "/static/change.js"):
        assert k in html
    nav = (S / "navgroup.js").read_text(encoding="utf-8")
    assert '["bill", "cc", "lc", "save"]' in nav and '"bot", "chg", "rd"' in nav
    for f in ("save.js", "change.js", "tour.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
