"""2.48.0 — What-If: 시간에 따른 영향 · 단일 장애점 순위 · 연속 검증(기록·새 실패 알림) · 보고서"""
import asyncio
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

from app import scenlib as L
from app import simulator as SIM
from app import spof as SP
from tests.test_v2460 import _world

ROOT = Path(__file__).resolve().parents[1]


def test_timeline():
    r = SIM.simulate(_world(), [{"type": "node_down", "target": "pay/w-1"}])
    t = r["timeline"]
    assert [p["t"] for p in t["phases"]] == ["즉시", "~1분", "~5분", "복구 전까지", "복구 후"]
    assert t["phases"][0]["vms"] >= 1 and t["phases"][-1] == {**t["phases"][-1], "vms": 0, "pods": 0, "vips": 0}
    assert t["phases"][0]["pods"] >= t["phases"][2]["pods"] and t["vm_minutes"][0] <= t["vm_minutes"][1]
    # HA 재시작만 있는 경우 — 5분 뒤에는 VM 0
    w = _world()
    for v in w["vcenters"][0]["topo"]["vms"].values():
        v["datastores"] = ["ds1"]
    h = SIM.simulate(w, [{"type": "host_down", "vcenter": "vc1", "target": "h0"}])
    c = h["counts"]
    if not (c.get("down") or c.get("io") or c.get("maybe")):
        assert h["timeline"]["phases"][2]["vms"] == 0
    assert "4시간(가정)" in h["timeline"]["assume"]


def test_spof_scan():
    d = SP.scan(_world(), 50)
    assert d["scanned"] >= 10 and {"ESXi 호스트", "VKS 노드", "Avi SE", "Avi 컨트롤러", "Supervisor"} <= set(d["by_kind"])
    sc = [x["score"] for x in d["top"]]
    assert sc == sorted(sc, reverse=True) and all("failure" in x for x in d["top"])
    top = d["top"][0]
    r = SIM.simulate(_world(), [top["failure"]])
    assert SP.score(r, top["name"])[0] == top["score"]
    se = next(x for x in d["top"] if x["kind"] == "Avi SE" and x["name"] == "se-2")
    assert se["stop"] == 0                                                                  # SE VM 자신은 중단 VM 에서 뺌


def test_diff_and_markdown():
    prev = {"ts": 1.0, "verdicts": {"c01": "pass", "c02": "fail", "c03": "warn"}}
    cur = {"verdicts": {"c01": "fail", "c02": "pass", "c03": "fail", "c04": "fail"}}
    d = L.LibWatch.diff(prev, cur)
    assert d["new_fail"] == ["c01", "c03"] and d["fixed"] == ["c02"] and d["prev_ts"] == 1.0         # 처음 보는 c04 는 '새로 실패' 아님
    assert L.LibWatch.diff(None, cur)["new_fail"] == []
    lib = L.run_all(_world())
    md = L.to_markdown(lib, SP.scan(_world(), 10), d)
    for h in ("# What-If 점검 보고서", "## 지난번과 달라진 것", "## 파트별", "## 단일 장애점 상위 10", "새로 실패: c01"):
        assert h in md


def test_watch_snapshot_and_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_checkbot import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    got = []
    eng = NS(store=e.store, ingest=lambda ev: got.append(ev))
    w = L.LibWatch(eng)
    W = _world()
    r1 = asyncio.run(w.snapshot(W, "t"))
    assert r1["counts"]["fail"] >= 1 and r1["new_fail"] == [] and not got
    # 다음 실행에서 통과였던 것이 실패로 → 이상징후
    import json
    row = asyncio.run(e.store.q1("SELECT ts, data FROM scnlib_runs"))
    d = json.loads(row["data"])
    flip = next(i for i, v in d["verdicts"].items() if v == "fail")
    d["verdicts"][flip] = "pass"
    asyncio.run(e.store.x("UPDATE scnlib_runs SET data=? WHERE ts=?", (json.dumps(d), row["ts"])))
    r2 = asyncio.run(w.snapshot(W, "t"))
    assert flip in r2["new_fail"] and got and "새로 실패" in got[0].message and got[0].connector == "whatif"
    assert len(asyncio.run(w.history())) == 2

    ENGINE = NS(store=e.store, connectors=[], certs=NS(last={}), scnwatch=w)
    import app.api_checkbot as AC
    orig = AC.build_world
    AC.build_world = lambda eng: W
    calls = []

    async def audit(*a, **k):
        calls.append(a[1])
    try:
        app = FastAPI()
        app.include_router(build_router(ENGINE, NS(latest=None, state={}, cfg={}), lambda r: {"user": "u"}, audit))
        with TestClient(app) as cl:
            lib = cl.get("/api/checkbot/library?run=1").json()
            assert "diff" in lib and lib["watch"]["interval_h"] == 6.0
            sp = cl.get("/api/checkbot/spof?top=5").json()
            assert len(sp["top"]) == 5
            assert cl.get("/api/checkbot/library/history").json()["items"]
            s = cl.post("/api/checkbot/library/snapshot").json()
            assert "counts" in s and calls == ["whatif.snapshot"]
            md = cl.get("/api/checkbot/library.md")
            assert md.status_code == 200 and "What-If 점검 보고서" in md.text
            cs = cl.get("/api/checkbot/library.csv")
            assert cs.text.startswith("﻿ID,파트,시나리오")
    finally:
        AC.build_world = orig


def test_wiring():
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert "ENGINE.scnwatch = LibWatch(" in main and 'S.spawn("scnwatch"' in main
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/checkbot/library/snapshot$", "operate"' in auth
    src = (ROOT / "app" / "spof.py").read_text(encoding="utf-8")
    for bad in ("requests", "httpx", "subprocess", "ReconfigVM", ".post("):
        assert bad not in src
    js = (ROOT / "app" / "static" / "scnlib.js").read_text(encoding="utf-8")
    assert "단일 장애점 순위" in js and "/api/checkbot/library.md" in js and "기록 저장" in js
    assert "function tline(" in (ROOT / "app" / "static" / "sim.js").read_text(encoding="utf-8")
    for f in ("scnlib.js", "sim.js"):
        subprocess.run(["node", "--check", str(ROOT / "app" / "static" / f)], check=True)
