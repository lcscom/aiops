"""2.45.0 — AIOps 인사이트: 토폴로지 근본 원인 · 변경 상관 · 전조 학습 · 피드백 학습"""
import asyncio
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace as NS

from app import aiopsx as AX
from app.detect import Detector, make_template, pattern_key
from app.models import LogEvent
from tests.test_v2380 import _world_conns
from tests.test_v2410 import _world

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _sym(g, *names, t0=1000.0, step=30):
    out = []
    for i, n in enumerate(names):
        for node in AX.resolve(g, {"entity": n}):
            out.append({"node": node, "ts": t0 + i * step, "title": n})
    return out


def test_graph_and_resolve():
    g = AX.graph(_world())
    k = g["kids"]
    assert "host:vc1/h0" in k["switch:leaf-a"] and "host:vc1/h0" in k["switch:leaf-b"]          # 물리 결선
    assert "switch:spine-1" in k["device:fw-01"]
    assert "ds:vc1/ds1" in k["storage:NETAPP AFF"] and "vm:vc1/cp-1" in k["ds:vc1/ds1"]
    assert "vm:vc1/cp-1" in k["host:vc1/h2"] and "vks:pay" in k["vm:vc1/cp-1"]
    assert AX.resolve(g, {"entity": "perf:vm-ready:vm:cp-1"}) == ["vm:vc1/cp-1"]
    assert AX.resolve(g, {"entity": "leaf-a:Ethernet8"}) == ["switch:leaf-a"]
    assert AX.resolve(g, {"entity": "", "host": "h3.bank.local"}) == ["host:vc1/h3"]
    assert AX.resolve(g, {"entity": "없는개체"}) == []


def test_rca_ranks_common_cause():
    g = AX.graph(_world())
    # h2 위 VM 두 대 + VKS + h2 자신(가장 먼저) → h2
    r = AX.rca(g, _sym(g, "h2", "cp-1", "cp-2", "pay"))
    assert r[0]["node"] == "host:vc1/h2" and r[0]["covers"] == 4 and r[0]["own_symptom"] and r[0]["earliest"]
    assert any("h2 → cp-1" in p for p in r[0]["paths"])
    # 스토리지 장비가 먼저 → 여러 호스트의 VM 이 같이 → 스토리지 장비
    r = AX.rca(g, _sym(g, "NETAPP AFF", "vcsa01", "gpu-vm", "cp-3"))
    assert r[0]["node"] == "storage:NETAPP AFF" and r[0]["covers"] == 4
    # 리프 스위치 + 모든 호스트 → 스위치(vCenter·클러스터처럼 넓은 후보는 벌점·설명력 같아도 아래)
    r = AX.rca(g, _sym(g, "leaf-a", "h0", "h1", "h2", "h3"))
    assert r[0]["node"] == "switch:leaf-a"
    # 증상 개체에 직전 변경이 있으면 앞선다
    s = _sym(g, "cp-1", "w-1", t0=1000, step=0)
    a = AX.rca(g, s)
    b = AX.rca(g, s, [{"node": "vm:vc1/w-1"}])
    assert b[0]["node"] == "vm:vc1/w-1" and b[0]["changed"] and a[0]["score"] <= b[0]["score"]
    assert AX.rca(g, []) == []


def test_learn_precursors_and_weights():
    sc = {"cluster:vc1/c1"}
    incs = [{"id": f"I{i}", "title": "HA 격리", "ts": 10000 + i * 20000, "kind": "host", "scope": sc} for i in range(4)]
    anoms = [{"ts": i["ts"] - 900, "pkey": "esxi|vmkernel: link down <n>", "scope": sc, "title": "링크 다운"} for i in incs[:3]]
    anoms += [{"ts": 5000 + n * 7000, "pkey": "esxi|harmless <N>", "scope": sc, "title": "잡음"} for n in range(12)]     # 아무 때나
    anoms += [{"ts": incs[3]["ts"] - 900, "pkey": "esxi|other scope", "scope": {"cluster:vc1/c9"}, "title": "다른 범위"}]
    rules = AX.learn_precursors(incs, anoms, days=1)
    assert [r["pkey"] for r in rules] == ["esxi|vmkernel: link down <n>"]
    r = rules[0]
    assert r["support"] == 3 and r["confidence"] == 1.0 and r["lead_min"] == 15 and r["lift"] >= 3 and r["kind"] == "host"
    assert AX.learn_precursors(incs, anoms, days=1, min_support=4) == []
    assert AX.learned_weight(0, 0) == 1.0 and AX.learned_weight(0, 1) == 0.6 and AX.learned_weight(0, 50) <= 0.22 and AX.learned_weight(0, 5) < 0.4
    assert 1.0 < AX.learned_weight(5, 0) <= 1.2 and AX.learned_weight(1, 1) < 1.0


def test_detector_feedback_hook():
    d = Detector({"warmup_seconds": 0})
    ev = LogEvent(source="esxi", connector="c", message="vmkernel: NIC vmnic1 link down on esx01", severity="error", host="esx01")
    s0, _, _ = d.evaluate(ev)
    k = pattern_key("esxi", make_template(ev.message), "esx01", "")
    assert "<n>" in k and "esx01" not in k
    d.learned = {k: 0.2}
    ev2 = LogEvent(source="esxi", connector="c", message="vmkernel: NIC vmnic1 link down on esx01", severity="error", host="esx01")
    s1, _, _ = d.evaluate(ev2)
    assert s1 < s0 and any("피드백 학습 ×0.2" in r for r in ev2.reasons)
    ev3 = LogEvent(source="esxi", connector="c", message="vmkernel: NIC vmnic1 link down on esx02", severity="error", host="esx02")
    d.evaluate(ev3)
    assert any("피드백 학습" in r for r in ev3.reasons)                                  # 같은 패턴의 다른 호스트에도 적용


async def _seed(e, now):
    def an(i, ts, ent, msg, src="vcenter", host=""):
        ev = {"source": src, "host": host, "entity": ent, "message": msg, "template": make_template(msg), "ts": ts, "connector": "c"}
        return (f"A{i}", ts, ts, "error", "open", 0, json.dumps({"event": ev, "title": f"{ent}: {msg}", "severity": "error", "score": 0.6, "category": "host"}))
    rows = [an(1, now - 600, "h2", "Host h2 not responding"), an(2, now - 560, "cp-1", "VM cp-1 heartbeat lost"),
            an(3, now - 550, "cp-2", "VM cp-2 heartbeat lost"), an(4, now - 3000, "h9", "noise pattern 1")]
    for r in rows:
        await e.store.x("INSERT INTO anomalies(id,created,last_seen,severity,status,ack,body) VALUES(?,?,?,?,?,?,?)", r)
    await e.store.x("INSERT INTO incidents(id,title,severity,status,category,cluster,anomaly_ids,anomaly_count,created,acknowledged_at,resolved_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("INC-1", "h2 장애", "critical", "resolved", "host", "c1", json.dumps(["A1", "A2", "A3"]), 3, now - 600, now - 480, now - 60))
    await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, now - 1800, "vcenter", "vc1", "info", "vc1", "h2", "event", "Host h2 configuration changed: NTP", 0, "", "{}"))
    await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (2, now - 1700, "vcenter", "vc1", "info", "vc1", "h0", "event", "Reconfigured iso-vm on h0", 0, "", "{}"))


def test_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_aiopsx import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    now = time.time()
    asyncio.run(_seed(e, now))
    det = Detector({})
    eng = NS(store=e.store, connectors=_world_conns(), certs=NS(last={}), llm=None, detector=det)
    x = AX.AIOpsX(eng)
    calls = []

    async def audit(*a, **k):
        calls.append(a[1])
    app = FastAPI()
    app.include_router(build_router(eng, x, lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        k = cl.get("/api/aiops/kpi").json()
        assert k["anomalies"] == 4 and k["incidents"] == 1 and k["anomaly_to_incident"] == 4.0 and k["mtta_min"] == 2.0 and k["mttr_min"] == 9.0 and k["noise_pct"] is None
        assert [i["id"] for i in cl.get("/api/aiops/incidents").json()["items"]] == ["INC-1"]
        r = cl.get("/api/aiops/rca/INC-1").json()
        assert not r["weak"] and r["roots"][0]["name"] == "h2" and r["roots"][0]["covers"] == 3 and r["symptoms"] == 3 and len(r["timeline"]) == 3
        assert r["roots"][0]["changed"]                                                     # h2 NTP 변경이 직전에 있음
        ch = {c["what"]: c for c in r["changes"]}
        assert ch["Host h2 configuration changed: NTP"]["related"] and not ch["Reconfigured iso-vm on h0"]["related"]
        assert r["changes"][0]["what"].startswith("Host h2")
        assert cl.get("/api/aiops/rca/INC-404").status_code == 404
        assert "error" in cl.get("/api/aiops/rca/INC-1?ai=1").json()["ai"]                 # AI 미설정 — 근거 표는 그대로
        t = cl.get("/api/aiops/triage").json()["items"]
        assert {a["id"] for a in t} >= {"A1", "A4"} and all(a["verdict"] is None for a in t)
        assert cl.post("/api/aiops/feedback", json={"anomaly_id": "A4", "verdict": "bad"}).status_code == 400
        assert cl.post("/api/aiops/feedback", json={"anomaly_id": "ZZ", "verdict": "noise"}).status_code == 404
        f = cl.post("/api/aiops/feedback", json={"anomaly_id": "A4", "verdict": "noise"}).json()
        assert f["weight"] == 0.6 and det.learned == {f["pkey"]: 0.6}
        assert cl.get("/api/aiops/kpi").json()["noise_pct"] == 100.0
        assert next(a for a in cl.get("/api/aiops/triage").json()["items"] if a["id"] == "A4")["verdict"] == "noise"
        assert cl.post("/api/aiops/feedback", json={"anomaly_id": "A4", "verdict": "clear"}).json()["weight"] == 1.0 and det.learned == {}
        p = cl.post("/api/aiops/precursors/learn").json()
        assert p["state"]["incidents"] == 1 and isinstance(p["rules"], list)
        assert cl.get("/api/aiops/precursors").json()["state"]["incidents"] == 1
    assert calls == ["aiops.feedback", "aiops.feedback", "aiops.learn"]                     # 잘못된 요청은 감사 기록 없음


def test_watch_raises_early_warning(tmp_path):
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    got = []
    now = time.time()

    async def main():
        await _seed(e, now)
        eng = NS(store=e.store, connectors=_world_conns(), certs=NS(last={}), llm=None, detector=None, ingest=lambda ev: got.append(ev))
        x = AX.AIOpsX(eng)
        await x.ensure()
        body = json.loads((await e.store.q1("SELECT body FROM anomalies WHERE id='A1'"))["body"])
        await e.store.x("UPDATE anomalies SET created=? WHERE id='A1'", (now - 60,))
        x.rules = [{"id": "host|p", "kind": "host", "pkey": AX.pkey(body["event"]), "title": "t", "support": 3, "occurrences": 3, "confidence": 0.8, "lift": 9.0, "lead_min": 12}]
        w1 = await x.watch(now)
        w2 = await x.watch(now + 60)                                                         # 같은 전조·개체 1시간 1번
        return w1, w2
    w1, w2 = asyncio.run(main())
    assert len(w1) == 1 and w2 == [] and len(got) == 1
    ev = got[0]
    assert ev.source == "aiops" and ev.connector == "precursor" and "조기 경보" in ev.message and "약 12분" in ev.message and "80%" in ev.message


def test_wiring_and_safety():
    src = (ROOT / "app" / "aiopsx.py").read_text(encoding="utf-8")
    for bad in ("ReconfigVM", "PowerOff", "EnterMaintenance", "requests.post", "subprocess"):
        assert bad not in src                                                               # 분석만
    assert "names=names" in src                                                            # 외부 AI 에는 가명 처리
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert "ENGINE.aiopsx = AIOpsX(" in main and 'S.spawn("aiopsx"' in main
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/aiops/(feedback|precursors/learn)$", "operate"' in auth and '("GET", r"^/api/aiops/", "view")' in auth
    html = (S / "index.html").read_text(encoding="utf-8")
    for k in ('id="nav-aiops"', 'id="drawer-aiops"', "/static/aiopsx.js"):
        assert k in html
    assert '["inc", "aiops", "sr"]' in (S / "navgroup.js").read_text(encoding="utf-8")
    assert "    aiops: [" in (S / "tour.js").read_text(encoding="utf-8")
    for f in ("aiopsx.js", "tour.js", "navgroup.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
