"""2.25.0 자체 성능 이력·계절성 이상 탐지·동료 이상치·감시 규칙·호스트 맵"""
import asyncio
import math
import random
import re
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _pw(tmp_path, monkeypatch):
    import app.main as M
    from app.connectors.demo import demo_perf_latest, demo_perf_series, demo_topology
    from app.perfview import PerfView
    from app.perfwatch import PerfWatch

    class C:
        type, name, enabled = "vcenter", "demo-vc", True
        topology = demo_topology()
        perf_series = staticmethod(demo_perf_series)
        perf_latest = staticmethod(demo_perf_latest)
    monkeypatch.setattr(M.ENGINE, "connectors", [C()])
    ev = []
    monkeypatch.setattr(M.ENGINE, "submit", lambda e: ev.append(e) or True)
    pv = PerfView(M.ENGINE)
    pw = PerfWatch(M.ENGINE, pv, {"db_path": str(tmp_path / "perf.db")}, str(tmp_path))
    pv.watch = pw
    return M, pv, pw, ev


def _history(pw, days=22, spike=None):
    S = pw.store
    now = int(time.time() // 300 * 300)
    random.seed(7)
    ents = list(S.ents)
    for d in range(days * 24 * 12, 0, -1):
        ts = now - d * 300
        hr = ((ts + time.localtime().tm_gmtoff) // 3600) % 24
        S.put(ts, [(e, {"cpu": 30 + 15 * math.sin(hr / 24 * 2 * math.pi) + random.gauss(0, 1.5), "mem": 50.0, "rdy": 1.0, "iops": 400.0,
                        "lat": 3.0 + random.random(), "dbps": 1e7, "nbps": 5e7}) for e in ents])
    S._x("INSERT OR REPLACE INTO meta(k, v) VALUES('rollup', ?)", (str(now - (days + 1) * 86400),))
    S.ret5 = days + 1
    S.rollup()
    S.ret5 = 3
    S.rollup()
    return now


def test_sample_store_rollup_and_detail(tmp_path, monkeypatch):
    M, pv, pw, ev = _pw(tmp_path, monkeypatch)

    async def go():
        st = await pw.sample()
        assert st["count"] == len(pw.store.ents) > 0 and not st["errors"]
        _history(pw, days=4)
        z = pw.store.size()
        assert z["h1"] > 0 and z["s5"] > 0 and z["mb"] > 0
        host = next(e for e, v in pw.store.ents.items() if v["kind"] == "host")
        name = pw.store.ents[host]["name"]
        d = await pv.detail("host", name, "demo-vc", "s3d")
        assert d["source"] == "store" and d["interval"] == 300 and "cpu.usage_pct" in d["series"] and d["bands"]["cpu.usage_pct"]["lo"]
        h = await pv.detail("host", name, "demo-vc", "h6w")
        assert h["interval"] == 3600 and "cpu.usage_pct_max" in h["series"]
        rt = await pv.detail("host", name, "demo-vc", "rt")
        assert "cpu.usage_pct" in rt.get("bands", {})                         # 실시간 차트에도 정상 범위
        pw.store.ret5, pw.store.ret1 = 1, 2                                   # 보존 기간 정리
        pw.store.rollup()
        old = pw.store._x("SELECT COUNT(*) FROM s5 WHERE ts < ?", (int(time.time() - 1.1 * 86400),))[0][0]
        assert old == 0
    asyncio.run(go())


def test_anomaly_outlier_threshold_and_recovery(tmp_path, monkeypatch):
    M, pv, pw, ev = _pw(tmp_path, monkeypatch)

    async def go():
        await pw.sample()
        now = _history(pw, days=22)
        S = pw.store
        hosts = [e for e, v in S.ents.items() if v["kind"] == "host"]
        cl = S.ents[hosts[0]]["cluster"]
        peers = [h for h in hosts if S.ents[h]["cluster"] == cl]
        assert len(peers) >= 3
        bad, vm = peers[0], next(e for e, v in S.ents.items() if v["kind"] == "vm")
        hr = ((now + time.localtime().tm_gmtoff) // 3600) % 24
        normal = 30 + 15 * math.sin(hr / 24 * 2 * math.pi)
        for i in range(7, -1, -1):
            ts = now - i * 300 + 300
            S.put(ts, [(e, {"cpu": 96.0 if e == bad else (normal + 40 if e == vm else normal), "mem": 50.0, "rdy": 12.0 if e == vm else 1.0,
                            "iops": 400.0, "lat": 3.0, "dbps": 1e7, "nbps": 5e7}) for e in S.ents])
        bl = await pw.baselines("cpu")
        assert bl[bad][2] == "weekly"                                         # 3주 이력 → 주 계절성
        await pw.evaluate()
        now_al = {(a["rule"], a["name"]): a for a in pw.alerts_now()}
        bn, vn = S.ents[bad]["name"], S.ents[vm]["name"]
        assert now_al[("host-cpu", bn)]["sev"] == "critical"
        assert ("host-cpu-outlier", bn) in now_al and "중앙값" in now_al[("host-cpu-outlier", bn)]["msg"]
        assert ("vm-cpu-anom", vn) in now_al and "평소 범위" in now_al[("vm-cpu-anom", vn)]["msg"]
        assert now_al[("vm-ready", vn)]["sev"] == "critical"
        n_ev = len(ev)
        await pw.evaluate()
        assert len(ev) == n_ev                                                # 상태 그대로면 이벤트 없음
        assert any(e.entity == f"perf:host-cpu:host:{bn}" and e.severity == "critical" for e in ev)
        for i in range(7, -1, -1):                                            # 회복
            ts = now + 600 + (8 - i) * 300
            S.put(ts, [(e, {"cpu": normal, "mem": 50.0, "rdy": 1.0, "iops": 400.0, "lat": 3.0, "dbps": 1e7, "nbps": 5e7}) for e in S.ents])
        monkeypatch.setattr(time, "time", lambda: now + 600 + 9 * 300)
        await pw.evaluate()
        assert ("host-cpu", bn) not in {(a["rule"], a["name"]) for a in pw.alerts_now()}
        assert any(e.attrs.get("recovered") and e.entity == f"perf:host-cpu:host:{bn}" for e in ev)
        hist = await pw.history(48)
        assert any(h["rule"] == "host-cpu" and h["end"] for h in hist)
    asyncio.run(go())


def test_rules_validate_crud(tmp_path, monkeypatch):
    from app.perfwatch import validate_rule
    with pytest.raises(ValueError):
        validate_rule({"kind": "host", "metric": "rdy", "type": "threshold", "warn": 5})
    with pytest.raises(ValueError):
        validate_rule({"kind": "vm", "metric": "cpu", "type": "threshold"})
    with pytest.raises(ValueError):
        validate_rule({"kind": "vm", "metric": "cpu", "type": "anomaly", "name_re": "("})
    r = validate_rule({"id": "My Rule!", "kind": "vm", "metric": "cpu", "type": "anomaly", "k": 99, "pct": 5, "window": 30})
    assert r["id"] == "myrule" and r["k"] == 10 and r["pct"] == 10
    M, pv, pw, ev = _pw(tmp_path, monkeypatch)
    assert len(pw.rules) == 10
    pw.save_rule({"id": "db-cpu", "name": "DB CPU", "kind": "vm", "metric": "cpu", "type": "threshold", "warn": 70, "name_re": "^core-bank-db"}, "t")
    assert "db-cpu" in pw.rules
    pw.delete_rule("db-cpu")
    assert "db-cpu" not in pw.rules
    pw.reset_rules()
    assert len(pw.rules) == 10


def test_api_rbac_and_ui():
    from app.security.auth import ROUTE_RULES

    def perm(m, p):
        for mm, rx, pr in ROUTE_RULES:
            if (mm == "*" or mm == m) and re.search(rx, p):
                return pr
    assert perm("GET", "/api/perf/watch") == "view" and perm("GET", "/api/perf/map") == "view"
    assert perm("POST", "/api/perf/rules") == "settings" and perm("DELETE", "/api/perf/rules/x") == "settings"
    assert perm("POST", "/api/perf/rules/preview") == "settings" and perm("POST", "/api/perf/rules/reset") == "settings"
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert html.index("/static/perfwatch.js") < html.index("/static/perfview.js")
    for f in ("perfwatch.js", "perfview.js"):
        assert subprocess.run(["node", "-e", f"new Function(require('fs').readFileSync('{ROOT / 'app/static' / f}','utf8'))"]).returncode == 0
    js = (ROOT / "app/static/perfview.js").read_text(encoding="utf-8")
    assert "pf-band" in js and '"s3d"' in js and "AIOPS_PW" in js


def test_qa_validation_hysteresis_scope_restore(tmp_path, monkeypatch):
    from app.perfwatch import validate_rule
    for bad in ({"name_re": "(a+)+$"}, {"name_re": "(x*)*"}, {"name_re": r"(a)\\1"}, {"name_re": "a" * 101}):
        with pytest.raises(ValueError):
            validate_rule({"kind": "vm", "metric": "cpu", "type": "anomaly", **bad})
    with pytest.raises(ValueError):
        validate_rule({"kind": "vm", "metric": "cpu", "type": "threshold", "warn": "nan"})
    with pytest.raises(ValueError):
        validate_rule({"kind": "vm", "metric": "cpu", "type": "threshold", "warn": 80, "window": 360})
    assert validate_rule({"kind": "host", "metric": "cpu", "type": "outlier"})["direction"] == "above"
    M, pv, pw, ev = _pw(tmp_path, monkeypatch)

    async def go():
        await pw.sample()
        S = pw.store
        now = int(time.time() // 300 * 300)
        vm = next(e for e, v in S.ents.items() if v["kind"] == "vm")
        name = S.ents[vm]["name"]
        for r in list(pw.rules):
            pw.delete_rule(r)
        pw.save_rule({"id": "t", "kind": "vm", "metric": "cpu", "type": "threshold", "warn": 80, "window": 15}, "t")

        def feed(t0, v):
            for i in range(3):
                S.put(t0 + i * 300, [(e, {"cpu": v if e == vm else 10.0, "mem": 50.0, "rdy": 1.0, "iops": 1.0, "lat": 1.0, "dbps": 1.0, "nbps": 1.0}) for e in S.ents])
        feed(now - 600, 90.0)
        await pw.evaluate()
        assert ("t", name) in {(a["rule"], a["name"]) for a in pw.alerts_now()}
        feed(now + 300, 78.0)                                                 # 경계 5% 안 → 유지(히스테리시스)
        monkeypatch.setattr(time, "time", lambda: now + 1000)
        await pw.evaluate()
        assert ("t", name) in {(a["rule"], a["name"]) for a in pw.alerts_now()}
        await pw.flush()
        pw2 = PW2(M, pv, tmp_path)                                            # 재시작 → 진행 중 경보 복원
        assert ("t", name) in {(a["rule"], a["name"]) for a in pw2.alerts_now()}
        pw.save_rule({"id": "t", "kind": "vm", "metric": "cpu", "type": "threshold", "warn": 80, "window": 15, "name_re": "^zzz-none$"}, "t")
        await pw.evaluate()                                                   # 범위를 좁히면 바로 해제
        assert not pw.alerts_now()
        fresh = S.latest()
        assert all(v["ts"] >= time.time() - S.interval * 3 for v in fresh.values())
        assert S.latest(max_age=0) == {} or all(v["ts"] >= time.time() for v in S.latest(max_age=0).values())
    asyncio.run(go())


def PW2(M, pv, tmp_path):
    from app.perfwatch import PerfWatch
    return PerfWatch(M.ENGINE, pv, {"db_path": str(tmp_path / "perf.db")}, str(tmp_path))
