"""런타임 안정성 단위 테스트 — `python -m pytest -q tests` (외부 서비스 불필요)"""
import asyncio
import os
import sqlite3
import tempfile
import time

import pytest

from app.detect import DEFAULT_RULES, Detector, literal_gate
from app.models import LogEvent
from app.realtime import Hub
from app.runtime import Breaker, MinuteCounter, Supervisor
from app.store import Store


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- 감독자: 비정상 종료 → 재기동, 정체 감지
def test_supervisor_restarts_crashed_job():
    async def main():
        sup = Supervisor()
        calls = {"n": 0}

        async def job():
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("boom")
            await asyncio.sleep(10)
        sup.spawn("j", job)
        for _ in range(60):               # 1초 + 2초 백오프(+지터) 후 3번째 실행 — 부하가 있으면 늦을 수 있어 최대 6초 기다림
            await asyncio.sleep(0.1)
            if calls["n"] >= 3 and {j["name"]: j for j in sup.summary()}["j"]["state"] == "running":
                break
        s = {j["name"]: j for j in sup.summary()}["j"]
        await sup.stop()
        return calls["n"], s
    n, s = run(main())
    assert n == 3 and s["restarts"] == 2 and s["state"] == "running"


def test_supervisor_detects_stall():
    async def main():
        sup = Supervisor()

        async def job():
            await asyncio.sleep(10)       # beat() 없음
        sup.spawn("quiet", job, heartbeat=0.2)
        await asyncio.sleep(0.8)
        bad = sup.unhealthy()
        await sup.stop()
        return bad
    assert run(main()) == ["quiet"]


# ---------------------------------------------------------------- 서킷 브레이커
def test_breaker_opens_and_half_opens():
    b = Breaker("x", threshold=2, reset=0.2)
    b.fail("e1")
    assert b.allow()
    b.fail("e2")
    assert b.state == "open" and not b.allow()
    time.sleep(0.25)
    assert b.allow() and b.state == "half_open"
    b.fail("e3")
    assert b.state == "open"
    time.sleep(0.25)
    assert b.allow()
    b.ok()
    assert b.state == "closed"


# ---------------------------------------------------------------- 분당 카운터
def test_minute_counter_rolls():
    m = MinuteCounter(60)
    m.add("esxi", "syslog", 5)
    m.minute -= 2                          # 2분 경과 흉내
    m.data[("esxi", "syslog")][-1] = 5
    series, sy5 = m.series({"esxi"})
    assert series[-3] == 5 and series[-1] == 0 and sy5 == 5


# ---------------------------------------------------------------- 규칙 사전 필터(필수 키워드)의 건전성
def test_literal_gate_examples():
    assert set(literal_gate(r"(All Paths Down|\bAPD\b|lost access to volume)")) == {"all paths down", "apd", "lost access to volume"}
    assert literal_gate(r"(a|bc)?x") == ()                 # 필수 리터럴 없음 → 필터 없음(항상 정규식 실행)
    assert all(r.gate for r in DEFAULT_RULES)


def test_literal_gate_sound_on_rule_matches():
    hyp = pytest.importorskip("hypothesis")
    from hypothesis import HealthCheck, given, settings, strategies as st
    for r in DEFAULT_RULES:
        @settings(max_examples=60, suppress_health_check=list(HealthCheck), deadline=None, database=None)
        @given(st.from_regex(r.pattern))
        def check(s):
            low = s.lower()
            assert any(k in low for k in r.gate), (r.name, s)
        check()
    assert hyp


def test_detector_same_result_with_gate():
    d = Detector({"warmup_seconds": 0})
    ev = LogEvent(source="esxi", connector="syslog", message="vmkernel: NMP lost access to volume ds01 following connectivity issues")
    score, cat, sev = d.evaluate(ev)
    assert sev == "critical" and any("apd_pdl" in r for r in ev.reasons)


# ---------------------------------------------------------------- 실시간 허브: 느린 클라이언트 격리
class FakeWS:
    def __init__(self, block=False):
        self.block, self.sent, self.closed = block, [], None
        self.client = None

    async def send_text(self, t):
        if self.block:
            await asyncio.sleep(3600)
        self.sent.append(t)

    async def close(self, code=1000, reason=""):
        self.closed = code


def test_hub_isolates_slow_client():
    async def main():
        hub = Hub({"ws_queue": 20, "ws_send_timeout": 30})
        fast, slow = FakeWS(), FakeWS(block=True)
        hub.add(fast, {"user": "a"}, lambda seq: '{"type":"snapshot"}')
        hub.add(slow, {"user": "b"}, lambda seq: '{"type":"snapshot"}')
        await asyncio.sleep(0.01)
        for i in range(30):
            hub.publish({"type": "logs", "data": [i]})       # 흐름 메시지: 절반 이상 차면 버림
        for i in range(30):
            hub.publish({"type": "anomaly", "data": {"i": i}})  # 상태 메시지: 가득 차면 그 클라이언트만 끊음
            await asyncio.sleep(0)
        await asyncio.sleep(0.05)
        return hub, fast, slow
    hub, fast, slow = run(main())
    assert slow.closed == 1013 and hub.stats["kicked_slow"] == 1
    assert fast.closed is None and sum('"anomaly"' in t for t in fast.sent) == 30
    seqs = [int(t.split('"seq": ')[1].split("}")[0].split(",")[0]) for t in fast.sent if '"anomaly"' in t]
    assert seqs == list(range(seqs[0], seqs[0] + 30))         # 상태 메시지 순번 연속


# ---------------------------------------------------------------- 저장소: 쓰기 실패 시 배치 보존·재시도
def test_store_retries_when_locked():
    async def main():
        d = tempfile.mkdtemp()
        path = os.path.join(d, "t.db")
        st = Store(path, 7, {"min_free_mb": 0})
        st._conn.execute("PRAGMA busy_timeout=100")
        locker = sqlite3.connect(path, timeout=1)
        locker.execute("BEGIN EXCLUSIVE")
        for i in range(10):
            st.put_log({"id": i, "ts": time.time(), "source": "esxi", "connector": "t", "severity": "info", "host": "h",
                        "entity": "", "kind": "log", "message": f"m{i}", "score": 0, "template": "", "attrs": {}})
        ok1 = await st._flush_once()               # 잠김 → 실패, 버퍼 보존
        backlog_after_fail = st.backlog
        locker.rollback()
        locker.close()
        ok2 = await st._flush_once()
        n = (await st.q("SELECT COUNT(*) n FROM logs"))[0]["n"]
        return ok1, backlog_after_fail, ok2, n, st.stats["write_errors"]
    ok1, bl, ok2, n, errs = run(main())
    assert not ok1 and bl == 10 and ok2 and n == 10 and errs == 1


# ---------------------------------------------------------------- 엔진: 우선 큐가 먼저 처리
def test_engine_priority_order(tmp_path, monkeypatch):
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False},
                            "rag": {"enabled": False}, "pipeline": {"classify_backlog": 0}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        order = []
        e._process = lambda ev: order.append(ev.message)
        for i in range(5):
            e.submit(LogEvent(source="esxi", connector="syslog", message=f"info {i}", severity="info"))
        e.submit(LogEvent(source="esxi", connector="syslog", message="vmkernel: lost access to volume ds1", severity="info"))
        e.submit(LogEvent(source="esxi", connector="syslog", message="crit", severity="critical"))
        t = asyncio.create_task(e.pipeline_worker())
        await asyncio.sleep(0.05)
        t.cancel()
        return order
    order = run(main())
    assert order[:2] == ["vmkernel: lost access to volume ds1", "crit"] and len(order) == 7
