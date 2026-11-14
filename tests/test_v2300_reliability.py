"""2.30.0 안정성·성능 — 조회 상한·백그라운드 인덱스·전용 연결 백업·SQL 집계(적정화·정산)·vCenter 무거운 수집 분리·
스텁 잠금 대기 상한·호스트 분석 캐시·무응답 감시 호스트 목록·NSX 백업 판정·성능 이력 엔티티 정리·발송함 보존"""
import asyncio
import json
import random
import sqlite3
import textwrap
import threading
import time
from types import SimpleNamespace as NS

import pytest

from app.store import QueryTimeout, Store


def _store(tmp_path, cfg=None, name="a.db"):
    return Store(str(tmp_path / name), 7, cfg or {})


def _logs(st, rows):
    """rows = [(ts, source, connector, severity, host, message, attrs)]"""
    st._conn.executemany("INSERT INTO logs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                         [(i, r[0], r[1], r[2], r[3], r[4], r[4], "log", r[5], 0, "", r[6] if len(r) > 6 else "{}") for i, r in enumerate(rows)])
    st._conn.commit()


class CountQ:
    """Store.q 호출을 세는 얇은 래퍼(캐시·단일 실행 검증)"""

    def __init__(self, st):
        self.st, self.sqls = st, []

    def __getattr__(self, k):
        return getattr(self.st, k)

    async def q(self, sql, params=(), **kw):
        self.sqls.append(" ".join(sql.split()))
        await asyncio.sleep(0.02)                       # 동시 요청이 겹치도록
        return await self.st.q(sql, params, **kw)


# ---------------------------------------------------------------- 8. 조회 상한 · /api/logs 범위 상한
def test_query_deadline_interrupts_and_recovers(tmp_path, capsys):
    st = _store(tmp_path, {"query_timeout_s": 0.3})
    _logs(st, [(time.time(), "esxi", "syslog", "info", "h1", "m")])
    slow = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 500000000) SELECT COUNT(*) AS n FROM c"

    async def main():
        t0 = time.time()
        with pytest.raises(QueryTimeout) as ei:
            await st.q(slow)
        assert time.time() - t0 < 3 and ei.value.status_code == 504 and isinstance(ei.value, TimeoutError) and "0.3" in str(ei.value)
        assert (await st.q("SELECT COUNT(*) AS n FROM logs"))[0]["n"] == 1          # 중단 뒤 다음 조회는 정상(읽기 연결 재사용)
        assert st.timeout_count == 1 and st.slow_count == 1 and st.status()["query_timeouts"] == 1
        with pytest.raises(QueryTimeout):                                            # 호출별 상한
            await st.q(slow, timeout=0.1)
        for _ in range(30):                                                          # 타이머가 끝난 조회 뒤 늦게 울려 다음 조회를 끊지 않는다
            assert (await st.q("SELECT COUNT(*) AS n FROM logs", timeout=0.05))[0]["n"] == 1
        assert (await st.q("SELECT 1 AS a", timeout=0))[0]["a"] == 1                 # 0 = 제한 없음
    asyncio.run(main())
    assert "상한 초과" in capsys.readouterr().out                                     # 느린 조회 로그에 원인 쿼리 기록


def test_api_logs_minutes_capped(monkeypatch):
    import app.main as M
    got = {}

    async def fake(since, until, *a, **k):
        got["span"] = until - since
        return []
    monkeypatch.setattr(M.ENGINE.store, "query_logs", fake)
    asyncio.run(M.logs(minutes=10 ** 9))
    assert abs(got["span"] - 10080 * 60) < 1
    asyncio.run(M.logs(minutes=30))
    assert abs(got["span"] - 1800) < 1


# ---------------------------------------------------------------- 1. 부분 인덱스(기동 후 백그라운드) · NOC 주요 이벤트 캐시
def test_late_partial_index_built_in_background(tmp_path):
    st = _store(tmp_path, {"late_index_delay_s": 0.05})
    now = time.time()
    _logs(st, [(now - i, "nsx", "syslog", "warning" if i % 50 == 0 else "info", "h", "m") for i in range(3000)])
    have = lambda: {r[0] for r in st._rconn.execute("SELECT name FROM sqlite_master WHERE type='index'")}   # noqa: E731
    assert "ix_logs_sevhi" not in have()                                              # 스키마 생성(기동 경로)에서는 만들지 않음

    async def main():
        beats = []
        w = asyncio.create_task(st.writer(lambda: beats.append(1)))
        st.put_log({"id": 9, "ts": now, "source": "nsx", "connector": "c", "severity": "error", "host": "h", "entity": "", "kind": "log",
                    "message": "x", "score": 0, "template": ""})
        for _ in range(100):
            await asyncio.sleep(0.05)
            if st.late_index["state"] == "ok" and not st.backlog:
                break
        assert st.late_index["state"] == "ok" and st.late_index["created"] == ["ix_logs_sevhi"] and beats
        assert st.stats["logs_written"] == 1                                          # 인덱스 생성 뒤 버퍼가 이어서 기록됨
        assert await st.ensure_late_indexes() == []                                   # 이미 있으면 다시 만들지 않음
        w.cancel()
        await asyncio.gather(w, return_exceptions=True)
    asyncio.run(main())
    plan = st._rconn.execute("EXPLAIN QUERY PLAN SELECT ts FROM logs WHERE source=? AND ts>? AND severity IN ('warning','error','critical') "
                             "ORDER BY ts DESC LIMIT 60", ("nsx", 0)).fetchall()
    assert "ix_logs_sevhi" in str(plan)
    from app.models import SEVERITIES
    assert {"warning", "error", "critical"} <= set(SEVERITIES)                         # 인덱스 조건의 심각도 문자열 = 저장 값


def test_noc_important_cache_single_flight(tmp_path, monkeypatch):
    from app import noc
    st = _store(tmp_path)
    now = time.time()
    _logs(st, [(now - 60, "nsx", "syslog", "error", "edge01", "BGP down"), (now - 50, "nsx", "syslog", "info", "edge01", "ok"),
               (now - 40, "nsx-edge", "syslog", "critical", "edge02", "BFD down")])
    E = NS(store=CountQ(st))

    async def main():
        res = await asyncio.gather(*[noc._important(E, {"nsx", "nsx-edge"}) for _ in range(6)])
        assert all(r is res[0] for r in res) and [r["message"] for r in res[0]] == ["BFD down", "BGP down"]
        assert len(E.store.sqls) == 2                                                 # 소스 2개 × 1회(동시 6건이 1회 조회)
        await noc._important(E, {"nsx", "nsx-edge"})
        assert len(E.store.sqls) == 2                                                 # TTL 안에서는 캐시
        await noc._important(E, {"nsx"})                                              # 다른 도메인(소스 묶음)은 별도 키
        assert len(E.store.sqls) == 3
        monkeypatch.setattr(noc, "IMPORTANT_TTL", 0.0)
        await noc._important(E, {"nsx"})
        assert len(E.store.sqls) == 4
    asyncio.run(main())


# ---------------------------------------------------------------- 7. 백업 — 전용 읽기 연결(읽기 잠금 미사용)·여유 공간 확인·실패 정리
def test_backup_uses_own_connection_and_fails_cleanly(tmp_path):
    st = _store(tmp_path)
    _logs(st, [(time.time() - i, "esxi", "syslog", "info", "h", "m" * 200) for i in range(20000)])
    dest = tmp_path / "bk" / "x.db"

    async def main():
        stop = False

        async def writes():
            while not stop:
                await st.x("INSERT INTO alerts VALUES(1,'a','b',1,'d')")
                await asyncio.sleep(0.005)
        w = asyncio.create_task(writes())
        async with st._rlock:                                                         # 화면 조회가 읽기 잠금을 쥐고 있어도 백업은 진행
            size = await asyncio.wait_for(st.backup(str(dest)), 30)
        stop = True
        await w
        assert size > 0 and dest.exists() and not (tmp_path / "bk" / "x.db.part").exists()
        c = sqlite3.connect(str(dest))
        assert c.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 20000 and c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        c.close()
        st.min_free_mb = 10 ** 9                                                      # 여유 공간 부족 → 시작하지 않음
        with pytest.raises(OSError, match="여유 부족"):
            await st.backup(str(tmp_path / "bk" / "y.db"))
        assert not (tmp_path / "bk" / "y.db").exists() and not (tmp_path / "bk" / "y.db.part").exists()
        st.min_free_mb = 0
        (tmp_path / "blk").write_text("x")                                            # 쓸 수 없는 경로 → 오류, 찌꺼기 없음
        with pytest.raises(Exception):
            await st.backup(str(tmp_path / "blk" / "z.db"))
        assert st._backup_busy is False and (await st.q("SELECT COUNT(*) AS n FROM logs"))[0]["n"] == 20000
    asyncio.run(main())


# ---------------------------------------------------------------- 2. bill_usage — SQL 집계(적정화·정산 보고서) = 예전 행 단위 계산
def _usage(st, now):
    from app import billing
    st.schema(billing.SCHEMA)
    rnd = random.Random(7)
    h0 = int(now // 3600) * 3600 - 10 * 86400
    rows = []
    for i in range(40):
        vc, vm = ("vc1" if i % 3 else "vc2"), f"vm{i:02d}"
        vcpu, mem, disk = rnd.choice([2, 4, 8, 16]), rnd.choice([4, 8, 16, 64]), rnd.choice([40, 100, 500])
        mode = i % 8                                # 0 = 계속 꺼짐, 1 = 유휴, 2 = 과소, 3 = 중간에 클러스터 이동, 4 = 마지막에 꺼짐, 5 = 관측 짧음, 6 = 과다, 7 = 일반
        if mode == 6:
            vcpu, mem = max(vcpu, 8), max(mem, 16)
        for k in range(240 if mode != 5 else 10):
            hour = h0 + k * 3600
            if mode == 3 and k % 7 == 0:
                continue                             # 표본 빠진 시각
            on = not (mode == 0 or (mode == 4 and k >= 200) or (mode >= 6 and k % 11 == 0))
            blocks = rnd.choice([12, 12, 12, 7]) if on else 0
            cu = {1: 0.01, 2: 0.95, 6: 0.12}.get(mode, rnd.uniform(0.05, 0.6))
            mu = {1: 0.05, 2: 0.97, 6: 0.2}.get(mode, rnd.uniform(0.1, 0.7))
            cluster = "CL-B" if (mode == 3 and k >= 120) else ("CL-A" if i % 2 else "CL-C")
            folder = "/dc/prod" if i % 4 else "/dc/dev/team1"
            tags = json.dumps(["env:prod"] if i % 5 == 0 else ([] if i % 5 else ["env:dev"]))
            if mode == 3 and k >= 180:
                tags = json.dumps(["env:prod", "tier:db"])
            rows.append((hour, vc, vm, f"vm-{i}", cluster, folder, tags, 12, blocks, round(vcpu * blocks, 3), round(mem * blocks, 3), round(disk * blocks, 3),
                         round(vcpu * blocks * cu * rnd.uniform(0.9 if mode == 2 else 0.5, 1.0), 4), round(mem * blocks * mu * rnd.uniform(0.95 if mode == 2 else 0.6, 1.0), 4),
                         0.0 if on else float(disk * 12)))
    st._conn.executemany("INSERT INTO bill_usage(hour,vc,vm,moid,cluster,folder,tags,seen,blocks,vcpu,mem,disk,vcpu_u,mem_u,disk_off) "
                         "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    st._conn.commit()
    return h0, len(rows)


def _same(a, b, path=""):
    """구조·값 비교 — 실수는 합산 순서 차이(1e-6)만 허용"""
    if isinstance(a, float) or isinstance(b, float):
        assert a is not None and b is not None and a == pytest.approx(b, rel=1e-9, abs=1e-6), f"{path}: {a} != {b}"
    elif isinstance(a, dict):
        assert isinstance(b, dict) and set(a) == set(b), f"{path}: keys {set(a) ^ set(b)}"
        for k in a:
            _same(a[k], b[k], f"{path}.{k}")
    elif isinstance(a, (list, tuple)):
        assert len(a) == len(b), f"{path}: len {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            _same(x, y, f"{path}[{i}]")
    else:
        assert a == b, f"{path}: {a!r} != {b!r}"


def _strip(d):
    return {k: v for k, v in d.items() if k not in ("generated", "sampler")}


def test_rightsizing_sql_equals_rowwise_and_single_flight(tmp_path):
    from app import billing, capacity
    st = _store(tmp_path)
    now = time.time()
    _usage(st, now)
    cq = CountQ(st)
    live = NS(type="vcenter", name="vc1", topology={"vms": {"vm01": {"vcpu": 8, "mem_mb": 32768, "prov_gb": 200, "os": "linux", "power": "poweredOn"},
                                                            "vm08": {"vcpu": 2, "mem_mb": 4096, "prov_gb": 40, "power": "poweredOff"}}})
    E = NS(store=cq, connectors=[live])
    E.billing = billing.Billing(E, {})
    cap = capacity.Capacity(E, {})
    ns = dict(vars(capacity))
    exec(textwrap.dedent(OLD_RIGHTSIZING), ns)                                        # 2.29.0 구현(행 단위) — 비교 기준

    async def main():
        await E.billing.save_rate({"name": "기본", "vcpu_hour": 10, "mem_gb_hour": 3, "disk_gb_hour": 0.1, "is_default": True}, "t")
        for days in (3, 14):
            old = await ns["rightsizing"](cap, days)
            cap._cache.clear()
            new = await cap.rightsizing(days)
            _same(_strip(old), _strip(new))
            assert new is not old
        assert all(new[k] for k in ("oversized", "undersized", "idle", "powered_off")), {k: len(new[k]) for k in ("oversized", "undersized", "idle", "powered_off")}
        cap._cache.clear()
        cq.sqls.clear()
        res = await asyncio.gather(*[cap.rightsizing(14) for _ in range(8)])
        assert all(r is res[0] for r in res)
        assert sum(1 for s in cq.sqls if "FROM bill_usage" in s) == 1                 # 동시 8건 → 집계 1회
        raw = await st.q(capacity.Capacity.RS_SQL, (now - 14 * 86400,))
        assert len(raw) == 40                                                         # VM 수만큼의 행(표본 9천여 행을 올리지 않음)
    asyncio.run(main())


def test_billing_report_sql_equals_rowwise(tmp_path):
    from app import billing
    st = _store(tmp_path)
    now = time.time()
    h0, n = _usage(st, now)
    E = NS(store=st, connectors=[])
    B = billing.Billing(E, {})
    ns = dict(vars(billing))
    exec(textwrap.dedent(OLD_REPORT), ns)                                             # 2.29.0 구현(SELECT * 행 단위) — 비교 기준

    async def main():
        r1 = await B.save_rate({"name": "기본", "vcpu_hour": 10, "mem_gb_hour": 3, "disk_gb_hour": 0.1, "is_default": True, "weighting": True,
                                "min_weight": 30, "disk_when_off": True}, "t")
        await B.save_rate({"name": "기본", "vcpu_hour": 12.5, "mem_gb_hour": 3.3, "disk_gb_hour": 0.12, "weighting": True, "min_weight": 40,
                           "disk_when_off": False, "effective_from": h0 + 100 * 3600 + 1800}, "t", r1)          # 기간 중 요율 개정(시각 중간)
        r2 = await B.save_rate({"name": "개발", "vcpu_hour": 4, "mem_gb_hour": 1, "disk_gb_hour": 0.05, "effective_from": h0 + 50 * 3600}, "t")
        t1 = await B.save_tenant({"name": "금융IT"})
        t2 = await B.save_tenant({"name": "개발본부", "rate_id": r2})
        await B.save_project({"tenant_id": t1, "name": "코어", "clusters": ["CL-A"]})
        await B.save_project({"tenant_id": t1, "name": "DB", "tags": ["tier:db"]})
        await B.save_project({"tenant_id": t2, "name": "dev", "folders": ["/dc/dev"]})
        await B.save_project({"tenant_id": t2, "name": "pin", "vms": ["vm07"], "rate_id": r1})
        for a, b in ((h0, h0 + 240 * 3600), (h0 + 30 * 3600 + 600, h0 + 130 * 3600), (h0 + 220 * 3600, h0 + 400 * 3600), (h0 - 86400, h0)):
            for ids in (None, {t1}, {t2}, {999}):
                for detail in (True, False):
                    old = await ns["report"](B, a, b, "기간", ids, detail)
                    new = await B.report(a, b, "기간", ids, detail)
                    _same(_strip(old), _strip(new), f"[{a - h0},{b - h0},{ids},{detail}]")
        full = await B.report(h0, h0 + 240 * 3600, "기간")
        assert full["totals"]["cost"] and full["totals"]["unassigned_vms"] and full["coverage"]["hours_with_data"] == 240
        assert any(v["matched_by"] for t in full["tenants"] for p in t["projects"] for v in p["vm_rows"])
    asyncio.run(main())
    seen = []
    orig = st.q

    async def spy(sql, params=(), **kw):
        rows = await orig(sql, params, **kw)
        if "bill_usage" in sql:
            seen.append(len(rows))
        return rows
    st.q = spy
    asyncio.run(B.report(h0, h0 + 240 * 3600, "기간"))
    assert seen and max(seen) < n / 10                                                # 표본 전체가 아니라 묶음(VM·속성·요율 구간) 단위만 올라옴


# ---------------------------------------------------------------- 3·4. vCenter — 폴링(이벤트)과 무거운 수집 분리 · 전용 풀 · 잠금 대기 상한
def _vc(emit, **cfg):
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc", "host": "vc.lab", "username": "u", "password": "p", "interval": 0.1, "poll_timeout": 0.5, "heavy_retry": 0.2,
                          "health": {"enabled": False}, **cfg}, emit)
    n = {"k": 0}

    async def login():
        return None

    def read_events():
        n["k"] += 1
        return [{"key": n["k"], "ts": time.time(), "sev": "info", "kind": "event", "msg": f"e{n['k']}", "entity": "", "host": "", "type": "X", "user": ""}]
    c.login, c._read_events = login, read_events
    return c


def test_slow_heavy_collector_does_not_block_or_lose_events():
    got, names, sli_calls = [], [], []

    async def emit(e):
        got.append(e.message)
    c = _vc(emit)

    def slow_topology():                                   # 폴링 상한(0.5초)보다 오래 걸리는 토폴로지 갱신
        names.append(threading.current_thread().name)
        time.sleep(1.2)
        c.topology = {"hosts": {}, "vms": {}, "datastores": {}, "clusters": {}, "updated": time.time()}
        return c.topology

    def sli():
        sli_calls.append(time.time())
        if len(sli_calls) == 1:
            raise RuntimeError("일시 오류")
        return {"updated": time.time(), "vms": {}, "clusters": {}, "error": ""}
    c._refresh_topology, c._collect_sli = slow_topology, sli
    c._sli_events = lambda res, first: [c.ev("sli-ev", severity="warning", kind="health")]

    async def main():
        t = asyncio.create_task(c.run())
        await asyncio.sleep(0.7)
        assert c._bg_busy("topology") and not c.topology["updated"] and c._last_topo == 0.0     # 아직 도는 중 — 성공 전에는 시각을 찍지 않음
        assert len([m for m in got if m.startswith("e")]) >= 3 and c._state["polls"] >= 3      # 그동안에도 이벤트는 계속 전달
        assert c._state["timeouts"] == 0 and c._state["state"] == "ok"
        for _ in range(100):
            await asyncio.sleep(0.05)
            if "sli-ev" in got:
                break
        assert c.topology["updated"] and c._last_topo > 0                                       # 무거운 결과가 결국 반영
        assert "sli-ev" in got and c.sli["updated"] and not c.sli["error"]                      # 백그라운드 수집이 만든 이벤트도 같은 emit 경로로
        assert len(sli_calls) == 2 and 0.15 <= sli_calls[1] - sli_calls[0] < 5                  # 실패 → 주기(300초)가 아니라 heavy_retry 뒤 재시도
        assert c._last_sli >= sli_calls[1] and names and names[0].startswith("conn-vc")         # 전용 스레드 풀
        assert [m for m in got if m.startswith("e")] == [f"e{i}" for i in range(1, len([m for m in got if m.startswith('e')]) + 1)]   # 빠짐·중복 없음
        assert c._state["collectors"]["topology"]["last_ok"] and c._state["events_total"] == len(got)
        n_topo = len(names)
        await asyncio.sleep(0.4)
        assert len(names) == n_topo                                                             # 주기(300초) 전에는 다시 돌지 않음
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
        assert c._bg == {} and c._pool_obj is None
    asyncio.run(main())


def test_stop_cancels_heavy_tasks_and_inflight_guard():
    async def emit(e):
        return None
    c = _vc(emit)
    started = []

    def slow_topology():
        started.append(1)
        time.sleep(0.8)
        return {}
    c._refresh_topology = slow_topology

    async def main():
        t = asyncio.create_task(c.run())
        await asyncio.sleep(0.45)
        task = c._bg["topology"]
        assert not task.done() and len(started) == 1 and c._state["polls"] >= 2                 # 여러 번 폴링해도 겹쳐 시작하지 않음
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
        await asyncio.sleep(0)
        assert task.cancelled() or task.done()
        assert c._last_topo != 0.0 and time.time() - c._last_topo > 200                         # 중단 = 실패 처리(성공 시각 아님, 곧 재시도 대상)
        await asyncio.sleep(0.6)                                                                # 스레드가 끝나며 진행 표시 해제
        assert not c._thr_busy
    asyncio.run(main())


def test_poll_cancel_does_not_advance_since_or_seen():
    async def emit(e):
        return None
    c = _vc(emit, poll_timeout=60)
    c._kick_heavy = lambda: None
    rows = [{"key": 101, "ts": time.time(), "sev": "error", "kind": "event", "msg": "host down", "entity": "", "host": "esx1", "type": "X", "user": ""}]
    c._read_events = lambda: list(rows)
    c.rest_token = "t"
    hang = {"on": True}

    async def peek():
        if hang["on"]:
            await asyncio.sleep(30)
        if "health:mem:red" in c.seen:
            return [], []
        return [c.ev("vCenter 어플라이언스 헬스 mem = red", severity="critical", kind="health")], ["health:mem:red"]
    c._appliance_health_peek = peek

    async def main():
        since = c.since
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(c.poll(), 0.2)                                               # 이벤트를 읽은 뒤 도중 취소(폴링 시간 초과)
        assert c.since == since and "101" not in c.seen and "health:mem:red" not in c.seen
        hang["on"] = False
        ev = await c.poll()
        assert [e.message for e in ev] == ["host down", "vCenter 어플라이언스 헬스 mem = red"]      # 다음 주기에 그대로 다시 전달
        assert c.since == rows[0]["ts"] and "101" in c.seen
        assert await c.poll() == []                                                             # 돌려준 뒤에는 중복 없음
    asyncio.run(main())


def test_stub_lock_bounded_wait_connect_timeout_and_iops_batches(monkeypatch):
    from app.connectors import vcenter as V
    lk = V.StubLock(0.2, "vc")
    held, release = threading.Event(), threading.Event()

    def holder():
        with lk:
            with lk:                                       # 재진입
                held.set()
                release.wait(5)
    th = threading.Thread(target=holder)
    th.start()
    held.wait(2)
    t0 = time.time()
    with pytest.raises(V.VCenterBusy, match="응답 대기"):    # 화면 요청 스레드 — 무한 대기 대신 상한 뒤 명확한 오류
        with lk:
            pass
    assert 0.15 < time.time() - t0 < 2
    with pytest.raises(V.VCenterBusy):
        with lk.hold(0.05):
            pass
    lk.set_wait(3)                                         # 백그라운드 수집 스레드 — 길게 기다림
    threading.Timer(0.3, release.set).start()
    with lk:
        pass
    th.join()
    lk.set_wait(None)

    # SmartConnect — 소켓 상한 전달, 재연결 시 이전 세션 반납
    calls, closed = [], []
    monkeypatch.setattr(V, "SmartConnect", lambda **kw: calls.append(kw) or NS(n=len(calls)))
    monkeypatch.setattr(V, "Disconnect", lambda si: closed.append(si.n))

    async def emit(e):
        return None
    c = V.VCenterConnector({"name": "vc", "host": "vc.lab:8443", "username": "u", "password": "p", "soap_timeout": 77}, emit)
    c._connect()
    c._connect()
    assert calls[0]["httpConnectionTimeout"] == 77 and calls[0]["port"] == 8443 and closed == [1] and c.si.n == 2
    assert isinstance(c._lock, V.StubLock) and c._lock.wait == 45

    # collect_vm_iops — 전체가 아니라 묶음마다 잠금
    class CountLock:
        n = 0

        def __enter__(self):
            CountLock.n += 1

        def __exit__(self, *a):
            return None
    ser = lambda cid, vals: NS(id=NS(counterId=cid), value=vals)   # noqa: E731

    class PM:
        perfCounter = [NS(groupInfo=NS(key="virtualDisk"), nameInfo=NS(key="numberReadAveraged"), rollupType="average", key=1)]

        def QueryPerf(self, querySpec):
            assert CountLock.n >= 2                              # 조회는 잠금 안에서
            return [NS(entity=qs.entity, value=[ser(1, [10, 20])]) for qs in querySpec]
    ents = {f"v{i}": NS(_moId=f"vm-{i}") for i in range(5)}
    f = V.VCenterConnector.__new__(V.VCenterConnector)
    f.name, f._lock = "vc", CountLock()
    f.topology = {"vms": {n: {"power": "poweredOn", "moid": o._moId} for n, o in ents.items()}}
    f._iops_env = lambda names: (PM(), {n: ents.get(n) for n in names})
    f._iops_spec = lambda ent, mids, interval, n: NS(entity=ent)
    res = f.collect_vm_iops(batch=2)
    assert len(res) == 5 and res["v0"] == {"min": 10.0, "max": 20.0, "sum": 30.0, "n": 2, "interval": 20}
    assert CountLock.n == 1 + 3                                  # 준비 1회 + 묶음 3회(5대 ÷ 2)


def test_connector_blocking_calls_use_dedicated_pool():
    import inspect
    from app.connectors import base, vcenter
    assert "asyncio.to_thread(" not in inspect.getsource(vcenter) and "asyncio.to_thread(" not in inspect.getsource(base)

    async def main():
        async def emit(e):
            return None
        c = base.Connector({"name": "x", "worker_threads": 2}, emit)
        assert (await c._t(lambda: threading.current_thread().name)).startswith("conn-x")
        gate = threading.Event()
        blocked = [c._t(gate.wait, 5) for _ in range(6)]                   # 커넥터 풀이 꽉 차도
        tasks = [asyncio.ensure_future(b) for b in blocked]
        await asyncio.sleep(0.05)
        assert await asyncio.wait_for(asyncio.to_thread(lambda: 7), 2) == 7   # 기본 실행기(저장소 읽기·쓰기)는 영향 없음
        gate.set()
        await asyncio.gather(*tasks)
        c._bg_cancel()
        assert c._pool_obj is None
    asyncio.run(main())


# ---------------------------------------------------------------- 5. 호스트 분석 목록 — 5분 캐시 · syslog 제외 · hostseen 보완
def test_hostdiag_list_cached_and_hostseen_overlay(tmp_path):
    from app.hostdiag.manager import HostDiag
    st = _store(tmp_path)
    now = time.time()
    ev = json.dumps({"eventType": "HostConnectionLostEvent"})
    _logs(st, [(now - 3600, "vcenter", "vc", "error", "esx01.lab", "Host esx01.lab is not responding", ev),
               (now - 1800, "vcenter", "syslog", "info", "vcsa", "vpxd: guest tools on esx02.lab not responding"),      # syslog 로 받은 vpxd 줄
               (now - 600, "esxi", "syslog", "info", "esx01.lab", "vmkernel: x"), (now - 500, "esxi", "syslog", "info", "esx01.lab", "vmkernel: y")])
    vc = NS(type="vcenter", name="vc", host_diag=lambda *a: {}, host_logs=[],
            topology={"hosts": {"esx01.lab": {"cluster": "CL", "conn": "connected"}, "esx02.lab": {"cluster": "CL", "conn": "connected"},
                                "esx03.lab": {"cluster": "CL", "conn": "connected"}}})
    E = NS(store=CountQ(st), connectors=[vc], hostseen={})
    M = HostDiag(E, {})

    async def main():
        a = await M.hosts(7)
        by = {r["name"]: r for r in a["items"]}
        assert by["esx01.lab"]["disconnects"] == 1 and by["esx02.lab"]["disconnects"] == 0       # vCenter 커넥터가 있으면 syslog 줄은 제외
        assert by["esx01.lab"]["syslog_24h"] == 2 and by["esx03.lab"]["syslog_24h"] == 0
        n = len(E.store.sqls)
        assert n == 2 and "connector != 'syslog'" in E.store.sqls[0]
        E.hostseen["esx03.lab"] = [{"esxi"}, 5, now]                                              # 막 syslog 를 보내기 시작한 호스트
        E.hostseen["esx02.lab"] = [{"vcenter"}, 9, now]                                           # vCenter 이벤트만 — syslog 아님
        res = await asyncio.gather(*[M.hosts(7) for _ in range(5)])
        by = {r["name"]: r for r in res[0]["items"]}
        assert len(E.store.sqls) == n                                                             # 캐시(5분) — DB 조회 없음
        assert by["esx03.lab"]["syslog_24h"] == 5 and by["esx03.lab"]["syslog_last"] == now and by["esx02.lab"]["syslog_24h"] == 0
        assert by["esx01.lab"]["syslog_24h"] == 2                                                 # DB 집계가 있으면 그 값(24시간 기준)
        M.list_ttl = 0
        await M.hosts(7)
        assert len(E.store.sqls) == n + 2
        E.connectors = []                                                                         # vCenter 커넥터가 없으면 syslog 줄도 본다
        await M.hosts(7)
        assert "connector != 'syslog'" not in E.store.sqls[-2]
    asyncio.run(main())


# ---------------------------------------------------------------- 6. 무응답 감시 — 호스트 목록은 메모리 집계(기동 후 1회만 DB)
def test_nodata_hosts_from_hostseen_not_db(tmp_path):
    from app.monitors import MonitorManager
    st = _store(tmp_path)
    now = time.time()
    _logs(st, [(now - 7200, "esxi", "syslog", "info", "old-esx", "재기동 전에 보내던 호스트"), (now - 7200, "nsx", "syslog", "info", "edge9", "x"),
               (now - 3 * 86400, "esxi", "syslog", "info", "gone-esx", "24시간 넘게 조용")])
    E = NS(store=CountQ(st), hostseen={"live-esx": [{"esxi"}, 3, now - 30], "stale-esx": [{"esxi"}, 3, now - 2 * 86400], "fw1": [{"fortigate"}, 1, now]},
           connectors=[])
    mm = MonitorManager.__new__(MonitorManager)
    mm.e = E
    m = {"type": "nodata", "window": 600, "query": {"sources": ["esxi"]}}

    async def main():
        v = await mm.values(m)
        assert set(v) == {"old-esx", "live-esx"} and all(x == 0.0 for x in v.values())            # DB 1회 적재분 + 메모리, 소스·24시간 조건 유지
        assert st._hosts_seeded is True
        n = len(E.store.sqls)
        for _ in range(5):
            v = await mm.values(m)
        assert len(E.store.sqls) == n + 5 and not any("DISTINCT host" in s for s in E.store.sqls)  # 평가마다 COUNT 1건뿐 — 24시간 DISTINCT 스캔 없음
        assert set(await mm.values({"type": "nodata", "window": 600, "query": {"host": "fw*"}})) == {"fw1"}
    asyncio.run(main())


# ---------------------------------------------------------------- 9. NSX 백업 판정 · 날짜 시간대 표기
def test_nsx_inventory_success_does_not_hide_cluster_failure():
    from app import protection as PR
    now = 1_800_000_000.0
    ms = lambda ago_h: (now - ago_h * 3600) * 1000   # noqa: E731
    cfg = {"backup_enabled": True, "backup_schedule": {"resource_type": "WeeklyBackupSchedule", "days_of_week": [1], "hour_of_day": 2, "minute_of_day": 0},
           "remote_file_server": {"server": "10.0.0.5", "directory_path": "/nsx"}}
    js = {"backup_config": cfg, "backup_operation_history": {
        "cluster_backup_statuses": [{"success": False, "end_time": ms(72), "error_message": "SFTP 인증 실패"}, {"success": True, "end_time": ms(240)}],
        "node_backup_statuses": [{"success": False, "end_time": ms(72)}, {"success": True, "end_time": ms(240)}],
        "inventory_backup_statuses": [{"success": True, "end_time": ms(0.05)}, {"success": True, "end_time": ms(0.1)}]}}
    p = PR.nsx_overview(js, now)
    assert p["last"]["status"] == "FAILED" and p["last"]["part"] in ("클러스터", "노드") and abs(p["last_success"] - (now - 240 * 3600)) < 1
    v, why = PR.appliance_verdict(p, now)
    assert v == "bad" and "실패" in why                                                           # 예전: 인벤토리 성공(3분 전) 때문에 ok
    assert p["inventory"]["status"] == "SUCCESS" and p["history"][0]["part"] == "인벤토리"          # 인벤토리는 참고 표시로 남음
    js["backup_operation_history"]["cluster_backup_statuses"].insert(0, {"success": True, "end_time": ms(1)})
    js["backup_operation_history"]["node_backup_statuses"].insert(0, {"success": True, "end_time": ms(1)})
    p = PR.nsx_overview(js, now)
    assert PR.appliance_verdict(p, now)[0] == "ok" and abs(p["last_success"] - (now - 3600)) < 1
    js["backup_operation_history"]["node_backup_statuses"] = [{"success": True, "end_time": ms(60)}]   # 한쪽만 오래됨 → 오래된 쪽 기준
    p = PR.nsx_overview(js, now)
    assert PR.appliance_verdict(p, now)[0] == "warn" and abs(p["last_success"] - (now - 60 * 3600)) < 1
    only_inv = PR.nsx_overview({"backup_config": cfg, "backup_operation_history": {"inventory_backup_statuses": [{"success": True, "end_time": ms(0.1)}]}}, now)
    assert only_inv["last_success"] is None and PR.appliance_verdict(only_inv, now)[0] == "warn"   # 인벤토리만으로는 '성공' 아님


def test_parse_when_honors_explicit_zone_suffix():
    from app import protection as PR
    utc = PR.parse_when("2026-11-09T23:10:00Z")
    off = 9 * 3600.0
    for s in ("2026-11-09 23:10:00 UTC", "2026-11-09 23:10:00Z", "2026-11-10 08:10:00 +09:00", "2026-11-10 08:10 +0900", "11/09/2026 11:10:00 PM GMT",
              "Last backup: 2026-11-09 18:10:00 -05:00 [Veeam]", "2026-11-10 08:10:00 UTC+09:00"):
        assert PR.parse_when(s, off) == utc, s
    for s in ("2026-11-10 08:10:00", "2026-11-10 08:10:00 [Veeam]", "2026-11-10 08:10:00 - job 12", "2026-11-10 08:10:00 Zerto", "2026-11-10 08:10:00 usual"):
        assert PR.parse_when(s, off) == utc, s                                                    # 표기가 없으면 예전처럼 로컬(tz_offset)


# ---------------------------------------------------------------- 10. 성능 이력 — 엔티티 정리 · id 일괄 확인
def test_perfstore_prunes_dead_entities_and_batches_ids(tmp_path, monkeypatch):
    from app.perfstore import METRICS, PerfStore
    S = PerfStore(str(tmp_path / "perf.db"), {"interval": 300})
    now = int(time.time()) // 300 * 300
    m = {k: 1.0 for k in METRICS}
    assert S.put_named(now, [("vm", "vc", f"clone-{i}", "CL", "esx1", m) for i in range(50)] + [("host", "vc", "esx1", "CL", "esx1", m)]) == 51
    assert len(S.ents) == 51 and S._x("SELECT COUNT(*) FROM s5")[0][0] == 51
    assert S.put_named(now + 300, [("vm", "vc", "clone-0", "CL2", "esx2", m)]) == 1 and len(S.ents) == 51      # 같은 엔티티는 재사용, 이동 반영
    assert S.ents[S.find("vm", "clone-0", "vc")]["host"] == "esx2"
    keep = {S.find("vm", "clone-0", "vc"), S.find("host", "esx1", "vc")}
    S._x(f"DELETE FROM s5 WHERE eid NOT IN ({','.join(str(i) for i in keep)})")                  # 인스턴트 클론 49대가 사라지고 표본도 보존 기간을 넘김
    for e in list(S.recent):
        if e not in keep:
            S.recent.pop(e)
    assert S.prune_entities() == 0                                                             # 방금 등록(하루 이내)은 건드리지 않음
    S._x("UPDATE ent SET last = last - 3 * 86400")
    S._last_prune = 0.0
    S.rollup()                                                                                 # 롤업 때 함께 정리
    assert len(S.ents) == 2 and len(S._ids) == 2 and S._x("SELECT COUNT(*) FROM ent")[0][0] == 2 and S.stats["pruned"] == 49
    assert S.find("vm", "clone-7", "vc") is None and S.find("vm", "clone-0", "vc") in keep
    new = S.eid("vm", "vc", "clone-7", "CL", "esx1")                                           # 다시 나타나면 새로 등록
    assert new not in keep and S.ents[new]["name"] == "clone-7"

    # perfwatch.sample — VM 마다 스레드를 넘기지 않고 저장 1회로
    from app import perfwatch
    hops = []
    real = asyncio.to_thread

    async def spy(fn, *a, **k):
        hops.append(getattr(fn, "__name__", "?"))
        return await real(fn, *a, **k)
    monkeypatch.setattr(perfwatch.asyncio, "to_thread", spy)
    vc = NS(name="vc", topology={"hosts": {"esx1": {"moid": "h1", "cluster": "CL"}},
                                 "vms": {f"vm{i}": {"moid": f"m{i}", "power": "poweredOn", "cluster": "CL", "host": "esx1"} for i in range(30)}},
            perf_latest=lambda kind, items, b, s: {n: {"cpu_pct": 5.0} for n, _m, _c in items}, perf_latest_errors=0)
    pw = perfwatch.PerfWatch.__new__(perfwatch.PerfWatch)
    pw.store, pw.pv = S, NS(vcenters=lambda: [vc])
    st = asyncio.run(pw.sample())
    assert st["count"] == 31 and hops.count("put_named") == 1 and "eid" not in hops and len(hops) == 3   # perf_latest 2(호스트·VM) + 저장 1


# ---------------------------------------------------------------- 11. 알림 발송함 보존 정리
def test_outbox_retention_purge(tmp_path):
    from app.alerting import Alerter
    st = _store(tmp_path)

    async def noop(*a, **k):
        return None
    al = Alerter({"outbox_keep_days": 14, "outbox_dead_keep_days": 90}, noop, noop)
    al.bind_store(st)
    now = time.time()
    d = 86400
    rows = [("sent", 20), ("sent", 1), ("skipped_standby", 15), ("skipped_standby", 13), ("dead", 30), ("dead", 100), ("pending", 200), ("retry", 200)]

    async def main():
        for state, age in rows:
            await st.x("INSERT INTO outbox(created,channel,ref,title,payload,state,attempts,next_at) VALUES(?,?,?,?,?,?,0,0)",
                       (now - age * d, "wh", "r", "t", "{}", state))
        assert await al.purge_outbox(now) == 3
        left = sorted((r["state"], round((now - r["created"]) / d)) for r in await st.q("SELECT state, created FROM outbox"))
        assert left == sorted([("sent", 1), ("skipped_standby", 13), ("dead", 30), ("pending", 200), ("retry", 200)])   # 미발송(대기·재시도)은 나이와 무관하게 유지
        assert await al.purge_outbox(now) == 0 and al.ob["purged"] == 3
        await st.x("INSERT INTO outbox(created,channel,ref,title,payload,state,attempts,next_at) VALUES(?,?,?,?,?,'sent',1,0)", (now - 30 * d, "nochan", "r", "t", "{}"))
        al._wake.set()
        await st.x("UPDATE outbox SET created=? WHERE state IN ('pending','retry')", (now,))
        t = asyncio.create_task(al.dispatcher())                                               # 발송 워커 루프가 주기적으로 정리
        for _ in range(60):
            await asyncio.sleep(0.05)
            if al.ob.get("purged") == 4:
                break
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
        assert al.ob["purged"] == 4
        await al.http.aclose()
    asyncio.run(main())


# ---------------------------------------------------------------- 비교 기준: 2.29.0 의 행 단위 구현(시험 전용 사본 — 앱에서는 제거됨)
OLD_RIGHTSIZING = r'''
    async def rightsizing(self, days: int | None = None) -> dict[str, Any]:
        days = days or self.rs_days
        key = f"rs:{days}"
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
        now = time.time()
        since = now - days * 86400
        try:
            self.e.billing._ensure()
            rows = await self.e.store.q("SELECT hour,vc,vm,cluster,folder,seen,blocks,vcpu,mem,disk,vcpu_u,mem_u FROM bill_usage WHERE hour>=?", (since,))
        except Exception:  # noqa: BLE001
            rows = []
        rate = None
        try:
            rates = await self.e.billing.rates()
            rate = next((r["current"] for r in rates if r["is_default"] and r.get("current")), (rates[0]["current"] if rates and rates[0].get("current") else None))
        except Exception:  # noqa: BLE001
            rate = None
        th = self.th
        agg: dict[tuple, dict] = {}
        for r in rows:
            a = agg.setdefault((r["vc"], r["vm"]), {"vc": r["vc"], "vm": r["vm"], "cluster": r["cluster"], "folder": r["folder"], "seen": 0, "blocks": 0,
                                                     "vcpu_bh": 0.0, "mem_bh": 0.0, "disk_bh": 0.0, "vcpu_u": 0.0, "mem_u": 0.0, "peak_cpu": 0.0, "peak_mem": 0.0,
                                                     "hours_on": 0, "last": 0, "first": r["hour"], "vcpu": 0.0, "mem": 0.0, "disk": 0.0})
            a["seen"] += r["seen"]
            a["blocks"] += r["blocks"]
            a["first"] = min(a["first"], r["hour"])
            a["vcpu_bh"] += r["vcpu"]
            a["mem_bh"] += r["mem"]
            a["disk_bh"] += r["disk"]
            a["vcpu_u"] += r["vcpu_u"]
            a["mem_u"] += r["mem_u"]
            if r["blocks"]:
                a["hours_on"] += 1
                a["peak_cpu"] = max(a["peak_cpu"], r["vcpu_u"] / r["vcpu"] * 100 if r["vcpu"] else 0)
                a["peak_mem"] = max(a["peak_mem"], r["mem_u"] / r["mem"] * 100 if r["mem"] else 0)
            if r["hour"] >= a["last"]:
                a["last"] = r["hour"]
                a["cluster"], a["folder"] = r["cluster"], r["folder"]
                if r["blocks"]:
                    a["vcpu"], a["mem"], a["disk"] = r["vcpu"] / r["blocks"], r["mem"] / r["blocks"], r["disk"] / r["blocks"]
        live = {}
        for c in self.e.connectors:
            if getattr(c, "type", "") == "vcenter":
                for vn, v in ((getattr(c, "topology", {}) or {}).get("vms", {}) or {}).items():
                    live[(c.name, vn)] = v
        over, under, idle, off = [], [], [], []
        judged: list[dict] = []
        pending = 0
        for k, a in agg.items():
            v = live.get(k, {})
            vcpu = float(v.get("vcpu") or a["vcpu"] or 0)
            mem = round(float(v.get("mem_mb") or 0) / 1024, 1) if v.get("mem_mb") else round(a["mem"], 1)
            disk = float(v.get("prov_gb") or a["disk"] or 0)
            base = {"vm": a["vm"], "vcenter": a["vc"], "cluster": a["cluster"], "folder": a["folder"], "vcpu": vcpu, "mem_gb": mem, "disk_gb": round(disk, 1),
                    "os": v.get("os", ""), "power": v.get("power", ""), "hours_on": a["hours_on"], "observed_days": round(a["seen"] * 5 / 60 / 24, 1)}
            if a["blocks"] == 0:
                span_days = (a["last"] - a["first"] + 3600) / 86400                 # 꺼진 채 관측된 기간(첫~마지막 표본)
                if span_days >= th["off_days"] and v.get("power", "poweredOff") != "poweredOn":
                    off.append({**base, "off_days": round(span_days, 1), "saving": round(disk * (rate or {}).get("disk_gb_hour", 0) * 730, 0) if rate else None,
                                "why": f"{span_days:.0f}일 동안 한 번도 켜지지 않음 — 디스크 {disk:g} GB 점유", "action": "보존 필요 여부 확인 후 삭제·아카이브",
                                "confidence": "high" if span_days >= 14 else "medium"})
                continue
            if a["hours_on"] < 24:
                pending += 1
                continue                                            # 하루 미만 관측은 판단 보류
            avg_cpu = a["vcpu_u"] / a["vcpu_bh"] * 100 if a["vcpu_bh"] else 0
            avg_mem = a["mem_u"] / a["mem_bh"] * 100 if a["mem_bh"] else 0
            od = base["observed_days"]
            m = {**base, "avg_cpu": round(avg_cpu, 1), "peak_cpu": round(a["peak_cpu"], 1), "avg_mem": round(avg_mem, 1), "peak_mem": round(a["peak_mem"], 1),
                 "confidence": "high" if od >= 7 else "medium" if od >= 3 else "low"}
            judged.append({"cluster": a["cluster"], "vcpu": vcpu, "mem_gb": mem})
            used_c, used_m = vcpu * a["peak_cpu"] / 100, mem * a["peak_mem"] / 100
            if a["peak_cpu"] < th["idle_cpu"] and a["peak_mem"] < th["idle_mem"]:
                m["saving"] = round((vcpu * (rate or {}).get("vcpu_hour", 0) + mem * (rate or {}).get("mem_gb_hour", 0)) * 730, 0) if rate else None
                m["why"] = (f"켜져 있던 {a['hours_on']}시간 동안 CPU 피크 {a['peak_cpu']:.1f}%·메모리 피크 {a['peak_mem']:.1f}% — "
                            f"사용하지 않는 VM 으로 보임")
                m["action"] = "담당자 확인 후 전원 끄기 또는 삭제"
                idle.append(m)
                continue
            rc = max(2, math.ceil(vcpu * a["peak_cpu"] / 100 * th["headroom"])) if vcpu >= 4 and a["peak_cpu"] < th["over_cpu"] else None
            rm = max(2, math.ceil(mem * a["peak_mem"] / 100 * th["headroom"])) if mem >= 8 and a["peak_mem"] < th["over_mem"] else None
            if (rc is not None and rc < vcpu) or (rm is not None and rm < mem):
                m.update(rec_vcpu=rc if rc is not None and rc < vcpu else vcpu, rec_mem_gb=rm if rm is not None and rm < mem else mem)
                m["saving"] = round(((vcpu - m["rec_vcpu"]) * (rate or {}).get("vcpu_hour", 0) + (mem - m["rec_mem_gb"]) * (rate or {}).get("mem_gb_hour", 0)) * 730, 0) if rate else None
                parts = []
                if m["rec_vcpu"] < vcpu:
                    parts.append(f"CPU 피크 {a['peak_cpu']:.0f}% = vCPU {vcpu:g} 중 약 {used_c:.1f}개 사용 → ×{th['headroom']:g} 여유 = {m['rec_vcpu']:g} vCPU")
                if m["rec_mem_gb"] < mem:
                    parts.append(f"메모리 피크 {a['peak_mem']:.0f}% = {mem:g} GB 중 약 {used_m:.1f} GB 사용 → ×{th['headroom']:g} 여유 = {m['rec_mem_gb']:g} GB")
                m["why"] = " / ".join(parts)
                m["action"] = " · ".join(x for x in [f"vCPU {vcpu:g}→{m['rec_vcpu']:g}" if m["rec_vcpu"] < vcpu else "",
                                                     f"메모리 {mem:g}→{m['rec_mem_gb']:g} GB" if m["rec_mem_gb"] < mem else ""] if x) + " 축소"
                over.append(m)
            if avg_cpu >= th["under_cpu"] or avg_mem >= th["under_mem"]:
                m2 = dict(m)
                m2["rec_vcpu"] = math.ceil(vcpu * 1.5) if avg_cpu >= th["under_cpu"] else vcpu
                m2["rec_mem_gb"] = math.ceil(mem * 1.5) if avg_mem >= th["under_mem"] else mem
                m2["why"] = " · ".join(x for x in [f"평균 CPU {avg_cpu:.0f}%" if avg_cpu >= th["under_cpu"] else "", f"평균 메모리 {avg_mem:.0f}%" if avg_mem >= th["under_mem"] else ""] if x)
                m2["action"] = " · ".join(x for x in [f"vCPU {vcpu:g}→{m2['rec_vcpu']:g}" if m2["rec_vcpu"] > vcpu else "",
                                                      f"메모리 {mem:g}→{m2['rec_mem_gb']:g} GB" if m2["rec_mem_gb"] > mem else ""] if x) + " 증설"
                m2["saving"] = None
                under.append(m2)
        over.sort(key=lambda x: -(x.get("saving") or (x["vcpu"] - x.get("rec_vcpu", 0))))
        under.sort(key=lambda x: -max(x["avg_cpu"], x["avg_mem"]))
        idle.sort(key=lambda x: -(x.get("saving") or x["vcpu"]))
        off.sort(key=lambda x: -x["disk_gb"])
        flagged = {(x["vcenter"], x["vm"]) for x in over + under + idle}
        by_cl: dict[str, dict] = {}
        for j in judged:
            b = by_cl.setdefault(j["cluster"] or "-", {"cluster": j["cluster"] or "-", "vms": 0, "vcpu": 0.0, "mem_gb": 0.0, "oversized": 0, "undersized": 0, "idle": 0,
                                                       "powered_off": 0, "reclaim_vcpu": 0.0, "reclaim_mem_gb": 0.0, "add_vcpu": 0.0, "add_mem_gb": 0.0, "saving": 0.0})
            b["vms"] += 1
            b["vcpu"] += j["vcpu"]
            b["mem_gb"] += j["mem_gb"]
        for kind, lst in (("oversized", over), ("undersized", under), ("idle", idle), ("powered_off", off)):
            for x in lst:
                b = by_cl.setdefault(x["cluster"] or "-", {"cluster": x["cluster"] or "-", "vms": 0, "vcpu": 0.0, "mem_gb": 0.0, "oversized": 0, "undersized": 0, "idle": 0,
                                                           "powered_off": 0, "reclaim_vcpu": 0.0, "reclaim_mem_gb": 0.0, "add_vcpu": 0.0, "add_mem_gb": 0.0, "saving": 0.0})
                b[kind] += 1
                if kind == "oversized":
                    b["reclaim_vcpu"] += x["vcpu"] - x["rec_vcpu"]
                    b["reclaim_mem_gb"] += x["mem_gb"] - x["rec_mem_gb"]
                elif kind == "idle":
                    b["reclaim_vcpu"] += x["vcpu"]
                    b["reclaim_mem_gb"] += x["mem_gb"]
                elif kind == "undersized":
                    b["add_vcpu"] += x["rec_vcpu"] - x["vcpu"]
                    b["add_mem_gb"] += x["rec_mem_gb"] - x["mem_gb"]
                b["saving"] += x.get("saving") or 0
        clusters = sorted(({k: (round(v, 1) if isinstance(v, float) else v) for k, v in b.items()} for b in by_cl.values()),
                          key=lambda b: (-b["saving"], -b["reclaim_vcpu"], b["cluster"]))
        alloc_c, alloc_m = sum(j["vcpu"] for j in judged), sum(j["mem_gb"] for j in judged)
        rec_c = alloc_c - sum(x["vcpu"] - x["rec_vcpu"] for x in over) - sum(x["vcpu"] for x in idle) + sum(x["rec_vcpu"] - x["vcpu"] for x in under)
        rec_m = alloc_m - sum(x["mem_gb"] - x["rec_mem_gb"] for x in over) - sum(x["mem_gb"] for x in idle) + sum(x["rec_mem_gb"] - x["mem_gb"] for x in under)
        res = {"generated": now, "days": days, "thresholds": th, "rate": {k: rate.get(k) for k in ("vcpu_hour", "mem_gb_hour", "disk_gb_hour")} if rate else None,
               "currency": self.e.billing.currency if rate else None, "vms_observed": len(agg),
               "oversized": over[:500], "undersized": under[:500], "idle": idle[:500], "powered_off": off[:500],
               "summary": {"oversized": len(over), "undersized": len(under), "idle": len(idle), "powered_off": len(off),
                           "reclaim_vcpu": round(sum(x["vcpu"] - x["rec_vcpu"] for x in over) + sum(x["vcpu"] for x in idle), 1),
                           "reclaim_mem_gb": round(sum(x["mem_gb"] - x["rec_mem_gb"] for x in over) + sum(x["mem_gb"] for x in idle), 1),
                           "reclaim_disk_gb": round(sum(x["disk_gb"] for x in off), 1),
                           "saving_month": round(sum((x.get("saving") or 0) for x in over + idle + off), 0) if rate else None,
                           "judged": len(judged), "pending": pending, "ok": len(judged) - len(flagged),
                           "add_vcpu": round(sum(x["rec_vcpu"] - x["vcpu"] for x in under), 1), "add_mem_gb": round(sum(x["rec_mem_gb"] - x["mem_gb"] for x in under), 1),
                           "alloc_vcpu": round(alloc_c, 1), "alloc_mem_gb": round(alloc_m, 1), "rec_vcpu": round(rec_c, 1), "rec_mem_gb": round(rec_m, 1)},
               "clusters": clusters[:200]}
        self._cache[key] = (now, res)
        return res
'''

OLD_REPORT = r'''
    async def report(self, start: float, end: float, label: str = "", tenant_ids: set[int] | None = None, vm_detail: bool = True) -> dict[str, Any]:
        self._ensure()
        rows = await self.e.store.q("SELECT * FROM bill_usage WHERE hour>=? AND hour<?", (int(start // 3600 * 3600), end))
        rates = {r["id"]: r for r in await self.rates()}
        default_rate = next((r["id"] for r in rates.values() if r["is_default"]), None)
        tenants = await self.tenants()
        tmap = {t["id"]: t for t in tenants}
        projects = [p for t in tenants for p in t["projects"]]
        pmap = {p["id"]: p for p in projects}
        M = Matcher(projects)

        def ver_at(rid, hour):
            r = rates.get(rid)
            if not r or not r["versions"]:
                return None
            v = None
            for x in r["versions"]:
                if x["effective_from"] <= hour:
                    v = x
            return v or r["versions"][0]

        agg: dict[tuple, dict] = {}
        cover = {"first": None, "last": None, "hours": set()}
        for r in rows:
            tags = _j(r["tags"], [])
            pid, how = M.match(r["vm"], r["cluster"] or "", r["folder"] or "", tags)
            p = pmap.get(pid) if pid else None
            tid = p["tenant_id"] if p else None
            if tenant_ids is not None and tid not in tenant_ids:
                continue
            rid = (p or {}).get("rate_id") or (tmap.get(tid) or {}).get("rate_id") or default_rate
            v = ver_at(rid, r["hour"]) if rid else None
            h = 5 / 60
            cpu_c = mem_c = disk_c = 0.0
            if v:
                mw = (v["min_weight"] or 0) / 100
                vc = (mw * r["vcpu"] + (1 - mw) * r["vcpu_u"]) if v["weighting"] else r["vcpu"]
                mm = (mw * r["mem"] + (1 - mw) * r["mem_u"]) if v["weighting"] else r["mem"]
                cpu_c = vc * v["vcpu_hour"] * h
                mem_c = mm * v["mem_gb_hour"] * h
                disk_c = (r["disk"] + (r["disk_off"] if v["disk_when_off"] else 0)) * v["disk_gb_hour"] * h
            k = (pid, r["vc"], r["vm"])
            a = agg.get(k)
            if a is None:
                a = agg[k] = {"vm": r["vm"], "vc": r["vc"], "project_id": pid, "tenant_id": tid, "matched_by": how, "rate_id": rid,
                              "blocks": 0, "seen": 0, "vcpu_bh": 0.0, "mem_bh": 0.0, "disk_bh": 0.0, "vcpu_u": 0.0, "mem_u": 0.0,
                              "cpu_cost": 0.0, "mem_cost": 0.0, "disk_cost": 0.0, "cluster": r["cluster"], "folder": r["folder"], "tags": tags, "last": 0}
            a["blocks"] += r["blocks"]
            a["seen"] += r["seen"]
            a["vcpu_bh"] += r["vcpu"]
            a["mem_bh"] += r["mem"]
            a["disk_bh"] += r["disk"]
            a["vcpu_u"] += r["vcpu_u"]
            a["mem_u"] += r["mem_u"]
            a["cpu_cost"] += cpu_c
            a["mem_cost"] += mem_c
            a["disk_cost"] += disk_c
            a["priced"] = a.get("priced", False) or bool(v)
            if r["hour"] >= a["last"]:
                a.update(last=r["hour"], cluster=r["cluster"], folder=r["folder"], tags=tags)
            cover["hours"].add(r["hour"])

        def vm_out(a: dict) -> dict:
            on_h = a["blocks"] * 5 / 60
            return {"vm": a["vm"], "vcenter": a["vc"], "cluster": a["cluster"], "folder": a["folder"], "tags": a["tags"], "matched_by": a["matched_by"],
                    "on_hours": round(on_h, 2), "observed_hours": round(a["seen"] * 5 / 60, 2),
                    "vcpu_hours": round(a["vcpu_bh"] * 5 / 60, 2), "mem_gb_hours": round(a["mem_bh"] * 5 / 60, 2), "disk_gb_hours": round(a["disk_bh"] * 5 / 60, 2),
                    "avg_vcpu": round(a["vcpu_bh"] / a["blocks"], 2) if a["blocks"] else 0, "avg_mem_gb": round(a["mem_bh"] / a["blocks"], 2) if a["blocks"] else 0,
                    "avg_disk_gb": round(a["disk_bh"] / a["blocks"], 1) if a["blocks"] else 0,
                    "cpu_util": round(a["vcpu_u"] / a["vcpu_bh"] * 100, 1) if a["vcpu_bh"] else None,
                    "mem_util": round(a["mem_u"] / a["mem_bh"] * 100, 1) if a["mem_bh"] else None,
                    "cpu_cost": round(a["cpu_cost"], 2), "mem_cost": round(a["mem_cost"], 2), "disk_cost": round(a["disk_cost"], 2),
                    "cost": round(a["cpu_cost"] + a["mem_cost"] + a["disk_cost"], 2) if a.get("priced") else None}

        def sums(vms: list[dict]) -> dict:
            keys = ("on_hours", "vcpu_hours", "mem_gb_hours", "disk_gb_hours", "cpu_cost", "mem_cost", "disk_cost")
            out = {k: round(sum(v[k] or 0 for v in vms), 2) for k in keys}
            out["cost"] = round(sum(v["cost"] or 0 for v in vms), 2) if any(v["cost"] is not None for v in vms) else None
            out["vms"] = len(vms)
            out["vms_on"] = sum(1 for v in vms if v["on_hours"] > 0)
            return out

        by_proj: dict[int | None, list[dict]] = {}
        for a in agg.values():
            by_proj.setdefault(a["project_id"], []).append(vm_out(a))
        t_out = []
        for t in tenants:
            if tenant_ids is not None and t["id"] not in tenant_ids:
                continue
            ps = []
            for p in t["projects"]:
                vms = sorted(by_proj.get(p["id"], []), key=lambda v: (-(v["cost"] or 0), -v["vcpu_hours"], v["vm"]))
                rid = p.get("rate_id") or t.get("rate_id") or default_rate
                ps.append({"id": p["id"], "name": p["name"], "note": p.get("note", ""), "rate": (rates.get(rid) or {}).get("name", "") if rid else "",
                           "match": {k: p[k] for k in ("clusters", "folders", "tags", "vms")}, **sums(vms), "vm_rows": vms if vm_detail else []})
            allv = [v for p in ps for v in p["vm_rows"]] if vm_detail else []
            tot = {k: round(sum(p[k] or 0 for p in ps), 2) for k in ("on_hours", "vcpu_hours", "mem_gb_hours", "disk_gb_hours", "cpu_cost", "mem_cost", "disk_cost")}
            tot["cost"] = round(sum(p["cost"] or 0 for p in ps), 2) if any(p["cost"] is not None for p in ps) else None
            tot["vms"] = sum(p["vms"] for p in ps)
            t_out.append({"id": t["id"], "name": t["name"], "note": t.get("note", ""), "rate": (rates.get(t.get("rate_id")) or {}).get("name", ""),
                          "projects": ps, **tot, "top_vms": sorted(allv, key=lambda v: -(v["cost"] or 0))[:5]})
        un = sorted(by_proj.get(None, []), key=lambda v: (-v["vcpu_hours"], v["vm"])) if tenant_ids is None else []
        cur = next((r["currency"] for r in rates.values() if r["is_default"]), None) or self.currency
        hours = sorted(cover["hours"])
        all_cost = [t["cost"] for t in t_out if t["cost"] is not None]
        return {"period": {"start": start, "end": end, "label": label}, "currency": cur, "generated": time.time(),
                "coverage": {"first_hour": hours[0] if hours else None, "last_hour": hours[-1] if hours else None, "hours_with_data": len(hours),
                             "period_hours": round((end - start) / 3600, 1)},
                "totals": {"cost": round(sum(all_cost), 2) if all_cost else None, "tenants": len(t_out), "projects": sum(len(t["projects"]) for t in t_out),
                           "vms": sum(t["vms"] for t in t_out), "vcpu_hours": round(sum(t["vcpu_hours"] for t in t_out), 2),
                           "mem_gb_hours": round(sum(t["mem_gb_hours"] for t in t_out), 2), "disk_gb_hours": round(sum(t["disk_gb_hours"] for t in t_out), 2),
                           "unassigned_vms": len(un), "unassigned_vcpu_hours": round(sum(v["vcpu_hours"] for v in un), 2)},
                "tenants": t_out, "unassigned": un[:2000], "rates": [{"id": r["id"], "name": r["name"], "currency": r["currency"], "is_default": r["is_default"],
                                                                      "current": r["current"]} for r in rates.values()],
                "sampler": dict(self.stats)}
'''
