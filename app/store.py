"""SQLite 영속화 — 로그/이상징후/알림 이력.

안정성 설계
- 쓰기 연결 1개(직렬화) + 읽기 전용 연결 1개(WAL 동시 읽기) → 화면 조회·리포트가 수집 저장을 막지 않는다.
- 로그·이상징후는 write-behind: 호출자는 큐에 넣고 즉시 반환, writer 가 묶어서(최대 2000건) 한 트랜잭션으로 커밋.
  같은 이상징후의 연속 갱신(재발 카운트)은 id 단위로 병합해 마지막 상태만 저장한다.
- 쓰기 실패(디스크 가득·잠금)는 배치를 버리지 않고 지수 백오프 재시도. 큐가 넘치면 로그만 폐기하고 건수를 센다.
- 보존 기간 삭제는 2만 행 단위로 쪼개 긴 쓰기 잠금을 피하고, 10분마다 WAL 체크포인트로 WAL 파일 증가를 막는다.
- 디스크 여유 공간이 storage.min_free_mb 아래로 떨어지면 원본 로그 저장을 멈춘다(이상징후·감사는 계속).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any

from starlette.exceptions import HTTPException


class QueryTimeout(HTTPException, TimeoutError):
    """읽기 조회 상한 초과(2.30.0) — API 는 504 로 응답(다른 조회가 읽기 잠금 뒤에 줄줄이 멈추지 않게 중단)."""

    def __init__(self, limit: float, sql: str = ""):
        HTTPException.__init__(self, 504, f"조회 시간 초과({limit:g}초) — 기간·조건을 좁혀 다시 시도하세요")
        self.limit, self.sql = limit, sql

    def __str__(self) -> str:
        return str(self.detail)


class _BackupRestart(Exception):
    pass


# 2.30.0 기동 후 백그라운드로 만드는 인덱스(대용량 테이블에서 기동을 막지 않게) — severity 값은 models.SEVERITIES 그대로
LATE_INDEXES = {
    "ix_logs_sevhi": "CREATE INDEX IF NOT EXISTS ix_logs_sevhi ON logs(source, ts) WHERE severity IN ('warning','error','critical')",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER, ts REAL, source TEXT, connector TEXT, severity TEXT, host TEXT,
  entity TEXT, kind TEXT, message TEXT, score REAL, template TEXT, attrs TEXT);
CREATE INDEX IF NOT EXISTS ix_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS ix_logs_src ON logs(source, ts);
CREATE TABLE IF NOT EXISTS anomalies(id TEXT PRIMARY KEY, created REAL, last_seen REAL,
  severity TEXT, status TEXT, ack INTEGER, body TEXT);
CREATE INDEX IF NOT EXISTS ix_anom_created ON anomalies(created);
CREATE INDEX IF NOT EXISTS ix_anom_last ON anomalies(last_seen);
CREATE TABLE IF NOT EXISTS alerts(ts REAL, anomaly_id TEXT, channel TEXT, ok INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
"""


def _open(path: str, readonly: bool = False) -> sqlite3.Connection:
    c = sqlite3.connect(path, check_same_thread=False, timeout=10)
    c.execute("PRAGMA busy_timeout=10000")
    if readonly:
        c.execute("PRAGMA query_only=1")
    else:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")       # WAL 모드에서 전원 장애 시에도 DB 손상 없음(마지막 커밋 일부만 유실 가능)
        c.execute("PRAGMA wal_autocheckpoint=2000")
    c.execute("PRAGMA temp_store=MEMORY")
    c.execute("PRAGMA cache_size=-32000")           # 32MB
    return c


class Store:
    def __init__(self, path: str, retention_days: int = 7, cfg: dict | None = None):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        cfg = cfg or {}
        self.path = path
        self.retention = retention_days * 86400
        self.q_max = int(cfg.get("log_queue", 100000))
        self.min_free_mb = int(cfg.get("min_free_mb", 1024))
        self._logs: list[dict] = []                      # write-behind 로그 버퍼
        self._anoms: OrderedDict[str, tuple] = OrderedDict()   # id → 최신 행(병합)
        self._alerts: list[tuple] = []
        self._wake = asyncio.Event()
        self._inflight = 0                               # 쓰기 중(트랜잭션 진행) 건수 — 지연 시에도 적체를 정확히 노출
        self._conn = _open(path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._rconn = _open(path, readonly=True)
        self._lock = asyncio.Lock()                      # 쓰기 연결 직렬화
        self._rlock = asyncio.Lock()                     # 읽기 연결 직렬화
        self._rlat: deque = deque(maxlen=2000)            # (시각, 조회 ms) — read_p95
        self.slow_ms, self.slow_count = float(cfg.get("slow_query_ms", 2000)), 0
        self.query_timeout = float(cfg.get("query_timeout_s", 20))     # 2.30.0 읽기 1건 상한(0 = 제한 없음)
        self.timeout_count = 0
        self.late_index_delay = float(cfg.get("late_index_delay_s", 30))
        self._maint = False                              # 인덱스 생성 중 — writer 는 버퍼만 쌓고 기다림(하트비트 유지)
        self._late_task: asyncio.Task | None = None
        self.late_index: dict[str, Any] = {"state": "pending", "created": [], "error": "", "seconds": 0.0}
        self.stats: dict[str, Any] = {"logs_written": 0, "logs_dropped": 0, "logs_skipped_disk": 0, "anoms_written": 0,
                                      "batches": 0, "write_errors": 0, "last_write": time.time(), "last_error": "",
                                      "last_batch_ms": 0.0, "max_batch_ms": 0.0, "disk_free_mb": None, "disk_low": False,
                                      "state": "ok"}
        self._check_disk()

    # ------------------------------------------------------------------ write-behind 입구(즉시 반환)
    def put_log(self, ev: dict[str, Any]) -> None:
        if self.stats["disk_low"]:
            self.stats["logs_skipped_disk"] += 1
            return
        if len(self._logs) >= self.q_max:
            self.stats["logs_dropped"] += 1               # 백프레셔: DB가 밀리면 실시간 처리 우선, 원본 로그 저장은 폐기
            return
        self._logs.append(ev)
        if len(self._logs) >= 500:
            self._wake.set()

    async def save_anomaly(self, a: dict[str, Any]) -> None:
        self._anoms[a["id"]] = (a["id"], a["created"], a["last_seen"], a["severity"], a["status"], int(a["ack"]),
                                json.dumps(a, ensure_ascii=False, default=str))
        self._anoms.move_to_end(a["id"])
        self._wake.set()

    async def save_alert(self, anomaly_id: str, channel: str, ok: bool, detail: str) -> None:
        self._alerts.append((time.time(), anomaly_id, channel, int(ok), str(detail)[:500]))
        self._wake.set()

    @property
    def backlog(self) -> int:
        return len(self._logs) + len(self._anoms) + len(self._alerts) + self._inflight

    # ------------------------------------------------------------------ writer
    async def writer(self, beat=lambda: None) -> None:
        last_purge = last_ckpt = time.time()
        delay = 0.5
        if self._late_task is None:                         # 기동 후 1회 — 준비 상태(readyz)를 막지 않게 별도 작업
            self._late_task = asyncio.create_task(self.ensure_late_indexes(self.late_index_delay), name="store-late-index")
        while True:
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            beat()
            if self.backlog and not self._maint:
                ok = await self._flush_once()
                if not ok:                                  # 실패 → 백오프 후 재시도(배치는 버퍼에 그대로)
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, 30)
                    continue
                delay = 0.5
                if self.backlog:
                    self._wake.set()
            now = time.time()
            if now - last_ckpt > 600:
                last_ckpt = now
                self._check_disk()
                await self._run_write(lambda: self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)"))
            if now - last_purge > 3600:
                last_purge = now
                await self._purge()

    async def ensure_late_indexes(self, delay: float = 0.0) -> list[str]:
        """없는 인덱스만 백그라운드 스레드에서 생성 — 생성 동안 쓰기는 버퍼에 쌓였다가 이어서 기록(읽기는 WAL 로 계속)."""
        if delay > 0:
            await asyncio.sleep(delay)
        st = self.late_index
        try:
            have = {r["name"] for r in await self.q("SELECT name FROM sqlite_master WHERE type='index'")}
            todo = [(n, sql) for n, sql in LATE_INDEXES.items() if n not in have]
            if not todo:
                st["state"] = "ok"
                return []
            t0 = time.time()
            st["state"] = "building"
            print(f"[store] 인덱스 생성 시작(백그라운드): {', '.join(n for n, _ in todo)}", flush=True)
            self._maint = True
            try:
                for n, sql in todo:
                    await self._run_write(lambda s=sql: self._exec(s))
                    st["created"].append(n)
            finally:
                self._maint = False
                self._wake.set()
            st.update(state="ok", seconds=round(time.time() - t0, 1))
            print(f"[store] 인덱스 생성 완료 {st['seconds']}초: {', '.join(st['created'])}", flush=True)
            return list(st["created"])
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001  — 실패해도 조회는 기존 인덱스로 동작, 다음 기동 때 다시 시도
            st.update(state="error", error=f"{type(e).__name__}: {e}"[:200])
            print(f"[store] 인덱스 생성 실패: {st['error']}", flush=True)
            return []

    async def _flush_once(self) -> bool:
        logs, self._logs = self._logs[:2000], self._logs[2000:]
        anoms = list(self._anoms.values())[:500]
        for r in anoms:
            self._anoms.pop(r[0], None)
        alerts, self._alerts = self._alerts[:500], self._alerts[500:]
        rows = [(e["id"], e["ts"], e["source"], e["connector"], e["severity"], e["host"], e["entity"], e["kind"],
                 e["message"], e["score"], e["template"],
                 json.dumps(e.get("attrs", {}), ensure_ascii=False, default=str)[:4000]) for e in logs]

        def run():
            with self._conn:                                   # 단일 트랜잭션
                if rows:
                    self._conn.executemany("INSERT INTO logs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                if anoms:
                    self._conn.executemany("INSERT OR REPLACE INTO anomalies VALUES(?,?,?,?,?,?,?)", anoms)
                if alerts:
                    self._conn.executemany("INSERT INTO alerts VALUES(?,?,?,?,?)", alerts)
        t0 = time.perf_counter()
        self._inflight = len(rows) + len(anoms) + len(alerts)
        try:
            await self._run_write(run)
        except Exception as e:  # noqa: BLE001
            self._inflight = 0
            self.stats["write_errors"] += 1
            self.stats["last_error"] = f"{type(e).__name__}: {e}"[:300]
            self.stats["state"] = "error"
            print(f"[store] 쓰기 실패 — 재시도 예정: {self.stats['last_error']}", flush=True)
            # 되돌려 놓기(로그는 앞쪽에, 넘치면 오래된 것부터 폐기)
            self._logs = (logs + self._logs)[-self.q_max:]
            for r in anoms:
                self._anoms.setdefault(r[0], r)
            self._alerts = alerts + self._alerts
            if "disk" in str(e).lower() or "full" in str(e).lower():
                self._check_disk()
            return False
        self._inflight = 0
        ms = (time.perf_counter() - t0) * 1000
        st = self.stats
        st["logs_written"] += len(rows)
        st["anoms_written"] += len(anoms)
        st["batches"] += 1
        st["last_write"] = time.time()
        st["last_batch_ms"] = round(ms, 1)
        st["max_batch_ms"] = round(max(st["max_batch_ms"] * 0.98, ms), 1)
        st["state"] = "disk_low" if st["disk_low"] else "ok"
        return True

    async def flush(self, timeout: float = 10.0) -> None:
        """종료 시 남은 버퍼를 최대한 기록"""
        t_end = time.time() + timeout
        while (len(self._logs) + len(self._anoms) + len(self._alerts)) and time.time() < t_end:
            if not await self._flush_once():
                await asyncio.sleep(0.5)

    def _check_disk(self) -> None:
        try:
            free = shutil.disk_usage(Path(self.path).parent).free // (1024 * 1024)
        except OSError:
            return
        self.stats["disk_free_mb"] = free
        low = free < self.min_free_mb
        if low != self.stats["disk_low"]:
            print(f"[store] 디스크 여유 {free}MB — 원본 로그 저장 {'중지' if low else '재개'}", flush=True)
        self.stats["disk_low"] = low

    async def _purge(self) -> None:
        cut = time.time() - self.retention
        for table, col in (("logs", "ts"), ("anomalies", "last_seen"), ("alerts", "ts")):
            while True:
                n = await self._run_write(lambda t=table, c=col: self._exec_n(
                    f"DELETE FROM {t} WHERE rowid IN (SELECT rowid FROM {t} WHERE {c} < ? LIMIT 20000)", (cut,)))
                if n < 20000:
                    break
                await asyncio.sleep(0.05)                    # 수집 쓰기에 양보
        mcut = time.time() - max(self.retention, getattr(self, "moves_retention", 400 * 86400), 90 * 86400)   # VM 액티비티: vm_activity.retention_days(기본 400일, 최소 90일)
        try:
            await self._run_write(lambda: self._exec_n("DELETE FROM vm_moves WHERE ts < ?", (mcut,)))
        except Exception:  # noqa: BLE001  (테이블 아직 없음)
            pass
        await self._run_write(lambda: self._conn.execute("PRAGMA optimize"))

    def _exec_n(self, sql, params=()) -> int:
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur.rowcount

    async def _run_write(self, fn):
        async with self._lock:
            return await asyncio.to_thread(fn)

    # ------------------------------------------------------------------ 범용 헬퍼(다른 모듈 공용)
    def schema(self, script: str) -> None:
        self._conn.executescript(script)
        self._conn.commit()

    async def x(self, sql: str, params: tuple | list = ()) -> int:
        """쓰기 1건 — lastrowid 반환(즉시 커밋, 읽기 연결에서 바로 보임)"""
        def run():
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid
        return await self._run_write(run)

    async def xm(self, sql: str, rows: list) -> int:
        """같은 문장 여러 건 — 한 트랜잭션(executemany)"""
        if not rows:
            return 0

        def run():
            cur = self._conn.executemany(sql, rows)
            self._conn.commit()
            return cur.rowcount
        return await self._run_write(run)

    async def q(self, sql: str, params: tuple | list = (), timeout: float | None = None) -> list[dict]:
        """읽기 — 실행 시간이 상한(storage.query_timeout_s, 기본 20초)을 넘으면 중단하고 QueryTimeout(504). timeout=0 은 제한 없음."""
        limit = self.query_timeout if timeout is None else float(timeout)

        def run():
            if limit <= 0:
                cur = self._rconn.execute(sql, params)
                cols = [c[0] for c in cur.description] if cur.description else []
                return [dict(zip(cols, r)) for r in cur.fetchall()]
            guard, st = threading.Lock(), {"done": False, "fired": False}

            def fire():
                with guard:                                 # 끝난 뒤 늦게 울려 다음 조회를 끊는 일이 없게
                    if not st["done"]:
                        st["fired"] = True
                        self._rconn.interrupt()
            timer = threading.Timer(limit, fire)
            timer.daemon = True
            timer.start()
            try:
                cur = self._rconn.execute(sql, params)
                cols = [c[0] for c in cur.description] if cur.description else []
                return [dict(zip(cols, r)) for r in cur.fetchall()]
            except sqlite3.OperationalError as e:
                if st["fired"] and "interrupt" in str(e).lower():
                    raise QueryTimeout(limit, sql) from None
                raise
            finally:
                with guard:
                    st["done"] = True
                timer.cancel()
        t0 = time.monotonic()
        timed_out = False
        try:
            async with self._rlock:
                return await asyncio.to_thread(run)
        except QueryTimeout:
            timed_out = True
            self.timeout_count += 1
            raise
        finally:                                            # 대기(읽기 잠금) 포함 조회 시간 — 화면이 느려지는지 판단(2.22.1)
            ms = (time.monotonic() - t0) * 1000
            self._rlat.append((time.monotonic(), ms))
            if ms >= self.slow_ms or timed_out:             # 느린 조회 기록 — 원인 쿼리 찾기
                self.slow_count += 1
                print(f"[store] 느린 조회 {ms:.0f}ms{' (상한 초과·중단)' if timed_out else ''}: {' '.join(sql.split())[:160]}", flush=True)

    def read_p95(self, window: float = 60.0) -> float:
        now = time.monotonic()
        xs = sorted(ms for t, ms in self._rlat if now - t <= window)
        return round(xs[int(len(xs) * 0.95) - 1], 1) if len(xs) >= 20 else 0.0      # 표본이 적으면(보고서 1건 등) 판단 안 함

    async def q1(self, sql: str, params: tuple | list = ()) -> dict | None:
        rows = await self.q(sql, params)
        return rows[0] if rows else None

    async def backup(self, dest: str) -> int:
        """온라인 백업(sqlite3 backup API — 쓰기 중에도 일관된 스냅샷). 2.30.0: 전용 읽기 연결 사용 — 화면 조회(읽기 잠금)·수집 저장을
        막지 않는다. 대상 디스크 여유가 모자라면 시작하지 않고, 실패하면 만들다 만 파일을 지운다."""
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        if getattr(self, "_backup_busy", False):
            raise RuntimeError("백업이 이미 진행 중")

        def run():
            need = sum(Path(self.path + sfx).stat().st_size for sfx in ("", "-wal") if Path(self.path + sfx).exists())
            free = shutil.disk_usage(Path(dest).parent).free
            if free < need + self.min_free_mb * 1024 * 1024:
                raise OSError(f"백업 대상 디스크 여유 부족 — 필요 {need // 1048576}MB + 여유 {self.min_free_mb}MB, 남은 공간 {free // 1048576}MB")
            tmp = dest + ".part"
            src = tgt = None
            try:
                src = sqlite3.connect(f"file:{Path(self.path).resolve().as_posix()}?mode=ro", uri=True, check_same_thread=False, timeout=10)
                src.execute("PRAGMA busy_timeout=10000")
                # 묶음(16MB)마다 쉬어 디스크를 양보. 단, 다른 연결이 쓰면 SQLite 가 복사를 처음부터 다시 하므로(쓰기가 잦은 큰 DB 는 끝나지 않음)
                # 재시작이 반복되면 한 번에 복사(읽기 스냅숏 1개 — WAL 이라 쓰기는 막지 않음)로 바꾼다.
                for pages in (4096, -1):
                    Path(tmp).unlink(missing_ok=True)
                    tgt = sqlite3.connect(tmp)
                    seen = {"last": None, "restarts": 0}

                    def prog(status, remaining, total, seen=seen):
                        if seen["last"] is not None and remaining > seen["last"]:
                            seen["restarts"] += 1
                            if seen["restarts"] >= 3:
                                raise _BackupRestart()
                        seen["last"] = remaining
                    try:
                        with tgt:
                            src.backup(tgt, pages=pages, sleep=0.01, progress=prog if pages > 0 else None)
                        tgt.close()
                        tgt = None
                        break
                    except _BackupRestart:
                        tgt.close()
                        tgt = None
                Path(tmp).replace(dest)
                return Path(dest).stat().st_size
            except BaseException:
                if tgt is not None:
                    tgt.close()
                Path(tmp).unlink(missing_ok=True)
                raise
            finally:
                if src is not None:
                    src.close()
        self._backup_busy = True
        try:
            return await asyncio.to_thread(run)
        finally:
            self._backup_busy = False

    def _exec(self, sql, params=()):
        self._conn.execute(sql, params)
        self._conn.commit()

    async def query_logs(self, since: float, until: float, source: str | None, q: str | None,
                         min_sev: list[str] | None, limit: int, host: str | None = None) -> list[dict]:
        sql = "SELECT id,ts,source,connector,severity,host,entity,kind,message,score,template FROM logs WHERE ts BETWEEN ? AND ?"
        p: list[Any] = [since, until]
        if host:                                         # FQDN·짧은 이름 모두 일치
            h = host.strip().lower()
            short = h.split(".")[0]
            if "." not in h and len(h) >= 3:              # 접두어(esx0 → esx01·esx02…) · VM 이름(entity)
                sql += " AND (lower(host) LIKE ? OR lower(entity) = ? OR lower(entity) LIKE ?)"
                p += [h + "%", h, "%/" + h]
            else:
                sql += " AND (lower(host) = ? OR lower(host) = ? OR lower(host) LIKE ? OR lower(entity) = ?)"
                p += [h, short, short + ".%", h]
        if source:
            sql += " AND source = ?"
            p.append(source)
        if q:
            sql += " AND message LIKE ?"
            p.append(f"%{q}%")
        if min_sev:
            sql += f" AND severity IN ({','.join('?' * len(min_sev))})"
            p += min_sev
        sql += " ORDER BY ts DESC LIMIT ?"
        p.append(limit)
        return await self.q(sql, p)

    async def known_hosts(self, since: float, limit: int = 3000) -> list[dict]:
        """최근 로그를 보낸 호스트(실시간 로그 보기 자동완성·제안) — 호스트별 소스·건수·마지막 수신."""
        return await self.q("SELECT lower(host) AS host, group_concat(DISTINCT source) AS sources, COUNT(*) AS n, MAX(ts) AS last "
                            "FROM logs WHERE ts >= ? AND host != '' GROUP BY lower(host) ORDER BY last DESC LIMIT ?", (since, limit))

    async def seed_hostseen(self, hostseen: dict, hours: float = 24) -> None:
        """기동 후 1회 — 최근 24시간 송신 호스트(소스·마지막 수신)를 메모리 집계(ENGINE.hostseen)에 채운다(2.30.0).
        무응답 감시가 평가 때마다 24시간치 로그를 훑지 않고도, 재기동 전에 보내다 끊긴 호스트를 알 수 있게."""
        if getattr(self, "_hosts_seeded", False):
            return
        lock = getattr(self, "_hosts_seed_lock", None)
        if lock is None:
            lock = self._hosts_seed_lock = asyncio.Lock()
        async with lock:
            if getattr(self, "_hosts_seeded", False):
                return
            try:
                rows = await self.q("SELECT host, source, MAX(ts) AS last FROM logs WHERE ts >= ? AND host != '' GROUP BY host, source LIMIT 20000",
                                    (time.time() - hours * 3600,))
            except Exception as e:  # noqa: BLE001  — 실패해도 이후 수신분은 메모리에 쌓인다
                print(f"[store] 호스트 목록 초기 적재 실패: {type(e).__name__}: {e}", flush=True)
                rows = []
            for r in rows:
                hs = hostseen.get(r["host"])
                if hs is None:
                    if len(hostseen) >= 5000:
                        continue
                    hs = hostseen[r["host"]] = [set(), 0, 0.0]
                hs[0].add(r["source"])
                hs[2] = max(hs[2], float(r["last"] or 0))
            self._hosts_seeded = True

    async def load_recent_anomalies(self, limit: int = 300) -> list[dict]:
        rows = await self.q("SELECT body FROM anomalies ORDER BY last_seen DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            try:
                out.append(json.loads(r["body"]))
            except (TypeError, ValueError):
                pass
        return out

    async def minute_counts(self, minutes: int = 60) -> list[dict]:
        return await self.q("SELECT CAST(ts/60 AS INTEGER) m, source, connector, severity, COUNT(*) n FROM logs "
                            "WHERE ts > ? GROUP BY m, source, connector, severity", (time.time() - minutes * 60,))

    def status(self) -> dict[str, Any]:
        return {**self.stats, "slow_queries": self.slow_count, "query_timeouts": self.timeout_count, "late_index": self.late_index["state"], "backlog": self.backlog, "log_queue": len(self._logs), "log_queue_max": self.q_max,
                "write_age": round(time.time() - self.stats["last_write"], 1)}
