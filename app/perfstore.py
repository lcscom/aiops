"""자체 성능 이력 저장소(2.25.0) — vCenter 과거 통계 수준과 무관하게 모든 호스트·VM 의 핵심 지표를 직접 보관.

  수집   interval(기본 300초)마다 연결된 호스트 + 전원 켠 VM(최대 max_vms)의 최근 실시간 표본(20초 × 15 = 5분) 평균
         지표 7개: cpu(%), mem(%), rdy(CPU ready %, VM), iops, lat(디스크 최대 지연 ms), dbps(디스크 B/s), nbps(네트워크 bit/s)
  저장   별도 SQLite(perf.db, WAL) — 로그 DB 와 잠금을 나누어 화면 조회를 막지 않음
         s5: 5분 표본(보존 retention_5m_days, 기본 3일) · h1: 1시간 롤업 평균·최대(보존 retention_1h_days, 기본 42일 = 6주)
  용도   계절성 기준선(이상 탐지)·동료 이상치·감시 규칙·호스트 맵·'자체 이력' 차트
읽기 전용 수집(QueryPerf). 저장 위치는 데이터 디렉터리.
"""
from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

METRICS = ("cpu", "mem", "rdy", "iops", "lat", "dbps", "nbps")
FROM_LATEST = {"cpu": "cpu_pct", "mem": "mem_pct", "rdy": "ready_pct", "iops": "iops", "lat": "disk_lat_ms", "dbps": "disk_Bps", "nbps": "net_bps"}
SCHEMA = f"""
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS ent(id INTEGER PRIMARY KEY, kind TEXT, vc TEXT, name TEXT, cluster TEXT, host TEXT, last REAL,
  UNIQUE(kind, vc, name));
CREATE TABLE IF NOT EXISTS s5(ts INTEGER, eid INTEGER, {", ".join(m + " REAL" for m in METRICS)}, PRIMARY KEY(eid, ts)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS s5_ts ON s5(ts);
CREATE TABLE IF NOT EXISTS h1(ts INTEGER, eid INTEGER, {", ".join(m + " REAL" for m in METRICS)},
  {", ".join(m + "_max REAL" for m in METRICS)}, n INTEGER, PRIMARY KEY(eid, ts)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS h1_ts ON h1(ts);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


class PerfStore:
    def __init__(self, path: str, cfg: dict | None = None):
        cfg = cfg or {}
        self.path = str(path)
        self.interval = max(60, int(cfg.get("interval", 300)))
        self.max_vms = int(cfg.get("max_vms", 3000))
        self.ret5 = float(cfg.get("retention_5m_days", 3))
        self.ret1 = float(cfg.get("retention_1h_days", 42))
        self.enabled = bool(cfg.get("enabled", True))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._db.executescript(SCHEMA)
        self._mu = threading.Lock()
        self._ids: dict[tuple, int] = {}
        self.keep = max(12, int(7200 // self.interval) + 1)    # 감시 규칙 창 최대 120분
        self.recent: dict[int, deque] = {}          # eid → 최근 2시간 5분 표본 [(ts, {m: v})] — 감시 규칙 평가용
        self.ents: dict[int, dict] = {}              # eid → {kind, vc, name, cluster, host}
        self.stats: dict[str, Any] = {"last": 0.0, "count": 0, "ms": 0, "errors": [], "runs": 0, "rows": 0}
        self._last_prune = 0.0
        self._load_ents()

    # ------------------------------------------------------------------ 기본
    def _x(self, sql: str, params: Any = ()) -> list[tuple]:
        with self._mu:
            cur = self._db.execute(sql, params)
            rows = cur.fetchall()
            self._db.commit()
            return rows

    def _many(self, sql: str, rows: list) -> None:
        with self._mu:
            self._db.executemany(sql, rows)
            self._db.commit()

    async def q(self, sql: str, params: Any = ()) -> list[tuple]:
        return await asyncio.to_thread(self._x, sql, params)

    def _load_ents(self) -> None:
        for i, k, vc, n, cl, h in self._x("SELECT id, kind, vc, name, cluster, host FROM ent"):
            self._ids[(k, vc, n)] = i
            self.ents[i] = {"kind": k, "vc": vc, "name": n, "cluster": cl or "", "host": h or ""}

    def eid(self, kind: str, vc: str, name: str, cluster: str = "", host: str = "") -> int:
        k = (kind, vc, name)
        i = self._ids.get(k)
        e = self.ents.get(i) if i else None
        if i is None:
            self._x("INSERT OR IGNORE INTO ent(kind, vc, name, cluster, host, last) VALUES(?,?,?,?,?,?)", (kind, vc, name, cluster, host, time.time()))
            i = self._x("SELECT id FROM ent WHERE kind=? AND vc=? AND name=?", k)[0][0]
            self._ids[k] = i
            self.ents[i] = {"kind": kind, "vc": vc, "name": name, "cluster": cluster, "host": host}
        elif e and (e["cluster"] != cluster or e["host"] != host):          # vMotion·클러스터 이동
            e.update(cluster=cluster, host=host)
            self._x("UPDATE ent SET cluster=?, host=? WHERE id=?", (cluster, host, i))
        return i

    # ------------------------------------------------------------------ 쓰기
    def put(self, ts: int, rows: list[tuple[int, dict]]) -> None:
        """rows = [(eid, {cpu, mem, …})] — 같은 5분 칸에 다시 쓰면 덮어씀"""
        data = [(ts, e, *[(None if m.get(k) is None else float(m[k])) for k in METRICS]) for e, m in rows]
        self._many(f"INSERT OR REPLACE INTO s5(ts, eid, {', '.join(METRICS)}) VALUES(?,?,{','.join('?' * len(METRICS))})", data)
        for e, m in rows:
            d = self.recent.setdefault(e, deque(maxlen=self.keep))
            item = (ts, {k: m.get(k) for k in METRICS})
            if not d or d[-1][0] < ts:
                d.append(item)
            else:                                            # 같은 칸 다시 쓰기·늦게 온 표본 — 시각 순서 유지
                xs = sorted([x for x in d if x[0] != ts] + [item], key=lambda x: x[0])[-self.keep:]
                d.clear()
                d.extend(xs)

    def put_named(self, ts: int, items: list[tuple]) -> int:
        """items = [(kind, vc, name, cluster, host, {지표})] — 엔티티 id 확인과 저장을 한 번에(2.30.0, 수집 스레드 1회 호출로 끝나게)"""
        rows = [(self.eid(kind, vc, name, cluster, host), m) for kind, vc, name, cluster, host, m in items]
        if rows:
            self.put(ts, rows)
        return len(rows)

    def rollup(self, upto: int | None = None) -> int:
        """완료된 시간 칸을 h1 로(재실행 안전) + 보존 기간 정리"""
        upto = int(upto or time.time()) // 3600 * 3600
        last = self._x("SELECT v FROM meta WHERE k='rollup'")
        start = int(last[0][0]) if last else upto - 3 * 3600
        start = max(start, upto - int(self.ret5 * 86400))
        n = 0
        for h in range(start, upto, 3600):
            avg = ", ".join(f"AVG({m})" for m in METRICS)
            mx = ", ".join(f"MAX({m})" for m in METRICS)
            self._x(f"INSERT OR REPLACE INTO h1(ts, eid, {', '.join(METRICS)}, {', '.join(m + '_max' for m in METRICS)}, n) "
                    f"SELECT {h}, eid, {avg}, {mx}, COUNT(*) FROM s5 WHERE ts >= ? AND ts < ? GROUP BY eid", (h, h + 3600))
            n += 1
        self._x("INSERT OR REPLACE INTO meta(k, v) VALUES('rollup', ?)", (str(upto),))
        mx = self._x("SELECT MAX(ts) FROM s5")[0][0] or time.time()
        ref = min(time.time(), mx + 86400)                   # 시계가 크게 앞으로 튀어도 전부 지우지 않게(마지막 표본 기준 + 하루)
        self._x("DELETE FROM s5 WHERE ts < ?", (int(ref - self.ret5 * 86400),))
        self._x("DELETE FROM h1 WHERE ts < ?", (int(ref - self.ret1 * 86400),))
        if time.time() - self._last_prune > 6 * 3600:
            self.prune_entities()
        return n

    def prune_entities(self, min_age: float = 86400) -> int:
        """표본(s5)·롤업(h1)이 하나도 남지 않은 엔티티 정리(2.30.0) — VDI·인스턴트 클론처럼 생겼다 사라지는 VM 으로 ent 표와
        메모리 사전이 끝없이 커지지 않게. 방금 등록돼 아직 표본을 쓰기 전인 엔티티(min_age 이내)는 건드리지 않는다."""
        self._last_prune = time.time()
        dead = [r[0] for r in self._x("SELECT id FROM ent WHERE last < ? AND NOT EXISTS (SELECT 1 FROM s5 WHERE s5.eid = ent.id) "
                                      "AND NOT EXISTS (SELECT 1 FROM h1 WHERE h1.eid = ent.id)", (time.time() - min_age,))]
        dead = [i for i in dead if i not in self.recent]
        for i in range(0, len(dead), 500):
            part = dead[i:i + 500]
            self._x(f"DELETE FROM ent WHERE id IN ({','.join('?' * len(part))})", part)
        gone = set(dead)
        for k in [k for k, i in list(self._ids.items()) if i in gone]:
            self._ids.pop(k, None)
        for i in dead:
            self.ents.pop(i, None)
        self.stats["pruned"] = self.stats.get("pruned", 0) + len(dead)
        return len(dead)

    def warm(self) -> None:
        """기동 시 최근 1시간 표본을 메모리로(감시 규칙 즉시 평가)"""
        since = int(time.time() - 7200)
        for row in self._x(f"SELECT ts, eid, {', '.join(METRICS)} FROM s5 WHERE ts >= ? ORDER BY ts", (since,)):
            self.recent.setdefault(row[1], deque(maxlen=self.keep)).append((row[0], dict(zip(METRICS, row[2:]))))

    # ------------------------------------------------------------------ 읽기
    def series(self, eid: int, table: str, since: float, until: float | None = None) -> dict:
        until = until or time.time() + 1
        if table == "h1":
            cols = ", ".join(list(METRICS) + [m + "_max" for m in METRICS])
        else:
            cols = ", ".join(METRICS)
        rows = self._x(f"SELECT ts, {cols} FROM {table} WHERE eid=? AND ts >= ? AND ts < ? ORDER BY ts", (eid, int(since), int(until)))
        names = list(METRICS) + ([m + "_max" for m in METRICS] if table == "h1" else [])
        return {"ts": [r[0] for r in rows], **{n: [r[i + 1] for r in rows] for i, n in enumerate(names)}}

    def cluster_peak(self, hosts: list[tuple[int, float, float]], days: int = 14, q: float = 0.95) -> dict[str, Any]:
        """클러스터 수요의 피크(2.35.0 가정 분석) — 시간별 평균(h1)을 호스트 용량으로 환산해 같은 시각끼리 더한 뒤 q 분위수.
        hosts = [(eid, cpu_mhz, mem_mb)]. 호스트의 80% 이상이 있는 시각만 쓰고, 빠진 호스트는 평균으로 채운다."""
        if not hosts:
            return {"samples": 0}
        cap = {e: (c, m) for e, c, m in hosts}
        ids = list(cap)
        rows = self._x(f"SELECT ts, eid, cpu, mem FROM h1 WHERE ts >= ? AND eid IN ({','.join('?' * len(ids))})", (int(time.time() - days * 86400), *ids))
        by: dict[int, list[float]] = {}
        for ts, eid, cpu, mem in rows:
            if cpu is None or mem is None:
                continue
            b = by.setdefault(ts, [0.0, 0.0, 0])
            b[0] += cpu / 100 * cap[eid][0]
            b[1] += mem / 100 * cap[eid][1]
            b[2] += 1
        need = max(1, -(-len(ids) * 8 // 10))
        cs = sorted(b[0] * len(ids) / b[2] for b in by.values() if b[2] >= need)
        ms = sorted(b[1] * len(ids) / b[2] for b in by.values() if b[2] >= need)
        if not cs:
            return {"samples": 0}
        k = min(len(cs) - 1, max(0, int(-(-q * len(cs) // 1)) - 1))
        ts = [t for t, b in by.items() if b[2] >= need]
        return {"samples": len(cs), "cpu_mhz": cs[k], "mem_mb": ms[k], "cpu_max_mhz": cs[-1], "mem_max_mb": ms[-1],
                "cpu_avg_mhz": sum(cs) / len(cs), "mem_avg_mb": sum(ms) / len(ms), "span_h": round((max(ts) - min(ts)) / 3600) + 1}

    def vm_peaks(self, eids: list[int], days: int = 14, q: float = 0.95, min_samples: int = 24) -> dict[int, dict[str, float]]:
        """2.37.0 VM 별 CPU 사용률 피크(시간 평균의 q 분위수, %) — 클러스터 간 이동·DR 수용 가정의 수요. 표본이 min_samples 미만인 VM 은 빼고 돌려준다"""
        ids = [e for e in eids if e is not None]
        if not ids:
            return {}
        out: dict[int, dict[str, float]] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            rows = self._x(f"SELECT eid, cpu FROM h1 WHERE ts >= ? AND cpu IS NOT NULL AND eid IN ({','.join('?' * len(chunk))})", (int(time.time() - days * 86400), *chunk))
            by: dict[int, list[float]] = {}
            for eid, cpu in rows:
                by.setdefault(eid, []).append(float(cpu))
            for eid, v in by.items():
                if len(v) < min_samples:
                    continue
                v.sort()
                k = min(len(v) - 1, max(0, int(-(-q * len(v) // 1)) - 1))
                out[eid] = {"cpu_pct": v[k], "samples": len(v), "max_pct": v[-1]}
        return out

    def latest(self, max_age: float | None = None) -> dict[int, dict]:
        out = {}
        cut = time.time() - (max_age if max_age is not None else self.interval * 3)
        for e, d in list(self.recent.items()):
            if d and d[-1][0] >= cut:
                out[e] = {"ts": d[-1][0], **d[-1][1]}
        return out

    def find(self, kind: str, name: str, vc: str = "") -> int | None:
        if vc:
            return self._ids.get((kind, vc, name))
        for (k, _v, n), i in list(self._ids.items()):
            if k == kind and n == name:
                return i
        return None

    def size(self) -> dict:
        try:
            s5 = self._x("SELECT COUNT(*) FROM s5")[0][0]
            h1 = self._x("SELECT COUNT(*) FROM h1")[0][0]
        except sqlite3.Error:
            s5 = h1 = -1
        try:
            mb = round(Path(self.path).stat().st_size / 1048576, 1)
        except OSError:
            mb = 0
        return {"s5": s5, "h1": h1, "entities": len(self.ents), "mb": mb}
