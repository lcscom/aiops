"""성능 상시 감시(2.25.0) — 자체 이력(perfstore) 위의 계절성 기준선 이상 탐지 · 동료 이상치 · 감시 규칙.

참고한 업계 방식(이름은 비교 설명용)
  · 계절성 이상 탐지  같은 시각의 과거 값으로 '정상 범위(회색 밴드)'를 잡고 벗어나면 이상 — 일 계절성은 3일 이상, 주 계절성은
                      3주 이상 이력이 있을 때 사용하고, 부족하면 최근 24시간 분포(basic)로 대체.
                      이 구현은 시간대(하루 24칸 / 일주일 168칸)별 중앙값 ± k × 1.4826 × MAD(강건 표준편차)
  · 동료 이상치       같은 클러스터(DRS 로 비슷하게 움직여야 하는 호스트들) 안에서 시점마다 중앙값·MAD 를 구해, 대상이 창의
                      pct% 이상 시점에서 tolerance × MAD 밖이면 이상치(MAD 방식, 그룹 3대 이상)
  · 감시 규칙        임계(창 평균) · 이상(밴드 밖 비율) · 이상치 — 트리거 창(분), 경고/위험 값, 같은 창 동안 정상이면 회복
상태가 바뀔 때만 플랫폼 이벤트(source=aiops, connector=perfmon, kind=alert, entity=perf:<규칙>:<종류>:<이름>)를 보내
기존 알림 라우팅·인시던트로 이어지고, 회복 시 정상화 이벤트. 이력은 perf.db(perf_alerts).
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from statistics import median
from typing import Any

from .models import LogEvent
from .perfstore import FROM_LATEST, METRICS, PerfStore

MLABEL = {"cpu": "CPU 사용률", "mem": "메모리 사용률", "rdy": "CPU ready", "iops": "디스크 IOPS", "lat": "디스크 지연", "dbps": "디스크 처리량", "nbps": "네트워크"}
MUNIT = {"cpu": "%", "mem": "%", "rdy": "%", "iops": "", "lat": " ms", "dbps": " B/s", "nbps": " bps"}
FLOOR = {"cpu": 5.0, "mem": 3.0, "rdy": 1.0, "lat": 2.0}             # 밴드 최소 폭(절대) — 너무 평탄한 지표의 과민 반응 방지
REL_FLOOR = {"iops": 0.2, "dbps": 0.2, "nbps": 0.2}                   # 상대(중앙값의 20%)
ABS_MIN = {"cpu": 10.0, "mem": 10.0, "rdy": 2.0, "lat": 5.0, "iops": 50.0, "dbps": 5e6, "nbps": 5e6}   # 이 값 아래는 이상으로 보지 않음

DEFAULT_RULES = [
    {"id": "vm-ready", "name": "VM CPU 경합(ready)", "kind": "vm", "metric": "rdy", "type": "threshold", "warn": 5, "crit": 10, "window": 15},
    {"id": "vm-lat", "name": "VM 디스크 지연", "kind": "vm", "metric": "lat", "type": "threshold", "warn": 20, "crit": 50, "window": 15},
    {"id": "host-cpu", "name": "호스트 CPU 포화", "kind": "host", "metric": "cpu", "type": "threshold", "warn": 85, "crit": 95, "window": 15},
    {"id": "host-mem", "name": "호스트 메모리 포화", "kind": "host", "metric": "mem", "type": "threshold", "warn": 90, "crit": 97, "window": 30},
    {"id": "host-lat", "name": "호스트 디스크 지연", "kind": "host", "metric": "lat", "type": "threshold", "warn": 20, "crit": 50, "window": 15},
    {"id": "vm-cpu-anom", "name": "VM CPU 평소와 다름", "kind": "vm", "metric": "cpu", "type": "anomaly", "k": 3, "window": 30, "direction": "above", "pct": 80},
    {"id": "vm-lat-anom", "name": "VM 디스크 지연 평소와 다름", "kind": "vm", "metric": "lat", "type": "anomaly", "k": 3, "window": 30, "direction": "above", "pct": 80},
    {"id": "host-net-anom", "name": "호스트 네트워크 평소와 다름", "kind": "host", "metric": "nbps", "type": "anomaly", "k": 3, "window": 30, "direction": "both", "pct": 80},
    {"id": "host-cpu-outlier", "name": "클러스터 안에서 튀는 호스트(CPU)", "kind": "host", "metric": "cpu", "type": "outlier", "tolerance": 3, "window": 30, "pct": 60},
    {"id": "host-lat-outlier", "name": "클러스터 안에서 튀는 호스트(디스크 지연)", "kind": "host", "metric": "lat", "type": "outlier", "tolerance": 3, "window": 30, "pct": 60},
]
RULE_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, body TEXT, updated REAL, by TEXT);
CREATE TABLE IF NOT EXISTS perf_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT, eid INTEGER, sev TEXT, start REAL, end REAL,
  peak REAL, msg TEXT);
CREATE INDEX IF NOT EXISTS perf_alerts_start ON perf_alerts(start);
CREATE INDEX IF NOT EXISTS perf_alerts_open ON perf_alerts(rule, eid, end);
"""


def robust(xs: list[float]) -> tuple[float, float]:
    """(중앙값, 1.4826 × MAD)"""
    m = median(xs)
    return m, 1.4826 * median(abs(x - m) for x in xs)


def band(metric: str, med: float, sd: float, k: float) -> tuple[float, float]:
    w = max(k * sd, FLOOR.get(metric, 0.0), REL_FLOOR.get(metric, 0.0) * abs(med))
    return max(0.0, med - w), med + w


def tzoff() -> int:
    return time.localtime().tm_gmtoff


def fmt(metric: str, v: float | None) -> str:
    if v is None:
        return "-"
    if metric in ("dbps", "nbps"):
        return f"{v / 1e6:,.1f} M{'B/s' if metric == 'dbps' else 'bps'}"
    return f"{v:,.1f}{MUNIT[metric]}" if metric not in ("iops",) else f"{v:,.0f}"


_NESTED_Q = re.compile(r"\([^)]*[+*}][^)]*\)\s*[+*{]")         # (…+)+ · (…*)* 같은 중첩 반복(파국적 되돌림)


def safe_regex(v: str, field: str) -> str:
    if len(v) > 100:
        raise ValueError(f"{field}: 정규식은 100자 이하")
    if _NESTED_Q.search(v) or re.search(r"\\\d", v):
        raise ValueError(f"{field}: 중첩 반복·역참조는 쓸 수 없습니다(성능 보호)")
    try:
        re.compile(v)
    except re.error as e:
        raise ValueError(f"{field} 정규식 오류: {e}") from e
    return v


def _num(v, field: str) -> float:
    x = float(v)
    if not math.isfinite(x):
        raise ValueError(f"{field}: 유한한 숫자가 필요합니다")
    return x


def validate_rule(r: dict) -> dict:
    out = {"id": re.sub(r"[^a-z0-9-]", "", str(r.get("id") or "").lower())[:40] or f"r{int(time.time() * 1000) % 10**9}",
           "name": str(r.get("name") or "")[:80] or "이름 없는 규칙", "kind": r.get("kind"), "metric": r.get("metric"), "type": r.get("type"),
           "enabled": bool(r.get("enabled", True)), "window": int(r.get("window") or 15)}
    if out["kind"] not in ("vm", "host") or out["metric"] not in METRICS or out["type"] not in ("threshold", "anomaly", "outlier"):
        raise ValueError("kind(vm|host)·metric·type(threshold|anomaly|outlier) 확인")
    if out["metric"] == "rdy" and out["kind"] == "host":
        raise ValueError("CPU ready 는 VM 지표입니다")
    if not 5 <= out["window"] <= 120:
        raise ValueError("창은 5~120분")
    for k in ("cluster", "name_re", "exclude_re"):
        v = str(r.get(k) or "")
        out[k] = safe_regex(v, k) if v else ""
    if out["type"] == "threshold":
        w, c = r.get("warn"), r.get("crit")
        out["warn"] = None if w in (None, "") else _num(w, "경고 값")
        out["crit"] = None if c in (None, "") else _num(c, "위험 값")
        if out["warn"] is None and out["crit"] is None:
            raise ValueError("경고 또는 위험 값이 필요합니다")
        out["op"] = "below" if r.get("op") == "below" else "above"
    elif out["type"] == "anomaly":
        out["k"] = min(max(_num(r.get("k") or 3, "밴드 폭"), 1.0), 10.0)
        out["direction"] = r.get("direction") if r.get("direction") in ("above", "below", "both") else "above"
        out["pct"] = min(max(_num(r.get("pct") or 80, "비율"), 10.0), 100.0)
        out["sev"] = "critical" if r.get("sev") == "critical" else "warning"
    else:
        out["tolerance"] = min(max(_num(r.get("tolerance") or 3, "허용 폭"), 1.0), 10.0)
        out["pct"] = min(max(_num(r.get("pct") or 60, "비율"), 10.0), 100.0)
        out["direction"] = "both" if r.get("direction") == "both" else "above"      # 기본: 동료보다 '나쁜' 쪽만
        out["sev"] = "critical" if r.get("sev") == "critical" else "warning"
    return out


class PerfWatch:
    def __init__(self, engine, perfview, cfg: dict | None, data_dir: str):
        cfg = cfg or {}
        self.e, self.pv = engine, perfview
        self.store = PerfStore(str(cfg.get("db_path") or f"{data_dir}/perf.db"), cfg)
        self.store._x("SELECT 1")
        with self.store._mu:
            self.store._db.executescript(RULE_SCHEMA)
        self.max_alerts = int(cfg.get("max_alerts_per_cycle", 100))
        self.rules: dict[str, dict] = {}
        self.state: dict[tuple[str, int], dict] = {}     # (규칙, eid) → {sev, since, value, msg}
        self._bl: dict[tuple, tuple[float, dict]] = {}   # (metric, 계절 칸) → (만든 시각, {eid: (med, sd, season, n)})
        self.last_eval: dict[str, Any] = {}
        self._pending: list[tuple[str, tuple]] = []      # 경보 이력 쓰기(평가 끝에 스레드에서 한꺼번에 — 이벤트 루프 막지 않게)
        self._load_rules()
        self._restore()

    def _restore(self) -> None:
        """재시작 전 진행 중이던 경보를 상태로 되살림 — 같은 경보가 재시작마다 다시 울리지 않게, 끝난 것은 다음 평가에서 정상화"""
        for rid, eid, sev, start, peak, msg in self.store._x("SELECT rule, eid, sev, start, peak, msg FROM perf_alerts WHERE end IS NULL ORDER BY start"):
            if rid in self.rules and eid in self.store.ents:
                self.state[(rid, eid)] = {"sev": sev, "since": start, "value": peak, "peak": peak, "msg": msg or ""}
            else:
                self.store._x("UPDATE perf_alerts SET end=? WHERE rule=? AND eid=? AND end IS NULL", (time.time(), rid, eid))

    # ------------------------------------------------------------------ 규칙
    def _load_rules(self) -> None:
        rows = self.store._x("SELECT id, body FROM rules")
        if not rows:
            for r in DEFAULT_RULES:
                v = validate_rule({**r, "enabled": True})
                self.store._x("INSERT OR REPLACE INTO rules(id, body, updated, by) VALUES(?,?,?,?)", (v["id"], json.dumps(v, ensure_ascii=False), time.time(), "기본"))
            rows = self.store._x("SELECT id, body FROM rules")
        self.rules = {}
        for i, b in rows:
            try:
                self.rules[i] = json.loads(b)
            except ValueError:
                pass

    def save_rule(self, r: dict, by: str) -> dict:
        v = validate_rule(r)
        self.store._x("INSERT OR REPLACE INTO rules(id, body, updated, by) VALUES(?,?,?,?)", (v["id"], json.dumps(v, ensure_ascii=False), time.time(), by))
        self.rules[v["id"]] = v
        return v

    def delete_rule(self, rid: str) -> None:
        self.store._x("DELETE FROM rules WHERE id=?", (rid,))
        self.store._x("UPDATE perf_alerts SET end=? WHERE rule=? AND end IS NULL", (time.time(), rid))
        self.rules.pop(rid, None)
        for k in [k for k in self.state if k[0] == rid]:
            self.state.pop(k, None)

    def reset_rules(self) -> None:
        self.store._x("DELETE FROM rules")
        self.store._x("UPDATE perf_alerts SET end=? WHERE end IS NULL", (time.time(),))
        self.state.clear()
        self._load_rules()

    # ------------------------------------------------------------------ 수집
    async def sample(self) -> dict:
        t0 = time.time()
        ts = int(t0 // self.store.interval * self.store.interval)
        rows: list[tuple] = []                      # (kind, vc, name, cluster, host, 지표) — 엔티티 id 는 저장 스레드에서 한 번에(2.30.0)
        errs: list[str] = []
        for c in self.pv.vcenters():
            t = getattr(c, "topology", None) or {}
            hosts = [(n, h.get("moid", ""), 1, h.get("cluster", ""), n) for n, h in (t.get("hosts") or {}).items()
                     if h.get("moid") and h.get("conn", "connected") == "connected"]
            vms = [(n, v.get("moid", ""), int(v.get("vcpu") or 1), v.get("cluster", ""), v.get("host", "")) for n, v in (t.get("vms") or {}).items()
                   if v.get("moid") and v.get("power") == "poweredOn"][:self.store.max_vms]
            for kind, items in (("host", hosts), ("vm", vms)):
                if not items:
                    continue
                meta = {n: (cl, h) for n, _m, _c, cl, h in items}
                try:
                    args = (kind, [(n, m, cp) for n, m, cp, _cl, _h in items], 50, 15)
                    if getattr(c, "_thr_busy", None) is None:
                        run = asyncio.to_thread(c.perf_latest, *args)
                    elif c._thr_busy.get("perf"):               # 이전 수집 스레드가 아직 안 끝남 — 겹쳐 쌓지 않음
                        errs.append(f"{c.name}/{kind}: 이전 수집 진행 중")
                        continue
                    else:
                        run = c._tx("perf", c.perf_latest, *args)   # 커넥터 전용 스레드 풀(기본 실행기를 붙잡지 않게)
                    r = await asyncio.wait_for(run, 600)
                except Exception as ex:  # noqa: BLE001
                    errs.append(f"{c.name}/{kind}: {type(ex).__name__}")
                    continue
                if getattr(c, "perf_latest_errors", 0):
                    errs.append(f"{c.name}/{kind}: {c.perf_latest_errors}대 실패")
                for n, m in r.items():
                    cl, h = meta.get(n, ("", ""))
                    rows.append((kind, c.name, n, cl, h, {k: m.get(FROM_LATEST[k]) for k in METRICS}))
        if rows:
            await asyncio.to_thread(self.store.put_named, ts, rows)
        for e in [e for e, d in list(self.store.recent.items()) if not d or d[-1][0] < t0 - 7200]:
            self.store.recent.pop(e, None)                       # 꺼진·삭제된 VM — 맵·평가에서 빠지게
        st = self.store.stats
        st.update(last=t0, ts=ts, count=len(rows), ms=int((time.time() - t0) * 1000), errors=errs[:10], runs=st.get("runs", 0) + 1)
        return st

    # ------------------------------------------------------------------ 기준선
    async def baselines(self, metric: str, now: float | None = None) -> dict[int, tuple]:
        """현재 시각 칸의 엔티티별 기준(중앙값, 강건 sd, 계절성, 표본 수) — 주(3주↑) > 일(3일↑) > basic(최근 24시간)"""
        now = now or time.time()
        off = tzoff()
        how = int((now + off) // 3600 % 168)
        hod = how % 24
        key = (metric, hod)
        hit = self._bl.get(key)
        if hit and now - hit[0] < 3600:
            return hit[1]
        since = int(now - 42 * 86400)

        def run() -> dict[int, tuple]:
            rows = self.store._x(f"SELECT ts, eid, {metric} FROM h1 WHERE ts >= ? AND ((ts + ?) / 3600) % 24 = ? AND {metric} IS NOT NULL",
                                 (since, off, hod))
            by: dict[int, list[tuple[int, float]]] = {}
            for ts, e, v in rows:
                by.setdefault(e, []).append((ts, v))
            out: dict[int, tuple] = {}
            for e, xs in by.items():
                wk = [v for ts, v in xs if ((ts + off) // 3600) % 168 == how]
                if len(wk) >= 3:
                    m, sd = robust(wk)
                    out[e] = (m, sd, "weekly", len(wk))
                elif len(xs) >= 3:
                    m, sd = robust([v for _, v in xs][-21:])
                    out[e] = (m, sd, "daily", min(len(xs), 21))
            # 퍼짐(sd)은 5분 표본 기준이어야 함 — 1시간 평균의 MAD 는 5분 값의 흔들림을 약 √12 배 작게 잡아 오탐
            sp = self.store._x(f"SELECT eid, {metric} FROM s5 WHERE ts >= ? AND ((ts + ?) / 3600) % 24 = ? AND {metric} IS NOT NULL",
                               (int(now - self.store.ret5 * 86400), off, hod))
            s5b: dict[int, list[float]] = {}
            for e, v in sp:
                s5b.setdefault(e, []).append(v)
            for e, (m, sd, season, n) in list(out.items()):
                xs = s5b.get(e)
                if xs and len(xs) >= 6:
                    out[e] = (m, max(sd, robust(xs)[1]), season, n)
            day = self.store._x(f"SELECT eid, {metric} FROM s5 WHERE ts >= ? AND {metric} IS NOT NULL", (int(now - 86400),))
            bas: dict[int, list[float]] = {}
            for e, v in day:
                if e not in out:
                    bas.setdefault(e, []).append(v)
            for e, xs in bas.items():
                if len(xs) >= 24:                              # 2시간 이상 쌓이면 basic
                    m, sd = robust(xs)
                    out[e] = (m, sd, "basic", len(xs))
            return out
        res = await asyncio.to_thread(run)
        self._bl[key] = (now, res)
        for k in [k for k, v in self._bl.items() if now - v[0] > 7200]:
            self._bl.pop(k, None)
        return res

    async def band_series(self, eid: int, metric: str, ts_list: list[float], k: float = 3.0) -> dict:
        """상세 차트용 — 각 시각의 정상 범위(하한·상한). 시간대 칸별 같은 계산"""
        off = tzoff()
        since = int(time.time() - 42 * 86400)
        rows = await self.store.q(f"SELECT ts, {metric} FROM h1 WHERE eid=? AND ts >= ? AND {metric} IS NOT NULL", (eid, since))
        if len(rows) < 72:                                    # 3일 미만 — 밴드 없음
            return {"lo": [], "hi": [], "season": "", "n": len(rows)}
        hod: dict[int, list[float]] = {}
        how: dict[int, list[float]] = {}
        for t, v in rows:
            hod.setdefault(((t + off) // 3600) % 24, []).append(v)
            how.setdefault(((t + off) // 3600) % 168, []).append(v)
        weekly = len(rows) >= 21 * 24
        s5 = await self.store.q(f"SELECT ts, {metric} FROM s5 WHERE eid=? AND {metric} IS NOT NULL", (eid,))
        spread: dict[int, float] = {}
        tmp: dict[int, list[float]] = {}
        for t, v in s5:
            tmp.setdefault(((t + off) // 3600) % 24, []).append(v)
        for h, xs in tmp.items():
            if len(xs) >= 6:
                spread[h] = robust(xs)[1]
        lo, hi = [], []
        cache: dict[int, tuple] = {}
        for t in ts_list:
            hw = int(((t + off) // 3600) % 168)
            if hw not in cache:
                xs = how.get(hw) if weekly and len(how.get(hw) or []) >= 3 else hod.get(hw % 24)
                if xs and len(xs) >= 3:
                    m, sd = robust(xs)
                    cache[hw] = band(metric, m, max(sd, spread.get(hw % 24, 0.0)), k)
                else:
                    cache[hw] = (None, None)
            lo.append(cache[hw][0])
            hi.append(cache[hw][1])
        return {"lo": lo, "hi": hi, "season": "weekly" if weekly else "daily", "n": len(rows)}

    # ------------------------------------------------------------------ 평가
    def _scope(self, r: dict, eid: int) -> bool:
        e = self.store.ents.get(eid)
        if not e or e["kind"] != r["kind"]:
            return False
        if r.get("cluster") and not re.search(r["cluster"], e.get("cluster") or ""):
            return False
        if r.get("name_re") and not re.search(r["name_re"], e["name"]):
            return False
        if r.get("exclude_re") and re.search(r["exclude_re"], e["name"]):
            return False
        return True

    def _window(self, eid: int, minutes: int, metric: str) -> list[tuple[int, float]]:
        d = self.store.recent.get(eid) or ()
        cut = time.time() - minutes * 60 - self.store.interval
        return [(ts, m.get(metric)) for ts, m in d if ts >= cut and m.get(metric) is not None]

    async def evaluate(self) -> dict:
        t0 = time.time()
        result: dict[str, Any] = {"ts": t0, "rules": {}, "changes": 0}
        fresh_cut = t0 - self.store.interval * 3
        live = [e for e, d in self.store.recent.items() if d and d[-1][0] >= fresh_cut]
        for rid, r in list(self.rules.items()):
            if not r.get("enabled", True):
                for k in [k for k in self.state if k[0] == rid]:
                    self._change(r, k[1], None, None, "규칙 꺼짐")
                continue
            verdict = await self.verdicts(r, live, t0)
            n_alert = 0
            for e, (sev, val, msg) in verdict.items():
                cur = self.state.get((rid, e))
                if (cur or {}).get("sev") != sev:
                    if sev and not cur and result["changes"] >= self.max_alerts:
                        continue                               # 한 번에 폭주 방지(다음 주기에 이어서)
                    self._change(r, e, sev, val, msg)
                    result["changes"] += 1
                elif cur and sev:
                    cur.update(value=val, msg=msg, peak=max(cur.get("peak") or val or 0, val or 0) if r.get("op", "above") == "above" else cur.get("peak"))
                if sev:
                    n_alert += 1
            for k in [k for k in self.state if k[0] == rid and k[1] not in verdict]:
                self._change(r, k[1], None, None, "규칙 범위 밖이거나 판정할 데이터 부족")     # 범위 변경·꺼짐·삭제·수집 중단
            result["rules"][rid] = {"evaluated": len(verdict), "alerting": n_alert}
        await self.flush()
        result["ms"] = int((time.time() - t0) * 1000)
        self.last_eval = result
        return result

    async def flush(self) -> None:
        if not self._pending:
            return
        todo, self._pending = self._pending, []

        def run() -> None:
            with self.store._mu:
                for sql, p in todo:
                    self.store._db.execute(sql, p)
                self.store._db.commit()
        await asyncio.to_thread(run)

    async def verdicts(self, r: dict, live: list[int] | None = None, t0: float | None = None) -> dict[int, tuple[str | None, float | None, str]]:
        """규칙 하나의 엔티티별 판정 {eid: (경고 수준|None, 값, 설명)} — 상태를 바꾸지 않음(미리 보기에도 사용)"""
        t0 = t0 or time.time()
        if live is None:
            live = [e for e, d in list(self.store.recent.items()) if d and d[-1][0] >= t0 - self.store.interval * 3]
        ents = await asyncio.to_thread(lambda: [e for e in live if self._scope(r, e)])     # 사용자 정규식은 루프 밖에서
        verdict: dict[int, tuple[str | None, float | None, str]] = {}
        need = max(1, int(r["window"] * 60 // self.store.interval))
        min_n = max(2, math.ceil(need * 0.8))                       # 창의 80% 이상 표본이 있어야 판정(기동 직후·새 VM)
        held = lambda e: (self.state.get((r["id"], e)) or {}).get("sev")  # noqa: E731  — 진행 중 경보(회복 히스테리시스)
        if r["type"] == "threshold":
            for e in ents:
                w = self._window(e, r["window"], r["metric"])
                if len(w) < min_n:
                    continue
                avg = sum(v for _, v in w) / len(w)
                above = r.get("op", "above") == "above"
                hit = lambda x, m=1.0: x is not None and (avg >= x * m if above else avg <= x / m)  # noqa: E731
                sev = "critical" if hit(r.get("crit")) else "warning" if hit(r.get("warn")) else None
                if not sev and held(e) and hit(r.get("warn") if r.get("warn") is not None else r.get("crit"), 0.95):
                    sev = "warning"                                 # 경계값 5% 안쪽이면 경보 유지(깜빡임 방지)
                verdict[e] = (sev, avg, f"{MLABEL[r['metric']]} {r['window']}분 평균 {fmt(r['metric'], avg)} "
                                        f"({'≥' if above else '≤'} {fmt(r['metric'], r.get('crit') if sev == 'critical' else r.get('warn'))})" if sev else "")
        elif r["type"] == "anomaly":
            bl = await self.baselines(r["metric"], t0)
            for e in ents:
                b = bl.get(e)
                w = self._window(e, r["window"], r["metric"])
                if not b or len(w) < min_n:
                    continue
                lo, hi = band(r["metric"], b[0], b[1], r["k"])
                amin = ABS_MIN.get(r["metric"], 0)
                out = [v for _, v in w if (v > hi and r["direction"] in ("above", "both") and v >= amin) or
                       (v < lo and r["direction"] in ("below", "both") and lo >= amin)]      # 아래로: 평소에도 의미 있는 값일 때만(야간 저부하 잡음 방지)
                pct = len(out) * 100 / len(w)
                last = w[-1][1]
                sev = r.get("sev", "warning") if pct >= r["pct"] or (held(e) and pct >= r["pct"] / 2) else None
                verdict[e] = (sev, last, f"{MLABEL[r['metric']]} {fmt(r['metric'], last)} — 평소 범위 {fmt(r['metric'], lo)}~{fmt(r['metric'], hi)}"
                                         f"({ {'weekly': '주', 'daily': '일', 'basic': '최근 24시간'}[b[2]] } 기준, 최근 {r['window']}분 중 {pct:.0f}% 밖)" if sev else "")
        else:                                              # outlier — 클러스터별
            groups: dict[str, list[int]] = {}
            for e in ents:
                groups.setdefault(f"{self.store.ents[e]['vc']}|{self.store.ents[e].get('cluster') or ''}", []).append(e)
            for g, members in groups.items():
                if len(members) < 3 or not g.split("|", 1)[1]:
                    continue
                series = {e: dict(self._window(e, r["window"], r["metric"])) for e in members}
                tss = sorted({t for s in series.values() for t in s})
                flags: dict[int, list[bool]] = {e: [] for e in members}
                for t in tss:
                    vals = {e: s[t] for e, s in series.items() if t in s}
                    if len(vals) < 3:
                        continue
                    m, sd = robust(list(vals.values()))
                    width = r["tolerance"] * max(sd, FLOOR.get(r["metric"], 0.0), REL_FLOOR.get(r["metric"], 0.0) * abs(m))
                    for e, v in vals.items():
                        up = v - m > width and v >= ABS_MIN.get(r["metric"], 0)
                        flags[e].append(up or (r.get("direction") == "both" and m - v > width))
                for e, fl in flags.items():
                    if len(fl) < min_n:
                        continue
                    pct = sum(fl) * 100 / len(fl)
                    last = list(series[e].values())[-1] if series[e] else None
                    peers = [list(series[x].values())[-1] for x in members if x != e and series[x]]
                    sev = r.get("sev", "warning") if pct >= r["pct"] or (held(e) and pct >= r["pct"] / 2) else None
                    verdict[e] = (sev, last, f"{MLABEL[r['metric']]} {fmt(r['metric'], last)} — 같은 클러스터 {len(members)}대 중앙값 "
                                             f"{fmt(r['metric'], median(peers) if peers else None)} 와 다름(최근 {r['window']}분 중 {pct:.0f}%)" if sev else "")
        return verdict

    def _change(self, r: dict, eid: int, sev: str | None, val: float | None, msg: str) -> None:
        key = (r["id"], eid)
        cur = self.state.get(key)
        e = self.store.ents.get(eid) or {"kind": r["kind"], "name": str(eid), "vc": ""}
        now = time.time()
        if sev:
            if cur:
                cur.update(sev=sev, value=val, msg=msg)
            else:
                self.state[key] = {"sev": sev, "since": now, "value": val, "peak": val, "msg": msg}
                self._pending.append(("INSERT INTO perf_alerts(rule, eid, sev, start, peak, msg) VALUES(?,?,?,?,?,?)", (r["id"], eid, sev, now, val, msg[:300])))
            self._pending.append(("UPDATE perf_alerts SET sev=?, msg=? WHERE rule=? AND eid=? AND end IS NULL", (sev, msg[:300], r["id"], eid)))
            text = f"[성능] {r['name']}: {e['name']} — {msg}"
            self._emit(r, e, "critical" if sev == "critical" else "warning", text, False)
        elif cur:
            self.state.pop(key, None)
            self._pending.append(("UPDATE perf_alerts SET end=?, peak=COALESCE(?, peak) WHERE rule=? AND eid=? AND end IS NULL", (now, cur.get("peak"), r["id"], eid)))
            self._emit(r, e, "info", f"[성능] {r['name']} 정상화: {e['name']} ({msg or '정상 범위'})", True)

    def _emit(self, r: dict, e: dict, sev: str, text: str, recovered: bool) -> None:
        try:
            self.e.submit(LogEvent(source="aiops", connector="perfmon", message=text, severity=sev, host=e["name"] if e["kind"] == "host" else (e.get("host") or e["name"]),
                                   entity=f"perf:{r['id']}:{e['kind']}:{e['name']}", kind="alert",
                                   attrs={"rule": r["id"], "metric": r["metric"], "type": r["type"], "recovered": recovered, "vm" if e["kind"] == "vm" else "esxi": e["name"]}))
        except Exception as ex:  # noqa: BLE001
            print(f"[perfwatch] 이벤트 실패: {ex}", flush=True)

    # ------------------------------------------------------------------ 조회
    def alerts_now(self) -> list[dict]:
        out = []
        for (rid, eid), s in self.state.items():
            r, e = self.rules.get(rid) or {}, self.store.ents.get(eid) or {}
            out.append({"rule": rid, "rule_name": r.get("name", rid), "type": r.get("type"), "metric": r.get("metric"), "kind": e.get("kind"),
                        "name": e.get("name"), "vcenter": e.get("vc"), "cluster": e.get("cluster"), "host": e.get("host"), **s})
        return sorted(out, key=lambda x: (x["sev"] != "critical", -x["since"]))

    async def history(self, hours: float = 24, eid: int | None = None) -> list[dict]:
        rows = await self.store.q("SELECT rule, eid, sev, start, end, peak, msg FROM perf_alerts WHERE (end IS NULL OR end >= ?)" +
                                  (" AND eid=?" if eid else "") + " ORDER BY start DESC LIMIT 500",
                                  (time.time() - hours * 3600, eid) if eid else (time.time() - hours * 3600,))
        out = []
        for rid, e, sev, start, end, peak, msg in rows:
            ent = self.store.ents.get(e) or {}
            out.append({"rule": rid, "rule_name": (self.rules.get(rid) or {}).get("name", rid), "kind": ent.get("kind"), "name": ent.get("name"),
                        "vcenter": ent.get("vc"), "sev": sev, "start": start, "end": end, "peak": peak, "msg": msg})
        return out

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.to_thread(self.store.warm)
        await asyncio.sleep(30)
        last_roll = 0.0
        while True:
            beat()
            if self.store.enabled:
                try:
                    st = await self.sample()
                    ev = await self.evaluate()
                    if time.time() - last_roll > 600:
                        await asyncio.to_thread(self.store.rollup)
                        await self.store.q("DELETE FROM perf_alerts WHERE end IS NOT NULL AND end < ?", (time.time() - self.store.ret1 * 86400,))
                        last_roll = time.time()
                    print(f"[perfwatch] 표본 {st['count']}대 {st['ms']}ms · 규칙 평가 {ev['ms']}ms · 경보 {len(self.state)}건(변화 {ev['changes']})"
                          + (f" · 오류 {st['errors']}" if st["errors"] else ""), flush=True)
                except Exception as ex:  # noqa: BLE001
                    print(f"[perfwatch] 오류: {type(ex).__name__}: {ex}", flush=True)
            nxt = (time.time() // self.store.interval + 1) * self.store.interval + 15          # 다음 칸 + 15초
            while time.time() < nxt:
                beat()
                await asyncio.sleep(min(60, max(1, nxt - time.time())))
