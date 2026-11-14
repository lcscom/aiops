"""수집 현황 모니터 — 항목별로 로그가 '실제로 들어오고 있는지' 판정한다.

항목 단위
  conn:<커넥터>      API 폴링 커넥터 (vCenter·NSX·VCF Ops …)  → API 상태 + 이벤트 유입
  syslog:<호스트>    syslog 송신 장비별                      → 마지막 수신 후 경과시간
  snmp:<송신IP>      SNMP 트랩 송신 장비별                   → 트랩은 간헐적이라 기본 '대기', 기대값 지정 시 침묵 감시
  ingest:<호스트>    HTTP /api/ingest 송신자별
  recv:<수신기>      syslog/SNMP 수신기 자체(포트 바인드 상태)

상태
  collecting 수집 중 · idle 정상(신규 없음) · delayed 지연 · stopped 중단 · down 오류 · never 미수신(기대 장비)
수집 중단/복구 전환 시 내부 이벤트(source=aiops)를 만들어 기존 탐지·알림 파이프라인으로 보낸다.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from typing import Any, Awaitable, Callable

from .models import LogEvent

LABEL = {"collecting": "수집 중", "idle": "정상·신규 없음", "delayed": "지연", "stopped": "중단",
         "down": "오류", "never": "미수신"}
RANK = {"down": 5, "never": 4, "stopped": 4, "delayed": 3, "idle": 1, "collecting": 0}
SELF_CONNECTOR = "collection-monitor"


class _Item:
    __slots__ = ("key", "kind", "name", "source", "target", "first", "last", "total", "buckets", "last_msg",
                 "last_sev", "err15", "sources", "expected", "max_silence", "status", "reason")

    def __init__(self, key: str, kind: str, name: str, target: str = "", source: str = ""):
        self.key, self.kind, self.name, self.target, self.source = key, kind, name, target, source
        self.first = 0.0
        self.last = 0.0
        self.total = 0
        self.buckets: deque[list[int]] = deque(maxlen=60)    # [epoch_minute, count] 최근 60분
        self.last_msg = ""
        self.last_sev = ""
        self.err15: deque[float] = deque(maxlen=500)          # error 이상 수신 시각
        self.sources: set[str] = set()
        self.expected = False
        self.max_silence = 0
        self.status = "idle"
        self.reason = ""

    def hit(self, ev: LogEvent, now: float) -> None:
        m = int(now // 60)
        if self.buckets and self.buckets[-1][0] == m:
            self.buckets[-1][1] += 1
        else:
            self.buckets.append([m, 1])
        if not self.first:
            self.first = now
        self.last = now
        self.total += 1
        self.last_msg = ev.message[:240]
        self.last_sev = ev.severity
        self.sources.add(ev.source)
        if ev.severity in ("error", "critical"):
            self.err15.append(now)

    def spark(self, now: float, minutes: int = 30) -> list[int]:
        cur = int(now // 60)
        d = {m: c for m, c in self.buckets}
        return [d.get(cur - i, 0) for i in range(minutes - 1, -1, -1)]

    def rate(self, now: float, minutes: int) -> float:
        """최근 N분 분당 유입(슬라이딩 창 근사: 진행 중인 분 + 직전 분의 남은 비율)."""
        cur = int(now // 60)
        frac = (now % 60) / 60
        d = {m: c for m, c in self.buckets}
        total = d.get(cur, 0) + sum(d.get(cur - i, 0) for i in range(1, minutes)) + d.get(cur - minutes, 0) * (1 - frac)
        return round(total / minutes, 2)


class CollectionMonitor:
    def __init__(self, cfg: dict, emit: Callable[[LogEvent], Awaitable[None]]):
        self.emit = emit
        self.items: dict[str, _Item] = {}
        self.started = time.time()
        self._prev: dict[str, str] = {}
        self.configure(cfg)

    def configure(self, cfg: dict) -> None:
        """설정 화면 핫리로드 — 수집 이력은 유지하고 기대 장비·침묵 기준만 다시 적용"""
        self.cfg = cfg or {}
        self.active_window = float(self.cfg.get("active_window", 300))
        self.default_silence: dict[str, int] = {"syslog": 900, "ingest": 900, "snmp": 0, "conn": 0, "vcflogs": 600,
                                                **(self.cfg.get("max_silence") or {})}
        self.expected = []
        for e in self.cfg.get("expected") or []:
            try:
                self.expected.append({**e, "rx": re.compile(str(e["match"]), re.I)})
            except (KeyError, re.error):
                continue
        keys = set()
        for e in self.expected:                       # 기대 장비는 수신 전에도 목록에 표시(미수신 감지)
            key = f"exp:{e.get('kind', 'syslog')}:{e.get('name', e['match'])}"
            keys.add(key)
            it = self.items.get(key) or _Item(key, e.get("kind", "syslog"), e.get("name", e["match"]), str(e["match"]))
            self.items[key] = it
            it.expected = True
            it.max_silence = int(e.get("max_silence", self.default_silence.get(it.kind, 900)))
        for k in [k for k, v in self.items.items() if k.startswith("exp:") and k not in keys]:
            self.items.pop(k, None)

    # ------------------------------------------------------------------ 기록
    def _key(self, ev: LogEvent) -> tuple[str, str, str, str]:
        """(key, kind, name, target)"""
        a = ev.attrs or {}
        if ev.connector == "syslog":
            h = ev.host or a.get("peer", "?")
            return f"syslog:{h.lower()}", "syslog", h, a.get("peer", "")
        if ev.connector.startswith("snmp"):
            p = a.get("peer") or ev.host
            return f"snmp:{p}", "snmp", ev.host if ev.host and ev.host != p else p, p
        if ev.connector == "ingest":
            return f"ingest:{(ev.host or '?').lower()}", "ingest", ev.host, a.get("peer", "")
        if ev.connector == "agent":                 # Fluent Bit 에이전트 — 침묵 감시는 에이전트 레지스트리(하트비트 기준)가 담당
            return f"agent:{(ev.host or '?').lower()}", "agent", ev.host, a.get("peer", "")
        return f"conn:{ev.connector}", "conn", ev.connector, ""

    def _match_expected(self, kind: str, *vals: str) -> _Item | None:
        for e in self.expected:
            if e.get("kind", "syslog") != kind:
                continue
            if any(v and e["rx"].search(v) for v in vals):
                return self.items.get(f"exp:{kind}:{e.get('name', e['match'])}")
        return None

    def record(self, ev: LogEvent) -> None:
        if ev.connector in (SELF_CONNECTOR, "platform-health", "agent-monitor"):
            return
        now = time.time()
        key, kind, name, target = self._key(ev)
        exp = self._match_expected(kind, ev.host, target, name) if self.expected else None
        if exp is not None:
            exp.hit(ev, now)
            if not exp.target or exp.target == exp.name:
                exp.target = target or ev.host
            return
        it = self.items.get(key)
        if it is None:
            it = self.items[key] = _Item(key, kind, name, target, ev.source)
            it.max_silence = int(self.default_silence.get(kind, 0))
            if len(self.items) > 5000:                # 상한 — 오래된 미활동 항목 정리
                for k in sorted(self.items, key=lambda k: self.items[k].last)[:500]:
                    if not self.items[k].expected:
                        self.items.pop(k, None)
        it.hit(ev, now)

    # ------------------------------------------------------------------ 판정
    def _evaluate(self, it: _Item, now: float, conn_state: dict | None) -> None:
        silence = now - it.last if it.last else None
        recent = silence is not None and silence <= self.active_window
        if it.kind == "conn" and conn_state is not None:
            st = conn_state.get("state")
            if st == "disabled":
                it.status, it.reason = "idle", "비활성화됨"
            elif st == "down":
                it.status, it.reason = "down", conn_state.get("last_error") or "API 접속 실패"
            elif st == "degraded":
                it.status, it.reason = "delayed", conn_state.get("last_error") or "최근 폴링 실패"
            elif st == "init":
                it.status, it.reason = "delayed", "첫 폴링 대기"
            elif recent:
                it.status, it.reason = "collecting", "API 정상 · 이벤트 유입"
            else:
                it.status, it.reason = "idle", "API 정상 · 신규 이벤트 없음(알람·작업 발생 시 수집)"
            if it.max_silence and silence is not None and silence > it.max_silence and st == "ok":
                it.status, it.reason = "stopped", f"API는 정상이나 {int(silence // 60)}분간 이벤트 없음"
            return
        if it.kind == "recv":
            return
        if silence is None:
            if it.expected:
                grace = max(30.0, min(it.max_silence or 900, 900))
                it.status = "never" if now - self.started > grace else "idle"
                it.reason = "기대 장비 — 아직 수신 이력 없음" if it.status == "never" else "기동 직후 대기"
            else:
                it.status, it.reason = "idle", "-"
            return
        ms = it.max_silence
        if ms and silence > ms:
            it.status, it.reason = "stopped", f"{self._dur(silence)}간 수신 없음 (허용 {self._dur(ms)})"
        elif ms and silence > ms / 2:
            it.status, it.reason = "delayed", f"{self._dur(silence)}간 수신 없음"
        elif recent:
            it.status, it.reason = "collecting", "정상 수신"
        else:
            it.status = "idle"
            it.reason = "간헐 수신(트랩)" if it.kind == "snmp" else f"마지막 수신 {self._dur(silence)} 전"

    @staticmethod
    def _dur(sec: float) -> str:
        sec = int(sec)
        if sec < 60:
            return f"{sec}초"
        if sec < 3600:
            return f"{sec // 60}분"
        return f"{sec // 3600}시간 {sec % 3600 // 60}분"

    def snapshot(self, connectors: list[Any]) -> dict[str, Any]:
        now = time.time()
        states = {c.name: c.state() for c in connectors}
        rows: list[dict[str, Any]] = []
        # API 커넥터: 이벤트가 0건이어도 목록에 표시
        for c in connectors:
            if c.type in ("syslog", "snmp", "demo"):
                continue
            key = f"conn:{c.name}"
            it = self.items.get(key)
            if it is None:
                it = self.items[key] = _Item(key, "conn", c.name, states[c.name].get("target", ""), c.source)
                it.max_silence = int(self.default_silence.get(c.type, 0))   # 연속 로그형(vcflogs)만 침묵 감시
            it.target = states[c.name].get("target", "") or it.target
            it.source = c.type
        for it in list(self.items.values()):
            self._evaluate(it, now, states.get(it.name) if it.kind == "conn" else None)
            rows.append(self._row(it, now, states.get(it.name) if it.kind == "conn" else None))
        # 수신기 자체(포트 바인드)
        for c in connectors:
            if c.type in ("syslog", "snmp"):
                s = states[c.name]
                st = "down" if s.get("state") in ("down", "degraded") else "collecting" if s.get("events_total") else "idle"
                rows.append({"key": f"recv:{c.name}", "kind": "recv", "name": c.name, "target": s.get("target", ""),
                             "source": c.type, "status": st, "label": LABEL[st],
                             "reason": s.get("last_error") or ("포트 수신 대기 중" if st == "idle" else "수신 중"),
                             "last": s.get("last_ok"), "ago": None, "total": s.get("events_total", 0),
                             "rate1": None, "rate15": None, "spark": [], "err15": 0, "last_msg": "",
                             "expected": False, "max_silence": 0, "api": s.get("state")})
        rows.sort(key=lambda r: (-RANK.get(r["status"], 0), r["kind"], r["name"]))
        summary = {k: 0 for k in LABEL}
        for r in rows:
            summary[r["status"]] = summary.get(r["status"], 0) + 1
        problems = sum(summary[k] for k in ("delayed", "stopped", "down", "never"))
        return {"generated": now, "summary": summary, "problems": problems, "total": len(rows), "items": rows,
                "active_window": self.active_window}

    def _row(self, it: _Item, now: float, conn: dict | None) -> dict[str, Any]:
        return {"key": it.key, "kind": it.kind, "name": it.name, "target": it.target,
                "source": it.source or ",".join(sorted(it.sources)), "status": it.status, "label": LABEL[it.status],
                "reason": it.reason, "last": it.last or None, "ago": round(now - it.last, 1) if it.last else None,
                "total": it.total, "rate1": it.rate(now, 1), "rate15": it.rate(now, 15), "spark": it.spark(now),
                "err15": sum(1 for t in it.err15 if now - t < 900), "last_msg": it.last_msg, "last_sev": it.last_sev,
                "expected": it.expected, "max_silence": it.max_silence,
                "api": (conn or {}).get("state"), "latency_ms": (conn or {}).get("latency_ms"),
                "last_poll": (conn or {}).get("last_ok")}

    def summary(self) -> dict[str, Any]:
        s = {k: 0 for k in LABEL}
        for it in self.items.values():
            s[it.status] = s.get(it.status, 0) + 1
        return {"summary": s, "problems": sum(s[k] for k in ("delayed", "stopped", "down", "never")),
                "total": len(self.items)}

    # ------------------------------------------------------------------ 중단/복구 알림
    async def watch(self, connectors_fn: Callable[[], list[Any]]) -> None:
        await asyncio.sleep(30)
        while True:
            snap = self.snapshot(connectors_fn())
            if self.cfg.get("alert_on_stop", True):
                for r in snap["items"]:
                    if r["kind"] == "recv":
                        continue
                    prev = self._prev.get(r["key"], "idle")    # 첫 점검에서 이미 장애인 항목도 알림
                    cur = r["status"]
                    self._prev[r["key"]] = cur
                    if prev == cur:
                        continue
                    bad = cur in ("stopped", "down", "never")
                    was_bad = prev in ("stopped", "down", "never")
                    if bad and not was_bad:
                        await self.emit(LogEvent(
                            source="aiops", connector=SELF_CONNECTOR, kind="health", severity="error",
                            host=r["name"], entity=f"collection:{r['key']}",
                            message=f"수집 {r['label']}: {r['name']} ({r['kind']}) — {r['reason']}"))
                    elif was_bad and cur in ("collecting", "idle"):
                        await self.emit(LogEvent(
                            source="aiops", connector=SELF_CONNECTOR, kind="health", severity="info",
                            host=r["name"], entity=f"collection:{r['key']}",
                            message=f"수집 복구: {r['name']} ({r['kind']}) — {r['reason']}"))
            await asyncio.sleep(float(self.cfg.get("check_interval", 30)))
