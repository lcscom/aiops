"""플랫폼 자체 감시 — 실시간 처리 여유·저장·내부 작업·외부 의존·이중화 상태를 5초마다 점검.

- 상태가 바뀔 때만(정상→이상, 이상→정상) 내부 이벤트(source=aiops)를 발생시켜 일반 이상징후와 같은 경로로
  화면·인시던트·알림에 올린다. 정상화되면 해당 이상징후를 시스템이 자동 확인 처리한다.
- ready(): /readyz·HA 상대 노드 판단용. 내부 핵심 작업 정지, DB 쓰기 장기 실패, 이벤트 루프 심각 지연이면 not ready.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from .models import LogEvent

SELF = "platform-health"
LEVEL_RANK = {"warning": 1, "error": 2, "critical": 3}


class HealthMonitor:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.lag_warn = float(c.get("loop_lag_warn_ms", 500))
        self.lag_crit = float(c.get("loop_lag_crit_ms", 2000))
        self.ready_lag = float(c.get("ready_lag_ms", 5000))
        self.pipe_lag_warn = float(c.get("pipeline_lag_warn_s", 30))
        self.outbox_delay_warn = float(c.get("outbox_delay_warn_s", 600))
        self.state: dict[str, Any] = {"state": "ok", "issues": [], "checked": 0.0}
        self.active: dict[str, dict] = {}
        self._last = {"dropped": 0, "dead": 0, "kicked": 0, "logs_dropped": 0}
        self._started = time.time()

    # ---------------------------------------------------------------- 판정
    def _checks(self) -> list[dict]:
        e, out = self.e, []
        add = lambda key, level, text: out.append({"key": key, "level": level, "text": text})   # noqa: E731
        lag = e.lag.stats()
        if time.time() - self._started > 30:            # 기동 직후(팩 적재 등) 지연은 제외
            if lag["p99_ms"] >= self.lag_crit:
                add("loop_lag", "error", f"이벤트 루프 지연 p99 {lag['p99_ms']:.0f}ms — 실시간 처리 여유 부족(CPU 포화 의심)")
            elif lag["p99_ms"] >= self.lag_warn:
                add("loop_lag", "warning", f"이벤트 루프 지연 p99 {lag['p99_ms']:.0f}ms")
        p = e.pipe
        dropped = p["dropped_low"] + p["dropped_high"]
        if dropped > self._last["dropped"]:
            lvl = "error" if p["dropped_high"] else "warning"
            add("pipeline_drop", lvl, f"수집 과부하 — 최근 {dropped - self._last['dropped']:,}건 처리 전 폐기"
                                      f"(일반 {p['dropped_low']:,} / 우선 {p['dropped_high']:,} 누적)")
        backlog = len(e.q_hi) + len(e.q_lo)
        if backlog > e.q_lo_max // 2:
            add("pipeline_backlog", "warning", f"처리 대기 {backlog:,}건 — 수집량이 처리량을 넘음")
        if p["lag_ms"] / 1000 > self.pipe_lag_warn and backlog > 1000:
            add("pipeline_lag", "warning", f"수집→처리 지연 {p['lag_ms'] / 1000:.0f}초")
        st = e.store.stats
        if st["state"] == "error" and e.store.backlog:
            add("store_write", "critical", f"DB 쓰기 실패 — {st['last_error'][:160]}")
        if st["disk_low"]:
            add("disk_low", "error", f"디스크 여유 {st['disk_free_mb']}MB — 원본 로그 저장 중지(이상징후·감사는 계속)")
        if st["logs_dropped"] > self._last["logs_dropped"]:
            add("store_drop", "warning", f"DB 저장 지연으로 원본 로그 {st['logs_dropped'] - self._last['logs_dropped']:,}건 미저장")
        bad = e.sup.unhealthy()
        if bad:
            add("supervisor", "critical", f"내부 작업 정지·재기동 반복: {', '.join(bad)}")
        if e.llm and e.llm_breaker.state == "open":
            add("llm", "warning", f"LLM 응답 없음 — 규칙 탐지로 운영 중({e.llm_breaker.last_error[:120]})")
        aq = getattr(e, "aq", None)
        if e.llm and aq and len(aq.items) >= aq.shed_at:
            add("ai_backlog", "warning", f"AI 분석 대기 {aq.depth():,}건 — warning 이하 신규는 규칙 탐지로만 처리(부하 차단)")
        ob = e.alerter.ob
        if ob["dead"] > self._last["dead"]:
            add("outbox_dead", "error", f"알림 발송 최종 실패 {ob['dead'] - self._last['dead']}건 — 알림 채널 점검 필요")
        if ob["oldest_pending"] > self.outbox_delay_warn and (not e.ha or e.ha.is_leader()):
            add("outbox_delay", "warning", f"외부 알림 발송 지연 {ob['oldest_pending'] / 60:.0f}분(대기 {ob['pending']}건)")
        if e.ha and e.ha.enabled:
            if e.ha.peer["state"] in ("down", "not_ready"):
                add("ha_peer", "warning", f"이중화 상대 노드 이상 — {e.ha.peer['last_error'][:140]}")
            if e.ha.role == "standby" and e.ha.leader:
                add("ha_takeover", "warning", "대기 노드가 알림 리더로 동작 중(primary 복구 확인 필요)")
        sc = getattr(e, "selfcheck", None)
        if sc:
            try:
                out += sc.checks()                     # DB 무결성·WAL·백업·메모리·fd·인증서(2.2)
            except Exception as ex:  # noqa: BLE001
                add("selfcheck", "warning", f"자가 점검 오류: {type(ex).__name__}: {ex}")
        self._last.update(dropped=dropped, dead=ob["dead"], logs_dropped=st["logs_dropped"])
        return out

    def ready(self) -> tuple[bool, list[str]]:
        e, why = self.e, []
        bad = e.sup.unhealthy()
        if bad:
            why.append("내부 작업 정지: " + ", ".join(bad))
        st = e.store.stats
        if st["state"] == "error" and e.store.backlog and time.time() - st["last_write"] > 60:
            why.append("DB 쓰기 60초 이상 실패")
        if e.lag.stats()["p99_ms"] >= self.ready_lag:
            why.append(f"이벤트 루프 지연 p99 {e.lag.stats()['p99_ms']:.0f}ms")
        return (not why), why

    # ---------------------------------------------------------------- 루프
    async def loop(self, beat=lambda: None) -> None:
        while True:
            await asyncio.sleep(5)
            beat()
            try:
                issues = self._checks()
            except Exception as ex:  # noqa: BLE001
                print(f"[health] 점검 오류: {type(ex).__name__}: {ex}", flush=True)
                continue
            now = time.time()
            cur = {i["key"]: i for i in issues}
            for k, i in cur.items():                                  # 신규·등급 상향 → 이벤트
                prev = self.active.get(k)
                if not prev or LEVEL_RANK[i["level"]] > LEVEL_RANK[prev["level"]]:
                    self._emit(i, recovered=False)
                i["since"] = prev["since"] if prev else now
            for k, prev in list(self.active.items()):                  # 해소 → 정상화 이벤트 + 자동 확인
                if k not in cur:
                    if k in ("pipeline_drop", "store_drop", "outbox_dead") and now - prev["since"] < 60:
                        cur[k] = prev                                  # 증가형 지표는 1분간 유지(깜빡임 방지)
                        continue
                    self._emit(prev, recovered=True)
                    await self._auto_ack(k)
            self.active = cur
            worst = max((LEVEL_RANK[i["level"]] for i in cur.values()), default=0)
            self.state = {"state": "down" if worst >= 2 else "warn" if worst == 1 else "ok",
                          "issues": sorted(cur.values(), key=lambda i: -LEVEL_RANK[i["level"]]), "checked": now}

    def _emit(self, i: dict, recovered: bool) -> None:
        node = self.e.ha.node if self.e.ha else ""
        if recovered:
            msg, sev = f"플랫폼 정상화: {i['text']}", "info"
        else:
            msg = f"플랫폼 {'장애' if LEVEL_RANK[i['level']] >= 2 else '경고'}: {i['text']}"
            sev = i["level"]
        self.e.submit(LogEvent(source="aiops", connector=SELF, message=msg, severity=sev, host=node or "aiops",
                               entity=f"platform:{i['key']}", kind="health", attrs={"check": i["key"], "recovered": recovered}))

    async def _auto_ack(self, key: str) -> None:
        for a in list(self.e.anomalies.values()):
            if not a.ack and (a.event or {}).get("entity") == f"platform:{key}":
                await self.e.ack(a.id)
