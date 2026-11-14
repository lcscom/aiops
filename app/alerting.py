"""알림 — 대시보드(WebSocket 토스트/브라우저 알림) + 웹훅(Slack/Teams/일반 JSON) + SMTP 메일.
fingerprint 단위 cooldown으로 중복 알림 억제.

외부 채널(웹훅·메일)은 내구성 있는 발송함(outbox, SQLite)을 거친다.
- 알림 생성 즉시 outbox 에 기록 → 발송 워커가 전송. 실패 시 30초·2분·5분·15분·30분… 지수 백오프로 재시도,
  alerting.max_attempts(기본 8회) 초과 시 'dead'(발송 실패함)로 옮기고 화면·감사·메트릭에 노출.
- 서비스가 재기동돼도 미발송 건은 이어서 보낸다. 채널별 서킷 브레이커로 죽은 채널이 다른 채널을 늦추지 않는다.
- 이중화(HA) 구성에서는 알림 리더 노드만 발송한다(대기 노드는 기록만 하고, 리더 인계 시 미발송분을 이어받지 않도록
  primary 의 마지막 정상 응답 이전에 생성된 건은 'skipped_standby' 로 정리 — 같은 알림을 두 번 보내지 않기 위함).
"""
from __future__ import annotations

import asyncio
import json
import random
import re
import smtplib
import time
from collections import deque
from email.mime.text import MIMEText
from typing import Any, Awaitable, Callable

import httpx

from .models import SEV_RANK
from .runtime import Breaker, bg

OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, created REAL, channel TEXT, ref TEXT,
  title TEXT, payload TEXT, state TEXT, attempts INTEGER DEFAULT 0, next_at REAL, last_error TEXT, sent_at REAL);
CREATE INDEX IF NOT EXISTS ix_outbox_state ON outbox(state, next_at);
"""
RETRY = [30, 120, 300, 900, 1800, 3600, 3600, 3600]


class Alerter:
    def __init__(self, cfg: dict, save: Callable[[str, str, bool, str], Awaitable[None]],
                 broadcast: Callable[[dict], Awaitable[None]]):
        self.cfg = cfg
        self.save = save
        self.broadcast = broadcast
        self.last: dict[str, float] = {}
        self.http = httpx.AsyncClient(timeout=10, verify=False)
        self.sent_total = 0
        self.recent: deque[dict] = deque(maxlen=200)   # 폴링형 외부 연동용
        self.store = None                              # Engine 이 bind_store() 로 연결(outbox)
        self.is_leader: Callable[[], bool] = lambda: True
        self.breakers: dict[str, Breaker] = {}
        self._wake = asyncio.Event()
        self.ob = {"queued": 0, "sent": 0, "retry": 0, "dead": 0, "pending": 0, "oldest_pending": 0.0}
        self.on_fire = None                            # SIEM 등 동기 훅(a)
        self._last_purge = 0.0

    def bind_store(self, store) -> None:
        self.store = store
        store.schema(OUTBOX_SCHEMA)

    def should_alert(self, a: dict[str, Any], fp: str) -> bool:
        if a.get("ack"):
            return False
        if SEV_RANK.get(a["severity"], 0) < SEV_RANK.get(self.cfg.get("min_severity", "error"), 3):
            return False
        if self.cfg.get("require_llm_confirm") and a.get("status") != "analyzed":
            return False
        if a.get("ai") and a["ai"].get("is_anomaly") is False:
            return False
        if time.time() - self.last.get(fp, 0) < float(self.cfg.get("cooldown", 900)):
            return False
        return True

    async def fire(self, a: dict[str, Any], fp: str) -> None:
        self.last[fp] = time.time()
        self.sent_total += 1
        ev = a["event"]
        ai = a.get("ai") or {}
        title = f"[{a['severity'].upper()}] {a['title']}"
        lines = [
            f"소스: {ev['source']} ({ev['connector']})  대상: {ev.get('entity') or ev.get('host') or '-'}",
            f"시각: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev['ts']))}  재발: {a.get('count', 1)}회",
            f"로그: {ev['message'][:500]}",
        ]
        if ai:
            lines += [f"AI 요약: {ai.get('summary', '')}", f"추정 원인: {ai.get('probable_cause', '')}"]
            for i, s in enumerate(ai.get("actions", [])[:5], 1):
                lines.append(f"  {i}. {s}")
            for r in (ai.get("references") or [])[:3]:
                vv = r.get("versions") or []
                lines.append(f"근거: {r.get('title', '')}{' (적용 ' + '/'.join(vv[:3]) + ')' if vv else ''} {r.get('url', '')}".strip())
        else:
            lines.append("탐지 사유: " + ", ".join(a.get("reasons", [])))
        body = "\n".join(lines)

        payload = {"anomaly_id": a["id"], "title": title, "severity": a["severity"], "body": body,
                   "ts": time.time(), "seq": self.sent_total}
        self.recent.append(payload)
        await self.broadcast({"type": "alert", "data": payload})
        await self.save(a["id"], "dashboard", True, title)
        if self.on_fire:
            try:
                self.on_fire(a)
            except Exception:  # noqa: BLE001
                pass
        await self._enqueue(a, title, body)

    async def notify_text(self, title: str, body: str, severity: str = "warning", ref: str = "") -> None:
        """이상징후가 아닌 시스템 알림(SLA 초과·조치 승인 요청 등) — 같은 채널로 전송"""
        self.sent_total += 1
        fake = {"id": ref or "system", "severity": severity, "title": title, "event": {}, "reasons": []}
        payload = {"anomaly_id": ref, "title": title, "severity": severity, "body": body, "ts": time.time(), "seq": self.sent_total}
        self.recent.append(payload)
        await self.broadcast({"type": "alert", "data": payload})
        await self._enqueue(fake, title, body)

    # ---------------------------------------------------------------- outbox
    def _channels(self, a: dict | None = None) -> list[tuple[str, dict]]:
        out = [(f"webhook:{wh.get('name') or wh.get('format', 'generic')}", wh) for wh in self.cfg.get("webhooks", []) or []]
        smtp = self.cfg.get("smtp") or {}
        if smtp.get("enabled"):
            out.append(("smtp", smtp))
        if a is None or not (self.cfg.get("routes") or []):
            return out
        names = self.route(a)
        if names is None:
            return out
        return [(n, c) for n, c in out if n.split(":", 1)[-1] in names or n in names]

    def route(self, a: dict) -> set[str] | None:
        """알림 라우팅 정책(alerting.routes, 위에서부터) — 맞는 규칙의 채널을 모음. 규칙이 하나도 안 맞으면
        default_channels(비우면 전체=None). 규칙: severities·sources·categories·connectors·match(제목·대상 정규식)·hours(HH:MM-HH:MM)·days(0=월)·stop"""
        ev = a.get("event") or {}
        now = time.localtime()
        chosen: set[str] = set()
        matched = False
        for r in self.cfg.get("routes") or []:
            if not r.get("enabled", True):
                continue
            if r.get("severities") and a.get("severity") not in r["severities"]:
                continue
            if r.get("sources") and ev.get("source") not in r["sources"]:
                continue
            if r.get("categories") and a.get("category") not in r["categories"]:
                continue
            if r.get("connectors") and ev.get("connector") not in r["connectors"]:
                continue
            if r.get("match"):
                try:
                    if not re.search(str(r["match"]), f"{a.get('title', '')} {ev.get('entity', '')} {ev.get('host', '')}", re.I):
                        continue
                except re.error:
                    continue
            if r.get("days") and now.tm_wday not in [int(d) for d in r["days"]]:
                continue
            if r.get("hours"):
                try:
                    h1, h2 = str(r["hours"]).split("-")
                    cur = now.tm_hour * 60 + now.tm_min
                    a1 = int(h1.split(":")[0]) * 60 + int(h1.split(":")[1] if ":" in h1 else 0)
                    a2 = int(h2.split(":")[0]) * 60 + int(h2.split(":")[1] if ":" in h2 else 0)
                    if a2 == 23 * 60 + 59:                      # '…-23:59' 는 하루 끝까지(23:59 한 분이 빠지지 않게), '24:00' 도 허용
                        a2 = 24 * 60
                    inside = a1 <= cur < a2 if a1 <= a2 else (cur >= a1 or cur < a2)   # 22:00-06:00 같은 야간 창
                    if not inside:
                        continue
                except (ValueError, IndexError):
                    continue
            matched = True
            chosen |= {str(c) for c in (r.get("channels") or [])}
            if r.get("stop", True):
                break
        if not matched:
            d = self.cfg.get("default_channels") or []
            return set(str(c) for c in d) if d else None
        return chosen

    async def _enqueue(self, a: dict, title: str, body: str) -> None:
        chans = self._channels(a)
        if not chans:
            return
        slim = {k: a.get(k) for k in ("id", "severity", "title", "status", "count", "category", "incident_id", "reasons")}
        slim["event"] = {k: (a.get("event") or {}).get(k) for k in ("source", "connector", "host", "entity", "ts", "message")}
        if a.get("ai"):
            slim["ai"] = {k: a["ai"].get(k) for k in ("summary", "probable_cause", "impact", "actions", "confidence")}
        now = time.time()
        if self.store is None:                       # 테스트/초기화 전 — 직접 발송
            for name, conf in chans:
                bg(self._send(name, conf, slim, title, body))
            return
        for name, _conf in chans:
            await self.store.x("INSERT INTO outbox(created,channel,ref,title,payload,state,attempts,next_at,last_error) "
                               "VALUES(?,?,?,?,?,'pending',0,?,'')",
                               (now, name, str(a.get("id", "")), title[:300],
                                json.dumps({"a": slim, "body": body}, ensure_ascii=False, default=str), now))
            self.ob["queued"] += 1
        self._wake.set()

    async def _send(self, name: str, conf: dict, a: dict, title: str, body: str) -> str:
        if name == "smtp":
            return await self._smtp(conf, a, title, body)
        return await self._webhook(conf, a, title, body)

    async def dispatcher(self, beat=lambda: None) -> None:
        """outbox 발송 워커 — 리더 노드에서만 전송. 채널별 서킷 브레이커·지수 백오프·DLQ."""
        while True:
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            beat()
            if self.store is None:
                continue
            try:
                await self._dispatch_once()
                if time.time() - self._last_purge > 3600:
                    self._last_purge = time.time()
                    await self.purge_outbox()
            except Exception as e:  # noqa: BLE001
                print(f"[alerting] 발송 워커 오류: {type(e).__name__}: {e}", flush=True)

    async def purge_outbox(self, now: float | None = None) -> int:
        """끝난 발송 기록 보존 정리(2.30.0) — 보냄·대기 노드 건너뜀은 outbox_keep_days(기본 14일), 발송 실패(dead)는
        outbox_dead_keep_days(기본 90일, 재발송·원인 확인용) 뒤 삭제. 대기·재시도 중인 건은 지우지 않는다."""
        if self.store is None:
            return 0
        now = now or time.time()
        cut = now - float(self.cfg.get("outbox_keep_days", 14)) * 86400
        dcut = now - float(self.cfg.get("outbox_dead_keep_days", 90)) * 86400
        cond = "(state IN ('sent','skipped_standby') AND created < ?) OR (state='dead' AND created < ?)"
        n = (await self.store.q(f"SELECT COUNT(*) n FROM outbox WHERE {cond}", (cut, dcut)))[0]["n"]
        if n:
            await self.store.x(f"DELETE FROM outbox WHERE {cond}", (cut, dcut))
            self.ob["purged"] = self.ob.get("purged", 0) + n
        return n

    async def _dispatch_once(self) -> None:
        now = time.time()
        stat = await self.store.q("SELECT COUNT(*) n, MIN(created) o FROM outbox WHERE state IN ('pending','retry')")
        self.ob["pending"] = stat[0]["n"] if stat else 0
        self.ob["oldest_pending"] = round(now - stat[0]["o"], 1) if stat and stat[0]["o"] else 0.0
        if not self.is_leader():
            await self.store.x("UPDATE outbox SET state='skipped_standby' WHERE state IN ('pending','retry') AND created < ?",
                               (now - 900,))
            return
        rows = await self.store.q("SELECT * FROM outbox WHERE state IN ('pending','retry') AND next_at <= ? "
                                  "ORDER BY id LIMIT 50", (now,))
        chans = dict(self._channels())
        jobs = []
        for r in rows:
            conf = chans.get(r["channel"])
            if conf is None:                          # 설정에서 채널이 사라짐
                await self.store.x("UPDATE outbox SET state='dead', last_error=? WHERE id=?", ("채널 설정 없음", r["id"]))
                continue
            br = self.breakers.get(r["channel"])
            if br is None:
                br = self.breakers[r["channel"]] = Breaker(r["channel"], int(self.cfg.get("channel_breaker_threshold", 3)),
                                                           float(self.cfg.get("channel_breaker_reset", 60)))
            if not br.allow():
                continue
            jobs.append(self._deliver(r, conf, br))
        if jobs:
            await asyncio.gather(*jobs)

    async def _deliver(self, r: dict, conf: dict, br: Breaker) -> None:
        p = json.loads(r["payload"])
        try:
            detail = await asyncio.wait_for(self._send(r["channel"], conf, p["a"], r["title"], p["body"]), 30)
            br.ok()
            await self.store.x("UPDATE outbox SET state='sent', attempts=attempts+1, sent_at=?, last_error='' WHERE id=?",
                               (time.time(), r["id"]))
            await self.save(r["ref"], r["channel"], True, str(detail))
            self.ob["sent"] += 1
        except Exception as e:  # noqa: BLE001
            br.fail(f"{type(e).__name__}: {e}")
            n = int(r["attempts"]) + 1
            err = f"{type(e).__name__}: {e}"[:300]
            mx = int(self.cfg.get("max_attempts", 8))
            if n >= mx:
                await self.store.x("UPDATE outbox SET state='dead', attempts=?, last_error=? WHERE id=?", (n, err, r["id"]))
                self.ob["dead"] += 1
                await self.save(r["ref"], r["channel"], False, f"최종 실패({n}회): {err}")
                await self.broadcast({"type": "alert", "data": {
                    "anomaly_id": r["ref"], "severity": "error", "ts": time.time(), "seq": 0,
                    "title": f"[알림 발송 실패] {r['channel']} — {r['title'][:80]}",
                    "body": f"{n}회 재시도 후 포기했습니다. 마지막 오류: {err}\n운영 설정 > 알림 채널을 점검하세요."}})
            else:
                sched = [float(x) for x in (self.cfg.get("retry_schedule") or RETRY)]
                wait = sched[min(n - 1, len(sched) - 1)] * random.uniform(0.9, 1.1)
                await self.store.x("UPDATE outbox SET state='retry', attempts=?, next_at=?, last_error=? WHERE id=?",
                                   (n, time.time() + wait, err, r["id"]))
                self.ob["retry"] += 1
                await self.save(r["ref"], r["channel"], False, f"재시도 예정({n}/{mx}): {err}")

    async def retry_dead(self, ids: list[int] | None = None) -> int:
        """발송 실패함(DLQ) 재발송 — 운영자 수동"""
        if ids:
            q = ",".join("?" * len(ids))
            n = len(await self.store.q(f"SELECT id FROM outbox WHERE state='dead' AND id IN ({q})", ids))
            await self.store.x(f"UPDATE outbox SET state='retry', attempts=0, next_at=0 WHERE state='dead' AND id IN ({q})", ids)
        else:
            n = len(await self.store.q("SELECT id FROM outbox WHERE state='dead'"))
            await self.store.x("UPDATE outbox SET state='retry', attempts=0, next_at=0 WHERE state='dead'")
        self._wake.set()
        return n

    async def takeover(self, since: float) -> int:
        """대기 노드가 리더를 인계받을 때 — 인계 이전에 생성된 미발송 건은 원 리더가 이미 보냈을 수 있으므로 정리"""
        if self.store is None:
            return 0
        rows = await self.store.q("SELECT id FROM outbox WHERE state IN ('pending','retry') AND created < ?", (since,))
        if rows:
            await self.store.x("UPDATE outbox SET state='skipped_standby' WHERE state IN ('pending','retry') AND created < ?",
                               (since,))
        return len(rows)

    def outbox_status(self) -> dict[str, Any]:
        return {**self.ob, "breakers": {k: b.status() for k, b in self.breakers.items()}}

    PD_SEV = {"critical": "critical", "error": "error", "warning": "warning", "info": "info"}
    OG_PRI = {"critical": "P1", "error": "P2", "warning": "P3", "info": "P5"}

    async def _webhook(self, wh: dict, a: dict, title: str, body: str) -> str:
        fmt = wh.get("format", "generic")
        ev = a.get("event") or {}
        key = wh.get("secret") or wh.get("key") or ""
        if fmt == "pagerduty":                       # Events API v2 — dedup_key=이상징후 id(같은 건은 한 인시던트로)
            if not key:
                raise RuntimeError("PagerDuty Integration Key(secret) 없음")
            payload: Any = {"routing_key": key, "event_action": "trigger", "dedup_key": f"aiops-{a.get('id', 'x')}",
                            "client": "VCF AIops", "client_url": wh.get("console_url") or "",
                            "payload": {"summary": title[:1024], "severity": self.PD_SEV.get(a.get("severity", "warning"), "warning"),
                                        "source": ev.get("host") or ev.get("entity") or ev.get("connector") or "vcf-aiops",
                                        "component": ev.get("source") or "", "group": ev.get("connector") or "", "class": a.get("category") or "",
                                        "custom_details": {"body": body[:4000], "incident": a.get("incident_id"), "count": a.get("count")}}}
            r = await self.http.post(wh.get("url") or "https://events.pagerduty.com/v2/enqueue", json=payload)
        elif fmt == "opsgenie":                      # Alert API — alias=이상징후 id(중복 제거), priority 매핑
            if not key:
                raise RuntimeError("Opsgenie API Key(secret) 없음")
            payload = {"message": title[:130], "alias": f"aiops-{a.get('id', 'x')}", "description": body[:15000],
                       "priority": self.OG_PRI.get(a.get("severity", "warning"), "P3"), "source": "VCF AIops",
                       "entity": ev.get("host") or ev.get("entity") or "", "tags": [t for t in ("vcf-aiops", ev.get("source"), a.get("category")) if t],
                       "details": {"connector": ev.get("connector") or "", "incident": a.get("incident_id") or "", "count": str(a.get("count") or 1)}}
            r = await self.http.post(wh.get("url") or "https://api.opsgenie.com/v2/alerts", json=payload, headers={"Authorization": f"GenieKey {key}"})
        elif fmt == "slack":
            payload: Any = {"text": f"*{title}*\n```{body}```"}
        elif fmt == "teams":
            payload = {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                                     {"type": "TextBlock", "text": body, "wrap": True, "fontType": "Monospace"}]}}]}
        else:
            payload = {"title": title, "body": body, "anomaly": a}
        if fmt not in ("pagerduty", "opsgenie"):
            r = await self.http.post(wh["url"], json=payload, headers=wh.get("headers") or {})
        if r.status_code >= 300:
            raise RuntimeError(f"HTTP {r.status_code} {r.text[:120]}")
        return f"HTTP {r.status_code}"

    async def _smtp(self, s: dict, a: dict, title: str, body: str) -> str:
        def send():
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = title
            msg["From"] = s["from"]
            msg["To"] = ", ".join(s["to"])
            with smtplib.SMTP(s["host"], int(s.get("port", 25)), timeout=15) as c:
                if s.get("starttls"):
                    c.starttls()
                if s.get("username"):
                    c.login(s["username"], s["password"])
                c.sendmail(s["from"], s["to"], msg.as_string())
        await asyncio.to_thread(send)
        return "sent"

    async def test(self) -> dict[str, Any]:
        fake = {"id": "test", "severity": "warning", "title": "알림 채널 테스트", "reasons": ["수동 테스트"],
                "count": 1, "event": {"source": "aiops", "connector": "self", "entity": "-", "host": "-",
                                      "ts": time.time(), "message": "VCF AIops 알림 채널 테스트 메시지입니다."}}
        self.last.pop("test", None)
        await self.fire(fake, "test")
        return {"ok": True, "channels": ["dashboard"] + [w.get("name", w.get("format", "webhook"))
                                                        for w in self.cfg.get("webhooks", []) or []]
                + (["smtp"] if (self.cfg.get("smtp") or {}).get("enabled") else [])}
