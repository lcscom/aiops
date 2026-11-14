"""인시던트 관리 — 이상징후를 장애 단위로 묶고(상관분석) 처리 이력·SLA·유지보수·ITSM·AI 근본원인 분석을 관리.

상관분석   이상징후의 대상(VM/호스트/데이터스토어)을 vCenter 토폴로지로 클러스터까지 해석 → 같은 상관 그룹에서
           correlation_window(기본 15분) 안에 발생하면 같은 인시던트로 병합. 토폴로지에 없으면 호스트 단위.
상태       open(신규) → acknowledged(접수) → investigating(조사 중) → resolved(해결) → closed(종료)  ※ 재개 가능
SLA        심각도별 접수·해결 목표(분) — 초과 시 표시·알림
억제       유지보수 창(기간/주간 반복, 대상 정규식) + vCenter 유지보수 모드 호스트 + 사일런스(지문/정규식, 기한)
           → 기록은 남기고 알림·ITSM 생성만 억제
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime
from typing import Any

from .itsm import ItsmClient
from .models import SEV_RANK
from .sanitize import clean

STATUSES = ["open", "acknowledged", "investigating", "resolved", "closed"]
STATUS_LABEL = {"open": "신규", "acknowledged": "접수", "investigating": "조사 중", "resolved": "해결", "closed": "종료"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT, category TEXT, correlation_key TEXT, cluster TEXT,
  hosts TEXT, sources TEXT, anomaly_ids TEXT, anomaly_count INTEGER, assignee TEXT, created REAL, updated REAL,
  last_anomaly REAL, acknowledged_at REAL, resolved_at REAL, closed_at REAL, sla TEXT, itsm TEXT, rca TEXT, rca_at REAL,
  maintenance INTEGER DEFAULT 0, summary TEXT, resolution TEXT, primary_entity TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents(status, updated);
CREATE INDEX IF NOT EXISTS ix_inc_created ON incidents(created);
CREATE TABLE IF NOT EXISTS incident_notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, ts REAL, user TEXT, kind TEXT, text TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS ix_note_inc ON incident_notes(incident_id, ts);
CREATE TABLE IF NOT EXISTS maintenance(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start REAL, end REAL, weekly TEXT, scope TEXT, enabled INTEGER DEFAULT 1,
  created_by TEXT, created REAL);
CREATE TABLE IF NOT EXISTS silences(
  id INTEGER PRIMARY KEY AUTOINCREMENT, match TEXT, until REAL, reason TEXT, created_by TEXT, created REAL);
"""
JSON_COLS = ("hosts", "sources", "anomaly_ids", "sla", "itsm", "rca")
COLS = ("id", "title", "severity", "status", "category", "correlation_key", "cluster", "hosts", "sources", "anomaly_ids",
        "anomaly_count", "assignee", "created", "updated", "last_anomaly", "acknowledged_at", "resolved_at", "closed_at",
        "sla", "itsm", "rca", "rca_at", "maintenance", "summary", "resolution", "primary_entity")


def _row(r: dict | None) -> dict | None:
    if not r:
        return r
    for c in JSON_COLS:
        if c in r:
            try:
                r[c] = json.loads(r[c]) if r[c] else ({} if c in ("sla", "itsm", "rca") else [])
            except (TypeError, ValueError):
                pass
    r["status_label"] = STATUS_LABEL.get(r.get("status"), r.get("status"))
    return r


class IncidentManager:
    def __init__(self, engine, cfg: dict):
        self.e = engine
        self.cfg = cfg
        self.store = engine.store
        self.store.schema(SCHEMA)
        self.itsm = ItsmClient(engine.cfg.get("itsm") or {})
        self._bg: set[asyncio.Task] = set()
        self._lock = asyncio.Lock()
        self._seq_day = ""
        self._seq = 0
        self.maint_cache: list[dict] = []
        self.silence_cache: list[dict] = []

    def _spawn(self, coro) -> None:
        """백그라운드 작업 참조 유지(가비지 수집으로 중간 취소 방지)"""
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    # ------------------------------------------------------------------ 공통
    async def note(self, inc_id: str, user: str, kind: str, text: str, data: Any = None) -> None:
        await self.store.x("INSERT INTO incident_notes(incident_id,ts,user,kind,text,data) VALUES(?,?,?,?,?,?)",
                           (inc_id, time.time(), user, kind, text[:4000], json.dumps(data, ensure_ascii=False, default=str) if data else None))

    async def get(self, inc_id: str) -> dict | None:
        return _row(await self.store.q1("SELECT * FROM incidents WHERE id=?", (inc_id,)))

    async def _save(self, inc: dict) -> None:
        cols = [c for c in COLS if c in inc]           # 화면용 파생 필드(status_label 등) 제외
        vals = [json.dumps(inc[c], ensure_ascii=False, default=str) if c in JSON_COLS else inc[c] for c in cols]
        await self.store.x(f"INSERT INTO incidents({','.join(cols)}) VALUES({','.join('?' * len(cols))}) "
                           f"ON CONFLICT(id) DO UPDATE SET {', '.join(f'{c}=excluded.{c}' for c in cols if c != 'id')}", vals)

    async def _next_id(self) -> str:
        day = datetime.now().strftime("%Y%m%d")
        if day != self._seq_day:
            row = await self.store.q1("SELECT COUNT(*) AS n FROM incidents WHERE id LIKE ?", (f"INC-{day}-%",))
            self._seq_day, self._seq = day, (row or {}).get("n", 0)
        self._seq += 1
        return f"INC-{day}-{self._seq:04d}"

    async def broadcast(self, inc: dict) -> None:
        await self.e.broadcast({"type": "incident", "data": self._brief(inc)})

    @staticmethod
    def _brief(inc: dict) -> dict:
        return {k: inc.get(k) for k in ("id", "title", "severity", "status", "status_label", "category", "correlation_key",
                                        "cluster", "hosts", "anomaly_count", "assignee", "created", "updated", "last_anomaly",
                                        "sla", "itsm", "maintenance", "primary_entity")} | {"has_rca": bool(inc.get("rca"))}

    # ------------------------------------------------------------------ 억제(유지보수·사일런스)
    async def reload_suppression(self) -> None:
        self.maint_cache = [_m for _m in (await self.store.q("SELECT * FROM maintenance WHERE enabled=1"))]
        for m in self.maint_cache:
            m["weekly"] = json.loads(m["weekly"]) if m["weekly"] else None
            m["scope"] = json.loads(m["scope"]) if m["scope"] else {}
        self.silence_cache = await self.store.q("SELECT * FROM silences WHERE until > ?", (time.time(),))
        for s in self.silence_cache:
            s["match"] = json.loads(s["match"])

    @staticmethod
    def _in_window(m: dict, now: float) -> bool:
        if m.get("weekly"):
            w = m["weekly"]
            lt = time.localtime(now)
            if lt.tm_wday not in (w.get("days") or list(range(7))):
                return False
            hm = lt.tm_hour * 60 + lt.tm_min
            f = int(w["from"][:2]) * 60 + int(w["from"][3:5])
            t = int(w["to"][:2]) * 60 + int(w["to"][3:5])
            return f <= hm < t if f <= t else (hm >= f or hm < t)
        return (m.get("start") or 0) <= now <= (m.get("end") or 0)

    def _scope_match(self, scope: dict, ev: dict, ctx: dict | None) -> bool:
        names = [ev.get("host") or "", ev.get("entity") or "", (ctx or {}).get("host", ""), (ctx or {}).get("name", "")]
        if scope.get("hosts_regex") and not any(n and re.search(scope["hosts_regex"], n, re.I) for n in names):
            return False
        if scope.get("clusters") and (ctx or {}).get("cluster") not in scope["clusters"]:
            return False
        if scope.get("sources") and ev.get("source") not in scope["sources"]:
            return False
        return True

    def suppression(self, anomaly: dict, fingerprint: str) -> str | None:
        """억제 사유(없으면 None)"""
        ev = anomaly["event"]
        now = time.time()
        ctx = self.e.resolve(ev.get("entity") or ev.get("host"))
        for s in self.silence_cache:
            if s["until"] < now:
                continue
            m = s["match"]
            if m.get("fingerprint") and m["fingerprint"] == fingerprint:
                return f"사일런스 #{s['id']} ({s['reason']})"
            if m.get("message_regex") and re.search(m["message_regex"], ev.get("message", ""), re.I) and \
                    (not m.get("host_regex") or re.search(m["host_regex"], ev.get("host", ""), re.I)):
                return f"사일런스 #{s['id']} ({s['reason']})"
        for m in self.maint_cache:
            if self._in_window(m, now) and self._scope_match(m["scope"], ev, ctx):
                return f"유지보수 창 '{m['name']}'"
        if ctx and ctx.get("host"):
            h = self.e.topology_host(ctx["host"])
            if h and h.get("maintenance"):
                return f"vCenter 유지보수 모드 호스트 {ctx['host']}"
        return None

    # ------------------------------------------------------------------ 상관분석
    def correlation(self, ev: dict) -> tuple[str, str, str]:
        """(correlation_key, cluster, primary_entity)"""
        if ev.get("source") == "aiops":
            return "collection", "", ev.get("host", "")
        ctx = self.e.resolve(ev.get("entity") or "") or self.e.resolve(ev.get("host") or "")
        if ctx and ctx.get("cluster"):
            return f"cluster:{ctx['cluster']}", ctx["cluster"], ctx["name"]
        host = (ctx or {}).get("host") or ev.get("host") or ev.get("connector") or "unknown"
        return f"host:{host.split('.')[0].lower()}", "", (ctx or {}).get("name") or ev.get("entity") or host

    async def on_anomaly(self, a: dict, fingerprint: str, suppressed: str | None) -> dict | None:
        if not self.cfg.get("enabled", True):
            return None
        ai = a.get("ai") or {}
        if ai.get("is_anomaly") is False:
            await self._detach(a)
            return None
        if SEV_RANK.get(a["severity"], 0) < SEV_RANK.get(self.cfg.get("min_severity", "error"), 3):
            return None
        ev = a["event"]
        key, cluster, primary = self.correlation(ev)
        now = time.time()
        async with self._lock:
            inc = _row(await self.store.q1(
                "SELECT * FROM incidents WHERE correlation_key=? AND status IN ('open','acknowledged','investigating') "
                "AND last_anomaly > ? ORDER BY updated DESC LIMIT 1", (key, now - float(self.cfg.get("correlation_window", 900)))))
            new = inc is None
            if new:
                sev = a["severity"]
                sla_cfg = (self.cfg.get("sla") or {}).get(sev, {})
                inc = {"id": await self._next_id(), "title": a.get("title", "")[:200], "severity": sev, "status": "open",
                       "category": a.get("category", "general"), "correlation_key": key, "cluster": cluster,
                       "hosts": [], "sources": [], "anomaly_ids": [], "anomaly_count": 0, "assignee": None,
                       "created": now, "updated": now, "last_anomaly": now, "acknowledged_at": None, "resolved_at": None,
                       "closed_at": None, "itsm": {}, "rca": {}, "rca_at": None, "maintenance": int(bool(suppressed)),
                       "summary": "", "resolution": None, "primary_entity": primary,
                       "sla": {"ack_due": now + sla_cfg.get("ack", 60) * 60 if sla_cfg else None,
                               "resolve_due": now + sla_cfg.get("resolve", 480) * 60 if sla_cfg else None,
                               "ack_breached": False, "resolve_breached": False}}
            if a["id"] not in inc["anomaly_ids"]:
                inc["anomaly_ids"] = (inc["anomaly_ids"] + [a["id"]])[-500:]
            inc["anomaly_count"] = len(inc["anomaly_ids"])
            for h in (ev.get("host"), ev.get("entity") if ev.get("source") in ("vcenter", "esxi") else None):
                if h and h not in inc["hosts"]:
                    inc["hosts"] = (inc["hosts"] + [h])[:100]
            if ev.get("source") and ev["source"] not in inc["sources"]:
                inc["sources"].append(ev["source"])
            if SEV_RANK.get(a["severity"], 0) > SEV_RANK.get(inc["severity"], 0):
                inc["severity"] = a["severity"]
            if not suppressed:
                inc["maintenance"] = 0
            if ai.get("title") and (new or inc["anomaly_count"] == 1):
                inc["title"] = ai["title"][:200]
            if ai.get("summary") and not inc["summary"]:
                inc["summary"] = ai["summary"][:1000]
            if inc["anomaly_count"] > 1 and not inc["title"].startswith("["):
                inc["title"] = f"[{inc['anomaly_count']}건] {inc['title'].split('] ', 1)[-1]}"[:200]
            inc["updated"] = now
            inc["last_anomaly"] = now
            await self._save(inc)
        if new:
            await self.note(inc["id"], "system", "system",
                            f"인시던트 생성 — 상관 그룹 {key}" + (f" · 억제: {suppressed}" if suppressed else ""),
                            {"anomaly": a["id"]})
            await self.e.audit.log("incident.create", target=inc["id"], detail={"key": key, "severity": inc["severity"]})
            getattr(self.e, "siem", None) and self.e.siem.incident(inc, "created")
            leader = not getattr(self.e, "ha", None) or self.e.ha.is_leader()    # 이중화: 알림 리더만 ITSM 자동 등록
            if leader and not suppressed and SEV_RANK.get(inc["severity"], 0) >= SEV_RANK.get((self.e.cfg.get("itsm") or {}).get("min_severity", "critical"), 4):
                self._spawn(self.itsm_create(inc["id"], "system"))
        await self.broadcast(inc)
        return inc

    async def _detach(self, a: dict) -> None:
        rows = await self.store.q("SELECT id FROM incidents WHERE anomaly_ids LIKE ? AND status IN ('open','acknowledged','investigating')",
                                  (f'%"{a["id"]}"%',))
        for r in rows:
            inc = await self.get(r["id"])
            inc["anomaly_ids"] = [x for x in inc["anomaly_ids"] if x != a["id"]]
            inc["anomaly_count"] = len(inc["anomaly_ids"])
            if not inc["anomaly_ids"]:
                inc["status"], inc["closed_at"], inc["resolution"] = "closed", time.time(), "AI 판정 정상(오탐) — 자동 종료"
            inc["updated"] = time.time()
            await self._save(inc)
            await self.note(inc["id"], "system", "system", f"이상징후 {a['id']} AI 판정 정상 — 인시던트에서 제외")
            await self.broadcast(inc)

    # ------------------------------------------------------------------ 처리(사용자)
    async def create_manual(self, title: str, severity: str, user: str, anomaly_ids: list[str]) -> dict:
        now = time.time()
        sla_cfg = (self.cfg.get("sla") or {}).get(severity, {})
        iid = await self._next_id()
        inc = {"id": iid, "title": title[:200], "severity": severity, "status": "open", "category": "manual",
               "correlation_key": f"manual:{iid}", "cluster": "", "hosts": [], "sources": [], "anomaly_ids": anomaly_ids,
               "anomaly_count": len(anomaly_ids), "assignee": user, "created": now, "updated": now, "last_anomaly": now,
               "acknowledged_at": None, "resolved_at": None, "closed_at": None, "itsm": {}, "rca": {}, "rca_at": None,
               "maintenance": 0, "summary": "", "resolution": None, "primary_entity": "",
               "sla": {"ack_due": now + sla_cfg.get("ack", 60) * 60 if sla_cfg else None,
                       "resolve_due": now + sla_cfg.get("resolve", 480) * 60 if sla_cfg else None,
                       "ack_breached": False, "resolve_breached": False}}
        await self._save(inc)
        getattr(self.e, "siem", None) and self.e.siem.incident(inc, "created")
        await self.note(inc["id"], user, "system", "수동 생성")
        await self.broadcast(inc)
        return inc

    async def set_status(self, inc_id: str, status: str, user: str, note: str = "") -> dict:
        if status not in STATUSES:
            raise ValueError("상태 오류")
        inc = await self.get(inc_id)
        if not inc:
            raise KeyError(inc_id)
        if status in ("resolved", "closed") and not (note or inc.get("resolution")):
            raise ValueError("해결/종료 시 처리 내용을 입력하세요")
        prev = inc["status"]
        now = time.time()
        inc["status"] = status
        if status in ("acknowledged", "investigating") and not inc["acknowledged_at"]:
            inc["acknowledged_at"] = now
        if status == "resolved":
            inc["resolved_at"] = now
            inc["resolution"] = note or inc.get("resolution")
            inc["acknowledged_at"] = inc["acknowledged_at"] or now
        if status == "closed":
            inc["closed_at"] = now
            inc["resolved_at"] = inc["resolved_at"] or now
            inc["resolution"] = note or inc.get("resolution")
        if status in ("open", "acknowledged", "investigating") and prev in ("resolved", "closed"):
            inc["resolved_at"] = inc["closed_at"] = None
        if not inc["assignee"] and status in ("acknowledged", "investigating"):
            inc["assignee"] = user
        inc["updated"] = now
        await self._save(inc)
        getattr(self.e, "siem", None) and self.e.siem.incident(inc, status)
        await self.note(inc_id, user, "status", f"상태 {STATUS_LABEL[prev]} → {STATUS_LABEL[status]}" + (f": {note}" if note else ""))
        if status in ("acknowledged", "investigating"):     # 연결된 이상징후도 확인 처리
            for aid in inc["anomaly_ids"]:
                an = self.e.anomalies.get(aid)
                if an and not an.ack:
                    await self.e.ack(aid)
        if inc.get("itsm"):
            self._spawn(self._itsm_update(inc, f"[AIOps] {STATUS_LABEL[status]} by {user}: {note}", status))
        await self.broadcast(inc)
        return inc

    async def assign(self, inc_id: str, assignee: str, user: str) -> dict:
        inc = await self.get(inc_id)
        if not inc:
            raise KeyError(inc_id)
        prev = inc["assignee"]
        inc["assignee"] = assignee or None
        inc["updated"] = time.time()
        await self._save(inc)
        await self.note(inc_id, user, "assign", f"담당자 {prev or '-'} → {assignee or '-'}")
        await self.broadcast(inc)
        return inc

    async def comment(self, inc_id: str, text: str, user: str) -> None:
        await self.note(inc_id, user, "comment", clean(text, 4000))
        inc = await self.get(inc_id)
        if inc:
            inc["updated"] = time.time()
            await self._save(inc)
            if inc.get("itsm"):
                self._spawn(self._itsm_update(inc, f"[AIOps] {user}: {text}", None))

    async def notes(self, inc_id: str) -> list[dict]:
        rows = await self.store.q("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY ts", (inc_id,))
        for r in rows:
            r["data"] = json.loads(r["data"]) if r["data"] else None
        return rows

    async def list(self, status: str | None, q: str | None, days: int = 30, limit: int = 300) -> list[dict]:
        sql = "SELECT * FROM incidents WHERE created > ?"
        p: list[Any] = [time.time() - days * 86400]
        if status == "active":
            sql += " AND status IN ('open','acknowledged','investigating')"
        elif status:
            sql += " AND status = ?"
            p.append(status)
        if q:
            sql += " AND (title LIKE ? OR hosts LIKE ? OR id LIKE ? OR correlation_key LIKE ?)"
            p += [f"%{q}%"] * 4
        sql += " ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'investigating' THEN 2 ELSE 3 END, updated DESC LIMIT ?"
        p.append(limit)
        return [self._brief(_row(r)) for r in await self.store.q(sql, p)]

    # ------------------------------------------------------------------ ITSM
    def link(self, inc_id: str) -> str:
        base = (self.e.cfg.get("server") or {}).get("public_url") or ""
        return f"{base.rstrip('/')}/#incident/{inc_id}" if base else f"#incident/{inc_id}"

    async def itsm_create(self, inc_id: str, user: str) -> dict:
        inc = await self.get(inc_id)
        if not inc or inc.get("itsm"):
            return inc.get("itsm") if inc else {}
        try:
            ref = await self.itsm.create(inc, self.link(inc_id))
        except Exception as e:  # noqa: BLE001
            await self.note(inc_id, user, "itsm", f"ITSM 등록 실패: {type(e).__name__}: {e}"[:400])
            raise
        if ref:
            inc = await self.get(inc_id)
            inc["itsm"] = ref
            await self._save(inc)
            await self.note(inc_id, user, "itsm", f"ITSM 등록 {ref.get('system')} {ref.get('number', '')}", ref)
            await self.e.audit.log("incident.itsm", user=user, target=inc_id, detail=ref)
            await self.broadcast(inc)
        return ref or {}

    async def _itsm_update(self, inc: dict, note: str, status: str | None) -> None:
        try:
            await self.itsm.update(inc, inc.get("itsm") or {}, note, status)
        except Exception as e:  # noqa: BLE001
            await self.note(inc["id"], "system", "itsm", f"ITSM 갱신 실패: {type(e).__name__}: {e}"[:400])

    # ------------------------------------------------------------------ AI 근본원인 분석
    async def vm_changes(self, inc: dict, before_hours: float = 6, limit: int = 40) -> list[dict[str, Any]]:
        """인시던트 대상(주 개체·묶인 이상징후의 VM/호스트·클러스터)의 발생 전 before_hours ~ 마지막 이상까지 VM 변경"""
        moves = getattr(self.e, "moves", None)
        if not moves:
            return []
        names, hosts = {inc.get("primary_entity") or ""}, set(inc.get("hosts") or [])
        for aid in (inc.get("anomaly_ids") or [])[-60:]:
            an = self.e.anomalies.get(aid)
            if an:
                names |= {an.event.get("entity") or "", an.event.get("host") or ""}
        for n in list(names):
            ctx = self.e.resolve(n) if n else None
            if ctx and ctx.get("kind") == "vm" and ctx.get("host"):
                hosts.add(ctx["host"])
            elif ctx and ctx.get("kind") == "host":
                hosts.add(ctx.get("name") or n)
        hosts |= {n for n in names if n}                     # 개체 이름이 ESXi 호스트일 수도 있음(토폴로지 미해석 시)
        clusters = {inc.get("cluster")} if inc.get("cluster") else set()
        t0 = inc["created"] - before_hours * 3600
        t1 = max(inc.get("last_anomaly") or 0, inc.get("updated") or 0, inc["created"]) + 600
        return await moves.related(names, hosts, clusters, t0, t1, limit)

    async def build_bundle(self, inc: dict) -> dict[str, Any]:
        anomalies = []
        for aid in inc["anomaly_ids"][-40:]:
            an = self.e.anomalies.get(aid)
            if an:
                ev = an.event
                anomalies.append({"id": aid, "time": ev["ts"], "source": ev["source"], "host": ev["host"], "entity": ev["entity"],
                                  "severity": an.severity, "message": clean(ev["message"], 600), "detector": an.reasons,
                                  "ai": {k: an.ai.get(k) for k in ("title", "summary", "probable_cause") if an.ai}})
        t0 = inc["created"] - 1800
        t1 = max(inc["last_anomaly"] or inc["updated"], inc["created"]) + 600
        hosts = [h for h in inc["hosts"]][:20]
        logs = []
        if hosts:
            ph = ",".join("?" * len(hosts))
            logs = await self.store.q(f"SELECT ts,source,severity,host,entity,message FROM logs WHERE ts BETWEEN ? AND ? "
                                      f"AND (host IN ({ph}) OR entity IN ({ph})) ORDER BY "
                                      f"CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, ts DESC LIMIT 150",
                                      [t0, t1, *hosts, *hosts])
            logs.sort(key=lambda r: r["ts"])
            for r in logs:
                r["message"] = clean(r["message"], 300)
        investigation = None
        ctx = self.e.resolve(inc.get("primary_entity") or "")
        if ctx and ctx.get("kind") in ("vm", "host", "datastore", "cluster"):
            try:
                investigation = await self.e.investigate(ctx["kind"], ctx["name"], hours=12)
                if investigation and investigation.get("timeline"):
                    investigation["timeline"] = investigation["timeline"][:80]
            except Exception as e:  # noqa: BLE001
                investigation = {"error": f"{type(e).__name__}: {e}"[:200]}
        refs = []
        if self.e.rag.has_any():
            # 1) 자동 연결(묶인 이상징후의 AI 근거·원문 로그별 검색 합산) 2) 인시던트 전체 문맥 검색(원인 구역 가중) — 문서 단위로 합침
            linked = await self.e.kblink.for_incident(inc, k=6)
            q = " ".join([inc["title"], inc.get("summary") or ""] + [x["message"][:200] for x in anomalies[:5]])
            hits = await self.e.rag.search(q, source=(inc.get("sources") or [None])[0], k=6, intent="rca")
            full = {}
            for h in hits:
                full.setdefault(h.get("doc_id") or h.get("url") or h.get("title"), h)
            if linked:                                       # 자동 연결 문서는 본문이 없으므로 같은 문서를 RCA 의도로 다시 꺼냄
                for d in linked:
                    kid = d.get("doc_id") or d.get("url") or d.get("title")
                    if kid in full:
                        continue
                    q2 = " ".join(x for x in [d.get("title", ""), (f"KB {d['kb']}" if d.get("kb") else "")] if x)
                    for h in await self.e.rag.search(q2, source=(inc.get("sources") or [None])[0], k=2, intent="rca"):
                        if (h.get("doc_id") or h.get("url") or h.get("title")) == kid:
                            full[kid] = h
                            break
                order = [d.get("doc_id") or d.get("url") or d.get("title") for d in linked]
                hits = [full[k] for k in order if k in full] + [h for k, h in full.items() if k not in order]
            hits = hits[:8]
            refs = [{"ref": f"R{i}", "title": h["title"], "type": h["type"], "url": h["url"],
                     **({"kb": h["kb"], "applies_to": h.get("versions"), "sections": h.get("sections")} if h.get("pack") == "library" else {}),
                     "text": clean(h["text"], 2400 if h.get("pack") == "library" else 1200)}
                    for i, h in enumerate(hits, 1)]
        return {"incident": {k: inc.get(k) for k in ("id", "title", "severity", "category", "correlation_key", "cluster",
                                                     "hosts", "sources", "created", "primary_entity", "summary")},
                "anomalies": anomalies, "log_timeline": logs, "investigation": investigation, "knowledge": refs,
                "topology_context": ctx, **(await self._vm_change_bundle(inc))}

    async def _vm_change_bundle(self, inc: dict) -> dict[str, Any]:
        moves = getattr(self.e, "moves", None)
        if not moves:
            return {"vm_changes": []}
        rows = await self.vm_changes(inc)
        return {"vm_changes": moves.brief(rows), "mask_names": moves.names_of(rows)}

    async def run_rca(self, inc_id: str, user: str) -> dict:
        if not self.e.llm:
            raise RuntimeError("LLM 비활성")
        inc = await self.get(inc_id)
        if not inc:
            raise KeyError(inc_id)
        bundle = await self.build_bundle(inc)
        res = await self.e.llm.rca(bundle)
        used = set(res.get("references") or [])
        res["references"] = [{k: r[k] for k in ("ref", "title", "url", "type")} for r in bundle["knowledge"] if r["ref"] in used]
        res["bundle_stats"] = {"anomalies": len(bundle["anomalies"]), "logs": len(bundle["log_timeline"]),
                               "investigation": bool(bundle["investigation"] and not bundle["investigation"].get("error")),
                               "knowledge": len(bundle["knowledge"]), "vm_changes": len(bundle.get("vm_changes") or [])}
        inc = await self.get(inc_id)
        inc["rca"], inc["rca_at"], inc["updated"] = res, time.time(), time.time()
        if res.get("summary") and not inc.get("summary"):
            inc["summary"] = res["summary"][:1000]
        await self._save(inc)
        await self.note(inc_id, user, "ai", "AI 근본원인 분석 " + ("완료" if res.get("complete") else "— 근거 불완전(⚠ INCOMPLETE)"),
                        {"root_cause": res.get("root_cause"), "confidence": res.get("confidence")})
        await self.broadcast(inc)
        return res

    # ------------------------------------------------------------------ SLA 감시
    async def sla_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await self.reload_suppression()
                now = time.time()
                rows = await self.store.q("SELECT * FROM incidents WHERE status IN ('open','acknowledged','investigating')")
                for r in rows:
                    inc = _row(r)
                    sla = inc.get("sla") or {}
                    changed = None
                    if sla.get("ack_due") and not inc["acknowledged_at"] and now > sla["ack_due"] and not sla.get("ack_breached"):
                        sla["ack_breached"], changed = True, "접수"
                    if sla.get("resolve_due") and now > sla["resolve_due"] and not sla.get("resolve_breached"):
                        sla["resolve_breached"], changed = True, "해결"
                    if changed:
                        inc["sla"] = sla
                        await self._save(inc)
                        await self.note(inc["id"], "system", "system", f"SLA {changed} 목표 시간 초과")
                        if not inc["maintenance"]:
                            await self.e.alerter.notify_text(
                                f"[SLA 초과] {inc['id']} {inc['title']}",
                                f"{changed} 목표 시간을 초과했습니다. 심각도 {inc['severity']} · 상태 {STATUS_LABEL[inc['status']]} · "
                                f"담당 {inc['assignee'] or '미지정'}", inc["severity"], inc["id"])
                        await self.broadcast(inc)
            except Exception as e:  # noqa: BLE001
                print(f"[incidents] SLA 점검 오류: {e}", flush=True)

    # ------------------------------------------------------------------ 지표
    async def metrics(self, since: float, until: float) -> dict[str, Any]:
        rows = await self.store.q("SELECT severity,status,created,acknowledged_at,resolved_at,sla,maintenance FROM incidents "
                                  "WHERE created BETWEEN ? AND ?", (since, until))
        tta = [r["acknowledged_at"] - r["created"] for r in rows if r["acknowledged_at"]]
        ttr = [r["resolved_at"] - r["created"] for r in rows if r["resolved_at"]]
        by_sev: dict[str, int] = {}
        breaches = 0
        for r in rows:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
            s = json.loads(r["sla"] or "{}")
            breaches += int(bool(s.get("ack_breached") or s.get("resolve_breached")))
        avg = lambda xs: round(sum(xs) / len(xs) / 60, 1) if xs else None   # noqa: E731
        return {"total": len(rows), "by_severity": by_sev, "mtta_min": avg(tta), "mttr_min": avg(ttr),
                "resolved": len(ttr), "sla_breaches": breaches, "maintenance": sum(r["maintenance"] or 0 for r in rows),
                "active": sum(1 for r in rows if r["status"] in ("open", "acknowledged", "investigating"))}
