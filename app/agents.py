"""VM 게스트·물리 서버 OS 로그 — 에이전트 레코드 정규화와 에이전트 레지스트리.

수집 경로
1) Fluent Bit(권장) → HTTPS POST /api/ingest (format json — 레코드 배열, json_date_key=date(double), gzip 가능)
   · Linux  : systemd(journald) 입력 → MESSAGE·PRIORITY·SYSLOG_IDENTIFIER·_SYSTEMD_UNIT·_HOSTNAME
              tail 입력(앱 로그 파일) → log · file(Path_Key)
   · Windows: winevtlog 입력 → ProviderName·EventID(숫자)·Level(1 위험·2 오류·3 경고·4 정보·5 상세)·Channel·Computer·
              Message·TimeCreated("YYYY-MM-DD HH:MM:SS ±HHMM", 로컬 시각)
   · 공통 표식(record_modifier): aiops_host · aiops_kind(vm|baremetal) · aiops_os · aiops_role · aiops_agent
   · 하트비트: dummy 입력 60초마다 {"aiops_heartbeat": 1} → 로그가 조용해도 에이전트 생존 판정
2) rsyslog(패키지 설치 불가 서버) → syslog TCP/TLS, RFC5424 구조화 데이터 [aiops@32473 kind="vm" role="db"]
   · systemd 타이머가 60초마다 logger -t aiops-heartbeat 로 하트비트 송신
3) VM 하이퍼바이저(vmx) 로그 → ESXi syslog 경유(VM 고급 설정 vmx.log.destination=syslog-and-disk,
   vmx.log.syslogID=vmx-<VM 이름>) — 게스트 OS 와 무관하게 VM 단위 장치·스냅샷·vMotion 오류

레지스트리
- 호스트별 최초·마지막 수신, 마지막 하트비트, 분당 유입, 최근 15분 등급별 건수, OS·역할·에이전트 종류, vCenter VM 매핑.
- agents.stale_seconds(기본 300초) 동안 로그·하트비트가 모두 없으면 '무응답' → 이벤트(source=vm|baremetal) 발생,
  복구되면 '복구' 이벤트 + 무응답 이상징후 자동 확인. 퇴역(DELETE /api/agents/{host}) 처리한 서버는 감시 제외.
- vCenter 인벤토리와 비교해 '에이전트 미설치 VM'(전원 켜짐) 목록 — 수집 사각지대 확인.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from datetime import datetime
from typing import Any

from .models import LogEvent, norm_severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(host TEXT PRIMARY KEY, kind TEXT, os TEXT, agent TEXT, role TEXT, peer TEXT,
  first_seen REAL, last_seen REAL, last_hb REAL, vm TEXT, info TEXT, retired INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS agent_blocks(host TEXT PRIMARY KEY, since REAL, by TEXT, reason TEXT, hits INTEGER DEFAULT 0,
  last REAL DEFAULT 0, peer TEXT DEFAULT '', path TEXT DEFAULT '');
"""
KINDS = {"vm": "vm", "guest": "vm", "baremetal": "baremetal", "physical": "baremetal", "server": "baremetal",
         "bm": "baremetal"}
WIN_LEVEL = {1: "critical", 2: "error", 3: "warning", 4: "info", 5: "debug", 0: "info"}
JOURNAL_PRI = {"0": "critical", "1": "critical", "2": "critical", "3": "error", "4": "warning", "5": "info", "6": "info",
               "7": "debug"}
HOST_KEYS = ("aiops_host", "_HOSTNAME", "HOSTNAME", "hostname", "host", "Computer", "computer_name", "ComputerName")
DROP_KEYS = {"MESSAGE", "message", "msg", "log", "text", "Message", "StringInserts", "date", "_SOURCE_REALTIME_TIMESTAMP",
             "__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "_BOOT_ID", "_MACHINE_ID", "__CURSOR"}


def _host(it: dict, peer: str) -> str:
    for k in HOST_KEYS:
        v = it.get(k)
        if v:
            return str(v).strip()
    return peer


def _ts(it: dict) -> float:
    for k in ("date", "ts", "timestamp", "@timestamp"):
        v = it.get(k)
        if v is None or v == "":
            continue
        try:
            f = float(v)
            return f / 1000 if f > 1e11 else f
        except (TypeError, ValueError):
            pass
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    tc = it.get("TimeCreated")                        # winevtlog: "2026-10-11 14:03:12 +0900"
    if tc:
        try:
            return datetime.strptime(str(tc), "%Y-%m-%d %H:%M:%S %z").timestamp()
        except ValueError:
            pass
    rt = it.get("_SOURCE_REALTIME_TIMESTAMP") or it.get("__REALTIME_TIMESTAMP")   # journald µs
    if rt:
        try:
            return int(rt) / 1e6
        except (TypeError, ValueError):
            pass
    return time.time()


def _text(v: Any) -> str:
    if isinstance(v, list):                           # journald 바이너리 MESSAGE 는 바이트 배열로 올 수 있음
        try:
            return bytes(int(x) & 0xFF for x in v).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return " ".join(map(str, v))
    return "" if v is None else str(v)


def normalize(it: dict, peer: str, sev_from_text) -> tuple[str, LogEvent | None, dict]:
    """→ (형태, 이벤트, 에이전트 메타). 형태: heartbeat | windows | journald | file | generic | empty"""
    host = _host(it, peer)
    kind = KINDS.get(str(it.get("aiops_kind", "")).lower(), "")
    meta = {"host": host, "kind": kind or "vm", "os": str(it.get("aiops_os", "")).lower(), "role": str(it.get("aiops_role", "")),
            "agent": str(it.get("aiops_agent", "fluent-bit")), "vm": str(it.get("aiops_vm", "")), "peer": peer,
            "version": str(it.get("aiops_agent_version", "")), "distro": str(it.get("aiops_distro", "")).lower()}
    if it.get("aiops_heartbeat"):
        return "heartbeat", None, meta
    explicit = bool(kind)
    src = kind or "vm"
    attrs: dict[str, Any] = {"peer": peer}
    if it.get("aiops_role"):
        attrs["role"] = it["aiops_role"]
    if "EventID" in it and ("Channel" in it or "ProviderName" in it):          # Windows 이벤트 로그
        meta["os"] = meta["os"] or "windows"
        lvl = it.get("Level")
        try:
            sev = WIN_LEVEL.get(int(lvl), "info")
        except (TypeError, ValueError):
            sev = norm_severity(lvl, "info")
        prov = str(it.get("ProviderName", ""))
        body = _text(it.get("Message")).strip() or " ".join(map(str, it.get("StringInserts") or []))
        msg = f"EventID={it.get('EventID')} {prov}: {body}"
        attrs.update({k: it.get(k) for k in ("Channel", "ProviderName", "EventID", "EventRecordID", "Task", "Keywords", "UserID")
                      if it.get(k) not in (None, "")})
        return "windows", LogEvent(source=src, connector="agent", message=msg[:8000], severity=sev, host=host,
                                   entity=str(it.get("Channel", "")), kind="log", ts=_ts(it), attrs=attrs), meta
    if "MESSAGE" in it or "PRIORITY" in it:                                       # journald
        meta["os"] = meta["os"] or "linux"
        ident = str(it.get("SYSLOG_IDENTIFIER") or it.get("_COMM") or it.get("COMM") or "")
        unit = str(it.get("_SYSTEMD_UNIT") or it.get("SYSTEMD_UNIT") or "")
        pid = it.get("_PID") or it.get("PID") or it.get("SYSLOG_PID")
        body = _text(it.get("MESSAGE")).strip()
        pri = str(it.get("PRIORITY", "6"))
        sev = JOURNAL_PRI.get(pri, "info")
        s2 = sev_from_text(body)
        if s2 in ("error", "critical") and sev in ("info", "debug"):
            sev = s2
        msg = f"{ident}{f'[{pid}]' if pid else ''}: {body}" if ident else body
        attrs.update({"unit": unit, "ident": ident, "priority": pri})
        return "journald", LogEvent(source=src, connector="agent", message=msg[:8000], severity=sev, host=host,
                                    entity=ident or unit, kind="log", ts=_ts(it), attrs=attrs), meta
    body = _text(it.get("message") or it.get("msg") or it.get("log") or it.get("text") or it.get("MESSAGE")).strip()
    if not body:
        return "empty", None, meta
    form = "file" if ("file" in it or "path" in it) else "generic"
    if form == "file":
        attrs["file"] = str(it.get("file") or it.get("path"))
    sev = norm_severity(it.get("severity") or it.get("level") or it.get("loglevel"), sev_from_text(body))
    if not explicit:                                     # 표식 없는 기존 HTTP 수집(스크립트 등) — 원래 소스 유지
        src = str(it.get("source") or "vm")
    extra = {k: v for k, v in it.items() if k not in DROP_KEYS and not k.startswith("aiops_") and k not in HOST_KEYS}
    attrs.update({k: v for k, v in list(extra.items())[:30]})
    ent = str(it.get("entity") or it.get("app") or (attrs.get("file", "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1] if form == "file" else ""))
    return form, LogEvent(source=src, connector="agent" if explicit or form == "file" else str(it.get("connector") or "ingest"),
                          message=body[:8000], severity=sev, host=host, entity=ent, kind=str(it.get("kind") or "log"),
                          ts=_ts(it), attrs=attrs), meta


class AgentRegistry:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.stale = float(c.get("stale_seconds", 300))
        self.alert = bool(c.get("alert_on_stale", True))
        self.items: dict[str, dict[str, Any]] = {}
        self._dirty: set[str] = set()
        self.blocked: dict[str, dict[str, Any]] = {}     # 등록 삭제 후 차단 — 다시 보내도 등록·저장하지 않음(시도만 기록)
        self._bdirty: set[str] = set()
        self.dropped = 0
        self._loaded = False
        engine.store.schema(SCHEMA)

    async def load(self) -> None:
        for r in await self.e.store.q("SELECT * FROM agents"):
            try:
                info = json.loads(r.get("info") or "{}")
            except ValueError:
                info = {}
            self.items[r["host"].lower()] = {**r, "info": info, "state": "unknown", "eps": deque(maxlen=15),
                                             "sev15": {}, "cur": 0, "minute": int(time.time() // 60), "alerted": False}
        for r in await self.e.store.q("SELECT * FROM agent_blocks"):
            self.blocked[r["host"].lower()] = dict(r)
        self._loaded = True

    def is_blocked(self, host: str | None, peer: str = "", path: str = "") -> bool:
        """차단된 호스트면 시도(시각·보낸 주소·경로)를 기록하고 True — 누가 아직 보내는지 화면에서 확인"""
        if not self.blocked:
            return False
        b = self.blocked.get((host or "").lower())
        if b is None:
            return False
        b["hits"] = int(b.get("hits") or 0) + 1
        b["last"] = time.time()
        if peer:
            b["peer"] = peer
        if path:
            b["path"] = path
        self._bdirty.add((host or "").lower())
        return True

    def _get(self, meta: dict, path: str = "http") -> dict | None:
        key = (meta.get("host") or "?").lower()
        if key in self.blocked:
            self.is_blocked(key, meta.get("peer") or "", path)
            return None
        it = self.items.get(key)
        now = time.time()
        if it is None:
            it = self.items[key] = {"host": meta.get("host") or "?", "kind": meta.get("kind") or "vm", "os": meta.get("os") or "",
                                    "agent": meta.get("agent") or "", "role": meta.get("role") or "", "peer": meta.get("peer") or "",
                                    "first_seen": now, "last_seen": 0.0, "last_hb": 0.0, "vm": meta.get("vm") or "",
                                    "info": {}, "retired": 0, "state": "new", "eps": deque(maxlen=15), "sev15": {}, "cur": 0,
                                    "minute": int(now // 60), "alerted": False}
        for k in ("kind", "os", "agent", "role", "peer", "vm"):
            v = meta.get(k)
            if v and it.get(k) != v:
                it[k] = v
        if meta.get("version"):
            it["info"]["version"] = meta["version"]
        if meta.get("distro") and it["info"].get("distro") != meta["distro"]:
            it["info"]["distro"] = meta["distro"]
        if it.get("retired"):                      # 퇴역 처리 후 다시 보내기 시작하면 자동 복귀
            it["retired"] = 0
        self._dirty.add(key)
        return it

    def heartbeat(self, meta: dict, path: str = "http") -> None:
        it = self._get(meta, path + " 하트비트")
        if it is None:
            return
        it["last_hb"] = time.time()

    def seen(self, meta: dict, sev: str = "info", path: str = "http") -> None:
        it = self._get(meta, path)
        if it is None:
            return
        now = time.time()
        it["last_seen"] = now
        m = int(now // 60)
        if m != it["minute"]:
            it["eps"].append(it["cur"])
            it["cur"], it["minute"] = 0, m
        it["cur"] += 1
        if sev in ("critical", "error", "warning"):
            s = it["sev15"]
            s[sev] = s.get(sev, 0) + 1

    def touch_syslog(self, ev: LogEvent) -> None:
        """syslog 경로(rsyslog 에이전트·vmx)로 들어온 게스트·서버 로그를 레지스트리에 반영"""
        a = ev.attrs or {}
        meta = {"host": ev.host, "kind": ev.source if ev.source in ("vm", "baremetal") else "vm",
                "os": a.get("aiops_os", "linux" if a.get("app") != "vmx" else ""), "agent": a.get("aiops_agent") or "syslog",
                "role": a.get("role", ""), "peer": a.get("peer", ""), "distro": a.get("aiops_distro", "")}
        path = "ESXi vmx 로그(syslog)" if a.get("app") == "vmx" or str(a.get("app", "")).startswith("vmx-") else "syslog(rsyslog)"
        if a.get("app") in ("aiops-heartbeat", "rsyslogd-pstats"):
            self.heartbeat(meta, path)
        else:
            self.seen(meta, ev.severity, path)

    # ---------------------------------------------------------------- 상태·감시
    def _state(self, it: dict, now: float) -> str:
        if it.get("retired"):
            return "retired"
        last = max(it.get("last_seen") or 0, it.get("last_hb") or 0)
        if not last:
            return "unknown"
        return "stale" if now - last > self.stale else "ok"

    async def loop(self, beat=lambda: None) -> None:
        if not self._loaded:
            await self.load()
        last_flush = 0.0
        while True:
            await asyncio.sleep(15)
            beat()
            now = time.time()
            for key, it in list(self.items.items()):
                st = self._state(it, now)
                prev = it.get("state")
                it["state"] = st
                if int(now // 60) != it["minute"]:          # 유입 없는 분도 0 으로 기록
                    it["eps"].append(it["cur"])
                    it["cur"], it["minute"] = 0, int(now // 60)
                if not self.alert:
                    continue
                if st == "stale" and not it.get("alerted"):
                    it["alerted"] = True
                    last = max(it.get("last_seen") or 0, it.get("last_hb") or 0)
                    self._emit(it, f"에이전트 무응답: {it['host']} — {int((now - last) // 60)}분 동안 로그·하트비트 없음 "
                                   f"(마지막 {time.strftime('%H:%M:%S', time.localtime(last))}, {it.get('agent') or '-'}"
                                   f"{', ' + it['os'] if it.get('os') else ''})", "warning")
                elif st == "ok" and it.get("alerted"):
                    it["alerted"] = False
                    self._emit(it, f"에이전트 복구: {it['host']} — 수집 재개", "info")
                    for a in list(self.e.anomalies.values()):
                        if not a.ack and (a.event or {}).get("entity") == f"agent:{key}":
                            await self.e.ack(a.id)
                if prev != st and st in ("ok", "stale"):
                    self._dirty.add(key)
            if now - last_flush > 30 and (self._dirty or self._bdirty):
                last_flush = now
                await self._flush()
                await self._flush_blocks()

    def _emit(self, it: dict, msg: str, sev: str) -> None:
        self.e.submit(LogEvent(source=it.get("kind") or "vm", connector="agent-monitor", message=msg, severity=sev,
                               host=it["host"], entity=f"agent:{it['host'].lower()}", kind="health",
                               attrs={"agent": it.get("agent"), "os": it.get("os")}))

    async def _flush(self) -> None:
        keys, self._dirty = list(self._dirty), set()
        for k in keys:
            it = self.items.get(k)
            if not it:
                continue
            await self.e.store.x("INSERT OR REPLACE INTO agents(host,kind,os,agent,role,peer,first_seen,last_seen,last_hb,vm,info,retired) "
                                 "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (k, it.get("kind"), it.get("os"), it.get("agent"), it.get("role"), it.get("peer"),
                                  it.get("first_seen"), it.get("last_seen"), it.get("last_hb"), it.get("vm"),
                                  json.dumps(it.get("info") or {}, ensure_ascii=False), int(it.get("retired") or 0)))

    async def retire(self, host: str) -> bool:
        it = self.items.get(host.lower())
        if not it:
            return False
        it["retired"], it["alerted"] = 1, False
        self._dirty.add(host.lower())
        await self._flush()
        return True

    async def _flush_blocks(self) -> None:
        keys, self._bdirty = list(self._bdirty), set()
        for k in keys:
            b = self.blocked.get(k)
            if b:
                await self.e.store.x("UPDATE agent_blocks SET hits=?, last=?, peer=?, path=? WHERE host=?",
                                     (int(b.get("hits") or 0), b.get("last") or 0, b.get("peer") or "", b.get("path") or "", k))

    def blocks(self) -> list[dict]:
        now = time.time()
        out = []
        for k, b in sorted(self.blocked.items(), key=lambda x: -(x[1].get("since") or 0)):
            last = b.get("last") or 0
            out.append({"host": k, "since": b.get("since"), "by": b.get("by") or "", "reason": b.get("reason") or "",
                        "hits": int(b.get("hits") or 0), "last": last, "peer": b.get("peer") or "", "path": b.get("path") or "",
                        "sending": bool(last and now - last < 600)})          # 최근 10분 안에 시도 = 아직 무언가 보내는 중
        return out

    async def unblock(self, host: str) -> bool:
        k = host.lower()
        if self.blocked.pop(k, None) is None:
            return False
        self._bdirty.discard(k)
        await self.e.store.x("DELETE FROM agent_blocks WHERE host=?", (k,))
        return True

    async def purge(self, host: str, block: bool = True, by: str = "") -> bool:
        """등록 삭제 — 목록·DB 에서 지움. block=True(기본)면 같은 호스트가 다시 보내도 등록·저장하지 않고 시도만 기록"""
        k = host.lower()
        it = self.items.pop(k, None)
        self._dirty.discard(k)
        await self.e.store.x("DELETE FROM agents WHERE host=?", (k,))
        if block and (it is not None or k in self.blocked):
            peer = (it or {}).get("peer") or ""
            b = self.blocked.setdefault(k, {"host": k, "since": time.time(), "by": by, "reason": "등록 삭제", "hits": 0, "last": 0,
                                            "peer": peer, "path": ""})
            await self.e.store.x("INSERT OR REPLACE INTO agent_blocks(host,since,by,reason,hits,last,peer,path) VALUES(?,?,?,?,?,?,?,?)",
                                 (k, b["since"], b.get("by") or "", b.get("reason") or "", int(b.get("hits") or 0), b.get("last") or 0,
                                  b.get("peer") or "", b.get("path") or ""))
        if it is None:
            return False
        for a in list(self.e.anomalies.values()):          # 이 호스트의 무응답 경보는 함께 확인 처리
            ev = a.event or {}
            if not a.ack and str(ev.get("host", "")).lower() == k and ev.get("source") == "aiops" and "agent" in str(ev.get("message", "")).lower():
                await self.e.ack(a.id)
        return True

    # ---------------------------------------------------------------- 조회
    def _vm_of(self, it: dict) -> dict | None:
        names = [n for n in (it.get("vm"), it.get("host"), (it.get("host") or "").split(".")[0]) if n]
        for c in self.e._vcenters():
            vms = c.topology.get("vms", {})
            for n in names:
                v = vms.get(n)
                if v:
                    return {"vm": n, **{k: v.get(k) for k in ("host", "cluster", "power")}}
            low = {k.lower(): k for k in vms}
            for n in names:
                k = low.get(n.lower())
                if k:
                    return {"vm": k, **{x: vms[k].get(x) for x in ("host", "cluster", "power")}}
        return None

    def list(self) -> list[dict]:
        now = time.time()
        out = []
        for key, it in sorted(self.items.items()):
            st = self._state(it, now)
            eps = list(it["eps"])
            out.append({"host": it["host"], "kind": it.get("kind"), "os": it.get("os"), "agent": it.get("agent"),
                        "role": it.get("role"), "peer": it.get("peer"), "state": st, "first_seen": it.get("first_seen"),
                        "last_seen": it.get("last_seen") or None, "last_heartbeat": it.get("last_hb") or None,
                        "per_min": it["cur"], "avg_per_min": round(sum(eps) / len(eps), 1) if eps else it["cur"],
                        "sev15": it.get("sev15", {}), "version": (it.get("info") or {}).get("version", ""),
                        "vcenter": self._vm_of(it) if it.get("kind") == "vm" else None})
        return out

    def entities(self, kind: str) -> list[dict]:
        """통합 관제 상태맵 — 그룹: 역할(aiops_role) 또는 OS"""
        now = time.time()
        out = []
        for it in self.items.values():
            if (it.get("kind") or "vm") != kind or it.get("retired"):
                continue
            st = self._state(it, now)
            last = max(it.get("last_seen") or 0, it.get("last_hb") or 0)
            v = self._vm_of(it) if kind == "vm" else None
            detail = f"{it.get('os') or '-'} · {it.get('agent') or '-'} · 마지막 수신 {time.strftime('%H:%M:%S', time.localtime(last)) if last else '-'}"
            if v:
                detail += f" · ESXi {v.get('host') or '-'} / {v.get('cluster') or '-'}"
            out.append({"name": it["host"], "kind": "guest" if kind == "vm" else "os",
                        "group": it.get("role") or {"windows": "Windows", "linux": "Linux"}.get(it.get("os") or "", "기타"),
                        "state": {"ok": "ok", "stale": "warn", "unknown": "unknown"}.get(st, "unknown"),
                        "detail": detail + (" · 에이전트 무응답" if st == "stale" else "")})
        return out

    def coverage(self) -> dict[str, Any]:
        """vCenter 전원 켜진 VM 중 에이전트(로그 수신) 기록이 없는 VM"""
        have = set()
        for it in self.items.values():
            if it.get("retired"):
                continue
            for n in (it.get("vm"), it.get("host"), (it.get("host") or "").split(".")[0]):
                if n:
                    have.add(n.lower())
        total, missing = 0, []
        for c in self.e._vcenters():
            for name, v in c.topology.get("vms", {}).items():
                if "poweredOn" not in str(v.get("power", "")):
                    continue
                total += 1
                if name.lower() not in have and name.split(".")[0].lower() not in have:
                    missing.append({"vm": name, "host": v.get("host"), "cluster": v.get("cluster"), "vcenter": c.name})
        return {"powered_on_vms": total, "with_agent": total - len(missing), "missing": sorted(missing, key=lambda x: x["vm"])[:2000]}
