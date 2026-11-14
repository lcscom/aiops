"""호스트 분석(2.18.0) — 호스트 목록(최근 끊김 횟수·syslog 수신 상태) · 한 호스트의 끊김 구간 원인 분석 · AI 설명

데이터: ① vCenter API(커넥터의 읽기 전용 계정 — 이벤트·작업·vpxd 로그·호스트 hostd/vpxa/vmkernel/vobd 로그)
       ② 이 제품이 이미 저장한 로그(vCenter 이벤트, ESXi syslog, BrowseDiagnosticLog 수집분) — 보관 기간(server.retention_days) 만큼 과거까지
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import time
from typing import Any

from . import analyze as A
from .parse import is_down

DOWN_SQL = ("(message LIKE '%not responding%' OR message LIKE '%isconnected%' OR message LIKE '%connection lost%' OR message LIKE '%lost connection%' "
            "OR message LIKE '%Cannot synchronize host%' OR message LIKE '%NO_RESPONSE%' OR attrs LIKE '%HostConnectionLostEvent%' OR attrs LIKE '%HostDisconnectedEvent%')")


class HostDiag:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self.cache: dict[str, dict] = {}
        self.list_ttl = float(self.cfg.get("list_cache_seconds", 300))    # 2.30.0 목록용 DB 집계(끊김 7일·syslog 24시간) 캐시
        self._lc: dict[str, tuple[float, Any]] = {}
        self._lc_locks: dict[str, asyncio.Lock] = {}

    async def _cached(self, key: str, fn):
        """목록 화면용 무거운 조회 — TTL 캐시 + 동시 요청은 1회만 조회"""
        hit = self._lc.get(key)
        if hit and time.time() - hit[0] < self.list_ttl:
            return hit[1]
        async with self._lc_locks.setdefault(key, asyncio.Lock()):
            hit = self._lc.get(key)
            if hit and time.time() - hit[0] < self.list_ttl:
                return hit[1]
            val = await fn()
            if len(self._lc) > 50:
                self._lc.clear()
            self._lc[key] = (time.time(), val)
            return val

    def vcenters(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcenter" and hasattr(c, "host_diag")]

    def all_hosts(self) -> dict[str, dict]:
        out = {}
        for c in self.vcenters():
            for hn, h in (getattr(c, "topology", {}) or {}).get("hosts", {}).items():
                out[hn] = {"name": hn, "vcenter": c.name, "cluster": h.get("cluster", ""), "connection": h.get("conn", ""),
                           "maintenance": bool(h.get("maintenance")), "status": h.get("status", "")}
        return out

    def _owner(self, msg: str, row_host: str, names: list[tuple[str, str, str]]) -> str:
        m = (msg or "").lower()
        for full, short, orig in names:           # 메시지에 이름이 나오면 그 호스트(vCenter 이벤트의 host 필드가 다른 경우가 있음)
            if full in m or (len(short) >= 4 and re.search(rf"(?<![\w-]){re.escape(short)}(?![\w-])", m)):
                return orig
        rh = (row_host or "")
        return next((o for f, sh, o in names if rh.lower() in (f, sh)), rh)

    async def _downs(self, since: float, until: float) -> list[dict]:
        # 2.30.0 vCenter API 커넥터가 있으면 이벤트는 그쪽(connector = vCenter 이름)으로 들어온다 — syslog 로 받은 vpxd 줄(connector='syslog',
        # 건수가 압도적)은 LIKE 검사 전에 제외. vCenter 커넥터가 없을 때만 syslog 줄까지 본다.
        skip = "connector != 'syslog' AND " if self.vcenters() else ""
        rows = await self.e.store.q(f"SELECT ts, host, message, attrs FROM logs WHERE source='vcenter' AND ts BETWEEN ? AND ? AND {skip}{DOWN_SQL} "   # noqa: S608
                                    "ORDER BY ts LIMIT 50000", (since, until))
        names = [(n.lower(), n.split(".")[0].lower(), n) for n in self.all_hosts()]
        out = []
        for r in rows:
            try:
                at = json.loads(r["attrs"] or "{}")
            except Exception:  # noqa: BLE001
                at = {}
            it = {"ts": r["ts"], "type": at.get("eventType") or "", "message": r["message"], "user": at.get("user")}
            if is_down(it):
                out.append({**it, "host": self._owner(r["message"], r["host"], names)})
        return out

    async def hosts(self, days: float = 7) -> dict:
        now = time.time()
        base = self.all_hosts()
        downs = await self._cached(f"downs:{days:g}", lambda: self._downs(now - days * 86400, now))
        per: dict[str, list] = {}
        for d in downs:
            per.setdefault(d["host"].lower(), []).append(d["ts"])
        sl = await self._cached("syslog24", lambda: self.e.store.q(
            "SELECT lower(host) AS h, COUNT(*) AS n, MAX(ts) AS last FROM logs WHERE source='esxi' AND ts > ? "
            "AND (attrs IS NULL OR attrs NOT LIKE '%BrowseDiagnosticLog%') GROUP BY lower(host)", (now - 86400,)))
        sys = {r["h"]: dict(r) for r in sl}
        # 캐시 사이(최대 5분)의 최신 수신은 메모리 집계(ENGINE.hostseen)로 보완 — 막 보내기 시작한 호스트가 바로 ✓ 로 보이게.
        # vCenter 가 호스트 로그를 대신 읽어 오는(BrowseDiagnosticLog) 구성에서는 syslog 와 구분할 수 없어 보완하지 않는다.
        if not any(getattr(c, "host_logs", None) for c in self.vcenters()):
            for hn, hs in list((getattr(self.e, "hostseen", None) or {}).items()):
                if "esxi" in hs[0] and hs[2] > now - 86400:
                    r = sys.setdefault(hn.lower(), {"h": hn.lower(), "n": 0, "last": None})
                    r["n"] = r["n"] or int(hs[1])
                    r["last"] = max(r["last"] or 0, hs[2])
        rows = []
        for hn, h in base.items():
            k, short = hn.lower(), hn.split(".")[0].lower()
            ts = sorted(per.get(k, []))
            eps = []                                   # 5분 안의 표식은 한 번으로
            for t in ts:
                if not eps or t - eps[-1] > 300:
                    eps.append(t)
            s = sys.get(k) or sys.get(short) or {}
            rows.append({**h, "disconnects": len(eps), "last_disconnect": eps[-1] if eps else None,
                         "syslog_24h": int(s.get("n") or 0), "syslog_last": s.get("last")})
        known = {x.lower() for x in base}
        for k, ts in per.items():                       # 인벤토리에서 빠졌지만 기록이 있는 호스트
            if k and k not in known and not any(k == x.split(".")[0] for x in known):
                rows.append({"name": k, "vcenter": "", "cluster": "", "connection": "(인벤토리에 없음)", "maintenance": False, "status": "",
                             "disconnects": len({int(t // 300) for t in ts}), "last_disconnect": max(ts), "syslog_24h": 0, "syslog_last": None})
        rows.sort(key=lambda r: (-(r["disconnects"] or 0), r["connection"] == "connected", r["name"]))
        return {"items": rows, "days": days, "vcenters": [c.name for c in self.vcenters()], "generated": now}

    async def _stored(self, name: str, ip: str, start: float, end: float, limit: int = 40000) -> list[dict]:
        h, short = name.lower(), name.split(".")[0].lower()
        cond = "(lower(host) = ? OR lower(host) = ? OR lower(host) LIKE ?" + (" OR host = ?" if ip else "") + \
               " OR (source='vcenter' AND (lower(message) LIKE ? OR lower(message) LIKE ?)))"
        p: list[Any] = [start, end, h, short, short + ".%"] + ([ip] if ip else []) + [f"%{h}%", f"%{short}%"]
        rows = await self.e.store.q(f"SELECT id, ts, source, severity, host, entity, kind, message, attrs FROM logs WHERE ts BETWEEN ? AND ? AND {cond} "   # noqa: S608
                                    "ORDER BY ts DESC LIMIT ?", p + [limit])
        if short and len(short) < 4:
            return rows
        out = []
        for r in rows:                                   # 메시지 LIKE 로 잡힌 vCenter 이벤트는 단어 경계로 다시 확인(esx1 ⊂ esx10 방지)
            hh = (r["host"] or "").lower()
            if hh in (h, short) or hh.startswith(short + ".") or (ip and r["host"] == ip) or \
                    re.search(rf"(?<![\w-]){re.escape(short)}(?![\w-])", (r["message"] or "").lower()):
                out.append(r)
        return out

    async def analyze(self, name: str, start: float, end: float, live: bool = True, before: float = 1800, after: float = 600) -> dict:
        start, end = float(start), float(end)
        if end <= start:
            raise ValueError("기간 오류")
        if end - start > 31 * 86400:
            raise ValueError("기간은 31일 이하")
        conn = next((c for c in self.vcenters() if name in (getattr(c, "topology", {}) or {}).get("hosts", {})), None)
        vc, err = None, ""
        if conn is not None:
            try:
                vc = await asyncio.wait_for(asyncio.to_thread(conn.host_diag, name, start, end, live), 300)
                if vc.get("error"):
                    err, vc = vc["error"], None
            except Exception as ex:  # noqa: BLE001
                err = f"vCenter 조회 실패: {type(ex).__name__}: {ex}"[:300]
        else:
            err = "이 호스트를 가진 vCenter 커넥터가 없음 — 저장된 로그로만 분석"
        ip = ((vc or {}).get("state") or {}).get("mgmt_ip", "")
        stored = await self._stored(name, ip, start, end)
        downs = await self._downs(start - 300, end + 300)
        me = {name.lower(), name.split(".")[0].lower()}

        def peers(ts):
            seen, out = set(), []
            for d in downs:
                hl = d["host"].lower()
                if abs(d["ts"] - ts) <= 120 and hl not in me and hl.split(".")[0] not in me and hl not in seen:
                    seen.add(hl)
                    out.append(d)
            return out
        hs = await self.hosts(1)
        mine = next((x for x in hs["items"] if x["name"] == name), {})
        sysrate = {"lines_24h": mine.get("syslog_24h", 0), "last": mine.get("syslog_last")}
        res = await asyncio.to_thread(A.analyze, name, vc, stored, start, end, peers, sysrate, before, after)
        res.update({"state": (vc or {}).get("state") or {}, "vcenter": getattr(conn, "name", ""), "error": err, "gaps": (vc or {}).get("gaps", []),
                    "vpxd": (vc or {}).get("vpxd"), "host_logs": (vc or {}).get("host_logs"), "syslog": sysrate, "live": live,
                    "stored_rows": len(stored), "generated": time.time(), "kb": A.KB})
        if len(res["items"]) > 20000:
            res["items"] = res["items"][-20000:]
            res["gaps"].append("타임라인 20,000줄 초과 — 최신분만")
        self.cache[name] = res
        return res

    def csv(self, res: dict) -> bytes:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["time", "kind", "via", "source", "severity", "type", "user", "message"])
        for it in res["items"]:
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it["ts"])), it.get("kind"), it.get("via"), it.get("source"), it.get("severity"),
                        it.get("type", ""), it.get("user") or "", it.get("message")])
        return ("﻿" + buf.getvalue()).encode("utf-8")

    async def ai(self, name: str) -> dict:
        res = self.cache.get(name)
        if not res:
            raise KeyError(name)
        llm = self.e.llm
        if not llm:
            raise RuntimeError("LLM 비활성")
        eps = []
        for ep in res["episodes"][:8]:
            eps.append({"시작": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ep["start"])), "지속초": ep["duration"], "진행중": ep["ongoing"],
                        "사용자작업": ep["user_initiated"], "계기": ep["trigger"].get("message"), "메모": ep["notes"],
                        "원인후보": [{"원인": c["title"], "점수": c["score"], "확신": c["confidence"],
                                   "증거": [f"{time.strftime('%H:%M:%S', time.localtime(x['ts']))} [{x.get('source')}] {str(x.get('message'))[:220]}" for x in c["evidence"][:6]]}
                                  for c in ep["causes"][:4]]})
        d = {"호스트": name, "상태": {k: res["state"].get(k) for k in ("connection", "version", "build", "boot_time", "mgmt_ip", "vc_managed_ip", "vc_ip_seen_by_host",
                                                                     "ha_state", "lockdown", "vendor", "model") if res["state"].get(k) is not None},
             "기간": [time.strftime("%Y-%m-%d %H:%M", time.localtime(res["start"])), time.strftime("%Y-%m-%d %H:%M", time.localtime(res["end"]))],
             "끊김횟수": res["counts"]["episodes"], "반복패턴": res["patterns"], "수집공백": res["gaps"], "syslog": res["syslog"], "끊김구간": eps}
        sys = ("너는 VMware vSphere 운영 SRE 다. 아래 JSON(호스트 연결 끊김 구간별 원인 후보·증거 로그·반복 패턴)만 근거로 한국어로 답한다. "
               "## 결론(가장 가능성 높은 원인 1~2개와 근거 로그 시각) · ## 근거 · ## 확인 순서(읽기 전용 명령 먼저, 변경은 [변경] 표시) · ## 재발 방지. "
               "참고 KB: 344682(not responding/disconnected 점검), 318647(UDP 902 하트비트·60초 반복=방화벽), 377738(다수 호스트 동시), 433257(hostd 무응답), "
               "320280(관리 에이전트 재시작). JSON 에 없는 로그·수치는 만들지 않고, 증거가 부족하면 무엇을 더 수집할지 말한다.")
        names = list(self.all_hosts()) + [name]
        txt = await llm.complete(sys, json.dumps(d, ensure_ascii=False, default=str)[:14000], max_tokens=2500, task="report", names=names)
        return {"report": txt, "at": time.time()}
