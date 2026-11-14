"""수집 일시정지 스위치(2.22.1) — 로그 폭주(예: vCenter syslog)로 서버가 느려질 때 수집을 멈춘다.

  수동   화면(플랫폼 상태 › 수집 일시정지)·API·CLI(sudo vcf-aiopsctl pause [분] [--sender IP] | resume)
         범위: all(플랫폼 자체 이벤트 제외 전부) · syslog(syslog 수신만) · senders(지정한 보낸 쪽 IP·호스트 이름만)
         기간: N분 후 자동 재개 또는 직접 재개할 때까지
  자동   5초마다 과부하 판정 — 처리 대기열 사용률 · 이벤트 루프 지연(p99) · DB 읽기 지연(p95, 화면 조회가 밀리는지) ·
         초당 수신 건수 중 하나라도 기준을 연속 3회(15초) 넘으면 일시정지.
         기본 범위 top_sender: 최근 60초 수신량의 30% 이상을 보낸 상위 송신자만 멈춤(나머지 장비 로그는 계속).
         pause_minutes 뒤 자동 재개, 다시 과부하면 2배씩(최대 max_pause_minutes) 길게 다시 멈춤.
멈춘 동안 들어온 로그는 저장·분석하지 않고 건수만 센다(syslog 는 파싱 전에 버려 CPU 를 아낌).
플랫폼 자체 이벤트(source=aiops)·폴링 커넥터의 상태 수집은 범위 all 이 아니면 계속된다.
상태는 DB(settings: ingest_gate)에 저장돼 재시작 후에도 유지.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

from .models import LogEvent

AUTO_DEFAULT = {"enabled": True, "queue_pct": 70, "lag_ms": 800, "read_ms": 3000, "max_eps": 0, "consecutive": 3,
                "pause_minutes": 10, "max_pause_minutes": 60, "scope": "top_sender", "top_share": 30}
SCOPES = ("all", "syslog", "senders")


def _norm_sender(s: str) -> str:
    return str(s or "").strip().lower().rstrip(".")


class IngestGate:
    def __init__(self, engine, cfg: dict | None, data_dir: str):
        self.e = engine
        cfg = cfg or {}
        self.auto = {**AUTO_DEFAULT, **(cfg.get("auto") or {})}
        self.ctl_file = Path(cfg.get("control_file") or Path(data_dir) / "ingest-control.json")
        self.paused = False
        self.scope = "syslog"
        self.senders: set[str] = set()
        self.nets: list = []
        self.shorts: set[str] = set()
        self.until = 0.0
        self.since = 0.0
        self.by = ""
        self.reason = ""
        self.dropped = 0
        self.dropped_by: dict[str, int] = {}
        self.auto_level = 0                        # 자동 재일시정지 단계(2배씩)
        self._over = 0
        self.last_check: dict[str, Any] = {}
        self.history: deque[dict] = deque(maxlen=50)
        self._win: deque[tuple[float, dict[str, int]]] = deque(maxlen=12)      # 5초 칸 × 12 = 60초
        self._cur: dict[str, int] = {}
        self._cur_total = 0
        self._loaded = False

    # ------------------------------------------------------------------ 빠른 경로(수신마다)
    def tick(self, sender: str) -> None:
        self._cur[sender] = self._cur.get(sender, 0) + 1
        self._cur_total += 1

    def _sender_match(self, ip: str, host: str = "") -> bool:
        if ip and ip in self.senders:
            return True
        if host and _norm_sender(host) in self.senders:
            return True
        if host and _norm_sender(host).split(".")[0] in self.shorts:      # FQDN ↔ 짧은 이름
            return True
        if ip and self.nets:
            try:
                a = ipaddress.ip_address(ip)
                return any(a in n for n in self.nets)
            except ValueError:
                return False
        return False

    @staticmethod
    def _shorts(ss: set[str]) -> set[str]:
        out = set()
        for s in ss:
            try:
                ipaddress.ip_network(s, strict=False)
            except ValueError:
                out.add(s.split(".")[0])
        return out

    def drop_raw(self, peer: str) -> bool:
        """syslog 원문(파싱 전) — 멈춘 대상이면 True(버림)"""
        if not self.paused:
            return False
        if self.until and time.time() >= self.until:
            return False                                      # 만료 — 다음 점검에서 재개 처리
        if self.scope in ("all", "syslog") or (self.scope == "senders" and self._sender_match(peer)):
            self._count(peer)
            return True
        return False

    def drop_event(self, ev: LogEvent) -> bool:
        """엔진 입구 — syslog 외 경로(HTTP 수집·에이전트·SNMP·폴링)와 호스트 이름 지정"""
        if not self.paused or ev.source == "aiops":
            return False
        if self.until and time.time() >= self.until:
            return False
        if self.scope == "all":
            self._count(ev.host or ev.connector or "-")
            return True
        if self.scope == "senders" and self.senders and self._sender_match(str(ev.attrs.get("peer", "")) if ev.attrs else "", ev.host or ""):
            self._count(ev.host or "-")
            return True
        return False

    def _count(self, key: str) -> None:
        self.dropped += 1
        if len(self.dropped_by) < 500 or key in self.dropped_by:
            self.dropped_by[key] = self.dropped_by.get(key, 0) + 1

    # ------------------------------------------------------------------ 상태 바꾸기
    async def pause(self, minutes: float | None, scope: str = "syslog", senders: list[str] | None = None, by: str = "", reason: str = "") -> dict:
        if scope not in SCOPES:
            raise ValueError(f"범위는 {', '.join(SCOPES)}")
        ss = {_norm_sender(s) for s in (senders or []) if _norm_sender(s)}
        if scope == "senders" and not ss:
            raise ValueError("멈출 송신자(IP·호스트 이름)를 하나 이상 지정하세요")
        nets = []
        for s in ss:
            if "/" in s:
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError as e:
                    raise ValueError(f"잘못된 대역 {s}") from e
        self.paused, self.scope, self.senders, self.nets = True, scope, ss, nets
        self.shorts = self._shorts(ss)
        self.since = time.time()
        self.until = time.time() + float(minutes) * 60 if minutes else 0.0
        self.by, self.reason = by or "-", (reason or "")[:300]
        self.dropped, self.dropped_by = 0, {}
        self._log("pause")
        await self._save()
        self._event(f"수집 일시정지({self._scope_text()}) — {self.reason or by}" + (f", {minutes:g}분 후 자동 재개" if minutes else ", 직접 재개할 때까지"),
                    "warning", False)
        return self.status()

    async def resume(self, by: str = "", reason: str = "") -> dict:
        if not self.paused:
            return self.status()
        n = self.dropped
        self.paused = False
        self.by, self.reason = by or "-", reason
        self._log("resume", dropped=n)
        if by != "auto":
            self.auto_level = 0
        await self._save()
        self._event(f"수집 재개 — 멈춘 동안 버린 로그 {n:,}건 ({reason or by})", "info", True)
        return self.status()

    def _scope_text(self) -> str:
        return {"all": "전체 수집", "syslog": "syslog 전체"}.get(self.scope) or ("송신자 " + ", ".join(sorted(self.senders))[:120])

    def _log(self, action: str, **kw) -> None:
        self.history.appendleft({"ts": time.time(), "action": action, "scope": self.scope, "senders": sorted(self.senders),
                                 "by": self.by, "reason": self.reason, "until": self.until, **kw})

    def _event(self, msg: str, sev: str, recovered: bool) -> None:
        print(f"[ingest-gate] {msg}", flush=True)
        try:
            self.e.submit(LogEvent(source="aiops", connector="ingest-gate", message=msg, severity=sev, host="aiops",
                                   entity="platform:ingest_paused", kind="health", attrs={"check": "ingest_paused", "recovered": recovered}))
        except Exception:  # noqa: BLE001
            pass
        try:
            asyncio.get_running_loop().create_task(self.e.audit.log("ingest.resume" if recovered else "ingest.pause", user=self.by or "-",
                                                                    target=self._scope_text(), result="ok", detail={"reason": self.reason[:200]}))
        except Exception:  # noqa: BLE001
            pass

    async def set_auto(self, cfg: dict, by: str) -> dict:
        a = dict(self.auto)
        for k, typ in (("enabled", bool), ("queue_pct", float), ("lag_ms", float), ("read_ms", float), ("max_eps", float),
                       ("consecutive", int), ("pause_minutes", float), ("max_pause_minutes", float), ("top_share", float)):
            if k in cfg and cfg[k] is not None:
                a[k] = bool(cfg[k]) if typ is bool else typ(cfg[k])
        if cfg.get("scope") in ("top_sender", "syslog", "all"):
            a["scope"] = cfg["scope"]
        a["queue_pct"] = min(max(a["queue_pct"], 10), 100)
        a["consecutive"] = min(max(a["consecutive"], 1), 60)
        a["pause_minutes"] = min(max(a["pause_minutes"], 1), 1440)
        a["max_pause_minutes"] = min(max(a["max_pause_minutes"], a["pause_minutes"]), 1440)
        a["top_share"] = min(max(a["top_share"], 5), 100)
        for k in ("lag_ms", "read_ms", "max_eps"):
            a[k] = max(0.0, a[k])
        self.auto = a
        await self._save()
        return a

    # ------------------------------------------------------------------ 저장·복원
    async def _save(self) -> None:
        v = {"paused": self.paused, "scope": self.scope, "senders": sorted(self.senders), "until": self.until, "since": self.since,
             "by": self.by, "reason": self.reason, "auto": self.auto, "auto_level": self.auto_level}
        try:
            await self.e.store.x("INSERT INTO settings(key,value,updated,updated_by) VALUES('ingest_gate',?,?,?) "
                                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
                                 (json.dumps(v, ensure_ascii=False), time.time(), self.by or "-"))
        except Exception as e:  # noqa: BLE001
            print(f"[ingest-gate] 저장 실패: {e}", flush=True)

    async def load(self) -> None:
        self._loaded = True
        try:
            r = await self.e.store.q1("SELECT value FROM settings WHERE key='ingest_gate'")
        except Exception:  # noqa: BLE001
            return
        if not r:
            return
        try:
            v = json.loads(r["value"])
        except ValueError:
            return
        self.auto = {**self.auto, **(v.get("auto") or {})}
        self.auto_level = int(v.get("auto_level") or 0)
        if v.get("paused") and (not v.get("until") or v["until"] > time.time()):
            ss = set(v.get("senders") or [])
            self.paused, self.scope, self.senders = True, v.get("scope", "syslog"), ss
            self.nets = [ipaddress.ip_network(s, strict=False) for s in ss if "/" in s]
            self.shorts = self._shorts(ss)
            self.until, self.since, self.by, self.reason = float(v.get("until") or 0), float(v.get("since") or time.time()), v.get("by", ""), v.get("reason", "")
            print(f"[ingest-gate] 재시작 전 일시정지 유지 — {self._scope_text()}", flush=True)

    # ------------------------------------------------------------------ 측정·자동
    def rates(self) -> dict:
        tot = sum(sum(b.values()) for _, b in self._win)
        span = max(5.0, (time.time() - self._win[0][0]) if self._win else 5.0)
        per: dict[str, int] = {}
        for _, b in self._win:
            for k, v in b.items():
                per[k] = per.get(k, 0) + v
        top = sorted(per.items(), key=lambda x: -x[1])[:10]
        return {"eps": round(tot / span, 1), "window_s": round(span), "top": [{"sender": k, "eps": round(v / span, 1), "share": round(v * 100 / tot, 1) if tot else 0}
                                                                         for k, v in top]}

    def measure(self) -> dict:
        e = self.e
        q = round(len(e.q_lo) * 100 / max(1, e.q_lo_max), 1)
        st = e.store.status()
        sq = round(st.get("log_queue", 0) * 100 / max(1, st.get("log_queue_max", 1)), 1)
        lag = e.lag.stats().get("p99_ms", 0.0)
        read = e.store.read_p95() if hasattr(e.store, "read_p95") else 0.0
        r = self.rates()
        a = self.auto
        why = []
        if max(q, sq) >= a["queue_pct"]:
            why.append(f"처리 대기열 {max(q, sq):.0f}% ≥ {a['queue_pct']:.0f}%")
        if a["lag_ms"] and lag >= a["lag_ms"]:
            why.append(f"이벤트 루프 지연 p99 {lag:.0f}ms ≥ {a['lag_ms']:.0f}ms")
        if a["read_ms"] and read >= a["read_ms"]:
            why.append(f"DB 조회 지연 p95 {read:.0f}ms ≥ {a['read_ms']:.0f}ms")
        if a["max_eps"] and r["eps"] >= a["max_eps"]:
            why.append(f"수신 {r['eps']:.0f}건/초 ≥ {a['max_eps']:.0f}")
        return {"ts": time.time(), "queue_pct": max(q, sq), "lag_p99_ms": lag, "read_p95_ms": read, "eps": r["eps"], "top": r["top"], "overload": why}

    async def step(self) -> None:
        now = time.time()
        self._win.append((now, self._cur))
        self._cur, self._cur_total = {}, 0
        await self._control_file()
        if self.paused and self.until and now >= self.until:
            await self.resume("auto" if self.by == "auto" else "timer", "기간 만료")
        m = self.measure()
        self.last_check = m
        a = self.auto
        if not a["enabled"]:
            self._over = 0
            return
        if m["overload"]:
            self._over += 1
        else:
            self._over = 0
            if not self.paused and self.auto_level and now - self.since > 3600:
                self.auto_level = 0                          # 1시간 안정 → 단계 초기화
        if self._over >= int(a["consecutive"]) and not self.paused:
            self._over = 0
            mins = min(a["pause_minutes"] * (2 ** self.auto_level), a["max_pause_minutes"])
            scope, senders = a["scope"], []
            if scope == "top_sender":
                top = [t for t in m["top"] if t["share"] >= a["top_share"]]
                if top:
                    scope, senders = "senders", [top[0]["sender"]]
                else:
                    scope = "syslog"
            self.auto_level += 1
            await self.pause(mins, scope, senders, by="auto", reason="자동: " + " · ".join(m["overload"]))

    async def _control_file(self) -> None:
        """CLI(sudo vcf-aiopsctl pause|resume) 가 남긴 요청 처리"""
        p = self.ctl_file
        if not p.exists():
            return
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            req = {}
        try:
            p.unlink()
        except OSError:
            pass
        try:
            if req.get("action") == "pause":
                s = [x for x in (req.get("senders") or []) if x]
                await self.pause(float(req["minutes"]) if req.get("minutes") else None, "senders" if s else req.get("scope", "syslog"), s,
                                 by="cli", reason=req.get("reason") or "콘솔 명령")
            elif req.get("action") == "resume":
                await self.resume("cli", "콘솔 명령")
            elif req.get("action") == "auto":
                await self.set_auto({"enabled": bool(req.get("enabled"))}, "cli")
        except (ValueError, KeyError) as e:
            print(f"[ingest-gate] 콘솔 요청 오류: {e}", flush=True)

    async def loop(self, beat=lambda: None) -> None:
        if not self._loaded:
            await self.load()
        while True:
            beat()
            try:
                await self.step()
            except Exception as e:  # noqa: BLE001
                print(f"[ingest-gate] 오류: {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(5)

    def status(self) -> dict:
        left = max(0.0, self.until - time.time()) if self.paused and self.until else None
        top_dropped = sorted(self.dropped_by.items(), key=lambda x: -x[1])[:10]
        return {"paused": self.paused, "scope": self.scope, "scope_text": self._scope_text() if self.paused else "", "senders": sorted(self.senders),
                "since": self.since, "until": self.until, "left_s": round(left) if left is not None else None, "by": self.by, "reason": self.reason,
                "dropped": self.dropped, "dropped_by": [{"sender": k, "n": v} for k, v in top_dropped],
                "auto": self.auto, "auto_level": self.auto_level, "over_count": self._over, "check": self.last_check,
                "history": list(self.history)[:20], "cli": os.path.basename(str(self.ctl_file))}
