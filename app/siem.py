"""SIEM 전달 — CEF(ArcSight Common Event Format) 를 syslog(RFC 5424, UDP·TCP·TLS)로 보낸다. Splunk·QRadar·ArcSight·Sentinel·Elastic 공통.

보내는 것(설정 siem.*): 감사 로그(인증·설정·조치·사용자) · 이상징후(알림 등급 이상) · 인시던트 생성/상태 변경 · 보안 판독(VMSA 긴급)
형식  CEF:0|Broadcom|VCF AIops|<버전>|<signature>|<name>|<severity 0-10>|키=값 …  (CEF 이스케이프: '\\' '|' '=' 개행)
전송  비동기 큐(최대 5,000건, 넘치면 오래된 것부터 버리고 drops 집계) → 단일 소켓, 실패 시 5초 뒤 재연결. 수신 확인이 없는 UDP 는 재시도 없음.
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
from collections import deque
from typing import Any

from .models import SEV_RANK

CEF_SEV = {"info": 2, "warning": 5, "error": 7, "critical": 10}
AUDIT_SEV = {"ok": 3, "fail": 6, "denied": 7, "locked": 7, "rate_limited": 6, "mfa_pending": 2, "disabled": 6, "ip_denied": 7, "no_role": 6}
AUDIT_SKIP = ("auth.heartbeat",)


def cef_escape(v: Any, header: bool = False) -> str:
    s = str(v if v is not None else "")
    s = s.replace("\\", "\\\\")
    if header:
        s = s.replace("|", "\\|")
    else:
        s = s.replace("=", "\\=")
    return s.replace("\r", " ").replace("\n", "\\n")


def cef(vendor: str, product: str, version: str, sig: str, name: str, sev: int, ext: dict[str, Any]) -> str:
    head = "|".join(cef_escape(x, True) for x in ("CEF:0", vendor, product, version, sig, name[:200], str(max(0, min(10, int(sev))))))
    body = " ".join(f"{k}={cef_escape(v)}" for k, v in ext.items() if v not in (None, ""))
    return f"{head}|{body}"


class Siem:
    def __init__(self, cfg: dict | None, version: str = "", hostname: str = ""):
        self.version = version or "0"
        self.hostname = hostname or socket.gethostname()
        self.q: deque[str] = deque(maxlen=5000)
        self.stats = {"sent": 0, "drops": 0, "errors": 0, "last_error": "", "last_sent": 0.0, "connected": False}
        self._wake = asyncio.Event()
        self._sock: Any = None
        self._writer: asyncio.StreamWriter | None = None
        self.configure(cfg or {})

    def configure(self, cfg: dict) -> None:
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled")) and bool(self.cfg.get("host"))
        self.min_sev = SEV_RANK.get(str(self.cfg.get("min_severity", "warning")), 2)
        self._close()

    def status(self) -> dict:
        return {**self.stats, "enabled": self.enabled, "queued": len(self.q), "host": self.cfg.get("host", ""),
                "port": int(self.cfg.get("port", 514)), "protocol": self.cfg.get("protocol", "udp")}

    # ---------------------------------------------------------------- 이벤트 입구(동기 — 큐에만 넣음)
    def _push(self, sig: str, name: str, sev: int, ext: dict[str, Any]) -> None:
        if not self.enabled:
            return
        line = cef("Broadcom", "VCF AIops", self.version, sig, name, sev, {"rt": int(time.time() * 1000), "dvchost": self.hostname, **ext})
        if len(self.q) >= self.q.maxlen:
            self.stats["drops"] += 1
        self.q.append(line)
        self._wake.set()

    def audit(self, action: str, user: str, role: str, ip: str, target: str, result: str, detail: Any) -> None:
        if not self.cfg.get("audit", True) or action in AUDIT_SKIP:
            return
        sev = AUDIT_SEV.get(result, 4 if result not in ("ok", "") else 3)
        if action.startswith(("auth.denied", "auth.lockout", "auth.dormant")):
            sev = max(sev, 7)
        self._push(f"audit:{action}", action, sev, {"suser": user, "spriv": role, "src": ip, "cs1Label": "target", "cs1": target,
                                                    "outcome": result, "cs2Label": "detail", "cs2": (detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False, default=str))[:1500]})

    def anomaly(self, a: dict) -> None:
        if not self.cfg.get("anomalies", True) or SEV_RANK.get(a.get("severity", "info"), 0) < self.min_sev:
            return
        ev = a.get("event") or {}
        ai = a.get("ai") or {}
        self._push(f"anomaly:{a.get('category') or 'general'}", a.get("title", "anomaly"), CEF_SEV.get(a.get("severity", "info"), 3),
                   {"externalId": a.get("id"), "cat": a.get("category"), "shost": ev.get("host"), "dvc": ev.get("entity"),
                    "deviceProcessName": ev.get("source"), "cs3Label": "connector", "cs3": ev.get("connector"),
                    "cnt": a.get("count", 1), "msg": str(ev.get("message", ""))[:1000],
                    "cs4Label": "incident", "cs4": a.get("incident_id"), "cs5Label": "ai_summary", "cs5": str(ai.get("summary", ""))[:500],
                    "cs6Label": "reasons", "cs6": ", ".join(a.get("reasons") or [])[:300]})

    def incident(self, inc: dict, what: str = "created") -> None:
        if not self.cfg.get("incidents", True):
            return
        self._push(f"incident:{what}", f"[{inc.get('severity', '').upper()}] {inc.get('title', '')}", CEF_SEV.get(inc.get("severity", "warning"), 5),
                   {"externalId": inc.get("id"), "cat": inc.get("category"), "act": what, "outcome": inc.get("status"),
                    "suser": inc.get("assignee"), "cs1Label": "cluster", "cs1": inc.get("cluster"), "cnt": inc.get("anomaly_count"),
                    "cs2Label": "hosts", "cs2": ", ".join(inc.get("hosts") or [])[:300], "msg": str(inc.get("summary") or "")[:800]})

    def security(self, sig: str, name: str, sev: str, ext: dict) -> None:
        self._push(f"security:{sig}", name, CEF_SEV.get(sev, 5), ext)

    # ---------------------------------------------------------------- 발송 워커
    def _close(self) -> None:
        try:
            if self._writer:
                self._writer.close()
            if self._sock:
                self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        self._writer, self._sock = None, None
        self.stats["connected"] = False

    def _syslog(self, line: str) -> bytes:
        # RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG   (facility local4=20, severity notice=5 → 165)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"
        return f"<165>1 {ts} {self.hostname} vcf-aiops - - - {line}\n".encode("utf-8", "replace")

    async def _ensure(self) -> None:
        proto = str(self.cfg.get("protocol", "udp")).lower()
        host, port = str(self.cfg["host"]), int(self.cfg.get("port", 514))
        if proto == "udp":
            if self._sock is None:
                self._sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setblocking(False)
                self._sock.connect((host, port))
                self.stats["connected"] = True
            return
        if self._writer is None:
            ctx = None
            if proto == "tls":
                ctx = ssl.create_default_context()
                if self.cfg.get("ca_file"):
                    ctx.load_verify_locations(self.cfg["ca_file"])
                if not self.cfg.get("verify_tls", True):
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            _, self._writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=8)
            self.stats["connected"] = True

    async def _send(self, line: str) -> None:
        await self._ensure()
        data = self._syslog(line)
        if self._sock is not None:
            self._sock.send(data)
        else:
            self._writer.write(data)   # type: ignore[union-attr]
            await asyncio.wait_for(self._writer.drain(), timeout=8)   # type: ignore[union-attr]

    async def loop(self, beat=lambda: None) -> None:
        while True:
            beat()
            if not self.q or not self.enabled:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=30)
                except asyncio.TimeoutError:
                    pass
                continue
            line = self.q[0]
            try:
                await self._send(line)
                self.q.popleft()
                self.stats["sent"] += 1
                self.stats["last_sent"] = time.time()
            except Exception as e:  # noqa: BLE001
                self.stats["errors"] += 1
                self.stats["last_error"] = f"{type(e).__name__}: {str(e)[:120]}"
                self._close()
                if str(self.cfg.get("protocol", "udp")).lower() == "udp":
                    self.q.popleft()           # UDP 는 재시도 의미 없음
                await asyncio.sleep(5)

    async def test(self) -> dict:
        if not self.enabled:
            return {"ok": False, "detail": "SIEM 전달이 꺼져 있거나 호스트가 없습니다"}
        line = cef("Broadcom", "VCF AIops", self.version, "test", "SIEM 전달 테스트", 1, {"rt": int(time.time() * 1000), "dvchost": self.hostname, "msg": "VCF AIops → SIEM CEF 테스트"})
        try:
            await self._send(line)
            return {"ok": True, "detail": f"{self.cfg.get('protocol', 'udp')}://{self.cfg.get('host')}:{self.cfg.get('port', 514)} 전송", "sample": line}
        except Exception as e:  # noqa: BLE001
            self._close()
            return {"ok": False, "detail": f"{type(e).__name__}: {str(e)[:160]}", "sample": line}
