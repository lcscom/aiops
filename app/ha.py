"""이중화(HA) — 2노드 액티브/액티브 수집 + 단일 알림 리더.

구성
- 두 노드 모두 syslog·폴링·화면을 독립적으로 운영(각자 DB). 장비는 두 노드로 동시에 syslog 를 보낸다
  (ESXi Syslog.global.logHost 콤마 구분, vCenter 원격 syslog 최대 3대, NSX exporter 복수, Fluent Bit output 복수).
- 외부로 나가는 동작(웹훅·메일 발송, ITSM 자동 등록, 에스컬레이션, 정기 리포트 메일)은 '알림 리더'만 수행.
- primary 는 기본 리더. standby 는 primary 의 /api/ha/peer 가 failover_seconds 동안 실패(또는 not ready)하면 리더를 인계,
  primary 가 failback_seconds 동안 정상이면 반납한다.
- 노드 간 확인은 공유 비밀(HMAC-SHA256, 시각 포함 ±60초) 헤더로 인증한다(세션 불필요).
- standby 도 알림을 outbox 에 쌓아 두되 보내지 않는다. 인계 시 primary 의 마지막 정상 응답 이후 생성분만 발송,
  리더가 아닌 동안 15분 넘은 대기분은 정리한다.
- 네트워크 분리로 두 노드가 서로를 못 보면 둘 다 리더가 될 수 있다 → 알림이 '누락' 대신 '중복' 되는 쪽으로 설계.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import socket
import time
from typing import Any

import httpx


def sign(secret: str, ts: str) -> str:
    return hmac.new(secret.encode(), f"aiops-ha|{ts}".encode(), hashlib.sha256).hexdigest()


def verify(secret: str, ts: str, sig: str) -> bool:
    try:
        if abs(time.time() - float(ts)) > 60:
            return False
    except (TypeError, ValueError):
        return False
    return bool(secret) and hmac.compare_digest(sign(secret, ts), sig or "")


class HAManager:
    def __init__(self, cfg: dict, engine):
        self.cfg = cfg or {}
        self.e = engine
        self.enabled = bool(self.cfg.get("enabled"))
        self.role = self.cfg.get("role", "primary") if self.enabled else "single"
        self.node = self.cfg.get("node_name") or socket.gethostname()
        self.peer_url = str(self.cfg.get("peer_url", "")).rstrip("/")
        self.secret = str(self.cfg.get("shared_secret", ""))
        self.failover = float(self.cfg.get("failover_seconds", 30))
        self.failback = float(self.cfg.get("failback_seconds", 60))
        self.interval = float(self.cfg.get("check_interval", 5))
        self.leader = self.role in ("primary", "single")
        self.since = time.time()
        self.peer: dict[str, Any] = {"state": "unknown", "last_ok": None, "last_error": "", "info": {}}
        self._bad_since: float | None = None
        self._good_since: float | None = None
        self._http = httpx.AsyncClient(verify=bool(self.cfg.get("verify_tls", False)), timeout=httpx.Timeout(4, connect=3))

    def is_leader(self) -> bool:
        return self.leader

    def public(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "node": self.node, "role": self.role, "leader": self.leader,
                "since": self.since, "peer": {k: self.peer[k] for k in ("state", "last_ok", "last_error")}
                | {"node": self.peer["info"].get("node"), "leader": self.peer["info"].get("leader")}}

    def peer_payload(self) -> dict[str, Any]:
        """상대 노드가 조회하는 내 상태"""
        ready, reasons = self.e.health.ready() if self.e.health else (True, [])
        return {"node": self.node, "role": self.role, "leader": self.leader, "ready": ready, "reasons": reasons,
                "boot": self.e.stats["started"], "ts": time.time()}

    async def _probe(self) -> dict[str, Any]:
        ts = f"{time.time():.3f}"
        r = await self._http.get(f"{self.peer_url}/api/ha/peer", headers={"X-AIOps-HA-Ts": ts, "X-AIOps-HA-Sig": sign(self.secret, ts)})
        r.raise_for_status()
        return r.json()

    async def loop(self, beat=lambda: None) -> None:
        if not self.enabled:
            while True:                      # 단일 노드: 감독자 하트비트만
                beat()
                await asyncio.sleep(30)
        if not self.peer_url or not self.secret:
            print("[ha] peer_url / shared_secret 미설정 — 단일 노드로 동작", flush=True)
            self.enabled, self.role, self.leader = False, "single", True
            while True:
                beat()
                await asyncio.sleep(30)
        while True:
            beat()
            now = time.time()
            ok = False
            try:
                info = await self._probe()
                self.peer["info"] = info
                ok = bool(info.get("ready"))
                self.peer.update(state="ok" if ok else "not_ready", last_ok=now if ok else self.peer["last_ok"],
                                 last_error="" if ok else "상대 노드 not ready: " + ", ".join(info.get("reasons") or [])[:200])
            except Exception as e:  # noqa: BLE001
                self.peer.update(state="down", last_error=f"{type(e).__name__}: {e}"[:200])
            if ok:
                self._bad_since = None
                self._good_since = self._good_since or now
            else:
                self._good_since = None
                self._bad_since = self._bad_since or now
            await self._decide(now)
            await asyncio.sleep(self.interval)

    async def _decide(self, now: float) -> None:
        if self.role != "standby":
            return                           # primary 는 항상 리더(상대 장애는 상태로만 노출)
        if not self.leader and self._bad_since and now - self._bad_since >= self.failover:
            self.leader, self.since = True, now
            # primary 가 마지막으로 정상 응답한 시각 이전 건은 primary 가 보냈다고 보고 정리, 이후 건은 이어서 발송
            skipped = await self.e.alerter.takeover((self.peer["last_ok"] or now) - 5)
            msg = f"primary({self.peer_url}) 응답 없음 {int(now - self._bad_since)}초 — 이 노드({self.node})가 알림 리더를 인계"
            print(f"[ha] {msg}", flush=True)
            await self.e.audit.log("ha.takeover", target=self.node, detail={"peer": self.peer_url, "skipped_outbox": skipped,
                                                                           "error": self.peer["last_error"]})
            await self.e.alerter.notify_text("[HA] 대기 노드가 알림 리더를 인계", msg, "error", "ha")
        elif self.leader and self._good_since and now - self._good_since >= self.failback:
            self.leader, self.since = False, now
            msg = f"primary({self.peer_url}) {int(now - self._good_since)}초 정상 — 알림 리더 반납"
            print(f"[ha] {msg}", flush=True)
            await self.e.audit.log("ha.release", target=self.node, detail={"peer": self.peer_url})
