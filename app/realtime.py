"""실시간 푸시 허브 — WebSocket 클라이언트별 송신 큐로 느린 화면이 전체 파이프라인을 막지 못하게 한다.

메시지 분류
- 상태 메시지(anomaly·incident·alert·action·noc_brief·snapshot): 유실 불가. 전역 seq 를 붙인다.
  클라이언트는 seq 가 건너뛰면 'resync' 를 보내 스냅샷을 다시 받는다.
- 흐름 메시지(logs·status): 유실 허용. 송신 큐가 절반 이상 차면 버린다(최신 status 가 곧 다시 온다).
송신 큐가 가득 차면(상태 메시지까지 밀림) 해당 클라이언트만 1013 으로 끊는다 → 브라우저가 재접속해 스냅샷부터 다시 받는다.
송신 1건이 send_timeout 을 넘겨도(죽은 TCP) 끊는다. 서버 종료 시 1012(service restart) 로 닫아 즉시 재접속을 유도한다.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections import deque
from typing import Any, Callable

from fastapi import WebSocket

from .runtime import bg

DROPPABLE = {"logs", "status", "avi_vips"}


class Client:
    __slots__ = ("ws", "user", "q", "wake", "task", "sent", "dropped", "connected", "closed", "max", "last_rx", "peer", "tail")

    def __init__(self, ws: WebSocket, user: dict, maxq: int):
        self.ws, self.user, self.max = ws, user, maxq
        self.q: deque[str] = deque()
        self.wake = asyncio.Event()
        self.task: asyncio.Task | None = None
        self.sent = self.dropped = 0
        self.connected = self.last_rx = time.time()
        self.closed = ""
        self.peer = f"{ws.client.host}:{ws.client.port}" if ws.client else "-"
        self.tail: dict | None = None               # 실시간 로그 보기 필터 {hosts:set, sources:set, q:str, min:int}


class Hub:
    def __init__(self, cfg: dict):
        self.maxq = int(cfg.get("ws_queue", 2000))
        self.send_timeout = float(cfg.get("ws_send_timeout", 15))
        self.idle_timeout = float(cfg.get("ws_idle_timeout", 0))      # 0 = 앱 메시지 무수신으로 끊지 않음(프로토콜 ping 으로 정리)
        self.clients: dict[WebSocket, Client] = {}
        self.seq = 0
        self.stats = {"broadcasts": 0, "dropped_flow": 0, "kicked_slow": 0, "kicked_dead": 0, "connects": 0,
                      "bytes": 0}

    def __len__(self) -> int:
        return len(self.clients)

    def __bool__(self) -> bool:            # 기존 코드의 `if not self.clients` 호환
        return bool(self.clients)

    # ---------------------------------------------------------------- 등록·해제
    def add(self, ws: WebSocket, user: dict, first: Callable[[int], str]) -> Client:
        """first(seq) → 스냅샷 JSON. await 없이 생성·등록해 스냅샷과 이후 브로드캐스트 사이 공백이 없다."""
        c = Client(ws, user, self.maxq)
        c.q.append(first(self.seq))
        self.clients[ws] = c
        self.stats["connects"] += 1
        c.task = asyncio.create_task(self._sender(c), name=f"ws:{c.peer}")
        c.wake.set()
        return c

    def discard(self, ws: WebSocket) -> None:
        c = self.clients.pop(ws, None)
        if c and c.task and not c.task.done() and c.task is not asyncio.current_task():
            c.task.cancel()

    def resync(self, ws: WebSocket, first: Callable[[int], str]) -> None:
        c = self.clients.get(ws)
        if c:
            c.q.clear()
            c.q.append(first(self.seq))
            c.wake.set()

    # ---------------------------------------------------------------- 실시간 로그 보기(Live Tail)
    # host_match: FQDN·짧은 이름·IP(syslog 송신 주소)·BMC 주소·VM 이름(entity)·접두어(esx0 → esx01·esx02) 모두 일치
    def set_tail(self, ws: WebSocket, spec: dict | None) -> None:
        """클라이언트별 서버측 필터 — 전체 로그 표본(250ms당 300줄)과 무관하게 지정 호스트의 로그를 빠짐없이 전달"""
        c = self.clients.get(ws)
        if not c:
            return
        if not spec:
            c.tail = None
            return
        rank = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}
        hosts = {str(h).strip().lower() for h in (spec.get("hosts") or []) if str(h).strip()}
        c.tail = {"hosts": hosts, "short": {h.split(".")[0] for h in hosts if not _IP.match(h)},
                  "sources": {str(x) for x in (spec.get("sources") or []) if x},
                  "q": str(spec.get("q") or "").lower()[:200], "min": rank.get(str(spec.get("min") or "debug"), 0)}

    def publish_tail(self, batch: list[dict]) -> None:
        if not batch:
            return
        rank = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}
        for ws, c in list(self.clients.items()):
            t = c.tail
            if not t:
                continue
            out = []
            for e in batch:
                if t["sources"] and e.get("source") not in t["sources"]:
                    continue
                if rank.get(e.get("severity"), 1) < t["min"]:
                    continue
                if t["hosts"] and not host_match(t, e):
                    continue
                if t["q"] and t["q"] not in str(e.get("message", "")).lower():
                    continue
                out.append(e)
            if not out:
                continue
            if len(c.q) >= c.max - 2:                   # 실시간 로그 보기는 대시보드 표본보다 우선(큐 거의 가득 찰 때만 생략)
                c.dropped += 1
                self.stats["dropped_flow"] += 1
                continue
            c.q.append(json.dumps({"type": "tail", "data": out[-1000:], "truncated": max(0, len(out) - 1000)},
                                  ensure_ascii=False, default=str))
            c.wake.set()

    # ---------------------------------------------------------------- 송신
    def publish(self, msg: dict[str, Any]) -> None:
        """동기 · 즉시 반환. 인코딩은 1회, 클라이언트 큐에 넣기만 한다."""
        if not self.clients:
            if msg.get("type") not in DROPPABLE:
                self.seq += 1
            return
        flow = msg.get("type") in DROPPABLE
        if not flow:
            self.seq += 1
            msg = {**msg, "seq": self.seq}
        txt = json.dumps(msg, ensure_ascii=False, default=str)
        self.stats["broadcasts"] += 1
        for ws, c in list(self.clients.items()):
            n = len(c.q)
            if flow and n >= c.max // 2:
                c.dropped += 1
                self.stats["dropped_flow"] += 1
                continue
            if n >= c.max:
                self._kick(c, 1013, "송신 지연(느린 클라이언트) — 재접속 필요")
                self.stats["kicked_slow"] += 1
                continue
            c.q.append(txt)
            c.wake.set()

    async def broadcast(self, msg: dict[str, Any]) -> None:   # 기존 호출부 호환(await 가능)
        self.publish(msg)

    async def _sender(self, c: Client) -> None:
        try:
            while True:
                await c.wake.wait()
                c.wake.clear()
                while c.q:
                    txt = c.q.popleft()
                    await asyncio.wait_for(c.ws.send_text(txt), timeout=self.send_timeout)
                    c.sent += 1
                    self.stats["bytes"] += len(txt)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.stats["kicked_dead"] += 1
            self._kick(c, 1011, "송신 시간 초과")
        except Exception:  # noqa: BLE001  연결 끊김
            self.clients.pop(c.ws, None)

    def _kick(self, c: Client, code: int, reason: str) -> None:
        c.closed = reason
        self.clients.pop(c.ws, None)

        async def close():
            try:
                await asyncio.wait_for(c.ws.close(code=code, reason=reason[:100]), timeout=3)
            except Exception:  # noqa: BLE001
                pass
        if c.task and not c.task.done() and c.task is not asyncio.current_task():
            c.task.cancel()
        bg(close())

    async def close_all(self, code: int = 1012, reason: str = "service restart") -> None:
        cs = list(self.clients.values())
        self.clients.clear()
        for c in cs:
            if c.task:
                c.task.cancel()
        await asyncio.gather(*[asyncio.wait_for(c.ws.close(code=code, reason=reason), timeout=2) for c in cs],
                             return_exceptions=True)

    def status(self) -> dict[str, Any]:
        now = time.time()
        return {**self.stats, "clients": len(self.clients), "seq": self.seq,
                "max_queue": max((len(c.q) for c in self.clients.values()), default=0),
                "detail": [{"peer": c.peer, "user": c.user.get("user", ""), "kiosk": bool(c.user.get("kiosk")),
                            "queue": len(c.q), "sent": c.sent, "dropped": c.dropped,
                            "age": round(now - c.connected)} for c in list(self.clients.values())[:50]]}


_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|:")


def host_match(t: dict, e: dict) -> bool:
    h = str(e.get("host") or "").lower()
    if h in t["hosts"] or h.split(".")[0] in t["short"]:
        return True
    a = e.get("attrs") or {}
    for v in (a.get("peer"), a.get("bmc"), a.get("esxi"), a.get("pod"), e.get("entity")):
        if v and str(v).lower() in t["hosts"]:
            return True
    return any(len(p) >= 3 and "." not in p and h.startswith(p) for p in t["short"])
