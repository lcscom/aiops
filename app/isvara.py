"""Isvara(isvara.io) iO — MCP(Streamable HTTP) 클라이언트.

isvara.io/mcp 공개 정보: 서버 https://isvara.io/api/mcp
  도구  ask_isvara(question, chapter?) — 가이드 근거로 답하고 사용한 절 링크를 붙임
        ops_score(metric, value) · health_check(vms, …) · fleet_view(…)
  자원  isvara://index · isvara://thresholds · isvara://book/{id}
이 포털은 **ask_isvara 와 자원 읽기만** 사용합니다. 카운터·인벤토리(health_check·fleet_view)는 외부로 보내지 않습니다 —
점수는 app/sli.py 가 로컬에서 계산. 전송되는 것은 운영자가 입력한 질문 문장뿐이며 기본값은 꺼짐(망분리 환경 고려).
"""
from __future__ import annotations

import asyncio
import itertools
import json
import re
import time
from collections import OrderedDict
from typing import Any

import httpx

PROTOCOL = "2025-06-18"
LINK_RE = re.compile(r"https://isvara\.io/[^\s)\]>\"']+")
PERF_HINT = re.compile(r"(ready|co-?stop|contention|latency|ballon|balloon|swap|vsan|iops|dropped|capacity|rightsiz|"
                       r"overcommit|성능|지연|경합|레디|용량|과할당|드롭|패킷 ?손실|vCPU|메모리 압박|느려|느림|SLI|SLA)", re.I)


class IsvaraError(RuntimeError):
    pass


class IsvaraClient:
    def __init__(self, cfg: dict[str, Any]):
        c = cfg or {}
        self.enabled = bool(c.get("enabled"))
        self.url = c.get("url") or "https://isvara.io/api/mcp"
        self.timeout = float(c.get("timeout", 20))
        self.chat_grounding = bool(c.get("chat_grounding", True))
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=8), verify=c.get("verify_tls", True),
                                       proxy=c.get("proxy") or None, follow_redirects=False,
                                       headers={"User-Agent": "vcf-aiops-portal"})
        self._sid: str | None = None
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self.server: dict[str, Any] = {}
        self.last_error = ""
        self.last_ok = 0.0

    # ------------------------------------------------------------------ 전송
    async def _post(self, payload: dict[str, Any], expect_id: int | None) -> dict[str, Any] | None:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self._sid:
            h["Mcp-Session-Id"] = self._sid
        if self.server:
            h["MCP-Protocol-Version"] = self.server.get("protocolVersion", PROTOCOL)
        async with self._http.stream("POST", self.url, json=payload, headers=h) as r:
            if r.status_code == 404 and self._sid:
                self._sid = None                           # 세션 만료 → 호출자가 재초기화
                raise IsvaraError("session_expired")
            if r.status_code >= 400:
                body = (await r.aread())[:300].decode("utf-8", "replace")
                raise IsvaraError(f"HTTP {r.status_code}: {body}")
            sid = r.headers.get("mcp-session-id")
            if sid:
                self._sid = sid
            if expect_id is None:
                return None
            ctype = r.headers.get("content-type", "")
            if "text/event-stream" in ctype:
                data: list[str] = []
                async for line in r.aiter_lines():
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip())
                    elif line == "" and data:
                        msg = _json("\n".join(data))
                        data = []
                        if isinstance(msg, dict) and msg.get("id") == expect_id:
                            return msg
                if data:
                    msg = _json("\n".join(data))
                    if isinstance(msg, dict) and msg.get("id") == expect_id:
                        return msg
                raise IsvaraError("SSE 응답에 결과 없음")
            msg = _json((await r.aread()).decode("utf-8", "replace"))
            if isinstance(msg, list):
                msg = next((m for m in msg if isinstance(m, dict) and m.get("id") == expect_id), None)
            if not isinstance(msg, dict):
                raise IsvaraError("JSON-RPC 응답 형식 오류")
            return msg

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        for attempt in (1, 2):
            if not self.server:
                await self._initialize()
            rid = next(self._ids)
            try:
                msg = await self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}, rid)
            except IsvaraError as e:
                if str(e) == "session_expired" and attempt == 1:
                    self.server = {}
                    continue
                raise
            if "error" in msg:
                raise IsvaraError(f"{msg['error'].get('code')}: {msg['error'].get('message')}")
            return msg.get("result")
        raise IsvaraError("재시도 실패")

    async def _initialize(self) -> None:
        rid = next(self._ids)
        msg = await self._post({"jsonrpc": "2.0", "id": rid, "method": "initialize",
                                "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                           "clientInfo": {"name": "vcf-aiops", "version": "1"}}}, rid)
        if "error" in msg:
            raise IsvaraError(f"initialize: {msg['error']}")
        self.server = msg.get("result") or {}
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, None)

    # ------------------------------------------------------------------ 공개 API
    async def ask(self, question: str, chapter: str | None = None) -> dict[str, Any]:
        """→ {answer, links[{url,title}], cached}. 실패 시 IsvaraError."""
        if not self.enabled:
            raise IsvaraError("disabled")
        q = " ".join(question.split())[:1500]
        key = f"{chapter or ''}|{q.lower()}"
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < 86400:
            self._cache.move_to_end(key)
            return {**hit[1], "cached": True}
        args: dict[str, Any] = {"question": q}
        if chapter:
            args["chapter"] = chapter
        async with self._lock:
            try:
                res = await self._rpc("tools/call", {"name": "ask_isvara", "arguments": args})
            except (httpx.HTTPError, IsvaraError) as e:
                self.last_error = f"{type(e).__name__}: {e}"[:300]
                raise IsvaraError(self.last_error) from e
        texts = [c.get("text", "") for c in (res or {}).get("content", []) if isinstance(c, dict) and c.get("type") == "text"]
        sc = (res or {}).get("structuredContent")
        if not texts and isinstance(sc, dict):
            texts = [str(sc.get("answer") or sc.get("text") or json.dumps(sc, ensure_ascii=False))]
        answer = "\n".join(t for t in texts if t).strip()
        if (res or {}).get("isError"):
            raise IsvaraError(answer[:300] or "tool error")
        links = list(dict.fromkeys(LINK_RE.findall(answer + " " + json.dumps(sc or {}, ensure_ascii=False))))
        out = {"answer": answer, "links": [{"url": u.rstrip(".,;"), "title": _title(u)} for u in links][:8], "cached": False}
        self._cache[key] = (time.time(), out)
        while len(self._cache) > 200:
            self._cache.popitem(last=False)
        self.last_ok, self.last_error = time.time(), ""
        return out

    async def read(self, uri: str) -> str:
        if not self.enabled:
            raise IsvaraError("disabled")
        async with self._lock:
            res = await self._rpc("resources/read", {"uri": uri})
        return "\n".join(c.get("text", "") for c in (res or {}).get("contents", []) if isinstance(c, dict))

    def status(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "url": self.url, "server": (self.server.get("serverInfo") or {}),
                "last_ok": self.last_ok or None, "last_error": self.last_error, "chat_grounding": self.chat_grounding}

    @staticmethod
    def relevant(question: str) -> bool:
        return bool(PERF_HINT.search(question or ""))

    async def close(self) -> None:
        await self._http.aclose()


def _json(s: str) -> Any:
    try:
        return json.loads(s)
    except ValueError:
        return None


def _title(url: str) -> str:
    path = url.split("isvara.io/", 1)[-1].split("#")
    t = path[0].strip("/").replace("read/", "").replace("-", " ")
    return (t + (" › " + path[1].replace("-", " ") if len(path) > 1 else "")) or "isvara.io"
