"""하드웨어 준비도 전용 Redfish 클라이언트 — '읽기 전용'을 전송 계층에서 강제

허용: GET · HEAD · (세션 만들기) POST /redfish/v1/SessionService/Sessions · (그 세션 닫기) DELETE <자기 세션 URI>
그 밖의 메서드·경로(PATCH/PUT, Actions POST, 전원·리셋·펌웨어·계정·BIOS 변경)는 보내기 전에 ReadOnlyViolation 으로 막는다.
경로당 1회 조회(같은 스캔 안 캐시), 요청 상한(max_requests), 동시 요청 상한, 응답 크기 상한을 둔다.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

SESSIONS = "/redfish/v1/SessionService/Sessions"


class ReadOnlyViolation(RuntimeError):
    pass


class RfClient:
    def __init__(self, host: str, username: str, password: str, *, verify: bool = False, timeout: float = 20, max_requests: int = 1500,
                 concurrency: int = 6, transport: httpx.AsyncBaseTransport | None = None, basic: bool = False, port: int | None = None):
        h = host.strip()
        if h.startswith(("http://", "https://")):
            self.base = h.rstrip("/")
        else:
            self.base = f"https://{h}" + (f":{port}" if port else "")
        self.username, self.password = username, password
        self.verify, self.timeout, self.max_requests = verify, timeout, max_requests
        self.sem = asyncio.Semaphore(concurrency)
        self.transport = transport
        self.basic = basic
        self.session_uri = ""
        self.cache: dict[str, Any] = {}
        self.errors: dict[str, str] = {}
        self.count = 0
        self.started = time.time()
        self._c: httpx.AsyncClient | None = None
        self.auth_mode = ""

    # ------------------------------------------------------------- 전송 계층 정책
    def _check(self, method: str, path: str) -> None:
        m = method.upper()
        if m in ("GET", "HEAD"):
            return
        if m == "POST" and path.rstrip("/") == SESSIONS:
            return
        if m == "DELETE" and self.session_uri and path == self.session_uri:
            return
        raise ReadOnlyViolation(f"읽기 전용 정책 위반: {m} {path}")

    async def _req(self, method: str, path: str, **kw) -> httpx.Response:
        self._check(method, path)
        if self.count >= self.max_requests:
            raise RuntimeError(f"요청 상한({self.max_requests}) 도달")
        self.count += 1
        async with self.sem:
            return await self._c.request(method, path, **kw)

    async def __aenter__(self):
        self._c = httpx.AsyncClient(base_url=self.base, verify=self.verify, transport=self.transport, follow_redirects=False, trust_env=False,   # BMC 는 관리망 직접 연결(프록시 환경변수 무시)
                                    timeout=httpx.Timeout(self.timeout, connect=8), headers={"Accept": "application/json", "OData-Version": "4.0"})
        await self.login()
        return self

    async def __aexit__(self, *a):
        try:
            if self.session_uri:
                await self._req("DELETE", self.session_uri)
        except Exception:  # noqa: BLE001
            pass
        finally:
            await self._c.aclose()

    async def login(self) -> None:
        r = await self._req("GET", "/redfish/v1/")
        if r.status_code >= 400 and r.status_code not in (401, 403):
            raise RuntimeError(f"/redfish/v1/ HTTP {r.status_code}")
        self.cache["/redfish/v1"] = _json(r)
        if not self.basic:
            try:
                s = await self._req("POST", SESSIONS, json={"UserName": self.username, "Password": self.password})
                if s.status_code < 300 and s.headers.get("X-Auth-Token"):
                    self._c.headers["X-Auth-Token"] = s.headers["X-Auth-Token"]
                    loc = s.headers.get("Location", "")
                    self.session_uri = httpx.URL(loc).path if loc else ""
                    self.auth_mode = "session"
                    return
                if s.status_code in (401, 403):
                    raise PermissionError("BMC 인증 실패(아이디·비밀번호·잠금 상태 확인)")
            except (httpx.HTTPError, ValueError):
                pass
        self._c.auth = (self.username, self.password)
        self.auth_mode = "basic"
        r = await self._req("GET", "/redfish/v1/Systems")
        if r.status_code in (401, 403):
            raise PermissionError("BMC 인증 실패(아이디·비밀번호·잠금 상태 확인)")

    # ------------------------------------------------------------- 조회
    async def get(self, path: str | None, default: Any = None) -> Any:
        """경로 JSON(dict). 실패·404·비JSON → default({}). 같은 경로는 한 번만."""
        if not path:
            return {} if default is None else default
        p = str(path).split("#")[0].rstrip("/") or "/redfish/v1"
        if p.startswith("http"):
            p = httpx.URL(p).path.rstrip("/")
        if p in self.cache:
            return self.cache[p]
        try:
            r = await self._req("GET", p)
            d = _json(r) if r.status_code < 300 else {}
            if r.status_code >= 300:
                self.errors[p] = f"HTTP {r.status_code}"
        except ReadOnlyViolation:
            raise
        except Exception as e:  # noqa: BLE001
            self.errors[p] = f"{type(e).__name__}"
            d = {}
        self.cache[p] = d
        return d if d else ({} if default is None else default)

    async def members(self, path: str | None, limit: int = 256) -> list[dict]:
        """컬렉션 → 각 멤버 JSON(Members 안에 이미 펼쳐져 있으면 그대로, 아니면 하나씩 GET)"""
        col = await self.get(path)
        out = []
        refs = (col.get("Members") or [])[:limit] if isinstance(col, dict) else []
        need = [m.get("@odata.id") for m in refs if isinstance(m, dict) and len(m) <= 2 and m.get("@odata.id")]
        got = await asyncio.gather(*(self.get(u) for u in need)) if need else []
        gi = iter(got)
        for m in refs:
            if not isinstance(m, dict):
                continue
            if len(m) <= 2 and m.get("@odata.id"):
                d = next(gi)
                if d:
                    out.append(d)
            else:
                out.append(m)
        return out

    @staticmethod
    def link(d: dict, key: str) -> str | None:
        v = (d or {}).get(key)
        if isinstance(v, dict):
            return v.get("@odata.id")
        return None


def _json(r: httpx.Response) -> dict:
    if len(r.content) > 8 * 1024 * 1024:
        return {}
    try:
        d = json.loads(r.content or b"{}")
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}
