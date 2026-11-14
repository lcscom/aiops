"""커넥터 공통 베이스: 인증 세션 유지, 주기 폴링, 지수 백오프, 상태/헬스체크, 중복 제거."""
from __future__ import annotations

import asyncio
import concurrent.futures
import random
import time
import traceback
from collections import OrderedDict
from typing import Any, Awaitable, Callable

import httpx

from ..models import LogEvent

LEGACY_TLS_MARKERS = ("UNSUPPORTED_PROTOCOL", "WRONG_VERSION_NUMBER", "TLSV1_ALERT_PROTOCOL_VERSION", "SSLV3_ALERT_HANDSHAKE_FAILURE",
                      "NO_CIPHERS_AVAILABLE", "NO_SHARED_CIPHER", "DH_KEY_TOO_SMALL", "UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
                      "NO_PROTOCOLS_AVAILABLE", "VERSION_TOO_LOW", "CA_MD_TOO_WEAK", "EE_KEY_TOO_SMALL")


def is_legacy_tls_error(e: BaseException | None) -> bool:
    """httpx.ConnectError 등 예외 사슬 안에 'TLS 버전·암호군이 너무 오래됨' 류 OpenSSL 오류가 있는지"""
    seen = 0
    while e is not None and seen < 6:
        t = f"{e!s} {getattr(e, 'reason', '')}".upper()
        if any(m in t for m in LEGACY_TLS_MARKERS):
            return True
        e = e.__cause__ or e.__context__
        seen += 1
    return False


class SeenSet(OrderedDict):
    """폴링 API가 같은 알람을 반복 반환하므로 (id,상태) 키로 신규/변경분만 내보낸다."""

    def __init__(self, cap: int = 20000):
        super().__init__()
        self.cap = cap

    def is_new(self, key: str) -> bool:
        if key in self:
            self.move_to_end(key)
            return False
        self[key] = time.time()
        if len(self) > self.cap:
            self.popitem(last=False)
        return True


class Connector:
    type = "base"
    source = "base"
    default_interval = 30

    def __init__(self, cfg: dict, emit: Callable[[LogEvent], Awaitable[None]]):
        self.cfg = cfg
        self.name = cfg.get("name") or f"{self.type}"
        self.emit = emit
        self.enabled = cfg.get("enabled", True)
        self.interval = float(cfg.get("interval", self.default_interval))
        self.host = cfg.get("host", "")
        self.base_url = cfg.get("base_url") or (f"https://{self.host}" if self.host else "")
        self.verify = cfg.get("verify_tls", False)
        self.legacy_tls = bool(cfg.get("legacy_tls", False))   # 2.3.1 TLS 1.0/1.1·약한 암호군만 지원하는 장비 — 자동 전환되거나 설정으로 고정
        self.seen = SeenSet()
        self.first_poll = True
        self.since: float = time.time() - float(cfg.get("backfill_seconds", 600))
        self._http: httpx.AsyncClient | None = None
        self._state: dict[str, Any] = {
            "name": self.name, "type": self.type, "source": self.source, "target": self.base_url or self.host,
            "state": "disabled" if not self.enabled else "init", "latency_ms": None, "last_ok": None,
            "last_error": "", "events_total": 0, "polls": 0, "auth": "none", "checks": {},
            "timeouts": 0, "consecutive_failures": 0, "next_poll": None,
        }
        # 폴링 1회 전체(로그인 포함) 상한 — 응답 없는 API가 커넥터를 영구 정지시키지 않도록
        self.poll_timeout = float(cfg.get("poll_timeout", max(60.0, 3 * self.interval)))
        # 2.30.0 무거운 수집은 폴링과 분리된 작업으로(_bg_start) — 폴링 시간 초과가 이벤트를 잃거나 결과를 버리지 않게
        self._bg: dict[str, asyncio.Task] = {}
        self._bg_stat: dict[str, dict[str, Any]] = {}
        self._pool_obj: concurrent.futures.ThreadPoolExecutor | None = None

    # ------------------------------------------------------------ 하위 클래스 구현
    async def login(self) -> None:
        """세션/토큰 획득. 실패 시 예외."""

    async def poll(self) -> list[LogEvent]:
        return []

    async def checks(self) -> dict[str, Any]:
        """엔드포인트별 접근성 점검(헬스체크 화면용). 기본: login 성공 여부."""
        await self.login()
        return {"auth": "ok"}

    # ------------------------------------------------------------ 공통
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            verify = self.verify
            if self.legacy_tls:
                from .cimc import legacy_ssl
                verify = legacy_ssl(bool(self.verify))
            self._http = httpx.AsyncClient(base_url=self.base_url, verify=verify,
                                           timeout=httpx.Timeout(float(self.cfg.get("timeout", 30)), connect=8),
                                           headers={"Accept": "application/json"})
        return self._http

    def switch_legacy_tls(self, e: BaseException) -> bool:
        """표준 TLS 협상이 프로토콜·암호군 문제로 실패했으면 구형 호환(TLS 1.0+·SECLEVEL=0)으로 한 번 전환. 전환했으면 True."""
        if self.legacy_tls or not is_legacy_tls_error(e):
            return False
        self.legacy_tls = True
        old, self._http = self._http, None
        if old is not None:
            try:
                asyncio.get_running_loop().create_task(old.aclose())
            except RuntimeError:
                pass
        self._state.setdefault("checks", {})["TLS"] = "warn: 장비가 TLS 1.2 미만·구형 암호군만 지원 — 구형 호환으로 자동 전환(장비 TLS 설정 개선 권장)"
        return True

    def ev(self, message: str, **kw) -> LogEvent:
        kw.setdefault("host", self.host)
        kw.setdefault("source", self.source)        # 같은 커넥터가 여러 계열을 낼 때 덮어쓰기(NSX → nsx-edge 등)
        return LogEvent(connector=self.name, message=message, **kw)

    def state(self) -> dict[str, Any]:
        return self._state

    def entities(self) -> list[dict[str, Any]]:
        """통합 관제 상태맵용 개체 목록 [{name, kind, state: ok|warn|down|maint|unknown, detail}] — 커넥터별 재정의"""
        return []

    # ------------------------------------------------------------ 전용 스레드 풀·백그라운드 수집(2.30.0)
    @property
    def _pool(self) -> concurrent.futures.ThreadPoolExecutor:
        """커넥터 전용 스레드 풀 — 응답 없는 장비가 기본 실행기(저장소 읽기·쓰기 공용)를 고갈시키지 않게 분리"""
        if self._pool_obj is None:
            self._pool_obj = concurrent.futures.ThreadPoolExecutor(max_workers=max(2, int(self.cfg.get("worker_threads", 8))),
                                                                   thread_name_prefix=f"conn-{self.name}"[:40])
        return self._pool_obj

    async def _t(self, fn, *args):
        """블로킹 호출을 전용 풀에서 실행(asyncio.to_thread 대신)"""
        return await asyncio.get_running_loop().run_in_executor(self._pool, fn, *args)

    async def _deliver(self, events: list[LogEvent] | None) -> int:
        """폴링 밖(백그라운드 수집)에서 만든 이벤트를 폴링 결과와 같은 경로(emit)로 엔진에 전달"""
        n = 0
        for e in events or []:
            await self.emit(e)
            n += 1
        self._state["events_total"] += n
        return n

    def _bg_busy(self, key: str | None = None) -> bool:
        if key is not None:
            t = self._bg.get(key)
            return bool(t and not t.done())
        return any(not t.done() for t in self._bg.values())

    def _bg_start(self, key: str, factory: Callable[[], Awaitable[Any]], timeout: float) -> bool:
        """무거운 수집 1종을 별도 작업으로 시작. 같은 종류가 아직 돌고 있으면 건너뜀(겹침 방지). factory 가 돌려준 이벤트는 엔진으로 전달.
        성공·실패 시각은 _bg_stat 에 남는다 — 다음 실행 시점(성공 후 주기·실패 후 짧은 재시도)은 호출 쪽이 판단."""
        if self._bg_busy(key):
            return False
        st = self._bg_stat.setdefault(key, {"runs": 0, "fails": 0, "last_ok": 0.0, "last_fail": 0.0, "last_error": "", "seconds": 0.0, "started": 0.0})
        st["started"] = time.time()

        async def run():
            t0 = time.time()
            try:
                evs = await asyncio.wait_for(factory(), timeout=timeout)
                if isinstance(evs, list):
                    await self._deliver(evs)
                st.update(last_ok=time.time(), last_error="")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                st["fails"] += 1
                st.update(last_fail=time.time(), last_error=(f"시간 초과({int(timeout)}초)" if isinstance(e, asyncio.TimeoutError) and not str(e)
                                                             else f"{type(e).__name__}: {e}")[:300])
                if self.cfg.get("debug"):
                    traceback.print_exc()
            finally:
                st["runs"] += 1
                st["seconds"] = round(time.time() - t0, 1)
        self._bg[key] = asyncio.get_running_loop().create_task(run(), name=f"bg:{self.name}:{key}")
        return True

    def _bg_cancel(self) -> None:
        """커넥터 정지·교체 시 — 백그라운드 수집 취소, 전용 풀 반납(대기 중이던 호출은 버림)"""
        for t in self._bg.values():
            if not t.done():
                t.cancel()
        self._bg.clear()
        pool, self._pool_obj = self._pool_obj, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)

    def __del__(self):                                     # 실행(run) 없이 연결 테스트만 하고 버려진 커넥터의 풀 스레드 반납
        pool = getattr(self, "_pool_obj", None)
        if pool is not None:
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:  # noqa: BLE001
                pass

    def _mark(self, ok: bool, t0: float, err: str = "") -> None:
        s = self._state
        s["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        if ok:
            s.update(state="ok", last_ok=time.time(), last_error="", consecutive_failures=0)
        else:
            s["consecutive_failures"] = s.get("consecutive_failures", 0) + 1
            s.update(state="down" if s["last_ok"] is None or time.time() - s["last_ok"] > 3 * self.interval
                     else "degraded", last_error=err[:400])

    async def run(self) -> None:
        if not self.enabled:
            return
        try:
            await self._run_loop()
        finally:                                           # 취소(정지·재구성·종료) 포함 — 딸린 수집 작업도 함께 정리
            self._bg_cancel()

    async def _run_loop(self) -> None:
        backoff = self.interval
        authed = False
        await asyncio.sleep(random.uniform(0, min(5.0, self.interval / 2)))   # 재기동 직후 동시 폴링 분산
        while True:
            t0 = time.perf_counter()
            try:
                async def once():
                    nonlocal authed
                    if not authed:
                        await self.login()
                        authed = True
                        self._state["auth"] = "ok"
                    return await self.poll()
                events = await asyncio.wait_for(once(), timeout=self.poll_timeout)
                self._state["polls"] += 1
                for e in events:
                    await self.emit(e)
                self._state["events_total"] += len(events)
                self.first_poll = False
                self._mark(True, t0)
                backoff = self.interval
            except asyncio.TimeoutError:
                authed = False
                self._state["timeouts"] = self._state.get("timeouts", 0) + 1
                self._mark(False, t0, f"폴링 시간 초과({int(self.poll_timeout)}초) — 대상 API 응답 없음")
                backoff = min(backoff * 2, 300)
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403, 419, 440):
                    authed = False   # 세션 만료 → 다음 루프 재인증
                    self._state["auth"] = f"재인증 필요({e.response.status_code})"
                self._mark(False, t0, f"HTTP {e.response.status_code} {e.request.url.path}: {e.response.text[:200]}")
                backoff = min(backoff * 2, 300)
            except Exception as e:  # noqa: BLE001
                authed = False
                if self.switch_legacy_tls(e):              # 구형 TLS 장비 → 곧바로 다시 시도
                    self._state["next_poll"] = time.time() + 1
                    await asyncio.sleep(1)
                    continue
                self._mark(False, t0, f"{type(e).__name__}: {e}")
                if self.cfg.get("debug"):
                    traceback.print_exc()
                backoff = min(backoff * 2, 300)
            wait = backoff if backoff == self.interval else backoff * random.uniform(0.8, 1.2)   # 실패 재시도는 지터
            self._state["next_poll"] = time.time() + wait
            await asyncio.sleep(wait)

    async def test(self) -> dict[str, Any]:
        """대시보드 '연결 테스트' 버튼 — 인증 + 개별 API 엔드포인트 점검."""
        t0 = time.perf_counter()
        try:
            try:
                res = await self.checks()
            except Exception as e:  # noqa: BLE001
                if not self.switch_legacy_tls(e):
                    raise
                res = await self.checks()                 # 구형 호환으로 한 번 더
            ok = all(v in ("ok", True) or (isinstance(v, str) and v.startswith(("ok", "warn"))) for v in res.values())
            self._state["checks"] = res
            self._mark(ok, t0, "" if ok else "일부 엔드포인트 실패")
            return {"ok": ok, "checks": res, "latency_ms": self._state["latency_ms"]}
        except Exception as e:  # noqa: BLE001
            self._mark(False, t0, f"{type(e).__name__}: {e}")
            out = {"ok": False, "error": self._state["last_error"]}
            if self.base_url.startswith("https") or (self.host and not self.base_url.startswith("http:")):
                try:                                       # 어느 단계(DNS·TCP·TLS)에서 막히는지 함께 표시
                    from .diag import diagnose
                    d = await diagnose(self.base_url or self.host)
                    out["checks"] = d
                    self._state["checks"] = d
                except Exception:  # noqa: BLE001
                    pass
            return out

    async def _probe(self, method: str, path: str, **kw) -> str:
        try:
            r = await self.http.request(method, path, **kw)
            return "ok" if r.status_code < 300 else f"HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001
            return f"{type(e).__name__}: {e}"[:200]
