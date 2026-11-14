"""런타임 안정성 기반 — 백그라운드 작업 감독·이벤트 루프 지연 감시·서킷 브레이커·분당 카운터.

Supervisor   모든 상주 루프를 감독. 예외로 죽으면 지수 백오프(1→60초)로 재기동, 하트비트가 끊기면 '정체'로 판정.
             critical 작업이 정체/반복 실패하면 /readyz 가 503 → 로드밸런서·서비스 감시가 감지.
LoopLag      이벤트 루프 지연(ms) 측정 — 실시간 처리 여유의 1차 지표(정상 < 50ms).
Breaker      외부 의존(LLM·웹훅·ITSM) 연속 실패 시 일정 시간 호출 차단 → 대기열 적체·지연 전파 방지.
MinuteCounter 최근 60분 (source, connector)별 분당 건수 — 관제 화면 집계를 DB 스캔 없이 메모리에서 계산.
"""
from __future__ import annotations

import asyncio
import random
import time
import traceback
from collections import deque
from typing import Any, Awaitable, Callable


class Supervisor:
    def __init__(self):
        self.jobs: dict[str, dict[str, Any]] = {}
        self._stopping = False

    def spawn(self, name: str, factory: Callable[[], Awaitable[None]], *, critical: bool = True,
              heartbeat: float = 0.0) -> asyncio.Task:
        """factory: 매번 새 코루틴을 만드는 함수. heartbeat>0 이면 그 주기의 3배 동안 beat() 가 없을 때 정체로 본다."""
        j = self.jobs.setdefault(name, {"name": name, "critical": critical, "heartbeat": heartbeat, "restarts": 0,
                                        "state": "starting", "last_error": "", "last_beat": time.time(),
                                        "started": time.time(), "task": None})
        j["task"] = asyncio.create_task(self._run(name, factory), name=f"sup:{name}")
        return j["task"]

    async def _run(self, name: str, factory) -> None:
        j = self.jobs[name]
        delay = 1.0
        while not self._stopping:
            j["state"], j["started"], j["last_beat"] = "running", time.time(), time.time()
            t0 = time.time()
            try:
                await factory()
                if self._stopping:
                    break
                j["state"], j["last_error"] = "exited", "정상 종료(재기동)"
            except asyncio.CancelledError:
                j["state"] = "stopped"
                raise
            except Exception as e:  # noqa: BLE001
                j["state"] = "crashed"
                j["last_error"] = f"{type(e).__name__}: {e}"[:400]
                print(f"[supervisor] {name} 비정상 종료 — {j['last_error']}\n{traceback.format_exc(limit=6)}", flush=True)
            j["restarts"] += 1
            if time.time() - t0 > 300:     # 5분 이상 정상 동작 후 죽었으면 백오프 초기화
                delay = 1.0
            await asyncio.sleep(delay + random.uniform(0, delay / 4))
            delay = min(delay * 2, 60.0)

    def cancel(self, name: str) -> None:
        j = self.jobs.pop(name, None)
        if j and j.get("task"):
            j["task"].cancel()

    def beat(self, name: str) -> None:
        j = self.jobs.get(name)
        if j:
            j["last_beat"] = time.time()

    def summary(self) -> list[dict[str, Any]]:
        now = time.time()
        out = []
        for j in self.jobs.values():
            st = j["state"]
            if st == "running" and j["heartbeat"] and now - j["last_beat"] > 3 * j["heartbeat"]:
                st = "stalled"
            out.append({"name": j["name"], "critical": j["critical"], "state": st, "restarts": j["restarts"], "heartbeat": j["heartbeat"],
                        "last_error": j["last_error"], "beat_age": round(now - j["last_beat"], 1),
                        "uptime": round(now - j["started"], 1)})
        return out

    def unhealthy(self) -> list[str]:
        return [j["name"] for j in self.summary() if j["critical"] and j["state"] in ("stalled", "crashed", "exited")]

    async def stop(self) -> None:
        self._stopping = True
        tasks = [j["task"] for j in self.jobs.values() if j.get("task")]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class LoopLag:
    """0.25초마다 깨어나 예정 대비 지연을 잰다. 최근 1분 p99·최대·현재 노출."""

    def __init__(self, interval: float = 0.25):
        self.interval = interval
        self.samples: deque[float] = deque(maxlen=int(60 / interval))
        self.current = 0.0

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            t = loop.time()
            await asyncio.sleep(self.interval)
            self.current = max(0.0, (loop.time() - t - self.interval) * 1000)
            self.samples.append(self.current)

    def stats(self) -> dict[str, float]:
        xs = sorted(self.samples) or [0.0]
        return {"current_ms": round(self.current, 1), "p50_ms": round(xs[len(xs) // 2], 1),
                "p99_ms": round(xs[min(len(xs) - 1, int(len(xs) * 0.99))], 1), "max_ms": round(xs[-1], 1)}


class BreakerOpen(RuntimeError):
    pass


class Breaker:
    """closed → (연속 실패 threshold회) → open(reset 초 동안 즉시 거절) → half_open(1회 시험) → closed/open"""

    def __init__(self, name: str, threshold: int = 3, reset: float = 60.0):
        self.name, self.threshold, self.reset = name, threshold, reset
        self.state, self.fails, self.opened, self.last_error = "closed", 0, 0.0, ""
        self.rejected = 0

    def allow(self) -> bool:
        if self.state == "open":
            if time.time() - self.opened >= self.reset:
                self.state = "half_open"
                return True
            self.rejected += 1
            return False
        return True

    def ok(self) -> None:
        self.state, self.fails = "closed", 0

    def fail(self, err: str = "") -> None:
        self.fails += 1
        self.last_error = err[:300]
        if self.state == "half_open" or self.fails >= self.threshold:
            if self.state != "open":
                print(f"[breaker] {self.name} 차단(open) — {self.last_error}", flush=True)
            self.state, self.opened = "open", time.time()

    async def call(self, coro_fn: Callable[[], Awaitable[Any]], timeout: float | None = None) -> Any:
        if not self.allow():
            raise BreakerOpen(f"{self.name} 일시 차단 중({int(self.reset - (time.time() - self.opened))}초 남음): {self.last_error}")
        try:
            res = await (asyncio.wait_for(coro_fn(), timeout) if timeout else coro_fn())
        except Exception as e:  # noqa: BLE001
            self.fail(f"{type(e).__name__}: {e}")
            raise
        self.ok()
        return res

    def status(self) -> dict[str, Any]:
        return {"state": self.state, "fails": self.fails, "rejected": self.rejected, "last_error": self.last_error,
                "retry_in": max(0, int(self.reset - (time.time() - self.opened))) if self.state == "open" else 0}


class MinuteCounter:
    """(source, connector) 키별 최근 60분 분당 건수 링버퍼. add() 는 O(1)."""

    def __init__(self, minutes: int = 60):
        self.n = minutes
        self.data: dict[tuple[str, str], list[int]] = {}
        self.last: dict[str, float] = {}                 # source → 마지막 수신 시각(관제 화면 데이터 신선도)
        self.minute = int(time.time() // 60)
        self.sev: dict[tuple[str, str], list[int]] = {}  # (source, warning|error|critical) → 분당 건수(도메인 상세 화면)
        self.hot: dict[str, dict[str, int]] = {}          # source → 호스트별 건수(현재 10분 창)
        self.hot_prev: dict[str, dict[str, int]] = {}     # 직전 10분 창
        self.hot_win = int(time.time() // 600)
        self.hmin: dict[str, list] = {}                   # 호스트(소문자) → [마지막 분, 60분 분당 건수] (개체 상세 추이)

    def _roll(self, m: int) -> None:
        if m == self.minute:
            return
        shift = min(self.n, m - self.minute)
        if shift > 0:
            for arr in list(self.data.values()) + list(self.sev.values()):
                del arr[:shift]
                arr.extend([0] * shift)
        self.minute = m

    def add(self, source: str, connector: str, k: int = 1, sev: str | None = None, host: str | None = None) -> None:
        now = time.time()
        self.last[source] = now
        self._roll(int(now // 60))
        arr = self.data.get((source, connector))
        if arr is None:
            arr = self.data[(source, connector)] = [0] * self.n
        arr[-1] += k
        if sev in ("warning", "error", "critical"):
            a2 = self.sev.get((source, sev))
            if a2 is None:
                a2 = self.sev[(source, sev)] = [0] * self.n
            a2[-1] += k
        if host:
            w = int(now // 600)
            if w != self.hot_win:
                self.hot_prev = self.hot if w == self.hot_win + 1 else {}
                self.hot, self.hot_win = {}, w
            d = self.hot.setdefault(source, {})
            if host in d or len(d) < 5000:              # 호스트 수 상한(메모리 보호)
                d[host] = d.get(host, 0) + k
            hk = host.lower()
            r = self.hmin.get(hk)
            if r is None and len(self.hmin) < 8000:
                r = self.hmin[hk] = [self.minute, [0] * self.n]
            if r is not None:
                self._hroll(r, self.minute)
                r[1][-1] += k

    def _hroll(self, r: list, m: int) -> None:
        sh = min(self.n, m - r[0])
        if sh > 0:
            del r[1][:sh]
            r[1].extend([0] * sh)
            r[0] = m

    def host_series(self, *names: str) -> list[int]:
        """호스트(FQDN·짧은 이름 모두 시도)의 60분 분당 이벤트 수"""
        m = int(time.time() // 60)
        out = [0] * self.n
        seen = set()
        for nm in names:
            if not nm:
                continue
            nm = str(nm).lower()
            for k in {nm, nm.split(".")[0]} | {h for h in self.hmin if h.split(".")[0] == nm.split(".")[0]}:
                if k in seen or k not in self.hmin:
                    continue
                seen.add(k)
                r = self.hmin[k]
                self._hroll(r, m)
                for i, v in enumerate(r[1]):
                    out[i] += v
        return out

    def sev_series(self, sources: set[str]) -> dict[str, list[int]]:
        """해당 소스들의 심각도별(경고·오류·위험) 60분 분당 시계열"""
        self._roll(int(time.time() // 60))
        out = {s: [0] * self.n for s in ("warning", "error", "critical")}
        for (src, sv), arr in self.sev.items():
            if src in sources:
                o = out[sv]
                for i, v in enumerate(arr):
                    o[i] += v
        return out

    def top_hosts(self, sources: set[str], n: int = 12) -> list[dict]:
        """최근 10~20분 이벤트가 많은 호스트(현재 창 + 직전 창)"""
        w = int(time.time() // 600)
        cur = self.hot if w == self.hot_win else {}
        prev = self.hot_prev if w == self.hot_win else self.hot if w == self.hot_win + 1 else {}
        agg: dict[str, int] = {}
        for d in (cur, prev):
            for src in sources:
                for h, v in (d.get(src) or {}).items():
                    agg[h] = agg.get(h, 0) + v
        return [{"host": h, "n": v} for h, v in sorted(agg.items(), key=lambda x: -x[1])[:n]]

    def series(self, sources: set[str]) -> tuple[list[int], int]:
        """해당 소스들의 60분 분당 합계 시계열(마지막 = 현재 분), syslog 최근 5분 합"""
        self._roll(int(time.time() // 60))
        out = [0] * self.n
        sy5 = 0
        for (src, conn), arr in self.data.items():
            if src in sources:
                for i, v in enumerate(arr):
                    out[i] += v
                if conn == "syslog":
                    sy5 += sum(arr[-5:])
        return out, sy5

    def seed(self, rows: list[dict]) -> None:
        """재기동 시 DB 의 최근 60분 집계로 초기화 — rows: [{m, source, connector, n}]"""
        m_now = int(time.time() // 60)
        self.minute = m_now
        for r in rows:
            age = m_now - int(r["m"])
            if 0 <= age < self.n:
                arr = self.data.setdefault((r["source"], r["connector"]), [0] * self.n)
                arr[self.n - 1 - age] += int(r["n"])
                if r.get("severity") in ("warning", "error", "critical"):
                    self.sev.setdefault((r["source"], r["severity"]), [0] * self.n)[self.n - 1 - age] += int(r["n"])
                self.last[r["source"]] = max(self.last.get(r["source"], 0.0), (int(r["m"]) + 1) * 60.0)

    def last_seen(self, sources: set[str]) -> float:
        return max((self.last.get(s, 0.0) for s in sources), default=0.0)


_BG: set[asyncio.Task] = set()


def bg(coro) -> asyncio.Task:
    """참조를 유지하는 백그라운드 작업 — asyncio 는 약한 참조만 들고 있어 create_task 결과를 버리면 도중에 사라질 수 있다."""
    t = asyncio.ensure_future(coro)
    _BG.add(t)
    t.add_done_callback(_BG.discard)
    return t


class SystemdNotifier:
    """systemd sd_notify(3) 구현(의존성 없음) — Type=notify 서비스의 기동 완료·워치독·상태 문자열.

    · READY=1      : 수집기·작업 기동이 끝난 뒤 1회(systemctl start 가 이때 반환)
    · WATCHDOG=1   : WatchdogSec 의 1/3 주기. 이벤트 루프가 멈추면 자연히 끊기고, /readyz 기준 '준비 안 됨'이
                     unready_grace(기본 300초) 넘게 이어지면 의도적으로 보내지 않아 systemd 가 재시작하게 한다.
    · STATUS=...   : systemctl status 에 처리량·이상징후·준비 상태 표시
    · STOPPING=1   : 종료 시작
    NOTIFY_SOCKET 이 없으면(직접 실행·Windows) 아무것도 하지 않는다."""

    def __init__(self):
        import os
        self.addr = os.environ.get("NOTIFY_SOCKET", "")
        usec = os.environ.get("WATCHDOG_USEC", "")
        self.watchdog = (int(usec) / 1e6) if usec.isdigit() else 0.0
        self.enabled = bool(self.addr)

    def send(self, msg: str) -> bool:
        if not self.enabled:
            return False
        import socket
        addr = "\0" + self.addr[1:] if self.addr.startswith("@") else self.addr
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
                s.connect(addr)
                s.sendall(msg.encode())
            return True
        except OSError:
            return False

    async def loop(self, ready, status, unready_grace: float = 300.0, beat=lambda: None) -> None:
        if not self.enabled:
            while True:
                beat()
                await asyncio.sleep(60)
        period = max(1.0, self.watchdog / 3) if self.watchdog else 10.0
        last_ready = time.time()
        while True:
            beat()
            ok, why = ready()
            now = time.time()
            if ok:
                last_ready = now
            self.send(f"STATUS={status()}{'' if ok else ' · 준비 안 됨: ' + ', '.join(why)[:200]}")
            if self.watchdog and now - last_ready < unready_grace:
                self.send("WATCHDOG=1")
            await asyncio.sleep(period)
