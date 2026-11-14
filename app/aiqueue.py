"""AI(LLM) 분석 대기열 — 로그 폭주 때 분석이 밀리지 않도록 '중요한 것부터, 같은 것은 한 번만, 감당할 만큼만' 순차 처리.

  · 우선순위: 수동 재분석 > critical > error > warning > info, 같은 등급은 먼저 온 순서(FIFO)
  · 병합(coalescing): 같은 소스·같은 로그 패턴(템플릿)의 이상징후는 대표 1건만 LLM 에 보내고, 결과를 나머지에 복사(공유 분석)
  · 소스 할당: 한 소스가 대기열을 독점하지 못하게 소스당 대기 상한(기본 300) — 초과분 중 error 미만은 규칙 탐지로 처리
  · 부하 차단: 대기 500건 초과 시 info/warning 신규는 받지 않음(규칙 탐지 결과 그대로 게시), 상한(2000) 도달 시 가장 낮은 것을 밀어냄
  · 노화: error 미만은 15분 넘게 기다리면 분석 생략(이미 지난 일 — 알림은 규칙 탐지로 이미 나감)
  · 적응형 배치: 대기가 많으면 배치 크기를 batch_max 까지 키워 처리량 확보
"""
from __future__ import annotations

import asyncio
import heapq
import itertools
import time
from collections import Counter, deque
from typing import Any, Callable

PRIO = {"manual": 0, "critical": 1, "error": 2, "warning": 3, "info": 4, "debug": 5}
NAME = {0: "manual", 1: "critical", 2: "error", 3: "warning", 4: "info", 5: "debug"}


class AIQueue:
    def __init__(self, cfg: dict | None = None, on_skip: Callable[[str, str], None] | None = None):
        self.on_skip = on_skip or (lambda aid, why: None)
        self._seq = itertools.count()
        self.heap: list[tuple[int, int, str]] = []
        self.items: dict[str, dict[str, Any]] = {}          # aid → {prio, sig, src, t}
        self.by_sig: dict[str, str] = {}                    # sig → 대표 aid(대기 중)
        self.followers: dict[str, list[str]] = {}           # 대표 aid → 병합된 aid
        self.per_src: Counter = Counter()
        self.wake = asyncio.Event()
        self.stats: Counter = Counter()
        self.done: deque = deque(maxlen=600)                # (완료 시각, 건수, 소요초)
        self.configure(cfg or {})

    def configure(self, cfg: dict) -> None:
        g = lambda k, d: type(d)(cfg.get(k, d)) if cfg.get(k) not in (None, "") else d   # noqa: E731
        self.max_depth = g("queue_max", 2000)
        self.shed_at = g("queue_shed_at", 500)
        self.src_quota = g("queue_source_quota", 300)
        self.max_age = g("queue_max_age", 900)
        self.coalesce = bool(cfg.get("queue_coalesce", True))
        self.batch = g("batch_size", 6)
        self.batch_max = max(self.batch, g("batch_max", self.batch * 2))
        self.interval = float(cfg.get("batch_interval", 5) or 5)

    # ------------------------------------------------------------ 넣기
    def put(self, aid: str, severity: str, source: str = "", template: str = "", manual: bool = False) -> str:
        """반환: queued | coalesced | skipped:<사유>"""
        if aid in self.items:
            return "queued"
        p = 0 if manual else PRIO.get(severity, 4)
        sig = f"{source}|{template}" if template and self.coalesce and not manual else ""
        rep = self.by_sig.get(sig) if sig else None
        if rep and rep in self.items:
            self.followers.setdefault(rep, []).append(aid)
            r = self.items[rep]
            if p < r["prio"]:                                # 더 심각한 것이 합류하면 대표 우선순위 상향
                r["prio"] = p
                heapq.heappush(self.heap, (p, next(self._seq), rep))
            self.stats["coalesced"] += 1
            return "coalesced"
        depth = len(self.items)
        if not manual:
            if source and self.per_src[source] >= self.src_quota and p >= PRIO["warning"]:
                self.stats["quota"] += 1
                return f"skipped:소스 할당 초과({source} 대기 {self.per_src[source]}건)"
            if depth >= self.shed_at and p >= PRIO["warning"]:
                self.stats["shed"] += 1
                return "skipped:부하 차단(대기 많음 — warning 이하는 규칙 탐지로 처리)"
            if depth >= self.max_depth:
                victim = self._lowest()
                if victim is None or self.items[victim]["prio"] <= p:
                    self.stats["full"] += 1
                    return "skipped:대기열 가득 참"
                self._remove(victim, "더 중요한 분석에 밀림(대기열 가득 참)")
        self.items[aid] = {"prio": p, "sig": sig, "src": source, "t": time.time()}
        if sig:
            self.by_sig[sig] = aid
        self.per_src[source] += 1
        heapq.heappush(self.heap, (p, next(self._seq), aid))
        self.stats["queued"] += 1
        self.wake.set()
        return "queued"

    def _lowest(self) -> str | None:
        if not self.items:
            return None
        return max(self.items, key=lambda k: (self.items[k]["prio"], self.items[k]["t"]))

    def _remove(self, aid: str, why: str = "") -> None:
        r = self.items.pop(aid, None)
        if not r:
            return
        self.per_src[r["src"]] -= 1
        if r["sig"] and self.by_sig.get(r["sig"]) == aid:
            self.by_sig.pop(r["sig"], None)
        fol = self.followers.pop(aid, [])
        if why:
            self.stats["dropped"] += 1 + len(fol)
            for x in [aid] + fol:
                self.on_skip(x, why)

    # ------------------------------------------------------------ 꺼내기
    def _pop(self) -> tuple[str, int] | None:
        now = time.time()
        while self.heap:
            p, _s, aid = heapq.heappop(self.heap)
            r = self.items.get(aid)
            if not r or r["prio"] != p:                       # 지난 항목(우선순위 상향으로 재등록됨)
                continue
            if p >= PRIO["warning"] and now - r["t"] > self.max_age:
                self.stats["aged"] += 1
                self._remove(aid, f"대기 {int((now - r['t']) / 60)}분 초과 — 규칙 탐지로 처리")
                continue
            return aid, p
        return None

    def batch_size(self) -> int:
        d = len(self.items)
        return self.batch_max if d > self.batch * 4 else self.batch

    async def get_batch(self, idle_timeout: float = 5.0) -> list[str]:
        """첫 건을 기다렸다가(최대 idle_timeout) 배치 크기만큼 모아 반환. 대기가 많으면 기다리지 않고 바로 채운다."""
        if not self.items:
            self.wake.clear()
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=idle_timeout)
            except asyncio.TimeoutError:
                return []
        bs = self.batch_size()
        if len(self.items) < bs:                              # 조금 모아서 보내기(배치 효율)
            deadline = time.time() + self.interval
            while len(self.items) < bs and time.time() < deadline:
                self.wake.clear()
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout=max(0.05, deadline - time.time()))
                except asyncio.TimeoutError:
                    break
        out = []
        while len(out) < bs:
            x = self._pop()
            if not x:
                break
            out.append(x[0])
        return out

    def take(self, aid: str) -> list[str]:
        """배치에 들어간 대표를 대기열에서 빼고 병합된 aid 목록을 돌려준다(결과 복사 대상)."""
        r = self.items.get(aid)
        fol = self.followers.pop(aid, [])
        if r:
            self.items.pop(aid, None)
            self.per_src[r["src"]] -= 1
            if r["sig"] and self.by_sig.get(r["sig"]) == aid:
                self.by_sig.pop(r["sig"], None)
        return fol

    def record(self, n: int, secs: float) -> None:
        self.done.append((time.time(), n, secs))
        self.stats["analyzed"] += n

    def discard(self, aid: str) -> None:
        self._remove(aid, "")

    # ------------------------------------------------------------ 상태
    def depth(self) -> int:
        return len(self.items) + sum(len(v) for v in self.followers.values())

    def qsize(self) -> int:                                   # asyncio.Queue 호환
        return self.depth()

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        recent = [x for x in self.done if now - x[0] <= 300]
        n5 = sum(x[1] for x in recent)
        span = max(30.0, now - min(t - secs for t, _n, secs in recent)) if recent else 300.0
        rate = n5 / (span / 60.0) if recent else 0.0         # 건/분(최근 5분 안에서 실제 경과 기준)
        lat = (sum(x[2] for x in recent) / len(recent)) if recent else None
        by = Counter(NAME[r["prio"]] for r in self.items.values())
        oldest = min((r["t"] for r in self.items.values()), default=None)
        top = Counter({k: v for k, v in self.per_src.items() if v > 0}).most_common(6)
        d = self.depth()
        return {"depth": d, "unique": len(self.items), "coalesced_waiting": d - len(self.items), "by_severity": dict(by),
                "rate_per_min": round(rate, 1), "batch_latency_s": round(lat, 1) if lat else None,
                "eta_min": round(len(self.items) / rate * 1.0, 1) if rate else None,
                "oldest_wait_s": round(now - oldest) if oldest else 0, "batch_size": self.batch_size(),
                "by_source": dict(top), "stats": dict(self.stats),
                "limits": {"max": self.max_depth, "shed_at": self.shed_at, "source_quota": self.src_quota, "max_age": self.max_age,
                           "coalesce": self.coalesce, "batch": self.batch, "batch_max": self.batch_max}}
