"""AI 호출 조절기(governor) — GPU 발열·부하와 외부 API 비용을 최소화하도록 LLM 호출 속도를 제한.

  · 쿨다운: 자동 분석 호출 사이 최소 간격(min_interval, 기본 5초) — GPU 가 연속 풀가동되지 않게 쉬는 시간 확보
  · 시간당 상한: 공급자별 자동 호출 수(max_calls_per_hour, 기본 120; 0 = 무제한). 넘으면 다음 시간대까지 대기(대기열이 보관)
  · GPU 온도·사용률(선택): DCGM exporter /metrics(Prometheus) 의 DCGM_FI_DEV_GPU_TEMP·DCGM_FI_DEV_GPU_UTIL 을 읽어
    temp_pause(기본 80°C) 이상이면 자동 분석 일시 중지, temp_resume(기본 72°C) 이하로 내려오면 재개(히스테리시스)
  · LLM 서버 대기열(선택): vLLM /metrics 의 vllm:num_requests_waiting 이 vllm_waiting_max 이상이면 대기
  · 사람이 누른 요청(AI 질의·수동 재분석·RCA)은 쿨다운·시간당 상한을 건너뛰고, GPU 과열 중지만 따른다

외부 API(Claude·Gemini)에는 GPU 조건을 적용하지 않고 시간당 상한(비용)만 적용한다.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from typing import Any

import httpx

DEFAULTS = {"min_interval": 5.0, "max_calls_per_hour": 120, "gpu_metrics_url": "", "temp_pause": 80.0, "temp_resume": 72.0,
            "util_pause": 0.0, "vllm_metrics_url": "", "vllm_waiting_max": 4, "poll_interval": 15.0}
_M = re.compile(r"^([a-zA-Z_:][\w:]*)(\{[^}]*\})?\s+([-+0-9.eE]+|NaN)\s*$")


def parse_prom(text: str, names: set[str]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for ln in text.splitlines():
        if not ln or ln[0] == "#":
            continue
        m = _M.match(ln.strip())
        if m and m.group(1) in names:
            try:
                out.setdefault(m.group(1), []).append(float(m.group(3)))
            except ValueError:
                pass
    return out


class Governor:
    def __init__(self, cfg: dict | None = None):
        self.last_call: dict[str, float] = {}
        self.calls: dict[str, deque] = {}
        self.gpu: dict[str, Any] = {}
        self.vllm: dict[str, Any] = {}
        self.hot = False
        self.waiting_reason = ""
        self.waits = 0
        self.configure(cfg or {})

    def configure(self, cfg: dict) -> None:
        c = dict(DEFAULTS)
        for k, d in DEFAULTS.items():
            v = (cfg or {}).get(k)
            if v in (None, ""):
                continue
            try:
                c[k] = type(d)(v)
            except (TypeError, ValueError):
                pass
        self.cfg = c

    # ------------------------------------------------------------ 판정
    def _hour(self, name: str) -> int:
        dq = self.calls.setdefault(name, deque())
        cut = time.time() - 3600
        while dq and dq[0] < cut:
            dq.popleft()
        return len(dq)

    def blocked(self, provider, interactive: bool = False) -> tuple[str, float]:
        """(사유, 대기 초) — 사유가 빈 문자열이면 호출 가능"""
        now = time.time()
        local = not getattr(provider, "external", False)
        if local and self.hot:
            return f"GPU 과열 보호 — {self.gpu.get('temp_max', '?')}°C (재개 {self.cfg['temp_resume']:.0f}°C 이하)", 15.0
        if local and self.cfg["util_pause"] and (self.gpu.get("util_max") or 0) >= self.cfg["util_pause"] and not interactive:
            return f"GPU 사용률 {self.gpu.get('util_max')}% — 여유 생길 때까지 대기", 10.0
        if local and self.cfg["vllm_waiting_max"] and (self.vllm.get("waiting") or 0) >= self.cfg["vllm_waiting_max"] and not interactive:
            return f"LLM 서버 대기 요청 {int(self.vllm['waiting'])}건 — 대기", 5.0
        if interactive:
            return "", 0.0
        gap = now - self.last_call.get(provider.name, 0)
        if gap < self.cfg["min_interval"]:
            return "쿨다운", self.cfg["min_interval"] - gap
        lim = self.cfg["max_calls_per_hour"]
        if lim and self._hour(provider.name) >= lim:
            first = self.calls[provider.name][0]
            return f"시간당 상한 {lim}회 도달 — {int((first + 3600 - now) / 60) + 1}분 뒤 재개", min(60.0, first + 3600 - now)
        return "", 0.0

    async def acquire(self, provider, interactive: bool = False, max_wait: float = 0) -> None:
        """호출 가능할 때까지 대기(자동 분석은 무기한 — 대기열이 쌓이고 노화 규칙이 정리). max_wait>0 이면 초과 시 예외."""
        t0 = time.time()
        while True:
            why, wait = self.blocked(provider, interactive)
            if not why:
                break
            self.waiting_reason = why if why != "쿨다운" else ""
            self.waits += 1
            if max_wait and time.time() - t0 + wait > max_wait:
                raise RuntimeError(f"AI 호출 보류: {why}")
            await asyncio.sleep(max(0.2, min(wait, 15.0)))
        self.waiting_reason = ""
        now = time.time()
        self.last_call[provider.name] = now
        self.calls.setdefault(provider.name, deque()).append(now)

    # ------------------------------------------------------------ 텔레메트리
    async def poll_once(self, http: httpx.AsyncClient) -> None:
        c = self.cfg
        if c["gpu_metrics_url"]:
            try:
                r = await http.get(c["gpu_metrics_url"])
                r.raise_for_status()
                m = parse_prom(r.text, {"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_GPU_UTIL", "DCGM_FI_DEV_POWER_USAGE", "DCGM_FI_DEV_MEMORY_TEMP"})
                t = m.get("DCGM_FI_DEV_GPU_TEMP") or []
                self.gpu = {"temp_max": max(t) if t else None, "temps": t[:16], "util_max": max(m.get("DCGM_FI_DEV_GPU_UTIL") or [0]),
                            "power_w": round(sum(m.get("DCGM_FI_DEV_POWER_USAGE") or []), 1), "gpus": len(t), "ts": time.time(), "error": ""}
                tm = self.gpu["temp_max"]
                if tm is not None:
                    if not self.hot and tm >= c["temp_pause"]:
                        self.hot = True
                    elif self.hot and tm <= c["temp_resume"]:
                        self.hot = False
            except Exception as e:  # noqa: BLE001
                self.gpu = {**self.gpu, "error": f"{type(e).__name__}: {e}"[:200], "ts": time.time()}
        if c["vllm_metrics_url"]:
            try:
                r = await http.get(c["vllm_metrics_url"])
                r.raise_for_status()
                m = parse_prom(r.text, {"vllm:num_requests_waiting", "vllm:num_requests_running", "vllm:gpu_cache_usage_perc",
                                        "vllm:kv_cache_usage_perc"})
                self.vllm = {"waiting": sum(m.get("vllm:num_requests_waiting") or [0]), "running": sum(m.get("vllm:num_requests_running") or [0]),
                             "kv_cache": max((m.get("vllm:kv_cache_usage_perc") or m.get("vllm:gpu_cache_usage_perc") or [0])),
                             "ts": time.time(), "error": ""}
            except Exception as e:  # noqa: BLE001
                self.vllm = {**self.vllm, "error": f"{type(e).__name__}: {e}"[:200], "ts": time.time()}

    async def loop(self, beat=None) -> None:
        async with httpx.AsyncClient(verify=False, timeout=8) as http:
            while True:
                if beat:
                    beat()
                if self.cfg["gpu_metrics_url"] or self.cfg["vllm_metrics_url"]:
                    await self.poll_once(http)
                await asyncio.sleep(self.cfg["poll_interval"])

    def snapshot(self) -> dict[str, Any]:
        return {"config": self.cfg, "hot": self.hot, "gpu": self.gpu, "vllm": self.vllm, "waiting": self.waiting_reason,
                "calls_last_hour": {n: self._hour(n) for n in list(self.calls)}, "waits": self.waits}
