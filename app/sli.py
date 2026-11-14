"""성능 SLI — Isvara(isvara.io)의 '4대 경합 지표·정의된 좋음(Defined good)' 기준으로 VM·클러스터 성능을 점수화.

지표와 기준(isvara.io 첫 화면 'Defined good')
  CPU ready 2.5% · 메모리 latency 1% · 디스크 latency 10 ms · dropped packets 0
점수(0~100, 4밴드) — isvara.io/tools/ops-score 의 밴드 경계(기준의 1·2·3·4배 → 75·50·25·0)와
  예시(디스크 14 ms → 65점)에서 도출한 선형식:  score = max(0, 100 − 25 × 측정값 ÷ 기준)
  밴드: green ≥75 · yellow ≥50 · orange ≥25 · red <25
  dropped packets 는 기준이 0 이라 위 식을 쓸 수 없어 이 프로젝트의 규칙을 씀(설정 가능):
  0 → 100, 0 초과 → 75 − 25 × 측정값 ÷ drop_budget (기본 100개/5분 → 1개 75, 100개 50, 300개 0)
클러스터 KPI — isvara.io/tools/cluster-kpi 의 '평균이 아니라 개별 신호로, 빨강 하나가 초록 여덟과 같은 무게'
  → 밴드 가중치 green 1 · yellow 2 · orange 4 · red 8 로 VM 점수를 가중 평균(깊이) + 밴드별 VM 수(폭)
페일오버 여유 — 가장 큰 호스트 N대가 빠졌을 때 남는 CPU·메모리 용량으로 현재 사용량을 감당하는지(현재값 기준).

이 모듈은 순수 계산만 담당(vCenter 수집은 connectors/vcenter.py). Isvara 의 공식 수식은 공개되지 않았으므로
위 도출식은 '사이트 밴드·예시와 일치하는 해석'이며 Broadcom/VMware 공식 평가가 아닙니다.
"""
from __future__ import annotations

import math
from typing import Any

SIGNALS = ("cpu_ready", "mem_latency", "disk_latency", "net_dropped")
LABEL = {"cpu_ready": "CPU ready", "mem_latency": "메모리 latency", "disk_latency": "디스크 latency",
         "net_dropped": "dropped packets"}
UNIT = {"cpu_ready": "%", "mem_latency": "%", "disk_latency": "ms", "net_dropped": "개"}
DEFAULT_THRESHOLDS = {"cpu_ready": 2.5, "mem_latency": 1.0, "disk_latency": 10.0, "net_dropped": 0.0}
BAND_WEIGHT = {"green": 1, "yellow": 2, "orange": 4, "red": 8}
SOURCES = {
    "defined_good": "https://isvara.io/",
    "ops_score": "https://isvara.io/tools/ops-score",
    "cluster_kpi": "https://isvara.io/tools/cluster-kpi",
    "cpu": "https://isvara.io/read/part-3/cpu#contention-metrics",
    "memory": "https://isvara.io/read/part-3/memory#contention-metrics",
    "storage": "https://isvara.io/read/part-3/storage#storage",
    "network": "https://isvara.io/read/part-3/network#network",
}


def band(score: float | None) -> str:
    if score is None:
        return "none"
    return "green" if score >= 75 else "yellow" if score >= 50 else "orange" if score >= 25 else "red"


def score(signal: str, value: float | None, thresholds: dict[str, float] | None = None,
          drop_budget: float = 100.0) -> float | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    t = (thresholds or DEFAULT_THRESHOLDS).get(signal, DEFAULT_THRESHOLDS[signal])
    v = max(0.0, float(value))
    if t > 0:
        s = 100.0 - 25.0 * v / t
    elif v <= 0:
        s = 100.0
    else:
        s = 75.0 - 25.0 * v / max(1.0, float(drop_budget))
    return round(max(0.0, min(100.0, s)), 1)


def percentile(xs: list[float], p: float) -> float | None:
    """nearest-rank 백분위(p=99 → 상위 1% 제외 최댓값). 표본이 적으면 사실상 최댓값."""
    v = sorted(x for x in xs if x is not None and x >= 0)
    if not v:
        return None
    k = max(0, min(len(v) - 1, math.ceil(p / 100.0 * len(v)) - 1))
    return v[k]


def vm_result(name: str, readings: dict[str, float | None], thresholds: dict[str, float] | None = None,
              drop_budget: float = 100.0, **meta) -> dict[str, Any]:
    """VM 1대: 신호별 측정값·점수 → 가장 나쁜 신호가 VM 점수(약한 고리)."""
    sig = {}
    for s in SIGNALS:
        v = readings.get(s)
        sc = score(s, v, thresholds, drop_budget)
        sig[s] = {"value": None if v is None else round(float(v), 3), "score": sc, "band": band(sc)}
    scored = [(d["score"], s) for s, d in sig.items() if d["score"] is not None]
    worst = min(scored) if scored else (None, "")
    return {"name": name, "score": worst[0], "band": band(worst[0]), "worst": worst[1], "signals": sig, **meta}


def cluster_kpi(vms: list[dict[str, Any]]) -> dict[str, Any]:
    """깊이(진행 가중 평균)·폭(밴드별 VM 수)·신호별 최악값."""
    rows = [v for v in vms if v.get("score") is not None]
    counts = {b: 0 for b in BAND_WEIGHT}
    for v in rows:
        counts[v["band"]] += 1
    if not rows:
        return {"score": None, "band": "none", "vms": 0, "bands": counts, "signals": {}}
    wsum = sum(BAND_WEIGHT[v["band"]] for v in rows)
    sc = round(sum(v["score"] * BAND_WEIGHT[v["band"]] for v in rows) / wsum, 1)
    per = {}
    for s in SIGNALS:
        vals = [(v["signals"][s]["score"], v["name"], v["signals"][s]["value"]) for v in rows
                if v["signals"][s]["score"] is not None]
        if vals:
            w = min(vals)
            per[s] = {"worst_score": w[0], "worst_vm": w[1], "worst_value": w[2],
                      "breach": sum(1 for x in vals if x[0] < 75)}
    return {"score": sc, "band": band(sc), "vms": len(rows), "bands": counts, "signals": per}


def failover(hosts: list[dict[str, Any]], tolerate: int = 1) -> dict[str, Any]:
    """hosts: [{name, cpu_mhz, mem_mb, cpu_used_mhz, mem_used_mb, maintenance, connected}]
    가장 큰 호스트 N대를 뺀 용량 대비 현재 사용량 → 여유(%)·판정. 유지보수·연결 끊김 호스트는 용량에서 제외."""
    live = [h for h in hosts if h.get("connected", True) and not h.get("maintenance")]
    if len(live) <= tolerate:
        return {"tolerate": tolerate, "hosts": len(live), "verdict": "insufficient_hosts",
                "detail": f"가동 호스트 {len(live)}대 — {tolerate}대 장애를 견딜 수 없음"}
    out: dict[str, Any] = {"tolerate": tolerate, "hosts": len(live)}
    ok = True
    for res, cap_k, used_k in (("cpu", "cpu_mhz", "cpu_used_mhz"), ("mem", "mem_mb", "mem_used_mb")):
        caps = sorted((float(h.get(cap_k) or 0) for h in live), reverse=True)
        total, after = sum(caps), sum(caps[tolerate:])
        used = sum(float(h.get(used_k) or 0) for h in live)
        head = round((after - used) / after * 100, 1) if after else None
        out[res] = {"capacity": round(total), "after_failure": round(after), "used": round(used),
                    "used_pct_now": round(used / total * 100, 1) if total else None,
                    "used_pct_after": round(used / after * 100, 1) if after else None, "headroom_pct": head}
        ok = ok and head is not None and head >= 0
    out["verdict"] = "ok" if ok else "at_risk"
    return out
