"""용량 계획·VM 적정화(2.0) — 클러스터·데이터스토어 사용량을 시간 단위로 누적해 추세를 예측하고, 정산 표본(bill_usage)의
VM 사용률로 과다·과소·유휴·장기 꺼짐 VM 을 찾는다.

  · 표본: 5분마다(정산 루프와 같은 주기) 클러스터 CPU·메모리(quickStats 합), vSAN/공유 데이터스토어 용량 → cap_usage(hour 단위 합·횟수)
  · 예측: 최근 N일(기본 30) 일 평균에 최소제곱 직선을 맞춰 하루 증가량·80%/90% 도달 예상일·30/90일 뒤 사용률. 표본이 7일 미만이면 '수집 중'
  · 적정화(최근 14일, 켜진 블록 기준): 평균·피크(시간 평균의 최댓값) 사용률
       과다(oversized) : vCPU 4 이상·피크 CPU < 25% 또는 메모리 8GB 이상·피크 메모리 < 30% → 권장 크기 = 피크 × 1.5 여유(최소 2 vCPU·2 GB)
       과소(undersized): 평균 CPU ≥ 75% 또는 평균 메모리 ≥ 85%
       유휴(idle)       : 켜져 있는데 피크 CPU < 3% 이고 피크 메모리 < 10%
       장기 꺼짐        : 기간 내 켜진 블록 0, 꺼진 채 관측된 시간 ≥ 7일(디스크만 차지)
    절감 추정 = 기본 요율표의 vCPU·메모리 단가 × 줄일 수 있는 양 × 730시간(월)
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import math
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS cap_usage(hour INTEGER, vc TEXT, kind TEXT, name TEXT, n INTEGER DEFAULT 0,
  cpu_used REAL DEFAULT 0, cpu_total REAL DEFAULT 0, mem_used REAL DEFAULT 0, mem_total REAL DEFAULT 0,
  disk_used REAL DEFAULT 0, disk_total REAL DEFAULT 0, vms INTEGER DEFAULT 0, vms_on INTEGER DEFAULT 0, PRIMARY KEY(hour, vc, kind, name));
CREATE INDEX IF NOT EXISTS ix_cap_usage_hour ON cap_usage(hour);
"""
BLOCK = 300


def forecast(points: list[tuple[float, float]], now: float, thresholds=(80.0, 90.0)) -> dict[str, Any]:
    """points: [(일 번호(float, 일 단위), 사용률 %)] → 기울기(%/일)·도달일·30/90일 예측"""
    if len(points) < 3:
        return {"slope": None, "days_to": {str(int(t)): None for t in thresholds}, "p30": None, "p90": None, "r2": None, "samples": len(points)}
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx if sxx else 0.0
    b = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + b)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / ss_tot if ss_tot else None
    last_x = xs[-1]
    cur = ys[-1]
    out = {"slope": round(slope, 3), "r2": round(r2, 3) if r2 is not None else None, "samples": n,
           "p30": round(min(100.0, max(0.0, slope * (last_x + 30) + b)), 1), "p90": round(min(100.0, max(0.0, slope * (last_x + 90) + b)), 1), "days_to": {}}
    for t in thresholds:
        if cur >= t:
            out["days_to"][str(int(t))] = 0
        elif slope <= 0.01:
            out["days_to"][str(int(t))] = None
        else:
            out["days_to"][str(int(t))] = int(math.ceil((t - cur) / slope))
    return out


class Capacity:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.enabled = bool(c.get("enabled", True))
        self.days = int(c.get("forecast_days", 30))
        self.rs_days = int(c.get("rightsizing_days", 14))
        self.retention_days = int(c.get("retention_days", 400))
        self.th = {"over_cpu": float(c.get("oversized_cpu_pct", 25)), "over_mem": float(c.get("oversized_mem_pct", 30)),
                   "under_cpu": float(c.get("undersized_cpu_pct", 75)), "under_mem": float(c.get("undersized_mem_pct", 85)),
                   "idle_cpu": float(c.get("idle_cpu_pct", 3)), "idle_mem": float(c.get("idle_mem_pct", 10)), "headroom": float(c.get("headroom", 1.5)),
                   "off_days": int(c.get("powered_off_days", 7))}
        self._schema = False
        self._last_block = 0
        self.stats: dict[str, Any] = {"last_sample": 0, "rows": 0, "error": ""}
        self._cache: dict[str, tuple[float, dict]] = {}
        self._flight: dict[str, asyncio.Lock] = {}          # 캐시 키별 단일 실행

    def _ensure(self):
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    # ------------------------------------------------------------------ 표본
    def snapshot_rows(self, now: float | None = None) -> list[tuple]:
        now = now or time.time()
        hour = int(now // 3600 * 3600)
        rows = []
        for c in self.e.connectors:
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
                continue
            t = getattr(c, "topology", {}) or {}
            if not t.get("updated"):
                continue
            H, V = t.get("hosts", {}) or {}, t.get("vms", {}) or {}
            for cn, x in (t.get("clusters", {}) or {}).items():
                hs = [H.get(h, {}) for h in x.get("hosts", [])]
                vms = [v for v in V.values() if v.get("host") in set(x.get("hosts", []))]
                rows.append((hour, c.name, "cluster", cn, 1, sum(h.get("cpu_used_mhz", 0) for h in hs), sum(h.get("cpu_mhz", 0) for h in hs),
                             sum(h.get("mem_used_mb", 0) for h in hs), sum(h.get("mem_mb", 0) for h in hs), 0, 0,
                             len(vms), sum(1 for v in vms if v.get("power") == "poweredOn")))
            for dn, d in (t.get("datastores", {}) or {}).items():
                cap = d.get("capacity_gb") or 0
                if not cap or (d.get("local") is True) or (d.get("local") is None and len(d.get("hosts") or []) == 1 and str(d.get("type", "")).lower() == "vmfs"):
                    continue                                         # 로컬 디스크는 용량 계획 대상 아님
                rows.append((hour, c.name, "datastore", dn, 1, 0, 0, 0, 0, cap - (d.get("free_gb") or 0), cap, d.get("vms") or 0, 0))
        return rows

    async def sample(self, now: float | None = None) -> int:
        now = now or time.time()
        blk = int(now // BLOCK)
        if blk == self._last_block:
            return 0
        self._ensure()
        rows = self.snapshot_rows(now)
        await self.e.store.xm(
            "INSERT INTO cap_usage(hour,vc,kind,name,n,cpu_used,cpu_total,mem_used,mem_total,disk_used,disk_total,vms,vms_on) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(hour,vc,kind,name) DO UPDATE SET n=n+1, cpu_used=cpu_used+excluded.cpu_used, cpu_total=cpu_total+excluded.cpu_total, "
            "mem_used=mem_used+excluded.mem_used, mem_total=mem_total+excluded.mem_total, disk_used=disk_used+excluded.disk_used, "
            "disk_total=disk_total+excluded.disk_total, vms=excluded.vms, vms_on=excluded.vms_on", rows)
        self._last_block = blk
        self.stats.update(last_sample=now, rows=len(rows), error="")
        self._cache.clear()
        return len(rows)

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(25)
        last_purge = 0.0
        while True:
            beat()
            if self.enabled:
                try:
                    await self.sample()
                    if time.time() - last_purge > 86400:
                        last_purge = time.time()
                        await self.e.store.x("DELETE FROM cap_usage WHERE hour < ?", (time.time() - self.retention_days * 86400,))
                except Exception as e:  # noqa: BLE001
                    self.stats["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(BLOCK - (time.time() % BLOCK) + 5)

    # ------------------------------------------------------------------ 용량 예측
    async def overview(self, days: int | None = None) -> dict[str, Any]:
        days = days or self.days
        key = f"ov:{days}"
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < 120:
            return hit[1]
        self._ensure()
        now = time.time()
        since = now - days * 86400
        rows = await self.e.store.q("SELECT hour,vc,kind,name,n,cpu_used,cpu_total,mem_used,mem_total,disk_used,disk_total,vms,vms_on "
                                    "FROM cap_usage WHERE hour>=? ORDER BY hour", (since,))
        series: dict[tuple, list[dict]] = {}
        for r in rows:
            series.setdefault((r["vc"], r["kind"], r["name"]), []).append(r)
        live: dict[tuple, dict] = {}
        for c in self.e.connectors:                              # 현재 값(표본이 없어도 현재 상태는 표시)
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
                continue
            t = getattr(c, "topology", {}) or {}
            H = t.get("hosts", {}) or {}
            for cn, x in (t.get("clusters", {}) or {}).items():
                hs = [H.get(h, {}) for h in x.get("hosts", [])]
                ct, mt = sum(h.get("cpu_mhz", 0) for h in hs), sum(h.get("mem_mb", 0) for h in hs)
                live[(c.name, "cluster", cn)] = {"cpu": round(sum(h.get("cpu_used_mhz", 0) for h in hs) / ct * 100, 1) if ct else None,
                                                  "mem": round(sum(h.get("mem_used_mb", 0) for h in hs) / mt * 100, 1) if mt else None,
                                                  "hosts": len(hs), "cpu_total_ghz": round(ct / 1000, 1), "mem_total_gb": round(mt / 1024, 1), "vsan": bool(x.get("vsan")),
                                                  "ha_n1": round(sum(h.get("mem_used_mb", 0) for h in hs) / (mt - max((h.get("mem_mb", 0) for h in hs), default=0)) * 100, 1)
                                                  if len(hs) > 1 and mt - max((h.get("mem_mb", 0) for h in hs), default=0) > 0 else None}
            for dn, d in (t.get("datastores", {}) or {}).items():
                if (d.get("capacity_gb") or 0) and d.get("local") is not True:
                    live[(c.name, "datastore", dn)] = {"disk": d.get("used_pct"), "capacity_gb": d.get("capacity_gb"), "free_gb": d.get("free_gb"),
                                                        "type": d.get("type", ""), "prov_gb": d.get("prov_gb"), "vms": d.get("vms")}
        out = []
        for k in sorted(set(series) | set(live), key=lambda x: (x[1], x[0], x[2])):
            vc, kind, name = k
            rs = series.get(k, [])
            daily: dict[int, list[float]] = {}
            spark = []
            for r in rs:
                n = r["n"] or 1
                if kind == "cluster":
                    v = r["cpu_used"] / r["cpu_total"] * 100 if r["cpu_total"] else None
                    vm = r["mem_used"] / r["mem_total"] * 100 if r["mem_total"] else None
                else:
                    v = r["disk_used"] / r["disk_total"] * 100 if r["disk_total"] else None
                    vm = None
                if v is None:
                    continue
                d = int((r["hour"] - since) // 86400)
                daily.setdefault(d, []).append(v)
                if kind == "cluster" and vm is not None:
                    daily.setdefault(-1000 - d, []).append(vm)
                spark.append(round(v, 1))
            cpu_pts = sorted((d, sum(v) / len(v)) for d, v in daily.items() if d >= 0)
            mem_pts = sorted((-1000 - d, sum(v) / len(v)) for d, v in daily.items() if d < 0)
            fc = forecast(cpu_pts, now)
            fm = forecast(mem_pts, now) if kind == "cluster" else None
            step = max(1, len(spark) // 60)
            row = {"vcenter": vc, "kind": kind, "name": name, **live.get(k, {}), "days_observed": round(len({d for d in daily if d >= 0}), 0),
                   "forecast": fc, "forecast_mem": fm, "spark": spark[::step][-60:], "hours": len(rs),
                   "first": rs[0]["hour"] if rs else None, "last": rs[-1]["hour"] if rs else None}
            if kind == "datastore" and rs:
                last = rs[-1]
                row["growth_gb_day"] = round(fc["slope"] / 100 * (last["disk_total"] / (last["n"] or 1)), 1) if fc["slope"] is not None and last["disk_total"] else None
            cur = row.get("cpu") if kind == "cluster" else row.get("disk")
            worst = min([x for x in (fc["days_to"].get("90"), (fm or {}).get("days_to", {}).get("90")) if x is not None], default=None)
            row["state"] = "down" if (cur or 0) >= 90 or (kind == "cluster" and (row.get("mem") or 0) >= 90) else \
                "warn" if (cur or 0) >= 80 or (kind == "cluster" and (row.get("mem") or 0) >= 80) or (worst is not None and worst <= 30) else "ok"
            out.append(row)
        res = {"generated": now, "days": days, "items": out, "sampler": dict(self.stats),
               "summary": {"clusters": sum(1 for r in out if r["kind"] == "cluster"), "datastores": sum(1 for r in out if r["kind"] == "datastore"),
                           "warn": sum(1 for r in out if r["state"] == "warn"), "down": sum(1 for r in out if r["state"] == "down"),
                           "soon": sum(1 for r in out if any((x or {}).get("days_to", {}).get("90") is not None and (x or {}).get("days_to", {}).get("90") <= 90
                                                           for x in (r["forecast"], r.get("forecast_mem"))))}}
        self._cache[key] = (now, res)
        return res

    # ------------------------------------------------------------------ VM 적정화
    async def rightsizing(self, days: int | None = None) -> dict[str, Any]:
        days = days or self.rs_days
        key = f"rs:{days}"
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
        lock = self._flight.setdefault(key, asyncio.Lock())       # 동시 요청은 1회만 계산(2.30.0)
        async with lock:
            hit = self._cache.get(key)
            if hit and time.time() - hit[0] < 300:
                return hit[1]
            return await self._rightsizing(days, key)

    # VM 단위 집계는 SQL 에서(2.30.0) — 14일·5,000 VM 이면 표본 167만 행을 파이썬으로 올리던 것을 VM 수만큼의 행으로 줄인다.
    # cluster·folder = 마지막 표본, vcpu·mem·disk = 마지막으로 켜져 있던 표본의 평균(블록당). 순서 = 처음 관측된 순(동점 정렬 유지)
    RS_SQL = """
WITH g AS (
  SELECT vc, vm, SUM(seen) AS seen, SUM(blocks) AS blocks, MIN(hour) AS first, MAX(hour) AS last,
         SUM(vcpu) AS vcpu_bh, SUM(mem) AS mem_bh, SUM(disk) AS disk_bh, SUM(vcpu_u) AS vcpu_u, SUM(mem_u) AS mem_u,
         SUM(CASE WHEN blocks THEN 1 ELSE 0 END) AS hours_on,
         MAX(CASE WHEN blocks AND vcpu THEN vcpu_u / vcpu * 100 ELSE 0.0 END) AS peak_cpu,
         MAX(CASE WHEN blocks AND mem THEN mem_u / mem * 100 ELSE 0.0 END) AS peak_mem,
         MAX(CASE WHEN blocks THEN hour END) AS last_on, MIN(rowid) AS rid0
  FROM bill_usage WHERE hour>=? GROUP BY vc, vm)
SELECT g.*, l.cluster AS cluster, l.folder AS folder,
       COALESCE(o.vcpu / o.blocks, 0.0) AS vcpu, COALESCE(o.mem / o.blocks, 0.0) AS mem, COALESCE(o.disk / o.blocks, 0.0) AS disk
FROM g JOIN bill_usage l ON l.hour = g.last AND l.vc IS g.vc AND l.vm IS g.vm
LEFT JOIN bill_usage o ON o.hour = g.last_on AND o.vc IS g.vc AND o.vm IS g.vm
ORDER BY g.first, g.rid0"""

    async def _rightsizing(self, days: int, key: str) -> dict[str, Any]:
        now = time.time()
        since = now - days * 86400
        try:
            self.e.billing._ensure()
            rows = await self.e.store.q(self.RS_SQL, (since,))
        except Exception:  # noqa: BLE001
            rows = []
        rate = None
        try:
            rates = await self.e.billing.rates()
            rate = next((r["current"] for r in rates if r["is_default"] and r.get("current")), (rates[0]["current"] if rates and rates[0].get("current") else None))
        except Exception:  # noqa: BLE001
            rate = None
        th = self.th
        agg: dict[tuple, dict] = {(r["vc"], r["vm"]): r for r in rows}
        live = {}
        for c in self.e.connectors:
            if getattr(c, "type", "") == "vcenter":
                for vn, v in ((getattr(c, "topology", {}) or {}).get("vms", {}) or {}).items():
                    live[(c.name, vn)] = v
        over, under, idle, off = [], [], [], []
        judged: list[dict] = []
        pending = 0
        for k, a in agg.items():
            v = live.get(k, {})
            vcpu = float(v.get("vcpu") or a["vcpu"] or 0)
            mem = round(float(v.get("mem_mb") or 0) / 1024, 1) if v.get("mem_mb") else round(a["mem"], 1)
            disk = float(v.get("prov_gb") or a["disk"] or 0)
            base = {"vm": a["vm"], "vcenter": a["vc"], "cluster": a["cluster"], "folder": a["folder"], "vcpu": vcpu, "mem_gb": mem, "disk_gb": round(disk, 1),
                    "os": v.get("os", ""), "power": v.get("power", ""), "hours_on": a["hours_on"], "observed_days": round(a["seen"] * 5 / 60 / 24, 1)}
            if a["blocks"] == 0:
                span_days = (a["last"] - a["first"] + 3600) / 86400                 # 꺼진 채 관측된 기간(첫~마지막 표본)
                if span_days >= th["off_days"] and v.get("power", "poweredOff") != "poweredOn":
                    off.append({**base, "off_days": round(span_days, 1), "saving": round(disk * (rate or {}).get("disk_gb_hour", 0) * 730, 0) if rate else None,
                                "why": f"{span_days:.0f}일 동안 한 번도 켜지지 않음 — 디스크 {disk:g} GB 점유", "action": "보존 필요 여부 확인 후 삭제·아카이브",
                                "confidence": "high" if span_days >= 14 else "medium"})
                continue
            if a["hours_on"] < 24:
                pending += 1
                continue                                            # 하루 미만 관측은 판단 보류
            avg_cpu = a["vcpu_u"] / a["vcpu_bh"] * 100 if a["vcpu_bh"] else 0
            avg_mem = a["mem_u"] / a["mem_bh"] * 100 if a["mem_bh"] else 0
            od = base["observed_days"]
            m = {**base, "avg_cpu": round(avg_cpu, 1), "peak_cpu": round(a["peak_cpu"], 1), "avg_mem": round(avg_mem, 1), "peak_mem": round(a["peak_mem"], 1),
                 "confidence": "high" if od >= 7 else "medium" if od >= 3 else "low"}
            judged.append({"cluster": a["cluster"], "vcpu": vcpu, "mem_gb": mem})
            used_c, used_m = vcpu * a["peak_cpu"] / 100, mem * a["peak_mem"] / 100
            if a["peak_cpu"] < th["idle_cpu"] and a["peak_mem"] < th["idle_mem"]:
                m["saving"] = round((vcpu * (rate or {}).get("vcpu_hour", 0) + mem * (rate or {}).get("mem_gb_hour", 0)) * 730, 0) if rate else None
                m["why"] = (f"켜져 있던 {a['hours_on']}시간 동안 CPU 피크 {a['peak_cpu']:.1f}%·메모리 피크 {a['peak_mem']:.1f}% — "
                            f"사용하지 않는 VM 으로 보임")
                m["action"] = "담당자 확인 후 전원 끄기 또는 삭제"
                idle.append(m)
                continue
            rc = max(2, math.ceil(vcpu * a["peak_cpu"] / 100 * th["headroom"])) if vcpu >= 4 and a["peak_cpu"] < th["over_cpu"] else None
            rm = max(2, math.ceil(mem * a["peak_mem"] / 100 * th["headroom"])) if mem >= 8 and a["peak_mem"] < th["over_mem"] else None
            if (rc is not None and rc < vcpu) or (rm is not None and rm < mem):
                m.update(rec_vcpu=rc if rc is not None and rc < vcpu else vcpu, rec_mem_gb=rm if rm is not None and rm < mem else mem)
                m["saving"] = round(((vcpu - m["rec_vcpu"]) * (rate or {}).get("vcpu_hour", 0) + (mem - m["rec_mem_gb"]) * (rate or {}).get("mem_gb_hour", 0)) * 730, 0) if rate else None
                parts = []
                if m["rec_vcpu"] < vcpu:
                    parts.append(f"CPU 피크 {a['peak_cpu']:.0f}% = vCPU {vcpu:g} 중 약 {used_c:.1f}개 사용 → ×{th['headroom']:g} 여유 = {m['rec_vcpu']:g} vCPU")
                if m["rec_mem_gb"] < mem:
                    parts.append(f"메모리 피크 {a['peak_mem']:.0f}% = {mem:g} GB 중 약 {used_m:.1f} GB 사용 → ×{th['headroom']:g} 여유 = {m['rec_mem_gb']:g} GB")
                m["why"] = " / ".join(parts)
                m["action"] = " · ".join(x for x in [f"vCPU {vcpu:g}→{m['rec_vcpu']:g}" if m["rec_vcpu"] < vcpu else "",
                                                     f"메모리 {mem:g}→{m['rec_mem_gb']:g} GB" if m["rec_mem_gb"] < mem else ""] if x) + " 축소"
                over.append(m)
            if avg_cpu >= th["under_cpu"] or avg_mem >= th["under_mem"]:
                m2 = dict(m)
                m2["rec_vcpu"] = math.ceil(vcpu * 1.5) if avg_cpu >= th["under_cpu"] else vcpu
                m2["rec_mem_gb"] = math.ceil(mem * 1.5) if avg_mem >= th["under_mem"] else mem
                m2["why"] = " · ".join(x for x in [f"평균 CPU {avg_cpu:.0f}%" if avg_cpu >= th["under_cpu"] else "", f"평균 메모리 {avg_mem:.0f}%" if avg_mem >= th["under_mem"] else ""] if x)
                m2["action"] = " · ".join(x for x in [f"vCPU {vcpu:g}→{m2['rec_vcpu']:g}" if m2["rec_vcpu"] > vcpu else "",
                                                      f"메모리 {mem:g}→{m2['rec_mem_gb']:g} GB" if m2["rec_mem_gb"] > mem else ""] if x) + " 증설"
                m2["saving"] = None
                under.append(m2)
        over.sort(key=lambda x: -(x.get("saving") or (x["vcpu"] - x.get("rec_vcpu", 0))))
        under.sort(key=lambda x: -max(x["avg_cpu"], x["avg_mem"]))
        idle.sort(key=lambda x: -(x.get("saving") or x["vcpu"]))
        off.sort(key=lambda x: -x["disk_gb"])
        flagged = {(x["vcenter"], x["vm"]) for x in over + under + idle}
        by_cl: dict[str, dict] = {}
        for j in judged:
            b = by_cl.setdefault(j["cluster"] or "-", {"cluster": j["cluster"] or "-", "vms": 0, "vcpu": 0.0, "mem_gb": 0.0, "oversized": 0, "undersized": 0, "idle": 0,
                                                       "powered_off": 0, "reclaim_vcpu": 0.0, "reclaim_mem_gb": 0.0, "add_vcpu": 0.0, "add_mem_gb": 0.0, "saving": 0.0})
            b["vms"] += 1
            b["vcpu"] += j["vcpu"]
            b["mem_gb"] += j["mem_gb"]
        for kind, lst in (("oversized", over), ("undersized", under), ("idle", idle), ("powered_off", off)):
            for x in lst:
                b = by_cl.setdefault(x["cluster"] or "-", {"cluster": x["cluster"] or "-", "vms": 0, "vcpu": 0.0, "mem_gb": 0.0, "oversized": 0, "undersized": 0, "idle": 0,
                                                           "powered_off": 0, "reclaim_vcpu": 0.0, "reclaim_mem_gb": 0.0, "add_vcpu": 0.0, "add_mem_gb": 0.0, "saving": 0.0})
                b[kind] += 1
                if kind == "oversized":
                    b["reclaim_vcpu"] += x["vcpu"] - x["rec_vcpu"]
                    b["reclaim_mem_gb"] += x["mem_gb"] - x["rec_mem_gb"]
                elif kind == "idle":
                    b["reclaim_vcpu"] += x["vcpu"]
                    b["reclaim_mem_gb"] += x["mem_gb"]
                elif kind == "undersized":
                    b["add_vcpu"] += x["rec_vcpu"] - x["vcpu"]
                    b["add_mem_gb"] += x["rec_mem_gb"] - x["mem_gb"]
                b["saving"] += x.get("saving") or 0
        clusters = sorted(({k: (round(v, 1) if isinstance(v, float) else v) for k, v in b.items()} for b in by_cl.values()),
                          key=lambda b: (-b["saving"], -b["reclaim_vcpu"], b["cluster"]))
        alloc_c, alloc_m = sum(j["vcpu"] for j in judged), sum(j["mem_gb"] for j in judged)
        rec_c = alloc_c - sum(x["vcpu"] - x["rec_vcpu"] for x in over) - sum(x["vcpu"] for x in idle) + sum(x["rec_vcpu"] - x["vcpu"] for x in under)
        rec_m = alloc_m - sum(x["mem_gb"] - x["rec_mem_gb"] for x in over) - sum(x["mem_gb"] for x in idle) + sum(x["rec_mem_gb"] - x["mem_gb"] for x in under)
        res = {"generated": now, "days": days, "thresholds": th, "rate": {k: rate.get(k) for k in ("vcpu_hour", "mem_gb_hour", "disk_gb_hour")} if rate else None,
               "currency": self.e.billing.currency if rate else None, "vms_observed": len(agg),
               "oversized": over[:500], "undersized": under[:500], "idle": idle[:500], "powered_off": off[:500],
               "summary": {"oversized": len(over), "undersized": len(under), "idle": len(idle), "powered_off": len(off),
                           "reclaim_vcpu": round(sum(x["vcpu"] - x["rec_vcpu"] for x in over) + sum(x["vcpu"] for x in idle), 1),
                           "reclaim_mem_gb": round(sum(x["mem_gb"] - x["rec_mem_gb"] for x in over) + sum(x["mem_gb"] for x in idle), 1),
                           "reclaim_disk_gb": round(sum(x["disk_gb"] for x in off), 1),
                           "saving_month": round(sum((x.get("saving") or 0) for x in over + idle + off), 0) if rate else None,
                           "judged": len(judged), "pending": pending, "ok": len(judged) - len(flagged),
                           "add_vcpu": round(sum(x["rec_vcpu"] - x["vcpu"] for x in under), 1), "add_mem_gb": round(sum(x["rec_mem_gb"] - x["mem_gb"] for x in under), 1),
                           "alloc_vcpu": round(alloc_c, 1), "alloc_mem_gb": round(alloc_m, 1), "rec_vcpu": round(rec_c, 1), "rec_mem_gb": round(rec_m, 1)},
               "clusters": clusters[:200]}
        self._cache[key] = (now, res)
        return res

    @staticmethod
    def to_csv(ov: dict, rs: dict) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["구분", "vCenter", "이름", "유형", "현재 CPU %", "현재 메모리 %", "현재 디스크 %", "CPU 증가 %/일", "CPU 80% 도달(일)", "CPU 90% 도달(일)",
                    "메모리 90% 도달(일)", "30일 뒤 CPU/디스크 %", "90일 뒤 CPU/디스크 %", "관측 일수"])
        for r in ov["items"]:
            f, fm = r["forecast"], r.get("forecast_mem") or {}
            w.writerow(["용량", r["vcenter"], r["name"], r["kind"], r.get("cpu"), r.get("mem"), r.get("disk"), f["slope"], f["days_to"].get("80"), f["days_to"].get("90"),
                        (fm.get("days_to") or {}).get("90"), f["p30"], f["p90"], r["days_observed"]])
        w.writerow([])
        w.writerow(["구분", "VM", "vCenter", "클러스터", "폴더", "vCPU", "메모리 GB", "디스크 GB", "평균 CPU %", "피크 CPU %", "평균 메모리 %", "피크 메모리 %", "권장 vCPU", "권장 메모리 GB", "월 절감 추정", "조치", "근거", "판단 신뢰도"])
        for kind, lst in (("과다", rs["oversized"]), ("과소", rs["undersized"]), ("유휴", rs["idle"]), ("장기 꺼짐", rs["powered_off"])):
            for x in lst:
                w.writerow([kind, x["vm"], x["vcenter"], x["cluster"], x["folder"], x["vcpu"], x["mem_gb"], x["disk_gb"], x.get("avg_cpu"), x.get("peak_cpu"), x.get("avg_mem"),
                            x.get("peak_mem"), x.get("rec_vcpu"), x.get("rec_mem_gb"), x.get("saving"), x.get("action", ""), x.get("why", ""),
                            {"high": "높음", "medium": "보통", "low": "낮음"}.get(x.get("confidence", ""), "")])
        return "﻿" + buf.getvalue()
