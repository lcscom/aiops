"""호스트·VM 성능 상세(2.23.0) — 성능·용량 › 호스트·VM 성능.

  목록   vCenter 토폴로지(1~5분 주기 수집) — 호스트·VM 이름·클러스터·전원·vCPU·메모리·CPU/메모리 사용(quickStats)
  순위   지금(최근 1분 실시간 표본) CPU·메모리·디스크 IOPS·디스크 지연·디스크 처리량·네트워크·CPU ready — 60초 캐시
  상세   한 대의 CPU(사용률·MHz·ready·co-stop)·메모리(사용률·active·consumed·balloon·swap·compressed·latency)·
         디스크(IOPS·처리량·지연, 가상 디스크/장치별)·네트워크(수신·송신·패킷·드롭, vNIC/vmnic별) —
         실시간 1시간(20초) · 24시간(5분) · 7일(30분) · 30일(2시간)
모두 읽기 전용(PerformanceManager.QueryPerf).
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from . import perfcalc, perfdiag

METRICS = ("cpu_pct", "mem_pct", "iops", "disk_lat_ms", "disk_Bps", "net_bps", "ready_pct")


class PerfView:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        cfg = cfg or {}
        self.max_vms = int(cfg.get("max_vms", 3000))
        self.top_ttl = float(cfg.get("top_ttl", 60))
        self._top: dict[tuple, tuple[float, Any]] = {}
        self._det: dict[tuple, tuple[float, Any]] = {}
        self._locks: dict[tuple, asyncio.Lock] = {}

    def vcenters(self) -> list:
        return [c for c in self.e.connectors if c.type == "vcenter" and getattr(c, "enabled", True) and hasattr(c, "perf_series")]

    # ------------------------------------------------------------------ 목록
    def entities(self, kind: str) -> list[dict]:
        out = []
        for c in self.vcenters():
            t = getattr(c, "topology", None) or {}
            hosts = t.get("hosts") or {}
            if kind == "host":
                for n, h in hosts.items():
                    cap, used = h.get("cpu_mhz") or 0, h.get("cpu_used_mhz") or 0
                    out.append({"kind": "host", "name": n, "vcenter": c.name, "moid": h.get("moid", ""), "cluster": h.get("cluster", ""),
                                "state": h.get("conn", ""), "maintenance": bool(h.get("maintenance")), "vms": h.get("vms", 0),
                                "cpu_pct": round(used * 100 / cap, 1) if cap else None, "mem_pct": round((h.get("mem_used_mb") or 0) * 100 / h["mem_mb"], 1) if h.get("mem_mb") else None,
                                "cpu_mhz": cap, "mem_mb": h.get("mem_mb", 0)})
            else:
                for n, v in (t.get("vms") or {}).items():
                    core = (hosts.get(v.get("host", "")) or {}).get("core_mhz") or 0
                    vcpu = v.get("vcpu") or 1
                    on = v.get("power") == "poweredOn"
                    out.append({"kind": "vm", "name": n, "vcenter": c.name, "moid": v.get("moid", ""), "cluster": v.get("cluster", ""),
                                "host": v.get("host", ""), "state": v.get("power", ""), "vcpu": vcpu, "mem_mb": v.get("mem_mb", 0),
                                "cpu_pct": round((v.get("cpu_mhz") or 0) * 100 / (core * vcpu), 1) if on and core else None,
                                "mem_pct": round((v.get("mem_used_mb") or 0) * 100 / v["mem_mb"], 1) if on and v.get("mem_mb") else None,
                                "os": v.get("os", ""), "ips": (v.get("ips") or [])[:3]})
        return out

    def find(self, kind: str, name: str, vcenter: str = "") -> tuple[Any, dict] | tuple[None, None]:
        for c in self.vcenters():
            if vcenter and c.name != vcenter:
                continue
            t = getattr(c, "topology", None) or {}
            d = (t.get("hosts") if kind == "host" else t.get("vms")) or {}
            if name in d:
                return c, d[name]
        return None, None

    # ------------------------------------------------------------------ 순위
    async def top(self, kind: str, fresh: bool = False) -> dict:
        key = (kind,)
        hit = self._top.get(key)
        age = time.time() - hit[0] if hit else 1e9
        if hit and (age < (30 if fresh else self.top_ttl)):         # 다시 측정은 30초에 한 번까지(연타·여러 사용자)
            return hit[1]
        lock = self._locks.setdefault(("top",) + key, asyncio.Lock())
        async with lock:
            hit = self._top.get(key)
            if hit and time.time() - hit[0] < 30:                   # 기다리는 동안 다른 요청이 측정함
                return hit[1]
            ents = self.entities(kind)
            vals: dict[tuple[str, str], dict] = {}
            errs = []
            for c in self.vcenters():
                if kind == "vm":
                    items = [(e["name"], e["moid"], e["vcpu"]) for e in ents if e["vcenter"] == c.name and e["state"] == "poweredOn" and e["moid"]][:self.max_vms]
                else:
                    items = [(e["name"], e["moid"], 1) for e in ents if e["vcenter"] == c.name and e["state"] == "connected" and e["moid"]]
                if not items:
                    continue
                try:
                    r = await asyncio.wait_for(asyncio.to_thread(c.perf_latest, kind, items), 180)
                except Exception as ex:  # noqa: BLE001
                    errs.append(f"{c.name}: {type(ex).__name__}")
                    continue
                if getattr(c, "perf_latest_errors", 0):
                    errs.append(f"{c.name}: {c.perf_latest_errors}대 조회 실패")
                for n, m in r.items():
                    vals[(c.name, n)] = m
            rows = []
            for e in ents:
                m = vals.get((e["vcenter"], e["name"]))
                if m:
                    rows.append({**e, "now": {k: (round(v, 2) if isinstance(v, float) else v) for k, v in m.items()}})
            res = {"kind": kind, "ts": time.time(), "rows": rows, "errors": errs, "measured": len(rows), "total": len(ents)}
            self._top[key] = (time.time(), res)
            return res

    # ------------------------------------------------------------------ 상세
    async def detail(self, kind: str, name: str, vcenter: str = "", rng: str = "rt", fresh: bool = False) -> dict:
        if rng not in ("rt", "1d", "7d", "30d", "s3d", "h6w"):
            rng = "rt"
        c, ent = self.find(kind, name, vcenter)
        if c is None:
            raise KeyError(name)
        key = (kind, c.name, name, rng)
        hit = self._det.get(key)
        ttl = 20 if rng == "rt" else 300
        if hit and time.time() - hit[0] < (min(ttl, 10) if fresh else ttl):
            return hit[1]
        lock = self._locks.setdefault(("det",) + key, asyncio.Lock())
        async with lock:
            hit = self._det.get(key)
            if hit and time.time() - hit[0] < (min(ttl, 10) if fresh else ttl):
                return hit[1]
            t = getattr(c, "topology", None) or {}
            labels = self._labels(kind, ent, t)
            vcpu = int(ent.get("vcpu") or 1) if kind == "vm" else 1
            pw = getattr(self, "watch", None)
            eid = pw.store.find(kind, name, c.name) if pw else None
            if rng in ("s3d", "h6w"):                                # 2.25.0 자체 이력(통계 수준과 무관하게 ready·지연 포함)
                r = await self._stored(pw, eid, rng)
            else:
                try:
                    r = await asyncio.wait_for(asyncio.to_thread(c.perf_series, kind, ent.get("moid", ""), rng, vcpu, labels), 120)
                except Exception as ex:  # noqa: BLE001
                    r = {"ts": [], "series": {}, "instances": {}, "interval": 0, "missing": [], "error": f"{type(ex).__name__}: {str(ex)[:120]}"}
            if pw and eid and r.get("ts") and rng != "h6w":           # 정상 범위 밴드(시간대별 중앙값 ± 3×강건 sd)
                bands = {}
                for m, sname in (("cpu", "cpu.usage_pct"), ("mem", "mem.usage_pct"), ("lat", "disk.max_lat_ms"), ("nbps", "net.usage_bps"), ("rdy", "cpu.ready_pct")):
                    if kind == "host" and m == "rdy":
                        continue
                    try:
                        b = await pw.band_series(eid, m, r["ts"])
                    except Exception:  # noqa: BLE001
                        continue
                    if b.get("lo"):
                        bands[sname] = b
                r["bands"] = bands
            if pw and eid and r.get("ts"):
                try:
                    r["alerts"] = [a for a in await pw.history((time.time() - r["ts"][0]) / 3600 + 1, eid) if (a.get("end") or time.time()) >= r["ts"][0]][:100]
                except Exception:  # noqa: BLE001
                    r["alerts"] = []
            info = self._info(kind, name, ent, t, c)
            res = {"kind": kind, "name": name, "vcenter": c.name, "range": rng, "info": info, **r,
                   "summary": perfcalc.summarize(r.get("series") or {}), "fetched": time.time()}
            if rng == "rt" and r.get("ts"):                         # 2.24.0 자동 진단(최근 24시간 기준선·같은 호스트 VM)
                try:
                    day = await self.detail(kind, name, c.name, "1d")
                except Exception:  # noqa: BLE001
                    day = None
                h = (t.get("hosts") or {}).get(ent.get("host", "") if kind == "vm" else name) or {}
                res["diag"] = perfdiag.diagnose(kind, res, day, {**info, "_self": name, "host_cpu_used_mhz": h.get("cpu_used_mhz")},
                                                self._neighbors(kind, name, ent, t))
            if r.get("ts") and not r.get("error"):                   # 오류·빈 결과는 캐시하지 않음(일시 끊김 뒤 바로 다시 시도)
                self._det[key] = (time.time(), res)
            if len(self._det) > 300:
                for k in sorted(self._det, key=lambda k: self._det[k][0])[:100]:
                    self._det.pop(k, None)
                    lk = self._locks.get(("det",) + k)
                    if lk is not None and not lk.locked():
                        self._locks.pop(("det",) + k, None)
            return res

    @staticmethod
    async def _stored(pw, eid: int | None, rng: str) -> dict:
        if not pw or not eid:
            return {"ts": [], "series": {}, "instances": {}, "interval": 0, "missing": [], "error": "자체 이력이 아직 없습니다(성능 감시 수집 대기 — 5분 간격)"}
        table, span, iv = ("s5", pw.store.ret5 * 86400, pw.store.interval) if rng == "s3d" else ("h1", pw.store.ret1 * 86400, 3600)
        d = await asyncio.to_thread(pw.store.series, eid, table, time.time() - span)
        names = {"cpu": "cpu.usage_pct", "mem": "mem.usage_pct", "rdy": "cpu.ready_pct", "iops": "disk.iops", "lat": "disk.max_lat_ms",
                 "dbps": "disk.usage_Bps", "nbps": "net.usage_bps"}
        series = {v: d.get(k) or [] for k, v in names.items() if any(x is not None for x in d.get(k) or [])}
        if table == "h1":
            series.update({v + "_max": d.get(k + "_max") or [] for k, v in names.items() if any(x is not None for x in d.get(k + "_max") or [])})
        return {"ts": d["ts"], "series": series, "instances": {}, "interval": iv, "missing": [], "source": "store",
                "error": "" if d["ts"] else "이 기간의 자체 이력이 없습니다"}

    @staticmethod
    def _neighbors(kind: str, name: str, ent: dict, t: dict) -> list[dict]:
        host = ent.get("host", "") if kind == "vm" else name
        vms = [{"name": n, "cpu_mhz": v.get("cpu_mhz") or 0, "mem_used_mb": v.get("mem_used_mb") or 0}
               for n, v in (t.get("vms") or {}).items() if host and v.get("host") == host and v.get("power") == "poweredOn"]
        return sorted(vms, key=lambda v: -v["cpu_mhz"])[:20]

    async def explain(self, kind: str, name: str, vcenter: str = "") -> str:
        d = await self.detail(kind, name, vcenter, "rt")
        if not d.get("ts"):
            raise ValueError(d.get("error") or "실시간 통계가 없어 해설할 수 없습니다")
        diag = d.get("diag") or {"findings": [], "baseline": {}}
        dg = perfdiag.digest(kind, name, d, diag, d.get("info") or {})
        nb = [{"name": n} for n in diag.get("neighbors") or []]          # 진단에 쓴 이웃 목록 그대로(시점 차이로 가명이 빠지지 않게)
        info = d.get("info") or {}
        inst_labels = {str(r.get("label") or "") for g in (d.get("instances") or {}).values() for r in g if r.get("label") and "Mbps" not in str(r.get("label"))}
        names = sorted(({name, str(info.get("host") or ""), str(info.get("cluster") or "")} | {v["name"] for v in nb} | inst_labels |
                        {str(x) for x in (info.get("datastores") or [])} | {str(x) for x in (info.get("networks") or [])} |
                        {str(v.get("name")) for v in (info.get("vms") or [])}) - {""})   # 외부 AI 에는 가명으로
        system = ("너는 VMware vSphere 성능 분석 전문가다. 아래는 " + ("VM" if kind == "vm" else "ESXi 호스트") + " 한 대의 vCenter 성능 카운터 요약"
                  "(최근 1시간 실시간 20초 간격, 단위: %, MB, ms, B/s, bit/s)과 규칙 기반 자동 진단·24시간 평소 대비 값이다. 한국어로 "
                  "① 지금 상태 한 줄 요약 ② 문제 가능성이 큰 순서로 원인 추정(근거 수치 인용) ③ 확인 순서(읽기 전용 먼저: esxtop c/m/d/u/n 화면의 항목, "
                  "vCenter 성능 차트, 게스트 OS 도구) ④ 개선 방안(vCPU·메모리 조정, DRS·스토리지·네트워크)을 간결한 목록으로 써라. "
                  "데이터에 없는 것은 지어내지 말고 '확인 필요'라고 써라. 문제가 없으면 없다고 짧게 말하라.")
        return await self.e.llm.complete(system, json.dumps(dg, ensure_ascii=False, default=str), max_tokens=1400, task="report", names=names)

    @staticmethod
    def _labels(kind: str, ent: dict, t: dict) -> dict[str, str]:
        lab: dict[str, str] = {}
        if kind == "host":
            for dn, d in (t.get("datastores") or {}).items():          # 장치(naa.…) → 데이터스토어 이름
                for x in d.get("extents") or []:
                    lab[f"disk:{x}"] = dn
            for p in ent.get("pnics") or []:
                if isinstance(p, dict) and p.get("name"):
                    lab[f"net:{p['name']}"] = f"{p['speed']:,} Mbps" if p.get("speed") else "링크 다운"
        return lab

    @staticmethod
    def _info(kind: str, name: str, ent: dict, t: dict, c) -> dict:
        if kind == "host":
            vms = sorted(((n, v) for n, v in (t.get("vms") or {}).items() if v.get("host") == name), key=lambda x: -(x[1].get("cpu_mhz") or 0))
            return {"cluster": ent.get("cluster", ""), "state": ent.get("conn", ""), "maintenance": bool(ent.get("maintenance")),
                    "cpu_mhz": ent.get("cpu_mhz", 0), "core_mhz": ent.get("core_mhz", 0), "mem_mb": ent.get("mem_mb", 0),
                    "cpu_used_mhz": ent.get("cpu_used_mhz", 0), "mem_used_mb": ent.get("mem_used_mb", 0), "version": ent.get("esx_version", ""),
                    "model": " ".join(x for x in (ent.get("hw_vendor", ""), ent.get("hw_model", "")) if x), "datastores": (ent.get("datastores") or [])[:20],
                    "vms_total": len(vms),
                    "vms": [{"name": n, "power": v.get("power", ""), "vcpu": v.get("vcpu", 1), "mem_mb": v.get("mem_mb", 0),
                             "cpu_mhz": v.get("cpu_mhz", 0), "mem_used_mb": v.get("mem_used_mb", 0)} for n, v in vms[:30]]}
        h = (t.get("hosts") or {}).get(ent.get("host", "")) or {}
        return {"host_cpu_pct": round((h.get("cpu_used_mhz") or 0) * 100 / h["cpu_mhz"], 1) if h.get("cpu_mhz") else None,
                "cluster": ent.get("cluster", ""), "host": ent.get("host", ""), "state": ent.get("power", ""), "vcpu": ent.get("vcpu", 1),
                "mem_mb": ent.get("mem_mb", 0), "os": ent.get("os", ""), "ips": (ent.get("ips") or [])[:6], "tools": ent.get("tools", ""),
                "datastores": (ent.get("datastores") or [])[:10], "networks": (ent.get("networks") or [])[:8], "hw": ent.get("hw", ""),
                "cpu_mhz": ent.get("cpu_mhz", 0), "mem_used_mb": ent.get("mem_used_mb", 0), "host_core_mhz": h.get("core_mhz", 0),
                "snapshots": ent.get("snapshots", 0)}

    def csv(self, d: dict) -> str:
        import csv
        import io
        buf = io.StringIO()
        cols = sorted((d.get("series") or {}).keys())
        w = csv.writer(buf)
        w.writerow(["time"] + cols)
        for i, ts in enumerate(d.get("ts") or []):
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))] +
                       [("" if (d["series"][k][i] if i < len(d["series"][k]) else None) is None else round(d["series"][k][i], 3)) for k in cols])
        return "﻿" + buf.getvalue()
