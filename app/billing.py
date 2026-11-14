"""VM 사용량 정산(Billing) — vCenter 인벤토리를 5분마다 표본으로 남기고, 테넌트·프로젝트·요율표로 기간 비용을 계산한다.

설계(독자 구현 — 공개 저장소 postout7979/vcf-billing 의 개념을 참고, 코드·데이터는 가져오지 않음)
  · 표본: 5분 블록마다 VM 의 전원·vCPU·메모리(GB)·할당 디스크(GB)·CPU/메모리 사용률(quickStats) — 읽기 전용 vCenter 계정으로 충분
          저장은 VM·시간(1시간) 단위 누적(bill_usage): 켜짐 블록 수, Σ vCPU, Σ 메모리, Σ 디스크, Σ vCPU×CPU%, Σ 메모리×메모리%,
          꺼짐 블록의 Σ 디스크 → 5분 정산과 같은 결과를 1/12 행 수로 보관(기본 400일)
  · 비용(켜짐 5분 블록마다): (vCPU×vCPU 단가 + 메모리GB×GB 단가 + 디스크GB×GB 단가) × 5/60
          꺼진 블록은 과금하지 않음(요율표 bill_disk_when_off 를 켜면 디스크만 과금)
          사용률 가중(선택, vCPU·메모리만): 가중치 = 최소 가중치 + (1 − 최소 가중치) × 사용률/100
  · 요율 버전: 요율을 바꾸면 적용 시작 시각과 함께 새 버전이 쌓이고, 각 시간 행은 그 시각에 유효한 버전으로 계산(소급 없음)
  · 프로젝트 매칭(OR): VM 이름 지정 > 태그 > 폴더(경로 접두, 가장 긴 경로) > 클러스터, 같은 순위면 프로젝트 id 가 작은 쪽
          시간 행마다 그 시각의 클러스터·폴더·태그로 매칭(이동·태그 변경 이력 반영) — 어디에도 안 맞으면 '미할당'
  · 테넌트 사용자: 테넌트에 계정을 지정하면 그 계정(관리자 제외)은 자기 테넌트 보고서만 조회
"""
from __future__ import annotations

import asyncio
import calendar
import csv
import html
import io
import json
import time
from datetime import datetime
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS bill_usage(
  hour INTEGER, vc TEXT, vm TEXT, moid TEXT, cluster TEXT, folder TEXT, tags TEXT,
  seen INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, vcpu REAL DEFAULT 0, mem REAL DEFAULT 0, disk REAL DEFAULT 0,
  vcpu_u REAL DEFAULT 0, mem_u REAL DEFAULT 0, disk_off REAL DEFAULT 0, PRIMARY KEY(hour, vc, vm));
CREATE INDEX IF NOT EXISTS ix_bill_usage_hour ON bill_usage(hour);
CREATE TABLE IF NOT EXISTS bill_tenants(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, note TEXT, rate_id INTEGER, users TEXT, created REAL);
CREATE TABLE IF NOT EXISTS bill_projects(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER, name TEXT, note TEXT, rate_id INTEGER,
  clusters TEXT, folders TEXT, tags TEXT, vms TEXT, created REAL);
CREATE TABLE IF NOT EXISTS bill_rates(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, currency TEXT, is_default INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS bill_rate_ver(id INTEGER PRIMARY KEY AUTOINCREMENT, rate_id INTEGER, effective_from REAL, vcpu_hour REAL, mem_gb_hour REAL,
  disk_gb_hour REAL, weighting INTEGER, min_weight REAL, disk_when_off INTEGER, user TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_bill_rate_ver ON bill_rate_ver(rate_id, effective_from);
"""
BLOCK = 300


def _j(v, d):
    try:
        return json.loads(v) if v else d
    except (TypeError, ValueError):
        return d


def _clean_list(v) -> list[str]:
    if isinstance(v, str):
        v = [x for x in v.replace("\r", "").split("\n")]
    return sorted({str(x).strip()[:300] for x in (v or []) if str(x).strip()})[:500]


def period_range(period: str = "mtd", month: str = "", start: str = "", end: str = "", now: float | None = None) -> tuple[float, float, str]:
    """기간 → (시작, 끝, 표시) — 7d | 30d | mtd(이번 달 1일~지금) | month(YYYY-MM) | custom(YYYY-MM-DD ~ YYYY-MM-DD, 끝 날 포함)"""
    now = now or time.time()
    lt = time.localtime(now)
    if period == "7d":
        return now - 7 * 86400, now, "최근 7일"
    if period == "30d":
        return now - 30 * 86400, now, "최근 30일"
    if period == "month" and month:
        y, m = (int(x) for x in month.split("-")[:2])
        s = time.mktime((y, m, 1, 0, 0, 0, 0, 0, -1))
        e = time.mktime((y, m, calendar.monthrange(y, m)[1], 0, 0, 0, 0, 0, -1)) + 86400
        return s, min(e, now), f"{y}년 {m}월"
    if period == "custom" and start and end:
        s = time.mktime(time.strptime(start[:10], "%Y-%m-%d"))
        e = time.mktime(time.strptime(end[:10], "%Y-%m-%d")) + 86400
        if e <= s:
            raise ValueError("끝 날짜가 시작 날짜보다 빠릅니다")
        return s, min(e, now), f"{start[:10]} ~ {end[:10]}"
    s = time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))
    return s, now, f"{lt.tm_year}년 {lt.tm_mon}월(오늘까지)"


class Matcher:
    """프로젝트 매칭 — VM 이름 > 태그 > 폴더(가장 긴 접두) > 클러스터, 동순위는 낮은 프로젝트 id"""

    def __init__(self, projects: list[dict]):
        self.p = sorted(projects, key=lambda x: x["id"])
        self.cache: dict[tuple, tuple[int | None, str]] = {}

    def match(self, vm: str, cluster: str, folder: str, tags: list[str]) -> tuple[int | None, str]:
        key = (vm, cluster, folder, tuple(tags))
        if key in self.cache:
            return self.cache[key]
        best: tuple[int, int, int] | None = None              # (순위, -폴더 길이, id)
        how = ""
        tl = {t.lower() for t in tags} | {t.split(":", 1)[-1].lower() for t in tags}
        fl = (folder or "").lower().rstrip("/")
        for p in self.p:
            cand = []
            if vm.lower() in {x.lower() for x in p["vms"]}:
                cand.append(((0, 0, p["id"]), "VM"))
            if any(t.lower() in tl for t in p["tags"]):
                cand.append(((1, 0, p["id"]), "태그"))
            for f in p["folders"]:
                f0 = f.lower().rstrip("/")
                if f0 and (fl == f0 or fl.startswith(f0 + "/")):
                    cand.append(((2, -len(f0), p["id"]), "폴더"))
            if cluster and cluster.lower() in {x.lower() for x in p["clusters"]}:
                cand.append(((3, 0, p["id"]), "클러스터"))
            for k, h in cand:
                if best is None or k < best:
                    best, how = k, h
        out = (best[2], how) if best else (None, "")
        if len(self.cache) > 50000:
            self.cache.clear()
        self.cache[key] = out
        return out


class Billing:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.enabled = bool(c.get("enabled", True))
        self.retention_days = int(c.get("retention_days", 400))
        self.currency = str(c.get("currency", "KRW"))
        self._schema = False
        self._last_block = 0
        self.stats: dict[str, Any] = {"last_sample": 0, "vms": 0, "rows": 0, "error": ""}

    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    # ------------------------------------------------------------------ 표본 수집
    def snapshot_rows(self, now: float | None = None) -> list[tuple]:
        """현재 vCenter 인벤토리 → 시간 행 증분(5분 블록 1개)"""
        now = now or time.time()
        hour = int(now // 3600 * 3600)
        rows = []
        for c in self.e.connectors:
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
                continue
            t = getattr(c, "topology", {}) or {}
            if not t.get("updated"):
                continue
            hosts = t.get("hosts", {}) or {}
            for vn, v in (t.get("vms", {}) or {}).items():
                on = v.get("power") == "poweredOn"
                vcpu = float(v.get("vcpu") or 0)
                mem = round(float(v.get("mem_mb") or 0) / 1024, 3)
                disk = float(v.get("prov_gb") or v.get("disk_gb") or 0)
                core = float((hosts.get(v.get("host", "")) or {}).get("core_mhz") or 0)
                cpu_pct = min(100.0, float(v.get("cpu_mhz") or 0) / (vcpu * core) * 100) if on and vcpu and core else 0.0
                mem_pct = min(100.0, float(v.get("mem_used_mb") or 0) / float(v.get("mem_mb") or 1) * 100) if on and v.get("mem_mb") else 0.0
                rows.append((hour, c.name, vn, v.get("moid", ""), v.get("cluster", ""), v.get("folder", ""), json.dumps(v.get("tags") or [], ensure_ascii=False),
                             1, 1 if on else 0, vcpu if on else 0, mem if on else 0, disk if on else 0,
                             vcpu * cpu_pct / 100 if on else 0, mem * mem_pct / 100 if on else 0, 0 if on else disk))
        return rows

    async def sample(self, now: float | None = None) -> int:
        now = now or time.time()
        blk = int(now // BLOCK)
        if blk == self._last_block:
            return 0
        self._ensure()
        rows = self.snapshot_rows(now)
        await self.e.store.xm(
            "INSERT INTO bill_usage(hour,vc,vm,moid,cluster,folder,tags,seen,blocks,vcpu,mem,disk,vcpu_u,mem_u,disk_off) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(hour,vc,vm) DO UPDATE SET moid=excluded.moid, cluster=excluded.cluster, folder=excluded.folder, tags=excluded.tags, "
            "seen=seen+1, blocks=blocks+excluded.blocks, vcpu=vcpu+excluded.vcpu, mem=mem+excluded.mem, disk=disk+excluded.disk, "
            "vcpu_u=vcpu_u+excluded.vcpu_u, mem_u=mem_u+excluded.mem_u, disk_off=disk_off+excluded.disk_off", rows)
        self._last_block = blk
        self.stats.update(last_sample=now, vms=len(rows), error="")
        return len(rows)

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(20)
        last_purge = 0.0
        while True:
            beat()
            if self.enabled:
                try:
                    await self.sample()
                    if time.time() - last_purge > 86400:
                        last_purge = time.time()
                        await self.e.store.x("DELETE FROM bill_usage WHERE hour < ?", (time.time() - self.retention_days * 86400,))
                except Exception as e:  # noqa: BLE001
                    self.stats["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(BLOCK - (time.time() % BLOCK) + 2)

    # ------------------------------------------------------------------ 테넌트·프로젝트·요율
    async def tenants(self) -> list[dict]:
        self._ensure()
        ts = await self.e.store.q("SELECT * FROM bill_tenants ORDER BY name")
        ps = await self.projects()
        for t in ts:
            t["users"] = _j(t.get("users"), [])
            t["projects"] = [p for p in ps if p["tenant_id"] == t["id"]]
        return ts

    async def projects(self) -> list[dict]:
        self._ensure()
        out = await self.e.store.q("SELECT * FROM bill_projects ORDER BY id")
        for p in out:
            for k in ("clusters", "folders", "tags", "vms"):
                p[k] = _j(p.get(k), [])
        return out

    async def save_tenant(self, d: dict, tid: int | None = None) -> int:
        self._ensure()
        name = str(d.get("name") or "").strip()[:100]
        if not name:
            raise ValueError("테넌트 이름이 필요합니다")
        users = json.dumps(_clean_list(d.get("users")), ensure_ascii=False)
        rate = int(d["rate_id"]) if d.get("rate_id") not in (None, "", 0, "0") else None
        if tid:
            await self.e.store.x("UPDATE bill_tenants SET name=?, note=?, rate_id=?, users=? WHERE id=?", (name, str(d.get("note") or "")[:500], rate, users, tid))
            return tid
        return await self.e.store.x("INSERT INTO bill_tenants(name,note,rate_id,users,created) VALUES(?,?,?,?,?)",
                                    (name, str(d.get("note") or "")[:500], rate, users, time.time()))

    async def delete_tenant(self, tid: int) -> None:
        self._ensure()
        await self.e.store.x("DELETE FROM bill_projects WHERE tenant_id=?", (tid,))
        await self.e.store.x("DELETE FROM bill_tenants WHERE id=?", (tid,))

    async def save_project(self, d: dict, pid: int | None = None) -> int:
        self._ensure()
        name = str(d.get("name") or "").strip()[:100]
        tid = int(d.get("tenant_id") or 0)
        if not name or not tid:
            raise ValueError("프로젝트 이름과 테넌트가 필요합니다")
        if not await self.e.store.q1("SELECT id FROM bill_tenants WHERE id=?", (tid,)):
            raise ValueError("테넌트가 없습니다")
        vals = [json.dumps(_clean_list(d.get(k)), ensure_ascii=False) for k in ("clusters", "folders", "tags", "vms")]
        if not any(_j(v, []) for v in vals):
            raise ValueError("클러스터·폴더·태그·VM 중 하나 이상 지정하세요")
        rate = int(d["rate_id"]) if d.get("rate_id") not in (None, "", 0, "0") else None
        if pid:
            await self.e.store.x("UPDATE bill_projects SET tenant_id=?, name=?, note=?, rate_id=?, clusters=?, folders=?, tags=?, vms=? WHERE id=?",
                                 (tid, name, str(d.get("note") or "")[:500], rate, *vals, pid))
            return pid
        return await self.e.store.x("INSERT INTO bill_projects(tenant_id,name,note,rate_id,clusters,folders,tags,vms,created) VALUES(?,?,?,?,?,?,?,?,?)",
                                    (tid, name, str(d.get("note") or "")[:500], rate, *vals, time.time()))

    async def delete_project(self, pid: int) -> None:
        self._ensure()
        await self.e.store.x("DELETE FROM bill_projects WHERE id=?", (pid,))

    async def rates(self) -> list[dict]:
        self._ensure()
        rs = await self.e.store.q("SELECT * FROM bill_rates ORDER BY id")
        vers = await self.e.store.q("SELECT * FROM bill_rate_ver ORDER BY rate_id, effective_from")
        for r in rs:
            r["versions"] = [v for v in vers if v["rate_id"] == r["id"]]
            r["current"] = next((v for v in reversed(r["versions"]) if v["effective_from"] <= time.time()), r["versions"][0] if r["versions"] else None)
        return rs

    async def save_rate(self, d: dict, user: str, rid: int | None = None) -> int:
        self._ensure()
        name = str(d.get("name") or "").strip()[:100]
        if not name:
            raise ValueError("요율표 이름이 필요합니다")
        try:
            vals = [float(d.get(k) or 0) for k in ("vcpu_hour", "mem_gb_hour", "disk_gb_hour")]
            mw = float(d.get("min_weight") if d.get("min_weight") not in (None, "") else 30)
        except (TypeError, ValueError) as e:
            raise ValueError("단가는 숫자여야 합니다") from e
        if any(v < 0 for v in vals) or not 0 <= mw <= 100:
            raise ValueError("단가는 0 이상, 최소 가중치는 0~100(%)")
        ef = d.get("effective_from")
        if isinstance(ef, str) and "-" in ef:
            eff = time.mktime(time.strptime(ef[:10], "%Y-%m-%d"))
        elif ef not in (None, "", 0, "0"):
            eff = float(ef)
        else:
            eff = 0.0 if not rid else time.time()          # 새 요율표의 첫 버전은 지난 사용량에도 적용, 수정은 지금부터
        cur = str(d.get("currency") or self.currency)[:8]
        if rid:
            await self.e.store.x("UPDATE bill_rates SET name=?, currency=? WHERE id=?", (name, cur, rid))
        else:
            rid = await self.e.store.x("INSERT INTO bill_rates(name,currency,is_default,created) VALUES(?,?,0,?)", (name, cur, time.time()))
        if d.get("is_default"):
            await self.e.store.x("UPDATE bill_rates SET is_default=CASE WHEN id=? THEN 1 ELSE 0 END", (rid,))
        await self.e.store.x("INSERT INTO bill_rate_ver(rate_id,effective_from,vcpu_hour,mem_gb_hour,disk_gb_hour,weighting,min_weight,disk_when_off,user,ts) "
                             "VALUES(?,?,?,?,?,?,?,?,?,?)", (rid, eff, *vals, 1 if d.get("weighting") else 0, mw, 1 if d.get("disk_when_off") else 0, user, time.time()))
        return rid

    async def delete_rate(self, rid: int) -> None:
        self._ensure()
        if await self.e.store.q1("SELECT id FROM bill_projects WHERE rate_id=? UNION SELECT id FROM bill_tenants WHERE rate_id=?", (rid, rid)):
            raise ValueError("이 요율표를 쓰는 테넌트·프로젝트가 있습니다")
        await self.e.store.x("DELETE FROM bill_rate_ver WHERE rate_id=?", (rid,))
        await self.e.store.x("DELETE FROM bill_rates WHERE id=?", (rid,))

    async def inventory_choices(self) -> dict[str, list[str]]:
        """매칭 입력 도우미 — 현재 인벤토리의 클러스터·폴더·태그(최근 표본 포함)"""
        cl, fo, tg = set(), set(), set()
        for c in self.e.connectors:
            if getattr(c, "type", "") == "vcenter":
                for v in ((getattr(c, "topology", {}) or {}).get("vms", {}) or {}).values():
                    if v.get("cluster"):
                        cl.add(v["cluster"])
                    f = v.get("folder") or ""
                    while f:
                        fo.add(f)
                        f = f.rsplit("/", 1)[0] if "/" in f else ""
                    tg.update(v.get("tags") or [])
        return {"clusters": sorted(cl), "folders": sorted(fo), "tags": sorted(tg)}

    # ------------------------------------------------------------------ 보고서
    async def report(self, start: float, end: float, label: str = "", tenant_ids: set[int] | None = None, vm_detail: bool = True) -> dict[str, Any]:
        self._ensure()
        h_from = int(start // 3600 * 3600)
        rates = {r["id"]: r for r in await self.rates()}
        # 2.30.0 표본을 행 단위로 올리지 않고 SQL 에서 VM·매칭 속성(클러스터·폴더·태그)·요율 적용 구간별로 합산 — 금액은 표본 합에 선형이라 결과 동일.
        # seg = 그 시각까지 지난 요율 개정(effective_from) 수 → 한 묶음 안에서는 적용 요율 버전이 같다. 먼저 나온 표본부터(h0 순) 처리.
        cuts = sorted({x["effective_from"] for r in rates.values() for x in r["versions"] if h_from < x["effective_from"] < end})[:900]
        seg = " + ".join("(hour>=?)" for _ in cuts) or "0"
        rows = await self.e.store.q(
            "SELECT vc, vm, cluster, folder, tags, MIN(hour) AS h0, MAX(hour) AS hour, SUM(seen) AS seen, SUM(blocks) AS blocks, SUM(vcpu) AS vcpu, "
            "SUM(mem) AS mem, SUM(disk) AS disk, SUM(vcpu_u) AS vcpu_u, SUM(mem_u) AS mem_u, SUM(disk_off) AS disk_off, "
            f"json_array(vc, vm, cluster, folder, tags) AS gk, {seg} AS seg FROM bill_usage WHERE hour>=? AND hour<? "
            "GROUP BY vc, vm, cluster, folder, tags, seg ORDER BY h0, MIN(rowid)", (*cuts, h_from, end))
        default_rate = next((r["id"] for r in rates.values() if r["is_default"]), None)
        tenants = await self.tenants()
        tmap = {t["id"]: t for t in tenants}
        projects = [p for t in tenants for p in t["projects"]]
        pmap = {p["id"]: p for p in projects}
        M = Matcher(projects)

        def ver_at(rid, hour):
            r = rates.get(rid)
            if not r or not r["versions"]:
                return None
            v = None
            for x in r["versions"]:
                if x["effective_from"] <= hour:
                    v = x
            return v or r["versions"][0]

        agg: dict[tuple, dict] = {}
        cover = {"first": None, "last": None, "hours": set()}
        kept: set[str] = set()
        dropped = False
        for r in rows:
            tags = _j(r["tags"], [])
            pid, how = M.match(r["vm"], r["cluster"] or "", r["folder"] or "", tags)
            p = pmap.get(pid) if pid else None
            tid = p["tenant_id"] if p else None
            if tenant_ids is not None and tid not in tenant_ids:
                dropped = True
                continue
            kept.add(r["gk"])
            rid = (p or {}).get("rate_id") or (tmap.get(tid) or {}).get("rate_id") or default_rate
            v = ver_at(rid, r["h0"]) if rid else None
            h = 5 / 60
            cpu_c = mem_c = disk_c = 0.0
            if v:
                mw = (v["min_weight"] or 0) / 100
                vc = (mw * r["vcpu"] + (1 - mw) * r["vcpu_u"]) if v["weighting"] else r["vcpu"]
                mm = (mw * r["mem"] + (1 - mw) * r["mem_u"]) if v["weighting"] else r["mem"]
                cpu_c = vc * v["vcpu_hour"] * h
                mem_c = mm * v["mem_gb_hour"] * h
                disk_c = (r["disk"] + (r["disk_off"] if v["disk_when_off"] else 0)) * v["disk_gb_hour"] * h
            k = (pid, r["vc"], r["vm"])
            a = agg.get(k)
            if a is None:
                a = agg[k] = {"vm": r["vm"], "vc": r["vc"], "project_id": pid, "tenant_id": tid, "matched_by": how, "rate_id": rid,
                              "blocks": 0, "seen": 0, "vcpu_bh": 0.0, "mem_bh": 0.0, "disk_bh": 0.0, "vcpu_u": 0.0, "mem_u": 0.0,
                              "cpu_cost": 0.0, "mem_cost": 0.0, "disk_cost": 0.0, "cluster": r["cluster"], "folder": r["folder"], "tags": tags, "last": 0}
            a["blocks"] += r["blocks"]
            a["seen"] += r["seen"]
            a["vcpu_bh"] += r["vcpu"]
            a["mem_bh"] += r["mem"]
            a["disk_bh"] += r["disk"]
            a["vcpu_u"] += r["vcpu_u"]
            a["mem_u"] += r["mem_u"]
            a["cpu_cost"] += cpu_c
            a["mem_cost"] += mem_c
            a["disk_cost"] += disk_c
            a["priced"] = a.get("priced", False) or bool(v)
            if r["hour"] >= a["last"]:
                a.update(last=r["hour"], cluster=r["cluster"], folder=r["folder"], tags=tags)
        # 자료가 있는 시각(커버리지) — 전체 보고서는 인덱스만 훑고, 테넌트 범위 보고서는 포함된 묶음의 표본만
        if kept and not dropped:
            hq = await self.e.store.q("SELECT DISTINCT hour FROM bill_usage WHERE hour>=? AND hour<?", (h_from, end))
        elif kept:
            hq = await self.e.store.q("SELECT DISTINCT hour FROM bill_usage WHERE hour>=? AND hour<? AND json_array(vc, vm, cluster, folder, tags) IN "
                                      "(SELECT value FROM json_each(?))", (h_from, end, json.dumps(sorted(kept), ensure_ascii=False)))
        else:
            hq = []
        cover["hours"] = {x["hour"] for x in hq}

        def vm_out(a: dict) -> dict:
            on_h = a["blocks"] * 5 / 60
            return {"vm": a["vm"], "vcenter": a["vc"], "cluster": a["cluster"], "folder": a["folder"], "tags": a["tags"], "matched_by": a["matched_by"],
                    "on_hours": round(on_h, 2), "observed_hours": round(a["seen"] * 5 / 60, 2),
                    "vcpu_hours": round(a["vcpu_bh"] * 5 / 60, 2), "mem_gb_hours": round(a["mem_bh"] * 5 / 60, 2), "disk_gb_hours": round(a["disk_bh"] * 5 / 60, 2),
                    "avg_vcpu": round(a["vcpu_bh"] / a["blocks"], 2) if a["blocks"] else 0, "avg_mem_gb": round(a["mem_bh"] / a["blocks"], 2) if a["blocks"] else 0,
                    "avg_disk_gb": round(a["disk_bh"] / a["blocks"], 1) if a["blocks"] else 0,
                    "cpu_util": round(a["vcpu_u"] / a["vcpu_bh"] * 100, 1) if a["vcpu_bh"] else None,
                    "mem_util": round(a["mem_u"] / a["mem_bh"] * 100, 1) if a["mem_bh"] else None,
                    "cpu_cost": round(a["cpu_cost"], 2), "mem_cost": round(a["mem_cost"], 2), "disk_cost": round(a["disk_cost"], 2),
                    "cost": round(a["cpu_cost"] + a["mem_cost"] + a["disk_cost"], 2) if a.get("priced") else None}

        def sums(vms: list[dict]) -> dict:
            keys = ("on_hours", "vcpu_hours", "mem_gb_hours", "disk_gb_hours", "cpu_cost", "mem_cost", "disk_cost")
            out = {k: round(sum(v[k] or 0 for v in vms), 2) for k in keys}
            out["cost"] = round(sum(v["cost"] or 0 for v in vms), 2) if any(v["cost"] is not None for v in vms) else None
            out["vms"] = len(vms)
            out["vms_on"] = sum(1 for v in vms if v["on_hours"] > 0)
            return out

        by_proj: dict[int | None, list[dict]] = {}
        for a in agg.values():
            by_proj.setdefault(a["project_id"], []).append(vm_out(a))
        t_out = []
        for t in tenants:
            if tenant_ids is not None and t["id"] not in tenant_ids:
                continue
            ps = []
            for p in t["projects"]:
                vms = sorted(by_proj.get(p["id"], []), key=lambda v: (-(v["cost"] or 0), -v["vcpu_hours"], v["vm"]))
                rid = p.get("rate_id") or t.get("rate_id") or default_rate
                ps.append({"id": p["id"], "name": p["name"], "note": p.get("note", ""), "rate": (rates.get(rid) or {}).get("name", "") if rid else "",
                           "match": {k: p[k] for k in ("clusters", "folders", "tags", "vms")}, **sums(vms), "vm_rows": vms if vm_detail else []})
            allv = [v for p in ps for v in p["vm_rows"]] if vm_detail else []
            tot = {k: round(sum(p[k] or 0 for p in ps), 2) for k in ("on_hours", "vcpu_hours", "mem_gb_hours", "disk_gb_hours", "cpu_cost", "mem_cost", "disk_cost")}
            tot["cost"] = round(sum(p["cost"] or 0 for p in ps), 2) if any(p["cost"] is not None for p in ps) else None
            tot["vms"] = sum(p["vms"] for p in ps)
            t_out.append({"id": t["id"], "name": t["name"], "note": t.get("note", ""), "rate": (rates.get(t.get("rate_id")) or {}).get("name", ""),
                          "projects": ps, **tot, "top_vms": sorted(allv, key=lambda v: -(v["cost"] or 0))[:5]})
        un = sorted(by_proj.get(None, []), key=lambda v: (-v["vcpu_hours"], v["vm"])) if tenant_ids is None else []
        cur = next((r["currency"] for r in rates.values() if r["is_default"]), None) or self.currency
        hours = sorted(cover["hours"])
        all_cost = [t["cost"] for t in t_out if t["cost"] is not None]
        return {"period": {"start": start, "end": end, "label": label}, "currency": cur, "generated": time.time(),
                "coverage": {"first_hour": hours[0] if hours else None, "last_hour": hours[-1] if hours else None, "hours_with_data": len(hours),
                             "period_hours": round((end - start) / 3600, 1)},
                "totals": {"cost": round(sum(all_cost), 2) if all_cost else None, "tenants": len(t_out), "projects": sum(len(t["projects"]) for t in t_out),
                           "vms": sum(t["vms"] for t in t_out), "vcpu_hours": round(sum(t["vcpu_hours"] for t in t_out), 2),
                           "mem_gb_hours": round(sum(t["mem_gb_hours"] for t in t_out), 2), "disk_gb_hours": round(sum(t["disk_gb_hours"] for t in t_out), 2),
                           "unassigned_vms": len(un), "unassigned_vcpu_hours": round(sum(v["vcpu_hours"] for v in un), 2)},
                "tenants": t_out, "unassigned": un[:2000], "rates": [{"id": r["id"], "name": r["name"], "currency": r["currency"], "is_default": r["is_default"],
                                                                      "current": r["current"]} for r in rates.values()],
                "sampler": dict(self.stats)}

    @staticmethod
    def to_csv(rep: dict) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["기간", rep["period"]["label"], "통화", rep["currency"]])
        w.writerow(["테넌트", "프로젝트", "VM", "vCenter", "클러스터", "폴더", "태그", "매칭", "켜짐(시간)", "vCPU·시간", "메모리 GB·시간", "디스크 GB·시간",
                    "평균 vCPU", "평균 메모리 GB", "평균 디스크 GB", "CPU 사용률 %", "메모리 사용률 %", "CPU 비용", "메모리 비용", "디스크 비용", "합계"])
        for t in rep["tenants"]:
            for p in t["projects"]:
                for v in p["vm_rows"]:
                    w.writerow([t["name"], p["name"], v["vm"], v["vcenter"], v["cluster"], v["folder"], " ".join(v["tags"]), v["matched_by"], v["on_hours"],
                                v["vcpu_hours"], v["mem_gb_hours"], v["disk_gb_hours"], v["avg_vcpu"], v["avg_mem_gb"], v["avg_disk_gb"], v["cpu_util"], v["mem_util"],
                                v["cpu_cost"], v["mem_cost"], v["disk_cost"], v["cost"]])
        for v in rep.get("unassigned", []):
            w.writerow(["(미할당)", "", v["vm"], v["vcenter"], v["cluster"], v["folder"], " ".join(v["tags"]), "", v["on_hours"], v["vcpu_hours"], v["mem_gb_hours"],
                        v["disk_gb_hours"], v["avg_vcpu"], v["avg_mem_gb"], v["avg_disk_gb"], v["cpu_util"], v["mem_util"], "", "", "", ""])
        return "﻿" + buf.getvalue()

    @staticmethod
    def statement_html(rep: dict, tenant: dict, issuer: str = "VCF AIops") -> str:
        """테넌트 월 명세서(인쇄용 HTML — 브라우저 인쇄로 PDF 저장)"""
        e = html.escape
        cur = rep["currency"]
        money = lambda v: "-" if v is None else f"{v:,.0f}" if cur in ("KRW", "JPY") else f"{v:,.2f}"   # noqa: E731
        num = lambda v: f"{v:,.1f}"   # noqa: E731
        rows = []
        for p in tenant["projects"]:
            rows.append(f"<tr class='p'><td colspan='2'>{e(p['name'])}<small> {e(p.get('rate') or '')}</small></td><td>{p['vms']}</td><td>{num(p['vcpu_hours'])}</td>"
                        f"<td>{num(p['mem_gb_hours'])}</td><td>{num(p['disk_gb_hours'])}</td><td>{money(p['cpu_cost'])}</td><td>{money(p['mem_cost'])}</td>"
                        f"<td>{money(p['disk_cost'])}</td><td><b>{money(p['cost'])}</b></td></tr>")
            for v in p["vm_rows"]:
                rows.append(f"<tr><td></td><td>{e(v['vm'])}</td><td>{v['on_hours']:.1f}h</td><td>{num(v['vcpu_hours'])}</td><td>{num(v['mem_gb_hours'])}</td>"
                            f"<td>{num(v['disk_gb_hours'])}</td><td>{money(v['cpu_cost'])}</td><td>{money(v['mem_cost'])}</td><td>{money(v['disk_cost'])}</td>"
                            f"<td>{money(v['cost'])}</td></tr>")
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{e(tenant['name'])} 사용료 명세서 — {e(rep['period']['label'])}</title>
<style>body{{font-family:Pretendard,'Malgun Gothic',sans-serif;color:#1d2328;margin:32px;font-size:13px}}h1{{font-size:22px;margin:0 0 4px}}
.meta{{color:#5b6670;margin-bottom:18px}}.sum{{display:flex;gap:14px;margin:14px 0}}.sum div{{border:1px solid #cfd6db;border-radius:6px;padding:8px 14px}}
.sum b{{display:block;font-size:20px}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #e1e6ea;padding:5px 6px;text-align:right}}
th:nth-child(-n+2),td:nth-child(-n+2){{text-align:left}}th{{background:#f1f4f6;font-weight:600}}tr.p td{{background:#f7f9fa;font-weight:600}}
small{{color:#7a858d;font-weight:400}}.note{{margin-top:16px;color:#5b6670;font-size:12px;line-height:1.6}}
@media print{{.noprint{{display:none}}body{{margin:12mm}}}}</style></head><body>
<p class="noprint"><button onclick="print()">인쇄 / PDF 저장</button></p>
<h1>{e(tenant['name'])} — 가상 인프라 사용료 명세서</h1>
<div class="meta">기간 {e(rep['period']['label'])} · 통화 {e(cur)} · 발행 {now} · {e(issuer)}</div>
<div class="sum"><div>합계<b>{money(tenant['cost'])}</b></div><div>VM<b>{tenant['vms']}</b></div><div>vCPU·시간<b>{num(tenant['vcpu_hours'])}</b></div>
<div>메모리 GB·시간<b>{num(tenant['mem_gb_hours'])}</b></div><div>디스크 GB·시간<b>{num(tenant['disk_gb_hours'])}</b></div></div>
<table><thead><tr><th>프로젝트</th><th>VM</th><th>VM 수·켜짐</th><th>vCPU·h</th><th>메모리 GB·h</th><th>디스크 GB·h</th><th>CPU</th><th>메모리</th><th>디스크</th><th>합계</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="10">사용 기록 없음</td></tr>'}</tbody></table>
<div class="note">산정 기준: VM 이 켜져 있던 5분 블록마다 (vCPU × vCPU 단가 + 메모리 GB × GB 단가 + 할당 디스크 GB × GB 단가) × 5/60.
꺼져 있던 블록은 요율표 설정에 따라 디스크만 과금하거나 과금하지 않습니다. 사용률 가중이 켜진 요율은 vCPU·메모리에 (최소 가중치 + (1 − 최소 가중치) × 사용률) 을 곱합니다.
표본은 vCenter 인벤토리 기준이며 수집이 멈춘 구간은 과금되지 않습니다(데이터가 있는 시간 {rep['coverage']['hours_with_data']} / 기간 {rep['coverage']['period_hours']}시간).</div>
</body></html>"""
