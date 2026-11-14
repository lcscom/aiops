"""VCF Operations 메트릭(2.8.0) — VCF Ops 커넥터가 모은 최신 값을 한 곳에서 조회·추세·내보내기·선택

  · 최신 값: 커넥터 메모리(수집 주기 기본 5분) — 개체 목록·정렬·검색·상위 N
  · 추세: 호스트·클러스터·데이터스토어(기본, history_kinds)만 SQLite ops_metric_hist 에 보관(기본 14일) — VM 은 개체 수가 많아 최신 값만
  · 메트릭 선택기: VCF Ops 카탈로그(statkeys)에서 종류별 키를 골라 DB(ops_metric_keys)에 저장 → 다음 수집부터 적용
  · 다른 기능과 연계: AI 질의 '질문 대상'·인벤토리 상세에 같은 이름 개체의 Ops 지표 표시
설계 참고(코드 미사용): github.com/brockpeterson/miscellaneous 'VCF Operations Metrics Picker'(라이선스 표기 없음 → 설계만 참고)
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import time
from typing import Any

SCHEMA = """CREATE TABLE IF NOT EXISTS ops_metric_hist(ts REAL, connector TEXT, kind TEXT, name TEXT, key TEXT, value REAL);
CREATE INDEX IF NOT EXISTS ix_omh ON ops_metric_hist(kind, name, key, ts);
CREATE INDEX IF NOT EXISTS ix_omh_ts ON ops_metric_hist(ts);
CREATE TABLE IF NOT EXISTS ops_metric_keys(connector TEXT, kind TEXT, keys TEXT, updated REAL, by TEXT, PRIMARY KEY(connector, kind));"""
KIND_KO = {"HostSystem": "ESXi 호스트", "VirtualMachine": "VM", "ClusterComputeResource": "클러스터", "Datastore": "데이터스토어"}


class OpsMetrics:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.history_kinds = list(c.get("history_kinds") or ["HostSystem", "ClusterComputeResource", "Datastore"])
        self.retention_days = float(c.get("retention_days", 14))
        self._schema = False
        self._gens: dict[str, int] = {}
        self._keys: dict[tuple[str, str], list[str]] = {}
        self.stats = {"written": 0, "last_write": 0.0, "error": ""}

    # ------------------------------------------------------------------ 공통
    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True
            try:
                for r in self.e.store._conn.execute("SELECT connector, kind, keys FROM ops_metric_keys").fetchall():
                    self._keys[(r[0], r[1])] = json.loads(r[2] or "[]")
            except Exception:  # noqa: BLE001
                pass

    def connectors(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcfops"]

    def _conn(self, name: str):
        for c in self.connectors():
            if not name or c.name == name:
                return c
        return None

    def push_keys(self) -> None:
        """선택기 값 → 커넥터(다음 수집부터 적용)"""
        self._ensure()
        for c in self.connectors():
            c.keys_override = {k: v for (cn, k), v in self._keys.items() if cn == c.name and v}

    # ------------------------------------------------------------------ 백그라운드
    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(15)
        last_purge = 0.0
        while True:
            beat()
            try:
                self.push_keys()
                await self.persist()
                if time.time() - last_purge > 86400:
                    last_purge = time.time()
                    await self.e.store.x("DELETE FROM ops_metric_hist WHERE ts < ?", (time.time() - self.retention_days * 86400,))
            except Exception as e:  # noqa: BLE001
                self.stats["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(30)

    async def persist(self) -> int:
        """새 수집분(gen 변경) 중 추세 보관 종류만 기록"""
        self._ensure()
        n = 0
        for c in self.connectors():
            ops = getattr(c, "ops", {}) or {}
            if not ops.get("updated") or self._gens.get(c.name) == ops.get("gen"):
                continue
            self._gens[c.name] = ops.get("gen")
            rows = []
            for kind, kd in (ops.get("kinds") or {}).items():
                if kind not in self.history_kinds:
                    continue
                for rid, kv in (kd.get("values") or {}).items():
                    name = (kd.get("objects") or {}).get(rid, {}).get("name", rid)
                    for k, (v, ts) in kv.items():
                        rows.append((float(ops["updated"]), c.name, kind, name, k, float(v)))
            for i in range(0, len(rows), 2000):
                chunk = rows[i:i + 2000]
                await self.e.store.x(f"INSERT INTO ops_metric_hist(ts,connector,kind,name,key,value) VALUES {','.join(['(?,?,?,?,?,?)'] * len(chunk))}",
                                     tuple(x for r in chunk for x in r))
            n += len(rows)
        if n:
            self.stats.update(written=self.stats["written"] + n, last_write=time.time())
        return n

    # ------------------------------------------------------------------ 조회
    def summary(self) -> dict[str, Any]:
        out = []
        for c in self.connectors():
            ops = getattr(c, "ops", {}) or {}
            kinds = {}
            for kind, kd in (ops.get("kinds") or {}).items():
                kinds[kind] = {"label": KIND_KO.get(kind, kind), "objects": len(kd.get("objects") or {}), "with_data": kd.get("with_data", 0),
                               "keys": kd.get("keys") or [], "keys_no_data": kd.get("keys_no_data") or [],
                               "meta": {k: (getattr(c, "catalog", {}).get(kind) or {}).get(k, {}) for k in kd.get("keys") or []}}
            out.append({"connector": c.name, "host": getattr(c, "host", ""), "enabled": getattr(c, "metrics_on", False), "updated": ops.get("updated") or None,
                        "interval": getattr(c, "metric_interval", 300), "took_ms": ops.get("took_ms"), "api": ops.get("api", ""),
                        "error": ops.get("error", ""), "kinds": kinds})
        return {"connectors": out, "history_kinds": self.history_kinds, "retention_days": self.retention_days, "store": self.stats}

    def objects(self, kind: str, connector: str = "", q: str = "", sort: str = "", desc: bool = True, limit: int = 500) -> dict[str, Any]:
        rows, keys, meta = [], [], {}
        ql = (q or "").lower()
        for c in self.connectors():
            if connector and c.name != connector:
                continue
            kd = ((getattr(c, "ops", {}) or {}).get("kinds") or {}).get(kind) or {}
            for k in kd.get("keys") or []:
                if k not in keys:
                    keys.append(k)
                    meta[k] = (getattr(c, "catalog", {}).get(kind) or {}).get(k, {})
            for rid, o in (kd.get("objects") or {}).items():
                if ql and ql not in o.get("name", "").lower():
                    continue
                vals = (kd.get("values") or {}).get(rid, {})
                rows.append({"id": rid, "name": o.get("name", rid), "connector": c.name, "health": o.get("health", ""), "status": o.get("status", ""),
                             "values": {k: v[0] for k, v in vals.items()}, "ts": max((v[1] for v in vals.values()), default=None)})
        if sort:
            rows.sort(key=lambda r: (r["values"].get(sort) is None, -(r["values"].get(sort) or 0) if desc else (r["values"].get(sort) or 0)))
        else:
            rows.sort(key=lambda r: r["name"].lower())
        return {"kind": kind, "label": KIND_KO.get(kind, kind), "keys": keys, "meta": meta, "total": len(rows), "items": rows[:max(1, min(limit, 20000))]}

    def for_entity(self, name: str) -> list[dict[str, Any]]:
        """같은 이름(대소문자 무시, 짧은 이름도) 개체의 최신 Ops 지표 — AI 질의·인벤토리용"""
        if not name:
            return []
        nl = name.lower()
        short = nl.split(".")[0]
        out = []
        for c in self.connectors():
            for kind, kd in ((getattr(c, "ops", {}) or {}).get("kinds") or {}).items():
                for rid, o in (kd.get("objects") or {}).items():
                    on = (o.get("name") or "").lower()
                    if on == nl or (("." in nl or "." in on) and on.split(".")[0] == short and len(short) >= 4):
                        vals = (kd.get("values") or {}).get(rid, {})
                        cat = getattr(c, "catalog", {}).get(kind) or {}
                        out.append({"connector": c.name, "kind": kind, "name": o.get("name"), "health": o.get("health", ""),
                                    "metrics": [{"key": k, "name": (cat.get(k) or {}).get("name") or k, "unit": (cat.get(k) or {}).get("unit", ""),
                                                 "value": v[0], "ts": v[1]} for k, v in vals.items()]})
        return out

    def brief(self, name: str) -> str:
        """AI 입력용 한 줄 — 'VCF Ops(HostSystem): CPU Usage 72.1 % · Memory Usage 64 % · Health 100'"""
        parts = []
        for x in self.for_entity(name):
            m = " · ".join(f"{y['name']} {round(y['value'], 2):g}{(' ' + y['unit']) if y['unit'] else ''}" for y in x["metrics"][:12])
            if m:
                parts.append(f"VCF Ops({x['kind']}{', 상태 ' + x['health'] if x['health'] else ''}): {m}")
        return "\n".join(parts)

    async def series(self, kind: str, name: str, key: str, hours: float = 24) -> dict[str, Any]:
        self._ensure()
        rows = await self.e.store.q("SELECT ts, value FROM ops_metric_hist WHERE kind=? AND name=? AND key=? AND ts>=? ORDER BY ts",
                                    (kind, name, key, time.time() - hours * 3600))
        return {"kind": kind, "name": name, "key": key, "points": [[r["ts"], r["value"]] for r in rows], "stored": kind in self.history_kinds}

    async def catalog(self, connector: str, kind: str, q: str = "", refresh: bool = False) -> dict[str, Any]:
        c = self._conn(connector)
        if not c:
            raise KeyError("VCF Operations 커넥터 없음")
        cat = c.catalog.get(kind) if not refresh else None
        if not cat:
            cat = await c.fetch_catalog(kind)
        ql = (q or "").lower()
        items = [{"key": k, **v} for k, v in cat.items() if not v.get("property") and (not ql or ql in k.lower() or ql in (v.get("name") or "").lower())]
        items.sort(key=lambda x: x["key"])
        return {"connector": c.name, "kind": kind, "total": len(cat), "items": items[:2000], "selected": c.metric_keys(kind)}

    async def save_keys(self, connector: str, kind: str, keys: list[str], by: str) -> dict[str, Any]:
        self._ensure()
        c = self._conn(connector)
        if not c:
            raise KeyError("VCF Operations 커넥터 없음")
        keys = [str(k).strip() for k in keys if str(k).strip()][:40]
        if c.catalog.get(kind):
            bad = [k for k in keys if k not in c.catalog[kind]]
            if bad:
                raise ValueError(f"카탈로그에 없는 키: {', '.join(bad[:5])}")
        await self.e.store.x("INSERT OR REPLACE INTO ops_metric_keys(connector, kind, keys, updated, by) VALUES(?,?,?,?,?)",
                             (c.name, kind, json.dumps(keys), time.time(), by))
        self._keys[(c.name, kind)] = keys
        self.push_keys()
        return {"connector": c.name, "kind": kind, "keys": c.metric_keys(kind)}

    def export(self, kind: str, fmt: str = "csv", connector: str = "", q: str = "") -> tuple[str, str]:
        d = self.objects(kind, connector, q, limit=20000)
        if fmt == "json":
            return json.dumps({"kind": kind, "exported": time.time(), "metric_info": d["meta"], "items": d["items"]}, ensure_ascii=False, indent=1), "application/json"
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["connector", "kind", "name", "health"] + [f"{(d['meta'].get(k) or {}).get('name') or k} [{k}]" + (f" ({(d['meta'].get(k) or {}).get('unit')})" if (d['meta'].get(k) or {}).get("unit") else "") for k in d["keys"]] + ["collected"])
        for r in d["items"]:
            w.writerow([r["connector"], kind, r["name"], r["health"]] + [r["values"].get(k, "") for k in d["keys"]]
                       + [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])) if r["ts"] else ""])
        return "﻿" + buf.getvalue(), "text/csv; charset=utf-8"
