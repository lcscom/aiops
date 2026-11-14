"""AI 분석 패턴 저장소 — 같은 '로그 패턴'은 한 번만 LLM 으로 분석하고, 이후 발생은 저장된 분석을 즉시 재사용.

패턴 키 = 소스 + 정규화한 메시지 템플릿. 정규화: 숫자·16진·UUID·IP·FQDN·경로의 숫자·따옴표 값, 그리고 이벤트의
호스트·개체 이름을 자리표시자로 바꿔 'esx01 의 경로 다운'과 'esx07 의 경로 다운'이 같은 패턴이 되게 한다.

  · 분석 재사용 기간(ttl, 기본 7일)이 지나거나, 분석 당시보다 더 높은 심각도로 발생하면 다시 분석
  · 패턴별 '분석 제외'(이 패턴은 규칙 탐지로만) / '다시 분석' / '분석 지우기'
  · 메모리 + SQLite(ai_patterns) — 재기동 후에도 분석 결과 유지(GPU 재사용 최소화)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import Any

from .models import SEV_RANK

SCHEMA = """CREATE TABLE IF NOT EXISTS ai_patterns(
  key TEXT PRIMARY KEY, source TEXT, template TEXT, sample TEXT, host TEXT, first REAL, last REAL, count INTEGER,
  anomalies INTEGER, sev_max TEXT, state TEXT, analysis TEXT, analyzed_at REAL, analyzed_sev TEXT, provider TEXT, model TEXT,
  excluded INTEGER DEFAULT 0, reused INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_aip_last ON ai_patterns(last);"""

_NORM = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<MAC>"),
    (re.compile(r"\b(?=[\w-]*[a-z])[\w-]+(?:\.[\w-]+){2,}\b", re.I), "<FQDN>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I), "<HEX>"),
    (re.compile(r"\"[^\"]{1,120}\"|'[^']{1,120}'"), "<S>"),
    (re.compile(r"\d+"), "#"),
    (re.compile(r"\s+"), " "),
]


def normalize(template: str, names: list[str] | None = None) -> str:
    t = (template or "")[:500]
    for n in sorted({x for x in (names or []) if x and len(x) >= 3}, key=len, reverse=True):
        t = t.replace(n, "<OBJ>")
    for rx, rep in _NORM:
        t = rx.sub(rep, t)
    return t.strip()


class PatternStore:
    def __init__(self, store, cfg: dict | None = None):
        self.store = store
        self.rows: dict[str, dict[str, Any]] = {}
        self.dirty: set[str] = set()
        self.stats = {"observed": 0, "reused": 0, "new": 0}
        self.configure(cfg or {})

    def configure(self, cfg: dict) -> None:
        self.ttl = float(cfg.get("pattern_ttl_hours", 168)) * 3600
        self.cap = int(cfg.get("pattern_cap", 20000))
        self.enabled = cfg.get("pattern_reuse", True) is not False

    async def load(self) -> None:
        self.store.schema(SCHEMA)
        try:
            rows = await self.store.q("SELECT * FROM ai_patterns ORDER BY last DESC LIMIT ?", (self.cap,))
        except Exception:  # noqa: BLE001
            rows = []
        for r in rows:
            try:
                r["analysis"] = json.loads(r["analysis"]) if r.get("analysis") else None
            except ValueError:
                r["analysis"] = None
            self.rows[r["key"]] = r

    @staticmethod
    def key_of(source: str, template: str, host: str = "", entity: str = "") -> tuple[str, str]:
        norm = normalize(template, [host, entity, host.split(".")[0] if host else ""])
        return hashlib.sha1(f"{source}|{norm}".encode()).hexdigest()[:16], norm

    def observe(self, source: str, template: str, sample: str, host: str, entity: str, sev: str) -> dict[str, Any]:
        key, norm = self.key_of(source, template, host, entity)
        now = time.time()
        r = self.rows.get(key)
        if r is None:
            r = self.rows[key] = {"key": key, "source": source, "template": norm, "sample": sample[:600], "host": host, "first": now,
                                  "last": now, "count": 0, "anomalies": 0, "sev_max": sev, "state": "new", "analysis": None,
                                  "analyzed_at": None, "analyzed_sev": None, "provider": "", "model": "", "excluded": 0, "reused": 0}
            self.stats["new"] += 1
            if len(self.rows) > self.cap:
                for k in sorted(self.rows, key=lambda k: self.rows[k]["last"])[: len(self.rows) - self.cap]:
                    self.rows.pop(k, None)
        r["last"] = now
        r["count"] += 1
        r["anomalies"] += 1
        if SEV_RANK.get(sev, 1) > SEV_RANK.get(r.get("sev_max") or "info", 1):
            r["sev_max"] = sev
        self.stats["observed"] += 1
        self.dirty.add(key)
        return r

    def cached(self, r: dict[str, Any], sev: str, kgen: int = 0) -> dict[str, Any] | None:
        """재사용 가능한 분석(없으면 None) — 기간 내이고 분석 당시 심각도 이상이 아닐 때.
        근거 문서 없이 분석했는데 그 뒤로 지식 라이브러리가 바뀌었으면(kgen 증가) 한 번 다시 분석해 새 KB 를 반영한다."""
        if not self.enabled or not r.get("analysis") or not r.get("analyzed_at"):
            return None
        an = r["analysis"]
        if kgen and not an.get("references") and int(an.get("_kgen") or 0) < kgen:
            self.stats["kb_refresh"] = self.stats.get("kb_refresh", 0) + 1
            return None
        if time.time() - r["analyzed_at"] > self.ttl:
            return None
        if SEV_RANK.get(sev, 1) > SEV_RANK.get(r.get("analyzed_sev") or "info", 1):
            return None
        r["reused"] = (r.get("reused") or 0) + 1
        self.stats["reused"] += 1
        self.dirty.add(r["key"])
        return r["analysis"]

    def set_state(self, key: str, state: str) -> None:
        r = self.rows.get(key)
        if r:
            r["state"] = state
            self.dirty.add(key)

    def save_analysis(self, key: str, ai: dict[str, Any], sev: str) -> None:
        r = self.rows.get(key)
        if not r or not ai or ai.get("error"):
            return
        keep = {k: v for k, v in ai.items() if k not in ("shared_from", "shared_title", "shared_count", "cached", "pattern", "pattern_count")}
        r.update(analysis=keep, analyzed_at=time.time(), analyzed_sev=sev, provider=ai.get("_provider", ""), model=ai.get("_model", ""),
                 state="analyzed")
        self.dirty.add(key)

    def exclude(self, key: str, on: bool) -> bool:
        r = self.rows.get(key)
        if not r:
            return False
        r["excluded"] = 1 if on else 0
        self.dirty.add(key)
        return True

    def forget(self, key: str) -> bool:
        r = self.rows.get(key)
        if not r:
            return False
        r.update(analysis=None, analyzed_at=None, analyzed_sev=None, state="new")
        self.dirty.add(key)
        return True

    async def flush(self) -> int:
        keys, self.dirty = list(self.dirty), set()
        rows = [self.rows[k] for k in keys if k in self.rows]
        if not rows:
            return 0
        cols = ("key", "source", "template", "sample", "host", "first", "last", "count", "anomalies", "sev_max", "state", "analysis",
                "analyzed_at", "analyzed_sev", "provider", "model", "excluded", "reused")
        sql = f"INSERT OR REPLACE INTO ai_patterns({','.join(cols)}) VALUES({','.join('?' * len(cols))})"
        for r in rows:
            vals = tuple(json.dumps(r[c], ensure_ascii=False) if c == "analysis" and r[c] is not None else r.get(c) for c in cols)
            await self.store.x(sql, vals)
        return len(rows)

    async def loop(self, beat=None) -> None:
        while True:
            await asyncio.sleep(10)
            if beat:
                beat()
            try:
                await self.flush()
            except Exception as e:  # noqa: BLE001
                print(f"[ai-patterns] 저장 오류: {type(e).__name__}: {e}", flush=True)

    def list(self, q: str = "", state: str = "", limit: int = 300) -> list[dict[str, Any]]:
        ql = q.lower()
        out = []
        for r in sorted(self.rows.values(), key=lambda r: -r["last"]):
            if state == "excluded" and not r["excluded"]:
                continue
            if state and state != "excluded" and r["state"] != state:
                continue
            if ql and ql not in f"{r['source']} {r['template']} {r['sample']} {r.get('host', '')}".lower():
                continue
            a = r.get("analysis") or {}
            out.append({k: r.get(k) for k in ("key", "source", "template", "sample", "host", "first", "last", "count", "sev_max", "state",
                                              "analyzed_at", "analyzed_sev", "provider", "model", "excluded", "reused")}
                       | {"title": a.get("title", ""), "summary": a.get("summary", ""), "ai_severity": a.get("severity", ""),
                          "is_anomaly": a.get("is_anomaly"), "category": a.get("category", "")})
            if len(out) >= limit:
                break
        return out

    def summary(self) -> dict[str, Any]:
        rs = list(self.rows.values())
        return {"patterns": len(rs), "analyzed": sum(1 for r in rs if r.get("analysis")), "excluded": sum(1 for r in rs if r["excluded"]),
                "occurrences": sum(r["count"] for r in rs), "reused_total": sum(r.get("reused") or 0 for r in rs), **self.stats,
                "ttl_hours": round(self.ttl / 3600)}
