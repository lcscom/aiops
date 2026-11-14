"""로그 내보내기(2.11.0) — 어떤 화면의 로그든 같은 조건으로 파일로 받기

  형식: csv(UTF-8 BOM, Excel) · txt(한 줄 = 시각 등급 소스 호스트 개체 메시지) · ndjson(한 줄 JSON) · zip(소스별 txt + 전체 csv + 조건 README)
  조건: 기간(minutes 또는 since/until) · 소스 · 커넥터 · 호스트(여러 개) · 개체(entity, 여러 개) · 최소 등급 · 포함 문자열 · 종류(kind)
  모든 줄은 비밀값 패턴(password=·token=·Bearer·JWT·URL 자격 증명 …)을 가린 뒤 쓴다(vksobs.mask_log).
  DB 를 5,000행씩 끊어 읽어 메모리를 일정하게 유지한다. 최대 행 수는 기본 200,000(요청 max_rows, 상한 1,000,000).
"""
from __future__ import annotations

import csv
import io
import json
import time
import zipfile
from datetime import datetime
from typing import Any, AsyncIterator

from .models import SEVERITIES
from .security.audit import csv_cell
from .vksobs import mask_log

SEVS = list(SEVERITIES)
COLS = ["ts", "time", "severity", "source", "connector", "host", "entity", "kind", "message"]
MAX_ROWS = 1_000_000


def sev_at_least(min_sev: str) -> list[str]:
    i = SEVS.index(min_sev) if min_sev in SEVS else 0
    return SEVS[i:]


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(float(ts or 0)).astimezone().strftime("%Y-%m-%d %H:%M:%S%z")


class LogQuery:
    """조회 조건 — SQL 은 매개변수로만(문자열 결합 없음)"""

    def __init__(self, since: float, until: float, sources: list[str] | None = None, connectors: list[str] | None = None,
                 hosts: list[str] | None = None, entities: list[str] | None = None, min_severity: str = "debug", q: str = "",
                 kinds: list[str] | None = None, max_rows: int = 200_000):
        self.since, self.until = float(since), float(until)
        self.sources = [s for s in (sources or []) if s][:20]
        self.connectors = [s for s in (connectors or []) if s][:20]
        self.hosts = [h.strip().lower() for h in (hosts or []) if h and h.strip()][:200]
        self.entities = [e for e in (entities or []) if e][:500]
        self.min_severity = min_severity if min_severity in SEVS else "debug"
        self.q = (q or "")[:200]
        self.kinds = [k for k in (kinds or []) if k][:20]
        self.max_rows = max(1, min(int(max_rows or 200_000), MAX_ROWS))

    def where(self) -> tuple[str, list[Any]]:
        sql, p = " WHERE ts BETWEEN ? AND ?", [self.since, self.until]
        if self.sources:
            sql += f" AND source IN ({','.join('?' * len(self.sources))})"
            p += self.sources
        if self.connectors:
            sql += f" AND connector IN ({','.join('?' * len(self.connectors))})"
            p += self.connectors
        if self.kinds:
            sql += f" AND kind IN ({','.join('?' * len(self.kinds))})"
            p += self.kinds
        ors, op = [], []
        for h in self.hosts:                             # FQDN·짧은 이름·접두어
            short = h.split(".")[0]
            ors.append("(lower(host) = ? OR lower(host) = ? OR lower(host) LIKE ? OR lower(entity) = ? OR lower(entity) LIKE ?)")
            op += [h, short, short + ".%", h, "%/" + h]
        if self.entities:
            ors.append(f"entity IN ({','.join('?' * len(self.entities))})")
            op += self.entities
        if ors:
            sql += " AND (" + " OR ".join(ors) + ")"
            p += op
        sevs = sev_at_least(self.min_severity)
        if len(sevs) < len(SEVS):
            sql += f" AND severity IN ({','.join('?' * len(sevs))})"
            p += sevs
        if self.q:
            sql += " AND message LIKE ?"
            p.append(f"%{self.q}%")
        return sql, p

    def describe(self) -> dict[str, Any]:
        return {"since": fmt_ts(self.since), "until": fmt_ts(self.until), "sources": self.sources, "connectors": self.connectors,
                "hosts": self.hosts, "entities": self.entities[:50] + (["…"] if len(self.entities) > 50 else []), "min_severity": self.min_severity,
                "contains": self.q, "kinds": self.kinds, "max_rows": self.max_rows, "masked": "password·token·secret·api_key·Bearer·JWT·URL 자격 증명"}


async def rows(store, lq: LogQuery, chunk: int = 5000) -> AsyncIterator[dict]:
    """시간순(오래된 것 → 최근)으로 끊어 읽기 — (ts, rowid) 커서"""
    where, p = lq.where()
    last_ts, last_id, n = lq.since - 1, -1, 0
    while n < lq.max_rows:
        lim = min(chunk, lq.max_rows - n)
        batch = await store.q(f"SELECT rowid AS rid, ts, severity, source, connector, host, entity, kind, message FROM logs{where} "
                              "AND (ts > ? OR (ts = ? AND rowid > ?)) ORDER BY ts, rowid LIMIT ?", [*p, last_ts, last_ts, last_id, lim])
        if not batch:
            return
        n += len(batch)
        last_ts, last_id = batch[-1]["ts"], batch[-1]["rid"]
        for r in batch:
            r["message"] = mask_log(r.get("message") or "")
            r["time"] = fmt_ts(r["ts"])
            yield r
        if len(batch) < lim:
            return


async def count(store, lq: LogQuery) -> int:
    where, p = lq.where()
    r = await store.q1(f"SELECT COUNT(*) AS n FROM logs{where}", p)
    return int((r or {}).get("n") or 0)


def line_txt(r: dict) -> str:
    return f"{r['time']} {str(r.get('severity') or '').upper():8} {r.get('source', '')} {r.get('host') or '-'} {r.get('entity') or '-'} {(r.get('message') or '').replace(chr(10), ' ⏎ ')}"


async def stream(store, lq: LogQuery, fmt: str) -> AsyncIterator[bytes]:
    if fmt == "csv":
        yield "﻿".encode()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(COLS)
        async for r in rows(store, lq):
            w.writerow([csv_cell(r.get(c, "")) for c in COLS])      # 2.30.0 수식 주입 방지
            if buf.tell() > 64_000:
                yield buf.getvalue().encode()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue().encode()
    elif fmt == "ndjson":
        out = []
        async for r in rows(store, lq):
            r.pop("rid", None)
            out.append(json.dumps(r, ensure_ascii=False))
            if len(out) >= 1000:
                yield ("\n".join(out) + "\n").encode()
                out = []
        if out:
            yield ("\n".join(out) + "\n").encode()
    else:                                                 # txt
        out = []
        async for r in rows(store, lq):
            out.append(line_txt(r))
            if len(out) >= 2000:
                yield ("\n".join(out) + "\n").encode()
                out = []
        if out:
            yield ("\n".join(out) + "\n").encode()


async def build_zip(store, lq: LogQuery, extra: dict[str, bytes | str] | None = None, readme: str = "") -> bytes:
    """소스별 txt + 전체 csv + 조건 README (+ 추가 파일: 보고서·파드 로그 등)"""
    mem = io.BytesIO()
    per: dict[str, list[str]] = {}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLS)
    n = 0
    async for r in rows(store, lq):
        w.writerow([csv_cell(r.get(c, "")) for c in COLS])      # 2.30.0 수식 주입 방지
        per.setdefault(r.get("source") or "unknown", []).append(line_txt(r))
        n += 1
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/all.csv", "﻿" + buf.getvalue())
        for src, lines in sorted(per.items()):
            z.writestr(f"logs/by-source/{_safe(src)}.log", "\n".join(lines) + "\n")
        cond = lq.describe()
        z.writestr("README.txt", (readme + "\n\n" if readme else "") + "VCF AIOps 로그 내보내기\n" + f"생성 {fmt_ts(time.time())} · {n:,}행\n\n조건\n"
                   + "\n".join(f"  {k}: {v}" for k, v in cond.items()) + "\n")
        for name, data in (extra or {}).items():
            z.writestr(_safe_path(name), data)
    return mem.getvalue()


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(s))[:80] or "x"


def _safe_path(p: str) -> str:
    parts = [x for x in str(p).replace("\\", "/").split("/") if x not in ("", ".", "..")]
    return "/".join(_safe(x) for x in parts)[:200] or "file"
