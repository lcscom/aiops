"""감사 로그 — 해시 체인(위·변조 탐지) + 보존기간. 모든 인증·설정·처리·조치 이력을 남긴다.

각 행의 hash = SHA-256(prev_hash | ts | user | action | target | result | detail)
verify() 로 체인 무결성을 검증(중간 행 수정·삭제 시 불일치 위치 보고).
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, user TEXT, role TEXT, ip TEXT,
  action TEXT, target TEXT, result TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS ix_audit_user ON audit(user, ts);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit(action, ts);
"""

SECRET_KEYS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth_key", "priv_key",
               "community", "credential", "private_key", "refresh_token", "authorization", "cookie")
_USERINFO = re.compile(r"://[^/@\s]+@")


def _redact_url(v: Any) -> Any:
    """url 값 — 경로·쿼리(웹훅 토큰이 들어가는 자리)·계정 정보를 지우고 scheme://host[:port] 만 남김"""
    if not isinstance(v, str) or "://" not in v:
        return v
    try:
        u = urlsplit(v)
        base = f"{u.scheme}://{u.hostname or ''}" + (f":{u.port}" if u.port else "")
    except ValueError:
        return "***"
    return base + "/***" if (u.path not in ("", "/") or u.query or u.fragment or u.username) else v


def redact(obj: Any) -> Any:
    """감사 상세에서 비밀값 제거(키 이름 기준, VMware-AIops 계열과 동일한 토큰 규칙).
    2.30.0: headers 딕셔너리의 모든 값·Authorization·Cookie, url/webhook_url 의 경로·쿼리, 문자열 안 URL 의 계정 정보(user:pw@)도 가림"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(s in kl for s in SECRET_KEYS) and v not in (None, ""):
                out[k] = "***"
            elif kl == "headers" and isinstance(v, dict):
                out[k] = {hk: ("***" if hv not in (None, "") else hv) for hk, hv in v.items()}
            elif kl in ("url", "webhook_url"):
                out[k] = _redact_url(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str) and "://" in obj and "@" in obj:
        return _USERINFO.sub("://***@", obj)
    return obj


def csv_cell(v: Any) -> str:
    """CSV 수식 주입 방지 — =,+,-,@,탭,CR 로 시작하면 ' 를 붙임(Excel 이 수식으로 실행하지 않게). 감사로그·로그 내보내기 공용"""
    v = str(v if v is not None else "")
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def _digest(prev: str, ts: float, user: str, action: str, target: str, result: str, detail: str) -> str:
    raw = "|".join([prev, f"{ts:.6f}", user, action, target, result, detail])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, store, retention_days: int = 1825):
        self.store = store
        self.retention = retention_days * 86400
        store.schema(SCHEMA)
        self._lock = asyncio.Lock()
        self._last_hash: str | None = None
        self.sink = None            # SIEM 전달 등 — (action,user,role,ip,target,result,detail) 동기 콜백

    async def log(self, action: str, *, user: str = "system", role: str = "", ip: str = "", target: str = "",
                  result: str = "ok", detail: Any = None) -> None:
        from ..httputil import finite
        d = json.dumps(finite(redact(detail)) if detail is not None else {}, ensure_ascii=False, default=str)[:8000]   # NaN·Infinity 저장 금지(2.20)
        async with self._lock:
            if self._last_hash is None:
                row = await self.store.q1("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
                self._last_hash = row["hash"] if row else "GENESIS"
            ts = time.time()
            h = _digest(self._last_hash, ts, user, action, target, result, d)
            await self.store.x("INSERT INTO audit(ts,user,role,ip,action,target,result,detail,prev_hash,hash) "
                               "VALUES(?,?,?,?,?,?,?,?,?,?)", (ts, user, role, ip, action, target, result, d,
                                                              self._last_hash, h))
            self._last_hash = h
        if self.sink:
            try:
                self.sink(action, user, role, ip, target, result, d)
            except Exception:  # noqa: BLE001
                pass

    async def query(self, since: float, until: float, user: str | None = None, action: str | None = None,
                    q: str | None = None, limit: int = 500) -> list[dict]:
        sql = "SELECT id,ts,user,role,ip,action,target,result,detail FROM audit WHERE ts BETWEEN ? AND ?"
        p: list[Any] = [since, until]
        if user:
            sql += " AND user = ?"
            p.append(user)
        if action:
            sql += " AND action LIKE ?"
            p.append(f"{action}%")
        if q:
            sql += " AND (target LIKE ? OR detail LIKE ?)"
            p += [f"%{q}%", f"%{q}%"]
        sql += " ORDER BY id DESC LIMIT ?"
        p.append(min(limit, 10000))
        return await self.store.q(sql, p)

    async def verify(self, limit: int = 200000) -> dict:
        rows = await self.store.q("SELECT id,ts,user,action,target,result,detail,prev_hash,hash FROM audit "
                                  "ORDER BY id DESC LIMIT ?", (limit,))
        rows.reverse()

        def check() -> dict:                       # SHA-256 수만 건 — 이벤트 루프 밖에서(2.22.0)
            prev = rows[0]["prev_hash"] if rows else "GENESIS"
            for r in rows:
                if r["prev_hash"] != prev or _digest(prev, r["ts"], r["user"], r["action"], r["target"], r["result"],
                                                     r["detail"]) != r["hash"]:
                    return {"ok": False, "checked": len(rows), "broken_at": r["id"]}
                prev = r["hash"]
            return {"ok": True, "checked": len(rows), "first_id": rows[0]["id"] if rows else None,
                    "last_id": rows[-1]["id"] if rows else None}
        return await asyncio.to_thread(check) if len(rows) > 2000 else check()

    async def export_csv(self, since: float, until: float) -> str:
        rows = await self.query(since, until, limit=10000)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "시각", "사용자", "역할", "IP", "행위", "대상", "결과", "상세"])
        for r in reversed(rows):
            w.writerow([csv_cell(x) for x in (r["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["user"], r["role"],
                                              r["ip"], r["action"], r["target"], r["result"], r["detail"])])
        return "﻿" + buf.getvalue()      # Excel 한글 깨짐 방지 BOM

    async def purge(self) -> None:
        # 해시 체인은 남은 첫 행의 prev_hash 로 이어서 검증되므로 보존기간 초과분 삭제 가능
        await self.store.x("DELETE FROM audit WHERE ts < ?", (time.time() - self.retention,))
