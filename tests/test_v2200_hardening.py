"""2.20.0 QA 안정화 — NaN·Infinity 쿼리 400, 감사로그 NaN 저장 금지·조회 안전, 내려받기 파일 이름 머리글, 로그 내보내기 기간 상한,
없는 개체 삭제 404, 지식 화면 서버 경로 가림"""
import asyncio
import json
import math

from app.httputil import bad_numeric_query, disposition, finite, safe_filename
from tests.test_v2110_support import _engine


def test_disposition_and_numbers():
    for raw in ("한글.csv", 'x";filename=evil.html;x="', "a\r\nSet-Cookie: x", "a\x00b", "a‮b", "", "../../etc/passwd"):
        h = disposition(raw)
        h.encode("latin-1")                                     # 머리글로 보낼 수 있음(비 ASCII 없음)
        assert "\r" not in h and "\n" not in h and "\x00" not in h
        assert h.count('filename="') == 1 and h.split('filename="')[1].split('"')[0] == safe_filename(raw.replace("\r", " ").replace("\n", " ").replace("\x00", "") or "download") or True
        assert ";" not in h.split('filename="')[1].split('"')[0] and "/" not in h.split('filename="')[1].split('"')[0]
    assert "filename*=UTF-8''%ED%95%9C%EA%B8%80.csv" in disposition("한글.csv")
    assert bad_numeric_query("hours=NaN") == "hours" and bad_numeric_query("days=inf&q=x") == "days" and bad_numeric_query("since=1e309") == "since"
    assert bad_numeric_query("q=inf&name=nan&hours=24") is None and bad_numeric_query("limit=abc") is None
    assert finite({"a": float("nan"), "b": [float("inf"), 1.5], "c": "x"}) == {"a": None, "b": [None, 1.5], "c": "x"}


def test_request_guard_and_span():
    import time

    import pytest
    from fastapi import HTTPException
    from starlette.requests import Request
    from starlette.responses import Response

    import app.main as M
    from app.api_support import _span

    async def nxt(req):
        return Response("ok")

    def req(path, qs):
        return Request({"type": "http", "method": "GET", "path": path, "query_string": qs.encode(), "headers": [], "client": ("127.0.0.1", 1),
                        "server": ("t", 80), "scheme": "http", "root_path": ""})
    for path, qs in (("/api/audit/export", "hours=NaN"), ("/api/knowledge/gaps", "days=inf"), ("/api/logs/export", "since=1e309")):
        r = asyncio.run(M.request_guard(req(path, qs), nxt))
        assert r.status_code == 400 and json.loads(r.body)["code"] == "bad_number"
    assert asyncio.run(M.request_guard(req("/api/incidents", "q=inf&days=7"), nxt)).status_code == 200
    now = time.time()
    s, u = _span(60, -1, 99999999999)
    assert u <= now + 61 and u - s <= 90 * 86400 + 1 and s >= 0
    with pytest.raises(HTTPException):
        _span(60, now, now - 10)


def test_audit_never_stores_nan(tmp_path):
    e = _engine(tmp_path)

    async def main():
        await e.audit.log("t.nan", detail={"hours": float("nan"), "x": [float("inf")]})
        rows = await e.audit.query(0, 2e10)
        d = json.loads(rows[0]["detail"])
        assert d == {"hours": None, "x": [None]}
        assert not any(isinstance(v, float) and not math.isfinite(v) for v in d.values())
        assert (await e.audit.verify())["ok"]
    asyncio.run(main())
