"""호스트 분석 API(2.18.0) — 조회 view, AI 설명 operate

  GET  /api/hostdiag/hosts?days=7                          호스트별 최근 끊김 횟수·마지막 끊김·syslog 수신(24시간)
  GET  /api/hostdiag/host?name=&hours=24|start=&end=&live=1&before=1800&after=600
                                                            끊김 구간·원인 후보·통합 타임라인(vCenter 이벤트·작업·vpxd·호스트 로그·syslog)
  GET  /api/hostdiag/host.csv?name=…                       직전 분석 타임라인 CSV
  POST /api/hostdiag/ai {name}                             직전 분석으로 AI 설명(설정된 LLM)
"""
from __future__ import annotations

import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    M = ENGINE.hostdiag

    @r.get("/api/hostdiag/hosts")
    async def hosts(days: float = 7):
        return await M.hosts(max(0.05, min(days, 90)))

    @r.get("/api/hostdiag/host")
    async def host(request: Request, name: str, hours: float = 24, start: float = 0, end: float = 0, live: int = 1,
                   before: float = 1800, after: float = 600):
        name = name.strip()[:255]
        if not name:
            raise HTTPException(400, "name 필요")
        now = time.time()
        e = end or now
        s = start or (e - max(0.25, min(hours, 24 * 31)) * 3600)
        try:
            res = await M.analyze(name, s, e, bool(live), max(60, min(before, 6 * 3600)), max(60, min(after, 6 * 3600)))
        except ValueError as ex:
            raise HTTPException(400, str(ex)) from None
        await audit(request, "hostdiag.analyze", name, detail={"start": s, "end": e, "live": bool(live), "episodes": res["counts"]["episodes"]})
        return res

    @r.get("/api/hostdiag/host.csv")
    async def host_csv(request: Request, name: str):
        res = M.cache.get(name)
        if not res:
            raise HTTPException(404, "먼저 분석하세요")
        await audit(request, "hostdiag.export", name)
        fn = f"hostdiag-{name}-{time.strftime('%Y%m%d-%H%M')}.csv"
        return Response(M.csv(res), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=\"hostdiag.csv\"; filename*=UTF-8''{quote(fn)}", "Cache-Control": "private, no-store"})

    @r.post("/api/hostdiag/ai")
    async def ai(request: Request):
        b = await request.json()
        name = str(b.get("name") or "")
        try:
            out = await M.ai(name)
        except KeyError:
            raise HTTPException(404, "먼저 분석하세요") from None
        except RuntimeError as ex:
            raise HTTPException(400, str(ex)) from None
        await audit(request, "hostdiag.ai", name)
        return out

    return r
