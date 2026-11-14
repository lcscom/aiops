"""2.45.0 API — AIOps 인사이트(원인 추정·변경 상관·전조·피드백 학습). 모두 읽기·분석만

  GET  /api/aiops/kpi?days=14                소음 감소·MTTA·MTTR·학습 현황
  GET  /api/aiops/incidents                  최근 인시던트(분석 대상 목록)
  GET  /api/aiops/rca/{incident_id}?ai=0|1   토폴로지 근본 원인 후보 + 직전 변경 + 타임라인
  GET  /api/aiops/precursors                 학습된 전조 규칙
  POST /api/aiops/precursors/learn           지금 다시 학습(operate)
  GET  /api/aiops/triage                     표시 안 한 최근 이상징후(패턴별 1건)
  POST /api/aiops/feedback {anomaly_id, verdict: noise|useful|clear}   (operate)
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request


def build_router(ENGINE, X, who, audit) -> APIRouter:
    r = APIRouter()

    @r.get("/api/aiops/kpi")
    async def kpi(days: int = 14):
        return await X.kpis(max(1, min(90, days)))

    @r.get("/api/aiops/incidents")
    async def incs(days: int = 14):
        rows = await ENGINE.store.q("SELECT id, title, severity, status, created, cluster, anomaly_count, category FROM incidents WHERE created>=? ORDER BY created DESC LIMIT 100",
                                    (time.time() - max(1, min(90, days)) * 86400,))
        return {"items": [dict(x) for x in rows]}

    @r.get("/api/aiops/rca/{inc_id}")
    async def rca(inc_id: str, ai: int = 0):
        try:
            return await X.analyze(inc_id, ai=bool(ai))
        except KeyError:
            raise HTTPException(404, "인시던트가 없습니다") from None

    @r.get("/api/aiops/precursors")
    async def pre():
        await X.ensure()
        return {"rules": X.rules, "state": X.state, "cfg": X.cfg}

    @r.post("/api/aiops/precursors/learn")
    async def learn(request: Request):
        rules = await X.learn()
        await audit(request, "aiops.learn", str(len(rules)))
        return {"rules": rules, "state": X.state}

    @r.get("/api/aiops/triage")
    async def triage(n: int = 30):
        return {"items": await X.triage(max(1, min(100, n)))}

    @r.post("/api/aiops/feedback")
    async def fb(request: Request):
        b = await request.json()
        if not isinstance(b, dict) or not b.get("anomaly_id"):
            raise HTTPException(400, "anomaly_id 가 필요합니다")
        try:
            res = await X.feedback(str(b["anomaly_id"]), str(b.get("verdict") or ""), (who(request) or {}).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        except KeyError:
            raise HTTPException(404, "이상징후가 없습니다") from None
        await audit(request, "aiops.feedback", f"{b['anomaly_id']}={b.get('verdict')}")
        return res

    return r
