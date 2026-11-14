"""2.44.0 API — 비용 절감 찾기 · AI 변경 사전 검토(모두 계산만)

  GET  /api/savings?ai=0|1        절감 기회(금액은 입력한 단가로만) · ai=1 이면 한 장 요약
  PUT  /api/savings/prices        단가 저장(operate)
  GET  /api/savings.csv
  POST /api/change/review {text, ai?, failures?}   작업 계획 → 해석·영향·사전 점검·권장 시간대·절차서(markdown)
"""
from __future__ import annotations

import csv
import io
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response


def build_router(ENGINE, PR, who, audit) -> APIRouter:
    r = APIRouter()

    @r.get("/api/savings")
    async def savings(ai: int = 0):
        return await PR.savings(ai=bool(ai))

    @r.put("/api/savings/prices")
    async def prices(request: Request):
        b = await request.json()
        if not isinstance(b, dict):
            raise HTTPException(400, "JSON 객체가 필요합니다")
        try:
            p = await PR.set_prices(b)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "savings.prices", ",".join(sorted(k for k in b)))
        return p

    @r.get("/api/savings.csv")
    async def savings_csv():
        d = await PR.savings()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["절감 기회", "수량", f"연 금액({d['currency']})", "위험", "노력", "근거", "방법"])
        for o in d["ops"]:
            w.writerow([o["title"], o["qty"], "" if o["amount"] is None else round(o["amount"]), o["risk"], o["effort"], o["why"], o["how"]])
        return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-savings-{time.strftime("%Y%m%d")}.csv"', "Cache-Control": "private, no-store"})

    @r.post("/api/change/review")
    async def review(request: Request):
        b = await request.json()
        if not isinstance(b, dict) or not str(b.get("text") or "").strip():
            raise HTTPException(400, "작업 계획(text)을 적어 주세요")
        fs = b.get("failures")
        return await PR.review(str(b["text"]), use_ai=bool(b.get("ai", True)), overrides=fs if isinstance(fs, list) else None)

    return r
