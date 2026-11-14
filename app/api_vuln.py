"""2.43.0 API — 내부 취약점 검증 · vSAN ESA 전환 산정

  GET  /api/vuln?sev=&layer=&q=        마지막 검증 — 요약·공격 경로·약점(위험 순)
  POST /api/vuln/run                   지금 검증(operate)
  GET  /api/vuln/history               점수·건수 추이
  PUT  /api/vuln/settings {active}     능동 확인(TCP 연결만) 켜기·끄기(settings)
  POST /api/vuln/kev                   CISA KEV JSON 가져오기(operate)
  GET  /api/vuln.csv                   약점 CSV
  GET  /api/capacity/esa/sources       외장 데이터스토어·클러스터
  POST /api/capacity/esa               vSAN ESA 전환 산정(계산만)
"""
from __future__ import annotations

import csv
import io
import json
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from . import esa as ESA
from .vulnscan import SEV, SEV_KO


def build_router(ENGINE, VC, who, audit) -> APIRouter:
    r = APIRouter()

    @r.get("/api/vuln")
    async def latest(sev: str = "", layer: str = "", q: str = "", run: int = 1):
        d = await VC.latest()
        if not d and run:
            d = await VC.run("first-view")
        if not d:
            return {"summary": None, "findings": [], "paths": [], "state": VC.state, "active": VC.cfg.get("active")}
        F = d["findings"]
        if sev:
            F = [f for f in F if f["sev"] in sev.split(",")]
        if layer:
            F = [f for f in F if f["layer"] == layer]
        if q:
            ql = q.lower()
            F = [f for f in F if ql in (f["asset"] + " " + f["title"] + " " + f["evidence"]).lower()]
        return {**d, "findings": F, "matched": len(F), "state": VC.state, "active": VC.cfg.get("active"), "interval_h": VC.cfg["interval_h"], "sev_ko": SEV_KO}

    @r.post("/api/vuln/run")
    async def run(request: Request):
        if VC.state.get("running"):
            raise HTTPException(409, "이미 검증 중입니다")
        d = await VC.run(who(request).get("user", "user"))
        await audit(request, "vuln.run", str(d["summary"]["findings"]))
        return {"summary": d["summary"]}

    @r.get("/api/vuln/history")
    async def history():
        return {"runs": await VC.history()}

    @r.put("/api/vuln/settings")
    async def settings(request: Request):
        b = await request.json()
        await VC.set_active(bool((b or {}).get("active")))
        await audit(request, "vuln.settings", f"active={VC.cfg['active']}")
        return {"active": VC.cfg["active"]}

    @r.post("/api/vuln/kev")
    async def kev(request: Request):
        raw = await request.body()
        if len(raw) > 30 * 2**20:
            raise HTTPException(413, "30MB 이하만")
        try:
            n = await VC.import_kev(json.loads(raw.decode("utf-8-sig")))
        except (ValueError, UnicodeDecodeError) as e:
            raise HTTPException(400, str(e)[:200]) from None
        await audit(request, "vuln.kev", str(n))
        return {"imported": n}

    @r.get("/api/vuln.csv")
    async def csv_out():
        d = await VC.latest() or {"findings": []}
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["등급", "영역", "자산", "약점", "근거", "출처", "확인", "조치"])
        for f in d["findings"]:
            w.writerow([SEV_KO.get(f["sev"], f["sev"]), f["layer"], f["asset"], f["title"], f["evidence"], f["source"], f.get("verified", ""), f["fix"]])
        return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-vuln-{time.strftime("%Y%m%d")}.csv"', "Cache-Control": "private, no-store"})

    # ---------------------------------------------------------------- vSAN ESA 전환
    async def _src():
        items = []
        try:
            items = (await ENGINE.capacity.overview()).get("items", [])
        except Exception:  # noqa: BLE001
            items = []
        return ESA.sources(ENGINE, items)

    @r.get("/api/capacity/esa/sources")
    async def esa_sources():
        return await _src()

    @r.post("/api/capacity/esa")
    async def esa_size(request: Request):
        try:
            b = await request.json()
        except Exception:  # noqa: BLE001
            b = {}
        try:
            return ESA.size(await _src(), b if isinstance(b, dict) else {})
        except (TypeError, ValueError) as e:
            raise HTTPException(400, f"입력값 오류: {e}") from None

    _ = SEV
    return r
