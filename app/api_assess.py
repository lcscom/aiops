"""보안 판독 API — 조회 view, 즉시 점검 operate, 취약점 목록 동기화·가져오기·삭제 settings.

  GET    /api/assessment                     최근 결과(요약·하드닝 행·KISA 표·VMSA/CVE 판독)
  GET    /api/assessment/history             최근 30회 요약
  GET    /api/assessment/report.csv          CSV(UTF-8 BOM)
  GET    /api/assessment/report.html         인쇄용 보고서(브라우저 인쇄 → PDF)
  POST   /api/assessment/run                 지금 점검(읽기 전용 수집)
  GET    /api/assessment/advisories          취약점 목록(가져온·동기화한 권고) 요약
  POST   /api/assessment/advisories/import   JSON 본문 업로드(NVD CVE API 2.0 응답 또는 advisories 형식, 50MB 이하)
  POST   /api/assessment/advisories/sync     NVD 동기화(설정 assessment.nvd — 프록시·API 키)
  DELETE /api/assessment/advisories          목록 비우기
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    A = ENGINE.assess

    @r.get("/api/assessment")
    async def latest():
        d = await A.latest()
        return {"result": d, "state": {**A.state, "running": A.running, "nvd_enabled": A.nvd["enabled"], "interval_hours": A.interval / 3600}}

    @r.get("/api/assessment/history")
    async def history():
        return await A.history()

    @r.get("/api/assessment/report.csv")
    async def csv_(request: Request):
        d = await A.latest()
        if not d:
            raise HTTPException(404, "점검 결과가 없습니다 — 먼저 점검을 실행하세요")
        await audit(request, "assessment.export", detail={"format": "csv"})
        return Response(A.to_csv(d), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-aiops-assessment-{time.strftime("%Y%m%d")}.csv"'})

    @r.get("/api/assessment/report.html", response_class=HTMLResponse)
    async def html_(request: Request):
        d = await A.latest()
        if not d:
            raise HTTPException(404, "점검 결과가 없습니다 — 먼저 점검을 실행하세요")
        await audit(request, "assessment.export", detail={"format": "html"})
        return HTMLResponse(A.report_html(d))

    @r.post("/api/assessment/run")
    async def run(request: Request):
        try:
            d = await A.run(by=who(request).get("user", ""))
        except RuntimeError as e:
            raise HTTPException(409, str(e))
        await audit(request, "assessment.run", detail=d["summary"]["counts"])
        return {"summary": d["summary"]}

    @r.get("/api/assessment/advisories")
    async def advs(q: str = "", limit: int = 300):
        rows = await A.advisories()
        ql = q.lower()
        if ql:
            rows = [x for x in rows if ql in (x["id"] + " " + (x["title"] or "") + " " + " ".join(x["cves"])).lower()]
        rows.sort(key=lambda x: x.get("published") or "", reverse=True)
        return {"total": A.state["advisories"], "items": [{k: x[k] for k in ("id", "title", "severity", "cvss", "published", "url", "source", "cves")}
                                                          | {"products": sorted({m["product"] for m in x["matches"]})} for x in rows[: max(1, min(limit, 2000))]],
                "sources": {s: sum(1 for x in rows if x["source"] == s) for s in ("nvd", "import")}}

    @r.post("/api/assessment/advisories/import")
    async def imp(request: Request):
        """본문 = JSON 파일 그대로(Content-Type: application/json), 파일 이름은 X-Filename 헤더"""
        buf = bytearray()
        async for part in request.stream():
            buf += part
            if len(buf) > 50 * 2**20:
                raise HTTPException(413, "50MB 이하 JSON 만 가져올 수 있습니다")
        raw = bytes(buf)
        fname = request.headers.get("x-filename", "advisories.json")
        try:
            res = await A.import_json(raw)
        except ValueError as e:
            raise HTTPException(400, str(e))
        await audit(request, "assessment.advisories.import", target=fname[:120], detail=res)
        return res

    @r.post("/api/assessment/advisories/sync")
    async def sync(request: Request):
        try:
            res = await A.nvd_sync()
        except Exception as e:  # noqa: BLE001
            A.state["nvd_error"] = f"{type(e).__name__}: {e}"[:200]
            raise HTTPException(502, f"NVD 동기화 실패: {type(e).__name__}: {e}"[:300])
        await audit(request, "assessment.advisories.sync", detail=res)
        return res

    @r.delete("/api/assessment/advisories")
    async def clear(request: Request):
        A._ensure()
        await ENGINE.store.x("DELETE FROM assess_adv")
        A.state["advisories"] = 0
        await audit(request, "assessment.advisories.clear")
        return {"ok": True}

    return r
