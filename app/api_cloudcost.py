"""클라우드 비용 비교 API(2.13.0)

  GET  /api/cloudcost/report?commit=&basis=&cluster=&currency=   구성요소 매핑·VM 별 짝(AWS·Azure·GCP)·VCF 원가·IOPS 최소/평균/최대·합계
  GET  /api/cloudcost/report.csv                                 VM 별 표(CSV, UTF-8 BOM)
  GET  /api/cloudcost/settings · PUT(settings)                   VCF 원가 모델·약정·기준·환율·관리 VM 패턴·IOPS 기간
  GET  /api/cloudcost/prices · PUT(settings)                     단가표(기본값·출처·확인 여부·수정분) / {changes:{'aws.storage.gb_month': 0.0912, ...}}
  DELETE /api/cloudcost/prices                                   수정분 모두 지우기(기본값으로)
  POST /api/cloudcost/prices/refresh                             {provider: azure} | {provider: gcp, api_key}(키는 저장하지 않음)
  POST /api/cloudcost/iops/collect                               IOPS 지금 수집
  GET  /api/cloudcost/openshift/reference                        OpenShift 구독 참고 단가(일본 표준가·SKU·출처, 2.27.0)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    C = ENGINE.cloudcost

    def _opts(req: Request) -> dict:
        q = req.query_params
        o = {k: q.get(k) for k in ("commit", "basis", "cluster", "currency") if q.get(k)}
        if o.get("commit") and o["commit"] not in ("ondemand", "1y", "3y") or o.get("basis") and o["basis"] not in ("allocated", "rightsized") \
                or o.get("currency") and o["currency"] not in ("USD", "KRW"):
            raise HTTPException(400, "선택 값 오류")
        return o

    @r.get("/api/cloudcost/report")
    async def report(request: Request):
        return await C.report(_opts(request))

    @r.get("/api/cloudcost/report.csv")
    async def report_csv(request: Request):
        return Response(await C.csv(_opts(request)), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=\"vcf-cloud-cost.csv\"", "Cache-Control": "private, no-store"})

    @r.get("/api/cloudcost/settings")
    async def get_settings():
        return await C.settings()

    @r.put("/api/cloudcost/settings")
    async def put_settings(request: Request):
        body = await request.json()
        try:
            st = await C.save_settings(body if isinstance(body, dict) else {}, who(request).get("user", ""))
        except (ValueError, Exception) as e:  # noqa: BLE001 — re.error 포함
            raise HTTPException(400, str(e)) from None
        await audit(request, "cloudcost.settings", "", detail={k: body.get(k) for k in ("vcf_mode", "commit", "basis", "currency") if k in body})
        return st

    @r.get("/api/cloudcost/prices")
    async def get_prices():
        return await C.prices()

    @r.put("/api/cloudcost/prices")
    async def put_prices(request: Request):
        body = await request.json()
        ch = (body or {}).get("changes")
        if not isinstance(ch, dict) or len(ch) > 200:
            raise HTTPException(400, "changes 객체가 필요합니다")
        try:
            out = await C.save_prices(ch, who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "cloudcost.prices", "", detail={"changes": ch})
        return out

    @r.delete("/api/cloudcost/prices")
    async def reset_prices(request: Request):
        await C.reset_prices(who(request).get("user", ""))
        await audit(request, "cloudcost.prices.reset", "")
        return await C.prices()

    @r.post("/api/cloudcost/prices/refresh")
    async def refresh(request: Request):
        body = await request.json()
        prov = (body or {}).get("provider")
        user = who(request).get("user", "")
        try:
            if prov == "azure":
                res = await C.refresh_azure(user, region=str(body.get("region") or "koreacentral"))
            elif prov == "gcp":
                res = await C.refresh_gcp(str(body.get("api_key") or ""), user, region_desc=str(body.get("region_desc") or "Seoul"))
            else:
                raise HTTPException(400, "provider: azure | gcp (AWS 는 직접 입력)")
        except HTTPException:
            raise
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        except Exception as e:  # noqa: BLE001
            await audit(request, "cloudcost.prices.refresh", prov, result="error", detail=f"{type(e).__name__}: {e}"[:300])
            raise HTTPException(502, f"가져오기 실패: {type(e).__name__}: {e}"[:300]) from None
        await audit(request, "cloudcost.prices.refresh", prov, detail={"updated": res["updated"]})
        return res

    @r.get("/api/cloudcost/openshift/reference")
    async def os_reference():
        return C.os_reference()

    @r.post("/api/cloudcost/iops/collect")
    async def iops_collect(request: Request):
        n = await C.collect_iops()
        await audit(request, "cloudcost.iops.collect", "", detail={"vms": n})
        return {"vms": n, "error": C.stats["error"]}

    return r
