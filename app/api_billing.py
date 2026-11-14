"""정산(Billing) API — 조회는 view, 테넌트·프로젝트·요율 변경은 settings(관리자), 즉시 표본은 operate.

  GET    /api/billing/report?period=mtd|7d|30d|month|custom&month=YYYY-MM&start=&end=&tenant=   기간 보고서(테넌트→프로젝트→VM)
  GET    /api/billing/report.csv                                                              같은 조건 CSV(UTF-8 BOM)
  GET    /api/billing/statement?tenant=<id>&period=month&month=YYYY-MM                         테넌트 명세서(인쇄용 HTML)
  GET    /api/billing/config                                                                  테넌트·프로젝트·요율표·인벤토리 선택지·표본 상태
  POST   /api/billing/tenants · PUT/DELETE /api/billing/tenants/{id}
  POST   /api/billing/projects · PUT/DELETE /api/billing/projects/{id}
  POST   /api/billing/rates · PUT/DELETE /api/billing/rates/{id}                               요율 수정 = 새 버전(적용 시작 시각)
  POST   /api/billing/sample                                                                  지금 5분 블록 표본(이미 기록됐으면 0)
테넌트에 계정을 지정하면 그 계정(관리자 제외)은 자기 테넌트만 조회한다.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from .billing import period_range


def build_router(ENGINE, CFG: dict, who, audit, allowed) -> APIRouter:
    r = APIRouter()
    B = ENGINE.billing

    async def scope(request: Request) -> set[int] | None:
        u = who(request)
        if u.get("role") == "admin":
            return None
        mine = {t["id"] for t in await B.tenants() if u.get("user") in (t.get("users") or [])}
        return mine or None

    def rng(period: str, month: str, start: str, end: str):
        try:
            return period_range(period, month, start, end)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, f"기간 형식 오류: {e}")

    async def build(request: Request, period: str, month: str, start: str, end: str, tenant: int, detail: bool = True):
        s, e, label = rng(period, month, start, end)
        sc = await scope(request)
        ids = {tenant} if tenant else None
        if sc is not None:
            if ids and not ids <= sc:
                raise HTTPException(403, "이 테넌트를 조회할 권한이 없습니다")
            ids = ids or sc
        return await B.report(s, e, label, ids, vm_detail=detail)

    @r.get("/api/billing/report")
    async def report(request: Request, period: str = "mtd", month: str = "", start: str = "", end: str = "", tenant: int = 0, detail: bool = True):
        return await build(request, period, month, start, end, tenant, detail)

    @r.get("/api/billing/report.csv")
    async def report_csv(request: Request, period: str = "mtd", month: str = "", start: str = "", end: str = "", tenant: int = 0):
        rep = await build(request, period, month, start, end, tenant)
        await audit(request, "billing.export", detail={"period": rep["period"]["label"], "tenant": tenant or "all"})
        return Response(B.to_csv(rep), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-aiops-billing-{time.strftime("%Y%m%d")}.csv"'})

    @r.get("/api/billing/statement", response_class=HTMLResponse)
    async def statement(request: Request, tenant: int, period: str = "month", month: str = "", start: str = "", end: str = ""):
        if period == "month" and not month:
            month = time.strftime("%Y-%m")
        rep = await build(request, period, month, start, end, tenant)
        t = next((x for x in rep["tenants"] if x["id"] == tenant), None)
        if not t:
            raise HTTPException(404, "테넌트를 찾을 수 없습니다")
        await audit(request, "billing.statement", target=t["name"], detail={"period": rep["period"]["label"]})
        return HTMLResponse(B.statement_html(rep, t))

    @r.get("/api/billing/config")
    async def config(request: Request):
        sc = await scope(request)
        ts = await B.tenants()
        if sc is not None:
            ts = [t for t in ts if t["id"] in sc]
        return {"tenants": ts, "rates": await B.rates(), "choices": await B.inventory_choices() if sc is None else {},
                "sampler": B.stats, "enabled": B.enabled, "retention_days": B.retention_days, "currency": B.currency,
                "can_edit": allowed(request, "settings"), "scoped": sc is not None}

    async def body(request: Request) -> dict:
        try:
            d = await request.json()
        except ValueError:
            raise HTTPException(400, "JSON 본문이 필요합니다")
        if not isinstance(d, dict):
            raise HTTPException(400, "JSON 객체가 필요합니다")
        return d

    def guard(fn):
        async def run(*a, **k):
            try:
                return await fn(*a, **k)
            except ValueError as e:
                raise HTTPException(400, str(e))
            except Exception as e:  # noqa: BLE001
                if "UNIQUE" in str(e):
                    raise HTTPException(409, "같은 이름이 이미 있습니다")
                raise
        return run

    @r.post("/api/billing/tenants")
    async def t_add(request: Request):
        d = await body(request)
        tid = await guard(B.save_tenant)(d)
        await audit(request, "billing.tenant.create", target=str(d.get("name")))
        return {"id": tid}

    @r.put("/api/billing/tenants/{tid}")
    async def t_put(tid: int, request: Request):
        d = await body(request)
        await guard(B.save_tenant)(d, tid)
        await audit(request, "billing.tenant.update", target=str(d.get("name")))
        return {"id": tid}

    @r.delete("/api/billing/tenants/{tid}")
    async def t_del(tid: int, request: Request):
        await B.delete_tenant(tid)
        await audit(request, "billing.tenant.delete", target=str(tid))
        return {"ok": True}

    @r.post("/api/billing/projects")
    async def p_add(request: Request):
        d = await body(request)
        pid = await guard(B.save_project)(d)
        await audit(request, "billing.project.create", target=str(d.get("name")), detail={k: d.get(k) for k in ("tenant_id", "clusters", "folders", "tags", "vms")})
        return {"id": pid}

    @r.put("/api/billing/projects/{pid}")
    async def p_put(pid: int, request: Request):
        d = await body(request)
        await guard(B.save_project)(d, pid)
        await audit(request, "billing.project.update", target=str(d.get("name")), detail={k: d.get(k) for k in ("tenant_id", "clusters", "folders", "tags", "vms")})
        return {"id": pid}

    @r.delete("/api/billing/projects/{pid}")
    async def p_del(pid: int, request: Request):
        await B.delete_project(pid)
        await audit(request, "billing.project.delete", target=str(pid))
        return {"ok": True}

    @r.post("/api/billing/rates")
    async def r_add(request: Request):
        d = await body(request)
        rid = await guard(B.save_rate)(d, who(request).get("user", ""))
        await audit(request, "billing.rate.create", target=str(d.get("name")), detail={k: d.get(k) for k in ("vcpu_hour", "mem_gb_hour", "disk_gb_hour", "weighting", "min_weight")})
        return {"id": rid}

    @r.put("/api/billing/rates/{rid}")
    async def r_put(rid: int, request: Request):
        d = await body(request)
        await guard(B.save_rate)(d, who(request).get("user", ""), rid)
        await audit(request, "billing.rate.update", target=str(d.get("name")),
                    detail={k: d.get(k) for k in ("vcpu_hour", "mem_gb_hour", "disk_gb_hour", "weighting", "min_weight", "effective_from")})
        return {"id": rid}

    @r.delete("/api/billing/rates/{rid}")
    async def r_del(rid: int, request: Request):
        await guard(B.delete_rate)(rid)
        await audit(request, "billing.rate.delete", target=str(rid))
        return {"ok": True}

    @r.post("/api/billing/sample")
    async def sample(request: Request):
        n = await B.sample()
        return {"sampled": n, "stats": B.stats}

    return r
