"""라이선스 관리 API(2.16.0) — 조회 view · 업로드·할당·수집·프로젝트 operate · 키 전체 보기 operate(감사) · 설정 settings

  GET  /api/license/overview?project=           요약·점검(LIC-*)·키 매칭 통계·프로젝트별 요약
  GET  /api/license/data/{supplier|csp|hosts|licenses|usage|match}?project=     (키 가림)
  GET  /api/license/reveal/{…}?project=          같은 데이터, 키 전체(operate·감사로그)
  GET  /api/license/projects · POST /api/license/projects · PUT/DELETE /api/license/projects/{id}
  POST /api/license/assign {project|null, kind: supplier|csp|source, ids:[…], filter:{customer|folder}}
  POST /api/license/upload/{supplier|csp|vcfops}?name=   (본문 = 파일)
  GET  /api/license/batches · DELETE /api/license/batches/{id}
  GET  /api/license/sources · POST /api/license/collect {connectors:[…]} · POST /api/license/rvtools/{import id}
  POST /api/license/vcfops/{connector}/pull · DELETE /api/license/sources/{id}
  GET  /api/license/report.xlsx?project=&full=0|1 · GET/PUT /api/license/settings · POST /api/license/ai
"""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .httputil import disposition
from .license import manager as LM
from .license import util as U

NOSTORE = {"Cache-Control": "private, no-store"}
KINDS = {"supplier", "csp", "hosts", "licenses", "usage", "match"}


def _proj(project: str | None) -> str | None:
    if project in (None, "*", "all"):
        return None
    return "" if project in ("", "none", "unassigned") else project


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    M = ENGINE.license

    @r.get("/api/license/overview")
    async def overview(project: str = "*"):
        o = await M.overview(_proj(project))
        return {**o, "settings": await M.settings(), "vcenters": [c.name for c in M.vcenters()], "vcfops": [c.name for c in M.vcfops()],
                "llm": bool(ENGINE.llm)}

    @r.get("/api/license/data/{what}")
    async def data(what: str, project: str = "*"):
        if what not in KINDS:
            raise HTTPException(404, "없음")
        return {"items": await M.data(what, _proj(project))}

    @r.get("/api/license/reveal/{what}")
    async def reveal(what: str, request: Request, project: str = "*"):
        if what not in KINDS:
            raise HTTPException(404, "없음")
        await audit(request, "license.reveal", what, detail={"project": project})
        return {"items": await M.data(what, _proj(project), full=True)}

    @r.get("/api/license/projects")
    async def projects():
        return {"items": await M.project_summaries(), "list": await M.projects()}

    @r.post("/api/license/projects")
    async def create(request: Request):
        try:
            p = await M.save_project(await request.json(), who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "license.project.create", p["id"], detail={"name": p["name"]})
        return p

    @r.put("/api/license/projects/{pid}")
    async def update(pid: str, request: Request):
        try:
            p = await M.save_project(await request.json(), who(request).get("user", ""), pid)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        except KeyError:
            raise HTTPException(404, "없음") from None
        await audit(request, "license.project.update", pid, detail={"name": p["name"]})
        return p

    @r.delete("/api/license/projects/{pid}")
    async def delete_project(pid: str, request: Request):
        ok = await M.delete_project(pid)
        await audit(request, "license.project.delete", pid)
        return {"ok": ok}

    @r.post("/api/license/assign")
    async def assign(request: Request):
        b = await request.json()
        try:
            n = await M.assign(b.get("project") or None, str(b.get("kind", "")), list(b.get("ids") or []), b.get("filter"))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        except KeyError:
            raise HTTPException(404, "프로젝트 없음") from None
        await audit(request, "license.assign", str(b.get("project") or "-"), detail={"kind": b.get("kind"), "count": n, "filter": b.get("filter")})
        return {"count": n}

    @r.post("/api/license/upload/{kind}")
    async def upload(kind: str, request: Request, name: str = "upload.xlsx"):
        if kind not in ("supplier", "csp", "vcfops"):
            raise HTTPException(404, "supplier | csp | vcfops")
        if int(request.headers.get("content-length") or 0) > 50 * 1024 * 1024:
            raise HTTPException(413, "파일이 50MB 를 넘습니다")
        buf = bytearray()
        async for ch in request.stream():
            buf += ch
            if len(buf) > 50 * 1024 * 1024:
                raise HTTPException(413, "파일이 50MB 를 넘습니다")
        try:
            out = await M.upload(kind, bytes(buf), name.split("/")[-1].split("\\")[-1], who(request).get("user", ""))
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            raise HTTPException(400, f"{e}") from None
        except Exception as e:  # noqa: BLE001 — 형식 오류(gzip·JWS 등)
            raise HTTPException(400, f"파일을 읽지 못했습니다: {type(e).__name__}: {e}"[:300]) from None
        await audit(request, "license.upload", out.get("id") or out.get("source", ""), detail={"kind": kind, "name": name[:160],
                                                                                                "rows": out.get("rows"), "products": out.get("products")})
        return out

    @r.get("/api/license/batches")
    async def batches():
        return {"items": await M.batches()}

    @r.delete("/api/license/batches/{bid}")
    async def del_batch(bid: str, request: Request):
        ok = await M.delete_batch(bid)
        await audit(request, "license.batch.delete", bid)
        return {"ok": ok}

    @r.get("/api/license/sources")
    async def sources():
        rv = getattr(ENGINE, "rvtools", None)
        return {"items": await M.sources(), "rvtools": (await rv.list()) if rv else [], "vcfops": [c.name for c in M.vcfops()],
                "settings": await M.settings()}

    @r.post("/api/license/collect")
    async def collect(request: Request):
        b = await request.json() if int(request.headers.get("content-length") or 0) else {}
        res = await M.collect_vcenter(b.get("connectors") or None, who(request).get("user", ""))
        await audit(request, "license.collect", ",".join(x["source"] for x in res)[:200], detail={"results": res})
        return {"items": res}

    @r.post("/api/license/rvtools/{iid}")
    async def from_rvtools(iid: str, request: Request):
        try:
            out = await M.import_rvtools(iid, who(request).get("user", ""))
        except KeyError:
            raise HTTPException(404, "RVTools 분석 없음") from None
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "license.rvtools", iid, detail=out)
        return out

    @r.post("/api/license/vcfops/{cname}/pull")
    async def pull(cname: str, request: Request):
        try:
            out = await M.pull_vcfops(cname, who(request).get("user", ""))
        except PermissionError as e:                          # 권한이 아니라 설정 상태(사용량 API 꺼짐) — 409(2.20)
            raise HTTPException(409, str(e)) from None
        except KeyError:
            raise HTTPException(404, "VCF Ops 커넥터 없음") from None
        except RuntimeError as e:
            raise HTTPException(502, str(e)) from None
        await audit(request, "license.vcfops.pull", cname, detail=out)
        return out

    @r.delete("/api/license/sources/{sid:path}")
    async def del_source(sid: str, request: Request):
        ok = await M.delete_source(sid)
        await audit(request, "license.source.delete", sid)
        return {"ok": ok}

    @r.get("/api/license/settings")
    async def get_settings():
        return await M.settings()

    @r.put("/api/license/settings")
    async def put_settings(request: Request):
        s = await M.save_settings(await request.json(), who(request).get("user", ""))
        await audit(request, "license.settings", "", detail=s)
        return s

    @r.get("/api/license/report.xlsx")
    async def report(request: Request, project: str = "*", full: int = 0):
        p = _proj(project)
        if full:                                            # 키 전체 내보내기는 operate(라우트 규칙과 별도로 역할 확인)
            from .security.auth import PERMS
            if (who(request) or {}).get("role") not in PERMS.get("operate", set()):
                raise HTTPException(403, "키 전체 내보내기는 operate 권한 필요")
        sheets = await _sheets(M, p, bool(full))
        from .readiness.export import xlsx
        await audit(request, "license.export", project, detail={"full": bool(full)})
        name = f"license-{time.strftime('%Y%m%d-%H%M')}.xlsx"
        return Response(xlsx(sheets), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": disposition(name), **NOSTORE})

    @r.post("/api/license/ai")
    async def ai(request: Request):
        if not ENGINE.llm:
            raise HTTPException(400, "LLM 비활성 — 설정 › AI 에서 공급자를 켜세요")
        b = await request.json() if int(request.headers.get("content-length") or 0) else {}
        p = _proj(b.get("project", "*"))
        o = await M.overview(p)
        d = {"요약": o["summary"], "키 매칭": o["match"], "점검": [{k: c[k] for k in ("id", "severity", "entity", "title", "detail")} for c in o["checks"][:60]],
             "프로젝트": [{k: x.get(k) for k in ("name", "supplier", "csp", "inventory", "usage")} for x in o["projects"][:30]]}
        sys = ("너는 VMware/Broadcom 라이선스 관리 담당자다. 아래 JSON(공급자 데이터·CSP 데이터·실사용·키 매칭·점검)만 근거로 한국어로 쓴다. "
               "## 종합 · ## 위험(만료·초과·미등록 키) 표 · ## 갱신·VCF 9 전환 시 확인할 것 · ## 바로 할 일. JSON 에 없는 수치·계약 조건은 만들지 않는다. "
               "라이선스 키는 가려진 형태 그대로 쓴다.")
        txt = await ENGINE.llm.complete(sys, json.dumps(d, ensure_ascii=False, default=str)[:14000], max_tokens=2500, task="report",
                                        names=[x["name"] for x in await M.projects()])
        await audit(request, "license.ai", str(b.get("project", "*")))
        return {"report": txt, "at": time.time()}

    return r


async def _sheets(M, p, full: bool) -> list[tuple[str, list[list]]]:
    o = await M.overview(p)
    s = o["summary"]
    mk = (lambda k: k) if full else U.mask_key
    summ = [["항목", "값"], ["공급자 행", s["supplier"]["rows"]], ["CSP 행 · 키", f"{s['csp']['rows']} · {s['csp']['keys']}"],
            ["실사용 호스트 · vCenter", f"{s['inventory']['hosts']} · {s['inventory']['vcenters']}"], ["키 매칭률(%)", o["match"]["rate"]],
            ["매칭 · 실사용만 · CSP만 · 초과", f"{o['match']['matched']} · {o['match']['inventory_only']} · {o['match']['csp_only']} · {o['match']['over']}"]]
    for k, v in s["inventory"]["by_category"].items():
        summ.append([f"실사용 {k} — 호스트·수량(영구=CPU, 구독=코어 16 최소)·물리 코어", f"{v['hosts']} · {v['qty']} · {v['cores']}"])
    for k, v in s["csp"]["by_unit"].items():
        summ.append([f"CSP {k} 유지·만료", f"{v['active']} · {v['expired']}"])
    for k, v in s["supplier"]["by_type"].items():
        summ.append([f"공급자 {k} 유지·만료", f"{v['active']} · {v['expired']}"])
    chk = [["등급", "점검", "대상", "내용", "상세", "조치"]] + [[c["severity"], c["id"], c["entity"], c["title"], c["detail"], c["fix"]] for c in o["checks"]]
    m = [["License Key", "상태", "제품", "구분", "실사용 수량", "호스트", "vCenter 총량", "vCenter 사용", "만료", "CSP 수량", "CSP 단위", "CSP 종료", "초과", "소스"]] + [
        [mk(x["license_key"]), {"matched": "매칭", "inventory_only": "실사용만", "csp_only": "CSP만"}[x["status"]], x["name"], x["category"], x["inv_qty"], x["inv_hosts"],
         x["vc_total"], x["vc_used"], x["expires"], x["csp_qty"], x["csp_unit"], x["csp_end"], "예" if x["over"] else "", ", ".join(x["sources"])]
        for x in await M.data("match", p, full=True)]
    h = [["소스", "vCenter", "클러스터", "호스트", "소켓", "코어", "라이선스 코어(16 최소)", "License Key", "라이선스", "구분", "수량"]] + [
        [x["source_name"], x["vcenter"], x["cluster"], x["host"], x.get("sockets"), x.get("cores"), x["licensed_cores"], mk(x.get("license_key")),
         x.get("license_name"), x["category"], x["qty"]] for x in await M.data("hosts", p, full=True)]
    lic = [["소스", "License Key", "이름", "비용 단위", "구분", "총량", "사용", "만료"]] + [
        [x["source_name"], mk(x.get("key")), x.get("name"), x.get("cost_unit"), x["category"], x.get("total"), x.get("used"), x.get("expires")]
        for x in await M.data("licenses", p, full=True)]
    csp = [["License Key", "제품", "수량", "단위", "폴더", "계약 종료"]] + [
        [mk(x["license_key"]), x["product"], x["quantity"], x["unit"], x["folder"], x["end_date"]] for x in await M.data("csp", p, full=True)]
    sup = [["Serial Number", "Parent Customer", "Customer", "License Key", "License Type", "Product", "Quantity-ENT", "Contract Status", "Start", "End",
            "ERP Site ID", "Enduser", "Part Number", "Division"]] + [
        [x["serial"], x["parent_customer"], x["customer"], mk(x["license_key"]), x["license_type"], x["product"], x["quantity"], x["contract_status"],
         x["start_date"], x["end_date"], x["erp_site_id"], x["enduser"], x["part_number"], x["division"]] for x in await M.data("supplier", p, full=True)]
    us = [["보고서", "제품", "단위", "수량", "자산", "기준 시각"]] + [
        [u["name"], pr["product"], pr["uom"], pr["quantity"], pr["assets"], time.strftime("%Y-%m-%d", time.localtime(u["usage_end"] or u["timestamp"] or 0))]
        for u in await M.data("usage", p, full=True) for pr in u["products"]]
    return [("요약", summ), ("점검", chk), ("키 매칭", m), ("실사용 호스트", h), ("vCenter 라이선스", lic), ("CSP", csp), ("공급자", sup), ("VCF Ops 사용량", us)]


__all__ = ["build_router", "LM"]
