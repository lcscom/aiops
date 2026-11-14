"""RVTools 분석 API(2.15.0) — 조회 view · 업로드·재분석·AI·삭제 operate

  POST   /api/rvtools/upload?name=파일.xlsx          본문 = RVTools 'Export all to xlsx' 파일(원본은 저장하지 않음)
  GET    /api/rvtools                                업로드 목록
  GET    /api/rvtools/{id}                           요약·점검·KISA·VMSA·VCF 9·AI 결과
  GET    /api/rvtools/{id}/graph/{physical|logical|storage}[?vm_limit=]
  GET    /api/rvtools/{id}/table/{vms|hosts|datastores|networks|snapshots|partitions|licenses|vmks|pnics|hbas|paths|health}
  POST   /api/rvtools/{id}/reanalyze · POST /api/rvtools/{id}/ai/report · POST /api/rvtools/{id}/ask (SSE)
  GET    /api/rvtools/{id}/report.xlsx|report.html
  DELETE /api/rvtools/{id}
"""
from __future__ import annotations

import json
import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from .rvtools import analyze as A
from .rvtools import report as RP
from .rvtools.xlsx import XlsxError
from .sanitize import wrap

NOSTORE = {"Cache-Control": "private, no-store"}
TABLES = {"vms", "hosts", "datastores", "networks", "snapshots", "partitions", "licenses", "vmks", "pnics", "hbas", "paths", "health", "dvswitches", "disks", "clusters"}


def _dl(name: str) -> dict:
    return {"Content-Disposition": f"attachment; filename=\"{name.encode('ascii', 'ignore').decode() or 'rvtools'}\"; filename*=UTF-8''{quote(name)}", **NOSTORE}


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    M = ENGINE.rvtools

    async def _get(iid: str):
        g = await M.get(iid)
        if not g:
            raise HTTPException(404, "없음")
        return g

    @r.post("/api/rvtools/upload")
    async def upload(request: Request, name: str = "rvtools.xlsx"):
        cl = int(request.headers.get("content-length") or 0)
        if cl > M.max_mb * 1024 * 1024:
            raise HTTPException(413, f"파일이 {M.max_mb}MB 를 넘습니다")
        buf = bytearray()
        async for chunk in request.stream():
            buf += chunk
            if len(buf) > M.max_mb * 1024 * 1024:
                raise HTTPException(413, f"파일이 {M.max_mb}MB 를 넘습니다")
        t0 = time.time()
        try:
            out = await M.upload(bytes(buf), name, who(request).get("user", ""))
        except (XlsxError, ValueError) as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "rvtools.upload", out["id"], detail={"name": out["name"], "size": len(buf), "vcenters": out["vcenters"], "hosts": out["counts"]["hosts"],
                                                                  "vms": out["counts"]["vms"], "secs": round(time.time() - t0, 1)})
        return out

    @r.get("/api/rvtools")
    async def items():
        return {"items": await M.list(), "llm": bool(ENGINE.llm), "max_mb": M.max_mb, "retention": M.retention}

    @r.get("/api/rvtools/{iid}")
    async def detail(iid: str):
        meta, inv, res = await _get(iid)
        return {"meta": meta, "summary": res["summary"], "findings": res["findings"], "counts": res["counts"], "areas": res["areas"], "score": res["score"],
                "hardening": res["hardening"], "vmsa": res["vmsa"], "vcf9": res["vcf9"], "evaluated": res["evaluated"], "exported": inv["meta"].get("exported"),
                "llm": bool(ENGINE.llm)}

    @r.get("/api/rvtools/{iid}/graph/{kind}")
    async def graph(iid: str, kind: str, vm_limit: int = 400):
        _, inv, _ = await _get(iid)
        vm_limit = max(0, min(vm_limit, 3000))
        if kind == "physical":
            return A.graph_physical(inv)
        if kind == "logical":
            return A.graph_logical(inv, vm_limit)
        if kind == "storage":
            return A.graph_storage(inv, vm_limit)
        raise HTTPException(404, "physical|logical|storage")

    @r.get("/api/rvtools/{iid}/table/{name}")
    async def table(iid: str, name: str):
        if name not in TABLES:
            raise HTTPException(404, "표 없음")
        _, inv, _ = await _get(iid)
        v = inv.get(name)
        items = list(v.values()) if isinstance(v, dict) else (v or [])
        if name in ("licenses", "hosts"):                  # 라이선스 키는 가림(전체 키는 '라이선스 관리'의 키 보기 — operate·감사로그)
            from .license.util import mask_key
            items = [dict(x, key=mask_key(x["key"])) if "key" in x else dict(x, license=mask_key(x.get("license", ""))) for x in items]
        return {"items": items}

    @r.post("/api/rvtools/{iid}/reanalyze")
    async def reanalyze(iid: str, request: Request):
        sm = await M.reanalyze(iid)
        if sm is None:
            raise HTTPException(404, "없음")
        await audit(request, "rvtools.reanalyze", iid)
        return sm

    @r.post("/api/rvtools/{iid}/ai/report")
    async def ai_report(iid: str, request: Request):
        await _get(iid)
        try:
            ai = await M.ai_report(iid, who(request).get("user", ""))
        except RuntimeError as e:
            raise HTTPException(400, str(e)) from None
        except Exception as e:
            raise HTTPException(502, f"AI 분석 실패: {type(e).__name__}: {e}"[:400]) from None
        await audit(request, "rvtools.ai_report", iid, detail={"provider": ai.get("provider"), "secs": ai.get("secs")})
        return ai

    @r.post("/api/rvtools/{iid}/ask")
    async def ask(iid: str, request: Request):
        if not ENGINE.llm:
            raise HTTPException(400, "LLM 비활성")
        _, inv, res = await _get(iid)
        b = await request.json()
        q = str((b or {}).get("question", "")).strip()[:3000]
        if not q:
            raise HTTPException(400, "질문 필요")
        await audit(request, "rvtools.ask", iid, detail={"q": q[:200]})
        ctx = M.ask_context(inv, res, q)
        refs = []
        try:
            if ENGINE.rag.has_any():                       # 사내 KB·TechDocs 가 있으면 근거 문서도 함께(질문만으로 검색 — 고객 개체 이름은 검색어에서 뺌)
                from . import chatctx
                en = await ENGINE.kblink.en_query(q)          # 한국어 질문 → 영문 검색어(라이브러리가 영문 KB)
                qq = chatctx.clean_query(en or q, A.names_of(inv)[:400])
                kc = CFG.get("knowledge") or {}
                refs = chatctx.gate(await ENGINE.rag.search(qq, intent="chat", k=6), max(0.6, float(kc.get("chat_min_rel", 0.5))),
                                    float(kc.get("chat_min_pack_score", 0.3)))[:4] if chatctx.meaningful(qq) else []
        except Exception:
            refs = []
        if refs:
            ctx += "\n\n## 참고 지식([R#]로 인용)\n" + "\n\n".join(f"[R{i}] {x['title']} ({x.get('url', '')})\n" + wrap(x["text"], 1200, "UNTRUSTED_DOC")
                                                           for i, x in enumerate(refs, 1))
        names = A.names_of(inv)

        async def gen():
            yield "data: " + json.dumps({"refs": [{"ref": f"R{i}", "title": x["title"], "url": x.get("url", "")} for i, x in enumerate(refs, 1)]}, ensure_ascii=False) + "\n\n"
            try:
                async for tok in ENGINE.llm.chat_stream(q, ctx, lang=str(b.get("lang") or ""), names=names, system=M.SYSTEM_ASK):
                    yield f"data: {json.dumps({'t': tok}, ensure_ascii=False)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': f'{type(e).__name__}: {e}'}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream", headers=NOSTORE)

    @r.get("/api/rvtools/{iid}/report.xlsx")
    async def rep_xlsx(iid: str, request: Request):
        meta, inv, res = await _get(iid)
        await audit(request, "rvtools.export", iid, detail={"fmt": "xlsx"})
        return Response(RP.xlsx(meta, inv, res), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers=_dl(f"rvtools-analysis-{iid}.xlsx"))

    @r.get("/api/rvtools/{iid}/report.html")
    async def rep_html(iid: str, request: Request, download: int = 0):
        meta, inv, res = await _get(iid)
        await audit(request, "rvtools.export", iid, detail={"fmt": "html"})
        h = RP.report_html(meta, inv, res)
        return HTMLResponse(h, headers=_dl(f"rvtools-analysis-{iid}.html") if download else {**NOSTORE, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})

    @r.delete("/api/rvtools/{iid}")
    async def delete(iid: str, request: Request):
        ok = await M.delete(iid)
        await audit(request, "rvtools.delete", iid)
        return {"ok": ok}

    return r
