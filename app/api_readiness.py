"""하드웨어 준비도(VCF-R) API(2.14.0) — 조회 view · 스캔 operate · 설정·HCL·BCG settings

  GET  /api/readiness/overview                     대상(BMC 커넥터)·최근 스캔·설정·HCL·BCG 상태
  POST /api/readiness/scans                        {connectors:[…]|'all', targets:'10.0.0.1-5', username, password, port, verify_tls, label, profile} — 계정은 저장 안 함
  GET  /api/readiness/scans · /{id} · /{id}/hosts/{target}
  POST /api/readiness/scans/{id}/cancel · DELETE /api/readiness/scans/{id}
  GET  /api/readiness/scans/{id}/report.html|report.xlsx|report.zip|report.json[?obfuscate=1]
  GET/PUT /api/readiness/settings
  POST /api/readiness/hcl/refresh · PUT /api/readiness/hcl(본문 = all.json[.gz]) · PUT /api/readiness/bcg-cpu(본문 = BCG CPU CSV)
"""
from __future__ import annotations

import io
import json
import time
import zipfile

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from .readiness import export as X
from .readiness import rules as R

NOSTORE = {"Cache-Control": "private, no-store"}


def _dl(name: str) -> dict:
    from .httputil import disposition
    return {"Content-Disposition": disposition(name), **NOSTORE}


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    M = ENGINE.readiness

    @r.get("/api/readiness/overview")
    async def overview():
        await M.load_bcg()
        return {"targets": await M.targets(), "scans": await M.scans(10), "settings": await M.settings(), "hcl": {"loaded": M.hcl.loaded, **(M.hcl.meta or {})},
                "bcg": R.bcg_info(), "running": [M.job_view(k) for k, j in M.jobs.items() if j["status"] == "running"]}

    @r.post("/api/readiness/scans")
    async def start(request: Request):
        b = await request.json()
        try:
            job = await M.start(b if isinstance(b, dict) else {}, who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        except RuntimeError as e:
            raise HTTPException(409, str(e)) from None
        await audit(request, "readiness.scan", job["id"], detail={"targets": job["total"], "connectors": b.get("connectors"),
                                                                  "adhoc": bool(b.get("targets")), "label": b.get("label")})
        return job

    @r.get("/api/readiness/scans")
    async def scans():
        return {"items": await M.scans(100)}

    @r.get("/api/readiness/scans/{sid}")
    async def scan(sid: str):
        s = await M.scan(sid)
        if not s:
            raise HTTPException(404, "없음")
        return s

    @r.get("/api/readiness/scans/{sid}/hosts/{target:path}")
    async def host(sid: str, target: str):
        h = await M.host(sid, target)
        if not h:
            raise HTTPException(404, "없음")
        return h

    @r.post("/api/readiness/scans/{sid}/cancel")
    async def cancel(sid: str, request: Request):
        ok = await M.cancel(sid)
        await audit(request, "readiness.cancel", sid)
        return {"ok": ok}

    @r.delete("/api/readiness/scans/{sid}")
    async def delete(sid: str, request: Request):
        if sid in M.jobs and M.jobs[sid]["status"] == "running":
            raise HTTPException(409, "진행 중인 스캔은 먼저 취소")
        if not await ENGINE.store.q1("SELECT id FROM rd_scans WHERE id=?", (sid,)):
            raise HTTPException(404, "스캔 없음")
        await ENGINE.store.x("DELETE FROM rd_hosts WHERE scan_id=?", (sid,))
        await ENGINE.store.x("DELETE FROM rd_scans WHERE id=?", (sid,))
        await audit(request, "readiness.delete", sid)
        return {"ok": True}

    async def _recs(sid: str, obf: bool):
        meta, recs = await M.records(sid)
        if not meta:
            raise HTTPException(404, "없음")
        fl = meta.get("fleet") or {}
        o = None
        if obf:
            o = X.Obf()
            recs = [o.host_rec(x, i + 1) for i, x in enumerate(recs)]
            fl = o.fleet(fl)
        return meta, recs, fl, o

    @r.get("/api/readiness/scans/{sid}/report.{fmt}")
    async def report(sid: str, fmt: str, request: Request, obfuscate: int = 0):
        if fmt not in ("html", "xlsx", "zip", "json"):
            raise HTTPException(404, "형식: html | xlsx | zip | json")
        meta, recs, fl, o = await _recs(sid, bool(obfuscate))
        await audit(request, "readiness.export", sid, detail={"format": fmt, "obfuscate": bool(obfuscate)})
        tag = "-obfuscated" if obfuscate else ""
        name = f"vcf-readiness-{sid}{tag}"
        if fmt == "html":
            return HTMLResponse(X.report_html(meta, recs, fl, bool(obfuscate)), headers=NOSTORE)
        if fmt == "xlsx":
            data = X.xlsx([(nm, fn(recs)) for nm, fn in X.SHEETS])
            return Response(data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=_dl(name + ".xlsx"))
        if fmt == "json":
            return Response(json.dumps({"scan": {k: meta[k] for k in ("id", "created", "finished", "status", "label")}, "fleet": fl, "hosts": recs}, ensure_ascii=False, default=str),
                            media_type="application/json", headers=_dl(name + ".json"))
        man = {"tool": "VCF AIOps — 하드웨어 준비도", "version": getattr(ENGINE, "version", ""), "scan": sid, "generated": time.time(), "obfuscated": bool(obfuscate),
               "hosts": len(recs), "files": [nm + ".csv" for nm, _ in X.SHEETS] + ["report.html", "report.xlsx", "fleet.json"]}
        buf = io.BytesIO(X.csv_zip(recs, fl, man))
        with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as z:
            z.writestr("report.html", X.report_html(meta, recs, fl, bool(obfuscate)))
            z.writestr("report.xlsx", X.xlsx([(nm, fn(recs)) for nm, fn in X.SHEETS]))
        return Response(buf.getvalue(), media_type="application/zip", headers=_dl(name + ".zip"))

    @r.get("/api/readiness/settings")
    async def get_settings():
        return await M.settings()

    @r.put("/api/readiness/settings")
    async def put_settings(request: Request):
        b = await request.json()
        try:
            st = await M.save_settings(b if isinstance(b, dict) else {}, who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "readiness.settings", "", detail={k: b.get(k) for k in ("schedule_hours", "concurrency", "profile") if k in b})
        return st

    @r.post("/api/readiness/hcl/refresh")
    async def hcl_refresh(request: Request):
        try:
            meta = await M.hcl_refresh(who(request).get("user", ""))
        except Exception as e:  # noqa: BLE001
            await audit(request, "readiness.hcl.refresh", "", result="error", detail=f"{type(e).__name__}: {e}"[:200])
            raise HTTPException(502, f"HCL 받기 실패: {type(e).__name__}: {e}"[:300]) from None
        await audit(request, "readiness.hcl.refresh", "", detail={"entries": meta.get("entries")})
        return meta

    @r.put("/api/readiness/hcl")
    async def hcl_upload(request: Request):
        raw = await request.body()
        if not raw or len(raw) > 200 * 1024 * 1024:
            raise HTTPException(400, "파일이 비었거나 200MB 초과")
        try:
            meta = await M.hcl_upload(raw, who(request).get("user", ""))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(400, f"HCL 파일 오류: {e}"[:300]) from None
        await audit(request, "readiness.hcl.upload", "", detail={"entries": meta.get("entries"), "bytes": len(raw)})
        return meta

    @r.put("/api/readiness/bcg-cpu")
    async def bcg_upload(request: Request):
        raw = await request.body()
        if not raw or len(raw) > 5 * 1024 * 1024:
            raise HTTPException(400, "파일이 비었거나 5MB 초과")
        try:
            info = await M.import_bcg_csv(raw.decode("utf-8-sig", errors="replace"), who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "readiness.bcg.upload", "", detail=info)
        return info

    return r
