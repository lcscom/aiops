"""지원 요청(SR)·로그 내보내기 API(2.11.0)

  GET  /api/support/meta                              벤더 양식(심각도·포털 입력 항목·참고 문서)·기본 정보·상태
  GET  /api/support/profile · PUT(settings)           회사·연락처·Site ID·AWS 계정·Azure 구독·기본 수신자
  GET  /api/support/requests?status=&q=               목록
  POST /api/support/requests                          {source:{kind: incident|anomaly|vks|host|vm|manual|readiness, ...}, vendor, lang, severity, title}
  GET  /api/support/requests/{id}                     보고서 데이터 + 이메일(제목·본문) + 공유 링크 목록
  PUT  /api/support/requests/{id}                     편집(제목·요약·영향·심각도·벤더·언어·포털 값·요청·수신자·상태·케이스 번호)
  DELETE /api/support/requests/{id}
  POST /api/support/requests/{id}/refresh             근거 다시 모으기(편집 내용 유지)
  POST /api/support/requests/{id}/refine              AI 로 제목·요약·영향·요청 다듬기(가명화 규칙 적용) — 결과는 미리보기, apply=true 면 저장
  GET  /api/support/requests/{id}/report.html|report.pdf|email.txt|email.eml|logs.zip
  POST /api/support/requests/{id}/share               {days, require_login, include_logs} → URL(토큰은 이때 한 번만 표시)
  DELETE /api/support/requests/{id}/share/{sid}       폐기
  GET  /share/sr/{token}[/report.pdf|/logs.zip]       공유 보고서(토큰·만료·폐기·로그인 요구 확인, 열람 감사)
  GET  /api/logs/export?format=csv|txt|ndjson|zip&minutes=|since=&until=&source=&connector=&host=&entity=&min_severity=&q=&kind=
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

from . import logexport
from .support import LANGS, STATUSES, VENDORS

NOSTORE = {"Cache-Control": "private, no-store", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}


_EXPORTS = {"n": 0}
_MAX_SPAN = 90 * 86400


def _span(minutes: float, since: float, until: float) -> tuple[float, float]:
    """로그 내보내기 기간 — 최대 90일, 미래·음수 시각 보정(2.20)"""
    now = time.time()
    until = min(until or now, now + 60)
    since = since or until - max(1.0, min(minutes, 60 * 24 * 90)) * 60
    since = max(since, until - _MAX_SPAN, 0.0)
    if since >= until:
        raise HTTPException(400, "기간 오류")
    return since, until


def _dl(name: str) -> dict:
    from .httputil import disposition
    return {"Content-Disposition": disposition(name), **NOSTORE}


def build_router(ENGINE, AUTH, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    S = ENGINE.support

    def base_url(request: Request) -> str:
        pub = (CFG.get("server") or {}).get("public_url") or ""
        return (pub or str(request.base_url)).rstrip("/")

    async def get_or_404(sr_id: str) -> dict:
        x = await S.get(sr_id)
        if not x:
            raise HTTPException(404, "SR 없음")
        return x

    def payload(x: dict, request: Request) -> dict:
        b = f"/api/support/requests/{x['id']}"
        return {"id": x["id"], "status": x["status"], "created": x["created"], "updated": x["updated"], "created_by": x["created_by"],
                "data": {k: v for k, v in x["data"].items() if k != "attach_files"},
                "attach_files": [{"name": k, "bytes": len(v)} for k, v in (x["data"].get("attach_files") or {}).items()],
                "email": {"subject": S.subject(x), "body": S.email_text(x), "to": (x["data"].get("email") or {}).get("to", ""),
                          "cc": (x["data"].get("email") or {}).get("cc", "")},
                "en": {"pending": S.en_pending(x["data"])[:50], "pending_count": len(S.en_pending(x["data"])), "stale": S.en_stale(x["data"]),
                       "translated": x["data"].get("translated"), "error": x["data"].get("translate_error", "")},
                "links": {"html": f"{b}/report.html", "pdf": f"{b}/report.pdf", "eml": f"{b}/email.eml", "txt": f"{b}/email.txt", "logs": f"{b}/logs.zip"}}

    @r.get("/api/support/meta")
    async def meta():
        return {"vendors": {k: {"label": v["label"], "portal": v["portal"], "sev": {str(n): {"code": t[0], "label": t[1], "desc": t[2], "desc_en": t[3] if len(t) > 3 else t[2]} for n, t in v["sev"].items()},
                                "fields": [{"key": k2, "label": lab} for k2, lab, _ in v["fields"]], "notes": v["notes"], "refs": v["refs"]} for k, v in VENDORS.items()},
                "statuses": STATUSES, "langs": list(LANGS), "profile": await S.profile(), "llm": bool(getattr(ENGINE, "llm", None))}

    @r.get("/api/support/profile")
    async def profile_get():
        return await S.profile()

    @r.put("/api/support/profile")
    async def profile_put(request: Request):
        p = await S.save_profile(await request.json())
        await audit(request, "support.profile")
        return p

    @r.get("/api/support/requests")
    async def sr_list(status: str = "", q: str = "", limit: int = 300):
        return {"items": await S.list(status[:20], q[:120], limit)}

    @r.post("/api/support/requests")
    async def sr_create(request: Request):
        b = await request.json()
        src = b.get("source") or {}
        if src.get("kind") not in ("incident", "anomaly", "vks", "host", "vm", "entity", "manual", "readiness"):
            raise HTTPException(400, "source.kind 은 incident·anomaly·vks·host·vm·manual·readiness 중 하나")
        try:
            x = await S.create(src, who(request), b)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e
        except KeyError as e:
            raise HTTPException(404, f"대상 없음: {e}") from e
        await audit(request, "support.create", x["id"], detail={"source": src.get("kind"), "ref": str(src.get("ref") or src.get("obj") or "")[:120]})
        return payload(x, request)

    @r.get("/api/support/requests/{sr_id}")
    async def sr_get(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        out = payload(x, request)
        out["shares"] = await S.shares(sr_id)
        return out

    @r.put("/api/support/requests/{sr_id}")
    async def sr_put(sr_id: str, request: Request):
        try:
            x = await S.update(sr_id, await request.json(), who(request))
        except KeyError as e:
            raise HTTPException(404, "SR 없음") from e
        await audit(request, "support.update", sr_id)
        out = payload(x, request)
        out["shares"] = await S.shares(sr_id)
        return out

    @r.delete("/api/support/requests/{sr_id}")
    async def sr_delete(sr_id: str, request: Request):
        if not await S.delete(sr_id):
            raise HTTPException(404, "SR 없음")
        await audit(request, "support.delete", sr_id)
        return {"ok": True}

    @r.post("/api/support/requests/{sr_id}/refresh")
    async def sr_refresh(sr_id: str, request: Request):
        try:
            x = await S.refresh(sr_id)
        except (KeyError, LookupError):
            raise HTTPException(404, "SR 없음") from None
        await audit(request, "support.refresh", sr_id)
        out = payload(x, request)
        out["shares"] = await S.shares(sr_id)
        return out

    @r.post("/api/support/requests/{sr_id}/refine")
    async def sr_refine(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        b = await request.json() if request.headers.get("content-length") not in (None, "0") else {}
        try:
            prop = await S.refine(x)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"AI 다듬기 실패: {type(e).__name__}: {e}"[:300]) from e
        if b.get("apply"):
            x = await S.update(sr_id, {k: v for k, v in prop.items() if k in ("title", "summary", "impact", "requests", "title_en", "summary_en", "impact_en", "requests_en")}, who(request))
            x["data"]["refined"] = prop.get("refined")
            await S._save(x)
        await audit(request, "support.refine", sr_id, detail={"apply": bool(b.get("apply"))})
        return {"proposal": prop, "applied": bool(b.get("apply"))}

    @r.post("/api/support/requests/{sr_id}/translate")
    async def sr_translate(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        b = await request.json() if request.headers.get("content-length") not in (None, "0") else {}
        try:
            res = await S.translate(x, stale=bool(b.get("stale")))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"영문 번역 실패: {type(e).__name__}: {e}"[:300]) from e
        await audit(request, "support.translate", sr_id, detail=res)
        out = payload(await get_or_404(sr_id), request)
        out["shares"] = await S.shares(sr_id)
        out["result"] = res
        return out

    @r.get("/api/support/requests/{sr_id}/report.html")
    async def sr_html(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        b = f"/api/support/requests/{sr_id}"
        return HTMLResponse(S.html(x, {"pdf": f"{b}/report.pdf", "logs": f"{b}/logs.zip"}), headers=NOSTORE)

    @r.get("/api/support/requests/{sr_id}/report.pdf")
    async def sr_pdf(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        await audit(request, "support.download", sr_id, detail={"file": "pdf"})
        return Response(await asyncio.to_thread(S.pdf, x), media_type="application/pdf", headers=_dl(f"report-{sr_id}.pdf"))

    @r.get("/api/support/requests/{sr_id}/email.txt")
    async def sr_txt(sr_id: str):
        x = await get_or_404(sr_id)
        return Response(f"Subject: {S.subject(x)}\n\n{S.email_text(x)}", media_type="text/plain; charset=utf-8", headers=_dl(f"email-{sr_id}.txt"))

    @r.get("/api/support/requests/{sr_id}/email.eml")
    async def sr_eml(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        z = await S.logs_zip(x, with_report=False)
        await audit(request, "support.download", sr_id, detail={"file": "eml"})
        return Response(S.eml(x, await asyncio.to_thread(S.pdf, x), z), media_type="message/rfc822", headers=_dl(f"SR-draft-{sr_id}.eml"))

    @r.get("/api/support/requests/{sr_id}/logs.zip")
    async def sr_logs(sr_id: str, request: Request):
        x = await get_or_404(sr_id)
        z = await S.logs_zip(x)
        await audit(request, "support.download", sr_id, detail={"file": "logs.zip", "bytes": len(z)})
        return Response(z, media_type="application/zip", headers=_dl(f"logs-{sr_id}.zip"))

    @r.post("/api/support/requests/{sr_id}/share")
    async def sr_share(sr_id: str, request: Request):
        await get_or_404(sr_id)
        b = await request.json()
        s = await S.share_create(sr_id, who(request).get("user", ""), b.get("days") or (await S.profile())["share_days"],
                                 bool(b.get("require_login")), b.get("include_logs", True) is not False)
        url = f"{base_url(request)}/share/sr/{s['token']}"
        await audit(request, "support.share", sr_id, detail={"share": s["id"], "expires": s["expires"], "require_login": s["require_login"], "include_logs": s["include_logs"]})
        return {**{k: v for k, v in s.items() if k != "token"}, "url": url, "note": "이 URL 은 지금 한 번만 표시됩니다(서버에는 해시만 저장)."}

    @r.delete("/api/support/requests/{sr_id}/share/{sid}")
    async def sr_share_del(sr_id: str, sid: str, request: Request):
        if not await S.share_revoke(sr_id, sid):
            raise HTTPException(404, "공유 링크 없음")
        await audit(request, "support.share_revoke", sr_id, detail={"share": sid})
        return {"ok": True}

    # ---------------------------------------------------------------- 공유 페이지(토큰)
    async def shared(token: str, request: Request):
        res = await S.share_resolve(token)
        if not res:
            raise HTTPException(404, "링크가 없거나 만료·폐기되었습니다")
        s, x = res
        user = None
        if s["require_login"]:
            sess = AUTH.session(request) if AUTH.enabled else {"user": "anonymous"}
            if not sess:
                return None, None, RedirectResponse(f"/login?next={quote(str(request.url.path))}")
            user = sess.get("user") if isinstance(sess, dict) else getattr(sess, "user", None)
        await ENGINE.audit.log("support.share_open", user=user or "(link)", role="", ip=(request.client.host if request.client else ""),
                               target=x["id"], result="ok", detail={"share": s["id"], "path": request.url.path[-20:]})
        return s, x, None

    @r.get("/share/sr/{token}")
    async def share_page(token: str, request: Request):
        s, x, redir = await shared(token, request)
        if redir:
            return redir
        links = {"pdf": f"/share/sr/{token}/report.pdf"}
        if s["include_logs"]:
            links["logs"] = f"/share/sr/{token}/logs.zip"
        return HTMLResponse(S.html(x, links, shared=True), headers={**NOSTORE, "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"})

    @r.get("/share/sr/{token}/report.pdf")
    async def share_pdf(token: str, request: Request):
        s, x, redir = await shared(token, request)
        if redir:
            return redir
        return Response(await asyncio.to_thread(S.pdf, x), media_type="application/pdf", headers=_dl(f"report-{x['id']}.pdf"))

    @r.get("/share/sr/{token}/logs.zip")
    async def share_logs(token: str, request: Request):
        s, x, redir = await shared(token, request)
        if redir:
            return redir
        if not s["include_logs"]:
            raise HTTPException(403, "이 링크는 로그 내려받기를 허용하지 않습니다")
        return Response(await S.logs_zip(x), media_type="application/zip", headers=_dl(f"logs-{x['id']}.zip"))

    # ---------------------------------------------------------------- 로그 내보내기
    @r.get("/api/logs/export")
    async def logs_export(request: Request, format: str = "csv", minutes: float = 60, since: float = 0, until: float = 0, source: str = "",
                          connector: str = "", host: str = "", entity: str = "", min_severity: str = "debug", q: str = "", kind: str = "",
                          max_rows: int = 200_000, name: str = ""):
        fmt = format if format in ("csv", "txt", "ndjson", "zip") else "csv"
        since, until = _span(minutes, since, until)
        max_rows = max(1, min(int(max_rows), 500_000))
        if _EXPORTS["n"] >= 2:                                  # 동시 내보내기 2건까지(대용량 요청이 서버를 잠식하지 않게, 2.20)
            raise HTTPException(429, "다른 로그 내보내기가 진행 중입니다 — 잠시 후 다시 시도하세요")
        sp = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]   # noqa: E731
        lq = logexport.LogQuery(since, until, sp(source), sp(connector), sp(host), sp(entity), min_severity, q, sp(kind), max_rows)
        stem = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (name or "logs"))[:60] or "logs"
        fname = f"{stem}-{datetime.fromtimestamp(since).strftime('%Y%m%d-%H%M')}-{datetime.fromtimestamp(until).strftime('%H%M')}.{ 'log' if fmt == 'txt' else fmt}"
        await audit(request, "logs.export", detail={**lq.describe(), "format": fmt})
        if fmt == "zip":
            _EXPORTS["n"] += 1
            try:
                return Response(await logexport.build_zip(ENGINE.store, lq), media_type="application/zip", headers=_dl(fname))
            finally:
                _EXPORTS["n"] -= 1
        mt = {"csv": "text/csv; charset=utf-8", "ndjson": "application/x-ndjson", "txt": "text/plain; charset=utf-8"}[fmt]

        async def counted():
            _EXPORTS["n"] += 1
            try:
                async for chunk in logexport.stream(ENGINE.store, lq, fmt):
                    yield chunk
            finally:
                _EXPORTS["n"] -= 1
        return StreamingResponse(counted(), media_type=mt, headers=_dl(fname))

    @r.get("/api/logs/export/count")
    async def logs_export_count(minutes: float = 60, since: float = 0, until: float = 0, source: str = "", connector: str = "", host: str = "",
                                entity: str = "", min_severity: str = "debug", q: str = "", kind: str = ""):
        since, until = _span(minutes, since, until)
        sp = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]   # noqa: E731
        lq = logexport.LogQuery(since, until, sp(source), sp(connector), sp(host), sp(entity), min_severity, q, sp(kind))
        return {"rows": await logexport.count(ENGINE.store, lq), "since": since, "until": until}

    return r
