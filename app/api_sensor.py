"""2.50.0 API — 현장 센서(안드로이드 폰)

폰(장치 토큰, 로그인 세션 아님 — auth.PUBLIC 에서 열고 여기서 토큰 확인)
  POST /api/sensor/enroll   {code, info}               → {device_id, token, config}   1회용 코드(30분), IP당 10분 10회 실패 제한
  POST /api/sensor/push     Bearer sns_…  {samples, info} → {config, snap}
  POST /api/sensor/snap     Bearer sns_…  image/jpeg 본문(최대 3MB) ?reason=
  GET  /sensor-setup?c=코드        폰에서 여는 설치 안내(APK 받기 + 앱에서 등록 링크) — 유효한 코드일 때만, 아니면 404
  GET  /api/sensor/app.apk?c=코드   센서 앱 APK — 유효한 코드일 때만
화면(로그인)
  GET  /api/sensors                         목록·최신값·상태
  GET  /api/sensors/meta                    측정값·센서 정의, 기본 설정
  GET  /api/sensors/{id}/series?metric=&hours=
  GET  /api/sensors/{id}/snaps              사진 목록
  GET  /api/sensors/{id}/snap/{name}        사진(JPEG)
  POST /api/sensors                         {name, site, note, config} → 등록 코드·QR 내용     (settings)
  PUT  /api/sensors/{id}                    {name, site, note, config, set_home, clear_home}  (settings)
  POST /api/sensors/{id}/reenroll           새 등록 코드(기존 폰 토큰 폐기)                      (settings)
  POST /api/sensors/{id}/snap-now           다음 전송 때 사진 1장                               (operate)
  POST /api/sensors/{id}/retire · DELETE /api/sensors/{id}                                      (settings)
"""
from __future__ import annotations

import html
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from .edgesense import DEFAULT_CONFIG, METRICS, SENSORS


def build_router(ENGINE, S, who, audit, client_ip, public_base) -> APIRouter:
    r = APIRouter()

    def dev_of(request: Request) -> dict:
        h = request.headers.get("authorization") or ""
        d = S.auth(h[7:].strip() if h.lower().startswith("bearer ") else "")
        if not d:
            raise HTTPException(401, "장치 토큰이 없거나 폐기되었습니다 — 앱에서 다시 등록하세요")
        return d

    async def body_json(request: Request, limit: int = 64 * 1024) -> dict:
        raw = await request.body()
        if len(raw) > limit:
            raise HTTPException(413, "요청이 너무 큽니다")
        try:
            import json
            b = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(400, "JSON 형식이 아닙니다") from None
        if not isinstance(b, dict):
            raise HTTPException(400, "JSON 객체가 필요합니다")
        return b

    # ---------------------------------------------------------------- 폰
    @r.post("/api/sensor/enroll")
    async def enroll(request: Request):
        b = await body_json(request)
        ip = client_ip(request)
        try:
            res = await S.enroll(str(b.get("code") or "")[:40], b.get("info") or {}, ip)
        except PermissionError as e:
            await ENGINE.audit.log("sensor.enroll", user="-", ip=ip, result="denied", detail={"reason": str(e)})
            raise HTTPException(403, str(e)) from None
        await ENGINE.audit.log("sensor.enroll", user=f"sensor:{res['device_id']}", ip=ip, target=res["device_id"], result="ok",
                               detail={"model": (b.get("info") or {}).get("model", "")})
        return res

    @r.post("/api/sensor/push")
    async def push(request: Request):
        d = dev_of(request)
        return await S.push(d, await body_json(request, 1024 * 1024), client_ip(request))   # 밀린 값 묶음 포함

    @r.post("/api/sensor/snap")
    async def snap(request: Request, reason: str = ""):
        d = dev_of(request)
        data = await request.body()
        try:
            return await S.snap(d, data, reason)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None

    # ---------------------------------------------------------------- 화면
    @r.get("/api/sensors")
    async def lst():
        if not S._loaded:
            await S.load()
        return {"items": S.list(), "now": time.time(), "stale_seconds": S.stale}

    @r.get("/api/sensors/clusters")
    async def clusters():
        """2.51.0 연결할 vSphere 클러스터 이름(수집된 vCenter 토폴로지)"""
        out: set[str] = set()
        try:
            for c in ENGINE._vcenters():
                out.update((getattr(c, "topology", {}) or {}).get("clusters", {}).keys())
        except Exception:  # noqa: BLE001
            pass
        return {"items": sorted(x for x in out if x)}

    @r.get("/api/sensors/meta")
    async def meta():
        return {"metrics": METRICS, "sensors": SENSORS, "defaults": DEFAULT_CONFIG}

    def g(did: str) -> dict:
        try:
            return S._get(did)
        except KeyError:
            raise HTTPException(404, "장치가 없습니다") from None

    @r.get("/api/sensors/{did}/series")
    async def series(did: str, metric: str = "temp_c", hours: float = 24):
        g(did)
        if metric not in METRICS:
            raise HTTPException(400, "알 수 없는 측정값")
        return {"metric": metric, "points": await S.series(did, metric, hours)}

    @r.get("/api/sensors/{did}/export.csv")
    async def export(did: str, hours: float = 168):
        """2.51.0 측정값 CSV(시각·측정값·값) — 감사·보고용"""
        d = g(did)
        since = time.time() - max(1, min(24 * 30, hours)) * 3600
        rows = await ENGINE.store.q("SELECT ts, m, v FROM sensor_samples WHERE dev=? AND ts>=? ORDER BY ts, m", (did, since))
        import csv
        import io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["time", "metric", "label", "value", "unit"])
        for x in rows:
            meta = METRICS.get(x["m"], {"label": x["m"], "unit": ""})
            w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(x["ts"])), x["m"], meta["label"], x["v"], meta["unit"]])
        from fastapi.responses import Response
        name = f"sensor-{d['id']}-{time.strftime('%Y%m%d')}.csv"
        return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @r.get("/api/sensors/{did}/snaps")
    async def snaps(did: str, limit: int = 60):
        g(did)
        return {"items": await S.snaps(did, limit)}

    @r.get("/api/sensors/{did}/snap/{name}")
    async def snap_file(did: str, name: str):
        p = S.snap_path(did, name)
        if not p:
            raise HTTPException(404, "사진이 없습니다")
        return FileResponse(p, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff"})

    def qr_payload(request: Request, code: str) -> dict:
        base = public_base(request)
        setup = f"{base}/sensor-setup?c={quote(code)}"
        svg = ""
        try:
            import io
            import segno
            buf = io.BytesIO()
            segno.make(setup, error="m").save(buf, kind="svg", scale=4, border=2, xmldecl=False, svgns=True, nl=False, omitsize=True)
            svg = buf.getvalue().decode()
        except Exception:  # noqa: BLE001
            svg = ""
        return {"server": base, "code": code, "setup_url": setup, "qr_svg": svg,
                "uri": f"vcfaiops-sensor://enroll?u={quote(base, safe='')}&c={quote(code)}"}

    APK = Path(__file__).resolve().parent / "static" / "app" / "vcf-aiops-sensor.apk"

    @r.get("/api/sensor/app.apk")
    async def apk(request: Request, c: str = ""):
        if not S._loaded:
            await S.load()
        if not S.code_device(c) or not APK.is_file():
            raise HTTPException(404)
        await ENGINE.audit.log("sensor.apk_download", user="-", ip=client_ip(request), result="ok")
        return FileResponse(APK, media_type="application/vnd.android.package-archive", filename="vcf-aiops-sensor.apk",
                            headers={"Cache-Control": "no-store"})

    @r.get("/sensor-setup", include_in_schema=False)
    async def setup(request: Request, c: str = ""):
        if not S._loaded:
            await S.load()
        d = S.code_device(c)
        if not d:
            raise HTTPException(404)
        base = public_base(request)
        uri = f"vcfaiops-sensor://enroll?u={quote(base, safe='')}&c={quote(c)}"
        left = max(1, int((d["enroll_until"] - time.time()) // 60))
        e = html.escape
        page = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>AIops 센서 설치</title><style>
body{{font:16px/1.55 system-ui,sans-serif;margin:0;padding:22px;color:#1b2a32;background:#f4f6f8}}h1{{font-size:21px;margin:0 0 4px}}
.c{{background:#fff;border:1px solid #dde3e8;border-radius:10px;padding:16px;margin:14px 0}}a.b{{display:block;text-align:center;background:#1a5fbf;color:#fff;
padding:14px;border-radius:8px;text-decoration:none;font-weight:600;margin:10px 0}}code{{font-size:18px;letter-spacing:1px}}small{{color:#5f6b73}}</style></head><body>
<h1>VCF AIops 현장 센서</h1><small>장치: {e(d['name'])}{(' · ' + e(d['site'])) if d.get('site') else ''} · 이 화면은 {left}분 뒤 만료</small>
<div class="c"><b>1. 앱 설치</b><a class="b" href="/api/sensor/app.apk?c={e(quote(c))}">센서 앱(APK) 받기</a>
<small>받은 파일을 열어 설치합니다. '출처를 알 수 없는 앱' 허용을 물으면 이 브라우저에 허용하세요.</small></div>
<div class="c"><b>2. 등록</b><a class="b" href="{e(uri)}">앱에서 등록하기</a>
<small>앱이 열리지 않으면 앱에 직접 입력 — 서버 <code>{e(base)}</code><br>등록 코드 <code>{e(c.upper())}</code></small></div>
<div class="c"><b>3. 권한·위치</b><br><small>앱에서 카메라·마이크·위치·알림을 허용하고, 폰을 충전기에 꽂아 감시할 자리에 둡니다. 소리는 크기만 재고 녹음하지 않습니다.</small></div>
</body></html>"""
        return HTMLResponse(page, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"})

    @r.post("/api/sensors")
    async def create(request: Request):
        b = await body_json(request)
        try:
            res = await S.create(str(b.get("name") or ""), str(b.get("site") or ""), str(b.get("note") or ""), b.get("config") or None)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "sensor.create", res["device"]["id"], detail={"site": res["device"]["site"]})
        return {**res, "enroll": qr_payload(request, res["code"])}

    @r.put("/api/sensors/{did}")
    async def upd(did: str, request: Request):
        g(did)
        b = await body_json(request)
        try:
            res = await S.update(did, b)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "sensor.update", did, detail={k: b[k] for k in b if k != "config"} | ({"config": list(b["config"])} if isinstance(b.get("config"), dict) else {}))
        return res

    @r.post("/api/sensors/{did}/reenroll")
    async def reenroll(did: str, request: Request):
        g(did)
        res = await S.reenroll(did)
        await audit(request, "sensor.reenroll", did)
        return {**res, "enroll": qr_payload(request, res["code"])}

    @r.post("/api/sensors/{did}/snap-now")
    async def snap_now(did: str, request: Request):
        d = g(did)
        if "camera" not in d["config"]["sensors"]:
            raise HTTPException(400, "이 장치는 카메라가 꺼져 있습니다(설정에서 켜기)")
        S.request_snap(did)
        await audit(request, "sensor.snap_request", did)
        return {"ok": True, "next_push_within_s": d["config"]["interval_s"]}

    @r.post("/api/sensors/{did}/retire")
    async def retire(did: str, request: Request):
        g(did)
        await S.retire(did)
        await audit(request, "sensor.retire", did)
        return {"ok": True}

    @r.delete("/api/sensors/{did}")
    async def delete(did: str, request: Request):
        g(did)
        await S.delete(did)
        await audit(request, "sensor.delete", did)
        return {"ok": True}

    return r
