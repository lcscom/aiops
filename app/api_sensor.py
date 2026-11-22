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
2.54.0
  POST /api/sensors/maint                   {ids|site, minutes, reason} 작업 모드 = 유지보수 창(출처 sensor, 대상 장치)  (operate)
  POST /api/sensors/maint/{mid}/end         작업 모드 일찍 끝내기                                 (operate)
  GET  /api/sensors/{id}/baseline?metric=   시간대별 평소 값(중앙값·변동 폭) · POST …/baseline/rebuild (settings)
  GET  /api/sensors/{id}/calibrate          보정 기록·비교 후보 · POST {what, reference | from_device}  (settings)
  GET  /api/sensors/{id}/events             장치 경보 기록
  POST /api/sensors/bulk                    {ids, action: config|command|snap, ...} 여러 대 한 번에   (settings)
  GET  /api/sensors/summary?days=7          기간 환경 요약(최저·평균·최고, 기준 초과 시간, 수신율, 경보 수)
"""
from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from .edgesense import BASE_METRICS, CALIB, COMMANDS, DEFAULT_CONFIG, METRICS, SENSORS, URL_RX
from . import sensorprov


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
    # 2.54.0 작업 모드 — 새 억제 장치를 만들지 않고 기존 유지보수 창(출처 sensor + 장치 개체)으로 만든다
    INC = getattr(ENGINE, "incidents", None)

    def _maint_of(items: list[dict]) -> None:
        now = time.time()
        wins = [m for m in (getattr(INC, "maint_cache", None) or []) if INC._in_window(m, now)]
        for it in items:
            ev = {"host": it["name"], "entity": f"sensor:{it['id']}", "source": "sensor"}
            for m in wins:
                try:
                    if INC._scope_match(m.get("scope") or {}, ev, None):
                        it["maint"] = {"id": m["id"], "name": m["name"], "end": None if m.get("weekly") else m.get("end"),
                                       "sensor": str((m.get("scope") or {}).get("hosts_regex") or "").startswith("^sensor:")}
                        break
                except re.error:
                    continue

    @r.get("/api/sensors")
    async def lst():
        if not S._loaded:
            await S.load()
        items = S.list()
        if INC:
            _maint_of(items)
        return {"items": items, "now": time.time(), "stale_seconds": S.stale}

    @r.get("/api/sensors/summary")
    async def summary(days: float = 7):
        now = time.time()
        return await S.summary(now - max(1, min(90, days)) * 86400, now)

    @r.post("/api/sensors/maint")
    async def maint_start(request: Request):
        if not INC:
            raise HTTPException(503, "유지보수 창을 쓸 수 없습니다")
        b = await body_json(request)
        if not S._loaded:
            await S.load()
        ids = [str(x) for x in (b.get("ids") or []) if str(x) in S.devs]
        site = str(b.get("site") or "").strip()
        if site and not ids:
            ids = [d["id"] for d in S.devs.values() if (d.get("site") or "") == site and not d.get("retired")]
        if not ids:
            raise HTTPException(400, "작업 모드로 둘 장치(ids) 또는 사이트(site)를 지정하세요")
        try:
            minutes = int(float(b.get("minutes") or 60))
        except (TypeError, ValueError):
            raise HTTPException(400, "시간(분)") from None
        minutes = max(10, min(24 * 60, minutes))
        reason = str(b.get("reason") or "").strip()[:60]
        now = time.time()
        label = site or (S.devs[ids[0]]["name"] + (f" 외 {len(ids) - 1}대" if len(ids) > 1 else ""))
        name = f"현장 센서 작업 — {label}" + (f" ({reason})" if reason else "")
        scope = {"hosts_regex": "^sensor:(" + "|".join(re.escape(i) for i in ids) + ")$", "clusters": [], "sources": ["sensor"]}
        u = who(request).get("user", "")
        mid = await ENGINE.store.x("INSERT INTO maintenance(name,start,end,weekly,scope,enabled,created_by,created) VALUES(?,?,?,?,?,?,?,?)",
                                   (name[:100], now, now + minutes * 60, None, json.dumps(scope, ensure_ascii=False), 1, u, now))
        await INC.reload_suppression()
        await audit(request, "sensor.maint_start", ",".join(ids)[:200], detail={"id": mid, "minutes": minutes, "reason": reason, "site": site})
        return {"ok": True, "id": mid, "ids": ids, "end": now + minutes * 60, "name": name}

    @r.post("/api/sensors/maint/{mid}/end")
    async def maint_end(mid: int, request: Request):
        if not INC:
            raise HTTPException(503, "유지보수 창을 쓸 수 없습니다")
        row = await ENGINE.store.q1("SELECT id, scope FROM maintenance WHERE id=?", (mid,))
        sc = json.loads((row or {}).get("scope") or "{}") if row else {}
        if not row or not str(sc.get("hosts_regex") or "").startswith("^sensor:") or sc.get("sources") != ["sensor"]:
            raise HTTPException(404, "현장 센서 작업 모드가 아닙니다(일반 유지보수 창은 설정 › 유지보수에서)")
        await ENGINE.store.x("UPDATE maintenance SET enabled=0, end=? WHERE id=?", (time.time(), mid))
        await INC.reload_suppression()
        await audit(request, "sensor.maint_end", str(mid))
        return {"ok": True}

    @r.post("/api/sensors/bulk")
    async def bulk(request: Request):
        """여러 대 한 번에 — 설정 일부(config)·원격 명령(command)·사진(snap). 장치마다 결과"""
        b = await body_json(request, 256 * 1024)
        if not S._loaded:
            await S.load()
        ids = [str(x) for x in (b.get("ids") or [])][:200]
        act = str(b.get("action") or "")
        if act not in ("config", "command", "snap") or not ids:
            raise HTTPException(400, "ids 와 action(config|command|snap)")
        if act == "config" and not isinstance(b.get("config"), dict):
            raise HTTPException(400, "config 객체가 필요합니다")
        if act == "command" and str(b.get("op") or "") not in COMMANDS:
            raise HTTPException(400, "모르는 명령")
        u = who(request).get("user", "")
        out = []
        for did in ids:
            d = S.devs.get(did)
            if not d or d.get("retired"):
                out.append({"id": did, "ok": False, "msg": "없는 장치 또는 퇴역"})
                continue
            try:
                if act == "config":
                    cfg = dict(b["config"])
                    if isinstance(cfg.get("thresholds"), dict):                # 일괄은 바꾼 칸만(다른 경고·위험 칸은 장치 값 유지)
                        cfg["thresholds"] = {m: {**(d["config"]["thresholds"].get(m) or {}), **t} for m, t in cfg["thresholds"].items() if isinstance(t, dict)}
                    await S.update(did, {"config": cfg})
                    out.append({"id": did, "ok": True, "msg": "다음 전송 때 적용"})
                elif act == "command":
                    if not d.get("enrolled"):
                        raise ValueError("등록 전 장치")
                    r_ = await S.add_command(did, str(b["op"]), b.get("args") or {}, u)
                    out.append({"id": did, "ok": True, "msg": r_["warn"] or "대기(다음 전송 때)", "cmd": r_["id"]})
                else:
                    if "camera" not in d["config"]["sensors"]:
                        raise ValueError("카메라 꺼짐")
                    S.request_snap(did)
                    out.append({"id": did, "ok": True, "msg": "다음 전송 때 촬영"})
            except (ValueError, TypeError) as e:
                out.append({"id": did, "ok": False, "msg": str(e)[:200]})
        await audit(request, "sensor.bulk", act, detail={"ids": ids[:50], "n": len(ids), "op": b.get("op"),
                                                         "config": list(b["config"]) if act == "config" else None,
                                                         "ok": sum(1 for x in out if x["ok"])})
        return {"items": out, "ok": sum(1 for x in out if x["ok"]), "failed": sum(1 for x in out if not x["ok"])}

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

    @r.get("/api/sensors/{did}/baseline")
    async def baseline(did: str, metric: str = "temp_c"):
        d = g(did)
        if metric not in BASE_METRICS:
            raise HTTPException(400, "기준선 측정값: " + ", ".join(BASE_METRICS))
        b = (d.get("info") or {}).get("baseline") or {}
        return {"metric": metric, "built": b.get("built"), "days": b.get("days", 0), "hours": (b.get("m") or {}).get(metric) or {},
                "enabled": d["config"].get("baseline"), "k": d["config"].get("baseline_k")}

    @r.post("/api/sensors/{did}/baseline/rebuild")
    async def baseline_rebuild(did: str, request: Request):
        d = g(did)
        b = await S.build_baseline(d)
        await audit(request, "sensor.baseline_rebuild", did)
        return {"ok": True, "built": b["built"], "days": b["days"], "metrics": {m: len(v) for m, v in b["m"].items()}}

    @r.get("/api/sensors/{did}/calibrate")
    async def calib_info(did: str):
        d = g(did)
        return {"history": (d.get("info") or {}).get("calib") or [], "candidates": S.calib_candidates(did), "what": CALIB,
                "latest": {k: (d.get("latest") or {}).get(k) for k in ("temp_c", "temp_src", "battery_c", "humidity", "sound_db", "ts")}}

    @r.post("/api/sensors/{did}/calibrate")
    async def calib(did: str, request: Request):
        g(did)
        b = await body_json(request)
        try:
            rec = await S.calibrate(did, str(b.get("what") or ""), b.get("reference"), who(request).get("user", ""), str(b.get("from_device") or ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "sensor.calibrate", did, detail={k: rec[k] for k in ("what", "key", "reference", "measured", "old", "new")})
        return rec

    @r.get("/api/sensors/{did}/events")
    async def dev_events(did: str, limit: int = 50):
        g(did)
        return {"items": await S.events(did, limit)}

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

    def qr_payload(request: Request, code: str, server: str = "") -> dict:
        """server: 폰이 접속할 주소(내부 IP:포트 등) — 비우면 포털 공개 주소"""
        base = server.rstrip("/") if server and URL_RX.match(server.rstrip("/")) else public_base(request)
        setup = f"{base}/sensor-setup?c={quote(code)}" + (f"&u={quote(base, safe='')}" if server else "")
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
        h = request.headers.get("authorization") or ""
        by_token = S.auth(h[7:].strip()) if h.lower().startswith("bearer ") else None     # 2.52.0 앱 자체 업데이트(장치 토큰)
        if (not by_token and not S.code_device(c)) or not APK.is_file():
            raise HTTPException(404)
        await ENGINE.audit.log("sensor.apk_download", user="-", ip=client_ip(request), result="ok")
        return FileResponse(APK, media_type="application/vnd.android.package-archive", filename="vcf-aiops-sensor.apk",
                            headers={"Cache-Control": "no-store"})

    @r.get("/sensor-setup", include_in_schema=False)
    async def setup(request: Request, c: str = "", u: str = ""):
        if not S._loaded:
            await S.load()
        d = S.code_device(c)
        if not d:
            raise HTTPException(404)
        base = public_base(request)
        uri = f"vcfaiops-sensor://enroll?u={quote(base, safe='')}&c={quote(c)}"
        left = max(1, int((d["enroll_until"] - time.time()) // 60))
        e = html.escape
        if u and URL_RX.match(u.rstrip("/")):                            # 2.53.0 장치 추가 때 고른 주소(내부 IP 등)
            base = u.rstrip("/")
            uri = f"vcfaiops-sensor://enroll?u={quote(base, safe='')}&c={quote(c)}"
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
        return {**res, "enroll": qr_payload(request, res["code"], str(b.get("server") or ""))}

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
        b = await body_json(request) if int(request.headers.get("content-length") or 0) else {}
        res = await S.reenroll(did)
        await audit(request, "sensor.reenroll", did)
        return {**res, "enroll": qr_payload(request, res["code"], str(b.get("server") or ""))}

    @r.post("/api/sensors/{did}/snap-now")
    async def snap_now(did: str, request: Request):
        d = g(did)
        if "camera" not in d["config"]["sensors"]:
            raise HTTPException(400, "이 장치는 카메라가 꺼져 있습니다(설정에서 켜기)")
        S.request_snap(did)
        await audit(request, "sensor.snap_request", did)
        return {"ok": True, "next_push_within_s": d["config"]["interval_s"]}

    # ---------------------------------------------------------------- 2.53.0 원격 설정·설치 스크립트·접속 주소
    @r.get("/api/sensors/addresses")
    async def addresses(request: Request):
        """폰이 접속할 수 있는 이 서버 주소 후보(공개 주소·지금 접속 주소·서버 내부 IP)"""
        return {"items": sensorprov.addresses(public_base(request), request)}

    @r.get("/api/sensors/commands/meta")
    async def cmd_meta():
        return {"commands": {k: {"label": v["label"], "owner": v["owner"], "args": {a: t.__name__ for a, t in (v.get("args") or {}).items()}}
                             for k, v in COMMANDS.items()}}

    @r.get("/api/sensors/{did}/commands")
    async def cmd_list(did: str):
        g(did)
        return {"items": await S.commands(did)}

    @r.post("/api/sensors/{did}/commands")
    async def cmd_add(did: str, request: Request):
        g(did)
        b = await body_json(request)
        try:
            res = await S.add_command(did, str(b.get("op") or ""), b.get("args") or {}, who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "sensor.command", did, detail={"op": res["op"], "args": res["args"]})
        return res

    @r.delete("/api/sensors/{did}/commands/{cid}")
    async def cmd_cancel(did: str, cid: str, request: Request):
        g(did)
        if not await S.cancel_command(did, cid):
            raise HTTPException(409, "이미 폰이 가져간 명령은 취소할 수 없습니다")
        await audit(request, "sensor.command_cancel", did, detail={"id": cid})
        return {"ok": True}

    @r.post("/api/sensors/{did}/provision")
    async def provision(did: str, request: Request):
        """adb 설치·설정 스크립트(.sh·.bat) — 등록 전 장치면 새 등록 코드를 넣음(등록된 폰이면 설정만)"""
        d = g(did)
        b = await body_json(request)
        server = str(b.get("server") or "").rstrip("/")
        if server and not URL_RX.match(server):
            raise HTTPException(400, "서버 주소 형식: http(s)://호스트 또는 IP[:포트]")
        server = server or public_base(request)
        code = ""
        if not d.get("enrolled") or b.get("reenroll"):
            code = (await S.reenroll(did))["code"]
        opts = {k: bool(b.get(k)) for k in ("owner", "stay_awake", "insecure")}
        wl = {k: str(b.get(k) or "").strip()[:60] for k in ("phone_ip", "phone_port", "pair_port", "pair_code")}
        try:
            out = sensorprov.scripts(d, server, code, opts, wl)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await audit(request, "sensor.provision", did, detail={"server": server, "owner": opts["owner"], "wireless": bool(wl["phone_ip"]), "new_code": bool(code)})
        return out

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
