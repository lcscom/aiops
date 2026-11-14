"""수명 주기·점검 API(2.36.0) — 인증서 만료 달력 · 구성 드리프트 · 버전 수명

  GET  /api/lifecycle/certs                 마지막 스캔(없으면 지금 스캔) — 항목별 만료일·남은 일·단계·갱신 방법
  POST /api/lifecycle/certs/scan            지금 스캔(operate)
  PUT  /api/lifecycle/certs/settings        경고 기준(일)·스캔 주기·kubelet 탐침·직접 등록 주소(settings)
  GET  /api/lifecycle/certs.ics             만료일 달력(iCalendar) — Outlook·구글 캘린더로 가져오기
  GET  /api/lifecycle/certs.csv
  GET  /api/lifecycle/drift?vcenter=&baseline=   기준선 대비 차이 + 같은 클러스터 호스트끼리 차이
  POST /api/lifecycle/drift/baseline        {vcenter, name} 지금 구성을 기준선으로 저장(operate)
  DELETE /api/lifecycle/drift/baseline/{id}
  GET  /api/lifecycle/versions              구성요소 버전 ↔ 지원 종료일·다음 줄
  PUT  /api/lifecycle/versions/table        수명 표 바꾸기(JSON, settings) · DELETE 기본 표로
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response


def build_router(ENGINE, CERTS, who, audit) -> APIRouter:
    r = APIRouter()
    from .drift import DriftStore
    from .lifecycle import Lifecycle
    DS = DriftStore(ENGINE.store)
    LC = Lifecycle(ENGINE)

    # ------------------------------------------------------------ 인증서
    @r.get("/api/lifecycle/certs")
    async def certs(scan: int = 1):
        """scan=0 이면 마지막 결과만(메뉴 배지용 — 첫 스캔을 일으키지 않음)"""
        if scan and not CERTS.last.get("ts"):
            await CERTS.scan()
        return CERTS.last

    @r.post("/api/lifecycle/certs/scan")
    async def certs_scan(request: Request):
        res = await CERTS.scan()
        await audit(request, "lifecycle.certs_scan", str(len(res.get("items", []))))
        return res

    @r.put("/api/lifecycle/certs/settings")
    async def certs_settings(request: Request):
        try:
            b = await request.json()
            if not isinstance(b, dict):
                raise ValueError("JSON 객체가 필요합니다")
            st = await CERTS.save_settings(b)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        await audit(request, "lifecycle.certs_settings")
        return st

    def _items():
        return [x for x in CERTS.last.get("items", []) if x.get("not_after")]

    @r.get("/api/lifecycle/certs.ics")
    async def certs_ics():
        """만료일마다 하루 일정 + 주의 기준일에 알림(VALARM) — 장비 이름이 들어가므로 공유 범위에 주의"""
        if not CERTS.last.get("ts"):
            await CERTS.scan()
        st = CERTS.last.get("settings") or {}
        esc = lambda s: str(s).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")   # noqa: E731
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        L = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//VCF AIops//Cert Expiry//KO", "CALSCALE:GREGORIAN", "X-WR-CALNAME:VCF 인증서 만료"]
        for i, x in enumerate(_items()):
            d = dt.date.fromtimestamp(x["not_after"])
            L += ["BEGIN:VEVENT", f"UID:vcf-aiops-cert-{abs(hash((x['system'], x['kind'], x['name']))) % 10**12}-{i}@vcf-aiops", f"DTSTAMP:{now}",
                  f"DTSTART;VALUE=DATE:{d.strftime('%Y%m%d')}", f"DTEND;VALUE=DATE:{(d + dt.timedelta(days=1)).strftime('%Y%m%d')}",
                  f"SUMMARY:{esc('인증서 만료 — ' + x['kind'] + ' ' + x['name'])}",
                  f"DESCRIPTION:{esc(x['system'] + (' / ' + x['cluster'] if x.get('cluster') else '') + chr(10) + '갱신: ' + (x.get('renew') or ''))}",
                  "BEGIN:VALARM", "ACTION:DISPLAY", f"DESCRIPTION:{esc('인증서 만료 ' + str(st.get('warn_days', 60)) + '일 전')}",
                  f"TRIGGER:-P{int(st.get('warn_days', 60))}D", "END:VALARM", "END:VEVENT"]
        L.append("END:VCALENDAR")
        return Response("\r\n".join(L) + "\r\n", media_type="text/calendar; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="vcf-cert-expiry.ics"', "Cache-Control": "private, no-store"})

    @r.get("/api/lifecycle/certs.csv")
    async def certs_csv():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["만료일", "남은 일", "단계", "출처", "시스템", "클러스터", "종류", "이름", "주체", "발급자", "갱신 방법"])
        for x in CERTS.last.get("items", []):
            w.writerow([dt.date.fromtimestamp(x["not_after"]).isoformat() if x.get("not_after") else "", x.get("days_left", ""), x.get("band", ""), x["source"],
                        x["system"], x.get("cluster", ""), x["kind"], x["name"], x.get("subject", ""), x.get("issuer", ""), x.get("renew", "")])
        return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-cert-expiry-{time.strftime("%Y%m%d")}.csv"', "Cache-Control": "private, no-store"})

    # ------------------------------------------------------------ 구성 드리프트
    def _vcs():
        return [c for c in ENGINE.connectors if getattr(c, "type", "") == "vcenter" and getattr(c, "enabled", True)]

    @r.get("/api/lifecycle/drift")
    async def drift(vcenter: str = "", baseline: int = 0):
        from . import drift as D
        vcs = _vcs()
        c = next((x for x in vcs if x.name == vcenter), None) or \
            max(vcs, key=lambda x: len(((getattr(x, "health_snap", None) or {}).get("hosts") or {})), default=None)   # 기본: 호스트가 가장 많은 vCenter
        if not c:
            return {"vcenters": [], "baselines": [], "peers": [], "diff": [], "error": "vCenter 커넥터가 없습니다"}
        snap = getattr(c, "health_snap", None) or {}
        cur = D.normalize(snap) if snap.get("hosts") else None
        bl = [x for x in await DS.list() if x["vcenter"] == c.name]
        base = await DS.get(baseline) if baseline else (await DS.latest_for(c.name))
        if base and base["vcenter"] != c.name:
            base = None
        out = {"vcenters": [x.name for x in vcs], "vcenter": c.name, "baselines": bl, "updated": (getattr(c, "health", None) or {}).get("updated", 0),
               "hosts": len((cur or {}).get("hosts", {})), "clusters": len((cur or {}).get("clusters", {}))}
        if not cur:
            return out | {"peers": [], "diff": [], "error": "아직 인프라 점검 전입니다(최대 30분) — 점검이 끝나면 비교합니다"}
        out["peers"] = D.peers(cur)
        if base:
            out["baseline"] = {k: base[k] for k in ("id", "name", "created", "by")}
            out["diff"] = D.diff(base["data"], cur)
        else:
            out["diff"] = []
        return out

    @r.get("/api/lifecycle/drift/history")
    async def drift_history(vcenter: str = "", days: int = 30, entity: str = ""):
        """2.37.0 언제 무엇이 바뀌었나 — 인프라 점검마다 직전 구성과 비교해 쌓은 변경 이력"""
        dw = getattr(ENGINE, "driftwatch", None)
        if not dw:
            return {"changes": [], "error": "변경 이력이 꺼져 있습니다"}
        vcs = _vcs()
        vc = vcenter or (vcs[0].name if vcs else "")
        rows = await dw.history(vc, max(1, min(days, 180)), entity)
        by_day: dict[str, int] = {}
        for x in rows:
            d = dt.date.fromtimestamp(x["ts"]).isoformat()
            by_day[d] = by_day.get(d, 0) + 1
        return {"vcenter": vc, "days": days, "changes": rows, "by_day": by_day, "state": dw.state}

    @r.post("/api/lifecycle/drift/baseline")
    async def drift_baseline(request: Request):
        from . import drift as D
        b = await request.json()
        c = next((x for x in _vcs() if x.name == str((b or {}).get("vcenter") or "")), None)
        if not c:
            raise HTTPException(404, "vCenter 를 찾을 수 없습니다")
        snap = getattr(c, "health_snap", None) or {}
        if not snap.get("hosts"):
            raise HTTPException(409, "인프라 점검 전이라 기준선을 만들 수 없습니다")
        try:
            o = await DS.add(str(b.get("name") or ""), c.name, D.normalize(snap), who(request).get("user", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        await audit(request, "lifecycle.drift_baseline", f"{c.name} {o['name']}")
        return o

    @r.delete("/api/lifecycle/drift/baseline/{bid}")
    async def drift_baseline_del(bid: int, request: Request):
        if not await DS.remove(bid):
            raise HTTPException(404)
        await audit(request, "lifecycle.drift_baseline_remove", str(bid))
        return {"ok": True}

    # ------------------------------------------------------------ 버전 수명
    @r.get("/api/lifecycle/versions")
    async def versions():
        return await LC.report()

    @r.put("/api/lifecycle/versions/table")
    async def versions_table(request: Request):
        try:
            t = await LC.save_table(await request.json())
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        await audit(request, "lifecycle.table_update", str(len(t["entries"])))
        return {"ok": True, "entries": len(t["entries"])}

    @r.delete("/api/lifecycle/versions/table")
    async def versions_table_reset(request: Request):
        await LC.reset_table()
        await audit(request, "lifecycle.table_reset")
        return {"ok": True}

    return r
