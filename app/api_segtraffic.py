"""2.21.0 NSX 세그먼트 트래픽 API — 조회는 view, AI 는 operate"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .httputil import disposition


def _strip(ov: dict, limit: int = 3000) -> dict:
    return {**{k: v for k, v in ov.items() if not k.startswith("_")}, "vnics": ov.get("vnics", [])[:limit], "vnics_total": len(ov.get("vnics", []))}


def build_router(ENGINE, CFG, who, audit) -> APIRouter:
    r = APIRouter()
    M = ENGINE.segtraffic

    def win(w: int) -> int:
        return w if w in (300, 900, 3600) else 300

    def sco(s: str) -> str:
        return s if s in ("nsx", "vds", "std", "all", "avi") else "nsx"

    @r.get("/api/segtraffic")
    async def overview(window: int = 300, scope: str = "nsx", fresh: bool = False):
        return _strip(await M.overview(win(window), sco(scope), fresh))

    @r.get("/api/segtraffic/segment")
    async def segment(key: str, window: int = 300, scope: str = "nsx"):
        try:
            return await M.segment(key, win(window), sco(scope))
        except KeyError:
            raise HTTPException(404, "세그먼트 없음") from None

    @r.get("/api/segtraffic/vms")
    async def vms(window: int = 300, fresh: bool = False):
        ov = await M.overview(win(window), "all", fresh)
        return {"window": ov["window"], "updated": ov["updated"], "items": M.vm_list(ov), "errors": ov["errors"],
                "sources": ov["sources"]}

    @r.get("/api/segtraffic/vm")
    async def vm(name: str, window: int = 300, vcenter: str = ""):
        try:
            return await M.vm(name, win(window), vcenter=vcenter)
        except KeyError:
            raise HTTPException(404, "VM 없음(네트워크에 연결된 vNIC 이 없거나 이름이 다름)") from None

    @r.get("/api/segtraffic/vm/history")
    async def vm_history(name: str, hours: float = 24, vcenter: str = ""):
        try:
            return await M.vm_history(name, hours, vcenter)
        except KeyError:
            raise HTTPException(404, "VM 없음") from None

    @r.get("/api/segtraffic/history")
    async def history(key: str = "", hours: float = 24, scope: str = "all"):
        return await M.history(key, hours, scope if scope in ("nsx", "vds", "std", "all", "avi") else "all")

    @r.get("/api/segtraffic.csv")
    async def export(request: Request, window: int = 300, key: str = "", scope: str = "nsx", vm: str = "", vcenter: str = ""):
        sc = sco(scope)
        if vm:                                                    # VM 한 대의 모든 vNIC
            try:
                d = await M.vm(vm, win(window), vcenter=vcenter)
            except KeyError:
                raise HTTPException(404, "VM 없음") from None
            ov = {"segments": [{"key": v["segment"], "name": (v.get("net") or {}).get("name") or v["segment"]} for v in d["vnics"]], "vnics": d["vnics"]}
        elif key:                                                   # 세그먼트 하나면 NSX 포트 통계(DFW 차단)까지 붙은 상세로
            try:
                sg = await M.segment(key, win(window), sc)
            except KeyError:
                raise HTTPException(404, "세그먼트 없음") from None
            ov = {"segments": [sg["segment"]], "vnics": sg["vnics"]}
        else:
            ov = await M.overview(win(window), sc)
        await audit(request, "segtraffic.export", vm or key or "all")
        return Response(M.csv(ov, key), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": disposition(f"segment-traffic-{time.strftime('%Y%m%d-%H%M')}.csv")})

    @r.post("/api/segtraffic/ai")
    async def ai(request: Request, body: dict):
        try:
            w = win(int(body.get("window") or 300))
        except (TypeError, ValueError):
            raise HTTPException(400, "window 는 300·900·3600 중 하나") from None
        key = str(body.get("key") or "")
        if key and not any(s["key"] == key for s in (await M.overview(w, sco(str(body.get("scope") or "nsx"))))["segments"]):
            raise HTTPException(404, "세그먼트 없음")
        await audit(request, "segtraffic.ai", key or "all")
        try:
            return {"report": await M.ai(w, key, sco(str(body.get("scope") or "nsx")))}
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"AI 분석 실패: {type(e).__name__}") from None

    return r
