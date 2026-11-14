"""AI 체크봇 API(2.38.0)

  GET  /api/checkbot?type=&verdict=&q=&limit=   마지막 실행 — 요약·AI 요약·시나리오(위험 순, 상세 목록은 줄여서)
  GET  /api/checkbot/scenario?id=                시나리오 하나의 전체 영향 리소스 목록
  POST /api/checkbot/run {ai?: bool}             지금 실행(operate)
  GET  /api/checkbot/history                     실행 이력(판정 수 추이)
  GET  /api/checkbot.csv?id=                     전체 결과(또는 시나리오 하나의 영향 리소스) CSV
  GET  /api/checkbot/inventory                   (2.39.0) 시뮬레이터용 인벤토리 트리
  POST /api/checkbot/simulate {failures:[...]}   (2.39.0) 고른 장애를 겹쳐 영향 계산(읽기 전용 — view 권한)
  POST /api/checkbot/refresh                     (2.41.0) 초기화 — 스냅숏 버리고 vCenter 토폴로지·인프라 점검 읽기 전용 재수집(60초에 한 번)
"""
from __future__ import annotations

import asyncio
import csv
import io
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from . import simulator as SIM
from .checkbot import TYPES, build_world


def _lite(r: dict) -> dict:
    return {k: r.get(k) for k in ("id", "type", "kind", "target", "vcenter", "cluster", "verdict", "score", "impact", "origin", "why", "history")} | \
        {"top": [f["text"] for f in r.get("findings", []) if f["sev"] == r["verdict"]][:2]}


def build_router(ENGINE, BOT, who, audit) -> APIRouter:
    r = APIRouter()

    async def _last() -> dict:
        res = await BOT.latest()
        if not res:
            res = await BOT.run("first-view")
        return res

    @r.get("/api/checkbot")
    async def latest(type: str = "", verdict: str = "", q: str = "", limit: int = 400, run: int = 1):
        res = await BOT.latest()
        if not res:
            if not run:
                return {"summary": None, "results": [], "types": {k: v[0] for k, v in TYPES.items()}, "state": BOT.state}
            res = await BOT.run("first-view")
        rs = res["results"]
        if type:
            rs = [x for x in rs if x["type"] == type]
        if verdict:
            rs = [x for x in rs if x["verdict"] in verdict.split(",")]
        if q:
            ql = q.lower()
            rs = [x for x in rs if ql in str(x.get("target", "")).lower() or ql in str(x.get("vcenter", "")).lower()
                  or any(ql in v["name"].lower() for v in x.get("vms", []))]
        return {"summary": res["summary"], "ai": res.get("ai") or {}, "new_fail": res.get("new_fail", []), "fixed": res.get("fixed", []),
                "results": [_lite(x) for x in rs[:max(1, min(limit, 2000))]], "matched": len(rs),
                "types": {k: {"name": v[0], "desc": v[1]} for k, v in TYPES.items()}, "state": BOT.state, "interval_h": BOT.cfg["interval_h"]}

    @r.get("/api/checkbot/scenario")
    async def scenario(id: str):
        res = await _last()
        hit = next((x for x in res["results"] if x["id"] == id), None)
        if not hit:
            raise HTTPException(404, "시나리오를 찾지 못했습니다(다시 실행돼 바뀌었을 수 있습니다)")
        return hit

    @r.post("/api/checkbot/run")
    async def run(request: Request):
        try:
            b = await request.json()
        except Exception:  # noqa: BLE001
            b = {}
        if BOT.state.get("running"):
            raise HTTPException(409, "이미 실행 중입니다")
        res = await BOT.run(who(request).get("user", "user"), ai=(b or {}).get("ai") if isinstance(b, dict) else None)
        await audit(request, "checkbot.run", str(res["summary"]["scenarios"]))
        return {"summary": res["summary"], "ai": res.get("ai") or {}}

    @r.get("/api/checkbot/history")
    async def history(n: int = 60):
        return {"runs": await BOT.history(max(1, min(n, 200)))}

    @r.get("/api/checkbot.csv")
    async def csv_out(id: str = ""):
        res = await _last()
        buf = io.StringIO()
        w = csv.writer(buf)
        if id:
            x = next((r_ for r_ in res["results"] if r_["id"] == id), None)
            if not x:
                raise HTTPException(404, "시나리오를 찾지 못했습니다")
            w.writerow(["시나리오", x["kind"], x["target"], "판정", x["verdict"]])
            w.writerow([])
            w.writerow(["구분", "이름", "전원·종류", "호스트·클러스터", "vCPU", "메모리GB", "영향·사유"])
            for v in x["vms"]:
                w.writerow(["VM", v["name"], v["power"], f"{v['host']} / {v['cluster']}", v["vcpu"], v["mem_gb"], v["reason"]])
            for h in x["hosts"]:
                w.writerow(["호스트", h, "", "", "", "", ""])
            for s in x["services"]:
                w.writerow(["서비스", s["name"], s["kind"], "", "", "", s["impact"]])
            for c in x["vks"]["clusters"]:
                for p in c["pod_list"]:
                    w.writerow(["VKS 파드", p, c["cluster"], "", "", "", ""])
            w.writerow([])
            for f in x["findings"]:
                w.writerow(["판단", f["sev"], f["text"]])
            name = f"vcf-checkbot-{x['type']}-{time.strftime('%Y%m%d')}.csv"
        else:
            w.writerow(["위험점수", "판정", "유형", "대상", "vCenter", "클러스터", "켜진VM", "관리서비스", "VKS파드", "출처", "주요 판단"])
            for x in res["results"]:
                w.writerow([x["score"], x["verdict"], x["kind"], x["target"], x.get("vcenter", ""), x.get("cluster", ""), x["impact"]["vms_on"],
                            x["impact"]["services"], x["impact"]["pods"], x.get("origin", ""), " / ".join(f["text"] for f in x["findings"] if f["sev"] != "pass")[:500]])
            name = f"vcf-checkbot-{time.strftime('%Y%m%d')}.csv"
        return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "private, no-store"})

    # 2.39.0 장애 시뮬레이터 — 인벤토리 트리 + 고른 장애의 영향(읽기 전용 계산)
    # 2.40.0 안전 장치: 계산은 30초마다 새로 뜨는 깊은 복사 스냅숏 위에서만 한다. 이 경로에는 커넥터 메서드 호출·저장소 쓰기·외부 요청이 없다
    snap: dict = {"ts": 0.0, "w": None}

    def world() -> dict:
        if snap["w"] is None or time.time() - snap["ts"] > 30:
            snap["w"], snap["ts"] = build_world(ENGINE), time.time()
        return snap["w"]

    @r.post("/api/checkbot/refresh")
    async def refresh():
        """2.41.0 '초기화' — 시뮬레이터 스냅숏을 버리고, vCenter 커넥터의 토폴로지·인프라 점검 수집을 지금 다시 돌린다.
        평소 주기 수집과 같은 읽기 전용 조회이며(변경 명령 없음) 60초에 한 번만 받아들인다. 네트워크 장비는 자기 주기(보통 1분)로 계속 수집 중."""
        now = time.time()
        if now - snap.get("rf", 0) < 60:
            snap["w"] = None
            return {"requested": [], "throttled": True, "wait_s": int(60 - (now - snap["rf"]))}
        req = []
        for c in ENGINE.connectors:
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True) or not hasattr(c, "_kick_heavy"):
                continue
            for a in ("_last_topo", "_last_health"):
                if hasattr(c, a):
                    setattr(c, a, 0.0)
            try:
                c._kick_heavy()
                req.append(c.name)
            except Exception:  # noqa: BLE001
                pass
        snap["w"], snap["rf"] = None, now
        return {"requested": req, "throttled": False}

    # 2.47.0 시나리오 라이브러리 — 파트별 시나리오(파트마다 20개 이상), 계산만
    @r.get("/api/checkbot/library")
    async def library(run: int = 0):
        from . import scenlib as L
        w = world()
        res = await asyncio.to_thread(L.run_all if run else L.catalog, w)
        W_ = getattr(ENGINE, "scnwatch", None)
        if run and W_:                                   # 2.48.0 지난 기록과 비교
            prev = await W_.last()
            cur = {"verdicts": {x["id"]: x["verdict"] for x in res["items"]}}
            res["diff"] = W_.diff(prev, cur)
            res["watch"] = {"last": W_.state.get("last") or (prev or {}).get("ts"), "interval_h": W_.interval_h}
        return res

    @r.get("/api/checkbot/spof")
    async def spof_rank(top: int = 40):
        from . import spof as SP
        return await asyncio.to_thread(SP.scan, world(), max(5, min(200, top)))

    @r.get("/api/checkbot/library/history")
    async def library_hist(n: int = 30):
        W_ = getattr(ENGINE, "scnwatch", None)
        return {"items": await W_.history(n) if W_ else [], "state": W_.state if W_ else {}}

    @r.post("/api/checkbot/library/snapshot")
    async def library_snap(request: Request):
        W_ = getattr(ENGINE, "scnwatch", None)
        if not W_:
            raise HTTPException(503, "연속 검증이 꺼져 있습니다")
        res = await W_.snapshot(world(), "manual")
        await audit(request, "whatif.snapshot", f"fail={res['counts'].get('fail', 0)} new={len(res['new_fail'])}")
        return res

    @r.get("/api/checkbot/library.md")
    async def library_md():
        from . import scenlib as L
        from . import spof as SP
        w = world()
        lib = await asyncio.to_thread(L.run_all, w)
        sp = await asyncio.to_thread(SP.scan, w, 10)
        W_ = getattr(ENGINE, "scnwatch", None)
        d = W_.diff(await W_.last(), {"verdicts": {x["id"]: x["verdict"] for x in lib["items"]}}) if W_ else None
        return Response(L.to_markdown(lib, sp, d), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=whatif-report-{time.strftime('%Y%m%d-%H%M')}.md"})

    @r.get("/api/checkbot/library.csv")
    async def library_csv():
        from . import scenlib as L
        lib = await asyncio.to_thread(L.run_all, world())
        parts = {p["key"]: p["label"] for p in lib["parts"]}
        buf = io.StringIO()
        wr = csv.writer(buf)
        wr.writerow(["ID", "파트", "시나리오", "판정", "대상", "중단", "위험", "재시작·잠깐", "Pod", "이유·해당 없음"])
        for x in lib["items"]:
            wr.writerow([x["id"], parts.get(x["part"], x["part"]), x["title"], {"fail": "실패", "warn": "주의", "pass": "통과", "none": "해당 없음"}[x["verdict"]],
                         x.get("target", ""), x.get("stop", ""), x.get("risk", ""), x.get("boot", ""), x.get("pods", ""), (x.get("top") or x.get("why_na") or "")])
        return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=whatif-scenarios-{time.strftime('%Y%m%d-%H%M')}.csv"})

    @r.post("/api/checkbot/library/run")
    async def library_run(request: Request):
        from . import scenlib as L
        try:
            b = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "JSON 이 아닙니다") from None
        try:
            return await asyncio.to_thread(L.run, world(), str((b or {}).get("id") or "")) | {"simulation_only": True, "applied": False}
        except KeyError:
            raise HTTPException(404, "시나리오가 없습니다") from None

    @r.get("/api/checkbot/inventory")
    async def inventory():
        snap["w"] = None                                         # 트리를 새로 부를 때는 최신 수집으로
        return SIM.inventory(world()) | {"simulation_only": True, "snapshot_ts": snap["ts"]}

    @r.post("/api/checkbot/simulate")
    async def simulate(request: Request):
        try:
            b = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "JSON 이 아닙니다") from None
        fs = (b or {}).get("failures") if isinstance(b, dict) else None
        if not isinstance(fs, list):
            raise HTTPException(400, "failures 목록이 필요합니다")
        return SIM.simulate(world(), fs) | {"simulation_only": True, "applied": False, "snapshot_ts": snap["ts"]}

    return r
