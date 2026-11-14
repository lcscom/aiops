"""용량 계획·VM 적정화 API — 조회 view, 즉시 표본 operate.

  GET  /api/capacity?days=30            클러스터·데이터스토어 현재 사용률·추세·80/90% 도달 예상일·30/90일 예측
  GET  /api/capacity/rightsizing?days=14  과다·과소·유휴·장기 꺼짐 VM, 회수 가능 자원·월 절감 추정(기본 요율표 기준)
  GET  /api/capacity/report.csv
  POST /api/capacity/sample             지금 5분 블록 표본
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import Response


def build_router(ENGINE, CFG: dict, who, audit) -> APIRouter:
    r = APIRouter()
    C = ENGINE.capacity
    from .whatif import ScenarioStore                       # 저장한 가정(2.35.0) — 보고서 묶음(2.36.0)도 씀
    SCN = ScenarioStore(ENGINE.store)

    @r.get("/api/capacity")
    async def overview(days: int = 0):
        return await C.overview(max(3, min(days, 365)) if days else None)

    @r.get("/api/capacity/rightsizing")
    async def rightsizing(days: int = 0):
        return await C.rightsizing(max(1, min(days, 90)) if days else None)

    @r.get("/api/capacity/report.csv")
    async def csv_(request: Request):
        ov, rs = await C.overview(), await C.rightsizing()
        await audit(request, "capacity.export")
        return Response(C.to_csv(ov, rs), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="vcf-aiops-capacity-{time.strftime("%Y%m%d")}.csv"'})

    @r.get("/api/capacity/whatif")
    async def whatif_clusters():
        """가정 분석 대상 클러스터와 지금 값"""
        from . import whatif as W
        out = []
        for c in ENGINE.connectors:
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
                continue
            for cn in sorted((getattr(c, "topology", {}) or {}).get("clusters") or {}):
                b = W.cluster_base(c, cn)
                if b and b["hosts"]:
                    n = len(b["hosts"])
                    out.append({"vcenter": c.name, "cluster": cn, "hosts": n, "vms_on": b["vms_on"],
                                "host_list": [{"name": h["name"], "cores": round(h["cpu_mhz"] / h["core_mhz"]) if h["core_mhz"] else 0, "mem_gb": round(h["mem_mb"] / 1024)} for h in b["hosts"]],
                                "avg_host": {"cores": round(sum(h["cpu_mhz"] / h["core_mhz"] for h in b["hosts"] if h["core_mhz"]) / n),
                                             "core_ghz": round(sum(h["core_mhz"] for h in b["hosts"]) / n / 1000, 2), "mem_gb": round(sum(h["mem_mb"] for h in b["hosts"]) / n / 1024)}})
        return {"clusters": out}

    @r.post("/api/capacity/whatif")
    async def whatif(request: Request):
        """VM·호스트를 더하거나 뺐을 때의 여유·남은 기간(계산만 — vCenter 변경 없음)"""
        from fastapi import HTTPException

        from . import whatif as W
        try:
            b = await request.json()
            if not isinstance(b, dict):
                raise ValueError("JSON 객체가 필요합니다")
            conn = next((c for c in ENGINE.connectors if c.name == str(b.get("vcenter") or "") and getattr(c, "type", "") == "vcenter"), None)
            base = conn and W.cluster_base(conn, str(b.get("cluster") or ""))
            if not base:
                raise HTTPException(404, "클러스터를 찾을 수 없습니다")
            ov = await C.overview()
            row = next((x for x in ov["items"] if x["kind"] == "cluster" and x["vcenter"] == conn.name and x["name"] == b.get("cluster")), {})
            slopes = {"cpu": (row.get("forecast") or {}).get("slope"), "mem": (row.get("forecast_mem") or {}).get("slope"),
                      "disk_gb_day": _ds_growth(ov, conn.name, base)}
            demand = None
            if str(b.get("basis") or "now") == "p95":        # 2.35.0 — 순간 값 대신 최근 N일 시간별 평균의 95퍼센타일
                days = int(b.get("basis_days") or 14)
                if days not in (7, 14, 28):
                    raise ValueError("피크 기간은 7·14·28일")
                demand = await _peak(conn, base, days)
            reclaim = None
            if b.get("apply_rightsizing"):                     # 2.36.0 적정화 반영
                from .whatif_multi import rightsizing_reclaim
                reclaim = rightsizing_reclaim(await C.rightsizing(), (conn.topology or {}).get("vms") or {}, conn.name, str(b.get("cluster")))
            res = W.simulate(base, b, slopes, demand, reclaim) | {"vcenter": conn.name, "cluster": b.get("cluster"), "days_observed": row.get("days_observed"),
                                                                    "host_names": [h["name"] for h in base["hosts"]], "vsan_policies": W.VSAN_POLICIES}
            res["cost"] = await _cost(res, b)
            return res
        except ValueError as e:
            raise HTTPException(400, str(e))

    def _ds_growth(ov: dict, vc: str, base: dict) -> float | None:
        """2.37.0 클러스터 공유 데이터스토어의 실제 증가량 합(GB/일) — 용량 예측의 데이터스토어 추세"""
        g = [x.get("growth_gb_day") for x in ov.get("items", []) if x["kind"] == "datastore" and x["vcenter"] == vc and x["name"] in (base.get("ds_names") or [])]
        g = [x for x in g if x is not None]
        return round(sum(g), 1) if g else None

    async def _vm_peaks(conn, vms: list[dict], days: int = 14) -> dict:
        """VM 성능 이력 피크를 vms 에 붙인다(peak_mhz) — 이력이 없으면 지금 값"""
        import asyncio as _a

        from .whatif_multi import attach_peaks
        ps = getattr(getattr(ENGINE, "perfwatch", None), "store", None)
        if not ps or not vms:
            return {"kind": "now", "vms_with_history": 0, "vms": len(vms), "why": "성능 이력이 꺼져 있어 VM 의 지금 CPU 사용량으로 계산했습니다" if not ps else ""}
        ids = {v["name"]: ps.find("vm", v["name"], conn.name) for v in vms}
        pk = await _a.to_thread(ps.vm_peaks, [i for i in ids.values() if i is not None], days)
        core = {}
        for h in ((conn.topology or {}).get("hosts") or {}).values():
            if h.get("core_mhz"):
                core.setdefault(h.get("cluster", ""), []).append(h["core_mhz"])
        out = {}
        for v in vms:
            e = ids.get(v["name"])
            if e in pk:
                out[v["name"]] = pk[e]
        cl = vms[0].get("cluster", "")
        cm = core.get(cl) or [h for x in core.values() for h in x] or [2500]
        r = attach_peaks(vms, out, sum(cm) / len(cm))
        r["days"] = days
        if r["vms_with_history"] < len(vms):
            r["why"] = f"VM {len(vms) - r['vms_with_history']}대는 성능 이력이 하루치가 안 돼 지금 CPU 사용량으로 셉니다"
        return r

    async def _cost(res: dict, b: dict) -> dict | None:
        """2.36.0 가정 분석 → 비용: 증설분 VCF 원가 ↔ 같은 VM 의 퍼블릭 클라우드 월 비용"""
        cc = getattr(ENGINE, "cloudcost", None)
        if not cc:
            return None
        from .whatif_multi import cost
        inp = res["inputs"]
        hosts = inp["add_hosts"] or (res.get("hosts_needed") or 0)
        try:
            st, pr = await cc.settings(), await cc.prices()
        except Exception:  # noqa: BLE001
            return None
        out = cost(res, st, pr, add_vms=inp["add_vms"], vm_vcpu=inp["vm_vcpu"], vm_mem_gb=inp["vm_mem_gb"],
                   vm_disk_gb=float(b.get("vm_disk_gb") or 0), hosts_planned=None if inp["add_hosts"] else hosts)
        out["hosts_basis"] = "입력한 추가 서버" if inp["add_hosts"] else ("80% 안에 들기 위해 필요한 서버" if hosts else "추가 서버 없음")
        v = out.get("vcf")
        fx = out.get("fx_krw_per_usd")
        if v and v["currency"] == "KRW" and fx:
            v["monthly_usd"] = round(v["monthly"] / fx)
        elif v:
            v["monthly_usd"] = v["monthly"] if v["currency"] == "USD" else None
        return out

    def _vc(name: str):
        return next((c for c in ENGINE.connectors if c.name == str(name or "") and getattr(c, "type", "") == "vcenter"), None)

    @r.get("/api/capacity/whatif/vms")
    async def whatif_vms(vcenter: str, cluster: str):
        """2.36.0 옮길 VM 고르기 — 클러스터의 VM(템플릿 제외)"""
        from fastapi import HTTPException
        conn = _vc(vcenter)
        if not conn:
            raise HTTPException(404, "vCenter 를 찾을 수 없습니다")
        vms = [{"name": n, "power": "on" if "poweredOn" in str(v.get("power")) else "off", "vcpu": int(v.get("vcpu") or 0), "mem_gb": round(int(v.get("mem_mb") or 0) / 1024, 1),
                "disk_gb": float(v.get("disk_gb") or 0), "cpu_ghz": round(float(v.get("cpu_mhz") or 0) / 1000, 2), "folder": v.get("folder", "")}
               for n, v in ((conn.topology or {}).get("vms") or {}).items() if v.get("cluster") == cluster]
        vms.sort(key=lambda x: (x["folder"], x["name"]))
        return {"vms": vms[:5000], "total": len(vms)}

    @r.post("/api/capacity/whatif/move")
    async def whatif_move(request: Request):
        """2.36.0 클러스터 간 이동 가정 — 계산만"""
        from fastapi import HTTPException

        from . import whatif as W
        from .whatif_multi import move
        try:
            b = await request.json()
            if not isinstance(b, dict):
                raise ValueError("JSON 객체가 필요합니다")
            sc, dc = _vc(b.get("vcenter")), _vc(b.get("dst_vcenter") or b.get("vcenter"))
            src = sc and W.cluster_base(sc, str(b.get("cluster") or ""))
            dst = dc and W.cluster_base(dc, str(b.get("dst_cluster") or ""))
            if not src or not dst:
                raise HTTPException(404, "클러스터를 찾을 수 없습니다")
            names = [str(x) for x in (b.get("vms") or [])][:5000]
            if not names:
                raise ValueError("옮길 VM 을 고르세요")
            T = (sc.topology or {}).get("vms") or {}
            vms = [{**T[n], "name": n} for n in names if n in T and T[n].get("cluster") == b.get("cluster")]
            if not vms:
                raise ValueError("고른 VM 이 원본 클러스터에 없습니다")
            ha = int(W._num(b, "ha_failures", 0, 4, 1))
            basis = await _vm_peaks(sc, vms) if str(b.get("basis") or "p95") == "p95" else {"kind": "now"}
            res = move(src, dst, vms, src_name=str(b["cluster"]), dst_name=str(b["dst_cluster"]), cross_vc=sc is not dc, dst_topo=dc.topology or {},
                       ha=ha, mem_util=W._num(b, "vm_mem_util_pct", 1, 100, 80), basis=basis)
            return res | {"vcenter": sc.name, "dst_vcenter": dc.name}
        except ValueError as e:
            raise HTTPException(400, str(e))

    @r.get("/api/capacity/whatif/dr-sources")
    async def whatif_dr_sources():
        """2.36.0 DR 수용 가정의 원본 — SRM 보호 그룹(있으면) + 클러스터 전체"""
        groups = []
        for c in ENGINE.connectors:
            if getattr(c, "type", "") == "srm" and getattr(c, "enabled", True):
                pr = getattr(c, "protection", None) or {}
                cnt: dict[str, int] = {}
                for v in pr.get("vms") or []:
                    cnt[v.get("group", "")] = cnt.get(v.get("group", ""), 0) + 1
                for g in pr.get("groups") or []:
                    groups.append({"srm": c.name, "name": g.get("name", ""), "vms": cnt.get(g.get("name", ""), g.get("vms") or 0), "status": g.get("status", ""),
                                   "protected_site": g.get("protected_site", "")})
        return {"groups": groups}

    @r.post("/api/capacity/whatif/dr")
    async def whatif_dr(request: Request):
        """2.36.0 DR 사이트 수용 가정 — 보호 그룹(또는 원본 클러스터 전체)을 대상 클러스터가 받을 때"""
        from fastapi import HTTPException

        from . import whatif as W
        from .whatif_multi import dr
        try:
            b = await request.json()
            if not isinstance(b, dict):
                raise ValueError("JSON 객체가 필요합니다")
            dc = _vc(b.get("dst_vcenter"))
            dst = dc and W.cluster_base(dc, str(b.get("dst_cluster") or ""))
            if not dst:
                raise HTTPException(404, "대상 클러스터를 찾을 수 없습니다")
            vms, missing, src, order = [], [], "", []
            allvms: dict[str, dict] = {}
            alias: dict[str, str] = {}
            vcs = sorted((c for c in ENGINE.connectors if getattr(c, "type", "") == "vcenter" and getattr(c, "enabled", True)), key=lambda c: c is dc)
            for c in vcs:                                     # 보호 VM 의 사양은 보호 사이트 vCenter 인벤토리에서 이름으로 찾는다(대상 vCenter 는 마지막에)
                for n, v in ((c.topology or {}).get("vms") or {}).items():
                    if n not in allvms:
                        allvms[n] = {**v, "name": n, "_vc": c.name, "_conn": c}
                    for k in (n.lower(), n.lower().split(".")[0]):   # 2.37.0 대소문자·도메인 꼬리가 다른 이름도 찾는다
                        alias.setdefault(k, n)

            def find(nm: str):
                if nm in allvms:
                    return allvms[nm]
                k = alias.get(nm.lower()) or alias.get(nm.lower().split(".")[0])
                return allvms.get(k) if k else None
            if b.get("groups"):
                glist = [(str(g.get("srm")), str(g.get("name"))) for g in b["groups"] if isinstance(g, dict)][:100]
                srms = {c.name: c for c in ENGINE.connectors if getattr(c, "type", "") == "srm"}
                seen: set[str] = set()
                for sname, gname in glist:                    # 고른 순서 = 복구 순서
                    gv = []
                    for v in ((getattr(srms.get(sname), "protection", None) or {}).get("vms") or []):
                        if v.get("group", "") != gname or not v.get("name"):
                            continue
                        x = find(v["name"])
                        if x is None:
                            if v["name"] not in missing:
                                missing.append(v["name"])
                            continue
                        gv.append(x)
                        if x["name"] not in seen:
                            seen.add(x["name"])
                            vms.append(x)
                    order.append((gname, gv))
                src = f"SRM 보호 그룹 {len(glist)}개"
            elif b.get("src_cluster"):
                sc = _vc(b.get("src_vcenter"))
                if not sc:
                    raise HTTPException(404, "원본 vCenter 를 찾을 수 없습니다")
                if sc is dc and b.get("src_cluster") == b.get("dst_cluster"):
                    raise ValueError("원본과 대상 클러스터가 같습니다")
                vms = [{**v, "name": n, "_conn": sc} for n, v in ((sc.topology or {}).get("vms") or {}).items()
                       if v.get("cluster") == b["src_cluster"] and (b.get("include_off") or "poweredOn" in str(v.get("power")))]
                src = f"{sc.name} / {b['src_cluster']} 전체({'꺼진 VM 포함' if b.get('include_off') else '켜진 VM'})"
            else:
                raise ValueError("보호 그룹이나 원본 클러스터를 고르세요")
            if not vms and not missing:
                raise ValueError("받을 VM 이 없습니다")
            if not vms:
                raise ValueError(f"보호 VM {len(missing)}대의 사양을 vCenter 인벤토리에서 찾지 못했습니다 — SRM 의 VM 이름이 vCenter VM 이름과 같은지 확인하세요"
                                 f"(예: {', '.join(missing[:3])})")
            basis = {"kind": "now"}
            if str(b.get("basis") or "p95") == "p95" and vms:
                by: dict = {}
                for v in vms:
                    c_ = v.get("_conn") or dc
                    by.setdefault(id(c_), (c_, []))[1].append(v)
                hist = 0
                for c, lst in by.values():
                    r = await _vm_peaks(c, lst)
                    hist += r.get("vms_with_history", 0)
                basis = {"kind": "p95" if hist else "now", "vms_with_history": hist, "vms": len(vms), "days": 14,
                         "why": "" if hist == len(vms) else f"VM {len(vms) - hist}대는 성능 이력이 없어 지금 CPU 사용량(꺼진 VM 은 25% 가정)으로 셉니다"}
            for v in vms:
                v.pop("_conn", None)
            res = dr(dst, vms, missing, dst_name=str(b["dst_cluster"]), ha=int(W._num(b, "ha_failures", 0, 4, 1)),
                     mem_util=W._num(b, "vm_mem_util_pct", 1, 100, 80), source=src, order=order or None, basis=basis)
            return res | {"dst_vcenter": dc.name}
        except ValueError as e:
            raise HTTPException(400, str(e))

    @r.get("/api/capacity/report-bundle")
    async def report_bundle(request: Request, format: str = "pdf", scenarios: str = "", customer: str = ""):
        """2.36.0 고객 제출용 보고서 묶음 — 용량·가정 분석(저장한 가정)·권장 구성·보안 판독을 PDF 또는 Word 한 파일로"""
        from fastapi import HTTPException

        from . import reportbundle as RB
        if format not in ("pdf", "docx", "html"):
            raise HTTPException(400, "형식은 pdf·docx·html")
        ids = [int(x) for x in scenarios.split(",") if x.strip().isdigit()][:10]
        data = await RB.gather(ENGINE, C, SCN, ids, run_whatif=_run_saved)
        data["customer"] = " ".join(str(customer).split())[:80]
        body, mt, ext = RB.render(data, format)
        await audit(request, "capacity.report_bundle", f"{format} scenarios={len(ids)}")
        fn = f"vcf-aiops-report-{time.strftime('%Y%m%d')}.{ext}"
        return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="{fn}"', "Cache-Control": "private, no-store"})

    async def _run_saved(sc: dict) -> dict | None:
        """저장한 가정을 지금 값으로 다시 계산(보고서용)"""
        from . import whatif as W
        conn = _vc(sc.get("vcenter"))
        base = conn and W.cluster_base(conn, str(sc.get("cluster") or ""))
        if not base:
            return None
        b = {**sc.get("inputs", {}), "vcenter": sc.get("vcenter"), "cluster": sc.get("cluster")}
        ov = await C.overview()
        row = next((x for x in ov["items"] if x["kind"] == "cluster" and x["vcenter"] == conn.name and x["name"] == sc.get("cluster")), {})
        slopes = {"cpu": (row.get("forecast") or {}).get("slope"), "mem": (row.get("forecast_mem") or {}).get("slope")}
        demand = await _peak(conn, base, int(b.get("basis_days") or 14)) if b.get("basis") == "p95" else None
        reclaim = None
        if b.get("apply_rightsizing"):
            from .whatif_multi import rightsizing_reclaim
            reclaim = rightsizing_reclaim(await C.rightsizing(), (conn.topology or {}).get("vms") or {}, conn.name, str(sc.get("cluster")))
        try:
            res = W.simulate(base, b, slopes, demand, reclaim)
        except ValueError:
            return None
        res["cost"] = await _cost(res, b)
        return res

    async def _peak(conn, base: dict, days: int) -> dict:
        """성능 이력(perf.db)에서 클러스터 수요의 95퍼센타일 — 이력이 하루치도 안 되면 지금 값으로(사유 표시)"""
        import asyncio
        pw = getattr(ENGINE, "perfwatch", None)
        ps = getattr(pw, "store", None)
        if not ps:
            return {"why": "성능 이력이 꺼져 있어 지금 값으로 계산했습니다"}
        hosts = [(ps.find("host", h["name"], conn.name), h["cpu_mhz"], h["mem_mb"]) for h in base["hosts"]]
        hosts = [h for h in hosts if h[0] is not None]
        if len(hosts) < max(1, len(base["hosts"]) * 8 // 10):
            return {"why": "성능 이력에 이 클러스터의 호스트가 충분히 없어 지금 값으로 계산했습니다"}
        r = await asyncio.to_thread(ps.cluster_peak, hosts, days)
        if r.get("samples", 0) < 24:
            return {"why": f"성능 이력이 {r.get('samples', 0)}시간뿐이라(최소 24시간) 지금 값으로 계산했습니다"}
        k = len(base["hosts"]) / len(hosts)               # 이력이 없는 호스트 몫을 평균으로 보정
        return {**r, "days": days, "cpu_mhz": r["cpu_mhz"] * k, "mem_mb": r["mem_mb"] * k, "cpu_max_mhz": r["cpu_max_mhz"] * k, "mem_max_mb": r["mem_max_mb"] * k}


    @r.get("/api/capacity/whatif/scenarios")
    async def scenarios():
        return {"scenarios": await SCN.list()}

    @r.post("/api/capacity/whatif/scenarios")
    async def scenario_add(request: Request):
        from fastapi import HTTPException
        try:
            b = await request.json()
            if not isinstance(b, dict):
                raise ValueError("JSON 객체가 필요합니다")
            o = await SCN.add(b, who(request).get("user", ""))
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        await audit(request, "capacity.scenario_add", o["name"])
        return o

    @r.delete("/api/capacity/whatif/scenarios/{sid}")
    async def scenario_del(sid: int, request: Request):
        from fastapi import HTTPException
        if not await SCN.remove(sid):
            raise HTTPException(404)
        await audit(request, "capacity.scenario_remove", str(sid))
        return {"ok": True}

    # ---- 서버 사양(2.34.0): vCenter 호스트 유형 · BMC 스캔 · 수집 스크립트로 올린 것
    from .serverspec import SpecStore
    SPECS = SpecStore(ENGINE.store)

    @r.get("/api/capacity/specs")
    async def specs():
        from . import serverspec as SS
        rd = []
        try:
            rd = SS.from_readiness(await ENGINE.readiness.latest_hosts())
        except Exception:  # noqa: BLE001  — 준비도 스캔이 없거나 꺼진 설치본
            rd = []
        return {"uploaded": await SPECS.list(), "vcenter": SS.from_vcenter(ENGINE.connectors), "bmc": rd,
                "scripts": [{"name": "collect-server-spec.sh", "os": "Linux · ESXi 셸"}, {"name": "collect-server-spec.ps1", "os": "Windows"}]}

    @r.post("/api/capacity/specs")
    async def spec_add(request: Request):
        from fastapi import HTTPException
        try:
            b = await request.json()
            raw = b.get("spec") if isinstance(b, dict) else None
            if isinstance(raw, str):
                import json as _json
                raw = _json.loads(raw)
            o = await SPECS.add(str(b.get("name") or ""), raw, who(request).get("user", ""))
        except (ValueError, TypeError, AttributeError) as e:
            raise HTTPException(400, str(e) if isinstance(e, ValueError) and "JSON" not in type(e).__name__ else "JSON 형식이 아닙니다 — 수집 스크립트 출력을 그대로 붙여 넣으세요")
        await audit(request, "capacity.spec_add", o["name"])
        return o

    @r.delete("/api/capacity/specs/{sid}")
    async def spec_del(sid: int, request: Request):
        from fastapi import HTTPException
        if not await SPECS.remove(sid):
            raise HTTPException(404)
        await audit(request, "capacity.spec_remove", str(sid))
        return {"ok": True}

    @r.get("/api/capacity/spec-script/{name}")
    async def spec_script(name: str):
        from pathlib import Path

        from fastapi import HTTPException
        if name not in ("collect-server-spec.sh", "collect-server-spec.ps1"):
            raise HTTPException(404)
        f = Path(__file__).resolve().parent.parent / "scripts" / "spec" / name
        if not f.is_file():
            raise HTTPException(404, "이 설치본에 스크립트가 없습니다")
        return Response(f.read_bytes(), media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})

    @r.post("/api/capacity/sample")
    async def sample():
        n = await C.sample()
        return {"sampled": n, "stats": C.stats}

    return r
