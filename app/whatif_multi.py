"""가정 분석 확장(2.36.0) — 여러 클러스터·적정화·비용을 엮는 계산. 모두 읽기 전용(vCenter·SRM 에 아무것도 바꾸지 않음).

  · rightsizing_reclaim  적정화 권고(유휴 VM 끄기·과다 할당 축소·과소 할당 증설·장기 꺼짐 VM 정리)를 적용했을 때 클러스터가 돌려받는 수요
  · move                  VM 묶음을 다른 클러스터로 옮겼을 때 양쪽의 여유·확인할 점(공유 데이터스토어·EVC·교차 vCenter)
  · dr                    보호 그룹(SRM) 또는 클러스터 전체를 복구 사이트 클러스터가 받을 때 버티는지
  · cost                  증설안의 서버·라이선스 비용(클라우드 비용 비교의 VCF 원가 모델) ↔ 같은 VM 을 퍼블릭 클라우드에 올릴 때
VM 수요: CPU = vCenter quickStats overallCpuUsage(MHz), 메모리 = 설정 메모리 × 사용률 가정(기본 80%, 가정 분석의 VM 추가와 같은 기준).
"""
from __future__ import annotations

from typing import Any

from . import whatif as W
from .cpugen import EVC_RANK, generation


def rightsizing_reclaim(rs: dict, live_vms: dict, vcenter: str, cluster: str) -> dict[str, Any]:
    """capacity.rightsizing() 결과 중 이 클러스터 몫 → 돌려받는 CPU(MHz)·메모리(MB)·vCPU·켜진 VM 수·디스크(GB)"""
    mine = lambda x: x.get("vcenter") == vcenter and (x.get("cluster") or "") == cluster   # noqa: E731
    out = {"cpu_mhz": 0.0, "mem_mb": 0.0, "vcpu": 0.0, "vms_off": 0, "disk_gb": 0.0, "idle": 0, "oversized": 0, "undersized": 0, "powered_off": 0,
           "observed_days": (rs or {}).get("days")}
    for x in (rs or {}).get("idle") or []:
        if mine(x):
            v = live_vms.get(x["vm"], {})
            out["cpu_mhz"] += float(v.get("cpu_mhz") or 0)
            out["mem_mb"] += float(x.get("mem_gb") or 0) * 1024
            out["vcpu"] += float(x.get("vcpu") or 0)
            out["vms_off"] += 1
            out["idle"] += 1
    for x in (rs or {}).get("oversized") or []:
        if mine(x):
            out["mem_mb"] += max(0.0, float(x.get("mem_gb") or 0) - float(x.get("rec_mem_gb") or x.get("mem_gb") or 0)) * 1024
            out["vcpu"] += max(0.0, float(x.get("vcpu") or 0) - float(x.get("rec_vcpu") or x.get("vcpu") or 0))
            out["oversized"] += 1
    for x in (rs or {}).get("undersized") or []:
        if mine(x):
            out["mem_mb"] -= max(0.0, float(x.get("rec_mem_gb") or 0) - float(x.get("mem_gb") or 0)) * 1024
            out["vcpu"] -= max(0.0, float(x.get("rec_vcpu") or 0) - float(x.get("vcpu") or 0))
            out["undersized"] += 1
    for x in (rs or {}).get("powered_off") or []:
        if mine(x):
            out["disk_gb"] += float(x.get("disk_gb") or 0)
            out["powered_off"] += 1
    return out


def _vm_demand(v: dict, mem_util: float) -> tuple[float, float]:
    """CPU = 성능 이력 피크(peak_mhz, 2.37.0)가 있으면 그것, 없으면 vCenter 순간 값. 메모리 = 설정 × 사용률 가정"""
    cpu = v.get("peak_mhz")
    return float(cpu if cpu is not None else (v.get("cpu_mhz") or 0)), float(v.get("mem_mb") or 0) * mem_util / 100


def attach_peaks(vms: list[dict], peaks: dict[str, dict], core_mhz: float) -> dict[str, Any]:
    """peaks = {VM 이름: {cpu_pct, samples}} → vms 에 peak_mhz(= vCPU × 코어 MHz × 피크%) 를 붙이고 기준 요약을 돌려준다"""
    n = 0
    for v in vms:
        p = peaks.get(v.get("name", ""))
        if p:
            v["peak_mhz"] = int(v.get("vcpu") or 1) * core_mhz * p["cpu_pct"] / 100
            n += 1
    return {"vms_with_history": n, "vms": len(vms), "kind": "p95" if n else "now"}


def _cluster_gen(base: dict) -> tuple[str | None, int | None]:
    """클러스터가 VM 에 보여 주는 CPU 기능 수준 — EVC 가 있으면 EVC, 없으면 가장 낮은 호스트 세대"""
    if base.get("evc") and base["evc"] in EVC_RANK:
        return EVC_RANK[base["evc"]]
    gs = [g for g in (generation(h.get("cpu_model", "")) for h in base["hosts"]) if g and g.get("rank") is not None]
    if not gs:
        return None, None
    lo = min(gs, key=lambda g: g["rank"])
    return lo["vendor"], lo["rank"]


def _side(base: dict, d_cpu: float, d_mem: float, d_vcpu: float, d_vms: int, ha: int) -> dict[str, Any]:
    cpu = sum(h["cpu_used"] for h in base["hosts"])
    mem = sum(h["mem_used"] for h in base["hosts"])
    b = W._state(base, base["hosts"], cpu, mem, base["vcpu"], base["vms_on"], ha)
    a = W._state(base, base["hosts"], max(0.0, cpu + d_cpu), max(0.0, mem + d_mem), max(0.0, base["vcpu"] + d_vcpu), max(0, base["vms_on"] + d_vms), ha)
    b.pop("_")
    a.pop("_")
    return {"before": b | {"verdict": W._verdict(b)}, "after": a | {"verdict": W._verdict(a)}}


def _storage_after(base: dict, add_gb: float) -> dict[str, Any] | None:
    if not base.get("ds_total_gb"):
        return None
    tot, used = base["ds_total_gb"], base["ds_total_gb"] - base.get("ds_free_gb", 0)
    return {"total_tb": round(tot / 1000, 1), "pct": round(used / tot * 100, 1), "after_pct": round((used + add_gb) / tot * 100, 1), "added_tb": round(add_gb / 1000, 2)}


def _avg_host(base: dict) -> dict:
    n = len(base["hosts"])
    return {"name": "(추가)", "cpu_mhz": sum(h["cpu_mhz"] for h in base["hosts"]) / n, "mem_mb": sum(h["mem_mb"] for h in base["hosts"]) / n,
            "core_mhz": sum(h["core_mhz"] for h in base["hosts"]) / n, "cpu_used": 0.0, "mem_used": 0.0,
            "sockets": base["hosts"][0].get("sockets", 0), "cpu_model": base["hosts"][0].get("cpu_model", "")}


def move(src: dict, dst: dict, vms: list[dict], *, src_name: str, dst_name: str, cross_vc: bool, dst_topo: dict, ha: int = 1,
         mem_util: float = 80.0, basis: dict | None = None) -> dict[str, Any]:
    """vms = 옮길 VM(토폴로지 레코드 + 'name'). 켜진 VM 만 CPU·메모리 수요에 들어가고, 디스크는 모두 센다"""
    if src is dst or src_name == dst_name and not cross_vc:
        raise ValueError("원본과 대상 클러스터가 같습니다")
    on = [v for v in vms if "poweredOn" in str(v.get("power"))]
    c = sum(_vm_demand(v, mem_util)[0] for v in on)
    m = sum(_vm_demand(v, mem_util)[1] for v in on)
    vc = sum(int(v.get("vcpu") or 0) for v in on)
    disk = sum(float(v.get("disk_gb") or 0) for v in vms)
    s = _side(src, -c, -m, -vc, -len(on), ha)
    d = _side(dst, c, m, vc, len(on), ha)
    d["hosts_needed"] = W._need(dst, dst["hosts"], sum(h["cpu_used"] for h in dst["hosts"]) + c, sum(h["mem_used"] for h in dst["hosts"]) + m, ha, _avg_host(dst))
    # 대상 호스트가 모두 보는 데이터스토어에 VM 디스크가 있나(없으면 스토리지 vMotion 도 함께)
    dst_hosts = {h["name"] for h in dst["hosts"]}
    H = dst_topo.get("hosts") or {}
    seen = set.intersection(*[set((H.get(h) or {}).get("datastores") or []) for h in dst_hosts]) if dst_hosts else set()
    need_sv = [v for v in vms if not set(v.get("datastores") or []) <= seen]
    sv_gb = sum(float(v.get("disk_gb") or 0) for v in need_sv)
    checks = []
    if need_sv:
        checks.append({"level": "warn", "text": f"{len(need_sv)}대({sv_gb / 1000:.1f} TB)는 대상 클러스터가 보지 못하는 데이터스토어에 있습니다 — 스토리지 vMotion 을 함께 해야 합니다."})
    else:
        checks.append({"level": "ok", "text": "모든 VM 디스크가 대상 클러스터와 공유하는 데이터스토어에 있습니다 — 컴퓨트 vMotion 만으로 옮길 수 있습니다."})
    sv_, sr = _cluster_gen(src)
    dv, dr_ = _cluster_gen(dst)
    if sv_ and dv and sv_ != dv:
        checks.append({"level": "bad", "text": "원본과 대상의 CPU 회사(Intel/AMD)가 달라 켜진 채로 옮길 수 없습니다 — 전원을 끄고 옮겨야 합니다(KB 324991)."})
    elif sr is not None and dr_ is not None and dr_ < sr:
        checks.append({"level": "warn", "text": f"대상 클러스터의 CPU 기능 수준({dst.get('evc') or '최저 호스트 세대'})이 원본보다 낮습니다 — "
                                                "켜진 VM 은 전원을 껐다 켜거나 VM 단위 EVC 가 필요할 수 있습니다."})
    elif sr is not None and dr_ is not None:
        checks.append({"level": "ok", "text": "대상 클러스터의 CPU 기능 수준이 원본 이상입니다 — 켜진 채로 옮길 수 있습니다."})
    if cross_vc:
        checks.append({"level": "info", "text": "다른 vCenter 로 옮깁니다 — 교차 vCenter vMotion(같은 SSO 도메인 또는 Advanced Cross vCenter vMotion)과 "
                                                 "대상 쪽 포트그룹 이름을 확인하세요."})
        nets = set((dst_topo.get("networks") or {}).keys())
        miss = sorted({n for v in vms for n in (v.get("networks") or []) if n and nets and n not in nets})
        if miss:
            checks.append({"level": "warn", "text": "대상 vCenter 에 없는 네트워크: " + ", ".join(miss[:8]) + (" 외" if len(miss) > 8 else "")})
    return {"source": {"cluster": src_name, **s, "storage": _storage_after(src, -sv_gb)},
            "target": {"cluster": dst_name, **d, "storage": _storage_after(dst, sv_gb)},
            "moved": {"vms": len(vms), "powered_on": len(on), "cpu_ghz": round(c / 1000, 1), "mem_gb": round(m / 1024, 1), "vcpu": vc,
                      "disk_tb": round(disk / 1000, 2), "storage_vmotion_tb": round(sv_gb / 1000, 2)},
            "checks": checks, "assume": {"ha_failures": ha, "mem_util_pct": mem_util}, "basis": basis or {"kind": "now"}}


def _dr_demand(v: dict, mem_util: float, core: float) -> tuple[float, float]:
    cpu, mem = _vm_demand(v, mem_util)
    if "poweredOn" not in str(v.get("power")) and v.get("peak_mhz") is None:   # 꺼져 있던 VM 은 복구 때 켜진다 — CPU 수요는 vCPU × 코어 MHz × 25% 가정
        cpu = int(v.get("vcpu") or 1) * core * 0.25
    return cpu, mem


def dr(dst: dict, vms: list[dict], missing: list[str], *, dst_name: str, ha: int = 1, mem_util: float = 80.0, source: str = "",
       order: list[tuple[str, list[dict]]] | None = None, basis: dict | None = None) -> dict[str, Any]:
    """복구 사이트 클러스터가 vms(보호 VM — 복구 때 모두 켜짐)를 받을 때. 꺼져 있던 VM 은 설정값×사용률로 센다.
    order = [(보호 그룹, 그 그룹 VM)] — 주어지면 그 순서로 하나씩 복구했을 때 어디까지 80%·100% 안에 드는지(2.37.0 복구 순서 계획)"""
    core = sum(h["core_mhz"] for h in dst["hosts"]) / len(dst["hosts"])
    c = m = 0.0
    vc = 0
    disk = 0.0
    for v in vms:
        cpu, mem = _dr_demand(v, mem_util, core)
        c += cpu
        m += mem
        vc += int(v.get("vcpu") or 0)
        disk += float(v.get("disk_gb") or 0)
    d = _side(dst, c, m, vc, len(vms), ha)
    d["hosts_needed"] = W._need(dst, dst["hosts"], sum(h["cpu_used"] for h in dst["hosts"]) + c, sum(h["mem_used"] for h in dst["hosts"]) + m, ha, _avg_host(dst))
    a = d["after"]
    verdict = a["verdict"]
    lines = []
    if verdict == "ok":
        lines.append(f"복구 후에도 {dst_name} 의 사용률이 쓸 수 있는 용량의 80% 미만입니다.")
    elif verdict == "warn":
        lines.append("복구는 되지만 쓸 수 있는 용량의 80~100% 입니다 — 복구 중 성능 저하와 HA 여유 부족을 감안하세요.")
    else:
        lines.append(f"복구 사이트 용량이 모자랍니다 — 같은 사양 서버 {d['hosts_needed'] if d['hosts_needed'] is not None else '64대 이상'}대가 더 있어야 80% 안에 듭니다. "
                     "중요도가 낮은 VM 을 복구 계획에서 빼거나, 대상 쪽 개발·시험 VM 을 끄는 순서를 계획하세요.")
    if missing:
        lines.append(f"보호 VM {len(missing)}대는 인벤토리에서 사양을 찾지 못해 빠졌습니다(이름 불일치·다른 vCenter).")
    plan = []
    if order:
        c0, m0 = sum(h["cpu_used"] for h in dst["hosts"]), sum(h["mem_used"] for h in dst["hosts"])
        cc = mm = 0.0
        seen: set[str] = set()
        for gname, gvms in order:
            gv = [v for v in gvms if v.get("name") not in seen]
            seen.update(v.get("name") for v in gv)
            gc = gm = 0.0
            for v in gv:
                x, y = _dr_demand(v, mem_util, core)
                gc, gm = gc + x, gm + y
            cc, mm = cc + gc, mm + gm
            st = W._state(dst, dst["hosts"], c0 + cc, m0 + mm, 0, 0, ha)
            st.pop("_")
            plan.append({"group": gname, "vms": len(gv), "cpu_ghz": round(gc / 1000, 1), "mem_gb": round(gm / 1024, 1),
                         "cpu_pct": st["cpu"]["pct_usable"], "mem_pct": st["mem"]["pct_usable"], "verdict": W._verdict(st)})
        fit80 = next((i for i, p in enumerate(plan) if p["verdict"] != "ok"), len(plan))
        fit100 = next((i for i, p in enumerate(plan) if p["verdict"] == "bad"), len(plan))
        if plan and fit100 < len(plan):
            lines.append(f"첫 그룹 '{plan[0]['group']}' 부터 모자랍니다 — 복구 사이트가 이미 빠듯하므로 대상 쪽 개발·시험 VM 을 먼저 끄는 단계를 복구 계획 맨 앞에 두세요."
                         if fit100 == 0 else
                         f"고른 순서대로 복구하면 {fit100}번째 그룹('{plan[fit100 - 1]['group']}')까지 수용되고 '{plan[fit100]['group']}' 부터 모자랍니다 — 뒤 그룹은 대상 쪽 VM 을 끈 뒤 복구하도록 계획하세요.")
        plan = {"rows": plan, "fit_80": fit80, "fit_100": fit100}
    return {"target": {"cluster": dst_name, **d, "storage": _storage_after(dst, disk)}, "plan": plan or None, "basis": basis or {"kind": "now"},
            "recovered": {"vms": len(vms), "cpu_ghz": round(c / 1000, 1), "mem_gb": round(m / 1024, 1), "vcpu": vc, "disk_tb": round(disk / 1000, 2)},
            "missing": missing[:200], "missing_count": len(missing), "source": source, "summary": lines,
            "assume": {"ha_failures": ha, "mem_util_pct": mem_util, "off_vm_cpu_pct": 25, "storage": "복제된 디스크가 대상 데이터스토어에 이미 있다면 추가 용량은 0 — 여기서는 대상 공유 데이터스토어 사용률에 더해 보수적으로 표시"}}


def cost(res: dict, st: dict, prices: dict, *, add_vms: int, vm_vcpu: float, vm_mem_gb: float, vm_disk_gb: float, hosts_planned: int | None = None) -> dict[str, Any]:
    """증설안 비용(VCF 원가 모델) ↔ 같은 VM 을 퍼블릭 클라우드에 올렸을 때(클라우드 비용 비교 단가표). 금액은 각 모델의 통화 그대로"""
    from .cloudcost import CloudCost
    from .serverspec import licensed_cores
    H = float(prices.get("hours_per_month") or 730)
    inp = res.get("inputs") or {}
    add_h = hosts_planned if hosts_planned is not None else int(inp.get("add_hosts") or 0)
    lic = res.get("license") or {}
    per_host = lic.get("per_new_host")
    if per_host is None:
        hs = res.get("host_spec") or {}
        per_host = licensed_cores(hs.get("sockets") or 2, hs.get("cores") or 0) if hs.get("cores") else None
    lic_delta = (lic.get("delta") if hosts_planned is None and lic.get("delta") is not None else (per_host or 0) * add_h)
    sub, hw, am, fac = (float(st.get(k) or 0) for k in ("subscription_per_core_year", "hw_per_host", "amort_years", "facility_per_host_year"))
    am = max(1.0, am)
    cur = st.get("vcf_currency") or "USD"
    vcf = None
    note = ""
    if sub or hw or fac:
        annual = lic_delta * sub + add_h * (hw / am + fac)
        vcf = {"currency": cur, "hosts": add_h, "license_cores": lic_delta, "capex_hw": round(add_h * hw), "annual": round(annual), "monthly": round(annual / 12),
               "parts": {"subscription_year": round(lic_delta * sub), "hardware_year": round(add_h * hw / am), "facility_year": round(add_h * fac)},
               "per_vm_month": round(annual / 12 / add_vms, 1) if add_vms else None, "years": int(st.get("tco_years") or 5)}
        vcf["tco"] = round(annual * vcf["years"])
    else:
        note = "클라우드 비용 비교 › 원가 모델에 VCF 구독 단가(코어·연)·서버 단가·상면 비용을 넣으면 증설 비용을 계산합니다."
    cloud = []
    if add_vms:
        for pk, prov in (prices.get("providers") or {}).items():
            mt = CloudCost.match(prov, vm_vcpu, vm_mem_gb, False, st.get("commit") or "ondemand")
            gbm = ((prov.get("storage") or {}).get("gb_month"))
            if mt.get("hourly") is None:
                cloud.append({"provider": pk, "label": prov.get("label", pk), "sku": mt.get("sku"), "monthly": None, "missing": mt.get("missing")})
                continue
            comp = mt["hourly"] * H * add_vms
            stor = (gbm or 0) * vm_disk_gb * add_vms
            cloud.append({"provider": pk, "label": prov.get("label", pk), "sku": mt.get("sku"), "region": prov.get("region", ""), "verified": mt.get("verified"),
                          "monthly": round(comp + stor), "compute": round(comp), "storage": round(stor), "note": mt.get("note", ""),
                          "years_total": round((comp + stor) * 12 * int(st.get("tco_years") or 5) + float(st.get("cloud_migration_once") or 0))})
    return {"vcf": vcf, "cloud": cloud, "cloud_currency": "USD", "commit": st.get("commit") or "ondemand", "note": note,
            "vm": {"count": add_vms, "vcpu": vm_vcpu, "mem_gb": vm_mem_gb, "disk_gb": vm_disk_gb},
            "fx_krw_per_usd": float(st.get("fx_krw_per_usd") or 0) or None,
            "caveat": "클라우드 단가는 '클라우드 비용 비교'의 단가표(확인 여부 표시) 기준, VCF 쪽은 증설분(서버·코어)만 — 기존 플랫폼 원가는 넣지 않았습니다."}
