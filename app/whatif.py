"""가정 분석(What-If, 2.33.0) — VM·호스트를 더하거나 뺐을 때 클러스터 CPU·메모리 여유와 남은 기간이 어떻게 바뀌는지 계산

· 지금 값: vCenter 토폴로지(호스트 총 MHz·메모리, 지금 사용량, 켜진 VM 의 vCPU·메모리)
· HA 여유: 가장 큰 호스트 N대를 뺀 용량을 '쓸 수 있는 용량'으로 본다(N = 견딜 호스트 장애 수)
· 남은 기간: 용량 계획의 일별 증가율(%p/일)을 그대로 쓰되, 용량이 바뀌면 같은 증가량이 차지하는 비율도 바뀐다
· 판정: 쓸 수 있는 용량 대비 사용률 80% 미만 = 수용 가능, 80~100% = 빠듯함, 100% 초과 = 수용 불가
읽기 전용 계산 — vCenter 에 아무것도 바꾸지 않는다.
"""
from __future__ import annotations

import math
from typing import Any

WARN, FULL, HORIZON = 80.0, 100.0, 90.0


def cluster_base(conn, cluster: str) -> dict[str, Any] | None:
    """커넥터 토폴로지 → 계산 입력(없으면 None)"""
    t = getattr(conn, "topology", {}) or {}
    c = (t.get("clusters") or {}).get(cluster)
    if not c:
        return None
    H = t.get("hosts") or {}
    hosts = [{"name": h, "cpu_mhz": float(H[h].get("cpu_mhz") or 0), "mem_mb": float(H[h].get("mem_mb") or 0), "core_mhz": float(H[h].get("core_mhz") or 0),
              "cpu_used": float(H[h].get("cpu_used_mhz") or 0), "mem_used": float(H[h].get("mem_used_mb") or 0),
              "sockets": int(H[h].get("sockets") or 0), "cpu_model": str(H[h].get("cpu_model") or "")}
             for h in c.get("hosts", []) if h in H and (H[h].get("cpu_mhz") or 0) > 0 and not H[h].get("maintenance")]
    vms = [v for v in (t.get("vms") or {}).values() if v.get("cluster") == cluster and "poweredOn" in str(v.get("power"))]
    # 공유 데이터스토어(클러스터의 모든 호스트가 보는 것, 로컬 제외) — VM 디스크를 더했을 때의 사용률
    names = [h["name"] for h in hosts]
    D = t.get("datastores") or {}
    shared = [d for dn, d in D.items() if (d.get("capacity_gb") or 0) and d.get("local") is not True
              and names and all(dn in (H[n].get("datastores") or []) for n in names)]
    vs = [d for d in shared if str(d.get("type") or "").lower() == "vsan"]
    return {"hosts": hosts, "vms_on": len(vms), "vcpu": sum(int(v.get("vcpu") or 0) for v in vms), "vm_mem_mb": sum(int(v.get("mem_mb") or 0) for v in vms),
            "vsan": bool(c.get("vsan")), "ds_total_gb": sum(float(d.get("capacity_gb") or 0) for d in shared), "ds_free_gb": sum(float(d.get("free_gb") or 0) for d in shared),
            "ds_count": len(shared), "vm_disk_gb": sum(float(v.get("disk_gb") or 0) for v in vms),
            "ds_names": [dn for dn, d in D.items() if (d.get("capacity_gb") or 0) and d.get("local") is not True and names and all(dn in (H[n].get("datastores") or []) for n in names)],
            # 2.36.0 — vSAN 원시 용량(정책 반영 전)·ESA 여부·클러스터 EVC
            "vsan_esa": bool(c.get("vsan_esa")), "evc": str(c.get("evc") or ""),
            "vsan_raw_gb": sum(float(d.get("capacity_gb") or 0) for d in vs), "vsan_free_gb": sum(float(d.get("free_gb") or 0) for d in vs),
            "vsan_meas": _vsan_meas(c.get("vsan_health") or {})}


def _vsan_meas(vh: dict) -> dict[str, Any] | None:
    """2.37.0 vSAN 공간 보고 실측값 — 정책 배수(주 사본 대비 복제·패리티), 중복 제거·압축 절감률, 용량 예비 설정"""
    sp = vh.get("space") or {}
    if not sp:
        return None
    rv = vh.get("reserve") or {}
    on = lambda v: None if not v else not any(x in str(v).lower() for x in ("disable", "none", "off"))   # noqa: E731
    return {"policy_mult": sp.get("policy_mult"), "dr": sp.get("ratio"), "total_gb": sp.get("total_gb"), "free_gb": sp.get("free_gb"),
            "primary_gb": sp.get("primary_gb"), "ops_reserve": on(rv.get("ops")), "host_reserve": on(rv.get("host_rebuild")), "ts": vh.get("ts")}


# ------------------------------------------------------------------ vSAN 사용 가능 용량(2.36.0)
# 정책별 원시 용량 배수·최소 호스트 — vSAN ESA 는 적응형 RAID-5(3~5대 2+1, 6대 이상 4+1)
VSAN_POLICIES = {
    "measured": "실측(지금 객체들의 복제·패리티 비율)",
    "auto": "클러스터 기본(ESA=RAID-5 적응형, OSA=RAID-1)",
    "r1": "FTT=1 RAID-1(미러)", "r5": "FTT=1 RAID-5(이레이저 코딩)", "r6": "FTT=2 RAID-6(4+2)", "r1f2": "FTT=2 RAID-1(미러)",
}


def vsan_scheme(policy: str, hosts: int, esa: bool) -> dict[str, Any]:
    p = policy if policy in VSAN_POLICIES else "auto"
    if p == "auto":
        p = "r5" if esa else "r1"
    if p == "r1":
        return {"policy": p, "scheme": "RAID-1", "mult": 2.0, "min_hosts": 3}
    if p == "r1f2":
        return {"policy": p, "scheme": "RAID-1 ×3", "mult": 3.0, "min_hosts": 5}
    if p == "r6":
        return {"policy": p, "scheme": "RAID-6 4+2", "mult": 1.5, "min_hosts": 6}
    if esa:
        return {"policy": p, "scheme": "RAID-5 4+1", "mult": 1.25, "min_hosts": 6} if hosts >= 6 else {"policy": p, "scheme": "RAID-5 2+1", "mult": 1.5, "min_hosts": 3}
    return {"policy": p, "scheme": "RAID-5 3+1", "mult": 4 / 3, "min_hosts": 4}


def vsan_usable(raw_gb: float, free_gb: float, hosts: int, esa: bool, policy: str, reserve_pct: float, host_reserve: bool, dr: float,
                hosts2: int | None = None, raw2_gb: float | None = None, add_logical_gb: float = 0.0, measured_mult: float | None = None) -> dict[str, Any]:
    """원시 용량 → 실제로 VM 데이터를 담을 수 있는 용량(TB, 논리).
    쓸 수 있는 원시 = 원시 × (1 − 운영 예비율) − (호스트 재구축 예비: 호스트 1대 몫)
      vSAN 7 U1 이후 고정 25~30% 여유 대신 Operations Reserve(0~25%) + Host Rebuild Reserve(N+1) — 기본 10% + 1대(vSAN Sizer 값으로 조정)
    논리 용량 = 쓸 수 있는 원시 ÷ 정책 배수 × 데이터 절감률(중복 제거·압축)
    지금 사용량(원시)도 같은 배수·절감률로 논리 사용량으로 환산한다 — 모든 객체가 이 정책이라고 가정."""
    meas = measured_mult if measured_mult and measured_mult >= 1 and policy == "measured" else None
    sc = {"policy": "measured", "scheme": f"실측 {measured_mult:.2f}배", "mult": measured_mult, "min_hosts": 3} if meas else vsan_scheme(policy, hosts, esa)
    dr = max(1.0, dr)

    def calc(raw: float, n: int, sch: dict) -> tuple[float, float, float]:
        host_res = raw / n if host_reserve and n > 0 else 0.0
        eff = max(0.0, raw * (1 - reserve_pct / 100) - host_res)
        return eff, host_res, eff / sch["mult"] * dr
    used_raw = max(0.0, raw_gb - free_gb)
    eff, hres, usable = calc(raw_gb, hosts, sc)
    used_log = used_raw / sc["mult"] * dr
    out = {"policy": sc["policy"], "policy_label": VSAN_POLICIES.get(sc["policy"], sc["policy"]), "scheme": sc["scheme"], "mult": round(sc["mult"], 3), "min_hosts": sc["min_hosts"],
           "esa": esa, "reserve_pct": reserve_pct, "host_reserve": host_reserve, "dr": dr,
           "raw_tb": round(raw_gb / 1000, 1), "reserve_tb": round(raw_gb * reserve_pct / 100 / 1000, 1), "host_reserve_tb": round(hres / 1000, 1),
           "usable_tb": round(usable / 1000, 1), "used_tb": round(used_log / 1000, 1), "free_tb": round((usable - used_log) / 1000, 1),
           "pct": round(used_log / usable * 100, 1) if usable else None, "hosts_ok": hosts >= sc["min_hosts"]}
    if hosts2 is not None:
        sc2 = sc if meas else vsan_scheme(policy, hosts2, esa)
        eff2, _, usable2 = calc(raw2_gb if raw2_gb is not None else raw_gb, hosts2, sc2)
        used2 = max(0.0, used_log + add_logical_gb)
        out["after"] = {"scheme": sc2["scheme"], "mult": round(sc2["mult"], 3), "raw_tb": round((raw2_gb if raw2_gb is not None else raw_gb) / 1000, 1),
                        "usable_tb": round(usable2 / 1000, 1), "used_tb": round(used2 / 1000, 1), "free_tb": round((usable2 - used2) / 1000, 1),
                        "pct": round(used2 / usable2 * 100, 1) if usable2 else None, "hosts_ok": hosts2 >= sc2["min_hosts"], "min_hosts": sc2["min_hosts"]}
        if sc2["scheme"] != sc["scheme"]:
            out["after"]["scheme_note"] = (f"호스트 {hosts}→{hosts2}대로 {sc['scheme']} → {sc2['scheme']} 로 바뀝니다"
                                           + (" — ESA 적응형 RAID-5 는 호스트 수가 바뀐 뒤 약 24시간 지나 재배치합니다." if esa and sc["policy"] == "r5" else ""))
    return out


def _need(base: dict, hosts: list[dict], cpu: float, mem: float, ha: int, new_host: dict, cap: int = 64) -> int | None:
    """80% 안(판정 ok)에 들이려면 new_host 사양을 몇 대 더해야 하나 — 이미 ok 면 0, cap 대로도 안 되면 None"""
    hs = list(hosts)
    for k in range(cap + 1):
        s = _state(base, hs, max(0.0, cpu), max(0.0, mem), 0, 0, ha)
        s.pop("_")
        if _verdict(s) == "ok":
            return k
        hs.append(dict(new_host))
    return None


def _quarters(today) -> list[tuple[str, Any]]:
    """오늘이 속한 분기부터 4개 분기의 마지막 날"""
    import datetime as dt
    out = []
    y, q = today.year, (today.month - 1) // 3 + 1
    for _ in range(4):
        end_m = q * 3
        nxt = dt.date(y + (end_m == 12), 1 if end_m == 12 else end_m + 1, 1)
        out.append((f"{y}년 {q}분기({end_m - 2}~{end_m}월)", nxt - dt.timedelta(days=1)))
        y, q = (y + 1, 1) if q == 4 else (y, q + 1)
    return out


def _num(b: dict, k: str, lo: float, hi: float, default: float = 0.0) -> float:
    try:
        v = float(b.get(k) if b.get(k) not in (None, "") else default)
    except (TypeError, ValueError):
        raise ValueError(f"{k}: 숫자가 필요합니다") from None
    if not lo <= v <= hi or math.isnan(v):
        raise ValueError(f"{k}: {lo:g}~{hi:g} 범위")
    return v


def _state(base: dict, hosts: list[dict], cpu_used: float, mem_used: float, vcpu: float, vms: float, ha: int) -> dict[str, Any]:
    ct, mt = sum(h["cpu_mhz"] for h in hosts), sum(h["mem_mb"] for h in hosts)
    big = sorted(hosts, key=lambda h: h["mem_mb"], reverse=True)[:ha]
    bigc = sorted(hosts, key=lambda h: h["cpu_mhz"], reverse=True)[:ha]
    cu, mu = max(0.0, ct - sum(h["cpu_mhz"] for h in bigc)), max(0.0, mt - sum(h["mem_mb"] for h in big))
    cores = sum(h["cpu_mhz"] / h["core_mhz"] for h in hosts if h["core_mhz"])
    pct = lambda a, b: round(a / b * 100, 1) if b > 0 else None   # noqa: E731
    return {"hosts": len(hosts), "vms": round(vms), "vcpu": round(vcpu), "cores": round(cores),
            "vcpu_per_core": round(vcpu / cores, 2) if cores else None,
            "cpu": {"total_ghz": round(ct / 1000, 1), "usable_ghz": round(cu / 1000, 1), "used_ghz": round(cpu_used / 1000, 1), "free_ghz": round((cu - cpu_used) / 1000, 1),
                    "pct_total": pct(cpu_used, ct), "pct_usable": pct(cpu_used, cu)},
            "mem": {"total_gb": round(mt / 1024, 1), "usable_gb": round(mu / 1024, 1), "used_gb": round(mem_used / 1024, 1), "free_gb": round((mu - mem_used) / 1024, 1),
                    "pct_total": pct(mem_used, mt), "pct_usable": pct(mem_used, mu)},
            "_": (ct, mt, cu, mu)}


def _verdict(s: dict) -> str:
    p = [x for x in (s["cpu"]["pct_usable"], s["mem"]["pct_usable"]) if x is not None]
    if not p or len(p) < 2:
        return "bad"                                   # 쓸 수 있는 용량이 0(호스트가 HA 여유 수 이하)
    return "bad" if max(p) > FULL else "warn" if max(p) >= WARN else "ok"


def _days(pct_total: float | None, slope: float | None, scale: float) -> int | None:
    """전체 용량 대비 90% 도달까지 남은 날. slope = 지금 용량 기준 %p/일, scale = 지금 용량 ÷ 가정 뒤 용량"""
    if pct_total is None:
        return None
    if pct_total >= HORIZON:
        return 0
    if not slope or slope <= 0:
        return None                                    # 증가 없음
    return int((HORIZON - pct_total) / (slope * scale))


def simulate(base: dict, body: dict, slopes: dict | None = None, demand: dict | None = None, reclaim: dict | None = None,
             today=None) -> dict[str, Any]:
    """base = cluster_base(), body = 화면 입력, slopes = {"cpu": %p/일, "mem": %p/일}(용량 계획 예측),
    demand = {"cpu_mhz", "mem_mb", ...}: 지금 값 대신 쓸 수요(최근 N일 95퍼센타일 등, 2.35.0)
    reclaim = 적정화 권고를 적용했을 때 돌려받는 수요(2.36.0, rightsizing_reclaim()), today = 분기 계획 기준일(시험용)"""
    hosts = [dict(h) for h in base["hosts"]]
    if not hosts:
        raise ValueError("이 클러스터에 계산할 호스트가 없습니다(유지보수 모드 제외)")
    b = body or {}
    if demand and demand.get("cpu_mhz") is not None:               # 호스트별 사용량을 비율대로 늘리거나 줄여 합계를 맞춘다
        for key, tot in (("cpu_used", demand["cpu_mhz"]), ("mem_used", demand["mem_mb"])):
            cur = sum(h[key] for h in hosts)
            for h in hosts:
                h[key] = h[key] * tot / cur if cur > 0 else tot / len(hosts)
    ha = int(_num(b, "ha_failures", 0, 4, 1))
    add_vms, rm_vms = int(_num(b, "add_vms", 0, 20000)), int(_num(b, "remove_vms", 0, 20000))
    vcpu, mem_gb = _num(b, "vm_vcpu", 1, 512, 4), _num(b, "vm_mem_gb", 0.5, 4096, 16)
    cpu_util, mem_util = _num(b, "vm_cpu_util_pct", 1, 100, 25), _num(b, "vm_mem_util_pct", 1, 100, 80)
    add_h, rm_h = int(_num(b, "add_hosts", 0, 256)), int(_num(b, "remove_hosts", 0, 256))
    n = len(hosts)
    avg_core = sum(h["core_mhz"] for h in hosts) / n or 2500.0
    avg = {"cpu_mhz": sum(h["cpu_mhz"] for h in hosts) / n, "mem_mb": sum(h["mem_mb"] for h in hosts) / n, "core_mhz": avg_core}
    h_cores, h_ghz, h_mem = _num(b, "host_cores", 0, 1024), _num(b, "host_core_ghz", 0, 8), _num(b, "host_mem_gb", 0, 16384)
    h_sock, h_flash, vm_disk = int(_num(b, "host_sockets", 0, 64)), _num(b, "host_flash_tb", 0, 10000), _num(b, "vm_disk_gb", 0, 100000)
    h_model = " ".join(str(b.get("host_cpu_model") or "").split())[:120]
    perf = _num(b, "perf_factor", 0.3, 3, 1)           # 2.36.0 새 서버의 GHz 당 처리 성능(기존 = 1) — 세대가 다를 때 보정
    new_host = {"name": "(추가)", "core_mhz": (h_ghz * 1000) or avg_core, "cpu_used": 0.0, "mem_used": 0.0, "sockets": h_sock, "cpu_model": h_model,
                "cpu_mhz": (h_cores * ((h_ghz * 1000) or avg_core) if h_cores else avg["cpu_mhz"]) * perf, "mem_mb": h_mem * 1024 if h_mem else avg["mem_mb"]}
    if perf != 1:
        new_host["core_mhz"] = new_host["core_mhz"] * perf
    if not h_sock and not (h_cores or h_mem):          # 평균 사양으로 더할 때는 기존 호스트의 소켓 수를 따른다
        known = sorted(h.get("sockets") or 0 for h in hosts)
        new_host["sockets"] = known[len(known) // 2] if known and known[0] else 0
        h_sock = new_host["sockets"]
    rm_names = [str(x) for x in (b.get("remove_names") or [])][:256]      # 2.35.0 — 어느 호스트를 뺄지 지정(교체·장애 가정)
    unknown = [x for x in rm_names if x not in {h["name"] for h in hosts}]
    if unknown:
        raise ValueError("이 클러스터에 없는 호스트: " + ", ".join(unknown[:5]))
    rm_names = list(dict.fromkeys(rm_names))
    if rm_h + len(rm_names) >= n + add_h:
        raise ValueError("호스트를 모두 뺄 수는 없습니다")
    ha0 = ha
    if b.get("consume_ha"):                             # 장애 가정 — 죽은 호스트만큼 HA 여유를 이미 쓴 것으로 본다
        ha = max(0, ha - len(rm_names) - rm_h)
    cpu_used, mem_used = sum(h["cpu_used"] for h in hosts), sum(h["mem_used"] for h in hosts)
    vms_on = max(1, base["vms_on"])
    before = _state(base, hosts, cpu_used, mem_used, base["vcpu"], base["vms_on"], ha0)
    # 가정 적용 — VM 제거는 지금 켜진 VM 의 평균 수요만큼, 호스트 제거는 작은 호스트부터(보수적으로 큰 호스트가 남는 쪽이 아니라 용량이 덜 줄어드는 쪽을 가정하지 않도록 평균으로)
    rm_vms = min(rm_vms, base["vms_on"])
    one_cpu, one_mem = vcpu * avg_core * cpu_util / 100, mem_gb * 1024 * mem_util / 100
    cpu2 = cpu_used + add_vms * one_cpu - rm_vms * cpu_used / vms_on
    mem2 = mem_used + add_vms * one_mem - rm_vms * mem_used / vms_on
    vcpu2 = base["vcpu"] + add_vms * vcpu - rm_vms * base["vcpu"] / vms_on
    hosts2 = [h for h in hosts if h["name"] not in rm_names] + [dict(new_host) for _ in range(add_h)]
    for _ in range(rm_h):                                # 평균에 가장 가까운 기존 호스트를 뺀다(추가한 호스트는 남김)
        cand = [h for h in hosts2 if h["name"] != "(추가)"] or hosts2
        hosts2.remove(min(cand, key=lambda h: abs(h["mem_mb"] - avg["mem_mb"]) + abs(h["cpu_mhz"] - avg["cpu_mhz"]) / 1000))
    vms2 = base["vms_on"] + add_vms - rm_vms
    rs_out = None
    if reclaim and b.get("apply_rightsizing"):          # 2.36.0 — 적정화 권고를 적용했을 때(유휴 VM 끄기·과다 할당 축소·과소 할당 증설)
        need0 = _need(base, hosts2, cpu2, mem2, ha, new_host)
        cpu2 -= reclaim.get("cpu_mhz", 0.0)
        mem2 -= reclaim.get("mem_mb", 0.0)
        vcpu2 -= reclaim.get("vcpu", 0.0)
        vms2 -= reclaim.get("vms_off", 0)
        need1 = _need(base, hosts2, cpu2, mem2, ha, new_host)
        rs_out = {**{k: reclaim.get(k) for k in ("idle", "oversized", "undersized", "powered_off", "observed_days")},
                  "cpu_ghz": round(reclaim.get("cpu_mhz", 0) / 1000, 1), "mem_gb": round(reclaim.get("mem_mb", 0) / 1024, 1), "vcpu": round(reclaim.get("vcpu", 0)),
                  "disk_tb": round(reclaim.get("disk_gb", 0) / 1000, 2), "hosts_needed_without": need0, "hosts_needed_with": need1,
                  "deferred": (need0 - need1) if need0 is not None and need1 is not None else None}
    after = _state(base, hosts2, max(0.0, cpu2), max(0.0, mem2), max(0.0, vcpu2), vms2, ha)
    ct1, mt1, _, _ = before.pop("_")
    ct2, mt2, cu2, mu2 = after.pop("_")
    sl = slopes or {}
    for k, t1, t2 in (("cpu", ct1, ct2), ("mem", mt1, mt2)):
        before[k]["days_to_90"] = _days(before[k]["pct_total"], sl.get(k), 1.0)
        after[k]["days_to_90"] = _days(after[k]["pct_total"], sl.get(k), t1 / t2 if t2 else 1.0)
    # 같은 사양 VM 을 얼마나 더 넣을 수 있나(쓸 수 있는 용량의 80%·100%까지)
    def room(limit: float) -> int:
        c = (cu2 * limit / 100 - max(0.0, cpu2)) / one_cpu if one_cpu else 0
        m = (mu2 * limit / 100 - max(0.0, mem2)) / one_mem if one_mem else 0
        return max(0, int(math.floor(min(c, m))))
    # 80% 안에 들이려면 같은 사양(추가 호스트 사양 또는 평균 호스트) 몇 대가 더 필요한가
    need = _need(base, hosts2, cpu2, mem2, ha, new_host)
    limit = "mem" if (after["mem"]["pct_usable"] or 0) >= (after["cpu"]["pct_usable"] or 0) else "cpu"
    # 라이선스 코어(소켓당 최소 16코어) — 소켓 수를 아는 호스트만
    from .serverspec import licensed_cores
    def lic(hs):   # noqa: E306
        if any(not h.get("sockets") for h in hs):
            return None
        return sum(licensed_cores(h["sockets"], round(h["cpu_mhz"] / h["core_mhz"]) if h["core_mhz"] else 0) for h in hs)
    l1, l2 = lic(hosts), lic(hosts2)
    license_ = {"before": l1, "after": l2, "delta": (l2 - l1) if l1 is not None and l2 is not None else None,
                "per_new_host": licensed_cores(h_sock, round(new_host["cpu_mhz"] / new_host["core_mhz"])) if add_h and h_sock and new_host["core_mhz"] else None}
    # 스토리지 — 공유 데이터스토어 합계 기준(원시). vSAN 은 아래 vsan 블록에서 정책·예비·절감률을 반영한 '쓸 수 있는 용량'을 따로 계산
    storage = None
    disk_reclaim = (reclaim or {}).get("disk_gb", 0.0) if reclaim and b.get("apply_rightsizing") else 0.0
    if base.get("ds_total_gb"):
        tot, used = base["ds_total_gb"], base["ds_total_gb"] - base.get("ds_free_gb", 0)
        per_vm = (base.get("vm_disk_gb", 0) / vms_on) if base.get("vms_on") else 0
        used2 = max(0.0, used + add_vms * vm_disk - rm_vms * per_vm - disk_reclaim)
        add_raw = add_h * h_flash * 1000 if base.get("vsan") else 0.0
        storage = {"datastores": base.get("ds_count", 0), "vsan": bool(base.get("vsan")), "total_tb": round(tot / 1000, 1), "used_tb": round(used / 1000, 1),
                   "pct": round(used / tot * 100, 1), "after_used_tb": round(used2 / 1000, 1), "after_pct": round(used2 / tot * 100, 1),
                   "raw_added_tb": round(add_raw / 1000, 1) if add_raw else 0, "counted": bool(add_vms and vm_disk) or bool(rm_vms)}
    vsan = None
    if base.get("vsan") and base.get("vsan_raw_gb"):
        per_vm = (base.get("vm_disk_gb", 0) / vms_on) if base.get("vms_on") else 0
        raw_per_host = base["vsan_raw_gb"] / n
        raw2 = base["vsan_raw_gb"] + add_h * h_flash * 1000 - (rm_h + len(rm_names)) * raw_per_host
        m = base.get("vsan_meas") or {}
        pol = str(b.get("vsan_policy") or "")
        if not pol:                                         # 2.37.0 기본 — 실측 배수가 있으면 실측, 없으면 클러스터 기본 정책
            pol = "measured" if m.get("policy_mult") else "auto"
        if pol == "measured" and not m.get("policy_mult"):
            pol = "auto"
        dr_in = b.get("vsan_dr")
        dr_v = _num(b, "vsan_dr", 1, 10, 1) if dr_in not in (None, "") else max(1.0, float(m.get("dr") or 1.0))
        hr = b.get("vsan_host_reserve")
        hr_v = (hr is not False and hr != "false") if hr not in (None, "") else (m.get("host_reserve") if m.get("host_reserve") is not None else True)
        vsan = vsan_usable(base["vsan_raw_gb"], base.get("vsan_free_gb", 0), n, bool(base.get("vsan_esa")), pol,
                           _num(b, "vsan_reserve_pct", 0, 30, 10), bool(hr_v), dr_v,
                           hosts2=len(hosts2), raw2_gb=max(0.0, raw2), add_logical_gb=add_vms * vm_disk - rm_vms * per_vm - disk_reclaim,
                           measured_mult=m.get("policy_mult"))
        vsan["measured"] = {k: m.get(k) for k in ("policy_mult", "dr", "ops_reserve", "host_reserve", "ts")} if m else None
        vsan["sources"] = {"policy": "실측" if pol == "measured" else "입력", "dr": "입력" if dr_in not in (None, "") else ("실측" if m.get("dr") else "기본 1배"),
                           "host_reserve": "입력" if hr not in (None, "") else ("vSAN 설정" if m.get("host_reserve") is not None else "기본 켬")}
        if pol == "measured" and add_h and base.get("vsan_esa"):
            vsan.setdefault("after", {})["note2"] = "실측 배수는 지금 객체 구성 그대로 둡니다 — ESA 에서 호스트가 6대 이상이 되면 RAID-5 객체가 4+1 로 바뀌어 실제로는 조금 더 남을 수 있습니다."
        if add_h and not h_flash:
            vsan["after"]["note"] = "추가 서버의 vSAN 디스크(원시 TB)를 넣지 않아 원시 용량은 그대로 두고 계산했습니다."
    # 혼합 세대(EVC) — 다른 CPU 모델의 서버를 더할 때
    evc = None
    if add_h:
        from .cpugen import evc_review
        evc = evc_review([h.get("cpu_model", "") for h in hosts], h_model, base.get("evc", ""))
        old_ghz = sum(h["core_mhz"] for h in hosts) / n / 1000
        evc["core_ghz"] = {"existing": round(old_ghz, 2), "new": round((h_ghz or avg_core / 1000), 2), "perf_factor": perf}
    # 분기별 증설 계획(4개 분기) — 연 성장률을 주면 복리로, 없으면 용량 계획의 일별 증가율(%p/일)로
    quarters = _plan(base, hosts2, cpu2, mem2, ha, new_host, b, slopes or {}, sum(h["cpu_mhz"] for h in hosts), sum(h["mem_mb"] for h in hosts),
                     today, storage, vsan)
    # 섞어 쓸 때 확인할 점
    notes = []
    if add_h:
        models = {h["cpu_model"] for h in hosts if h.get("cpu_model")}
        if h_model and models and h_model not in models:
            notes.append(f"CPU 모델이 기존 호스트와 다릅니다({h_model} ↔ {sorted(models)[0]}) — 세대가 다르면 vMotion 을 위해 EVC 모드가 필요할 수 있습니다.")
        if perf != 1:
            notes.append(f"새 서버의 GHz 당 성능을 기존의 {perf:g}배로 보정했습니다 — CPU 용량(MHz)에 곱해 계산합니다.")
        if new_host["mem_mb"] > 1.5 * avg["mem_mb"] or new_host["cpu_mhz"] > 1.5 * avg["cpu_mhz"]:
            notes.append("추가 호스트가 기존 평균보다 1.5배 넘게 큽니다 — HA 여유는 가장 큰 호스트 기준이라, 늘어난 용량의 상당 부분이 여유분으로 잡힙니다.")
        if h_sock and new_host["core_mhz"] and round(new_host["cpu_mhz"] / new_host["core_mhz"]) / h_sock < 16:
            notes.append("소켓당 코어가 16 미만입니다 — 라이선스는 소켓당 16코어로 셉니다.")
        if base.get("vsan") and not h_flash:
            notes.append("vSAN 클러스터입니다 — 추가 호스트의 디스크 사양을 모르면 스토리지 증가분은 계산하지 않습니다.")
    return {"before": before | {"verdict": _verdict(before)}, "after": after | {"verdict": _verdict(after)},
            "inputs": {"ha_failures": ha0, "add_vms": add_vms, "remove_vms": rm_vms, "vm_vcpu": vcpu, "vm_mem_gb": mem_gb, "vm_cpu_util_pct": cpu_util, "vm_mem_util_pct": mem_util,
                       "add_hosts": add_h, "remove_hosts": rm_h, "remove_names": rm_names, "consume_ha": bool(b.get("consume_ha")), "ha_after": ha},
            "basis": ({"kind": "p95", **{k: demand.get(k) for k in ("days", "samples", "span_h")},
                       "now_cpu_ghz": round(sum(h["cpu_used"] for h in base["hosts"]) / 1000, 1), "now_mem_gb": round(sum(h["mem_used"] for h in base["hosts"]) / 1024, 1),
                       "max_cpu_ghz": round(demand.get("cpu_max_mhz", 0) / 1000, 1), "max_mem_gb": round(demand.get("mem_max_mb", 0) / 1024, 1)}
                      if demand and demand.get("cpu_mhz") is not None else {"kind": "now", "why": (demand or {}).get("why", "")}),
            "host_spec": {"cores": round(new_host["cpu_mhz"] / new_host["core_mhz"]) if new_host["core_mhz"] else 0, "core_ghz": round(new_host["core_mhz"] / 1000, 2),
                          "mem_gb": round(new_host["mem_mb"] / 1024), "custom": bool(h_cores or h_mem), "sockets": h_sock, "cpu_model": h_model},
            "per_vm": {"cpu_ghz": round(one_cpu / 1000, 2), "mem_gb": round(one_mem / 1024, 1)},
            "room": {"to_80": room(WARN), "to_100": room(FULL)}, "hosts_needed": need, "limit": limit, "license": license_, "storage": storage, "notes": notes,
            "slopes": {"cpu": sl.get("cpu"), "mem": sl.get("mem")}, "vsan": vsan, "evc": evc, "rightsizing": rs_out, "quarters": quarters}


def _plan(base, hosts2, cpu2, mem2, ha, new_host, b, sl, ct1, mt1, today, storage, vsan) -> dict[str, Any]:
    import datetime as dt
    from .serverspec import licensed_cores
    g = b.get("growth_pct_year")
    g = None if g in (None, "") else _num(b, "growth_pct_year", -50, 500)
    today = today or dt.date.today()
    if g is None and not (sl.get("cpu") or sl.get("mem")):
        return {"basis": "none", "why": "연 성장률을 넣거나 용량 계획에 7일 이상 추세가 쌓이면 분기별 계획을 냅니다", "rows": []}
    rows, prev = [], 0
    for label, end in _quarters(today):
        d = (end - today).days
        if g is not None:
            f = (1 + g / 100) ** (d / 365)
            c, m = cpu2 * f, mem2 * f
        else:
            f = None
            c = cpu2 + (sl.get("cpu") or 0) / 100 * ct1 * d
            m = mem2 + (sl.get("mem") or 0) / 100 * mt1 * d
        k = _need(base, hosts2, c, m, ha, new_host)
        hs = list(hosts2) + [dict(new_host) for _ in range(k or 0)]
        lic = None if any(not h.get("sockets") for h in hs) else sum(
            licensed_cores(h["sockets"], round(h["cpu_mhz"] / h["core_mhz"]) if h["core_mhz"] else 0) for h in hs)
        st = None
        gday = sl.get("disk_gb_day")                         # 2.37.0 추세 기준이면 공유 데이터스토어의 실제 증가량(GB/일, 원시)
        if vsan and vsan.get("after") and vsan["after"].get("usable_tb"):
            a = vsan["after"]
            if f is not None:
                st = round(a["used_tb"] * f / a["usable_tb"] * 100, 1)
            elif gday is not None:
                st = round((a["used_tb"] + gday * d / 1000 / (a["mult"] or 1) * (vsan.get("dr") or 1)) / a["usable_tb"] * 100, 1)
        elif storage:
            if f is not None:
                st = round(storage["after_pct"] * f, 1)
            elif gday is not None and storage.get("total_tb"):
                st = round(storage["after_pct"] + gday * d / 1000 / storage["total_tb"] * 100, 1)
        rows.append({"label": label, "end": end.isoformat(), "days": d, "cpu_ghz": round(c / 1000, 1), "mem_gb": round(m / 1024),
                     "hosts_total": len(hosts2) + (k or 0) if k is not None else None, "hosts_add": k, "add_this_q": (k - prev) if k is not None else None,
                     "license_cores": lic, "storage_pct": st})
        prev = k if k is not None else prev
    return {"basis": "growth" if g is not None else "trend", "growth_pct_year": g,
            "slopes": {"cpu": sl.get("cpu"), "mem": sl.get("mem"), "disk_gb_day": sl.get("disk_gb_day")} if g is None else None, "rows": rows,
            "host": {"cores": round(new_host["cpu_mhz"] / new_host["core_mhz"]) if new_host["core_mhz"] else 0, "mem_gb": round(new_host["mem_mb"] / 1024)}}


# ------------------------------------------------------------------ 시나리오 저장(2.35.0)
SC_SCHEMA = """CREATE TABLE IF NOT EXISTS whatif_scenarios(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, vcenter TEXT, cluster TEXT, inputs TEXT NOT NULL, created REAL, by TEXT)"""
SC_KEYS = ("ha_failures", "add_vms", "remove_vms", "vm_vcpu", "vm_mem_gb", "vm_disk_gb", "vm_cpu_util_pct", "vm_mem_util_pct", "add_hosts", "remove_hosts", "remove_names", "consume_ha",
           "host_cores", "host_core_ghz", "host_mem_gb", "host_sockets", "host_flash_tb", "host_cpu_model", "basis", "basis_days", "spec_name",
           "vsan_policy", "vsan_reserve_pct", "vsan_host_reserve", "vsan_dr", "perf_factor", "growth_pct_year", "apply_rightsizing")


class ScenarioStore:
    def __init__(self, store):
        self.store = store
        self._ready = False

    async def ensure(self) -> None:
        if not self._ready:
            await self.store.x(SC_SCHEMA)
            self._ready = True

    async def list(self) -> list[dict]:
        import json
        await self.ensure()
        out = []
        for r in await self.store.q("SELECT id,name,vcenter,cluster,inputs,created,by FROM whatif_scenarios ORDER BY id DESC LIMIT 100"):
            try:
                out.append({**{k: r[k] for k in ("id", "name", "vcenter", "cluster", "created", "by")}, "inputs": json.loads(r["inputs"])})
            except ValueError:
                continue
        return out

    async def add(self, body: dict, by: str) -> dict:
        import json
        import time
        await self.ensure()
        name = " ".join(str(body.get("name") or "").split())[:80]
        vc, cl = str(body.get("vcenter") or "")[:120], str(body.get("cluster") or "")[:120]
        if not name or not vc or not cl:
            raise ValueError("이름과 클러스터가 필요합니다")
        inputs = {k: body[k] for k in SC_KEYS if body.get(k) not in (None, "")}
        if len(json.dumps(inputs)) > 8000:
            raise ValueError("가정이 너무 큽니다")
        if ((await self.store.q1("SELECT COUNT(*) AS n FROM whatif_scenarios")) or {}).get("n", 0) >= 100:
            raise ValueError("저장한 가정은 100개까지 — 안 쓰는 것을 지우세요")
        await self.store.x("INSERT INTO whatif_scenarios(name,vcenter,cluster,inputs,created,by) VALUES(?,?,?,?,?,?)", (name, vc, cl, json.dumps(inputs, ensure_ascii=False), time.time(), by))
        r = await self.store.q1("SELECT MAX(id) AS m FROM whatif_scenarios")
        return {"id": r["m"], "name": name, "vcenter": vc, "cluster": cl, "inputs": inputs}

    async def remove(self, sid: int) -> bool:
        await self.ensure()
        if not await self.store.q1("SELECT id FROM whatif_scenarios WHERE id=?", (sid,)):
            return False
        await self.store.x("DELETE FROM whatif_scenarios WHERE id=?", (sid,))
        return True
