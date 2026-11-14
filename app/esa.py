"""외장 스토리지 → vSAN ESA 전환 산정(2.43.0) — 성능·용량 › 용량·적정화 › 'vSAN ESA 전환' 탭

지금 외장 스토리지(VMFS·NFS·vVol — vSAN·로컬 제외)에 있는 데이터를 vSAN ESA 로 옮기면 무엇이 얼마나 필요한지:
  · 옮길 양      데이터스토어 사용량(기본) 또는 할당량(씬 디스크가 다 차는 최악) × (1 + 연 증가율)^기간
                 증가율은 용량 추세(GB/일)가 있으면 그 값, 없으면 입력값
  · 사용 가능량  whatif.vsan_usable — 원시 × (1 − 운영 예비율) − 호스트 재구축 예비(1대 몫) ÷ 정책 배수 × 데이터 절감률
                 ESA RAID-5 적응형: 3~5대 2+1(1.5배), 6대 이상 4+1(1.25배) · RAID-6 4+2(1.5배, 6대 이상) · RAID-1(2배)
  · 방법 A      기존 클러스터 호스트에 NVMe 를 넣어 ESA 로 — 호스트당 필요한 원시 TB·드라이브 수
  · 방법 B      새 ESA 클러스터 — 필요한 호스트 수(정책 최소 대수 포함), 호스트당 원시 TB 입력
  · 라이선스     VCF 는 라이선스 코어 1개당 vSAN 1 TiB(원시) 포함, 코어는 CPU 당 최소 16개 — 부족분 = vSAN 추가 TiB
                 (VCF Specific Program Documentation, KB 313548 — vSAN TiB 는 호스트에 할당된 원시 용량 기준)
  · ReadyNode   호스트당 원시 TB 로 vSAN ESA ReadyNode 프로필(AF-0~AF-8·HighDensity) 최소 기준(코어·메모리·네트워크)을 맞춰 보고,
                 지금 호스트의 코어·메모리·NIC 속도와 비교(Broadcom vSAN ESA ReadyNode Hardware Guidance)
읽기 전용 계산 — 수집된 토폴로지·용량 추세만 사용.
"""
from __future__ import annotations

import math
from typing import Any

from . import whatif as W

# vSAN ESA ReadyNode Hardware Guidance(최소값) — 노드 원시 용량 TB, 코어, 메모리 GB, 네트워크 GbE
PROFILES = [("vSAN-ESA-AF-0", 1.6, 16, 128, 10), ("vSAN-ESA-AF-2", 10, 24, 256, 25), ("vSAN-ESA-AF-4", 20, 32, 512, 25),
            ("vSAN-ESA-AF-6", 40, 48, 768, 50), ("vSAN-ESA-AF-8", 60, 56, 1024, 100), ("vSAN-ESA-AF-HighDensity", 100, 48, 768, 50)]
MAX_DEV = 24                      # ESA 호스트당 최대 저장 장치 수(KB 326717)
TB_PER_TIB = 1.099511627776


def sources(engine, cap_items: list[dict] | None = None) -> dict[str, Any]:
    """외장 데이터스토어 목록 — 어레이(physmap), 사용량·할당량, 켜진 VM, 추세(GB/일)"""
    from . import physmap as PH
    try:
        arr_of = {(d["vcenter"], d["name"]): a["name"] for a in PH.build(engine)["storage"].values() for d in a["datastores"]}
    except Exception:  # noqa: BLE001
        arr_of = {}
    growth = {(x.get("vcenter"), x.get("name")): x.get("growth_gb_day") for x in cap_items or [] if x.get("kind") == "datastore"}
    out, hosts = [], []
    for c in getattr(engine, "connectors", []):
        if getattr(c, "type", "") != "vcenter" or not getattr(c, "topology", None):
            continue
        T = c.topology
        H = T.get("hosts") or {}
        for hn, h in H.items():
            cores = int(h.get("cores") or 0) or (int(round(float(h.get("cpu_mhz") or 0) / float(h.get("core_mhz") or 1))) if h.get("core_mhz") else 0)
            hosts.append({"vcenter": c.name, "name": hn, "cluster": h.get("cluster", ""), "cores": cores, "sockets": int(h.get("sockets") or 0),
                          "mem_gb": round((h.get("mem_mb") or 0) / 1024), "nic_gbe": max([int((n.get("speed") or 0) / 1000) for n in (h.get("pnics") or [])] or [0]),
                          "vsan": bool((T.get("clusters") or {}).get(h.get("cluster", ""), {}).get("vsan")),
                          "esa": bool((T.get("clusters") or {}).get(h.get("cluster", ""), {}).get("vsan_esa"))})
        V = T.get("vms") or {}
        for dn, d in (T.get("datastores") or {}).items():
            t = str(d.get("type", "")).lower()
            cap = float(d.get("capacity_gb") or 0)
            if not cap or t == "vsan" or d.get("local") is True:
                continue
            used = cap - float(d.get("free_gb") or 0)
            prov = float(d.get("prov_gb") or 0) or used + float(d.get("uncommitted_gb") or 0)
            vms = [v for v in V.values() if dn in (v.get("datastores") or [])]
            out.append({"vcenter": c.name, "name": dn, "type": d.get("type", ""), "array": arr_of.get((c.name, dn), ""), "capacity_gb": round(cap), "used_gb": round(used),
                        "prov_gb": round(max(prov, used)), "vms": len(vms), "vms_on": sum(1 for v in vms if "poweredOn" in str(v.get("power"))),
                        "clusters": sorted({v.get("cluster", "") for v in vms} - {""}), "growth_gb_day": growth.get((c.name, dn))})
    out.sort(key=lambda x: (-x["used_gb"], x["name"]))
    clusters = {}
    for h in hosts:
        k = (h["vcenter"], h["cluster"])
        x = clusters.setdefault(k, {"vcenter": h["vcenter"], "name": h["cluster"], "hosts": 0, "cores": [], "mem_gb": [], "nic_gbe": [], "lic_cores": 0, "vsan": h["vsan"], "esa": h["esa"]})
        x["hosts"] += 1
        x["cores"].append(h["cores"])
        x["mem_gb"].append(h["mem_gb"])
        x["nic_gbe"].append(h["nic_gbe"])
        x["lic_cores"] += lic_cores(h["cores"], h["sockets"])
    cl = [{**v, "cores_min": min(v["cores"]) if v["cores"] else 0, "mem_min": min(v["mem_gb"]) if v["mem_gb"] else 0,
           "nic_min": min(v["nic_gbe"]) if v["nic_gbe"] else 0} for v in clusters.values() if v["name"]]
    for x in cl:
        for k in ("cores", "mem_gb", "nic_gbe"):
            x.pop(k)
    return {"datastores": out, "clusters": sorted(cl, key=lambda x: (x["vcenter"], x["name"]))}


def lic_cores(cores: int, sockets: int) -> int:
    """VCF 라이선스 코어 — CPU 당 최소 16코어"""
    s = max(1, sockets or 1)
    per = math.ceil((cores or 0) / s) if cores else 16
    return max(16, per) * s


def profile_for(raw_tb: float, cores: int = 0, mem_gb: int = 0, nic: int = 0) -> dict[str, Any]:
    """호스트당 원시 TB 에 맞는 ReadyNode 프로필 + 지금 호스트가 그 최소 기준(코어·메모리·NIC)을 맞추는지"""
    # 프로필의 '노드 용량'은 최소값 — 원시 TB 가 그 이상인 가장 큰 프로필(100 TB 이상은 HighDensity)
    fit = [p for p in PROFILES[:5] if raw_tb >= p[1]]
    pick = fit[-1] if fit else PROFILES[0]
    if raw_tb >= PROFILES[5][1]:
        pick = PROFILES[5]
    name, tb, c, m, n = pick
    gaps = []
    if cores and cores < c:
        gaps.append(f"코어 {cores} < {c}")
    if mem_gb and mem_gb < m:
        gaps.append(f"메모리 {mem_gb} GB < {m} GB")
    if nic and nic < n:
        gaps.append(f"NIC {nic} GbE < {n} GbE")
    return {"profile": name, "min_tb": tb, "min_cores": c, "min_mem_gb": m, "min_gbe": n, "gaps": gaps}


def size(src: dict, body: dict) -> dict[str, Any]:
    sel = set(body.get("datastores") or [])
    if sel:
        ds = [d for d in src["datastores"] if f"{d['vcenter']}/{d['name']}" in sel]
    else:                                                            # 기본: VM 이 있는 데이터스토어(백업 대상 NFS 등은 빼고)
        ds = [d for d in src["datastores"] if d["vms"]] or list(src["datastores"])
    basis = body.get("basis") if body.get("basis") in ("used", "prov") else "used"
    years = max(0.0, min(10.0, float(body.get("years") or 3)))
    dr = max(1.0, min(4.0, float(body.get("dr") or 1.0)))
    reserve = max(0.0, min(30.0, float(body.get("reserve_pct") if body.get("reserve_pct") not in (None, "") else 10)))
    host_res = str(body.get("host_reserve", "true")).lower() not in ("false", "0", "no")
    policy = body.get("policy") if body.get("policy") in ("auto", "r5", "r6", "r1", "r1f2") else "auto"
    drive_tb = max(0.8, min(61.44, float(body.get("drive_tb") or 7.68)))
    now_gb = sum(d["used_gb" if basis == "used" else "prov_gb"] for d in ds)
    gday = [d["growth_gb_day"] for d in ds if d.get("growth_gb_day") is not None]
    trend_pct = (sum(gday) * 365 / now_gb * 100) if gday and now_gb else None
    g = body.get("growth_pct_year")
    trend_ok = trend_pct is not None and trend_pct > 0
    g = float(g) if g not in (None, "") else (round(trend_pct, 1) if trend_ok else 20.0)
    need_gb = now_gb * (1 + g / 100) ** years
    res: dict[str, Any] = {"inputs": {"basis": basis, "years": years, "growth_pct_year": g, "growth_source": "입력" if body.get("growth_pct_year") not in (None, "") else
                                      ("추세" if trend_ok else "기본 20%(추세가 없거나 0 이하)"), "dr": dr, "reserve_pct": reserve, "host_reserve": host_res, "policy": policy,
                                      "drive_tb": drive_tb},
                           "selected": [f"{d['vcenter']}/{d['name']}" for d in ds], "now_tb": round(now_gb / 1000, 1), "need_tb": round(need_gb / 1000, 1), "datastores": len(ds), "vms": sum(d["vms"] for d in ds),
                           "arrays": sorted({d["array"] or "(어레이 모름)" for d in ds})}
    if not ds:
        res["error"] = "옮길 외장 데이터스토어가 없습니다"
        return res
    # 방법 B — 새 ESA 클러스터: 호스트당 원시 TB(입력 또는 드라이브 수 × 용량) 로 필요한 대수
    per_host_tb = float(body.get("host_raw_tb") or 0) or drive_tb * int(body.get("drives_per_host") or 8)
    rows = []
    found = None
    for n in range(2, 65):
        u = W.vsan_usable(n * per_host_tb * 1000, n * per_host_tb * 1000, n, True, policy, reserve, host_res, dr)
        ok = n >= u["min_hosts"] and u["usable_tb"] * 1000 >= need_gb
        rows.append({"hosts": n, "raw_tb": round(n * per_host_tb, 1), "usable_tb": u["usable_tb"], "scheme": u["scheme"], "ok": ok, "min_hosts": u["min_hosts"]})
        if ok and found is None:
            found = n
        if found is not None and n >= found + 2:
            break
    cores_new = int(body.get("cores_per_host") or 64)
    sockets_new = int(body.get("sockets_per_host") or 2)
    nb = found or 64
    lic_tib = nb * lic_cores(cores_new, sockets_new)
    raw_tib_b = nb * per_host_tb / TB_PER_TIB
    res["new_cluster"] = {"per_host_tb": round(per_host_tb, 2), "drives_per_host": math.ceil(per_host_tb / drive_tb - 1e-9), "hosts": found, "table": rows[-6:] if found else rows[:8],
                          "raw_tb": round(nb * per_host_tb, 1), "raw_tib": round(raw_tib_b, 1), "entitled_tib": lic_tib, "addon_tib": max(0, math.ceil(raw_tib_b - lic_tib)),
                          "cores_per_host": cores_new, "sockets_per_host": sockets_new, "profile": profile_for(per_host_tb, cores_new, int(body.get("mem_gb_per_host") or 0), 0),
                          "too_many_drives": math.ceil(per_host_tb / drive_tb - 1e-9) > MAX_DEV}
    # 방법 A — 기존 클러스터를 ESA 로: 호스트 N 대가 나눠 담을 원시 TB
    out_a = []
    for cl in src["clusters"]:
        n = cl["hosts"]
        sc = W.vsan_scheme(policy, n, True)
        denom = 1 - reserve / 100 - (1 / n if host_res and n else 0)
        if n < sc["min_hosts"] or denom <= 0:
            out_a.append({**cl, "possible": False, "why": f"호스트 {n}대 — {sc['scheme']} 최소 {sc['min_hosts']}대"})
            continue
        raw_gb = need_gb * sc["mult"] / dr / denom
        ph = raw_gb / 1000 / n
        drives = math.ceil(ph / drive_tb - 1e-9)
        prof = profile_for(drives * drive_tb, cl["cores_min"], cl["mem_min"], cl["nic_min"])
        osa = cl["vsan"] and not cl.get("esa")
        why = (f"호스트당 드라이브 {drives}개 > ESA 최대 {MAX_DEV}개 — 호스트를 늘리거나 더 큰 드라이브" if drives > MAX_DEV else
               "지금 vSAN OSA — 같은 클러스터를 ESA 로 바로 바꿀 수 없음(ESA 클러스터를 새로 만들어 옮김: 방법 B)" if osa else
               "지금 vSAN ESA — 위 값은 기존 vSAN 데이터 외에 '추가로' 필요한 원시 용량" if cl["vsan"] else "")
        out_a.append({**cl, "possible": drives <= MAX_DEV and not osa, "scheme": sc["scheme"], "raw_tb": round(raw_gb / 1000, 1), "installed_tb": round(drives * drive_tb * n, 1),
                      "per_host_tb": round(ph, 2), "drives_per_host": drives,
                      "raw_tib": round(drives * drive_tb * n / TB_PER_TIB, 1), "entitled_tib": cl["lic_cores"],
                      "addon_tib": max(0, math.ceil(drives * drive_tb * n / TB_PER_TIB - cl["lic_cores"])), "profile": prof,
                      "why": why, "already_vsan": cl["vsan"], "osa": osa})
    res["existing"] = sorted(out_a, key=lambda x: (not x.get("possible"), x.get("addon_tib", 9e9)))
    res["notes"] = ["vSAN TiB 라이선스는 호스트에 꽂힌 원시 용량 기준(KB 313548). VCF 는 라이선스 코어당 1 TiB 포함, 코어는 CPU 당 최소 16개.",
                    "ESA 는 NVMe TLC 인증 장치·ReadyNode 구성이 전제입니다. 성능(IOPS·지연)은 이 계산에 들어 있지 않으니 지금 LUN 지연·IOPS 를 함께 보세요(호스트·VM 성능).",
                    "데이터 절감률 1.0 = 압축 효과를 가정하지 않음(보수적). 실측 압축률이 있으면 입력하세요."]
    return res
