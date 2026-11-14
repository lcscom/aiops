"""호스트·VM 성능 자동 진단(2.24.0) — 실시간 1시간 + 최근 24시간 기준선 + 토폴로지(같은 호스트의 VM)로 규칙 판정.

판정 기준(일반 운영 기준선 — 화면에 근거 수치와 함께 표시하고, 단정 대신 '확인할 곳'을 안내)
  CPU ready  vCPU 평균 ≥5% 경고 · ≥10% 위험 (vCPU 가 물리 코어를 기다리는 시간)
  co-stop    ≥3% — 여러 vCPU 를 동시에 못 잡음 → vCPU 과다 할당 의심
  CPU 사용률  p95 ≥90% 포화 · (VM, 24시간 평균 <10% 이면서 vCPU ≥4) 과다 할당 후보
  메모리      balloon·swapped·compressed >0 또는 VM mem.latency ≥1% → 호스트 메모리 압박 / 호스트 swap in·out >0
  디스크 지연 평균 ≥20 ms 경고 · ≥50 ms 위험. 호스트는 DAVG(장치) ≥20 → 스토리지 쪽, KAVG(커널) ≥2 → 큐 깊이·HBA 대기열
  네트워크    드롭 >0 (vNIC·vmnic 별)
  평소 대비   지금(최근 1시간 평균)이 24시간 p95 의 1.5배 이상이고 절대값도 의미 있을 때
"""
from __future__ import annotations

from typing import Any

SEV_ORDER = {"critical": 3, "warning": 2, "info": 1, "ok": 0}


def _xs(s: dict, k: str) -> list[float]:
    return [x for x in (s.get(k) or []) if x is not None]


def _avg(xs: list[float]) -> float | None:
    return sum(xs) / len(xs) if xs else None


def _p95(xs: list[float]) -> float | None:
    if not xs:
        return None
    ys = sorted(xs)
    return ys[min(len(ys) - 1, int(len(ys) * 0.95))]


def _f(x: float | None, unit: str = "", nd: int = 1) -> str:
    return "-" if x is None else f"{x:,.{nd}f}{unit}"


def _mbps(x: float | None) -> str:
    return "-" if x is None else f"{x / 1e6:,.1f} Mbps"


def diagnose(kind: str, rt: dict, day: dict | None, info: dict, neighbors: list[dict] | None = None) -> dict[str, Any]:
    """rt/day = PerfView.detail 결과(series·instances). 반환 {"level", "findings": [{sev, area, title, evidence, advice}], "baseline": {...}}"""
    S = rt.get("series") or {}
    D = (day or {}).get("series") or {}
    out: list[dict] = []

    def add(sev: str, area: str, title: str, evidence: str, advice: str = "") -> None:
        out.append({"sev": sev, "area": area, "title": title, "evidence": evidence, "advice": advice})

    vm = kind == "vm"
    # ---------------- CPU
    rd = _xs(S, "cpu.ready_pct")
    if vm and rd:
        a, p = _avg(rd), _p95(rd)
        host_cpu = info.get("host_cpu_pct")
        if a >= 5:
            add("critical" if a >= 10 else "warning", "cpu", "CPU 경합(ready)",
                f"CPU ready vCPU 평균 {_f(a, '%')} · p95 {_f(p, '%')}" + (f" · 호스트 CPU {_f(host_cpu, '%', 0)}" if host_cpu is not None else ""),
                "호스트 CPU 가 바쁘면 DRS 균형·이웃 VM 확인, 호스트가 한가한데 높으면 vCPU 수·CPU 제한(limit)·리소스 풀 공유값 확인")
        cs = _avg(_xs(S, "cpu.costop_pct"))
        if cs is not None and cs >= 3:
            add("warning", "cpu", "vCPU 과다 할당 의심(co-stop)", f"co-stop 평균 {_f(cs, '%')} · vCPU {info.get('vcpu', '?')}개",
                "vCPU 를 실제 사용량에 맞게 줄이면 ready·co-stop 이 함께 줄어드는 경우가 많음")
    cu = _xs(S, "cpu.usage_pct")
    if cu:
        p = _p95(cu)
        if p >= 90:
            add("warning", "cpu", "CPU 포화", f"CPU 사용률 p95 {_f(p, '%')} · 평균 {_f(_avg(cu), '%')}",
                ("게스트 안 상위 프로세스 확인 후 vCPU 추가 검토" if vm else "DRS 이동·VM 재배치, 클러스터 용량 확인"))
    du = _xs(D, "cpu.usage_pct")
    if vm and du and int(info.get("vcpu") or 1) >= 4 and _avg(du) < 10 and (_p95(du) or 0) < 30:
        add("info", "cpu", "vCPU 과다 할당 후보", f"24시간 CPU 평균 {_f(_avg(du), '%')} · p95 {_f(_p95(du), '%')} · vCPU {info.get('vcpu')}개",
            "업무 주기(월말 배치 등)를 확인한 뒤 vCPU 축소 검토 — 용량·적정화 화면 참고")
    # ---------------- 메모리
    mem_mb = float(info.get("mem_mb") or 0)
    floor_mb = max(64.0, mem_mb * 0.01)                    # 64 MB 또는 메모리의 1% 미만은 무시(측정 잡음·잔여 페이지)
    for k, lab in (("mem.balloon_mb", "balloon"), ("mem.swapped_mb", "swap"), ("mem.compressed_mb", "압축")):
        xs = _xs(S, k)
        if xs and max(xs) >= floor_mb:
            add("warning", "mem", f"메모리 회수 발생({lab})", f"{lab} 최대 {_f(max(xs), ' MB', 0)} · 현재 {_f(xs[-1], ' MB', 0)}",
                "호스트 메모리 과할당·메모리 제한(limit) 확인 — 같은 호스트의 다른 VM 도 함께 확인" if vm else "")
    ml = _xs(S, "mem.latency_pct")
    if vm and ml and _avg(ml) >= 1:
        add("warning", "mem", "메모리 접근 지연", f"mem.latency 평균 {_f(_avg(ml), '%')}", "balloon·swap 이 원인인지 확인")
    if not vm:
        si, so = _xs(S, "mem.swapin_Bps"), _xs(S, "mem.swapout_Bps")
        busy = sum(1 for a, b in zip(si or [0.0] * len(so), so or [0.0] * len(si)) if (a or 0) > 0 or (b or 0) > 0)
        if busy:                                            # 예전에 스왑된 페이지를 다시 읽는 것만으로도 0 이 아닐 수 있음 → 지속될 때만 위험
            add("critical" if busy >= 3 else "info", "mem", "호스트 스왑 발생" if busy >= 3 else "호스트 스왑(일시)", f"swap in 최대 {_f(max(si) / 1024 if si else 0, ' KB/s', 0)} · out 최대 {_f(max(so) / 1024 if so else 0, ' KB/s', 0)}",
                "메모리 과할당 해소(VM 이동·예약 조정) — 스왑은 VM 성능을 크게 떨어뜨림")
    mu = _xs(S, "mem.usage_pct")
    if mu and _p95(mu) >= 95:
        add("warning", "mem", "메모리 사용률 높음", f"p95 {_f(_p95(mu), '%')}", "VM: 게스트 메모리 확인 / 호스트: VM 재배치·용량 확인")
    # ---------------- 디스크
    lat = [max(a, b) for a, b in zip(S.get("disk.read_lat_ms") or [], S.get("disk.write_lat_ms") or []) if a is not None and b is not None] or _xs(S, "disk.max_lat_ms")
    if lat:
        a = _avg(lat)
        if a >= 20:
            worst = max(((r.get("id"), max(r.get("read_lat_ms_avg") or 0, r.get("write_lat_ms_avg") or 0)) for r in (rt.get("instances") or {}).get("disk") or []),
                        key=lambda x: x[1], default=(None, 0))
            ev = f"지연 평균 {_f(a, ' ms')} · p95 {_f(_p95(lat), ' ms')}" + (f" · 가장 느린 {worst[0]} {_f(worst[1], ' ms')}" if worst[0] else "")
            adv = "같은 데이터스토어의 다른 VM·호스트 화면의 DAVG/KAVG 로 원인 위치 확인"
            if not vm:
                dv, kv = _avg(_xs(S, "disk.device_lat_ms")), _avg(_xs(S, "disk.kernel_lat_ms"))
                ev += f" · DAVG {_f(dv, ' ms')} · KAVG {_f(kv, ' ms')}"
                adv = ("장치 지연(DAVG)이 큼 → 스토리지 어레이·경로(HBA·스위치) 쪽" if (dv or 0) >= 20 else
                       "커널 대기(KAVG)가 큼 → 큐 깊이(HBA·LUN)·과도한 IO 몰림" if (kv or 0) >= 2 else adv)
            add("critical" if a >= 50 else "warning", "disk", "디스크 지연", ev, adv)
    if not vm:
        kv = _xs(S, "disk.kernel_lat_ms")
        if kv and _avg(kv) >= 2 and not any(f["area"] == "disk" for f in out):
            add("warning", "disk", "커널 IO 대기(KAVG)", f"KAVG 평균 {_f(_avg(kv), ' ms')}", "HBA·LUN 큐 깊이, 특정 VM 의 IO 몰림 확인")
    # ---------------- 네트워크
    drops = [(r.get("id"), r.get("label") or "", (r.get("drop_rx_avg") or 0) + (r.get("drop_tx_avg") or 0), r.get("drop_rx_max") or 0, r.get("drop_tx_max") or 0)
             for r in (rt.get("instances") or {}).get("net") or []]
    n_iv = max(1, len(rt.get("ts") or []))
    bad = [d for d in drops if d[2] * n_iv >= 10]           # 1시간 합계 10개 이상(간헐적 1~2개는 무시)
    if bad:
        add("warning", "net", "네트워크 패킷 드롭", " · ".join(f"{d[0]} 합계 약 {d[2] * n_iv:,.0f}개(간격당 최대 수신 {d[3]:.0f} / 송신 {d[4]:.0f})" for d in bad[:4]),
            "VM: 게스트 링 버퍼·CPU ready 함께 확인 / 호스트: 업링크 포화·드라이버 — 네트워크 트래픽 화면 vNIC 상세" if vm else
            "업링크(vmnic) 포화·링크 오류·드라이버·펌웨어 확인(esxcli network nic stats get -n vmnicX)")
    # ---------------- 평소 대비(24시간)
    base: dict[str, Any] = {}
    for k, lab, unit, floor in (("cpu.usage_pct", "CPU 사용률", "%", 20), ("disk.max_lat_ms", "디스크 지연", " ms", 5),
                                ("net.usage_bps", "네트워크", "bps", 5e6), ("disk.usage_Bps", "디스크 처리량", "B/s", 5e6),
                                ("mem.usage_pct", "메모리 사용률", "%", 30)):
        now, hist = _avg(_xs(S, k)), _xs(D, k)
        if now is None or len(hist) < 12:
            continue
        p95, avg = _p95(hist), _avg(hist)
        base[k] = {"now": now, "avg24": avg, "p95_24": p95, "ratio": (now / avg) if avg else None}
        if p95 and now >= p95 * 1.5 and now >= floor:
            shown = _mbps(now) if unit == "bps" else (f"{now / 1e6:,.1f} MB/s" if unit == "B/s" else _f(now, unit))
            ref = _mbps(p95) if unit == "bps" else (f"{p95 / 1e6:,.1f} MB/s" if unit == "B/s" else _f(p95, unit))
            add("warning", "baseline", f"평소보다 높은 {lab}", f"최근 1시간 평균 {shown} — 24시간 p95 {ref} 의 {now / p95:.1f}배",
                "이 시간대에 시작된 작업(백업·배치·배포)·이웃 VM 변화 확인")
    # ---------------- 이웃(같은 호스트)
    me = info.get("_self", "")
    nb = [v for v in (neighbors or []) if not (vm and v.get("name") == me)]          # VM 은 자기 자신 제외
    if nb:
        cap = float(info.get("host_cpu_used_mhz") or info.get("cpu_used_mhz") or 0)
        tot = cap or sum(v.get("cpu_mhz") or 0 for v in (neighbors or [])) or 0      # 분모 = 호스트 전체 사용량
        top = [v for v in nb if (v.get("cpu_mhz") or 0) > 0][:3]
        if top and tot:
            shares = ", ".join(f"{v['name']} {v['cpu_mhz'] * 100 / tot:.0f}%" for v in top)
            hot = any(f["title"] in ("CPU 경합(ready)", "vCPU 과다 할당 의심(co-stop)") for f in out) or \
                (not vm and any(f["title"] == "CPU 포화" for f in out))
            add("warning" if hot and top[0]["cpu_mhz"] * 100 / tot >= 40 else "info", "neighbor",
                "같은 호스트에서 CPU 를 많이 쓰는 VM" if vm else "이 호스트에서 CPU 를 많이 쓰는 VM",
                f"호스트 내 CPU 사용 비중: {shares} (vCenter 요약값)",
                "경합이 있으면 상위 VM 을 다른 호스트로 옮기거나(DRS 규칙) 리소스 공유값 조정" if hot else "")
    out.sort(key=lambda f: -SEV_ORDER.get(f["sev"], 0))
    level = out[0]["sev"] if out and out[0]["sev"] in ("critical", "warning") else "ok"
    return {"level": level, "findings": out, "baseline": base, "neighbors": [v.get("name") for v in (neighbors or [])]}


def digest(kind: str, name: str, rt: dict, diag: dict, info: dict) -> dict:
    """AI 해설용 요약(수치만 — 이름은 호출 쪽에서 가명 처리)"""
    sm = rt.get("summary") or {}
    pick = {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in sm.items()}
    return {"대상": ("VM" if kind == "vm" else "호스트") + " " + name, "구성": {k: info.get(k) for k in ("cluster", "host", "vcpu", "mem_mb", "os", "cpu_mhz", "version", "model") if info.get(k)},
            "최근1시간요약(최근·평균·최대)": pick, "디스크별": (rt.get("instances") or {}).get("disk", [])[:8],
            "NIC별": (rt.get("instances") or {}).get("net", [])[:8], "자동진단": diag.get("findings", []), "평소대비": diag.get("baseline", {})}
