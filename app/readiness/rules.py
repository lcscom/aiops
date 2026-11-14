"""VCF 9.x 하드웨어 준비도 평가 규칙 — 입력은 collect.collect() 의 정규화 dict, 네트워크 I/O 없음

근거(1차 출처, 2026-10 확인)
  · CPU: Broadcom KB 428874(2026-09-18 갱신) — Cascade Lake 는 VCF 9 'Deprecated Mode(지원)', Skylake-SP 는 9/18 갱신으로 VCF 9.x 'Deprecated Mode'
    (설치·업그레이드에 override 필요, VCF 9.x 이후 연장 없음), 9.0 BCG 에 없는 CPU 는 EOL. + BCG CPU Series(ESXi 9.1) CPUID 목록(있으면 우선)
  · 부팅: Broadcom KB 313152 — vSphere 8.0 부터 신규 인증 플랫폼(Intel Cascade Lake·AMD Rome 이후)은 legacy BIOS 불가, 향후 완전 제거 예정
  · vSAN ESA: VMware 블로그 2025-11-14 'lower hardware requirements for vSAN' — ReadyNode 최소 16코어·128GB, HCI 는 호스트당 NVMe 1개부터,
    스토리지 클러스터는 2개부터, 권장 4(Gen5)~6(Gen4)개, 10GbE 는 최소 ReadyNode 에서 지원·신규는 25GbE 이상 강력 권장
값이 없으면 'unknown'(확인 불가)으로 남긴다 — 통과로 간주하지 않는다.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ASSETS = Path(__file__).resolve().parent.parent / "assets"
STATUS_RANK = {"fail": 4, "warn": 3, "unknown": 2, "info": 1, "pass": 0}
TIER = {
    "supported": ("pass", "지원"),
    "deprecated": ("warn", "지원 · Deprecated Mode"),
    "deprecated_override": ("warn", "지원 · Deprecated Mode(설치·업그레이드 시 CPU override 필요, VCF 9.x 까지)"),
    "verify": ("unknown", "BCG 확인 필요"),
    "eol": ("fail", "미지원(EOL — 9.0 BCG 목록에 없음)"),
    "not_eligible": ("fail", "서버용 CPU 아님(BCG 대상 아님)"),
}
KB = {"cpu": "https://knowledge.broadcom.com/external/article/428874", "bios": "https://knowledge.broadcom.com/external/article/313152",
      "esa": "https://blogs.vmware.com/cloud-foundation/2025/11/14/driving-down-storage-costs-with-lower-hardware-requirements-for-vsan/",
      "bcg": "https://compatibilityguide.broadcom.com/"}

# (정규식, 계열, 등급, 채널/소켓, 최대 DDR MT/s) — 위에서부터 첫 일치. 숫자는 '참고'(메모리 채널 평가에만 씀)
CPU_TABLE: list[tuple[str, str, str, int, int]] = [
    (r"\bMAX\s*94\d\d", "Intel Xeon CPU Max 9400 (Sapphire Rapids HBM)", "supported", 8, 4800),
    (r"\b69\d\d[PE]\b|GRANITE RAPIDS-AP", "Intel Xeon 6 6900 (Granite Rapids-AP)", "supported", 12, 6400),
    (r"\b6[5-8]\d\dP\b|GRANITE RAPIDS", "Intel Xeon 6 6500P/6700P (Granite Rapids-SP)", "supported", 8, 6400),
    (r"\b6[5-8]\d\dE\b|SIERRA FOREST", "Intel Xeon 6 6700E (Sierra Forest)", "verify", 8, 6400),
    (r"\b63\d\dP\b|\bE-24\d\d", "Intel Xeon E-2400 / Xeon 6300", "supported", 2, 4800),
    (r"(PLATINUM|GOLD|SILVER|BRONZE)\s*[3-9]5\d\d|EMERALD RAPIDS", "Intel Xeon 5th Gen (Emerald Rapids)", "supported", 8, 5600),
    (r"(PLATINUM|GOLD|SILVER|BRONZE)\s*[3-9]4\d\d|SAPPHIRE RAPIDS", "Intel Xeon 4th Gen (Sapphire Rapids)", "supported", 8, 4800),
    (r"(PLATINUM|GOLD)\s*[3-9]3\d\dH|COOPER LAKE", "Intel Xeon 3rd Gen (Cooper Lake)", "supported", 6, 3200),
    (r"(PLATINUM|GOLD|SILVER)\s*[3-9]3\d\d|ICE LAKE-SP|ICE LAKE SP", "Intel Xeon 3rd Gen (Ice Lake-SP)", "supported", 8, 3200),
    (r"(PLATINUM|GOLD|SILVER|BRONZE)\s*([3-9]2\d\d|92\d\d)|CASCADE LAKE", "Intel Xeon 2nd Gen (Cascade Lake)", "deprecated", 6, 2933),
    (r"(PLATINUM|GOLD|SILVER|BRONZE)\s*[3-9]1\d\d|SKYLAKE-SP|SKYLAKE SP", "Intel Xeon 1st Gen (Skylake-SP)", "deprecated_override", 6, 2666),
    (r"\bD-?\s?[12]7\d\d", "Intel Xeon D-1700/D-2700 (Ice Lake-D)", "supported", 4, 3200),
    (r"\bD-?\s?[12]8\d\d", "Intel Xeon D-1800/D-2800", "verify", 4, 3200),
    (r"\bD-?\s?(15|16|21)\d\d", "Intel Xeon D-1500/1600/2100", "eol", 4, 2666),
    (r"\bE-2[123]\d\d", "Intel Xeon E-2100/2200/2300", "supported", 2, 3200),
    (r"\bE3-1\d\d\d", "Intel Xeon E3-1200", "eol", 2, 2400),
    (r"\bW-11\d\d\d", "Intel Xeon W-11000", "supported", 2, 3200),
    (r"\bE[57]-\d{4}|\bV[234]\b", "Intel Xeon E5/E7 (Haswell·Broadwell 이전)", "eol", 4, 2400),
    (r"\bC3\d\d\d\b|\bATOM.*C3", "Intel Atom C3000", "supported", 2, 2400),
    (r"\bATOM\b|\bP59\d\d\b", "Intel Atom(기타)", "verify", 2, 2933),
    (r"\bI[357]-11\d\dGRE\b", "Intel Core 1100GRE(임베디드)", "supported", 2, 3200),
    (r"EPYC\s*9\d\d5|TURIN", "AMD EPYC 9005 (Turin)", "supported", 12, 6400),
    (r"EPYC\s*9\d\d4|GENOA|BERGAMO", "AMD EPYC 9004 (Genoa·Bergamo)", "supported", 12, 4800),
    (r"EPYC\s*8\d\d4|SIENA", "AMD EPYC 8004 (Siena)", "supported", 6, 4800),
    (r"EPYC\s*7(\d\d|[FH]\d)3|MILAN", "AMD EPYC 7003 (Milan)", "supported", 8, 3200),
    (r"EPYC\s*7(\d\d|[FH]\d)2|ROME", "AMD EPYC 7002 (Rome)", "supported", 8, 3200),
    (r"EPYC\s*7\d\d1|NAPLES", "AMD EPYC 7001 (Naples)", "supported", 8, 2666),
    (r"EPYC\s*4\d\d[45]", "AMD EPYC 4004/4005", "verify", 2, 5200),
    (r"EPYC\s*3\d\d\d|EPYC EMBEDDED 3", "AMD EPYC Embedded 3000", "verify", 4, 2666),
    (r"RYZEN.*\bV1\d\d\d|\bV1\d\d\dB?\b", "AMD Ryzen Embedded V1000", "supported", 2, 3200),
    (r"RYZEN|ATHLON", "AMD Ryzen(데스크톱·모바일)", "not_eligible", 2, 3200),
    (r"INTEL.*\bCORE\b(?!-)|\bI[3579]-\d|CELERON|PENTIUM|CORE ULTRA", "Intel Core(데스크톱·모바일)", "not_eligible", 2, 3200),
]
_BCG: dict | None = None


def bcg_cpu() -> dict[str, list[str]]:
    """CPUID(0x%08x 소문자) → [시리즈 이름] — BCG CPU Series 목록(가져온 값이 있으면 그것, 없으면 동봉본)"""
    global _BCG
    if _BCG is None:
        p = ASSETS / "bcg_cpu_series.json"
        d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"series": []}
        set_bcg_cpu(d)
    return _BCG["by"]


def set_bcg_cpu(d: dict) -> None:
    global _BCG
    by: dict[str, list[str]] = defaultdict(list)
    for s in d.get("series") or []:
        for c in s.get("cpuids") or []:
            by[str(c).lower()].append(s.get("series", ""))
    _BCG = {"by": dict(by), "source": d.get("source", ""), "count": len(d.get("series") or [])}


def bcg_info() -> dict:
    bcg_cpu()
    return {"source": _BCG["source"], "series": _BCG["count"]}


def parse_bcg_csv(text: str) -> dict:
    """BCG 'CPU Series' CSV(열: CPU Series, Cores/Threads, CPUID Info, CPUIDs, Supported Releases) → 동봉 형식"""
    import csv
    import io
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    if not rows or "CPUIDs" not in rows[0]:
        raise ValueError("CPUIDs 열이 있는 BCG CPU Series CSV 가 아닙니다")
    out = []
    for r in rows:
        ids = [x.strip().lower() for x in re.split(r"[,\n]", r.get("CPUIDs") or "") if re.fullmatch(r"0x[0-9a-fA-F]{8}", x.strip())]
        if ids:
            out.append({"series": " ".join((r.get("CPU Series") or "").split()), "cores_threads": " ".join((r.get("Cores/Threads") or "").split()),
                        "cpuids": ids, "releases": [x.strip() for x in (r.get("Supported Releases") or "").split("\n") if x.strip()]})
    if not out:
        raise ValueError("CPUID 행이 없습니다")
    return {"source": "BCG CPU Series CSV(관리자 가져오기)", "series": out}


def cpuid_sig(family: str, model: str, step: str) -> str | None:
    """Redfish ProcessorId.EffectiveFamily/EffectiveModel/Step → CPUID 시그니처 '0x000606a6'"""
    def num(v):
        s = str(v or "").strip().lower()
        try:
            return int(s, 16) if s.startswith("0x") else int(s)
        except ValueError:
            return None
    f, m, st = num(family), num(model), num(step)
    if f is None or m is None or st is None:
        return None
    bf, ef = (f, 0) if f < 0xF else (0xF, f - 0xF)
    sig = (ef << 20) | ((m >> 4) << 16) | (bf << 8) | ((m & 0xF) << 4) | (st & 0xF)
    return f"0x{sig:08x}"


def classify_cpu(model: str, cpuid: str | None = None) -> dict[str, Any]:
    u = " " + re.sub(r"\(R\)|\(TM\)|CPU @.*$", " ", str(model or "").upper()) + " "
    row = next((r for r in CPU_TABLE if re.search(r[0], u)), None)
    fam, tier, ch, ddr = (row[1], row[2], row[3], row[4]) if row else ("알 수 없음", "verify", 8, 3200)
    bcg = bcg_cpu().get((cpuid or "").lower()) if cpuid else None
    evidence = "이름 규칙"
    if bcg:
        evidence = f"BCG CPUID {cpuid}: {bcg[0]}"
        if tier in ("verify", "eol", "not_eligible") or not row:
            tier = "supported"                       # BCG 에 있으면 최소 '지원'(Skylake·Cascade 는 위 이름 규칙의 Deprecated 유지)
    elif cpuid and row and tier == "supported" and bcg_cpu():
        evidence = f"이름 규칙(CPUID {cpuid} 는 동봉 BCG 목록에 없음 — 최신 BCG 확인 권장)"
    st, label = TIER[tier]
    return {"family": fam, "tier": tier, "status": st, "label": label, "channels": ch, "max_ddr": ddr, "evidence": evidence, "cpuid": cpuid}


# ---------------------------------------------------------------------------------- 공통
def chk(area: str, cid: str, title: str, status: str, detail: str = "", fix: str = "", ref: str = "", evidence: Any = None) -> dict:
    return {"area": area, "id": cid, "title": title, "status": status, "detail": detail, "fix": fix, "ref": ref, **({"evidence": evidence} if evidence is not None else {})}


def worst(items: list[dict]) -> str:
    return max((i["status"] for i in items), key=lambda s: STATUS_RANK.get(s, 0), default="unknown")


BOOT_RX = re.compile(r"(?i)boss|m\.2|satadom|ns204|nvme boot|\bsd\b|idsdm|usb|dual sd|raid1 boot")


def is_boot(d: dict, ctrl: dict | None) -> bool:
    t = f"{d.get('name', '')} {d.get('ctrl', '')} {(ctrl or {}).get('name', '')} {(ctrl or {}).get('model', '')} {d.get('form', '')}"
    return bool(BOOT_RX.search(t)) or (0 < (d.get("capacity_gb") or 0) <= 600 and "m.2" in t.lower())


TRIMODE_RX = re.compile(r"(?i)9[45][068]0|9600|sas39\d\d|tri-?mode|perc\s?1[12]|h7[45]5n|h9[56]5|mr9\d\d0|940-\d+i")
CONSUMER_RX = re.compile(r"(?i)\b(evo|qvo|crucial mx|crucial p[1-5]|wd (blue|black|green)|sn[5-8]50|970 pro|980 pro|990 pro|kingston a\d|mp600)\b")


# ---------------------------------------------------------------------------------- 영역별 평가
def eval_cpu(h: dict) -> tuple[list[dict], dict]:
    cpus = h.get("cpus") or []
    if not cpus:
        return [chk("cpu", "cpu.class", "CPU 지원 등급", "unknown", "CPU 정보를 받지 못함(권한·BMC 지원 확인)", ref=KB["cpu"])], {}
    c0 = cpus[0]
    sig = cpuid_sig(c0.get("family"), c0.get("model_id"), c0.get("step"))
    cl = classify_cpu(c0.get("model"), sig)
    cores = sum(c.get("cores") or 0 for c in cpus)
    models = {c.get("model") for c in cpus}
    out = [chk("cpu", "cpu.class", "CPU 지원 등급(VCF 9.x)", cl["status"], f"{c0.get('model')} → {cl['family']} · {cl['label']} ({cl['evidence']})",
               {"deprecated": "지원되지만 신규 기능 개선이 없고 교체 계획 권장(KB 428874)",
                "deprecated_override": "ESX 9.x 설치·업그레이드 시 CPU 지원 override 절차 필요(KB 428874 첨부 문서), VCF 9.x 이후 지원 없음",
                "eol": "교체 대상 — ESX 9.x 설치 단계에서 인식되지 않음", "not_eligible": "서버 플랫폼으로 교체",
                "verify": "Broadcom Compatibility Guide 에서 CPU 시리즈 확인"}.get(cl["tier"], ""), KB["cpu"])]
    if len(models) > 1:
        out.append(chk("cpu", "cpu.mixed", "소켓 간 CPU 모델 동일", "fail", " / ".join(sorted(m for m in models if m)), "같은 모델로 맞추세요"))
    bad = [c["socket"] for c in cpus if c.get("health") not in ("", "OK")]
    if bad:
        out.append(chk("cpu", "cpu.health", "CPU 상태", "fail", f"비정상: {', '.join(bad)}"))
    esa_cores = "pass" if cores >= 16 else "warn"
    out.append(chk("cpu", "cpu.cores", "물리 코어(ESA ReadyNode 최소 16)", esa_cores, f"{len(cpus)}소켓 × {c0.get('cores') or '?'}코어 = {cores}코어", "" if esa_cores == "pass" else "vSAN ESA 최소 사양 미달", KB["esa"]))
    return out, {**cl, "sockets": len(cpus), "cores": cores, "threads": sum(c.get("threads") or 0 for c in cpus), "model": c0.get("model"),
                 "cores_per_socket": c0.get("cores")}


def eval_memory(h: dict, cpu: dict) -> tuple[list[dict], dict]:
    dimms = [d for d in h.get("dimms") or [] if d.get("present")]
    allslots = h.get("dimms") or []
    if not dimms:
        return [chk("memory", "mem.inv", "메모리 구성", "unknown", "DIMM 정보를 받지 못함")], {}
    sockets = cpu.get("sockets") or max([d.get("socket") or 1 for d in dimms] + [1])
    nch = cpu.get("channels") or 8
    total = round(sum(d["size_gib"] for d in dimms))
    out = []
    per_sock: dict[int, list[dict]] = defaultdict(list)
    for d in dimms:
        per_sock[d.get("socket") or 1].append(d)
    gib = {s: sum(x["size_gib"] for x in v) for s, v in per_sock.items()}
    if sockets > 1 and len(set(round(x) for x in gib.values())) > 1 or (sockets > 1 and len(per_sock) < sockets):
        out.append(chk("memory", "mem.socket_balance", "소켓 간 메모리 균형", "warn", " · ".join(f"CPU{s} {round(g)}GB" for s, g in sorted(gib.items())),
                       "소켓마다 같은 용량·같은 개수로 장착(NUMA 불균형 방지)"))
    else:
        out.append(chk("memory", "mem.socket_balance", "소켓 간 메모리 균형", "pass", " · ".join(f"CPU{s} {round(g)}GB" for s, g in sorted(gib.items()))))
    have_ch = any(d.get("channel") for d in dimms)
    ch_used = {s: len({d.get("channel") for d in v if d.get("channel") not in (None, "")}) for s, v in per_sock.items()}
    if have_ch:
        under = {s: n for s, n in ch_used.items() if n < nch}
        if under:
            out.append(chk("memory", "mem.channels", f"채널 모두 사용(소켓당 {nch}채널)", "warn", " · ".join(f"CPU{s} {n}/{nch}채널" for s, n in sorted(under.items())),
                           f"채널마다 1개 이상 장착해야 메모리 대역폭을 다 씀(현재 약 {round(min(under.values()) / nch * 100)}%)"))
        else:
            out.append(chk("memory", "mem.channels", f"채널 모두 사용(소켓당 {nch}채널)", "pass", " · ".join(f"CPU{s} {n}/{nch}" for s, n in sorted(ch_used.items()))))
        dpc = Counter((d.get("socket") or 1, d.get("channel")) for d in dimms)
        if len(set(dpc.values())) > 1:
            out.append(chk("memory", "mem.dpc", "채널당 DIMM 수 균일", "warn", f"채널당 {sorted(set(dpc.values()))}개 혼재", "모든 채널을 같은 DPC 로"))
    else:
        exp = sockets * nch
        st = "pass" if len(dimms) % exp == 0 else "warn"
        out.append(chk("memory", "mem.channels", f"DIMM 수가 채널 수의 배수(총 {exp}채널)", st, f"DIMM {len(dimms)}개 / 슬롯 {len(allslots)}개 (채널 위치 미보고 — 개수로 판단)",
                       "" if st == "pass" else "소켓당 채널 수의 배수로 장착 권장"))
    sizes = Counter(d["size_gib"] for d in dimms)
    parts = Counter(d.get("part") for d in dimms if d.get("part"))
    if len(sizes) > 1:
        out.append(chk("memory", "mem.mixed_size", "DIMM 용량 혼용 없음", "warn", ", ".join(f"{s:g}GB×{n}" for s, n in sizes.items()), "같은 용량·랭크로 통일"))
    if len(parts) > 1:
        out.append(chk("memory", "mem.mixed_part", "DIMM 부품 번호 단일", "info", ", ".join(f"{p}×{n}" for p, n in parts.most_common(4))))
    slow = [d for d in dimms if d.get("speed") and d.get("rated") and d["speed"] < d["rated"]]
    if slow:
        sp = Counter((d["speed"], d["rated"]) for d in slow)
        out.append(chk("memory", "mem.speed", "DIMM 정격 속도로 동작", "info", ", ".join(f"{a}/{b} MT/s ×{n}" for (a, b), n in sp.items()),
                       "2DPC·CPU 지원 속도·BIOS 메모리 설정 때문일 수 있음(성능 영향 확인)"))
    bad = [d for d in dimms if d.get("health") not in ("", "OK")]
    if bad:
        out.append(chk("memory", "mem.health", "DIMM 상태", "fail" if any(d["health"] == "Critical" for d in bad) else "warn",
                       ", ".join(f"{d['locator']} {d['health']}" for d in bad[:8]), "SEL 의 정정 가능/불가 오류 확인 후 교체"))
    esa = "pass" if total >= 128 else "warn"
    out.append(chk("memory", "mem.total", "총 메모리(ESA ReadyNode 최소 128GB)", esa, f"{total}GB · DIMM {len(dimms)}/{len(allslots)} 슬롯 · {dimms[0].get('type') or ''}", ref=KB["esa"]))
    return out, {"total_gib": total, "dimms": len(dimms), "slots": len(allslots), "channels_per_socket": nch, "type": dimms[0].get("type")}


def eval_storage(h: dict, nic_gbps: float | None, cpu: dict, mem: dict, hcl=None) -> tuple[list[dict], dict]:
    st = h.get("storage") or {}
    ctrls = {c["id"]: c for c in st.get("controllers") or []}
    drives = st.get("drives") or []
    out = []
    direct, behind_raid, osa, boot, hcl_rows = [], [], [], [], []
    for d in drives:
        c = ctrls.get(d.get("ctrl"))
        d["role"] = "boot" if is_boot(d, c) else "data"
        if d["role"] == "boot":
            boot.append(d)
            continue
        mode = (c or {}).get("mode", "").upper()
        cname = f"{(c or {}).get('name', '')} {(c or {}).get('model', '')}"
        nvme = (d.get("protocol") or "").upper() == "NVME"
        if nvme and (TRIMODE_RX.search(cname) or mode == "RAID"):
            behind_raid.append(d)
        elif nvme:
            direct.append(d)
        elif (d.get("media") or "").upper() == "SSD":
            osa.append(d)
        m = hcl.match_drive(d) if hcl else None
        d["hcl"] = m
        hcl_rows.append(m)
    tb = round(sum(d["capacity_gb"] for d in direct) / 1000, 2)
    life = [d for d in drives if d.get("life_left") is not None]
    for d in life:
        if d["life_left"] < 20:
            out.append(chk("storage", f"drv.life.{d['name']}", f"드라이브 수명 {d['name']}", "fail", f"남은 수명 {d['life_left']:g}% · {d['model']}", "교체 계획"))
        elif d["life_left"] < 50:
            out.append(chk("storage", f"drv.life.{d['name']}", f"드라이브 수명 {d['name']}", "warn", f"남은 수명 {d['life_left']:g}% · {d['model']}"))
    for d in drives:
        if d.get("failure_predicted") or d.get("health") in ("Critical",):
            out.append(chk("storage", f"drv.health.{d['name']}", f"드라이브 상태 {d['name']}", "fail", f"{d.get('health')} · 고장 예측 {d.get('failure_predicted')}"))
        elif d.get("health") == "Warning":
            out.append(chk("storage", f"drv.health.{d['name']}", f"드라이브 상태 {d['name']}", "warn", f"{d['model']} Warning"))
        if CONSUMER_RX.search(d.get("model") or ""):
            out.append(chk("storage", f"drv.consumer.{d['name']}", "소비자용 SSD", "fail", d["model"], "vSAN 미인증 — 엔터프라이즈 SSD 로 교체"))
    if not boot:
        out.append(chk("storage", "boot.device", "전용 부트 장치(BOSS·M.2 RAID1 등)", "unknown", "BMC 에서 부트 장치를 식별하지 못함"))
    else:
        out.append(chk("storage", "boot.device", "전용 부트 장치", "pass" if len(boot) >= 2 or any("boss" in (b.get("ctrl") or "").lower() for b in boot) else "info",
                       ", ".join(f"{b['name']} {b['capacity_gb']:g}GB" for b in boot), "부트 장치 이중화(RAID1) 권장"))
    # vSAN ESA / OSA 판정
    esa_hcl = [d for d in direct if (d.get("hcl") or {}).get("esa")]
    if behind_raid and not direct:
        v = chk("vsan", "vsan.esa", "vSAN ESA", "fail", f"NVMe {len(behind_raid)}개가 RAID/Tri-Mode 컨트롤러 뒤에 있음",
                "ESA 는 컨트롤러를 거치지 않는 직결 NVMe 필요 — 직결 백플레인/케이블 구성으로 변경")
        verdict = "not_supported"
    elif direct:
        net = "pass" if (nic_gbps or 0) >= 25 else ("warn" if (nic_gbps or 0) >= 10 else "fail")
        cnt = "pass" if len(direct) >= 4 else "warn"
        parts = [f"직결 NVMe {len(direct)}개({tb}TB)", f"NIC 최대 {nic_gbps or '?'}Gb", f"코어 {cpu.get('cores', '?')}", f"메모리 {mem.get('total_gib', '?')}GB"]
        if hcl and hcl.loaded:
            parts.append(f"HCL ESA 인증 {len(esa_hcl)}/{len(direct)}")
        sev = "fail" if net == "fail" else ("warn" if "warn" in (net, cnt) or (hcl and hcl.loaded and len(esa_hcl) < len(direct)) or (cpu.get("cores") or 0) < 16 or (mem.get("total_gib") or 0) < 128 else "pass")
        fixes = []
        if net == "warn":
            fixes.append("10GbE 는 최소 ReadyNode 에서만 지원 — 25GbE 이상 강력 권장")
        if net == "fail":
            fixes.append("10GbE 이상 NIC 필요")
        if cnt == "warn":
            fixes.append("HCI 는 1개부터 가능하나 4(Gen5)~6(Gen4)개 권장, 스토리지 클러스터는 2개 이상")
        if hcl and hcl.loaded and len(esa_hcl) < len(direct):
            fixes.append("HCL 에서 ESA 인증되지 않은 드라이브 확인")
        v = chk("vsan", "vsan.esa", "vSAN ESA", sev, " · ".join(parts), " / ".join(fixes), KB["esa"])
        verdict = "esa_ready" if sev == "pass" else ("esa_actions" if sev == "warn" else "esa_network")
    elif len(osa) >= 2:
        raid = [c for c in ctrls.values() if c.get("mode", "").upper() == "RAID"]
        v = chk("vsan", "vsan.osa", "vSAN OSA", "warn" if raid else "info", f"SAS/SATA SSD {len(osa)}개" + (f" · RAID 모드 컨트롤러 {len(raid)}개" if raid else ""),
                "OSA 는 HBA/패스스루 모드 필요" if raid else "ESA 로 가려면 직결 NVMe 필요(OSA 는 VCF 9 에서 신규 구성 비권장 여부 확인)")
        verdict = "osa_only"
    else:
        v = chk("vsan", "vsan.none", "vSAN 데이터 장치", "fail" if drives else "unknown", f"데이터용 SSD/NVMe {len(direct) + len(osa)}개", "외부 스토리지(VMFS·NFS·vVols) 주 스토리지 또는 NVMe 증설")
        verdict = "no_vsan"
    out.insert(0, v)
    raid_ctrl = [c for c in ctrls.values() if c.get("mode")]
    return out, {"verdict": verdict, "direct_nvme": len(direct), "nvme_tb": tb, "osa_ssd": len(osa), "nvme_behind_raid": len(behind_raid), "boot": len(boot),
                 "controllers": [f"{c['name']} ({c['mode'] or '모드 미확인'})" for c in raid_ctrl],
                 "hcl_loaded": bool(hcl and hcl.loaded), "hcl_esa": len(esa_hcl)}


def eval_network(h: dict) -> tuple[list[dict], dict]:
    ports = h.get("nics") or []
    up = [p for p in ports if str(p.get("link", "")).lower() in ("up", "linkup")]
    sp = max([p.get("speed_gbps") or 0 for p in up] + [0]) or None
    mx = max([p.get("max_gbps") or 0 for p in ports] + [0]) or None
    out = []
    if not ports:
        return [chk("network", "nic.inv", "NIC 정보", "unknown", "BMC 가 NIC 를 보고하지 않음")], {"max_up_gbps": None}
    stv = "pass" if (sp or 0) >= 25 else ("warn" if (sp or 0) >= 10 else ("fail" if sp else "unknown"))
    out.append(chk("network", "nic.speed", "데이터 NIC 링크 속도(VCF·vSAN: 10GbE 이상, 25GbE 권장)", stv,
                   f"연결된 포트 최대 {sp or '?'}Gb · 장착 NIC 최대 {mx or '?'}Gb · 연결 {len(up)}/{len(ports)}",
                   " — ".join(x for x in ({"warn": "25GbE 이상 권장(신규 ESA 는 강력 권장)", "fail": "10GbE 이상 NIC·스위치 필요"}.get(stv, ""),
                                         "NIC 는 더 빠른 속도를 지원함(스위치·광모듈 확인)" if mx and sp and mx > sp else "") if x), KB["esa"]))
    out.append(chk("network", "nic.redundancy", "업링크 이중화(연결 포트 2개 이상)", "pass" if len(up) >= 2 else "warn", f"연결 {len(up)}개",
                   "" if len(up) >= 2 else "스위치 2대로 이중화"))
    sw = {(p.get("lldp") or {}).get("system_name") or (p.get("lldp") or {}).get("chassis_id") for p in up if p.get("lldp")}
    sw.discard(None)
    sw.discard("")
    if not any(p.get("lldp") for p in up):
        out.append(chk("network", "nic.tor", "ToR 스위치 이중 연결(LLDP)", "unknown", "LLDP 이웃 정보 없음(스위치 LLDP 송신·BMC 지원 확인)"))
    elif len(sw) >= 2:
        out.append(chk("network", "nic.tor", "ToR 스위치 이중 연결(LLDP)", "pass", ", ".join(sorted(sw))))
    else:
        out.append(chk("network", "nic.tor", "ToR 스위치 이중 연결(LLDP)", "warn", f"모든 연결 포트가 한 스위치({', '.join(sw)})", "리프 쌍(2대)으로 분산 — 단일 스위치 장애 시 호스트 단절"))
    models = Counter(p.get("model") for p in ports)
    return out, {"max_up_gbps": sp, "max_nic_gbps": mx, "up": len(up), "ports": len(ports), "switches": sorted(sw), "adapters": [f"{m} ×{n}" for m, n in models.items()]}


def eval_platform(h: dict, cpu: dict) -> list[dict]:
    out = []
    bm = (h.get("system") or {}).get("boot_mode", "")
    sb = h.get("secureboot") or {}
    if sb.get("current") == "Enabled" or sb.get("enable") is True:
        bm = bm or "UEFI"
    new_plat = cpu.get("tier") in ("supported", "deprecated") and "Skylake" not in cpu.get("family", "") and "E5" not in cpu.get("family", "")
    if re.search(r"(?i)uefi", bm):
        out.append(chk("platform", "boot.uefi", "부팅 모드 UEFI", "pass", bm, ref=KB["bios"]))
    elif re.search(r"(?i)legacy|bios", bm):
        out.append(chk("platform", "boot.uefi", "부팅 모드 UEFI", "fail" if new_plat else "warn", f"{bm}" + (" — Cascade Lake/Rome 이후 플랫폼은 legacy BIOS 인증 불가" if new_plat else ""),
                       "UEFI 로 전환(재설치 필요할 수 있음) — legacy BIOS 는 향후 제거 예정(KB 313152)", KB["bios"]))
    else:
        out.append(chk("platform", "boot.uefi", "부팅 모드 UEFI", "unknown", "부팅 모드 미보고", ref=KB["bios"]))
    tpm = h.get("tpm") or []
    t = next((x for x in tpm if x.get("state") == "Enabled"), tpm[0] if tpm else None)
    attrs = (h.get("bios") or {}).get("attributes") or {}
    if not t:
        tb = next((str(v) for k, v in attrs.items() if re.search(r"(?i)^tpm(security|state|2|mode|_?enable)", k)), "")
        if tb and re.search(r"(?i)on|enable|present", tb) and not re.search(r"(?i)not ?present|off|disable", tb):
            out.append(chk("platform", "tpm", "TPM 2.0", "info", f"BIOS 설정 {tb}(Redfish TrustedModules 미보고 — 2.0 여부 확인)"))
        else:
            out.append(chk("platform", "tpm", "TPM 2.0", "warn", f"TPM 없음/미보고{(' (BIOS ' + tb + ')') if tb else ''}",
                           "호스트 증명(Attestation)·vSAN/VM 암호화 키 보호·ESXi 구성 암호화에 TPM 2.0 권장"))
    elif "2" in (t.get("type") or "") and t.get("state") == "Enabled":
        out.append(chk("platform", "tpm", "TPM 2.0", "pass", f"{t['type']} fw {t.get('fw')}"))
    else:
        out.append(chk("platform", "tpm", "TPM 2.0", "warn", f"{t.get('type') or '형식 미보고'} · {t.get('state')}", "TPM 2.0(FIFO/CRB) 활성화"))
    if sb:
        ok = sb.get("current") == "Enabled" or (sb.get("enable") is True and not sb.get("current"))
        out.append(chk("platform", "secureboot", "UEFI Secure Boot", "pass" if ok else "warn", f"Enable={sb.get('enable')} · 현재 부팅={sb.get('current') or '?'} · {sb.get('mode')}",
                       "" if ok else "Secure Boot 활성화(ESXi 9 보안 기준)"))
    pw = h.get("power") or {}
    psus = pw.get("psus") or []
    if psus:
        bad = [p for p in psus if p.get("health") not in ("", "OK")]
        red = pw.get("redundancy", "")
        st = "fail" if bad or "critical" in red.lower() else ("warn" if len(psus) < 2 else "pass")
        out.append(chk("platform", "psu", "전원 공급 장치 이중화", st, f"PSU {len(psus)}개 × {psus[0].get('watts') or '?'}W · 이중화 {red or '미보고'}" +
                       (f" · 비정상 {', '.join(p['name'] for p in bad)}" if bad else "") + (f" · 소비 {pw.get('consumed_w'):g}W" if pw.get("consumed_w") else ""),
                       "" if st == "pass" else "PSU 2개 이상·서로 다른 전원 계통 연결"))
    hot = [t for t in (h.get("thermal") or {}).get("temps") or [] if t.get("c") is not None and ((t.get("warn") and t["c"] >= t["warn"]) or t.get("health") not in ("", "OK"))]
    if hot:
        out.append(chk("platform", "thermal", "온도 센서", "warn", ", ".join(f"{t['name']} {t['c']:g}°C" for t in hot[:6])))
    fans = [f for f in (h.get("thermal") or {}).get("fans") or [] if f.get("health") not in ("", "OK")]
    if fans:
        out.append(chk("platform", "fans", "팬 상태", "warn", ", ".join(f["name"] for f in fans)))
    return out


def eval_sel(h: dict, days: int = 30) -> list[dict]:
    from datetime import datetime, timedelta, timezone
    ents = h.get("sel") or []
    if not ents:
        return [chk("events", "sel", "하드웨어 이벤트 로그(SEL/IML)", "unknown", "로그 서비스 미보고")]
    cut = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rec = [e for e in ents if (e.get("ts") or "") >= cut[:19] and e.get("severity") in ("critical", "warning")]
    crit = [e for e in rec if e["severity"] == "critical"]
    st = "fail" if crit else ("warn" if rec else "pass")
    return [chk("events", "sel", f"최근 {days}일 경고·위험 하드웨어 이벤트", st, f"위험 {len(crit)} · 경고 {len(rec) - len(crit)}" + (f" — 최근: {rec[0]['message'][:120]}" if rec else ""),
                "" if st == "pass" else "원인 부품 점검 후 진행(필요하면 SR)", evidence=rec[:20])]
