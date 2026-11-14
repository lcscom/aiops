"""BIOS 기준선(가상화 호스트) — 기능 단위 규칙을 벤더별 속성 이름 후보로 대조

등급: blocker(가상화·부팅 필수) · warn(성능·vSAN ESA 영향) · info(운영 선택). 속성이 없으면 'unknown'(벤더·세대마다 이름이 달라 판단 불가) — 드리프트로 치지 않는다.
근거: vSphere 성능 모범 사례(하드웨어 가상화·하이퍼스레딩·터보·전원 정책은 OS 제어 권장), vSAN ESA 는 Intel VMD 를 쓰지 않는 직결 NVMe 구성.
값 비교는 대소문자·공백·구분자를 무시한다.
"""
from __future__ import annotations

import re
from typing import Any

# (id, 기능, 등급, 범주, [속성 후보], [허용 값 정규식], 설명, esa_only)
RULES: list[tuple[str, str, str, str, list[str], list[str], str, bool]] = [
    ("virt", "CPU 가상화(VT-x/AMD-V)", "blocker", "가상화",
     ["ProcVirtualization", "IntelVirtualizationTechnology", "Processors_IntelVirtualizationTechnology", "SVMMode", "SvmMode", "CbsCmnCpuSvmMode", "VTx", "IntelVT"],
     [r"enabled?", r"^on$", r"^auto$"], "꺼져 있으면 ESX 가 VM 을 실행할 수 없음", False),
    ("iommu", "I/O 가상화(VT-d/AMD-Vi IOMMU)", "blocker", "가상화",
     ["IntelProcVtd", "VtdSupport", "DevicesandIOPorts_IntelVTforDirectedIOVTd", "IOMMU", "AmdIoMmu", "CbsCmnGnbNbIOMMU", "ProcVirtualizationDirectIO", "VTd"],
     [r"enabled?", r"^on$", r"^auto$"], "DirectPath I/O·SR-IOV·vGPU·일부 보안 기능에 필요", False),
    ("boot", "부팅 모드 UEFI", "blocker", "부팅",
     ["BootMode", "BootModes_SystemBootMode", "BootModeSelect", "SystemBootMode", "BootModeSetting"], [r"uefi"], "legacy BIOS 는 신규 플랫폼에서 인증 불가(KB 313152)", False),
    ("vmd", "Intel VMD 비활성(직결 NVMe)", "warn", "스토리지",
     ["VmdSupport", "DevicesandIOPorts_EnableDisableIntelVMD", "IntelVmd", "VMDConfig", "VmdEnable", "IntelVMDTechnology"], [r"disabled?", r"^off$"],
     "VMD 가 켜져 있으면 NVMe 가 VMD 컨트롤러 뒤로 숨어 vSAN ESA 직결 요건·HCL 대조가 어긋남", True),
    ("smt", "하이퍼스레딩/SMT", "warn", "성능",
     ["LogicalProc", "ProcHyperthreading", "Processors_HyperThreading", "HyperThreading", "SMTControl", "CbsCmnCpuSmtCtrl", "SMTMode"], [r"enabled?", r"^on$", r"^auto$"],
     "끄면 논리 CPU 가 절반 — ESX 스케줄러는 SMT 를 인지해 활용", False),
    ("turbo", "터보 부스트/CPB", "warn", "성능",
     ["ProcTurboMode", "ProcTurbo", "Processors_TurboMode", "TurboMode", "CbsCmnCpuCpb", "CorePerformanceBoost"], [r"enabled?", r"^on$", r"^auto$"], "단일 스레드 성능", False),
    ("power", "전원 정책 OS 제어 또는 최대 성능", "warn", "전원",
     ["SysProfile", "WorkloadProfile", "PowerRegulator", "SystemSettings_WorkloadProfile", "OperatingModes_ChooseOperatingMode", "PwrPerfTuning", "PowerPerformanceTuning",
      "DeterminismControl", "DeterminismSlider"],
     [r"perf", r"os ?(control|dbpm)|osdbpm|oscontrol", r"virtuali[sz]ation", r"custom", r"staticHighPerf", r"maxperf", r"power determinism|^power$|manual|auto"],
     "BIOS 절전(DAPC·Dynamic Power Savings 등)은 지연·성능 저하 — 'OS 제어'로 ESX 전원 정책을 쓰거나 최대 성능", False),
    ("sriov", "SR-IOV", "info", "가상화", ["SriovGlobalEnable", "Sriov", "DevicesandIOPorts_SRIOV", "SRIOVSupport", "SriovSupport"], [r"enabled?", r"^on$"],
     "SR-IOV NIC·vGPU 쓸 때 필요", False),
    ("numa", "노드 인터리브 끔(NUMA 노출)", "warn", "성능", ["NodeInterleave", "NodeInterleaving", "NUMAOptimize"], [r"disabled?", r"^off$", r"^enabled$"],
     "노드 인터리브가 켜지면 NUMA 가 숨겨져 ESX NUMA 스케줄링 불가(NUMAOptimize 는 Enabled 가 정상)", False),
    ("snc", "Sub-NUMA Clustering 끔 / NPS1", "info", "성능", ["SubNumaCluster", "SubNumaClustering", "Processors_SNC", "NumaNodesPerSocket", "CbsDfCmnMemIntlv"],
     [r"disabled?", r"^off$", r"nps1", r"^auto$", r"^1$"], "일반 가상화는 SNC 끔/NPS1 이 단순 — HPC·지연 민감 워크로드는 예외", False),
    ("x2apic", "x2APIC", "info", "가상화", ["ProcX2Apic", "X2ApicOptOut", "X2APIC", "Processors_X2APIC"], [r"enabled?", r"^on$", r"^auto$"], "대규모 코어·IOMMU 인터럽트 리매핑", False),
    ("tpm", "TPM 활성", "warn", "보안", ["TpmSecurity", "TpmState", "TrustedComputingGroup_DeviceOperation", "Tpm2Hierarchy", "TPMState", "TpmEnable"],
     [r"on", r"enabled?", r"present"], "호스트 증명·암호화 키 보호", False),
    ("mmio", "4GB 이상 MMIO", "info", "가상화", ["MmioAbove4Gb", "Above4GDecoding", "MMIOAbove4G", "DevicesandIOPorts_MMIOAbove4GB"], [r"enabled?", r"^on$"],
     "GPU·대용량 BAR 장치 패스스루에 필요", False),
]


def _norm(v) -> str:
    return re.sub(r"[\s_\-]+", " ", str(v)).strip().lower()


def evaluate(h: dict, esa_candidate: bool = False) -> dict[str, Any]:
    attrs = (h.get("bios") or {}).get("attributes") or {}
    if not attrs:
        return {"rows": [], "status": "unknown", "compliance": None, "note": "BIOS 속성을 받지 못함(Bios 리소스 미노출·권한)"}
    low = {k.lower(): (k, v) for k, v in attrs.items()}
    rows = []
    for rid, title, sev, cat, cands, allowed, why, esa_only in RULES:
        hit = next((low[c.lower()] for c in cands if c.lower() in low), None)
        if not hit:
            rows.append({"id": rid, "title": title, "severity": sev, "category": cat, "attribute": "", "current": "", "status": "unknown", "why": why})
            continue
        k, v = hit
        ok = any(re.search(a, _norm(v), re.I) for a in allowed)
        s = sev if (esa_only is False or esa_candidate) else "info"
        rows.append({"id": rid, "title": title, "severity": s, "category": cat, "attribute": k, "current": str(v), "status": "pass" if ok else "drift", "why": why})
    app = [r for r in rows if r["status"] != "unknown"]
    drift = [r for r in app if r["status"] == "drift"]
    st = "fail" if any(r["severity"] == "blocker" for r in drift) else ("warn" if any(r["severity"] == "warn" for r in drift) else ("info" if drift else "pass"))
    return {"rows": rows, "status": st, "compliance": round((len(app) - len(drift)) / len(app) * 100, 1) if app else None,
            "assessed": len(app), "drift": len(drift), "registry": (h.get("bios") or {}).get("registry", "")}


def drift_between(a: dict, b: dict) -> list[dict]:
    """같은 모델 호스트 간 BIOS 속성 차이(플릿 기준선 편차) — 이름이 같은 속성만"""
    aa, bb = (a.get("bios") or {}).get("attributes") or {}, (b.get("bios") or {}).get("attributes") or {}
    return [{"attribute": k, "a": aa[k], "b": bb[k]} for k in sorted(set(aa) & set(bb)) if str(aa[k]) != str(bb[k])]
