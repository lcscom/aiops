"""CPU 세대 판별과 EVC(Enhanced vMotion Compatibility) 검토 — 2.36.0 혼합 세대 클러스터 가정

근거(모두 Broadcom KB, 원문은 저장소에 넣지 않음 — 번호만 표기):
  · KB 313545 / 318962: vCenter 버전별 EVC 기준(Intel L0 Merom … L9 Cascade Lake, L10 Ice Lake, L11 Sapphire Rapids)
  · KB 405881: Sapphire Rapids EVC 는 vCenter 8.0 U1 이상
  · KB 324991: EVC 는 Intel ↔ AMD 사이 vMotion 을 허용하지 않음
  · KB 438859: Ice Lake ↔ Sapphire/Emerald Rapids 사이 HW v21 VM 마이그레이션 주의
모델명 → 세대 대응은 Intel·AMD 제품 번호 체계(Xeon Scalable 두 번째 자리, EPYC 마지막 자리)로 추정한다.
추정이 불확실하거나 표에 없는 세대(Xeon 6, Zen 5 등)는 'BCG(Broadcom Compatibility Guide)에서 확인'으로 표시한다.
"""
from __future__ import annotations

import re
from typing import Any

# (키, 이름, EVC 모드 키 또는 None, 순위) — 순위가 클수록 새 세대(같은 회사 안에서만 비교)
INTEL = [
    ("ivybridge", "Ivy Bridge", "intel-ivybridge", 5), ("haswell", "Haswell", "intel-haswell", 6),
    ("broadwell", "Broadwell", "intel-broadwell", 7), ("skylake", "Skylake", "intel-skylake", 8),
    ("cascadelake", "Cascade Lake", "intel-cascadelake", 9), ("icelake", "Ice Lake", "intel-icelake", 10),
    ("sapphirerapids", "Sapphire Rapids", "intel-sapphirerapids", 11), ("emeraldrapids", "Emerald Rapids", None, 12),
    ("xeon6", "Xeon 6 (Granite/Sierra)", None, 13),
]
AMD = [
    ("zen1", "Naples (Zen)", "amd-zen", 1), ("zen2", "Rome (Zen 2)", "amd-zen2", 2), ("zen3", "Milan (Zen 3)", "amd-zen3", 3),
    ("zen4", "Genoa (Zen 4)", "amd-zen4", 4), ("zen5", "Turin (Zen 5)", None, 5),
]
_I = {k: (n, e, r) for k, n, e, r in INTEL}
_A = {k: (n, e, r) for k, n, e, r in AMD}
EVC_RANK = {e: ("intel", r) for _, _, e, r in INTEL if e} | {e: ("amd", r) for _, _, e, r in AMD if e}
# vCenter 가 내주는 이전 세대 키(L0~L4)도 순위만 알면 된다
EVC_RANK.update({"intel-merom": ("intel", 0), "intel-penryn": ("intel", 1), "intel-nehalem": ("intel", 2),
                 "intel-westmere": ("intel", 3), "intel-sandybridge": ("intel", 4)})


def generation(model: str) -> dict[str, Any] | None:
    """'Intel(R) Xeon(R) Gold 6430' → {'vendor': 'intel', 'key': 'sapphirerapids', 'name': ..., 'evc': ..., 'rank': 11}"""
    m = " ".join(str(model or "").split())
    if not m:
        return None
    u = m.upper()
    if "EPYC" in u:
        x = re.search(r"EPYC\s+(\d{4})", u)
        if not x:
            return {"vendor": "amd", "key": "", "name": "EPYC(세대 미상)", "evc": None, "rank": None, "sure": False}
        n = x.group(1)
        k = {"1": "zen1", "2": "zen2", "3": "zen3"}.get(n[3]) if n[0] == "7" else ("zen4" if n[3] == "4" else "zen5" if n[3] == "5" else None) if n[0] in "489" else None
        if not k:
            return {"vendor": "amd", "key": "", "name": f"EPYC {n}", "evc": None, "rank": None, "sure": False}
        nm, e, r = _A[k]
        return {"vendor": "amd", "key": k, "name": nm, "evc": e, "rank": r, "sure": e is not None}
    if "XEON" not in u and "INTEL" not in u:
        return None
    k = None
    v = re.search(r"E5-\d{4}[A-Z]?\s*V(\d)", u) or re.search(r"E7-\d{4}[A-Z]?\s*V(\d)", u)
    if v:
        k = {"2": "ivybridge", "3": "haswell", "4": "broadwell"}.get(v.group(1))
    elif re.search(r"XEON\(?R?\)?\s*6\s*\d{3,4}[PE]\b|XEON\s+6\d{3}[PE]\b", u):
        k = "xeon6"
    else:
        s = re.search(r"(PLATINUM|GOLD|SILVER|BRONZE)\s+(\d)(\d)(\d{2})([A-Z]*)", u)
        if s:
            g = s.group(3)
            if g == "3" and "H" in s.group(5):                       # Cooper Lake(3세대 4소켓) — Cascade Lake 기준선
                k = "cascadelake"
            else:
                k = {"1": "skylake", "2": "cascadelake", "3": "icelake", "4": "sapphirerapids", "5": "emeraldrapids"}.get(g)
        elif re.search(r"MAX\s*94\d\d", u):
            k = "sapphirerapids"
    if not k:
        return {"vendor": "intel", "key": "", "name": "Xeon(세대 미상)", "evc": None, "rank": None, "sure": False}
    nm, e, r = _I[k]
    return {"vendor": "intel", "key": k, "name": nm, "evc": e, "rank": r, "sure": e is not None}


def evc_review(models: list[str], new_model: str, cluster_evc: str = "") -> dict[str, Any]:
    """기존 호스트 CPU 모델들 + 추가할 호스트 모델 → EVC 판단(ok | warn | bad)과 할 일"""
    olds = [g for g in (generation(m) for m in models if m) if g]
    new = generation(new_model) if new_model else None
    out: dict[str, Any] = {"cluster_evc": cluster_evc or "", "existing": sorted({g["name"] for g in olds}), "new": new["name"] if new else "",
                           "verdict": "ok", "needed_evc": "", "items": [], "refs": ["KB 313545", "KB 324991"]}
    if not new:
        out["verdict"] = "unknown"
        out["items"].append("추가할 서버의 CPU 모델을 모릅니다 — 사양에서 CPU 모델을 넣으면 EVC 를 검토합니다.")
        return out
    vendors = {g["vendor"] for g in olds} | {new["vendor"]}
    if len(vendors) > 1:
        out["verdict"] = "bad"
        out["items"].append("Intel 과 AMD 를 한 클러스터에 섞으면 vMotion 이 되지 않습니다(EVC 로도 불가, KB 324991). 별도 클러스터로 구성하세요.")
        return out
    ranks = [g["rank"] for g in olds if g.get("rank") is not None]
    if new.get("rank") is None or not ranks:
        out["verdict"] = "warn"
        out["items"].append(f"CPU 세대를 확정하지 못했습니다({new['name']}) — BCG(Broadcom Compatibility Guide)의 CPU Series 에서 지원 EVC 모드를 확인하세요.")
        return out
    lo = min(ranks + [new["rank"]])
    lo_gen = next(g for g in olds + [new] if g.get("rank") == lo)
    needed = lo_gen.get("evc") or ""
    out["needed_evc"] = needed
    if not new.get("sure"):
        out["items"].append(f"{new['name']} 의 EVC 기준선은 이 표에 없습니다 — BCG 에서 지원 EVC 모드를 확인하세요(KB 318962).")
    if cluster_evc:
        cv, cr = EVC_RANK.get(cluster_evc, (None, None))
        if cv and cv != new["vendor"]:
            out["verdict"] = "bad"
            out["items"].append(f"클러스터 EVC({cluster_evc})와 새 서버의 CPU 회사가 다릅니다 — 넣을 수 없습니다.")
        elif cr is not None and new["rank"] < cr:
            out["verdict"] = "bad"
            out["items"].append(f"새 서버({new['name']})가 클러스터 EVC({cluster_evc})보다 낮은 세대입니다 — 클러스터에 넣으면 EVCAdmissionFailed 로 실패합니다. "
                                "EVC 를 낮추려면 그 기능을 쓰는 VM 의 전원을 껐다 켜야 합니다.")
        else:
            out["items"].append(f"클러스터 EVC {cluster_evc} 를 그대로 씁니다 — 새 서버의 추가 CPU 기능은 VM 에 보이지 않습니다.")
            if new["rank"] > (cr or 0) + 1:
                out["items"].append("새 서버가 EVC 기준보다 두 세대 이상 새것입니다 — 기존 서버를 모두 바꾼 뒤 EVC 를 올려야 새 기능(예: AMX·AVX-512 확장)을 씁니다.")
        return out
    if len(set(ranks + [new["rank"]])) == 1:
        out["items"].append("기존 서버와 같은 세대입니다 — EVC 없이도 vMotion 이 됩니다.")
        return out
    out["verdict"] = "warn"
    if new["rank"] > max(ranks):
        if len(set(ranks)) == 1:
            out["items"].append(f"새 서버를 넣기 전에 클러스터 EVC 를 {needed or lo_gen['name']} 로 켜세요 — 기존 서버가 모두 이 세대라 실행 중인 VM 에 영향이 없습니다.")
        else:
            out["items"].append(f"기존 서버끼리도 세대가 다릅니다 — EVC 를 가장 낮은 {needed or lo_gen['name']} 로 켜야 합니다. "
                                "높은 세대 기능을 이미 쓰는 VM 은 전원을 껐다 켜야 합니다.")
    else:
        out["items"].append(f"새 서버가 기존보다 낮은 세대입니다 — EVC 를 {needed or lo_gen['name']} 로 낮춰야 하고, 기존 서버에서 켜진 VM 은 전원을 껐다 켜야 합니다.")
    if {"icelake", "sapphirerapids"} <= {g["key"] for g in olds + [new]} or {"icelake", "emeraldrapids"} <= {g["key"] for g in olds + [new]}:
        out["items"].append("Ice Lake 와 Sapphire/Emerald Rapids 를 섞을 때 HW 버전 21 VM 의 이동 제약이 알려져 있습니다(KB 438859).")
        out["refs"].append("KB 438859")
    if needed == "intel-sapphirerapids":
        out["items"].append("Sapphire Rapids EVC 는 vCenter 8.0 U1 이상에서만 고를 수 있습니다(KB 405881).")
        out["refs"].append("KB 405881")
    return out
