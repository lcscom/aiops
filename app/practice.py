"""실무 도우미(2.44.0) — 비용 절감 찾기 · AI 변경 사전 검토. 모두 읽기 전용 계산.

비용 절감 찾기(보안·비용 › 비용·라이선스 › 비용 절감)
  흩어져 있던 근거(VM 적정화·장기 꺼짐 VM·스냅숏·외장 스토리지→ESA·라이선스 보유분)를 '돈이 되는 순서'로 한 장에.
  · 호스트 줄이기   클러스터 p95 사용량(최근 14일 표본)에서 적정화로 돌려받는 메모리를 뺀 뒤, 80% 목표 + N+1(vSAN 최소 3대)로 필요한 호스트 수
                    → 줄일 수 있는 호스트 × (VCF 코어 라이선스 + 전력 + 하드웨어 유지보수)
  · 장기 꺼진 VM     디스크 합계 × 스토리지 TB 단가
  · 외장 스토리지   ESA 전환 산정 결과 — 외장 스토리지 유지비 − (vSAN 추가 TiB + NVMe 감가)
  · 라이선스 여유   보유 VCF 코어 − 필요 코어(호스트 줄인 뒤)
  · 스냅숏          72시간 넘은 스냅숏 수(크기는 수집하지 않아 금액 없음)
  단가는 모두 사용자가 넣는 값 — 넣지 않으면 수량만 보여 주고 금액은 비움(가격을 지어내지 않음).
  AI 가 있으면 '갱신 협상·경영진 보고용 한 장 요약'을 쓴다(이름 가명화).

AI 변경 사전 검토(인프라·워크로드 › 점검·진단 › 변경 사전 검토)
  작업 계획을 한국어로 적으면(예: "11/20 02시 esx05 BIOS 업데이트 후 재부팅, esx06 도 순차 진행")
  · 대상·작업 해석   인벤토리 이름(호스트·클러스터·데이터스토어·vCenter·스위치·방화벽·스토리지)과 작업 낱말로 규칙 해석 + (선택) AI 해석 → 인벤토리로 검증
  · 영향            장애 시뮬레이터 계산 — 같은 클러스터 호스트 여러 대의 유지보수는 '순차(한 대씩)'로 가장 나쁜 경우
  · 사전 점검       vCenter 백업 · 30일 안 만료 인증서 · 최근 7일 구성 변경 · 열린 인시던트 · 체크봇 실패 시나리오 · 대상의 취약점(패치로 해소 가능) · 지원 종료
  · 권장 시간대      최근 28일 같은 요일·시각의 클러스터 CPU·메모리 사용률로 부하가 가장 낮은 3시간
  · 작업 절차서     사전·작업·사후·되돌리기 체크리스트(변경 티켓에 붙여 넣는 마크다운)
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import math
import re
import time
from typing import Any

from . import simulator as SIM
from .checkbot import build_world

PRICE_KEYS = {"vcf_core_year": "VCF 코어당 연 구독료", "hw_host_year": "호스트당 연 하드웨어 유지보수", "kwh": "전기 단가(kWh)", "host_watt": "호스트 평균 소비전력(W)",
              "pue": "PUE", "storage_tb_year": "스토리지 TB당 연 비용(외장)", "vsan_tib_year": "vSAN 추가 TiB 연 구독료", "nvme_price": "NVMe 1개 가격",
              "nvme_years": "NVMe 감가 기간(년)", "owned_cores": "보유 VCF 코어 수", "currency": "통화"}
DEFAULT_PRICES = {"vcf_core_year": "", "hw_host_year": "", "kwh": "", "host_watt": 600, "pue": 1.5, "storage_tb_year": "", "vsan_tib_year": "", "nvme_price": "",
                  "nvme_years": 5, "owned_cores": "", "currency": "원"}
SCHEMA = "CREATE TABLE IF NOT EXISTS practice_kv(k TEXT PRIMARY KEY, v TEXT)"


def _n(v) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ 비용 절감 — 순수 계산
def hosts_needed(cpu_need: float, mem_need: float, host_cpu: float, host_mem: float, vsan: bool, target: float = 0.8) -> int:
    n = max(math.ceil(cpu_need / (host_cpu * target)) if host_cpu else 0, math.ceil(mem_need / (host_mem * target)) if host_mem else 0) + 1
    return max(n, 3 if vsan else 2)


def consolidation(world: dict, p95: dict, rs_clusters: list[dict]) -> list[dict]:
    """클러스터별 줄일 수 있는 호스트(추정) — p95 사용량 − 적정화 회수 메모리(70% 반영)"""
    rsc = {c["cluster"]: c for c in rs_clusters}
    out = []
    for vc in world["vcenters"]:
        T = vc["topo"]
        H = T.get("hosts") or {}
        for cn, c in (T.get("clusters") or {}).items():
            hs = [H[h] for h in c.get("hosts", []) if h in H and not H[h].get("maintenance")]
            if len(hs) < 2:
                continue
            hc = sum(float(h.get("cpu_mhz") or 0) for h in hs) / len(hs)
            hm = sum(float(h.get("mem_mb") or 0) for h in hs) / len(hs)
            pk = p95.get((vc["name"], cn)) or {}
            cpu = pk.get("cpu") if pk.get("cpu") is not None else sum(float(h.get("cpu_used_mhz") or 0) for h in hs)
            mem = pk.get("mem") if pk.get("mem") is not None else sum(float(h.get("mem_used_mb") or 0) for h in hs)
            r = rsc.get(cn) or {}
            back = float(r.get("reclaim_mem_gb") or 0) * 1024 * 0.7
            mem_after = max(mem - back, mem * 0.5)
            need = hosts_needed(cpu, mem_after, hc, hm, bool(c.get("vsan")))
            cores = [int(h.get("cores") or 0) or int(round(float(h.get("cpu_mhz") or 0) / float(h.get("core_mhz") or 1))) for h in hs]
            from .esa import lic_cores
            lic = sum(lic_cores(co, int(h.get("sockets") or 2)) for co, h in zip(cores, hs)) / len(hs)
            out.append({"vcenter": vc["name"], "cluster": cn, "hosts": len(hs), "needed": need, "removable": max(0, len(hs) - need), "vsan": bool(c.get("vsan")),
                        "cpu_pct_now": round(cpu / (hc * len(hs)) * 100, 1) if hc else None, "mem_pct_now": round(mem / (hm * len(hs)) * 100, 1) if hm else None,
                        "mem_back_gb": round(back / 1024, 1), "lic_cores_per_host": round(lic), "basis": "p95(14일)" if pk else "현재값"})
    return sorted(out, key=lambda x: -x["removable"])


def money(x: float | None, cur: str) -> str:
    if x is None:
        return "—"
    return f"{x:,.0f} {cur}"


def opportunities(cons: list[dict], rs: dict, snaps: dict, esa: dict | None, prices: dict, total_hosts_cores: int) -> dict[str, Any]:
    P = {k: _n(prices.get(k)) for k in PRICE_KEYS if k != "currency"}
    cur = prices.get("currency") or "원"
    ops = []
    # 1) 호스트 줄이기
    rem = [c for c in cons if c["removable"] > 0]
    nrem = sum(c["removable"] for c in rem)
    cores_rem = sum(c["removable"] * c["lic_cores_per_host"] for c in rem)
    kwh_year = (P["host_watt"] or 600) * 24 * 365 * (P["pue"] or 1.5) / 1000
    parts = []
    lic = cores_rem * P["vcf_core_year"] if P["vcf_core_year"] is not None else None
    pw = nrem * kwh_year * P["kwh"] if P["kwh"] is not None else None
    hw = nrem * P["hw_host_year"] if P["hw_host_year"] is not None else None
    amt = sum(x for x in (lic, pw, hw) if x is not None) if any(x is not None for x in (lic, pw, hw)) else None
    if lic is not None:
        parts.append(f"라이선스 {money(lic, cur)}")
    if pw is not None:
        parts.append(f"전력 {money(pw, cur)}")
    if hw is not None:
        parts.append(f"HW 유지보수 {money(hw, cur)}")
    ops.append({"id": "hosts", "title": "VM 적정화 후 호스트 줄이기", "qty": f"호스트 {nrem}대 · VCF 코어 {cores_rem}개 · 전력 {nrem * kwh_year:,.0f} kWh/년",
                "amount": amt, "breakdown": parts, "risk": "중간", "effort": "중간",
                "why": "; ".join(f"{c['cluster']} {c['hosts']}→{c['needed']}대(p95 CPU {c['cpu_pct_now']}% · 메모리 {c['mem_pct_now']}%, 회수 {c['mem_back_gb']} GB)" for c in rem[:6])
                or "모든 클러스터가 N+1·80% 목표에서 줄일 여유가 없습니다",
                "how": "VM 적정화 탭의 과다·유휴 VM 을 먼저 정리 → 가정 분석에서 호스트 제거를 확인 → 유지보수 모드로 비우고 라이선스 재할당", "detail": rem})
    # 2) 장기 꺼진 VM
    S = (rs or {}).get("summary") or {}
    off_tb = float(S.get("reclaim_disk_gb") or 0) / 1000
    ops.append({"id": "poweroff", "title": f"{(rs or {}).get('thresholds', {}).get('off_days', 7)}일 넘게 꺼진 VM 정리", "qty": f"VM {S.get('powered_off', 0)}대 · 디스크 {off_tb:,.1f} TB",
                "amount": off_tb * P["storage_tb_year"] if P["storage_tb_year"] is not None else None, "breakdown": [], "risk": "낮음", "effort": "낮음",
                "why": "켜지지 않는 VM 의 디스크가 스토리지를 차지", "how": "담당자 확인 → 보관이 필요하면 백업·OVF 로 내보낸 뒤 삭제"})
    # 3) 유휴 VM(메모리·vCPU)
    ops.append({"id": "idle", "title": "유휴·과다 할당 VM 줄이기", "qty": f"vCPU {S.get('reclaim_vcpu', 0)} · 메모리 {S.get('reclaim_mem_gb', 0)} GB 회수"
                + (f" · 정산 기준 월 {money(S.get('saving_month'), cur)}" if S.get("saving_month") else ""),
                "amount": None, "breakdown": [], "risk": "낮음", "effort": "중간", "why": "호스트 줄이기의 전제(위 1번 금액에 포함)",
                "how": "VM 적정화 탭 권장값으로 다음 작업 창에 축소"})
    # 4) 외장 스토리지 → ESA
    if esa and not esa.get("error"):
        ext_tb = esa.get("now_tb") or 0
        b = (esa.get("existing") or [{}])[0] if esa.get("existing") else {}
        addon = (b.get("addon_tib") if b.get("possible") else (esa.get("new_cluster") or {}).get("addon_tib")) or 0
        drives = (b.get("drives_per_host", 0) * b.get("hosts", 0)) if b.get("possible") else 0
        keep = ext_tb * P["storage_tb_year"] if P["storage_tb_year"] is not None else None
        cost = (addon * P["vsan_tib_year"] if P["vsan_tib_year"] is not None else 0) + ((drives * P["nvme_price"] / (P["nvme_years"] or 5)) if P["nvme_price"] is not None else 0)
        amt4 = keep - cost if keep is not None else None
        ops.append({"id": "esa", "title": "외장 스토리지를 vSAN ESA 로(VCF 포함 vSAN 활용)", "qty": f"외장 {ext_tb:,.1f} TB → vSAN 추가 {addon} TiB" + (f" · NVMe {drives}개({b.get('name')})" if drives else ""),
                    "amount": amt4, "breakdown": [f"외장 유지비 {money(keep, cur)}", f"vSAN 추가·NVMe 감가 {money(cost, cur)}"] if keep is not None else [],
                    "risk": "중간", "effort": "높음", "why": "VCF 에는 라이선스 코어당 vSAN 1 TiB 가 포함 — 쓰지 않으면 낭비",
                    "how": "vSAN ESA 전환 탭에서 대상·정책 확정 → Storage vMotion 으로 단계 이전 → 어레이 유지보수 계약 종료 시점과 맞춤"})
    # 5) 라이선스 여유
    owned = P["owned_cores"]
    if owned is not None:
        need = total_hosts_cores - cores_rem
        extra = owned - need
        ops.append({"id": "license", "title": "갱신 때 VCF 코어 수 맞추기", "qty": f"보유 {owned:,.0f} · 필요 {need:,} (호스트 줄인 뒤) → {'여유 ' if extra >= 0 else '부족 '}{abs(extra):,.0f} 코어",
                    "amount": extra * P["vcf_core_year"] if P["vcf_core_year"] is not None and extra > 0 else None, "breakdown": [], "risk": "낮음", "effort": "낮음",
                    "why": "필요 코어 = 호스트별 max(16, 코어/CPU) × CPU 수 합계", "how": "갱신 견적에 필요 코어를 반영(부족하면 컴플라이언스 위험)"})
    # 6) 스냅숏
    ops.append({"id": "snap", "title": "72시간 넘은 스냅숏 정리", "qty": f"스냅숏 {snaps.get('over72', 0)}개 · 남은 작업 스냅숏 {snaps.get('leftover', 0)}개 · 통합 필요 VM {snaps.get('consolidate', 0)}",
                "amount": None, "breakdown": [], "risk": "낮음", "effort": "낮음", "why": "델타 디스크가 계속 커져 용량·성능을 먹음(크기는 수집하지 않아 금액 없음)",
                "how": "DR·보호 › 스냅숏에서 대상 확인 후 삭제·통합"})
    total = sum(o["amount"] for o in ops if o["amount"] and o["amount"] > 0)
    ops.sort(key=lambda o: -(o["amount"] or 0))
    return {"ops": ops, "total_year": total if any(o["amount"] for o in ops) else None, "currency": cur,
            "priced": {k: P[k] is not None for k in ("vcf_core_year", "kwh", "hw_host_year", "storage_tb_year", "vsan_tib_year", "nvme_price", "owned_cores")}}


# ------------------------------------------------------------------ 변경 사전 검토 — 해석
DOWN_W = ("교체", "제거", "폐기", "철거", "전원 차단", "전원차단", "power off", "poweroff", "shutdown", "셧다운", "이전", "반출")
MAINT_W = ("재부팅", "리부팅", "reboot", "패치", "업데이트", "업그레이드", "upgrade", "펌웨어", "firmware", "bios", "드라이버", "유지보수", "점검", "증설", "메모리 추가")
SEQ_W = ("순차", "한 대씩", "한대씩", "롤링", "rolling", "차례로")


def candidates(world: dict) -> list[dict]:
    out = []
    for vc in world["vcenters"]:
        T = vc["topo"]
        out.append({"kind": "vcenter", "name": vc["name"], "alias": [vc.get("host") or "", "vcenter", "vcsa"], "vcenter": vc["name"], "target": vc.get("host") or vc["name"]})
        for cn in T.get("clusters") or {}:
            out.append({"kind": "cluster", "name": cn, "alias": [], "vcenter": vc["name"], "target": cn})
        for hn in T.get("hosts") or {}:
            out.append({"kind": "host", "name": hn, "alias": [hn.split(".")[0]], "vcenter": vc["name"], "target": hn})
        for dn, d in (T.get("datastores") or {}).items():
            if d.get("capacity_gb") and d.get("local") is not True:
                out.append({"kind": "datastore", "name": dn, "alias": [], "vcenter": vc["name"], "target": dn})
    ph = world.get("phys") or {}
    for n in ph.get("switches") or {}:
        out.append({"kind": "switch", "name": n, "alias": [n.split(".")[0]], "vcenter": "", "target": n})
    for n, d in (ph.get("devices") or {}).items():
        out.append({"kind": "device", "name": n, "alias": [n.split(".")[0]], "vcenter": "", "target": n})
    for n in ph.get("storage") or {}:
        out.append({"kind": "storage", "name": n, "alias": [], "vcenter": "", "target": n})
    return out


def _found(text: str, c: dict) -> int:
    low = text.lower()
    best = -1
    for nm in [c["name"]] + [a for a in c["alias"] if a and len(a) >= 3]:
        for mm in re.finditer(re.escape(nm.lower()), low):                 # 앞뒤가 글자·숫자면 다른 이름의 일부(h1 ↔ h10, esx0 ↔ esx05)
            i, j = mm.start(), mm.end()
            if (i > 0 and (low[i - 1].isascii() and low[i - 1].isalnum() or low[i - 1] in "-_")) or \
                    (j < len(low) and (low[j].isascii() and low[j].isalnum() or low[j] in "-_")):
                continue
            best = i if best < 0 else min(best, i)
            break
    return best


def parse_change(text: str, world: dict) -> dict[str, Any]:
    low = text.lower()
    down = any(w in low for w in DOWN_W)
    seq = any(w in low for w in SEQ_W)
    hits = []
    multi_vc = len(world["vcenters"]) > 1
    for c in candidates(world):
        if c["kind"] == "vcenter" and multi_vc:                          # vCenter 가 여럿이면 일반 낱말(vcenter·vcsa)로는 고르지 않음
            c = {**c, "alias": [a for a in c["alias"] if a not in ("vcenter", "vcsa")]}
        if _found(text, c) >= 0:
            hits.append(c)
    # 더 긴 이름이 잡히면 그 안의 짧은 이름(클러스터 이름이 호스트 이름의 일부 등)은 버림
    names = [h["name"].lower() for h in hits]
    hits = [h for h in hits if not any(h["name"].lower() != o and h["name"].lower() in o for o in names)]
    F = []
    for c in hits:
        k = c["kind"]
        t = {"host": "host_down" if down else "host_maint", "cluster": "cluster_down" if down else "host_maint", "datastore": "ds_apd", "vcenter": "vcenter_upgrade",
             "switch": "switch_down", "device": "device_down", "storage": "storage_down"}[k]
        F.append({"type": t, "vcenter": c["vcenter"], "target": c["target"], "kind": k, "name": c["name"], "src": "규칙"})
    hosts_m = [f for f in F if f["type"] == "host_maint" and f["kind"] == "host"]
    mode = "sequential" if (seq or len(hosts_m) >= 2) and len(hosts_m) >= 2 else "simultaneous"
    hint = ""
    if multi_vc and re.search(r"vcenter|vcsa|브이센터", low) and not any(f["kind"] == "vcenter" for f in F):
        hint = "vCenter 가 여러 개입니다 — 어느 vCenter 인지 이름(예: " + ", ".join(v["name"] for v in world["vcenters"][:3]) + ")을 적어 주세요"
    return {"failures": F, "mode": mode, "action": "제거·전원 차단" if down else "유지보수·패치·재부팅", "when": parse_when(text), "hint": hint}


def parse_when(text: str, now: dt.datetime | None = None) -> dict | None:
    now = now or dt.datetime.now()
    m = re.search(r"(20\d\d)[-./](\d{1,2})[-./](\d{1,2})", text) or re.search(r"(?<!\d)(\d{1,2})\s*[/월.]\s*(\d{1,2})\s*일?", text)
    d = None
    if m:
        try:
            g = m.groups()
            d = dt.date(int(g[0]), int(g[1]), int(g[2])) if len(g) == 3 else dt.date(now.year, int(g[0]), int(g[1]))
            if len(g) == 2 and d < now.date() - dt.timedelta(days=30):
                d = dt.date(now.year + 1, d.month, d.day)
        except ValueError:
            d = None
    if not d:                                                            # '다음주 토요일', '이번 주 수요일', '내일', '모레'
        wm = re.search(r"(다음\s*주|이번\s*주|차주|금주)?\s*([월화수목금토일])요일", text)
        if wm:
            wd = "월화수목금토일".index(wm.group(2))
            base = now.date()
            if wm.group(1) and wm.group(1).replace(" ", "") in ("다음주", "차주"):
                base = base + dt.timedelta(days=7 - base.weekday())       # 다음 주 월요일
                d = base + dt.timedelta(days=wd)
            else:
                ahead = (wd - base.weekday()) % 7
                d = base + dt.timedelta(days=ahead)
        elif "모레" in text:
            d = now.date() + dt.timedelta(days=2)
        elif "내일" in text:
            d = now.date() + dt.timedelta(days=1)
    rest = text[m.end():] if m else text
    t = re.search(r"(새벽|오전|오후|밤)?\s*(\d{1,2})\s*(?:시|:)\s*(\d{1,2})?", rest)
    if not (d or t):
        return None
    hh, mm = (int(t.group(2)), int(t.group(3) or 0)) if t else (2, 0)
    if t and t.group(1) in ("오후", "밤") and hh < 12:
        hh += 12
    if hh > 23 or mm > 59:
        return None
    if not d:
        d = now.date() + dt.timedelta(days=0 if (hh, mm) > (now.hour, now.minute) else 1)
    w = dt.datetime(d.year, d.month, d.day, hh, mm)
    return {"iso": w.isoformat(timespec="minutes"), "weekday": w.weekday(), "hour": w.hour, "ts": w.timestamp()}


def windows(rows: list[tuple], hours: int = 3, now: dt.datetime | None = None) -> dict[str, Any]:
    """rows = (hour_ts, cpu%, mem%) — (요일, 시)별 평균 → 다음 7일에서 연속 hours 시간 평균이 가장 낮은 시작 시각 3개"""
    now = now or dt.datetime.now()
    agg: dict[tuple, list] = {}
    for ts, cpu, mem in rows:
        t = dt.datetime.fromtimestamp(ts)
        agg.setdefault((t.weekday(), t.hour), []).append(max(cpu, mem))
    if not agg:
        return {"best": [], "grid": {}, "days": 0}
    avg = {k: sum(v) / len(v) for k, v in agg.items()}
    days = len({dt.datetime.fromtimestamp(r[0]).date() for r in rows})
    start = (now + dt.timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    cands = []
    for i in range(0, 24 * 7):
        s = start + dt.timedelta(hours=i)
        vals = [avg.get(((s + dt.timedelta(hours=k)).weekday(), (s + dt.timedelta(hours=k)).hour)) for k in range(hours)]
        if any(v is None for v in vals):
            continue
        cands.append((sum(vals) / hours, max(vals), s))
    cands.sort(key=lambda x: (x[0], x[2]))
    best, used = [], []
    for a, mx, s in cands:
        if any(abs((s - u).total_seconds()) < 6 * 3600 for u in used):
            continue
        used.append(s)
        best.append({"start": s.isoformat(timespec="minutes"), "weekday": s.weekday(), "hour": s.hour, "avg_pct": round(a, 1), "max_pct": round(mx, 1)})
        if len(best) == 3:
            break
    return {"best": best, "grid": {f"{k[0]}-{k[1]}": round(v, 1) for k, v in avg.items()}, "days": days}


MOP = {
    "host_maint": (["대상 호스트 VM 목록·vMotion 불가 VM 확인(이 결과의 '위험' 칸)", "DRS 완전 자동 확인, 필요하면 VM-호스트 규칙 일시 조정", "vSAN: 데이터 이동 모드(접근성 보장/전체 이동) 결정"],
                   ["유지보수 모드 진입 → VM 이동 완료 확인", "작업(패치·펌웨어·재부팅) 진행", "호스트 연결·하드웨어 상태·vmnic 링크 확인 후 유지보수 모드 해제"],
                   ["DRS 재배치·HA 상태 정상, vSAN 재동기화 완료 확인", "이 포털: 인프라 점검·구성 드리프트에서 의도한 변경만 생겼는지 확인"],
                   ["패치 실패 시 vLCM 이전 이미지로 되돌리기 또는 부트 뱅크 전환(Shift+R)", "펌웨어 실패 시 BMC 에서 이전 펌웨어"]),
    "host_down": (["대상 호스트 VM 을 다른 호스트로 옮길 계획", "HA 승인 제어·남은 용량 확인(이 결과의 용량 판정)"], ["유지보수 모드로 비운 뒤 전원 차단·제거"],
                  ["클러스터 HA·DRS·vSAN 상태 확인", "라이선스·모니터링 대상에서 정리"], ["되돌리기: 호스트 다시 연결·클러스터 재가입"]),
    "vcenter_upgrade": (["vCenter 파일 기반 백업 + 스냅숏", "Interoperability Matrix(ESXi·NSX·VKS·백업 SW) 확인", "백업 창·자동화 작업 피하기"],
                        ["업그레이드 진행(작업 중 DRS·vMotion·프로비저닝 멈춤)"], ["서비스·플러그인·연동 솔루션 연결 확인", "이 포털 수집 현황에서 vCenter 커넥터 재연결 확인"],
                        ["실패 시 스냅숏 또는 파일 기반 백업으로 복원"]),
    "switch_down": (["업링크 이중화(MLAG/vPC 양쪽)와 지금 내려가 있는 vmnic 확인(이 결과의 단일 장애점)", "NSX BGP 세션 이중화 확인"],
                    ["한 대씩 작업, 상대 스위치로 트래픽이 넘어간 것 확인 후 진행"], ["LLDP 이웃·포트 상태·BGP 재수립 확인"], ["이전 이미지로 부팅"]),
    "device_down": (["HA 쌍 상태·세션 동기화 확인"], ["대기 장비부터 작업 후 전환"], ["정책·세션·VPN 정상 확인"], ["이전 펌웨어·설정 백업 복원"]),
    "storage_down": (["컨트롤러 이중화·경로(MPIO) 상태 확인 — 이 결과는 데이터스토어 전체 APD 최악 가정", "중요 VM 백업 최신화"],
                     ["컨트롤러 순차 작업, 경로 장애 조치 확인"], ["ESXi 경로 상태(dead path 없음)·지연 확인"], ["제조사 절차에 따른 이전 펌웨어"]),
    "ds_apd": (["데이터스토어의 VM 목록·이전 계획"], ["Storage vMotion 으로 비운 뒤 작업"], ["마운트·경로 확인"], ["원래 데이터스토어로 다시 이동"]),
    "cluster_down": (["클러스터 전체 VM 의 이전·종료 계획, DR(SRM) 보호 확인"], ["VM 종료 → 호스트 종료"], ["전원 복구 후 vSAN·HA·VM 기동 순서 확인"], ["DR 사이트 전환 절차"]),
}


def mop(types: set[str]) -> dict[str, list[str]]:
    out = {"사전": [], "작업": [], "사후": [], "되돌리기": []}
    for t in ["vcenter_upgrade", "switch_down", "device_down", "storage_down", "ds_apd", "cluster_down", "host_maint", "host_down"]:
        if t in types:
            a, b, c, d = MOP[t]
            for k, v in zip(out, (a, b, c, d)):
                out[k] += [x for x in v if x not in out[k]]
    return out


def to_markdown(r: dict) -> str:
    L = [f"# 변경 사전 검토 — {r['verdict']['label']}", "", f"- 계획: {r['text']}", "- 해석: " + (", ".join(f["label"] for f in r["failures"]) or "대상 없음") + (" (한 대씩 순차)" if r.get("mode") == "sequential" else "")]
    if r.get("when"):
        L.append(f"- 예정: {r['when']['iso']} (그 시각 평균 부하 {r['when'].get('load', '—')}%)")
    if r.get("window", {}).get("best"):
        L.append("- 권장 시간대: " + ", ".join(f"{b['start']} (평균 {b['avg_pct']}%)" for b in r["window"]["best"]))
    L += ["", "## 영향", f"- 서비스 중단 VM {r['impact']['stop']} · 위험 {r['impact']['risk']} · 재부팅 {r['impact']['boot']} · 무중단 이동 {r['impact']['move']}"]
    L += [f"- [{x['sev']}] {x['text']}" for x in r["impact"]["top"]]
    L += ["", "## 사전 점검"] + [f"- [{'통과' if c['state'] == 'ok' else '주의' if c['state'] == 'warn' else '실패'}] {c['name']} — {c['detail']}" for c in r["checks"]]
    for k, v in r["mop"].items():
        L += ["", f"## {k}"] + [f"- [ ] {x}" for x in v]
    if r.get("ai"):
        L += ["", "## AI 검토", r["ai"]]
    L += ["", "_VCF AIops 변경 사전 검토 — 읽기 전용 계산. 실제 인프라에는 아무것도 하지 않았습니다._"]
    return "\n".join(L)


# ------------------------------------------------------------------ 엔진 연결
class Practice:
    def __init__(self, engine):
        self.e = engine
        self._ready = False

    async def ensure(self):
        if not self._ready:
            await self.e.store.x(SCHEMA)
            self._ready = True

    async def prices(self) -> dict:
        await self.ensure()
        r = await self.e.store.q1("SELECT v FROM practice_kv WHERE k='prices'")
        p = dict(DEFAULT_PRICES)
        if r:
            try:
                p.update(json.loads(r["v"]))
            except ValueError:
                pass
        return p

    async def set_prices(self, body: dict) -> dict:
        p = await self.prices()
        for k in PRICE_KEYS:
            if k in body:
                v = body[k]
                if k == "currency":
                    p[k] = str(v or "원")[:8]
                else:
                    f = _n(v)
                    if f is not None and (f < 0 or f > 1e12):
                        raise ValueError(f"{PRICE_KEYS[k]} 값이 범위를 벗어났습니다")
                    p[k] = "" if f is None else f
        await self.e.store.x("INSERT OR REPLACE INTO practice_kv(k, v) VALUES('prices', ?)", (json.dumps(p),))
        return p

    async def _p95(self, days: int = 14) -> dict:
        try:
            rows = await self.e.store.q("SELECT vc, name, cpu_used/n AS c, mem_used/n AS m FROM cap_usage WHERE kind='cluster' AND hour>=? AND n>0", (time.time() - days * 86400,))
        except Exception:  # noqa: BLE001
            return {}
        by: dict[tuple, list] = {}
        for r in rows:
            by.setdefault((r["vc"], r["name"]), []).append((r["c"], r["m"]))
        out = {}
        for k, v in by.items():
            if len(v) < 24:
                continue
            cs, ms = sorted(x[0] for x in v), sorted(x[1] for x in v)
            out[k] = {"cpu": cs[int(len(cs) * 0.95) - 1], "mem": ms[int(len(ms) * 0.95) - 1]}
        return out

    async def savings(self, ai: bool = False) -> dict[str, Any]:
        world = await asyncio.to_thread(build_world, self.e)
        prices = await self.prices()
        try:
            rs = await self.e.capacity.rightsizing()
        except Exception:  # noqa: BLE001
            rs = {}
        cons = consolidation(world, await self._p95(), (rs or {}).get("clusters") or [])
        try:
            from . import protection as PR
            snaps = PR.build(getattr(self.e, "connectors", [])).get("summary", {}).get("snapshots") or {}
        except Exception:  # noqa: BLE001
            snaps = {}
        esa = None
        try:
            from . import esa as ESA
            items = (await self.e.capacity.overview()).get("items", [])
            esa = ESA.size(ESA.sources(self.e, items), {})
        except Exception:  # noqa: BLE001
            esa = None
        from .esa import lic_cores
        cores = 0
        for vc in world["vcenters"]:
            for h in (vc["topo"].get("hosts") or {}).values():
                co = int(h.get("cores") or 0) or int(round(float(h.get("cpu_mhz") or 0) / float(h.get("core_mhz") or 1)))
                cores += lic_cores(co, int(h.get("sockets") or 2))
        res = opportunities(cons, rs, snaps, esa, prices, cores)
        res.update(prices=prices, labels=PRICE_KEYS, clusters=cons, total_cores=cores, generated=time.time())
        if ai:
            res["ai"] = await self._ai_savings(res, world)
        return res

    async def _llm_ok(self) -> bool:
        llm = getattr(self.e, "llm", None)
        try:
            return bool(llm and llm.order("report"))
        except Exception:  # noqa: BLE001
            return False

    async def _ai_savings(self, res: dict, world: dict) -> dict:
        if not await self._llm_ok():
            return {"error": "AI 공급자가 설정되지 않았습니다"}
        names = [vc["name"] for vc in world["vcenters"]] + [c["cluster"] for c in res["clusters"]]
        payload = {"currency": res["currency"], "total_year": res["total_year"], "ops": [{k: o[k] for k in ("title", "qty", "amount", "risk", "effort", "why")} for o in res["ops"]]}
        sys_ = ("너는 VMware VCF 를 쓰는 금융권 고객의 인프라 비용 담당 컨설턴트다. 주어진 절감 기회(JSON)만 근거로 한국어로 쓴다.\n"
                "형식: **한 줄 결론** — 연간 절감 가능액과 가장 큰 항목. **우선순위** — 번호 목록 3~5개(금액·위험·노력, 먼저 할 것부터). "
                "**갱신·협상 포인트** — 2~3줄. **주의** — 1~2줄(추정 근거·단가 미입력 항목). 결과에 없는 숫자는 만들지 않는다.")
        try:
            txt = await asyncio.wait_for(self.e.llm.complete(sys_, json.dumps(payload, ensure_ascii=False), max_tokens=1200, task="report", names=names), 120)
            return {"text": txt}
        except Exception as ex:  # noqa: BLE001
            return {"error": f"AI 요약 실패: {type(ex).__name__}"}

    # ---------------------------------------------------------------- 변경 사전 검토
    async def _ai_parse(self, text: str, world: dict) -> list[dict]:
        if not await self._llm_ok():
            return []
        cands = candidates(world)
        names = [c["name"] for c in cands]
        sys_ = ("너는 VMware 변경 관리 담당이다. 작업 계획 문장에서 영향받는 대상과 작업 유형을 뽑아 JSON 배열만 출력한다.\n"
                "원소: {\"name\": 후보 목록에 있는 이름 그대로, \"action\": \"maint\"(재부팅·패치·펌웨어·유지보수) | \"down\"(제거·전원 차단·교체) | \"upgrade\"(vCenter 업그레이드)}. 후보에 없는 이름 금지.")
        user = json.dumps({"계획": text, "후보": [{"name": c["name"], "kind": c["kind"]} for c in cands[:400]]}, ensure_ascii=False)
        try:
            txt = await asyncio.wait_for(self.e.llm.complete(sys_, user, max_tokens=600, task="report", names=names), 25)
        except Exception:  # noqa: BLE001
            return []
        m = re.search(r"\[.*\]", txt or "", re.S)
        try:
            arr = json.loads(m.group(0)) if m else []
        except ValueError:
            return []
        by = {c["name"]: c for c in cands}
        out = []
        for x in arr[:20] if isinstance(arr, list) else []:
            c = by.get(str((x or {}).get("name", "")))
            if not c:
                continue
            a = str(x.get("action", "maint"))
            t = {"host": "host_down" if a == "down" else "host_maint", "cluster": "cluster_down" if a == "down" else "host_maint", "datastore": "ds_apd",
                 "vcenter": "vcenter_upgrade", "switch": "switch_down", "device": "device_down", "storage": "storage_down"}[c["kind"]]
            out.append({"type": t, "vcenter": c["vcenter"], "target": c["target"], "kind": c["kind"], "name": c["name"], "src": "AI"})
        return out

    async def _load_rows(self, clusters: set[tuple], days: int = 28) -> list[tuple]:
        if not clusters:
            return []
        try:
            rows = await self.e.store.q("SELECT hour, vc, name, cpu_used, cpu_total, mem_used, mem_total FROM cap_usage WHERE kind='cluster' AND hour>=?",
                                        (time.time() - days * 86400,))
        except Exception:  # noqa: BLE001
            return []
        by: dict[int, list] = {}
        for r in rows:
            if (r["vc"], r["name"]) in clusters and r["cpu_total"] and r["mem_total"]:
                by.setdefault(r["hour"], []).append((r["cpu_used"] / r["cpu_total"] * 100, r["mem_used"] / r["mem_total"] * 100))
        return [(h, max(x[0] for x in v), max(x[1] for x in v)) for h, v in sorted(by.items())]

    async def review(self, text: str, use_ai: bool = True, overrides: list[dict] | None = None) -> dict[str, Any]:
        text = " ".join(str(text or "").split())[:2000]
        world = await asyncio.to_thread(build_world, self.e)
        p = parse_change(text, world)
        F = p["failures"]
        ai_used = False
        if use_ai and not overrides:
            extra = await self._ai_parse(text, world)
            have = {(f["type"], f["target"]) for f in F}
            for x in extra:
                if (x["type"], x["target"]) not in have:
                    F.append(x)
                    ai_used = True
        if overrides is not None:
            F = [f for f in overrides if isinstance(f, dict) and f.get("type") and f.get("target")]
        labels = {"host_maint": "유지보수", "host_down": "제거·전원 차단", "cluster_down": "클러스터 중단", "ds_apd": "데이터스토어 중단", "vcenter_upgrade": "vCenter 업그레이드",
                  "switch_down": "스위치 작업", "device_down": "방화벽·라우터 작업", "storage_down": "스토리지 작업"}
        for f in F:
            f["label"] = f"{labels.get(f['type'], f['type'])} · {f.get('name') or f['target']}"
        # 영향 — 순차면 한 대씩 계산해 가장 나쁜 경우, 아니면 한꺼번에
        if p["mode"] == "sequential" and not overrides:
            seqs = [f for f in F if f["type"] == "host_maint"]
            rest = [f for f in F if f["type"] != "host_maint"]
            sims = [SIM.simulate(world, [s] + rest) for s in seqs]
            sim = max(sims, key=lambda r: (r["counts"].get("down", 0) + r["counts"].get("io", 0) + r["counts"].get("net", 0), len(r["findings"]))) if sims else SIM.simulate(world, rest)
        else:
            sim = SIM.simulate(world, F)
        c = sim.get("counts") or {}
        impact = {"stop": sum(c.get(k, 0) for k in ("down", "io", "net", "ext")), "risk": c.get("maybe", 0) + c.get("blocked", 0), "boot": c.get("restart", 0), "move": c.get("vmotion", 0),
                  "top": [{"sev": {"fail": "실패", "warn": "주의", "pass": "통과"}[x["sev"]], "text": x["text"]} for x in sim.get("findings", []) if x["sev"] != "pass"][:8],
                  "services": sim.get("services", [])[:20], "vms": sim.get("vms", [])[:300], "verdict": sim.get("verdict")}
        checks = await self._checks(F, world, p["action"])
        clusters = set()
        for f in F:
            vc = next((v for v in world["vcenters"] if v["name"] == f.get("vcenter")), None)
            if not vc:
                continue
            if f["kind"] == "cluster":
                clusters.add((vc["name"], f["target"]))
            elif f["kind"] == "host":
                clusters.add((vc["name"], (vc["topo"].get("hosts") or {}).get(f["target"], {}).get("cluster", "")))
            elif f["kind"] == "vcenter":
                clusters |= {(vc["name"], cn) for cn in vc["topo"].get("clusters") or {}}
        rows = await self._load_rows(clusters)
        win = windows([(r[0], r[1], r[2]) for r in rows])
        when = p["when"]
        if when and win.get("grid"):
            when["load"] = win["grid"].get(f"{when['weekday']}-{when['hour']}")
        fails = [x for x in checks if x["state"] == "fail"]
        if impact["stop"] or fails:
            verdict = {"key": "hold", "label": "보류 — 먼저 해결할 것이 있음"}
        elif impact["risk"] or any(x["state"] == "warn" for x in checks) or sim.get("verdict") == "warn":
            verdict = {"key": "cond", "label": "조건부 진행 — 주의 항목 확인 후"}
        elif not F:
            verdict = {"key": "none", "label": "대상을 찾지 못함 — 호스트·클러스터 이름을 적어 주세요"}
        else:
            verdict = {"key": "go", "label": "진행 가능"}
        res = {"text": text, "failures": F, "mode": p["mode"], "hint": p.get("hint", ""), "action": p["action"], "when": when, "window": win, "impact": impact, "checks": checks,
               "mop": mop({f["type"] for f in F}), "verdict": verdict, "ai_parse": ai_used, "generated": time.time()}
        if use_ai and F and await self._llm_ok():
            try:
                sys_ = ("너는 VMware 변경 관리(CAB) 검토자다. 아래 사전 검토 결과(JSON)만 근거로 한국어로 짧게: **판단** 1줄, **꼭 확인할 것** 번호 3~5개, "
                        "**작업 중 지켜볼 지표** 2~3개. 결과에 없는 사실은 쓰지 않는다.")
                pay = {k: res[k] for k in ("text", "mode", "verdict")} | {"impact": {k: impact[k] for k in ("stop", "risk", "boot", "move", "top")}, "checks": checks,
                                                                         "when": when, "best": win.get("best")}
                names = [f.get("name") or f["target"] for f in F] + [vc["name"] for vc in world["vcenters"]]
                res["ai"] = await asyncio.wait_for(self.e.llm.complete(sys_, json.dumps(pay, ensure_ascii=False, default=str), max_tokens=900, task="report", names=names), 40)
            except Exception as ex:  # noqa: BLE001
                res["ai_error"] = f"AI 검토 실패: {type(ex).__name__}"
        res["markdown"] = to_markdown(res)
        return res

    async def _checks(self, F: list[dict], world: dict, action: str) -> list[dict]:
        out = []
        tg = {f["target"] for f in F} | {(f.get("name") or "") for f in F}
        vcs = {f.get("vcenter") for f in F if f.get("vcenter")}
        # 1) vCenter 백업
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") == "vcenter" and c.name in vcs:
                b = getattr(c, "protection", None) or {}
                if isinstance(b, dict) and b.get("kind") == "appliance_backup":
                    age = (time.time() - float(b["last_success"])) / 3600 if b.get("last_success") else None
                    out.append({"name": f"vCenter 백업({c.name})", "state": "fail" if not b.get("configured") else "ok" if age is not None and age < 48 else "warn",
                                "detail": "설정 안 됨" if not b.get("configured") else f"마지막 성공 {age:.0f}시간 전" if age is not None else "성공 기록 없음"})
                else:
                    out.append({"name": f"vCenter 백업({c.name})", "state": "warn", "detail": "백업 상태를 모름 — 작업 전 확인"})
        # 2) 인증서 30일
        certs = (getattr(getattr(self.e, "certs", None), "last", None) or {}).get("items") or []
        bad = [x for x in certs if x.get("band") in ("expired", "crit") and (x.get("system") in vcs or any(t and t in str(x.get("name", "")) for t in tg))]
        out.append({"name": "관련 인증서", "state": "warn" if bad else "ok", "detail": ", ".join(f"{x.get('kind')} {x.get('name')} {x.get('days_left')}일" for x in bad[:4]) or "30일 안 만료 없음"})
        # 3) 최근 7일 구성 변경
        dw = getattr(self.e, "driftwatch", None)
        n = 0
        if dw:
            for f in F:
                if f["kind"] == "host" and f.get("vcenter"):
                    try:
                        n += len(await dw.history(f["vcenter"], days=7, entity=f["target"], limit=200))
                    except Exception:  # noqa: BLE001
                        pass
        out.append({"name": "최근 7일 구성 변경(대상 호스트)", "state": "warn" if n else "ok", "detail": f"{n}건 — 변경이 겹치면 원인 구분이 어려움" if n else "없음"})
        # 4) 열린 인시던트
        inc = getattr(self.e, "incidents", None)
        hits = []
        if inc:
            for t in [x for x in tg if x][:10]:
                try:
                    hits += [r for r in await inc.list("active", t.split(".")[0], days=30, limit=20)]
                except Exception:  # noqa: BLE001
                    pass
        ids = {h.get("id") for h in hits}
        out.append({"name": "열린 인시던트(대상)", "state": "fail" if any(str(h.get("severity", "")).lower() in ("critical", "error") for h in hits) else "warn" if hits else "ok",
                    "detail": f"{len(ids)}건 — 먼저 원인 정리" if ids else "없음"})
        # 5) 체크봇 실패 시나리오
        cb = getattr(self.e, "checkbot", None)
        if cb:
            try:
                last = await cb.latest()
                fs = [r for r in (last or {}).get("results", []) if r["verdict"] == "fail" and any(t and t in str(r.get("target", "")) for t in tg)]
                out.append({"name": "What-If 시나리오(대상)", "state": "warn" if fs else "ok", "detail": "; ".join(f"{r['kind']} {r['target']}" for r in fs[:3]) or "실패 시나리오 없음"})
            except Exception:  # noqa: BLE001
                pass
        # 6) 취약점(패치로 해소 가능)
        vc_ = getattr(self.e, "vulncheck", None)
        if vc_:
            try:
                last = await vc_.latest()
                vs = [f for f in (last or {}).get("findings", []) if f.get("asset") in tg]
                cves = [f for f in vs if f["id"].startswith("cve:")]
                det = "없음"
                if vs:
                    det = (f"패치로 해소 가능한 버전 취약점 {len(cves)}건 — 이번 작업에 포함 검토. " if cves else "") + "; ".join(f["title"][:40] for f in vs[:3])
                out.append({"name": "대상의 취약점", "state": "warn" if vs else "ok", "detail": det})
            except Exception:  # noqa: BLE001
                pass
        return out
