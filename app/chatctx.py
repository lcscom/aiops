"""AI 질의 문맥·근거 검색 정확도(2.6.1)

문제: "esx08.rangers.lab issues" 처럼 개체 이름이 든 질문을 그대로 KB 검색어로 쓰면 도메인 조각(rangers·lab)과 일반어(issues)가
'Hands-on Lab … issues' 같은 무관한 문서와 맞고, 답변 문맥도 전체 최근 로그라 질문 대상의 근거가 흐려진다.

해결:
  1) 질문에서 대상 개체(ESXi 호스트·VM·데이터스토어·클러스터·로그에 보인 장비)를 찾아 그 개체의 로그·이상징후·상태·알람·VM 변경을 먼저 싣는다.
  2) KB 검색어는 개체 이름·FQDN·IP·일반어를 뺀 질문 + 대상의 실제 증상(경고 이상 로그·이상징후 원문)으로 만들고, 여러 검색어 결과를 순위 병합한다.
  3) 관련도가 낮은 문서는 근거에서 뺀다(라이브러리 relevance < chat_min_rel, 팩 score < chat_min_pack_score).
"""
from __future__ import annotations

import re
import time
from typing import Any

from .models import SEV_RANK

_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_FQDN = re.compile(r"\b(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
                   r"\.(?:lab|local|corp|internal|intra|lan|com|net|org|kr|io|co|biz|info|cloud|vcf|vmware|home|site|xyz)\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I)
# 질문에만 흔한 일반어 — 이것만 남으면 질문 문장은 검색어로 쓰지 않음(증상 검색어만 사용)
GENERIC = {"issue", "issues", "problem", "problems", "error", "errors", "check", "status", "state", "what", "why", "how", "please", "help",
           "wrong", "happen", "happened", "going", "show", "tell", "about", "any", "there", "now", "today", "recent", "latest", "the", "and",
           "for", "with", "this", "that", "host", "server", "vm", "문제", "이슈", "확인", "상태", "원인", "알려줘", "알려", "뭐야", "무엇", "왜",
           "어떻게", "있어", "있나", "있는지", "최근", "지금", "현재", "봐줘", "분석", "해줘", "관련", "오류", "에러", "장애"}


def _short(n: str) -> str:
    return n.split(".")[0].lower() if n else ""


def _bound(word: str, text: str) -> bool:
    return bool(re.search(rf"(?<![\w-]){re.escape(word)}(?![\w-])", text))


def candidates(engine) -> dict[str, dict[str, Any]]:
    """찾을 수 있는 개체 — vCenter 토폴로지(호스트·VM·데이터스토어·클러스터) + 최근 로그·이상징후에 보인 호스트"""
    out: dict[str, dict[str, Any]] = {}
    for c in getattr(engine, "connectors", []) or []:
        t = getattr(c, "topology", None) or {}
        for kind, key in (("host", "hosts"), ("vm", "vms"), ("datastore", "datastores"), ("cluster", "clusters")):
            for n, v in (t.get(key) or {}).items():
                if n and n not in out and n != "(standalone)":
                    out[n] = {"kind": kind, "name": n, "vcenter": c.name, "data": v if isinstance(v, dict) else {}}
    for e in list(getattr(engine, "buffer", []) or [])[-3000:]:
        h = e.get("host") or ""
        if h and h not in out and len(h) >= 4:
            out[h] = {"kind": "device", "name": h, "vcenter": "", "data": {}}
    for a in list((getattr(engine, "anomalies", {}) or {}).values())[-500:]:
        for h in (a.event.get("host") or "", a.event.get("entity") or ""):
            if h and h not in out and len(h) >= 4:
                out[h] = {"kind": "device", "name": h, "vcenter": "", "data": {}}
    return out


def find_entities(engine, question: str, limit: int = 3) -> list[dict[str, Any]]:
    """질문에 나온 개체 — 전체 이름(대소문자 무시) 우선, 점(.)이 있는 이름은 짧은 이름(esx08)으로도 찾음(4자 이상)"""
    ql = (question or "").lower()
    if not ql.strip():
        return []
    hits = []
    for n, info in candidates(engine).items():
        nl = n.lower()
        if len(nl) >= 3 and _bound(nl, ql):
            hits.append((200 + len(nl), info))
            continue
        s = _short(n)
        if "." in n and len(s) >= 4 and _bound(s, ql):
            hits.append((100 + len(s), info))
    hits.sort(key=lambda x: (-x[0], {"host": 0, "vm": 1, "datastore": 2, "cluster": 3}.get(x[1]["kind"], 4)))
    out, seen = [], set()
    for _, info in hits:
        if info["name"] in seen:
            continue
        seen.add(info["name"])
        out.append(info)
        if len(out) >= limit:
            break
    return out


def _matches(e: dict, ent: dict) -> bool:
    n, s = ent["name"].lower(), _short(ent["name"])
    for f in (e.get("host") or "", e.get("entity") or ""):
        fl = f.lower()
        if fl and (fl == n or (("." in ent["name"]) and (fl == s or fl.split(".")[0] == s and "." not in fl))):
            return True
    if ent["kind"] in ("vm", "datastore", "cluster") and len(n) >= 4 and _bound(n, (e.get("message") or "").lower()):
        return True
    return False


def template(msg: str) -> str:
    t = _UUID.sub("#", _IP.sub("#", msg or ""))
    return re.sub(r"\d+", "#", t)[:140].lower()


def clean_query(text: str, names: list[str] | set[str] = ()) -> str:
    """검색어 정리 — 개체 이름(전체·짧은 이름)·FQDN·IP·UUID/MAC·숫자 토큰 제거"""
    t = text or ""
    for n in sorted({x for x in names if x}, key=len, reverse=True):
        t = re.sub(rf"(?<![\w-]){re.escape(n)}(?![\w-])", " ", t, flags=re.I)
        if "." in n and len(_short(n)) >= 4:
            t = re.sub(rf"(?<![\w-]){re.escape(_short(n))}(?![\w-])", " ", t, flags=re.I)
    t = _EMAIL.sub(" ", t)
    t = _FQDN.sub(" ", t)
    t = _UUID.sub(" ", _IP.sub(" ", t))
    t = re.sub(r"(?<![A-Za-z])\d[\d:./-]*", " ", t)
    return re.sub(r"\s+", " ", t).strip()


_KO_GENERIC = sorted((w for w in GENERIC if re.match(r"[가-힣]", w)), key=len, reverse=True)


def _generic(w: str) -> bool:
    if w in GENERIC:
        return True
    if re.match(r"[가-힣]", w):                     # 한국어 활용형(확인해줘·문제가·알려주세요) — 일반어 어간으로 시작하면 일반어
        return any(w.startswith(g) for g in _KO_GENERIC) or bool(re.fullmatch(r"(해|하|주|줘|요|는|가|이|을|를|좀|좀더)+", w))
    return False


def keywords(q: str) -> str:
    """웹 검색용 — 일반어(문제·알려줘·issues …)와 기호 조각을 뺀 핵심어만(순서 유지)"""
    toks = re.findall(r"[A-Za-z][A-Za-z0-9_.:-]*[A-Za-z0-9]|[가-힣]{2,}|\d+[A-Za-z]+", q or "")
    out = [t for t in toks if not _generic(t.lower())]
    return " ".join(dict.fromkeys(out))


def meaningful(q: str) -> bool:
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}|[가-힣]{2,}", q or "")]
    return any(not _generic(w) for w in words)


def entity_brief(engine, ent: dict[str, Any], hours: float = 6) -> dict[str, Any]:
    """대상 개체 근거 — 상태(토폴로지·BMC)·이상징후·최근 로그(경고 이상 우선)·vCenter 알람 + KB 검색용 증상"""
    now = time.time()
    since = now - hours * 3600
    lines: list[str] = []
    d = ent.get("data") or {}
    kind = ent["kind"]
    if kind == "host":
        vms = 0
        for c in getattr(engine, "connectors", []) or []:
            vms += sum(1 for v in ((getattr(c, "topology", None) or {}).get("vms") or {}).values() if v.get("host") == ent["name"])
        facts = [f"연결 {d.get('conn', '-')}", f"상태 {d.get('status', '-')}", f"유지보수 {'예' if d.get('maintenance') else '아니오'}",
                 f"클러스터 {d.get('cluster') or '-'}", f"VM {vms}"]
        for k, lab in (("version", "버전"), ("build", "빌드"), ("model", "모델"), ("cpu_used_mhz", "CPU 사용 MHz"), ("mem_used_mb", "메모리 사용 MB")):
            if d.get(k) not in (None, "", 0):
                facts.append(f"{lab} {d[k]}")
        try:
            hw = (engine.bmc_inventory() or {}).get(ent["name"]) or (engine.bmc_inventory() or {}).get(_short(ent["name"]))
            if hw:
                facts.append(f"BMC 상태 {hw.get('health') or '-'} · {hw.get('model') or ''} · BMC FW {hw.get('bmc_fw') or '-'} · BIOS {hw.get('bios') or '-'}")
        except Exception:  # noqa: BLE001
            pass
        lines.append("상태: " + " · ".join(facts))
    elif kind == "vm":
        lines.append("상태: " + " · ".join(f"{lab} {d.get(k)}" for k, lab in (("power", "전원"), ("host", "호스트"), ("cluster", "클러스터"), ("vcpu", "vCPU"),
                                                                             ("mem_mb", "메모리 MB"), ("os", "OS"), ("tools", "Tools"), ("snapshots", "스냅샷"),
                                                                             ("datastores", "데이터스토어")) if d.get(k) not in (None, "", [])))
    elif kind in ("datastore", "cluster") and d:
        keep = {k: v for k, v in d.items() if isinstance(v, (str, int, float, bool)) and k not in ("moid",)}
        lines.append("상태: " + " · ".join(f"{k}={v}" for k, v in list(keep.items())[:12]))
    anoms = [a for a in (getattr(engine, "anomalies", {}) or {}).values() if a.last_seen >= since and _matches(a.event, ent)]
    anoms.sort(key=lambda a: (-SEV_RANK.get(a.severity, 0), -a.last_seen))
    if anoms:
        lines.append("이상징후:")
        for a in anoms[:10]:
            ai = a.ai or {}
            lines.append(f"- {time.strftime('%m-%d %H:%M', time.localtime(a.last_seen))} [{a.severity}] {a.title} (x{a.count})"
                         + (f" — AI: {ai.get('summary', '')[:160]}" if ai.get("summary") else ""))
    logs = [e for e in list(getattr(engine, "buffer", []) or [])[-5000:] if e.get("ts", 0) >= since and _matches(e, ent)]
    warn = [e for e in logs if SEV_RANK.get(e.get("severity"), 0) >= 2]
    seen_t: set[str] = set()
    picked = []
    for e in sorted(warn, key=lambda e: -e["ts"]) + sorted(logs, key=lambda e: -e["ts"]):
        t = template(e.get("message", ""))
        if t in seen_t:
            continue
        seen_t.add(t)
        picked.append(e)
        if len(picked) >= 30:
            break
    if picked:
        lines.append(f"최근 로그(최근 {hours:g}시간, 같은 문구는 1건 · 경고 이상 우선, 총 {len(logs)}건 중 경고 이상 {len(warn)}건):")
        for e in sorted(picked, key=lambda e: e["ts"]):
            lines.append(f"- {time.strftime('%m-%d %H:%M:%S', time.localtime(e['ts']))} [{e.get('severity')}] {e.get('source')} "
                         f"{e.get('entity') or ''} {str(e.get('message', ''))[:240]}")
    else:
        lines.append(f"최근 {hours:g}시간 이 개체의 수집 로그 없음(syslog 전달·커넥터 확인).")
    try:                                                   # 2.8.0 VCF Operations 최신 지표(같은 이름 개체)
        om = engine.opsmetrics.brief(ent["name"]) if getattr(engine, "opsmetrics", None) else ""
    except Exception:  # noqa: BLE001
        om = ""
    if om:
        lines.append(om)
    try:
        al = [a for a in engine.moves.alarms() if (a.get("entity") or "").lower() in (ent["name"].lower(), _short(ent["name"]))]
    except Exception:  # noqa: BLE001
        al = []
    if al:
        lines.append("vCenter 알람: " + "; ".join(f"[{a['status']}] {a['alarm']}" for a in al[:8]))
    symptoms: list[str] = []
    st: set[str] = set()
    for src in ([a.event.get("message", "") for a in anoms if SEV_RANK.get(a.severity, 0) >= 2]
                + [e.get("message", "") for e in sorted(warn, key=lambda e: (-SEV_RANK.get(e.get("severity"), 0), -e["ts"]))]):
        t = template(src)
        if t and t not in st:
            st.add(t)
            symptoms.append(src[:500])
        if len(symptoms) >= 4:
            break
    return {"text": "\n".join(lines), "symptoms": symptoms, "logs": len(logs), "warn": len(warn), "anomalies": len(anoms)}


def gate(refs: list[dict], min_rel: float = 0.5, min_pack: float = 0.3) -> list[dict]:
    """관련도가 낮은 근거 제거 — 라이브러리 relevance(질의어 일치율·의미 유사도·오류 문구 일치), 팩 score"""
    out = []
    for r in refs:
        if r.get("pack") == "library" or "relevance" in r:
            if float(r.get("relevance") or 0) >= min_rel:
                out.append(r)
        elif float(r.get("score") or 0) >= min_pack:
            out.append(r)
    return out


async def search_refs(engine, question: str, en: str, entities: list[dict], briefs: list[dict], source: str | None,
                      extra: str = "", k: int = 6) -> tuple[list[dict], list[str]]:
    """질문(개체 이름 제거) + 대상 증상 → 여러 검색어 → 순위 병합 → 관련도 필터. (근거, 실제 검색어)"""
    from .knowledge import rrf_merge
    kc = (getattr(engine, "cfg", {}) or {}).get("knowledge") or {}
    names = [e["name"] for e in entities]
    queries: list[str] = []
    if extra:
        queries.append(clean_query(extra, names))
    q0 = clean_query(f"{question} {en}", names)
    if meaningful(q0):
        queries.append(q0)
    for b in briefs:
        for s in b["symptoms"]:
            q = clean_query(s, names)
            if meaningful(q) and q not in queries:
                queries.append(q)
    queries = [q for q in queries if q][:6]
    if not queries:
        return [], []
    lists = []
    for q in queries:
        try:
            lists.append(await engine.rag.search(q[:1200], source=source, intent="chat", k=4))
        except Exception:  # noqa: BLE001
            lists.append([])
    merged = rrf_merge(*lists, k=k * 2) if len(lists) > 1 else lists[0]
    refs = gate(merged, float(kc.get("chat_min_rel", 0.5)), float(kc.get("chat_min_pack_score", 0.3)))[:k]
    return refs, queries
