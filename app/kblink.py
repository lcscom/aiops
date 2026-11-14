"""KB 자동 연결 — 이상징후·인시던트마다 비슷한 KB·TechDocs 문서를 찾아 붙여 둔다(LLM 호출 없음).

왜: AI 판정은 같은 로그 패턴을 재사용하고(분석 재사용), 근거 후보가 약하면 붙이지 않는다. 그래서 KB 아카이브를 나중에
올리면 이미 분석된 패턴·인시던트에는 문서가 보이지 않았다. 이 작업이 뒤에서 계속 돌며
  · 근거 문서가 없는 미확인 이상징후에 '관련 KB(자동)'을 붙이고(지식 세대가 바뀌면 다시 찾음)
  · 인시던트는 묶인 이상징후들의 원문 로그·AI 근거를 모아 문서별로 합산해 '관련 KB' 를 만든다(RCA 입력에도 사용)
검색은 지식 라이브러리 + RAG 팩(rag.search) — 한국어 질문은 영문 운영 용어로 확장(knowledge.expand_query).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

KEEP = ("title", "url", "kb", "doc_id", "type", "section", "sections", "versions", "product", "doc_type", "summary",
        "relevance", "score", "pack_name")
SEV = {"critical": 4, "error": 3, "warning": 2, "info": 1, "debug": 0}


def compact(h: dict) -> dict:
    out = {k: h.get(k) for k in KEEP if h.get(k) not in (None, "", [])}
    if "summary" in out:
        out["summary"] = str(out["summary"])[:300]
    return out


class KbLinker:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.enabled = bool(c.get("auto_link", True))
        self.interval = float(c.get("link_interval", 20))
        self.per_cycle = int(c.get("link_per_cycle", 40))
        self.min_rel = float(c.get("link_min_relevance", 0.6))
        self.k = int(c.get("link_top_k", 3))
        self.stats: dict[str, Any] = {"last_run": 0.0, "anomalies_linked": 0, "anomalies_checked": 0, "incidents": 0, "gen": 0}
        self._inc: dict[str, tuple[tuple, list[dict]]] = {}
        self._enq: dict[str, str] = {}

    def _ready(self) -> bool:
        lib = getattr(self.e, "knowledge", None)
        return bool(self.enabled and self.e.rag and (self.e.rag.has_any()))

    async def related(self, ev: dict, reasons: list[str] | None = None, k: int | None = None, query: str | None = None) -> list[dict]:
        from .knowledge import kb_query_of
        q = query or kb_query_of(ev or {}, reasons)
        if not q.strip():
            return []
        try:
            hits = await self.e.rag.search(q, source=(ev or {}).get("source") or None, k=k or self.k, intent="analyze")
        except Exception:  # noqa: BLE001
            return []
        return [compact(h) for h in hits if h.get("relevance") is None or float(h.get("relevance") or 0) >= self.min_rel]

    # ------------------------------------------------------------------ 이상징후
    def _needs(self, a, gen: int, now: float) -> bool:
        if a.ack or now - (a.last_seen or 0) > 86400 or a.status in ("pending", "queued", "analyzing"):
            return False
        if (a.ai or {}).get("references"):                 # AI 가 이미 근거로 인용 — 그대로 둔다
            return False
        if (a.event or {}).get("source") == "aiops":       # 포털 자체 감시(수집 오류 등) — KB 대상 아님
            return False
        return getattr(a, "related_gen", -1) != gen

    async def run_once(self) -> int:
        if not self._ready():
            return 0
        lib = self.e.knowledge
        gen = lib.gen if lib and lib.enabled else 0
        now = time.time()
        for a in list(self.e.anomalies.values()):          # 대상이 아니게 된 카드(포털 자체 감시 등)의 예전 연결은 지움
            if a.related and (a.event or {}).get("source") == "aiops":
                a.related = []
                d = a.to_dict()
                await self.e.store.save_anomaly(d)
                self.e.hub.publish({"type": "anomaly", "data": d})
        cands = [a for a in list(self.e.anomalies.values()) if self._needs(a, gen, now)]
        cands.sort(key=lambda a: (SEV.get(a.severity, 1), a.last_seen), reverse=True)
        n = 0
        for a in cands[: self.per_cycle]:
            rel = await self.related(a.event or {}, a.reasons)
            changed = [x.get("doc_id") or x.get("url") for x in rel] != [x.get("doc_id") or x.get("url") for x in (a.related or [])]
            a.related, a.related_gen = rel, gen
            self.stats["anomalies_checked"] += 1
            if rel:
                n += 1
            if changed:
                d = a.to_dict()
                await self.e.store.save_anomaly(d)
                self.e.hub.publish({"type": "anomaly", "data": d})
            await asyncio.sleep(0)
        self.stats.update(last_run=now, gen=gen)
        self.stats["anomalies_linked"] += n
        return n

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(30)
        while True:
            beat()
            try:
                await self.run_once()
            except Exception as e:  # noqa: BLE001
                self.stats["last_error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(self.interval)

    # ------------------------------------------------------------------ 한국어 질문 → 영문 검색어(질의·RCA)
    async def en_query(self, q: str, timeout: float = 8.0, names: list[str] | None = None) -> str:
        """한국어 질문을 영문 KB 검색어로(사내 LLM, 짧게). 용어 사전(expand_query)으로 못 바꾸는 표현을 보완 — 실패하면 빈 문자열"""
        import re
        if not q or not re.search(r"[가-힣]", q) or not getattr(self.e, "llm", None):
            return ""
        key = q.strip()[:300]
        if key in self._enq:
            return self._enq[key]
        names = list(names or [])
        try:                                      # 2.30.0 질문에 나온 개체 이름 — 외부 공급자일 때 가명화 대상
            from . import chatctx
            names += [x["name"] for x in chatctx.find_entities(self.e, key)]
        except Exception:  # noqa: BLE001
            pass
        try:
            txt = await asyncio.wait_for(self.e.llm.complete(
                "You convert an operator question about VMware VCF/vSphere/NSX/Avi/VKS into English search keywords for Broadcom KB articles. "
                "Keep product names, error strings, IDs and codes verbatim. Output ONE line of 4-12 English keywords, nothing else.",
                key, max_tokens=60, task="chat", names=names), timeout)
        except Exception:  # noqa: BLE001
            return ""
        out = re.sub(r"[^\w .:/_-]+", " ", (txt or "").splitlines()[0] if txt else "")[:200].strip()
        if re.search(r"[가-힣]", out) or len(re.findall(r"[A-Za-z]{3,}", out)) < 2:   # 2.7.0 영문 키워드가 아니면 버림(모델이 엉뚱한 답을 낸 경우)
            out = ""
        self._enq[key] = out
        if len(self._enq) > 300:
            self._enq.pop(next(iter(self._enq)))
        return out

    # ------------------------------------------------------------------ 인시던트
    async def for_incident(self, inc: dict, k: int = 6) -> list[dict]:
        """인시던트 관련 KB — 묶인 이상징후의 AI 근거·자동 연결 문서와 원문 로그별 검색을 문서 단위로 합산(지식 세대·이상징후 수로 캐시)"""
        if not self._ready():
            return []
        lib = self.e.knowledge
        gen = lib.gen if lib and lib.enabled else 0
        aids = list(inc.get("anomaly_ids") or [])
        key = (gen, len(aids), inc.get("updated"))
        hit = self._inc.get(inc["id"])
        if hit and hit[0][:2] == key[:2]:
            return hit[1]
        score: dict[str, float] = {}
        docs: dict[str, dict] = {}
        why: dict[str, set] = {}

        def add(h: dict, w: float, aid: str) -> None:
            kid = f"kb:{h['kb']}" if h.get("kb") else (h.get("doc_id") or h.get("url") or h.get("title"))   # AI 근거·자동 연결·검색이 같은 KB 면 하나로
            if not kid:
                return
            docs.setdefault(kid, compact(h))
            score[kid] = score.get(kid, 0.0) + w * (0.5 + float(h.get("relevance") or 0.5))
            why.setdefault(kid, set()).add(aid)

        anoms = [self.e.anomalies[x] for x in aids if x in self.e.anomalies and (self.e.anomalies[x].event or {}).get("source") != "aiops"]
        if aids and not anoms:                              # 포털 자체 감시 인시던트(수집 오류 등) — KB 대상 아님
            self._inc[inc["id"]] = (key, [])
            return []
        anoms.sort(key=lambda a: (SEV.get(a.severity, 1), a.count), reverse=True)
        for a in anoms[:8]:
            for h in (a.ai or {}).get("references") or []:
                add(h, 2.0, a.id)                           # AI 가 인용한 근거가 가장 강함
            for h in a.related or []:
                add(h, 1.0, a.id)
        for a in anoms[:5]:                                 # 원문 로그 기준으로 새로 찾기(지식이 바뀐 뒤에도 반영)
            for h in await self.related(a.event or {}, a.reasons, k=4):
                add(h, 1.0, a.id)
        if not anoms and (inc.get("title") or inc.get("summary")):
            for h in await self.related({"source": (inc.get("sources") or [None])[0]}, query=f"{inc.get('title', '')} {inc.get('summary') or ''}", k=4):
                add(h, 1.0, "")
        out = []
        for kid in sorted(score, key=lambda x: -score[x])[:k]:
            d = dict(docs[kid])
            d["matched_anomalies"] = len(why.get(kid, set()) - {""})
            d["link_score"] = round(score[kid], 2)
            out.append(d)
        self._inc[inc["id"]] = (key, out)
        if len(self._inc) > 500:
            for x in list(self._inc)[:100]:
                self._inc.pop(x, None)
        self.stats["incidents"] = len(self._inc)
        return out
