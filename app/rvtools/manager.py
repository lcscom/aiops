"""RVTools 분석 관리자(2.15.0) — 업로드 → 정규화 → 분석 → 저장(정규화·분석 결과만, 원본 파일은 저장하지 않음)

저장: rv_imports(id, name, uploaded, by, size, summary(JSON), inv(zlib JSON), res(zlib JSON), ai(JSON))
보관: retention(기본 20)개 초과분은 오래된 것부터 삭제. 업로드 크기 상한 100MB(설정 max_mb).
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
import zlib
from typing import Any

from . import analyze as A
from . import model as Mdl
from . import xlsx as X

SCHEMA = """CREATE TABLE IF NOT EXISTS rv_imports(id TEXT PRIMARY KEY, name TEXT, uploaded REAL, by TEXT, size INTEGER, summary TEXT, inv BLOB, res BLOB, ai TEXT);"""
SHEETS = {"vInfo", "vCPU", "vMemory", "vDisk", "vPartition", "vNetwork", "vCD", "vSnapshot", "vTools", "vSource", "vRP", "vCluster", "vHost", "vHBA", "vNIC",
          "vSwitch", "vPort", "dvSwitch", "dvPort", "vSC_VMK", "vDatastore", "vMultiPath", "vLicense", "vHealth", "vMetaData"}


def _pack(d: Any) -> bytes:
    return zlib.compress(json.dumps(d, ensure_ascii=False, default=str).encode(), 6)


def _unpack(b) -> Any:
    try:
        return json.loads(zlib.decompress(b))
    except Exception:
        return {}


def safe_name(name: str) -> str:
    """표시용 파일 이름 — 경로 성분·제어 문자 제거"""
    n = re.split(r"[\\/]", str(name or ""))[-1]
    n = re.sub(r"[\x00-\x1f\x7f]", "", n).strip()[:160]
    return n or "rvtools.xlsx"


class RvToolsManager:
    def __init__(self, engine, cfg: dict | None = None):
        self.engine = engine
        cfg = cfg or {}
        self.max_mb = int(cfg.get("max_mb", 100))
        self.retention = int(cfg.get("retention", 20))
        self._ready = False
        self._cache: dict[str, tuple[dict, dict]] = {}       # id → (inv, res) 최근 3개
        self._lock = asyncio.Lock()

    async def _db(self):
        st = self.engine.store
        if not self._ready:
            st.schema(SCHEMA)
            self._ready = True
        return st

    async def _advisories(self) -> list[dict]:
        try:
            a = self.engine.assess
            return list(await a.advisories()) if a else []
        except Exception:
            return []

    async def upload(self, raw: bytes, name: str, by: str) -> dict:
        if len(raw) > self.max_mb * 1024 * 1024:
            raise ValueError(f"파일이 {self.max_mb}MB 를 넘습니다")
        if raw[:2] != b"PK":
            raise ValueError("xlsx 파일이 아닙니다 — RVTools 'Export all to xlsx' 결과를 올리세요")
        advs = await self._advisories()

        def work():
            sh = X.read(raw, SHEETS)
            inv = Mdl.normalize(sh)
            return inv, A.analyze(inv, advs)
        async with self._lock:                                # 큰 파일 동시 분석으로 메모리 급증 방지
            inv, res = await asyncio.to_thread(work)
        iid = time.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        sm = res["summary"]
        summary = {"vcenters": [v["name"] for v in sm["vcenters"]], "counts": sm["counts"], "score": res["score"], "findings": res["counts"],
                   "exported": inv["meta"].get("exported"), "rvtools": inv["meta"].get("rvtools"), "kisa": res["hardening"]["score"],
                   "vcf9": res["vcf9"]["verdicts"]}
        st = await self._db()
        await st.x("INSERT INTO rv_imports(id,name,uploaded,by,size,summary,inv,res,ai) VALUES(?,?,?,?,?,?,?,?,?)",
                   (iid, safe_name(name), time.time(), by, len(raw), json.dumps(summary, ensure_ascii=False, default=str), _pack(inv), _pack(res), "{}"))
        old = await st.q("SELECT id FROM rv_imports ORDER BY uploaded DESC LIMIT -1 OFFSET ?", (self.retention,))
        for r in old:
            await st.x("DELETE FROM rv_imports WHERE id=?", (r["id"],))
        self._remember(iid, inv, res)
        return {"id": iid, "name": safe_name(name), **summary}

    def _remember(self, iid, inv, res):
        self._cache[iid] = (inv, res)
        while len(self._cache) > 3:
            self._cache.pop(next(iter(self._cache)))

    async def list(self) -> list[dict]:
        st = await self._db()
        rows = await st.q("SELECT id,name,uploaded,by,size,summary,ai FROM rv_imports ORDER BY uploaded DESC")
        out = []
        for r in rows:
            ai = json.loads(r["ai"] or "{}")
            out.append({"id": r["id"], "name": r["name"], "uploaded": r["uploaded"], "by": r["by"], "size": r["size"], **json.loads(r["summary"] or "{}"),
                        "ai": bool(ai.get("report"))})
        return out

    async def get(self, iid: str) -> tuple[dict, dict, dict] | None:
        st = await self._db()
        r = await st.q1("SELECT id,name,uploaded,by,size,summary,ai FROM rv_imports WHERE id=?", (iid,))
        if not r:
            return None
        if iid not in self._cache:
            b = await st.q1("SELECT inv,res FROM rv_imports WHERE id=?", (iid,))
            self._remember(iid, _unpack(b["inv"]), _unpack(b["res"]))
        inv, res = self._cache[iid]
        meta = {"id": r["id"], "name": r["name"], "uploaded": r["uploaded"], "by": r["by"], "size": r["size"], **json.loads(r["summary"] or "{}"),
                "ai": json.loads(r["ai"] or "{}")}
        return meta, inv, res

    async def reanalyze(self, iid: str) -> dict | None:
        """규칙·권고 DB 가 바뀐 뒤 저장된 정규화 데이터로 다시 평가"""
        g = await self.get(iid)
        if not g:
            return None
        meta, inv, _ = g
        res = await asyncio.to_thread(A.analyze, inv, await self._advisories())
        st = await self._db()
        sm = json.loads((await st.q1("SELECT summary FROM rv_imports WHERE id=?", (iid,)))["summary"] or "{}")
        sm.update({"score": res["score"], "findings": res["counts"], "kisa": res["hardening"]["score"], "vcf9": res["vcf9"]["verdicts"]})
        await st.x("UPDATE rv_imports SET res=?, summary=? WHERE id=?", (_pack(res), json.dumps(sm, ensure_ascii=False, default=str), iid))
        self._remember(iid, inv, res)
        return sm

    async def save_ai(self, iid: str, ai: dict):
        st = await self._db()
        await st.x("UPDATE rv_imports SET ai=? WHERE id=?", (json.dumps(ai, ensure_ascii=False, default=str), iid))

    async def delete(self, iid: str) -> bool:
        st = await self._db()
        self._cache.pop(iid, None)
        r = await st.q1("SELECT id FROM rv_imports WHERE id=?", (iid,))
        if r:
            await st.x("DELETE FROM rv_imports WHERE id=?", (iid,))
        return bool(r)

    # ---------------------------------------------------------------------------------------- AI(PAIS 등 설정된 LLM)
    SYSTEM_REPORT = ("너는 VMware vSphere/VCF 아키텍트다. 고객사 RVTools 내보내기를 집계한 JSON(환경·용량·점검 결과·KISA·VMSA·VCF 9 준비도)만 근거로 "
                     "한국어 진단 보고서를 쓴다. 형식(마크다운):\n"
                     "## 종합 의견 — 3~5문장(환경 규모, 전반 상태, 가장 큰 위험 3가지)\n"
                     "## 주요 위험과 조치 — 표(우선순위 | 영역 | 대상 | 문제 | 조치 | 근거 수치). 위험·오류부터, 같은 유형은 묶는다\n"
                     "## 용량·성능 — vCPU:코어 비율, 메모리 할당률, N+1 여유, 데이터스토어 사용률·과할당, 회수 가능 자원(꺼진 VM·좀비·스냅숏)\n"
                     "## 보안·컴플라이언스 — KISA 실패/현장 확인 항목, VMSA 취약 빌드, 인증서·라이선스 만료, 지원 종료 OS\n"
                     "## VCF 9 전환 준비 — CPU 등급, ESXi/vCenter 업그레이드 경로(KB 418259 상호운용성 매트릭스, KB 457561 빌드 출시일), NIC, 라이선스 코어 수\n"
                     "## 단계별 실행 계획 — 즉시(1주)/단기(1개월)/중기(분기)\n"
                     "규칙: JSON 에 없는 수치·KB·CVE 를 만들지 않는다. 추정은 '추정'이라 밝힌다. RVTools 로 확인 안 되는 항목(ESXi 고급 설정·서비스·방화벽)은 '현장 확인 필요'로 쓴다.")
    SYSTEM_ASK = ("너는 VMware vSphere/VCF 아키텍트다. 아래 'RVTools 분석' 컨텍스트(집계·점검 결과·관련 원본 행)와 참고 문서만 근거로 질문에 한국어로 답한다. "
                  "결론 → 근거 수치(개체 이름과 값) → 조치 순서로 간결하게. 컨텍스트에 없는 값은 만들지 말고 무엇을 더 확인해야 하는지 말한다. "
                  "참고 문서를 쓰면 [R#] 로 인용한다. RVTools 는 내보낸 시점의 스냅숏이라는 점을 감안한다.")

    async def ai_report(self, iid: str, by: str) -> dict:
        llm = self.engine.llm
        if not llm:
            raise RuntimeError("LLM 비활성 — 설정 › AI 에서 PAIS 등 공급자를 켜세요")
        g = await self.get(iid)
        if not g:
            raise KeyError(iid)
        meta, inv, res = g
        digest = A.ai_digest(inv, res)
        t0 = time.time()
        txt = await llm.complete(self.SYSTEM_REPORT, "RVTools 분석 집계(JSON):\n" + digest, max_tokens=3500, task="report", names=A.names_of(inv))
        prov = ""
        try:
            o = llm.order("report")
            prov = f"{o[0].name} · {o[0].model}" if o else ""
        except Exception:
            pass
        ai = dict(meta.get("ai") or {}, report=txt, at=time.time(), by=by, provider=prov, secs=round(time.time() - t0, 1))
        await self.save_ai(iid, ai)
        return ai

    def ask_context(self, inv: dict, res: dict, question: str) -> str:
        parts = ["## RVTools 분석 집계\n" + A.ai_digest(inv, res, 9000)]
        rows = A.search_rows(inv, question)
        if rows:
            parts.append("## 질문과 관련된 원본 행(RVTools)\n" + "\n".join("- " + r for r in rows))
        rel = [f for f in res["findings"] if any(t in (f["entity"] + f["title"]).lower() for t in re.split(r"\s+", question.lower()) if len(t) >= 3)][:30]
        if rel:
            parts.append("## 질문과 관련된 점검 결과\n" + "\n".join(f"- [{A.SEV_KO.get(f['severity'])}] {f['id']} {f['entity']}: {f['title']} — {str(f['detail'])[:200]}" for f in rel))
        return "\n\n".join(parts)
