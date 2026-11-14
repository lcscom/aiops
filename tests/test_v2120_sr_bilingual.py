"""2.12.0 SR 한국어·영어 병기 — 기본 '병기', 규칙 영문화(제품이 만든 문구), AI 번역(가명화)·미번역 표시·한국어 수정 후 영문 낡음 감지, 이메일·HTML·PDF"""
import asyncio
import io
import json
import time
from types import SimpleNamespace as NS

from app import srlang
from tests.test_v2110_support import _engine, _logs, _rows, _vks_conn


def test_rule_en():
    for ko, en in [("준비 1/2", "Ready 1/2"), ("CrashLoopBackOff 1개 — worker-1a-x", "CrashLoopBackOff ×1 — worker-1a-x"),
                   ("최근 1시간 컨테이너 재시작 +4", "Container restarts in the last hour +4"), ("셀렉터와 일치하는 파드 없음 — 엔드포인트 0", "No pods match the selector — 0 endpoints"),
                   ("HPA 최대 레플리카 도달 (1–2 (현재 2))", "HPA at max replicas (1–2 (current 2))"), ("백엔드 1/1 저하: worker", "Backends degraded 1/1: worker"),
                   ("파드 w-1 재시작 +2 (누적 9) — 직전 종료 OOMKilled (exit 137)", "Pod w-1 restarted +2 (total 9) — last terminated OOMKilled (exit 137)"),
                   ("이미지 api:1.4 → api:1.5 (리비전 3 → 4)", "Image api:1.4 → api:1.5 (revision 3 → 4)"), ("레플리카 2 → 4", "Replicas 2 → 4"),
                   ("10-20 07:10 [대상 VM] DRS 자동 이동 core-db01 esx01→esx02 vCPU 4 → 8, 메모리 16 → 32 GB (업무 외)",
                    "10-20 07:10 [target VM] DRS migration core-db01 esx01→esx02 vCPU 4 → 8, memory 16 → 32 GB (off-hours)"),
                   ("평일 09:00–18:00(KST), P1 은 24x7", "Weekdays 09:00–18:00 (KST), 24x7 for P1")]:
        assert srlang.rule_en(ko) == en, (ko, srlang.rule_en(ko))
    assert srlang.has_ko(srlang.rule_en("esx01 스토리지 경로 장애"))          # 사람이 쓴 문장은 규칙으로 못 바꿈(지어내지 않음)
    assert srlang.rule_en("NMP path dead") == "NMP path dead"


def test_bilingual_vks_offline(tmp_path):
    async def main():
        e = _engine(tmp_path)
        e.connectors = [_vks_conn()]
        S = e.support
        assert (await S.profile())["default_lang"] == "both"
        r = await S.create({"kind": "vks", "connector": "tkc1", "okind": "Deployment", "ns": "pay", "obj": "worker"}, {"user": "op1"}, {})
        d = r["data"]
        assert d["lang"] == "both" and d["requests_en"] and d["requests"] != d["requests_en"]
        body = S.email_text(r)
        ko, en = body.split(" English ")
        assert "1. 문제 요약" in ko and "1. Problem summary" in en and "안녕하세요" in ko and "Hello," in en
        assert "No ready pods" in en and "Queried" in en and "Checked node → vSphere VM → ESXi placement" in en and "Production" not in ko[:20]
        assert "(KO)" not in en, [ln for ln in en.splitlines() if "(KO)" in ln]   # VKS 근거는 모두 규칙으로 영문화
        assert S.en_pending(d) == []
        subj = S.subject(r)
        assert " / " in subj or "VKS" in subj
        html = S.html(r)
        assert "문제 요약 · Problem summary" in html and "class='en'" in html and "<span class=tag>EN</span>" in html
        from pypdf import PdfReader
        txt = "".join(p.extract_text() for p in PdfReader(io.BytesIO(S.pdf(r))).pages).replace("\x00", "").replace(" ", "")
        assert "문제요약·Problemsummary" in txt and "Noreadypods" in txt
        # 한국어만 / 영어만
        r = await S.update(r["id"], {"lang": "ko"}, {"user": "op1"})
        assert " English " not in S.email_text(r) and "1. 문제 요약" in S.email_text(r)
        r = await S.update(r["id"], {"lang": "en"}, {"user": "op1"})
        b2 = S.email_text(r)
        assert "1. Problem summary" in b2 and "문제 요약" not in b2 and "Hello," in b2
    asyncio.run(main())


def test_translate_and_stale(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        await _logs(e, _rows(now))
        calls = []

        async def complete(system, user, max_tokens=800, task="brief", names=None):
            calls.append((system, user, names))
            items = json.loads(user)["items"]
            return json.dumps({"items": [f"EN<{i}>" for i in range(len(items))]})
        e.llm = NS(complete=complete)
        S = e.support
        r = await S.create({"kind": "manual", "title": "esx01 스토리지 경로 장애", "description": "esx01.lab 에서 경로가 끊김", "hosts": ["esx01.lab"],
                            "since": now - 3600, "until": now}, {"user": "op1"}, {"vendor": "broadcom"})
        d = r["data"]
        assert calls and "esx01.lab" in calls[0][2] and d["title_en"].startswith("EN<") and d["summary_en"].startswith("EN<")
        assert S.en_pending(d) == [] and "EN<" in S.email_text(r).split(" English ")[1]
        # 한국어 제목 수정 → 영문 낡음
        r = await S.update(r["id"], {**{k: d[k] for k in ("title_en", "summary_en", "impact_en") if d.get(k)}, "title": "esx01 HBA 경로 장애(수정)"}, {"user": "op1"})
        assert S.en_stale(r["data"]) == ["title"]
        res = await S.translate(r, stale=True)
        r = await S.get(r["id"])
        assert res["pending"] == 0 and S.en_stale(r["data"]) == [] and r["data"]["title_en"].startswith("EN<")
        # 영문 직접 입력 우선
        r = await S.update(r["id"], {"title_en": "esx01 HBA path failure"}, {"user": "op1"})
        assert "esx01 HBA path failure" in S.subject(r) and "esx01 HBA path failure" in S.html(r) and S.en_stale(r["data"]) == []
        # LLM 없으면 '(KO) 원문'으로 드러냄
        e.llm = None
        r2 = await S.create({"kind": "manual", "title": "vSAN 디스크 그룹 오류", "hosts": ["esx01.lab"], "since": now - 3600, "until": now}, {"user": "op1"}, {})
        assert "(KO) vSAN 디스크 그룹 오류" in S.subject(r2) + S.html(r2) and "vSAN 디스크 그룹 오류" in S.en_pending(r2["data"])
        try:
            await S.translate(r2)
            raise AssertionError
        except RuntimeError:
            pass
        # AI 다듬기 — 병기면 두 언어 키 모두
        seen = {}

        async def complete2(system, user, max_tokens=800, task="brief", names=None):
            seen["sys"] = system
            return json.dumps({"title": "제목", "summary": "요약", "impact": "영향", "requests": ["가"], "title_en": "Title", "summary_en": "Summary", "impact_en": "Impact", "requests_en": ["A"]})
        e.llm = NS(complete=complete2)
        p = await S.refine(r2)
        assert p["title_en"] == "Title" and p["requests"] == ["가"] and "'summary_en' (English)" in seen["sys"]
    asyncio.run(main())
