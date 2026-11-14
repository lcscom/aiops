"""2.6.1 AI 질의 근거 정확도 — 질문 대상 개체 문맥 · 개체 이름/도메인 조각 제거 · 증상 기반 다중 검색 · 관련도 필터"""
import asyncio
import time
from types import SimpleNamespace as NS

from app import chatctx
from app.knowledge import KnowledgeLibrary


def _kb(num, title, product, symptom, cause, resolution, sig=""):
    return f"""---
doc_id: kb-{num}
title: "{title}"
source: kb
article_id: {num}
vendor: vmware
product: {product}
doc_type: troubleshooting
{('error_signatures:' + chr(10) + '- "' + sig + '"') if sig else ''}
url: https://knowledge.broadcom.com/external/article/{num}
---
# {title}

## Issue/Introduction
{symptom}

## Environment
VMware ESXi 8.0.x

## Cause
{cause}

## Resolution
{resolution}
"""


DOCS = [
    ("370489", "Troubleshooting VMware Hands-on Lab, Education OnDemand Labs and Instructor Led Trainings performance and connectivity issues", "other",
     "Lab console is slow or the lab does not load. Hands-on Lab connectivity issues.", "Browser or network issues on the student side.", "Clear the browser cache and retry the lab."),
    ("400495", "Troubleshooting SAML related issues on AVI when VS is configured as a Service Provider", "avi",
     "SAML login fails on the virtual service.", "IdP metadata mismatch.", "Re-import the IdP metadata."),
    ("910001", "ESXi host hardware sensor reports voltage alarm (Yellow) on power supply", "esxi",
     "The host hardware status shows a voltage sensor in Yellow or Red state. vobd reports PSU voltage state assert.",
     "A power supply unit or its input voltage is out of range.", "1. Check the BMC (iLO/iDRAC) power supply status. 2. Reseat or replace the PSU.",
     "voltage state assert for Yellow"),
    ("910002", "Virtual machines report high disk latency on VMFS datastore", "esxi",
     "VM disk latency above 20 ms; storage latency high; esxtop DAVG high.", "Array or path congestion.", "Check esxtop DAVG/KAVG and path policy."),
]


def _lib(tmp_path):
    L = KnowledgeLibrary({"embed": False}, str(tmp_path / "d"))
    for num, title, prod, sym, cause, res, *sig in DOCS:
        L.save_file(_kb(num, title, prod, sym, cause, res, sig[0] if sig else "").encode(), f"{num}.md", f"kb/{num}.md")
    return L


def _engine(L):
    now = time.time()
    buf = [
        {"ts": now - 600, "severity": "warning", "source": "esxi", "host": "esx08.rangers.lab", "entity": "vobd",
         "message": "Sensor 25 type voltage, Description PSU1 Voltage state assert for Yellow"},
        {"ts": now - 500, "severity": "info", "source": "vcenter", "host": "esx08.rangers.lab", "entity": "",
         "message": "Hardware Sensor Status: Processor Green, Memory Green, Fan Green, Voltage Yellow"},
        {"ts": now - 400, "severity": "error", "source": "esxi", "host": "esx01.rangers.lab", "entity": "hostd", "message": "other host problem"},
    ]

    async def search(q, source=None, intent="chat", k=4, **kw):
        return L.search_sync(q, source, k, intent)
    return NS(connectors=[NS(name="vc1", topology={"hosts": {"esx08.rangers.lab": {"cluster": "CL1", "conn": "connected", "status": "yellow"},
                                                             "esx01.rangers.lab": {"cluster": "CL1", "conn": "connected", "status": "green"}},
                                                   "vms": {"Holo-A-Console": {"host": "esx08.rangers.lab", "power": "poweredOn"}}, "datastores": {}, "clusters": {}})],
              buffer=buf, anomalies={}, moves=NS(alarms=lambda: [{"entity": "esx08.rangers.lab", "status": "yellow", "alarm": "Host hardware voltage"}]),
              bmc_inventory=lambda: {}, cfg={"knowledge": {}}, rag=NS(search=search))


def test_hostname_fragments_no_longer_match_lab_docs(tmp_path):
    L = _lib(tmp_path)
    hits = L.search_sync("esx08.rangers.lab issues", None, 6, "chat")
    assert not [h for h in hits if h["kb"] in ("370489", "400495")]


def test_find_entities_by_short_name_and_brief(tmp_path):
    e = _engine(_lib(tmp_path))
    ents = chatctx.find_entities(e, "esx08 issues?")
    assert [x["name"] for x in ents] == ["esx08.rangers.lab"] and ents[0]["kind"] == "host"
    assert chatctx.find_entities(e, "esx08.rangers.lab issues")[0]["name"] == "esx08.rangers.lab"
    b = chatctx.entity_brief(e, ents[0])
    assert "PSU1 Voltage state assert" in b["text"] and "other host problem" not in b["text"]       # 다른 호스트 로그 섞지 않음
    assert "Host hardware voltage" in b["text"] and "VM 1" in b["text"]
    assert b["symptoms"] == ["Sensor 25 type voltage, Description PSU1 Voltage state assert for Yellow"]


def test_search_refs_uses_symptoms_and_gates_irrelevant(tmp_path):
    e = _engine(_lib(tmp_path))
    ents = chatctx.find_entities(e, "esx08.rangers.lab issues")
    briefs = [chatctx.entity_brief(e, x) for x in ents]
    refs, queries = asyncio.run(chatctx.search_refs(e, "esx08.rangers.lab issues", "", ents, briefs, None))
    kbs = [r["kb"] for r in refs]
    assert kbs and kbs[0] == "910001" and "370489" not in kbs and "400495" not in kbs
    assert all("rangers" not in q and "esx08" not in q for q in queries) and any("voltage" in q.lower() for q in queries)


def test_clean_query_and_meaningful():
    assert chatctx.clean_query("esx08.rangers.lab issues 10.0.0.5", ["esx08.rangers.lab"]) == "issues"
    assert not chatctx.meaningful("issues") and not chatctx.meaningful("문제 확인해줘") and chatctx.meaningful("disk latency high")
    assert chatctx.clean_query("PSU1 Voltage state assert on esx08 at 2026-10-19", ["esx08.rangers.lab"]) == "PSU1 Voltage state assert on at"


def test_gate_filters_low_relevance():
    refs = [{"pack": "library", "relevance": 0.33, "kb": "1"}, {"pack": "library", "relevance": 0.8, "kb": "2"}, {"pack": "vmsa", "score": 0.2}, {"pack": "vmsa", "score": 0.6}]
    assert [r.get("kb") or r["score"] for r in chatctx.gate(refs)] == ["2", 0.6]


def test_chat_prompt_rules():
    import inspect
    from app import llm
    src = inspect.getsource(llm.LLMClient.chat_stream)
    assert "질문 대상" in src and "Green" in src and "[W#]" in src and "없습니다'로 칸을 채우지 않는다" in src
