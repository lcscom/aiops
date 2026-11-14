"""1.10: KB·TechDocs Markdown 라이브러리 — 파싱·증분 색인·하이브리드 검색·피드백·환각 방지·zip 업로드·MCP"""
import asyncio
import io
import os
import shutil
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace as NS

import numpy as np

from app.knowledge import KnowledgeLibrary, chunk_sections, guard_kb_numbers, parse_markdown, techdocs_meta, versions_in

FX = Path(__file__).parent / "fixtures" / "knowledge"


def _lib(tmp_path, **kw):
    src = tmp_path / "src"
    shutil.copytree(FX / "kb", src / "kb")
    shutil.copytree(FX / "techdocs", src / "techdocs")
    return KnowledgeLibrary({"paths": [str(src)], **kw}, str(tmp_path / "data")), src


def test_parse_kb_front_matter_head_fields_and_techdocs():
    d = parse_markdown((FX / "kb" / "kb_900001_apd.md").read_text(), "kb/kb_900001_apd.md")
    assert d["kind"] == "kb" and d["kb"] == "900001" and d["product"] == "esxi" and d["versions"] == ["7.0", "8.0"]
    roles = [s["role"] for s in d["sections"]]
    assert {"symptom", "cause", "resolution", "workaround", "env"} <= set(roles)
    res = next(c for c in chunk_sections(d) if c["role"] == "resolution")["text"]
    assert res.index("1. Identify") < res.index("esxcli storage core path list") < res.index("2. Check the array")   # 코드 블록 순서 보존
    d3 = parse_markdown((FX / "kb" / "kb_900003_edge_cpu.md").read_text(), "kb_900003_edge_cpu.md")       # front matter 없음 — 머리 줄
    assert d3["kb"] == "900003" and d3["product"] == "nsx" and d3["versions"] == ["4.1", "4.2"] and d3["url"].endswith("/900003")
    d4 = parse_markdown((FX / "kb" / "kb_900004_se_down.md").read_text(), "x.md")
    assert d4["kb"] == "900004" and d4["product"] == "avi" and [s["crumb"] for s in d4["sections"]] == ["Symptoms", "Cause", "Resolution"]
    td = parse_markdown((FX / "techdocs" / "avi-se-ha.md").read_text(), "techdocs/avi-se-ha.md")
    assert td["kind"] == "techdoc" and td["product"] == "avi" and td["versions"] == ["31.1"]
    assert techdocs_meta("https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/x.html") == ("vsphere", "8.0")
    assert versions_in("VMware NSX 4.2.x and ESXi 8.0 U3") == ["4.2", "8.0"]


def test_incremental_scan_and_search_ranking(tmp_path):
    L, src = _lib(tmp_path)
    r = L.scan()
    assert r["changed"] == 4 and r["errors"] == 0 and L.stats()["kb"] == 3
    assert L.scan()["changed"] == 0                                           # 변경 없음
    f = src / "kb" / "kb_900003_edge_cpu.md"
    f.write_text(f.read_text() + "\n\n## Additional Information\nRelated: Tier-0 SR failover.\n")
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert L.scan()["changed"] == 1
    (src / "techdocs" / "avi-se-ha.md").unlink()
    assert L.scan()["removed"] == 1 and L.stats()["techdoc"] == 0
    hits = L.search_sync("vobd: [vob.storage.apd.start] Device or filesystem with identifier [naa.600a09803830] has entered the All Paths Down state",
                         "esxi", 3, "analyze", None, {"esxi": {"8.0", "8.x"}})
    top = hits[0]
    assert top["kb"] == "900001" and top["doc_id"].startswith("lib:") and "[해결]" in top["text"] and "esxcli storage core path list" in top["text"]
    assert top["sections"] == ["증상", "원인", "해결", "우회"] and top["versions"] == ["7.0", "8.0"]
    assert L.search_sync("Alarm edge_health.edge_datapath_cpu_high raised on edge04", "nsx-edge", 2)[0]["kb"] == "900003"
    assert L.search_sync("BGP neighbor down", "nsx", 3) == []                  # 근거 약하면 붙이지 않음


def test_feedback_reorders_for_same_pattern(tmp_path):
    L, _ = _lib(tmp_path)
    L.scan()
    q = "Service Engine heartbeat failure SE_DOWN virtual service placement"
    base = [h["doc_id"] for h in L.search_sync(q, "avi", 3)]
    assert len(base) >= 2
    first, second = base[0], base[1]
    L.feedback("sig1", int(first[4:]), -1, "op")
    L.feedback("sig1", int(second[4:]), 1, "op")
    again = [h["doc_id"] for h in L.search_sync(q, "avi", 3, sig="sig1")]
    assert again[0] == second
    assert [h["doc_id"] for h in L.search_sync(q, "avi", 3, sig="other")][0] == first        # 다른 패턴에는 영향 없음


class FakeEmb:
    enabled, model = True, "fake-64"

    async def embed(self, texts):
        m = np.zeros((len(texts), 64), np.float32)
        for i, t in enumerate(texts):
            for w in t.lower().split():
                m[i, hash(w.strip(".,:()[]`")) % 64] += 1
        m /= np.linalg.norm(m, axis=1, keepdims=True) + 1e-9
        return m


def test_embedding_incremental_and_dense(tmp_path):
    L, _ = _lib(tmp_path)
    L.embedder = FakeEmb()
    L.scan()
    n = asyncio.run(L.embed_pending(batch=5))
    st = L.stats()
    assert n == st["chunks"] and st["embedded"] == st["chunks"] and st["vector_model"] == "fake-64"
    assert asyncio.run(L.embed_pending()) == 0                                # 증분: 새 청크 없음
    qv = asyncio.run(FakeEmb().embed(["paths down storage device rescan adapters"]))[0]
    d = L._dense(qv, 5)
    assert d and isinstance(d[0][0], int)


def test_guard_kb_numbers():
    r = {"summary": "KB 900001 참고", "actions": ["KB 123456 의 절차 수행", "esxcli storage core adapter rescan --all"]}
    bad = guard_kb_numbers(r, [{"kb": "900001", "title": "x", "url": "", "text": ""}])
    assert bad == ["123456"] and "확인 필요" in r["actions"][0] and r["summary"] == "KB 900001 참고"


def test_import_zip_rejects_traversal(tmp_path):
    L = KnowledgeLibrary({}, str(tmp_path / "d"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("kb/kb_900001.md", (FX / "kb" / "kb_900001_apd.md").read_text())
        z.writestr("../../evil.md", "# evil")
        z.writestr("img.png", b"\x89PNG")
    info = L.import_zip(buf.getvalue(), "Broadcom KB 2026.zip")
    assert info["files"] == 2 and info["skipped"] == 1                       # ../ 는 경로에서 제거되어 업로드 폴더 안에만
    assert not (tmp_path / "evil.md").exists() and not (tmp_path / "d" / "evil.md").exists()
    assert L.scan()["changed"] >= 1 and L.stats()["roots"]


def test_ragmanager_merges_library_and_mcp(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.mcp_server import build_router
    from app.rag.store import RagManager
    L, _ = _lib(tmp_path)
    L.scan()
    rm = RagManager({"embedding": {"enabled": False}}, str(tmp_path / "rag"))
    rm.library = L
    assert rm.has_any()
    hits = asyncio.run(rm.search("SE_DOWN heartbeat", source="avi", k=3))
    assert hits and hits[0]["pack"] == "library"
    eng = NS(rag=rm, knowledge=L, anomalies={}, build="t")
    app = FastAPI()
    app.include_router(build_router(eng, {}))
    c = TestClient(app)
    init = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).json()
    assert init["result"]["serverInfo"]["name"] == "vcf-aiops"
    assert c.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202
    tools = c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()["result"]["tools"]
    assert {t["name"] for t in tools} == {"knowledge_search", "knowledge_get", "open_anomalies", "noc_status"}
    res = c.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                               "params": {"name": "knowledge_search", "arguments": {"query": "vob.storage.apd.start", "source": "esxi"}}}).json()
    txt = res["result"]["content"][0]["text"]
    assert "KB 900001" in txt and "<untrusted_document>" in txt
    did = txt.split("doc_id=")[1].split(" ")[0]
    full = c.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "knowledge_get", "arguments": {"doc_id": did}}}).json()
    assert "esxcli storage core adapter rescan" in full["result"]["content"][0]["text"]


# ── 수집기 아카이브 형식(vendor/product/kb/0NNNxxx/NNNNNN.md + _catalog 메타) — 가상의 KB 번호·문구 ──
ARC_KB = """---
doc_id: kb-990001
title: Hosts disconnect from vCenter with "FAKE_TLS_RECORD:bad record digest"
source: kb
article_id: 990001
vendor: vmware
product: vsphere
products:
- VMware vCenter Server
doc_type: troubleshooting
summary: ESXi hosts drop from inventory every few minutes and reconnect on their own.
error_signatures:
- "`FAKE_TLS_RECORD:bad record digest` on <timestamp> from 10.0.0.1"
updated: '2026-08-01'
url: https://knowledge.broadcom.com/external/article/990001
---
# Hosts disconnect from vCenter with "FAKE_TLS_RECORD:bad record digest"

> Product: VMware vCenter Server

- Hosts show Not Responding for a short time.
- vpxa.log shows the TLS record error.

VMware vCenter Server 8.0.x

VMware ESXi 8.0.x

A middlebox rewrites TLS records between vCenter and the host.

To resolve this issue, exclude port 902 from TLS inspection on the firewall.

Workaround: pin the host to a management VLAN that bypasses inspection.

Additional Information

Related to network appliances.

Yes

No
"""
ARC_JA = ARC_KB.replace("990001", "990002").replace("title: Hosts", "title: ホストが切断される Hosts").replace("summary: ESXi", "summary: ホストが ESXi")
ARC_CA = ARC_KB.replace("990001", "990003").replace("vendor: vmware", "vendor: ca").replace("product: vsphere", "product: apm")


def test_archive_format_segments_signatures_vendor_lang(tmp_path):
    src = tmp_path / "archive"
    for rel, txt in {"vmware/vsphere/kb/0990xxx/990001.md": ARC_KB, "vmware/vsphere/kb/0990xxx/990002.md": ARC_JA,
                     "ca/apm/kb/0990xxx/990003.md": ARC_CA, "_catalog/vsphere.md": ARC_KB.replace("990001", "990009"),
                     "README.md": "# Archive guide\n\n" + "explains folders " * 10}.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")
    d = parse_markdown(ARC_KB, "vmware/vsphere/kb/0990xxx/990001.md")
    roles = {s["role"]: s["text"] for s in d["sections"]}
    assert d["segmentation"] == "inferred" and d["kb"] == "990001" and d["product"] == "vsphere"
    assert "Not Responding" in roles["symptom"] and "8.0.x" in roles["env"] and "middlebox" in roles["cause"]
    assert "port 902" in roles["resolution"] and "management VLAN" in roles["workaround"]
    assert "Yes" not in roles.get("info", "") and "8.0" in d["versions"]
    assert d["signatures"] == ["FAKE_TLS_RECORD:bad record digest on <timestamp> from 10.0.0.1"]
    assert d["vendor"] == "vmware" and d["lang"] == "en" and parse_markdown(ARC_JA)["lang"] == "ja"

    L = KnowledgeLibrary({"paths": [str(src)], "embed": False}, str(tmp_path / "data"))
    L.scan()
    st = L.stats()
    assert st["docs"] == 3                       # _catalog·맨 위 README 제외
    # 로그 원문(숫자·주소가 다름) ↔ error_signatures 정확 일치 → 1위, 일본어 번역본·다른 사업부 문서는 뒤로
    hits = L.search_sync("2026-10-12T01:02:03Z vpxa[123] FAKE_TLS_RECORD:bad record digest on 2026-10-12 from 192.168.7.7", source="vcenter", k=3)
    assert hits[0]["kb"] == "990001" and hits[0]["relevance"] == 1.0
    assert [h["kb"] for h in hits] == ["990001", "990002", "990003"]
    assert hits[0]["doc_type"] == "troubleshooting" and "reconnect" in hits[0]["summary"]
    full = L.doc(int(hits[0]["doc_id"][4:]))
    assert full["segmentation"] == "inferred" and full["signatures"]
    rec = L.recent(days=3650, env={"vsphere": {"8.0", "8.x"}})
    assert [x["kb"] for x in rec] == ["990001"]                     # ja 번역본·ca 문서 제외
    assert rec[0]["applies"] and rec[0]["matched"] == ["8.0"]
    assert L.recent(days=3650, env={"vsphere": {"9.0", "9.x"}}, mine=True) == []


def test_save_single_md_file_indexes_immediately(tmp_path):
    import pytest
    L = KnowledgeLibrary({"embed": False}, str(tmp_path / "data"))
    r = L.save_file(ARC_KB.encode(), "990001.md", "vmware/vsphere/kb/0990xxx/990001.md", "manual")
    assert r["indexed"] and r["kb"] == "990001" and r["collection"] == "manual" and "해결" in r["sections"]
    assert (tmp_path / "data/knowledge/uploads/manual/vmware/vsphere/kb/0990xxx/990001.md").exists()
    hits = L.search_sync("FAKE_TLS_RECORD:bad record digest from 10.9.9.9", source="vcenter", k=1)
    assert hits and hits[0]["kb"] == "990001"
    r2 = L.save_file(ARC_KB.replace("port 902", "port 903").encode(), "990001.md", "vmware/vsphere/kb/0990xxx/990001.md")
    assert r2["changed"] and L.stats()["docs"] == 1                      # 같은 경로 = 덮어씀(문서 수 그대로)
    L.scan()
    assert L.stats()["docs"] == 1                                          # 다음 주기 색인과 충돌 없음
    for bad, rel in [(b"x" * 100, "a.pdf"), (ARC_KB.encode(), "../../etc/x.md"), (ARC_KB.encode(), "_catalog/x.md"), (b"short", "s.md")]:
        if rel.startswith(".."):
            out = L.save_file(bad, "x.md", rel)                            # .. 는 버리고 묶음 안에만 저장
            assert ".." not in out["saved"] and (tmp_path / "data/knowledge/uploads/manual/etc/x.md").exists()
            continue
        with pytest.raises(ValueError):
            L.save_file(bad, rel, rel)


def test_front_matter_fallback_keeps_lists_when_yaml_broken():
    from app.knowledge import _front_matter
    fm, body = _front_matter('---\ntitle: "Hosts fail with "X: y" error"\nproducts:\n- VMware vCenter Server\nerror_signatures:\n- "X: y"\nupdated: \'2026-10-10\'\n---\nbody')
    assert fm["title"] == 'Hosts fail with "X: y" error' and fm["products"] == ["VMware vCenter Server"]
    assert fm["error_signatures"] == ["X: y"] and fm["updated"] == "2026-10-10" and body == "body"


def test_korean_question_finds_english_kb(tmp_path):
    L = KnowledgeLibrary({"embed": False}, str(tmp_path / "d"))
    L.save_file(ARC_KB.encode(), "990001.md", "kb/990001.md")
    assert [h["kb"] for h in L.search_sync("호스트가 응답 없음 상태가 됐어 원인이 뭐야", source="vcenter", k=2, intent="chat")] == ["990001"]
    from app.knowledge import expand_query, kb_query_of
    assert "not responding" in expand_query("응답 없음") and expand_query("plain english") == "plain english"
    q = kb_query_of({"message": "vpxa failed", "entity": "esx01", "attrs": {"app": "vpxa"}}, ["원본 심각도 error/log", "규칙:host_conn", "신규 로그 패턴"])
    assert "host_conn" in q and "원본" not in q and "vpxa failed" in q


def test_pattern_cache_reanalyzes_once_after_knowledge_changes():
    from app.aipatterns import PatternStore
    ps = PatternStore.__new__(PatternStore)
    ps.enabled, ps.ttl, ps.stats, ps.dirty = True, 3600, {"reused": 0}, set()
    r = {"key": "p1", "analysis": {"summary": "x", "references": [], "_kgen": 3}, "analyzed_at": time.time(), "analyzed_sev": "error"}
    assert ps.cached(r, "error", kgen=3) is not None              # 지식 그대로 → 재사용
    assert ps.cached(r, "error", kgen=4) is None                  # 근거 없이 분석했는데 지식이 바뀜 → 다시 분석
    r["analysis"]["references"] = [{"ref": "R1"}]
    assert ps.cached(r, "error", kgen=9) is not None              # 근거가 있으면 계속 재사용


def test_kblinker_links_anomalies_and_incidents(tmp_path):
    from app.kblink import KbLinker
    from app.models import Anomaly
    from app.rag.store import RagManager
    L = KnowledgeLibrary({"embed": False}, str(tmp_path / "d"))
    L.save_file(ARC_KB.encode(), "990001.md", "kb/990001.md")
    rag = RagManager({"enabled": True}, str(tmp_path / "d"))
    rag.library = L
    saved, pub = [], []

    class Store:
        async def save_anomaly(self, d): saved.append(d["id"])
    a1 = Anomaly(id="A1", event={"source": "vcenter", "message": "vpxa FAKE_TLS_RECORD:bad record digest from 10.1.1.1", "entity": "esx01"},
                 severity="error", category="x", title="t", reasons=["규칙:host_conn"], score=1, status="rule_only")
    a2 = Anomaly(id="A2", event={"source": "vcenter", "message": "unrelated gibberish zzz"}, severity="warning", category="x", title="t",
                 reasons=[], score=1, status="analyzed", ai={"references": [{"ref": "R1", "title": "kept"}]})
    eng = NS(knowledge=L, rag=rag, anomalies={"A1": a1, "A2": a2}, store=Store(), hub=NS(publish=lambda m: pub.append(m)), llm=None)
    lk = KbLinker(eng, {})
    assert asyncio.run(lk.run_once()) == 1
    assert a1.related and a1.related[0]["kb"] == "990001" and a1.related_gen == L.gen and saved == ["A1"]
    assert a2.related == []                                        # AI 근거가 있는 카드는 건드리지 않음
    assert asyncio.run(lk.run_once()) == 0 and saved == ["A1"]     # 지식 그대로면 다시 찾지 않음
    L.save_file(ARC_KB.replace("990001", "990077").encode(), "990077.md", "kb/990077.md")   # 지식 세대 증가 → 다시 연결
    asyncio.run(lk.run_once())
    assert a1.related_gen == L.gen and {x["kb"] for x in a1.related} >= {"990001"}
    kb = asyncio.run(lk.for_incident({"id": "I1", "anomaly_ids": ["A1", "A2"], "title": "인시던트", "sources": ["vcenter"]}))
    assert kb and kb[0]["kb"] in ("990001", "990077") and kb[0]["matched_anomalies"] >= 1
