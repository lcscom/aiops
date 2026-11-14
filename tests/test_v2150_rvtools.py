"""2.15.0 RVTools 분석 — xlsx 읽기·정규화·기존 엔진 재사용(stack·vcheck·assess)·RVTools 점검·VCF 9·구성도·내보내기·가명화·API·권한 (합성 데이터만 사용)"""
import io
import json
import zipfile
from datetime import datetime
from types import SimpleNamespace as NS

import pytest

from app.llm import Masker
from app.rvtools import analyze as A
from app.rvtools import model as Mdl
from app.rvtools import report as RP
from app.rvtools import xlsx as X
from tests.rvtools_fake import VC, build
from tests.test_v2110_support import _engine


@pytest.fixture(scope="module")
def inv():
    return Mdl.normalize(X.read(build()))


def _ids(res):
    return {f["id"] for f in res["findings"]}


def test_xlsx_reader_shared_strings_and_dates():
    """공유 문자열·불리언·날짜 서식(내장 22 + 사용자 서식)·빈 칸 열 위치"""
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w")
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    z.writestr("xl/workbook.xml", f'<workbook {ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="vInfo" sheetId="1" r:id="rId1"/></sheets></workbook>')
    z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
    z.writestr("xl/sharedStrings.xml", f'<sst {ns}><si><t>VM</t></si><si><t>Created</t></si><si><r><t>Pow</t></r><r><t>er</t></r></si><si><t>Day</t></si><si><t>vm-a</t></si></sst>')
    z.writestr("xl/styles.xml", f'<styleSheet {ns}><numFmts><numFmt numFmtId="164" formatCode="yyyy/mm/dd"/></numFmts><cellXfs><xf numFmtId="0"/><xf numFmtId="22"/><xf numFmtId="164"/></cellXfs></styleSheet>')
    z.writestr("xl/worksheets/sheet1.xml", f'<worksheet {ns}><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c></row>'
               '<row r="2"><c r="A2" t="s"><v>4</v></c><c r="B2" s="1"><v>46037.5</v></c><c r="D2" s="2"><v>46037</v></c></row><row r="3"><c r="C3" t="b"><v>1</v></c></row></sheetData></worksheet>')
    z.close()
    sh = X.read(buf.getvalue())["vInfo"]
    assert sh[0]["VM"] == "vm-a" and sh[0]["Power"] is None and sh[0]["Created"] == datetime(2026, 1, 15, 12, 0) and sh[0]["Day"] == datetime(2026, 1, 15)
    assert sh[1]["Power"] is True
    with pytest.raises(X.XlsxError):
        X.read(b"not a zip")
    with pytest.raises(ValueError):
        Mdl.normalize(X.read(buf.getvalue()))           # vHost 시트 없음


def test_normalize(inv):
    assert set(inv["hosts"]) == {"esx01.example.test", "esx02.example.test"} and inv["hosts"]["esx02.example.test"]["version"] == "7.0.3"
    assert inv["hosts"]["esx02.example.test"]["build"] == "21424296" and inv["vcenters"][VC]["version"] == "8.0.3"
    v = inv["vms"]["db01"]
    assert v["vcpu"] == 16 and v["mem_limit"] == 32768 and v["cpu_ready"] == 25 and v["networks"] == ["pg-app"] and v["tools"] == "toolsOk"
    assert inv["vms"]["tpl-rhel9"]["template"] is True and inv["meta"]["rvtools"] == "4.7.1.4" and inv["meta"]["exported"]
    assert inv["networks"]["vds-01-DVUplinks"]["uplink_pg"] and inv["networks"]["pg-app"]["vm_count"] == 6
    assert inv["vmks"][0]["services"] == ["vmotion"]              # 포트그룹 이름으로 추정
    assert {p["dead"] for p in inv["paths"] if p["host"] == "esx02.example.test"} == {1}


def test_analyze_reuses_existing_rules(inv):
    res = A.analyze(inv)
    ids = _ids(res)
    # 기존 vcheck 규칙(인프라 점검)
    assert {"C06", "C08", "C03", "C05", "C09", "N01", "N02", "N03", "S01", "S04", "S05"} <= ids
    s04 = [f for f in res["findings"] if f["id"] == "S04"]
    assert any(f["severity"] == "error" and "dead" in f["title"] for f in s04)
    assert any("단일 경로" in f["title"] and "ds-san-02" in f["detail"] and "local" not in f["detail"] for f in s04)    # 로컬 컨트롤러 단일 경로 제외
    assert not any(f["id"] == "S08" for f in res["findings"])          # 경로 없는 offline 예비 FC 포트는 오류 아님 → RV-19(정보)
    # RVTools 전용
    assert {"RV-01", "RV-04", "RV-05", "RV-07", "RV-08", "RV-09", "RV-10", "RV-13", "RV-14", "RV-15", "RV-19", "RV-20", "RV-21", "RV-26", "RV-27"} <= ids
    assert not ({"RV-06", "RV-25"} & ids)                              # vcheck S05·N03 와 중복 없음
    assert "app02" in next(f for f in res["findings"] if f["id"] == "RV-01")["detail"]
    assert next(f for f in res["findings"] if f["id"] == "RV-13")["severity"] == "warning"   # Win2008 은 이미 지원 종료
    # VCF 9 — 하드웨어 준비도와 같은 CPU 규칙(KB 428874)
    v9 = {h["host"]: h for h in res["vcf9"]["hosts"]}
    assert v9["esx02.example.test"]["verdict"] == "not_ready" and v9["esx02.example.test"]["cpu_status"] == "fail"
    assert v9["esx01.example.test"]["cpu_status"] == "pass" and v9["esx01.example.test"]["licensed_cores"] == 64
    assert v9["esx02.example.test"]["licensed_cores"] == 32                                 # CPU 당 최소 16코어
    assert {"VCF-01", "VCF-02", "VCF-03", "VCF-04"} <= ids
    assert any(f["ref"].endswith("418259") for f in res["findings"] if f["id"] == "VCF-02")
    # KISA — RVTools 로 안 보이는 항목은 MANUAL(지어내지 않음)
    hc = res["hardening"]["counts"]
    assert hc.get("MANUAL", 0) > 10 and res["hardening"]["kisa"] and "현장 확인" in res["hardening"]["note"]
    assert 0 <= res["score"] <= 100 and res["counts"]["error"] >= 5
    sm = res["summary"]
    assert sm["counts"]["vms"] == 5 and sm["counts"]["templates"] == 1 and sm["compute"]["cores"] == 92
    cl = sm["clusters"][0]
    assert cl["name"] == "CL1" and cl["n1_mem_pct"] > cl["mem_used_pct"]


def test_vmsa_with_advisories(inv):
    """보안 판독의 권고 DB(가져오기 정규화 형식) → RVTools 빌드로 VMSA 판정"""
    adv = [{"id": "VMSA-2099-0001", "title": "fake", "severity": "CRITICAL", "cvss": 9.8, "published": "2099-01-01", "url": "https://example.test/a", "cves": ["CVE-2099-0001"],
            "vmsa": ["VMSA-2099-0001"], "matches": [{"product": "esxi", "branch": "7.0", "fixed_build": 99999999, "fixed_version": "7.0 U3z"}]}]
    res = A.analyze(inv, adv)
    v = res["vmsa"]
    assert v["db"] == 1 and v["vulnerable"] == 1 and v["rows"][0]["target"] == "esx02.example.test" and v["rows"][0]["verdict"] == "취약"


def test_graphs(inv):
    g = A.graph_physical(inv)
    kinds = {n["kind"] for n in g["nodes"]}
    assert {"vcenter", "datacenter", "cluster", "esxi", "pnic", "hba", "vds", "mpath", "datastore", "portgroup"} <= kinds
    ids = {n["id"] for n in g["nodes"]}
    assert "nic:esx02.example.test:vmnic5" not in ids                 # 미할당·미연결 예비 NIC 생략
    assert "hba:esx01.example.test:vmhba3" not in ids                 # 경로 없는 offline FC 포트 생략
    assert next(n for n in g["nodes"] if n["id"] == "nic:esx02.example.test:vmnic1")["state"] == "down"
    assert next(n for n in g["nodes"] if n["id"] == "path:esx02.example.test:ds-san-01")["state"] == "down"
    assert all(l["s"] in ids and l["t"] in ids for l in g["links"])
    lg = A.graph_logical(inv, 0)                                       # 기존 stack.build 로직
    assert lg["counts"]["esxi"] == 2 and lg["counts"]["vds"] >= 1 and lg["counts"]["vm"] >= 4
    st = A.graph_storage(inv)
    sk = {n["id"]: n for n in st["nodes"]}
    assert sk["ds:ds-san-01"]["state"] == "warn" and "vm:db01" in sk and any(l["t"] == "vm:db01" and l["s"] == "ds:ds-san-02" for l in st["links"])


def test_ai_digest_and_masking(inv):
    res = A.analyze(inv)
    d = A.ai_digest(inv, res)
    j = json.loads(d)
    assert j["환경"]["수량"]["hosts"] == 2 and j["주요 이슈"] and "VCF9 준비도" in j
    names = A.names_of(inv)
    assert "db01" in names and "esx01.example.test" in names and "CL1" in names and all(len(x) >= 3 for x in names)
    mk = Masker(names)
    m = mk.mask(d)
    assert "db01" not in m and "esx01.example.test" not in m and "legacy01" not in m and "10.0.2.11" not in m
    assert mk.unmask(m) == d
    rows = A.search_rows(inv, "db01 성능은?")
    assert rows and rows[0].startswith("VM db01")


def test_exports(inv):
    res = A.analyze(inv)
    meta = {"name": "t.xlsx", "ai": {"report": "## 종합 의견\n| a | b |\n|---|---|\n| <x> | 2 |\n- **굵게**", "provider": "p", "at": 1}}
    x = RP.xlsx(meta, inv, res)
    back = X.read(x)
    assert set(back) == {"요약", "점검 결과", "KISA", "VMSA", "VCF 9", "클러스터", "호스트", "VM", "데이터스토어"}
    assert any(r["점검"] == "RV-01" for r in back["점검 결과"]) and len(back["VM"]) == 6
    h = RP.report_html(meta, inv, res)
    assert "RVTools 분석 보고서" in h and "&lt;x&gt;" in h and "<x>" not in h and "<b>굵게</b>" in h and "KB 418259" in h


def test_manager_and_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_rvtools import build_router
    from app.security.auth import AuthManager
    e = _engine(tmp_path)
    calls = []

    class FakeLLM:
        def order(self, task):
            return [NS(name="pais", model="pais-agent")]

        async def complete(self, system, user, max_tokens=800, task="brief", names=None):
            calls.append(("complete", task, names, user))
            return "## 종합 의견\n테스트"

        async def chat_stream(self, question, context, lang=None, names=None, system=None):
            calls.append(("ask", question, names, context, system))
            for t in ["결론: ", "db01 ", "확인"]:
                yield t
    e.llm = FakeLLM()
    logs = []

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append((action, target, detail))
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda req: {"user": "op1", "role": "operator"}, audit))
    raw = build()
    with TestClient(app) as cl:
        r = cl.post("/api/rvtools/upload?name=..%2F..%2Fcustomer%2FRV.xlsx", content=raw, headers={"Content-Type": "application/octet-stream"})
        assert r.status_code == 200, r.text
        j = r.json()
        iid = j["id"]
        assert j["name"] == "RV.xlsx" and j["counts"]["hosts"] == 2 and j["vcenters"] == [VC]
        assert cl.post("/api/rvtools/upload", content=b"PK\x03\x04junk").status_code == 400
        assert cl.post("/api/rvtools/upload", content=b"hello").status_code == 400
        lst = cl.get("/api/rvtools").json()
        assert lst["llm"] and lst["items"][0]["id"] == iid
        d = cl.get(f"/api/rvtools/{iid}").json()
        assert d["summary"]["counts"]["vms"] == 5 and d["findings"] and d["vcf9"]["hosts"]
        for k in ("physical", "logical", "storage"):
            g = cl.get(f"/api/rvtools/{iid}/graph/{k}").json()
            assert g["nodes"] and g["links"]
        assert cl.get(f"/api/rvtools/{iid}/graph/xx").status_code == 404
        assert len(cl.get(f"/api/rvtools/{iid}/table/vms").json()["items"]) == 6
        assert cl.get(f"/api/rvtools/{iid}/table/meta").status_code == 404
        assert cl.get(f"/api/rvtools/{iid}/report.xlsx").content[:2] == b"PK"
        h = cl.get(f"/api/rvtools/{iid}/report.html")
        assert h.status_code == 200 and "default-src 'none'" in h.headers["content-security-policy"]
        ai = cl.post(f"/api/rvtools/{iid}/ai/report").json()
        assert ai["report"].startswith("## 종합 의견") and ai["provider"] == "pais · pais-agent"
        c0 = next(c for c in calls if c[0] == "complete")
        assert c0[1] == "report" and "db01" in c0[2] and "RVTools 분석 집계" in c0[3]           # 가명화 대상 이름 전달
        assert cl.get(f"/api/rvtools/{iid}").json()["meta"]["ai"]["report"]                  # 저장됨
        sse = cl.post(f"/api/rvtools/{iid}/ask", json={"question": "db01 성능 문제 있어?"}).text
        assert '"t": "결론: "' in sse and sse.rstrip().endswith("[DONE]")
        c1 = next(c for c in calls if c[0] == "ask")
        assert "VM db01" in c1[3] and "RV-08" in c1[3] and "RVTools" in c1[4] and "db01" in c1[2]
        assert cl.post(f"/api/rvtools/{iid}/ask", json={"question": ""}).status_code == 400
        assert cl.post(f"/api/rvtools/{iid}/reanalyze").json()["score"] == d["score"]
        assert {a for a, *_ in logs} >= {"rvtools.upload", "rvtools.ai_report", "rvtools.ask", "rvtools.export", "rvtools.reanalyze"}
        assert cl.delete(f"/api/rvtools/{iid}").json()["ok"] and cl.get(f"/api/rvtools/{iid}").status_code == 404
    # 권한: 조회 view, 업로드·AI·질문·삭제 operate
    rp = AuthManager.required_perm
    assert rp("GET", "/api/rvtools") == "view" and rp("GET", "/api/rvtools/x/graph/physical") == "view"
    assert rp("POST", "/api/rvtools/upload") == "operate" and rp("POST", "/api/rvtools/x/ask") == "operate" and rp("DELETE", "/api/rvtools/x") == "operate"


def test_raw_not_stored_and_retention(tmp_path):
    import asyncio

    from app.rvtools.manager import RvToolsManager
    e = _engine(tmp_path)
    M = RvToolsManager(e, {"retention": 2, "max_mb": 1})
    raw = build()

    async def main():
        ids = [(await M.upload(raw, "a.xlsx", "u"))["id"] for _ in range(3)]
        lst = await M.list()
        assert [x["id"] for x in lst] == ids[::-1][:2]
        blob = await e.store.q1("SELECT inv, res, summary FROM rv_imports WHERE id=?", (ids[-1],))
        assert raw not in bytes(blob["inv"]) and b"PK\x03\x04" not in bytes(blob["inv"]) + bytes(blob["res"])
        with pytest.raises(ValueError):
            await M.upload(b"PK" + b"0" * (1024 * 1024 + 1), "big.xlsx", "u")
    asyncio.run(main())
