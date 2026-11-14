"""2.11.0 지원 요청(SR)·로그 내보내기 — 조건별 내보내기(가림)·SR 수집(인시던트·VKS·직접)·이메일·HTML·PDF(한글)·.eml·로그 묶음·공유 링크(만료·폐기·로그인)"""
import asyncio
import email
import email.policy
import io
import json
import time
import zipfile
from types import SimpleNamespace as NS

from app import logexport, support


def _engine(tmp_path):
    from app.config import DEFAULTS, _merge
    from app.engine import Engine
    return Engine(_merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}}))


async def _logs(e, rows):
    for i, (ts, src, sev, host, ent, msg) in enumerate(rows):
        await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (i, ts, src, "c1" if src != "vks" else "tkc1", sev, host, ent, "k8s-log" if src == "vks" else "log", msg, 0, "", "{}"))


def _rows(now):
    return [(now - 600, "esxi", "error", "esx01.lab", "esx01.lab", "vmkernel: NMP device naa.1 path dead password=hunter22"),
            (now - 500, "esxi", "warning", "esx01.lab", "esx01.lab", "vobd: APD start"),
            (now - 400, "vcenter", "info", "vc.lab", "vm-app01", "Task: Migrate vm-app01"),
            (now - 300, "esxi", "info", "esx02.lab", "esx02.lab", "heartbeat"),
            (now - 200, "vks", "error", "np-1", "Pod/pay/worker-1", "java.lang.OutOfMemoryError token=abcdef12")]


def test_logexport(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        await _logs(e, _rows(now))
        q = logexport.LogQuery(now - 3600, now, hosts=["esx01"])
        assert await logexport.count(e.store, q) == 2
        csv_b = b"".join([x async for x in logexport.stream(e.store, q, "csv")]).decode("utf-8-sig")
        assert "hunter22" not in csv_b and "<가림>" in csv_b and csv_b.splitlines()[0].startswith("ts,time,severity")
        txt = b"".join([x async for x in logexport.stream(e.store, logexport.LogQuery(now - 3600, now, min_severity="error"), "txt")]).decode()
        assert len(txt.strip().splitlines()) == 2 and "abcdef12" not in txt
        nd = [json.loads(x) for x in b"".join([x async for x in logexport.stream(e.store, logexport.LogQuery(now - 3600, now, entities=["Pod/pay/worker-1"]), "ndjson")]).decode().splitlines()]
        assert len(nd) == 1 and nd[0]["source"] == "vks"
        assert await logexport.count(e.store, logexport.LogQuery(now - 3600, now, sources=["esxi"], q="APD")) == 1
        z = zipfile.ZipFile(io.BytesIO(await logexport.build_zip(e.store, logexport.LogQuery(now - 3600, now), {"../../etc/x": "a"})))
        names = set(z.namelist())
        assert {"logs/all.csv", "logs/by-source/esxi.log", "logs/by-source/vks.log", "README.txt"} <= names and "etc/x" in names   # 경로 이탈 제거
        big = [(now - 1000 + i * 0.01, "esxi", "info", "esx09", "esx09", f"line {i}") for i in range(12000)]
        await _logs(e, big)
        n = 0
        async for _ in logexport.rows(e.store, logexport.LogQuery(now - 3600, now, hosts=["esx09"], max_rows=11000)):
            n += 1
        assert n == 11000                                              # 끊어 읽기(커서)·상한
    asyncio.run(main())


def _vks_conn():
    from tests.test_v2100_vksobs import FakeConn, _pods, _topo

    class C(FakeConn):
        async def pod_log(self, ns, pod, container="", tail=200, previous=False, since_time="", timestamps=False):
            return [f"{'prev' if previous else 'cur'} line db password=pw{pod}", "ERROR OOM"]
    return C(_topo(), _pods(True))


def test_sr_flow(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        await _logs(e, _rows(now))
        S = e.support
        await S.save_profile({"company": "KB국민은행", "contact_name": "홍길동", "contact_email": "ops@bank.example", "broadcom_site_id": "12345", "to": "sam@broadcom.example"})
        # 직접 작성
        r = await S.create({"kind": "manual", "title": "ESXi 경로 장애", "hosts": ["esx01.lab"], "since": now - 3600, "until": now, "severity": 2,
                            "description": "esx01 에서 스토리지 경로 끊김"}, {"user": "op1"}, {"vendor": "broadcom", "lang": "ko"})
        d = r["data"]
        assert r["id"].startswith("SR-") and d["severity"] == 2 and d["vendor_fields"]["priority"].startswith("High - P2") and d["vendor_fields"]["site_id"] == "12345"
        assert d["log_stats"]["rows"] == 2 and any("NMP" in s for s in d["symptoms"]) and all("hunter22" not in s for s in d["symptoms"])
        assert d["contact"]["company"] == "KB국민은행" and d["email"]["to"] == "sam@broadcom.example"
        body = S.email_text(r)
        for sec in ("1. 문제 요약", "3. 발생 시각", "5. 영향 받은 개체", "8. 확인한 내용", "9. 관련 KB·TechDocs", "10. 첨부·로그", "12. 연락처", "Site ID"):
            assert sec in body
        assert S.subject(r).startswith("[P2]")
        # 편집: 심각도·벤더·언어
        r = await S.update(r["id"], {"severity": 1, "requests": ["원인 분석"], "case_no": "36990011", "status": "submitted"}, {"user": "op1"})
        assert r["data"]["vendor_fields"]["production_down"] == "Yes" and r["status"] == "submitted"
        r = await S.update(r["id"], {"impact": "결제 승인 지연 — 고객 3만 명"}, {"user": "op1"})
        assert r["data"]["vendor_fields"]["business_impact"] == "결제 승인 지연 — 고객 3만 명"
        r = await S.update(r["id"], {"vendor": "aws", "lang": "en"}, {"user": "op1"})
        assert r["data"]["vendor_fields"]["severity"].startswith("Production system down") and "1. Problem summary" in S.email_text(r)
        r = await S.update(r["id"], {"vendor": "azure"}, {"user": "op1"})
        assert r["data"]["vendor_fields"]["severity"].startswith("Severity A")
        # 출력
        html = S.html(r, {"pdf": "/x.pdf", "logs": "/x.zip"})
        assert "ESXi 경로 장애" in html and "(KO) ESXi" in html and "x.zip" in html and "hunter22" not in html and "<script" not in html.lower()
        pdf = S.pdf(r)
        assert pdf[:5] == b"%PDF-" and len(pdf) > 5000
        from pypdf import PdfReader
        text = PdfReader(io.BytesIO(pdf)).pages[0].extract_text().replace(" ", "").replace("\x00", "")
        assert "ESXi경로장애" in text
        z = await S.logs_zip(r)
        names = set(zipfile.ZipFile(io.BytesIO(z)).namelist())
        assert {f"report-{r['id']}.pdf", f"report-{r['id']}.html", "summary.json", "logs/all.csv", f"email-{r['id']}.txt"} <= names
        m = email.message_from_bytes(S.eml(r, pdf, z), policy=email.policy.default)
        assert m["X-Unsent"] == "1" and m["To"] == "sam@broadcom.example" and {p.get_filename() for p in m.iter_attachments()} == {f"report-{r['id']}.pdf", f"logs-{r['id']}.zip"}
        # 다시 모으기 — 편집 유지
        r2 = await S.refresh(r["id"])
        assert r2["data"]["case_no"] == "36990011" and r2["data"]["requests"] == ["원인 분석"] and r2["data"]["vendor"] == "azure"
        # 공유
        s = await S.share_create(r["id"], "op1", days=1)
        assert (await S.share_resolve(s["token"]))[1]["id"] == r["id"]
        assert await S.share_resolve("x" * 43) is None and await S.share_resolve("../etc") is None
        assert await S.share_revoke(r["id"], s["id"]) and await S.share_resolve(s["token"]) is None
        s2 = await S.share_create(r["id"], "op1", days=1)
        await e.store.x("UPDATE support_shares SET expires=? WHERE id=?", (time.time() - 1, s2["id"]))
        assert await S.share_resolve(s2["token"]) is None
        rows = await e.store.q("SELECT token_hash FROM support_shares")
        assert all(len(x["token_hash"]) == 64 and s["token"] not in x["token_hash"] for x in rows)    # 토큰 원문 미저장
        assert [x["id"] for x in await S.list()] == [r["id"]]
    asyncio.run(main())


def test_sr_from_incident_and_vks(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        await _logs(e, _rows(now))
        from app.models import Anomaly
        a = Anomaly(id="a1", event={"ts": now - 600, "source": "esxi", "host": "esx01.lab", "entity": "esx01.lab", "message": "NMP path dead password=x1secret"},
                    severity="error", category="storage", title="경로 장애", reasons=["signature:nmp"], score=0.9)
        e.anomalies["a1"] = a
        inc = await e.incidents.create_manual("esx01 스토리지 경로 장애", "error", "op1", ["a1"])
        inc["hosts"] = ["esx01.lab"]
        await e.incidents._save(inc)
        await e.incidents.comment(inc["id"], "HBA 펌웨어 확인 — 최신", "op1")
        r = await e.support.create({"kind": "incident", "ref": inc["id"]}, {"user": "op1"}, {})
        d = r["data"]
        assert d["severity"] == 2 and d["title"] == "esx01 스토리지 경로 장애" and any("HBA 펌웨어" in c["text"] for c in d["checked"])
        assert any(o["name"] == "esx01.lab" for o in d["objects"]) and d["log_query"]["hosts"][0] == "esx01.lab" and d["links"]["incident"].endswith(inc["id"])
        ra = await e.support.create({"kind": "anomaly", "ref": "a1"}, {"user": "op1"}, {"vendor": "generic"})
        assert ra["data"]["symptoms"] and "x1secret" not in ra["data"]["symptoms"][0]
        # VKS
        conn = _vks_conn()
        e.connectors = [conn]
        rv = await e.support.create({"kind": "vks", "connector": "tkc1", "okind": "Deployment", "ns": "pay", "obj": "worker"}, {"user": "op1"}, {})
        dv = rv["data"]
        assert dv["severity"] == 2 and "CrashLoopBackOff" in " ".join(dv["symptoms"]) and dv["log_query"]["connectors"] == ["tkc1"]
        af = dv["attach_files"]
        assert any(k.endswith("worker-1a-x/api.previous.log") for k in af) and all("pwworker" not in v for v in af.values())
        z = zipfile.ZipFile(io.BytesIO(await e.support.logs_zip(rv)))
        assert any(n.startswith("pod-logs/pay/worker-1a-x/") for n in z.namelist())
        # AI 다듬기 — 가명화 이름 전달
        seen = {}

        async def complete(system, user, max_tokens=800, task="brief", names=None):
            seen["names"], seen["user"] = names, user
            return '{"title": "VKS worker CrashLoop", "summary": "s", "impact": "i", "requests": ["a", "b"]}'
        e.llm = NS(complete=complete)
        p = await e.support.refine(rv)
        assert p["title"] == "VKS worker CrashLoop" and p["requests"] == ["a", "b"] and "pay/worker" in seen["names"]
    asyncio.run(main())


def test_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app import api_support
    e = _engine(tmp_path)
    now = time.time()
    asyncio.run(_logs(e, _rows(now)))
    app = FastAPI()
    log = []

    async def audit(req, action, target="", result="ok", detail=None):
        log.append(action)
    sess = {"s": None}
    auth = NS(enabled=True, session=lambda req: sess["s"])
    app.include_router(api_support.build_router(e, auth, {"server": {"public_url": "https://aiops.bank.local"}}, lambda req: {"user": "op1", "role": "operator"}, audit))
    c = TestClient(app)
    m = c.get("/api/support/meta").json()
    assert set(m["vendors"]) == {"broadcom", "aws", "azure", "generic"} and m["vendors"]["aws"]["sev"]["1"]["code"] == "urgent"
    assert c.post("/api/support/requests", json={"source": {"kind": "nope"}}).status_code == 400
    assert c.post("/api/support/requests", json={"source": {"kind": "incident", "ref": "INC-x"}}).status_code == 404
    r = c.post("/api/support/requests", json={"source": {"kind": "manual", "title": "t1", "hosts": ["esx01.lab"], "since": now - 3600, "until": now}, "vendor": "broadcom"}).json()
    sid = r["id"]
    assert r["email"]["subject"] and r["links"]["pdf"].endswith("report.pdf")
    assert c.get(f"/api/support/requests/{sid}/report.pdf").content[:5] == b"%PDF-"
    assert c.get(f"/api/support/requests/{sid}/logs.zip").headers["content-type"] == "application/zip"
    assert c.get(f"/api/support/requests/{sid}/email.eml").headers["content-type"].startswith("message/rfc822")
    assert "t1" in c.get(f"/api/support/requests/{sid}/report.html").text
    sh = c.post(f"/api/support/requests/{sid}/share", json={"days": 2, "include_logs": False}).json()
    assert sh["url"].startswith("https://aiops.bank.local/share/sr/") and "token" not in sh
    path = sh["url"].replace("https://aiops.bank.local", "")
    pg = c.get(path)
    assert pg.status_code == 200 and "t1" in pg.text and "logs.zip" not in pg.text and "default-src 'none'" in pg.headers["content-security-policy"]
    assert c.get(path + "/report.pdf").status_code == 200 and c.get(path + "/logs.zip").status_code == 403
    sh2 = c.post(f"/api/support/requests/{sid}/share", json={"require_login": True}).json()
    p2 = sh2["url"].replace("https://aiops.bank.local", "")
    rr = c.get(p2, follow_redirects=False)
    assert rr.status_code in (302, 307) and rr.headers["location"].startswith("/login?next=")
    sess["s"] = {"user": "viewer1"}
    assert c.get(p2).status_code == 200 and c.get(p2 + "/logs.zip").status_code == 200
    assert c.delete(f"/api/support/requests/{sid}/share/{sh['id']}").status_code == 200 and c.get(path).status_code == 404
    up = c.put(f"/api/support/requests/{sid}", json={"severity": 1, "title": "t2"}).json()
    assert up["data"]["title"] == "t2" and up["email"]["subject"].startswith("[P1]")
    ex = c.get("/api/logs/export", params={"format": "csv", "minutes": 60, "host": "esx01"})
    assert ex.status_code == 200 and "attachment" in ex.headers["content-disposition"] and "hunter22" not in ex.text
    assert c.get("/api/logs/export/count", params={"minutes": 60, "min_severity": "error"}).json()["rows"] == 2
    assert zipfile.ZipFile(io.BytesIO(c.get("/api/logs/export", params={"format": "zip", "minutes": 60}).content)).namelist()
    assert c.get("/api/logs/export", params={"since": now, "until": now - 10}).status_code == 400
    assert {"support.create", "support.share", "support.share_revoke", "logs.export", "support.download"} <= set(log)
    assert c.delete(f"/api/support/requests/{sid}").status_code == 200 and c.get(p2).status_code == 404


def test_route_rules():
    from app.security.auth import PUBLIC, AuthManager
    assert PUBLIC.match("/share/sr/" + "A" * 43) and PUBLIC.match("/share/sr/" + "A" * 43 + "/logs.zip") and not PUBLIC.match("/share/sr/short")
    assert not PUBLIC.match("/share/sr/" + "A" * 43 + "/../api/x")
    rp = AuthManager.required_perm
    assert rp("GET", "/api/support/requests") == "view" and rp("POST", "/api/support/requests") == "operate"
    assert rp("PUT", "/api/support/profile") == "settings" and rp("POST", "/api/support/requests/SR-1/share") == "operate"
    assert rp("GET", "/api/logs/export") == "view"
