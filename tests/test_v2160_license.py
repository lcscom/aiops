"""2.16.0 라이선스 관리 — 공급자·CSP 엑셀 파싱, VCF Ops 사용량 파일, vCenter·RVTools 실사용, 키 매칭·점검, 프로젝트·할당, API·권한·키 가림 (합성 데이터만)"""
import asyncio
import base64
import gzip
import json
from datetime import date, timedelta

import pytest

from app.license import util as U
from app.readiness.export import xlsx
from tests.rvtools_fake import KEY_PERP, KEY_TERM, VC
from tests.rvtools_fake import build as rv_build
from tests.test_v2110_support import _engine

K_CSP_ONLY = "Z9Z9Z-Y8Y8Y-X7X7X-W6W6W-CSPON"
K_EXPIRED = "E1E1E-E2E2E-E3E3E-E4E4E-EXPRD"


def _d(n):
    return (date.today() + timedelta(days=n)).isoformat()


def supplier_xlsx():
    cols = ["Serial Number", "Parent Customer", "Customer Name", "License Key", "License Type", "Product Name", "Quantity - ENT", "Contract Status",
            "Start Date", "End Date", "ERP Site ID", "Enduser Account Name", "Part Number", "Division"]
    rows = [["S-001", "Group", "Cust A", KEY_PERP, "Perpetual", "VMware vSphere 8 Enterprise Plus", "8", "Active", "2023-01-01", "", "E1", "Cust A", "P1", "D"],
            ["S-002", "Group", "Cust A", KEY_TERM, "Subscription", "VMware vSphere Foundation", "256", "Active", "2025-01-01", _d(40), "E1", "Cust A", "P2", "D"],
            ["", "Group", "Cust B", "", "", "x", "1", "", "", "", "", "", "", ""]]
    return xlsx([("Sheet1", [cols] + rows)])


def csp_xlsx(extra=()):
    cols = ["License Key", "Product Name", "Quantity", "Folder Name", "Contract End Date"]
    rows = [[KEY_TERM, "VMware vSphere Foundation", "48 Core", "Folder-A", _d(400)],
            [KEY_PERP, "VMware vSphere 8 Enterprise Plus", "8 Processor", "Folder-A", ""],
            [K_CSP_ONLY, "VMware vSAN", "32 TiB", "Folder-B", _d(10)], *extra]
    return xlsx([("AllLicenseKeys", [cols] + rows)])


def _jws(payload: dict) -> str:
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJub25lIn0.{seg}.sig"


def usage_file(days_ago=10, wrapped=True):
    import time
    end = int((time.time() - days_ago * 86400) * 1000)
    a1 = _jws({"asset_id": "vc-1", "license_usage_data": [
        {"allocation_id": "al1", "product_name": "VMware Cloud Foundation", "uom": "CORE", "quantity": 96, "usage_end_time": end - 1000},
        {"allocation_id": "al1", "product_name": "VMware Cloud Foundation", "uom": "CORE", "quantity": 128, "usage_end_time": end},       # 최신만
        {"allocation_id": "al2", "product_name": "VMware vSAN", "uom": "TIB", "quantity": 20, "usage_end_time": end}]})
    a2 = _jws({"asset_id": "vc-2", "license_usage_data": [
        {"allocation_id": "al1", "product_name": "VMware Cloud Foundation", "uom": "CORE", "quantity": 64, "usage_end_time": end}]})
    z = gzip.compress(_jws({"jws_child_asset_usages": [a1, a2]}).encode())
    if not wrapped:
        return z
    return json.dumps({"gzipJwsEncodedData": base64.b64encode(z).decode(), "fileName": "usage.gzip", "timestamp": end}).encode()


def test_util():
    assert U.mask_key(KEY_TERM) == "*****-*****-*****-*****-TERM1" and U.mask_key("") == ""
    assert U.split_qty("1,432 Core") == (1432, "Core") and U.split_qty("32 TiB") == (32, "TiB") and U.split_qty(None) == (0, "")
    assert U.category("cpuPackage:32core") == "perpetual" and U.category("cpuCore:16core") == "term" and U.category("server") == "other"
    assert U.licensed_cores(2, 24) == 32 and U.licensed_cores(2, 64) == 64 and U.licensed_cores(1, 8) == 16      # CPU 당 최소 16코어
    assert U.to_date("10/27/27 12:00:00 AM") == "2027-10-27" and U.to_date("Never") is None
    rows, errs = U.parse_supplier(supplier_xlsx())
    assert len(rows) == 2 and errs and rows[0]["license_type"] == "PERPETUAL" and rows[1]["quantity"] == 256 and rows[1]["end_date"] == _d(40)
    c, _ = U.parse_csp(csp_xlsx())
    assert c[0]["quantity"] == 48 and c[0]["unit"] == "Core" and c[2]["unit"] == "TiB"
    with pytest.raises(ValueError):
        U.parse_csp(xlsx([("x", [["a", "b"], [1, 2]])]))
    for raw in (usage_file(), usage_file(wrapped=False), gzip.decompress(usage_file(wrapped=False))):
        rep = U.parse_usage(raw)
        p = {(x["product"], x["uom"]): x for x in rep["products"]}
        assert p[("VMware Cloud Foundation", "CORE")]["quantity"] == 192 and p[("VMware Cloud Foundation", "CORE")]["assets"] == 2
        assert p[("VMware vSAN", "TIB")]["quantity"] == 20 and rep["assets"] == 2 and rep["usage_end"]


class FakeVC:
    type = "vcenter"
    name = "vc-lab"

    def collect_licenses(self):
        return {"vcenter": "vc-lab", "version": "8.0.3", "error": "", "licenses": [
            {"key": KEY_TERM, "name": "vSphere 8 Enterprise Plus for VCF", "cost_unit": "cpuCore", "total": 48, "used": 96, "expires": _d(400)},
            {"key": K_EXPIRED, "name": "vSphere 7 Standard", "cost_unit": "cpuPackage", "total": 4, "used": 2, "expires": _d(-5)},
            {"key": U.EVAL_KEY, "name": "Evaluation Mode", "cost_unit": "", "total": 0, "used": 0, "expires": None}],
            "hosts": [{"host": "h1.lab", "cluster": "c1", "sockets": 2, "cores": 24, "license_key": KEY_TERM, "license_name": "vSphere 8 EP for VCF", "cost_unit": "cpuCore"},
                      {"host": "h2.lab", "cluster": "c1", "sockets": 2, "cores": 64, "license_key": KEY_TERM, "license_name": "vSphere 8 EP for VCF", "cost_unit": "cpuCore"},
                      {"host": "h3.lab", "cluster": "c2", "sockets": 2, "cores": 16, "license_key": K_EXPIRED, "license_name": "vSphere 7 Std", "cost_unit": "cpuPackage"},
                      {"host": "h4.lab", "cluster": "c2", "sockets": 1, "cores": 8, "license_key": "", "license_name": "", "cost_unit": ""}]}


def test_manager_end_to_end(tmp_path):
    e = _engine(tmp_path)
    e.connectors = [FakeVC()]
    M = e.license

    async def main():
        s1 = await M.upload("supplier", supplier_xlsx(), "sup.xlsx", "u")
        assert s1["inserted"] == 2 and s1["skipped"] == 1
        s2 = await M.upload("supplier", supplier_xlsx(), "sup2.xlsx", "u")                       # 같은 Serial → 갱신
        assert s2["updated"] == 2 and s2["inserted"] == 0
        c1 = await M.upload("csp", csp_xlsx(), "AllLicenseKeys.xlsx", "u")
        assert c1["rows"] == 3
        p = await M.save_project({"name": "고객 A", "location": "DC1"}, "u")
        with pytest.raises(ValueError):
            await M.save_project({"name": "고객 A"}, "u")
        assert await M.assign(p["id"], "csp", [], {"folder": "Folder-A"}) == 2
        await M.upload("csp", csp_xlsx(), "AllLicenseKeys.xlsx", "u")                            # 같은 이름 → 대체, 할당 유지
        assert len(await M.data("csp", None)) == 3 and len(await M.data("csp", p["id"])) == 2
        assert len([b for b in await M.batches() if b["kind"] == "csp"]) == 1
        r = await M.collect_vcenter(by="u")
        assert r[0]["hosts"] == 4 and not r[0]["error"]
        await M.assign(p["id"], "source", ["vcenter:vc-lab"])
        await M.assign(p["id"], "supplier", ["S-001", "S-002"])
        u = await M.upload("vcfops", usage_file(days_ago=170), "usage.gzip", "u")
        await M.assign(p["id"], "source", [u["source"]])
        o = await M.overview(p["id"])
        ids = {c["id"] for c in o["checks"]}
        assert {"LIC-01", "LIC-03", "LIC-04", "LIC-06", "LIC-08", "LIC-09", "LIC-10", "LIC-11"} <= ids, ids
        assert not any(c["id"] == "LIC-02" and "Evaluation" in c["entity"] for c in o["checks"])
        lic08 = next(c for c in o["checks"] if c["id"] == "LIC-08")
        assert "+8코어" in lic08["title"] and "h1.lab" in lic08["detail"]          # h1: 2×12코어 → 2×16 = 32 (+8)
        m = await M.data("match", p["id"], full=True)
        by = {x["license_key"]: x for x in m}
        assert by[KEY_TERM]["status"] == "matched" and by[KEY_TERM]["over"] and by[KEY_TERM]["inv_qty"] == 32 + 64
        assert by[K_EXPIRED]["status"] == "inventory_only" and by[KEY_PERP]["status"] == "csp_only"
        assert U.EVAL_KEY not in by
        masked = await M.data("match", p["id"])
        assert all("*****" in x["license_key"] for x in masked) and KEY_TERM not in json.dumps(masked)
        sm = o["summary"]
        assert sm["inventory"]["by_category"]["term"]["qty"] == 96 and sm["inventory"]["by_category"]["perpetual"]["qty"] == 2
        assert sm["inventory"]["by_category"]["unlicensed"]["hosts"] == 1 and sm["usage"]["products"]["VMware Cloud Foundation (CORE)"] == 192
        ps = await M.project_summaries()
        assert any(x["name"] == "고객 A" for x in ps) and any(x["name"] == "(미할당)" for x in ps)
        # RVTools 분석에서 가져오기(키 포함)
        rvm = await e.rvtools.upload(rv_build(), "rv.xlsx", "u")
        out = await M.import_rvtools(rvm["id"], "u")
        assert out["hosts"] == 2 and out["licenses"] == 2
        hs = [h for h in await M.data("hosts", "", full=True) if h["source"].startswith("rvtools:")]
        assert {h["license_key"] for h in hs} == {KEY_TERM, KEY_PERP} and all(h["vcenter"] == VC for h in hs)
        assert await M.delete_project(p["id"]) and len(await M.data("csp", "")) == 3
    asyncio.run(main())


def test_vcfops_pull_requires_opt_in(tmp_path):
    e = _engine(tmp_path)
    M = e.license

    class Resp:
        status_code = 200
        content = usage_file()

    class Http:
        def __init__(self):
            self.calls = []

        async def post(self, path, headers=None, params=None):
            self.calls.append((path, headers))
            return Resp()

    class Ops:
        type = "vcfops"
        name = "ops1"
        token = "t"

        def __init__(self):
            self.http = Http()
    ops = Ops()
    e.connectors = [ops]

    async def main():
        with pytest.raises(PermissionError):
            await M.pull_vcfops("ops1", "u")
        await M.save_settings({"vcfops_usage_api": True}, "u")
        r = await M.pull_vcfops("ops1", "u")
        assert r["products"] == 2 and ops.http.calls[0][1]["X-Ops-API-use-unsupported"] == "true"
        assert ops.http.calls[0][0] == "/suite-api/internal/license-manager/usage/report"
    asyncio.run(main())


def test_api_and_permissions(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_license import build_router
    from app.security.auth import AuthManager
    e = _engine(tmp_path)
    e.connectors = [FakeVC()]
    logs = []
    role = {"r": "operator"}

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append(action)
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda req: {"user": "op1", "role": role["r"]}, audit))
    with TestClient(app) as cl:
        h = {"Content-Type": "application/octet-stream"}
        assert cl.post("/api/license/upload/csp?name=../x/All.xlsx", content=csp_xlsx(), headers=h).json()["rows"] == 3
        assert cl.post("/api/license/upload/csp", content=b"nope", headers=h).status_code == 400
        assert cl.post("/api/license/upload/vcfops", content=b"\x1f\x8bjunk", headers=h).status_code == 400
        assert cl.post("/api/license/upload/zzz", content=b"x").status_code == 404
        assert cl.post("/api/license/collect", json={}).json()["items"][0]["hosts"] == 4
        p = cl.post("/api/license/projects", json={"name": "P1"}).json()
        assert cl.post("/api/license/assign", json={"project": p["id"], "kind": "source", "ids": ["vcenter:vc-lab"]}).json()["count"] == 1
        o = cl.get(f"/api/license/overview?project={p['id']}").json()
        assert o["match"]["total"] >= 1 and o["vcenters"] == ["vc-lab"] and o["checks"]
        d = cl.get("/api/license/data/match").json()["items"]
        assert d and KEY_TERM not in json.dumps(d)
        full = cl.get("/api/license/reveal/match").json()["items"]
        assert KEY_TERM in json.dumps(full) and "license.reveal" in logs
        x = cl.get("/api/license/report.xlsx")
        assert x.content[:2] == b"PK" and KEY_TERM.encode() not in x.content
        from app.rvtools import xlsx as X
        back = X.read(x.content)
        assert {"요약", "점검", "키 매칭", "실사용 호스트", "CSP"} <= set(back)
        assert KEY_TERM in json.dumps(X.read(cl.get("/api/license/report.xlsx?full=1").content), default=str)
        role["r"] = "viewer"
        assert cl.get("/api/license/report.xlsx?full=1").status_code == 403
        role["r"] = "operator"
        s = cl.put("/api/license/settings", json={"schedule_hours": 6, "vcfops_usage_api": True}).json()
        assert s["schedule_hours"] == 6 and s["vcfops_usage_api"] is True
        assert cl.post("/api/license/rvtools/none").status_code == 404
        assert cl.delete(f"/api/license/projects/{p['id']}").json()["ok"]
    rp = AuthManager.required_perm
    assert rp("GET", "/api/license/overview") == "view" and rp("GET", "/api/license/reveal/match") == "operate"
    assert rp("POST", "/api/license/upload/csp") == "operate" and rp("PUT", "/api/license/settings") == "settings"
    assert rp("POST", "/api/license/assign") == "operate" and rp("DELETE", "/api/license/batches/x") == "operate"



def test_vcsim_collect_licenses():
    """실제 pyVmomi 경로(vcsim) — LicenseManager·LicenseAssignmentManager 조회만"""
    import socket
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, lambda e: None)
    c.topology = {"hosts": {}}
    d = c.collect_licenses()
    assert d["licenses"] and d["hosts"] and all(h["sockets"] >= 1 for h in d["hosts"])
    assert all(h["license_key"] == U.EVAL_KEY for h in d["hosts"])          # vcsim = 평가 모드 → 미할당으로 분류
