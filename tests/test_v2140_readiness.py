"""2.14.0 하드웨어 준비도(VCF-R) — 읽기 전용 강제·수집 정규화·CPU(KB 428874·BCG CPUID)·메모리·vSAN ESA·NIC/ToR·부팅/TPM·BMC 보안·BIOS·플릿·스캔 작업·보고서·가명화·API"""
import asyncio
import io
import json
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace as NS

import httpx
import pytest

from app.readiness import rules as R
from app.readiness import security as S
from app.readiness.assess import assess_host, fleet
from app.readiness.collect import collect
from app.readiness.export import Obf, report_html, rows_summary, xlsx, SHEETS
from app.readiness.hcl import Hcl
from app.readiness.manager import expand_targets
from app.readiness.rfclient import ReadOnlyViolation, RfClient
from tests.redfish_mock import MockBmc
from tests.test_v2110_support import _engine


async def _scan(kind, **kw):
    m = MockBmc(kind, **kw)
    async with RfClient(f"bmc-{kind}", "aiops-ro", "Pw!", transport=m.transport()) as c:
        h = await collect(c)
    return m, h


def test_readonly_transport():
    async def main():
        m = MockBmc("dell")
        async with RfClient("bmc", "aiops-ro", "Pw!", transport=m.transport()) as c:
            await c.get("/redfish/v1/Systems")
            for meth, path in (("PATCH", "/redfish/v1/Systems/System.Embedded.1/Bios/Settings"), ("POST", "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"),
                               ("PUT", "/redfish/v1/AccountService/Accounts/2"), ("DELETE", "/redfish/v1/AccountService/Accounts/3"),
                               ("POST", "/redfish/v1/EventService/Subscriptions")):
                with pytest.raises(ReadOnlyViolation):
                    await c._req(meth, path)
        methods = {(a, b) for a, b in m.calls}
        assert {a for a, _ in methods} <= {"GET", "POST", "DELETE"}
        assert all(b == "/redfish/v1/SessionService/Sessions" for a, b in methods if a == "POST")
        assert all(b.startswith("/redfish/v1/SessionService/Sessions/") for a, b in methods if a == "DELETE")
        assert not m.tokens                                            # 세션 정리
        # 세션 미지원 → Basic, 잘못된 비밀번호 → PermissionError
        m2 = MockBmc("generic", sessions=False)
        async with RfClient("bmc", "aiops-ro", "Pw!", transport=m2.transport()) as c:
            assert c.auth_mode == "basic" and (await c.get("/redfish/v1/Systems"))["Members"]
        with pytest.raises(PermissionError):
            async with RfClient("bmc", "aiops-ro", "bad", transport=MockBmc("dell").transport()):
                pass
    asyncio.run(main())


def test_collect_normalized():
    async def main():
        _, h = await _scan("dell")
        assert h["vendor"] == "dell" and h["system"]["model"] == "PowerEdge R760" and h["system"]["serial"] == "7XK1R63"
        assert len(h["cpus"]) == 2 and h["cpus"][0]["cores"] == 32
        assert sum(1 for d in h["dimms"] if d["present"]) == 16 and h["dimms"][0]["socket"] == 1 and h["dimms"][0]["rated"] == 4800
        nv = [d for d in h["storage"]["drives"] if d["protocol"] == "NVMe" and d["capacity_gb"] > 1000]
        assert len(nv) == 4 and nv[0]["vid"] == "144d" and nv[0]["ssid"] == "2112"
        assert h["nics"][0]["lldp"]["system_name"] == "leaf-01.dc1" and h["nics"][0]["speed_gbps"] == 25
        assert "SetupPassword" not in h["bios"]["attributes"]          # 비밀 속성은 수집 안 함
        assert h["bmc"]["oem"]["IPMILan.1.EncryptionKeyDefault"] is True and "IPMILan.1.EncryptionKey" not in h["bmc"]["oem"]
        assert h["tpm"][0]["type"] == "TPM2_0" and h["secureboot"]["current"] == "Enabled"
        assert h["sel"] and h["sel"][0]["ts"] >= h["sel"][-1]["ts"]
        _, g = await _scan("hpe")
        assert g["vendor"] == "hpe" and g["storage"]["controllers"][0]["mode"] == "RAID" and g["power"]["redundancy"].endswith("Critical")
    asyncio.run(main())


def test_cpu_rules():
    c = R.classify_cpu
    assert c("Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz")["tier"] == "deprecated_override"
    assert c("Intel(R) Xeon(R) Gold 6248R")["tier"] == "deprecated"
    assert c("Intel Xeon Platinum 8380H")["family"].endswith("(Cooper Lake)")
    assert c("Intel(R) Xeon(R) Gold 6338N")["family"].endswith("(Ice Lake-SP)")
    assert c("AMD EPYC 9354 32-Core Processor")["tier"] == "supported"
    assert c("Intel(R) Core(TM) i9-13900K")["tier"] == "not_eligible" and c("Intel Xeon E5-2690 v4")["tier"] == "eol"
    assert c("Intel Xeon 6780E")["tier"] == "verify" and c("Intel(R) Xeon(R) E-2488")["tier"] == "supported"
    assert R.cpuid_sig("6", "0x6A", "6") == "0x000606a6" and R.cpuid_sig("0x19", "0x01", "1") == "0x00a00f11"
    x = c("Some Unknown CPU", "0x000606a6")                         # BCG CPUID 일치 → 지원 근거
    assert x["tier"] == "supported" and "BCG CPUID" in x["evidence"]
    d = R.parse_bcg_csv('CPU Series,Cores/Threads,CPUID Info,CPUIDs,Supported Releases\n"Intel Xeon 6700E (Sierra Forest) Series",144c/144t,6.AF.3,"0x000A06F3","ESXi 9.1"\n')
    R.set_bcg_cpu(d)
    try:
        assert c("Intel Xeon 6780E", "0x000a06f3")["tier"] == "supported"
    finally:
        R._BCG = None
    with pytest.raises(ValueError):
        R.parse_bcg_csv("a,b\n1,2\n")


def test_assess_hosts_and_fleet():
    async def main():
        res = []
        for k in ("dell", "hpe", "generic"):
            _, h = await _scan(k)
            r = assess_host(h)
            res.append({"target": k, "host": h, "result": r})
        dell, hpe, gen = (x["result"] for x in res)
        ck = lambda r, i: next(c for c in r["checks"] if c["id"] == i)   # noqa: E731
        assert dell["verdict"] == "ready" and ck(dell, "vsan.esa")["status"] == "pass" and dell["summary"]["storage"]["verdict"] == "esa_ready"
        assert dell["summary"]["storage"]["direct_nvme"] == 4 and dell["summary"]["storage"]["boot"] == 1
        assert ck(dell, "nic.tor")["status"] == "pass" and ck(dell, "mem.channels")["status"] == "pass"
        assert hpe["verdict"] == "actions" and ck(hpe, "cpu.class")["status"] == "warn" and "override" in ck(hpe, "cpu.class")["fix"]
        assert ck(hpe, "nic.speed")["status"] == "fail" and ck(hpe, "nic.tor")["status"] == "warn" and ck(hpe, "boot.uefi")["status"] == "warn"
        assert ck(hpe, "psu")["status"] == "fail" and ck(hpe, "sel")["status"] == "fail" and ck(hpe, "vsan.osa")["status"] == "warn"
        assert any(c["id"].startswith("drv.life") and c["status"] == "fail" for c in hpe["checks"])
        assert ck(hpe, "mem.channels")["status"] == "warn"           # 24슬롯 중 10개 → 채널 배수 아님
        assert gen["verdict"] == "actions" and ck(gen, "vsan.none")["status"] == "unknown" and ck(gen, "nic.tor")["status"] == "unknown"
        assert dell["memory_grid"][0]["channels"][0]["populated"] >= 1
        f = fleet(res + [{"target": "x"}])
        assert f["totals"]["hosts"] == 3 and f["totals"]["failed"] == 1 and f["totals"]["cores"] == 64 + 32 + 32
        assert f["verdicts"] == {"ready": 1, "actions": 2} and f["nodes"]["simple_vsan"] and not f["nodes"]["ha"]
        hs = {x["host"]: x for x in f["tor"]["hosts"]}
        assert hs["dell"]["state"] == "dual" and hs["hpe"]["state"] == "single" and hs["hpe"]["miscabled"] and hs["generic"]["state"] == "unknown"
        # 같은 모델 BIOS 편차
        _, h2 = await _scan("dell")
        h2["system"]["bios_version"] = "2.3.1"
        h2["bios"]["attributes"]["ProcCStates"] = "Enabled"
        f2 = fleet([res[0], {"target": "dell2", "host": h2, "result": assess_host(h2)}])
        items = {d["item"] for d in f2["drift"]}
        assert "BIOS" in items and any(i.startswith("BIOS 설정") for i in items)
        assert f2["tor"]["pairs"] == [{"a": "leaf-01.dc1", "b": "leaf-02.dc1", "dual": ["dell", "dell2"], "only_a": [], "only_b": []}]
    asyncio.run(main())


def test_security_and_bios():
    async def main():
        _, d = await _scan("dell")
        now = datetime(2026, 10, 23, 6, 1, tzinfo=timezone.utc)
        rows = {r["id"]: r for r in S.audit(d, now)}
        assert rows["BMC-05"]["status"] == "pass" and rows["BMC-07"]["status"] == "pass" and rows["BMC-12"]["status"] == "pass"
        assert rows["BMC-03"]["status"] == "pass" and rows["BMC-21"]["status"] == "pass" and rows["BMC-16"]["status"] == "warn"
        assert rows["BMC-02"]["status"] == "pass" and rows["BMC-02"]["scg"] == "esx-9.hardware-management-tls"
        _, h = await _scan("hpe")
        rows = {r["id"]: r for r in S.audit(h, now)}
        assert rows["BMC-05"]["status"] == "fail" and rows["BMC-07"]["status"] == "fail" and rows["BMC-12"]["status"] == "fail"
        assert rows["BMC-03"]["status"] == "fail" and rows["BMC-20"]["status"] == "fail" and rows["BMC-02"]["status"] == "unknown"   # 미노출은 통과 아님
        sc = S.score(list(rows.values()))
        assert sc["posture"] == "조치 필요" and sc["scg"]["tls"] == "fail" and 0 < sc["coverage"] < 100
        r = assess_host(h)
        b = {x["id"]: x for x in r["bios"]["rows"]}
        assert b["boot"]["status"] == "drift" and b["power"]["status"] == "drift" and b["virt"]["status"] == "pass" and b["iommu"]["status"] == "unknown"
        assert r["bios"]["status"] == "fail"
    asyncio.run(main())


def test_hcl_match():
    hcl = Hcl(__import__("pathlib").Path("/nonexistent/x.json"))
    data = {"payload": {"data": {"ssd": [{"model": "PM1733a", "vendorId": "0x144D", "deviceId": "0xA824", "subVendorId": "0x1028", "subDeviceId": "0x2112", "id": 123,
                                          "vsanSupport": {"mode": ["vSAN ESA"], "tier": ["vSAN ESA Storage Tier"]}, "releases": {"ESXi 9.1": {}}},
                                         {"model": "MZ7LH960HAJR", "vendorId": "144d", "deviceId": "a808", "vsanSupport": {"tier": ["All Flash Capacity Tier (AF-Cap)"]}}]}}}
    import gzip
    meta = hcl.load_bytes(gzip.compress(json.dumps(data).encode()), save=False)
    assert meta["entries"] == 2 and meta["esa"] == 1
    m = hcl.match_pci("144d", "a824", "1028", "2112")
    assert m["esa"] and m["rel91"] and m["how"] == "PCI quad 일치" and "productId=123" in m["link"]
    assert hcl.match_pci("144d", "a824", "1028", "9999")["partial"]
    assert hcl.match_pci("", "", "", "", "MZ7LH960HAJR")["osa"] and hcl.match_pci("1111", "2222")["missing"]
    with pytest.raises(ValueError):
        hcl.load_bytes(b'{"x": 1}', save=False)

    async def main():
        _, h = await _scan("dell")
        r = assess_host(h, hcl)
        assert r["summary"]["storage"]["hcl_esa"] == 4 and next(c for c in r["checks"] if c["id"] == "vsan.esa")["status"] == "pass"
    asyncio.run(main())


def test_expand_targets():
    assert expand_targets("10.0.0.1-3, bmc01.lab") == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "bmc01.lab"]
    assert len(expand_targets("10.0.1.0/28")) == 14
    for bad in ("169.254.169.254", "127.0.0.1", "10.0.0.0/16", "a;b|c", "10.0.0.9-2"):
        with pytest.raises(ValueError):
            expand_targets(bad)


def test_scan_job_reports_and_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api_readiness import build_router
    e = _engine(tmp_path)
    mocks = {k: MockBmc(k) for k in ("dell", "hpe")}
    rf = NS(type="redfish", name="bmc-r760", cfg={"host": "dell", "username": "aiops-ro", "password": "Pw!", "esxi_host": "esx01.lab"}, vendor="Dell")
    vc = NS(type="vcenter", name="vc1", topology={"hosts": {"esx02.lab": {"serial": "MXQ81204ZZ", "cluster": "wld"}}}, health_snap={})
    e.connectors = [rf, vc]
    M = e.readiness
    M.transport = {k: m.transport() for k, m in mocks.items()}
    events = []

    async def ingest(ev):
        events.append(ev)
    e.ingest = ingest
    logs = []

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append((action, detail))
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda req: {"user": "op1", "role": "admin"}, audit))
    with TestClient(app) as cl:
        assert cl.post("/api/readiness/scans", json={"targets": "hpe"}).status_code == 400      # 일회성은 계정 필요
        r = cl.post("/api/readiness/scans", json={"connectors": ["bmc-r760"], "targets": "hpe", "username": "aiops-ro", "password": "Pw!", "label": "t1"})
        assert r.status_code == 200 and r.json()["total"] == 2
        sid = r.json()["id"]
        for _ in range(200):
            s = cl.get(f"/api/readiness/scans/{sid}").json()
            if s["status"] != "running":
                break
            __import__("time").sleep(0.05)
        assert s["status"] == "done", s
        hs = {h["target"]: h for h in s["hosts"]}
        assert hs["connector:bmc-r760"]["verdict"] == "ready" and hs["connector:bmc-r760"]["esxi"]["esxi"] == "esx01.lab"
        assert hs["hpe"]["esxi"]["esxi"] == "esx02.lab" and hs["hpe"]["verdict"] == "actions"   # vCenter 시리얼 매칭
        assert s["fleet"]["totals"]["hosts"] == 2
        d = cl.get(f"/api/readiness/scans/{sid}/hosts/connector:bmc-r760").json()
        assert d["result"]["memory_grid"] and d["trend"][0]["verdict"] == "ready"
        assert "Pw!" not in json.dumps(d) and "Pw!" not in cl.get(f"/api/readiness/scans/{sid}/report.json").text
        h = cl.get(f"/api/readiness/scans/{sid}/report.html")
        assert h.status_code == 200 and "VCF 9.x 하드웨어 준비도 보고서" in h.text and "leaf-01.dc1" in h.text
        x = cl.get(f"/api/readiness/scans/{sid}/report.xlsx")
        zx = zipfile.ZipFile(io.BytesIO(x.content))
        assert "xl/worksheets/sheet9.xml" in zx.namelist() and "PowerEdge R760" in zx.read("xl/worksheets/sheet1.xml").decode()
        zz = zipfile.ZipFile(io.BytesIO(cl.get(f"/api/readiness/scans/{sid}/report.zip").content))
        assert {"요약.csv", "BMC 보안.csv", "report.html", "report.xlsx", "MANIFEST.json"} <= set(zz.namelist())
        ob = cl.get(f"/api/readiness/scans/{sid}/report.json?obfuscate=1").text
        assert "7XK1R63" not in ob and "MXQ81204ZZ" not in ob and "leaf-01.dc1" not in ob and "esx02.lab" not in ob and "Host-01" in ob
        oh = cl.get(f"/api/readiness/scans/{sid}/report.html?obfuscate=1").text
        assert "7XK1R63" not in oh and "가명화 사본" in oh
        # 두 번째 스캔: BIOS 변경 → 변화 이벤트
        mocks["dell"].tree["/redfish/v1/Systems/System.Embedded.1"]["BiosVersion"] = "2.2.0"
        r2 = cl.post("/api/readiness/scans", json={"connectors": ["bmc-r760"]}).json()
        for _ in range(200):
            if cl.get(f"/api/readiness/scans/{r2['id']}").json()["status"] != "running":
                break
            __import__("time").sleep(0.05)
        assert any("BIOS 변경" in ev.message and "esx01.lab" in ev.message for ev in events)
        ov = cl.get("/api/readiness/overview").json()
        assert ov["targets"][0]["verdict"] == "ready" and len(ov["scans"]) == 2 and ov["bcg"]["series"] == 38
        assert cl.put("/api/readiness/settings", json={"concurrency": "x"}).status_code == 400
        assert cl.put("/api/readiness/settings", json={"schedule_hours": 24, "concurrency": 99}).json()["concurrency"] == 16
        assert cl.put("/api/readiness/bcg-cpu", content=b"a,b\n").status_code == 400
        assert cl.put("/api/readiness/hcl", content=b'{"payload":{"data":{"ssd":[{"model":"PM1733a","vendorId":"144d","deviceId":"a824","subVendorId":"1028","subDeviceId":"2112","vsanSupport":{"tier":["vSAN ESA"]}}]}}}').json()["esa"] == 1
        # SR 초안(하드웨어 준비도 출처)
        sr = asyncio.run(e.support.create({"kind": "readiness", "ref": f"{sid}|hpe"}, {"user": "op1"}, {"vendor": "generic", "lang": "ko"}))
        d = sr["data"]
        assert "esx02.lab 하드웨어" in d["title"] and d["severity"] == 2 and any("Power supply redundancy" in x for x in d["symptoms"])
        assert any(x["label"] == "BIOS" for x in d["environment"]) and "하드웨어 준비도 스캔" in d["checked"][0]["text"]
        # 비용 비교: vCenter 코어 미확인 호스트를 BMC 실측으로 보완
        rep = asyncio.run(e.cloudcost.report())
        hh = {h["name"]: h for h in rep["hosts"]}
        assert hh["esx02.lab"]["cores"] == 32 and hh["esx02.lab"]["readiness"] == "actions" and rep["hardware"]["assessed"] == 1
        assert cl.delete(f"/api/readiness/scans/{sid}").json()["ok"]
    acts = [a for a, _ in logs]
    assert "readiness.scan" in acts and "readiness.export" in acts and not any("Pw!" in json.dumps(d, default=str) for _, d in logs)


def test_obfuscation_stability():
    o = Obf()
    a, b = o.tok("10.1.1.1", "IP"), o.tok("10.1.1.1", "IP")
    assert a == b and a.startswith("192.0.2.") and o.tok("aa:bb:cc:dd:ee:ff", "MAC").startswith("02:")
    assert o.text("link down on 10.1.1.1 aa:bb:cc:dd:ee:ff") == f"link down on {a} {o.tok('aa:bb:cc:dd:ee:ff', 'MAC')}"
    assert xlsx([("s", [["a", "b"], [1, "x<&>"]])])[:2] == b"PK"
    assert len(SHEETS) == 9 and rows_summary([{"target": "t", "ok": False, "error": "e"}])[1][2].startswith("스캔 실패")
    assert "<!doctype html>" in report_html({"id": "x"}, [], {})
