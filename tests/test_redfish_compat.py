"""Redfish 호환 — Lenovo XCC 비JSON 응답·오래된 순 로그, Cisco CIMC 3.0(RemoteProtocolError → 호환 단계 → XML API)."""
import asyncio
import ssl
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.connectors.redfish import RedfishConnector  # noqa: E402

_Orig = httpx.AsyncClient
ISO = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))  # noqa: E731


@pytest.fixture
def mock(monkeypatch):
    """httpx.AsyncClient 생성 시 MockTransport 주입. state['legacy'] = 마지막 클라이언트가 구형 TLS 컨텍스트였는지."""
    st = {"handler": None, "legacy": False, "clients": 0}

    class C(_Orig):
        def __init__(self, *a, **kw):
            st["legacy"] = isinstance(kw.get("verify"), ssl.SSLContext)
            st["clients"] += 1
            kw["transport"] = httpx.MockTransport(lambda r: st["handler"](r, st))
            super().__init__(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", C)
    return st


def conn(**kw):
    async def emit(_):
        pass
    return RedfishConnector({"name": "bmc", "host": "192.168.111.18", "username": "u", "password": "p",
                             "verify_tls": False, "events": "poll", **kw}, emit)


def xcc(req, st):
    p, q = req.url.path, req.url.params
    if p == "/redfish/v1/":
        return httpx.Response(200, json={"Vendor": "Lenovo"})
    if p == "/redfish/v1/SessionService/Sessions":
        return httpx.Response(201, headers={"X-Auth-Token": "t", "Location": "/redfish/v1/SessionService/Sessions/1"})
    if p == "/redfish/v1/Systems":
        return httpx.Response(200, json={"Members": [{"@odata.id": "/redfish/v1/Systems/1"}]})
    if p in ("/redfish/v1/Chassis", "/redfish/v1/Managers"):
        return httpx.Response(200, json={"Members": []})
    if p == "/redfish/v1/Systems/1/LogServices":
        return httpx.Response(200, json={"Members": [{"@odata.id": "/redfish/v1/Systems/1/LogServices/PlatformLog"},
                                                     {"@odata.id": "/redfish/v1/Systems/1/LogServices/AuditLog"}]})
    if p.endswith("/AuditLog/Entries"):
        return httpx.Response(200, text="")                      # XCC: 빈 본문(200) → 예전엔 JSONDecodeError
    if p.endswith("/PlatformLog/Entries"):
        now = time.time()
        allm = [{"@odata.id": f"{p}/{i}", "Id": str(i), "Created": ISO(now - 3000 + i * 10), "Severity": "Warning",
                 "Message": f"entry {i}", "MessageId": f"M{i}"} for i in range(300)]
        skip, top = int(q.get("$skip", 0)), int(q.get("$top", 100))
        return httpx.Response(200, json={"Members": allm[skip:skip + top], "Members@odata.count": 300})
    if p == "/redfish/v1/Systems/1":
        return httpx.Response(200, text="<html>busy</html>")     # 비JSON → 건너뜀
    return httpx.Response(404, text="")


def test_xcc_nonjson_and_oldest_first(mock):
    mock["handler"] = xcc
    c = conn(server_name="ESX09")
    c.since = time.time() - 3600

    async def go():
        await c.login()
        return await c.poll()
    evs = asyncio.run(go())
    assert c._state["auth"] == "session" and len(c.log_urls) == 2
    ids = sorted(int(e.native_id.rsplit("/", 1)[-1]) for e in evs if "PlatformLog" in e.native_id)
    assert ids and max(ids) == 299 and min(ids) >= 200          # 최신 페이지($skip=200)
    assert all(e.host == "ESX09" for e in evs)
    assert "비JSON 응답" in c._state["checks"]


def cisco(req, st):
    # CIMC 3.0(4q): 표준 연결(keep-alive)에서는 응답 줄 없이 끊김, Connection: close 면 정상
    if req.url.path.startswith("/redfish") and req.headers.get("connection", "").lower() != "close":
        raise httpx.RemoteProtocolError("no response line received", request=req)
    p = req.url.path
    if p == "/redfish/v1/":
        return httpx.Response(200, json={"Vendor": "Cisco Systems Inc."})
    if p.endswith("Systems"):
        return httpx.Response(200, json={"Members": [{"@odata.id": "/redfish/v1/Systems/WZP1"}]})
    if p.endswith("LogServices"):
        return httpx.Response(200, json={"Members": [{"@odata.id": "/redfish/v1/Systems/WZP1/LogServices/SEL"}]})
    if p.endswith("Entries"):
        assert req.headers.get("authorization", "").startswith("Basic")
        return httpx.Response(200, json={"Members": [{"Id": "1", "Created": ISO(time.time()), "Severity": "Critical", "Message": "PSU2 lost"}]})
    return httpx.Response(200, json={"Members": []})


def test_cisco_remote_protocol_error_escalates(mock):
    mock["handler"] = cisco
    c = conn(vendor="")
    c.since = time.time() - 3600

    async def go():
        await c.login()
        return await c.poll()
    evs = asyncio.run(go())
    assert c.compat == 1 and c._state["auth"] == "basic" and c.api_mode == "redfish"
    assert any("PSU2 lost" in e.message for e in evs)


NUOVA = {
    "computeRackUnit": '<computeRackUnit dn="sys/rack-unit-1" model="UCSC-C220-M3S" serial="FCH1815V147" operPower="on" totalMemory="131072"/>',
    "faultInst": '<faultInst dn="sys/rack-unit-1/psu-2/fault-F0369" id="1" code="F0369" severity="major" descr="Power supply 2 is in a degraded state" cause="psu-degraded" created="2026-10-11T01:00:00"/>',
    "firmwareRunning": '<firmwareRunning dn="sys/rack-unit-1/bios/fw-boot-loader" version="C220M3.3.0.4b.0" type="blade-bios"/>'
                       '<firmwareRunning dn="sys/rack-unit-1/mgmt/fw-system" version="3.0(4q)" type="blade-controller"/>',
}


def cimc_only(req, st):
    if req.url.path.startswith("/redfish"):
        raise httpx.RemoteProtocolError("no response line received", request=req)
    if req.url.path == "/nuova":
        body = req.content.decode()
        if not st["legacy"]:
            raise httpx.ConnectError("[SSL: UNSUPPORTED_PROTOCOL]", request=req)
        if body.startswith("<aaaLogin"):
            return httpx.Response(200, text='<aaaLogin cookie="" response="yes" outCookie="1700000000/abc"/>')
        if body.startswith("<aaaLogout"):
            return httpx.Response(200, text='<aaaLogout response="yes"/>')
        cid = body.split('classId="')[1].split('"')[0]
        return httpx.Response(200, text=f'<configResolveClass response="yes" classId="{cid}"><outConfigs>{NUOVA.get(cid, "")}</outConfigs></configResolveClass>')
    return httpx.Response(404)


def test_cimc_xml_fallback(mock):
    mock["handler"] = cimc_only
    c = conn(server_name="C220-FCH1815V147")

    async def go():
        chk = await c.checks()
        evs = await c.poll()
        return chk, evs
    chk, evs = asyncio.run(go())
    assert c.api_mode == "cimc" and chk["인증"].startswith("ok CIMC")
    assert "FCH1815V147" in chk["서버"] and chk["활성 장애(faultInst)"] == "ok 1건"
    assert any(e.attrs.get("code") == "F0369" and e.severity == "error" for e in evs)
    assert c.server["bmc_fw"] == "3.0(4q)" and c.server["bios"].startswith("C220M3")
    assert {f["version"] for f in c.firmware} == {"C220M3.3.0.4b.0", "3.0(4q)"}


def test_all_fail_message(mock):
    def dead(req, st):
        raise httpx.RemoteProtocolError("no response line received", request=req)
    mock["handler"] = dead
    c = conn()
    with pytest.raises(RuntimeError) as ei:
        asyncio.run(c.login())
    assert "RemoteProtocolError" in str(ei.value) and "CIMC XML API" in str(ei.value)
