"""1.7: Cisco UCS Manager · NSX Edge(Policy/Manager API) · Avi SE(페이지 200 제한) · 물리→논리 스택 토폴로지"""
import asyncio
import json
from types import SimpleNamespace as NS

import httpx

from app.connectors import ucsm as U
from app.connectors.vmware_rest import AviConnector, NsxConnector
from app.stack import build, host_for_hw, uuid_variants


def test_uuid_variants_byte_order():
    a = "dcf7fb3c-4a1c-5a05-b730-5e09f3704e2f"
    v = uuid_variants(a.upper())
    assert a in v and "3cfbf7dc-1c4a-055a-b730-5e09f3704e2f" in v
    assert uuid_variants("derived") == set() and uuid_variants("00000000-0000-0000-0000-000000000000") == set()


class FakeSess:
    DATA = {
        "topSystem": [{"name": "UCS-A", "address": "10.0.0.1", "mode": "cluster"}],
        "networkElement": [{"id": "A", "dn": "sys/switch-A", "model": "UCS-FI-6454", "oobIfIp": "10.0.0.2", "operability": "operable"}],
        "mgmtEntity": [{"id": "A", "leadership": "primary"}],
        "equipmentChassis": [{"id": "1", "dn": "sys/chassis-1", "model": "5108", "operState": "operable", "power": "ok"}],
        "computeBlade": [{"dn": "sys/chassis-1/blade-1", "chassisId": "1", "slotId": "1", "model": "B200M5", "serial": "FCH1", "uuid": "11111111-2222-3333-4444-555555555555",
                          "operState": "ok", "operPower": "on", "association": "associated", "assignedToDn": "org-root/ls-esx01"}],
        "computeRackUnit": [],
        "lsServer": [{"dn": "org-root/ls-esx01", "name": "esx01", "uuid": "derived", "assocState": "associated"}],
        "faultInst": [{"dn": "sys/chassis-1/blade-1/fault-F0174", "id": "1", "code": "F0174", "severity": "major", "descr": "POST failure"}],
        "adaptorHostEthIf": [{"dn": "sys/chassis-1/blade-1/adaptor-1/host-eth-1", "mac": "00:25:B5:00:00:01", "name": "vmnic0"}],
    }

    def __init__(self, x):
        self.x = x

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def resolve(self, cid):
        return [dict(d) for d in self.DATA.get(cid, [])]


class FakeXml:
    def __init__(self, *a, **k):
        self.verify = False
        self.cookie = "c"

    def session(self):
        return FakeSess(self)


def test_ucsm_poll_inventory_faults(monkeypatch):
    monkeypatch.setattr(U, "CimcXml", FakeXml)
    monkeypatch.setattr(U.UcsManagerConnector, "_dn", staticmethod(lambda s, dn: asyncio.sleep(0, result={"version": "4.2(3h)"})))
    c = U.UcsManagerConnector({"name": "ucs", "host": "ucs.lab", "username": "ro", "password": "p"}, None)

    async def main():
        await c.login()
        ev1 = await c.poll()
        c.first_poll = False
        FakeSess.DATA["computeBlade"][0]["operState"] = "inoperable"
        FakeSess.DATA["faultInst"] = []
        ev2 = await c.poll()
        return ev1, ev2
    ev1, ev2 = asyncio.run(main())
    assert c.ucs["system"]["version"] == "4.2(3h)" and c.ucs["fis"][0]["leadership"] == "primary"
    b = c.servers()[0]
    assert b["profile"] == "esx01" and b["uuid"] == "11111111-2222-3333-4444-555555555555"     # 'derived' → 하드웨어 UUID
    assert any("F0174" in e.message and e.severity == "error" for e in ev1)
    assert any("inoperable" in e.message and e.severity == "critical" for e in ev2) and any("장애 해소" in e.message for e in ev2)
    assert c.ucs["macs"]["00:25:b5:00:00:01"]["vnic"] == "vmnic0"


def _mock(c, handler, base="https://x"):
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=base)


def test_avi_list_page_limit_and_se_vs_mapping():
    calls = []

    def h(req: httpx.Request):
        q = dict(req.url.params)
        calls.append((req.url.path, q, req.headers.get("x-avi-tenant")))
        if int(q.get("page_size", 25)) > 200:
            return httpx.Response(400, json={"error": "page_size"})
        p = req.url.path
        if p == "/api/serviceengine-inventory":
            page = int(q.get("page", 1))
            res = [{"config": {"name": f"se-{page}-{i}", "se_group_ref": "https://c/api/serviceenginegroup/x#G1", "host_ref": "https://c/api/vimgrhostruntime/h#esx01.lab"},
                    "runtime": {"oper_status": {"state": "OPER_UP"}}} for i in range(2)]
            return httpx.Response(200, json={"count": 4, "results": res, "next": "more" if page == 1 else None})
        if p == "/api/virtualservice-inventory":
            return httpx.Response(200, json={"count": 1, "results": [{"uuid": "vs1", "config": {"uuid": "vs1", "name": "web"},
                                  "runtime": {"oper_status": {"state": "OPER_UP"}, "vip_summary": [{"service_engine": [{"url": "https://c/api/serviceengine/s#se-1-0"}]}]}}]})
        return httpx.Response(200, json={"results": []})
    c = AviConnector({"name": "avi", "host": "avi", "username": "u", "password": "p", "events": False}, None)
    _mock(c, h)
    asyncio.run(c.poll())
    assert len(c.se) == 4 and c.se["se-1-0"]["host"] == "esx01.lab" and c.se["se-1-0"]["se_group"] == "G1"
    assert c.se["se-1-0"]["vs"] == ["web"] and c.vs["vs1"]["ses"] == ["se-1-0"]
    calls = [x for x in calls if not x[0].startswith("/api/cluster")]          # 2.4 컨트롤러 클러스터 조회는 목록 API 아님
    assert all(int(q["page_size"]) <= 200 for _, q, _ in calls) and calls[0][2] == "*"
    assert "ok 4개" in c._state["checks"]["Service Engine(/api/serviceengine-inventory)"]


def test_nsx_edges_policy_then_manager_fallback():
    def policy(req):
        p = req.url.path
        if p.endswith("/edge-transport-nodes"):
            return httpx.Response(200, json={"results": [{"id": "e1", "display_name": "edge01", "form_factor": "MEDIUM",
                                                          "vm_deployment_config": {"host_id": "host-12"}, "management_interface": {"x": [{"ip_addresses": ["10.1.1.5"]}]}}]})
        if p == "/api/v1/edge-clusters":
            return httpx.Response(200, json={"results": [{"id": "ec1", "display_name": "EC-1", "members": [{"transport_node_id": "e1"}]}]})
        if p == "/api/v1/transport-nodes/e1/status":
            return httpx.Response(404)
        if p.endswith("/e1/state"):
            return httpx.Response(200, json={"edge_tn_state": {"overall_state": "failed"}})
        return httpx.Response(404)
    c = NsxConnector({"name": "nsx", "host": "nsx", "username": "u", "password": "p"}, None)
    _mock(c, policy)
    asyncio.run(c._refresh_edges())
    evs = asyncio.run(c._edge_status())
    e = c.edge_info["e1"]
    assert e["host_moid"] == "host-12" and e["edge_cluster"] == "EC-1" and e["mgmt_ip"] == "10.1.1.5"
    assert c._edge_state["e1"] == "DOWN" and evs and evs[0].severity == "critical"

    def manager(req):
        p = req.url.path
        if p.endswith("/edge-transport-nodes"):
            return httpx.Response(403)
        if p == "/api/v1/transport-nodes":
            return httpx.Response(200, json={"results": [{"id": "m1", "display_name": "edge-m", "node_deployment_info": {
                "resource_type": "EdgeNode", "ip_addresses": ["10.2.2.2"], "deployment_config": {"vm_deployment_config": {"host_id": "host-9"}}}},
                {"id": "h1", "display_name": "esx", "node_deployment_info": {"resource_type": "HostNode"}}]})
        return httpx.Response(200, json={"results": []})
    c2 = NsxConnector({"name": "nsx2", "host": "nsx", "username": "u", "password": "p"}, None)
    _mock(c2, manager)
    asyncio.run(c2._refresh_edges())
    assert list(c2.edges) == ["m1"] and c2.edge_info["m1"]["host_moid"] == "host-9"
    assert "HTTP 403" in c2._state["checks"]["Edge 목록(Policy API)"]


def test_stack_build_links_physical_to_service():
    vc = NS(type="vcenter", name="vc", enabled=True, host="vc", topology={
        "hosts": {"esx01": {"moid": "host-12", "cluster": "CL", "conn": "connected", "status": "green", "cpu_mhz": 1000, "cpu_used_mhz": 500,
                            "mem_mb": 100, "mem_used_mb": 50, "uuid": "dcf7fb3c-4a1c-5a05-b730-5e09f3704e2f", "serial": "FCH1",
                            "switches": [{"name": "VDS-1", "kind": "vds", "uplinks": ["vmnic0"]}]}},
        "vms": {"edge01": {"host": "esx01", "power": "poweredOn"}, "app": {"host": "esx01", "power": "poweredOn"}}, "clusters": {}})
    ucs = NS(type="ucsm", name="ucs", enabled=True, host="ucs", ucs={"system": {"name": "UCS-A"}, "fis": [{"id": "A", "state": "ok"}],
                                                                   "chassis": [{"id": "1", "state": "ok"}]},
             servers=lambda: [{"dn": "sys/chassis-1/blade-1", "kind": "blade", "chassis": "1", "profile": "sp-x", "uuid": "dcf7fb3c-4a1c-5a05-b730-5e09f3704e2f",
                               "serial": "", "state": "ok", "assoc": "associated"}])
    nsx = NS(type="nsx", name="nsx", enabled=True, host="nsx", edges={"e1": "edge01"}, edge_info={"e1": {"host_moid": "host-12", "edge_cluster": "EC-1"}},
             _edge_state={"e1": "UP"}, inv={"edge_clusters": [{"id": "ec1", "name": "EC-1"}], "tier0": [{"id": "t0", "name": "T0", "edge_cluster_id": "ec1"}],
                                           "tier1": [{"id": "t1", "name": "T1", "tier0": "t0"}], "segments": []},
             state=lambda: {"state": "ok"})
    avi = NS(type="avi", name="avi", enabled=True, host="avi", se={"se1": {"state": "OPER_UP", "host": "esx01.lab", "se_group": "G1"}},
             vips=lambda: [{"uuid": "vs1", "name": "web", "state": "OPER_UP", "vips": ["10.0.0.9"], "ports": [443]}], vs={"vs1": {"ses": ["se1"]}})
    eng = NS(connectors=[vc, ucs, nsx, avi], anomalies={})
    d = build(eng)
    L = {(l["s"], l["t"]) for l in d["links"]}
    assert ("fi:ucs:A", "ch:ucs:1") in L and ("ch:ucs:1", "srv:ucs:sys/chassis-1/blade-1") in L
    assert ("srv:ucs:sys/chassis-1/blade-1", "host:vc:esx01") in L and ("host:vc:esx01", "vds:vc:VDS-1") in L
    assert ("host:vc:esx01", "edge:nsx:e1") in L and ("edge:nsx:e1", "ec:nsx:EC-1") in L and ("ec:nsx:EC-1", "t0:nsx:t0") in L and ("t0:nsx:t0", "t1:nsx:t1") in L
    assert ("host:vc:esx01", "se:avi:se1") in L and ("se:avi:se1", "vs:avi:vs1") in L
    assert host_for_hw([vc], "3cfbf7dc-1c4a-055a-b730-5e09f3704e2f", "") == "esx01"          # 바이트 순서 다른 UUID
    assert not d["unmatched"] and d["counts"]["blade"] == 1
