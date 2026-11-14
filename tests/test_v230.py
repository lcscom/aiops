"""2.3 — NSX T0 BGP(Edge ↔ 물리 스위치) 수집·구성도, ESXi LLDP/CDP 힌트, 장비별 포트맵 점검, VM 적정화 근거·클러스터 요약"""
import asyncio
from types import SimpleNamespace as NS

import httpx

from app import billing, capacity, netmap, portmap
from app.connectors import network as N
from app.connectors.vcenter import parse_hints
from app.connectors.vmware_rest import NsxConnector
from tests.test_v200 import _store
from tests.test_v112 import _env

T0 = "/policy/api/v1/infra/tier-0s"
LS = f"{T0}/t0-a/locale-services/ls1"
EP = "/infra/sites/default/enforcement-points/default/edge-clusters/ec1/edge-nodes/"


def _nsx_handler(state):
    def h(req: httpx.Request):
        p = req.url.path
        if p == T0:
            return httpx.Response(200, json={"results": [{"id": "t0-a", "display_name": "T0-A", "ha_mode": "ACTIVE_ACTIVE"}]})
        if p == f"{T0}/t0-a/locale-services":
            return httpx.Response(200, json={"results": [{"id": "ls1"}]})
        if p == f"{LS}/bgp":
            return httpx.Response(200, json={"local_as_num": "65000", "enabled": True})
        if p == f"{LS}/bgp/neighbors":
            return httpx.Response(200, json={"results": [{"id": "n1", "neighbor_address": "10.40.1.1", "remote_as_num": "65101", "source_addresses": ["10.40.1.11"]}]})
        if p == f"{LS}/bgp/neighbors/status":                       # PolicyBgpNeighborStatus
            return httpx.Response(200, json={"results": [
                {"edge_path": EP + "tn-1", "source_address": "10.40.1.11", "neighbor_address": "10.40.1.1", "remote_as_number": "65101",
                 "connection_state": state.get("s1", "ESTABLISHED"), "time_since_established": 3600, "total_in_prefix_count": 3, "total_out_prefix_count": 9,
                 "connection_drop_count": 0, "type": "USER", "tier0_path": "/infra/tier-0s/t0-a"},
                {"edge_path": EP + "tn-2", "source_address": "10.40.9.12", "neighbor_address": "10.40.9.1", "remote_as_number": "65199",
                 "connection_state": "IDLE", "type": "USER", "tier0_path": "/infra/tier-0s/t0-a"},
                {"edge_path": EP + "tn-1", "source_address": "169.254.0.1", "neighbor_address": "169.254.0.2", "connection_state": "ESTABLISHED", "type": "INTER_SR",
                 "tier0_path": "/infra/tier-0s/t0-a"}]})
        if p == f"{LS}/interfaces":
            return httpx.Response(200, json={"results": [{"id": "up1", "display_name": "uplink-1", "type": "EXTERNAL", "edge_path": EP + "tn-1",
                                                          "segment_path": "/infra/segments/seg-up1", "access_vlan_id": 101,
                                                          "subnets": [{"ip_addresses": ["10.40.1.11"], "prefix_len": 24}]}]})
        return httpx.Response(404, json={})
    return h


def _nsx(state):
    c = NsxConnector({"name": "nsx", "host": "nsx.lab", "username": "a", "password": "b"}, None)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(_nsx_handler(state)), base_url="https://nsx.lab")
    c.edges = {"tn-1": "edge-01", "tn-2": "edge-02"}
    c.edge_info = {"tn-1": {"name": "edge-01", "host_moid": "host-1", "edge_cluster": "ec1", "mgmt_ip": "10.20.8.11"},
                   "tn-2": {"name": "edge-02", "host_moid": "host-2", "edge_cluster": "ec1"}}
    return c


def test_nsx_t0_bgp_sessions_and_change_events():
    st = {}
    c = _nsx(st)
    assert asyncio.run(c._refresh_routing()) == []                                  # 첫 수집은 기준선
    g = c.routing["tier0"][0]
    assert g["name"] == "T0-A" and g["local_as"] == "65000" and len(g["sessions"]) == 2                  # INTER_SR 제외
    s = {x["edge"]: x for x in g["sessions"]}
    assert s["edge-01"]["source"] == "10.40.1.11" and s["edge-01"]["state"] == "ESTABLISHED" and s["edge-01"]["in_prefix"] == 3 and s["edge-02"]["state"] == "IDLE"
    assert g["interfaces"][0]["ips"] == ["10.40.1.11/24"] and g["interfaces"][0]["vlan"] == 101 and g["interfaces"][0]["edge"] == "edge-01"
    assert c._state["checks"]["T0 BGP"].startswith("warn")
    st["s1"] = "ACTIVE"
    ev = asyncio.run(c._refresh_routing())
    assert len(ev) == 1 and ev[0].severity == "critical" and ev[0].source == "nsx-edge" and "ESTABLISHED -> ACTIVE" in ev[0].message
    st["s1"] = "ESTABLISHED"
    ev = asyncio.run(c._refresh_routing())
    assert ev[0].severity == "info"


def _switch(name, bgp, addresses=(), ifaces=None, nbs=None):
    c = N.AristaEosConnector({"name": f"c-{name}", "host": f"10.0.0.{len(name)}"}, None)
    c.device = {"hostname": name, "model": "DCS", "os": "EOS", "version": "4.32"}
    c.ifaces = ifaces or {"Ethernet1": {"state": "up", "speed": 25000, "desc": ""}}
    c.known_links = {N.if_short(n["local"]): {**n, "state": n.get("state", "up")} for n in (nbs or [])}
    c.bgp = bgp
    c.addresses = list(addresses)
    c.updated = 1.0
    c._state["state"] = "ok"
    return c


def test_netmap_edge_bgp_links_match_switch_and_unknown_peer():
    nsx = _nsx({})
    asyncio.run(nsx._refresh_routing())
    nsx.entities = lambda: [{"name": "edge-01", "kind": "edge", "state": "ok"}, {"name": "edge-02", "kind": "edge", "state": "ok"}]
    sw = _switch("leaf1", {"10.40.1.11": {"state": "Idle", "asn": 65000}})               # 스위치는 아직 Idle → 불일치·다운
    vc = NS(type="vcenter", enabled=True, name="vc", topology={"hosts": {"esx01.lab": {"moid": "host-1", "cluster": "CL", "conn": "connected"}}})
    m = netmap.build(NS(connectors=[sw, nsx, vc]))
    bgp = [l for l in m["links"] if l.get("kind") == "bgp"]
    a = next(l for l in bgp if l["b"] == "edge:edge-01")
    assert a["a"] == "sw:leaf1" and a["state"] == "down" and a["remote_as"] == "65101" and a["vlan"] == 101
    b = next(l for l in bgp if l["b"] == "edge:edge-02")
    assert b["a"] == "bgp:10.40.9.1" and b["state"] == "down"                              # 수집 안 된 피어
    assert any(l.get("kind") == "placement" and l["a"] == "host:esx01" for l in m["links"])
    nodes = {n["id"]: n for n in m["nodes"]}
    assert nodes["edge:edge-01"]["tier"] == 4 and nodes["bgp:10.40.9.1"]["kind"] == "bgp-peer"
    s = {x["edge"]: x for x in m["bgp"]}
    assert s["edge-01"]["switch"] == "leaf1" and s["edge-01"]["mismatch"] is True and s["edge-01"]["match"] == "bgp-peer"
    assert m["summary"]["bgp_sessions"] == 2 and m["summary"]["bgp_down"] == 1 and m["summary"]["edges"] == 2
    sw.bgp["10.40.1.11"]["state"] = "Established"
    sw2 = _switch("leaf9", {}, addresses=["10.40.9.1"])                                     # SVI 주소로 매칭
    m = netmap.build(NS(connectors=[sw, sw2, nsx, vc]))
    s = {x["edge"]: x for x in m["bgp"]}
    assert s["edge-01"]["mismatch"] is False and s["edge-02"]["switch"] == "leaf9" and s["edge-02"]["match"] == "mgmt"
    rows = netmap.bgp_rows(NS(connectors=[sw, sw2, nsx, vc]))
    assert {r["state"] for r in rows} == {"ok", "down"} and any("1시간" in r["up"] for r in rows)


def test_parse_hints_lldp_and_cdp():
    kv = lambda k, v: NS(key=k, value=v)                                                   # noqa: E731
    hints = [NS(device="vmnic0", lldpInfo=NS(chassisId="00:1c:73:aa", portId="Ethernet5", timeToLive=120,
                                            parameter=[kv("System Name", "leaf1"), kv("Port Description", "esx01 vmnic0"), kv("Management Address", "10.0.0.11")]),
                connectedSwitchPort=None),
             NS(device="vmnic1", lldpInfo=None, connectedSwitchPort=NS(devId="n9k-2", portId="Ethernet1/5", address="10.0.0.12", hardwarePlatform="N9K-C93180YC-FX")),
             NS(device="vmnic2", lldpInfo=None, connectedSwitchPort=None)]
    h = parse_hints(hints)
    assert h["vmnic0"] == {"switch": "leaf1", "port": "Ethernet5", "port_desc": "esx01 vmnic0", "mgmt": "10.0.0.11", "desc": "", "proto": "lldp", "ttl": 120}
    assert h["vmnic1"]["switch"] == "n9k-2" and h["vmnic1"]["proto"] == "cdp" and "vmnic2" not in h


def test_portmap_findings():
    l1 = _switch("leaf1", {}, ifaces={"Ethernet5": {"state": "up", "speed": 25000, "desc": "esx01 vmnic0"}, "Ethernet6": {"state": "up", "speed": 25000, "desc": ""},
                                      "Ethernet7": {"state": "down", "speed": 25000, "desc": "esx02 vmnic0"}, "Ethernet8": {"state": "down", "speed": None, "desc": ""},
                                      "Ethernet9": {"state": "up", "speed": 25000, "desc": ""}, "Port-Channel10": {"state": "up", "speed": 50000, "desc": ""},
                                      "Vlan101": {"state": "up", "speed": None, "desc": ""}},
                 nbs=[{"local": "Ethernet5", "remote": "esx01.lab", "remote_port": "vmnic0"}, {"local": "Ethernet6", "remote": "esx01.lab", "remote_port": "vmnic1"},
                      {"local": "Ethernet7", "remote": "esx02.lab", "remote_port": "vmnic0", "state": "lost"}])
    hosts = {"esx01.lab": {"moid": "h1", "cluster": "CL", "conn": "connected", "pnics": [
                {"name": "vmnic0", "speed": 25000, "up": True, "vswitch": "dvs", "peer": {"switch": "leaf1", "port": "Ethernet5"}},
                {"name": "vmnic1", "speed": 10000, "up": True, "vswitch": "dvs"}]},                        # 둘 다 leaf1 → 이중화 없음, 속도 혼재·불일치
             "esx02.lab": {"moid": "h2", "cluster": "CL", "conn": "connected", "pnics": [
                {"name": "vmnic0", "speed": 0, "up": False, "vswitch": "dvs"},
                {"name": "vmnic1", "speed": 25000, "up": True, "vswitch": "dvs", "peer": {"switch": "leaf1", "port": "Ethernet9"}}]}}   # ESXi 쪽에서만 보임
    vc = NS(type="vcenter", enabled=True, name="vc", topology={"hosts": hosts})
    p = portmap.build(NS(connectors=[l1, vc]))
    kinds = {(f["device"], f["kind"]) for f in p["findings"]}
    assert ("esx01.lab", "redundancy") in kinds and ("esx01.lab", "speed") in kinds and ("esx02.lab", "uplink-down") in kinds
    assert ("leaf1", "port-down") in kinds                                                  # Ethernet7: 설명·이웃 있는 다운
    sw = p["switches"][0]
    ports = {x["name"]: x for x in sw["ports"]}
    assert "Vlan101" not in ports and ports["Port-Channel10"]["kind"] == "lag" and ports["Ethernet8"]["cls"] == "down" and ports["Ethernet7"]["cls"] == "alert"
    assert ports["Ethernet9"]["peer"]["name"] == "esx02.lab" and ports["Ethernet9"]["peer"]["proto"] == "esxi-lldp"
    assert [x["name"] for x in sw["ports"]][:5] == ["Ethernet5", "Ethernet6", "Ethernet7", "Ethernet8", "Ethernet9"]
    h1 = next(h for h in p["hosts"] if h["name"] == "esx01.lab")
    n1 = {n["name"]: n for n in h1["nics"]}
    assert n1["vmnic0"]["source"] == ["switch", "esxi"] and n1["vmnic1"]["peer"]["port"] == "Ethernet6" and n1["vmnic1"]["switch_speed"] == 25000
    assert h1["state"] == "warn" and p["summary"]["no_redundancy"] == 1
    hosts["esx01.lab"]["pnics"][0]["peer"] = {"switch": "leaf1", "port": "Ethernet15"}          # ESXi·스위치가 다른 포트를 가리킴
    p = portmap.build(NS(connectors=[l1, vc]))
    assert any(f["kind"] == "lldp-mismatch" and f["port"] == "vmnic0" for f in p["findings"])
    assert portmap.port_kind("TenGigabitEthernet1/0/1") == "phys" and portmap.port_kind("Management1") == "mgmt" and portmap.port_kind("Loopback0") == "logical"


def test_rightsizing_reasons_and_cluster_summary():
    e = _env()
    e.store = _store()
    e.billing = billing.Billing(e, {})
    C = capacity.Capacity(e, {})
    t = e.connectors[0].topology
    t["vms"]["big"] = {"host": "esx01", "power": "poweredOn", "ips": [], "networks": [], "vcpu": 16, "mem_mb": 65536, "prov_gb": 200, "cluster": "CL", "folder": "DC",
                       "tags": [], "cpu_mhz": 1600, "mem_used_mb": 3277, "moid": "vm-9"}
    t["vms"]["hot"] = {"host": "esx01", "power": "poweredOn", "ips": [], "networks": [], "vcpu": 2, "mem_mb": 4096, "prov_gb": 40, "cluster": "CL", "folder": "DC",
                       "tags": [], "cpu_mhz": 3600, "mem_used_mb": 3800, "moid": "vm-7"}

    async def go():
        base = 1_800_000_000 - 1_800_000_000 % 86400
        for h in range(30):
            await e.billing.sample(base + h * 3600 + 10)
        return await C.rightsizing(7)
    rs = asyncio.run(go())
    big = next(x for x in rs["oversized"] if x["vm"] == "big")
    assert "vCPU 16→2" in big["action"] and "축소" in big["action"] and "CPU 피크" in big["why"] and big["confidence"] == "low"
    hot = rs["undersized"][0]
    assert "증설" in hot["action"] and hot["saving"] is None
    S = rs["summary"]
    assert S["judged"] >= 3 and S["ok"] == S["judged"] - len({x["vm"] for x in rs["oversized"] + rs["undersized"] + rs["idle"]})
    assert S["rec_vcpu"] == S["alloc_vcpu"] - S["reclaim_vcpu"] + S["add_vcpu"]
    cl = next(c for c in rs["clusters"] if c["cluster"] == "CL")
    assert cl["oversized"] >= 1 and cl["undersized"] == 1 and cl["reclaim_vcpu"] >= 14 and cl["add_vcpu"] == 1
    csv = capacity.Capacity.to_csv({"items": []}, rs)
    assert "판단 신뢰도" in csv and "축소" in csv
