"""2.2 — 네트워크 장비(Arista eAPI · Cisco NX-API · IOS-XE RESTCONF · SNMP) 수집, 변화 이벤트, syslog 분류, 전체 구성도"""
import asyncio
import json
from types import SimpleNamespace as NS

import httpx

from app import netmap
from app.connectors import REGISTRY, Connector
from app.connectors import network as N
from app.connectors import syslog as S


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://sw")


def _arista_handler(state):
    def h(req: httpx.Request):
        assert req.url.path == "/command-api" and req.headers.get("authorization", "").startswith("Basic ")
        body = json.loads(req.content)
        assert body["method"] == "runCmds" and body["params"]["format"] == "json" and body["params"]["version"] == 1
        res = []
        for c in body["params"]["cmds"]:
            if c == "show version":
                res.append({"modelName": "DCS-7050SX3-48YC8", "version": state.get("ver", "4.32.2F"), "serialNumber": "JPE123", "uptime": 3600.0})
            elif c == "show hostname":
                res.append({"hostname": "leaf1", "fqdn": "leaf1.lab"})
            elif c == "show interfaces status":
                res.append({"interfaceStatuses": {"Ethernet1": {"linkStatus": state.get("e1", "connected"), "description": "esx01 vmnic0", "bandwidth": 25000000000,
                                                                "vlanInformation": {"vlanId": 10}},
                                                  "Ethernet49/1": {"linkStatus": "connected", "description": "", "bandwidth": 100000000000},
                                                  "Ethernet9": {"linkStatus": "notconnect", "description": "", "bandwidth": 0}}})
            elif c == "show lldp neighbors detail":
                nbs = {"Ethernet49/1": {"lldpNeighborInfo": [{"systemName": "spine1.lab", "neighborInterfaceInfo": {"interfaceId_v2": "Ethernet1/1"},
                                                              "managementAddresses": [{"address": "10.0.0.1"}], "systemDescription": "Arista Networks EOS"}]}}
                if state.get("e1", "connected") == "connected":
                    nbs["Ethernet1"] = {"lldpNeighborInfo": [{"systemName": "esx01.vcf.lab", "neighborInterfaceInfo": {"interfaceId_v2": "vmnic0"},
                                                             "systemDescription": "VMware ESX Releasebuild"}]}
                res.append({"lldpNeighbors": nbs})
            elif c == "show mlag":
                res.append({"state": state.get("mlag", "active"), "negStatus": "connected", "peerLinkStatus": "up", "localIntfStatus": "up", "domainId": "m1"})
            elif c.startswith("show ip bgp summary"):
                res.append({"vrfs": {"default": {"peers": {"10.0.0.1": {"peerState": state.get("bgp", "Established"), "asn": "65000", "prefixReceived": 12}}}}})
            else:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": "aiops", "error": {"code": 1002, "message": f"invalid command '{c}'"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "aiops", "result": res})
    return h


def test_arista_eapi_collect_and_change_events():
    state = {}
    c = N.AristaEosConnector({"name": "leaf1", "host": "10.9.9.1", "username": "ro", "password": "p"}, None)
    c._http = _client(_arista_handler(state))
    asyncio.run(c.login())
    assert asyncio.run(c.poll()) == []                                     # 첫 수집은 기준선
    c.first_poll = False
    s = c.snapshot()
    assert s["name"] == "leaf1" and s["model"] == "DCS-7050SX3-48YC8" and s["version"] == "4.32.2F" and s["ifs_up"] == 2 and s["mlag"]["state"] == "active"
    assert {n["remote"] for n in s["neighbors"]} == {"spine1.lab", "esx01.vcf.lab"} and s["bgp"][0]["state"] == "Established"
    state.update(e1="notconnect", mlag="inactive", bgp="Idle", ver="4.33.0F")
    ev = asyncio.run(c.poll())
    msgs = " | ".join(e.message for e in ev)
    assert "인터페이스 Ethernet1 다운(notconnect) (→ esx01.vcf.lab vmnic0)" in msgs and any(e.severity == "error" and "Ethernet1" in e.message for e in ev)
    assert "LLDP/CDP 이웃 사라짐 — Ethernet1 → esx01.vcf.lab vmnic0" in msgs
    assert any(e.severity == "critical" and e.message.startswith("MLAG state active → inactive") for e in ev)
    assert any("BGP 피어 10.0.0.1" in e.message and "Established → Idle" in e.message and e.severity == "error" for e in ev)
    assert any("OS 버전 변경 4.32.2F → 4.33.0F" in e.message for e in ev)
    assert all(e.source == "arista" for e in ev)
    s = c.snapshot()
    assert s["state"] == "down"                                          # MLAG inactive → 장애
    assert any(n["state"] == "lost" and n["remote"] == "esx01.vcf.lab" for n in s["neighbors"])        # 사라진 링크 유지
    assert N.NET_PEERS.get("10.9.9.1") == "arista" and N.NET_PEERS.get("leaf1") == "arista"
    state.update(e1="connected")
    ev = asyncio.run(c.poll())
    assert any("Ethernet1 복구(up)" in e.message and e.severity == "info" for e in ev)


def test_nxos_nxapi_tables_single_and_list_rows():
    def h(req):
        b = json.loads(req.content)["ins_api"]
        assert req.url.path == "/ins" and b["type"] == "cli_show" and b["output_format"] == "json"
        cmds = [x.strip() for x in b["input"].split(";")]
        bodies = {"show version": {"host_name": "n9k-a", "chassis_id": "Nexus9000 C93180YC-FX Chassis", "nxos_ver_str": "10.3(4a)", "proc_board_id": "FDO1"},
                  "show hostname": {"hostname": "n9k-a"},
                  "show interface brief": {"TABLE_interface": {"ROW_interface": [{"interface": "Ethernet1/1", "state": "up", "speed": "25G"},
                                                                                {"interface": "Ethernet1/2", "state": "down", "state_rsn_desc": "Administratively down"},
                                                                                {"interface": "Ethernet1/49", "state": "down", "state_rsn_desc": "Link not connected"}]},
                                           "TABLE_mgmt": {"ROW_mgmt": {"interface": "mgmt0", "state": "up"}}},
                  "show lldp neighbors detail": {"TABLE_nbor_detail": {"ROW_nbor_detail": {"l_port_id": "Eth1/1", "sys_name": "esx05.vcf.lab", "port_id": "vmnic0",
                                                                                           "mgmt_addr": "10.10.0.5", "sys_desc": "VMware ESX"}}},
                  "show cdp neighbors": {"TABLE_cdp_neighbor_brief_info": {"ROW_cdp_neighbor_brief_info": [
                      {"device_id": "esx05.vcf.lab", "intf_id": "Ethernet1/1", "port_id": "vmnic0", "platform_id": "VMware ESXi"},
                      {"device_id": "spine1(FDO999)", "intf_id": "Ethernet1/49", "port_id": "Ethernet1/3", "platform_id": "N9K-C9336C-FX2"}]}},
                  "show vpc brief": {"vpc-domain-id": "10", "vpc-peer-status": "peer-ok", "vpc-peer-keepalive-status": "peer-alive",
                                     "TABLE_peerlink": {"ROW_peerlink": {"peer-link-port-state": "1"}}},
                  "show ip bgp summary vrf all": {"TABLE_vrf": {"ROW_vrf": {"vrf-name-out": "default", "TABLE_af": {"ROW_af": {"TABLE_saf": {"ROW_saf": {
                      "TABLE_neighbor": {"ROW_neighbor": [{"neighborid": "10.1.1.1", "state": "Established", "neighboras": "65001"},
                                                          {"neighborid": "10.1.1.2", "state": "Active", "neighboras": "65002"}]}}}}}}}}}
        outs = [{"body": bodies.get(c, {}), "code": "200", "input": c, "msg": "Success"} if c in bodies else {"code": "400", "msg": "bad", "input": c} for c in cmds]
        return httpx.Response(200, json={"ins_api": {"outputs": {"output": outs if len(outs) > 1 else outs[0]}}})
    c = REGISTRY["nxos"]({"name": "n9k", "host": "10.9.9.2", "username": "u", "password": "p"}, None)
    c._http = _client(h)
    asyncio.run(c.login())
    d = asyncio.run(c.collect())
    assert d["device"]["hostname"] == "n9k-a" and d["device"]["version"] == "10.3(4a)"
    assert d["ifaces"]["Ethernet1/1"]["state"] == "up" and d["ifaces"]["Ethernet1/2"]["state"] == "disabled" and d["ifaces"]["Ethernet1/49"]["state"] == "down"
    assert d["ifaces"]["mgmt0"]["state"] == "up"
    rem = {(n["local"], n["remote"], n["proto"]) for n in d["neighbors"]}
    assert ("Eth1/1", "esx05.vcf.lab", "lldp") in rem and ("Ethernet1/49", "spine1(FDO999)", "cdp") in rem
    assert not any(n["proto"] == "cdp" and n["remote"] == "esx05.vcf.lab" for n in d["neighbors"])     # LLDP·CDP 중복 제거
    assert d["mlag"]["kind"] == "vPC" and d["mlag"]["state"] == "peer-ok" and d["bgp"]["10.1.1.2"]["state"] == "Active"
    chk = asyncio.run(c.checks())
    assert chk["NX-API show version"].startswith("ok")


def test_iosxe_restconf_and_cisco_auto_detect():
    def h(req):
        p = req.url.path
        if p == "/ins":
            return httpx.Response(404)
        assert req.headers["accept"] == "application/yang-data+json"
        data = {"/restconf/data/Cisco-IOS-XE-native:native/hostname": {"Cisco-IOS-XE-native:hostname": "c9300-1"},
                "/restconf/data/Cisco-IOS-XE-native:native/version": {"Cisco-IOS-XE-native:version": "17.9"},
                "/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces": {"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": [
                    {"name": "GigabitEthernet1/0/1", "oper-status": "if-oper-state-ready", "admin-status": "if-state-up", "description": "to leaf1", "speed": "1000000000"},
                    {"name": "GigabitEthernet1/0/2", "oper-status": "if-oper-state-no-pass", "admin-status": "if-state-up"}]}},
                "/restconf/data/Cisco-IOS-XE-lldp-oper:lldp-entries": {"Cisco-IOS-XE-lldp-oper:lldp-entries": {"lldp-intf-details": [
                    {"if-name": "GigabitEthernet1/0/1", "lldp-neighbor-details": [{"identifier": "1", "system-name": "leaf1.lab", "port-id": "Ethernet48",
                                                                                   "mgmt-addrs": {"mgmt-addr": [{"mgmt-addr": "10.9.9.1"}]}}]}]}},
                "/restconf/data/Cisco-IOS-XE-cdp-oper:cdp-neighbor-details": {"Cisco-IOS-XE-cdp-oper:cdp-neighbor-details": {"cdp-neighbor-detail": [
                    {"device-name": "ap-01", "local-intf-name": "GigabitEthernet1/0/3", "port-id": "GigabitEthernet0", "platform-name": "cisco AIR-AP"}]}}}
        return httpx.Response(200, json=data[p]) if p in data else httpx.Response(404)
    c = REGISTRY["cisco"]({"name": "c9k", "host": "10.9.9.3", "username": "u", "password": "p"}, None)
    orig = N.CiscoAutoConnector._make

    def make(self, plat):
        x = orig(self, plat)
        x._http = _client(h)
        return x
    N.CiscoAutoConnector._make = make
    try:
        ev = asyncio.run(c.poll())
    finally:
        N.CiscoAutoConnector._make = orig
    s = c.snapshot()
    assert ev == [] and isinstance(c._impl, N.CiscoIosxeConnector) and "iosxe 자동 판별" in c._state["checks"]["플랫폼"]
    assert s["name"] == "c9300-1" and s["os"] == "IOS-XE" and s["ifs_up"] == 1
    assert {n["remote"] for n in s["neighbors"]} == {"leaf1.lab", "ap-01"} and s["neighbors"][0]["remote_mgmt"] == "10.9.9.1"


def test_snmp_collect_lldp_cdp_with_mocked_walk():
    c = REGISTRY["snmp-switch"]({"name": "old", "host": "10.9.9.4", "community": "ro"}, None)
    O = N.OID
    tables = {O["ifName"]: {f"{O['ifName']}.1": "Gi0/1", f"{O['ifName']}.2": "Gi0/2"},
              O["ifOper"]: {f"{O['ifOper']}.1": "1", f"{O['ifOper']}.2": "2"},
              O["ifAdmin"]: {f"{O['ifAdmin']}.1": "1", f"{O['ifAdmin']}.2": "1"},
              O["ifAlias"]: {f"{O['ifAlias']}.2": "uplink-b"}, O["ifHighSpeed"]: {f"{O['ifHighSpeed']}.1": "1000"},
              O["lldpLocPortId"]: {f"{O['lldpLocPortId']}.1": "Gi0/1"},
              O["lldpRemSysName"]: {f"{O['lldpRemSysName']}.0.1.1": "core1.lab"}, O["lldpRemPortId"]: {f"{O['lldpRemPortId']}.0.1.1": "Ethernet3"},
              O["cdpDeviceId"]: {f"{O['cdpDeviceId']}.2.1": "edge-rtr"}, O["cdpDevicePort"]: {f"{O['cdpDevicePort']}.2.1": "Gi0/0/1"},
              O["cdpPlatform"]: {f"{O['cdpPlatform']}.2.1": "cisco ISR4331"}}

    async def walk(oid):
        return tables.get(oid, {})

    async def get(oids):
        return {O["sysName"]: "old-sw", O["sysDescr"]: "Cisco IOS Software, C2960X Software, Version 15.2(7)E8, RELEASE", O["sysUpTime"]: "8640000"}
    c._walk, c._get = walk, get
    d = asyncio.run(c.collect())
    assert d["device"]["hostname"] == "old-sw" and d["device"]["version"] == "15.2(7)E8" and c.vendor == "Cisco" and c.source == "cisco"
    assert d["ifaces"]["Gi0/1"]["state"] == "up" and d["ifaces"]["Gi0/2"]["state"] == "down" and d["ifaces"]["Gi0/2"]["desc"] == "uplink-b"
    assert {(n["local"], n["remote"], n["proto"]) for n in d["neighbors"]} == {("Gi0/1", "core1.lab", "lldp"), ("Gi0/2", "edge-rtr", "cdp")}


def test_syslog_classifies_arista_cisco_and_severity():
    p = S.parse("<187>Oct 15 10:00:00 leaf9 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet3, changed state to down", "10.200.0.9")
    assert p.source == "arista" and p.severity == "warning" and p.attrs["interface"] == "Ethernet3" and p.entity == "leaf9:Ethernet3"
    p = S.parse("<189>: 2026 Oct 15 10:00:00 KST: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/7 is down (Link failure)", "10.200.0.10")
    assert p.source == "cisco" and p.host == "10.200.0.10" and p.message.startswith("%ETHPORT-5-IF_DOWN_LINK_FAILURE") and p.severity == "warning"
    p = S.parse("<187>45: n9k-b: *Oct 15 10:00:00.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up", "10.200.0.11")
    assert p.source == "cisco" and p.host == "n9k-b" and p.severity == "info"
    N.NET_PEERS["10.200.0.12"] = "arista"                                   # 등록된 장비 IP 에서 온 일반 로그
    assert S.parse("<190>Oct 15 10:00:00 leafx Cli: user admin logged in", "10.200.0.12").source == "arista"
    from app import detect
    m = S.parse("<185>: 2026 Oct 15 10:00:00 KST: %VPC-2-PEER_KEEP_ALIVE_RECV_FAIL: In domain 10, VPC peer keep-alive receive has failed", "10.200.0.10")
    hits = [r.name for r in detect.DEFAULT_RULES if (not r.sources or m.source in r.sources) and r.pattern.search(m.message)]
    assert hits == ["net_vpc"]                                              # 'domain … failed' 가 vSAN 규칙에 걸리던 오탐 수정


def test_network_map_from_demo_switches():
    from app.connectors.demo import demo_network, demo_topology
    vc = Connector({"name": "vc"}, None)
    vc.type = "vcenter"
    vc.topology = demo_topology()
    m = netmap.build(NS(connectors=[vc] + demo_network(None)))
    s = m["summary"]
    assert s["switches"] == 6 and s["hosts"] == 8 and s["vendors"] == ["Arista", "Cisco"] and s["links_down"] == 2
    tiers = {n["label"]: n["tier"] for n in m["nodes"]}
    assert tiers["dc1-spine-01"] == 1 and tiers["dc1-leaf-03"] == 2 and tiers["esx01.vcf.lab"] == 3 and tiers["dc1-border-01.corp.lab"] == 0
    sl = [l for l in m["links"] if {l["a"], l["b"]} == {"sw:dc1-spine-01", "sw:dc1-leaf-01"}]
    assert len(sl) == 1 and sl[0]["seen_both"]                              # 양쪽 LLDP → 한 링크
    assert any(l["state"] == "down" and {l["a"], l["b"]} == {"sw:dc1-spine-02", "sw:dc1-leaf-03"} for l in m["links"])
    assert any(l["state"] == "down" and l["b"] == "host:esx04" for l in m["links"])
    rows = netmap.device_rows(NS(connectors=demo_network(None)))
    assert len(rows) == 6 and any(r["mlag"] == "vPC peer-ok" for r in rows)
    assert {r["iface"] for r in netmap.iface_down_rows(NS(connectors=demo_network(None)))} >= {"Ethernet1/50", "Ethernet8"}
