"""2.4 — running-config 해석(포트 사용 구분·마스킹·변경 감지), 구성 기반 포트 점검, 구성도 논리 계층(NSX·VPC·Avi·VM·Pod)·전면 포트 패널"""
import asyncio
from types import SimpleNamespace as NS

from app import netconfig as NC
from app import netmap, portmap
from app.connectors.demo import DemoGenerator

EOS = """hostname leaf1
username admin privilege 15 secret sha512 $6$abc
snmp-server community Pub1ic ro
vlan 120
   name APP
!
interface Ethernet1
   description esx01 vmnic0
   switchport mode trunk
   switchport trunk allowed vlan 100-110,120
   switchport trunk allowed vlan add 130
   mtu 9214
!
interface Ethernet2
   shutdown
!
interface Ethernet3
!
interface Ethernet4
   switchport access vlan 30
!
interface Ethernet49/1
   no switchport
   ip address 10.0.0.1 255.255.255.254
   channel-group 10 mode active
!
management api http-commands
   no shutdown
"""


def test_parse_mask_usage_and_diff():
    p = NC.parse(EOS)
    i = p["interfaces"]
    assert i["Ethernet1"]["mode"] == "trunk" and NC.vlan_list(i["Ethernet1"]["trunk_vlans"]) == set(range(100, 111)) | {120, 130} and i["Ethernet1"]["mtu"] == 9214
    assert i["Ethernet2"]["shutdown"] and i["Ethernet4"]["access_vlan"] == 30 and i["Ethernet49/1"]["ip"] == "10.0.0.1/31" and i["Ethernet49/1"]["channel_group"] == "10"
    assert p["vlans"][120] == "APP" and p["global"]["eapi"] is True and p["hostname"] == "leaf1"
    m = NC.mask(EOS)
    assert "Pub1ic" not in m and "$6$abc" not in m and m.count("<가림>") == 2
    assert NC.port_usage("up", "connected", i["Ethernet1"], True) == "in_use"
    assert NC.port_usage("down", "notconnect", i["Ethernet2"], False) == "shut"
    assert NC.port_usage("down", "notconnect", i["Ethernet3"], False) == "open"
    assert NC.port_usage("down", "notconnect", i["Ethernet4"], False) == "configured"
    assert NC.port_usage("down", "errdisabled", None, False) == "err"
    assert NC.vlan_list("all") is None and NC.vlan_list("none") == set()
    d = NC.diff_summary(m, m.replace("   mtu 9214", "   mtu 1500"))
    assert d["added"] == 1 and d["removed"] == 1 and "interface Ethernet1" in d["blocks"]
    assert NC.digest("! Time: 1\nhostname a") == NC.digest("! Time: 2\nhostname a")


def test_iosxe_native_json_converted():
    j = {"Cisco-IOS-XE-native:interface": {"GigabitEthernet": [
        {"name": "1/0/1", "description": "esx01", "switchport": {"Cisco-IOS-XE-switch:mode": {"trunk": {}},
                                                                   "Cisco-IOS-XE-switch:trunk": {"allowed": {"vlan": {"vlans": "100,120"}}}}},
        {"name": "1/0/2", "shutdown": [None]}]}}
    text, p = NC.from_iosxe_native(j)
    assert p["interfaces"]["GigabitEthernet1/0/1"]["trunk_vlans"] == "100,120" and p["interfaces"]["GigabitEthernet1/0/2"]["shutdown"]


def _demo():
    d = DemoGenerator({}, lambda e: None)

    async def go():
        for f in d.fakes:
            if getattr(f, "vendor", ""):
                f.first_poll = False
                await f.poll()
    asyncio.run(go())
    return NS(connectors=[d] + d.fakes, anomalies={})


def test_config_change_event_and_findings():
    e = _demo()
    leaf = next(c for c in e.connectors if getattr(c, "vendor", "") and c.device.get("hostname") == "dc1-leaf-01")
    assert leaf.config["lines"] > 50 and "<가림>" in leaf.config["text"]
    orig = leaf.fetch_config

    async def changed():
        t, _ = await orig()
        t = t.replace("interface Ethernet22\n", "interface Ethernet22\n   description new-server\n")
        return t, NC.parse(t)
    leaf.fetch_config, leaf._cfg_at = changed, 0
    ev = asyncio.run(leaf.poll())
    assert any("구성 변경 감지" in x.message and "interface Ethernet22" in x.message for x in ev)
    p = portmap.build(e)
    kinds = {(f["device"], f["kind"]) for f in p["findings"]}
    assert ("esx03.vcf.lab", "vlan-missing") in kinds and ("dc1-leaf-01", "desc-mismatch") in kinds and ("dc1-leaf-03", "mtu-mismatch") in kinds
    assert ("dc1-leaf-01", "unused-open") in kinds
    sw = next(s for s in p["switches"] if s["name"] == "dc1-leaf-01")
    e5 = next(x for x in sw["ports"] if x["name"] == "Ethernet5")
    assert e5["usage"] == "in_use" and e5["cfg"]["mode"] == "trunk" and sw["usage"]["open"] >= 1


def test_network_map_logical_layers_and_panel():
    e = _demo()
    m = netmap.build(e)
    kinds = {n["kind"]: n.get("tier") for n in m["nodes"]}
    assert kinds["t0"] == 6 and kinds["t1"] == 7 and kinds["vpc"] == 7 and kinds["vpc-subnet"] == 8 and kinds["vm"] == 9 and kinds["pod"] == 10
    assert kinds["se"] == 4 and kinds["avi-ctrl"] == 4 and kinds["vs"] == 6 and kinds["edge"] == 4
    lk = {l.get("kind", "phys") for l in m["links"]}
    assert {"phys", "bgp", "logical", "vnic", "pod", "pool", "mgmt"} <= lk
    sw = next(n for n in m["nodes"] if n["kind"] == "switch")
    assert sw["panel"] and {"n", "s", "u"} <= set(sw["panel"][0]) and sum(sw["usage"].values()) == len(sw["panel"])
    assert any(l.get("a_s") for l in m["links"] if l.get("kind", "phys") == "phys")
    phys_only = netmap.build(e, layers=set())
    assert not any(n["kind"] in ("vm", "t1", "vs") for n in phys_only["nodes"])
