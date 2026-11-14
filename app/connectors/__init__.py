"""config.connectors[] → 커넥터 인스턴스 생성. type 값은 아래 REGISTRY 키."""
from __future__ import annotations

from .base import Connector
from .demo import DemoGenerator
from .fortigate import FortiGateConnector
from .ucsm import UcsManagerConnector
from .kubernetes import VksConnector
from .network import AristaEosConnector, CiscoAutoConnector, CiscoIosxeConnector, CiscoNxosConnector, SnmpSwitchConnector
from .redfish import RedfishConnector
from .snmp import SnmpTrapReceiver
from .syslog import SyslogReceiver
from .vcenter import VCenterConnector
from .vmware_rest import (AviConnector, NsxConnector, SddcManagerConnector, SrmConnector,
                          VcfAutomationConnector, VcfLogsConnector, VcfOpsConnector)

REGISTRY: dict[str, type[Connector]] = {
    "vcenter": VCenterConnector,
    "sddc": SddcManagerConnector,
    "nsx": NsxConnector,
    "vcfops": VcfOpsConnector,
    "vcflogs": VcfLogsConnector,
    "vcfa": VcfAutomationConnector,
    "srm": SrmConnector,
    "avi": AviConnector,
    "nsx-alb": AviConnector,       # NSX Advanced Load Balancer(Avi)
    "vks": VksConnector,           # vSphere Kubernetes Service — role: supervisor | workload
    "kubernetes": VksConnector,
    "redfish": RedfishConnector,   # iLO / iDRAC / XCC
    "ilo": RedfishConnector,
    "idrac": RedfishConnector,
    "fortigate": FortiGateConnector,
    "arista": AristaEosConnector,      # Arista EOS eAPI — 상태·LLDP·MLAG·BGP(로그는 syslog)
    "cisco": CiscoAutoConnector,       # Cisco — platform: auto(NX-API → RESTCONF → SNMP) | nxos | iosxe | snmp
    "nxos": CiscoNxosConnector,
    "iosxe": CiscoIosxeConnector,
    "snmp-switch": SnmpSwitchConnector,  # 기타 스위치·라우터(SNMP v2c/v3 — IF-MIB·LLDP-MIB·CDP-MIB)
    "ucsm": UcsManagerConnector,       # Cisco UCS Manager(패브릭 인터커넥트) — B-Series 블레이드·UCSM 관리 C-Series   # FortiOS REST(상태·자원) — 로그는 syslog 수신기에서 자동 인식
}


def build(cfg: dict, emit) -> list[Connector]:
    out: list[Connector] = []
    for c in cfg.get("connectors", []) or []:
        cls = REGISTRY.get(str(c.get("type", "")).lower())
        if not cls:
            raise ValueError(f"알 수 없는 커넥터 type: {c.get('type')} (가능: {', '.join(REGISTRY)})")
        hosts = c.get("hosts")
        if hosts:   # 동일 계정의 BMC/ESXi 다수 등록: hosts: [a, b, {host: c, esxi_host: esx03.vcf.lab, name: srv03}]
            base = {k: v for k, v in c.items() if k != "hosts"}
            for h in hosts:
                hd = h if isinstance(h, dict) else {"host": str(h)}
                name = hd.get("name") or (f"{c['name']}-" if c.get("name") else "") + str(hd["host"]).split(".")[0]
                out.append(cls({**base, **hd, "name": name}, emit))
        else:
            out.append(cls(c, emit))
    if cfg["syslog"].get("enabled"):
        out.append(SyslogReceiver(cfg["syslog"], emit))
    if cfg.get("snmp", {}).get("enabled"):
        out.append(SnmpTrapReceiver(cfg["snmp"], emit))
    if cfg["demo"].get("enabled"):
        d = DemoGenerator(cfg["demo"], emit)
        out.append(d)
        out += d.fakes
    return out
