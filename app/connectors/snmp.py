"""SNMP 트랩 수신기 (v1 / v2c / v3 USM, UDP 162) — pysnmp 7 asyncio.

트랩을 LogEvent로 정규화해 syslog·API 로그와 같은 탐지·LLM·알림 파이프라인으로 보낸다.
- 내장 OID 사전: SNMPv2 표준 트랩, VMware VC-EVENT / ENV / VMINFO MIB, 주요 벤더 enterprise 접두사
- config.snmp.oid_map 으로 사내/벤더 OID 이름·심각도 추가 가능
- 송신 장비 IP 또는 enterprise OID로 소스(esxi·vcenter·nsx·redfish·network 등) 자동 분류

송신 측 설정 예
  ESXi : esxcli system snmp set --targets <aiops>@162/public --enable true
         (v3) esxcli system snmp set --v3targets <aiops>@162/<user>/priv/trap
  vCenter: VAMI 또는 vSphere Client > vCenter > 설정 > SNMP 수신기 (알람 액션 'SNMP 트랩 전송')
  iLO  : 관리 > SNMP 설정 > 트랩 대상 <aiops>, 커뮤니티 public
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from ..models import LogEvent, norm_severity
from ..runtime import bg
from .base import Connector

try:
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.api import v2c
except ImportError:  # pragma: no cover
    engine = None

SNMP_TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"      # v1→v2 변환 시 enterprise
TRAP_ADDRESS = "1.3.6.1.6.3.18.1.3.0"          # snmpTrapAddress (v1 agent-addr)
TRAP_COMMUNITY = "1.3.6.1.6.3.18.1.4.0"        # snmpTrapCommunity (커뮤니티 문자열 — 로그에 남기지 않음)

# OID → (이름, 기본 심각도, 소스)   출처: SNMPv2-MIB / IF-MIB / VMWARE-VC-EVENT-MIB / VMWARE-ENV-MIB / VMWARE-VMINFO-MIB
TRAPS: dict[str, tuple[str, str, str]] = {
    "1.3.6.1.6.3.1.1.5.1": ("coldStart", "warning", ""),
    "1.3.6.1.6.3.1.1.5.2": ("warmStart", "warning", ""),
    "1.3.6.1.6.3.1.1.5.3": ("linkDown", "error", ""),
    "1.3.6.1.6.3.1.1.5.4": ("linkUp", "info", ""),
    "1.3.6.1.6.3.1.1.5.5": ("authenticationFailure", "warning", ""),
    "1.3.6.1.4.1.6876.4.3.0.201": ("vpxdAlarm", "warning", "vcenter"),
    "1.3.6.1.4.1.6876.4.3.0.202": ("vpxdDiagnostic", "info", "vcenter"),
    "1.3.6.1.4.1.6876.4.3.0.203": ("vpxdAlarmInfo", "warning", "vcenter"),
    "1.3.6.1.4.1.6876.4.1.0.1": ("vmwVmPoweredOn", "info", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.2": ("vmwVmPoweredOff", "warning", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.3": ("vmwVmHBLost", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.4": ("vmwVmHBDetected", "info", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.5": ("vmwVmSuspended", "warning", "esxi"),
    "1.3.6.1.4.1.6876.0.301": ("vmwEnvHardwareEvent", "warning", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.301": ("vmwESXEnvHardwareEvent", "warning", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.302": ("vmwESXEnvHardwareAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.303": ("vmwESXEnvBatteryAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.304": ("vmwESXEnvChassisAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.305": ("vmwESXEnvThermalAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.306": ("vmwESXEnvDiskAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.307": ("vmwESXEnvPowerAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.308": ("vmwESXEnvProcessorAlert", "critical", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.309": ("vmwESXEnvMemoryAlert", "critical", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.310": ("vmwESXEnvBIOSAlert", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.390": ("vmwEnvIpmiSelFull", "warning", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.400": ("vmwEnvIpmiSelMemoryRaised", "critical", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.401": ("vmwEnvIpmiSelMemoryCleared", "info", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.410": ("vmwEnvIpmiSelPowerSupplyRaised", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.411": ("vmwEnvIpmiSelPowerSupplyCleared", "info", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.420": ("vmwEnvIpmiSelFanRaised", "error", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.421": ("vmwEnvIpmiSelFanCleared", "info", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.430": ("vmwEnvIpmiSelCpuRaised", "critical", "esxi"),
    "1.3.6.1.4.1.6876.4.1.0.431": ("vmwEnvIpmiSelCpuCleared", "info", "esxi"),
}

# 변수 OID → 이름 (위 MIB 정의 기준)
VARS: dict[str, str] = {
    "1.3.6.1.4.1.6876.4.3.301": "vmwVpxdTrapType", "1.3.6.1.4.1.6876.4.3.302": "vmwVpxdHostName",
    "1.3.6.1.4.1.6876.4.3.303": "vmwVpxdVMName", "1.3.6.1.4.1.6876.4.3.304": "vmwVpxdOldStatus",
    "1.3.6.1.4.1.6876.4.3.305": "vmwVpxdNewStatus", "1.3.6.1.4.1.6876.4.3.306": "vmwVpxdObjValue",
    "1.3.6.1.4.1.6876.4.3.307": "vmwVpxdTargetObj", "1.3.6.1.4.1.6876.4.3.308": "vmwVpxdTargetObjType",
    "1.3.6.1.4.1.6876.50.101": "vmwVmID", "1.3.6.1.4.1.6876.50.102": "vmwVmConfigFilePath",
    "1.3.6.1.4.1.6876.2.1.1.2": "vmwVmDisplayName",
    "1.3.6.1.4.1.6876.4.20.3.1.2": "vmwSubsystemType", "1.3.6.1.4.1.6876.4.20.3.1.3": "vmwHardwareStatus",
    "1.3.6.1.4.1.6876.4.20.3.1.4": "vmwEventDescription", "1.3.6.1.4.1.6876.4.20.3.1.5": "vmwEnvHardwareTime",
    "1.3.6.1.4.1.6876.4.20.3.1.7": "vmwEnvSelSensorNumber", "1.3.6.1.4.1.6876.4.20.30": "vmwSELCapacity",
    "1.3.6.1.4.1.6876.4.30.1": "vmwEnvDescription", "1.3.6.1.4.1.6876.4.30.2": "vmwEnvEventTime",
    "1.3.6.1.4.1.6876.4.30.3": "vmwEnvIndicationTime", "1.3.6.1.4.1.6876.4.30.4": "vmwEnvPerceivedSeverity",
    "1.3.6.1.4.1.6876.4.30.5": "vmwEnvAlertType", "1.3.6.1.4.1.6876.4.30.6": "vmwEnvSysCreationClassName",
    "1.3.6.1.4.1.6876.4.30.7": "vmwEnvAlertingElement", "1.3.6.1.4.1.6876.4.30.8": "vmwEnvAlertingFormat",
    "1.3.6.1.4.1.6876.4.30.9": "vmwEnvSystemName", "1.3.6.1.4.1.6876.4.30.10": "vmwEnvProviderName",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex", "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus", "1.3.6.1.2.1.31.1.1.1.1": "ifName", "1.3.6.1.2.1.1.5.0": "sysName",
}

# enterprise 접두사 → 소스 분류 (IANA Private Enterprise Numbers)
ENTERPRISE_SOURCE = [
    ("1.3.6.1.4.1.6876.", "vmware"), ("1.3.6.1.4.1.232.", "redfish"), ("1.3.6.1.4.1.674.", "redfish"),
    ("1.3.6.1.4.1.19046.", "redfish"), ("1.3.6.1.4.1.2.6.", "redfish"), ("1.3.6.1.4.1.9.", "network"),
    ("1.3.6.1.4.1.2636.", "network"), ("1.3.6.1.4.1.30065.", "network"), ("1.3.6.1.4.1.2011.", "network"),
    ("1.3.6.1.4.1.789.", "storage"), ("1.3.6.1.4.1.1139.", "storage"), ("1.3.6.1.4.1.12740.", "storage"),
    ("1.3.6.1.4.1.40482.", "storage"),
]
VENDOR = {"232": "HPE", "674": "Dell", "19046": "Lenovo", "2": "IBM", "9": "Cisco", "2636": "Juniper",
          "30065": "Arista", "2011": "Huawei", "789": "NetApp", "1139": "Dell EMC", "12740": "Dell EqualLogic",
          "40482": "Pure Storage", "6876": "VMware"}

# VMWARE-TC-MIB: VmwSubsystemStatus / VmwCIMSeverity (CIM PerceivedSeverity)
HW_STATUS = {"1": ("unknown", "warning"), "2": ("normal", "info"), "3": ("marginal", "warning"),
             "4": ("critical", "critical"), "5": ("failed", "critical")}
CIM_SEV = {"0": "info", "1": "info", "2": "info", "3": "warning", "4": "warning", "5": "error", "6": "critical", "7": "critical"}

AUTH = {"MD5": "USM_AUTH_HMAC96_MD5", "SHA": "USM_AUTH_HMAC96_SHA", "SHA224": "USM_AUTH_HMAC128_SHA224",
        "SHA256": "USM_AUTH_HMAC192_SHA256", "SHA384": "USM_AUTH_HMAC256_SHA384", "SHA512": "USM_AUTH_HMAC384_SHA512",
        "NONE": "USM_AUTH_NONE"}
PRIV = {"DES": "USM_PRIV_CBC56_DES", "AES": "USM_PRIV_CFB128_AES", "AES128": "USM_PRIV_CFB128_AES",
        "AES192": "USM_PRIV_CFB192_AES", "AES256": "USM_PRIV_CFB256_AES", "NONE": "USM_PRIV_NONE"}


def _val(v: Any) -> str:
    try:
        if hasattr(v, "prettyPrint"):
            s = v.prettyPrint()
            if s.startswith("0x") and len(s) > 2:      # OctetString 바이너리 → 텍스트 시도
                try:
                    return bytes.fromhex(s[2:]).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    return s
            return s
        return str(v)
    except Exception:  # noqa: BLE001
        return str(v)


class SnmpTrapReceiver(Connector):
    type = "snmp"
    source = "snmp"

    def __init__(self, cfg, emit):
        super().__init__({"name": "snmp-trap", **cfg}, emit)
        self.bind = cfg.get("bind", "0.0.0.0")
        self.port = int(cfg.get("port", 162))
        self.communities = cfg.get("communities") or ["public"]
        self.v3_users = cfg.get("v3_users") or []
        self.host_map: dict[str, dict] = {h["ip"]: h for h in (cfg.get("hosts") or []) if h.get("ip")}
        self.traps = dict(TRAPS)
        self.vars = dict(VARS)
        for oid, v in (cfg.get("oid_map") or {}).items():     # 사용자 OID 사전
            oid = oid.lstrip(".")
            if isinstance(v, dict) and v.get("trap", True) and v.get("severity"):
                self.traps[oid] = (v.get("name", oid), norm_severity(v.get("severity"), "warning"), v.get("source", ""))
            else:
                self.vars[oid] = v["name"] if isinstance(v, dict) else str(v)
        self.peers: dict[str, int] = {}
        self.unknown: dict[str, int] = {}
        self._state["target"] = f"udp/{self.port}"
        self.engine = None

    # ------------------------------------------------------------ 설정
    def _setup(self):
        if engine is None:
            raise RuntimeError("pysnmp 미설치 (pip install pysnmp)")
        e = engine.SnmpEngine()
        if self.cfg.get("engine_id"):
            e = engine.SnmpEngine(snmpEngineID=bytes.fromhex(self.cfg["engine_id"].replace(":", "")))
        config.add_transport(e, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode((self.bind, self.port)))
        for i, c in enumerate(self.communities):
            config.add_v1_system(e, f"area-{i}", c)
        for u in self.v3_users:
            kw = {"authProtocol": getattr(config, AUTH[str(u.get("auth_protocol", "SHA")).upper()]),
                  "privProtocol": getattr(config, PRIV[str(u.get("priv_protocol", "AES")).upper()])}
            if u.get("auth_key"):
                kw["authKey"] = u["auth_key"]
            if u.get("priv_key"):
                kw["privKey"] = u["priv_key"]
            if u.get("engine_id"):     # 트랩은 송신 장비가 authoritative → 장비 engineID 필요
                kw["securityEngineId"] = v2c.OctetString(hexValue=u["engine_id"].replace(":", "").replace("0x", ""))
            config.add_v3_user(e, u["user"], **kw)
        ntfrcv.NotificationReceiver(e, self._on_trap)
        self.engine = e

    async def run(self):
        if not self.enabled:
            return
        if not getattr(self, "_ready", False):
            try:
                self._setup()
                self._ready = True
                self._state.update(state="ok", auth=f"v1/v2c {len(self.communities)} · v3 {len(self.v3_users)}",
                                   last_ok=time.time())
            except Exception as e:  # noqa: BLE001
                self._state.update(state="down", last_error=f"{type(e).__name__}: {e}"[:300])
        # pysnmp 디스패처는 현재 이벤트 루프에 UDP 엔드포인트를 등록 — 작업은 살아 있게 유지(감독자가 '종료'로 보고 반복 재기동하지 않도록)
        try:
            while True:
                await asyncio.sleep(3600)
        finally:                                     # 설정 재적용으로 취소되면 UDP 포트 반납(새 수신기가 다시 바인드)
            if getattr(self, "_ready", False) and getattr(self, "engine", None) is not None:
                try:
                    self.engine.transport_dispatcher.close_dispatcher()
                except Exception:  # noqa: BLE001
                    pass
                self._ready = False

    # ------------------------------------------------------------ 수신 콜백
    def _on_trap(self, snmp_engine, state_ref, ctx_engine_id, ctx_name, var_binds, cb_ctx):
        try:
            _dom, addr = snmp_engine.message_dispatcher.get_transport_info(state_ref)
            peer = addr[0]
        except Exception:  # noqa: BLE001
            peer = "unknown"
        self.peers[peer] = self.peers.get(peer, 0) + 1
        try:
            ev = self.decode(peer, [(str(o), v) for o, v in var_binds])
        except Exception as e:  # noqa: BLE001
            self._state["last_error"] = f"decode: {e}"[:300]
            return
        self._state["events_total"] += 1
        self._state["last_ok"] = time.time()
        bg(self.emit(ev))

    def decode(self, peer: str, vbs: list[tuple[str, Any]]) -> LogEvent:
        trap_oid, uptime, enterprise, agent = "", "", "", ""
        fields: dict[str, str] = {}
        for oid, v in vbs:
            oid = oid.lstrip(".")
            if oid == SNMP_TRAP_OID:
                trap_oid = _val(v).lstrip(".")
            elif oid == SYS_UPTIME:
                uptime = _val(v)
            elif oid == TRAP_ENTERPRISE:
                enterprise = _val(v).lstrip(".")
            elif oid == TRAP_ADDRESS:
                agent = _val(v)
            elif oid == TRAP_COMMUNITY:
                continue
            else:
                fields[self._var_name(oid)] = _val(v)
        name, sev, src = self.traps.get(trap_oid, ("", "", ""))
        if not name:
            self.unknown[trap_oid] = self.unknown.get(trap_oid, 0) + 1
            name = trap_oid
        if agent in ("", "0.0.0.0"):
            agent = ""
        host_cfg = self.host_map.get(agent or peer, {})
        host = host_cfg.get("name") or fields.get("sysName") or fields.get("vmwVpxdHostName") or agent or peer
        source = host_cfg.get("source") or src or self._classify(trap_oid or enterprise)
        vendor = VENDOR.get((trap_oid or enterprise).split(".")[6] if (trap_oid or enterprise).startswith("1.3.6.1.4.1.") else "", "")

        # 트랩별 심각도·메시지 보정
        msg = ""
        if name.startswith("vpxdAlarm"):
            new = fields.get("vmwVpxdNewStatus", "").lower()
            sev = {"red": "critical", "yellow": "warning", "green": "info", "gray": "warning"}.get(new, sev or "warning")
            tgt = fields.get("vmwVpxdTargetObj") or fields.get("vmwVpxdVMName") or fields.get("vmwVpxdHostName", "")
            msg = (f"vCenter 알람 {fields.get('vmwVpxdOldStatus', '?')}→{fields.get('vmwVpxdNewStatus', '?')} "
                   f"[{tgt}] {fields.get('vmwVpxdObjValue', '')}").strip()
        elif "vmwHardwareStatus" in fields:
            st, s2 = HW_STATUS.get(fields["vmwHardwareStatus"], (fields["vmwHardwareStatus"], sev))
            sev = s2
            msg = f"ESXi 하드웨어 이벤트 [{fields.get('vmwSubsystemType', '')}] 상태={st} {fields.get('vmwEventDescription', '')}"
        elif "vmwEnvPerceivedSeverity" in fields:
            sev = CIM_SEV.get(fields["vmwEnvPerceivedSeverity"], sev or "warning")
            msg = f"ESXi CIM 경보 {name} {fields.get('vmwEnvDescription', '')} ({fields.get('vmwEnvAlertingElement', '')})"
        elif name.startswith("vmwVm"):
            msg = f"VM {fields.get('vmwVmDisplayName', '')} {name.replace('vmwVm', '')}"
        elif name in ("linkDown", "linkUp"):
            msg = f"{name} {fields.get('ifName') or fields.get('ifDescr') or ''} (ifIndex {fields.get('ifIndex', '?')}) oper={fields.get('ifOperStatus', '?')}"
        if not sev:
            text = " ".join(fields.values()).lower()
            sev = ("critical" if any(w in text for w in ("critical", "fatal", "failed", "failure")) else
                   "error" if any(w in text for w in ("error", "down", "fault", "lost")) else
                   "warning" if any(w in text for w in ("warn", "degrad", "major", "minor")) else "info")
        if not msg:
            detail = " ".join(f"{k}={v}" for k, v in list(fields.items())[:8])
            msg = f"SNMP 트랩 {name}{' (' + vendor + ')' if vendor else ''} {detail}".strip()
        return LogEvent(source=source, connector=self.name, message=msg[:3000], severity=sev, host=host,
                        entity=fields.get("vmwVpxdTargetObj") or fields.get("vmwVmDisplayName") or fields.get("ifName") or name,
                        kind="alarm" if sev in ("critical", "error") else "event",
                        attrs={"snmp_trap_oid": trap_oid, "snmp_trap": name, "peer": peer, "uptime": uptime,
                               "vendor": vendor, "varbinds": fields})

    def _var_name(self, oid: str) -> str:
        if oid in self.vars:
            return self.vars[oid]
        base, _, idx = oid.rpartition(".")          # 테이블 인스턴스(ifIndex 등) 제거 후 재조회
        if base in self.vars:
            return self.vars[base]
        return oid

    @staticmethod
    def _classify(oid: str) -> str:
        for pre, src in ENTERPRISE_SOURCE:
            if oid.startswith(pre):
                return "esxi" if src == "vmware" else src
        return "snmp"

    def state(self):
        c = {f"송신자 {p}": f"ok {n}건" for p, n in sorted(self.peers.items(), key=lambda x: -x[1])[:15]}
        c.update({f"미등록 OID {o}": f"{n}건 (oid_map 추가 권장)" for o, n in sorted(self.unknown.items(), key=lambda x: -x[1])[:5]})
        self._state["checks"] = c
        return self._state

    async def test(self):
        return {"ok": self._state["state"] == "ok", "checks": self.state()["checks"] or {"수신": "아직 수신된 트랩 없음"},
                "error": self._state["last_error"]}
