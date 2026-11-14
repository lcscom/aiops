"""운영 설정 저장소 — 화면에서 편집하는 설정(커넥터·알림·감시·탐지·ITSM·리포트)을 DB에 보관하고
config.yaml 위에 덮어써 적용한다(화면 설정 우선). 비밀 필드는 DPAPI/Fernet 로 암호화 저장.

  부트스트랩(config.yaml): server · auth · llm · rag · syslog · snmp 포트 등 재시작이 필요한 항목
  운영 설정(DB, 즉시 반영): connectors · alerting · monitoring · detection · incidents · itsm · reports · backup
"""
from __future__ import annotations

import copy
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .security.secrets import SECRET_FIELDS, decrypt_tree, encrypt_tree, mask_tree

MANAGED_KEYS = ("connectors", "alerting", "monitoring", "detection", "incidents", "itsm", "reports", "backup", "actions", "vks_overrides", "fortigate", "llm", "knowledge", "siem", "web_search")
MASK = "********"

SCHEMA = "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT, updated REAL, updated_by TEXT);"

# 화면 입력 폼 스키마 (type → 필드). f: 필드명, t: text|password|number|bool|select|list, req: 필수
_COMMON = [
    {"f": "name", "t": "text", "label": "이름", "req": True},
    {"f": "host", "t": "text", "label": "호스트(FQDN/IP[:포트])", "req": True},
    {"f": "username", "t": "text", "label": "계정", "req": True},
    {"f": "password", "t": "password", "label": "비밀번호", "req": True},
    {"f": "interval", "t": "number", "label": "폴링 주기(초)"},
    {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
    {"f": "enabled", "t": "bool", "label": "사용", "default": True},
]
CONNECTOR_SCHEMA: dict[str, dict] = {
    "vcenter": {"label": "vCenter Server", "fields": _COMMON + [
        {"f": "host_logs", "t": "list", "label": "ESXi 호스트 로그 수집(hostd·vmkernel·vpxa)", "hint": "비우면 수집 안 함 · Global.Diagnostics 권한 필요"},
        {"f": "host_log_lines", "t": "number", "label": "호스트 로그 회당 최대 줄"},
        {"f": "vks_discovery", "t": "bool", "label": "VKS 자동 발견(Supervisor·워크로드 클러스터·노드·파드)", "default": True},
        {"f": "vks_log_namespaces", "t": "list", "label": "VKS 파드 로그 실시간 수집 네임스페이스", "hint": "줄마다 하나 · * = 전체(로그량 주의) · 비우면 문제 파드의 마지막 로그만 자동 첨부"},
        {"f": "environment", "t": "select", "label": "환경", "options": ["prod", "dr", "dev", "test"]}]},
    "sddc": {"label": "SDDC Manager", "fields": _COMMON},
    "nsx": {"label": "NSX Manager", "fields": _COMMON + [{"f": "environment", "t": "select", "label": "환경", "options": ["prod", "dr", "dev", "test"]}]},
    "vcfops": {"label": "VCF Operations", "fields": _COMMON + [
        {"f": "auth_source", "t": "text", "label": "인증 소스(선택)"},
        {"f": "token_scheme", "t": "select", "label": "토큰 헤더", "options": ["OpsToken", "vRealizeOpsToken"]},
        {"f": "metrics", "t": "bool", "label": "메트릭 수집(2.8 — 호스트·VM·클러스터·데이터스토어 최신 값)", "default": True},
        {"f": "metric_interval", "t": "number", "label": "메트릭 수집 주기(초, 최소 60 · 기본 300)"},
        {"f": "metric_kinds", "t": "list", "label": "메트릭 대상 종류(resourceKind, 비우면 HostSystem·VirtualMachine·ClusterComputeResource·Datastore)"},
        {"f": "metric_max_objects", "t": "number", "label": "종류당 최대 개체 수(기본 10000)"}]},
    "vcflogs": {"label": "VCF Operations for logs", "fields": _COMMON + [
        {"f": "provider", "t": "select", "label": "인증 제공자", "options": ["Local", "ActiveDirectory", "vIDM"]},
        {"f": "constraint", "t": "text", "label": "서버측 필터(예: text/CONTAINS error)"}]},
    "vcfa": {"label": "VCF Automation", "fields": [f for f in _COMMON if f["f"] != "password"] + [
        {"f": "password", "t": "password", "label": "비밀번호(provider/aria8)"},
        {"f": "mode", "t": "select", "label": "모드", "options": ["provider", "vmapps", "aria8"], "req": True},
        {"f": "api_version", "t": "text", "label": "API 버전(9.0.0/9.1.0)"},
        {"f": "org", "t": "text", "label": "조직(vmapps)"},
        {"f": "api_token", "t": "password", "label": "API(Refresh) 토큰(vmapps)"}]},
    "srm": {"label": "Site Recovery Manager", "fields": _COMMON + [
        {"f": "remote_username", "t": "text", "label": "원격 vCenter 계정"},
        {"f": "remote_password", "t": "password", "label": "원격 vCenter 비밀번호"},
        {"f": "api_prefix", "t": "text", "label": "API 경로(/api/rest/srm/v2)"}]},
    "avi": {"label": "NSX ALB (Avi Load Balancer)", "fields": _COMMON + [
        {"f": "events", "t": "bool", "label": "이벤트 로그 수집(/api/analytics/logs type=2)", "default": True},
        {"f": "api_version", "t": "text", "label": "X-Avi-Version(비우면 자동)"},
        {"f": "tenant", "t": "text", "label": "테넌트"}]},
    "ucsm": {"label": "Cisco UCS Manager (B-Series 블레이드·패브릭 인터커넥트, XML API)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "host", "t": "text", "label": "UCS Manager 주소(FI 클러스터 VIP)", "req": True},
        {"f": "username", "t": "text", "label": "계정(read-only 역할)", "req": True, "hint": "UCSM › Admin › User Management › 로컬 사용자에 read-only 역할만"},
        {"f": "password", "t": "password", "label": "비밀번호", "req": True},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)", "default": 60},
        {"f": "inventory_interval", "t": "number", "label": "서비스 프로필·vNIC 갱신(초)", "default": 600},
        {"f": "skip_acked", "t": "bool", "label": "확인(ack)한 장애 제외"},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "arista": {"label": "Arista EOS 스위치 (eAPI — 상태·LLDP·MLAG·BGP, 로그는 syslog)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "host", "t": "text", "label": "관리 주소(FQDN/IP[:포트])", "req": True,
         "hint": "eAPI: management api http-commands › no shutdown (관리 VRF 면 vrf MGMT › no shutdown) — eAPI 를 못 켜면 SSH(22)로 자동 수집"},
        {"f": "transport", "t": "select", "label": "수집 방식", "options": ["auto", "eapi", "ssh"]},
        {"f": "username", "t": "text", "label": "계정(role network-operator)", "req": True},
        {"f": "password", "t": "password", "label": "비밀번호", "req": True},
        {"f": "role", "t": "select", "label": "구성도 계층", "options": ["", "spine", "leaf", "core", "border", "access"]},
        {"f": "site", "t": "text", "label": "사이트·랙(선택)"},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)", "default": 60},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "legacy_tls", "t": "bool", "label": "구형 TLS 호환(TLS 1.0/1.1 장비 — 비우면 자동 판별)"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "cisco": {"label": "Cisco 스위치·라우터 (NX-OS NX-API · IOS-XE RESTCONF · SNMP 자동 판별)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "host", "t": "text", "label": "관리 주소(FQDN/IP[:포트])", "req": True,
         "hint": "NX-OS: feature nxapi · IOS-XE: restconf + ip http secure-server · 구형 IOS: SNMP 커뮤니티만 입력"},
        {"f": "platform", "t": "select", "label": "플랫폼", "options": ["auto", "nxos", "iosxe", "snmp"]},
        {"f": "username", "t": "text", "label": "계정(NX-OS network-operator / IOS-XE 읽기)"},
        {"f": "password", "t": "password", "label": "비밀번호"},
        {"f": "community", "t": "password", "label": "SNMP v2c 커뮤니티(읽기 전용, SNMP 사용 시)"},
        {"f": "snmp_user", "t": "text", "label": "SNMPv3 사용자(선택)"},
        {"f": "auth_key", "t": "password", "label": "SNMPv3 인증 키(SHA)"},
        {"f": "priv_key", "t": "password", "label": "SNMPv3 암호 키(AES)"},
        {"f": "role", "t": "select", "label": "구성도 계층", "options": ["", "spine", "leaf", "core", "border", "access"]},
        {"f": "site", "t": "text", "label": "사이트·랙(선택)"},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)", "default": 60},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "legacy_tls", "t": "bool", "label": "구형 TLS 호환(TLS 1.0/1.1 장비 — 비우면 자동 판별)"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "snmp-switch": {"label": "기타 스위치·라우터 (SNMP v2c/v3 — IF-MIB·LLDP-MIB·CDP-MIB)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "host", "t": "text", "label": "장비 주소", "req": True},
        {"f": "community", "t": "password", "label": "v2c 커뮤니티(읽기 전용)"},
        {"f": "snmp_user", "t": "text", "label": "SNMPv3 사용자"},
        {"f": "auth_key", "t": "password", "label": "SNMPv3 인증 키(SHA)"},
        {"f": "priv_key", "t": "password", "label": "SNMPv3 암호 키(AES)"},
        {"f": "vendor", "t": "text", "label": "벤더 표시(선택 — sysDescr 로 자동)"},
        {"f": "role", "t": "select", "label": "구성도 계층", "options": ["", "spine", "leaf", "core", "border", "access"]},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)", "default": 120},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "fortigate": {"label": "FortiGate (FortiOS REST — 상태·자원, 로그는 syslog)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "host", "t": "text", "label": "관리 주소(FQDN/IP[:포트])", "req": True},
        {"f": "api_token", "t": "password", "label": "REST API 토큰(읽기 전용 프로필)", "req": True,
         "hint": "System > Administrators > REST API Admin · 관리자 프로필 전 항목 Read · Trusted Hosts 에 AIops 주소"},
        {"f": "vdom", "t": "text", "label": "VDOM(비우면 기본)"},
        {"f": "cpu_warn", "t": "number", "label": "CPU 경고 임계(%)", "default": 90},
        {"f": "mem_warn", "t": "number", "label": "메모리 경고 임계(%)", "default": 90},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)", "default": 60},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "vks": {"label": "VKS — Supervisor / 워크로드 클러스터(Kubernetes API)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "role", "t": "select", "label": "역할", "options": ["supervisor", "workload"], "req": True},
        {"f": "host", "t": "text", "label": "API 주소(IP/FQDN[:포트], 기본 6443)", "req": True},
        {"f": "cluster_name", "t": "text", "label": "클러스터 표시 이름"},
        {"f": "auth", "t": "select", "label": "인증", "options": ["token", "vsphere"], "req": True},
        {"f": "token", "t": "password", "label": "ServiceAccount 토큰(auth=token)"},
        {"f": "username", "t": "text", "label": "vSphere SSO 계정(auth=vsphere)"},
        {"f": "password", "t": "password", "label": "vSphere SSO 비밀번호(auth=vsphere)"},
        {"f": "supervisor", "t": "text", "label": "Supervisor 주소(/wcp/login, 워크로드+vsphere 인증 시)"},
        {"f": "guest_cluster_name", "t": "text", "label": "워크로드 클러스터 이름(vsphere 인증)"},
        {"f": "guest_cluster_namespace", "t": "text", "label": "vSphere 네임스페이스(vsphere 인증)"},
        {"f": "namespaces", "t": "list", "label": "네임스페이스 범위(클러스터 범위 권한이 없을 때)"},
        {"f": "include_normal_events", "t": "bool", "label": "Normal 이벤트도 수집(기본: Warning 만)"},
        {"f": "problem_logs", "t": "bool", "label": "문제 파드의 마지막 로그 30줄 자동 첨부", "default": True},
        {"f": "log_namespaces", "t": "list", "label": "파드 로그 실시간 수집 네임스페이스(* = 전체)"},
        {"f": "interval", "t": "number", "label": "watch 주기(초)"},
        {"f": "status_interval", "t": "number", "label": "노드·파드·CAPI 점검 주기(초)"},
        {"f": "topology", "t": "bool", "label": "구성도 수집(2.9 — Deployment·Service·Ingress·PVC·PV·StorageClass·HPA 목록, Secret 은 읽지 않음)", "default": True},
        {"f": "topology_interval", "t": "number", "label": "구성도 수집 주기(초, 기본 300)"},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "ca_file", "t": "text", "label": "CA 인증서 파일(PEM)"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
    "redfish": {"label": "서버 BMC (iLO·iDRAC·XCC / Redfish)", "fields": [
        {"f": "name", "t": "text", "label": "이름", "req": True},
        {"f": "hosts", "t": "list", "label": "BMC 주소 목록", "req": True},
        {"f": "username", "t": "text", "label": "계정", "req": True},
        {"f": "password", "t": "password", "label": "비밀번호", "req": True},
        {"f": "log_services", "t": "list", "label": "로그 서비스(비우면 전체: IML·IEL·Sel·Lclog)"},
        {"f": "interval", "t": "number", "label": "폴링 주기(초)"},
        {"f": "verify_tls", "t": "bool", "label": "TLS 인증서 검증"},
        {"f": "enabled", "t": "bool", "label": "사용", "default": True}]},
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_overlay(db_path: str) -> dict[str, Any]:
    """기동 시 동기 로드(엔진 생성 전)."""
    if not Path(db_path).exists():
        return {}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    finally:
        conn.close()
    out = {}
    for k, v in rows:
        if k in MANAGED_KEYS:
            try:
                out[k] = decrypt_tree(json.loads(v))
            except Exception as e:  # noqa: BLE001
                print(f"[settings] '{k}' 복호화 실패 — config.yaml 값을 사용합니다: {e}", flush=True)
    return out


def apply_overlay(cfg: dict, overlay: dict) -> dict:
    cfg = copy.deepcopy(cfg)
    for k, v in overlay.items():
        if k == "connectors":
            cfg["connectors"] = v
        elif isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k] = _merge(cfg[k], v)
        else:
            cfg[k] = v
    return cfg


def _keep_secrets(new: Any, old: Any) -> Any:
    """화면에서 '********' 그대로 저장되면 기존 비밀값 유지"""
    if isinstance(new, dict):
        o = old if isinstance(old, dict) else {}
        return {k: (o.get(k) if v == MASK and k in SECRET_FIELDS else _keep_secrets(v, o.get(k))) for k, v in new.items()}
    if isinstance(new, list):
        ol = old if isinstance(old, list) else []
        if all(isinstance(x, dict) and "name" in x for x in new):
            by = {x.get("name"): x for x in ol if isinstance(x, dict)}
            return [_keep_secrets(x, by.get(x.get("name"))) for x in new]
        return new
    return new


class SettingsManager:
    def __init__(self, store, cfg_ref: dict, base_cfg: dict):
        self.store = store
        self.cfg = cfg_ref              # 엔진이 쓰는 실효 설정(dict, 제자리 갱신)
        self.base = base_cfg            # config.yaml 원본(초기화 시 복귀값)
        store.schema(SCHEMA)

    async def get(self, key: str) -> dict:
        row = await self.store.q1("SELECT value, updated, updated_by FROM settings WHERE key=?", (key,))
        managed = row is not None
        val = decrypt_tree(json.loads(row["value"])) if row else self.cfg.get(key)
        return {"key": key, "value": mask_tree(val), "managed": managed,
                "updated": row["updated"] if row else None, "updated_by": row["updated_by"] if row else None}

    async def put(self, key: str, value: Any, user: str) -> Any:
        if key not in MANAGED_KEYS:
            raise KeyError(key)
        old = self.cfg.get(key)
        merged = _keep_secrets(value, old)
        await self.store.x("INSERT INTO settings(key,value,updated,updated_by) VALUES(?,?,?,?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
                           (key, json.dumps(encrypt_tree(merged), ensure_ascii=False), time.time(), user))
        self.cfg[key] = merged
        return merged

    async def reset(self, key: str) -> Any:
        await self.store.x("DELETE FROM settings WHERE key=?", (key,))
        self.cfg[key] = copy.deepcopy(self.base.get(key))
        return self.cfg[key]
