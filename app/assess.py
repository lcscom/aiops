"""보안 판독 — ESXi·vCenter 하드닝 점검, KISA 가상화 점검 항목(HV-01~25) 대응표, VMSA/CVE 버전 판독.

설계(독자 구현 — 공개 저장소 postout7979/infra_assessment 의 점검 흐름을 참고, 스크립트·데이터는 가져오지 않음)
  · 수집: vCenter 커넥터의 읽기 전용 속성·QueryOptions(System.Read) — 호스트 고급 설정, 서비스, 방화벽 기본 정책, 잠금 모드, NTP,
          표준 vSwitch·분산 포트그룹 보안 정책, VM 고급 설정(표본), 스냅샷, vCenter·ESXi 버전/빌드. 설정 변경(조치)은 하지 않는다.
  · 하드닝 점검: 각 항목은 기대값·현재값·판정(PASS·FAIL·WARN·MANUAL·N/A)·조치 방법. 기준은 vSphere 보안 구성 가이드의 일반 원칙과
          KISA 주요정보통신기반시설 가상화(HV) 점검 항목 분류를 따른다(문구는 이 프로젝트가 작성).
          호스트 로컬 계정·백업 정책처럼 vCenter 경유 읽기 전용으로 확인할 수 없는 항목은 MANUAL(현장 확인)로 남긴다.
  · VMSA/CVE: 취약점 목록은 NVD CVE API 2.0(https://services.nvd.nist.gov/rest/json/cves/2.0, virtualMatchString=제품 CPE)으로
          동기화하거나(프록시·API 키 선택), 폐쇄망에서는 NVD 응답 JSON 이나 이 프로젝트 형식의 권고 JSON 을 가져온다.
          판정: 권고에 고정 빌드(fixed_build)가 있으면 실행 빌드와 비교해 '취약/조치됨', CPE 버전·업데이트만 있으면 '가능(빌드 확인)'.
"""
from __future__ import annotations

import asyncio
import csv
import html
import io
import json
import re
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS assess_adv(id TEXT PRIMARY KEY, title TEXT, severity TEXT, cvss REAL, published TEXT, url TEXT, cves TEXT, matches TEXT,
  source TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS assess_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, summary TEXT, data TEXT);
"""
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PRODUCTS = {"esxi": "cpe:2.3:o:vmware:esxi", "vcenter": "cpe:2.3:a:vmware:vcenter_server"}
KISA = {"HV-01": ("기본 관리자 계정 변경", "상"), "HV-02": ("비밀번호 복잡성 설정", "상"), "HV-03": ("계정 잠금 임계값 설정", "상"),
        "HV-04": ("불필요한 계정 제거", "상"), "HV-05": ("관리자 권한 최소화", "상"), "HV-06": ("세션 타임아웃 설정", "중"),
        "HV-07": ("로그인 경고 메시지 설정", "하"), "HV-08": ("불필요한 서비스 비활성화", "상"), "HV-09": ("SSH 보안 설정", "상"),
        "HV-10": ("SNMP 보안 설정", "상"), "HV-11": ("NTP 시각 동기화", "중"), "HV-12": ("호스트 방화벽 설정", "상"),
        "HV-13": ("보안 패치 적용", "상"), "HV-14": ("로그 설정 및 관리", "중"), "HV-15": ("백업 정책 수립", "중"),
        "HV-16": ("SSL/TLS 관리 콘솔 암호화", "상"), "HV-17": ("VM 간 격리 설정", "상"), "HV-18": ("VM 리소스 제한 설정", "중"),
        "HV-19": ("VM 스냅샷 관리", "중"), "HV-20": ("VM 이동/복제 시 보안", "상"), "HV-21": ("불필요한 VM 제거", "중"),
        "HV-22": ("가상 스위치 보안 설정", "상"), "HV-23": ("VLAN 분리 설정", "상"), "HV-24": ("가상 네트워크 모니터링", "중"),
        "HV-25": ("무차별 모드(Promiscuous Mode) 제한", "상")}
STATUS_ORDER = {"FAIL": 0, "WARN": 1, "MANUAL": 2, "PASS": 3, "N/A": 4}
SEV_KO = {"CRITICAL": "긴급", "HIGH": "높음", "MEDIUM": "보통", "LOW": "낮음", "": "-"}


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _vt(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or (0,)


def branch_of(version: str) -> tuple[str, int]:
    """'8.0.3' → ('8.0', 3) · '7.0.3' → ('7.0', 3) · '9.0.0.0' → ('9.0', 0)"""
    t = _vt(version)
    return f"{t[0]}.{t[1] if len(t) > 1 else 0}", (t[2] if len(t) > 2 else 0)


def _upd(u: str) -> tuple[int, str] | None:
    """CPE 업데이트 필드 → (업데이트 번호, 접미 문자) — '-'·'*' 은 GA(0)"""
    u = str(u or "").lower()
    if u in ("-", "", "ga"):
        return (0, "")
    m = re.match(r"update_?(\d+)([a-z]*)", u)
    return (int(m.group(1)), m.group(2)) if m else None


# ---------------------------------------------------------------- 하드닝 점검 정의
def _rng(lo: float | None, hi: float | None):
    def f(v):
        n = _num(v)
        if n is None:
            return None
        return (lo is None or n >= lo) and (hi is None or n <= hi)
    return f


def _eq(x):
    return lambda v: None if v is None else str(v).strip().lower() == str(x).lower()


def _empty(v):
    return None if v is None else str(v).strip() in ("", "None")


def _nonempty(v):
    return None if v is None else str(v).strip() not in ("", "None")


def _pwqc(v):
    if v is None:
        return None
    m = re.search(r"min=([\w,]+)", str(v))
    if not m:
        return False
    nums = [int(x) for x in m.group(1).split(",") if x.isdigit()]
    return bool(nums) and min(nums) >= 7


def _tls(v):
    if v is None:
        return None
    s = str(v).lower().replace(" ", "")
    return all(p in s.split(",") for p in ("sslv3", "tlsv1", "tlsv1.1"))


# (id, KISA, 제목, 분류, 심각도, 고급 설정 키, 판정 함수, 기대값 설명, 조치, 키 없으면 N/A)
HOST_ADV = [
    ("ESXI-01", "HV-06", "ESXi Shell 유휴 세션 타임아웃", "계정·세션", "중", "UserVars.ESXiShellInteractiveTimeOut", _rng(1, 900), "1~900초",
     "고급 설정 UserVars.ESXiShellInteractiveTimeOut = 900 이하", False),
    ("ESXI-02", "HV-06", "ESXi Shell·SSH 사용 가능 시간 제한", "계정·세션", "중", "UserVars.ESXiShellTimeOut", _rng(1, 900), "1~900초",
     "UserVars.ESXiShellTimeOut = 900 이하(켜 둔 Shell·SSH 가 자동으로 꺼짐)", False),
    ("ESXI-03", "HV-06", "DCUI 유휴 타임아웃", "계정·세션", "중", "UserVars.DcuiTimeOut", _rng(1, 600), "1~600초", "UserVars.DcuiTimeOut = 600 이하", False),
    ("ESXI-04", "HV-06", "Host Client 세션 타임아웃", "계정·세션", "중", "UserVars.HostClientSessionTimeout", _rng(1, 900), "1~900초",
     "UserVars.HostClientSessionTimeout = 900 이하", True),
    ("ESXI-05", "HV-03", "로그인 실패 잠금 횟수", "계정·세션", "상", "Security.AccountLockFailures", _rng(1, 5), "1~5회",
     "Security.AccountLockFailures = 5 이하(0 은 잠금 없음)", False),
    ("ESXI-06", "HV-03", "계정 잠금 해제 대기 시간", "계정·세션", "상", "Security.AccountUnlockTime", _rng(900, None), "900초 이상",
     "Security.AccountUnlockTime = 900 이상", False),
    ("ESXI-07", "HV-02", "비밀번호 복잡성(최소 길이)", "계정·세션", "상", "Security.PasswordQualityControl", _pwqc, "min= 의 숫자 값이 모두 7 이상",
     "Security.PasswordQualityControl 예: retry=3 min=disabled,disabled,disabled,7,7 (조직 기준 길이 이상)", False),
    ("ESXI-08", "HV-02", "비밀번호 재사용 제한", "계정·세션", "중", "Security.PasswordHistory", _rng(5, None), "5개 이상",
     "Security.PasswordHistory = 5 이상", True),
    ("ESXI-09", "HV-02", "비밀번호 최대 사용 기간", "계정·세션", "중", "Security.PasswordMaxDays", _rng(1, 90), "1~90일",
     "Security.PasswordMaxDays = 90 이하(ESXi 8.0 이상)", True),
    ("ESXI-10", "HV-14", "원격 로그 서버 지정", "로그", "중", "Syslog.global.logHost", _nonempty, "비어 있지 않음",
     "Syslog.global.logHost = udp://… 또는 tcp://…:514 (관제·SIEM)", False),
    ("ESXI-11", "HV-14", "hostd 로그 수준", "로그", "하", "Config.HostAgent.log.level", _eq("info"), "info",
     "Config.HostAgent.log.level = info(감사 추적에 필요한 수준)", True),
    ("ESXI-12", "HV-08", "Managed Object Browser 비활성", "서비스", "상", "Config.HostAgent.plugins.solo.enableMob", _eq("false"), "false",
     "Config.HostAgent.plugins.solo.enableMob = false", True),
    ("ESXI-13", "HV-22", "게스트 BPDU 차단", "네트워크", "중", "Net.BlockGuestBPDU", _eq("1"), "1", "Net.BlockGuestBPDU = 1", True),
    ("ESXI-14", "HV-22", "dvFilter 네트워크 API 비사용", "네트워크", "중", "Net.DVFilterBindIpAddress", _empty, "비어 있음",
     "Net.DVFilterBindIpAddress 를 비움(보안 어플라이언스가 쓰지 않는 경우)", True),
    ("ESXI-15", "HV-17", "TPS 메모리 공유 VM 간 격리(salting)", "VM 격리", "중", "Mem.ShareForceSalting", _eq("2"), "2",
     "Mem.ShareForceSalting = 2(같은 VM 안에서만 페이지 공유)", True),
    ("ESXI-16", "HV-08", "Shell 활성 경고 숨김 금지", "서비스", "하", "UserVars.SuppressShellWarning", _eq("0"), "0", "UserVars.SuppressShellWarning = 0", True),
    ("ESXI-17", "HV-17", "하이퍼스레딩 보안 경고 숨김 금지", "VM 격리", "하", "UserVars.SuppressHyperthreadWarning", _eq("0"), "0",
     "UserVars.SuppressHyperthreadWarning = 0(L1TF 등 사이드채널 경고 확인)", True),
    ("ESXI-18", "HV-13", "설치된 VIB 바이너리만 실행", "패치·무결성", "중", "VMkernel.Boot.execInstalledOnly", _eq("true"), "true",
     "VMkernel.Boot.execInstalledOnly = true(재부팅 필요)", True),
    ("ESXI-19", "HV-16", "구 TLS·SSL 프로토콜 비활성", "암호화", "상", "UserVars.ESXiVPsDisabledProtocols", _tls, "sslv3,tlsv1,tlsv1.1 포함",
     "ESXi 7.0: UserVars.ESXiVPsDisabledProtocols = sslv3,tlsv1,tlsv1.1 · ESXi 8.0 이상은 TLS 프로파일(esxcli system tls server)로 관리", True),
]
SERVICES = [  # (id, KISA, 제목, 서비스 키, 심각도, 조치)
    ("ESXI-20", "HV-09", "SSH 서비스 중지·수동 시작", "TSM-SSH", "상", "호스트 › 구성 › 서비스 › SSH 중지, 시작 정책 '수동 시작'(필요 시만 켬)"),
    ("ESXI-21", "HV-08", "ESXi Shell 서비스 중지·수동 시작", "TSM", "상", "호스트 › 구성 › 서비스 › ESXi Shell 중지, 시작 정책 '수동 시작'"),
    ("ESXI-22", "HV-08", "SLP(slpd) 서비스 중지", "slpd", "상", "slpd 중지·시작 정책 off, 방화벽 CIMSLP 규칙 비활성(공개 OpenSLP 취약점 대응)"),
    ("ESXI-23", "HV-08", "CIM(sfcbd) 서비스 필요 시만 사용", "sfcbd-watchdog", "하", "하드웨어 감시를 CIM 으로 하지 않으면 sfcbd-watchdog 중지"),
]


def _row(cid, kisa, title, cat, sev, target, status, current, expected, fix) -> dict:
    return {"id": cid, "kisa": kisa, "kisa_title": KISA.get(kisa, ("", ""))[0], "title": title, "category": cat, "severity": sev, "target": target,
            "status": status, "current": "" if current is None else str(current)[:300], "expected": expected, "fix": fix}


def hardening(inv: dict, adv_hits: dict[str, list[dict]] | None = None, have_db: bool = False, snap_days: int = 3) -> list[dict]:
    """수집 결과 → 점검 행(호스트별·VM 묶음·vCenter)"""
    out: list[dict] = []
    for h in inv.get("hosts", []):
        name = h["name"]
        if h.get("conn") != "connected":
            out.append(_row("ESXI-00", "HV-13", "호스트 연결 상태", "수집", "중", name, "MANUAL", h.get("conn"), "connected", "연결 끊긴 호스트는 점검하지 못함"))
            continue
        adv = h.get("adv") or {}
        for cid, kisa, title, cat, sev, key, fn, exp, fix, na_ok in HOST_ADV:
            if key not in adv:
                out.append(_row(cid, kisa, title, cat, sev, name, "N/A" if na_ok else "MANUAL", "(설정 키 없음)", exp,
                                f"{fix} — 이 버전에 키가 없거나 조회 권한 부족" if not na_ok else fix))
                continue
            ok = fn(adv[key])
            out.append(_row(cid, kisa, title, cat, sev, name, "PASS" if ok else "FAIL", f"{key}={adv[key]}", exp, fix))
        if not (adv.get("Annotations.WelcomeMessage") or adv.get("Config.Etc.issue")):
            out.append(_row("ESXI-24", "HV-07", "로그인 경고 문구(배너)", "계정·세션", "하", name,
                            "FAIL" if ("Annotations.WelcomeMessage" in adv or "Config.Etc.issue" in adv) else "MANUAL",
                            "(비어 있음)", "경고 문구 지정", "Annotations.WelcomeMessage·Config.Etc.issue 에 무단 접근 경고 문구"))
        else:
            out.append(_row("ESXI-24", "HV-07", "로그인 경고 문구(배너)", "계정·세션", "하", name, "PASS", "지정됨", "경고 문구 지정", ""))
        sv = h.get("services") or {}
        for cid, kisa, title, key, sev, fix in SERVICES:
            s = sv.get(key)
            if s is None:
                out.append(_row(cid, kisa, title, "서비스", sev, name, "N/A" if sv else "MANUAL", "(서비스 없음)" if sv else "(서비스 목록 미수집)", "중지·off", fix))
                continue
            bad = s["running"] or s["policy"] == "on"
            out.append(_row(cid, kisa, title, "서비스", sev, name, ("WARN" if key == "sfcbd-watchdog" else "FAIL") if bad else "PASS",
                            f"실행 {'예' if s['running'] else '아니오'} · 정책 {s['policy']}", "중지 · off/수동", fix))
        snmp = sv.get("snmpd")
        out.append(_row("ESXI-25", "HV-10", "SNMP 사용 시 v3·제한", "서비스", "상", name,
                        "PASS" if snmp is not None and not snmp["running"] else "MANUAL" if snmp is not None else "N/A",
                        f"snmpd 실행 {'예' if snmp and snmp['running'] else '아니오'}" if snmp is not None else "(미수집)", "미사용 또는 SNMPv3·접근 제한",
                        "SNMP 를 쓰면 esxcli system snmp 로 v3(인증·암호화)와 대상 제한 — 커뮤니티 문자열(v1/v2c)은 쓰지 않음"))
        ntp_run = any((sv.get(k) or {}).get("running") for k in ("ntpd", "ptpd"))
        out.append(_row("ESXI-26", "HV-11", "NTP 시각 동기화", "시간", "중", name, "PASS" if h.get("ntp") and ntp_run else "FAIL" if sv else "MANUAL",
                        f"서버 {', '.join(h.get('ntp') or []) or '없음'} · ntpd {'실행' if ntp_run else '중지'}", "NTP 서버 2개 이상 · ntpd 실행",
                        "호스트 › 구성 › 시간 구성 › NTP 서버 지정·서비스 시작(정책: 호스트와 함께 시작)"))
        fw = h.get("firewall") or {}
        if fw:
            out.append(_row("ESXI-27", "HV-12", "방화벽 기본 수신 차단", "방화벽", "상", name, "PASS" if fw.get("incoming_blocked") else "FAIL",
                            f"incomingBlocked={fw.get('incoming_blocked')}", "True", "esxcli network firewall set --default-action false(기본 차단)"))
            wide = [x for x in fw.get("open_all") or [] if x in ("sshServer", "webAccess", "vSphereClient", "snmp", "CIMHttpServer", "CIMHttpsServer", "CIMSLP", "httpClient")]
            out.append(_row("ESXI-28", "HV-12", "관리 서비스 접근 IP 제한", "방화벽", "중", name, "WARN" if wide else "PASS",
                            ", ".join(wide) or "제한됨", "관리 규칙은 허용 IP 지정", "호스트 › 방화벽 › 규칙 편집 › '모든 IP 주소에서 연결 허용' 해제 후 관리망 대역 지정"))
        else:
            out.append(_row("ESXI-27", "HV-12", "방화벽 기본 수신 차단", "방화벽", "상", name, "MANUAL", "(미수집)", "True", ""))
        lk = h.get("lockdown") or ""
        out.append(_row("ESXI-29", "HV-05", "잠금 모드(Lockdown)", "계정·세션", "상", name, "PASS" if lk and lk != "lockdownDisabled" else "FAIL" if lk else "MANUAL",
                        lk or "(미수집)", "normal 또는 strict", "호스트 › 구성 › 보안 프로필 › 잠금 모드 '일반'(예외 사용자는 최소)"))
        bad_sw = [f"{x['name']}({'P' if x['promiscuous'] else ''}{'M' if x['mac_changes'] else ''}{'F' if x['forged'] else ''})"
                  for x in h.get("vswitch") or [] if x["promiscuous"] or x["mac_changes"] or x["forged"]]
        out.append(_row("ESXI-30", "HV-25", "표준 vSwitch 무차별 모드·MAC 변경·위조 전송 거부", "네트워크", "상", name, "FAIL" if bad_sw else "PASS",
                        ", ".join(bad_sw) or f"vSwitch {len(h.get('vswitch') or [])}개 모두 거부", "모두 거부(Reject)",
                        "vSwitch·포트그룹 › 보안 › 무차별 모드·MAC 주소 변경·위조 전송 = 거부(P=무차별, M=MAC 변경, F=위조 전송)"))
        hits = (adv_hits or {}).get(f"esxi:{name}") or []
        vul = [x for x in hits if x["verdict"] == "취약"]
        pos = [x for x in hits if x["verdict"] == "가능"]
        out.append(_row("ESXI-31", "HV-13", "보안 패치(VMSA) 적용", "패치·무결성", "상", name,
                        "FAIL" if vul else "WARN" if pos else "PASS" if have_db else "MANUAL",
                        f"{h.get('version')} 빌드 {h.get('build')} · 취약 {len(vul)} · 가능 {len(pos)}" if have_db else f"{h.get('version')} 빌드 {h.get('build')} (취약점 목록 없음)",
                        "알려진 VMSA 고정 빌드 이상", "보안 판독 › VMSA/CVE 에서 해당 권고의 고정 빌드로 업데이트(vLCM)"))
    # 분산 포트그룹
    bad_pg = [f"{x['name']}({'P' if x['promiscuous'] else ''}{'M' if x['mac_changes'] else ''}{'F' if x['forged'] else ''})"
              for x in inv.get("dvpg", []) if x["promiscuous"] or x["mac_changes"] or x["forged"]]
    if inv.get("dvpg"):
        out.append(_row("NET-01", "HV-22", "분산 포트그룹 보안 정책", "네트워크", "상", "분산 포트그룹 전체", "FAIL" if bad_pg else "PASS",
                        ", ".join(bad_pg[:30]) + (f" 외 {len(bad_pg) - 30}" if len(bad_pg) > 30 else "") or f"{len(inv['dvpg'])}개 모두 거부",
                        "무차별 모드·MAC 변경·위조 전송 거부", "분산 포트그룹 › 설정 편집 › 보안 = 거부(중첩 ESXi·보안 장비 포트그룹만 예외로 문서화)"))
    # VM 표본
    vms = inv.get("vms", [])
    if vms:
        def vm_check(cid, kisa, title, sev, bad_fn, exp, fix, cat="VM 격리"):
            bad = [v["name"] for v in vms if bad_fn(v)]
            out.append(_row(cid, kisa, title, cat, sev, f"VM {len(vms)}대(표본)", "FAIL" if bad else "PASS",
                            (", ".join(bad[:20]) + (f" 외 {len(bad) - 20}" if len(bad) > 20 else "")) if bad else "해당 없음", exp, fix))
        adv = lambda v, k: str((v.get("adv") or {}).get(k, "")).strip().lower()   # noqa: E731
        vm_check("VM-01", "HV-17", "VM 콘솔 복사·붙여넣기 차단", "중", lambda v: adv(v, "isolation.tools.copy.disable") == "false" or adv(v, "isolation.tools.paste.disable") == "false",
                 "미설정(기본 차단) 또는 TRUE", "VM 고급 설정 isolation.tools.copy.disable·paste.disable = TRUE")
        vm_check("VM-02", "HV-17", "게스트에서 장치 연결·해제 차단", "중", lambda v: adv(v, "isolation.device.connectable.disable") == "false",
                 "미설정 또는 TRUE", "isolation.device.connectable.disable = TRUE")
        vm_check("VM-03", "HV-17", "원격 콘솔 동시 연결 1개", "하", lambda v: (_num(adv(v, "RemoteDisplay.maxConnections")) or 1) > 1,
                 "1 이하", "RemoteDisplay.maxConnections = 1")
        vm_check("VM-04", "HV-18", "VMX 정보 전달 크기 제한", "하", lambda v: (_num(adv(v, "tools.setInfo.sizeLimit")) or 0) > 1048576,
                 "1048576 이하", "tools.setInfo.sizeLimit = 1048576", cat="VM 자원")
        now = time.time()
        vm_check("VM-05", "HV-19", f"오래된 스냅샷({snap_days}일 초과)", "중", lambda v: bool(v.get("oldest_snapshot")) and now - v["oldest_snapshot"] > snap_days * 86400,
                 f"{snap_days}일 이내 정리", "스냅샷은 백업이 아님 — 작업 후 삭제(통합), 장기 보관은 백업으로", cat="VM 관리")
        off = [v["name"] for v in vms if v.get("power") != "poweredOn"]
        out.append(_row("VM-06", "HV-21", "꺼진 VM 정리 검토", "VM 관리", "중", f"VM {len(vms)}대(표본)", "WARN" if off else "PASS",
                        f"꺼진 VM {len(off)}대: " + ", ".join(off[:15]) if off else "없음", "용도 확인 후 정리", "장기간 꺼진 VM 은 소유자 확인 후 삭제·보관(템플릿·백업)"))
        notools = [v["name"] for v in vms if v.get("power") == "poweredOn" and v.get("tools") not in ("guestToolsRunning",)]
        out.append(_row("VM-07", "HV-24", "VMware Tools 실행(가시성)", "VM 관리", "하", f"VM {len(vms)}대(표본)", "WARN" if notools else "PASS",
                        ", ".join(notools[:15]) or "모두 실행", "켜진 VM 은 Tools 실행", "게스트에 VMware Tools(open-vm-tools) 설치·실행"))
    # vCenter
    vc = inv.get("vcenter") or {}
    hits = (adv_hits or {}).get(f"vcenter:{vc.get('host', '')}") or []
    vul = [x for x in hits if x["verdict"] == "취약"]
    pos = [x for x in hits if x["verdict"] == "가능"]
    out.append(_row("VC-01", "HV-13", "vCenter 보안 패치(VMSA)", "패치·무결성", "상", vc.get("host", "vCenter"),
                    "FAIL" if vul else "WARN" if pos else "PASS" if have_db else "MANUAL",
                    f"{vc.get('version', '')} 빌드 {vc.get('build', '')} · 취약 {len(vul)} · 가능 {len(pos)}", "알려진 VMSA 고정 빌드 이상",
                    "VAMI 또는 vCenter 수명 주기 관리자에서 권고 고정 버전으로 업데이트"))
    # vCenter 경유로 확인할 수 없는 KISA 항목(현장 확인)
    for k, why in (("HV-01", "호스트 로컬 root 계정명·비밀번호 변경 여부는 vCenter 읽기 API 로 확인 불가 — 호스트 직접 확인"),
                   ("HV-04", "호스트 로컬 계정 목록은 호스트 직접 접속(esxcli system account list) 필요"),
                   ("HV-15", "백업 정책(vCenter 파일 백업·VM 백업 솔루션)은 운영 문서·VAMI 백업 일정으로 확인"),
                   ("HV-20", "vMotion 암호화·전용망 분리, 복제(클론) 시 민감 정보 정리 — 정책·네트워크 설계 확인"),
                   ("HV-23", "업무·관리·vMotion·스토리지 VLAN 분리 — 포트그룹 VLAN 설계 확인"),
                   ("HV-18", "VM 리소스 제한·예약·공유는 업무 요구에 따름 — 과도한 제한·예약 여부 검토")):
        out.append(_row(f"KISA-{k}", k, KISA[k][0], "수동 확인", KISA[k][1], "현장 확인", "MANUAL", "", "운영 기준 충족", why))
    return out


def kisa_summary(rows: list[dict]) -> list[dict]:
    out = []
    for code, (title, imp) in KISA.items():
        rs = [r for r in rows if r["kisa"] == code]
        if not rs:
            out.append({"code": code, "title": title, "importance": imp, "status": "MANUAL", "checks": 0, "fail": 0, "targets": 0, "note": "자동 점검 항목 없음"})
            continue
        worst = min(rs, key=lambda r: STATUS_ORDER.get(r["status"], 9))["status"]
        if worst == "N/A" and any(r["status"] == "PASS" for r in rs):
            worst = "PASS"
        out.append({"code": code, "title": title, "importance": imp, "status": worst, "checks": len({r["id"] for r in rs}),
                    "fail": sum(1 for r in rs if r["status"] == "FAIL"), "targets": len({r["target"] for r in rs}),
                    "note": "; ".join(sorted({r["title"] for r in rs if r["status"] in ("FAIL", "WARN")}))[:200]})
    return out


# ---------------------------------------------------------------- VMSA/CVE
def parse_nvd(data: dict) -> list[dict]:
    """NVD CVE API 2.0 응답 → 권고 행(CVE 단위). 같은 VMSA 를 참조하는 CVE 는 references 의 'VMSA-YYYY-NNNN' 으로 묶음"""
    out = []
    for item in data.get("vulnerabilities") or []:
        c = item.get("cve") or {}
        cid = c.get("id")
        if not cid:
            continue
        desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
        sev, score = "", None
        mets = c.get("metrics") or {}
        for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if mets.get(k):
                m = mets[k][0]
                cd = m.get("cvssData") or {}
                score = cd.get("baseScore")
                sev = (cd.get("baseSeverity") or m.get("baseSeverity") or "").upper()
                break
        refs = [r.get("url", "") for r in c.get("references") or []]
        vmsa = sorted({m.upper() for r in refs for m in re.findall(r"VMSA-\d{4}-\d{4}", r, re.I)})
        matches = []
        for cfg in c.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for cm in node.get("cpeMatch") or []:
                    if not cm.get("vulnerable"):
                        continue
                    crit = str(cm.get("criteria", ""))
                    prod = next((p for p, base in PRODUCTS.items() if crit.startswith(base + ":")), None)
                    if not prod:
                        continue
                    parts = crit.split(":")
                    matches.append({"product": prod, "version": parts[5] if len(parts) > 5 else "*", "update": parts[6] if len(parts) > 6 else "*",
                                    "start_incl": cm.get("versionStartIncluding"), "start_excl": cm.get("versionStartExcluding"),
                                    "end_incl": cm.get("versionEndIncluding"), "end_excl": cm.get("versionEndExcluding")})
        if not matches:
            continue
        out.append({"id": cid, "title": (f"{', '.join(vmsa)} " if vmsa else "") + desc[:300], "severity": sev, "cvss": score,
                    "published": str(c.get("published", ""))[:10], "url": next((r for r in refs if "VMSA" in r.upper()), f"https://nvd.nist.gov/vuln/detail/{cid}"),
                    "cves": [cid], "vmsa": vmsa, "matches": matches, "source": "nvd"})
    return out


def parse_own(data: dict) -> list[dict]:
    """이 프로젝트 형식: {"advisories":[{"id":"VMSA-…","title","severity","cvss","published","url","cves":[…],
       "fixes":[{"product":"esxi|vcenter","branch":"8.0","fixed_build":24585383,"fixed_version":"8.0 U3d"}]}]}"""
    out = []
    for a in data.get("advisories") or []:
        if not a.get("id"):
            continue
        ms = []
        for f in a.get("fixes") or []:
            if f.get("product") in PRODUCTS and f.get("branch"):
                ms.append({"product": f["product"], "branch": str(f["branch"]), "fixed_build": int(f["fixed_build"]) if str(f.get("fixed_build", "")).isdigit() else None,
                           "fixed_version": str(f.get("fixed_version") or "")})
        if not ms:
            continue
        out.append({"id": str(a["id"])[:60], "title": str(a.get("title") or "")[:300], "severity": str(a.get("severity") or "").upper()[:10],
                    "cvss": _num(a.get("cvss")), "published": str(a.get("published") or "")[:10], "url": str(a.get("url") or "")[:300],
                    "cves": [str(x)[:20] for x in a.get("cves") or []][:100], "vmsa": [str(a["id"])] if str(a["id"]).upper().startswith("VMSA") else [],
                    "matches": ms, "source": "import"})
    return out


def judge(m: dict, version: str, build: str) -> tuple[str, str] | None:
    """한 매칭 조건 × 실행 버전/빌드 → (판정, 근거) · 해당 없음 None"""
    br, upd = branch_of(version)
    if "branch" in m:                                   # 고정 빌드가 있는 권고(가져오기 형식)
        if m["branch"] != br:
            return None
        if m.get("fixed_build") and str(build).isdigit():
            return ("취약", f"빌드 {build} < 고정 {m['fixed_build']} ({m.get('fixed_version') or ''})") if int(build) < m["fixed_build"] else None
        return ("가능", f"고정 버전 {m.get('fixed_version') or '-'} — 빌드 확인 필요")
    v = m.get("version") or "*"
    if v not in ("*", "-"):
        if branch_of(v)[0] != br:
            return None
        u = _upd(m.get("update"))
        if m.get("update") in ("*", None):
            return ("가능", f"{v} 전체 업데이트 대상")
        if u is None:
            return None
        if u[0] == upd:
            return ("가능", f"{v} {m.get('update')} 대상 — 같은 업데이트의 패치 빌드 확인 필요")
        return None
    rv = _vt(version)
    for k, op in (("start_incl", lambda a, b: a >= b), ("start_excl", lambda a, b: a > b), ("end_incl", lambda a, b: a <= b), ("end_excl", lambda a, b: a < b)):
        if m.get(k) and not op(rv, _vt(m[k])):
            return None
    if any(m.get(k) for k in ("start_incl", "start_excl", "end_incl", "end_excl")):
        return ("가능", "버전 범위 " + " ".join(f"{k}={m[k]}" for k in ("start_incl", "start_excl", "end_incl", "end_excl") if m.get(k)))
    return None


def evaluate(advs: list[dict], targets: list[dict]) -> tuple[list[dict], dict[str, list[dict]]]:
    """targets: [{product, name, version, build}] → 판정 목록·대상별 적중"""
    rows, hits = [], {}
    for t in targets:
        for a in advs:
            best = None
            for m in a["matches"]:
                if m["product"] != t["product"]:
                    continue
                j = judge(m, t["version"], t["build"])
                if j and (best is None or (j[0] == "취약" and best[0] != "취약")):
                    best = j
            if best:
                r = {"target": t["name"], "product": t["product"], "version": t["version"], "build": t["build"], "id": a["id"], "vmsa": ", ".join(a.get("vmsa") or []),
                     "title": a["title"], "severity": a["severity"], "cvss": a["cvss"], "published": a["published"], "url": a["url"],
                     "cves": a["cves"], "verdict": best[0], "why": best[1], "hosts": t.get("hosts", 1)}
                rows.append(r)
                hits.setdefault(f"{t['product']}:{t['name']}", []).append(r)
    sv = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: (r["verdict"] != "취약", sv.get(r["severity"], 9), -(r["cvss"] or 0), r["published"]), reverse=False)
    return rows, hits


# ---------------------------------------------------------------- 변경 추적(구성 드리프트)
def diff_inventory(prev: dict | None, cur: dict) -> list[dict]:
    """두 수집 결과의 차이 — 호스트 추가/삭제·버전/빌드·고급 설정·서비스·잠금 모드·NTP·방화벽·vSwitch 정책·분산 포트그룹·VM 고급 설정"""
    if not prev:
        return []
    out: list[dict] = []

    def add(target, area, key, before, after, sev="info"):
        out.append({"target": target, "area": area, "key": key, "before": "" if before is None else str(before)[:200], "after": "" if after is None else str(after)[:200],
                    "severity": sev})
    ph = {h["name"]: h for h in prev.get("hosts", [])}
    ch = {h["name"]: h for h in cur.get("hosts", [])}
    for n in sorted(set(ph) - set(ch)):
        add(n, "호스트", "인벤토리", "있음", "제거됨", "warning")
    for n in sorted(set(ch) - set(ph)):
        add(n, "호스트", "인벤토리", "없음", "추가됨", "warning")
    for n in sorted(set(ph) & set(ch)):
        a, b = ph[n], ch[n]
        if (a.get("version"), a.get("build")) != (b.get("version"), b.get("build")) and b.get("build"):
            add(n, "버전", "ESXi", f"{a.get('version')} ({a.get('build')})", f"{b.get('version')} ({b.get('build')})", "info")
        if a.get("lockdown") != b.get("lockdown") and b.get("lockdown"):
            add(n, "계정·세션", "잠금 모드", a.get("lockdown"), b.get("lockdown"), "warning" if b.get("lockdown") == "lockdownDisabled" else "info")
        if sorted(a.get("ntp") or []) != sorted(b.get("ntp") or []) and (a.get("ntp") or b.get("ntp")):
            add(n, "시간", "NTP 서버", ", ".join(a.get("ntp") or []), ", ".join(b.get("ntp") or []), "warning")
        aa, ba = a.get("adv") or {}, b.get("adv") or {}
        for k in sorted(set(aa) | set(ba)):
            if k in aa and k in ba and str(aa[k]) != str(ba[k]):
                add(n, "고급 설정", k, aa[k], ba[k], "warning" if k.startswith(("Security.", "UserVars.ESXiShell", "Syslog.", "Config.HostAgent.plugins", "UserVars.ESXiVPs")) else "info")
        sa, sb = a.get("services") or {}, b.get("services") or {}
        for k in sorted(set(sa) & set(sb)):
            if (sa[k].get("running"), sa[k].get("policy")) != (sb[k].get("running"), sb[k].get("policy")):
                add(n, "서비스", k, f"실행 {sa[k].get('running')} · {sa[k].get('policy')}", f"실행 {sb[k].get('running')} · {sb[k].get('policy')}",
                    "warning" if k in ("TSM-SSH", "TSM", "slpd", "snmpd") and (sb[k].get("running") or sb[k].get("policy") == "on") else "info")
        fa, fb = a.get("firewall") or {}, b.get("firewall") or {}
        if fa and fb:
            if fa.get("incoming_blocked") != fb.get("incoming_blocked"):
                add(n, "방화벽", "기본 수신 차단", fa.get("incoming_blocked"), fb.get("incoming_blocked"), "warning")
            oa, ob = set(fa.get("open_all") or []), set(fb.get("open_all") or [])
            if oa != ob:
                add(n, "방화벽", "모든 IP 허용 규칙", ", ".join(sorted(oa)), ", ".join(sorted(ob)), "warning" if ob - oa else "info")
        va = {x["name"]: x for x in a.get("vswitch") or []}
        vb = {x["name"]: x for x in b.get("vswitch") or []}
        for k in sorted(set(va) & set(vb)):
            if {x: va[k].get(x) for x in ("promiscuous", "mac_changes", "forged")} != {x: vb[k].get(x) for x in ("promiscuous", "mac_changes", "forged")}:
                fmt = lambda x: f"P={x.get('promiscuous')} M={x.get('mac_changes')} F={x.get('forged')}"   # noqa: E731
                add(n, "네트워크", f"vSwitch {k} 보안 정책", fmt(va[k]), fmt(vb[k]), "warning" if any(vb[k].get(x) for x in ("promiscuous", "mac_changes", "forged")) else "info")
    pa = {x["name"]: x for x in prev.get("dvpg", [])}
    pb = {x["name"]: x for x in cur.get("dvpg", [])}
    for k in sorted(set(pa) & set(pb)):
        if {x: pa[k].get(x) for x in ("promiscuous", "mac_changes", "forged")} != {x: pb[k].get(x) for x in ("promiscuous", "mac_changes", "forged")}:
            fmt = lambda x: f"P={x.get('promiscuous')} M={x.get('mac_changes')} F={x.get('forged')}"   # noqa: E731
            add("분산 포트그룹", "네트워크", k, fmt(pa[k]), fmt(pb[k]), "warning" if any(pb[k].get(x) for x in ("promiscuous", "mac_changes", "forged")) else "info")
    vma = {x["name"]: x for x in prev.get("vms", [])}
    vmb = {x["name"]: x for x in cur.get("vms", [])}
    for k in sorted(set(vma) & set(vmb)):
        ea, eb = vma[k].get("adv") or {}, vmb[k].get("adv") or {}
        for key in sorted(set(ea) | set(eb)):
            if ea.get(key) != eb.get(key):
                add(k, "VM 설정", key, ea.get(key, "(없음)"), eb.get(key, "(없음)"), "warning" if str(eb.get(key, "")).lower() == "false" and "disable" in key else "info")
    vc0, vc1 = prev.get("vcenter") or {}, cur.get("vcenter") or {}
    if vc0.get("build") and vc1.get("build") and (vc0.get("version"), vc0.get("build")) != (vc1.get("version"), vc1.get("build")):
        add(vc1.get("host", "vCenter"), "버전", "vCenter", f"{vc0.get('version')} ({vc0.get('build')})", f"{vc1.get('version')} ({vc1.get('build')})", "info")
    out.sort(key=lambda x: (x["severity"] != "warning", x["area"], x["target"]))
    return out[:2000]


def diff_rows(prev_rows: list[dict], rows: list[dict]) -> list[dict]:
    """판정 변화 — PASS→FAIL(악화)·FAIL→PASS(개선)"""
    pk = {(r["id"], r["target"]): r["status"] for r in prev_rows or []}
    out = []
    for r in rows:
        old = pk.get((r["id"], r["target"]))
        if old and old != r["status"] and {old, r["status"]} & {"FAIL", "WARN", "PASS"}:
            out.append({"id": r["id"], "title": r["title"], "target": r["target"], "before": old, "after": r["status"],
                        "worse": STATUS_ORDER.get(r["status"], 9) < STATUS_ORDER.get(old, 9)})
    out.sort(key=lambda x: (not x["worse"], x["id"]))
    return out


class Assessor:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.enabled = bool(c.get("enabled", True))
        self.interval = float(c.get("interval_hours", 24)) * 3600
        self.max_vms = int(c.get("max_vms", 500))
        self.snap_days = int(c.get("snapshot_days", 3))
        n = c.get("nvd") or {}
        self.nvd = {"enabled": bool(n.get("enabled", False)), "url": n.get("url") or NVD_URL, "api_key": n.get("api_key", ""), "proxy": n.get("proxy", ""),
                    "interval_days": float(n.get("interval_days", 7))}
        self._schema = False
        self.last: dict | None = None
        self.running = False
        self.state: dict[str, Any] = {"last_run": 0, "last_nvd": 0, "nvd_error": "", "error": "", "advisories": 0}

    def _ensure(self):
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    async def advisories(self) -> list[dict]:
        self._ensure()
        rows = await self.e.store.q("SELECT * FROM assess_adv")
        for r in rows:
            r["cves"] = json.loads(r["cves"] or "[]")
            r["matches"] = json.loads(r["matches"] or "[]")
            r["vmsa"] = re.findall(r"VMSA-\d{4}-\d{4}", r["title"] or "") or ([r["id"]] if str(r["id"]).startswith("VMSA") else [])
        self.state["advisories"] = len(rows)
        return rows

    async def save_advisories(self, advs: list[dict]) -> int:
        self._ensure()
        now = time.time()
        await self.e.store.xm("INSERT OR REPLACE INTO assess_adv(id,title,severity,cvss,published,url,cves,matches,source,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              [(a["id"], a["title"], a["severity"], a["cvss"], a["published"], a["url"], json.dumps(a["cves"]), json.dumps(a["matches"]),
                                a["source"], now) for a in advs])
        self.state["advisories"] = len(await self.e.store.q("SELECT id FROM assess_adv"))
        return len(advs)

    async def import_json(self, raw: bytes) -> dict:
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError) as e:
            raise ValueError(f"JSON 형식 오류: {e}") from e
        items = data if isinstance(data, list) else [data]
        advs = []
        for d in items:
            if not isinstance(d, dict):
                continue
            advs += parse_nvd(d) if "vulnerabilities" in d else parse_own(d) if "advisories" in d else []
        if not advs:
            raise ValueError("ESXi·vCenter 에 해당하는 항목이 없습니다(NVD CVE API 2.0 응답 또는 advisories 형식)")
        n = await self.save_advisories(advs)
        return {"imported": n, "nvd": sum(1 for a in advs if a["source"] == "nvd"), "own": sum(1 for a in advs if a["source"] == "import")}

    async def nvd_sync(self) -> dict:
        """NVD CVE API 2.0 — 제품 CPE(virtualMatchString)별로 페이지(최대 2,000건) 단위 조회. 키 없으면 요청 간 6초(공개 권장)"""
        import httpx
        headers = {"apiKey": self.nvd["api_key"]} if self.nvd["api_key"] else {}
        kw: dict[str, Any] = {"timeout": 60, "headers": headers}
        if self.nvd["proxy"]:
            kw["proxy"] = self.nvd["proxy"]
        total = 0
        async with httpx.AsyncClient(**kw) as cl:
            for prod, cpe in PRODUCTS.items():
                start = 0
                while True:
                    r = await cl.get(self.nvd["url"], params={"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start})
                    if r.status_code >= 300:
                        raise RuntimeError(f"NVD HTTP {r.status_code} ({prod})")
                    j = r.json()
                    advs = parse_nvd(j)
                    total += await self.save_advisories(advs)
                    start += int(j.get("resultsPerPage") or 0)
                    if not j.get("resultsPerPage") or start >= int(j.get("totalResults") or 0):
                        break
                    await asyncio.sleep(0.7 if self.nvd["api_key"] else 6.5)
                await asyncio.sleep(0.7 if self.nvd["api_key"] else 6.5)
        self.state.update(last_nvd=time.time(), nvd_error="")
        return {"saved": total}

    async def run(self, by: str = "schedule") -> dict:
        if self.running:
            raise RuntimeError("이미 점검 중입니다")
        self.running = True
        try:
            self._ensure()
            invs = []
            for c in self.e.connectors:
                if getattr(c, "type", "") == "vcenter" and getattr(c, "enabled", True) and hasattr(c, "assess_collect"):
                    try:
                        invs.append(await asyncio.to_thread(c.assess_collect, self.max_vms))
                    except Exception as ex:  # noqa: BLE001
                        invs.append({"vcenter": {"name": c.name, "host": getattr(c, "host", "")}, "hosts": [], "vms": [], "dvpg": [],
                                     "errors": [f"수집 실패: {type(ex).__name__}: {ex}"[:200]]})
            advs = await self.advisories()
            targets = []
            for inv in invs:
                vc = inv.get("vcenter") or {}
                if vc.get("version"):
                    targets.append({"product": "vcenter", "name": vc.get("host", ""), "version": vc["version"], "build": vc.get("build", "")})
                for h in inv.get("hosts", []):
                    if h.get("version"):
                        targets.append({"product": "esxi", "name": h["name"], "version": h["version"], "build": h["build"]})
            cve_rows, hits = evaluate(advs, targets)
            rows = []
            for inv in invs:
                rows += [dict(r, vcenter=(inv.get("vcenter") or {}).get("name", "")) for r in hardening(inv, hits, bool(advs), self.snap_days)]
            prev = await self.latest()
            prev_inv = (prev or {}).get("inventory") or []
            changes = []
            for inv in invs:
                pi = next((x for x in prev_inv if (x.get("vcenter") or {}).get("name") == (inv.get("vcenter") or {}).get("name")), None)
                changes += [dict(c, vcenter=(inv.get("vcenter") or {}).get("name", "")) for c in diff_inventory(pi, inv)]
            verdicts = diff_rows((prev or {}).get("rows") or [], rows)
            await self._change_events(changes, verdicts)
            cnt = {s: sum(1 for r in rows if r["status"] == s) for s in STATUS_ORDER}
            scored = cnt["PASS"] + cnt["FAIL"] + cnt["WARN"]
            # 버전별 묶음(같은 버전·빌드 호스트 수)
            vers: dict[tuple, int] = {}
            for t in targets:
                vers[(t["product"], t["version"], t["build"])] = vers.get((t["product"], t["version"], t["build"]), 0) + 1
            summary = {"ts": time.time(), "by": by, "vcenters": len(invs), "hosts": sum(len(i.get("hosts", [])) for i in invs),
                       "vms": sum(len(i.get("vms", [])) for i in invs), "counts": cnt, "score": round(cnt["PASS"] / scored * 100, 1) if scored else None,
                       "cve": {"vulnerable": sum(1 for r in cve_rows if r["verdict"] == "취약"), "possible": sum(1 for r in cve_rows if r["verdict"] == "가능"),
                               "critical": sum(1 for r in cve_rows if r["severity"] == "CRITICAL"), "advisories_db": len(advs),
                               "targets": len(targets)},
                       "versions": [{"product": p, "version": v, "build": b, "count": n} for (p, v, b), n in sorted(vers.items())],
                       "errors": [e for i in invs for e in i.get("errors", [])][:20],
                       "changes": {"total": len(changes), "warning": sum(1 for c in changes if c["severity"] == "warning"),
                                   "worse": sum(1 for v in verdicts if v["worse"]), "better": sum(1 for v in verdicts if not v["worse"]),
                                   "since": (prev or {}).get("summary", {}).get("ts")}}
            slim = [{"vcenter": i.get("vcenter"), "hosts": [{k: h.get(k) for k in ("name", "version", "build", "conn", "lockdown", "adv", "services", "firewall", "ntp", "vswitch")}
                                                             for h in i.get("hosts", [])], "dvpg": i.get("dvpg", []),
                     "vms": [{k: v.get(k) for k in ("name", "adv")} for v in i.get("vms", [])]} for i in invs]
            data = {"summary": summary, "rows": rows, "kisa": kisa_summary(rows), "cve": cve_rows[:5000], "changes": changes, "verdicts": verdicts,
                    "inventory": slim}
            await self.e.store.x("INSERT INTO assess_runs(ts,summary,data) VALUES(?,?,?)", (summary["ts"], json.dumps(summary, ensure_ascii=False),
                                                                                         json.dumps(data, ensure_ascii=False)))
            await self.e.store.x("DELETE FROM assess_runs WHERE id NOT IN (SELECT id FROM assess_runs ORDER BY id DESC LIMIT 30)")
            self.last = data
            self.state.update(last_run=summary["ts"], error="")
            return data
        except Exception as ex:
            self.state["error"] = f"{type(ex).__name__}: {ex}"[:200]
            raise
        finally:
            self.running = False

    async def _change_events(self, changes: list[dict], verdicts: list[dict]) -> None:
        """구성 변경·판정 악화를 이벤트로(소스 vcenter, kind config) — 악화·보안 관련 변경은 경고(이상징후), 나머지는 정보"""
        ingest = getattr(self.e, "ingest", None)
        if not ingest:
            return
        from .models import LogEvent
        n = 0
        for c in changes[:100]:
            ev = LogEvent(source="vcenter", connector="assessment", message=f"구성 변경 — {c['target']} {c['area']} {c['key']}: {c['before'] or '(없음)'} → {c['after'] or '(없음)'}",
                          severity=c["severity"], host=c["target"] if c["area"] != "VM 설정" else "", entity=c["target"], kind="config",
                          attrs={"app": "config-drift", "area": c["area"], "key": c["key"], "no_anomaly": 0 if c["severity"] == "warning" else 1})
            ingest(ev) if not asyncio.iscoroutinefunction(ingest) else await ingest(ev)
            n += 1
        for v in verdicts[:100]:
            ev = LogEvent(source="vcenter", connector="assessment", message=f"보안 판정 {'악화' if v['worse'] else '개선'} — {v['target']} {v['id']} {v['title']}: {v['before']} → {v['after']}",
                          severity="warning" if v["worse"] else "info", host=v["target"], entity=v["target"], kind="config",
                          attrs={"app": "assessment", "check": v["id"], "no_anomaly": 0 if v["worse"] else 1})
            ingest(ev) if not asyncio.iscoroutinefunction(ingest) else await ingest(ev)
            n += 1
        self.state["last_events"] = n

    async def latest(self) -> dict | None:
        if self.last:
            return self.last
        self._ensure()
        r = await self.e.store.q1("SELECT data FROM assess_runs ORDER BY id DESC LIMIT 1")
        self.last = json.loads(r["data"]) if r else None
        return self.last

    async def history(self) -> list[dict]:
        self._ensure()
        return [dict(json.loads(r["summary"]), id=r["id"]) for r in await self.e.store.q("SELECT id, summary FROM assess_runs ORDER BY id DESC LIMIT 30")]

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(600)
        while True:
            beat()
            if self.enabled:
                try:
                    if self.nvd["enabled"] and time.time() - self.state["last_nvd"] > self.nvd["interval_days"] * 86400:
                        try:
                            await self.nvd_sync()
                        except Exception as ex:  # noqa: BLE001
                            self.state.update(nvd_error=f"{type(ex).__name__}: {ex}"[:200], last_nvd=time.time())
                    last = await self.latest()
                    if not last or time.time() - last["summary"]["ts"] > self.interval:
                        await self.run()
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(900)

    # ------------------------------------------------------------------ 보고서
    @staticmethod
    def to_csv(d: dict) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["구분", "ID", "KISA", "항목", "분류", "중요도", "대상", "판정", "현재값", "기대값", "조치", "vCenter"])
        for r in d["rows"]:
            w.writerow(["하드닝", r["id"], r["kisa"], r["title"], r["category"], r["severity"], r["target"], r["status"], r["current"], r["expected"], r["fix"],
                        r.get("vcenter", "")])
        w.writerow([])
        w.writerow(["구분", "대상", "영역", "항목", "이전", "현재", "심각도"])
        for c in d.get("changes") or []:
            w.writerow(["변경", c["target"], c["area"], c["key"], c["before"], c["after"], c["severity"]])
        w.writerow([])
        w.writerow(["구분", "권고/CVE", "VMSA", "제목", "심각도", "CVSS", "공개일", "대상", "제품", "버전", "빌드", "판정", "근거", "CVE", "링크"])
        for r in d["cve"]:
            w.writerow(["VMSA/CVE", r["id"], r["vmsa"], r["title"], r["severity"], r["cvss"], r["published"], r["target"], r["product"], r["version"], r["build"],
                        r["verdict"], r["why"], " ".join(r["cves"]), r["url"]])
        return "﻿" + buf.getvalue()

    @staticmethod
    def report_html(d: dict) -> str:
        e = html.escape
        s = d["summary"]
        c = s["counts"]
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["ts"]))
        st = lambda x: f"<b class='s-{x.replace('/', '')}'>{x}</b>"   # noqa: E731
        kisa = "".join(f"<tr><td>{e(k['code'])}</td><td>{e(k['title'])}</td><td>{e(k['importance'])}</td><td>{st(k['status'])}</td><td>{k['fail']}</td>"
                       f"<td>{k['targets']}</td><td>{e(k['note'])}</td></tr>" for k in d["kisa"])
        fails = [r for r in d["rows"] if r["status"] in ("FAIL", "WARN")]
        hard = "".join(f"<tr><td>{e(r['id'])}</td><td>{e(r['kisa'])}</td><td>{e(r['title'])}</td><td>{e(r['target'])}</td><td>{st(r['status'])}</td>"
                       f"<td>{e(r['current'])}</td><td>{e(r['expected'])}</td><td>{e(r['fix'])}</td></tr>" for r in fails[:1500])
        cve = "".join(f"<tr><td>{e(r['id'])}</td><td>{e(r['vmsa'])}</td><td>{e(SEV_KO.get(r['severity'], r['severity']))} {r['cvss'] or ''}</td><td>{e(r['target'])}</td>"
                      f"<td>{e(r['version'])} ({e(r['build'])})</td><td>{st('FAIL' if r['verdict'] == '취약' else 'WARN')} {e(r['verdict'])}</td><td>{e(r['why'])}</td>"
                      f"<td>{e(r['title'][:160])}</td></tr>" for r in d["cve"][:1500])
        vers = "".join(f"<tr><td>{e(v['product'])}</td><td>{e(v['version'])}</td><td>{e(v['build'])}</td><td>{v['count']}</td></tr>" for v in s["versions"])
        chg = "".join(f"<tr><td>{st('WARN' if c['severity'] == 'warning' else 'PASS')}</td><td>{e(c['target'])}</td><td>{e(c['area'])}</td><td>{e(c['key'])}</td><td>{e(c['before'])}</td><td>{e(c['after'])}</td></tr>"
                      for c in (d.get("changes") or [])[:500])
        return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>보안 판독 보고서 — {ts}</title>
<style>body{{font-family:Pretendard,'Malgun Gothic',sans-serif;color:#1d2328;margin:28px;font-size:12.5px}}h1{{font-size:22px;margin:0}}h2{{font-size:16px;margin:22px 0 8px}}
.k{{display:flex;gap:12px;margin:14px 0}}.k div{{border:1px solid #cfd6db;border-radius:6px;padding:8px 14px}}.k b{{display:block;font-size:20px}}
table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid #e1e6ea;padding:4px 6px;text-align:left;vertical-align:top}}th{{background:#f1f4f6}}
.s-FAIL{{color:#c62828}}.s-WARN{{color:#b26a00}}.s-PASS{{color:#2e7d32}}.s-MANUAL{{color:#455a64}}.s-NA{{color:#90a4ae}}
.note{{color:#5b6670;font-size:11.5px;line-height:1.6}}@media print{{.noprint{{display:none}}body{{margin:10mm}}}}</style></head><body>
<p class="noprint"><button onclick="print()">인쇄 / PDF 저장</button></p>
<h1>VCF 보안 판독 보고서</h1><div class="note">점검 {ts} · vCenter {s['vcenters']} · ESXi {s['hosts']} · VM 표본 {s['vms']} · 읽기 전용 수집(설정 변경 없음)</div>
<div class="k"><div>준수율<b>{s['score'] if s['score'] is not None else '-'}%</b></div><div>FAIL<b>{c['FAIL']}</b></div><div>WARN<b>{c['WARN']}</b></div>
<div>MANUAL<b>{c['MANUAL']}</b></div><div>PASS<b>{c['PASS']}</b></div><div>VMSA/CVE 취약<b>{s['cve']['vulnerable']}</b></div><div>가능(빌드 확인)<b>{s['cve']['possible']}</b></div></div>
<h2>버전 현황</h2><table><tr><th>제품</th><th>버전</th><th>빌드</th><th>대수</th></tr>{vers}</table>
<h2>KISA 가상화 점검 항목(HV)</h2><table><tr><th>코드</th><th>항목</th><th>중요도</th><th>판정</th><th>FAIL</th><th>대상</th><th>미흡 내용</th></tr>{kisa}</table>
<h2>하드닝 미흡 항목(FAIL·WARN)</h2><table><tr><th>ID</th><th>KISA</th><th>항목</th><th>대상</th><th>판정</th><th>현재값</th><th>기대값</th><th>조치</th></tr>{hard or '<tr><td colspan=8>없음</td></tr>'}</table>
<h2>지난 점검 이후 구성 변경 <small>{len(d.get("changes") or [])}건</small></h2><table><tr><th>심각도</th><th>대상</th><th>영역</th><th>항목</th><th>이전</th><th>현재</th></tr>{chg or '<tr><td colspan=6>변경 없음(또는 첫 점검)</td></tr>'}</table>
<h2>VMSA/CVE 판독</h2><table><tr><th>CVE/권고</th><th>VMSA</th><th>심각도</th><th>대상</th><th>버전(빌드)</th><th>판정</th><th>근거</th><th>설명</th></tr>{cve or '<tr><td colspan=8>해당 없음(취약점 목록 {s["cve"]["advisories_db"]}건 기준)</td></tr>'}</table>
<p class="note">판정 기준: PASS 기준 충족 · FAIL 미충족 · WARN 검토 필요 · MANUAL vCenter 경유 읽기 전용으로 확인 불가(현장 확인) · N/A 해당 버전에 설정 없음.
VMSA/CVE '취약' 은 권고의 고정 빌드보다 낮은 빌드, '가능' 은 NVD CPE 의 버전·업데이트가 일치해 패치 빌드 확인이 필요한 경우입니다. 취약점 목록 출처: NVD CVE API 2.0 또는 가져온 권고 파일.</p>
</body></html>"""
