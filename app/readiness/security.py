"""BMC 보안 점검(읽기 전용) — VCF 9 보안 구성 가이드(SCG) 하드웨어 관리 항목 + CISA/NSA BMC 하드닝 권고 기반

원칙: Redfish 가 값을 주지 않으면 'unknown'(미노출) — 통과로 치지 않는다. 비밀번호·SNMP 커뮤니티·키 값은 수집하지 않는다.
SCG ID(esx-9.hardware-management-*)·NIST 800-53r5 매핑은 VCF 9 SCG 의 하드웨어 관리 항목을 따른다.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SCG = {
    "tls": ("esx-9.hardware-management-tls", "SC-08, SC-08(01), SC-13"),
    "certificates": ("esx-9.hardware-management-certificates", "IA-05(02), SC-08, SC-17"),
    "ssh": ("esx-9.hardware-management-ssh-cryptography", "CM-07, SC-08, SC-13"),
    "security": ("esx-9.hardware-management-security", "AC-12, CM-07, IA-05(05), SC-10"),
    "authentication": ("esx-9.hardware-management-authentication", "AC-04(21), AC-07, IA-05(01)"),
    "time": ("esx-9.hardware-management-time", "AU-08, SC-45(01)"),
    "log": ("esx-9.hardware-management-log-forwarding", "AU-06(04), SI-04"),
    "secureboot": ("esx-9.hardware-secureboot", "SI-07(09), SI-07(10)"),
}
CISA = {"cred": "자격 증명 보호", "net": "관리망 분리", "harden": "구성 하드닝", "update": "업데이트·무결성", "monitor": "감시"}
DEFAULT_ADMINS = {"root", "admin", "administrator", "ADMIN", "USERID"}


def _row(cid, title, status, observed, expected, group, cisa, sev="medium", fix="", scg=None):
    s = SCG.get(scg) if scg else None
    return {"id": cid, "title": title, "status": status, "observed": observed, "expected": expected, "group": group, "cisa": CISA.get(cisa, cisa),
            "severity": sev, "fix": fix, "scg": s[0] if s else "", "nist": s[1] if s else ""}


def _on(v) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("enabled", "enable", "on", "true", "1", "yes"):
        return True
    if s in ("disabled", "disable", "off", "false", "0", "no"):
        return False
    return None


def audit(h: dict, now: datetime | None = None) -> list[dict]:
    b = h.get("bmc") or {}
    if not b:
        return []
    now = now or datetime.now(timezone.utc)
    pr = b.get("protocols") or {}
    oem = b.get("oem") or {}
    pol = b.get("policy") or {}
    out: list[dict] = []

    def proto(name: str, dell_key: str | None = None):
        v = (pr.get(name) or {}).get("enabled")
        if v is None and dell_key:
            v = _on(oem.get(dell_key))
        return v

    # TLS·HTTP
    http = proto("HTTP")
    redir = _on(oem.get("WebServer.1.HttpsRedirection"))
    if http is False or redir:
        out.append(_row("BMC-01", "평문 HTTP 차단(또는 HTTPS 리다이렉트)", "pass", "HTTP 꺼짐" if http is False else "HTTPS 리다이렉트", "HTTP 끔/리다이렉트", "TLS", "harden", "high", scg="tls"))
    elif http:
        out.append(_row("BMC-01", "평문 HTTP 차단(또는 HTTPS 리다이렉트)", "fail", "HTTP 켜짐", "HTTP 끔/리다이렉트", "TLS", "harden", "high", "BMC 웹 서버 HTTP 비활성 또는 HTTPS 리다이렉트", "tls"))
    else:
        out.append(_row("BMC-01", "평문 HTTP 차단(또는 HTTPS 리다이렉트)", "unknown", "미노출", "HTTP 끔", "TLS", "harden", scg="tls"))
    tls = str(oem.get("WebServer.1.TLSProtocol") or "")
    if tls:
        bad = re.search(r"1\.0|1\.1", tls) and not re.search(r"1\.2 and higher|1\.3 only|1\.2 only", tls, re.I)
        out.append(_row("BMC-02", "최소 TLS 1.2", "fail" if bad else "pass", tls, "TLS 1.2 이상", "TLS", "harden", "high", "TLS 1.0/1.1 비활성" if bad else "", "tls"))
    else:
        out.append(_row("BMC-02", "최소 TLS 1.2", "unknown", "표준 Redfish 로 노출되지 않음(벤더 설정 확인)", "TLS 1.2 이상", "TLS", "harden", "high", scg="tls"))
    certs = b.get("certificates") or []
    if certs:
        c = certs[0]
        exp = None
        try:
            exp = datetime.fromisoformat(str(c.get("not_after")).replace("Z", "+00:00"))
        except ValueError:
            pass
        expired = exp is not None and exp < now
        soon = exp is not None and not expired and (exp - now).days < 30
        dflt = bool(re.search(r"(?i)default|idrac|ilo|xcc|ibmc|supermicro|cimc", f"{c.get('issuer')}")) and c.get("self_signed")
        st = "fail" if expired or c.get("self_signed") or dflt else ("warn" if soon else "pass")
        out.append(_row("BMC-03", "신뢰 CA 발급 웹 인증서", st, f"발급자 {c.get('issuer') or '?'} · 만료 {str(c.get('not_after'))[:10]}" + (" · 자체 서명" if c.get("self_signed") else ""),
                        "사내 CA 발급·유효", "인증서", "harden", "high", "사내 CA 인증서로 교체·만료 관리" if st != "pass" else "", "certificates"))
    else:
        out.append(_row("BMC-03", "신뢰 CA 발급 웹 인증서", "unknown", "CertificateService 미노출", "사내 CA 발급", "인증서", "harden", scg="certificates"))
    # 서비스 노출
    ssh = proto("SSH", "SSH.1.Enable")
    out.append(_row("BMC-04", "SSH 노출 최소화", "pass" if ssh is False else ("info" if ssh else "unknown"), {True: "켜짐", False: "꺼짐"}.get(ssh, "미노출"),
                    "불필요 시 끔(쓰면 약한 암호 제외)", "서비스", "harden", "medium", "사용하지 않으면 비활성, 사용 시 SSH 암호 정책 점검" if ssh else "", "ssh"))
    ipmi = proto("IPMI", "IPMILan.1.Enable")
    keydef = oem.get("IPMILan.1.EncryptionKeyDefault")
    out.append(_row("BMC-05", "IPMI over LAN 비활성", "fail" if ipmi else ("pass" if ipmi is False else "unknown"), {True: "켜짐" + (" · 암호화 키 기본값(0)" if keydef else ""), False: "꺼짐"}.get(ipmi, "미노출"),
                    "끔", "서비스", "harden", "high", "IPMI over LAN 비활성(필요 시 암호화 키 설정·Cipher 0 차단)" if ipmi else "", "security"))
    tel = proto("Telnet", "Telnet.1.Enable")
    out.append(_row("BMC-06", "Telnet 비활성", "fail" if tel else ("pass" if tel is False or pr else "unknown"), {True: "켜짐", False: "꺼짐"}.get(tel, "항목 없음" if pr else "미노출"),
                    "끔", "서비스", "harden", "high", "Telnet 비활성" if tel else "", "security"))
    sn = b.get("snmp") or {}
    snmp_on = proto("SNMP", "SNMP.1.AgentEnable")
    if snmp_on is False:
        out.append(_row("BMC-07", "SNMP v1/v2c 비활성(v3 만)", "pass", "SNMP 꺼짐", "v3 만", "서비스", "harden", "high", scg="security"))
    elif sn.get("v1") or sn.get("v2c") or re.search(r"(?i)all|v1|v2", str(oem.get("SNMP.1.SNMPProtocol") or "")) and "v3" not in str(oem.get("SNMP.1.SNMPProtocol") or "").lower():
        out.append(_row("BMC-07", "SNMP v1/v2c 비활성(v3 만)", "fail", f"v1={sn.get('v1')} v2c={sn.get('v2c')} v3={sn.get('v3')}", "v3 만", "서비스", "harden", "high", "SNMP v1/v2c 끄고 v3(SHA·AES) 사용", "security"))
    elif sn.get("v3") or snmp_on:
        out.append(_row("BMC-07", "SNMP v1/v2c 비활성(v3 만)", "pass" if sn.get("v1") is False and sn.get("v2c") is False else "unknown",
                        f"v1={sn.get('v1')} v2c={sn.get('v2c')} v3={sn.get('v3')}", "v3 만", "서비스", "harden", "high", scg="security"))
    else:
        out.append(_row("BMC-07", "SNMP v1/v2c 비활성(v3 만)", "unknown", "미노출", "v3 만", "서비스", "harden", scg="security"))
    ssdp = proto("SSDP")
    out.append(_row("BMC-08", "자동 탐색(SSDP) 비활성", "fail" if ssdp else ("pass" if ssdp is False else "unknown"), {True: "켜짐", False: "꺼짐"}.get(ssdp, "미노출"),
                    "끔", "서비스", "net", "low", "SSDP 비활성" if ssdp else ""))
    vnc = _on(oem.get("VNCServer.1.Enable"))
    if vnc is not None:
        out.append(_row("BMC-09", "VNC 서버 비활성", "fail" if vnc else "pass", "켜짐" if vnc else "꺼짐", "끔", "서비스", "harden", "medium", "VNC 비활성" if vnc else ""))
    osbmc = str(oem.get("OS-BMC.1.AdminState") or "")
    if osbmc:
        on = _on(osbmc)
        out.append(_row("BMC-10", "OS↔BMC 패스스루 비활성", "fail" if on else "pass", osbmc, "Disabled", "망 분리", "net", "medium", "호스트 OS 에서 BMC 로 가는 내부 경로 차단" if on else ""))
    # 인증·계정
    tmo = b.get("session_timeout")
    if tmo is not None:
        st = "pass" if 0 < tmo <= 1800 else "fail"
        out.append(_row("BMC-11", "세션 유휴 시간 제한 ≤ 30분", st, f"{tmo}초", "1–1800초", "인증", "cred", "medium", "세션 타임아웃 1800초 이하" if st == "fail" else "", "security"))
    else:
        out.append(_row("BMC-11", "세션 유휴 시간 제한 ≤ 30분", "unknown", "미노출", "1–1800초", "인증", "cred", scg="security"))
    lt = pol.get("lockout_threshold")
    ipblk = _on(oem.get("IPBlocking.1.BlockEnable"))
    if lt and 1 <= lt <= 5 or ipblk:
        out.append(_row("BMC-12", "로그인 실패 잠금(1–5회)", "pass", f"임계 {lt}회" if lt else "IP 차단 켜짐", "1–5회", "인증", "cred", "high", scg="authentication"))
    elif lt is not None:
        out.append(_row("BMC-12", "로그인 실패 잠금(1–5회)", "fail", f"임계 {lt}회" + (" (잠금 없음)" if lt == 0 else ""), "1–5회", "인증", "cred", "high", "계정 잠금 임계 5회 이하·잠금 시간 설정", "authentication"))
    else:
        out.append(_row("BMC-12", "로그인 실패 잠금(1–5회)", "unknown", "미노출", "1–5회", "인증", "cred", "high", scg="authentication"))
    mp = pol.get("min_pw") or (int(oem["Security.1.PasswordMinimumLength"]) if str(oem.get("Security.1.PasswordMinimumLength") or "").isdigit() else None)
    if mp:
        st = "pass" if mp >= 12 else ("warn" if mp >= 8 else "fail")
        out.append(_row("BMC-13", "최소 비밀번호 길이 ≥ 12", st, f"{mp}자", "12자 이상", "인증", "cred", "high", "최소 길이 12자 이상" if st != "pass" else "", "authentication"))
    else:
        out.append(_row("BMC-13", "최소 비밀번호 길이 ≥ 12", "unknown", "미노출", "12자 이상", "인증", "cred", scg="authentication"))
    out.append(_row("BMC-14", "디렉터리(LDAP/AD) 인증 연동", "pass" if pol.get("ldap") or pol.get("ad") else "info", "LDAP" if pol.get("ldap") else ("AD" if pol.get("ad") else "로컬 계정만"),
                    "중앙 인증", "인증", "cred", "medium", "" if pol.get("ldap") or pol.get("ad") else "LDAPS/AD(인증서 검증) 연동 권장", "authentication"))
    out.append(_row("BMC-15", "다단계 인증(MFA)", "pass" if pol.get("mfa") else "info", "켜짐" if pol.get("mfa") else "미사용/미노출", "MFA", "인증", "cred", "low"))
    accts = [a for a in b.get("accounts") or [] if a.get("enabled")]
    dflt = [a["user"] for a in accts if a.get("user") in DEFAULT_ADMINS and a.get("role") == "Administrator"]
    out.append(_row("BMC-16", "기본 관리자 계정 이름 사용 안 함", "warn" if dflt else ("pass" if accts else "unknown"), ", ".join(dflt) or (f"활성 {len(accts)}개" if accts else "미노출"),
                    "기본 계정 이름 변경·비활성(비밀번호 공장값 여부는 확인 불가)", "계정", "cred", "high", "기본 관리자 계정 이름 변경 또는 비활성, 개인 계정 사용" if dflt else ""))
    adm = [a["user"] for a in accts if a.get("role") == "Administrator"]
    if accts:
        out.append(_row("BMC-17", "관리자 권한 계정 최소화(≤ 3)", "pass" if len(adm) <= 3 else "warn", f"관리자 {len(adm)} / 활성 {len(accts)}", "≤ 3", "계정", "cred", "medium",
                        "" if len(adm) <= 3 else "역할 분리(ReadOnly·Operator)"))
    # 망·시간·로그
    nic_sel = str(oem.get("NIC.1.Selection") or "")
    if nic_sel:
        ded = "dedicated" in nic_sel.lower() or nic_sel == "1"
        out.append(_row("BMC-18", "전용 관리 포트 사용", "pass" if ded else "fail", nic_sel, "Dedicated", "망 분리", "net", "high", "" if ded else "LOM 공유 대신 전용 관리 포트(관리망 분리)"))
    ifs = b.get("ifaces") or []
    if ifs:
        dh = any(i.get("dhcp") for i in ifs)
        out.append(_row("BMC-19", "관리 IP 고정(DHCP 미사용)", "warn" if dh else "pass", "DHCP" if dh else "고정", "고정 IP", "망 분리", "net", "low", "관리 IP 고정·DNS 등록" if dh else ""))
    ntp = b.get("ntp_servers") or []
    ntp_on = (pr.get("NTP") or {}).get("enabled")
    out.append(_row("BMC-20", "NTP 시간 동기화", "pass" if ntp and ntp_on is not False else ("fail" if pr else "unknown"), ", ".join(ntp) or "서버 없음", "NTP 2대 이상", "시간", "monitor", "medium",
                    "" if ntp else "사내 NTP 서버 지정", "time"))
    dt = b.get("datetime")
    if dt:
        try:
            drift = abs((datetime.fromisoformat(dt.replace("Z", "+00:00")) - now).total_seconds())
            out.append(_row("BMC-21", "BMC 시계 오차 ≤ 5분", "pass" if drift <= 300 else ("warn" if drift <= 1800 else "fail"), f"{drift:.0f}초", "≤ 300초", "시간", "monitor", "medium",
                            "" if drift <= 300 else "NTP 설정·도달성 확인(로그 상관 분석·인증서 검증에 영향)", "time"))
        except ValueError:
            pass
    sl = _on(oem.get("SysLog.1.SysLogEnable"))
    out.append(_row("BMC-22", "원격 syslog 전송", "pass" if sl else ("fail" if sl is False else "unknown"), {True: "켜짐", False: "꺼짐"}.get(sl, "표준 Redfish 미노출(벤더 설정 확인)"),
                    "원격 syslog(가능하면 TLS)", "로그", "monitor", "medium", "BMC syslog 를 이 AIOps(UDP/TCP 514·TLS 6514)로 전송" if sl is False else "", "log"))
    lock = _on(oem.get("Lockdown.1.SystemLockdown"))
    if lock is not None:
        out.append(_row("BMC-23", "시스템 잠금(System Lockdown)", "pass" if lock else "info", "켜짐" if lock else "꺼짐", "운영 중 켬(변경 창구에서만 해제)", "구성", "harden", "low"))
    sb = h.get("secureboot") or {}
    if sb:
        ok = sb.get("current") == "Enabled" or sb.get("enable") is True
        out.append(_row("BMC-24", "UEFI Secure Boot", "pass" if ok else "fail", f"Enable={sb.get('enable')} 현재={sb.get('current') or '?'}", "Enabled", "무결성", "update", "high",
                        "" if ok else "Secure Boot 활성화", "secureboot"))
    return out


def score(rows: list[dict]) -> dict[str, Any]:
    p = sum(1 for r in rows if r["status"] == "pass")
    f = sum(1 for r in rows if r["status"] == "fail")
    w = sum(1 for r in rows if r["status"] == "warn")
    u = sum(1 for r in rows if r["status"] == "unknown")
    assessed = p + f + w
    posture = "조치 필요" if f else ("주의" if w else ("일부만 확인" if u else ("기준 충족" if p else "미평가")))
    return {"pass": p, "fail": f, "warn": w, "unknown": u, "total": len(rows), "compliance": round(p / assessed * 100, 1) if assessed else None,
            "coverage": round(assessed / len(rows) * 100, 1) if rows else 0, "posture": posture,
            "scg": {k: _scg_state(rows, v[0]) for k, v in SCG.items()}}


def _scg_state(rows: list[dict], sid: str) -> str:
    st = {r["status"] for r in rows if r["scg"] == sid}
    return "fail" if "fail" in st else ("warn" if "warn" in st else ("pass" if "pass" in st else "unknown"))
