"""Active Directory / LDAP 인증 (ldap3, 순수 파이썬).

흐름: 사용자 자격증명으로 bind(UPN user@domain 또는 DN 템플릿) → 사용자 엔트리 조회
     → 그룹 매핑(AD 중첩 그룹은 LDAP_MATCHING_RULE_IN_CHAIN 1.2.840.113556.1.4.1941) → 역할 결정
매핑된 그룹이 없으면 로그인 거부(최소 권한).
"""
from __future__ import annotations

import ssl
from typing import Any

ROLE_ORDER = ["viewer", "auditor", "operator", "admin"]


class LdapError(Exception):
    pass


def _escape(v: str) -> str:
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(v)


def authenticate(cfg: dict, username: str, password: str) -> dict[str, Any]:
    """성공 시 {username, display, email, role, groups}. 실패 시 LdapError."""
    from ldap3 import ALL, Connection, Server, ServerPool, Tls, FIRST
    from ldap3.core.exceptions import LDAPBindError, LDAPException

    if not password:
        raise LdapError("빈 비밀번호")
    tls = None
    if cfg.get("use_ssl", True) or cfg.get("start_tls"):
        tls = Tls(validate=ssl.CERT_REQUIRED if cfg.get("verify_tls", True) else ssl.CERT_NONE,
                  ca_certs_file=cfg.get("ca_file") or None, version=ssl.PROTOCOL_TLS_CLIENT)
    servers = [Server(u, use_ssl=str(u).lower().startswith("ldaps"), tls=tls, get_info=ALL,
                      connect_timeout=int(cfg.get("timeout", 8))) for u in cfg.get("servers") or []]
    if not servers:
        raise LdapError("ldap.servers 미설정")
    pool = ServerPool(servers, FIRST, active=True, exhaust=60)

    user = username.strip()
    sam = user.split("\\")[-1].split("@")[0]
    if cfg.get("bind_dn_template"):
        bind_user = cfg["bind_dn_template"].format(username=sam)
    elif "@" in user or "\\" in user:
        bind_user = user
    else:
        bind_user = f"{sam}@{cfg['domain']}" if cfg.get("domain") else sam
    try:
        conn = Connection(pool, user=bind_user, password=password, auto_bind=False,
                          receive_timeout=int(cfg.get("timeout", 8)), raise_exceptions=True)
        if cfg.get("start_tls"):
            conn.open()
            conn.start_tls()
        conn.bind()
    except LDAPBindError as e:
        raise LdapError("아이디 또는 비밀번호가 올바르지 않습니다") from e
    except LDAPException as e:
        raise LdapError(f"디렉터리 서버 연결 실패: {type(e).__name__}") from e

    try:
        base = cfg["base_dn"]
        flt = cfg.get("user_filter", "(&(objectClass=user)(sAMAccountName={username}))").format(username=_escape(sam))
        conn.search(base, flt, attributes=["distinguishedName", "displayName", "mail", "memberOf", "cn"])
        if not conn.entries:
            raise LdapError("디렉터리에서 사용자를 찾을 수 없습니다")
        ent = conn.entries[0]
        dn = str(ent.entry_dn)
        groups = [str(g) for g in (ent.memberOf.values if "memberOf" in ent else [])]
        role = None
        gmap: dict[str, str] = cfg.get("group_role_map") or {}
        for group_dn, r in sorted(gmap.items(), key=lambda kv: -ROLE_ORDER.index(kv[1]) if kv[1] in ROLE_ORDER else 0):
            if any(g.lower() == group_dn.lower() for g in groups):
                role = r
                break
            if cfg.get("nested_groups", True):     # AD 중첩 그룹 포함 멤버십
                conn.search(base, f"(&(distinguishedName={_escape(dn)})(memberOf:1.2.840.113556.1.4.1941:={_escape(group_dn)}))",
                            attributes=["cn"])
                if conn.entries:
                    role = r
                    break
        if not role:
            raise LdapError("허용된 AD 그룹(group_role_map)에 속하지 않은 사용자입니다")
        return {"username": sam.lower(), "display": str(ent.displayName) if "displayName" in ent else sam,
                "email": str(ent.mail) if "mail" in ent else "", "role": role, "groups": groups[:50], "dn": dn}
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass
