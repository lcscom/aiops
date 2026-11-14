"""2.1 — MFA(TOTP), OIDC SSO(JWT 검증·역할 매핑), SIEM CEF, PagerDuty/Opsgenie, API 토큰 IP 허용 목록, 경영진 요약"""
import asyncio
import base64
import json
import os
import tempfile
import time
from types import SimpleNamespace as NS

from app import siem
from app.security import mfa, oidc
from app.security.audit import AuditLog
from app.security.auth import AuthManager, PUBLIC, ip_allowed
from app.store import Store


def _store():
    return Store(os.path.join(tempfile.mkdtemp(), "t.db"))


# ---------------------------------------------------------------- MFA
def test_totp_rfc6238_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()      # RFC 6238 부록 B (SHA1, 8자리 → 6자리는 뒤 6자리)
    assert mfa.totp(secret, 59) == "287082"[-6:] and mfa.totp(secret, 1111111109) == "081804"[-6:]
    assert mfa.totp(secret, 1234567890) == "005924"[-6:]


def test_mfa_enroll_confirm_verify_recovery_and_replay():
    st = _store()
    m = mfa.Mfa(st, {"required_roles": ["admin"]})

    async def go():
        assert m.must_enroll("admin", False) and not m.must_enroll("viewer", False)
        en = await m.enroll("alice")
        assert en["uri"].startswith("otpauth://totp/VCF%20AIops:alice?secret=") and (en["qr_svg"] == "" or "<svg" in en["qr_svg"])
        assert not (await m.status("alice"))["enrolled"]
        try:
            await m.confirm("alice", "000000")
            raise AssertionError("잘못된 코드로 등록되면 안 됨")
        except ValueError:
            pass
        codes = await m.confirm("alice", mfa.totp(en["secret"], time.time() - 30))   # 이전 창 코드(±1 허용)로 등록
        assert len(codes) == 8 and (await m.status("alice"))["enrolled"] and (await m.status("alice"))["recovery_left"] == 8
        assert await m.verify("alice", mfa.totp(en["secret"])) == "totp"            # 현재 창 — 등록 때 쓴 창보다 뒤
        try:                                                                        # 같은 창의 코드 재사용 금지
            await m.verify("alice", mfa.totp(en["secret"]))
            raise AssertionError("재사용 코드가 통과하면 안 됨")
        except ValueError as e:
            assert "이미 사용" in str(e)
        assert await m.verify("alice", codes[0].upper()) == "recovery"
        assert (await m.status("alice"))["recovery_left"] == 7
        try:
            await m.verify("alice", codes[0])
            raise AssertionError("복구 코드는 1회만")
        except ValueError:
            pass
        assert await m.enrolled_users() == {"alice"}
        en2 = await m.enroll("alice")                                        # 재등록 — 확인 전까지 기존 키 유지
        assert (await m.status("alice"))["enrolled"]
        assert await m.verify("alice", mfa.totp(en["secret"], time.time() + 30)) == "totp"
        await m.confirm("alice", mfa.totp(en2["secret"]))
        await m.reset("alice")
        assert not (await m.status("alice"))["enrolled"]
    asyncio.run(go())


def test_login_two_step_with_mfa_and_token_ip_allowlist():
    st = _store()
    audit = AuditLog(st)
    d = tempfile.mkdtemp()
    os.environ["AIOPS_ADMIN_PASSWORD"] = "Boot#Pass2026xyz"
    A = AuthManager(st, {"enabled": True, "mfa": {"enabled": True, "required_roles": ["admin"]}, "password": {}}, audit, d)

    async def go():
        await A.bootstrap()
        r = await A.login("admin", "Boot#Pass2026xyz", "10.0.0.5", "ua")
        assert r.get("sid") and r["must_enroll_mfa"] is True                 # 등록 전: 세션은 열리되 등록 요구
        en = await A.mfa.enroll("admin")
        await A.mfa.confirm("admin", mfa.totp(en["secret"], time.time() - 30))
        r2 = await A.login("admin", "Boot#Pass2026xyz", "10.0.0.5", "ua")
        assert r2.get("mfa_required") and "sid" not in r2
        try:
            await A.mfa_verify(r2["mfa_token"], "000000", "10.0.0.5")
            raise AssertionError
        except Exception as e:  # noqa: BLE001
            assert getattr(e, "status_code", 0) == 401
        s = await A.mfa_verify(r2["mfa_token"], mfa.totp(en["secret"]), "10.0.0.5")
        assert s["sid"] in A.sessions and A.sessions[s["sid"]]["mfa"] and A.sessions[s["sid"]]["must_enroll_mfa"] is False
        try:
            await A.mfa_verify(r2["mfa_token"], mfa.totp(en["secret"], time.time() + 30), "10.0.0.5")   # 토큰 1회용
            raise AssertionError
        except Exception as e:  # noqa: BLE001
            assert getattr(e, "status_code", 0) == 401
        # API 토큰 IP 허용 목록
        await st.x("INSERT INTO api_tokens(name,hash,prefix,scopes,created_by,created,expires,allow_ips) VALUES(?,?,?,?,?,?,?,?)",
                   ("t", __import__("hashlib").sha256(b"aiops_x").hexdigest(), "aiops_x", json.dumps(["read"]), "admin", time.time(), 0, "10.10.0.0/24, 192.168.1.9"))
        assert await A.token_user("aiops_x", "read", "10.10.0.77") and await A.token_user("aiops_x", "read", "192.168.1.9")
        assert await A.token_user("aiops_x", "read", "172.16.0.1") is None and await A.token_user("aiops_x", "read") is not None
        rows = await audit.query(0, time.time() + 1, action="auth.mfa")
        assert {r["result"] for r in rows} >= {"ok", "fail"}
    asyncio.run(go())
    os.environ.pop("AIOPS_ADMIN_PASSWORD", None)
    assert ip_allowed("10.0.0.1", "") and ip_allowed("10.0.0.1", "10.0.0.0/8") and not ip_allowed("bad", "10.0.0.0/8") and not ip_allowed("10.0.0.1", "notacidr")
    assert PUBLIC.match("/api/auth/mfa/verify") and PUBLIC.match("/api/auth/oidc/callback") and not PUBLIC.match("/api/auth/mfa/enroll")


# ---------------------------------------------------------------- OIDC
def _jwt(payload: dict, key, kid="k1", alg="RS256"):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    h = oidc._b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    p = oidc._b64u(json.dumps(payload).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{oidc._b64u(sig)}"


def test_oidc_jwt_verify_and_role_mapping():
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "k1", "n": oidc._b64u(pub.n.to_bytes(256, "big")), "e": oidc._b64u(pub.e.to_bytes(3, "big"))}
    claims = {"iss": "https://idp", "aud": "vcf-aiops", "exp": time.time() + 60, "nonce": "n", "preferred_username": "Bob@corp.local", "groups": ["AIOps-Operators", "x"]}
    tok = _jwt(claims, key)
    assert oidc.verify_jwt(tok, [jwk])["preferred_username"] == "Bob@corp.local"
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        oidc.verify_jwt(_jwt(claims, other), [jwk])
        raise AssertionError("다른 키 서명이 통과하면 안 됨")
    except ValueError:
        pass
    none_tok = oidc._b64u(b'{"alg":"none"}') + "." + oidc._b64u(json.dumps(claims).encode()) + "."
    try:
        oidc.verify_jwt(none_tok, [jwk])
        raise AssertionError("alg=none 거부")
    except ValueError:
        pass
    cfg = {"role_claim": "groups", "group_role_map": {"aiops-operators": "operator", "aiops-admins": "admin"}, "default_role": ""}
    assert oidc.map_role(claims, cfg) == "operator"
    assert oidc.map_role({"groups": ["AIOps-Admins", "AIOps-Operators"]}, cfg) == "admin"
    assert oidc.map_role({"groups": ["nobody"]}, cfg) == "" and oidc.map_role({"groups": []}, {**cfg, "default_role": "viewer"}) == "viewer"
    assert oidc.map_role({"realm_access": {"roles": ["aiops-admins"]}}, {**cfg, "role_claim": "realm_access.roles"}) == "admin"
    o = oidc.Oidc({"enabled": True, "issuer": "https://idp", "client_id": "vcf-aiops", "strip_domain": True}, b"k" * 32)
    assert o.enabled and o.username(claims) == "bob"
    signed = o._sign({"state": "s", "exp": time.time() + 10})
    assert o._open(signed)["state"] == "s"
    try:
        o._open(signed[:-2] + "zz")
        raise AssertionError
    except Exception as e:  # noqa: BLE001
        assert getattr(e, "status_code", 0) == 400


# ---------------------------------------------------------------- SIEM CEF
def test_cef_format_and_siem_queue():
    line = siem.cef("Broadcom", "VCF AIops", "2.1.0", "audit:auth.login", "auth|login", 7, {"suser": "a=b", "msg": "x\ny", "src": "10.0.0.1"})
    assert line.startswith("CEF:0|Broadcom|VCF AIops|2.1.0|audit:auth.login|auth\\|login|7|") and "suser=a\\=b" in line and "msg=x\\ny" in line
    s = siem.Siem({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "udp", "min_severity": "error"}, "2.1.0", "aiops-1")
    s.audit("auth.login", "alice", "admin", "10.0.0.1", "", "fail", {"x": 1})
    s.anomaly({"id": "a1", "severity": "warning", "title": "w", "event": {}})          # min_severity 미만 → 제외
    s.anomaly({"id": "a2", "severity": "critical", "title": "disk", "category": "storage", "event": {"host": "esx01", "message": "m"}, "ai": {"summary": "s"}})
    s.incident({"id": "INC-1", "severity": "error", "title": "t", "status": "open", "hosts": ["h"], "anomaly_count": 2}, "created")
    assert len(s.q) == 3 and "externalId=a2" in s.q[1] and "|10|" in s.q[1] and "incident:created" in s.q[2]
    assert s.status()["queued"] == 3 and s.status()["enabled"]
    off = siem.Siem({"enabled": False}, "2.1.0")
    off.audit("auth.login", "a", "", "", "", "ok", None)
    assert len(off.q) == 0
    # 감사 로그 싱크·알림 훅 연결
    st = _store()
    au = AuditLog(st)
    au.sink = s.audit
    asyncio.run(au.log("user.create", user="root", target="bob"))
    assert any("audit:user.create" in x and "suser=root" in x for x in s.q)
    # UDP 전송(로컬 포트 — 수신 없음이어도 send 성공)
    asyncio.run(s._send(s.q[0]))
    assert s.stats["connected"]
    s._close()


def test_alerter_pagerduty_opsgenie_payloads():
    from app.alerting import Alerter
    sent = []

    class H:
        async def post(self, url, json=None, headers=None):
            sent.append((url, json, headers or {}))
            return NS(status_code=202, text="")
    al = Alerter({"webhooks": []}, lambda *a: None, lambda *a: None)
    al.http = H()
    a = {"id": "an1", "severity": "critical", "title": "t", "category": "storage", "count": 3, "incident_id": "INC-1", "event": {"host": "esx01", "source": "esxi", "connector": "vc"}}
    asyncio.run(al._webhook({"format": "pagerduty", "secret": "RK"}, a, "[CRITICAL] t", "body"))
    url, pl, _ = sent[-1]
    assert url.endswith("/v2/enqueue") and pl["routing_key"] == "RK" and pl["dedup_key"] == "aiops-an1" and pl["payload"]["severity"] == "critical" and pl["payload"]["source"] == "esx01"
    asyncio.run(al._webhook({"format": "opsgenie", "secret": "GK"}, {**a, "severity": "warning"}, "[WARNING] t", "body"))
    url, pl, hd = sent[-1]
    assert url.endswith("/v2/alerts") and hd["Authorization"] == "GenieKey GK" and pl["alias"] == "aiops-an1" and pl["priority"] == "P3"
    try:
        asyncio.run(al._webhook({"format": "pagerduty"}, a, "t", "b"))
        raise AssertionError("키 없으면 실패")
    except RuntimeError:
        pass
    asyncio.run(al._webhook({"format": "slack", "url": "http://x"}, a, "t", "b"))
    assert sent[-1][0] == "http://x" and "text" in sent[-1][1]


# ---------------------------------------------------------------- 경영진 요약
def test_executive_summary_aggregates():
    from app import billing, capacity, noc
    from tests.test_v112 import _env
    e = _env()
    e.store = _store()
    e.billing = billing.Billing(e, {})
    e.capacity = capacity.Capacity(e, {})
    e.siem = siem.Siem({"enabled": False}, "2.1.0")

    class Inc:
        async def metrics(self, a, b):
            return {"total": 2, "by_severity": {"critical": 1}, "mtta_min": 5, "mttr_min": 30, "resolved": 1, "sla_breaches": 0, "maintenance": 0, "active": 1}

    class As:
        async def latest(self):
            return {"summary": {"ts": time.time(), "score": 88.5, "counts": {"PASS": 10, "FAIL": 1, "WARN": 2}, "cve": {"vulnerable": 1}, "hosts": 1, "versions": []}}
    e.incidents, e.assess = Inc(), As()
    e.collection = NS(summary=lambda: {"summary": {"ok": 1}, "problems": 0, "total": 1})
    e.ai_state = lambda: {"on": False}
    e.stats = {"eps": 3}
    e.alerter = NS(sent_total=4, outbox_status=lambda: {"pending": 0, "dead": 0})
    e.store.schema("CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT, created REAL, assignee TEXT)")
    asyncio.run(e.store.x("INSERT INTO incidents VALUES('INC-1','disk','critical','open',?,NULL)", (time.time() - 100,)))
    d = asyncio.run(noc.executive(e, {}))
    assert d["incidents"]["total"] == 2 and d["incidents"]["daily"][-1] == 1 and d["incidents"]["open"][0]["id"] == "INC-1"
    assert d["availability"]["hosts"] == 1 and d["availability"]["host_pct"] == 100.0 and d["vsan"]["clusters"] == 1
    assert d["assessment"]["score"] == 88.5 and d["billing"]["label"] and "summary" in d["capacity"] and d["siem"]["enabled"] is False
    assert asyncio.run(noc.executive(e, {})) is d                                      # 60초 캐시
