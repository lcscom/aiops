"""2.49.0 — 외부 공개 로그인 보호: 계정+IP 잠금, 계정 대입 IP 차단, 세션 국가 고정, 새 위치 알림, 공개 표면 점검"""
import asyncio
import os
import tempfile
import time
from pathlib import Path

from fastapi import HTTPException

from app.security.audit import AuditLog
from app.security.auth import AuthManager, PUBLIC
from app.security.guard import REQ_EDGE, LoginGuard, loc_key
from app.store import Store

ROOT = Path(__file__).resolve().parents[1]
PW = "Boot#Pass2026xyz"


def _mgr(cfg=None):
    d = tempfile.mkdtemp()
    st = Store(os.path.join(d, "a.db"))
    os.environ["AIOPS_ADMIN_PASSWORD"] = PW
    m = AuthManager(st, {"enabled": True, "password": {}, "lockout_threshold": 3, "lockout_minutes": 30,
                         "rate_limit_per_5min": 1000, "guard": cfg or {}}, AuditLog(st), d)
    asyncio.run(m.bootstrap())
    os.environ.pop("AIOPS_ADMIN_PASSWORD", None)
    events = []
    m.guard.notify = lambda sev, msg, ent, attrs: events.append((sev, attrs.get("rule"), msg))
    return m, events


async def _try(m, user, pw, ip, ext=True, country=""):
    REQ_EDGE.set({"external": ext, "country": country, "ip": ip})
    try:
        return await m.login(user, pw, ip, "ua")
    except HTTPException as e:
        return e.status_code


def test_external_failures_do_not_lock_account_for_everyone():
    m, ev = _mgr()

    async def go():
        for _ in range(3):
            assert await _try(m, "admin", "wrong", "198.51.100.7") == 401
        assert await _try(m, "admin", PW, "198.51.100.7") == 423            # 공격 IP 는 잠김
        r = await _try(m, "admin", PW, "10.0.0.5", ext=False)                 # 내부망 관리자는 그대로 로그인
        assert isinstance(r, dict) and r.get("sid")
        r = await _try(m, "admin", PW, "203.0.113.9")                         # 다른 외부 IP 도 로그인 가능
        assert isinstance(r, dict) and r.get("sid")
        u = await m.store.q1("SELECT locked_until, failed FROM users WHERE username='admin'")
        assert not u["locked_until"]
    asyncio.run(go())
    assert m.guard.snapshot()["locked_pairs"][0]["ip"] == "198.51.100.7"


def test_internal_failures_keep_account_lock():
    m, _ = _mgr()

    async def go():
        for _ in range(3):
            await _try(m, "admin", "wrong", "10.0.0.9", ext=False)
        return await _try(m, "admin", PW, "10.0.0.10", ext=False)
    assert asyncio.run(go()) == 423


def test_distributed_failures_hit_account_cap():
    m, ev = _mgr({"external_account_cap": 4, "stuffing_users": 0})

    async def go():
        for i in range(4):
            await _try(m, "admin", "wrong", f"198.51.100.{i + 1}")
        return await _try(m, "admin", PW, "203.0.113.50")
    assert asyncio.run(go()) == 423
    assert any(r == "external_account_cap" for _, r, _ in ev)


def test_credential_stuffing_blocks_ip_and_unblock():
    m, ev = _mgr({"stuffing_users": 3})

    async def go():
        for u in ("alice", "bob", "carol"):
            await _try(m, u, "x", "192.0.2.66")
        blocked = await _try(m, "admin", PW, "192.0.2.66")                   # 맞는 비밀번호여도 차단 중
        m.guard.unblock(ip="192.0.2.66")
        ok = await _try(m, "admin", PW, "192.0.2.66")
        return blocked, ok
    blocked, ok = asyncio.run(go())
    assert blocked == 429 and isinstance(ok, dict)
    assert ("error", "stuffing") == ev[0][:2]


def test_nonexistent_and_existing_accounts_same_external_response():
    m, _ = _mgr({"stuffing_users": 0})

    async def go():
        a = [await _try(m, "admin", "wrong", "198.51.100.20") for _ in range(4)]
        b = [await _try(m, "ghostuser", "wrong", "198.51.100.21") for _ in range(4)]
        return a, b
    a, b = asyncio.run(go())
    assert a == b == [401, 401, 401, 423]


class _Req:
    def __init__(self, sid, ip):
        self.cookies = {"aiops_sid": sid}
        self.client = type("C", (), {"host": ip})()


def test_session_country_change_revokes():
    m, ev = _mgr()

    async def go():
        r = await _try(m, "admin", PW, "198.51.100.30", country="KR")
        await asyncio.sleep(0.05)
        return r["sid"]
    sid = asyncio.run(go())
    assert m.sessions[sid]["country"] == "KR"

    async def check():
        REQ_EDGE.set({"external": True, "country": "KR"})
        assert m.session(_Req(sid, "198.51.100.31")) is not None              # 같은 국가 IP 변경 → 유지(기록만)
        assert m.sessions[sid]["ips"] == ["198.51.100.31"]
        REQ_EDGE.set({"external": True, "country": "NL"})
        assert m.session(_Req(sid, "185.0.0.1")) is None and sid not in m.sessions
        await asyncio.sleep(0.05)
    asyncio.run(check())
    assert ev[-1][0] == "critical" and ev[-1][1] == "session_country"


def test_new_location_alert():
    m, ev = _mgr()

    async def go():
        await _try(m, "admin", PW, "198.51.100.40", country="KR")           # 첫 로그인 = 기준
        await _try(m, "admin", PW, "198.51.100.41", country="KR")
        await _try(m, "admin", PW, "45.1.2.3", country="US")
        await asyncio.sleep(0.05)
    asyncio.run(go())
    news = [e for e in ev if e[1] == "new_location"]
    assert len(news) == 1 and "US" in news[0][2] and news[0][0] == "error"   # 관리자는 error


def test_loc_key():
    assert loc_key("1.2.3.4", "kr") == "CC:KR"
    assert loc_key("1.2.3.4", "XX") == "IP:1.2.3.0/24"
    assert loc_key("2001:db8:1:2::5", "") == "IP:2001:db8:1::/48"
    assert loc_key("127.0.0.1") == "IP:local"


def test_guard_memory_bounded():
    g = LoginGuard({"stuffing_users": 0})
    for i in range(6000):
        g.external_fail(f"u{i}", f"10.{i // 256 % 256}.{i % 256}.1", 99, 1)
    g.pairs = {k: [[time.time() - 7200], 0.0] for k in g.pairs}
    g.external_fail("x", "1.1.1.1", 99, 1)
    assert len(g.pairs) < 10


def test_security_txt_public_only_when_configured():
    assert PUBLIC.match("/.well-known/security.txt")
    src = (ROOT / "app/main.py").read_text(encoding="utf-8")
    assert "Contact: {c}" in src and "Expires: {exp}" in src and 'security_contact' in src


def test_public_surface_scan_clean():
    from app.main import app, PROBE_TOKEN
    from app.security import surface
    r = asyncio.run(surface.scan(app, PROBE_TOKEN))
    assert r["checked"] > 150 and r["errors"] == []
    assert r["open"] == [], r["open"]


def test_edge_header_counts_as_external():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        assert c.get("/readyz", headers={"cf-ray": "x"}).json() == {"ready": True}
        assert set(c.get("/healthz", headers={"cf-ray": "x"}).json()) == {"ok"}
        assert c.get("/metrics", headers={"cf-ray": "x"}).status_code == 404     # 연동 경로는 외부에서 차단
        assert "node" in c.get("/readyz").json()


def test_ui_and_posture_wired():
    js = (ROOT / "app/static/enterprise.js").read_text(encoding="utf-8")
    assert "/api/users/guard" in js and "data-gub-ip" in js and "guardHtml(guard)" in js
    p = (ROOT / "app/posture.py").read_text(encoding="utf-8")
    assert '"public_surface"' in p and '"login_guard"' in p


def test_loopback_never_ip_blocked_and_cf_ip_used():
    g = LoginGuard({"stuffing_users": 2})
    for u in ("a", "b", "c"):
        g.external_fail(u, "127.0.0.1", 99, 1)
    assert not g.blocked
    from app.security.auth import edge_ip

    class R:
        headers = {"cf-connecting-ip": "198.51.100.77"}
        client = type("C", (), {"host": "127.0.0.1"})()
    assert edge_ip(R()) == "198.51.100.77"
    R.client.host = "10.1.1.1"
    assert edge_ip(R()) == "10.1.1.1"                                          # 프록시 설정이 맞으면 그대로
