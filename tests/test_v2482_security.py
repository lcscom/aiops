"""2.48.2 — 외부 점검 지적 반영: 로그인 전 공개 사전 축소, 평문 HTTP→HTTPS, SSO MFA 토큰 URL 제거"""
import asyncio
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def test_full_dictionary_not_public():
    from app.security.auth import PUBLIC
    assert not PUBLIC.match("/static/i18n-en.js")
    assert PUBLIC.match("/static/i18n-login.js") and PUBLIC.match("/static/i18n.js") and PUBLIC.match("/static/login.js")
    html = (S / "login.html").read_text(encoding="utf-8")
    assert "/static/i18n-login.js" in html and "i18n-en.js" not in html
    for f in ("index.html", "noc.html", "nocwall.html"):          # 로그인 뒤 화면은 전체 사전 그대로
        assert "/static/i18n-en.js" in (S / f).read_text(encoding="utf-8")


def test_login_dictionary_small_and_clean():
    src = (S / "i18n-login.js").read_text(encoding="utf-8")
    assert src.count('": "') < 200 and len(src) < 20_000
    for bad in ("vcf-aiopsctl", "sudo ", "/etc/", "/api/", "ClusterRole", "너는 ", "SRE"):
        assert bad not in src, bad
    assert '"비밀번호": "Password"' in src and '"2단계 인증": "Two-factor authentication"' in src
    import importlib.util
    spec = importlib.util.spec_from_file_location("b", ROOT / "scripts/dev/build-login-i18n.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    assert m.render(m.build()) == src                             # 사전·로그인 문구를 바꾸면 다시 생성해야 함


def test_reset_admin_hint_removed_from_ui():
    for f in S.glob("*.js"):
        assert "reset-admin" not in f.read_text(encoding="utf-8"), f.name
    assert "reset-admin" not in (S / "login.html").read_text(encoding="utf-8")


def test_oidc_mfa_token_not_in_url():
    o = (ROOT / "app/security/oidc.py").read_text(encoding="utf-8")
    assert "?mfa={" not in o and "mfa_token']}&" not in o
    assert 'resp.set_cookie(MFA_COOKIE, res["mfa_token"], httponly=True' in o and 'path="/api/auth/mfa"' in o
    a = (ROOT / "app/security/auth.py").read_text(encoding="utf-8")
    assert 'request.cookies.get("aiops_mfa")' in a and 'resp.delete_cookie("aiops_mfa", path="/api/auth/mfa")' in a
    j = (S / "login.js").read_text(encoding="utf-8")
    assert 'qs.get("mfa") === "1"' in j and 'mfaTok = qs.get("mfa")' not in j and "history.replaceState" in j


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_https_redirect_behaviour():
    with _client() as c:
        r = c.get("/login", headers={"cf-visitor": '{"scheme":"http"}', "host": "aiops.example.com"}, follow_redirects=False)
        assert r.status_code == 301 and r.headers["location"] == "https://aiops.example.com/login"
        r = c.get("/login?next=%2Fx", headers={"cf-visitor": '{"scheme":"http"}', "host": "aiops.example.com:80"}, follow_redirects=False)
        assert r.headers["location"] == "https://aiops.example.com/login?next=%2Fx"
        r = c.post("/api/auth/login", headers={"cf-visitor": '{"scheme":"http"}', "host": "aiops.example.com"}, json={}, follow_redirects=False)
        assert r.status_code == 308
        assert c.get("/healthz", headers={"cf-visitor": '{"scheme":"http"}'}, follow_redirects=False).status_code == 200
        assert c.get("/login", headers={"cf-visitor": '{"scheme":"https"}'}, follow_redirects=False).status_code == 200
        assert c.get("/login", follow_redirects=False).status_code == 200            # 앞단 없는 내부 직접 접속은 그대로
        r = c.get("/login", headers={"cf-visitor": '{"scheme":"http"}', "host": "bad host\\x"}, follow_redirects=False)
        assert r.status_code != 301


def test_static_dictionary_requires_login_when_auth_on():
    from app.main import AUTH
    if not AUTH.enabled:
        return
    with _client() as c:
        assert c.get("/static/i18n-en.js", follow_redirects=False).status_code in (302, 307)
        assert c.get("/static/i18n-login.js", follow_redirects=False).status_code == 200


def test_posture_has_new_checks():
    p = (ROOT / "app/posture.py").read_text(encoding="utf-8")
    for k in ('"static_public"', '"https_redirect"', 'f"edge_http:{host}"', '"ClusterRole"'):
        assert k in p
