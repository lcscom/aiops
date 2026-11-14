"""2.22.0 보안 상태 점검·Cloudflare Access 원본 JWT 검증·머리글 강화"""
import asyncio
import base64
import json
import re
import subprocess
import time
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.responses import Response

ROOT = Path(__file__).resolve().parents[1]
TEAM, AUD = "myteam.cloudflareaccess.com", "ab12cd34" * 8


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture(scope="module")
def keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pn = k.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "k1", "alg": "RS256", "n": _b64u(pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")),
           "e": _b64u(pn.e.to_bytes(3, "big"))}
    return k, jwk


def _jwt(key, claims, alg="RS256", kid="k1"):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    h = _b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    p = _b64u(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64u(sig)}"


def _claims(**kw):
    now = time.time()
    c = {"iss": f"https://{TEAM}", "aud": [AUD], "exp": now + 600, "iat": now, "nbf": now - 5, "email": "jane@broadcom.com"}
    c.update(kw)
    return c


def _cfa(jwk, enforce=True):
    from app.security.cfaccess import CfAccess
    c = CfAccess({"team_domain": f"https://{TEAM}/", "aud": AUD, "enforce": enforce})
    c._jwks, c._fetched = [jwk], time.time()
    return c


def test_cfaccess_verify(keypair):
    key, jwk = keypair
    c = _cfa(jwk)
    assert c.enabled and c.team == TEAM and c.issuer == f"https://{TEAM}"
    ok, why, cl = asyncio.run(c.check({"cf-access-jwt-assertion": _jwt(key, _claims())}, {}))
    assert ok and cl["email"] == "jane@broadcom.com"
    ok, _, _ = asyncio.run(c.check({}, {"CF_Authorization": _jwt(key, _claims())}))          # 쿠키도 허용
    assert ok
    bad = [_claims(aud=["other"]), _claims(iss="https://evil.cloudflareaccess.com"), _claims(exp=time.time() - 120), _claims(nbf=time.time() + 600)]
    for cl in bad:
        ok, why, _ = asyncio.run(c.check({"cf-access-jwt-assertion": _jwt(key, cl)}, {}))
        assert not ok, cl
    from cryptography.hazmat.primitives.asymmetric import rsa
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c._fetched = time.time()                                    # 강제 갱신은 1분 제한 → 그대로 실패
    ok, _, _ = asyncio.run(c.check({"cf-access-jwt-assertion": _jwt(other, _claims())}, {}))
    assert not ok
    none_tok = _b64u(json.dumps({"alg": "none"}).encode()) + "." + _b64u(json.dumps(_claims()).encode()) + "."
    assert not asyncio.run(c.check({"cf-access-jwt-assertion": none_tok}, {}))[0]
    assert not asyncio.run(c.check({}, {}))[0]
    s = c.snapshot()
    assert s["ok"] == 2 and s["missing"] == 1 and s["invalid"] >= 5


def _req(path, host, headers=()):
    return Request({"type": "http", "method": "GET", "path": path, "query_string": b"",
                    "headers": [(b"host", host.encode()), *[(k.encode(), v.encode()) for k, v in headers]],
                    "client": ("127.0.0.1", 1), "server": ("t", 443), "scheme": "https", "root_path": ""})


def test_external_guard_access(monkeypatch, keypair):
    import app.main as M
    key, jwk = keypair

    async def nxt(req):
        return Response("ok")
    monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.krvcf.com"})
    monkeypatch.setattr(M, "CFA", _cfa(jwk))
    run = lambda p, h, hd=(): asyncio.run(M.external_guard(_req(p, h, hd), nxt))  # noqa: E731
    r = run("/", "aiops.krvcf.com")
    assert r.status_code == 403 and r.headers["x-robots-tag"].startswith("noindex")
    r = run("/", "aiops.krvcf.com", [("cf-access-jwt-assertion", _jwt(key, _claims()))])
    assert r.status_code == 200 and r.headers["x-robots-tag"].startswith("noindex")
    assert run("/metrics", "aiops.krvcf.com", [("cf-access-jwt-assertion", _jwt(key, _claims()))]).status_code == 404   # 토큰 있어도 내부 경로 차단
    assert run("/", "aiops.vcf.lab").status_code == 200                                 # 내부 이름은 검증 없음
    monkeypatch.setattr(M, "CFA", _cfa(jwk, enforce=False))
    assert run("/", "aiops.krvcf.com").status_code == 200                               # 검증만 모드


def test_headers_robots_healthz(monkeypatch):
    from fastapi.testclient import TestClient

    import app.main as M
    with TestClient(M.app) as cl:
        r = cl.get("/robots.txt")
        assert r.status_code == 200 and "Disallow: /" in r.text
        r = cl.get("/login")
        assert r.headers["cross-origin-opener-policy"] == "same-origin" and r.headers["cross-origin-resource-policy"] == "same-origin"
        assert "server" not in {k.lower() for k in r.headers if k.lower() == "server" and r.headers[k].startswith("uvicorn")}
        assert "uptime" in cl.get("/healthz").json()
        monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.krvcf.com"})
        monkeypatch.setattr(M, "CFA", type(M.CFA)(None))
        assert cl.get("/healthz", headers={"host": "aiops.krvcf.com"}).json() == {"ok": True}


def test_posture_run_and_regression(monkeypatch, keypair):
    import app.main as M
    _, jwk = keypair
    P = M.POSTURE
    ev = []
    monkeypatch.setattr(P.e, "submit", lambda e: ev.append(e))
    monkeypatch.setattr(P, "external_probe", False)
    hosts = {"aiops.krvcf.com"}
    monkeypatch.setattr(M, "_EXT_HOSTS", hosts)
    monkeypatch.setattr(P, "ext_hosts", hosts)
    c = _cfa(jwk)
    monkeypatch.setattr(M, "CFA", c)
    monkeypatch.setattr(P, "cfa", c)
    monkeypatch.setattr(P, "last", None)

    async def go():
        await P.e.store.x("DELETE FROM posture_runs")
        r1 = await P.run("test")
        by = {i["id"]: i for i in r1["items"]}
        assert by["cf_access_config"]["status"] == "pass" and by["cf_access_enforce"]["status"] == "pass"
        assert by["ext_block_paths"]["status"] == "pass", by["ext_block_paths"]
        assert by["ext_no_token_denied"]["status"] == "pass", by["ext_no_token_denied"]
        assert by["web_headers"]["status"] == "pass" and by["login_leak"]["status"] == "pass"
        assert by["trusted_proxies"]["status"] == "pass"
        assert 0 <= r1["score"] <= 100 and r1["grade"] in "ABCD"
        assert ev == [] and r1["new"] == []                                    # 첫 점검 = 기준선(알림·'새로' 없음)
        monkeypatch.setitem(P.e.cfg["server"], "trusted_proxies", "*")        # 설정 약화 → 새 실패
        r2 = await P.run("test")
        assert "trusted_proxies" in r2["new"] and r2["score"] < r1["score"]
        assert any(e.entity == "posture:trusted_proxies" and e.kind == "security" and e.severity == "error" for e in ev)
        monkeypatch.setitem(P.e.cfg["server"], "trusted_proxies", "127.0.0.1")
        ev.clear()
        r3 = await P.run("test")
        assert {"id": "trusted_proxies", "title": "신뢰 프록시 범위"} in r3["fixed"]
        assert any(e.attrs.get("recovered") and e.entity == "posture:trusted_proxies" for e in ev)
        h = await P.history(1)
        assert len(h) == 3 and h[-1]["score"] == r3["score"]
        monkeypatch.setattr(P, "ignore", {"trusted_proxies"})
        monkeypatch.setitem(P.e.cfg["server"], "trusted_proxies", "*")
        r4 = await P.run("test")
        assert next(i for i in r4["items"] if i["id"] == "trusted_proxies")["status"] == "na"      # 예외 처리(ignore)
    asyncio.run(go())


def test_posture_api_rbac():
    from app.security.auth import ROUTE_RULES
    import re as _re

    def perm(m, p):
        for mm, rx, pr in ROUTE_RULES:
            if (mm == "*" or mm == m) and _re.search(rx, p):
                return pr
    assert perm("GET", "/api/posture") == "audit.view" and perm("GET", "/api/posture.csv") == "audit.view"
    assert perm("POST", "/api/posture/run") == "settings"


def test_helpers():
    from app.posture import grade, parse_cfd_version, score_of
    assert parse_cfd_version("cloudflared version 2025.8.1 (built 2025-08-21-1234 UTC)") == (2025, 8)
    assert parse_cfd_version("garbage") is None
    items = [{"sev": "high", "status": "fail"}, {"sev": "medium", "status": "warn"}, {"sev": "low", "status": "pass"}]
    assert score_of(items) == 100 - 15 - 3 and grade(82) == "B" and grade(95) == "A" and grade(10) == "D"


def test_ui_wiring():
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="nav-sp"' in html and 'id="drawer-sp"' in html and "/static/posture.js" in html
    assert html.index("/static/posture.js") < html.index("/static/layout.js")
    ng = (ROOT / "app/static/navgroup.js").read_text(encoding="utf-8")
    assert re.search(r'"g-sys".*"sp"[,\]]', ng)                              # 2.30.0 — 뒤에 "mobile" 추가
    assert subprocess.run(["node", "-e", f"new Function(require('fs').readFileSync('{ROOT / 'app/static/posture.js'}','utf8'))"]).returncode == 0
    en = (ROOT / "app/static/i18n-en.js").read_text(encoding="utf-8")
    for k in ("보안 점검", "보안 점수", "지금 점검", "Cloudflare Access 원본 검증(JWT)"):
        assert f'"{k}":' in en


def test_tunnel_script_writes_cf_access(tmp_path):
    s = (ROOT / "scripts/linux/cloudflare-tunnel.sh").read_text(encoding="utf-8")
    ed = tmp_path / "ed.py"
    ed.write_text(re.findall(r"<<'PY'\n(.*?)\nPY\n", s, re.S)[1], encoding="utf-8")
    cfg = tmp_path / "config.yaml"
    cfg.write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    acc = tmp_path / "access.json"
    acc.write_text(json.dumps({"team_domain": TEAM, "aud": AUD}), encoding="utf-8")
    import yaml
    for _ in range(2):
        subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com", str(acc)], check=True, capture_output=True)
        d = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        assert d["server"]["cf_access"] == {"team_domain": TEAM, "aud": AUD, "enforce": True}
        assert d["server"]["external_hosts"] == ["aiops.krvcf.com"]
    acc.write_text(json.dumps({"team_domain": "x;rm -rf /", "aud": AUD}), encoding="utf-8")       # 이상한 값은 기록하지 않음
    cfg.write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com", str(acc)], check=True, capture_output=True)
    assert "cf_access" not in yaml.safe_load(cfg.read_text(encoding="utf-8"))["server"]


def test_ws_origin_and_access(monkeypatch, keypair):
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    import app.main as M
    _, jwk = keypair
    with TestClient(M.app) as cl:
        with pytest.raises(WebSocketDisconnect) as ex:
            with cl.websocket_connect("/ws", headers={"origin": "https://evil.example", "host": "testserver"}) as w:
                w.receive_text()
        assert ex.value.code == 4403                                           # 교차 출처 WebSocket 차단
        monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.krvcf.com"})
        monkeypatch.setattr(M, "CFA", _cfa(jwk))
        with pytest.raises(WebSocketDisconnect) as ex:
            with cl.websocket_connect("/ws", headers={"host": "aiops.krvcf.com.", "origin": "https://aiops.krvcf.com"}) as w:
                w.receive_text()
        assert ex.value.code == 4403                                           # 외부 이름(끝 점 포함)은 Access 토큰 필요


def test_host_name_trailing_dot(monkeypatch):
    import app.main as M

    async def nxt(req):
        return Response("ok")
    monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.krvcf.com"})
    assert asyncio.run(M.external_guard(_req("/metrics", "aiops.krvcf.com."), nxt)).status_code == 404


def test_tunnel_script_block_yaml(tmp_path):
    """블록형 cf_access·external_hosts 가 있어도 YAML 이 깨지지 않고, 사용자가 둔 enforce: false 는 유지"""
    import os
    s = (ROOT / "scripts/linux/cloudflare-tunnel.sh").read_text(encoding="utf-8")
    ed = tmp_path / "ed.py"
    ed.write_text(re.findall(r"<<'PY'\n(.*?)\nPY\n", s, re.S)[1], encoding="utf-8")
    cfg = tmp_path / "config.yaml"
    base = (ROOT / "config.example.yaml").read_text(encoding="utf-8").replace(
        "server:\n", "server:\n  cf_access:\n    team_domain: old.cloudflareaccess.com\n    aud: deadbeef\n    enforce: false\n"
                     "  external_hosts:\n    - old.krvcf.com\n\n    - aiops.krvcf.com\n", 1)
    cfg.write_text(base, encoding="utf-8")
    acc = tmp_path / "access.json"
    acc.write_text(json.dumps({"team_domain": TEAM, "aud": AUD, "host": "aiops.krvcf.com"}), encoding="utf-8")
    import yaml
    for env in ({}, {"CF_ENFORCE": "false"}):
        subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com", str(acc)], check=True, capture_output=True, env={**os.environ, **env})
        d = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        assert d["server"]["cf_access"] == {"team_domain": TEAM, "aud": AUD, "enforce": False}
        assert d["server"]["external_hosts"] == ["old.krvcf.com", "aiops.krvcf.com"]
    acc.write_text(json.dumps({"team_domain": "x.cloudflareaccess.com", "aud": "ff", "host": "other.krvcf.com"}), encoding="utf-8")
    subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com", str(acc)], check=True, capture_output=True)
    assert yaml.safe_load(cfg.read_text(encoding="utf-8"))["server"]["cf_access"]["team_domain"] == TEAM     # 다른 이름용 정보는 무시
    cfg.write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    acc.write_text(json.dumps({"team_domain": TEAM, "aud": AUD, "host": "aiops.krvcf.com"}), encoding="utf-8")
    subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com", str(acc)], check=True, capture_output=True, env={**os.environ, "CF_ENFORCE": "false"})
    assert yaml.safe_load(cfg.read_text(encoding="utf-8"))["server"]["cf_access"]["enforce"] is False             # 공개키 사전 확인 실패 → 검증만


def test_posture_na_carries_state(monkeypatch):
    """확인 불가(na)로 바뀐 실패 항목은 '해결'로 알리지 않고 이전 상태를 이어받음"""
    import app.main as M
    P = M.POSTURE
    ev = []
    monkeypatch.setattr(P.e, "submit", lambda e: ev.append(e))
    monkeypatch.setattr(P, "external_probe", False)
    monkeypatch.setattr(P, "last", None)

    async def go():
        await P.e.store.x("DELETE FROM posture_runs")
        await P.run("t")
        monkeypatch.setitem(P.e.cfg["server"], "trusted_proxies", "*")
        await P.run("t")
        ev.clear()

        async def boom():
            raise RuntimeError("x")
        monkeypatch.setattr(P, "_external", boom)                    # 그 분류 점검 오류 → na
        r = await P.run("t")
        assert r["fixed"] == [] and not any(e.attrs.get("recovered") for e in ev)
        assert r["bad_ids"].get("trusted_proxies") == "fail"
        monkeypatch.undo()
    asyncio.run(go())


def test_csv_cell():
    from app.main import csv_cell
    assert csv_cell("=1+1") == "'=1+1" and csv_cell("-x") == "'-x" and csv_cell("@a") == "'@a" and csv_cell("ok") == "ok"


def test_cfaccess_no_stampede(keypair):
    """공개키 조회가 실패해도 요청마다 재조회하지 않음 — 1분에 한 번, 그동안 캐시 키로 검증"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    key, jwk = keypair
    c = _cfa(jwk)
    calls = []

    async def bad_fetch():
        calls.append(1)
        await asyncio.sleep(0)
        raise OSError("down")
    c._fetch = bad_fetch
    c._fetched = time.time() - 7200                          # 캐시 만료(1시간 초과)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    async def go():
        oks = 0
        for i in range(10):
            ok, _, _ = await c.check({"cf-access-jwt-assertion": _jwt(key if i % 2 else other, _claims())}, {})
            oks += ok
            await asyncio.sleep(0)
        await asyncio.sleep(0.01)
        return oks
    assert asyncio.run(go()) == 5 and len(calls) <= 1          # 정상 토큰은 캐시 키로 계속 통과
    c2 = _cfa(jwk)
    c2._fetch = bad_fetch
    calls.clear()
    async def burst():
        return await asyncio.gather(*[c2.check({"cf-access-jwt-assertion": _jwt(other, _claims(), kid="zzz")}, {}) for _ in range(10)])
    asyncio.run(burst())
    assert len(calls) <= 1                                       # 모르는 kid 폭주도 1회


def test_edge_gate_classification(monkeypatch):
    import httpx

    import app.main as M
    P = M.POSTURE

    def mk(status, headers=None, text=""):
        class C:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url): return httpx.Response(status, headers=headers or {}, text=text, request=httpx.Request("GET", url))
        return C
    cases = [(mk(302, {"location": "https://t.cloudflareaccess.com/cdn-cgi/access/login/x", "cf-ray": "1"}), True, False),
             (mk(403, {"x-robots-tag": "noindex", "cf-ray": "1"}, '{"detail":"x","code":"cf_access"}'), False, True),
             (mk(200, {"cf-ray": "1"}, "<html>login"), False, False)]
    for cls, gate, origin in cases:
        monkeypatch.setattr(httpx, "AsyncClient", cls)
        monkeypatch.setattr("app.posture.socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        r = asyncio.run(P._edge("aiops.krvcf.com"))
        assert r["gate"] is gate and r["origin_blocked"] is origin, r
