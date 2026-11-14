"""2.30.0 보안 수정 — 읽기 토큰 RBAC, 잠금·계정 추측·MFA 무차별 대입, 청크 본문 상한, 외부 LLM 가명화 누락, 비밀 마스킹(헤더·웹훅 URL),
모니터 정규식(ReDoS·최신 행 우선), MFA 재등록 재인증·비밀번호 변경 시 다른 세션 종료, 경로 불일치(400), OIDC 계정 덮어쓰기,
CSV 수식 주입, 로그인 next 검사, 지식 업로드 삭제 경로, 연결 시험의 저장 비밀 전송 대상 검사"""
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
PW = "Xk9!mQ2#vLp7"


def _req(path, method="GET", headers=None, receive=None):
    scope = {"type": "http", "method": method, "path": path, "query_string": b"", "client": ("10.0.0.9", 1), "server": ("t", 80), "scheme": "http",
             "root_path": "", "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
    return Request(scope, receive) if receive else Request(scope)


async def _ok(req):
    return Response("ok")


@pytest.fixture
def fast(monkeypatch):
    """PBKDF2 반복 수·지연을 줄여 인증 테스트를 빠르게"""
    from app.security import auth as A
    from app.security import passwords as P
    _sleep = asyncio.sleep
    monkeypatch.setattr(A.asyncio, "sleep", lambda *_: _sleep(0))
    monkeypatch.setattr(A, "hash_password", lambda pw: P.hash_password(pw, 1000))
    monkeypatch.setattr(A, "_DUMMY_HASH", "")
    return A


def _mgr(A, tmp_path, cfg=None, sub="a"):
    (tmp_path / sub).mkdir(exist_ok=True)
    e = _engine(tmp_path / sub)
    return e, A.AuthManager(e.store, {"enabled": True, **(cfg or {})}, e.audit, tmp_path)


# ---------------------------------------------------------------- 1. 읽기 토큰 RBAC
def test_read_token_rbac(tmp_path, fast):
    async def main():
        e, m = _mgr(fast, tmp_path)
        raw = await m.create_token("ro", ["read"], 1, "admin")
        mw = m.middleware()
        run = lambda p, method="GET": mw(_req(p, method, {"authorization": f"Bearer {raw}"}), _ok)  # noqa: E731
        for p in ("/api/incidents", "/api/anomalies", "/api/vm/moves", "/api/system/version", "/api/monitors", "/api/knowledge/search"):
            assert (await run(p)).status_code == 200, p
        for p in ("/api/audit", "/api/audit/export", "/api/posture", "/api/users", "/api/tokens", "/api/settings/connectors", "/api/forwarding",
                  "/api/license/reveal/keys", "/api/backup", "/api/system/selfcheck", "/api/maintenance"):
            r = await run(p)
            assert r.status_code == 403 and json.loads(r.body)["code"] == "forbidden", p
        assert (await run("/api/incidents", "POST")).status_code == 401          # 읽기 토큰은 GET 만
        await asyncio.sleep(0.05)
        assert any(r["result"] == "denied" and r["user"] == "token:ro" for r in await e.audit.query(0, 2e10, action="auth.denied"))
    asyncio.run(main())


# ---------------------------------------------------------------- 2. 잠금·계정 추측·MFA
def test_lockout_reset_and_no_enumeration(tmp_path, fast):
    async def main():
        e, m = _mgr(fast, tmp_path, {"lockout_threshold": 3, "rate_limit_per_5min": 1000})
        await m._upsert_local("bob", "Bob", "viewer", PW, must_change=False)

        async def attempt(u, pw="wrong"):
            try:
                return 200, (await m.login(u, pw, "10.0.0.9", "t")).get("user")
            except HTTPException as ex:
                return ex.status_code, ex.detail
        seq_known = [await attempt("bob") for _ in range(4)]
        seq_ghost = [await attempt("nobody") for _ in range(4)]
        assert seq_known == seq_ghost                                              # 없는 계정도 같은 응답(실패 → 잠금 → 423)
        assert [s for s, _ in seq_known] == [401, 401, 401, 423]
        assert not await e.store.q1("SELECT 1 FROM users WHERE username='nobody'")
        # 잠금이 풀린 뒤 1회 오류로 다시 잠기지 않음(실패 횟수 초기화)
        await e.store.x("UPDATE users SET locked_until=? WHERE username='bob'", (time.time() - 1,))
        assert (await attempt("bob"))[0] == 401
        u = await e.store.q1("SELECT failed, locked_until FROM users WHERE username='bob'")
        assert u["failed"] == 1 and not u["locked_until"]
        assert (await attempt("bob", PW))[0] == 200
        # 비활성 계정: 틀린 비밀번호엔 일반 오류, 맞는 비밀번호일 때만 안내
        await e.store.x("UPDATE users SET disabled=1, failed=0 WHERE username='bob'")
        assert await attempt("bob") == (401, "아이디 또는 비밀번호가 올바르지 않습니다.")
        assert (await attempt("bob", PW))[0] == 403
    asyncio.run(main())


def test_login_username_cap_and_rate_audit_sampling(tmp_path, fast):
    async def main():
        e, m = _mgr(fast, tmp_path, {"rate_limit_per_5min": 2})
        for _ in range(45):
            with pytest.raises(HTTPException):
                await m.login("x" * 5000, "pw", "10.0.0.7", "t")
        rows = await e.audit.query(0, 2e10, action="auth.login")
        assert all(len(r["user"]) <= 64 for r in rows)
        assert sum(1 for r in rows if r["result"] == "rate_limited") == 3            # 43건 중 1·21·41번째만 기록
    asyncio.run(main())


def test_mfa_failures_lock_account(tmp_path, fast):
    async def main():
        e, m = _mgr(fast, tmp_path, {"lockout_threshold": 3, "rate_limit_per_5min": 1000})
        await m._upsert_local("carol", "Carol", "admin", PW, must_change=False)
        from app.security.mfa import totp
        en = await m.mfa.enroll("carol")
        await m.mfa.confirm("carol", totp(en["secret"]))
        codes = []
        for i in range(3):                                                         # 매번 새로 로그인해도(토큰별 5회 한도 우회) 실패가 누적
            tok = (await m.login("carol", PW, "10.0.0.9", "t"))["mfa_token"]
            with pytest.raises(HTTPException) as ex:
                await m.mfa_verify(tok, "000000" if totp(en["secret"]) != "000000" else "111111", "10.0.0.9")
            codes.append(ex.value.detail)
        assert "잠겼습니다" in codes[-1] and not m._mfa_pending
        u = await e.store.q1("SELECT failed, locked_until FROM users WHERE username='carol'")
        assert u["failed"] == 3 and u["locked_until"] > time.time()
        with pytest.raises(HTTPException) as ex:
            await m.login("carol", PW, "10.0.0.9", "t")
        assert ex.value.status_code == 423
        assert any(json.loads(r["detail"]).get("by") == "mfa" for r in await e.audit.query(0, 2e10, action="auth.lockout"))
    asyncio.run(main())


# ---------------------------------------------------------------- 3. 청크 본문 상한
def test_chunked_body_cap(monkeypatch):
    import app.main as M

    def chunks(parts):
        it = iter(parts)

        async def receive():
            try:
                b = next(it)
            except StopIteration:
                return {"type": "http.disconnect"}
            return {"type": "http.request", "body": b, "more_body": True} if b is not None else {"type": "http.request", "body": b"", "more_body": False}
        return receive
    monkeypatch.setattr(M, "_MAX_BODY", 1000)
    seen = {}

    async def nxt(req):
        seen["body"] = await req.body()
        return Response("ok")
    before = M.REQ_STATS["too_large"]
    r = asyncio.run(M.request_guard(_req("/api/chat", "POST", receive=chunks([b"x" * 400] * 5 + [None])), nxt))
    assert r.status_code == 413 and json.loads(r.body)["code"] == "too_large" and M.REQ_STATS["too_large"] == before + 1 and not seen
    r = asyncio.run(M.request_guard(_req("/api/chat", "POST", receive=chunks([b'{"a":', b"1}", None])), nxt))
    assert r.status_code == 200 and seen["body"] == b'{"a":1}'                    # 읽은 본문은 안쪽으로 그대로
    r = asyncio.run(M.request_guard(_req("/api/knowledge/upload", "PUT", receive=chunks([b"x" * 400] * 5 + [None])), nxt))
    assert r.status_code == 200                                                    # 업로드 경로는 제외(각 라우트가 직접 제한)


def test_chunked_login_end_to_end():
    from fastapi.testclient import TestClient

    import app.main as M

    def gen(n):
        yield b'{"username":"zz-nobody","password":"'
        for _ in range(n):
            yield b"a" * 1024
        yield b'"}'
    with TestClient(M.app) as cl:
        h = {"X-Requested-With": "aiops", "Content-Type": "application/json"}
        r = cl.post("/api/auth/login", content=gen(1), headers=h)                  # 청크 본문이 미들웨어를 거쳐 라우트까지 전달됨
        assert r.status_code in (401, 423, 429), r.text
        assert cl.post("/api/auth/login", content=gen(80), headers=h).status_code == 413      # 인증 전 본문은 64KB 상한
        assert cl.post("/api/auth/mfa/verify", content=gen(80), headers=h).status_code == 413


# ---------------------------------------------------------------- 4. 외부 LLM 가명화
def test_llm_external_by_host_and_verify_default():
    from app.llm import LLMClient, host_internal
    for u in ("http://127.0.0.1:8000/v1", "https://10.1.2.3/v1", "http://ollama:11434/v1", "https://pais.vcf.lab/v1", "http://[::1]:8000", "http://169.254.10.1/v1", "https://gw.corp.internal"):
        assert host_internal(u), u
    for u in ("https://api.openai.com/v1", "https://8.8.8.8/v1", "https://llm.example.co.kr/v1", ""):
        assert not host_internal(u), u
    assert host_internal("https://llm.example.co.kr/v1", ["example.co.kr"])
    c = LLMClient({"internal_suffixes": ["corp.example"], "verify_tls": False, "providers": [
        {"name": "pais", "type": "openai", "base_url": "https://pais.vcf.lab/v1"},
        {"name": "corp", "type": "openai", "base_url": "https://llm.corp.example/v1"},
        {"name": "oai", "type": "openai", "base_url": "https://api.openai.com/v1"},
        {"name": "oai-forced", "type": "openai", "base_url": "https://api.openai.com/v1", "external": False},
        {"name": "claude", "type": "anthropic", "api_key": "k"},
        {"name": "claude-gw", "type": "anthropic", "base_url": "https://10.0.0.5", "api_key": "k"},
        {"name": "ext-noverify", "type": "openai", "base_url": "https://api.openai.com/v1", "verify_tls": False}]})
    ext = {n: p.external for n, p in c.providers.items()}
    # 2.36.0 — 공용 AI 주소를 '사내'로 저장해도 외부로 보고 가명화(oai-forced)
    assert ext == {"pais": False, "corp": False, "oai": True, "oai-forced": True, "claude": True, "claude-gw": True, "ext-noverify": True}
    assert c.providers["oai-forced"].forced_external and not c.providers["oai"].forced_external
    ver = {n: p.http._transport._pool._ssl_context.verify_mode != 0 for n, p in c.providers.items()}
    assert ver == {"pais": False, "corp": False, "oai": True, "oai-forced": True, "claude": True, "claude-gw": True, "ext-noverify": False}
    legacy = LLMClient({"base_url": "https://pais.bank.example/v1", "model": "m"})            # 기존 단일 설정(local)은 그대로 사내
    assert not legacy.providers["local"].external


def test_llm_callers_pass_names(tmp_path):
    from app.kblink import KbLinker
    from app.llm import LLMClient
    sent = {}

    async def main():
        c = LLMClient({"providers": [{"name": "oai", "type": "openai", "base_url": "https://api.openai.com/v1"}]})

        async def chat(system, messages, json_mode=False, max_tokens=None):
            sent["user"] = messages[0]["content"]
            return "host NAME_1 purple screen PSOD troubleshooting"
        c.providers["oai"].chat = chat
        e = SimpleNamespace(llm=c)
        k = KbLinker.__new__(KbLinker)
        k.e, k._enq = e, {}
        out = await k.en_query("esx-prod-07 호스트 10.9.8.7 퍼플스크린 원인", names=["esx-prod-07"])
        assert "esx-prod-07" not in sent["user"] and "10.9.8.7" not in sent["user"] and "NAME_1" in sent["user"]
        assert "esx-prod-07" in out                                                # 응답에서는 복원
    asyncio.run(main())
    src = {f: (ROOT / "app" / f).read_text(encoding="utf-8") for f in ("main.py", "noc.py", "reports.py", "kblink.py")}
    assert "names=mask_names)" in src["main.py"] and "500, names=names)" in src["noc.py"]
    assert 'task="report",\n                    names=names)' in src["reports.py"] and 'task="chat", names=names)' in src["kblink.py"]


# ---------------------------------------------------------------- 5. 비밀 마스킹(헤더·웹훅 URL)
def test_secret_headers_and_webhook_urls(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_SECRET_KEY_FILE", str(tmp_path / "secret.key"))
    from app.security import secrets as S
    from app.security.audit import redact
    from app.settings_store import SettingsManager
    alerting = {"webhooks": [{"name": "slack", "format": "slack", "url": "https://hooks.slack.com/services/T0/B0/XYZSECRET", "secret": ""},
                             {"name": "sms", "format": "generic", "url": "http://192.168.0.50:8080/alert", "headers": {"X-Token": "tok123", "X-Env": "${SMS_ENV}"}}],
                "smtp": {"host": "smtp.lab", "password": "pw"}}
    itsm = {"type": "webhook", "webhook": {"url": "https://itsm.corp.local/api/incident?key=abc", "headers": {"Authorization": "Bearer zzz"}}}
    web = {"provider": "searxng", "url": "http://searx.lab:8080"}
    m = S.mask_tree(alerting)
    assert m["webhooks"][0]["url"] == S.MASK and m["webhooks"][1]["headers"] == {"X-Token": S.MASK, "X-Env": S.MASK} and m["smtp"] == {"host": "smtp.lab", "password": S.MASK}
    assert m["webhooks"][0]["name"] == "slack" and S.mask_tree(web) == web      # 웹훅이 아닌 url 은 그대로
    mi = S.mask_tree(itsm)
    assert mi["webhook"] == {"url": S.MASK, "headers": {"Authorization": S.MASK}}
    enc = S.encrypt_tree(alerting)
    blob = json.dumps(enc)
    assert "XYZSECRET" not in blob and "tok123" not in blob and enc["webhooks"][1]["headers"]["X-Env"] == "${SMS_ENV}" and S.decrypt_tree(enc) == alerting
    assert S.decrypt_tree(alerting) == alerting                                    # 평문으로 저장돼 있던 기존 값도 그대로 읽힘
    # 화면 왕복: 마스크 그대로 저장 → 기존 값 유지, 새 값은 교체, 저장된 값이 없으면 거부
    edited = json.loads(json.dumps(m))
    edited["webhooks"][1]["headers"]["X-Token"] = "newtok"
    kept = S.keep_masked(edited, alerting, "alerting")
    assert kept["webhooks"][0]["url"] == alerting["webhooks"][0]["url"] and kept["webhooks"][1]["headers"] == {"X-Token": "newtok", "X-Env": "${SMS_ENV}"}
    assert kept["smtp"]["password"] == S.MASK                                      # 이름 기준 비밀은 settings_store 가 이어서 처리
    assert S.keep_masked(mi, itsm, "itsm") == itsm
    with pytest.raises(ValueError):
        S.keep_masked({"webhooks": [{"name": "renamed", "url": S.MASK}]}, alerting, "alerting")

    async def main():
        e = _engine(tmp_path)
        cfg = {"alerting": json.loads(json.dumps(alerting))}
        sm = SettingsManager(e.store, cfg, {})
        await sm.put("alerting", alerting, "admin")
        raw = (await e.store.q1("SELECT value FROM settings WHERE key='alerting'"))["value"]
        assert "XYZSECRET" not in raw and "tok123" not in raw and '"pw"' not in raw
        shown = (await sm.get("alerting"))["value"]
        assert shown == m
        merged = await sm.put("alerting", S.keep_masked(shown, cfg["alerting"], "alerting"), "admin")
        assert merged == alerting and cfg["alerting"] == alerting
    asyncio.run(main())
    r = redact({"before": alerting, "after": itsm, "x": {"Authorization": "Bearer a", "note": "https://u:p@h.lab/x"}, "llm": {"base_url": "https://pais.lab/v1"}})
    blob = json.dumps(r)
    for s in ("XYZSECRET", "tok123", "Bearer", "key=abc", "u:p@"):
        assert s not in blob, s
    assert r["before"]["webhooks"][0]["url"] == "https://hooks.slack.com/***" and r["after"]["webhook"]["url"] == "https://itsm.corp.local/***"
    assert r["llm"]["base_url"] == "https://pais.lab/v1" and r["before"]["webhooks"][1]["url"] == "http://192.168.0.50:8080/***"


# ---------------------------------------------------------------- 6. 모니터 정규식
def test_monitor_regex_safe_recent_first(tmp_path, monkeypatch):
    import threading

    from app import monitors as M
    from app.security.auth import AuthManager
    base = {"name": "r", "type": "log", "critical": 1, "query": {"text": "(a+)+$", "regex": True}}
    with pytest.raises(ValueError):
        M.normalize(dict(base))
    with pytest.raises(ValueError):
        M.normalize({**base, "query": {"text": "a" * 101, "regex": True}})
    assert AuthManager.required_perm("POST", "/api/monitors/preview") == "operate" and AuthManager.required_perm("GET", "/api/monitors") == "view"

    async def main():
        e = _engine(tmp_path)
        now = time.time()
        rows = [(now - 500, "old boom"), (now - 400, "old boom"), (now - 30, "new boom"), (now - 20, "fine"), (now - 10, "new boom")]
        for i, (ts, msg) in enumerate(rows):
            await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (i, ts, "esxi", "c1", "error", "esx01.lab", "esx01.lab", "log", msg, 0, "", "{}"))
        await e.store.flush(5)
        m = M.normalize({**base, "window": 3600, "query": {"text": "bo+m$", "regex": True}})
        seen = []
        orig = M.asyncio.to_thread

        async def spy(fn, *a, **k):
            seen.append(getattr(fn, "__name__", ""))
            return await orig(lambda: (seen.append(threading.current_thread() is not threading.main_thread()), fn(*a, **k))[1])
        monkeypatch.setattr(M.asyncio, "to_thread", spy)
        assert (await e.monitors.values(m)) == {"*": 4.0}
        assert "scan" in seen and True in seen                                     # 정규식 훑기는 이벤트 루프 밖 스레드에서
        monkeypatch.setattr(M, "REGEX_ROW_CAP", 3)                                 # 상한에 걸리면 최신 행부터(ORDER BY ts DESC)
        assert (await e.monitors.values(m)) == {"*": 2.0}
        bad = {**m, "query": {"text": "(x+)+y", "regex": True}}                    # 저장돼 있던 위험한 정의도 실행 전에 거부
        with pytest.raises(ValueError):
            await e.monitors.values(bad)
    asyncio.run(main())


# ---------------------------------------------------------------- 7. MFA 재등록 재인증·세션
def test_mfa_reenroll_reauth_password_sessions_ws(tmp_path, fast):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.security.mfa import totp
    e, m = _mgr(fast, tmp_path, {"rate_limit_per_5min": 1000, "lockout_threshold": 50})
    app = FastAPI()
    app.middleware("http")(m.middleware())
    app.include_router(m.router())
    H = {"X-Requested-With": "aiops"}
    with TestClient(app) as a, TestClient(app) as b:
        a.portal.call(m._upsert_local, "dave", "Dave", "operator", PW, False)
        for cl in (a, b):
            assert cl.post("/api/auth/login", json={"username": "dave", "password": PW}, headers=H).status_code == 200
        en = a.post("/api/auth/mfa/enroll", headers=H)                             # 첫 등록은 그대로
        assert en.status_code == 200
        assert a.post("/api/auth/mfa/confirm", json={"code": totp(en.json()["secret"])}, headers=H).status_code == 200
        assert a.post("/api/auth/mfa/enroll", headers=H).status_code == 400        # 재등록: 재확인 없으면 거부
        assert a.post("/api/auth/mfa/enroll", json={"password": "wrong"}, headers=H).status_code == 403
        assert a.post("/api/auth/mfa/enroll", json={"code": "000000" if totp(en.json()["secret"]) != "000000" else "111111"}, headers=H).status_code == 403
        st = a.portal.call(m.mfa.status, "dave")
        assert st["enrolled"] and not a.portal.call(m.store.q1, "SELECT pending FROM mfa WHERE username='dave'")["pending"]
        r = a.post("/api/auth/mfa/enroll", json={"password": PW}, headers=H)
        assert r.status_code == 200 and r.json()["secret"] != en.json()["secret"]
        # 비밀번호 변경 → 다른 세션 종료, 현재 세션 유지
        assert b.get("/api/auth/me").status_code == 200
        new = "Zt4$wN8@hRq3"
        assert a.post("/api/auth/password", json={"old": PW, "new": new}, headers=H).status_code == 200
        assert a.get("/api/auth/me").status_code == 200 and b.get("/api/auth/me").status_code == 401
        # 비밀번호 변경·MFA 등록 전 세션은 WebSocket 불가
        sid = a.cookies.get("aiops_sid")
        ws = SimpleNamespace(headers={}, cookies={"aiops_sid": sid})
        assert m.ws_user(ws)["user"] == "dave"
        for flag in ("must_change", "must_enroll_mfa"):
            m.sessions[sid][flag] = True
            assert m.ws_user(ws) is None
            m.sessions[sid][flag] = False


# ---------------------------------------------------------------- 8. 경로 불일치
def test_bad_path_rejected(tmp_path, fast, monkeypatch):
    import app.main as M
    from app.security.auth import PUBLIC, bad_path
    evil = "/static/login.js?/../app.js"                                           # GET /static/login.js%3F/../app.js 의 라우팅 경로(디코딩됨)
    assert not PUBLIC.match(evil)        # 옛 starlette 의 url.path 는 '?' 뒤를 잘라 공개 경로로 보였음(새 버전은 %3F 로 남김) — 어느 쪽이든 아래에서 차단 확인
    del PUBLIC
    for p in (evil, "/static/../config.yaml", "/api/../metrics", "/api//users", "/static\\app.js", "/login#x", "/noc?x", "/a\x00b", "nope"):
        assert bad_path(p), p
    for p in ("/", "/login", "/static/app.js", "/api/connectors/vc#1/test", "/api/vks/a.b-c/pods", "/share/sr/" + "a" * 32, "/agents/install.sh", "/api/license/sources/vcenter:vc01"):
        assert not bad_path(p), p

    async def main():
        e, m = _mgr(fast, tmp_path)
        mw = m.middleware()
        for p in (evil, "/static/../app.js", "/api//users"):
            r = await mw(_req(p), _ok)
            assert r.status_code == 400 and json.loads(r.body)["code"] == "bad_path", p
            assert (await M.external_guard(_req(p), _ok)).status_code == 400, p
        assert (await mw(_req("/static/login.js"), _ok)).status_code == 200
        assert (await mw(_req("/static/app.js"), _ok)).status_code in (302, 307)   # 비공개 정적 파일은 로그인으로
        monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.example.com"})                # 외부 이름 차단도 라우팅 경로 기준
        assert (await M.external_guard(_req("/metrics", headers={"host": "aiops.example.com"}), _ok)).status_code == 404
        assert (await M.external_guard(_req("/login", headers={"host": "aiops.example.com"}), _ok)).status_code in (200, 403)
    asyncio.run(main())


# ---------------------------------------------------------------- 9. OIDC
def test_sso_cannot_take_over_local_account(tmp_path, fast):
    async def main():
        e, m = _mgr(fast, tmp_path)
        await m._upsert_local("admin", "로컬 관리자", "admin", PW, must_change=False)
        with pytest.raises(HTTPException) as ex:
            await m.sso_login("admin", "Evil", "e@x", "admin", "10.0.0.9", "t")
        assert ex.value.status_code == 409
        u = await e.store.q1("SELECT source, display, pw_hash FROM users WHERE username='admin'")
        assert u["source"] == "local" and u["display"] == "로컬 관리자" and u["pw_hash"]
        assert any(r["result"] == "conflict" for r in await e.audit.query(0, 2e10, action="auth.sso"))
        r1 = await m.sso_login("erin", "Erin", "e@x", "viewer", "10.0.0.9", "t")   # 새 SSO 사용자·재로그인(역할 재계산)은 그대로
        r2 = await m.sso_login("erin", "Erin", "e@x", "operator", "10.0.0.9", "t")
        assert r1["role"] == "viewer" and r2["role"] == "operator"
    asyncio.run(main())
    src = (ROOT / "app/security/oidc.py").read_text(encoding="utf-8")
    assert "<p>{_html.escape(str(e.detail))}</p>" in src and "<p>{e.detail}</p>" not in src


# ---------------------------------------------------------------- 10. CSV 수식 주입
def test_csv_formula_neutralized(tmp_path):
    import csv
    import io

    from app import logexport
    from app.security.audit import csv_cell
    assert [csv_cell(x) for x in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "ok", 5, None)] == ["'=1+1", "'+1", "'-1", "'@SUM(A1)", "'\tx", "ok", "5", ""]

    async def main():
        e = _engine(tmp_path)
        now = time.time()
        await e.audit.log("auth.login", user="=cmd|' /C calc'!A0", target="@SUM(1)", detail={"a": 1})
        rows = list(csv.reader(io.StringIO((await e.audit.export_csv(0, 2e10)).lstrip("﻿"))))
        assert rows[1][2] == "'=cmd|' /C calc'!A0" and rows[1][6] == "'@SUM(1)" and not any(c[:1] in "=+-@" for c in rows[1] if c)
        await e.store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (1, now - 60, "esxi", "c1", "error", "=HYPERLINK(\"http://x\")", "+e", "log", "-2+3 cmd", 0, "", "{}"))
        await e.store.flush(5)
        q = logexport.LogQuery(now - 3600, now)
        out = list(csv.reader(io.StringIO(b"".join([x async for x in logexport.stream(e.store, q, "csv")]).decode("utf-8-sig"))))
        assert len(out) == 2 and not any(c[:1] in "=+-@" for c in out[1] if c) and "'=HYPERLINK(\"http://x\")" in out[1]
        import zipfile
        z = zipfile.ZipFile(io.BytesIO(await logexport.build_zip(e.store, q, {})))
        allcsv = list(csv.reader(io.StringIO(z.read("logs/all.csv").decode("utf-8-sig"))))
        assert not any(c[:1] in "=+-@" for c in allcsv[1] if c)
    asyncio.run(main())


# ---------------------------------------------------------------- 11. 로그인 next
def test_login_next_same_origin_only():
    js = (ROOT / "app/static/login.js").read_text(encoding="utf-8")
    assert "new URL(n, location.origin).origin === location.origin" in js and 'n.startsWith("//")' in js and r"/[\\\u0000-\u001f]/.test(n)" in js
    src = (ROOT / "app/security/oidc.py").read_text(encoding="utf-8")
    assert 'or "\\\\" in nxt' in src


# ---------------------------------------------------------------- 12. 지식 업로드 삭제
def test_knowledge_remove_upload_confined(tmp_path):
    from app.knowledge import KnowledgeLibrary
    root = tmp_path / "kb"
    (root / "uploads" / "pack1").mkdir(parents=True)
    (root / "uploads" / "pack1" / "a.md").write_text("x")
    (root / "keep.md").write_text("keep")
    lib = SimpleNamespace(root=root)
    for bad in ("..", "upload:..", ".", "a/b", "..\\x", "", "%2e%2e", "pack1/../..", "x" * 81):
        with pytest.raises(ValueError):
            KnowledgeLibrary.remove_upload(lib, bad)
    assert (root / "keep.md").exists() and (root / "uploads" / "pack1" / "a.md").exists()
    KnowledgeLibrary.remove_upload(lib, "nope")                                    # 없는 묶음은 조용히 통과
    KnowledgeLibrary.remove_upload(lib, "upload:pack1")
    assert not (root / "uploads" / "pack1").exists() and (root / "uploads").is_dir() and (root / "keep.md").exists()


# ---------------------------------------------------------------- 13. 연결 시험 — 저장 비밀의 전송 대상
def test_masked_secret_not_sent_to_other_host():
    from app.security.secrets import MASK, mask_redirect
    conns = [{"name": "vc01", "type": "vcenter", "host": "vc01.lab", "username": "svc", "password": "p"},
             {"name": "bmc", "type": "redfish", "hosts": ["10.0.0.1", "10.0.0.2"], "username": "u", "password": "p"},
             {"name": "tkc", "type": "vks", "host": "10.1.1.1:6443", "supervisor": "sup.lab", "password": "p", "token": "t"}]
    mr = lambda d: mask_redirect([d], conns, "connectors")  # noqa: E731
    assert mr({"name": "vc01", "host": "evil.example.com", "password": MASK}) == "host"
    assert mr({"name": "vc01", "host": "VC01.lab ", "password": MASK}) is None
    assert mr({"name": "vc01", "host": "evil.example.com", "password": "typed-again"}) is None      # 비밀을 다시 입력했으면 허용
    assert mr({"name": "bmc", "hosts": ["10.0.0.2"], "password": MASK}) is None and mr({"name": "bmc", "hosts": ["6.6.6.6"], "password": MASK}) == "hosts"
    assert mr({"name": "tkc", "host": "10.1.1.1:6443", "supervisor": "evil.example.com", "password": MASK}) == "supervisor"
    assert mr({"name": "new", "host": "x.lab", "password": MASK}) == "host"                          # 저장된 것이 없는 이름 + 마스크
    itsm = {"type": "servicenow", "servicenow": {"instance": "https://corp.service-now.com", "username": "u", "password": "p"},
            "webhook": {"url": "https://itsm.lab/hook", "headers": {"Authorization": "Bearer z"}}}
    assert mask_redirect({"servicenow": {"instance": "https://evil.example.com", "password": MASK}}, itsm, "itsm") == "instance"
    assert mask_redirect({"webhook": {"url": "https://evil.example.com/h", "headers": {"Authorization": MASK}}}, itsm, "itsm") == "url"
    assert mask_redirect({"webhook": {"url": MASK, "headers": {"Authorization": MASK}}, "servicenow": {"instance": "https://corp.service-now.com/", "password": MASK}}, itsm, "itsm") is None
    llm = {"providers": [{"name": "claude", "type": "anthropic", "base_url": "", "api_key": "k"}]}
    assert mask_redirect({"providers": [{"name": "claude", "type": "anthropic", "base_url": "https://evil.example.com", "api_key": MASK}]}, llm, "llm") == "base_url"
    assert mask_redirect({"providers": [{"name": "claude", "type": "anthropic", "api_key": MASK}]}, llm, "llm") is None
    src = (ROOT / "app/api_enterprise.py").read_text(encoding="utf-8")
    assert src.count("_no_redirect(") == 4 and "mask_redirect(val," in (ROOT / "app/main.py").read_text(encoding="utf-8")
