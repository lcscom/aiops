"""OIDC SSO(Authorization Code + PKCE, RFC 6749/7636, OpenID Connect Core 1.0) — Keycloak·Entra ID·Okta·ADFS 등 표준 IdP.

  1. GET /api/auth/oidc/start     state·nonce·PKCE verifier 를 HMAC 서명한 임시 쿠키(10분)에 담고 IdP authorization_endpoint 로 302
  2. GET /api/auth/oidc/callback  code → token_endpoint(client_secret_post 또는 basic) → id_token 서명 검증(JWKS, RS256/ES256)
                                  iss·aud·exp·nonce 확인 → 역할 매핑(role_claim 값 ↔ group_role_map, 없으면 default_role) → 세션
설정 auth.oidc: enabled, issuer, client_id, client_secret, scopes, role_claim(groups), group_role_map{}, default_role(''=거부),
                 username_claim(preferred_username), display_name, verify_tls, ca_file, redirect_base(역방향 프록시 뒤 외부 URL)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import ssl
import time
from urllib.parse import urlencode, quote

import httpx
from fastapi import APIRouter, HTTPException, Request
import html as _html

from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

MFA_COOKIE = "aiops_mfa"          # 2.48.2 SSO 뒤 2단계 인증 대기 토큰(HttpOnly, /api/auth/mfa 경로 한정, 5분)

ROLE_ORDER = ["admin", "operator", "auditor", "viewer"]


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_to_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_b64d(jwk["n"]), "big")
        e = int.from_bytes(_b64d(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[jwk["crv"]]
        x = int.from_bytes(_b64d(jwk["x"]), "big")
        y = int.from_bytes(_b64d(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise ValueError(f"지원하지 않는 키 형식 {kty}")


def verify_jwt(token: str, jwks: list[dict]) -> dict:
    """서명 검증(RS256/384/512 · ES256/384/512) 후 payload — 실패면 ValueError"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise ValueError("JWT 형식 오류")
    header = json.loads(_b64d(h))
    alg = header.get("alg", "")
    kid = header.get("kid")
    cands = [k for k in jwks if not kid or k.get("kid") == kid] or jwks
    hname = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}.get(alg[-3:])
    if not hname or alg[:2] not in ("RS", "ES"):
        raise ValueError(f"허용하지 않는 서명 알고리즘 {alg or '(none)'}")
    sig, msg = _b64d(s), f"{h}.{p}".encode()
    for jwk in cands:
        try:
            key = jwk_to_key(jwk)
            if alg.startswith("RS"):
                key.verify(sig, msg, padding.PKCS1v15(), hname)
            else:
                n = len(sig) // 2
                der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
                key.verify(der, msg, ec.ECDSA(hname))
            return json.loads(_b64d(p))
        except (InvalidSignature, ValueError, KeyError):
            continue
    raise ValueError("id_token 서명 검증 실패(JWKS 불일치)")


def map_role(claims: dict, cfg: dict) -> str:
    """role_claim(기본 groups) 값들과 group_role_map 대조 — 가장 높은 역할; 없으면 default_role('' 이면 거부)"""
    rc = str(cfg.get("role_claim") or "groups")
    vals = claims.get(rc)
    if vals is None and "." in rc:                       # 중첩 클레임 (예: realm_access.roles)
        cur = claims
        for part in rc.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        vals = cur
    vals = vals if isinstance(vals, list) else ([vals] if vals else [])
    m = {str(k).lower(): str(v) for k, v in (cfg.get("group_role_map") or {}).items()}
    got = {m[str(v).lower()] for v in vals if str(v).lower() in m}
    for r in ROLE_ORDER:
        if r in got:
            return r
    return str(cfg.get("default_role") or "")


class Oidc:
    def __init__(self, cfg: dict, secret: bytes):
        self.cfg = cfg or {}
        self.secret = secret
        self._disc: dict = {}
        self._jwks: list[dict] = []
        self._ts = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled") and self.cfg.get("issuer") and self.cfg.get("client_id"))

    def _client(self) -> httpx.AsyncClient:
        verify: bool | ssl.SSLContext = bool(self.cfg.get("verify_tls", True))
        if verify and self.cfg.get("ca_file"):
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(self.cfg["ca_file"])
            verify = ctx
        return httpx.AsyncClient(timeout=float(self.cfg.get("timeout", 10)), verify=verify)

    async def discover(self, force: bool = False) -> dict:
        if self._disc and not force and time.time() - self._ts < 3600:
            return self._disc
        iss = str(self.cfg["issuer"]).rstrip("/")
        async with self._client() as c:
            r = await c.get(iss + "/.well-known/openid-configuration")
            r.raise_for_status()
            d = r.json()
            j = await c.get(d["jwks_uri"])
            j.raise_for_status()
            self._jwks = j.json().get("keys", [])
        self._disc, self._ts = d, time.time()
        return d

    def _sign(self, payload: dict) -> str:
        body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
        return body + "." + _b64u(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())

    def _open(self, tok: str) -> dict:
        try:
            body, mac = tok.split(".")
        except ValueError:
            raise HTTPException(400, "SSO 상태 쿠키 오류 — 다시 시도하세요")
        if not hmac.compare_digest(_b64u(hmac.new(self.secret, body.encode(), hashlib.sha256).digest()), mac):
            raise HTTPException(400, "SSO 상태 쿠키 서명 불일치")
        p = json.loads(_b64d(body))
        if p.get("exp", 0) < time.time():
            raise HTTPException(400, "SSO 로그인 시간이 지났습니다 — 다시 시도하세요")
        return p

    def redirect_uri(self, request: Request) -> str:
        base = str(self.cfg.get("redirect_base") or "").rstrip("/")
        if not base:
            proto = request.headers.get("x-forwarded-proto") or request.url.scheme
            host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
            base = f"{proto}://{host}"
        return base + "/api/auth/oidc/callback"

    async def start(self, request: Request, nxt: str):
        d = await self.discover()
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
        q = {"response_type": "code", "client_id": self.cfg["client_id"], "redirect_uri": self.redirect_uri(request),
             "scope": " ".join(self.cfg.get("scopes") or ["openid", "profile", "email"]), "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        resp = RedirectResponse(d["authorization_endpoint"] + "?" + urlencode(q), status_code=302)
        secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        resp.set_cookie("aiops_oidc", self._sign({"state": state, "nonce": nonce, "v": verifier, "next": nxt, "exp": time.time() + 600}),
                        httponly=True, samesite="lax", secure=secure, path="/api/auth/oidc", max_age=600)
        return resp

    async def callback(self, request: Request) -> tuple[dict, str]:
        """code 교환 + id_token 검증 → (claims, next)"""
        if request.query_params.get("error"):
            raise HTTPException(401, f"IdP 오류: {request.query_params.get('error_description') or request.query_params['error']}")
        st = self._open(request.cookies.get("aiops_oidc", ""))
        if not hmac.compare_digest(st.get("state", ""), request.query_params.get("state", "")):
            raise HTTPException(400, "state 불일치(CSRF 의심)")
        code = request.query_params.get("code", "")
        if not code:
            raise HTTPException(400, "code 없음")
        d = await self.discover()
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri(request),
                "client_id": self.cfg["client_id"], "code_verifier": st["v"]}
        auth = None
        if self.cfg.get("client_secret"):
            if str(self.cfg.get("token_auth") or "post") == "basic":
                auth = (self.cfg["client_id"], self.cfg["client_secret"])
            else:
                data["client_secret"] = self.cfg["client_secret"]
        async with self._client() as c:
            r = await c.post(d["token_endpoint"], data=data, auth=auth, headers={"Accept": "application/json"})
        if r.status_code != 200:
            raise HTTPException(401, f"토큰 교환 실패 {r.status_code}: {r.text[:200]}")
        tok = r.json()
        idt = tok.get("id_token", "")
        try:
            claims = verify_jwt(idt, self._jwks)
        except ValueError:
            await self.discover(force=True)          # 키 회전 → JWKS 새로 받아 1회 재시도
            try:
                claims = verify_jwt(idt, self._jwks)
            except ValueError as e:
                raise HTTPException(401, str(e))
        now = time.time()
        iss = str(self.cfg["issuer"]).rstrip("/")
        aud = claims.get("aud")
        aud = aud if isinstance(aud, list) else [aud]
        if str(claims.get("iss", "")).rstrip("/") != iss:
            raise HTTPException(401, "id_token iss 불일치")
        if self.cfg["client_id"] not in aud:
            raise HTTPException(401, "id_token aud 불일치")
        if float(claims.get("exp", 0)) < now - 60:
            raise HTTPException(401, "id_token 만료")
        if not hmac.compare_digest(str(claims.get("nonce", "")), st.get("nonce", "")):
            raise HTTPException(401, "nonce 불일치")
        # 그룹 클레임이 userinfo 에만 있는 IdP(Okta 등) 보완
        rc = str(self.cfg.get("role_claim") or "groups").split(".")[0]
        if rc not in claims and tok.get("access_token") and d.get("userinfo_endpoint"):
            try:
                async with self._client() as c:
                    ui = await c.get(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"})
                if ui.status_code == 200:
                    claims = {**ui.json(), **claims}
            except Exception:  # noqa: BLE001
                pass
        return claims, st.get("next") or "/"

    def username(self, claims: dict) -> str:
        uc = str(self.cfg.get("username_claim") or "preferred_username")
        u = str(claims.get(uc) or claims.get("email") or claims.get("sub") or "").strip().lower()
        return u.split("@")[0] if self.cfg.get("strip_domain", True) and "@" in u else u

    def router(self, auth, audit) -> APIRouter:
        r = APIRouter()
        me = self

        @r.get("/api/auth/oidc/start")
        async def oidc_start(request: Request):
            if not me.enabled:
                raise HTTPException(404, "SSO 비활성")
            nxt = request.query_params.get("next") or "/"
            if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt or any(ord(c) < 32 for c in nxt):   # 2.30.0 "/\\evil.com" 도 차단
                nxt = "/"
            try:
                return await me.start(request, nxt)
            except Exception as e:  # noqa: BLE001
                await audit.log("auth.sso", result="fail", detail={"stage": "discover", "error": str(e)[:200]})
                raise HTTPException(502, f"IdP 메타데이터 조회 실패: {str(e)[:160]}")

        @r.get("/api/auth/oidc/callback")
        async def oidc_callback(request: Request):
            if not me.enabled:
                raise HTTPException(404, "SSO 비활성")
            from .auth import client_ip
            ip = client_ip(request)
            try:
                claims, nxt = await me.callback(request)
                uname = me.username(claims)
                if not uname or not uname.replace(".", "").replace("_", "").replace("-", "").isalnum():
                    raise HTTPException(401, "사용자 이름 클레임 없음/형식 오류")
                role = map_role(claims, me.cfg)
                if role not in ROLE_ORDER:
                    await audit.log("auth.sso", user=uname, ip=ip, result="no_role", detail={"claims": {k: claims.get(k) for k in ("groups", "roles", "email")}})
                    raise HTTPException(403, "역할 매핑 없음 — 관리자에게 그룹 권한을 요청하세요")
                res = await auth.sso_login(uname, str(claims.get("name") or claims.get("preferred_username") or uname)[:60],
                                           str(claims.get("email") or "")[:120], role, ip, request.headers.get("user-agent", ""))
            except HTTPException as e:
                await audit.log("auth.sso", ip=ip, result="fail", detail={"error": str(e.detail)[:200]})
                html = f"<!doctype html><meta charset=utf-8><title>SSO</title><body style='font-family:sans-serif;padding:40px'>" \
                       f"<h3>SSO 로그인 실패</h3><p>{_html.escape(str(e.detail))}</p><p><a href='/login'>로그인 화면으로</a></p>"
                return HTMLResponse(html, status_code=e.status_code)
            secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            if res.get("mfa_required"):
                # 2.48.2 MFA 토큰은 URL(브라우저 기록·접근 로그·Referer)에 싣지 않고 HttpOnly 임시 쿠키로 넘김
                resp = RedirectResponse(f"/login?mfa=1&next={quote(nxt, safe='')}", status_code=302)
                resp.set_cookie(MFA_COOKIE, res["mfa_token"], httponly=True, samesite="lax", secure=secure,
                                path="/api/auth/mfa", max_age=300)
            else:
                resp = RedirectResponse(nxt, status_code=302)
                resp.set_cookie("aiops_sid", res["sid"], httponly=True, samesite="strict", secure=secure, path="/")
            resp.delete_cookie("aiops_oidc", path="/api/auth/oidc")
            return resp

        @r.post("/api/auth/oidc/test")
        async def oidc_test(request: Request):
            """관리자: IdP 메타데이터·JWKS 조회 점검(설정 저장 전)"""
            if not me.enabled:
                return {"ok": False, "detail": "SSO 비활성(issuer·client_id 필요)"}
            try:
                d = await me.discover(force=True)
                return {"ok": True, "issuer": d.get("issuer"), "authorization_endpoint": d.get("authorization_endpoint"),
                        "token_endpoint": d.get("token_endpoint"), "jwks_keys": len(me._jwks), "redirect_uri": me.redirect_uri(request)}
            except Exception as e:  # noqa: BLE001
                return JSONResponse({"ok": False, "detail": str(e)[:200]}, status_code=502)

        return r
