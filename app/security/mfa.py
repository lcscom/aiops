"""MFA(TOTP, RFC 6238) — 로컬·LDAP·SSO 계정 공통. 비밀은 사용자별로 저장하고, 복구 코드는 해시만 저장한다.

  · enroll(user)     → base32 비밀 + otpauth:// URI + QR(SVG, segno) — 확인 코드 1회 성공 뒤 '사용'으로 전환
  · verify(user, c)  → 현재·앞뒤 30초 창(±1) 허용, 같은 코드 재사용 금지(마지막 사용 카운터 저장)
  · 복구 코드 8개(각 1회), 관리자 '재설정'으로 해제
  · 정책 auth.mfa.required_roles (예: [admin]) — 해당 역할은 등록 전까지 화면에서 등록을 요구(must_enroll)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

SCHEMA = """
CREATE TABLE IF NOT EXISTS mfa(username TEXT PRIMARY KEY, secret TEXT, pending TEXT, enabled INTEGER DEFAULT 0, recovery TEXT, last_counter INTEGER DEFAULT 0,
  created REAL, enabled_at REAL);
"""


def totp(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((t if t is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def _counter(t: float | None = None, step: int = 30) -> int:
    return int((t if t is not None else time.time()) // step)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(secret: str, user: str, issuer: str = "VCF AIops") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(user)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def qr_svg(data: str) -> str:
    """QR 코드 SVG(segno, 순수 파이썬) — 없으면 빈 문자열(URI·비밀 수동 입력으로 등록 가능)"""
    try:
        import io
        import segno
        buf = io.BytesIO()
        segno.make(data, error="m").save(buf, kind="svg", scale=4, border=2, dark="#1d2328", xmldecl=False, svgns=True)
        return buf.getvalue().decode()
    except Exception:  # noqa: BLE001
        return ""


def _hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").strip().lower().encode()).hexdigest()


class Mfa:
    def __init__(self, store, cfg: dict | None = None, issuer: str = "VCF AIops"):
        self.store = store
        store.schema(SCHEMA)
        c = cfg or {}
        self.required_roles = {str(r) for r in (c.get("required_roles") or [])}
        self.issuer = str(c.get("issuer") or issuer)
        self.enabled = bool(c.get("enabled", True))

    async def status(self, user: str) -> dict:
        r = await self.store.q1("SELECT enabled, enabled_at, recovery FROM mfa WHERE username=?", (user,))
        left = len(json.loads(r["recovery"] or "[]")) if r else 0
        return {"enrolled": bool(r and r["enabled"]), "enabled_at": r["enabled_at"] if r else None, "recovery_left": left}

    def must_enroll(self, role: str, enrolled: bool) -> bool:
        return self.enabled and role in self.required_roles and not enrolled

    async def enroll(self, user: str) -> dict:
        """새 비밀 생성 — pending 에 두고 confirm 성공 때 secret 으로 승격(기존 '사용' 상태는 그때까지 유지)"""
        secret = new_secret()
        await self.store.x("INSERT INTO mfa(username,secret,pending,enabled,recovery,created) VALUES(?,'',?,0,'[]',?) "
                           "ON CONFLICT(username) DO UPDATE SET pending=excluded.pending", (user, secret, time.time()))
        uri = otpauth_uri(secret, user, self.issuer)
        return {"secret": secret, "uri": uri, "qr_svg": qr_svg(uri), "issuer": self.issuer}

    async def confirm(self, user: str, code: str) -> list[str]:
        """등록 확인 — 코드가 맞으면 사용 상태로 전환하고 복구 코드 8개 반환(한 번만 표시)"""
        r = await self.store.q1("SELECT pending FROM mfa WHERE username=?", (user,))
        if not r or not r["pending"]:
            raise ValueError("등록을 먼저 시작하세요")
        secret = r["pending"]
        cnt = self._match(secret, code)
        if cnt is None:
            raise ValueError("인증 코드가 맞지 않습니다 — 기기 시간(NTP)과 앱에 등록한 키를 확인하세요")
        codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(8)]
        await self.store.x("UPDATE mfa SET secret=?, pending='', enabled=1, recovery=?, enabled_at=?, last_counter=? WHERE username=?",
                           (secret, json.dumps([_hash(c) for c in codes]), time.time(), cnt, user))
        return codes

    @staticmethod
    def _match(secret: str, code: str, window: int = 1) -> int | None:
        """코드가 맞는 30초 창의 카운터(현재·앞뒤 window 개) — 없으면 None"""
        code = (code or "").strip().replace(" ", "")
        if not secret or not code.isdigit():
            return None
        now = time.time()
        for d in range(-window, window + 1):
            if hmac.compare_digest(totp(secret, now + d * 30), code):
                return _counter(now + d * 30)
        return None

    def _check(self, secret: str, code: str, window: int = 1) -> bool:
        return self._match(secret, code, window) is not None

    async def verify(self, user: str, code: str) -> str:
        """로그인 2단계 — 'totp' | 'recovery' 를 돌려주고, 실패면 ValueError"""
        r = await self.store.q1("SELECT secret, enabled, recovery, last_counter FROM mfa WHERE username=?", (user,))
        if not r or not r["enabled"]:
            raise ValueError("MFA 미등록")
        code = (code or "").strip()
        if code.replace(" ", "").isdigit():
            cnt = self._match(r["secret"], code)
            if cnt is None:
                raise ValueError("인증 코드가 맞지 않습니다")
            if cnt <= int(r["last_counter"] or 0):
                raise ValueError("이미 사용한 코드입니다 — 다음 코드를 기다리세요")
            await self.store.x("UPDATE mfa SET last_counter=? WHERE username=?", (cnt, user))
            return "totp"
        rec = json.loads(r["recovery"] or "[]")
        h = _hash(code)
        if h not in rec:
            raise ValueError("인증 코드가 맞지 않습니다")
        rec.remove(h)
        await self.store.x("UPDATE mfa SET recovery=? WHERE username=?", (json.dumps(rec), user))
        return "recovery"

    async def reset(self, user: str) -> None:
        await self.store.x("DELETE FROM mfa WHERE username=?", (user,))

    async def enrolled_users(self) -> set[str]:
        return {r["username"] for r in await self.store.q("SELECT username FROM mfa WHERE enabled=1")}
