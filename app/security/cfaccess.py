"""Cloudflare Access JWT 검증(2.22.0) — 외부 이름(server.external_hosts)으로 들어온 요청이 Access 를 거쳤는지 원본 서버에서 다시 확인.

Access 앞단 정책이 꺼지거나(실수·대시보드 변경) DNS·터널 설정이 바뀌어 Access 를 우회하는 경로가 생겨도, 서명된 토큰
(Cf-Access-Jwt-Assertion 머리글, 없으면 CF_Authorization 쿠키)이 없으면 403 으로 막는다.
검증: https://<팀>.cloudflareaccess.com/cdn-cgi/access/certs 의 공개키(RS256), iss = 팀 도메인, aud ∋ 앱 AUD 태그, exp·nbf.

설정(server.cf_access):
  team_domain: myteam.cloudflareaccess.com   # 또는 https://… — vcf-aiopsctl tunnel --access-allow 가 자동 기록
  aud: <Access 앱 AUD 태그>
  enforce: true                              # false = 검증만 하고 통과(상태·보안 점검에 결과 표시)
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

from .oidc import _b64d, verify_jwt


def _norm_domain(d: str) -> str:
    d = (d or "").strip().rstrip("/")
    if d.startswith("https://"):
        d = d[8:]
    elif d.startswith("http://"):
        d = d[7:]
    return d.split("/")[0].lower()


class CfAccess:
    def __init__(self, cfg: dict | None):
        cfg = cfg or {}
        self.team = _norm_domain(str(cfg.get("team_domain") or ""))
        self.aud = str(cfg.get("aud") or "").strip()
        self.enforce = bool(cfg.get("enforce", True))
        self.enabled = bool(self.team and self.aud)
        self.issuer = f"https://{self.team}" if self.team else ""
        self._jwks: list[dict] = []
        self._fetched = 0.0
        self._last_attempt = 0.0
        self.refresh_min = float(cfg.get("refresh_min_seconds", 60))
        self._bg: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self.stats: dict[str, Any] = {"ok": 0, "missing": 0, "invalid": 0, "last_error": "", "last_ok": 0.0, "jwks_keys": 0,
                                      "jwks_fetched": 0.0}

    # ------------------------------------------------------------------ 공개키
    async def _fetch(self) -> None:
        url = f"https://{self.team}/cdn-cgi/access/certs"
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(url)
            r.raise_for_status()
            keys = (r.json() or {}).get("keys") or []
        if not keys:
            raise ValueError("certs 응답에 keys 없음")
        self._jwks, self._fetched = keys, time.time()
        self.stats.update(jwks_keys=len(keys), jwks_fetched=self._fetched)

    async def _refresh(self) -> bool:
        """공개키 재조회 — 성공·실패와 무관하게 refresh_min 초에 한 번만(요청 폭주·조회 실패 시 직렬 대기 방지)"""
        if time.time() - self._last_attempt < self.refresh_min:
            return False
        async with self._lock:
            if time.time() - self._last_attempt < self.refresh_min:
                return False
            self._last_attempt = time.time()
            try:
                await self._fetch()
                return True
            except Exception as e:  # noqa: BLE001
                self.stats["last_error"] = f"공개키 조회 실패: {type(e).__name__}"
                return False

    def _bg_refresh(self) -> None:
        if self._bg is None or self._bg.done():
            try:
                self._bg = asyncio.get_running_loop().create_task(self._refresh())
            except RuntimeError:
                pass

    async def jwks(self, force: bool = False) -> list[dict]:
        """캐시된 키를 바로 돌려줌. 1시간 지나면 백그라운드 갱신(stale-while-revalidate). 키가 아예 없을 때만 기다려서 조회."""
        if not self._jwks:
            await self._refresh()
            if not self._jwks:
                raise ValueError(self.stats.get("last_error") or "Access 공개키 없음")
            return self._jwks
        if force:
            await self._refresh()
        elif time.time() - self._fetched >= 3600:
            self._bg_refresh()
        return self._jwks

    # ------------------------------------------------------------------ 검증
    def _claims_ok(self, c: dict) -> None:
        now = time.time()
        if str(c.get("iss", "")).rstrip("/") != self.issuer:
            raise ValueError("iss 불일치")
        aud = c.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.aud not in auds:
            raise ValueError("aud 불일치(다른 Access 앱의 토큰)")
        if float(c.get("exp") or 0) < now - 30:
            raise ValueError("만료된 토큰")
        if float(c.get("nbf") or 0) > now + 30:
            raise ValueError("아직 유효하지 않은 토큰")

    async def verify(self, token: str) -> dict:
        if not token or token.count(".") != 2:
            raise ValueError("토큰 없음")
        try:
            alg = json.loads(_b64d(token.split(".")[0])).get("alg", "")
        except Exception as e:  # noqa: BLE001
            raise ValueError("토큰 형식 오류") from e
        if alg != "RS256":
            raise ValueError(f"허용하지 않는 알고리즘 {alg or '(none)'}")
        keys = await self.jwks()
        try:
            claims = verify_jwt(token, keys)
        except ValueError:
            hdr = json.loads(_b64d(token.split(".")[0]))
            kid = hdr.get("kid")
            if kid and not any(k.get("kid") == kid for k in keys) and await self._refresh():   # 모르는 kid(키 교체 직후)만 재조회
                claims = verify_jwt(token, self._jwks)
            else:
                raise
        self._claims_ok(claims)
        return claims

    @staticmethod
    def token_from(headers, cookies) -> str:
        return (headers.get("cf-access-jwt-assertion") or cookies.get("CF_Authorization") or "").strip()

    async def check(self, headers, cookies, count: bool = True) -> tuple[bool, str, dict]:
        """(통과 여부, 사유, claims) — count=False 는 내부 점검 요청(통계 제외)"""
        tok = self.token_from(headers, cookies)
        if not tok:
            if count:
                self.stats["missing"] += 1
            return False, "Cloudflare Access 토큰 없음", {}
        try:
            c = await self.verify(tok)
        except Exception as e:  # noqa: BLE001  (형식 오류·키 문제 — 500 대신 거부)
            if count:
                self.stats["invalid"] += 1
                self.stats["last_error"] = str(e)[:160]
            return False, str(e) or type(e).__name__, {}
        if not count:
            return True, "", c
        self.stats["ok"] += 1
        self.stats["last_ok"] = time.time()
        return True, "", c

    def snapshot(self) -> dict:
        return {"enabled": self.enabled, "enforce": self.enforce, "team_domain": self.team, "aud_set": bool(self.aud), **self.stats}
