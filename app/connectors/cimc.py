"""Cisco IMC(CIMC) XML API — Redfish 를 지원하지 않거나 불안정한 구형 C-Series(M3·일부 M4, CIMC 2.x·3.0) 보조 경로.

Cisco IMC XML API(POST https://<cimc>/nuova):
  <aaaLogin inName=".." inPassword=".."/>                           → outCookie
  <configResolveClass cookie=".." classId="faultInst" inHierarchical="false"/>  → 활성 장애(faultInst)
  <configResolveClass cookie=".." classId="computeRackUnit" .../>   → 모델·S/N·전원·메모리
  <configResolveClass cookie=".." classId="firmwareRunning" .../>   → 구성요소별 실행 펌웨어
  <aaaLogout cookie=".." inCookie=".."/>                            (세션 수 제한이 있어 폴링마다 로그아웃)
"""
from __future__ import annotations

import ssl
import warnings
import xml.etree.ElementTree as ET
from typing import Any
from xml.sax.saxutils import quoteattr

import httpx

FAULT_SEV = {"critical": "critical", "major": "error", "minor": "warning", "warning": "warning",
             "condition": "info", "info": "info", "cleared": "info"}


def legacy_ssl(verify: bool) -> ssl.SSLContext:
    """구형 BMC(TLS 1.0/1.1·약한 암호군) 호환 컨텍스트 — 해당 장비에만 쓰고 기본은 표준 컨텍스트."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")          # RSA 키 교환·3DES·SHA1 서명 등 구형 BMC 암호군까지
    except ssl.SSLError:
        pass
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


class CimcXml:
    def __init__(self, base_url: str, user: str, password: str, verify: bool, legacy: bool = False, timeout: float = 30):
        self.url = base_url.rstrip("/") + "/nuova"
        self.user, self.password = user, password
        self.verify = legacy_ssl(verify) if legacy else verify
        self.timeout = timeout
        self.cookie = ""

    async def _post(self, c: httpx.AsyncClient, body: str) -> ET.Element:
        r = await c.post(self.url, content=body.encode(), headers={"Content-Type": "application/xml", "Connection": "close"})
        r.raise_for_status()
        root = ET.fromstring(r.text)
        if root.get("errorCode"):
            raise RuntimeError(f"CIMC XML API 오류 {root.get('errorCode')}: {root.get('errorDescr', '')}")
        return root

    def session(self) -> "_Session":
        return _Session(self)

    async def probe(self) -> bool:
        """/nuova 가 XML API 로 응답하는지(로그인 시도 없이 빈 요청)."""
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=10) as c:
                r = await c.post(self.url, content=b"<aaaKeepAlive cookie=''/>", headers={"Content-Type": "application/xml"})
            return r.status_code < 500 and "<" in r.text
        except httpx.HTTPError:
            return False


class _Session:
    def __init__(self, x: CimcXml):
        self.x = x
        self.c: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self.c = httpx.AsyncClient(verify=self.x.verify, timeout=self.x.timeout)
        root = await self.x._post(self.c, f"<aaaLogin inName={quoteattr(self.x.user)} inPassword={quoteattr(self.x.password)}/>")
        self.x.cookie = root.get("outCookie", "")
        if not self.x.cookie:
            raise RuntimeError("CIMC XML API 로그인 실패(outCookie 없음)")
        return self

    async def resolve(self, class_id: str) -> list[dict[str, Any]]:
        root = await self.x._post(self.c, f"<configResolveClass cookie={quoteattr(self.x.cookie)} classId={quoteattr(class_id)} inHierarchical=\"false\"/>")
        out = root.find("outConfigs")
        return [dict(el.attrib) for el in (list(out) if out is not None else [])]

    async def __aexit__(self, *exc):
        try:
            if self.x.cookie:
                await self.x._post(self.c, f"<aaaLogout cookie={quoteattr(self.x.cookie)} inCookie={quoteattr(self.x.cookie)}/>")
        except Exception:  # noqa: BLE001
            pass
        self.x.cookie = ""
        await self.c.aclose()
