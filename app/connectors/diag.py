"""연결 단계 진단 — DNS → TCP → TLS(표준) → TLS(구형 호환) 순서로 어디서 막히는지 보여 준다(구형 BMC·UCS Manager 연결 실패 원인 파악).

TLS 결과에는 협상된 프로토콜·암호군과 인증서 주체·만료일을 담는다. 표준 TLS 가 실패하고 구형 호환만 성공하면
장비가 TLS 1.0/1.1 또는 RSA 키 교환·3DES·SHA-1 같은 오래된 설정만 지원하는 것 — 커넥터는 자동으로 구형 호환으로 접속한다.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import Any

from .cimc import legacy_ssl


def _split(target: str, default_port: int = 443) -> tuple[str, int]:
    t = target.replace("https://", "").replace("http://", "").split("/")[0]
    if t.startswith("["):
        h, _, p = t[1:].partition("]")
        return h, int(p.lstrip(":") or default_port)
    if t.count(":") == 1:
        h, p = t.split(":")
        return h, int(p or default_port)
    return t, default_port


async def _tls(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if not host.replace(".", "").isdigit() else None), timeout)
        so = w.get_extra_info("ssl_object")
        cert = {}
        try:
            der = so.getpeercert(binary_form=True)
            if der:
                import cryptography.x509 as x509
                c = x509.load_der_x509_certificate(der)
                cert = {"subject": c.subject.rfc4514_string()[:120], "expires": c.not_valid_after_utc.strftime("%Y-%m-%d")}
        except Exception:  # noqa: BLE001
            pass
        out = {"ok": True, "version": so.version(), "cipher": (so.cipher() or ("",))[0], "ms": int((time.perf_counter() - t0) * 1000), **cert}
        w.close()
        try:
            await w.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return out
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}


async def diagnose(target: str, timeout: float = 8.0) -> dict[str, str]:
    host, port = _split(target)
    res: dict[str, str] = {}
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        res["① DNS"] = f"ok {infos[0][4][0]}"
    except Exception as e:  # noqa: BLE001
        res["① DNS"] = f"실패 {type(e).__name__}: {e}"[:160]
        return res
    t0 = time.perf_counter()
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        res["② TCP"] = f"ok {port}/tcp {int((time.perf_counter() - t0) * 1000)}ms"
    except Exception as e:  # noqa: BLE001
        res["② TCP"] = f"실패 {port}/tcp {type(e).__name__} — 방화벽·관리망 경로 확인"
        return res
    std = ssl.create_default_context()
    std.check_hostname = False
    std.verify_mode = ssl.CERT_NONE
    a = await _tls(host, port, std, timeout)
    res["③ TLS 표준"] = f"ok {a['version']} {a['cipher']}" + (f" · 인증서 {a.get('subject', '')} ~{a.get('expires', '')}" if a.get("subject") else "") if a["ok"] else f"실패 {a['error']}"
    if not a["ok"]:
        b = await _tls(host, port, legacy_ssl(False), timeout)
        res["④ TLS 구형 호환"] = (f"ok {b['version']} {b['cipher']} — 장비가 오래된 TLS 만 지원(자동으로 구형 호환 사용)" if b["ok"]
                              else f"실패 {b['error']} — HTTPS 서비스 비활성 또는 TLS 아님(포트 확인)")
    return res
