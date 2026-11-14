"""2.3.1 — TLS 1.0/1.1·구형 암호군만 지원하는 장비(구형 Nexus 등)에 구형 호환으로 자동 전환"""
import asyncio
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import warnings
import http.server

import httpx
import pytest

from app.connectors.base import is_legacy_tls_error
from app.connectors.network import CiscoAutoConnector


def test_legacy_tls_error_detection_and_switch():
    e = httpx.ConnectError("[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1000)")
    assert is_legacy_tls_error(e)
    inner = ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version")
    outer = httpx.ConnectError("handshake")
    outer.__cause__ = inner
    assert is_legacy_tls_error(outer) and not is_legacy_tls_error(httpx.ConnectError("Connection refused"))
    c = CiscoAutoConnector({"name": "x", "host": "10.0.0.1"}, None)
    _ = c.http
    assert c.switch_legacy_tls(e) is True and c.legacy_tls and c._http is None and "TLS" in c._state["checks"]
    assert c.switch_legacy_tls(e) is False                                   # 한 번만
    assert isinstance(c.http._transport._pool._ssl_context, ssl.SSLContext)  # 구형 호환 컨텍스트로 새 클라이언트


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl 없음")
def test_cisco_auto_detects_nxos_over_tlsv1_only_server():
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/k.pem", "-out", f"{d}/c.pem", "-days", "1", "-subj", "/CN=sw"],
                   check=True, capture_output=True)

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            outs = []
            for c in body["ins_api"]["input"].split(" ;"):
                b = {"show version": {"chassis_id": "Nexus7000 C7010", "nxos_ver_str": "6.2(20)"}, "show hostname": {"hostname": "n7k-old"},
                     "show interface brief": {"TABLE_interface": {"ROW_interface": [{"interface": "Ethernet1/1", "state": "up"}]}}}.get(c.strip(), {})
                outs.append({"code": "200", "msg": "Success", "body": b})
            data = json.dumps({"ins_api": {"outputs": {"output": outs}}}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pytest.skip("이 OpenSSL 은 TLS 1.0 서버를 만들 수 없음")
    ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = CiscoAutoConnector({"name": "n7k", "host": f"127.0.0.1:{srv.server_address[1]}", "username": "u", "password": "p"}, None)

        async def go():
            await c.login()
            await c.poll()
            return c.snapshot()
        s = asyncio.run(go())
        assert c.legacy_tls and s["name"] == "n7k-old" and s["version"] == "6.2(20)"
        assert "구형 TLS" in c._state["checks"]["플랫폼"]
    finally:
        srv.shutdown()
        os.system(f"rm -rf {d}")
