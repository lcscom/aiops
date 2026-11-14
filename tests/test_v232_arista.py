"""2.3.2 — Arista eAPI 견고성: 명령별 재시도(JSON 미지원·구버전), HTTP 전용 eAPI 자동 전환, 원인별 안내"""
import asyncio
import http.server
import json
import threading

import httpx
import pytest

from app.connectors import network as N


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://sw")


def _h(fail=(), status=200):
    def h(req):
        if status != 200:
            return httpx.Response(status, text="no")
        cmds = json.loads(req.content)["params"]["cmds"]
        for c in cmds:
            if c in fail:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": "aiops", "error": {"code": 1003, "message": f"CLI command 1 of 1 '{c}' failed: command not converted to JSON"}})
        res = []
        for c in cmds:
            res.append({"show version": {"modelName": "cEOS", "version": "4.30.1F"}, "show hostname": {"hostname": "dc1-leaf1"},
                        "show interfaces status": {"interfaceStatuses": {"Ethernet1": {"linkStatus": "connected"}}},
                        "show lldp neighbors": {"lldpNeighbors": [{"port": "Ethernet1", "neighborDevice": "dc1-spine1", "neighborPort": "Ethernet3"}]}}.get(c, {}))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "aiops", "result": res})
    return h


def test_batch_falls_back_per_command_and_summary_lldp():
    c = N.AristaEosConnector({"name": "a", "host": "sw", "username": "u", "password": "p"}, None)
    c._http = _client(_h(fail=("show lldp neighbors detail",)))
    d = asyncio.run(c.collect())
    assert d["device"]["hostname"] == "dc1-leaf1" and d["neighbors"][0]["remote"] == "dc1-spine1" and d["ifaces"]["Ethernet1"]["state"] == "up"


def test_clear_error_messages():
    c = N.AristaEosConnector({"name": "a", "host": "sw", "username": "u", "password": "p"}, None)
    c._http = _client(_h(status=401))
    with pytest.raises(RuntimeError, match="계정"):
        asyncio.run(c.run_cmds(["show version"]))
    c._http = _client(lambda req: httpx.Response(200, text="<html>login</html>", headers={"content-type": "text/html"}))
    with pytest.raises(RuntimeError, match="JSON 이 아님"):
        asyncio.run(c.run_cmds(["show version"]))


def test_http_only_eapi_port_switches_to_http():
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            cmds = json.loads(self.rfile.read(int(self.headers["content-length"])))["params"]["cmds"]
            data = json.dumps({"jsonrpc": "2.0", "id": "aiops", "result": [{"modelName": "vEOS", "version": "4.29"} for _ in cmds]}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = N.AristaEosConnector({"name": "a", "host": f"127.0.0.1:{srv.server_address[1]}", "username": "u", "password": "p"}, None)
        r = asyncio.run(c.test())
        assert r["ok"] and c.base_url.startswith("http://") and "eAPI 프로토콜" in r["checks"] and "vEOS" in r["checks"]["eAPI show version"]
    finally:
        srv.shutdown()


def test_refused_on_both_protocols_gives_clear_message():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                                                   # 닫힌 포트 → 연결 거부
    c = N.AristaEosConnector({"name": "a", "host": f"127.0.0.1:{port}", "username": "u", "password": "p"}, None)
    r = asyncio.run(c.test())
    assert not r["ok"] and "HTTPS·HTTP 모두 연결 거부" in r["error"] and c.base_url.startswith("http://")
