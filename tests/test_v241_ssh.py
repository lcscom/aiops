"""2.4.1 — eAPI 를 쓸 수 없는 Arista 를 SSH CLI(show … | json)로 수집(자동 전환·호스트 키 기억)"""
import asyncio
import json
import socket

import asyncssh
import pytest

from app.connectors.network import AristaEosConnector

OUT = {"show version | json": {"modelName": "cEOSLab", "version": "4.31.0F", "serialNumber": "X1"},
       "show hostname | json": {"hostname": "dc1-leaf1", "fqdn": "dc1-leaf1.lab"},
       "show interfaces status | json": {"interfaceStatuses": {"Ethernet1": {"linkStatus": "connected", "description": "esx01 vmnic0", "bandwidth": 25000000000}}},
       "show lldp neighbors detail | json": {"lldpNeighbors": {"Ethernet1": {"lldpNeighborInfo": [{"systemName": "esx01.lab", "neighborInterfaceInfo": {"interfaceId_v2": "vmnic0"}}]}}},
       "show running-config": "hostname dc1-leaf1\ninterface Ethernet1\n   description esx01 vmnic0\n   switchport mode trunk\n!\n"}


class Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "ro" and password == "pw"


async def handle(proc):
    cmd = proc.command or ""
    v = OUT.get(cmd)
    if v is None:
        proc.stdout.write("% Invalid input\n")
    else:
        proc.stdout.write(v if isinstance(v, str) else json.dumps(v))
    proc.exit(0)


def _free():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_arista_auto_falls_back_to_ssh_when_eapi_refused():
    async def go():
        key = asyncssh.generate_private_key("ssh-ed25519")
        sp = _free()
        srv = await asyncssh.create_server(Srv, "127.0.0.1", sp, server_host_keys=[key], process_factory=handle)
        try:
            eapi = _free()                                                    # 닫힌 포트 → eAPI HTTPS·HTTP 연결 거부
            c = AristaEosConnector({"name": "a", "host": f"127.0.0.1:{eapi}", "username": "ro", "password": "pw", "ssh_port": sp}, None)
            r = await c.test()
            assert r["ok"], r
            assert c.transport == "ssh" and "SSH" in r["checks"]["전송"] and "cEOSLab" in r["checks"]["SSH show version"]
            fp = c._ssh_cli().fingerprint
            assert fp.startswith("SHA256:")
            await c.login()
            c.first_poll = False
            await c.poll()
            s = c.snapshot()
            assert s["name"] == "dc1-leaf1" and s["neighbors"][0]["remote"] == "esx01.lab" and s["port_cfg"]["Ethernet1"]["mode"] == "trunk"
            c._ssh_cli().close()
            c._ssh.pinned = "SHA256:different"                                 # 호스트 키 바뀜 → 거부
            with pytest.raises(RuntimeError, match="호스트 키"):
                await c.run_cmds(["show version"])
            wrong = AristaEosConnector({"name": "b", "host": f"127.0.0.1:{eapi}", "username": "ro", "password": "bad", "ssh_port": sp}, None)
            r2 = await wrong.test()
            assert not r2["ok"] and "SSH" in r2["error"]
            fixed = AristaEosConnector({"name": "c", "host": f"127.0.0.1:{eapi}", "username": "ro", "password": "pw", "ssh_port": sp, "transport": "eapi"}, None)
            r3 = await fixed.test()
            assert not r3["ok"] and fixed.transport == "eapi"
        finally:
            srv.close()
    asyncio.run(go())
