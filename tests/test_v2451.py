"""2.45.1 — VM 액티비티 실행 주체 IP·클라이언트"""
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

from app import vmmoves as M

ROOT = Path(__file__).resolve().parents[1]


def test_norm_and_client():
    assert M.norm_user("VSPHERE.LOCAL\\Administrator") == "administrator" == M.norm_user("administrator@vsphere.local")
    assert M.client_of("VMware PowerCLI/13.3") == "PowerCLI" and M.client_of("pyvmomi 9.1 Python/3.13") == "pyVmomi(Python)"
    assert M.client_of("Mozilla/5.0 (Windows NT 10.0)") == "vSphere Client(브라우저)" and M.client_of("govc/0.43") == "govc"


def test_who_of():
    logins = {"admin": [(1000, "10.0.0.5", "VMware PowerCLI"), (5000, "10.0.0.9", "Mozilla/5.0")],
              "wcp-schedext-user-1": [(100, "10.10.1.2", "Go-http-client/1.1")]}
    w = M.who_of("VSPHERE.LOCAL\\admin", 6000, logins, [])
    assert w["ip"] == "10.0.0.9" and w["client"] == "vSphere Client(브라우저)" and "다른 IP 10.0.0.5" in w["via"]
    assert M.who_of("admin", 2000, logins, [])["ip"] == "10.0.0.5"                       # 그 시각 이전 로그인만
    assert M.who_of("VSPHERE.LOCAL\\wcp-schedext-user-1", 200, logins, [])["client"] == "Go 클라이언트"
    h = M.who_of("dcui", 10, logins, [], "esx11.rangers.lab", "10.1.1.11")
    assert h["ip"] == "10.1.1.11" and "esx11.rangers.lab" in h["via"] and h["client"] == "ESXi 호스트"
    live = [{"user": "VSPHERE.LOCAL\\ops", "ip": "10.2.2.2", "agent": "govc/0.43", "login": 50, "last": 90}]
    assert M.who_of("ops@vsphere.local", 100, logins, live) == {"ip": "10.2.2.2", "client": "govc", "via": "현재 열린 세션"}
    assert M.who_of("ghost", 100, logins, live)["ip"] == "" and "로그인 기록 없음" in M.who_of("ghost", 100, logins, live)["via"]
    assert M.who_of("", 100, logins, live) == {}


def test_connector_attaches_ip():
    import datetime as dt

    from app.connectors.vcenter import VCenterConnector

    class UserLoginSessionEvent:
        def __init__(self, ts, user, ip, ua):
            self.createdTime, self.userName, self.ipAddress, self.userAgent = dt.datetime.fromtimestamp(ts, dt.timezone.utc), user, ip, ua
    c = VCenterConnector.__new__(VCenterConnector)
    c._state = {"checks": {}}
    c.health_snap = {"hosts": {"esx11": {"mgmt_ip": "10.1.1.11"}}}
    c.si = NS(content=NS(sessionManager=NS(sessionList=[NS(userName="VSPHERE.LOCAL\\bob", ipAddress="10.3.3.3", userAgent="PowerCLI",
                                                            loginTime=dt.datetime.fromtimestamp(10, dt.timezone.utc),
                                                            lastActiveTime=dt.datetime.fromtimestamp(20, dt.timezone.utc))])))
    import time
    now = time.time()
    c._collect_sessions([UserLoginSessionEvent(now - 60, "VSPHERE.LOCAL\\alice", "10.9.9.9", "pyvmomi Python")])
    assert c._who("VSPHERE.LOCAL\\alice", now, "esx11")["ip"] == "10.9.9.9"
    assert c._who("VSPHERE.LOCAL\\bob", now, "esx11")["ip"] == "10.3.3.3"
    assert c._who("dcui", now, "esx11")["ip"] == "10.1.1.11"
    assert c._state["checks"]["세션 목록"].startswith("ok")
    c.si = None                                                                            # 권한 없음 등 — 로그인 이벤트로만
    c._collect_sessions([])
    assert c._state["checks"]["세션 목록"].startswith("warn") and c._who("VSPHERE.LOCAL\\alice", now, "x")["ip"] == "10.9.9.9"


def test_record_and_csv():
    row = {"ts": 0, "type": "removed", "vm": "v", "from_host": "h", "to_host": "", "from_ds": "", "to_ds": "", "cluster": "", "user": "u",
           "vcenter": "vc", "ip": "10.0.0.1", "client": "PowerCLI", "via": "로그인 이벤트"}
    assert "u,10.0.0.1,PowerCLI,로그인 이벤트" in M.MoveTracker.to_csv([row])
    assert {"ip", "client", "via"} <= set(M.COLS)
    js = (ROOT / "app" / "static" / "vmmoves.js").read_text(encoding="utf-8")
    assert "data-ip=" in js and "접속 IP·클라이언트" in js
    subprocess.run(["node", "--check", str(ROOT / "app" / "static" / "vmmoves.js")], check=True)
