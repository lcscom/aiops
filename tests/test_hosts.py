"""VM 게스트·물리 서버 수집 단위 테스트 — 에이전트 정규화 · Redfish 이벤트 · 실시간 로그 보기 필터 · systemd 워치독"""
import asyncio
import json
import os
import socket
import tempfile
import time

from app.agents import normalize
from app.connectors.redfish import RedfishConnector
from app.connectors.vmware_rest import sev_from_text
from app.models import LogEvent
from app.realtime import Hub
from app.runtime import SystemdNotifier


def test_normalize_journald():
    form, ev, meta = normalize({"date": 1.0, "aiops_host": "db01", "aiops_kind": "vm", "aiops_role": "DB",
                                "MESSAGE": "Out of memory: Killed process 1 (java)", "PRIORITY": "3",
                                "SYSLOG_IDENTIFIER": "kernel", "_PID": "0"}, "10.0.0.1", sev_from_text)
    assert form == "journald" and ev.source == "vm" and ev.host == "db01" and ev.severity == "error"
    assert ev.message.startswith("kernel[0]: Out of memory") and meta["os"] == "linux" and ev.attrs["role"] == "DB"


def test_normalize_journald_binary_message():
    _, ev, _ = normalize({"aiops_host": "h", "aiops_kind": "baremetal", "MESSAGE": [104, 105], "PRIORITY": "6"}, "", sev_from_text)
    assert ev.message == "hi" and ev.source == "baremetal"


def test_normalize_winevtlog():
    form, ev, meta = normalize({"aiops_host": "was01", "aiops_kind": "vm", "ProviderName": "Microsoft-Windows-Kernel-Power",
                                "EventID": 41, "Level": 1, "Channel": "System", "Computer": "WAS01",
                                "Message": "The system has rebooted without cleanly shutting down first.",
                                "TimeCreated": "2026-10-11 15:30:00 +0900"}, "", sev_from_text)
    assert form == "windows" and ev.severity == "critical" and meta["os"] == "windows"
    assert ev.message.startswith("EventID=41 Microsoft-Windows-Kernel-Power:")
    from datetime import datetime, timezone
    assert abs(ev.ts - datetime(2026, 10, 11, 6, 30, tzinfo=timezone.utc).timestamp()) < 1   # +0900 오프셋 반영


def test_normalize_heartbeat_and_tail():
    form, ev, meta = normalize({"aiops_heartbeat": 1, "aiops_host": "x", "aiops_kind": "vm"}, "", sev_from_text)
    assert form == "heartbeat" and ev is None and meta["host"] == "x"
    form, ev, _ = normalize({"aiops_host": "bm1", "aiops_kind": "baremetal", "log": "ERROR ORA-00600 internal", "file": "/u01/alert.log"},
                            "", sev_from_text)
    assert form == "file" and ev.entity == "alert.log" and ev.severity == "error"


def test_fingerprint_per_host_for_guests():
    a = LogEvent(source="vm", connector="agent", host="vm1", entity="sshd", message="x", template="t")
    b = LogEvent(source="vm", connector="agent", host="vm2", entity="sshd", message="x", template="t")
    c = LogEvent(source="esxi", connector="syslog", host="esx1", entity="vmkernel", message="x", template="t")
    d = LogEvent(source="esxi", connector="syslog", host="esx2", entity="vmkernel", message="x", template="t")
    assert a.fingerprint() != b.fingerprint() and c.fingerprint() == d.fingerprint()


def test_redfish_event_parsing_and_dedupe():
    rc = RedfishConnector({"name": "srv-a", "host": "10.0.0.5", "username": "u", "password": "p", "esxi_host": "esx03"},
                          lambda e: asyncio.sleep(0))
    payload = {"@odata.type": "#Event.v1_7_0.Event", "Id": "1", "Name": "Event", "Events": [
        {"EventType": "Alert", "EventId": "77", "EventTimestamp": "2026-10-11T06:00:00Z", "MemberId": "0",
         "MessageId": "iLOEvents.2.3.PowerSupplyFailure", "Message": "Power Supply 2 has failed.", "MessageSeverity": "Critical",
         "OriginOfCondition": {"@odata.id": "/redfish/v1/Chassis/1"}}]}
    evs = rc.events_from(payload)
    assert len(evs) == 1 and evs[0].severity == "critical" and evs[0].host == "esx03" and evs[0].attrs["bmc"] == "10.0.0.5"
    assert rc.events_from(payload) == []                       # 같은 이벤트 재전송(push 재시도·SSE 재연결) 중복 제거
    legacy = {"Events": [{"EventType": "Alert", "EventId": "78", "MessageId": "Base.1.0.Success", "Severity": "OK", "Message": "test"}]}
    assert rc.events_from(legacy)[0].severity == "info"


class _WS:
    def __init__(self):
        self.sent, self.client = [], None

    async def send_text(self, t):
        self.sent.append(t)

    async def close(self, code=1000, reason=""):
        pass


def test_hub_tail_filter():
    async def main():
        hub = Hub({})
        w = _WS()
        hub.add(w, {"user": "a"}, lambda s: '{"type":"snapshot"}')
        hub.set_tail(w, {"hosts": ["db01.bank.local"], "min": "warning"})
        hub.publish_tail([{"host": "db01", "severity": "error", "message": "a", "source": "vm"},
                          {"host": "db01.bank.local", "severity": "info", "message": "b", "source": "vm"},
                          {"host": "was01", "severity": "critical", "message": "c", "source": "vm"},
                          {"host": "esx03", "severity": "critical", "message": "d", "source": "redfish", "attrs": {"bmc": "db01.bank.local"}}])
        await asyncio.sleep(0.02)
        return [json.loads(t) for t in w.sent if '"tail"' in t]
    msgs = asyncio.run(main())
    assert len(msgs) == 1 and [e["message"] for e in msgs[0]["data"]] == ["a", "d"]


def test_systemd_notifier_watchdog_stops_when_unready():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "n.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(path)
    srv.setblocking(False)
    os.environ["NOTIFY_SOCKET"], os.environ["WATCHDOG_USEC"] = path, "3000000"     # 3초 → 1초 주기
    try:
        n = SystemdNotifier()
        state = {"ok": True}

        async def main():
            t = asyncio.create_task(n.loop(lambda: (state["ok"], [] if state["ok"] else ["DB"]), lambda: "s", unready_grace=1.5))
            await asyncio.sleep(1.2)
            state["ok"] = False
            await asyncio.sleep(3.5)
            t.cancel()
        t0 = time.time()
        asyncio.run(main())
        msgs = []
        while True:
            try:
                msgs.append((time.time() - t0, srv.recv(4096).decode()))
            except BlockingIOError:
                break
    finally:
        os.environ.pop("NOTIFY_SOCKET"); os.environ.pop("WATCHDOG_USEC")
    wd = [m for m in msgs if m[1] == "WATCHDOG=1"]
    status = [m[1] for m in msgs if m[1].startswith("STATUS=")]
    assert 2 <= len(wd) <= 4                                   # 준비 상태 + 유예 1.5초 동안만 송신, 이후 중단 → systemd 재시작
    assert any("준비 안 됨: DB" in s for s in status)


def test_agent_purge_removes_registration_and_acks_stale_alert():
    from types import SimpleNamespace
    from app.agents import AgentRegistry

    class Store:
        def __init__(self): self.sql = []
        def schema(self, s): pass
        async def x(self, sql, args=()): self.sql.append((sql, args))
        async def q(self, sql, args=()): return []

    acked = []
    anomaly = SimpleNamespace(id="a1", ack=False, event={"host": "web01", "source": "aiops", "message": "agent stale: web01"})
    other = SimpleNamespace(id="a2", ack=False, event={"host": "web02", "source": "aiops", "message": "agent stale: web02"})

    async def ack(i): acked.append(i)
    eng = SimpleNamespace(store=Store(), anomalies={"a1": anomaly, "a2": other}, ack=ack)
    reg = AgentRegistry(eng)
    reg.heartbeat({"host": "WEB01", "kind": "vm"})
    reg.heartbeat({"host": "web02", "kind": "vm"})
    assert asyncio.run(reg.purge("web01")) is True
    assert "web01" not in reg.items and "web02" in reg.items
    assert "web01" not in reg._dirty
    assert ("DELETE FROM agents WHERE host=?", ("web01",)) in eng.store.sql
    assert acked == ["a1"]
    assert asyncio.run(reg.purge("web01")) is False


def test_agent_block_after_purge_drops_and_records_sender():
    from types import SimpleNamespace
    from app.agents import AgentRegistry

    class Store:
        def __init__(self): self.sql = []
        def schema(self, s): pass
        async def x(self, sql, args=()): self.sql.append((sql, args))
        async def q(self, sql, args=()): return []

    async def ack(i): pass
    eng = SimpleNamespace(store=Store(), anomalies={}, ack=ack)
    reg = AgentRegistry(eng)
    reg.seen({"host": "web01", "kind": "vm", "peer": "10.1.1.5"})
    assert asyncio.run(reg.purge("web01", by="admin")) is True
    assert "web01" in reg.blocked and any("agent_blocks" in q for q, _ in eng.store.sql)
    reg.heartbeat({"host": "WEB01", "peer": "10.1.1.9"})                    # 다시 보내도 등록 안 됨
    reg.seen({"host": "web01", "peer": "10.1.1.9"}, "error")
    ev = LogEvent(source="vm", connector="syslog", message="x", host="web01", attrs={"app": "vmx", "peer": "192.168.0.11"})
    reg.touch_syslog(ev)
    assert "web01" not in reg.items
    b = reg.blocks()[0]
    assert b["hits"] == 3 and b["peer"] == "192.168.0.11" and "vmx" in b["path"] and b["sending"] and b["by"] == "admin"
    assert asyncio.run(reg.unblock("web01")) and not reg.blocked
    reg.seen({"host": "web01", "peer": "10.1.1.9"})
    assert "web01" in reg.items
    assert asyncio.run(reg.purge("web01", block=False)) and not reg.blocked  # 차단 없이 삭제
