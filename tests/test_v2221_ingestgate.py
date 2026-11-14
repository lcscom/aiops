"""2.22.1 수집 일시정지 스위치 — 수동·자동·범위·재시작 유지·콘솔 요청·syslog 파싱 전 차단"""
import asyncio
import json
import time

from app.models import LogEvent


def _gate(tmp_path, monkeypatch=None):
    import app.main as M
    from app.ingestgate import IngestGate
    if monkeypatch is not None:
        async def nolog(*a, **k):
            return None
        monkeypatch.setattr(M.ENGINE.audit, "log", nolog)
    g = IngestGate(M.ENGINE, {"control_file": str(tmp_path / "ctl.json")}, str(tmp_path))
    return M, g


def test_pause_scopes_and_resume(tmp_path, monkeypatch):
    M, g = _gate(tmp_path, monkeypatch)
    ev = []
    monkeypatch.setattr(M.ENGINE, "submit", lambda e: ev.append(e) or True)

    async def go():
        await g.pause(None, "senders", ["10.0.0.10", "10.1.0.0/16", "vcsa01.corp.local"], by="t", reason="폭주")
        assert g.drop_raw("10.0.0.10") and g.drop_raw("10.1.2.3") and not g.drop_raw("10.2.0.1")
        assert g.drop_event(LogEvent(source="vcenter", connector="syslog", message="x", host="vcsa01.corp.local"))
        assert g.drop_event(LogEvent(source="vcenter", connector="syslog", message="x", host="VCSA01"))      # 짧은 이름·대소문자
        assert not g.drop_event(LogEvent(source="esxi", connector="syslog", message="x", host="esx01"))
        assert not g.drop_event(LogEvent(source="aiops", connector="x", message="x", host="vcsa01.corp.local"))   # 플랫폼 자체는 통과
        await g.pause(5, "syslog", by="t")
        assert g.drop_raw("1.2.3.4") and not g.drop_event(LogEvent(source="vcenter", connector="vcenter", message="x"))   # 폴링은 계속
        await g.pause(5, "all", by="t")
        assert g.drop_event(LogEvent(source="vcenter", connector="vcenter", message="x"))
        st = g.status()
        assert st["paused"] and st["left_s"] > 250 and st["dropped"] == 1
        g.until = time.time() - 1                                   # 만료 → 다음 단계에서 재개
        await g.step()
        assert not g.paused and g.history[0]["action"] == "resume"
        assert any("수집 일시정지" in e.message for e in ev) and any("수집 재개" in e.message for e in ev)
        import pytest
        with pytest.raises(ValueError):
            await g.pause(5, "senders", [], by="t")
        with pytest.raises(ValueError):
            await g.pause(5, "bogus", by="t")
    asyncio.run(go())


def test_auto_top_sender_and_backoff(tmp_path, monkeypatch):
    M, g = _gate(tmp_path, monkeypatch)
    monkeypatch.setattr(M.ENGINE, "submit", lambda e: True)

    async def go():
        await g.set_auto({"enabled": True, "max_eps": 50, "pause_minutes": 2, "consecutive": 2, "scope": "top_sender"}, "t")
        for _ in range(3):
            for _ in range(900):
                g.tick("10.0.0.10")
            for _ in range(100):
                g.tick("10.0.0.20")
            g._win.clear() if False else None
            await g.step()
            if g.paused:
                break
        assert g.paused and g.scope == "senders" and g.senders == {"10.0.0.10"} and g.by == "auto"
        assert 110 <= g.until - time.time() <= 121 and g.auto_level == 1
        g.until = time.time() - 1
        await g.step()
        assert not g.paused
        for _ in range(3):
            for _ in range(900):
                g.tick("10.0.0.10")
            await g.step()
            if g.paused:
                break
        assert g.paused and 230 <= g.until - time.time() <= 241       # 두 번째는 2배
    asyncio.run(go())


def test_persist_and_control_file(tmp_path, monkeypatch):
    M, g = _gate(tmp_path, monkeypatch)
    monkeypatch.setattr(M.ENGINE, "submit", lambda e: True)

    async def go():
        await M.ENGINE.store.x("DELETE FROM settings WHERE key='ingest_gate'")
        await g.pause(30, "senders", ["10.9.9.9"], by="admin")
        from app.ingestgate import IngestGate
        g2 = IngestGate(M.ENGINE, {"control_file": str(tmp_path / "ctl.json")}, str(tmp_path))
        await g2.load()
        assert g2.paused and g2.senders == {"10.9.9.9"} and g2.drop_raw("10.9.9.9")
        (tmp_path / "ctl.json").write_text(json.dumps({"action": "resume"}), encoding="utf-8")
        await g2.step()
        assert not g2.paused and not (tmp_path / "ctl.json").exists()
        (tmp_path / "ctl.json").write_text(json.dumps({"action": "pause", "minutes": 15, "scope": "syslog", "senders": ["10.0.0.1"], "reason": "콘솔"}), encoding="utf-8")
        await g2.step()
        assert g2.paused and g2.scope == "senders" and g2.by == "cli"
        await M.ENGINE.store.x("DELETE FROM settings WHERE key='ingest_gate'")
    asyncio.run(go())


def test_syslog_push_gated(monkeypatch):
    import app.main as M
    from app.connectors.syslog import SyslogReceiver
    from app.ingestgate import IngestGate
    got = []

    async def nolog(*a, **k):
        return None
    monkeypatch.setattr(M.ENGINE.audit, "log", nolog)
    monkeypatch.setattr(M.ENGINE, "submit", lambda e: got.append(e) or True)
    g = IngestGate(M.ENGINE, {}, "/tmp")
    monkeypatch.setattr(M.ENGINE, "gate", g)
    r = SyslogReceiver({"udp_port": 0, "tcp_port": 0}, M.ENGINE.ingest)
    r._submit = M.ENGINE.submit
    line = "<14>1 2026-11-09T00:00:00Z vcsa01 vpxd 1 - - hello"
    r._push(line, "10.0.0.10")
    assert len(got) == 1
    asyncio.run(g.pause(None, "senders", ["10.0.0.10"], by="t"))
    got.clear()
    r._push(line, "10.0.0.10")
    r._push(line, "10.0.0.11")
    assert len([e for e in got if e.source != "aiops"]) == 1 and r._state["paused_dropped"] == 1


def test_rbac_and_ui():
    import re
    from pathlib import Path

    from app.security.auth import ROUTE_RULES

    def perm(m, p):
        for mm, rx, pr in ROUTE_RULES:
            if (mm == "*" or mm == m) and re.search(rx, p):
                return pr
    assert perm("GET", "/api/ingest-gate") == "view" and perm("POST", "/api/ingest-gate") == "settings" and perm("PUT", "/api/ingest-gate/auto") == "settings"
    root = Path(__file__).resolve().parents[1]
    html = (root / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="ig-box"' in html and "/static/ingestgate.js" in html
    ctl = (root / "scripts/linux/vcf-aiopsctl").read_text(encoding="utf-8")
    assert "pause|resume|pause-status)" in ctl and "ingest-control.json" in ctl


def test_known_hosts_memory():
    import app.main as M
    M.ENGINE.hostseen["vcsa01.corp.local"] = [{"vcenter"}, 5, time.time()]
    M._KNOWN.update(t=0.0, seeded=True)
    items = asyncio.run(M.hosts_known())["items"]
    if True:
        assert any(i["host"] == "vcsa01.corp.local" and i["n"] >= 5 and "vcenter" in i["sources"] for i in items)
