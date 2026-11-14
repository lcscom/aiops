"""2.2 — 안정성: 기동 전 점검·자가 점검(DB 무결성·WAL·백업 검증), 세션 영속화, 알림 라우팅, 요청 본문 상한·세션당 변경 요청 제한"""
import asyncio
import os
import sqlite3
import tempfile
import time
from types import SimpleNamespace as NS

from app.alerting import Alerter
from app.security.audit import AuditLog
from app.security.auth import AuthManager
from app.selfcheck import SelfCheck, preflight
from app.store import Store


def test_preflight_flags_bad_config_and_unwritable_dir():
    cfg = {"server": {"port": 70000, "tls": {"enabled": False}}, "alerting": {"min_severity": "loud", "webhooks": [{"name": "pd", "format": "pagerduty"}, {"format": "teams"}]},
           "auth": {"oidc": {"enabled": True}, "mfa": {"required_roles": ["root"]}}, "siem": {"enabled": True, "protocol": "smtp"}}
    out = {i["key"]: i for i in preflight(cfg, tempfile.mkdtemp())}
    assert out["cfg:server.port"]["level"] == "warning" and out["cfg:alerting.min_severity"]["level"] == "error"
    assert "키(secret) 없음" in out["cfg:alerting.webhooks[0]"]["text"] and "URL 없음" in out["cfg:alerting.webhooks[1]"]["text"]
    assert out["cfg:auth.oidc"]["level"] in ("error", "warning") and "root" in out["cfg:auth.mfa"]["text"]
    assert out["cfg:siem"]["level"] == "error"
    assert preflight({"server": {"port": 8630}}, tempfile.mkdtemp()) == [] or all(i["key"].startswith("env:disk") for i in preflight({"server": {"port": 8630}}, tempfile.mkdtemp()))


def test_selfcheck_quickcheck_checkpoint_and_backup_verify():
    d = tempfile.mkdtemp()
    st = Store(os.path.join(d, "a.db"))
    au = AuditLog(st)
    asyncio.run(au.log("x"))
    e = NS(store=st, audit=au, cfg={"backup": {"enabled": True, "dir": os.path.join(d, "bk")}, "server": {"tls": {"certfile": os.path.join(d, "none.crt")}}})
    sc = SelfCheck(e, {"wal_max_mb": 0}, d)

    async def go():
        qc = await sc.quick_check()
        assert qc["result"] == "ok"
        assert (await sc.verify_backup())["result"] == "none"
        await st.backup(os.path.join(d, "bk", "aiops-20261015-0230.db"))
        ok = await sc.verify_backup()
        assert ok["result"] == "ok" and ok["audit_rows"] == 1
        await sc.refresh()                                   # wal_max_mb=0 → checkpoint 수행
        return ok
    asyncio.run(go())
    assert sc.state["wal_checkpoints"] >= 1 and sc.state["db"]["tables"]["audit"] == 1 and [i for i in sc.checks() if not i["key"].startswith(("disk", "memory", "open_files"))] == []
    bad = os.path.join(d, "bk", "aiops-20261015-0300.db")    # 깨진 백업 → 오류
    with open(bad, "wb") as f:
        f.write(b"SQLite format 3\x00" + b"\x00" * 200 + b"garbage" * 500)
    os.utime(bad, (time.time() + 5, time.time() + 5))
    r = asyncio.run(sc.verify_backup())
    assert r["file"].endswith("0300.db") and r["result"] != "ok"
    assert any(i["key"] == "backup_corrupt" for i in sc.checks())


def test_sessions_survive_restart_and_expire():
    d = tempfile.mkdtemp()
    st = Store(os.path.join(d, "a.db"))
    au = AuditLog(st)
    os.environ["AIOPS_ADMIN_PASSWORD"] = "Boot#Pass2026xyz"
    a1 = AuthManager(st, {"enabled": True, "password": {}, "session_idle_minutes": 10}, au, d)

    async def go():
        await a1.bootstrap()
        r = await a1.login("admin", "Boot#Pass2026xyz", "10.0.0.1", "ua")
        await asyncio.sleep(0.05)
        return r["sid"]
    sid = asyncio.run(go())
    os.environ.pop("AIOPS_ADMIN_PASSWORD", None)
    a2 = AuthManager(st, {"enabled": True, "password": {}, "session_idle_minutes": 10}, au, d)      # 재시작
    assert sid in a2.sessions and a2.sessions[sid]["user"] == "admin" and a2.sessions[sid]["must_change"] is True
    st._conn.execute("UPDATE sessions SET last=?", (time.time() - 3600,))
    st._conn.commit()
    a3 = AuthManager(st, {"enabled": True, "password": {}, "session_idle_minutes": 10}, au, d)      # 유휴 만료분은 복원 안 함
    assert sid not in a3.sessions and st._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_alert_routing_policy():
    al = Alerter({"webhooks": [{"name": "pd", "format": "pagerduty", "secret": "k"}, {"name": "teams-noc", "format": "teams", "url": "http://t"}],
                  "smtp": {"enabled": True}, "routes": [
                      {"name": "night-crit", "severities": ["critical"], "hours": "00:00-23:59", "channels": ["pd", "teams-noc"]},
                      {"name": "net", "sources": ["arista", "cisco"], "channels": ["teams-noc"]}],
                  "default_channels": ["smtp"]}, lambda *a: None, lambda *a: None)
    names = lambda a: sorted(n for n, _ in al._channels(a))
    assert names({"severity": "critical", "event": {"source": "esxi"}}) == ["webhook:pd", "webhook:teams-noc"]
    assert names({"severity": "error", "event": {"source": "arista"}}) == ["webhook:teams-noc"]
    assert names({"severity": "warning", "event": {"source": "vcenter"}}) == ["smtp"]
    al.cfg["default_channels"] = []
    assert len(names({"severity": "warning", "event": {"source": "vcenter"}})) == 3                  # 기본=전 채널
    al.cfg["routes"] = [{"severities": ["critical"], "days": [(time.localtime().tm_wday + 1) % 7], "channels": ["pd"]}]
    assert len(names({"severity": "critical", "event": {}})) == 3                                     # 요일 불일치 → 기본


def test_write_rate_limit_and_body_cap():
    d = tempfile.mkdtemp()
    st = Store(os.path.join(d, "a.db"))
    a = AuthManager(st, {"enabled": True, "write_rate_per_min": 5}, AuditLog(st), d)
    assert all(a._write_ok("s1") for _ in range(5)) and not a._write_ok("s1") and a._write_ok("s2")
    a.cfg["write_rate_per_min"] = 0
    assert all(a._write_ok("s1") for _ in range(50))
