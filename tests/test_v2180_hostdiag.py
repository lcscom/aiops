"""2.18.0 호스트 분석 — 끊김 구간 검출·원인 판정(사용자·hostd·관리망)·동시 끊김·syslog 판별·반복 패턴, 매니저·API·권한·CSV·AI (합성 데이터만)"""
import asyncio
import json
import time

import pytest

from app.hostdiag import analyze as A
from app.hostdiag.parse import is_down, is_up, line_ts
from tests.hostdiag_fake import H, PEER, rows, seed
from tests.test_v2110_support import _engine


def test_parse():
    assert line_ts("2026-11-03T22:15:58.123Z vmkwarning: x") == pytest.approx(1793744158.123)
    assert line_ts("2026-11-04T07:15:58.123+09:00 info vpxd") == pytest.approx(1793744158.123)
    assert line_ts("2026-11-03T22:15:58 no tz") == pytest.approx(1793744158)          # 시간대 없으면 UTC
    assert line_ts("junk") is None and line_ts("") is None
    assert is_down({"type": "HostConnectionLostEvent", "message": "x"}) and is_down({"type": "HostDisconnectedEvent", "message": ""})
    assert is_down({"type": "", "message": "[VpxdInvtHostSyncHostLRO] connection state changed to NO_RESPONSE"})
    assert is_up({"type": "HostConnectedEvent", "message": ""}) and not is_up({"type": "VmPoweredOnEvent", "message": "powered on"})
    assert not is_down({"type": "VmPoweredOnEvent", "message": "vm powered on"})


def _stored(now):
    return [{**r, "id": i, "connector": "x"} for i, r in enumerate(rows(now))]


def test_analyze_fixture():
    now = time.time()
    peers_db = [r for r in rows(now) if r["host"] == PEER]

    def peers(ts):
        return [{"ts": r["ts"], "host": r["host"], "message": r["message"]} for r in peers_db if abs(r["ts"] - ts) <= 120 and "not responding" in r["message"]]
    res = A.analyze(H, None, [r for r in _stored(now) if r["host"] == H], now - 86400, now, peers, {"lines_24h": 50, "last": now - 10})
    eps = res["episodes"]
    assert res["counts"]["episodes"] == 3 and not res["counts"]["ongoing"] and res["counts"]["downtime_s"] > 0
    assert [e["start"] < now - 1800 for e in eps] == [True] * 3 and eps[0]["start"] > eps[1]["start"] > eps[2]["start"]   # 최신 먼저
    user, agent, net = eps
    assert user["user_initiated"] and user["causes"][0]["id"] == "user" and user["causes"][0]["confidence"] == "높음"
    assert agent["causes"][0]["id"] == "agent" and any("syslog" in n and "수신" in n for n in agent["notes"])
    assert net["causes"][0]["id"] in ("network", "mass") and {"network", "mass"} <= {c["id"] for c in net["causes"]}
    assert any("syslog 도 끊김" in n for n in net["notes"]) and any(PEER in n and "377738" in n for n in net["notes"])
    assert all(c["kb"].startswith("https://knowledge.broadcom.com/") for e in eps for c in e["causes"])
    assert res["patterns"] and res["counts"]["by_source"]
    assert all(it["ts"] >= now - 86400 for it in res["items"]) and res["items"] == sorted(res["items"], key=lambda x: x["ts"])


def test_judge_no_evidence_and_ip_mismatch():
    now = time.time()
    items = [{"ts": now - 600, "kind": "event", "type": "HostConnectionLostEvent", "message": f"Host {H} is not responding", "source": "vcenter"},
             {"ts": now - 300, "kind": "event", "type": "HostConnectedEvent", "message": f"Connected to {H}", "source": "vcenter"}]
    ep = A.episodes(items, now)
    assert len(ep) == 1 and ep[0]["duration"] == pytest.approx(300, abs=1)
    j = A.judge(ep[0], items, state={"vc_managed_ip": "10.0.0.5", "vc_ip_seen_by_host": "10.0.0.9"}, syslog_rate={"lines_24h": 0})
    assert j["causes"][0]["id"] == "heartbeat" and any("10.0.0.9" in n for n in j["notes"]) and any("syslog 를 받고 있지 않아" in n for n in j["notes"])
    ongoing = A.episodes(items[:1], now)
    assert ongoing[0]["ongoing"] and ongoing[0]["end"] is None


class FakeVC:
    type = "vcenter"
    name = "lab-vc"
    calls = []

    def __init__(self, fail=False):
        self.fail = fail
        self.topology = {"hosts": {H: {"cluster": "Cluster-01", "conn": "connected"}, PEER: {"cluster": "Cluster-01", "conn": "connected"}}}

    def host_diag(self, name, start, end, logs=True):
        self.calls.append((name, logs))
        if self.fail:
            raise RuntimeError("boom")
        return {"vcenter": self.name, "host": name, "events": [], "tasks": [
                    {"ts": end - 3600 - 2, "end": end - 3600, "name": "host.Disconnect", "state": "success", "user": "LAB\\admin", "entity": name, "error": ""}],
                "logs": [], "gaps": ["DiagnosticManager 미지원"],
                "state": {"connection": "connected", "mgmt_ip": "10.0.0.15", "vc_managed_ip": "", "version": "8.0.3", "build": "24022510"}}


def test_manager_api_permissions(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_hostdiag import build_router
    from app.security.auth import AuthManager
    e = _engine(tmp_path)
    e.connectors = [FakeVC()]
    now = time.time()
    asyncio.run(seed(e.store, now))
    M = e.hostdiag

    hs = asyncio.run(M.hosts(1))
    by = {x["name"]: x for x in hs["items"]}
    assert by[H]["disconnects"] == 3 and by[PEER]["disconnects"] >= 1 and hs["items"][0]["name"] == H and by[H]["syslog_24h"] > 0
    res = asyncio.run(M.analyze(H, now - 86400, now))
    assert res["counts"]["episodes"] == 3 and res["vcenter"] == "lab-vc" and res["state"]["mgmt_ip"] == "10.0.0.15"
    assert "DiagnosticManager 미지원" in res["gaps"] and any(it["kind"] == "task" for it in res["items"])
    assert any(PEER in n for e_ in res["episodes"] for n in e_["notes"])
    with pytest.raises(ValueError):
        asyncio.run(M.analyze(H, now, now - 1))
    with pytest.raises(ValueError):
        asyncio.run(M.analyze(H, now - 40 * 86400, now))
    e.connectors = [FakeVC(fail=True)]
    r2 = asyncio.run(M.analyze(H, now - 86400, now))
    assert "vCenter 조회 실패" in r2["error"] and r2["counts"]["episodes"] == 3            # 저장된 로그만으로도 분석
    e.connectors = []
    assert "커넥터가 없음" in asyncio.run(M.analyze(H, now - 86400, now))["error"]
    e.connectors = [FakeVC()]

    class FakeLLM:
        seen = {}

        async def complete(self, system, user, max_tokens=0, task="", names=None):
            self.seen.update(system=system, user=user, task=task, names=names)
            return "## 결론\n관리망"
    e.llm = FakeLLM()
    logs, role = [], {"r": "operator"}

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append(action)
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda req: {"user": "op1", "role": role["r"]}, audit))
    with TestClient(app) as cl:
        assert cl.get("/api/hostdiag/hosts?days=1").json()["items"][0]["name"] == H
        r = cl.get(f"/api/hostdiag/host?name={H}&hours=24").json()
        assert r["counts"]["episodes"] == 3 and "hostdiag.analyze" in logs
        assert cl.get("/api/hostdiag/host?name=x&start=10&end=5").status_code == 400
        c = cl.get(f"/api/hostdiag/host.csv?name={H}")
        assert c.content.startswith("﻿".encode()) and b"HostConnectionLostEvent" in c.content and c.content.decode("utf-8-sig").splitlines()[0].startswith("time,kind")
        assert cl.get("/api/hostdiag/host.csv?name=none").status_code == 404
        a = cl.post("/api/hostdiag/ai", json={"name": H}).json()
        assert "관리망" in a["report"] and FakeLLM.seen["task"] == "report" and H in FakeLLM.seen["names"] and PEER in FakeLLM.seen["names"]
        assert "344682" in FakeLLM.seen["system"] and json.loads(FakeLLM.seen["user"])["끊김횟수"] == 3
        assert cl.post("/api/hostdiag/ai", json={"name": "none"}).status_code == 404
    rp = AuthManager.required_perm
    assert rp("GET", "/api/hostdiag/hosts") == "view" and rp("GET", "/api/hostdiag/host") == "view"
    assert rp("POST", "/api/hostdiag/ai") == "operate"


def test_ui_wired():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app" / "static"
    idx = (root / "index.html").read_text()
    assert 'data-nav="hd"' in idx and 'id="drawer-hd"' in idx
    assert idx.index("/static/hostdiag.js") < idx.index("/static/layout.js") and idx.rstrip().rfind("layout.js") > idx.rfind("hostdiag.js")
    js = (root / "hostdiag.js").read_text()
    assert "AIOPS_HOSTDIAG" in js and "/api/hostdiag/host" in js


def test_vcsim_host_diag():
    """실제 pyVmomi 경로(vcsim) — 작업 조회, DiagnosticManager 미지원은 공백 메시지로"""
    import socket
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "sim", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, lambda e: None)
    c.topology = {"hosts": {}}
    now = time.time()
    r = c.host_diag("DC0_H0", now - 86400 * 3, now + 60)
    assert r["host"] == "DC0_H0" and r["state"]["connection"] and isinstance(r["events"], list) and isinstance(r["tasks"], list)
    assert all(isinstance(g, str) and "\n" not in g for g in r["gaps"])
    assert "error" in c.host_diag("no-such-host", now - 3600, now)
