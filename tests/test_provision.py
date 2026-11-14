"""수집 전용 계정 자동 생성 — 제품별 REST 흐름(모의 서버)·비밀번호 생성·검증 실패 처리."""
import asyncio
import json
import re
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import provision as P  # noqa: E402


def mock(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(base, verify, timeout=30):
        return real(base_url=base, transport=httpx.MockTransport(handler), headers={"Accept": "application/json"})
    monkeypatch.setattr(P, "_client", factory)


def test_password_policy():
    for _ in range(200):
        pw = P.gen_password()
        assert len(pw) == 20 and re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw) and re.search(r"\d", pw)
        assert re.search(r"[!@#%^*\-_=+]", pw) and not re.search(r"(.)\1\1", pw) and not re.search(r"[\s'\"$\\`]", pw)


def test_nsx_41_create_activate(monkeypatch):
    calls = []

    def h(req: httpx.Request):
        calls.append((req.method, req.url.path, dict(req.url.params), json.loads(req.content or b"null")))
        auth = req.headers.get("authorization", "")
        if req.url.path == "/api/v1/node/version":
            return httpx.Response(200, json={"product_version": "4.2.1.0.0"})
        if req.url.path == "/api/v1/node/users" and req.method == "GET":
            return httpx.Response(200, json={"results": [{"userid": 0, "username": "root"}, {"userid": 10000, "username": "admin"}]})
        if req.url.path == "/api/v1/node/users" and req.method == "POST":
            assert req.url.params["action"] == "create_user"
            return httpx.Response(201, json={"userid": 10003, "username": "svc-aiops-ro", "status": "NOT_ACTIVATED"})
        if req.url.path == "/api/v1/node/users/10003" and req.method == "POST":
            assert req.url.params["action"] == "activate" and json.loads(req.content)["password"]
            return httpx.Response(200, json={"status": "ACTIVE"})
        if req.url.path == "/api/v1/node/users/10003" and req.method == "PUT":
            return httpx.Response(200, json={})
        if req.url.path == "/api/v1/aaa/role-bindings" and req.method == "GET":
            return httpx.Response(200, json={"results": [{"name": "svc-aiops-ro", "roles_for_paths": [{"path": "/", "roles": [{"role": "auditor"}]}]}]})
        return httpx.Response(404)
    mock(monkeypatch, h)
    monkeypatch.setattr(asyncio, "sleep", lambda s: _noop())
    r = asyncio.run(P.provision({"type": "nsx", "host": "nsx.lab", "admin_user": "admin", "admin_password": "x"}))
    assert r["ok"], r
    assert r["username"] == "svc-aiops-ro" and len(r["password"]) == 20 and r["role"] == "auditor"
    paths = [(m, p) for m, p, _, _ in calls]
    assert ("POST", "/api/v1/node/users") in paths and ("POST", "/api/v1/node/users/10003") in paths
    put = [b for m, p, _, b in calls if m == "PUT"]
    assert {"password_change_frequency": 0} in put


async def _noop():
    return None


def test_nsx_old_uses_audit(monkeypatch):
    def h(req):
        if req.url.path == "/api/v1/node/version":
            return httpx.Response(200, json={"product_version": "3.2.3.0.0"})
        if req.url.path == "/api/v1/node/users" and req.method == "GET":
            return httpx.Response(200, json={"results": [{"userid": 10002, "username": "audit", "status": "NOT_ACTIVATED"}]})
        if req.url.path == "/api/v1/node/users/10002":
            return httpx.Response(200, json={"status": "ACTIVE"})
        if req.url.path == "/api/v1/aaa/role-bindings":
            return httpx.Response(200, json={"results": []}) if req.method == "GET" else httpx.Response(201, json={})
        return httpx.Response(404)
    mock(monkeypatch, h)
    monkeypatch.setattr(asyncio, "sleep", lambda s: _noop())
    r = asyncio.run(P.provision({"type": "nsx", "host": "nsx.lab", "admin_user": "admin", "admin_password": "x"}))
    assert r["ok"] and r["username"] == "audit"
    assert any("4.1+" in w for w in r["warnings"])


def test_nsx_rejects_extra_roles(monkeypatch):
    def h(req):
        if req.url.path == "/api/v1/node/version":
            return httpx.Response(200, json={"product_version": "4.1.2"})
        if req.url.path == "/api/v1/node/users" and req.method == "GET":
            return httpx.Response(200, json={"results": [{"userid": 10004, "username": "svc-aiops-ro", "status": "ACTIVE"}]})
        if req.url.path == "/api/v1/aaa/role-bindings":
            return httpx.Response(200, json={"results": [{"roles_for_paths": [{"path": "/", "roles": [{"role": "enterprise_admin"}]}]}]})
        return httpx.Response(200, json={})
    mock(monkeypatch, h)
    r = asyncio.run(P.provision({"type": "nsx", "host": "nsx.lab", "admin_user": "admin", "admin_password": "x"}))
    assert not r["ok"] and "enterprise_admin" in r["error"] and r["steps"]


def test_vcfops(monkeypatch):
    seen = {}

    def h(req):
        if req.url.path == "/suite-api/api/auth/token/acquire":
            b = json.loads(req.content)
            return httpx.Response(200, json={"token": "T-" + b["username"]})
        if req.url.path == "/suite-api/api/auth/roles":
            return httpx.Response(200, json={"userRoles": [{"name": "Administrator"}, {"name": "ReadOnly"}]})
        if req.url.path == "/suite-api/api/auth/users" and req.method == "GET":
            return httpx.Response(200, json={"users": []})
        if req.url.path == "/suite-api/api/auth/users" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            assert req.headers["authorization"] == "OpsToken T-admin"
            return httpx.Response(201, json={"id": "u1"})
        return httpx.Response(404)
    mock(monkeypatch, h)
    r = asyncio.run(P.provision({"type": "vcfops", "host": "ops.lab", "admin_user": "admin", "admin_password": "x"}))
    assert r["ok"] and r["role"] == "ReadOnly"
    assert seen["body"]["role-permissions"] == [{"roleName": "ReadOnly", "allowAllObjects": True}]
    assert seen["body"]["password"] == r["password"]


def test_vcflogs_no_email(monkeypatch):
    seen = {}

    def h(req):
        assert req.url.port == 9543
        if req.url.path == "/api/v2/sessions":
            return httpx.Response(200, json={"sessionId": "S", "userId": "x", "ttl": 1800})
        if req.url.path == "/api/v2/roles":
            return httpx.Response(200, json={"roles": [{"id": "r1", "name": "Super Admin"}, {"id": "r9", "name": "View Only Admin"}]})
        if req.url.path == "/api/v2/users" and req.method == "GET":
            return httpx.Response(200, json={"users": []})
        if req.url.path == "/api/v2/users" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return httpx.Response(201, json={"id": "u1"})
        return httpx.Response(404)
    mock(monkeypatch, h)
    r = asyncio.run(P.provision({"type": "vcflogs", "host": "logs.lab", "admin_user": "admin", "admin_password": "x"}))
    assert r["ok"] and r["role"] == "View Only Admin"
    assert "email" not in seen["body"] and seen["body"]["roleIds"] == ["r9"]   # email 이 있으면 비밀번호 무시(KB 382067)


def test_sddc_viewer(monkeypatch):
    seen = {}

    def h(req):
        if req.url.path == "/v1/tokens":
            return httpx.Response(200, json={"accessToken": "A", "refreshToken": {"id": "r"}})
        if req.url.path == "/v1/roles":
            return httpx.Response(200, json={"elements": [{"id": "1", "name": "ADMIN"}, {"id": "3", "name": "VIEWER"}]})
        if req.url.path == "/v1/users" and req.method == "GET":
            return httpx.Response(200, json={"elements": []})
        if req.url.path == "/v1/users" and req.method == "POST":
            seen["body"] = json.loads(req.content)
            return httpx.Response(200, json={"elements": [{"id": "x"}]})
        return httpx.Response(404)
    mock(monkeypatch, h)
    r = asyncio.run(P.provision({"type": "sddc", "host": "sddc.lab", "admin_user": "administrator@vsphere.local",
                                 "admin_password": "x", "new_user": "readonly@vsphere.local"}))
    assert r["ok"] and r["role"] == "VIEWER"
    assert seen["body"] == [{"name": "readonly@vsphere.local", "domain": "vsphere.local", "type": "USER", "role": {"id": "3"}}]


def test_unsupported_and_missing():
    with pytest.raises(P.ProvisionError):
        asyncio.run(P.provision({"type": "avi", "host": "x", "admin_user": "a", "admin_password": "b"}))
    with pytest.raises(P.ProvisionError):
        asyncio.run(P.provision({"type": "nsx", "host": "", "admin_user": "a", "admin_password": "b"}))


def test_vcenter_vcsim_flow():
    """vcsim + govc 가 있으면 실제 pyVmomi·SSO 경로 확인. vcsim 의 유효 권한 조회는 항상 Admin 권한을 돌려주므로
    (simulator/authorization_manager.go) 검증 단계가 '허용 밖 권한'으로 멈추고 부여한 권한을 회수하는 것이 정상."""
    import os
    import socket
    govc = "/var/tmp/govc/govc"
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    if not os.path.exists(govc):
        pytest.skip("govc 없음")
    os.environ["AIOPS_GOVC"] = govc
    r = asyncio.run(P.provision({"type": "vcenter", "host": "127.0.0.1:8989", "admin_user": "administrator@vsphere.local",
                                 "admin_password": "pass", "new_user": "pytest-ro", "reset_password": True, "vks_rbac": False}))
    steps = {s["step"]: s["ok"] for s in r["steps"]}
    assert steps.get("SSO 그룹 점검") is True and steps.get("권한 부여") is True
    assert not r["ok"] and "허용 밖 유효 권한" in r["error"] and "회수" in r["error"]
