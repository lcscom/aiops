"""2.18.1 조치 승인 — admin 역할만 본인 요청 승인(감사 self_approved), 그 외 역할은 4-eyes 유지, 설정으로 끄기"""
import asyncio
import time

import pytest

from app.actions import ActionGate
from tests.test_v2110_support import _engine


def _gate(tmp_path, **cfg):
    e = _engine(tmp_path)
    g = ActionGate(e, {"approval_ttl_hours": 4, **cfg})
    ran = []

    async def fake_exec(aid, actor):
        ran.append((aid, actor))
    g._execute = fake_exec
    return e, g, ran


async def _pending(g, user):
    await g.store.x("INSERT INTO actions(incident_id,action,connector,target,params,level,status,reason,requested_by,requested_at,preview) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("", "vc_syslog_add", "vc", "aiops.lab", "{}", 3, "pending_approval", "test", user, time.time(), "{}"))
    return (await g.store.q("SELECT max(id) AS i FROM actions"))[0]["i"]


def test_admin_self_approve(tmp_path):
    e, g, ran = _gate(tmp_path)
    audits = []
    orig = e.audit.log

    async def log(action, **kw):
        audits.append((action, kw.get("detail")))
        return await orig(action, **kw)
    e.audit.log = log

    async def main():
        a = await _pending(g, "admin")
        r = await g.approve(a, "admin", "admin", "127.0.0.1")
        assert r["status"] == "approved" and r["approved_by"] == "admin"
        assert ("action.approve", {"id": a, "self_approved": True}) in audits
        b = await _pending(g, "op1")
        with pytest.raises(PermissionError):
            await g.approve(b, "op1", "operator", "127.0.0.1")           # admin 이 아니면 4-eyes
        assert (await g.approve(b, "admin", "admin", "127.0.0.1"))["status"] == "approved"
        assert ("action.approve", {"id": b, "self_approved": False}) in audits
        await asyncio.sleep(0)
    asyncio.run(main())
    assert len(ran) == 2


def test_admin_self_approve_disabled(tmp_path):
    e, g, ran = _gate(tmp_path, admin_self_approve=False)

    async def main():
        a = await _pending(g, "admin")
        with pytest.raises(PermissionError):
            await g.approve(a, "admin", "admin", "127.0.0.1")
    asyncio.run(main())
