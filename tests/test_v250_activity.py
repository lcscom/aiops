"""2.5.0 VM 액티비티 — 전원·구성 변경·스냅샷 · 위험 신호(업무 외·대량 삭제·보호 VM·단명 VM) · 일대기 · CSV · 규칙 API"""
import asyncio
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.models import LogEvent


def _vc(**cfg):
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc1", "host": "vc", "username": "u", "password": "p", **cfg}, None)
    c.topology = {"vms": {"app01": {"host": "esx01", "cluster": "CL1"}}, "hosts": {"esx01": {"cluster": "CL1"}}, "updated": 1}
    return c


def test_reconfig_power_snapshot_extracted():
    from pyVmomi import vim
    c = _vc()
    H = lambda n: vim.event.HostEventArgument(name=n, host=vim.HostSystem("host-1"))           # noqa: E731
    V = lambda n: vim.event.VmEventArgument(name=n, vm=vim.VirtualMachine("vm-1"))             # noqa: E731
    spec = vim.vm.ConfigSpec(numCPUs=8, memoryMB=16384, deviceChange=[
        vim.vm.device.VirtualDeviceSpec(operation="add", device=vim.vm.device.VirtualDisk(capacityInKB=100 * 1048576)),
        vim.vm.device.VirtualDeviceSpec(operation="remove", device=vim.vm.device.VirtualVmxnet3())])
    m = c._move_of(vim.event.VmReconfiguredEvent(vm=V("app01"), host=H("esx01"), configSpec=spec, userName="ops"))
    assert m["type"] == "reconfigured" and m["detail"] == "vCPU 8, 메모리 16 GB, 디스크 추가 100 GB, NIC 제거"
    ch = vim.event.ChangesInfoEventArgument(modified="config.hardware.memoryMB: 4096 -> 8192\nconfig.annotation: a -> b")
    m = c._move_of(vim.event.VmReconfiguredEvent(vm=V("app01"), host=H("esx01"), configSpec=vim.vm.ConfigSpec(), configChanges=ch))
    assert m["detail"].startswith("변경: config.hardware.memoryMB: 4096 -> 8192")
    assert c._move_of(vim.event.VmPoweredOffEvent(vm=V("app01"), host=H("esx01")))["type"] == "power_off"
    assert c._move_of(vim.event.VmGuestRebootEvent(vm=V("app01"), host=H("esx01")))["type"] == "guest_reboot"
    t = vim.event.TaskEvent(vm=V("app01"), host=H("esx01"), info=vim.TaskInfo(descriptionId="VirtualMachine.createSnapshot", entityName="app01", key="t1", task=vim.Task("task-1"), state="queued", cancelled=False, cancelable=False, queueTime=datetime.now()))
    assert c._move_of(t)["type"] == "snapshot_create"
    t2 = vim.event.TaskEvent(vm=V("app01"), info=vim.TaskInfo(descriptionId="VirtualMachine.powerOn", key="t2", task=vim.Task("task-2"), state="queued", cancelled=False, cancelable=False, queueTime=datetime.now()))
    assert c._move_of(t2) is None
    assert _vc(activity_power=False)._move_of(vim.event.VmPoweredOnEvent(vm=V("x"))) is None


def test_power_event_does_not_suppress_placement_detection():
    c = _vc()
    c._move_vms = set()
    from app.connectors import vcenter as V
    mv = {"type": "power_on", "vm": "app01", "from_host": "", "to_host": "esx02"}
    assert not (mv["type"] in V.LIFE_TYPES or (mv["type"] not in V.ACT_TYPES and mv["from_host"] != mv["to_host"]))


def _engine(tmp_path):
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False},
                            "vm_activity": {"protected": ["core-*"], "bulk_delete_count": 3, "bulk_delete_minutes": 10}})
    from app.engine import Engine
    return Engine(cfg)


def _ts(y, mo, d, h, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=ZoneInfo("Asia/Seoul")).timestamp()


def test_risk_flags_and_events(tmp_path):
    async def main():
        e = _engine(tmp_path)
        raised = []
        orig = e.submit
        e.submit = lambda ev: (raised.append(ev), orig(ev))[1]
        n = iter(range(1000))

        def ev(mv, ts):
            return LogEvent(source="vcenter", connector="vc1", message="m", ts=ts, native_id=str(next(n)), attrs={"move": {"vcenter": "vc1", **mv}})
        wk_day, sat = _ts(2026, 10, 14, 11), _ts(2026, 10, 17, 11)       # 수요일 11시 / 토요일
        r1 = e.moves.record(ev({"type": "reconfigured", "vm": "web01", "user": "ops"}, wk_day))
        r2 = e.moves.record(ev({"type": "reconfigured", "vm": "web01", "user": "ops"}, _ts(2026, 10, 14, 22)))
        r3 = e.moves.record(ev({"type": "power_off", "vm": "web01", "user": "ops"}, sat))
        r4 = e.moves.record(ev({"type": "drs", "vm": "web01", "from_host": "a", "to_host": "b"}, sat))                     # 시스템 → 업무 외 아님
        r5 = e.moves.record(ev({"type": "reconfigured", "vm": "web02", "user": "VSPHERE.LOCAL\\vpxd-extension-1"}, sat))  # 서비스 계정
        assert r1["flags"] == "" and r2["flags"] == "offhours" and r3["flags"] == "offhours" and r4["flags"] == "" and r5["flags"] == ""
        p = e.moves.record(ev({"type": "removed", "vm": "core-bank-01", "from_host": "esx01", "user": "adm"}, wk_day + 60))
        assert "protected" in p["flags"] and any(x.attrs.get("vm_activity") == "protected" and x.severity == "critical" for x in raised)
        e.moves.record(ev({"type": "created", "vm": "tmp-1", "to_host": "esx01", "user": "dev"}, wk_day + 100))
        rows = [e.moves.record(ev({"type": "removed", "vm": f"tmp-{i}", "from_host": "esx01", "user": "dev"}, wk_day + 200 + i * 30)) for i in range(1, 4)]
        assert "short_lived" in rows[0]["flags"] and "수명" in rows[0]["detail"]
        assert "bulk_delete" in rows[2]["flags"]
        assert all("bulk_delete" in r["flags"] for r in rows)                                  # 앞선 행도 표시
        bulk = [x for x in raised if x.attrs.get("vm_activity") == "bulk_delete"]
        assert len(bulk) == 1 and "3대" in bulk[0].message and bulk[0].severity == "critical"
        e.moves.record(ev({"type": "removed", "vm": "tmp-9", "from_host": "esx01", "user": "dev"}, wk_day + 400))
        assert len([x for x in raised if x.attrs.get("vm_activity") == "bulk_delete"]) == 1    # 같은 창 재경보 없음
        await asyncio.sleep(0.2)
        e.moves.recent.clear()                                                                   # DB 에서도 flags·detail 유지
        db = await e.moves.query(24 * 30, flag="bulk_delete")
        s = await e.moves.summary(24 * 30)
        return db, s
    db, s = asyncio.run(main())
    assert len(db) == 4 and all("bulk_delete" in r["flags"] for r in db)
    assert s["risk_counts"]["bulk_delete"] == 4 and s["risk_counts"]["protected"] == 1 and s["offhours_total"] == 2
    dev = next(a for a in s["actors"] if a["user"] == "dev")
    assert dev["risk"] == 4 and not dev["service"] and dev["cats"]["delete"] == 4


def test_rules_validation_and_persist(tmp_path):
    from app.vmmoves import clean_rules
    with pytest.raises(ValueError):
        clean_rules({"business_hours": "9-18"})
    with pytest.raises(ValueError):
        clean_rules({"holidays": "2026-13-01"})
    with pytest.raises(ValueError):
        clean_rules({"tz": "Mars/Base"})
    r = clean_rules({"business_days": "1,2,3", "protected": "a*\nb*", "bulk_delete_count": "7"})
    assert r["business_days"] == [1, 2, 3] and r["protected"] == ["a*", "b*"] and r["bulk_delete_count"] == 7

    async def main():
        e = _engine(tmp_path)
        assert e.moves.rules()["protected"] == ["core-*"]                     # config 초기값
        await e.moves.save_rules({"holidays": ["2026-10-09"], "protected": ["db*"]}, "admin")
        e2 = _engine(tmp_path)                                                  # 재기동 후에도 DB 값
        return e2.moves.rules_view(), e2.moves.offhours(_ts(2026, 10, 9, 11)), e2.moves.offhours(_ts(2026, 10, 8, 11))
    v, hol, work = asyncio.run(main())
    assert v["rules"]["protected"] == ["db*"] and v["by"] == "admin" and hol is True and work is False


def test_timeline_follows_rename_and_csv(tmp_path):
    async def main():
        e = _engine(tmp_path)
        t0 = time.time() - 3600
        n = iter(range(1000))

        def ev(mv, dt_):
            return LogEvent(source="vcenter", connector="vc1", message="m", ts=t0 + dt_, native_id=str(next(n)), attrs={"move": {"vcenter": "vc1", **mv}})
        e.moves.record(ev({"type": "deployed", "vm": "old", "to_host": "esx01", "user": "ops", "source": "tpl"}, 0))
        e.moves.record(ev({"type": "reconfigured", "vm": "old", "to_host": "esx01", "detail": "vCPU 4"}, 10))
        e.moves.record(ev({"type": "renamed", "vm": "new", "to_host": "esx01", "source": "old"}, 20))
        e.moves.record(ev({"type": "vmotion", "vm": "new", "from_host": "esx01", "to_host": "esx02"}, 30))
        e.moves.record(ev({"type": "cloned", "vm": "child", "to_host": "esx02", "source": "new"}, 40))
        t = await e.moves.timeline("new")
        csv = e.moves.to_csv(await e.moves.query(24))
        return t, csv
    t, csv = asyncio.run(main())
    assert t["names"] == ["new", "old"] and t["born"]["type"] == "deployed" and t["born"]["source"] == "tpl"
    assert [r["type"] for r in t["items"]][-1] == "deployed" and len(t["items"]) == 5
    assert [r["vm"] for r in t["children"]] == ["child"] and t["cats"]["config"] == 2
    assert csv.startswith("﻿시각,유형") and "템플릿 배포" in csv and "vCPU 4" in csv


def test_route_permissions():
    from app.security.auth import AuthManager as Auth
    assert Auth.required_perm("PUT", "/api/vm/activity/rules") == "settings"
    assert Auth.required_perm("GET", "/api/vm/activity.csv") == "view"
