"""2.4.2 VM 액티비티 — 생성·복제·배포·등록·삭제·이름 변경·생성 실패 이벤트 + 인벤토리 비교(새 VM·사라진 VM)"""
import asyncio
import time

from app.models import LogEvent


def _vc():
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc1", "host": "vc", "username": "u", "password": "p"}, None)
    c.topology = {"vms": {"app01": {"host": "esx01", "cluster": "CL1"}}, "hosts": {"esx01": {"cluster": "CL1"}, "esx02": {"cluster": "CL1"}}, "updated": 1}
    return c


def test_lifecycle_events_extracted():
    from pyVmomi import vim
    c = _vc()
    H = lambda n: vim.event.HostEventArgument(name=n, host=vim.HostSystem("host-1"))           # noqa: E731
    V = lambda n: vim.event.VmEventArgument(name=n, vm=vim.VirtualMachine("vm-1"))             # noqa: E731
    D = lambda n: vim.event.DatastoreEventArgument(name=n, datastore=vim.Datastore("ds-1"))    # noqa: E731
    m = c._move_of(vim.event.VmCreatedEvent(vm=V("web01"), host=H("esx02"), ds=D("ds1"), userName="VSPHERE.LOCAL\\ops"))
    assert m["type"] == "created" and m["to_host"] == "esx02" and m["to_ds"] == "ds1" and m["cluster"] == "CL1" and m["user"].endswith("ops")
    m = c._move_of(vim.event.VmClonedEvent(vm=V("web02"), host=H("esx01"), ds=D("ds1"), sourceVm=V("web01")))
    assert m["type"] == "cloned" and m["source"] == "web01"
    m = c._move_of(vim.event.VmDeployedEvent(vm=V("web03"), host=H("esx01"), srcTemplate=V("tpl-ubuntu")))
    assert m["type"] == "deployed" and m["source"] == "tpl-ubuntu"
    assert c._move_of(vim.event.VmRegisteredEvent(vm=V("old01"), host=H("esx01")))["type"] == "registered"
    m = c._move_of(vim.event.VmRemovedEvent(vm=V("app01"), host=H("esx01"), ds=D("ds2")))
    assert m["type"] == "removed" and m["from_host"] == "esx01" and m["to_host"] == "" and m["from_ds"] == "ds2"
    m = c._move_of(vim.event.VmRenamedEvent(vm=V("new"), host=H("esx01"), oldName="old", newName="new"))
    assert m["type"] == "renamed" and m["vm"] == "new" and m["source"] == "old"
    m = c._move_of(vim.event.VmCloneFailedEvent(vm=V("web01"), host=H("esx01"), destName="web09", destHost=H("esx02")))
    assert m["type"] == "create_failed" and m["vm"] == "web09" and m["source"] == "web01" and m["to_host"] == "esx02"
    assert c._move_of(vim.event.VmPoweredOffEvent(vm=V("x")))["type"] == "power_off"
    assert c._move_of(vim.event.VmMessageEvent(vm=V("x"))) is None


def test_inventory_detects_new_and_gone_vms():
    c = _vc()
    prev = {"app01": "esx01", "db01": "esx02", "old01": "esx01"}
    c.topology["vms"] = {"app01": {"host": "esx01"}, "db01": {"host": "esx02"}, "web05": {"host": "esx02", "cluster": "CL1", "datastores": ["ds1"]}, "evt01": {"host": "esx01"}}
    c._life_vms = {"evt01": time.time()}                                   # 이벤트로 이미 기록된 생성 → 중복 생략
    evs = c._placement_diff(prev)
    got = {(e.attrs["move"]["type"], e.attrs["move"]["vm"]) for e in evs}
    assert got == {("detected_new", "web05"), ("detected_gone", "old01")}
    assert all(e.attrs.get("no_anomaly") for e in evs)
    # 대량 소실(부분 조회·재연결)은 건너뜀
    c._life_vms = {}
    big = {f"vm{i}": "esx01" for i in range(200)}
    c.topology["vms"] = {f"vm{i}": {"host": "esx01"} for i in range(100)}
    assert not [e for e in c._placement_diff(big) if e.attrs["move"]["type"] == "detected_gone"]


def test_tracker_lifecycle_summary_and_dedupe(tmp_path):
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        t = time.time()

        def ev(mv, nid):
            return LogEvent(source="vcenter", connector="vc1", message="m", ts=t, native_id=nid, attrs={"move": {"vcenter": "vc1", **mv}})
        e.moves.record(ev({"type": "cloned", "vm": "web02", "to_host": "esx01", "user": "ops", "source": "web01"}, "11"))
        e.moves.record(ev({"type": "created", "vm": "web03", "to_host": "esx02", "user": "ops"}, "12"))
        e.moves.record(ev({"type": "removed", "vm": "old01", "from_host": "esx01", "user": "adm"}, "13"))
        e.moves.record(ev({"type": "create_failed", "vm": "web09"}, "14"))
        e.moves.record(ev({"type": "detected_new", "vm": "web02", "to_host": "esx01"}, ""))     # 이벤트로 기록됨 → 생략
        e.moves.record(ev({"type": "detected_gone", "vm": "old01"}, ""))                        # 이벤트로 기록됨 → 생략
        e.moves.record(ev({"type": "detected_new", "vm": "x01", "to_host": "esx03"}, ""))
        e.moves.record(ev({"type": "vmotion", "vm": "web02", "from_host": "esx01", "to_host": "esx02"}, "15"))
        await asyncio.sleep(0.2)
        s = await e.moves.summary(24)
        q = await e.moves.query(24, q="web01")
        cols = {r["name"] for r in await e.store.q("PRAGMA table_info(vm_moves)")}
        e.moves.recent.clear()
        db = await e.moves.query(24, types=["cloned"])
        return s, q, cols, db
    s, q, cols, db = asyncio.run(main())
    assert s["total"] == 6 and s["created_total"] == 3 and s["deleted_total"] == 1 and s["fail_total"] == 1 and s["move_total"] == 1
    assert s["creators"] == [{"user": "ops", "count": 2}] and s["deleters"] == [{"user": "adm", "count": 1}]
    assert sum(p["create"] for p in s["series"]) == 3 and sum(p["delete"] for p in s["series"]) == 1 and sum(p["fail"] for p in s["series"]) == 1
    assert s["top_vms"] == [{"vm": "web02", "count": 1}]                  # 생성·삭제는 '자주 옮겨진 VM' 에서 제외
    assert "VM 생성" in s["labels"].values() and q and q[0]["vm"] == "web02"
    assert "source" in cols and db and db[0]["source"] == "web01"


def test_legacy_db_gets_source_column(tmp_path):
    import sqlite3
    from app.config import DEFAULTS, _merge
    p = tmp_path / "old.db"
    con = sqlite3.connect(p)
    con.executescript("""CREATE TABLE vm_moves(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, vcenter TEXT, vm TEXT, type TEXT, from_host TEXT, to_host TEXT,
      from_ds TEXT, to_ds TEXT, cluster TEXT, user TEXT, msg TEXT, key TEXT UNIQUE);
      INSERT INTO vm_moves(ts,vcenter,vm,type,from_host,to_host,from_ds,to_ds,cluster,user,msg,key) VALUES(%f,'vc1','a','vmotion','h1','h2','','','','','m','k1');""" % time.time())
    con.commit(); con.close()
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(p)}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        rows = await e.moves.query(24)
        return rows
    rows = asyncio.run(main())
    assert rows and rows[0]["vm"] == "a" and rows[0].get("source") in ("", None)


def test_menu_renamed_to_vm_activity():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app"
    idx = (root / "static/index.html").read_text(encoding="utf-8")
    assert "<span>VM 액티비티</span>" in idx and "VM 이동·HA" not in idx
    assert "VM 이동·HA" not in (root / "static/noc.js").read_text(encoding="utf-8")
    assert '"VM 액티비티 (최근)"' in (root / "noc.py").read_text(encoding="utf-8")
    assert '"VM 액티비티": "VM activity"' in (root / "static/i18n-en.js").read_text(encoding="utf-8")


def test_first_topology_does_not_flag_all_vms_new():
    c = _vc()
    assert c._placement_diff({}) == []
    c.topology["vms"] = {}
    assert c._placement_diff({"app01": "esx01"}) == []                       # 전부 사라짐(조회 실패)도 건너뜀
