"""2.6.0 VM 액티비티 × 변경 관리 — 이전→이후 구성 · 변경 창(유지보수 창) 안/밖 · 반복 이동 · 장애 직전 변경(AI·RCA·인시던트) · 리포트 · 보관 기간"""
import asyncio
import time

from app.models import LogEvent


def _engine(tmp_path, **va):
    from app.config import DEFAULTS, _merge
    from app.engine import Engine
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}, "vm_activity": va})
    return Engine(cfg)


def _ev(mv, ts, nid):
    return LogEvent(source="vcenter", connector="vc1", message="m", ts=ts, native_id=nid, attrs={"move": {"vcenter": "vc1", **mv}})


def test_reconfig_before_after():
    from pyVmomi import vim
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc1", "host": "vc", "username": "u", "password": "p"}, None)
    c.topology = {"vms": {"db01": {"host": "esx01", "vcpu": 4, "mem_mb": 16384}}, "hosts": {"esx01": {"cluster": "CL"}}, "updated": 1}
    V = vim.event.VmEventArgument(name="db01", vm=vim.VirtualMachine("vm-1"))
    m = c._move_of(vim.event.VmReconfiguredEvent(vm=V, configSpec=vim.vm.ConfigSpec(numCPUs=8, memoryMB=24576)))
    assert m["detail"] == "vCPU 4 → 8, 메모리 16 → 24 GB"
    m = c._move_of(vim.event.VmReconfiguredEvent(vm=V, configSpec=vim.vm.ConfigSpec(numCPUs=8)))       # 직전 이벤트로 갱신된 값과 같음
    assert m["detail"] == "vCPU 8"


def test_change_window_and_pingpong(tmp_path):
    async def main():
        e = _engine(tmp_path, change_window_check=True, pingpong_count=3, pingpong_minutes=30, business_days=[1, 2, 3, 4, 5, 6, 7], business_hours="00:00-24:00")
        raised = []
        orig = e.submit
        e.submit = lambda ev: (raised.append(ev), orig(ev))[1]
        now = time.time()
        e.incidents.maint_cache = [{"id": 1, "name": "DB 증설", "start": now - 3600, "end": now + 3600, "weekly": None,
                                    "scope": {"hosts_regex": "^esx0[12]$", "clusters": [], "sources": []}}]
        a = e.moves.record(_ev({"type": "reconfigured", "vm": "db01", "to_host": "esx01", "user": "dba", "detail": "vCPU 4 → 8"}, now, "1"))
        b = e.moves.record(_ev({"type": "reconfigured", "vm": "web01", "to_host": "esx09", "user": "ops"}, now, "2"))
        c = e.moves.record(_ev({"type": "power_on", "vm": "web01", "to_host": "esx09", "user": "ops"}, now, "3"))          # 판정 대상 아님
        d = e.moves.record(_ev({"type": "drs", "vm": "app01", "from_host": "esx01", "to_host": "esx02"}, now - 900, "4"))
        e.moves.record(_ev({"type": "drs", "vm": "app01", "from_host": "esx02", "to_host": "esx01"}, now - 600, "5"))
        f = e.moves.record(_ev({"type": "drs", "vm": "app01", "from_host": "esx01", "to_host": "esx02"}, now - 300, "6"))
        g = e.moves.record(_ev({"type": "drs", "vm": "app01", "from_host": "esx02", "to_host": "esx01"}, now - 100, "7"))
        return a, b, c, d, f, g, raised
    a, b, c, d, f, g, raised = asyncio.run(main())
    assert a["flags"] == "in_window" and "변경 창 'DB 증설'" in a["detail"]
    assert b["flags"] == "unplanned" and c["flags"] == ""
    assert d["flags"] == "" and "pingpong" in f["flags"] and "pingpong" in g["flags"]                                  # DRS 는 사용자 없음 → 변경 창 판정 제외
    pp = [x for x in raised if x.attrs.get("vm_activity") == "pingpong"]
    assert len(pp) == 1 and "3회" in pp[0].message and "esx01 → esx02" in pp[0].message


def test_change_window_check_off_by_default(tmp_path):
    async def main():
        e = _engine(tmp_path)
        return e.moves.record(_ev({"type": "reconfigured", "vm": "x", "to_host": "h", "user": "ops"}, time.time(), "1"))
    assert "unplanned" not in asyncio.run(main())["flags"]


def test_related_changes_feed_ai_and_incident(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        e.resolve = lambda n: {"kind": "vm", "name": "db01", "host": "esx01", "cluster": "CL"} if n == "db01" else \
            ({"kind": "host", "name": n, "cluster": "CL"} if n.startswith("esx") else None)
        e.moves.record(_ev({"type": "reconfigured", "vm": "db01", "to_host": "esx01", "user": "dba", "detail": "메모리 32 → 16 GB"}, now - 1200, "1"))
        e.moves.record(_ev({"type": "snapshot_create", "vm": "app02", "to_host": "esx01", "user": "bk"}, now - 600, "2"))
        e.moves.record(_ev({"type": "power_on", "vm": "app03", "to_host": "esx01"}, now - 500, "3"))                        # 시스템 전원 켬 → 제외
        e.moves.record(_ev({"type": "vmotion", "vm": "web09", "from_host": "esx05", "to_host": "esx06", "cluster": "CL", "user": "ops"}, now - 400, "4"))
        e.moves.record(_ev({"type": "reconfigured", "vm": "db01", "to_host": "esx01", "user": "dba"}, now - 3 * 3600, "5"))  # AI 창(2시간) 밖·인시던트 창(6시간) 안
        r = await e.vm_changes_for({"entity": "db01", "host": "esx01", "ts": now})
        lines = r["lines"]
        assert "VSPHERE.LOCAL\\dba" not in r["names"] and "dba" in r["names"] and "app02" in r["names"]
        inc = {"primary_entity": "db01", "hosts": ["esx01"], "cluster": "CL", "anomaly_ids": [], "created": now, "last_anomaly": now, "updated": now}
        rows = await e.incidents.vm_changes(inc)
        await asyncio.sleep(0.2)
        e.moves.recent.clear()                                       # 재기동 직후처럼 메모리 비움 → DB 에서 보충
        rows_db = await e.incidents.vm_changes(inc)
        return lines, rows, rows_db
    lines, rows, rows_db = asyncio.run(main())
    assert len(lines) == 2 and "[대상 VM] 구성 변경 db01 esx01 by dba 메모리 32 → 16 GB" in lines[0] and "[같은 호스트] 스냅샷 생성 app02" in lines[1]
    assert [r["relation"] for r in rows] == ["vm", "vm", "host", "cluster"] and len(rows) == 4 and rows[0]["vm"] == "db01"
    assert [r["key"] for r in rows_db] == [r["key"] for r in rows]


def test_llm_payload_includes_recent_changes(monkeypatch):
    from app import llm as L
    seen = {}

    class P:
        name, model = "p", "m"

        def _fail(self, e):
            pass

    async def fake_run(self, task, system, user, **kw):
        seen["user"], seen["system"], seen["names"] = user, system, kw.get("names") or []
        return '{"results":[]}', P(), None
    monkeypatch.setattr(L.LLMClient, "_run", fake_run)
    m = L.LLMClient.__new__(L.LLMClient)
    m.cfg = {}
    ev = {"source": "vcenter", "connector": "vc", "kind": "event", "severity": "error", "ts": time.time(), "message": "x", "host": "esx01", "entity": "db01"}
    asyncio.run(m.analyze([{"id": "a1", "event": ev, "changes": ["10-19 06:00 [대상 VM] 구성 변경 db01 by VSPHERE.LOCAL\\dba01"],
                            "change_names": ["db01", "VSPHERE.LOCAL\\dba01", "dba01"]}]))
    assert "recent_vm_changes" in seen["user"] and "구성 변경 db01" in seen["user"] and "recent_vm_changes" in seen["system"]
    assert {"db01", "dba01"} <= set(seen["names"])


def test_masker_hides_change_names():
    from app.llm import Masker
    m = Masker(["db01", "VSPHERE.LOCAL\\dba01", "dba01", "esx01"])
    out = m.mask("10-19 06:00 [대상 VM] 구성 변경 db01 esx01 by VSPHERE.LOCAL\\dba01 메모리 32 → 16 GB")
    assert "db01" not in out and "dba01" not in out and "esx01" not in out and "메모리 32 → 16 GB" in out
    assert m.unmask(out).endswith("by VSPHERE.LOCAL\\dba01 메모리 32 → 16 GB")


def test_report_has_vm_activity_section(tmp_path):
    async def main():
        e = _engine(tmp_path, protected=["core-*"])
        now = time.time()
        e.moves.record(_ev({"type": "removed", "vm": "core-01", "from_host": "esx01", "user": "adm"}, now - 60, "1"))
        e.moves.record(_ev({"type": "created", "vm": "web01", "to_host": "esx01", "user": "ops"}, now - 30, "2"))
        await asyncio.sleep(0.1)
        from app.reports import Reporter
        return await Reporter(e).generate("daily", now - 86400, now)
    rep = asyncio.run(main())
    assert "<h2>VM 액티비티" in rep["html"] and "core-01" in rep["html"] and "보호 VM" in rep["html"] and "순증감 +0대" in rep["html"]


def test_retention_rule_applied_to_store(tmp_path):
    async def main():
        e = _engine(tmp_path, retention_days=200)
        a = e.store.moves_retention
        await e.moves.save_rules({**e.moves.rules(), "retention_days": 730}, "admin")
        return a, e.store.moves_retention
    a, b = asyncio.run(main())
    assert a == 200 * 86400 and b == 730 * 86400
