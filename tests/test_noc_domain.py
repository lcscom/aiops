"""1.8: 관제 도메인 상세 탭 — 심각도 분당·상위 호스트 집계, /api/noc/domain 상세·호스트 이벤트, 슬롯 상태"""
import asyncio
import time
from types import SimpleNamespace as NS

from app.models import LogEvent
from app.runtime import MinuteCounter


def test_minute_counter_severity_and_hot_hosts():
    m = MinuteCounter(60)
    for _ in range(3):
        m.add("nsx", "syslog", sev="error", host="edge01")
    m.add("nsx", "syslog", sev="critical", host="edge02")
    m.add("nsx", "syslog", sev="info", host="edge01")
    m.add("esxi", "syslog", sev="warning", host="esx01")
    s = m.sev_series({"nsx"})
    assert s["error"][-1] == 3 and s["critical"][-1] == 1 and s["warning"][-1] == 0
    assert m.top_hosts({"nsx"})[0] == {"host": "edge01", "n": 4}
    m.minute -= 2                                   # 2분 경과 → 링버퍼 이동
    assert m.sev_series({"nsx"})["error"][-3] == 3
    m.seed([{"m": int(time.time() // 60), "source": "avi", "connector": "api", "severity": "critical", "n": 5}])
    assert m.sev_series({"avi"})["critical"][-1] == 5


def test_domain_detail_and_host_events(tmp_path):
    from app.config import DEFAULTS, _merge
    from app import noc
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        nsx = NS(type="nsx", name="nsx-m01", host="nsx", edges={"e1": "edge01"}, _edge_state={"e1": "DOWN"},
                 edge_info={"e1": {"host_moid": "host-12", "edge_cluster": "EC-1", "mgmt_ip": "10.0.0.5", "form": "MEDIUM"}},
                 inv={"tier0": [{"id": "t0", "name": "T0", "ha_mode": "ACTIVE_STANDBY"}], "tier1": []},
                 entities=lambda: [{"name": "edge01", "kind": "edge", "state": "down", "detail": ""}],
                 state=lambda: {"name": "nsx-m01", "type": "nsx", "state": "ok", "checks": {"Edge 목록(Policy API)": "ok 1개"}, "last_ok": time.time()})
        vc = NS(type="vcenter", name="vc", topology={"hosts": {"esx12.lab": {"moid": "host-12"}}, "clusters": {}, "vms": {}}, alarms=[],
                entities=lambda: [], state=lambda: {"state": "ok"})
        e.connectors = [vc, nsx]
        now = time.time()
        rows = [(1, now - 30, "nsx", "syslog", "critical", "edge01.lab", "edge01", "log", "BGP down", 0, "", "{}"),
                (2, now - 20, "nsx-edge", "syslog", "info", "edge02.lab", "edge02", "log", "BFD up", 0, "", '{"peer":"1.1.1.1","_q":1}'),
                (3, now - 10, "esxi", "syslog", "error", "esx01", "esx01", "log", "other domain", 0, "", "{}")]
        await e.store.q("SELECT 1")
        for r in rows:
            await e.store.x("INSERT INTO logs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", r)
        e.minutes.add("nsx", "syslog", sev="critical", host="edge01.lab")
        d = await noc.domain_detail(e, cfg, "nsx")
        h = await noc._recent(e, {"nsx", "nsx-edge"}, 6, 50, host="edge01")
        sl = noc.slots(cfg)
        return d, h, sl
    d, h, sl = asyncio.run(main())
    assert d["id"] == "nsx" and [r["message"] for r in d["recent"]] == ["BFD up", "BGP down"]      # 다른 도메인 제외, 최신순
    assert d["recent"][0]["attrs"] == {"peer": "1.1.1.1"} and [r["message"] for r in d["important"]] == ["BGP down"]
    ed = next(p for p in d["panels"] if p["id"] == "edges")["rows"][0]
    assert ed["host"] == "esx12.lab" and ed["state"] == "DOWN" and ed["cluster"] == "EC-1"           # moid → ESXi 이름
    assert d["checks"]["nsx-m01"]["Edge 목록(Policy API)"] == "ok 1개" and d["kinds"]["edge"]["down"] == 1
    assert d["sev"]["critical"][-1] == 1 and d["top_hosts"][0]["host"] == "edge01.lab"
    assert [r["message"] for r in h] == ["BGP down"]
    assert {s["id"] for s in sl} >= {"vc", "nsx", "avi", "vks", "srv", "vmg", "sec"}


def test_host_series_and_stack_path():
    from app.stack import path_of
    m = MinuteCounter(60)
    m.add("esxi", "syslog", host="ESX01.lab")
    m.add("esxi", "syslog", host="esx01.lab")
    m.add("esxi", "syslog", host="esx02.lab")
    assert m.host_series("esx01")[-1] == 2 and m.host_series("esx01.lab", "esx01")[-1] == 2
    d = {"nodes": [{"id": "fi", "label": "FI-A", "kind": "fi", "state": "ok", "layer": 0}, {"id": "b", "label": "blade-1", "kind": "blade", "state": "down", "layer": 2},
                   {"id": "h", "label": "esx01.lab", "kind": "esxi", "state": "ok", "layer": 3}, {"id": "e", "label": "edge01", "kind": "edge", "state": "down", "layer": 5},
                   {"id": "t0", "label": "T0", "kind": "t0", "state": "ok", "layer": 7}],
         "links": [{"s": "fi", "t": "b"}, {"s": "b", "t": "h"}, {"s": "h", "t": "e"}, {"s": "e", "t": "t0"}]}
    p = path_of(d, "edge01")
    assert [x["label"] for x in p["up"]] == ["esx01.lab", "blade-1", "FI-A"] and [x["label"] for x in p["down"]] == ["T0"]
    assert path_of(d, "esx01")["node"]["id"] == "h" and path_of(d, "nope") is None


def test_search_patterns_entity(tmp_path):
    from app.config import DEFAULTS, _merge
    from app import noc
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "b.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        vc = NS(type="vcenter", name="vc", enabled=True, host="vc", alarms=[], state=lambda: {"state": "ok"},
                topology={"hosts": {"esx01.lab": {"moid": "host-1", "cluster": "CL", "conn": "connected"}}, "clusters": {"CL": {"hosts": ["esx01.lab"]}},
                          "vms": {"core-bank-db01": {"host": "esx01.lab", "cluster": "CL", "power": "poweredOn"}}},
                entities=lambda: [{"name": "esx01.lab", "kind": "host", "state": "warn", "detail": "connected"}])
        e.connectors = [vc]
        now = time.time()
        for i, (h, msg, sev) in enumerate([("esx01.lab", "Lost access to volume 5f1a-77 on esx01", "error"), ("esx01.lab", "Lost access to volume 6b2c-88 on esx01", "error"),
                                           ("esx02.lab", "Lost access to volume 9d9d-11 on esx02", "warning"), ("esx01.lab", "User root logged in", "info")]):
            await e.store.x("INSERT INTO logs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (i, now - 60 + i, "esxi", "syslog", sev, h, h, "log", msg, 0, "", "{}"))
        s1 = noc.search(e, cfg, "core-bank")
        s2 = noc.search(e, cfg, "esx01")
        pt = await noc.domain_patterns(e, cfg, "vc", 60)
        en = await noc.entity_detail(e, cfg, "vc", "esx01.lab")
        return s1, s2, pt, en
    s1, s2, pt, en = asyncio.run(main())
    assert s1[0]["name"] == "core-bank-db01" and s1[0]["kind"] == "vm" and s1[0]["sid"] == "vc"
    assert s2[0]["name"] == "esx01.lab" and s2[0]["state"] == "warn"
    top = pt["patterns"][0]
    assert top["count"] == 3 and top["sev"] == "error" and top["host_count"] == 2 and pt["total_patterns"] == 2   # 숫자·ID 다른 같은 로그 → 1 패턴
    assert en["entity"]["kind"] == "host" and len(en["events"]) == 3 and en["sev6h"]["error"] == 2 and len(en["series"]) == 60
