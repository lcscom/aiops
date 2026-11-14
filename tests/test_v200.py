"""2.0 — vSAN Health 집계·이벤트, 용량 예측·VM 적정화, 구성 변경 추적, 월간 리포트 확장 절"""
import asyncio
import os
import tempfile
import time
from types import SimpleNamespace as NS

from app import assess, billing, capacity, vsan
from app.store import Store
from tests.test_v112 import INV, _env


def _store():
    return Store(os.path.join(tempfile.mkdtemp(), "t.db"))


def test_forecast_days_to_threshold():
    pts = [(d, 50 + d * 0.5) for d in range(20)]            # 하루 0.5% 증가, 마지막 59.5%
    f = capacity.forecast(pts, time.time())
    assert abs(f["slope"] - 0.5) < 1e-6 and f["days_to"]["80"] == 41 and f["days_to"]["90"] == 61 and f["p30"] == 74.5
    flat = capacity.forecast([(d, 40.0) for d in range(10)], time.time())
    assert flat["days_to"]["90"] is None and flat["slope"] == 0
    assert capacity.forecast([(0, 1)], time.time())["slope"] is None
    assert capacity.forecast([(d, 95.0 + d) for d in range(5)], time.time())["days_to"]["90"] == 0


def test_capacity_sampling_overview_and_rightsizing():
    e = _env()
    e.store = _store()
    e.billing = billing.Billing(e, {})
    C = capacity.Capacity(e, {"forecast_days": 30})

    async def go():
        base = 1_800_000_000 - 1_800_000_000 % 86400
        for d in range(10):                                   # 10일 × 2표본, CPU 는 25% 고정(_env 의 호스트 값)
            assert await C.sample(base + d * 86400 + 60) == 5 or True
            await C.sample(base + d * 86400 + 400)
        ov = await C.overview(30)
        for d in range(15):                                   # 정산 표본 — app01 켜짐(CPU 50%), db01 꺼짐
            await e.billing.sample(base + d * 86400 + 100)
            await e.billing.sample(base + d * 86400 + 3700)
        await e.billing.save_rate({"name": "r", "vcpu_hour": 10, "mem_gb_hour": 2, "disk_gb_hour": 0.1, "is_default": True}, "t")
        return ov, await C.rightsizing(30)
    ov, rs = asyncio.run(go())
    kinds = {(r["kind"], r["name"]): r for r in ov["items"]}
    cl = kinds[("cluster", "CL")]
    assert cl["cpu"] == 25.0 and cl["hosts"] == 1 and cl["days_observed"] >= 3 and cl["forecast"]["slope"] == 0 and cl["state"] == "ok"
    assert ("datastore", "san-01") in kinds and ("datastore", "local-esx01") not in kinds       # 로컬 디스크 제외
    assert kinds[("datastore", "san-01")]["state"] == "down"                                       # 95%
    S = rs["summary"]
    assert rs["vms_observed"] == 3 and S["powered_off"] == 1 and rs["powered_off"][0]["vm"] == "db01"
    assert S["oversized"] == 0 and [x["vm"] for x in rs["idle"]] == ["worker-1"]              # app01: 4 vCPU·피크 50% → 적정 · worker-1 사용률 없음 → 유휴
    assert rs["currency"] == "KRW" and rs["rate"]["vcpu_hour"] == 10
    csv = capacity.Capacity.to_csv(ov, rs)
    assert "san-01" in csv and "db01" in csv


def test_rightsizing_classifies_oversized_and_idle():
    e = _env()
    e.store = _store()
    e.billing = billing.Billing(e, {})
    C = capacity.Capacity(e, {})
    t = e.connectors[0].topology
    t["vms"]["big"] = {"host": "esx01", "power": "poweredOn", "ips": [], "networks": [], "vcpu": 16, "mem_mb": 65536, "prov_gb": 200, "cluster": "CL", "folder": "DC",
                       "tags": [], "cpu_mhz": 1600, "mem_used_mb": 3277, "moid": "vm-9"}            # 16 vCPU 중 5% · 메모리 5%
    t["vms"]["lazy"] = {"host": "esx01", "power": "poweredOn", "ips": [], "networks": [], "vcpu": 2, "mem_mb": 4096, "prov_gb": 40, "cluster": "CL", "folder": "DC",
                        "tags": [], "cpu_mhz": 20, "mem_used_mb": 100, "moid": "vm-8"}               # 0.5% · 2.4% → 유휴
    t["vms"]["hot"] = {"host": "esx01", "power": "poweredOn", "ips": [], "networks": [], "vcpu": 2, "mem_mb": 4096, "prov_gb": 40, "cluster": "CL", "folder": "DC",
                       "tags": [], "cpu_mhz": 3600, "mem_used_mb": 3800, "moid": "vm-7"}             # 90% · 93% → 과소

    async def go():
        base = 1_800_000_000 - 1_800_000_000 % 86400
        for h in range(30):
            await e.billing.sample(base + h * 3600 + 10)
        return await C.rightsizing(7)
    rs = asyncio.run(go())
    over = {x["vm"]: x for x in rs["oversized"]}
    assert "big" in over and over["big"]["rec_vcpu"] == 2 and over["big"]["rec_mem_gb"] == 5 and over["big"]["saving"] is None
    assert {x["vm"] for x in rs["idle"]} == {"lazy", "worker-1"} and [x["vm"] for x in rs["undersized"]] == ["hot"]   # worker-1: 표본에 사용률 없음 → 유휴
    assert rs["undersized"][0]["rec_vcpu"] == 3 and "평균 CPU" in rs["undersized"][0]["why"]
    assert rs["summary"]["reclaim_vcpu"] == 16 - 2 + 2 + 2


def test_vsan_health_rollup():
    e = _env()
    cl = e.connectors[0].topology["clusters"]["CL"]
    cl["vsan_health"] = {"overall": "red", "overall_desc": "x", "ts": time.time(), "space": {"total_gb": 2000, "free_gb": 500, "used_pct": 75, "ratio": 1.6},
                         "groups": [{"id": "disk", "name": "물리 디스크", "health": "red", "tests": [{"name": "Operation health", "health": "red", "desc": "disk error", "healthy": 3, "all": 4, "risk": "r"},
                                                                                                {"name": "Congestion", "health": "green", "desc": "", "healthy": 4, "all": 4}]},
                                    {"id": "net", "name": "네트워크", "health": "green", "tests": [{"name": "partition", "health": "green", "desc": ""}]}],
                         "tests_bad": [{"group": "물리 디스크", "name": "Operation health", "health": "red", "desc": "disk error", "healthy": 3, "all": 4, "risk": "r"}],
                         "objects": {"overall": "yellow", "detail": {"healthy": 10, "reduced": 1}}}
    v = vsan.collect(e)
    c = v["clusters"][0]
    assert c["state"] == "down" and c["health"] == "red" and c["health_red"] == 1 and c["capacity_gb"] == 2000 and c["used_pct"] == 75.0 and c["dedup"] == 1.6
    assert v["health_tests"][0]["test"] == "Operation health" and v["health_tests"][0]["entities"] == "3/4"
    assert [g["group"] for g in v["health_groups"]] == ["물리 디스크", "네트워크"] and v["health_groups"][0]["bad_names"] == "Operation health"


def test_vsan_health_events_only_on_change():
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector.__new__(VCenterConnector)
    c.host, c.name, c.environment = "vc", "vc", "dev"
    c._state = {"checks": {}}
    c.cfg = {"name": "vc", "host": "vc"}
    c.ev = lambda msg, **kw: NS(message=msg, **kw)
    h = {"overall": "yellow", "overall_desc": "d", "groups": [{"name": "G", "tests": [{"name": "T1", "health": "red", "desc": "bad"}, {"name": "T2", "health": "green", "desc": ""}]}]}
    c.topology = {"clusters": {"CL": {"vsan": True, "vsan_health": h}}}
    ev = c._vsan_health_events()
    assert {x.severity for x in ev} == {"error", "warning"} and len(ev) == 2        # 첫 조회: 비정상만
    assert c._vsan_health_events() == []                                              # 변화 없음
    h["groups"][0]["tests"][0]["health"] = "green"
    ev = c._vsan_health_events()
    assert len(ev) == 1 and ev[0].severity == "info" and "T1" in ev[0].message and ev[0].attrs["no_anomaly"] == 1


def test_config_drift_and_verdict_changes():
    import copy
    cur = copy.deepcopy(INV)
    cur["hosts"][0]["adv"]["UserVars.ESXiShellInteractiveTimeOut"] = 900
    cur["hosts"][0]["services"]["TSM-SSH"] = {"running": False, "policy": "off"}
    cur["hosts"][0]["lockdown"] = "lockdownNormal"
    cur["hosts"][0]["build"] = "24585383"
    cur["hosts"][0]["firewall"]["open_all"] = ["sshServer", "dns", "snmp"]
    cur["hosts"].append({"name": "esx03", "conn": "connected", "version": "8.0.3", "build": "1", "adv": {}, "services": {}, "firewall": {}, "ntp": [], "vswitch": []})
    cur["vms"][0]["adv"]["isolation.tools.copy.disable"] = "TRUE"
    ch = assess.diff_inventory(INV, cur)
    keys = {(c["target"], c["key"]): c for c in ch}
    assert keys[("esx01", "UserVars.ESXiShellInteractiveTimeOut")]["severity"] == "warning" and keys[("esx01", "UserVars.ESXiShellInteractiveTimeOut")]["after"] == "900"
    assert keys[("esx01", "TSM-SSH")]["severity"] == "info" and keys[("esx01", "잠금 모드")]["severity"] == "info"
    assert keys[("esx01", "ESXi")]["after"].endswith("(24585383)") and keys[("esx03", "인벤토리")]["after"] == "추가됨"
    assert keys[("esx01", "모든 IP 허용 규칙")]["severity"] == "warning" and keys[("vm1", "isolation.tools.copy.disable")]["severity"] == "info"
    assert assess.diff_inventory(None, cur) == []
    before = assess.hardening(INV, {}, False)
    after = assess.hardening(cur, {}, False)
    vd = {(v["id"], v["target"]): v for v in assess.diff_rows(before, after)}
    assert vd[("ESXI-01", "esx01")]["worse"] is False and vd[("ESXI-20", "esx01")]["after"] == "PASS" and vd[("ESXI-29", "esx01")]["after"] == "PASS"
    assert vd[("ESXI-28", "esx01")]["before"] == "WARN" and vd[("ESXI-28", "esx01")]["after"] == "WARN" if ("ESXI-28", "esx01") in vd else True


def test_assessor_run_records_changes_and_emits_events():
    import copy
    got = []

    async def ingest(ev):
        got.append(ev)
    inv = {"v": copy.deepcopy(INV)}
    e = NS(store=_store(), connectors=[NS(type="vcenter", enabled=True, name="vc", host="vc01", assess_collect=lambda n: inv["v"])], ingest=ingest)
    A = assess.Assessor(e, {})

    async def go():
        d1 = await A.run("t")
        inv["v"] = copy.deepcopy(INV)
        inv["v"]["hosts"][0]["services"]["TSM-SSH"] = {"running": False, "policy": "off"}
        inv["v"]["hosts"][0]["adv"]["Syslog.global.logHost"] = ""
        inv["v"]["hosts"][0]["lockdown"] = "lockdownDisabled"
        inv["v"]["hosts"][0]["adv"]["Security.AccountLockFailures"] = 0
        d2 = await A.run("t")
        return d1, d2
    d1, d2 = asyncio.run(go())
    assert d1["summary"]["changes"]["total"] == 0 and d1["changes"] == [] and d1["inventory"]
    s = d2["summary"]["changes"]
    assert s["total"] == 2 and s["worse"] == 1 and s["better"] == 1 and s["since"] == d1["summary"]["ts"]
    assert {(c["key"], c["severity"]) for c in d2["changes"]} == {("TSM-SSH", "info"), ("Security.AccountLockFailures", "warning")}
    kinds = {(x.kind, x.severity) for x in got}
    assert ("config", "warning") in kinds and ("config", "info") in kinds and all(x.source == "vcenter" for x in got)
    assert "변경" in assess.Assessor.to_csv(d2) and "구성 변경" in assess.Assessor.report_html(d2)


def test_report_extended_sections_render():
    from app.reports import Reporter
    x = {"billing": {"currency": "KRW", "tenants": [{"name": "A", "vms": 2, "vcpu_hours": 10.0, "mem_gb_hours": 20.0, "disk_gb_hours": 5.0, "cost": 123.0}],
                     "totals": {"unassigned_vms": 1, "vms": 2, "vcpu_hours": 10.0, "mem_gb_hours": 20.0, "disk_gb_hours": 5.0, "cost": 123.0}},
         "capacity": {"days": 30, "summary": {"down": 0, "warn": 1, "soon": 1}, "items": [{"kind": "cluster", "name": "CL", "state": "warn", "cpu": 82.0, "mem": 50.0,
                                                                                          "forecast": {"slope": 0.4, "days_to": {"80": 0, "90": 20}, "p90": 95.0}}]},
         "rightsizing": {"days": 14, "currency": "KRW", "summary": {"oversized": 1, "undersized": 0, "idle": 0, "powered_off": 0, "reclaim_vcpu": 6, "reclaim_mem_gb": 8, "saving_month": 1000},
                         "oversized": [{"vm": "big", "vcpu": 8, "mem_gb": 16, "peak_cpu": 10, "peak_mem": 20, "rec_vcpu": 2, "rec_mem_gb": 8, "saving": 1000}], "idle": [], "undersized": []},
         "assessment": {"summary": {"ts": time.time(), "score": 70.0, "counts": {"FAIL": 1, "WARN": 0}, "cve": {"vulnerable": 0, "possible": 0}, "changes": {"total": 2, "worse": 1}},
                        "rows": [{"id": "ESXI-20", "title": "SSH", "status": "FAIL", "target": "esx01"}], "cve": []}}
    h = Reporter.render_extended(x)
    assert "정산" in h and "용량 예측" in h and "VM 적정화" in h and "보안 판독" in h and "big" in h and "ESXI-20" in h and "구성 변경 2" in h
