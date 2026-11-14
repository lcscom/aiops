"""2.29.0 DR·보호 — SRM 현황·Appliance 백업(vCenter·NSX·SDDC Manager)·스냅숏·VM 백업(추정)"""
import asyncio
import re
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace as NS

import httpx

from app import protection as PR
from app.connectors.vmware_rest import NsxConnector, SddcManagerConnector, SrmConnector

ROOT = Path(__file__).resolve().parents[1]
NOW = time.time()


def test_parse_when_and_verdicts():
    off = 9 * 3600
    assert PR.parse_when("2026-11-09 01:00:00", off) == PR.parse_when("2026-11-08T16:00:00Z")
    assert PR.parse_when("Last backup: 11/09/2026 01:30:00 PM [Veeam]", 0) == PR.parse_when("2026-11-09T13:30:00Z")
    assert PR.parse_when("없음") is None
    ok = {"configured": True, "schedule": "매일", "last": {"status": "SUCCESS"}, "last_success": NOW - 3600}
    assert PR.appliance_verdict(ok, NOW)[0] == "ok"
    assert PR.appliance_verdict({**ok, "last_success": NOW - 40 * 3600}, NOW)[0] == "warn"
    assert PR.appliance_verdict({**ok, "schedule": ""}, NOW)[0] == "warn"
    assert PR.appliance_verdict({**ok, "last": {"status": "FAILED", "message": "SFTP"}}, NOW) == ("bad", "마지막 백업 실패 — SFTP")
    assert PR.appliance_verdict({"configured": False}, NOW)[0] == "bad"
    assert PR.appliance_verdict({"error": "조회 불가"}, NOW)[0] == "unknown"
    assert PR.srm_status_verdict("READY") == "ok" and PR.srm_status_verdict("INCOMPLETE") == "bad" and PR.srm_status_verdict("TEST_IN_PROGRESS") == "warn"


def test_snapshots_and_vm_backups():
    snap = {"hosts": {"esx1": {"cluster": "wld"}},
            "vms": [{"name": "a", "snapshots": [{"name": "VEEAM BACKUP TEMPORARY SNAPSHOT", "created": NOW - 3600}], "consolidation": False},
                    {"name": "b", "snapshots": [{"name": f"s{k}", "created": NOW - (100 - k) * 3600} for k in range(4)], "consolidation": True}],
            "bp_vms": {"vms": [{"name": "a", "host": "esx1", "power": "poweredOn", "backup_fields": {"NB_LAST_BACKUP": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW - 5 * 3600))}},
                               {"name": "b", "host": "esx1", "power": "poweredOn", "notes_backup": "Last backup: " + time.strftime("%m/%d/%Y %I:%M:%S %p", time.localtime(NOW - 3 * 86400))},
                               {"name": "c", "host": "esx1", "power": "poweredOff"}]}}
    s = PR.snapshots([("vc", snap)], NOW)
    assert s["vms"] == 2 and s["snapshots"] == 5 and s["leftover"] == 1 and s["consolidate"] == 1
    b = [r for r in s["rows"] if r["vm"] == "b"]
    assert all("chain" in r["flags"] and "consolidate" in r["flags"] for r in b) and sum("72h" in r["flags"] for r in b) == 4
    assert s["rows"][0]["cluster"] == "wld"
    v = {r["vm"]: r for r in PR.vm_backups([("vc", snap)], NOW)["rows"]}
    assert v["a"]["status"] == "ok" and v["a"]["source"] == "NB_LAST_BACKUP" and abs(v["a"]["age_h"] - 5) < .1
    assert v["b"]["status"] == "warn" and v["b"]["source"] == "메모(Notes)" and v["c"]["status"] == "none"


def _mk(cls, cfg, handler):
    c = cls({"name": cfg.pop("name", "x"), "host": "h", "username": "u", "password": "p", **cfg}, None)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://h")
    return c


def test_nsx_backup_overview():
    js = {"backup_config": {"backup_enabled": True, "backup_schedule": {"resource_type": "IntervalBackupSchedule", "seconds_between_backups": 3600},
                            "remote_file_server": {"server": "10.0.0.5", "directory_path": "/nsx"}},
          "backup_operation_history": {"overall_backup_status": "FAILED",
                                       "cluster_backup_statuses": [{"success": False, "end_time": (NOW - 600) * 1000, "start_time": (NOW - 700) * 1000, "error_message": "SFTP 연결 실패"}],
                                       "node_backup_statuses": [{"success": True, "end_time": (NOW - 7200) * 1000}]}}
    c = _mk(NsxConnector, {}, lambda r: httpx.Response(200, json=js) if r.url.path == "/api/v1/cluster/backups/overview" else httpx.Response(404))
    ev = asyncio.run(c._backup())
    p = c.protection
    assert p["schedule"] == "60분마다" and p["last"]["status"] == "FAILED" and abs(p["last_success"] - (NOW - 7200)) < 1 and "10.0.0.5" in p["location"]
    assert PR.appliance_verdict(p, NOW)[0] == "bad" and ev and "SFTP" in ev[0].message
    assert asyncio.run(c._backup()) == []                                         # 같은 실패는 한 번만 알림
    c2 = _mk(NsxConnector, {}, lambda r: httpx.Response(403, json={"error_message": "권한"}))
    asyncio.run(c2._backup())
    assert c2.protection["error"].startswith("조회 불가") and PR.appliance_verdict(c2.protection, NOW)[0] == "unknown"


def test_sddc_backup_and_task():
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))  # noqa: E731
    tasks = {"elements": [{"id": "t1", "name": "SDDC Manager Backup", "type": "SDDCMANAGER_BACKUP", "status": "SUCCESSFUL", "completionTimestamp": iso(NOW - 3 * 3600)},
                          {"id": "t2", "name": "Commission host", "type": "HOST_COMMISSION", "status": "FAILED", "completionTimestamp": iso(NOW - 600)}]}
    cfg = {"isConfigured": True, "backupLocations": [{"server": "bk.lab", "directoryPath": "/sddc"}],
           "backupSchedules": [{"resourceType": "SDDC_MANAGER", "frequency": "WEEKLY", "daysOfWeek": ["SUNDAY"], "hourOfDay": 2, "minuteOfHour": 0, "takeScheduledBackups": True}]}

    def h(r):
        if r.url.path == "/v1/tasks":
            return httpx.Response(200, json=tasks)
        if r.url.path == "/v1/system/backup-configuration":
            return httpx.Response(200, json=cfg)
        if r.url.path == "/v1/domains":
            return httpx.Response(200, json={"elements": []})
        return httpx.Response(404)
    c = _mk(SddcManagerConnector, {}, h)
    asyncio.run(c.poll())
    asyncio.run(c.poll())                                                         # 두 번째 poll 에서 작업 결과 반영
    p = c.protection
    assert p["schedule"] == "매주 SUN 02:00" and p["last"]["status"] == "SUCCESS" and abs(p["last_success"] - (NOW - 3 * 3600)) < 2
    assert PR.appliance_verdict(p, NOW)[0] == "ok"


def test_srm_state():
    def h(r):
        p = r.url.path
        if p.endswith("/pairings"):
            return httpx.Response(200, json={"list": [{"pairing_id": "p1", "local_vc_server": {"name": "vc-a"}, "remote_vc_server": {"name": "vc-b"},
                                                       "remote_srm_server": {"name": "srm-b", "connection_status": "CONNECTED"}}]})
        if p.endswith("/srms"):
            return httpx.Response(200, json={"list": []})
        if p.endswith("/recovery-management/plans"):
            return httpx.Response(200, json={"list": [{"id": "rp1", "name": "Core-DR", "status": "READY"}, {"id": "rp2", "name": "Mob-DR", "status": "INCOMPLETE"}]})
        if "/plans/" in p and p.endswith("/issues"):
            return httpx.Response(200, json={"list": []})
        if p.endswith("/protection-management/groups"):
            return httpx.Response(200, json={"list": [{"id": "g1", "name": "PG-Core", "replication_type": "HBR", "protection_status": "OK"}]})
        if p.endswith("/groups/g1/virtual-machines"):
            return httpx.Response(200, json={"list": [{"name": "db01", "protection_status_details": {"status": "OK"}},
                                                      {"name": "db02", "protection_status_details": {"status": "ERROR", "errors": [{"message": "RPO 위반"}]}}]})
        return httpx.Response(404)
    c = _mk(SrmConnector, {}, h)
    asyncio.run(c.poll())
    s = c.protection
    assert s["pairings"][0]["remote_site"] == "vc-b" and s["pairings"][0]["status"] == "CONNECTED"
    assert [p["verdict"] for p in s["plans"]] == ["ok", "bad"] and s["groups"][0]["vms"] == 2 and s["groups"][0]["vms_bad"] == 1
    assert s["vms"][1]["errors"] == "RPO 위반"
    d = PR.build([NS(name="srm", type="srm", enabled=True, protection=s)], NOW)
    assert d["summary"]["srm"]["plans_bad"] == 1 and d["summary"]["srm"]["vms_bad"] == 1


def test_vcenter_backup_and_ui():
    sch = {"default": {"enable": True, "location": "sftp://bk.lab/vcsa", "recurrence_info": {"hour": 1, "minute": 30, "days": []}}}
    jobs = {"20261109-013000": {"status": "SUCCEEDED", "end_time": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(NOW - 7200)), "type": "SCHEDULED", "messages": []},
            "20261108-013000": {"status": "FAILED", "end_time": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(NOW - 86400 - 7200)), "type": "SCHEDULED",
                                "messages": [{"default_message": "디스크 부족"}]}}
    p = PR.vcenter_backup(sch, jobs, NOW)
    assert p["schedule"] == "매일 01:30" and p["last"]["status"] == "SUCCESS" and PR.appliance_verdict(p, NOW)[0] == "ok" and len(p["history"]) == 2
    from app.connectors.demo import demo_protection, demo_vm_protection
    d = PR.build([NS(name=f"demo-{t}", type=t, enabled=True, protection=demo_protection(t),
                     health_snap=(demo_vm_protection() if t == "vcenter" else None)) for t in ("vcenter", "nsx", "sddc", "srm")], NOW)
    s = d["summary"]
    assert s["appliances"]["total"] == 3 and s["appliances"]["bad"] == 1 and s["srm"]["plans_bad"] == 1 and s["snapshots"]["leftover"] >= 1
    assert s["vm_backup"]["vms"] > 0 and s["vm_backup"]["ok"] > 0
    nav = (ROOT / "app/static/navgroup.js").read_text(encoding="utf-8")
    assert re.search(r'\["g-dr", "DR·보호", "[^"]*", \["dr"\]\]', nav)
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="nav-dr"' in html and 'id="drawer-dr"' in html and html.index("/static/dr.js") < html.index("navgroup.js")
    from app.security.auth import ROUTE_RULES
    assert any(m == "POST" and "dr/run" in rx and p_ == "operate" for m, rx, p_ in ROUTE_RULES)
    assert subprocess.run(["node", "--check", str(ROOT / "app/static/dr.js")]).returncode == 0
