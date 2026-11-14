"""1.12 — 논리 토폴로지(VM·Pod·네트워크)·서비스 흐름도, Avi 처리량·End user, vSAN 관제, 정산(Billing), 보안 판독(하드닝·KISA·VMSA/CVE)"""
import asyncio
import json
import os
import socket
import tempfile
import time
from types import SimpleNamespace as NS

import pytest

from app import assess, billing, stack, vsan
from app.connectors.vmware_rest import AviConnector, aggregate_app_logs
from app.store import Store


def _env():
    vc = NS(type="vcenter", name="vc", enabled=True, host="vc", state=lambda: {"name": "vc", "type": "vcenter", "state": "ok", "last_ok": time.time()}, topology={
        "hosts": {"esx01": {"moid": "host-1", "cluster": "CL", "conn": "connected", "status": "green", "cpu_mhz": 2000, "cpu_used_mhz": 500, "core_mhz": 2000,
                            "mem_mb": 100, "mem_used_mb": 50, "uuid": "dcf7fb3c-4a1c-5a05-b730-5e09f3704e2f",
                            "vsan": {"enabled": True, "role": "master", "health": "healthy", "disk_groups": 2, "capacity_disks": 4, "disk_issues": []}}},
        "vms": {"app01": {"host": "esx01", "power": "poweredOn", "ips": ["10.0.0.11"], "networks": ["seg-web"], "vcpu": 4, "mem_mb": 8192, "prov_gb": 100,
                          "cluster": "CL", "folder": "DC/BANK/Prod", "tags": ["CostCenter:bank"], "cpu_mhz": 4000, "mem_used_mb": 4096, "moid": "vm-1"},
                "db01": {"host": "esx01", "power": "poweredOff", "ips": [], "networks": ["pg-db"], "vcpu": 8, "mem_mb": 16384, "prov_gb": 500,
                         "cluster": "CL", "folder": "DC/CARD", "tags": [], "moid": "vm-2"},
                "worker-1": {"host": "esx01", "power": "poweredOn", "ips": ["10.0.40.11"], "networks": ["seg-web"], "vcpu": 2, "mem_mb": 4096, "prov_gb": 60,
                             "cluster": "CL", "folder": "DC/VKS", "tags": [], "moid": "vm-3"}},
        "clusters": {"CL": {"hosts": ["esx01"], "vsan": True}},
        "datastores": {"vsanDatastore": {"type": "vsan", "capacity_gb": 1000, "free_gb": 400, "used_pct": 60, "hosts": ["esx01"]},
                       "local-esx01": {"type": "VMFS", "capacity_gb": 400, "free_gb": 390, "used_pct": 2.5, "hosts": ["esx01"], "local": True, "shared": False},
                       "san-01": {"type": "VMFS", "capacity_gb": 2000, "free_gb": 100, "used_pct": 95, "hosts": ["esx01", "esx02"], "local": False, "shared": True},
                       "nfs-01": {"type": "NFS41", "capacity_gb": 500, "free_gb": 250, "used_pct": 50, "hosts": ["esx01"], "remote": "nas:/vol"}},
        "networks": {"pg-db": {"kind": "dvportgroup", "vlan": 130, "dvs": "dvs1", "accessible": True}}, "updated": 1.0})
    ucs = NS(type="redfish", name="bmc", enabled=True, host="bmc1", server={"uuid": "dcf7fb3c-4a1c-5a05-b730-5e09f3704e2f", "serial": "S1"},
             entities=lambda: [{"state": "ok"}], state=lambda: {"state": "ok"}, display="srv-01", cfg={}, vendor="HPE")
    nsx = NS(type="nsx", name="nsx", enabled=True, host="nsx", edges={}, edge_info={}, _edge_state={},
             inv={"tier0": [{"id": "t0", "name": "T0"}], "tier1": [{"id": "t1", "name": "T1", "tier0": "t0"}],
                  "segments": [{"name": "seg-web", "tier1": "t1", "connected_to": "t1", "gateway": "10.0.0.1/24"}], "edge_clusters": []},
             state=lambda: {"state": "ok"})
    vks = NS(type="vks", name="vks", enabled=True, cluster_label="wld", inv={
        "nodes": [{"name": "worker-1", "ready": "True", "roles": ["worker"], "ip": "10.0.40.11"}],
        "pods": [{"ns": "bank", "name": f"api-{i}", "node": "worker-1", "phase": "Running", "ready": "1/1", "restarts": 0, "ip": f"192.168.0.{10 + i}",
                  "host_ip": "10.0.40.11"} for i in range(3)] + [{"ns": "bank", "name": "bad", "node": "worker-1", "phase": "Pending", "ip": ""}]})
    avi = NS(type="avi", name="avi", enabled=True, host="avi", se={"se1": {"state": "OPER_UP", "host": "esx01", "se_group": "G"}},
             vs={"vs-1": {"name": "web", "state": "OPER_UP", "vips": ["10.9.9.9"], "ports": [443], "pool": "p-web", "ses": ["se1"], "metrics": {"bw": [1, 2]}},
                 "vs-2": {"name": "api", "state": "OPER_UP", "vips": ["10.9.9.10"], "ports": [443], "pool": "p-api", "ses": ["se1"]}},
             pools=[{"name": "p-web", "up": 1, "servers": 2, "members": [{"ip": "10.0.0.11", "port": 8443}, {"ip": "172.16.0.5", "port": 80}]},
                    {"name": "p-api", "up": 3, "servers": 3, "members": [{"ip": f"192.168.0.{10 + i}", "port": 8080} for i in range(3)]}],
             vips=lambda: [{"uuid": "vs-1", "name": "web", "state": "OPER_UP", "vips": ["10.9.9.9"], "ports": [443]},
                           {"uuid": "vs-2", "name": "api", "state": "OPER_UP", "vips": ["10.9.9.10"], "ports": [443]}],
             _eu_cache={("vs-1", 60, 1000): {"ts": time.time(), "data": {"top_clients": [{"ip": "1.2.3.4", "n": 10, "err": 0}], "unique_clients": 1, "minutes": 60}}})
    return NS(connectors=[vc, ucs, nsx, vks, avi], anomalies={})


def test_stack_shows_each_vm_pod_and_network():
    d = stack.build(_env())
    ids = {n["id"]: n for n in d["nodes"]}
    assert "vm:vc:app01" in ids and ids["vm:vc:app01"]["label"] == "app01" and ids["vm:vc:app01"]["layer"] == stack.L_VM
    assert ids["vm:vc:db01"]["state"] == "maint"                                     # 꺼진 VM
    assert "pod:vks:bank/api-0" in ids and ids["pod:vks:bank/api-0"]["layer"] == stack.L_POD
    L = {(l["s"], l["t"]) for l in d["links"]}
    assert ("host:vc:esx01", "vm:vc:app01") in L and ("vm:vc:worker-1", "pod:vks:bank/api-0") in L
    assert ("vm:vc:app01", "nseg:nsx:seg-web") in L and ("t1:nsx:t1", "nseg:nsx:seg-web") in L and ("vm:vc:db01", "pg:vc:pg-db") in L
    assert ids["pod:vks:bank/bad"]["state"] == "warn" and d["totals"] == {"vms": 3, "pods": 4}
    d2 = stack.build(_env(), vm_limit=1)                                            # 표시 수 제한 → 나머지는 묶음
    assert "vmg:vc:esx01" in {n["id"] for n in d2["nodes"]}
    assert "vm:vc:worker-1" in {n["id"] for n in d2["nodes"]}                       # VKS 노드 VM 은 우선 표시


def test_flow_resolves_pool_members_to_vm_pod_host_server():
    f = stack.flow(_env(), vs="vs-1")
    ids = {n["id"]: n for n in f["nodes"]}
    L = {(l["s"], l["t"]) for l in f["links"]}
    assert ("cl:1.2.3.4", "vs:vs-1") in L                                           # End user 캐시의 상위 클라이언트
    assert ("vs:vs-1", "se:se1") in L and ("se:se1", "pool:p-web") in L and ("pool:p-web", "vm:app01") in L
    assert ("vm:app01", "net:seg-web") in L and ("net:seg-web", "t1:t1") in L and ("t1:t1", "t0:t0") in L
    assert ("vm:app01", "host:esx01") in L and any(s == "host:esx01" and t.startswith("srv:") for s, t in L)
    assert ids["m:172.16.0.5"]["kind"] == "ip"                                      # 인벤토리에 없는 멤버
    g = stack.flow(_env(), vs="api")
    gl = {(l["s"], l["t"]) for l in g["links"]}
    assert ("pool:p-api", "pod:bank/api-0") in gl and ("pod:bank/api-0", "vm:worker-1") in gl
    h = stack.flow(_env(), vm="worker-1")                                          # VM 기준: 이 VM(노드) 의 Pod 로 들어오는 VIP
    assert any(n["id"] == "vs:vs-2" for n in h["nodes"]) and not any(n["id"] == "vs:vs-1" for n in h["nodes"])
    assert [s["key"] for s in f["stages"]][:2] == ["client", "vs"]


def test_avi_end_user_aggregation_and_metrics_ids():
    logs = [{"client_ip": "1.1.1.1", "client_os": "iOS", "client_browser": "Safari", "client_location": "KR", "response_code": 200, "total_time": 10,
             "request_length": 100, "response_length": 900, "uri_path": "/a", "host": "m.x", "method": "GET", "significant": False},
            {"client_ip": "1.1.1.1", "client_os": "iOS", "response_code": 503, "total_time": 300, "request_length": 50, "response_length": 0, "significant": True},
            {"client_ip": "2.2.2.2", "client_os": "Windows", "response_code": 404, "total_time": 20}]
    d = aggregate_app_logs(logs, 30)
    assert d["logs"] == 3 and d["unique_clients"] == 2 and d["significant"] == 1
    assert d["top_clients"][0]["ip"] == "1.1.1.1" and d["top_clients"][0]["err"] == 1 and d["top_clients"][0]["bytes"] == 1050
    assert {x["k"]: x["n"] for x in d["codes"]} == {"2xx": 1, "5xx": 1, "4xx": 1} and d["latency_ms"]["p95"] == 300.0
    m = AviConnector.VIP_METRICS
    for mid in ("l4_client.avg_rx_bytes", "l4_client.avg_tx_bytes", "l4_client.avg_rx_pkts", "l4_client.avg_tx_pkts", "l7_client.avg_resp_2xx",
                "l7_client.avg_resp_4xx", "l7_client.avg_resp_5xx", "l7_client.avg_ssl_handshakes_new", "l7_client.apdexr"):
        assert mid in m


def test_avi_end_users_request_and_fallback():
    calls = []

    class R:
        def __init__(self, code, body):
            self.status_code, self._b, self.text = code, body, json.dumps(body)

        def json(self):
            return self._b

        def raise_for_status(self):
            pass

    class H:
        async def get(self, path, params=None, headers=None):
            calls.append((path, dict(params), headers))
            if "nf" in params:
                return R(400, {"error": "unknown"})
            return R(200, {"count": 1, "results": [{"client_ip": "9.9.9.9", "response_code": 200}]})
    c = AviConnector.__new__(AviConnector)
    c.cfg, c._http, c.vs = {}, H(), {"u1": {"name": "web", "tenant": "t1", "vips": ["1.1.1.1"], "ports": [443]}}
    d = asyncio.run(c.end_users("u1", 15, 500))
    assert d["unique_clients"] == 1 and d["tenant"] == "t1" and d["total_reported"] == 1
    assert calls[0][1]["type"] == 1 and calls[0][1]["virtualservice"] == "u1" and calls[0][1]["duration"] == 900 and calls[0][2] == {"X-Avi-Tenant": "t1"}
    assert "nf" not in calls[1][1]                                                  # 미지원 인자 → 기본 조회


def test_vsan_classification_and_noc_slot():
    assert vsan.is_vsan_event("esxi", "LSOM: LSOMEventNotify:7015: Throttled", {}) and vsan.is_vsan_event("vcenter", "x", {"eventType": "esx.problem.vob.vsan.lsom.diskerror"})
    assert not vsan.is_vsan_event("esxi", "random: unrelated domain message", {}) and not vsan.is_vsan_event("nsx", "vsan", {})
    e = _env()
    v = vsan.collect(e)
    assert v["clusters"][0]["name"] == "CL" and v["clusters"][0]["used_pct"] == 60.0 and v["hosts"][0]["role"] == "master"
    kinds = {r["name"]: r["kind"] for r in v["other"]}
    assert kinds == {"local-esx01": "local", "san-01": "san", "nfs-01": "nfs"} and [r["name"] for r in v["datastores"]] == ["vsanDatastore"]
    assert next(r for r in v["other"] if r["name"] == "san-01")["state"] == "warn"   # 95% 사용
    from app import noc
    e.store = NS(q=lambda *a, **k: asyncio.sleep(0, []))
    from app.runtime import MinuteCounter
    e.minutes = MinuteCounter(60)
    e.minutes.add("vsan", "syslog", sev="error", host="esx01")
    e.agents = NS(entities=lambda k: [], items={})
    e.runtime = lambda: {}
    e.llm = None
    e.moves = NS(alarms=lambda: [{"status": "red", "name": "vSAN health alarm 'Disk'", "entity": "CL", "ts": 1}, {"status": "red", "name": "Host CPU", "entity": "h", "ts": 1}])
    e.anomalies = {}

    async def q(*a, **k):
        return []
    e.store = NS(q=q)
    snap = asyncio.run(noc.snapshot(e, {}, only="vsan"))
    s = snap["slots"][0]
    assert s["id"] == "vsan" and sum(s["rate"]) == 1 and {x["kind"] for x in s["entities"]} >= {"vSAN 클러스터", "vSAN 호스트", "로컬 디스크"}
    d = asyncio.run(noc.domain_detail(e, {}, "vsan"))
    ids = [p["id"] for p in d["panels"]]
    assert ids[:5] == ["vsan-cl", "vsan-health", "vsan-host", "vsan-ds", "vsan-alarms"] and d["panels"][-1]["section"] and d["match"]
    assert [a["name"] for a in d["panels"][4]["rows"]] == ["vSAN health alarm 'Disk'"]


def test_engine_counts_vsan_pseudo_source():
    from app.models import LogEvent
    from app.vsan import is_vsan_event
    ev = LogEvent(source="esxi", connector="syslog", message="clomd[1234]: Object repair started", host="esx01")
    assert is_vsan_event(ev.source, ev.message, ev.attrs)


def _store():
    d = tempfile.mkdtemp()
    return Store(os.path.join(d, "t.db"))


def test_billing_sampling_matching_rates_and_report():
    e = _env()
    e.store = _store()
    B = billing.Billing(e, {})

    async def go():
        t0 = 1_800_000_000 - 1_800_000_000 % 3600 + 60
        assert await B.sample(t0) == 3
        assert await B.sample(t0 + 30) == 0                                     # 같은 5분 블록은 한 번만
        await B.sample(t0 + 300)
        rid = await B.save_rate({"name": "std", "currency": "KRW", "vcpu_hour": 10, "mem_gb_hour": 2, "disk_gb_hour": 0.1, "is_default": True}, "admin")
        tb = await B.save_tenant({"name": "BANK", "users": "bankuser"})
        tc = await B.save_tenant({"name": "CARD"})
        p1 = await B.save_project({"tenant_id": tb, "name": "bank-prod", "folders": "DC/BANK"})
        await B.save_project({"tenant_id": tc, "name": "all-cl", "clusters": ["CL"]})
        p3 = await B.save_project({"tenant_id": tc, "name": "tagged", "tags": ["CostCenter:bank"]})    # 태그가 폴더보다 우선
        rep = await B.report(t0 - 3600, t0 + 3600, "t")
        return rep, rid, p1, p3, tb
    rep, rid, p1, p3, tb = asyncio.run(go())
    by = {p["name"]: p for t in rep["tenants"] for p in t["projects"]}
    app = by["tagged"]["vm_rows"][0]
    assert app["vm"] == "app01" and app["matched_by"] == "태그" and app["on_hours"] == round(10 / 60, 2)
    # app01: 4 vCPU·8GB·100GB, 켜짐 2블록 → (4×10 + 8×2 + 100×0.1) × 5/60 × 2
    assert app["cost"] == round((40 + 16 + 10) * 5 / 60 * 2, 2) and app["cpu_util"] == 50.0 and app["mem_util"] == 50.0
    db = next(v for v in by["all-cl"]["vm_rows"] if v["vm"] == "db01")
    assert db["cost"] == 0 and db["on_hours"] == 0                                  # 꺼진 VM 은 과금 없음
    assert by["bank-prod"]["vms"] == 0 and rep["totals"]["unassigned_vms"] == 0
    assert "app01" in billing.Billing.to_csv(rep) and "명세서" in billing.Billing.statement_html(rep, rep["tenants"][1])

    async def go2():
        await B.save_rate({"name": "std", "vcpu_hour": 10, "mem_gb_hour": 2, "disk_gb_hour": 0.1, "weighting": True, "min_weight": 20,
                           "disk_when_off": True, "effective_from": 1_000}, "admin", rid)          # 새 버전(과거부터) — 가중·꺼짐 디스크
        return await B.report(1_800_000_000 - 7200, 1_800_000_000 + 7200, "t")
    rep2 = asyncio.run(go2())
    by2 = {p["name"]: p for t in rep2["tenants"] for p in t["projects"]}
    a2 = by2["tagged"]["vm_rows"][0]
    w = 0.2 + 0.8 * 0.5                                                              # CPU·메모리 사용률 50%
    assert a2["cpu_cost"] == round(4 * w * 10 * 5 / 60 * 2, 2)
    d2 = next(v for v in by2["all-cl"]["vm_rows"] if v["vm"] == "db01")
    assert d2["disk_cost"] == round(500 * 0.1 * 5 / 60 * 2, 2)
    rep3 = asyncio.run(B.report(1_800_000_000 - 7200, 1_800_000_000 + 7200, "t", tenant_ids={tb}))
    assert [t["name"] for t in rep3["tenants"]] == ["BANK"] and rep3["unassigned"] == []


def test_billing_period_and_matcher_rules():
    s, e, lab = billing.period_range("month", "2026-02", now=time.mktime((2026, 10, 1, 0, 0, 0, 0, 0, -1)))
    assert (e - s) / 86400 == 28 and "2월" in lab
    with pytest.raises(ValueError):
        billing.period_range("custom", start="2026-03-02", end="2026-03-01")
    M = billing.Matcher([{"id": 2, "vms": [], "tags": [], "folders": ["DC/A"], "clusters": []},
                         {"id": 1, "vms": [], "tags": [], "folders": ["DC/A/B"], "clusters": ["CL"]},
                         {"id": 3, "vms": ["x"], "tags": [], "folders": [], "clusters": []}])
    assert M.match("y", "CL", "DC/A/B/C", []) == (1, "폴더")                          # 가장 긴 폴더 경로
    assert M.match("y", "CL", "DC/AB", []) == (1, "클러스터")                          # 'DC/A' 는 'DC/AB' 의 접두가 아님(경로 단위)
    assert M.match("x", "CL", "DC/A", []) == (3, "VM")


def test_billing_api_scope_and_validation():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app import api_billing
    e = _env()
    e.store = _store()
    e.billing = billing.Billing(e, {})
    users = {"u": {"user": "bankuser", "role": "viewer"}}
    app = FastAPI()
    audit_log = []

    async def audit(req, action, target="", result="ok", detail=None):
        audit_log.append(action)
    app.include_router(api_billing.build_router(e, {}, lambda req: users["u"], audit, lambda req, p: users["u"]["role"] == "admin"))
    c = TestClient(app)
    users["u"] = {"user": "root", "role": "admin"}
    assert c.post("/api/billing/tenants", json={"name": ""}).status_code == 400
    tid = c.post("/api/billing/tenants", json={"name": "BANK", "users": ["bankuser"]}).json()["id"]
    c.post("/api/billing/tenants", json={"name": "CARD"})
    assert c.post("/api/billing/tenants", json={"name": "BANK"}).status_code == 409
    assert c.post("/api/billing/projects", json={"tenant_id": tid, "name": "p"}).status_code == 400   # 매칭 조건 없음
    assert c.post("/api/billing/projects", json={"tenant_id": tid, "name": "p", "clusters": ["CL"]}).status_code == 200
    users["u"] = {"user": "bankuser", "role": "viewer"}
    r = c.get("/api/billing/report?period=7d").json()
    assert [t["name"] for t in r["tenants"]] == ["BANK"] and r["unassigned"] == []
    assert c.get("/api/billing/report?period=7d&tenant=2").status_code == 403
    assert c.get("/api/billing/config").json()["scoped"] is True
    assert c.get(f"/api/billing/statement?tenant={tid}").status_code == 200 and "billing.statement" in audit_log
    assert c.get("/api/billing/report?period=custom&start=2026-13-01&end=x").status_code == 400


INV = {"vcenter": {"host": "vc01", "version": "8.0.3", "build": "24022515", "name": "vc"},
       "hosts": [{"name": "esx01", "version": "8.0.3", "build": "24022510", "conn": "connected", "lockdown": "lockdownDisabled",
                  "adv": {"UserVars.ESXiShellInteractiveTimeOut": 0, "UserVars.ESXiShellTimeOut": 900, "UserVars.DcuiTimeOut": 600,
                          "Security.AccountLockFailures": 5, "Security.AccountUnlockTime": 900, "Security.PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,7,7",
                          "Syslog.global.logHost": "", "Config.HostAgent.plugins.solo.enableMob": False, "Net.BlockGuestBPDU": 1,
                          "Mem.ShareForceSalting": 2, "Annotations.WelcomeMessage": ""},
                  "services": {"TSM-SSH": {"running": True, "policy": "on"}, "TSM": {"running": False, "policy": "off"}, "slpd": {"running": False, "policy": "off"},
                               "ntpd": {"running": True, "policy": "on"}},
                  "firewall": {"incoming_blocked": True, "open_all": ["sshServer", "dns"]}, "ntp": ["ntp1"],
                  "vswitch": [{"name": "vSwitch0", "promiscuous": False, "mac_changes": True, "forged": False}]},
                 {"name": "esx02", "conn": "disconnected"}],
       "dvpg": [{"name": "pg-a", "promiscuous": False, "mac_changes": False, "forged": False}],
       "vms": [{"name": "vm1", "power": "poweredOn", "tools": "guestToolsRunning", "adv": {"isolation.tools.copy.disable": "FALSE"}, "oldest_snapshot": time.time() - 10 * 86400},
               {"name": "vm2", "power": "poweredOff", "tools": "", "adv": {}}], "errors": []}


def test_hardening_rows_and_kisa():
    rows = assess.hardening(INV, {}, False)
    st = {(r["id"], r["target"]): r["status"] for r in rows}
    assert st[("ESXI-01", "esx01")] == "FAIL" and st[("ESXI-02", "esx01")] == "PASS" and st[("ESXI-07", "esx01")] == "PASS"
    assert st[("ESXI-10", "esx01")] == "FAIL" and st[("ESXI-12", "esx01")] == "PASS" and st[("ESXI-09", "esx01")] == "N/A"
    assert st[("ESXI-20", "esx01")] == "FAIL" and st[("ESXI-21", "esx01")] == "PASS" and st[("ESXI-26", "esx01")] == "PASS"
    assert st[("ESXI-28", "esx01")] == "WARN" and st[("ESXI-29", "esx01")] == "FAIL" and st[("ESXI-30", "esx01")] == "FAIL"
    assert st[("ESXI-31", "esx01")] == "MANUAL" and st[("ESXI-00", "esx02")] == "MANUAL" and st[("NET-01", "분산 포트그룹 전체")] == "PASS"
    vm = {r["id"]: r for r in rows if r["id"].startswith("VM-")}
    assert vm["VM-01"]["status"] == "FAIL" and "vm1" in vm["VM-01"]["current"] and vm["VM-05"]["status"] == "FAIL" and vm["VM-06"]["status"] == "WARN"
    k = {x["code"]: x for x in assess.kisa_summary(rows)}
    assert len(k) == 25 and k["HV-09"]["status"] == "FAIL" and k["HV-01"]["status"] == "MANUAL" and k["HV-11"]["status"] == "PASS"


NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2099-0001", "published": "2099-01-02T00:00:00", "descriptions": [{"lang": "en", "value": "ESXi heap overflow"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}]},
             "references": [{"url": "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/99999 VMSA-2099-0001"}],
             "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*"},
                                                         {"vulnerable": True, "criteria": "cpe:2.3:o:vmware:esxi:8.0:update_2:*:*:*:*:*:*"}]}]}]}},
    {"cve": {"id": "CVE-2099-0002", "published": "2099-02-02", "descriptions": [{"lang": "en", "value": "vCenter RCE"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}, "references": [],
             "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
                                                          "versionStartIncluding": "8.0", "versionEndExcluding": "8.0.3.00400"}]}]}]}},
    {"cve": {"id": "CVE-2099-0003", "descriptions": [], "metrics": {}, "references": [],
             "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:1:*:*:*:*:*:*:*"}]}]}]}}]}


def test_cve_parse_judge_and_assessor_run():
    advs = assess.parse_nvd(NVD)
    assert [a["id"] for a in advs] == ["CVE-2099-0001", "CVE-2099-0002"] and advs[0]["vmsa"] == ["VMSA-2099-0001"] and advs[0]["severity"] == "CRITICAL"
    own = assess.parse_own({"advisories": [{"id": "VMSA-2099-0009", "severity": "high", "cvss": 8.1, "cves": ["CVE-2099-0009"],
                                            "fixes": [{"product": "esxi", "branch": "8.0", "fixed_build": 24100000, "fixed_version": "8.0 U3x"}]}]})
    rows, hits = assess.evaluate(advs + own, [{"product": "esxi", "name": "esx01", "version": "8.0.3", "build": "24022510"},
                                              {"product": "esxi", "name": "esx09", "version": "7.0.3", "build": "1"},
                                              {"product": "vcenter", "name": "vc01", "version": "8.0.3", "build": "24022515"}])
    v = {(r["id"], r["target"]): r["verdict"] for r in rows}
    assert v[("VMSA-2099-0009", "esx01")] == "취약" and v[("CVE-2099-0001", "esx01")] == "가능" and v[("CVE-2099-0002", "vc01")] == "가능"
    assert not any(t == "esx09" for _, t in v) and rows[0]["verdict"] == "취약"
    assert assess.judge({"product": "esxi", "branch": "8.0", "fixed_build": 24000000}, "8.0.3", "24022510") is None    # 이미 고정 빌드 이상

    e = NS(store=_store(), connectors=[NS(type="vcenter", enabled=True, name="vc", host="vc01", assess_collect=lambda n: INV)])
    A = assess.Assessor(e, {})

    async def go():
        r = await A.import_json(json.dumps(NVD).encode())
        r2 = await A.import_json(json.dumps({"advisories": [{"id": "VMSA-2099-0009", "fixes": [{"product": "esxi", "branch": "8.0", "fixed_build": 24100000}]}]}).encode())
        with pytest.raises(ValueError):
            await A.import_json(b'{"x": 1}')
        d = await A.run("test")
        return r, r2, d, await A.latest(), await A.history()
    r, r2, d, last, hist = asyncio.run(go())
    assert r == {"imported": 2, "nvd": 2, "own": 0} and r2["own"] == 1
    s = d["summary"]
    assert s["cve"]["vulnerable"] == 1 and s["cve"]["possible"] == 2 and s["hosts"] == 2 and last["summary"]["ts"] == s["ts"] and hist[0]["counts"] == s["counts"]
    esx = next(x for x in d["rows"] if x["id"] == "ESXI-31" and x["target"] == "esx01")
    assert esx["status"] == "FAIL" and "취약 1" in esx["current"]
    assert "VMSA-2099-0009" in assess.Assessor.to_csv(d) and "KISA" in assess.Assessor.report_html(d)


def test_assess_collect_vcsim():
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector

    async def emit(_):
        pass
    c = VCenterConnector({"name": "vc", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, emit)

    async def go():
        await c.login()
        c._refresh_topology()
        return c.assess_collect(10)
    inv = asyncio.run(go())
    h = inv["hosts"][0]
    assert h["version"] and h["firewall"] and h["lockdown"] and h["vswitch"] and inv["vms"] and inv["vcenter"]["version"]
    v = next(iter(c.topology["vms"].values()))
    assert v["folder"].startswith(v["datacenter"]) and "core_mhz" in next(iter(c.topology["hosts"].values()))
    rows = assess.hardening(inv, {}, False)
    assert any(r["id"] == "ESXI-27" and r["status"] == "PASS" for r in rows)
