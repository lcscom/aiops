"""2.37.0 — 가정 대신 실측: vSAN 실측 정책 배수·절감률·예비 설정, VM CPU 피크(이동·DR), 스토리지 추세 분기 계획,
DR 복구 순서 계획·이름 매칭, 구성 변경 이력·알림, 인증서 확인·갱신 명령, 주간 리포트 수명 주기 절, 모바일 타일"""
import asyncio
import datetime as dt
import time
from pathlib import Path
from types import SimpleNamespace as NS

from app import whatif as W
from app import whatif_multi as WM
from app.perfstore import METRICS, PerfStore
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _h(name, cores=64, ghz=2.5, mem_gb=1000, cpu_used=40000.0, mem_used_gb=400.0):
    return {"name": name, "cpu_mhz": cores * ghz * 1000, "mem_mb": mem_gb * 1024.0, "core_mhz": ghz * 1000, "cpu_used": cpu_used, "mem_used": mem_used_gb * 1024,
            "sockets": 2, "cpu_model": "Intel(R) Xeon(R) Gold 6338"}


def _base(meas=None, n=4):
    return {"hosts": [_h(f"e{i}") for i in range(n)], "vms_on": 100, "vcpu": 400, "vsan": True, "vsan_esa": True, "evc": "",
            "ds_total_gb": 100000.0, "ds_free_gb": 40000.0, "ds_count": 1, "vm_disk_gb": 20000.0, "vsan_raw_gb": 100000.0, "vsan_free_gb": 40000.0,
            "vsan_meas": meas, "ds_names": ["vsan-ds"]}


def test_vsan_measured_defaults_and_override():
    m = W._vsan_meas({"space": {"policy_mult": 1.8, "ratio": 1.5, "total_gb": 1, "free_gb": 1}, "reserve": {"ops": "reported", "host_rebuild": "disabled"}, "ts": 5})
    assert m == {"policy_mult": 1.8, "dr": 1.5, "total_gb": 1, "free_gb": 1, "primary_gb": None, "ops_reserve": True, "host_reserve": False, "ts": 5}
    assert W._vsan_meas({}) is None and W._vsan_meas({"space": {"total_gb": 1}})["host_reserve"] is None
    r = W.simulate(_base(m), {})["vsan"]
    # 실측: 배수 1.8 · 절감률 1.5 · 호스트 예비 끔(vSAN 설정) → (100 TB × 0.9) ÷ 1.8 × 1.5 = 75 TB, 쓰는 원시 60 TB → 논리 50 TB
    assert r["policy"] == "measured" and r["mult"] == 1.8 and r["dr"] == 1.5 and r["host_reserve"] is False and r["usable_tb"] == 75.0 and r["used_tb"] == 50.0
    assert r["sources"] == {"policy": "실측", "dr": "실측", "host_reserve": "vSAN 설정"} and r["measured"]["policy_mult"] == 1.8
    o = W.simulate(_base(m), {"vsan_policy": "r1", "vsan_dr": 1, "vsan_host_reserve": "true"})["vsan"]
    assert o["policy"] == "r1" and o["dr"] == 1.0 and o["host_reserve"] is True and o["sources"] == {"policy": "입력", "dr": "입력", "host_reserve": "입력"}
    assert W.simulate(_base(m), {"vsan_host_reserve": "false"})["vsan"]["host_reserve"] is False
    n = W.simulate(_base(None), {"vsan_policy": "measured"})["vsan"]         # 실측이 없으면 클러스터 기본으로
    assert n["policy"] == "r5" and n["sources"]["dr"] == "기본 1배" and n["host_reserve"] is True and n["measured"] is None
    a = W.simulate(_base(m), {"add_hosts": 2, "host_flash_tb": 25})["vsan"]["after"]
    assert a["mult"] == 1.8 and "실측 배수" in a["note2"]


def test_quarter_storage_trend():
    q = W.simulate(_base(None), {}, {"cpu": 0.05, "mem": 0.05, "disk_gb_day": 100.0}, today=dt.date(2026, 11, 11))["quarters"]
    assert q["basis"] == "trend" and q["slopes"]["disk_gb_day"] == 100.0
    r0, r3 = q["rows"][0], q["rows"][-1]
    assert r0["storage_pct"] is not None and r3["storage_pct"] > r0["storage_pct"]
    v = W.simulate(_base(None), {})["vsan"]
    exp = round((v["after"]["used_tb"] + 100 * r3["days"] / 1000 / v["after"]["mult"] * v["dr"]) / v["after"]["usable_tb"] * 100, 1)
    assert r3["storage_pct"] == exp
    nv = {**_base(None), "vsan": False}
    q2 = W.simulate(nv, {}, {"cpu": 0.05, "mem": 0.05, "disk_gb_day": 1000.0}, today=dt.date(2026, 11, 11))["quarters"]["rows"]
    assert q2[0]["storage_pct"] == round(60.0 + 1000 * q2[0]["days"] / 1000 / 100.0 * 100, 1)


def _fill_vm(ps, eid, hours, cpu):
    now = int(time.time()) // 3600 * 3600
    cols = ", ".join(list(METRICS) + [m + "_max" for m in METRICS])
    for i in range(hours):
        row = [cpu(i) if k == "cpu" else None for k in METRICS] * 2
        ps._x(f"INSERT INTO h1(ts, eid, {cols}, n) VALUES(?,?,{','.join('?' * len(row))},12)", (now - (i + 1) * 3600, eid, *row))


def test_vm_peaks_and_attach(tmp_path):
    ps = PerfStore(str(tmp_path / "p.db"), {})
    _fill_vm(ps, 1, 100, lambda i: 90.0 if i < 3 else 20.0)
    _fill_vm(ps, 2, 10, lambda i: 50.0)
    pk = ps.vm_peaks([1, 2, None], days=14)
    assert set(pk) == {1} and pk[1]["cpu_pct"] == 20.0 and pk[1]["max_pct"] == 90.0 and pk[1]["samples"] == 100     # 95번째 = 아직 20%
    assert ps.vm_peaks([1], q=0.99)[1]["cpu_pct"] == 90.0 and ps.vm_peaks([]) == {}
    vms = [{"name": "a", "vcpu": 4, "cpu_mhz": 100}, {"name": "b", "vcpu": 2, "cpu_mhz": 700}]
    b = WM.attach_peaks(vms, {"a": {"cpu_pct": 50.0}}, 2500)
    assert b == {"vms_with_history": 1, "vms": 2, "kind": "p95"} and vms[0]["peak_mhz"] == 5000 and "peak_mhz" not in vms[1]
    assert WM._vm_demand(vms[0], 50) == (5000, 0) and WM._vm_demand(vms[1], 50)[0] == 700


def test_dr_plan_order():
    dst = {**_base(None, n=3), "hosts": [_h(f"d{i}", mem_used_gb=300) for i in range(3)]}
    g1 = [{"name": f"a{i}", "cpu_mhz": 1000, "mem_mb": 102400, "vcpu": 4, "power": "poweredOn"} for i in range(5)]     # 5 × 100 GB × 80%
    g2 = [{"name": f"b{i}", "cpu_mhz": 1000, "mem_mb": 512000, "vcpu": 4, "power": "poweredOn"} for i in range(3)]     # 3 × 500 GB × 80%
    r = WM.dr(dst, g1 + g2, [], dst_name="dst", order=[("핵심", g1), ("부가", g2 + g1[:1])])
    p = r["plan"]
    assert [x["group"] for x in p["rows"]] == ["핵심", "부가"] and p["rows"][1]["vms"] == 3               # 겹친 VM 은 한 번만
    assert p["rows"][0]["verdict"] == "ok" and p["rows"][1]["verdict"] == "bad" and p["fit_80"] == 1 and p["fit_100"] == 1
    assert any("1번째 그룹('핵심')까지" in x for x in r["summary"])
    z = WM.dr({**dst, "hosts": [_h(f"d{i}", mem_used_gb=990) for i in range(3)]}, g1, [], dst_name="dst", order=[("핵심", g1)])
    assert z["plan"]["fit_100"] == 0 and any("첫 그룹 '핵심' 부터" in x for x in z["summary"])
    assert WM.dr(dst, g1, [], dst_name="dst")["plan"] is None
    off = WM.dr(dst, [{"name": "o", "vcpu": 4, "mem_mb": 1024, "power": "poweredOff", "peak_mhz": 1234}], [], dst_name="dst")
    assert off["recovered"]["cpu_ghz"] == 1.2                                                           # 이력이 있으면 25% 가정 대신 피크


def test_drift_watch_history_events(tmp_path):
    from app import drift as D
    seen = []
    e = _engine(tmp_path)
    snap = {"hosts": {"e1": {"cluster": "c", "conn": "connected", "version": "8.0.3", "build": "1", "ntp_servers": ["n1"], "power_policy": "static",
                             "vmks": [{"device": "vmk1", "mtu": 9000, "services": ["vsan"], "switch": "dvs"}]}}, "clusters": {"c": {"drs_behavior": "fullyAutomated"}}}
    vc = NS(name="vc", type="vcenter", enabled=True, health_snap=snap, health={"updated": 100.0})
    dw = D.DriftWatch(NS(store=e.store, connectors=[vc], ingest=lambda ev: seen.append(ev)))
    _run(dw.tick())
    assert _run(dw.history("vc")) == []                                         # 첫 스냅숏은 비교 대상 없음
    _run(dw.tick())
    snap["hosts"]["e1"].update(build="2", ntp_servers=["n9"], power_policy="dynamic")
    snap["hosts"]["e1"]["vmks"][0]["mtu"] = 1500
    snap["clusters"]["c"]["drs_behavior"] = "manual"
    _run(dw.tick())
    assert _run(dw.history("vc")) == []                                         # 점검 시각(updated)이 그대로면 다시 비교하지 않음
    vc.health = {"updated": time.time()}
    _run(dw.tick())
    h = {x["key"]: x for x in _run(dw.history("vc"))}
    assert set(h) == {"build", "ntp", "power_policy", "vmk:vmk1:mtu", "drs_behavior"} and h["ntp"]["before"] == "n1" and h["ntp"]["after"] == "n9"
    keys = {ev.attrs["key"] for ev in seen}
    assert keys == {"power_policy", "vmk:vmk1:mtu", "drs_behavior"}                # NTP·빌드는 보안 판독이 알리므로 기록만
    assert all(ev.attrs["app"] == "config-drift" and ev.kind == "config" for ev in seen)
    assert len(_run(dw.history("vc", entity="e1"))) == 4 and _run(dw.history("other")) == []


def test_cert_commands_and_report_lifecycle(tmp_path):
    from app import certs as CT
    from app.reports import Reporter
    sc = CT.CertScanner(NS(store=None, connectors=[]))
    it = sc._item(src="vks", system="v", kind="cert-manager", name="ns/x", not_after=1.0, cmd="kubectl -n ns describe certificate x")
    assert it["cmd"].startswith("kubectl")
    src = (ROOT / "app" / "certs.py").read_text(encoding="utf-8")
    assert "cmctl renew" in src and "openssl s_client" in src and "rolloutBefore" in src
    now = time.time()
    html = Reporter.render_extended({"lifecycle": {"certs_scanned": True, "certs": [{"not_after": now + 86400 * 3, "days_left": 3, "kind": "API 서버", "name": "a:6443", "system": "vks1", "cluster": "bank/w"}],
                                                   "drift": [{"ts": now, "vcenter": "vc", "entity": "e1", "label": "NTP 서버", "before": "n1", "after": "n9", "severity": "warning"}],
                                                   "versions": [{"product": "esxi", "scope": "c1", "version": "8.0.3", "eogs": "2027-10-11", "days_left": 334}]}})
    assert "수명 주기" in html and "a:6443" in html and "n9" in html and "2027-10-11" in html
    assert "인증서 스캔 전입니다" in Reporter.render_extended({"lifecycle": {"certs_scanned": False, "certs": [], "drift": [], "versions": []}})

    async def main():
        e = _engine(tmp_path)
        e.certs = NS(last={"ts": now, "items": [{"days_left": 5, "band": "crit", "kind": "k", "name": "n", "system": "s"}, {"days_left": 1, "band": "auto"}]})
        from app.drift import DriftWatch
        e.driftwatch = DriftWatch(e)
        await e.driftwatch.observe("vc", {"hosts": {"h": {"_cluster": "c", "x": "1"}}, "clusters": {}}, now - 60)
        await e.driftwatch.observe("vc", {"hosts": {"h": {"_cluster": "c", "x": "2"}}, "clusters": {}}, now - 30)
        x = await Reporter(e).extended(now - 3600, now)
        return x["lifecycle"]
    lf = _run(main())
    assert [c["name"] for c in lf["certs"]] == ["n"] and len(lf["drift"]) == 1 and "versions" in lf


def test_api_dr_alias_order_history(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_capacity import build_router
    from app.api_lifecycle import build_router as build_lc
    from app.certs import CertScanner
    from app.drift import DriftWatch
    H = {f"d{i}": {"cpu_mhz": 160000, "core_mhz": 2500, "mem_mb": 1024000, "cpu_used_mhz": 40000, "mem_used_mb": 400000, "sockets": 2, "datastores": ["ds"], "cluster": "dst"} for i in range(3)}
    topo = {"clusters": {"dst": {"hosts": list(H)}}, "hosts": H, "datastores": {"ds": {"capacity_gb": 10000, "free_gb": 5000}},
            "vms": {"Core-DB01.bank.local": {"cluster": "src", "power": "poweredOn", "vcpu": 4, "mem_mb": 8192, "cpu_mhz": 500, "disk_gb": 50},
                    "card-app": {"cluster": "src", "power": "poweredOn", "vcpu": 4, "mem_mb": 8192, "cpu_mhz": 500, "disk_gb": 50}}}

    class Cap:
        async def overview(self, days=None):
            return {"items": []}

    async def audit(*a, **k):
        return None
    e = _engine(tmp_path)
    ps = PerfStore(str(tmp_path / "p.db"), {})
    ps._ids[("vm", "vc1", "card-app")] = 7
    _fill_vm(ps, 7, 48, lambda i: 40.0)
    vc = NS(name="vc1", type="vcenter", enabled=True, topology=topo, host="vc1", health_snap={}, health={})
    srm = NS(name="srm1", type="srm", enabled=True, protection={"groups": [], "vms": [{"group": "G2", "name": "core-db01"}, {"group": "G1", "name": "CARD-APP"}, {"group": "G1", "name": "ghost"}]})
    eng = NS(capacity=Cap(), store=e.store, connectors=[vc, srm], perfwatch=NS(store=ps), assess=None)
    eng.driftwatch = DriftWatch(eng)
    app = FastAPI()
    app.include_router(build_router(eng, {}, lambda r: {"user": "op"}, audit))
    app.include_router(build_lc(eng, CertScanner(eng), lambda r: {"user": "op"}, audit))
    with TestClient(app) as cl:
        d = cl.post("/api/capacity/whatif/dr", json={"dst_vcenter": "vc1", "dst_cluster": "dst", "groups": [{"srm": "srm1", "name": "G1"}, {"srm": "srm1", "name": "G2"}]}).json()
        assert d["recovered"]["vms"] == 2 and d["missing"] == ["ghost"]                                    # 대소문자·도메인 꼬리 무시
        assert [x["group"] for x in d["plan"]["rows"]] == ["G1", "G2"] and d["basis"]["vms_with_history"] == 1 and d["basis"]["kind"] == "p95"
        assert d["plan"]["rows"][0]["cpu_ghz"] == round(4 * 2500 * 0.40 / 1000, 1)                         # 이력 피크 40% × 4 vCPU × 2.5 GHz
        n = cl.post("/api/capacity/whatif/dr", json={"dst_vcenter": "vc1", "dst_cluster": "dst", "groups": [{"srm": "srm1", "name": "G1"}], "basis": "now"}).json()
        assert n["basis"]["kind"] == "now" and n["plan"]["rows"][0]["cpu_ghz"] == 0.5
        h = cl.get("/api/lifecycle/drift/history", params={"vcenter": "vc1"}).json()
        assert h["changes"] == [] and h["vcenter"] == "vc1"


def test_ui_and_mobile():
    wi = (S / "whatif.js").read_text(encoding="utf-8")
    for k in ('"measured"', "basisLine", "복구 순서 계획", "v: 37", "vSAN 공간 보고"):
        assert k in wi, k
    lc = (S / "lifecycle.js").read_text(encoding="utf-8")
    for k in ("/api/lifecycle/drift/history", "data-lfcopy", "function history", "lf-spark"):
        assert k in lc, k
    mb = (S / "mobile.js").read_text(encoding="utf-8")
    assert 'tile("life"' in mb and "drift7" in mb
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert '"life": life' in main and "DriftWatch(ENGINE)" in main and 'S.spawn("drift"' in main
    vh = (ROOT / "app" / "connectors" / "vsanhealth.py").read_text(encoding="utf-8")
    assert "primaryCapacityB" in vh and "capacityReservationInfo" in vh
    import subprocess
    for f in ("whatif.js", "lifecycle.js", "mobile.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
