"""2.35.0 가정 분석 — 피크(95퍼센타일) 기준, 뺄 호스트 지정(교체), 장애 가정, 가정 저장·비교"""
import asyncio
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from app import whatif as W
from app.perfstore import METRICS, PerfStore
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _h(name, cores=64, ghz=2.5, mem_gb=1000, cpu_used=40000.0, mem_used_gb=400.0, sockets=2):
    return {"name": name, "cpu_mhz": cores * ghz * 1000, "mem_mb": mem_gb * 1024.0, "core_mhz": ghz * 1000, "cpu_used": cpu_used, "mem_used": mem_used_gb * 1024, "sockets": sockets, "cpu_model": "X"}


BASE = {"hosts": [_h("old1", 24, 2.5, 500, 20000, 300), _h("old2", 24, 2.5, 500, 20000, 300), _h("esx3"), _h("esx4")], "vms_on": 100, "vcpu": 400, "vm_mem_mb": 0}


def _fill(ps, eids, hours, cpu, mem):
    now = int(time.time()) // 3600 * 3600
    cols = ", ".join(list(METRICS) + [m + "_max" for m in METRICS])
    for i in range(hours):
        for e in eids:
            c, m = cpu(i, e), mem(i, e)
            vals = {"cpu": c, "mem": m}
            row = [vals.get(k) for k in METRICS] + [vals.get(k) for k in METRICS]
            ps._x(f"INSERT INTO h1(ts, eid, {cols}, n) VALUES(?,?,{','.join('?' * len(row))},12)", (now - (i + 1) * 3600, e, *row))


def test_cluster_peak_percentile(tmp_path):
    ps = PerfStore(str(tmp_path / "perf.db"), {})
    # 호스트 2대(각 100000MHz · 100000MB). 100시간 중 5시간만 80%, 나머지 20% → p95 는 80% 구간의 시작, 최대 80%
    _fill(ps, [1, 2], 100, lambda i, e: 80.0 if i < 5 else 20.0, lambda i, e: 60.0 if i < 10 else 30.0)
    r = ps.cluster_peak([(1, 100000.0, 100000.0), (2, 100000.0, 100000.0)], days=14)
    assert r["samples"] == 100 and r["cpu_max_mhz"] == 160000 and r["cpu_mhz"] == 40000 and r["mem_mb"] == 120000   # 95번째 = cpu 는 아직 20%, mem 은 60%
    assert round(r["cpu_avg_mhz"]) == round((5 * 160000 + 95 * 40000) / 100) and r["span_h"] == 100
    assert ps.cluster_peak([(1, 100000.0, 100000.0), (2, 100000.0, 100000.0)], days=14, q=0.99)["cpu_mhz"] == 160000
    assert ps.cluster_peak([(1, 1.0, 1.0)], days=1)["samples"] in (23, 24) and ps.cluster_peak([(99, 1.0, 1.0)], days=14) == {"samples": 0} and ps.cluster_peak([], 14) == {"samples": 0}
    ps._x("DELETE FROM h1 WHERE eid=2 AND ts >= ?", (int(time.time()) - 3 * 3600,))       # 한 대가 빠진 시각은(호스트의 80% 미만) 버림
    assert ps.cluster_peak([(1, 100000.0, 100000.0), (2, 100000.0, 100000.0)], days=14)["samples"] in (97, 98)


def test_peak_basis_changes_demand():
    now = W.simulate(BASE, {})
    assert now["basis"] == {"kind": "now", "why": ""} and now["before"]["mem"]["used_gb"] == 1400
    pk = W.simulate(BASE, {"add_vms": 10}, None, {"cpu_mhz": 240000.0, "mem_mb": 2100 * 1024.0, "cpu_max_mhz": 300000.0, "mem_max_mb": 2300 * 1024.0, "days": 14, "samples": 336, "span_h": 336})
    assert pk["basis"]["kind"] == "p95" and pk["basis"]["days"] == 14 and pk["basis"]["now_mem_gb"] == 1400 and pk["basis"]["max_mem_gb"] == 2300
    assert pk["before"]["mem"]["used_gb"] == 2100 and pk["before"]["cpu"]["used_ghz"] == 240 and pk["before"]["mem"]["pct_usable"] == 105.0 and pk["before"]["verdict"] == "bad"   # 지금 값으로는 70% — 피크로는 넘침
    assert pk["after"]["mem"]["used_gb"] == 2100 + 10 * 12.8
    fb = W.simulate(BASE, {}, None, {"why": "성능 이력이 3시간뿐이라(최소 24시간) 지금 값으로 계산했습니다"})
    assert fb["basis"]["kind"] == "now" and "3시간" in fb["basis"]["why"] and fb["before"]["mem"]["used_gb"] == 1400


def test_replace_named_hosts():
    # 낡은 24코어·500GB 2대를 빼고 64코어·1000GB 1대를 넣는다
    r = W.simulate(BASE, {"remove_names": ["old1", "old2", "old1"], "add_hosts": 1, "host_sockets": 2, "host_cores": 64, "host_core_ghz": 2.5, "host_mem_gb": 1000})
    assert r["inputs"]["remove_names"] == ["old1", "old2"] and r["before"]["hosts"] == 4 and r["after"]["hosts"] == 3
    assert r["after"]["mem"]["total_gb"] == 3000 and r["after"]["mem"]["usable_gb"] == 2000 and r["after"]["mem"]["used_gb"] == 1400 and r["after"]["mem"]["pct_usable"] == 70.0   # 수요는 그대로 남는다
    assert r["license"] == {"before": 32 * 2 + 64 * 2, "after": 64 * 3, "delta": 0, "per_new_host": 64}     # 24코어 2소켓 = 32코어로 셈
    with pytest.raises(ValueError, match="없는 호스트"):
        W.simulate(BASE, {"remove_names": ["없음"]})
    with pytest.raises(ValueError, match="모두"):
        W.simulate(BASE, {"remove_names": ["old1", "old2", "esx3", "esx4"]})
    with pytest.raises(ValueError, match="모두"):
        W.simulate(BASE, {"remove_names": ["old1", "old2", "esx3"], "remove_hosts": 1})


def test_host_failure_consumes_ha():
    f = W.simulate(BASE, {"remove_names": ["esx3"], "consume_ha": True})
    assert f["inputs"]["consume_ha"] and f["inputs"]["ha_failures"] == 1 and f["inputs"]["ha_after"] == 0 and f["before"]["mem"]["usable_gb"] == 2000        # 지금: N+1
    assert f["after"]["hosts"] == 3 and f["after"]["mem"]["usable_gb"] == 2000 and f["after"]["mem"]["pct_usable"] == 70.0 and f["after"]["verdict"] == "ok"   # 죽은 뒤: 남은 3대 전부가 쓸 수 있는 용량
    d = W.simulate(BASE, {"remove_names": ["esx3"]})                                                                   # 그냥 빼면(폐기) N+1 을 다시 남겨야 함
    assert d["inputs"]["ha_after"] == 1 and d["after"]["mem"]["usable_gb"] == 1000 and d["after"]["verdict"] == "bad"
    two = W.simulate(BASE, {"remove_names": ["esx3", "esx4"], "consume_ha": True})                                     # 2대 장애 = 여유 1대로는 모자람
    assert two["inputs"]["ha_after"] == 0 and two["after"]["mem"]["usable_gb"] == 1000 and two["after"]["verdict"] == "bad"


def test_scenarios_store_and_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_capacity import build_router
    from app.security.auth import AuthManager
    rp = AuthManager.required_perm
    assert rp("GET", "/api/capacity/whatif/scenarios") == "view" and rp("POST", "/api/capacity/whatif/scenarios") == "operate" and rp("DELETE", "/api/capacity/whatif/scenarios/2") == "operate"
    assert rp("POST", "/api/capacity/whatif") == "view"
    topo = {"clusters": {"wld": {"hosts": ["e1", "e2", "e3"]}},
            "hosts": {f"e{i}": {"cpu_mhz": 160000, "core_mhz": 2500, "mem_mb": 1024000, "cpu_used_mhz": 40000, "mem_used_mb": 400000, "sockets": 2} for i in (1, 2, 3)}, "vms": {}}

    class Cap:
        async def overview(self, days=None):
            return {"items": []}

    async def audit(*a, **k):
        return None
    e = _engine(tmp_path)
    ps = PerfStore(str(tmp_path / "perf.db"), {})
    eng = NS(capacity=Cap(), store=e.store, connectors=[NS(name="vc1", type="vcenter", enabled=True, topology=topo)], perfwatch=NS(store=ps))
    app = FastAPI()
    app.include_router(build_router(eng, {}, lambda r: {"user": "op"}, audit))
    with TestClient(app) as cl:
        c = cl.get("/api/capacity/whatif").json()["clusters"][0]
        assert [h["name"] for h in c["host_list"]] == ["e1", "e2", "e3"] and c["host_list"][0] == {"name": "e1", "cores": 64, "mem_gb": 1000}
        r = cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "basis": "p95", "basis_days": 14}).json()
        assert r["basis"]["kind"] == "now" and "호스트가 충분히 없어" in r["basis"]["why"] and r["host_names"] == ["e1", "e2", "e3"]    # 이력 없음 → 지금 값 + 사유
        for i, n in enumerate(("e1", "e2", "e3")):
            ps._ids[("host", "vc1", n)] = i + 1
        _fill(ps, [1, 2, 3], 10, lambda i, e: 50.0, lambda i, e: 50.0)
        r = cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "basis": "p95", "basis_days": 14}).json()
        assert r["basis"]["kind"] == "now" and "10시간" in r["basis"]["why"]
        ps._x("DELETE FROM h1")
        _fill(ps, [1, 2, 3], 48, lambda i, e: 50.0, lambda i, e: 75.0)
        r = cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "basis": "p95", "basis_days": 14}).json()
        assert r["basis"]["kind"] == "p95" and r["basis"]["samples"] == 48 and r["before"]["mem"]["used_gb"] == 2250 and r["before"]["cpu"]["used_ghz"] == 240
        assert cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "basis": "p95", "basis_days": 3}).status_code == 400
        s = cl.post("/api/capacity/whatif/scenarios", json={"name": " 증설안  A ", "vcenter": "vc1", "cluster": "wld", "add_hosts": 1, "host_cores": 64, "host_mem_gb": 1000, "basis": "p95", "basis_days": 14,
                                                           "remove_names": ["e1"], "쓸데없는키": "x", "vm_vcpu": ""})
        assert s.status_code == 200 and s.json()["name"] == "증설안 A" and s.json()["inputs"] == {"add_hosts": 1, "host_cores": 64, "host_mem_gb": 1000, "basis": "p95", "basis_days": 14, "remove_names": ["e1"]}
        assert cl.post("/api/capacity/whatif/scenarios", json={"name": "", "vcenter": "vc1", "cluster": "wld"}).status_code == 400
        assert cl.post("/api/capacity/whatif/scenarios", json=[1]).status_code == 400
        L = cl.get("/api/capacity/whatif/scenarios").json()["scenarios"]
        assert len(L) == 1 and L[0]["by"] == "op"
        again = cl.post("/api/capacity/whatif", json={**L[0]["inputs"], "vcenter": L[0]["vcenter"], "cluster": L[0]["cluster"]}).json()     # 저장한 가정을 지금 값으로 다시 계산
        assert again["after"]["hosts"] == 3 and again["inputs"]["remove_names"] == ["e1"] and again["basis"]["kind"] == "p95"
        assert cl.delete(f"/api/capacity/whatif/scenarios/{L[0]['id']}").status_code == 200 and cl.delete("/api/capacity/whatif/scenarios/999").status_code == 404


def test_ui_wiring():
    js = (S / "whatif.js").read_text(encoding="utf-8")
    for k in ("wi-fail", "wi-save", "wi-cmp", "remove_names", "consume_ha", 'value="p95:${d}"', "/api/capacity/whatif/scenarios", "function payload", "function compare"):
        assert k in js, k
    assert subprocess.run(["node", "--check", str(S / "whatif.js")], capture_output=True).returncode == 0
    assert "ENGINE.perfwatch = PW" in (ROOT / "app" / "main.py").read_text(encoding="utf-8")
