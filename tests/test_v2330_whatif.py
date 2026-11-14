"""2.33.0 가정 분석(What-If) — VM·호스트 증감에 따른 여유·HA·남은 기간 계산, API, 화면 연결. 당직 기능은 제거됨"""
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from app import whatif as W

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _h(name, cpu_used=40000.0, mem_used_gb=400.0, cores=64, ghz=2.6, mem_gb=768):
    return {"name": name, "cpu_mhz": cores * ghz * 1000, "mem_mb": mem_gb * 1024.0, "core_mhz": ghz * 1000, "cpu_used": cpu_used, "mem_used": mem_used_gb * 1024}


BASE = {"hosts": [_h(f"esx{i}") for i in range(4)], "vms_on": 200, "vcpu": 1200, "vm_mem_mb": 200 * 16 * 1024}


def test_before_matches_hand_calc():
    r = W.simulate(BASE, {})
    b = r["before"]
    assert b["cpu"]["total_ghz"] == 665.6 and b["cpu"]["usable_ghz"] == 499.2 and b["cpu"]["used_ghz"] == 160.0      # 4대 × 64코어 × 2.6GHz, N+1 = 3대분
    assert b["mem"]["total_gb"] == 3072 and b["mem"]["usable_gb"] == 2304 and b["mem"]["pct_usable"] == 69.4 and b["mem"]["pct_total"] == 52.1
    assert b["vcpu_per_core"] == 4.69 and b["verdict"] == "ok" and r["after"]["mem"] == b["mem"]                      # 변경 없음 = 같은 값
    assert W.simulate(BASE, {"ha_failures": 0})["before"]["mem"]["usable_gb"] == 3072
    assert W.simulate(BASE, {"ha_failures": 2})["before"]["mem"]["usable_gb"] == 1536


def test_add_vms_verdict_room_hosts_needed():
    r = W.simulate(BASE, {"add_vms": 50, "vm_vcpu": 8, "vm_mem_gb": 32, "vm_cpu_util_pct": 25, "vm_mem_util_pct": 80}, {"cpu": 0.05, "mem": 0.1})
    a = r["after"]
    assert r["per_vm"] == {"cpu_ghz": 5.2, "mem_gb": 25.6}
    assert a["mem"]["used_gb"] == 2880 and a["mem"]["pct_usable"] == 125.0 and a["cpu"]["used_ghz"] == 420.0 and a["verdict"] == "bad" and r["limit"] == "mem"
    assert a["vms"] == 250 and a["vcpu"] == 1600 and a["vcpu_per_core"] == 6.25
    assert r["hosts_needed"] == 2                                                # 6대면 N+1 = 5대분 3840GB, 2880/3840 = 75%
    assert r["room"] == {"to_80": 0, "to_100": 0}
    assert r["before"]["mem"]["days_to_90"] == 378 and a["mem"]["days_to_90"] == 0 and a["cpu"]["days_to_90"] == 537   # (90-52.1)/0.1, 이미 초과, (90-63.1)/0.05
    ok = W.simulate(BASE, {"add_vms": 5, "vm_vcpu": 4, "vm_mem_gb": 16})
    assert ok["after"]["verdict"] == "ok" and ok["hosts_needed"] == 0
    assert ok["room"]["to_80"] == int((2304 * 0.8 - (1600 + 5 * 12.8)) / 12.8) and ok["room"]["to_100"] > ok["room"]["to_80"]
    warn = W.simulate(BASE, {"add_vms": 25, "vm_vcpu": 4, "vm_mem_gb": 16})       # 1600 + 320 = 1920 / 2304 = 83.3%
    assert warn["after"]["verdict"] == "warn" and warn["hosts_needed"] == 1


def test_hosts_add_remove_and_time_scaling():
    r = W.simulate(BASE, {"add_hosts": 2}, {"cpu": 0.05, "mem": 0.1})
    a = r["after"]
    assert a["hosts"] == 6 and a["mem"]["total_gb"] == 4608 and a["mem"]["usable_gb"] == 3840 and a["mem"]["pct_total"] == 34.7 and r["host_spec"] | {"sockets": 0, "cpu_model": ""} == {"cores": 64, "core_ghz": 2.6, "mem_gb": 768, "custom": False, "sockets": 0, "cpu_model": ""}
    assert a["mem"]["days_to_90"] == int((90 - 34.7) / (0.1 * 3072 / 4608))       # 용량이 늘면 같은 증가량이 차지하는 비율이 줄어 더 오래 감
    big = W.simulate(BASE, {"add_hosts": 1, "host_cores": 96, "host_core_ghz": 3.0, "host_mem_gb": 1536})
    assert big["host_spec"]["custom"] and big["after"]["mem"]["total_gb"] == 4608 and big["after"]["mem"]["usable_gb"] == 3072   # 가장 큰(새) 호스트가 HA 여유로 빠짐
    rm = W.simulate(BASE, {"remove_hosts": 1})
    assert rm["after"]["hosts"] == 3 and rm["after"]["mem"]["usable_gb"] == 1536 and rm["after"]["mem"]["pct_usable"] == 104.2 and rm["after"]["verdict"] == "bad"
    rv = W.simulate(BASE, {"remove_vms": 50})
    assert rv["after"]["vms"] == 150 and rv["after"]["mem"]["used_gb"] == 1200 and rv["after"]["vcpu"] == 900
    assert W.simulate(BASE, {"remove_vms": 9999})["after"]["vms"] == 0           # 있는 만큼만
    assert W.simulate(BASE, {"add_hosts": 2}, {"cpu": 0, "mem": -0.2})["after"]["mem"]["days_to_90"] is None     # 증가 없음


def test_bad_inputs():
    for body, msg in [({"add_vms": -1}, "add_vms"), ({"vm_vcpu": 0}, "vm_vcpu"), ({"add_vms": "많이"}, "숫자"), ({"remove_hosts": 4}, "모두"), ({"ha_failures": 9}, "ha_failures"),
                      ({"vm_cpu_util_pct": 0}, "vm_cpu_util_pct"), ({"add_vms": float("nan")}, "add_vms")]:
        with pytest.raises(ValueError, match=msg):
            W.simulate(BASE, body)
    with pytest.raises(ValueError, match="호스트가 없습니다"):
        W.simulate({"hosts": [], "vms_on": 0, "vcpu": 0, "vm_mem_mb": 0}, {})
    one = W.simulate({"hosts": [_h("a")], "vms_on": 10, "vcpu": 40, "vm_mem_mb": 0}, {})     # 호스트 1대 + N+1 = 쓸 수 있는 용량 0
    assert one["before"]["verdict"] == "bad" and one["before"]["mem"]["pct_usable"] is None


def test_cluster_base_from_topology():
    topo = {"clusters": {"wld": {"hosts": ["e1", "e2", "e3", "없는호스트"]}},
            "hosts": {"e1": {"cpu_mhz": 100000, "core_mhz": 2500, "mem_mb": 512000, "cpu_used_mhz": 30000, "mem_used_mb": 200000},
                      "e2": {"cpu_mhz": 100000, "core_mhz": 2500, "mem_mb": 512000, "cpu_used_mhz": 10000, "mem_used_mb": 100000, "maintenance": True},
                      "e3": {"cpu_mhz": 0, "mem_mb": 0}},
            "vms": {"a": {"cluster": "wld", "power": "poweredOn", "vcpu": 8, "mem_mb": 32768}, "b": {"cluster": "wld", "power": "poweredOff", "vcpu": 4, "mem_mb": 8192},
                    "c": {"cluster": "other", "power": "poweredOn", "vcpu": 2, "mem_mb": 4096}}}
    b = W.cluster_base(NS(topology=topo), "wld")
    assert [h["name"] for h in b["hosts"]] == ["e1"] and b["vms_on"] == 1 and b["vcpu"] == 8          # 유지보수·값 없는 호스트 제외, 켜진 VM 만
    assert W.cluster_base(NS(topology=topo), "없음") is None and W.cluster_base(NS(topology={}), "wld") is None


def test_api_and_wiring():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_capacity import build_router
    from app.security.auth import AuthManager
    assert AuthManager.required_perm("POST", "/api/capacity/whatif") == "view" and AuthManager.required_perm("GET", "/api/capacity/whatif") == "view"
    topo = {"clusters": {"wld": {"hosts": ["e1", "e2", "e3"]}},
            "hosts": {f"e{i}": {"cpu_mhz": 166400, "core_mhz": 2600, "mem_mb": 786432, "cpu_used_mhz": 40000, "mem_used_mb": 300000} for i in (1, 2, 3)},
            "vms": {f"v{i}": {"cluster": "wld", "power": "poweredOn", "vcpu": 4, "mem_mb": 16384} for i in range(30)}}

    class Cap:
        async def overview(self, days=None):
            return {"items": [{"kind": "cluster", "vcenter": "vc1", "name": "wld", "forecast": {"slope": 0.02}, "forecast_mem": {"slope": 0.05}, "days_observed": 21}]}

    async def audit(*a, **k):
        return None
    eng = NS(capacity=Cap(), store=None, connectors=[NS(name="vc1", type="vcenter", enabled=True, topology=topo), NS(name="nsx", type="nsx", enabled=True)])
    app = FastAPI()
    app.include_router(build_router(eng, {}, lambda r: {"user": "v"}, audit))
    with TestClient(app) as cl:
        c = cl.get("/api/capacity/whatif").json()["clusters"]
        assert [{k: v for k, v in x.items() if k != "host_list"} for x in c] == [{"vcenter": "vc1", "cluster": "wld", "hosts": 3, "vms_on": 30, "avg_host": {"cores": 64, "core_ghz": 2.6, "mem_gb": 768}}]
        r = cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "add_vms": 10})
        assert r.status_code == 200 and r.json()["after"]["vms"] == 40 and r.json()["slopes"] == {"cpu": 0.02, "mem": 0.05} and r.json()["days_observed"] == 21
        assert cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "없음"}).status_code == 404
        assert cl.post("/api/capacity/whatif", json={"vcenter": "nsx", "cluster": "wld"}).status_code == 404
        assert cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "wld", "add_vms": -5}).status_code == 400
        assert cl.post("/api/capacity/whatif", json=[1]).status_code == 400
    html = (S / "index.html").read_text(encoding="utf-8")
    assert html.index("/static/capacity.js") < html.index("/static/whatif.js")
    assert '["wi", "가정 분석"]' in (S / "capacity.js").read_text(encoding="utf-8") and "AIOPS_WHATIF" in (S / "whatif.js").read_text(encoding="utf-8")
    assert subprocess.run(["node", "--check", str(S / "whatif.js")], capture_output=True).returncode == 0


def test_oncall_removed():
    assert not (ROOT / "app" / "oncall.py").exists() and not (S / "oncall.js").exists()
    for f in [ROOT / "app" / "main.py", ROOT / "app" / "mobile.py", ROOT / "app" / "security" / "auth.py", S / "index.html", S / "navgroup.js", S / "mobile.js",
              ROOT / "mobile" / "android" / "AndroidManifest.xml", ROOT / "docs" / "GUIDE.md", ROOT / "config.example.yaml"]:
        t = f.read_text(encoding="utf-8")
        assert "oncall" not in t.lower() and "당직" not in t and "/api/mobile/act" not in t, f.name
    assert not (ROOT / "mobile/android/src/com/krvcf/vcfaiops/ActReceiver.java").exists()
