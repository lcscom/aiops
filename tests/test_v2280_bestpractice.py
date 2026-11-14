"""2.28.0 VMware 권장 구성 판독 — 규칙·판정·근거 문서"""
import re
import subprocess
import time
from pathlib import Path

from app.bestpractice import RULES, evaluate

ROOT = Path(__file__).resolve().parents[1]
NOW = time.time()


def _host(cl, speed=25000, mtu=9000, ht=True, pp="dynamic", cores=64, sockets=2):
    return {"cluster": cl, "conn": "connected", "cores": cores, "sockets": sockets, "numa_nodes": sockets, "ht_available": True, "ht_active": ht,
            "power_policy": pp, "nics": [{"device": "vmnic0", "speed": speed}, {"device": "vmnic1", "speed": speed}],
            "vswitches": [{"name": "vds", "uplinks": ["vmnic0", "vmnic1"]}],
            "vmks": [{"device": "vmk2", "mtu": mtu, "switch": "vds", "services": ["vsan"]}, {"device": "vmk1", "mtu": 9000, "switch": "vds", "services": ["vmotion"]}]}


def _good():
    cl = {"ha": True, "ha_admission": True, "drs": True, "drs_behavior": "fullyAutomated", "drs_rate": 3, "vsan": True, "vsan_esa": True,
          "ha_host_monitoring": "enabled", "ha_vm_monitoring": "vmMonitoringOnly", "ha_isolation": "powerOff",
          "ha_policy": "vim.cluster.FailoverResourcesAdmissionControlPolicy", "ha_cpu_pct": 25, "ha_mem_pct": 25, "ha_failover_level": 1}
    hosts = {f"esx{i}": _host("wld") for i in range(4)}
    vms = [{"name": f"vm{i}", "host": f"esx{i % 4}", "power": "poweredOn", "vcpu": 8, "nics": ["Vmxnet3"], "cdrom_connected": 0,
            "tools": "guestToolsRunning", "snapshots": 0, "snap_oldest": None} for i in range(40)]
    return {"hosts": hosts, "clusters": {"wld": cl}, "bp_vms": {"vms": vms, "collected": NOW, "error": ""}}


def test_recommended_cluster():
    r = evaluate(_good(), NOW)["clusters"][0]
    assert r["verdict"] == "ok" and r["score"] == 100 and not r["must_fail"], [x for x in r["results"] if x["status"] != "pass"]
    assert {x["id"] for x in r["results"]} == {x["id"] for x in RULES}


def test_not_recommended_and_partial():
    s = _good()
    s["clusters"]["wld"]["ha_isolation"] = "none"                                  # vSAN 격리 대응 → 필수 위반
    s["hosts"]["esx3"] = _host("wld", speed=10000, mtu=1500)                       # ESA 25GbE 미만 · MTU 불일치
    s["bp_vms"]["vms"][0]["snapshots"], s["bp_vms"]["vms"][0]["snap_oldest"] = 1, NOW - 5 * 86400
    for v in s["bp_vms"]["vms"][:5]:
        v["nics"] = ["E1000e"]
    r = evaluate(s, NOW)["clusters"][0]
    res = {x["id"]: x for x in r["results"]}
    assert r["verdict"] == "not" and set(r["must_fail"]) >= {"BP-C05", "BP-H03", "BP-H04"}
    assert res["BP-H04"]["entities"] == ["esx3(vsan 1500)"] and res["BP-H03"]["n_entities"] == 1
    assert res["BP-V02"]["status"] == "partial" and "35/40" in res["BP-V02"]["detail"]          # 87.5% → 부분
    assert res["BP-V03"]["status"] == "pass"                                                  # 1/40 위반 = 97.5%
    # 필수 위반을 고치면 점수로 판정(부분 권장)
    s["clusters"]["wld"]["ha_isolation"] = "powerOff"
    s["hosts"]["esx3"] = _host("wld")
    s["clusters"]["wld"].update(drs_behavior="partiallyAutomated", ha_vm_monitoring="vmMonitoringDisabled")
    s["hosts"]["esx0"]["ht_active"] = False
    r = evaluate(s, NOW)["clusters"][0]
    assert r["verdict"] == "partial" and 50 < r["score"] < 90


def test_non_vsan_and_no_vm_data():
    s = _good()
    s["clusters"]["wld"].update(vsan=False, ha=False)
    s["bp_vms"] = {}
    for h in s["hosts"].values():
        h["vmks"] = [k for k in h["vmks"] if "vsan" not in k["services"]]
    r = evaluate(s, NOW)["clusters"][0]
    res = {x["id"]: x for x in r["results"]}
    assert res["BP-C05"]["status"] == "na" and res["BP-C07"]["status"] == "na" and res["BP-H03"]["status"] == "na"
    assert res["BP-C01"]["status"] == "fail" and r["verdict"] == "not"
    assert res["BP-V01"]["status"] == "na" and "미수집" in res["BP-V01"]["detail"]


def test_rule_sources_and_ui():
    for r in RULES:
        assert r["level"] in ("must", "should", "may") and r["src"][1].startswith("https://") and r["rec"]
    assert len({r["id"] for r in RULES}) == len(RULES)
    nav = (ROOT / "app/static/navgroup.js").read_text(encoding="utf-8")
    assert re.search(r'"g-chk".*\["vchk", "bp", "life", "bot", "chg", "rd", "rv"\]', nav)     # 2.36.0 수명 주기 점검 추가
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="nav-bp"' in html and 'id="drawer-bp"' in html and html.index("bestpractice.js") < html.index("navgroup.js")
    from app.security.auth import ROUTE_RULES
    assert any(m == "POST" and "bestpractice/run" in rx and p == "operate" for m, rx, p in ROUTE_RULES)
    assert subprocess.run(["node", "--check", str(ROOT / "app/static/bestpractice.js")]).returncode == 0
