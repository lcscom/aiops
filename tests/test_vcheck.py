"""vCenter 인프라 상세 점검 — 규칙(Compute·Storage·Network·Hardware) + vcsim 수집 경로."""
import asyncio
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import vcheck  # noqa: E402

NOW = 1_800_000_000.0


def host(n, **kw):
    h = {"cluster": "CL1", "conn": "connected", "vendor": "Lenovo", "model": "ThinkSystem SR650 V3", "cpu_model": "Xeon 6430",
         "cores": 32, "mem_mb": 512 * 1024, "mem_used_mb": 200 * 1024, "bios": "ESE120M", "version": "8.0.3", "build": "24022510",
         "ntp_servers": ["10.0.0.1"], "services": {"ntpd": True, "TSM-SSH": False, "TSM": False}, "lockdown": "lockdownNormal",
         "vcpus": 64, "boot_time": NOW - 86400 * 30,
         "nics": [{"device": "vmnic0", "driver": "bnxtnet", "driver_version": "228.0.0", "firmware": "230.0.1", "speed": 25000, "duplex": True},
                  {"device": "vmnic1", "driver": "bnxtnet", "driver_version": "228.0.0", "firmware": "230.0.1", "speed": 25000, "duplex": True}],
         "vswitches": [{"name": "dvs-prod", "kind": "dvs", "mtu": 9000, "uplinks": ["vmnic0", "vmnic1"]}],
         "vmks": [{"device": "vmk1", "mtu": 9000, "switch": "dvs-prod", "services": ["vmotion"]}],
         "hbas": [{"device": "vmhba2", "model": "QLE2772", "driver": "qlnativefc", "driver_version": "5.4.81", "firmware": "9.12", "status": "online"}],
         "paths": {"dead": 0, "dead_luns": [], "single": []}, "sensors": [], "hw_status": []}
    h.update(kw)
    return n, h


def snap():
    hs = dict([host("esx01"), host("esx02"), host("esx03")])
    return {"hosts": hs, "clusters": {"CL1": {"ha": True, "ha_admission": True, "drs": True, "drs_behavior": "fullyAutomated", "evc": ""}},
            "datastores": {"ds-vmfs01": {"capacity": 10 * 2**40, "free": 3 * 2**40, "uncommitted": 1 * 2**40, "accessible": True,
                                         "type": "VMFS", "hosts": ["esx01", "esx02", "esx03"]}},
            "vms": [], "bmc": {}}


def ids(r):
    return {(f["id"], f["severity"]) for f in r["findings"]}


def test_clean_environment_has_no_findings():
    r = vcheck.evaluate(snap(), now=NOW)
    assert r["findings"] == [] and r["hosts"] == 3 and r["clusters"] == 1


def test_compute_rules():
    s = snap()
    s["clusters"]["CL1"].update(ha=False, drs=False)
    s["hosts"]["esx02"].update(build="23299997", version="8.0.2", cpu_model="Xeon 6330", vcpus=900,
                               services={"ntpd": False, "TSM-SSH": True, "TSM": False}, conn="connected")
    s["hosts"]["esx03"].update(conn="notResponding")
    r = vcheck.evaluate(s, now=NOW)
    got = ids(r)
    assert ("C03", "error") in got and ("C04", "warning") in got
    assert ("C05", "warning") in got and ("C06", "error") in got          # 빌드·CPU(EVC 없음) 드리프트
    assert ("C01", "critical") in got and ("C09", "warning") in got and ("C10", "warning") in got
    assert ("C07", "error") in got                                          # (64+900)/64 코어 > 8:1
    drift = next(f for f in r["findings"] if f["id"] == "C05")
    assert drift["outliers"] == ["esx02"]


def test_storage_rules():
    s = snap()
    s["datastores"]["ds-vmfs01"].update(free=int(0.4 * 2**40), uncommitted=8 * 2**40)
    s["datastores"]["ds-partial"] = {"capacity": 2**40, "free": 2**39, "accessible": True, "type": "VMFS", "hosts": ["esx01", "esx02"]}
    s["datastores"]["ds-gone"] = {"capacity": 2**40, "free": 2**39, "accessible": False, "type": "NFS", "hosts": ["esx01"]}
    s["hosts"]["esx01"]["paths"] = {"dead": 2, "dead_luns": ["naa.600a"], "single": ["naa.600b"]}
    s["hosts"]["esx01"]["hbas"][0]["status"] = "offline"
    s["vms"] = [{"name": "db01", "snapshots": [{"name": "pre-patch", "created": NOW - 86400 * 20}], "consolidation": True}]
    got = ids(vcheck.evaluate(s, now=NOW))
    assert ("S01", "critical") in got and ("S02", "warning") in got and ("S03", "critical") in got
    assert ("S07", "warning") in got and ("S04", "error") in got and ("S04", "warning") in got
    assert ("S08", "error") in got and ("S05", "error") in got and ("S06", "warning") in got


def test_network_rules():
    s = snap()
    s["hosts"]["esx01"]["nics"][1].update(speed=0)
    s["hosts"]["esx02"]["vswitches"][0]["mtu"] = 1500
    s["hosts"]["esx03"]["vmks"][0]["mtu"] = 1500
    s["hosts"]["esx03"]["nics"][1].update(speed=10000)
    got = ids(vcheck.evaluate(s, now=NOW))
    assert ("N01", "error") in got and ("N02", "warning") in got             # 링크 다운 → 이중화 상실
    assert ("N03", "error") in got                                          # vmk 9000 > 스위치 1500
    assert ("N03", "warning") in got and ("N04", "warning") in got          # vmotion MTU 드리프트·속도 불일치


def test_hardware_driver_firmware_drift_and_bmc():
    s = snap()
    s["hosts"]["esx03"]["nics"][0].update(driver_version="227.0.1", firmware="229.0.0")
    s["hosts"]["esx03"]["nics"][1].update(driver_version="227.0.1", firmware="229.0.0")
    s["hosts"]["esx02"]["bios"] = "ESE118K"
    s["hosts"]["esx01"]["sensors"] = [{"name": "Power Supply 2", "type": "power", "state": "red", "reading": "0 Watts"}]
    s["bmc"] = {"esx01": {"bmc_fw": "3.10", "firmware": [{"name": "XCC", "version": "3.10"}]},
                "esx02": {"bmc_fw": "3.10", "firmware": [{"name": "XCC", "version": "3.10"}]},
                "esx03": {"bmc_fw": "2.90", "firmware": [{"name": "XCC", "version": "2.90"}]}}
    r = vcheck.evaluate(s, now=NOW)
    got = ids(r)
    assert ("H01", "critical") in got and ("H02", "warning") in got and ("H05", "warning") in got
    titles = [f["title"] for f in r["findings"] if f["id"] in ("H03", "H04")]
    assert any("드라이버 bnxtnet" in t for t in titles) and any("펌웨어 bnxtnet" in t for t in titles) and any("BMC:XCC" in t for t in titles)
    hw = vcheck.hw_table(s)
    assert hw[0]["host"] == "esx01" and hw[0]["sensors_bad"] == 1 and hw[2]["bmc_fw"] == "2.90"


def test_driver_version_from_vibs():
    vibs = {"nmlx5-core": "4.23.0.66-1OEM", "qlnativefc": "5.4.81.2", "lsi-mr3": "7.727"}
    assert vcheck.driver_version("nmlx5_core", "", vibs) == "4.23.0.66-1OEM"
    assert vcheck.driver_version("qlnativefc", "", vibs) == "5.4.81.2"
    assert vcheck.driver_version("ixgben", "1.15.1.0", vibs) == "1.15.1.0"
    assert vcheck.driver_version("ne1000", "", vibs) == ""


def test_vcsim_collect():
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector

    async def emit(_):
        pass
    c = VCenterConnector({"name": "vc", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, emit)
    c.bmc_provider = lambda: {"DC0_C0_H0": {"connector": "bmc1", "bmc_fw": "3.10", "firmware": []}}

    async def go():
        await c.login()
        c._refresh_topology()
        return await c.run_health()
    evs = asyncio.run(go())
    h = c.health
    assert not h["error"] and h["hosts"] >= 1 and h["hw"]
    row = next(x for x in h["hw"] if x["host"] == "DC0_C0_H0")
    assert row["bios"] and row["nics"] and row["bmc_fw"] == "3.10" and row["esxi"].strip("() ")
    assert all(e.kind == "health" for e in evs)
    assert c._health_events(h["findings"], False) == []                  # 같은 결과 재평가 → 새 이벤트 없음
    assert time.time() - h["updated"] < 60
