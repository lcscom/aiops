"""2.34.0 서버 사양 — 수집 스크립트·vCenter·BMC 스캔에서 사양을 얻어 가정 분석에 쓰기, 라이선스 코어·스토리지·호환 주의점"""
import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from app import serverspec as SS
from app import whatif as W
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def test_licensed_cores_rule():
    # Broadcom KB 313548 — CPU(소켓)당 최소 16코어
    assert SS.licensed_cores(2, 16) == 32 and SS.licensed_cores(2, 24) == 32 and SS.licensed_cores(2, 64) == 64
    assert SS.licensed_cores(1, 8) == 16 and SS.licensed_cores(1, 6) == 16 and SS.licensed_cores(4, 40) == 64 and SS.licensed_cores(2, 40) == 40
    assert SS.licensed_cores(0, 40) == 40 and SS.licensed_cores(2, 0) == 0


def test_script_runs_and_output_normalizes():
    sh = ROOT / "scripts" / "spec" / "collect-server-spec.sh"
    assert subprocess.run(["sh", "-n", str(sh)]).returncode == 0
    out = subprocess.run(["sh", str(sh)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    raw = json.loads(out.stdout)                                                  # 이 테스트 기기의 실제 사양
    assert raw["schema"] == "vcf-aiops-server-spec/1" and raw["cores"] >= 1 and raw["mem_gb"] >= 1 and raw["sockets"] >= 1
    for k in ("hostname", "serial", "ip", "mac", "uuid"):
        assert k not in raw                                                       # 식별 정보는 담지 않음
    s = SS.normalize(raw, "script")
    assert s["cores"] == raw["cores"] and s["licensed_cores"] >= 16 and s["source"] == "script"
    txt = sh.read_text(encoding="utf-8")
    assert "esxcli hardware cpu global get" in txt and "/proc/cpuinfo" in txt
    import re
    code = "\n".join(ln for ln in txt.replace("2>/dev/null", "").splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"(^|[;&|(\s])(rm|mv|cp|dd|curl|wget|nc|ssh|scp|tee)\s", code) and "> /" not in code and "esxcli system settings" not in code   # 읽기만·전송 없음
    ps = (ROOT / "scripts" / "spec" / "collect-server-spec.ps1").read_text(encoding="utf-8")
    assert "vcf-aiops-server-spec/1" in ps and "Win32_Processor" in ps and "ConvertTo-Json" in ps and "Set-" not in ps and "Invoke-WebRequest" not in ps


def test_normalize_and_bad_input():
    s = SS.normalize({"schema": "vcf-aiops-server-spec/1", "vendor": "Dell Inc.", "model": "PowerEdge R760", "cpu_model": "Intel(R) Xeon(R) Gold 6548Y+  @ 2.50GHz",
                      "sockets": 2, "cores": 64, "threads": 128, "mem_gb": 1024, "disks": [{"gb": 3840, "type": "nvme"}] * 8 + [{"gb": 480, "type": "ssd"}, {"gb": 0, "type": "x"}],
                      "nics": [{"gbps": 25}, {"gbps": 25}, {"gbps": 1}], "hostname": "비밀"})
    assert s["core_ghz"] == 2.5 and s["flash_tb"] == 31.2 and s["nvme"] == 8 and s["nic_gbps"] == [25, 25, 1] and s["licensed_cores"] == 64 and "hostname" not in s
    assert SS.label(s) == "2×32코어 2.5GHz · 1024GB"
    for bad in ({}, {"cores": 0, "mem_gb": 64}, {"cores": 16}, {"sockets": 4, "cores": 2, "mem_gb": 64}, [1, 2]):
        with pytest.raises(ValueError):
            SS.normalize(bad)


def test_sources_vcenter_bmc_and_store(tmp_path):
    topo = {"hosts": {**{f"esx{i}": {"cluster": "wld", "cpu_mhz": 166400, "core_mhz": 2600, "mem_mb": 786432, "sockets": 2, "cpu_model": "Xeon Gold 6338", "hw_vendor": "Dell", "hw_model": "R750"} for i in range(3)},
                      "esx9": {"cluster": "mgmt", "cpu_mhz": 57600, "core_mhz": 2400, "mem_mb": 393216, "sockets": 2, "cpu_model": "Xeon Silver 4310"}, "bad": {"cluster": "wld"}}}
    v = SS.from_vcenter([NS(name="vc1", type="vcenter", enabled=True, topology=topo), NS(name="nsx", type="nsx", enabled=True)])
    assert [(x["cluster"], x["count"], x["spec"]["cores"], x["spec"]["mem_gb"], x["spec"]["licensed_cores"]) for x in v] == [("mgmt", 1, 24, 384, 32), ("wld", 3, 64, 768, 64)]
    assert v[1]["spec"]["model"] == "R750" and v[1]["id"].startswith("vc:vc1:esx")
    b = SS.from_readiness([{"target": "10.0.0.9", "ts": 1, "summary": {"vendor": "HPE", "model": "DL380 Gen11", "cpu": {"model": "Xeon Platinum 8468 @ 2.10GHz", "sockets": 2, "cores": 96, "threads": 192},
                                                                         "memory": {"total_gib": 2048}, "storage": {"nvme_tb": 30.7, "direct_nvme": 8}}},
                           {"target": "10.0.0.10", "summary": {}}])
    assert len(b) == 1 and b[0]["id"] == "bmc:10.0.0.9" and b[0]["spec"]["cores"] == 96 and b[0]["spec"]["core_ghz"] == 2.1 and b[0]["spec"]["flash_tb"] == 30.7

    async def main():
        st = SS.SpecStore(_engine(tmp_path).store)
        o = await st.add("", {"schema": "vcf-aiops-server-spec/1", "vendor": "Dell Inc.", "model": "R760", "sockets": 2, "cores": 64, "mem_gb": 1024}, "kim")
        assert o["name"] == "Dell Inc. R760" and o["id"].startswith("up:") and o["spec"]["source"] == "script"
        o2 = await st.add("직접 넣은 것", {"sockets": 1, "cores": 8, "mem_gb": 128}, "kim")
        assert o2["spec"]["source"] == "manual" and o2["spec"]["licensed_cores"] == 16
        assert [x["name"] for x in await st.list()] == ["직접 넣은 것", "Dell Inc. R760"]
        with pytest.raises(ValueError):
            await st.add("x", {"cores": 0}, "kim")
        assert await st.remove(int(o["id"][3:])) and not await st.remove(999) and len(await st.list()) == 1
    _run(main())


def _h(name, sockets=2, cores=64, ghz=2.6, mem_gb=768, model="Xeon Gold 6338"):
    return {"name": name, "cpu_mhz": cores * ghz * 1000, "mem_mb": mem_gb * 1024.0, "core_mhz": ghz * 1000, "cpu_used": 40000.0, "mem_used": 400 * 1024.0, "sockets": sockets, "cpu_model": model}


BASE = {"hosts": [_h(f"esx{i}") for i in range(4)], "vms_on": 200, "vcpu": 1200, "vm_mem_mb": 0, "vsan": True, "ds_total_gb": 100000.0, "ds_free_gb": 40000.0, "ds_count": 1, "vm_disk_gb": 50000.0}


def test_add_one_server_license_storage_notes():
    r = W.simulate(BASE, {"add_hosts": 1, "host_sockets": 2, "host_cores": 64, "host_core_ghz": 2.6, "host_mem_gb": 768, "host_flash_tb": 30.7, "host_cpu_model": "Xeon Gold 6338"})
    assert r["after"]["hosts"] == 5 and r["after"]["mem"]["usable_gb"] == 3072 and r["after"]["mem"]["pct_usable"] == 52.1 and r["before"]["mem"]["pct_usable"] == 69.4
    assert r["license"] == {"before": 256, "after": 320, "delta": 64, "per_new_host": 64}
    assert r["storage"]["pct"] == 60.0 and r["storage"]["after_pct"] == 60.0 and r["storage"]["raw_added_tb"] == 30.7 and r["storage"]["counted"] is False
    assert r["notes"] == [] and r["host_spec"]["sockets"] == 2
    small = W.simulate(BASE, {"add_hosts": 1, "host_sockets": 2, "host_cores": 16, "host_core_ghz": 3.0, "host_mem_gb": 256, "host_cpu_model": "Xeon Silver 4309Y"})
    assert small["license"]["per_new_host"] == 32 and small["license"]["delta"] == 32            # 8코어 × 2소켓도 32코어로 셈
    assert any("EVC" in n for n in small["notes"]) and any("16 미만" in n for n in small["notes"]) and any("vSAN" in n for n in small["notes"])
    big = W.simulate(BASE, {"add_hosts": 1, "host_sockets": 2, "host_cores": 128, "host_core_ghz": 2.6, "host_mem_gb": 2048, "host_flash_tb": 10})
    assert any("1.5배" in n for n in big["notes"]) and big["after"]["mem"]["usable_gb"] == 3072     # 큰 호스트가 HA 여유로 빠져 쓸 수 있는 용량은 4대분
    vm = W.simulate(BASE, {"add_vms": 100, "vm_disk_gb": 200, "add_hosts": 0})
    assert vm["storage"]["after_used_tb"] == 80.0 and vm["storage"]["after_pct"] == 80.0 and vm["storage"]["counted"] is True
    rm = W.simulate(BASE, {"remove_vms": 100})
    assert rm["storage"]["after_pct"] == 35.0                                                    # 평균 VM 디스크 250GB × 100
    unk = W.simulate({**BASE, "hosts": [dict(h, sockets=0) for h in BASE["hosts"]]}, {"add_hosts": 1, "host_sockets": 2, "host_cores": 64, "host_mem_gb": 768})
    assert unk["license"]["before"] is None and unk["license"]["per_new_host"] == 64             # 기존 소켓 수를 모르면 추가분만
    assert W.simulate({k: v for k, v in BASE.items() if not k.startswith("ds_")}, {})["storage"] is None
    avg = W.simulate(BASE, {"add_hosts": 1})                                                     # 평균 사양 = 기존 호스트의 소켓 수를 따름
    assert avg["license"] == {"before": 256, "after": 320, "delta": 64, "per_new_host": 64} and avg["host_spec"]["custom"] is False


def test_cluster_base_shared_datastores():
    topo = {"clusters": {"wld": {"hosts": ["e1", "e2"], "vsan": True}},
            "hosts": {"e1": {"cpu_mhz": 100000, "core_mhz": 2500, "mem_mb": 512000, "datastores": ["vsan", "local1", "nfs"], "sockets": 2, "cpu_model": "X"},
                      "e2": {"cpu_mhz": 100000, "core_mhz": 2500, "mem_mb": 512000, "datastores": ["vsan", "local2"], "sockets": 2, "cpu_model": "X"}},
            "datastores": {"vsan": {"capacity_gb": 50000, "free_gb": 20000}, "local1": {"capacity_gb": 400, "free_gb": 300, "local": True}, "nfs": {"capacity_gb": 9000, "free_gb": 1000},
                           "local2": {"capacity_gb": 400, "free_gb": 300}},
            "vms": {"a": {"cluster": "wld", "power": "poweredOn", "vcpu": 4, "mem_mb": 8192, "disk_gb": 120.5}}}
    b = W.cluster_base(NS(topology=topo), "wld")
    assert b["ds_count"] == 1 and b["ds_total_gb"] == 50000 and b["ds_free_gb"] == 20000 and b["vsan"] is True and b["vm_disk_gb"] == 120.5   # 모든 호스트가 보는 것만
    assert b["hosts"][0]["sockets"] == 2 and b["hosts"][0]["cpu_model"] == "X"


def test_api_and_ui_wiring(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_capacity import build_router
    from app.security.auth import AuthManager
    rp = AuthManager.required_perm
    assert rp("GET", "/api/capacity/specs") == "view" and rp("POST", "/api/capacity/specs") == "operate" and rp("DELETE", "/api/capacity/specs/3") == "operate"
    assert rp("GET", "/api/capacity/spec-script/collect-server-spec.sh") == "view"

    class RD:
        async def latest_hosts(self):
            return [{"target": "bmc1", "summary": {"cpu": {"sockets": 2, "cores": 48}, "memory": {"total_gib": 512}}}]

    async def audit(*a, **k):
        return None
    e = _engine(tmp_path)
    eng = NS(capacity=None, store=e.store, readiness=RD(), connectors=[])
    app = FastAPI()
    app.include_router(build_router(eng, {}, lambda r: {"user": "op"}, audit))
    with TestClient(app) as cl:
        j = cl.get("/api/capacity/specs").json()
        assert j["uploaded"] == [] and j["bmc"][0]["id"] == "bmc:bmc1" and [x["name"] for x in j["scripts"]] == ["collect-server-spec.sh", "collect-server-spec.ps1"]
        r = cl.post("/api/capacity/specs", json={"name": "새 서버", "spec": json.dumps({"schema": "vcf-aiops-server-spec/1", "sockets": 2, "cores": 64, "mem_gb": 1024})})
        assert r.status_code == 200 and r.json()["spec"]["licensed_cores"] == 64
        assert cl.post("/api/capacity/specs", json={"name": "x", "spec": "{깨진 JSON"}).status_code == 400
        assert cl.post("/api/capacity/specs", json={"name": "x", "spec": {"cores": 0}}).status_code == 400
        assert len(cl.get("/api/capacity/specs").json()["uploaded"]) == 1
        sc = cl.get("/api/capacity/spec-script/collect-server-spec.sh")
        assert sc.status_code == 200 and sc.text.startswith("#!/bin/sh") and "attachment" in sc.headers["content-disposition"]
        assert cl.get("/api/capacity/spec-script/..%2F..%2Fconfig.yaml").status_code == 404 and cl.get("/api/capacity/spec-script/install.sh").status_code == 404
        assert cl.delete(f"/api/capacity/specs/{r.json()['id'][3:]}").status_code == 200 and cl.delete("/api/capacity/specs/999").status_code == 404
    js = (S / "whatif.js").read_text(encoding="utf-8")
    for k in ("/api/capacity/specs", "wi-one", "host_sockets", "spec-script", "r.license", "r.storage", "r.notes", "esc("):
        assert k in js
    assert subprocess.run(["node", "--check", str(S / "whatif.js")], capture_output=True).returncode == 0
    assert '"summary.hardware.numCpuPkgs"' in (ROOT / "app/connectors/vcenter.py").read_text(encoding="utf-8")
    assert "scripts" in (ROOT / "appliance/patch/build-patch.sh").read_text(encoding="utf-8")      # 스크립트가 패치에 실림
