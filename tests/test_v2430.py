"""2.43.0 — 외장 스토리지 → vSAN ESA 전환 산정 · 내부 취약점 검증(약점·망 분리·공격 경로·계속 검증)"""
import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from app import esa as ESA
from app import vulnscan as VS
from tests.test_v2380 import _world_conns

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _conns():
    c = _world_conns()
    vc = c[0]
    for h in vc.topology["hosts"].values():
        h.update(cores=32, sockets=2, pnics=[{"name": "vmnic0", "speed": 25000}])
    vc.topology["datastores"]["ds1"].update(type="VMFS", capacity_gb=20000, free_gb=10000, prov_gb=14000, extents=["naa.1"])
    vc.topology["datastores"]["nfs-bk"] = {"capacity_gb": 50000, "free_gb": 10000, "type": "NFS", "remote": "nas:/b"}
    vc._lunv = {"naa.1": "PURE FlashArray"}
    return c


# ---------------------------------------------------------------- vSAN ESA
def test_esa_sources_and_licensing():
    src = ESA.sources(NS(connectors=_conns()), [{"kind": "datastore", "vcenter": "vc1", "name": "ds1", "growth_gb_day": 10}])
    ds = {d["name"]: d for d in src["datastores"]}
    assert set(ds) == {"ds1", "nfs-bk"} and ds["ds1"]["array"] == "PURE FlashArray" and ds["ds1"]["used_gb"] == 10000 and ds["ds1"]["vms"] == 9
    assert ds["nfs-bk"]["vms"] == 0 and src["clusters"][0]["lic_cores"] == 4 * 32 and src["clusters"][0]["nic_min"] == 25
    assert ESA.lic_cores(12, 2) == 32 and ESA.lic_cores(48, 1) == 48            # CPU 당 최소 16코어
    assert ESA.profile_for(15)["profile"] == "vSAN-ESA-AF-2" and ESA.profile_for(65)["profile"] == "vSAN-ESA-AF-8" and ESA.profile_for(120)["profile"] == "vSAN-ESA-AF-HighDensity"
    assert ESA.profile_for(45, cores=32, mem_gb=512, nic=25)["gaps"] == ["코어 32 < 48", "메모리 512 GB < 768 GB", "NIC 25 GbE < 50 GbE"]
    r = ESA.size(src, {})
    assert r["selected"] == ["vc1/ds1"]                                            # 기본: VM 이 있는 데이터스토어만
    assert r["inputs"]["growth_source"] == "추세" and abs(r["inputs"]["growth_pct_year"] - 36.5) < 0.1   # 10 GB/일 ÷ 10 TB × 365
    assert r["now_tb"] == 10.0 and abs(r["need_tb"] - 10 * 1.365 ** 3) < 0.2
    # 방법 A: 원시 = 필요 × 배수 ÷ (1 − 예비 − 1/N) — 4대 RAID-5 2+1(1.5) · 10% · 1대
    a = r["existing"][0]
    need = 10000 * 1.365 ** 3
    assert a["scheme"] == "RAID-5 2+1" and abs(a["raw_tb"] - need * 1.5 / (1 - 0.1 - 0.25) / 1000) < 0.2
    assert a["drives_per_host"] == -(-a["per_host_tb"] // 7.68) and a["entitled_tib"] == 128
    # 방법 B: 새 클러스터 — 쓸 수 있는 용량 ≥ 필요 를 만족하는 최소 대수
    b = r["new_cluster"]
    row = next(x for x in b["table"] if x["hosts"] == b["hosts"])
    assert row["ok"] and row["usable_tb"] * 1000 >= need and all(not x["ok"] for x in b["table"] if x["hosts"] < b["hosts"])
    r2 = ESA.size(src, {"datastores": ["vc1/ds1", "vc1/nfs-bk"], "basis": "prov", "growth_pct_year": 0, "years": 1, "policy": "r6", "dr": 1.5})
    assert r2["now_tb"] == 54.0 and r2["need_tb"] == 54.0 and r2["inputs"]["growth_source"] == "입력"
    assert r2["existing"][0]["possible"] is False and "최소 6대" in r2["existing"][0]["why"]     # RAID-6 는 6대 이상
    # OSA 클러스터는 ESA 로 바로 못 바꿈
    c = _conns()
    c[0].topology["clusters"]["c1"].update(vsan=True, vsan_esa=False)
    r3 = ESA.size(ESA.sources(NS(connectors=c)), {})
    assert r3["existing"][0]["osa"] and not r3["existing"][0]["possible"]
    assert ESA.size({"datastores": [], "clusters": []}, {})["error"]


# ---------------------------------------------------------------- 취약점 검증
CFG = """hostname leaf-x
feature telnet
snmp-server community public group network-operator
enable password cisco
interface Ethernet1
"""


def _world_seg():
    c = _conns()
    vc = c[0]
    vc.topology["networks"] = {"pg-mgmt": {"vlan": 100, "key": "dvpg-1"}, "pg-app": {"vlan": 120}}
    for v in vc.topology["vms"].values():
        v["networks"] = ["pg-app"]
    vc.topology["vms"]["db-local"]["networks"] = ["pg-mgmt"]
    for h in vc.health_snap["hosts"].values():
        h["vmks"] = [{"device": "vmk0", "services": ["management"], "pg_key": "dvpg-1", "vlan": None}]
        h["services"] = {"TSM-SSH": False, "TSM": False}
        h["lockdown"] = "lockdownNormal"
    vc.health_snap["hosts"]["h1"]["services"] = {"TSM-SSH": True, "TSM": True}
    vc.health_snap["hosts"]["h2"]["lockdown"] = "lockdownDisabled"
    return CB.build_world(NS(connectors=c, certs=NS(last={}))), c


def test_findings_and_paths():
    w, _ = _world_seg()
    assert {f["id"] for f in VS.switch_config_findings("leaf-x", CFG)} == {"sw-telnet:leaf-x", "sw-snmp-default:leaf-x", "sw-enable:leaf-x", "sw-nolog:leaf-x"}
    assert VS.switch_config_findings("ok", "snmp-server user ops network-admin auth sha x\nlogging host 10.0.0.1\n") == []
    seg = VS.segmentation(w)
    assert len(seg) == 1 and seg[0]["sev"] == "critical" and seg[0]["vlan"] == 100 and seg[0]["vms"] == ["db-local"]
    assessed = {"cve": [{"target": "h0", "product": "esxi", "id": "CVE-2024-1", "vmsa": "VMSA-2024-0001", "title": "heap overflow", "severity": "CRITICAL", "cvss": 9.8,
                         "cves": ["CVE-2024-1"], "verdict": "취약", "version": "8.0.2", "build": "1", "why": "fixed 2"}],
                "rows": [{"id": "ESXI-05", "title": "SSH 비활성", "severity": "상", "target": "h1", "status": "FAIL", "current": "on", "expected": "off", "fix": "SSH 끄기", "vcenter": "vc1"}]}
    kev = {"CVE-2024-1": {"cve": "CVE-2024-1", "vendor": "VMware", "product": "ESXi"}}
    F = VS.evaluate(w, assessed, [{"band": "expired", "system": "vc1", "name": "vc1", "kind": "vCenter 머신 SSL", "days_left": -3}],
                    [{"product": "vSphere", "version": "7.0", "where": "h3", "eogs": "2025-10-02", "eogs_passed": True}], {"vc1": {"configured": False}},
                    {"leaf-x": CFG}, [{"kind": "unused-open", "device": "leaf-x", "text": "미사용 포트 3개"}], kev, {"fortios": 4})
    ids = {f["id"].split(":")[0] for f in F}
    assert {"cve", "hard", "esx-shell", "esx-lock", "seg-management", "sw-telnet", "port-open", "cert", "eol", "bkp", "kev-prod"} <= ids
    assert "esx-ssh" not in ids                                                    # 하드닝 SSH 실패와 겹치면 하나만
    cve = next(f for f in F if f["id"].startswith("cve:"))
    assert cve["sev"] == "critical" and cve["kev"] == ["CVE-2024-1"] and cve["vcenter"] == "vc1"
    assert [SEV for SEV in [VS.SEV[f["sev"]] for f in F]] == sorted([VS.SEV[f["sev"]] for f in F], reverse=True)
    P = VS.attack_paths(w, F)
    top = P[0]
    assert top["target"] == "h0" and top["reach"] == "확인됨" and top["kev"] and top["break"]["at"] == "망 분리"
    assert any(p["kind"] == "vCenter" for p in P)                                  # 약점이 없어도 관리망이 열려 있으면 로그인 경로
    assert 0 < VS.risk_score(F, P) <= 100 and VS.risk_score([], []) == 0
    # 망 분리가 없으면 경로는 '조건부'
    w2, c2 = _world_seg()
    for v in w2["vcenters"][0]["topo"]["vms"].values():
        v["networks"] = ["pg-app"]
    F2 = VS.evaluate(w2, assessed, [], [], {}, {}, [], {}, {})
    P2 = VS.attack_paths(w2, F2)
    assert P2 and all(p["reach"] == "조건부" for p in P2) and not any(p["kind"] == "vCenter" for p in P2)


def test_vulncheck_run_events_kev(tmp_path):
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    _, conns = _world_seg()
    got = []
    eng = NS(store=e.store, connectors=conns, certs=NS(last={}), ingest=lambda ev: got.append(ev), assess=None)

    async def main():
        vc = VS.VulnCheck(eng)
        d1 = await vc.run("t")
        assert d1["summary"]["by_sev"]["critical"] == 1 and d1["summary"]["paths_confirmed"] >= 1 and got == []     # 첫 실행은 알림 없음
        n = await vc.import_kev({"vulnerabilities": [{"cveID": "CVE-2023-27997", "vendorProject": "Fortinet", "product": "FortiOS"}, {"cveID": "bad"}]})
        assert n == 1
        conns[0].health_snap["hosts"]["h3"]["services"] = {"TSM-SSH": True}         # 새 약점
        d2 = await vc.run("t")
        assert d2["summary"]["new"] == 1 and len(got) == 2 and "h3" in got[0].message and got[1].attrs["path"] == "path:vc1:h3"   # 새 약점 + 새 공격 경로
        conns[0].health_snap["hosts"]["h3"]["services"] = {}
        d3 = await vc.run("t")
        assert d3["summary"]["fixed"] == 1 and d3["fixed"][0]["asset"] == "h3"
        await vc.set_active(True)
        vc2 = VS.VulnCheck(eng)
        await vc2.ensure()
        assert vc2.cfg["active"] is True and len(await vc2.history()) == 3
        try:
            await vc.import_kev({"x": 1})
            raise AssertionError
        except ValueError:
            pass
    _run(main())


def test_active_check_tcp_only(tmp_path):
    async def main():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        vc = VS.VulnCheck(NS(store=None), {"active": True})
        F = [{"id": "a", "layer": "ESXi", "asset": "127.0.0.1", "port": port, "sev": "high"}, {"id": "b", "layer": "ESXi", "asset": "127.0.0.1", "port": 1, "sev": "high"}]
        await vc._active_check(F, {})
        srv.close()
        return F
    F = _run(main())
    assert F[0]["verified"].startswith("열림") and F[1]["verified"].startswith("연결 안 됨") and F[1]["sev"] == "medium"


def test_api_and_ui(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_vuln import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    _, conns = _world_seg()

    class Cap:
        async def overview(self):
            return {"items": []}
    eng = NS(store=e.store, connectors=conns, certs=NS(last={}), assess=None, capacity=Cap())

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(eng, VS.VulnCheck(eng), lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        d = cl.get("/api/vuln").json()
        assert d["summary"]["findings"] >= 3 and d["paths"]
        assert all(f["sev"] == "critical" for f in cl.get("/api/vuln", params={"sev": "critical"}).json()["findings"])
        assert cl.post("/api/vuln/kev", content=b"{bad").status_code == 400
        assert cl.post("/api/vuln/kev", json={"vulnerabilities": [{"cveID": "CVE-2024-0009"}]}).json()["imported"] == 1
        assert cl.put("/api/vuln/settings", json={"active": True}).json()["active"] is True
        assert cl.get("/api/vuln.csv").content.decode("utf-8-sig").startswith("등급,")
        r = cl.post("/api/capacity/esa", json={}).json()
        assert r["selected"] == ["vc1/ds1"] and r["new_cluster"]["hosts"]
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    for k in ('r"^/api/vuln", "view"', 'r"^/api/vuln/run$", "operate"', 'r"^/api/vuln/settings$", "settings"', 'r"^/api/capacity/esa$", "view"'):
        assert k in auth
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-vuln"' in html and 'id="drawer-vuln"' in html and "/static/vuln.js" in html and "/static/esa.js" in html
    assert '["assess", "vuln", "sec"]' in (S / "navgroup.js").read_text(encoding="utf-8")
    assert '["esa", "vSAN ESA 전환"]' in (S / "capacity.js").read_text(encoding="utf-8")
    for f in ("vuln.js", "esa.js", "capacity.js", "tour.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
    _ = json
