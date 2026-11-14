"""2.13.0 클라우드 비용 비교 — 짝짓기 규칙·VCF 원가(16코어 최소)·관리 VM 제외·VKS/Avi 매핑·미입력 단가 표시·IOPS 수집(모의 PerformanceManager)·API"""
import asyncio
import time
from types import SimpleNamespace as NS

import pytest

from app.cloudcost import CloudCost, _class_of
from tests.test_v2110_support import _engine


def _vc():
    vms = {
        "app01": {"power": "poweredOn", "vcpu": 4, "mem_mb": 16384, "os": "Ubuntu Linux (64-bit)", "prov_gb": 100, "disk_gb": 40, "cluster": "wld"},
        "db01": {"power": "poweredOn", "vcpu": 8, "mem_mb": 65536, "os": "Microsoft Windows Server 2022 (64-bit)", "prov_gb": 500, "disk_gb": 300, "cluster": "wld"},
        "batch01": {"power": "poweredOn", "vcpu": 16, "mem_mb": 16384, "os": "Red Hat Enterprise Linux 9", "prov_gb": 50, "cluster": "wld"},
        "huge01": {"power": "poweredOn", "vcpu": 4, "mem_mb": 2 * 1024 * 1024, "os": "Linux", "prov_gb": 10, "cluster": "wld"},
        "old01": {"power": "poweredOff", "vcpu": 2, "mem_mb": 4096, "os": "Linux", "prov_gb": 20, "cluster": "wld"},
        "vCLS-abc": {"power": "poweredOn", "vcpu": 1, "mem_mb": 128, "os": "Photon", "prov_gb": 2, "cluster": "wld"},
        "nsx-edge-01": {"power": "poweredOn", "vcpu": 8, "mem_mb": 32768, "os": "Linux", "prov_gb": 200, "cluster": "wld"},
        "tkc1-control-plane-x1": {"power": "poweredOn", "vcpu": 2, "mem_mb": 8192, "os": "Photon", "prov_gb": 20, "cluster": "wld"},
        "tkc1-np-1-w1": {"power": "poweredOn", "vcpu": 4, "mem_mb": 16384, "os": "Photon", "prov_gb": 20, "cluster": "wld"},
        "tpl": {"template": True, "power": "poweredOff", "vcpu": 2, "mem_mb": 4096},
    }
    hosts = {"esx01": {"cluster": "wld"}, "esx02": {"cluster": "wld"}, "esx03": {"cluster": "wld"}}
    snap = {"hosts": {"esx01": {"cores": 24, "sockets": 2}, "esx02": {"cores": 64, "sockets": 2}}}   # esx03 미확인 → 16
    return NS(type="vcenter", name="vc1", topology={"hosts": hosts, "vms": vms}, health_snap=snap)


def _setup(tmp_path):
    e = _engine(tmp_path)
    vks = NS(type="vks", name="tkc1", role="workload", cluster_label="tkc1",
             inv={"nodes": [{"name": "tkc1-control-plane-x1", "roles": ["control-plane"]}, {"name": "tkc1-np-1-w1", "roles": ["worker"]}]})
    avi = NS(type="avi", name="avi1", vs={"u1": {"name": "vs-web", "vips": ["10.0.0.5"], "state": "OPER_UP"}})
    e.connectors = [_vc(), vks, avi]
    return e


def test_class_and_match():
    assert _class_of(16, 16) == "compute" and _class_of(4, 16) == "general" and _class_of(8, 64) == "memory"
    cat = CloudCost.__new__(CloudCost).base_catalog()["providers"]
    m = CloudCost.match(cat["aws"], 4, 16, False, "ondemand")
    assert m["sku"] == "m7i.xlarge" and abs(m["hourly"] - 0.1239 * 2) < 1e-9
    m = CloudCost.match(cat["azure"], 8, 64, True, "ondemand")
    assert m["sku"] == "E8s_v5" and abs(m["hourly"] - 0.244 * 4) < 1e-9
    m = CloudCost.match(cat["aws"], 3, 5, False, "ondemand")          # 비율 1.7 → 연산, 4 vCPU·8 GB
    assert m["sku"] == "c7i.xlarge"
    m = CloudCost.match(cat["aws"], 4, 2048, False, "ondemand")
    assert m["over"] and m["sku"] == "r7i.48xlarge"
    m = CloudCost.match(cat["gcp"], 4, 16, False, "ondemand")
    assert m["sku"] == "n2-standard-4" and m["hourly"] is None and m["missing"] == "단가 미입력"   # 추정하지 않음
    m = CloudCost.match(cat["azure"], 2, 8, False, "1y")              # RI 총액 / 8760
    assert m["note"] == "RI 1y" and abs(m["hourly"] - 638 / 8760) < 1e-9
    m = CloudCost.match(cat["aws"], 2, 8, False, "1y")
    assert "미입력" in m["note"] and abs(m["hourly"] - 0.1239) < 1e-9


def test_report(tmp_path):
    async def main():
        e = _setup(tmp_path)
        C = e.cloudcost
        r = await C.report()
        names = {v["name"]: v for v in r["vms"]}
        assert "old01" not in names and "tpl" not in names
        assert names["vCLS-abc"]["category"] == "mgmt" and names["nsx-edge-01"]["category"] == "mgmt"
        assert names["tkc1-control-plane-x1"]["category"] == "vks_cp" and names["tkc1-np-1-w1"]["category"] == "workload"
        assert names["vCLS-abc"]["cloud"] == {}
        a = names["app01"]["cloud"]
        assert a["aws"]["sku"] == "m7i.xlarge" and a["azure"]["sku"] == "D4s_v5" and a["gcp"]["sku"] == "n2-standard-4"
        assert a["aws"]["storage"] == 8.0 and a["gcp"]["monthly"] is None
        assert names["db01"]["cloud"]["azure"]["sku"] == "E8s_v5" and names["huge01"]["cloud"]["aws"]["over"]
        t = r["totals"]
        assert t["azure"]["complete"] and not t["gcp"]["complete"] and any("단가 미입력" in x for x in t["gcp"]["missing"])
        assert t["aws"]["k8s"] == 73.0 and t["azure"]["lb"] == round((0.27 + 0.008) * 730, 2) and "로드밸런서" in t["aws"]["unverified"]
        assert r["vcf"]["monthly"] is None and "입력" in r["vcf"]["note"]
        assert r["vcf"]["licensed_cores"] == 32 + 64 + 16 and len(r["mapping"]) == 7
        # TCO 입력 → VM 배분 합 = 월 비용
        await C.save_settings({"subscription_per_core_year": 350, "hw_per_host": 30000, "amort_years": 5, "facility_per_host_year": 2000, "ops_per_year": 60000}, "admin")
        r = await C.report()
        v = r["vcf"]
        assert v["monthly"] == round((112 * 350 + 3 * (6000 + 2000) + 60000) / 12, 2)
        alloc = sum(x["vcf_monthly"] for x in r["vms"] if x["category"] == "workload")
        assert abs(alloc - v["monthly"]) < 0.1 and all(x["vcf_monthly"] is None for x in r["vms"] if x["category"] != "workload")
        # GCP 단가 입력 → 완성
        await C.save_prices({"gcp.compute.n2-standard.vcpu_hour": 0.04, "gcp.compute.n2-standard.gb_hour": 0.005,
                             "gcp.compute.n2-highmem.vcpu_hour": 0.04, "gcp.compute.n2-highmem.gb_hour": 0.005,
                             "gcp.compute.n2-highcpu.vcpu_hour": 0.04, "gcp.compute.n2-highcpu.gb_hour": 0.005, "gcp.lb.hour": 0.025}, "admin")
        r = await C.report()
        app = next(x for x in r["vms"] if x["name"] == "app01")["cloud"]["gcp"]
        assert app["compute"] == round((4 * 0.04 + 16 * 0.005) * 730, 2)
        db = next(x for x in r["vms"] if x["name"] == "db01")["cloud"]["gcp"]
        assert db["compute"] is None and "Windows" in db["missing"]
        p = await C.prices()
        assert p["providers"]["gcp"]["compute"][0]["verified"] and "gcp.lb.hour" in p["overrides"]
        with pytest.raises(ValueError):
            await C.save_prices({"aws.compute.zz.linux": 1}, "x")
        with pytest.raises(ValueError):
            await C.save_prices({"aws.storage.gb_month": -1}, "x")
        # 약정·KRW
        await C.save_settings({"commit": "3y", "currency": "KRW", "fx_krw_per_usd": 1400}, "admin")
        r = await C.report()
        assert r["convert_ok"] and r["totals"]["gcp"]["compute"] < r["totals"]["gcp"]["compute"] / 0.54 and r["commit"] == "3y"
        csv = await C.csv()
        assert csv.startswith("﻿vm,") and "app01" in csv and "m7i.xlarge" in csv
    asyncio.run(main())


class _Ser:
    def __init__(self, cid, vals):
        self.id = NS(counterId=cid, instance="")
        self.value = vals


def test_iops_collect_and_report(tmp_path):
    from app.connectors.vcenter import VCenterConnector
    pm_calls = {}

    class PM:
        perfCounter = [NS(key=1, groupInfo=NS(key="virtualDisk"), nameInfo=NS(key="numberReadAveraged"), rollupType="average"),
                       NS(key=2, groupInfo=NS(key="virtualDisk"), nameInfo=NS(key="numberWriteAveraged"), rollupType="average"),
                       NS(key=3, groupInfo=NS(key="datastore"), nameInfo=NS(key="numberReadAveraged"), rollupType="average"),
                       NS(key=4, groupInfo=NS(key="datastore"), nameInfo=NS(key="numberWriteAveraged"), rollupType="average")]

        def QueryPerfProviderSummary(self, entity):
            return NS(currentSupported=True, refreshRate=20)

        def QueryPerf(self, querySpec):
            pm_calls["n"] = pm_calls.get("n", 0) + 1
            out = []
            for qs in querySpec:
                mid = qs.entity._moId
                if mid == "vm-1":   # 디스크 2개 읽기+쓰기 합
                    out.append(NS(entity=qs.entity, value=[_Ser(1, [100, 200, 50]), _Ser(1, [10, 20, 5]), _Ser(2, [30, 3000, 0])]))
                elif mid == "vm-2":  # 가상 디스크 카운터 없음 → 데이터스토어
                    out.append(NS(entity=qs.entity, value=[_Ser(3, [5, 7]), _Ser(4, [1, -1])]))
            return out

    import threading
    ents = {"app01": NS(_moId="vm-1"), "db01": NS(_moId="vm-2"), "x": NS(_moId="vm-3")}
    c = VCenterConnector.__new__(VCenterConnector)
    c.name, c.type, c._lock = "vc1", "vcenter", threading.RLock()
    c.topology = {"vms": {"app01": {"power": "poweredOn", "moid": "vm-1"}, "db01": {"power": "poweredOn", "moid": "vm-2"},
                          "x": {"power": "poweredOn", "moid": "vm-3"}, "off": {"power": "poweredOff", "moid": "vm-4"}}}
    c._iops_env = lambda names: (PM(), {n: ents.get(n) for n in names})
    c._iops_spec = lambda ent, mids, interval, n: NS(entity=ent, interval=interval)
    res = c.collect_vm_iops()
    assert res["app01"]["max"] == 3220 and res["app01"]["min"] == 55 and res["app01"]["n"] == 3 and res["app01"]["interval"] == 20
    assert res["db01"]["max"] == 7 and res["db01"]["min"] == 6 and "x" not in res and "off" not in res

    async def main():
        e = _setup(tmp_path)
        c.type = "vcenter"
        e.connectors = [c] + e.connectors[1:]
        C = e.cloudcost
        assert await C.collect_iops() == 2
        assert await C.collect_iops() == 2          # 같은 시간대 → 병합
        e.connectors = [_vc()] + e.connectors[1:]
        r = await C.report()
        io = next(x for x in r["vms"] if x["name"] == "app01")["iops"]
        assert io["max"] == 3220 and io["min"] == 55 and io["avg"] == round((140 + 3220 + 55) / 3, 1) and io["hours"] == 1
        az = next(x for x in r["vms"] if x["name"] == "app01")["cloud"]["azure"]
        assert az["iops_over"] and az["iops"] == round(220 * 0.00584, 2)
        assert next(x for x in r["vms"] if x["name"] == "app01")["cloud"]["aws"]["iops"] == 0.0
        await e.store.x("UPDATE cc_iops SET hour=hour-24*30")
        assert (await C.iops(7)) == {}
    asyncio.run(main())


def test_api(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api_cloudcost import build_router
    e = _setup(tmp_path)
    logs = []

    async def audit(req, action, target="", result="ok", detail=None):
        logs.append((action, detail))
    app = FastAPI()
    app.include_router(build_router(e, {}, lambda req: {"user": "admin", "role": "admin"}, audit))
    with TestClient(app) as cl:
        r = cl.get("/api/cloudcost/report?commit=1y")
        assert r.status_code == 200 and r.json()["commit"] == "1y"
        assert cl.get("/api/cloudcost/report?commit=9y").status_code == 400
        assert cl.put("/api/cloudcost/settings", json={"subscription_per_core_year": "abc"}).status_code == 400
        assert cl.put("/api/cloudcost/settings", json={"mgmt_patterns": ["(bad"]}).status_code == 400
        assert cl.put("/api/cloudcost/settings", json={"mgmt_patterns": ["^tkc1-np"]}).status_code == 200
        assert next(v for v in cl.get("/api/cloudcost/report").json()["vms"] if v["name"] == "tkc1-np-1-w1")["category"] == "mgmt"
        assert cl.put("/api/cloudcost/prices", json={"changes": {"aws.storage.gb_month": 0.0912}}).json()["providers"]["aws"]["storage"]["verified"]
        assert cl.delete("/api/cloudcost/prices").json()["overrides"] == {}
        assert cl.post("/api/cloudcost/prices/refresh", json={"provider": "aws"}).status_code == 400
        assert cl.post("/api/cloudcost/prices/refresh", json={"provider": "gcp", "api_key": "x"}).status_code == 400
        r = cl.get("/api/cloudcost/report.csv")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert ("cloudcost.prices", {"changes": {"aws.storage.gb_month": 0.0912}}) in logs


def test_refresh_azure_gcp(tmp_path):
    import httpx

    def az(req):
        f = req.url.params.get("$filter", "")
        items = []
        if "Standard_D2s_v5" in f:
            items = [{"type": "Consumption", "skuName": "D2s v5", "productName": "Virtual Machines DSv5 Series", "retailPrice": 0.119},
                     {"type": "Consumption", "skuName": "D2s v5 Spot", "productName": "Virtual Machines DSv5 Series", "retailPrice": 0.02},
                     {"type": "Consumption", "skuName": "D2s v5", "productName": "Virtual Machines DSv5 Series Windows", "retailPrice": 0.211},
                     {"type": "Reservation", "skuName": "D2s v5", "productName": "Virtual Machines DSv5 Series", "reservationTerm": "1 Year", "retailPrice": 640}]
        if "Kubernetes" in f:
            items = [{"type": "Consumption", "meterName": "Standard Uptime SLA", "retailPrice": 0.1}]
        return httpx.Response(200, json={"Items": items, "NextPageLink": None})

    def gcp(req):
        assert req.headers["x-goog-api-key"] == "A" * 39 and "key" not in req.url.params
        return httpx.Response(200, json={"skus": [
            {"description": "N2 Instance Core running in Seoul", "category": {"usageType": "OnDemand"},
             "pricingInfo": [{"pricingExpression": {"usageUnit": "h", "tieredRates": [{"unitPrice": {"units": "0", "nanos": 38800000}}]}}]},
            {"description": "N2 Instance Ram running in Seoul", "category": {"usageType": "OnDemand"},
             "pricingInfo": [{"pricingExpression": {"usageUnit": "GiBy.h", "tieredRates": [{"unitPrice": {"units": "0", "nanos": 5200000}}]}}]},
            {"description": "N2 Instance Core running in Tokyo", "category": {"usageType": "OnDemand"},
             "pricingInfo": [{"pricingExpression": {"usageUnit": "h", "tieredRates": [{"unitPrice": {"units": "1", "nanos": 0}}]}}]}]})

    async def main():
        e = _setup(tmp_path)
        C = e.cloudcost
        res = await C.refresh_azure("admin", transport=httpx.MockTransport(az))
        assert res["items"]["compute.Dsv5.linux"] == 0.119 and res["items"]["compute.Dsv5.windows"] == 0.211 and res["items"]["compute.Dsv5.ri_1y_total"] == 640
        p = await C.prices()
        assert p["providers"]["azure"]["compute"][0]["linux"] == 0.119 and "Retail" in p["overrides"]["azure.compute.Dsv5.linux"]["source"]
        res = await C.refresh_gcp("A" * 39, "admin", transport=httpx.MockTransport(gcp))
        assert res["items"]["vcpu_hour"] == pytest.approx(0.0388) and res["items"]["gb_hour"] == pytest.approx(0.0052)
        r = await C.report()
        assert next(x for x in r["vms"] if x["name"] == "app01")["cloud"]["gcp"]["compute"] == round((4 * 0.0388 + 16 * 0.0052) * 730, 2)
    asyncio.run(main())
