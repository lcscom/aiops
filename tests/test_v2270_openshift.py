"""2.27.0 Red Hat OpenShift(자체 운영) 비용 비교 · 여러 해 누적 TCO"""
import asyncio
import subprocess
from pathlib import Path

import pytest

from tests.test_v2130_cloudcost import _setup

ROOT = Path(__file__).resolve().parents[1]


def test_openshift_cost_rules(tmp_path):
    async def main():
        e = _setup(tmp_path)                    # 호스트 3대(24c·64c·미확인), VKS 워크로드 1개, Avi 1개
        C = e.cloudcost
        r = await C.report()
        o = r["openshift"]
        assert o["edition"] == "opp" and "Platform Plus" in o["auto_why"]          # VKS 있음 → 자동 Platform Plus
        assert o["units"] == 3 and o["hosts_unknown_cores"] == 1 and not o["complete"] and o["monthly"] is None
        assert any("환율" in m for m in o["missing"])                               # 기본 통화 KRW, 환율 없음
        await C.save_settings({"os_currency": "USD", "os_price_opp": 10000, "hw_per_host": 30000, "amort_years": 5,
                               "facility_per_host_year": 2000, "ops_per_year": 60000, "subscription_per_core_year": 350,
                               "os_cp_nodes": 3, "os_ops_delta_pct": 20, "os_migration_once": 120000, "tco_years": 3}, "admin")
        r = await C.report()
        o = r["openshift"]
        assert o["complete"], o["missing"]
        exp = (3 * 10000 + 6 * 6000 + 6 * 2000 + 60000 * 1.2) / 12              # 구독(소켓 쌍 3) + 서버·상면(워커 3 + 컨트롤 플레인 3) + 운영 +20%
        assert o["monthly"] == round(exp, 2) and o["parts"]["storage"] == 0          # ODF Essentials 포함
        alloc = sum(v["os_monthly"] for v in r["vms"] if v["category"] == "workload")
        assert abs(alloc - o["monthly"]) < 0.1
        tco = {x["key"]: x for x in r["tco"]["rows"]}
        assert r["tco"]["years"] == 3 and tco["openshift"]["total"] == round(exp * 36 + 120000, 2)
        assert tco["vcf"]["by_year"][0] == round(r["vcf"]["monthly"] * 12, 2) and len(tco["aws"]["by_year"]) == 3
        # VM 전용 에디션인데 컨테이너가 있으면 빠진 항목으로 경고 · ODF 단가 없으면 미완성
        await C.save_settings({"os_mode": "ove", "os_price_ove": 3000}, "admin")
        o = (await C.report())["openshift"]
        assert not o["complete"] and any("컨테이너" in m for m in o["missing"]) and any("ODF" in m for m in o["missing"])
        await C.save_settings({"os_storage": "external", "os_storage_per_year": 24000}, "admin")
        o = (await C.report())["openshift"]
        assert o["parts"]["storage"] == 2000.0
        # 엔화 단가 → 원/100엔 · 원/달러 둘 다 필요
        await C.save_settings({"os_mode": "opp", "os_currency": "JPY", "os_price_opp": 7425000}, "admin")
        o = (await C.report())["openshift"]
        assert o["monthly"] is None and any("100엔" in m for m in o["missing"])
        await C.save_settings({"os_fx_krw_per_100jpy": 900, "fx_krw_per_usd": 1400}, "admin")
        o = (await C.report())["openshift"]
        assert o["parts"]["subscription"] == round(3 * 7425000 * 9 / 1400 / 12, 2)
        # 큰 서버: 128코어 초과 → 소켓 쌍 2개
        e.connectors[0].health_snap["hosts"]["esx03"] = {"cores": 192, "sockets": 2}
        o = (await C.report())["openshift"]
        assert o["units"] == 4
        with pytest.raises(ValueError):
            await C.save_settings({"os_mode": "rhv"}, "admin")
        with pytest.raises(ValueError):
            await C.save_settings({"os_price_ocp": "nan"}, "admin")
        await C.save_settings({"os_mode": "none"}, "admin")
        r = await C.report()
        assert r["openshift"]["mode"] == "none" and all(x["key"] != "openshift" or x["total"] is None for x in r["tco"]["rows"])
        assert "openshift_monthly_usd" in (await C.csv())
    asyncio.run(main())


def test_reference_and_ui():
    from app.cloudcost import CloudCost
    ref = CloudCost.os_reference()
    assert ref["currency"] == "JPY" and set(ref["editions"]) == {"ove", "oke", "ocp", "opp"}
    assert ref["editions"]["ove"]["premium"]["sku"] == "MW05767" and ref["src"].startswith("https://")
    js = (ROOT / "app/static/cloudcost.js").read_text(encoding="utf-8")
    assert "osCard()" in js and "tcoCard()" in js and "/api/cloudcost/openshift/reference" in js
    assert subprocess.run(["node", "--check", str(ROOT / "app/static/cloudcost.js")]).returncode == 0
