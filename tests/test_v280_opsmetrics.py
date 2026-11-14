"""2.8.0 VCF Operations 메트릭 — 개체 목록(페이지) · 일괄 최신 값(POST query, 구버전 GET 대체) · 카탈로그 기반 기본 키 · 선택기 저장 · 추세 · 내보내기 · AI 문맥"""
import asyncio
import json
import time
from urllib.parse import parse_qs

import httpx

from app.connectors.vmware_rest import VcfOpsConnector

HOSTS = [{"identifier": f"h{i}", "resourceKey": {"name": f"esx{i:02d}.lab.local"}, "resourceHealth": "GREEN"} for i in range(1, 4)]


def _ops(calls, bulk=True):
    def h(req: httpx.Request):
        p, q = req.url.path, parse_qs(req.url.query.decode())
        calls.append((req.method, p, dict(q), req.content))
        if p.endswith("/auth/token/acquire"):
            return httpx.Response(200, json={"token": "T"})
        if p.endswith("/statkeys"):
            kind = p.split("/resourcekinds/")[1].split("/")[0]
            keys = {"HostSystem": ["cpu|capacity_usagepct_average", "mem|consumed_average", "badge|health", "summary|version"],
                    "Datastore": ["capacity|usedSpacePct", "badge|health"]}.get(kind, [])
            return httpx.Response(200, json={"resourceTypeAttributes": [{"key": k, "name": k.split("|")[1], "unit": "%" if "pct" in k.lower() else "KB",
                                                                         "property": k.startswith("summary")} for k in keys]})
        if p == "/suite-api/api/resources":
            kind = q["resourceKind"][0]
            assert q["adapterKind"] == ["VMWARE"]
            items = HOSTS if kind == "HostSystem" else ([{"identifier": "d1", "resourceKey": {"name": "vsanDatastore"}}] if kind == "Datastore" else [])
            return httpx.Response(200, json={"resourceList": items, "pageInfo": {"totalCount": len(items)}})
        if p.endswith("/stats/latest/query"):
            if not bulk:
                return httpx.Response(404)
            b = json.loads(req.content)
            return httpx.Response(200, json={"values": [{"resourceId": rid, "stat-list": {"stat": [
                {"statKey": {"key": k}, "timestamps": [int(time.time() * 1000)], "data": [10.0 * (i + 1)]} for k in b["statKey"] if k != "mem|consumed_average" or rid != "h3"]}}
                for i, rid in enumerate(b["resourceId"])]})
        if p.endswith("/stats/latest"):
            ids, keys = q["resourceId"], q["statKey"]
            return httpx.Response(200, json={"values": [{"resourceId": rid, "stat-list": {"stat": [{"statKey": {"key": k}, "timestamps": [1], "data": [5.0]} for k in keys]}} for rid in ids]})
        if p.endswith("/alerts"):
            return httpx.Response(200, json={"alerts": []})
        return httpx.Response(404)
    return httpx.MockTransport(h)


def _conn(calls, bulk=True, **cfg):
    c = VcfOpsConnector({"name": "ops1", "host": "ops.lab", "username": "u", "password": "p", "metric_kinds": ["HostSystem", "Datastore"], **cfg}, lambda e: None)
    c._http = httpx.AsyncClient(base_url="https://ops.lab", transport=_ops(calls, bulk))
    return c


def test_collect_bulk_and_catalog_defaults():
    calls = []
    c = _conn(calls)
    asyncio.run(c.login())
    ops = asyncio.run(c.collect_metrics())
    hk = ops["kinds"]["HostSystem"]
    assert hk["keys"] == ["cpu|capacity_usagepct_average", "mem|consumed_average", "badge|health"]          # 카탈로그에 있는 선호 키만
    assert len(hk["objects"]) == 3 and hk["values"]["h2"]["cpu|capacity_usagepct_average"][0] == 20.0 and hk["with_data"] == 3
    assert ops["kinds"]["Datastore"]["keys"] == ["capacity|usedSpacePct", "badge|health"] and ops["api"] == "POST stats/latest/query"
    body = json.loads(next(x[3] for x in calls if x[1].endswith("/latest/query")))
    assert body["maxSamples"] == 1 and set(body["resourceId"]) == {"h1", "h2", "h3"}
    assert not ops["error"]


def test_fallback_to_get_and_override_keys():
    calls = []
    c = _conn(calls, bulk=False)
    c.keys_override = {"HostSystem": ["cpu|capacity_usagepct_average"]}
    asyncio.run(c.login())
    ops = asyncio.run(c.collect_metrics())
    assert ops["api"] == "GET stats/latest" and ops["kinds"]["HostSystem"]["keys"] == ["cpu|capacity_usagepct_average"]
    assert ops["kinds"]["HostSystem"]["values"]["h1"]["cpu|capacity_usagepct_average"][0] == 5.0


def _engine(tmp_path):
    from app.config import DEFAULTS, _merge
    from app.engine import Engine
    return Engine(_merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}}))


def test_store_series_export_entity_and_picker(tmp_path):
    async def main():
        e = _engine(tmp_path)
        calls = []
        c = _conn(calls)
        e.connectors = [c]
        await c.login()
        await c.collect_metrics()
        n = await e.opsmetrics.persist()
        n2 = await e.opsmetrics.persist()                                       # 같은 gen → 다시 쓰지 않음
        objs = e.opsmetrics.objects("HostSystem", sort="cpu|capacity_usagepct_average")
        s = await e.opsmetrics.series("HostSystem", "esx03.lab.local", "cpu|capacity_usagepct_average")
        csv, ct = e.opsmetrics.export("HostSystem")
        js, _ = e.opsmetrics.export("HostSystem", "json")
        ent = e.opsmetrics.for_entity("esx02")                                  # 짧은 이름
        brief = e.opsmetrics.brief("esx02.lab.local")
        cat = await e.opsmetrics.catalog("ops1", "HostSystem", q="cpu")
        try:
            await e.opsmetrics.save_keys("ops1", "HostSystem", ["nope|x"], "admin")
            bad = None
        except ValueError as ex:
            bad = str(ex)
        r = await e.opsmetrics.save_keys("ops1", "HostSystem", ["badge|health"], "admin")
        e2 = _engine(tmp_path)                                                   # 재기동 후에도 선택 유지
        e2.connectors = [_conn([])]
        e2.opsmetrics.push_keys()
        return n, n2, objs, s, csv, ct, js, ent, brief, cat, bad, r, e2.connectors[0].metric_keys("HostSystem"), e.opsmetrics.summary()
    n, n2, objs, s, csv, ct, js, ent, brief, cat, bad, r, keys2, summ = asyncio.run(main())
    assert n == 3 * 3 - 1 + 2 and n2 == 0                                         # 호스트 3×3(1개 빠짐) + 데이터스토어 1×2
    assert [x["name"] for x in objs["items"]] == ["esx03.lab.local", "esx02.lab.local", "esx01.lab.local"] and objs["meta"]["badge|health"]["name"] == "health"
    assert s["stored"] and s["points"][0][1] == 30.0
    assert csv.startswith("﻿connector,kind,name,health,capacity_usagepct_average [cpu|capacity_usagepct_average] (%)") and "esx01.lab.local" in csv and ct.startswith("text/csv")
    assert json.loads(js)["metric_info"]["cpu|capacity_usagepct_average"]["unit"] == "%"
    assert ent and ent[0]["name"] == "esx02.lab.local" and ent[0]["health"] == "GREEN"
    assert "VCF Ops(HostSystem, 상태 GREEN)" in brief and "capacity_usagepct_average 20 %" in brief
    assert [x["key"] for x in cat["items"]] == ["cpu|capacity_usagepct_average"] and "summary|version" not in str(cat["items"])
    assert bad and "nope|x" in bad and r["keys"] == ["badge|health"] and keys2 == ["badge|health"]
    hs = summ["connectors"][0]["kinds"]["HostSystem"]
    assert hs["objects"] == 3 and hs["keys_no_data"] == []


def test_chat_brief_includes_ops(tmp_path):
    from types import SimpleNamespace as NS
    from app import chatctx
    om = NS(brief=lambda n: "VCF Ops(HostSystem): cpu 50 %" if n == "esx08.lab.local" else "")
    eng = NS(connectors=[NS(name="vc", topology={"hosts": {"esx08.lab.local": {"conn": "connected"}}, "vms": {}, "datastores": {}, "clusters": {}})],
             buffer=[], anomalies={}, moves=NS(alarms=lambda: []), bmc_inventory=lambda: {}, opsmetrics=om)
    ent = chatctx.find_entities(eng, "esx08 상태")[0]
    assert "VCF Ops(HostSystem): cpu 50 %" in chatctx.entity_brief(eng, ent)["text"]


def test_route_permission():
    from app.security.auth import AuthManager
    assert AuthManager.required_perm("POST", "/api/opsmetrics/collect") == "operate"
    assert AuthManager.required_perm("PUT", "/api/opsmetrics/keys") == "settings"
    assert AuthManager.required_perm("GET", "/api/opsmetrics/objects") == "view"
