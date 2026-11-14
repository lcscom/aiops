"""1.10.1: Avi VIP 메트릭 — 테넌트별 X-Avi-Tenant 조회, step 5→300 같은 주기 재시도, VS 개별 조회 대체, 실패 사유 표시"""
import asyncio
import json

import httpx

from app.connectors.vmware_rest import AviConnector


def _vs(c, uid, name, tenant):
    c._vs_meta({"config": {"uuid": uid, "name": name, "tenant_ref": f"https://c/api/tenant/{tenant}-uuid#{tenant}",
                           "vip": [{"ip_address": {"addr": "10.0.0.1"}}], "services": [{"port": 443}]}}, name, "OPER_UP")


def _ser(mids, val):
    return [{"header": {"name": m}, "data": [{"value": val}, {"value": val}]} for m in mids.split(",")]


def test_tenant_scoped_collection_and_step_fallback():
    calls = []

    def h(req: httpx.Request):
        t = req.headers.get("x-avi-tenant")
        if req.url.path == "/api/analytics/metrics/collection":
            q = json.loads(req.content)["metric_requests"][0]
            calls.append(("coll", t, q["step"]))
            if q["step"] == 5:
                return httpx.Response(200, json={"series": {"vip": {}}})                   # 실시간 메트릭 꺼짐
            mine = {"vs-a": "admin", "vs-b": "bank"}
            return httpx.Response(200, json={"series": {"vip": {u: _ser(q["metric_id"], 100.0) for u, tt in mine.items() if tt == t}}})
        calls.append(("vs", t, req.url.path))
        return httpx.Response(404, text="not found")
    c = AviConnector({"name": "avi", "host": "avi", "username": "u", "password": "p"}, None)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(h), base_url="https://x")
    _vs(c, "vs-a", "web", "admin")
    _vs(c, "vs-b", "core", "bank")
    asyncio.run(c.vip_metrics())
    v = {x["name"]: x for x in c.vips()}
    assert v["web"]["step"] == 300 and v["core"]["step"] == 300 and v["core"]["last"]["bw"] == 100.0 and v["core"]["tenant"] == "bank"
    assert ("coll", "bank", 300) in calls and ("coll", "admin", 300) in calls       # 테넌트별 헤더
    assert c._metrics_step == 300 and "ok 값 2·유휴 0·실패 0 / 2" in c._state["checks"]["VIP 메트릭"]
    calls.clear()
    asyncio.run(c.vip_metrics())
    assert all(x[2] == 300 for x in calls if x[0] == "coll")                        # 다음부터 바로 5분 평균


def test_per_vs_fallback_and_failure_note():
    def h(req: httpx.Request):
        if req.url.path.endswith("/collection"):
            return httpx.Response(403, json={"error": "Insufficient privileges"})
        if req.headers.get("x-avi-tenant") == "bank" and req.url.path.endswith("/vs-b"):
            return httpx.Response(200, json={"series": _ser(req.url.params["metric_id"], 7.0)})
        return httpx.Response(404, text="VirtualService object not found!")
    c = AviConnector({"name": "avi", "host": "avi", "username": "u", "password": "p"}, None)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(h), base_url="https://x")
    _vs(c, "vs-a", "web", "admin")
    _vs(c, "vs-b", "core", "bank")
    asyncio.run(c.vip_metrics())
    v = {x["name"]: x for x in c.vips()}
    assert v["core"]["last"]["rps"] == 7.0 and v["core"]["step"] == 5
    assert not v["web"].get("step") and "HTTP 403" in v["web"]["mnote"]
    assert c.metrics_diag["with_data"] == 1 and c.metrics_diag["http"]["403"] >= 1


def test_v211_rejected_metric_split_idle_and_pool_resolution():
    """2.1.1: 컨트롤러가 모르는 지표 하나로 전체 요청이 400 → L4/L7 묶음 분리·거부 지표 학습, 유휴 VS 구분, AKO L4 VS 풀 연결"""
    BAD = "l7_client.avg_ssl_errors"
    seen = []

    def h(req: httpx.Request):
        if req.url.path.endswith("/collection"):
            q = json.loads(req.content)["metric_requests"][0]
            seen.append(q["metric_id"])
            if BAD in q["metric_id"]:
                return httpx.Response(400, json={"error": f"Invalid metric_id {BAD}"})
            ser = {"vs-a": _ser(q["metric_id"], 50.0) if q["metric_id"].startswith("l4_") else [],
                   "vs-i": [{"header": {"name": m}, "data": []} for m in q["metric_id"].split(",")]}       # 유휴: 머리만 오고 값 없음
            return httpx.Response(200, json={"series": {"vip": ser}})
        mid = req.url.params.get("metric_id", "")
        if BAD in mid:
            return httpx.Response(400, json={"error": "Invalid metric_id"})
        return httpx.Response(200, json={"series": []})
    c = AviConnector({"name": "avi", "host": "avi", "username": "u", "password": "p"}, None)
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(h), base_url="https://x")
    c._metrics_step = 300
    _vs(c, "vs-a", "da7e23e3-a39--kube-system-docker-registry", "admin")
    _vs(c, "vs-i", "idle-vs", "admin")
    c._vs_meta({"config": {"uuid": "vs-g", "name": "grp", "tenant_ref": "https://c/api/tenant/admin#admin",
                           "pool_group_ref": "https://c/api/poolgroup/pg-1#pg-web"}}, "grp", "OPER_UP")
    c.pools = [{"name": "da7e23e3-a39--kube-system-docker-registry-TCP-5000", "up": 1, "servers": 1, "members": [{"ip": "10.244.1.5", "port": 5000}]},
               {"name": "p-by-ref", "vs_uuids": ["vs-i"], "up": 2, "servers": 2, "members": [{"ip": "10.0.1.1", "port": 80}]},
               {"name": "p-in-group", "poolgroups": ["pg-web"], "up": 0, "servers": 1, "members": [{"ip": "10.0.2.1", "port": 80}]}]
    asyncio.run(c.vip_metrics())
    v = {x["name"]: x for x in c.vips()}
    a = v["da7e23e3-a39--kube-system-docker-registry"]
    assert a["mstate"] == "ok" and a["last"]["bw"] == 50.0 and a["step"] == 300                 # L4 값은 L7 거부와 무관하게 수신
    assert v["idle-vs"]["mstate"] == "idle" and "트래픽 기록 없음" in v["idle-vs"]["mnote"]
    assert BAD in c._bad_metrics and len(c._bad_metrics) == 1                                       # 하나씩 물어 거부 지표만 학습
    assert "유휴 1" in c._state["checks"]["VIP 메트릭"] and "미지원 지표 제외 1개" in c._state["checks"]["VIP 메트릭"]
    seen.clear()
    asyncio.run(c.vip_metrics())
    assert seen and all(BAD not in m for m in seen)                                                  # 다음 주기부터 제외
    assert a["pool"] == "da7e23e3-a39--kube-system-docker-registry-TCP-5000" and a["members"][0]["ip"] == "10.244.1.5"   # AKO 이름 접두
    assert v["idle-vs"]["pool"] == "p-by-ref" and v["idle-vs"]["pool_up"] == 2                      # 풀 인벤토리 역참조
    assert v["grp"]["pool"] == "p-in-group" and v["grp"]["pool_group"] == "pg-web" and v["grp"]["members"][0]["pool"] == "p-in-group"
