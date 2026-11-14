"""VKS — 파드 인벤토리·문제 파드 로그 첨부·로그 따라가기·CAPI 클러스터(자동 발견 입력)."""
import asyncio
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.connectors.kubernetes import VksConnector  # noqa: E402

NOW = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))


def pod(ns, name, crash=False):
    cs = {"name": "app", "ready": not crash, "restartCount": 5 if crash else 0,
          "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "back-off"}} if crash else {"running": {}}}
    return {"metadata": {"namespace": ns, "name": name, "creationTimestamp": NOW},
            "spec": {"nodeName": "w1", "containers": [{"name": "app"}]}, "status": {"phase": "Running", "containerStatuses": [cs]}}


def handler(req: httpx.Request):
    p = req.url.path
    if p == "/api/v1/pods":
        return httpx.Response(200, json={"items": [pod("shop", "web"), pod("shop", "api", crash=True)], "metadata": {}})
    if p.endswith("/log"):
        prev = req.url.params.get("previous") == "true"
        if req.url.params.get("timestamps") == "true":
            return httpx.Response(200, text="2099-01-01T00:00:01Z new line A\n2099-01-01T00:00:02Z new line B")
        return httpx.Response(200, text=("prev " if prev else "") + "panic: db unreachable\nexit 1")
    if p == "/apis/cluster.x-k8s.io/v1beta1/clusters":
        return httpx.Response(200, json={"items": [{"metadata": {"namespace": "team-a", "name": "tkc01", "creationTimestamp": NOW},
                                                    "spec": {"controlPlaneEndpoint": {"host": "10.0.0.9", "port": 6443}},
                                                    "status": {"phase": "Provisioned", "conditions": [{"type": "Ready", "status": "True"}]}}]})
    if p == "/apis/cluster.x-k8s.io/v1beta1/machines":
        return httpx.Response(200, json={"items": []})
    return httpx.Response(404)


def conn(**kw):
    async def emit(_):
        pass
    c = VksConnector({"name": "t", "host": "10.0.0.1", "auth": "token", "token": "x", **kw}, emit)
    c._http = httpx.AsyncClient(base_url=c.base_url, transport=httpx.MockTransport(handler))
    return c


def test_inventory_and_problem_logs():
    c = conn()
    evs = asyncio.run(c._pods())
    names = {(p["name"], p["reason"], p["ready"]) for p in c.inv["pods"]}
    assert ("api", "CrashLoopBackOff", "0/1") in names and ("web", "", "1/1") in names
    logs = [e for e in evs if e.kind == "k8s-log"]
    assert logs and logs[0].message.startswith("prev panic") and logs[0].attrs["previous"] is True
    assert logs[0].entity == "Pod/shop/api" and logs[0].severity in ("error", "critical")
    assert asyncio.run(c._pods()) == []          # 같은 상태 재확인 → 중복 이벤트·로그 없음


def test_follow_logs_since():
    c = conn(log_namespaces=["shop"])
    asyncio.run(c._pods())
    assert asyncio.run(c._follow_logs()) == []    # 첫 회는 위치만
    out = asyncio.run(c._follow_logs())
    assert [e.message for e in out if e.entity == "Pod/shop/web"] == ["new line A", "new line B"]
    assert asyncio.run(c._follow_logs()) == []    # 이미 받은 줄은 다시 안 보냄(타임스탬프 기준)


def test_capi_clusters_for_discovery():
    c = conn(role="supervisor")
    asyncio.run(c._capi())
    assert c.inv["clusters"] == [{"ns": "team-a", "name": "tkc01", "phase": "Provisioned", "ready": "True",
                                  "endpoint": "10.0.0.9:6443", "version": "", "age": c.inv["clusters"][0]["age"]}]
