"""성능 SLI(Isvara 4대 경합 지표) 계산 · vCenter 밴드 이벤트 · Isvara MCP 클라이언트."""
import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import sli  # noqa: E402
from app.isvara import IsvaraClient, IsvaraError  # noqa: E402


# ---------------------------------------------------------------- 점수
def test_score_matches_isvara_bands_and_example():
    # isvara.io/tools/ops-score: 디스크 14 ms → 65점(노랑), 밴드 경계 = 기준의 1·2·3·4배
    assert sli.score("disk_latency", 14) == 65.0 and sli.band(65) == "yellow"
    assert [sli.score("disk_latency", v) for v in (0, 10, 20, 30, 40, 55)] == [100, 75, 50, 25, 0, 0]
    assert sli.score("cpu_ready", 2.5) == 75 and sli.band(75) == "green" and sli.band(74.9) == "yellow"
    assert sli.score("mem_latency", 1.5) == 62.5
    assert sli.score("cpu_ready", None) is None and sli.band(None) == "none"


def test_dropped_packets_rule():
    assert sli.score("net_dropped", 0) == 100
    assert sli.score("net_dropped", 1, drop_budget=100) == 74.8
    assert sli.score("net_dropped", 100, drop_budget=100) == 50
    assert sli.score("net_dropped", 1000, drop_budget=100) == 0


def test_percentile_nearest_rank():
    xs = list(range(1, 101))
    assert sli.percentile(xs, 99) == 99 and sli.percentile(xs, 100) == 100
    assert sli.percentile([3, -1, 7], 99) == 7          # -1(수집 없음) 제외
    assert sli.percentile([], 99) is None


def test_vm_worst_signal_and_cluster_weighting():
    good = [sli.vm_result(f"g{i}", {"cpu_ready": 0.5, "disk_latency": 2}) for i in range(8)]
    bad = sli.vm_result("db01", {"cpu_ready": 12.0, "disk_latency": 3})       # CPU ready 12% → 0점
    assert bad["worst"] == "cpu_ready" and bad["score"] == 0 and bad["band"] == "red"
    k = sli.cluster_kpi(good + [bad])
    plain_mean = sum(v["score"] for v in good + [bad]) / 9
    # 빨강 1대(가중 8)가 초록 8대(가중 각 1)와 같은 무게 → 단순 평균보다 훨씬 낮음
    assert k["score"] == pytest.approx((sum(v["score"] for v in good) + 0 * 8) / 16, abs=0.1)
    assert k["score"] < plain_mean - 30 and k["bands"]["red"] == 1 and k["vms"] == 9
    assert k["signals"]["cpu_ready"]["worst_vm"] == "db01" and k["signals"]["cpu_ready"]["breach"] == 1


def test_failover():
    hosts = [{"name": f"h{i}", "cpu_mhz": 100000, "mem_mb": 512000, "cpu_used_mhz": 60000, "mem_used_mb": 300000}
             for i in range(4)]
    r = sli.failover(hosts, 1)
    assert r["verdict"] == "ok" and r["mem"]["used_pct_after"] == pytest.approx(78.1, abs=0.1)
    r2 = sli.failover(hosts, 2)                       # 2대 빠지면 메모리 117% → 위험
    assert r2["verdict"] == "at_risk" and r2["mem"]["headroom_pct"] < 0
    assert sli.failover(hosts[:1], 1)["verdict"] == "insufficient_hosts"
    hosts[0]["maintenance"] = True                     # 유지보수 호스트는 용량 제외
    assert sli.failover(hosts, 1)["hosts"] == 3


# ---------------------------------------------------------------- vCenter 밴드 이벤트
def test_vcenter_band_events():
    from app.connectors.vcenter import VCenterConnector

    async def emit(_):
        pass
    c = VCenterConnector({"name": "vc", "host": "vc.lab"}, emit)
    vm = lambda v: sli.vm_result("db01", {"cpu_ready": v}, host="esx01", cluster="C1")  # noqa: E731
    res = lambda v: {"vms": {"db01": vm(v)}, "clusters": {}}                            # noqa: E731
    assert c._sli_events(res(0.5), True) == []                       # 첫 계산·정상 → 없음
    e = c._sli_events(res(9.0), False)                               # 9% → 10점 → 빨강
    assert len(e) == 1 and e[0].severity == "error" and e[0].message.startswith("성능 SLI 위반(red): VM db01")
    assert "기준 2.5%" in e[0].message and e[0].entity == "sli:vm:db01"
    assert c._sli_events(res(9.5), False) == []                      # 같은 밴드 유지 → 없음
    assert c._sli_events(res(5.5), False) == []                      # 빨강→주황(둘 다 위반) → 없음
    r = c._sli_events(res(1.0), False)
    assert len(r) == 1 and r[0].severity == "info" and "회복" in r[0].message


def test_sli_rule_fires():
    from app.detect import Detector
    from app.models import LogEvent
    d = Detector({})
    ev = LogEvent(source="vcenter", connector="vc", message="성능 SLI 위반(orange): VM a — 디스크 latency 25ms (기준 10ms)",
                  severity="warning", kind="health")
    score, cat, sev = d.evaluate(ev)
    assert "규칙:sli_breach" in ev.reasons and cat == "performance"


# ---------------------------------------------------------------- Isvara MCP 클라이언트
def _client(handler, **cfg) -> IsvaraClient:
    c = IsvaraClient({"enabled": True, "url": "https://isvara.test/api/mcp", **cfg})
    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


def _mcp_handler(sse: bool, calls: list):
    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        calls.append((body.get("method"), req.headers.get("mcp-session-id"), req.headers.get("accept")))
        if body["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {
                "protocolVersion": "2025-06-18", "serverInfo": {"name": "isvara", "version": "1"}, "capabilities": {}}},
                headers={"Mcp-Session-Id": "s-1"})
        if body["method"] == "notifications/initialized":
            return httpx.Response(202)
        assert req.headers.get("mcp-session-id") == "s-1"
        if body["method"] == "tools/call":
            assert body["params"] == {"name": "ask_isvara", "arguments": {"question": "Why is CPU ready high?"}}
            result = {"content": [{"type": "text", "text": "Ready is time a vCPU waits for a physical thread. "
                                   "See https://isvara.io/read/part-3/cpu#contention-metrics."}]}
        else:
            result = {"contents": [{"uri": "isvara://thresholds", "text": "CPU ready 2.5%"}]}
        msg = {"jsonrpc": "2.0", "id": body["id"], "result": result}
        if sse:
            return httpx.Response(200, headers={"Content-Type": "text/event-stream"},
                                  content=(f"event: message\ndata: {json.dumps(msg)}\n\n").encode())
        return httpx.Response(200, json=msg)
    return handler


@pytest.mark.parametrize("sse", [False, True])
def test_isvara_ask_json_and_sse(sse):
    calls: list = []
    c = _client(_mcp_handler(sse, calls))
    r = asyncio.run(c.ask("Why  is CPU ready high?"))
    assert "physical thread" in r["answer"] and r["cached"] is False
    assert r["links"][0]["url"] == "https://isvara.io/read/part-3/cpu#contention-metrics"
    assert [m for m, _, _ in calls] == ["initialize", "notifications/initialized", "tools/call"]
    assert all("text/event-stream" in a for _, _, a in calls)
    assert asyncio.run(c.ask("Why is CPU ready high?"))["cached"] is True      # 캐시(공백 정규화)
    assert len(calls) == 3
    assert asyncio.run(c.read("isvara://thresholds")) == "CPU ready 2.5%"


def test_isvara_disabled_and_errors():
    c = IsvaraClient({"enabled": False})
    with pytest.raises(IsvaraError):
        asyncio.run(c.ask("cpu ready"))

    def boom(req):
        return httpx.Response(503, text="down")
    c2 = _client(boom)
    with pytest.raises(IsvaraError, match="HTTP 503"):
        asyncio.run(c2.ask("cpu ready"))
    assert "503" in c2.status()["last_error"]


def test_isvara_relevance():
    assert IsvaraClient.relevant("VM CPU ready 가 높아요") and IsvaraClient.relevant("vSAN 지연 원인")
    assert not IsvaraClient.relevant("NSX 방화벽 규칙 추가 방법")
