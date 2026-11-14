"""1.5: LLM 공급자(OpenAI 호환·Claude·Gemini)·가명화·대체 전환 / 패턴 재사용 / 호출 조절기 / AI 토글 / VM 이동·HA"""
import asyncio
import json
import time

import httpx

from app.aigov import Governor, parse_prom
from app.aipatterns import PatternStore, normalize
from app.llm import LLMClient, Masker
from app.models import LogEvent


def _client(cfg, handlers):
    c = LLMClient(cfg)
    for name, h in handlers.items():
        p = c.providers[name]
        p.http = httpx.AsyncClient(transport=httpx.MockTransport(h), headers=p.headers())
    return c


CAND = [{"id": "A1", "event": {"source": "esxi", "connector": "syslog", "kind": "log", "severity": "error", "ts": time.time(),
                               "message": "esx01.rangers.lab lost path to 10.0.0.5", "host": "esx01.rangers.lab", "entity": "vmkernel"},
         "context": [], "refs": [], "reasons": []}]


def test_anthropic_gemini_openai_and_masking():
    seen = {}

    def anth(req: httpx.Request):
        b = json.loads(req.content)
        seen["anth"] = (req.headers.get("x-api-key"), req.headers.get("anthropic-version"), b["system"][:10], b["messages"][0]["content"])
        user = b["messages"][0]["content"]
        assert "esx01" not in user and "10.0.0.5" not in user            # 외부로는 가명만
        tok = next(t for t in ("HOST_1", "NAME_1") if t in user)
        res = {"results": [{"id": "A1", "is_anomaly": True, "severity": "error", "title": f"{tok} 경로 장애", "summary": f"{tok} 에서 IP_1 경로 끊김"}]}
        return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}], "usage": {"input_tokens": 10, "output_tokens": 5}})

    def gem(req: httpx.Request):
        b = json.loads(req.content)
        seen["gem"] = (req.headers.get("x-goog-api-key"), str(req.url), b["generationConfig"].get("responseMimeType"))
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": '{"results":[{"id":"A1","title":"g"}]}'}]}}], "usageMetadata": {"totalTokenCount": 7}})

    def oai(req: httpx.Request):
        b = json.loads(req.content)
        seen["oai"] = (b["model"], b.get("response_format"))
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"results":[{"id":"A1","title":"local"}]}'}}], "usage": {"total_tokens": 3}})

    cfg = {"enabled": True, "base_url": "http://pais/v1", "model": "gemma", "providers": [
        {"name": "claude", "type": "anthropic", "api_key": "sk-ant", "model": "claude-haiku-5-5"},
        {"name": "gemini", "type": "gemini", "api_key": "g-key", "model": "gemini-3.5-flash-lite"}],
        "routing": {"analyze": "claude", "brief": "gemini"}}
    c = _client(cfg, {"claude": anth, "gemini": gem, "local": oai})

    async def main():
        r = await c.analyze(CAND)
        b = await c.complete("요약", "esx01.rangers.lab 상태", task="brief")
        o = await c.analyze(CAND, only="local")
        return r, b, o
    r, b, o = asyncio.run(main())
    a = r["A1"]
    assert a["_provider"] == "claude" and "esx01" in a["title"] and "10.0.0.5" in a["summary"]      # 응답은 원래 이름으로 복원
    assert seen["anth"][0] == "sk-ant" and seen["anth"][1] == "2023-06-01"
    assert seen["gem"][0] == "g-key" and seen["gem"][1].endswith("/models/gemini-3.5-flash-lite:generateContent")
    assert o["A1"]["title"] == "local" and seen["oai"] == ("gemma", {"type": "json_object"})
    assert c.providers["claude"].status["tokens"] == 15 and c.status["routing"]["analyze"] == "claude"


def test_fallback_to_next_provider():
    def bad(req):
        return httpx.Response(529, json={"error": "overloaded"})

    def ok(req):
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"results":[{"id":"A1","title":"ok"}]}'}}]})
    c = _client({"base_url": "http://pais/v1", "model": "m", "providers": [{"name": "claude", "type": "anthropic", "api_key": "k"}],
                 "routing": {"analyze": "claude"}}, {"claude": bad, "local": ok})
    r = asyncio.run(c.analyze(CAND))
    assert r["A1"]["_provider"] == "local" and c.providers["claude"].status["failures"] == 1


def test_masker_roundtrip():
    m = Masker(["web-01"])
    t = m.mask("web-01 on esx02.corp.local 192.168.1.10 and again web-01 192.168.1.10")
    assert "web-01" not in t and "192.168" not in t and t.count("IP_1") == 2
    assert m.unmask({"a": [t]}) == {"a": ["web-01 on esx02.corp.local 192.168.1.10 and again web-01 192.168.1.10"]}


def test_pattern_normalize_and_reuse(tmp_path):
    a = normalize("Lost access to volume 5f1a-11 (ds1) on esx01.rangers.lab path vmhba64:C0:T1:L3", ["esx01.rangers.lab"])
    b = normalize("Lost access to volume 5f1a-27 (ds2) on esx07.rangers.lab path vmhba65:C0:T2:L9", ["esx07.rangers.lab"])
    assert a == b

    class S:
        def schema(self, s): pass
    ps = PatternStore(S(), {"pattern_ttl_hours": 1})
    r1 = ps.observe("esxi", "path down on esx01", "m", "esx01", "vmkernel", "error")
    assert ps.cached(r1, "error") is None
    ps.save_analysis(r1["key"], {"title": "경로 다운", "severity": "error", "_provider": "local"}, "error")
    r2 = ps.observe("esxi", "path down on esx02", "m", "esx02", "vmkernel", "warning")
    assert r2 is r1 and ps.cached(r2, "warning")["title"] == "경로 다운"
    assert ps.cached(r2, "critical") is None                          # 더 심각하면 다시 분석
    r1["analyzed_at"] -= 7200
    assert ps.cached(r1, "error") is None                             # 기간 만료
    ps.exclude(r1["key"], True)
    assert ps.list(state="excluded")[0]["key"] == r1["key"]


def test_governor_cooldown_hourly_and_thermal():
    class P:
        name, external = "local", False
    g = Governor({"min_interval": 2, "max_calls_per_hour": 2, "temp_pause": 80, "temp_resume": 70})
    p = P()
    assert g.blocked(p)[0] == ""
    asyncio.run(g.acquire(p))
    assert g.blocked(p)[0] == "쿨다운" and g.blocked(p, interactive=True)[0] == ""
    g.last_call["local"] -= 5
    asyncio.run(g.acquire(p))
    g.last_call["local"] -= 5
    assert "시간당 상한" in g.blocked(p)[0]
    m = parse_prom('# HELP x\nDCGM_FI_DEV_GPU_TEMP{gpu="0"} 83\nDCGM_FI_DEV_GPU_TEMP{gpu="1"} 61\nDCGM_FI_DEV_GPU_UTIL{gpu="0"} 97\n', {"DCGM_FI_DEV_GPU_TEMP", "DCGM_FI_DEV_GPU_UTIL"})
    assert m["DCGM_FI_DEV_GPU_TEMP"] == [83.0, 61.0]
    g.hot = True
    assert "과열" in g.blocked(p, interactive=True)[0]
    p.external = True
    g.calls.clear()
    assert g.blocked(p)[0] == ""                                      # 외부 API 는 GPU 조건 무관


def test_ai_toggle_and_pattern_reuse_in_engine(tmp_path):
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False, "batch_interval": 0.05, "governor": {"min_interval": 0}},
                            "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        calls = []

        class Fake:
            status = {}
            providers = {}

            def primary(self, t):
                return None

            async def analyze(self, items, **kw):
                calls.append(len(items))
                return {i["id"]: {"title": "AI", "severity": "error", "summary": "s"} for i in items}
        e.llm = Fake()
        w = asyncio.create_task(e.pipeline_worker())
        lw = asyncio.create_task(e.llm_worker())
        for h in ("esx01", "esx02"):
            e.submit(LogEvent(source="esxi", connector="syslog", host=h, entity=h, severity="error",
                              message=f"Lost access to volume 64f2a1b3-55aa12cd-77ee-0050569a1b2c (datastore1) due to connectivity issues on {h}"))
        await asyncio.sleep(0.6)
        e.submit(LogEvent(source="esxi", connector="syslog", host="esx03", entity="esx03", severity="error",
                          message="Lost access to volume 64f2a1b3-55aa12cd-77ee-0050569a1b2c (datastore1) due to connectivity issues on esx03"))      # 같은 패턴 → 재사용
        await asyncio.sleep(0.3)
        r = await e.set_ai(False)
        e.submit(LogEvent(source="nsx", connector="syslog", host="edge1", entity="edge1", severity="critical", message="BGP neighbor 10.1.1.1 down"))
        await asyncio.sleep(0.3)
        w.cancel(); lw.cancel()
        return e, calls, r
    e, calls, r = asyncio.run(main())
    esx = sorted((a for a in e.anomalies.values() if a.event["source"] == "esxi"), key=lambda a: a.created)
    assert len(esx) == 3 and all(a.status == "analyzed" for a in esx)
    assert sum(calls) <= 2 and esx[-1].ai.get("cached")
    nsx = [a for a in e.anomalies.values() if a.event["source"] == "nsx"][0]
    assert nsx.status == "rule_only" and nsx.ai.get("off") and r["on"] is False


def test_move_extraction_from_vcenter_events():
    from pyVmomi import vim
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "vc1", "host": "vc", "username": "u", "password": "p"}, None)
    c.topology = {"vms": {"app01": {"host": "esx01", "cluster": "CL1"}}, "hosts": {"esx02": {"cluster": "CL1"}, "esx01": {"cluster": "CL1"}}}
    H = lambda n: vim.event.HostEventArgument(name=n, host=vim.HostSystem("host-1"))           # noqa: E731
    V = lambda n: vim.event.VmEventArgument(name=n, vm=vim.VirtualMachine("vm-1"))             # noqa: E731
    D = lambda n: vim.event.DatastoreEventArgument(name=n, datastore=vim.Datastore("ds-1"))    # noqa: E731
    e1 = vim.event.DrsVmMigratedEvent(vm=V("app01"), host=H("esx02"), sourceHost=H("esx01"), ds=D("ds1"), sourceDatastore=D("ds1"))
    m1 = c._move_of(e1)
    assert m1["type"] == "drs" and m1["from_host"] == "esx01" and m1["to_host"] == "esx02" and m1["cluster"] == "CL1"
    e2 = vim.event.VmMigratedEvent(vm=V("db01"), host=H("esx03"), sourceHost=H("esx03"), ds=D("ds2"), sourceDatastore=D("ds1"))
    assert c._move_of(e2)["type"] == "svmotion"
    e3 = vim.event.EventEx(eventTypeId="com.vmware.vc.ha.VmRestartedByHAEvent", vm=V("app01"), host=H("esx02"))
    m3 = c._move_of(e3)
    assert m3["type"] == "ha_restart" and m3["from_host"] == "esx01"                    # 출발 = 직전 인벤토리 위치
    e4 = vim.event.DasHostFailedEvent(failedHost=H("esx01"))
    assert c._move_of(e4)["type"] == "host_failed"
    assert c._move_of(vim.event.VmPoweredOnEvent(vm=V("x")))["type"] == "power_on"          # 2.5.0 전원도 VM 액티비티
    assert c._move_of(vim.event.VmMessageEvent(vm=V("x"))) is None


def test_move_tracker_dedupe_and_summary(tmp_path):
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        t = time.time()

        def ev(mv, nid, ts=t, msg="m"):
            return LogEvent(source="vcenter", connector="vc1", message=msg, ts=ts, native_id=nid, attrs={"move": {"vcenter": "vc1", **mv}})
        e.moves.record(ev({"type": "ha_restart", "vm": "a", "from_host": "esx01", "to_host": "esx02", "cluster": "CL"}, "1"))
        e.moves.record(ev({"type": "ha_restart", "vm": "b", "from_host": "esx01", "to_host": "esx03", "cluster": "CL"}, "2"))
        e.moves.record(ev({"type": "ha_restart", "vm": "b", "from_host": "esx01", "to_host": "esx03", "cluster": "CL"}, "2"))   # 같은 이벤트 키
        e.moves.record(ev({"type": "vmotion", "vm": "c", "from_host": "esx05", "to_host": "esx05"}, "3"))
        e.moves.record(ev({"type": "detected", "vm": "c", "from_host": "esx05", "to_host": "esx06"}, ""))     # 이벤트 호스트 보완
        e.moves.record(ev({"type": "detected", "vm": "a", "from_host": "esx01", "to_host": "esx02"}, ""))     # 이벤트로 확인된 이동 → 생략
        await asyncio.sleep(0.2)
        s = await e.moves.summary(24)
        db = await e.store.q("SELECT COUNT(*) n FROM vm_moves")
        return s, db[0]["n"], await e.moves.query(24, vm="c")
    s, n, c = asyncio.run(main())
    assert s["total"] == 3 and s["by_type"] == {"ha_restart": 2, "vmotion": 1} and n == 3
    assert s["ha_incidents"][0]["host"] == "esx01" and s["ha_incidents"][0]["vm_count"] == 2
    assert c[0]["from_host"] == "esx05" and c[0]["to_host"] == "esx06"
