"""2.7.0 PAIS Agent Builder 에이전트 공급자 — 주소 조합 · system 역할 거부 시 재시도 · 비스트리밍 응답 처리 · /models 없음"""
import asyncio
import json

import httpx

from app.llm import PROVIDERS, LLMClient, PaisAgentProvider, provider_defs

URL = "https://kr-pais.rangers.lab/api/v1/compatibility/openai/v1/agents/53108691-9d38-4902-b18a-f10029a0249f"


def _p(handler, **pc):
    p = PaisAgentProvider({"name": "agent", "type": "pais_agent", "api_key": "TOK", **pc}, {})
    p.http = httpx.AsyncClient(transport=httpx.MockTransport(handler), headers=p.headers())
    return p


def test_url_forms_and_defaults():
    a = PaisAgentProvider({"name": "a", "base_url": URL + "/"}, {})
    b = PaisAgentProvider({"name": "b", "base_url": "https://kr-pais.rangers.lab", "agent_id": "53108691-9d38-4902-b18a-f10029a0249f"}, {})
    c = PaisAgentProvider({"name": "c", "base_url": URL + "/chat/completions"}, {})
    assert a.base == b.base == c.base == URL
    assert not a.external and a.model == "agent" and a.tasks == {"chat", "brief", "report"} and "pais_agent" in PROVIDERS
    assert provider_defs({"providers": [{"name": "x", "type": "pais_agent", "base_url": URL}]})[0]["type"] == "pais_agent"


def test_chat_retries_without_system_role():
    seen = []

    def h(req):
        b = json.loads(req.content)
        seen.append(b)
        assert req.url.path.endswith("/agents/53108691-9d38-4902-b18a-f10029a0249f/chat/completions") and req.headers["Authorization"] == "Bearer TOK"
        if b["messages"][0]["role"] == "system":
            return httpx.Response(400, json={"detail": "role 'system' is not allowed for agents"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok-answer"}}], "usage": {"total_tokens": 7}})
    p = _p(h, base_url=URL)
    out = asyncio.run(p.chat("SYS CONTEXT", [{"role": "user", "content": "Q?"}], json_mode=True))
    assert out == "ok-answer" and p.system_mode == "user"
    assert "response_format" not in seen[0] and seen[1]["messages"] == [{"role": "user", "content": "SYS CONTEXT\n\n---\nQ?"}]
    asyncio.run(p.chat("S2", [{"role": "user", "content": "Q2"}]))
    assert seen[-1]["messages"][0]["role"] == "user" and len(seen) == 3                          # 이후엔 바로 user 모드


def test_stream_sse_and_json_fallback():
    def sse(req):
        body = "".join(f"data: {json.dumps({'choices': [{'delta': {'content': w}}]})}\n\n" for w in ["가", "나"]) + "data: [DONE]\n\n"
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
    p = _p(sse, base_url=URL)

    async def run(p):
        return [t async for t in p.stream("s", [{"role": "user", "content": "q"}])]
    assert asyncio.run(run(p)) == ["가", "나"]

    def plain(req):
        return httpx.Response(200, json={"choices": [{"message": {"content": "통째 응답"}}]})
    assert asyncio.run(run(_p(plain, base_url=URL))) == ["통째 응답"]

    calls = []

    def nostream(req):
        b = json.loads(req.content)
        calls.append(b["stream"])
        if b["stream"]:
            return httpx.Response(400, json={"detail": "stream not supported"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "일반"}}]})
    p3 = _p(nostream, base_url=URL)
    assert asyncio.run(run(p3)) == ["일반"] and asyncio.run(run(p3)) == ["일반"] and calls == [True, False, False]


def test_health_without_models_endpoint():
    p = _p(lambda req: httpx.Response(404), base_url=URL)
    st = asyncio.run(p.health())
    assert st["state"] == "unknown" and "연결 시험" in st["last_error"]


def test_routing_chat_to_agent():
    c = LLMClient({"providers": [{"name": "pais", "type": "openai", "base_url": "http://x/v1"}, {"name": "agent", "type": "pais_agent", "base_url": URL}],
                   "routing": {"chat": "agent"}})
    assert c.order("chat")[0].name == "agent" and [p.name for p in c.order("analyze")] == ["pais"]       # JSON 판정 작업엔 기본 제외
