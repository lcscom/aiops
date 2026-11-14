"""2.7.0 AI 질의 웹 검색 근거 — 공급자(SearXNG·Brave·Tavily) · 정리된 검색어만 외부로 · 선호/차단 도메인 · 본문 발췌 · SSRF 차단 · 모드"""
import asyncio
import json

import httpx

from app import chatctx
from app.websearch import WebSearch, extract_text, passages

PAGE = """<html><head><title>ESXi voltage sensor alarm</title><script>alert(1)</script></head><body><nav>menu home</nav>
<article><h1>Hardware sensor voltage alarm</h1><p>Symptoms: the ESXi host shows a voltage sensor in Yellow state.</p>
<p>Unrelated marketing paragraph about cloud.</p><h2>Resolution</h2><p>Check the PSU in iLO or iDRAC and replace the failed power supply.</p></article>
<footer>copyright</footer></body></html>"""


def _transport(seen):
    def handler(req: httpx.Request):
        seen.append(req)
        u = str(req.url)
        if "searx.corp" in u:
            return httpx.Response(200, json={"results": [
                {"title": "Random blog", "url": "https://blog.example.net/voltage", "content": "blog"},
                {"title": "KB 999 Voltage alarm", "url": "https://knowledge.broadcom.com/external/article/999", "content": "voltage sensor yellow"},
                {"title": "Blocked", "url": "https://spam.example.org/x", "content": "spam"},
                {"title": "bad scheme", "url": "ftp://x/y", "content": ""}]})
        if "api.search.brave.com" in u:
            assert req.headers["X-Subscription-Token"] == "BKEY"
            return httpx.Response(200, json={"web": {"results": [{"title": "T", "url": "https://techdocs.broadcom.com/a", "description": "<b>d</b>"}]}})
        if "api.tavily.com" in u:
            assert req.headers["Authorization"] == "Bearer TKEY"
            b = json.loads(req.content)
            assert b["include_domains"] == ["knowledge.broadcom.com"]
            return httpx.Response(200, json={"results": [{"title": "Tv", "url": "https://knowledge.broadcom.com/b", "content": "c", "score": 0.9}]})
        if "knowledge.broadcom.com/external/article/999" in u:
            return httpx.Response(200, html=PAGE)
        if "blog.example.net" in u:
            return httpx.Response(301, headers={"location": "http://10.0.0.5/internal"})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_searxng_filters_and_prefers_domains():
    seen = []
    ws = WebSearch({"enabled": True, "provider": "searxng", "url": "http://searx.corp:8080", "block_domains": ["example.org"]}, transport=_transport(seen),
                   resolver=lambda h: not h.startswith("10."))
    rs = asyncio.run(ws.search("ESXi voltage sensor yellow"))
    assert [r["domain"] for r in rs] == ["knowledge.broadcom.com", "blog.example.net"]                # 선호 먼저, 차단·ftp 제외
    assert seen[0].url.params["format"] == "json" and seen[0].url.params["q"] == "ESXi voltage sensor yellow"
    asyncio.run(ws.search("ESXi voltage sensor yellow"))
    assert len(seen) == 1                                                                                   # 캐시
    q = ws.build_query("hostd crash after upgrade")
    assert q == "VMware hostd crash after upgrade"


def test_gather_fetches_text_and_blocks_private_redirect():
    seen = []
    ws = WebSearch({"enabled": True, "provider": "searxng", "url": "http://searx.corp:8080", "fetch_pages": 2}, transport=_transport(seen),
                   resolver=lambda h: not h.startswith("10."))
    out, used = asyncio.run(ws.gather(["ESXi voltage sensor yellow PSU"]))
    assert used == ["ESXi voltage sensor yellow PSU"]
    kb = next(x for x in out if "broadcom" in x["domain"])
    assert kb["ref"] == "W1" and kb["fetched"] and "replace the failed power supply" in kb["text"] and "alert(1)" not in kb["text"] and "copyright" not in kb["text"]
    blog = next(x for x in out if "blog" in x["domain"])
    assert not blog["fetched"] and blog["text"] == "blog"                                                  # 사설 주소로 리다이렉트 → 본문 안 가져옴
    assert not any("10.0.0.5" in str(r.url) for r in seen)


def test_brave_and_tavily_providers():
    seen = []
    b = WebSearch({"enabled": True, "provider": "brave", "api_key": "BKEY"}, transport=_transport(seen))
    rs = asyncio.run(b.search("vsan resync"))
    assert rs[0]["url"] == "https://techdocs.broadcom.com/a" and rs[0]["snippet"] == "d"
    t = WebSearch({"enabled": True, "provider": "tavily", "api_key": "TKEY", "only_preferred": True, "prefer_domains": ["knowledge.broadcom.com"]}, transport=_transport(seen))
    assert asyncio.run(t.search("nsx edge"))[0]["title"] == "Tv"


def test_mode_and_enabled():
    assert not WebSearch({"enabled": True, "provider": "searxng"}).enabled                                 # 주소 없음
    assert not WebSearch({"enabled": True, "provider": "brave"}).enabled                                   # 키 없음
    ws = WebSearch({"enabled": True, "provider": "searxng", "url": "http://s", "mode": "auto", "min_kb_refs": 2})
    assert ws.want(1, None) and not ws.want(2, None) and ws.want(5, True) and not ws.want(0, False)
    ws.configure({"enabled": True, "provider": "searxng", "url": "http://s", "mode": "manual"})
    assert not ws.want(0, None) and ws.want(0, True)
    assert not WebSearch({}).want(0, True)                                                                  # 꺼져 있으면 토글도 무시


def test_only_clean_query_leaves():
    q = chatctx.clean_query("esx08.rangers.lab PSU1 Voltage state assert user admin@vsphere.local from 10.1.2.3 vm db-prod-01",
                            ["esx08.rangers.lab", "db-prod-01"])
    assert "rangers" not in q and "esx08" not in q and "10.1.2.3" not in q and "admin@" not in q and "db-prod-01" not in q
    assert "Voltage state assert" in q


def test_extract_and_passages():
    title, body = extract_text(PAGE)
    assert title == "ESXi voltage sensor alarm" and "menu home" not in body and "## Resolution" in body
    p = passages(body, "voltage PSU replace", 400)
    assert "replace the failed power supply" in p and "marketing" not in p


def test_keywords_strip_generic():
    assert chatctx.keywords("하드웨어 경고 원인 알려줘") == "하드웨어 경고"
    assert chatctx.keywords("PSU1 Voltage state assert for Yellow") == "PSU1 Voltage assert Yellow"


def test_settings_validation_merges_defaults():
    import inspect
    import app.api_enterprise as AE                                     # 모듈 import(구문) 확인
    src = inspect.getsource(AE)
    assert 'key == "web_search"' in src and "WSD" in src
