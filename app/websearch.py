"""AI 질의 웹 검색 근거(2.7.0) — 사내 KB 로 근거가 부족할 때 공개 웹에서 찾아 [W#] 로 인용

공급자(선택):
  · searxng — 사내에 두는 메타 검색(키 불필요, 폐쇄망 프록시 뒤 권장). GET {url}/search?q=…&format=json (settings.yml 의 search.formats 에 json 허용 필요)
  · brave   — Brave Search API. GET https://api.search.brave.com/res/v1/web/search, 헤더 X-Subscription-Token
  · tavily  — Tavily Search API. POST https://api.tavily.com/search, 헤더 Authorization: Bearer
  (Google Custom Search JSON API 는 신규 가입이 닫혔고 2027-01-01 종료 예정이라 지원하지 않음)

보안:
  · 밖으로 나가는 것은 '정리된 검색어'뿐 — 호출 전에 개체 이름·FQDN·IP·UUID/MAC·이메일·숫자 토큰을 뺀다(chatctx.clean_query)
  · 결과 페이지 본문은 공개 주소(사설·루프백·링크로컬 IP 차단, http/https 만, 리다이렉트 3회·2MB 상한)만 가져온다(SSRF 방지)
  · 본문은 UNTRUSTED_DOC 로 감싸 프롬프트 주입을 막고, 사내 KB 보다 낮은 신뢰로 쓰도록 지시
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

DEFAULTS: dict[str, Any] = {
    "enabled": False, "provider": "searxng", "url": "", "api_key": "", "proxy": "", "verify_tls": True, "timeout": 12,
    "mode": "auto",                 # auto: 사내 KB 근거가 min_kb_refs 미만이거나 화면에서 '웹' 을 켰을 때 · always · manual(화면에서 켤 때만)
    "min_kb_refs": 2, "max_results": 8, "fetch_pages": 3, "max_chars_per_page": 3500, "cache_minutes": 60,
    "language": "", "product_hint": "VMware",
    "prefer_domains": ["knowledge.broadcom.com", "techdocs.broadcom.com", "docs.vmware.com", "community.broadcom.com", "blogs.vmware.com",
                       "williamlam.com", "core.vmware.com", "github.com", "kb.vmware.com", "support.broadcom.com"],
    "only_preferred": False, "block_domains": [],
}
PRODUCT_WORDS = re.compile(r"\b(vmware|esxi?|vsphere|vcenter|vcsa|nsx|vsan|avi|vcf|tanzu|vks|aria|sddc|hcx|vrops|horizon|broadcom)\b", re.I)
UA = "Mozilla/5.0 (compatible; VCF-AIOps/2.7; +web-grounding)"


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _match(dom: str, pats: list[str]) -> bool:
    return any(dom == p or dom.endswith("." + p) for p in pats if p)


def public_host(host: str) -> bool:
    """사설·루프백·링크로컬·예약 주소로 풀리는 호스트는 거부(SSRF)"""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for i in infos:
        ip = ipaddress.ip_address(i[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def extract_text(html: str, url: str = "") -> tuple[str, str]:
    """HTML → (제목, 본문) — 스크립트·내비·머리글·바닥글 제거, article/main 우선"""
    try:
        from bs4 import BeautifulSoup
    except ImportError:                                          # bs4 없으면 태그만 제거
        t = re.sub(r"(?is)<(script|style|nav|header|footer|aside|form)[^>]*>.*?</\1>", " ", html)
        title = re.search(r"(?is)<title[^>]*>(.*?)</title>", t)
        return (re.sub(r"\s+", " ", title.group(1)).strip() if title else ""), re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()
    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.get_text(" ", strip=True) if soup.title else "")[:200]
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "aside", "form", "svg", "iframe", "button"]):
        tag.decompose()
    root = soup.find("article") or soup.find("main") or soup.find(attrs={"role": "main"}) \
        or soup.find("div", class_=re.compile(r"(article|content|kb|body|post)", re.I)) or soup.body or soup
    lines = []
    for el in root.find_all(["h1", "h2", "h3", "h4", "p", "li", "pre", "code", "td"]):
        t = el.get_text(" ", strip=True)
        if len(t) >= 3 and (not lines or lines[-1] != t):
            lines.append(("## " + t) if el.name in ("h1", "h2", "h3", "h4") else t)
    text = "\n".join(lines) if lines else root.get_text("\n", strip=True)
    return title, re.sub(r"\n{3,}", "\n\n", text)


def passages(text: str, query: str, limit: int) -> str:
    """질의어가 많이 겹치는 문단부터 limit 글자까지(제목 줄은 맥락으로 함께)"""
    words = {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}|[가-힣]{2,}", query or "") if len(w) > 2}
    paras = [p.strip() for p in re.split(r"\n(?=## )|\n{2,}|\n", text or "") if p.strip()]
    if not paras:
        return ""
    scored = []
    head = ""
    for i, p in enumerate(paras):
        if p.startswith("## "):
            head = p
        pl = p.lower()
        s = sum(1 for w in words if w in pl)
        scored.append((s, i, head, p))
    top = sorted([x for x in scored if x[0] > 0], key=lambda x: (-x[0], x[1]))
    if not top:
        top = scored[:6]
    keep, total = [], 0
    for s, i, head, p in top:
        if total >= limit:
            break
        keep.append((i, head, p))
        total += len(p)
    keep.sort()
    out, last_head = [], None
    for i, head, p in keep:
        if p.startswith("## "):
            last_head = p
        elif head and head != last_head:
            out.append(head)
            last_head = head
        out.append(p)
    return "\n".join(out)[:limit]


class WebSearch:
    def __init__(self, cfg: dict | None = None, transport: httpx.AsyncBaseTransport | None = None, resolver=None):
        self._transport = transport
        self._resolver = resolver or public_host
        self.cache: dict[str, tuple[float, list[dict]]] = {}
        self.stats = {"queries": 0, "errors": 0, "last_error": "", "last_query": "", "last_ts": 0.0, "pages": 0}
        self.configure(cfg or {})

    def configure(self, cfg: dict) -> None:
        c = {**DEFAULTS, **{k: v for k, v in (cfg or {}).items() if v is not None}}
        c["provider"] = str(c.get("provider") or "searxng").lower()
        c["mode"] = c.get("mode") if c.get("mode") in ("auto", "always", "manual") else "auto"
        for k in ("prefer_domains", "block_domains"):
            v = c.get(k) or []
            c[k] = [x.strip().lower() for x in (v.split(",") if isinstance(v, str) else v) if str(x).strip()]
        self.cfg = c
        self.cache.clear()

    @property
    def enabled(self) -> bool:
        c = self.cfg
        if not c["enabled"]:
            return False
        if c["provider"] == "searxng":
            return bool(c.get("url"))
        return bool(c.get("api_key"))

    def status(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "provider": self.cfg["provider"], "mode": self.cfg["mode"], **self.stats}

    def want(self, kb_refs: int, toggle: bool | None) -> bool:
        """이번 질문에 웹 검색을 할지 — 화면 토글(True/False)이 우선, 없으면 mode"""
        if not self.enabled:
            return False
        if toggle is not None:
            return bool(toggle)
        m = self.cfg["mode"]
        return m == "always" or (m == "auto" and kb_refs < int(self.cfg["min_kb_refs"]))

    def _client(self) -> httpx.AsyncClient:
        c = self.cfg
        return httpx.AsyncClient(timeout=httpx.Timeout(float(c["timeout"]), connect=6), verify=c["verify_tls"], proxy=c.get("proxy") or None,
                                 transport=self._transport, follow_redirects=False, headers={"User-Agent": UA})

    def build_query(self, q: str) -> str:
        q = re.sub(r"\s+", " ", q or "").strip()[:300]
        hint = self.cfg.get("product_hint") or ""
        if hint and not PRODUCT_WORDS.search(q):
            q = f"{hint} {q}"
        return q

    async def search(self, query: str) -> list[dict[str, Any]]:
        """검색 결과 목록 [{title,url,snippet,domain}] — 차단 도메인 제외, 선호 도메인 먼저"""
        c = self.cfg
        q = self.build_query(query)
        if not q:
            return []
        key = f"{c['provider']}|{q}"
        hit = self.cache.get(key)
        if hit and time.time() - hit[0] < float(c["cache_minutes"]) * 60:
            return hit[1]
        self.stats.update(queries=self.stats["queries"] + 1, last_query=q, last_ts=time.time())
        n = max(1, min(int(c["max_results"]), 20))
        try:
            async with self._client() as cl:
                if c["provider"] == "searxng":
                    params = {"q": q, "format": "json"}
                    if c.get("language"):
                        params["language"] = c["language"]
                    r = await cl.get(c["url"].rstrip("/") + "/search", params=params)
                    r.raise_for_status()
                    raw = [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": x.get("content", "")} for x in (r.json().get("results") or [])]
                elif c["provider"] == "brave":
                    params = {"q": q, "count": n}
                    if c.get("language"):
                        params["search_lang"] = c["language"]
                    r = await cl.get("https://api.search.brave.com/res/v1/web/search", params=params,
                                     headers={"X-Subscription-Token": c["api_key"], "Accept": "application/json"})
                    r.raise_for_status()
                    raw = [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": re.sub(r"<[^>]+>", "", x.get("description", ""))}
                           for x in ((r.json().get("web") or {}).get("results") or [])]
                elif c["provider"] == "tavily":
                    body = {"query": q, "max_results": n, "search_depth": "basic"}
                    if c["only_preferred"] and c["prefer_domains"]:
                        body["include_domains"] = c["prefer_domains"][:300]
                    if c["block_domains"]:
                        body["exclude_domains"] = c["block_domains"][:150]
                    r = await cl.post("https://api.tavily.com/search", json=body, headers={"Authorization": f"Bearer {c['api_key']}"})
                    r.raise_for_status()
                    raw = [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": x.get("content", "")} for x in (r.json().get("results") or [])]
                else:
                    raise ValueError(f"지원하지 않는 공급자: {c['provider']}")
        except Exception as e:  # noqa: BLE001
            self.stats.update(errors=self.stats["errors"] + 1, last_error=f"{type(e).__name__}: {e}"[:200])
            raise
        out, seen = [], set()
        for x in raw:
            u = x["url"]
            d = _domain(u)
            if not u.startswith(("http://", "https://")) or not d or u in seen or _match(d, c["block_domains"]):
                continue
            if c["only_preferred"] and not _match(d, c["prefer_domains"]):
                continue
            seen.add(u)
            out.append({"title": re.sub(r"\s+", " ", x["title"]).strip()[:200] or d, "url": u, "snippet": re.sub(r"\s+", " ", x["snippet"] or "").strip()[:400],
                        "domain": d, "preferred": _match(d, c["prefer_domains"])})
        out = sorted(out, key=lambda r: not r["preferred"])[:n]           # 선호 도메인 먼저(같은 그룹 안에서는 검색 엔진 순위 유지)
        self.cache[key] = (time.time(), out)
        if len(self.cache) > 300:
            for k in sorted(self.cache, key=lambda k: self.cache[k][0])[:100]:
                self.cache.pop(k, None)
        return out

    async def fetch(self, url: str) -> tuple[str, str]:
        """공개 주소의 HTML/텍스트 본문 — (제목, 본문). 사설 주소·비 HTML·2MB 초과는 빈 값"""
        cur = url
        async with self._client() as cl:
            for _ in range(4):
                p = urlparse(cur)
                if p.scheme not in ("http", "https") or not await asyncio.to_thread(self._resolver, p.hostname or ""):
                    return "", ""
                async with cl.stream("GET", cur, headers={"Accept": "text/html,text/plain;q=0.9"}) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        cur = urljoin(cur, r.headers["location"])
                        continue
                    if r.status_code != 200:
                        return "", ""
                    ct = r.headers.get("content-type", "")
                    if "html" not in ct and "text/plain" not in ct:
                        return "", ""
                    buf = b""
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > 2 * 1024 * 1024:
                            break
                    text = buf.decode(r.encoding or "utf-8", "replace")
                    self.stats["pages"] += 1
                    return extract_text(text, cur) if "html" in ct else ("", text)
        return "", ""

    async def gather(self, queries: list[str], focus: str = "") -> tuple[list[dict[str, Any]], list[str]]:
        """검색어 여러 개 → 결과 병합 → 상위 fetch_pages 개 본문에서 관련 문단 발췌. ([{ref,title,url,domain,snippet,text}], 실제 웹 검색어)"""
        if not self.enabled or not queries:
            return [], []
        c = self.cfg
        results: list[dict] = []
        used: list[str] = []
        seen = set()
        for q in queries[:2]:
            try:
                rs = await self.search(q)
            except Exception:  # noqa: BLE001
                continue
            used.append(self.build_query(q))
            for r in rs:
                if r["url"] not in seen:
                    seen.add(r["url"])
                    results.append(r)
        results = sorted(results, key=lambda r: not r["preferred"])[: max(int(c["max_results"]), 1)]
        n_fetch = max(0, min(int(c["fetch_pages"]), 6))
        focus = focus or " ".join(queries[:2])

        async def one(r):
            try:
                title, body = await asyncio.wait_for(self.fetch(r["url"]), float(c["timeout"]) + 3)
            except Exception:  # noqa: BLE001
                title, body = "", ""
            text = passages(body, focus, int(c["max_chars_per_page"])) if body else ""
            return {**r, "title": r["title"] or title, "text": text or r["snippet"], "fetched": bool(text)}
        top = await asyncio.gather(*[one(r) for r in results[:n_fetch]])
        rest = [{**r, "text": r["snippet"], "fetched": False} for r in results[n_fetch:]]
        out = [x for x in list(top) + rest if x["text"]]
        for i, x in enumerate(out, 1):
            x["ref"] = f"W{i}"
        return out, used

    async def test(self, query: str = "ESXi host not responding vCenter") -> dict[str, Any]:
        t = time.perf_counter()
        try:
            rs = await self.search(query)
            return {"ok": True, "count": len(rs), "ms": int((time.perf_counter() - t) * 1000), "query": self.build_query(query),
                    "results": [{"title": r["title"], "url": r["url"]} for r in rs[:5]]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}
