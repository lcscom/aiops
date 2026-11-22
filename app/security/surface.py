"""로그인 전 공개 표면 자동 점검(2.49.0) — 모든 GET 경로를 '로그인 안 한 외부 사용자'로 불러 보고,
허용 목록 밖에서 2xx 로 내용을 돌려주는 경로를 찾는다. 새 기능이 공개 경로를 실수로 늘리면 보안 점검·테스트가 바로 잡는다.

- 내부 요청(앱 안 ASGI 호출)이라 실제 외부망·프록시는 거치지 않는다. 출발지는 문서용 IP(203.0.113.10),
  '외부' 판정은 Cloudflare 머리글(CF-Ray)로 흉내 낸다.
- GET 만 부른다. 인증 전 단계에서 막히므로 처리기 자체는 공개 경로에서만 실행된다(부작용 없음).
"""
from __future__ import annotations

import re
from typing import Any

import httpx

# 로그인 없이 2xx 가 정상인 경로와 이유
PUBLIC_OK: dict[str, str] = {
    "/login": "로그인 화면",
    "/healthz": "생존 확인(외부에는 ok 만)",
    "/readyz": "준비 확인(외부에는 ready 만)",
    "/robots.txt": "검색 노출 차단",
    "/api/auth/config": "로그인 화면 설정(배너·SSO 여부)",
    "/.well-known/security.txt": "보안 연락처(설정한 경우만)",
    "/static/login.js": "로그인 화면 스크립트",
    "/static/i18n.js": "언어 전환 엔진(사전 없음)",
    "/static/i18n-login.js": "로그인 화면 영어 사전",
    "/static/style.css": "화면 스타일",
}
# 로그인 뒤여야 하는 대표 정적 파일(경로 목록에 없으므로 따로 확인)
STATIC_PRIVATE = ("/static/i18n-en.js", "/static/core.js", "/static/index.html", "/static/app/vcf-aiops.apk", "/static/noc.html")
PARAM = re.compile(r"\{[^}]+\}")


def _walk(routes, prefix: str = ""):
    for r in routes or []:
        sub = getattr(r, "original_router", None)            # FastAPI 0.16x: include_router 가 지연 포함 객체를 만듦
        if sub is not None:
            ctx = getattr(r, "include_context", None)
            pre = prefix + (getattr(ctx, "prefix", "") or getattr(sub, "prefix", "") or "")
            yield from _walk(getattr(sub, "routes", []), pre)
            continue
        yield prefix + getattr(r, "path", ""), getattr(r, "methods", None) or set()


def get_paths(app) -> list[str]:
    out: set[str] = set()
    for path, methods in _walk(getattr(app, "routes", [])):
        if "GET" not in methods or not path.startswith("/") or path.startswith("/static"):
            continue
        out.add(PARAM.sub("probe0000", path))
    return sorted(out)


async def scan(app, probe_token: str = "") -> dict[str, Any]:
    paths = get_paths(app) + list(PUBLIC_OK) + list(STATIC_PRIVATE)
    seen: set[str] = set()
    rows: list[dict] = []
    tr = httpx.ASGITransport(app=app, client=("203.0.113.10", 41000))
    h = {"cf-ray": "probe-aiops", "cf-connecting-ip": "203.0.113.10"}
    if probe_token:
        h["x-aiops-probe"] = probe_token
    async with httpx.AsyncClient(transport=tr, base_url="http://surface.internal", timeout=8) as c:
        for p in paths:
            if p in seen:
                continue
            seen.add(p)
            try:
                r = await c.get(p, headers=h, follow_redirects=False)
                st, size = r.status_code, len(r.content)
            except Exception as e:  # noqa: BLE001
                st, size = 0, 0
                rows.append({"path": p, "status": 0, "size": 0, "error": type(e).__name__})
                continue
            rows.append({"path": p, "status": st, "size": size})
    open_ = [r for r in rows if 200 <= r["status"] < 300 and r["path"] not in PUBLIC_OK]
    public = [r for r in rows if 200 <= r["status"] < 300 and r["path"] in PUBLIC_OK]
    return {"checked": len(rows), "open": open_, "public": public,
            "errors": [r for r in rows if r["status"] == 0 or r["status"] >= 500]}
