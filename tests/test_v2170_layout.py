"""2.17.0 레이아웃·새 창 — 모든 메뉴가 서랍(페이지)과 짝, layout.js 로드 순서, 새 창 주소의 로그인 후 복귀"""
import re
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "app" / "static"


def test_every_nav_has_page_and_layout_last():
    html = (S / "index.html").read_text(encoding="utf-8")
    navs = re.findall(r'<a[^>]*data-nav="([a-z0-9_-]+)"', html)
    drawers = set(re.findall(r'class="drawer" id="drawer-([a-z0-9_-]+)"', html))
    assert len(navs) >= 30
    missing = [n for n in navs if n != "dash" and n not in drawers]
    assert not missing, missing                       # 새 창(/?view=<메뉴>)이 열 화면이 모두 있음
    scripts = re.findall(r'<script src="/static/([^"]+)"', html)
    assert scripts[-1] == "layout.js"                 # 다른 모듈이 메뉴 핸들러를 건 뒤에 로드
    js = (S / "layout.js").read_text(encoding="utf-8")
    assert "window.open(`/?view=" in js and "auxclick" in js and "replace(/[^a-z0-9_-]/gi" in js


def test_login_redirect_keeps_view(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.security.auth import AuthManager
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    mgr = AuthManager(e.store, {"enabled": True}, e.audit, tmp_path)
    app = FastAPI()
    app.middleware("http")(mgr.middleware())

    @app.get("/")
    async def root():
        return {"ok": True}
    with TestClient(app) as cl:
        r = cl.get("/?view=rv", follow_redirects=False)
        assert r.status_code in (302, 303, 307) and r.headers["location"] == "/login?next=%2F%3Fview%3Drv"
        r = cl.get("/?view=<script>", follow_redirects=False)
        assert r.headers["location"] == "/login"           # 이상한 값은 버림
        assert cl.get("/", follow_redirects=False).headers["location"] == "/login"
