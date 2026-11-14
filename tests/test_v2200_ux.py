"""2.20.0 사용성 — 검색·명령 팔레트·즐겨찾기·메뉴 접기·단축키·진행 막대 모듈의 배치와 안전장치(정적 검사)"""
import re
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "app" / "static"


def test_load_order_and_hooks():
    html = (S / "index.html").read_text(encoding="utf-8")
    scripts = re.findall(r'<script src="/static/([^"]+)"', html)
    assert scripts[-3:] == ["navgroup.js", "ux.js", "layout.js"]
    js = (S / "ux.js").read_text(encoding="utf-8")
    for needle in ('e.key === "k"', 'e.key === "/"', 'e.key === "?"', 'e.key === "["', "aiops.favs", "aiops.recent", "aiops.navmini",
                   "/api/noc/search", "/api/incidents?q=", "role\", \"dialog\"", "aria-activedescendant", "aria-selected", "aria-current"):
        assert needle in js, needle
    assert "input,textarea,select" in js                     # 입력 중에는 단축키 무시
    assert "localStorage" in js and "try {" in js            # 저장소 접근은 예외 처리


def test_palette_escapes_html():
    js = (S / "ux.js").read_text(encoding="utf-8")
    draw = js[js.index("function draw("):js.index("function pick(")]
    assert "${hl(x.k" in draw and "${esc(T(x.sub" in draw and "esc(s.slice" in draw
    assert "${x.name}" not in draw and "${x.sub}" not in draw


def test_styles_present():
    css = (S / "style.css").read_text(encoding="utf-8")
    for sel in (".cpal{", ".fav-btn{", "html.nav-mini .vnav{", ".api-prog{", ":focus-visible{", "prefers-reduced-motion"):
        assert sel in css, sel
    en = (S / "i18n-en.js").read_text(encoding="utf-8")
    assert '"즐겨찾기": "Favorites"' in en and '"메뉴 접기": "Collapse menu"' in en
