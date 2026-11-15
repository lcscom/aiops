"""2.19.0 메뉴 묶음 — 모든 메뉴가 정확히 한 묶음에 속함, 로드 순서, 로그인 화면 번역 파일 공개, 한 글자 번역어 낱말 보호"""
import re
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "app" / "static"


def _groups():
    js = (S / "navgroup.js").read_text(encoding="utf-8")
    body = js[js.index("const SECTIONS = ["):js.index("const KEY")]
    return re.findall(r'\["(g-[a-z]+)", "([^"]+)", "[^"]*", \[([^\]]*)\]\]', body)


def test_every_menu_in_exactly_one_group():
    html = (S / "index.html").read_text(encoding="utf-8")
    navs = re.findall(r'<a[^>]*data-nav="([a-z0-9_-]+)"', html)
    groups = _groups()
    members = [m.strip().strip('"') for _, _, lst in groups for m in lst.split(",")]
    assert len(groups) >= 12 and len(navs) >= 30
    in_groups = [m for m in members if not m.startswith("#")]
    assert sorted(in_groups) == sorted(set(in_groups))                # 중복 없음
    assert set(navs) == set(in_groups), set(navs) ^ set(in_groups)    # 빠진 메뉴 없음
    for m in members:
        if m.startswith("#"):
            assert f'id="{m[1:]}"' in html                             # 새 창 링크(통합 관제·경영진 요약·네트워크 구성도)
    assert len(groups) <= 16 < len(navs)                              # 왼쪽 메뉴 항목 수 감소
    scripts = re.findall(r'<script src="/static/([^"]+)"', html)
    assert scripts[-1] == "layout.js" and scripts.index("navgroup.js") < scripts.index("layout.js")


def test_i18n_public_for_login_page():
    from app.security.auth import PUBLIC
    assert PUBLIC.match("/static/i18n.js") and PUBLIC.match("/static/i18n-login.js")
    assert not PUBLIC.match("/static/i18n-en.js")          # 2.48.2 전체 사전은 로그인 뒤
    assert not PUBLIC.match("/static/app.js") and not PUBLIC.match("/static/i18n.js.map")
    assert '"대시보드": "Dashboard"' in (S / "i18n-en.js").read_text(encoding="utf-8")
    assert "AMBIG.has(m) || HANGUL.test(str[i - 1]" in (S / "i18n.js").read_text(encoding="utf-8")
