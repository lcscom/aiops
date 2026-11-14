"""2.42.0 — 기능 둘러보기: 전체 메뉴를 영역별 타일로(처음 보는 사람 설명용)"""
import re
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "app" / "static"


def _nav_keys():
    nav = (S / "navgroup.js").read_text(encoding="utf-8")
    body = nav[nav.index("const SECTIONS"):nav.index("];", nav.index("const SECTIONS"))]
    keys = set()
    for lst in re.findall(r'\[((?:"[^"]+",?\s*)+)\]\]', body):
        keys |= set(re.findall(r'"([^"]+)"', lst))
    return keys


def test_every_menu_has_a_tile_description():
    keys = _nav_keys()
    assert {"dash", "tour", "bot", "cap", "#nav-noc", "#nav-exec", "#nav-netmap"} <= keys
    js = (S / "tour.js").read_text(encoding="utf-8")
    body = js[js.index("const D = {"):js.index("};", js.index("const D = {"))]
    desc = set(re.findall(r'^\s*"?([#\w-]+)"?: \[', body, re.M))
    missing = keys - desc - {"tour"}
    assert not missing, f"기능 둘러보기 설명이 없는 메뉴: {missing}"          # 새 메뉴를 만들면 여기에도 한 줄
    assert not desc - keys, f"없는 메뉴 설명: {desc - keys}"


def test_wiring():
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-tour"' in html and 'id="drawer-tour"' in html and "/static/tour.js" in html
    assert '"dash", "mhome", "tour", "#nav-noc"' in (S / "navgroup.js").read_text(encoding="utf-8")
    js = (S / "tour.js").read_text(encoding="utf-8")
    for k in ("AIOPS_NAVGROUPS", "처음이라면 이 순서로", "tour-print", "aiops.tour.seen", "읽기 전용", "a.hidden"):
        assert k in js, k
    css = (S / "style.css").read_text(encoding="utf-8")
    assert ".tr-tile" in css and "html.tour-print" in css
    subprocess.run(["node", "--check", str(S / "tour.js")], check=True)
