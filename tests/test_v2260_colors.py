"""2.26.0 영역 색 — 메뉴 영역별 강조색, 대시보드 요약 칸 의미 색"""
import re
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "app/static"


def _lum(h):
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return .2126 * c[0] + .7152 * c[1] + .0722 * c[2]


def _cr(a, b):
    x, y = sorted([_lum(a), _lum(b)])
    return (y + .05) / (x + .05)


def test_sections_have_keys_and_palette_contrast():
    js = (S / "navgroup.js").read_text(encoding="utf-8")
    keys = re.findall(r'\["[^"]+", "(ops|infra|secu|ai|adm)", \[', js)
    assert keys == ["ops", "infra", "secu", "ai", "adm"]
    assert "documentElement.dataset.sec" in js and 'chat.dataset.sec = "ai"' in js
    css = (S / "style.css").read_text(encoding="utf-8")
    for k in keys:
        m = re.search(r"\[data-sec=" + k + r"\]\{--s:(#[0-9a-f]{6});--s-ink:(#[0-9a-f]{6});--s-bg:(#[0-9a-f]{6})", css)
        assert m, k
        s, ink, bg = m.groups()
        assert _cr(s, "#ffffff") >= 4.5 and _cr(s, bg) >= 4.5 and _cr(ink, bg) >= 4.5      # 흰 바탕·영역 바탕 모두 읽힘
    assert ".content,.drawer,.cmdk,.modal{--action:var(--s)" in css
    assert ".kpis .kpi.hot" in css and "#pane-anoms" in css
    # 데이터 색(차트 범례·상태 점)은 영역 색으로 바뀌지 않음
    assert ".pf-leg i.s0{background:#0072a3}" in css and ".tp-dot.maint{background:#0072a3}" in css


def test_kpi_hot_toggle_and_syntax():
    app = (S / "app.js").read_text(encoding="utf-8")
    assert 'classList.toggle("hot", open.length > 0)' in app
    for f in ("navgroup.js", "app.js"):
        assert subprocess.run(["node", "--check", str(S / f)]).returncode == 0
