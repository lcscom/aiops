"""고객 제출용 보고서 묶음(2.36.0) — 용량·가정 분석(저장한 가정)·권장 구성·보안 판독을 한 파일로.

형식: PDF(fpdf2, 한글 글꼴 내장) · Word(.docx, 표준 WordprocessingML 을 직접 작성 — 추가 의존성 없음) · HTML(인쇄용)
문서 모델: [("h1"|"h2"|"p"|"note", 텍스트) | ("table", 머리글, 행들)] — 세 형식이 같은 내용을 그린다.
보고서에는 vCenter·클러스터·호스트 이름이 들어간다 — 외부 제출 전 고객과 공개 범위를 확인할 것(화면에서 안내).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import html as _h
import io
import zipfile
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as _x

FONT_DIR = Path(__file__).parent / "assets" / "fonts"
VERD = {"ok": "수용 가능", "warn": "빠듯함", "bad": "수용 불가", "unknown": "판단 불가"}


async def gather(engine, cap, scn, ids: list[int], run_whatif) -> dict[str, Any]:
    """보고서 재료 — 실패한 절은 '자료 없음'으로 두고 계속"""
    out: dict[str, Any] = {"generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "errors": []}
    try:
        out["capacity"] = await cap.overview()
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"용량: {type(e).__name__}")
    try:
        out["rightsizing"] = await cap.rightsizing()
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"적정화: {type(e).__name__}")
    sc = []
    if ids:
        allsc = {x["id"]: x for x in await scn.list()}
        for i in ids:
            if i in allsc:
                r = await run_whatif(allsc[i])
                sc.append({"meta": allsc[i], "result": r})
    out["scenarios"] = sc
    from . import bestpractice as BP
    bp = []
    for c in engine.connectors:
        if getattr(c, "type", "") == "vcenter" and getattr(c, "enabled", True) and getattr(c, "health_snap", None):
            try:
                r = await asyncio.to_thread(BP.evaluate, c.health_snap)
                bp += [{**x, "vcenter": c.name} for x in r["clusters"]]
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"권장 구성({c.name}): {type(e).__name__}")
    out["bestpractice"] = bp
    out["bp_rules"] = {r["id"]: r for r in BP.RULES}
    try:
        out["assessment"] = await engine.assess.latest() if getattr(engine, "assess", None) else None
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"보안 판독: {type(e).__name__}")
    return out


def _f(x, unit: str = "", nd: int = 1) -> str:
    if x is None or x == "":
        return "—"
    if isinstance(x, float):
        x = round(x, nd)
        if nd == 0 or x == int(x):
            x = int(x)
    return f"{x:,}{unit}" if isinstance(x, (int, float)) else f"{x}{unit}"


def build(d: dict[str, Any]) -> list[tuple]:
    """문서 모델"""
    B: list[tuple] = []
    who = d.get("customer") or ""
    B.append(("title", f"{who + ' ' if who else ''}VCF 인프라 용량·구성 점검 보고서"))
    B.append(("p", f"작성 {d['generated']} · VCF AIops 읽기 전용 수집 결과(설정 변경 없음)"))
    # 1 요약
    cap = d.get("capacity") or {}
    items = cap.get("items") or []
    cls = [x for x in items if x["kind"] == "cluster"]
    dss = [x for x in items if x["kind"] == "datastore"]
    bp = d.get("bestpractice") or []
    asum = ((d.get("assessment") or {}).get("summary") or {})
    B.append(("h1", "1. 요약"))
    lines = []
    if cls:
        warn = [x for x in cls if x.get("state") != "ok"]
        lines.append(f"클러스터 {len(cls)}개 중 {len(warn)}개가 80% 이상이거나 30일 안에 90%에 닿을 것으로 보입니다." if warn else
                     f"클러스터 {len(cls)}개 모두 사용률 80% 미만이며 30일 안에 90%에 닿을 추세가 없습니다.")
    if dss:
        dw = [x for x in dss if x.get("state") != "ok"]
        lines.append(f"공유 데이터스토어 {len(dss)}개 중 {len(dw)}개가 주의 구간입니다.")
    for s in d.get("scenarios") or []:
        r = s.get("result")
        if r:
            lines.append(f"가정 '{s['meta']['name']}'({s['meta']['cluster']}): {VERD.get(r['after']['verdict'], r['after']['verdict'])}"
                         + (f", 추가 필요 서버 {r['hosts_needed']}대" if r.get("hosts_needed") else ""))
    if bp:
        n = {k: sum(1 for x in bp if x["verdict"] == k) for k in ("ok", "partial", "not")}
        lines.append(f"권장 구성 판독: 권장 {n['ok']} · 부분 권장 {n['partial']} · 권장 아님 {n['not']} (클러스터 {len(bp)}개)")
    if asum:
        c = asum.get("counts") or {}
        lines.append(f"보안 판독: 점수 {_f(asum.get('score'))} · 실패 {c.get('FAIL', 0)} · 경고 {c.get('WARN', 0)} · 알려진 취약 버전 {((asum.get('cve') or {}).get('vulnerable', 0))}건")
    for x in lines or ["수집된 자료가 없습니다."]:
        B.append(("bullet", x))
    # 2 용량
    B.append(("h1", "2. 용량 현황"))
    if cls:
        rows = []
        for x in sorted(cls, key=lambda x: -(max(x.get("cpu") or 0, x.get("mem") or 0))):
            fc = (x.get("forecast") or {}).get("days_to", {}) or {}
            fm = (x.get("forecast_mem") or {}).get("days_to", {}) or {}
            d90 = min([v for v in (fc.get("90"), fm.get("90")) if v is not None], default=None)
            rows.append([x["vcenter"], x["name"], _f(x.get("hosts")), _f(x.get("cpu"), "%"), _f(x.get("mem"), "%"), _f(x.get("ha_n1"), "%"),
                         f"{d90}일" if d90 is not None else "추세 없음", {"ok": "정상", "warn": "주의", "down": "위험"}.get(x.get("state"), "—")])
        B.append(("table", ["vCenter", "클러스터", "호스트", "CPU", "메모리", "메모리(N-1)", "90% 도달", "상태"], rows))
        B.append(("note", "메모리(N-1) = 가장 큰 호스트 1대를 뺀 용량 대비 사용률. 90% 도달 = 일별 추세 연장(관측 7일 미만이면 추세 없음)."))
    else:
        B.append(("p", "용량 표본이 아직 없습니다."))
    if dss:
        rows = [[x["vcenter"], x["name"], x.get("type", ""), _f((x.get("capacity_gb") or 0) / 1000, " TB"), _f(x.get("disk"), "%"),
                 _f(x.get("growth_gb_day"), " GB/일")] for x in sorted(dss, key=lambda x: -(x.get("disk") or 0))[:30]]
        B.append(("h2", "데이터스토어"))
        B.append(("table", ["vCenter", "데이터스토어", "유형", "용량", "사용률", "증가"], rows))
    rs = d.get("rightsizing") or {}
    if rs.get("clusters"):
        B.append(("h2", "적정화(회수 가능 자원)"))
        rows = [[x["cluster"], _f(x["vms"]), _f(x["oversized"]), _f(x["idle"]), _f(x["undersized"]), _f(x["reclaim_vcpu"]), _f(x["reclaim_mem_gb"], " GB")]
                for x in rs["clusters"][:20]]
        B.append(("table", ["클러스터", "판단 VM", "과다", "유휴", "과소", "회수 vCPU", "회수 메모리"], rows))
        B.append(("note", f"관측 {rs.get('days')}일 피크 기준. 과다 = 피크×여유율보다 큰 할당, 유휴 = CPU·메모리 피크가 기준 미만."))
    # 3 가정 분석
    B.append(("h1", "3. 증설·변경 가정 분석"))
    if not d.get("scenarios"):
        B.append(("p", "포함한 가정이 없습니다 — 가정 분석에서 시나리오를 저장한 뒤 보고서에 넣을 수 있습니다."))
    for s in d.get("scenarios") or []:
        m, r = s["meta"], s.get("result")
        B.append(("h2", f"{m['name']} — {m['vcenter']} / {m['cluster']}"))
        if not r:
            B.append(("p", "지금 인벤토리로 다시 계산하지 못했습니다(클러스터 없음·입력 오류)."))
            continue
        i = r["inputs"]
        parts = [f"HA 장애 대비 {i['ha_failures']}대"]
        if i["add_vms"]:
            parts.append(f"VM {i['add_vms']}대 추가({i['vm_vcpu']:g} vCPU·{i['vm_mem_gb']:g} GB)")
        if i["remove_vms"]:
            parts.append(f"VM {i['remove_vms']}대 제거")
        if i["add_hosts"]:
            hs = r["host_spec"]
            parts.append(f"서버 {i['add_hosts']}대 추가({hs['cores']}코어·{hs['mem_gb']} GB)")
        if i["remove_hosts"] or i["remove_names"]:
            parts.append(f"서버 {i['remove_hosts'] + len(i['remove_names'])}대 제외")
        B.append(("p", "가정: " + ", ".join(parts) + f" · 기준 {'최근 피크(p95)' if r['basis']['kind'] == 'p95' else '지금 값'}"))
        b, a = r["before"], r["after"]
        B.append(("table", ["", "호스트", "CPU 사용/가용", "메모리 사용/가용", "판정"],
                  [["지금", _f(b["hosts"]), f"{_f(b['cpu']['pct_usable'], '%')}", f"{_f(b['mem']['pct_usable'], '%')}", VERD.get(b["verdict"], "")],
                   ["가정 후", _f(a["hosts"]), f"{_f(a['cpu']['pct_usable'], '%')}", f"{_f(a['mem']['pct_usable'], '%')}", VERD.get(a["verdict"], "")]]))
        extra = []
        if r.get("hosts_needed"):
            extra.append(f"80% 안에 들려면 같은 사양 서버 {r['hosts_needed']}대 추가 필요")
        lic = r.get("license") or {}
        if lic.get("after") is not None:
            extra.append(f"라이선스 코어 {_f(lic['before'])} → {_f(lic['after'])}")
        v = r.get("vsan")
        if v:
            va = v.get("after") or {}
            extra.append(f"vSAN 쓸 수 있는 용량 {v['usable_tb']} TB({v['scheme']}, 운영 예비 {v['reserve_pct']:g}%{' + 호스트 1대' if v['host_reserve'] else ''}) 사용률 {_f(v['pct'], '%')} → {_f(va.get('pct'), '%')}")
        ev = r.get("evc")
        if ev and ev.get("items") and ev.get("verdict") != "unknown":
            extra.append("혼합 세대: " + " ".join(ev["items"][:2]))
        rsz = r.get("rightsizing")
        if rsz and rsz.get("deferred"):
            extra.append(f"적정화 반영 시 증설 {rsz['deferred']}대를 미룰 수 있음")
        for x in extra:
            B.append(("bullet", x))
        q = (r.get("quarters") or {}).get("rows") or []
        if q:
            B.append(("table", ["분기", "CPU 수요", "메모리 수요", "필요 서버(누적)", "그 분기 추가", "라이선스 코어"],
                      [[x["label"], _f(x["cpu_ghz"], " GHz"), _f(x["mem_gb"], " GB"), _f(x["hosts_add"]), _f(x["add_this_q"]), _f(x["license_cores"])] for x in q]))
        co = r.get("cost") or {}
        if co.get("vcf"):
            vv = co["vcf"]
            B.append(("bullet", f"증설 비용(VCF 원가 모델): 연 {_f(vv['annual'])} {vv['currency']}(구독 {_f(vv['parts']['subscription_year'])} · 서버 감가 {_f(vv['parts']['hardware_year'])} · 상면 {_f(vv['parts']['facility_year'])})"))
        for c in co.get("cloud") or []:
            if c.get("monthly") is not None:
                B.append(("bullet", f"같은 VM 을 {c['label']}({c['sku']})에 올리면 월 {_f(c['monthly'])} USD"))
    # 4 권장 구성
    B.append(("h1", "4. 권장 구성 판독"))
    if bp:
        V = {"ok": "권장 구성", "partial": "부분 권장", "not": "권장 아님"}
        B.append(("table", ["vCenter", "클러스터", "호스트", "점수", "판정", "필수 미충족"],
                  [[x["vcenter"], x["cluster"], _f(x["hosts"]), _f(x["score"]), V.get(x["verdict"], ""),
                    ", ".join((d.get("bp_rules", {}).get(i) or {}).get("title", i) for i in x.get("must_fail") or []) or "—"] for x in bp]))
        fails = []
        for x in bp:
            for rr in x.get("results") or []:
                if rr["status"] == "fail":
                    rule = d.get("bp_rules", {}).get(rr["id"]) or {}
                    fails.append([x["cluster"], rule.get("title", rr["id"]), (rr.get("detail") or "")[:120]])
        if fails:
            B.append(("h2", "미충족 항목"))
            B.append(("table", ["클러스터", "항목", "내용"], fails[:60]))
    else:
        B.append(("p", "인프라 점검 스냅숏이 없어 판독하지 못했습니다."))
    # 5 보안 판독
    B.append(("h1", "5. 보안 판독"))
    asd = d.get("assessment") or {}
    if asum:
        c = asum.get("counts") or {}
        B.append(("p", f"점검 {dt.datetime.fromtimestamp(asum.get('ts', 0)).strftime('%Y-%m-%d %H:%M')} · vCenter {asum.get('vcenters')} · ESXi {asum.get('hosts')} · "
                       f"통과 {c.get('PASS', 0)} · 실패 {c.get('FAIL', 0)} · 경고 {c.get('WARN', 0)} · 점수 {_f(asum.get('score'))}"))
        bad = [r for r in asd.get("rows") or [] if r.get("status") == "FAIL"]
        sev = {"high": 0, "medium": 1, "low": 2}
        bad.sort(key=lambda r: (sev.get(str(r.get("severity", "")).lower(), 3), r.get("id", "")))
        if bad:
            B.append(("table", ["항목", "KISA", "대상", "현재", "권고"],
                      [[f"{r.get('id', '')} {r.get('title', '')}"[:70], r.get("kisa", "") or "—", str(r.get("target", ""))[:40], str(r.get("current", ""))[:40],
                        str(r.get("expected", ""))[:40]] for r in bad[:60]]))
        vul = [r for r in asd.get("cve") or [] if r.get("verdict") == "취약"]
        if vul:
            B.append(("h2", "알려진 취약 버전"))
            B.append(("table", ["권고", "대상", "현재 빌드", "고정 빌드", "심각도"],
                      [[str(r.get("id", ""))[:30], str(r.get("target", ""))[:40], str(r.get("build", "")), str(r.get("fixed", "") or r.get("fix", ""))[:30], str(r.get("severity", ""))]
                       for r in vul[:40]]))
    else:
        B.append(("p", "보안 판독 결과가 없습니다."))
    B.append(("h1", "부록. 계산 기준"))
    for x in ("사용률 판정: 쓸 수 있는 용량(HA 대비 가장 큰 호스트 N대 제외) 대비 80% 미만 수용 가능, 80~100% 빠듯함, 100% 초과 수용 불가.",
              "라이선스 코어: CPU 당 최소 16코어(Broadcom KB 313548).",
              "vSAN 쓸 수 있는 용량: (원시 × (1 - 운영 예비율) - 호스트 1대 몫(재구축 예비)) ÷ 정책 배수 × 데이터 절감률. ESA RAID-5 는 3~5대 2+1(1.5배), 6대 이상 4+1(1.25배). 모든 객체가 같은 정책이라고 가정.",
              "모든 수치는 수집 시점의 vCenter 값과 용량 표본(5분)에서 계산했으며 vCenter 설정은 바꾸지 않았습니다."):
        B.append(("bullet", x))
    if d.get("errors"):
        B.append(("note", "수집하지 못한 자료: " + ", ".join(d["errors"])))
    return B


# ------------------------------------------------------------------ 그리기
def render(d: dict[str, Any], fmt: str) -> tuple[bytes, str, str]:
    B = build(d)
    if fmt == "docx":
        return to_docx(B), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"
    if fmt == "html":
        return to_html(B).encode(), "text/html; charset=utf-8", "html"
    return to_pdf(B), "application/pdf", "pdf"


def to_html(B: list[tuple]) -> str:
    o = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>VCF 점검 보고서</title><style>'
         'body{font:13px/1.55 "Noto Sans KR","Malgun Gothic",sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1b2a33}'
         'h1{font-size:20px}h2{font-size:16px;border-bottom:2px solid #d5dee4;padding-bottom:3px;margin-top:26px}h3{font-size:14px;margin:16px 0 6px}'
         'table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:12px}th,td{border:1px solid #cfd8de;padding:4px 6px;text-align:left;vertical-align:top}'
         'th{background:#eef3f6}.note{color:#5b6b75;font-size:12px}@media print{body{margin:0}}</style></head><body>']
    ul = False
    for b in B:
        if b[0] != "bullet" and ul:
            o.append("</ul>")
            ul = False
        if b[0] == "title":
            o.append(f"<h1>{_h.escape(b[1])}</h1>")
        elif b[0] == "h1":
            o.append(f"<h2>{_h.escape(b[1])}</h2>")
        elif b[0] == "h2":
            o.append(f"<h3>{_h.escape(b[1])}</h3>")
        elif b[0] == "p":
            o.append(f"<p>{_h.escape(b[1])}</p>")
        elif b[0] == "note":
            o.append(f'<p class="note">{_h.escape(b[1])}</p>')
        elif b[0] == "bullet":
            if not ul:
                o.append("<ul>")
                ul = True
            o.append(f"<li>{_h.escape(b[1])}</li>")
        elif b[0] == "table":
            o.append("<table><tr>" + "".join(f"<th>{_h.escape(str(c))}</th>" for c in b[1]) + "</tr>"
                     + "".join("<tr>" + "".join(f"<td>{_h.escape(str(c))}</td>" for c in r) + "</tr>" for r in b[2]) + "</table>")
    if ul:
        o.append("</ul>")
    return "".join(o) + "</body></html>"


def to_pdf(B: list[tuple]) -> bytes:
    from fpdf import FPDF
    from fpdf.fonts import FontFace

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(True, 14)
    pdf.add_font("kr", "", str(FONT_DIR / "NotoSansKR-Regular-sub.otf"))
    pdf.add_font("kr", "B", str(FONT_DIR / "NotoSansKR-Bold-sub.otf"))
    pdf.set_margins(14, 14, 14)
    pdf.add_page()
    W = pdf.w - 28
    for b in B:
        k = b[0]
        if k == "title":
            pdf.set_font("kr", "B", 16)
            pdf.multi_cell(W, 8, b[1], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        elif k == "h1":
            pdf.ln(3)
            pdf.set_font("kr", "B", 13)
            pdf.multi_cell(W, 7, b[1], new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(200, 210, 216)
            pdf.line(14, pdf.get_y(), 14 + W, pdf.get_y())
            pdf.ln(2)
        elif k == "h2":
            pdf.ln(1.5)
            pdf.set_font("kr", "B", 11)
            pdf.multi_cell(W, 6, b[1], new_x="LMARGIN", new_y="NEXT")
        elif k in ("p", "note"):
            pdf.set_font("kr", "", 9 if k == "p" else 8)
            pdf.set_text_color(0 if k == "p" else 90, 0 if k == "p" else 105, 0 if k == "p" else 115)
            pdf.multi_cell(W, 5, b[1], new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(0.8)
        elif k == "bullet":
            pdf.set_font("kr", "", 9)
            pdf.multi_cell(W, 5, "• " + b[1], new_x="LMARGIN", new_y="NEXT")
        elif k == "table":
            heads, rows = b[1], b[2]
            n = len(heads)
            lens = [max([len(str(h))] + [len(str(r[i])) for r in rows]) for i, h in enumerate(heads)]
            tot = sum(min(40, max(4, x)) for x in lens)
            widths = tuple(min(40, max(4, x)) / tot * W for x in lens)
            pdf.set_font("kr", "", 7.6)
            with pdf.table(col_widths=widths, width=W, text_align="LEFT", line_height=4.2, padding=1.2,
                           headings_style=FontFace(emphasis="BOLD", fill_color=(236, 242, 245)), borders_layout="HORIZONTAL_LINES") as t:
                hr = t.row()
                for h in heads:
                    hr.cell(str(h))
                for r in rows:
                    rr = t.row()
                    for i in range(n):
                        rr.cell(str(r[i]) if i < len(r) else "")
            pdf.ln(2)
    return bytes(pdf.output())


def _run(t: str, bold: bool = False, size: int | None = None, color: str = "") -> str:
    pr = "<w:rPr>" + ('<w:rFonts w:ascii="Malgun Gothic" w:hAnsi="Malgun Gothic" w:eastAsia="Malgun Gothic"/>') + ("<w:b/>" if bold else "") + \
         (f'<w:color w:val="{color}"/>' if color else "") + (f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>' if size else "") + "</w:rPr>"
    return f'<w:r>{pr}<w:t xml:space="preserve">{_x(t)}</w:t></w:r>'


def to_docx(B: list[tuple]) -> bytes:
    body = []
    for b in B:
        k = b[0]
        if k == "title":
            body.append(f'<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr>{_run(b[1], True, 36)}</w:p>')
        elif k == "h1":
            body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>{_run(b[1], True, 28)}</w:p>')
        elif k == "h2":
            body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>{_run(b[1], True, 23)}</w:p>')
        elif k == "p":
            body.append(f"<w:p>{_run(b[1], size=20)}</w:p>")
        elif k == "note":
            body.append(f"<w:p>{_run(b[1], size=17, color='5B6B75')}</w:p>")
        elif k == "bullet":
            body.append(f'<w:p><w:pPr><w:ind w:left="360" w:hanging="220"/></w:pPr>{_run("• " + b[1], size=20)}</w:p>')
        elif k == "table":
            heads, rows = b[1], b[2]
            grid = "".join('<w:gridCol w:w="1500"/>' for _ in heads)
            tr = []
            for i, r in enumerate([heads] + rows):
                shd = '<w:shd w:val="clear" w:color="auto" w:fill="EEF3F6"/>' if i == 0 else ""
                cells = "".join(f"<w:tc><w:tcPr>{shd}</w:tcPr><w:p>{_run(str(c), i == 0, 17)}</w:p></w:tc>" for c in r)
                tr.append(f"<w:tr>{'<w:trPr><w:tblHeader/></w:trPr>' if i == 0 else ''}{cells}</w:tr>")
            body.append('<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/>'
                        '<w:tblBorders><w:top w:val="single" w:sz="4" w:color="CFD8DE"/><w:bottom w:val="single" w:sz="4" w:color="CFD8DE"/>'
                        '<w:insideH w:val="single" w:sz="4" w:color="CFD8DE"/><w:left w:val="single" w:sz="4" w:color="CFD8DE"/>'
                        '<w:right w:val="single" w:sz="4" w:color="CFD8DE"/><w:insideV w:val="single" w:sz="4" w:color="CFD8DE"/></w:tblBorders>'
                        f'</w:tblPr><w:tblGrid>{grid}</w:tblGrid>{"".join(tr)}</w:tbl><w:p/>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + "".join(body) +
           '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1021" w:bottom="1134" w:left="1021" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>'
           '</w:body></w:document>')
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
              '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Malgun Gothic" w:hAnsi="Malgun Gothic" w:eastAsia="Malgun Gothic" w:cs="Malgun Gothic"/>'
              '<w:sz w:val="20"/><w:lang w:val="ko-KR" w:eastAsia="ko-KR"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
              '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
              '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="160"/></w:pPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
              '<w:pPr><w:keepNext/><w:spacing w:before="320" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr></w:style>'
              '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
              '<w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr></w:style>'
              '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>'
              '</w:styles>')
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
          '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    drels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)
        z.writestr("word/_rels/document.xml.rels", drels)
        z.writestr("word/styles.xml", styles)
    return buf.getvalue()
