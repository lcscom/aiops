"""운영 리포트 · Prometheus 메트릭 · 정기 작업(리포트 발송, DB 백업, 보존기간 정리).

리포트   일간/주간/임의 기간 — 수집량, 이상징후(심각도·소스·카테고리), 인시던트(MTTA·MTTR·SLA 위반), 상위 호스트,
         반복 패턴, 수집 현황 문제, AI 요약(선택). 단일 HTML(인쇄·PDF 저장 가능)로 data/reports 에 보관, 메일 발송.
메트릭   /metrics (Prometheus text format 0.0.4) — 토큰(scope=metrics) 또는 허용 IP
"""
from __future__ import annotations

import asyncio
import html
import json
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

SEV_ORDER = ["critical", "error", "warning", "info", "debug"]
SEV_COLOR = {"critical": "#c21d00", "error": "#d45500", "warning": "#a36500", "info": "#0072a3", "debug": "#8c8c8c"}


class Reporter:
    def __init__(self, engine):
        self.e = engine
        self.dir = Path(engine.cfg["server"]["db_path"]).parent / "reports"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._done: set[str] = set()

    # ------------------------------------------------------------------ 집계
    async def stats(self, since: float, until: float) -> dict[str, Any]:
        st = self.e.store
        ev_src = await st.q("SELECT source, severity, COUNT(*) n FROM logs WHERE ts BETWEEN ? AND ? GROUP BY source, severity", (since, until))
        an = await st.q("SELECT severity, json_extract(body,'$.event.source') src, json_extract(body,'$.category') cat, "
                        "json_extract(body,'$.event.host') host, json_extract(body,'$.ai.is_anomaly') ia, "
                        "json_extract(body,'$.count') cnt, json_extract(body,'$.title') title FROM anomalies WHERE created BETWEEN ? AND ?",
                        (since, until))
        tmpl = await st.q("SELECT template, source, COUNT(*) n, MAX(severity) sev FROM logs WHERE ts BETWEEN ? AND ? AND score >= ? "
                          "GROUP BY template, source ORDER BY n DESC LIMIT 10",
                          (since, until, float(self.e.cfg["detection"].get("llm_threshold", 0.5))))
        inc = await self.e.incidents.metrics(since, until)
        top_inc = await st.q("SELECT id,title,severity,status,created,acknowledged_at,resolved_at,assignee FROM incidents "
                             "WHERE created BETWEEN ? AND ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 ELSE 2 END, created DESC LIMIT 15",
                             (since, until))
        events_by_source: dict[str, dict[str, int]] = {}
        for r in ev_src:
            events_by_source.setdefault(r["source"], {})[r["severity"]] = r["n"]
        a_sev: dict[str, int] = {}
        a_src: dict[str, int] = {}
        a_cat: dict[str, int] = {}
        hosts: dict[str, int] = {}
        false_pos = 0
        for r in an:
            if r["ia"] == 0:
                false_pos += 1
                continue
            a_sev[r["severity"]] = a_sev.get(r["severity"], 0) + 1
            a_src[r["src"] or "-"] = a_src.get(r["src"] or "-", 0) + 1
            a_cat[r["cat"] or "-"] = a_cat.get(r["cat"] or "-", 0) + 1
            if r["host"]:
                hosts[r["host"]] = hosts.get(r["host"], 0) + int(r["cnt"] or 1)
        coll = self.e.collection.snapshot(self.e.connectors)
        return {"since": since, "until": until, "events_total": sum(sum(v.values()) for v in events_by_source.values()),
                "events_by_source": events_by_source, "anomalies_total": sum(a_sev.values()), "anomalies_by_severity": a_sev,
                "anomalies_by_source": dict(sorted(a_src.items(), key=lambda x: -x[1])),
                "anomalies_by_category": dict(sorted(a_cat.items(), key=lambda x: -x[1])), "ai_false_positive": false_pos,
                "top_hosts": sorted(hosts.items(), key=lambda x: -x[1])[:10], "recurring": tmpl, "incidents": inc,
                "incident_list": top_inc,
                "collection_problems": [r for r in coll["items"] if r["status"] in ("delayed", "stopped", "down", "never")][:30],
                "collection_summary": coll["summary"]}

    # ------------------------------------------------------------------ HTML
    def render(self, title: str, s: dict, ai: str = "") -> str:
        e = html.escape
        fmt = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "-"     # noqa: E731
        sev_cells = "".join(f'<div class="k"><span>{x}</span><b style="color:{SEV_COLOR[x]}">{s["anomalies_by_severity"].get(x, 0):,}</b></div>'
                            for x in ("critical", "error", "warning"))
        inc = s["incidents"]
        rows_src = "".join(f"<tr><td>{e(src)}</td>" + "".join(f"<td class=r>{v.get(x, 0):,}</td>" for x in SEV_ORDER) +
                           f"<td class=r><b>{sum(v.values()):,}</b></td></tr>"
                           for src, v in sorted(s["events_by_source"].items(), key=lambda kv: -sum(kv[1].values())))
        bar = lambda d: "".join(f'<tr><td>{e(str(k))}</td><td class=r>{v:,}</td><td><div class=bar style="width:{int(v / max(d.values()) * 100) if d else 0}%"></div></td></tr>'   # noqa: E731
                                for k, v in list(d.items())[:10])
        incs = "".join(f"<tr><td>{e(r['id'])}</td><td><span class=sev style='color:{SEV_COLOR.get(r['severity'], '#565656')}'>{r['severity']}</span></td>"
                       f"<td>{e(r['title'] or '')}</td><td>{e(r['status'])}</td><td>{e(r['assignee'] or '-')}</td><td>{fmt(r['created'])}</td>"
                       f"<td class=r>{round((r['acknowledged_at'] - r['created']) / 60) if r['acknowledged_at'] else '-'}</td>"
                       f"<td class=r>{round((r['resolved_at'] - r['created']) / 60) if r['resolved_at'] else '-'}</td></tr>" for r in s["incident_list"])
        rec = "".join(f"<tr><td>{e(r['source'])}</td><td class=mono>{e((r['template'] or '')[:160])}</td><td class=r>{r['n']:,}</td></tr>" for r in s["recurring"])
        coll = "".join(f"<tr><td>{e(r['label'])}</td><td>{e(r['name'])}</td><td>{e(r['kind'])}</td><td>{e(r['reason'])}</td></tr>" for r in s["collection_problems"])
        hosts = "".join(f"<tr><td>{e(h)}</td><td class=r>{n:,}</td></tr>" for h, n in s["top_hosts"])
        ai_html = f'<section><h2>AI 요약 <small>Gemma 4 31B · Private AI</small></h2><div class="ai">{e(ai).replace(chr(10), "<br>")}</div></section>' if ai else ""
        return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>
body{{margin:0;background:#fafafa;color:#313131;font:14px/1.5 Calibri,"Pretendard Variable",Pretendard,"Malgun Gothic",sans-serif}}
header{{background:#1b2a32;color:#fafafa;padding:16px 28px}}header h1{{margin:0;font-size:20px;font-weight:600}}header p{{margin:4px 0 0;color:#c8d6de;font-size:13px}}
main{{padding:18px 28px;max-width:1200px}}section{{background:#fff;border:1px solid #dcdcdc;border-radius:3px;padding:12px 16px;margin-bottom:14px}}
h2{{font-size:16px;font-weight:600;margin:0 0 10px}}h2 small{{color:#8c8c8c;font-weight:400;font-size:12px}}
.kpis{{display:flex;flex-wrap:wrap;gap:10px}}.k{{border:1px solid #dcdcdc;border-radius:3px;padding:6px 12px;min-width:120px;background:#fff}}
.k span{{display:block;font-size:11px;color:#8c8c8c;text-transform:uppercase}}.k b{{font-size:22px;font-weight:300}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid #ebebeb;vertical-align:top}}
th{{background:#fafafa;font-weight:600;font-size:12px}}.r{{text-align:right;font-variant-numeric:tabular-nums}}.mono{{font-family:Consolas,monospace;font-size:12px}}
.bar{{height:10px;background:#0072a3;border-radius:2px}}.sev{{font-weight:700;text-transform:uppercase;font-size:11px}}
.ai{{background:#e3f5fc;border-left:3px solid #0072a3;padding:10px 12px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
@media print{{body{{background:#fff}}section{{break-inside:avoid}}}}@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}}
</style></head><body><header><h1>{e(title)}</h1><p>VMware Cloud Foundation · AIOps — 기간 {fmt(s['since'])} ~ {fmt(s['until'])} · 생성 {fmt(time.time())}</p></header><main>
<section><h2>요약 지표</h2><div class="kpis">
<div class="k"><span>수집 이벤트</span><b>{s['events_total']:,}</b></div><div class="k"><span>이상 징후</span><b>{s['anomalies_total']:,}</b></div>{sev_cells}
<div class="k"><span>AI 오탐 판정</span><b>{s['ai_false_positive']:,}</b></div>
<div class="k"><span>인시던트</span><b>{inc['total']:,}</b></div><div class="k"><span>미해결</span><b>{inc['active']:,}</b></div>
<div class="k"><span>MTTA(분)</span><b>{inc['mtta_min'] if inc['mtta_min'] is not None else '-'}</b></div>
<div class="k"><span>MTTR(분)</span><b>{inc['mttr_min'] if inc['mttr_min'] is not None else '-'}</b></div>
<div class="k"><span>SLA 위반</span><b style="color:{'#c21d00' if inc['sla_breaches'] else '#313131'}">{inc['sla_breaches']:,}</b></div>
</div></section>{ai_html}
<section><h2>인시던트</h2><table><tr><th>ID</th><th>심각도</th><th>제목</th><th>상태</th><th>담당</th><th>발생</th><th class=r>접수(분)</th><th class=r>해결(분)</th></tr>{incs or '<tr><td colspan=8>없음</td></tr>'}</table></section>
<div class="grid"><section><h2>이상 징후 — 소스별</h2><table>{bar(s['anomalies_by_source']) or '<tr><td>없음</td></tr>'}</table></section>
<section><h2>이상 징후 — 유형별</h2><table>{bar(s['anomalies_by_category']) or '<tr><td>없음</td></tr>'}</table></section></div>
<div class="grid"><section><h2>이상 징후 상위 호스트</h2><table><tr><th>호스트</th><th class=r>건수</th></tr>{hosts or '<tr><td colspan=2>없음</td></tr>'}</table></section>
<section><h2>수집 현황 문제 <small>보고 시점</small></h2><table><tr><th>상태</th><th>항목</th><th>유형</th><th>사유</th></tr>{coll or '<tr><td colspan=4>문제 없음</td></tr>'}</table></section></div>
<section><h2>반복 이상 패턴 상위 10</h2><table><tr><th>소스</th><th>템플릿</th><th class=r>건수</th></tr>{rec or '<tr><td colspan=3>없음</td></tr>'}</table></section>
<section><h2>소스별 수집량</h2><table><tr><th>소스</th>{''.join(f'<th class=r>{x}</th>' for x in SEV_ORDER)}<th class=r>합계</th></tr>{rows_src}</table></section>
</main></body></html>"""

    async def extended(self, since: float, until: float) -> dict[str, Any]:
        """월간·경영 요약용 — 정산 합계·용량 예측·VM 적정화·보안 판독(있는 것만, 실패해도 리포트는 만들어짐)"""
        out: dict[str, Any] = {}
        for key, fn in (("billing", lambda: self.e.billing.report(since, until, "기간", vm_detail=False)),
                        ("capacity", lambda: self.e.capacity.overview()),
                        ("rightsizing", lambda: self.e.capacity.rightsizing()),
                        ("assessment", lambda: self.e.assess.latest())):
            try:
                out[key] = await asyncio.wait_for(fn(), 60)
            except Exception as e:  # noqa: BLE001
                out[key] = {"error": f"{type(e).__name__}: {e}"[:160]}
        try:                                                  # 2.37.0 수명 주기 — 30일 안 만료 인증서·기간 중 구성 변경·지원 종료 1년 안 버전
            life: dict[str, Any] = {}
            cs = getattr(getattr(self.e, "certs", None), "last", None) or {}
            life["certs"] = [x for x in cs.get("items") or [] if x.get("days_left") is not None and x["days_left"] < 30 and x.get("band") != "auto"][:30]
            life["certs_scanned"] = bool(cs.get("ts"))
            dw = getattr(self.e, "driftwatch", None)
            if dw:
                await dw.ensure()
                life["drift"] = [dict(r) for r in await self.e.store.q(
                    "SELECT ts, vcenter, entity, label, before, after, severity FROM drift_changes WHERE ts >= ? AND ts < ? ORDER BY ts DESC LIMIT 40", (since, until))]
            from .lifecycle import Lifecycle
            vr = await asyncio.wait_for(Lifecycle(self.e).report(), 60)
            life["versions"] = [r for r in vr["rows"] if r["state"] in ("ended", "soon")][:30]
            out["lifecycle"] = life
        except Exception as e:  # noqa: BLE001
            out["lifecycle"] = {"error": f"{type(e).__name__}: {e}"[:160]}
        sn = getattr(self.e, "sensors", None)                 # 2.54.0 현장 센서 환경 요약(등록된 폰이 있을 때만)
        if sn is not None:
            try:
                sm = await asyncio.wait_for(sn.summary(since, until), 60)
                if sm["items"]:
                    out["sensors"] = sm
            except Exception as e:  # noqa: BLE001
                out["sensors"] = {"error": f"{type(e).__name__}: {e}"[:160]}
        return out

    @staticmethod
    def render_extended(x: dict) -> str:
        e = html.escape
        n = lambda v, d=0: "-" if v is None else f"{v:,.{d}f}"   # noqa: E731
        parts = []
        b = x.get("billing") or {}
        if b.get("tenants") is not None:
            rows = "".join(f"<tr><td>{e(t['name'])}</td><td class=r>{t['vms']}</td><td class=r>{n(t['vcpu_hours'])}</td><td class=r>{n(t['mem_gb_hours'])}</td><td class=r>{n(t['disk_gb_hours'])}</td><td class=r><b>{n(t['cost'])}</b></td></tr>" for t in b["tenants"])
            parts.append(f"<section><h2>정산 <small>{e(b['currency'])} · 미할당 VM {b['totals']['unassigned_vms']}</small></h2><table><tr><th>테넌트</th><th class=r>VM</th><th class=r>vCPU·h</th><th class=r>메모리 GB·h</th><th class=r>디스크 GB·h</th><th class=r>비용</th></tr>{rows or '<tr><td colspan=6>테넌트 없음</td></tr>'}"
                         f"<tr><th>합계</th><th class=r>{b['totals']['vms']}</th><th class=r>{n(b['totals']['vcpu_hours'])}</th><th class=r>{n(b['totals']['mem_gb_hours'])}</th><th class=r>{n(b['totals']['disk_gb_hours'])}</th><th class=r>{n(b['totals']['cost'])}</th></tr></table></section>")
        c = x.get("capacity") or {}
        if c.get("items") is not None:
            items = sorted(c["items"], key=lambda r: ({"down": 0, "warn": 1}.get(r["state"], 2), r["name"]))[:30]
            rows = "".join(f"<tr><td>{e(r['kind'])}</td><td>{e(r['name'])}</td><td class=r>{n(r.get('cpu') if r['kind'] == 'cluster' else r.get('disk'), 1)}%</td><td class=r>{n(r.get('mem'), 1) + '%' if r['kind'] == 'cluster' else '-'}</td>"
                           f"<td class=r>{('+' if (r['forecast']['slope'] or 0) > 0 else '') + n(r['forecast']['slope'], 2) if r['forecast']['slope'] is not None else '-'}</td>"
                           f"<td class=r>{r['forecast']['days_to'].get('90') if r['forecast']['days_to'].get('90') is not None else '-'}</td><td class=r>{n(r['forecast']['p90'], 0)}%</td></tr>" for r in items)
            parts.append(f"<section><h2>용량 예측 <small>최근 {c['days']}일 추세 · 위험 {c['summary']['down']} · 주의 {c['summary']['warn']} · 90일 내 90% 도달 {c['summary']['soon']}</small></h2>"
                         f"<table><tr><th>유형</th><th>이름</th><th class=r>CPU/디스크 %</th><th class=r>메모리 %</th><th class=r>%/일</th><th class=r>90% 도달(일)</th><th class=r>90일 뒤</th></tr>{rows or '<tr><td colspan=7>표본 없음</td></tr>'}</table></section>")
        rs = x.get("rightsizing") or {}
        if rs.get("summary"):
            S = rs["summary"]
            top = "".join(f"<tr><td>{e(k)}</td><td>{e(v['vm'])}</td><td>{v['vcpu']} vCPU · {n(v['mem_gb'], 1)} GB</td><td>{n(v.get('peak_cpu'), 0)}% / {n(v.get('peak_mem'), 0)}%</td><td>{(str(v.get('rec_vcpu')) + ' vCPU · ' + n(v.get('rec_mem_gb'), 0) + ' GB') if v.get('rec_vcpu') else '-'}</td><td class=r>{n(v.get('saving'))}</td></tr>"
                          for k, lst in (("과다", rs["oversized"][:8]), ("유휴", rs["idle"][:5]), ("과소", rs["undersized"][:5])) for v in lst)
            parts.append(f"<section><h2>VM 적정화 <small>최근 {rs['days']}일 · 과다 {S['oversized']} · 과소 {S['undersized']} · 유휴 {S['idle']} · 장기 꺼짐 {S['powered_off']} · 회수 가능 vCPU {n(S['reclaim_vcpu'])} · 메모리 {n(S['reclaim_mem_gb'])} GB · 월 절감 추정 {n(S['saving_month'])} {e(rs.get('currency') or '')}</small></h2>"
                         f"<table><tr><th>구분</th><th>VM</th><th>현재</th><th>피크 CPU/메모리</th><th>권장</th><th class=r>월 절감</th></tr>{top or '<tr><td colspan=6>해당 없음</td></tr>'}</table></section>")
        a = x.get("assessment") or {}
        if a.get("summary"):
            s = a["summary"]
            fails = [r for r in a.get("rows", []) if r["status"] == "FAIL"]
            by = {}
            for r in fails:
                by.setdefault((r["id"], r["title"]), []).append(r["target"])
            rows = "".join(f"<tr><td>{e(k[0])}</td><td>{e(k[1])}</td><td class=r>{len(v)}</td><td>{e(', '.join(v[:6]))}{' …' if len(v) > 6 else ''}</td></tr>" for k, v in sorted(by.items(), key=lambda kv: -len(kv[1]))[:20])
            cve = "".join(f"<tr><td>{e(r['id'])}</td><td>{e(r['severity'])}</td><td>{e(r['target'])}</td><td>{e(r['verdict'])}</td><td>{e(r['why'][:100])}</td></tr>" for r in a.get("cve", [])[:15])
            ch = s.get("changes") or {}
            parts.append(f"<section><h2>보안 판독 <small>점검 {datetime.fromtimestamp(s['ts']).strftime('%Y-%m-%d %H:%M')} · 준수율 {s['score'] if s['score'] is not None else '-'}% · FAIL {s['counts']['FAIL']} · WARN {s['counts']['WARN']} · VMSA 취약 {s['cve']['vulnerable']} · 가능 {s['cve']['possible']} · 구성 변경 {ch.get('total', 0)}(악화 {ch.get('worse', 0)})</small></h2>"
                         f"<table><tr><th>ID</th><th>항목</th><th class=r>대상 수</th><th>대상</th></tr>{rows or '<tr><td colspan=4>미흡 항목 없음</td></tr>'}</table>"
                         + (f"<table style='margin-top:8px'><tr><th>CVE/권고</th><th>심각도</th><th>대상</th><th>판정</th><th>근거</th></tr>{cve}</table>" if cve else "") + "</section>")
        lf = x.get("lifecycle") or {}
        if lf and not lf.get("error"):
            cr = "".join(f"<tr><td>{datetime.fromtimestamp(c['not_after']).strftime('%Y-%m-%d') if c.get('not_after') else '-'}</td><td class=r><b>{c['days_left']}</b></td>"
                         f"<td>{e(c['kind'])}</td><td>{e(c['name'])}</td><td>{e(c['system'])}{(' / ' + e(c['cluster'])) if c.get('cluster') else ''}</td></tr>" for c in lf.get("certs") or [])
            dr_ = "".join(f"<tr><td>{datetime.fromtimestamp(d['ts']).strftime('%m-%d %H:%M')}</td><td>{e(d['entity'])}</td><td>{e(d['label'])}</td><td>{e(str(d['before']))} → <b>{e(str(d['after']))}</b></td></tr>"
                          for d in lf.get("drift") or [])
            vr = "".join(f"<tr><td>{e(v['product'])}</td><td>{e(v.get('scope') or '')}</td><td>{e(v['version'])}</td><td>{e(v.get('eogs') or '-')}</td><td class=r>{v.get('days_left') if v.get('days_left') is not None else '-'}</td></tr>"
                         for v in lf.get("versions") or [])
            parts.append("<section><h2>수명 주기 <small>30일 안 만료 인증서 · 이 기간 구성 변경 · 지원 종료 1년 안 버전</small></h2>"
                         + (f"<table><tr><th>만료일</th><th class=r>남은 일</th><th>종류</th><th>대상</th><th>시스템</th></tr>{cr}</table>" if cr else
                            f"<p>{'30일 안에 만료되는 인증서가 없습니다.' if lf.get('certs_scanned') else '인증서 스캔 전입니다.'}</p>")
                         + (f"<table style='margin-top:8px'><tr><th>시각</th><th>대상</th><th>항목</th><th>변경</th></tr>{dr_}</table>" if dr_ else "<p>이 기간 기록된 구성 변경이 없습니다.</p>")
                         + (f"<table style='margin-top:8px'><tr><th>구성요소</th><th>범위</th><th>버전</th><th>지원 종료</th><th class=r>남은 일</th></tr>{vr}</table>" if vr else "")
                         + "</section>")
        sn = x.get("sensors") or {}
        if sn.get("items"):
            t = sn["totals"]
            st = lambda it, m: (lambda v: "-" if not v else f"{v['min']:g} / {v['avg']:g} / <b>{v['max']:g}</b>")((it.get("stats") or {}).get(m))  # noqa: E731
            rows = "".join(f"<tr><td>{e(it['site'] or '-')}</td><td>{e(it['name'])}{' <small>(배터리 추정)</small>' if it['temp_src'] == 'battery' else ''}</td>"
                           f"<td class=r>{st(it, 'temp_c')}</td><td class=r>{st(it, 'humidity')}</td><td class=r>{st(it, 'sound_db')}</td>"
                           f"<td class=r>{it['temp_over_min'] if it['temp_warn_hi'] is not None else '-'}</td><td class=r>{it['coverage']:g}%</td>"
                           f"<td class=r>{it['alerts']['critical']}</td><td class=r>{it['alerts']['warning']}</td></tr>" for it in sn["items"][:60])
            parts.append(f"<section><h2>현장 센서 환경 <small>폰 {t['devices']}대 · 위험 {t['critical']} · 경고 {t['warning']} · 온도 경고 상한 이상 {t['temp_over_min']}분 · 수신율 90% 미만 {t['low_coverage']}대</small></h2>"
                         f"<table><tr><th>사이트</th><th>장치</th><th class=r>온도 °C 최저/평균/최고</th><th class=r>습도 %</th><th class=r>소리 dB</th><th class=r>온도 상한 이상(분)</th><th class=r>수신율</th><th class=r>위험</th><th class=r>경고</th></tr>{rows}</table></section>")
        return "".join(parts)

    @staticmethod
    def render_vm_activity(v: dict) -> str:
        """VM 액티비티 — 생성·삭제 순증감, 분류별 건수, 위험 신호·업무 외 변경 상위, 사용자 상위(사람)"""
        e = html.escape
        if not v or v.get("error"):
            return f"<section><h2>VM 액티비티</h2><p>집계 실패: {e(str((v or {}).get('error', '')))}</p></section>"
        L, F = v["labels"], v["flag_labels"]
        cats = " · ".join(f"{e(v['cats'][k])} {v['by_cat'].get(k, 0):,}" for k in ("create", "delete", "move", "ha", "config", "power", "fail"))
        net = v["created_total"] - v["deleted_total"]
        row = lambda r: (f"<tr><td>{datetime.fromtimestamp(r['ts']).strftime('%m-%d %H:%M')}</td><td>{e(L.get(r['type'], r['type']))}</td><td>{e(r['vm'])}</td>"   # noqa: E731
                         f"<td>{e(r['user'] or '-')}</td><td>{e(', '.join(F.get(f, f) for f in sorted(str(r.get('flags') or '').split(',')) if f))}</td><td>{e(r.get('detail') or r.get('source') or '')}</td></tr>")
        risks = "".join(row(r) for r in v["risks"][:15])
        offh = "".join(row(r) for r in v["offhours"][:10])
        people = [a for a in v["actors"] if not a["service"]][:10]
        act = "".join(f"<tr><td>{e(a['user'])}</td><td class=r>{a['total']:,}</td><td class=r>{a['cats'].get('create', 0)}</td><td class=r>{a['cats'].get('delete', 0)}</td>"
                      f"<td class=r>{a['cats'].get('config', 0)}</td><td class=r>{a['offhours']}</td><td class=r>{a['risk']}</td></tr>" for a in people)
        hd = "<tr><th>시각</th><th>유형</th><th>VM</th><th>사용자</th><th>표시</th><th>내용</th></tr>"
        return (f"<section><h2>VM 액티비티 <small>총 {v['total']:,}건 · {cats} · 순증감 {'+' if net >= 0 else ''}{net:,}대 · 위험 신호 {v['risk_total']:,} · 업무 외 변경 {v['offhours_total']:,}</small></h2>"
                f"<h3>위험 신호</h3><table>{hd}{risks or '<tr><td colspan=6>없음</td></tr>'}</table>"
                f"<h3>업무 외 시간 변경</h3><table>{hd}{offh or '<tr><td colspan=6>없음</td></tr>'}</table>"
                f"<h3>사용자(사람) 상위</h3><table><tr><th>사용자</th><th class=r>건수</th><th class=r>생성</th><th class=r>삭제</th><th class=r>구성·스냅샷</th><th class=r>업무 외</th><th class=r>위험</th></tr>{act or '<tr><td colspan=7>없음</td></tr>'}</table></section>")

    async def generate(self, kind: str, since: float, until: float, user: str = "system") -> dict[str, Any]:
        s = await self.stats(since, until)
        label = {"daily": "일간", "weekly": "주간", "monthly": "월간"}.get(kind, "기간")
        title = f"VCF AIops {label} 운영 리포트 {datetime.fromtimestamp(until).strftime('%Y-%m-%d')}"
        ext_html = ""
        if kind in ("weekly", "monthly", "custom") and (self.e.cfg.get("reports") or {}).get("extended", True):
            try:
                ext_html = self.render_extended(await self.extended(since, until))
            except Exception as e:  # noqa: BLE001
                ext_html = f"<section><h2>확장 집계</h2><p>실패: {html.escape(type(e).__name__)}</p></section>"
        va = None
        if (self.e.cfg.get("reports") or {}).get("vm_activity", True) and getattr(self.e, "moves", None):
            try:
                va = await asyncio.wait_for(self.e.moves.summary(max(1.0, min((until - since) / 3600, 24 * 30))), 30)
            except Exception as ex:  # noqa: BLE001
                va = {"error": f"{type(ex).__name__}: {ex}"[:160]}
        ai = ""
        if self.e.llm and (self.e.cfg.get("reports") or {}).get("ai_summary", True):
            try:
                brief = {k: s[k] for k in ("events_total", "anomalies_total", "anomalies_by_severity", "anomalies_by_source",
                                           "anomalies_by_category", "top_hosts", "incidents", "collection_summary")}
                brief["incident_titles"] = [f"{r['severity']} {r['title']} ({r['status']})" for r in s["incident_list"][:10]]
                if va and not va.get("error"):
                    brief["vm_activity"] = {k: va.get(k) for k in ("total", "created_total", "deleted_total", "move_total", "ha_total", "config_total",
                                                                  "power_total", "fail_total", "offhours_total", "risk_total", "risk_counts")}
                names = {str(h) for h, _ in s["top_hosts"] if h}                 # 2.30.0 외부 공급자 가명화 대상(상위 호스트 + 인시던트 제목에 나오는 개체)
                ids = [r["id"] for r in s["incident_list"][:10]]
                if ids:
                    for r in await self.e.store.q(f"SELECT hosts, cluster, primary_entity FROM incidents WHERE id IN ({','.join('?' * len(ids))})", ids):
                        try:
                            names |= {str(x) for x in json.loads(r["hosts"] or "[]") if x}
                        except ValueError:
                            pass
                        names |= {str(r[k]) for k in ("cluster", "primary_entity") if r[k]}
                names = sorted(names)
                ai = await self.e.llm.complete(
                    "너는 VCF 운영 보고서 작성자다. 주어진 집계만 근거로 경영진·운영팀이 읽을 한국어 요약을 쓴다. "
                    "5개 이내 글머리(•)로: 전반 상태, 주요 장애와 영향, 반복 문제, 수집·운영 리스크, 권고. 수치는 입력 그대로 인용, 추정 금지.",
                    json.dumps(brief, ensure_ascii=False, default=str), max_tokens=700, task="report",
                    names=names)
            except Exception as e:  # noqa: BLE001
                ai = f"(AI 요약 생성 실패: {type(e).__name__})"
        body = self.render(title, s, ai)
        if va is not None:
            ext_html = self.render_vm_activity(va) + ext_html
        if ext_html:
            body = body.replace("</main></body></html>", ext_html + "</main></body></html>")
        name = f"{kind}-{datetime.fromtimestamp(until).strftime('%Y%m%d-%H%M')}.html"
        (self.dir / name).write_text(body, encoding="utf-8")
        await self.e.audit.log("report.generate", user=user, target=name, detail={"kind": kind, "since": since, "until": until})
        return {"name": name, "title": title, "size": len(body), "html": body}

    def list(self) -> list[dict]:
        return sorted([{"name": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime} for p in self.dir.glob("*.html")],
                      key=lambda x: -x["mtime"])

    async def email(self, rep: dict, recipients: list[str]) -> None:
        smtp = (self.e.cfg.get("alerting") or {}).get("smtp") or {}
        if not smtp.get("enabled") or not recipients:
            return
        if getattr(self.e, "ha", None) and not self.e.ha.is_leader():    # 이중화: 알림 리더만 정기 리포트 메일 발송
            return

        def send():
            msg = MIMEMultipart("mixed")
            msg["Subject"] = rep["title"]
            msg["From"] = smtp["from"]
            msg["To"] = ", ".join(recipients)
            alt = MIMEMultipart("alternative")
            alt.attach(MIMEText(rep["html"], "html", "utf-8"))
            msg.attach(alt)
            att = MIMEApplication(rep["html"].encode("utf-8"), Name=rep["name"])
            att["Content-Disposition"] = f'attachment; filename="{rep["name"]}"'
            msg.attach(att)
            with smtplib.SMTP(smtp["host"], int(smtp.get("port", 25)), timeout=30) as c:
                if smtp.get("starttls"):
                    c.starttls()
                if smtp.get("username"):
                    c.login(smtp["username"], smtp["password"])
                c.sendmail(smtp["from"], recipients, msg.as_string())
        await asyncio.to_thread(send)

    # ------------------------------------------------------------------ 정기 작업
    async def scheduler(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                now = datetime.now()
                hm = now.strftime("%H:%M")
                rc = self.e.cfg.get("reports") or {}
                d = rc.get("daily") or {}
                key = f"daily:{now:%Y%m%d}"
                if d.get("enabled") and hm == d.get("time", "08:30") and key not in self._done:
                    self._done.add(key)
                    end = now.replace(second=0, microsecond=0).timestamp()
                    rep = await self.generate("daily", end - 86400, end)
                    await self.email(rep, d.get("recipients") or [])
                m = rc.get("monthly") or {}
                key = f"monthly:{now:%Y%m}"
                if m.get("enabled") and now.day == int(m.get("day", 1)) and hm == m.get("time", "08:50") and key not in self._done:
                    self._done.add(key)
                    end = now.replace(second=0, microsecond=0).timestamp()
                    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    prev_end = first.timestamp()
                    prev_start = (first - timedelta(days=1)).replace(day=1).timestamp()
                    rep = await self.generate("monthly", prev_start, prev_end)
                    await self.email(rep, m.get("recipients") or [])
                w = rc.get("weekly") or {}
                key = f"weekly:{now:%Y%W}"
                if w.get("enabled") and now.weekday() == int(w.get("weekday", 0)) and hm == w.get("time", "08:40") and key not in self._done:
                    self._done.add(key)
                    end = now.replace(second=0, microsecond=0).timestamp()
                    rep = await self.generate("weekly", end - 7 * 86400, end)
                    await self.email(rep, w.get("recipients") or [])
                b = self.e.cfg.get("backup") or {}
                key = f"backup:{now:%Y%m%d}"
                if b.get("enabled", True) and hm == b.get("time", "02:30") and key not in self._done:
                    self._done.add(key)
                    await self.backup("system")
                    await self.e.audit.purge()
                    keep = time.time() - float(rc.get("keep_days", 180)) * 86400
                    for p in self.dir.glob("*.html"):
                        if p.stat().st_mtime < keep:
                            p.unlink(missing_ok=True)
            except Exception as e:  # noqa: BLE001
                print(f"[scheduler] 오류: {type(e).__name__}: {e}", flush=True)

    async def backup(self, user: str) -> dict:
        b = self.e.cfg.get("backup") or {}
        d = Path(b.get("dir", "data/backup"))
        dest = d / f"aiops-{datetime.now():%Y%m%d-%H%M}.db"
        size = await self.e.store.backup(str(dest))
        files = sorted(d.glob("aiops-*.db"), key=lambda p: p.stat().st_mtime)
        for old in files[:-int(b.get("keep", 14))]:
            old.unlink(missing_ok=True)
        await self.e.audit.log("backup.run", user=user, target=dest.name, detail={"size": size})
        return {"file": dest.name, "size": size}

    def backups(self) -> list[dict]:
        d = Path((self.e.cfg.get("backup") or {}).get("dir", "data/backup"))
        return sorted([{"name": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime} for p in d.glob("aiops-*.db")],
                      key=lambda x: -x["mtime"]) if d.exists() else []

    # ------------------------------------------------------------------ Prometheus
    def metrics_text(self) -> str:
        e = self.e
        L: list[str] = []

        def m(name: str, typ: str, helptext: str, samples: list[tuple[dict, float]]):
            L.append(f"# HELP {name} {helptext}")
            L.append(f"# TYPE {name} {typ}")
            for labels, v in samples:
                lab = ",".join(f'{k}="{str(val).replace(chr(34), "")}"' for k, val in labels.items())
                L.append(f"{name}{{{lab}}} {v}" if lab else f"{name} {v}")
        m("aiops_events_total", "counter", "Ingested events", [({}, e.stats["events_total"])])
        m("aiops_events_per_second", "gauge", "Ingest rate (last second)", [({}, e.stats["eps"])])
        m("aiops_anomalies_total", "counter", "Anomalies raised", [({}, e.stats["anomalies_total"])])
        open_by: dict[str, int] = {}
        for a in e.anomalies.values():
            if not a.ack and (a.ai or {}).get("is_anomaly") is not False:
                open_by[a.severity] = open_by.get(a.severity, 0) + 1
        m("aiops_anomalies_open", "gauge", "Unacknowledged anomalies", [({"severity": k}, v) for k, v in open_by.items()] or [({"severity": "none"}, 0)])
        m("aiops_incidents_active", "gauge", "Active incidents", [({"severity": k}, v) for k, v in e.incidents_active.items()] or [({"severity": "none"}, 0)])
        m("aiops_connector_up", "gauge", "Connector state (1=ok)",
          [({"name": c.name, "type": c.type}, 1 if c.state().get("state") == "ok" else 0) for c in e.connectors])
        m("aiops_connector_latency_ms", "gauge", "Last poll latency",
          [({"name": c.name}, c.state().get("latency_ms") or 0) for c in e.connectors])
        cs = e.collection.summary()
        m("aiops_collection_items", "gauge", "Collection items by status", [({"status": k}, v) for k, v in cs["summary"].items()])
        llm = e.llm.status if e.llm else {}
        m("aiops_llm_up", "gauge", "LLM endpoint state (1=ok)", [({"model": llm.get("model", "")}, 1 if llm.get("state") == "ok" else 0)])
        m("aiops_llm_latency_ms", "gauge", "LLM last latency", [({}, llm.get("latency_ms") or 0)])
        m("aiops_llm_queue", "gauge", "LLM analysis queue length", [({}, e.llm_q.qsize())])
        m("aiops_alerts_sent_total", "counter", "Alerts sent", [({}, e.alerter.sent_total)])
        m("aiops_rag_chunks_loaded", "gauge", "RAG chunks loaded", [({}, sum(len(p.chunks) for p in e.rag.loaded.values()))])
        # ---- 런타임 안정성 지표
        lag = e.lag.stats()
        m("aiops_loop_lag_ms", "gauge", "Event loop lag", [({"q": "p50"}, lag["p50_ms"]), ({"q": "p99"}, lag["p99_ms"]), ({"q": "max"}, lag["max_ms"])])
        p = e.pipe
        m("aiops_pipeline_queue", "gauge", "Pipeline queue depth", [({"queue": "high"}, len(e.q_hi)), ({"queue": "low"}, len(e.q_lo)),
                                                                    ({"queue": "publish"}, len(e._pub))])
        m("aiops_pipeline_dropped_total", "counter", "Events dropped before processing", [({"queue": "high"}, p["dropped_high"]), ({"queue": "low"}, p["dropped_low"])])
        m("aiops_pipeline_errors_total", "counter", "Pipeline processing errors", [({}, p["errors"])])
        m("aiops_pipeline_lag_ms", "gauge", "Ingest-to-process lag of last event", [({}, p["lag_ms"])])
        st = e.store.stats
        m("aiops_store_backlog", "gauge", "DB write-behind backlog", [({}, e.store.backlog)])
        m("aiops_store_write_errors_total", "counter", "DB write errors", [({}, st["write_errors"])])
        m("aiops_store_logs_dropped_total", "counter", "Raw logs not stored (queue full / disk low)", [({"reason": "queue"}, st["logs_dropped"]), ({"reason": "disk"}, st["logs_skipped_disk"])])
        m("aiops_store_batch_ms", "gauge", "Last DB batch commit time", [({}, st["last_batch_ms"])])
        m("aiops_disk_free_mb", "gauge", "Free disk at DB volume", [({}, st["disk_free_mb"] or 0)])
        h = e.hub.stats
        m("aiops_ws_clients", "gauge", "Connected realtime clients", [({}, len(e.hub))])
        m("aiops_ws_kicked_total", "counter", "Realtime clients disconnected by server", [({"reason": "slow"}, h["kicked_slow"]), ({"reason": "dead"}, h["kicked_dead"])])
        m("aiops_ws_dropped_flow_total", "counter", "Droppable realtime messages skipped for slow clients", [({}, h["dropped_flow"])])
        ob = e.alerter.ob
        m("aiops_outbox", "gauge", "Alert outbox pending", [({"state": "pending"}, ob["pending"])])
        m("aiops_outbox_total", "counter", "Alert outbox outcomes", [({"result": "sent"}, ob["sent"]), ({"result": "retry"}, ob["retry"]), ({"result": "dead"}, ob["dead"])])
        m("aiops_outbox_oldest_pending_seconds", "gauge", "Age of oldest undelivered alert", [({}, ob["oldest_pending"])])
        m("aiops_breaker_open", "gauge", "Circuit breaker open (1)", [({"name": "llm"}, 1 if e.llm_breaker.state == "open" else 0)] +
          [({"name": k}, 1 if b.state == "open" else 0) for k, b in e.alerter.breakers.items()])
        m("aiops_job_restarts_total", "counter", "Supervised job restarts", [({"job": j["name"]}, j["restarts"]) for j in e.sup.summary()])
        m("aiops_job_healthy", "gauge", "Supervised job healthy (1)", [({"job": j["name"]}, 1 if j["state"] == "running" else 0) for j in e.sup.summary()])
        if e.health:
            ok, _ = e.health.ready()
            m("aiops_ready", "gauge", "Readiness (1=ready)", [({}, 1 if ok else 0)])
        sc = getattr(e, "selfcheck", None)
        if sc:
            st = sc.state
            m("aiops_process_rss_mb", "gauge", "Process resident memory", [({}, (st["resources"] or {}).get("rss_mb") or 0)])
            m("aiops_process_open_files", "gauge", "Open file descriptors", [({}, (st["resources"] or {}).get("open_files") or 0)])
            m("aiops_db_size_mb", "gauge", "SQLite file sizes", [({"file": "db"}, (st["db"] or {}).get("db_mb") or 0), ({"file": "wal"}, (st["db"] or {}).get("wal_mb") or 0)])
            m("aiops_db_rows", "gauge", "Rows per table", [({"table": k}, v or 0) for k, v in ((st["db"] or {}).get("tables") or {}).items()] or [({"table": "none"}, 0)])
            m("aiops_db_integrity_ok", "gauge", "Last quick_check ok (1)", [({}, 1 if st["quick_check"]["result"] in ("ok", "") else 0)])
            m("aiops_backup_verified_ok", "gauge", "Latest backup integrity ok (1)", [({}, 1 if (st["backup"] or {}).get("result") in ("ok", "none", None) else 0)])
            m("aiops_backup_age_seconds", "gauge", "Age of latest backup", [({}, time.time() - st["backup"]["mtime"] if (st["backup"] or {}).get("mtime") else 0)])
            m("aiops_tls_cert_days_left", "gauge", "Days until TLS certificate expiry", [({}, (st["cert"] or {}).get("days_left") if (st["cert"] or {}).get("days_left") is not None else -1)])
            m("aiops_sessions_active", "gauge", "Active web sessions", [({}, len(getattr(getattr(e, "auth", None), "sessions", {}) or {}))])
        if e.ha:
            m("aiops_ha_leader", "gauge", "This node is alert leader (1)", [({"node": e.ha.node, "role": e.ha.role}, 1 if e.ha.leader else 0)])
        return "\n".join(L) + "\n"
