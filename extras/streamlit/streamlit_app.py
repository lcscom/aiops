"""VCF AIops — Streamlit UI (선택 구성요소 · 기본 배포에서 제외)
기본 운영 UI는 FastAPI 대시보드(app/static)이며, 이 앱은 필요 시에만 별도 실행:
  cd extras/streamlit && pip install -r requirements.txt && streamlit run streamlit_app.py
수집·탐지·LLM 엔진은 FastAPI 백엔드(app.main)가 상주 실행하고, 이 앱은 REST 폴링으로 화면만 그린다.

실행:
  uvicorn app.main:app --host 0.0.0.0 --port 8080          # 백엔드
  streamlit run streamlit_app.py                            # UI :8630 (.streamlit/config.toml)  (AIOPS_API 로 백엔드 주소 지정)
"""
from __future__ import annotations

import html
import json
import os
import time

import pandas as pd
import requests
import streamlit as st

import sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)
try:                                     # .env 의 AIOPS_API 등 적재(Windows/conda 직접 실행)
    from app.config import load_dotenv
    load_dotenv()
except Exception:  # noqa: BLE001
    pass
API = os.environ.get("AIOPS_API", "http://127.0.0.1:8080").rstrip("/")
SEV = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}
SEV_COLOR = {"critical": "#c21d00", "error": "#d45500", "warning": "#a36500", "info": "#0072a3", "debug": "#8c8c8c"}
SEV_BG = {"critical": "#fdeae6", "error": "#fff0e5", "warning": "#fef7d9", "info": "#e3f5fc", "debug": "#f4f4f4"}
SRC_COLOR = {"vcenter": "#0072a3", "esxi": "#1a5c86", "sddc": "#6a3fa0", "nsx": "#00796b", "vcfops": "#c25400",
             "vcflogs": "#8a6d00", "vcfa": "#b5197b", "srm": "#3c8500", "avi": "#00809d", "redfish": "#a3401a",
             "syslog": "#565656", "vm": "#5d3fa0", "snmp": "#4d4d4d", "network": "#00567a", "storage": "#7a5c00"}
STATUS_TXT = {"queued": "AI 분석 대기", "analyzing": "Gemma 4 분석 중…", "analyzed": "AI 분석 완료",
              "llm_error": "AI 분석 실패", "rule_only": "규칙 탐지(LLM 비활성)", "llm_skipped": "LLM 큐 초과"}
MAX_LOGS = 3000

st.set_page_config(page_title="VCF AIops", page_icon="🔷", layout="wide")
# VMware Clarity(라이트) 스타일 — 영문 Calibri, 한글 Pretendard(./static/fonts, enableStaticServing)
st.markdown("""<style>
@font-face{font-family:"Pretendard Variable";font-weight:45 920;font-display:swap;
  src:url("app/static/fonts/PretendardVariable.woff2") format("woff2-variations")}
:root{--font:Calibri,"Pretendard Variable",Pretendard,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
  --mono:Consolas,"Cascadia Mono","D2Coding","Pretendard Variable",monospace;--action:#0072a3;--line:#dcdcdc;--title:#313131}
html,body,.stApp,.stMarkdown,.stText,p,li,label,input,textarea,select,button,h1,h2,h3,h4,h5,h6,
[data-testid="stMetricValue"],[data-testid="stMetricLabel"],[data-testid="stCaptionContainer"],
[data-testid="stWidgetLabel"],[data-baseweb="tab"],[data-testid="stDataFrame"]{font-family:var(--font)!important}
header[data-testid="stHeader"]{display:none}
.block-container{padding-top:4.6rem!important;padding-bottom:0!important;max-width:100%!important}
.stApp{background:#fafafa}
/* Clarity 헤더 */
.clr-hdr{position:fixed;top:0;left:0;right:0;height:56px;z-index:999990;background:#1b2a32;color:#fafafa;
  display:flex;align-items:center;justify-content:space-between;padding:0 18px;font-family:var(--font)}
.clr-hdr .b{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;white-space:nowrap}
.clr-hdr .b svg{width:28px;height:28px}
.clr-hdr .sep{width:1px;height:24px;background:rgba(255,255,255,.3)}
.clr-hdr .app{font-weight:400;color:#c8d6de}
.clr-hdr .r{font-size:13px;color:#c8d6de}
/* 사이드바 = 세로 내비 */
section[data-testid="stSidebar"]{background:#eeeeee;border-right:1px solid var(--line);top:56px!important;height:calc(100vh - 56px)!important}
section[data-testid="stSidebar"] h3{font-weight:600;color:var(--title)}
/* 메트릭 카드 */
div[data-testid="stMetric"]{background:#fff;border:1px solid var(--line);border-radius:3px;padding:6px 12px}
div[data-testid="stMetricLabel"] p{font-size:11px!important;text-transform:uppercase;letter-spacing:.4px;color:#8c8c8c}
div[data-testid="stMetricValue"]{font-size:24px!important;font-weight:300!important;color:var(--title)}
/* 탭: Clarity 밑줄형 */
button[data-baseweb="tab"] p{font-size:14px}
div[data-baseweb="tab-highlight"]{background:var(--action)!important}
/* 버튼: Clarity outline */
.stButton>button{border:1px solid var(--action)!important;color:var(--action)!important;background:#fff!important;border-radius:3px!important;
  font-weight:600;text-transform:uppercase;letter-spacing:.4px;font-size:12px!important;min-height:30px;padding:2px 12px}
.stButton>button:hover{background:#e3f5fc!important}
.stButton>button[kind="primary"]{background:var(--action)!important;color:#fff!important}
/* 테두리 컨테이너 = Clarity 카드 */
div[data-testid="stVerticalBlockBorderWrapper"]{border-radius:3px!important;border-color:var(--line)!important;background:#fff}
h5{font-weight:400!important;color:var(--title)!important;font-size:17px!important}
.chip{display:inline-flex;align-items:center;gap:6px;padding:0 10px;margin:0 5px 5px 0;border-radius:12px;border:1px solid var(--line);
  background:#fff;font-size:12px;color:var(--title);line-height:22px;white-space:nowrap}
.chip i{width:8px;height:8px;border-radius:50%;display:inline-block}
.chip small{color:#8c8c8c;font-family:var(--mono);font-size:11px}
.lbl{display:inline-block;border:1px solid #8c8c8c;border-radius:12px;padding:0 8px;font-size:11px;line-height:18px;background:#fff;color:var(--title);margin-right:4px}
/* 로그 데이터그리드 */
.logbox{height:620px;overflow-y:auto;background:#fff;border:1px solid var(--line);border-radius:3px;font-size:13px;font-family:var(--font)}
.lh,.lr{display:grid;grid-template-columns:70px 72px 72px 190px 1fr;gap:10px;padding:3px 12px}
.lh{position:sticky;top:0;background:#fafafa;border-bottom:1px solid var(--line);font-size:12px;font-weight:600;color:var(--title);padding:6px 12px}
.lr{border-bottom:1px solid #ebebeb;color:var(--title)}
.lr:hover{background:#eef3f6}
.lr.f{box-shadow:inset 3px 0 var(--sev)}
.lr .t{color:#8c8c8c;font-family:var(--mono);font-size:12px}
.lr .h{color:#565656;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lr .m{font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word}
.raw{font:12px/1.45 var(--mono);color:#565656;background:#f4f4f4;border:1px solid #ebebeb;border-radius:3px;padding:6px 8px;
  white-space:pre-wrap;word-break:break-word;max-height:90px;overflow:auto}
.atitle{font-weight:600;font-size:15px;color:var(--title);margin:6px 0}
</style>
<div class="clr-hdr"><div class="b">
<svg viewBox="0 0 36 36"><path d="M18 3 31 10.5v15L18 33 5 25.5v-15Z" fill="none" stroke="#fafafa" stroke-width="2.4"/><path d="M11 19.5l4.5 4.5L25 13" fill="none" stroke="#49afd9" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
VMware Cloud Foundation<span class="sep"></span><span class="app">AIOps</span></div>
<div class="r">Operations · Log Intelligence</div></div>""", unsafe_allow_html=True)


# ------------------------------------------------------------------ API
def api(method: str, path: str, **kw):
    try:
        r = requests.request(method, f"{API}{path}", timeout=kw.pop("timeout", 10), **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001
        st.session_state["api_error"] = f"{type(e).__name__}: {e}"
        return None


ss = st.session_state
ss.setdefault("logs", [])
ss.setdefault("last_id", 0)
ss.setdefault("alert_seq", None)
ss.setdefault("chat", [])
ss.setdefault("chat_aid", None)


# ------------------------------------------------------------------ 사이드바
with st.sidebar:
    st.subheader("Log Intelligence")
    st.caption(f"백엔드: `{API}`")
    refresh = st.slider("갱신 주기(초)", 1, 15, 2)
    min_sev = st.selectbox("최소 심각도", list(SEV), index=0)
    sources = st.multiselect("소스", sorted(SRC_COLOR), placeholder="전체")
    query = st.text_input("검색 (host·메시지)")
    flag_only = st.toggle("이상 탐지된 줄만", False)
    paused = st.toggle("로그 일시정지", False)
    st.divider()
    anom_view = st.radio("이상징후 보기", ["미확인", "critical", "전체"], horizontal=True)
    if st.button("알림 채널 테스트", use_container_width=True):
        api("POST", "/api/alerts/test")
    if st.button("로그 화면 비우기", use_container_width=True):
        ss.logs = []


def visible(e: dict) -> bool:
    if SEV.get(e["severity"], 0) < SEV[min_sev]:
        return False
    if sources and e["source"] not in sources:
        return False
    if flag_only and not e.get("flagged"):
        return False
    if query and query.lower() not in f"{e['host']} {e['entity']} {e['message']}".lower():
        return False
    return True


def hms(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


# ------------------------------------------------------------------ 상단 상태
@st.fragment(run_every=refresh)
def header():
    s = api("GET", "/api/status")
    if not s:
        st.error(f"백엔드 연결 실패 — {ss.get('api_error', '')}")
        return
    llm = s.get("llm") or {}
    open_n = sum(1 for a in (api("GET", "/api/anomalies?limit=500") or [])
                 if not a["ack"] and (a.get("ai") or {}).get("is_anomaly") is not False)
    c = st.columns([1, 1.2, 1, 1, 2.2])
    c[0].metric("EPS", s["stats"]["eps"])
    c[1].metric("수집 이벤트", f"{s['stats']['events_total']:,}")
    c[2].metric("미확인 이상", open_n)
    c[3].metric("알림 발송", s["alerts_sent"])
    lat = f" {llm.get('latency_ms')}ms" if llm.get("latency_ms") else ""
    c[4].metric(f"AI 분석 엔진 · {llm.get('model', '')}", f"{str(llm.get('state', '-')).upper()}{lat}",
                f"대기 {s.get('queue', 0)}" if s.get("queue") else None, delta_color="off",
                help=llm.get("last_error") or "VMware Private AI Services (OpenAI 호환)")
    dot = {"ok": "#3c8500", "degraded": "#efc006", "down": "#c21d00", "init": "#0072a3", "disabled": "#b3b3b3"}
    st.markdown("".join(f'<span class="chip" title="{html.escape(x["target"])}\n{html.escape(x.get("last_error") or "")}"'
                        f'{" style=border-color:#c21d00;color:#c21d00" if x["state"] == "down" else ""}>'
                        f'<i style="background:{dot.get(x["state"], "#b3b3b3")}"></i>{html.escape(x["name"])} '
                        f'<small>{x["latency_ms"] if x["latency_ms"] is not None else "-"}ms · {x["events_total"]}</small></span>'
                        for x in s["connectors"]), unsafe_allow_html=True)

    # 신규 알림 → 토스트
    alerts = api("GET", f"/api/alerts/recent?after_seq={ss.alert_seq or 0}") or []
    if ss.alert_seq is None:                       # 첫 로드는 기존 알림을 다시 띄우지 않음
        ss.alert_seq = max([a["seq"] for a in alerts], default=0)
    else:
        for a in alerts[-3:]:
            st.toast(f"**{a['title']}**\n\n{a['body'][:300]}", icon="🚨" if a["severity"] == "critical" else "⚠️")
        if alerts:
            ss.alert_seq = alerts[-1]["seq"]


def row_html(e: dict) -> str:
    sev = e["severity"]
    flag = ""
    if e.get("flagged"):
        flag = f' f" style="--sev:{SEV_COLOR.get(sev, "#565656")};background:{SEV_BG.get(sev, "#fff")}'
    ent = " · " + html.escape(e["entity"]) if e["entity"] else ""
    return (f'<div class="lr{flag}" title="{html.escape(e["connector"])} · score {e["score"]}">'
            f'<span class="t">{hms(e["ts"])}</span>'
            f'<span style="color:{SRC_COLOR.get(e["source"], "#565656")};font-weight:600">{html.escape(e["source"])}</span>'
            f'<span style="color:{SEV_COLOR.get(sev, "#565656")};font-weight:700;font-size:11px;text-transform:uppercase">{sev}</span>'
            f'<span class="h">{html.escape(e["host"])}{ent}</span>'
            f'<span class="m">{html.escape(e["message"][:1500])}</span></div>')


# ------------------------------------------------------------------ 실시간 로그
@st.fragment(run_every=refresh)
def log_stream():
    if not paused:
        new = api("GET", f"/api/live?after_id={ss.last_id}&limit=1000") or []
        if new:
            ss.last_id = new[-1]["id"]
            ss.logs = (ss.logs + new)[-MAX_LOGS:]
    rows = [e for e in reversed(ss.logs) if visible(e)][:800]   # 최신이 위
    body = "".join(row_html(e) for e in rows)
    head = '<div class="lh"><span>시각</span><span>소스</span><span>심각도</span><span>호스트 / 대상</span><span>메시지</span></div>'
    st.markdown(f'<div class="logbox">{head}{body or "<div style=padding:20px;color:#8c8c8c>수신 대기 중…</div>"}</div>',
                unsafe_allow_html=True)
    st.caption(f"{len(rows):,}줄 표시 / 버퍼 {len(ss.logs):,}줄" + (" · ⏸ 일시정지" if paused else ""))


# ------------------------------------------------------------------ 이상징후
@st.fragment(run_every=refresh)
def anomaly_panel():
    items = api("GET", "/api/anomalies?limit=300") or []
    if anom_view == "미확인":
        items = [a for a in items if not a["ack"] and (a.get("ai") or {}).get("is_anomaly") is not False]
    elif anom_view == "critical":
        items = [a for a in items if a["severity"] == "critical"]
    box = st.container(height=690, border=False)
    if not items:
        box.info("표시할 이상 징후가 없습니다.")
    for a in items[:60]:
        e, ai = a["event"], a.get("ai") or {}
        sevc = SEV_COLOR.get(a["severity"], "#0072a3")
        cnt = (f'<span style="display:inline-block;background:#565656;color:#fff;border-radius:9px;padding:0 7px;'
               f'font-size:11px;line-height:18px;margin-right:6px">×{a["count"]}</span>') if a["count"] > 1 else ""
        with box.container(border=True):
            ent = " / " + html.escape(e["entity"]) if e["entity"] else ""
            st.markdown(
                f'<div style="border-top:3px solid {sevc};margin:-6px -2px 8px"></div>'
                f'<span class="lbl" style="border-color:{sevc};color:{sevc};background:{SEV_BG.get(a["severity"], "#fff")};'
                f'font-weight:700;text-transform:uppercase">{a["severity"]}</span>'
                f'<span class="lbl">{html.escape(a["category"])}</span>{cnt}'
                f'<small style="color:{SRC_COLOR.get(e["source"], "#565656")};font-weight:600">{html.escape(e["source"])}</small>'
                f'<small style="color:#8c8c8c"> · {html.escape(e["connector"])} · {time.strftime("%m-%d %H:%M:%S", time.localtime(a["last_seen"]))}</small>'
                f'<div class="atitle">{html.escape(a["title"])}</div>'
                f'<div class="raw">{html.escape(e["host"])}{ent}\n{html.escape(e["message"][:800])}</div>',
                unsafe_allow_html=True)
            st.caption(f'{STATUS_TXT.get(a["status"], a["status"])} · score {a["score"]} · '
                       + ", ".join(a.get("reasons") or []))
            if a["status"] == "analyzed" and not ai.get("error"):
                lab = 'style="display:inline-block;min-width:64px;color:#0072a3;font-weight:600;font-size:12px"'
                parts = ['<div style="border-top:1px solid #ebebeb;padding-top:6px;font-size:13.5px;color:#313131;line-height:1.55">']
                if ai.get("is_anomaly") is False:
                    parts.append(f"<div><span {lab}>AI 판정</span>정상/정보성 로그</div>")
                for k, t in (("summary", "요약"), ("probable_cause", "추정 원인"), ("impact", "영향")):
                    if ai.get(k):
                        parts.append(f"<div><span {lab}>{t}</span>{html.escape(str(ai[k]))}</div>")
                if ai.get("actions"):
                    parts.append(f"<div><span {lab}>조치</span></div><ol style='margin:2px 0 0 20px;padding:0'>"
                                 + "".join(f"<li>{html.escape(str(x))}</li>" for x in ai["actions"]) + "</ol>")
                if ai.get("references"):
                    parts.append(f"<div><span {lab}>근거</span></div><ul style='margin:2px 0 0 20px;padding:0'>" + "".join(
                        f"<li><span class='lbl'>{html.escape(r.get('type', 'doc'))}</span>"
                        + (f"<a href='{html.escape(r['url'])}' target='_blank'>{html.escape(r.get('title', ''))}</a>"
                           if str(r.get('url', '')).startswith('http') else html.escape(r.get('title', '')))
                        + f" <small style='color:#8c8c8c'>· {html.escape(str(r.get('pack_name', '')))}</small></li>"
                        for r in ai["references"]) + "</ul>")
                elif a.get("refs"):
                    parts.append(f"<div style='color:#8c8c8c;font-size:12px'>RAG 후보 {len(a['refs'])}건 검색됨 · AI가 관련 없다고 판단</div>")
                if ai.get("confidence") is not None:
                    parts.append(f"<div style='color:#8c8c8c;font-size:12px'>신뢰도 {round(float(ai['confidence']) * 100)}%</div>")
                st.markdown("".join(parts) + "</div>", unsafe_allow_html=True)
            elif ai.get("error"):
                st.caption(f"AI 오류: {ai['error']}")
            b = st.columns(3)
            if not a["ack"] and b[0].button("확인 처리", key=f"ack{a['id']}"):
                api("POST", f"/api/anomalies/{a['id']}/ack")
                st.rerun(scope="fragment")
            if a["status"] not in ("queued", "analyzing") and b[1].button("재분석", key=f"re{a['id']}"):
                api("POST", f"/api/anomalies/{a['id']}/analyze")
                st.rerun(scope="fragment")
            if b[2].button("AI 질문", key=f"ask{a['id']}"):
                ss.chat_aid = a["id"]
                ss.chat_ctx = a["title"]
                st.toast("‘AI 질의’ 탭에서 이 이상징후로 질문하세요", icon="💬")


# ------------------------------------------------------------------ 커넥터
def connector_tab():
    s = api("GET", "/api/status") or {"connectors": []}
    c1, c2 = st.columns([1, 5])
    results = ss.get("test_results", {})
    if c1.button("전체 연결 테스트", type="primary"):
        with st.spinner("모든 커넥터 인증·엔드포인트 점검 중…"):
            results = api("POST", "/api/connectors/test-all", timeout=120) or {}
        ss.test_results = results
    rows = []
    for c in s["connectors"]:
        r = results.get(c["name"], {})
        checks = r.get("checks") or c.get("checks") or {}
        rows.append({"커넥터": c["name"], "유형": c["type"], "대상": c["target"], "상태": c["state"],
                     "인증": c["auth"], "지연(ms)": c["latency_ms"], "이벤트": c["events_total"],
                     "마지막 성공": hms(c["last_ok"]) if c["last_ok"] else "-",
                     "점검 결과": " | ".join(f"{k}: {v}" for k, v in checks.items()),
                     "오류": r.get("error") or c.get("last_error") or ""})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True,
                 column_config={"점검 결과": st.column_config.TextColumn(width="large"),
                                "오류": st.column_config.TextColumn(width="large")})
    st.markdown("##### 개별 테스트")
    names = [c["name"] for c in s["connectors"]]
    if names:
        pick = st.selectbox("커넥터", names, label_visibility="collapsed")
        if st.button("선택 커넥터 테스트"):
            with st.spinner(f"{pick} 점검 중…"):
                r = api("POST", f"/api/connectors/{pick}/test", timeout=60)
            st.json(r)


# ------------------------------------------------------------------ AI 질의
def chat_tab():
    ctx = ss.get("chat_ctx") if ss.chat_aid else None
    c1, c2 = st.columns([5, 1])
    c1.caption(f"컨텍스트: {ctx}" if ctx else "컨텍스트: 최근 이상징후 25건 + 경고 이상 로그 40줄")
    if ss.chat_aid and c2.button("컨텍스트 해제"):
        ss.chat_aid = None
        st.rerun()
    for m in ss.chat:
        st.chat_message(m["role"]).markdown(m["content"])
    q = st.chat_input("예) 지난 10분간 스토리지 이상의 공통 원인은? / 이 APD가 vSAN에 영향을 주나?")
    if not q:
        return
    ss.chat.append({"role": "user", "content": q})
    st.chat_message("user").markdown(q)

    def stream():
        try:
            with requests.post(f"{API}/api/chat", json={"question": q, "anomaly_id": ss.chat_aid},
                               stream=True, timeout=300) as r:
                r.raise_for_status()
                for line in r.iter_lines(decode_unicode=True):
                    if not line or not line.startswith("data:"):
                        continue
                    d = line[5:].strip()
                    if d == "[DONE]":
                        break
                    j = json.loads(d)
                    if j.get("refs"):
                        ss["_chat_refs"] = j["refs"]
                        continue
                    if j.get("error"):
                        yield f"\n\n[오류] {j['error']}"
                    elif j.get("t"):
                        yield j["t"]
        except Exception as e:  # noqa: BLE001
            yield f"[연결 오류] {e}"

    ss["_chat_refs"] = []
    with st.chat_message("assistant"):
        ans = st.write_stream(stream())
        if ss.get("_chat_refs"):
            st.caption("참고 지식: " + " · ".join(f"[{r['ref']}] {r['title'][:60]} ({r['pack']})" for r in ss["_chat_refs"]))
    ss.chat.append({"role": "assistant", "content": ans if isinstance(ans, str) else "".join(ans)})


# ------------------------------------------------------------------ SNMP 트랩
@st.fragment(run_every=refresh)
def snmp_tab():
    traps = [e for e in reversed(ss.logs) if str(e.get("connector", "")).startswith("snmp")]
    conn = next((c for c in (api("GET", "/api/connectors") or []) if c["type"] == "snmp"), None)
    c = st.columns(4)
    c[0].metric("수신 상태", (conn or {}).get("state", "disabled").upper())
    c[1].metric("수신 트랩(화면 버퍼)", len(traps))
    c[2].metric("송신 장비", len({(e.get("attrs") or {}).get("peer") for e in traps}))
    unknown = {k: v for k, v in ((conn or {}).get("checks") or {}).items() if k.startswith("미등록 OID")}
    c[3].metric("미등록 트랩 OID", len(unknown))
    if conn:
        st.caption(f"수신 포트 {conn['target']} · 인증 {conn['auth']}" + (f" · 오류: {conn['last_error']}" if conn.get("last_error") else ""))
    if unknown:
        with st.expander("미등록 트랩 OID — config.yaml `snmp.oid_map`에 이름·심각도를 추가하면 정확도가 올라갑니다"):
            st.code("snmp:\n  oid_map:\n" + "\n".join(
                f'    "{k.replace("미등록 OID ", "")}": {{name: <트랩이름>, severity: error, source: redfish}}' for k in unknown),
                language="yaml")
    if not traps:
        st.info("아직 수신된 SNMP 트랩이 없습니다. 장비의 트랩 대상을 이 서버의 UDP 162로 지정하세요.")
        return
    rows = [{"시각": hms(e["ts"]), "심각도": e["severity"].upper(), "소스": e["source"],
             "송신 장비": (e.get("attrs") or {}).get("peer", ""), "호스트": e["host"],
             "트랩": (e.get("attrs") or {}).get("snmp_trap", ""), "벤더": (e.get("attrs") or {}).get("vendor", ""),
             "메시지": e["message"], "이상": "●" if e.get("flagged") else ""} for e in traps[:500]]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=360,
                 column_config={"메시지": st.column_config.TextColumn(width="large")})
    st.markdown("##### 트랩 상세 (varbind)")
    pick = st.selectbox("트랩 선택", range(min(len(traps), 200)), label_visibility="collapsed",
                        format_func=lambda i: f'{hms(traps[i]["ts"])} · {(traps[i].get("attrs") or {}).get("snmp_trap", "")} · {traps[i]["host"]}')
    a = traps[pick].get("attrs") or {}
    st.dataframe(pd.DataFrame([{"이름/OID": k, "값": v} for k, v in (a.get("varbinds") or {}).items()]
                              + [{"이름/OID": "snmpTrapOID", "값": a.get("snmp_trap_oid", "")},
                                 {"이름/OID": "sysUpTime", "값": a.get("uptime", "")}]),
                 use_container_width=True, hide_index=True)


# ------------------------------------------------------------------ RAG 팩
def rag_tab():
    d = api("GET", "/api/rag/packs") or {"packs": [], "status": {}, "presets": {}}
    stt = d.get("status") or {}
    emb = stt.get("embedding") or {}
    c = st.columns(4)
    c[0].metric("설치된 팩", stt.get("packs_total", 0))
    c[1].metric("활성 팩", len(stt.get("enabled", [])))
    c[2].metric("검색 대상 청크", f"{stt.get('chunks_loaded', 0):,}")
    c[3].metric(f"임베딩 · {emb.get('model', '-')}", str(emb.get("state", "disabled")).upper(),
                help=emb.get("last_error") or "rag.embedding 설정. 비활성 시 BM25 키워드 검색만 사용")
    st.caption("활성 팩은 이벤트 소스(applies_to)가 맞는 이상징후 분석과 AI 질의에 근거 문서로 주입됩니다.")

    with st.expander("RAG 팩 가져오기 (.ragpack)", expanded=not d["packs"]):
        up = st.file_uploader("팩 파일", type=["ragpack", "zip"], label_visibility="collapsed")
        en = st.checkbox("가져온 뒤 바로 활성화", True)
        if up is not None and st.button("가져오기", type="primary"):
            with st.spinner("팩 검증·저장 중 (벡터가 없거나 모델이 다르면 백그라운드 재임베딩)…"):
                r = requests.post(f"{API}/api/rag/packs", params={"filename": up.name, "enable": en},
                                  data=up.getvalue(), headers={"Content-Type": "application/octet-stream"}, timeout=600)
            if r.ok:
                st.success(f"가져오기 완료: {r.json()}")
            else:
                st.error(r.text)
        st.markdown("팩 만들기: `python -m app.rag.builder build ragpacks/vsphere.yaml` → `dist/vsphere.ragpack` "
                    "(NVD CVE·Broadcom KB·URL·로컬 문서·pgvector export)")

    if not d["packs"]:
        st.info("설치된 RAG 팩이 없습니다.")
        return
    for p in d["packs"]:
        with st.container(border=True):
            h = st.columns([5, 1.2, 1, 1])
            badge = ('<span class="lbl" style="border-color:#3c8500;color:#3c8500;background:#eaf6dc">ENABLED</span>'
                     if p["enabled"] else '<span class="lbl">DISABLED</span>')
            job = p.get("job") or {}
            jtxt = ""
            if job.get("state") == "embedding":
                jtxt = f" · 임베딩 {job['done']}/{job['total']}"
            elif job.get("state") == "error":
                jtxt = f" · ⚠ {job.get('error', '')}"
            h[0].markdown(f'{badge}<span class="lbl">{html.escape(str(p["product"]))}</span>'
                          f'<b style="font-size:16px;color:#313131">{html.escape(str(p["name"]))}</b> '
                          f'<small style="color:#8c8c8c">v{html.escape(str(p["version"]))} · {p["id"]}</small>',
                          unsafe_allow_html=True)
            stats = p.get("stats") or {}
            h[0].caption(f"문서 {stats.get('documents', 0):,} · 청크 {stats.get('chunks', 0):,} · "
                         + " · ".join(f"{k} {v:,}" for k, v in (stats.get("by_type") or {}).items())
                         + f" · {p['size_mb']}MB · 검색: {'하이브리드(Dense+BM25)' if p['embedding_match'] else 'BM25'}{jtxt}")
            h[0].caption("적용 소스: " + ", ".join(p.get("applies_to") or ["*"]) + (f" — {p['description']}" if p.get("description") else ""))
            if p["enabled"]:
                if h[1].button("비활성화", key=f"dis{p['id']}"):
                    api("POST", f"/api/rag/packs/{p['id']}/disable")
                    st.rerun()
            elif h[1].button("활성화", key=f"en{p['id']}", type="primary"):
                with st.spinner("인덱스 적재 중…"):
                    api("POST", f"/api/rag/packs/{p['id']}/enable", timeout=600)
                st.rerun()
            if not p["embedding_match"] and h[2].button("재임베딩", key=f"re{p['id']}"):
                api("POST", f"/api/rag/packs/{p['id']}/reembed")
                st.rerun()
            if h[3].button("삭제", key=f"del{p['id']}"):
                requests.delete(f"{API}/api/rag/packs/{p['id']}", timeout=30)
                st.rerun()
            with st.expander("수집 소스"):
                st.dataframe(pd.DataFrame(p.get("sources") or []), hide_index=True, use_container_width=True)

    st.markdown("##### 검색 테스트")
    q1, q2, q3 = st.columns([4, 1.4, 1.4])
    q = q1.text_input("질의", placeholder="예) vob.storage.apd.start / CVE-2024-37085 / BGP Hold Timer Expired",
                      label_visibility="collapsed")
    srcs = ["(전체)"] + sorted(SRC_COLOR)
    src = q2.selectbox("소스", srcs, label_visibility="collapsed")
    pack = q3.selectbox("팩", ["(활성 전체)"] + [p["id"] for p in d["packs"] if p["enabled"]], label_visibility="collapsed")
    if q:
        params = {"q": q, "k": 8}
        if src != "(전체)":
            params["source"] = src
        if pack != "(활성 전체)":
            params["pack"] = pack
        for r in api("GET", "/api/rag/search", params=params) or []:
            with st.container(border=True):
                link = f"[{r['title']}]({r['url']})" if str(r["url"]).startswith("http") else r["title"]
                st.markdown(f"**{link}**  \n`{r['type']}` · {r['pack_name']} · score {r['score']} · {r['mode']}")
                st.caption(r["text"][:600])


# ------------------------------------------------------------------ 구성도
def arch_tab():
    svg_path = os.path.join(ROOT, "app", "static", "architecture.svg")
    try:
        svg = open(svg_path, encoding="utf-8").read()
    except OSError:
        st.warning("architecture.svg 를 찾을 수 없습니다.")
        return
    st.markdown(f'<div style="background:#fff;border:1px solid #dcdcdc;border-radius:3px;padding:8px">{svg}</div>',
                unsafe_allow_html=True)
    st.download_button("구성도 SVG 다운로드", svg, file_name="vcf-aiops-architecture.svg", mime="image/svg+xml")


# ------------------------------------------------------------------ 레이아웃
header()
t1, t2, t4, t5, t3, t6 = st.tabs(["실시간 대시보드", "API 커넥터", "SNMP 트랩", "RAG 팩", "AI 질의", "구성도"])
with t1:
    left, right = st.columns([1.65, 1])
    with left:
        st.markdown("##### 실시간 로그")
        log_stream()
    with right:
        st.markdown("##### 이상 징후 · 규칙/통계 → Gemma 4 31B 판정")
        anomaly_panel()
with t2:
    connector_tab()
with t4:
    snmp_tab()
with t5:
    rag_tab()
with t6:
    arch_tab()
with t3:
    chat_tab()
