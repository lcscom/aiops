/* 지원 요청(SR, 2.11.0) — 장애 근거로 벤더(Broadcom·AWS·Azure·일반) SR 양식 보고서·이메일 초안·PDF·로그 묶음·공유 링크
   + 공용 로그 내려받기 창(AIOPS_LOGS_EXPORT) — 대시보드·실시간 로그 보기·인시던트·VKS 에서 같은 창을 씀 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {meta: null, list: [], sel: "", d: null, tab: "email", status: "", q: "", dirty: false, shareUrl: null};
  const SEVC = {1: "#c21d00", 2: "#e8730c", 3: "#e0a800", 4: "#62a420"};
  const fmt = ts => ts ? new Date(ts * 1000).toLocaleString([], {year: "2-digit", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";
  const SRC = {incident: "인시던트", anomaly: "이상징후", vks: "VKS 개체", host: "호스트", vm: "VM", entity: "개체", manual: "직접 작성", readiness: "하드웨어 준비도"};
  const dl = url => { const a = document.createElement("a"); a.href = url; a.download = ""; document.body.append(a); a.click(); a.remove(); };
  const meta = async () => st.meta || (st.meta = await A.api("GET", "/api/support/meta", undefined, {background: true}));

  // ---------------------------------------------------------------- 공용: 로그 내려받기
  async function logsExport(p = {}) {
    const presets = [["15", "최근 15분"], ["60", "최근 1시간"], ["360", "최근 6시간"], ["1440", "최근 24시간"], ["10080", "최근 7일"], ["custom", "직접 지정"]];
    const toLocal = ts => { const d = new Date(ts * 1000 - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };
    const fixed = p.since && p.until;
    const cond = [["host", "호스트"], ["source", "소스"], ["connector", "커넥터"], ["entity", "개체"], ["q", "포함 문자열"]].filter(([k]) => p[k]).map(([k, l]) => `${l}: <b>${esc(String(p[k]).slice(0, 200))}</b>`).join(" · ");
    const html = `<p class="small muted">${esc(p.title || "현재 조건의 로그를 파일로 받습니다.")} 비밀번호·토큰·API 키·Bearer·JWT 같은 값은 가려서 씁니다.</p>
      ${cond ? `<p class="small">${cond}</p>` : `<p class="small">조건 없음 — 전체 로그</p>`}<p class="small" id="lx-count">예상 행 수 계산 중…</p>`;
    const v = await A.modal({title: "로그 내려받기", html, ok: "내려받기", wide: false, fields: [
      {id: "range", label: "기간", type: "select", value: fixed ? "custom" : String(p.minutes || 60), options: presets},
      {id: "since", label: "시작(직접 지정)", type: "datetime-local", value: toLocal(p.since || Date.now() / 1000 - 3600)},
      {id: "until", label: "끝(직접 지정)", type: "datetime-local", value: toLocal(p.until || Date.now() / 1000)},
      {id: "min", label: "최소 등급", type: "select", value: p.min_severity || "debug", options: [["debug", "전체"], ["info", "정보↑"], ["warning", "경고↑"], ["error", "오류↑"], ["critical", "위험"]]},
      {id: "format", label: "형식", type: "select", value: p.format || "csv", options: [["csv", "CSV (Excel)"], ["txt", "텍스트(.log)"], ["ndjson", "NDJSON(한 줄 JSON)"], ["zip", "ZIP(소스별 .log + 전체 CSV)"]]},
      {id: "max", label: "최대 행 수", type: "number", value: 200000, min: 1, max: 1000000}],
      onOpen: m => {
        const upd = async () => {
          const q = params(read(m)); q.delete("format"); q.delete("max_rows"); q.delete("name");
          const el = $("#lx-count", m); if (!el) return;
          try { const r = await A.api("GET", "/api/logs/export/count?" + q, undefined, {background: true}); el.innerHTML = `예상 <b>${r.rows.toLocaleString()}</b>행 · ${fmt(r.since)} ~ ${fmt(r.until)}`; }
          catch (e) { el.textContent = e.message; }
        };
        const showCustom = () => { const c = $("#mf-range", m).value === "custom"; ["since", "until"].forEach(k => { $(`#mf-${k}`, m).closest("label").hidden = !c; }); };
        $$("select,input", m).forEach(x => x.addEventListener("change", () => { showCustom(); upd(); }));
        showCustom(); upd();
      }});
    if (!v) return;
    function read(m) { return {range: $("#mf-range", m).value, since: $("#mf-since", m).value, until: $("#mf-until", m).value, min: $("#mf-min", m).value, format: $("#mf-format", m).value, max: $("#mf-max", m).value}; }
    function params(x) {
      const q = new URLSearchParams();
      if (x.range === "custom") { q.set("since", String(Math.floor(new Date(x.since).getTime() / 1000))); q.set("until", String(Math.floor(new Date(x.until).getTime() / 1000))); }
      else q.set("minutes", x.range);
      ["host", "source", "connector", "entity", "q", "kind"].forEach(k => { if (p[k]) q.set(k, p[k]); });
      q.set("min_severity", x.min); q.set("format", x.format); q.set("max_rows", String(x.max || 200000)); q.set("name", p.name || "logs");
      return q;
    }
    dl("/api/logs/export?" + params(v));
  }

  // ---------------------------------------------------------------- 새 SR
  async function srNew(source = {kind: "manual"}, hint = {}) {
    const m = await meta();
    const sd = document.getElementById("vk-side"); if (sd) sd.remove();
    const vend = Object.entries(m.vendors).map(([k, x]) => [k, x.label]);
    const manual = source.kind === "manual";
    const fields = [{id: "vendor", label: "제출 대상(양식)", type: "select", value: m.profile.default_vendor, options: vend},
      {id: "lang", label: "언어", type: "select", value: m.profile.default_lang, options: [["both", "한국어 + English(병기)"], ["ko", "한국어"], ["en", "English"]]},
      {id: "severity", label: "심각도(비우면 근거로 자동)", type: "select", value: hint.severity || "", options: [["", "자동"], ["1", "1 — 운영 중단"], ["2", "2 — 주요 기능 저하"], ["3", "3 — 부분 영향"], ["4", "4 — 문의"]]}];
    if (manual) fields.push({id: "title", label: "제목", required: true}, {id: "description", label: "증상 설명", type: "textarea", rows: 4},
      {id: "hosts", label: "관련 호스트·VM(쉼표, 로그 수집 대상)", placeholder: "esx03.vcf.lab, core-bank-db01"}, {id: "hours", label: "로그 기간(시간)", type: "number", value: 6, min: 1, max: 168});
    const v = await A.modal({title: `지원 요청(SR) 초안 만들기 — ${SRC[source.kind] || source.kind}${hint.label ? " · " + hint.label : ""}`, wide: true,
      html: `<p class="small muted">근거(발생 시각·환경·영향 개체·증상·변경·확인한 내용·관련 KB·로그)를 자동으로 모아 선택한 벤더 SR 양식에 맞춘 보고서와 이메일 초안을 만듭니다. 만든 뒤 화면에서 고칠 수 있습니다.</p>`,
      fields, ok: "초안 만들기"});
    if (!v) return;
    const src = {...source};
    if (manual) { const h = Number(v.hours || 6); Object.assign(src, {title: v.title, description: v.description, hosts: v.hosts.split(",").map(x => x.trim()).filter(Boolean), since: Date.now() / 1000 - h * 3600, until: Date.now() / 1000}); }
    A.toast("SR 초안 작성 중", "근거를 모으고 있습니다(VKS 는 파드 로그까지 수집 — 수십 초).", "info", 4000);
    try {
      const r = await A.api("POST", "/api/support/requests", {source: src, vendor: v.vendor, lang: v.lang, ...(v.severity ? {severity: Number(v.severity)} : {})});
      await openDrawer(); st.sel = r.id; st.d = r; st.tab = "email"; await loadList(); render();
      A.ok("SR 초안 작성", `${r.id} — 내용을 확인·보완한 뒤 이메일·PDF·로그 묶음으로 보내세요.`);
    } catch (e) { A.fail("SR 초안 실패", e); }
  }

  // ---------------------------------------------------------------- 화면
  async function openDrawer() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-sr") d.hidden = true; });
    $("#drawer-sr").hidden = false;
    await meta();
  }
  async function loadList() {
    try { st.list = (await A.api("GET", "/api/support/requests?" + new URLSearchParams({status: st.status, q: st.q}), undefined, {background: true})).items; }
    catch (e) { st.list = []; }
  }
  async function loadOne(id) {
    st.sel = id; st.shareUrl = null; st.dirty = false;
    try { st.d = await A.api("GET", `/api/support/requests/${encodeURIComponent(id)}`, undefined, {background: true}); } catch (e) { A.fail("SR 불러오기 실패", e); st.d = null; }
    render();
  }
  function render() {
    const m = st.meta; if (!m) return;
    const box = $("#sr-body");
    box.innerHTML = `<div class="sr-grid"><aside class="sr-list"><div class="sr-lh"><button class="btn-sm solid" data-sra="new" data-perm="operate">+ 새 SR</button>
        <select id="sr-st"><option value="">전체 상태</option>${Object.entries(m.statuses).map(([k, l]) => `<option value="${k}" ${k === st.status ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
        <input id="sr-q" placeholder="제목·SR·케이스 번호" value="${esc(st.q)}"></div>
        <div class="sr-items">${st.list.map(x => `<button class="sr-it ${x.id === st.sel ? "sel" : ""}" data-sr="${esc(x.id)}"><i style="background:${SEVC[x.severity] || "#9aa5ad"}"></i>
          <div><b>${esc(x.title)}</b><div class="mini">${esc(x.id)} · ${esc(m.vendors[x.vendor] ? m.vendors[x.vendor].label : x.vendor)} · ${esc(m.statuses[x.status] || x.status)}${x.case_no ? " · #" + esc(x.case_no) : ""}</div>
          <div class="mini muted">${esc(SRC[x.source_kind] || x.source_kind)} ${esc(x.source_ref || "")} · ${fmt(x.updated)}</div></div></button>`).join("") || `<div class="empty small">아직 SR 이 없습니다.<br>인시던트·이상징후·VKS 개체에서 'SR 초안'을 누르거나 '+ 새 SR'.</div>`}</div>
        <div class="sr-prof"><button class="btn-sm" data-sra="profile" data-perm="settings">기본 정보(연락처·계정 ID)</button></div></aside>
      <section class="sr-main">${st.d ? detail() : `<div class="empty">왼쪽에서 SR 을 고르거나 새로 만드세요.<p class="small muted">SR 양식은 Broadcom KB 142884·440029·140745, AWS Support 사용자 안내서, Azure 지원 요청 문서의 항목을 따릅니다.</p></div>`}</section></div>`;
    $("#sr-st").onchange = async e => { st.status = e.target.value; await loadList(); render(); };
    let qt; $("#sr-q").oninput = e => { clearTimeout(qt); qt = setTimeout(async () => { st.q = e.target.value.trim(); await loadList(); render(); const i = $("#sr-q"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }, 350); };
    box.querySelectorAll("[data-perm]").forEach(el => { el.hidden = !A.can(el.dataset.perm); });
    wire();
  }
  function detail() {
    const m = st.meta, x = st.d, d = x.data, v = m.vendors[d.vendor] || m.vendors.generic;
    const sev = v.sev[String(d.severity)] || {};
    const ro = !A.can("operate");
    const fld = (id, label, val, type = "text", extra = "") => `<label class="mf"><span>${esc(label)}</span>${type === "textarea" ? `<textarea data-f="${id}" rows="${extra || 4}" ${ro ? "readonly" : ""}>${esc(val || "")}</textarea>` : `<input data-f="${id}" value="${esc(val || "")}" ${ro ? "readonly" : ""}>`}</label>`;
    const vf = d.vendor_fields || {};
    const bi = (d.lang || "both") !== "ko";
    const pairF = (id, lko, len_, vko, ven, type, rows) => !bi ? fld(id, lko, vko, type, rows || "") :
      `<div class="sr-bi">${fld(id, lko, vko, type, rows || "")}${fld(id + "_en", len_, ven || "", type, rows || "")}</div>`;
    const tabs = [["email", "이메일 초안"], ["report", "보고서"], ["logs", `첨부·로그 ${((d.log_stats || {}).rows || 0).toLocaleString()}행`], ["share", `공유 링크${(x.shares || []).filter(s => !s.revoked && s.expires > Date.now() / 1000).length ? " " + (x.shares || []).filter(s => !s.revoked && s.expires > Date.now() / 1000).length : ""}`]];
    return `<div class="sr-head"><div><span class="sr-sev" style="background:${SEVC[d.severity]}">${esc(sev.code || "")}</span> <b class="sr-id">${esc(x.id)}</b>
        <span class="small muted">${esc(SRC[d.source.kind] || d.source.kind)} ${esc(d.source.ref || d.source.obj || d.source.name || "")} · 근거 수집 ${fmt(d.collected)} · 작성 ${esc(x.created_by)}</span>
        ${d.links && d.links.incident ? ` <a class="small" href="#" data-inc="${esc(d.source.ref)}">인시던트 열기</a>` : ""}</div>
      <div class="sr-acts">${ro ? "" : `<button class="btn-sm solid" data-sra="save" ${st.dirty ? "" : "disabled"}>저장</button><button class="btn-sm ai" data-sra="refine" title="제목·요약·업무 영향·요청 사항을 AI 가 다듬어 제안(외부 AI 는 개체 이름·IP 가명화)">AI로 다듬기</button>
        <button class="btn-sm" data-sra="refresh" title="근거(로그·이벤트·KB)를 다시 모음 — 직접 고친 내용은 유지">근거 다시 모으기</button>`}
        <button class="btn-sm" data-dl="${esc(x.links.pdf)}">PDF</button><button class="btn-sm" data-dl="${esc(x.links.logs)}">로그 묶음(.zip)</button>
        ${ro ? "" : `<button class="btn-sm danger" data-sra="del">삭제</button>`}</div></div>
      <div class="sr-form">
        <div class="sr-row"><label class="mf"><span>제출 대상(양식)</span><select data-f="vendor" ${ro ? "disabled" : ""}>${Object.entries(m.vendors).map(([k, y]) => `<option value="${k}" ${k === d.vendor ? "selected" : ""}>${esc(y.label)}</option>`).join("")}</select></label>
          <label class="mf"><span>심각도</span><select data-f="severity" ${ro ? "disabled" : ""}>${[1, 2, 3, 4].map(n => `<option value="${n}" ${n === d.severity ? "selected" : ""}>${esc((v.sev[String(n)] || {}).label || n)}</option>`).join("")}</select></label>
          <label class="mf"><span>언어</span><select data-f="lang" ${ro ? "disabled" : ""}>${[["both", "한국어 + English(병기)"], ["ko", "한국어"], ["en", "English"]].map(([k, l]) => `<option value="${k}" ${(d.lang || "both") === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
          <label class="mf"><span>상태</span><select data-f="status" ${ro ? "disabled" : ""}>${Object.entries(m.statuses).map(([k, l]) => `<option value="${k}" ${k === x.status ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>
          ${fld("case_no", "케이스 번호(접수 후)", d.case_no)}</div>
        <p class="small muted sr-sevd">${esc(sev.desc || "")}${bi ? ` <span class="sr-enl">/ ${esc(sev.desc_en || "")}</span>` : ""}</p>
        ${enBanner(x)}
        ${pairF("title", "제목", "Title (English)", d.title, d.title_en, "text")}
        ${pairF("summary", "1. 문제 요약", "1. Problem summary (English)", d.summary, d.summary_en, "textarea", 4)}
        ${pairF("impact", "2. 업무 영향 — 서비스·사용자 수·거래 영향을 구체적으로(P1 은 필수)", "2. Business impact (English)", d.impact, d.impact_en, "textarea", 3)}
        ${pairF("requests", "11. 요청 사항(한 줄에 하나)", "11. Requests (English, one per line)", (d.requests || []).join("\n"), (d.requests_en || []).join("\n"), "textarea", 3)}
        ${fld("checked_extra", "8. 확인한 내용 추가(한 줄에 하나 — 자동 수집분에 덧붙임)", (d.checked_extra || []).join("\n"), "textarea", 3)}
        <details class="sr-det"><summary>포털 입력값 — ${esc(v.label)} ${v.portal ? `<a href="${esc(v.portal)}" target="_blank" rel="noopener noreferrer" class="small">포털 열기 ↗</a>` : ""}</summary>
          <div class="sr-row">${v.fields.map(f => `<label class="mf"><span>${esc(f.label)}</span><input data-vf="${esc(f.key)}" value="${esc(vf[f.key] || "")}" ${ro ? "readonly" : ""}></label>`).join("")}</div>
          ${(v.notes || []).length ? `<ul class="small muted">${v.notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
          <div class="small muted">양식 근거: ${(v.refs || []).map(u => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u.replace(/^https:\/\//, "").slice(0, 60))}</a>`).join(" · ")}</div></details>
        <details class="sr-det"><summary>받는 사람·연락처</summary><div class="sr-row">
          <label class="mf"><span>받는 사람(To)</span><input data-em="to" value="${esc((d.email || {}).to || "")}" ${ro ? "readonly" : ""}></label>
          <label class="mf"><span>참조(Cc)</span><input data-em="cc" value="${esc((d.email || {}).cc || "")}" ${ro ? "readonly" : ""}></label>
          ${["company:회사", "name:담당자", "email:이메일", "phone:전화", "secondary:보조 연락처", "availability:연락 가능 시간"].map(s => { const [k, l] = s.split(":"); return `<label class="mf"><span>${l}</span><input data-ct="${k}" value="${esc((d.contact || {})[k] || "")}" ${ro ? "readonly" : ""}></label>`; }).join("")}</div></details>
      </div>
      <div class="vks-tabs sr-tabs">${tabs.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-srt="${k}">${l}</button>`).join("")}${st.dirty ? `<span class="small om-warn">저장하지 않은 변경 — 미리보기는 저장 후 반영</span>` : ""}</div>
      <div class="sr-tab">${tabBody()}</div>`;
  }
  function tabBody() {
    const x = st.d, d = x.data;
    if (st.tab === "email") {
      const mailto = `mailto:${encodeURIComponent(x.email.to || "")}?${new URLSearchParams({...(x.email.cc ? {cc: x.email.cc} : {}), subject: x.email.subject, body: x.email.body.length > 1800 ? x.email.body.slice(0, 1800) + "\n…(본문이 길어 잘림 — .eml 또는 PDF 첨부 사용)" : x.email.body}).toString().replace(/\+/g, "%20")}`;
      return `<div class="sr-mail"><div class="sr-mh"><span class="muted">제목</span><b id="sr-subj">${esc(x.email.subject)}</b><button class="btn-sm" data-copy="subj">복사</button></div>
        <div class="sr-mh"><span class="muted">받는 사람</span>${esc(x.email.to || "(기본 정보에서 지정)")}${x.email.cc ? ` · 참조 ${esc(x.email.cc)}` : ""}</div>
        <div class="sr-ma"><button class="btn-sm solid" data-copy="body">본문 복사</button><a class="btn-sm" href="${esc(mailto)}">메일 앱으로 열기</a>
          <button class="btn-sm" data-dl="${esc(x.links.eml)}" title="Outlook 에서 '보내지 않은 초안'으로 열림 — PDF·로그(10MB 이하) 첨부">.eml(첨부 포함)</button><button class="btn-sm" data-dl="${esc(x.links.txt)}">.txt</button></div>
        <pre class="sr-body">${esc(x.email.body)}</pre></div>`;
    }
    if (st.tab === "report") return `<div class="sr-rep"><div class="sr-ma"><a class="btn-sm" href="${esc(x.links.html)}" target="_blank" rel="noopener">새 창으로</a><button class="btn-sm" data-dl="${esc(x.links.pdf)}">PDF 내려받기</button></div>
      <iframe class="sr-frame" src="${esc(x.links.html)}?t=${Math.round(x.updated)}" sandbox="allow-same-origin allow-downloads allow-popups" title="보고서 미리보기"></iframe></div>`;
    if (st.tab === "logs") {
      const ls = d.log_stats || {}, lq = d.log_query || {};
      return `<p class="small">로그 묶음(.zip)에는 <b>보고서(PDF·HTML)·이메일 본문·summary.json·타임라인 CSV</b>와 조건에 맞는 <b>로그 전체(CSV + 소스별 .log)</b>${(x.attach_files || []).length ? `, <b>수집해 둔 파드 로그 ${x.attach_files.length}개</b>` : ""}가 들어갑니다. 비밀값 패턴은 가립니다.</p>
        <table class="vc-t"><tr><th>기간</th><td>${fmt(ls.since || lq.since)} ~ ${fmt(ls.until || lq.until)}</td></tr><tr><th>행 수</th><td>${(ls.rows || 0).toLocaleString()}</td></tr>
          ${lq.hosts && lq.hosts.length ? `<tr><th>호스트·개체</th><td>${esc(lq.hosts.join(", ").slice(0, 600))}</td></tr>` : ""}${lq.connectors && lq.connectors.length ? `<tr><th>커넥터</th><td>${esc(lq.connectors.join(", "))}</td></tr>` : ""}
          ${lq.entities && lq.entities.length ? `<tr><th>Kubernetes 개체</th><td>${esc(lq.entities.slice(0, 20).join(", "))}${lq.entities.length > 20 ? ` 외 ${lq.entities.length - 20}` : ""}</td></tr>` : ""}</table>
        <div class="sr-ma"><button class="btn-sm solid" data-dl="${esc(x.links.logs)}">로그 묶음(.zip) 내려받기</button><button class="btn-sm" data-sra="logs-custom">기간·형식 바꿔 받기</button></div>
        ${(x.attach_files || []).length ? `<h5>수집해 둔 파일</h5><ul class="inv-moves">${x.attach_files.map(f => `<li class="mono small">${esc(f.name)} <span class="muted">${(f.bytes / 1024).toFixed(1)} KB</span></li>`).join("")}</ul>` : ""}
        <h5>로그 발췌(보고서 부록 B)</h5><pre class="vk-log">${(d.logs_excerpt || []).map(r => `<span class="${["error", "critical"].includes(r.severity) ? "e" : r.severity === "warning" ? "w" : ""}">${esc(fmt(r.ts))} ${esc(String(r.severity || "").toUpperCase())} ${esc(r.host || "")} ${esc(r.message || "")}</span>`).join("\n") || "(없음)"}</pre>`;
    }
    const shares = x.shares || [];
    const now = Date.now() / 1000;
    return `<p class="small">이 서버의 자체 URL 로 보고서를 공유합니다(무작위 토큰 — 서버에는 해시만 저장, 만료·폐기 가능, 열람은 감사로그). 받는 사람이 이 서버에 접속할 수 있어야 합니다.</p>
      ${A.can("operate") ? `<div class="sr-row sr-share"><label class="mf"><span>유효 기간(일)</span><input type="number" id="sh-days" min="1" max="90" value="${st.meta.profile.share_days || 7}"></label>
        <label class="mf chk"><span>로그 묶음 내려받기 허용</span><input type="checkbox" id="sh-logs" checked></label>
        <label class="mf chk"><span>이 서버 로그인 요구(사내용)</span><input type="checkbox" id="sh-login"></label><button class="btn-sm solid" data-sra="share">링크 만들기</button></div>` : ""}
      ${st.shareUrl ? `<div class="sr-newurl"><b>새 공유 링크</b> <span class="small muted">— 지금 한 번만 표시됩니다</span><div class="sr-url"><input readonly value="${esc(st.shareUrl)}" id="sh-url"><button class="btn-sm solid" data-copy="url">복사</button></div></div>` : ""}
      <table class="vc-t"><thead><tr><th>만든 시각</th><th>만료</th><th>로그</th><th>로그인</th><th>열람</th><th>상태</th><th></th></tr></thead><tbody>
        ${shares.map(s => `<tr><td>${fmt(s.created)} <span class="muted">${esc(s.created_by)}</span></td><td>${fmt(s.expires)}</td><td>${s.include_logs ? "허용" : "-"}</td><td>${s.require_login ? "필요" : "-"}</td>
          <td>${s.opened}회${s.last_open ? ` · ${fmt(s.last_open)}` : ""}</td><td>${s.revoked ? "폐기" : s.expires < now ? "만료" : "<b class='good'>유효</b>"}</td>
          <td>${!s.revoked && s.expires > now && A.can("operate") ? `<button class="btn-sm danger" data-revoke="${esc(s.id)}">폐기</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">공유 링크 없음</td></tr>`}</tbody></table>`;
  }
  function enBanner(x) {
    const d = x.data, en = x.en || {};
    if ((d.lang || "both") === "ko") return "";
    const ro = !A.can("operate"), llm = st.meta.llm;
    const parts = [];
    if (en.pending_count) parts.push(`영문 미번역 <b>${en.pending_count}</b>건 — 보고서에는 <code>(KO) 원문</code>으로 표시됩니다`);
    if ((en.stale || []).length) parts.push(`한국어를 고친 뒤 영문이 이전 내용입니다: <b>${esc(en.stale.join(", "))}</b>`);
    if (en.error) parts.push(`자동 번역 실패: ${esc(en.error)}`);
    if (!parts.length) return `<p class="small good sr-enok">영문 병기 준비됨 — 제품이 만든 문구는 규칙으로, 사람이 쓴 글은 ${d.translated ? "AI 번역" : "직접 입력"}으로 영문화${d.translated ? ` (${fmt(d.translated.ts)})` : ""}. 영문 칸을 고치면 그대로 씁니다.</p>`;
    return `<div class="sr-enwarn small">${parts.join("<br>")}${en.pending && en.pending.length ? `<details><summary>미번역 문구 보기</summary><ul>${en.pending.slice(0, 20).map(t => `<li>${esc(t.slice(0, 160))}</li>`).join("")}</ul></details>` : ""}
      ${ro ? "" : llm ? `<div class="sr-ma">${en.pending_count ? `<button class="btn-sm ai" data-sra="translate">AI로 영문 번역</button>` : ""}${(en.stale || []).length ? `<button class="btn-sm ai" data-sra="translate-stale">낡은 영문 다시 번역</button>` : ""}</div>`
        : `<div class="muted">AI 가 꺼져 있습니다 — 영문 칸(제목·요약·업무 영향·요청 사항)에 직접 입력하세요.</div>`}</div>`;
  }
  function collect() {
    const box = $("#sr-body"), p = {};
    $$("[data-f]", box).forEach(el => { const k = el.dataset.f; p[k] = ["requests", "requests_en", "checked_extra"].includes(k) ? el.value.split("\n").map(x => x.trim()).filter(Boolean) : el.value; });
    p.vendor_fields = {}; $$("[data-vf]", box).forEach(el => { p.vendor_fields[el.dataset.vf] = el.value; });
    p.email = {}; $$("[data-em]", box).forEach(el => { p.email[el.dataset.em] = el.value; });
    p.contact = {}; $$("[data-ct]", box).forEach(el => { p.contact[el.dataset.ct] = el.value; });
    p.severity = Number(p.severity);
    return p;
  }
  async function save(extra = {}) {
    const p = {...collect(), ...extra};
    if (p.vendor !== st.d.data.vendor) delete p.vendor_fields;                // 벤더를 바꾸면 그 양식 기본값으로 다시 채움
    try { st.d = await A.api("PUT", `/api/support/requests/${encodeURIComponent(st.sel)}`, p); st.dirty = false; await loadList(); render(); A.ok("저장", st.sel); }
    catch (e) { A.fail("저장 실패", e); }
  }
  async function profileEdit() {
    const p = st.meta.profile;
    const F = [["company", "회사(기관)"], ["contact_name", "담당자 이름"], ["contact_email", "담당자 이메일"], ["contact_phone", "전화"], ["secondary_contact", "보조 연락처"],
      ["availability", "연락 가능 시간"], ["to", "기본 받는 사람(To) — 예: 담당 SAM/TAM·파트너"], ["cc", "기본 참조(Cc)"], ["broadcom_site_id", "Broadcom Site ID"],
      ["aws_account_id", "AWS 계정 ID"], ["azure_subscription", "Azure 구독 ID"]];
    const v = await A.modal({title: "SR 기본 정보", wide: true, html: `<p class="small muted">새 SR 의 연락처·받는 사람·포털 입력값(Site ID 등) 기본값입니다.</p>`,
      fields: [...F.map(([k, l]) => ({id: k, label: l, value: p[k] || ""})),
        {id: "default_vendor", label: "기본 제출 대상", type: "select", value: p.default_vendor, options: Object.entries(st.meta.vendors).map(([k, x]) => [k, x.label])},
        {id: "default_lang", label: "기본 언어", type: "select", value: p.default_lang, options: [["both", "한국어 + English(병기)"], ["ko", "한국어"], ["en", "English"]]},
        {id: "share_days", label: "공유 링크 기본 유효 기간(일)", type: "number", value: p.share_days, min: 1, max: 90}]});
    if (!v) return;
    try { st.meta.profile = await A.api("PUT", "/api/support/profile", v); A.ok("저장", "SR 기본 정보"); } catch (e) { A.fail("저장 실패", e); }
  }
  async function refine() {
    const b = $("[data-sra='refine']"); if (b) { b.disabled = true; b.innerHTML = `<span class="spin"></span> 다듬는 중…`; }
    let r;
    try { r = await A.api("POST", `/api/support/requests/${encodeURIComponent(st.sel)}/refine`, {}); }
    catch (e) { A.fail("AI 다듬기 실패", e); render(); return; }
    const p = r.proposal;
    const row = (l, a, b2) => `<tr><th>${l}</th><td><div class="muted small">현재</div>${esc(a || "")}<div class="muted small" style="margin-top:6px">제안</div><b>${esc(b2 || "")}</b></td></tr>`;
    const d = st.d.data;
    const ok = await A.modal({title: "AI 제안 — 적용할까요?", wide: true, ok: "적용", html: `<table class="vc-t">${row("제목", d.title, p.title)}${row("요약", d.summary, p.summary)}${row("업무 영향", d.impact, p.impact)}
      ${row("요청 사항", (d.requests || []).join(" / "), (p.requests || []).join(" / "))}
      ${p.title_en ? row("Title (EN)", d.title_en, p.title_en) + row("Summary (EN)", d.summary_en, p.summary_en) + row("Impact (EN)", d.impact_en, p.impact_en) + row("Requests (EN)", (d.requests_en || []).join(" / "), (p.requests_en || []).join(" / ")) : ""}</table><p class="small muted">AI 는 주어진 근거만 쓰도록 지시했지만, 보내기 전에 사실 여부를 확인하세요.</p>`});
    if (ok === null) { render(); return; }
    const ap = {title: p.title || d.title, summary: p.summary || d.summary, impact: p.impact || d.impact, requests: p.requests || d.requests};
    if (p.title_en) Object.assign(ap, {title_en: p.title_en, summary_en: p.summary_en || d.summary_en, impact_en: p.impact_en || d.impact_en, requests_en: p.requests_en || d.requests_en});
    await save(ap);
  }
  const copy = async t => { try { await navigator.clipboard.writeText(t); A.ok("복사", "클립보드에 복사했습니다."); } catch { A.toast("복사 실패", "브라우저가 클립보드 접근을 막았습니다 — 직접 선택해 복사하세요.", "warning"); } };

  function wire() {
    const box = $("#sr-body"); if (!box || box.dataset.wired) return; box.dataset.wired = "1";
    box.addEventListener("input", e => { if (e.target.closest(".sr-form")) { if (!st.dirty) { st.dirty = true; const s = $("[data-sra='save']"); if (s) s.disabled = false; const t = $(".sr-tabs"); if (t && !t.querySelector(".om-warn")) t.insertAdjacentHTML("beforeend", `<span class="small om-warn">저장하지 않은 변경 — 미리보기는 저장 후 반영</span>`); } } });
    box.addEventListener("change", e => { if (e.target.matches("[data-f='vendor'],[data-f='severity'],[data-f='lang']") && !e.target.disabled) save(); });
    box.addEventListener("click", async e => {
      const it = e.target.closest("[data-sr]"); if (it) { if (st.dirty && !(await A.confirm("저장하지 않은 변경", "변경 내용을 버리고 다른 SR 을 열까요?"))) return; return loadOne(it.dataset.sr); }
      const t = e.target.closest("[data-srt]"); if (t) { st.tab = t.dataset.srt; $(".sr-tab").innerHTML = tabBody(); $$(".sr-tabs button").forEach(b => b.classList.toggle("on", b.dataset.srt === st.tab)); return; }
      const d1 = e.target.closest("[data-dl]"); if (d1) { if (st.dirty) await save(); return dl(d1.dataset.dl); }
      const cp = e.target.closest("[data-copy]"); if (cp) { const k = cp.dataset.copy; return copy(k === "subj" ? st.d.email.subject : k === "body" ? st.d.email.body : st.shareUrl); }
      const rv = e.target.closest("[data-revoke]"); if (rv) { if (!(await A.confirm("공유 링크 폐기", "이 링크로는 더 이상 열 수 없습니다.", true))) return;
        try { await A.api("DELETE", `/api/support/requests/${encodeURIComponent(st.sel)}/share/${rv.dataset.revoke}`); await loadOne(st.sel); st.tab = "share"; render(); } catch (err) { A.fail("폐기 실패", err); } return; }
      const inc = e.target.closest("[data-inc]"); if (inc) { e.preventDefault(); if (window.AIOPS_OPEN_INCIDENT) window.AIOPS_OPEN_INCIDENT(inc.dataset.inc); return; }
      const a = e.target.closest("[data-sra]"); if (!a) return;
      const k = a.dataset.sra;
      if (k === "new") return srNew({kind: "manual"});
      if (k === "profile") return profileEdit();
      if (k === "save") return save();
      if (k === "refine") return refine();
      if (k === "translate" || k === "translate-stale") { if (st.dirty) await save(); a.disabled = true; a.innerHTML = `<span class="spin"></span> 번역 중…`;
        try { st.d = await A.api("POST", `/api/support/requests/${encodeURIComponent(st.sel)}/translate`, {stale: k === "translate-stale"}); A.ok("영문 번역", `${st.d.result.translated}건 번역 · 남은 미번역 ${st.d.result.pending}건`); }
        catch (err) { A.fail("영문 번역 실패", err); } return render(); }
      if (k === "logs-custom") { const lq = st.d.data.log_query || {}; return logsExport({since: lq.since, until: lq.until, host: (lq.hosts || []).join(","), connector: (lq.connectors || []).join(","),
        entity: (lq.entities || []).join(","), name: st.sel, title: `${st.sel} 의 로그 조건으로 받습니다.`}); }
      if (k === "refresh") { a.disabled = true; a.innerHTML = `<span class="spin"></span> 모으는 중…`;
        try { st.d = await A.api("POST", `/api/support/requests/${encodeURIComponent(st.sel)}/refresh`, {}); A.ok("근거 갱신", st.sel); } catch (err) { A.fail("근거 갱신 실패", err); } return render(); }
      if (k === "del") { if (!(await A.confirm("SR 삭제", `${st.sel} 을(를) 지웁니다. 공유 링크도 모두 폐기됩니다.`, true))) return;
        try { await A.api("DELETE", `/api/support/requests/${encodeURIComponent(st.sel)}`); st.sel = ""; st.d = null; await loadList(); render(); } catch (err) { A.fail("삭제 실패", err); } return; }
      if (k === "share") {
        try { const r = await A.api("POST", `/api/support/requests/${encodeURIComponent(st.sel)}/share`, {days: Number($("#sh-days").value || 7), include_logs: $("#sh-logs").checked, require_login: $("#sh-login").checked});
          const url = r.url; await loadOne(st.sel); st.shareUrl = url; st.tab = "share"; render(); } catch (err) { A.fail("링크 만들기 실패", err); }
      }
    });
  }
  async function show(id) {
    await openDrawer(); wire(); await loadList();
    if (id) await loadOne(id); else render();
  }
  const nav = document.getElementById("nav-sr");
  if (nav) nav.onclick = () => show(st.sel);
  window.AIOPS_SR_NEW = srNew;
  window.AIOPS_SR_OPEN = show;
  window.AIOPS_LOGS_EXPORT = logsExport;
})();
