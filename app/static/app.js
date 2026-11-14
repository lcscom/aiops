(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const SEV = {debug:0, info:1, warning:2, error:3, critical:4};
  const SRC_COLOR = {vcenter:"#0072a3", esxi:"#1a5c86", sddc:"#6a3fa0", nsx:"#00796b", vcfops:"#c25400", vcflogs:"#8a6d00",
    vcfa:"#b5197b", srm:"#3c8500", avi:"#00809d", redfish:"#a3401a", syslog:"#565656", vm:"#5d3fa0", ingest:"#5d3fa0", snmp:"#4d4d4d", network:"#00567a", storage:"#7a5c00",
    "nsx-edge":"#00a38f", vks:"#1d6fd1", "vks-supervisor":"#0a3d91", aiops:"#8c8c8c"};
  const MAX_ROWS = 2500;
  const CAN = p => !window.AIOPS || !window.AIOPS.me || window.AIOPS.can(p);
  const p2 = n => String(n).padStart(2, "0");
  const fmtT = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
  const fmtDT = ts => { const d = new Date(ts * 1000); return `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${fmtT(ts)}`; };

  const st = {
    logs: [], anomalies: new Map(), sources: new Set(), off: new Set(),
    paused: false, pausedBuf: [], minSev: "debug", q: "", qRx: null, flagOnly: false,
    af: "open", connectors: [], eps: [], chatAid: null, alertsSeen: 0,
  };
  window.AIOPS_STATE = st;                   // knowledge.js(관련 문서)에서 이상징후 참조

  // ------------------------------------------------------------ 실시간 스트림(core.js A.stream — 재접속·하트비트·재동기화)
  function onWs(m) {
    if (m.type === "snapshot") {
      st.logs = []; $("#loglist").innerHTML = "";
      addLogs(m.data.logs, false);
      st.anomalies.clear(); m.data.anomalies.forEach(a => st.anomalies.set(a.id, a));
      renderAnoms(); status(m.data.status);
    } else if (m.type === "logs") addLogs(m.data, true);
    else if (m.type === "anomaly") { st.anomalies.set(m.data.id, m.data); scheduleAnoms(); }
    else if (m.type === "status") status(m.data);
    else if (m.type === "alert") alertToast(m.data);
    window.dispatchEvent(new CustomEvent("aiops:ws", {detail: m}));   // enterprise.js(인시던트·조치) 구독
  }
  function onWsState(state, info) {
    const dot = $(".brand .dot"); if (!dot) return;
    dot.classList.toggle("off", state !== "live");
    dot.classList.toggle("warn", state === "resync" || state === "stale");
    const secs = info.downSince ? Math.round((Date.now() - info.downSince) / 1000) : 0;
    dot.title = state === "live" ? "실시간 연결" : state === "resync" ? "누락 감지 — 재동기화 중"
      : `실시간 연결 끊김 ${secs}초 — 재연결 중(화면 정보가 최신이 아닐 수 있음)`;
    const bar = $("#ws-banner");
    if (bar) { bar.hidden = state === "live" || secs < 5; bar.textContent = dot.title; }
  }
  // ------------------------------------------------------------ 로그 스트림
  function visible(e) {
    if (st.off.has(e.source)) return false;
    if (SEV[e.severity] < SEV[st.minSev]) return false;
    if (st.flagOnly && !e.flagged) return false;
    if (st.q) {
      const hay = `${e.host} ${e.entity} ${e.message} ${e.connector}`;
      if (st.qRx ? !st.qRx.test(hay) : !hay.toLowerCase().includes(st.q)) return false;
    }
    return true;
  }
  function rowHtml(e, fresh) {
    const c = SRC_COLOR[e.source] || "#565656";
    return `<div class="row ${e.flagged ? "flag" : ""} sev-${e.severity} ${fresh ? "new" : ""}" ${e.anomaly_id ? `data-aid="${e.anomaly_id}"` : ""} title="${esc(e.connector)} · score ${e.score}${e.reasons?.length ? " · " + esc(e.reasons.join(", ")) : ""}">
      <span class="t">${fmtT(e.ts)}</span><span class="src" style="color:${c}">${esc(e.source)}</span>
      <span class="sev ${e.severity}">${e.severity}</span><span class="h">${esc(e.host)}${e.entity ? " · " + esc(e.entity) : ""}</span>
      <span class="m">${esc(e.message)}</span></div>`;
  }
  function addLogs(list, fresh) {
    for (const e of list) { if (!st.sources.has(e.source)) { st.sources.add(e.source); renderSrcFilters(); } }
    st.logs.push(...list);
    if (st.logs.length > MAX_ROWS * 2) st.logs = st.logs.slice(-MAX_ROWS);
    if (st.paused) { st.pausedBuf.push(...list); $("#paused-n").textContent = `일시정지 중 ${st.pausedBuf.length}건 대기`; return; }
    appendRows(list.filter(visible), fresh);
  }
  function appendRows(list, fresh) {
    const box = $("#loglist");
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
    box.insertAdjacentHTML("beforeend", list.map(e => rowHtml(e, fresh)).join(""));
    // 위로 올려 읽는 중이면 위쪽 줄을 지우지 않는다(2배까지) — 지울 때는 지운 높이만큼 되돌려 보던 줄이 제자리에 있게
    const cap = atBottom ? MAX_ROWS : MAX_ROWS * 2;
    let cut = 0;
    while (box.childElementCount > cap) { cut += box.firstElementChild.offsetHeight; box.firstElementChild.remove(); }
    if (atBottom) box.scrollTop = box.scrollHeight;
    else if (cut) box.scrollTop = Math.max(0, box.scrollTop - cut);
    $("#log-count").textContent = box.childElementCount.toLocaleString();
  }
  function rerender() {
    $("#loglist").innerHTML = "";
    appendRows(st.logs.filter(visible).slice(-MAX_ROWS), false);
  }
  function renderSrcFilters() {
    $("#src-filters").innerHTML = [...st.sources].sort().map(s =>
      `<button data-src="${esc(s)}" class="${st.off.has(s) ? "" : "on"}" style="color:${SRC_COLOR[s] || "#565656"}">${esc(s)}</button>`).join("");
  }
  $("#src-filters").addEventListener("click", e => {
    const b = e.target.closest("button"); if (!b) return;
    const s = b.dataset.src;
    if (e.altKey || e.metaKey) { st.off = new Set([...st.sources].filter(x => x !== s)); }  // Alt+클릭: 단독 보기
    else st.off.has(s) ? st.off.delete(s) : st.off.add(s);
    renderSrcFilters(); rerender();
  });
  $("#btn-logdl").onclick = () => {                     // 2.11.0 지금 필터 그대로 파일로
    const raw = $("#f-q").value.trim(), on = [...st.sources].filter(s => !st.off.has(s));
    const p = {min_severity: st.minSev, name: "aiops-logs", title: "실시간 로그 화면의 필터(소스·등급·문자열)로 받습니다."};
    if (st.off.size && on.length) p.source = on.join(",");
    if (raw && !/^\/.*\/$/.test(raw)) { if (/^[\w.-]+$/.test(raw) && /[.-]|\d/.test(raw)) p.host = raw; else p.q = raw; }
    if (window.AIOPS_LOGS_EXPORT) window.AIOPS_LOGS_EXPORT(p);
  };
  $("#f-sev").onchange = e => { st.minSev = e.target.value; rerender(); };
  let qT; $("#f-q").oninput = e => { clearTimeout(qT); qT = setTimeout(() => {
    const v = e.target.value.trim(); st.qRx = null; st.q = v.toLowerCase();
    const m = v.match(/^\/(.+)\/([a-z]*)$/); if (m) { try { st.qRx = new RegExp(m[1], m[2] || "i"); } catch {} }
    rerender(); }, 200); };
  $("#f-flag").onchange = e => { st.flagOnly = e.target.checked; rerender(); };
  $("#btn-pause").onclick = e => {
    st.paused = !st.paused; e.target.textContent = st.paused ? "재개" : "일시정지";
    if (!st.paused) { appendRows(st.pausedBuf.filter(visible), true); st.pausedBuf = []; $("#paused-n").textContent = ""; }
  };
  $("#btn-clear").onclick = () => { $("#loglist").innerHTML = ""; st.logs = []; $("#log-count").textContent = 0; };
  $("#loglist").addEventListener("click", e => {
    const r = e.target.closest(".row[data-aid]"); if (!r) return;
    const card = $(`.acard[data-id="${r.dataset.aid}"]`);
    if (!card) { st.af = "all"; $$(".tabs button").forEach(b => b.classList.toggle("on", b.dataset.af === "all")); renderAnoms(); }
    showPane("anoms");
    const c2 = $(`.acard[data-id="${r.dataset.aid}"]`); if (c2) { window.AIOPS.reveal(c2, {block: "center"}); c2.animate([{outline:"2px solid #0072a3"},{outline:"0"}], 1500); }
  });

  // ------------------------------------------------------------ 이상 징후
  let anomT; const scheduleAnoms = () => { clearTimeout(anomT); anomT = setTimeout(renderAnoms, 150); };
  const STATUS_TXT = {queued:"AI 분석 대기", analyzing:"Gemma 4 분석 중", analyzed:"AI 분석 완료", llm_error:"AI 분석 실패",
                      rule_only:"규칙 탐지(LLM 비활성)", llm_skipped:"AI 분석 생략 — 규칙 판정"};
  // AI 근거가 없는 카드(규칙 판정·AI 오류·생략)에도 자동 연결 KB 를 보여 줌
  const relKb = a => window.AIOPS_KNOW && (a.related || []).length ? window.AIOPS_KNOW.refs({}, a) : "";
  function cardHtml(a) {
    const e = a.event, ai = a.ai || {};
    const busy = a.status === "queued" || a.status === "analyzing";
    const notAnom = ai.is_anomaly === false;
    let aiHtml = "";
    if (a.status === "analyzed" && !ai.error) {
      aiHtml = `<div class="ai">
        ${notAnom ? `<p><span class="lab">AI 판정</span>정상/정보성 로그로 판단</p>` : ""}
        ${ai.summary ? `<p><span class="lab">요약</span>${esc(ai.summary)}</p>` : ""}
        ${ai.probable_cause ? `<p><span class="lab">추정 원인</span>${window.AIOPS_KNOW ? window.AIOPS_KNOW.mdLite(String(ai.probable_cause), ai.references || []) : esc(ai.probable_cause)}</p>` : ""}
        ${ai.impact ? `<p><span class="lab">영향</span>${esc(ai.impact)}</p>` : ""}
        ${Array.isArray(ai.actions) && ai.actions.length ? `<p><span class="lab">조치</span></p><ol>${ai.actions.map(x => `<li>${window.AIOPS_KNOW ? window.AIOPS_KNOW.mdLite(String(x), ai.references || []) : esc(x)}</li>`).join("")}</ol>` : ""}
        ${window.AIOPS_KNOW ? window.AIOPS_KNOW.refs(ai, a) : ""}
        ${ai.confidence != null ? `<p class="conf">신뢰도 ${Math.round(Number(ai.confidence) * 100)}%</p>` : ""}
        ${ai.shared_from ? `<p class="conf">같은 로그 패턴의 대표 분석을 공유함(${esc(ai.shared_title || ai.shared_from)})</p>` : ai.shared_count ? `<p class="conf">분석 공유: 같은 로그 패턴 ${ai.shared_count}건</p>` : ""}</div>`;
    } else if (ai.skipped) aiHtml = `<div class="ai"><p class="conf">AI 분석 생략: ${esc(ai.error)} — 규칙 탐지 결과로 알림·인시던트 처리됨. 필요하면 '재분석'.</p>${relKb(a)}</div>`;
    else if (ai.coalesced && busy) aiHtml = `<div class="ai"><p class="conf">같은 로그 패턴의 대표 1건만 분석 대기 중 — 결과를 공유받습니다</p></div>`;
    else if (ai.error) aiHtml = `<div class="ai"><p class="conf">AI 오류: ${esc(ai.error)}</p>${relKb(a)}</div>`;
    else if ((a.related || []).length) aiHtml = `<div class="ai">${relKb(a)}</div>`;
    return `<div class="acard ${a.severity} ${a.ack ? "ack" : ""} ${notAnom ? "notanom" : ""}" data-id="${a.id}">
      <div class="hd"><span class="label solid ${a.severity}">${a.severity}</span><span class="label">${esc(a.category)}</span>
        ${a.count > 1 ? `<span class="badge">×${a.count}</span>` : ""}
        <span style="color:${SRC_COLOR[e.source] || "#565656"}">${esc(e.source)}</span> · ${esc(e.connector)} · ${fmtDT(a.last_seen)}
        ${a.incident_id ? `<a class="inc-link" data-inc="${esc(a.incident_id)}">${esc(a.incident_id)}</a>` : ""}</div>
      ${a.suppressed ? `<div class="supp">알림 억제 — ${esc(a.suppressed)}</div>` : ""}
      <h4>${esc(a.title)}</h4>
      <div class="raw">${esc(e.host)}${e.entity ? " / " + esc(e.entity) : ""}\n${esc(e.message)}</div>
      <div class="status">${busy ? '<span class="spin"></span>' : ""}${STATUS_TXT[a.status] || esc(a.status)} · score ${a.score}</div>
      ${aiHtml}
      <div class="reasons">${(a.reasons || []).map(r => `<span>${esc(r)}</span>`).join("")}</div>
      <div class="btns">${a.ack || !CAN("operate") ? "" : `<button data-act="ack">확인 처리</button>`}
        <button data-act="logs">관련 로그</button><button data-act="kb" title="KB·TechDocs 라이브러리에서 이 로그와 맞는 문서">관련 문서</button><button data-act="ask">AI에게 질문</button>
        ${busy || !CAN("operate") ? "" : `<button data-act="re">재분석</button>`}${CAN("operate") ? `<button data-act="sr" title="이 이상징후로 벤더 SR 보고서·이메일 초안 만들기">SR 초안</button>` : ""}
        ${CAN("operate") && !a.suppressed ? `<button data-act="silence">사일런스</button>` : ""}</div></div>`;
  }
  function renderAnoms() {
    let list = [...st.anomalies.values()].sort((a, b) => b.last_seen - a.last_seen);
    const open = list.filter(a => !a.ack && a.ai?.is_anomaly !== false);
    $("#k-open").textContent = open.length;
    const kb = $("#k-open").closest(".kpi"); if (kb) { kb.classList.toggle("hot", open.length > 0); kb.classList.toggle("calm", !open.length); }
    $("#mt-count").textContent = open.length ? `(${open.length})` : "";
    if (st.af === "open") list = open;
    else if (st.af === "crit") list = list.filter(a => a.severity === "critical");
    $("#anomlist").innerHTML = list.length ? list.slice(0, 200).map(cardHtml).join("")
      : `<div class="empty">표시할 이상 징후가 없습니다.<br>수집 중인 로그는 1차 규칙·통계 탐지를 통과하면 이곳에 올라옵니다.</div>`;
  }
  $$(".tabs button").forEach(b => b.onclick = () => { st.af = b.dataset.af; $$(".tabs button").forEach(x => x.classList.toggle("on", x === b)); renderAnoms(); });
  $("#anomlist").addEventListener("click", async e => {
    const il = e.target.closest("[data-inc]");
    if (il) { window.dispatchEvent(new CustomEvent("aiops:open-incident", {detail: il.dataset.inc})); return; }
    const b = e.target.closest("button[data-act]"); if (!b) return;
    const id = b.closest(".acard").dataset.id, a = st.anomalies.get(id);
    if (b.dataset.act === "ack") await fetch(`/api/anomalies/${id}/ack`, {method:"POST"});
    if (b.dataset.act === "re") await fetch(`/api/anomalies/${id}/analyze`, {method:"POST"});
    if (b.dataset.act === "ask") openChat(id);
    if (b.dataset.act === "sr" && window.AIOPS_SR_NEW) window.AIOPS_SR_NEW({kind: "anomaly", ref: id}, {label: a.title});
    if (b.dataset.act === "kb" && window.AIOPS_KNOW) window.AIOPS_KNOW.openForAnomaly(a);
    if (b.dataset.act === "silence") {
      const v = await AIOPS.modal({title: "사일런스 — 같은 유형 알림 억제", html: `<p class="modal-text">${esc(a.title)}<br><small>동일 지문(fingerprint)의 이상징후는 계속 기록되지만 알림·인시던트 생성이 억제됩니다.</small></p>`,
        fields: [{id: "hours", label: "기간", type: "select", value: "4", options: [["1", "1시간"], ["4", "4시간"], ["8", "8시간"], ["24", "1일"], ["72", "3일"], ["168", "7일"]]},
                 {id: "reason", label: "사유", required: true, placeholder: "예) 작업 중 예상된 경고 · CHG0012345"}], ok: "사일런스"});
      if (v) { try { await AIOPS.api("POST", `/api/anomalies/${id}/silence`, {hours: Number(v.hours), reason: v.reason}); AIOPS.ok("사일런스 등록"); } catch (err) { AIOPS.fail("사일런스 실패", err); } }
    }
    if (b.dataset.act === "logs") { $("#f-q").value = a.event.host || a.event.entity; $("#f-q").dispatchEvent(new Event("input")); showPane("logs"); }
  });

  // ------------------------------------------------------------ 상태/커넥터
  function status(s) {
    const ia = s.incidents_active || {}, nInc = Object.values(ia).reduce((x, y) => x + y, 0), ib = $("#inc-badge");
    if (ib) { ib.hidden = !nInc; ib.textContent = nInc; ib.classList.toggle("warnb", !ia.critical && !ia.error); }
    $("#k-eps").textContent = s.stats.eps; $("#k-total").textContent = s.stats.events_total.toLocaleString();
    $("#k-alerts").textContent = s.alerts_sent;
    const l = s.llm || {};
    const el = $("#k-llm-state"), off = s.ai && s.ai.on === false;
    el.textContent = off ? "OFF" : (l.state || "-").toUpperCase() + (l.latency_ms ? ` ${l.latency_ms}ms` : "");
    el.style.color = off ? "#9fb0ba" : {ok:"#8cd34f", degraded:"#ffc300", down:"#ff6b4a"}[l.state] || "#c8d6de";
    $("#k-llm-model").textContent = off ? "규칙 탐지만" : (l.provider ? `${l.provider} · ` : "") + (l.model || "") + (s.queue ? ` · 대기 ${s.queue}` : "") + (s.ai && s.ai.hot ? " · GPU 과열 대기" : "");
    $("#k-llm").title = (l.last_error ? l.last_error + "\n" : "") + "AI 분석 — 눌러서 상태·패턴·공급자 보기";
    window.dispatchEvent(new CustomEvent("aiops:ai", {detail: s.ai || {}}));
    st.eps.push(s.stats.eps); if (st.eps.length > 110) st.eps.shift(); spark();
    st.connectors = s.connectors; renderStrip();
    const cs = s.collection || {};
    if (cs.summary) {
      const ok = (cs.summary.collecting || 0) + (cs.summary.idle || 0), tot = cs.total || 0, bad = cs.problems || 0;
      const v = $("#k-coll-v"); v.textContent = bad ? `문제 ${bad}` : `정상 ${ok}/${tot}`; v.className = bad ? "bad" : "ok";
      const nb = $("#coll-badge"); nb.hidden = !bad; nb.textContent = bad;
    }
    if (!$("#drawer-conn").hidden) renderConnTable();
  }
  function spark() {
    const c = $("#spark"), g = c.getContext("2d"), w = c.width, h = c.height, mx = Math.max(5, ...st.eps);
    g.clearRect(0, 0, w, h); g.strokeStyle = "#0072a3"; g.lineWidth = 1.2; g.beginPath();
    st.eps.forEach((v, i) => { const x = w - (st.eps.length - 1 - i), y = h - 2 - (v / mx) * (h - 4); i ? g.lineTo(x, y) : g.moveTo(x, y); });
    g.stroke();
  }
  function renderStrip() {
    $("#conn-strip").innerHTML = st.connectors.map(c =>
      `<span class="chip ${c.state}" data-name="${esc(c.name)}" title="${esc(c.target)}\n${esc(c.last_error || "")}"><i></i>${esc(c.name)}<small>${c.latency_ms != null ? c.latency_ms + "ms" : ""} ${c.events_total || 0}</small></span>`).join("");
  }
  function renderConnTable(results = {}) {
    $("#conn-table").innerHTML = `<table><thead><tr><th>커넥터</th><th>유형</th><th>대상</th><th>상태</th><th>인증</th><th>지연</th><th>이벤트</th><th>마지막 성공</th><th>점검 결과 / 오류</th><th></th></tr></thead><tbody>
      ${st.connectors.map(c => {
        const ck = (results[c.name]?.checks) || c.checks || {};
        const lines = Object.entries(ck).map(([k, v]) => `<div class="${String(v).startsWith("ok") || v === true ? "" : String(v).startsWith("warn") ? "warn" : "bad"}">${esc(k)}: ${esc(v)}</div>`).join("");
        return `<tr><td><b>${esc(c.name)}</b></td><td>${esc(c.type)}</td><td>${esc(c.target)}</td>
          <td><span class="st ${c.state}">${esc(c.state)}</span></td><td>${esc(c.auth)}</td><td>${c.latency_ms ?? "-"}ms</td>
          <td>${(c.events_total || 0).toLocaleString()}</td><td>${c.last_ok ? fmtT(c.last_ok) : "-"}</td>
          <td><div class="checks">${lines}${c.last_error ? `<div class="bad">${esc(c.last_error)}</div>` : ""}${results[c.name]?.error ? `<div class="bad">${esc(results[c.name].error)}</div>` : ""}</div></td>
          <td><button class="btn-sm" data-test="${esc(c.name)}">테스트</button></td></tr>`;}).join("")}</tbody></table>`;
  }
  $("#conn-strip").onclick = () => openConn();
  $("#btn-conn").onclick = () => openConn();
  function openConn() {                     // 운영 설정 권한이 있으면 통합 커넥터 화면(등록·자동 발견·수신기·상태·시험)으로
    if (AIOPS.can("settings") && window.AIOPS_OPEN_CONNECTORS) { window.AIOPS_OPEN_CONNECTORS(); return; }
    $("#drawer-conn").hidden = false; renderConnTable();
  }
  $("#conn-table").addEventListener("click", async e => {
    const b = e.target.closest("button[data-test]"); if (!b) return;
    b.textContent = "…"; b.disabled = true;
    const r = await (await fetch(`/api/connectors/${encodeURIComponent(b.dataset.test)}/test`, {method:"POST"})).json();
    renderConnTable({[b.dataset.test]: r});
  });
  $("#btn-test-all").onclick = async e => {
    e.target.textContent = "테스트 중…"; e.target.disabled = true;
    const r = await (await fetch("/api/connectors/test-all", {method:"POST"})).json();
    e.target.textContent = "전체 연결 테스트"; e.target.disabled = false; renderConnTable(r);
  };
  $("#btn-alert-test").onclick = async () => { try { const r = await AIOPS.api("POST", "/api/alerts/test"); AIOPS.ok("테스트 알림 발송", JSON.stringify(r)); } catch (e) { AIOPS.fail("알림 테스트 실패", e); } };
  $$("[data-close]").forEach(b => b.onclick = () => b.closest(".drawer").hidden = true);
  $$(".drawer").forEach(d => d.addEventListener("click", e => { if (e.target === d) d.hidden = true; }));
  // Esc — 열린 서랍 닫기(모달이 떠 있으면 모달이 먼저, 입력 중인 글자는 건드리지 않음)
  document.addEventListener("keydown", e => {
    if (e.key !== "Escape" || document.querySelector(".modal")) return;
    const open = $$(".drawer").filter(x => !x.hidden); if (!open.length) return;
    open[open.length - 1].hidden = true;
  });

  // ------------------------------------------------------------ 알림
  $("#btn-notify").onclick = () => "Notification" in window && Notification.requestPermission();
  let audio;
  function beep(sev) {
    try {
      audio = audio || new AudioContext(); const o = audio.createOscillator(), g = audio.createGain();
      o.frequency.value = sev === "critical" ? 880 : 620; g.gain.value = 0.06; o.connect(g); g.connect(audio.destination);
      o.start(); o.stop(audio.currentTime + 0.18);
    } catch {}
  }
  function alertToast(a) {
    const t = document.createElement("div");
    t.className = `toast ${a.severity}`; t.innerHTML = `<b>${esc(a.title)}</b><pre>${esc(a.body)}</pre>`;
    t.onclick = () => { t.remove(); const c = $(`.acard[data-id="${a.anomaly_id}"]`); showPane("anoms"); c && setTimeout(() => window.AIOPS.reveal(c, {block: "center"}), 30); };
    $("#toasts").prepend(t); setTimeout(() => t.remove(), a.severity === "critical" ? 30000 : 12000);
    while ($("#toasts").childElementCount > 4) $("#toasts").lastElementChild.remove();
    beep(a.severity);
    if ("Notification" in window && Notification.permission === "granted" && document.hidden)
      new Notification(a.title, {body: a.body.slice(0, 240), tag: a.anomaly_id});
  }

  // ------------------------------------------------------------ AI 질의
  function openChat(aid) {
    st.chatAid = aid || null;
    const a = aid && st.anomalies.get(aid);
    $("#chat-ctx").textContent = a ? `— ${a.title}` : "— 최근 이상징후·로그 기반";
    document.querySelectorAll(".drawer").forEach(d => { if (d.id !== "drawer-chat") d.hidden = true; });   // 다른 창(VKS 등) 뒤에 가려지지 않게
    $("#drawer-chat").hidden = false; $("#chat-q").focus();
    if (a && !$("#chat-q").value) $("#chat-q").value = "이 이상징후의 근본 원인과 확인 순서, 연관된 다른 이상이 있는지 알려줘.";
  }
  $("#btn-chat").onclick = () => openChat(null);
  $("#nav-chat").onclick = () => openChat(null);
  $("#btn-alert-test-nav").onclick = () => $("#btn-alert-test").click();
  // 세로 내비 활성 표시: 패널이 닫히면 대시보드로 복귀
  const navOn = k => $$(".vnav a[data-nav]").forEach(a => a.classList.toggle("on", a.dataset.nav === k));
  new MutationObserver(() => { const d = $$(".drawer").find(x => !x.hidden); navOn(d ? d.id.replace("drawer-", "") : "dash"); })
    .observe(document.body, {subtree:true, attributes:true, attributeFilter:["hidden"]});
  $("#chat-form").onsubmit = async e => {
    e.preventDefault();
    const q = $("#chat-q").value.trim(); if (!q) return;
    $("#chat-q").value = "";
    const log = $("#chat-log");
    log.insertAdjacentHTML("beforeend", `<div class="msg q">${esc(q)}</div>`);
    const out = document.createElement("div"); out.className = "msg a"; out.textContent = "…"; log.append(out);
    log.scrollTop = log.scrollHeight;                              // 방금 보낸 질문은 보이게, 이후 답변은 아래에 붙어 있을 때만 따라감
    // 2.36.0 스트림 오류 처리 — 네트워크 끊김·서버 오류·중간 종료를 답변 칸에 표시하고, 답변 중에는 다시 보내지 않게 막는다
    const btn = $("#chat-form").querySelector("button[type=submit],button:not([type])");
    if (btn) btn.disabled = true;
    let txt = "", refs = [], meta = {}, ended = false;
    try {
      const ctl = new AbortController(); st.chatAbort = ctl;
      const r = await fetch("/api/chat", {method:"POST", signal: ctl.signal, headers:{"Content-Type":"application/json", "X-Requested-With": "XMLHttpRequest"},
        body: JSON.stringify({question:q, anomaly_id: st.chatAid, lang: (window.AIOPS_I18N || {}).lang || "ko",
        web: $("#chat-web") && $("#chat-web").dataset.touched ? $("#chat-web").checked : null})});
      if (!r.ok) {
        let m = await r.text(); try { m = JSON.parse(m).detail || m; } catch {}
        out.textContent = r.status === 401 ? "로그인이 만료되었습니다 — 다시 로그인하세요." : r.status === 429 ? "요청이 많습니다 — 잠시 뒤 다시 시도하세요." : `오류 ${r.status}: ${String(m).slice(0, 300)}`;
        out.classList.add("err"); return;
      }
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = "";
      for (;;) {
        const {done, value} = await rd.read(); if (done) break;
        buf += dec.decode(value, {stream:true});
        const parts = buf.split("\n\n"); buf = parts.pop();
        for (const p of parts) {
          const d = p.replace(/^data:\s*/, ""); if (d === "[DONE]") { ended = true; continue; }
          try { const j = JSON.parse(d); if (j.refs) { refs = j.refs; meta = j; continue; } if (j.t) txt += j.t; if (j.error) { txt += `\n[오류] ${j.error}`; ended = true; } } catch {}
          const stick = window.AIOPS.nearBottom(log); out.textContent = txt.replace(/<think>[\s\S]*?<\/think>/g, ""); window.AIOPS.stick(log, stick);
        }
      }
      if (!ended) txt += txt ? "\n\n[연결이 끊겨 답변이 중간에 멈췄습니다 — 다시 질문하세요]" : "[응답 없이 연결이 끊겼습니다 — AI 공급자 상태(운영 설정 › AI)를 확인하세요]";
    } catch (e) {
      txt += (txt ? "\n\n" : "") + (e && e.name === "AbortError" ? "[중단됨]" : `[네트워크 오류 — ${e && e.message ? e.message : e}]`);
      out.classList.add("err");
    } finally {
      if (btn) btn.disabled = false;
      st.chatAbort = null;
    }
    if (!txt) { out.textContent = "답변이 비어 있습니다."; return; }
    out.textContent = txt.replace(/<think>[\s\S]*?<\/think>/g, "");
    const stickEnd = window.AIOPS.nearBottom(log);
    if (window.AIOPS_KNOW) { out.innerHTML = window.AIOPS_KNOW.mdLite(txt.replace(/<think>[\s\S]*?<\/think>/g, ""), refs); out.classList.add("md"); }
    // 2.6.1 답변이 실제로 인용한 문서와 검색만 된 문서를 나눠 표시 + 질문 대상·실제 검색어
    const cited = new Set((txt.match(/\[(R\d+|I1|W\d+)\]/g) || []).map(x => x.slice(1, -1)));
    const refLink = x => (/^https?:/.test(x.url) ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">[${x.ref}] ${esc(x.title)}</a>` : `[${x.ref}] ${esc(x.title)}`)
      + (x.type === "web" ? ` <small class="chat-dom${x.preferred ? " off" : ""}">${esc(x.domain || "")}</small>` : "")
      + ((x.versions || []).length ? ` <small>(${esc(x.versions.slice(0, 3).join("·"))})</small>` : "")
      + (String(x.doc_id || "").startsWith("lib:") ? ` <a href="#" data-kdoc="${esc(x.doc_id)}" title="문서 전문(구역별)">전문</a>` : "");
    const used = refs.filter(x => cited.has(x.ref)), unused = refs.filter(x => !cited.has(x.ref));
    const ctx = [(meta.entities || []).length ? `질문 대상: <b>${meta.entities.map(esc).join(", ")}</b>` : "",
      (meta.queries || []).length ? `KB 검색어: ${meta.queries.map(q => `<code>${esc(q.slice(0, 80))}</code>`).join(" ")}` : "",
      (meta.web_queries || []).length ? `웹 검색어: ${meta.web_queries.map(q => `<code>${esc(q.slice(0, 80))}</code>`).join(" ")}` : ""].filter(Boolean).join(" · ");
    if (used.length || unused.length || ctx) out.insertAdjacentHTML("beforeend", `<div class="chat-refs">${used.length ? `인용한 근거: ${used.map(refLink).join(" · ")}` : ""}
      ${unused.length ? `<details${used.length ? "" : " open"}><summary>${used.length ? "검색됐지만 인용하지 않은 문서" : "검색된 문서(답변에 인용 안 됨 — 관련성 낮음)"} ${unused.length}</summary>${unused.map(refLink).join(" · ")}</details>` : ""}
      ${!refs.length && (meta.queries || []).length ? `<div class="muted">관련도 기준을 넘는 KB 가 없습니다 — 지식(KB·문서) 화면에서 색인 상태를 확인하세요.</div>` : ""}
      ${ctx ? `<div class="chat-ctx">${ctx}</div>` : ""}</div>`);
    window.AIOPS.stick(log, stickEnd);
  };
  { const w = $("#chat-web"); if (w) { w.addEventListener("change", () => { w.dataset.touched = "1"; });
      window.AIOPS.ready.then(me => me === null ? null : window.AIOPS.api("GET", "/api/web_search/status", undefined, {background: true})).then(s => { if (!s) return; const lb = w.closest("label");
        if (!s.enabled) { w.disabled = true; lb.title = "웹 검색 꺼짐 — 운영 설정 › 웹 검색에서 공급자(SearXNG·Brave·Tavily) 설정"; lb.classList.add("off"); }
        else { w.checked = s.mode === "always"; lb.title += ` · 모드 ${s.mode === "auto" ? "자동(사내 KB 근거 부족 시)" : s.mode === "always" ? "항상" : "수동"}`; } }).catch(() => {}); } }
  $("#chat-q").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#chat-form").requestSubmit(); } });

  // ------------------------------------------------------------ 수집 현황
  const coll = {scope: "all", kind: "", q: "", tile: "", timer: null, data: null};
  const KIND = {conn: "API 커넥터", syslog: "Syslog", snmp: "SNMP 트랩", ingest: "HTTP 수집", recv: "수신기"};
  const BAD = new Set(["delayed", "stopped", "down", "never"]);
  const TILE = [["collecting", "수집 중"], ["idle", "정상·신규 없음"], ["delayed", "지연"], ["stopped", "중단"], ["down", "오류"], ["never", "미수신"]];
  const ago = sec => sec == null ? "-" : sec < 60 ? `${Math.round(sec)}초 전` : sec < 3600 ? `${Math.floor(sec / 60)}분 전` : sec < 86400 ? `${Math.floor(sec / 3600)}시간 전` : `${Math.floor(sec / 86400)}일 전`;
  function sparkSvg(arr, status) {
    if (!arr || !arr.length) return '<span style="color:var(--muted)">-</span>';
    const w = 120, h = 22, bw = w / arr.length, mx = Math.max(1, ...arr);
    const col = BAD.has(status) ? "#c21d00" : status === "collecting" ? "#0072a3" : "#8c8c8c";
    return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-label="최근 30분 분당 유입">` +
      arr.map((v, i) => { const bh = v ? Math.max(2, v / mx * (h - 2)) : 1; return `<rect x="${(i * bw + .5).toFixed(1)}" y="${(h - bh).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${bh.toFixed(1)}" fill="${v ? col : "#dcdcdc"}"/>`; }).join("") + "</svg>";
  }
  async function loadColl() {
    try { coll.data = await (await fetch("/api/collection", {background: true})).json(); } catch { return; }
    renderColl();
  }
  function renderColl() {
    const d = coll.data; if (!d) return;
    $("#coll-sub").textContent = `— ${d.total}개 항목 · 문제 ${d.problems} · '수집 중' 기준 ${d.active_window >= 60 ? Math.round(d.active_window / 60) + "분" : d.active_window + "초"} 내 수신 · ${fmtT(d.generated)} 갱신`;
    $("#coll-tiles").innerHTML = TILE.map(([k, l]) => `<div class="ctile ${k} ${coll.tile === k ? "on" : ""}" data-t="${k}"><span>${l}</span><b>${d.summary[k] || 0}</b></div>`).join("");
    const q = coll.q.toLowerCase();
    const rows = d.items.filter(r => (coll.scope === "all" || BAD.has(r.status)) && (!coll.kind || r.kind === coll.kind)
      && (!coll.tile || r.status === coll.tile) && (!q || `${r.name} ${r.target} ${r.source}`.toLowerCase().includes(q)));
    $("#coll-rows").innerHTML = rows.length ? rows.map(r => `<tr data-name="${esc(r.name)}">
      <td><span class="st-badge ${r.status}"><i></i>${esc(r.label)}</span>${r.expected ? '<span class="sub">기대 장비</span>' : ""}</td>
      <td><b>${esc(r.name)}</b>${r.target && r.target !== r.name ? `<span class="sub">${esc(r.target)}</span>` : ""}</td>
      <td><span class="kindtag">${KIND[r.kind] || r.kind}</span>${r.kind === "conn" && r.api ? `<span class="sub">API ${esc(r.api)}${r.latency_ms != null ? " · " + r.latency_ms + "ms" : ""}</span>` : ""}</td>
      <td><span style="color:${SRC_COLOR[r.source] || "#565656"};font-weight:600">${esc(r.source || "-")}</span></td>
      <td title="${r.last ? fmtDT(r.last) : ""}">${ago(r.ago)}${r.kind === "conn" && r.last_poll ? `<span class="sub">폴링 ${ago(d.generated - r.last_poll)}</span>` : ""}${r.max_silence ? `<span class="sub">허용 ${Math.round(r.max_silence / 60)}분</span>` : ""}</td>
      <td class="r">${r.rate1 == null ? "-" : `${r.rate1} / ${r.rate15}`}</td>
      <td>${sparkSvg(r.spark, r.status)}</td>
      <td class="r">${(r.total || 0).toLocaleString()}</td>
      <td class="r" style="${r.err15 ? "color:var(--crit);font-weight:600" : ""}">${r.err15 || 0}</td>
      <td class="why">${esc(r.reason || "")}${r.last_msg ? `<span class="m" title="${esc(r.last_msg)}">${esc(r.last_msg)}</span>` : ""}</td></tr>`).join("")
      : `<tr><td colspan="10"><div class="empty">조건에 맞는 항목이 없습니다.</div></td></tr>`;
  }
  function openColl() {
    $("#drawer-coll").hidden = false; loadColl();
    clearInterval(coll.timer); coll.timer = setInterval(() => $("#drawer-coll").hidden ? clearInterval(coll.timer) : loadColl(), 3000);
  }
  $("#nav-coll").onclick = openColl; $("#k-coll").onclick = openColl;
  const grp = (id, key) => $(id).addEventListener("click", e => { const b = e.target.closest("button"); if (!b) return;
    coll[key] = b.dataset.v; $$(`${id} button`).forEach(x => x.classList.toggle("on", x === b)); renderColl(); });
  grp("#coll-scope", "scope"); grp("#coll-kind", "kind");
  $("#coll-tiles").addEventListener("click", e => { const t = e.target.closest(".ctile"); if (!t) return; coll.tile = coll.tile === t.dataset.t ? "" : t.dataset.t; renderColl(); });
  $("#coll-q").oninput = e => { coll.q = e.target.value.trim(); renderColl(); };
  $("#coll-rows").addEventListener("click", e => {          // 항목 클릭 → 실시간 로그를 해당 항목으로 필터
    const tr = e.target.closest("tr[data-name]"); if (!tr) return;
    $("#drawer-coll").hidden = true; $("#f-q").value = tr.dataset.name; $("#f-q").dispatchEvent(new Event("input")); showPane("logs");
  });

  // ------------------------------------------------------------ SNMP 트랩
  let snmpSel = null, snmpTimer;
  function renderSnmp() {
    const traps = st.logs.filter(e => String(e.connector || "").startsWith("snmp")).slice(-500).reverse();
    const conn = (st.connectors || []).find(c => c.type === "snmp");
    const peers = new Set(traps.map(e => (e.attrs || {}).peer));
    $("#snmp-sum").textContent = `— 수신 ${conn ? String(conn.state).toUpperCase() : "비활성"}${conn ? " · " + conn.target + " · " + conn.auth : ""} · 화면 버퍼 ${traps.length}건 · 송신 장비 ${peers.size}`;
    const unk = Object.entries((conn && conn.checks) || {}).filter(([k]) => k.startsWith("미등록 OID"));
    $("#snmp-unknown").innerHTML = unk.length ? `<div class="box"><b>미등록 트랩 OID ${unk.length}건</b> — config.yaml <code>snmp.oid_map</code> 에 이름·심각도를 등록하면 해석 정확도가 올라갑니다.
      <pre>snmp:\n  oid_map:\n${unk.map(([k, v]) => `    "${k.replace("미등록 OID ", "")}": {name: 트랩이름, severity: error, source: redfish}   # ${v}`).join("\n")}</pre></div>` : "";
    $("#snmp-rows").innerHTML = traps.length ? traps.map((e, i) => {
      const a = e.attrs || {};
      return `<tr data-i="${e.id}" class="${snmpSel === e.id ? "sel" : ""}"><td>${fmtT(e.ts)}</td><td><span class="sev ${e.severity}">${e.severity}</span></td>
        <td><span class="src" style="color:${SRC_COLOR[e.source] || "#565656"}">${esc(e.source)}</span></td><td>${esc(a.peer || "")}</td><td>${esc(e.host)}</td>
        <td>${esc(a.snmp_trap || "")}</td><td>${esc(a.vendor || "")}</td><td class="msg" title="${esc(e.message)}">${e.flagged ? "● " : ""}${esc(e.message)}</td></tr>`;
    }).join("") : `<tr><td colspan="8"><div class="empty">아직 수신된 트랩이 없습니다. 장비의 트랩 대상을 이 서버 UDP 162로 지정하세요.</div></td></tr>`;
    if (snmpSel != null) showSnmp(traps.find(e => e.id === snmpSel));
  }
  function showSnmp(e) {
    if (!e) return;
    const a = e.attrs || {};
    const rows = Object.entries(a.varbinds || {}).concat([["snmpTrapOID", a.snmp_trap_oid || ""], ["sysUpTime", a.uptime || ""], ["송신 장비", a.peer || ""]]);
    $("#snmp-detail").innerHTML = `<h4>${esc(a.snmp_trap || "trap")}</h4><div class="status"><span class="sev ${e.severity}">${e.severity}</span> · ${esc(e.source)} · ${fmtDT(e.ts)}${e.anomaly_id ? " · 이상징후 연결됨" : ""}</div>
      <p style="margin:8px 0;color:var(--title)">${esc(e.message)}</p>
      <table><thead><tr><th>이름 / OID</th><th>값</th></tr></thead><tbody>${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td style="font-family:var(--mono)">${esc(v)}</td></tr>`).join("")}</tbody></table>`;
  }
  $("#snmp-rows").addEventListener("click", ev => {
    const tr = ev.target.closest("tr[data-i]"); if (!tr) return;
    snmpSel = Number(tr.dataset.i); renderSnmp();
  });
  $("#nav-snmp").onclick = () => { $("#drawer-snmp").hidden = false; renderSnmp();
    clearInterval(snmpTimer); snmpTimer = setInterval(() => $("#drawer-snmp").hidden ? clearInterval(snmpTimer) : renderSnmp(), 2000); };

  // ------------------------------------------------------------ RAG 팩
  async function loadRag() {
    const can = AIOPS.can("settings");                      // RAG 팩 관리는 운영 설정 권한 — 없으면 이 절을 숨김(2.20)
    $("#rag-sum").closest("h4").hidden = !can; $("#rag-list").hidden = !can;
    if (!can) return;
    const r = await fetch("/api/rag/packs", {background: true});
    if (!r.ok) return;
    const d = await r.json();
    const stt = d.status || {}, emb = stt.embedding || {};
    $("#rag-sum").textContent = `— 활성 ${(stt.enabled || []).length}/${stt.packs_total || 0} · 청크 ${(stt.chunks_loaded || 0).toLocaleString()} · 임베딩 ${emb.model || "-"} ${String(emb.state || "disabled").toUpperCase()}`;
    $("#rag-list").innerHTML = (d.packs || []).length ? d.packs.map(p => {
      const s2 = p.stats || {}, job = p.job || {};
      const jt = job.state === "embedding" ? ` · 임베딩 ${job.done}/${job.total}` : job.state === "error" ? ` · <span style="color:var(--crit)">${esc(job.error)}</span>` : "";
      return `<div class="rpack ${p.enabled ? "on" : ""}"><div>
        <span class="label">${esc(p.product)}</span> <small style="color:var(--muted)">v${esc(p.version)} · ${esc(p.id)}</small>
        <h4>${esc(p.name)}</h4>
        <div class="meta">문서 ${(s2.documents || 0).toLocaleString()} · 청크 ${(s2.chunks || 0).toLocaleString()} · ${Object.entries(s2.by_type || {}).map(([k, v]) => `${esc(k)} ${v.toLocaleString()}`).join(" · ")} · ${p.size_mb}MB · 검색 ${p.embedding_match ? "하이브리드" : "BM25"}${jt}</div>
        <div class="meta">적용 소스: ${(p.applies_to || ["*"]).map(esc).join(", ")}${p.description ? " — " + esc(p.description) : ""}</div></div>
        <div class="acts"><button class="switch ${p.enabled ? "on" : ""}" data-rag="${esc(p.id)}" data-on="${p.enabled}" title="${p.enabled ? "비활성화" : "활성화"}"></button>
        ${p.embedding_match ? "" : `<button class="btn-sm" data-reembed="${esc(p.id)}">재임베딩</button>`}
        <button class="btn-sm" data-ragdel="${esc(p.id)}">삭제</button></div></div>`;
    }).join("") : `<div class="empty">설치된 RAG 팩이 없습니다. <b>팩 가져오기</b>로 .ragpack 파일을 올리세요.<br><code>python -m app.rag.builder build ragpacks/vsphere.yaml</code></div>`;
    const sel = $("#rag-src"); if (sel.options.length <= 1) Object.keys(SRC_COLOR).forEach(k => sel.add(new Option(k, k)));
    return d;
  }
  let ragTimer;
  $("#nav-rag").onclick = async () => { $("#drawer-rag").hidden = false; await loadRag();
    clearInterval(ragTimer); ragTimer = setInterval(() => $("#drawer-rag").hidden ? clearInterval(ragTimer) : loadRag(), 3000); };
  $("#rag-list").addEventListener("click", async e => {
    const b = e.target.closest("button"); if (!b) return;
    if (b.dataset.rag) { b.disabled = true; await fetch(`/api/rag/packs/${encodeURIComponent(b.dataset.rag)}/${b.dataset.on === "true" ? "disable" : "enable"}`, {method:"POST"}); }
    if (b.dataset.reembed) await fetch(`/api/rag/packs/${encodeURIComponent(b.dataset.reembed)}/reembed`, {method:"POST"});
    if (b.dataset.ragdel && confirm(`RAG 팩 '${b.dataset.ragdel}' 을(를) 삭제할까요?`)) await fetch(`/api/rag/packs/${encodeURIComponent(b.dataset.ragdel)}`, {method:"DELETE"});
    loadRag();
  });
  $("#rag-file").onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    $("#rag-sum").textContent = `— ${f.name} 가져오는 중…`;
    const r = await fetch(`/api/rag/packs?filename=${encodeURIComponent(f.name)}&enable=true`, {method:"POST", headers:{"Content-Type":"application/octet-stream"}, body: f});
    if (!r.ok) alert(`가져오기 실패: ${await r.text()}`);
    e.target.value = ""; loadRag();
  };
  let rq;
  const ragSearch = async () => {
    const q = $("#rag-q").value.trim(); if (!q) { $("#rag-results").innerHTML = ""; return; }
    const src = $("#rag-src").value;
    const hits = await (await fetch(`/api/knowledge/search?k=8&intent=chat&q=${encodeURIComponent(q)}${src ? "&source=" + src : ""}`)).json();
    $("#rag-results").innerHTML = window.AIOPS_KNOW ? window.AIOPS_KNOW.hitsHtml(Array.isArray(hits) ? hits : [], "")
      : `<div class="empty">결과 없음</div>`;
  };
  $("#rag-q").oninput = () => { clearTimeout(rq); rq = setTimeout(ragSearch, 300); };
  $("#rag-src").onchange = ragSearch;

  // ------------------------------------------------------------ 모바일 탭
  function showPane(p) {
    $$(".mobile-tabs button").forEach(b => b.classList.toggle("on", b.dataset.pane === p));
    $("#pane-logs").classList.toggle("show", p === "logs"); $("#pane-anoms").classList.toggle("show", p === "anoms");
  }
  $$(".mobile-tabs button").forEach(b => b.onclick = () => showPane(b.dataset.pane));
  showPane("logs");

  // 세션 확인 후 실시간 스트림 연결(미인증이면 core.js 가 로그인 화면으로 이동)
  (window.AIOPS ? AIOPS.ready : Promise.resolve(true)).then(me => { if (me !== null) AIOPS.stream(onWs, onWsState); });
})();
