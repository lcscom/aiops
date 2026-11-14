/* 통합 관제 — 슬롯별 상태 판정·개체 상태맵·도메인 타임라인·AI 상황 브리핑·실시간 알림 피드.
   초기값 GET /api/noc · /api/noc/brief, 이후 WebSocket /ws(anomaly·logs·status·incident·alert·noc_brief) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const p2 = n => String(n).padStart(2, "0");
  const hms = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
  const hm = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}`; };
  const dur = sec => sec < 3600 ? `${Math.floor(sec / 60)}분 ${p2(Math.floor(sec % 60))}초` : `${Math.floor(sec / 3600)}시간 ${Math.floor(sec % 3600 / 60)}분`;
  const SEV_KO = {critical: "위험", error: "오류", warning: "경고", info: "정보", debug: "디버그"};
  const SEV_R = {debug: 0, info: 1, warning: 2, error: 3, critical: 4};
  const STATE = {down: ["장애", "s-down"], warn: ["주의", "s-warn"], ok: ["정상", "s-ok"], idle: ["대기", "s-idle"]};
  const ENT_KO = {ok: "정상", warn: "주의", down: "장애", maint: "유지보수", unknown: "미확인"};
  const AI_KO = {queued: "AI 분석 대기", analyzing: "AI 분석 중", analyzed: "AI 분석 완료", llm_error: "AI 분석 실패", rule_only: "규칙 탐지"};
  const ADD_HINT = {vsan: "vCenter 커넥터가 있으면 vSAN 클러스터·호스트·데이터스토어 상태와 vSAN 로그(vCenter 이벤트·ESXi syslog)를 자동으로 모읍니다.", vc: "운영 설정 > 커넥터에서 vCenter Server 를 추가하면 ESXi 이벤트까지 함께 수집합니다.",
                    nsx: "운영 설정 > 커넥터에서 NSX Manager 를 추가하면 Edge 상태와 알람도 함께 수집합니다.",
                    avi: "운영 설정 > 커넥터에서 NSX ALB(Avi) 컨트롤러를 추가하세요.",
                    vks: "운영 설정 > 커넥터에서 VKS(Supervisor·워크로드 클러스터)를 추가하세요.",
                    srv: "운영 설정 > 커넥터에서 Redfish(iLO·iDRAC·XCC)를 추가하면 서버 부품 상태와 실시간 하드웨어 이벤트를, 물리 서버에 에이전트를 설치하면 OS 로그를 표시합니다.",
                    vmg: "운영 콘솔 > VM·서버 에이전트 > 에이전트 등록에서 설치 명령을 받아 VM 에 실행하세요(Linux·Windows)."};

  const st = {slots: [], bySource: {}, byType: {}, window: 30 * 60, escalate: 15 * 60, staleSec: 600, minute: Math.floor(Date.now() / 60000), runtime: null,
              openOnly: true, sound: false, cycle: false, focus: null, alarmAck: {}, fresh: new Map(), filter: {}, cycleIdx: 0};
  const pref = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } return null; };
  st.openOnly = pref("noc.openOnly") !== "0"; st.cycle = pref("noc.cycle") === "1";
  $("#n-open").checked = st.openOnly; $("#n-cycle").setAttribute("aria-pressed", st.cycle);

  // ---------------------------------------------------------------- 판정
  const now = () => Date.now() / 1000;
  const isOpen = a => !a.ack && (a.ai || {}).is_anomaly !== false && !a.suppressed && now() - a.last_seen < st.window;
  function keysOf(a) {
    const e = a.event || {}, out = new Set();
    [e.host, e.entity, (e.attrs || {}).node].forEach(v => { if (!v) return; v = String(v).toLowerCase(); out.add(v); out.add(v.split("/").pop()); out.add(v.split(".")[0]); if (v.startsWith("edge:") || v.startsWith("agent:")) out.add(v.split(":").slice(1).join(":")); });
    return out;
  }
  function overlay(s, open) {                 // 서버 원 상태(base) 위에 실시간 열린 이상을 다시 겹침
    const idx = {};
    s.entities.forEach(en => { en.state = en.base || en.state; en.alerts = 0; en.worst = ""; const n = en.name.toLowerCase(); idx[n] = idx[n] || en; idx[n.split(".")[0]] = idx[n.split(".")[0]] || en; });
    for (const a of open) for (const k of keysOf(a)) {
      const en = idx[k]; if (!en) continue;
      en.alerts++; if ((SEV_R[a.severity] || 0) > (SEV_R[en.worst] || 0)) en.worst = a.severity;
      if (a.severity === "critical") en.state = "down"; else if (["error", "warning"].includes(a.severity) && ["ok", "unknown"].includes(en.state)) en.state = "warn";
      break;
    }
  }
  function health(s) {
    const open = s.anomalies.filter(isOpen);
    overlay(s, open);
    const c = {critical: 0, error: 0, warning: 0};
    open.forEach(a => { if (a.severity in c) c[a.severity]++; });
    s.counts = c;
    const down = s.connectors.filter(x => x.state === "down").length, deg = s.connectors.filter(x => x.state === "degraded").length;
    const entDown = s.entities.filter(e => e.state === "down").length, entWarn = s.entities.filter(e => e.state === "warn").length;
    const critInc = s.incidents.some(i => i.severity === "critical");
    // 데이터 신선도: 마지막 수신(로그·이벤트) 또는 커넥터 폴링 성공 중 최신 — 끊겼는데 '정상'으로 보이는 것 방지
    const last = Math.max(s.last_data || 0, ...s.connectors.map(x => x.last_ok || 0));
    const feed = s.connectors.length || s.rate.some(Boolean) || last;
    s.fresh_age = last ? now() - last : null;
    s.stale = !!(st.staleSec && feed && (!last || s.fresh_age > st.staleSec));
    const why = [];
    if (c.critical) why.push(`위험 ${c.critical}건`);
    if (c.error) why.push(`오류 ${c.error}건`);
    if (c.warning) why.push(`경고 ${c.warning}건`);
    if (entDown) why.push(`개체 장애 ${entDown}`);
    if (down) why.push(`커넥터 오류 ${down}`);
    if (deg) why.push(`커넥터 지연 ${deg}`);
    if (s.stale) why.push(s.fresh_age ? `데이터 수신 지연 ${dur(s.fresh_age)}` : "데이터 수신 기록 없음");
    let state = "ok";
    if (c.critical || critInc || entDown) state = "down";
    else if (c.error || c.warning || down || deg || s.incident_count || entWarn || s.stale) state = "warn";
    else if (!s.connectors.length && !s.anomalies.length && !s.rate.some(Boolean)) state = "idle";
    if (state === "ok") why.push(`최근 ${Math.round(st.window / 60)}분 미확인 이상 없음`);
    if (state === "idle") why.push("수집 대상 없음");
    const ce = open.filter(a => a.severity === "critical" || a.severity === "error").sort((x, y) => x.created - y.created);
    s.oldest = ce[0] || null;
    s.state = state; s.why = why.join(", ");
    return state;
  }

  // ---------------------------------------------------------------- 렌더: 슬롯
  function rateSvg(rate) {
    const w = 300, h = 36, bw = w / 60, mx = Math.max(1, ...rate);
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-label="최근 60분 분당 이벤트">` + rate.map((v, i) => {
      const bh = v ? Math.max(2, v / mx * (h - 2)) : 1;
      return `<rect x="${(i * bw).toFixed(1)}" y="${(h - bh).toFixed(1)}" width="${(bw - 1).toFixed(1)}" height="${bh.toFixed(1)}" fill="${i === 59 ? "#4fb3e0" : v ? "#5d7c89" : "#2c434e"}"/>`;
    }).join("") + "</svg>";
  }
  function rowHtml(a) {
    const e = a.event || {}, ai = a.ai || {};
    return `<div class="row ${esc(a.severity)} ${isOpen(a) ? "" : "ack"} ${(st.fresh.get(a.id) || 0) > Date.now() ? "fresh" : ""}" data-aid="${esc(a.id)}" tabindex="0">
      <span class="tm">${hms(a.last_seen)}</span><span class="bar"></span>
      <span class="ti">${esc(a.title)}</span>
      <span class="mt"><span class="sv">${SEV_KO[a.severity] || esc(a.severity)}</span>${a.count > 1 ? `<span class="cnt">×${a.count}</span>` : ""}
        ${a.escalated ? '<span class="esc">에스컬레이션</span>' : ""}
        <span>${esc(e.host || "")}${e.entity && e.entity !== e.host ? " / " + esc(e.entity) : ""}</span>
        <span>${esc(e.source || "")}</span><span>${AI_KO[a.status] || ""}${ai.confidence != null && a.status === "analyzed" ? ` ${Math.round(ai.confidence * 100)}%` : ""}</span>
        ${a.incident_id ? `<span class="inc">${esc(a.incident_id)}</span>` : ""}${a.alerted ? "<span>알림 발송</span>" : ""}${a.suppressed ? `<span>억제: ${esc(a.suppressed)}</span>` : ""}</span></div>`;
  }
  function emapHtml(s) {
    const conns = s.connectors.length ? s.connectors.map(c => `<span class="chip ${esc(c.state)}" title="${esc(c.target || "")}${c.last_error ? "\n" + esc(c.last_error) : ""}"><i></i>${esc(c.name)}</span>`).join("")
      : s.agents ? `<span class="chip ok"><i></i>에이전트 ${s.entities.length}대(Fluent Bit·rsyslog)</span>` : "<span>연결된 커넥터 없음</span>";
    const groups = {};
    s.entities.forEach(e => { const g = e.group || {host: "호스트", edge: "Edge", manager: "Manager", SE: "서비스 엔진", VS: "가상 서비스", node: "노드", cluster: "클러스터", server: "서버(BMC)", guest: "VM", os: "서버 OS"}[e.kind] || e.kind; (groups[g] = groups[g] || []).push(e); });
    const cnt = {}; s.entities.forEach(e => { cnt[e.state] = (cnt[e.state] || 0) + 1; });
    const sum = ["down", "warn", "maint", "ok"].filter(k => cnt[k]).map(k => `${ENT_KO[k]} ${cnt[k]}`).join(", ");
    const sel = st.filter[s.id];
    const order = {down: 0, warn: 1, unknown: 2, maint: 3, ok: 4};
    return `<div class="emap"><div class="grp">${conns}<span class="emap-sum">${s.entities.length ? `개체 ${s.entities.length} — ${sum}` : ""} · syslog 5분 <b class="sy">${s.syslog_5m.toLocaleString()}</b>건</span></div>
      ${Object.entries(groups).sort((x, y) => Math.min(...x[1].map(e => order[e.state] ?? 9)) - Math.min(...y[1].map(e => order[e.state] ?? 9))).map(([g, es]) => `<div class="grp"><span class="gl">${esc(g)}</span>${es.sort((x, y) => (order[x.state] ?? 9) - (order[y.state] ?? 9) || x.name.localeCompare(y.name)).map(e =>
        `<button class="tile ${esc(e.state)} ${sel === e.name ? "sel" : ""}" data-ent="${esc(e.name)}" title="${esc(e.name)} — ${ENT_KO[e.state] || e.state}${e.detail ? "\n" + esc(e.detail) : ""}${e.alerts ? `\n열린 이상 ${e.alerts}건` : ""}">${esc(e.name)}${e.alerts ? ` <b>${e.alerts}</b>` : ""}</button>`).join("")}</div>`).join("")}</div>`;
  }
  function slotHtml(s) {
    const [lab, cls] = STATE[s.state];
    const sel = st.filter[s.id];
    let list = st.openOnly ? s.anomalies.filter(isOpen) : s.anomalies;
    if (sel) { const k = sel.toLowerCase(); list = list.filter(a => keysOf(a).has(k) || keysOf(a).has(k.split(".")[0])); }
    list = list.slice(0, 80);
    const alarm = s.state === "down" && !st.alarmAck[s.id];
    const total = s.rate.reduce((x, y) => x + y, 0);
    const k = (c, label, v, extra = "") => `<div class="kpi ${c} ${v ? "" : "zero"}" ${extra}><span>${label}</span><b>${v}</b></div>`;
    const age = s.oldest ? now() - s.oldest.created : 0;
    const esc_ = s.oldest && age >= st.escalate && s.oldest.severity === "critical";
    return `<section class="slot ${cls} ${alarm ? "alarm" : ""} ${st.focus === s.id ? "focused" : ""}" data-slot="${esc(s.id)}" aria-label="${esc(s.name)} ${lab}">
      <div class="plate"><h2>${panelTools(s.id)}<button data-focus="${esc(s.id)}" title="${st.focus === s.id ? "전체 보기로 돌아가기(Esc)" : "이 슬롯 확대"}">${esc(s.name)}</button>${panelTools2(s.id)}</h2>${alarm ? `<button class="ackbtn" data-ack="${esc(s.id)}">알림 확인</button>` : `<span class="scope">${esc(s.scope)}</span>`}
        <div class="state" title="${esc(s.why)}"><b>${lab}</b>${s.stale ? `<span class="stale-b" title="마지막 수신 ${s.fresh_age ? hms(now() - s.fresh_age) : "-"}">데이터 지연</span>` : ""}<span>${esc(s.why)}</span>
          ${s.oldest ? `<span class="age ${esc_ ? "esc" : ""}" data-age="${s.oldest.created}" title="${esc(s.oldest.title)}">미확인 ${SEV_KO[s.oldest.severity]} ${dur(age)} 경과</span>` : ""}</div>
</div>
      <div class="kpis">${k("c", "위험", s.counts.critical)}${k("e", "오류", s.counts.error)}${k("w", "경고", s.counts.warning)}
        ${k("inc", "활성 인시던트", s.incident_count, s.incident_count ? `data-incs="${esc(s.id)}" role="button" tabindex="0" title="인시던트 목록"` : "")}${k("pm", "분당 이벤트", s.rate[59])}
        <div class="rate">${rateSvg(s.rate)}<small>최근 60분 ${total.toLocaleString()}건</small></div></div>
      ${emapHtml(s)}
      ${sel ? `<div class="filter-note">개체 ${esc(sel)} 의 알림만 표시 중 <button data-unfilter="${esc(s.id)}">전체 보기</button></div>` : ""}
      <div class="feed" role="log" aria-live="polite">${list.length ? list.map(rowHtml).join("")
        : `<div class="empty">${s.state === "idle" ? esc(ADD_HINT[s.id] || "커넥터를 추가하세요.") : sel ? "이 개체에 해당하는 알림이 없습니다." : st.openOnly ? `최근 ${Math.round(st.window / 60)}분 동안 미확인 이상 징후가 없습니다.` : "이상 징후가 없습니다."}</div>`}</div>
    </section>`;
  }

  // ---------------------------------------------------------------- 렌더: 타임라인(최근 60분 × 도메인 레인)
  function timeline() {
    const t1 = now(), t0 = t1 - 3600;
    const lanes = st.slots.map(s => {
      const mk = s.anomalies.filter(a => a.last_seen >= t0).slice(0, 120).map(a => {
        const x = Math.max(0, Math.min(100, (a.last_seen - t0) / 36));
        const size = Math.min(16, 7 + Math.log2(Math.max(1, a.count)) * 2 + (a.severity === "critical" ? 3 : 0));
        return `<button class="tl-mk ${esc(a.severity)} ${isOpen(a) ? "" : "ack"}" style="left:${x.toFixed(2)}%;width:${size}px;height:${size}px" data-aid="${esc(a.id)}"
          title="${hm(a.last_seen)} ${SEV_KO[a.severity] || ""} ${esc(a.title)}" aria-label="${hm(a.last_seen)} ${esc(a.title)}"></button>`;
      }).join("");
      return `<div class="tl-lane ${STATE[s.state][1]}"><span class="ln"><i></i>${esc(s.name)}</span><div class="tl-track">${mk}<span class="tl-now"></span></div></div>`;
    }).join("");
    const ticks = [60, 50, 40, 30, 20, 10, 0].map(m => `<span style="left:${100 - m / 0.6}%${m ? "" : ";transform:translateX(-100%)"}">${m ? `-${m}분` : "지금"}</span>`).join("");
    $("#n-tl").innerHTML = lanes + `<div class="tl-axis"><i></i><div class="ax">${ticks}</div></div>`;
  }

  // ---------------------------------------------------------------- 전체 렌더
  let rT;
  function render() {
    clearTimeout(rT);
    rT = setTimeout(() => {
      const scroll = {};
      $$(".slot").forEach(el => { const f = el.querySelector(".feed"); if (f) scroll[el.dataset.slot] = f.scrollTop; });
      const focusEl = document.activeElement && document.activeElement.dataset ? {...document.activeElement.dataset} : null;
      st.slots.forEach(health);
      const g = $("#n-grid");
      g.classList.toggle("focus", !!st.focus);
      layoutPanels();
      st.slots.forEach(sl => patch(sl.id, slotHtml(sl)));
      if (panelOn("vip")) patch("vip", vipHtml());
      if (panelOn("moves")) patch("moves", movesHtml());
      $$(".slot").forEach(el => { const f = el.querySelector(".feed"); if (f && scroll[el.dataset.slot] != null) f.scrollTop = scroll[el.dataset.slot]; });
      if (focusEl && focusEl.focus) { const b = document.querySelector(`[data-focus="${CSS.escape(focusEl.focus)}"]`); if (b) b.focus(); }
      timeline();
      compactSlots();
      const cnt = {down: 0, warn: 0};
      st.slots.forEach(s => { if (s.state in cnt) cnt[s.state]++; });
      $("#n-sum").innerHTML = st.slots.map(s => `<span class="pill ${STATE[s.state][1]}">${esc(s.name)} ${STATE[s.state][0]}</span>`).join("");
      document.title = `${cnt.down ? `장애 ${cnt.down} — ` : cnt.warn ? `주의 ${cnt.warn} — ` : ""}통합 관제 · VCF AIops`;
      const worst = cnt.down ? "s-down" : cnt.warn ? "s-warn" : "s-ok";
      $("#n-brief").className = `brief ${worst}`;
    }, 120);
  }
  function compactSlots() {               // 슬롯 높이가 낮으면(화면·레이아웃에 따라) 압축 표시 — 지표가 잘리지 않게
    $$(".slot").forEach(el => { const h = el.clientHeight; el.classList.toggle("compact", h > 0 && h < 240); el.classList.toggle("tiny", h > 0 && h < 150); });
  }
  if (window.ResizeObserver) document.addEventListener("DOMContentLoaded", () => { const g = $("#n-grid"); if (g) new ResizeObserver(() => compactSlots()).observe(g); });
  function updateRates() {                // 로그 유입(초당 수 회)은 지표·그래프만 부분 갱신
    st.slots.forEach(s => {
      const el = document.querySelector(`.slot[data-slot="${CSS.escape(s.id)}"]`); if (!el) return;
      const total = s.rate.reduce((x, y) => x + y, 0);
      el.querySelector(".rate").innerHTML = `${rateSvg(s.rate)}<small>최근 60분 ${total.toLocaleString()}건</small>`;
      const k = el.querySelector(".kpi.pm"); if (k) { k.querySelector("b").textContent = s.rate[59]; k.classList.toggle("zero", !s.rate[59]); }
      const sy = el.querySelector(".sy"); if (sy) sy.textContent = s.syslog_5m.toLocaleString();
    });
  }
  function tickAges() {                   // 미확인 경과 타이머(1초)
    $$(".age[data-age]").forEach(el => {
      const sec = now() - Number(el.dataset.age);
      el.textContent = el.textContent.replace(/\d+(시간|분) .*경과$/, `${dur(sec)} 경과`);
      if (sec >= st.escalate && el.textContent.includes("위험")) el.classList.add("esc");
    });
  }

  // ---------------------------------------------------------------- 데이터
  function index() {
    st.bySource = {}; st.byType = {};
    st.slots.forEach(s => { s.sources.forEach(x => { st.bySource[x] = s; }); s.types.forEach(x => { st.byType[x] = s; }); });
  }
  async function load() {
    const d = await A.api("GET", "/api/noc", undefined, {background: true});
    const keep = {}; st.slots.forEach(x => { keep[x.id] = x.last_data; });
    st.slots = d.slots; st.window = d.window_minutes * 60; st.escalate = (d.escalate_minutes || 15) * 60;
    st.staleSec = (d.stale_minutes ?? 10) * 60;
    st.slots.forEach(x => { x.last_data = Math.max(x.last_data || 0, keep[x.id] || 0); });
    if (d.runtime) plat(d.runtime);
    index(); render();
    A.api("GET", "/api/avi/vips", undefined, {background: true}).then(v => vipData(v.items || [])).catch(() => {});
    loadKpi();
  }
  function showBrief(b) {
    if (!b) return;
    $("#n-brief-text").textContent = b.text || "";
    $("#n-brief-meta").textContent = `${b.mode === "ai" ? `AI 요약(${b.model || "Gemma"})` : "규칙 기반 요약"} · ${hm(b.ts)} 기준`;
  }
  async function loadBrief(refresh = false) {
    try { showBrief(await A.api("GET", `/api/noc/brief${refresh ? "?refresh=1" : ""}`, undefined, {background: !refresh})); }
    catch (e) { $("#n-brief-meta").textContent = `브리핑 실패: ${e.message}`; }
  }
  function upsert(a, quiet = false) {
    const s = st.bySource[(a.event || {}).source]; if (!s) return;
    const i = s.anomalies.findIndex(x => x.id === a.id);
    const prev = i < 0 ? null : s.anomalies[i];
    if (i < 0) s.anomalies.unshift(a); else s.anomalies[i] = a;
    s.anomalies.sort((x, y) => y.last_seen - x.last_seen);
    if (s.anomalies.length > 150) s.anomalies.length = 150;
    if (!quiet && (!prev || a.count > prev.count || a.severity !== prev.severity)) {
      st.fresh.set(a.id, Date.now() + 5000);
      if (a.severity === "critical" && isOpen(a)) { st.alarmAck[s.id] = false; beep(); }
    }
  }
  function rollMinute() {
    const m = Math.floor(Date.now() / 60000);
    if (m === st.minute) return;
    const shift = Math.min(60, m - st.minute);
    st.slots.forEach(s => { for (let i = 0; i < shift; i++) { s.rate.shift(); s.rate.push(0); } });
    st.minute = m;
  }

  // ---------------------------------------------------------------- 실시간(core.js A.stream — 재접속·하트비트·누락 재동기화·빌드 변경 새로고침)
  let incT, lastLive = Date.now();
  function onMsg(m) {
    if (m.type === "snapshot") {
      (m.data.anomalies || []).forEach(a => { const s = st.bySource[(a.event || {}).source]; if (s && !s.anomalies.some(x => x.id === a.id)) s.anomalies.push(a); else if (s) upsert(a, true); });
      if (m.data.status && m.data.status.runtime) plat(m.data.status.runtime);
      if (m.reconnect) { load().catch(() => {}); loadBrief(); }      // 끊긴 동안의 변화(인시던트·개체 상태) 서버 집계로 재동기화
      render();
    } else if (m.type === "anomaly") { upsert(m.data); render(); }
    else if (m.type === "logs") {
      rollMinute();
      let hit = false; const t = now();
      for (const l of m.data) { const s = st.bySource[l.source]; if (s) { s.rate[59]++; s.last_data = t; if (l.connector === "syslog") s.syslog_5m++; hit = true; } }
      if (hit) updateRates();
      live(m.data);
    } else if (m.type === "status") {
      if (m.data.runtime) plat(m.data.runtime);
      const by = {};
      (m.data.connectors || []).forEach(c => { const s = st.byType[c.type]; if (s) (by[s.id] = by[s.id] || []).push(c); });
      let changed = false;
      st.slots.forEach(s => { const n = (by[s.id] || []).map(c => ({name: c.name, type: c.type, state: c.state, latency_ms: c.latency_ms, last_error: c.last_error, target: c.target, last_ok: c.last_ok}));
        if (JSON.stringify(n.map(x => x.name + x.state)) !== JSON.stringify(s.connectors.map(x => x.name + x.state))) changed = true;
        s.connectors = n; });
      const stale = st.slots.map(s => s.stale).join();
      st.slots.forEach(s => { const last = Math.max(s.last_data || 0, ...s.connectors.map(x => x.last_ok || 0)); s._staleNow = !!(st.staleSec && (s.connectors.length || last) && (!last || now() - last > st.staleSec)); });
      if (changed || stale !== st.slots.map(s => s._staleNow).join()) render();
    } else if (m.type === "incident" || m.type === "action") {
      clearTimeout(incT); incT = setTimeout(() => load().catch(() => {}), 1500);
    } else if (m.type === "alert") {
      for (const s of st.slots) { const a = s.anomalies.find(x => x.id === m.data.anomaly_id); if (a) { a.alerted = true; render(); break; } }
    } else if (m.type === "noc_brief") showBrief(m.data);
    else if (m.type === "avi_vips") { vipData(m.data); }
    else if (m.type === "vm_move") onMove(m.data);
    else if (m.type === "ai_state") { if (st.kpi) { st.kpi.ai = {...st.kpi.ai, ...m.data}; kpiRender(); } }
  }
  function onState(state, info) {
    const l = $("#n-live"), box = $("#n-conn");
    const live = state === "live";
    l.classList.toggle("off", !live);
    if (live) lastLive = Date.now();
    const down = info.downSince ? (Date.now() - info.downSince) / 1000 : 0;
    l.textContent = live ? "실시간" : state === "resync" ? "재동기화 중" : state === "stale" ? "응답 없음 — 재연결" : `연결 끊김 ${Math.round(down)}초`;
    const frozen = !live && state !== "resync" && down >= 5;
    document.body.classList.toggle("frozen", frozen);
    box.hidden = !frozen;
    if (frozen) {
      const wait = Math.max(0, Math.round((info.retryAt - Date.now()) / 1000));
      box.innerHTML = `<span>실시간 연결 끊김 — 화면은 ${hms(lastLive / 1000)} 기준 정보입니다</span><small>${dur(down)} 경과 · ${wait ? `${wait}초 후 재연결 시도` : "재연결 시도 중"} · 재시도 ${info.reconnects}회</small>`;
    }
  }
  function plat(rt) {
    st.runtime = rt;
    const b = $("#n-plat"); if (!b) return;
    const lab = {ok: "플랫폼 정상", warn: "플랫폼 주의", down: "플랫폼 장애"}[rt.state] || "플랫폼";
    b.className = `plat ${rt.state}`;
    b.textContent = lab + (rt.ha && rt.ha.enabled ? ` · ${rt.ha.node}${rt.ha.leader ? "(리더)" : "(대기)"}` : "");
    b.title = (rt.issues || []).map(i => `• ${i.text}`).join("\n") || `처리 지연 p99 ${rt.lag.p99_ms}ms · 대기 ${rt.pipeline.high + rt.pipeline.low}건 · 화면 연결 ${rt.ws.clients}`;
  }
  $("#n-plat").onclick = () => {
    const rt = st.runtime; if (!rt) return;
    A.modal({title: `플랫폼 상태 — ${{ok: "정상", warn: "주의", down: "장애"}[rt.state] || rt.state}`, ok: "", cancel: "닫기", html: `<dl class="dl">
      <dt>이상 항목</dt><dd>${(rt.issues || []).map(i => esc(i.text)).join("<br>") || "없음"}</dd>
      <dt>처리 지연</dt><dd>이벤트 루프 p99 ${rt.lag.p99_ms}ms · 수집→처리 ${(rt.pipeline.lag_ms / 1000).toFixed(1)}초</dd>
      <dt>대기열</dt><dd>우선 ${rt.pipeline.high} · 일반 ${rt.pipeline.low} · 게시 ${rt.pipeline.pub_backlog} · 누적 폐기 ${rt.pipeline.dropped}</dd>
      <dt>저장</dt><dd>${esc(rt.store.state)} · 기록 대기 ${rt.store.backlog} · 디스크 ${rt.store.disk_free_mb ?? "-"}MB</dd>
      <dt>LLM</dt><dd>${{closed: "정상", open: "일시 차단(규칙 탐지로 운영)", half_open: "시험 중"}[rt.llm_breaker] || rt.llm_breaker}${rt.ai ? ` · AI 분석 대기 ${rt.ai.depth}건${rt.ai.rate_per_min ? ` (분당 ${rt.ai.rate_per_min}, 예상 ${rt.ai.eta_min ?? "-"}분)` : ""} · 병합 ${rt.ai.coalesced} · 생략 ${rt.ai.skipped}` : ""}</dd>
      <dt>이중화</dt><dd>${rt.ha.enabled ? `${esc(rt.ha.node)} · ${rt.ha.role} · ${rt.ha.leader ? "알림 리더" : "대기"} · 상대 ${esc(rt.ha.peer.state)}` : "단일 노드"}</dd></dl>`});
  };
  setInterval(() => { rollMinute(); for (const [k, t] of st.fresh) if (t < Date.now()) st.fresh.delete(k); render(); }, 15000);
  setInterval(() => load().catch(() => {}), 60000);                  // 개체 상태맵·인시던트 서버 집계 동기화
  setInterval(() => loadBrief().catch(() => {}), 120000);
  setInterval(tickAges, 1000);
  // 관제 전용(키오스크) 화면: 브라우저 장기 실행 누수 대비 매일 04:30 새로고침(연결 정상일 때만)
  const pageStart = Date.now();
  setInterval(() => { const d = new Date(); if (me && me.kiosk && d.getHours() === 4 && d.getMinutes() === 30 && Date.now() - pageStart > 3600e3 && !document.body.classList.contains("frozen")) location.reload(); }, 60000);

  // ---------------------------------------------------------------- 패널 배치(드래그 순서 바꾸기·숨기기·글자 크기) — 브라우저별 저장
  const jget = (k, d) => { try { return JSON.parse(pref(k) || "null") ?? d; } catch { return d; } };
  st.order = jget("noc.order", []); st.hidden = jget("noc.hidden", []); st.scale = jget("noc.scale", {}); st.cols = pref("noc.cols") || "auto";
  st.vips = []; st.vipSort = pref("noc.vipSort") || "bw"; st.vipPrev = {};
  const XP = {vip: "VIP 트래픽", stream: "실시간 이벤트", river: "이벤트 흐름", moves: "VM 액티비티"};
  function panelOn(id) {
    if (st.hidden.includes(id)) return false;
    if (id === "vip") return st.vips.length > 0 || !!(st.slots.find(x => x.id === "avi") || {connectors: []}).connectors.length;
    if (id === "moves") return !!(st.kpi && (st.kpi.vms || (st.kpi.moves || []).length));
    return true;
  }
  function panelIds() {
    const all = [...st.slots.map(x => x.id), "moves", "vip", "stream"].filter(panelOn);
    const ord = st.order.filter(x => all.includes(x));
    return [...ord, ...all.filter(x => !ord.includes(x))];
  }
  function panelTools(id) {          // 제목 줄 왼쪽(⠿)·오른쪽(A− A+ ⤢) — 상태 표시와 겹치지 않게 제목과 같은 줄
    return `<span class="grip" draggable="true" data-grip="${esc(id)}" title="끌어서 위치 바꾸기">⠿</span>`;
  }
  function panelTools2(id) {
    const dom = !["stream", "vip", "moves", "kpi", "brief"].includes(id);
    return `${dom ? `<a class="pdet" href="/noc/d/${encodeURIComponent(id)}" title="도메인 상세 탭 — 실시간 이벤트·개체·커넥터 점검">상세 ›</a>` : ""}<span class="ptools"><button data-scale="-1" title="글자 작게">A−</button><button data-scale="1" title="글자 크게">A+</button>
      <button class="zf" data-focus="${esc(id)}" title="${st.focus === id ? "전체 보기(Esc)" : "이 패널만 크게"}">${st.focus === id ? "⤡" : "⤢"}</button></span>`;
  }
  function layoutPanels() {
    const g = $("#n-grid"), ids = panelIds();
    g.dataset.n = ids.length; g.dataset.cols = st.cols;
    for (const el of [...g.children]) if (!ids.includes(el.dataset.slot)) el.remove();
    ids.forEach(id => {
      let el = g.querySelector(`:scope > [data-slot="${CSS.escape(id)}"]`);
      if (!el) {
        el = document.createElement("section"); el.dataset.slot = id; el.className = "slot";
        if (id === "stream") { el.className = "slot xpanel s-idle"; el.innerHTML = streamShell(); }
      }
      g.appendChild(el);                           // 저장된 순서대로 재배치(이미 있으면 이동)
      el.style.zoom = st.scale[id] ? String(1 + st.scale[id] * 0.1) : "";
      el.classList.toggle("focused", st.focus === id);
    });
    if (st.focus && !ids.includes(st.focus)) st.focus = null;
  }
  function patch(id, html) {
    const el = $(`#n-grid > [data-slot="${CSS.escape(id)}"]`); if (!el) return;
    const tpl = document.createElement("template"); tpl.innerHTML = html.trim();
    const n = tpl.content.firstElementChild; if (!n) return;
    el.className = n.className + (st.focus === id ? " focused" : "");
    for (const a of ["aria-label"]) if (n.hasAttribute(a)) el.setAttribute(a, n.getAttribute(a));
    el.innerHTML = n.innerHTML;
  }
  function scalePanel(id, d) {
    st.scale[id] = Math.max(-3, Math.min(6, (st.scale[id] || 0) + d));
    pref("noc.scale", JSON.stringify(st.scale)); layoutPanels();
  }
  // 드래그 앤 드롭 — 판(plate)의 ⠿ 를 끌어 다른 패널 위에 놓으면 그 자리로 이동
  let dragId = null;
  $("#n-grid").addEventListener("dragstart", e => {
    const gr = e.target.closest && e.target.closest("[data-grip]"); if (!gr) return;
    dragId = gr.dataset.grip; e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", dragId);
    const sec = gr.closest(".slot"); sec.classList.add("dragging");
    try { e.dataTransfer.setDragImage(sec, 40, 20); } catch { /* 무시 */ }
  });
  $("#n-grid").addEventListener("dragover", e => {
    if (!dragId) return; const sec = e.target.closest(".slot"); if (!sec || sec.dataset.slot === dragId) return;
    e.preventDefault(); $$(".slot.dropon").forEach(x => x !== sec && x.classList.remove("dropon")); sec.classList.add("dropon");
  });
  $("#n-grid").addEventListener("dragleave", e => { const sec = e.target.closest(".slot"); if (sec && !sec.contains(e.relatedTarget)) sec.classList.remove("dropon"); });
  $("#n-grid").addEventListener("drop", e => {
    e.preventDefault(); const sec = e.target.closest(".slot"); $$(".slot.dropon,.slot.dragging").forEach(x => x.classList.remove("dropon", "dragging"));
    if (!dragId || !sec || sec.dataset.slot === dragId) { dragId = null; return; }
    const ids = panelIds(), from = ids.indexOf(dragId), to = ids.indexOf(sec.dataset.slot);
    ids.splice(from, 1); ids.splice(to, 0, dragId);
    st.order = ids; pref("noc.order", JSON.stringify(ids)); dragId = null;
    layoutPanels(); A.ok("배치 저장됨", "이 브라우저에 저장했습니다(레이아웃 › 초기화로 되돌리기)");
  });
  $("#n-grid").addEventListener("dragend", () => { dragId = null; $$(".slot.dropon,.slot.dragging").forEach(x => x.classList.remove("dropon", "dragging")); });

  // ---------------------------------------------------------------- 레이아웃 메뉴
  $("#n-layout").onclick = async () => {
    const all = [...st.slots.map(x => [x.id, x.name]), ["moves", XP.moves], ["vip", XP.vip], ["stream", XP.stream], ["river", XP.river]];
    const v = await A.modal({title: "레이아웃 — 패널 표시·열 수", ok: "적용",
      html: `<p class="modal-text">패널 순서는 각 패널 왼쪽 위 <b>⠿</b> 를 끌어서 바꿉니다. 이 설정은 이 브라우저에만 저장됩니다.</p>
        <div class="lay-list">${all.map(([id, n]) => `<label><input type="checkbox" data-lay="${esc(id)}" ${st.hidden.includes(id) ? "" : "checked"}> ${esc(n)}</label>`).join("")}</div>`,
      fields: [{id: "cols", label: "열 수", type: "select", value: st.cols, options: [["auto", "자동"], ["1", "1열"], ["2", "2열"], ["3", "3열"], ["4", "4열"]]},
               {id: "reset", label: "순서·글자 크기 초기화", type: "select", value: "no", options: [["no", "유지"], ["yes", "초기화"]]}],
      onOpen: m => { st._layModal = m; }});
    if (!v) return;
    st.hidden = $$("[data-lay]", st._layModal).filter(x => !x.checked).map(x => x.dataset.lay);
    st.cols = v.cols; pref("noc.cols", st.cols); pref("noc.hidden", JSON.stringify(st.hidden));
    if (v.reset === "yes") { st.order = []; st.scale = {}; pref("noc.order", "[]"); pref("noc.scale", "{}"); }
    $("#n-river-box").hidden = st.hidden.includes("river");
    render();
  };

  // ---------------------------------------------------------------- 영역 확대 — 끌어서 고른 사각형을 화면 가득
  st.zoomRect = null;
  $("#n-zoom").onclick = () => {
    if (st.zoomRect) { unzoom(); return; }
    const ov = document.createElement("div"); ov.className = "zsel"; ov.innerHTML = `<div class="zhint">확대할 영역을 끌어서 선택하세요 · Esc 취소</div><div class="zbox" hidden></div>`;
    document.body.appendChild(ov);
    let p0 = null; const box = ov.querySelector(".zbox");
    const end = () => ov.remove();
    ov.addEventListener("pointerdown", e => { p0 = {x: e.clientX, y: e.clientY}; box.hidden = false; ov.setPointerCapture(e.pointerId); });
    ov.addEventListener("pointermove", e => { if (!p0) return; const x = Math.min(p0.x, e.clientX), y = Math.min(p0.y, e.clientY);
      Object.assign(box.style, {left: x + "px", top: y + "px", width: Math.abs(e.clientX - p0.x) + "px", height: Math.abs(e.clientY - p0.y) + "px"}); });
    ov.addEventListener("pointerup", e => {
      if (!p0) { end(); return; }
      const rr = $("#n-zoomroot").getBoundingClientRect();
      const x1 = Math.max(rr.left, Math.min(p0.x, e.clientX)), y1 = Math.max(rr.top, Math.min(p0.y, e.clientY));
      const x2 = Math.min(rr.right, Math.max(p0.x, e.clientX)), y2 = Math.min(rr.bottom, Math.max(p0.y, e.clientY));
      const r = {x: x1, y: y1, w: x2 - x1, h: y2 - y1};
      end(); if (r.w < 40 || r.h < 30) return;
      zoomTo(r);
    });
    const esc_ = ev => { if (ev.key === "Escape") { end(); removeEventListener("keydown", esc_); } };
    addEventListener("keydown", esc_);
  };
  function zoomTo(r) {
    const root = $("#n-zoomroot"), vw = root.clientWidth, vh = root.clientHeight, rr = root.getBoundingClientRect();
    const z = Math.min(4, vw / r.w, vh / r.h);
    const ox = (r.x - rr.left), oy = (r.y - rr.top);
    root.firstElementChild.style.transform = `translate(${(vw - r.w * z) / 2 - ox * z}px,${(vh - r.h * z) / 2 - oy * z}px) scale(${z})`;
    st.zoomRect = r; document.body.classList.add("zoomed"); $("#n-zoom").setAttribute("aria-pressed", "true"); $("#n-zoom").textContent = "확대 해제";
  }
  function unzoom() {
    $("#n-zoomroot").firstElementChild.style.transform = ""; st.zoomRect = null;
    document.body.classList.remove("zoomed"); $("#n-zoom").setAttribute("aria-pressed", "false"); $("#n-zoom").textContent = "영역 확대";
  }

  // ---------------------------------------------------------------- 실시간 이벤트: 흐름(캔버스)·스트림 패널·슬롯 맥박·개체 깜빡임
  const SEVC = {critical: "#ff5a4f", error: "#ff8a3d", warning: "#f2c200", info: "#4fb3e0", notice: "#4fb3e0", debug: "#6b7f88"};
  const SEVSZ = {critical: 6, error: 4.5, warning: 3.2, info: 2.3, notice: 2.3, debug: 1.5};
  const rv = {parts: [], bursts: [], labels: [], eps: {}, cnt: {}, last: performance.now()};
  const pulseAt = {};
  function live(logs) {
    const t = performance.now();
    const n = logs.length, step = n > 80 ? Math.ceil(n / 80) : 1;
    for (let i = 0; i < n; i++) {
      const l = logs[i], s = st.bySource[l.source]; if (!s) continue;
      rv.cnt[s.id] = (rv.cnt[s.id] || 0) + 1;
      const sev = l.severity || "info";
      if (i % step === 0 || sev === "critical" || sev === "error") {
        if (rv.parts.length < 900) rv.parts.push({lane: s.id, x: 0, y: Math.random() - 0.5, v: 0.18 + Math.random() * 0.1 + (SEV_R[sev] || 0) * 0.02, sev, r: SEVSZ[sev] || 2});
        if ((sev === "critical" || sev === "error") && rv.labels.length < 6) rv.labels.push({lane: s.id, text: `${l.host || ""} ${String(l.message || "").slice(0, 70)}`, sev, t0: t});
      }
      if (!pulseAt[s.id] || t - pulseAt[s.id] > 700) {
        pulseAt[s.id] = t;
        const el = $(`#n-grid > [data-slot="${CSS.escape(s.id)}"] .plate`);
        if (el) { el.style.setProperty("--pc", SEVC[sev]); el.classList.remove("beat"); void el.offsetWidth; el.classList.add("beat"); }
      }
      if (sev !== "debug") flashTile(s.id, l);
    }
    streamAdd(logs);
  }
  function flashTile(sid, l) {
    const keys = [l.host, l.entity].filter(Boolean).map(x => String(x).toLowerCase());
    if (!keys.length) return;
    const tiles = $$(`#n-grid > [data-slot="${CSS.escape(sid)}"] .tile`);
    for (const tl of tiles) {
      const n = tl.dataset.ent.toLowerCase(), sn = n.split(".")[0];
      if (keys.some(k => k === n || k.split(".")[0] === sn || k.endsWith("/" + n))) {
        tl.style.setProperty("--pc", SEVC[l.severity] || SEVC.info); tl.classList.remove("blip"); void tl.offsetWidth; tl.classList.add("blip"); break;
      }
    }
  }
  const cv = $("#n-river"), ctx = cv && cv.getContext("2d");
  const TT = x => (window.AIOPS_I18N && window.AIOPS_I18N.t ? window.AIOPS_I18N.t(x) : x);   // 캔버스 글자는 DOM 번역 대상이 아님
  function riverFrame(now_) {
    requestAnimationFrame(riverFrame);
    if (!ctx || document.hidden || $("#n-river-box").hidden) { rv.last = now_; return; }
    const dt = Math.min(64, now_ - rv.last); rv.last = now_;
    const dpr = window.devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight;
    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(H * dpr)) { cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const lanes = st.slots.filter(s => !st.hidden.includes(s.id)), LW = 118, RW = 92, lh = H / Math.max(1, lanes.length), track = W - LW - RW;
    ctx.font = "12px Calibri, 'Pretendard Variable', sans-serif"; ctx.textBaseline = "middle";
    lanes.forEach((s, i) => {
      const y = lh * i + lh / 2;
      ctx.fillStyle = {down: "#ff5a4f", warn: "#f2c200", ok: "#56b62b", idle: "#6b7f88"}[s.state] || "#6b7f88";
      ctx.beginPath(); ctx.arc(10, y, 4, 0, 6.3); ctx.fill();
      ctx.fillStyle = "#c9d6dc"; ctx.fillText(TT(s.name), 20, y);
      ctx.strokeStyle = "#2b4450"; ctx.beginPath(); ctx.moveTo(LW, y); ctx.lineTo(LW + track, y); ctx.stroke();
      const e = rv.eps[s.id] || 0;
      ctx.fillStyle = e ? "#e8eef1" : "#6b7f88"; ctx.textAlign = "right"; ctx.fillText(`${e < 10 ? e.toFixed(1) : Math.round(e)} ${TT("/초")}`, W - 8, y); ctx.textAlign = "left";
    });
    const idx = Object.fromEntries(lanes.map((s, i) => [s.id, i]));
    ctx.globalCompositeOperation = "lighter";
    rv.parts = rv.parts.filter(p => {
      p.x += p.v * dt / 1000 * 1.0;                  // 트랙 비율/초
      const li = idx[p.lane]; if (li === undefined) return false;
      if (p.x >= 1) { if (p.r >= 4) rv.bursts.push({lane: p.lane, r: p.r, sev: p.sev, a: 1}); return false; }
      const x = LW + p.x * track, y = lh * li + lh / 2 + p.y * Math.min(lh - 8, 16);
      if (p.r >= 3) { const g = ctx.createRadialGradient(x, y, 0, x, y, p.r * 3); g.addColorStop(0, SEVC[p.sev]); g.addColorStop(1, "transparent"); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, p.r * 3, 0, 6.3); ctx.fill(); }
      ctx.fillStyle = SEVC[p.sev]; ctx.beginPath(); ctx.arc(x, y, p.r, 0, 6.3); ctx.fill();
      if (p.r >= 4) { ctx.strokeStyle = SEVC[p.sev]; ctx.globalAlpha = .35; ctx.beginPath(); ctx.moveTo(x - 30 * p.v * 4, y); ctx.lineTo(x, y); ctx.stroke(); ctx.globalAlpha = 1; }
      return true;
    });
    rv.bursts = rv.bursts.filter(b => {
      const li = idx[b.lane]; if (li === undefined) return false;
      b.a -= dt / 900; if (b.a <= 0) return false;
      const x = LW + track, y = lh * li + lh / 2, rr = b.r * 2 + (1 - b.a) * 22;
      ctx.strokeStyle = SEVC[b.sev]; ctx.globalAlpha = b.a; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x, y, rr, 0, 6.3); ctx.stroke(); ctx.globalAlpha = 1; ctx.lineWidth = 1;
      return true;
    });
    ctx.globalCompositeOperation = "source-over";
    rv.labels = rv.labels.filter(lb => {
      const age = now_ - lb.t0; if (age > 4500) return false;
      const li = idx[lb.lane]; if (li === undefined) return false;
      ctx.globalAlpha = Math.min(1, (4500 - age) / 800); ctx.fillStyle = SEVC[lb.sev];
      ctx.fillText(lb.text, LW + track * 0.45, lh * li + lh / 2 - Math.min(11, lh / 3)); ctx.globalAlpha = 1;
      return true;
    });
  }
  setInterval(() => { for (const s of st.slots) { const c = rv.cnt[s.id] || 0; rv.eps[s.id] = (rv.eps[s.id] || 0) * 0.5 + c * 0.5; rv.cnt[s.id] = 0; } }, 1000);
  requestAnimationFrame(riverFrame);

  // 스트림 패널(최근 이벤트가 위에서 밀려 들어옴, 마우스를 올리면 멈춤)
  st.streamMin = pref("noc.streamMin") || "info";
  const sq = []; let streamPaused = false;
  function streamShell() {
    return `<div class="plate"><h2>${panelTools("stream")}<button data-focus="stream" title="이 패널만 크게">${XP.stream}</button>${panelTools2("stream")}</h2>
      <div class="state"><select id="n-smin" aria-label="최소 등급">${["info", "warning", "error", "critical"].map(x => `<option value="${x}" ${st.streamMin === x ? "selected" : ""}>${x === "critical" ? SEV_KO[x] : SEV_KO[x] + "↑"}</option>`).join("")}</select>
      <span id="n-scount">대기 중</span></div></div><ol class="stream" id="n-stream" aria-live="off"></ol>`;
  }
  function streamAdd(logs) {
    const min = SEV_R[st.streamMin] || 0;
    for (const l of logs) if ((SEV_R[l.severity] || 0) >= min) sq.push(l);
    if (sq.length > 200) sq.splice(0, sq.length - 200);
  }
  setInterval(() => {
    const ol = $("#n-stream"); if (!ol || streamPaused || !sq.length) return;
    const take = sq.splice(Math.max(0, sq.length - 8));
    sq.length = 0;
    const frag = document.createDocumentFragment();
    for (const l of take) {
      const li = document.createElement("li"); li.className = `sr ${l.severity}`;
      li.innerHTML = `<time>${hms(l.ts || now())}</time><b>${esc(SEV_KO[l.severity] || l.severity)}</b><span class="src">${esc(l.source)}</span><span class="hst">${esc(l.host || "")}</span><span class="msg">${esc(String(l.message || "").slice(0, 240))}</span>`;
      frag.prepend(li);
    }
    ol.prepend(frag);
    while (ol.children.length > 80) ol.lastElementChild.remove();
    $("#n-scount").textContent = `${hms(now())} 수신`;
  }, 400);
  $("#n-grid").addEventListener("mouseover", e => { if (e.target.closest("#n-stream")) streamPaused = true; });
  $("#n-grid").addEventListener("mouseout", e => { if (e.target.closest("#n-stream") && !e.relatedTarget?.closest?.("#n-stream")) streamPaused = false; });
  $("#n-grid").addEventListener("change", e => { if (e.target.id === "n-smin") { st.streamMin = e.target.value; pref("noc.streamMin", st.streamMin); } });
  $("#n-grid").addEventListener("click", e => {
    const li = e.target.closest(".sr"); if (!li || (me && me.kiosk)) return;
    const h = li.querySelector(".hst").textContent; if (h) window.open(`/#tail/${encodeURIComponent(h)}`, "_blank", "noopener");
  });

  // ---------------------------------------------------------------- NSX ALB VIP 별 실시간 트래픽
  const fmtBw = b => b == null ? "-" : b >= 1e9 ? `${(b / 1e9).toFixed(2)}<small>Gb/s</small>` : b >= 1e6 ? `${(b / 1e6).toFixed(1)}<small>Mb/s</small>` : b >= 1e3 ? `${(b / 1e3).toFixed(0)}<small>kb/s</small>` : `${Math.round(b)}<small>b/s</small>`;
  const fmtN = v => v == null ? "-" : v >= 1000 ? `${(v / 1000).toFixed(1)}k` : (Math.round(v * 10) / 10).toString();
  function spark(vals, w = 160, h = 34, color = "#4fb3e0") {
    const v = (vals || []).map(x => x == null ? null : Number(x)); const ok = v.filter(x => x != null);
    if (ok.length < 2) return `<svg viewBox="0 0 ${w} ${h}" class="spk"><text x="4" y="${h / 2}" fill="#6b7f88" font-size="10">${ok.length === 1 ? "값 1개(추세 대기)" : "데이터 대기"}</text></svg>`;
    const mx = Math.max(...ok) || 1, mn = Math.min(0, ...ok), dx = w / (v.length - 1);
    const pts = v.map((x, i) => `${(i * dx).toFixed(1)},${(h - 2 - ((x ?? mn) - mn) / (mx - mn || 1) * (h - 4)).toFixed(1)}`);
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="spk"><path d="M0,${h} L${pts.join(" L")} L${w},${h}Z" fill="${color}" opacity=".18"/><polyline points="${pts.join(" ")}" fill="none" stroke="${color}" stroke-width="1.6"/><circle cx="${pts[pts.length - 1].split(",")[0]}" cy="${pts[pts.length - 1].split(",")[1]}" r="2.6" fill="${color}"/></svg>`;
  }
  let vipT;
  function vipData(items) {
    const prev = Object.fromEntries(st.vips.map(v => [v.uuid, v.last || {}]));
    st.vips = items || []; st.vipPrev = prev;
    clearTimeout(vipT);
    vipT = setTimeout(() => { if (!panelOn("vip")) { render(); return; } if (!$(`#n-grid > [data-slot="vip"]`)) { render(); return; } patch("vip", vipHtml()); }, 60);
  }
  function vipHtml() {
    const vs = st.vips.slice().sort((a, b) => st.vipSort === "name" ? a.name.localeCompare(b.name) : ((b.last || {})[st.vipSort] || 0) - ((a.last || {})[st.vipSort] || 0));
    const down = vs.filter(v => v.state && v.state !== "OPER_UP").length;
    const tot = vs.reduce((a, v) => a + ((v.last || {}).bw || 0), 0), rps = vs.reduce((a, v) => a + ((v.last || {}).rps || 0), 0);
    const withData = vs.filter(v => v.mstate ? v.mstate === "ok" : v.step), step = ((withData[0] || vs.find(v => v.step)) || {}).step;
    const note = !withData.length && vs.length ? ((vs.find(v => v.mnote) || {}).mnote || "") : "";
    const cls = down ? "s-warn" : vs.length ? "s-ok" : "s-idle";
    const trend = (v, k) => { const p = (st.vipPrev[v.uuid] || {})[k], c = (v.last || {})[k]; if (p == null || c == null || p === c) return ""; return c > p ? `<i class="up">▲</i>` : `<i class="dn">▼</i>`; };
    return `<section class="slot xpanel ${cls}" aria-label="NSX ALB VIP 트래픽"><div class="plate"><h2>${panelTools("vip")}<button data-focus="vip" title="이 패널만 크게">${XP.vip}</button>${panelTools2("vip")}</h2>
      <div class="state"><b>${fmtBw(tot)}</b><span>VIP ${vs.length}개${down ? ` · 비정상 ${down}` : ""} · 요청 ${fmtN(rps)}/초 · ${step === 5 ? "5초 실시간" : step ? `5분 평균${withData.length < vs.length ? ` · 값 ${withData.length}/${vs.length}` : ""}` : "수집 대기"}</span></div></div>
      ${note ? `<div class="vip-note" title="${esc(note)}">메트릭 미수신 — ${esc(note)}</div>` : ""}
      <div class="vsort">정렬 ${[["bw", "대역폭"], ["rps", "요청/초"], ["cps", "연결/초"], ["err", "오류"], ["name", "이름"]].map(([k, l]) => `<button data-vsort="${k}" class="${st.vipSort === k ? "on" : ""}">${l}</button>`).join("")}</div>
      <div class="vipgrid">${vs.length ? vs.slice(0, 60).map(v => { const L = v.last || {}, s = v.series || {}, bad = v.state && v.state !== "OPER_UP";
        return `<button class="vip ${bad ? "bad" : ""}" data-vip="${esc(v.uuid)}" title="${esc(v.name)} — ${esc((v.vips || []).join(", "))} · ${esc(v.state || "")}${v.tenant ? " · 테넌트 " + esc(v.tenant) : ""}${v.mnote ? "\n" + esc(v.mnote) : ""}">
          <div class="vh"><i class="${bad ? "d" : "o"}"></i><b>${esc(v.name)}</b>${v.health != null ? `<span class="hs ${v.health < 50 ? "lo" : v.health < 80 ? "mid" : ""}">${v.health}</span>` : ""}</div>
          <div class="va">${esc((v.vips || []).join(", ") || "-")}${(v.ports || []).length ? `:${v.ports.join(",")}` : ""}</div>
          <div class="vb">${v.mstate === "idle" ? `<small class="vnone" title="${esc(v.mnote || "")}">트래픽 없음</small>` : v.mstate === "ok" || (v.step && !v.mstate) ? `${fmtBw(L.bw)} ${trend(v, "bw")}` : `<small class="vnone" title="${esc(v.mnote || "")}">메트릭 없음</small>`}</div>${spark(s.bw, 160, 34, bad ? "#ff5a4f" : "#4fb3e0")}
          <div class="vm"><span>연결/초 <b>${fmtN(L.cps)}</b></span><span>요청/초 <b>${fmtN(L.rps)}</b>${trend(v, "rps")}</span><span>RTT <b>${fmtN(L.rtt)}</b>ms</span><span class="${L.err ? "e" : ""}">오류 <b>${fmtN(L.err)}</b>/초</span></div></button>`; }).join("")
        : `<div class="empty">${(st.slots.find(x => x.id === "avi") || {connectors: []}).connectors.length ? "VIP 트래픽 수집 대기(10초 주기)" : esc(ADD_HINT.avi)}</div>`}</div></section>`;
  }
  $("#n-grid").addEventListener("click", e => { const b = e.target.closest("[data-vsort]"); if (b) { st.vipSort = b.dataset.vsort; pref("noc.vipSort", st.vipSort); patch("vip", vipHtml()); } });
  function vipDetail(uuid) {
    const v = st.vips.find(x => x.uuid === uuid); if (!v) return;
    const fB = b => b == null ? "-" : b >= 1e9 ? `${(b / 1e9).toFixed(2)} GB/s` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB/s` : b >= 1e3 ? `${(b / 1e3).toFixed(1)} kB/s` : `${Math.round(b)} B/s`;
    const fSz = b => b == null ? "-" : b >= 1e9 ? `${(b / 1e9).toFixed(2)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${(b / 1e3).toFixed(1)} kB` : `${b} B`;
    // 처리량(Avi l4_client·l7_client 메트릭) — 값이 없는 지표는 숨김
    const S = [["bw", "대역폭", "#4fb3e0", "bw"], ["rx", "수신(클라이언트→VIP)", "#4fb3e0", "B"], ["tx", "송신(VIP→클라이언트)", "#7fc7a8", "B"], ["rxp", "수신 패킷/초", "#4fb3e0"],
               ["txp", "송신 패킷/초", "#7fc7a8"], ["cps", "완료 연결/초", "#9b8cff"], ["newc", "신규 연결/초", "#9b8cff"], ["open", "열린 연결", "#7fc7a8"], ["maxopen", "최대 열린 연결", "#7fc7a8"],
               ["drop", "끊긴 연결/초", "#ff5a4f"], ["rps", "HTTP 응답/초", "#56b62b"], ["r2xx", "2xx/초", "#56b62b"], ["r4xx", "4xx/초", "#f2c200"], ["r5xx", "5xx/초", "#ff5a4f"],
               ["err", "오류 응답/초", "#ff5a4f"], ["errpct", "오류 비율 %", "#ff5a4f"], ["sslnew", "신규 SSL 세션/초", "#9b8cff"], ["sslerr", "SSL 오류/초", "#ff5a4f"],
               ["rtt", "RTT(ms)", "#f2c200"], ["txlat", "클라이언트 트랜잭션 지연", "#f2c200"], ["apdex", "Apdex(응답)", "#56b62b"]];
    const val = (k, u, x) => u === "bw" ? fmtBw(x) : u === "B" ? fB(x) : fmtN(x);
    const have = S.filter(([k]) => ((v.series || {})[k] || []).some(x => x != null));
    const ST = {ok: ["정상 수집", "ok"], idle: ["트래픽 없음", "idle"], error: ["수집 실패", "err"], nodata: ["값 없음", "err"]};
    const ago = t => t ? `${Math.max(0, Math.round(Date.now() / 1000 - t))}초 전` : "-";
    const diag = () => { const [lab, cls] = ST[v.mstate] || (v.step ? ST.ok : ["수집 대기", "idle"]);
      return `<div class="vip-diag ${cls}"><b>${lab}</b><span>${v.step === 5 ? "5초 실시간" : v.step === 300 ? "5분 평균" : "간격 미정"} · 갱신 ${ago(v.updated)}${v.tenant ? ` · 테넌트 ${esc(v.tenant)}` : ""}</span>${v.mnote ? `<small>${esc(v.mnote)}</small>` : ""}</div>`; };
    const thr = () => `${diag()}<div class="vipd">${(have.length ? have : S.slice(0, 6)).map(([k, l, c, u]) => `<div><div class="vdl">${l} <b>${val(k, u, (v.last || {})[k])}</b>${(v.avg || {})[k] != null ? `<small> 평균 ${val(k, u, v.avg[k])}</small>` : ""}</div>${spark((v.series || {})[k], 420, 60, c)}</div>`).join("")}</div>
      <p class="small">VIP ${esc((v.vips || []).join(", "))} · 포트 ${esc((v.ports || []).join(", ") || "-")} · 풀 ${esc(v.pool || "-")}${v.pool_group ? ` · 풀 그룹 ${esc(v.pool_group)}` : ""}${v.pool_servers != null ? ` (멤버 ${v.pool_up ?? "-"}/${v.pool_servers} up)` : ""} · SE ${esc((v.ses || []).join(", ") || "-")} · SE 그룹 ${esc(v.se_group || "-")} · 컨트롤러 ${esc(v.controller || "")}</p>`;
    const bar = (rows, tot) => rows.length ? rows.map(r => `<div class="eub"><span title="${esc(r.k)}">${esc(r.k)}</span><i style="width:${Math.max(2, Math.round(r.n / (tot || 1) * 100))}%"></i><b>${r.n}</b></div>`).join("") : `<p class="muted small">없음</p>`;
    const eu = d => d.error ? `<div class="vip-note">${esc(d.error)}</div>` : `
      <div class="eu-k"><div><span>로그 표본</span><b>${d.logs}</b><small>최근 ${d.minutes}분${d.total_reported != null ? ` · 전체 ${d.total_reported}` : ""}</small></div>
        <div><span>고유 클라이언트</span><b>${d.unique_clients}</b><small>중요 로그 ${d.significant}</small></div>
        <div><span>응답 지연</span><b>${d.latency_ms.avg ?? "-"}<small>ms</small></b><small>p95 ${d.latency_ms.p95 ?? "-"} · p99 ${d.latency_ms.p99 ?? "-"}</small></div>
        <div><span>클라이언트 RTT</span><b>${d.client_rtt_ms ?? "-"}<small>ms</small></b><small>&nbsp;</small></div>
        <div><span>요청·응답 바이트</span><b>${fSz(d.req_bytes)} · ${fSz(d.resp_bytes)}</b><small>표본 합계</small></div></div>
      ${d.note ? `<div class="vip-note">${esc(d.note)}</div>` : ""}
      <h4>상위 클라이언트</h4><table class="tbl eu-t"><tr><th>클라이언트 IP</th><th>요청</th><th>오류</th><th>바이트</th><th>평균 ms</th><th>OS</th><th>브라우저</th><th>위치</th></tr>
        ${(d.top_clients || []).map(c => `<tr><td class="mono">${esc(c.ip || "(미상)")}</td><td>${c.n}</td><td class="${c.err ? "e" : ""}">${c.err}</td><td>${fSz(c.bytes)}</td><td>${c.avg_ms ?? "-"}</td><td>${esc(c.os || "")}</td><td>${esc(c.browser || "")}</td><td>${esc(c.location || "")}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">없음</td></tr>`}</table>
      <div class="eu-g">${[["응답 코드", "codes"], ["OS", "os"], ["브라우저", "browser"], ["기기", "device"], ["위치", "location"], ["도메인(Host)", "hosts"], ["URI", "uris"], ["메서드", "methods"], ["풀 서버", "servers"], ["SSL/TLS", "ssl"]]
        .map(([t, k]) => `<div><h5>${t}</h5>${bar(d[k] || [], d.logs)}</div>`).join("")}</div>`;
    const mem = () => (v.members || []).length ? `<table class="tbl eu-t"><tr><th>풀</th><th>멤버 IP</th><th>포트</th><th>호스트명</th><th>사용</th></tr>${v.members.map(m => `<tr><td class="small">${esc(m.pool || v.pool || "")}</td><td class="mono">${esc(m.ip)}</td><td>${esc(m.port ?? "")}</td><td>${esc(m.hostname || "")}</td><td>${m.enabled === false ? "비활성" : "예"}</td></tr>`).join("")}</table>
      <p class="small"><a href="/noc/topology" data-flow-open="${esc(v.uuid)}">흐름도에서 멤버 → VM·Pod → ESXi → 서버 경로 보기</a></p>` : `<p class="muted">풀 멤버 정보 없음(풀 인벤토리는 5분 주기)</p>`;
    let tab = "thr", euData = null, mins = 60;
    const body = () => `<div class="eu-tabs">${[["thr", "처리량"], ["eu", "End user"], ["mem", "풀 멤버"]].map(([k, l]) => `<button data-eut="${k}" class="${tab === k ? "on" : ""}">${l}</button>`).join("")}
        ${tab === "eu" ? `<select id="eu-min">${[15, 60, 360, 1440].map(m => `<option value="${m}" ${m === mins ? "selected" : ""}>최근 ${m < 60 ? m + "분" : m / 60 + "시간"}</option>`).join("")}</select>` : ""}</div>
      ${tab === "thr" ? thr() : tab === "mem" ? mem() : euData ? eu(euData) : `<p class="muted">불러오는 중…</p>`}`;
    const loadEu = async m => { euData = null; m.querySelector("#vipd-body").innerHTML = body();
      try { euData = await A.api("GET", `/api/avi/vips/${encodeURIComponent(uuid)}/endusers?minutes=${mins}`); } catch (e) { euData = {error: e.message}; }
      if (document.body.contains(m) && tab === "eu") m.querySelector("#vipd-body").innerHTML = body(); };
    A.modal({title: `${v.name} — ${v.state || ""} · Health ${v.health ?? "-"}`, wide: true, ok: "", cancel: "닫기", html: `<div id="vipd-body">${body()}</div>`,
      onOpen: m => {
        m.addEventListener("click", e => { const b = e.target.closest("[data-eut]"); if (b) { tab = b.dataset.eut; m.querySelector("#vipd-body").innerHTML = body(); if (tab === "eu" && !euData) loadEu(m); }
          const fo = e.target.closest("[data-flow-open]"); if (fo) { e.preventDefault(); location.href = `/noc/topology?flow=${encodeURIComponent(fo.dataset.flowOpen)}`; } });
        m.addEventListener("change", e => { if (e.target.id === "eu-min") { mins = Number(e.target.value); loadEu(m); } });
        const t = setInterval(() => { if (!document.body.contains(m)) { clearInterval(t); return; } const n = st.vips.find(x => x.uuid === uuid); if (n && tab === "thr") { Object.assign(v, n); m.querySelector("#vipd-body").innerHTML = body(); } }, 3000); }});
  }

  // ---------------------------------------------------------------- 상단 지표 띠 · AI 상태 · VM 액티비티 패널
  const MV_KO = {vmotion: "vMotion", drs: "DRS", svmotion: "Storage vMotion", relocate: "콜드 이전", ha_restart: "HA 재시작", ha_failed: "HA 실패",
                 ha_reset: "HA 리셋", ha_reset_failed: "HA 리셋 실패", host_failed: "호스트 장애", host_isolated: "호스트 격리", move_failed: "이동 실패", detected: "위치 변경", created: "VM 생성", cloned: "VM 복제", deployed: "템플릿 배포", registered: "VM 등록", removed: "VM 삭제", renamed: "이름 변경", create_failed: "생성 실패", detected_new: "새 VM 감지", detected_gone: "VM 사라짐", power_on: "전원 켬", power_off: "전원 끔", suspended: "일시 중단", reset: "리셋", guest_shutdown: "게스트 종료", guest_reboot: "게스트 재시작", reconfigured: "구성 변경", snapshot_create: "스냅샷 생성", snapshot_remove: "스냅샷 삭제", snapshot_remove_all: "스냅샷 모두 삭제", snapshot_revert: "스냅샷 되돌림"};
  const MV_HA = new Set(["ha_restart", "ha_failed", "ha_reset", "ha_reset_failed", "host_failed", "host_isolated"]);
  const MV_LIFE = new Set(["power_on", "power_off", "suspended", "reset", "guest_shutdown", "guest_reboot", "reconfigured", "snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert", "created", "cloned", "deployed", "registered", "removed", "renamed", "create_failed", "detected_new", "detected_gone"]);
  async function loadKpi() {
    try { st.kpi = await A.api("GET", "/api/noc/kpi", undefined, {background: true}); } catch { return; }
    const had = !!$(`#n-grid > [data-slot="moves"]`);
    kpiRender();
    if (panelOn("moves")) { if (!had) render(); else patch("moves", movesHtml()); }
  }
  function kpiRender() {
    const k = st.kpi; if (!k) return;
    const inc = k.incidents || {}, ninc = Object.values(inc).reduce((a, b) => a + b, 0), m = k.moves_1h || {}, ai = k.ai || {};
    const cell = (cls, label, val, sub, act = "") => `<div class="kc ${cls}" ${act}><span>${label}</span><b>${val}</b><small>${sub}</small></div>`;
    $("#n-kpi").innerHTML = [
      cell("", "VM", (k.vms || 0).toLocaleString(), `켜짐 ${(k.vms_on || 0).toLocaleString()}`),
      cell(k.hosts_bad ? "bad" : k.hosts_maint ? "warn" : "", "ESXi 호스트", k.hosts || 0, `${k.clusters || 0} 클러스터${k.hosts_bad ? ` · 연결 이상 ${k.hosts_bad}` : ""}${k.hosts_maint ? ` · 유지보수 ${k.hosts_maint}` : ""}`),
      cell(k.alarms.red ? "bad" : k.alarms.yellow ? "warn" : "", "vCenter 알람", k.alarms.total, `위험 ${k.alarms.red} · 경고 ${k.alarms.yellow}`),
      cell(inc.critical ? "bad" : ninc ? "warn" : "", "열린 인시던트", ninc, `위험 ${inc.critical || 0} · 오류 ${inc.error || 0}`),
      cell("", "VM 이동(1시간)", m.move || 0, `DRS ${m.drs || 0} · 생성 ${m.created || 0} · 삭제 ${m.deleted || 0}${m.failed ? ` · 실패 ${m.failed}` : ""}`, `data-kmv="1"`),
      cell(m.ha ? "bad" : k.ha_6h ? "warn" : "", "HA(1시간)", m.ha || 0, `6시간 ${k.ha_6h || 0}`, `data-kmv="1"`),
      k.security ? cell(k.security.attackers ? "bad" : "", "공격 출발지", k.security.attackers, `차단 ${(k.security.denied || 0).toLocaleString()}/15분`) : "",
      cell(!ai.on ? "off" : ai.hot ? "bad" : (ai.queue || 0) > 100 ? "warn" : "", "AI 분석", ai.on ? "켜짐" : "꺼짐",
           ai.on ? `대기 ${ai.queue || 0}${ai.gpu_temp != null ? ` · GPU ${ai.gpu_temp}°C` : ""}${ai.hot ? " · 과열 대기" : ""}` : "규칙 탐지만"),
      cell("", "수집", `${(k.eps || 0).toLocaleString()}<i>/초</i>`, "이벤트 유입"),
    ].join("");
    const b = $("#n-ai");
    if (b) { b.className = `plat ${!ai.on ? "idle" : ai.hot || ai.provider_state === "down" ? "down" : ai.provider_state === "degraded" || (ai.queue || 0) > 100 ? "warn" : "ok"}`;
      b.textContent = ai.on ? `AI ${ai.provider || ""}${ai.queue ? ` · 대기 ${ai.queue}` : ""}` : "AI 꺼짐";
      b.title = ai.on ? `${ai.provider} / ${ai.model} · 패턴 ${(ai.patterns || {}).patterns || 0} · 재사용 ${(ai.patterns || {}).reused_total || 0}${ai.waiting ? " · " + ai.waiting : ""}` : "AI 분석 꺼짐 — 규칙 탐지만"; }
  }
  function movesHtml() {
    const k = st.kpi || {}, ms = k.moves || [], m = k.moves_1h || {};
    const ha = ms.filter(x => MV_HA.has(x.type) && now() - x.ts < 3600).length;
    const cls = ha ? "s-down" : m.failed ? "s-warn" : ms.length ? "s-ok" : "s-idle";
    return `<section class="slot xpanel ${cls}" aria-label="VM 액티비티"><div class="plate"><h2>${panelTools("moves")}<button data-focus="moves" title="이 패널만 크게">${XP.moves}</button>${panelTools2("moves")}</h2>
      <div class="state"><b>${ha ? `HA ${ha}` : (m.move || 0)}</b><span>${ha ? "최근 1시간 vSphere HA 동작" : "최근 1시간 이동"} · DRS ${m.drs || 0} · 생성 ${m.created || 0} · 삭제 ${m.deleted || 0} · 6시간 HA ${k.ha_6h || 0}</span></div></div>
      <ol class="mvlist">${ms.length ? ms.slice(0, 18).map(x => `<li class="${MV_HA.has(x.type) ? "ha" : (x.type === "move_failed" || x.type === "create_failed") ? "fail" : MV_LIFE.has(x.type) ? "life" : ""}" data-mvvm="${esc(x.vm || x.from_host)}"><time>${hm(x.ts)}</time><b>${esc(MV_KO[x.type] || x.type)}</b>
        <span class="vm">${esc(x.vm || "-")}</span><span class="fl">${MV_LIFE.has(x.type) ? esc(x.to_host || x.from_host || "") : `${esc(x.from_host || "?")} → ${esc(x.to_host || "?")}`}</span></li>`).join("")
        : `<li class="empty">최근 6시간 VM 액티비티 기록 없음</li>`}</ol></section>`;
  }
  function onMove(r) {
    if (!st.kpi) return;
    if (r.enriched) { st.kpi.moves = (st.kpi.moves || []).map(x => x.key === r.key ? r : x); if (panelOn("moves") && $(`#n-grid > [data-slot="moves"]`)) patch("moves", movesHtml()); return; }
    st.kpi.moves = [r, ...(st.kpi.moves || [])].slice(0, 25);
    const m = st.kpi.moves_1h = st.kpi.moves_1h || {};
    if (MV_HA.has(r.type)) { m.ha = (m.ha || 0) + 1; st.kpi.ha_6h = (st.kpi.ha_6h || 0) + 1; if (st.sound && ["ha_failed", "host_failed", "host_isolated"].includes(r.type)) beep(); }
    else if (["move_failed"].includes(r.type)) m.failed = (m.failed || 0) + 1;
    else { m.move = (m.move || 0) + 1; if (r.type === "drs") m.drs = (m.drs || 0) + 1; }
    kpiRender();
    if (panelOn("moves")) { if ($(`#n-grid > [data-slot="moves"]`)) patch("moves", movesHtml()); else render(); }
  }
  setInterval(() => loadKpi().catch(() => {}), 15000);
  $("#n-kpi").addEventListener("click", e => { if (e.target.closest("[data-kmv]") && !(me && me.kiosk)) window.open("/#mv", "_blank", "noopener"); });
  $("#n-ai").onclick = () => {
    const ai = (st.kpi || {}).ai || {}, p = ai.patterns || {};
    A.modal({title: `AI 분석 — ${ai.on ? "켜짐" : "꺼짐"}`, ok: "", cancel: "닫기", html: `<dl class="dl"><dt>공급자</dt><dd>${esc(ai.provider || "-")} / ${esc(ai.model || "-")} (${esc(ai.provider_state || "")})${ai.external ? " · 외부·가명화" : ""}</dd>
      <dt>대기</dt><dd>${ai.queue || 0}건${ai.rate_per_min ? ` · 분당 ${ai.rate_per_min}` : ""}${ai.waiting ? ` · ${esc(ai.waiting)}` : ""}</dd>
      <dt>GPU</dt><dd>${ai.gpu_temp != null ? `${ai.gpu_temp}°C` : "지표 미설정"}${ai.hot ? " · 과열 보호로 자동 분석 일시 중지" : ""}</dd>
      <dt>로그 패턴</dt><dd>${p.patterns || 0}개 · 분석됨 ${p.analyzed || 0} · 재사용 ${p.reused_total || 0}회(LLM 호출 절약)</dd></dl>
      <p class="small">켜기·끄기는 운영 콘솔 머리글의 'AI 분석' 스위치에서 합니다.</p>`});
  };

  // ---------------------------------------------------------------- 포커스·자동 순환
  function setFocus(id) { st.focus = st.focus === id ? null : id; render(); }
  setInterval(() => {
    if (!st.cycle) return;
    const bad = st.slots.filter(s => s.state === "down" || s.state === "warn");
    if (!bad.length) { if (st.focus) { st.focus = null; render(); } return; }
    st.cycleIdx = (st.cycleIdx + 1) % bad.length;
    st.focus = bad[st.cycleIdx].id; render();
  }, 20000);

  // ---------------------------------------------------------------- 조작
  $("#n-grid").addEventListener("click", e => {
    const t = e.target;
    const f = t.closest("[data-focus]"); if (f) { setFocus(f.dataset.focus); return; }
    const sc = t.closest("[data-scale]"); if (sc) { scalePanel(sc.closest(".slot").dataset.slot, Number(sc.dataset.scale)); return; }
    const vc = t.closest("[data-vip]"); if (vc) { vipDetail(vc.dataset.vip); return; }
    const ack = t.closest("[data-ack]"); if (ack) { st.alarmAck[ack.dataset.ack] = true; render(); return; }
    const ent = t.closest("[data-ent]");
    if (ent) { const sid = ent.closest(".slot").dataset.slot; st.filter[sid] = st.filter[sid] === ent.dataset.ent ? null : ent.dataset.ent; render(); return; }
    const uf = t.closest("[data-unfilter]"); if (uf) { st.filter[uf.dataset.unfilter] = null; render(); return; }
    const inc = t.closest("[data-incs]"); if (inc) { incidents(inc.dataset.incs); return; }
    const r = t.closest(".row[data-aid]"); if (r) detail(r.dataset.aid);
  });
  $("#n-tl").addEventListener("click", e => { const m = e.target.closest("[data-aid]"); if (m) detail(m.dataset.aid); });
  document.addEventListener("keydown", e => {
    if (document.querySelector(".modal")) return;
    if (e.key === "Escape" && st.zoomRect) { unzoom(); return; }
    if (e.key === "Escape" && st.focus) { st.focus = null; render(); }
    const n = Number(e.key); if (!e.altKey && !e.ctrlKey && n >= 1 && n <= st.slots.length && !e.target.closest("input,textarea")) setFocus(st.slots[n - 1].id);
    if (e.key === "Enter") { const r = e.target.closest && e.target.closest(".row[data-aid]"); if (r) detail(r.dataset.aid); }
  });
  function findA(id) { for (const s of st.slots) { const a = s.anomalies.find(x => x.id === id); if (a) return a; } return null; }
  function incidents(sid) {
    const s = st.slots.find(x => x.id === sid); if (!s) return;
    A.modal({title: `${s.name} 활성 인시던트 ${s.incident_count}건`, wide: true, ok: "", cancel: "닫기", html: s.incidents.map(i => `<div class="row ${esc(i.severity)}" style="cursor:default">
      <span class="tm">${hm(i.created)}</span><span class="bar"></span><span class="ti">${esc(i.title)}</span>
      <span class="mt"><span class="sv">${SEV_KO[i.severity] || ""}</span><span>${esc(i.status)}</span><span>담당 ${esc(i.assignee || "미지정")}</span>
      ${(i.sla || {}).ack_breached || (i.sla || {}).resolve_breached ? '<span class="esc">SLA 초과</span>' : ""}${(i.itsm || {}).number ? `<span>${esc(i.itsm.number)}</span>` : ""}
      ${me && !me.kiosk ? `<a class="inc" href="/#incident/${encodeURIComponent(i.id)}" target="_blank" rel="noopener">${esc(i.id)} 열기</a>` : `<span class="inc">${esc(i.id)}</span>`}</span></div>`).join("")});
  }
  function detail(id) {
    const a = findA(id); if (!a) return;
    const e = a.event || {}, ai = a.ai || {};
    const canOp = A.can("operate") && !(me && me.kiosk);
    A.modal({title: a.title, wide: true, ok: "", cancel: "닫기", html: `<dl class="dl">
      <dt>심각도</dt><dd>${SEV_KO[a.severity] || esc(a.severity)}${a.count > 1 ? ` · ${a.count}회` : ""}${a.escalated ? ` · ${hm(a.escalated)} 에스컬레이션` : ""}</dd>
      <dt>발생</dt><dd>${new Date(a.created * 1000).toLocaleString()} (최근 ${hms(a.last_seen)}, ${dur(now() - a.created)} 전)</dd>
      <dt>대상</dt><dd>${esc(e.source)} · ${esc(e.host)}${e.entity ? " / " + esc(e.entity) : ""}</dd>
      <dt>탐지 근거</dt><dd>${(a.reasons || []).map(esc).join(", ") || "-"}</dd>
      ${ai.summary ? `<dt>AI 요약</dt><dd>${esc(ai.summary)}</dd>` : ""}${ai.probable_cause ? `<dt>추정 원인</dt><dd>${esc(ai.probable_cause)}</dd>` : ""}
      ${ai.impact ? `<dt>영향</dt><dd>${esc(ai.impact)}</dd>` : ""}
      ${(ai.actions || []).length ? `<dt>조치</dt><dd>${ai.actions.map(x => esc(x)).join("<br>")}</dd>` : ""}
      ${a.suppressed ? `<dt>억제</dt><dd>${esc(a.suppressed)}</dd>` : ""}${a.ack ? "<dt>처리</dt><dd>확인됨</dd>" : ""}</dl>
      <p class="raw">${esc(e.message || "")}</p>
      <div class="detail-acts">${canOp && !a.ack ? `<button class="pri" data-da="ack">확인 처리</button>` : ""}
        ${canOp ? `<button data-da="re">AI 재분석</button><button data-da="silence">사일런스</button>` : ""}
        ${e.host && !(me && me.kiosk) ? `<a href="/#tail/${encodeURIComponent(e.host)}" target="_blank" rel="noopener">${esc(e.host)} 실시간 로그</a>` : ""}
        ${a.incident_id && !(me && me.kiosk) ? `<a href="/#incident/${encodeURIComponent(a.incident_id)}" target="_blank" rel="noopener">인시던트 ${esc(a.incident_id)} 열기</a>` : a.incident_id ? `<span>인시던트 ${esc(a.incident_id)}</span>` : ""}</div>`,
      onOpen: m => m.addEventListener("click", async ev => {
        const b = ev.target.closest("[data-da]"); if (!b) return;
        b.disabled = true;
        try {
          if (b.dataset.da === "ack") { await A.api("POST", `/api/anomalies/${encodeURIComponent(id)}/ack`); A.ok("확인 처리됨", a.title); m.querySelector("[data-x]").click(); }
          if (b.dataset.da === "re") { await A.api("POST", `/api/anomalies/${encodeURIComponent(id)}/analyze`); A.ok("AI 재분석 요청됨"); }
          if (b.dataset.da === "silence") {
            m.querySelector("[data-x]").click();
            const v = await A.modal({title: "사일런스 — 같은 유형 알림 억제", html: `<p class="modal-text">${esc(a.title)}</p>`, ok: "사일런스",
              fields: [{id: "hours", label: "기간", type: "select", value: "4", options: [["1", "1시간"], ["4", "4시간"], ["8", "8시간"], ["24", "1일"]]},
                       {id: "reason", label: "사유", required: true, placeholder: "예) 작업 중 예상된 경고 · CHG0012345"}]});
            if (v) { await A.api("POST", `/api/anomalies/${encodeURIComponent(id)}/silence`, {hours: Number(v.hours), reason: v.reason}); A.ok("사일런스 등록"); }
          }
        } catch (err) { A.fail("처리 실패", err); }
        b.disabled = false;
      })});
  }
  $("#n-open").onchange = e => { st.openOnly = e.target.checked; pref("noc.openOnly", st.openOnly ? "1" : "0"); render(); };
  $("#n-cycle").onclick = e => { st.cycle = !st.cycle; e.target.setAttribute("aria-pressed", st.cycle); pref("noc.cycle", st.cycle ? "1" : "0"); if (!st.cycle && st.focus) { st.focus = null; render(); } };
  $("#n-brief-refresh").onclick = () => { $("#n-brief-meta").textContent = "갱신 중…"; loadBrief(true); };
  let audio;
  function beep() {
    if (!st.sound) return;
    try { audio = audio || new AudioContext(); const o = audio.createOscillator(), g = audio.createGain();
      o.frequency.value = 880; g.gain.value = .08; o.connect(g); g.connect(audio.destination); o.start(); o.stop(audio.currentTime + .25); } catch { /* 무시 */ }
  }
  $("#n-sound").onclick = e => { st.sound = !st.sound; e.target.setAttribute("aria-pressed", st.sound); e.target.textContent = st.sound ? "소리 끄기" : "소리 켜기"; if (st.sound) beep(); };
  $("#n-full").onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(() => {});
  const tick = () => { const d = new Date(); $("#n-time").textContent = `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    $("#n-date").textContent = d.toLocaleDateString((window.AIOPS_I18N || {}).lang === "en" ? "en-US" : "ko-KR", {year: "numeric", month: "long", day: "numeric", weekday: "short"}); };
  tick(); setInterval(tick, 1000);

  let me = null;
  A.ready.then(async m => {
    if (m === null) return;
    me = m;
    if (me.kiosk) $("#n-console").hidden = true;
    $("#n-brief-refresh").hidden = !A.can("operate") || me.kiosk;
    try { await load(); } catch (e) { $("#n-grid").innerHTML = `<div class="empty">관제 데이터를 불러오지 못했습니다: ${esc(e.message)}</div>`; }
    A.stream(onMsg, onState); loadBrief();
  });
})();
