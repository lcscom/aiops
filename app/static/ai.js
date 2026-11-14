/* AI 분석 — 머리글 토글(켜기/끄기), 상태·조절기·패턴 화면, 운영 설정 › AI 분석(공급자·라우팅·발열/호출 조절·패턴·대기열) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const ai = {d: null, q: "", st: "", items: [], cat: null, timer: null, on: null};
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.max(0, Math.round(s))}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };
  const n = v => (v || 0).toLocaleString();
  const PST = {new: "신규", queued: "분석 대기", analyzed: "분석됨", error: "분석 실패"};

  // ---------------------------------------------------------------- 머리글 토글
  function paint(on, avail = true) {
    const t = $("#ai-toggle"); if (!t) return;
    ai.on = on;
    t.classList.toggle("on", !!on); t.setAttribute("aria-checked", on ? "true" : "false");
    t.disabled = !A.can("operate") || !avail;
    t.title = !avail ? "LLM 공급자가 설정되지 않음 — 운영 설정 › AI 분석" : on ? "AI 분석 켜짐 — 누르면 끔(규칙 탐지만, GPU 사용 0)" : "AI 분석 꺼짐 — 누르면 켬";
  }
  async function toggle(e) {
    e.stopPropagation();
    const next = !ai.on;
    if (!next && !await A.confirm("AI 분석 끄기", "새 이상징후를 LLM 으로 분석하지 않고 규칙 탐지 결과로만 처리합니다. 대기 중인 분석도 규칙 탐지로 바로 게시됩니다. AI 질의·수동 재분석·RCA 는 계속 쓸 수 있습니다.")) return;
    try { const r = await A.api("POST", "/api/ai/toggle", {on: next}); paint(r.on, true); A.ok(r.on ? "AI 분석 켬" : "AI 분석 끔", r.flushed ? `대기 ${r.flushed}건을 규칙 탐지로 게시` : ""); if (!$("#drawer-ai").hidden) load(); }
    catch (err) { A.fail("전환 실패", err); }
  }

  // ---------------------------------------------------------------- 상태·패턴 화면
  async function load() {
    try {
      const [d, p] = await Promise.all([A.api("GET", "/api/ai", undefined, {background: true}),
        A.api("GET", `/api/ai/patterns?q=${encodeURIComponent(ai.q)}&state=${ai.st}&limit=400`, undefined, {background: true})]);
      ai.d = d; ai.items = p.items;
    } catch (e) { $("#ai-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }
  const card = (l, v, s, c = "") => `<div class="sec-kpi ${c}"><small>${l}</small><b>${v}</b><span>${s}</span></div>`;
  function render() {
    const d = ai.d, s = d.state, q = d.queue, g = d.governor, ps = d.patterns;
    paint(s.on, s.available);
    $("#ai-sub").textContent = `— ${s.on ? "켜짐" : "꺼짐(규칙 탐지만)"} · ${s.provider ? `${s.provider} / ${s.model}` : "공급자 없음"}`;
    const calls = Object.entries(g.calls_last_hour || {}).map(([k, v]) => `${k} ${v}`).join(" · ") || "0";
    const lim = g.config.max_calls_per_hour ? `/ ${g.config.max_calls_per_hour}` : "(무제한)";
    const gpu = g.gpu || {}, vl = g.vllm || {};
    $("#ai-body").innerHTML = `
      <div class="ai-hero ${s.on ? "on" : "off"}"><button type="button" class="ai-tgl big ${s.on ? "on" : ""}" data-tgl ${A.can("operate") && s.available ? "" : "disabled"}><i></i></button>
        <div><b>${s.on ? "AI 분석 켜짐" : "AI 분석 꺼짐"}</b><span>${s.on ? "새 로그 패턴만 LLM 으로 분석하고, 이미 분석한 패턴은 저장된 결과를 재사용합니다." : "모든 이상징후를 규칙 탐지로 처리합니다(LLM 호출 0). AI 질의·수동 재분석은 사용 가능."}</span></div>
        ${g.hot ? `<span class="mon-st ALERT">GPU 과열 보호 중 ${esc(String(gpu.temp_max ?? ""))}°C</span>` : g.waiting ? `<span class="mon-st WARN">${esc(g.waiting)}</span>` : ""}</div>
      <div class="sec-kpis">
        ${card("분석 대기", n(q.depth), q.rate_per_min ? `분당 ${q.rate_per_min} · 예상 ${q.eta_min ?? "-"}분` : "처리율 측정 중", q.unique > 100 ? "warn" : "")}
        ${card("로그 패턴", n(ps.patterns), `분석됨 ${n(ps.analyzed)} · 제외 ${n(ps.excluded)}`)}
        ${card("분석 재사용", n(ps.reused_total), `LLM 호출 없이 처리 · 기간 ${ps.ttl_hours}시간`, "")}
        ${card("최근 1시간 호출", calls, `상한 ${lim} · 간격 ${g.config.min_interval}초`)}
        ${card("GPU 온도", gpu.temp_max != null ? `${gpu.temp_max}°C` : "-", g.config.gpu_metrics_url ? `중지 ${g.config.temp_pause}° / 재개 ${g.config.temp_resume}°${gpu.util_max != null ? ` · 사용률 ${gpu.util_max}%` : ""}${gpu.error ? " · 수집 오류" : ""}` : "DCGM 주소 미설정", g.hot ? "bad" : (gpu.temp_max || 0) >= g.config.temp_pause - 5 ? "warn" : "")}
        ${card("LLM 서버 대기", vl.waiting != null ? n(vl.waiting) : "-", g.config.vllm_metrics_url ? `실행 ${n(vl.running)} · 상한 ${g.config.vllm_waiting_max}` : "vLLM /metrics 미설정")}
      </div>
      <section class="sec-sec"><h4>공급자 <small class="muted">작업별 라우팅 — 실패 시 ${d.routing ? "다음 공급자로 자동 전환" : ""}</small></h4>
        ${Object.keys(d.providers || {}).length ? `<div class="tbl-x"><table class="vc-t"><thead><tr><th>이름</th><th>유형</th><th>모델</th><th>상태</th><th>지연</th><th>호출</th><th>실패</th><th>토큰</th><th>담당 작업</th><th>오류</th></tr></thead><tbody>
          ${Object.values(d.providers).map(p => `<tr><td><b>${esc(p.name)}</b>${p.external ? ' <span class="label">외부·가명화</span>' : ' <span class="label">사내</span>'}${p.forced_external ? ' <span class="label warn" title="\'사내\'로 저장했지만 주소가 사설 IP·내부 도메인이 아니어서 외부로 보고 가명화합니다(2.36.0). 사내 도메인이면 llm.internal_suffixes 에 추가하세요.">사내로 저장됨 → 주소가 사내가 아니어서 가명화</span>' : ""}${!p.external && p.host_internal === false ? ' <span class="label warn" title="\'사내\'로 설정했지만 주소가 사설 IP·내부 도메인이 아닙니다. 이 공급자에는 IP·호스트명이 가명화 없이 전송됩니다 — 인터넷 서비스라면 \'외부\'로 바꾸고, 사내 도메인이면 llm.internal_suffixes 에 추가하세요.">주소가 사내가 아님 — 가명화 안 됨</span>' : ""}</td><td>${esc(p.type)}</td><td class="mono small">${esc(p.model)}</td>
            <td><span class="st ${esc(p.state)}">${esc(p.state)}</span></td><td>${p.latency_ms != null ? p.latency_ms + "ms" : "-"}</td><td>${n(p.calls)}</td><td>${n(p.failures)}</td><td>${n(p.tokens)}</td>
            <td class="small">${Object.entries(d.routing || {}).filter(([, v]) => v === p.name).map(([k]) => esc(TL(k))).join(", ") || "-"}</td><td class="small bad">${esc(p.last_error || "")}</td></tr>`).join("")}</tbody></table></div>`
          : `<p class="muted small">LLM 공급자가 없습니다. 운영 설정 › AI 분석에서 사내 PAIS/vLLM, Claude API, Gemini API 를 추가하세요.</p>`}</section>
      <section class="sec-sec"><h4>로그 패턴 <small class="muted">같은 패턴은 한 번만 LLM 분석 — 이후 발생은 결과 재사용(분석 당시보다 심각하면 다시 분석)</small></h4>
        <div class="mon-bar"><div class="inv-chips">${[["", "전체"], ["analyzed", "분석됨"], ["queued", "대기"], ["new", "신규"], ["error", "실패"], ["excluded", "제외"]].map(([k, l]) => `<button data-pst="${k}" class="${ai.st === k ? "on" : ""}">${l}</button>`).join("")}</div>
          <input id="ai-q" placeholder="패턴·샘플·소스 검색" value="${esc(ai.q)}"></div>
        ${ai.items.length ? `<div class="tbl-x"><table class="vc-t ai-pt"><thead><tr><th>상태</th><th>소스</th><th>패턴 / AI 요약</th><th>발생</th><th>재사용</th><th>최대 심각도</th><th>최근</th><th>분석</th><th></th></tr></thead><tbody>
          ${ai.items.map(r => `<tr class="${r.excluded ? "off" : ""}"><td><span class="mon-st ${r.state === "analyzed" ? "OK" : r.state === "error" ? "ALERT" : r.state === "queued" ? "PENDING" : "NO_DATA"}">${r.excluded ? "제외" : PST[r.state] || esc(r.state)}</span></td>
            <td>${esc(r.source)}</td><td><code class="ai-tpl" title="${esc(r.sample)}">${esc(r.template)}</code>${r.title || r.summary ? `<div class="small">${r.is_anomaly === false ? '<span class="label">정상/정보성</span> ' : ""}<b>${esc(r.title)}</b> ${esc(r.summary)}</div>` : ""}</td>
            <td>${n(r.count)}</td><td>${n(r.reused)}</td><td><span class="sev ${esc(r.sev_max)}">${esc(r.sev_max)}</span></td><td class="small">${ago(r.last)}</td>
            <td class="small">${r.analyzed_at ? `${ago(r.analyzed_at)}<br><span class="muted">${esc(r.provider)}</span>` : "-"}</td>
            <td class="nowrap">${A.can("operate") ? `<button class="btn-sm" data-pa="reanalyze" data-k="${esc(r.key)}">다시 분석</button> <button class="btn-sm" data-pa="exclude" data-on="${r.excluded ? 0 : 1}" data-k="${esc(r.key)}">${r.excluded ? "제외 해제" : "분석 제외"}</button>` : ""}</td></tr>`).join("")}</tbody></table></div>`
          : `<p class="muted small">${ai.q || ai.st ? "조건에 맞는 패턴이 없습니다." : "아직 분석 대상 패턴이 없습니다."}</p>`}</section>`;
  }
  const TL = k => ((ai.cat || {}).task_labels || {})[k] || k;

  // ---------------------------------------------------------------- 운영 설정 › AI 분석
  const INTERNAL = t => t === "openai" || t === "pais_agent";                  // 사내 공급자(가명화 없음)
  const ROW = (p, i, cat) => `<tr data-i="${i}"><td><input data-p="name" value="${esc(p.name || "")}" placeholder="pais"></td>
    <td><select data-p="type">${Object.entries(cat.types).map(([k, l]) => `<option value="${k}" ${p.type === k ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></td>
    <td class="w2"><input data-p="base_url" value="${esc(p.base_url || "")}" placeholder="${esc(cat.default_url[p.type || "openai"])}"></td>
    <td><input data-p="model" value="${esc(p.model || "")}" placeholder="${esc(cat.default_model[p.type || "openai"])}"></td>
    <td><input data-p="api_key" type="password" autocomplete="new-password" value="${esc(p.api_key || "")}" placeholder="${p.type === "openai" ? "없으면 비움" : p.type === "pais_agent" ? "PAIS 인증 토큰" : "필수"}"></td>
    <td><button type="button" class="switch ${p.enabled !== false ? "on" : ""}" data-p="enabled"></button></td>
    <td><button type="button" class="switch ${(p.external ?? !INTERNAL(p.type)) ? "on" : ""}" data-p="external" title="외부(인터넷) 공급자 — IP·호스트명 가명화, GPU 조절 미적용"></button></td>
    <td class="nowrap"><button type="button" class="btn-sm" data-ptest="${i}">시험</button> <button type="button" class="x" data-pdel="${i}">✕</button></td></tr>`;
  async function renderSettings(box) {
    ai.cat = ai.cat || await A.api("GET", "/api/ai/catalog");
    const cat = ai.cat, d = await A.api("GET", "/api/settings/llm"), v = d.value || {};
    let provs = (v.providers || []).slice();
    if (!provs.length && v.base_url) provs = [{name: "local", type: "openai", base_url: v.base_url, model: v.model, api_key: v.api_key || "", external: false}];
    const g = {...cat.governor, ...(v.governor || {})}, r = v.routing || {};
    const num = (p, l, val, h = "", step = "1") => `<label class="frow"><span class="fl">${l}</span><input type="number" step="${step}" data-n="${p}" value="${esc(val ?? "")}">${h ? `<small class="fh">${h}</small>` : ""}</label>`;
    const sw = (p, l, val, h = "") => `<label class="frow"><span class="fl">${l}</span><button type="button" class="switch ${val ? "on" : ""}" data-b="${p}"></button>${h ? `<small class="fh">${h}</small>` : ""}</label>`;
    const txt = (p, l, val, h = "") => `<label class="frow"><span class="fl">${l}</span><input data-s="${p}" value="${esc(val ?? "")}">${h ? `<small class="fh">${h}</small>` : ""}</label>`;
    box.innerHTML = `<form class="sform" id="ai-form"><div class="sform-head"><h5>AI 분석</h5><small>${d.managed ? `화면 설정 적용 중 · ${esc(d.updated_by || "")}` : "config.yaml 값 사용 중"} · 저장 즉시 적용(재기동 불필요)</small>
        <span class="gap"></span><button type="button" class="btn-sm" data-json="llm">JSON 편집</button>${d.managed ? `<button type="button" class="btn-sm" data-reset="llm">config.yaml 값으로 복원</button>` : ""}<button class="btn-sm solid">저장·적용</button></div>
      <div class="fgrid">${sw("enabled", "LLM 사용", v.enabled, "끄면 AI 질의·RCA 도 비활성")}${sw("analysis_enabled", "자동 AI 분석(머리글 토글과 같음)", v.analysis_enabled !== false)}
        ${sw("fallback", "실패 시 다음 공급자로 자동 전환", v.fallback !== false)}${sw("external_mask", "외부 공급자 전송 시 IP·호스트명 가명화", v.external_mask !== false, "응답에서 원래 이름으로 복원 — 망분리·개인정보 보호")}</div>
      <div class="fsec">공급자</div>
      <div class="rows"><table class="ai-prov"><thead><tr><th>이름</th><th>유형</th><th>주소(base URL)</th><th>모델</th><th>API 키</th><th>사용</th><th>외부</th><th></th></tr></thead>
        <tbody id="ai-prov">${provs.map((p, i) => ROW(p, i, cat)).join("")}</tbody></table>
        <button type="button" class="btn-sm" data-padd="openai">+ 사내 PAIS/vLLM</button> <button type="button" class="btn-sm" data-padd="pais_agent" title="PAIS Agent Builder 에서 만든 에이전트 — 'base_url_for_agents' 주소를 그대로 붙여 넣기">+ PAIS 에이전트</button> <button type="button" class="btn-sm" data-padd="anthropic">+ Claude API</button> <button type="button" class="btn-sm" data-padd="gemini">+ Gemini API</button>
        <p class="small muted">Claude: x-api-key · anthropic-version 2023-06-01 · 예) claude-haiku-5-5(대량·저지연), claude-sonnet-5-5 · Gemini: x-goog-api-key · 예) gemini-3.5-flash-lite, gemini-3.8-flash · 외부 API 는 어플라이언스에서 인터넷(HTTPS 443) 연결이 필요합니다.</p></div>
      <div class="fsec">작업별 공급자</div>
      <div class="fgrid">${cat.tasks.map(t => `<label class="frow"><span class="fl">${esc(cat.task_labels[t] || t)}</span><select data-route="${t}"><option value="">(기본: 첫 번째)</option>${provs.map(p => `<option ${r[t] === p.name ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>`).join("")}</div>
      <div class="fsec">GPU 발열·호출량 조절 <small class="muted">자동 분석에만 적용 — AI 질의·수동 재분석은 즉시(과열 중지만 따름)</small></div>
      <div class="fgrid">${num("governor.min_interval", "호출 간 최소 간격(초)", g.min_interval, "GPU 쉬는 시간", "0.5")}${num("governor.max_calls_per_hour", "공급자당 시간당 최대 호출(0=무제한)", g.max_calls_per_hour)}
        ${txt("governor.gpu_metrics_url", "GPU 지표 주소(DCGM exporter /metrics)", g.gpu_metrics_url, "예) http://gpu-node:9400/metrics — DCGM_FI_DEV_GPU_TEMP")}
        ${num("governor.temp_pause", "중지 온도(°C)", g.temp_pause)}${num("governor.temp_resume", "재개 온도(°C)", g.temp_resume)}${num("governor.util_pause", "중지 GPU 사용률(%, 0=안 씀)", g.util_pause)}
        ${txt("governor.vllm_metrics_url", "vLLM 지표 주소(/metrics)", g.vllm_metrics_url, "예) http://pais:8000/metrics — vllm:num_requests_waiting")}${num("governor.vllm_waiting_max", "LLM 서버 대기 요청 상한", g.vllm_waiting_max)}</div>
      <div class="fsec">패턴 재사용·대기열</div>
      <div class="fgrid">${sw("pattern_reuse", "같은 로그 패턴 분석 재사용", v.pattern_reuse !== false)}${num("pattern_ttl_hours", "재사용 기간(시간)", v.pattern_ttl_hours ?? 168)}
        ${num("batch_size", "배치 크기", v.batch_size ?? 6)}${num("batch_max", "대기 많을 때 최대 배치", v.batch_max ?? 12)}${num("queue_shed_at", "부하 차단 시작(대기 건수)", v.queue_shed_at ?? 500)}
        ${num("queue_source_quota", "소스당 대기 상한", v.queue_source_quota ?? 300)}${num("queue_max_age", "warning 이하 최대 대기(초)", v.queue_max_age ?? 900)}${num("timeout", "호출 시간 제한(초)", v.timeout ?? 120)}</div></form>`;
    ai.form = {base: v, provs};
  }
  function collect(box) {
    const f = $("#ai-form", box), base = JSON.parse(JSON.stringify(ai.form.base || {}));
    const orig = Object.fromEntries((ai.form.provs || []).map(p => [p.name, p]));      // 화면에 없는 필드(tasks·verify_tls·system_mode·extra_body)는 유지
    const provs = $$("#ai-prov tr", f).map(tr => { const o = {}; tr.querySelectorAll("[data-p]").forEach(el => { o[el.dataset.p] = el.classList.contains("switch") ? el.classList.contains("on") : el.value.trim(); });
      const prev = orig[o.name]; return prev && prev.type === o.type ? {...prev, ...o} : o; })
      .filter(p => p.name);
    provs.forEach(p => { if (!p.base_url) delete p.base_url; if (!p.model) delete p.model; });
    base.providers = provs;
    if (provs.length) { base.base_url = ""; }               // 기존 단일 설정 대신 공급자 목록 사용
    base.routing = {}; $$("[data-route]", f).forEach(s => { if (s.value) base.routing[s.dataset.route] = s.value; });
    $$("[data-b]", f).forEach(b => { base[b.dataset.b] = b.classList.contains("on"); });
    $$("[data-n]", f).forEach(i => { if (i.value === "") return; const ks = i.dataset.n.split("."); if (ks.length === 2) { base[ks[0]] = base[ks[0]] || {}; base[ks[0]][ks[1]] = Number(i.value); } else base[ks[0]] = Number(i.value); });
    $$("[data-s]", f).forEach(i => { const ks = i.dataset.s.split("."); base[ks[0]] = base[ks[0]] || {}; base[ks[0]][ks[1]] = i.value.trim(); });
    return base;
  }
  function wireSettings(box) {
    box.addEventListener("click", async e => {
      if (!$("#ai-form", box)) return;
      const sw = e.target.closest("#ai-form .switch"); if (sw) { sw.classList.toggle("on"); return; }
      const add = e.target.closest("[data-padd]");
      if (add) { const t = add.dataset.padd, tb = $("#ai-prov", box), i = tb.children.length;
        tb.insertAdjacentHTML("beforeend", ROW({name: {openai: "pais", pais_agent: "pais-agent", anthropic: "claude", gemini: "gemini"}[t] + (i ? `-${i + 1}` : ""), type: t, model: ai.cat.default_model[t], external: !INTERNAL(t)}, i, ai.cat)); return; }
      const del = e.target.closest("[data-pdel]"); if (del) { del.closest("tr").remove(); return; }
      const ts = e.target.closest("[data-ptest]");
      if (ts) { const name = ts.closest("tr").querySelector("[data-p=name]").value.trim(); ts.disabled = true;
        const r = await A.api("POST", "/api/ai/providers/test", {name, value: collect(box)}).catch(err => ({ok: false, error: err.message}));
        ts.disabled = false;
        r.ok ? A.ok(`${name} 연결 정상`, `${r.model} · ${r.latency_ms}ms · 응답 "${r.reply}"${r.warning ? " · " + r.warning : ""}`) : A.fail(`${name} 연결 실패`, r.error || ""); }
    });
    box.addEventListener("change", e => { const t = e.target.closest("[data-p=type]"); if (!t) return;
      const tr = t.closest("tr"); tr.querySelector("[data-p=base_url]").placeholder = ai.cat.default_url[t.value]; tr.querySelector("[data-p=model]").placeholder = ai.cat.default_model[t.value];
      tr.querySelector("[data-p=external]").classList.toggle("on", !INTERNAL(t.value)); });
    box.addEventListener("submit", async e => {
      if (e.target.id !== "ai-form") return;
      e.preventDefault(); e.stopImmediatePropagation();
      try { const r = await A.api("PUT", "/api/settings/llm", {value: collect(box)}); A.ok("AI 분석 설정 저장·적용", (r.applied && r.applied.providers || []).join(", ")); renderSettings(box); }
      catch (err) { A.fail("저장 실패", err); }
    }, true);
  }
  window.AIOPS_AI_SETTINGS = async box => { if (!box.dataset.aiWired) { wireSettings(box); box.dataset.aiWired = "1"; } await renderSettings(box); };

  // ---------------------------------------------------------------- 연결
  document.addEventListener("DOMContentLoaded", () => {
    const t = $("#ai-toggle"); if (!t) return;
    t.addEventListener("click", toggle);
    $("#k-llm").addEventListener("click", e => { if (e.target.closest("#ai-toggle")) return; openDrawer(); });
    $("#ai-body").addEventListener("click", async e => {
      if (e.target.closest("[data-tgl]")) return toggle(e);
      const c = e.target.closest("[data-pst]"); if (c) { ai.st = c.dataset.pst; load(); return; }
      const b = e.target.closest("[data-pa]"); if (!b) return;
      try {
        await A.api("POST", `/api/ai/patterns/${b.dataset.k}/${b.dataset.pa}`, b.dataset.pa === "exclude" ? {on: b.dataset.on === "1"} : {});
        A.ok({reanalyze: "다시 분석 요청", exclude: b.dataset.on === "1" ? "분석 제외" : "제외 해제"}[b.dataset.pa]); load();
      } catch (err) { A.fail("실패", err); }
    });
    let qt; $("#ai-body").addEventListener("input", e => { if (e.target.id !== "ai-q") return; clearTimeout(qt); qt = setTimeout(() => { ai.q = e.target.value; load().then(() => { const i = $("#ai-q"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 350); });
    $("#ai-reload").onclick = load;
    $("#ai-settings").onclick = () => { $("#drawer-ai").hidden = true; if (window.AIOPS_OPEN_SETTINGS) window.AIOPS_OPEN_SETTINGS("ai"); };
    window.addEventListener("aiops:ai", e => { const s = e.detail || {}; if (s.on !== undefined) paint(s.on, s.available !== false); });
    window.addEventListener("aiops:ws", e => { const m = e.detail; if (m && m.type === "ai_state") paint(m.data.on, m.data.available); });
    A.ready.then(me => { if (me === null) return; A.api("GET", "/api/ai/catalog", undefined, {background: true}).then(c => { ai.cat = c; }).catch(() => {}); });
  });
  function openDrawer() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-ai") d.hidden = true; });
    $("#drawer-ai").hidden = false; load();
    clearInterval(ai.timer); ai.timer = setInterval(() => $("#drawer-ai").hidden ? clearInterval(ai.timer) : (document.activeElement && document.activeElement.id === "ai-q") ? null : load(), 15000);
  }
  window.AIOPS_OPEN_AI = openDrawer;
})();
