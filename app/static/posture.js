/* 보안 상태 점검(2.22.0) — 인증·토큰·외부 공개(Cloudflare Access)·웹 머리글·서버 파일을 주기 점검, 점수·추이·새로 나빠진 항목 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const EN = ((window.AIOPS_I18N || {}).lang || "ko") === "en";       // 짧은 라벨은 사전 치환 대신 직접(다른 화면 문구 오염 방지)
  const ST = EN ? {pass: "Pass", warn: "Warning", fail: "Fail", na: "N/A"} : {pass: "통과", warn: "경고", fail: "실패", na: "해당 없음"};
  const SEV = EN ? {critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info"} : {critical: "위험", high: "높음", medium: "보통", low: "낮음", info: "정보"};
  const CATL = EN ? {auth: "Authentication & accounts", token: "API tokens", ext: "External exposure", web: "Web security headers", server: "Server & files"} : {};
  const every = h => EN ? `every ${h} h` : `${h}시간마다`;
  const SEV_CLS = {critical: "critical", high: "error", medium: "warning", low: "info", info: "info"};
  const SRANK = {critical: 4, high: 3, medium: 2, low: 1, info: 0};
  const STRANK = {fail: 3, warn: 2, na: 1, pass: 0};
  const st = {d: null, cat: "", show: "bad", q: "", busy: false, seq: 0};
  const dt = ts => ts ? new Date(ts * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";

  async function load(run = false) {
    const my = ++st.seq;
    st.busy = true; render();
    let d = null;
    try { d = await A.api(run ? "POST" : "GET", run ? "/api/posture/run" : "/api/posture"); }
    catch (e) { if (my === st.seq) { st.busy = false; A.fail(run ? "보안 점검을 실행하지 못했습니다" : "보안 점검 결과를 불러오지 못했습니다", e); render(); } return; }
    if (my !== st.seq) return;
    st.d = d; st.busy = false;
    if (run) A.toast && A.toast(`보안 점검 완료 — ${d.score}점(${d.grade})`);
    render();
  }

  function trend(h) {
    if (!h || h.length < 2) return `<p class="muted small">점검 이력이 2회 이상 쌓이면 추이를 보여 줍니다.</p>`;
    const W = 520, H = 90, P = 28, n = h.length, X = i => P + i * (W - P - 6) / (n - 1), Y = v => H - 14 - v / 100 * (H - 22);
    const pts = h.map((x, i) => `${X(i).toFixed(1)},${Y(x.score).toFixed(1)}`).join(" ");
    const g = [0, 50, 100].map(v => `<line class="st-grid" x1="${P}" x2="${W}" y1="${Y(v)}" y2="${Y(v)}"/><text class="st-ax" x="${P - 4}" y="${Y(v) + 4}" text-anchor="end">${v}</text>`).join("");
    const dots = h.map((x, i) => `<circle cx="${X(i).toFixed(1)}" cy="${Y(x.score).toFixed(1)}" r="2.5" class="sp-dot ${x.fail ? "bad" : x.warn ? "warn" : "ok"}"><title>${esc(dt(x.ts))} · ${x.score}점 · 실패 ${x.fail} · 경고 ${x.warn}</title></circle>`).join("");
    return `<svg class="st-chart sp-trend" viewBox="0 0 ${W} ${H}" role="img" aria-label="보안 점수 추이">${g}<polyline class="st-rx" points="${pts}"/>${dots}
      <text class="st-ax" x="${P}" y="${H - 1}">${esc(dt(h[0].ts))}</text><text class="st-ax" x="${W}" y="${H - 1}" text-anchor="end">${esc(dt(h[n - 1].ts))}</text></svg>`;
  }

  function render() {
    const box = $("#sp-body"); if (!box) return;
    const d = st.d;
    if (!d) { box.innerHTML = `<div class="empty">${st.busy ? "점검 결과를 읽는 중…" : "결과 없음"}</div>`; return; }
    const items = d.items || [], cats = d.cats || [];
    const byCat = Object.fromEntries(cats.map(([k]) => [k, items.filter(i => i.cat === k)]));
    const sc = d.score, cls = sc >= 90 ? "ok" : sc >= 75 ? "" : "bad";
    const next = d.ts ? d.ts + (d.interval_hours || 6) * 3600 : 0;
    const delta = d.prev_score == null ? "" : sc - d.prev_score;
    const newItems = (d.new || []).map(id => items.find(i => i.id === id)).filter(Boolean);
    box.innerHTML = `
      <div class="kpis sp-kpis">
        <div class="kpi"><span>보안 점수</span><b class="${cls}">${sc}<small class="sp-grade"> ${esc(d.grade)}</small></b>${delta !== "" && delta !== 0 ? `<small class="sp-delta ${delta > 0 ? "up" : "down"}">${delta > 0 ? "▲" : "▼"} ${Math.abs(delta)} (직전 대비)</small>` : ""}</div>
        <div class="kpi"><span>실패</span><b class="${d.counts.fail ? "bad" : "ok"}">${d.counts.fail}</b></div>
        <div class="kpi"><span>경고</span><b>${d.counts.warn}</b></div>
        <div class="kpi"><span>통과</span><b class="ok">${d.counts.pass}</b></div>
        <div class="kpi"><span>마지막 점검</span><b class="sp-small">${esc(dt(d.ts))}</b><small class="muted">${esc(d.trigger === "manual" ? "수동 점검" : d.trigger === "schedule" ? "예약 점검" : "자동 점검")} · ${d.ms}ms</small></div>
        <div class="kpi"><span>다음 예약 점검</span><b class="sp-small">${esc(dt(next))}</b><small class="muted">${esc(every(d.interval_hours))}</small></div>
      </div>
      ${newItems.length ? `<div class="sp-alert bad" role="alert"><b>직전 점검 이후 새로 나빠진 항목 ${newItems.length}개</b> — ${newItems.map(i => esc(i.title)).join(" · ")}</div>` : ""}
      ${(d.fixed || []).length ? `<div class="sp-alert ok"><b>해결된 항목 ${d.fixed.length}개</b> — ${d.fixed.map(f => esc(f.title)).join(" · ")}</div>` : ""}
      <div class="vc-cards">${cats.map(([k, label]) => {
        const xs = byCat[k] || [], f = xs.filter(i => i.status === "fail").length, w = xs.filter(i => i.status === "warn").length;
        const worst = f ? (xs.some(i => i.status === "fail" && SRANK[i.sev] >= 3) ? "critical" : "error") : w ? "warning" : "ok";
        return `<button class="vc-card ${worst}${st.cat === k ? " on" : ""}" data-cat="${esc(k)}" aria-pressed="${st.cat === k}"><b>${esc(CATL[k] || label)}</b>
          <span class="vc-n">${f + w}</span><small>${f ? `실패 ${f}` : ""}${f && w ? " · " : ""}${w ? `경고 ${w}` : ""}${!f && !w ? `이상 없음 · ${xs.filter(i => i.status === "pass").length}개 통과` : ""}</small></button>`;
      }).join("")}</div>
      <div class="vc-ctl">
        <select id="sp-show" aria-label="표시 범위"><option value="bad"${st.show === "bad" ? " selected" : ""}>실패·경고만</option><option value="all"${st.show === "all" ? " selected" : ""}>전체 항목</option></select>
        <input id="sp-q" type="search" placeholder="항목·근거·조치 검색" value="${esc(st.q)}" aria-label="검색">
        ${st.cat ? `<button class="btn-sm" id="sp-allcat">모든 분류</button>` : ""}
        <a class="btn-sm" href="/api/posture.csv" download>CSV</a>
      </div>
      <div id="sp-rows">${rowsHtml(filtered(d), d)}</div>
      ${tail(d)}`;
  }
  function rowsHtml(rows, d) {
    return `${rows.length ? `<table class="vc-t sp-t"><thead><tr><th>상태</th><th>중요도</th><th>항목</th><th>근거</th><th>조치</th></tr></thead><tbody>
        ${rows.map(i => `<tr class="sp-${i.status}"><td><span class="sp-st ${esc(i.status)}">${esc(ST[i.status] || i.status)}</span>${(d.new || []).includes(i.id) ? ` <span class="sp-new">신규</span>` : ""}</td>
          <td><span class="vc-sev ${SEV_CLS[i.sev] || "info"}">${esc(SEV[i.sev] || i.sev)}</span></td>
          <td><b>${esc(i.title)}</b><div class="muted small vc-ent">${esc(i.id)}</div></td>
          <td class="small">${esc(i.evidence || "")}</td>
          <td class="small">${i.fix ? `<div class="vc-fix">${esc(i.fix)}</div>` : ""}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">${st.show === "bad" ? "실패·경고 항목이 없습니다." : "항목이 없습니다."}</div>`}`;
  }
  function filtered(d) {
    let rows = (d.items || []).filter(i => (!st.cat || i.cat === st.cat) && (st.show === "all" || i.status === "fail" || i.status === "warn"));
    const q = st.q.trim().toLowerCase();
    if (q) rows = rows.filter(i => `${i.id} ${i.title} ${i.evidence} ${i.fix}`.toLowerCase().includes(q));
    return rows.sort((a, b) => STRANK[b.status] - STRANK[a.status] || SRANK[b.sev] - SRANK[a.sev]);
  }
  function tail(d) {
    const ca = d.cf_access || {}, ex = d.external || {};
    return `
      <div class="sp-grid">
        <section><h4>점수 추이(30일)</h4>${trend(d.history)}</section>
        <section><h4>외부 공개 · Cloudflare Access</h4>
          ${(ex.hosts || []).length ? `<dl class="sp-dl">
            <dt>외부 이름</dt><dd>${(ex.hosts || []).map(esc).join(", ")}</dd>
            <dt>Access 원본 검증</dt><dd>${ca.enabled ? `${ca.enforce ? "차단(enforce)" : "검증만"} · ${esc(ca.team_domain)}` : `<span class="sp-st fail">미설정</span>`}</dd>
            <dt>요청(시작 후)</dt><dd>${(ex.requests || 0).toLocaleString()}건 · 경로 차단 ${(ex.blocked_path || 0).toLocaleString()} · Access 거부 ${(ex.access_denied || 0).toLocaleString()}</dd>
            ${ca.enabled ? `<dt>토큰 검증</dt><dd>통과 ${(ca.ok || 0).toLocaleString()} · 없음 ${(ca.missing || 0).toLocaleString()} · 무효 ${(ca.invalid || 0).toLocaleString()}${ca.last_error ? ` — <span class="muted">${esc(ca.last_error)}</span>` : ""}</dd>` : ""}
          </dl>` : `<p class="muted small">외부 공개 안 함(server.external_hosts 없음). 외부 공개는 <code>sudo vcf-aiopsctl tunnel --api-token --access-allow @회사도메인 --waf-ratelimit</code>.</p>`}
        </section>
      </div>
      <p class="muted small">새로 나빠진 항목(${esc(SEV[d.alert_min_severity] || d.alert_min_severity)} 이상)은 플랫폼 이벤트(보안 점검)로 올라가 알림 경로를 탑니다. 점검은 읽기만 하며 설정을 바꾸지 않습니다.</p>`;
  }

  let wired = false;
  function wire() {
    if (wired) return; wired = true;
    const box = $("#sp-body");
    box.addEventListener("click", e => {
      const c = e.target.closest("[data-cat]"); if (c) { st.cat = st.cat === c.dataset.cat ? "" : c.dataset.cat; render(); return; }
      if (e.target.id === "sp-allcat") { st.cat = ""; render(); }
    });
    box.addEventListener("change", e => { if (e.target.id === "sp-show") { st.show = e.target.value; render(); } });
    const rowsOnly = () => { const r = $("#sp-rows"); if (r && st.d) r.innerHTML = rowsHtml(filtered(st.d), st.d); };   // 검색창은 그대로(한글 조합·포커스 유지)
    box.addEventListener("input", e => {
      if (e.target.id !== "sp-q" || e.isComposing) return;
      st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(rowsOnly, 200);
    });
    box.addEventListener("compositionend", e => { if (e.target.id === "sp-q") { st.q = e.target.value; rowsOnly(); } });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-sp") d.hidden = true; });
    $("#drawer-sp").hidden = false; wire();
    await load();
  }
  const nav = document.getElementById("nav-sp"); if (nav) nav.onclick = () => show();
  const rl = document.getElementById("sp-reload"); if (rl) rl.onclick = () => load();
  const run = document.getElementById("sp-run"); if (run) run.onclick = async () => { run.disabled = true; try { await load(true); } finally { run.disabled = false; } };
  window.AIOPS_POSTURE = show;
})();
