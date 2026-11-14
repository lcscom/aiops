/* 내부 취약점 검증(2.43.0) — 보안·비용 › 보안 › 취약점 검증
   침해된 업무 VM 이 어디까지 갈 수 있나 — 약점(VMware 버전·하드닝·노출·망 분리·네트워크 장비·인증서·지원 종료·백업·KEV)과 공격 경로를 계속 다시 계산. 공격 도구 없음 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {d: null, h: [], sev: "", layer: "", q: "", busy: false, err: "", open: ""};
  const SK = {critical: ["치명", "crit"], high: ["높음", "high"], medium: ["중간", "med"], low: ["낮음", "low"]};
  const when = ts => ts ? new Date(ts * 1000).toLocaleString() : "—";

  async function load(run = 1) {
    try {
      const qs = new URLSearchParams({sev: st.sev, layer: st.layer, q: st.q, run});
      [st.d, st.h] = await Promise.all([A.api("GET", `/api/vuln?${qs}`, undefined, {background: true}), A.api("GET", "/api/vuln/history", undefined, {background: true}).then(x => x.runs)]);
      st.err = "";
    } catch (e) { st.err = String(e.message || e); }
    draw(); badge();
  }
  function badge() {
    const b = $("#vuln-badge"), s = (st.d || {}).summary; if (!b) return;
    const n = s ? (s.by_sev.critical || 0) + (s.by_sev.high || 0) : 0;
    b.hidden = !n; b.textContent = n || ""; b.title = n ? `치명·높음 약점 ${n}개` : "";
  }
  function spark(runs) {
    if (!runs || runs.length < 2) return "";
    const w = 160, h = 34, xs = runs.map((r, i) => i / (runs.length - 1) * w), ys = runs.map(r => h - 2 - (r.score / 100) * (h - 4));
    return `<svg class="vu-sp" viewBox="0 0 ${w} ${h}" aria-label="위험 점수 추이"><polyline fill="none" stroke="#c21d00" stroke-width="2" points="${xs.map((x, i) => `${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ")}"/></svg>`;
  }
  function head() {
    const s = st.d.summary;
    const lvl = s.score >= 70 ? ["crit", "위험"] : s.score >= 40 ? ["high", "주의"] : ["ok", "양호"];
    return `<div class="vu-top">
      <div class="vu-score ${lvl[0]}"><small>위험 점수</small><b>${s.score}</b><span>${lvl[1]}</span>${spark(st.h)}</div>
      <div class="vu-tiles">${Object.entries(SK).map(([k, [l, c]]) => `<button type="button" class="vu-t ${c} ${st.sev === k ? "on" : ""}" data-sev="${k}"><b>${s.by_sev[k] || 0}</b><span>${l}</span></button>`).join("")}
        <div class="vu-t path"><b>${s.paths_confirmed}<small>/${s.paths}</small></b><span>공격 경로(확인됨/전체)</span></div></div>
      <div class="vu-meta small muted">마지막 검증 ${when(s.ts)} · ${st.d.interval_h}시간마다 + 보안 판독이 새로 돌면 다시 · ${s.new ? `<b class="cb-new">새 약점 ${s.new}</b> · ` : ""}${s.fixed ? `<span class="cb-fixed">해소 ${s.fixed}</span> · ` : ""}
        ${s.assess ? "VMware 버전·하드닝: 보안 판독 결과 사용" : `<span class="es-bad">보안 판독 결과가 없어 VMware 버전 취약점·하드닝은 빠짐</span>`} · KEV ${s.kev ? `${s.kev}건` : "없음"} · 능동 확인 ${s.active ? "켬" : "꺼짐"}
        <div class="lf-acts">${A.can("operate") ? `<button class="btn-sm" id="vu-run" ${st.busy ? "disabled" : ""}>${st.busy ? "검증 중…" : "지금 검증"}</button>
          <label class="btn-sm vu-kev">KEV 가져오기<input type="file" accept=".json,application/json" id="vu-kev" hidden></label>` : ""}
          ${A.can("settings") ? `<label class="vu-act"><input type="checkbox" id="vu-active" ${st.d.active ? "checked" : ""}> 능동 확인(TCP 연결만)</label>` : ""}
          <a class="btn-sm" href="/api/vuln.csv" download>CSV</a></div></div></div>`;
  }
  function paths() {
    const P = st.d.paths || [];
    if (!P.length) return `<div class="vu-none">찾은 공격 경로가 없습니다 — 업무 VM 에서 관리망으로 닿는 근거와 ESXi·vCenter 약점이 함께 있는 곳이 없습니다.</div>`;
    return `<h4 class="vu-h">공격 경로 <small>침해된 업무 VM 에서 시작 — 위험 순 · 빨간 고리를 끊으면 경로가 막힘</small></h4><div class="vu-paths">${P.slice(0, 6).map(p => `
      <div class="vu-path ${p.reach === "확인됨" ? "conf" : "cond"}"><div class="vu-ph"><b>${esc(p.kind)} ${esc(p.target)}</b><span class="vu-reach">${esc(p.reach)}</span>${p.kev ? `<span class="vu-kev-b">악용 중(KEV)</span>` : ""}<small>위험 ${p.score}</small></div>
        <ol class="vu-steps">${p.steps.map((s, i) => `<li class="${(i === 1 && p.break.at === "망 분리") || (i === 2 && p.break.at !== "망 분리") ? "brk" : ""}"><i>${esc(s.t)}</i><span>${esc(s.x)}</span></li>`).join("")}</ol>
        <p class="vu-fix"><b>끊는 곳: ${esc(p.break.at)}</b> — ${esc(p.break.how)}</p></div>`).join("")}</div>`;
  }
  function list() {
    const F = st.d.findings || [], L = st.d.summary.by_layer || {};
    return `<h4 class="vu-h">약점 <small>${st.d.matched}개</small></h4>
      <div class="cb-types">${Object.entries(L).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<button type="button" class="cb-type ${st.layer === k ? "on" : ""}" data-layer="${esc(k)}">${esc(k)} <span>${n}</span></button>`).join("")}
        <input id="vu-q" value="${esc(st.q)}" placeholder="찾기(자산·약점)" aria-label="약점 찾기">${st.sev || st.layer || st.q ? `<button class="btn-sm" id="vu-clr">거르기 풀기</button>` : ""}</div>
      <div class="vu-list">${F.map(f => {
        const [l, c] = SK[f.sev]; const op = st.open === f.id;
        return `<div class="vu-row ${c} ${op ? "open" : ""}"><button type="button" class="vu-sum" data-open="${esc(f.id)}" aria-expanded="${op}"><span class="vu-sev ${c}">${l}</span><span class="vu-layer">${esc(f.layer)}</span>
          <span class="vu-ti">${esc(f.title)}</span><span class="vu-as mono">${esc(f.asset)}</span>${st.d.new && st.d.new.includes(f.id) ? `<span class="vu-newb">새로</span>` : ""}${(f.kev || []).length ? `<span class="vu-kev-b">KEV</span>` : ""}</button>
          ${op ? `<div class="vu-det"><p><b>근거</b> ${esc(f.evidence)}</p>${f.verified ? `<p><b>능동 확인</b> ${esc(f.verified)}</p>` : ""}<p><b>조치</b> ${esc(f.fix)}</p>
            <p class="small muted">출처: ${esc(f.source)}${(f.cves || []).length ? ` · ${esc(f.cves.join(", "))}` : ""}${f.vms ? ` · 같은 VLAN VM: ${esc(f.vms.slice(0, 12).join(", "))}${f.vms.length > 12 ? " …" : ""}` : ""}</p></div>` : ""}</div>`;
      }).join("") || `<div class="empty">해당하는 약점이 없습니다.</div>`}</div>
      ${(st.d.fixed || []).length ? `<details class="sm-det"><summary>지난 검증 뒤 해소 ${st.d.fixed.length}</summary><ul>${st.d.fixed.map(x => `<li class="small">${esc(x.asset)} — ${esc(x.title)}</li>`).join("")}</ul></details>` : ""}
      <p class="small muted">공격 도구·로그인 시도 없이 이미 수집한 구성·버전·결선으로 판단합니다. 방화벽·ACL 정책은 수집하지 않으므로 다른 VLAN 사이 도달은 '조건부'로 표시합니다. 능동 확인을 켜면 노출로 판단한 ESXi 서비스 포트에 TCP 연결만 해 실제로 열렸는지 확인합니다.</p>`;
  }
  function draw() {
    const b = $("#vuln-body"); if (!b) return;
    if (!st.d) { b.innerHTML = `<div class="empty">${st.err ? esc(st.err) : "검증하는 중…"}</div>`; return; }
    if (!st.d.summary) { b.innerHTML = `<div class="empty">아직 검증 기록이 없습니다.</div>`; return; }
    b.innerHTML = head() + paths() + list();
  }
  function wire() {
    const b = $("#vuln-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const t = e.target.closest("button"); if (!t) return;
      try {
        if (t.dataset.open) { st.open = st.open === t.dataset.open ? "" : t.dataset.open; draw(); return; }
        if (t.dataset.sev) { st.sev = st.sev === t.dataset.sev ? "" : t.dataset.sev; await load(0); return; }
        if (t.dataset.layer) { st.layer = st.layer === t.dataset.layer ? "" : t.dataset.layer; await load(0); return; }
        if (t.id === "vu-clr") { st.sev = st.layer = st.q = ""; await load(0); return; }
        if (t.id === "vu-run") { st.busy = true; draw(); try { await A.api("POST", "/api/vuln/run", {}); A.ok("취약점 검증", "다시 검증했습니다"); } finally { st.busy = false; await load(0); } }
      } catch (err) { A.fail("취약점 검증", err); }
    });
    b.addEventListener("change", async e => {
      try {
        if (e.target.id === "vu-active") { await A.api("PUT", "/api/vuln/settings", {active: e.target.checked}); A.ok("능동 확인", e.target.checked ? "다음 검증부터 TCP 연결로 확인합니다" : "껐습니다"); }
        if (e.target.id === "vu-kev" && e.target.files[0]) {
          const txt = await e.target.files[0].text();
          const r = await A.api("POST", "/api/vuln/kev", JSON.parse(txt));
          A.ok("KEV", `${r.imported}건을 가져왔습니다 — 다음 검증부터 반영`);
        }
      } catch (err) { A.fail("취약점 검증", err); }
    });
    b.addEventListener("input", e => {
      if (e.target.id !== "vu-q") return;
      st.q = e.target.value; clearTimeout(st._t);
      st._t = setTimeout(async () => { await load(0); const q = $("#vu-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 300);
    });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-vuln") d.hidden = true; });
    $("#drawer-vuln").hidden = false;
    wire(); draw(); await load(1);
  }
  const nav = document.getElementById("nav-vuln"); if (nav) nav.onclick = show;
  const rl = document.getElementById("vuln-reload"); if (rl) rl.onclick = () => load(0);
  window.AIOPS_VULN = show;
  if (A.ready) A.ready.then(me => { if (me === null) return; setTimeout(() => A.api("GET", "/api/vuln?run=0", undefined, {background: true}).then(d => { st.d = st.d || d; badge(); }).catch(() => {}), 6000); });
})();
