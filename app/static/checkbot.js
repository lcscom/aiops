/* AI 체크봇(2.38.0) — AI·지식 › AI 체크봇
   장애·작업 what-if 시나리오(호스트 장애·롤링 유지보수·클러스터 장애·데이터스토어 APD/가득 참·업링크·vCenter 업그레이드·Edge·인증서·복합)를
   인벤토리 전체에 대해 대량으로 만들고 계속 검증 — 시나리오마다 영향받는 VM·호스트·관리 서비스·VKS 파드 목록과 판단 근거·할 일 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {d: null, h: null, type: "", verdict: "fail,warn", q: "", open: "", det: {}, err: "", busy: false};
  const V = {fail: ["실패", "bad"], warn: ["주의", "warn"], pass: ["통과", "ok"]};
  const N = v => v == null ? "—" : Number(v).toLocaleString();
  const when = ts => ts ? new Date(ts * 1000).toLocaleString() : "—";
  const md = t => esc(t || "").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").split(/\n+/).map(l => l.trim()).filter(Boolean)
    .map(l => /^(\d+[.)]|[-*·])\s+/.test(l) ? `<li>${l.replace(/^(\d+[.)]|[-*·])\s+/, "")}</li>` : `<p>${l}</p>`).join("").replace(/(<li>.*?<\/li>)+/g, m => `<ul>${m}</ul>`);
  const ORIGIN = {rule: "규칙", ai: "AI 제안"};

  function head() {
    const d = st.d, s = (d || {}).summary;
    if (!s) return `<div class="empty">${st.busy ? "시나리오를 만들고 검증하는 중…" : "아직 실행 기록이 없습니다."}</div>`;
    const bv = s.by_verdict || {};
    const tile = (v, n) => `<button type="button" class="lf-tile ${V[v][1]} ${st.verdict === v ? "on" : ""}" data-cbv="${v}"><b>${N(n)}</b><span>${V[v][0]}</span></button>`;
    const types = Object.entries(s.by_type || {}).sort((a, b) => b[1].fail - a[1].fail || b[1].n - a[1].n);
    const hist = Object.entries(s.history || {}).filter(([, n]) => n).sort((a, b) => b[1] - a[1]);
    return `<div class="lf-tiles"><div class="lf-tile cb-total"><b>${N(s.scenarios)}</b><span>시나리오</span></div>${["fail", "warn", "pass"].map(v => tile(v, bv[v] || 0)).join("")}
      <div class="lf-meta small muted">마지막 실행 ${when(s.ts)} (${esc(s.by === "schedule" ? "자동" : s.by || "")}) · ${d.interval_h}시간마다 자동 · vCenter ${s.vcenters}개
        ${s.new_fail ? ` · <b class="cb-new">새 실패 ${s.new_fail}</b>` : ""}${s.fixed ? ` · <span class="cb-fixed">해소 ${s.fixed}</span>` : ""}
        <div class="lf-acts">${A.can("operate") ? `<button class="btn-sm" id="cb-run" ${st.busy || (d.state || {}).running ? "disabled" : ""}>${st.busy ? "검증 중…" : "지금 다시 검증"}</button>` : ""}
          <a class="btn-sm" href="/api/checkbot.csv" download>전체 CSV</a></div></div></div>
      <div class="cb-types">${types.map(([k, x]) => `<button type="button" class="cb-type ${st.type === k ? "on" : ""} ${x.fail ? "bad" : ""}" data-cbt="${k}" title="${esc(((d.types || {})[k] || {}).desc || "")}">
        ${esc(((d.types || {})[k] || {}).name || k)} <b>${x.fail}</b>/<span>${x.n}</span></button>`).join("")}</div>
      ${ai(d)}
      ${hist.length ? `<p class="small muted cb-hist">이 환경에서 최근 30일 실제로 본 문제(이상징후) — ${hist.map(([k, n]) => `${esc(((d.types || {})[k] || {}).name || k)} ${n}건`).join(" · ")} → 같은 유형 시나리오의 우선순위를 올렸습니다.</p>` : ""}`;
  }
  function ai(d) {
    const a = d.ai || {}, s = d.summary || {};
    if (a.summary) return `<div class="cb-ai"><h5>AI 판독 <small>${s.ai_scenarios ? `AI 가 제안한 복합 시나리오 ${s.ai_scenarios}개를 함께 검증` : ""}</small></h5><div class="cb-md">${md(a.summary)}</div></div>`;
    return `<div class="cb-ai off"><h5>AI 판독</h5><p class="small muted">${a.error ? `AI 를 쓰지 못했습니다(${esc(a.error)}) — ` : "AI 공급자가 설정되지 않았습니다 — "}규칙으로 만든 시나리오와 규칙 기반 복합 시나리오만 검증했습니다.
      AI 를 연결하면(운영 설정 › AI) 인벤토리를 보고 복합 장애 시나리오를 더 제안하고 결과를 요약합니다. 외부 AI 에는 이름을 가명으로 바꿔 보냅니다.</p></div>`;
  }

  function list() {
    const d = st.d; if (!d || !d.summary) return "";
    const rs = d.results || [];
    return `<div class="lf-filter"><input id="cb-q" value="${esc(st.q)}" placeholder="찾기(호스트·데이터스토어·클러스터·VM 이름)">
        ${st.type || st.verdict ? `<button class="btn-sm" id="cb-clear">거르기 풀기</button>` : ""}<span class="small muted">${N(d.matched)}개${d.matched > rs.length ? ` 중 ${rs.length}개 표시` : ""} · 위험 점수 순</span></div>
      <div class="cb-list">${rs.map(row).join("") || `<div class="empty">해당하는 시나리오가 없습니다.</div>`}</div>
      <p class="small muted">읽기 전용 — 아무것도 끄거나 바꾸지 않고, 지금 수집된 인벤토리·인프라 점검 스냅숏·용량 추세·VKS·NSX·SRM 정보로 '그 일이 일어나면'을 계산합니다.
        위험 점수 = 판정 × 발생 가능성(유형 기본값 + 이 환경 이력) × 영향 규모(켜진 VM·관리 서비스·VKS 파드). 새로 실패가 된 시나리오는 이상징후로 알립니다.</p>`;
  }
  function row(r) {
    const op = st.open === r.id, v = V[r.verdict];
    const im = r.impact || {};
    return `<div class="cb-row cb-${r.verdict} ${op ? "open" : ""}"><button type="button" class="cb-sum" data-cbo="${esc(r.id)}" aria-expanded="${op}">
        <span class="dr-v ${v[1]}">${v[0]}</span><span class="cb-kind">${esc(r.kind)}${r.origin && r.origin !== "rule" ? ` <i class="cb-o">${ORIGIN[r.origin] || esc(r.origin)}</i>` : ""}</span>
        <span class="cb-tg mono">${esc(r.target)}${r.cluster && r.cluster !== r.target ? `<small class="muted"> · ${esc(r.cluster)}</small>` : ""}${r.vcenter ? `<small class="muted"> · ${esc(r.vcenter)}</small>` : ""}</span>
        <span class="cb-im small">${im.vms_on ? `VM <b>${im.vms_on}</b>` : ""}${im.services ? ` · 서비스 <b>${im.services}</b>` : ""}${im.pods ? ` · 파드 <b>${im.pods}</b>` : ""}${im.hosts ? ` · 호스트 ${im.hosts}` : ""}</span>
        <span class="cb-sc small muted" title="위험 점수">${r.score}</span>
        <span class="cb-top small">${(r.top || []).map(esc).join("<br>")}</span></button>
      ${op ? `<div class="cb-det">${detail(st.det[r.id])}</div>` : ""}</div>`;
  }
  function detail(x) {
    if (!x) return `<div class="small muted">불러오는 중…</div>`;
    if (x.err) return `<div class="small muted">${esc(x.err)}</div>`;
    const F = x.findings || [];
    const vms = x.vms || [], sv = x.services || [], k = (x.vks || {}).clusters || [];
    return `${x.why ? `<p class="small"><b>왜 이 시나리오:</b> ${esc(x.why)}</p>` : ""}
      ${(x.steps || []).length ? `<p class="small muted">단계: ${x.steps.map(s => `${esc(((st.d.types || {})[s.type] || {}).name || s.type)}(${esc(s.target)})`).join(" → ")}</p>` : ""}
      <ul class="cb-f">${F.map(f => `<li><span class="dr-v ${V[f.sev][1]}">${V[f.sev][0]}</span> ${esc(f.text)}</li>`).join("")}</ul>
      ${x.capacity ? `<p class="small muted">용량(가정 분석 엔진): 남는 호스트 ${x.capacity.hosts_left ?? "—"}대 · CPU ${x.capacity.cpu_pct ?? "—"}% · 메모리 ${x.capacity.mem_pct ?? "—"}%${x.capacity.limit ? ` · 한계 ${esc(x.capacity.limit)}` : ""}</p>` : ""}
      ${(x.actions || []).length ? `<div class="cb-act"><h5>할 일</h5><ol>${x.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ol></div>` : ""}
      <div class="cb-res">
        ${sv.length ? `<div><h5>관리·서비스 ${sv.length}</h5><table class="dr-t"><tbody>${sv.map(s => `<tr><td>${esc(s.kind)}</td><td class="mono small">${esc(s.name)}</td><td class="small muted">${esc(s.impact)}</td></tr>`).join("")}</tbody></table></div>` : ""}
        ${k.length ? `<div><h5>VKS</h5>${k.map(c => `<div class="small"><b>${esc(c.cluster)}</b> — 노드 ${c.nodes.length}/${c.nodes_total}${c.control_plane_lost.length ? ` (컨트롤 플레인 ${c.control_plane_lost.length}/${c.control_plane_total})` : ""} · 파드 ${c.pods}
          <details><summary>파드·네임스페이스</summary><div class="mono small cb-pods">${c.pod_list.map(esc).join("<br>")}</div></details></div>`).join("")}</div>` : ""}
        ${(x.hosts || []).length ? `<div><h5>호스트 ${x.hosts.length}</h5><div class="mono small">${x.hosts.map(esc).join(", ")}</div></div>` : ""}
      </div>
      ${vms.length ? `<h5>영향받는 VM ${vms.length}</h5><div style="overflow-x:auto"><table class="dr-t cb-vms"><thead><tr><th>VM</th><th>전원</th><th>호스트 · 클러스터</th><th class="r">vCPU</th><th class="r">메모리</th><th>영향 · 사유</th></tr></thead><tbody>
        ${vms.slice(0, 500).map(v => `<tr><td class="mono small">${esc(v.name)}</td><td>${v.power === "on" ? "켜짐" : "꺼짐"}</td><td class="small">${esc(v.host)}<div class="muted">${esc(v.cluster)}</div></td>
          <td class="r">${v.vcpu}</td><td class="r nw">${v.mem_gb} GB</td><td class="small">${esc(v.reason)}</td></tr>`).join("")}</tbody></table></div>${vms.length > 500 ? `<p class="small muted">처음 500대만 — 전체는 CSV</p>` : ""}` : ""}
      <div class="lf-acts"><a class="btn-sm" href="/api/checkbot.csv?id=${encodeURIComponent(x.id)}" download>영향 리소스 CSV</a>
        ${simFails(x).length ? `<button type="button" class="btn-sm" data-cbsim="${esc(x.id)}">시뮬레이터에서 열기</button>` : ""}</div>`;
  }

  const SIMT = new Set(["host_down", "host_maint", "uplink_loss", "cluster_down", "ds_apd", "ds_full", "vcenter_upgrade", "edge_down"]);
  function simFails(x) {
    if (!x) return [];
    if (x.type === "maint_plus_fail") return (x.hosts || []).map((h, i) => ({type: i ? "host_maint" : "host_down", vcenter: x.vcenter, target: h}));
    if (x.type === "compound") return (x.steps || []).filter(s => SIMT.has(s.type)).map(s => ({type: s.type, vcenter: s.vcenter || "", target: s.target}));
    return SIMT.has(x.type) ? [{type: x.type, vcenter: x.vcenter || "", target: x.type === "host_maint" ? x.cluster || x.target : x.target}] : [];
  }
  function mode(m, fails, scn) {
    st.mode = m;
    $$("[data-cbmode]").forEach(b => { b.classList.toggle("on", b.dataset.cbmode === m); b.setAttribute("aria-selected", b.dataset.cbmode === m); });
    $("#cb-body").hidden = m !== "list"; $("#sm-body").hidden = m !== "sim"; $("#lib-body").hidden = m !== "lib";
    if (m === "sim" && window.AIOPS_SIM) window.AIOPS_SIM.show($("#sm-body"), fails, scn);
    if (m === "lib" && window.AIOPS_SCNLIB) window.AIOPS_SCNLIB.show($("#lib-body"));
  }
  window.AIOPS_CB_MODE = mode;
  function draw() {
    const b = $("#cb-body"); if (!b) return;
    b.innerHTML = st.err ? `<div class="empty">${esc(st.err)}</div>` : head() + list();
  }
  async function load() {
    st.err = "";
    try {
      st.d = await A.api("GET", `/api/checkbot?type=${encodeURIComponent(st.type)}&verdict=${encodeURIComponent(st.verdict)}&q=${encodeURIComponent(st.q)}&limit=400`, undefined, {background: true});
    } catch (e) { st.err = String(e.message || e); }
    draw(); badge();
  }
  function badge() {
    const b = $("#cb-badge"), s = (st.d || {}).summary; if (!b || !s) return;
    const n = (s.by_verdict || {}).fail || 0;
    b.hidden = !n; b.textContent = n || "";
    b.title = n ? `검증에 실패한 시나리오 ${n}개` : "";
  }
  async function openRow(id) {
    st.open = st.open === id ? "" : id; draw();
    if (!st.open || st.det[id]) return;
    try { st.det[id] = await A.api("GET", `/api/checkbot/scenario?id=${encodeURIComponent(id)}`, undefined, {background: true}); }
    catch (e) { st.det[id] = {err: String(e.message || e)}; }
    draw();
  }
  function wire() {
    const b = $("#cb-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const t = e.target.closest("button"); if (!t) return;
      try {
        if (t.dataset.cbo !== undefined) { await openRow(t.dataset.cbo); return; }
        if (t.dataset.cbsim) { mode("sim", simFails(st.det[t.dataset.cbsim])); return; }
        if (t.dataset.cbv) { st.verdict = st.verdict === t.dataset.cbv ? "" : t.dataset.cbv; await load(); return; }
        if (t.dataset.cbt) { st.type = st.type === t.dataset.cbt ? "" : t.dataset.cbt; await load(); return; }
        if (t.id === "cb-clear") { st.type = ""; st.verdict = ""; await load(); return; }
        if (t.id === "cb-run") {
          st.busy = true; draw();
          try { const o = await A.api("POST", "/api/checkbot/run", {}); st.det = {}; A.ok("검증 완료", `시나리오 ${o.summary.scenarios}개 — 실패 ${o.summary.by_verdict.fail} · 주의 ${o.summary.by_verdict.warn}`); }
          finally { st.busy = false; await load(); }
        }
      } catch (err) { A.fail("AI 체크봇", err); }
    });
    b.addEventListener("input", e => {
      if (e.target.id !== "cb-q") return;
      st.q = e.target.value; clearTimeout(st._t);
      st._t = setTimeout(async () => { await load(); const q = $("#cb-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 300);
    });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-bot") d.hidden = true; });
    $("#drawer-bot").hidden = false;
    wire(); if (!st.d) { st.busy = true; draw(); } await load(); st.busy = false; draw();
  }
  const nav = document.getElementById("nav-bot"); if (nav) nav.onclick = show;
  const rl = document.getElementById("cb-reload"); if (rl) rl.onclick = () => { if (st.mode === "sim" && window.AIOPS_SIM) { window.AIOPS_SIM.reload(); return; }
    if (st.mode === "lib" && window.AIOPS_SCNLIB) { window.AIOPS_SCNLIB.reload(); return; } st.det = {}; load(); };
  $$("[data-cbmode]").forEach(b => { b.onclick = () => mode(b.dataset.cbmode); });
  window.AIOPS_CHECKBOT = show;
  if (A.ready) A.ready.then(me => { if (me === null) return; setTimeout(() => A.api("GET", "/api/checkbot?run=0&limit=1", undefined, {background: true}).then(d => { if (d && d.summary) { st.d = st.d || null; const s = d.summary; const b = $("#cb-badge"); if (b) { const n = (s.by_verdict || {}).fail || 0; b.hidden = !n; b.textContent = n || ""; } } }).catch(() => {}), 5000); });
})();
