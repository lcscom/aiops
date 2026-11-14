/* AIOps 인사이트(2.45.0) — 관제 › 인시던트·SR › AIOps 인사이트
   탐지 다음 단계: ① 인시던트 근본 원인 추정(의존 그래프) + 직전 변경 ② 전조 패턴 학습·조기 경보 ③ 소음/유용 피드백 학습 ④ 소음 감소·MTTA·MTTR. 모두 분석만 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const st = {tab: "rca", kpi: null, incs: null, sel: "", rca: null, rcaBusy: false, aiBusy: false, pre: null, tri: null, err: ""};
  const T = ts => ts ? new Date(ts * 1000).toLocaleString("ko-KR", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "—";
  const KIND = {switch: "스위치", device: "방화벽·라우터", storage: "스토리지 장비", ds: "데이터스토어", host: "ESXi", vm: "VM", vks: "VKS 클러스터", cluster: "클러스터", vcenter: "vCenter"};
  const CAT = {agent: "에이전트", capacity: "용량", cluster: "클러스터", collection: "수집", config: "구성", dr: "DR", edge: "NSX Edge", hardware: "하드웨어", host: "호스트", kubernetes: "쿠버네티스",
    lb: "로드밸런서", network: "네트워크", operation: "작업", ops: "운영", os: "OS", performance: "성능", platform: "플랫폼", security: "보안", service: "서비스", storage: "스토리지",
    supervisor: "Supervisor", vm: "VM", general: "일반"};
  const SEV = {critical: "치명", error: "오류", warning: "경고", info: "정보"};
  const md = t => esc(t || "").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").split(/\n+/).map(l => l.trim()).filter(Boolean)
    .map(l => /^(\d+[.)]|[-*·])\s+/.test(l) ? `<li>${l.replace(/^(\d+[.)]|[-*·])\s+/, "")}</li>` : `<p>${l}</p>`).join("").replace(/(<li>.*?<\/li>)+/g, m => `<ul>${m}</ul>`);

  async function load() {
    try {
      const [k, i] = await Promise.all([A.api("GET", "/api/aiops/kpi", undefined, {background: true}), A.api("GET", "/api/aiops/incidents", undefined, {background: true})]);
      st.kpi = k; st.incs = i.items; st.err = "";
      if (!st.sel && st.incs.length) { const top = [...st.incs].sort((a, b) => (b.anomaly_count || 0) - (a.anomaly_count || 0))[0]; st.sel = top.id; }
    } catch (e) { st.err = String(e.message || e); }
    draw();
    if (st.tab === "rca" && st.sel && !st.rca) rca();
    if (st.tab === "pre" && !st.pre) pre();
    if (st.tab === "fb" && !st.tri) tri();
  }
  async function rca(ai = false) {
    if (!st.sel) return;
    ai ? st.aiBusy = true : st.rcaBusy = true; draw();
    try { st.rca = await A.api("GET", `/api/aiops/rca/${encodeURIComponent(st.sel)}${ai ? "?ai=1" : ""}`, undefined, {background: !ai}); } catch (e) { st.rca = {error: String(e.message || e)}; }
    st.rcaBusy = st.aiBusy = false; draw();
  }
  async function pre() { try { st.pre = await A.api("GET", "/api/aiops/precursors", undefined, {background: true}); } catch (e) { st.pre = {error: String(e.message || e), rules: []}; } draw(); }
  async function tri() { try { st.tri = (await A.api("GET", "/api/aiops/triage", undefined, {background: true})).items; } catch (e) { st.tri = []; st.err = String(e.message || e); } draw(); }

  function kpis() {
    const k = st.kpi; if (!k) return "";
    const c = (lbl, v, sub) => `<div class="ax-k"><small>${lbl}</small><b>${v}</b>${sub ? `<span>${sub}</span>` : ""}</div>`;
    return `<div class="ax-kpi">
      ${c("이벤트 → 이상징후", k.event_to_anomaly ? `${k.event_to_anomaly} : 1` : "—", `${k.events.toLocaleString()} → ${k.anomalies.toLocaleString()}`)}
      ${c("이상징후 → 인시던트", k.anomaly_to_incident ? `${k.anomaly_to_incident} : 1` : "—", `${k.anomalies.toLocaleString()} → ${k.incidents.toLocaleString()}`)}
      ${c("소음률(표시 기준)", k.noise_pct == null ? "—" : `${k.noise_pct}%`, `소음 ${k.feedback.noise || 0} · 유용 ${k.feedback.useful || 0}`)}
      ${c("MTTA · MTTR(중앙값)", `${k.mtta_min == null ? "—" : k.mtta_min + "분"} · ${k.mttr_min == null ? "—" : k.mttr_min + "분"}`, `최근 ${k.days}일`)}
      ${c("학습", `패턴 ${k.learned_patterns} · 전조 ${k.precursors}`, "피드백 가중치 · 전조 규칙")}
    </div>`;
  }
  function tabs() {
    const t = (k, l) => `<button class="ax-tab ${st.tab === k ? "on" : ""}" data-tab="${k}">${l}</button>`;
    return `<div class="ax-tabs">${t("rca", "원인 추정")}${t("pre", "전조·조기 경보")}${t("fb", "피드백 학습")}</div>`;
  }
  function rcaView() {
    const extra = st.sel && !(st.incs || []).some(i => i.id === st.sel) ? `<option value="${esc(st.sel)}" selected>${esc(st.sel)}</option>` : "";
    const opts = extra + (st.incs || []).map(i => `<option value="${esc(i.id)}" ${i.id === st.sel ? "selected" : ""}>${esc(i.id)} · ${esc(SEV[i.severity] || i.severity)} · ${esc((i.title || "").slice(0, 70))} (${i.anomaly_count || 0})</option>`).join("");
    const r = st.rca;
    let body = "";
    if (st.rcaBusy) body = `<div class="empty">분석 중…</div>`;
    else if (r && r.error) body = `<div class="empty">${esc(r.error)}</div>`;
    else if (r) {
      const top = r.roots[0];
      body = `<div class="ax-sum">증상 개체 <b>${r.symptoms}</b> · 이상징후 <b>${r.anomalies}</b>${r.unresolved.length ? ` · 구성도에 없는 개체 ${r.unresolved.length}(${r.unresolved.slice(0, 3).map(esc).join(", ")})` : ""}</div>
        ${r.weak ? `<div class="ax-warn">어느 후보도 증상의 절반을 설명하지 못합니다 — 하나의 원인이 아니라 같은 시간대에 겹친 <b>별개 문제</b>일 가능성이 큽니다. 인시던트를 나눠 보세요.</div>` : ""}
        ${r.roots.length ? `<div class="ax-roots">${r.roots.map((c, i) => `<div class="ax-root ${i === 0 ? "top" : ""}">
          <div class="ax-rk">${i + 1}</div><div class="ax-rm"><b>${esc(c.name)}</b> <span class="ax-kind">${esc(KIND[c.kind] || c.kind)}</span>
          <div class="ax-bar"><i style="width:${Math.max(4, Math.round(c.score * 100))}%"></i></div>
          <p class="small">증상 ${c.covers}/${c.symptoms} 설명${c.own_symptom ? " · 자체 이상징후" : ""}${c.earliest ? " · 가장 먼저" : ""}${c.changed ? " · <b>직전 변경 있음</b>" : ""}</p>
          ${c.paths.length ? `<p class="small muted">${c.paths.map(esc).join(" · ")}</p>` : ""}</div><div class="ax-sc">${Math.round(c.score * 100)}</div></div>`).join("")}</div>`
          : `<div class="empty">구성도와 이어지는 증상이 없어 원인 후보를 만들지 못했습니다.</div>`}
        ${A.can("view") && top ? `<button class="btn-sm" id="ax-ai" ${st.aiBusy ? "disabled" : ""}>${st.aiBusy ? "AI 가 쓰는 중…" : "AI 원인 설명"}</button>` : ""}
        ${r.ai ? `<div class="cb-ai ${r.ai.error ? "off" : ""}"><h5>AI 원인 설명 <small>위 후보·변경·타임라인만 근거(이름은 가명 처리해 전송)</small></h5>${r.ai.error ? `<p class="small muted">${esc(r.ai.error)}</p>` : `<div class="cb-md">${md(r.ai.text)}</div>`}</div>` : ""}
        <h5 class="vu-h">직전 변경 <small>시작 6시간 전부터 · 증상과 그래프로 이어진 것 먼저</small></h5>
        ${r.changes.length ? `<div class="ax-chg">${r.changes.slice(0, 12).map(c => `<div class="${c.related ? "rel" : ""}"><span class="ax-t">${c.minutes_before}분 전</span><span class="ax-kind">${esc(c.kind)}</span>
          <span>${esc(c.what)}${c.count > 1 ? ` <small class="muted">×${c.count}</small>` : ""}</span>${c.related ? `<b class="ax-rel">관련</b>` : ""}</div>`).join("")}</div>` : `<p class="small muted">창 안에 기록된 변경이 없습니다.</p>`}
        <h5 class="vu-h">타임라인</h5>
        <div class="ax-tl">${r.timeline.map(t => `<div><span class="ax-t">${T(t.ts)}</span><span class="sev-${esc(t.severity)}">${esc(SEV[t.severity] || t.severity)}</span><span>${esc(t.title)}</span></div>`).join("")}</div>`;
    }
    return `<div class="ax-sel"><select id="ax-inc">${opts || `<option>최근 인시던트 없음</option>`}</select></div>${body}
      <p class="small muted">점수 = 설명력 45% + 자체 이상징후 25% + 가장 먼저 15% + 직전 변경 15% − 범위가 너무 넓은 후보 벌점. 의존 그래프: 방화벽·라우터→스위치→ESXi→VM, 스토리지 장비→데이터스토어→VM, VM→VKS, vCenter→클러스터→호스트. 추정이니 확정 전 해당 개체를 확인하세요.</p>`;
  }
  function preView() {
    const p = st.pre; if (!p) return `<div class="empty">불러오는 중…</div>`;
    const s = p.state || {};
    return `<div class="ax-sum">최근 ${p.cfg ? p.cfg.precursor_days : 30}일 인시던트에서 학습 · 마지막 학습 ${s.learned ? T(s.learned) : "아직"}${s.incidents != null ? ` · 인시던트 ${s.incidents} · 이상징후 ${s.anomalies}` : ""}
        ${A.can("operate") ? ` <button class="btn-sm" id="ax-learn">지금 다시 학습</button>` : ""}</div>
      ${p.rules.length ? `<div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>전조 패턴</th><th>뒤따른 인시던트</th><th class="r">과거</th><th class="r">신뢰도</th><th class="r">평소 대비</th><th class="r">앞선 시간</th></tr></thead><tbody>
        ${p.rules.slice(0, 50).map(r => `<tr><td>${esc(r.title.slice(0, 110))}</td><td><span class="ax-kind">${esc(CAT[r.kind] || r.kind)}</span> <small class="muted">${esc((r.example || "").slice(0, 60))}</small></td>
          <td class="r">${r.support}번</td><td class="r">${Math.round(r.confidence * 100)}%</td><td class="r">${r.lift}배</td><td class="r">${r.lead_min ?? "—"}분</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="empty">아직 전조 규칙이 없습니다 — 인시던트가 쌓이면 6시간마다 다시 학습합니다.</div>`}
      <p class="small muted">기준: 같은 범위(클러스터·호스트)에서 인시던트 시작 2~60분 전에 나온 패턴 · 3번 이상(구성도에 없는 개체는 5번) · 신뢰도 30% 이상 · 평소보다 3배 이상. 5분마다 최근 이상징후에 전조가 보이면 '조기 경보' 이상징후(같은 전조·개체는 1시간에 1번)를 냅니다. 상관이지 인과가 아닙니다.</p>`;
  }
  function fbView() {
    const t = st.tri; if (!t) return `<div class="empty">불러오는 중…</div>`;
    const can = A.can("operate");
    return `<p class="small">최근 3일 이상징후(패턴별 1건). <b>소음</b>으로 표시하면 같은 패턴의 탐지 점수가 낮아지고(최저 ×0.2), <b>유용</b>은 조금 올라갑니다(최고 ×1.2). 원본 로그는 그대로 저장됩니다.</p>
      ${t.length ? `<div class="ax-fb">${t.map(a => `<div class="${a.verdict ? "done" : ""}"><div><span class="sev-${esc(a.severity)}">${esc(SEV[a.severity] || a.severity)}</span> <b>${esc(a.title.slice(0, 120))}</b>
        <p class="small muted">${esc(a.source)} · ${esc(a.entity)} · ${T(a.ts)} · 점수 ${a.score ?? "—"}${a.count > 1 ? ` · ${a.count}회` : ""}${a.weight !== 1 ? ` · 학습 ×${a.weight}` : ""}</p></div>
        <div class="ax-btns">${can ? `<button class="btn-sm ${a.verdict === "noise" ? "on" : ""}" data-fb="noise" data-id="${esc(a.id)}">소음</button><button class="btn-sm ${a.verdict === "useful" ? "on" : ""}" data-fb="useful" data-id="${esc(a.id)}">유용</button>${a.verdict ? `<button class="btn-sm" data-fb="clear" data-id="${esc(a.id)}">취소</button>` : ""}` : `<small class="muted">${a.verdict ? (a.verdict === "noise" ? "소음" : "유용") : ""}</small>`}</div></div>`).join("")}</div>`
        : `<div class="empty">최근 3일 이상징후가 없습니다.</div>`}`;
  }
  function draw() {
    const b = $("#aiops-body"); if (!b) return;
    if (!st.kpi) { b.innerHTML = `<div class="empty">${st.err ? esc(st.err) : "불러오는 중…"}</div>`; return; }
    b.innerHTML = kpis() + tabs() + `<div class="ax-pane">${st.tab === "rca" ? rcaView() : st.tab === "pre" ? preView() : fbView()}</div>`;
  }
  function wire() {
    const b = $("#aiops-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("change", e => { if (e.target.id === "ax-inc") { st.sel = e.target.value; st.rca = null; rca(); } });
    b.addEventListener("click", async e => {
      const t = e.target.closest("button"); if (!t) return;
      try {
        if (t.dataset.tab) { st.tab = t.dataset.tab; draw(); if (st.tab === "rca" && !st.rca) rca(); if (st.tab === "pre" && !st.pre) pre(); if (st.tab === "fb" && !st.tri) tri(); }
        if (t.id === "ax-ai") await rca(true);
        if (t.id === "ax-learn") { t.disabled = true; st.pre = await A.api("POST", "/api/aiops/precursors/learn"); st.pre.cfg = st.pre.cfg || {precursor_days: 30}; A.ok("AIOps", `전조 규칙 ${st.pre.rules.length}개`); draw(); }
        if (t.dataset.fb) {
          const r = await A.api("POST", "/api/aiops/feedback", {anomaly_id: t.dataset.id, verdict: t.dataset.fb});
          const a = (st.tri || []).find(x => x.id === t.dataset.id); if (a) { a.verdict = t.dataset.fb === "clear" ? null : t.dataset.fb; a.weight = r.weight; }
          (st.tri || []).forEach(x => { if (x.pkey === r.pkey) x.weight = r.weight; });
          draw(); A.api("GET", "/api/aiops/kpi", undefined, {background: true}).then(k => { st.kpi = k; draw(); }).catch(() => {});
        }
      } catch (err) { A.fail("AIOps", err); }
    });
  }
  async function show(incId) {
    if (typeof incId === "string" && incId) { st.sel = incId; st.rca = null; st.tab = "rca"; }
    document.querySelectorAll(".drawer").forEach(d => { if (d.id !== "drawer-aiops") d.hidden = true; });
    $("#drawer-aiops").hidden = false;
    wire(); draw(); await load();
  }
  const nav = document.getElementById("nav-aiops"); if (nav) nav.onclick = () => show();
  const rl = document.getElementById("aiops-reload"); if (rl) rl.onclick = () => { st.rca = null; st.pre = null; st.tri = null; load(); };
  window.AIOPS_AIOPSX = show;
})();
