/* 비용 절감 찾기(2.44.0) — 보안·비용 › 비용·라이선스 › 비용 절감
   흩어진 근거(VM 적정화·꺼진 VM·스냅숏·외장 스토리지→ESA·라이선스)를 돈이 되는 순서로. 금액은 입력한 단가로만 계산(가격을 지어내지 않음). AI 한 장 요약 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {d: null, err: "", ai: null, aiBusy: false, edit: false};
  const M = (v, cur) => v == null ? "—" : `${Math.round(v).toLocaleString()} ${esc(cur || "원")}`;

  async function load() {
    try { st.d = await A.api("GET", "/api/savings", undefined, {background: true}); st.err = ""; } catch (e) { st.err = String(e.message || e); }
    draw();
  }
  function prices() {
    const d = st.d, P = d.prices, L = d.labels;
    const need = Object.entries(d.priced).filter(([, v]) => !v).map(([k]) => L[k]);
    const f = k => `<label><span>${esc(L[k])}</span><input data-p="${k}" value="${esc(P[k] ?? "")}" ${k === "currency" ? "" : 'inputmode="decimal"'} placeholder="${k === "currency" ? "원" : "비움"}"></label>`;
    return `<details class="sv-prices" ${st.edit ? "open" : ""}><summary>단가 ${need.length ? `<small class="es-bad">입력하지 않은 단가 ${need.length}개 — 그 항목은 수량만 표시</small>` : `<small class="es-ok">모두 입력됨</small>`}</summary>
      <div class="sv-grid">${Object.keys(L).map(f).join("")}</div>
      ${A.can("operate") ? `<button class="btn-sm" id="sv-save">단가 저장</button>` : `<p class="small muted">단가 저장은 운영 권한이 필요합니다.</p>`}
      <p class="small muted">계약 단가는 고객사마다 달라 기본값을 두지 않습니다. 호스트 소비전력·PUE 만 일반값(600 W·1.5)을 넣어 두었습니다.</p></details>`;
  }
  function draw() {
    const b = $("#save-body"); if (!b) return;
    if (!st.d) { b.innerHTML = `<div class="empty">${st.err ? esc(st.err) : "계산 중…"}</div>`; return; }
    const d = st.d, cur = d.currency;
    b.innerHTML = `<div class="sv-hero"><div><small>연간 절감 가능(입력한 단가 기준)</small><b>${d.total_year == null ? "단가를 넣으면 계산" : M(d.total_year, cur)}</b>
        <span>VCF 필요 코어 ${d.total_cores.toLocaleString()} · 클러스터 ${d.clusters.length}</span></div>
        <div class="sv-acts">${A.can("view") ? `<button class="btn-sm" id="sv-ai" ${st.aiBusy ? "disabled" : ""}>${st.aiBusy ? "AI 가 쓰는 중…" : "AI 한 장 요약"}</button>` : ""}<a class="btn-sm" href="/api/savings.csv" download>CSV</a></div></div>
      ${st.ai ? `<div class="cb-ai ${st.ai.error ? "off" : ""}"><h5>AI 요약 <small>갱신 협상·경영진 보고용</small></h5>${st.ai.error ? `<p class="small muted">${esc(st.ai.error)} — 아래 표가 같은 근거입니다.</p>` : `<div class="cb-md">${md(st.ai.text)}</div>`}</div>` : ""}
      ${prices()}
      <div class="sv-list">${d.ops.map((o, i) => `<div class="sv-op ${o.amount > 0 ? "has" : ""}"><div class="sv-rank">${i + 1}</div>
        <div class="sv-main"><b>${esc(o.title)}</b><p class="sv-qty">${esc(o.qty)}</p><p class="small"><i>근거</i> ${esc(o.why)}</p><p class="small"><i>방법</i> ${esc(o.how)}</p>
          ${o.breakdown.length ? `<p class="small muted">${o.breakdown.map(esc).join(" · ")}</p>` : ""}</div>
        <div class="sv-amt"><b>${M(o.amount, cur)}</b><small>/년</small><span class="sv-tag">위험 ${esc(o.risk)}</span><span class="sv-tag">노력 ${esc(o.effort)}</span></div></div>`).join("")}</div>
      <h5 class="vu-h">클러스터별 호스트 여유 <small>p95 사용량(표본 14일, 없으면 현재값) − 적정화 회수 메모리 → 80% 목표 + N+1(vSAN 최소 3대)</small></h5>
      <div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>클러스터</th><th class="r">지금</th><th class="r">필요</th><th class="r">줄일 수 있음</th><th class="r">CPU</th><th class="r">메모리</th><th class="r">회수 메모리</th><th>기준</th></tr></thead><tbody>
      ${d.clusters.map(c => `<tr><td><b>${esc(c.cluster)}</b> <small class="muted">${esc(c.vcenter)}${c.vsan ? " · vSAN" : ""}</small></td><td class="r">${c.hosts}대</td><td class="r">${c.needed}대</td>
        <td class="r ${c.removable ? "es-ok" : ""}"><b>${c.removable}대</b></td><td class="r">${c.cpu_pct_now ?? "—"}%</td><td class="r">${c.mem_pct_now ?? "—"}%</td><td class="r">${c.mem_back_gb} GB</td><td class="small">${esc(c.basis)}</td></tr>`).join("")}
      </tbody></table></div>
      <p class="small muted">추정입니다 — 호스트를 실제로 빼기 전에 가정 분석·What-If 시나리오로 장애 여유를 확인하세요. VCF 코어 = 호스트별 max(16, 코어/CPU) × CPU 수.</p>`;
  }
  const md = t => esc(t || "").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").split(/\n+/).map(l => l.trim()).filter(Boolean)
    .map(l => /^(\d+[.)]|[-*·])\s+/.test(l) ? `<li>${l.replace(/^(\d+[.)]|[-*·])\s+/, "")}</li>` : `<p>${l}</p>`).join("").replace(/(<li>.*?<\/li>)+/g, m => `<ul>${m}</ul>`);
  function wire() {
    const b = $("#save-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const t = e.target.closest("button"); if (!t) return;
      try {
        if (t.id === "sv-save") {
          const body = {}; $$("[data-p]", b).forEach(i => { body[i.dataset.p] = i.value.trim(); });
          await A.api("PUT", "/api/savings/prices", body); st.edit = true; A.ok("비용 절감", "단가를 저장했습니다"); await load();
        }
        if (t.id === "sv-ai") { st.aiBusy = true; draw(); try { const d = await A.api("GET", "/api/savings?ai=1"); st.d = d; st.ai = d.ai; } finally { st.aiBusy = false; draw(); } }
      } catch (err) { A.fail("비용 절감", err); }
    });
    b.addEventListener("toggle", e => { if (e.target.classList && e.target.classList.contains("sv-prices")) st.edit = e.target.open; }, true);
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-save") d.hidden = true; });
    $("#drawer-save").hidden = false;
    wire(); draw(); await load();
  }
  const nav = document.getElementById("nav-save"); if (nav) nav.onclick = show;
  const rl = document.getElementById("save-reload"); if (rl) rl.onclick = load;
  window.AIOPS_SAVE = show;
})();
