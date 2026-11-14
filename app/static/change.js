/* AI 변경 사전 검토(2.44.0) — 인프라·워크로드 › 점검·진단 › 변경 사전 검토
   작업 계획을 한국어로 적으면 대상·작업 해석 → 영향(장애 시뮬레이터) → 사전 점검 → 권장 시간대 → 작업 절차서(마크다운). 계산만 — 실제 작업은 하지 않음 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {text: "", r: null, busy: false, err: "", ai: true, fails: null};
  try { st.text = localStorage.getItem("aiops.chg.text") || ""; } catch (e) { /* 무시 */ }
  const WD = "월화수목금토일";
  const EX = ["11/20 새벽 2시 esx05 BIOS 업데이트 후 재부팅, esx06 도 순차 진행", "다음주 토요일 밤 10시 dc1-leaf-01 NX-OS 업그레이드", "esx02 메모리 교체로 전원 차단"];

  async function review(overrides) {
    if (!st.text.trim()) return;
    st.busy = true; st.err = ""; draw();
    try { localStorage.setItem("aiops.chg.text", st.text); } catch (e) { /* 무시 */ }
    try { st.r = await A.api("POST", "/api/change/review", {text: st.text, ai: st.ai, ...(overrides ? {failures: overrides} : {})}); st.fails = null; }
    catch (e) { st.err = String(e.message || e); }
    st.busy = false; draw();
  }
  const SC = {ok: ["통과", "ok"], warn: ["주의", "warn"], fail: ["실패", "bad"]};
  const md = t => esc(t || "").replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").split(/\n+/).map(l => l.trim()).filter(Boolean)
    .map(l => /^(\d+[.)]|[-*·])\s+/.test(l) ? `<li>${l.replace(/^(\d+[.)]|[-*·])\s+/, "")}</li>` : `<p>${l}</p>`).join("").replace(/(<li>.*?<\/li>)+/g, m => `<ul>${m}</ul>`);
  function fmt(iso) { const d = new Date(iso); return `${d.getMonth() + 1}/${d.getDate()}(${WD[(d.getDay() + 6) % 7]}) ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`; }
  function result() {
    const r = st.r; if (!r) return "";
    const I = r.impact;
    const tile = (n, l, c) => `<div class="sm-tile b-${c} ${n ? "" : "zero"}"><b>${n}</b><span>${l}</span></div>`;
    return `<div class="ch-verdict ${r.verdict.key}"><b>${esc(r.verdict.label)}</b>
        <span>${r.failures.length ? r.failures.map(f => `<span class="ch-f">${esc(f.label)}${f.src === "AI" ? " <i>AI</i>" : ""}<button type="button" data-rmf="${esc(f.type + "|" + f.target)}" aria-label="빼기">✕</button></span>`).join("") : ""}
        ${r.mode === "sequential" ? `<small>한 대씩 순차 — 가장 나쁜 경우로 계산</small>` : ""}</span></div>
      ${r.hint ? `<p class="es-bad small">${esc(r.hint)}</p>` : ""}
      <div class="sm-tiles">${tile(I.stop, "서비스 중단", "stop")}${tile(I.risk, "위험", "risk")}${tile(I.boot, "재부팅", "boot")}${tile(I.move, "무중단 이동", "move")}</div>
      <div class="ch-grid">
        <section><h5>사전 점검</h5><ul class="ch-chk">${r.checks.map(c => `<li class="${SC[c.state][1]}"><span class="dr-v ${SC[c.state][1]}">${SC[c.state][0]}</span><b>${esc(c.name)}</b> <span class="small">${esc(c.detail)}</span></li>`).join("")}</ul></section>
        <section><h5>작업 시간</h5>${r.when ? `<p>예정 <b>${fmt(r.when.iso)}</b>${r.when.load != null ? ` — 그 시각 평균 부하 <b>${r.when.load}%</b>` : ""}</p>` : `<p class="small muted">계획에 날짜·시각이 없습니다(예: 11/20 02시).</p>`}
          ${r.window.best.length ? `<p class="small">부하가 가장 낮은 3시간(최근 ${r.window.days}일 같은 요일·시각 평균):</p><ol class="ch-win">${r.window.best.map(b => `<li><b>${fmt(b.start)}</b> 평균 ${b.avg_pct}% · 최대 ${b.max_pct}%</li>`).join("")}</ol>` : `<p class="small muted">사용률 표본이 쌓이면(최소 하루) 권장 시간대를 계산합니다.</p>`}</section>
      </div>
      ${I.top.length ? `<h5 class="vu-h">영향 근거</h5><ul class="sm-why">${I.top.map(x => `<li class="s-${x.sev === "실패" ? "fail" : "warn"}">${esc(x.text)}</li>`).join("")}</ul>` : ""}
      ${r.ai ? `<div class="cb-ai"><h5>AI 검토</h5><div class="cb-md">${md(r.ai)}</div></div>` : r.ai_error ? `<p class="small muted">${esc(r.ai_error)}</p>` : ""}
      <h5 class="vu-h">작업 절차서 <small>변경 티켓에 붙여 넣기</small></h5>
      <div class="ch-mop">${Object.entries(r.mop).map(([k, v]) => v.length ? `<section><b>${esc(k)}</b><ul>${v.map(x => `<li><input type="checkbox" aria-label="${esc(x)}"> ${esc(x)}</li>`).join("")}</ul></section>` : "").join("")}</div>
      <div class="lf-acts"><button class="btn-sm" id="ch-copy">마크다운 복사</button><button class="btn-sm" id="ch-dl">.md 저장</button>
        ${window.AIOPS_SIM && r.failures.length ? `<button class="btn-sm" id="ch-sim">시뮬레이터에서 보기</button>` : ""}</div>
      <p class="small muted">계산만 합니다 — 실제 작업·명령은 하지 않습니다. 해석이 틀리면 칩의 ✕ 로 빼고 다시 검토하세요.</p>`;
  }
  function draw() {
    const b = $("#chg-body"); if (!b) return;
    b.innerHTML = `<div class="ch-in"><textarea id="ch-text" rows="3" placeholder="작업 계획을 적으세요 — 예: ${esc(EX[0])}">${esc(st.text)}</textarea>
        <div class="ch-bar"><button class="btn-sm primary" id="ch-go" ${st.busy ? "disabled" : ""}>${st.busy ? "검토 중…" : "사전 검토"}</button>
          <label class="vu-act"><input type="checkbox" id="ch-ai" ${st.ai ? "checked" : ""}> AI 해석·검토(설정돼 있을 때, 이름은 가명)</label>
          <span class="small muted">예시: ${EX.map((x, i) => `<button type="button" class="linkish" data-ex="${i}">${esc(x)}</button>`).join(" · ")}</span></div></div>
      ${st.err ? `<p class="es-bad">${esc(st.err)}</p>` : ""}${result()}`;
  }
  function wire() {
    const b = $("#chg-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const t = e.target.closest("button"); if (!t) return;
      if (t.id === "ch-go") { st.text = $("#ch-text").value; await review(); return; }
      if (t.dataset.ex !== undefined) { st.text = EX[+t.dataset.ex]; await review(); return; }
      if (t.dataset.rmf) { const keep = st.r.failures.filter(f => `${f.type}|${f.target}` !== t.dataset.rmf).map(({type, vcenter, target, kind, name}) => ({type, vcenter, target, kind, name})); await review(keep); return; }
      if (t.id === "ch-copy") { try { await navigator.clipboard.writeText(st.r.markdown); A.ok("변경 사전 검토", "마크다운을 복사했습니다"); } catch (err) { A.fail("복사", err); } return; }
      if (t.id === "ch-dl") { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([st.r.markdown], {type: "text/markdown"})); a.download = `change-review-${new Date().toISOString().slice(0, 10)}.md`; a.click(); return; }
      if (t.id === "ch-sim") { const nav = document.getElementById("nav-bot"); if (nav) nav.click(); setTimeout(() => { const m = document.querySelector('[data-cbmode="sim"]'); if (m) m.click(); window.AIOPS_SIM.show(document.getElementById("sm-body"), st.r.failures.map(({type, vcenter, target}) => ({type, vcenter, target}))); }, 400); }
    });
    b.addEventListener("change", e => { if (e.target.id === "ch-ai") st.ai = e.target.checked; });
    b.addEventListener("keydown", e => { if (e.target.id === "ch-text" && e.key === "Enter" && (e.ctrlKey || e.metaKey)) { st.text = e.target.value; review(); } });
  }
  function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-chg") d.hidden = true; });
    $("#drawer-chg").hidden = false;
    wire(); draw();
  }
  const nav = document.getElementById("nav-chg"); if (nav) nav.onclick = show;
  window.AIOPS_CHG = show;
})();
