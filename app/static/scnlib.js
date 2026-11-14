/* What-If 시나리오 라이브러리(2.47.0) — 점검·진단 › What-If 시나리오 › 시나리오 라이브러리
   파트(컴퓨트·스토리지·물리 네트워크·NSX·관리 서비스·쿠버네티스·Avi·DR)별 시나리오를 지금 구성에 대고 한꺼번에 계산.
   카드를 누르면 장애 시뮬레이터에서 영향(VM·Pod·가상 서비스)을 자세히. 계산만 — 어떤 명령도 보내지 않음 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const st = {d: null, part: "comp", busy: false, err: "", f: "", q: "", view: "lib", sp: null, spBusy: false, hist: null};
  const V = {fail: ["bad", "실패"], warn: ["warn", "주의"], pass: ["ok", "통과"], none: ["na", "해당 없음"]};
  let body = null;

  async function load() {
    st.busy = true; draw();
    try { st.d = await A.api("GET", "/api/checkbot/library?run=1", undefined, {background: true}); st.err = ""; } catch (e) { st.err = String(e.message || e); }
    st.busy = false; draw();
  }
  async function loadSpof() { st.spBusy = true; draw(); try { st.sp = await A.api("GET", "/api/checkbot/spof?top=60", undefined, {background: true}); } catch (e) { st.err = String(e.message || e); } st.spBusy = false; draw(); }
  async function loadHist() { try { st.hist = await A.api("GET", "/api/checkbot/library/history?n=30", undefined, {background: true}); } catch (e) { st.hist = {items: [], error: String(e.message || e)}; } draw(); }
  const T = ts => ts ? new Date(ts * 1000).toLocaleString("ko-KR", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "—";
  function views() {
    const b = (k, l) => `<button type="button" class="${st.view === k ? "on" : ""}" data-view="${k}">${l}</button>`;
    return `<div class="sl-view">${b("lib", "파트별 시나리오")}${b("spof", "단일 장애점 순위")}${b("hist", "검증 기록")}
      <span class="sl-exp"><a href="/api/checkbot/library.md" download>보고서(.md)</a><a href="/api/checkbot/library.csv" download>CSV</a>
      ${A.can("operate") ? `<button type="button" id="sl-snap" title="지금 결과를 기록하고 지난번과 비교(새로 실패하면 이상징후로 알림)">기록 저장</button>` : ""}</span></div>`;
  }
  function spofView() {
    if (!st.sp) return `<p class="sm-hint">${st.spBusy ? "객체를 하나씩 고장 내 계산하는 중…" : ""}</p>`;
    const mx = Math.max(1, ...st.sp.top.map(x => x.score));
    const kinds = Object.entries(st.sp.by_kind).map(([k, n]) => `${esc(k)} ${n}`).join(" · ");
    return `<div class="sl-sum">객체 <b>${st.sp.scanned}</b>개(${kinds})를 하나씩 고장 내 계산 · 혼자 고장 나도 서비스가 멈추는 단일 장애점 <b class="v-bad">${st.sp.spof}</b>개</div>
      <div style="overflow-x:auto"><table class="dr-t"><thead><tr><th class="r">#</th><th>종류</th><th>이름</th><th>점수</th><th class="r">중단 VM</th><th class="r">재시작 불확실</th><th class="r">HA 재시작</th><th class="r">중단 워크로드·VIP</th><th class="r">Pod</th><th>이유</th><th></th></tr></thead><tbody>
      ${st.sp.top.map((x, i) => `<tr><td class="r">${i + 1}</td><td class="small">${esc(x.kind)}</td><td class="mono small">${esc(x.name)}</td>
        <td><div class="sp-bar" title="${x.score}"><i style="width:${Math.max(3, Math.round(x.score / mx * 100))}%"></i></div><small>${x.score}</small></td>
        <td class="r ${x.stop ? "v-bad" : ""}">${x.stop || ""}</td><td class="r">${x.maybe || ""}</td><td class="r">${x.restart || ""}</td><td class="r ${x.pstop ? "v-bad" : ""}">${x.pstop || ""}</td><td class="r">${x.pods || ""}</td>
        <td class="small">${esc((x.why || "").replace(/^\[[^\]]+\]\s*/, "").slice(0, 120))}</td><td><button type="button" class="btn-sm" data-spi="${i}">보기</button></td></tr>`).join("")}</tbody></table></div>
      <p class="small muted">${esc(st.sp.rule)}. 같은 점수면 종류·이름 순. 객체 하나만 고장 나는 경우만 봅니다 — 동시 장애는 파트별 시나리오에서.</p>`;
  }
  function histView() {
    const h = st.hist; if (!h) return `<p class="sm-hint">불러오는 중…</p>`;
    if (!h.items.length) return `<p class="sm-hint">아직 기록이 없습니다 — 6시간마다 자동으로 기록하며 '기록 저장'으로 지금 남길 수 있습니다.</p>`;
    const titles = Object.fromEntries((st.d ? st.d.items : []).map(x => [x.id, x.title]));
    return `<div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>시각</th><th class="r">실패</th><th class="r">주의</th><th class="r">통과</th><th class="r">단일 장애점</th><th>새로 실패</th><th>해소</th></tr></thead><tbody>
      ${h.items.map(x => `<tr><td class="small">${T(x.ts)}</td><td class="r v-bad">${x.counts.fail || 0}</td><td class="r">${x.counts.warn || 0}</td><td class="r">${x.counts.pass || 0}</td><td class="r">${x.spof}</td>
        <td class="small">${x.new_fail.map(i => `<span title="${esc(titles[i] || "")}">${esc(i)}</span>`).join(", ") || "—"}</td><td class="small">${x.fixed.map(esc).join(", ") || "—"}</td></tr>`).join("")}</tbody></table></div>
      <p class="small muted">새로 실패한 시나리오가 생기면 '이상징후'로 올라와 알림 규칙을 탑니다.</p>`;
  }
  function draw() {
    if (!body) return;
    if (st.view !== "lib" && st.d) { body.innerHTML = `<div class="sm-safe" role="note"><b>시뮬레이션 전용</b> — 계산만 합니다. 어떤 장비에도 명령을 보내지 않습니다.</div>${views()}${st.view === "spof" ? spofView() : histView()}`; return; }
    if (!st.d) { body.innerHTML = `<div class="sm-safe" role="note"><b>시뮬레이션 전용</b> — 계산만 합니다.</div><p class="sm-hint">${st.err ? esc(st.err) : "파트별 시나리오를 지금 구성에 대고 계산하는 중…"}</p>`; return; }
    const P = st.d.parts, all = st.d.items;
    const tot = k => all.filter(x => x.verdict === k).length;
    const tabs = P.map(p => `<button type="button" class="sl-tab ${st.part === p.key ? "on" : ""}" data-part="${p.key}" title="${esc(p.desc)}"><b>${esc(p.label)}</b>
      <span>${p.total}</span>${p.fail ? `<i class="v-bad">${p.fail}</i>` : ""}${p.warn ? `<i class="v-warn">${p.warn}</i>` : ""}</button>`).join("");
    const cur = P.find(p => p.key === st.part) || P[0];
    const q = st.q.toLowerCase();
    let it = all.filter(x => x.part === cur.key && (!st.f || x.verdict === st.f) && (!q || (x.title + " " + (x.target || "") + " " + (x.top || "")).toLowerCase().includes(q)));
    const ord = {fail: 0, warn: 1, pass: 2, none: 3};
    it = it.slice().sort((a, b) => ord[a.verdict] - ord[b.verdict]);
    body.innerHTML = `<div class="sm-safe" role="note"><b>시뮬레이션 전용</b> — 수집해 둔 구성의 복사본으로 시나리오마다 가장 영향이 큰 대상을 골라 계산합니다. 어떤 장비에도 명령을 보내지 않습니다.
        <button type="button" class="sm-reset" id="sl-run" ${st.busy ? "disabled" : ""}>${st.busy ? "계산 중…" : "다시 계산"}</button></div>
      ${views()}
      ${st.d.diff && (st.d.diff.new_fail.length || st.d.diff.fixed.length) ? `<div class="sl-diff">지난 기록(${T(st.d.diff.prev_ts)}) 대비 — 새로 실패 <b>${st.d.diff.new_fail.length}</b>${st.d.diff.new_fail.length ? ` (${st.d.diff.new_fail.slice(0, 8).map(esc).join(", ")})` : ""} · 해소 <b>${st.d.diff.fixed.length}</b></div>` : ""}
      <div class="sl-sum">시나리오 <b>${all.length}</b>개 · <span class="v-bad">실패 ${tot("fail")}</span> · <span class="v-warn">주의 ${tot("warn")}</span> · <span class="v-ok">통과 ${tot("pass")}</span> · <span class="muted">해당 없음 ${tot("none")}</span></div>
      <div class="sl-tabs" role="tablist">${tabs}</div>
      <div class="sl-head"><div><b>${esc(cur.label)}</b> <small class="muted">${esc(cur.desc)}</small></div>
        <div class="sl-f">${["", "fail", "warn", "pass", "none"].map(k => `<button type="button" class="${st.f === k ? "on" : ""}" data-f="${k}">${k ? V[k][1] : "전체"}</button>`).join("")}
        <input id="sl-q" placeholder="찾기" value="${esc(st.q)}"></div></div>
      <div class="sl-grid">${it.map(card).join("") || `<p class="sm-hint">해당하는 시나리오가 없습니다.</p>`}</div>
      <p class="small muted">판정은 수집된 구성과 일반적인 VMware 동작 기준입니다. 지식형 시나리오(DNS·KMS·인증서 등)는 '멈추는 것·계속되는 것·확인할 것'으로 보여 줍니다. 대상은 시나리오마다 가장 영향이 큰 것으로 자동 선택 — 시뮬레이터에서 바꿀 수 있습니다.</p>`;
  }
  function card(x) {
    const v = V[x.verdict] || V.none;
    const nums = x.applicable ? [[x.stop, "중단", "bad"], [x.risk, "위험", "warn"], [x.boot, "재시작·잠깐", "boot"], [x.pods, "Pod", "pod"]].filter(n => n[0]).map(n => `<span class="sl-n n-${n[2]}">${n[1]} ${n[0]}</span>`).join("") : "";
    const df = (st.d && st.d.diff) || {new_fail: [], fixed: []};
    const badge = df.new_fail.includes(x.id) ? `<span class="sl-new">새로 실패</span>` : df.fixed.includes(x.id) ? `<span class="sl-fix">해소</span>` : "";
    return `<div class="sl-card v-${v[0]}"><div class="sl-top"><span><span class="sl-v v-${v[0]}">${v[1]}</span>${badge}</span><small class="mono">${esc(x.id)}</small></div>
      <b class="sl-t">${esc(x.title)}</b>
      ${x.applicable ? `<div class="sl-tg">대상 <b>${esc(x.target || "—")}</b></div>${nums ? `<div class="sl-nums">${nums}</div>` : ""}${x.top ? `<p class="sl-why">${esc(x.top.replace(/^\[[^\]]+\]\s*/, ""))}</p>` : ""}
        <button type="button" class="btn-sm" data-open="${esc(x.id)}">시뮬레이터에서 자세히</button>` : `<p class="sl-why muted">${esc(x.why_na || "이 환경에 해당 없음")}</p>`}</div>`;
  }
  function wire(b) {
    if (b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", e => {
      const t = e.target.closest("button"); if (!t) return;
      if (t.dataset.view) { st.view = t.dataset.view; draw(); if (st.view === "spof" && !st.sp) loadSpof(); if (st.view === "hist") loadHist(); return; }
      if (t.id === "sl-snap") { t.disabled = true; A.api("POST", "/api/checkbot/library/snapshot").then(r => { A.ok("What-If", `기록 저장 — 실패 ${r.counts.fail || 0} · 새로 실패 ${r.new_fail.length}`); st.hist = null; if (st.view === "hist") loadHist(); load(); }).catch(e => A.fail("What-If", e)); return; }
      if (t.dataset.spi !== undefined) { const x = st.sp.top[+t.dataset.spi]; if (window.AIOPS_CB_MODE) window.AIOPS_CB_MODE("sim", [{...x.failure, label: x.kind + " 장애"}]); return; }
      if (t.dataset.part) { st.part = t.dataset.part; st.f = ""; draw(); return; }
      if (t.dataset.f !== undefined) { st.f = t.dataset.f; draw(); return; }
      if (t.id === "sl-run") { load(); return; }
      if (t.dataset.open) { const x = st.d.items.find(y => y.id === t.dataset.open); if (window.AIOPS_CB_MODE) window.AIOPS_CB_MODE("sim", null, {id: x.id, title: x.title}); }
    });
    b.addEventListener("input", e => { if (e.target.id !== "sl-q") return; st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(() => { draw(); const q = document.getElementById("sl-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 200); });
  }
  window.AIOPS_SCNLIB = {
    async show(b) { body = b; wire(b); draw(); if (!st.d && !st.busy) await load(); },
    reload: () => { st.sp = null; st.hist = null; load(); if (st.view === "spof") loadSpof(); if (st.view === "hist") loadHist(); },
  };
})();
