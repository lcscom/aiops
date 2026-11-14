/* 성능 상시 감시(2.25.0) — 호스트 맵 · 이상·경보 · 감시 규칙 탭(호스트·VM 성능 화면 안). perfview.js 가 탭을 그리고 여기 렌더러를 부름 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const M = {cpu: ["CPU 사용률", "%"], mem: ["메모리 사용률", "%"], rdy: ["CPU ready", "%"], iops: ["디스크 IOPS", ""], lat: ["디스크 지연", "ms"], dbps: ["디스크 처리량", "B/s"], nbps: ["네트워크", "bps"]};
  const TYPE = {threshold: "임계값", anomaly: "평소와 다름(계절성 기준선)", outlier: "클러스터 안 이상치"};
  const SEVL = {critical: "위험", warning: "경고"};
  const fmtv = (m, v) => v == null ? "—" : m === "dbps" ? `${(v / 1e6).toFixed(1)} MB/s` : m === "nbps" ? (v >= 1e9 ? `${(v / 1e9).toFixed(2)} Gbps` : `${(v / 1e6).toFixed(1)} Mbps`)
    : m === "iops" ? Math.round(v).toLocaleString() : m === "lat" ? `${v.toFixed(1)} ms` : `${v.toFixed(v < 10 ? 1 : 0)}%`;
  const ago = t => { const s = Math.max(0, Date.now() / 1000 - t); return s < 3600 ? `${Math.round(s / 60)}분` : s < 86400 ? `${(s / 3600).toFixed(1)}시간` : `${(s / 86400).toFixed(1)}일`; };
  const dt = t => t ? new Date(t * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";
  const st = {map: {kind: "host", group: "cluster", fill: "cpu", size: "none", q: ""}, mapData: null, watch: null, hist: null, edit: null, preview: null, seq: 0};

  // ------------------------------------------------------------ 색 척도(지표별 기준 — %는 0~100, 지연은 0~50ms, 그 밖은 현재 분포의 95번째 값)
  function scale(metric, items) {
    if (metric === "cpu" || metric === "mem") return v => v / 100;
    if (metric === "rdy") return v => v / 15;
    if (metric === "lat") return v => v / 50;
    const xs = items.map(i => i[metric]).filter(v => v != null).sort((a, b) => a - b);
    const p95 = xs.length ? xs[Math.floor(xs.length * 0.95)] || xs[xs.length - 1] : 1;
    return v => p95 ? v / p95 : 0;
  }
  const color = f => { if (f == null || isNaN(f)) return "#e6e6e6"; const x = Math.max(0, Math.min(1, f));
    const stops = [[0, [223, 240, 213]], [0.5, [255, 229, 138]], [0.75, [255, 170, 80]], [1, [214, 64, 45]]];
    let i = 0; while (i < stops.length - 2 && x > stops[i + 1][0]) i++;
    const [a, ca] = stops[i], [b, cb] = stops[i + 1], t = (x - a) / (b - a || 1);
    return `rgb(${ca.map((c, k) => Math.round(c + (cb[k] - c) * t)).join(",")})`; };

  // ------------------------------------------------------------ 호스트 맵
  async function loadMap(box, ctx) {
    const my = ++st.seq;
    try { const d = await A.api("GET", `/api/perf/map?kind=${st.map.kind}`, undefined, {background: true}); if (my === st.seq) { st.mapData = d; drawMap(box, ctx); } }
    catch (e) { if (my === st.seq) { box.innerHTML = `<div class="empty">호스트 맵을 불러오지 못했습니다 — ${esc(e.message || e)}</div>`; } }
  }
  function drawMap(box, ctx) {
    const d = st.mapData, o = st.map;
    const ctl = `<div class="pw-ctl">
      <label>대상<select data-mk="kind"><option value="host"${o.kind === "host" ? " selected" : ""}>호스트</option><option value="vm"${o.kind === "vm" ? " selected" : ""}>VM</option></select></label>
      <label>묶기<select data-mk="group">${[["cluster", "클러스터"], ["host", "호스트(VM)"], ["vcenter", "vCenter"], ["none", "묶지 않음"]].filter(([k]) => k !== "host" || o.kind === "vm").map(([k, l]) => `<option value="${k}"${o.group === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>
      <label>색<select data-mk="fill">${Object.entries(M).filter(([k]) => k !== "rdy" || o.kind === "vm").map(([k, [l]]) => `<option value="${k}"${o.fill === k ? " selected" : ""}>${esc(l)}</option>`).join("")}</select></label>
      <label>크기<select data-mk="size">${[["none", "같게"], ["vcpu", "vCPU"], ["mem_mb", "메모리"], ["iops", "디스크 IOPS"], ["nbps", "네트워크"]].filter(([k]) => o.kind === "vm" || !["vcpu"].includes(k)).map(([k, l]) => `<option value="${k}"${o.size === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>
      <input type="search" data-mk="q" placeholder="이름·클러스터 거르기" value="${esc(o.q)}" aria-label="거르기">
      <button class="btn-sm" data-pw="map-reload">새로 고침</button></div>`;
    if (!d) { box.innerHTML = ctl + `<div class="empty">불러오는 중…</div>`; return; }
    let items = d.items.slice();
    const q = o.q.trim().toLowerCase();
    if (q) items = items.filter(i => `${i.name} ${i.cluster} ${i.host}`.toLowerCase().includes(q));
    if (!items.length) { box.innerHTML = ctl + `<div class="empty">${d.items.length ? "거르기 결과 없음" : "자체 성능 이력이 아직 없습니다 — 성능 감시가 5분마다 모든 호스트·VM 을 수집합니다(첫 수집은 기동 후 약 1분)."}</div>`; return; }
    const sc = scale(o.fill, items);
    const sizes = o.size === "none" ? null : items.map(i => i[o.size] || 0);
    const smax = sizes ? Math.max(...sizes, 1) : 1;
    const px = i => o.size === "none" ? (o.kind === "vm" ? 24 : 48) : Math.round(16 + 34 * Math.sqrt((i[o.size] || 0) / smax));
    const txt = (i, s) => s >= 40 && i[o.fill] != null ? `<span>${esc(o.fill === "cpu" || o.fill === "mem" || o.fill === "rdy" ? Math.round(i[o.fill]) : o.fill === "lat" ? i[o.fill].toFixed(0) : "")}</span>` : "";
    const key = i => o.group === "cluster" ? `${i.vcenter} · ${i.cluster || "(클러스터 없음)"}` : o.group === "host" ? (i.host || "(호스트 없음)") : o.group === "vcenter" ? i.vcenter : "전체";
    const groups = {};
    for (const i of items) (groups[key(i)] ||= []).push(i);
    const avg = xs => { const v = xs.map(x => x[o.fill]).filter(x => x != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
    box.innerHTML = ctl + `<div class="pw-legend small"><span>${esc(M[o.fill][0])}</span><i style="background:${color(0)}"></i>낮음<i style="background:${color(0.5)}"></i><i style="background:${color(0.75)}"></i><i style="background:${color(1)}"></i>높음
        <span class="pw-al crit"></span>위험 경보 <span class="pw-al warn"></span>경고 · ${items.length.toLocaleString()}대 · 최근 수집 ${esc(dt(d.last))} (${Math.round(d.interval / 60)}분 간격)</div>
      <div class="pw-map">${Object.entries(groups).sort((a, b) => (avg(b[1]) ?? -1) - (avg(a[1]) ?? -1)).map(([g, xs]) => `<section class="pw-grp"><h5>${esc(g)} <small class="muted">${xs.length}대 · 평균 ${esc(fmtv(o.fill, avg(xs)))}</small></h5>
        <div class="pw-cells">${xs.sort((a, b) => (b[o.fill] ?? -1) - (a[o.fill] ?? -1)).map(i => { const s = px(i);
          return `<button type="button" class="pw-cell${i.alert ? " al-" + i.alert : ""}${i.maintenance ? " mm" : ""}" style="width:${s}px;height:${s}px;background:${color(i[o.fill] == null ? null : sc(i[o.fill]))}"
            data-go-kind="${o.kind}" data-go-name="${esc(i.name)}" data-go-vc="${esc(i.vcenter)}"
            title="${esc(i.name)}\n${esc(M[o.fill][0])} ${esc(fmtv(o.fill, i[o.fill]))} · CPU ${esc(fmtv("cpu", i.cpu))} · 메모리 ${esc(fmtv("mem", i.mem))} · 지연 ${esc(fmtv("lat", i.lat))}${i.alert ? `\n경보: ${SEVL[i.alert]}` : ""}" aria-label="${esc(i.name)} ${esc(fmtv(o.fill, i[o.fill]))}">${txt(i, s)}</button>`; }).join("")}</div></section>`).join("")}</div>`;
  }

  // ------------------------------------------------------------ 이상·경보
  async function loadWatch(box, ctx, withHist = true) {
    const my = ++st.seq;
    try {
      const [w, h] = await Promise.all([A.api("GET", "/api/perf/watch", undefined, {background: true}), withHist ? A.api("GET", "/api/perf/watch/history?hours=24", undefined, {background: true}) : Promise.resolve(st.hist)]);
      if (my !== st.seq) return;
      st.watch = w; st.hist = h; ctx.tab === "alerts" ? drawAlerts(box) : drawRules(box);
    } catch (e) { if (my === st.seq) box.innerHTML = `<div class="empty">성능 감시 상태를 불러오지 못했습니다 — ${esc(e.message || e)}</div>`; }
  }
  const tgt = a => `<a href="#" data-go-kind="${esc(a.kind)}" data-go-name="${esc(a.name)}" data-go-vc="${esc(a.vcenter || "")}">${esc(a.name)}</a> <small class="muted">${a.kind === "vm" ? "VM" : "호스트"}${a.cluster ? " · " + esc(a.cluster) : ""}</small>`;
  function drawAlerts(box) {
    const w = st.watch, s = w.stats || {}, z = w.size || {};
    const al = w.alerts || [];
    const by = {critical: al.filter(a => a.sev === "critical").length, warning: al.filter(a => a.sev === "warning").length};
    const types = {threshold: 0, anomaly: 0, outlier: 0}; al.forEach(a => { types[a.type] = (types[a.type] || 0) + 1; });
    box.innerHTML = `<div class="kpis pw-kpis">
        <div class="kpi"><span>지금 경보</span><b class="${by.critical ? "bad" : by.warning ? "warn" : "ok"}">${al.length}</b><small class="muted">위험 ${by.critical} · 경고 ${by.warning}</small></div>
        <div class="kpi"><span>임계값</span><b>${types.threshold}</b></div><div class="kpi"><span>평소와 다름</span><b>${types.anomaly}</b></div><div class="kpi"><span>클러스터 이상치</span><b>${types.outlier}</b></div>
        <div class="kpi"><span>수집</span><b class="pw-small">${(s.count || 0).toLocaleString()}대</b><small class="muted">${s.last ? `${esc(ago(s.last))} 전 · ${s.ms}ms` : "아직 없음"}${(s.errors || []).length ? ` · 오류 ${esc(s.errors.join(", "))}` : ""}</small></div>
        <div class="kpi"><span>자체 이력</span><b class="pw-small">${z.mb ?? 0} MB</b><small class="muted">5분 ${(z.s5 || 0).toLocaleString()} · 1시간 ${(z.h1 || 0).toLocaleString()} · ${z.entities || 0}대</small></div></div>
      ${al.length ? `<table class="vc-t pw-t"><thead><tr><th>수준</th><th>규칙</th><th>대상</th><th>내용</th><th>지속</th></tr></thead><tbody>
        ${al.map(a => `<tr><td><span class="pf-fs ${a.sev}">${SEVL[a.sev]}</span></td><td>${esc(a.rule_name)}<div class="small muted">${esc(TYPE[a.type] || a.type)}</div></td><td>${tgt(a)}</td><td class="small">${esc(a.msg)}</td><td class="num">${esc(ago(a.since))}</td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">지금 경보 없음 — 모든 감시 규칙이 정상 범위입니다.</div>`}
      <details class="pw-hist" open><summary>최근 24시간 경보 기록 ${(st.hist && st.hist.items || []).length}건</summary>
      ${(st.hist && st.hist.items || []).length ? `<table class="vc-t"><thead><tr><th>시작</th><th>끝</th><th>수준</th><th>규칙</th><th>대상</th><th>내용</th></tr></thead><tbody>
        ${st.hist.items.slice(0, 200).map(a => `<tr><td>${esc(dt(a.start))}</td><td>${a.end ? esc(dt(a.end)) : "<b>진행 중</b>"}</td><td><span class="pf-fs ${a.sev}">${SEVL[a.sev] || a.sev}</span></td><td>${esc(a.rule_name)}</td><td>${tgt(a)}</td><td class="small">${esc(a.msg || "")}</td></tr>`).join("")}</tbody></table>` : `<p class="small muted">기록 없음</p>`}</details>
      <p class="small muted">경보는 상태가 바뀔 때만 플랫폼 이벤트(성능 감시)로 올라가 알림 라우팅·인시던트로 이어지고, 정상으로 돌아오면 정상화 이벤트가 갑니다.</p>`;
  }

  // ------------------------------------------------------------ 감시 규칙
  const cond = r => r.type === "threshold" ? `${esc(M[r.metric][0])} ${r.window}분 평균 ${r.op === "below" ? "≤" : "≥"} ${r.warn != null ? "경고 " + esc(fmtv(r.metric, r.warn)) : ""}${r.warn != null && r.crit != null ? " / " : ""}${r.crit != null ? "위험 " + esc(fmtv(r.metric, r.crit)) : ""}`
    : r.type === "anomaly" ? `${esc(M[r.metric][0])} 이 평소 범위(시간대 기준선 ±${r.k}σ) ${({above: "위로", below: "아래로", both: "위아래로"})[r.direction]} 벗어남 — ${r.window}분 중 ${r.pct}%`
    : `${esc(M[r.metric][0])} 이 같은 클러스터 동료 중앙값에서 ${r.tolerance}×MAD 밖 — ${r.window}분 중 ${r.pct}%`;
  function drawRules(box) {
    const w = st.watch, can = A.can("settings");
    const cnt = {}; (w.alerts || []).forEach(a => { cnt[a.rule] = (cnt[a.rule] || 0) + 1; });
    const ev = (w.last_eval && w.last_eval.rules) || {};
    box.innerHTML = `<div class="pw-ctl">${can ? `<button class="btn-sm solid" data-pw="new">새 규칙</button><button class="btn-sm" data-pw="reset">기본 규칙으로 되돌리기</button>` : `<span class="small muted">규칙 변경은 settings 권한</span>`}</div>
      ${st.edit ? editor() : ""}
      <table class="vc-t pw-t"><thead><tr><th>켬</th><th>규칙</th><th>대상</th><th>조건</th><th>평가/경보</th><th></th></tr></thead><tbody>
      ${(w.rules || []).map(r => `<tr class="${r.enabled ? "" : "pw-off"}"><td>${can ? `<input type="checkbox" data-pw-toggle="${esc(r.id)}"${r.enabled ? " checked" : ""} aria-label="${esc(r.name)} 켜기">` : (r.enabled ? "켬" : "끔")}</td>
        <td><b>${esc(r.name)}</b><div class="small muted">${esc(TYPE[r.type])} · ${esc(r.id)}</div></td>
        <td>${r.kind === "vm" ? "VM" : "호스트"}${r.cluster ? `<div class="small muted">클러스터 ~ ${esc(r.cluster)}</div>` : ""}${r.name_re ? `<div class="small muted">이름 ~ ${esc(r.name_re)}</div>` : ""}${r.exclude_re ? `<div class="small muted">제외 ~ ${esc(r.exclude_re)}</div>` : ""}</td>
        <td class="small">${cond(r)}</td><td class="num">${(ev[r.id] || {}).evaluated ?? "—"} / <b class="${cnt[r.id] ? "bad" : ""}">${cnt[r.id] || 0}</b></td>
        <td>${can ? `<button class="btn-sm" data-pw-edit="${esc(r.id)}">편집</button><button class="btn-sm" data-pw-del="${esc(r.id)}">삭제</button>` : ""}</td></tr>`).join("")}</tbody></table>
      <p class="small muted">평가는 ${Math.round((w.interval || 300) / 60)}분마다(자체 이력 수집 직후). '평소와 다름'은 같은 시각의 과거 값(3주 이상이면 요일·시간, 3일 이상이면 시간, 그보다 적으면 최근 24시간)으로 정상 범위를 만들고, '클러스터 이상치'는 3대 이상 클러스터에서 동료와 비교합니다.</p>`;
  }
  function editor() {
    const r = st.edit, p = st.preview;
    const opt = (arr, v) => arr.map(([k, l]) => `<option value="${k}"${String(v) === String(k) ? " selected" : ""}>${esc(l)}</option>`).join("");
    return `<form class="pw-edit" id="pw-form" autocomplete="off"><h5>${r._new ? "새 규칙" : "규칙 편집"}</h5>
      <div class="pw-grid">
        <label>이름<input name="name" value="${esc(r.name || "")}" maxlength="80" required></label>
        <label>ID<input name="id" value="${esc(r.id || "")}" maxlength="40" ${r._new ? "" : "readonly"} pattern="[a-z0-9-]*" placeholder="자동"></label>
        <label>대상<select name="kind">${opt([["vm", "VM"], ["host", "호스트"]], r.kind)}</select></label>
        <label>지표<select name="metric">${opt(Object.entries(M).map(([k, [l]]) => [k, l]), r.metric)}</select></label>
        <label>방식<select name="type">${opt(Object.entries(TYPE), r.type)}</select></label>
        <label>창(분)<input name="window" type="number" min="5" max="120" value="${r.window || 15}"></label>
        ${r.type === "threshold" ? `<label>방향<select name="op">${opt([["above", "이상(≥)"], ["below", "이하(≤)"]], r.op || "above")}</select></label>
          <label>경고 값<input name="warn" type="number" step="any" value="${r.warn ?? ""}"></label><label>위험 값<input name="crit" type="number" step="any" value="${r.crit ?? ""}"></label>`
        : r.type === "anomaly" ? `<label>밴드 폭(σ)<input name="k" type="number" step="0.5" min="1" max="10" value="${r.k ?? 3}"></label>
          <label>방향<select name="direction">${opt([["above", "위로 벗어남"], ["below", "아래로"], ["both", "양쪽"]], r.direction || "above")}</select></label>
          <label>창 중 비율(%)<input name="pct" type="number" min="10" max="100" value="${r.pct ?? 80}"></label><label>수준<select name="sev">${opt([["warning", "경고"], ["critical", "위험"]], r.sev || "warning")}</select></label>`
        : `<label>허용 폭(×MAD)<input name="tolerance" type="number" step="0.5" min="1" max="10" value="${r.tolerance ?? 3}"></label>
          <label>방향<select name="direction">${opt([["above", "동료보다 높음"], ["both", "높거나 낮음"]], r.direction === "both" ? "both" : "above")}</select></label>
          <label>창 중 비율(%)<input name="pct" type="number" min="10" max="100" value="${r.pct ?? 60}"></label><label>수준<select name="sev">${opt([["warning", "경고"], ["critical", "위험"]], r.sev || "warning")}</select></label>`}
        <label>클러스터(정규식)<input name="cluster" value="${esc(r.cluster || "")}" placeholder="예: ^Prod-"></label>
        <label>이름(정규식)<input name="name_re" value="${esc(r.name_re || "")}" placeholder="예: ^db-"></label>
        <label>제외(정규식)<input name="exclude_re" value="${esc(r.exclude_re || "")}" placeholder="예: -test$"></label>
        <label class="pw-chk"><input type="checkbox" name="enabled"${r.enabled !== false ? " checked" : ""}> 켬</label>
      </div>
      <div class="pw-ctl"><button type="button" class="btn-sm" data-pw="preview">지금 데이터로 미리 보기</button><button type="submit" class="btn-sm solid">저장</button><button type="button" class="btn-sm" data-pw="cancel">취소</button></div>
      ${p ? `<div class="pw-prev small">${p.error ? `<span class="bad">${esc(p.error)}</span>` : `평가 ${p.evaluated}대 중 <b>${p.hits.length}대</b> 경보${p.hits.length ? ": " + p.hits.slice(0, 12).map(h => `${esc(h.name)}(${SEVL[h.sev]})`).join(", ") + (p.hits.length > 12 ? " …" : "") : ""}`}</div>` : ""}
    </form>`;
  }
  function formRule(box) {
    const f = $("#pw-form", box); if (!f) return st.edit;
    const r = {...st.edit};
    for (const el of f.elements) { if (!el.name) continue; r[el.name] = el.type === "checkbox" ? el.checked : el.value; }
    delete r._new; return r;
  }

  // ------------------------------------------------------------ 이벤트(한 번만 연결)
  function wire(box, ctx) {
    if (box._pwWired) return; box._pwWired = true;
    box.addEventListener("change", e => {
      const k = e.target.dataset && e.target.dataset.mk;
      if (k && k !== "q") { st.map[k] = e.target.value; if (k === "kind") { if (st.map.group === "host" && st.map.kind === "host") st.map.group = "cluster"; if (st.map.fill === "rdy" && st.map.kind === "host") st.map.fill = "cpu"; st.mapData = null; loadMap(box, ctx); } else drawMap(box, ctx); return; }
      const tg = e.target.dataset && e.target.dataset.pwToggle;
      if (tg) { const r = (st.watch.rules || []).find(x => x.id === tg); if (st.edit) st.edit = {...formRule(box), _new: st.edit._new}; if (r) saveRule({...r, enabled: e.target.checked}, box, ctx); return; }
      if (e.target.name === "type" && st.edit) { st.edit = {...formRule(box), type: e.target.value, _new: st.edit._new}; st.preview = null; drawRules(box); }
    });
    box.addEventListener("compositionend", e => { if (e.target.dataset && e.target.dataset.mk === "q") e.target.dispatchEvent(new Event("input", {bubbles: true})); });   // 한글·모바일 자판
    box.addEventListener("input", e => { if (e.target.dataset && e.target.dataset.mk === "q" && !e.isComposing) { st.map.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(() => { drawMap(box, ctx); const i = box.querySelector('[data-mk="q"]'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 300); } });
    box.addEventListener("submit", e => { if (e.target.id === "pw-form") { e.preventDefault(); const isNew = st.edit && st.edit._new; const r = formRule(box); st.edit = {...r, _new: isNew}; saveRule(isNew ? {...r, create: true} : r, box, ctx, true); } });
    box.addEventListener("click", async e => {
      const t = e.target;
      const go = t.closest("[data-go-name]"); if (go) { e.preventDefault(); ctx.select(go.dataset.goKind, go.dataset.goName, go.dataset.goVc); return; }
      const a = t.closest("[data-pw]"); const act = a && a.dataset.pw;
      if (act === "map-reload") { st.mapData = null; loadMap(box, ctx); }
      else if (act === "new") { st.edit = {_new: true, kind: "vm", metric: "cpu", type: "threshold", window: 15, warn: 80, crit: 95, enabled: true}; st.preview = null; drawRules(box); }
      else if (act === "cancel") { st.edit = null; st.preview = null; drawRules(box); }
      else if (act === "preview") {
        const r = formRule(box);
        try { st.preview = await A.api("POST", "/api/perf/rules/preview", r); } catch (er) { st.preview = {error: er.message || String(er)}; }
        st.edit = {...r, _new: st.edit && st.edit._new}; drawRules(box);
      } else if (act === "reset") {
        if (!confirm("감시 규칙을 기본 10개로 되돌립니다(직접 만든 규칙은 지워짐). 계속할까요?")) return;
        try { await A.api("POST", "/api/perf/rules/reset", {}); A.ok("기본 규칙으로 되돌렸습니다"); loadWatch(box, ctx, false); } catch (er) { A.fail("되돌리지 못했습니다", er); }
      }
      const ed = t.closest("[data-pw-edit]"); if (ed) { st.edit = {...(st.watch.rules || []).find(x => x.id === ed.dataset.pwEdit)}; st.preview = null; drawRules(box); box.scrollIntoView({block: "start"}); }
      const dl = t.closest("[data-pw-del]"); if (dl) {
        if (!confirm(`규칙 '${dl.dataset.pwDel}' 을(를) 삭제할까요? 진행 중인 경보도 함께 사라집니다.`)) return;
        try { await A.api("DELETE", `/api/perf/rules/${encodeURIComponent(dl.dataset.pwDel)}`); A.ok("삭제했습니다"); loadWatch(box, ctx, false); } catch (er) { A.fail("삭제하지 못했습니다", er); }
      }
    });
  }
  async function saveRule(r, box, ctx, closeForm) {
    try { await A.api("POST", "/api/perf/rules", r); A.ok("규칙을 저장했습니다"); if (closeForm) { st.edit = null; st.preview = null; } loadWatch(box, ctx, false); }
    catch (e) { A.fail("규칙을 저장하지 못했습니다", e); }
  }

  window.AIOPS_PW = {
    map(box, ctx) { wire(box, ctx); if (st.mapData) drawMap(box, ctx); else { drawMap(box, ctx); loadMap(box, ctx); } },
    alerts(box, ctx) { wire(box, ctx); ctx.tab = "alerts"; if (st.watch) drawAlerts(box); else box.innerHTML = `<div class="empty">불러오는 중…</div>`; loadWatch(box, ctx); },
    rules(box, ctx) { wire(box, ctx); ctx.tab = "rules"; if (st.watch) drawRules(box); else box.innerHTML = `<div class="empty">불러오는 중…</div>`; loadWatch(box, ctx, false); },
    refresh(tab, box, ctx) {
      if (tab === "map") { if (!box.contains(document.activeElement) || !document.activeElement.closest(".pw-ctl")) loadMap(box, ctx); }   // 조작 중엔 다시 그리지 않음
      else if (tab === "alerts") loadWatch(box, ctx);
    },
    count() { return st.watch ? (st.watch.alerts || []).length : null; },
  };
})();
