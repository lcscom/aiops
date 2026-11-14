/* VCF Ops 메트릭(2.8.0) — VCF Operations 커넥터가 모은 호스트·VM·클러스터·데이터스토어 최신 지표 · 정렬·검색 · 추세 · 메트릭 선택기 · CSV/JSON */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const om = {kind: "HostSystem", conn: "", q: "", sort: "", desc: true, sum: null, data: null, sel: null, timer: null};
  const KINDS = [["HostSystem", "ESXi 호스트"], ["VirtualMachine", "VM"], ["ClusterComputeResource", "클러스터"], ["Datastore", "데이터스토어"]];
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.max(0, Math.round(s))}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : `${Math.round(s / 3600)}시간 전`; };
  const isPct = (k, m) => /pct|percent|%/i.test(k) || /%/.test((m || {}).unit || "") || /usage_average$|^badge\|/.test(k) && !/net\||disk\|/.test(k);
  const fmt = (v, k, m) => { if (v == null) return `<span class="muted">-</span>`; const u = (m || {}).unit || "";
    if (/^kb$/i.test(u) && v >= 1048576) return `${(v / 1048576).toFixed(1)} <small>GB</small>`;
    if (/^kb$/i.test(u) && v >= 1024) return `${(v / 1024).toFixed(1)} <small>MB</small>`;
    return `${Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : (+v.toFixed(2)).toLocaleString()}${u ? ` <small>${esc(u)}</small>` : ""}`; };
  const cell = (v, k, m) => { const p = isPct(k, m) && v != null && v <= 100 && v >= 0;
    const c = /^badge\|health/.test(k) ? (v < 50 ? "#c21d00" : v < 75 ? "#e0a800" : "#62a420") : v >= 90 ? "#c21d00" : v >= 75 ? "#e0a800" : "#4f9fd0";
    return p ? `<div class="om-bar"><i style="width:${v}%;background:${c}"></i><span>${fmt(v, k, m)}</span></div>` : fmt(v, k, m); };
  const label = (k, m) => (m && m.name && m.name !== k) ? m.name : k;

  async function load() {
    try {
      om.sum = await A.api("GET", "/api/opsmetrics", undefined, {background: true});
      om.data = await A.api("GET", `/api/opsmetrics/objects?kind=${om.kind}&connector=${encodeURIComponent(om.conn)}&q=${encodeURIComponent(om.q)}&sort=${encodeURIComponent(om.sort)}&desc=${om.desc}&limit=1000`, undefined, {background: true});
    } catch (e) { $("#om-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }
  function render() {
    const s = om.sum, d = om.data, cs = s.connectors;
    $("#om-sub").textContent = cs.length ? `— ${cs.map(c => `${c.connector} ${c.updated ? ago(c.updated) : "수집 전"}`).join(" · ")}` : "— VCF Operations 커넥터 없음";
    if (!cs.length) { $("#om-body").innerHTML = `<div class="empty">VCF Operations 커넥터가 없습니다 — 운영 설정 › 커넥터에서 'VCF Operations' 를 추가하면(읽기 전용 계정) 메트릭 수집이 함께 켜집니다.</div>`; return; }
    const kinfo = k => cs.reduce((a, c) => { const x = (c.kinds || {})[k]; if (x) { a.n += x.objects; a.d += x.with_data; a.nd = a.nd.concat(x.keys_no_data || []); } return a; }, {n: 0, d: 0, nd: []});
    const ki = kinfo(om.kind);
    $("#om-body").innerHTML = `
      <div class="om-conns">${cs.map(c => `<div class="om-conn ${c.error ? "bad" : c.updated ? "" : "wait"}"><b>${esc(c.connector)}</b> <span class="small muted">${esc(c.host)}</span>
          <span class="small">${c.enabled ? `수집 ${c.updated ? ago(c.updated) : "대기"} · ${Math.round(c.interval / 60)}분 주기${c.took_ms != null ? ` · ${(c.took_ms / 1000).toFixed(1)}초` : ""}${c.api ? ` · ${esc(c.api)}` : ""}` : "메트릭 수집 꺼짐(커넥터 설정)"}</span>
          ${c.error ? `<span class="mon-st ALERT" title="${esc(c.error)}">오류</span> <span class="small">${esc(c.error.slice(0, 160))}</span>` : ""}</div>`).join("")}</div>
      <div class="sec-bar"><div class="inv-chips">${KINDS.map(([k, l]) => { const x = kinfo(k); return `<button data-kind="${k}" class="${om.kind === k ? "on" : ""}">${l} ${x.n ? x.n.toLocaleString() : ""}</button>`; }).join("")}</div>
        ${cs.length > 1 ? `<select id="om-conn"><option value="">전체 커넥터</option>${cs.map(c => `<option ${om.conn === c.connector ? "selected" : ""}>${esc(c.connector)}</option>`).join("")}</select>` : ""}
        <input id="om-q" placeholder="이름 검색" value="${esc(om.q)}"></div>
      ${ki.nd.length ? `<p class="small om-warn">값이 오지 않은 지표: ${[...new Set(ki.nd)].map(k => `<code>${esc(k)}</code>`).join(" ")} — 이 종류에 없는 키이거나 아직 수집 전입니다. '메트릭 선택'에서 카탈로그의 키로 바꾸세요.</p>` : ""}
      ${d.items.length ? `<div class="tbl-x"><table class="vc-t om-t"><thead><tr><th data-sort="">이름${!om.sort ? " ▲" : ""}</th><th>상태</th>${d.keys.map(k => `<th data-sort="${esc(k)}" title="${esc(k)}${(d.meta[k] || {}).description ? " — " + esc(d.meta[k].description) : ""}">${esc(label(k, d.meta[k]))}${om.sort === k ? (om.desc ? " ▼" : " ▲") : ""}</th>`).join("")}<th>수집</th></tr></thead><tbody>
        ${d.items.map(r => `<tr data-name="${esc(r.name)}" class="${om.sel === r.name ? "sel" : ""}"><td><b>${esc(r.name)}</b>${cs.length > 1 ? `<div class="small muted">${esc(r.connector)}</div>` : ""}</td>
          <td class="small">${esc(r.health || r.status || "")}</td>${d.keys.map(k => `<td>${cell(r.values[k], k, d.meta[k])}</td>`).join("")}<td class="small nowrap">${ago(r.ts)}</td></tr>`).join("")}</tbody></table></div>
        ${d.total > d.items.length ? `<p class="small muted">${d.items.length.toLocaleString()} / ${d.total.toLocaleString()}개 표시 — 검색하거나 CSV 로 내려받으세요.</p>` : ""}`
        : `<p class="muted small">${om.q ? "검색 결과가 없습니다." : ki.n ? "값이 아직 없습니다." : "이 종류의 개체가 아직 수집되지 않았습니다 — '지금 수집'을 누르거나 다음 주기를 기다리세요."}</p>`}
      <p class="small muted">VCF Operations Suite API 로 읽기 전용 수집: 개체 목록 <code>GET /suite-api/api/resources?resourceKind=…</code> → 최신 값 <code>POST /suite-api/api/resources/stats/latest/query</code>(최대 1,000개씩) · 지표 이름·단위 <code>…/resourcekinds/{kind}/statkeys</code>. 값은 VCF Ops 원래 단위 그대로입니다(KB 는 MB/GB 로 표시만 변환). 추세는 ${s.history_kinds.map(k => (KINDS.find(x => x[0] === k) || [k, k])[1]).join("·")} ${s.retention_days}일 보관 — 행을 누르면 봅니다. 같은 이름의 호스트·VM 지표는 AI 질의 근거와 인벤토리 상세에도 들어갑니다.</p>
      <aside class="mv-tl" id="om-side" ${om.sel ? "" : "hidden"}></aside>`;
    if (om.sel) side(om.sel);
  }
  async function side(name) {
    const el = $("#om-side"); if (!el) return;
    const d = om.data, row = d.items.find(r => r.name === name); if (!row) { el.hidden = true; return; }
    el.hidden = false;
    const hist = (om.sum.history_kinds || []).includes(om.kind);
    el.innerHTML = `<div class="mv-tl-h"><b>${esc(name)}</b><span class="small muted">${esc((KINDS.find(x => x[0] === om.kind) || [0, om.kind])[1])} · ${esc(row.connector)}</span><span class="gap"></span>
        <a href="#inv/${om.kind === "VirtualMachine" ? "vm" : om.kind === "HostSystem" ? "host" : om.kind === "Datastore" ? "datastore" : "cluster"}/${encodeURIComponent(name)}" class="btn-sm" data-close-om>인벤토리</a><button class="x" data-omx>✕</button></div>
      ${d.keys.map(k => `<div class="om-kv"><div><b>${esc(label(k, d.meta[k]))}</b> <code class="small">${esc(k)}</code></div><div>${cell(row.values[k], k, d.meta[k])}</div>
        ${hist ? `<div class="om-spark" data-key="${esc(k)}"><span class="small muted">추세 불러오는 중…</span></div>` : ""}</div>`).join("")}
      ${hist ? "" : `<p class="small muted">VM 은 개체 수가 많아 최신 값만 보관합니다(추세는 호스트·클러스터·데이터스토어).</p>`}`;
    if (!hist) return;
    for (const box of $$(".om-spark", el)) {
      const k = box.dataset.key;
      try {
        const s = await A.api("GET", `/api/opsmetrics/series?kind=${om.kind}&name=${encodeURIComponent(name)}&key=${encodeURIComponent(k)}&hours=24`, undefined, {background: true});
        box.innerHTML = spark(s.points, k, d.meta[k]);
      } catch { box.innerHTML = `<span class="small muted">추세 없음</span>`; }
    }
  }
  function spark(pts, k, m) {
    if (!pts || pts.length < 2) return `<span class="small muted">추세 표본 부족(수집 주기마다 쌓임)</span>`;
    const W = 420, H = 56, xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    const x0 = Math.min(...xs), x1 = Math.max(...xs), lo = Math.min(...ys), hi = Math.max(...ys), sp = hi - lo || 1;
    const path = pts.map((p, i) => `${i ? "L" : "M"}${((p[0] - x0) / (x1 - x0 || 1) * W).toFixed(1)},${(H - 4 - (p[1] - lo) / sp * (H - 10)).toFixed(1)}`).join("");
    return `<svg viewBox="0 0 ${W} ${H}" class="om-svg" preserveAspectRatio="none"><path d="${path}" fill="none" stroke="#4f9fd0" stroke-width="1.6"/></svg>
      <div class="small muted">24시간 · 최저 ${fmt(lo, k, m)} · 최고 ${fmt(hi, k, m)} · ${pts.length}개 표본</div>`;
  }
  async function picker() {
    const cs = om.sum.connectors; if (!cs.length) return;
    const conn = om.conn || cs[0].connector;
    let cat;
    try { cat = await A.api("GET", `/api/opsmetrics/catalog?connector=${encodeURIComponent(conn)}&kind=${om.kind}`); }
    catch (e) { A.fail("카탈로그 조회 실패", e); return; }
    const sel = new Set(cat.selected);
    const kl = (KINDS.find(x => x[0] === om.kind) || [0, om.kind])[1];
    const list = q => cat.items.filter(x => !q || (x.key + " " + x.name).toLowerCase().includes(q.toLowerCase())).slice(0, 400)
      .map(x => `<label class="om-pk"><input type="checkbox" value="${esc(x.key)}" ${sel.has(x.key) ? "checked" : ""}> <b>${esc(x.name)}</b> <code>${esc(x.key)}</code>${x.unit ? ` <small>${esc(x.unit)}</small>` : ""}${x.instanced ? ` <small class="muted">인스턴스</small>` : ""}</label>`).join("");
    const out = await A.modal({title: `메트릭 선택 — ${kl} (${conn})`, wide: true, ok: "저장",
      html: `<p class="small muted">VCF Operations 카탈로그 ${cat.total.toLocaleString()}개 중 수집할 지표를 고릅니다(최대 40). 저장하면 다음 수집부터 적용됩니다. 선택: <b id="om-pk-n">${sel.size}</b></p>
        <input id="om-pk-q" placeholder="키·이름 검색(예: cpu ready, latency, usedSpace)" style="width:100%;margin-bottom:6px"><div id="om-pk-list" class="om-pk-list">${list("")}</div>`,
      onOpen: m => {
        const lst = $("#om-pk-list", m), n = $("#om-pk-n", m);
        $("#om-pk-q", m).addEventListener("input", e => { lst.innerHTML = list(e.target.value.trim()); });
        lst.addEventListener("change", e => { const c = e.target; if (c.type !== "checkbox") return; c.checked ? sel.add(c.value) : sel.delete(c.value);
          if (sel.size > 40) { sel.delete(c.value); c.checked = false; A.toast("최대 40개", "", "warn"); } n.textContent = sel.size; });
      }});
    if (!out) return;
    try {
      const r = await A.api("PUT", "/api/opsmetrics/keys", {connector: conn, kind: om.kind, keys: [...sel]});
      A.toast("메트릭 선택 저장", `${kl}: ${r.keys.length}개 — '지금 수집'으로 바로 확인할 수 있습니다.`, "ok");
      load();
    } catch (e) { A.fail("저장 실패", e); }
  }
  async function collect() {
    const cs = om.sum && om.sum.connectors || []; if (!cs.length) return;
    const b = $("#om-collect"); b.disabled = true; b.textContent = "수집 중…";
    try {
      for (const c of cs.filter(c => !om.conn || c.connector === om.conn)) {
        const r = await A.api("POST", "/api/opsmetrics/collect", {connector: c.connector});
        r.ok ? A.toast(`${c.connector} 수집 완료`, Object.entries(r.kinds).map(([k, v]) => `${k} ${v.objects}개(값 ${v.with_data})`).join(" · ") + ` · ${(r.took_ms / 1000).toFixed(1)}초`, "ok")
             : A.fail(`${c.connector} 일부 실패`, r.error);
      }
    } catch (e) { A.fail("수집 실패", e); }
    b.disabled = false; b.textContent = "지금 수집"; load();
  }
  const dl = fmt_ => { const a = document.createElement("a"); a.href = `/api/opsmetrics/export?kind=${om.kind}&fmt=${fmt_}&connector=${encodeURIComponent(om.conn)}&q=${encodeURIComponent(om.q)}`; a.download = ""; document.body.append(a); a.click(); a.remove(); };

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-om")) return;
    const b = $("#om-body");
    b.addEventListener("click", e => {
      const k = e.target.closest("[data-kind]"); if (k) { om.kind = k.dataset.kind; om.sort = ""; om.sel = null; load(); return; }
      const s = e.target.closest("th[data-sort]"); if (s) { const v = s.dataset.sort; if (om.sort === v) om.desc = !om.desc; else { om.sort = v; om.desc = true; } load(); return; }
      if (e.target.closest("[data-omx]")) { om.sel = null; $("#om-side").hidden = true; $$(".om-t tr.sel").forEach(x => x.classList.remove("sel")); return; }
      if (e.target.closest("[data-close-om]")) { $("#drawer-om").hidden = true; return; }
      const r = e.target.closest("tr[data-name]"); if (r) { om.sel = r.dataset.name; $$(".om-t tr.sel").forEach(x => x.classList.remove("sel")); r.classList.add("sel"); side(om.sel); }
    });
    b.addEventListener("change", e => { if (e.target.id === "om-conn") { om.conn = e.target.value; load(); } });
    let qt; b.addEventListener("input", e => { if (e.target.id !== "om-q") return; clearTimeout(qt); qt = setTimeout(() => { om.q = e.target.value; load().then(() => { const i = $("#om-q"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 350); });
    $("#om-reload").onclick = load; $("#om-csv").onclick = () => dl("csv"); $("#om-json").onclick = () => dl("json");
    const pk = $("#om-pick"); if (pk) pk.onclick = picker;
    const co = $("#om-collect"); if (co) co.onclick = collect;
    $("#nav-om").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-om") d.hidden = true; });
      $("#drawer-om").hidden = false; load();
      clearInterval(om.timer); om.timer = setInterval(() => $("#drawer-om").hidden ? clearInterval(om.timer) : (document.activeElement && document.activeElement.id === "om-q") || om.sel ? null : load(), 60000);
    };
    window.AIOPS_OPS_METRICS = async name => (await A.api("GET", `/api/opsmetrics/entity?name=${encodeURIComponent(name)}`, undefined, {background: true})).items;
  });
})();
