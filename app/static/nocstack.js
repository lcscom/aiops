/* 물리·논리 토폴로지(관제 월 /noc/topology) — 패브릭 → 섀시 → 서버 → ESXi → VDS → Edge·SE·VM(이름) → Pod → Edge 클러스터·SE 그룹 → T0·VS → T1·세그먼트
   GET /api/topology/stack(30초). 노드를 누르면 위(물리)·아래(서비스) 방향 경로 전체를 강조하고 상세를 보여 준다. 끌기 = 이동, 휠 = 확대
   흐름도 탭: GET /api/topology/flow?vs=|vm= — 클라이언트 → VIP → SE → 풀 → 멤버(VM·Pod) → 세그먼트 → 게이트웨이 → ESXi → 물리 서버 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const TAG = {fi: "FI", chassis: "CH", blade: "BL", rack: "RK", server: "SRV", esxi: "ESX", vds: "VDS", vmgroup: "VM+", vm: "VM", edge: "EDGE", se: "SE",
               "edge-cluster": "EC", "se-group": "SEG", t0: "T0", t1: "T1", vs: "VS", "nsx-manager": "NSX", pod: "POD", podgroup: "POD+", "k8s-node": "NODE",
               segment: "SEG", portgroup: "PG", client: "CLI", pool: "POOL", ip: "IP"};
  const KIND_KO = {fi: "패브릭 인터커넥트", chassis: "섀시", blade: "블레이드", rack: "랙 서버(UCSM)", server: "물리 서버(BMC)", esxi: "ESXi 호스트", vds: "Distributed Switch",
                   vmgroup: "VM", edge: "NSX Edge", se: "Avi Service Engine", "edge-cluster": "Edge 클러스터", "se-group": "SE 그룹", t0: "Tier-0 게이트웨이",
                   t1: "Tier-1 게이트웨이", vs: "가상 서비스(VIP)", "nsx-manager": "NSX Manager", vm: "가상 머신", pod: "Pod(VKS)", podgroup: "Pod 묶음",
                   "k8s-node": "Kubernetes 노드", segment: "NSX 세그먼트", portgroup: "포트그룹", client: "클라이언트", pool: "Avi 풀", ip: "풀 멤버(미식별 IP)"};
  const COL = {ok: "#56b62b", warn: "#f2c200", down: "#ff5a4f", maint: "#7f8fa6", unknown: "#56707c"};
  const ST_KO = {ok: "정상", warn: "주의", down: "장애", maint: "유지보수", unknown: "미확인"};
  const S = {d: null, cluster: "", q: "", sel: null, view: {x: 0, y: 0, k: 1}, drag: null, pos: {}, timer: null,
             mode: "stack", vmLimit: 60, podLimit: 25, flowVs: "", flowVm: "", f: null};
  { const fp = new URLSearchParams(location.search).get("flow"); if (fp) { S.mode = "flow"; S.flowVs = fp; } }
  try { const o = JSON.parse(localStorage.getItem("noc.stackOpt") || "{}"); if (o.vmLimit != null) S.vmLimit = o.vmLimit; if (o.podLimit != null) S.podLimit = o.podLimit; } catch { /* 저장소 없음 */ }
  const saveOpt = () => { try { localStorage.setItem("noc.stackOpt", JSON.stringify({vmLimit: S.vmLimit, podLimit: S.podLimit})); } catch { /* 무시 */ } };

  async function load() {
    if (S.mode === "flow") return loadFlow();
    const qs = `vm_limit=${S.vmLimit < 0 ? 25 : S.vmLimit}&pod_limit=${S.podLimit < 0 ? 25 : S.podLimit}&vms=${S.vmLimit !== -1}&pods=${S.podLimit !== -1}`;
    try { S.d = await A.api("GET", `/api/topology/stack?${qs}`, undefined, {background: true}); }
    catch (e) { $("#pg-topology").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    render();
    const q = S.want || new URLSearchParams(location.search).get("q");          // /noc/topology?q=<이름> 또는 select(이름)
    if (q && !S.wantDone) { S.wantDone = true; S.want = null; pick(q); }
  }
  function pick(q) {
    q = String(q).trim().toLowerCase(); if (!q || !S.d) return false;
    const n = S.d.nodes.find(x => x.label.toLowerCase() === q) || S.d.nodes.find(x => x.label.toLowerCase().split(".")[0] === q.split(".")[0]) || S.d.nodes.find(x => x.label.toLowerCase().includes(q));
    if (!n) return false;
    if (S.cluster) { S.cluster = ""; const c = $("#stk-cl"); if (c) c.value = ""; }
    S.sel = n.id; render(); focusNode(n.id); return true;
  }
  function visibleSet() {
    const d = S.d; if (!S.cluster) return null;
    const out = new Map(d.links.map(l => [l.s, []])), inn = new Map();
    d.links.forEach(l => { (out.get(l.s) || out.set(l.s, []).get(l.s)).push(l.t); (inn.get(l.t) || inn.set(l.t, []).get(l.t)).push(l.s); });
    const seeds = d.nodes.filter(n => n.layer === 3 && n.group === S.cluster).map(n => n.id);
    const keep = new Set(seeds);
    const walk = (start, m) => { const st = [...start]; while (st.length) { const x = st.pop(); for (const y of m.get(x) || []) if (!keep.has(y)) { keep.add(y); st.push(y); } } };
    walk(seeds, out); walk(seeds, inn);
    return keep;
  }
  function layout(nodes, links, W) {
    const layers = [...new Set(nodes.map(n => n.layer))].sort((a, b) => a - b);
    const colW = Math.max(210, (W - 40) / Math.max(1, layers.length));
    const cols = layers.map(l => nodes.filter(n => n.layer === l).sort((a, b) => (a.group || "").localeCompare(b.group || "") || a.label.localeCompare(b.label)));
    const idx = {}; const nb = {};
    links.forEach(l => { (nb[l.s] = nb[l.s] || []).push(l.t); (nb[l.t] = nb[l.t] || []).push(l.s); });
    const setIdx = () => cols.forEach(c => c.forEach((n, i) => { idx[n.id] = i / Math.max(1, c.length - 1 || 1); }));
    setIdx();
    for (let it = 0; it < 6; it++) {                    // 이웃 평균 위치(barycenter)로 정렬 — 교차 줄이기
      const order = it % 2 === 0 ? cols : [...cols].reverse();
      for (const c of order) {
        c.forEach(n => { const ns = (nb[n.id] || []).filter(x => idx[x] != null); n._b = ns.length ? ns.reduce((a, x) => a + idx[x], 0) / ns.length : idx[n.id]; });
        c.sort((a, b) => a._b - b._b); c.forEach((n, i) => { idx[n.id] = i / Math.max(1, c.length - 1); });
      }
    }
    const H = 30, G = 8, top = 46, maxN = Math.max(...cols.map(c => c.length), 1), totalH = top + maxN * (H + G) + 20;
    const pos = {};
    cols.forEach((c, ci) => { const off = (maxN - c.length) * (H + G) / 2;
      c.forEach((n, i) => { pos[n.id] = {x: 20 + ci * colW, y: top + off + i * (H + G), w: colW - 56, h: H}; }); });
    return {pos, layers, colW, totalH, width: 20 + layers.length * colW};
  }
  function chain(id) {
    const d = S.d, up = new Set([id]), down = new Set([id]);
    const L = Object.fromEntries(d.nodes.map(n => [n.id, n.layer]));
    let ch = true;
    while (ch) { ch = false;
      for (const l of d.links) {
        if (down.has(l.s) && !down.has(l.t) && L[l.t] >= L[l.s]) { down.add(l.t); ch = true; }
        if (up.has(l.t) && !up.has(l.s) && L[l.s] <= L[l.t]) { up.add(l.s); ch = true; }
      }
    }
    return new Set([...up, ...down]);
  }
  function render() {
    const d = S.d, box = $("#pg-topology");
    if (!d.nodes.length) { box.innerHTML = `<div class="wempty">표시할 구성요소가 없습니다. vCenter·NSX·Avi·UCS Manager·서버 BMC 커넥터를 추가하세요.</div>`; return; }
    const keep = visibleSet();
    const nodes = d.nodes.filter(n => !keep || keep.has(n.id));
    const ids = new Set(nodes.map(n => n.id));
    const links = d.links.filter(l => ids.has(l.s) && ids.has(l.t));
    if (!$(".stk-wrap", box)) {
      box.innerHTML = `<div class="stk-wrap"><div class="stk-bar">${modeTabs()}<select id="stk-cl"><option value="">전체 클러스터</option></select>
          <label class="stk-opt">VM <select id="stk-vml">${[[-1, "묶음만"], [20, "호스트당 20"], [60, "호스트당 60"], [200, "호스트당 200"], [0, "전부"]].map(([v, l]) => `<option value="${v}" ${S.vmLimit === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
          <label class="stk-opt">Pod <select id="stk-pdl">${[[-1, "문제만"], [10, "노드당 10"], [25, "노드당 25"], [100, "노드당 100"], [0, "전부"]].map(([v, l]) => `<option value="${v}" ${S.podLimit === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
          <input id="stk-q" placeholder="이름 검색(호스트·VM·Pod·Edge·SE·VS·세그먼트) — Enter" autocomplete="off"><button id="stk-clear">경로 해제</button><button id="stk-fit">화면 맞춤</button>
          <span class="stk-cnt" id="stk-cnt"></span><span class="gap"></span><span class="stk-leg">${Object.entries(ST_KO).map(([k, l]) => `<i style="background:${COL[k]}"></i>${l}`).join("")}</span>
          <button id="stk-um" hidden></button></div>
        <div class="stk-canvas" id="stk-cv"><svg id="stk-svg"><g id="stk-g"></g></svg></div><aside class="stk-side" id="stk-side" hidden></aside></div>`;
      wire();
    }
    const cl = $("#stk-cl"); if (cl.options.length !== d.clusters.length + 1) cl.innerHTML = `<option value="">전체 클러스터</option>` + d.clusters.map(c => `<option ${c === S.cluster ? "selected" : ""}>${esc(c)}</option>`).join("");
    const c = d.counts;
    const T = d.totals || {};
    $("#stk-cnt").textContent = `서버 ${c.blade + c.rack + c.server} · ESXi ${c.esxi} · VM ${c.vm || 0}/${T.vms ?? "-"} · Pod ${c.pod || 0}/${T.pods ?? "-"} · Edge ${c.edge} · SE ${c.se} · VS ${c.vs} · T0 ${c.t0} · T1 ${c.t1} · 네트워크 ${(c.segment || 0) + (c.portgroup || 0)}`;
    $("#w-sub").textContent = `노드 ${nodes.length} · 연결 ${links.length}`;
    const um = $("#stk-um"); um.hidden = !d.unmatched.length; um.textContent = `ESXi 미연결 서버 ${d.unmatched.length}`;
    const W = $("#stk-cv").clientWidth || 1600;
    const L = layout(nodes, links, W); S.pos = L.pos; S.L = L;
    const hl = S.sel && ids.has(S.sel) ? chain(S.sel) : null;
    const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
    const hdr = L.layers.map((l, i) => `<text class="stk-lh" x="${20 + i * L.colW}" y="22">${esc(d.layers[l])} <tspan>${nodes.filter(n => n.layer === l).length}</tspan></text>
      <line x1="${20 + i * L.colW - 14}" x2="${20 + i * L.colW - 14}" y1="8" y2="${L.totalH}" class="stk-sep"/>`).join("");
    const paths = links.map(l => { const a = L.pos[l.s], b = L.pos[l.t]; const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2, dx = Math.max(30, (x2 - x1) / 2);
      const on = hl && hl.has(l.s) && hl.has(l.t), bad = byId[l.t].state === "down" || byId[l.s].state === "down";
      return `<path d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}" class="stk-l ${on ? "on" : hl ? "dim" : ""} ${bad ? "bad" : ""}"><title>${esc(byId[l.s].label)} → ${esc(byId[l.t].label)}${l.k ? " (" + esc(l.k) + ")" : ""}</title></path>`; }).join("");
    const rects = nodes.map(n => { const p = L.pos[n.id], col = COL[n.state] || COL.unknown, on = !hl || hl.has(n.id);
      const lab = n.label.length > 30 ? n.label.slice(0, 29) + "…" : n.label;
      return `<g class="stk-n ${on ? "" : "dim"} ${n.id === S.sel ? "sel" : ""} st-${n.state}" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})">
        <rect width="${p.w}" height="${p.h}" rx="4"/><rect width="5" height="${p.h}" rx="2" fill="${col}"/>
        <text class="tg" x="12" y="19">${TAG[n.kind] || ""}</text><text class="lb" x="${["edge", "esxi", "vmgroup", "k8s-node", "podgroup"].includes(n.kind) ? 52 : 46}" y="19">${esc(lab)}</text>
        ${n.alert ? `<circle cx="${p.w - 10}" cy="${p.h / 2}" r="5" fill="${n.alert >= 4 ? COL.down : COL.warn}"><animate attributeName="r" values="4;7;4" dur="1.4s" repeatCount="indefinite"/></circle>` : ""}
        <title>${esc(KIND_KO[n.kind] || n.kind)} · ${esc(n.label)} — ${ST_KO[n.state] || n.state}${n.sub ? "\n" + esc(n.sub) : ""}</title></g>`; }).join("");
    const svg = $("#stk-svg"); svg.setAttribute("viewBox", `0 0 ${Math.max(L.width, W)} ${L.totalH}`); svg.style.height = `${Math.max(L.totalH * (Math.max(L.width, W) > W ? W / Math.max(L.width, W) : 1), 300)}px`;
    $("#stk-g").innerHTML = hdr + paths + rects;
    applyView();
    side(byId, hl);
  }
  function side(byId, hl) {
    const p = $("#stk-side"); if (!S.sel || !byId[S.sel]) { p.hidden = true; return; }
    const n = byId[S.sel]; p.hidden = false;
    const kv = (k, v) => v === undefined || v === null || v === "" ? "" : `<dt>${k}</dt><dd>${esc(String(v))}</dd>`;
    const per = {};
    [...hl].filter(x => x !== n.id && byId[x]).forEach(x => { const m = byId[x]; (per[m.layer] = per[m.layer] || []).push(m); });
    p.innerHTML = `<div class="stk-sh"><b>${esc(n.label)}</b><button class="x" id="stk-sx">✕</button></div>
      <div class="stk-st" style="--sc:${COL[n.state]}">${esc(KIND_KO[n.kind] || n.kind)} · ${ST_KO[n.state] || n.state}${n.match ? ` · ESXi 연결 근거: ${esc(n.match)}` : ""}</div>
      <dl>${kv("설명", n.sub)}${kv("그룹", n.group)}${kv("CPU", n.cpu != null ? n.cpu + "%" : "")}${kv("메모리", n.mem != null ? n.mem + "%" : "")}${kv("VM", n.vms)}${kv("S/N", n.serial)}${kv("UUID", n.uuid)}
        ${kv("ESXi", n.esx)}${kv("vSAN", n.vsan)}${kv("ESXi 호스트", n.host)}${kv("전원", n.power)}${kv("IP", (n.ips || []).join(", ") || n.ip)}${kv("게스트 OS", n.os)}
        ${kv("vCPU·메모리", n.vcpu != null ? `${n.vcpu} vCPU · ${n.mem_gb} GB` : "")}${kv("폴더", n.folder)}${kv("태그", (n.tags || []).join(", "))}${kv("네트워크", (n.networks || []).join(", "))}
        ${kv("데이터스토어", (n.datastores || []).join(", "))}${kv("Kubernetes", n.k8s_cluster)}${kv("네임스페이스", n.ns)}${kv("노드", n.node_name)}
        ${kv("출처", n.source)}${kv("BMC 상태", n.bmc_state)}${kv("BMC 오류", n.bmc_error)}</dl>
      ${(n.pnics || []).length ? `<h5>물리 NIC</h5><table class="stk-t">${n.pnics.map(x => `<tr><td>${esc(x.name)}</td><td class="mono">${esc(x.mac)}</td><td>${x.speed ? (x.speed >= 1000 ? x.speed / 1000 + "G" : x.speed + "M") : '<b style="color:#ff5a4f">down</b>'}</td></tr>`).join("")}</table>` : ""}
      ${(n.switches || []).length ? `<h5>가상 스위치</h5><table class="stk-t">${n.switches.map(x => `<tr><td>${x.kind === "vds" ? "VDS" : "vSS"}</td><td>${esc(x.name)}</td><td>${esc((x.uplinks || []).join(", "))}</td></tr>`).join("")}</table>` : ""}
      ${n.detail ? `<h5>연결 상태</h5><dl>${Object.entries(n.detail).map(([k, v]) => kv(k.replace("_status", ""), v)).join("")}</dl>` : ""}
      ${["vm", "vs"].includes(n.kind) ? `<p><button class="stk-fl" data-flow-${n.kind}="${esc(n.kind === "vs" ? (n.id.split(":").slice(2).join(":")) : n.label)}">이 ${n.kind === "vs" ? "VIP" : "VM"} 흐름도 보기</button></p>` : ""}
      <h5>연결된 경로 <small>물리 → 서비스</small></h5>${Object.keys(per).sort((a, b) => a - b).map(l => `<div class="stk-pl"><span>${esc(S.d.layers[l])}</span>${per[l].slice(0, 30).map(m => `<button data-go="${esc(m.id)}" style="--sc:${COL[m.state]}">${esc(m.label)}</button>`).join("")}${per[l].length > 30 ? ` <small>외 ${per[l].length - 30}</small>` : ""}</div>`).join("") || `<p class="muted">연결 없음</p>`}`;
  }
  function applyView() { const v = S.view; const g = $("#stk-g"); if (g) g.setAttribute("transform", `translate(${v.x},${v.y}) scale(${v.k})`); }
  function focusNode(id) {
    const p = S.pos[id]; if (!p) return;
    const cv = $("#stk-cv"), svg = $("#stk-svg"), vb = svg.viewBox.baseVal, sc = cv.clientWidth / vb.width;
    S.view.k = Math.max(S.view.k, 1); S.view.x = (cv.clientWidth / 2) / sc - (p.x + p.w / 2) * S.view.k; S.view.y = Math.min(0, 140 / sc - p.y * S.view.k);
    applyView();
  }
  function wire() {
    const cv = $("#stk-cv");
    cv.addEventListener("click", e => {
      if (S.moved) { S.moved = false; e.stopPropagation(); return; }
      if (S.mode === "flow") return;
      const g = e.target.closest(".stk-n"); S.sel = g ? (S.sel === g.dataset.id ? null : g.dataset.id) : null; render();
    });
    cv.addEventListener("pointerdown", e => { if (e.button !== 0) return; S.drag = {x: e.clientX, y: e.clientY, vx: S.view.x, vy: S.view.y}; S.moved = false; });
    if (S.gwired) { wireBox(); return; }
    S.gwired = true;
    addEventListener("pointermove", e => { if (!S.drag) return; const svg = $("#stk-svg"), sc = svg.clientWidth / svg.viewBox.baseVal.width;
      const dx = (e.clientX - S.drag.x) / sc, dy = (e.clientY - S.drag.y) / sc; if (Math.abs(dx) + Math.abs(dy) > 4) S.moved = true;
      S.view.x = S.drag.vx + dx; S.view.y = S.drag.vy + dy; applyView(); });
    addEventListener("pointerup", () => { S.drag = null; });
    wireBox();
  }
  function wireBox() {
    const cv = $("#stk-cv");
    cv.addEventListener("wheel", e => { e.preventDefault(); const svg = $("#stk-svg"), r = svg.getBoundingClientRect(), sc = svg.clientWidth / svg.viewBox.baseVal.width;
      const mx = (e.clientX - r.left) / sc, my = (e.clientY - r.top) / sc, k0 = S.view.k, k1 = Math.min(3, Math.max(0.3, k0 * (e.deltaY < 0 ? 1.12 : 0.89)));
      S.view.x = mx - (mx - S.view.x) * (k1 / k0); S.view.y = my - (my - S.view.y) * (k1 / k0); S.view.k = k1; applyView(); }, {passive: false});
    const box = $("#pg-topology");
    if (box._stkWired) return;
    box._stkWired = true;
    box.addEventListener("change", e => {
      if (e.target.id === "stk-cl") { S.cluster = e.target.value; S.sel = null; S.view = {x: 0, y: 0, k: 1}; render(); }
      if (e.target.id === "stk-vml") { S.vmLimit = Number(e.target.value); saveOpt(); load(); }
      if (e.target.id === "stk-pdl") { S.podLimit = Number(e.target.value); saveOpt(); load(); }
      if (e.target.id === "fl-vs") { S.flowVs = e.target.value; S.flowVm = ""; loadFlow(); }
    });
    box.addEventListener("keydown", e => { if (e.target.id === "fl-vm" && e.key === "Enter") { S.flowVm = e.target.value.trim(); S.flowVs = ""; loadFlow(); return; }
      if (e.target.id === "stk-q" && e.key === "Enter") {
      const q = e.target.value.trim().toLowerCase(); if (!q) return;
      const n = S.d.nodes.find(x => x.label.toLowerCase() === q) || S.d.nodes.find(x => x.label.toLowerCase().includes(q));
      if (!n) { A.toast("찾을 수 없음", q, "info", 2500); return; }
      if (S.cluster && !(visibleSet() || new Set()).has(n.id)) { S.cluster = ""; $("#stk-cl").value = ""; }
      S.sel = n.id; render(); focusNode(n.id); } });
    box.addEventListener("click", e => {
      const md = e.target.closest("[data-smode]"); if (md) { setMode(md.dataset.smode); return; }
      const fv = e.target.closest("[data-flow-vs]"), fm = e.target.closest("[data-flow-vm]");
      if (fv || fm) { S.flowVs = fv ? fv.dataset.flowVs : ""; S.flowVm = fm ? fm.dataset.flowVm : ""; setMode("flow"); return; }
      if (e.target.id === "fl-eu") { endUsers(); return; }
      if (S.mode === "flow") { if (e.target.id === "stk-sx") { S.fsel = null; renderFlow(); return; } if (e.target.id === "stk-fit") { S.view = {x: 0, y: 0, k: 1}; applyView(); return; }
        const g = e.target.closest(".fl-n"); if (g) { S.fsel = S.fsel === g.dataset.id ? null : g.dataset.id; renderFlow(); } return; }
      if (e.target.id === "stk-clear") { S.sel = null; render(); }
      if (e.target.id === "stk-fit") { S.view = {x: 0, y: 0, k: 1}; applyView(); }
      if (e.target.id === "stk-sx") { S.sel = null; render(); }
      const go = e.target.closest("[data-go]"); if (go) { S.sel = go.dataset.go; render(); focusNode(S.sel); }
      if (e.target.id === "stk-um") A.modal({title: "ESXi 호스트와 연결되지 않은 서버", ok: "", cancel: "닫기",
        html: `<p class="modal-text">UUID·S/N·이름으로 vCenter 호스트를 찾지 못했습니다. 서버 커넥터의 'ESXi 호스트 이름(esxi_host)'을 지정하거나 vCenter 인벤토리 갱신(5분)을 기다리세요.</p>
          <table class="stk-t">${S.d.unmatched.map(u => `<tr><td>${esc(u.server)}</td><td>${esc(u.source)}</td><td class="mono">${esc(u.serial || "")}</td><td class="mono">${esc(u.uuid || "")}</td><td>${esc(u.state || "")}</td></tr>`).join("")}</table>`});
    });
  }
  // ---------------------------------------------------------------- 흐름도
  function modeTabs() { return `<span class="stk-mode">${[["stack", "스택 토폴로지"], ["flow", "서비스 흐름도"]].map(([k, l]) => `<button data-smode="${k}" class="${S.mode === k ? "on" : ""}">${l}</button>`).join("")}</span>`; }
  function setMode(m) {
    S.mode = m; const box = $("#pg-topology"); box.innerHTML = ""; S.view = {x: 0, y: 0, k: 1};
    if (m === "flow") loadFlow(); else load();
  }
  async function loadFlow() {
    const box = $("#pg-topology");
    if (!$(".fl-wrap", box)) {
      box.innerHTML = `<div class="stk-wrap fl-wrap"><div class="stk-bar">${modeTabs()}<select id="fl-vs"><option value="">전체 가상 서비스(최대 30)</option></select>
          <input id="fl-vm" placeholder="VM 이름으로 흐름 보기 — Enter" autocomplete="off" value="${esc(S.flowVm)}"><button id="fl-eu" title="선택한 VIP 의 최근 60분 애플리케이션 로그로 상위 클라이언트를 펼침">End user 분석 반영</button>
          <span class="stk-cnt" id="fl-cnt"></span><span class="gap"></span><span class="stk-leg">${Object.entries(ST_KO).map(([k, l]) => `<i style="background:${COL[k]}"></i>${l}`).join("")}</span></div>
        <div class="stk-canvas" id="stk-cv"><svg id="stk-svg"><g id="stk-g"></g></svg></div><aside class="stk-side" id="stk-side" hidden></aside></div>`;
      wire();
    }
    try { S.f = await A.api("GET", `/api/topology/flow?vs=${encodeURIComponent(S.flowVs)}&vm=${encodeURIComponent(S.flowVm)}`, undefined, {background: true}); }
    catch (e) { $("#stk-g").innerHTML = ""; $("#fl-cnt").textContent = e.message; return; }
    const sel = $("#fl-vs");
    sel.innerHTML = `<option value="">전체 가상 서비스(최대 30)</option>` + S.f.vs_list.map(v => `<option value="${esc(v.uuid)}" ${v.uuid === S.flowVs || v.name === S.flowVs ? "selected" : ""}>${esc(v.name)} — ${esc((v.vips || []).join(", "))}</option>`).join("");
    renderFlow();
  }
  async function endUsers() {
    const u = S.flowVs || ((S.f && S.f.nodes.find(n => n.kind === "vs")) || {}).uuid;
    if (!u) { A.toast("VIP 를 먼저 선택하세요", "", "info", 2500); return; }
    try { const r = await A.api("GET", `/api/avi/vips/${encodeURIComponent(u)}/endusers?minutes=60`); if (r.note) A.toast("End user", r.note, "info", 6000); }
    catch (e) { A.toast("End user 분석 실패", e.message, "error", 5000); return; }
    S.flowVs = u; loadFlow();
  }
  function renderFlow() {
    const f = S.f; if (!f) return;
    if (!f.nodes.length) { $("#stk-g").innerHTML = `<text x="20" y="40" fill="#8aa">${esc(f.vs_list.length ? "선택한 대상의 흐름을 만들 데이터가 없습니다(풀 멤버 IP ↔ VM guest IP·Pod IP 를 찾지 못함)" : "NSX ALB(Avi) 커넥터의 가상 서비스가 없어 VIP 흐름이 없습니다 — VM 이름으로 조회해 보세요")}</text>`; $("#fl-cnt").textContent = ""; return; }
    const W = $("#stk-cv").clientWidth || 1600, cols = f.stages.map(s => s.key), colW = Math.max(200, (W - 40) / Math.max(1, cols.length));
    const byStage = {}; f.nodes.forEach(n => (byStage[n.stage] = byStage[n.stage] || []).push(n));
    const nb = {}; f.links.forEach(l => { (nb[l.s] = nb[l.s] || []).push(l.t); (nb[l.t] = nb[l.t] || []).push(l.s); });
    const idx = {}; cols.forEach(k => (byStage[k] || []).forEach((n, i) => { idx[n.id] = i; }));
    for (let it = 0; it < 4; it++) cols.forEach(k => { const c = byStage[k] || []; c.forEach(n => { const ns = (nb[n.id] || []).filter(x => idx[x] != null); n._b = ns.length ? ns.reduce((a, x) => a + idx[x], 0) / ns.length : idx[n.id]; }); c.sort((a, b) => a._b - b._b); c.forEach((n, i) => { idx[n.id] = i; }); });
    const H = 40, G = 12, top = 50, maxN = Math.max(...cols.map(k => (byStage[k] || []).length), 1), totalH = top + maxN * (H + G) + 20, pos = {};
    cols.forEach((k, ci) => { const c = byStage[k] || [], off = (maxN - c.length) * (H + G) / 2; c.forEach((n, i) => { pos[n.id] = {x: 20 + ci * colW, y: top + off + i * (H + G), w: colW - 60, h: H}; }); });
    const hl = S.fsel ? (() => { const s = new Set([S.fsel]); let ch = true; while (ch) { ch = false; f.links.forEach(l => { if (s.has(l.s) && !s.has(l.t) && cols.indexOf(f.nodes.find(n => n.id === l.t).stage) > cols.indexOf(f.nodes.find(n => n.id === l.s).stage)) { s.add(l.t); ch = true; } }); } ch = true;
      while (ch) { ch = false; f.links.forEach(l => { if (s.has(l.t) && !s.has(l.s) && cols.indexOf(f.nodes.find(n => n.id === l.s).stage) < cols.indexOf(f.nodes.find(n => n.id === l.t).stage)) { s.add(l.s); ch = true; } }); } return s; })() : null;
    const byId = Object.fromEntries(f.nodes.map(n => [n.id, n]));
    const maxW = Math.max(1, ...f.links.map(l => l.w || 0));
    const hdr = f.stages.map((s, i) => `<text class="stk-lh" x="${20 + i * colW}" y="24">${esc(s.title)} <tspan>${(byStage[s.key] || []).length}</tspan></text>`).join("");
    const paths = f.links.map(l => { const a = pos[l.s], b = pos[l.t]; if (!a || !b) return "";
      const back = b.x <= a.x, x1 = back ? a.x : a.x + a.w, y1 = a.y + a.h / 2, x2 = back ? b.x + b.w : b.x, y2 = b.y + b.h / 2, dx = Math.max(30, Math.abs(x2 - x1) / 2);
      const on = hl && hl.has(l.s) && hl.has(l.t), bad = byId[l.t].state === "down" || byId[l.s].state === "down", sw = l.w ? 1.4 + 4 * l.w / maxW : 1.4;
      return `<path d="M${x1},${y1} C${x1 + (back ? -dx : dx)},${y1} ${x2 + (back ? dx : -dx)},${y2} ${x2},${y2}" class="stk-l fl-l ${on ? "on" : hl ? "dim" : ""} ${bad ? "bad" : ""}" style="stroke-width:${sw}"><title>${esc(byId[l.s].label)} → ${esc(byId[l.t].label)}${l.k ? " (" + esc(l.k) + ")" : ""}${l.w ? " · " + l.w + "건" : ""}</title></path>`; }).join("");
    const fb = v => v == null ? "" : v >= 1e9 ? (v / 1e9).toFixed(1) + "Gb/s" : v >= 1e6 ? (v / 1e6).toFixed(1) + "Mb/s" : v >= 1e3 ? (v / 1e3).toFixed(0) + "kb/s" : Math.round(v) + "b/s";
    const rects = f.nodes.map(n => { const p = pos[n.id]; if (!p) return ""; const col = COL[n.state] || COL.unknown, on = !hl || hl.has(n.id);
      const mx = Math.max(12, Math.floor((p.w - 20) / 6.4)), lab = n.label.length > mx - 6 ? n.label.slice(0, mx - 7) + "…" : n.label, sub = n.kind === "vs" && n.bw != null ? `${fb(n.bw)} · ${Math.round(n.rps || 0)} req/s` : (n.sub || "");
      return `<g class="stk-n fl-n ${on ? "" : "dim"} ${n.id === S.fsel ? "sel" : ""}" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})"><rect width="${p.w}" height="${p.h}" rx="5"/><rect width="5" height="${p.h}" rx="2" fill="${col}"/>
        <text class="tg" x="12" y="17">${TAG[n.kind] || ""}</text><text class="lb" x="52" y="17">${esc(lab)}</text><text class="fs" x="12" y="33">${esc(sub.length > mx ? sub.slice(0, mx - 1) + "…" : sub)}</text>
        <title>${esc(KIND_KO[n.kind] || n.kind)} · ${esc(n.label)} — ${ST_KO[n.state] || n.state}${n.sub ? "\n" + esc(n.sub) : ""}</title></g>`; }).join("");
    const width = 20 + cols.length * colW, svg = $("#stk-svg");
    svg.setAttribute("viewBox", `0 0 ${Math.max(width, W)} ${totalH}`); svg.style.height = `${Math.max(totalH, 300)}px`;
    $("#stk-g").innerHTML = hdr + paths + rects; applyView();
    $("#fl-cnt").textContent = `${f.mode === "vm" ? "VM " + f.vm : f.mode === "vs" ? "VIP 1개" : "전체 VIP"} · 노드 ${f.nodes.length} · 연결 ${f.links.length}`;
    $("#w-sub").textContent = "서비스 흐름도";
    const sd = $("#stk-side"), n = S.fsel && byId[S.fsel];
    if (!n) { sd.hidden = true; return; }
    sd.hidden = false;
    sd.innerHTML = `<div class="stk-sh"><b>${esc(n.label)}</b><button class="x" id="stk-sx">✕</button></div><div class="stk-st" style="--sc:${COL[n.state]}">${esc(KIND_KO[n.kind] || n.kind)} · ${ST_KO[n.state] || n.state}</div>
      <dl><dt>설명</dt><dd>${esc(n.sub || "-")}</dd></dl>
      ${n.kind === "vm" ? `<p><button data-flow-vm="${esc(n.label)}">이 VM 기준 흐름</button> <button data-go-stack="${esc(n.label)}">스택에서 보기</button></p>` : ""}
      ${n.kind === "vs" ? `<p><button data-flow-vs="${esc(n.uuid)}">이 VIP 만 보기</button></p>` : ""}`;
  }
  document.addEventListener("click", e => { const g = e.target.closest("[data-go-stack]"); if (!g) return; const q = g.dataset.goStack; S.mode = "stack"; $("#pg-topology").innerHTML = ""; S.want = q; S.wantDone = false; load(); });
  window.NOCSTACK = {load, render: () => S.d && render(), select: q => { if (S.d) return pick(q); S.want = q; S.wantDone = false; return true; }};
})();
