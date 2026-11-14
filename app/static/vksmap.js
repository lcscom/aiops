/* VKS 구성도(2.9.0 → 2.10.0 상태·관측) — Kubernetes 아키텍처 다이어그램 관례(네임스페이스 묶음 · Ingress → Service → 워크로드 → Pod → PVC → PV → StorageClass)
   + VCF 확장(LoadBalancer VIP ↔ Avi VS, 노드 ↔ vSphere VM ↔ ESXi, Supervisor ↔ vSphere 네임스페이스 ↔ VKS 클러스터). 아이콘은 KIS 형태(파란 다각형+약어)를 직접 그림
   2.10.0: 개체마다 지금 상태(색·파드 점·문제 한 줄·경고 이벤트·최근 변경)와 영향 전파(하류 장애 → 상류 점선), 누르면 상태·이벤트·로그·변경 이력·연관 패널 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const NW = 196, NH = 52, RG = 12, CG = 60, PAD = 14, HEAD = 36;
  const KCOL = {VIP: 0, Ingress: 1, Service: 2, Deployment: 3, StatefulSet: 3, DaemonSet: 3, CronJob: 3, Job: 3, Pod: 3, PersistentVolumeClaim: 4};
  const COLN = ["외부 VIP", "Ingress", "Service", "워크로드", "PVC"];
  const SC = {ok: "#62a420", idle: "#9aa5ad", warn: "#e0a800", down: "#c21d00"};
  const SF = {ok: "#ffffff", idle: "#f4f6f8", warn: "#fff8e1", down: "#fdece9"};
  const SL = {ok: "정상", idle: "중지", warn: "주의", down: "장애"};
  const PD = {ok: "#62a420", warn: "#e0a800", down: "#c21d00", done: "#9aa5ad"};
  const EC = {route: "#7a5af8", select: "#326ce5", lb: "#e8730c", mount: "#8a9aa5", bind: "#5b8c5a", class: "#5b8c5a", owns: "#9aa5ad"};
  const EL = {route: "Ingress → Service", select: "Service 셀렉터", lb: "LoadBalancer VIP", mount: "볼륨 마운트", bind: "PVC ↔ PV", class: "StorageClass", owns: "포함"};
  const WL = new Set(["Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod"]);
  const st = {name: "", ns: "", system: false, q: "", g: null, sel: null, onlyBad: false, auto: true, timer: null, box: null, side: null};
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? "방금" : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };
  const tm = ts => ts ? new Date(ts * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "-";
  try { const v = localStorage.getItem("vk-auto"); if (v != null) st.auto = v === "1"; } catch { /* 저장소 없음 */ }

  const hex = (x, y, r, abbr, fill = "#326ce5") => {
    const pts = Array.from({length: 7}, (_, i) => { const a = -Math.PI / 2 + i * 2 * Math.PI / 7; return `${(x + r * Math.cos(a)).toFixed(1)},${(y + r * Math.sin(a)).toFixed(1)}`; }).join(" ");
    return `<polygon points="${pts}" fill="${fill}" stroke="#fff" stroke-width="1.2"/><text x="${x}" y="${y + 3}" text-anchor="middle" class="vk-ab" style="font-size:${abbr.length > 4 ? 6.4 : abbr.length > 3 ? 7.4 : 8.5}px">${esc(abbr)}</text>`;
  };
  const cut = (s, n) => (s = String(s || "")).length > n ? s.slice(0, n - 1) + "…" : s;
  const icoFill = k => k === "VIP" ? "#e8730c" : k === "StorageClass" || k === "PersistentVolume" ? "#5b8c5a" : "#326ce5";
  const firstIssue = n => (n.issues || []).find(i => i.sev === "error") || (n.issues || []).find(i => i.sev === "warn") || (n.issues || []).find(i => i.sev === "impact");

  const nodeSvg = (n, x, y, sel) => {
    const s = n.status || "ok", own = n.own || s;
    const sub = WL.has(n.kind)
      ? `${n.pods != null ? `파드 ${n.pods_ready ?? 0}/${n.pods}` : n.detail || ""}${n.want != null && n.kind !== "DaemonSet" ? ` · 목표 ${n.want}` : ""}${n.hpa ? " · HPA" : ""}`
      : (n.detail || "");
    const fi = firstIssue(n);
    let l3 = "";
    if (WL.has(n.kind) && (n.podlist || []).length) {
      const ps = n.podlist.slice(0, 14);
      l3 = ps.map((p, i) => `<rect x="${36 + i * 9}" y="38" width="7" height="7" rx="1.5" fill="${PD[p.st] || "#9aa5ad"}"><title>${esc(`${p.name} — ${p.reason || p.phase} ${p.ready}${p.restarts ? ` · 재시작 ${p.restarts}` : ""}`)}</title></rect>`).join("")
        + (n.podlist.length > 14 || (n.pods || 0) > 14 ? `<text x="${36 + 14 * 9 + 2}" y="45" class="vk-s">+${(n.pods || n.podlist.length) - 14}</text>` : "")
        + (fi ? `<text x="${36 + Math.min(ps.length, 14) * 9 + (n.pods > 14 ? 22 : 4)}" y="45" class="vk-i ${fi.sev}">${esc(cut(fi.text, 14))}</text>` : "");
    } else if (fi) l3 = `<text x="36" y="45" class="vk-i ${fi.sev}">${esc(cut(fi.text, 27))}</text>`;
    const tip = [`${n.kind} ${n.ns ? n.ns + "/" : ""}${n.name} — ${SL[s] || s}${n.impact ? " (하류 영향)" : ""}`, ...(n.issues || []).map(i => `· ${i.text}`), n.detail,
      n.hpa ? `HPA ${n.hpa}` : "", (n.images || []).length ? `이미지 ${n.images.join(", ")}` : "", n.events ? `경고 이벤트 ${n.events}건(1시간)` : "",
      n.recent ? `최근 변경 ${n.recent.n}건 — ${n.recent.detail || ""}` : "", "누르면 상태·이벤트·로그·변경 이력"].filter(Boolean).join("\n");
    let bx = NW - 8;
    const badge = (w, fill, txt, title) => { bx -= w; const g = `<g transform="translate(${bx},3)"><title>${esc(title)}</title><rect width="${w - 2}" height="13" rx="6.5" fill="${fill}"/><text x="${(w - 2) / 2}" y="9.6" text-anchor="middle" class="vk-bd">${esc(txt)}</text></g>`; return g; };
    const badges = [own === "down" ? badge(16, SC.down, "✕", "장애") : own === "warn" ? badge(16, SC.warn, "!", "주의") : "",
      n.events ? badge(10 + String(n.events).length * 6 + 8, "#e8730c", `⚡${n.events}`, `경고 이벤트 ${n.events}건(최근 1시간)`) : "",
      n.recent ? badge(10 + String(n.recent.n).length * 6 + 8, "#0072a3", `↻${n.recent.n}`, `최근 1시간 변경 ${n.recent.n}건 — ${n.recent.action}: ${n.recent.detail || ""}`) : ""].join("");
    return `<g class="vk-n${sel ? " sel" : ""}${n.impact ? " imp" : ""}" data-nid="${esc(n.id)}" transform="translate(${x},${y})"><title>${esc(tip)}</title>
      <rect width="${NW}" height="${NH}" rx="5" class="vk-box" style="stroke:${SC[s] || "#9aa5ad"};fill:${SF[own] || "#fff"}"/>
      ${hex(17, 20, 13, n.abbr || "", icoFill(n.kind))}
      <text x="36" y="15" class="vk-t">${esc(cut(n.name, n.events || n.recent ? 17 : 22))}</text><text x="36" y="29" class="vk-s">${esc(cut(sub, 28))}</text>${l3}${badges}</g>`;
  };

  // 네임스페이스별 열 배치 + 공용 스토리지(PV·StorageClass)
  function layout(g) {
    const byNs = {}, shared = {pv: [], sc: []};
    g.nodes.forEach(n => {
      if (n.kind === "PersistentVolume") shared.pv.push(n);
      else if (n.kind === "StorageClass") shared.sc.push(n);
      else (byNs[n.ns] = byNs[n.ns] || [[], [], [], [], []])[KCOL[n.kind] ?? 3].push(n);
    });
    const out = new Map(), boxes = [];
    const succ = {}, pred = {};
    g.edges.forEach(e => { (succ[e.from] = succ[e.from] || []).push(e.to); (pred[e.to] = pred[e.to] || []).push(e.from); });
    let y = 6;
    const nsW = 5 * NW + 4 * CG + 2 * PAD;
    const rank = n => ({down: 0, warn: 1}[n.status] ?? 2);
    Object.keys(byNs).sort((a, b) => {                              // 문제 있는 네임스페이스 먼저
      const ra = Math.min(...byNs[a].flat().map(rank)), rb = Math.min(...byNs[b].flat().map(rank));
      return ra - rb || a.localeCompare(b);
    }).forEach(ns => {
      const cols = byNs[ns];
      cols[3].sort((a, b) => rank(a) - rank(b) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
      const idx = id => { const p = out.get(id); return p ? p.y : 1e9; };
      const place = (ci, list) => list.forEach((n, i) => out.set(n.id, {x: PAD + ci * (NW + CG), y: y + HEAD + PAD + i * (NH + RG), n}));
      place(3, cols[3]);
      const order = (list, rel) => list.sort((a, b) => Math.min(...(rel[a.id] || []).map(idx), 1e9) - Math.min(...(rel[b.id] || []).map(idx), 1e9) || a.name.localeCompare(b.name));
      place(2, order(cols[2], succ)); place(4, order(cols[4], pred)); place(1, order(cols[1], succ)); place(0, order(cols[0], succ));
      const rows = Math.max(1, ...cols.map(c => c.length));
      const h = HEAD + 2 * PAD + rows * (NH + RG) - RG;
      const worst = Math.min(...cols.flat().map(rank));
      boxes.push({ns, y, h, worst, bad: cols.flat().filter(n => n.own === "down" || n.own === "warn").length});
      y += h + 14;
    });
    const sx = nsW + 50;
    const sorted = (list, rel) => list.sort((a, b) => Math.min(...(rel[a.id] || []).map(id => (out.get(id) || {y: 1e9}).y), 1e9) - Math.min(...(rel[b.id] || []).map(id => (out.get(id) || {y: 1e9}).y), 1e9));
    sorted(shared.pv, pred).forEach((n, i) => out.set(n.id, {x: sx, y: 6 + HEAD + PAD + i * (NH + RG), n}));
    sorted(shared.sc, pred).forEach((n, i) => out.set(n.id, {x: sx + NW + CG, y: 6 + HEAD + PAD + i * (NH + RG), n}));
    const sh = shared.pv.length || shared.sc.length ? HEAD + 2 * PAD + Math.max(shared.pv.length, shared.sc.length) * (NH + RG) : 0;
    return {pos: out, boxes, nsW, sx, sh, W: (sh ? sx + 2 * NW + CG + PAD + 10 : nsW + 10), H: Math.max(y, sh + 12) + 6};
  }
  function view(g) {                                                  // '문제 경로만' — 이상·영향 개체와 그 이웃
    if (!st.onlyBad) return g;
    const bad = new Set(g.nodes.filter(n => n.status === "warn" || n.status === "down").map(n => n.id));
    const keep = new Set(bad);
    g.edges.forEach(e => { if (bad.has(e.from) || bad.has(e.to)) { keep.add(e.from); keep.add(e.to); } });
    return {...g, nodes: g.nodes.filter(n => keep.has(n.id)), edges: g.edges.filter(e => keep.has(e.from) && keep.has(e.to))};
  }
  function svg(g) {
    const L = layout(g);
    const ed = g.edges.map(e => { const a = L.pos.get(e.from), b = L.pos.get(e.to); if (!a || !b) return "";
      const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, dx = Math.max(30, (x2 - x1) / 2);
      const hot = st.sel && (e.from === st.sel || e.to === st.sel), bad = e.st === "down" || e.st === "warn";
      const col = e.st === "down" ? SC.down : e.st === "warn" ? SC.warn : (EC[e.kind] || "#9aa5ad");
      return `<path d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}" class="vk-e${hot ? " hot" : ""}${bad ? " bad" : ""}" stroke="${col}" marker-end="url(#vk-ar)"><title>${esc((EL[e.kind] || e.kind) + (bad ? ` — 대상 ${SL[e.st]}` : ""))}</title></path>`; }).join("");
    const bx = L.boxes.map(b => `<g class="vk-ns${b.worst === 0 ? " down" : b.worst === 1 ? " warn" : ""}"><rect x="2" y="${b.y}" width="${L.nsW}" height="${b.h}" rx="8"/><text x="14" y="${b.y + 17}">namespace <tspan class="vk-nsn">${esc(b.ns)}</tspan>${b.bad ? ` <tspan class="vk-nsb">· 문제 ${b.bad}</tspan>` : ""}</text>
      ${COLN.map((c, i) => `<text x="${PAD + i * (NW + CG) + NW / 2}" y="${b.y + 31}" text-anchor="middle" class="vk-col">${c}</text>`).join("")}</g>`).join("");
    const sh = L.sh ? `<g class="vk-ns shared"><rect x="${L.sx - 12}" y="6" width="${2 * NW + CG + 24}" height="${L.sh}" rx="8"/><text x="${L.sx}" y="${6 + 31}" class="vk-col">PersistentVolume</text><text x="${L.sx + NW + CG}" y="${6 + 31}" class="vk-col">StorageClass(vSphere 스토리지 정책)</text></g>` : "";
    const ns = [...L.pos.values()].map(p => nodeSvg(p.n, p.x, p.y, st.sel === p.n.id)).join("");
    return `<svg xmlns="http://www.w3.org/2000/svg" class="vk-svg" width="${L.W}" height="${L.H}" viewBox="0 0 ${L.W} ${L.H}">
      <defs><marker id="vk-ar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0L8,4L0,8z" fill="#8a9aa5"/></marker>
      <style>.vk-box{stroke-width:1.6}.vk-t{font:600 11.5px sans-serif;fill:#1b2a35}.vk-s{font:10.5px sans-serif;fill:#5a6b78}.vk-ab{font:700 8.5px sans-serif;fill:#fff}
      .vk-i{font:600 10px sans-serif}.vk-i.error{fill:#c21d00}.vk-i.warn{fill:#a07000}.vk-i.impact{fill:#c21d00;font-style:italic}.vk-i.info{fill:#5a6b78}.vk-bd{font:700 8.5px sans-serif;fill:#fff}
      .vk-ns rect{fill:rgba(50,108,229,.04);stroke:#b8c9e6;stroke-dasharray:5 4}.vk-ns.warn rect{stroke:#e0c060}.vk-ns.down rect{stroke:#e39a8c;fill:rgba(194,29,0,.03)}
      .vk-ns.shared rect{fill:rgba(91,140,90,.05);stroke:#b9d3b8}.vk-ns text{font:11px sans-serif;fill:#5a6b78}.vk-nsn{font-weight:700;fill:#1b4fb8}.vk-nsb{fill:#c21d00;font-weight:600}
      .vk-col{font:10.5px sans-serif;fill:#8a9aa5}.vk-e{fill:none;stroke-width:1.4;opacity:.55}.vk-e.bad{opacity:.9;stroke-width:2;stroke-dasharray:6 4;animation:vkflow 1.1s linear infinite}
      .vk-e.hot{opacity:1;stroke-width:2.6}.vk-n{cursor:pointer}.vk-n.sel .vk-box{stroke-width:3.2}.vk-n.imp .vk-box{stroke-dasharray:6 3}.vk-n:hover .vk-box{filter:drop-shadow(0 1px 3px rgba(0,0,0,.25))}
      @keyframes vkflow{to{stroke-dashoffset:-20}}</style></defs>
      ${bx}${sh}${ed}${ns}</svg>`;
  }
  function nodeLane(g) {
    if (!g.k8s_nodes.length) return "";
    return `<h5>노드 → vSphere VM → ESXi <small class="muted">노드 이름과 같은 vCenter VM 을 찾아 연결 · 누르면 노드 상세</small></h5><div class="vk-lane">${g.k8s_nodes.map(n => `<div class="vk-kn ${n.status}" data-knode="${esc(n.name)}" role="button" tabindex="0">
      <svg width="30" height="30">${hex(15, 15, 13, "node")}</svg><div><b>${esc(n.name)}</b>${n.events ? ` <span class="vk-pill ev">⚡${n.events}</span>` : ""}${n.recent ? ` <span class="vk-pill ch">↻${n.recent.n}</span>` : ""}
      <div class="small">${esc((n.roles || []).join(", "))} · ${n.ready === "True" ? "Ready" : "Ready=" + esc(n.ready)} · 파드 ${n.pods}${n.pods_bad ? ` <span class="bad">(이상 ${n.pods_bad})</span>` : ""}</div>
      <div class="small muted">${n.vm ? `VM ${esc(n.vm_power || "")} → ESXi <b>${esc(n.esxi || "?")}</b>${n.vsphere_cluster ? " · " + esc(n.vsphere_cluster) : ""}` : "vCenter VM 미일치"} · ${esc(n.cpu || "")} vCPU · ${esc(n.memory || "")}</div>
      ${(n.issues || []).length ? `<div class="small bad">${n.issues.map(i => esc(i.text)).join(" · ")}</div>` : ""}</div></div>`).join("")}</div>`;
  }
  function healthBar(g) {
    const s = g.summary || {};
    const pill = (cls, lab, v, t) => `<span class="vk-hp ${cls}${v ? "" : " zero"}" title="${esc(t)}"><b>${v || 0}</b> ${lab}</span>`;
    const probs = (g.problems || []).slice(0, 10);
    return `<div class="vk-health">${pill("down", "장애", s.down, "자체 문제가 장애 수준인 개체")}${pill("warn", "주의", s.warn, "자체 문제가 주의 수준인 개체")}
        ${pill("imp", "영향", s.impacted, "하류(백엔드·볼륨) 장애로 영향받는 개체 — 점선 테두리")}${pill("ok", "정상", s.ok, "")}
        ${pill("ev", "경고 이벤트(1시간)", s.events, "AIOps 가 수집한 Kubernetes 경고 이벤트·파드 이상")}${pill("ch", "최근 변경(1시간)", s.changed, "롤아웃·스케일·재시작·생성·삭제")}
        ${s.nodes_bad ? pill("down", "노드 이상", s.nodes_bad, "") : ""}
        <span class="gap"></span><label class="chk"><input type="checkbox" id="vk-bad" ${st.onlyBad ? "checked" : ""}> 문제 경로만</label>
        <label class="chk" title="30초마다 상태 다시 읽기(보던 위치 유지)"><input type="checkbox" id="vk-auto" ${st.auto ? "checked" : ""}> 자동 갱신</label>
        <span class="small muted" id="vk-upd">상태 ${g.pods_updated ? new Date(g.pods_updated * 1000).toLocaleTimeString() : "-"} · 구성 ${g.updated ? new Date(g.updated * 1000).toLocaleTimeString() : "수집 전"}</span></div>
      ${probs.length ? `<div class="vk-probs">${probs.map(p => `<button class="vk-prob ${p.status}" data-goto="${esc(p.id)}" data-kind="${esc(p.kind)}" data-name="${esc(p.name)}" data-ns="${esc(p.ns)}"><i></i><b>${esc(p.kind === "PersistentVolumeClaim" ? "PVC" : p.kind)} ${esc(p.ns ? p.ns + "/" : "")}${esc(p.name)}</b> <span>${esc(p.text)}</span></button>`).join("")}${(g.problems || []).length > 10 ? `<span class="small muted">외 ${g.problems.length - 10}건</span>` : ""}</div>` : ""}`;
  }

  async function fetchGraph() {
    return A.api("GET", `/api/vks/${encodeURIComponent(st.name)}/map?` + new URLSearchParams({ns: st.ns, system: st.system, q: st.q}), undefined, {background: true});
  }
  async function loadCluster(box, name) {
    st.name = name; st.box = box;
    box.innerHTML = `<div class="empty"><span class="spin"></span></div>`;
    try { st.g = await fetchGraph(); } catch (e) { box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    renderCluster(box);
    arm();
  }
  function arm() {
    clearInterval(st.timer);
    if (!st.auto) return;
    st.timer = setInterval(async () => {
      const box = st.box;
      if (!box || !box.isConnected) { clearInterval(st.timer); return; }
      if (document.hidden) return;
      try { st.g = await fetchGraph(); } catch { return; }
      renderMain(box, true);
      if (st.side && st.side.nid) sideHead();                       // 패널 머리(상태)만 갱신 — 보던 탭 유지
    }, 30000);
  }
  function renderCluster(box) {
    box.innerHTML = `<div id="vk-main"></div>`;
    renderMain(box, false);
  }
  function renderMain(box, keepScroll) {
    const main = $("#vk-main", box); if (!main) return;
    const g = st.g, c = g.counts, v = view(g);
    const sc = $(".vk-wrap", box), keep = keepScroll && sc ? [sc.scrollLeft, sc.scrollTop] : null;
    const errs = Object.entries(g.errors || {});
    main.innerHTML = `<div class="vks-filter vk-bar"><select id="vk-ns"><option value="">전체 네임스페이스${g.system ? "" : "(시스템 제외)"}</option>${g.namespaces.map(n => `<option value="${esc(n)}" ${n === st.ns ? "selected" : ""}>${esc(n)}${g.system_ns.includes(n) ? " · 시스템" : ""}</option>`).join("")}</select>
        <label class="chk"><input type="checkbox" id="vk-sys" ${st.system ? "checked" : ""}> 시스템 네임스페이스 포함</label><input id="vk-q" placeholder="리소스 이름 검색(이웃 함께)" value="${esc(st.q)}">
        <span class="gap"></span><button class="btn-sm" id="vk-svg">SVG</button><button class="btn-sm" id="vk-mmd" title="Mermaid flowchart(상태 색 포함) — 위키·문서에 붙여넣기">Mermaid</button></div>
      ${healthBar(g)}
      <p class="small muted">${esc(g.cluster)} · ${[["Ingress", "ing"], ["Service", "svc"], ["Deployment", "deploy"], ["StatefulSet", "sts"], ["DaemonSet", "ds"], ["PersistentVolumeClaim", "pvc"], ["PersistentVolume", "pv"]].map(([k, l]) => `${l} ${c[k] || 0}`).join(" · ")}
        ${g.truncated ? " · <b>노드가 많아 일부만 표시(문제 개체 우선) — 네임스페이스를 고르세요</b>" : ""}${st.onlyBad ? ` · <b>문제 경로만 표시 중 (${v.nodes.length}/${g.nodes.length})</b>` : ""}</p>
      ${errs.length ? `<p class="small om-warn">읽지 못한 리소스: ${errs.map(([k, x]) => `${esc(k)}(${esc(x)})`).join(", ")} — 수집 계정에 list 권한(읽기 전용 ClusterRole)을 주면 구성도에 나옵니다.</p>` : ""}
      ${v.nodes.length ? `<div class="vk-wrap">${svg(v)}</div>` : `<div class="empty small">${st.onlyBad && g.nodes.length ? "문제 개체가 없습니다 — 모두 정상입니다." : g.updated ? "표시할 리소스가 없습니다(필터 확인)." : "구성 정보를 수집 중입니다(최대 5분) — 커넥터 '구성도 수집'이 켜져 있어야 합니다."}</div>`}
      <div class="sec-leg small">${Object.entries(EL).filter(([k]) => k !== "owns").map(([k, l]) => `<i style="background:${EC[k]}"></i>${l}`).join(" ")}</div>
      <div class="vk-leg small muted"><span><span class="vk-sw ok"></span>정상</span><span><span class="vk-sw warn"></span>주의</span><span><span class="vk-sw down"></span>장애</span>
        <span><span class="vk-sw imp"></span>하류 장애 영향(점선)</span><span>움직이는 선 = 문제 개체로 가는 경로</span><span>작은 칸 = 파드별 상태</span>
        <span><span class="vk-pill ev">⚡</span> 경고 이벤트(1시간)</span><span><span class="vk-pill ch">↻</span> 최근 변경(1시간)</span><span>개체를 누르면 상태·이벤트·로그·변경 이력·연관</span></div>
      ${nodeLane(g)}`;
    if (keep) { const s2 = $(".vk-wrap", box); if (s2) { s2.scrollLeft = keep[0]; s2.scrollTop = keep[1]; } }
    $("#vk-ns", box).onchange = e => { st.ns = e.target.value; st.sel = null; loadCluster(box, st.name); };
    $("#vk-sys", box).onchange = e => { st.system = e.target.checked; loadCluster(box, st.name); };
    $("#vk-bad", box).onchange = e => { st.onlyBad = e.target.checked; renderMain(box, false); };
    $("#vk-auto", box).onchange = e => { st.auto = e.target.checked; try { localStorage.setItem("vk-auto", st.auto ? "1" : "0"); } catch { /* */ } arm(); };
    let qt; $("#vk-q", box).oninput = e => { clearTimeout(qt); qt = setTimeout(() => { st.q = e.target.value.trim(); loadCluster(box, st.name).then(() => { const i = $("#vk-q", box); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 400); };
    $("#vk-svg", box).onclick = () => { const s = $(".vk-svg", box); if (!s) return; const b = new Blob([s.outerHTML], {type: "image/svg+xml"}); window.AIOPS.download(`vks-${g.cluster}-${st.ns || "all"}.svg`, b); };
    $("#vk-mmd", box).onclick = () => { const a = document.createElement("a"); a.href = `/api/vks/${encodeURIComponent(st.name)}/map.mmd?` + new URLSearchParams({ns: st.ns, system: st.system}); a.download = ""; document.body.append(a); a.click(); a.remove(); };
    main.onclick = e => {
      const kn = e.target.closest("[data-knode]");
      if (kn) { select(`Node:/${kn.dataset.knode}`); return; }
      const gp = e.target.closest("[data-goto]");
      if (gp) { select(gp.dataset.goto, true); return; }
      const n = e.target.closest("[data-nid]"); if (!n) return;
      select(n.dataset.nid);
    };
    main.onkeydown = e => { const kn = e.target.closest("[data-knode]"); if (kn && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); select(`Node:/${kn.dataset.knode}`); } };
  }
  function select(nid, scroll) {
    st.sel = nid;
    renderMain(st.box, true);
    if (scroll) { const el = st.box.querySelector(`[data-nid="${CSS.escape(nid)}"]`); if (el) el.scrollIntoView({block: "center", inline: "center", behavior: "smooth"}); }
    openSide(nid);
  }

  // ---------------------------------------------------------------- 개체 상세 패널(상태 · 이벤트 · 로그 · 변경 이력 · 연관)
  const parseId = nid => { const [kind, rest] = [nid.slice(0, nid.indexOf(":")), nid.slice(nid.indexOf(":") + 1)]; const i = rest.indexOf("/"); return {kind, ns: rest.slice(0, i), name: rest.slice(i + 1)}; };
  const gNode = nid => { const g = st.g; if (!g) return null; const n = g.nodes.find(x => x.id === nid); if (n) return n;
    if (nid.startsWith("Node:/")) { const k = g.k8s_nodes.find(x => x.name === nid.slice(6)); if (k) return {id: nid, kind: "Node", ns: "", name: k.name, abbr: "node", status: k.status, own: k.status, issues: k.issues, events: k.events, recent: k.recent, k8s: k}; }
    return null; };
  function sideEl() {
    let sd = document.getElementById("vk-side");
    if (!sd) { sd = document.createElement("aside"); sd.id = "vk-side"; sd.className = "mv-tl vk-side"; ((st.box && st.box.closest(".drawer")) || document.body).append(sd); }
    return sd;
  }
  function closeSide() { const sd = document.getElementById("vk-side"); if (sd) sd.remove(); st.side = null; st.sel = null; if (st.box && st.box.isConnected) renderMain(st.box, true); }
  async function openSide(nid) {
    const n = gNode(nid); if (!n) return;
    const p = parseId(nid);
    const prevTab = st.side && st.side.nid === nid ? st.side.tab : (n.own === "down" || n.own === "warn") && WL.has(n.kind) ? "state" : "state";
    st.side = {nid, tab: prevTab, d: null, err: "", log: {pod: "", container: "", previous: null, tail: 300, lines: null, q: "", err: ""}, evWarn: false, kind: p.kind, ns: p.ns, name: p.name};
    const sd = sideEl();
    sd.innerHTML = `<div class="vk-sh"></div><div class="vk-stabs"></div><div class="vk-sbody"><div class="empty"><span class="spin"></span></div></div>`;
    sideHead(); sideTabs(); sideBody();
    sd.onclick = sideClick; sd.oninput = sideInput; sd.onchange = sideChange;
    document.addEventListener("keydown", escClose);
    await loadDetail();
  }
  function escClose(e) { if (e.key === "Escape" && st.side) { closeSide(); document.removeEventListener("keydown", escClose); } }
  async function loadDetail() {
    const s = st.side; if (!s) return;
    s.err = "";
    try { s.d = await A.api("GET", `/api/vks/${encodeURIComponent(st.name)}/object?` + new URLSearchParams({kind: s.kind, ns: s.ns, obj: s.name}), undefined, {background: true}); }
    catch (e) { s.err = e.message; }
    if (st.side !== s) return;
    if (s.d && !s.log.pod) { const bp = (s.d.pods || [])[0]; if (bp) { s.log.pod = bp.name; s.log.ns = bp.ns || s.ns; s.log.container = (bp.containers || [])[0] || ""; s.log.previous = !!(bp.restarts && (bp.st === "down" || bp.st === "warn")); } }
    sideHead(); sideTabs(); sideBody();
  }
  function sideHead() {
    const s = st.side, sd = document.getElementById("vk-side"); if (!s || !sd) return;
    const n = gNode(s.nid) || (s.d && s.d.node) || {};
    const stt = n.status || "ok";
    $(".vk-sh", sd).innerHTML = `<div class="mv-tl-h"><svg width="30" height="30">${hex(15, 15, 13, n.abbr || "", icoFill(n.kind))}</svg><div><b>${esc(s.name)}</b><div class="small muted">${esc(s.kind)}${s.ns ? " · " + esc(s.ns) : ""} · ${esc(st.g ? st.g.cluster : "")}</div></div>
      <span class="vk-st ${stt}">${SL[stt] || stt}${n.impact ? " · 영향" : ""}</span><span class="gap"></span>
      <button class="btn-sm" data-sact="refresh" title="다시 읽기">↻</button><button class="btn-sm" data-sact="ai" title="이 개체의 상태·이벤트·변경을 넣어 AI 질의 열기">AI에게 묻기</button>
      ${A.can("operate") ? `<button class="btn-sm" data-sact="sr" title="이 개체의 상태·이벤트·변경·파드 로그로 벤더 SR 보고서·이메일 초안">SR 초안</button>` : ""}<button class="btn-sm" data-sact="bundle" title="관련 파드 전부의 로그(컨테이너별 현재·이전) + 이벤트·변경 이력 CSV + 수집 로그 — zip">로그 묶음</button><button class="x" data-sact="close" aria-label="닫기">✕</button></div>
      ${(n.issues || []).length ? `<ul class="vk-iss">${n.issues.map(i => `<li class="${i.sev}">${esc(i.text)}</li>`).join("")}</ul>` : `<div class="small good" style="margin:4px 0 8px">문제 없음${n.detail ? " · " + esc(n.detail) : ""}</div>`}`;
  }
  function sideTabs() {
    const s = st.side, sd = document.getElementById("vk-side"); if (!s || !sd) return;
    const d = s.d || {};
    const evN = (d.events || []).filter(e => e.type === "Warning").length + (d.stored_events || []).length;
    const tabs = [["state", "상태"], ["events", `이벤트${d.events ? ` ${(d.events || []).length}` : ""}${evN ? ` <i class="vk-dot"></i>` : ""}`], ["logs", "로그"],
      ["activity", `변경 이력${d.activity ? ` ${d.activity.length}` : ""}`], ["rel", `연관${d.incidents && d.incidents.length ? ` <span class="vk-pill inc">${d.incidents.length}</span>` : ""}`]];
    $(".vk-stabs", sd).innerHTML = `<div class="vks-tabs">${tabs.map(([k, l]) => `<button class="${s.tab === k ? "on" : ""}" data-stab="${k}">${l}</button>`).join("")}</div>`;
  }
  const row = (k, v) => v != null && v !== "" && (!Array.isArray(v) || v.length) ? `<tr><th>${k}</th><td>${Array.isArray(v) ? v.map(esc).join("<br>") : esc(String(v))}</td></tr>` : "";
  const podTable = (pods, withWl) => pods.length ? `<table class="vc-t vk-pt"><thead><tr><th></th><th>파드</th><th>상태</th><th>준비</th><th>재시작</th><th>노드</th><th></th></tr></thead><tbody>${pods.slice(0, 200).map(p => `<tr class="${p.st === "down" ? "bad-row" : ""}">
      <td><i class="vk-pd" style="background:${PD[p.st] || "#9aa5ad"}"></i></td><td><b>${esc(p.name)}</b>${withWl && p.workload ? `<div class="mini">${esc(p.workload)}</div>` : ""}${p.msg ? `<div class="mini bad">${esc(cut(p.msg, 140))}</div>` : ""}</td>
      <td>${esc(p.phase)}${p.reason ? ` <span class="${p.st === "down" ? "bad" : "mini"}">${esc(p.reason)}</span>` : ""}${p.last_term && p.last_term.reason ? `<div class="mini">직전 종료 ${esc(p.last_term.reason)} (exit ${esc(String(p.last_term.exit ?? ""))})</div>` : ""}</td>
      <td>${esc(p.ready)}</td><td>${p.restarts || 0}</td><td class="mini">${esc(p.node || "-")}</td><td><button class="btn-sm" data-plog="${esc(p.name)}" data-pns="${esc(p.ns || "")}">로그</button></td></tr>`).join("")}</tbody></table>` : "";
  function sideBody() {
    const s = st.side, sd = document.getElementById("vk-side"); if (!s || !sd) return;
    const b = $(".vk-sbody", sd), d = s.d, n = gNode(s.nid) || (d && d.node) || {};
    if (s.err) { b.innerHTML = `<div class="empty small">${esc(s.err)}</div>`; return; }
    const wait = `<div class="empty"><span class="spin"></span></div>`;
    if (s.tab === "state") {
      const k = n.k8s || (d && d.node && d.node.k8s);
      const rel = (d && d.related) || [];
      b.innerHTML = `<table class="vc-t">${row("요약", n.detail)}${row("파드", n.pods != null ? `${n.pods_ready}/${n.pods}${n.pods_bad ? ` (이상 ${n.pods_bad})` : ""}` : "")}
        ${row("목표·준비·갱신", n.want != null ? `${n.want} · ${n.ready} · ${n.updated}` : "")}${row("리비전", n.rev)}${row("재시작(누적)", n.restarts)}${row("HPA", n.hpa)}${row("이미지", n.images)}
        ${row("실행 노드", n.on_nodes)}${row("ConfigMap", n.cms)}${row("Secret(이름만)", n.secrets)}${row("ServiceAccount", n.sa)}${row("포트", n.ports)}${row("호스트", n.hosts)}
        ${row("VIP", n.lb)}${row("Avi 가상 서비스", n.avi)}${row("스토리지 정책", n.policy)}${row("볼륨 핸들", n.handle)}
        ${k ? row("역할", (k.roles || []).join(", ")) + row("kubelet · OS", `${k.kubelet || ""} · ${k.os || ""}`) + row("CPU · 메모리", `${k.cpu} · ${k.memory}`) + row("vSphere", k.vm ? `VM ${k.vm_power || ""} → ESXi ${k.esxi} (${k.vsphere_cluster || ""})` : "VM 미일치") : ""}
        ${row("최근 변경(1시간)", n.recent ? `${n.recent.n}건 — ${n.recent.action}: ${n.recent.detail}` : "")}</table>
        ${d ? (d.pods.length ? `<h5>파드 ${d.pods.length}${d.pods.length > 200 ? " (200개 표시)" : ""}</h5>${podTable(d.pods, ["Service", "Ingress", "VIP", "PersistentVolumeClaim"].includes(s.kind))}` : "") : wait}
        ${rel.length ? `<h5>연결</h5><ul class="inv-moves">${rel.map(r => `<li><a href="#" data-sgo="${esc(r.id)}"><i class="vk-pd" style="background:${SC[r.status] || "#9aa5ad"}"></i> ${r.dir} ${esc(r.okind)} ${esc(r.name)}</a> <small class="muted">${esc(EL[r.kind] || r.kind)}</small></li>`).join("")}</ul>` : ""}`;
    } else if (s.tab === "events") {
      if (!d) { b.innerHTML = wait; return; }
      const ev = (d.events || []).filter(e => !s.evWarn || e.type === "Warning");
      b.innerHTML = `<div class="vk-bar"><label class="chk"><input type="checkbox" data-evwarn ${s.evWarn ? "checked" : ""}> 경고만</label><span class="small muted">Kubernetes API 실시간(Normal 포함) — 개체와 소속 파드·ReplicaSet</span></div>
        ${d.events_error ? `<p class="small om-warn">실시간 이벤트를 읽지 못했습니다: ${esc(d.events_error)} — 아래 수집된 경고만 표시</p>` : ""}
        <ul class="mv-tl-list">${ev.map(e => `<li><i style="background:${e.type === "Warning" ? SC.down : "#9aa5ad"}"></i><time title="${esc(tm(e.ts))}">${ago(e.ts)}</time><div><span class="label ${e.type === "Warning" ? "error" : "info"}">${esc(e.reason)}</span> <small class="muted">${esc(e.kind)} ${esc(e.name)}${e.count > 1 ? ` · x${e.count}` : ""}${e.component ? " · " + esc(e.component) : ""}</small><div>${esc(e.message)}</div></div></li>`).join("") || `<li class="muted small">이벤트 없음(Kubernetes 는 이벤트를 기본 1시간만 보관)</li>`}</ul>
        <h5>AIOps 가 수집한 경고 (24시간)</h5><ul class="mv-tl-list">${(d.stored_events || []).map(e => `<li><i style="background:${e.severity === "error" || e.severity === "critical" ? SC.down : SC.warn}"></i><time title="${esc(tm(e.ts))}">${ago(e.ts)}</time><div><small class="muted">${esc(e.entity)}</small><div>${esc(e.message)}</div></div></li>`).join("") || `<li class="muted small">없음</li>`}</ul>`;
    } else if (s.tab === "logs") {
      if (!d) { b.innerHTML = wait; return; }
      const pods = d.pods || [], L = s.log;
      const pod = pods.find(p => p.name === L.pod) || pods[0];
      if (!pods.length) { b.innerHTML = `<div class="empty small">이 개체에 연결된 파드가 없습니다.${s.kind === "Node" ? "" : " (노드 로그는 syslog 경로로 수집)"}</div>`; return; }
      const re = L.q ? new RegExp(L.q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") : null;
      const lines = (L.lines || []).filter(x => !re || re.test(x));
      b.innerHTML = `<div class="vk-bar vk-logbar"><select data-lpod>${pods.slice(0, 300).map(p => `<option value="${esc(p.name)}" data-ns="${esc(p.ns || s.ns)}" ${p.name === (pod && pod.name) ? "selected" : ""}>${p.st === "down" ? "✕ " : p.st === "warn" ? "! " : ""}${esc(p.name)}</option>`).join("")}</select>
          <select data-lcont>${((pod && pod.containers) || []).map(c => `<option ${c === L.container ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
          <label class="chk" title="재시작 직전(이전 컨테이너) 로그 — CrashLoop·OOM 원인 확인용"><input type="checkbox" data-lprev ${L.previous ? "checked" : ""}> 이전 컨테이너</label>
          <select data-ltail>${[100, 300, 1000, 3000].map(t => `<option ${t === L.tail ? "selected" : ""}>${t}</option>`).join("")}</select><button class="btn-sm solid" data-sact="logs">가져오기</button><button class="btn-sm" data-sact="logfile" title="이 컨테이너 로그 전체(최대 10만 줄, 시각 포함)를 파일로">파일로 받기</button>
          <input data-lq placeholder="로그 내 검색" value="${esc(L.q)}"></div>
        ${L.err ? `<p class="small om-warn">${esc(L.err)}</p>` : ""}
        ${L.lines == null ? `<p class="small muted">‘가져오기’를 누르면 Kubernetes API 에서 마지막 ${L.tail}줄을 읽습니다(읽기 전용 · 비밀번호·토큰 패턴은 가림).</p>`
          : `<pre class="vk-log">${lines.map(x => `<span class="${/\b(error|err|fatal|panic|exception|fail(ed|ure)?|oom|killed|refused|timeout)\b/i.test(x) ? "e" : /\bwarn(ing)?\b/i.test(x) ? "w" : ""}">${esc(x)}</span>`).join("\n") || "(빈 로그)"}</pre><div class="small muted">${lines.length}/${L.lines.length}줄${L.prevUsed ? " · 이전 컨테이너" : ""} · 비밀값 패턴 가림</div>`}
        ${(d.logs || []).length ? `<h5>AIOps 가 수집한 파드 로그 (24시간 · 문제 파드 자동 첨부·지정 네임스페이스)</h5><pre class="vk-log">${d.logs.slice(0, 300).map(l => `<span class="${l.severity === "error" || l.severity === "critical" ? "e" : l.severity === "warning" ? "w" : ""}">${esc(tm(l.ts))} ${esc(l.entity.split("/").pop())} ${esc(l.message)}</span>`).join("\n")}</pre>` : ""}`;
    } else if (s.tab === "activity") {
      if (!d) { b.innerHTML = wait; return; }
      const C = {created: "#62a420", deleted: "#8a6fb3", rollout: "#0072a3", scale: "#326ce5", hpa: "#326ce5", restart: SC.warn, pod_bad: SC.down, pod_ok: "#62a420", pod_replace: "#9aa5ad", node: "#e8730c", network: "#7a5af8", storage: "#5b8c5a"};
      b.innerHTML = `<p class="small muted">구성(기본 5분)·파드 상태(기본 1분) 스냅숏 비교로 기록 — 롤아웃·스케일·재시작·파드 교체·생성/삭제 (최근 7일)${["Service", "Ingress", "VIP", "PersistentVolumeClaim"].includes(s.kind) ? " · 하류 워크로드 변경 포함" : ""}</p>
        <ul class="mv-tl-list">${(d.activity || []).map(r => `<li><i style="background:${C[r.action] || "#9aa5ad"}"></i><time title="${esc(tm(r.ts))}">${tm(r.ts)}</time><div><span class="label ${r.sev === "error" ? "error" : r.sev === "warn" ? "warning" : "info"}">${esc(r.label)}</span>${r.via ? ` <small class="muted">${esc(r.kind)} ${esc(r.via)}</small>` : ""} ${esc(r.detail)}</div></li>`).join("") || `<li class="muted small">기록된 변경 없음 — 2.10.0 적용 이후 변경부터 쌓입니다.</li>`}</ul>`;
    } else if (s.tab === "rel") {
      if (!d) { b.innerHTML = wait; return; }
      const L = window.AIOPS_VM_LABELS || {};
      b.innerHTML = `<h5>인시던트 (14일)</h5>${(d.incidents || []).map(i => `<div class="mv-inc"><div class="mv-inc-h"><a href="#" data-inc="${esc(i.id)}"><b>${esc(i.id)}</b></a><span class="label ${i.severity === "critical" ? "critical" : i.severity === "error" ? "error" : "warning"}">${esc(i.severity || "")}</span><span class="small">${esc(i.status || "")}</span><span class="gap"></span><small class="muted">${ago(i.updated)}</small></div><div class="small">${esc(i.title || "")}</div></div>`).join("") || `<p class="small muted">연관 인시던트 없음</p>`}
        <h5>실행 위치 — 노드 → vSphere VM → ESXi</h5><table class="vc-t"><thead><tr><th>노드</th><th>파드</th><th>VM 전원</th><th>ESXi · 클러스터</th><th></th></tr></thead><tbody>${(d.infra || []).map(x => `<tr><td><i class="vk-pd" style="background:${SC[x.status] || "#9aa5ad"}"></i> <a href="#" data-sgo="Node:/${esc(x.node)}">${esc(x.node)}</a></td><td>${x.pods}</td><td>${esc(x.vm ? x.vm_power || "-" : "VM 미일치")}</td><td>${esc(x.esxi || "-")}${x.vsphere_cluster ? " · " + esc(x.vsphere_cluster) : ""}${x.ops ? `<div class="mini">${esc(x.ops.split("\n")[0])}</div>` : ""}</td><td>${x.vm && window.AIOPS_VM_TIMELINE ? `<button class="btn-sm" data-vmtl="${esc(x.node)}">VM 일대기</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">-</td></tr>`}</tbody></table>
        <h5>노드 VM·ESXi 의 VM 액티비티 (7일)</h5><ul class="mv-tl-list">${(d.vm_activity || []).map(m => `<li><i style="background:#0072a3"></i><time title="${esc(tm(m.ts))}">${tm(m.ts)}</time><div><span class="label info">${esc(L[m.type] || m.type)}</span> <b>${esc(m.vm || "")}</b> ${esc(m.from_host && m.to_host && m.from_host !== m.to_host ? `${m.from_host} → ${m.to_host}` : m.to_host || m.from_host || "")} ${esc(m.detail || m.msg || "")}</div></li>`).join("") || `<li class="muted small">없음</li>`}</ul>`;
    }
  }
  async function fetchLogs() {
    const s = st.side; if (!s) return;
    const L = s.log, pod = (s.d.pods || []).find(p => p.name === L.pod); if (!pod) return;
    L.err = ""; L.lines = []; sideBody();
    try {
      const r = await A.api("GET", `/api/vks/${encodeURIComponent(st.name)}/log?` + new URLSearchParams({ns: pod.ns || s.ns, pod: pod.name, container: L.container || "", tail: L.tail, previous: !!L.previous}), undefined, {background: true});
      L.lines = r.lines || []; L.prevUsed = !!L.previous;
    } catch (e) { L.err = `로그 조회 실패: ${e.message}`; L.lines = null; }
    if (st.side === s) sideBody();
  }
  function askAi() {
    const s = st.side; if (!s) return;
    const n = gNode(s.nid) || (s.d && s.d.node) || {}, d = s.d || {};
    const ev = (d.events || []).filter(e => e.type === "Warning").slice(0, 5).map(e => `${e.reason}: ${cut(e.message, 120)}`);
    const ch = (d.activity || []).slice(0, 4).map(r => `${tm(r.ts)} ${r.label} ${cut(r.detail, 100)}`);
    const q = `VKS 클러스터 ${st.g ? st.g.cluster : ""}의 ${s.kind} ${s.ns ? s.ns + "/" : ""}${s.name} 상태: ${SL[n.status] || n.status}. 문제: ${(n.issues || []).map(i => i.text).join("; ") || "없음"}.`
      + (ev.length ? `\n최근 경고 이벤트: ${ev.join(" | ")}` : "") + (ch.length ? `\n최근 변경: ${ch.join(" | ")}` : "") + "\n원인 후보와 확인 순서, 조치 방법을 알려줘.";
    closeSide();
    const nav = document.getElementById("nav-chat"); if (nav) nav.click();
    setTimeout(() => { const t = document.getElementById("chat-q"); if (t) { t.value = q; t.focus(); t.setSelectionRange(t.value.length, t.value.length); }
      const cx = document.getElementById("chat-ctx"); if (cx) cx.textContent = `— VKS ${st.g ? st.g.cluster : ""} · ${s.kind} ${s.ns ? s.ns + "/" : ""}${s.name}`; }, 150);
  }
  function sideClick(e) {
    const s = st.side; if (!s) return;
    const a = e.target.closest("[data-sact]");
    if (a) { const k = a.dataset.sact; if (k === "close") closeSide(); else if (k === "refresh") { s.d = null; sideBody(); loadDetail(); } else if (k === "ai") askAi(); else if (k === "logs") fetchLogs();
      else if (k === "sr") { const src = {kind: "vks", connector: st.name, okind: s.kind, ns: s.ns, obj: s.name}; closeSide(); if (window.AIOPS_SR_NEW) window.AIOPS_SR_NEW(src, {label: `${s.kind} ${s.ns ? s.ns + "/" : ""}${s.name}`}); }
      else if (k === "bundle") { const a2 = document.createElement("a"); a2.href = `/api/vks/${encodeURIComponent(st.name)}/object/logs.zip?` + new URLSearchParams({kind: s.kind, ns: s.ns, obj: s.name}); a2.download = ""; document.body.append(a2); a2.click(); a2.remove(); A.toast("로그 묶음", "관련 파드 로그를 모으는 중입니다 — 파드가 많으면 수십 초 걸립니다.", "info", 4000); }
      else if (k === "logfile") { const L2 = s.log, pod = (s.d.pods || []).find(p => p.name === L2.pod); if (!pod) return; const a2 = document.createElement("a");
        a2.href = `/api/vks/${encodeURIComponent(st.name)}/log/download?` + new URLSearchParams({ns: pod.ns || s.ns, pod: pod.name, container: L2.container || "", previous: !!L2.previous}); a2.download = ""; document.body.append(a2); a2.click(); a2.remove(); }
      return; }
    const t = e.target.closest("[data-stab]"); if (t) { s.tab = t.dataset.stab; sideTabs(); sideBody(); return; }
    const pl = e.target.closest("[data-plog]");
    if (pl) { const p = (s.d.pods || []).find(x => x.name === pl.dataset.plog); s.log.pod = pl.dataset.plog; s.log.container = ((p && p.containers) || [])[0] || ""; s.log.previous = !!(p && p.restarts && p.st !== "ok"); s.log.lines = null; s.tab = "logs"; sideTabs(); sideBody(); fetchLogs(); return; }
    const go = e.target.closest("[data-sgo]"); if (go) { e.preventDefault(); if (gNode(go.dataset.sgo)) select(go.dataset.sgo, true); else A.toast("구성도에 없음", "현재 필터(네임스페이스·검색·문제 경로만)에 없는 개체입니다.", "info"); return; }
    const inc = e.target.closest("[data-inc]"); if (inc) { e.preventDefault(); const id = inc.dataset.inc; closeSide(); if (window.AIOPS_OPEN_INCIDENT) window.AIOPS_OPEN_INCIDENT(id); return; }
    const vt = e.target.closest("[data-vmtl]"); if (vt) { const vm = vt.dataset.vmtl; closeSide(); window.AIOPS_VM_TIMELINE(vm); }
  }
  function sideInput(e) {
    const s = st.side; if (!s) return;
    if (e.target.matches("[data-lq]")) { s.log.q = e.target.value; const pos = e.target.selectionStart; sideBody(); const i = document.querySelector("#vk-side [data-lq]"); if (i) { i.focus(); i.setSelectionRange(pos, pos); } }
  }
  function sideChange(e) {
    const s = st.side; if (!s) return;
    const L = s.log, t = e.target;
    if (t.matches("[data-lpod]")) { const p = (s.d.pods || []).find(x => x.name === t.value); L.pod = t.value; L.container = ((p && p.containers) || [])[0] || ""; L.previous = !!(p && p.restarts && p.st !== "ok"); L.lines = null; sideBody(); fetchLogs(); }
    else if (t.matches("[data-lcont]")) { L.container = t.value; fetchLogs(); }
    else if (t.matches("[data-lprev]")) { L.previous = t.checked; fetchLogs(); }
    else if (t.matches("[data-ltail]")) { L.tail = +t.value; fetchLogs(); }
    else if (t.matches("[data-evwarn]")) { s.evWarn = t.checked; sideBody(); }
  }

  // ---------------------------------------------------------------- 전체(Supervisor → vSphere 네임스페이스 → 클러스터)
  async function overview(box) {
    box.innerHTML = `<div class="empty"><span class="spin"></span></div>`;
    let d; try { d = await A.api("GET", "/api/vks/map", undefined, {background: true}); } catch (e) { box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (!d.supervisors.length && !d.standalone.length) { box.innerHTML = `<div class="empty small">Supervisor 커넥터가 없습니다 — vCenter 자동 발견 또는 VKS 커넥터(역할 supervisor)를 추가하세요.</div>`; return; }
    const nodes = [], edges = [];
    const N = (id, kind, abbr, name, detail, status = "ok", col = 0) => nodes.push({id, kind, abbr, name, detail, status, own: status, col});
    d.supervisors.forEach(s => {
      const sid = "sup:" + s.connector; N(sid, "Supervisor", "sup", s.label, `노드 ${s.nodes} · vSphere 네임스페이스 ${s.namespaces.length}`, Object.keys(s.errors).length ? "warn" : "ok", 0);
      s.namespaces.forEach(ns => {
        const nid = `vns:${s.connector}/${ns.name}`; N(nid, "vSphereNamespace", "vns", ns.name, `클러스터 ${ns.clusters.length} · VM ${ns.vms.length}`, "ok", 1); edges.push({from: sid, to: nid, kind: "owns"});
        ns.clusters.forEach(k => { const kid = `k:${s.connector}/${ns.name}/${k.name}`;
          const stt = k.phase && k.phase !== "Provisioned" ? "warn" : k.connector && k.nodes_ready < k.nodes ? "down" : k.pods_bad ? "warn" : "ok";
          N(kid, "VKSCluster", "k8s", k.name, `${k.phase || ""} ${k.version || ""}${k.connector ? ` · 노드 ${k.nodes_ready}/${k.nodes} · 파드 ${k.pods}` : " · 커넥터 없음"}`.trim(), stt, 2);
          const last = nodes[nodes.length - 1]; last.connector = k.connector; if (k.pods_bad) last.issues = [{sev: "warn", text: `문제 파드 ${k.pods_bad}`}];
          edges.push({from: nid, to: kid, kind: "owns"}); });
        ns.vms.forEach(v => { const vid = `vm:${s.connector}/${ns.name}/${v.name}`; N(vid, "VirtualMachine", "vm", v.name, `${v.power || ""} ${v.class || ""} ${v.ip || ""}`.trim(), /on/i.test(v.power || "") ? "ok" : "warn", 2); edges.push({from: nid, to: vid, kind: "owns"}); });
      });
    });
    d.standalone.forEach(w => { N("k:" + w.connector, "VKSCluster", "k8s", w.name, `Supervisor 정보 없음 · 노드 ${w.nodes}`, "ok", d.supervisors.length ? 2 : 0); nodes[nodes.length - 1].connector = w.connector; });
    const cols = [[], [], []]; nodes.forEach(n => cols[n.col].push(n));
    const pos = new Map(); let maxy = 0;
    cols[2].forEach((n, i) => { pos.set(n.id, {x: 2 * (NW + CG) + 10, y: 10 + i * (NH + RG)}); maxy = Math.max(maxy, 10 + i * (NH + RG)); });
    const avgY = id => { const ys = edges.filter(e => e.from === id).map(e => (pos.get(e.to) || {}).y).filter(v => v != null); return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : null; };
    let lastY = -1e9; cols[1].forEach(n => { let y = avgY(n.id); y = Math.max(y == null ? lastY + NH + RG : y, lastY + NH + RG); pos.set(n.id, {x: NW + CG + 10, y}); lastY = y; maxy = Math.max(maxy, y); });
    lastY = -1e9; cols[0].forEach(n => { let y = avgY(n.id); y = Math.max(y == null ? lastY + NH + RG : y, lastY + NH + RG); pos.set(n.id, {x: 10, y}); lastY = y; maxy = Math.max(maxy, y); });
    const W = 3 * NW + 2 * CG + 30, H = maxy + NH + 20;
    const ed = edges.map(e => { const a = pos.get(e.from), b = pos.get(e.to); if (!a || !b) return ""; const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
      return `<path d="M${x1},${y1} C${x1 + 30},${y1} ${x2 - 30},${y2} ${x2},${y2}" fill="none" stroke="#9aa5ad" stroke-width="1.3" opacity=".7"/>`; }).join("");
    box.innerHTML = `<div class="vk-wrap"><svg class="vk-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><style>.vk-box{stroke-width:1.6}.vk-t{font:600 11.5px sans-serif;fill:#1b2a35}.vk-s{font:10.5px sans-serif;fill:#5a6b78}.vk-ab{font:700 8.5px sans-serif;fill:#fff}.vk-n{cursor:pointer}.vk-i{font:600 10px sans-serif}.vk-i.warn{fill:#a07000}.vk-i.error{fill:#c21d00}.vk-bd{font:700 8.5px sans-serif;fill:#fff}</style>
      ${ed}${nodes.map(n => { const p = pos.get(n.id); return `<g data-ovc="${esc(n.connector || "")}">${nodeSvg(n, p.x, p.y, false)}</g>`; }).join("")}</svg></div>
      <p class="small muted">Supervisor → vSphere 네임스페이스 → VKS 클러스터(Cluster API·TanzuKubernetesCluster)·VM Service VM. 클러스터를 누르면 그 클러스터의 구성도로 이동합니다(워크로드 클러스터 커넥터가 있을 때).</p>`;
    box.onclick = e => { const g = e.target.closest("[data-ovc]"); if (g && g.dataset.ovc && window.AIOPS_VKS_SELECT) window.AIOPS_VKS_SELECT(g.dataset.ovc, "map"); };
  }
  window.AIOPS_VKS_MAP = (box, name) => { if (st.name !== name) { st.ns = ""; st.q = ""; st.sel = null; const sd = document.getElementById("vk-side"); if (sd) sd.remove(); st.side = null; } return loadCluster(box, name); };
  window.AIOPS_VKS_OVERVIEW = overview;
})();
