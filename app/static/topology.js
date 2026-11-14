/* 고객 환경 토폴로지 — 연결된 커넥터가 실제로 본 VCF 구성(SDDC·도메인·vCenter·클러스터·호스트·BMC·NSX·ALB·VKS)
   GET /api/topology/live(15초) + WebSocket 로그가 들어오면 해당 개체가 깜빡임. 휠=확대/축소, 드래그=이동, 클릭=상세 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const ST = {ok: "정상", warn: "주의", down: "장애", maint: "유지보수", unknown: "미확인", degraded: "불안정", init: "연결 중", error: "오류"};
  const SEVC = {critical: "#c21d00", error: "#e12200", warning: "#efc006", info: "#0072a3", notice: "#0072a3", debug: "#8c8c8c"};
  const t = {d: null, z: 1, x: 0, y: 0, timer: null, q: "", sel: null, idx: new Map(), hits: new Map(), tab: "live"};
  const short = h => { const x = String(h || "").split(":")[0].toLowerCase(); return /^[\d.]+$/.test(x) ? x : x.split(".")[0]; };
  const cst = s => s === "ok" ? "ok" : s === "degraded" ? "warn" : s === "down" || s === "error" ? "down" : s === "init" ? "unknown" : (s || "unknown");
  const pct = v => v === null || v === undefined ? "" : `${v}%`;
  const fmtBw = b => b == null ? "-" : b >= 1e9 ? `${(b / 1e9).toFixed(1)} Gb/s` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} Mb/s` : b >= 1e3 ? `${(b / 1e3).toFixed(0)} kb/s` : `${Math.round(b)} b/s`;

  async function load() {
    try { t.d = await A.api("GET", "/api/topology/live", undefined, {background: true}); }
    catch (e) { $("#tp-canvas").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }

  // ------------------------------------------------------------ 렌더링
  const node = (id, cls, inner, title = "") => { t.idx.set(id, true); return `<div class="tp-n ${cls}" data-id="${esc(id)}" title="${esc(title)}">${inner}</div>`; };
  const dot = s => `<i class="tp-dot ${cst(s)}" title="${esc(ST[s] || s)}"></i>`;
  const fbadge = f => !f ? "" : f.critical ? `<b class="tp-fb critical" title="인프라 점검 위험 ${f.critical}">${f.critical}</b>` : f.error ? `<b class="tp-fb error" title="인프라 점검 오류 ${f.error}">${f.error}</b>` : f.warning ? `<b class="tp-fb warning" title="인프라 점검 경고 ${f.warning}">${f.warning}</b>` : "";

  function hostTile(h, vc) {
    const id = `host:${h.name}`;
    const bmc = h.bmc ? `<span class="tp-bmc ${cst(h.bmc.state)}" title="BMC ${esc(h.bmc.connector)} ${esc(h.bmc.health || "")} ${esc(h.bmc.fw || "")}">BMC</span>` : "";
    const bar = (v, l) => v == null ? "" : `<span class="tp-bar" title="${l} ${v}%"><i style="width:${Math.min(100, v)}%" class="${v >= 90 ? "hot" : v >= 75 ? "warm" : ""}"></i></span>`;
    return node(id, `tp-host ${h.state}`, `<div class="tp-hn">${dot(h.state)}<span>${esc(/^[\d.]+$/.test(h.name) ? h.name : h.name.split(".")[0])}</span>${fbadge(h.findings)}</div>
      <div class="tp-hm">${bar(h.cpu_pct, "CPU")}${bar(h.mem_pct, "메모리")}</div>
      <div class="tp-hf"><span title="전원 켜진 VM">VM ${h.vms}</span>${h.agents ? `<span title="에이전트 설치 VM">AG ${h.agents}</span>` : ""}${bmc}</div><i class="tp-pulse"></i>`,
      `${h.name} · ${ST[h.state] || h.state} · VM ${h.vms} · CPU ${pct(h.cpu_pct)} · MEM ${pct(h.mem_pct)}`);
  }

  function cluster(cl, vc) {
    const id = `cluster:${cl.name}`;
    const isCl = cl.ha !== null && cl.ha !== undefined;
    const tags = isCl ? [cl.ha ? "HA" : `<s title="HA 꺼짐">HA</s>`, cl.drs ? "DRS" : `<s title="DRS 꺼짐">DRS</s>`, cl.vsan ? "vSAN" : ""].filter(Boolean).join(" ") : `<span class="muted">단독 호스트</span>`;
    const ds = cl.datastores.slice(0, 6).map(d => `<div class="tp-ds" data-id="ds:${esc(d.name)}" title="${esc(d.name)} ${d.type} ${d.cap_gb ?? ""}GB"><span>${esc(d.name)}</span><span class="tp-bar w"><i style="width:${Math.min(100, d.used_pct || 0)}%" class="${(d.used_pct || 0) >= 90 ? "hot" : (d.used_pct || 0) >= 80 ? "warm" : ""}"></i></span><em>${d.used_pct ?? "-"}%</em></div>`).join("");
    const vks = t.d.vks.filter(v => v.discovered_by === vc.connector && (v.role === "supervisor" ? v.name === `Supervisor ${cl.name}` : (cl.supervisor && v.supervisor === cl.supervisor.endpoint)));
    const sup = cl.supervisor ? `<div class="tp-sup" data-id="sup:${esc(cl.name)}">${dot(cl.supervisor.k8s === "READY" || cl.supervisor.status === "RUNNING" ? "ok" : "warn")}<b>Supervisor</b> <span class="muted">${esc(cl.supervisor.endpoint)} · NS ${cl.supervisor.namespaces}</span>
      <div class="tp-vks">${vks.filter(v => v.role !== "supervisor").map(v => node(`vks:${v.connector}`, `tp-chip ${v.pods_problem ? "warn" : cst(v.state)}`, `⎈ ${esc(v.name)} <small>${v.nodes_ready}/${v.nodes_total}노드 · 파드 ${v.pods_total}${v.pods_problem ? ` · 문제 ${v.pods_problem}` : ""}</small><i class="tp-pulse"></i>`, `VKS ${v.name}`)).join("") || `<span class="muted small">워크로드 클러스터 없음/발견 대기</span>`}</div></div>` : "";
    return `<div class="tp-cl ${cl.state}" data-id="${esc(id)}"><div class="tp-clh">${dot(cl.state)}<b>${esc(cl.name)}</b><span class="tp-tags">${tags}</span>${fbadge(cl.findings)}<span class="muted small">호스트 ${cl.hosts.length}</span></div>
      <div class="tp-hosts">${cl.hosts.map(h => hostTile(h, vc)).join("")}</div>
      ${ds ? `<div class="tp-dss">${ds}${cl.datastores_total > 6 ? `<span class="muted small">외 ${cl.datastores_total - 6}개</span>` : ""}</div>` : ""}${sup}</div>`;
  }

  function vcCard(vc) {
    t.idx.set(vc.id, true);
    return `<div class="tp-vc ${cst(vc.state)}" data-id="${esc(vc.id)}"><div class="tp-cardh">${dot(cst(vc.state))}<span class="tp-ico">vC</span><b>${esc(vc.name)}</b>
      <span class="muted small">클러스터 ${vc.clusters.length} · 호스트 ${vc.hosts} · VM ${vc.vms}</span>${vc.error ? `<span class="tp-err" title="${esc(vc.error)}">수집 오류</span>` : ""}</div>
      <div class="tp-cls">${vc.clusters.map(cl => cluster(cl, vc)).join("") || `<div class="muted small pad8">토폴로지 수집 대기(5분 주기)</div>`}</div></div>`;
  }

  function nsxCard(n) {
    t.idx.set(n.id, true);
    const mst = n.managers[0] ? n.managers[0].state : cst(n.state);
    return `<div class="tp-nsx ${cst(n.state)}" data-id="${esc(n.id)}"><div class="tp-cardh">${dot(mst)}<span class="tp-ico nsx">NSX</span><b>${esc(n.name)}</b><span class="muted small">Edge ${n.edges.length}</span></div>
      <div class="tp-chips">${n.edges.map(e => node(`edge:${e.name}`, `tp-chip ${e.state}`, `${esc(e.name)}<i class="tp-pulse"></i>`, `${e.name} ${e.detail || ""}`)).join("") || `<span class="muted small">Edge 없음/수집 대기</span>`}</div></div>`;
  }

  function aviCard(a) {
    t.idx.set(a.id, true);
    return `<div class="tp-avi ${cst(a.state)}" data-id="${esc(a.id)}"><div class="tp-cardh">${dot(cst(a.state))}<span class="tp-ico avi">ALB</span><b>${esc(a.name)}</b><span class="muted small">SE ${a.se.length} · VS ${a.vs_total}</span></div>
      <div class="tp-chips">${a.se.map(s => node(`se:${s.name}`, `tp-chip ${s.state}`, `SE ${esc(s.name)}<i class="tp-pulse"></i>`, s.detail)).join("")}</div>
      <div class="tp-chips">${a.vs.map(v => node(`vs:${v.name}`, `tp-chip vs ${v.state === "OPER_UP" ? "ok" : v.state ? "down" : "unknown"}`, `${esc(v.name)} <small>${esc((v.vips || []).join(","))}${v.last && v.last.bw != null ? " · " + fmtBw(v.last.bw) : ""}</small><i class="tp-pulse"></i>`, `VIP ${v.name} ${(v.vips || []).join(",")} health ${v.health ?? "-"}`)).join("")}</div></div>`;
  }

  function render() {
    const d = t.d;
    t.idx.clear();
    const c = d.counts;
    $("#tp-sum").innerHTML = [["VCF", d.sddc.length], ["도메인", d.domains.length], ["vCenter", c.vcenters], ["클러스터", c.clusters], ["호스트", c.hosts], ["VM", c.vms],
      ["NSX", c.nsx], ["Edge", c.edges], ["ALB", c.avi], ["VIP", c.vips], ["Supervisor", c.supervisors], ["VKS", c.vks], ["BMC", c.bmc], ["에이전트", `${c.agents_ok}/${c.agents}`]]
      .map(([k, v]) => `<span><b>${v}</b>${k}</span>`).join("");
    if (d.empty) {
      $("#tp-canvas").innerHTML = `<div class="empty tp-empty"><b>연결된 커넥터가 없습니다.</b><br>운영 설정 › 커넥터에서 SDDC Manager·vCenter·NSX·NSX ALB·VCF Operations·서버 BMC 를 추가하면, 각 커넥터가 실제로 수집한 구성으로 이 화면이 자동으로 그려집니다.</div>`;
      return;
    }
    const byId = Object.fromEntries([...d.vcenters, ...d.nsx].map(x => [x.id, x]));
    const doms = d.domains.map(dm => {
      const vcs = dm.members.filter(id => id.startsWith("vc:")).map(id => byId[id]).filter(Boolean);
      const nx = dm.members.filter(id => id.startsWith("nsx:")).map(id => byId[id]).filter(Boolean);
      const missing = dm.source === "sddc" ? [...(dm.vcenter_fqdns || []).filter(f => !vcs.some(v => short(v.name) === short(f))).map(f => `vCenter ${f}`),
        ...(dm.nsx_fqdn && !nx.length ? [`NSX ${dm.nsx_fqdn}`] : [])] : [];
      return `<section class="tp-dom ${dm.source}"><div class="tp-domh"><span class="tp-ico dom">${dm.type === "MANAGEMENT" ? "MGMT" : dm.type === "VI" ? "VI" : "도메인"}</span><b>${esc(dm.name)}</b>
        <span class="muted small">${dm.source === "sddc" ? `SDDC Manager 기준 · ${esc(dm.status)} · 클러스터 ${dm.clusters}` : "SDDC Manager 미연결 — 커넥터 환경 이름으로 묶음"}</span>
        ${missing.length ? `<span class="tp-miss" title="이 도메인의 구성요소 중 커넥터가 없는 것">커넥터 없음: ${esc(missing.join(", "))}</span>` : ""}</div>
        <div class="tp-domb">${vcs.map(vcCard).join("")}<div class="tp-side">${nx.map(nsxCard).join("")}</div></div></section>`;
    }).join("");
    const sddc = d.sddc.map(s => `<div class="tp-root" data-id="${esc(s.id)}">${dot(cst(s.state))}<span class="tp-ico">VCF</span><b>${esc(s.name)}</b><span class="muted small">SDDC Manager · 도메인 ${s.domains.length}</span></div>`).join("");
    const unl = d.bmc.filter(b => !b.linked);
    $("#tp-canvas").innerHTML = `<div class="tp-world" id="tp-world">
      ${sddc ? `<div class="tp-roots">${sddc}</div>` : ""}
      <div class="tp-doms">${doms}</div>
      ${d.avi.length ? `<section class="tp-dom lane"><div class="tp-domh"><span class="tp-ico avi">ALB</span><b>NSX Advanced Load Balancer</b><span class="muted small">컨트롤러 ${d.avi.length}</span></div><div class="tp-domb">${d.avi.map(aviCard).join("")}</div></section>` : ""}
      ${d.mgmt.length || unl.length ? `<section class="tp-dom lane"><div class="tp-domh"><span class="tp-ico">OPS</span><b>관리 · 운영</b></div><div class="tp-domb tp-chips">
        ${d.mgmt.map(m => node(m.id, `tp-chip big ${cst(m.state)}`, `${dot(cst(m.state))}<b>${esc(m.label)}</b> <small>${esc(m.name)}</small><i class="tp-pulse"></i>`, m.error)).join("")}
        ${unl.map(b => node(b.id, `tp-chip big ${cst(b.state)}`, `${dot(cst(b.state))}<b>BMC</b> ${esc(b.name)} <small>${esc(b.vendor || "")} ${esc(b.model || "")} · ESXi 미연결</small><i class="tp-pulse"></i>`, "커넥터의 'ESXi 호스트' 칸을 채우면 해당 호스트 타일에 연결됩니다")).join("")}</div></section>` : ""}
    </div>`;
    apply();
    highlight();
    if (t.sel) detail(t.sel, false);
  }

  // ------------------------------------------------------------ 확대·이동
  function apply() { const w = $("#tp-world"); if (w) w.style.transform = `translate(${t.x}px,${t.y}px) scale(${t.z})`; $("#tp-zoom").textContent = `${Math.round(t.z * 100)}%`; }
  function zoomAt(f, cx, cy) {
    const nz = Math.min(3, Math.max(0.25, t.z * f));
    t.x = cx - (cx - t.x) * (nz / t.z); t.y = cy - (cy - t.y) * (nz / t.z); t.z = nz; apply();
  }
  function fit() {
    const w = $("#tp-world"), c = $("#tp-canvas"); if (!w) return;
    t.z = 1; t.x = 0; t.y = 0; apply();
    const z = Math.min(1, (c.clientWidth - 20) / w.scrollWidth, (c.clientHeight - 20) / w.scrollHeight);
    t.z = Math.max(0.3, z); t.x = 10; t.y = 10; apply();
  }
  function focusEl(el) {
    const c = $("#tp-canvas"), r = el.getBoundingClientRect(), cr = c.getBoundingClientRect();
    t.x += (cr.left + cr.width / 2) - (r.left + r.width / 2); t.y += (cr.top + cr.height / 2) - (r.top + r.height / 2); apply();
  }

  // ------------------------------------------------------------ 검색 강조
  function highlight() {
    const q = t.q.trim().toLowerCase();
    $$("#tp-world [data-id]").forEach(el => el.classList.toggle("tp-dim", !!q && !el.dataset.id.toLowerCase().includes(q) && !el.textContent.toLowerCase().includes(q)));
    if (q) { const m = $$("#tp-world .tp-n").find(el => el.dataset.id.toLowerCase().includes(q)); if (m) focusEl(m); }
  }

  // ------------------------------------------------------------ 상세 패널
  async function detail(id, fetchLogs = true) {
    t.sel = id;
    $$("#tp-world .tp-sel").forEach(e => e.classList.remove("tp-sel"));
    const el = $(`#tp-world [data-id="${CSS.escape(id)}"]`); if (el) el.classList.add("tp-sel");
    const [kind, ...rest] = id.split(":"); const name = rest.join(":");
    const d = t.d, p = $("#tp-detail");
    let html = "", host = name;
    if (kind === "host") {
      const h = d.vcenters.flatMap(v => v.clusters.flatMap(c => c.hosts.map(x => ({...x, cluster: c.name, vc: v.name})))).find(x => x.name === name) || {};
      html = `<dl><dt>상태</dt><dd>${dot(h.state)} ${ST[h.state] || h.state} (${esc(h.conn || "")})</dd><dt>vCenter · 클러스터</dt><dd>${esc(h.vc)} · ${esc(h.cluster)}</dd>
        <dt>CPU · 메모리</dt><dd>${pct(h.cpu_pct) || "-"} · ${pct(h.mem_pct) || "-"}</dd><dt>VM(전원 켜짐)</dt><dd>${h.vms} · 에이전트 ${h.agents}</dd>
        <dt>BMC</dt><dd>${h.bmc ? `${esc(h.bmc.connector)} · ${esc(h.bmc.health || ST[h.bmc.state] || "")} · fw ${esc(h.bmc.fw || "-")}` : "연결된 BMC 커넥터 없음"}</dd>
        <dt>인프라 점검</dt><dd>${h.findings ? `위험 ${h.findings.critical} · 오류 ${h.findings.error} · 경고 ${h.findings.warning} <a href="#" data-vchk="${esc(name)}">상세</a>` : "이상 없음"}</dd></dl>`;
    } else if (kind === "vks") {
      const v = d.vks.find(x => x.connector === name) || {}; host = v.name;
      html = `<dl><dt>역할</dt><dd>${v.role === "supervisor" ? "Supervisor" : "워크로드 클러스터"}</dd><dt>노드</dt><dd>${v.nodes_ready}/${v.nodes_total} Ready</dd>
        <dt>파드</dt><dd>${v.pods_total} · 문제 ${v.pods_problem}</dd>${(v.problem_pods || []).length ? `<dt>문제 파드</dt><dd>${v.problem_pods.map(esc).join("<br>")}</dd>` : ""}
        <dt>커넥터</dt><dd>${esc(v.connector)} · ${esc(ST[v.state] || v.state)}</dd></dl><button class="btn-sm" data-open="vks">VKS 화면에서 보기</button>`;
    } else if (kind === "vs") {
      const v = d.avi.flatMap(a => a.vs).find(x => x.name === name) || {}; host = name;
      html = `<dl><dt>VIP</dt><dd>${esc((v.vips || []).join(", ") || "-")}</dd><dt>상태 · Health</dt><dd>${esc(v.state || "-")} · ${v.health ?? "-"}</dd>
        <dt>대역폭</dt><dd>${fmtBw(v.last && v.last.bw)}</dd><dt>연결/초 · 요청/초</dt><dd>${(v.last && v.last.cps) ?? "-"} · ${(v.last && v.last.rps) ?? "-"}</dd></dl>`;
    } else {
      const any = [...d.vcenters, ...d.nsx, ...d.avi, ...d.mgmt, ...d.bmc, ...d.sddc].find(x => x.id === id);
      if (any) { host = any.name; html = `<dl><dt>커넥터</dt><dd>${esc(any.connector)} (${esc(any.type)})</dd><dt>대상</dt><dd>${esc(any.target)}</dd><dt>상태</dt><dd>${dot(cst(any.state))} ${esc(ST[any.state] || any.state)}${any.latency_ms != null ? ` · ${any.latency_ms}ms` : ""}</dd>${any.error ? `<dt>오류</dt><dd class="bad">${esc(any.error)}</dd>` : ""}</dl>`; }
      else html = `<p class="muted">${esc(name)}</p>`;
    }
    const hits = t.hits.get(id);
    p.hidden = false;
    p.innerHTML = `<div class="tp-dh"><b>${esc(name)}</b><button class="x" id="tp-dx" aria-label="닫기">✕</button></div>${html}
      <div class="tp-dact"><button class="btn-sm" data-tail="${esc(host)}">실시간 로그 보기</button>${{host: "host", vks: "vks-cluster", vs: "avi-vs", edge: "nsx-edge", se: "avi-se"}[kind] ? `<button class="btn-sm" data-inv="${esc({host: "host", vks: "vks-cluster", vs: "avi-vs", edge: "nsx-edge", se: "avi-se"}[kind])}/${esc(encodeURIComponent(kind === "vks" ? host : name))}">인벤토리에서 보기</button>` : ""}</div>
      <h5>최근 1시간 로그 ${hits ? `<span class="muted small">(이 화면을 연 뒤 ${hits}건 수신)</span>` : ""}</h5><div id="tp-logs" class="tp-logs"><span class="muted small">불러오는 중…</span></div>`;
    if (!fetchLogs) { $("#tp-logs").innerHTML = t.lastLogs || ""; return; }
    try {
      const r = await A.api("GET", `/api/logs?minutes=60&limit=30&min_severity=info&host=${encodeURIComponent(short(host))}`, undefined, {background: true});
      const rows = r.items || r.logs || r || [];
      t.lastLogs = rows.length ? rows.slice(0, 30).map(l => `<div class="tp-log"><i style="background:${SEVC[l.severity] || "#999"}"></i><time>${new Date(l.ts * 1000).toLocaleTimeString()}</time> ${esc(String(l.message).slice(0, 220))}</div>`).join("") : `<span class="muted small">최근 1시간 로그 없음</span>`;
    } catch (e) { t.lastLogs = `<span class="bad small">${esc(e.message)}</span>`; }
    if (t.sel === id) $("#tp-logs").innerHTML = t.lastLogs;
  }

  // ------------------------------------------------------------ 실시간 이벤트 → 개체 깜빡임
  function onLogs(logs) {
    if ($("#drawer-arch").hidden || t.tab !== "live" || !t.d) return;
    const shortMap = new Map();
    $$("#tp-world .tp-n").forEach(el => { const n = el.dataset.id.split(":").slice(1).join(":"); shortMap.set(short(n), el); shortMap.set(n.toLowerCase(), el); });
    let n = 0;
    for (const l of logs) {
      if (n > 40) break;
      const el = shortMap.get(String(l.host || "").toLowerCase()) || shortMap.get(short(l.host)) || shortMap.get(String(l.entity || "").toLowerCase());
      if (!el) continue;
      n++;
      const sev = l.severity || "info";
      el.style.setProperty("--pc", SEVC[sev] || "#0072a3");
      el.classList.remove("tp-hit"); void el.offsetWidth; el.classList.add("tp-hit");
      if (sev === "critical" || sev === "error") el.classList.add("tp-alarm");
      t.hits.set(el.dataset.id, (t.hits.get(el.dataset.id) || 0) + 1);
    }
    if (n) { const f = $("#tp-feed"); f.textContent = `실시간 ${n}건 반영 · ${new Date().toLocaleTimeString()}`; f.classList.remove("blink"); void f.offsetWidth; f.classList.add("blink"); }
  }

  // ------------------------------------------------------------ 이벤트 연결
  function wire() {
    const c = $("#tp-canvas");
    c.addEventListener("wheel", e => { e.preventDefault(); const r = c.getBoundingClientRect(); zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top); }, {passive: false});
    let drag = null;
    c.addEventListener("pointerdown", e => { if (e.button !== 0) return; drag = {x: e.clientX, y: e.clientY, ox: t.x, oy: t.y, moved: false}; });
    addEventListener("pointermove", e => { if (!drag) return; const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 4) { drag.moved = true; c.classList.add("grab"); } t.x = drag.ox + dx; t.y = drag.oy + dy; if (drag.moved) apply(); });
    addEventListener("pointerup", e => {
      if (!drag) return; const moved = drag.moved; drag = null; c.classList.remove("grab");
      if (moved) return;
      const el = e.target.closest && e.target.closest("#tp-world [data-id]"); if (el) detail(el.dataset.id);
    });
    c.addEventListener("dblclick", e => { const el = e.target.closest("[data-id]"); if (!el) return; const r = c.getBoundingClientRect(); zoomAt(1.6, e.clientX - r.left, e.clientY - r.top); focusEl(el); });
    $("#tp-zin").onclick = () => zoomAt(1.2, c.clientWidth / 2, c.clientHeight / 2);
    $("#tp-zout").onclick = () => zoomAt(1 / 1.2, c.clientWidth / 2, c.clientHeight / 2);
    $("#tp-fit").onclick = fit;
    $("#tp-reload").onclick = load;
    let qt; $("#tp-q").oninput = e => { clearTimeout(qt); qt = setTimeout(() => { t.q = e.target.value; highlight(); }, 200); };
    $("#tp-detail").addEventListener("click", e => {
      if (e.target.id === "tp-dx") { $("#tp-detail").hidden = true; t.sel = null; $$("#tp-world .tp-sel").forEach(x => x.classList.remove("tp-sel")); return; }
      const tl = e.target.closest("[data-tail]"); if (tl) { $("#drawer-arch").hidden = true; location.hash = ""; location.hash = `#tail/${encodeURIComponent(tl.dataset.tail)}`; return; }
      const ib = e.target.closest("[data-inv]"); if (ib) { $("#drawer-arch").hidden = true; location.hash = ""; location.hash = `#inv/${ib.dataset.inv}`; return; }
      const vk = e.target.closest("[data-vchk]"); if (vk) { e.preventDefault(); $("#drawer-arch").hidden = true; $("#nav-vchk").click(); setTimeout(() => { const q = $("#vc-q"); if (q) { q.value = vk.dataset.vchk; q.dispatchEvent(new Event("input", {bubbles: true})); } }, 600); return; }
      const op = e.target.closest("[data-open]"); if (op) { $("#drawer-arch").hidden = true; $(`#nav-${op.dataset.open}`).click(); }
    });
    $$("#drawer-arch [data-tptab]").forEach(b => b.onclick = () => {
      t.tab = b.dataset.tptab;
      $$("#drawer-arch [data-tptab]").forEach(x => x.classList.toggle("on", x === b));
      $("#tp-live").hidden = t.tab !== "live"; $("#tp-sys").hidden = t.tab !== "sys";
    });
    window.addEventListener("aiops:ws", e => { const m = e.detail; if (m.type === "logs") onLogs(m.data || []); });
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#tp-canvas")) return;
    wire();
    $("#nav-arch").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-arch") d.hidden = true; });
      $("#drawer-arch").hidden = false;
      load().then(() => { if (t.z === 1 && t.x === 0) fit(); });
      clearInterval(t.timer);
      t.timer = setInterval(() => $("#drawer-arch").hidden ? clearInterval(t.timer) : load(), 15000);
    };
  });
})();
