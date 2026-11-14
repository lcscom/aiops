/* 네트워크 구성도(/noc/network) — 물리(스위치·라우터 전면 포트·ESXi)부터 NSX·Avi·VM·Pod 까지 한 장
   계층: 외부·업링크 → 스파인·코어 → 리프·ToR → ESXi·서버 → Edge·Avi SE·컨트롤러 → Edge 클러스터·SE 그룹·관리 → T0·VPC 프로젝트·VS → T1·VPC
         → 세그먼트·포트그룹·VPC 서브넷 → VM → Pod
   스위치는 전면 포트 패널(포트별 사용 구분 — 사용 중·구성됨 미연결·닫힘·열린 미사용·오류)로 그리고, 물리 링크는 실제 포트 위치에 붙는다.
   선: 파랑 = 물리(빨간 점선 다운) · 보라 점선 = Edge↔스위치 BGP · 청록 = 논리(T0→T1→세그먼트) · 회색 = vNIC · 주황 점선 = Avi 풀 멤버 · 점선 = 관리·배치
   보기 전환 — 구성도 · 포트맵 · BGP 피어링. 30초 갱신 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const NS = "http://www.w3.org/2000/svg";
  const TIER_DEF = ["외부·업링크", "스파인·코어", "리프·ToR", "ESXi·서버", "Edge·Avi SE·컨트롤러", "Edge 클러스터·SE 그룹·관리", "Tier-0·VPC 프로젝트·Avi VS",
                    "Tier-1·VPC", "세그먼트·포트그룹·VPC 서브넷", "VM", "Pod"];
  const SC = {ok: "#56b62b", warn: "#f2c200", down: "#ff5a4f", maint: "#8a7cff", unknown: "#56707c", idle: "#56707c"};
  const KIND = {switch: "스위치", "external-switch": "외부 스위치·라우터", host: "ESXi", server: "서버", device: "장치", group: "호스트 묶음", edge: "NSX Edge", "bgp-peer": "BGP 피어(미수집)",
                se: "Avi Service Engine", "avi-ctrl": "Avi Controller", "se-group": "SE 그룹", "edge-cluster": "Edge 클러스터", "nsx-manager": "NSX Manager",
                t0: "Tier-0 게이트웨이", t1: "Tier-1 게이트웨이", vs: "Avi 가상 서비스", segment: "NSX 세그먼트", portgroup: "포트그룹", vpc: "NSX VPC", "vpc-project": "NSX 프로젝트",
                "vpc-subnet": "VPC 서브넷", vm: "VM", vmgroup: "VM 묶음", "k8s-node": "K8s 노드", pod: "Pod", podgroup: "Pod 묶음"};
  const BADGE = {host: "H", group: "H", server: "S", edge: "E", "bgp-peer": "B", se: "SE", "avi-ctrl": "AC", "se-group": "SG", "edge-cluster": "EC", "nsx-manager": "NM",
                 t0: "T0", t1: "T1", vs: "VS", segment: "SEG", portgroup: "PG", vpc: "VPC", "vpc-project": "PJ", "vpc-subnet": "SN", vm: "VM", vmgroup: "VM", "k8s-node": "K8", pod: "P", podgroup: "P"};
  const USE = {in_use: "사용 중", configured: "구성됨·미연결", shut: "미사용·닫힘", open: "미사용·열림", err: "오류(err-disabled)"};
  const LAYERS = [["nsx", "NSX(T0·T1·세그먼트)"], ["vpc", "VPC"], ["avi", "Avi"], ["vm", "VM"], ["pod", "Pod"]];
  const pref = (k, v) => { try { if (v === undefined) return JSON.parse(localStorage.getItem(k) || "null"); localStorage.setItem(k, JSON.stringify(v)); } catch { return null; } return null; };
  const NT = {d: null, pm: null, hosts: pref("net.hosts") ?? true, ext: pref("net.ext") ?? true, edges: pref("net.edges") ?? true, q: "", sel: null, maxHosts: 36,
              view: pref("net.view") || "map", onlyUsed: pref("net.used") ?? true, onlyBad: false, pmSel: null,
              layers: new Set(pref("net.layers") || ["nsx", "vpc", "avi", "vm", "pod"]), place: pref("net.place") ?? false, vms: pref("net.vms") ?? 12};

  async function load() {
    try {
      const q = `hosts=${NT.hosts ? 1 : 0}&layers=${[...NT.layers].join(",")}&vms=${NT.vms}&pods=8`;
      const [d, pm] = await Promise.all([A.api("GET", `/api/network/map?${q}`, undefined, {background: true}),
                                         NT.view === "ports" ? A.api("GET", "/api/network/portmap", undefined, {background: true}) : Promise.resolve(NT.pm)]);
      NT.d = d; NT.pm = pm;
    } catch (e) { $("#pg-network").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    render();
  }

  // ---------------------------------------------------------------- 그래프 정리(필터·호스트 묶기·계층 순서)
  const PHYS = l => !l.kind || l.kind === "phys";
  function prepare() {
    const d = NT.d;
    let nodes = d.nodes.filter(n => (NT.ext || !["external-switch", "device", "bgp-peer"].includes(n.kind)) && (NT.edges || n.kind !== "edge"));
    const ids = new Set(nodes.map(n => n.id));
    let links = d.links.filter(l => ids.has(l.a) && ids.has(l.b) && (NT.place || l.kind !== "placement" || (d.nodes.find(n => n.id === l.b) || {}).kind === "edge"));
    const hosts = nodes.filter(n => n.kind === "host");
    if (hosts.length > NT.maxHosts) {                         // 같은 스위치 집합에 붙은 호스트 묶기
      const up = {}; links.forEach(l => { if (!PHYS(l)) return; const [h, s] = hostSide(l, hosts); if (h) (up[h] = up[h] || new Set()).add(s); });
      const groups = {};
      hosts.forEach(h => { const key = [...(up[h.id] || [])].sort().join("+") || "none"; (groups[key] = groups[key] || []).push(h); });
      const gnodes = [], remap = {};
      Object.entries(groups).forEach(([key, hs], i) => {
        const bad = hs.filter(h => h.state === "down").length, warn = hs.filter(h => ["warn", "maint"].includes(h.state)).length;
        const g = {id: `grp:${i}`, kind: "group", tier: 3, label: `ESXi ×${hs.length}`, members: hs, state: bad ? "down" : warn ? "warn" : "ok",
                   detail: hs.slice(0, 6).map(h => h.label.split(".")[0]).join(", ") + (hs.length > 6 ? " …" : "")};
        hs.forEach(h => { remap[h.id] = g.id; }); gnodes.push(g);
      });
      nodes = nodes.filter(n => n.kind !== "host").concat(gnodes);
      const agg = {};
      links.forEach(l => {
        const a = remap[l.a] || l.a, b = remap[l.b] || l.b, k = `${a}|${b}|${l.kind || "phys"}`;
        const x = agg[k] || (agg[k] = {...l, a, b, count: 0, down: 0, ports: []});
        x.count++; if (l.state === "down") x.down++; x.ports.push(`${l.a_port}↔${l.b_port}`);
        x.state = x.down ? "down" : "up";
      });
      links = Object.values(agg);
    } else {
      const agg = {};                                          // 같은 장비 쌍 다중 링크 — 물리는 포트마다 따로(포트 위치에 붙임), 나머지는 합침
      links.forEach(l => { const k = PHYS(l) ? `${l.a}|${l.a_s}|${l.b}|${l.b_s}` : [l.a, l.b].sort().join("|") + "|" + (l.kind || "phys");
        const x = agg[k] || (agg[k] = {...l, count: 0, down: 0, ports: []});
        x.count++; if (l.state === "down") x.down++;
        x.ports.push(l.kind === "bgp" ? `${l.b_port} → ${l.a_port} (AS ${l.remote_as || "-"})${l.state === "down" ? " 미수립" : ""}` : `${l.a_port || ""}↔${l.b_port || ""}${l.state === "down" ? " (다운)" : ""}`);
        x.state = x.down ? "down" : "up"; });
      links = Object.values(agg);
    }
    const byTier = {}; nodes.forEach(n => { const t = n.tier ?? 3; (byTier[t] = byTier[t] || []).push(n); });
    Object.values(byTier).forEach(arr => arr.sort((a, b) => a.label.localeCompare(b.label)));
    const nb = {}; links.forEach(l => { (nb[l.a] = nb[l.a] || []).push(l.b); (nb[l.b] = nb[l.b] || []).push(l.a); });
    const order = Object.keys(byTier).map(Number).sort((a, b) => a - b);
    for (let pass = 0; pass < 4; pass++) {                    // 바리센터: 아래로 한 번, 위로 한 번
      const seq = pass % 2 ? [...order].reverse() : order;
      seq.forEach(t => { const pos = {}; Object.values(byTier).forEach(arr => arr.forEach((n, i) => { pos[n.id] = (i + 0.5) / arr.length; }));
        const arr = byTier[t];
        arr.forEach(n => { const ps = (nb[n.id] || []).map(x => pos[x]).filter(x => x != null); n._bc = ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : pos[n.id]; });
        arr.sort((a, b) => a._bc - b._bc); });
    }
    return {nodes, links, byTier};
  }
  function hostSide(l, hosts) { const hs = new Set(hosts.map(h => h.id)); return hs.has(l.a) ? [l.a, l.b] : hs.has(l.b) ? [l.b, l.a] : [null, null]; }

  // ---------------------------------------------------------------- 크기·포트 패널
  const PW = 9, PG = 2, PROW = 11;                             // 포트 칸 폭·간격·줄 높이
  function dims(n) {
    if (n.kind === "switch" && (n.panel || []).length) {
      const cols = Math.ceil(n.panel.length / 2);
      return {w: Math.max(176, 20 + cols * (PW + PG) + 6), h: 52 + 2 * PROW + 10};
    }
    if (["vm", "pod", "podgroup", "vmgroup", "k8s-node"].includes(n.kind)) return {w: 128, h: 40};
    if (["segment", "portgroup", "vpc-subnet"].includes(n.kind)) return {w: 140, h: 44};
    return {w: 152, h: 52};
  }
  function portXY(n, w, short) {                               // 패널 안 포트 중심(노드 왼쪽 위 기준)
    const i = (n.panel || []).findIndex(p => p.s === short); if (i < 0) return null;
    const col = Math.floor(i / 2), row = i % 2;
    return {x: 12 + col * (PW + PG) + PW / 2, y: 50 + row * PROW + 4, row};
  }
  function panelSvg(n) {
    return (n.panel || []).map((p, i) => { const col = Math.floor(i / 2), row = i % 2, x = 12 + col * (PW + PG), y = 50 + row * PROW;
      return `<rect class="np u-${p.u}${p.lost ? " lost" : ""}" x="${x}" y="${y}" width="${PW}" height="${PROW - 3}" rx="1.5"><title>${esc(p.n)} — ${USE[p.u] || p.u}${p.p ? `\n→ ${esc(p.p)}` : ""}${p.m ? `\n${esc(p.m)}` : ""}${p.d ? `\n설명: ${esc(p.d)}` : ""}${p.sp ? `\n${p.sp >= 1000 ? p.sp / 1000 + "G" : p.sp + "M"}` : ""}</title></rect>`; }).join("");
  }

  // ---------------------------------------------------------------- 그리기
  const VIEWS = [["map", "구성도"], ["ports", "포트맵"], ["bgp", "BGP 피어링"]];
  function bar(extra) {
    const s = NT.d.summary;
    return `<div class="net-bar"><span class="net-views">${VIEWS.map(([k, l]) => `<button data-nv="${k}" class="${NT.view === k ? "on" : ""}">${l}${k === "bgp" && s.bgp_sessions ? ` <small class="${s.bgp_down ? "bad" : ""}">${s.bgp_sessions - s.bgp_down}/${s.bgp_sessions}</small>` : ""}${k === "ports" && NT.pm ? ` <small class="${NT.pm.summary.down ? "bad" : NT.pm.summary.warn ? "warn" : ""}">${NT.pm.summary.down + NT.pm.summary.warn || ""}</small>` : ""}</button>`).join("")}</span>
        <span class="chip ${s.switches_down ? "bad" : s.switches_warn ? "warn" : "ok"}">스위치 ${s.switches}${s.switches_down ? ` · 장애 ${s.switches_down}` : ""}${s.switches_warn ? ` · 주의 ${s.switches_warn}` : ""}</span>
        <span class="chip ${s.links_down ? "bad" : "ok"}">링크 ${s.links}${s.links_down ? ` · 다운 ${s.links_down}` : ""}</span>
        ${s.bgp_sessions ? `<span class="chip ${s.bgp_down ? "bad" : "ok"}">Edge BGP ${s.bgp_sessions - s.bgp_down}/${s.bgp_sessions}</span>` : ""}
        <span class="chip">ESXi ${s.hosts}</span>${s.edges ? `<span class="chip">Edge ${s.edges}</span>` : ""}${extra || ""}</div>`;
  }
  function render() {
    const box = $("#pg-network"); if (!box || !NT.d) return;
    const d = NT.d, s = d.summary, lg = s.logical || {};
    $("#w-sub").textContent = `스위치 ${s.switches} · 링크 ${s.links}${s.links_down ? ` · 다운 ${s.links_down}` : ""} · ESXi ${s.hosts}${s.edges ? ` · Edge ${s.edges} · BGP ${s.bgp_sessions - s.bgp_down}/${s.bgp_sessions}` : ""}${lg.t1 ? ` · T1 ${lg.t1} · 세그먼트 ${lg.segment}` : ""}${lg.vm ? ` · VM ${lg.vm}` : ""}${lg.vs ? ` · VS ${lg.vs}` : ""} · ${s.vendors.join("·") || "벤더 미수집"}`;
    if (!d.nodes.length) {
      box.innerHTML = `<div class="wempty">네트워크 장비가 없습니다 — 운영 콘솔 › 커넥터에서 <b>Arista(eAPI)</b> · <b>Cisco(NX-API·RESTCONF·SNMP)</b> 를 추가하면 LLDP/CDP 이웃으로 구성도를 그립니다.<br>
        NSX·Avi·vCenter 커넥터가 있으면 Edge·T0·T1·세그먼트·VPC·SE·VS·VM·Pod 도 함께 표시합니다. 로그는 장비에서 <code>logging host &lt;AIops&gt;</code> 로 514/udp 에 보내면 '네트워크' 도메인으로 분류됩니다.${(s.collectors || []).filter(c => c.error).map(c => `<br><small>${esc(c.name)}: ${esc(c.error)}</small>`).join("")}</div>`;
      return;
    }
    if (NT.view === "ports" || NT.view === "bgp") {                 // 30초 갱신 때 스크롤 위치 유지
      const sc = $(".net-scroll", box), top = sc ? sc.scrollTop : 0;
      if (NT.view === "ports") renderPorts(box); else renderBgp(box);
      const sc2 = $(".net-scroll", box); if (sc2 && top) sc2.scrollTop = top;
      return;
    }
    const cvOld = $(".net-canvas", box), keep = cvOld ? [cvOld.scrollLeft, cvOld.scrollTop] : null;
    const g = prepare();
    const tierNames = d.tiers || TIER_DEF;
    const W = Math.max((NT.cw || box.clientWidth - (window.innerWidth > 1300 ? 362 : 0) - 26) - 4, 640), PAD = 132, GAP = 14;
    const tiers = Object.keys(g.byTier).map(Number).sort((a, b) => a - b);
    const avail = W - PAD - 40;
    const widest = Math.max(...tiers.map(t => Math.max(...g.byTier[t].map(n => dims(n).w))));
    const width = Math.max(W, PAD + widest + 40);
    const pos = {}; let y = 30; const rowY = {};
    tiers.forEach(t => {                                        // 화면 폭을 넘는 계층은 여러 줄로 접어서(바리센터 순서 유지)
      const lines = [[]]; let acc = 0;
      g.byTier[t].forEach(n => { const w = dims(n).w; if (acc && acc + GAP + w > avail) { lines.push([]); acc = 0; } lines[lines.length - 1].push(n); acc += (acc ? GAP : 0) + w; });
      const y0 = y;
      lines.forEach((arr, li) => { const hmax = Math.max(...arr.map(n => dims(n).h)), tot = arr.reduce((a2, n) => a2 + dims(n).w, 0) + GAP * (arr.length - 1);
        let x = PAD + (width - PAD - 40 - tot) / 2;
        arr.forEach(n => { const dd = dims(n); pos[n.id] = {x: x + dd.w / 2, y: y + hmax / 2, w: dd.w, h: dd.h, n}; x += dd.w + GAP; });
        y += hmax + (li < lines.length - 1 ? 14 : 0); });
      rowY[t] = [y0, y - y0];
      y += t >= 8 ? 64 : 92; });
    const height = y + 10;
    const q = NT.q.toLowerCase();
    const hit = n => q && (n.label.toLowerCase().includes(q) || (n.members || []).some(m => m.label.toLowerCase().includes(q)));
    const ebgp = {}; g.links.filter(l => l.kind === "bgp").forEach(l => { const e = ebgp[l.b] || (ebgp[l.b] = {t: 0, up: 0}); e.t += l.count || 1; e.up += (l.count || 1) - (l.down || 0); });
    const anchor = (P, other, short) => {                       // 링크 끝점 — 스위치는 해당 포트 위치, 나머지는 위/아래 가장자리 중앙
      const down = other.y > P.y || (other.y === P.y && false);
      const pp = short && P.n.kind === "switch" ? portXY(P.n, P.w, short) : null;
      const x = pp ? P.x - P.w / 2 + pp.x : P.x;
      return {x, y: down ? P.y + P.h / 2 : P.y - P.h / 2};
    };
    const lk = g.links.map(l => { const a = pos[l.a], b = pos[l.b]; if (!a || !b) return "";
      const kind = l.kind || "phys", bad = l.state === "down";
      const A1 = anchor(a, b, PHYS(l) ? l.a_s : null), B1 = anchor(b, a, PHYS(l) ? l.b_s : null);
      const same = Math.abs(a.y - b.y) < 2;
      const w = ["placement", "mgmt", "vnic", "pod"].includes(kind) ? 1 : Math.min(5, 1.4 + Math.log2((l.count || 1) + 0.0001) * 1.2);
      const path = same ? `M${A1.x},${a.y - a.h / 2} C${A1.x},${a.y - a.h / 2 - 40} ${B1.x},${b.y - b.h / 2 - 40} ${B1.x},${b.y - b.h / 2}`
                        : `M${A1.x},${A1.y} C${A1.x},${(A1.y + B1.y) / 2} ${B1.x},${(A1.y + B1.y) / 2} ${B1.x},${B1.y}`;
      const sel = NT.sel && (l.a === NT.sel || l.b === NT.sel);
      const ttl = kind === "bgp" ? `BGP ${esc(b.n.label)} ⇄ ${esc(a.n.label)}\n${esc((l.ports || []).slice(0, 12).join("\n"))}`
        : kind === "placement" ? `${esc(b.n.label)} 이(가) ${esc(a.n.label)} 에서 실행 중`
        : kind === "pool" ? `${esc(a.n.label)} 풀 멤버 → ${esc(b.n.label)} ${esc(l.b_port || "")}`
        : kind === "phys" ? `${esc(a.n.label)} ${esc(l.a_port || "")} ⇄ ${esc(b.n.label)} ${esc(l.b_port || "")}${l.speed ? ` · ${l.speed >= 1000 ? l.speed / 1000 + "G" : l.speed + "M"}` : ""} · ${esc(l.proto || "")}${l.count > 1 ? `\n${esc((l.ports || []).join("\n"))}` : ""}`
        : `${esc(a.n.label)} → ${esc(b.n.label)} ${esc(l.proto || "")}`;
      return `<path d="${path}" class="nl k-${kind} ${bad ? "down" : ""} ${sel ? "sel" : ""} ${l.proto === "cdp" ? "cdp" : ""}" stroke-width="${w.toFixed(1)}"><title>${ttl}</title></path>`; }).join("");
    const nd = Object.values(pos).map(({x, y, w, h, n}) => {
      const isSw = n.kind === "switch", isE = n.kind === "edge", small = h <= 44;
      const badge = n.vendor === "Arista" ? "A" : n.vendor === "Cisco" ? "C" : BADGE[n.kind] || "?";
      const eb = ebgp[n.id];
      const sub = isSw ? `${n.model || ""} ${n.version || ""}`.trim() : isE ? `T0 ${n.tier0 || ""} · AS ${n.local_as || "-"}` : n.kind === "group" ? n.detail
        : n.kind === "host" ? (n.cluster || "ESXi") : n.kind === "vm" ? `${(n.ips || [])[0] || ""} ${n.power === "poweredOff" ? "꺼짐" : ""}`.trim() || "VM"
        : n.kind === "pod" ? (n.ip || n.ns || "Pod") : (n.detail || KIND[n.kind] || n.kind);
      const meta = isSw ? `${n.usage ? `사용 ${n.usage.in_use} · 미연결 ${n.usage.configured} · 열림 ${n.usage.open} · 닫힘 ${n.usage.shut}` : `포트 ${n.ifs_up}/${n.ifs_total}`}${n.mlag && n.mlag.state ? ` · ${n.mlag.kind}` : ""}`
        : isE ? `BGP ${eb ? `${eb.up}/${eb.t}` : "-"}${n.edge_cluster ? ` · ${n.edge_cluster}` : ""}` : "";
      const st = isE && eb && eb.up < eb.t && n.state === "ok" ? "warn" : n.state;
      const c = SC[st] || SC.unknown, maxc = Math.floor(w / 7.6);
      return `<g class="nn k-${esc(n.kind)} ${isSw ? "sw" : ""} ${NT.sel === n.id ? "sel" : ""} ${hit(n) ? "hit" : ""} st-${esc(st || "unknown")}" data-nid="${esc(n.id)}" transform="translate(${x - w / 2},${y - h / 2})">
        <rect width="${w}" height="${h}" rx="6" style="stroke:${c}"/><rect width="5" height="${h}" rx="2" fill="${c}"/>
        <rect x="${w - 30}" y="5" width="25" height="15" rx="7" class="vb b-${esc(n.kind)} ${badge}"/><text x="${w - 17.5}" y="16" class="vbt">${badge}</text>
        <text x="11" y="${small ? 16 : 18}" class="nt">${esc(n.label.length > maxc - 4 ? n.label.slice(0, maxc - 5) + "…" : n.label)}</text>
        <text x="11" y="${small ? 31 : 32}" class="ns">${esc(String(sub || "").slice(0, maxc))}</text>${meta ? `<text x="11" y="45" class="nm">${esc(meta.slice(0, maxc + 6))}</text>` : ""}
        ${isSw ? panelSvg(n) : ""}
        <title>${esc(n.label)} — ${esc(KIND[n.kind] || n.kind)}${n.mgmt ? `\n관리 ${esc(n.mgmt)}` : ""}${n.detail ? `\n${esc(n.detail)}` : ""}${(n.nodes_detail || []).length ? `\n${esc(n.nodes_detail.join("\n"))}` : ""}${n.error ? `\n수집 오류: ${esc(n.error)}` : ""}</title></g>`; }).join("");
    const rows = tiers.map(t => `<text class="tier" x="10" y="${rowY[t][0] + rowY[t][1] / 2 + 4}">${esc(tierNames[t] || "")}</text><line class="tl" x1="${PAD - 10}" x2="${width - 20}" y1="${rowY[t][0] + rowY[t][1] + 34}" y2="${rowY[t][0] + rowY[t][1] + 34}"/>`).join("");
    const downs = d.links.filter(l => l.state === "down" && (PHYS(l) || l.kind === "bgp"));
    box.innerHTML = `<div class="net-wrap">${bar(`
        <span class="net-layers">${LAYERS.map(([k, l]) => `<label><input type="checkbox" data-layer="${k}" ${NT.layers.has(k) ? "checked" : ""}> ${l}</label>`).join("")}
          <label title="ESXi → VM·SE 배치선"><input type="checkbox" id="net-place" ${NT.place ? "checked" : ""}> 배치선</label>
          <select id="net-vms" title="호스트당 VM 표시 수">${[6, 12, 30, 0].map(v => `<option value="${v}" ${NT.vms === v ? "selected" : ""}>VM ${v || "전부"}</option>`).join("")}</select></span>
        <label><input type="checkbox" id="net-hosts" ${NT.hosts ? "checked" : ""}> 호스트</label><label><input type="checkbox" id="net-ext" ${NT.ext ? "checked" : ""}> 외부</label>
        <input id="net-q" placeholder="장비·VM·세그먼트 찾기" value="${esc(NT.q)}">
        <span class="gap"></span><span class="lg"><i class="up"></i>물리 <i class="down"></i>다운 <i class="bgp"></i>BGP <i class="lgc"></i>논리 <i class="vnic"></i>vNIC <i class="pool"></i>풀 멤버 <i class="plc"></i>관리·배치
          <b class="pl-l"><i class="np u-in_use"></i>사용 <i class="np u-configured"></i>미연결 <i class="np u-open"></i>열림 <i class="np u-shut"></i>닫힘</b></span>`)}
      <div class="net-main"><div class="net-canvas"><svg xmlns="${NS}" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${rows}${lk}${nd}</svg></div>
        <aside class="net-side" id="net-side">${NT.sel ? "" : sideDefault(downs)}</aside></div></div>`;
    if (NT.sel) side(NT.sel);
    const cv = $(".net-canvas", box);                         // 실제 캔버스 폭에 맞춰 한 번 더(옆 패널·스크롤바 반영)
    if (cv && keep) { cv.scrollLeft = keep[0]; cv.scrollTop = keep[1]; }
    if (cv && cv.clientWidth && Math.abs((NT.cw || 0) - cv.clientWidth) > 2) { NT.cw = cv.clientWidth; render(); }
  }

  // ---------------------------------------------------------------- BGP 피어링(NSX Edge ↔ 물리)
  const dur = s => s == null ? "" : s >= 86400 ? `${Math.floor(s / 86400)}일 ${Math.floor(s % 86400 / 3600)}시간` : s >= 3600 ? `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분` : `${Math.floor(s / 60)}분`;
  function renderBgp(box) {
    const B = NT.d.bgp || [];
    const byT0 = {}; B.forEach(b => { (byT0[b.tier0] = byT0[b.tier0] || []).push(b); });
    const q = NT.q.toLowerCase();
    const card = (t0, arr) => {
      const edges = [...new Set(arr.map(b => b.edge))].sort(), peers = [...new Set(arr.map(b => b.switch || `BGP ${b.neighbor}`))].sort();
      const cell = (e, p) => { const xs = arr.filter(b => b.edge === e && (b.switch || `BGP ${b.neighbor}`) === p); if (!xs.length) return `<td class="bm-na">—</td>`;
        return `<td>${xs.map(b => `<div class="bm-c ${b.state === "ESTABLISHED" ? (b.mismatch ? "warn" : "ok") : "bad"}" title="${esc(b.source)} → ${esc(b.neighbor)} · AS ${esc(b.local_as)} → ${esc(b.remote_as)}${b.switch_state ? `\n스위치: ${esc(b.switch_state)}` : ""}">
          <b>${b.state === "ESTABLISHED" ? "Established" : esc(b.state)}</b><small>${esc(b.source)} → ${esc(b.neighbor)}</small><small>${b.state === "ESTABLISHED" ? `경로 ${b.in_prefix ?? "-"}/${b.out_prefix ?? "-"} · ${dur(b.uptime_s)}` : `끊김 ${b.drops ?? 0}회`}${b.vlan ? ` · VLAN ${esc(b.vlan)}` : ""}</small></div>`).join("")}</td>`; };
      const lst = arr.filter(b => !q || `${b.edge} ${b.neighbor} ${b.switch} ${b.source}`.toLowerCase().includes(q));
      return `<section class="bm-t0"><h4>T0 ${esc(t0)} <small>로컬 AS ${esc(arr[0].local_as || "-")} · 세션 ${arr.filter(b => b.state === "ESTABLISHED").length}/${arr.length} · ${esc(arr[0].nsx)}</small></h4>
        <div class="bm-scroll"><table class="bm-m"><tr><th>Edge \\ 물리 피어</th>${peers.map(p => `<th>${esc(p)}</th>`).join("")}</tr>
          ${edges.map(e => { const one = arr.find(b => b.edge === e); return `<tr><th><span class="dot st-${esc(one.edge_state)}"></span>${esc(e)}<br><small>${esc(one.edge_cluster || "")}</small></th>${peers.map(p => cell(e, p)).join("")}</tr>`; }).join("")}</table></div>
        <table class="tbl bm-l"><tr><th>상태</th><th>Edge</th><th>Edge 업링크</th><th>세그먼트·VLAN</th><th>피어</th><th>피어 AS</th><th>물리 스위치</th><th>스위치가 보는 상태</th><th>수신/광고 경로</th><th>수립 후</th><th>끊김</th></tr>
          ${lst.map(b => `<tr class="${b.state !== "ESTABLISHED" ? "bad" : b.mismatch ? "warn" : ""}"><td>${b.state === "ESTABLISHED" ? (b.mismatch ? "불일치" : "정상") : "미수립"}</td><td>${esc(b.edge)}</td><td class="mono">${esc(b.source)}${b.uplink ? `<br><small>${esc(b.uplink)}</small>` : ""}</td>
            <td>${esc(b.segment || "")}${b.vlan ? ` · VLAN ${esc(b.vlan)}` : ""}</td><td class="mono">${esc(b.neighbor)}</td><td>${esc(b.remote_as)}</td><td>${b.switch ? esc(b.switch) : `<span class="muted">미수집</span>`}</td>
            <td>${esc(b.switch_state || (b.switch ? "-" : ""))}${b.switch_vrf ? ` <small>${esc(b.switch_vrf)}</small>` : ""}</td><td>${b.in_prefix ?? "-"} / ${b.out_prefix ?? "-"}</td><td>${b.state === "ESTABLISHED" ? dur(b.uptime_s) : ""}</td><td>${b.drops ?? ""}</td></tr>`).join("")}</table></section>`;
    };
    box.innerHTML = `<div class="net-wrap">${bar(`<input id="net-q" placeholder="Edge·피어·스위치 찾기" value="${esc(NT.q)}">`)}
      <div class="net-scroll">${B.length ? Object.entries(byT0).map(([t, a]) => card(t, a)).join("") :
        `<div class="wempty">NSX T0 BGP 세션이 없습니다 — NSX 커넥터(읽기 전용 Auditor)를 추가하면 <code>/policy/api/v1/infra/tier-0s/…/bgp/neighbors/status</code> 로 Edge ↔ 물리 스위치 세션을 가져옵니다.</div>`}
        <p class="small muted">NSX 상태 = Edge 별 connection_state(PolicyBgpNeighborStatus), 스위치 상태 = 스위치의 BGP 요약에서 Edge 업링크 주소로 찾은 피어. 둘이 다르면 '불일치'. 스위치를 못 찾으면 '미수집'(해당 스위치 커넥터를 추가).</p></div></div>`;
  }

  // ---------------------------------------------------------------- 포트맵(장비별)
  const PCLS = {peer: "연결됨", up: "링크 up(이웃 정보 없음)", alert: "다운(연결·설명 있음)", down: "미사용", disabled: "관리상 꺼짐"};
  const tail = n => (String(n).match(/(\d+(?:\/\d+)*)$/) || [, ""])[1];
  function labeler(ph) {                                      // 전면 패널 번호: 공통 모듈 번호(NX-OS 1/x) 는 빼고, 브레이크아웃 첫 레인(/1) 은 생략
    const segs = ph.map(p => tail(p.name).split("/"));
    const two = segs.filter(x => x.length >= 2);
    const dropFirst = two.length === segs.length && two.length > 1 && new Set(two.map(x => x[0])).size === 1;
    return p => { let x = tail(p.name).split("/"); if (dropFirst && x.length >= 2) x = x.slice(1); if (x.length === 2 && x[1] === "1") x = [x[0]];
      const t = x.join("/"); return t.length > 4 ? x[x.length - 1] : t; };
  }
  function panel(sw) {
    const ph = sw.ports.filter(p => p.kind === "phys");
    const pnum = labeler(ph).bind(null);
    const groups = [ph.filter(p => !(p.speed >= 40000)), ph.filter(p => p.speed >= 40000)].filter(g => g.length);
    const PW = 28, PH = 20, GAP = 4;
    let x = 10; const parts = [];
    groups.forEach(g => {
      const cols = Math.ceil(g.length / 2);
      g.forEach((p, i) => { const cx = x + Math.floor(i / 2) * (PW + GAP), cy = i % 2 ? 10 + PH + 14 : 10;
        const sel = NT.pmSel === `${sw.name}|${p.name}`;
        parts.push(`<g class="pp ${p.usage ? "u-" + p.usage : p.cls} ${p.cls === "alert" ? "alert" : ""} ${sel ? "sel" : ""}" data-pp="${esc(sw.name)}|${esc(p.name)}"><rect x="${cx}" y="${cy}" width="${PW}" height="${PH}" rx="2"/>
          <text x="${cx + PW / 2}" y="${cy + 14}">${esc(pnum(p))}</text><title>${esc(p.name)} — ${esc(USE[p.usage] || PCLS[p.cls] || p.cls)}${p.speed_txt ? ` · ${p.speed_txt}` : ""}${p.cfg && p.cfg.mode ? `\n${esc(cfgTxt(p.cfg))}` : ""}${p.peer.name ? `\n→ ${esc(p.peer.name)} ${esc(p.peer.port || "")}${p.peer.lost ? " (사라짐)" : ""}` : ""}${p.desc ? `\n설명: ${esc(p.desc)}` : ""}${p.vlan ? `\nVLAN ${esc(p.vlan)}` : ""}</title></g>`); });
      x += cols * (PW + GAP) + 18;
    });
    const w = Math.max(x, 200);
    return `<svg class="pm-panel" viewBox="0 0 ${w} ${PH * 2 + 26}" width="${w}" height="${PH * 2 + 26}">${parts.join("")}</svg>`;
  }
  const cfgTxt = c => !c ? "" : [c.mode === "trunk" ? `trunk ${c.trunk_vlans || "all"}${c.native ? ` native ${c.native}` : ""}` : c.mode === "access" || c.access_vlan ? `access ${c.access_vlan || 1}` : c.mode === "routed" ? `routed ${c.ip || ""}` : c.mode,
                                 c.channel ? `Po${c.channel}${c.lacp ? " " + c.lacp : ""}` : "", c.vrf ? `vrf ${c.vrf}` : "", c.mtu ? `MTU ${c.mtu}` : ""].filter(Boolean).join(" · ");
  function renderPorts(box) {
    const P = NT.pm;
    if (!P) { box.innerHTML = `<div class="net-wrap">${bar()}<div class="wempty">불러오는 중…</div></div>`; load(); return; }
    const S = P.summary, q = NT.q.toLowerCase();
    const bad = new Set(P.findings.filter(f => f.sev !== "info").map(f => f.device));
    const fsev = {down: "장애", warn: "주의", info: "참고"};
    const swCard = sw => {
      const rows = sw.ports.filter(p => (!NT.onlyUsed || p.peer.name || p.cls === "alert" || ["configured", "err"].includes(p.usage) || p.kind !== "phys" && p.state === "up") && (!q || `${p.name} ${p.peer.name || ""} ${p.desc}`.toLowerCase().includes(q) || sw.name.toLowerCase().includes(q)));
      const c = sw.counts;
      return `<section class="pm-card st-${esc(sw.state)}"><header><b>${esc(sw.name)}</b><small>${esc(sw.vendor)} ${esc(sw.model)} · ${esc(sw.os)} ${esc(sw.version)} · ${esc(sw.mgmt)}${sw.mlag && sw.mlag.state ? ` · ${esc(sw.mlag.kind)} ${esc(sw.mlag.state)}` : ""}</small>
          <span class="gap"></span><span class="pm-cnt">물리 ${c.phys} · 사용 <b>${(sw.usage || {}).in_use ?? c.up}</b> · 구성됨·미연결 ${(sw.usage || {}).configured ?? "-"} · 열린 미사용 ${(sw.usage || {}).open ?? "-"} · 닫힘 ${(sw.usage || {}).shut ?? "-"}${c.alert ? ` · <em class="bad">다운 ${c.alert}</em>` : ""} · ESXi ${c.hosts}
            ${sw.config && sw.config.updated ? ` · 구성 ${new Date(sw.config.updated * 1000).toLocaleTimeString()}${sw.config.changed_at ? ` <em class="bad">변경됨</em>` : ""}` : sw.config && sw.config.error ? ` · <em class="bad">구성 미수집</em>` : ""}</span></header>
        <div class="pm-pwrap">${panel(sw)}</div>
        <table class="tbl pm-t"><tr><th>포트</th><th>사용</th><th>링크</th><th>속도</th><th>연결 상대</th><th>상대 포트</th><th>구성(모드·VLAN·LAG·MTU)</th><th>설명</th><th></th></tr>
          ${rows.map(p => `<tr class="${p.cls === "alert" || p.usage === "err" ? "bad" : p.peer.lost || p.usage === "open" ? "warn" : ""} ${NT.pmSel === `${sw.name}|${p.name}` ? "sel" : ""}" data-pp="${esc(sw.name)}|${esc(p.name)}"><td class="mono">${esc(p.name)}</td>
            <td><i class="np-dot u-${esc(p.usage || "")}"></i>${esc(USE[p.usage] || "")}</td><td>${esc(p.state)}</td><td>${esc(p.speed_txt)}</td><td>${p.peer.name ? `<span class="pk ${esc(p.peer.kind)}">${{switch: "SW", host: "ESXi", device: "장치"}[p.peer.kind] || ""}</span> ${esc(p.peer.name)}` : ""}</td>
            <td class="mono">${esc(p.peer.port || "")}</td><td class="mono small">${esc(cfgTxt(p.cfg) || (p.vlan != null ? "vlan " + p.vlan : ""))}</td><td>${esc(p.desc || "")}</td><td><small>${esc(p.peer.proto || "")}${p.peer.lost ? " · 사라짐" : ""}</small></td></tr>`).join("") || `<tr><td colspan="9" class="muted">표시할 포트 없음</td></tr>`}</table></section>`;
    };
    const hostCard = h => `<section class="pm-card pm-h st-${esc(h.state)}"><header><b>${esc(h.name)}</b><small>${esc(h.cluster)} · ${esc(h.model || "")}</small><span class="gap"></span>
        <span class="pm-cnt">vmnic ${h.nics.length} · up ${h.up} · 스위치 연결 확인 ${h.connected}</span></header>
      <div class="pm-nics">${h.nics.map(n => `<div class="pm-nic ${n.state} ${n.mismatch ? "mis" : ""}"><div class="pm-nn"><b>${esc(n.name)}</b><small>${esc(n.speed_txt || (n.state === "down" ? "링크 없음" : ""))}</small></div>
          <div class="pm-arrow">${n.state === "up" ? "━━" : "╌╌"}</div>
          <div class="pm-peer">${n.peer.switch ? `<b>${esc(n.peer.switch)}</b> <span class="mono">${esc(n.peer.port)}</span>${n.peer.collected ? "" : ` <small class="muted">(미수집 스위치)</small>`}` : `<span class="muted">${n.state === "up" ? "상대 모름(LLDP 없음)" : "미연결"}</span>`}
            <br><small>${n.vswitch ? esc(n.vswitch) : "가상 스위치 없음"}${n.source.length ? ` · 출처 ${n.source.map(x => x === "switch" ? "스위치 LLDP" : "ESXi LLDP").join("+")}` : ""}</small>
            ${n.mismatch ? `<br><small class="bad">⚠ ${esc(n.mismatch)}</small>` : ""}</div></div>`).join("") || `<p class="muted small">물리 NIC 정보 없음</p>`}</div></section>`;
    const sws = P.switches.filter(sw => !NT.onlyBad || bad.has(sw.name));
    const hs = P.hosts.filter(h => (!NT.onlyBad || bad.has(h.name)) && (!q || h.name.toLowerCase().includes(q) || h.nics.some(n => `${n.peer.switch || ""}`.toLowerCase().includes(q))));
    box.innerHTML = `<div class="net-wrap">${bar(`<span class="chip">포트 사용 ${S.ports_used}/${S.ports} · 빈 포트 ${S.ports_free}</span>
        ${S.no_redundancy ? `<span class="chip warn">이중화 없음 ${S.no_redundancy}</span>` : ""}
        <label><input type="checkbox" id="pm-used" ${NT.onlyUsed ? "checked" : ""}> 연결된 포트만</label><label><input type="checkbox" id="pm-bad" ${NT.onlyBad ? "checked" : ""}> 문제 장비만</label>
        <input id="net-q" placeholder="포트·장비·호스트 찾기" value="${esc(NT.q)}"><span class="gap"></span>
        <span class="lg pm-lg">${Object.entries(USE).map(([k, l]) => `<i class="np-dot u-${k}"></i>${l}`).join(" ")}</span>`)}
      <div class="net-scroll">
        ${P.findings.length ? `<section class="pm-find"><h4>점검 결과 <small>장애 ${S.down} · 주의 ${S.warn} · 참고 ${S.info}</small></h4><ul>${P.findings.slice(0, 60).map(f => `<li class="${f.sev}"><span class="fs">${fsev[f.sev]}</span><b>${esc(f.device)}</b> ${esc(f.text)}</li>`).join("")}</ul></section>`
          : `<section class="pm-find ok"><h4>점검 결과 — 문제 없음</h4></section>`}
        <h3 class="pm-h3">스위치 <small>${sws.length}</small></h3>${sws.map(swCard).join("") || `<p class="muted">수집된 스위치 없음</p>`}
        <h3 class="pm-h3">ESXi 호스트 vmnic <small>${hs.length}</small></h3><div class="pm-hgrid">${hs.map(hostCard).join("") || `<p class="muted">vCenter 호스트 없음</p>`}</div>
        <p class="small muted">스위치 포트 ↔ vmnic 은 스위치 LLDP/CDP 와 ESXi 쪽 LLDP/CDP(QueryNetworkHint, 15분) 를 합쳐서 그립니다. 둘이 가리키는 포트가 다르면 '불일치'. 점검: 가상 스위치 업링크가 한 스위치에만 연결(이중화 없음)·업링크 다운·속도 혼재·포트/NIC 속도 불일치.</p></div></div>`;
  }
  function sideDefault(downs) {
    const s = NT.d.summary;
    return `<h4>다운·사라진 링크 <small>${downs.length}</small></h4>${downs.length ? `<ul class="net-down">${downs.slice(0, 40).map(l => `<li data-nid="${esc(l.a)}"><b>${esc(nodeLabel(l.a))}</b> ${esc(l.a_port)} → ${esc(nodeLabel(l.b))} ${esc(l.b_port || "")}</li>`).join("")}</ul>` : `<p class="muted">없음</p>`}
      <h4>수집 커넥터</h4><ul class="net-col">${(s.collectors || []).map(c => `<li class="${c.state === "ok" ? "ok" : "bad"}"><b>${esc(c.name)}</b> <small>${esc(c.type)} · ${esc(c.state || "")}</small>${c.error ? `<br><small>${esc(c.error)}</small>` : ""}</li>`).join("") || "<li>없음</li>"}</ul>
      <p class="small muted">장비를 누르면 인터페이스·이웃·MLAG/vPC·BGP 상세가 보입니다.</p>`;
  }
  const nodeLabel = id => (NT.d.nodes.find(n => n.id === id) || {label: id.split(":").slice(1).join(":")}).label;
  async function side(id) {
    const el = $("#net-side"); if (!el) return;
    const n = NT.d.nodes.find(x => x.id === id) || {}; const g = id.startsWith("grp:");
    if (n.kind === "edge") {
      const bs = (NT.d.bgp || []).filter(b => b.edge === n.label);
      const plc = NT.d.links.filter(l => l.kind === "placement" && l.b === id).map(l => nodeLabel(l.a));
      el.innerHTML = `<button class="x" id="net-close">✕</button><h4>${esc(n.label)} <small>NSX Edge</small></h4>
        <dl class="net-dl"><dt>T0</dt><dd>${esc(n.tier0 || "-")} · AS ${esc(n.local_as || "-")}</dd><dt>Edge 클러스터</dt><dd>${esc(n.edge_cluster || "-")}</dd>
          <dt>관리</dt><dd>${esc(n.mgmt || "-")}</dd><dt>실행 호스트</dt><dd>${esc(plc.join(", ") || "-")}</dd><dt>커넥터</dt><dd>${esc(n.connector || "")}</dd></dl>
        <h5>BGP 세션 <small>${bs.filter(b => b.state === "ESTABLISHED").length}/${bs.length}</small></h5>
        <table class="tbl"><tr><th>업링크</th><th>피어</th><th>스위치</th><th>상태</th></tr>${bs.map(b => `<tr class="${b.state !== "ESTABLISHED" ? "bad" : ""}"><td class="mono">${esc(b.source)}${b.vlan ? `<br><small>VLAN ${esc(b.vlan)}</small>` : ""}</td>
          <td class="mono">${esc(b.neighbor)}<br><small>AS ${esc(b.remote_as)}</small></td><td>${esc(b.switch || "미수집")}${b.switch_state ? `<br><small>${esc(b.switch_state)}</small>` : ""}</td><td>${esc(b.state)}${b.state === "ESTABLISHED" ? `<br><small>${dur(b.uptime_s)}</small>` : ""}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">세션 없음</td></tr>`}</table>
        <p class="small"><a href="/noc/d/nsx">NSX 도메인 보기 →</a></p>`;
      return;
    }
    if (g || n.kind !== "switch") {
      const rel = NT.d.links.filter(l => l.a === id || l.b === id);
      const KL = {phys: "물리 링크", bgp: "BGP", placement: "배치", logical: "논리 연결", vnic: "vNIC", pod: "Pod", pool: "Avi 풀 멤버", mgmt: "관리"};
      const by = {}; rel.forEach(l => { const k = l.kind || "phys"; (by[k] = by[k] || []).push(l); });
      const attrs = [["클러스터", n.cluster], ["vCenter", n.vcenter], ["관리", n.mgmt], ["IP", (n.ips || []).slice(0, 4).join(", ") || n.ip], ["OS", n.os], ["호스트", n.host],
                     ["vCPU·메모리", n.vcpu ? `${n.vcpu} vCPU · ${n.mem_gb} GB` : ""], ["전원", n.power], ["네임스페이스", n.ns], ["노드", n.node_name], ["K8s 클러스터", n.k8s_cluster],
                     ["네트워크", (n.networks || []).join(", ")], ["그룹", n.group]].filter(([, v]) => v);
      el.innerHTML = `<button class="x" id="net-close">✕</button><h4>${esc(n.label || "호스트 묶음")} <small>${esc(KIND[n.kind] || n.kind || "")}</small></h4>
        ${n.detail ? `<p class="small">${esc(n.detail)}</p>` : ""}${(n.nodes_detail || []).length ? `<ul class="net-col">${n.nodes_detail.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
        ${attrs.length ? `<dl class="net-dl">${attrs.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : ""}
        ${Object.entries(by).map(([k, ls]) => `<h5>${KL[k] || k} <small>${ls.length}</small></h5><table class="tbl">${ls.slice(0, 60).map(l => { const o = l.a === id ? l.b : l.a;
          const mp = l.a === id ? l.a_port : l.b_port, op = l.a === id ? l.b_port : l.a_port;
          return `<tr class="${l.state === "down" ? "bad" : ""}" data-nid="${esc(o)}"><td>${esc(nodeLabel(o))}</td><td class="mono">${esc(op || "")}</td><td class="mono">${esc(mp || "")}</td><td>${l.state === "down" ? "다운" : ""}</td></tr>`; }).join("")}</table>`).join("")
          || `<p class="muted small">연결 없음</p>`}`;
      return;
    }
    el.innerHTML = `<p class="muted">불러오는 중…</p>`;
    let s; try { s = await A.api("GET", `/api/network/device/${encodeURIComponent(n.label)}`, undefined, {background: true}); } catch (e) { el.innerHTML = `<p class="vc-err">${esc(e.message)}</p>`; return; }
    const pnl = n.panel || [], cfgm = s.config || {}, us = n.usage || {};
    const big = (() => { const cols = Math.ceil(pnl.length / 2), BW = 17, BG = 3, H = 2 * 18 + 8, lab = labeler(pnl.map(p => ({name: p.n})));
      return `<svg class="pm-panel big" viewBox="0 0 ${12 + cols * (BW + BG)} ${H}" width="100%">${pnl.map((p, i) => { const c = Math.floor(i / 2), r = i % 2, x = 6 + c * (BW + BG), y = 4 + r * 18;
        return `<g class="pp2" data-port="${esc(p.n)}"><rect class="np u-${p.u}${p.lost ? " lost" : ""}" x="${x}" y="${y}" width="${BW}" height="15" rx="2"/><text x="${x + BW / 2}" y="${y + 11}">${esc(lab({name: p.n}))}</text>
          <title>${esc(p.n)} — ${USE[p.u]}${p.p ? `\n→ ${esc(p.p)}` : ""}${p.m ? `\n${esc(p.m)}` : ""}${p.d ? `\n${esc(p.d)}` : ""}</title></g>`; }).join("")}</svg>`; })();
    const rowsP = pnl.filter(p => p.u !== "shut" || p.p || p.d).map(p => `<tr class="${p.u === "err" || (p.u === "configured" && p.p) ? "bad" : p.u === "open" ? "warn" : ""}"><td class="mono">${esc(p.n)}</td>
        <td class="nw"><i class="np-dot u-${p.u}"></i>${USE[p.u]}</td><td>${esc(p.m || "")}</td><td>${esc(p.p || p.d || "")}</td></tr>`).join("");
    el.innerHTML = `<button class="x" id="net-close">✕</button><h4>${esc(s.name)} <small>${esc(s.vendor)} ${esc(s.model)}</small></h4>
      <dl class="net-dl"><dt>OS</dt><dd>${esc(s.os)} ${esc(s.version)}</dd><dt>관리</dt><dd>${esc(s.mgmt)}</dd><dt>S/N</dt><dd>${esc(s.serial || "-")}</dd>
        <dt>가동</dt><dd>${s.uptime ? Math.floor(s.uptime / 86400) + "일" : "-"}</dd>
        ${s.mlag && s.mlag.state ? `<dt>${esc(s.mlag.kind)}</dt><dd>${esc(s.mlag.state)} · peer-link ${esc(s.mlag.peer_link || "-")} · ${esc(s.mlag.neg || "")}</dd>` : ""}
        <dt>구성</dt><dd>${cfgm.updated ? `${cfgm.lines}줄 · ${new Date(cfgm.updated * 1000).toLocaleTimeString()} 수집${cfgm.changed_at ? ` · <b class="warn">변경 ${new Date(cfgm.changed_at * 1000).toLocaleString()}</b>` : ""}` : cfgm.error ? `<span class="vc-err">${esc(cfgm.error)}</span>` : "미수집"}</dd>
        <dt>커넥터</dt><dd>${esc(s.connector)} · ${new Date(s.updated * 1000).toLocaleTimeString()}</dd></dl>
      ${s.error ? `<p class="vc-err small">${esc(s.error)}</p>` : ""}
      <h5>전면 포트 <small>사용 ${us.in_use ?? "-"} · 구성됨·미연결 ${us.configured ?? "-"} · 열린 미사용 ${us.open ?? "-"} · 닫힘 ${us.shut ?? "-"}${us.err ? ` · 오류 ${us.err}` : ""}</small></h5>${big}
      ${cfgm.diff && cfgm.changed_at ? `<details class="cfg-diff"><summary>최근 구성 변경 +${cfgm.diff.added}/−${cfgm.diff.removed}줄 ${esc((cfgm.diff.blocks || []).slice(0, 4).join(", "))}</summary><pre>${esc((cfgm.diff.sample || []).join("\n"))}</pre></details>` : ""}
      <h5>포트 구성 <small>${pnl.length}개(닫힌 빈 포트 제외)</small> ${cfgm.updated && A.can && A.can("operate") ? `<button class="btn-sm" id="net-cfg" data-dev="${esc(s.name)}">running-config 보기</button>` : ""}</h5>
      <table class="tbl"><tr><th>포트</th><th>사용</th><th>모드·VLAN</th><th>상대·설명</th></tr>${rowsP || `<tr><td colspan="4" class="muted">포트 없음</td></tr>`}</table>
      <h5>LLDP/CDP 이웃 <small>${s.neighbors.length}</small></h5><table class="tbl"><tr><th>로컬</th><th>상대</th><th>상대 포트</th><th></th></tr>${s.neighbors.slice(0, 120).map(x => `<tr class="${x.state === "lost" ? "bad" : ""}"><td class="mono">${esc(x.local)}</td><td>${esc(x.remote)}</td><td class="mono">${esc(x.remote_port || "")}</td><td><small>${esc(x.proto || "")}${x.state === "lost" ? " 사라짐" : ""}</small></td></tr>`).join("")}</table>
      ${s.bgp.length ? `<h5>BGP <small>${s.bgp.filter(b => String(b.state).toLowerCase() === "established").length}/${s.bgp.length}</small></h5><table class="tbl"><tr><th>피어</th><th>AS</th><th>VRF</th><th>상태</th></tr>${s.bgp.map(b => `<tr class="${String(b.state).toLowerCase() === "established" ? "" : "bad"}"><td class="mono">${esc(b.peer)}</td><td>${esc(b.asn ?? "")}</td><td>${esc(b.vrf || "")}</td><td>${esc(b.state)}</td></tr>`).join("")}</table>` : ""}
      <p class="small"><a href="/noc/d/net">네트워크 도메인 로그 보기 →</a></p>`;
  }
  async function showConfig(dev) {
    const el = $("#net-side"); if (!el) return;
    let c; try { c = await A.api("GET", `/api/network/device/${encodeURIComponent(dev)}/config`); } catch (e) { A.fail ? A.fail("구성", e) : alert(e.message); return; }
    el.innerHTML = `<button class="x" id="net-cfg-back">←</button><h4>${esc(c.name)} running-config <small>${c.lines || 0}줄 · ${c.updated ? new Date(c.updated * 1000).toLocaleString() : ""} · 비밀값 가림</small></h4>
      <p class="small muted">VLAN ${Object.keys(c.vlans || {}).length}개 · logging ${esc((c.global.logging || []).join(", ") || "-")} · NTP ${esc((c.global.ntp || []).join(", ") || "-")} · LLDP ${c.global.lldp === false ? "꺼짐" : "켜짐"}</p>
      <pre class="cfg-pre">${esc(c.text || c.error || "")}</pre>`;
  }

  document.addEventListener("click", e => {
    if (!$("#pg-network") || $("#pg-network").hidden) return;
    const v = e.target.closest("[data-nv]"); if (v) { NT.view = v.dataset.nv; pref("net.view", NT.view); NT.cw = 0; if (NT.view === "ports" && !NT.pm) load(); else render(); return; }
    const pp = e.target.closest("[data-pp]"); if (pp && $("#pg-network").contains(pp)) {
      NT.pmSel = NT.pmSel === pp.dataset.pp ? null : pp.dataset.pp; const sc = $(".net-scroll"), top = sc ? sc.scrollTop : 0; render();
      const sc2 = $(".net-scroll"); if (sc2) sc2.scrollTop = top;
      if (pp.tagName !== "TR") { const row = [...document.querySelectorAll("tr[data-pp]")].find(r => r.dataset.pp === NT.pmSel); if (row) row.scrollIntoView({block: "center"}); }
      return; }
    const n = e.target.closest("[data-nid]"); if (n && $("#pg-network").contains(n)) { NT.sel = n.dataset.nid; render(); return; }
    if (e.target.id === "net-close") { NT.sel = null; render(); }
    if (e.target.id === "net-cfg") { showConfig(e.target.dataset.dev); return; }
    if (e.target.id === "net-cfg-back") { side(NT.sel); }
  });
  document.addEventListener("change", e => {
    if (e.target.id === "net-hosts") { NT.hosts = e.target.checked; pref("net.hosts", NT.hosts); load(); }
    if (e.target.id === "net-ext") { NT.ext = e.target.checked; pref("net.ext", NT.ext); render(); }
    if (e.target.id === "net-edges") { NT.edges = e.target.checked; pref("net.edges", NT.edges); render(); }
    if (e.target.id === "pm-used") { NT.onlyUsed = e.target.checked; pref("net.used", NT.onlyUsed); render(); }
    if (e.target.id === "pm-bad") { NT.onlyBad = e.target.checked; render(); }
    if (e.target.dataset && e.target.dataset.layer) { if (e.target.checked) NT.layers.add(e.target.dataset.layer); else NT.layers.delete(e.target.dataset.layer);
      pref("net.layers", [...NT.layers]); NT.cw = 0; load(); }
    if (e.target.id === "net-place") { NT.place = e.target.checked; pref("net.place", NT.place); render(); }
    if (e.target.id === "net-vms") { NT.vms = Number(e.target.value); pref("net.vms", NT.vms); NT.cw = 0; load(); }
  });
  let qt; document.addEventListener("input", e => { if (e.target.id === "net-q") { NT.q = e.target.value; clearTimeout(qt); qt = setTimeout(() => { const pos = e.target.selectionStart; render(); const i = $("#net-q"); if (i) { i.focus(); i.setSelectionRange(pos, pos); } }, 250); } });
  addEventListener("resize", () => { NT.cw = 0; });
  window.NOCNET = {load, render};
})();
