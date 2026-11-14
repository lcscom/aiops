/* NSX 세그먼트 트래픽(2.21.0) — NSX 세그먼트에 붙은 모든 VM(vNIC)의 수신·송신 대역폭·패킷·드롭
   vCenter 실시간(20초) 성능 카운터 net.received/transmitted·packets·dropped + NSX 세그먼트 정보(게이트웨이·Tier-1)·포트 통계(DFW 차단) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const enc = encodeURIComponent;
  const st = {vm: "", vmvc: "", vmErr: "", vmFocus: false, vms: null, vmData: null, vmHist: 0, vmHistData: null, vmBusy: false, window: 300, scope: "nsx", ov: null, sel: "", seg: null, q: "", vq: "", sort: "tot", dir: -1, hist: 0, histData: null, ai: null, busy: false, segBusy: false};
  const WIN = [[300, "최근 5분"], [900, "최근 15분"], [3600, "최근 1시간"]];
  const SCOPES = [["nsx", "NSX 세그먼트(오버레이·VLAN)"], ["vds", "VDS 포트그룹(NSX 제외)"], ["std", "표준 vSwitch 포트그룹"], ["all", "모든 네트워크"], ["avi", "Avi 가상 서비스 뒤 VM"], ["vm", "VM 별 조회"]];
  const KIND = {nsx: ["NSX", "nsx"], dvpg: ["VDS", "vds"], std: ["vSS", "std"], avi: ["Avi", "avi"]};
  const kindB = k => { const m = KIND[k]; return m ? `<span class="st-k ${m[1]}">${m[0]}</span>` : ""; };
  const aviB = v => (v.avi || []).length ? ` <span class="st-k avi" title="${esc(v.avi.map(a => `${a.vs} · ${a.pool}${a.port ? ":" + a.port : ""}`).join("\n"))}">Avi ${esc(v.avi.map(a => a.vs).slice(0, 2).join(", "))}${v.avi.length > 2 ? ` +${v.avi.length - 2}` : ""}</span>` : "";

  const bps = x => { x = Number(x) || 0; return x >= 1e9 ? `${(x / 1e9).toFixed(2)} Gbps` : x >= 1e6 ? `${(x / 1e6).toFixed(1)} Mbps` : x >= 1e3 ? `${(x / 1e3).toFixed(0)} Kbps` : `${Math.round(x)} bps`; };
  const short = x => x >= 1e9 ? `${(x / 1e9).toFixed(1)}G` : x >= 1e6 ? `${(x / 1e6).toFixed(x >= 1e8 ? 0 : 1)}M` : x >= 1e3 ? `${Math.round(x / 1e3)}K` : `${Math.round(x)}`;
  const hms = ts => new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
  const num = x => x == null ? "—" : Math.round(x).toLocaleString();
  const pps = x => x == null ? "—" : x >= 1000 ? `${(x / 1000).toFixed(1)}k` : x.toFixed(x < 10 ? 1 : 0);
  const hm = ts => new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  const mdt = ts => new Date(ts * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"});

  function spark(xs, w = 90, h = 22) {
    if (!xs || xs.length < 2) return `<svg class="st-spark" viewBox="0 0 ${w} ${h}"></svg>`;
    const mx = Math.max(...xs, 1), dx = w / (xs.length - 1);
    const pts = xs.map((v, i) => `${(i * dx).toFixed(1)},${(h - 1 - v / mx * (h - 3)).toFixed(1)}`).join(" ");
    return `<svg class="st-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}"/></svg>`;
  }
  function chart(ts, rx, tx, drops, tick = hm, single = "") {
    const W = 760, H = 170, P = 52, n = Math.max(rx.length, tx.length);
    if (n < 2) return `<p class="muted small">표본이 아직 부족합니다(20초 간격 실시간 통계).</p>`;
    const mx = Math.max(...rx, ...tx, 1), X = i => P + i * (W - P - 6) / (n - 1), Y = v => H - 18 - v / mx * (H - 30);
    const line = (xs, cls) => `<polyline class="${cls}" points="${xs.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" ")}"/>`;
    const area = (xs, cls) => `<polygon class="${cls}" points="${X(0)},${Y(0)} ${xs.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" ")} ${X(n - 1)},${Y(0)}"/>`;
    const ys = [0, 0.5, 1].map(f => `<line class="st-grid" x1="${P}" x2="${W}" y1="${Y(mx * f)}" y2="${Y(mx * f)}"/><text class="st-ax" x="${P - 4}" y="${Y(mx * f) + 4}" text-anchor="end">${esc(short(mx * f))}</text>`).join("");
    const k = Math.max(1, Math.floor(n / (tick === mdt ? 4 : 6)));        // 날짜가 붙은 긴 눈금은 덜 촘촘하게
    const xt = ts && ts.length === n ? ts.map((t, i) => (i % k && i !== n - 1) || (i !== n - 1 && n - 1 - i < k) ? ""      // 마지막 눈금은 오른쪽 끝에 맞춰(잘림 방지)
      : `<text class="st-ax" x="${X(i)}" y="${H - 3}" text-anchor="${i === 0 ? "start" : i === n - 1 ? "end" : "middle"}">${esc(tick(t))}</text>`).join("") : "";
    const dr = (drops || []).map((v, i) => v > 0 ? `<line class="st-drop" x1="${X(i)}" x2="${X(i)}" y1="${Y(0)}" y2="${Y(0) - 8}"><title>드롭 ${num(v)}</title></line>` : "").join("");
    return `<svg class="st-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="수신·송신 대역폭 추이">${ys}${area(rx, "st-rxa")}${line(rx, "st-rx")}${line(tx, "st-tx")}${dr}${xt}</svg>
      <div class="small muted st-leg">${single ? `<i class="rx"></i><span>${esc(single)}</span>` : `<i class="rx"></i>수신(Rx) <i class="tx"></i>송신(Tx)${drops && drops.length ? ` <i class="dr"></i>드롭 발생` : ""}`}</div>`;
  }

  const SEQ = {ov: 0, seg: 0, hist: 0, vm: 0, vmh: 0};                   // 늦게 도착한 이전 응답은 버림(빠른 전환 시 다른 데이터가 덮어쓰지 않게)
  async function load(fresh = false) {
    if (st.scope === "vm") return loadVms(fresh);
    const my = ++SEQ.ov;
    st.busy = true; render();
    let ov = null;
    try { ov = await A.api("GET", `/api/segtraffic?window=${st.window}&scope=${st.scope}${fresh ? "&fresh=1" : ""}`); }
    catch (e) { if (my === SEQ.ov) A.fail("세그먼트 트래픽을 불러오지 못했습니다", e); }
    if (my !== SEQ.ov) return;
    st.ov = ov; st.busy = false;
    if (st.sel && !(st.ov && st.ov.segments.some(s => s.key === st.sel))) st.sel = "";
    render();
    if (st.sel) loadSeg(st.sel);
  }
  async function loadVms(fresh = false) {
    const my = ++SEQ.ov;
    st.busy = true; render();
    let r = null;
    try { r = await A.api("GET", `/api/segtraffic/vms?window=${st.window}${fresh ? "&fresh=1" : ""}`); }
    catch (e) { if (my === SEQ.ov) A.fail("VM 목록을 불러오지 못했습니다", e); }
    if (my !== SEQ.ov) return;
    st.vms = r; st.busy = false;
    if (st.vm && r && !r.items.some(v => v.vm === st.vm && (!st.vmvc || v.vcenter === st.vmvc))) {
      A.toast && A.toast("VM 을 찾지 못했습니다", st.vm, "warn", 6000);
      st.vm = ""; st.vmvc = "";
    }
    if (!st.vm && r && r.items.length) { st.vm = r.items[0].vm; st.vmvc = r.items[0].vcenter; }
    render();
    if (st.vm) loadVm(st.vm, st.vmvc);
  }
  async function loadVm(name, vc = "") {
    const my = ++SEQ.vm;
    st.vm = name; st.vmvc = vc || ""; st.vmData = null; st.vmHistData = null; st.vmErr = ""; st.vmBusy = true; render();
    let r = null;
    try { r = await A.api("GET", `/api/segtraffic/vm?name=${enc(name)}&window=${st.window}${vc ? "&vcenter=" + enc(vc) : ""}`); }
    catch (e) { if (my === SEQ.vm) { A.fail("VM 트래픽을 불러오지 못했습니다", e); st.vmErr = (e && e.message) || "조회 실패"; } }
    if (my !== SEQ.vm || st.vm !== name) return;
    st.vmData = r; st.vmBusy = false; render();
    if (st.vmFocus) { st.vmFocus = false; const b = $$("[data-vmsel]").find(x => x.dataset.vmsel === name && (!st.vmvc || x.dataset.vc === st.vmvc)); if (b) b.focus({preventScroll: true}); }
    if (st.vmHist) loadVmHist();
  }
  async function loadVmHist() {
    const my = ++SEQ.vmh, name = st.vm;
    let h;
    try { h = await A.api("GET", `/api/segtraffic/vm/history?name=${enc(name)}&hours=${st.vmHist}${st.vmvc ? "&vcenter=" + enc(st.vmvc) : ""}`, undefined, {background: true}); }
    catch { h = {ts: [], series: {}, error: "조회 실패"}; }
    if (my !== SEQ.vmh || name !== st.vm) return;
    st.vmHistData = h; render();
  }
  function openVm(name, vc = "", byKey = false) {         // 다른 범위의 표에서 VM 을 고르면 'VM 별 조회'로
    st.scope = "vm"; st.vm = name; st.vmvc = vc; st.sel = ""; st.q = ""; st.vq = ""; st.vmFocus = byKey; load();
  }
  function vmList(o) {
    const f = st.q.toLowerCase();
    const V = o.items.filter(v => !f || `${v.vm} ${v.host} ${v.ips.join(" ")} ${v.avi.join(" ")}`.toLowerCase().includes(f));
    const mx = Math.max(1, ...o.items.map(v => v.rx_bps + v.tx_bps));
    const kb = v => v.kinds.map(k => kindB(k)).join("");
    return `<div class="st-side"><div class="rd-tools"><input id="st-q" placeholder="VM·호스트·IP·Avi 검색" value="${esc(st.q)}" aria-label="VM 검색"></div>
      <div class="st-segs" role="listbox" aria-label="VM">${V.slice(0, 1000).map(v => `<button class="st-seg ${v.vm === st.vm && (!st.vmvc || v.vcenter === st.vmvc) ? "on" : ""}" data-vmsel="${esc(v.vm)}" data-vc="${esc(v.vcenter)}" role="option" aria-selected="${v.vm === st.vm && (!st.vmvc || v.vcenter === st.vmvc)}">
          <span class="st-sn">${esc(v.vm)}${v.drops ? ` <b class="st-db" title="드롭 패킷">드롭 ${num(v.drops)}</b>` : ""}</span>
          <small>${kb(v)}${esc([v.host, `vNIC ${v.vnics}`, v.avi.length ? "Avi " + v.avi.join(", ") : ""].filter(Boolean).join(" · "))}</small>
          <span class="st-bar"><i class="rx" style="width:${(v.rx_bps / mx * 100).toFixed(1)}%"></i><i class="tx" style="width:${(v.tx_bps / mx * 100).toFixed(1)}%"></i></span>
          <span class="st-sr">${v.has_data ? `↓ ${bps(v.rx_bps)} · ↑ ${bps(v.tx_bps)}` : `<span class="muted">${v.power === "poweredOn" ? "성능 통계 없음" : "꺼짐"}</span>`}</span></button>`).join("")
        || `<p class="muted small pad">${o.items.length ? "검색 결과가 없습니다." : "네트워크에 연결된 VM 이 없습니다."}</p>`}</div></div>`;
  }
  function vmDetail() {
    if (!st.vm) return `<div class="rd-card"><p class="muted">왼쪽에서 VM 을 고르세요.</p></div>`;
    const d = st.vmData;
    if (!st.vmBusy && !d) return `<div class="rd-card"><h4>${esc(st.vm)}</h4><p class="cc-na small">VM 트래픽을 불러오지 못했습니다${st.vmErr ? " — " + esc(st.vmErr) : ""}</p><button class="btn-sm" id="st-vmretry">다시 시도</button></div>`;
    if (st.vmBusy || !d) return `<div class="rd-card"><h4>${esc(st.vm)}</h4><p class="muted">VM 의 vNIC·성능 통계를 읽는 중…</p></div>`;
    const t = d.totals, kv = (k, v) => v || v === 0 ? `<span>${k}</span><b>${v}</b>` : "";
    const head = `<div class="rd-card"><h4>${esc(d.vm)} ${d.power !== "poweredOn" ? `<span class="rd-b unk">꺼짐</span>` : ""} <small>${esc(d.vcenter)}</small>
        <button class="btn-sm st-tl" data-tl="${esc(d.vm)}">VM 일대기</button></h4>
      <div class="rv-kv">${kv("호스트", esc(d.host))}${kv("클러스터", esc(d.cluster))}${kv("IP", esc(d.ips.join(", ")))}${kv("vNIC", num(d.vnics.length))}
        ${kv("수신 · 송신(평균)", t.has_data ? `${bps(t.rx_bps)} · ${bps(t.tx_bps)}` : "—")}${kv("최대(합)", t.has_data ? bps(t.peak_bps) : "")}${kv("패킷/초", t.has_data ? `${pps(t.rx_pps)} / ${pps(t.tx_pps)}` : "")}
        ${kv("드롭(vNIC)", t.has_data ? num(t.drops) : "")}${kv("DFW 차단(NSX 누적)", d.vnics.some(v => v.nsx) ? num(t.dfw) : "")}
        ${kv("Avi 가상 서비스", d.avi.length ? d.avi.map(a => `${kindB("avi")}${esc(a.vs)} <span class="muted">${esc(a.pool)}${a.port ? ":" + esc(a.port) : ""}</span>`).join("<br>") : "")}</div></div>`;
    const c = d.chart;
    const ch = `<div class="rd-card"><h4><span>대역폭 추이</span> <small><span>${WIN.find(w => w[0] === st.window)[1]}</span> · <span>20초 간격</span> · <span>모든 vNIC 합계</span></small></h4>
      ${t.has_data ? chart(c.ts, c.rx_bps, c.tx_bps, c.drops, st.window <= 900 ? hms : hm) : `<p class="muted small">이 VM 의 vNIC 성능 통계를 받지 못했습니다 — VM 전원·vNIC 연결·vCenter 통계 수준을 확인하세요.</p>`}
      <div class="st-hist"><label class="small">과거 사용량 <select id="st-vmhist" aria-label="과거 사용량 기간"><option value="0">끄기</option>${[[24, "24시간"], [72, "3일"], [168, "7일"]].map(([v, l]) => `<option value="${v}" ${st.vmHist === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <span class="muted small">vCenter 과거 통계(net.usage — 24시간 5분, 7일 30분 간격)</span></div>${vmHistBlock()}</div>`;
    const rows = d.vnics.map(v => `<tr><td><b>${esc(v.label || "vNIC")}</b><br><small class="muted">${esc(v.mac || "")}${v.ips && v.ips.length ? " · " + esc(v.ips.join(", ")) : ""}${!v.connected ? " · 연결 끊김" : ""}</small></td>
        <td>${kindB((v.net || {}).kind)}<b>${esc((v.net || {}).name || v.network || "")}</b>${aviB(v)}<br><small class="muted">${esc([(v.net || {}).gateway, (v.net || {}).connected_to].filter(Boolean).join(" · "))}</small></td>
        <td class="num">${v.has_data ? bps(v.rx_bps) : "—"}</td><td class="num">${v.has_data ? bps(v.tx_bps) : "—"}</td><td class="num">${v.has_data ? bps(v.peak_bps) : "—"}</td>
        <td class="num small">${v.has_data ? `${pps(v.rx_pps)} / ${pps(v.tx_pps)}` : "—"}</td>
        <td class="num ${v.drop_rx + v.drop_tx ? "cc-na" : "muted"}">${v.has_data ? `${num(v.drop_rx)} / ${num(v.drop_tx)}` : "—"}</td>
        <td class="num ${(v.nsx || {}).dfw_drop ? "cc-na" : "muted"}">${v.nsx ? num(v.nsx.dfw_drop) : "—"}</td><td>${spark(v.spark)}</td></tr>`).join("");
    return head + ch + `<div class="rd-card"><h4><span>vNIC 별 트래픽</span></h4><div class="st-tw"><table class="rd-t st-t"><thead><tr><th>vNIC</th><th>네트워크</th><th class="num">수신(Rx)</th><th class="num">송신(Tx)</th>
      <th class="num">최대(합)</th><th class="num">패킷/초</th><th class="num">드롭(vNIC)</th><th class="num">DFW 차단</th><th>추이</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  }
  function vmHistBlock() {
    if (!st.vmHist) return "";
    const h = st.vmHistData;
    if (!h) return `<p class="muted small">읽는 중…</p>`;
    const sr = h.series || {};
    if (!h.ts || h.ts.length < 2) return `<p class="muted small">${esc(h.error || "과거 통계가 없습니다.")}</p>`;
    return sr.rx_bps && sr.tx_bps ? chart(h.ts, sr.rx_bps, sr.tx_bps, [], mdt) : chart(h.ts, sr.usage_bps || [], [], [], mdt, "사용량(수신+송신)");
  }
  async function loadSeg(key) {
    const my = ++SEQ.seg;
    st.sel = key; st.seg = null; st.ai = null; st.histData = null;
    if (!key) { st.segBusy = false; render(); if (st.hist) loadHist(); return; }
    st.segBusy = true; render();
    let r = null;
    try { r = await A.api("GET", `/api/segtraffic/segment?key=${enc(key)}&window=${st.window}&scope=${st.scope}`); }
    catch (e) { if (my === SEQ.seg) A.fail("세그먼트 상세를 불러오지 못했습니다", e); }
    if (my !== SEQ.seg || st.sel !== key) return;
    st.seg = r; st.segBusy = false; render();
    if (st.hist) loadHist();
  }
  async function loadHist() {
    const my = ++SEQ.hist, key = st.sel;
    let h;
    try { h = await A.api("GET", `/api/segtraffic/history?key=${enc(key)}&hours=${st.hist}&scope=${st.scope}`, undefined, {background: true}); }
    catch { h = {points: []}; }
    if (my !== SEQ.hist || key !== st.sel) return;
    st.histData = h; render();
  }

  // ------------------------------------------------------------------ 화면
  function kpis(o) {
    const t = o.totals;
    const k = (l, v, cls = "") => `<div class="kpi"><span>${l}</span><b class="${cls}">${v}</b></div>`;
    if (o.scope === "avi") {
      return `<div class="kpis st-kpis">${k("가상 서비스 수", num(t.segments))}${k("백엔드 VM · vNIC", `${num(t.vms)} · ${num(t.vnics)}`)}${k("VIP 대역폭 합계(Avi 최근 1분)", bps(t.avi_bw))}
        ${k("백엔드 vNIC 수신", bps(t.rx_bps))}${k("백엔드 vNIC 송신", bps(t.tx_bps))}${k("드롭 패킷", num(t.drops), t.drops ? "cc-na" : "")}</div>`;
    }
    return `<div class="kpis st-kpis">${k(o.scope === "nsx" ? "세그먼트 수" : "네트워크 수", num(t.segments))}${k("VM · vNIC", `${num(t.vms)} · ${num(t.vnics)}`)}${k("수신 합계(평균)", bps(t.rx_bps))}
      ${k("송신 합계(평균)", bps(t.tx_bps))}${k("드롭 패킷", num(t.drops), t.drops ? "cc-na" : "")}${k("카운터 없음(켜진 VM)", num(t.no_data), t.no_data ? "warn" : "")}</div>`;
  }
  function segList(o) {
    const f = st.q.toLowerCase();
    const S = o.segments.filter(s => !f || `${s.name} ${s.pg} ${s.gateway} ${s.connected_to}`.toLowerCase().includes(f));
    const mx = Math.max(1, ...o.segments.map(s => s.rx_bps + s.tx_bps));
    const allLabel = o.scope === "avi" ? "전체 가상 서비스" : "전체 네트워크";
    const all = o.totals;
    return `<div class="st-side"><div class="rd-tools"><input id="st-q" placeholder="이름·게이트웨이·VIP 검색" value="${esc(st.q)}" aria-label="세그먼트 검색"></div>
      <div class="st-segs" role="listbox" aria-label="세그먼트">
        <button class="st-seg ${!st.sel ? "on" : ""}" data-seg="" role="option" aria-selected="${!st.sel}"><span class="st-sn">${allLabel}</span>
          <small>${num(all.segments)}개 · VM ${num(all.vms)}</small><span class="st-sr">↓ ${bps(all.rx_bps)} · ↑ ${bps(all.tx_bps)}</span></button>
        ${S.map(s => `<button class="st-seg ${s.key === st.sel ? "on" : ""}" data-seg="${esc(s.key)}" role="option" aria-selected="${s.key === st.sel}">
          <span class="st-sn">${kindB(s.kind)}${esc(s.name || s.pg)}${s.drops ? ` <b class="st-db" title="드롭 패킷">드롭 ${num(s.drops)}</b>` : ""}</span>
          <small>${esc([s.gateway, s.connected_to, `VM ${s.vms}`].filter(Boolean).join(" · "))}</small>
          <span class="st-bar"><i class="rx" style="width:${(s.rx_bps / mx * 100).toFixed(1)}%"></i><i class="tx" style="width:${(s.tx_bps / mx * 100).toFixed(1)}%"></i></span>
          <span class="st-sr">${s.kind === "avi" ? `VIP ${bps((s.avi || {}).bw)}${s.vnics ? ` · <span>백엔드</span> ↓ ${bps(s.rx_bps)} · ↑ ${bps(s.tx_bps)}` : ""}`
            : s.has_data === false ? `<span class="muted">성능 통계 없음</span>` : `↓ ${bps(s.rx_bps)} · ↑ ${bps(s.tx_bps)}`}</span>${spark(s.kind === "avi" ? (s.avi || {}).bw_series : s.spark)}</button>`).join("")
        || `<p class="muted small pad">${o.segments.length && f ? "검색 결과가 없습니다." : st.scope === "avi" ? (o.sources.avi.length ? "Avi 가상 서비스가 없습니다." : "NSX ALB(Avi) 커넥터가 없습니다.")
          : o.sources.vcenter.length ? (st.scope === "nsx" ? "NSX 세그먼트에 연결된 VM 이 없습니다. '모든 네트워크'로 바꿔 보세요." : "이 종류의 네트워크에 연결된 VM 이 없습니다.") : "vCenter 커넥터가 없습니다."}</p>`}
      </div></div>`;
  }
  function vmTable(rows, withNsx) {
    const vf = st.vq.toLowerCase();
    let R = rows.filter(v => !vf || `${v.vm} ${v.host} ${(v.ips || []).join(" ")} ${v.mac}`.toLowerCase().includes(vf));
    const key = {tot: v => v.rx_bps + v.tx_bps, rx: v => v.rx_bps, tx: v => v.tx_bps, peak: v => v.peak_bps, pps: v => v.rx_pps + v.tx_pps,
                 drop: v => v.drop_rx + v.drop_tx, dfw: v => (v.nsx || {}).dfw_drop || 0, vm: v => v.vm, host: v => v.host}[st.sort] || (v => v.rx_bps + v.tx_bps);
    R = R.slice().sort((a, b) => { const x = key(a), y = key(b); return (typeof x === "string" ? x.localeCompare(y) : x - y) * st.dir; });
    const th = (k, l, cls = "num") => `<th class="${cls} sortable" tabindex="0" data-sort="${k}" aria-sort="${st.sort === k ? (st.dir > 0 ? "ascending" : "descending") : "none"}">${l}${st.sort === k ? (st.dir > 0 ? " ▲" : " ▼") : ""}</th>`;
    const shown = R.slice(0, 500);
    return `<div class="rd-tools st-vt"><input id="st-vq" placeholder="VM·호스트·IP·MAC 검색" value="${esc(st.vq)}" aria-label="VM 검색"><span class="muted small"><span>vNIC ${num(R.length)}</span>${R.length > 500 ? " <span>(상위 500)</span>" : ""} · <span>줄을 누르면 VM 별 조회</span></span></div>
      <div class="st-tw"><table class="rd-t st-t"><thead><tr>${th("vm", "VM · vNIC", "")}${st.sel && st.scope !== "avi" ? "" : `<th>${st.scope === "avi" ? "네트워크 · 풀" : "네트워크"}</th>`}${th("host", "호스트", "")}${th("rx", "수신(Rx)")}${th("tx", "송신(Tx)")}${th("peak", "최대(합)")}
        ${th("pps", "패킷/초")}${th("drop", "드롭(vNIC)")}${withNsx ? th("dfw", "DFW 차단") : ""}<th>추이</th></tr></thead><tbody>
        ${shown.map(v => `<tr data-vm="${esc(v.vm)}" data-vc="${esc(v.vcenter || "")}" class="${v.drop_rx + v.drop_tx ? "st-hasdrop" : ""}" tabindex="0">
          <td><b>${esc(v.vm)}</b>${aviB(v)}${v.power !== "poweredOn" ? ` <span class="rd-b unk">꺼짐</span>` : !v.connected ? ` <span class="rd-b warn">vNIC 끊김</span>` : ""}
            <br><small class="muted">${esc(v.label || "")} · ${esc(v.mac || "")}${v.ips && v.ips.length ? " · " + esc(v.ips.join(", ")) : ""}</small></td>
          ${st.sel && st.scope !== "avi" ? "" : `<td class="small">${st.scope === "avi" ? `${esc(v.network || "")}${v.pool ? `<br><span class="muted">${esc(v.pool)}${v.member_port ? ":" + esc(v.member_port) : ""}</span>` : ""}` : esc(segName(v.segment))}</td>`}<td class="small">${esc(v.host || "")}</td>
          <td class="num">${v.has_data ? bps(v.rx_bps) : "—"}</td><td class="num">${v.has_data ? bps(v.tx_bps) : "—"}</td><td class="num">${v.has_data ? bps(v.peak_bps) : "—"}</td>
          <td class="num small">${v.has_data ? `${pps(v.rx_pps)} / ${pps(v.tx_pps)}` : "—"}</td>
          <td class="num ${v.drop_rx + v.drop_tx ? "cc-na" : "muted"}">${v.has_data ? `${num(v.drop_rx)} / ${num(v.drop_tx)}` : "—"}</td>
          ${withNsx ? `<td class="num ${(v.nsx || {}).dfw_drop ? "cc-na" : "muted"}">${v.nsx ? num(v.nsx.dfw_drop) : "—"}</td>` : ""}
          <td>${spark(v.spark)}</td></tr>`).join("") || `<tr><td colspan="10" class="muted">해당하는 vNIC 이 없습니다.</td></tr>`}</tbody></table></div>`;
  }
  function md(t) {
    const inl = x => esc(x).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>"); const out = [];
    for (const ln of String(t || "").replace(/<think>[\s\S]*?<\/think>/g, "").split("\n")) {
      const m = ln.match(/^(#{1,4})\s+(.+)$/);
      if (m) out.push(`<h5 class="rv-mh">${inl(m[2])}</h5>`); else if (/^\s*([-*]|\d+\.)\s+/.test(ln)) out.push(`<div class="rv-li">• ${inl(ln.replace(/^\s*([-*]|\d+\.)\s+/, ""))}</div>`); else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
    }
    return out.join("");
  }
  const segName = k => { const s = st.ov && st.ov.segments.find(x => x.key === k); return s ? (s.name || s.pg) : String(k).split("/").pop(); };

  function detail() {
    const o = st.ov;
    if (!st.sel) {
      return `<div class="rd-card"><h4><span>${o.scope === "avi" ? "전체 가상 서비스 — 백엔드 VM 트래픽" : "전체 네트워크 — 트래픽 상위 VM"}</span> <small><span>${WIN.find(w => w[0] === st.window)[1]}</span> · <span>평균 · vCenter 실시간 성능 통계</span></small></h4>${histBlock()}${vmTable(o.vnics.map(v => ({...v, spark: null})), false)}</div>`;
    }
    const s = st.seg && st.seg.segment || o.segments.find(x => x.key === st.sel) || {};
    if (s.kind === "avi") return aviDetail(s);
    const kv = (k, v) => v ? `<span>${k}</span><b>${esc(v)}</b>` : "";
    const nsx = st.seg && st.seg.nsx || {};
    const head = `<div class="rd-card"><h4>${esc(s.name || s.pg || "")} <small><span>${esc(s.kind === "nsx" ? "NSX 세그먼트" : "포트그룹")}</span>${s.admin ? ` · <span>관리 상태</span> ${esc(s.admin)}` : ""}</small></h4>
      <div class="rv-kv">${kv("게이트웨이", s.gateway)}${kv("연결(Tier-1)", s.connected_to)}${kv("종류", s.seg_type)}${kv("전송 영역", s.tz)}${kv("세그먼트 ID", s.segment_id)}
        ${kv("분산 포트그룹", s.pg)}${kv("vCenter", (s.vcenters || []).join(", "))}${kv("NSX Manager", s.nsx)}${kv("VM · vNIC", s.vms != null ? `${s.vms} · ${s.vnics}` : "")}
        ${kv("수신 · 송신(평균)", s.has_data === false ? "—" : s.rx_bps != null ? `${bps(s.rx_bps)} · ${bps(s.tx_bps)}` : "")}${kv("최대(합)", s.peak_bps ? bps(s.peak_bps) : "")}</div>
      ${nsx.error ? `<div class="hd-note">NSX 포트 통계: ${esc(nsx.error)}</div>` : ""}${nsx.truncated ? `<div class="hd-note">포트가 많아 앞 400개만 NSX 통계를 읽었습니다.</div>` : ""}</div>`;
    if (st.segBusy || !st.seg) return head + `<div class="rd-card"><p class="muted">세그먼트 상세를 읽는 중…</p></div>`;
    const c = st.seg.chart;
    const withNsx = st.seg.vnics.some(v => v.nsx);
    const noData = s.has_data === false;
    return head + `<div class="rd-card"><h4><span>대역폭 추이</span> <small><span>${WIN.find(w => w[0] === st.window)[1]}</span> · <span>20초 간격</span> · <span>이 세그먼트 vNIC 합계</span></small></h4>${noData
      ? `<p class="muted small">이 세그먼트의 vNIC 성능 통계를 받지 못했습니다 — VM 전원·vNIC 연결·vCenter 통계 수준을 확인하세요.</p>` : chart(c.ts, c.rx_bps, c.tx_bps, c.drops, st.window <= 900 ? hms : hm)}<div class="small muted">세로축 단위 bps(M = Mbps)</div>${histBlock()}</div>
      <div class="rd-card"><h4><span>VM 별 트래픽</span> <small><span>vCenter vNIC 카운터</span>${withNsx ? " · <span>DFW 차단 = NSX 포트 통계 누적값</span>" : ""}</small></h4>${vmTable(st.seg.vnics, withNsx)}</div>`;
  }
  function aviDetail(s) {
    const a = s.avi || {}, kv = (k, v) => v || v === 0 ? `<span>${k}</span><b>${esc(v)}</b>` : "";
    const step = a.step || 5, ser = a.bw_series || [];
    const now = Date.now() / 1000, ts = ser.map((_, i) => now - (ser.length - 1 - i) * step);
    const head = `<div class="rd-card"><h4>${kindB("avi")}${esc(s.name)} <small><span>NSX ALB(Avi) 가상 서비스</span> · ${esc(a.state || "")}</small></h4>
      <div class="rv-kv">${kv("VIP", s.gateway)}${kv("풀", s.connected_to)}${kv("헬스", a.health)}${kv("SE 그룹", a.se_group)}${kv("컨트롤러", a.controller)}${kv("Avi 커넥터", s.nsx)}
        ${kv("VIP 대역폭(최근 1분 평균 · 마지막)", a.bw != null ? `${bps(a.bw)} · ${bps(a.bw_last)}` : "")}${kv("VIP 수신 · 송신", a.rx_bps || a.tx_bps ? `${bps(a.rx_bps)} · ${bps(a.tx_bps)}` : "")}
        ${kv("요청/초 · 연결/초", a.rps != null ? `${pps(a.rps)} · ${pps(a.cps)}` : "")}${kv("열린 연결", a.open != null ? num(a.open) : "")}${kv("RTT", a.rtt != null ? `${a.rtt} ms` : "")}
        ${kv("풀 멤버 · VM 으로 찾음", `${num(a.members)} · ${num(s.vnics)}`)}</div>
      ${(a.external || []).length ? `<div class="hd-note"><span>vCenter VM 으로 찾지 못한 풀 멤버(물리 서버·컨테이너·다른 vCenter)</span>: ${a.external.map(x => esc(`${x.ip}${x.port ? ":" + x.port : ""}`)).join(", ")}</div>` : ""}</div>`;
    const vipChart = `<div class="rd-card"><h4><span>VIP 대역폭(클라이언트 ↔ 가상 서비스)</span> <small><span>Avi l4_client.avg_bandwidth</span> · ${step}<span>초 간격</span></small></h4>
      ${ser.length >= 2 ? chart(ts, ser, [], [], hms, "VIP 대역폭") : `<p class="muted small">Avi 지표가 아직 없습니다.</p>`}</div>`;
    if (st.segBusy || !st.seg) return head + vipChart + `<div class="rd-card"><p class="muted">백엔드 VM 을 읽는 중…</p></div>`;
    const c = st.seg.chart;
    return head + vipChart + `<div class="rd-card"><h4><span>백엔드 VM vNIC 대역폭</span> <small><span>${WIN.find(w => w[0] === st.window)[1]}</span> · <span>풀 멤버 IP 와 맞는 VM vNIC 합계</span></small></h4>
        ${st.seg.vnics.length ? chart(c.ts, c.rx_bps, c.tx_bps, c.drops, st.window <= 900 ? hms : hm) : `<p class="muted small">풀 멤버 IP 와 맞는 VM 이 없습니다.</p>`}</div>
      <div class="rd-card"><h4><span>백엔드 VM</span> <small><span>vCenter vNIC 카운터</span></small></h4>${vmTable(st.seg.vnics, false)}</div>`;
  }
  function histBlock() {
    const sel = `<label class="small">추세 <select id="st-hist" aria-label="저장된 추세 기간"><option value="0">끄기</option>${[[24, "24시간"], [72, "3일"], [168, "7일"]].map(([v, l]) => `<option value="${v}" ${st.hist === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>`;
    if (st.scope === "avi" && !st.sel) return "";
    if (!st.hist) return `<div class="st-hist">${sel} <span class="muted small">5분마다 저장한 네트워크 합계(기본 14일 보관) — 이 범위의 네트워크만</span></div>`;
    const p = (st.histData || {}).points || [];
    return `<div class="st-hist">${sel}</div>${p.length >= 2 ? chart(p.map(x => x.ts), p.map(x => x.rx_bps), p.map(x => x.tx_bps), p.map(x => x.drops), mdt)
      : `<p class="muted small">${st.histData ? "저장된 이력이 아직 없습니다 — 5분마다 쌓입니다." : "읽는 중…"}</p>`}`;
  }
  function render() {
    const box = $("#st-body"); if (!box) return;
    const tools = `<div class="rd-tools st-tools"><select id="st-win" aria-label="기간">${WIN.map(([v, l]) => `<option value="${v}" ${st.window === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <select id="st-scope" aria-label="네트워크 종류">${SCOPES.map(([v, l]) => `<option value="${v}" ${st.scope === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <a class="btn-sm" href="/api/segtraffic.csv?window=${st.window}&scope=${st.scope === "vm" ? "all" : st.scope}${st.scope === "vm" ? (st.vm ? "&vm=" + enc(st.vm) : "") : st.sel ? "&key=" + enc(st.sel) : ""}" download>CSV</a>
      ${st.scope === "vm" ? "" : `<button class="btn-sm" id="st-ai" data-perm="operate" ${st.ov ? "" : "disabled"}>AI 분석</button>`}
      <span class="muted small">${st.scope === "vm" && st.vms ? `<span>갱신 시각</span> ${hm(st.vms.updated)} · vCenter ${esc(st.vms.sources.vcenter.join(", "))}` : st.ov ? `<span>갱신 시각</span> ${hm(st.ov.updated)} · vCenter ${esc(st.ov.sources.vcenter.join(", ") || "없음")}${st.ov.sources.nsx.length ? " · NSX " + esc(st.ov.sources.nsx.join(", ")) : ""}${(st.ov.sources.avi || []).length ? " · Avi " + esc(st.ov.sources.avi.join(", ")) : ""}` : ""}</span></div>`;
    if (st.scope === "vm") {
      if (!st.vms) { box.innerHTML = tools + `<p class="muted pad">${st.busy ? "vCenter 에서 vNIC·성능 카운터를 읽는 중…" : "데이터가 없습니다."}</p>`; return; }
      const ae2 = document.activeElement, kq = ae2 && ["st-q", "st-win", "st-scope", "st-vmhist"].includes(ae2.id) ? ae2.id : "";
      const kv2 = ae2 && ae2.dataset && ae2.dataset.vmsel !== undefined && box.contains(ae2) ? ae2.dataset.vmsel : null;
      const sc2 = ($(".st-segs", box) || {}).scrollTop || 0;
      const errs2 = st.vms.errors && st.vms.errors.length ? `<details class="hd-note"><summary>수집 공백 ${st.vms.errors.length}건</summary>${st.vms.errors.map(e => `<div class="small">${esc(e)}</div>`).join("")}</details>` : "";
      box.innerHTML = tools + errs2 + `<div class="st-grid">${vmList(st.vms)}<div class="st-main">${vmDetail()}</div></div>`;
      const sg2 = $(".st-segs", box); if (sg2) sg2.scrollTop = sc2;
      if (kq) { const i = $("#" + kq); if (i) { i.focus({preventScroll: true}); if (i.setSelectionRange && i.type !== "select-one") i.setSelectionRange(i.value.length, i.value.length); } }
      if (kv2 !== null) { const b = $$("[data-vmsel]", box).find(x => x.dataset.vmsel === kv2); if (b) b.focus({preventScroll: true}); }
      $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
      return;
    }
    if (!st.ov) { box.innerHTML = tools + `<p class="muted pad">${st.busy ? "vCenter 에서 vNIC·성능 카운터를 읽는 중…" : "데이터가 없습니다."}</p>`; return; }
    const errs = st.ov.errors && st.ov.errors.length ? `<details class="hd-note"><summary>수집 공백 ${st.ov.errors.length}건</summary>${st.ov.errors.map(e => `<div class="small">${esc(e)}</div>`).join("")}</details>` : "";
    const ai = st.ai ? `<div class="rd-card"><h4>AI 분석 <small>${esc(st.sel ? segName(st.sel) : "전체 세그먼트")}</small></h4><div class="rv-md">${md(st.ai)}</div></div>` : "";
    const ae = document.activeElement;
    const keepQ = ae && ["st-q", "st-vq"].includes(ae.id) ? ae.id : "";
    const keepSel = ae && ["st-win", "st-scope", "st-hist"].includes(ae.id) ? ae.id : "";
    const keepSeg = ae && ae.dataset && ae.dataset.seg !== undefined && box.contains(ae) ? ae.dataset.seg : null;
    const keepSort = ae && ae.dataset && ae.dataset.sort && box.contains(ae) ? ae.dataset.sort : "";
    const scrollSegs = ($(".st-segs", box) || {}).scrollTop || 0;
    box.innerHTML = tools + kpis(st.ov) + errs + `<div class="st-grid">${segList(st.ov)}<div class="st-main">${ai}${detail()}</div></div>`;
    const sg = $(".st-segs", box); if (sg) sg.scrollTop = scrollSegs;
    if (keepQ) { const i = $("#" + keepQ); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }
    if (keepSeg !== null) { const b = $$("[data-seg]", box).find(x => x.dataset.seg === keepSeg); if (b) b.focus({preventScroll: true}); }   // 다시 그려도 키보드 포커스 유지
    if (keepSel) { const x = $("#" + keepSel); if (x) x.focus({preventScroll: true}); }
    if (keepSort) { const h = $(`[data-sort="${keepSort}"]`, box); if (h) h.focus({preventScroll: true}); }
    $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
  }

  function wire() {
    const box = $("#st-body"); if (!box || box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target;
      const tl = t.closest("[data-tl]"); if (tl) { if (window.AIOPS_VM_TIMELINE) window.AIOPS_VM_TIMELINE(tl.dataset.tl); return; }
      const vs = t.closest("[data-vmsel]"); if (vs) { loadVm(vs.dataset.vmsel, vs.dataset.vc || ""); return; }
      const sg = t.closest("[data-seg]"); if (sg) { loadSeg(sg.dataset.seg); return; }
      const so = t.closest("[data-sort]");
      if (so) { const k = so.dataset.sort; st.dir = st.sort === k ? -st.dir : (k === "vm" || k === "host" ? 1 : -1); st.sort = k; render(); return; }
      const tr = t.closest("tr[data-vm]"); if (tr) { openVm(tr.dataset.vm, tr.dataset.vc || ""); return; }
      if (t.id === "st-vmretry") { loadVm(st.vm, st.vmvc); return; }
      if (t.id === "st-ai") {
        t.disabled = true; t.textContent = "AI 분석 중…";
        try { st.ai = (await A.api("POST", "/api/segtraffic/ai", {window: st.window, key: st.sel, scope: st.scope})).report; } catch (er) { A.fail("AI 분석 실패", er); }
        render();
      }
    });
    box.addEventListener("keydown", e => {
      const tr = e.target.closest && e.target.closest("tr[data-vm]"); if (tr && e.key === "Enter") openVm(tr.dataset.vm, tr.dataset.vc || "", true);
      const opt = e.target.closest && e.target.closest(".st-segs [role='option']");
      if (opt && (e.key === "ArrowDown" || e.key === "ArrowUp")) {       // 목록에서 ↑↓ 로 이동
        e.preventDefault();
        const all = $$(".st-segs [role='option']", box), i = all.indexOf(opt), n = all[i + (e.key === "ArrowDown" ? 1 : -1)];
        if (n) n.focus();
      }
      const so = e.target.closest && e.target.closest("[data-sort]");
      if (so && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); so.click(); }
    });
    box.addEventListener("change", e => {
      const t = e.target;
      if (t.id === "st-win") { st.window = Number(t.value); load(); }
      if (t.id === "st-scope") { st.scope = t.value; st.sel = ""; st.q = ""; st.vq = ""; load(true); }
      if (t.id === "st-vmhist") { st.vmHist = Number(t.value); st.vmHistData = null; render(); if (st.vmHist) loadVmHist(); }
      if (t.id === "st-hist") { st.hist = Number(t.value); st.histData = null; render(); if (st.hist) loadHist(); }
    });
    box.addEventListener("input", e => {
      if (e.target.id === "st-q") { st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 200); }
      if (e.target.id === "st-vq") { st.vq = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 200); }
    });
  }
  async function show(seg, scope, vm) {
    if (scope && SCOPES.some(x => x[0] === scope)) st.scope = scope;
    if (vm) { st.scope = "vm"; st.vm = vm; }
    $$(".drawer").forEach(d => { if (d.id !== "drawer-st") d.hidden = true; });
    $("#drawer-st").hidden = false; wire();
    if (typeof seg === "string") st.sel = seg;
    await load();
  }
  const nav = document.getElementById("nav-st"); if (nav) nav.onclick = () => show();
  const rl = document.getElementById("st-reload"); if (rl) rl.onclick = () => load(true);
  window.AIOPS_SEGTRAFFIC = show;
  { const q = new URLSearchParams(location.search); if (q.get("view") === "st" && (q.get("segment") || q.get("scope") || q.get("vm"))) setTimeout(() => show(q.get("segment") || "", q.get("scope"), q.get("vm")), 1200); }
  window.AIOPS_VM_TRAFFIC = name => show("", "vm", name);
})();
