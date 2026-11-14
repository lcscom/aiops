/* 호스트·VM 성능(2.23.0) — 호스트·VM 별 CPU·메모리·디스크 I/O·네트워크 상세(vCenter 성능 카운터, 읽기 전용) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const enc = encodeURIComponent;
  const st = {tab: "detail", cmp: [], cmpMetric: "cpu.usage_pct", cmpData: {}, ai: null, aiBusy: false, closed: new Set(), kind: "vm", ents: null, top: null, topBusy: false, q: "", sort: "cpu_pct", sel: null, det: null, detBusy: false, range: "rt", more: 0};
  const SEQ = {ents: 0, top: 0, det: 0};
  const RANGES = [["rt", "실시간 1시간(20초)"], ["1d", "24시간(5분)"], ["7d", "7일(30분)"], ["30d", "30일(2시간)"], ["s3d", "자체 이력 3일(5분)"], ["h6w", "자체 이력 6주(1시간)"]];
  const SORTS = [["cpu_pct", "CPU 사용률"], ["mem_pct", "메모리 사용률"], ["iops", "디스크 IOPS"], ["disk_lat_ms", "디스크 지연"], ["disk_Bps", "디스크 처리량"],
    ["net_bps", "네트워크"], ["ready_pct", "CPU ready(VM)"], ["name", "이름"]];
  const NOW_KEYS = ["iops", "disk_lat_ms", "disk_Bps", "net_bps", "ready_pct"];

  const pct = x => x == null ? "—" : `${x.toFixed(x < 10 ? 1 : 0)}%`;
  const ms = x => x == null ? "—" : `${x.toFixed(x < 10 ? 1 : 0)} ms`;
  const num = x => x == null ? "—" : x >= 1e6 ? `${(x / 1e6).toFixed(1)}M` : x >= 1e4 ? `${(x / 1e3).toFixed(1)}K` : Math.round(x).toLocaleString();
  const bps = x => x == null ? "—" : x >= 1e9 ? `${(x / 1e9).toFixed(2)} Gbps` : x >= 1e6 ? `${(x / 1e6).toFixed(1)} Mbps` : x >= 1e3 ? `${(x / 1e3).toFixed(0)} Kbps` : `${Math.round(x)} bps`;
  const Bps = x => x == null ? "—" : x >= 1e9 ? `${(x / 1e9).toFixed(2)} GB/s` : x >= 1e6 ? `${(x / 1e6).toFixed(1)} MB/s` : x >= 1e3 ? `${(x / 1e3).toFixed(0)} KB/s` : `${Math.round(x)} B/s`;
  const mb = x => x == null ? "—" : x >= 1024 ? `${(x / 1024).toFixed(1)} GB` : `${Math.round(x)} MB`;
  const FMT = {pct, ms, num, bps, Bps, mb, mhz: x => x == null ? "—" : `${Math.round(x).toLocaleString()} MHz`};
  const lvl = (k, v) => v == null ? "" : (k === "cpu_pct" || k === "mem_pct") ? (v >= 90 ? "bad" : v >= 75 ? "warn" : "")
    : k === "disk_lat_ms" ? (v >= 20 ? "bad" : v >= 10 ? "warn" : "") : k === "ready_pct" ? (v >= 10 ? "bad" : v >= 5 ? "warn" : "") : "";
  const p2 = x => String(x).padStart(2, "0");
  const tick = (ts, rng) => { const d = new Date(ts * 1000); return rng === "rt" || rng === "1d" ? `${p2(d.getHours())}:${p2(d.getMinutes())}` : `${d.getMonth() + 1}/${d.getDate()}${rng === "7d" ? ` ${p2(d.getHours())}h` : ""}`; };
  const short = x => x >= 1e9 ? `${(x / 1e9).toFixed(1)}G` : x >= 1e6 ? `${(x / 1e6).toFixed(1)}M` : x >= 1e3 ? `${(x / 1e3).toFixed(x >= 1e4 ? 0 : 1)}K` : `${+x.toFixed(x < 10 ? 1 : 0)}`;

  // ------------------------------------------------------------ 차트(여러 계열, 공통 Y축)
  function chart(title, ts, lines, fmt, opts = {}) {
    const W = 560, H = 150, P = 48;
    let ls = lines.filter(l => l.vals && l.vals.some(v => v != null));
    if (ts && ts.length === 1) { ts = [ts[0], ts[0]]; ls = ls.map(l => ({...l, vals: [l.vals[0], l.vals[0]]})); }     // 표본 1개 — 수평선
    if (!ls.length || !ts || ts.length < 2) return `<div class="pf-ch"><h5>${esc(title)}</h5><p class="muted small">데이터 없음${opts.why ? ` — ${esc(opts.why)}` : ""}</p></div>`;
    const n = ts.length, all = ls.flatMap(l => l.vals.filter(v => v != null)).concat(opts.band && opts.band.hi ? opts.band.hi.filter(v => v != null) : []);
    const mx = Math.max(opts.max || 0, ...all, opts.floor || 1e-9) * (opts.max ? 1 : 1.08);
    const X = i => P + i * (W - P - 6) / (n - 1), Y = v => H - 18 - v / mx * (H - 28);
    const path = vals => { let d = "", pen = false; vals.forEach((v, i) => { if (v == null) { pen = false; return; } d += `${pen ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`; pen = true; }); return d; };
    const grid = [0, 0.5, 1].map(f => `<line class="st-grid" x1="${P}" x2="${W}" y1="${Y(mx * f)}" y2="${Y(mx * f)}"/><text class="st-ax" x="${P - 4}" y="${Y(mx * f) + 4}" text-anchor="end">${esc(short(mx * f))}</text>`).join("");
    const k = Math.max(1, Math.floor(n / (st.range === "7d" ? 4 : 5)));
    const xt = ts.map((t, i) => (i % k && i !== n - 1) || (i !== n - 1 && n - 1 - i < k) ? "" : `<text class="st-ax" x="${X(i)}" y="${H - 3}" text-anchor="${i === 0 ? "start" : i === n - 1 ? "end" : "middle"}">${esc(tick(t, st.range))}</text>`).join("");
    let bandSvg = "";
    if (opts.band && opts.band.hi && opts.band.hi.length === n) {         // 정상 범위(회색 밴드)
      const top = [], bot = [];
      for (let i = 0; i < n; i++) { const h = opts.band.hi[i], l = opts.band.lo[i]; if (h == null || l == null) continue; top.push(`${X(i).toFixed(1)},${Y(Math.min(h, mx)).toFixed(1)}`); bot.unshift(`${X(i).toFixed(1)},${Y(Math.max(0, l)).toFixed(1)}`); }
      if (top.length > 1) bandSvg = `<polygon class="pf-band" points="${top.concat(bot).join(" ")}"><title>정상 범위(${opts.band.season === "weekly" ? "요일·시간" : "시간대"} 기준선)</title></polygon>`;
    }
    const marks = (opts.marks || []).map(m => { if (!ts.length || m.t < ts[0]) return ""; let i = ts.findIndex(t => t >= m.t); if (i < 0) return ""; return `<line class="pf-mark ${esc(m.sev)}" x1="${X(i)}" x2="${X(i)}" y1="8" y2="${H - 18}"><title>${esc(m.label)}</title></line>`; }).join("");
    const thr = opts.thr != null && opts.thr < mx ? `<line class="pf-thr" x1="${P}" x2="${W}" y1="${Y(opts.thr)}" y2="${Y(opts.thr)}"><title>기준 ${esc(fmt(opts.thr))}</title></line>` : "";
    const last = l => { const xs = l.vals.filter(v => v != null); return xs.length ? xs[xs.length - 1] : null; };
    const mxv = l => Math.max(...l.vals.filter(v => v != null));
    return `<div class="pf-ch"><h5>${esc(title)}</h5>
      <svg class="st-chart pf-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">${grid}${bandSvg}${thr}${marks}${ls.map((l, i) => `<path class="pf-l s${l.c ?? i}" d="${path(l.vals)}"/>`).join("")}${xt}</svg>
      <div class="pf-leg">${ls.map((l, i) => `<span><i class="s${l.c ?? i}"></i>${esc(l.name)} <b>${esc(fmt(last(l)))}</b> <small class="muted">최대 ${esc(fmt(mxv(l)))}</small></span>`).join("")}${bandSvg ? `<span><i class="band"></i><small class="muted">정상 범위</small></span>` : ""}</div></div>`;
  }

  // ------------------------------------------------------------ 데이터
  async function loadEnts() {
    const my = ++SEQ.ents;
    try { const d = await A.api("GET", `/api/perf/entities?kind=${st.kind}`); if (my === SEQ.ents) { st.ents = d; renderList(); } }
    catch (e) { if (my === SEQ.ents) A.fail("목록을 불러오지 못했습니다", e); }
  }
  function nowBtn() { const b = $("#pf-now"); if (b) { b.disabled = st.topBusy; b.textContent = st.topBusy ? "측정 중…" : "지금 부하 측정"; } }
  async function loadTop(fresh = false) {
    if (st.topBusy) return;
    const my = ++SEQ.top;
    st.topBusy = true; nowBtn();
    let d = null;
    try { d = await A.api("GET", `/api/perf/top?kind=${st.kind}${fresh ? "&fresh=1" : ""}`); } catch (e) { if (my === SEQ.top) A.fail("지금 부하를 측정하지 못했습니다", e); }
    if (my !== SEQ.top) return;
    st.topBusy = false; nowBtn();
    if (d) { st.top = d; renderList(); }                    // 실패하면 이전 측정 유지
  }
  async function loadDet(fresh = false, silent = false) {
    if (!st.sel) return;
    const my = ++SEQ.det, s = st.sel;
    st.detBusy = true; if (!silent) renderDet();
    let d = null, err = "";
    try { d = await A.api("GET", `/api/perf/detail?kind=${s.kind}&name=${enc(s.name)}&vcenter=${enc(s.vcenter || "")}&range=${st.range}${fresh ? "&fresh=1" : ""}`, undefined, silent ? {background: true} : undefined); }
    catch (e) { err = e.message || String(e); }
    if (my !== SEQ.det) return;
    st.detBusy = false;
    if (silent && !d) return;                               // 자동 갱신 실패는 조용히(이전 화면 유지)
    st.det = d; st.detErr = err;
    const ae = document.activeElement, det = $("#pf-det");
    if (silent && det && ae && det.contains(ae) && ae.tagName === "SELECT") return;   // 기간 고르는 중
    const y = det ? det.scrollTop : 0; renderDet(); if (det) det.scrollTop = y;
  }

  // ------------------------------------------------------------ 목록
  function rows() {
    const ents = (st.ents && st.ents.items) || [];
    const now = new Map(((st.top && st.top.kind === st.kind && st.top.rows) || []).map(r => [`${r.vcenter}\u0000${r.name}`, r.now]));
    const q = st.q.trim().toLowerCase();
    let xs = ents.map(e => {
      const n = now.get(`${e.vcenter}\u0000${e.name}`) || null;
      return {...e, nowv: n, cpu: n && n.cpu_pct != null ? n.cpu_pct : e.cpu_pct, mem: n && n.mem_pct != null ? n.mem_pct : e.mem_pct};
    });
    if (q) xs = xs.filter(e => `${e.name} ${e.cluster} ${e.host || ""} ${(e.ips || []).join(" ")} ${e.os || ""}`.toLowerCase().includes(q));
    const v = e => st.sort === "cpu_pct" ? e.cpu : st.sort === "mem_pct" ? e.mem : e.nowv ? e.nowv[st.sort] : null;
    if (st.sort === "name") xs.sort((a, b) => a.name.localeCompare(b.name));
    else xs.sort((a, b) => (v(b) ?? -1) - (v(a) ?? -1) || a.name.localeCompare(b.name));
    return xs;
  }
  const bar = (v, k) => v == null ? `<span class="muted">—</span>` : `<span class="pf-bar ${lvl(k, v)}"><i style="width:${Math.min(100, Math.max(0, v)).toFixed(0)}%"></i></span><span class="pf-v">${pct(v)}</span>`;

  function renderList() {
    const box = $("#pf-list"); if (!box) return;
    if (!st.ents) { box.innerHTML = `<div class="empty">목록을 읽는 중…</div>`; return; }
    const xs = rows(), lim = 200 + st.more;
    const needNow = NOW_KEYS.includes(st.sort) && !(st.top && st.top.kind === st.kind);
    const topInfo = st.top && st.top.kind === st.kind ? `지금 부하 ${new Date(st.top.ts * 1000).toLocaleTimeString()} · ${st.top.measured}/${st.top.total}대${st.top.errors.length ? ` · 오류 ${esc(st.top.errors.join(", "))}` : ""}` : "CPU·메모리는 vCenter 요약값(1~5분) — '지금 부하 측정'으로 디스크·네트워크까지 최근 1분 실측";
    box.innerHTML = `${heat()}
      <div class="small muted pf-topinfo">${topInfo}${needNow ? ` <b>— 이 정렬은 '지금 부하 측정'이 필요합니다</b>` : ""}</div>
      ${xs.length ? `<table class="vc-t pf-t" aria-label="${st.kind === "vm" ? "VM" : "호스트"} 목록"><thead><tr><th>${st.kind === "vm" ? "VM" : "호스트"}</th><th>CPU</th><th>메모리</th><th>IOPS</th><th>지연</th><th>네트워크</th></tr></thead><tbody>
        ${xs.slice(0, lim).map(e => { const n = e.nowv || {}; const on = st.sel && st.sel.name === e.name && st.sel.vcenter === e.vcenter && st.sel.kind === e.kind;
          return `<tr class="pf-r${on ? " on" : ""}${(e.state && e.state !== "poweredOn" && e.state !== "connected") ? " off" : ""}" tabindex="0" data-name="${esc(e.name)}" data-vc="${esc(e.vcenter)}">
          <td><b>${esc(e.name)}</b><div class="small muted">${esc(st.kind === "vm" ? `${e.host || "-"} · ${e.vcpu} vCPU · ${mb(e.mem_mb)}` : `${e.cluster || "-"} · VM ${e.vms}${e.maintenance ? " · 유지 관리" : ""}`)}${e.state && e.state !== "poweredOn" && e.state !== "connected" ? ` · ${esc(e.state)}` : ""}</div></td>
          <td>${bar(e.cpu, "cpu_pct")}</td><td>${bar(e.mem, "mem_pct")}</td>
          <td class="num">${num(n.iops)}</td><td class="num ${lvl("disk_lat_ms", n.disk_lat_ms)}">${ms(n.disk_lat_ms)}</td><td class="num">${n.net_bps == null ? "—" : short(n.net_bps) + "bps"}</td></tr>`; }).join("")}
      </tbody></table>${xs.length > lim ? `<button class="btn-sm" id="pf-more">${(xs.length - lim).toLocaleString()}대 더 보기</button>` : ""}` : `<div class="empty">${st.q ? "검색 결과 없음" : "vCenter 커넥터의 호스트·VM 이 아직 없습니다"}</div>`}`;
  }

  // ------------------------------------------------------------ 상세
  function kpi(label, s, f, k, extra = "", bk = "") {
    const b = bk && st.det && st.det.diag && st.det.diag.baseline ? st.det.diag.baseline[bk] : null;
    if (b && b.avg24 != null) extra += ` · 24시간 평균 ${f(b.avg24)}`;
    if (!s) return `<div class="kpi pf-kpi"><span>${esc(label)}</span><b class="muted">—</b></div>`;
    return `<div class="kpi pf-kpi"><span>${esc(label)}</span><b class="${lvl(k, s.last)}">${esc(f(s.last))}</b><small class="muted">평균 ${esc(f(s.avg))} · 최대 ${esc(f(s.max))}${extra}</small></div>`;
  }
  function renderDet() {
    const box = $("#pf-det"); if (!box) return;
    if (!st.sel) { box.innerHTML = `<div class="empty pf-hint">왼쪽에서 ${st.kind === "vm" ? "VM" : "호스트"}을(를) 고르면 CPU·메모리·디스크 I/O·네트워크를 자세히 봅니다.</div>`; return; }
    const d = st.det;
    const head = `<div class="pf-dh"><div><h4>${esc(st.sel.name)} <span class="st-k ${st.sel.kind === "vm" ? "vds" : "nsx"}">${st.sel.kind === "vm" ? "VM" : "호스트"}</span></h4>
        <div class="small muted">${d && d.info ? infoLine(d) : esc(st.sel.vcenter || "")}</div></div>
      <div class="pf-dc"><select id="pf-range" aria-label="기간">${RANGES.map(([k, v]) => `<option value="${k}"${k === st.range ? " selected" : ""}>${esc(v)}</option>`).join("")}</select>
        <button class="btn-sm" id="pf-addcmp" title="같은 차트에 겹쳐 보기(최대 4대)">비교에 추가</button><button class="btn-sm" id="pf-dre">새로 고침</button>${d && d.ts && d.ts.length ? `<a class="btn-sm" href="/api/perf/detail.csv?kind=${st.sel.kind}&name=${enc(st.sel.name)}&vcenter=${enc(st.sel.vcenter || "")}&range=${st.range}" download>CSV</a>` : ""}</div></div>`;
    if (st.detBusy && !d) { box.innerHTML = head + `<div class="empty">성능 통계를 읽는 중…</div>`; return; }
    if (!d) { box.innerHTML = head + `<div class="empty">${esc(st.detErr || "결과 없음")} <button class="btn-sm" id="pf-dre2">다시 시도</button></div>`; return; }
    const S = d.series || {}, M = d.summary || {}, ts = d.ts || [], vm = d.kind === "vm";
    const B = d.bands || {};
    const marks = (d.alerts || []).map(a => ({t: a.start, sev: a.sev, label: `${a.rule_name}: ${a.msg || ""}`}));
    const hist = d.range !== "rt";
    const why = hist ? "과거 통계 수준(기본 1)에 없는 카운터 — 실시간에서 확인" : "";
    box.innerHTML = head + `
      ${st.detBusy ? `<div class="small muted">갱신 중…</div>` : ""}
      ${d.error ? `<div class="sp-alert bad">${esc(d.error)}</div>` : ""}
      ${diagBox(d)}
      <div class="kpis pf-kpis">
        ${kpi("CPU 사용률", M["cpu.usage_pct"], pct, "cpu_pct", M["cpu.usage_mhz"] ? ` · ${Math.round(M["cpu.usage_mhz"].last).toLocaleString()} MHz` : "", "cpu.usage_pct")}
        ${vm ? kpi("CPU ready(vCPU 평균)", M["cpu.ready_pct"], pct, "ready_pct") : ""}
        ${kpi("메모리 사용률", M["mem.usage_pct"], pct, "mem_pct", "", "mem.usage_pct")}
        ${kpi("디스크 IOPS", M["disk.read_iops"] || M["disk.write_iops"] ? sumS(M, "disk.read_iops", "disk.write_iops") : null, num, "")}
        ${kpi("디스크 지연(최대)", M["disk.max_lat_ms"] || maxS(M, "disk.read_lat_ms", "disk.write_lat_ms"), ms, "disk_lat_ms", "", "disk.max_lat_ms")}
        ${kpi("디스크 처리량", M["disk.usage_Bps"] || sumS(M, "disk.read_Bps", "disk.write_Bps"), Bps, "")}
        ${kpi("네트워크", M["net.usage_bps"] || sumS(M, "net.rx_bps", "net.tx_bps"), bps, "", "", "net.usage_bps")}
      </div>
      <section class="pf-sec"><h4>CPU</h4><div class="pf-grid">
        ${chart("CPU 사용률(%)", ts, [{name: "사용률", vals: S["cpu.usage_pct"]}, {name: "시간 최대", vals: S["cpu.usage_pct_max"], c: 5}], pct, {max: 100, thr: 90, band: B["cpu.usage_pct"], marks})}
        ${vm ? chart("CPU ready · co-stop(% , vCPU 평균)", ts, [{name: "ready", vals: S["cpu.ready_pct"]}, {name: "ready 시간 최대", vals: S["cpu.ready_pct_max"], c: 5}, {name: "co-stop", vals: S["cpu.costop_pct"], c: 2}], pct, {thr: 5, floor: 1, why, band: B["cpu.ready_pct"], marks})
             : chart("CPU 사용량(MHz)", ts, [{name: "사용량", vals: S["cpu.usage_mhz"]}], FMT.mhz, {max: d.info.cpu_mhz || 0})}
      </div></section>
      <section class="pf-sec"><h4>메모리</h4><div class="pf-grid">
        ${chart("메모리 사용률(%)", ts, [{name: "사용률", vals: S["mem.usage_pct"]}], pct, {max: 100, thr: 90, band: B["mem.usage_pct"], marks})}
        ${chart("메모리(MB)", ts, [{name: vm ? "consumed" : "consumed", vals: S["mem.consumed_mb"]}, {name: "active", vals: S["mem.active_mb"], c: 1},
          {name: "balloon", vals: S["mem.balloon_mb"], c: 3}, {name: "swapped", vals: S["mem.swapped_mb"], c: 4}, {name: "compressed", vals: S["mem.compressed_mb"], c: 5}], mb, {why})}
        ${vm ? chart("메모리 latency(%)", ts, [{name: "latency", vals: S["mem.latency_pct"]}], pct, {thr: 1, floor: 1, why})
             : chart("스왑 입출력(B/s)", ts, [{name: "swap in", vals: S["mem.swapin_Bps"], c: 3}, {name: "swap out", vals: S["mem.swapout_Bps"], c: 4}], Bps, {floor: 1, why})}
      </div></section>
      <section class="pf-sec"><h4>디스크 I/O</h4><div class="pf-grid">
        ${chart("IOPS", ts, S["disk.iops"] ? [{name: "합계", vals: S["disk.iops"]}, {name: "시간 최대", vals: S["disk.iops_max"], c: 5}] : [{name: "읽기", vals: S["disk.read_iops"]}, {name: "쓰기", vals: S["disk.write_iops"], c: 1}], num, {why, marks})}
        ${chart("처리량(B/s)", ts, S["disk.read_Bps"] ? [{name: "읽기", vals: S["disk.read_Bps"]}, {name: "쓰기", vals: S["disk.write_Bps"], c: 1}] : [{name: "사용", vals: S["disk.usage_Bps"]}], Bps, {why})}
        ${chart("지연(ms)", ts, [{name: "읽기", vals: S["disk.read_lat_ms"]}, {name: "쓰기", vals: S["disk.write_lat_ms"], c: 1}, {name: "최대", vals: S["disk.max_lat_ms"], c: 2},
          ...(vm ? [] : [{name: "장치(DAVG)", vals: S["disk.device_lat_ms"], c: 4}, {name: "커널(KAVG)", vals: S["disk.kernel_lat_ms"], c: 5}]), {name: "시간 최대", vals: S["disk.max_lat_ms_max"], c: 3}], ms, {thr: 20, floor: 1, band: B["disk.max_lat_ms"], marks})}
      </div>${instTable("disk", d)}</section>
      <section class="pf-sec"><h4>네트워크</h4><div class="pf-grid">
        ${chart("대역폭(bps)", ts, S["net.rx_bps"] ? [{name: "수신", vals: S["net.rx_bps"]}, {name: "송신", vals: S["net.tx_bps"], c: 1}, ...(B["net.usage_bps"] ? [{name: "합계", vals: S["net.usage_bps"], c: 3}] : [])] : [{name: "사용", vals: S["net.usage_bps"]}, {name: "시간 최대", vals: S["net.usage_bps_max"], c: 5}], bps, {why, band: B["net.usage_bps"], marks})}
        ${chart("패킷(초당) · 드롭(간격당)", ts, [{name: "수신 pps", vals: S["net.rx_pps"]}, {name: "송신 pps", vals: S["net.tx_pps"], c: 1},
          {name: "드롭 수신", vals: S["net.drop_rx"], c: 2}, {name: "드롭 송신", vals: S["net.drop_tx"], c: 3}], num, {why})}
      </div>${instTable("net", d)}</section>
      ${vm ? "" : hostVms(d)}
      ${d.source === "store" ? `<p class="small muted">자체 이력 — 성능 감시가 ${Math.round((d.interval === 3600 ? 300 : d.interval) / 60)}분마다 모든 호스트·VM 의 최근 5분 실시간 평균을 직접 저장한 값${d.interval === 3600 ? "(1시간 평균·최대)" : ""}. vCenter 통계 수준과 무관하게 CPU ready·디스크 지연 포함.</p>` : ""}
      ${(d.alerts || []).length ? `<p class="small"><b>이 기간 성능 경보</b> ${d.alerts.slice(0, 6).map(a => `<span class="pf-fs ${esc(a.sev)}">${a.sev === "critical" ? "위험" : "경고"}</span> ${esc(new Date(a.start * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}))} ${esc(a.rule_name)}`).join(" · ")} <small class="muted">(차트의 세로선)</small></p>` : ""}
      ${(d.missing || []).length ? `<p class="small muted">이 기간에 없는 카운터 ${d.missing.length}개: ${esc(d.missing.join(", "))}${hist ? " — 과거(5분 이상) 통계는 vCenter 통계 수준에 따라 일부만 보관됩니다(수준 1: CPU·메모리 사용률·디스크·네트워크 사용량)." : ""}</p>` : ""}
      <p class="small muted">${esc(d.interval)}초 간격 · ${ts.length}개 표본 · 기준선: CPU·메모리 90%, CPU ready 5%/vCPU, 메모리 latency 1%, 디스크 지연 20 ms</p>`;
  }
  const sumS = (M, a, b) => { const x = M[a], y = M[b]; if (!x && !y) return null; const g = k => ((x && x[k]) || 0) + ((y && y[k]) || 0); return {last: g("last"), avg: g("avg"), max: g("max")}; };
  const maxS = (M, a, b) => { const x = M[a], y = M[b]; if (!x && !y) return null; const g = k => Math.max((x && x[k]) || 0, (y && y[k]) || 0); return {last: g("last"), avg: g("avg"), max: g("max")}; };
  function infoLine(d) {
    const i = d.info;
    if (d.kind === "vm") return `${esc(d.vcenter)} · ${i.cluster ? esc(i.cluster) + " · " : ""}호스트 <a href="#" data-pf-host="${esc(i.host)}">${esc(i.host || "-")}</a> · ${i.vcpu} vCPU · ${mb(i.mem_mb)} · ${esc(i.os || "")}${(i.ips || []).length ? " · " + esc(i.ips.join(", ")) : ""}${i.state !== "poweredOn" ? ` · <b>${esc(i.state)}</b>` : ""}
      ${window.AIOPS_VM_TRAFFIC ? ` · <a href="#" data-pf-net="${esc(d.name)}">vNIC 트래픽 상세</a>` : ""}`;
    return `${esc(d.vcenter)} · ${esc(i.cluster || "-")} · ${esc(i.model || "")} · ESXi ${esc(i.version || "-")} · CPU ${Math.round((i.cpu_mhz || 0) / 1000)} GHz · 메모리 ${mb(i.mem_mb)} · VM ${i.vms_total}${i.maintenance ? " · <b>유지 관리</b>" : ""}${i.state !== "connected" ? ` · <b>${esc(i.state)}</b>` : ""}`;
  }
  function instTable(g, d) {
    const xs = (d.instances || {})[g] || [];
    if (!xs.length) return "";
    const vm = d.kind === "vm";
    if (g === "disk") return `<details class="pf-inst" data-g="disk"${st.closed.has("disk") ? "" : " open"}><summary>${vm ? "가상 디스크별" : "장치(LUN)별"} ${xs.length}개</summary><table class="vc-t"><thead><tr><th>${vm ? "가상 디스크" : "장치"}</th><th>읽기 IOPS</th><th>쓰기 IOPS</th><th>읽기</th><th>쓰기</th><th>읽기 지연</th><th>쓰기 지연</th>${vm ? "" : "<th>DAVG</th><th>KAVG</th>"}<th>최대 지연</th></tr></thead><tbody>
      ${xs.map(r => `<tr><td class="vc-ent">${esc(r.id)}${r.label ? `<div class="small muted">${esc(r.label)}</div>` : ""}</td><td class="num">${num(r.read_iops)}</td><td class="num">${num(r.write_iops)}</td><td class="num">${Bps(r.read_Bps)}</td><td class="num">${Bps(r.write_Bps)}</td>
        <td class="num ${lvl("disk_lat_ms", r.read_lat_ms)}">${ms(r.read_lat_ms)}</td><td class="num ${lvl("disk_lat_ms", r.write_lat_ms)}">${ms(r.write_lat_ms)}</td>${vm ? "" : `<td class="num">${ms(r.device_lat_ms)}</td><td class="num">${ms(r.kernel_lat_ms)}</td>`}
        <td class="num ${lvl("disk_lat_ms", Math.max(r.read_lat_ms_max || 0, r.write_lat_ms_max || 0))}">${ms(Math.max(r.read_lat_ms_max || 0, r.write_lat_ms_max || 0) || null)}</td></tr>`).join("")}</tbody></table></details>`;
    return `<details class="pf-inst" data-g="net"${st.closed.has("net") ? "" : " open"}><summary>${vm ? "vNIC별" : "물리 NIC(vmnic)별"} ${xs.length}개</summary><table class="vc-t"><thead><tr><th>${vm ? "vNIC(장치 키)" : "vmnic"}</th><th>수신</th><th>송신</th><th>수신 최대</th><th>송신 최대</th><th>수신 pps</th><th>송신 pps</th><th>드롭(합)</th></tr></thead><tbody>
      ${xs.map(r => `<tr><td class="vc-ent">${esc(r.id)}${r.label ? `<div class="small muted">${esc(r.label)}</div>` : ""}</td><td class="num">${bps(r.rx_bps)}</td><td class="num">${bps(r.tx_bps)}</td><td class="num">${bps(r.rx_bps_max)}</td><td class="num">${bps(r.tx_bps_max)}</td>
        <td class="num">${num(r.rx_pps)}</td><td class="num">${num(r.tx_pps)}</td><td class="num${(r.drop_rx_max || r.drop_tx_max) ? " warn" : ""}">${num((r.drop_rx_avg || 0) + (r.drop_tx_avg || 0) ? Math.round(((r.drop_rx_avg || 0) + (r.drop_tx_avg || 0)) * d.ts.length) : 0)}</td></tr>`).join("")}</tbody></table></details>`;
  }
  function hostVms(d) {
    const v = (d.info && d.info.vms) || [];
    if (!v.length) return "";
    const core = d.info.core_mhz || 0;
    return `<section class="pf-sec"><h4>이 호스트의 VM <small class="muted">CPU 사용량 순 상위 ${v.length}/${d.info.vms_total} (vCenter 요약값)</small></h4>
      <table class="vc-t"><thead><tr><th>VM</th><th>전원</th><th>vCPU</th><th>CPU</th><th>메모리(활성/할당)</th></tr></thead><tbody>
      ${v.map(x => `<tr class="pf-r" tabindex="0" data-vmgo="${esc(x.name)}"><td><b>${esc(x.name)}</b></td><td>${esc(x.power)}</td><td class="num">${x.vcpu}</td>
        <td>${bar(core && x.power === "poweredOn" ? x.cpu_mhz * 100 / (core * x.vcpu) : null, "cpu_pct")} <small class="muted">${Math.round(x.cpu_mhz).toLocaleString()} MHz</small></td>
        <td class="num">${mb(x.mem_used_mb)} / ${mb(x.mem_mb)}</td></tr>`).join("")}</tbody></table></section>`;
  }

  // ------------------------------------------------------------ 2.24.0 진단 · AI 해설
  function md(t) {
    const inl = x => esc(x).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>"); const out = [];
    for (const ln of String(t || "").replace(/<think>[\s\S]*?<\/think>/g, "").split("\n")) {
      const m = ln.match(/^(#{1,4})\s+(.+)$/);
      if (m) out.push(`<h5 class="rv-mh">${inl(m[2])}</h5>`); else if (/^\s*([-*]|\d+\.)\s+/.test(ln)) out.push(`<div class="rv-li">• ${inl(ln.replace(/^\s*([-*]|\d+\.)\s+/, ""))}</div>`); else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
    }
    return out.join("");
  }
  const AREA = {cpu: "CPU", mem: "메모리", disk: "디스크", net: "네트워크", baseline: "평소 대비", neighbor: "이웃 VM"};
  const SEVL = {critical: "위험", warning: "주의", info: "참고"};
  function diagBox(d) {
    const g = d.diag;
    if (!g) return d.range === "rt" ? "" : `<div class="pf-diag ok small muted">자동 진단은 '실시간 1시간'에서 합니다.</div>`;
    const f = g.findings || [];
    const ai = st.ai && st.ai.key === selKey() ? `<div class="pf-ai rv-md">${md(st.ai.text)}</div>` : "";
    return `<div class="pf-diag ${esc(g.level)}" role="region" aria-label="성능 진단">
      <div class="pf-dg-h"><b>${g.level === "critical" ? "위험 신호" : g.level === "warning" ? "주의할 점" : "특이 사항 없음"}</b>
        <small class="muted">최근 1시간 · 24시간 평소 대비 · 같은 호스트 VM 기준 자동 진단</small>
        ${A.can("operate") ? `<button class="btn-sm" id="pf-ai"${st.aiBusy ? " disabled" : ""}>${st.aiBusy ? "AI 해설 작성 중…" : "AI 해설"}</button>` : ""}</div>
      ${f.length ? `<ul class="pf-fl">${f.map(x => `<li class="${esc(x.sev)}"><span class="pf-fs ${esc(x.sev)}">${esc(SEVL[x.sev] || x.sev)}</span><span class="pf-fa">${esc(AREA[x.area] || x.area)}</span>
          <b>${esc(x.title)}</b> <span class="small">${esc(x.evidence)}</span>${x.advice ? `<div class="small muted pf-adv">→ ${esc(x.advice)}</div>` : ""}</li>`).join("")}</ul>` : `<p class="small muted">CPU ready·메모리 회수·디스크 지연·드롭·평소 대비 급증 모두 기준선 아래입니다.</p>`}
      ${ai}</div>`;
  }
  const selKey = () => st.sel ? `${st.sel.kind}|${st.sel.vcenter}|${st.sel.name}` : "";
  async function explain() {
    if (!st.sel || st.aiBusy) return;
    const key = selKey(), s = st.sel;
    st.aiBusy = true; renderDet();
    try { const r = await A.api("POST", "/api/perf/explain", {kind: s.kind, name: s.name, vcenter: s.vcenter}); st.ai = {key, text: r.text}; }
    catch (e) { A.fail("AI 해설을 만들지 못했습니다", e); }
    finally { st.aiBusy = false; renderDet(); }
  }

  // ------------------------------------------------------------ 2.24.0 비교(최대 4대, 시간축)
  const CMP_METRICS = [["cpu.usage_pct", "CPU 사용률(%)", pct], ["cpu.ready_pct", "CPU ready(%)", pct], ["mem.usage_pct", "메모리 사용률(%)", pct],
    ["disk.max_lat_ms", "디스크 최대 지연(ms)", ms], ["disk.read_iops", "디스크 읽기 IOPS", num], ["disk.write_iops", "디스크 쓰기 IOPS", num],
    ["disk.usage_Bps", "디스크 처리량", Bps], ["net.usage_bps", "네트워크", bps]];
  const cmpKey = x => `${x.kind}|${x.vcenter}|${x.name}|${st.range}`;
  const cmpLoading = new Set();
  async function loadCmp() {
    const keep = new Set(st.cmp.map(cmpKey));                // 지운 대상·지난 기간 데이터 정리
    for (const k of Object.keys(st.cmpData)) if (!keep.has(k)) delete st.cmpData[k];
    const todo = st.cmp.filter(x => !st.cmpData[cmpKey(x)] && !cmpLoading.has(cmpKey(x)));
    renderCmp();
    await Promise.all(todo.map(async x => {
      const k = cmpKey(x), rng = st.range;                    // await 전에 키·기간 고정
      cmpLoading.add(k);
      try { st.cmpData[k] = await A.api("GET", `/api/perf/detail?kind=${x.kind}&name=${enc(x.name)}&vcenter=${enc(x.vcenter)}&range=${rng}`); }
      catch (e) { st.cmpData[k] = {error: e.message || "오류", ts: [], series: {}}; }
      finally { cmpLoading.delete(k); }
    }));
    renderCmp();
  }
  function chartT(title, items, fmt) {                         // 계열마다 자기 시각(대상마다 표본 시각이 조금씩 다름)
    const W = 900, H = 190, P = 52;
    const ls = items.map((l, idx) => ({...l, idx})).filter(l => l.ts.length && l.vals.some(v => v != null));   // 색 = 원래 순서(표 범례와 일치)
    if (!ls.length) return `<p class="muted small">비교할 데이터가 없습니다.</p>`;
    const t0 = Math.min(...ls.map(l => l.ts[0])), t1 = Math.max(...ls.map(l => l.ts[l.ts.length - 1])), span = Math.max(1, t1 - t0);
    const mx = Math.max(...ls.flatMap(l => l.vals.filter(v => v != null)), 1e-9) * 1.08;
    const X = t => P + (t - t0) / span * (W - P - 6), Y = v => H - 18 - v / mx * (H - 28);
    const path = l => { let d = "", pen = false; l.vals.forEach((v, i) => { if (v == null) { pen = false; return; } d += `${pen ? "L" : "M"}${X(l.ts[i]).toFixed(1)},${Y(v).toFixed(1)}`; pen = true; }); return d; };
    const grid = [0, 0.5, 1].map(f => `<line class="st-grid" x1="${P}" x2="${W}" y1="${Y(mx * f)}" y2="${Y(mx * f)}"/><text class="st-ax" x="${P - 4}" y="${Y(mx * f) + 4}" text-anchor="end">${esc(short(mx * f))}</text>`).join("");
    const xt = [0, 0.25, 0.5, 0.75, 1].map((f, i) => `<text class="st-ax" x="${X(t0 + span * f)}" y="${H - 3}" text-anchor="${i === 0 ? "start" : i === 4 ? "end" : "middle"}">${esc(tick(t0 + span * f, st.range))}</text>`).join("");
    return `<svg class="st-chart pf-svg pf-cmp-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">${grid}${ls.map(l => `<path class="pf-l s${l.idx}" d="${path(l)}"/>`).join("")}${xt}</svg>`;
  }
  function renderCmp() {
    const box = $("#pf-cmp"); if (!box) return;
    if (!st.cmp.length) { box.innerHTML = ""; box.hidden = true; return; }
    box.hidden = false;
    const m = CMP_METRICS.find(x => x[0] === st.cmpMetric) || CMP_METRICS[0];
    const items = st.cmp.map(x => { const d = st.cmpData[cmpKey(x)]; return {x, d, ts: (d && d.ts) || [], vals: (d && d.series && d.series[m[0]]) || []}; });
    const stat = v => { const xs = v.filter(y => y != null); return xs.length ? {last: xs[xs.length - 1], avg: xs.reduce((a, b) => a + b, 0) / xs.length, max: Math.max(...xs)} : null; };
    box.innerHTML = `<div class="pf-cmp-h"><b>비교</b> <small class="muted">최대 4대 · ${esc((RANGES.find(r => r[0] === st.range) || RANGES[0])[1])}</small>
        <select id="pf-cmp-m" aria-label="비교 지표">${CMP_METRICS.map(([k, l]) => `<option value="${k}"${k === m[0] ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>
        <button class="btn-sm" id="pf-cmp-clear">비교 지우기</button></div>
      ${items.some(i => !i.d) ? `<p class="small muted">불러오는 중…</p>` : chartT(m[1], items, m[2])}
      <table class="vc-t pf-cmp-t"><thead><tr><th></th><th>대상</th><th>최근</th><th>평균</th><th>최대</th><th></th></tr></thead><tbody>
      ${items.map((i, n) => { const s2 = stat(i.vals); return `<tr><td><i class="pf-sw s${n}"></i></td><td><a href="#" data-cmp-go="${n}">${esc(i.x.name)}</a> <small class="muted">${i.x.kind === "vm" ? "VM" : "호스트"}${i.d && i.d.error ? ` · ${esc(i.d.error)}` : ""}</small></td>
        <td class="num">${s2 ? esc(m[2](s2.last)) : "—"}</td><td class="num">${s2 ? esc(m[2](s2.avg)) : "—"}</td><td class="num">${s2 ? esc(m[2](s2.max)) : "—"}</td>
        <td><button class="btn-sm" data-cmp-del="${n}" aria-label="${esc(i.x.name)} 비교에서 빼기">✕</button></td></tr>`; }).join("")}</tbody></table>`;
  }
  function addCmp() {
    if (!st.sel) return;
    const x = {...st.sel};
    if (st.cmp.some(y => y.kind === x.kind && y.name === x.name && y.vcenter === x.vcenter)) { A.ok("이미 비교 중입니다"); return; }
    if (st.cmp.length >= 4) { A.fail("비교는 최대 4대까지", new Error("하나를 빼고 추가하세요")); return; }
    st.cmp.push(x);
    if (st.det && st.det.range === st.range) st.cmpData[cmpKey(x)] = st.det;
    loadCmp();
  }

  // ------------------------------------------------------------ 2.24.0 클러스터별 호스트 히트맵
  function heat() {
    if (st.kind !== "host" || !st.ents) return "";
    const now = new Map(((st.top && st.top.kind === "host" && st.top.rows) || []).map(r => [`${r.vcenter}\u0000${r.name}`, r.now]));
    const by = {};
    for (const e of st.ents.items) (by[`${e.vcenter} · ${e.cluster || "(독립 호스트)"}`] ||= []).push(e);
    const metric = st.sort === "mem_pct" ? "mem_pct" : "cpu_pct";
    const col = v => v == null ? "na" : v >= 90 ? "h5" : v >= 75 ? "h4" : v >= 50 ? "h3" : v >= 25 ? "h2" : "h1";
    return `<div class="pf-heat" aria-label="클러스터별 호스트 ${metric === "mem_pct" ? "메모리" : "CPU"} 사용률">
      <div class="small muted">클러스터별 호스트 — ${metric === "mem_pct" ? "메모리" : "CPU"} 사용률(정렬 기준을 '메모리'로 바꾸면 메모리)</div>
      ${Object.entries(by).sort().map(([k, hs]) => `<div class="pf-hc"><span class="pf-hn">${esc(k)}</span><span class="pf-tiles">${hs.sort((a, b) => a.name.localeCompare(b.name)).map(h => {
        const n = now.get(`${h.vcenter}\u0000${h.name}`); const v = n && n[metric] != null ? n[metric] : h[metric];
        return `<button type="button" class="pf-tile ${col(v)}${h.maintenance ? " mm" : ""}${st.sel && st.sel.name === h.name ? " on" : ""}" data-name="${esc(h.name)}" data-vc="${esc(h.vcenter)}" title="${esc(h.name)} · ${v == null ? "—" : v.toFixed(0) + "%"}${h.maintenance ? " · 유지 관리" : ""}">${v == null ? "" : Math.round(v)}</button>`; }).join("")}</span></div>`).join("")}</div>`;
  }

  // ------------------------------------------------------------ 화면 골격·이벤트
  const TABS = [["detail", "상세"], ["map", "호스트 맵"], ["alerts", "이상·경보"], ["rules", "감시 규칙"]];
  const ctx = {select: (kind, name, vc) => { if (st.tab !== "detail") { st.tab = "detail"; shell(); loadEnts(); } select(kind, name, vc); }, tab: ""};
  function tabs() {
    const n = window.AIOPS_PW && window.AIOPS_PW.count();
    return `<div class="pf-tabs" role="tablist">${TABS.map(([k, l]) => `<button type="button" role="tab" data-tab="${k}" class="${st.tab === k ? "on" : ""}" aria-selected="${st.tab === k}">${esc(l)}${k === "alerts" && n ? ` <span class="pf-badge">${n}</span>` : ""}</button>`).join("")}</div>`;
  }
  function shell() {
    const box = $("#pf-body");
    if (st.tab !== "detail") {
      box.innerHTML = tabs() + `<div id="pf-tab" class="pf-tabbox"></div>`;
      const tb = $("#pf-tab"); ctx.tab = st.tab;
      if (window.AIOPS_PW) window.AIOPS_PW[st.tab](tb, ctx); else tb.innerHTML = `<div class="empty">성능 감시 모듈을 불러오지 못했습니다</div>`;
      return;
    }
    box.innerHTML = tabs() + `<div class="pf-bar-top">
        <div class="pf-seg" role="group" aria-label="대상"><button type="button" data-k="host" class="${st.kind === "host" ? "on" : ""}" aria-pressed="${st.kind === "host"}">호스트</button><button type="button" data-k="vm" class="${st.kind === "vm" ? "on" : ""}" aria-pressed="${st.kind === "vm"}">VM</button></div>
        <input id="pf-q" type="search" placeholder="이름·클러스터·호스트·IP 검색" value="${esc(st.q)}" aria-label="검색">
        <label class="small">정렬 <select id="pf-sort">${SORTS.map(([k, v]) => `<option value="${k}"${k === st.sort ? " selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
        <button class="btn-sm solid" id="pf-now"${st.topBusy ? " disabled" : ""}>${st.topBusy ? "측정 중…" : "지금 부하 측정"}</button>
      </div>
      <div id="pf-cmp" class="pf-cmp" hidden></div>
      <div class="pf-wrap"><div id="pf-list" class="pf-list"></div><div id="pf-det" class="pf-det"></div></div>`;
    renderList(); renderDet(); renderCmp();
  }
  function select(kind, name, vcenter) {
    if (kind !== st.kind) { st.kind = kind; st.ents = null; st.top = null; shell(); loadEnts(); }
    st.sel = {kind, name, vcenter: vcenter || ""}; st.det = null; renderList(); renderDet(); loadDet();
    const det = $("#pf-det"); if (det && window.innerWidth < 900) det.scrollIntoView({block: "start"});
  }
  let wired = false;
  function wire() {
    if (wired) return; wired = true;
    const box = $("#pf-body");
    box.addEventListener("click", e => {
      const t = e.target;
      const k = t.closest("[data-k]"); if (k) { if (k.dataset.k !== st.kind) { SEQ.top++; SEQ.det++; st.topBusy = false; st.kind = k.dataset.k; st.ents = null; st.top = null; st.sel = null; st.det = null; st.sort = st.sort === "ready_pct" && st.kind === "host" ? "cpu_pct" : st.sort; st.more = 0; shell(); loadEnts(); } return; }
      const tb = t.closest("[data-tab]"); if (tb && tb.closest(".pf-tabs")) { if (tb.dataset.tab !== st.tab) { st.tab = tb.dataset.tab; shell(); if (st.tab === "detail") { renderList(); if (!st.ents) loadEnts(); } } return; }
      if (t.id === "pf-now") { loadTop(true); return; }
      if (t.id === "pf-ai") { explain(); return; }
      if (t.id === "pf-addcmp") { addCmp(); return; }
      if (t.id === "pf-cmp-clear") { st.cmp = []; st.cmpData = {}; renderCmp(); return; }
      const cd = t.closest("[data-cmp-del]"); if (cd) { st.cmp.splice(+cd.dataset.cmpDel, 1); loadCmp(); return; }
      const cg = t.closest("[data-cmp-go]"); if (cg) { e.preventDefault(); const x = st.cmp[+cg.dataset.cmpGo]; if (x) select(x.kind, x.name, x.vcenter); return; }
      const tl = t.closest(".pf-tile[data-name]"); if (tl) { select("host", tl.dataset.name, tl.dataset.vc); return; }
      if (t.id === "pf-more") { st.more += 300; renderList(); return; }
      if (t.id === "pf-dre" || t.id === "pf-dre2") { loadDet(true); return; }
      const h = t.closest("[data-pf-host]"); if (h) { e.preventDefault(); if (h.dataset.pfHost) select("host", h.dataset.pfHost, st.sel && st.sel.vcenter); return; }
      const nt = t.closest("[data-pf-net]"); if (nt) { e.preventDefault(); window.AIOPS_VM_TRAFFIC(nt.dataset.pfNet); return; }
      const vg = t.closest("[data-vmgo]"); if (vg) { select("vm", vg.dataset.vmgo, st.sel && st.sel.vcenter); return; }
      const r = t.closest("tr[data-name]"); if (r) select(st.kind, r.dataset.name, r.dataset.vc);
    });
    box.addEventListener("toggle", e => { const g = e.target.dataset && e.target.dataset.g; if (g) { if (e.target.open) st.closed.delete(g); else st.closed.add(g); } }, true);
    box.addEventListener("keydown", e => {
      if (e.key !== "Enter") return;
      const r = e.target.closest && e.target.closest("tr[data-name]"); if (r) select(st.kind, r.dataset.name, r.dataset.vc);
      const vg = e.target.closest && e.target.closest("[data-vmgo]"); if (vg) select("vm", vg.dataset.vmgo, st.sel && st.sel.vcenter);
    });
    box.addEventListener("change", e => {
      if (e.target.id === "pf-sort") { st.sort = e.target.value; renderList(); if (NOW_KEYS.includes(st.sort) && !(st.top && st.top.kind === st.kind)) loadTop(); }
      if (e.target.id === "pf-range") { st.range = e.target.value; st.det = null; loadDet(); if (st.cmp.length) loadCmp(); }
      if (e.target.id === "pf-cmp-m") { st.cmpMetric = e.target.value; renderCmp(); }
    });
    box.addEventListener("input", e => { if (e.target.id === "pf-q" && !e.isComposing) { st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(renderList, 200); } });
    box.addEventListener("compositionend", e => { if (e.target.id === "pf-q") { st.q = e.target.value; renderList(); } });
  }
  async function show(kind, name, vcenter) {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-pf") d.hidden = true; });
    $("#drawer-pf").hidden = false; wire();
    if (kind && kind !== st.kind) { st.kind = kind; st.ents = null; st.top = null; }
    shell();
    await loadEnts();
    if (name) select(kind || st.kind, name, vcenter);
  }
  const nav = document.getElementById("nav-pf"); if (nav) nav.onclick = () => show();
  const rl = document.getElementById("pf-reload"); if (rl) rl.onclick = () => { loadEnts(); if (st.top) loadTop(true); loadDet(); };
  setInterval(() => {
    const d = $("#drawer-pf"); if (!d || d.hidden || document.hidden) return;
    if (st.tab === "detail") { if (st.sel && st.range === "rt" && !st.detBusy) loadDet(false, true); }
    else if (window.AIOPS_PW && $("#pf-tab")) window.AIOPS_PW.refresh(st.tab, $("#pf-tab"), ctx);
  }, 60000);   // 실시간은 1분마다
  window.AIOPS_PERF = show;
  { const q = new URLSearchParams(location.search); if (q.get("view") === "pf" && ["map", "alerts", "rules"].includes(q.get("tab"))) st.tab = q.get("tab");
    if (q.get("view") === "pf" && q.get("name")) setTimeout(() => show(q.get("kind") === "host" ? "host" : "vm", q.get("name"), q.get("vcenter") || ""), 1200); }
})();
