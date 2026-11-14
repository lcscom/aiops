/* 라이선스 관리(2.16.0) — 프로젝트 단위로 공급자 데이터·Broadcom CSP 데이터·실사용(vCenter 커넥터·RVTools·VCF Operations 사용량)을 모아 비교.
   설계 참고: postout7979/VCF-Lic-MGMT(MIT). 키는 기본으로 가려 보이고 '키 전체 보기'(operate·감사로그)에서만 전체 표시 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const enc = encodeURIComponent;
  const st = {tab: "ov", project: "*", ov: null, data: {}, reveal: false, tf: "", sort: {}, src: null, batches: [], projects: null, ai: null, mf: ""};
  const TABS = [["ov", "종합 현황"], ["match", "키 매칭"], ["hosts", "실사용"], ["csp", "CSP 현황"], ["supplier", "공급자 현황"], ["usage", "VCF Ops 사용량"],
                ["data", "데이터·수집"], ["proj", "프로젝트"], ["set", "설정"]];
  const SEV = {critical: ["위험", "bad"], error: ["오류", "bad"], warning: ["경고", "warn"], info: ["정보", "inf"]};
  const MST = {matched: ["매칭", "ok"], inventory_only: ["실사용만", "warn"], csp_only: ["CSP만", "inf"]};
  const CAT = {perpetual: "영구(CPU)", term: "구독(코어)", other: "기타", unlicensed: "미할당"};
  const KIND = {vcenter: "vCenter 커넥터", rvtools: "RVTools", vcfops: "VCF Ops 사용량"};
  const n = (x, d = 0) => x === null || x === undefined || x === "" ? "—" : Number(x).toLocaleString(undefined, {maximumFractionDigits: d});
  const fmt = ts => ts ? new Date(ts * 1000).toLocaleString([], {year: "2-digit", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";
  const b = (m, k, lab) => { const x = m[k] || [k, "unk"]; return `<span class="rd-b ${x[1]}">${esc(lab || x[0])}</span>`; };
  const can = p => !A.me || !A.can || A.can(p);
  const perms = box => { if (A.me && A.can) $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); }); };
  const days = d => d ? Math.floor((new Date(d) - new Date(new Date().toDateString())) / 86400000) : null;
  const dateCell = d => { const x = days(d); return d ? `<span class="${x < 0 ? "cc-na" : x <= 90 ? "lc-soon" : ""}">${esc(d)}${x < 0 ? " (만료)" : x <= 90 ? ` (${x}일)` : ""}</span>` : "—"; };
  const qp = () => `project=${enc(st.project)}`;

  async function loadOv() { try { st.ov = await A.api("GET", `/api/license/overview?${qp()}`, undefined, {background: true}); } catch (e) { A.fail("라이선스 현황 실패", e); } }
  async function data(what) {
    const k = `${what}|${st.project}|${st.reveal}`;
    if (!st.data[k]) {
      try { st.data[k] = (await A.api("GET", `/api/license/${st.reveal ? "reveal" : "data"}/${what}?${qp()}`, undefined, {background: true})).items; }
      catch (e) { A.fail("불러오기 실패", e); st.data[k] = []; }
    }
    return st.data[k];
  }
  const reset = () => { st.data = {}; st.ov = null; st.projects = null; };

  // ------------------------------------------------------------------ 도넛(SVG)
  function donut(title, segs, center, sub) {
    const tot = segs.reduce((a, s) => a + (s.v || 0), 0); let acc = 0; const R = 46, C = 2 * Math.PI * R;
    const arcs = tot ? segs.filter(s => s.v > 0).map(s => { const len = s.v / tot * C, o = `<circle r="${R}" cx="60" cy="60" fill="none" stroke="${s.c}" stroke-width="16" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-acc}" transform="rotate(-90 60 60)"><title>${esc(s.l)} ${n(s.v)}</title></circle>`; acc += len; return o; }).join("")
      : `<circle r="${R}" cx="60" cy="60" fill="none" stroke="var(--line2)" stroke-width="16"/>`;
    return `<div class="lc-donut"><h5>${esc(title)}</h5><div class="lc-dw"><svg viewBox="0 0 120 120" width="120" height="120">${arcs}<text x="60" y="58" text-anchor="middle" class="lc-dc">${esc(center ?? n(tot))}</text><text x="60" y="74" text-anchor="middle" class="lc-ds">${esc(sub || "")}</text></svg>
      <div class="lc-leg">${segs.map(s => `<div><i style="background:${s.c}"></i>${esc(s.l)} <b>${n(s.v)}</b></div>`).join("")}</div></div></div>`;
  }
  const C = {ok: "#2e7d32", warn: "#c77700", bad: "#c21d00", blue: "#1d6fb8", aqua: "#1baf7a", grey: "#8a96a0", mag: "#b0458a"};

  // ------------------------------------------------------------------ 종합 현황
  function ovTab() {
    const o = st.ov; if (!o) return `<p class="muted">불러오는 중…</p>`;
    const s = o.summary, m = o.match, inv = s.inventory.by_category, cu = s.csp.by_unit, sp = s.supplier.by_type;
    const tiles = [["키 매칭률", m.rate == null ? "—" : m.rate + "%", m.rate == null ? "" : m.rate >= 90 ? "ok" : "warn"], ["위험·오류", o.checks.filter(c => ["critical", "error"].includes(c.severity)).length, o.checks.some(c => ["critical", "error"].includes(c.severity)) ? "bad" : "ok"],
      ["경고", o.checks.filter(c => c.severity === "warning").length, ""], ["실사용 호스트", s.inventory.hosts, ""], ["vCenter", s.inventory.vcenters, ""],
      ["CSP 키", s.csp.keys, ""], ["공급자 행", s.supplier.rows, ""], ["VCF Ops 보고서", s.usage.reports, ""]];
    const invSegs = [["perpetual", C.blue], ["term", C.aqua], ["other", C.grey], ["unlicensed", C.bad]].filter(([k]) => inv[k]).map(([k, c]) => ({l: `${CAT[k]} 호스트`, v: inv[k].hosts, c}));
    const cspCore = cu.Core || cu.core || {active: 0, expired: 0}, cspProc = cu.Processor || cu.processor || cu.CPU || {active: 0, expired: 0};
    const supP = sp.PERPETUAL || {active: 0, expired: 0}, supS = sp.SUBSCRIPTION || {active: 0, expired: 0};
    const projRows = (o.projects || []).map(p => { const i = p.inventory.by_category || {};
      return `<tr class="rd-click" data-lcp="${esc(p.id ?? "")}"><td><b>${esc(p.name)}</b><div class="small muted">${esc(p.location || "")}</div></td><td>${n(p.supplier.rows)}</td>
        <td>${n((p.supplier.by_type.PERPETUAL || {}).active)} / ${n((p.supplier.by_type.SUBSCRIPTION || {}).active)}</td><td>${n(p.csp.keys)}</td>
        <td>${n(((p.csp.by_unit.Core || {}).active || 0))}</td><td>${n(p.inventory.hosts)}</td><td>${n((i.perpetual || {}).qty)}</td><td>${n((i.term || {}).qty)}</td><td>${n(p.usage.reports)}</td></tr>`; }).join("");
    return `<div class="rd-tiles">${tiles.map(([k, v, c]) => `<div class="rd-tile ${c}"><small>${k}</small><b>${v}</b></div>`).join("")}</div>
      <div class="lc-donuts">
        ${donut("키 매칭(실사용 ↔ CSP)", [{l: "매칭", v: m.matched, c: C.ok}, {l: "실사용만", v: m.inventory_only, c: C.warn}, {l: "CSP만", v: m.csp_only, c: C.blue}], m.rate == null ? "—" : m.rate + "%", `${n(m.matched)}/${n(m.total)} 키`)}
        ${donut("실사용 호스트 라이선스 구분", invSegs, n(s.inventory.hosts), "호스트")}
        ${donut("실사용 수량", [{l: "영구 — CPU", v: (inv.perpetual || {}).qty, c: C.blue}, {l: "구독 — 코어(16 최소)", v: (inv.term || {}).qty, c: C.aqua}], "", "CPU · 코어")}
        ${donut("CSP Core 유지·만료", [{l: "유지", v: cspCore.active, c: C.ok}, {l: "만료", v: cspCore.expired, c: C.bad}], n(cspCore.active + cspCore.expired), "Core")}
        ${cspProc.active + cspProc.expired ? donut("CSP Processor 유지·만료", [{l: "유지", v: cspProc.active, c: C.ok}, {l: "만료", v: cspProc.expired, c: C.bad}], n(cspProc.active + cspProc.expired), "Processor") : ""}
        ${donut("공급자 수량(Quantity-ENT)", [{l: "Perpetual", v: supP.active + supP.expired, c: C.blue}, {l: "Subscription 유지", v: supS.active, c: C.aqua}, {l: "Subscription 만료", v: supS.expired, c: C.bad}], "", "ENT")}
      </div>
      <div class="rd-card"><h4>점검 <small>LIC-01~12 — 만료·초과·미할당·CSP 미등록·16코어 최소·사용량 보고 주기</small></h4>${o.checks.length ? `<table class="rd-t"><tbody>${o.checks.map(c => `<tr><td>${b(SEV, c.severity)}</td><td class="small nowrap">${esc(c.id)}</td><td><b>${esc(c.entity)}</b></td><td>${esc(c.title)}</td><td class="small">${esc(c.detail || "")}</td><td class="small rd-fix">${esc(c.fix || "")}${c.ref ? ` <a href="${esc(c.ref)}" target="_blank" rel="noopener">근거</a>` : ""}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">문제 없음(또는 데이터 없음)</p>`}</div>
      ${st.project === "*" ? `<div class="rd-card"><h4>프로젝트별 <small>행을 누르면 그 프로젝트로</small></h4><table class="rd-t"><thead><tr><th>프로젝트</th><th>공급자 행</th><th>공급자 Perpetual / Subscription</th><th>CSP 키</th><th>CSP Core</th><th>실사용 호스트</th><th>영구(CPU)</th><th>구독(코어)</th><th>VCF Ops</th></tr></thead><tbody>${projRows || `<tr><td colspan="9" class="muted">프로젝트가 없습니다 — '프로젝트' 탭에서 만드세요.</td></tr>`}</tbody></table></div>` : ""}
      <div class="rd-card"><h4>AI 요약 <small>설정된 LLM(PAIS 등) — 현황·점검 집계만 보내고 키는 가린 채로</small></h4><button class="btn-sm solid" id="lc-ai" data-perm="operate" ${o.llm ? "" : "disabled"}>AI 요약 작성</button>
        <div class="rv-md" id="lc-aib">${st.ai ? md(st.ai.report) : ""}</div></div>`;
  }
  function md(t) {
    const inl = x => esc(x).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>"); const out = [], tbl = [];
    const flush = () => { if (!tbl.length) return; const rows = tbl.filter(r => !/^\s*\|?[\s:\-|]+\|?\s*$/.test(r)).map(r => r.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim()));
      out.push(`<table class="rd-t"><thead><tr>${rows[0].map(c => `<th>${inl(c)}</th>`).join("")}</tr></thead><tbody>${rows.slice(1).map(r => `<tr>${r.map(c => `<td>${inl(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`); tbl.length = 0; };
    for (const ln of String(t || "").replace(/<think>[\s\S]*?<\/think>/g, "").split("\n")) {
      if (ln.trim().startsWith("|")) { tbl.push(ln); continue; } flush();
      const m = ln.match(/^(#{1,4})\s+(.+)$/);
      if (m) out.push(`<h5 class="rv-mh">${inl(m[2])}</h5>`); else if (/^\s*[-*]\s+/.test(ln)) out.push(`<div class="rv-li">• ${inl(ln.replace(/^\s*[-*]\s+/, ""))}</div>`); else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
    }
    flush(); return out.join("");
  }

  // ------------------------------------------------------------------ 표
  function grid(key, rows, cols, opt = {}) {
    const f = (st.tf || "").toLowerCase(), so = st.sort[key] || {};
    let R = rows.filter(r => !f || cols.some(c => String(c.v(r) ?? "").toLowerCase().includes(f)));
    if (opt.filter) R = R.filter(opt.filter);
    if (so.i != null) { const c = cols[so.i]; R = [...R].sort((a, b2) => { const x = c.v(a), y = c.v(b2); return (typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""))) * (so.d ? -1 : 1); }); }
    return `<div class="rd-card"><h4>${opt.title} <small>${R.length}/${rows.length}</small></h4>${opt.note ? `<p class="small muted">${opt.note}</p>` : ""}<div class="rd-scroll"><table class="rd-t"><thead><tr>${opt.sel ? `<th><input type="checkbox" data-lcall="${key}"></th>` : ""}${cols.map((c, i) => `<th class="rd-click" data-lcsort="${key}:${i}">${esc(c.h)}${so.i === i ? (so.d ? " ▼" : " ▲") : ""}</th>`).join("")}</tr></thead>
      <tbody>${R.slice(0, 5000).map(r => `<tr>${opt.sel ? `<td><input type="checkbox" data-lcsel="${esc(opt.sel(r))}"></td>` : ""}${cols.map(c => `<td class="${c.c || ""}">${c.f ? c.f(r) : esc(String(c.v(r) ?? ""))}</td>`).join("")}</tr>`).join("")}</tbody></table></div></div>`;
  }
  const filt = (extra = "") => `<div class="rd-tools"><input id="lc-tf" placeholder="필터 — 모든 열" value="${esc(st.tf)}" style="min-width:300px">${extra}<span class="rd-sp"></span>
    ${can("operate") ? `<label class="small"><input type="checkbox" id="lc-rev" ${st.reveal ? "checked" : ""}> 키 전체 보기 <span class="muted">(감사로그)</span></label>` : ""}</div>`;
  const projSel = id => `<select id="${id}"><option value="">(할당 해제)</option>${(st.ov?.projects || []).filter(p => p.id).map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}</select>`;
  const assignBar = kind => can("operate") ? `<div class="rd-tools lc-asg" data-perm="operate">선택한 행을 ${projSel("lc-asgp")} <button class="btn-sm solid" data-lcassign="${kind}">프로젝트에 할당</button></div>` : "";

  async function matchTab() {
    const rows = await data("match");
    return filt(`<select id="lc-mf"><option value="">모든 상태</option>${Object.entries(MST).map(([k, v]) => `<option value="${k}" ${st.mf === k ? "selected" : ""}>${v[0]}</option>`).join("")}<option value="over" ${st.mf === "over" ? "selected" : ""}>CSP 초과</option></select>`)
      + grid("match", rows, [
        {h: "License Key", v: r => r.license_key, c: "mono small"}, {h: "상태", v: r => r.status, f: r => b(MST, r.status) + (r.over ? ' <span class="rd-b bad">초과</span>' : "")},
        {h: "제품", v: r => r.name}, {h: "구분", v: r => CAT[r.category] || r.category}, {h: "실사용 수량", v: r => r.inv_qty, f: r => n(r.inv_qty)}, {h: "호스트", v: r => r.inv_hosts, f: r => n(r.inv_hosts)},
        {h: "vCenter 사용/총량", v: r => r.vc_used, f: r => r.vc_total == null ? "—" : `${n(r.vc_used)} / ${n(r.vc_total)}`}, {h: "만료", v: r => r.expires, f: r => dateCell(r.expires)},
        {h: "CSP 수량", v: r => r.csp_qty, f: r => r.csp_qty == null ? "—" : `${n(r.csp_qty)} ${esc(r.csp_unit || "")}`}, {h: "CSP 종료", v: r => r.csp_end, f: r => dateCell(r.csp_end)},
        {h: "CSP 폴더", v: r => (r.csp_folders || []).join(", "), c: "small"}, {h: "공급자", v: r => r.supplier ? "있음" : "", c: "small"}, {h: "실사용 소스", v: r => (r.sources || []).join(", "), c: "small"}],
        {title: "라이선스 키 매칭 — 실사용(vCenter·RVTools) ↔ Broadcom CSP", note: "실사용 수량: 영구 = CPU 수, 구독(코어) = CPU 당 최소 16코어 적용 코어 수. 'vCenter 사용/총량'은 vCenter·RVTools 라이선스 목록 값.",
         filter: r => !st.mf || (st.mf === "over" ? r.over : r.status === st.mf)});
  }
  async function hostsTab() {
    const [hs, ls] = await Promise.all([data("hosts"), data("licenses")]);
    return filt() + grid("hosts", hs, [
      {h: "소스", v: r => r.source_name, c: "small"}, {h: "vCenter", v: r => r.vcenter, c: "small"}, {h: "클러스터", v: r => r.cluster}, {h: "호스트", v: r => r.host, f: r => `<b>${esc(r.host)}</b>`},
      {h: "소켓", v: r => r.sockets}, {h: "코어", v: r => r.cores}, {h: "라이선스 코어", v: r => r.licensed_cores, f: r => `${n(r.licensed_cores)}${r.category === "term" && r.licensed_cores > r.cores ? ' <span class="small cc-na">16↑</span>' : ""}`},
      {h: "License Key", v: r => r.license_key, c: "mono small"}, {h: "라이선스", v: r => r.license_name, c: "small"}, {h: "구분", v: r => CAT[r.category] || r.category, f: r => r.category === "unlicensed" ? '<b class="cc-na">미할당·평가</b>' : esc(CAT[r.category] || r.category)},
      {h: "수량", v: r => r.qty}, {h: "ESXi", v: r => r.version, c: "small"}], {title: "실사용 — 호스트별 할당", note: "영구(cpuPackage) = CPU 단위, 구독(cpuCore) = 코어 단위(CPU 당 최소 16코어, Broadcom KB 313548)."})
      + grid("lics", ls, [{h: "소스", v: r => r.source_name, c: "small"}, {h: "License Key", v: r => r.key, c: "mono small"}, {h: "이름", v: r => r.name}, {h: "비용 단위", v: r => r.cost_unit, c: "small"},
        {h: "구분", v: r => CAT[r.category] || r.category}, {h: "총량", v: r => r.total}, {h: "사용", v: r => r.used, f: r => `<span class="${r.total && r.used > r.total ? "cc-na" : ""}">${n(r.used)}</span>`},
        {h: "만료", v: r => r.expires, f: r => dateCell(r.expires)}], {title: "vCenter·RVTools 라이선스 목록"});
  }
  async function cspTab() {
    const rows = await data("csp");
    return filt() + assignBar("csp") + grid("csp", rows, [{h: "License Key", v: r => r.license_key, c: "mono small"}, {h: "제품", v: r => r.product}, {h: "수량", v: r => r.quantity, f: r => n(r.quantity)},
      {h: "단위", v: r => r.unit}, {h: "폴더", v: r => r.folder}, {h: "계약 종료", v: r => r.end_date, f: r => dateCell(r.end_date)},
      {h: "프로젝트", v: r => projName(r.project), c: "small"}], {title: "Broadcom CSP — AllLicenseKeys", sel: r => r.id});
  }
  async function supTab() {
    const rows = await data("supplier");
    return filt() + assignBar("supplier") + grid("sup", rows, [{h: "Serial", v: r => r.serial, c: "small"}, {h: "Parent Customer", v: r => r.parent_customer, c: "small"}, {h: "Customer", v: r => r.customer},
      {h: "License Key", v: r => r.license_key, c: "mono small"}, {h: "Type", v: r => r.license_type}, {h: "Product", v: r => r.product}, {h: "Qty-ENT", v: r => r.quantity, f: r => n(r.quantity)},
      {h: "Status", v: r => r.contract_status, c: "small"}, {h: "Start", v: r => r.start_date, c: "small"}, {h: "End", v: r => r.end_date, f: r => dateCell(r.end_date)},
      {h: "ERP Site", v: r => r.erp_site_id, c: "small"}, {h: "Enduser", v: r => r.enduser, c: "small"}, {h: "Part", v: r => r.part_number, c: "small"},
      {h: "프로젝트", v: r => projName(r.project), c: "small"}], {title: "공급자(총판·리셀러) 데이터", sel: r => r.serial});
  }
  async function usageTab() {
    const rows = await data("usage");
    if (!rows.length) return `<div class="rd-card"><p class="muted">VCF Operations 사용량 보고서가 없습니다 — '데이터·수집' 탭에서 사용량 파일을 올리거나(비연결 모드에서 받은 파일) VCF Ops 커넥터에서 받으세요.</p></div>`;
    return rows.map(u => `<div class="rd-card"><h4>${esc(u.name)} <small>${u.origin === "api" ? "VCF Ops API" : "업로드"} · 기준 ${fmt(u.usage_end || u.timestamp)} · 자산 ${n(u.assets)} · 수집 ${fmt(u.collected)}</small></h4>
      <table class="rd-t"><thead><tr><th>제품</th><th>단위</th><th>사용량(자산별 최신 합계)</th><th>자산</th></tr></thead><tbody>${u.products.map(p => `<tr><td>${esc(p.product)}</td><td>${esc(p.uom)}</td><td><b>${n(p.quantity)}</b></td><td>${n(p.assets)}</td></tr>`).join("")}</tbody></table></div>`).join("")
      + `<p class="small muted">VCF 9 라이선스는 약 180일 롤링 유효 기간이라 사용량 보고가 주기적으로 필요합니다(Broadcom KB 448518). 보고 후 경과일은 '종합 현황' 점검(LIC-10)에 표시됩니다.</p>`;
  }
  const projName = id => id ? ((st.ov?.projects || []).find(p => p.id === id) || {}).name || id : "";

  // ------------------------------------------------------------------ 데이터·수집
  async function dataTab() {
    try { [st.src, st.batches] = await Promise.all([A.api("GET", "/api/license/sources", undefined, {background: true}), A.api("GET", "/api/license/batches", undefined, {background: true}).then(x => x.items)]); }
    catch (e) { A.fail("불러오기 실패", e); }
    const S = st.src || {items: [], rvtools: [], vcfops: [], settings: {}};
    const up = (k, t, d, acc) => `<div class="lc-up"><b>${t}</b><p class="small muted">${d}</p><label class="btn-sm solid" data-perm="operate">파일 올리기<input type="file" data-lcup="${k}" accept="${acc}" hidden></label></div>`;
    return `<div class="lc-ups">${up("supplier", "공급자 데이터(.xlsx)", "열: Serial Number · License Key · Product Name · Quantity - ENT (+ Parent Customer · Customer Name · License Type · Contract Status · Start/End Date · ERP Site ID · Enduser Account Name · Part Number · Division). 같은 Serial 은 갱신.", ".xlsx")}
      ${up("csp", "Broadcom CSP — AllLicenseKeys(.xlsx)", "열: License Key · Product Name · Quantity('1432 Core') · Folder Name · Contract End Date. 같은 파일 이름으로 다시 올리면 대체(프로젝트 할당 유지).", ".xlsx")}
      ${up("vcfops", "VCF Operations 사용량 파일", "VCF Operations 9.x 에서 받은 사용량 파일(.gzip) 또는 suite-api 응답(JSON). 사용량만 읽습니다.", ".gz,.gzip,.json,.txt,.rpt,*/*")}</div>
      <div class="rd-card"><h4>실사용 소스 <small>프로젝트에 할당하면 그 프로젝트의 실사용으로 집계</small></h4>
        <div class="rd-tools"><button class="btn-sm solid" id="lc-coll" data-perm="operate" ${(st.ov?.vcenters || []).length ? "" : "disabled"}>vCenter 커넥터 전체 지금 수집</button>
          <select id="lc-rvsel"><option value="">RVTools 분석에서 가져오기…</option>${(S.rvtools || []).map(x => `<option value="${esc(x.id)}">${esc(x.name)} · ${esc((x.vcenters || []).join(", "))} · ${fmt(x.uploaded)}</option>`).join("")}</select><button class="btn-sm" id="lc-rvimp" data-perm="operate">가져오기</button>
          ${(S.vcfops || []).map(c => `<button class="btn-sm" data-lcpull="${esc(c)}" data-perm="operate" ${S.settings.vcfops_usage_api ? "" : "disabled title='설정에서 VCF Ops 사용량 API 를 켜야 합니다'"}>VCF Ops '${esc(c)}' 사용량 받기</button>`).join("")}</div>
        <table class="rd-t"><thead><tr><th><input type="checkbox" data-lcall="src"></th><th>소스</th><th>종류</th><th>호스트</th><th>라이선스·제품</th><th>수집·기준</th><th>프로젝트</th><th>상태</th><th></th></tr></thead><tbody>${(S.items || []).map(x => `<tr>
          <td>${x.pending ? "" : `<input type="checkbox" data-lcsel="${esc(x.id)}">`}</td><td><b>${esc(x.name)}</b><div class="small muted">${esc(x.version || "")}</div></td><td>${esc(KIND[x.kind] || x.kind)}</td><td>${n(x.hosts)}</td><td>${n(x.licenses || x.products)}</td>
          <td class="small">${x.pending ? "미수집" : fmt(x.collected)}${x.timestamp ? `<div class="muted">기준 ${fmt(x.timestamp)}</div>` : ""}</td><td class="small">${esc(projName(x.project))}</td>
          <td class="small">${x.error ? `<span class="cc-na" title="${esc(x.error)}">${esc(x.error.slice(0, 60))}</span>` : x.pending ? "" : "정상"}</td>
          <td>${x.pending ? "" : `<button class="btn-sm" data-lcdelsrc="${esc(x.id)}" data-perm="operate">삭제</button>`}</td></tr>`).join("") || `<tr><td colspan="9" class="muted">소스가 없습니다.</td></tr>`}</tbody></table>
        ${assignBar("source")}</div>
      <div class="rd-card"><h4>올린 파일</h4><table class="rd-t"><thead><tr><th>파일</th><th>종류</th><th>행</th><th>건너뜀</th><th>올린 시각</th><th></th></tr></thead><tbody>${(st.batches || []).map(x => `<tr><td>${esc(x.name)}</td><td>${x.kind === "csp" ? "CSP" : "공급자"}</td><td>${n(x.rows)}</td><td>${n(x.errors)}</td><td class="small">${fmt(x.uploaded)} · ${esc(x.by || "")}</td><td><button class="btn-sm" data-lcdelb="${esc(x.id)}" data-perm="operate">삭제</button></td></tr>`).join("") || `<tr><td colspan="6" class="muted">없음</td></tr>`}</tbody></table></div>`;
  }
  async function projTab() {
    let P = [];
    try { P = (await A.api("GET", "/api/license/projects", undefined, {background: true})).list; } catch (e) { A.fail("프로젝트 실패", e); }
    return `<div class="rd-card" data-perm="operate"><h4>프로젝트 만들기 <small>고객사·사이트 단위로 공급자·CSP·실사용 데이터를 묶음</small></h4>
        <div class="rd-tools"><input id="lc-pn" placeholder="이름(예: 고객사 A 데이터센터)"><input id="lc-pd" placeholder="설명"><input id="lc-pl" placeholder="위치"><button class="btn-sm solid" id="lc-padd">만들기</button></div>
        <p class="small muted">공급자 데이터는 고객(Customer·Enduser) 이름으로, CSP 데이터는 폴더 이름으로 한 번에 할당할 수 있습니다.</p>
        <div class="rd-tools">${projSel("lc-bp")} 에 <input id="lc-bcust" placeholder="공급자 Customer/Enduser 이름"><button class="btn-sm" id="lc-bcustb">공급자 일괄 할당</button>
          <input id="lc-bfold" placeholder="CSP Folder Name"><button class="btn-sm" id="lc-bfoldb">CSP 일괄 할당</button></div></div>
      <div class="rd-card"><h4>프로젝트 <small>${P.length}</small></h4><table class="rd-t"><thead><tr><th>이름</th><th>설명</th><th>위치</th><th>만든 이</th><th></th></tr></thead><tbody>${P.map(p => `<tr>
        <td><input value="${esc(p.name)}" data-lcpe="${esc(p.id)}:name"></td><td><input value="${esc(p.description || "")}" data-lcpe="${esc(p.id)}:description"></td><td><input value="${esc(p.location || "")}" data-lcpe="${esc(p.id)}:location"></td>
        <td class="small">${esc(p.by || "")} · ${fmt(p.created)}</td><td><button class="btn-sm" data-lcpsave="${esc(p.id)}" data-perm="operate">저장</button><button class="btn-sm" data-lcpdel="${esc(p.id)}" data-perm="operate">삭제</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">없음</td></tr>`}</tbody></table></div>`;
  }
  function setTab() {
    const s = st.ov?.settings || {};
    return `<div class="rd-card"><h4>설정 <small>settings 권한</small></h4>
      <label class="rd-f"><span>vCenter 라이선스 예약 수집 주기(시간, 0 = 끔)</span><input id="lc-sh" type="number" min="0" value="${s.schedule_hours ?? 24}"></label>
      <label class="rd-f"><span>만료 경고(일)</span><input id="lc-sw" type="number" min="7" value="${s.expiry_warn_days ?? 90}"></label>
      <label class="rd-f"><span>사용량 보고 경과 경고(일, 180일 전)</span><input id="lc-su" type="number" min="30" max="179" value="${s.usage_report_days ?? 150}"></label>
      <label class="rd-f"><span>VCF Ops 사용량 API(내부·비지원 API)</span><select id="lc-sa"><option value="0">끔 — 파일 업로드만</option><option value="1" ${s.vcfops_usage_api ? "selected" : ""}>켬 — 커넥터 계정으로 사용량 보고서 받기</option></select></label>
      <p class="small muted">VCF Ops 사용량 API 는 Broadcom KB 448518 이 안내하는 suite-api 내부 경로(<code>X-Ops-API-use-unsupported: true</code>)를 씁니다. 라이선스·구성은 바꾸지 않고 보고서 내용만 받지만, 비지원 API 라 기본은 꺼 둡니다.
      vCenter 수집은 LicenseManager·LicenseAssignmentManager 조회만 합니다(커넥터의 읽기 전용 계정).</p>
      <button class="btn-sm solid" id="lc-ssave" data-perm="settings">저장</button></div>`;
  }

  // ------------------------------------------------------------------ 화면
  async function render() {
    const box = $("#lc-body"); if (!box) return;
    if (!st.ov) await loadOv();
    const P = (st.ov?.projects || []);
    const head = `<div class="rv-top"><label class="small">프로젝트 <select id="lc-proj"><option value="*" ${st.project === "*" ? "selected" : ""}>전체</option><option value="" ${st.project === "" ? "selected" : ""}>(미할당)</option>
        ${P.filter(p => p.id).map(p => `<option value="${esc(p.id)}" ${st.project === p.id ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label><span class="rd-sp"></span>
      <a class="btn-sm" href="/api/license/report.xlsx?${qp()}">Excel</a>${can("operate") ? `<a class="btn-sm" href="/api/license/report.xlsx?${qp()}&full=1" title="키 전체(감사로그)">Excel(키 전체)</a>` : ""}</div>
      <div class="rv-tabs">${TABS.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-lct="${k}">${l}${k === "ov" && st.ov ? ` <small>${st.ov.checks.filter(c => ["critical", "error"].includes(c.severity)).length || ""}</small>` : ""}</button>`).join("")}</div>`;
    let body = "";
    try {
      body = st.tab === "ov" ? ovTab() : st.tab === "match" ? await matchTab() : st.tab === "hosts" ? await hostsTab() : st.tab === "csp" ? await cspTab()
        : st.tab === "supplier" ? await supTab() : st.tab === "usage" ? await usageTab() : st.tab === "data" ? await dataTab() : st.tab === "proj" ? await projTab() : setTab();
    } catch (e) { body = `<div class="rd-alert bad">${esc(e.message)}</div>`; }
    const keep = document.activeElement && document.activeElement.id === "lc-tf" ? document.activeElement.selectionStart : null;
    box.innerHTML = head + `<div class="rv-pane">${body}</div>`;
    if (keep != null) { const t = $("#lc-tf"); if (t) { t.focus(); t.setSelectionRange(keep, keep); } }
    perms(box);
  }
  async function refresh() { reset(); await loadOv(); render(); }
  async function uploadFile(kind, f) {
    if (!f) return;
    try {
      const r = await fetch(`/api/license/upload/${kind}?name=${enc(f.name)}`, {method: "POST", body: f, headers: {"X-Requested-With": "aiops", "Content-Type": "application/octet-stream"}});
      const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.status);
      A.ok("올리기 완료", kind === "vcfops" ? `제품 ${j.products} · 자산 ${j.assets}` : `${j.rows}행(새 ${j.inserted} · 갱신 ${j.updated || 0}${j.skipped ? ` · 건너뜀 ${j.skipped}` : ""})`);
      await refresh();
    } catch (e) { A.fail("올리기 실패", e); }
  }
  const selected = () => $$("[data-lcsel]:checked", $("#lc-body")).map(x => x.dataset.lcsel);
  function wire() {
    const box = $("#lc-body"); if (box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target.closest("[data-lct],[data-lcp],[data-lcsort],[data-lcassign],[data-lcpull],[data-lcdelsrc],[data-lcdelb],[data-lcpsave],[data-lcpdel],#lc-ai,#lc-coll,#lc-rvimp,#lc-padd,#lc-ssave,#lc-bcustb,#lc-bfoldb");
      if (!t) return;
      try {
        if (t.dataset.lct) { st.tab = t.dataset.lct; st.tf = ""; render(); return; }
        if (t.dataset.lcp !== undefined) { st.project = t.dataset.lcp; reset(); render(); return; }
        if (t.dataset.lcsort) { const [k, i] = t.dataset.lcsort.split(":"); const so = st.sort[k] || {}; st.sort[k] = {i: +i, d: so.i === +i ? !so.d : false}; render(); return; }
        if (t.dataset.lcassign) { const ids = selected(); if (!ids.length) { A.fail("선택 없음", new Error("행을 고르세요")); return; }
          const r = await A.api("POST", "/api/license/assign", {project: $("#lc-asgp").value || null, kind: t.dataset.lcassign, ids}); A.ok("할당", `${r.count}건`); await refresh(); return; }
        if (t.dataset.lcpull) { const r = await A.api("POST", `/api/license/vcfops/${enc(t.dataset.lcpull)}/pull`); A.ok("사용량 받음", `제품 ${r.products}`); await refresh(); return; }
        if (t.dataset.lcdelsrc) { if (!confirm("이 소스를 삭제할까요?")) return; await A.api("DELETE", `/api/license/sources/${enc(t.dataset.lcdelsrc)}`); await refresh(); return; }
        if (t.dataset.lcdelb) { if (!confirm("이 파일의 행을 모두 삭제할까요?")) return; await A.api("DELETE", `/api/license/batches/${enc(t.dataset.lcdelb)}`); await refresh(); return; }
        if (t.dataset.lcpsave) { const id = t.dataset.lcpsave, v = k => ($(`[data-lcpe="${id}:${k}"]`) || {}).value || "";
          await A.api("PUT", `/api/license/projects/${enc(id)}`, {name: v("name"), description: v("description"), location: v("location")}); A.ok("저장", ""); await refresh(); return; }
        if (t.dataset.lcpdel) { if (!confirm("프로젝트를 삭제할까요? (데이터는 미할당으로 남습니다)")) return; await A.api("DELETE", `/api/license/projects/${enc(t.dataset.lcpdel)}`); if (st.project === t.dataset.lcpdel) st.project = "*"; await refresh(); return; }
        if (t.id === "lc-padd") { await A.api("POST", "/api/license/projects", {name: $("#lc-pn").value, description: $("#lc-pd").value, location: $("#lc-pl").value}); A.ok("프로젝트 만듦", ""); await refresh(); return; }
        if (t.id === "lc-bcustb") { const r = await A.api("POST", "/api/license/assign", {project: $("#lc-bp").value || null, kind: "supplier", ids: [], filter: {customer: $("#lc-bcust").value}}); A.ok("공급자 일괄 할당", `${r.count}건`); await refresh(); return; }
        if (t.id === "lc-bfoldb") { const r = await A.api("POST", "/api/license/assign", {project: $("#lc-bp").value || null, kind: "csp", ids: [], filter: {folder: $("#lc-bfold").value}}); A.ok("CSP 일괄 할당", `${r.count}건`); await refresh(); return; }
        if (t.id === "lc-coll") { t.disabled = true; const r = await A.api("POST", "/api/license/collect", {}); const bad = r.items.filter(x => x.error);
          (bad.length ? A.fail : A.ok)("vCenter 라이선스 수집", r.items.map(x => `${x.source}: ${x.error || `호스트 ${x.hosts} · 라이선스 ${x.licenses}`}`).join(" / ")); await refresh(); return; }
        if (t.id === "lc-rvimp") { const v = $("#lc-rvsel").value; if (!v) return; const r = await A.api("POST", `/api/license/rvtools/${enc(v)}`); A.ok("RVTools 가져오기", `호스트 ${r.hosts} · 라이선스 ${r.licenses}`); await refresh(); return; }
        if (t.id === "lc-ssave") { await A.api("PUT", "/api/license/settings", {schedule_hours: +$("#lc-sh").value, expiry_warn_days: +$("#lc-sw").value, usage_report_days: +$("#lc-su").value, vcfops_usage_api: $("#lc-sa").value === "1"}); A.ok("설정 저장", ""); await refresh(); return; }
        if (t.id === "lc-ai") { t.disabled = true; $("#lc-aib").innerHTML = `<p class="muted">AI 가 쓰는 중…</p>`; st.ai = await A.api("POST", "/api/license/ai", {project: st.project}); render(); }
      } catch (x) { A.fail("실패", x); t.disabled = false; }
    });
    box.addEventListener("change", e => {
      const t = e.target;
      if (t.dataset.lcup) uploadFile(t.dataset.lcup, t.files[0]);
      if (t.id === "lc-proj") { st.project = t.value; reset(); render(); }
      if (t.id === "lc-rev") { st.reveal = t.checked; st.data = {}; render(); }
      if (t.id === "lc-mf") { st.mf = t.value; render(); }
      if (t.dataset.lcall) $$("[data-lcsel]", t.closest("table")).forEach(x => { x.checked = t.checked; });
    });
    box.addEventListener("input", e => { if (e.target.id === "lc-tf") { st.tf = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 250); } });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-lc") d.hidden = true; });
    $("#drawer-lc").hidden = false; wire(); reset(); render();
  }
  const nav = document.getElementById("nav-lc"); if (nav) nav.onclick = show;
  const rl = document.getElementById("lc-reload"); if (rl) rl.onclick = refresh;
  window.AIOPS_LICENSE = show;
})();
