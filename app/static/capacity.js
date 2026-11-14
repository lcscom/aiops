/* 용량 계획·VM 적정화(2.0) — 클러스터 CPU/메모리·데이터스토어 추세와 80/90% 도달 예상일, 과다·과소·유휴·장기 꺼짐 VM. core.js(AIOPS) 이후 로드
   GET /api/capacity · /api/capacity/rightsizing · /api/capacity/report.csv · POST /api/capacity/sample */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const st = {ov: null, rs: null, tab: "cap", kind: "", q: "", rtab: "oversized", days: 30, rdays: 14, rcl: "", rsort: "saving"};
  const N = (v, d = 1) => v == null ? "-" : Number(v).toLocaleString(undefined, {maximumFractionDigits: d});
  const money = v => v == null ? "-" : Number(v).toLocaleString(undefined, {maximumFractionDigits: 0});
  const days = d => d == null ? "증가 없음" : d === 0 ? "도달" : d > 365 ? "1년 이상" : `${d}일`;
  const dcls = d => d == null ? "" : d <= 30 ? "crit" : d <= 90 ? "warn" : "";
  function spark(vals, w = 140, h = 30, color = "#0072a3") {
    const v = (vals || []).map(Number); if (v.length < 2) return `<svg viewBox="0 0 ${w} ${h}" class="cp-spk"><text x="4" y="${h / 2 + 4}" fill="#8c8c8c" font-size="10">수집 중</text></svg>`;
    const dx = w / (v.length - 1), pts = v.map((x, i) => `${(i * dx).toFixed(1)},${(h - 2 - Math.min(100, Math.max(0, x)) / 100 * (h - 4)).toFixed(1)}`);
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="cp-spk"><line x1="0" x2="${w}" y1="${(h - 2 - 0.8 * (h - 4)).toFixed(1)}" y2="${(h - 2 - 0.8 * (h - 4)).toFixed(1)}" stroke="#efc006" stroke-dasharray="3 3"/>
      <path d="M0,${h} L${pts.join(" L")} L${w},${h}Z" fill="${color}" opacity=".15"/><polyline points="${pts.join(" ")}" fill="none" stroke="${color}" stroke-width="1.5"/></svg>`;
  }
  const pct = v => v == null ? "-" : `<span class="dm-pct cp-pct ${v >= 90 ? "down" : v >= 80 ? "warn" : ""}"><i style="--w:${Math.min(100, v)}%"></i><em>${N(v)}%</em></span>`;

  async function load() {
    try { [st.ov, st.rs] = await Promise.all([A.api("GET", `/api/capacity?days=${st.days}`, undefined, {background: true}), A.api("GET", `/api/capacity/rightsizing?days=${st.rdays}`, undefined, {background: true})]); }
    catch (e) { $("#cp-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (st.rs && !st._picked) { st._picked = true; const f = ["oversized", "idle", "undersized", "powered_off"].find(k => (st.rs[k] || []).length); if (f) st.rtab = f; }
    render();
  }
  function render() {
    const b = $("#cp-body"); if (!b || !st.ov) return;
    const sm = st.ov.sampler || {};
    $("#cp-sub").textContent = `클러스터 ${st.ov.summary.clusters} · 데이터스토어 ${st.ov.summary.datastores} · 표본 ${sm.last_sample ? new Date(sm.last_sample * 1000).toLocaleTimeString() : "대기"}${sm.error ? " · 오류 " + sm.error : ""}`;
    b.innerHTML = `<div class="vc-tabs">${[["cap", `용량 예측 <small>${st.ov.summary.warn + st.ov.summary.down || ""}</small>`], ["rs", `VM 적정화 <small>${st.rs ? st.rs.summary.oversized + st.rs.summary.idle + st.rs.summary.undersized + st.rs.summary.powered_off : ""}</small>`], ["wi", "가정 분석"], ["esa", "vSAN ESA 전환"]]
      .map(([k, l]) => `<button data-ct="${k}" class="${st.tab === k ? "on" : ""}">${l}</button>`).join("")}<span class="gap"></span><button class="btn-sm" id="cp-csv">CSV</button>${A.can("operate") ? `<button class="btn-sm" id="cp-sample">지금 표본</button>` : ""}</div>
      ${st.tab === "cap" ? capacity() : st.tab === "wi" ? `<div id="wi-root"></div>` : st.tab === "esa" ? `<div id="esa-root"></div>` : rightsizing()}`;
    if (st.tab === "wi" && window.AIOPS_WHATIF) window.AIOPS_WHATIF.mount($("#wi-root"));
    if (st.tab === "esa" && window.AIOPS_ESA) window.AIOPS_ESA.mount($("#esa-root"));
  }
  function capacity() {
    const O = st.ov, S = O.summary;
    const items = O.items.filter(r => (!st.kind || r.kind === st.kind) && (!st.q || r.name.toLowerCase().includes(st.q.toLowerCase())));
    const card = (cls, t, n, sub) => `<div class="vc-card ${cls}"><b>${t}</b><span class="vc-n">${n}</span><small>${sub}</small></div>`;
    const row = r => { const f = r.forecast, fm = r.forecast_mem || null, isC = r.kind === "cluster";
      return `<tr class="cp-r st-${r.state}"><td><span class="dm-st ${r.state}">${{ok: "정상", warn: "주의", down: "위험"}[r.state]}</span></td><td>${isC ? "클러스터" : "데이터스토어"}${r.vsan ? ' <small class="muted">vSAN</small>' : r.type ? ` <small class="muted">${esc(r.type)}</small>` : ""}</td>
        <td><b>${esc(r.name)}</b><br><small class="muted">${esc(r.vcenter)}${isC ? ` · 호스트 ${r.hosts} · ${N(r.cpu_total_ghz, 0)} GHz · ${N(r.mem_total_gb, 0)} GB` : ` · ${N(r.capacity_gb, 0)} GB · VM ${r.vms ?? "-"}`}</small></td>
        <td>${isC ? pct(r.cpu) : pct(r.disk)}</td><td>${isC ? pct(r.mem) : (r.prov_gb ? `할당 ${N(r.prov_gb / r.capacity_gb * 100, 0)}%` : "-")}</td>
        <td>${spark(r.spark, 140, 30, isC ? "#0072a3" : "#62a420")}</td>
        <td>${f.slope == null ? `<small class="muted">표본 ${r.days_observed}일 — 7일 이상 쌓이면 예측</small>` : `<b>${f.slope > 0 ? "+" : ""}${N(f.slope, 2)}%/일</b>${fm && fm.slope != null ? `<br><small>메모리 ${fm.slope > 0 ? "+" : ""}${N(fm.slope, 2)}%/일</small>` : ""}${r.growth_gb_day != null ? `<br><small>${N(r.growth_gb_day, 1)} GB/일</small>` : ""}`}</td>
        <td class="${dcls(f.days_to["80"])}">${f.slope == null ? "-" : days(f.days_to["80"])}${fm && fm.slope != null ? `<br><small class="${dcls(fm.days_to["80"])}">메모리 ${days(fm.days_to["80"])}</small>` : ""}</td>
        <td class="${dcls(f.days_to["90"])}">${f.slope == null ? "-" : days(f.days_to["90"])}${fm && fm.slope != null ? `<br><small class="${dcls(fm.days_to["90"])}">메모리 ${days(fm.days_to["90"])}</small>` : ""}</td>
        <td>${f.p30 == null ? "-" : `${N(f.p30, 0)}% / ${N(f.p90, 0)}%`}${isC && r.ha_n1 != null ? `<br><small class="muted ${r.ha_n1 >= 100 ? "crit" : r.ha_n1 >= 90 ? "warn" : ""}">N-1 메모리 ${N(r.ha_n1, 0)}%</small>` : ""}</td></tr>`; };
    return `<div class="vc-cards">${card(S.down ? "critical" : "", "위험(90% 이상)", S.down, "클러스터·데이터스토어")}${card(S.warn ? "warning" : "", "주의(80% 이상·90일 내 도달)", S.warn, "")}
        ${card(S.soon ? "warning" : "info", "90일 안에 90% 도달", S.soon, "추세 기준")}${card("info", "추세 기간", `${O.days}일`, `일 평균에 직선 적합`)}</div>
      <div class="vc-ctl"><select id="cp-kind"><option value="">전체</option><option value="cluster" ${st.kind === "cluster" ? "selected" : ""}>클러스터</option><option value="datastore" ${st.kind === "datastore" ? "selected" : ""}>데이터스토어</option></select>
        <select id="cp-days">${[14, 30, 60, 90].map(d => `<option value="${d}" ${st.days === d ? "selected" : ""}>최근 ${d}일 추세</option>`).join("")}</select><input id="cp-q" placeholder="이름 검색" value="${esc(st.q)}"></div>
      <table class="vc-t cp-t"><tr><th>상태</th><th>유형</th><th>이름</th><th>CPU / 사용률</th><th>메모리 / 할당</th><th>추세(${O.days}일)</th><th>증가</th><th>80% 도달</th><th>90% 도달</th><th>30일/90일 뒤</th></tr>
        ${items.map(row).join("") || `<tr><td colspan="10" class="muted">표시할 항목이 없습니다 — vCenter 커넥터 연결 후 5분 안에 첫 표본</td></tr>`}</table>
      <p class="small muted">예측: 최근 ${O.days}일 일 평균 사용률에 최소제곱 직선을 맞춘 기울기(%/일)로 80%·90% 도달일과 30/90일 뒤 값을 계산(표본 7일 미만이면 보류). 로컬 디스크는 제외. N-1 메모리 = 가장 큰 호스트 1대가 빠졌을 때 메모리 사용률(HA 여유).</p>`;
  }
  // ---------------------------------------------------------------- VM 적정화(2.3 개편 — 요약 → 클러스터 → VM, 현재→권장·근거를 한눈에)
  const CONF = {high: ["높음", "7일 이상 관측"], medium: ["보통", "3~7일 관측"], low: ["낮음", "3일 미만 관측 — 참고용"]};
  function gauge(avg, peak, warnAt, label) {
    const a = Math.min(100, Math.max(0, avg || 0)), p = Math.min(100, Math.max(0, peak || 0));
    const cls = (avg || 0) >= 85 ? "hi" : (peak || 0) < 10 ? "lo" : "";
    return `<div class="rs-g ${cls}" title="${label} 평균 ${N(avg)}% · 피크 ${N(peak)}%"><div class="rs-gb"><i style="width:${a}%"></i><b style="left:${p}%"></b>${warnAt ? `<u style="left:${warnAt}%"></u>` : ""}</div>
      <small><em>${label}</em> 평균 <b>${N(avg, 0)}%</b> · 피크 <b>${N(peak, 0)}%</b></small></div>`;
  }
  function chg(cur, rec, unit) {
    if (rec == null || Number(rec) === Number(cur)) return `<span class="rs-same">${N(cur)}${unit}</span>`;
    const d = Number(rec) - Number(cur);
    return `<span class="rs-old">${N(cur)}</span><span class="rs-arr">→</span><b class="rs-new">${N(rec)}${unit}</b><span class="rs-d ${d < 0 ? "dn" : "up"}">${d > 0 ? "+" : ""}${N(d)}</span>`;
  }
  function allocBar(label, cur, rec, unit) {
    if (!cur) return "";
    const base = Math.max(cur, rec), diff = rec - cur;
    return `<div class="rs-ab"><div class="rs-abh"><b>${label}</b><span>${N(cur, 0)} → <b>${N(rec, 0)}</b> ${unit} <em class="${diff < 0 ? "dn" : diff > 0 ? "up" : ""}">${diff > 0 ? "+" : ""}${N(diff, 0)} (${diff > 0 ? "+" : ""}${N(diff / cur * 100, 0)}%)</em></span></div>
      <div class="rs-abb"><i style="width:${Math.min(cur, rec) / base * 100}%"></i>${diff < 0 ? `<s class="dn" style="width:${-diff / base * 100}%" title="회수 ${N(-diff, 0)}"></s>` : diff > 0 ? `<s class="up" style="width:${diff / base * 100}%" title="증설 ${N(diff, 0)}"></s>` : ""}</div></div>`;
  }
  const pm = (a, b, sign) => [a ? `${sign}${N(a, 0)} vCPU` : "", b ? `${sign}${N(b, 0)} GB` : ""].filter(Boolean).join(" · ") || "-";
  function rightsizing() {
    const R = st.rs; if (!R) return `<div class="empty">불러오는 중…</div>`;
    const S = R.summary, cur = R.currency || "", T = R.thresholds;
    const tabs = [["oversized", "과다 할당", "축소 권장"], ["idle", "유휴", "끄기·삭제 검토"], ["undersized", "과소 할당", "증설 권장"], ["powered_off", "장기 꺼짐", "삭제·아카이브 검토"]];
    const total = (S.judged || 0) + (S.powered_off || 0) + (S.pending || 0);
    const seg = (k, n, l) => n ? `<i class="rs-s ${k}" style="flex:${n}" data-rt="${k === "ok" || k === "pending" ? "" : k}" title="${l} ${n}대">${n / Math.max(total, 1) > 0.06 ? n : ""}</i>` : "";
    const hero = `<div class="rs-hero">
      <div class="rs-box rs-save"><h5>회수 가능 자원</h5>
        <div class="rs-big"><div><b>${N(S.reclaim_vcpu, 0)}</b><small>vCPU</small></div><div><b>${N(S.reclaim_mem_gb, 0)}</b><small>GB 메모리</small></div><div><b>${N(S.reclaim_disk_gb, 0)}</b><small>GB 디스크</small></div></div>
        <p>${S.saving_month == null ? `<span class="muted">월 절감액은 정산 › 요율표를 추가하면 계산합니다</span>` : `월 절감 추정 <b class="rs-money">${money(S.saving_month)}</b> ${esc(cur)}`}</p></div>
      <div class="rs-box"><h5>판단한 VM ${S.judged || 0}대 · 현재 할당 → 권장 합계</h5>${allocBar("vCPU", S.alloc_vcpu, S.rec_vcpu, "vCPU")}${allocBar("메모리", S.alloc_mem_gb, S.rec_mem_gb, "GB")}
        ${S.add_vcpu || S.add_mem_gb ? `<p class="small"><span class="rs-key dn"></span>회수 ${pm(S.reclaim_vcpu, S.reclaim_mem_gb, "−")} &nbsp; <span class="rs-key up"></span>증설 필요 ${pm(S.add_vcpu, S.add_mem_gb, "+")}(과소 할당 ${S.undersized}대)</p>` : ""}</div>
      <div class="rs-box"><h5>판단 결과 <small>최근 ${R.days}일</small></h5>
        <div class="rs-stack">${seg("ok", S.ok, "적정")}${seg("oversized", S.oversized, "과다")}${seg("idle", S.idle, "유휴")}${seg("undersized", S.undersized, "과소")}${seg("powered_off", S.powered_off, "장기 꺼짐")}${seg("pending", S.pending, "판단 보류")}</div>
        <ul class="rs-leg"><li><i class="rs-s ok"></i>적정 ${S.ok ?? "-"}</li><li data-rt="oversized"><i class="rs-s oversized"></i>과다 ${S.oversized}</li><li data-rt="idle"><i class="rs-s idle"></i>유휴 ${S.idle}</li>
          <li data-rt="undersized"><i class="rs-s undersized"></i>과소 ${S.undersized}</li><li data-rt="powered_off"><i class="rs-s powered_off"></i>장기 꺼짐 ${S.powered_off}</li>${S.pending ? `<li><i class="rs-s pending"></i>보류 ${S.pending} <small>(켜진 시간 24시간 미만)</small></li>` : ""}</ul></div></div>`;
    const cls = (R.clusters || []).filter(c => c.oversized + c.undersized + c.idle + c.powered_off);
    const clTable = cls.length ? `<h4 class="rs-h">클러스터별 <small>누르면 해당 클러스터만</small></h4><table class="vc-t rs-ct"><tr><th>클러스터</th><th>판단 VM</th><th>과다</th><th>유휴</th><th>과소</th><th>장기 꺼짐</th><th>회수 가능</th><th>증설 필요</th><th>월 절감</th></tr>
      ${cls.map(c => `<tr class="${st.rcl === c.cluster ? "on" : ""}" data-rcl="${esc(c.cluster)}"><td><b>${esc(c.cluster)}</b></td><td>${c.vms}</td>${["oversized", "idle", "undersized", "powered_off"].map(k => `<td>${c[k] ? `<span class="rs-n ${k}">${c[k]}</span>` : `<span class="muted">0</span>`}</td>`).join("")}
        <td class="rs-dn">${pm(c.reclaim_vcpu, c.reclaim_mem_gb, "−")}</td><td class="rs-up">${pm(c.add_vcpu, c.add_mem_gb, "+")}</td><td>${R.rate ? money(c.saving) : "-"}</td></tr>`).join("")}</table>` : "";
    const q = st.q.toLowerCase();
    let items = (R[st.rtab] || []).filter(x => (!q || `${x.vm} ${x.cluster} ${x.folder} ${x.os}`.toLowerCase().includes(q)) && (!st.rcl || x.cluster === st.rcl));
    const sorters = {saving: x => -(x.saving || 0) - ((x.vcpu - (x.rec_vcpu ?? x.vcpu)) + (x.mem_gb - (x.rec_mem_gb ?? x.mem_gb))) / 1000,
                     size: x => -(Math.abs(x.vcpu - (x.rec_vcpu ?? (st.rtab === "idle" ? 0 : x.vcpu))) * 8 + Math.abs(x.mem_gb - (x.rec_mem_gb ?? (st.rtab === "idle" ? 0 : x.mem_gb))) + (st.rtab === "powered_off" ? x.disk_gb : 0)),
                     usage: x => st.rtab === "undersized" ? -Math.max(x.avg_cpu || 0, x.avg_mem || 0) : (x.peak_cpu || 0) + (x.peak_mem || 0) - (x.off_days || 0),
                     name: x => x.vm};
    const sf = sorters[st.rsort] || sorters.saving;
    items = items.slice().sort((a, b) => { const x = sf(a), y = sf(b); return typeof x === "string" ? x.localeCompare(y) : x - y; });
    const meta = tabs.find(t => t[0] === st.rtab);
    const row = x => {
      const conf = CONF[x.confidence] || null;
      const right = st.rtab === "powered_off" ? `<div class="rs-res"><span class="rs-same">디스크 <b>${N(x.disk_gb, 0)} GB</b></span><br><small>${N(x.off_days, 0)}일째 꺼짐</small></div>`
        : st.rtab === "idle" ? `<div class="rs-res"><span class="rs-old">${x.vcpu} vCPU · ${N(x.mem_gb)} GB</span><span class="rs-arr">→</span><b class="rs-new">0</b></div>`
        : `<div class="rs-res">${chg(x.vcpu, x.rec_vcpu, " vCPU")}<br>${chg(x.mem_gb, x.rec_mem_gb, " GB")}</div>`;
      const gauges = st.rtab === "powered_off" ? `<div class="rs-gs"><small class="muted">게스트 OS ${esc(x.os || "-")}</small></div>`
        : `<div class="rs-gs">${gauge(x.avg_cpu, x.peak_cpu, st.rtab === "undersized" ? T.under_cpu : T.over_cpu, "CPU")}${gauge(x.avg_mem, x.peak_mem, st.rtab === "undersized" ? T.under_mem : T.over_mem, "메모리")}</div>`;
      return `<div class="rs-row ${st.rtab}"><div class="rs-vm"><b>${esc(x.vm)}</b><small>${esc(x.cluster || "")} · ${esc(x.folder || "")}</small><small>${esc(x.os || "")}${x.hours_on ? ` · 켜진 ${x.hours_on}시간` : ""}</small></div>
        ${gauges}${right}
        <div class="rs-act"><span class="rs-chip ${st.rtab}">${esc(x.action || meta[2])}</span>${conf ? `<small class="rs-conf ${x.confidence}" title="${conf[1]}">신뢰도 ${conf[0]}</small>` : ""}</div>
        <div class="rs-sv">${st.rtab === "undersized" ? `<small class="muted">비용 증가</small>` : x.saving != null ? `<b>${money(x.saving)}</b><small>/월</small>` : "-"}</div>
        ${x.why ? `<div class="rs-why">근거: ${esc(x.why)}</div>` : ""}</div>`;
    };
    return `${hero}${clTable}
      <div class="vc-tabs rs-tabs">${tabs.map(([k, l, sub]) => `<button data-rt="${k}" class="${st.rtab === k ? "on" : ""}">${l} <small>${R[k].length}</small><em>${sub}</em></button>`).join("")}</div>
      <div class="vc-ctl rs-ctl"><select id="cp-rcl"><option value="">전체 클러스터</option>${(R.clusters || []).map(c => `<option ${st.rcl === c.cluster ? "selected" : ""}>${esc(c.cluster)}</option>`).join("")}</select>
        <select id="cp-rsort">${[["saving", "절감액 순"], ["size", "회수·증설 규모 순"], ["usage", "사용률 순"], ["name", "이름 순"]].map(([k, l]) => `<option value="${k}" ${st.rsort === k ? "selected" : ""}>${l}</option>`).join("")}</select>
        <select id="cp-rdays">${[7, 14, 30].map(d => `<option value="${d}" ${st.rdays === d ? "selected" : ""}>최근 ${d}일 기준</option>`).join("")}</select>
        <input id="cp-q2" placeholder="VM·클러스터·폴더·OS 검색" value="${esc(st.q)}"><span class="muted small">${items.length}대${st.rcl ? ` · ${esc(st.rcl)}` : ""}</span></div>
      <div class="rs-list"><div class="rs-row rs-hd"><span>VM</span><span>사용률(막대 = 평균, 세로선 = 피크, 점선 = 기준)</span><span>현재 → 권장</span><span>조치</span><span>월 절감</span></div>
        ${items.map(row).join("") || `<div class="empty">해당 VM 없음 — 관측 VM ${R.vms_observed}대 중 하루 이상 켜진 VM 만 판단합니다</div>`}</div>
      <details class="rs-rule"><summary>판단 기준</summary><p class="small">최근 ${R.days}일 켜진 시간 기준. 과다 = vCPU 4 이상·피크 CPU &lt; ${T.over_cpu}% 또는 메모리 8GB 이상·피크 &lt; ${T.over_mem}% → 권장 = 피크 사용량 × ${T.headroom}(최소 2) ·
        과소 = 평균 CPU ≥ ${T.under_cpu}% 또는 메모리 ≥ ${T.under_mem}% → ×1.5 · 유휴 = 피크 CPU &lt; ${T.idle_cpu}% 이고 메모리 &lt; ${T.idle_mem}% · 장기 꺼짐 = ${T.off_days}일 이상.
        피크 = 1시간 평균의 최댓값(순간 피크보다 낮게 나옴) — 배치·월말 작업 VM 은 업무 주기를 확인하세요. 신뢰도 = 관측 기간(7일 이상 높음·3일 이상 보통). 절감 = 기본 요율표 단가 × 730시간${R.rate ? `(vCPU ${R.rate.vcpu_hour} · GB ${R.rate.mem_gb_hour} · 디스크 ${R.rate.disk_gb_hour} /시간)` : ""}.</p></details>`;
  }
  function wire() {
    const b = $("#cp-body");
    b.addEventListener("click", async e => {
      const t = e.target;
      const ct = t.closest("[data-ct]"); if (ct) { st.tab = ct.dataset.ct; st.q = ""; render(); return; }
      const rt = t.closest("[data-rt]"); if (rt && rt.dataset.rt) { st.rtab = rt.dataset.rt; render(); return; }
      const rcl = t.closest("[data-rcl]"); if (rcl) { st.rcl = st.rcl === rcl.dataset.rcl ? "" : rcl.dataset.rcl; render(); return; }
      if (t.id === "cp-csv") { location.href = "/api/capacity/report.csv"; return; }
      if (t.id === "cp-sample") { try { const r = await A.api("POST", "/api/capacity/sample"); A.ok("표본", r.sampled ? `${r.sampled}건 기록` : "이번 5분 블록은 이미 기록됨"); } catch (er) { A.fail("표본 실패", er); } load(); }
    });
    b.addEventListener("change", e => {
      if (e.target.id === "cp-kind") { st.kind = e.target.value; render(); }
      if (e.target.id === "cp-days") { st.days = Number(e.target.value); load(); }
      if (e.target.id === "cp-rdays") { st.rdays = Number(e.target.value); load(); }
      if (e.target.id === "cp-rcl") { st.rcl = e.target.value; render(); }
      if (e.target.id === "cp-rsort") { st.rsort = e.target.value; render(); }
    });
    let tm;
    b.addEventListener("input", e => { if (e.target.id !== "cp-q" && e.target.id !== "cp-q2") return; const id = e.target.id, pos = e.target.selectionStart; clearTimeout(tm);
      tm = setTimeout(() => { st.q = e.target.value; render(); const el = $("#" + id); if (el) { el.focus(); el.setSelectionRange(pos, pos); } }, 250); });
    $("#cp-reload").onclick = load;
  }
  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-cap")) return;
    wire();
    $("#nav-cap").onclick = () => { open("drawer-cap"); load(); };
    const badge = async () => { try { const o = await A.api("GET", "/api/capacity", undefined, {background: true}); const n = o.summary.down + o.summary.soon; const el = $("#cap-badge"); el.hidden = !n; el.textContent = n; el.title = `위험 ${o.summary.down} · 90일 내 90% 도달 ${o.summary.soon}`; } catch { /* 권한·로그인 전 */ } };
    setTimeout(badge, 8000); setInterval(badge, 300000);
  });
  window.AIOPS_CAP = {load};
})();
