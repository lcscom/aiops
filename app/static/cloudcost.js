/* 클라우드 비용 비교(2.13.0) — VCF 객체 ↔ AWS·Azure·GCP 서비스 짝짓기, 월 비용·구성요소별 비교, VM 별 IOPS 최소/평균/최대, 단가표(출처·확인 여부)·VCF 원가 모델 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const P = ["aws", "azure", "gcp"];
  const PL = {aws: "AWS", azure: "Azure", gcp: "GCP", vcf: "VCF(온프레미스)", openshift: "OpenShift(온프레미스)"};
  const PC = {vcf: "#1d428a", aws: "#e88a00", azure: "#0a7ad6", gcp: "#2e9e4f", openshift: "#8a1538"};
  const OSP = {subscription: "OpenShift 구독", storage: "스토리지(ODF·외부)", hardware: "서버 감가상각", facility: "상면·전력", operations: "운영 인력", other: "기타"};
  const PART = [["compute", "컴퓨트"], ["storage", "스토리지"], ["iops", "추가 IOPS"], ["k8s", "관리형 K8s"], ["lb", "로드밸런서"]];
  const PARTC = {compute: 1, storage: .72, iops: .55, k8s: .4, lb: .28};
  const CAT = {workload: "업무", mgmt: "관리", vks_cp: "VKS 컨트롤 플레인"};
  const st = {osref: null, tab: "sum", r: null, prices: null, settings: null, q: "", cat: "workload", sort: "vcf", dir: -1, opts: {}, loading: false};

  const cur = () => (st.r && st.r.currency) || "USD";
  const money = x => {
    if (x === null || x === undefined) return `<span class="cc-na" title="단가 미입력 또는 계산 불가">—</span>`;
    if (cur() === "KRW") { if (!st.r.fx) return `<span class="cc-na" title="환율 미입력">환율?</span>`; return "₩" + Math.round(x * st.r.fx).toLocaleString(); }
    return "$" + Number(x).toLocaleString(undefined, {minimumFractionDigits: 0, maximumFractionDigits: x < 100 ? 2 : 0});
  };
  const num = (x, d = 0) => x === null || x === undefined ? "—" : Number(x).toLocaleString(undefined, {maximumFractionDigits: d});
  const badge = ok => ok ? `<span class="cc-b ok" title="공식 단가 출처에서 해당 리전 값을 확인했거나 관리자가 입력">확인</span>` : `<span class="cc-b no" title="리전 단가를 확인하지 못함 — 단가표에서 확인 후 수정">미확인</span>`;

  // 2.36.0 — 선택을 빠르게 바꾸면 늦게 온 이전 응답이 새 결과를 덮어쓰던 문제: 요청마다 번호를 붙여 마지막 요청의 응답만 반영
  let seq = 0;
  async function load() {
    const my = ++seq;
    // 저장하지 않은 입력(원가 모델·단가표)은 다시 그려도 지우지 않는다 — 그리기 전에 모아 둔다
    const box = $("#cc-body");
    const key = i => i.dataset.cs ? "cs:" + i.dataset.cs : "pp:" + i.dataset.pp;
    if (box) $$("[data-cs],[data-pp]", box).forEach(i => { if (i.type !== "checkbox" && i.value !== i.defaultValue) st.dirty = {...(st.dirty || {}), [key(i)]: i.value}; });
    st.loading = true; render();
    let res = null;
    try {
      const q = new URLSearchParams(Object.entries(st.opts).filter(([, v]) => v));
      res = await Promise.all([A.api("GET", "/api/cloudcost/report?" + q, undefined, {background: true}),
        A.api("GET", "/api/cloudcost/prices", undefined, {background: true}), A.api("GET", "/api/cloudcost/settings", undefined, {background: true})]);
    } catch (e) { if (my === seq) A.fail("비용 비교 불러오기 실패", e); }
    if (my !== seq) return;                                   // 더 새 요청이 있음 — 이 응답은 버린다
    if (res) [st.r, st.prices, st.settings] = res;
    if (!st.osref) { try { st.osref = await A.api("GET", "/api/cloudcost/openshift/reference", undefined, {background: true}); } catch { st.osref = null; } }
    if (my !== seq) return;
    st.loading = false; render();
    const dirty = st.dirty || {}, b2 = $("#cc-body");
    if (b2 && Object.keys(dirty).length) {
      let n = 0;
      $$("[data-cs],[data-pp]", b2).forEach(i => { const k = key(i); if (k in dirty) { i.value = dirty[k]; i.classList.add("cc-dirty"); n++; } });
      if (n) A.toast("저장하지 않은 입력이 있습니다", "다시 불러오면서 지우지 않았습니다 — '저장'을 눌러야 반영됩니다", "info", 3500);
    }
  }

  // ---------------------------------------------------------------- 요약
  function summary() {
    const r = st.r, t = r.totals, v = r.vcf;
    const o = r.openshift || {mode: "none"};
    const rows = [{k: "vcf", total: v.monthly, parts: v.parts ? Object.entries(v.parts).map(([k, x]) => [k, x]) : null, complete: v.monthly != null}]
      .concat(o.mode !== "none" ? [{k: "openshift", total: o.monthly, parts: o.parts ? Object.entries(o.parts) : null, complete: !!o.complete, os: o}] : [])
      .concat(P.map(p => ({k: p, total: t[p].total, parts: PART.map(([k]) => [k, t[p][k]]), complete: t[p].complete, t: t[p]})));
    const max = Math.max(1, ...rows.map(x => x.total || 0));
    const VP = {subscription: "VCF 구독", hardware: "서버 감가상각", facility: "상면·전력", operations: "운영 인력", other: "기타"};
    const bar = x => {
      if (x.total == null) return `<div class="cc-bar empty">${x.k === "vcf" ? esc(v.note || "원가 미입력") : x.k === "openshift" ? esc(o.note || "단가 미입력") : "합계 계산 불가"}</div>`;
      const onp = x.k === "vcf" || x.k === "openshift";
      const segs = (x.parts || [["total", x.total]]).filter(([, y]) => y).map(([k, y], i) => `<i style="width:${(y / max * 100).toFixed(2)}%;background:${PC[x.k]};opacity:${onp ? 1 - i * .14 : PARTC[k] || 1}" title="${esc((x.k === "vcf" ? VP[k] : x.k === "openshift" ? OSP[k] : (PART.find(p => p[0] === k) || [])[1]) || k)} ${money(y).replace(/<[^>]+>/g, "")}"></i>`).join("");
      return `<div class="cc-bar">${segs}</div>`;
    };
    const kp = rows.map(x => {
      const d = x.k !== "vcf" && x.total != null && x.complete && v.monthly ? (x.total - v.monthly) / v.monthly * 100 : null;
      return `<div class="cc-kpi" style="border-top-color:${PC[x.k]}"><small>${esc(PL[x.k])}${x.t ? ` · ${esc(x.t.region)}` : ""}${x.os ? ` · ${esc(x.os.edition_name)}` : ""}</small><b>${money(x.total)}</b><span>/월${(x.t || x.os) && !x.complete ? " · 부분 합계(단가 없는 항목 제외)" : ""}</span>
        ${x.os && !x.complete ? `<em class="warn" title="${esc((x.os.missing || []).join("\n"))}">빠진 항목 ${(x.os.missing || []).length}</em>` : ""}
        ${d != null ? `<em class="${d > 0 ? "up" : "dn"}">VCF 대비 ${d > 0 ? "+" : ""}${d.toFixed(0)}%</em>` : ""}
        ${x.t && !x.complete ? `<em class="warn" title="${esc(x.t.missing.join("\n"))}">빠진 항목 ${x.t.missing_count}</em>` : ""}
        ${x.t && x.t.unverified.length ? `<em class="warn" title="리전 단가 미확인 항목">미확인: ${esc(x.t.unverified.join("·"))}</em>` : ""}</div>`;
    }).join("");
    const legend = PART.map(([k, l]) => `<span><i style="background:#555;opacity:${PARTC[k]}"></i>${l}</span>`).join("");
    const comp = `<table class="cc-t"><thead><tr><th>구성요소</th><th class="r">VCF</th>${P.map(p => `<th class="r">${PL[p]}</th>`).join("")}</tr></thead><tbody>
      ${PART.map(([k, l]) => `<tr><td>${l}</td><td class="r muted">${k === "compute" ? "배분" : ""}</td>${P.map(p => `<td class="r">${money(t[p][k])}</td>`).join("")}</tr>`).join("")}
      ${v.parts ? Object.entries(v.parts).map(([k, x]) => `<tr class="muted"><td>VCF · ${esc(VP[k] || k)}</td><td class="r">${money(x)}</td><td colspan="3"></td></tr>`).join("") : ""}
      <tr class="tot"><td>합계</td><td class="r">${money(v.monthly)}</td>${P.map(p => `<td class="r">${money(t[p].total)}${t[p].complete ? "" : " <span class='cc-na' title='단가가 없는 항목은 합계에서 빠짐'>*</span>"}</td>`).join("")}</tr></tbody></table>`;
    const map = `<table class="cc-t cc-map"><thead><tr><th>VCF 객체</th><th class="r">수</th>${P.map(p => `<th>${PL[p]}</th>`).join("")}<th>짝짓기 규칙</th></tr></thead><tbody>
      ${r.mapping.map(m => `<tr class="${m.key === "included" ? "muted" : ""}"><td><b>${esc(m.vcf)}</b></td><td class="r">${num(m.count)}</td>${P.map(p => `<td>${esc(m[p] || "")}</td>`).join("")}<td class="small">${esc(m.rule)}</td></tr>`).join("")}</tbody></table>`;
    const flow = mapFlow();
    const hw = r.hardware || {};
    const hwc = hw.assessed ? `<div class="cc-card"><h4>하드웨어 재사용 <small>하드웨어 준비도(BMC 실측) ${hw.assessed}/${hw.hosts}대</small></h4>
      <p>준비됨 ${hw.verdicts.ready || 0} · 조치 후 가능 ${hw.verdicts.actions || 0} · <b class="cc-na">불가 ${hw.verdicts.not_ready || 0}</b>${(hw.refresh || []).length ? ` — 교체 대상: ${hw.refresh.map(x => esc(x.host) + (x.cpu ? ` (${esc(x.cpu)})` : "")).join(", ")}` : ""}</p>
      <p class="small muted">${esc(hw.note || "")}. 서버 구매가·감가상각은 '원가·기준 설정'에서 반영하세요.</p></div>`
      : `<p class="small muted">하드웨어 준비도 스캔 결과가 있으면 호스트별 VCF 9 재사용 가능 여부와 BMC 실측 코어 수가 여기에 반영됩니다(메뉴 › 하드웨어 준비도).</p>`;
    return `<div class="cc-kpis">${kp}</div>${tcoCard()}${osCard()}${hwc}
      <div class="cc-card"><h4>월 비용 비교 <small>${esc(r.commit === "ondemand" ? "온디맨드" : r.commit + " 약정")} · ${r.basis === "rightsized" ? "적정화 크기 기준" : "할당 크기 기준"} · ${r.hours_per_month}시간/월 · 단가 기준일 ${esc(r.as_of || "")}</small></h4>
        ${rows.map(x => `<div class="cc-row"><label style="color:${PC[x.k]}">${esc(PL[x.k])}</label>${bar(x)}<b>${money(x.total)}${x.k !== "vcf" && !x.complete ? "<small class=cc-na> 부분</small>" : ""}</b></div>`).join("")}
        <div class="cc-leg">${legend}<span class="muted">VCF·OpenShift 막대 = 구독·(스토리지)·서버·상면·운영·기타</span></div></div>
      <div class="cc-card"><h4>구성요소 매핑 <small>VCF 객체가 각 클라우드의 어떤 서비스로 짝지어지는지</small></h4>${flow}${map}</div>
      <div class="cc-card"><h4>구성요소별 월 비용</h4>${comp}
        <p class="small muted">${esc(v.note || "")}${v.licensed_cores ? ` · 라이선스 코어 ${num(v.licensed_cores)} (호스트 ${v.hosts}대)` : ""}. 관리 VM ${r.counts.mgmt}개·VKS 컨트롤 플레인 ${r.counts.vks_cp}개는 클라우드에서 서비스 요금에 포함되므로 비교에서 제외하고, VCF 원가는 업무 VM ${r.counts.workload}개에 vCPU·메모리 비중으로 배분합니다.</p></div>`;
  }

  function tcoCard() {
    const T = st.r.tco; if (!T || !T.rows.length) return "";
    const rows = T.rows.filter(x => x.key !== "openshift" || (st.r.openshift || {}).mode !== "none");
    const max = Math.max(1, ...rows.map(x => x.total || 0));
    const base = (rows.find(x => x.key === "vcf") || {}).total;
    const yrs = Array.from({length: T.years}, (_, i) => i + 1);
    return `<div class="cc-card"><h4>${T.years}년 누적 비용 <small>월 비용 × 12 × ${T.years}년 + 전환 일회성 비용 · 기간은 '원가·기준 설정'에서</small></h4>
      ${rows.map(x => { const d = base && x.total != null && x.key !== "vcf" && x.complete ? (x.total - base) / base * 100 : null;
        return `<div class="cc-row"><label style="color:${PC[x.key]}">${esc(PL[x.key] || x.label)}</label>${x.total == null ? `<div class="cc-bar empty">계산 불가</div>` : `<div class="cc-bar"><i style="width:${(x.total / max * 100).toFixed(2)}%;background:${PC[x.key]}" title="누적 ${money(x.total).replace(/<[^>]+>/g, "")}"></i>${x.once ? `<i style="width:${(x.once / max * 100).toFixed(2)}%;background:${PC[x.key]};opacity:.4" title="전환 일회성 ${money(x.once).replace(/<[^>]+>/g, "")}"></i>` : ""}</div>`}
          <b>${money(x.total)}${!x.complete && x.total != null ? "<small class=cc-na> 부분</small>" : ""}${d != null ? ` <small class="${d > 0 ? "cc-up" : "cc-dn"}">${d > 0 ? "+" : ""}${d.toFixed(0)}%</small>` : ""}</b></div>`; }).join("")}
      <table class="cc-t small"><thead><tr><th></th>${yrs.map(y => `<th class="r">${y}년차 누적</th>`).join("")}</tr></thead><tbody>
        ${rows.map(x => `<tr><td style="color:${PC[x.key]}"><b>${esc(PL[x.key] || x.label)}</b></td>${yrs.map(y => `<td class="r">${money(x.by_year[y - 1])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  function osCard() {
    const o = st.r.openshift; if (!o || o.mode === "none") return "";
    const sup = o.support === "premium" ? "Premium(24x7)" : "Standard(8x5)";
    return `<div class="cc-card cc-os"><h4 style="color:${PC.openshift}">Red Hat OpenShift(자체 운영) <small>${esc(o.edition_name)} · ${sup}${o.auto_why ? ` · 자동 선택: ${esc(o.auto_why)}` : ""}</small></h4>
      <p class="small">${esc(o.edition_desc || "")} — 소켓 쌍 구독 <b>${num(o.units)}</b>개(서버 ${num(o.hosts)}대, 1~2소켓·최대 128코어마다 1개)${o.cp_nodes ? ` · 컨트롤 플레인 서버 ${o.cp_nodes}대(구독 제외, 서버·상면만)` : ""} · 스토리지: ${esc(o.storage_note || "")}</p>
      ${(o.missing || []).length ? `<div class="cc-miss"><b>계산에 빠진 항목</b><ul>${o.missing.map(m => `<li>${esc(m)}</li>`).join("")}</ul><button class="btn-sm" data-cct="set">원가·기준 설정에서 입력</button></div>` : ""}
      ${o.parts ? `<table class="cc-t"><thead><tr><th>구성</th><th class="r">OpenShift /월</th><th class="r">VCF /월</th></tr></thead><tbody>
        ${Object.entries(o.parts).map(([k, x]) => { const vk = {subscription: "subscription", hardware: "hardware", facility: "facility", operations: "operations", other: "other"}[k];
          return `<tr><td>${esc(OSP[k] || k)}</td><td class="r">${money(x)}</td><td class="r muted">${vk && st.r.vcf.parts ? money(st.r.vcf.parts[vk]) : k === "storage" ? "vSAN 포함" : ""}</td></tr>`; }).join("")}
        <tr class="tot"><td>합계</td><td class="r">${money(o.monthly)}</td><td class="r">${money(st.r.vcf.monthly)}</td></tr>
        ${o.once ? `<tr class="muted"><td>전환 일회성(별도)</td><td class="r">${money(o.once)}</td><td></td></tr>` : ""}</tbody></table>` : ""}
      <table class="cc-t cc-map"><thead><tr><th>VCF</th><th>OpenShift 대응</th><th>차이·주의</th></tr></thead><tbody>
        ${(o.mapping || []).map(m => `<tr><td><b>${esc(m.vcf)}</b></td><td>${esc(m.os)}</td><td class="small">${esc(m.note || "")}</td></tr>`).join("")}</tbody></table>
      <p class="small muted">${esc(o.note || "")}. 같은 서버를 그대로 쓰고 플랫폼만 바꾼다고 보고, 서버·상면·운영 원가는 VCF 원가 모델 값을 함께 씁니다(운영 인력 증감은 설정 %). 구독 규칙: Red Hat Self-managed OpenShift subscription guide.</p></div>`;
  }

  function mapFlow() {   // 왼쪽 VCF 계층 → 오른쪽 세 클라우드 서비스 (SVG 선)
    const m = st.r.mapping, n = m.length, H = 34, W = 940, h = n * H + 16;
    const lx = 10, lw = 290, rx = 400, cw = 170;
    const rows = m.map((x, i) => {
      const y = 8 + i * H, inc = x.key === "included";
      const left = `<rect x="${lx}" y="${y}" width="${lw}" height="26" rx="3" class="cc-n ${inc ? "inc" : ""}"/><text x="${lx + 8}" y="${y + 17}">${esc(x.vcf.length > 40 ? x.vcf.slice(0, 39) + "…" : x.vcf)} <tspan class="cc-cnt">${x.count}</tspan></text>`;
      const right = P.map((p, j) => { const X = rx + j * (cw + 8); const t = x[p] || ""; return `<rect x="${X}" y="${y}" width="${cw}" height="26" rx="3" class="cc-n ${inc ? "inc" : ""}" style="stroke:${PC[p]}"/><text x="${X + 6}" y="${y + 17}"><title>${esc(t)}</title>${esc(t.length > 24 ? t.slice(0, 23) + "…" : t)}</text>`; }).join("");
      const line = `<path d="M${lx + lw} ${y + 13} C ${lx + lw + 50} ${y + 13}, ${rx - 50} ${y + 13}, ${rx} ${y + 13}" class="cc-l ${inc ? "inc" : ""}"/>`;
      return left + line + right;
    }).join("");
    const head = P.map((p, j) => `<text x="${rx + j * (cw + 8) + 4}" y="-2" class="cc-h" style="fill:${PC[p]}">${PL[p]}</text>`).join("");
    return `<div class="cc-flow"><svg viewBox="0 -14 ${W} ${h + 14}" role="img" aria-label="VCF 구성요소와 클라우드 서비스 매핑">${head}<text x="${lx + 4}" y="-2" class="cc-h" style="fill:${PC.vcf}">VCF</text>${rows}</svg></div>`;
  }

  const osOn = () => ((st.r || {}).openshift || {}).mode && st.r.openshift.mode !== "none";
  // ---------------------------------------------------------------- VM 매핑
  function vmTable() {
    const r = st.r, q = st.q.toLowerCase();
    let vms = r.vms.filter(v => (!st.cat || v.category === st.cat) && (!q || (v.name + " " + v.cluster + " " + v.os).toLowerCase().includes(q)));
    const key = {name: v => v.name, vcpu: v => v.vcpu, mem: v => v.mem_gb, disk: v => v.disk_gb, imin: v => (v.iops || {}).min ?? -1, iavg: v => (v.iops || {}).avg ?? -1,
                 imax: v => (v.iops || {}).max ?? -1, vcf: v => v.vcf_monthly ?? -1, os: v => v.os_monthly ?? -1, aws: v => ((v.cloud.aws || {}).monthly ?? -1), azure: v => ((v.cloud.azure || {}).monthly ?? -1), gcp: v => ((v.cloud.gcp || {}).monthly ?? -1)}[st.sort];
    vms = vms.slice().sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * st.dir; });
    const th = (k, l, cls = "r") => `<th class="${cls} sort ${st.sort === k ? "on" : ""}" data-ccs="${k}">${l}${st.sort === k ? (st.dir > 0 ? " ▲" : " ▼") : ""}</th>`;
    const cell = (v, p) => {
      const c = v.cloud[p]; if (!c) return `<td class="muted small">${v.category === "workload" ? "" : "포함"}</td>`;
      const tip = [`${c.sku || "?"} (${c.vcpu} vCPU · ${c.mem} GB)`, `컴퓨트 ${money(c.compute)}`, `스토리지 ${money(c.storage)}`, c.iops ? `추가 IOPS ${money(c.iops)}` : "", c.note || "", c.missing || ""].filter(Boolean).join("\n").replace(/<[^>]+>/g, "");
      return `<td title="${esc(tip)}"><div class="cc-sku">${esc(c.sku || "-")}${c.over ? ` <span class="cc-b no" title="가장 큰 크기로도 부족">초과</span>` : ""}${c.iops_over && !c.iops && p !== "azure" ? ` <span class="cc-b no" title="최대 IOPS 가 기본 제공(3,000)을 넘음 — 추가 IOPS 단가 미입력">IOPS↑</span>` : ""}</div><b>${money(c.monthly)}</b>${c.missing ? ` <small class="cc-na">${esc(c.missing)}</small>` : ""}</td>`;
    };
    const io = r.iops;
    const tot = c => vms.reduce((s, v) => s + (c(v) || 0), 0);
    return `<div class="cc-tools"><input id="cc-q" placeholder="VM·클러스터·OS 검색" value="${esc(st.q)}">
        <select id="cc-cat"><option value="">전체 분류</option>${Object.entries(CAT).map(([k, l]) => `<option value="${k}" ${st.cat === k ? "selected" : ""}>${l}</option>`).join("")}</select>
        <span class="small muted">${vms.length}개 · IOPS ${io.days}일 기준 · 표본 VM ${io.vms}개${io.last ? ` · 마지막 수집 ${new Date(io.last * 1000).toLocaleString()}${io.vms ? "" : " (vCenter 가 가상 디스크·데이터스토어 IOPS 카운터 값을 주지 않음 — 통계 수준 확인)"}` : " · 아직 수집 전(1시간마다)"}${io.error ? ` · <span class="cc-na">${esc(io.error)}</span>` : ""}</span>
        <button class="btn-sm" id="cc-iops" data-perm="settings">IOPS 지금 수집</button><button class="btn-sm" id="cc-csv">CSV</button></div>
      <div class="cc-scroll"><table class="cc-t cc-vm"><thead><tr>${th("name", "VM", "")}<th>분류</th>${th("vcpu", "vCPU")}${th("mem", "메모리 GB")}${th("disk", "디스크 GB")}
        ${th("imin", "IOPS 최소")}${th("iavg", "평균")}${th("imax", "최대")}${th("vcf", "VCF /월")}${osOn() ? th("os", "OpenShift /월") : ""}${P.map(p => th(p, PL[p], "")).join("")}</tr></thead><tbody>
        ${vms.slice(0, 2000).map(v => `<tr class="${v.category !== "workload" ? "muted" : ""}"><td><b>${esc(v.name)}</b><div class="small muted">${esc(v.cluster)} · ${esc((v.os || "").slice(0, 34))}${v.power !== "poweredOn" ? " · 꺼짐" : ""}</div></td>
          <td class="small">${esc(CAT[v.category] || v.category)}${v.sized && v.sized.rightsized ? `<div class="cc-b ok" title="적정화 권장 크기로 계산">${v.sized.vcpu}/${v.sized.mem_gb}GB</div>` : ""}</td>
          <td class="r">${num(v.vcpu)}</td><td class="r">${num(v.mem_gb, 1)}</td><td class="r">${num(v.disk_gb)}</td>
          <td class="r">${num((v.iops || {}).min)}</td><td class="r">${num((v.iops || {}).avg)}</td><td class="r ${((v.iops || {}).max || 0) > (st.r.settings.iops_baseline || 3000) ? "cc-hot" : ""}">${num((v.iops || {}).max)}</td>
          <td class="r">${money(v.vcf_monthly)}</td>${osOn() ? `<td class="r">${money(v.os_monthly)}</td>` : ""}${P.map(p => cell(v, p)).join("")}</tr>`).join("")}</tbody>
        <tfoot><tr class="tot"><td colspan="8">합계(표시된 VM)</td><td class="r">${money(tot(v => v.vcf_monthly))}</td>${osOn() ? `<td class="r">${money(tot(v => v.os_monthly))}</td>` : ""}${P.map(p => `<td><b>${money(tot(v => (v.cloud[p] || {}).monthly))}</b></td>`).join("")}</tr></tfoot></table></div>
      ${r.k8s.length || r.lb.length ? `<div class="cc-two">
        <div><h4>VKS 클러스터 → 관리형 Kubernetes</h4><table class="cc-t"><thead><tr><th>클러스터</th><th class="r">노드</th>${P.map(p => `<th>${PL[p]}</th>`).join("")}</tr></thead><tbody>
          ${r.k8s.map(k => `<tr><td>${esc(k.name)}</td><td class="r">${k.nodes}</td>${P.map(p => `<td><div class="cc-sku">${esc(k.cloud[p].sku || "")}</div>${money(k.cloud[p].monthly)}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="5" class="muted">없음</td></tr>`}</tbody></table></div>
        <div><h4>NSX ALB 가상 서비스 → L7 로드밸런서</h4><table class="cc-t"><thead><tr><th>가상 서비스</th>${P.map(p => `<th>${PL[p]}</th>`).join("")}</tr></thead><tbody>
          ${r.lb.map(k => `<tr><td>${esc(k.name)}<div class="small muted">${esc((k.vips || []).join(", "))}</div></td>${P.map(p => `<td><div class="cc-sku">${esc(k.cloud[p].sku || "")}</div>${money(k.cloud[p].monthly)}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="4" class="muted">없음</td></tr>`}</tbody></table></div></div>` : ""}`;
  }

  // ---------------------------------------------------------------- 단가표
  function priceTab() {
    const c = st.prices, ov = c.overrides || {};
    const inp = (path, val, unit) => `<input class="cc-in ${ov[path] ? "ed" : ""}" data-pp="${esc(path)}" type="number" step="any" min="0" value="${val ?? ""}" placeholder="미입력" title="${esc(ov[path] ? `수정: ${ov[path].by || ""} · ${ov[path].source} · ${new Date(ov[path].ts * 1000).toLocaleString()}` : path)}"> <small>${unit}</small>`;
    const src = x => x.src ? `<a href="${esc(x.src)}" target="_blank" rel="noopener noreferrer" class="small">출처</a>${x.src_date ? ` <small class="muted">${esc(x.src_date)}</small>` : ""}` : "";
    const prov = p => {
      const x = c.providers[p];
      const comp = x.compute.map(f => `<tr><td><b>${esc(f.family)}</b><div class="small muted">${esc(f.name)} · 메모리:vCPU ${f.ratio}:1 · ${f.sizes.length}개 크기</div></td>
        <td>${f.per_vcpu ? `${inp(`${p}.compute.${f.family}.vcpu_hour`, f.vcpu_hour, "/vCPU·h")}<br>${inp(`${p}.compute.${f.family}.gb_hour`, f.gb_hour, "/GB·h")}<br>${inp(`${p}.compute.${f.family}.windows_core_hour`, f.windows_core_hour, "Win /vCPU·h")}`
          : `${inp(`${p}.compute.${f.family}.linux`, f.linux, `Linux /h (${esc(f.sizes[0][0])})`)}<br>${inp(`${p}.compute.${f.family}.windows`, f.windows, "Windows /h")}${f.ri_1y_total != null ? `<br>${inp(`${p}.compute.${f.family}.ri_1y_total`, f.ri_1y_total, "RI 1년 총액")}<br>${inp(`${p}.compute.${f.family}.ri_3y_total`, f.ri_3y_total, "RI 3년 총액")}` : ""}`}</td>
        <td>${badge(f.verified)} ${src(f)}${f.note ? `<div class="small muted">${esc(f.note)}</div>` : ""}${f.windows_note ? `<div class="small muted">${esc(f.windows_note)}</div>` : ""}</td></tr>`).join("");
      const s = x.storage, k = x.k8s, l = x.lb, cm = x.commit;
      return `<div class="cc-card"><h4 style="color:${PC[p]}">${esc(x.label)} <small>${esc(x.region)}</small>
          ${p === "azure" ? `<button class="btn-sm" data-ccr="azure" data-perm="settings">Azure Retail Prices API 로 갱신</button>` : ""}${p === "gcp" ? `<button class="btn-sm" data-ccr="gcp" data-perm="settings">Cloud Billing Catalog API 로 가져오기</button>` : ""}</h4>
        <table class="cc-t"><thead><tr><th>항목</th><th>단가(USD)</th><th>출처·확인</th></tr></thead><tbody>${comp}
        <tr><td><b>스토리지</b><div class="small muted">${esc(s.name)}</div></td><td>${inp(`${p}.storage.gb_month`, s.gb_month, "/GB·월")}<br>${inp(`${p}.storage.iops_month`, s.iops_month, "/IOPS·월(기본 초과분)")}</td><td>${badge(s.verified)} ${src(s)}<div class="small muted">${esc(s.note || "")} ${esc(s.iops_note || "")}</div></td></tr>
        <tr><td><b>관리형 Kubernetes</b><div class="small muted">${esc(k.name)}</div></td><td>${inp(`${p}.k8s.cluster_hour`, k.cluster_hour, "/클러스터·h")}</td><td>${badge(k.verified)} ${src(k)}</td></tr>
        <tr><td><b>로드밸런서</b><div class="small muted">${esc(l.name)}</div></td><td>${inp(`${p}.lb.hour`, l.hour, "/h")}<br>${inp(`${p}.lb.unit_hour`, l.unit_hour, `/${esc(l.unit_name || "단위")}·h`)}<br>${inp(`${p}.lb.units`, l.units, "단위 수(평균)")}</td><td>${badge(l.verified)} ${src(l)}<div class="small muted">${esc(l.note || "")}</div></td></tr>
        <tr><td><b>약정 할인율</b><div class="small muted">${esc(cm.note || "")}</div></td><td>${inp(`${p}.commit.1y`, cm["1y"], "% (1년)")}<br>${inp(`${p}.commit.3y`, cm["3y"], "% (3년)")}</td><td>${cm.verified ? badge(true) : ""} ${src(cm)}</td></tr></tbody></table></div>`;
    };
    return `<div class="cc-tools"><span class="small muted">${esc(c.note)}</span><button class="btn-sm solid" id="cc-psave" data-perm="settings">수정한 단가 저장</button><button class="btn-sm" id="cc-preset" data-perm="settings">기본값으로</button></div>${P.map(prov).join("")}`;
  }

  // ---------------------------------------------------------------- 설정
  function setTab() {
    const s = st.settings;
    const f = (k, l, unit = "", type = "number", extra = "") => `<label class="cc-f"><span>${l}</span><input data-cs="${k}" type="${type}" value="${esc(String(s[k] ?? ""))}" ${type === "number" ? 'step="any" min="0"' : ""} ${extra}> <small>${unit}</small></label>`;
    const sel = (k, l, opts) => `<label class="cc-f"><span>${l}</span><select data-cs="${k}">${opts.map(([v, t]) => `<option value="${v}" ${String(s[k]) === v ? "selected" : ""}>${t}</option>`).join("")}</select></label>`;
    return `<div class="cc-card"><h4>VCF 원가</h4>
        ${sel("vcf_mode", "계산 방식", [["tco", "TCO 모델(구독·서버·상면·운영)"], ["rate", "정산(Billing) 기본 요율표"], ["none", "계산 안 함"]])}
        ${sel("vcf_currency", "입력 통화", [["USD", "USD"], ["KRW", "KRW(원)"]])}
        ${f("subscription_per_core_year", "VCF 구독 단가", "코어당·연 — 계약 단가")}
        ${f("hw_per_host", "서버 구매가", "호스트당")}${f("amort_years", "감가상각", "년")}
        ${f("facility_per_host_year", "상면·전력·네트워크", "호스트당·연")}${f("ops_per_year", "운영 인력", "연")}${f("other_per_year", "기타(백업·보안 등)", "연")}
        ${f("cpu_weight", "배분 가중치 vCPU", "% (나머지 메모리)")}
        <p class="small muted">라이선스 코어 = 호스트마다 CPU 당 max(실제 코어, 16) × CPU 수(Broadcom KB 313548). 코어 수를 모르는 호스트는 16코어로 계산합니다.</p></div>
      <div class="cc-card cc-os"><h4 style="color:${PC.openshift}">Red Hat OpenShift(자체 운영) 비교</h4>
        ${sel("os_mode", "에디션", [["auto", "자동(VM 만 → Virtualization Engine · VKS 있으면 → Platform Plus)"], ["ove", "OpenShift Virtualization Engine(VM 전용)"], ["oke", "OpenShift Kubernetes Engine"], ["ocp", "OpenShift Container Platform"], ["opp", "OpenShift Platform Plus"], ["none", "비교 안 함"]])}
        ${sel("os_support", "지원 수준", [["premium", "Premium(24x7)"], ["standard", "Standard(8x5)"]])}
        ${sel("os_currency", "단가 통화", [["KRW", "KRW(원)"], ["USD", "USD"], ["JPY", "JPY(엔 — 일본 표준가 참고용)"]])}${f("os_fx_krw_per_100jpy", "엔화 환율", "원/100엔 (JPY 일 때)")}
        ${f("os_price_ove", "Virtualization Engine", "소켓 쌍 1개·연")}${f("os_price_oke", "Kubernetes Engine", "소켓 쌍 1개·연")}
        ${f("os_price_ocp", "Container Platform", "소켓 쌍 1개·연")}${f("os_price_opp", "Platform Plus", "소켓 쌍 1개·연")}
        ${sel("os_storage", "스토리지", [["odf", "OpenShift Data Foundation(vSAN 대체 HCI)"], ["external", "외부 스토리지(SAN 등)"]])}
        ${f("os_odf_per_node_year", "ODF 단가", "서버당·연 (Platform Plus 는 Essentials 포함)")}${f("os_storage_per_year", "외부 스토리지", "연(외부일 때)")}
        ${f("os_cp_nodes", "컨트롤 플레인 서버", "대(구독 제외, 서버·상면 비용만)")}${f("os_ops_delta_pct", "운영 인력 증감", "% (예: 20 = 20% 증가)")}
        ${f("os_migration_once", "전환 일회성 비용", "이관·컨설팅·재교육(단가 통화)")}
        <div class="cc-ref" id="cc-osref">${osRef()}</div>
        <p class="small muted">구독 규칙(Red Hat 공식 가이드): Bare Metal 소켓 쌍 구독 1개 = 1~2소켓·최대 128코어 서버 1대(더 크면 쌓기), 컨트롤 플레인·인프라 전용 노드는 구독 제외, Virtualization Engine 은 소켓 쌍으로만·VM 무제한·사용자 컨테이너 불가·RHEL 게스트 권한 미포함. 서버·상면·운영 원가는 위 VCF 원가 모델 값을 같이 씁니다(같은 서버 재사용).</p></div>
      <div class="cc-card"><h4>비교 기준</h4>
        ${sel("commit", "클라우드 약정", [["ondemand", "온디맨드"], ["1y", "1년 약정"], ["3y", "3년 약정"]])}
        ${sel("basis", "VM 크기", [["allocated", "할당(vCPU·메모리 그대로)"], ["rightsized", "적정화 권장 크기(용량·적정화 결과)"]])}
        ${sel("disk_basis", "디스크", [["provisioned", "할당 용량"], ["used", "사용 용량"]])}
        ${sel("include_off", "꺼진 VM", [["false", "제외"], ["true", "포함"]])}
        ${sel("currency", "표시 통화", [["USD", "USD"], ["KRW", "KRW"]])}${f("fx_krw_per_usd", "환율", "원/달러")}
        ${f("tco_years", "누적 비교 기간", "년(1–10)")}${f("cloud_migration_once", "클라우드 전환 일회성 비용", "USD")}
        ${f("iops_days", "IOPS 집계 기간", "일(1–90)")}${f("iops_baseline", "기본 제공 IOPS", "초과분만 추가 단가")}
        <label class="cc-f wide"><span>관리 VM 이름 패턴(정규식, 줄마다)</span><textarea data-cs="mgmt_patterns" rows="3" placeholder="^backup-proxy">${esc((s.mgmt_patterns || []).join("\n"))}</textarea></label>
        <p class="small muted">기본 관리 VM: vCLS·vCenter·NSX Manager/Edge·SDDC Manager·Avi SE/Controller·Supervisor·VCF Operations 계열 — 클라우드에서는 사업자 운영이라 비교에서 빠집니다.</p>
        <button class="btn-sm solid" id="cc-ssave" data-perm="settings">저장</button></div>`;
  }

  function osRef() {
    const R = st.osref; if (!R) return `<span class="small muted">참고 단가 불러오는 중…</span>`;
    const sup = (st.settings || {}).os_support === "standard" ? "standard" : "premium";
    return `<details><summary>참고 단가 — ${esc(R.src_name)} (${esc(R.currency)}, ${esc(R.unit)})</summary>
      <table class="cc-t small"><thead><tr><th>에디션</th><th>SKU · Premium</th><th class="r">Premium</th><th>SKU · Standard</th><th class="r">Standard</th></tr></thead><tbody>
        ${Object.entries(R.editions).map(([k, e]) => `<tr><td>${esc(e.name)}</td><td>${esc(e.premium.sku)}</td><td class="r">¥${num(e.premium.price)}</td><td>${esc(e.standard.sku)}</td><td class="r">¥${num(e.standard.price)}</td></tr>`).join("")}</tbody></table>
      <p class="small muted">${esc(R.note)} <a href="${esc(R.src)}" target="_blank" rel="noopener noreferrer">출처</a> · <a href="${esc(R.rules_src)}" target="_blank" rel="noopener noreferrer">구독 규칙(Red Hat)</a></p>
      <button class="btn-sm" id="cc-osfill" data-perm="settings" data-sup="${sup}">이 참고가(${sup === "premium" ? "Premium" : "Standard"}, 엔)로 채우기</button> <small class="muted">통화가 JPY 로 바뀝니다 — '엔화 환율'과 '환율(원/달러)'을 넣고 저장하세요.</small></details>`;
  }

  function render() {
    const box = $("#cc-body"); if (!box) return;
    if (!st.r) { box.innerHTML = `<p class="muted">${st.loading ? "계산 중…" : "데이터 없음"}</p>`; return; }
    const tabs = [["sum", "요약·매핑"], ["vm", `VM 별 비교·IOPS (${st.r.counts.workload})`], ["price", "단가표"], ["set", "원가·기준 설정"]];
    const clusters = st.r.clusters || [];
    box.innerHTML = `<div class="cc-top"><div class="tabs">${tabs.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-cct="${k}">${l}</button>`).join("")}</div>
        <div class="cc-quick"><select id="cc-o-commit" title="약정"><option value="">약정: 설정값</option><option value="ondemand">온디맨드</option><option value="1y">1년</option><option value="3y">3년</option></select>
        <select id="cc-o-basis" title="크기 기준"><option value="">크기: 설정값</option><option value="allocated">할당</option><option value="rightsized">적정화</option></select>
        <select id="cc-o-cluster"><option value="">전체 클러스터</option>${clusters.map(c => `<option ${st.opts.cluster === c ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>${st.loading ? `<span class="small muted">계산 중…</span>` : ""}</div></div>
      <div class="cc-pane">${st.tab === "sum" ? summary() : st.tab === "vm" ? vmTable() : st.tab === "price" ? priceTab() : setTab()}</div>
      <p class="small muted cc-foot">공개 정가(USD, 세금·지원 요금·데이터 전송·백업·라이선스 이동(BYOL) 제외) 기준의 비교입니다. 실제 청구액은 계약 할인·사용 패턴에 따라 다릅니다. 확인하지 못한 단가는 추정해 채우지 않고 '—'·'미확인'으로 표시합니다.</p>`;
    ["commit", "basis"].forEach(k => { const el = $(`#cc-o-${k}`); if (el) el.value = st.opts[k] || ""; });
    $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
  }

  function wire() {
    const box = $("#cc-body"); if (box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target.closest("[data-cct],[data-ccs],#cc-csv,#cc-iops,#cc-psave,#cc-preset,#cc-ssave,[data-ccr],#cc-osfill"); if (!t) return;
      if (t.id === "cc-osfill") {
        const sup = $('[data-cs="os_support"]', box).value === "standard" ? "standard" : "premium";
        Object.entries(st.osref.editions).forEach(([k, ed]) => { const i = $(`[data-cs="os_price_${k}"]`, box); if (i) i.value = ed[sup].price; });
        const c = $('[data-cs="os_currency"]', box); if (c) c.value = "JPY";
        A.toast("참고가를 채웠습니다", "엔화 환율·원/달러 환율을 확인하고 '저장'을 누르세요", "info", 4000); return;
      }
      if (t.dataset.cct) { st.tab = t.dataset.cct; render(); return; }
      if (t.dataset.ccs) { if (st.sort === t.dataset.ccs) st.dir *= -1; else { st.sort = t.dataset.ccs; st.dir = t.dataset.ccs === "name" ? 1 : -1; } render(); return; }
      if (t.id === "cc-csv") { const a = document.createElement("a"); a.href = "/api/cloudcost/report.csv?" + new URLSearchParams(Object.entries(st.opts).filter(([, v]) => v)); a.download = ""; document.body.append(a); a.click(); a.remove(); return; }
      if (t.id === "cc-iops") { try { const r = await A.api("POST", "/api/cloudcost/iops/collect"); A.ok("IOPS 수집", `VM ${r.vms}개${r.error ? " · " + r.error : ""}`); await load(); } catch (x) { A.fail("IOPS 수집 실패", x); } return; }
      if (t.id === "cc-psave") {
        const ch = {}; const ov = st.prices.overrides || {};
        $$("[data-pp]", box).forEach(i => { const orig = i.defaultValue; if (i.value !== orig) ch[i.dataset.pp] = i.value === "" ? (ov[i.dataset.pp] ? "" : null) : i.value; });
        Object.keys(ch).forEach(k => { if (ch[k] === null) delete ch[k]; });
        if (!Object.keys(ch).length) { A.toast("변경 없음", "", "info", 2000); return; }
        try { await A.api("PUT", "/api/cloudcost/prices", {changes: ch}); st.dirty = {}; A.ok("단가 저장", `${Object.keys(ch).length}개 항목`); await load(); } catch (x) { A.fail("단가 저장 실패", x); }
        return;
      }
      if (t.id === "cc-preset") { if (!await A.confirm("단가 기본값으로", "관리자가 수정하거나 API 로 가져온 단가를 모두 지우고 기본 단가표로 되돌립니다.", true)) return; try { await A.api("DELETE", "/api/cloudcost/prices"); st.dirty = {}; await load(); } catch (x) { A.fail("되돌리기 실패", x); } return; }
      if (t.id === "cc-ssave") {
        const b = {};
        $$("[data-cs]", box).forEach(i => { const k = i.dataset.cs; b[k] = k === "mgmt_patterns" ? i.value.split("\n").map(x => x.trim()).filter(Boolean) : k === "include_off" ? i.value === "true" : i.value; });
        try { await A.api("PUT", "/api/cloudcost/settings", b); st.dirty = {}; A.ok("설정 저장", ""); await load(); } catch (x) { A.fail("설정 저장 실패", x); }
        return;
      }
      if (t.dataset.ccr === "azure") { t.disabled = true; try { const r = await A.api("POST", "/api/cloudcost/prices/refresh", {provider: "azure"}); A.ok("Azure 단가 갱신", `${r.updated}개 항목`); await load(); } catch (x) { A.fail("Azure 단가 갱신 실패", x); } t.disabled = false; return; }
      if (t.dataset.ccr === "gcp") {
        const v = await A.modal({title: "Google Cloud 단가 가져오기", html: `<p class="small muted">Cloud Billing Catalog API(읽기 전용 공개 가격표)를 Google Cloud 콘솔에서 만든 API 키로 조회합니다. 키는 이 요청에만 쓰고 저장하지 않습니다. 서울 리전(asia-northeast3) N2 vCPU·메모리·Balanced PD 단가를 가져옵니다.</p>`,
          ok: "가져오기", fields: [{id: "key", label: "API 키", type: "password", value: ""}, {id: "region", label: "리전 설명(SKU 표기)", type: "text", value: "Seoul"}]});
        if (!v || !v.key) return;
        try { const r = await A.api("POST", "/api/cloudcost/prices/refresh", {provider: "gcp", api_key: v.key, region_desc: v.region}); A.ok("GCP 단가 가져오기", `${r.updated}개 항목`); await load(); } catch (x) { A.fail("GCP 단가 가져오기 실패", x); }
      }
    });
    box.addEventListener("change", e => {
      const t = e.target;
      if (t.id === "cc-cat") { st.cat = t.value; render(); }
      if (t.id && t.id.startsWith("cc-o-")) { st.opts[t.id.slice(5)] = t.value; load(); }
    });
    box.addEventListener("input", e => { if (e.target.id === "cc-q") { st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(() => { render(); const q = $("#cc-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 250); } });
  }

  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-cc") d.hidden = true; });
    $("#drawer-cc").hidden = false;
    wire(); await load();
  }
  const nav = document.getElementById("nav-cc");
  if (nav) nav.onclick = show;
  const rl = document.getElementById("cc-reload");
  if (rl) rl.onclick = load;
  window.AIOPS_CLOUDCOST = show;
})();
