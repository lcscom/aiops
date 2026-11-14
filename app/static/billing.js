/* 정산(Billing) — 보고서(기간·테넌트 › 프로젝트 › VM)·테넌트/프로젝트 매칭·요율표. core.js(AIOPS) 이후 로드
   GET /api/billing/report · /config · report.csv · statement(인쇄용) · POST/PUT/DELETE tenants·projects·rates */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const st = {tab: "rep", period: "mtd", month: "", start: "", end: "", tenant: 0, rep: null, cfg: null, openT: new Set(), openP: new Set(), q: ""};
  const N = (v, d = 1) => v == null ? "-" : Number(v).toLocaleString(undefined, {maximumFractionDigits: d});
  const money = (v, cur) => v == null ? "-" : `${Number(v).toLocaleString(undefined, {maximumFractionDigits: cur === "KRW" || cur === "JPY" ? 0 : 2})}`;
  const ym = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; };
  const qs = () => new URLSearchParams({period: st.period, month: st.month || ym(), start: st.start, end: st.end, tenant: st.tenant || 0}).toString();

  async function load() {
    try {
      [st.cfg, st.rep] = await Promise.all([A.api("GET", "/api/billing/config", undefined, {background: true}),
                                            A.api("GET", `/api/billing/report?${qs()}`, undefined, {background: true})]);
    } catch (e) { $("#bl-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }
  const tabs = () => `<div class="vc-tabs">${[["rep", "보고서"], ["ten", `테넌트·프로젝트 <small>${(st.cfg.tenants || []).length}</small>`], ["rate", `요율표 <small>${(st.cfg.rates || []).length}</small>`]]
    .map(([k, l]) => `<button data-bt="${k}" class="${st.tab === k ? "on" : ""}">${l}</button>`).join("")}</div>`;

  function render() {
    const b = $("#bl-body"); if (!b || !st.cfg) return;
    const sm = st.cfg.sampler || {};
    $("#bl-sub").textContent = `VM 사용량 5분 표본 · 마지막 표본 ${sm.last_sample ? new Date(sm.last_sample * 1000).toLocaleTimeString() : "대기"} · VM ${sm.vms || 0}${sm.error ? " · 오류 " + sm.error : ""}${st.cfg.scoped ? " · 내 테넌트만" : ""}`;
    b.innerHTML = tabs() + (st.tab === "rep" ? report() : st.tab === "ten" ? tenants() : rates());
  }

  // ---------------------------------------------------------------- 보고서
  function report() {
    const R = st.rep, T = R.totals, cur = R.currency, cv = R.coverage;
    const per = `<div class="vc-ctl bl-ctl"><select id="bl-per">${[["mtd", "이번 달(오늘까지)"], ["7d", "최근 7일"], ["30d", "최근 30일"], ["month", "월 지정"], ["custom", "기간 지정"]]
        .map(([k, l]) => `<option value="${k}" ${st.period === k ? "selected" : ""}>${l}</option>`).join("")}</select>
      ${st.period === "month" ? `<input type="month" id="bl-month" value="${esc(st.month || ym())}">` : ""}
      ${st.period === "custom" ? `<input type="date" id="bl-start" value="${esc(st.start)}"> ~ <input type="date" id="bl-end" value="${esc(st.end)}"><button class="btn-sm" id="bl-apply">조회</button>` : ""}
      <select id="bl-ten"><option value="0">전체 테넌트</option>${(st.cfg.tenants || []).map(t => `<option value="${t.id}" ${st.tenant === t.id ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select>
      <input id="bl-q" placeholder="VM·프로젝트 검색" value="${esc(st.q)}"><span class="gap"></span>
      <button class="btn-sm" id="bl-csv">CSV</button>${A.can("operate") ? `<button class="btn-sm" id="bl-sample" title="지금 5분 블록 표본을 남김(이미 기록된 블록이면 건너뜀)">지금 표본</button>` : ""}</div>`;
    const kpi = `<div class="vc-cards bl-k">
      <div class="vc-card info"><b>합계 비용 <small>${esc(cur)}</small></b><span class="vc-n">${money(T.cost, cur)}</span><small>${esc(R.period.label)}</small></div>
      <div class="vc-card info"><b>VM</b><span class="vc-n">${N(T.vms, 0)}</span><small>테넌트 ${T.tenants} · 프로젝트 ${T.projects}</small></div>
      <div class="vc-card info"><b>vCPU·시간</b><span class="vc-n">${N(T.vcpu_hours, 0)}</span><small>켜진 시간 기준</small></div>
      <div class="vc-card info"><b>메모리 GB·시간</b><span class="vc-n">${N(T.mem_gb_hours, 0)}</span><small>&nbsp;</small></div>
      <div class="vc-card info"><b>디스크 GB·시간</b><span class="vc-n">${N(T.disk_gb_hours, 0)}</span><small>할당(프로비저닝) 기준</small></div>
      <div class="vc-card ${T.unassigned_vms ? "warning" : ""}"><b>미할당 VM</b><span class="vc-n">${N(T.unassigned_vms, 0)}</span><small>vCPU·h ${N(T.unassigned_vcpu_hours, 0)}</small></div></div>
      <p class="small muted">데이터 있는 시간 ${cv.hours_with_data} / 기간 ${N(cv.period_hours, 0)}시간${cv.first_hour ? ` · 첫 표본 ${new Date(cv.first_hour * 1000).toLocaleString()}` : ""}${!(R.rates || []).length ? " · 요율표가 없어 비용은 표시하지 않습니다(사용량만) — '요율표' 탭에서 추가" : ""}</p>`;
    const q = st.q.toLowerCase(), hit = v => !q || `${v.vm} ${v.folder} ${v.cluster} ${(v.tags || []).join(" ")}`.toLowerCase().includes(q);
    const vmRows = (vms, cur) => vms.filter(hit).map(v => `<tr class="bl-vm"><td></td><td></td><td class="vc-ent">${esc(v.vm)}</td><td>${esc(v.cluster || "")}</td><td title="${esc(v.folder || "")}">${esc((v.folder || "").split("/").slice(-2).join("/"))}</td>
        <td>${esc(v.matched_by)}</td><td>${N(v.on_hours)}</td><td>${N(v.avg_vcpu)}</td><td>${N(v.avg_mem_gb)}</td><td>${N(v.avg_disk_gb, 0)}</td><td>${v.cpu_util ?? "-"}%</td><td>${v.mem_util ?? "-"}%</td>
        <td>${money(v.cpu_cost, cur)}</td><td>${money(v.mem_cost, cur)}</td><td>${money(v.disk_cost, cur)}</td><td><b>${money(v.cost, cur)}</b></td></tr>`).join("");
    const rows = R.tenants.map(t => {
      const to = st.openT.has(t.id);
      const ps = to ? t.projects.map(p => { const po = st.openP.has(p.id);
        return `<tr class="bl-p" data-bp="${p.id}"><td></td><td>${po ? "▾" : "▸"} <b>${esc(p.name)}</b><small> ${esc(p.rate || "요율 없음")}</small></td><td colspan="4" class="small muted">${esc([...p.match.clusters.map(x => "클러스터 " + x), ...p.match.folders.map(x => "폴더 " + x), ...p.match.tags.map(x => "태그 " + x), ...p.match.vms.map(x => "VM " + x)].join(" · ").slice(0, 160))}</td>
          <td>${N(p.on_hours, 0)}</td><td colspan="5">VM ${p.vms} · vCPU·h ${N(p.vcpu_hours, 0)} · GB·h ${N(p.mem_gb_hours, 0)} / ${N(p.disk_gb_hours, 0)}</td><td>${money(p.cpu_cost, cur)}</td><td>${money(p.mem_cost, cur)}</td><td>${money(p.disk_cost, cur)}</td><td><b>${money(p.cost, cur)}</b></td></tr>${po ? vmRows(p.vm_rows, cur) : ""}`; }).join("") : "";
      return `<tr class="bl-t" data-bten="${t.id}"><td>${to ? "▾" : "▸"}</td><td colspan="5"><b>${esc(t.name)}</b> <small class="muted">프로젝트 ${t.projects.length} · VM ${t.vms}</small>
          <button class="btn-xs" data-stmt="${t.id}" title="월 명세서(인쇄·PDF)">명세서</button></td><td>${N(t.on_hours, 0)}</td><td colspan="5">vCPU·h ${N(t.vcpu_hours, 0)} · 메모리 GB·h ${N(t.mem_gb_hours, 0)} · 디스크 GB·h ${N(t.disk_gb_hours, 0)}</td>
        <td>${money(t.cpu_cost, cur)}</td><td>${money(t.mem_cost, cur)}</td><td>${money(t.disk_cost, cur)}</td><td><b>${money(t.cost, cur)}</b></td></tr>${ps}`;
    }).join("");
    const un = R.unassigned.filter(hit);
    const hdr = `<tr><th></th><th>테넌트 · 프로젝트</th><th>VM</th><th>클러스터</th><th>폴더</th><th>매칭</th><th>켜짐 h</th><th>vCPU</th><th>메모리 GB</th><th>디스크 GB</th><th>CPU%</th><th>MEM%</th><th>CPU</th><th>메모리</th><th>디스크</th><th>합계</th></tr>`;
    return per + kpi + (R.tenants.length ? `<div class="bl-wrap"><table class="vc-t bl-t2">${hdr}${rows}</table></div>` :
      `<div class="empty">테넌트가 없습니다 — '테넌트·프로젝트' 탭에서 테넌트와 프로젝트(클러스터·폴더·태그·VM 매칭)를 만드세요. 표본은 이미 쌓이고 있으므로 만든 즉시 지난 사용량도 정산됩니다.</div>`)
      + (un.length ? `<h4 class="bl-h">미할당 VM <small>${un.length}대 — 어느 프로젝트 조건에도 맞지 않음</small></h4><div class="bl-wrap"><table class="vc-t"><tr><th>VM</th><th>vCenter</th><th>클러스터</th><th>폴더</th><th>태그</th><th>켜짐 h</th><th>vCPU·h</th><th>메모리 GB·h</th><th>디스크 GB·h</th></tr>
        ${un.slice(0, 500).map(v => `<tr><td class="vc-ent">${esc(v.vm)}</td><td>${esc(v.vcenter)}</td><td>${esc(v.cluster || "")}</td><td>${esc(v.folder || "")}</td><td>${esc((v.tags || []).join(", "))}</td><td>${N(v.on_hours)}</td><td>${N(v.vcpu_hours)}</td><td>${N(v.mem_gb_hours)}</td><td>${N(v.disk_gb_hours)}</td></tr>`).join("")}</table></div>` : "")
      + `<p class="small muted bl-note">산정: VM 이 켜져 있던 5분 블록마다 (vCPU × vCPU 단가 + 메모리 GB × GB 단가 + 할당 디스크 GB × GB 단가) × 5/60 · 꺼진 블록은 과금하지 않음(요율표에서 디스크만 과금 선택 가능) · 사용률 가중 요율은 vCPU·메모리에 (최소 가중치 + (1 − 최소 가중치) × 사용률) 적용 · 매칭 우선순위 VM 이름 > 태그 > 폴더(긴 경로) > 클러스터</p>`;
  }

  // ---------------------------------------------------------------- 테넌트·프로젝트
  function tenants() {
    const C = st.cfg, rn = id => (C.rates.find(r => r.id === id) || {}).name || "기본 요율";
    const ed = C.can_edit;
    return `${ed ? `<div class="vc-ctl"><button class="btn-sm solid" id="bl-addt">테넌트 추가</button><button class="btn-sm" id="bl-addp" ${C.tenants.length ? "" : "disabled"}>프로젝트 추가</button>
        <span class="small muted">프로젝트는 클러스터·폴더(경로 접두)·태그(카테고리:태그 또는 태그)·VM 이름 중 하나라도 맞으면 포함(OR)</span></div>` : ""}
      ${C.tenants.length ? C.tenants.map(t => `<div class="bl-ten"><div class="bl-th"><b>${esc(t.name)}</b><small>${esc(t.note || "")} · 요율 ${esc(t.rate_id ? rn(t.rate_id) : "기본")}${(t.users || []).length ? ` · 테넌트 사용자 ${esc(t.users.join(", "))}` : ""}</small>
          ${ed ? `<span class="gap"></span><button class="btn-xs" data-et="${t.id}">수정</button><button class="btn-xs danger" data-dt="${t.id}">삭제</button>` : ""}</div>
        <table class="vc-t"><tr><th>프로젝트</th><th>요율</th><th>클러스터</th><th>폴더</th><th>태그</th><th>VM</th><th></th></tr>${t.projects.map(p => `<tr><td><b>${esc(p.name)}</b><br><small>${esc(p.note || "")}</small></td>
          <td>${esc(p.rate_id ? rn(p.rate_id) : "테넌트 요율")}</td><td>${p.clusters.map(esc).join("<br>")}</td><td>${p.folders.map(esc).join("<br>")}</td><td>${p.tags.map(esc).join("<br>")}</td><td>${p.vms.map(esc).join("<br>")}</td>
          <td>${ed ? `<button class="btn-xs" data-ep="${p.id}">수정</button><button class="btn-xs danger" data-dp="${p.id}">삭제</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">프로젝트 없음</td></tr>`}</table></div>`).join("")
        : `<div class="empty">테넌트가 없습니다.</div>`}`;
  }
  async function editTenant(t) {
    const C = st.cfg;
    const v = await A.modal({title: t ? `테넌트 수정 — ${t.name}` : "테넌트 추가", fields: [
      {id: "name", label: "이름", value: t?.name, required: true}, {id: "note", label: "설명", value: t?.note},
      {id: "rate_id", label: "요율표", type: "select", value: t?.rate_id || "", options: [["", "기본 요율표"], ...C.rates.map(r => [r.id, r.name])]},
      {id: "users", label: "테넌트 사용자(계정, 줄마다 1개)", type: "textarea", rows: 3, value: (t?.users || []).join("\n"), hint: "지정한 계정(관리자 제외)은 정산 화면에서 이 테넌트만 봅니다"}]});
    if (!v) return;
    try { await A.api(t ? "PUT" : "POST", t ? `/api/billing/tenants/${t.id}` : "/api/billing/tenants", v); A.ok("저장됨", v.name); load(); } catch (e) { A.fail("저장 실패", e); }
  }
  async function editProject(p) {
    const C = st.cfg, ch = C.choices || {};
    const dl = (id, list) => `<datalist id="${id}">${(list || []).slice(0, 2000).map(x => `<option value="${esc(x)}">`).join("")}</datalist>`;
    const v = await A.modal({title: p ? `프로젝트 수정 — ${p.name}` : "프로젝트 추가", wide: true,
      html: `${dl("bl-dl-c", ch.clusters)}${dl("bl-dl-f", ch.folders)}${dl("bl-dl-t", ch.tags)}<p class="small muted">한 줄에 하나씩. 폴더는 '데이터센터/폴더/하위폴더' 경로(하위 폴더 포함), 태그는 '카테고리:태그' 또는 태그 이름.
        아래 입력칸에서 고르면 줄이 추가됩니다.</p><div class="bl-pick"><input list="bl-dl-c" placeholder="클러스터 고르기" data-into="clusters"><input list="bl-dl-f" placeholder="폴더 고르기" data-into="folders"><input list="bl-dl-t" placeholder="태그 고르기" data-into="tags"></div>`,
      fields: [{id: "tenant_id", label: "테넌트", type: "select", value: p?.tenant_id || st.cfg.tenants[0]?.id, options: C.tenants.map(t => [t.id, t.name]), required: true},
        {id: "name", label: "이름", value: p?.name, required: true}, {id: "note", label: "설명", value: p?.note},
        {id: "rate_id", label: "요율표", type: "select", value: p?.rate_id || "", options: [["", "테넌트 요율표"], ...C.rates.map(r => [r.id, r.name])]},
        {id: "clusters", label: "클러스터", type: "textarea", rows: 2, value: (p?.clusters || []).join("\n")},
        {id: "folders", label: "VM 폴더(경로 접두)", type: "textarea", rows: 2, value: (p?.folders || []).join("\n")},
        {id: "tags", label: "태그", type: "textarea", rows: 2, value: (p?.tags || []).join("\n")},
        {id: "vms", label: "VM 이름(직접 지정)", type: "textarea", rows: 2, value: (p?.vms || []).join("\n")}],
      onOpen: m => m.addEventListener("change", e => { const k = e.target.dataset.into; if (!k || !e.target.value) return; const ta = m.querySelector(`#mf-${k}`);
        ta.value = [...new Set([...ta.value.split("\n").map(x => x.trim()).filter(Boolean), e.target.value])].join("\n"); e.target.value = ""; })});
    if (!v) return;
    v.tenant_id = Number(v.tenant_id);
    try { await A.api(p ? "PUT" : "POST", p ? `/api/billing/projects/${p.id}` : "/api/billing/projects", v); A.ok("저장됨", v.name); load(); } catch (e) { A.fail("저장 실패", e); }
  }

  // ---------------------------------------------------------------- 요율표
  function rates() {
    const C = st.cfg, ed = C.can_edit;
    return `${ed ? `<div class="vc-ctl"><button class="btn-sm solid" id="bl-addr">요율표 추가</button><span class="small muted">요율을 바꾸면 새 버전이 '적용 시작일'부터 쓰이고 그 전 사용량은 이전 단가로 계산됩니다</span></div>` : ""}
      ${C.rates.length ? `<table class="vc-t"><tr><th>요율표</th><th>통화</th><th>vCPU/시간</th><th>메모리 GB/시간</th><th>디스크 GB/시간</th><th>사용률 가중</th><th>꺼진 VM 디스크</th><th>버전</th><th></th></tr>
        ${C.rates.map(r => { const c = r.current || {}; return `<tr><td><b>${esc(r.name)}</b>${r.is_default ? ` <span class="vc-sev info">기본</span>` : ""}</td><td>${esc(r.currency)}</td><td>${c.vcpu_hour ?? "-"}</td><td>${c.mem_gb_hour ?? "-"}</td><td>${c.disk_gb_hour ?? "-"}</td>
          <td>${c.weighting ? `켜짐(최소 ${c.min_weight}%)` : "끔"}</td><td>${c.disk_when_off ? "과금" : "미과금"}</td>
          <td><details><summary>${r.versions.length}개</summary>${r.versions.map(x => `<div class="small">${x.effective_from ? new Date(x.effective_from * 1000).toLocaleDateString() : "처음부터"} — vCPU ${x.vcpu_hour} · GB ${x.mem_gb_hour} · 디스크 ${x.disk_gb_hour}${x.weighting ? ` · 가중 ${x.min_weight}%` : ""} <span class="muted">(${esc(x.user || "")})</span></div>`).join("")}</details></td>
          <td>${ed ? `<button class="btn-xs" data-er="${r.id}">단가 변경</button><button class="btn-xs danger" data-dr="${r.id}">삭제</button>` : ""}</td></tr>`; }).join("")}</table>`
        : `<div class="empty">요율표가 없습니다 — 단가를 정하면 보고서에 비용이 계산됩니다(요율 없이도 사용량은 집계).</div>`}`;
  }
  async function editRate(r) {
    const c = (r && r.current) || {};
    const today = new Date().toISOString().slice(0, 10);
    const v = await A.modal({title: r ? `단가 변경 — ${r.name}` : "요율표 추가", fields: [
      {id: "name", label: "이름", value: r?.name, required: true}, {id: "currency", label: "통화", value: r?.currency || st.cfg.currency || "KRW"},
      {id: "vcpu_hour", label: "vCPU 1개·1시간 단가", type: "number", step: "any", min: 0, value: c.vcpu_hour ?? "", required: true},
      {id: "mem_gb_hour", label: "메모리 1GB·1시간 단가", type: "number", step: "any", min: 0, value: c.mem_gb_hour ?? "", required: true},
      {id: "disk_gb_hour", label: "디스크 1GB·1시간 단가(할당 기준)", type: "number", step: "any", min: 0, value: c.disk_gb_hour ?? "", required: true},
      {id: "weighting", label: "사용률 가중(vCPU·메모리)", type: "checkbox", value: !!c.weighting},
      {id: "min_weight", label: "최소 가중치(%)", type: "number", min: 0, max: 100, value: c.min_weight ?? 30, hint: "가중치 = 최소 + (1 − 최소) × 사용률 — 유휴 VM 도 최소 비율만큼 과금"},
      {id: "disk_when_off", label: "꺼진 VM 의 디스크도 과금", type: "checkbox", value: !!c.disk_when_off},
      {id: "is_default", label: "기본 요율표로 사용", type: "checkbox", value: !!r?.is_default},
      ...(r ? [{id: "effective_from", label: "적용 시작일", type: "date", value: today, hint: "이 날짜 0시부터의 사용량에 새 단가 적용"}] : [])]});
    if (!v) return;
    try { await A.api(r ? "PUT" : "POST", r ? `/api/billing/rates/${r.id}` : "/api/billing/rates", v); A.ok("저장됨", v.name); load(); } catch (e) { A.fail("저장 실패", e); }
  }

  // ---------------------------------------------------------------- 이벤트
  function wire() {
    const b = $("#bl-body");
    b.addEventListener("click", async e => {
      const t = e.target;
      const bt = t.closest("[data-bt]"); if (bt) { st.tab = bt.dataset.bt; render(); return; }
      const sm = t.closest("[data-stmt]"); if (sm) { e.stopPropagation(); const mo = st.period === "month" ? (st.month || ym()) : ym(); window.open(`/api/billing/statement?tenant=${sm.dataset.stmt}&period=month&month=${mo}`, "_blank", "noopener"); return; }
      const tr = t.closest("[data-bten]"); if (tr) { const id = Number(tr.dataset.bten); st.openT.has(id) ? st.openT.delete(id) : st.openT.add(id); render(); return; }
      const pr = t.closest("[data-bp]"); if (pr) { const id = Number(pr.dataset.bp); st.openP.has(id) ? st.openP.delete(id) : st.openP.add(id); render(); return; }
      if (t.id === "bl-csv") { location.href = `/api/billing/report.csv?${qs()}`; return; }
      if (t.id === "bl-apply") { st.start = $("#bl-start").value; st.end = $("#bl-end").value; reload(); return; }
      if (t.id === "bl-sample") { try { const r = await A.api("POST", "/api/billing/sample"); A.ok("표본", r.sampled ? `VM ${r.sampled}대 기록` : "이번 5분 블록은 이미 기록됨"); reload(); } catch (er) { A.fail("표본 실패", er); } return; }
      if (t.id === "bl-addt") return editTenant(null);
      if (t.id === "bl-addp") return editProject(null);
      if (t.id === "bl-addr") return editRate(null);
      const all = st.cfg.tenants, P = all.flatMap(x => x.projects);
      if (t.dataset.et) return editTenant(all.find(x => x.id === Number(t.dataset.et)));
      if (t.dataset.ep) return editProject(P.find(x => x.id === Number(t.dataset.ep)));
      if (t.dataset.er) return editRate(st.cfg.rates.find(x => x.id === Number(t.dataset.er)));
      for (const [k, url, what] of [["dt", "tenants", "테넌트(프로젝트 포함)"], ["dp", "projects", "프로젝트"], ["dr", "rates", "요율표"]]) {
        if (t.dataset[k]) { if (!await A.confirm(`${what} 삭제`, "삭제하면 되돌릴 수 없습니다. 사용량 표본은 남고 보고서에서는 미할당으로 보입니다.", true)) return;
          try { await A.api("DELETE", `/api/billing/${url}/${t.dataset[k]}`); A.ok("삭제됨", ""); load(); } catch (er) { A.fail("삭제 실패", er); } return; }
      }
    });
    b.addEventListener("change", e => {
      const id = e.target.id;
      if (id === "bl-per") { st.period = e.target.value; if (st.period !== "custom") reload(); else render(); }
      if (id === "bl-month") { st.month = e.target.value; reload(); }
      if (id === "bl-ten") { st.tenant = Number(e.target.value); reload(); }
    });
    let tm;
    b.addEventListener("input", e => { if (e.target.id !== "bl-q") return; clearTimeout(tm); const pos = e.target.selectionStart;
      tm = setTimeout(() => { st.q = e.target.value; if (st.q) st.rep.tenants.forEach(t => { st.openT.add(t.id); t.projects.forEach(p => st.openP.add(p.id)); }); render(); const el = $("#bl-q"); if (el) { el.focus(); el.setSelectionRange(pos, pos); } }, 250); });
    $("#bl-reload").onclick = load;
  }
  async function reload() {
    try { st.rep = await A.api("GET", `/api/billing/report?${qs()}`); } catch (e) { A.fail("보고서", e); return; }
    render();
  }
  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-bill")) return;
    wire();
    $("#nav-bill").onclick = () => { open("drawer-bill"); load(); };
  });
  window.AIOPS_BILL = {load};
})();
