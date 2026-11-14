/* 수명 주기 점검(2.36.0) — 점검·진단 › 수명 주기 점검
   · 인증서 달력: VKS(API 서버·컨트롤 플레인·kubelet·cert-manager·커넥터 토큰) 먼저, vCenter·ESXi·NSX·각 커넥터 TLS — 월별 달력 + 목록 + .ics 내보내기
   · 구성 드리프트: 저장한 기준선과 지금 차이 + 같은 클러스터 호스트끼리(다수와 다른 호스트)
   · 버전 수명: 구성요소 버전 ↔ 일반 지원 종료일(EoGS)·다음 줄, 수명 표(출처·확인 여부) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {tab: "cert", c: null, d: null, v: null, err: "", vc: "", bl: 0, src: "", band: "", month: null, q: "", busy: false};
  const N = (v, d = 0) => v == null ? "—" : Number(v).toLocaleString(undefined, {maximumFractionDigits: d});
  const day = ts => ts ? new Date(ts * 1000).toLocaleDateString() : "—";
  const BAND = {expired: ["만료됨", "bad"], crit: ["위험", "bad"], warn: ["주의", "warn"], ok: ["정상", "ok"], none: ["만료 없음", ""], auto: ["자동 갱신", ""]};
  const SRC = {vks: "VKS", vcenter: "vCenter", esxi: "ESXi", nsx: "NSX", sddc: "SDDC Manager", avi: "Avi", vcfops: "VCF Operations", vcflogs: "VCF Logs", vcfa: "VCF Automation",
               srm: "SRM", redfish: "BMC", ucsm: "UCS", fortigate: "FortiGate", manual: "직접 등록"};
  const left = x => x.band === "auto" ? "자동" : x.days_left == null ? "—" : x.days_left < 0 ? `${-x.days_left}일 지남` : `${x.days_left}일`;

  // ------------------------------------------------------------ 인증서
  function certs() {
    const c = st.c; if (!c) return `<div class="empty">불러오는 중…</div>`;
    const s = c.summary || {}, items = c.items || [];
    const srcs = [...new Set(items.map(x => x.source))].sort((a, b) => (a === "vks" ? -1 : b === "vks" ? 1 : a.localeCompare(b)));
    const q = st.q.toLowerCase();
    const list = items.filter(x => (!st.src || x.source === st.src) && (!st.band || x.band === st.band)
      && (!q || `${x.system} ${x.cluster} ${x.kind} ${x.name} ${x.subject}`.toLowerCase().includes(q)));
    const tile = (b, n) => `<button type="button" class="lf-tile ${BAND[b][1]} ${st.band === b ? "on" : ""}" data-lfband="${b}"><b>${N(n)}</b><span>${BAND[b][0]}</span></button>`;
    return `<div class="lf-tiles">${["expired", "crit", "warn", "ok"].map(b => tile(b, s[b] || 0)).join("")}
        <div class="lf-meta small muted">마지막 스캔 ${c.ts ? new Date(c.ts * 1000).toLocaleString() : "—"} · 주의 ${c.settings ? c.settings.warn_days : 60}일 · 위험 ${c.settings ? c.settings.crit_days : 14}일 전
          <div class="lf-acts">${A.can("operate") ? `<button class="btn-sm" id="lf-scan" ${st.busy ? "disabled" : ""}>${st.busy ? "스캔 중…" : "지금 스캔"}</button>` : ""}
          <a class="btn-sm" href="/api/lifecycle/certs.ics" download>달력(.ics)</a><a class="btn-sm" href="/api/lifecycle/certs.csv" download>CSV</a>${A.can("settings") ? `<button class="btn-sm" id="lf-set">기준·주소 설정</button>` : ""}</div></div></div>
      ${vksPanel(items)}
      ${calendar(items)}
      <div class="lf-filter"><select id="lf-src"><option value="">전체 출처</option>${srcs.map(x => `<option value="${esc(x)}" ${st.src === x ? "selected" : ""}>${esc(SRC[x] || x)}</option>`).join("")}</select>
        <input id="lf-q" value="${esc(st.q)}" placeholder="찾기(시스템·클러스터·이름)">${st.band ? `<button class="btn-sm" data-lfband="">'${BAND[st.band][0]}' 거르기 풀기</button>` : ""}<span class="small muted">${list.length}개</span></div>
      <div style="overflow-x:auto"><table class="dr-t lf-t"><thead><tr><th>만료일</th><th class="r">남은 기간</th><th>출처</th><th>종류</th><th>대상</th><th>주체 · 발급자</th><th>갱신 방법</th></tr></thead><tbody>
      ${list.slice(0, 1000).map(x => `<tr class="${BAND[x.band][1]}"><td class="nw">${day(x.not_after)}<div><span class="dr-v ${BAND[x.band][1] || "ok"}">${BAND[x.band][0]}</span></div></td>
        <td class="r nw"><b>${left(x)}</b></td><td>${esc(SRC[x.source] || x.source)}<div class="small muted">${esc(x.system)}</div></td>
        <td>${esc(x.kind)}${x.ready === "False" ? ` <span class="dr-v bad" title="cert-manager Ready=False — 갱신 실패 가능">Ready 아님</span>` : ""}${x.auto_renew_days ? ` <span class="dr-v ok">자동 갱신 ${x.auto_renew_days}일 전</span>` : ""}</td>
        <td class="mono small">${esc(x.name)}${x.cluster ? `<div class="muted">${esc(x.cluster)}</div>` : ""}</td>
        <td class="small">${esc(x.subject || "")}${x.issuer ? `<div class="muted">발급: ${esc(x.issuer)}${x.self_signed ? " (자체 서명)" : ""}</div>` : ""}${x.note ? `<div class="muted">${esc(x.note)}</div>` : ""}</td>
        <td class="small muted">${esc(x.renew || "")}${x.cmd ? `<details class="lf-cmd"><summary>확인·갱신 명령</summary><pre>${esc(x.cmd)}</pre><button type="button" class="btn-sm" data-lfcopy="${esc(x.cmd)}">복사</button></details>` : ""}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">해당하는 인증서가 없습니다.</td></tr>`}</tbody></table></div>
      ${(c.errors || []).length || (c.skipped || []).length ? `<details class="lf-err"><summary>읽지 못한 곳 ${(c.errors || []).length} · 건너뛴 곳 ${(c.skipped || []).length}</summary>
        <ul>${(c.errors || []).map(x => `<li>${esc(x)}</li>`).join("")}${(c.skipped || []).map(x => `<li class="muted">${esc(x)}</li>`).join("")}</ul></details>` : ""}
      <p class="small muted">모두 공개 인증서만 읽습니다(TLS 핸드셰이크·Kubernetes CSR·cert-manager 상태·Cluster API 상태) — 시크릿·개인 키는 읽지 않습니다. 단계가 바뀌면 이상징후로 알립니다.</p>`;
  }

  function vksPanel(items) {
    const v = items.filter(x => x.source === "vks");
    if (!v.length) return `<div class="lf-vks"><h5>VKS 인증서</h5><p class="small muted">VKS 커넥터가 없거나 아직 스캔 전입니다. 워크로드 클러스터와 Supervisor 커넥터를 등록하면 API 서버·컨트롤 플레인(kubeadm 1년)·kubelet·cert-manager 인증서 만료를 봅니다.</p></div>`;
    const by = {};
    v.forEach(x => { (by[x.cluster || x.system] = by[x.cluster || x.system] || []).push(x); });
    const worst = xs => xs.filter(x => x.not_after && x.band !== "auto").sort((a, b) => a.not_after - b.not_after)[0];
    return `<div class="lf-vks"><h5>VKS 클러스터별 가장 먼저 만료되는 인증서</h5><div class="lf-cards">${Object.entries(by).sort((a, b) => ((worst(a[1]) || {}).not_after || 9e12) - ((worst(b[1]) || {}).not_after || 9e12)).map(([cl, xs]) => {
      const w = worst(xs), cp = xs.find(x => x.kind === "컨트롤 플레인(kubeadm)");
      return `<div class="lf-card ${w ? BAND[w.band][1] : ""}"><b>${esc(cl)}</b>
        ${w ? `<div class="lf-big">${left(w)}</div><div class="small">${esc(w.kind)} · ${esc(w.name)}</div><div class="small muted">${day(w.not_after)}</div>` : `<div class="small muted">만료일 정보 없음</div>`}
        ${cp ? `<div class="small ${cp.auto_renew_days ? "" : "warn"}">컨트롤 플레인 ${left(cp)} — ${esc(cp.note || "")}</div>` : ""}
        <div class="small muted">${xs.length}개 — ${[...new Set(xs.map(x => x.kind))].map(esc).join(" · ")}</div></div>`; }).join("")}</div>
      <p class="small muted">kubeadm 이 만든 컨트롤 플레인 인증서는 1년이 기본입니다. Supervisor 의 KubeadmControlPlane 에 rolloutBefore.certificatesExpiryDays 를 두면 만료 전에 컨트롤 플레인을 다시 만들어 자동 갱신합니다.</p></div>`;
  }

  function calendar(items) {
    const now = new Date(), base = st.month || new Date(now.getFullYear(), now.getMonth(), 1);
    const months = [0, 1, 2].map(k => new Date(base.getFullYear(), base.getMonth() + k, 1));
    const byDay = {};
    items.forEach(x => { if (!x.not_after || x.band === "auto") return; const d = new Date(x.not_after * 1000); const k = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; (byDay[k] = byDay[k] || []).push(x); });
    const one = m => {
      const first = new Date(m.getFullYear(), m.getMonth(), 1).getDay(), dim = new Date(m.getFullYear(), m.getMonth() + 1, 0).getDate();
      let cells = "";
      for (let i = 0; i < first; i++) cells += `<span></span>`;
      for (let d = 1; d <= dim; d++) {
        const xs = byDay[`${m.getFullYear()}-${m.getMonth()}-${d}`] || [];
        const lvl = xs.some(x => ["expired", "crit"].includes(x.band)) ? "bad" : xs.some(x => x.band === "warn") ? "warn" : xs.length ? "ok" : "";
        const today = m.getFullYear() === now.getFullYear() && m.getMonth() === now.getMonth() && d === now.getDate();
        cells += `<span class="${lvl}${today ? " today" : ""}" ${xs.length ? `title="${esc(xs.map(x => `${x.kind} ${x.name} (${x.system})`).join("\n"))}"` : ""}>${d}${xs.length ? `<i>${xs.length}</i>` : ""}</span>`;
      }
      return `<div class="lf-month"><b>${m.getFullYear()}년 ${m.getMonth() + 1}월</b><div class="lf-dow">${"일월화수목금토".split("").map(x => `<span>${x}</span>`).join("")}</div><div class="lf-days">${cells}</div></div>`;
    };
    return `<div class="lf-cal"><div class="lf-calnav"><button class="btn-sm" data-lfmon="-3" aria-label="이전 석 달">◀</button><button class="btn-sm" data-lfmon="0">이번 달</button><button class="btn-sm" data-lfmon="3" aria-label="다음 석 달">▶</button>
      <span class="small muted">날짜에 마우스를 올리면 그날 만료되는 인증서</span></div><div class="lf-months">${months.map(one).join("")}</div></div>`;
  }

  // ------------------------------------------------------------ 구성 드리프트
  function drift() {
    const d = st.d; if (!d) return `<div class="empty">불러오는 중…</div>`;
    const sev = x => x === "warning" ? "warn" : "";
    const can = A.can("operate");
    return `<div class="lf-filter"><label class="small">vCenter <select id="lf-vc">${(d.vcenters || []).map(x => `<option ${x === d.vcenter ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>
        <label class="small">기준선 <select id="lf-bl"><option value="0">가장 최근 기준선</option>${(d.baselines || []).map(b => `<option value="${b.id}" ${+st.bl === b.id ? "selected" : ""}>${esc(b.name)} — ${new Date(b.created * 1000).toLocaleString()}</option>`).join("")}</select></label>
        ${can ? `<button class="btn-sm solid" id="lf-mkbl">지금 구성을 기준선으로</button>` : ""}${can && d.baseline ? ` <button class="btn-sm danger" id="lf-rmbl" data-id="${d.baseline.id}">이 기준선 삭제</button>` : ""}
        <span class="small muted">호스트 ${d.hosts || 0} · 클러스터 ${d.clusters || 0} · 점검 ${d.updated ? new Date(d.updated * 1000).toLocaleString() : "—"}</span></div>
      ${d.error ? `<div class="empty">${esc(d.error)}</div>` : ""}
      <div class="wi-box"><h5>기준선과 달라진 곳 ${d.baseline ? `<small class="muted">기준선 '${esc(d.baseline.name)}' (${new Date(d.baseline.created * 1000).toLocaleString()}, ${esc(d.baseline.by || "")})</small>` : ""}</h5>
        ${!d.baseline ? `<p class="small muted">저장한 기준선이 없습니다 — 구축·점검이 끝난 '좋은 상태'에서 '지금 구성을 기준선으로'를 누르면 이후 바뀐 설정을 계속 보여 줍니다.</p>`
          : !(d.diff || []).length ? `<p class="small">기준선 이후 바뀐 설정이 없습니다.</p>`
          : `<div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>대상</th><th>항목</th><th>기준선</th><th>지금</th></tr></thead><tbody>${d.diff.slice(0, 800).map(x => `<tr class="${sev(x.severity)}">
            <td>${esc(x.entity)}<div class="small muted">${esc(x.scope)}${x.cluster && x.cluster !== x.entity ? ` · ${esc(x.cluster)}` : ""}</div></td><td>${esc(x.label)}</td><td class="mono small">${esc(x.baseline)}</td><td class="mono small"><b>${esc(x.current)}</b></td></tr>`).join("")}</tbody></table></div>`}</div>
      <div class="wi-box"><h5>같은 클러스터 안에서 다른 호스트 <small class="muted">다수(최빈값)와 다른 설정 — 기준선 없이도 보입니다(BIOS 는 제외)</small></h5>
        ${!(d.peers || []).length ? `<p class="small">클러스터 안 호스트 설정이 모두 같습니다.</p>` : `<div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>클러스터</th><th>항목</th><th>다수 값</th><th>다른 호스트</th></tr></thead><tbody>${d.peers.slice(0, 800).map(x => `<tr class="${sev(x.severity)}">
          <td>${esc(x.cluster)}</td><td>${esc(x.label)}</td><td class="mono small">${esc(x.majority)}${x.majority_n ? ` <span class="muted">(${x.majority_n}대)</span>` : ""}</td>
          <td class="small">${Object.entries(x.values).map(([h, v]) => `<div><b>${esc(h)}</b> <span class="mono">${esc(v)}</span></div>`).join("")}</td></tr>`).join("")}</tbody></table></div>`}</div>
      ${history()}
      <p class="small muted">재료는 인프라 점검 스냅숏(읽기 전용)입니다 — ESXi 빌드·BIOS·NTP·SSH·잠금 모드·하이퍼스레딩·전원 정책·NIC/HBA 드라이버·펌웨어·링크 속도·vSwitch/VMkernel MTU·서비스, 클러스터 HA·DRS·EVC·vSAN. 보안 항목의 직전 점검 대비 변경은 '보안 판독 › 구성 변경'에 있습니다.</p>`;
  }

  function history() {
    const h = st.h; if (!h) return "";
    const days = Object.entries(h.by_day || {}).sort();
    const mx = Math.max(1, ...days.map(([, n]) => n));
    const sev = x => x === "warning" ? "warn" : "";
    return `<div class="wi-box"><h5>변경 이력 <small class="muted">최근 ${h.days}일 · 인프라 점검마다 직전 구성과 비교해 쌓습니다(180일 보관) · ${h.changes.length}건</small></h5>
      ${days.length ? `<div class="lf-spark" title="날짜별 변경 건수">${days.map(([d, n]) => `<i style="height:${Math.max(8, n / mx * 100)}%" title="${esc(d)} · ${n}건"></i>`).join("")}</div>` : ""}
      ${!h.changes.length ? `<p class="small muted">기록된 변경이 없습니다 — 업데이트 뒤 첫 점검부터 쌓입니다.</p>` : `<div style="overflow-x:auto;max-height:420px"><table class="dr-t"><thead><tr><th>시각</th><th>대상</th><th>항목</th><th>이전</th><th>이후</th></tr></thead><tbody>
        ${h.changes.slice(0, 500).map(x => `<tr class="${sev(x.severity)}"><td class="nw">${new Date(x.ts * 1000).toLocaleString()}</td><td>${esc(x.entity)}<div class="small muted">${esc(x.scope)}${x.cluster && x.cluster !== x.entity ? ` · ${esc(x.cluster)}` : ""}</div></td>
          <td>${esc(x.label)}</td><td class="mono small">${esc(x.before)}</td><td class="mono small"><b>${esc(x.after)}</b></td></tr>`).join("")}</tbody></table></div>`}</div>`;
  }

  // ------------------------------------------------------------ 버전 수명
  function versions() {
    const v = st.v; if (!v) return `<div class="empty">불러오는 중…</div>`;
    const S = {ended: ["지원 종료", "bad"], soon: ["1년 안에 종료", "warn"], ok: ["지원 중", "ok"], unknown: ["수명 표에 없음", ""]};
    const P = (v.table || {}).products || {};
    const s = v.summary || {};
    return `<div class="lf-tiles">${["ended", "soon", "ok", "unknown"].map(k => `<div class="lf-tile ${S[k][1]}"><b>${N(s[k] || 0)}</b><span>${S[k][0]}</span></div>`).join("")}
        <div class="lf-meta small muted">수명 표 ${esc((v.table || {}).updated || "")}${(v.table || {}).custom ? " (직접 올린 표)" : " (기본 표)"}
          <div class="lf-acts">${A.can("settings") ? `<button class="btn-sm" id="lf-tbl">수명 표 바꾸기</button>${(v.table || {}).custom ? ` <button class="btn-sm" id="lf-tblreset">기본 표로</button>` : ""}` : ""}</div></div></div>
      <div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>구성요소</th><th>범위</th><th>버전</th><th>지원 종료(EoGS)</th><th class="r">남은 기간</th><th>다음 대상</th><th>출처</th></tr></thead><tbody>
      ${(v.rows || []).map(r => `<tr class="${S[r.state][1]}"><td><b>${esc(P[r.product] || r.product)}</b><div class="small muted">${esc(r.system)}</div></td>
        <td class="small">${esc(r.scope || "")}${r.count > 1 ? ` <span class="muted">· ${r.count}대</span>` : ""}</td>
        <td class="mono small">${esc(r.version)}${r.build && r.build !== r.version ? `<div class="muted">${esc(r.build)}</div>` : ""}</td>
        <td>${r.eogs ? esc(r.eogs) : "—"}${r.eotg ? `<div class="small muted">기술 안내 종료 ${esc(r.eotg)}</div>` : ""}<div><span class="dr-v ${S[r.state][1] || "na"}">${S[r.state][0]}</span></div></td>
        <td class="r nw"><b>${r.days_left == null ? "—" : r.days_left < 0 ? `${-r.days_left}일 지남` : `${N(r.days_left)}일`}</b></td>
        <td class="small">${r.next ? `${esc(r.next.line)} <span class="muted">(~${esc(r.next.eogs)}${r.next.verified === false ? ", 미확인" : ""})</span>` : "—"}${r.latest ? `<div class="muted">최신 ${esc(r.latest.line)} (~${esc(r.latest.eogs)})</div>` : ""}</td>
        <td class="small muted">${esc(r.src || "")}${r.verified === false ? ` <span class="dr-v warn">2차 출처</span>` : ""}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">수집한 버전이 없습니다.</td></tr>`}</tbody></table></div>
      ${(v.table || {}).order ? `<div class="wi-box"><h5>업그레이드 순서</h5><ol class="lf-order">${v.table.order.map(x => `<li>${esc(x)}</li>`).join("")}</ol><p class="small muted">${esc(v.table.order_note || "")}</p></div>` : ""}
      ${(v.errors || []).length ? `<details class="lf-err"><summary>버전을 읽지 못한 곳 ${v.errors.length}</summary><ul>${v.errors.map(x => `<li>${esc(x)}</li>`).join("")}</ul></details>` : ""}
      <p class="small muted">${esc((v.table || {}).note || "")} 다음 대상 = 같은 제품에서 지원 종료가 더 늦은 가장 가까운 줄. 실제 경로와 버전 조합은 Broadcom Interoperability Matrix·업그레이드 문서로 확인하세요.</p>`;
  }

  // ------------------------------------------------------------ 그리기·불러오기
  function draw() {
    const b = $("#life-body"); if (!b) return;
    const s = (st.c || {}).summary || {};
    b.innerHTML = `<div class="vc-tabs" role="tablist">${[["cert", `인증서 달력 <small>${(s.expired || 0) + (s.crit || 0) || ""}</small>`], ["drift", `구성 드리프트 <small>${st.d ? ((st.d.diff || []).length + (st.d.peers || []).length) || "" : ""}</small>`], ["ver", `버전 수명 <small>${st.v ? (st.v.summary.ended || 0) + (st.v.summary.soon || 0) || "" : ""}</small>`]]
      .map(([k, l]) => `<button role="tab" aria-selected="${st.tab === k}" data-lftab="${k}" class="${st.tab === k ? "on" : ""}">${l}</button>`).join("")}</div>
      ${st.err ? `<div class="empty">${esc(st.err)}</div>` : st.tab === "cert" ? certs() : st.tab === "drift" ? drift() : versions()}`;
  }
  async function load(force) {
    st.err = "";
    try {
      if (st.tab === "cert" && (!st.c || force)) st.c = await A.api("GET", "/api/lifecycle/certs", undefined, {background: true});
      if (st.tab === "drift" && (!st.d || force)) {
        st.d = await A.api("GET", `/api/lifecycle/drift?vcenter=${encodeURIComponent(st.vc)}&baseline=${+st.bl || 0}`, undefined, {background: true});
        try { st.h = await A.api("GET", `/api/lifecycle/drift/history?vcenter=${encodeURIComponent(st.d.vcenter || "")}&days=30`, undefined, {background: true}); } catch { st.h = null; }
      }
      if (st.tab === "ver" && (!st.v || force)) st.v = await A.api("GET", "/api/lifecycle/versions", undefined, {background: true});
    } catch (e) { st.err = String(e.message || e); }
    draw(); badge();
  }
  function badge() {
    const b = $("#life-badge"), s = (st.c || {}).summary; if (!b || !s) return;
    const n = (s.expired || 0) + (s.crit || 0);
    b.hidden = !n; b.textContent = n || "";
    b.title = n ? `만료됐거나 ${(st.c.settings || {}).crit_days || 14}일 안에 만료되는 인증서 ${n}개` : "";
  }

  function wire() {
    const b = $("#life-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const t = e.target.closest("button,[data-lfband]") || e.target;
      try {
        if (t.dataset.lfcopy !== undefined) { try { await navigator.clipboard.writeText(t.dataset.lfcopy); A.ok("복사했습니다", ""); } catch { A.fail("복사", "브라우저가 복사를 막았습니다 — 직접 선택해 복사하세요"); } return; }
        if (t.dataset.lftab) { st.tab = t.dataset.lftab; draw(); await load(); return; }
        if (t.dataset.lfband !== undefined) { st.band = st.band === t.dataset.lfband ? "" : t.dataset.lfband; draw(); return; }
        if (t.dataset.lfmon !== undefined) { const k = +t.dataset.lfmon, now = new Date(), cur = st.month || new Date(now.getFullYear(), now.getMonth(), 1);
          st.month = k ? new Date(cur.getFullYear(), cur.getMonth() + k, 1) : null; draw(); return; }
        if (t.id === "lf-scan") { st.busy = true; draw(); try { st.c = await A.api("POST", "/api/lifecycle/certs/scan"); A.ok("인증서 스캔", `${st.c.items.length}개`); } finally { st.busy = false; draw(); badge(); } return; }
        if (t.id === "lf-set") {
          const cur = (st.c || {}).settings || {};
          const v = await A.modal({title: "인증서 경고 기준·직접 등록 주소", fields: [
            {id: "warn_days", label: "주의(일 전)", type: "number", value: cur.warn_days ?? 60, min: 1, max: 3650},
            {id: "crit_days", label: "위험(일 전)", type: "number", value: cur.crit_days ?? 14, min: 1, max: 3650},
            {id: "interval_h", label: "자동 스캔 주기(시간)", type: "number", value: cur.interval_h ?? 12, min: 1, max: 720},
            {id: "kubelet_probe", label: "VKS 노드 kubelet(10250) 인증서도 확인", type: "checkbox", value: cur.kubelet_probe !== false},
            {id: "extra", label: "직접 등록할 TLS 주소(한 줄에 하나, host:port)", type: "textarea", value: (cur.extra || []).join("\n"), placeholder: "backup.bank.local:443\nharbor.bank.local:443"}], ok: "저장"});
          if (!v) return;
          await A.api("PUT", "/api/lifecycle/certs/settings", {...v, extra: String(v.extra || "").split(/\s+/).filter(Boolean)}); A.ok("저장했습니다", "다음 스캔부터 적용 — '지금 스캔'으로 바로 확인"); return;
        }
        if (t.id === "lf-mkbl") {
          const v = await A.modal({title: "지금 구성을 기준선으로", html: `<p class="modal-text">지금 인프라 점검 스냅숏을 '좋은 상태'로 저장합니다. 이후 달라진 설정이 드리프트로 표시됩니다.</p>`,
            fields: [{id: "name", label: "이름", placeholder: "예: 2026-11 정기 점검 완료"}], ok: "저장"});
          if (!v) return;
          const o = await A.api("POST", "/api/lifecycle/drift/baseline", {vcenter: (st.d || {}).vcenter || st.vc, name: v.name}); A.ok("기준선 저장", o.name); st.bl = o.id; await load(true); return;
        }
        if (t.id === "lf-rmbl") { if (!await A.confirm("기준선 삭제", "이 기준선을 지웁니다.", true)) return; await A.api("DELETE", `/api/lifecycle/drift/baseline/${t.dataset.id}`); st.bl = 0; await load(true); return; }
        if (t.id === "lf-tbl") {
          const v = await A.modal({title: "수명 표 바꾸기(JSON)", wide: true, html: `<p class="modal-text">Broadcom Product Lifecycle 포털에서 확인한 날짜로 표를 고칩니다. 형식: {"entries":[{"product":"esxi","line":"8","eogs":"2027-10-11","src":"…","verified":true}, …]} — product 는 esxi·vcenter·vsan·nsx·vcf·aria·hcx·vlr·k8s·avi.</p>`,
            fields: [{id: "j", label: "JSON", type: "textarea", rows: 12, value: JSON.stringify({entries: (st.v || {}).entries || []}, null, 1)}], ok: "저장"});
          if (!v) return;
          let j; try { j = JSON.parse(v.j); } catch { A.fail("수명 표", "JSON 형식이 아닙니다"); return; }
          const o = await A.api("PUT", "/api/lifecycle/versions/table", j); A.ok("수명 표 저장", `${o.entries}개 항목`); await load(true); return;
        }
        if (t.id === "lf-tblreset") { if (!await A.confirm("기본 표로", "직접 올린 수명 표를 지우고 기본 표로 되돌립니다.", true)) return; await A.api("DELETE", "/api/lifecycle/versions/table"); await load(true); return; }
      } catch (err) { A.fail("실패", err); }
    });
    b.addEventListener("change", e => {
      const t = e.target;
      if (t.id === "lf-src") { st.src = t.value; draw(); }
      if (t.id === "lf-vc") { st.vc = t.value; st.bl = 0; load(true); }
      if (t.id === "lf-bl") { st.bl = +t.value; load(true); }
    });
    b.addEventListener("input", e => {
      if (e.target.id !== "lf-q") return;
      st.q = e.target.value; clearTimeout(st._t);
      st._t = setTimeout(() => { draw(); const q = $("#lf-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 250);
    });
  }

  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-life") d.hidden = true; });
    $("#drawer-life").hidden = false;
    wire(); draw(); await load(true);
  }
  const nav = document.getElementById("nav-life"); if (nav) nav.onclick = show;
  const rl = document.getElementById("life-reload"); if (rl) rl.onclick = () => load(true);
  window.AIOPS_LIFECYCLE = show;
  // 메뉴 배지(만료·위험 인증서 수) — 화면을 열지 않아도 로그인 뒤 한 번
  if (A.ready) A.ready.then(me => { if (me === null) return; setTimeout(() => A.api("GET", "/api/lifecycle/certs?scan=0", undefined, {background: true}).then(c => { if (c && c.ts) { st.c = st.c || c; badge(); } }).catch(() => {}), 4000); });
})();
