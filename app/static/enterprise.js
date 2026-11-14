/* 엔터프라이즈 화면 — 인시던트·AI 근본원인·조치 승인 / 운영 설정 / 사용자·토큰 / 감사로그 / 리포트·백업 */
(() => {
  "use strict";
  const A = window.AIOPS;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = A.esc;
  const p2 = n => String(n).padStart(2, "0");
  const fmtDT = ts => { if (!ts) return "-"; const d = new Date(ts * 1000); return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`; };
  const fmtS = ts => { if (!ts) return "-"; const d = new Date(ts * 1000); return `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.max(0, Math.round(s))}초 전` : s < 3600 ? `${Math.floor(s / 60)}분 전` : s < 86400 ? `${Math.floor(s / 3600)}시간 전` : `${Math.floor(s / 86400)}일 전`; };
  const dur = sec => sec == null ? "-" : sec < 3600 ? `${Math.round(sec / 60)}분` : `${(sec / 3600).toFixed(1)}시간`;
  const sevLab = s => `<span class="label solid ${esc(s)}">${esc(s)}</span>`;
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const isOpen = id => !$(`#${id}`).hidden;
  const jsonPretty = v => esc(JSON.stringify(v, null, 2));
  const SEVS = ["critical", "error", "warning", "info"];
  const ROLE_LABEL = {viewer: "조회자", auditor: "감사자", operator: "운영자", admin: "관리자"};

  // ================================================================ 사용자 메뉴
  $("#btn-user").onclick = e => { e.stopPropagation(); const p = $("#user-pop"); p.hidden = !p.hidden;
    if (!p.hidden && A.me) $("#user-info").innerHTML = `<b>${esc(A.me.display || A.me.user)}</b> <span class="label">${esc(A.me.role_label || A.me.role)}</span>
      <div>계정 ${esc(A.me.user)} · ${A.me.source === "ldap" ? "AD/LDAP" : A.me.source === "oidc" ? "SSO" : "로컬"}${A.me.mfa_enabled ? ` · MFA ${A.me.mfa_enrolled ? "등록됨" : "미등록"}` : ""}</div>
      <div>직전 로그인 ${A.me.prev_login ? fmtDT(A.me.prev_login) + " · " + esc(A.me.prev_ip || "") : "-"}</div>
      <div>유휴 ${A.me.idle_minutes}분 후 자동 로그아웃</div>`; };
  document.addEventListener("click", e => { if (!e.target.closest(".user-menu")) $("#user-pop").hidden = true; });
  $("#user-pop").addEventListener("click", async e => {
    const b = e.target.closest("[data-um]"); if (!b) return;
    $("#user-pop").hidden = true;
    if (b.dataset.um === "logout") A.logout();
    if (b.dataset.um === "mfa") enrollMfa();
    if (b.dataset.um === "sess") {
      let list; try { list = await A.api("GET", "/api/auth/sessions"); } catch (err) { A.fail("조회 실패", err); return; }
      const v = await A.modal({title: "내 접속 세션", wide: true, html: `<table class="vc-t"><thead><tr><th>IP</th><th>브라우저</th><th>로그인</th><th>방식</th><th>유휴</th><th></th></tr></thead><tbody>${list.map(x => `<tr><td class="mono">${esc(x.ip)}</td><td class="small">${esc(x.ua)}</td><td>${fmtDT(x.since)}</td><td>${esc(x.method)}</td><td>${Math.floor(x.idle_sec / 60)}분</td><td>${x.current ? '<span class="label ok">현재</span>' : ""}</td></tr>`).join("")}</tbody></table><p class="modal-text">다른 기기·브라우저에서 열린 세션을 모두 종료할 수 있습니다(현재 세션은 유지).</p>`, ok: list.length > 1 ? "다른 세션 모두 종료" : "", cancel: "닫기"});
      if (!v) return;
      try { const r = await A.api("POST", "/api/auth/sessions/revoke", {others: true}); A.ok("세션 종료", `${r.revoked}개`); } catch (err) { A.fail("종료 실패", err); }
    }
    if (b.dataset.um === "pw") {
      if (A.me && A.me.source === "ldap") { A.toast("AD/LDAP 계정", "비밀번호는 사내 디렉터리(AD)에서 변경하세요.", "info"); return; }
      const v = await A.modal({title: "비밀번호 변경", fields: [
        {id: "old", label: "현재 비밀번호", type: "password", required: true},
        {id: "n1", label: "새 비밀번호", type: "password", required: true, hint: "9자 이상 · 대/소문자·숫자·특수문자 중 3종 · 아이디·연속/반복 문자 금지 · 최근 3개 재사용 금지"},
        {id: "n2", label: "새 비밀번호 확인", type: "password", required: true}], ok: "변경"});
      if (!v) return;
      if (v.n1 !== v.n2) { A.fail("확인 값 불일치", "새 비밀번호와 확인 값이 다릅니다."); return; }
      try { await A.api("POST", "/api/auth/password", {old: v.old, new: v.n1}); A.ok("비밀번호가 변경되었습니다"); } catch (err) { A.fail("변경 실패", err); }
    }
  });

  // ---------------------------------------------------------------- MFA(TOTP) 등록
  async function enrollMfa(forced = false) {
    let st; try { st = await A.api("GET", "/api/auth/mfa"); } catch (err) { A.fail("MFA 상태 조회 실패", err); return; }
    if (!st.enabled) { A.toast("MFA 비활성", "config.yaml auth.mfa.enabled 로 켭니다.", "info"); return; }
    let proof;                                   // 2.30.0 — 이미 등록된 계정은 현재 코드(또는 비밀번호)로 본인 확인 후에만 새 키 발급
    if (st.enrolled && !forced) {
      const c = await A.modal({title: "MFA 재등록", html: `<p class="modal-text">이미 등록된 인증 앱이 있습니다. 새 키를 발급하면 확인 코드 입력 후 기존 키·복구 코드는 무효가 됩니다. 본인 확인을 위해 <b>지금 인증 앱의 6자리 코드</b>(로컬 계정은 비밀번호도 가능) 중 하나를 입력하세요.</p>`,
        fields: [{id: "code", label: "현재 6자리 코드", placeholder: "123456"}, {id: "password", label: "또는 현재 비밀번호", type: "password"}], ok: "새 키 발급"});
      if (!c) return;
      if (!c.code && !c.password) { A.fail("본인 확인 필요", "현재 코드나 비밀번호를 입력하세요."); return; }
      proof = c.code ? {code: c.code} : {password: c.password};
    }
    let en; try { en = await A.api("POST", "/api/auth/mfa/enroll", proof); } catch (err) { A.fail("등록 시작 실패", err); return; }
    const v = await A.modal({title: forced ? "2단계 인증(MFA) 등록 필요" : "2단계 인증(MFA) 등록", wide: true, html: `<div class="mfa-box">
        <div class="mfa-qr">${en.qr_svg || `<div class="empty small">QR 모듈(segno) 없음 — 아래 키를 직접 입력</div>`}</div>
        <div class="mfa-txt"><p class="modal-text">${forced ? "이 역할은 2단계 인증이 필수입니다. " : ""}Google Authenticator·Microsoft Authenticator·1Password 등 TOTP 앱으로 QR 을 스캔하거나 키를 직접 입력한 뒤, 앱에 표시된 6자리 코드를 입력하세요.</p>
          <div class="sub">발급자 ${esc(en.issuer)} · 계정 ${esc(A.me.user)} · SHA1 · 6자리 · 30초</div><pre class="secret">${esc(en.secret)}</pre></div></div>`,
      fields: [{id: "code", label: "앱에 표시된 6자리 코드", required: true, placeholder: "123456"}], ok: "확인·등록", cancel: forced ? "" : "취소"});
    if (!v) { if (forced) return enrollMfa(true); return; }
    try {
      const r = await A.api("POST", "/api/auth/mfa/confirm", {code: v.code});
      await A.modal({title: "복구 코드", html: `<p class="modal-text">인증 앱을 잃어버렸을 때 쓰는 1회용 복구 코드 8개입니다. <b>이 창을 닫으면 다시 볼 수 없습니다.</b> 안전한 곳에 보관하세요.</p><pre class="secret">${r.recovery_codes.map(esc).join("\n")}</pre>`, ok: "", cancel: "보관했습니다"});
      A.ok("MFA 등록 완료"); if (A.me) { A.me.mfa_enrolled = true; A.me.must_enroll_mfa = false; }
      if (forced) location.reload();
    } catch (err) { A.fail("등록 실패", err); if (forced) enrollMfa(true); }
  }
  window.AIOPS_ENROLL_MFA = enrollMfa;
  A.ready.then(me => { if (me && me.mfa_enabled) { const b = document.createElement("button"); b.dataset.um = "mfa"; b.textContent = "2단계 인증(MFA)"; $("#user-pop [data-um=pw]").before(b); }
    if (me && !me.kiosk) { const b = document.createElement("button"); b.dataset.um = "sess"; b.textContent = "내 접속 세션"; $("#user-pop [data-um=logout]").before(b); }
    if (me && me.must_enroll_mfa) setTimeout(() => enrollMfa(true), 400); });

  // ================================================================ 인시던트
  const inc = {status: "active", q: "", sel: null, list: [], detail: null, timer: null, catalog: null};
  async function loadIncidents() {
    try {
      inc.list = await A.api("GET", `/api/incidents?status=${encodeURIComponent(inc.status)}&q=${encodeURIComponent(inc.q)}&days=90`, undefined, {background: true});
    } catch { return; }
    renderIncList();
    loadIncKpis();
    if (A.can("action.approve")) A.api("GET", "/api/actions?status=pending_approval", undefined, {background: true}).then(x => { $("#inc-appr-n").textContent = x.length; }).catch(() => {});
  }
  async function loadIncKpis() {
    try {
      const m = await A.api("GET", "/api/incidents/summary?days=7", undefined, {background: true});
      $("#inc-kpis").innerHTML = [["진행 중", m.active], ["7일 발생", m.total], ["해결", m.resolved], ["MTTA", m.mtta_min != null ? m.mtta_min + "분" : "-"],
        ["MTTR", m.mttr_min != null ? m.mttr_min + "분" : "-"], ["SLA 위반", m.sla_breaches], ["유지보수 중 발생", m.maintenance]]
        .map(([k, v], i) => `<div class="ctile ${i === 5 && v ? "down" : ""}"><span>${k}</span><b>${v}</b></div>`).join("");
      $("#inc-sub").textContent = `— 7일 기준 · ${fmtS(Date.now() / 1000)} 갱신`;
    } catch { /* 무시 */ }
  }
  function slaCell(i) {
    const s = i.sla || {};
    if (["resolved", "closed"].includes(i.status)) return s.ack_breached || s.resolve_breached ? `<span class="sla bad">위반</span>` : `<span class="sla ok">충족</span>`;
    if (s.resolve_breached || s.ack_breached) return `<span class="sla bad">${s.ack_breached && !s.resolve_breached ? "접수 초과" : "해결 초과"}</span>`;
    const due = i.status === "open" ? s.ack_due : s.resolve_due;
    if (!due) return "-";
    const left = due - Date.now() / 1000;
    return `<span class="sla ${left < 600 ? "warn" : ""}">${i.status === "open" ? "접수" : "해결"} ${left > 0 ? dur(left) + " 남음" : "초과"}</span>`;
  }
  function renderIncList() {
    $("#inc-rows").innerHTML = inc.list.length ? inc.list.map(i => `<tr data-id="${esc(i.id)}" class="${inc.sel === i.id ? "sel" : ""} ${i.maintenance ? "maint" : ""}">
      <td class="mono">${esc(i.id)}</td><td>${sevLab(i.severity)}</td>
      <td><b>${esc(i.title)}</b><span class="sub">${esc(i.cluster ? "클러스터 " + i.cluster : i.correlation_key)}${i.maintenance ? " · 유지보수 중" : ""}${i.itsm && i.itsm.number ? " · " + esc(i.itsm.number) : ""}${i.has_rca ? " · AI RCA" : ""}</span></td>
      <td><span class="ist ${esc(i.status)}">${esc(i.status_label)}</span></td><td>${esc(i.assignee || "-")}</td>
      <td class="r">${i.anomaly_count}</td><td title="${fmtDT(i.updated)}">${ago(i.last_anomaly || i.updated)}</td><td>${slaCell(i)}</td></tr>`).join("")
      : `<tr><td colspan="8"><div class="empty">조건에 맞는 인시던트가 없습니다.</div></td></tr>`;
  }
  async function openIncident(id) {
    open("drawer-inc");
    inc.sel = id; renderIncList();
    if (!inc.list.length) loadIncidents();
    $("#inc-detail").innerHTML = `<div class="empty"><span class="spin"></span></div>`;
    try { inc.detail = await A.api("GET", `/api/incidents/${encodeURIComponent(id)}`); }
    catch (e) { $("#inc-detail").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    renderIncDetail();
    if (location.hash !== `#incident/${id}`) history.replaceState(null, "", `#incident/${id}`);
  }
  const CRIT = {falsifiability: ["반증 가능성", "독립적으로 측정·검증 가능한가"], sufficiency: ["충분성", "원인을 제거하면 증상이 사라지는가"],
                necessity: ["필요성", "원인이 있을 때마다 증상이 나타나는가"], mechanism: ["메커니즘", "전파 경로를 설명하는가"]};
  function rcaHtml(r, at) {
    if (!r || !Object.keys(r).length) return `<div class="empty small">아직 AI 근본원인 분석을 실행하지 않았습니다.${A.can("operate") ? "<br><b>AI 근본원인 분석</b>을 누르면 묶인 이상징후·로그 타임라인·vCenter 조사·RAG 근거를 모아 Gemma 4 31B 가 인과 사슬과 4대 완결성 기준으로 판정합니다." : ""}</div>`;
    const chain = [["근본원인", r.root_cause], ["전파", r.propagation], ["증폭", r.amplification], ["영향", r.impact]].filter(x => x[1]);
    const cr = r.criteria || {};
    return `<div class="rca ${r.complete ? "complete" : "incomplete"}">
      <div class="rca-head">${r.complete ? `<span class="label ok">완결</span>` : `<span class="label warning">⚠ INCOMPLETE — 근거 불충분</span>`}
        <span>신뢰도 <b>${r.confidence != null ? Math.round(r.confidence * 100) + "%" : "-"}</b></span>
        <small>${esc(r._model || "")} · ${r._latency_ms ? (r._latency_ms / 1000).toFixed(1) + "초" : ""} · ${fmtDT(at)}${r.bundle_stats ? ` · 근거: 이상 ${r.bundle_stats.anomalies} · 로그 ${r.bundle_stats.logs} · vCenter 조사 ${r.bundle_stats.investigation ? "O" : "X"} · 지식 ${r.bundle_stats.knowledge}` : ""}</small></div>
      ${r.summary ? `<p class="rca-sum">${esc(r.summary)}</p>` : ""}
      <div class="chain">${chain.map(([k, v], i) => `${i ? '<i class="arr">→</i>' : ""}<div class="node n${i}"><span>${k}</span>${esc(v)}</div>`).join("")}</div>
      <table class="crit"><thead><tr><th>완결성 기준</th><th>판정</th><th>근거 / 부족한 점</th></tr></thead><tbody>
        ${Object.entries(CRIT).map(([k, [lab, q]]) => { const c = cr[k] || {}; return `<tr><td><b>${lab}</b><span class="sub">${q}</span></td>
          <td>${c.satisfied ? '<span class="ok-mark">✓ 충족</span>' : '<span class="no-mark">✗ 미충족</span>'}</td><td>${esc(c.evidence || "-")}</td></tr>`; }).join("")}</tbody></table>
      ${(r.missing_evidence || []).filter(Boolean).length ? `<div class="rca-sec"><h5>추가로 필요한 증거</h5><ul>${r.missing_evidence.filter(Boolean).map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}
      ${(r.next_checks || []).length ? `<div class="rca-sec"><h5>다음 확인 단계(읽기)</h5><ol>${r.next_checks.map(x => `<li>${esc(x)}</li>`).join("")}</ol></div>` : ""}
      ${(r.remediation || []).length ? `<div class="rca-sec"><h5>조치 권고</h5><ol>${r.remediation.map(x => `<li>${esc(x.step || x)} ${x.risk ? `<span class="label ${x.risk === "high" ? "critical" : x.risk === "medium" ? "warning" : ""}">위험 ${esc(x.risk)}</span>` : ""} ${x.requires_approval ? '<span class="label info">승인 필요</span>' : ""}</li>`).join("")}</ol></div>` : ""}
      ${(r.references || []).length ? `<div class="rca-sec"><h5>근거 문서</h5><ul class="refs">${r.references.map(x => `<li><span class="label">${esc(x.type || "doc")}</span> ${/^https?:/.test(x.url || "") ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a>` : esc(x.title)}</li>`).join("")}</ul></div>` : ""}
    </div>`;
  }
  const NOTE_ICON = {system: "⚙", status: "●", assign: "👤", comment: "💬", ai: "✦", action: "⚡", itsm: "↗"};
  function incKbHtml(kb) {
    const K = window.AIOPS_KNOW;
    if (!(kb || []).length) return `<div class="empty small">연결된 문서가 없습니다 — 지식(KB·문서)에 KB·TechDocs 를 넣으면 자동으로 찾습니다.</div>`;
    return `<ul class="refs kn-refs">${kb.map(x => `<li>${K ? K.badges(x) : ""} ${K ? K.link(x) : esc(x.title)}
      <small style="color:var(--muted)">${x.matched_anomalies ? ` · 이상징후 ${x.matched_anomalies}건과 연관` : ""}${x.section ? " · 일치 구역 " + esc(x.section) : ""}</small>
      ${String(x.doc_id || "").startsWith("lib:") ? ` <a href="#" data-kdoc="${esc(x.doc_id)}">전문</a>` : ""}
      ${x.summary ? `<div class="kn-sum">${esc(x.summary)}</div>` : ""}</li>`).join("")}</ul>`;
  }
  const VC_REL = {vm: ["대상 VM", "critical"], host: ["같은 호스트", "warning"], cluster: ["같은 클러스터", ""]};
  const VC_FLAG = {offhours: "업무 외", bulk_delete: "대량 삭제", bulk_power_off: "대량 전원 끔", protected: "보호 VM", short_lived: "단명 VM", unplanned: "변경 창 밖", in_window: "변경 창 안", pingpong: "반복 이동"};
  function vmChangesHtml(list, created) {
    if (!(list || []).length) return `<div class="empty small">이 기간에 대상과 관련된 VM 변경이 없습니다(구성·전원·스냅샷·생성·삭제·이동·HA).</div>`;
    const L = window.AIOPS_VM_LABELS || {};
    return `<table class="acts vchg"><thead><tr><th>시각</th><th>관계</th><th>변경</th><th>VM</th><th>호스트</th><th>사용자</th><th>내용</th></tr></thead><tbody>${list.map(r => {
      const dtm = r.ts - created, rel = VC_REL[r.relation] || [r.relation, ""];
      return `<tr><td class="nowrap">${fmtS(r.ts)}<span class="sub">${dtm < 0 ? `발생 ${Math.round(-dtm / 60)}분 전` : `발생 후 ${Math.round(dtm / 60)}분`}</span></td>
        <td><span class="label ${rel[1]}">${rel[0]}</span></td><td><b>${esc(L[r.type] || r.type)}</b>${String(r.flags || "").split(",").filter(Boolean).map(f => ` <span class="label ${f === "in_window" ? "ok" : "warning"}">${esc(VC_FLAG[f] || f)}</span>`).join("")}</td>
        <td>${r.vm ? `<a href="#" data-vmtl="${esc(r.vm)}">${esc(r.vm)}</a>` : "-"}</td><td class="mono small">${esc(r.from_host && r.to_host && r.from_host !== r.to_host ? r.from_host + " → " + r.to_host : r.to_host || r.from_host || "")}</td>
        <td>${esc(r.user || "-")}</td><td class="small">${esc(r.detail || r.source || "")}</td></tr>`; }).join("")}</tbody></table>`;
  }
  function renderIncDetail() {
    const d = inc.detail; if (!d) return;
    const canOp = A.can("operate");
    const active = ["open", "acknowledged", "investigating"].includes(d.status);
    const topo = d.topology || {};
    $("#inc-detail").innerHTML = `
      <div class="idh"><div><span class="mono">${esc(d.id)}</span> ${sevLab(d.severity)} <span class="ist ${esc(d.status)}">${esc(d.status_label)}</span>
        ${d.maintenance ? '<span class="label">유지보수 중 발생</span>' : ""}${d.itsm && d.itsm.number ? ` <a class="label info" href="${esc(d.itsm.url || "#")}" target="_blank" rel="noopener">${esc(d.itsm.system)} ${esc(d.itsm.number)}</a>` : ""}</div>
        <h4>${esc(d.title)}</h4>
        <div class="meta">발생 ${fmtDT(d.created)} · 최근 이상 ${ago(d.last_anomaly)} · 담당 <b>${esc(d.assignee || "미지정")}</b> · 상관 그룹 ${esc(d.correlation_key)}
          ${topo.name ? ` · 대상 ${esc(topo.kind)} <b>${esc(topo.name)}</b>${topo.host ? " @ " + esc(topo.host) : ""}${topo.cluster ? " / " + esc(topo.cluster) : ""}` : ""}</div>
        ${d.summary ? `<p class="isum">${esc(d.summary)}</p>` : ""}
        ${d.resolution ? `<p class="isum res"><b>처리 내용</b> ${esc(d.resolution)}</p>` : ""}
      </div>
      <div class="ibar">${canOp ? `
        ${d.status === "open" ? `<button class="btn-sm solid" data-st="acknowledged">접수</button>` : ""}
        ${["open", "acknowledged"].includes(d.status) ? `<button class="btn-sm" data-st="investigating">조사 시작</button>` : ""}
        ${active ? `<button class="btn-sm" data-st="resolved">해결</button>` : ""}
        ${d.status === "resolved" ? `<button class="btn-sm" data-st="closed">종료</button>` : ""}
        ${!active ? `<button class="btn-sm" data-st="open">재개</button>` : ""}
        <button class="btn-sm" data-ia="assign-me">나에게 할당</button><button class="btn-sm" data-ia="logs" title="인시던트 호스트·기간의 로그를 파일로">로그 받기</button><button class="btn-sm" data-ia="assign">담당 지정</button>
        <span class="gap"></span>
        <button class="btn-sm solid ai" data-ia="rca">AI 근본원인 분석</button><button class="btn-sm" data-ia="topo" title="AIOps 인사이트 — 의존 그래프로 원인 후보·직전 변경">원인 후보·직전 변경</button><button class="btn-sm" data-ia="bundle">근거 묶음</button><button class="btn-sm" data-ia="sr" title="Broadcom·AWS·Azure SR 양식 보고서·이메일 초안·PDF·로그 묶음">SR 초안</button>
        ${A.can("action.request") ? `<button class="btn-sm" data-ia="action">조치 요청</button>` : ""}
        ${!(d.itsm && d.itsm.number) ? `<button class="btn-sm" data-ia="itsm">ITSM 등록</button>` : ""}` : `<span class="muted">조회 전용 권한</span>`}
      </div>
      <div class="isec"><h5>직전 VM 변경 <small>발생 6시간 전 ~ 마지막 이상 — 대상 VM › 같은 호스트 › 같은 클러스터 순 · AI 근본원인 분석 근거로도 들어감</small></h5>${vmChangesHtml(d.vm_changes, d.created)}</div>
      <div class="isec"><h5>관련 KB·문서 <small>자동 연결 — 묶인 이상징후의 AI 근거와 원문 로그로 찾은 문서(많이 겹칠수록 위), AI 근본원인 분석의 근거로도 들어감</small></h5>${incKbHtml(d.kb)}</div>
      <div class="isec"><h5>AI 근본원인 분석 <small>VMware-AIops investigation protocol — 인과 사슬 + 4대 완결성 기준</small></h5><div id="rca-box">${rcaHtml(d.rca, d.rca_at)}</div></div>
      <div class="isec"><h5>조치 <small>미리보기 → 차단 사유 확인 → (L3 이상) 4-eyes 승인 → 실행 직전 재측정 → 감사 기록</small></h5>${actionsTable(d.actions)}</div>
      <div class="isec"><h5>묶인 이상 징후 <small>${d.anomaly_count}건</small></h5>
        <div class="ianoms">${(d.anomalies || []).slice().reverse().map(a => `<div class="ian ${esc(a.severity)}"><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="mono">${fmtS(a.last_seen)}</span> <b>${esc(a.title)}</b> ${a.count > 1 ? `<span class="badge">×${a.count}</span>` : ""}
          <div class="raw">${esc(a.event.source)} · ${esc(a.event.host)}${a.event.entity ? " / " + esc(a.event.entity) : ""} — ${esc(a.event.message.slice(0, 400))}</div></div>`).join("") || `<div class="empty small">${d.anomaly_count ? "메모리에 남은 이상징후가 없습니다(보존 기간 경과)." : "연결된 이상징후 없음(수동 생성)"}</div>`}</div></div>
      <div class="isec"><h5>처리 이력</h5>
        <div class="timeline">${(d.notes || []).slice().reverse().map(n => `<div class="tl ${esc(n.kind)}"><i>${NOTE_ICON[n.kind] || "•"}</i><div><div class="tlh"><b>${esc(n.user)}</b> · ${fmtS(n.ts)}</div><div>${esc(n.text)}</div></div></div>`).join("")}</div>
        ${canOp ? `<form class="cform" id="inc-comment"><textarea rows="2" placeholder="코멘트(ITSM 연동 시 작업 메모로 전송)"></textarea><button class="btn-sm solid">등록</button></form>` : ""}
      </div>`;
  }
  function actionsTable(list) {
    if (!list || !list.length) return `<div class="empty small">요청된 조치가 없습니다.</div>`;
    return `<table class="acts"><thead><tr><th>#</th><th>조치</th><th>대상</th><th>상태</th><th>요청</th><th>승인</th><th>결과</th><th></th></tr></thead><tbody>${list.map(x => `
      <tr><td>${x.id}</td><td><b>${esc(x.label)}</b><span class="sub">L${x.level} · ${esc(x.connector)}</span></td><td>${esc(x.target)}</td>
      <td><span class="ast ${esc(x.status)}">${esc(x.status_label)}</span></td>
      <td>${esc(x.requested_by)}<span class="sub">${fmtS(x.requested_at)}</span><span class="sub">${esc(x.reason || "")}</span></td>
      <td>${esc(x.approved_by || "-")}${x.reject_reason ? `<span class="sub">반려: ${esc(x.reject_reason)}</span>` : ""}</td>
      <td>${x.result ? `<span class="sub">${esc(x.result.error || x.result.task || x.result.result || "")}</span>` : (x.preview && x.preview.blockers && x.preview.blockers.length ? `<span class="sub bad">${esc(x.preview.blockers.join("; "))}</span>` : "")}</td>
      <td>${x.status === "pending_approval" && A.can("action.approve") ? `<button class="btn-sm solid" data-appr="${x.id}">승인</button> <button class="btn-sm" data-rej="${x.id}">반려</button>` : ""}
        <button class="btn-sm" data-axd="${x.id}">상세</button></td></tr>`).join("")}</tbody></table>`;
  }
  async function approveAction(id) {
    if (!await A.confirm(`조치 #${id} 승인`, "승인 즉시 실행됩니다. 실행 직전에 상태를 다시 측정해 차단 사유가 생기면 실패 처리됩니다.", true)) return;
    try { await A.api("POST", `/api/actions/${id}/approve`); A.ok(`조치 #${id} 승인 — 실행 중`); } catch (e) { A.fail("승인 실패", e); }
    refreshAfterAction();
  }
  async function rejectAction(id) {
    const v = await A.modal({title: `조치 #${id} 반려`, fields: [{id: "reason", label: "반려 사유", required: true}], ok: "반려", danger: true});
    if (!v) return;
    try { await A.api("POST", `/api/actions/${id}/reject`, {reason: v.reason}); A.ok(`조치 #${id} 반려`); } catch (e) { A.fail("반려 실패", e); }
    refreshAfterAction();
  }
  function refreshAfterAction() { setTimeout(() => { if (inc.sel) openIncident(inc.sel); loadIncidents(); if (!$("#appr-list")?.closest(".modal")?.hidden) loadApprovals(); }, 600); }

  const PARAM_LABEL = {entity: "대상 개체(호스트/VM/클러스터 이름)", alarm: "알람 이름(비우면 전체)", host: "ESXi 호스트", vm: "가상머신", service: "어플라이언스 서비스 ID(예: vsphere-ui)", alarm_id: "NSX 알람 ID"};
  async function requestAction(d) {
    inc.catalog = inc.catalog || await A.api("GET", "/api/actions/catalog");
    const cat = inc.catalog.filter(c => c.connectors.length);
    if (!cat.length) { A.toast("조치 불가", "조치 가능한 커넥터(vCenter·NSX)가 없습니다. 운영 설정 → 커넥터에서 등록하세요.", "warning"); return; }
    const topo = d.topology || {};
    const guess = {host: topo.host || (d.hosts || [])[0] || "", vm: topo.kind === "vm" ? topo.name : "", entity: topo.name || (d.hosts || [])[0] || ""};
    let pv = null;
    const v = await A.modal({title: "조치 요청", wide: true,
      html: `<div class="act-form"><label class="mf"><span>조치</span><select id="ax-action">${cat.map(c => `<option value="${esc(c.action)}">${esc(c.label)} (L${c.level}${c.needs_approval ? " · 승인 필요" : ""}${c.reversible ? "" : " · 되돌릴 수 없음"})</option>`).join("")}</select></label>
        <label class="mf"><span>커넥터</span><select id="ax-conn"></select></label><div id="ax-params"></div>
        <label class="mf"><span>사유 *</span><input id="ax-reason" placeholder="예) RCA 결과 경로 장애 — 호스트 격리 후 HBA 점검 (CHG0012345)"></label>
        <div class="ax-bar"><button class="btn-sm" id="ax-preview" type="button">미리보기(영향 범위 측정)</button></div><div id="ax-pv"></div></div>`,
      ok: "요청",
      onOpen: m => {
        const okb = m.querySelector("[data-ok]"); okb.disabled = true;
        const sync = () => {
          const c = cat.find(x => x.action === m.querySelector("#ax-action").value);
          m.querySelector("#ax-conn").innerHTML = c.connectors.map(n => `<option>${esc(n)}</option>`).join("");
          m.querySelector("#ax-params").innerHTML = c.params.map(p => `<label class="mf"><span>${esc(PARAM_LABEL[p] || p)}${p === "alarm" ? "" : " *"}</span><input data-param="${p}" value="${esc(guess[p] || "")}"></label>`).join("");
          m.querySelector("#ax-pv").innerHTML = ""; okb.disabled = true; pv = null;
        };
        m.querySelector("#ax-action").onchange = sync; sync();
        m.addEventListener("input", e => { if (e.target.dataset.param || e.target.id === "ax-conn") { okb.disabled = true; m.querySelector("#ax-pv").innerHTML = ""; } });
        m.querySelector("#ax-preview").onclick = async () => {
          const body = collect(m);
          m.querySelector("#ax-pv").innerHTML = `<div class="empty small"><span class="spin"></span> 읽기 전용으로 현재 상태를 측정하는 중…</div>`;
          try {
            pv = await A.api("POST", "/api/actions/preview", body);
            const bl = pv.blockers || [];
            m.querySelector("#ax-pv").innerHTML = `<div class="pv ${bl.length ? "blocked" : "clear"}">
              <div class="pvh">${bl.length ? `<b>차단 ${bl.length}건 — 요청할 수 없습니다</b>` : `<b>차단 사유 없음</b>`} · 위험도 L${pv.level} ${pv.needs_approval ? "· 관리자 승인 필요(요청자와 다른 사람)" : "· 운영자 즉시 실행"}${pv.reversible === false ? " · <b>되돌릴 수 없음</b>" : ""}</div>
              ${bl.length ? `<ul class="bad">${bl.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
              <h5>영향 범위(blast radius)</h5><pre>${jsonPretty(pv.blast_radius || {})}</pre></div>`;
            okb.disabled = !!bl.length;
          } catch (e) { m.querySelector("#ax-pv").innerHTML = `<div class="pv blocked"><b>미리보기 실패</b> ${esc(e.message)}</div>`; }
        };
        okb.addEventListener("click", ev => {
          const r = m.querySelector("#ax-reason").value.trim();
          if (r.length < 4) { ev.stopImmediatePropagation(); A.fail("사유 필요", "조치 사유를 4자 이상 입력하세요."); return; }
          inc._axBody = {...collect(m), reason: r, incident_id: d.id};
        }, {capture: true});
      }});
    if (!v || !inc._axBody) return;
    try {
      const res = await A.api("POST", "/api/actions", inc._axBody);
      A.ok(`조치 #${res.id} ${res.status_label}`, res.status === "pending_approval" ? "관리자 승인 후 실행됩니다." : "");
    } catch (e) { A.fail("조치 요청 실패", e); }
    inc._axBody = null; refreshAfterAction();
  }
  function collect(m) {
    const params = {};
    m.querySelectorAll("[data-param]").forEach(i => { if (i.value.trim()) params[i.dataset.param] = i.value.trim(); });
    return {action: m.querySelector("#ax-action").value, connector: m.querySelector("#ax-conn").value, params};
  }
  async function loadApprovals() {
    const list = await A.api("GET", "/api/actions?status=pending_approval");
    const box = $("#appr-list"); if (box) box.innerHTML = actionsTable(list);
    $("#inc-appr-n").textContent = list.length;
    return list;
  }
  $("#inc-approvals").onclick = async () => {
    await A.modal({title: "조치 승인 대기", wide: true, html: `<div id="appr-list"><div class="empty small"><span class="spin"></span></div></div>`, ok: "", cancel: "닫기",
      onOpen: m => { loadApprovals(); m.addEventListener("click", e => {
        const a = e.target.closest("[data-appr]"), r = e.target.closest("[data-rej]"), dx = e.target.closest("[data-axd]");
        if (a) approveAction(Number(a.dataset.appr)).then(loadApprovals); if (r) rejectAction(Number(r.dataset.rej)).then(loadApprovals);
        if (dx) actionDetail(Number(dx.dataset.axd)); }); }});
  };
  async function actionDetail(id) {
    const list = await A.api("GET", "/api/actions");
    const x = list.find(a => a.id === id); if (!x) return;
    A.modal({title: `조치 #${x.id} ${x.label}`, wide: true, ok: "", cancel: "닫기", html: `<div class="kv">
      <div><span>상태</span><b>${esc(x.status_label)}</b></div><div><span>대상</span>${esc(x.target)} (${esc(x.connector)})</div>
      <div><span>요청</span>${esc(x.requested_by)} · ${fmtS(x.requested_at)} — ${esc(x.reason)}</div>
      <div><span>승인</span>${esc(x.approved_by || "-")} ${x.approved_at ? "· " + fmtS(x.approved_at) : ""} ${x.reject_reason ? "— " + esc(x.reject_reason) : ""}</div>
      <div><span>실행</span>${fmtS(x.executed_at)} ~ ${fmtS(x.finished_at)}</div></div>
      <h5>미리보기(요청 시점)</h5><pre class="jpre">${jsonPretty(x.preview)}</pre><h5>실행 결과(전/후 상태)</h5><pre class="jpre">${jsonPretty(x.result)}</pre>`});
  }

  $("#inc-detail").addEventListener("click", async e => {
    const d = inc.detail; if (!d) return;
    const st = e.target.closest("[data-st]"), ia = e.target.closest("[data-ia]");
    const ap = e.target.closest("[data-appr]"), rj = e.target.closest("[data-rej]"), axd = e.target.closest("[data-axd]");
    if (ap) return approveAction(Number(ap.dataset.appr));
    if (rj) return rejectAction(Number(rj.dataset.rej));
    if (axd) return actionDetail(Number(axd.dataset.axd));
    if (st) {
      const s = st.dataset.st, need = ["resolved", "closed"].includes(s);
      const v = await A.modal({title: `상태 변경 — ${st.textContent}`, fields: [{id: "note", label: need ? "처리 내용(근본원인·조치)" : "메모", type: "textarea", required: need, value: need ? (d.rca && d.rca.root_cause ? `원인: ${d.rca.root_cause}\n조치: ` : "") : ""}], ok: "변경"});
      if (!v) return;
      try { await A.api("POST", `/api/incidents/${d.id}/status`, {status: s, note: v.note}); openIncident(d.id); loadIncidents(); } catch (err) { A.fail("상태 변경 실패", err); }
    }
    if (!ia) return;
    const k = ia.dataset.ia;
    if (k === "assign-me" || k === "assign") {
      let who = A.me.user;
      if (k === "assign") { const v = await A.modal({title: "담당자 지정", fields: [{id: "u", label: "사용자 아이디(비우면 해제)", value: d.assignee || ""}]}); if (!v) return; who = v.u; }
      try { await A.api("POST", `/api/incidents/${d.id}/assign`, {assignee: who}); openIncident(d.id); loadIncidents(); } catch (err) { A.fail("담당 지정 실패", err); }
    }
    if (k === "topo") { if (window.AIOPS_AIOPSX) window.AIOPS_AIOPSX(d.id); return; }
    if (k === "rca") {
      ia.disabled = true; ia.innerHTML = `<span class="spin"></span> 분석 중…`;
      $("#rca-box").innerHTML = `<div class="empty small"><span class="spin"></span> 근거 수집(이상징후·로그·vCenter 조사·RAG) → Gemma 4 31B 분석 중… 수십 초 걸릴 수 있습니다.</div>`;
      try { await A.api("POST", `/api/incidents/${d.id}/rca`); } catch (err) { A.fail("AI 분석 실패", err); }
      openIncident(d.id);
    }
    if (k === "sr") { if (window.AIOPS_SR_NEW) window.AIOPS_SR_NEW({kind: "incident", ref: d.id}, {label: d.title}); return; }
    if (k === "logs") {
      const until = ["resolved", "closed"].includes(d.status) ? (d.last_anomaly || d.updated) + 1800 : Date.now() / 1000;
      if (window.AIOPS_LOGS_EXPORT) window.AIOPS_LOGS_EXPORT({since: d.created - 1800, until, host: (d.hosts || []).join(","), name: d.id, format: "zip",
        title: `인시던트 ${d.id} 의 호스트·기간(발생 30분 전 ~ ${["resolved", "closed"].includes(d.status) ? "마지막 이상 30분 뒤" : "지금"})으로 받습니다.`});
      return;
    }
    if (k === "bundle") {
      const w = await A.modal({title: "근거 묶음(RCA 입력)", wide: true, ok: "", cancel: "닫기", html: `<div id="bundle-box"><div class="empty small"><span class="spin"></span></div></div>`,
        onOpen: async m => {
          try {
            const b = await A.api("POST", `/api/incidents/${d.id}/investigate`);
            const inv = b.investigation || {};
            m.querySelector("#bundle-box").innerHTML = `<div class="kv"><div><span>이상징후</span>${b.anomalies.length}건</div><div><span>로그 타임라인</span>${b.log_timeline.length}행</div>
              <div><span>토폴로지</span>${b.topology_context ? esc(JSON.stringify(b.topology_context)) : "해석 불가(vCenter 커넥터·토폴로지 확인)"}</div><div><span>지식(RAG)</span>${b.knowledge.length}건</div></div>
              ${inv.error ? `<p class="bad">vCenter 조사: ${esc(inv.error)}</p>` : inv.target ? `<h5>vCenter 조사 — ${esc(inv.kind)} ${esc(inv.target)}</h5><pre class="jpre">${jsonPretty({...inv, timeline: undefined})}</pre>
                <h5>이벤트·작업·알람 타임라인 (${(inv.timeline || []).length})</h5><div class="tl-mini">${(inv.timeline || []).map(t => `<div><span class="mono">${fmtS(t.ts)}</span> <span class="label">${esc(t.type)}</span> ${esc(t.text)}</div>`).join("")}</div>` : ""}
              <h5>로그 타임라인</h5><div class="tl-mini">${b.log_timeline.map(l => `<div><span class="mono">${fmtS(l.ts)}</span> <span class="sev ${esc(l.severity)}">${esc(l.severity)}</span> ${esc(l.host)} ${esc(l.message)}</div>`).join("") || "-"}</div>`;
          } catch (err) { m.querySelector("#bundle-box").innerHTML = `<p class="bad">${esc(err.message)}</p>`; }
        }});
      void w;
    }
    if (k === "action") requestAction(d);
    if (k === "itsm") {
      try { const r = await A.api("POST", `/api/incidents/${d.id}/itsm`); A.ok("ITSM 등록", `${r.system || ""} ${r.number || ""}`); openIncident(d.id); } catch (err) { A.fail("ITSM 등록 실패", err); }
    }
  });
  $("#inc-detail").addEventListener("submit", async e => {
    if (e.target.id !== "inc-comment") return;
    e.preventDefault();
    const t = e.target.querySelector("textarea").value.trim(); if (!t) return;
    try { await A.api("POST", `/api/incidents/${inc.detail.id}/comment`, {text: t}); openIncident(inc.detail.id); } catch (err) { A.fail("코멘트 실패", err); }
  });
  $("#inc-rows").addEventListener("click", e => { const tr = e.target.closest("tr[data-id]"); if (tr) openIncident(tr.dataset.id); });
  $("#inc-status").addEventListener("click", e => { const b = e.target.closest("button"); if (!b) return; inc.status = b.dataset.v;
    $$("#inc-status button").forEach(x => x.classList.toggle("on", x === b)); loadIncidents(); });
  let iqT; $("#inc-q").oninput = e => { clearTimeout(iqT); iqT = setTimeout(() => { inc.q = e.target.value.trim(); loadIncidents(); }, 250); };
  $("#inc-new").onclick = async () => {
    const v = await A.modal({title: "인시던트 수동 생성", fields: [{id: "title", label: "제목", required: true},
      {id: "severity", label: "심각도", type: "select", value: "error", options: SEVS}]});
    if (!v) return;
    try { const r = await A.api("POST", "/api/incidents", v); openIncident(r.id); loadIncidents(); } catch (e) { A.fail("생성 실패", e); }
  };
  function openIncDrawer() {
    open("drawer-inc"); loadIncidents();
    clearInterval(inc.timer); inc.timer = setInterval(() => isOpen("drawer-inc") ? loadIncidents() : clearInterval(inc.timer), 15000);
  }
  $("#nav-inc").onclick = openIncDrawer;
  addEventListener("aiops:open-incident", e => { openIncDrawer(); openIncident(e.detail); });
  let wsT;
  addEventListener("aiops:ws", e => {
    const m = e.detail;
    if ((m.type === "incident" || m.type === "action") && isOpen("drawer-inc")) {
      clearTimeout(wsT); wsT = setTimeout(() => { loadIncidents(); const id = m.type === "incident" ? m.data.id : m.data.incident_id; if (inc.sel && id === inc.sel) openIncident(inc.sel); }, 400);
    }
    if (m.type === "action" && m.data.status && ["succeeded", "failed"].includes(m.data.status))
      A.toast(`조치 #${m.data.id} ${m.data.status === "succeeded" ? "성공" : "실패"}`, m.data.incident_id || "", m.data.status === "succeeded" ? "ok" : "error");
  });

  // ================================================================ 리포트·백업
  async function loadReports() {
    const [r, b] = await Promise.all([A.api("GET", "/api/reports"), A.can("settings") ? A.api("GET", "/api/backup").catch(() => null) : null]);
    const sch = r.schedule || {}, dl = sch.daily || {}, wk = sch.weekly || {};
    const mo = sch.monthly || {};
    $("#rep-sub").textContent = `— 정기: 일간 ${dl.enabled ? dl.time : "꺼짐"} · 주간 ${wk.enabled ? ["월", "화", "수", "목", "금", "토", "일"][wk.weekday || 0] + " " + wk.time : "꺼짐"} · 월간 ${mo.enabled ? mo.day + "일 " + mo.time : "꺼짐"}`;
    $("#rep-body").innerHTML = `<h5>보관 리포트 <small>단일 HTML — 브라우저 인쇄로 PDF 저장 가능</small></h5>
      <table><thead><tr><th>리포트</th><th>생성</th><th class="r">크기</th><th></th></tr></thead><tbody>${r.reports.map(x => `<tr><td><b>${esc(x.name)}</b></td><td>${fmtDT(x.mtime)}</td><td class="r">${(x.size / 1024).toFixed(0)}KB</td>
        <td><a class="btn-sm" href="/api/reports/${encodeURIComponent(x.name)}" target="_blank" rel="noopener">열기</a> <a class="btn-sm" href="/api/reports/${encodeURIComponent(x.name)}?download=true">다운로드</a></td></tr>`).join("") || `<tr><td colspan="4"><div class="empty small">생성된 리포트가 없습니다.</div></td></tr>`}</tbody></table>
      ${b ? `<h5 style="margin-top:18px">DB 백업 <small>SQLite 온라인 백업 · 매일 ${esc(b.schedule)} · 최근 ${b.keep}개 보관 · ${esc(b.dir)}</small> <button class="btn-sm" id="bk-run">지금 백업</button></h5>
      <table><thead><tr><th>파일</th><th>생성</th><th class="r">크기</th></tr></thead><tbody>${b.backups.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${fmtDT(x.mtime)}</td><td class="r">${(x.size / 1048576).toFixed(1)}MB</td></tr>`).join("") || `<tr><td colspan="3"><div class="empty small">백업 없음</div></td></tr>`}</tbody></table>` : ""}`;
    const bk = $("#bk-run"); if (bk) bk.onclick = async () => { bk.disabled = true; try { const x = await A.api("POST", "/api/backup/run"); A.ok("백업 완료", `${x.file} (${(x.size / 1048576).toFixed(1)}MB)`); } catch (e) { A.fail("백업 실패", e); } loadReports(); };
  }
  $("#nav-rep").onclick = () => { open("drawer-rep"); loadReports(); };
  $$("[data-gen]").forEach(b => b.onclick = async () => {
    const kind = b.dataset.gen;
    let body = {kind};
    if (kind === "custom") {
      const now = new Date(), toLocal = d => new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      const v = await A.modal({title: "기간 지정 리포트", fields: [{id: "since", label: "시작", type: "datetime-local", value: toLocal(new Date(now - 86400000)), required: true},
        {id: "until", label: "종료", type: "datetime-local", value: toLocal(now), required: true},
        {id: "recipients", label: "메일 수신자(쉼표 구분, 선택)", placeholder: "noc@example.com, ops@example.com"}], ok: "생성"});
      if (!v) return;
      body = {kind, since: new Date(v.since).getTime() / 1000, until: new Date(v.until).getTime() / 1000};
      if (v.recipients) { body.email = true; body.recipients = v.recipients.split(/[,;\s]+/).filter(Boolean); }
    }
    b.disabled = true; const t = b.textContent; b.innerHTML = `<span class="spin"></span>`;
    try { const r = await A.api("POST", "/api/reports/generate", body); A.ok("리포트 생성", r.title + (r.email_error ? `\n메일 실패: ${r.email_error}` : "")); window.open(`/api/reports/${encodeURIComponent(r.name)}`, "_blank", "noopener"); }
    catch (e) { A.fail("리포트 생성 실패", e); }
    b.disabled = false; b.textContent = t; loadReports();
  });

  // ================================================================ 감사로그
  async function loadAudit() {
    const q = new URLSearchParams({hours: $("#au-hours").value, user: $("#au-user").value.trim(), action: $("#au-action").value, q: $("#au-q").value.trim(), limit: 1000});
    let rows;
    try { rows = await A.api("GET", `/api/audit?${q}`); } catch (e) { $("#au-rows").innerHTML = `<tr><td colspan="8">${esc(e.message)}</td></tr>`; return; }
    $("#audit-export").href = `/api/audit/export?hours=${$("#au-hours").value}`;
    $("#au-rows").innerHTML = rows.length ? rows.map(r => `<tr class="${/^(fail|denied|locked|broken|disabled|apply_fail|blocked)/.test(r.result) ? "au-bad" : ""}"><td class="mono">${fmtS(r.ts)}</td><td>${esc(r.user)}</td><td>${esc(ROLE_LABEL[r.role] || r.role || "")}</td>
      <td class="mono">${esc(r.ip || "")}</td><td><b>${esc(r.action)}</b></td><td>${esc(r.target || "")}</td><td><span class="res ${/^(ok|succeeded|approved)$/.test(r.result) ? "good" : /^(pending|running|rate)/.test(r.result) ? "mid" : "bad"}">${esc(r.result)}</span></td>
      <td class="det">${r.detail && Object.keys(r.detail).length ? `<code title="${esc(JSON.stringify(r.detail))}">${esc(JSON.stringify(r.detail).slice(0, 160))}</code>` : ""}</td></tr>`).join("")
      : `<tr><td colspan="8"><div class="empty small">기록 없음</div></td></tr>`;
  }
  $("#nav-audit").onclick = () => { open("drawer-audit"); loadAudit(); };
  ["#au-hours", "#au-action"].forEach(s => $(s).onchange = loadAudit);
  let auT; ["#au-user", "#au-q"].forEach(s => $(s).oninput = () => { clearTimeout(auT); auT = setTimeout(loadAudit, 300); });
  $("#audit-verify").onclick = async () => {
    try { const r = await A.api("GET", "/api/audit/verify");
      r.ok ? A.ok("무결성 검증 통과", `${r.checked.toLocaleString()}건 해시 체인 정상 (#${r.first_id} ~ #${r.last_id})`)
           : A.toast("무결성 검증 실패", `#${r.broken_at} 기록에서 해시 체인이 끊어졌습니다. 변조 가능성이 있습니다.`, "critical", 30000);
      loadAudit(); } catch (e) { A.fail("검증 실패", e); }
  };

  // ================================================================ 사용자 · 토큰
  async function loadUsers() {
    const [users, sessions, tokens] = await Promise.all([A.api("GET", "/api/users"), A.api("GET", "/api/users/sessions"), A.api("GET", "/api/tokens")]);
    const now = Date.now() / 1000;
    $("#users-body").innerHTML = `<h5>사용자 <small>로컬 계정 + AD/LDAP(로그인 시 그룹 → 역할 동기화)</small></h5>
      <table><thead><tr><th>아이디</th><th>이름</th><th>역할</th><th>유형</th><th>상태</th><th>MFA</th><th>마지막 로그인</th><th>비밀번호 변경</th><th></th></tr></thead><tbody>${users.map(u => {
        const locked = u.locked_until && u.locked_until > now;
        const stt = u.disabled ? '<span class="label critical">비활성</span>' : locked ? `<span class="label warning">잠금(${Math.ceil((u.locked_until - now) / 60)}분)</span>` : u.must_change ? '<span class="label info">변경 필요</span>' : '<span class="label ok">정상</span>';
        return `<tr data-u="${esc(u.username)}"><td><b>${esc(u.username)}</b>${u.online ? ' <span class="online" title="접속 중">●</span>' : ""}</td><td>${esc(u.display || "")}</td>
          <td><select data-role ${u.username === A.me.user ? "disabled" : ""}>${Object.entries(ROLE_LABEL).map(([k, l]) => `<option value="${k}" ${u.role === k ? "selected" : ""}>${l}</option>`).join("")}</select></td>
          <td>${u.source === "ldap" ? "AD/LDAP" : u.source === "oidc" ? "SSO" : "로컬"}</td><td>${stt}${u.failed ? `<span class="sub">실패 ${u.failed}회</span>` : ""}</td>
          <td>${u.mfa ? `<span class="label ok">등록</span> <button class="btn-sm" data-ua="mfa" title="인증 앱 분실 시 — 해제 후 다음 로그인에서 다시 등록">해제</button>` : '<span class="label">없음</span>'}</td>
          <td>${u.last_login ? fmtDT(u.last_login) : "-"}<span class="sub">${esc(u.last_ip || "")}</span></td><td>${u.source === "local" ? fmtDT(u.pw_changed) : "-"}</td>
          <td class="nowrap">${locked || u.failed ? `<button class="btn-sm" data-ua="unlock">잠금 해제</button>` : ""}
            ${u.source === "local" ? `<button class="btn-sm" data-ua="reset">비밀번호 초기화</button>` : ""}
            ${u.username !== A.me.user ? `<button class="btn-sm" data-ua="${u.disabled ? "enable" : "disable"}">${u.disabled ? "활성화" : "비활성화"}</button><button class="btn-sm" data-ua="delete">삭제</button>` : ""}</td></tr>`; }).join("")}</tbody></table>
      <h5 style="margin-top:18px">접속 세션 <small>${sessions.length}개</small></h5>
      <table><thead><tr><th>사용자</th><th>역할</th><th>IP</th><th>로그인</th><th>방식</th><th>유휴</th><th>세션</th><th></th></tr></thead><tbody>${sessions.map(s => `<tr><td>${esc(s.user)}</td><td>${esc(ROLE_LABEL[s.role] || s.role)}</td><td class="mono">${esc(s.ip)}</td><td>${fmtDT(s.since)}</td><td>${esc(s.method || "password")}</td><td>${Math.floor(s.idle_sec / 60)}분 ${s.idle_sec % 60}초</td><td class="mono" title="${esc(s.ua || "")}">${esc(s.sid)}…</td><td><button class="btn-sm" data-sess="${esc(s.sid)}">종료</button></td></tr>`).join("")}</tbody></table>
      <h5 style="margin-top:18px">API 토큰 <small>연동용(ingest: 로그 수신 · metrics: Prometheus · read: 조회 API) — SHA-256 해시만 저장</small></h5>
      <table><thead><tr><th>이름</th><th>접두어</th><th>범위</th><th>허용 IP</th><th>발급</th><th>만료</th><th>마지막 사용</th><th>상태</th><th></th></tr></thead><tbody>${tokens.map(t => {
        const exp = t.expires && t.expires < now;
        return `<tr><td><b>${esc(t.name)}</b><span class="sub">${esc(t.created_by)}</span></td><td class="mono">${esc(t.prefix)}…</td><td>${JSON.parse(t.scopes || "[]").map(s => `<span class="label">${esc(s)}</span>`).join(" ")}</td><td class="mono">${esc(t.allow_ips || "제한 없음")}</td>
          <td>${fmtDT(t.created)}</td><td>${t.expires ? fmtDT(t.expires) : "무기한"}</td><td>${t.last_used ? ago(t.last_used) : "-"}</td>
          <td>${t.revoked ? '<span class="label critical">폐기</span>' : exp ? '<span class="label warning">만료</span>' : '<span class="label ok">유효</span>'}</td>
          <td>${t.revoked ? "" : `<button class="btn-sm" data-revoke="${t.id}">폐기</button>`}</td></tr>`; }).join("") || `<tr><td colspan="9"><div class="empty small">발급된 토큰 없음</div></td></tr>`}</tbody></table>`;
  }
  $("#nav-users").onclick = () => { open("drawer-users"); loadUsers(); };
  $("#users-body").addEventListener("change", async e => {
    const sel = e.target.closest("select[data-role]"); if (!sel) return;
    const u = sel.closest("tr").dataset.u;
    if (!await A.confirm("역할 변경", `${u} 의 역할을 '${ROLE_LABEL[sel.value]}'(으)로 변경합니다. 해당 사용자의 세션은 즉시 종료됩니다.`)) { loadUsers(); return; }
    try { await A.api("POST", `/api/users/${encodeURIComponent(u)}`, {role: sel.value}); A.ok("역할 변경"); } catch (err) { A.fail("변경 실패", err); }
    loadUsers();
  });
  $("#users-body").addEventListener("click", async e => {
    const sv = e.target.closest("[data-sess]");
    if (sv) { if (await A.confirm("세션 종료", `세션 ${sv.dataset.sess}… 을 강제로 종료합니다(해당 사용자는 다시 로그인해야 함).`, true)) { await A.api("DELETE", `/api/users/sessions/${sv.dataset.sess}`).catch(err => A.fail("종료 실패", err)); loadUsers(); } return; }
    const rv = e.target.closest("[data-revoke]");
    if (rv) { if (await A.confirm("토큰 폐기", "폐기한 토큰은 즉시 사용할 수 없으며 되돌릴 수 없습니다.", true)) { await A.api("DELETE", `/api/tokens/${rv.dataset.revoke}`).catch(err => A.fail("폐기 실패", err)); loadUsers(); } return; }
    const b = e.target.closest("[data-ua]"); if (!b) return;
    const u = b.closest("tr").dataset.u, k = b.dataset.ua;
    try {
      if (k === "delete") { if (!await A.confirm("사용자 삭제", `${u} 계정을 삭제합니다.`, true)) return; await A.api("DELETE", `/api/users/${encodeURIComponent(u)}`); }
      else if (k === "mfa") { if (!await A.confirm("MFA 해제", `${u} 의 2단계 인증을 해제합니다. 필수 역할이면 다음 로그인 때 다시 등록해야 합니다.`, true)) return; await A.api("DELETE", `/api/users/${encodeURIComponent(u)}/mfa`); }
      else if (k === "reset") {
        if (!await A.confirm("비밀번호 초기화", `${u} 의 임시 비밀번호를 발급합니다(다음 로그인 시 변경 강제).`)) return;
        const r = await A.api("POST", `/api/users/${encodeURIComponent(u)}`, {reset_password: true});
        await A.modal({title: "임시 비밀번호", html: `<p class="modal-text">${esc(u)} 의 임시 비밀번호입니다. 안전한 경로로 전달하세요. 이 창을 닫으면 다시 볼 수 없습니다.</p><pre class="secret">${esc(r.temp_password)}</pre>`, ok: "", cancel: "닫기"});
      } else await A.api("POST", `/api/users/${encodeURIComponent(u)}`, k === "unlock" ? {unlock: true} : {disabled: k === "disable"});
      A.ok("처리 완료");
    } catch (err) { A.fail("처리 실패", err); }
    loadUsers();
  });
  $("#user-new").onclick = async () => {
    const v = await A.modal({title: "로컬 사용자 추가", fields: [{id: "username", label: "아이디(영문 소문자·숫자·._-)", required: true},
      {id: "display", label: "이름"}, {id: "email", label: "이메일"},
      {id: "role", label: "역할", type: "select", value: "viewer", options: Object.entries(ROLE_LABEL)},
      {id: "password", label: "초기 비밀번호(비우면 자동 생성)", type: "password"}], ok: "추가"});
    if (!v) return;
    try {
      const r = await A.api("POST", "/api/users", v);
      if (r.initial_password) await A.modal({title: "초기 비밀번호", html: `<p class="modal-text">${esc(v.username)} 의 초기 비밀번호입니다(최초 로그인 시 변경 강제). 이 창을 닫으면 다시 볼 수 없습니다.</p><pre class="secret">${esc(r.initial_password)}</pre>`, ok: "", cancel: "닫기"});
      else A.ok("사용자 추가");
    } catch (e) { A.fail("추가 실패", e); }
    loadUsers();
  };
  $("#token-new").onclick = async () => {
    const v = await A.modal({title: "API 토큰 발급", fields: [{id: "name", label: "이름(용도)", required: true, placeholder: "예) fluentbit-dc1 / prometheus"},
      {id: "ingest", label: "ingest — /api/ingest 로그 수신", type: "checkbox", value: true}, {id: "metrics", label: "metrics — /metrics Prometheus", type: "checkbox"},
      {id: "read", label: "read — 조회 API(GET)", type: "checkbox"}, {id: "days", label: "유효기간(일, 0=무기한)", type: "number", value: 365, min: 0},
      {id: "allow_ips", label: "허용 IP/CIDR(쉼표 구분, 비우면 제한 없음)", placeholder: "예) 10.10.0.0/24, 192.168.1.20"}], ok: "발급"});
    if (!v) return;
    try {
      const r = await A.api("POST", "/api/tokens", {name: v.name, days: v.days ?? 365, scopes: ["ingest", "metrics", "read"].filter(s => v[s]), allow_ips: v.allow_ips || ""});
      await A.modal({title: "발급된 토큰", html: `<p class="modal-text">이 값은 다시 표시되지 않습니다. 연동 대상의 비밀 저장소에 보관하세요.<br>사용: <code>Authorization: Bearer &lt;토큰&gt;</code></p><pre class="secret">${esc(r.token)}</pre>`, ok: "", cancel: "닫기"});
    } catch (e) { A.fail("발급 실패", e); }
    loadUsers();
  };

  // ================================================================ 운영 설정
  const set = {tab: "connectors", schema: null, cache: {}};
  const getP = (o, p) => p.split(".").reduce((x, k) => (x == null ? undefined : x[k]), o);
  const setP = (o, p, v) => { const ks = p.split("."); let x = o; ks.slice(0, -1).forEach(k => { if (x[k] == null || typeof x[k] !== "object") x[k] = {}; x = x[k]; }); x[ks.at(-1)] = v; };
  // 폼 명세: p 경로, t 유형(text|password|number|bool|select|list|rows|json), l 라벨, o 선택지, h 도움말
  const FORMS = {
    alerting: [
      {p: "min_severity", t: "select", l: "알림 최소 심각도", o: SEVS},
      {p: "cooldown", t: "number", l: "같은 유형 재알림 간격(초)"},
      {p: "require_llm_confirm", t: "bool", l: "AI가 이상으로 판정한 건만 알림"},
      {p: "webhooks", t: "rows", l: "웹훅·온콜(Teams·Slack·일반 JSON·PagerDuty·Opsgenie) — PagerDuty/Opsgenie 는 URL 비우고 키만 입력(Integration Key·GenieKey)", cols: [{p: "name", l: "이름"}, {p: "format", l: "형식", t: "select", o: ["teams", "slack", "generic", "pagerduty", "opsgenie"]}, {p: "url", l: "URL(PagerDuty·Opsgenie 는 선택)", w: 2}, {p: "secret", l: "키(PagerDuty·Opsgenie)"}]},
      {sec: "라우팅 정책 — 위에서부터 첫 일치. 비우면 모든 채널로 발송. 채널은 웹훅 이름 또는 smtp"},
      {p: "routes", t: "rows", l: "규칙", cols: [{p: "name", l: "이름"}, {p: "severities", l: "심각도(쉼표)"}, {p: "sources", l: "소스(쉼표)"}, {p: "hours", l: "시간대(09:00-18:00)"}, {p: "days", l: "요일(0=월,쉼표)"}, {p: "channels", l: "채널(쉼표)", w: 2}]},
      {p: "default_channels", t: "list", l: "어느 규칙에도 안 맞을 때 채널(줄 단위, 비우면 전체)"},
      {sec: "SMTP 메일"},
      {p: "smtp.enabled", t: "bool", l: "메일 발송 사용"}, {p: "smtp.host", l: "SMTP 서버"}, {p: "smtp.port", t: "number", l: "포트"},
      {p: "smtp.starttls", t: "bool", l: "STARTTLS"}, {p: "smtp.username", l: "계정"}, {p: "smtp.password", t: "password", l: "비밀번호"},
      {p: "smtp.from", l: "보내는 주소"}, {p: "smtp.to", t: "list", l: "받는 주소(줄 단위)"}],
    siem: [
      {p: "enabled", t: "bool", l: "SIEM 전달 사용(CEF over syslog)"},
      {p: "host", l: "SIEM 수신 호스트(Splunk HEC 아님 — syslog 수신기)"}, {p: "port", t: "number", l: "포트(514 / TLS 6514)"},
      {p: "protocol", t: "select", l: "프로토콜", o: ["udp", "tcp", "tls"]},
      {p: "verify_tls", t: "bool", l: "TLS 인증서 검증"}, {p: "ca_file", l: "사내 CA 파일(PEM, 선택)"},
      {sec: "보낼 항목"},
      {p: "audit", t: "bool", l: "감사 로그(인증·설정·조치·사용자)"}, {p: "anomalies", t: "bool", l: "이상징후(아래 등급 이상)"},
      {p: "min_severity", t: "select", l: "이상징후 최소 심각도", o: SEVS}, {p: "incidents", t: "bool", l: "인시던트 생성·상태 변경"}],
    web_search: [
      {p: "enabled", t: "bool", l: "AI 질의 웹 검색 사용(공개 웹 근거 [W#])"},
      {p: "provider", t: "select", l: "검색 공급자", o: [["searxng", "SearXNG(사내 설치·키 불필요 — 권장)"], ["brave", "Brave Search API"], ["tavily", "Tavily Search API"]]},
      {p: "url", l: "SearXNG 주소(예: http://searxng.corp:8080 — settings.yml search.formats 에 json 허용)"},
      {p: "api_key", t: "password", l: "API 키(Brave·Tavily)"},
      {p: "proxy", l: "외부 접속 프록시(예: http://proxy.corp:3128, 비우면 직접)"}, {p: "verify_tls", t: "bool", l: "TLS 인증서 검증"},
      {p: "mode", t: "select", l: "검색 시점", o: [["auto", "자동 — 사내 KB 근거가 부족할 때(또는 화면에서 켤 때)"], ["always", "항상"], ["manual", "수동 — 질의 화면에서 '웹 검색'을 켤 때만"]]},
      {p: "min_kb_refs", t: "number", l: "자동 모드 — 사내 KB 근거가 이 수 미만이면 웹 검색"},
      {sec: "결과·범위"},
      {p: "max_results", t: "number", l: "검색 결과 수(1~20)"}, {p: "fetch_pages", t: "number", l: "본문을 읽을 상위 페이지 수(0~6)"},
      {p: "max_chars_per_page", t: "number", l: "페이지당 AI 에 넣는 최대 글자"}, {p: "timeout", t: "number", l: "시간 제한(초)"},
      {p: "cache_minutes", t: "number", l: "같은 검색어 결과 재사용(분)"}, {p: "language", l: "검색 언어(예: en, ko — 비우면 공급자 기본)"},
      {p: "product_hint", l: "검색어에 제품명이 없을 때 앞에 붙일 말(기본 VMware)"},
      {p: "prefer_domains", t: "list", l: "우선 도메인(줄 단위 — 결과에서 먼저, 하위 도메인 포함)"},
      {p: "only_preferred", t: "bool", l: "우선 도메인 결과만 사용"},
      {p: "block_domains", t: "list", l: "제외 도메인(줄 단위)"}],
    incidents: [
      {p: "enabled", t: "bool", l: "인시던트 자동 생성"},
      {p: "min_severity", t: "select", l: "인시던트화 최소 심각도", o: SEVS},
      {p: "correlation_window", t: "number", l: "상관 병합 창(초) — 같은 클러스터/호스트에서 이 시간 내 발생 시 병합"},
      {sec: "SLA 목표(분)"},
      ...["critical", "error", "warning"].flatMap(s => [{p: `sla.${s}.ack`, t: "number", l: `${s} — 접수`}, {p: `sla.${s}.resolve`, t: "number", l: `${s} — 해결`}])],
    itsm: [
      {p: "type", t: "select", l: "연동 방식", o: [["none", "사용 안 함"], ["servicenow", "ServiceNow Table API"], ["webhook", "일반 웹훅"]]},
      {p: "min_severity", t: "select", l: "자동 티켓 생성 최소 심각도", o: SEVS},
      {sec: "ServiceNow"},
      {p: "servicenow.instance", l: "인스턴스 URL(https://xxx.service-now.com)"}, {p: "servicenow.table", l: "테이블(기본 incident)"},
      {p: "servicenow.username", l: "연동 계정"}, {p: "servicenow.password", t: "password", l: "비밀번호"}, {p: "servicenow.token", t: "password", l: "또는 OAuth Bearer 토큰"},
      {p: "servicenow.assignment_group", l: "배정 그룹(sys_id 또는 이름)"}, {p: "servicenow.caller_id", l: "Caller"}, {p: "servicenow.cmdb_ci", l: "CMDB CI"},
      {p: "servicenow.category", l: "Category"}, {p: "servicenow.close_code", l: "해결 코드(close_code)"}, {p: "servicenow.verify_tls", t: "bool", l: "TLS 인증서 검증"},
      {sec: "일반 웹훅"},
      {p: "webhook.url", l: "URL"}, {p: "webhook.headers", t: "json", l: "헤더(JSON)"}, {p: "webhook.verify_tls", t: "bool", l: "TLS 인증서 검증"}],
    actions: [
      {p: "enabled", t: "bool", l: "조치 기능 사용"},
      {p: "approval_min_level", t: "select", l: "승인 필요 위험도", o: [["2", "L2 이상(모든 조치)"], ["3", "L3 이상(유지보수 모드·통합·서비스 재시작)"], ["9", "승인 없음(권장하지 않음)"]], num: true},
      {p: "approval_ttl_hours", t: "number", l: "승인 유효시간(시간)"},
      {p: "deny_environments", t: "list", l: "쓰기 조치 차단 환경(줄 단위, 예: prod)"},
      {p: "task_timeout", t: "number", l: "vCenter 작업 대기 한도(초)"}],
    reports: [
      {sec: "일간"}, {p: "daily.enabled", t: "bool", l: "일간 리포트"}, {p: "daily.time", l: "발송 시각(HH:MM)"}, {p: "daily.recipients", t: "list", l: "수신자(줄 단위)"},
      {sec: "주간"}, {p: "weekly.enabled", t: "bool", l: "주간 리포트"}, {p: "weekly.weekday", t: "select", l: "요일", o: [["0", "월"], ["1", "화"], ["2", "수"], ["3", "목"], ["4", "금"], ["5", "토"], ["6", "일"]], num: true},
      {p: "weekly.time", l: "발송 시각(HH:MM)"}, {p: "weekly.recipients", t: "list", l: "수신자(줄 단위)"},
      {sec: "월간(지난달 전체 — 정산·용량·적정화·보안 판독 포함)"}, {p: "monthly.enabled", t: "bool", l: "월간 리포트"}, {p: "monthly.day", t: "number", l: "발송일(1~28)"},
      {p: "monthly.time", l: "발송 시각(HH:MM)"}, {p: "monthly.recipients", t: "list", l: "수신자(줄 단위)"},
      {sec: "공통"}, {p: "ai_summary", t: "bool", l: "AI 요약 포함(Gemma 4 31B)"}, {p: "keep_days", t: "number", l: "리포트 보관(일)"}],
    knowledge: [
      {p: "enabled", t: "bool", l: "KB·TechDocs 라이브러리 사용(AI 분석·질의·관제 개체 상세 근거)"},
      {p: "paths", t: "list", l: "md 아카이브 폴더(줄 단위, NFS/SMB 마운트 가능 — 하위 폴더 전체)"},
      {p: "scan_interval", t: "number", l: "증분 색인 주기(초)"}, {p: "embed", t: "bool", l: "임베딩 벡터 생성(rag.embedding 켜진 경우)"},
      {sec: "검색·답변"},
      {p: "top_k", t: "number", l: "이상징후 1건당 문서 수"}, {p: "min_relevance", t: "number", step: "0.05", l: "최소 관련도(0~1)"},
      {p: "max_chars_per_ref", t: "number", l: "문서 1건이 AI에 들어가는 최대 글자"},
      {p: "auto_link", t: "bool", l: "근거 없는 이상징후·인시던트에 비슷한 KB 자동 연결"}, {p: "link_min_relevance", t: "number", step: "0.05", l: "자동 연결 최소 관련도(0~1)"},
      {p: "link_top_k", t: "number", l: "이상징후당 자동 연결 문서 수"},
      {p: "vendors", t: "list", l: "우선 사업부(front matter vendor — 그 외 ca·symantec 등은 순위 낮춤)"},
      {p: "languages", t: "list", l: "우선 언어(en·ko — 일본어 번역본 등은 순위 낮춤)"},
      {sec: "파싱"},
      {p: "skip_dirs", t: "list", l: "추가 제외 폴더명(_catalog·_changes·_rag 등 _·. 시작 폴더는 항상 제외)"},
      {p: "chunk_size", t: "number", l: "청크 크기(글자)"}, {p: "chunk_overlap", t: "number", l: "청크 겹침(글자)"},
      {p: "max_file_mb", t: "number", l: "파일 최대(MB)"}, {p: "max_upload_gb", t: "number", step: "0.5", l: "zip 업로드 최대(GB)"}],
    backup: [{p: "enabled", t: "bool", l: "야간 DB 백업"}, {p: "time", l: "시각(HH:MM)"}, {p: "keep", t: "number", l: "보관 개수"}, {p: "dir", l: "백업 폴더"}],
    monitoring: [
      {p: "active_window", t: "number", l: "'수집 중' 판정 창(초)"}, {p: "check_interval", t: "number", l: "점검 주기(초)"},
      {p: "alert_on_stop", t: "bool", l: "중단·오류·미수신 전환 시 알림"},
      {sec: "유형별 허용 침묵(초, 0=감시 안 함)"},
      {p: "max_silence.syslog", t: "number", l: "Syslog"}, {p: "max_silence.ingest", t: "number", l: "HTTP 수집"}, {p: "max_silence.snmp", t: "number", l: "SNMP"}, {p: "max_silence.vcflogs", t: "number", l: "VCF Logs"},
      {p: "expected", t: "rows", l: "반드시 들어와야 하는 송신 장비", cols: [{p: "name", l: "이름"}, {p: "kind", l: "유형", t: "select", o: ["syslog", "snmp", "ingest"]}, {p: "match", l: "매칭(정규식: 호스트·IP)", w: 2}, {p: "max_silence", l: "허용 침묵(초)", t: "number"}]}],
    detection: [
      {p: "llm_threshold", t: "number", l: "AI 분석 대상 점수 임계값(0~1)", step: "0.05"}, {p: "warmup_seconds", t: "number", l: "신규 패턴 학습 시간(초)"},
      {p: "burst_z", t: "number", l: "급증 판정 Z-score", step: "0.1"}, {p: "burst_min_count", t: "number", l: "급증 최소 건수(분)"},
      {p: "dedupe_window", t: "number", l: "중복 병합 창(초)"},
      {p: "extra_rules", t: "rows", l: "추가 탐지 규칙", cols: [{p: "name", l: "이름"}, {p: "pattern", l: "정규식", w: 2}, {p: "category", l: "유형"}, {p: "severity", l: "심각도", t: "select", o: SEVS}, {p: "weight", l: "가중치", t: "number"}]},
      {p: "suppress", t: "list", l: "무시할 로그 정규식(줄 단위)"}],
  };
  function fieldHtml(f, val, prefix = "") {
    if (f.sec) return `<div class="fsec">${esc(f.sec)}</div>`;
    const id = `${prefix}${f.p}`, v = getP(val, f.p) ?? f.d;
    let inp;
    if (f.t === "bool") inp = `<button type="button" class="switch ${v ? "on" : ""}" data-f="${esc(id)}" data-t="bool"></button>`;
    else if (f.t === "select") inp = `<select data-f="${esc(id)}" data-t="select" ${f.num ? 'data-num="1"' : ""}>${f.o.map(o => { const [a, b] = Array.isArray(o) ? o : [o, o]; return `<option value="${esc(a)}" ${String(v ?? "") === String(a) ? "selected" : ""}>${esc(b)}</option>`; }).join("")}</select>`;
    else if (f.t === "list") inp = `<textarea data-f="${esc(id)}" data-t="list" rows="3">${esc((v || []).join("\n"))}</textarea>`;
    else if (f.t === "json") inp = `<textarea data-f="${esc(id)}" data-t="json" rows="3" class="mono">${esc(v == null ? "" : JSON.stringify(v, null, 1))}</textarea>`;
    else if (f.t === "rows") {
      const rows = Array.isArray(v) ? v : [];
      return `<div class="frow full"><span class="fl">${esc(f.l)}</span><div class="rows" data-f="${esc(id)}" data-t="rows">
        <table><thead><tr>${f.cols.map(c => `<th>${esc(c.l)}</th>`).join("")}<th></th></tr></thead><tbody>${rows.map(r => rowEdit(f, r)).join("")}</tbody></table>
        <button type="button" class="btn-sm" data-addrow="${esc(id)}">행 추가</button></div></div>`;
    } else inp = `<input data-f="${esc(id)}" data-t="${f.t || "text"}" type="${f.t === "number" ? "number" : f.t === "password" ? "password" : "text"}" ${f.step ? `step="${f.step}"` : ""} value="${esc(v ?? "")}" ${f.t === "password" ? 'autocomplete="new-password" placeholder="변경 시에만 입력"' : ""}>`;
    return `<label class="frow"><span class="fl">${esc(f.l)}</span>${inp}${f.h ? `<small class="fh">${esc(f.h)}</small>` : ""}</label>`;
  }
  function rowEdit(f, r = {}) {
    return `<tr>${f.cols.map(c => `<td class="${c.w ? "w2" : ""}">${c.t === "select" ? `<select data-c="${c.p}">${c.o.map(o => `<option ${String(r[c.p] ?? "") === String(o) ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`
      : `<input data-c="${c.p}" ${c.t === "number" ? 'type="number" data-num="1" step="any"' : ""} value="${esc(r[c.p] ?? "")}">`}</td>`).join("")}<td><button type="button" class="x" data-delrow>✕</button></td></tr>`;
  }
  function collectForm(box, spec, base) {
    const out = JSON.parse(JSON.stringify(base || {}));
    for (const f of spec) {
      if (f.sec) continue;
      const el = box.querySelector(`[data-f="${CSS.escape(f.p)}"]`); if (!el) continue;
      let v;
      if (f.t === "bool") v = el.classList.contains("on");
      else if (f.t === "number") v = el.value === "" ? null : Number(el.value);
      else if (f.t === "select") v = f.num ? Number(el.value) : el.value;
      else if (f.t === "list") v = el.value.split(/\n/).map(x => x.trim()).filter(Boolean);
      else if (f.t === "json") { try { v = el.value.trim() ? JSON.parse(el.value) : {}; } catch { throw new Error(`'${f.l}' JSON 형식 오류`); } }
      else if (f.t === "rows") v = [...el.querySelectorAll("tbody tr")].map(tr => { const o = {}; tr.querySelectorAll("[data-c]").forEach(i => { if (i.value !== "") o[i.dataset.c] = i.dataset.num ? Number(i.value) : i.value; }); return o; }).filter(o => Object.keys(o).length);
      else v = el.value;
      if (f.t === "password" && v === "") v = getP(base, f.p) ? "********" : "";
      if (v === null) continue;
      setP(out, f.p, v);
    }
    return out;
  }
  function wireForm(box, spec) {
    box.addEventListener("click", e => {
      const sw = e.target.closest(".switch[data-t=bool]"); if (sw) sw.classList.toggle("on");
      const add = e.target.closest("[data-addrow]");
      if (add) { const f = spec.find(x => x.p === add.dataset.addrow); add.previousElementSibling.querySelector("tbody").insertAdjacentHTML("beforeend", rowEdit(f)); }
      const del = e.target.closest("[data-delrow]"); if (del) del.closest("tr").remove();
    });
  }
  async function renderSettings() {
    $$("#set-tabs button").forEach(b => b.classList.toggle("on", b.dataset.t === set.tab));
    const box = $("#set-body");
    box.innerHTML = `<div class="empty"><span class="spin"></span></div>`;
    set.schema = set.schema || await A.api("GET", "/api/settings/schema");
    if (set.tab === "connectors") return renderConnectors(box);
    if (set.tab === "maint") return renderMaint(box);
    if (set.tab === "ai" && window.AIOPS_AI_SETTINGS) { await window.AIOPS_AI_SETTINGS(box); set.cache.llm = (await A.api("GET", "/api/settings/llm")).value || {}; return; }
    const keys = set.tab === "reports" ? ["reports", "backup"] : [set.tab];
    const data = {};
    for (const k of keys) data[k] = await A.api("GET", `/api/settings/${k}`);
    if (data.alerting && data.alerting.value && data.alerting.value.routes) data.alerting.value.routes = routesIn(data.alerting.value.routes);
    box.innerHTML = keys.map(k => { const d = data[k];
      return `<form class="sform" data-key="${k}"><div class="sform-head"><h5>${k === "backup" ? "DB 백업" : $(`#set-tabs [data-t=${set.tab}]`).textContent}</h5>
        <small>${d.managed ? `화면 설정 적용 중 · ${esc(d.updated_by || "")} ${fmtDT(d.updated)}` : "config.yaml 값 사용 중"}</small>
        <span class="gap"></span>${k === "itsm" ? `<button type="button" class="btn-sm" data-itsm-test>연결 시험</button>` : ""}${k === "siem" ? `<button type="button" class="btn-sm" data-siem-test>테스트 전송</button>` : ""}${k === "web_search" ? `<button type="button" class="btn-sm" data-web-test>검색 시험</button>` : ""}
        <button type="button" class="btn-sm" data-json="${k}">JSON 편집</button>${d.managed ? `<button type="button" class="btn-sm" data-reset="${k}">config.yaml 값으로 복원</button>` : ""}<button class="btn-sm solid">저장·적용</button></div>
        <div class="fgrid">${FORMS[k].map(f => fieldHtml(f, d.value || {})).join("")}</div></form>`; }).join("");
    $$(".sform", box).forEach(form => {
      const k = form.dataset.key; wireForm(form, FORMS[k]); set.cache[k] = data[k].value || {};
      form.onsubmit = async e => {
        e.preventDefault();
        let value; try { value = collectForm(form, FORMS[k], set.cache[k]); } catch (err) { A.fail("입력 오류", err); return; }
        await saveKey(k, value);
      };
    });
  }
  const ROUTE_LISTS = ["severities", "sources", "categories", "connectors", "channels", "days"];
  function routesOut(v) { return (v || []).map(r => { const o = {...r}; ROUTE_LISTS.forEach(k => { if (typeof o[k] === "string") o[k] = o[k].split(",").map(x => x.trim()).filter(Boolean).map(x => k === "days" ? Number(x) : x); }); return o; }); }
  function routesIn(v) { return (v || []).map(r => { const o = {...r}; ROUTE_LISTS.forEach(k => { if (Array.isArray(o[k])) o[k] = o[k].join(","); }); return o; }); }
  async function saveKey(k, value) {
    if (k === "alerting" && value && value.routes) value.routes = routesOut(value.routes);
    try { const r = await A.api("PUT", `/api/settings/${k}`, {value}); A.ok(`'${k}' 저장·적용`, r.applied && Object.keys(r.applied).length ? JSON.stringify(r.applied) : "즉시 반영되었습니다."); renderSettings(); }
    catch (err) { A.fail("저장 실패", err); }
  }
  $("#set-body").addEventListener("click", async e => {
    const j = e.target.closest("[data-json]"), rs = e.target.closest("[data-reset]"), it = e.target.closest("[data-itsm-test]"), sm = e.target.closest("[data-siem-test]");
    const wt = e.target.closest("[data-web-test]");
    if (wt) {
      const form = wt.closest("form"); let value; try { value = collectForm(form, FORMS.web_search, set.cache.web_search); } catch (err) { A.fail("입력 오류", err); return; }
      wt.disabled = true;
      const r = await A.api("POST", "/api/settings/web_search/test", {value}).catch(err => ({ok: false, detail: err.message}));
      wt.disabled = false;
      if (r.ok) A.toast(`웹 검색 시험 — ${r.count}건 · ${r.ms}ms`, `검색어: ${r.query}\n` + (r.results || []).map(x => `· ${x.title} — ${x.url}`).join("\n"), "ok", 15000);
      else A.fail("웹 검색 실패", r.detail || JSON.stringify(r));
    }
    if (sm) {
      const form = sm.closest("form"); let value; try { value = collectForm(form, FORMS.siem, set.cache.siem); } catch (err) { A.fail("입력 오류", err); return; }
      sm.disabled = true;
      const r = await A.api("POST", "/api/settings/siem/test", {value}).catch(err => ({ok: false, detail: err.message}));
      sm.disabled = false; r.ok ? A.ok("SIEM 테스트 전송", r.detail || "") : A.fail("SIEM 전송 실패", r.detail || JSON.stringify(r));
      if (r.sample) A.toast("CEF 샘플", r.sample, "info", 12000);
    }
    if (j) {
      const k = j.dataset.json;
      const v = await A.modal({title: `${k} — JSON 편집`, wide: true, fields: [{id: "j", label: "값(비밀값은 ******** 그대로 두면 유지)", type: "textarea", rows: 22, value: JSON.stringify(set.cache[k], null, 2)}], ok: "저장·적용"});
      if (!v) return;
      let val; try { val = JSON.parse(v.j); } catch (err) { A.fail("JSON 형식 오류", err); return; }
      saveKey(k, val);
    }
    if (rs) { if (!await A.confirm("복원", `'${rs.dataset.reset}' 화면 설정을 삭제하고 config.yaml 값으로 되돌립니다.`)) return;
      try { await A.api("POST", `/api/settings/${rs.dataset.reset}/reset`); A.ok("복원 완료"); renderSettings(); } catch (err) { A.fail("복원 실패", err); } }
    if (it) {
      const form = it.closest("form"); let value; try { value = collectForm(form, FORMS.itsm, set.cache.itsm); } catch (err) { A.fail("입력 오류", err); return; }
      it.disabled = true;
      const r = await A.api("POST", "/api/settings/itsm/test", {value}).catch(err => ({ok: false, detail: err.message}));
      it.disabled = false; r.ok ? A.ok("ITSM 연결 정상", r.detail || "") : A.fail("ITSM 연결 실패", r.detail || JSON.stringify(r));
    }
  });
  $("#set-tabs").addEventListener("click", e => { const b = e.target.closest("button"); if (!b) return; set.tab = b.dataset.t; renderSettings(); });
  $("#nav-set").onclick = () => { open("drawer-set"); renderSettings(); };
  window.AIOPS_OPEN_INCIDENT = openIncident;
  window.AIOPS_OPEN_CONNECTORS = () => { set.tab = "connectors"; open("drawer-set"); renderSettings(); };
  window.AIOPS_OPEN_SETTINGS = tab => { set.tab = tab || "connectors"; open("drawer-set"); renderSettings(); };

  // ---- 커넥터(등록·자동 발견·수신기 + 실시간 상태·연결 시험을 한 화면에)
  const ckHtml = ck => Object.entries(ck || {}).map(([k, v]) => `<div class="${String(v).startsWith("ok") || v === true ? "" : String(v).startsWith("warn") ? "warn" : "bad"}">${esc(k)}: ${esc(v)}</div>`).join("");
  const stCell = lv => lv ? `<span class="st ${esc(lv.state)}">${esc(lv.state)}</span>${lv.latency_ms != null ? ` <small>${lv.latency_ms}ms</small>` : ""}` : `<span class="muted">-</span>`;
  const detRow = (lv, res, cols) => {
    const ck = (res && res.checks) || (lv && lv.checks) || {};
    const err = (res && res.error) || (lv && lv.last_error) || "";
    if (!Object.keys(ck).length && !err) return "";
    return `<tr class="cn-det"><td colspan="${cols}"><div class="checks">${ckHtml(ck)}${err ? `<div class="bad">${esc(err)}</div>` : ""}</div></td></tr>`;
  };
  async function renderConnectors(box, results = {}) {
    const [d, liveArr, disc] = await Promise.all([A.api("GET", "/api/settings/connectors"), A.api("GET", "/api/connectors").catch(() => []),
      A.api("GET", "/api/connectors/discovered").catch(() => ({items: [], excluded: []}))]);
    const list = d.value || [];
    set.cache.connectors = list; set.cache.disc = disc;
    const live = {}; liveArr.forEach(c => { live[c.name] = c; });
    const types = set.schema.connector_types;
    const discNames = new Set(disc.items.map(x => x.name));
    const recv = liveArr.filter(c => ["syslog", "snmp"].includes(c.type));
    const demo = liveArr.filter(c => c.name.startsWith("demo"));
    const totalDown = liveArr.filter(c => c.state === "down").length;
    const lvOf = c => live[c.name] || (c.hosts ? live[String(c.hosts[0] || "").split(".")[0]] : null);
    box.innerHTML = `<div class="sform-head"><h5>커넥터 <small>등록 ${list.length} · 자동 발견 ${disc.items.length} · 수신기 ${recv.length}${totalDown ? ` · <b class="bad">오류 ${totalDown}</b>` : ""} — ${d.managed ? `화면 설정 적용 중 · ${esc(d.updated_by || "")} ${fmtDT(d.updated)}` : "config.yaml 값 사용 중"}</small></h5>
      <span class="gap"></span><select id="cn-type">${Object.entries(types).map(([k, t]) => `<option value="${k}">${esc(t.label)}</option>`).join("")}</select><button class="btn-sm solid" id="cn-add">커넥터 추가</button>
      <button class="btn-sm" id="cn-testall" data-perm="operate">전체 연결 시험</button><button class="btn-sm" id="cn-alerttest" data-perm="operate">알림 채널 시험</button>
      ${d.managed ? `<button class="btn-sm" data-reset="connectors">config.yaml 값으로 복원</button>` : ""}<button class="btn-sm" data-json="connectors">JSON 편집</button></div>
      <h6 class="cn-h">등록한 커넥터 <small>저장 시 변경된 커넥터만 재시작(Syslog·SNMP 수신기는 유지) · vCenter 를 지우면 그 vCenter 가 찾은 VKS 커넥터도 즉시 정리</small></h6>
      <table class="cn-t"><thead><tr><th>이름</th><th>유형</th><th>대상</th><th>환경</th><th>주기</th><th>상태</th><th>인증</th><th>이벤트</th><th>마지막 성공</th><th></th></tr></thead><tbody>${list.map((c, i) => {
        const lv = lvOf(c);
        return `<tr><td><b>${esc(c.name)}</b>${c.enabled === false ? ' <span class="label">꺼짐</span>' : ""}</td><td>${esc((types[c.type] || {}).label || c.type)}</td><td class="mono">${esc(c.host || (c.hosts || []).join(", "))}</td>
          <td>${c.environment ? `<span class="label ${c.environment === "prod" ? "critical" : ""}">${esc(c.environment)}</span>` : "-"}</td><td>${c.interval || "-"}</td>
          <td>${stCell(lv)}</td><td>${esc((lv && lv.auth) || "-")}</td><td>${lv ? (lv.events_total || 0).toLocaleString() : "-"}</td><td>${lv && lv.last_ok ? fmtDT(lv.last_ok) : "-"}</td>
          <td class="nowrap"><button class="btn-sm" data-ctest="${esc(c.name)}">시험</button> <button class="btn-sm" data-cedit="${i}">편집</button> <button class="btn-sm" data-cdel="${i}">삭제</button></td></tr>${detRow(lv, results[c.name], 10)}`; }).join("") || `<tr><td colspan="10"><div class="empty small">등록된 커넥터가 없습니다.</div></td></tr>`}</tbody></table>
      <h6 class="cn-h">자동 발견(VKS) <small>vCenter 커넥터가 찾은 Supervisor·워크로드 클러스터 — 편집 값은 다음 발견에도 유지, 삭제하면 다시 만들지 않음(아래에서 다시 포함)</small>
        <button class="btn-sm" id="cn-rediscover" data-perm="operate">지금 다시 찾기</button></h6>
      <table class="cn-t"><thead><tr><th>이름</th><th>역할</th><th>클러스터</th><th>발견한 vCenter</th><th>대상</th><th>상태</th><th>이벤트</th><th>마지막 성공</th><th></th></tr></thead><tbody>${disc.items.map(x => `<tr>
          <td><b>${esc(x.name)}</b>${Object.keys(x.override || {}).length ? ' <span class="label info" title="화면에서 바꾼 값 있음">편집됨</span>' : ""}${x.cfg.enabled === false ? ' <span class="label">꺼짐</span>' : ""}</td>
          <td>${x.role === "supervisor" ? "Supervisor" : "워크로드"}</td><td>${esc(x.cluster)}</td><td>${esc(x.discovered_by)}</td><td class="mono">${esc(x.target || x.cfg.host || "")}</td>
          <td>${stCell(x)}</td><td>${(x.events_total || 0).toLocaleString()}</td><td>${x.last_ok ? fmtDT(x.last_ok) : "-"}</td>
          <td class="nowrap"><button class="btn-sm" data-ctest="${esc(x.name)}">시험</button> <button class="btn-sm" data-dedit="${esc(x.name)}">편집</button> <button class="btn-sm" data-ddel="${esc(x.name)}">삭제</button></td></tr>${detRow(x, results[x.name], 9)}`).join("")
          || `<tr><td colspan="9"><div class="empty small">자동 발견된 VKS 클러스터가 없습니다(vCenter 커넥터의 'VKS 자동 발견'이 켜져 있으면 10분마다 찾습니다).</div></td></tr>`}</tbody></table>
      ${disc.excluded.length ? `<p class="small">제외됨: ${disc.excluded.map(n => `<span class="label">${esc(n)} <a href="#" data-dinc="${esc(n)}">다시 포함</a></span>`).join(" ")}</p>` : ""}
      <h6 class="cn-h">수신기 <small>장비가 보내는 syslog·SNMP 트랩(설정: syslog·snmp 탭)</small></h6>
      <table class="cn-t"><thead><tr><th>이름</th><th>유형</th><th>대상</th><th>상태</th><th>이벤트</th><th></th></tr></thead><tbody>${recv.concat(demo).map(c => `<tr><td><b>${esc(c.name)}</b></td><td>${esc(c.type)}</td><td class="mono">${esc(c.target || "")}</td><td>${stCell(c)}</td><td>${(c.events_total || 0).toLocaleString()}</td><td class="nowrap"><button class="btn-sm" data-ctest="${esc(c.name)}">시험</button></td></tr>${detRow(c, results[c.name], 6)}`).join("") || `<tr><td colspan="6"><div class="empty small">수신기 없음</div></td></tr>`}</tbody></table>`;
    $("#cn-add").onclick = () => editConnector(null, {type: $("#cn-type").value, enabled: true, verify_tls: false});
    box.querySelectorAll("[data-perm]").forEach(el => { el.hidden = !A.can(el.dataset.perm); });
    box.onclick = async e => {
      const ed = e.target.closest("[data-cedit]"), dl = e.target.closest("[data-cdel]"), ts = e.target.closest("[data-ctest]");
      const de = e.target.closest("[data-dedit]"), dd = e.target.closest("[data-ddel]"), di = e.target.closest("[data-dinc]");
      if (ed) editConnector(Number(ed.dataset.cedit), list[Number(ed.dataset.cedit)]);
      if (dl) { const c = list[Number(dl.dataset.cdel)]; if (!await A.confirm("커넥터 삭제", `'${c.name}' 커넥터를 삭제하고 수집을 중지합니다.${c.type === "vcenter" ? " 이 vCenter 가 찾은 VKS 커넥터도 함께 정리됩니다." : ""}`, true)) return;
        saveKey("connectors", list.filter((_, i) => i !== Number(dl.dataset.cdel))); }
      if (ts) { ts.textContent = "…"; ts.disabled = true;
        try { const r = await A.api("POST", `/api/connectors/${encodeURIComponent(ts.dataset.ctest)}/test`); renderConnectors(box, {...results, [ts.dataset.ctest]: r}); }
        catch (err) { A.fail("시험 실패", err); ts.textContent = "시험"; ts.disabled = false; } }
      if (de) editDiscovered(box, set.cache.disc.items.find(x => x.name === de.dataset.dedit));
      if (dd) { if (!await A.confirm("자동 발견 커넥터 삭제", `'${dd.dataset.ddel}' 수집을 중지하고 다음 발견에서도 다시 만들지 않습니다(아래 '다시 포함'으로 되돌릴 수 있음).`, true)) return;
        try { await A.api("DELETE", `/api/connectors/discovered/${encodeURIComponent(dd.dataset.ddel)}`); A.ok("삭제(제외)됨", dd.dataset.ddel); renderConnectors(box); } catch (err) { A.fail("삭제 실패", err); } }
      if (di) { e.preventDefault(); try { await A.api("POST", `/api/connectors/discovered/${encodeURIComponent(di.dataset.dinc)}/include`); A.ok("다시 포함", di.dataset.dinc); renderConnectors(box); } catch (err) { A.fail("실패", err); } }
      if (e.target.id === "cn-rediscover") { e.target.disabled = true; try { await A.api("POST", "/api/vks/discover"); } catch (err) { A.fail("발견 실패", err); } renderConnectors(box); }
      if (e.target.id === "cn-testall") { e.target.textContent = "시험 중…"; e.target.disabled = true;
        try { const r = await A.api("POST", "/api/connectors/test-all"); renderConnectors(box, r); } catch (err) { A.fail("전체 시험 실패", err); } }
      if (e.target.id === "cn-alerttest") { try { const r = await A.api("POST", "/api/alerts/test"); A.ok("시험 알림 발송", JSON.stringify(r).slice(0, 200)); } catch (err) { A.fail("알림 시험 실패", err); } }
    };
  }
  async function editDiscovered(box, x) {
    if (!x) return;
    const cur = {...x.cfg, ...(x.override || {})};
    const spec = [{p: "enabled", t: "bool", l: "사용"}, {p: "interval", t: "number", l: "수집 주기(초)"}, {p: "cluster_name", t: "text", l: "표시 이름"},
      {p: "environment", t: "text", l: "환경", h: "prod · dev 등 — 알림·화면 구분"}, {p: "problem_logs", t: "bool", l: "문제 파드 로그 자동 첨부"},
      {p: "log_namespaces", t: "list", l: "로그 수집 네임스페이스", h: "한 줄에 하나 · * = 전체"},
      {p: "username", t: "text", l: "계정(비우면 vCenter 커넥터 계정)"}, {p: "password", t: "password", l: "비밀번호(비우면 vCenter 커넥터 비밀번호)"},
      {p: "verify_tls", t: "bool", l: "TLS 인증서 검증"}];
    const base = {...cur, password: (x.override || {}).password ? "********" : ""};
    await A.modal({title: `자동 발견 커넥터 편집 — ${x.name}`, wide: true, ok: "저장·적용",
      html: `<p class="modal-text">이 값은 '${esc(x.discovered_by)}' 의 다음 자동 발견에도 유지됩니다. 비운 칸은 자동 발견 값(vCenter 커넥터 설정)을 씁니다.</p><form class="sform" id="dc-form"><div class="fgrid">${spec.map(f => fieldHtml(f, base)).join("")}</div>
        <div class="ax-bar"><button type="button" class="btn-sm" id="dc-reset">편집 값 지우기(자동 발견 값으로)</button></div></form>`,
      onOpen: m => {
        const form = m.querySelector("#dc-form"); wireForm(form, spec);
        m.querySelector("#dc-reset").onclick = async () => { try { await A.api("PUT", `/api/connectors/discovered/${encodeURIComponent(x.name)}`, {override: {}}); A.ok("편집 값 삭제", x.name); m.querySelector("[data-x]").click(); renderConnectors(box); } catch (err) { A.fail("실패", err); } };
        m.querySelector("[data-ok]").addEventListener("click", () => {
          const v = collectForm(form, spec, {}); const o = {};
          for (const f of spec) { const nv = v[f.p], ov = x.cfg[f.p]; if (nv === undefined || nv === "" || (f.t === "password" && (nv === "" || (nv === "********" && !(x.override || {}).password)))) continue;
            if (JSON.stringify(nv) !== JSON.stringify(ov) || (x.override || {})[f.p] !== undefined) o[f.p] = nv; }
          set._dc = o;
        }, {capture: true});
      }}).then(async v => {
        if (v === null || !set._dc) return;
        try { await A.api("PUT", `/api/connectors/discovered/${encodeURIComponent(x.name)}`, {override: set._dc}); A.ok("저장·적용", x.name); } catch (err) { A.fail("저장 실패", err); }
        set._dc = null; renderConnectors(box);
      });
  }
  // ---- 관리자 계정으로 수집 전용(읽기 전용) 계정 자동 생성
  const PROV = {
    vcenter: {user: "readonly@vsphere.local", admin: "administrator@vsphere.local", note: "SSO 사용자 + 읽기 전용 역할(System.* + Global.Diagnostics) + vCenter 루트 권한 + 네임스페이스 VIEW. 쓰기 권한이 하나라도 잡히면 권한을 회수하고 실패로 멈춥니다."},
    nsx: {user: "svc-aiops-ro", admin: "admin", note: "NSX 4.1+ 로컬 사용자(Auditor 역할) 생성·활성화·만료 해제. 4.0 이하는 내장 audit 계정을 활성화합니다."},
    vcfops: {user: "svc-aiops-ro", admin: "admin", note: "로컬 사용자 + ReadOnly 역할(모든 개체)."},
    vcflogs: {user: "svc-aiops-ro", admin: "admin", note: "로컬 사용자 + View Only Admin 역할(메일 등록 없이 비밀번호 직접 설정)."},
    sddc: {user: "readonly@vsphere.local", admin: "administrator@vsphere.local", note: "SDDC Manager 는 로컬 계정이 없어, 관리 도메인 vCenter 에서 먼저 만든 SSO 계정에 VIEWER 역할을 줍니다. 아래 '새 계정 비밀번호'에 그 SSO 계정 비밀번호를 넣으면 로그인까지 확인합니다."},
  };
  function provHtml(type) {
    const d = PROV[type];
    return `<details class="prov"><summary>관리자 계정으로 수집 전용 계정 만들기 <small>(읽기 전용 · 관리자 비밀번호는 저장하지 않음)</small></summary>
      <p class="hint">${esc(d.note)}</p>
      <div class="fgrid">
        <label class="frow"><span class="fl">관리자 계정</span><input id="pv-au" value="${esc(d.admin)}" autocomplete="off"></label>
        <label class="frow"><span class="fl">관리자 비밀번호</span><input id="pv-ap" type="password" autocomplete="new-password"></label>
        <label class="frow"><span class="fl">만들 계정</span><input id="pv-nu" value="${esc(d.user)}" autocomplete="off"></label>
        <label class="frow"><span class="fl">새 계정 비밀번호(선택)</span><input id="pv-np" type="password" autocomplete="new-password" placeholder="비우면 20자 무작위 생성"></label>
        <label class="frow chk"><input type="checkbox" id="pv-reset"> 이미 있으면 비밀번호 재설정</label>
        ${type === "vcenter" ? '<label class="frow chk"><input type="checkbox" id="pv-nodiag"> Global.Diagnostics 제외(ESXi 호스트 로그 API 조회 불가 → syslog 로)</label>' : ""}
      </div>
      <div class="ax-bar"><button type="button" class="btn-sm solid" id="pv-go">계정 만들고 위 계정 칸에 넣기</button><span id="pv-st"></span></div>
      <div id="pv-out"></div></details>`;
  }
  function wireProv(form, type) {
    const $f = s => form.querySelector(s);
    $f("#pv-go").onclick = async () => {
      const host = ($f('[data-f="host"]') || {}).value || "";
      if (!host.trim()) { A.fail("입력", new Error("먼저 위의 호스트(FQDN/IP)를 입력하세요")); return; }
      if (!$f("#pv-ap").value) { A.fail("입력", new Error("관리자 비밀번호를 입력하세요")); return; }
      const vt = $f('[data-f="verify_tls"]');
      const body = {type, host: host.trim(), admin_user: $f("#pv-au").value.trim(), admin_password: $f("#pv-ap").value,
        new_user: $f("#pv-nu").value.trim(), new_password: $f("#pv-np").value, reset_password: $f("#pv-reset").checked,
        no_diagnostics: !!($f("#pv-nodiag") && $f("#pv-nodiag").checked), verify_tls: !!(vt && vt.classList.contains("on"))};
      $f("#pv-st").innerHTML = '<span class="spin"></span> 생성·검증 중…'; $f("#pv-go").disabled = true;
      let r;
      try { r = await A.api("POST", "/api/connectors/provision", body); }
      catch (err) { $f("#pv-st").innerHTML = `<b class="no-mark">✗</b> ${esc(err.message)}`; $f("#pv-go").disabled = false; return; }
      $f("#pv-go").disabled = false; $f("#pv-ap").value = "";
      const ic = st => st.ok === true ? '<b class="ok-mark">✓</b>' : st.ok === false ? '<b class="no-mark">✗</b>' : '<b class="warn-mark">!</b>';
      $f("#pv-out").innerHTML = `<div class="checks">${(r.steps || []).map(st => `<div>${ic(st)} ${esc(st.step)} — ${esc(st.detail || "")}</div>`).join("")}${r.error ? `<div class="bad">${esc(r.error)}</div>` : ""}</div>`;
      if (r.ok) {
        const u = $f('[data-f="username"]'), p = $f('[data-f="password"]');
        if (u) u.value = r.username;
        if (p && r.password) p.value = r.password;
        $f("#pv-st").innerHTML = `<b class="ok-mark">✓</b> ${esc(r.username)} ${r.password ? "· 비밀번호를 위 칸에 넣었습니다 — '목록에 저장·적용'을 눌러야 반영" : "· 기존 비밀번호 유지(위 비밀번호 칸 직접 입력)"} (${r.elapsed_ms}ms)`;
      } else $f("#pv-st").innerHTML = `<b class="no-mark">✗ 실패</b>`;
    };
  }

  async function editConnector(idx, c) {
    const t = (set.schema.connector_types[c.type] || set.schema.connector_types.redfish);
    const spec = t.fields.map(f => ({p: f.f, t: f.t, l: f.label + (f.req ? " *" : ""), o: f.options, h: f.hint, d: f.default}));
    const base = {...c};
    await A.modal({title: `${t.label} — ${idx == null ? "추가" : "편집"}`, wide: true, ok: "목록에 저장·적용",
      html: `<form class="sform" id="cn-form"><div class="fgrid">${spec.map(f => fieldHtml(f, base)).join("")}</div>
        ${PROV[c.type] ? provHtml(c.type) : ""}
        <div class="ax-bar"><button type="button" class="btn-sm" id="cn-test">저장 전 연결 시험</button><span id="cn-test-r"></span></div></form>`,
      onOpen: m => {
        const form = m.querySelector("#cn-form"); wireForm(form, spec);
        const read = () => ({...collectForm(form, spec, base), type: c.type});
        if (PROV[c.type]) wireProv(form, c.type);
        m.querySelector("#cn-test").onclick = async () => {
          const out = m.querySelector("#cn-test-r"); out.innerHTML = `<span class="spin"></span> 인증·엔드포인트 점검 중…`;
          try { const r = await A.api("POST", "/api/settings/connectors/test", read());
            out.innerHTML = `${r.ok ? '<b class="ok-mark">✓ 정상</b>' : '<b class="no-mark">✗ 실패</b>'} ${r.latency_ms != null ? r.latency_ms + "ms" : ""}<div class="checks">${Object.entries(r.checks || {}).map(([k, v]) => `<div class="${String(v).startsWith("ok") || v === true ? "" : String(v).startsWith("warn") ? "warn" : "bad"}">${esc(k)}: ${esc(v)}</div>`).join("")}${r.error ? `<div class="bad">${esc(r.error)}</div>` : ""}</div>`;
          } catch (err) { out.innerHTML = `<b class="no-mark">✗</b> ${esc(err.message)}`; }
        };
        m.querySelector("[data-ok]").addEventListener("click", ev => {
          try { set._cn = read(); } catch (err) { ev.stopImmediatePropagation(); A.fail("입력 오류", err); }
        }, {capture: true});
      }}).then(v => {
        if (v === null || !set._cn) return;
        const list = [...(set.cache.connectors || [])];
        if (idx == null) list.push(set._cn); else list[idx] = set._cn;
        set._cn = null; saveKey("connectors", list);
      });
  }

  // ---- 유지보수 창 · 사일런스
  async function renderMaint(box) {
    const [ms, ss] = await Promise.all([A.api("GET", "/api/maintenance"), A.api("GET", "/api/silences?include_expired=true")]);
    const days = ["월", "화", "수", "목", "금", "토", "일"];
    box.innerHTML = `<div class="sform-head"><h5>유지보수 창 <small>기간·주간 반복 · 대상 범위 내 이상징후는 기록하되 알림·ITSM 생성 억제 (vCenter 유지보수 모드 호스트는 자동 억제)</small></h5><span class="gap"></span><button class="btn-sm solid" id="mt-add">유지보수 창 추가</button></div>
      <table><thead><tr><th>이름</th><th>일정</th><th>대상</th><th>상태</th><th>등록</th><th></th></tr></thead><tbody>${ms.map(m => `<tr><td><b>${esc(m.name)}</b></td>
        <td>${m.weekly ? `매주 ${(m.weekly.days && m.weekly.days.length ? m.weekly.days : [0, 1, 2, 3, 4, 5, 6]).map(i => days[i]).join("·")} ${esc(m.weekly.from)}~${esc(m.weekly.to)}` : `${fmtDT(m.start)} ~ ${fmtDT(m.end)}`}</td>
        <td>${[m.scope.hosts_regex ? `호스트 /${esc(m.scope.hosts_regex)}/` : "", (m.scope.clusters || []).length ? "클러스터 " + m.scope.clusters.map(esc).join(",") : "", (m.scope.sources || []).length ? "소스 " + m.scope.sources.map(esc).join(",") : ""].filter(Boolean).join(" · ") || "전체"}</td>
        <td>${!m.enabled ? '<span class="label">꺼짐</span>' : m.active ? '<span class="label warning">진행 중</span>' : '<span class="label">대기</span>'}</td><td>${esc(m.created_by)}<span class="sub">${fmtDT(m.created)}</span></td>
        <td class="nowrap"><button class="btn-sm" data-mtog="${m.id}">${m.enabled ? "끄기" : "켜기"}</button> <button class="btn-sm" data-mdel="${m.id}">삭제</button></td></tr>`).join("") || `<tr><td colspan="6"><div class="empty small">등록된 유지보수 창이 없습니다.</div></td></tr>`}</tbody></table>
      <div class="sform-head" style="margin-top:20px"><h5>사일런스 <small>메시지·호스트 정규식 또는 이상징후 카드의 '사일런스'(지문 일치) — 기한부 억제</small></h5><span class="gap"></span><button class="btn-sm solid" id="sl-add">사일런스 추가</button></div>
      <table><thead><tr><th>#</th><th>조건</th><th>사유</th><th>만료</th><th>등록</th><th></th></tr></thead><tbody>${ss.map(s => `<tr class="${s.active ? "" : "expired"}"><td>${s.id}</td>
        <td class="mono">${s.match.fingerprint ? `지문 ${esc(s.match.fingerprint.slice(0, 12))}… <span class="sub">${esc(s.match.sample || "")}</span>` : `msg /${esc(s.match.message_regex)}/${s.match.host_regex ? ` host /${esc(s.match.host_regex)}/` : ""}`}</td>
        <td>${esc(s.reason)}</td><td>${s.active ? `${fmtDT(s.until)} <span class="sub">${ago(Date.now() / 1000 - (s.until - Date.now() / 1000)).replace("전", "남음")}</span>` : "만료"}</td>
        <td>${esc(s.created_by)}<span class="sub">${fmtDT(s.created)}</span></td><td>${s.active ? `<button class="btn-sm" data-sexp="${s.id}">해제</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="6"><div class="empty small">사일런스 없음</div></td></tr>`}</tbody></table>`;
    $("#mt-add").onclick = async () => {
      const toLocal = d => new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      const v = await A.modal({title: "유지보수 창 추가", wide: true, fields: [
        {id: "name", label: "이름", required: true, placeholder: "예) 3월 정기점검 / CHG0012345"},
        {id: "mode", label: "일정 유형", type: "select", options: [["once", "기간 지정"], ["weekly", "주간 반복"]]},
        {id: "start", label: "시작(기간 지정)", type: "datetime-local", value: toLocal(new Date())}, {id: "end", label: "종료(기간 지정)", type: "datetime-local", value: toLocal(new Date(Date.now() + 4 * 3600000))},
        {id: "days", label: "요일(주간 반복, 예: 5,6 = 토·일 / 0=월)", placeholder: "비우면 매일"}, {id: "from", label: "시작 시각(HH:MM)", value: "22:00"}, {id: "to", label: "종료 시각(HH:MM)", value: "06:00"},
        {id: "hosts_regex", label: "대상 호스트·VM 정규식(비우면 전체)", placeholder: "^esx0[1-4]\\.|^vcsa"}, {id: "clusters", label: "대상 클러스터(쉼표)"}, {id: "sources", label: "대상 소스(쉼표: vcenter,esxi,nsx…)"}], ok: "추가"});
      if (!v) return;
      const csv = s => s ? s.split(/[,\s]+/).filter(Boolean) : [];
      const body = {name: v.name, enabled: true, scope: {hosts_regex: v.hosts_regex, clusters: csv(v.clusters), sources: csv(v.sources)}};
      if (v.mode === "weekly") body.weekly = {days: csv(v.days).map(Number), from: v.from, to: v.to};
      else { body.start = new Date(v.start).getTime() / 1000; body.end = new Date(v.end).getTime() / 1000; }
      try { await A.api("POST", "/api/maintenance", body); A.ok("유지보수 창 추가"); renderMaint(box); } catch (err) { A.fail("추가 실패", err); }
    };
    $("#sl-add").onclick = async () => {
      const v = await A.modal({title: "사일런스 추가", fields: [{id: "message_regex", label: "메시지 정규식", required: true, placeholder: "예) vSAN health.*(warning|yellow)"},
        {id: "host_regex", label: "호스트 정규식(선택)"}, {id: "hours", label: "기간(시간)", type: "number", value: 4, min: 0.25, step: 0.25}, {id: "reason", label: "사유", required: true}], ok: "추가"});
      if (!v) return;
      try { await A.api("POST", "/api/silences", v); A.ok("사일런스 추가"); renderMaint(box); } catch (err) { A.fail("추가 실패", err); }
    };
    box.onclick = async e => {
      const t = e.target.closest("[data-mtog]"), d = e.target.closest("[data-mdel]"), x = e.target.closest("[data-sexp]");
      try {
        if (t) { const m = ms.find(z => z.id === Number(t.dataset.mtog)); await A.api("PUT", `/api/maintenance/${m.id}`, {...m, enabled: !m.enabled}); }
        if (d) { if (!await A.confirm("삭제", "유지보수 창을 삭제합니다.", true)) return; await A.api("DELETE", `/api/maintenance/${d.dataset.mdel}`); }
        if (x) await A.api("DELETE", `/api/silences/${x.dataset.sexp}`);
        if (t || d || x) renderMaint(box);
      } catch (err) { A.fail("처리 실패", err); }
    };
  }

  // ================================================================ 로그 전송 설정 점검
  const FST = {ok: ["정상", "ok"], installed: ["설치됨", "ok"], receiving: ["수신 중", "ok"], missing: ["미설정", "bad"],
               "not-seen": ["수신 없음", "mid"], unknown: ["확인 불가", "mid"], error: ["오류", "bad"]};
  let fwdData = null;
  async function loadFwd() {
    $("#fwd-body").innerHTML = `<div class="empty"><span class="spin"></span> 각 제품의 전송 설정을 읽는 중… (ESXi 호스트 수에 따라 수십 초)</div>`;
    try { fwdData = await A.api("GET", "/api/forwarding"); } catch (e) { $("#fwd-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    renderFwd();
  }
  function renderFwd() {
    const d = fwdData, t = d.target;
    const bad = d.rows.filter(r => ["missing", "error"].includes(r.status)).length;
    const nb = $("#fwd-badge"); nb.hidden = !bad; nb.textContent = bad;
    $("#fwd-sub").textContent = `— 점검 ${fmtS(d.generated)} · 미설정·오류 ${bad}건`;
    $("#fwd-body").innerHTML = `
      <div class="fwd-target ${t.ok ? "" : "bad"}">${t.ok ? `수신 주소 <b class="mono">${esc(t.protocol)}://${esc(t.host)}:${t.port}</b> <small>ESXi 형식 ${esc(t.esxi_uri)}</small>`
        : `<b>수신 주소 미설정</b> — ${esc(t.hint)}`}
        <small>· 수신 포트: UDP/TCP 514, TLS 6514(certs/aiops.crt 있을 때) · 송신 장비별 분류 강제는 syslog.host_map</small></div>
      <table class="fwd"><thead><tr><th>제품</th><th>커넥터</th><th>대상</th><th>상태</th><th>현재 설정</th><th>판정</th><th></th></tr></thead><tbody>
      ${d.rows.map((r, i) => { const [lab, cls] = FST[r.status] || [r.status || "-", "mid"];
        const sub = (r.hosts || r.nodes || []);
        return `<tr><td><b>${esc(r.product)}</b></td><td>${esc(r.connector || "")}</td><td>${esc(r.target || "")}</td>
          <td><span class="res ${cls === "ok" ? "good" : cls}">${lab}</span></td>
          <td class="mono small">${(r.current || []).map(esc).join("<br>") || (sub.length ? "" : "-")}
            ${sub.length ? `<details><summary>${sub.length}개 상세</summary>${sub.map(h => `<div>${esc(h.host || h.name)} ${h.kind ? `<span class="label">${esc(h.kind)}</span>` : ""}
              ${h.configured === false || h.status === "missing" ? '<span class="res bad">미설정</span>' : h.status === "error" || h.error ? `<span class="res bad">${esc(h.error || h.detail || "오류")}</span>` : '<span class="res good">설정됨</span>'}
              ${h.receiving ? '<span class="res good">수신</span>' : ""}${h.firewall === false ? ' <span class="res bad">방화벽 off</span>' : ""}
              <span class="sub">${esc(h.loghost != null ? (h.loghost || "(없음)") : (h.current || []).join(", "))}</span></div>`).join("")}</details>` : ""}</td>
          <td>${esc(r.detail || "")}</td>
          <td class="nowrap">${r.action && A.can("action.request") ? `<button class="btn-sm solid" data-fwd-act="${i}">적용 요청</button>` : ""}
            ${r.guide ? `<button class="btn-sm" data-fwd-guide="${i}">설정 방법</button>` : ""}</td></tr>`; }).join("")}</tbody></table>
      <p class="muted" style="margin-top:10px">적용 요청은 조치 게이트를 거칩니다: 미리보기(대상·현재값·변경 후) → 사유 입력 → 관리자 승인(4-eyes) → 실행 직전 재측정 → 감사 기록. 기존 전송 대상은 유지하고 이 서버만 추가합니다.</p>`;
  }
  $("#fwd-body").addEventListener("click", async e => {
    const g = e.target.closest("[data-fwd-guide]"), a = e.target.closest("[data-fwd-act]");
    if (g) {
      const r = fwdData.rows[Number(g.dataset.fwdGuide)];
      A.modal({title: `${r.product} — 설정 방법`, wide: true, ok: "", cancel: "닫기",
        html: `<pre class="jpre copy" id="guide-pre">${esc(r.guide)}</pre><button class="btn-sm" id="guide-copy">복사</button>`,
        onOpen: m => { m.querySelector("#guide-copy").onclick = async () => { try { await navigator.clipboard.writeText(r.guide); A.ok("복사됨"); } catch { A.fail("복사 실패", "브라우저가 클립보드를 허용하지 않습니다 — 직접 선택해 복사하세요"); } }; }});
    }
    if (a) {
      const r = fwdData.rows[Number(a.dataset.fwdAct)], act = r.action;
      let pv;
      try { pv = await A.api("POST", "/api/actions/preview", act); } catch (err) { A.fail("미리보기 실패", err); return; }
      const bl = pv.blockers || [];
      const v = await A.modal({title: `${pv.label || act.action} — ${r.connector}`, wide: true, ok: bl.length ? "" : "요청",
        html: `<div class="pv ${bl.length ? "blocked" : "clear"}"><div class="pvh">${bl.length ? `<b>차단 ${bl.length}건</b>` : "<b>차단 사유 없음</b>"} · L${pv.level} ${pv.needs_approval ? "· 관리자 승인 필요" : ""}</div>
          ${bl.length ? `<ul class="bad">${bl.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}<h5>영향 범위</h5><pre>${jsonPretty(pv.blast_radius)}</pre></div>`,
        fields: bl.length ? [] : [{id: "reason", label: "사유", required: true, placeholder: "예) AIOps 로그 수집 대상 등록 (CHG0012345)"}]});
      if (!v || bl.length) return;
      try { const x = await A.api("POST", "/api/actions", {...act, reason: v.reason}); A.ok(`조치 #${x.id} ${x.status_label}`, x.status === "pending_approval" ? "관리자 승인 후 실행 — 인시던트 > 승인 대기" : ""); }
      catch (err) { A.fail("요청 실패", err); }
    }
  });
  $("#nav-fwd").onclick = () => { open("drawer-fwd"); if (!fwdData) loadFwd(); else renderFwd(); };

  // ================================================================ 플랫폼 상태(/api/health · /api/outbox)
  const JOB_KO = {pipeline: "수집 처리", publisher: "이상징후 게시", "store-writer": "DB 기록", flusher: "실시간 전송", "loop-lag": "지연 측정",
                  sweeper: "LLM 대기 감시", outbox: "알림 발송", health: "자체 감시", ha: "이중화", collection: "수집 감시", "incident-sla": "SLA 감시",
                  reports: "리포트 예약", "noc-escalation": "에스컬레이션", "noc-brief": "상황 브리핑", llm: "LLM 분석", "llm-health": "LLM 헬스", monitors: "모니터 평가", fortigate: "방화벽 집계"};
  const JST = {running: ["정상", "good"], stalled: ["정체", "bad"], crashed: ["비정상 종료", "bad"], exited: ["종료", "bad"], starting: ["시작 중", "mid"], stopped: ["중지", "mid"]};
  const OST = {pending: "대기", retry: "재시도 대기", sent: "발송", dead: "최종 실패", skipped_standby: "대기 노드 정리"};
  let platTimer = null;
  const n0 = v => (v ?? 0).toLocaleString();
  async function loadPlat() {
    let h, ob;
    try { [h, ob] = await Promise.all([A.api("GET", "/api/health", undefined, {background: true}),
                                       A.api("GET", "/api/outbox?limit=50", undefined, {background: true})]); }
    catch (e) { $("#plat-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    const r = h.runtime, p = h.pipeline, sto = h.store, w = h.ws, o = h.outbox, lag = h.lag, ha = h.ha;
    const cls = (v, warn, bad) => v >= bad ? "bad" : v >= warn ? "mid" : "";
    $("#plat-sub").textContent = `— ${new Date().toLocaleTimeString()} 기준 · 노드 ${ha.node}${ha.enabled ? ` (${ha.role}${ha.leader ? " · 알림 리더" : ""})` : ""}`;
    $("#plat-body").innerHTML = `
      <div class="plat-ready ${h.ready ? r.state : "down"}">${h.ready ? (r.state === "ok" ? "정상 — 실시간 처리 여유 충분" : "주의 — 아래 항목 확인") : "준비 안 됨(로드밸런서 헬스체크 실패) — " + h.reasons.map(esc).join(", ")}</div>
      ${h.issues.length ? `<ul class="plat-issues">${h.issues.map(i => `<li class="${esc(i.level)}">${esc(i.text)} <small>(${fmtS(i.since)}부터)</small></li>`).join("")}</ul>` : ""}
      <div class="plat-grid">
        <div class="pk ${cls(lag.p99_ms, 500, 2000)}"><span>이벤트 루프 지연 p99</span><b>${lag.p99_ms}ms</b><small>현재 ${lag.current_ms}ms · 최대 ${lag.max_ms}ms</small></div>
        <div class="pk ${cls(p.high_queue + p.low_queue, 1000, p.low_max / 2)}"><span>처리 대기(우선/일반)</span><b>${n0(p.high_queue)} / ${n0(p.low_queue)}</b><small>최대 ${n0(p.high_max)} / ${n0(p.low_max)} · 지연 ${(p.lag_ms / 1000).toFixed(1)}초</small></div>
        <div class="pk ${p.dropped_high ? "bad" : p.dropped_low ? "mid" : ""}"><span>과부하 폐기(누적)</span><b>${n0(p.dropped_low + p.dropped_high)}</b><small>일반 ${n0(p.dropped_low)} · 우선 ${n0(p.dropped_high)} · 처리 ${n0(p.processed)}${p.aggregated ? ` · 방화벽 집계 흡수 ${n0(p.aggregated)}` : ""}</small></div>
        <div class="pk ${sto.state === "error" ? "bad" : sto.disk_low ? "bad" : cls(sto.backlog, 5000, 50000)}"><span>DB 기록 대기</span><b>${n0(sto.backlog)}</b><small>배치 ${sto.last_batch_ms}ms · 오류 ${sto.write_errors} · 미저장 ${n0(sto.logs_dropped + sto.logs_skipped_disk)}</small></div>
        <div class="pk ${sto.disk_low ? "bad" : ""}"><span>디스크 여유</span><b>${sto.disk_free_mb != null ? n0(sto.disk_free_mb) + "MB" : "-"}</b><small>${sto.disk_low ? "원본 로그 저장 중지" : "정상"}</small></div>
        <div class="pk ${w.kicked_slow || w.kicked_dead ? "mid" : ""}"><span>실시간 화면 연결</span><b>${w.clients}</b><small>지연 끊김 ${w.kicked_slow + w.kicked_dead} · 생략 ${n0(w.dropped_flow)} · 최대 대기 ${w.max_queue}</small></div>
        <div class="pk ${o.dead ? "bad" : o.oldest_pending > 600 ? "mid" : ""}"><span>외부 알림 발송함</span><b>${n0(o.pending)}</b><small>발송 ${n0(o.sent)} · 재시도 ${n0(o.retry)} · 실패 ${n0(o.dead)}${o.oldest_pending ? ` · 최장 대기 ${Math.round(o.oldest_pending)}초` : ""}</small></div>
        ${h.llm_enabled ? (q => `<div class="pk ${cls(q.unique, 100, 400)}"><span>AI 분석 대기</span><b>${n0(q.depth)}</b><small>${q.rate_per_min ? `분당 ${q.rate_per_min}건 처리 · 예상 ${q.eta_min ?? "-"}분` : "처리율 측정 중"} · 최장 ${Math.round(q.oldest_wait_s / 60)}분 · 병합 ${n0(q.stats.coalesced)} · 생략 ${n0((q.stats.shed || 0) + (q.stats.quota || 0) + (q.stats.full || 0) + (q.stats.aged || 0) + (q.stats.dropped || 0))}${Object.keys(q.by_severity).length ? ` · ${Object.entries(q.by_severity).map(([k, v]) => `${k} ${v}`).join(" ")}` : ""}</small></div>`)(h.ai_queue) : ""}
        <div class="pk ${h.llm_breaker.state === "open" ? "mid" : ""}"><span>LLM 호출</span><b>${{closed: "정상", open: "일시 차단", half_open: "시험 중"}[h.llm_breaker.state]}</b><small>${h.llm_breaker.state === "open" ? `${h.llm_breaker.retry_in}초 후 재시도 · ` : ""}연속 실패 ${h.llm_breaker.fails}</small></div>
        <div class="pk ${ha.enabled && ha.peer.state !== "ok" ? "mid" : ""}"><span>이중화</span><b>${ha.enabled ? (ha.leader ? "알림 리더" : "대기") : "단일 노드"}</b><small>${ha.enabled ? `상대 ${esc(ha.peer.node || "-")} ${{ok: "정상", down: "응답 없음", not_ready: "준비 안 됨", unknown: "확인 중"}[ha.peer.state] || ha.peer.state}` : "ha.enabled=false"}</small></div>
      </div>
      <h4>내부 작업(감독자 — 비정상 종료 시 자동 재기동)</h4>
      <table class="plat"><thead><tr><th>작업</th><th>상태</th><th>재기동</th><th>마지막 신호</th><th>가동</th><th>마지막 오류</th></tr></thead><tbody>
      ${h.jobs.map(j => { const [lab, c] = JST[j.state] || [j.state, "mid"]; return `<tr><td>${esc(JOB_KO[j.name] || j.name)} <small class="muted">${esc(j.name)}${j.critical ? " · 핵심" : ""}</small></td>
        <td><span class="res ${c}">${lab}</span></td><td>${j.restarts}</td><td>${j.heartbeat ? `${j.beat_age}초 전` : "—"}</td><td>${Math.round(j.uptime / 60)}분</td><td class="small">${esc(j.last_error || "")}</td></tr>`; }).join("")}</tbody></table>
      <h4>외부 알림 발송함 <small class="muted">웹훅·메일 — 실패 시 지수 백오프 재시도, 한도 초과 시 최종 실패</small>
        ${o.dead && A.can("operate") ? `<button class="btn-sm solid" id="ob-retry">최종 실패 ${o.dead}건 재발송</button>` : ""}</h4>
      ${Object.keys(o.breakers || {}).length ? `<p class="small muted">채널 차단 상태: ${Object.entries(o.breakers).map(([k, b]) => `${esc(k)} ${b.state === "open" ? `<b class="bad">차단(${b.retry_in}초)</b>` : "정상"}`).join(" · ")}</p>` : ""}
      <table class="plat"><thead><tr><th>#</th><th>생성</th><th>채널</th><th>제목</th><th>상태</th><th>시도</th><th>다음/발송</th><th>오류</th></tr></thead><tbody>
      ${ob.items.map(x => `<tr><td>${x.id}</td><td class="nowrap">${fmtS(x.created)}</td><td>${esc(x.channel)}</td><td>${esc(x.title)}</td>
        <td><span class="res ${x.state === "sent" ? "good" : x.state === "dead" ? "bad" : "mid"}">${OST[x.state] || esc(x.state)}</span></td><td>${x.attempts}</td>
        <td class="nowrap">${x.state === "sent" ? fmtS(x.sent_at) : x.state === "retry" || x.state === "pending" ? fmtS(x.next_at) : "-"}</td><td class="small">${esc(x.last_error || "")}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">외부 채널(웹훅·메일) 발송 이력 없음</td></tr>`}</tbody></table>
      <h4>커넥터 폴링</h4>
      <table class="plat"><thead><tr><th>커넥터</th><th>상태</th><th>마지막 성공</th><th>연속 실패</th><th>시간 초과</th><th>오류</th></tr></thead><tbody>
      ${h.connectors.map(c => `<tr><td>${esc(c.name)} <small class="muted">${esc(c.type)}</small></td><td><span class="res ${c.state === "ok" ? "good" : c.state === "down" ? "bad" : "mid"}">${esc(c.state)}</span></td>
        <td class="nowrap">${c.last_ok ? fmtS(c.last_ok) : "-"}</td><td>${c.consecutive_failures || 0}</td><td>${c.timeouts || 0}</td><td class="small">${esc(c.last_error || "")}${c.dropped ? ` · 수신 폐기 ${n0(c.dropped)}` : ""}</td></tr>`).join("")}</tbody></table>`;
    const rb = $("#ob-retry");
    if (rb) rb.onclick = async () => { try { const x = await A.api("POST", "/api/outbox/retry", {}); A.ok(`${x.count}건 재발송 예약`); loadPlat(); } catch (err) { A.fail("재발송 실패", err); } };
  }
  $("#nav-plat").onclick = () => {
    open("drawer-plat"); loadPlat();
    clearInterval(platTimer); platTimer = setInterval(() => $("#drawer-plat").hidden ? clearInterval(platTimer) : loadPlat(), 3000);
  };
  window.addEventListener("aiops:ws", e => {               // 상단 내비 배지: 플랫폼 이상 건수
    const m = e.detail; if (m.type !== "status" && m.type !== "snapshot") return;
    const rt = (m.type === "status" ? m.data : m.data.status).runtime; if (!rt) return;
    const b = $("#plat-badge"); b.hidden = rt.state === "ok"; b.textContent = rt.issues.length || "!";
  });
  $("#fwd-run").onclick = loadFwd;

  // ================================================================ 해시 라우팅(ITSM·알림 링크 → #incident/ID)
  A.ready.then(me => {
    if (!me) return;
    const m = location.hash.match(/^#incident\/(.+)$/);
    if (m) { openIncDrawer(); openIncident(decodeURIComponent(m[1])); }
  });
})();
