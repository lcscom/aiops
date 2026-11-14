/* 보안 판독 — 하드닝(항목별)·KISA 가상화 HV 대응표·VMSA/CVE 판독·버전 현황·취약점 목록 관리. core.js(AIOPS) 이후 로드
   GET /api/assessment · POST /api/assessment/run · report.csv · report.html · advisories(import·sync) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const st = {d: null, s: null, tab: "hard", f: "bad", q: "", open: new Set(), adv: null};
  const ST = {FAIL: ["error", "미흡"], WARN: ["warning", "검토"], MANUAL: ["info", "수동 확인"], PASS: ["ok", "양호"], "N/A": ["na", "해당 없음"]};
  const SEVK = {CRITICAL: "긴급", HIGH: "높음", MEDIUM: "보통", LOW: "낮음"};
  const chip = s => `<span class="as-st ${ST[s] ? ST[s][0] : ""}">${ST[s] ? ST[s][1] : esc(s)}</span>`;

  async function load() {
    try { const r = await A.api("GET", "/api/assessment", undefined, {background: true}); st.d = r.result; st.s = r.state; }
    catch (e) { $("#as-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }
  function render() {
    const b = $("#as-body"); if (!b) return;
    const S = st.s || {};
    $("#as-sub").textContent = `하드닝 · KISA 가상화(HV) · VMSA/CVE — 읽기 전용 수집${S.last_run ? ` · 마지막 점검 ${new Date(S.last_run * 1000).toLocaleString()}` : ""}${S.running ? " · 점검 중…" : ""} · 취약점 목록 ${S.advisories || 0}건`;
    if (!st.d) { b.innerHTML = `<div class="empty">점검 결과가 없습니다. '지금 점검'을 누르면 연결된 vCenter 에서 ESXi·VM 설정을 읽어 판독합니다(설정은 바꾸지 않음). 자동 점검 주기 ${S.interval_hours || 24}시간.
      ${S.error ? `<div class="vc-err">${esc(S.error)}</div>` : ""}</div>` + advPane(); wireAdv(); return; }
    const s = st.d.summary, c = s.counts;
    const card = (cls, t, n, sub, tab) => `<button class="vc-card ${cls}${tab && st.tab === tab ? " on" : ""}" ${tab ? `data-at="${tab}"` : ""}><b>${t}</b><span class="vc-n">${n}</span><small>${sub}</small></button>`;
    b.innerHTML = `<div class="vc-cards">
        ${card(s.score >= 90 ? "info" : s.score >= 70 ? "warning" : "error", "준수율", s.score == null ? "-" : s.score + "%", `PASS ${c.PASS} / 판정 ${c.PASS + c.FAIL + c.WARN}`, "hard")}
        ${card(c.FAIL ? "error" : "", "미흡(FAIL)", c.FAIL, `검토 ${c.WARN} · 수동 ${c.MANUAL}`, "hard")}
        ${card("", "KISA HV", st.d.kisa.filter(k => k.status === "FAIL").length + "/25", "미흡 항목 수", "kisa")}
        ${card(s.cve.vulnerable ? "critical" : s.cve.possible ? "warning" : "", "VMSA/CVE 취약", s.cve.vulnerable, `가능 ${s.cve.possible} · 긴급 ${s.cve.critical}`, "cve")}
        ${card("", "대상", `${s.hosts}`, `ESXi · vCenter ${s.vcenters} · VM 표본 ${s.vms}`, "ver")}
        ${card(s.cve.advisories_db ? "" : "warning", "취약점 목록", s.cve.advisories_db, s.cve.advisories_db ? "NVD·가져온 권고" : "비어 있음 — 가져오기 필요", "adv")}
        ${card((s.changes || {}).worse || (s.changes || {}).warning ? "warning" : "", "변경 추적", (s.changes || {}).total ?? 0, `${(s.changes || {}).since ? "지난 점검 이후" : "첫 점검"} · 악화 ${(s.changes || {}).worse ?? 0} · 개선 ${(s.changes || {}).better ?? 0}`, "chg")}</div>
      ${s.errors && s.errors.length ? `<div class="vc-err">${s.errors.map(esc).join("<br>")}</div>` : ""}
      <div class="vc-tabs">${[["hard", "하드닝"], ["kisa", "KISA 대응표"], ["cve", "VMSA/CVE"], ["chg", "변경 추적"], ["ver", "버전 현황"], ["adv", "취약점 목록"]].map(([k, l]) => `<button data-at="${k}" class="${st.tab === k ? "on" : ""}">${l}</button>`).join("")}
        <span class="gap"></span><button class="btn-sm" id="as-csv">CSV</button><button class="btn-sm" id="as-html">보고서(인쇄·PDF)</button></div>
      ${st.tab === "hard" ? hard() : st.tab === "kisa" ? kisa() : st.tab === "cve" ? cve() : st.tab === "chg" ? changes() : st.tab === "ver" ? ver() : advPane()}`;
    if (st.tab === "adv") wireAdv();
  }
  function hard() {
    const q = st.q.toLowerCase();
    const rows = st.d.rows.filter(r => (st.f === "all" || (st.f === "bad" ? ["FAIL", "WARN"].includes(r.status) : r.status === st.f))
      && (!q || `${r.id} ${r.kisa} ${r.title} ${r.target} ${r.current}`.toLowerCase().includes(q)));
    const g = {}; rows.forEach(r => { (g[r.id] = g[r.id] || []).push(r); });
    const order = Object.values(g).sort((a, b) => ({FAIL: 0, WARN: 1, MANUAL: 2, PASS: 3, "N/A": 4}[a[0].status] - {FAIL: 0, WARN: 1, MANUAL: 2, PASS: 3, "N/A": 4}[b[0].status]) || a[0].id.localeCompare(b[0].id));
    return `<div class="vc-ctl"><select id="as-f">${[["bad", "미흡·검토만"], ["all", "전체"], ["FAIL", "미흡"], ["WARN", "검토"], ["MANUAL", "수동 확인"], ["PASS", "양호"], ["N/A", "해당 없음"]].map(([k, l]) => `<option value="${k}" ${st.f === k ? "selected" : ""}>${l}</option>`).join("")}</select>
        <input id="as-q" placeholder="항목·호스트·현재값 검색" value="${esc(st.q)}"><span class="small muted">${rows.length}행 · 항목 ${order.length}개</span></div>
      <table class="vc-t"><tr><th>판정</th><th>ID</th><th>KISA</th><th>항목</th><th>분류</th><th>중요도</th><th>대상</th><th>기대값</th></tr>
      ${order.map(list => { const r = list[0], worst = list.reduce((a, x) => ({FAIL: 0, WARN: 1, MANUAL: 2, PASS: 3, "N/A": 4}[x.status] < {FAIL: 0, WARN: 1, MANUAL: 2, PASS: 3, "N/A": 4}[a] ? x.status : a), r.status), on = st.open.has(r.id);
        return `<tr class="vc-r" data-ar="${esc(r.id)}"><td>${chip(worst)}</td><td class="vc-ent">${esc(r.id)}</td><td>${esc(r.kisa)}</td><td><b>${esc(r.title)}</b></td><td>${esc(r.category)}</td><td>${esc(r.severity)}</td>
          <td>${list.length > 1 ? `${list.length}개 대상` : esc(r.target)}</td><td>${esc(r.expected)}</td></tr>
          ${on ? `<tr><td></td><td colspan="7"><div class="vc-fix">조치: ${esc(r.fix || "-")}</div><table class="vc-t as-sub">${list.map(x => `<tr><td>${chip(x.status)}</td><td class="vc-ent">${esc(x.target)}</td><td class="vc-ent">${esc(x.current)}</td><td class="small muted">${esc(x.vcenter || "")}</td></tr>`).join("")}</table></td></tr>` : ""}`; }).join("")
        || `<tr><td colspan="8" class="muted">해당 항목 없음</td></tr>`}</table>`;
  }
  function kisa() {
    return `<p class="small muted">KISA 주요정보통신기반시설 가상화 점검 항목(HV-01~25) 기준으로 이 화면의 자동 점검 결과를 묶었습니다. 자동 확인이 불가능한 항목은 '수동 확인'입니다.</p>
      <table class="vc-t"><tr><th>코드</th><th>항목</th><th>중요도</th><th>판정</th><th>점검 수</th><th>미흡</th><th>대상</th><th>미흡 내용·비고</th></tr>
      ${st.d.kisa.map(k => `<tr class="vc-r" data-kq="${esc(k.code)}"><td class="vc-ent">${esc(k.code)}</td><td><b>${esc(k.title)}</b></td><td>${esc(k.importance)}</td><td>${chip(k.status)}</td><td>${k.checks}</td><td>${k.fail || ""}</td><td>${k.targets || ""}</td><td class="small">${esc(k.note || "")}</td></tr>`).join("")}</table>`;
  }
  function cve() {
    const rows = st.d.cve;
    if (!rows.length) return `<div class="empty">${st.d.summary.cve.advisories_db ? "실행 중인 ESXi·vCenter 버전에 해당하는 VMSA/CVE 가 없습니다(현재 취약점 목록 기준)." : "취약점 목록이 비어 있어 판독하지 못했습니다 — '취약점 목록' 탭에서 NVD 동기화 또는 JSON 가져오기."}</div>`;
    const g = {}; rows.forEach(r => { const k = r.id; (g[k] = g[k] || {r, t: []}).t.push(r); });
    return `<p class="small muted">'취약' = 권고의 고정 빌드보다 낮은 빌드 · '가능' = NVD CPE 의 버전·업데이트가 일치(같은 업데이트의 패치 빌드인지 확인 필요)</p>
      <table class="vc-t"><tr><th>판정</th><th>CVE·권고</th><th>VMSA</th><th>심각도</th><th>CVSS</th><th>공개일</th><th>대상</th><th>근거</th></tr>
      ${Object.values(g).slice(0, 800).map(({r, t}) => `<tr class="vc-r" data-cv="${esc(r.id)}"><td>${chip(t.some(x => x.verdict === "취약") ? "FAIL" : "WARN")} ${t.some(x => x.verdict === "취약") ? "취약" : "가능"}</td>
        <td class="vc-ent">${/^https?:/.test(r.url) ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.id)}</a>` : esc(r.id)}</td><td>${esc(r.vmsa || "")}</td><td><span class="vc-sev ${r.severity === "CRITICAL" ? "critical" : r.severity === "HIGH" ? "error" : r.severity === "MEDIUM" ? "warning" : "info"}">${esc(SEVK[r.severity] || r.severity || "-")}</span></td>
        <td>${r.cvss ?? "-"}</td><td>${esc(r.published || "")}</td><td>${t.length > 1 ? `${t.length}대(${esc([...new Set(t.map(x => x.product))].join("·"))})` : esc(r.target)}</td><td class="small">${esc(r.why)}</td></tr>
        ${st.open.has("cv:" + r.id) ? `<tr><td></td><td colspan="7"><div class="small">${esc(r.title)}</div><div class="small muted">CVE ${esc((r.cves || []).join(", "))}</div><div class="small">${t.map(x => `${esc(x.target)} ${esc(x.version)} (${esc(x.build)})`).join(" · ")}</div></td></tr>` : ""}`).join("")}</table>`;
  }
  function changes() {
    const C = st.d.changes || [], V = st.d.verdicts || [], s = st.d.summary.changes || {};
    const since = s.since ? new Date(s.since * 1000).toLocaleString() : null;
    if (!since) return `<div class="empty">첫 점검입니다 — 다음 점검부터 지난 점검과 비교해 구성 변경(고급 설정·서비스·잠금 모드·NTP·방화벽·vSwitch·VM 설정·버전)과 판정 악화·개선을 보여 줍니다. 변경은 이벤트(소스 vcenter, 종류 config)로도 남습니다.</div>`;
    return `<p class="small muted">기준: ${since} 점검 이후 · 구성 변경 ${C.length}건(주의 ${s.warning || 0}) · 판정 악화 ${s.worse || 0} · 개선 ${s.better || 0}</p>
      ${V.length ? `<h4>판정 변화</h4><table class="vc-t"><tr><th></th><th>ID</th><th>항목</th><th>대상</th><th>이전</th><th>현재</th></tr>${V.map(v => `<tr><td>${v.worse ? '<span class="as-st error">악화</span>' : '<span class="as-st ok">개선</span>'}</td><td class="vc-ent">${esc(v.id)}</td><td>${esc(v.title)}</td><td class="vc-ent">${esc(v.target)}</td><td>${chip(v.before)}</td><td>${chip(v.after)}</td></tr>`).join("")}</table>` : ""}
      <h4>구성 변경</h4><table class="vc-t"><tr><th>심각도</th><th>대상</th><th>영역</th><th>항목</th><th>이전</th><th>현재</th><th>vCenter</th></tr>
      ${C.map(c => `<tr><td>${c.severity === "warning" ? '<span class="as-st warning">주의</span>' : '<span class="as-st info">정보</span>'}</td><td class="vc-ent">${esc(c.target)}</td><td>${esc(c.area)}</td><td class="vc-ent">${esc(c.key)}</td><td class="small">${esc(c.before)}</td><td class="small"><b>${esc(c.after)}</b></td><td class="small muted">${esc(c.vcenter || "")}</td></tr>`).join("") || `<tr><td colspan="7" class="muted">변경 없음</td></tr>`}</table>`;
  }
  function ver() {
    return `<table class="vc-t"><tr><th>제품</th><th>버전</th><th>빌드</th><th>대수</th></tr>${st.d.summary.versions.map(v => `<tr><td>${v.product === "esxi" ? "ESXi" : "vCenter"}</td><td>${esc(v.version)}</td><td class="vc-ent">${esc(v.build)}</td><td>${v.count}</td></tr>`).join("")}</table>
      <p class="small muted">같은 버전에 빌드가 여러 개면 패치 수준이 섞여 있다는 뜻입니다 — vLCM 이미지(클러스터 단위)로 맞추세요.</p>`;
  }
  function advPane() {
    const a = st.adv, S = st.s || {};
    return `<div class="as-adv"><div class="vc-ctl">${A.can("settings") ? `<label class="btn-sm as-file">JSON 가져오기<input type="file" id="as-imp" accept=".json,application/json" hidden></label>
        <button class="btn-sm" id="as-sync" ${S.nvd_enabled ? "" : "title='설정 assessment.nvd.enabled 를 켜면 자동 동기화(주기) — 수동 동기화는 지금도 가능'"}>NVD 동기화</button>
        <button class="btn-sm danger" id="as-clear">목록 비우기</button>` : ""}<input id="as-aq" placeholder="CVE·VMSA·설명 검색"><span class="small muted">${S.nvd_error ? "NVD 오류: " + esc(S.nvd_error) : S.last_nvd ? "NVD 마지막 동기화 " + new Date(S.last_nvd * 1000).toLocaleString() : ""}</span></div>
      <p class="small muted">취약점 목록 출처 — ① NVD CVE API 2.0(인터넷·프록시 필요, 제품 CPE: cpe:2.3:o:vmware:esxi · cpe:2.3:a:vmware:vcenter_server) ② 폐쇄망: 인터넷 PC 에서 받은 NVD 응답 JSON 또는
        이 프로젝트 형식 {"advisories":[{"id":"VMSA-…","title","severity","cvss","published","url","cves":[…],"fixes":[{"product":"esxi","branch":"8.0","fixed_build":…,"fixed_version":"…"}]}]} 을 가져오기(고정 빌드가 있으면 '취약/조치됨'을 정확히 판정).</p>
      <div id="as-advl">${a ? `<p class="small">전체 ${a.total}건 (NVD ${a.sources.nvd || 0} · 가져옴 ${a.sources.import || 0})</p><table class="vc-t"><tr><th>ID</th><th>심각도</th><th>CVSS</th><th>공개일</th><th>제품</th><th>설명</th><th>출처</th></tr>
        ${a.items.map(x => `<tr><td class="vc-ent">${/^https?:/.test(x.url) ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.id)}</a>` : esc(x.id)}</td><td>${esc(SEVK[x.severity] || x.severity || "-")}</td><td>${x.cvss ?? "-"}</td><td>${esc(x.published || "")}</td><td>${esc(x.products.join(", "))}</td><td class="small">${esc((x.title || "").slice(0, 200))}</td><td>${esc(x.source)}</td></tr>`).join("")}</table>` : `<p class="muted">불러오는 중…</p>`}</div></div>`;
  }
  async function loadAdv(q = "") {
    try { st.adv = await A.api("GET", `/api/assessment/advisories?q=${encodeURIComponent(q)}&limit=300`, undefined, {background: true}); } catch (e) { st.adv = {total: 0, items: [], sources: {}}; }
    const el = $("#as-advl"); if (el) { const keep = st.tab; render(); st.tab = keep; }
  }
  function wireAdv() { if (!st.adv) loadAdv(); }

  function wire() {
    const b = $("#as-body");
    b.addEventListener("click", async e => {
      const t = e.target;
      const at = t.closest("[data-at]"); if (at) { st.tab = at.dataset.at; render(); return; }
      const ar = t.closest("[data-ar]"); if (ar) { const k = ar.dataset.ar; st.open.has(k) ? st.open.delete(k) : st.open.add(k); render(); return; }
      const cv = t.closest("[data-cv]"); if (cv && !t.closest("a")) { const k = "cv:" + cv.dataset.cv; st.open.has(k) ? st.open.delete(k) : st.open.add(k); render(); return; }
      const kq = t.closest("[data-kq]"); if (kq) { st.tab = "hard"; st.f = "all"; st.q = kq.dataset.kq; render(); return; }
      if (t.id === "as-csv") { location.href = "/api/assessment/report.csv"; return; }
      if (t.id === "as-html") { window.open("/api/assessment/report.html", "_blank", "noopener"); return; }
      if (t.id === "as-sync") { t.disabled = true; t.textContent = "동기화 중…(수 분)"; try { const r = await A.api("POST", "/api/assessment/advisories/sync"); A.ok("NVD 동기화", `${r.saved}건 저장 — 다시 점검하면 판독에 반영`); } catch (er) { A.fail("NVD 동기화 실패", er); } st.adv = null; await load(); return; }
      if (t.id === "as-clear") { if (!await A.confirm("취약점 목록 비우기", "가져오거나 동기화한 권고를 모두 지웁니다.", true)) return; try { await A.api("DELETE", "/api/assessment/advisories"); } catch (er) { A.fail("실패", er); } st.adv = null; load(); }
    });
    b.addEventListener("change", async e => {
      if (e.target.id === "as-f") { st.f = e.target.value; render(); }
      if (e.target.id === "as-imp" && e.target.files[0]) {
        const f = e.target.files[0];
        try {
          const r = await fetch("/api/assessment/advisories/import", {method: "POST", body: f, headers: {"Content-Type": "application/json", "X-Filename": encodeURIComponent(f.name)}});
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
          A.ok("가져오기", `${j.imported}건(NVD ${j.nvd} · 권고 ${j.own}) — '지금 점검'으로 판독 갱신`);
        } catch (er) { A.fail("가져오기 실패", er); }
        st.adv = null; load();
      }
    });
    let tm;
    b.addEventListener("input", e => {
      if (e.target.id === "as-q") { clearTimeout(tm); const pos = e.target.selectionStart; tm = setTimeout(() => { st.q = e.target.value; render(); const el = $("#as-q"); if (el) { el.focus(); el.setSelectionRange(pos, pos); } }, 250); }
      if (e.target.id === "as-aq") { clearTimeout(tm); const v = e.target.value; tm = setTimeout(async () => { await loadAdv(v); const el = $("#as-aq"); if (el) { el.value = v; el.focus(); } }, 300); }
    });
    $("#as-run").onclick = async () => {
      const bt = $("#as-run"); bt.disabled = true; bt.textContent = "점검 중…";
      try { const r = await A.api("POST", "/api/assessment/run"); A.ok("점검 완료", `FAIL ${r.summary.counts.FAIL} · WARN ${r.summary.counts.WARN} · 취약 ${r.summary.cve.vulnerable}`); }
      catch (e) { A.fail("점검 실패", e); }
      bt.disabled = false; bt.textContent = "지금 점검"; load();
    };
    $("#as-reload").onclick = () => { st.adv = null; load(); };
  }
  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-assess")) return;
    wire();
    $("#nav-assess").onclick = () => { open("drawer-assess"); load(); };
    const badge = async () => {
      try { const r = await A.api("GET", "/api/assessment", undefined, {background: true}); const n = r.result ? r.result.summary.cve.vulnerable + r.result.summary.counts.FAIL : 0;
        const el = $("#assess-badge"); el.hidden = !n; el.textContent = n; el.title = r.result ? `미흡 ${r.result.summary.counts.FAIL} · VMSA 취약 ${r.result.summary.cve.vulnerable}` : ""; } catch { /* 권한·로그인 전 */ }
    };
    setTimeout(badge, 6000); setInterval(badge, 300000);
  });
  window.AIOPS_ASSESS = {load};
})();
