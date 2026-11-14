/* 시스템 · 패치 — 현재 버전, 패치 번들 업로드(서명·무결성 검사) → 적용(root 패치 서비스) → 진행 상태, 기록, 롤백 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const STL = {queued: "대기", running: "진행 중", ok: "완료", failed: "실패", rolling_back: "롤백 중", rolled_back: "롤백됨"};
  const sy = {d: null, up: null, poll: null, busy: false, lastVer: ""};
  const dt = ts => ts ? new Date(ts * 1000).toLocaleString() : "-";
  const mb = n => `${(n / 2 ** 20).toFixed(1)}MB`;

  async function load() {
    try { sy.d = await A.api("GET", "/api/system/version", undefined, {background: true}); }
    catch (e) { if (sy.busy) { $("#sys-state").innerHTML = `<div class="sys-run">서비스 재기동 중… 다시 연결되면 자동으로 갱신합니다 <i class="spin"></i></div>`; return; }
      $("#sys-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }

  function stateHtml(s) {
    if (!s || !s.state) return `<span class="muted">패치 기록 없음</span>`;
    const run = ["queued", "running", "rolling_back"].includes(s.state);
    return `<div class="sys-st ${esc(s.state)}">${run ? '<i class="spin"></i>' : ""}<b>${STL[s.state] || esc(s.state)}</b> <span>${esc(s.step || "")}</span>
      <small>${dt(s.ts)}${s.by ? " · " + esc(s.by) : ""}</small></div>`;
  }

  function render() {
    const d = sy.d, can = A.can("system");
    const st = d.status || {};
    const run = ["queued", "running", "rolling_back"].includes(st.state);
    if (sy.busy && !run && st.state) {                     // 적용 끝
      sy.busy = false; clearInterval(sy.poll);
      st.state === "ok" ? A.ok("패치 완료", `${st.from || ""} → ${d.version}`) : A.fail("패치 실패", st.step || "");
      if (st.state === "ok" && sy.lastVer && sy.lastVer !== d.version) setTimeout(() => location.reload(), 2500);
    }
    $("#sys-sub").textContent = `— 현재 ${d.version}`;
    $("#sys-body").innerHTML = `
      <div class="sys-cards"><div class="sys-card"><small>현재 버전</small><b>${esc(d.version)}</b><span>${esc(d.appliance || "설치본(install.sh)")}</span></div>
        <div class="sys-card wide"><small>패치 상태</small><div id="sys-state">${stateHtml(st)}</div></div></div>
      ${can ? `<section class="sys-sec"><h4>패치 적용</h4>
        ${d.web_apply ? "" : `<p class="vc-err">이 서버에는 웹 패치 적용 유닛이 없습니다. 서버에서 <code>sudo vcf-aiopsctl patch &lt;번들&gt;</code> 로 적용하세요(업로드 검사는 가능).</p>`}
        <label class="sys-drop" id="sys-drop"><input type="file" id="sys-file" accept=".tgz,.tar.gz" hidden>
          <b>패치 번들(vcf-aiops-patch-&lt;버전&gt;.tgz)을 끌어 놓거나 눌러서 선택</b>
          <span>업로드하면 서명(${esc((d.trusted_keys_info || []).map(k => `${k.name} SHA256:${String(k.sha256 || "").slice(0, 16)}…`).join(", ") || (d.trusted_keys || []).join(", ") || "신뢰 키 없음")})·무결성·버전을 먼저 검사합니다. 적용 전 프로그램과 DB 를 자동 백업하고, 기동 확인에 실패하면 자동으로 되돌립니다.</span></label>
        <div id="sys-up">${sy.up ? upHtml(sy.up) : ""}</div></section>` : `<p class="muted small">패치 적용·롤백은 관리자만 할 수 있습니다.</p>`}
      <section class="sys-sec"><h4>백업 <small class="muted">패치 직전 자동 백업(최근 3개)</small></h4>
        ${d.backups.length ? `<table class="vc-t"><thead><tr><th>백업</th><th>버전</th><th>크기</th><th>DB 포함</th><th>시각</th></tr></thead><tbody>${d.backups.map(b => `<tr><td><code>${esc(b.name)}</code></td><td>${esc(b.version)}</td><td>${b.size_mb}MB</td><td>${b.db ? "예" : "-"}</td><td>${dt(b.ts)}</td></tr>`).join("")}</tbody></table>
          ${can && d.web_apply && d.backups.some(b => b.version !== d.version) ? `<button class="btn-sm" id="sys-rb" ${run ? "disabled" : ""}>이전 버전(${esc(d.backups.find(b => b.version !== d.version).version)})으로 되돌리기</button>` : ""}` : `<p class="muted small">백업 없음</p>`}</section>
      <section class="sys-sec"><h4>기록</h4>${d.history.length ? `<table class="vc-t"><thead><tr><th>시각</th><th>변경</th><th>결과</th><th>내용</th><th>실행</th></tr></thead><tbody>${d.history.map(h => `<tr><td>${dt(h.ts)}</td><td>${esc(h.from)} → ${esc(h.to)}</td><td><span class="sys-st ${esc(String(h.result).replace("rollback_", ""))}">${esc(h.result)}</span></td><td class="small">${esc(h.detail || "")}</td><td class="small">${esc(h.by || "")}</td></tr>`).join("")}</tbody></table>` : `<p class="muted small">기록 없음</p>`}</section>
      <section class="sys-sec" id="sys-selfcheck"><h4>자가 점검 <small class="muted">DB 무결성·WAL·백업 검증·메모리·인증서(5분 주기, quick_check 는 매일)</small>${can ? `<button class="btn-sm" id="sc-run" style="margin-left:auto">지금 점검</button>` : ""}</h4><div id="sc-body"><span class="spin"></span></div></section>
      <p class="small muted">CLI: <code>sudo vcf-aiopsctl patch &lt;번들&gt;</code> · <code>sudo vcf-aiopsctl rollback</code> · <code>vcf-aiopsctl patch-history</code> · 1.2 이하 설치본은 번들을 풀어 <code>sudo bash vcf-aiops-patch-&lt;버전&gt;/apply.sh</code></p>`;
    if (run && !sy.busy) startPoll();
    loadSelfcheck();
  }

  async function loadSelfcheck(data) {
    const box = $("#sc-body"); if (!box) return;
    let sc = data;
    try { sc = sc || (await A.api("GET", "/api/health", undefined, {background: true})).selfcheck; } catch (e) { box.innerHTML = `<p class="vc-err">${esc(e.message)}</p>`; return; }
    if (!sc) { box.innerHTML = `<p class="muted small">자가 점검 정보 없음</p>`; return; }
    const r = sc.resources || {}, db = sc.db || {}, bk = sc.backup || {}, qc = sc.quick_check || {}, c = sc.cert || {};
    const lv = x => x.level === "critical" || x.level === "error" ? "critical" : x.level;
    const tables = Object.entries(db.tables || {}).sort((a, b) => (b[1] || 0) - (a[1] || 0)).slice(0, 8);
    box.innerHTML = `
      ${(sc.issues || []).length ? `<ul class="sc-issues">${sc.issues.map(x => `<li class="${lv(x)}"><span class="label solid ${lv(x)}">${esc(x.level)}</span> ${esc(x.text)}</li>`).join("")}</ul>` : `<p class="small" style="color:var(--ok)">문제 없음 — 마지막 점검 ${sc.checked ? dt(sc.checked) : "대기 중"}</p>`}
      <div class="sys-cards">
        <div class="sys-card"><small>DB 무결성(quick_check)</small><b class="${qc.result && qc.result !== "ok" ? "vc-err" : ""}">${esc(qc.result || "대기")}</b><span>${qc.ts ? `${dt(qc.ts)} · ${qc.ms}ms` : "매일 1회"}</span></div>
        <div class="sys-card"><small>DB 파일</small><b>${db.db_mb ?? "-"} MB</b><span>WAL ${db.wal_mb ?? "-"} MB · 빈 공간 ${db.free_mb ?? "-"} MB · checkpoint ${sc.wal_checkpoints || 0}회</span></div>
        <div class="sys-card"><small>최신 백업 검증</small><b class="${bk.result && !["ok", "none"].includes(bk.result) ? "vc-err" : ""}">${esc(bk.result === "none" ? "백업 없음" : bk.result || "대기")}</b><span>${bk.file ? `${esc(bk.file)} · ${mb(bk.size || 0)} · ${dt(bk.mtime)}${bk.audit_rows != null ? ` · 감사 ${bk.audit_rows.toLocaleString()}행` : ""}` : ""}</span></div>
        <div class="sys-card"><small>프로세스</small><b>${r.rss_mb != null ? r.rss_mb.toFixed(0) + " MB" : "-"}</b><span>열린 파일 ${r.open_files ?? "-"} · 볼륨 사용 ${r.disk_used_pct ?? "-"}% · 기준 ${(sc.limits || {}).memory_warn_mb} MB</span></div>
        <div class="sys-card"><small>TLS 인증서</small><b class="${c.days_left != null && c.days_left < 14 ? "vc-err" : ""}">${c.days_left == null ? "-" : c.days_left < 0 ? "만료" : "D-" + c.days_left}</b><span>${esc(c.file || "")}</span></div>
      </div>
      ${tables.length ? `<table class="vc-t"><thead><tr><th>표</th><th class="r">행 수</th></tr></thead><tbody>${tables.map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td class="r">${v == null ? "-" : v.toLocaleString()}</td></tr>`).join("")}</tbody></table>` : ""}`;
    const b = $("#sc-run"); if (b) b.onclick = async () => { b.disabled = true; b.textContent = "점검 중…";
      try { const x = await A.api("POST", "/api/system/selfcheck/run"); loadSelfcheck(x.snapshot); A.ok("자가 점검 완료", `quick_check ${x.quick_check.result} · WAL 남은 프레임 ${x.wal_frames_left} · 백업 ${x.backup.result || "-"}`); }
      catch (e) { A.fail("점검 실패", e); } finally { b.disabled = false; b.textContent = "지금 점검"; } };
  }

  function upHtml(u) {
    if (u.error) return `<p class="vc-err">${esc(u.error)}</p>`;
    if (u.progress != null) return `<div class="sys-prog"><i style="width:${u.progress}%"></i></div><p class="small">${esc(u.name)} 업로드 ${u.progress}%</p>`;
    const m = u.manifest;
    return `<div class="sys-man"><dl class="dl"><dt>버전</dt><dd><b>${esc(m.version)}</b> (현재 ${esc(u.current)}${u.newer ? "" : " — 새 버전 아님"})</dd>
      <dt>만든 시각</dt><dd>${esc(m.created)}</dd><dt>서명</dt><dd>✔ ${esc(m.signed_by)}</dd><dt>SHA-256</dt><dd><code>${esc(m.sha256)}</code></dd>
      <dt>크기</dt><dd>${mb(m.size)}${m.wheels ? " · 패키지(wheel) 포함" : ""}</dd>${m.notes ? `<dt>내용</dt><dd>${esc(m.notes)}</dd>` : ""}</dl>
      ${!u.newer ? `<label class="chk"><input type="checkbox" id="sys-force"> 같은 버전 재적용·하향 허용</label>` : ""}
      <button class="btn-sm solid" id="sys-apply" ${sy.d.web_apply ? "" : "disabled"}>적용 (서비스 1~3분 재기동)</button></div>`;
  }

  function upload(file) {
    if (!file) return;
    sy.up = {name: file.name, progress: 0}; $("#sys-up").innerHTML = upHtml(sy.up);
    const x = new XMLHttpRequest();
    x.open("PUT", "/api/system/patch");
    x.setRequestHeader("Content-Type", "application/octet-stream");
    x.setRequestHeader("X-Filename", file.name);
    x.setRequestHeader("X-Requested-With", "aiops");          // CSRF 보호(서버가 요구하는 헤더)
    x.upload.onprogress = e => { if (e.lengthComputable) { sy.up.progress = Math.round(e.loaded / e.total * 100); $("#sys-up").innerHTML = upHtml(sy.up); } };
    x.onload = () => {
      let j = {}; try { j = JSON.parse(x.responseText); } catch { /* 무시 */ }
      sy.up = x.status < 300 ? j : {error: j.detail || `HTTP ${x.status}`};
      $("#sys-up").innerHTML = upHtml(sy.up);
    };
    x.onerror = () => { sy.up = {error: "업로드 실패(연결)"}; $("#sys-up").innerHTML = upHtml(sy.up); };
    x.send(file);
  }

  function startPoll() {
    sy.busy = true; sy.lastVer = sy.lastVer || (sy.d && sy.d.version) || "";
    clearInterval(sy.poll); sy.poll = setInterval(load, 2500);
  }

  function wire() {
    const b = $("#sys-body");
    b.addEventListener("change", e => { if (e.target.id === "sys-file") upload(e.target.files[0]); });
    b.addEventListener("dragover", e => { const d = e.target.closest("#sys-drop"); if (d) { e.preventDefault(); d.classList.add("over"); } });
    b.addEventListener("dragleave", e => { const d = e.target.closest("#sys-drop"); if (d) d.classList.remove("over"); });
    b.addEventListener("drop", e => { const d = e.target.closest("#sys-drop"); if (!d) return; e.preventDefault(); d.classList.remove("over"); upload(e.dataTransfer.files[0]); });
    b.addEventListener("click", async e => {
      if (e.target.id === "sys-apply") {
        const m = sy.up.manifest;
        if (!await A.confirm("패치 적용", `${sy.d.version} → ${m.version} 로 패치합니다. 프로그램·DB 를 백업한 뒤 서비스가 1~3분 재기동되며, 실패하면 자동으로 되돌립니다. 계속할까요?`, true)) return;
        try {
          sy.lastVer = sy.d.version;
          await A.api("POST", "/api/system/patch/apply", {file: sy.up.file, force: !!($("#sys-force") || {}).checked});
          sy.up = null; A.ok("패치 요청됨", "root 패치 서비스가 적용합니다"); startPoll(); load();
        } catch (err) { A.fail("적용 실패", err); }
      }
      if (e.target.id === "sys-rb") {
        const bk = sy.d.backups.find(b => b.version !== sy.d.version);
        if (!await A.confirm("롤백", `백업 ${bk.name}(${bk.version})으로 프로그램과 DB 를 되돌립니다. 그 백업 이후 쌓인 이벤트·설정 변경은 사라집니다. 계속할까요?`, true)) return;
        try { sy.lastVer = sy.d.version; await A.api("POST", "/api/system/patch/rollback"); startPoll(); load(); } catch (err) { A.fail("롤백 요청 실패", err); }
      }
    });
    $("#sys-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-sys")) return;
    wire();
    $("#nav-sys").onclick = () => { $$(".drawer").forEach(d => { if (d.id !== "drawer-sys") d.hidden = true; }); $("#drawer-sys").hidden = false; load(); };
    A.ready.then(me => { if (me === null) return; A.api("GET", "/api/system/version", undefined, {background: true}).then(d => { const v = $("#app-ver"); if (v) v.textContent = d.version; }).catch(() => {}); });
  });
})();
