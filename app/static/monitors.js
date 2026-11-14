/* 모니터(Datadog 방식) — 목록·상태 요약·상세(그룹·이력·추이)·만들기/편집(미리 보기)·음소거·복제·삭제 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const ST = {ALERT: "경보", WARN: "경고", NO_DATA: "데이터 없음", OK: "정상", PENDING: "평가 대기", MUTED: "음소거"};
  const mo = {d: null, cat: null, q: "", st: "", sel: null, timer: null};
  const dt = ts => ts ? new Date(ts * 1000).toLocaleString() : "-";
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.round(s)}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };
  const num = v => v === null || v === undefined ? "-" : (Math.abs(v) >= 1e6 ? `${(v / 1e6).toFixed(1)}M` : Math.abs(v) >= 1e4 ? `${(v / 1e3).toFixed(1)}k` : `${Math.round(v * 100) / 100}`);

  async function cat() { if (!mo.cat) mo.cat = await A.api("GET", "/api/monitors/catalog"); return mo.cat; }
  async function load() {
    try { mo.d = await A.api("GET", "/api/monitors", undefined, {background: true}); } catch (e) { $("#mon-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render(); badge();
  }
  function badge() {
    const n = (mo.d.summary.ALERT || 0), b = $("#mon-badge"); if (!b) return;
    b.hidden = !n; b.textContent = n; b.title = `경보 ${n}`;
  }
  function qsum(m, c) {
    const q = m.query || {};
    if (m.type === "metric") { const x = (c && c.metrics[q.metric]) || {}; return `${q.agg || "avg"}(${esc(x.label || q.metric)})${q.filter ? ` · ${esc(q.filter)}` : ""}`; }
    if (m.type === "log" || m.type === "nodata") return `${m.type === "nodata" ? "무수신 " : "로그 "}${(q.sources || []).join(",") || "전체 소스"}${q.min_severity ? ` · ${esc(q.min_severity)}↑` : ""}${q.host ? ` · ${esc(q.host)}` : ""}${q.text ? ` · "${esc(q.text)}"` : ""}${m.group_by && m.type === "log" ? ` · 그룹 ${esc(m.group_by)}` : ""}`;
    if (m.type === "connector") return `커넥터 ${(q.types || []).join(",") || "전체"} down`;
    if (m.type === "anomaly") return `열린 이상징후 ${esc(q.min_severity || "error")}↑${(q.sources || []).length ? " · " + q.sources.join(",") : ""}`;
    return m.type;
  }

  function render() {
    const d = mo.d, c = mo.cat;
    const q = mo.q.toLowerCase();
    const items = d.items.filter(m => (!q || `${m.name} ${(m.tags || []).join(" ")}`.toLowerCase().includes(q))
      && (!mo.st || (mo.st === "MUTED" ? m.muted : !m.muted && m.status === mo.st)));
    $("#mon-sub").textContent = `— ${d.items.length}개 · ${Math.round(d.interval)}초마다 평가`;
    $("#mon-body").innerHTML = `<div class="mon-bar"><div class="inv-chips">${["", "ALERT", "WARN", "NO_DATA", "OK", "MUTED"].map(s => `<button data-st="${s}" class="${mo.st === s ? "on" : ""}">${s ? `<i class="mon-dot ${s}"></i>${ST[s]} ${d.summary[s] || 0}` : `전체 ${d.items.length}`}</button>`).join("")}</div>
        <input id="mon-q" placeholder="이름·태그 검색" value="${esc(mo.q)}"></div>
      <div class="mon-wrap"><div class="mon-list">${items.length ? `<table class="vc-t mon-t"><thead><tr><th>상태</th><th>모니터</th><th>조건</th><th>그룹</th><th>우선</th><th>경보 시작</th><th>평가</th><th></th></tr></thead><tbody>${items.map(m => `
        <tr data-id="${esc(m.id)}" class="${mo.sel === m.id ? "sel" : ""}${m.enabled ? "" : " off"}"><td><span class="mon-st ${m.muted ? "MUTED" : m.status}">${m.muted ? "음소거" : ST[m.status] || m.status}</span></td>
          <td><b>${esc(m.name)}</b>${(m.tags || []).map(t => ` <span class="mon-tag">${esc(t)}</span>`).join("")}${m.error ? `<div class="bad small">${esc(m.error)}</div>` : ""}${m.enabled ? "" : ' <span class="label">꺼짐</span>'}</td>
          <td class="small">${qsum(m, c)} <b>${esc(m.op)} ${num(m.critical)}</b>${m.warning != null ? ` <span class="muted">(경고 ${num(m.warning)})</span>` : ""} · ${Math.round(m.window / 60)}분</td>
          <td class="small">${m.group_total ? `${m.groups.ALERT ? `<b class="bad">${m.groups.ALERT}</b>/` : m.groups.WARN ? `<b class="warn">${m.groups.WARN}</b>/` : ""}${m.group_total}` : "-"}</td>
          <td><span class="mon-p ${esc(m.priority)}">${esc(m.priority)}</span></td><td class="small">${m.triggered_since ? ago(m.triggered_since) : "-"}</td><td class="small">${ago(m.last_eval)}</td>
          <td class="nowrap"><button class="btn-sm" data-act="mute">${m.muted ? "음소거 해제" : "음소거"}</button> <button class="btn-sm" data-act="edit">편집</button> <button class="btn-sm" data-act="dup">복제</button> <button class="btn-sm" data-act="del">삭제</button></td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">${d.items.length ? "조건에 맞는 모니터가 없습니다." : "모니터가 없습니다. 오른쪽 위 '새 모니터'에서 빠른 템플릿(CPU·데이터스토어·커넥터·VIP·FortiGate 무차별 대입 등)으로 시작하세요."}</div>`}</div>
        <aside class="tp-detail" id="mon-detail" ${mo.sel ? "" : "hidden"}></aside></div>`;
    if (mo.sel) detail(mo.sel);
  }

  function spark(pts, w = 300, h = 46) {
    const v = pts.map(p => p[1]).filter(x => x != null); if (v.length < 2) return "";
    const mx = Math.max(...v), mn = Math.min(...v), t0 = pts[0][0], t1 = pts[pts.length - 1][0] || t0 + 1;
    const P = pts.filter(p => p[1] != null).map(p => `${((p[0] - t0) / (t1 - t0 || 1) * w).toFixed(1)},${(h - 3 - (p[1] - mn) / (mx - mn || 1) * (h - 6)).toFixed(1)}`);
    return `<svg viewBox="0 0 ${w} ${h}" class="mon-spk" preserveAspectRatio="none"><polyline points="${P.join(" ")}" fill="none" stroke="#0072a3" stroke-width="1.5"/></svg>`;
  }

  async function detail(id) {
    const p = $("#mon-detail"); if (!p) return;
    p.hidden = false;
    let d;
    try { d = await A.api("GET", `/api/monitors/${id}`, undefined, {background: true}); } catch (e) { p.innerHTML = `<p class="bad">${esc(e.message)}</p>`; return; }
    const m = d.monitor;
    p.innerHTML = `<div class="tp-dh"><b>${esc(m.name)}</b><button class="x" id="mon-dx" aria-label="닫기">✕</button></div>
      <div class="small muted">${esc(mo.d.types[m.type] || m.type)} · ${esc(m.priority)} · ${m.muted ? `음소거 ~${dt(m.muted_until)} ${esc(m.mute_reason || "")}` : ST[m.status] || m.status}</div>
      ${m.message ? `<p class="small">${esc(m.message)}</p>` : ""}
      <div class="tp-dact"><button class="btn-sm" id="mon-evalnow">지금 평가</button></div>
      <h5>그룹 <span class="muted small">${d.groups.length}</span></h5>
      <div class="mon-groups">${d.groups.slice(0, 200).map(g => `<div class="mon-g"><span class="mon-st ${g.state}">${ST[g.state] || g.state}</span><span class="mono">${esc(g.group === "*" ? "(전체)" : g.group)}</span><b>${num(g.value)}</b><small>${ago(g.since)}</small>
        ${d.series[g.group] ? spark(d.series[g.group]) : ""}</div>`).join("") || `<span class="muted small">아직 평가 전</span>`}</div>
      <h5>상태 변경 이력</h5><div class="tp-logs">${d.history.slice(0, 80).map(h => `<div class="tp-log"><i class="mon-dot ${h.to_state}"></i><time>${dt(h.ts)}</time> ${esc(h.grp === "*" ? "" : h.grp)} ${ST[h.from_state] || h.from_state} → <b>${ST[h.to_state] || h.to_state}</b> (${num(h.value)})</div>`).join("") || `<span class="muted small">이력 없음</span>`}</div>`;
  }

  // ---------------------------------------------------------------- 편집기
  async function edit(src, title) {
    const c = await cat();
    const m = JSON.parse(JSON.stringify(src || {type: "metric", query: {metric: "host.cpu_pct", agg: "avg"}, window: 300, op: ">", critical: 90, warning: 80, priority: "P3", tags: [], enabled: true}));
    const srcOpts = sel => c.sources.map(s => `<label class="chk"><input type="checkbox" value="${esc(s)}" ${sel.includes(s) ? "checked" : ""}> ${esc(s)}</label>`).join("");
    const body = () => {
      const q = m.query || {};
      const typeFields = {
        metric: `<label class="frow"><span class="fl">지표</span><select id="me-metric">${Object.entries(c.metrics).map(([k, v]) => `<option value="${k}" ${q.metric === k ? "selected" : ""}>${esc(v.label)} (${k}${v.unit ? ", " + esc(v.unit) : ""})</option>`).join("")}</select></label>
          <label class="frow"><span class="fl">집계(평가 창)</span><select id="me-agg">${["avg", "max", "min", "last"].map(a => `<option ${q.agg === a ? "selected" : ""}>${a}</option>`).join("")}</select></label>
          <label class="frow"><span class="fl">그룹 필터(와일드카드)</span><input id="me-filter" value="${esc(q.filter || "")}" placeholder="예) esx0*, prod-*"></label>`,
        log: `<div class="frow"><span class="fl">소스(비우면 전체)</span><div class="me-srcs" id="me-srcs">${srcOpts(q.sources || [])}</div></div>
          <label class="frow"><span class="fl">최소 등급</span><select id="me-sev"><option value="">전체</option>${c.severities.map(s => `<option ${q.min_severity === s ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <label class="frow"><span class="fl">호스트(와일드카드)</span><input id="me-host" value="${esc(q.host || "")}" placeholder="예) esx*, *.bank.local"></label>
          <label class="frow"><span class="fl">포함 문자열</span><input id="me-text" value="${esc(q.text || "")}" placeholder="예) login failed, ORA-"></label>
          <label class="frow chk"><input type="checkbox" id="me-regex" ${q.regex ? "checked" : ""}> 정규식</label>
          <label class="frow"><span class="fl">그룹(따로 알림)</span><select id="me-gb">${[["", "전체 합계"], ["host", "호스트별"], ["source", "소스별"], ["entity", "개체별"], ["connector", "커넥터별"]].map(([k, l]) => `<option value="${k}" ${m.group_by === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>`,
        nodata: `<div class="frow"><span class="fl">소스(비우면 전체)</span><div class="me-srcs" id="me-srcs">${srcOpts(q.sources || [])}</div></div>
          <label class="frow"><span class="fl">호스트(와일드카드)</span><input id="me-host" value="${esc(q.host || "")}" placeholder="예) db*"></label>
          <p class="hint">최근 24시간 안에 로그를 보낸 호스트 중 평가 창 동안 건수가 조건에 맞는 호스트를 알립니다(보통 '&lt;' 1).</p>`,
        connector: `<label class="frow"><span class="fl">커넥터 유형(쉼표, 비우면 전체)</span><input id="me-ctypes" value="${esc((q.types || []).join(","))}" placeholder="vcenter,nsx,avi"></label><p class="hint">평가 창 내내 연결 오류(down)인 커넥터를 알립니다.</p>`,
        anomaly: `<label class="frow"><span class="fl">최소 등급</span><select id="me-sev">${c.severities.map(s => `<option ${(q.min_severity || "error") === s ? "selected" : ""}>${s}</option>`).join("")}</select></label>
          <div class="frow"><span class="fl">소스(비우면 전체)</span><div class="me-srcs" id="me-srcs">${srcOpts(q.sources || [])}</div></div>`,
      }[m.type];
      return `<form class="sform" id="me-form"><div class="fgrid">
        <label class="frow"><span class="fl">이름 *</span><input id="me-name" value="${esc(m.name || "")}"></label>
        <label class="frow"><span class="fl">유형</span><select id="me-type">${Object.entries(c.types).map(([k, v]) => `<option value="${k}" ${m.type === k ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
        ${typeFields}
        <label class="frow"><span class="fl">평가 창(분)</span><input id="me-win" type="number" min="1" max="1440" value="${Math.round((m.window || 300) / 60)}"></label>
        <label class="frow"><span class="fl">조건</span><select id="me-op">${[">", ">=", "<", "<="].map(o => `<option ${m.op === o ? "selected" : ""}>${o}</option>`).join("")}</select></label>
        <label class="frow"><span class="fl">위험(경보) 임계 *</span><input id="me-crit" type="number" step="any" value="${m.critical ?? ""}"></label>
        <label class="frow"><span class="fl">경고 임계</span><input id="me-warn" type="number" step="any" value="${m.warning ?? ""}"></label>
        <label class="frow"><span class="fl">우선순위</span><select id="me-prio">${c.priorities.map(p => `<option ${m.priority === p ? "selected" : ""}>${p}</option>`).join("")}</select></label>
        <label class="frow"><span class="fl">재알림(분, 0=안 함)</span><input id="me-renot" type="number" min="0" value="${m.renotify_minutes || 0}"></label>
        <label class="frow"><span class="fl">태그(쉼표)</span><input id="me-tags" value="${esc((m.tags || []).join(","))}"></label>
        <label class="frow chk"><input type="checkbox" id="me-nodata" ${m.notify_nodata ? "checked" : ""}> 데이터 없음도 알림</label>
        <label class="frow chk"><input type="checkbox" id="me-en" ${m.enabled !== false ? "checked" : ""}> 사용</label>
        <label class="frow wide"><span class="fl">알림 메시지(선택) — {{value}} {{group}} {{name}}</span><textarea id="me-msg" rows="2">${esc(m.message || "")}</textarea></label>
      </div><div class="ax-bar"><button type="button" class="btn-sm" id="me-prev">미리 보기(현재 값)</button><span id="me-prev-st" class="small"></span></div><div id="me-prev-out"></div></form>`;
    };
    const read = f => {
      const g = s => f.querySelector(s);
      const out = {...m, name: g("#me-name").value.trim(), type: g("#me-type").value, window: Number(g("#me-win").value || 5) * 60, op: g("#me-op").value,
        critical: g("#me-crit").value === "" ? null : Number(g("#me-crit").value), warning: g("#me-warn").value === "" ? null : Number(g("#me-warn").value),
        priority: g("#me-prio").value, renotify_minutes: Number(g("#me-renot").value || 0), tags: g("#me-tags").value.split(",").map(x => x.trim()).filter(Boolean),
        notify_nodata: g("#me-nodata").checked, enabled: g("#me-en").checked, message: g("#me-msg").value};
      const srcs = g("#me-srcs") ? [...g("#me-srcs").querySelectorAll("input:checked")].map(x => x.value) : [];
      if (out.type === "metric") out.query = {metric: g("#me-metric").value, agg: g("#me-agg").value, filter: g("#me-filter").value.trim()};
      if (out.type === "log") { out.query = {sources: srcs, min_severity: g("#me-sev").value, host: g("#me-host").value.trim(), text: g("#me-text").value, regex: g("#me-regex").checked}; out.group_by = g("#me-gb").value; }
      if (out.type === "nodata") out.query = {sources: srcs, host: g("#me-host").value.trim()};
      if (out.type === "connector") out.query = {types: g("#me-ctypes").value.split(",").map(x => x.trim()).filter(Boolean)};
      if (out.type === "anomaly") out.query = {min_severity: g("#me-sev").value, sources: srcs};
      return out;
    };
    const v = await A.modal({title, wide: true, ok: src && src.id ? "저장" : "만들기", html: `<div id="me-box">${body()}</div>`,
      onOpen: md => {
        const box = md.querySelector("#me-box");
        box.addEventListener("change", e => {
          if (e.target.id === "me-type") { Object.assign(m, read(box.querySelector("#me-form"))); m.type = e.target.value;
            m.query = m.type === "metric" ? {metric: "host.cpu_pct", agg: "avg"} : m.type === "nodata" ? {} : m.type === "anomaly" ? {min_severity: "error"} : {};
            if (m.type === "nodata") { m.op = "<"; m.critical = 1; m.warning = null; }
            box.innerHTML = body(); }
        });
        box.addEventListener("click", async e => {
          if (e.target.id !== "me-prev") return;
          const st = box.querySelector("#me-prev-st"); st.innerHTML = '<span class="spin"></span>';
          try {
            const r = await A.api("POST", "/api/monitors/preview", read(box.querySelector("#me-form")));
            st.textContent = `그룹 ${r.total}개`;
            box.querySelector("#me-prev-out").innerHTML = `<div class="mon-groups">${r.groups.slice(0, 50).map(g => `<div class="mon-g"><span class="mon-st ${g.state}">${ST[g.state]}</span><span class="mono">${esc(g.group === "*" ? "(전체)" : g.group)}</span><b>${num(g.value)}</b></div>`).join("") || '<span class="muted small">해당 데이터 없음</span>'}</div>`;
          } catch (err) { st.innerHTML = `<span class="bad">${esc(err.message)}</span>`; }
        });
        md.querySelector("[data-ok]").addEventListener("click", () => { mo._ed = read(box.querySelector("#me-form")); }, {capture: true});
      }});
    if (v === null || !mo._ed) return;
    const body2 = mo._ed; mo._ed = null;
    try {
      if (src && src.id) await A.api("PUT", `/api/monitors/${src.id}`, body2); else { const r = await A.api("POST", "/api/monitors", body2); mo.sel = r.id; }
      A.ok("저장됨", body2.name); load();
    } catch (err) { A.fail("저장 실패", err); edit(body2, title); }
  }

  async function newMenu() {
    const c = await cat();
    const v = await A.modal({title: "새 모니터", ok: "", cancel: "닫기", wide: true,
      html: `<p class="modal-text">빠른 템플릿에서 시작하거나 빈 모니터를 만드세요(만든 뒤 임계값·대상을 조정).</p>
        <div class="mon-presets"><button class="mon-pre" data-pre="-1"><b>빈 모니터</b><span>유형·조건을 직접 설정</span></button>${c.presets.map((p, i) => `<button class="mon-pre" data-pre="${i}"><b>${esc(p.name)}</b><span>${esc(c.types[p.type])} · ${esc(p.priority)} · ${(p.tags || []).join(",")}</span></button>`).join("")}</div>`,
      onOpen: md => md.addEventListener("click", e => { const b = e.target.closest("[data-pre]"); if (!b) return; mo._pre = Number(b.dataset.pre); md.querySelector("[data-x]").click(); })});
    void v;
    if (mo._pre === undefined) return;
    const i = mo._pre; mo._pre = undefined;
    edit(i >= 0 ? {...c.presets[i], enabled: true} : null, "새 모니터");
  }

  function wire() {
    const b = $("#mon-body");
    b.addEventListener("click", async e => {
      const s = e.target.closest("[data-st]"); if (s) { mo.st = s.dataset.st; render(); return; }
      if (e.target.id === "mon-dx") { mo.sel = null; $("#mon-detail").hidden = true; $$(".mon-t tr.sel").forEach(x => x.classList.remove("sel")); return; }
      if (e.target.id === "mon-evalnow") { try { await A.api("POST", `/api/monitors/${mo.sel}/evaluate`); detail(mo.sel); load(); } catch (err) { A.fail("평가 실패", err); } return; }
      const act = e.target.closest("[data-act]"), tr = e.target.closest("tr[data-id]");
      if (!tr) return;
      const m = mo.d.items.find(x => x.id === tr.dataset.id);
      if (!act) { mo.sel = m.id; $$(".mon-t tr.sel").forEach(x => x.classList.remove("sel")); tr.classList.add("sel"); detail(m.id); return; }
      const a = act.dataset.act;
      if (a === "edit") edit(m, `모니터 편집 — ${m.name}`);
      if (a === "dup") edit({...m, id: undefined, name: `${m.name} (복사본)`}, "모니터 복제");
      if (a === "del" && await A.confirm("모니터 삭제", `'${m.name}' 모니터와 상태 이력을 삭제합니다.`, true)) { try { await A.api("DELETE", `/api/monitors/${m.id}`); if (mo.sel === m.id) mo.sel = null; load(); } catch (err) { A.fail("삭제 실패", err); } }
      if (a === "mute") {
        if (m.muted) { await A.api("POST", `/api/monitors/${m.id}/mute`, {}); load(); return; }
        const v = await A.modal({title: `음소거 — ${m.name}`, ok: "음소거", html: `<p class="modal-text">기간 동안 평가는 계속하고 알림만 보내지 않습니다(작업 창·알려진 이슈).</p>`,
          fields: [{id: "m", label: "기간", type: "select", value: "60", options: [["30", "30분"], ["60", "1시간"], ["240", "4시간"], ["1440", "1일"], ["10080", "1주"]]}, {id: "r", label: "사유", placeholder: "예) CHG0012345 패치 작업"}]});
        if (v) { await A.api("POST", `/api/monitors/${m.id}/mute`, {minutes: Number(v.m), reason: v.r || ""}); load(); }
      }
    });
    let t; b.addEventListener("input", e => { if (e.target.id !== "mon-q") return; clearTimeout(t); t = setTimeout(() => { mo.q = e.target.value; render(); const q = $("#mon-q"); q.focus(); q.setSelectionRange(q.value.length, q.value.length); }, 200); });
    $("#mon-new").onclick = newMenu;
    $("#mon-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-mon")) return;
    wire();
    $("#nav-mon").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-mon") d.hidden = true; });
      $("#drawer-mon").hidden = false; cat().then(load);
      clearInterval(mo.timer); mo.timer = setInterval(() => $("#drawer-mon").hidden ? clearInterval(mo.timer) : load(), 15000);
    };
    A.ready.then(me => { if (me === null) return; const tick = () => A.api("GET", "/api/monitors", undefined, {background: true}).then(d => { mo.d = d; badge(); }).catch(() => {}); setTimeout(tick, 5000); setInterval(tick, 60000); });
  });
})();
