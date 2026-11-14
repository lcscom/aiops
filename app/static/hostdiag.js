/* 호스트 분석(2.18.0) — ESXi 호스트 연결 끊김(not responding·disconnected) 원인 조사
   vCenter 이벤트·작업·vpxd 로그 + 호스트 hostd/vpxa/vmkernel/vobd 로그(vCenter 경유) + 이 서버가 받은 ESXi syslog 를 한 타임라인으로,
   끊김 구간마다 직전·직후 증거로 원인 후보(네트워크·hostd·하트비트 UDP 902·스토리지 APD·재부팅·사용자 작업·다수 호스트 동시 …) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const enc = encodeURIComponent;
  const st = {hosts: [], days: 7, sel: "", res: null, hours: 24, from: "", to: "", live: true, hf: "", tf: "", src: new Set(), sev: "", win: null, ai: null, busy: false, limit: 1500};
  const SRC = {event: ["vCenter 이벤트", "#1d6fb8"], task: ["vCenter 작업", "#5b2d90"], vpxd: ["vpxd 로그", "#0b7a75"], hostlog: ["호스트 로그(vCenter 경유)", "#8a5a00"],
               syslog: ["ESXi syslog", "#2e7d32"], pipeline: ["수집 이벤트", "#566"]};
  const CONF = {"높음": "bad", "중간": "warn", "낮음": "unk"};
  const fmt = ts => ts ? new Date(ts * 1000).toLocaleString([], {year: "2-digit", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "-";
  const hm = ts => ts ? new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "-";
  const dur = s => s == null ? "-" : s < 90 ? `${Math.round(s)}초` : s < 5400 ? `${Math.round(s / 60)}분` : `${(s / 3600).toFixed(1)}시간`;
  const ago = ts => ts ? dur(Date.now() / 1000 - ts) + " 전" : "-";
  const n = x => x == null ? "—" : Number(x).toLocaleString();
  const conn = c => { const m = {connected: ["연결", "ok"], disconnected: ["연결 끊김", "bad"], notResponding: ["응답 없음", "bad"]}[c] || [c || "?", "unk"]; return `<span class="rd-b ${m[1]}">${esc(m[0])}</span>`; };
  const srcKey = it => it.kind === "event" ? (it.via === "pipeline" ? "event" : "event") : it.kind === "task" ? "task" : it.kind === "vpxd" ? "vpxd" : it.via === "syslog" ? "syslog" : it.kind === "hostlog" || it.via === "hostlog" ? "hostlog" : "pipeline";
  const DOWN = /not responding|connection lost|lost connection|disconnected from|cannot synchronize host|NO_RESPONSE|state changed to \[?DISCONNECTED/i;
  const UP = /^connected to |connection state changed to \[?CONNECTED|reconnected/i;

  async function loadHosts() {
    try { const r = await A.api("GET", `/api/hostdiag/hosts?days=${st.days}`, undefined, {background: true}); st.hosts = r.items; st.vcs = r.vcenters; }
    catch (e) { A.fail("호스트 목록 실패", e); }
  }
  async function analyze(name) {
    if (!name || st.busy) return;
    st.sel = name; st.busy = true; st.win = null; st.focus = null; st.ai = null; render();
    const q = st.from && st.to ? `start=${new Date(st.from).getTime() / 1000}&end=${new Date(st.to).getTime() / 1000}` : `hours=${st.hours}`;
    try { st.res = await A.api("GET", `/api/hostdiag/host?name=${enc(name)}&${q}&live=${st.live ? 1 : 0}`); }
    catch (e) { A.fail("호스트 분석 실패", e); st.res = null; }
    st.busy = false; render();
  }

  // ------------------------------------------------------------------ 왼쪽: 호스트 목록
  function hostList() {
    const f = st.hf.toLowerCase();
    const H = st.hosts.filter(h => !f || (h.name + h.cluster + h.vcenter).toLowerCase().includes(f));
    return `<div class="hd-side"><div class="rd-tools"><input id="hd-hf" placeholder="호스트 검색" value="${esc(st.hf)}">
        <select id="hd-days">${[[1, "1일"], [3, "3일"], [7, "7일"], [14, "14일"], [30, "30일"]].map(([v, l]) => `<option value="${v}" ${st.days === v ? "selected" : ""}>끊김 ${l}</option>`).join("")}</select></div>
      <div class="hd-hosts">${H.map(h => `<button class="hd-h ${h.name === st.sel ? "on" : ""} ${h.disconnects ? "has" : ""}" data-hd="${esc(h.name)}">
          <span class="hd-hn">${esc(h.name)}</span>${conn(h.connection)}
          <small>${esc(h.cluster || h.vcenter || "")}</small>
          <span class="hd-hm"><b class="${h.disconnects ? "cc-na" : ""}">${h.disconnects ? `끊김 ${h.disconnects}회` : "끊김 없음"}</b>${h.last_disconnect ? ` · ${ago(h.last_disconnect)}` : ""}
            <i class="${h.syslog_24h ? "ok" : "no"}" title="${h.syslog_24h ? `최근 24시간 syslog ${h.syslog_24h}줄 · 마지막 ${fmt(h.syslog_last)}` : "이 서버로 syslog 를 보내지 않음"}">syslog ${h.syslog_24h ? "✓" : "✗"}</i></span></button>`).join("")
        || `<p class="muted small pad">vCenter 커넥터의 호스트가 없습니다.</p>`}</div></div>`;
  }

  // ------------------------------------------------------------------ 오른쪽: 분석
  function stateCard(r) {
    const s = r.state || {}, c = r.counts.by_source || {};
    const cnt = k => Object.entries(c).filter(([x]) => x.startsWith(k)).reduce((a, [, v]) => a + v, 0);
    const ipMis = s.vc_managed_ip && s.vc_ip_seen_by_host && s.vc_managed_ip !== s.vc_ip_seen_by_host;
    const kv = (k, v, cls = "") => v === undefined || v === null || v === "" ? "" : `<span>${k}</span><b class="${cls}">${v}</b>`;
    return `<div class="rd-card"><h4>${esc(r.host)} ${s.connection ? conn(s.connection) : ""} <small>${esc(r.vcenter || "")}${s.cluster ? " · " + esc(s.cluster) : ""}</small></h4>
      <div class="rv-kv">${kv("ESXi", esc(s.version || ""))}${kv("서버", esc(`${s.vendor || ""} ${s.model || ""}`.trim()))}${kv("부팅", s.boot_time ? `${fmt(s.boot_time)} (가동 ${dur(s.uptime_s)})` : "")}
        ${kv("관리 IP(vmk0)", esc(s.mgmt_ip || ""))}${kv("호스트가 아는 vCenter IP", esc(s.vc_ip_seen_by_host || ""), ipMis ? "cc-na" : "")}${kv("vCenter 관리 IP 설정", esc(s.vc_managed_ip || "(자동)"), ipMis ? "cc-na" : "")}
        ${kv("HA", esc(s.ha_state || ""))}${kv("잠금 모드", esc(s.lockdown || ""))}${kv("유지보수", s.maintenance ? "예" : "")}</div>
      <div class="hd-srcs">${[["vCenter 이벤트", cnt("event")], ["작업", cnt("task")], ["vpxd 로그", cnt("vpxd")], ["호스트 로그", cnt("hostlog") + cnt("log:hostlog")], ["syslog", cnt("log:syslog")]]
        .map(([k, v]) => `<span class="${v ? "" : "zero"}">${k} <b>${n(v)}</b></span>`).join("")}<span>저장 로그 ${n(r.stored_rows)}</span></div>
      ${r.error ? `<div class="rd-alert bad">${esc(r.error)}</div>` : ""}
      ${(r.gaps || []).length ? `<details class="hd-gaps"><summary>수집 공백 ${r.gaps.length}건</summary>${r.gaps.map(g => `<div>${esc(g)}</div>`).join("")}</details>` : ""}
      ${!r.syslog?.lines_24h ? `<div class="hd-warn">이 호스트의 ESXi syslog 를 이 서버가 받지 않고 있습니다 — 끊김 당시 호스트 쪽 근거(vmkernel·vobd·hostd)가 남지 않습니다. <button class="btn-sm" id="hd-fwd">로그 전송 설정 열기</button></div>` : ""}</div>`;
  }
  function strip(r) {
    const W = 1000, s0 = r.start, s1 = r.end, X = t => Math.max(0, Math.min(W, (t - s0) / (s1 - s0) * W)), P = t => (X(t) / W * 100).toFixed(2);
    const span = s1 - s0, step = [600, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400].find(x => span / x <= 8) || 7 * 86400;
    const ticks = []; for (let t = Math.ceil(s0 / step) * step; t < s1; t += step) ticks.push(t);
    const lab = t => new Date(t * 1000).toLocaleString([], step >= 86400 ? {month: "2-digit", day: "2-digit"} : {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"});
    const bars = r.episodes.map((e, i) => `<rect class="hd-ep ${e.user_initiated ? "user" : ""}" data-hdep="${i}" x="${X(e.start)}" y="4" width="${Math.max(4, X(e.end || s1) - X(e.start))}" height="24"><title>${fmt(e.start)} · ${dur(e.duration)} · ${esc((e.causes[0] || {}).title || "원인 미상")}</title></rect>`).join("");
    const sl = (r.items || []).filter(it => it.via === "syslog"); const bins = new Array(100).fill(0);
    sl.forEach(it => { bins[Math.min(99, Math.max(0, Math.floor((it.ts - s0) / (s1 - s0) * 100)))]++; });
    const mx = Math.max(1, ...bins);
    const sys = sl.length ? bins.map((v, i) => `<rect x="${i * 10}" y="${48 - v / mx * 16}" width="9" height="${v / mx * 16}" class="hd-sl"/>`).join("") : "";
    return `<div class="rd-card"><h4>끊김 구간 <small>${r.counts.episodes}회 · 합계 ${dur(r.counts.downtime_s)}${r.counts.ongoing ? " · <b class='cc-na'>지금 끊김 중</b>" : ""} — 막대를 누르면 그 구간으로</small></h4>
      <div class="hd-sw"><svg class="hd-strip" viewBox="0 0 ${W} 50" preserveAspectRatio="none"><rect x="0" y="4" width="${W}" height="24" class="hd-bg"/>
        ${ticks.map(t => `<line x1="${X(t)}" x2="${X(t)}" y1="0" y2="50" class="hd-tick"/>`).join("")}${sys}${bars}</svg>
        <div class="hd-ticks">${ticks.map(t => `<span style="left:${P(t)}%">${esc(lab(t))}</span>`).join("")}</div></div>
      <div class="small muted hd-leg"><i class="r"></i>응답 없음·끊김 <i class="g"></i>사용자 작업 연결 해제 <i class="s"></i>받은 syslog 양(끊김 동안 비면 관리망 단절 쪽)</div>
      ${(r.patterns || []).map(p => `<div class="hd-pat">⟳ ${esc(p)}</div>`).join("")}</div>`;
  }
  function epCard(e, i) {
    const top = e.causes[0];
    return `<div class="rd-card hd-epc" id="hd-ep-${i}"><h4>${fmt(e.start)} <small>${e.ongoing ? "<b class='cc-na'>진행 중</b>" : `${dur(e.duration)} 뒤 복구 ${hm(e.end)}`}</small>
        ${top ? `<span class="rd-b ${CONF[top.confidence]}">${esc(top.title)} · ${esc(top.confidence)}</span>` : `<span class="rd-b unk">원인 미상</span>`}
        <span class="rd-sp"></span><button class="btn-sm" data-hdwin="${i}">이 구간 타임라인</button></h4>
      <div class="small">계기: <code>${esc(e.trigger.type || "")}</code> ${esc(e.trigger.message || "")}${e.trigger.user ? ` · 사용자 ${esc(e.trigger.user)}` : ""}</div>
      ${e.notes.map(x => `<div class="hd-note">${esc(x)}</div>`).join("")}
      <div class="hd-causes">${e.causes.map(c => `<details ${c === top ? "open" : ""}><summary><span class="rd-b ${CONF[c.confidence]}">${esc(c.confidence)}</span> <b>${esc(c.title)}</b> <small class="muted">점수 ${c.score} · 증거 ${c.evidence.length}</small></summary>
          <table class="rd-t hd-ev"><tbody>${c.evidence.map(x => `<tr><td class="nowrap small">${hm(x.ts)}</td><td class="small nowrap">${esc(x.source || x.kind || "")}</td><td class="small mono">${esc(String(x.message || "").slice(0, 400))}</td></tr>`).join("")}</tbody></table>
          <div class="hd-chk"><b>확인</b>${c.checks.map(k => `<div>• ${esc(k)}</div>`).join("")}<a href="${esc(c.kb)}" target="_blank" rel="noopener">Broadcom KB</a></div></details>`).join("")}</div></div>`;
  }
  function timeline(r) {
    let items = r.items || [];
    if (st.win) items = items.filter(it => it.ts >= st.win[0] && it.ts <= st.win[1]);
    const f = st.tf.toLowerCase();
    const counts = {}; items.forEach(it => { const k = srcKey(it); counts[k] = (counts[k] || 0) + 1; });
    const R = items.filter(it => (!st.src.size || st.src.has(srcKey(it))) && (!st.sev || ["critical", "error", "warning"].slice(0, ["critical", "error", "warning"].indexOf(st.sev) + 1).includes(it.severity))
      && (!f || (it.message + " " + (it.type || "")).toLowerCase().includes(f)));
    const show = R.slice(-st.limit);
    return `<div class="rd-card"><h4>통합 타임라인 <small>${st.win ? `${fmt(st.win[0])} ~ ${hm(st.win[1])} <button class="btn-sm" id="hd-winx">전체 기간</button>` : "전체 기간"} · ${n(R.length)}줄${R.length > show.length ? ` (최신 ${n(show.length)}줄 표시)` : ""}</small></h4>
      <div class="rd-tools">${Object.entries(SRC).map(([k, [l, c]]) => `<label class="hd-chip" style="--c:${c}"><input type="checkbox" data-hdsrc="${k}" ${!st.src.size || st.src.has(k) ? "checked" : ""}>${l} <b>${n(counts[k] || 0)}</b></label>`).join("")}
        <select id="hd-sev"><option value="">모든 등급</option><option value="warning" ${st.sev === "warning" ? "selected" : ""}>경고 이상</option><option value="error" ${st.sev === "error" ? "selected" : ""}>오류 이상</option></select>
        <input id="hd-tf" placeholder="메시지 검색" value="${esc(st.tf)}"></div>
      <div class="rd-scroll hd-tl"><table class="rd-t"><thead><tr><th>시각</th>${st.focus ? "<th>끊김 기준</th>" : ""}<th>출처</th><th>등급</th><th>메시지</th></tr></thead><tbody>${show.map(it => {
        const k = srcKey(it), d = (it.kind === "event" || it.kind === "vpxd") && DOWN.test(it.message), u = (it.kind === "event" || it.kind === "vpxd") && UP.test(it.message);
        const dt = st.focus ? Math.round(it.ts - st.focus) : null;
        return `<tr class="${d ? "hd-down" : u ? "hd-up" : ""}" data-ts="${it.ts}"><td class="nowrap small">${fmt(it.ts)}</td>${st.focus ? `<td class="nowrap small num ${Math.abs(dt) <= 300 ? "hd-near" : "muted"}">${dt === 0 ? "T" : (dt > 0 ? "T+" : "T−") + dur(Math.abs(dt))}</td>` : ""}<td class="nowrap small"><i class="hd-dot" style="background:${SRC[k][1]}"></i>${esc(it.kind === "hostlog" || it.via === "hostlog" ? it.source : SRC[k][0])}${it.type && it.kind === "event" ? `<div class="muted">${esc(it.type)}</div>` : ""}</td>
          <td class="small">${esc(it.severity || "")}</td><td class="small mono hd-msg">${esc(it.message)}${it.user ? ` <span class="muted">· ${esc(it.user)}</span>` : ""}</td></tr>`; }).join("")}</tbody></table></div>
      ${R.length > show.length ? `<button class="btn-sm" id="hd-more">이전 ${n(Math.min(3000, R.length - show.length))}줄 더 보기</button>` : ""}</div>`;
  }
  function aiCard() {
    return `<div class="rd-card"><h4>AI 설명 <small>끊김 구간·원인 후보·증거 로그를 설정된 LLM(PAIS 등)에 보내 설명 — 외부 공급자면 호스트 이름 가명화</small></h4>
      <button class="btn-sm solid" id="hd-ai" data-perm="operate">AI 에게 원인 설명 받기</button><div class="rv-md" id="hd-aib">${st.ai ? md(st.ai.report) : ""}</div></div>`;
  }
  function md(t) {
    const inl = x => esc(x).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>"); const out = [];
    for (const ln of String(t || "").replace(/<think>[\s\S]*?<\/think>/g, "").split("\n")) {
      const m = ln.match(/^(#{1,4})\s+(.+)$/);
      if (m) out.push(`<h5 class="rv-mh">${inl(m[2])}</h5>`); else if (/^\s*([-*]|\d+\.)\s+/.test(ln)) out.push(`<div class="rv-li">• ${inl(ln.replace(/^\s*([-*]|\d+\.)\s+/, ""))}</div>`); else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
    }
    return out.join("");
  }
  function focusRow(tl, ts) {             // 끊김 시각에 가장 가까운 줄을 표 가운데로
    const rows = [...tl.querySelectorAll("tr[data-ts]")]; if (!rows.length) return;
    const r = rows.reduce((a, b) => Math.abs(+b.dataset.ts - ts) < Math.abs(+a.dataset.ts - ts) ? b : a);
    r.classList.add("hd-focus"); tl.scrollTop = r.offsetTop - tl.clientHeight / 2;
  }
  function main() {
    if (st.busy) return `<div class="rd-card"><p class="muted">${esc(st.sel)} 분석 중… vCenter 이벤트·작업·vpxd·호스트 로그와 저장된 syslog 를 모으는 중(로그 포함 시 수십 초)</p></div>`;
    const r = st.res;
    if (!r) return `<div class="rd-card"><h4>호스트를 고르세요</h4><p class="muted">왼쪽 목록은 최근 ${st.days}일 끊김 횟수 순입니다. 고르면 기간 안의 끊김 구간을 찾아 직전·직후 vCenter 이벤트·작업·vpxd 로그·호스트 로그·syslog 로 원인 후보를 매깁니다.</p>
      <p class="small muted">근거: Broadcom KB 344682(not responding/disconnected 점검), 318647(UDP 902 하트비트 — 10초 간격·60초 안에 못 받으면 not responding), 377738(다수 호스트 동시), 433257(hostd 무응답).</p></div>`;
    return stateCard(r) + strip(r) + (r.episodes.length ? r.episodes.map(epCard).join("") : `<div class="rd-card"><p class="muted">이 기간에 끊김 기록이 없습니다(vCenter 이벤트·vpxd 로그 기준). 기간을 넓혀 보세요.</p></div>`) + aiCard() + timeline(r);
  }
  function toolbar() {
    return `<div class="rv-top hd-bar"><label class="small">기간 <select id="hd-hours">${[[1, "1시간"], [6, "6시간"], [24, "24시간"], [72, "3일"], [168, "7일"], [336, "14일"], [744, "31일"]].map(([v, l]) => `<option value="${v}" ${!st.from && st.hours === v ? "selected" : ""}>${l}</option>`).join("")}<option value="c" ${st.from ? "selected" : ""}>직접 지정</option></select></label>
      ${st.from !== "" || st.custom ? `<input type="datetime-local" id="hd-from" value="${esc(st.from)}"> ~ <input type="datetime-local" id="hd-to" value="${esc(st.to)}">` : ""}
      <label class="small" title="끄면 저장된 로그만으로(빠름). 켜면 vCenter 에서 이벤트·작업·vpxd·호스트 로그까지 지금 읽음"><input type="checkbox" id="hd-live" ${st.live ? "checked" : ""}> vCenter 실시간 조회(로그 포함)</label>
      <button class="btn-sm solid" id="hd-go" ${st.sel ? "" : "disabled"}>분석</button><span class="rd-sp"></span>
      ${st.res ? `<a class="btn-sm" href="/api/hostdiag/host.csv?name=${enc(st.sel)}">타임라인 CSV</a>` : ""}</div>`;
  }
  function render() {
    const box = $("#hd-body"); if (!box) return;
    const keep = document.activeElement && ["hd-tf", "hd-hf"].includes(document.activeElement.id) ? [document.activeElement.id, document.activeElement.selectionStart] : null;
    box.innerHTML = toolbar() + `<div class="hd-grid">${hostList()}<div class="hd-main">${main()}</div></div>`;
    if (keep) { const t = $("#" + keep[0]); if (t) { t.focus(); t.setSelectionRange(keep[1], keep[1]); } }
    if (A.me && A.can) $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
  }
  function wire() {
    const box = $("#hd-body"); if (box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target.closest("[data-hd],[data-hdep],[data-hdwin],#hd-go,#hd-winx,#hd-more,#hd-ai,#hd-fwd"); if (!t) return;
      if (t.dataset.hd) { analyze(t.dataset.hd); return; }
      if (t.dataset.hdep !== undefined || t.dataset.hdwin !== undefined) {
        const i = +(t.dataset.hdep ?? t.dataset.hdwin), ep = st.res.episodes[i]; st.win = ep.window; st.focus = ep.start; st.limit = 5000; render();
        const c = $(`#hd-ep-${i}`); if (c && t.dataset.hdep !== undefined) c.scrollIntoView({block: "start", behavior: "smooth"});
        else { const tl = $(".hd-tl"); if (tl) { tl.scrollIntoView({block: "start"}); focusRow(tl, ep.start); } }
        return;
      }
      if (t.id === "hd-go") { analyze(st.sel); return; }
      if (t.id === "hd-winx") { st.win = null; st.focus = null; render(); return; }
      if (t.id === "hd-more") { st.limit += 3000; render(); return; }
      if (t.id === "hd-fwd") { const a = document.querySelector('.vnav a[data-nav="fwd"]'); if (a) a.click(); return; }
      if (t.id === "hd-ai") { t.disabled = true; $("#hd-aib").innerHTML = `<p class="muted">AI 가 분석 중…</p>`;
        try { st.ai = await A.api("POST", "/api/hostdiag/ai", {name: st.sel}); } catch (x) { A.fail("AI 설명 실패", x); } render(); }
    });
    box.addEventListener("change", async e => {
      const t = e.target;
      if (t.id === "hd-days") { st.days = +t.value; await loadHosts(); render(); }
      if (t.id === "hd-hours") { if (t.value === "c") { st.custom = true; const now = new Date(); const iso = d => new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
          st.to = iso(now); st.from = iso(new Date(now - 24 * 3600e3)); } else { st.custom = false; st.from = st.to = ""; st.hours = +t.value; } render(); }
      if (t.id === "hd-from") st.from = t.value; if (t.id === "hd-to") st.to = t.value;
      if (t.id === "hd-live") st.live = t.checked;
      if (t.dataset.hdsrc) { const all = Object.keys(SRC); if (!st.src.size) all.forEach(k => st.src.add(k)); t.checked ? st.src.add(t.dataset.hdsrc) : st.src.delete(t.dataset.hdsrc); if (st.src.size === all.length) st.src.clear(); render(); }
      if (t.id === "hd-sev") { st.sev = t.value; render(); }
    });
    box.addEventListener("input", e => { if (e.target.id === "hd-tf") { st.tf = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 250); }
      if (e.target.id === "hd-hf") { st.hf = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 200); } });
  }
  async function show(name) {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-hd") d.hidden = true; });
    $("#drawer-hd").hidden = false; wire(); await loadHosts(); render();
    if (typeof name === "string" && name) analyze(name);
  }
  const nav = document.getElementById("nav-hd"); if (nav) nav.onclick = () => show();
  const rl = document.getElementById("hd-reload"); if (rl) rl.onclick = async () => { await loadHosts(); if (st.sel) analyze(st.sel); else render(); };
  window.AIOPS_HOSTDIAG = show;
  { const q = new URLSearchParams(location.search); if (q.get("view") === "hd" && q.get("host")) setTimeout(() => show(q.get("host")), 1200); }
})();
