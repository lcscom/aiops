/* 관제 월 페이지 탭 · 자동 순환 — /noc(종합) · /noc/infra · /noc/events · /noc/security · /noc/ai
   + 도메인 상세 탭 줄 /noc/d/<슬롯>(vCenter·NSX·NSX ALB·VKS·물리 서버·VM 게스트·보안) — 상태 점 20초 갱신
   순환: 탭 줄의 '순환' 버튼 또는 URL ?rotate=초[&pages=infra,events]. 조작(마우스·키) 시 60초 일시정지. [ / ] 키로 이전·다음 페이지 */
(() => {
  "use strict";
  const PAGES = [["overview", "/noc", "종합 상황"], ["infra", "/noc/infra", "인프라 지도"], ["topology", "/noc/topology", "물리·논리 토폴로지"], ["events", "/noc/events", "이벤트·인시던트"],
                 ["security", "/noc/security", "보안"], ["ai", "/noc/ai", "AI·플랫폼"], ["network", "/noc/network", "네트워크 구성도"], ["exec", "/noc/exec", "경영진 요약"]];
  const WALL = new Set(["infra", "topology", "events", "security", "ai", "network", "exec"]);
  const DEF_DOM = [["vc", "vCenter"], ["vsan", "vSAN"], ["nsx", "NSX"], ["avi", "NSX ALB"], ["vks", "VKS"], ["srv", "물리 서버"], ["vmg", "VM 게스트"], ["sec", "보안(방화벽)"], ["net", "네트워크"]];
  const isWall = id => WALL.has(id) || String(id).startsWith("d-");
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
  const store = (k, v) => { try { if (v === undefined) return JSON.parse(localStorage.getItem(k) || "null"); localStorage.setItem(k, JSON.stringify(v)); } catch { return null; } return null; };
  const pageOf = () => { const p = location.pathname.replace(/\/+$/, ""); if (p === "/noc") return "overview"; const a = p.split("/"); return a[2] === "d" && a[3] ? "d-" + a[3] : (a[2] || "overview"); };
  let cur = pageOf();
  let DOM = store("noc.dom") || DEF_DOM.map(([id, name]) => ({id, name, state: ""}));
  const syncDom = () => { PAGES.splice(0, PAGES.length, ...PAGES.filter(p => !p[0].startsWith("d-")), ...DOM.map(d => ["d-" + d.id, "/noc/d/" + encodeURIComponent(d.id), d.name])); };
  syncDom();
  const qs = new URLSearchParams(location.search);
  let rot = store("noc.rot") || {on: false, sec: 60, pages: PAGES.map(p => p[0])};
  if (qs.has("rotate")) { const s = Number(qs.get("rotate")); rot.on = s > 0; if (s > 0) rot.sec = Math.max(10, s); }
  if (qs.get("pages")) rot.pages = qs.get("pages").split(",").filter(x => PAGES.some(p => p[0] === x));
  if (!rot.pages || !rot.pages.length) rot.pages = PAGES.filter(p => !p[0].startsWith("d-")).map(p => p[0]);
  let started = Date.now(), pausedUntil = 0;

  function render() {
    const nav = $("#n-pages"); if (!nav) return;
    const tab = ([id, href, label]) => `<a href="${href}" data-page="${id}" class="${id === cur ? "on" : ""}${rot.on && !rot.pages.includes(id) ? " skip" : ""}" title="${esc(label)}">${esc(label)}</a>`;
    nav.innerHTML = `<div class="np-tabs">${PAGES.filter(p => !p[0].startsWith("d-")).map(tab).join("")}</div>
      <div class="np-rot"><button type="button" id="np-rot" aria-pressed="${rot.on}" title="페이지 자동 순환(조작 시 60초 일시정지) — [ ] 키로 이동">${rot.on ? "순환 중" : "자동 순환"}</button>
        <select id="np-sec" aria-label="순환 간격">${[20, 30, 45, 60, 90, 120, 300].map(s => `<option value="${s}" ${rot.sec === s ? "selected" : ""}>${s < 60 ? s + "초" : s / 60 + "분"}</option>`).join("")}</select>
        <button type="button" id="np-pick" title="순환에 넣을 페이지 고르기">페이지</button><span id="np-state"></span>
        <button type="button" id="np-search" class="np-sbtn" title="전역 검색 (Ctrl+K 또는 /)">검색 <kbd>Ctrl K</kbd></button><button type="button" id="np-help" title="단축키 (?)">?</button></div>
      <i class="np-bar" id="np-bar"></i>`;
    let sub = $("#n-dom");
    if (!sub) { sub = document.createElement("nav"); sub.id = "n-dom"; sub.className = "ndom"; sub.setAttribute("aria-label", "도메인 상세"); nav.after(sub); }
    sub.innerHTML = `<span class="nd-l">도메인 상세</span>${DOM.map(d => `<a href="/noc/d/${encodeURIComponent(d.id)}" data-page="d-${esc(d.id)}" class="${"d-" + d.id === cur ? "on" : ""}${rot.on && !rot.pages.includes("d-" + d.id) ? " skip" : ""}" title="${esc(d.scope || d.name)}${d.why ? " — " + esc(d.why) : ""}"><i class="nd-dot ${esc(d.state || "")}"></i>${esc(d.name)}${d.n ? `<b>${d.n}</b>` : ""}</a>`).join("")}`;
  }
  async function loadDom() {
    try {
      const r = await fetch("/api/noc/slots?state=1", {headers: {"X-Requested-With": "aiops"}});
      if (!r.ok) return;
      const list = await r.json(); if (!Array.isArray(list) || !list.length) return;
      DOM = list; store("noc.dom", DOM.map(({id, name, scope}) => ({id, name, scope, state: ""}))); syncDom(); render();
    } catch { /* 다음 주기 */ }
  }
  function href(id) {
    const p = PAGES.find(x => x[0] === id); const q = new URLSearchParams(location.search); q.delete("rotate"); q.delete("pages");
    const s = q.toString(); return p[1] + (s ? "?" + s : "");
  }
  function go(id) {
    if (id === cur) return;
    if (isWall(id) && isWall(cur) && window.NOCWALL) {      // 같은 문서 안에서 전환(새로고침 없음, 실시간 연결 유지)
      history.pushState({page: id}, "", href(id)); cur = id; window.NOCWALL.show(id); render(); started = Date.now(); return;
    }
    location.href = href(id);
  }
  function next(step = 1) {
    const list = rot.on ? PAGES.filter(p => rot.pages.includes(p[0])) : PAGES;
    let i = list.findIndex(p => p[0] === cur); if (i < 0) i = -1;
    go(list[(i + step + list.length) % list.length][0]);
  }
  function tick() {
    const bar = $("#np-bar"), stl = $("#np-state");
    if (!rot.on) { if (bar) bar.style.width = "0"; if (stl) stl.textContent = ""; return; }
    const now = Date.now();
    if (now < pausedUntil) { if (stl) stl.textContent = `일시정지 ${Math.ceil((pausedUntil - now) / 1000)}초`; started += 250; return; }
    const p = Math.min(1, (now - started) / (rot.sec * 1000));
    if (bar) bar.style.width = `${(p * 100).toFixed(2)}%`;
    if (stl) stl.textContent = `${Math.ceil(rot.sec - (now - started) / 1000)}초 뒤 다음`;
    if (p >= 1) { started = now; next(1); }
  }
  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#n-pages")) return;
    render();
    const nav = $("#n-pages");
    loadDom(); setInterval(loadDom, 20000);
    document.addEventListener("click", e => {
      const a = e.target.closest("#n-dom [data-page]"); if (!a || e.ctrlKey || e.metaKey || e.shiftKey) return;
      e.preventDefault(); go(a.dataset.page);
    });
    nav.addEventListener("click", async e => {
      const a = e.target.closest("[data-page]");
      if (a) { e.preventDefault(); go(a.dataset.page); return; }
      if (e.target.closest("#np-search")) { openPal(); return; }
      if (e.target.id === "np-help") { help(); return; }
      if (e.target.id === "np-rot") { rot.on = !rot.on; started = Date.now(); pausedUntil = 0; store("noc.rot", rot); render(); return; }
      if (e.target.id === "np-pick" && window.AIOPS) {
        const v = await window.AIOPS.modal({title: "순환할 페이지", ok: "적용", html: `<div class="lay-list">${PAGES.map(([id, , l]) => `<label><input type="checkbox" data-rp="${id}" ${rot.pages.includes(id) ? "checked" : ""}> ${esc(l)}</label>`).join("")}</div>
          <p class="modal-text">월 디스플레이 고정 주소: <code>${esc(location.origin)}/noc?rotate=${rot.sec}&pages=${esc(rot.pages.join(","))}</code></p>`, onOpen: m => { rot._m = m; }});
        if (v === null) return;
        const sel = [...rot._m.querySelectorAll("[data-rp]")].filter(x => x.checked).map(x => x.dataset.rp);
        rot.pages = sel.length ? sel : PAGES.map(p => p[0]); delete rot._m; store("noc.rot", rot); render();
      }
    });
    nav.addEventListener("change", e => { if (e.target.id === "np-sec") { rot.sec = Number(e.target.value); started = Date.now(); store("noc.rot", rot); } });
    const pause = () => { if (rot.on) pausedUntil = Date.now() + 60000; };
    ["pointerdown", "wheel"].forEach(ev => document.addEventListener(ev, pause, {passive: true}));
    document.addEventListener("keydown", e => {
      if (e.target.closest && e.target.closest("input,textarea,select")) return;
      if (e.key === "]") { next(1); } else if (e.key === "[") { next(-1); } else pause();
    });
    addEventListener("popstate", () => { const p = pageOf(); if (p !== cur && isWall(p) && window.NOCWALL) { cur = p; window.NOCWALL.show(p); render(); } });
    setInterval(tick, 250);
  });
  // ---------------------------------------------------------------- 전역 검색(Ctrl+K · /) · 단축키 도움말(?)
  const PAL = {el: null, items: [], i: 0, t: null, seq: 0};
  function openPal() {
    if (PAL.el) { PAL.el.querySelector("input").focus(); return; }
    const el = document.createElement("div"); el.className = "npal"; el.setAttribute("role", "dialog"); el.setAttribute("aria-label", "관제 검색");
    el.innerHTML = `<div class="npal-box"><input type="search" placeholder="호스트·VM·Edge·SE·가상 서비스·블레이드·페이지 검색" aria-label="검색어" autocomplete="off">
      <ol class="npal-list" role="listbox"></ol><div class="npal-ft"><span><kbd>↑</kbd><kbd>↓</kbd> 이동</span><span><kbd>Enter</kbd> 열기</span><span><kbd>Esc</kbd> 닫기</span><span><kbd>?</kbd> 단축키</span></div></div>`;
    document.body.appendChild(el); PAL.el = el; PAL.items = []; PAL.i = 0;
    const inp = el.querySelector("input"); inp.focus();
    el.addEventListener("click", e => { if (e.target === el) closePal(); const li = e.target.closest("[data-i]"); if (li) pickPal(Number(li.dataset.i)); });
    inp.addEventListener("input", () => { clearTimeout(PAL.t); PAL.t = setTimeout(() => searchPal(inp.value), 140); });
    inp.addEventListener("keydown", e => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); PAL.i = Math.max(0, Math.min(PAL.items.length - 1, PAL.i + (e.key === "ArrowDown" ? 1 : -1))); drawPal(); }
      else if (e.key === "Enter") { e.preventDefault(); pickPal(PAL.i); }
      else if (e.key === "Escape") { e.preventDefault(); closePal(); }
    });
    searchPal("");
  }
  function closePal() { if (PAL.el) PAL.el.remove(); PAL.el = null; }
  const ST_KO = {down: "장애", warn: "주의", ok: "정상", idle: "대기", maint: "유지보수"};
  async function searchPal(q) {
    const seq = ++PAL.seq, ql = q.trim().toLowerCase();
    const pages = PAGES.filter(p => !ql || p[2].toLowerCase().includes(ql) || p[0].includes(ql)).map(p => ({kind: "page", name: p[2], page: p[0], sub: p[0].startsWith("d-") ? "도메인 상세" : "관제 페이지"}));
    let ents = [];
    if (ql.length >= 2) { try { const r = await fetch(`/api/noc/search?q=${encodeURIComponent(ql)}`, {headers: {"X-Requested-With": "aiops"}}); if (r.ok) ents = await r.json(); } catch { /* 무시 */ } }
    if (seq !== PAL.seq || !PAL.el) return;
    PAL.items = [...ents.map(e => ({kind: "ent", ...e})), ...pages].slice(0, 40); PAL.i = 0; drawPal(ql);
  }
  function drawPal(ql = "") {
    const ol = PAL.el && PAL.el.querySelector(".npal-list"); if (!ol) return;
    const hl = t => { const s = esc(t); if (!ql) return s; const i = String(t).toLowerCase().indexOf(ql); return i < 0 ? s : esc(String(t).slice(0, i)) + "<mark>" + esc(String(t).slice(i, i + ql.length)) + "</mark>" + esc(String(t).slice(i + ql.length)); };
    ol.innerHTML = PAL.items.map((x, i) => x.kind === "page"
      ? `<li data-i="${i}" class="${i === PAL.i ? "on" : ""}" role="option"><i class="pg">↗</i><b>${hl(x.name)}</b><small>${esc(x.sub)}</small></li>`
      : `<li data-i="${i}" class="${i === PAL.i ? "on" : ""}" role="option"><i class="st ${esc(x.state)}" title="${esc(ST_KO[x.state] || x.state)}"></i><b>${hl(x.name)}</b><small>${esc(x.kind)} · ${esc(x.domain)}${x.detail ? " · " + esc(String(x.detail).slice(0, 80)) : ""}</small></li>`).join("")
      || `<li class="none">${PAL.el.querySelector("input").value.trim().length < 2 ? "두 글자 이상 입력하세요" : "결과 없음"}</li>`;
    const on = ol.querySelector(".on"); if (on) (window.AIOPS.reveal || (() => {}))(on, {smooth: false});
  }
  function pickPal(i) {
    const x = PAL.items[i]; if (!x) return; closePal();
    if (x.kind === "page") { go(x.page); return; }
    const id = "d-" + x.sid;
    if (isWall(cur) && window.NOCWALL && window.NOCDOM) { if (cur !== id) go(id); window.NOCDOM.focus(x.name, true); return; }
    location.href = `/noc/d/${encodeURIComponent(x.sid)}?host=${encodeURIComponent(x.name)}&open=1`;
  }
  function help() {
    if (!window.AIOPS) return;
    window.AIOPS.modal({title: "관제 단축키", ok: "", cancel: "닫기", html: `<table class="npal-help">
      ${[["Ctrl+K 또는 /", "전역 검색(호스트·VM·Edge·SE·VS·블레이드·페이지)"], ["[ / ]", "이전·다음 페이지"], ["Alt+1 … Alt+9", "도메인 상세 탭 바로 가기"],
         ["P", "도메인 상세: 실시간 스트림 일시정지·재개"], ["Esc", "개체 상세·검색 닫기"], ["1 … 9", "종합 상황: 슬롯 확대"], ["?", "이 도움말"]]
        .map(([k, v]) => `<tr><td><kbd>${esc(k)}</kbd></td><td>${esc(v)}</td></tr>`).join("")}</table>`});
  }
  document.addEventListener("keydown", e => {
    const typing = e.target.closest && e.target.closest("input,textarea,select");
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); openPal(); return; }
    if (typing || document.querySelector(".modal")) return;
    if (e.key === "/" && !PAL.el) { e.preventDefault(); openPal(); return; }
    if (e.key === "?") { e.preventDefault(); help(); return; }
    if (e.altKey && /^[1-9]$/.test(e.key)) { const d = DOM[Number(e.key) - 1]; if (d) { e.preventDefault(); go("d-" + d.id); } }
  });
  window.NOCNAV = {current: () => cur, go, next, pages: PAGES, search: openPal, help};
})();
