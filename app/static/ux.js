/* 사용성(2.20.0) — 전역 검색·명령(Ctrl+K · /) · 즐겨찾기 · 최근 화면 · 메뉴 접기 · 탭 단축키([ ]) · 단축키 도움말(?) · API 진행 막대 · 접근성
   navgroup.js 뒤, layout.js 앞에 로드 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const A = window.AIOPS || {};
  const esc = A.esc || (s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]));
  const POP = new URLSearchParams(location.search).has("view");
  const store = {
    get(k, d) { try { const v = JSON.parse(localStorage.getItem(k)); return v ?? d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* 사생활 보호 모드 */ } },
  };
  const NG = () => window.AIOPS_NAVGROUPS || {GROUPS: []};
  const navA = n => $(`.vnav a[data-nav="${n}"]`);
  const navLabel = n => { const a = navA(n); return a ? (a.querySelector("span")?.textContent || n).trim() : n; };
  const allowed = n => { const a = navA(n); return !!a && !a.hidden; };
  const groupOf = n => NG().GROUPS.find(g => g.members.some(x => !x.ext && x.a.dataset.nav === n));
  const openNav = n => { const a = navA(n); if (a) a.click(); };
  const openDrawer = () => { const d = $$(".drawer").find(x => !x.hidden && x.id !== "drawer-chat"); return d ? d.id.replace("drawer-", "") : ""; };

  // ------------------------------------------------------------ 최근 화면 · 즐겨찾기
  let recent = store.get("aiops.recent", []), favs = store.get("aiops.favs", []);
  function touch(n) {
    if (!n || n === "chat") return;
    recent = [n, ...recent.filter(x => x !== n)].slice(0, 8); store.set("aiops.recent", recent);
  }
  function renderFavs() {
    const nav = $(".vnav"); if (!nav) return;
    let sec = $(".vnav-fav", nav);
    const list = favs.filter(allowed);
    if (!list.length) { if (sec) sec.remove(); return; }
    if (!sec) { sec = document.createElement("div"); sec.className = "vnav-fav"; nav.prepend(sec); }
    const html = `<div class="vnav-h">즐겨찾기</div>` + list.map(n => {
      const a = navA(n), svg = a.querySelector("svg");
      return `<a href="#" data-fav="${esc(n)}" title="${esc(navLabel(n))}">${svg ? svg.outerHTML : ""}<span>${esc(navLabel(n))}</span></a>`;
    }).join("");
    if (sec.dataset.h !== html) { sec.innerHTML = html; sec.dataset.h = html; }
    const cur = openDrawer();
    $$("a[data-fav]", sec).forEach(a => a.classList.toggle("on", a.dataset.fav === cur));
  }
  function toggleFav(n) {
    if (!n) return;
    favs = favs.filter(allowed);                              // 권한 없는 화면은 개수에서 제외
    if (!favs.includes(n) && favs.length >= 12) { A.toast && A.toast("즐겨찾기는 12개까지입니다", "다른 즐겨찾기를 먼저 빼세요", "warn", 4000); return; }
    const added = !favs.includes(n);
    favs = added ? [...favs, n] : favs.filter(x => x !== n);
    store.set("aiops.favs", favs); renderFavs(); decorate();
    A.toast && A.toast(added ? "즐겨찾기에 추가함" : "즐겨찾기에서 뺌", navLabel(n), "info", 2500);
  }
  function decorate() {                       // 화면 머리글의 ☆ 버튼
    $$(".drawer.page").forEach(d => {
      const n = d.id.replace("drawer-", ""); if (!navA(n)) return;
      const head = d.querySelector(".drawer-head"); if (!head) return;
      let b = head.querySelector(".fav-btn");
      if (!b) {
        b = document.createElement("button"); b.type = "button"; b.className = "fav-btn"; b.dataset.favToggle = n;
        const h3 = head.querySelector("h3"); if (h3) h3.prepend(b); else head.prepend(b);
      }
      const on = favs.includes(n);
      b.textContent = on ? "★" : "☆"; b.classList.toggle("on", on);
      b.title = on ? "즐겨찾기에서 빼기" : "즐겨찾기에 추가(왼쪽 메뉴 맨 위)"; b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  // ------------------------------------------------------------ 메뉴 접기
  const setMini = on => { document.documentElement.classList.toggle("nav-mini", on); store.set("aiops.navmini", on); dispatchEvent(new Event("resize")); };
  function navFoot() {
    const nav = $(".vnav"); if (!nav || $(".vnav-foot", nav)) return;
    nav.insertAdjacentHTML("beforeend", `<div class="vnav-foot"><button type="button" class="vnav-mini" title="메뉴 접기·펼치기 (\\)" aria-label="메뉴 접기·펼치기"><span class="ic">«</span><span>메뉴 접기</span></button>
      <button type="button" class="vnav-k" title="검색·명령 (Ctrl+K)"><kbd>Ctrl</kbd><kbd>K</kbd><span>검색·명령</span></button></div>`);
  }

  // ------------------------------------------------------------ 탭 이동([ · ])
  function stepTab(dir) {
    if (POP) return;                                           // 새 창은 그 화면 하나만
    const n = openDrawer() || "dash", g = groupOf(n); if (!g) return;
    const ms = g.members.filter(x => !x.ext && !x.a.hidden).map(x => x.a.dataset.nav);
    const i = ms.indexOf(n); if (i < 0 || ms.length < 2) return;
    openNav(ms[(i + dir + ms.length) % ms.length]);
  }

  // ------------------------------------------------------------ 검색·명령 팔레트
  const P = {el: null, items: [], i: 0, t: null, seq: 0};
  function commands() {
    const out = [];
    for (const g of NG().GROUPS) {
      for (const x of g.members) {
        if (x.a.hidden) continue;
        const name = (x.a.querySelector("span")?.textContent || "").trim();
        if (x.ext) out.push({k: "menu", name: `${name} ↗`, sub: `${g.name} · 새 창`, kw: g.name, run: () => x.a.click()});
        else out.push({k: "menu", nav: x.a.dataset.nav, name, sub: g.members.length > 1 ? g.name : "메뉴", kw: `${g.name} ${x.a.title || ""}`, run: () => openNav(x.a.dataset.nav)});
      }
    }
    if (window.AIOPS_OPEN_SETTINGS && allowed("set")) {
      $$("#set-tabs [data-t]").forEach(b => out.push({k: "set", name: `운영 설정 › ${b.textContent.trim()}`, sub: "설정", kw: "설정 settings", run: () => window.AIOPS_OPEN_SETTINGS(b.dataset.t)}));
    }
    const cur = openDrawer();
    if (cur) {
      out.push({k: "act", name: `${favs.includes(cur) ? "즐겨찾기에서 빼기" : "즐겨찾기에 추가"}: ${navLabel(cur)}`, sub: "명령", kw: "favorite 즐겨찾기 별", run: () => toggleFav(cur)});
      if (window.AIOPS_POPOUT) out.push({k: "act", name: `새 창에서 열기: ${navLabel(cur)}`, sub: "명령", kw: "popout window 새창", run: () => window.AIOPS_POPOUT(cur)});
    }
    if (innerWidth > 900) out.push({k: "act", name: document.documentElement.classList.contains("nav-mini") ? "메뉴 펼치기" : "메뉴 접기", sub: "명령 · \\", kw: "nav menu collapse 메뉴", run: () => setMini(!document.documentElement.classList.contains("nav-mini"))});
    const lang = (window.AIOPS_I18N || {}).lang;
    if (window.AIOPS_I18N) out.push({k: "act", name: lang === "en" ? "한국어로 보기" : "English", sub: "명령 · 언어", kw: "language 언어 english korean", run: () => window.AIOPS_I18N.set(lang === "en" ? "ko" : "en")});
    out.push({k: "act", name: "단축키 보기", sub: "명령 · ?", kw: "shortcut help 단축키 도움말", run: help});
    return out;
  }
  const T = s => { try { return (window.AIOPS_I18N && window.AIOPS_I18N.t) ? window.AIOPS_I18N.t(String(s)) : String(s); } catch { return String(s); } };
  const match = (x, toks) => { const raw = `${x.name} ${x.sub || ""} ${x.kw || ""}`; const h = `${raw} ${T(raw)}`.toLowerCase(); return toks.every(t => h.includes(t)); };
  function openPal(seed = "") {
    if (P.el) { P.el.querySelector("input").focus(); return; }
    const el = document.createElement("div");
    el.className = "cpal"; el.setAttribute("role", "dialog"); el.setAttribute("aria-modal", "true"); el.setAttribute("aria-label", "검색·명령");
    el.innerHTML = `<div class="cpal-box"><div class="cpal-in"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="m15.5 15.5 5 5" stroke="currentColor" stroke-width="2"/></svg>
      <input type="search" placeholder="메뉴·설정·명령, 호스트·VM 이름, 인시던트 번호" aria-label="검색어" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="cpal-list"></div>
      <ol class="cpal-list" id="cpal-list" role="listbox"></ol>
      <div class="cpal-ft"><span><kbd>↑</kbd><kbd>↓</kbd> 이동</span><span><kbd>Enter</kbd> 열기</span><span><kbd>Shift</kbd>+<kbd>Enter</kbd> 메뉴를 새 창에서</span><span><kbd>Esc</kbd> 닫기</span></div></div>`;
    document.body.append(el); P.el = el; P.items = []; P.i = 0;
    const inp = el.querySelector("input"); inp.value = seed; inp.focus();
    el.addEventListener("mousedown", e => { if (e.target === el) { closePal(); return; } if (!e.target.closest("input")) e.preventDefault(); });   // 상자 안을 눌러도 입력창 포커스 유지
    el.addEventListener("click", e => { const li = e.target.closest("[data-i]"); if (li) pick(Number(li.dataset.i), e.shiftKey); });
    inp.addEventListener("input", () => { clearTimeout(P.t); search(inp.value, true); P.t = setTimeout(() => search(inp.value, false), 180); });
    inp.addEventListener("keydown", e => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); P.i = Math.max(0, Math.min(P.items.length - 1, P.i + (e.key === "ArrowDown" ? 1 : -1))); draw(); }
      else if (e.key === "Enter") { e.preventDefault(); pick(P.i, e.shiftKey); }
      else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closePal(); }
      else if (e.key === "Tab") { e.preventDefault(); }
    });
    search(seed, true);
  }
  function closePal() { if (P.el) P.el.remove(); P.el = null; }
  async function search(q, local) {
    const seq = ++P.seq, ql = q.trim().toLowerCase(), toks = ql.split(/\s+/).filter(Boolean);
    const cmds = commands();
    let items;
    if (!toks.length) {
      const rec = recent.filter(allowed).map(n => cmds.find(c => c.nav === n)).filter(Boolean).map(c => ({...c, sub: `최근 · ${c.sub}`}));
      items = [...rec, ...cmds.filter(c => c.k === "act")];
    } else {
      items = cmds.filter(c => match(c, toks)).sort((a, b) => (T(a.name).toLowerCase().startsWith(toks[0]) || a.name.toLowerCase().startsWith(toks[0]) ? 0 : 1) - (T(b.name).toLowerCase().startsWith(toks[0]) || b.name.toLowerCase().startsWith(toks[0]) ? 0 : 1));
    }
    if (!local && ql.length >= 2) {
      const ext = [], incRows = [];
      const get = async u => { try { const r = await fetch(u, {headers: {"X-Requested-With": "aiops"}}); return r.ok ? await r.json() : null; } catch { return null; } };
      const [ents, incs] = await Promise.all([get(`/api/noc/search?q=${encodeURIComponent(ql)}`),
        allowed("inc") ? get(`/api/incidents?q=${encodeURIComponent(q.trim())}&days=90&limit=5`) : null]);
      for (const x of (Array.isArray(incs) ? incs : (incs && incs.items) || []).slice(0, 5)) {
        const ST = {open: "신규", acknowledged: "접수", investigating: "조사 중", resolved: "해결", closed: "종료"};
        incRows.push({k: "inc", name: `${x.id} ${x.title || ""}`.trim(), sub: `인시던트 · ${ST[x.status] || x.status || ""} · ${String(x.severity || "").toUpperCase()}`, run: () => window.AIOPS_OPEN_INCIDENT && window.AIOPS_OPEN_INCIDENT(x.id)});
      }
      for (const e of (Array.isArray(ents) ? ents : []).slice(0, 12)) {
        const kind = /esxi|host/i.test(e.kind || "") ? "host" : e.kind;
        ext.push({k: "ent", st: e.state, name: e.name, sub: `${e.kind} · ${e.domain}${e.detail ? " · " + String(e.detail).slice(0, 70) : ""}`, run: () => {
          const h = `#inv/${encodeURIComponent(kind)}/${encodeURIComponent(e.name)}`;
          if (location.hash === h) dispatchEvent(new HashChangeEvent("hashchange")); else location.hash = h;      // 같은 개체 다시 고를 때도 열림
        }});
        if ((kind === "host") && window.AIOPS_HOSTDIAG && allowed("hd")) ext.push({k: "ent2", name: `호스트 분석: ${e.name}`, sub: "연결 끊김 원인 · vCenter 이벤트·작업·syslog", run: () => window.AIOPS_HOSTDIAG(e.name)});
        if (kind === "vm" && window.AIOPS_VM_TIMELINE && allowed("mv")) ext.push({k: "ent2", name: `VM 일대기: ${e.name}`, sub: "생성·이동·전원·스냅샷 이력", run: () => window.AIOPS_VM_TIMELINE(e.name)});
        if ((kind === "vm" || kind === "host") && window.AIOPS_PERF && allowed("pf")) ext.push({k: "ent2", name: `${kind === "vm" ? "VM" : "호스트"} 성능: ${e.name}`, sub: "CPU·메모리·디스크 I/O·네트워크 상세 · 24시간·7일·30일", run: () => window.AIOPS_PERF(kind, e.name)});
        if (kind === "vm" && window.AIOPS_VM_TRAFFIC && allowed("st")) ext.push({k: "ent2", name: `VM 네트워크 트래픽: ${e.name}`, sub: "vNIC 별 수신·송신·드롭 · 과거 사용량", run: () => window.AIOPS_VM_TRAFFIC(e.name)});
      }
      if (seq !== P.seq || !P.el) return;
      const exact = ext.filter(x => x.k === "ent" && x.name.toLowerCase() === ql);
      items = [...(exact.length ? ext : []), ...items.slice(0, 8), ...(exact.length ? [] : ext), ...incRows, ...items.slice(8)];
    }
    if (seq !== P.seq || !P.el) return;
    const prev = !local && P.items[P.i] && P.i > 0 ? P.items[P.i] : null;      // 원격 결과가 와도 고른 줄 유지
    P.items = items.slice(0, 40);
    const keep = prev ? P.items.findIndex(x => x.k === prev.k && x.name === prev.name) : -1;
    P.i = keep >= 0 ? keep : 0; P.loading = local && ql.length >= 2; draw(ql);
  }
  function draw(ql = "") {
    const ol = P.el && P.el.querySelector(".cpal-list"); if (!ol) return;
    const hl = t => { const s = String(t); const i = ql ? s.toLowerCase().indexOf(ql.split(/\s+/)[0]) : -1; if (i < 0) return esc(s); const L = ql.split(/\s+/)[0].length; return esc(s.slice(0, i)) + "<mark>" + esc(s.slice(i, i + L)) + "</mark>" + esc(s.slice(i + L)); };
    const ic = {menu: "▤", set: "⚙", act: "›", inc: "!", ent: "●", ent2: "↳"};
    ol.innerHTML = P.items.map((x, i) => `<li data-i="${i}" id="cpal-o${i}" class="${i === P.i ? "on" : ""} k-${x.k}" role="option" aria-selected="${i === P.i}">
        <i class="${x.k === "ent" ? "st " + esc(x.st || "") : ""}">${x.k === "ent" ? "" : ic[x.k] || ""}</i><b>${hl(x.k === "ent" || x.k === "inc" ? x.name : T(x.name))}</b><small>${esc(T(x.sub || ""))}</small></li>`).join("")
      + (P.loading ? `<li class="none">호스트·VM·인시던트 찾는 중…</li>` : "")
      || `<li class="none">${ql.length >= 2 ? "결과 없음" : "메뉴 이름이나 호스트·VM 이름을 입력하세요"}</li>`;
    const inp = P.el.querySelector("input"); inp.setAttribute("aria-activedescendant", P.items.length ? `cpal-o${P.i}` : "");
    const on = ol.querySelector(".on"); if (on) on.scrollIntoView({block: "nearest"});
  }
  function pick(i, newWin) {
    const x = P.items[i]; if (!x) return; closePal();
    if (newWin && x.nav && window.AIOPS_POPOUT) { window.AIOPS_POPOUT(x.nav); return; }
    try { x.run(); } catch (e) { A.fail && A.fail("열지 못했습니다", e); }
  }

  // ------------------------------------------------------------ 단축키 도움말
  function help() {
    const rows = [["Ctrl+K · /", "검색·명령 — 메뉴·설정·명령·호스트·VM·인시던트"], ["[ · ]", "같은 묶음의 이전·다음 탭"], ["\\", "메뉴 접기·펼치기"],
      ["Esc", "화면·창 닫기"], ["Ctrl+클릭 · 가운데 클릭", "메뉴·탭을 새 창으로"], ["☆", "화면 제목 앞 — 즐겨찾기(왼쪽 메뉴 맨 위)"], ["?", "이 도움말"]];
    const html = `<table class="kbd-help">${rows.map(([k, v]) => `<tr><td>${k.split(" · ").map(x => `<kbd>${esc(x)}</kbd>`).join(" ")}</td><td>${esc(v)}</td></tr>`).join("")}</table>`;
    if (A.modal) A.modal({title: "단축키", html, ok: "", cancel: "닫기"});
  }

  // ------------------------------------------------------------ API 진행 막대(0.3초 넘는 요청만)
  function progress() {
    const bar = document.createElement("div"); bar.className = "api-prog"; bar.setAttribute("aria-hidden", "true"); document.body.append(bar);
    let n = 0, t = null;
    const upd = () => { clearTimeout(t); if (n > 0) t = setTimeout(() => bar.classList.add("on"), 300); else bar.classList.remove("on"); };
    const orig = window.fetch.bind(window);
    window.fetch = (u, o) => {
      const url = typeof u === "string" ? u : (u && u.url) || "";
      if (!/\/api\//.test(url) || /\/api\/(chat|stream|events|tail)/.test(url)) return orig(u, o);
      n++; upd();
      const done = () => { n = Math.max(0, n - 1); upd(); };
      const timer = setTimeout(done, 60000);               // 응답 머리글이 안 와도 1분 뒤 막대 해제
      return orig(u, o).then(r => { clearTimeout(timer); done(); return r; }, e => { clearTimeout(timer); done(); throw e; });
    };
  }

  // ------------------------------------------------------------ 접근성
  const FOCUS = {tab: "", until: 0};
  function refocus() {
    if (!FOCUS.tab || Date.now() > FOCUS.until) { FOCUS.tab = ""; return; }
    const ae = document.activeElement;
    if (ae && ae !== document.body && ae.dataset && ae.dataset.tab === FOCUS.tab && ae.offsetParent) return;
    if (ae && ae !== document.body && !(ae.closest && ae.closest(".grp-tabs"))) { FOCUS.tab = ""; return; }   // 사용자가 다른 곳으로 옮김
    const n = $$(`.grp-tabs [data-tab="${FOCUS.tab}"].on`).find(x => x.offsetParent);
    if (n) n.focus();
  }
  function a11y() {
    refocus();
    $$(".grp-tabs .grp-tl").forEach(t => {
      if (t.getAttribute("role") !== "tablist") { t.setAttribute("role", "tablist"); t.setAttribute("aria-label", t.previousElementSibling?.textContent || "탭"); }
      $$("button", t).forEach(b => {
        if (b.getAttribute("role") !== "tab") b.setAttribute("role", "tab");
        const sel = b.classList.contains("on") ? "true" : "false";
        if (b.getAttribute("aria-selected") !== sel) b.setAttribute("aria-selected", sel);
        const ti = sel === "true" ? "0" : "-1";
        if (b.getAttribute("tabindex") !== ti) b.setAttribute("tabindex", ti);
        if (b.dataset.tab && b.getAttribute("aria-controls") !== `drawer-${b.dataset.tab}`) b.setAttribute("aria-controls", `drawer-${b.dataset.tab}`);
      });
    });
    $$(".vnav > a, .vnav-fav > a").forEach(a => {
      if (!a.hasAttribute("href") && a.getAttribute("tabindex") !== "0") { a.setAttribute("tabindex", "0"); a.setAttribute("role", "link"); }
      const nm = (a.querySelector("span")?.textContent || "").trim();
      if (nm && a.getAttribute("aria-label") !== nm) a.setAttribute("aria-label", nm);          // 접힌 메뉴에서도 이름 읽힘
      if (nm && !a.title) a.title = nm;
      const on = a.classList.contains("on");
      if (on && a.getAttribute("aria-current") !== "page") a.setAttribute("aria-current", "page");
      else if (!on && a.hasAttribute("aria-current")) a.removeAttribute("aria-current");
    });
  }

  // ------------------------------------------------------------ 이벤트
  document.addEventListener("click", e => {
    const f = e.target.closest("[data-fav]");
    if (f && f.closest(".vnav")) { e.preventDefault(); if (e.ctrlKey || e.metaKey || e.shiftKey) { window.AIOPS_POPOUT && window.AIOPS_POPOUT(f.dataset.fav); } else openNav(f.dataset.fav); return; }
    const t = e.target.closest("[data-fav-toggle]"); if (t) { e.preventDefault(); e.stopPropagation(); toggleFav(t.dataset.favToggle); return; }
    if (e.target.closest(".vnav-mini")) { setMini(!document.documentElement.classList.contains("nav-mini")); return; }
    if (e.target.closest(".vnav-k, #btn-search")) { openPal(); }
  });
  document.addEventListener("keydown", e => {               // 메뉴: Enter·Space, 탭: ←·→·Home·End
    const a = e.target.closest && e.target.closest(".vnav a[role='link']");
    if (a && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); a.click(); return; }
    const tab = e.target.closest && e.target.closest(".grp-tabs [role='tab']");
    if (!tab || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const tabs = $$("[role='tab']", tab.parentElement), i = tabs.indexOf(tab);
    const j = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    const t = tabs[j]; if (!t) return;
    if (t.dataset.tab) {
      t.click();
      FOCUS.tab = t.dataset.tab; FOCUS.until = Date.now() + 2500;  // 화면이 탭 줄을 다시 그려도 새 탭에 포커스 유지(a11y 에서 복원)
      setTimeout(refocus, 60);
    } else t.focus();
  });
  document.addEventListener("auxclick", e => {
    if (e.button !== 1) return;
    const t = e.target.closest(".grp-tabs [data-tab], .vnav a[data-fav]"); if (!t) return;
    e.preventDefault(); window.AIOPS_POPOUT && window.AIOPS_POPOUT(t.dataset.tab || t.dataset.fav);
  });
  document.addEventListener("mousedown", e => { if (e.button === 1 && e.target.closest(".grp-tabs [data-tab], .vnav a[data-fav]")) e.preventDefault(); });
  document.addEventListener("keydown", e => {               // 팔레트가 열려 있으면 키는 팔레트로(뒤 화면 Esc 닫기 방지)
    if (!P.el) return;
    const inp = P.el.querySelector("input");
    if (e.target === inp) return;
    if (e.key === "Escape") { e.preventDefault(); e.stopImmediatePropagation(); closePal(); return; }
    inp.focus();
  }, true);
  document.addEventListener("keydown", e => {
    const typing = e.target.closest && e.target.closest("input,textarea,select,[contenteditable='true']");
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K")) { if ($(".modal") || POP) return; e.preventDefault(); openPal(); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey || $(".modal") || P.el) return;
    if (e.key === "/") { if (!POP) { e.preventDefault(); openPal(); } }
    else if (e.key === "?") { e.preventDefault(); help(); }
    else if (e.key === "[" || e.key === "]") { e.preventDefault(); stepTab(e.key === "]" ? 1 : -1); }
    else if (e.key === "\\" && !POP && innerWidth > 900) { e.preventDefault(); setMini(!document.documentElement.classList.contains("nav-mini")); }
  });

  function init() {
    if (store.get("aiops.navmini", false)) document.documentElement.classList.add("nav-mini");
    const act = $(".hdr-actions");
    if (act && !$("#btn-search")) act.insertAdjacentHTML("afterbegin", `<button type="button" class="hdr-btn hdr-search" id="btn-search" title="검색·명령 (Ctrl+K)" aria-label="검색·명령"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="m15.5 15.5 5 5" stroke="currentColor" stroke-width="2"/></svg><span>검색</span><kbd>Ctrl K</kbd></button>`);
    navFoot(); progress(); renderFavs(); decorate(); a11y();
    let last = "", pend = false;
    new MutationObserver(() => {
      if (pend) return; pend = true;
      requestAnimationFrame(() => {
        pend = false;
        const n = openDrawer(); if (n !== last) { last = n; touch(n); }
        renderFavs(); decorate(); a11y();
        const m = $(".vnav-mini span:last-child"); const mini = document.documentElement.classList.contains("nav-mini");
        if (m && m.textContent !== (mini ? "메뉴 펼치기" : "메뉴 접기")) { m.textContent = mini ? "메뉴 펼치기" : "메뉴 접기"; $(".vnav-mini .ic").textContent = mini ? "»" : "«"; }
      });
    }).observe(document.body, {subtree: true, attributes: true, attributeFilter: ["hidden", "class"], childList: true});
  }
  window.AIOPS_UX = {open: openPal, help, toggleFav, setMini, favs: () => favs.slice(), recent: () => recent.slice()};
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
