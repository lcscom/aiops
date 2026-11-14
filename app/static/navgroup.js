/* 메뉴 묶음(2.19.0) — 비슷한 메뉴를 한 항목으로 묶고, 화면 위쪽 탭으로 전환
   · 왼쪽 메뉴 37개 → 15개. 묶인 메뉴는 그 묶음의 화면 위쪽 탭(같은 줄)으로 이동, 마지막에 본 탭을 기억
   · 기존 메뉴 항목(id·data-nav·각 모듈의 클릭 처리기)은 그대로 두고 숨김 — 새 창(/?view=<메뉴>)·권한(data-perm)·배지 그대로 동작
   · 묶음 배지 = 묶인 메뉴 배지(숫자) 합. ↗·Ctrl·가운데 클릭 = 지금 탭을 새 창으로
   layout.js 보다 먼저, 다른 메뉴 모듈보다 뒤에 로드 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const POP = new URLSearchParams(location.search).has("view");
  // 영역 색(2.26.0): 관제=파랑 · 인프라·워크로드=청록 · 보안·비용=보라 · AI·지식=자홍 · 관리=회청 — html[data-sec] 로 화면 전체 강조색 전환
  // [섹션, 영역 키, [묶음 id, 이름, 설명, [메뉴...]]] — 메뉴 = data-nav 값, 또는 '#요소id'(새 창 링크)
  const SECTIONS = [
    ["관제", "ops", [
      ["g-dash", "대시보드", "실시간 로그 분석 · 한눈에 보기 · 기능 둘러보기 · 통합 관제(새 창)", ["dash", "mhome", "tour", "#nav-noc"]],
      ["g-inc", "인시던트·SR", "인시던트 · AIOps 인사이트(원인 추정·전조·학습) · 지원 요청(SR)", ["inc", "aiops", "sr"]],
      ["g-mon", "모니터·로그", "모니터 · 실시간 로그 보기", ["mon", "tail"]],
    ]],
    ["인프라·워크로드", "infra", [
      ["g-inv", "인벤토리·구성도", "인벤토리 · 토폴로지 · 네트워크 구성도(새 창)", ["inv", "arch", "#nav-netmap"]],
      ["g-vks", "VKS", "", ["vks"]],
      ["g-ana", "장애·변경 분석", "호스트 분석(연결 끊김) · VM 액티비티", ["hd", "mv"]],
      ["g-perf", "성능·용량", "호스트·VM 성능 · 성능 SLI · 네트워크 트래픽 · VCF Ops 메트릭 · 용량·적정화", ["pf", "sli", "st", "om", "cap"]],
      ["g-dr", "DR·보호", "SRM 복구 계획·보호 그룹 · 스냅숏 · Appliance·VM 백업", ["dr"]],
      ["g-chk", "점검·진단", "인프라 점검 · 권장 구성 판독 · 수명 주기 점검 · What-If 시나리오(AI 체크봇·장애 시뮬레이터) · 변경 사전 검토 · 하드웨어 준비도 · RVTools 분석", ["vchk", "bp", "life", "bot", "chg", "rd", "rv"]],
    ]],
    ["보안·비용", "secu", [
      ["g-sec", "보안", "보안 판독 · 취약점 검증 · 보안(방화벽)", ["assess", "vuln", "sec"]],
      ["g-cost", "비용·라이선스", "정산 · 클라우드 비용 비교 · 라이선스 관리 · 비용 절감", ["bill", "cc", "lc", "save"]],
      ["g-rep", "리포트", "리포트 · 경영진 요약(새 창)", ["rep", "#nav-exec"]],
    ]],
    ["AI·지식", "ai", [
      ["g-chat", "AI 질의", "", ["chat"]],
      ["g-rag", "지식(KB·문서)", "", ["rag"]],
    ]],
    ["관리", "adm", [
      ["g-coll", "수집·연동", "수집 현황 · 커넥터 · 로그 전송 · VM·서버 에이전트 · SNMP 트랩", ["coll", "conn", "fwd", "agents", "snmp"]],
      ["g-sys", "시스템·관리", "플랫폼 상태 · 시스템·패치 · 운영 설정 · 사용자 · 감사로그 · 보안 점검 · 모바일 앱", ["plat", "sys", "set", "users", "audit", "sp", "mobile"]],
    ]],
  ];
  const KEY = "aiops.navgroup";
  let last = {};
  try { last = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch { last = {}; }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(last)); } catch { /* 무시 */ } };

  const nav = $(".vnav");
  if (!nav) return;
  const el = m => m.startsWith("#") ? $(m) : $(`.vnav a[data-nav="${m}"]`);
  const ext = m => m.startsWith("#");
  const ok = a => a && !a.hidden;                                  // data-perm 으로 숨겨진 메뉴 제외
  const label = a => (a.querySelector("span")?.textContent || "").trim();
  const GROUPS = [];                                               // {id, name, members:[{m, a, ext}], g(그룹 a 또는 단일 메뉴 a)}
  const byNav = {};

  function build() {
    const frag = document.createDocumentFragment();
    for (const [sec, key, groups] of SECTIONS) {
      const h = document.createElement("div"); h.className = "vnav-h"; h.textContent = sec; h.dataset.sec = key; frag.append(h);
      for (const [id, name, desc, list] of groups) {
        const members = list.map(m => ({m, a: el(m), ext: ext(m)})).filter(x => x.a);
        if (!members.length) continue;
        const grp = {id, name, members, g: null, sec: key};
        members.forEach(x => { x.a.dataset.sec = key; });
        if (members.length === 1) {                                // 혼자면 원래 항목 그대로
          grp.g = members[0].a; frag.append(grp.g);
        } else {
          const g = document.createElement("a");
          g.className = "grp"; g.dataset.group = id; g.dataset.sec = key; g.title = desc || name; g.href = "#";
          const svg = members[0].a.querySelector("svg");
          if (svg) g.append(svg.cloneNode(true));
          g.insertAdjacentHTML("beforeend", `<span></span><b class="nav-badge" hidden></b><i class="nav-pop" aria-label="새 창으로 열기">↗</i>`);
          g.querySelector("span").textContent = name;
          grp.g = g; frag.append(g);
          for (const x of members) { x.a.classList.add("nav-sub"); frag.append(x.a); }
        }
        members.forEach(x => { if (!x.ext) byNav[x.a.dataset.nav] = grp; });
        GROUPS.push(grp);
      }
    }
    // 묶음에 없는 나머지(알림 채널 테스트 등 — 운영 설정 › 알림 채널에 같은 기능)는 숨김
    $$(":scope > *", nav).forEach(x => { if (!frag.contains(x)) x.classList.add("nav-sub"); });
    $$(":scope > .vnav-h, :scope > .vnav-sep", nav).forEach(x => x.remove());
    nav.prepend(frag);
  }

  const current = grp => {
    const vis = grp.members.filter(x => !x.ext && ok(x.a));
    const open = vis.find(x => { const d = $(`#drawer-${x.a.dataset.nav}`); return d && !d.hidden; });
    return open || vis.find(x => x.a.dataset.nav === last[grp.id]) || vis[0] || null;
  };

  function badges() {
    for (const grp of GROUPS) {
      if (grp.g.dataset.group === undefined) continue;
      let n = 0, warn = true, any = false;
      grp.members.forEach(x => {
        const b = x.a.querySelector(".nav-badge"); if (!b || b.hidden || b.classList.contains("sys-ver") || !ok(x.a)) return;
        const v = parseInt((b.textContent || "").replace(/[^\d]/g, ""), 10);
        if (v > 0) { n += v; any = true; if (!b.classList.contains("warnb")) warn = false; }
      });
      const gb = grp.g.querySelector(".nav-badge");
      const txt = any ? (n > 999 ? "999+" : String(n)) : "";
      if (gb.textContent !== txt) gb.textContent = txt;
      if (gb.hidden === any) gb.hidden = !any;
      gb.classList.toggle("warnb", any && warn);
      grp.g.hidden = !grp.members.some(x => ok(x.a));
    }
  }

  let viaConn = false;             // 수집·연동 › 커넥터 탭이 운영 설정 › 커넥터 화면을 연 경우 — 묶음 문맥 유지(2.20)
  function active() {
    const d = $$(".drawer").find(x => !x.hidden && x.id !== "drawer-chat");
    let k = d ? d.id.replace("drawer-", "") : ($("#drawer-chat") && !$("#drawer-chat").hidden ? "chat" : "dash");
    if (k !== "set") viaConn = false;
    const shown = k;
    if (k === "set" && viaConn && byNav.conn) k = "conn";
    const on = byNav[k];
    GROUPS.forEach(grp => {
      if (grp.g.dataset.group !== undefined) grp.g.classList.toggle("on", grp === on);
      const cur = current(grp); const pop = grp.g.querySelector(".nav-pop");
      if (pop && cur) { pop.dataset.pop = cur.a.dataset.nav; pop.title = `${label(cur.a)} — 새 창으로 열기`; }
    });
    if (on && k !== "dash") { last[on.id] = k; save(); }
    const chat = $("#drawer-chat"); if (chat && chat.dataset.sec !== "ai") chat.dataset.sec = "ai";   // AI 질의는 겹쳐 뜨는 창 — 제 색만, 뒤 화면 색은 그대로
    const sec = k === "chat" ? "ops" : (on && on.sec) || "ops";
    if (document.documentElement.dataset.sec !== sec) document.documentElement.dataset.sec = sec;
    strips(k, on, shown);
  }

  // ------------------------------------------------------------ 화면 위쪽 탭
  function stripHtml(grp, k) {
    const tabs = grp.members.filter(x => ok(x.a)).map(x => {
      const b = x.a.querySelector(".nav-badge");
      const bad = b && !b.hidden && !b.classList.contains("sys-ver") && /\d/.test(b.textContent) ? `<b class="nav-badge${b.classList.contains("warnb") ? " warnb" : ""}">${b.textContent}</b>` : "";
      return x.ext ? `<button type="button" data-tab-ext="${x.m.slice(1)}" title="새 창">${label(x.a)} <span class="muted">↗</span></button>`
        : `<button type="button" data-tab="${x.a.dataset.nav}" class="${x.a.dataset.nav === k ? "on" : ""}">${label(x.a)}${bad}</button>`;
    }).join("");
    return `<span class="grp-name" data-sec="${grp.sec}">${grp.name}</span><nav class="grp-tl">${tabs}</nav>`;
  }
  function strips(k, grp, shown = k) {
    if (!grp || grp.members.length < 2) return;
    let host;
    if (k === "dash") host = $(".content");
    else { const d = $(`#drawer-${shown}`); host = d && d.querySelector(".drawer-box"); }
    if (!host) return;
    let s = host.querySelector(":scope > .grp-tabs");
    if (!s) { s = document.createElement("div"); s.className = "grp-tabs"; host.prepend(s); }
    const html = stripHtml(grp, k);
    if (s.dataset.h !== html) { s.innerHTML = html; s.dataset.h = html; }
  }

  // ------------------------------------------------------------ 클릭
  document.addEventListener("click", e => {
    const t = e.target.closest(".grp-tabs [data-tab], .grp-tabs [data-tab-ext]");
    if (t) {
      e.preventDefault();
      const a = t.dataset.tab ? $(`.vnav a[data-nav="${t.dataset.tab}"]`) : $(`#${t.dataset.tabExt}`);
      if (a && (e.ctrlKey || e.metaKey || e.shiftKey) && t.dataset.tab && window.AIOPS_POPOUT) { window.AIOPS_POPOUT(t.dataset.tab); return; }
      viaConn = t.dataset.tab === "conn";
      if (a) a.click();
      return;
    }
    const g = e.target.closest(".vnav a[data-group]");
    if (!g || e.target.closest(".nav-pop")) return;                 // ↗ 는 layout.js 가 처리(data-pop)
    e.preventDefault();
    const grp = GROUPS.find(x => x.id === g.dataset.group), cur = grp && current(grp);
    if (!cur) return;
    if ((e.ctrlKey || e.metaKey || e.shiftKey) && window.AIOPS_POPOUT) { window.AIOPS_POPOUT(cur.a.dataset.nav); return; }
    viaConn = cur.a.dataset.nav === "conn";
    cur.a.click();
  });
  document.addEventListener("auxclick", e => {
    const g = e.button === 1 && e.target.closest(".vnav a[data-group]"); if (!g) return;
    e.preventDefault();
    const grp = GROUPS.find(x => x.id === g.dataset.group), cur = grp && current(grp);
    if (cur && window.AIOPS_POPOUT) window.AIOPS_POPOUT(cur.a.dataset.nav);
  });

  build();
  let pend = false;
  const tick = () => { if (pend) return; pend = true; requestAnimationFrame(() => { pend = false; badges(); active(); }); };
  new MutationObserver(tick).observe(document.body, {subtree: true, attributes: true, attributeFilter: ["hidden", "class"], childList: true, characterData: true});
  tick();
  if (POP) document.documentElement.classList.add("popout-grp");
  window.AIOPS_NAVGROUPS = {SECTIONS, GROUPS};
})();
