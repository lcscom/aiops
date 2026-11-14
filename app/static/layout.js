/* 레이아웃·새 창(2.17.0)
   ① 메뉴 화면(서랍)을 왼쪽 메뉴 오른쪽 전체 영역에 '페이지'로 표시 — 반쪽 패널·대시보드 비침 없음, 메뉴를 닫지 않고 바로 다른 메뉴로 이동
   ② 모든 메뉴를 새 창으로 — 메뉴 항목의 ↗(또는 Ctrl·가운데 클릭), 화면 머리글의 '새 창'. 새 창(/?view=<메뉴>)은 그 메뉴만 창 전체로
   ③ 정렬 — 표의 숫자 열 자동 오른쪽 정렬(tabular-nums), 도구 막대 입력·버튼 높이 통일 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const qs = new URLSearchParams(location.search);
  const VIEW = (qs.get("view") || "").replace(/[^a-z0-9_-]/gi, "").slice(0, 40);
  const POP = !!VIEW;
  const overlay = d => !!d.querySelector(".drawer-box.chat");          // AI 질의는 옆에서 여는 보조 창으로 유지
  const label = nav => { const a = $(`.vnav a[data-nav="${nav}"]`); return a ? (a.querySelector("span")?.textContent || nav).trim() : nav; };
  const drawerOf = nav => $(`#drawer-${nav}`);

  // ------------------------------------------------------------ 새 창
  function popout(nav) {
    const w = Math.min(screen.availWidth || 1600, 1600), h = Math.min(screen.availHeight || 1000, 1000);
    const win = window.open(`/?view=${encodeURIComponent(nav)}`, `aiops-${nav}`, `popup=yes,width=${w},height=${h},left=${Math.max(0, (screen.availWidth - w) / 2)},top=40`);
    if (win) win.focus();
    else window.AIOPS && window.AIOPS.fail && window.AIOPS.fail("새 창을 열지 못했습니다", new Error("브라우저의 팝업 차단을 이 사이트에 대해 해제하세요"));
  }
  window.AIOPS_POPOUT = popout;

  function decorateNav() {
    $$(".vnav a[data-nav]").forEach(a => {
      if (a.querySelector(".nav-pop")) return;
      const i = document.createElement("i");
      i.className = "nav-pop"; i.title = `${label(a.dataset.nav)} — 새 창으로 열기`; i.setAttribute("aria-label", i.title); i.textContent = "↗";
      a.append(i);
    });
  }
  function decorateDrawers() {
    $$(".drawer").forEach(d => {
      const head = d.querySelector(".drawer-head"); if (!head || head.querySelector(".pop-btn")) return;
      const nav = d.id.replace("drawer-", ""); if (!$(`.vnav a[data-nav="${nav}"]`)) return;
      const box = head.querySelector(":scope > div:last-child") || head;
      const b = document.createElement("button");
      b.className = "btn-sm pop-btn"; b.type = "button"; b.dataset.pop = nav; b.title = "이 메뉴를 새 창으로"; b.textContent = "새 창 ↗";
      const x = box.querySelector("[data-close]"); x ? box.insertBefore(b, x) : box.append(b);
    });
  }

  // 클릭 가로채기(캡처 단계 — 각 메뉴 모듈의 onclick 보다 먼저)
  document.addEventListener("click", e => {
    const pop = e.target.closest(".nav-pop, [data-pop]");
    if (pop) {
      e.preventDefault(); e.stopImmediatePropagation();
      popout(pop.dataset.pop || pop.closest("a[data-nav]").dataset.nav);
      return;
    }
    const a = e.target.closest(".vnav a[data-nav]");
    if (!a) return;
    if (e.ctrlKey || e.metaKey || e.shiftKey) { e.preventDefault(); e.stopImmediatePropagation(); popout(a.dataset.nav); return; }
    // 페이지 전환: 다른 메뉴 화면을 닫고 이 메뉴만(대시보드는 모두 닫기)
    $$(".drawer").forEach(d => { if (!d.hidden && d.id !== `drawer-${a.dataset.nav}`) d.hidden = true; });
  }, true);
  document.addEventListener("auxclick", e => {
    const a = e.button === 1 && e.target.closest(".vnav a[data-nav]");
    if (a) { e.preventDefault(); popout(a.dataset.nav); }
  });

  // ------------------------------------------------------------ 페이지 영역(머리글·배너·메뉴를 피해서)
  function place() {
    const hdr = $(".hdr"), ban = $("#ws-banner"), nav = $(".vnav");
    let top = hdr ? hdr.getBoundingClientRect().bottom : 0;
    if (ban && !ban.hidden) top = Math.max(top, ban.getBoundingClientRect().bottom);
    let left = 0;
    if (nav && !POP && getComputedStyle(nav).display !== "none") {
      const r = nav.getBoundingClientRect();
      if (r.height > r.width) left = r.right; else top = Math.max(top, r.bottom);   // 세로 메뉴 = 왼쪽, 모바일 가로 메뉴 = 위
    }
    document.documentElement.style.setProperty("--dtop", `${Math.round(top)}px`);
    document.documentElement.style.setProperty("--dleft", `${Math.round(left)}px`);
  }
  addEventListener("resize", place);

  // ------------------------------------------------------------ 숫자 열 오른쪽 정렬
  const NUM = /^[-+]?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?\s*(%|ms|s|초|분|일|시간|건|대|개|배|x|GB|TB|MB|KB|GiB|TiB|MiB|Gb|Mb|MHz|GHz|코어|vCPU|원|\$|:1)?$|^[$₩]\s?[\d,]+(\.\d+)?$|^—$|^-$/;
  function alignTables(root) {
    $$("table", root).forEach(t => {
      const rows = t.tBodies[0] ? [...t.tBodies[0].rows].slice(0, 120) : [];
      if (rows.length < 1 || t.dataset.alnN === String(t.tBodies[0].rows.length) + ":" + (rows[0]?.cells.length || 0)) return;
      const n = Math.max(0, ...rows.map(r => r.cells.length));
      const cols = [];
      for (let c = 0; c < n; c++) {
        let num = 0, tot = 0;
        for (const r of rows) {
          const cell = r.cells[c]; if (!cell || cell.colSpan > 1) continue;
          const tx = cell.textContent.trim(); if (!tx) continue;
          if (cell.querySelector("input,select,button,textarea")) { tot = -1; break; }
          tot++; if (NUM.test(tx) && !/^[-—]$/.test(tx)) num++; else if (!/^[-—]$/.test(tx)) { /* 문자 */ }
        }
        if (tot > 0 && num > 0 && num / tot >= 0.8) cols.push(c);
      }
      const head = t.tHead ? t.tHead.rows[t.tHead.rows.length - 1] : null;
      for (const c of cols) {
        if (head && head.cells[c] && head.cells.length === n) head.cells[c].classList.add("num");
        for (const r of t.tBodies[0].rows) if (r.cells[c] && r.cells.length === n) r.cells[c].classList.add("num");
      }
      t.dataset.alnN = String(t.tBodies[0].rows.length) + ":" + (rows[0]?.cells.length || 0);
    });
  }
  let pend = false;
  function schedule() {
    if (pend) return; pend = true;
    (window.requestIdleCallback || (f => setTimeout(f, 120)))(() => {
      pend = false;
      $$(".drawer:not([hidden]) .pad, .drawer:not([hidden]) .drawer-body, .drawer:not([hidden]) [id$='-body']").forEach(alignTables);
    }, {timeout: 400});
  }

  // ------------------------------------------------------------ 새 창 모드
  async function bootPopout() {
    document.documentElement.classList.add("popout");
    document.body.classList.add("popout");
    try { await (window.AIOPS && window.AIOPS.ready); } catch { /* 로그인 화면으로 이동됨 */ }
    await new Promise(r => setTimeout(r, 250));
    const a = $(`.vnav a[data-nav="${VIEW}"]`);
    document.title = `${label(VIEW)} — VCF AIops`;
    if (!a || VIEW === "dash") { document.body.classList.add("popout-dash"); return; }
    if (a.hidden) {                                   // 권한 없는 메뉴(data-perm) — 화면을 열지 않고 안내(2.20)
      document.body.classList.add("popout-dash");
      window.AIOPS && window.AIOPS.toast && window.AIOPS.toast("이 화면을 볼 권한이 없습니다", label(VIEW), "warn", 10000);
      document.title = "VCF AIops";
      return;
    }
    a.click();
    await new Promise(r => setTimeout(r, 300));
    const d = $$(".drawer").find(x => !x.hidden && x.id !== "drawer-chat") || drawerOf(VIEW);   // 커넥터처럼 다른 화면(운영 설정)을 여는 메뉴도 그 화면을 지킴(2.20)
    // 닫기 = 창 닫기(스크립트로 연 창이 아니면 메인으로), Esc 등으로 숨겨지면 다시 표시
    document.addEventListener("click", e => {
      const x = e.target.closest("[data-close]");
      if (x && d && x.closest(".drawer") === d) { e.preventDefault(); e.stopImmediatePropagation(); window.close(); setTimeout(() => { location.href = "/"; }, 250); }
    }, true);
    if (d) new MutationObserver(() => {
      if (d.hidden && !$$(".drawer").some(x => !x.hidden)) d.hidden = false;
    }).observe(d, {attributes: true, attributeFilter: ["hidden"]});
    const h = d && d.querySelector(".drawer-head h3");
    if (h) h.insertAdjacentHTML("afterbegin", `<a class="pop-home" href="/" target="aiops-main" title="메인 콘솔">VCF AIops</a><span class="pop-sep">›</span>`);
  }

  function init() {
    decorateNav(); decorateDrawers(); place();
    new MutationObserver(muts => {
      let lay = false;
      for (const m of muts) {
        if (m.type === "attributes" && m.attributeName === "hidden") { lay = true; }
      }
      if (lay) place();
      schedule();
    }).observe(document.body, {subtree: true, childList: true, attributes: true, attributeFilter: ["hidden"]});
    $$(".drawer").forEach(d => { if (!overlay(d)) d.classList.add("page"); });
    if (POP) bootPopout();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
