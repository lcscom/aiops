/* 한국어 / English — 화면 언어 전환(KO 기본·EN). 모든 페이지에서 core.js 보다 먼저 로드.
 * 방식: 화면의 한국어 문구(텍스트 노드·title·placeholder·aria-label)를 사전(i18n-en.js)으로 치환.
 *       동적으로 그려지는 표·모달·토스트도 MutationObserver 로 같은 방식 적용. 사전에 없는 문구는 한국어 그대로.
 * 언어 선택: 상단의 KO/EN 버튼 → localStorage(aiops.lang) · ?lang=en|ko · 처음 방문 시 브라우저 언어. */
(() => {
  "use strict";
  const KEY = "aiops.lang";
  const q = new URLSearchParams(location.search).get("lang");
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch { /* 사생활 보호 모드 */ }
  let lang = (q || saved || ((navigator.language || "ko").toLowerCase().startsWith("ko") ? "ko" : "en")).toLowerCase().startsWith("en") ? "en" : "ko";
  if (q) { try { localStorage.setItem(KEY, lang); } catch { /* 무시 */ } }
  document.documentElement.lang = lang;

  const API = window.AIOPS_I18N = {
    lang,
    set(l) { try { localStorage.setItem(KEY, l); } catch { /* 무시 */ } location.reload(); },
    t: s => s,
    toggleHtml: () => `<span class="lang-sw" role="group" aria-label="Language"><button type="button" data-lang="ko" class="${lang === "ko" ? "on" : ""}">KO</button><button type="button" data-lang="en" class="${lang === "en" ? "on" : ""}">EN</button></span>`,
  };
  document.addEventListener("click", e => {
    const b = e.target.closest && e.target.closest("[data-lang]");
    if (b && b.dataset.lang !== lang) API.set(b.dataset.lang);
  });
  const fillSlots = () => document.querySelectorAll("#lang-slot,.lang-slot").forEach(e => { if (!e.firstChild) e.innerHTML = API.toggleHtml(); });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fillSlots); else fillSlots();
  if (lang !== "en") return;

  const DICT = window.AIOPS_I18N_EN || {};
  const HANGUL = /[가-힣]/;
  const keys = Object.keys(DICT).filter(k => HANGUL.test(k)).sort((a, b) => b.length - a.length);
  const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // 긴 문구부터 일치(부분 문구가 긴 문구를 먼저 잘라먹지 않게)
  const RE = keys.length ? new RegExp(keys.map(escRe).join("|"), "g") : null;
  const AMBIG = new Set(["이상", "이하", "갱신", "확인", "사용", "보고", "결과", "기록", "관리", "표시", "시간"]);
  const PARTICLES = "으로|에서|까지|부터|에게|이나|은|는|이|가|을|를|에|의|로|와|과|도|만|된|된다|하는|한|할|중";
  const RE_B = keys.length ? new RegExp(`(${keys.map(escRe).join("|")})(${PARTICLES})?`, "g") : null;
  // 숫자가 낀 상대 시간·단위 패턴(사전 치환 전에 적용)
  const PAT = [
    [/최근 (\d+)분 동안 미확인 이상 징후가 없습니다\./g, "No unacknowledged anomalies in the last $1 min."],
    [/(\d+)\s*초 후 재시도/g, "retry in $1s"], [/최근 (\d+)개 보관/g, "keeps last $1"], [/(\d+)개 신호 중 최저/g, "lowest of $1 signals"],
    [/(\d{4})년\s*(\d{1,2})월\s*(\d{1,2})일/g, "$1-$2-$3"], [/([월화수목금토일])요일/g, (m, d) => ({월: "Mon", 화: "Tue", 수: "Wed", 목: "Thu", 금: "Fri", 토: "Sat", 일: "Sun"})[d]],
    [/\(([월화수목금토일])\)/g, (m, d) => "(" + ({월: "Mon", 화: "Tue", 수: "Wed", 목: "Thu", 금: "Fri", 토: "Sat", 일: "Sun"})[d] + ")"],
    [/(\d+(?:\.\d+)?)\s*초 전/g, "$1s ago"], [/(\d+(?:\.\d+)?)\s*분 전/g, "$1 min ago"], [/(\d+(?:\.\d+)?)\s*시간 전/g, "$1 h ago"],
    [/(\d+(?:\.\d+)?)\s*일 전/g, "$1 d ago"], [/(\d+(?:,\d{3})*)\s*건/g, "$1"], [/(\d+(?:,\d{3})*)\s*개/g, "$1"], [/(\d+)\s*대(?![가-힣])/g, "$1"],
    [/(\d+)\s*줄\/초/g, "$1 lines/s"], [/(\d+(?:,\d{3})*)\s*줄/g, "$1 lines"], [/(\d+)\s*분째/g, "for $1 min"], [/(\d+)\s*회/g, "$1×"],
    [/(\d+(?:\.\d+)?)\s*(%|년|개월|일|시간|분|초|대|개|건|GB|TB|코어)?\s*(이상|이하)(?![가-힣])/g, (m, n, u, op) => (op === "이상" ? "≥" : "≤") + n + ({년: "y", 개월: " mo", 일: "d", 시간: "h", 분: " min", 초: "s", 대: "", 개: "", 건: "", 코어: " cores"}[u] ?? (u || ""))],
    [/(\d+)\s*초(?![가-힣])/g, "$1s"], [/(\d+)\s*분(?![가-힣])/g, "$1 min"], [/(\d+)\s*시간(?![가-힣])/g, "$1 h"], [/(\d+)\s*일(?![가-힣])/g, "$1 d"],
  ];
  const cache = new Map();
  function tr(s) {
    if (!s || !HANGUL.test(s)) return s;
    const hit = cache.get(s); if (hit !== undefined) return hit;
    const t = s.trim();
    let out;
    if (DICT[t] !== undefined) out = s.replace(t, DICT[t]);
    else {
      out = s;
      for (const [re, rep] of PAT) out = out.replace(re, rep);
      // 문장 안 부분 치환은 낱말 경계에서만(2.20) — 한 글자·뜻이 여럿인 사전어는 문구 전체가 그 낱말일 때만,
      // 앞에 한글이 붙어 있으면 다른 낱말의 일부(예: '은행'·'관제실'), 뒤에는 조사만 허용하고 조사는 뺌(예: '커넥터를' → 'Connector')
      if (RE) out = out.replace(RE_B, (all, m, pt, i, str) => {
        if (m.length === 1 || AMBIG.has(m) || HANGUL.test(str[i - 1] || "")) return all;   // 한 글자·뜻이 여럿인 낱말(확인·갱신·이상·사용 …)은 문구 전체일 때만
        const after = str[i + all.length] || "";
        if (HANGUL.test(after)) return all;                       // 조사 뒤에 또 한글 → 다른 낱말
        return DICT[m] + (pt && /^[A-Za-z]/.test(DICT[m]) ? "" : (pt || ""));
      });
      out = out.replace(/\s{2,}/g, " ");
    }
    if (cache.size > 20000) cache.clear();
    cache.set(s, out);
    return out;
  }
  API.t = tr;
  const SKIP = new Set(["SCRIPT", "STYLE", "TEXTAREA", "NOSCRIPT"]);
  const ATTRS = ["title", "placeholder", "aria-label", "alt", "data-tip"];
  function attrs(el) {                        // 바뀔 때만 설정(같은 값 재설정 → 변경 감지 → 무한 반복 방지)
    if (!el.getAttribute) return;
    for (const a of ATTRS) { const v = el.getAttribute(a); if (v && HANGUL.test(v)) { const t = tr(v); if (t !== v) el.setAttribute(a, t); } }
    if (el.nodeName === "INPUT" && /^(button|submit)$/i.test(el.type) && HANGUL.test(el.value)) { const t = tr(el.value); if (t !== el.value) el.value = t; }
  }
  function walk(root) {
    if (!root) return;
    if (root.nodeType === 3) { const v = tr(root.nodeValue); if (v !== root.nodeValue) root.nodeValue = v; return; }
    if (root.nodeType !== 1 || SKIP.has(root.nodeName) || root.isContentEditable || root.closest?.(".no-i18n")) return;
    attrs(root);
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
      acceptNode: n => n.nodeType === 1 && (SKIP.has(n.nodeName) || n.classList.contains("no-i18n") || n.isContentEditable)
        ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT});
    let n;
    while ((n = w.nextNode())) {
      if (n.nodeType === 3) { if (HANGUL.test(n.nodeValue)) { const v = tr(n.nodeValue); if (v !== n.nodeValue) n.nodeValue = v; } }
      else attrs(n);
    }
  }
  let pending = new Set(), scheduled = false;
  const flush = () => { scheduled = false; const list = [...pending]; pending = new Set(); list.forEach(walk); };
  const mo = new MutationObserver(ms => {
    for (const m of ms) {
      if (m.type === "characterData") pending.add(m.target);
      else if (m.type === "attributes") pending.add(m.target);
      else m.addedNodes.forEach(n => pending.add(n));
    }
    if (!scheduled) { scheduled = true; queueMicrotask(flush); }
  });
  const start = () => {
    walk(document.body);
    document.title = tr(document.title);
    mo.observe(document.body, {childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS});
    new MutationObserver(() => { const t = tr(document.title); if (t !== document.title) document.title = t; })
      .observe(document.querySelector("title") || document.head, {childList: true, subtree: true, characterData: true});
  };
  if (document.body) start(); else document.addEventListener("DOMContentLoaded", start);
  // 브라우저 기본 대화상자(일부 화면에서 사용)도 번역
  const _c = window.confirm.bind(window), _a = window.alert.bind(window), _p = window.prompt.bind(window);
  window.confirm = m => _c(tr(String(m))); window.alert = m => _a(tr(String(m))); window.prompt = (m, d) => _p(tr(String(m)), d);
})();
