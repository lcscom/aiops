/* 공통 — 세션·권한·CSRF 헤더·유휴 타임아웃·모달·토스트. app.js / enterprise.js 보다 먼저 로드 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
  const A = window.AIOPS = {me: null, esc, ready: null};
  const toLogin = q => { if (!location.pathname.startsWith("/login")) location.replace(`/login?${q}&next=${encodeURIComponent(location.pathname + location.hash)}`); };

  // ---------------------------------------------------------------- 스크롤 보호
  // 화면 틀(body·패널 래퍼)은 overflow:hidden 이라 사용자가 스크롤할 수 없다. 그런데 scrollIntoView·focus()·앵커 이동은
  // 이런 상자도 프로그램으로 밀어 올리고, 한 번 밀리면 위로 되돌릴 방법이 없다("가끔 위로 스크롤이 안 됨").
  // → overflow 가 hidden/clip 인 상자에서 일어난 스크롤은 즉시 0 으로 되돌린다(capture 단계 — scroll 은 버블링되지 않음).
  const isClip = el => { try { const cs = getComputedStyle(el); return /hidden|clip/.test(cs.overflowY) && /hidden|clip/.test(cs.overflowX); } catch { return false; } };
  const fixScroll = el => {
    if (!el || el.nodeType !== 1 || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)) return;
    if ((el.scrollTop || el.scrollLeft) && isClip(el) && !el.hasAttribute("data-scroll-ok")) { el.scrollTop = 0; el.scrollLeft = 0; }
  };
  document.addEventListener("scroll", e => {
    const t = e.target;
    if (t === document || t === document.documentElement) {           // 문서 자체가 밀린 경우(body overflow:hidden 화면)
      const se = document.scrollingElement || document.documentElement;
      if (se.scrollTop && isClip(document.body)) { se.scrollTop = 0; document.body.scrollTop = 0; }
      return;
    }
    fixScroll(t);
  }, true);
  // 스크롤 가능한 가장 가까운 조상만 움직이는 scrollIntoView 대체 — 화면 틀은 건드리지 않는다
  const scroller = el => { for (let p = el && el.parentElement; p && p !== document.body; p = p.parentElement) { const o = getComputedStyle(p).overflowY; if ((o === "auto" || o === "scroll") && p.scrollHeight > p.clientHeight) return p; } return null; };
  A.reveal = (el, {block = "nearest", smooth = true} = {}) => {
    if (!el) return;
    const box = scroller(el); if (!box) return;
    const r = el.getBoundingClientRect(), b = box.getBoundingClientRect();
    let top = null;
    if (block === "center") top = box.scrollTop + (r.top - b.top) - (b.height - r.height) / 2;
    else if (r.top < b.top) top = box.scrollTop + (r.top - b.top) - 8;
    else if (r.bottom > b.bottom) top = box.scrollTop + (r.bottom - b.bottom) + 8;
    if (top !== null) box.scrollTo({top: Math.max(0, top), behavior: smooth ? "smooth" : "auto"});
  };
  // 아래쪽에 붙어 있을 때만 따라 내려가기(채팅·실시간 로그) — 사용자가 위로 올려 읽는 중이면 그대로 둔다
  A.nearBottom = (box, px = 80) => !box || box.scrollHeight - box.scrollTop - box.clientHeight < px;
  A.stick = (box, was) => { if (box && was) box.scrollTop = box.scrollHeight; };

  // ---------------------------------------------------------------- fetch 래퍼
  // · 모든 요청에 X-Requested-With(서버 CSRF 검사)  · {background:true} → X-Background(유휴 시간 갱신 안 함)
  // · 401 → 로그인 화면  · 403 must_change → 비밀번호 변경  · 403 forbidden → 안내 토스트
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (url, opts = {}) => {
    const o = {...opts, headers: new Headers(opts.headers || {})};
    o.headers.set("X-Requested-With", "aiops");
    if (opts.background) o.headers.set("X-Background", "1");
    if (typeof o.body === "string" && !o.headers.has("Content-Type")) o.headers.set("Content-Type", "application/json");
    delete o.background;
    const r = await nativeFetch(url, o);
    if (r.status === 401 && String(url).startsWith("/api/") && !String(url).startsWith("/api/auth/login")) toLogin("expired=1");
    else if (r.status === 403) {
      const j = await r.clone().json().catch(() => ({}));
      if (j.code === "must_change") toLogin("change=1");
      else if (j.code === "mfa_enroll") { if (window.AIOPS_ENROLL_MFA && !A._mfaPrompt) { A._mfaPrompt = true; window.AIOPS_ENROLL_MFA(true); } }
      else if (j.code === "forbidden") A.toast("권한 없음", j.detail || "이 작업을 수행할 권한이 없습니다.", "warning");
      else if (j.code === "csrf") A.toast("요청 차단", j.detail, "error");
    }
    return r;
  };

  /** JSON API 호출 — 실패 시 서버 detail 을 담은 Error */
  A.api = async (method, url, body, opt = {}) => {
    const r = await fetch(url, {method, body: body === undefined ? undefined : JSON.stringify(body), background: opt.background});
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json().catch(() => null) : await r.text();
    if (!r.ok) {
      const msg = (data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `HTTP ${r.status}`;
      const err = new Error(msg); err.status = r.status; throw err;
    }
    return data;
  };
  A.can = perm => !!(A.me && (A.me.perms || []).includes(perm));

  // ---------------------------------------------------------------- 토스트 · 모달
  A.toast = (title, body = "", kind = "info", ms = 6000) => {
    const box = $("#toasts"); if (!box) return;
    const t = document.createElement("div");
    t.className = `toast ${kind}`; t.innerHTML = `<b>${esc(title)}</b>${body ? `<pre>${esc(body)}</pre>` : ""}`;
    t.onclick = () => t.remove(); box.prepend(t); setTimeout(() => t.remove(), ms);
  };
  A.ok = (title, body) => A.toast(title, body, "ok", 3500);
  A.fail = (title, e) => A.toast(title, e && e.message ? e.message : String(e || ""), "error", 9000);
  // 화면에서 만든 파일 저장(2.30.0) — 안드로이드 앱(WebView)은 blob: 내려받기가 안 되므로 앱 브리지로 넘긴다
  A.inApp = /VCFAIopsApp\//.test(navigator.userAgent);
  A.download = (name, blob) => {
    const app = window.AIOPSApp;
    if (A.inApp && app && app.saveFile) {
      const fr = new FileReader();
      fr.onload = () => { if (!app.saveFile(name, String(fr.result).split(",")[1] || "", blob.type || "")) A.toast("저장 실패", "앱이 파일을 저장하지 못했습니다(28MB 이하만 가능).", "error"); };
      fr.onerror = () => A.toast("저장 실패", "파일을 읽지 못했습니다.", "error");
      fr.readAsDataURL(blob);
      return;
    }
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  };

  /** 모달 — fields: [{id,label,type,value,options,placeholder,required,hint}] → 확인 시 값 객체 반환, 취소 시 null */
  A.modal = ({title, html = "", fields = [], ok = "확인", cancel = "취소", danger = false, wide = false, onOpen}) => new Promise(resolve => {
    const m = document.createElement("div");
    m.className = "modal";
    const fh = fields.map(f => {
      const v = f.value ?? "";
      let input;
      if (f.type === "select") input = `<select id="mf-${f.id}">${(f.options || []).map(o => { const [val, lab] = Array.isArray(o) ? o : [o, o];
        return `<option value="${esc(val)}" ${String(val) === String(v) ? "selected" : ""}>${esc(lab)}</option>`; }).join("")}</select>`;
      else if (f.type === "textarea") input = `<textarea id="mf-${f.id}" rows="${f.rows || 4}" placeholder="${esc(f.placeholder || "")}">${esc(v)}</textarea>`;
      else if (f.type === "checkbox") input = `<input id="mf-${f.id}" type="checkbox" ${v ? "checked" : ""}>`;
      else input = `<input id="mf-${f.id}" type="${f.type || "text"}" value="${esc(v)}" placeholder="${esc(f.placeholder || "")}" ${f.min != null ? `min="${f.min}"` : ""} ${f.max != null ? `max="${f.max}"` : ""} ${f.step != null ? `step="${f.step}"` : ""}>`;
      return `<label class="mf ${f.type === "checkbox" ? "chk" : ""}"><span>${esc(f.label)}${f.required ? " *" : ""}</span>${input}${f.hint ? `<small>${esc(f.hint)}</small>` : ""}</label>`;
    }).join("");
    m.innerHTML = `<div class="modal-box ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-label="${esc(title)}"><div class="modal-head"><h3>${esc(title)}</h3><button class="x" data-x aria-label="닫기">✕</button></div>
      <div class="modal-body">${html}${fh}<div class="modal-err" hidden></div></div>
      <div class="modal-foot"><button class="btn-sm" data-x>${esc(cancel)}</button>${ok ? `<button class="btn-sm solid ${danger ? "danger" : ""}" data-ok>${esc(ok)}</button>` : ""}</div></div>`;
    const prev = document.activeElement;
    document.body.append(m);
    const close = v => { m.remove(); document.removeEventListener("keydown", key, true); try { if (prev && prev.focus && document.contains(prev)) prev.focus(); } catch {} resolve(v); };
    // 2.36.0 접근성 — 열린 창 안에서만 Tab 이 돌고(포커스 가두기), 닫으면 연 버튼으로 포커스를 돌려준다. 겹친 창은 맨 위 것만 반응
    const key = e => {
      const top = [...document.querySelectorAll(".modal")].pop();
      if (top !== m) return;
      if (e.key === "Escape") { e.stopPropagation(); close(null); return; }
      if (e.key !== "Tab") return;
      const fs = [...m.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
        .filter(x => x.offsetParent !== null || x === document.activeElement);
      if (!fs.length) { e.preventDefault(); return; }
      const i = fs.indexOf(document.activeElement);
      if (e.shiftKey && (i <= 0)) { e.preventDefault(); fs[fs.length - 1].focus(); }
      else if (!e.shiftKey && (i === -1 || i === fs.length - 1)) { e.preventDefault(); fs[0].focus(); }
    };
    document.addEventListener("keydown", key, true);
    m.addEventListener("click", e => { if (e.target === m || e.target.closest("[data-x]")) close(null); });
    const okb = m.querySelector("[data-ok]");
    if (okb) okb.onclick = () => {
      const out = {};
      for (const f of fields) {
        const el = m.querySelector(`#mf-${f.id}`);
        out[f.id] = f.type === "checkbox" ? el.checked : f.type === "number" ? (el.value === "" ? null : Number(el.value)) : el.value.trim();
        if (f.required && (out[f.id] === "" || out[f.id] == null)) {
          const er = m.querySelector(".modal-err"); er.hidden = false; er.textContent = `'${f.label}' 을(를) 입력하세요`; el.focus(); return;
        }
      }
      close(out);
    };
    const first = m.querySelector("input,select,textarea") || m.querySelector("[data-ok]") || m.querySelector(".modal-head [data-x]"); if (first) first.focus();
    if (onOpen) onOpen(m);
  });
  A.confirm = (title, text, danger = false) => A.modal({title, html: `<p class="modal-text">${esc(text)}</p>`, ok: danger ? "실행" : "확인", danger}).then(v => v !== null);

  // ---------------------------------------------------------------- 세션 · 유휴 타임아웃
  let lastInput = Date.now(), lastBeat = Date.now(), idleMs = 10 * 60000, warnShown = false;
  ["mousedown", "keydown", "wheel", "touchstart"].forEach(ev => addEventListener(ev, () => { lastInput = Date.now(); }, {passive: true, capture: true}));
  setInterval(async () => {
    if (!A.me || !A.me.auth || A.me.kiosk) return;     // 관제 전용 계정은 유휴 로그아웃 없음
    const now = Date.now(), idle = now - lastInput;
    if (idle < 60000 && now - lastBeat > 55000) { lastBeat = now; fetch("/api/auth/heartbeat", {method: "POST"}).catch(() => {}); }
    if (idle >= idleMs) { await fetch("/api/auth/logout", {method: "POST"}).catch(() => {}); toLogin("expired=1"); return; }
    if (idle >= idleMs - 60000 && !warnShown) {
      warnShown = true;
      const keep = await A.modal({title: "세션 만료 예정", html: `<p class="modal-text">입력이 없어 1분 후 자동 로그아웃됩니다. 계속 사용하시겠습니까?</p>`, ok: "계속 사용", cancel: "로그아웃"});
      warnShown = false;
      if (keep) { lastInput = Date.now(); lastBeat = Date.now(); fetch("/api/auth/heartbeat", {method: "POST"}); }
      else { await fetch("/api/auth/logout", {method: "POST"}); location.replace("/login?logout=1"); }
    }
  }, 5000);

  // ---------------------------------------------------------------- 실시간 스트림(공용)
  // · 재접속: 지수 백오프 + 지터(1→30초), 탭 복귀·네트워크 복구 시 즉시
  // · 하트비트: 서버가 1초마다 status 를 보내므로 10초간 수신이 없으면 반쯤 끊긴 연결로 보고 재접속
  // · 순번(seq): 상태 메시지(anomaly·incident·alert…)가 건너뛰면 'resync' 요청 → 서버가 스냅샷 재전송
  // · 빌드 변경: 서버 재배포(정적 파일 교체) 후 재접속 시 화면을 자동 새로고침 — 관제 화면을 며칠 띄워 둬도 최신 유지
  A.stream = (onMsg, onState = () => {}) => {
    let ws = null, retry = 1000, timer = null, lastMsg = 0, seq = null, build = null, waiting = false, first = true;
    const info = {state: "connecting", downSince: Date.now(), lastMsg: 0, retryAt: 0, reconnects: 0, resyncs: 0};
    const set = st => { info.state = st; info.lastMsg = lastMsg; onState(st, info); };
    const schedule = () => {
      clearTimeout(timer);
      const wait = Math.round(retry * (0.5 + Math.random()));
      retry = Math.min(retry * 2, 30000);
      info.retryAt = Date.now() + wait;
      timer = setTimeout(connect, wait);
    };
    function connect() {
      clearTimeout(timer);
      if (ws && (ws.readyState === 0 || ws.readyState === 1)) return;
      set(first ? "connecting" : "reconnecting");
      try { ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`); }
      catch { schedule(); return; }
      ws.onopen = () => { lastMsg = Date.now(); };
      ws.onmessage = e => {
        lastMsg = Date.now();
        let m; try { m = JSON.parse(e.data); } catch { return; }
        if (m.type === "snapshot") {
          if (build && m.build && m.build !== build) { location.reload(); return; }
          build = build || m.build; seq = m.seq; waiting = false; retry = 1000;
          m.reconnect = !first; first = false; info.downSince = 0;
          onMsg(m); set("live"); return;
        }
        if (m.seq != null && !waiting) {
          if (seq != null && m.seq !== seq + 1) {
            waiting = true; info.resyncs++;
            try { ws.send("resync"); } catch { /* 닫히는 중 */ }
            set("resync");
          } else seq = m.seq;
        }
        onMsg(m);
      };
      ws.onclose = ev => {
        if (!info.downSince) info.downSince = Date.now();
        info.reconnects++; seq = null; waiting = false;
        set("down");
        // 4401(세션 만료) 또는 핸드셰이크 거부(1006) → 세션 확인(401이면 로그인 화면으로)
        if (ev.code === 4401 || ev.code === 1006) fetch("/api/auth/me", {background: true}).catch(() => {});
        if (ev.code === 1012) retry = 2000;          // 서버 재시작 — 기동 시간만큼 기다렸다 재접속
        schedule();
      };
    }
    setInterval(() => { if (ws && ws.readyState === 1) try { ws.send("ping"); } catch { /* 무시 */ } }, 25000);
    setInterval(() => {
      if (ws && ws.readyState === 1 && lastMsg && Date.now() - lastMsg > 10000) { set("stale"); try { ws.close(4000, "stale"); } catch { /* 무시 */ } }
      else if (info.state !== "live") onState(info.state, info);   // 끊김 경과 시간 표시 갱신
    }, 2000);
    A.wsSend = t => { try { if (ws && ws.readyState === 1) { ws.send(t); return true; } } catch { /* 닫히는 중 */ } return false; };
    const now = () => { if (!ws || ws.readyState > 1) { retry = 1000; connect(); } };
    document.addEventListener("visibilitychange", () => { if (!document.hidden) now(); });
    addEventListener("online", now);
    connect();
    return info;
  };

  A.logout = async () => { await fetch("/api/auth/logout", {method: "POST"}).catch(() => {}); location.replace("/login?logout=1"); };

  A.ready = (async () => {
    const r = await fetch("/api/auth/me");
    if (r.status === 401 || r.status === 403) return null;
    const cfg = await (await fetch("/api/auth/config")).json().catch(() => ({enabled: true}));
    A.me = {...(await r.json()), auth: cfg.enabled !== false};
    idleMs = (A.me.idle_minutes || 10) * 60000;
    document.body.dataset.role = A.me.role;
    document.querySelectorAll("[data-perm]").forEach(el => { el.hidden = !A.can(el.dataset.perm); });
    const u = $("#user-name"); if (u) u.textContent = A.me.display || A.me.user;
    const rl = $("#user-role"); if (rl) rl.textContent = A.me.role_label || A.me.role;
    try {
      if (A.me.auth && !A.me.kiosk && !sessionStorage.getItem("aiops_greet") && !new URLSearchParams(location.search).get("view")) {   // 새 창(2.17)에서는 인사 생략
        sessionStorage.setItem("aiops_greet", "1");
        if (A.me.prev_login) A.toast((window.AIOPS_I18N || {}).lang === "en" ? `Welcome, ${A.me.display || A.me.user}` : `${A.me.display || A.me.user}님, 환영합니다`, `직전 로그인 ${new Date(A.me.prev_login * 1000).toLocaleString()} · ${A.me.prev_ip || "-"}\n본인이 아니면 즉시 비밀번호를 변경하고 관리자에게 알리세요.`, "info", 8000);
      }
    } catch { /* 저장소 차단 환경 */ }
    return A.me;
  })();
})();
