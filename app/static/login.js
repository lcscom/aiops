(() => {
  "use strict";
  const $ = s => document.querySelector(s);
  const qs = new URLSearchParams(location.search);
  const H = {"Content-Type": "application/json", "X-Requested-With": "aiops"};
  let user = "", lastPw = "", mfaTok = "";

  const msg = (text, kind = "error") => { const m = $("#msg"); m.hidden = !text; m.className = `login-msg ${kind}`; m.textContent = text || ""; };
  const next = () => {   // 같은 출처의 경로만(2.30.0 — "/\\evil.com"·"//evil.com"·제어문자 차단)
    const n = qs.get("next") || "/";
    if (!n.startsWith("/") || n.startsWith("//") || /[\\\u0000-\u001f]/.test(n)) return "/";
    try { return new URL(n, location.origin).origin === location.origin ? n : "/"; } catch { return "/"; }
  };

  if (qs.get("expired")) msg("세션이 만료되어 로그아웃되었습니다. 다시 로그인하세요.", "info");
  if (qs.get("logout")) msg("로그아웃되었습니다.", "info");

  fetch("/api/auth/config").then(r => r.json()).then(c => {
    if (!c.enabled) { location.replace("/"); return; }
    if (c.banner) { const b = $("#banner"); b.hidden = false; b.textContent = c.banner; const f = document.querySelector(".login-foot"); if (f) f.hidden = true; }   // 고지문 한 번만
    if (c.oidc) { const b = $("#b-sso"); b.hidden = false; b.textContent = `${c.oidc_name || "SSO"} 로그인`; b.onclick = () => { location.href = `/api/auth/oidc/start?next=${encodeURIComponent(next())}`; }; }
    if (c.ldap) { const h = $("#ldap-hint"); h.hidden = false; h.textContent = `AD 계정으로 로그인할 수 있습니다${c.ldap_domain ? ` (예: 홍길동 또는 ${c.ldap_domain}\\홍길동)` : ""}. 비상용 로컬 관리자도 사용 가능합니다.`; }
  }).catch(() => {});

  // SSO 뒤 2단계 인증이 필요해 넘어온 경우(?mfa=1) — 2.48.2 토큰은 URL이 아닌 HttpOnly 쿠키로 서버가 보관
  if (qs.get("mfa") === "1") { mfaTok = ""; showMfa(); history.replaceState(null, "", location.pathname + (qs.get("next") ? "?next=" + encodeURIComponent(qs.get("next")) : "")); }

  // 이미 로그인된 상태에서 비밀번호 변경이 필요해 넘어온 경우
  if (qs.get("change")) {
    fetch("/api/auth/me").then(r => r.ok ? r.json() : null).then(me => {
      if (me) { user = me.user; showChange(true); }
    });
  }

  $("#p").addEventListener("keyup", e => { $("#caps").hidden = !(e.getModifierState && e.getModifierState("CapsLock")); });

  $("#f-login").onsubmit = async e => {
    e.preventDefault();
    const u = $("#u").value.trim(), p = $("#p").value;
    if (!u || !p) { msg("아이디와 비밀번호를 입력하세요."); return; }
    $("#b-login").disabled = true; $("#b-login").textContent = "확인 중…"; msg("");
    try {
      const r = await fetch("/api/auth/login", {method: "POST", headers: H, body: JSON.stringify({username: u, password: p})});
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { msg(j.detail || `로그인 실패 (${r.status})`); $("#p").value = ""; $("#p").focus(); return; }
      user = j.user; lastPw = p;
      if (j.mfa_required) { mfaTok = j.mfa_token; showMfa(); return; }
      if (j.must_change) { showChange(false); return; }
      location.replace(next());
    } catch (err) { msg("서버에 연결할 수 없습니다."); }
    finally { $("#b-login").disabled = false; $("#b-login").textContent = "로그인"; }
  };

  function showMfa() {
    $("#f-login").hidden = true; $("#f-change").hidden = true; $("#f-mfa").hidden = false; msg("");
    $("#mfa-code").value = ""; $("#mfa-code").focus();
  }
  $("#f-mfa").onsubmit = async e => {
    e.preventDefault();
    const code = $("#mfa-code").value.trim();
    if (!code) { msg("인증 코드를 입력하세요."); return; }
    $("#b-mfa").disabled = true; msg("");
    try {
      const r = await fetch("/api/auth/mfa/verify", {method: "POST", headers: H, body: JSON.stringify({mfa_token: mfaTok, code})});
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { msg(j.detail || `인증 실패 (${r.status})`); $("#mfa-code").value = ""; $("#mfa-code").focus(); if (r.status === 401 && /처음부터/.test(j.detail || "")) setTimeout(() => location.replace("/login"), 1500); return; }
      if (j.recovery_used) msg("복구 코드를 사용했습니다. 남은 복구 코드를 확인하고 필요하면 MFA 를 다시 등록하세요.", "info");
      if (j.must_change) { showChange(!lastPw); return; }
      location.replace(next());
    } catch (err) { msg("서버에 연결할 수 없습니다."); }
    finally { $("#b-mfa").disabled = false; }
  };

  function showChange(needOld) {
    $("#f-login").hidden = true; $("#f-mfa").hidden = true; $("#f-change").hidden = false;
    $("#old-wrap").hidden = !needOld;
    if (!needOld) $("#old").value = lastPw;
    msg("");
    (needOld ? $("#old") : $("#n1")).focus();
  }

  function rules(pw, pw2) {
    const cls = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(pw)).length;
    let seq = false;
    const low = pw.toLowerCase();
    for (let i = 0; i + 3 < low.length; i++) {
      const c = [...low.slice(i, i + 4)].map(x => x.charCodeAt(0));
      if (c.every((v, k) => k === 0 || v - c[k - 1] === 1) || c.every((v, k) => k === 0 || c[k - 1] - v === 1)) { seq = true; break; }
    }
    return {len: pw.length >= 9, cls: cls >= 3, user: !user || !low.includes(user.toLowerCase()),
            rep: !/(.)\1\1/.test(pw) && !seq, eq: !!pw && pw === pw2};
  }
  const paint = () => {
    const r = rules($("#n1").value, $("#n2").value);
    document.querySelectorAll("#policy li").forEach(li => li.classList.toggle("ok", !!r[li.dataset.r]));
    return Object.values(r).every(Boolean);
  };
  $("#n1").oninput = paint; $("#n2").oninput = paint;

  $("#f-change").onsubmit = async e => {
    e.preventDefault();
    if (!paint()) { msg("비밀번호 정책을 확인하세요."); return; }
    $("#b-change").disabled = true;
    try {
      const r = await fetch("/api/auth/password", {method: "POST", headers: H, body: JSON.stringify({old: $("#old").value, new: $("#n1").value})});
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { msg(j.detail || `변경 실패 (${r.status})`); return; }
      lastPw = ""; $("#old").value = ""; msg("비밀번호가 변경되었습니다.", "ok");
      setTimeout(() => location.replace(next()), 600);
    } finally { $("#b-change").disabled = false; }
  };
})();
