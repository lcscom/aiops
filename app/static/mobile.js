/* 모바일 앱(2.30.0) — 안드로이드 앱 내려받기·기기 연결·알림 설정 + 좁은 화면 메뉴(≤760px)·앱 안 동작
   · 앱(WebView)은 User-Agent 에 VCFAIopsApp/ 를 붙이고 window.AIOPSApp(info·pair·openSettings·installUpdate·checkNow·saveFile)을 준다
   · 앱이 부르는 것: window.AIOPS_MOBILE.load()(연결 직후 화면 갱신) · .back()(뒤로 — 열린 메뉴·창·화면을 닫으면 true)
   · 알림을 누르면 /#go=<메뉴> 로 들어온다
   navgroup.js 보다 먼저 로드 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const APP = () => (A.inApp && window.AIOPSApp) || null;
  const root = document.documentElement;
  if (A.inApp) root.classList.add("is-app");
  const POP = new URLSearchParams(location.search).has("view");
  const st = {d: null, qr: null};
  const SEVL = {info: "정보 이상", warning: "주의 이상", error: "오류 이상", critical: "심각만"};
  const dt = t => t ? new Date(t * 1000).toLocaleString() : "—";
  const ago = t => { if (!t) return "아직 없음"; const m = (Date.now() / 1000 - t) / 60; return m < 2 ? "방금" : m < 90 ? `${Math.round(m)}분 전` : m < 2880 ? `${Math.round(m / 60)}시간 전` : `${Math.round(m / 1440)}일 전`; };
  const kb = n => n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
  const fp = h => String(h || "").toUpperCase().replace(/(.{2})(?=.)/g, "$1:");
  const appInfo = () => { try { return JSON.parse(APP().info() || "{}"); } catch { return {}; } };

  // ------------------------------------------------------------ 좁은 화면 메뉴(햄버거)
  const navOpen = on => { root.classList.toggle("nav-open", on); const b = $("#btn-menu"); if (b) b.setAttribute("aria-expanded", on ? "true" : "false"); };
  function shell() {
    const hdr = $(".hdr"); if (!hdr || POP || $("#btn-menu")) return;
    const b = document.createElement("button");
    b.id = "btn-menu"; b.type = "button"; b.className = "hdr-btn"; b.setAttribute("aria-label", "메뉴"); b.setAttribute("aria-expanded", "false");
    b.innerHTML = `<svg viewBox="0 0 36 36" aria-hidden="true"><path d="M5 8h26v3.4H5Zm0 8.3h26v3.4H5Zm0 8.3h26V28H5Z" fill="currentColor"/></svg>`;
    hdr.prepend(b);
    b.onclick = () => navOpen(!root.classList.contains("nav-open"));
    const shade = document.createElement("div"); shade.id = "nav-shade"; shade.onclick = () => navOpen(false); document.body.append(shade);
    document.addEventListener("click", e => {
      const a = e.target.closest(".vnav a"); if (!a || !root.classList.contains("nav-open")) return;
      setTimeout(() => navOpen(false), 0);
    });
    document.addEventListener("keydown", e => { if (e.key === "Escape") navOpen(false); });
    // 좁은 화면에서 머리글에 없는 기능(AI 질의·AI 분석 상태)을 메뉴 맨 아래에
    const nav = $(".vnav");
    if (nav && !$("#nav-m-extra")) {
      const x = document.createElement("div"); x.id = "nav-m-extra";
      x.innerHTML = `<button type="button" data-mx="chat">AI 질의</button><button type="button" data-mx="ai">AI 분석 상태·켜기/끄기</button>`;
      nav.append(x);
      x.onclick = e => { const k = e.target.dataset.mx; if (!k) return; navOpen(false); const t = k === "chat" ? $("#btn-chat") : $("#k-llm"); if (t) t.click(); };
    }
  }

  // ------------------------------------------------------------ 뒤로(앱)·알림 바로 가기
  function back() {
    if (root.classList.contains("nav-open")) { navOpen(false); return true; }
    const mx = $(".modal [data-x], .modal-box [data-x]"); if (mx && mx.offsetParent !== null) { mx.click(); return true; }
    const pop = $("#user-pop"); if (pop && !pop.hidden) { pop.hidden = true; return true; }
    const d = $$(".drawer").filter(x => !x.hidden).pop();
    const phone = A.inApp || matchMedia("(max-width:900px)").matches;
    if (d && d.id === "drawer-mhome" && phone) return false;          // 첫 화면 — 앱이 뒤로(배경으로) 보냄
    if (phone && $("#nav-mhome") && !$("#nav-mhome").hidden) { homeOpen(); return true; }   // 다른 화면(대시보드 포함) → 첫 화면으로
    if (d) { const x = d.querySelector("[data-close]"); if (x) x.click(); else d.hidden = true; return true; }
    return false;
  }
  function go() {
    const m = /^#go=([A-Za-z0-9_-]{1,40})/.exec(location.hash); if (!m) return;
    try { history.replaceState(null, "", location.pathname + location.search); } catch { /* 무시 */ }
    const a = $(`.vnav a[data-nav="${m[1]}"]`);
    if (m[1] === "dash" || !a || a.hidden) { $$(".drawer").forEach(d => { d.hidden = true; }); return; }
    a.click();
  }

  // ------------------------------------------------------------ 한눈에 보기(폰 첫 화면, 2.31.0)
  const hs = {d: null, tm: 0, seq: 0};
  const SEVK = {critical: "심각", error: "오류", warning: "주의", info: "정보"};
  const KINDK = {update: "업데이트", alert: "이상 징후", dr: "DR·백업", perf: "성능", system: "시스템", test: "시험"};
  const openNav = k => { const a = $(`.vnav a[data-nav="${k}"]`); if (a && !a.hidden) a.click(); };
  async function homeLoad() {
    const body = $("#mhome-body"); if (!body) return;
    const my = ++hs.seq;
    try { const d = await A.api("GET", "/api/mobile/summary", undefined, {background: true}); if (my !== hs.seq) return; hs.d = d; hs.err = ""; }
    catch (e) { if (my !== hs.seq) return; hs.err = String(e.message || e); }
    homeRender();
  }
  function homeRender() {
    const body = $("#mhome-body"); if (!body) return;
    const d = hs.d;
    if (!d) { body.innerHTML = `<div class="empty">${esc(hs.err || "불러오는 중…")}</div>`; return; }
    const tile = (go, v, title, big, sub) => `<button type="button" class="mh-tile ${v}" data-mgo="${go}"><small>${title}</small><b>${big}</b><span>${sub}</span></button>`;
    const i = d.incidents, a = d.anomalies, c = d.connectors, r = d.dr, p = d.platform;
    const an = a.critical + a.error;
    const drBad = r ? r.plans_bad + r.app_bad + r.snap_bad : 0;
    const ai = APP() ? appInfo() : null;
    const appRow = ai ? `<div class="mh-app ${ai.paired && ai.notify ? "" : "warn"}">
        ${!ai.paired ? `<span>이 기기는 아직 알림을 받지 않습니다.</span><button class="btn-sm solid" data-mgo="mobile">기기 연결</button>`
          : !ai.notify ? `<span>알림 권한이 꺼져 있습니다.</span><button class="btn-sm" data-mapp="set">앱 설정</button>`
          : `<span>알림 ${ai.live ? "실시간" : "주기 확인"} · 앱 잠금 ${ai.lock ? "켬" : "끔"}${ai.update ? " · <b>앱 새 버전 있음</b>" : ""}</span><button class="btn-sm" data-mapp="set">앱 설정</button>`}</div>` : "";
    const row = (go, sev, title, sub, t) => `<button type="button" class="mh-row" data-mgo="${go}"><i class="mh-dot ${sev}"></i><span><b>${esc(title)}</b><small>${esc(sub)}</small></span><time>${ago(t)}</time></button>`;
    body.innerHTML = `<div class="mh-wrap">${hs.err ? `<div class="mb-note warn">새 값을 받지 못했습니다 — ${esc(hs.err)} (아래는 ${ago(d.ts)} 값)</div>` : ""}${appRow}
      <div class="mh-tiles">
        ${tile("inc", i.critical ? "bad" : i.active ? "warn" : "ok", "진행 중 인시던트", i.active, i.critical ? `심각 ${i.critical}건` : i.active ? "심각 없음" : "없음")}
        ${tile("dash", a.critical ? "bad" : an ? "warn" : "ok", "미확인 이상 징후(24시간)", an, `심각 ${a.critical} · 오류 ${a.error} · 주의 ${a.warning}`)}
        ${tile("dr", !r ? "none" : r.plans_bad || r.app_bad ? "bad" : drBad || r.app_warn ? "warn" : "ok", "DR·백업", !r ? "—" : drBad ? `문제 ${drBad}` : "정상",
          !r ? "정보 없음" : `Appliance 백업 ${r.app_total - r.app_bad - r.app_warn}/${r.app_total}${r.srm ? ` · 복구 계획 ${r.plans}` : ""} · 오래된 스냅숏 ${r.snap_bad}`)}
        ${tile("coll", c.bad ? "bad" : "ok", "수집 연결", `${c.total - c.bad}/${c.total}`, c.bad ? `끊김: ${esc(c.names.join(", "))}` : "모두 연결됨")}
        ${tile("plat", p.ok ? "ok" : "bad", "플랫폼", p.ok ? "정상" : "점검 필요", p.ok ? `서버 ${esc(d.server)}` : esc((p.reasons || []).join(" · ")))}
        ${d.life ? tile("life", d.life.expired ? "bad" : d.life.crit ? "bad" : d.life.warn || d.life.drift7 ? "warn" : d.life.scanned ? "ok" : "none", "인증서·구성 변경",
          !d.life.scanned ? "—" : d.life.expired + d.life.crit ? `${d.life.expired + d.life.crit}개 임박` : d.life.warn ? `주의 ${d.life.warn}` : "정상",
          `${d.life.expired ? `만료 ${d.life.expired} · ` : ""}${(d.life.top || []).map(x => `${esc(x.kind)} ${x.days_left == null ? "" : x.days_left < 0 ? "만료" : x.days_left + "일"}`).slice(0, 2).join(" · ") || "임박한 인증서 없음"} · 구성 변경 7일 ${d.life.drift7}`) : ""}
        ${d.bot ? tile("bot", d.bot.new_fail ? "bad" : d.bot.fail ? "warn" : "ok", "AI 체크봇(what-if)", d.bot.fail ? `실패 ${d.bot.fail}` : "통과",
          `시나리오 ${d.bot.scenarios}${d.bot.new_fail ? ` · 새 실패 ${d.bot.new_fail}` : ""}${(d.bot.top || []).length ? ` · ${d.bot.top.map(x => `${esc(x.kind)} ${esc(x.target)}`).join(" · ")}` : ""}`) : ""}
      </div>
      ${i.top.length ? `<h4>진행 중 인시던트</h4><div class="mh-list">${i.top.map(x => row("inc", x.severity, x.title, `${SEVK[x.severity] || x.severity} · ${x.status_label || ""}`, x.updated)).join("")}</div>` : ""}
      ${a.top.length ? `<h4>미확인 이상 징후</h4><div class="mh-list">${a.top.map(x => row("dash", x.severity, x.title, `${SEVK[x.severity] || x.severity}${x.target ? ` · ${x.target}` : ""}${x.count > 1 ? ` · ${x.count}회` : ""}`, x.last_seen)).join("")}</div>` : ""}
      <h4>최근 알림 <small>7일</small></h4>
      ${d.notices.length ? `<div class="mh-list">${d.notices.map(n => row(n.view || "", n.kind === "update" ? "upd" : n.sev, n.title, `${KINDK[n.kind] || n.kind}${n.body ? ` · ${n.body.split("\n")[0]}` : ""}`, n.ts)).join("")}</div>` : `<div class="empty small">최근 알림이 없습니다.</div>`}
      <p class="small muted">갱신 ${new Date(d.ts * 1000).toLocaleTimeString()} · 30초마다 자동</p></div>`;
  }
  function homeOpen() {
    $$(".drawer").forEach(x => { if (x.id !== "drawer-mhome") x.hidden = true; });
    $("#drawer-mhome").hidden = false; homeRender(); homeLoad();
  }
  function homeWire() {
    $("#nav-mhome").onclick = homeOpen;
    $("#mhome-reload").onclick = homeLoad;
    $("#mhome-body").addEventListener("click", e => {
      const ap = e.target.closest("[data-mapp]"); if (ap && APP()) { APP().openSettings(); return; }
      const t = e.target.closest("[data-mgo]"); if (!t) return;
      const k = t.dataset.mgo; if (!k) return;
      if (k === "dash") { $$(".drawer").forEach(x => { x.hidden = true; }); return; }
      openNav(k);
    });
    hs.tm = setInterval(() => { if (!$("#drawer-mhome").hidden && document.visibilityState === "visible") homeLoad(); }, 30000);
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && !$("#drawer-mhome").hidden) homeLoad(); });
  }

  // ------------------------------------------------------------ 화면
  async function load() {
    const body = $("#mobile-body"); if (!body) return;
    try { st.d = await A.api("GET", "/api/mobile/info", undefined, {background: true}); }
    catch (e) { body.innerHTML = `<div class="empty">${esc(e.message || e)}</div>`; return; }
    render();
  }

  function appCard() {
    const m = st.d.app, ai = APP() ? appInfo() : null;
    if (!m) return `<div class="mb-card"><h4>안드로이드 앱</h4><div class="empty">이 설치본에는 앱 파일이 없습니다. 2.30.0 이상 패치에 앱(APK)이 함께 들어 있습니다.</div></div>`;
    let state = "";
    if (ai) {
      state = ai.code < m.code
        ? `<div class="mb-note warn"><b>앱 새 버전 ${esc(m.name)}</b> — 지금 쓰는 앱은 ${esc(ai.app || "")}입니다. <button class="btn-sm solid" id="mb-upd">앱 업데이트</button></div>`
        : `<div class="mb-note ok">이 앱은 최신입니다(${esc(ai.app || m.name)}).</div>`;
    }
    return `<div class="mb-card"><h4>안드로이드 앱 <small>서버 패치에 함께 들어 있는 앱 — 서버를 패치하면 앱도 새 버전을 알려 줍니다</small></h4>
      ${state}
      <div class="mb-app">
        <div class="mb-meta"><dl>
          <dt>버전</dt><dd><b>${esc(m.name)}</b> <span class="muted">(코드 ${m.code}) · 서버 ${esc(st.d.server)}</span></dd>
          <dt>크기</dt><dd>${kb(m.size)} · Android ${esc(m.min_android)} 이상</dd>
          <dt>파일 SHA-256</dt><dd class="mono mb-hash">${esc(m.sha256)}</dd>
          <dt>서명 인증서 SHA-256</dt><dd class="mono mb-hash">${esc(fp(m.cert_sha256))}</dd>
          <dt>만든 날</dt><dd>${esc(m.built)}</dd></dl>
          ${ai ? "" : `<p><a class="btn-sm solid" href="/api/mobile/app.apk" download>APK 내려받기</a></p>`}
        </div>
        ${ai ? "" : `<div class="mb-qr" id="mb-iqr"><div class="mb-qrbox">${st.qr || ""}</div><small>폰 카메라로 찍으면 이 화면이 폰에서 열립니다 — 로그인 후 'APK 내려받기'</small></div>`}
      </div>
      ${ai ? "" : `<details class="mb-help"><summary>설치 방법</summary><ol>
        <li>폰에서 이 포털에 로그인해 <b>APK 내려받기</b>를 누릅니다(위 QR 또는 PC 에서 받아 폰으로 옮겨도 됩니다).</li>
        <li>받은 파일을 열면 Android 가 '출처를 알 수 없는 앱' 설치 허용을 묻습니다 — 브라우저(또는 파일 앱)에 한 번 허용합니다.</li>
        <li>아래 <b>기기 연결</b>의 QR 을 폰 카메라로 찍거나, 앱을 열어 포털 주소를 직접 넣고 로그인합니다.</li>
        <li>알림 허용을 물으면 '허용' — 배터리 최적화에서 이 앱을 '제한 없음'으로 두면 알림이 덜 늦습니다.</li></ol>
        <p class="small muted">Play 스토어를 거치지 않는 사내 배포입니다. 설치 전 파일 SHA-256 이 위 값과 같은지 확인할 수 있습니다. 서명 인증서 지문이 바뀐 APK 는 기존 앱 위에 설치되지 않습니다.</p></details>`}
    </div>`;
  }

  function pairCard() {
    const s = st.d.settings, ai = APP() ? appInfo() : null;
    if (!s.enabled) return `<div class="mb-card"><h4>기기 연결</h4><div class="empty">모바일 앱 사용이 꺼져 있습니다${st.d.admin ? " — 아래 설정에서 켜세요." : "(관리자에게 문의)."}</div></div>`;
    const how = ai
      ? (ai.paired
        ? `<div class="mb-note ok">이 기기는 연결되어 있습니다 · 마지막 확인 ${ago((ai.last_ok || 0) / 1000)}${ai.notify ? "" : ` · <b class="bad">알림 권한이 꺼져 있습니다</b>`}</div>
           <p class="small">알림 받기: <b>${ai.live ? "실시간(연결 유지)" : "주기 확인"}</b> · 앱 잠금: <b>${ai.lock ? "켬" : "끔"}</b> · 토큰 보관: ${ai.secure_store ? "기기 보안 저장소 암호화" : "일반 저장"} — 실시간 알림과 앱 잠금은 <b>앱 설정</b>에서 켭니다.</p>
           <p><button class="btn-sm" id="mb-check">지금 확인</button> <button class="btn-sm" id="mb-appset">앱 설정</button> <button class="btn-sm" id="mb-pair">다시 연결</button></p>`
        : `<p>이 기기를 연결하면 포털을 열지 않아도 서버 업데이트·이상 징후 알림을 받습니다.</p><p><button class="btn-sm solid" id="mb-pair">이 기기 연결</button> <button class="btn-sm" id="mb-appset">앱 설정</button></p>`)
      : `<p>앱을 설치한 뒤 <b>연결 QR</b>을 폰 기본 카메라로 찍으면 앱이 열리면서 주소 입력과 기기 연결이 한 번에 됩니다. QR 은 10분 동안 한 번만 쓸 수 있습니다.</p>
         <p><button class="btn-sm solid" id="mb-pairqr">연결 QR 만들기</button></p><div id="mb-pairout"></div>`;
    return `<div class="mb-card"><h4>기기 연결 <small>알림을 받을 기기 — 사용자당 ${s.max_devices_per_user}대까지</small></h4>${how}
      <p class="small muted">앱은 ${s.poll_minutes}분마다(안드로이드 절전 상태에 따라 더 늦을 수 있음) 서버에 새 알림을 물어봅니다. 외부 푸시 서비스(FCM 등)를 쓰지 않으므로 알림 내용이 사내 밖으로 나가지 않습니다.</p></div>`;
  }

  function devCard() {
    const L = st.d.devices, K = st.d.kinds, s = st.d.settings, adm = st.d.admin;
    const row = d => {
      const p = d.prefs || {}, kinds = p.kinds || s.kinds, sev = p.min_sev || s.min_sev;
      return `<tr data-did="${d.id}"><td><b>${esc(d.name || "이름 없음")}</b><div class="small muted">${esc(d.os || "")} · 앱 ${d.app_code || "—"}${adm ? ` · ${esc(d.user)}` : ""}</div></td>
        <td class="small">${ago(d.last_seen)}<div class="muted">${esc(d.last_ip || "")}</div></td>
        <td class="mb-kinds">${Object.entries(K).map(([k, n]) => `<label><input type="checkbox" data-mk="${k}" ${kinds.includes(k) ? "checked" : ""}> ${esc(n)}</label>`).join("")}</td>
        <td><select data-msev>${Object.entries(SEVL).map(([k, n]) => `<option value="${k}" ${k === sev ? "selected" : ""}>${n}</option>`).join("")}</select></td>
        <td class="r"><button class="btn-sm danger" data-mrev>연결 해제</button></td></tr>`;
    };
    return `<div class="mb-card"><h4>${adm ? "연결된 기기(전체 사용자)" : "내 기기"} <small>${L.length}대</small>
        ${L.some(d => d.mine) ? `<button class="btn-sm" id="mb-test">시험 알림 보내기</button>` : ""}</h4>
      ${L.length ? `<table class="dr-t mb-t"><thead><tr><th>기기</th><th>마지막 확인</th><th>받을 알림</th><th>심각도</th><th></th></tr></thead><tbody>${L.map(row).join("")}</tbody></table>
        <p class="small muted">'서버 업데이트'와 시험 알림은 심각도와 상관없이 옵니다. 폰을 잃어버렸으면 바로 '연결 해제' 하세요 — 그 기기의 토큰이 즉시 무효가 됩니다.</p>`
        : `<div class="empty">연결된 기기가 없습니다.</div>`}</div>`;
  }

  function setCard() {
    if (!st.d.admin) return "";
    const s = st.d.settings, K = st.d.kinds, ac = st.d.access || {};
    return `<div class="mb-card"><h4>설정 <small>관리자</small></h4><form id="mb-set" class="mb-form">
      <label class="mb-chk"><input type="checkbox" name="enabled" ${s.enabled ? "checked" : ""}> 모바일 앱 사용(끄면 새 연결과 알림 확인을 모두 거부)</label>
      <label>확인 주기(분) <input type="number" name="poll_minutes" min="15" max="720" value="${s.poll_minutes}"> <small class="muted">15~720 · 안드로이드 최소 15분</small></label>
      <label>사용자당 기기 수 <input type="number" name="max_devices_per_user" min="1" max="20" value="${s.max_devices_per_user}"></label>
      <fieldset><legend>기본으로 보낼 알림</legend>${Object.entries(K).map(([k, n]) => `<label class="mb-chk"><input type="checkbox" name="kind" value="${k}" ${s.kinds.includes(k) ? "checked" : ""}> ${esc(n)}</label>`).join("")}</fieldset>
      <label>기본 최소 심각도 <select name="min_sev">${Object.entries(SEVL).map(([k, n]) => `<option value="${k}" ${k === s.min_sev ? "selected" : ""}>${n}</option>`).join("")}</select></label>
      <label class="mb-chk"><input type="checkbox" name="allow_without_access" ${s.allow_without_access ? "checked" : ""}> 외부 주소에서 Cloudflare Access 없이 앱 알림 확인 허용</label>
      <p class="small muted">외부 공개(Cloudflare Access ${ac.enabled ? (ac.enforce ? "강제 중" : "켜짐·강제 아님") : "꺼짐"}) 환경에서 앱은 로그인할 때 받은 Access 세션으로 알림을 확인합니다. Access 세션이 만료되면 앱을 열어 다시 로그인할 때까지 알림이 멈춥니다.
        위 항목을 켜면 <b>기기 연결·알림 확인·앱 내려받기 3개 주소만</b> Access 검사 없이 기기 토큰으로 통과시킵니다(포털 화면과 다른 API 는 그대로 Access 필요). 사내망·VPN 으로만 쓰면 켤 필요가 없습니다.</p>
      <p><button class="btn-sm solid" type="submit">저장</button></p></form></div>`;
  }

  function render() {
    const body = $("#mobile-body"); if (!body || !st.d) return;
    const keep = body.scrollTop;
    body.innerHTML = `<div class="mb-wrap">${appCard()}${pairCard()}${devCard()}${setCard()}</div>`;
    body.scrollTop = keep;
    if (!APP() && st.d.app && st.qr === null) {
      st.qr = "";
      A.api("GET", `/api/mobile/install-qr?origin=${encodeURIComponent(location.origin)}`, undefined, {background: true})
        .then(r => { st.qr = r.qr_svg || ""; const b = $(".mb-qrbox"); if (b) b.innerHTML = st.qr; if (!st.qr) { const q = $("#mb-iqr"); if (q) q.hidden = true; } })
        .catch(() => { const q = $("#mb-iqr"); if (q) q.hidden = true; });
    }
  }

  async function pairStart() {
    return A.api("POST", "/api/mobile/pair/start", {origin: location.origin});
  }

  function wire() {
    const body = $("#mobile-body");
    body.addEventListener("click", async ev => {
      const t = ev.target, id = t.id;
      try {
        if (id === "mb-upd") { APP().installUpdate(); return; }
        if (id === "mb-check") { APP().checkNow(); setTimeout(load, 4000); return; }
        if (id === "mb-appset") { APP().openSettings(); return; }
        if (id === "mb-pair") { t.disabled = true; const r = await pairStart(); APP().pair(r.code); setTimeout(load, 5000); return; }
        if (id === "mb-pairqr") {
          t.disabled = true;
          const r = await pairStart(), out = $("#mb-pairout");
          out.innerHTML = `<div class="mb-qr big"><div class="mb-qrbox">${r.qr_svg || ""}</div>
            <small>${new Date(r.expires * 1000).toLocaleTimeString()} 까지 · 한 번만 사용 · 이 QR 을 다른 사람에게 보여 주지 마세요(내 계정으로 연결됩니다)</small>
            ${r.qr_svg ? "" : `<p class="small">QR 을 만들 수 없습니다 — 폰에서 이 화면을 열어 아래 버튼을 누르세요.</p>`}
            <p><a class="btn-sm" href="${esc(r.link)}">이 폰의 앱에서 열기</a></p></div>`;
          t.disabled = false; t.textContent = "새 QR 만들기";
          return;
        }
        if (id === "mb-test") { const r = await A.api("POST", "/api/mobile/test"); A.ok("시험 알림을 보냈습니다", `기기 ${r.devices}대 · 최대 ${r.poll_minutes}분 안에 도착(앱의 '지금 확인'을 누르면 바로)`); return; }
        if (t.dataset.mrev !== undefined) {
          const tr = t.closest("[data-did]");
          if (!await A.confirm("기기 연결 해제", "이 기기의 알림 토큰을 무효로 만듭니다. 다시 받으려면 기기를 새로 연결해야 합니다.", true)) return;
          await A.api("DELETE", `/api/mobile/devices/${tr.dataset.did}`); A.ok("연결을 해제했습니다"); load();
        }
      } catch (e) { A.fail("실패", e); t.disabled = false; }
    });
    body.addEventListener("change", async ev => {
      const tr = ev.target.closest("[data-did]"); if (!tr) return;
      const kinds = $$("[data-mk]", tr).filter(c => c.checked).map(c => c.dataset.mk);
      try { await A.api("PUT", `/api/mobile/devices/${tr.dataset.did}`, {kinds, min_sev: $("[data-msev]", tr).value}); A.ok("저장했습니다"); }
      catch (e) { A.fail("저장 실패", e); load(); }
    });
    body.addEventListener("submit", async ev => {
      if (ev.target.id !== "mb-set") return;
      ev.preventDefault();
      const f = ev.target, on = n => f.elements[n].checked;
      if (on("allow_without_access") && !st.d.settings.allow_without_access &&
          !await A.confirm("Access 없이 허용", "외부 주소에서 기기 연결·알림 확인·앱 내려받기 주소가 Cloudflare Access 검사 없이 열립니다(기기 토큰·일회용 코드·로그인 세션은 그대로 필요). 계속할까요?", true)) return;
      try {
        await A.api("PUT", "/api/mobile/settings", {enabled: on("enabled"), poll_minutes: +f.elements.poll_minutes.value, max_devices_per_user: +f.elements.max_devices_per_user.value,
          kinds: $$('input[name="kind"]', f).filter(c => c.checked).map(c => c.value), min_sev: f.elements.min_sev.value, allow_without_access: on("allow_without_access")});
        A.ok("저장했습니다"); load();
      } catch (e) { A.fail("저장 실패", e); }
    });
    $("#mobile-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    shell();
    if ($("#nav-mobile")) {
      wire();
      $("#nav-mobile").onclick = () => { $$(".drawer").forEach(d => { if (d.id !== "drawer-mobile") d.hidden = true; }); $("#drawer-mobile").hidden = false; load(); };
    }
    if ($("#nav-mhome")) homeWire();
    Promise.resolve(A.ready).then(me => setTimeout(() => {
      if (/^#go=/.test(location.hash)) { go(); return; }
      // 폰·앱에서는 첫 화면을 '한눈에 보기'로(PC 는 기존 대시보드 그대로)
      if (me !== null && !POP && $("#nav-mhome") && (A.inApp || matchMedia("(max-width:900px)").matches) && !$$(".drawer").some(d => !d.hidden)) homeOpen();
    }, 0));
    addEventListener("hashchange", go);
  });
  window.AIOPS_MOBILE = {load: () => { if ($("#drawer-mobile") && !$("#drawer-mobile").hidden) load(); if ($("#drawer-mhome") && !$("#drawer-mhome").hidden) homeRender(); }, back};
})();
