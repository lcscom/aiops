/* 수집 일시정지 스위치(2.22.1) — 플랫폼 상태 화면 위 제어판 + 멈춘 동안 모든 화면 상단 띠 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const st = {d: null, seq: 0, t: null, busy: false};
  const mmss = s => s == null ? "직접 재개할 때까지" : s >= 3600 ? `${Math.floor(s / 3600)}시간 ${Math.round(s % 3600 / 60)}분 남음` : `${Math.floor(s / 60)}분 ${s % 60}초 남음`;
  const dt = ts => ts ? new Date(ts * 1000).toLocaleString([], {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "-";
  const SC = {all: "전체 수집(플랫폼 자체 이벤트 제외)", syslog: "syslog 수신 전체", senders: "지정한 송신자만"};
  const ASC = {top_sender: "가장 많이 보내는 송신자만", syslog: "syslog 수신 전체", all: "전체 수집"};

  async function load(bg = true) {
    const my = ++st.seq;
    let d = null;
    try { d = await A.api("GET", "/api/ingest-gate", undefined, {background: bg}); } catch (e) { if (!bg) A.fail("수집 상태를 불러오지 못했습니다", e); return; }
    if (my !== st.seq) return;
    st.d = d; banner();
    const box = $("#ig-box"), ae = document.activeElement;
    if (!(box && ae && box.contains(ae) && /^(INPUT|SELECT|TEXTAREA)$/.test(ae.tagName))) render();      // 입력 중에는 다시 그리지 않음
  }

  function banner() {
    let b = $("#ig-banner");
    const d = st.d;
    if (!d || !d.paused) { if (b) b.remove(); return; }
    if (!b) { b = document.createElement("div"); b.id = "ig-banner"; b.setAttribute("role", "status"); document.body.prepend(b); }
    b.innerHTML = `<b>수집 일시정지 중</b> — ${esc(d.scope_text)} · ${esc(mmss(d.left_s))} · 버린 로그 ${(d.dropped || 0).toLocaleString()}건${d.by === "auto" ? " · 자동" : ""}
      <button type="button" class="btn-sm" id="ig-open">자세히</button>${A.can("settings") ? `<button type="button" class="btn-sm solid" id="ig-resume-b">지금 재개</button>` : ""}`;
  }

  function render() {
    const box = $("#ig-box"); if (!box || box.closest(".drawer")?.hidden) return;
    const d = st.d; if (!d) { box.innerHTML = `<div class="empty">수집 상태를 읽는 중…</div>`; return; }
    const can = A.can("settings"), c = d.check || {}, a = d.auto || {};
    const top = c.top || [];
    box.innerHTML = `
      <section class="ig ${d.paused ? "paused" : ""}">
        <div class="ig-head">
          <h4>수집 일시정지 <small>로그 폭주로 느려질 때 수집을 멈춤 — 멈춘 동안 들어온 로그는 저장·분석하지 않고 건수만 셈</small></h4>
          <span class="ig-state ${d.paused ? "bad" : "ok"}">${d.paused ? "일시정지 중" : "수집 중"}</span>
        </div>
        ${d.paused ? `<div class="ig-now"><b>${esc(d.scope_text)}</b> · ${esc(mmss(d.left_s))} · 시작 ${esc(dt(d.since))} · ${d.by === "auto" ? "자동" : esc(d.by)}${d.reason ? ` — ${esc(d.reason)}` : ""}
            <div class="small">버린 로그 ${(d.dropped || 0).toLocaleString()}건${(d.dropped_by || []).length ? " — " + d.dropped_by.slice(0, 5).map(x => `${esc(x.sender)} ${x.n.toLocaleString()}`).join(" · ") : ""}</div>
            ${can ? `<button class="btn-sm solid" id="ig-resume">지금 재개</button>` : ""}</div>` : ""}
        ${can ? `<div class="ig-form">
          <label>범위<select id="ig-scope">${Object.entries(SC).map(([k, v]) => `<option value="${k}"${k === "syslog" ? " selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
          <label class="ig-snd" hidden>송신자(IP·대역·호스트 이름, 쉼표)<input id="ig-senders" placeholder="10.0.0.10, vcsa01.corp.local"></label>
          <label>기간<select id="ig-min"><option value="10">10분</option><option value="30" selected>30분</option><option value="60">1시간</option><option value="240">4시간</option><option value="1440">24시간</option><option value="">직접 재개할 때까지</option></select></label>
          <label class="ig-reason">사유<input id="ig-reason" maxlength="200" placeholder="예: vCenter syslog 폭주"></label>
          <button class="btn-sm solid" id="ig-pause">${d.paused ? "다시 설정" : "일시정지"}</button>
        </div>` : ""}
        <div class="ig-grid">
          <div><h5>지금 부하 <small>${esc(dt(c.ts))}</small></h5>
            <dl class="ig-dl">
              <dt>수신</dt><dd>${(c.eps ?? 0).toLocaleString()}건/초</dd>
              <dt>처리 대기열</dt><dd>${c.queue_pct ?? 0}% <small class="muted">(기준 ${a.queue_pct}%)</small></dd>
              <dt>이벤트 루프 지연 p99</dt><dd>${c.lag_p99_ms ?? 0}ms <small class="muted">(기준 ${a.lag_ms}ms)</small></dd>
              <dt>DB 조회 지연 p95</dt><dd>${c.read_p95_ms ?? 0}ms <small class="muted">(기준 ${a.read_ms}ms)</small></dd>
            </dl>
            ${(c.overload || []).length ? `<div class="ig-over">과부하 ${d.over_count}/${a.consecutive}회 — ${c.overload.map(esc).join(" · ")}</div>` : `<div class="small muted">과부하 아님</div>`}
          </div>
          <div><h5>많이 보내는 송신자(최근 1분)</h5>
            ${top.length ? `<table class="vc-t"><thead><tr><th>송신자</th><th>건/초</th><th>비중</th>${can ? "<th></th>" : ""}</tr></thead><tbody>
              ${top.slice(0, 6).map(t => `<tr><td class="vc-ent">${esc(t.sender)}</td><td>${t.eps}</td><td>${t.share}%</td>${can ? `<td><button class="btn-sm" data-ig-sender="${esc(t.sender)}">이 송신자만 멈춤</button></td>` : ""}</tr>`).join("")}</tbody></table>`
              : `<p class="small muted">최근 1분 syslog 수신 없음</p>`}
          </div>
          <div><h5>자동 일시정지 <small>5초마다 판정</small></h5>
            <div class="ig-auto">
              <label class="ig-chk"><input type="checkbox" id="ig-a-en"${a.enabled ? " checked" : ""}${can ? "" : " disabled"}> 과부하가 ${a.consecutive}회 연속(${a.consecutive * 5}초)이면 자동으로 멈춤</label>
              <label>범위<select id="ig-a-scope"${can ? "" : " disabled"}>${Object.entries(ASC).map(([k, v]) => `<option value="${k}"${a.scope === k ? " selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
              <label>대기열 %<input type="number" id="ig-a-q" min="10" max="100" value="${a.queue_pct}"${can ? "" : " disabled"}></label>
              <label>루프 지연 ms<input type="number" id="ig-a-lag" min="0" value="${a.lag_ms}"${can ? "" : " disabled"}></label>
              <label>조회 지연 ms<input type="number" id="ig-a-read" min="0" value="${a.read_ms}"${can ? "" : " disabled"}></label>
              <label>최대 건/초(0=끔)<input type="number" id="ig-a-eps" min="0" value="${a.max_eps}"${can ? "" : " disabled"}></label>
              <label>멈춤 시간(분)<input type="number" id="ig-a-min" min="1" value="${a.pause_minutes}"${can ? "" : " disabled"}></label>
              ${can ? `<button class="btn-sm" id="ig-a-save">자동 설정 저장</button>` : ""}
            </div>
            <p class="small muted">자동으로 멈추면 정해진 시간 뒤 스스로 재개하고, 다시 과부하면 2배씩(최대 ${a.max_pause_minutes}분) 길게 멈춥니다. 콘솔: <code>sudo vcf-aiopsctl pause 30 --sender 10.0.0.10</code> · <code>sudo vcf-aiopsctl resume</code></p>
          </div>
        </div>
        ${(d.history || []).length ? `<details class="ig-hist"><summary>최근 기록 ${d.history.length}건</summary><ul>${d.history.map(h => `<li>${esc(dt(h.ts))} · ${h.action === "pause" ? "일시정지" : "재개"} · ${esc(h.by)}${h.action === "pause" ? ` · ${esc(SC[h.scope] || h.scope)}${(h.senders || []).length ? " " + esc(h.senders.join(", ")) : ""}` : ` · 버린 로그 ${(h.dropped || 0).toLocaleString()}건`}${h.reason ? ` — ${esc(h.reason)}` : ""}</li>`).join("")}</ul></details>` : ""}
      </section>`;
    const sc = $("#ig-scope"); if (sc) { const f = () => { $(".ig-snd", box).hidden = sc.value !== "senders"; }; sc.onchange = f; f(); }
  }

  async function act(body, okMsg) {
    if (st.busy) return; st.busy = true;
    try { st.d = await A.api("POST", "/api/ingest-gate", body); A.ok(okMsg); banner(); render(); }
    catch (e) { A.fail("수집 상태를 바꾸지 못했습니다", e); }
    finally { st.busy = false; }
  }
  function pauseFromForm() {
    const scope = $("#ig-scope").value, senders = ($("#ig-senders").value || "").split(/[,\s]+/).filter(Boolean);
    if (scope === "senders" && !senders.length) { A.fail("송신자를 입력하세요", new Error("IP·대역·호스트 이름")); return; }
    if (scope === "all" && !confirm("전체 수집을 멈춥니다(장비 로그·알람·SNMP·HTTP 수집). 계속할까요?")) return;
    act({action: "pause", scope, senders, minutes: $("#ig-min").value || null, reason: $("#ig-reason").value}, "수집을 일시정지했습니다");
  }
  async function saveAuto() {
    const n = id => Number($(id).value);
    try {
      st.d = await A.api("PUT", "/api/ingest-gate/auto", {enabled: $("#ig-a-en").checked, scope: $("#ig-a-scope").value, queue_pct: n("#ig-a-q"),
        lag_ms: n("#ig-a-lag"), read_ms: n("#ig-a-read"), max_eps: n("#ig-a-eps"), pause_minutes: n("#ig-a-min")});
      A.ok("자동 일시정지 설정을 저장했습니다"); render();
    } catch (e) { A.fail("저장하지 못했습니다", e); }
  }

  document.addEventListener("click", e => {
    const t = e.target;
    if (t.id === "ig-resume" || t.id === "ig-resume-b") act({action: "resume", reason: "직접 재개"}, "수집을 재개했습니다");
    else if (t.id === "ig-pause") pauseFromForm();
    else if (t.id === "ig-a-save") saveAuto();
    else if (t.id === "ig-open") { const n = document.getElementById("nav-plat"); if (n) n.click(); }
    else if (t.dataset && t.dataset.igSender) {
      const s = t.dataset.igSender, m = $("#ig-min") ? $("#ig-min").value : "30";
      act({action: "pause", scope: "senders", senders: [s], minutes: m || null, reason: `${s} 수신 폭주`}, `${s} 수집을 일시정지했습니다`);
    }
  });
  const nav = document.getElementById("nav-plat");
  if (nav) nav.addEventListener("click", () => { setTimeout(() => load(false), 50); });
  setInterval(() => {                                   // 띠: 30초 · 화면이 열려 있으면 5초
    const open = $("#ig-box") && !$("#ig-box").closest(".drawer").hidden;
    if (open || !st.t || Date.now() - st.t > 30000) { st.t = Date.now(); if (!document.hidden) load(true); }
  }, 5000);
  setTimeout(() => load(true), 2500);
  window.AIOPS_INGEST_GATE = () => load(false);
})();
