/* 보안(방화벽) — FortiGate syslog 집계: 장비·KPI·분당 추이·무차별 대입 출발지·상위 차단·IPS·최근 보안 이벤트·처리 설정 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const sc = {d: null, min: 60, timer: null, edit: false};
  const n = v => (v || 0).toLocaleString();
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.max(0, Math.round(s))}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };
  const hm = ts => new Date(ts * 1000).toTimeString().slice(0, 5);
  const KIND = {login_fail: "로그인 실패", login_success_after_fail: "실패 후 성공", ips: "IPS", anomaly: "이상 트래픽", virus: "바이러스", config: "설정 변경", port_scan: "포트 스캔", webfilter: "웹 필터", "app-ctrl": "앱 제어"};
  const MODE = {aggregate: "집계(권장) — 개별 저장 안 함, 1분 요약만", store: "개별 저장 — 검색 가능, 저장량 큼", drop: "카운터만 — 요약 이벤트도 저장 안 함"};

  async function load() {
    try { sc.d = await A.api("GET", `/api/security/fortigate?minutes=${sc.min}`, undefined, {background: true}); }
    catch (e) { $("#sec-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (!sc.edit) render();
    badge();
  }
  function badge() {
    const b = $("#sec-badge"); if (!b || !sc.d) return;
    const k = sc.d.kpi.attackers || 0; b.hidden = !k; b.textContent = k; b.title = `공격 중인 출발지 ${k}`;
  }

  function chart(series) {
    if (!series.length) return `<div class="empty small">아직 1분 집계가 없습니다(수신 후 1분 뒤 표시).</div>`;
    const W = 760, H = 120, bw = W / Math.max(series.length, 30);
    const mx = Math.max(1, ...series.map(p => p.traffic || 0));
    const mf = Math.max(1, ...series.map(p => (p.login_fail || 0) + (p.ips || 0)));
    const bars = series.map((p, i) => {
      const h1 = (p.traffic || 0) / mx * (H - 16), h2 = (p.denied || 0) / mx * (H - 16);
      return `<rect x="${(i * bw).toFixed(1)}" y="${(H - h1).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h1.toFixed(1)}" fill="#c5d9e4"><title>${hm(p.t)} 트래픽 ${n(p.traffic)} · 차단 ${n(p.denied)} · 로그인 실패 ${n(p.login_fail)} · IPS ${n(p.ips)}</title></rect>
        <rect x="${(i * bw).toFixed(1)}" y="${(H - h2).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h2.toFixed(1)}" fill="#e57373" pointer-events="none"/>`;
    }).join("");
    const line = series.map((p, i) => `${(i * bw + bw / 2).toFixed(1)},${(H - ((p.login_fail || 0) + (p.ips || 0)) / mf * (H - 16)).toFixed(1)}`).join(" ");
    const lab = [0, Math.floor(series.length / 2), series.length - 1].map(i => `<text x="${Math.min(W - 30, i * bw).toFixed(0)}" y="${H + 12}" font-size="10" fill="currentColor">${hm(series[i].t)}</text>`).join("");
    return `<svg viewBox="0 0 ${W} ${H + 14}" class="sec-chart" preserveAspectRatio="none">${bars}<polyline points="${line}" fill="none" stroke="#e08a00" stroke-width="1.6"/>${lab}</svg>
      <div class="sec-leg small"><i style="background:#c5d9e4"></i>트래픽(최대 ${n(mx)}/분) <i style="background:#e57373"></i>차단 <i style="background:#e08a00;height:2px"></i>로그인 실패+IPS(최대 ${n(mf)}/분)</div>`;
  }

  function render() {
    const d = sc.d, k = d.kpi, can = A.can("settings");
    $("#sec-sub").textContent = `— FortiGate ${k.devices}대 · 최근 ${k.minutes}분`;
    if (!d.devices.length) {
      $("#sec-body").innerHTML = `<div class="sec-empty"><h4>FortiGate 로그가 아직 없습니다</h4>
        <p>FortiGate 에서 이 서버로 syslog 를 보내면 자동으로 인식합니다(별도 커넥터 불필요).</p>
        <pre>config log syslogd setting
    set status enable
    set server "&lt;AIops 주소&gt;"
    set port 514
    set mode udp            # 또는 reliable(TCP)
    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
end</pre>
        <p class="small muted">트래픽 로그는 기본 '집계' 모드로 개별 저장 없이 분당 카운터만 유지합니다. 장비 상태(버전·CPU·메모리)까지 보려면 운영 설정 › 커넥터에서 'FortiGate (FortiOS REST)' 를 읽기 전용 API 토큰으로 추가하세요.</p></div>${can ? cfgHtml(d.config) : ""}`;
      return;
    }
    const bf = d.bruteforce, active = bf.filter(r => r.active);
    $("#sec-body").innerHTML = `
      <div class="sec-bar"><div class="inv-chips">${[15, 60, 180].map(m => `<button data-min="${m}" class="${sc.min === m ? "on" : ""}">${m < 60 ? m + "분" : m / 60 + "시간"}</button>`).join("")}</div>
        <span class="small muted">처리: ${esc(MODE[d.config.traffic_mode] || d.config.traffic_mode)} · 수신 ${n(d.stats.received)} · 집계 흡수 ${n(d.stats.aggregated)} · 보안 경보 ${n(d.stats.alerts)}</span></div>
      <div class="sec-kpis">
        ${kpi("장비", `${k.online}/${k.devices}`, "온라인/전체")}
        ${kpi("트래픽", n(k.traffic), `분당 ${n((k.per_min_last || {}).traffic)}`)}
        ${kpi("차단", n(k.denied), `분당 ${n((k.per_min_last || {}).denied)}`, k.denied ? "warn" : "")}
        ${kpi("로그인 실패", n(k.login_fail), `출발지 ${k.bf_sources}`, k.login_fail ? "warn" : "")}
        ${kpi("IPS·이상 탐지", n(k.ips), "", k.ips ? "warn" : "")}
        ${kpi("공격 중 출발지", k.attackers, `${d.config.bf_window / 60}분 ${d.config.bf_threshold}회↑`, k.attackers ? "bad" : "")}
      </div>
      <section class="sec-sec"><h4>분당 추이</h4>${chart(d.series)}</section>
      <section class="sec-sec"><h4>무차별 대입(로그인 실패) 출발지 <small class="muted">관리자 GUI/SSH · SSL-VPN · 사용자 인증 — 판정 창 ${d.config.bf_window / 60}분(출발지 IP별)</small></h4>
        ${bf.length ? `<div class="tbl-x"><table class="vc-t"><thead><tr><th>상태</th><th>출발지</th><th>${d.config.bf_window / 60}분</th><th>누적</th><th>최대</th><th>계정</th><th>유형</th><th>장비</th><th>최초</th><th>최근</th></tr></thead><tbody>
          ${bf.slice(0, 100).map(r => `<tr class="${r.success_after ? "sec-crit" : ""}"><td>${r.success_after ? '<span class="mon-st ALERT">실패 후 성공</span>' : r.active ? `<span class="mon-st ${r.level === "critical" ? "ALERT" : "WARN"}">공격 중</span>` : '<span class="mon-st NO_DATA">관찰</span>'}</td>
            <td><code>${esc(r.srcip)}</code>${r.country ? ` <span class="small muted">${esc(r.country)}</span>` : ""}</td><td><b>${n(r.window)}</b></td><td>${n(r.total)}</td><td>${n(r.peak)}</td>
            <td class="small">${esc((r.users || []).slice(0, 6).join(", "))}${(r.users || []).length > 6 ? ` 외 ${r.users.length - 6}` : ""}</td><td class="small">${esc((r.kinds || []).join(", "))}</td>
            <td class="small">${esc((r.devs || []).join(", "))}</td><td class="small">${ago(r.first)}</td><td class="small">${ago(r.last)}</td></tr>`).join("")}</tbody></table></div>
          ${active.length ? `<p class="small muted">조치 예: FortiGate 에서 해당 출발지를 주소 객체로 차단(local-in-policy), 관리자 접근을 Trusted Hosts 로 제한, SSL-VPN 은 MFA·로그인 잠금(set login-attempt-limit / login-block-time). AIops 는 읽기 전용이라 장비 설정을 바꾸지 않습니다.</p>` : ""}`
          : `<p class="muted small">로그인 실패 기록 없음</p>`}</section>
      <div class="sec-two">
        <section class="sec-sec"><h4>상위 차단 출발지</h4>${top(d.top_src, "srcip", "출발지")}</section>
        <section class="sec-sec"><h4>상위 차단 목적지 포트</h4>${top(d.top_port, "port", "포트/프로토콜")}</section>
      </div>
      <section class="sec-sec"><h4>IPS · 이상 트래픽 · 바이러스 <small class="muted">(서명·출발지)별 첫 건만 이상징후, 반복은 건수로 집계</small></h4>
        ${d.ips.length ? `<div class="tbl-x"><table class="vc-t"><thead><tr><th>종류</th><th>서명</th><th>심각도</th><th>조치</th><th>출발지</th><th>목적지</th><th>건수</th><th>최근</th></tr></thead><tbody>
          ${d.ips.slice(0, 50).map(r => `<tr><td>${esc(KIND[r.subtype] || r.subtype)}</td><td>${r.ref ? `<a href="${esc(r.ref)}" target="_blank" rel="noopener">${esc(r.sig)}</a>` : esc(r.sig)}</td>
            <td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td><td>${esc(r.action || "-")}</td><td><code>${esc(r.srcip)}</code>${r.country ? ` <span class="small muted">${esc(r.country)}</span>` : ""}</td>
            <td class="small">${esc((r.dst || []).slice(0, 3).join(", "))}${(r.dst || []).length > 3 ? " …" : ""}</td><td>${n(r.count)}</td><td class="small">${ago(r.last)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted small">탐지 없음</p>`}</section>
      <section class="sec-sec"><h4>장비</h4><div class="tbl-x"><table class="vc-t"><thead><tr><th>장비</th><th>시리얼</th><th>펌웨어</th><th>CPU/MEM</th><th>VDOM</th><th>분당</th><th>송신 주소</th><th>마지막 수신</th></tr></thead><tbody>
        ${d.devices.map(x => { const r = x.rest || {}, lm = x.last_min || {}; return `<tr><td><span class="dot ${x.online ? "ok" : "down"}"></span> <b>${esc(x.name)}</b>${x.ha_role ? ` <span class="label">${esc(x.ha_role)}</span>` : ""}</td>
          <td><code>${esc(x.devid || r.serial || "")}</code></td><td class="small">${r.version ? `${esc(r.model || "")} ${esc(r.version)} build${esc(String(r.build || ""))}` : '<span class="muted">REST 커넥터 없음</span>'}</td>
          <td class="small">${r.cpu != null ? `${Math.round(r.cpu)}% / ${Math.round(r.mem || 0)}%` : "-"}</td><td class="small">${esc((x.vdoms || []).join(", "))}</td>
          <td class="small">${n(lm.total)}${lm.denied ? ` · 차단 ${n(lm.denied)}` : ""}</td><td class="small">${esc(x.peer || "")}</td><td class="small">${ago(x.last)}</td></tr>`; }).join("")}</tbody></table></div></section>
      <section class="sec-sec"><h4>최근 보안 이벤트</h4>${d.recent.length ? `<ul class="sec-recent">${d.recent.slice(0, 60).map(r => `<li><span class="small muted">${ago(r.ts)}</span> <span class="sev ${esc(r.severity)}">${esc(KIND[r.kind] || r.kind)}</span> ${r.srcip ? `<code>${esc(r.srcip)}</code> ` : ""}${r.user ? `<b>${esc(r.user)}</b> ` : ""}<span>${esc(r.msg)}</span></li>`).join("")}</ul>` : `<p class="muted small">없음</p>`}</section>
      ${can ? cfgHtml(d.config) : ""}`;
  }
  const kpi = (l, v, s, c = "") => `<div class="sec-kpi ${c}"><small>${l}</small><b>${v}</b><span>${s}</span></div>`;
  function top(rows, key, label) {
    if (!rows.length) return `<p class="muted small">차단 없음</p>`;
    const mx = rows[0].count || 1;
    return `<table class="vc-t sec-top"><thead><tr><th>${label}</th><th>건수</th></tr></thead><tbody>${rows.slice(0, 12).map(r => `<tr><td><code>${esc(r[key])}</code></td><td><div class="sec-barv"><i style="width:${Math.max(2, r.count / mx * 100)}%"></i><span>${n(r.count)}</span></div></td></tr>`).join("")}</tbody></table>`;
  }
  function cfgHtml(c) {
    const f = (k, l, h) => `<label><span>${l}</span><input type="number" min="1" data-k="${k}" value="${esc(String(c[k]))}">${h ? `<small class="muted">${h}</small>` : ""}</label>`;
    return `<details class="sec-sec sec-cfg"><summary><b>처리 설정</b> <span class="small muted">트래픽 처리 방식·무차별 대입 임계</span></summary>
      <div class="sec-form"><label><span>트래픽 로그 처리</span><select data-k="traffic_mode">${Object.entries(MODE).map(([k, v]) => `<option value="${k}" ${c.traffic_mode === k ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>
        ${f("bf_window", "무차별 대입 판정 창(초)")}${f("bf_threshold", "경보 임계(창 안 실패 횟수)")}${f("bf_critical", "위험(critical) 임계")}
        ${f("realert", "재알림 간격(초)")}${f("bf_store_max", "출발지당 개별 실패 로그 저장 상한", "넘으면 건수만 집계")}
        ${f("ips_dedupe", "IPS 같은 서명·출발지 묶음 시간(초)")}${f("ips_store_max", "IPS 반복 저장 상한")}
        ${f("scan_ports", "포트 스캔 판정(1분 차단 포트 수)")}${f("deny_flood", "차단 폭주 판정(1분 차단 건수)")}</div>
      <button class="btn-sm solid" id="sec-save">저장</button></details>`;
  }

  function wire() {
    const b = $("#sec-body");
    b.addEventListener("click", async e => {
      const m = e.target.closest("[data-min]");
      if (m) { sc.min = +m.dataset.min; load(); return; }
      if (e.target.id === "sec-save") {
        const body = {};
        $$(".sec-form [data-k]", b).forEach(i => { body[i.dataset.k] = i.tagName === "SELECT" ? i.value : +i.value; });
        try { await A.api("PUT", "/api/security/fortigate/config", body); A.ok("저장됨", "FortiGate 처리 설정"); sc.edit = false; load(); }
        catch (err) { A.fail("저장 실패", err); }
      }
    });
    b.addEventListener("toggle", e => { if (e.target.classList && e.target.classList.contains("sec-cfg")) sc.edit = e.target.open; }, true);
    $("#sec-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-sec")) return;
    wire();
    $("#nav-sec").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-sec") d.hidden = true; });
      $("#drawer-sec").hidden = false; sc.edit = false; load();
      clearInterval(sc.timer); sc.timer = setInterval(() => $("#drawer-sec").hidden ? clearInterval(sc.timer) : load(), 10000);
    };
    A.ready.then(me => { if (me === null) return; const tick = () => A.api("GET", "/api/security/fortigate?minutes=15", undefined, {background: true}).then(d => { sc.d = sc.d && !$("#drawer-sec").hidden ? sc.d : d; const b = $("#sec-badge"); if (b) { b.hidden = !d.kpi.attackers; b.textContent = d.kpi.attackers; } }).catch(() => {}); setTimeout(tick, 6000); setInterval(tick, 60000); });
  });
})();
