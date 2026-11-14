/* 관제 도메인 상세 탭 — /noc/d/<슬롯>
   상단: 상태·사유·미확인 위험/오류/경고·인시던트·개체 장애·실시간 유입(초당)
   좌: 심각도별 60분 추이 · 이벤트 상위 호스트 · 개체 상태(종류별 타일) · 도메인 전용 표(알람·클러스터·VM 이동·Edge·VS·SE·서버·공격 출발지) · 커넥터 점검
   우: 실시간 이벤트 스트림(WebSocket tail — 이 도메인 소스 전량, 심각도·호스트·검색어 필터, 일시정지) · 중요 이벤트(24시간) · 열린 이상징후 · 인시던트
   개체·호스트를 누르면 스트림이 그 호스트로 좁혀진다. 이상징후·인시던트 발생 시 상세를 자동 갱신
   1.9: 개체 상세 드로어(60분 추이·AI 판정 이상징후·확인 처리·물리↔논리 경로·최근 이벤트) · 패턴 탭(같은 로그 묶음)
        · 15분 증감 · CSV 내보내기 · 단축키(P 일시정지 · Esc 닫기) · ?host=&open=1 딥링크 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const p2 = n => String(n).padStart(2, "0");
  const hms = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
  const hm = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}`; };
  const N = v => (v || 0).toLocaleString();
  const ago = s => s < 60 ? `${Math.round(s)}초` : s < 3600 ? `${Math.floor(s / 60)}분` : `${Math.floor(s / 3600)}시간`;
  const SEV = {critical: "위험", error: "오류", warning: "경고", info: "정보", debug: "디버그"};
  const RANK = {debug: 0, info: 1, warning: 2, error: 3, critical: 4};
  const STK = {down: "장애", warn: "주의", ok: "정상", idle: "대기", maint: "유지보수", unknown: "미확인"};
  const MAXROWS = 400;
  const D = {sid: null, d: null, on: false, paused: false, buf: 0, rows: [], min: "info", host: "", q: "", tab: "live", ptab: null, rate: [], tick: 0, rt: null, hist: null,
             pat: null, patAt: 0, ent: null, entName: "", deep: null};

  const stCls = v => {
    v = String(v ?? "").toLowerCase();
    if (/^(down|red|critical|failed|fail|oper_down|inoperable|error)/.test(v) || v === "장애") return "down";
    if (/^(warn|yellow|degraded|oper_initializing|partial|maint|power-off|unknown)/.test(v)) return "warn";
    if (/^(ok|green|up|oper_up|success|connected|operable|on|정상)/.test(v)) return "ok";
    return "";
  };
  const pill = v => v === "" || v == null ? "" : `<span class="dm-st ${stCls(v)}">${esc(STK[v] || v)}</span>`;

  // ------------------------------------------------------------------ 그래프
  function sevChart(d) {
    const w = 640, h = 150, n = 60, s = d.sev || {}, rate = d.rate || [];
    const tot = i => (s.critical?.[i] || 0) + (s.error?.[i] || 0) + (s.warning?.[i] || 0);
    const mx = Math.max(1, ...Array.from({length: n}, (_, i) => tot(i))), rmx = Math.max(1, ...rate);
    const bw = w / n;
    let bars = "";
    for (let i = 0; i < n; i++) {
      let y = h - 16;
      for (const [k, c] of [["warning", "var(--warn)"], ["error", "var(--err)"], ["critical", "var(--crit)"]]) {
        const v = s[k]?.[i] || 0; if (!v) continue;
        const bh = v / mx * (h - 30); y -= bh;
        bars += `<rect x="${(i * bw + 1).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${bh.toFixed(1)}" fill="${c}"><title>${hm(Date.now() / 1000 - (n - 1 - i) * 60)} ${SEV[k]} ${v}</title></rect>`;
      }
    }
    const pts = rate.map((v, i) => `${(i * bw + bw / 2).toFixed(1)},${(h - 16 - v / rmx * (h - 30)).toFixed(1)}`).join(" ");
    const lab = [0, 15, 30, 45, 59].map(i => `<text x="${(i * bw + bw / 2).toFixed(0)}" y="${h - 3}" text-anchor="middle">${i === 59 ? "지금" : `-${59 - i}분`}</text>`).join("");
    return `<svg viewBox="0 0 ${w} ${h}" class="dm-chart" role="img" aria-label="60분 심각도 추이">${bars}
      ${pts ? `<polyline points="${pts}" fill="none" stroke="var(--info)" stroke-width="1.6" opacity=".85" vector-effect="non-scaling-stroke"/>` : ""}${lab}</svg>
      <div class="dm-leg"><span><i style="background:var(--crit)"></i>위험</span><span><i style="background:var(--err)"></i>오류</span><span><i style="background:var(--warn)"></i>경고</span>
      <span><i class="ln"></i>전체 유입(분당, 최대 ${N(rmx)})</span><span class="r">경고 이상 최대 ${N(mx)}/분</span></div>`;
  }
  function delta(d) {                                          // 경고 이상: 최근 15분 vs 직전 15분
    const s = d.sev || {}, sum = (a, b) => ["warning", "error", "critical"].reduce((t, k) => t + (s[k] || []).slice(a, b).reduce((x, y) => x + y, 0), 0);
    const cur = sum(45, 60), prev = sum(30, 45);
    if (!cur && !prev) return `<span class="dm-dl">최근 15분 경고 이상 없음</span>`;
    const p = prev ? Math.round((cur - prev) / prev * 100) : null;
    return `<span class="dm-dl ${cur > prev ? "up" : cur < prev ? "dn" : ""}" title="경고 이상 이벤트 — 최근 15분 ${cur}건 · 직전 15분 ${prev}건">최근 15분 ${N(cur)}건 ${cur > prev ? "▲" : cur < prev ? "▼" : "＝"}${p != null ? ` ${Math.abs(p)}%` : " 신규"}</span>`;
  }
  function spark(vals, {w = 120, h = 26, color = "var(--info)", bars = false} = {}) {
    const v = vals || []; if (!v.length) return "";
    const mx = Math.max(1, ...v), bw = w / v.length;
    if (bars) return `<svg viewBox="0 0 ${w} ${h}" class="dm-spark" preserveAspectRatio="none">${v.map((x, i) => x ? `<rect x="${(i * bw + .5).toFixed(1)}" y="${(h - x / mx * h).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${(x / mx * h).toFixed(1)}" fill="${color}"/>` : "").join("")}</svg>`;
    const pts = v.map((x, i) => `${(i * bw + bw / 2).toFixed(1)},${(h - 2 - x / mx * (h - 4)).toFixed(1)}`).join(" ");
    return `<svg viewBox="0 0 ${w} ${h}" class="dm-spark" preserveAspectRatio="none"><polygon points="0,${h} ${pts} ${w},${h}" fill="${color}" opacity=".18"/><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
  }
  function hostsHtml(d) {
    const t = d.top_hosts || []; if (!t.length) return `<div class="wempty">최근 20분 이벤트 없음</div>`;
    const mx = t[0].n || 1;
    return `<ol class="dm-hosts">${t.map(x => `<li data-host="${esc(x.host)}" class="${D.host === x.host ? "on" : ""}" title="눌러서 실시간 스트림을 이 호스트로 좁히기"><span>${esc(x.host)}</span><i><b style="width:${(x.n / mx * 100).toFixed(1)}%"></b></i><em>${N(x.n)}</em></li>`).join("")}</ol>`;
  }
  function entHtml(d) {
    if (!d.entities.length) return `<div class="wempty">이 도메인의 개체가 없습니다 — 운영 설정 › 커넥터에서 ${esc(d.name)} 커넥터를 추가하세요</div>`;
    const by = {};
    d.entities.forEach(e => { (by[e.kind || "기타"] = by[e.kind || "기타"] || []).push(e); });
    return Object.entries(by).map(([k, list]) => {
      const c = d.kinds[k] || {};
      return `<div class="dm-kind"><h4>${esc(k)} <small>${list.length}${c.down ? ` · <b class="c-down">장애 ${c.down}</b>` : ""}${c.warn ? ` · <b class="c-warn">주의 ${c.warn}</b>` : ""}</small></h4>
        <div class="dm-tiles">${list.slice(0, 160).map(e => `<button type="button" class="dm-t ${e.state}${D.entName && D.entName.toLowerCase() === String(e.name).toLowerCase() ? " on" : ""}" data-ent="${esc(e.name)}" title="${esc(e.name)} — ${esc(STK[e.state] || e.state)}${e.detail ? "\n" + esc(e.detail) : ""}${e.alerts ? `\n열린 이상징후 ${e.alerts}건` : ""}\n누르면 개체 상세">
          <span>${esc(e.name)}</span>${e.alerts ? `<b>${e.alerts}</b>` : ""}</button>`).join("")}${list.length > 160 ? `<span class="dm-more">+${list.length - 160}</span>` : ""}</div></div>`;
    }).join("");
  }
  function cell(k, v) {
    if (k === "state" || k === "status") return pill(v);
    if (k === "ts" && typeof v === "number") return `<span class="mono">${hm(v)}</span>`;
    if (k === "cpu" || k === "mem") return v == null ? "-" : `<span class="dm-pct ${v >= 90 ? "down" : v >= 75 ? "warn" : ""}"><i style="--w:${Math.min(100, v)}%"></i><em>${v}%</em></span>`;
    if (k === "active" && v) return `<span class="dm-st down">${esc(v)}</span>`;
    return esc(v ?? "");
  }
  const MV = {vmotion: "vMotion", drs: "DRS", svmotion: "Storage vMotion", relocate: "콜드 이전", ha_restart: "HA 재시작", ha_failed: "HA 실패", ha_reset: "HA 리셋",
              ha_reset_failed: "HA 리셋 실패", host_failed: "호스트 장애", host_isolated: "호스트 격리", move_failed: "이동 실패", detected: "위치 변경"};
  function panelBody(p) {
    if (p.kind === "moves") return p.rows.length ? `<ol class="dm-moves">${p.rows.map(r => `<li class="${/^ha|host_/.test(r.type) ? "ha" : ""}"><span class="mono">${hms(r.ts)}</span><b>${esc(MV[r.type] || r.type)}</b> ${esc(r.vm || "")}<span class="r">${esc(r.from_host || "?")} → ${esc(r.to_host || "?")}</span></li>`).join("")}</ol>` : `<div class="wempty">최근 이동 없음</div>`;
    if (!p.rows.length) return `<div class="wempty">${esc(p.empty || "데이터 없음")}</div>`;
    return `<table class="dm-tbl"><thead><tr>${p.cols.map(c => `<th>${esc(c[1])}</th>`).join("")}</tr></thead><tbody>${p.rows.map(r => `<tr${r.name ? ` data-ent="${esc(r.name)}"` : ""}>${p.cols.map(c => `<td>${cell(c[0], r[c[0]])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }
  function checksHtml(d) {
    const conns = d.connectors || [];
    if (!conns.length) return `<div class="wempty">이 도메인에 연결된 커넥터가 없습니다(syslog·에이전트 수신만)</div>`;
    return conns.map(c => {
      const ch = (d.checks || {})[c.name] || {};
      return `<div class="dm-conn"><h4>${pill(c.state)} ${esc(c.name)} <small>${esc(c.type)} · ${esc(c.target || "")}${c.latency_ms != null ? ` · ${c.latency_ms}ms` : ""}${c.last_ok ? ` · 마지막 성공 ${ago(Date.now() / 1000 - c.last_ok)} 전` : ""}</small></h4>
        ${c.last_error ? `<div class="dm-err">${esc(c.last_error)}</div>` : ""}
        ${Object.keys(ch).length ? `<ul class="dm-checks">${Object.entries(ch).map(([k, v]) => `<li class="${/^ok/.test(String(v)) ? "ok" : /HTTP|실패|오류|error|denied|거부/i.test(String(v)) ? "down" : "warn"}"><span>${esc(k)}</span><em>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</em></li>`).join("")}</ul>` : `<div class="mini">점검 결과 없음 — 운영 설정 › 커넥터 › 연결 테스트</div>`}</div>`;
    }).join("");
  }
  function ptabs(d) {
    const list = [...d.panels.filter(p => !p.section).map(p => [p.id, p.title, p.rows.length]), ["checks", "커넥터 점검", (d.connectors || []).filter(c => c.state !== "ok").length || ""]];
    if (!D.ptab || !list.some(x => x[0] === D.ptab)) D.ptab = list[0][0];
    return { list, body: D.ptab === "checks" ? checksHtml(d) : panelBody(d.panels.find(p => p.id === D.ptab)) };
  }

  // ------------------------------------------------------------------ 스트림
  const rowHtml = e => `<li class="s-${esc(e.severity)}${e._new ? " nw" : ""}" data-host="${esc(e.host || "")}"><span class="t mono">${hms(e.ts)}</span><span class="dm-sev ${esc(e.severity)}">${esc(SEV[e.severity] || e.severity)}</span>
    <span class="h" title="${esc(e.host || "")}">${esc(e.host || e.entity || "-")}</span><span class="m" title="${esc(e.message)}">${e.kind && e.kind !== "log" ? `<i class="k">${esc(e.kind)}</i>` : ""}${esc(String(e.message || "").slice(0, 400))}</span></li>`;
  function patKey(p) {                                        // 패턴에서 검색어로 쓸 가장 긴 고정 구간
    const parts = String(p.pattern || "").split(/#|<\*>|\*/).map(x => x.trim()).filter(x => x.length >= 4).sort((a, b) => b.length - a.length);
    return (parts[0] || String(p.sample || "").slice(0, 40)).slice(0, 60);
  }
  function patBody() {
    const P = D.pat; if (!P) return `<div class="wempty">패턴 집계 중…</div>`;
    if (!P.patterns.length) return `<div class="wempty">최근 ${P.minutes}분 이벤트 없음</div>`;
    const mx = Math.max(...P.patterns.map(p => p.count));
    return `<div class="dm-pinfo mini">최근 ${P.minutes}분 ${N(P.rows)}건 → 패턴 ${N(P.total_patterns)}개${P.truncated ? " (소스별 최근 4,000건 기준)" : ""} · 누르면 해당 패턴만 실시간 표시</div>
      <ol class="dm-pats">${P.patterns.map((p, i) => `<li class="s-${esc(p.sev)}" data-pat="${i}" title="${esc(p.sample)}"><span class="dm-sev ${esc(p.sev)}">${esc(SEV[p.sev] || p.sev)}</span>
        <div class="pm"><b>${esc(p.sample)}</b><small>${p.host_count}개 호스트${p.hosts.length ? ": " + esc(p.hosts.join(", ")) : ""}${p.host_count > p.hosts.length ? " …" : ""} · ${hm(p.first)}~${hm(p.last)}</small></div>
        ${spark(p.spark, {w: 96, h: 24, bars: true, color: RANK[p.sev] >= 3 ? "var(--err)" : RANK[p.sev] === 2 ? "var(--warn)" : "var(--info)"})}
        <em><i style="width:${(p.count / mx * 100).toFixed(1)}%"></i>${N(p.count)}</em></li>`).join("")}</ol>`;
  }
  async function loadPat(force) {
    if (!D.sid || (!force && Date.now() - D.patAt < 30000 && D.pat)) return;
    D.patAt = Date.now();
    try { D.pat = await A.api("GET", `/api/noc/domain/${encodeURIComponent(D.sid)}/patterns?minutes=60`, undefined, {background: true}); }
    catch (e) { D.pat = {patterns: [], minutes: 60, rows: 0, total_patterns: 0, error: e.message}; }
    if (D.tab === "pat") { const s = $(".dm-sbody"); if (s) s.innerHTML = patBody(); }
  }
  function ackBtn(a) { return a.open && !a.ack && A.can("operate") ? `<button type="button" class="dm-ack" data-ack="${esc(a.id)}">확인</button>` : ""; }
  function streamBody() {
    if (D.tab === "pat") return patBody();
    if (D.tab === "imp") return D.d.important.length ? `<ol class="dm-stream">${D.d.important.map(rowHtml).join("")}</ol>` : `<div class="wempty">최근 24시간 경고 이상 이벤트 없음</div>`;
    if (D.tab === "open") return D.d.open.length ? `<ol class="dm-open">${D.d.open.map(a => `<li class="s-${esc(a.severity)}"><div><span class="dm-sev ${esc(a.severity)}">${esc(SEV[a.severity])}</span><b>${esc(a.title)}</b><span class="r mono">${hm(a.last_seen)}${a.count > 1 ? ` · ${a.count}회` : ""}</span>${ackBtn({...a, open: true})}</div>
      <div class="mini"><a href="#" data-ent="${esc(a.host || a.entity || "")}">${esc(a.host || a.entity || "")}</a> — ${esc(a.message)}</div>${a.summary ? `<div class="dm-ai">AI: ${esc(a.summary)}</div>` : ""}</li>`).join("")}</ol>` : `<div class="wempty">열린 이상징후 없음(판정 창 ${D.d.window_minutes}분)</div>`;
    if (D.tab === "inc") return D.d.incidents.length ? `<ol class="dm-open">${D.d.incidents.map(i => `<li class="s-${esc(i.severity)}"><div><span class="dm-sev ${esc(i.severity)}">${esc(SEV[i.severity] || i.severity)}</span><b>${esc(i.title)}</b><span class="r">${esc(i.status)}${i.assignee ? " · " + esc(i.assignee) : ""}</span></div>
      <div class="mini">#${esc(i.id)} · 생성 ${hm(i.created)} · 갱신 ${hm(i.updated)}</div></li>`).join("")}</ol>` : `<div class="wempty">활성 인시던트 없음</div>`;
    const rows = D.rows.filter(visible).slice(0, MAXROWS);
    return `<ol class="dm-stream" id="dm-live">${rows.map(rowHtml).join("") || `<li class="dm-wait">${D.on ? "이벤트를 기다리는 중… (이 도메인 소스: " + esc(D.d.sources.join(", ")) + ")" : "실시간 연결 대기"}</li>`}</ol>`;
  }
  const visible = e => RANK[e.severity] >= RANK[D.min] && (!D.mrx || D.mrx.test(`${e.message || ""} ${(e.attrs || {}).app || ""} ${(e.attrs || {}).eventType || ""} ${e.entity || ""}`) || (e.attrs || {}).vsan) && (!D.q || String(e.message || "").toLowerCase().includes(D.q.toLowerCase()))
    && (!D.host || [e.host, e.entity].some(v => v && String(v).toLowerCase().split(".")[0] === D.host.toLowerCase().split(".")[0]));
  function subscribe() {
    if (!D.sid || !D.d) return;
    D.on = A.wsSend(JSON.stringify({op: "tail", sources: D.d.sources, min: "debug", hosts: [], q: ""}));
    const l = $(".dm-live"); if (l) { l.classList.toggle("off", !D.on); l.textContent = D.on ? "● 실시간" : "○ 대기"; }
    const w = $("#dm-live .dm-wait"); if (w && D.on) w.textContent = `이벤트를 기다리는 중… (이 도메인 소스: ${D.d.sources.join(", ")})`;
  }
  function onTail(list) {
    if (!D.d) return;
    D.tick += list.length;
    if (D.paused) { D.buf += list.length; const b = $("#dm-buf"); if (b) b.textContent = `${N(D.buf)}건 대기`; }
    list.forEach(e => { e._new = 1; });
    D.rows = [...list.slice(-MAXROWS).reverse(), ...D.rows].slice(0, MAXROWS * 2);
    if (D.paused || D.tab !== "live") return;
    const ol = $("#dm-live"); if (!ol) return;
    const w = ol.querySelector(".dm-wait"); if (w) w.remove();
    const add = list.filter(visible).slice(-60).reverse();
    if (add.length) {        // 최신이 위 — 아래로 내려 읽는 중이면 끼워 넣은 높이만큼 내려 보던 줄을 고정
      const sc = ol.closest(".dm-pbody") || ol.parentElement, h0 = sc.scrollHeight, top = sc.scrollTop;
      ol.insertAdjacentHTML("afterbegin", add.map(rowHtml).join("")); while (ol.children.length > MAXROWS) ol.lastElementChild.remove();
      if (top > 4) sc.scrollTop = top + (sc.scrollHeight - h0);
    }
    setTimeout(() => { list.forEach(e => { delete e._new; }); }, 50);
    const crit = list.filter(e => e.severity === "critical").length;
    if (crit) { const h = $(".dm-head"); if (h) { h.classList.remove("blink"); void h.offsetWidth; h.classList.add("blink"); } }
  }

  // ------------------------------------------------------------------ 렌더
  function head(d) {
    const c = d.counts, entDown = Object.values(d.kinds).reduce((a, k) => a + k.down, 0);
    const big = (cls, l, v, id) => `<div class="bign ${cls}"><b${id ? ` id="${id}"` : ""}>${v}</b><span>${l}</span></div>`;
    return `<div class="dm-head st-${d.state}"><div class="dm-state"><b>${esc(STK[d.state] || d.state)}</b><span>${esc(d.name)}</span><small>${esc(d.scope || "")}</small></div>
      <div class="dm-why">${d.why ? esc(d.why) : "미확인 이상 없음"}${d.stale ? ` <span class="dm-st warn">데이터 지연</span>` : ""}
        <small>${d.last_data ? `마지막 수신 ${ago(Date.now() / 1000 - d.last_data)} 전` : "수신 기록 없음"} · 소스 ${esc(d.sources.join(", "))}${d.oldest_unack ? ` · 가장 오래된 미확인 ${esc(SEV[d.oldest_unack.severity])} ${ago(Date.now() / 1000 - d.oldest_unack.created)}` : ""}</small></div>
      <div class="dm-bigs">${big(c.critical ? "crit" : "", "위험", c.critical)}${big(c.error ? "err" : "", "오류", c.error)}${big(c.warning ? "warn" : "", "경고", c.warning)}
        ${big(d.incident_count ? "warn" : "", "인시던트", d.incident_count)}${big(entDown ? "crit" : "", "개체 장애", `${entDown}<small>/${d.entity_total}</small>`)}${big("", "최근 1분 유입", N(D.rate.reduce((a, b) => a + b, 0)), "dm-eps")}</div></div>`;
  }
  function render() {
    const d = D.d, box = $("#pg-domain"); if (!d || !box) return;
    const keep = {ent: ($(".dm-ents", box) || {}).scrollTop || 0, pan: ($(".dm-pbody", box) || {}).scrollTop || 0, st: ($(".dm-sbody", box) || {}).scrollTop || 0};
    const pt = ptabs(d);
    box.innerHTML = `${head(d)}<div class="dm-grid">
      <div class="dm-left">
        <div class="dm-row2"><section class="wcard"><h3>심각도 추이 <small>최근 60분 · 분당</small><span class="gap"></span>${delta(d)}</h3><div class="dm-pad">${sevChart(d)}</div></section>
          <section class="wcard"><h3>이벤트 상위 호스트 <small>최근 10~20분 · 누르면 스트림 필터</small></h3><div class="dm-pad dm-hbox">${hostsHtml(d)}</div></section></div>
        <section class="wcard dm-entw"><h3>개체 상태 <small>${N(d.entity_total)}개 · <span>상태 = 커넥터 운영 상태 + 열린 이상징후 · 누르면 개체 상세</span></small></h3><div class="dm-ents">${entHtml(d)}</div></section>
        <section class="wcard dm-panw"><div class="dm-ptabs" role="tablist">${pt.list.map(([id, t, n]) => `<button type="button" role="tab" data-ptab="${esc(id)}" aria-selected="${id === D.ptab}">${esc(t)}${n !== "" && n != null ? ` <small>${n}</small>` : ""}</button>`).join("")}</div>
          <div class="dm-pbody">${pt.body}</div></section>
        ${d.panels.filter(p => p.section).map(p => `<section class="wcard dm-sect"><h3>${esc(p.title)} <small>${p.rows.length}개${p.summary ? " · " + Object.entries(p.summary).map(([k, v]) => `${esc(k)} ${v.count}개 ${N(Math.round(v.capacity_gb))} GB`).join(" · ") : ""}</small></h3>
          <div class="dm-pbody dm-sbody2">${panelBody(p)}</div></section>`).join("")}
      </div>
      <section class="wcard dm-right"><div class="dm-stabs" role="tablist">
          ${[["live", "실시간 이벤트"], ["pat", `패턴${D.pat ? ` <small>${D.pat.total_patterns}</small>` : ""}`], ["imp", `중요(24시간) <small>${d.important.length}</small>`], ["open", `열린 이상징후 <small>${d.open.length}</small>`], ["inc", `인시던트 <small>${d.incident_count}</small>`]]
            .map(([id, t]) => `<button type="button" role="tab" data-stab="${id}" aria-selected="${D.tab === id}">${t}</button>`).join("")}</div>
        <div class="dm-sctl" ${D.tab === "live" ? "" : "hidden"}>
          <select id="dm-min" aria-label="최소 심각도">${["debug", "info", "warning", "error", "critical"].map(s => `<option value="${s}" ${D.min === s ? "selected" : ""}>${SEV[s]} 이상</option>`).join("")}</select>
          <input id="dm-q" type="search" placeholder="메시지 검색" value="${esc(D.q)}" aria-label="메시지 검색">
          ${D.host ? `<button type="button" class="dm-chip" id="dm-host" title="호스트 필터 해제">${esc(D.host)} ✕</button>` : ""}
          <button type="button" id="dm-pause" aria-pressed="${D.paused}" title="단축키 P">${D.paused ? "재개" : "일시정지"}</button><span id="dm-buf" class="mini"></span>
          <button type="button" id="dm-csv" title="현재 필터의 이벤트를 CSV 로 저장">CSV</button>
          <span class="dm-live ${D.on ? "" : "off"}" title="WebSocket 실시간 구독(이 도메인 소스 전량)">${D.on ? "● 실시간" : "○ 대기"}</span></div>
        <div class="dm-sbody">${streamBody()}</div></section></div>`;
    const r = (s, v) => { const el = $(s, box); if (el) el.scrollTop = v; };
    r(".dm-ents", keep.ent); r(".dm-pbody", keep.pan); r(".dm-sbody", keep.st);
    $("#w-sub").textContent = `${d.name} · ${STK[d.state] || d.state}${d.why ? " — " + d.why : ""}`;
    if (D.ent) drawer();
  }

  // ------------------------------------------------------------------ 개체 상세 드로어
  async function openEnt(name) {
    if (!name) return;
    D.entName = name; D.ent = {loading: true, name};
    drawer();
    $$(".dm-t").forEach(t => t.classList.toggle("on", t.dataset.ent.toLowerCase() === name.toLowerCase()));
    try { D.ent = await A.api("GET", `/api/noc/entity?sid=${encodeURIComponent(D.sid)}&name=${encodeURIComponent(name)}`, undefined, {background: true}); }
    catch (e) { D.ent = {name, error: e.message}; }
    if (D.entName === name) drawer();
  }
  function closeEnt() { D.ent = null; D.entName = ""; const x = $("#dm-drawer"); if (x) x.remove(); $$(".dm-t.on").forEach(t => t.classList.remove("on")); }
  function byLayer(list) {                                  // 같은 계층은 나란히, 계층 사이는 › (물리 → 논리)
    const g = {}; list.forEach(n => { (g[n.layer] = g[n.layer] || []).push(n); });
    return Object.keys(g).sort((a, b) => a - b).map(l => g[l].map(chip).join("")).join("<i>›</i>");
  }
  function chip(n) { return `<button type="button" class="dm-pc ${esc(n.state)}" data-ent="${esc(n.label)}" title="${esc(n.kind)}${n.sub ? " · " + esc(n.sub) : ""}">${esc(n.label)}</button>`; }
  function drawer() {
    const E = D.ent; if (!E) return;
    let el = $("#dm-drawer");
    if (!el) { el = document.createElement("aside"); el.id = "dm-drawer"; el.className = "dm-drawer"; el.setAttribute("aria-label", "개체 상세"); $("#pg-domain").appendChild(el); }
    if (E.loading || E.error) { el.innerHTML = `<div class="dd-h"><b>${esc(E.name)}</b><button type="button" class="x" data-close="1" aria-label="닫기">✕</button></div><div class="wempty">${E.error ? esc(E.error) : "불러오는 중…"}</div>`; return; }
    const en = E.entity || {}, s6 = E.sev6h || {}, P = E.path;
    const open = E.anomalies.filter(a => a.open), past = E.anomalies.filter(a => !a.open);
    const keep = el.querySelector(".dd-b") ? el.querySelector(".dd-b").scrollTop : 0;
    el.innerHTML = `<div class="dd-h st-${esc(en.state || "")}"><div><b>${esc(E.name)}</b><small>${esc(en.kind || "")} · ${esc(E.domain)}${en.src ? " · " + esc(en.src) : ""}</small></div>${pill(en.state || "")}
        <button type="button" class="x" data-close="1" aria-label="닫기(Esc)">✕</button></div>
      <div class="dd-b">
        ${en.detail ? `<p class="dd-det">${esc(en.detail)}</p>` : ""}
        <div class="dd-act"><button type="button" data-filter="${esc(E.name)}">스트림 필터</button><a href="/#tail/${encodeURIComponent(E.name)}" target="_blank" rel="noopener">실시간 로그(콘솔)</a>
          <a href="/noc/topology?q=${encodeURIComponent(E.name)}" data-topo="${esc(E.name)}">토폴로지에서 보기</a></div>
        <h5>최근 60분 이벤트 <small>분당 · 합계 ${N(E.series.reduce((a, b) => a + b, 0))}</small></h5>${spark(E.series, {w: 480, h: 54})}
        <div class="dd-sev">${["critical", "error", "warning", "info"].map(k => `<span class="${k}">${SEV[k]} <b>${N(s6[k] || 0)}</b></span>`).join("")}<small>최근 6시간</small></div>
        <h5>이상징후 <small>열림 ${open.length} · 최근 ${past.length}</small></h5>
        ${E.anomalies.length ? `<ol class="dm-open">${E.anomalies.slice(0, 15).map(a => `<li class="s-${esc(a.severity)}${a.open ? "" : " past"}"><div><span class="dm-sev ${esc(a.severity)}">${esc(SEV[a.severity] || a.severity)}</span><b>${esc(a.title)}</b>
            <span class="r mono">${hm(a.last_seen)}${a.count > 1 ? ` · ${a.count}회` : ""}${a.ack ? " · 확인됨" : ""}</span>${ackBtn(a)}</div>
            ${a.summary ? `<div class="dm-ai">AI 판정: ${esc(a.summary)}</div>` : `<div class="mini">${esc(a.message)}</div>`}
            ${a.cause ? `<div class="mini">추정 원인: ${esc(a.cause)}</div>` : ""}${a.impact ? `<div class="mini">영향: ${esc(a.impact)}</div>` : ""}${a.action ? `<div class="mini">조치: ${esc(Array.isArray(a.action) ? a.action.join(" · ") : a.action)}</div>` : ""}</li>`).join("")}</ol>` : `<p class="mini">관련 이상징후 없음</p>`}
        ${(E.knowledge || []).length ? `<h5>관련 KB·문서 <small>이상징후 기준 · KB·TechDocs 라이브러리</small></h5><ol class="dd-kb">${E.knowledge.map(k => `<li>
            <div>${k.kb ? `<span class="dd-kbn">KB ${esc(k.kb)}</span>` : `<span class="dd-kbn t">${esc(k.type === "techdoc" ? "TechDocs" : k.type || "문서")}</span>`}
              ${/^https?:/.test(k.url || "") ? `<a href="${esc(k.url)}" target="_blank" rel="noopener">${esc(k.title)}</a>` : esc(k.title)}
              ${(k.versions || []).length ? `<small>${esc(k.versions.slice(0, 3).join(" · "))}</small>` : ""}</div>
            ${k.fix ? `<div class="dd-fix"><b>${esc(k.fix_kind || "발췌")}</b> ${esc(k.fix.replace(/```[a-z]*\n?/g, "").slice(0, 420))}${k.fix.length > 420 ? "…" : ""}</div>` : ""}</li>`).join("")}</ol>` : ""}
        ${E.incidents.length ? `<h5>관련 인시던트</h5><ol class="dm-open">${E.incidents.map(i => `<li class="s-${esc(i.severity)}"><div><span class="dm-sev ${esc(i.severity)}">${esc(SEV[i.severity] || i.severity)}</span><b>${esc(i.title)}</b><span class="r">${esc(i.status)}</span></div></li>`).join("")}</ol>` : ""}
        <h5>물리 ↔ 논리 경로</h5>
        ${P ? `<div class="dd-path"><div class="pp"><span>상위(물리)</span>${byLayer(P.up) || '<em class="mini">없음</em>'}</div>
            <div class="pp me"><span>이 개체</span>${chip(P.node)}</div>
            <div class="pp"><span>하위(서비스)</span>${byLayer(P.down.slice(0, 24)) || '<em class="mini">없음</em>'}${P.down.length > 24 ? `<small> 외 ${P.down.length - 24}</small>` : ""}</div></div>` : `<p class="mini">토폴로지에서 찾지 못함(VM·로그 전용 호스트 등)</p>`}
        <h5>최근 이벤트 <small>6시간 · ${E.events.length}건</small></h5>
        ${E.events.length ? `<ol class="dm-stream">${E.events.slice(0, 80).map(rowHtml).join("")}</ol>` : `<p class="mini">최근 6시간 이벤트 없음</p>`}
      </div>`;
    el.querySelector(".dd-b").scrollTop = keep;
  }
  function csv() {
    const rows = (D.tab === "imp" ? D.d.important : D.rows.filter(visible)).slice(0, 5000);
    const q = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const body = "\ufeff" + ["time,severity,source,host,entity,kind,message", ...rows.map(r => [new Date(r.ts * 1000).toISOString(), r.severity, r.source, r.host, r.entity, r.kind, r.message].map(q).join(","))].join("\r\n");
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([body], {type: "text/csv"}));
    a.download = `noc-${D.sid}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.csv`; document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  async function load() {
    if (!D.sid) return;
    try { D.d = await A.api("GET", `/api/noc/domain/${encodeURIComponent(D.sid)}`, undefined, {background: true}); }
    catch (e) { $("#pg-domain").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    try { D.mrx = D.d.match ? new RegExp(D.d.match, "i") : null; } catch { D.mrx = null; }
    if (!D.rows.length && D.d.recent.length) D.rows = D.d.recent.slice(0, MAXROWS);
    const tl = document.title; document.title = `${D.d.name} · 도메인 상세 · VCF AIops 관제`; void tl;
    $("#w-title").textContent = `${D.d.name} 상세`;
    render();
    if (!D.on) subscribe();
    if (D.tab === "pat") loadPat();
    if (D.deep) { const x = D.deep; D.deep = null; if (x.host) { D.host = x.host; render(); hist(x.host); } if (x.open) openEnt(x.open); }
  }
  function show(sid, deep) {
    if (D.sid !== sid) { D.rows = []; D.host = ""; D.q = ""; D.ptab = null; D.tab = "live"; D.paused = false; D.buf = 0; D.d = null; D.on = false; D.pat = null; D.patAt = 0;
      closeEnt(); $("#pg-domain").innerHTML = `<div class="wempty">불러오는 중…</div>`; }
    if (!deep && !D.sidShown) {                                // 첫 진입: /noc/d/<id>?host=<이름>&open=1
      const qs = new URLSearchParams(location.search), h = qs.get("host");
      if (h) deep = {host: qs.get("filter") === "0" ? "" : h, open: qs.get("open") === "1" ? h : ""};
    }
    D.sidShown = true; D.sid = sid; D.deep = deep || null;
    if (D.d && D.deep) { const x = D.deep; D.deep = null; if (x.host) { D.host = x.host; render(); hist(x.host); } if (x.open) openEnt(x.open); return; }
    load();
  }
  function focus(name, filter = true) { if (!D.sid) return; show(D.sid, {host: filter ? name : "", open: name}); }
  async function hist(host) {                                 // 호스트 필터 — 최근 6시간 과거분을 스트림에 채움
    try {
      const rows = await A.api("GET", `/api/noc/domain/${encodeURIComponent(D.sid)}/events?host=${encodeURIComponent(host)}&hours=6`, undefined, {background: true});
      if (D.host !== host) return;
      const seen = new Set(D.rows.map(r => `${r.ts}|${r.message}`));
      D.rows = [...D.rows, ...rows.filter(r => !seen.has(`${r.ts}|${r.message}`))].sort((a, b) => b.ts - a.ts).slice(0, MAXROWS * 2);
      if (D.tab === "live") { const s = $(".dm-sbody"); if (s) s.innerHTML = streamBody(); }
    } catch { /* 무시 */ }
  }
  function stop() { if (D.sid) A.wsSend(JSON.stringify({op: "untail"})); D.sid = null; D.on = false; closeEnt(); }
  function onMsg(m) {
    if (!D.sid) return;
    if (m.type === "snapshot") { D.on = false; subscribe(); return; }
    if (m.type === "tail") { onTail(m.data || []); return; }
    if ((m.type === "anomaly" && D.d && D.d.sources.includes(((m.data || {}).event || {}).source)) || m.type === "incident") {
      clearTimeout(D.rt); D.rt = setTimeout(load, 2000);
    }
  }
  setInterval(() => {                                          // 초당 유입(이 도메인)
    if (!D.sid) return;
    D.rate.push(D.tick); D.tick = 0; if (D.rate.length > 60) D.rate.shift();
    const el = $("#dm-eps"); if (el) el.textContent = N(D.rate.reduce((a, b) => a + b, 0));
  }, 1000);

  document.addEventListener("click", e => {
    const box = e.target.closest("#pg-domain"); if (!box || !D.d) return;
    if (e.target.closest("[data-close]")) { closeEnt(); return; }
    const ak = e.target.closest("[data-ack]");
    if (ak) { ak.disabled = true; A.api("POST", `/api/anomalies/${encodeURIComponent(ak.dataset.ack)}/ack`).then(() => { A.toast("확인 처리됨", "", "ok", 1800); load(); if (D.entName) openEnt(D.entName); })
      .catch(err => { ak.disabled = false; A.toast("확인 실패", err.message, "error", 3000); }); return; }
    const fl = e.target.closest("[data-filter]"); if (fl) { D.host = fl.dataset.filter; D.tab = "live"; render(); hist(D.host); return; }
    const tp = e.target.closest("[data-topo]");
    if (tp && window.NOCNAV && window.NOCSTACK) { e.preventDefault(); window.NOCSTACK.select(tp.dataset.topo); window.NOCNAV.go("topology"); return; }
    const en = e.target.closest("[data-ent]"); if (en && en.dataset.ent) { e.preventDefault(); openEnt(en.dataset.ent); return; }
    const pa = e.target.closest("[data-pat]");
    if (pa && D.pat) { const p = D.pat.patterns[Number(pa.dataset.pat)]; if (p) { D.q = patKey(p); D.min = "debug"; D.tab = "live"; render(); } return; }
    const pt = e.target.closest("[data-ptab]"); if (pt) { D.ptab = pt.dataset.ptab; render(); return; }
    const sb = e.target.closest("[data-stab]"); if (sb) { D.tab = sb.dataset.stab; render(); if (D.tab === "pat") loadPat(); return; }
    if (e.target.id === "dm-pause") { D.paused = !D.paused; D.buf = 0; render(); return; }
    if (e.target.id === "dm-csv") { csv(); return; }
    if (e.target.closest("#dm-host")) { D.host = ""; render(); return; }
    const li = e.target.closest(".dm-stream li"); if (li && !e.target.closest("[data-host].dm-t")) { li.classList.toggle("open"); return; }
    const h = e.target.closest("[data-host]");
    if (h && h.dataset.host) { D.host = D.host === h.dataset.host ? "" : h.dataset.host; D.tab = "live"; render(); if (D.host) hist(D.host); }
  });
  document.addEventListener("change", e => { if (e.target.id === "dm-min") { D.min = e.target.value; render(); } });
  document.addEventListener("keydown", e => {
    if (!D.sid || e.ctrlKey || e.metaKey || e.altKey || (e.target.closest && e.target.closest("input,textarea,select")) || document.querySelector(".modal,.npal")) return;
    if (e.key === "Escape" && D.ent) { closeEnt(); e.preventDefault(); }
    else if (e.key === "p" || e.key === "P") { D.paused = !D.paused; D.buf = 0; render(); }
  });
  document.addEventListener("input", e => { if (e.target.id === "dm-q") { D.q = e.target.value; clearTimeout(D.qt); D.qt = setTimeout(() => { const s = $(".dm-sbody"); if (s) s.innerHTML = streamBody(); }, 250); } });
  window.NOCDOM = {show, stop, load, onMsg, focus, current: () => D.sid};
})();
