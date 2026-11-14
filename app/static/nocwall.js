/* 관제 월 추가 페이지 — 인프라 지도(호스트·VM 상태 + VM 이동 애니메이션) · 이벤트·인시던트(도메인 추이·칸반·티커)
   · 보안(공격 출발지 버블·차단 추이·포트 히트맵) · AI·플랫폼(GPU 온도·대기열·호출량·작업 상태). 실시간 WebSocket + 주기 갱신 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const p2 = n => String(n).padStart(2, "0");
  const hm = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}`; };
  const hms = ts => { const d = new Date(ts * 1000); return `${hm(ts)}:${p2(d.getSeconds())}`; };
  const now = () => Date.now() / 1000;
  const N = v => (v || 0).toLocaleString();
  const dur = s => s < 3600 ? `${Math.floor(s / 60)}분` : s < 86400 ? `${Math.floor(s / 3600)}시간 ${Math.floor(s % 3600 / 60)}분` : `${Math.floor(s / 86400)}일`;
  const SEVR = {debug: 0, info: 1, warning: 2, error: 3, critical: 4};
  const MV = {vmotion: "vMotion", drs: "DRS", svmotion: "Storage vMotion", relocate: "콜드 이전", ha_restart: "HA 재시작", ha_failed: "HA 실패", ha_reset: "HA 리셋",
              ha_reset_failed: "HA 리셋 실패", host_failed: "호스트 장애", host_isolated: "호스트 격리", move_failed: "이동 실패", detected: "위치 변경", created: "VM 생성", cloned: "VM 복제", deployed: "템플릿 배포", registered: "VM 등록", removed: "VM 삭제", renamed: "이름 변경", create_failed: "생성 실패", detected_new: "새 VM 감지", detected_gone: "VM 사라짐", power_on: "전원 켬", power_off: "전원 끔", suspended: "일시 중단", reset: "리셋", guest_shutdown: "게스트 종료", guest_reboot: "게스트 재시작", reconfigured: "구성 변경", snapshot_create: "스냅샷 생성", snapshot_remove: "스냅샷 삭제", snapshot_remove_all: "스냅샷 모두 삭제", snapshot_revert: "스냅샷 되돌림"};
  const HA = new Set(["ha_restart", "ha_failed", "ha_reset", "ha_reset_failed", "host_failed", "host_isolated"]);
  const LIFE = new Set(["power_on", "power_off", "suspended", "reset", "guest_shutdown", "guest_reboot", "reconfigured", "snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert", "created", "cloned", "deployed", "registered", "removed", "renamed", "create_failed", "detected_new", "detected_gone"]);
  const ST_CLS = {down: "st-down", warn: "st-warn", ok: "st-ok", idle: "st-maint", maint: "st-maint"};
  const st = {page: null, me: null, sound: false, eps: [], audio: null};

  function animNum(el, to, fmt = N) {
    if (!el) return;
    const from = Number(el.dataset.v || 0); el.dataset.v = to;
    if (from === to) { el.textContent = fmt(to); return; }
    const t0 = performance.now(), d = 700;
    const step = t => { const p = Math.min(1, (t - t0) / d), e = 1 - Math.pow(1 - p, 3); el.textContent = fmt(Math.round(from + (to - from) * e)); if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
    if (to > from) { const c = el.closest(".bign"); if (c) { c.classList.remove("bump"); void c.offsetWidth; c.classList.add("bump"); } }
  }
  function beep(f = 880) {
    if (!st.sound) return;
    try { st.audio = st.audio || new AudioContext(); const o = st.audio.createOscillator(), g = st.audio.createGain(); o.frequency.value = f; g.gain.value = .08;
      o.connect(g); g.connect(st.audio.destination); o.start(); o.stop(st.audio.currentTime + .25); } catch { /* 무시 */ }
  }
  function lineSvg(vals, {w = 600, h = 120, color = "#4fb3e0", area = true, max = null, mark = null} = {}) {
    const v = (vals || []).map(x => Number(x) || 0); if (!v.length) return "";
    const mx = Math.max(1, max ?? Math.max(...v)), n = v.length, X = i => (n === 1 ? w : i / (n - 1) * w), Y = x => h - 4 - x / mx * (h - 10);
    const pts = v.map((x, i) => `${X(i).toFixed(1)},${Y(x).toFixed(1)}`).join(" ");
    const last = v[n - 1];
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      ${[0.5, 1].map(f => `<line x1="0" x2="${w}" y1="${Y(mx * f)}" y2="${Y(mx * f)}" stroke="rgba(255,255,255,.06)"/>`).join("")}
      ${mark != null ? `<line x1="0" x2="${w}" y1="${Y(mark)}" y2="${Y(mark)}" stroke="#f2c200" stroke-dasharray="4 4" stroke-width="1"/>` : ""}
      ${area ? `<polygon points="0,${h} ${pts} ${w},${h}" fill="${color}" opacity=".16"/>` : ""}
      <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
      <circle cx="${X(n - 1)}" cy="${Y(last)}" r="4" fill="${color}" vector-effect="non-scaling-stroke"><animate attributeName="r" values="3;6;3" dur="1.6s" repeatCount="indefinite"/></circle></svg>`;
  }

  // ======================================================================== 인프라 지도
  const INF = {d: null, timer: null, feed: []};
  async function infLoad() {
    try { INF.d = await A.api("GET", "/api/noc/infra", undefined, {background: true}); } catch (e) { $("#pg-infra").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    INF.feed = INF.d.moves.slice(0, 40);
    infRender();
  }
  const barCls = v => v >= 90 ? "vhi" : v >= 75 ? "hi" : "";
  function hostHtml(h) {
    const vm = h.vms.map(v => `<i class="${v.p ? "" : "off"} ${v.a >= 2 ? "a" + v.a : ""}" title="${esc(v.n)}${v.p ? "" : " (꺼짐)"}${v.a >= 2 ? " — 열린 이상징후" : ""}"></i>`).join("");
    return `<div class="inf-h ${ST_CLS[h.state]}" data-host="${esc(h.name)}"><div class="inf-hn"><span title="${esc(h.name)}">${esc(h.name)}</span><small>VM ${h.vm_on}/${h.vm_total}${h.state === "maint" ? " · 유지보수" : ""}</small></div>
      <div class="inf-bars"><span>CPU</span><i><b class="${barCls(h.cpu)}" style="width:${h.cpu ?? 0}%"></b></i><em>${h.cpu ?? "-"}%</em><span>MEM</span><i><b class="${barCls(h.mem)}" style="width:${h.mem ?? 0}%"></b></i><em>${h.mem ?? "-"}%</em></div>
      <div class="inf-vms">${vm}${h.vm_total > h.vms.length ? `<span class="inf-more">+${h.vm_total - h.vms.length}</span>` : ""}</div></div>`;
  }
  function infRender() {
    const d = INF.d, box = $("#pg-infra");
    if (!d.clusters.length) { box.innerHTML = `<div class="wempty">vCenter 커넥터가 없거나 인벤토리 수집 전입니다. 운영 설정 › 커넥터에서 vCenter Server 를 추가하세요.</div>`; return; }
    const hosts = d.clusters.reduce((a, c) => a + c.hosts.length, 0), vms = d.clusters.reduce((a, c) => a + c.hosts.reduce((x, h) => x + h.vm_total, 0), 0);
    $("#w-sub").textContent = `클러스터 ${d.clusters.length} · 호스트 ${hosts} · VM ${N(vms)}`;
    const scroll = ($(".inf-clusters", box) || {}).scrollTop || 0;
    box.innerHTML = `<div class="inf-wrap"><div class="inf-clusters">${d.clusters.map(c => `<section class="wcard inf-cl ${ST_CLS[c.state]}">
        <h3>${esc(c.name)} <small>${esc(c.vcenter)}</small>${c.drs ? '<span class="badge">DRS</span>' : ""}${c.ha ? '<span class="badge">HA</span>' : ""}${c.vsan ? '<span class="badge">vSAN</span>' : ""}<span class="gap"></span>
        <small>호스트 ${c.hosts.length} · VM ${N(c.hosts.reduce((x, h) => x + h.vm_total, 0))}${c.hosts.some(h => h.state === "down") ? ` · <b style="color:var(--crit)">장애 ${c.hosts.filter(h => h.state === "down").length}</b>` : ""}</small></h3>
        <div class="inf-hosts">${c.hosts.map(hostHtml).join("")}</div></section>`).join("")}</div>
      <aside class="inf-side"><section class="wcard"><h3>범례</h3><div class="inf-legend"><span><i style="background:#3f6b33"></i>VM 켜짐</span><span><i style="background:#3a4a52"></i>꺼짐</span>
        <span><i style="background:var(--warn)"></i>경고</span><span><i style="background:var(--err)"></i>오류</span><span><i style="background:var(--crit)"></i>위험</span><span>호스트 위 띠 = 상태 · 막대 = CPU/메모리</span></div></section>
        <section class="wcard" style="flex:1;min-height:0"><h3>VM 액티비티 <small>실시간 — 이동은 호스트 사이를 날아가고, 생성·삭제는 해당 호스트가 깜빡입니다</small></h3><ol class="mv-feed" id="mv-feed">${INF.feed.map(feedLi).join("") || `<li class="r">최근 1시간 VM 액티비티 없음</li>`}</ol></section></aside></div>`;
    const cl = $(".inf-clusters", box); if (cl) cl.scrollTop = scroll;
  }
  const feedLi = r => `<li class="${HA.has(r.type) ? "ha" : ""}"><span class="t">${hms(r.ts)}</span><b>${esc(MV[r.type] || r.type)}</b> ${esc(r.vm || "")}<span class="r">${LIFE.has(r.type) ? esc(r.to_host || r.from_host || "") : `${esc(r.from_host || "?")} → ${esc(r.to_host || "?")}`}${r.cluster ? " · " + esc(r.cluster) : ""}</span></li>`;
  const tile = name => name ? $(`#pg-infra [data-host="${CSS.escape(name)}"]`) : null;
  function fly(r) {
    const src = tile(r.from_host), dst = tile(r.to_host), ha = HA.has(r.type);
    const flash = el => { if (!el) return; const c = ha ? "flash-ha" : "flash"; el.classList.add(c); setTimeout(() => el.classList.remove(c), 1800); };
    if (!src || !dst || src === dst) { flash(dst || src); return; }
    A.reveal(dst);
    setTimeout(() => {
      const a = src.getBoundingClientRect(), b = dst.getBoundingClientRect();
      const x0 = a.left + a.width / 2, y0 = a.top + a.height / 2, x1 = b.left + b.width / 2, y1 = b.top + b.height / 2;
      const dist = Math.hypot(x1 - x0, y1 - y0), cx = (x0 + x1) / 2, cy = Math.min(y0, y1) - Math.max(60, dist * 0.3);
      const layer = $("#fly");
      const svgNS = "http://www.w3.org/2000/svg";
      const svg = document.createElementNS(svgNS, "svg"); svg.setAttribute("class", "fly-trail");
      const path = document.createElementNS(svgNS, "path");
      path.setAttribute("d", `M${x0},${y0} Q${cx},${cy} ${x1},${y1}`); path.setAttribute("fill", "none");
      path.setAttribute("stroke", ha ? "#ff5a4f" : "#4fb3e0"); path.setAttribute("stroke-width", "2"); path.setAttribute("stroke-dasharray", "6 6"); path.setAttribute("opacity", ".7");
      svg.appendChild(path); layer.appendChild(svg);
      const el = document.createElement("div"); el.className = `fly ${ha ? "ha" : r.type === "drs" ? "drs" : ""}`;
      el.innerHTML = `<i></i><span>${esc(r.vm || MV[r.type])}</span>`; layer.appendChild(el);
      const kf = [];
      for (let i = 0; i <= 40; i++) { const t = i / 40, x = (1 - t) * (1 - t) * x0 + 2 * (1 - t) * t * cx + t * t * x1, y = (1 - t) * (1 - t) * y0 + 2 * (1 - t) * t * cy + t * t * y1;
        kf.push({transform: `translate(${x - 7}px,${y - 7}px)`, opacity: i < 3 ? i / 3 : 1}); }
      const an = el.animate(kf, {duration: 2400, easing: "cubic-bezier(.45,.05,.35,1)"});
      an.onfinish = () => { el.remove(); svg.animate([{opacity: .7}, {opacity: 0}], {duration: 900}).onfinish = () => svg.remove(); flash(dst); };
      src.classList.add("flash"); setTimeout(() => src.classList.remove("flash"), 900);
    }, 350);
  }
  function infMove(r) {
    if (r.enriched) INF.feed = INF.feed.filter(x => x.key !== r.key);     // 출발/도착 보완된 기록 → 교체
    INF.feed = [r, ...INF.feed].slice(0, 40);
    const f = $("#mv-feed"); if (f) { if (r.enriched) f.innerHTML = INF.feed.map(feedLi).join(""); else { if (f.querySelector(".r:only-child")) f.innerHTML = ""; f.insertAdjacentHTML("afterbegin", feedLi(r)); while (f.children.length > 40) f.lastElementChild.remove(); } }
    if (st.page === "infra") fly(r);
    if (HA.has(r.type)) beep(660);
    clearTimeout(INF.rt); INF.rt = setTimeout(() => { if (st.page === "infra") infLoad(); }, 3500);
  }

  // ======================================================================== 이벤트·인시던트
  const EV = {noc: null, incs: [], timer: null};
  async function evLoad() {
    try {
      const [n, i] = await Promise.all([A.api("GET", "/api/noc", undefined, {background: true}), A.api("GET", "/api/incidents?days=14&limit=300", undefined, {background: true})]);
      EV.noc = n; EV.incs = (i || []).filter(x => ["open", "acknowledged", "investigating"].includes(x.status));
    } catch (e) { $("#pg-events").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    evRender();
  }
  function evRender() {
    const box = $("#pg-events"), s = EV.noc.slots;
    if (!$(".ev-wrap", box)) {
      box.innerHTML = `<div class="ev-wrap"><div class="ev-big">
          <div class="bign crit"><span>위험(미확인)</span><b id="ev-c">0</b><small id="ev-cs"></small></div>
          <div class="bign err"><span>오류(미확인)</span><b id="ev-e">0</b><small>최근 ${EV.noc.window_minutes}분</small></div>
          <div class="bign warn"><span>경고(미확인)</span><b id="ev-w">0</b><small>최근 ${EV.noc.window_minutes}분</small></div>
          <div class="bign inc"><span>열린 인시던트</span><b id="ev-i">0</b><small id="ev-is"></small></div>
          <div class="bign eps"><span>수집(초당)</span><b id="ev-eps">0</b><small id="ev-epss">이벤트 유입</small></div></div>
        <section class="wcard"><h3>도메인별 로그 유입 <small>최근 60분 · 분당 건수</small></h3><div class="dom-rows" id="ev-dom"></div></section>
        <section class="wcard"><h3>인시던트 보드 <small>SLA 막대: 접수(신규) / 해결(확인·조사) 기한 대비 경과</small></h3><div class="kanban" id="ev-kb"></div></section>
        <div class="ticker" id="ev-tk"><span class="lab">미확인 위험·오류</span><div class="run" id="ev-run"></div></div></div>`;
    }
    const c = {critical: 0, error: 0, warning: 0};
    s.forEach(x => { for (const k in c) c[k] += x.counts[k] || 0; });
    animNum($("#ev-c"), c.critical); animNum($("#ev-e"), c.error); animNum($("#ev-w"), c.warning); animNum($("#ev-i"), EV.incs.length);
    const worst = s.filter(x => x.counts.critical).map(x => x.name).join(" · ");
    $("#ev-cs").textContent = worst || "위험 없음";
    const breached = EV.incs.filter(i => (i.sla || {}).ack_breached || (i.sla || {}).resolve_breached).length;
    $("#ev-is").textContent = `SLA 초과 ${breached} · 위험 ${EV.incs.filter(i => i.severity === "critical").length}`;
    $("#w-sub").textContent = `도메인 ${s.length} · 미확인 ${c.critical + c.error + c.warning}`;
    $("#ev-dom").innerHTML = s.map(x => {
      const r = x.rate || [], cur = r[r.length - 1] || 0, avg = r.length ? Math.round(r.reduce((a, b) => a + b, 0) / r.length) : 0;
      const col = x.state === "down" ? "#ff5a4f" : x.state === "warn" ? "#f2c200" : x.state === "ok" ? "#4fb3e0" : "#6b7f88";
      return `<div class="dom ${ST_CLS[x.state]}"><span class="dn"><i></i>${esc(x.name)}</span>${lineSvg(r, {w: 600, h: 46, color: col})}<span class="dv"><b>${N(cur)}</b><small>평균 ${N(avg)}/분</small></span></div>`;
    }).join("");
    const cols = [["open", "신규"], ["acknowledged", "확인"], ["investigating", "조사 중"]];
    $("#ev-kb").innerHTML = cols.map(([k, l]) => { const xs = EV.incs.filter(i => i.status === k).sort((a, b) => SEVR[b.severity] - SEVR[a.severity] || a.created - b.created);
      return `<div class="kcol"><h4>${l}<span>${xs.length}</span></h4>${xs.slice(0, 14).map(i => kcard(i)).join("") || `<div class="wempty" style="padding:8px">없음</div>`}</div>`; }).join("");
    const top = s.flatMap(x => x.anomalies.filter(a => !a.ack && ["critical", "error"].includes(a.severity) && now() - a.last_seen < EV.noc.window_minutes * 60).map(a => ({...a, dom: x.name})))
      .sort((a, b) => SEVR[b.severity] - SEVR[a.severity] || b.last_seen - a.last_seen).slice(0, 25);
    const run = top.map(a => `<span class="${a.severity}"><b>${a.severity === "critical" ? "위험" : "오류"}</b>${esc(a.dom)} · ${esc(a.title)} <small>${hm(a.last_seen)}</small></span>`).join("");
    const r = $("#ev-run");
    if (r.dataset.k !== run) { r.dataset.k = run; r.innerHTML = run ? run + run : `<span>미확인 위험·오류 없음</span>`; r.style.setProperty("--dur", `${Math.max(30, top.length * 7)}s`); r.style.animationPlayState = run ? "running" : "paused"; }
  }
  function kcard(i) {
    const sla = i.sla || {}, t = now();
    const due = i.status === "open" ? sla.ack_due : sla.resolve_due;
    const p = due ? Math.min(1, (t - i.created) / Math.max(60, due - i.created)) : 0;
    const x = i.status === "open" ? sla.ack_breached : sla.resolve_breached;
    return `<div class="kc-i sev-${esc(i.severity)}"><b title="${esc(i.title)}">${esc(i.title)}</b>
      <div class="m"><span>${esc((i.hosts || []).slice(0, 2).join(", ") || i.cluster || "")}</span><span data-age="${i.created}">${dur(t - i.created)}</span></div>
      ${due ? `<div class="sla" title="${i.status === "open" ? "접수" : "해결"} 기한 ${new Date(due * 1000).toLocaleString()}"><i class="${x ? "x" : p > .75 ? "w" : ""}" style="width:${(x ? 1 : p) * 100}%"></i></div>` : ""}</div>`;
  }

  // ======================================================================== 보안
  const SC = {d: null, seen: new Set()};
  async function scLoad() {
    try { SC.d = await A.api("GET", "/api/security/fortigate?minutes=60", undefined, {background: true}); } catch (e) { $("#pg-security").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    scRender();
  }
  function pack(items, W, H) {           // 큰 것부터 나선형으로 겹치지 않게 배치
    const placed = [];
    for (const it of items) {
      let a = 0, rr = 0, ok = false, x = W / 2, y = H / 2;
      for (let k = 0; k < 2500 && !ok; k++) {
        x = W / 2 + rr * Math.cos(a) * 1.5; y = H / 2 + rr * Math.sin(a);
        ok = x - it.r > 2 && x + it.r < W - 2 && y - it.r > 2 && y + it.r < H - 2 && placed.every(p => Math.hypot(p.x - x, p.y - y) > p.r + it.r + 4);
        a += 0.35; rr += 0.9;
      }
      if (ok) placed.push({...it, x, y});
    }
    return placed;
  }
  function scRender() {
    const d = SC.d, box = $("#pg-security");
    if (!d.devices.length) { box.innerHTML = `<div class="wempty">FortiGate syslog 가 아직 없습니다. 장비에서 이 서버(514/udp)로 syslog 를 보내면 자동으로 인식합니다.</div>`; $("#w-sub").textContent = ""; return; }
    const k = d.kpi, last = k.per_min_last || {};
    if (!$(".sc-wrap", box)) {
      box.innerHTML = `<div class="sc-wrap"><div class="sc-big">
          <div class="bign crit"><span>공격 중 출발지</span><b id="sc-a">0</b><small id="sc-as"></small></div>
          <div class="bign err"><span>로그인 실패(60분)</span><b id="sc-l">0</b><small id="sc-ls"></small></div>
          <div class="bign warn"><span>차단(분당)</span><b id="sc-d">0</b><small id="sc-ds"></small></div>
          <div class="bign inc"><span>IPS·이상(60분)</span><b id="sc-i">0</b><small>서명·출발지별 묶음</small></div>
          <div class="bign eps"><span>장비</span><b id="sc-v">0</b><small id="sc-vs"></small></div></div>
        <section class="wcard" style="grid-row:span 2"><h3>무차별 대입 출발지 <small>원 크기 = 5분 실패 횟수 · 빨강 = 위험 · 주황 = 경보 · 보라 = 실패 후 로그인 성공 · 고리 = 공격 중</small></h3><div class="swarm" id="sc-sw"></div></section>
        <section class="wcard"><h3>차단 트래픽/분 <small>최근 60분</small></h3><div class="lchart" id="sc-c1"></div></section>
        <section class="wcard"><h3>로그인 실패/분 · 상위 차단 포트 <small>포트 색 진하기 = 건수</small></h3><div class="lchart" id="sc-c2" style="flex:0 0 90px"></div><div class="ports" id="sc-pt"></div></section></div>`;
    }
    animNum($("#sc-a"), k.attackers); animNum($("#sc-l"), k.login_fail); animNum($("#sc-d"), last.denied || 0); animNum($("#sc-i"), k.ips); animNum($("#sc-v"), k.devices);
    $("#sc-as").textContent = `관찰 ${k.bf_sources} · 창 ${d.config.bf_window / 60}분 ${d.config.bf_threshold}회↑`;
    $("#sc-ls").textContent = `분당 ${N(last.login_fail)}`; $("#sc-ds").textContent = `60분 ${N(k.denied)}`; $("#sc-vs").textContent = `온라인 ${k.online}`;
    $("#w-sub").textContent = d.devices.map(x => x.name).join(", ");
    const sw = $("#sc-sw"), W = sw.clientWidth || 700, H = sw.clientHeight || 400;
    const bf = d.bruteforce.slice(0, 40), val = r => r.window || r.total / 10 || 1, vmax = Math.max(1, ...bf.map(val));
    const rmax = Math.max(24, Math.min(W, H) / (2.4 * Math.sqrt(Math.max(1, bf.length)) + 0.6)), rmin = Math.min(16, rmax * 0.5);
    const items = bf.map(r => ({...r, r: rmin + (rmax - rmin) * Math.sqrt(val(r) / vmax)})).sort((a, b) => b.r - a.r);
    const P = pack(items, W, H);
    sw.innerHTML = P.length ? `<svg viewBox="0 0 ${W} ${H}">${P.map(b => { const col = b.success_after ? "#d946ef" : b.level === "critical" ? "#ff5a4f" : b.active ? "#ff8a3d" : "#56707c";
        const nw = !SC.seen.has(b.srcip); SC.seen.add(b.srcip);
        return `<g class="bub ${nw ? "new" : ""}" transform="translate(${b.x.toFixed(1)},${b.y.toFixed(1)})"><title>${esc(b.srcip)} ${esc(b.country || "")} — 5분 ${b.window}회 · 누적 ${b.total} · 계정 ${esc((b.users || []).slice(0, 6).join(", "))}${b.success_after ? " · 실패 후 로그인 성공!" : ""}</title>
          ${b.active ? `<circle class="ring" r="${b.r.toFixed(1)}" stroke="${col}"/>` : ""}<circle class="core" r="${b.r.toFixed(1)}" fill="${col}" fill-opacity=".85" stroke="#0e1a20" stroke-width="2"/>
          <text y="${b.r > 26 ? -2 : 4}" style="font-size:${Math.max(12, Math.min(22, b.r / 5)).toFixed(0)}px">${esc(b.srcip)}</text>${b.r > 26 ? `<text class="sub" y="${Math.max(12, Math.min(26, b.r / 4.5)).toFixed(0)}" style="font-size:${Math.max(10.5, Math.min(17, b.r / 7)).toFixed(0)}px">${b.window}회${b.country ? " · " + esc(b.country.slice(0, 18)) : ""}</text>` : ""}</g>`; }).join("")}</svg>`
      : `<div class="wempty">로그인 실패 출발지 없음</div>`;
    $("#sc-c1").innerHTML = d.series.length ? lineSvg(d.series.map(p => p.denied), {w: 600, h: 140, color: "#ff8a3d"}) : `<div class="wempty">1분 집계 대기</div>`;
    $("#sc-c2").innerHTML = d.series.length ? lineSvg(d.series.map(p => p.login_fail), {w: 600, h: 80, color: "#ff5a4f"}) : "";
    const mx = Math.max(1, ...d.top_port.map(p => p.count));
    $("#sc-pt").innerHTML = d.top_port.slice(0, 24).map(p => `<div style="background:rgba(79,179,224,${(0.15 + 0.85 * p.count / mx).toFixed(2)})" title="${esc(p.port)} — ${N(p.count)}"><span>${esc(p.port)}</span><b>${N(p.count)}</b></div>`).join("") || `<div class="wempty">차단 없음</div>`;
  }

  // ======================================================================== AI·플랫폼
  const AI = {d: null, h: null};
  async function aiLoad() {
    try { [AI.d, AI.h] = await Promise.all([A.api("GET", "/api/ai", undefined, {background: true}), A.api("GET", "/api/health", undefined, {background: true})]); }
    catch (e) { $("#pg-ai").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    aiRender();
  }
  function gauge(v, max, {label = "", unit = "", warn = null, crit = null, mark = null} = {}) {
    const f = v == null ? 0 : Math.max(0, Math.min(1, v / max)), R = 80, cx = 100, cy = 100;
    const pt = t => [cx - R * Math.cos(Math.PI * t), cy - R * Math.sin(Math.PI * t)];
    const [x1, y1] = pt(f), col = v == null ? "#56707c" : crit != null && v >= crit ? "#ff5a4f" : warn != null && v >= warn ? "#f2c200" : "#56b62b";
    const mk = mark != null ? (() => { const [mx, my] = pt(Math.min(1, mark / max)); const [ix, iy] = [cx + (mx - cx) * 0.82, cy + (my - cy) * 0.82]; return `<line x1="${ix}" y1="${iy}" x2="${mx + (mx - cx) * 0.1}" y2="${my + (my - cy) * 0.1}" stroke="#f2c200" stroke-width="3"/>`; })() : "";
    return `<svg viewBox="0 0 200 120"><path d="M20,100 A80,80 0 0 1 180,100" fill="none" stroke="#0e1a20" stroke-width="16" stroke-linecap="round"/>
      ${f > 0 ? `<path d="M20,100 A80,80 0 0 1 ${x1.toFixed(1)},${y1.toFixed(1)}" fill="none" stroke="${col}" stroke-width="16" stroke-linecap="round" style="transition:all .8s"/>` : ""}${mk}
      <text class="gv" x="100" y="92">${v == null ? "-" : Math.round(v) + unit}</text><text class="gl" x="100" y="114">${esc(label)}</text></svg>`;
  }
  function aiRender() {
    const d = AI.d, h = AI.h, s = d.state, g = d.governor, q = d.queue, ps = d.patterns, box = $("#pg-ai");
    const lim = g.config.max_calls_per_hour || 0, calls = Object.values(g.calls_last_hour || {}).reduce((a, b) => a + b, 0);
    const reuse = (ps.reused_total || 0), analyzed = ps.analyzed || 0, saved = reuse + analyzed ? reuse / (reuse + analyzed) : 0;
    $("#w-sub").textContent = s.on ? `AI 분석 켜짐 · ${s.provider} / ${s.model}` : "AI 분석 꺼짐 — 규칙 탐지만";
    box.innerHTML = `<div class="ai-wrap">
      <section class="wcard ai-hero2 ${!s.on ? "st-maint" : g.hot ? "st-down" : s.provider_state === "ok" ? "st-ok" : "st-warn"}"><span class="big">${s.on ? "AI 분석 켜짐" : "AI 분석 꺼짐"}</span>
        <span class="desc">${s.on ? `새 로그 패턴만 LLM 으로 분석 · 같은 패턴은 저장된 결과 재사용 · 호출 간 ${g.config.min_interval}초, 시간당 ${lim || "무제한"}회${g.waiting ? ` · <b style="color:var(--warn)">${esc(g.waiting)}</b>` : ""}` : "모든 이상징후를 규칙 탐지로 처리 — LLM·GPU 사용 없음"}</span>
        <span class="desc" style="flex:none;text-align:right">${esc(s.provider || "")}<br><small>${esc(s.model || "")}${s.external ? " · 외부·가명화" : ""}</small></span></section>
      <section class="wcard"><h3>GPU 온도 <small>${g.config.gpu_metrics_url ? `중지 ${g.config.temp_pause}°C · 재개 ${g.config.temp_resume}°C` : "DCGM 주소 미설정(운영 설정 › AI 분석)"}</small></h3>
        <div class="gauge">${gauge((g.gpu || {}).temp_max, 100, {label: g.hot ? "과열 보호 — 자동 분석 중지" : `GPU ${(g.gpu || {}).gpus || 0}개 최고 온도`, unit: "°", warn: g.config.temp_pause - 8, crit: g.config.temp_pause, mark: g.config.temp_pause})}
        <p>${(g.gpu || {}).util_max != null ? `사용률 ${g.gpu.util_max}% · 전력 ${g.gpu.power_w || 0}W` : ""}${(g.vllm || {}).waiting != null ? ` · LLM 서버 대기 ${g.vllm.waiting} / 실행 ${g.vllm.running}` : ""}</p></div></section>
      <section class="wcard"><h3>분석 대기열 <small>노란 표시 = 부하 차단 시작(${q.limits.shed_at})</small></h3>
        <div class="gauge">${gauge(q.depth, Math.max(q.limits.shed_at * 1.5, 10), {label: q.rate_per_min ? `분당 ${q.rate_per_min}건 처리 · 예상 ${q.eta_min ?? "-"}분` : "대기", warn: q.limits.shed_at * 0.5, crit: q.limits.shed_at, mark: q.limits.shed_at})}
        <p>병합 ${N(q.stats.coalesced)} · 생략 ${N((q.stats.shed || 0) + (q.stats.quota || 0) + (q.stats.aged || 0) + (q.stats.full || 0))} · 최장 대기 ${Math.round(q.oldest_wait_s / 60)}분</p></div></section>
      <section class="wcard"><h3>호출량·재사용</h3><div class="meters">
        <div class="meter"><span>최근 1시간 LLM 호출<b>${calls}${lim ? ` / ${lim}` : ""}</b></span><i><b style="width:${lim ? Math.min(100, calls / lim * 100) : Math.min(100, calls)}%"></b></i></div>
        <div class="meter"><span>패턴 재사용으로 절약한 분석<b>${Math.round(saved * 100)}%</b></span><i><b style="width:${saved * 100}%;background:#56b62b"></b></i></div>
        <div class="meter"><span>로그 패턴(분석됨/전체)<b>${N(analyzed)} / ${N(ps.patterns)}</b></span><i><b style="width:${ps.patterns ? analyzed / ps.patterns * 100 : 0}%"></b></i></div>
        <div class="meter"><span>패턴 발생 누적 · 재사용<b>${N(ps.occurrences)} · ${N(reuse)}</b></span></div></div></section>
      <section class="wcard"><h3>LLM 공급자</h3><div class="provs">${Object.values(d.providers || {}).map(p => `<div class="prov ${p.state === "ok" ? "st-ok" : p.state === "unknown" ? "st-maint" : p.state === "degraded" ? "st-warn" : "st-down"}">
          <div><b>${esc(p.name)}</b><small>${esc(p.type)} · ${esc(p.model)}${p.external ? " · 외부" : " · 사내"}</small></div><div class="r">${p.latency_ms != null ? p.latency_ms + "ms" : "-"}<br>호출 ${N(p.calls)} · 실패 ${N(p.failures)}</div></div>`).join("") || `<div class="wempty">공급자 없음</div>`}</div></section>
      <section class="wcard"><h3>수집 처리량 <small id="ai-epsl">초당 이벤트 — 실시간</small></h3><div class="spark-big" id="ai-eps">${lineSvg(st.eps.length ? st.eps : [0], {w: 600, h: 160, color: "#56b62b"})}</div></section>
      <section class="wcard"><h3>내부 작업 <small>${h.ready ? "준비됨" : "준비 안 됨"} · 루프 지연 p99 ${h.lag.p99_ms}ms · 처리 대기 ${N(h.pipeline.high_queue + h.pipeline.low_queue)}</small></h3>
        <div class="jobs">${h.jobs.map(j => `<div class="${j.state === "running" ? "st-ok" : ["crashed", "stalled", "exited"].includes(j.state) ? "st-down" : "st-warn"}" title="${esc(j.last_error || j.state)}"><i></i>${esc(j.name)}${j.restarts ? ` <small>↻${j.restarts}</small>` : ""}</div>`).join("")}</div></section></div>`;
  }

  // ======================================================================== 공통: 머리 지표·라우팅·실시간
  async function pulse() {
    let k; try { k = await A.api("GET", "/api/noc/kpi", undefined, {background: true}); } catch { return; }
    const inc = k.incidents || {}, m = k.moves_1h || {}, ai = k.ai || {};
    const pp = (cls, l, v) => `<span class="pp ${cls}">${l} <b>${v}</b></span>`;
    $("#w-pulse").innerHTML = pp(inc.critical ? "crit" : Object.keys(inc).length ? "warn" : "ok", "인시던트", Object.values(inc).reduce((a, b) => a + b, 0))
      + pp(k.alarms.red ? "crit" : k.alarms.yellow ? "warn" : "ok", "vCenter 알람", k.alarms.total)
      + pp(m.ha ? "crit" : "ok", "HA(1시간)", m.ha || 0) + pp("", "VM 이동(1시간)", m.move || 0) + pp("", "생성·삭제(1시간)", `${m.created || 0}/${m.deleted || 0}`)
      + (k.security ? pp(k.security.attackers ? "crit" : "ok", "공격 출발지", k.security.attackers) : "")
      + pp(!ai.on ? "" : ai.hot ? "crit" : "ok", "AI", ai.on ? `켜짐${ai.queue ? " · " + ai.queue : ""}` : "꺼짐");
  }
  const PAGES = {
    infra: {title: "인프라 지도", load: infLoad, every: 20000},
    topology: {title: "물리·논리 토폴로지", load: () => window.NOCSTACK && window.NOCSTACK.load(), every: 30000},
    events: {title: "이벤트·인시던트", load: evLoad, every: 15000},
    security: {title: "보안(방화벽)", load: scLoad, every: 10000},
    ai: {title: "AI·플랫폼", load: aiLoad, every: 10000},
    network: {title: "네트워크 구성도", load: () => window.NOCNET && window.NOCNET.load(), every: 30000},
    exec: {title: "경영진 요약", load: () => window.NOCEXEC && window.NOCEXEC.load(), every: 60000},
  };
  let ptimer = null;
  function show(id) {
    const dom = String(id).startsWith("d-") && window.NOCDOM;
    if (!PAGES[id] && !dom) id = "infra";
    if (!dom && window.NOCDOM) window.NOCDOM.stop();
    st.page = dom ? "domain" : id;
    const sec = dom ? "pg-domain" : `pg-${id}`;
    $$(".wpage").forEach(p => { p.hidden = p.id !== sec; });
    const pg = $("#" + sec); pg.style.animation = "none"; void pg.offsetWidth; pg.style.animation = "";
    clearInterval(ptimer);
    if (dom) { window.NOCDOM.show(id.slice(2)); ptimer = setInterval(() => window.NOCDOM.load(), 10000); return; }
    $("#w-title").textContent = PAGES[id].title; document.title = `${PAGES[id].title} · VCF AIops 관제`;
    PAGES[id].load(); ptimer = setInterval(() => PAGES[id].load(), PAGES[id].every);
  }
  window.NOCWALL = {show};
  function onMsg(m) {
    if (window.NOCDOM && st.page === "domain") window.NOCDOM.onMsg(m);
    if (m.type === "status") {
      st.eps.push(m.data.stats.eps || 0); if (st.eps.length > 180) st.eps.shift();
      if (st.page === "events") animNum($("#ev-eps"), Math.round(m.data.stats.eps || 0));
      if (st.page === "ai") { const e = $("#ai-eps"); if (e) e.innerHTML = lineSvg(st.eps, {w: 600, h: 160, color: "#56b62b"}); }
    } else if (m.type === "vm_move") infMove(m.data);
    else if (m.type === "anomaly") {
      if (m.data.severity === "critical" && m.data.status !== "analyzed") beep();
      if (st.page === "events") { clearTimeout(EV.rt); EV.rt = setTimeout(evLoad, 2500); }
      if (st.page === "infra") { clearTimeout(INF.at); INF.at = setTimeout(infLoad, 4000); }
    } else if (m.type === "incident" && st.page === "events") { clearTimeout(EV.rt); EV.rt = setTimeout(evLoad, 1500); }
    else if (m.type === "ai_state" && st.page === "ai") { clearTimeout(AI.rt); AI.rt = setTimeout(aiLoad, 800); }
  }
  function onState(state, info) {
    const l = $("#n-live"), live = state === "live";
    l.classList.toggle("off", !live);
    l.textContent = live ? "실시간" : state === "resync" ? "재동기화 중" : `연결 끊김 ${Math.round(info.downSince ? (Date.now() - info.downSince) / 1000 : 0)}초`;
    const box = $("#n-conn"), frozen = !live && state !== "resync" && info.downSince && Date.now() - info.downSince > 5000;
    box.hidden = !frozen; if (frozen) box.textContent = "실시간 연결 끊김 — 재연결 중(화면 정보가 최신이 아닐 수 있음)";
  }
  setInterval(() => { $$("[data-age]").forEach(el => { el.textContent = dur(now() - Number(el.dataset.age)); }); }, 15000);
  $("#n-sound").onclick = e => { st.sound = !st.sound; e.target.setAttribute("aria-pressed", st.sound); e.target.textContent = st.sound ? "소리 끄기" : "소리 켜기"; if (st.sound) beep(); };
  $("#n-full").onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(() => {});
  const clock = () => { const d = new Date(); $("#n-time").textContent = `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    $("#n-date").textContent = d.toLocaleDateString((window.AIOPS_I18N || {}).lang === "en" ? "en-US" : "ko-KR", {year: "numeric", month: "long", day: "numeric", weekday: "short"}); };
  clock(); setInterval(clock, 1000);
  addEventListener("resize", () => { if (st.page === "network" && window.NOCNET) window.NOCNET.render(); if (st.page === "security" && SC.d) scRender(); if (st.page === "topology" && window.NOCSTACK) window.NOCSTACK.render(); });
  A.ready.then(me => {
    if (me === null) { location.replace(`/login?next=${encodeURIComponent(location.pathname + location.search)}`); return; }
    st.me = me; if (me.kiosk) $("#n-console").hidden = true;
    show(window.NOCNAV ? window.NOCNAV.current() : "infra");
    pulse(); setInterval(pulse, 20000);
    A.stream(onMsg, onState);
  });
})();
