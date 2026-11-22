/* 현장 센서(2.50.0) — 수집·연동 › 현장 센서(폰)
   안 쓰는 안드로이드 폰을 전산실·장비실 감시 소스로: 온도·습도·소리·진동·위치 이동·배터리·사진.
   장치 추가 → QR(폰 카메라로 찍으면 설치 안내 화면) → 앱이 등록 코드를 장치 토큰으로 교환 → 주기 전송. */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const st = {items: null, sel: "", metric: "temp_c", hours: 24, series: null, snaps: null, meta: null, err: "", timer: null};
  const ST = {ok: ["정상", "ok"], warn: ["경고", "warn"], crit: ["위험", "crit"], offline: ["무응답", "off"], pending: ["등록 대기", "pend"], retired: ["퇴역", "ret"]};
  const SENS = {temperature: "온도", humidity: "습도", pressure: "기압", light: "조도", sound: "소리 크기", motion: "진동·움직임", location: "위치",
    camera: "카메라", battery: "배터리·발열", wifi: "Wi-Fi 신호", proximity: "근접"};
  const CHART = ["temp_c", "temp_rate", "battery_health", "humidity", "sound_db", "tonal_pct", "vibration", "battery_pct", "moved_m", "light", "pressure", "wifi_rssi", "battery_c"];
  const T = ts => ts ? new Date(ts * 1000).toLocaleString("ko-KR", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "—";
  const ago = ts => { if (!ts) return "—"; const s = Date.now() / 1000 - ts; return s < 90 ? `${Math.max(1, Math.round(s))}초 전` : s < 5400 ? `${Math.round(s / 60)}분 전` : s < 172800 ? `${Math.round(s / 3600)}시간 전` : T(ts); };
  const M = k => (st.meta && st.meta.metrics[k]) || {label: k, unit: ""};
  const val = (k, v) => v == null ? "—" : k === "alarm_tone" ? (v ? "감지" : "없음") : k === "battery_health" ? (["정상", "주의", "과열·손상"][Math.round(v)] || v) : `${k === "charging" ? (v ? "예" : "아니오") : (Math.round(v * 10) / 10).toLocaleString()}${M(k).unit ? " " + M(k).unit : ""}`;

  async function load() {
    try {
      if (!st.meta) st.meta = await A.api("GET", "/api/sensors/meta", undefined, {background: true});
      if (!st.clusters) { st.clusters = []; A.api("GET", "/api/sensors/clusters", undefined, {background: true}).then(r => { st.clusters = r.items || []; }).catch(() => {}); }
      const r = await A.api("GET", "/api/sensors", undefined, {background: true});
      st.items = r.items; st.stale = r.stale_seconds || 300; st.err = "";
      if (st.sel && !st.items.find(x => x.id === st.sel)) st.sel = "";
      const bad = st.items.filter(x => ["crit", "offline", "warn"].includes(x.status)).length;
      const b = $("#sns-badge"); if (b) { b.hidden = !bad; b.textContent = bad; }
    } catch (e) { st.err = String(e.message || e); }
    draw();
    if (st.sel) detail(false);
  }
  async function detail(full = true) {
    if (!st.sel) return;
    try {
      const [s, p] = await Promise.all([A.api("GET", `/api/sensors/${encodeURIComponent(st.sel)}/series?metric=${st.metric}&hours=${st.hours}`, undefined, {background: true}),
        full || !st.snaps ? A.api("GET", `/api/sensors/${encodeURIComponent(st.sel)}/snaps?limit=24`, undefined, {background: true}) : Promise.resolve({items: st.snaps})]);
      st.series = s.points; st.snaps = p.items;
    } catch (e) { st.series = []; }
    draw();
  }

  function chip(s) { const [t, c] = ST[s] || [s, ""]; return `<span class="sn-chip sn-${c}">${t}</span>`; }

  function card(d) {
    const L = d.latest || {}, lv = d.levels || {};
    const cell = (k, lab) => L[k] == null ? "" : `<div class="sn-v ${lv[k] && lv[k] !== "ok" ? "sn-" + lv[k] : ""}"><small>${lab}</small><b>${val(k, L[k])}</b></div>`;
    return `<button class="sn-card ${d.id === st.sel ? "on" : ""} st-${d.status}" data-dev="${esc(d.id)}">
      <div class="sn-h"><b>${esc(d.name)}</b>${chip(d.status)}</div>
      <small class="sub">${esc(d.site || "위치 미지정")}${(d.config || {}).link_rack ? " · " + esc(d.config.link_rack) : ""} · ${d.enrolled ? `마지막 ${ago(d.last_seen)}` : d.enroll_pending ? "등록 코드 발급됨" : "등록 코드 만료 — 재발급"}${d.info && d.info.model ? ` · ${esc(d.info.model)}` : ""}</small>
      ${L.alarm_tone ? `<div class="sn-alarm">🔔 경보음 감지 ${L.tone_hz ? `(약 ${L.tone_hz}Hz)` : ""}</div>` : ""}
      ${L.queued ? `<div class="sn-q">폰에 밀린 값 ${L.queued}건 — 통신 불안정</div>` : ""}
      ${d.health && d.health.level === "warn" ? `<div class="sn-q">앱 점검 ${d.health.issues.filter(i => i.level === "warn").length}건 — ${esc(d.health.issues.find(i => i.level === "warn").text.split(" — ")[0])}</div>` : ""}
      <div class="sn-vals">${cell("temp_c", L.temp_src === "battery" ? "온도(추정)" : "온도")}${cell("humidity", "습도")}${cell("sound_db", "소리")}${cell("vibration", "진동")}${cell("battery_pct", "배터리")}${cell("moved_m", "이동")}${L.temp_rate != null && Math.abs(L.temp_rate) >= 0.5 ? cell("temp_rate", "상승 속도") : ""}</div>
      ${L.snap ? `<img class="sn-thumb" loading="lazy" alt="" src="/api/sensors/${encodeURIComponent(d.id)}/snap/${encodeURIComponent(L.snap)}">` : ""}
    </button>`;
  }

  function spark(pts, k) {
    if (!pts || pts.length < 2) return `<div class="empty small">이 기간 측정값이 없습니다</div>`;
    const W = 760, H = 180, P = 34;
    const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    let lo = Math.min(...ys), hi = Math.max(...ys);
    const th = ((st.items.find(x => x.id === st.sel) || {}).config || {}).thresholds || {}, t = th[k] || {};
    [t.warn_hi, t.crit_hi, t.warn_lo, t.crit_lo].forEach(v => { if (v != null && Math.abs(v - (lo + hi) / 2) < (hi - lo + 10) * 2) { lo = Math.min(lo, v); hi = Math.max(hi, v); } });
    if (hi === lo) { hi += 1; lo -= 1; }
    const x0 = xs[0], x1 = xs[xs.length - 1] || x0 + 1;
    const X = x => P + (x - x0) / (x1 - x0 || 1) * (W - P - 8), Y = y => 8 + (1 - (y - lo) / (hi - lo)) * (H - 30);
    const line = pts.map((p, i) => `${i ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
    const ref = (v, c, lab) => v == null || v < lo || v > hi ? "" : `<line x1="${P}" x2="${W - 8}" y1="${Y(v)}" y2="${Y(v)}" class="sn-ref ${c}"/><text x="${W - 10}" y="${Math.max(12, Y(v) - 3)}" text-anchor="end" class="sn-reft">${lab} ${v}</text>`;
    const fmt = v => (Math.round(v * 10) / 10).toLocaleString();
    return `<svg viewBox="0 0 ${W} ${H}" class="sn-chart" role="img" aria-label="${esc(M(k).label)} 추이">
      <text x="2" y="14" class="sn-ax">${fmt(hi)}</text><text x="2" y="${H - 24}" class="sn-ax">${fmt(lo)}</text>
      ${ref(t.crit_hi, "crit", "위험")}${ref(t.warn_hi, "warn", "경고")}${ref(t.warn_lo, "warn", "경고")}${ref(t.crit_lo, "crit", "위험")}
      <path d="${line}" class="sn-line"/>
      <text x="${P}" y="${H - 6}" class="sn-ax">${T(x0)}</text><text x="${W - 8}" y="${H - 6}" text-anchor="end" class="sn-ax">${T(x1)}</text></svg>`;
  }

  // 2.52.0 앱 안정성 점검(폰이 보내는 진단 기준)
  function healthView(d) {
    const h = d.health || {};
    if (!h.diag) return d.enrolled ? `<h5>앱 상태</h5><p class="sub">아직 진단 보고가 없습니다(앱 2.52.0 이상에서 보냄)</p>` : "";
    const g = h.diag, yes = v => v ? "✔" : "✖";
    const cr = (d.info || {}).crash;
    return `<h5>앱 상태 ${h.level === "warn" ? chip("warn") : chip("ok")} <small>앱 ${esc(g.app || "?")} · Android SDK ${g.sdk || "?"} · 보고 ${ago(h.reported)}</small></h5>
      <div class="sn-health">
        <span>${yes(g.battery_exempt)} 배터리 최적화 제외</span><span>${yes(g.plugged)} 충전 중</span><span>${yes(g.full)} 카메라·마이크·위치 사용</span>
        <span>${yes((g.perms || {}).notify)} 알림</span><span>깨우기 ${g.wake === "wakelock" ? "WakeLock(충전)" : "알람(배터리)"}</span>
        <span>가동 ${Math.round((g.uptime_s || 0) / 3600)}시간 · 재시작 ${g.restarts || 0} · 앱 시작 ${g.starts || 0}</span>
        <span>최대 지연 ${g.late_s || 0}초</span><span>네트워크 ${esc(g.net || "?")}</span><span>저장 공간 ${g.free_mb != null ? g.free_mb + "MB" : "?"}</span>
      </div>
      ${h.issues.length ? `<ul class="sn-issues">${h.issues.map(i => `<li class="${i.level}">${esc(i.text)}</li>`).join("")}</ul>` : `<p class="sub">장기 운영 점검 항목 모두 정상</p>`}
      ${cr ? `<details><summary>마지막 앱 오류 ${T(cr.ts)} — ${esc(cr.first)} <small>(누적 ${(d.info || {}).crashes || 1}회)</small></summary><pre class="sn-crash">${esc(cr.text)}</pre></details>` : ""}`;
  }

  function detailView(d) {
    const L = d.latest || {}, c = d.config || {}, info = d.info || {};
    const avail = info.sensors || [];
    const home = info.home;
    const order = Object.keys((st.meta || {}).metrics || {});
    const rows = Object.keys(L).filter(k => st.meta && st.meta.metrics[k] && !["lat", "lon"].includes(k)).sort((a, b2) => order.indexOf(a) - order.indexOf(b2))
      .map(k => `<tr><td>${esc(M(k).label)}</td><td class="mono">${val(k, L[k])}</td><td>${d.levels[k] && d.levels[k] !== "ok" ? chip(d.levels[k]) : ""}</td></tr>`).join("");
    const th = c.thresholds || {};
    const thRows = Object.keys(th).map(k => `<tr><td>${esc(M(k).label)} <small class="sub">${esc(M(k).unit)}</small></td>${["warn_lo", "crit_lo", "warn_hi", "crit_hi"].map(f =>
      `<td><input type="number" step="any" data-th="${k}" data-f="${f}" value="${th[k][f] ?? ""}" ${A.can("settings") ? "" : "disabled"}></td>`).join("")}</tr>`).join("");
    return `<div class="sn-detail">
      <div class="sn-dh"><h4>${esc(d.name)} ${chip(d.status)}</h4>
        <div>${A.can("operate") && d.enrolled && !d.retired && c.sensors.includes("camera") ? `<button class="btn-sm" data-act="snap">${d.snap_requested ? "촬영 대기 중…" : "지금 촬영"}</button>` : ""}
          ${A.can("settings") ? `<button class="btn-sm" data-act="reenroll">${d.enrolled ? "폰 다시 등록" : "등록 코드 재발급"}</button><button class="btn-sm" data-act="retire">퇴역</button><button class="btn-sm danger" data-act="delete">삭제</button>` : ""}</div></div>
      <small class="sub">${esc(d.site || "")}${d.note ? " · " + esc(d.note) : ""} · ${info.maker ? esc(info.maker) + " " : ""}${esc(info.model || "")}${info.android ? ` · Android ${esc(info.android)}` : ""}${info.app ? ` · 앱 ${esc(info.app)}` : ""}
        · 등록 ${T(d.enrolled)} · 마지막 ${ago(d.last_seen)}${d.last_ip ? ` (${esc(d.last_ip)})` : ""}${c.link_cluster ? ` · 클러스터 ${esc(c.link_cluster)}(같은 인시던트로 묶음)` : ""}
        ${info.backfill ? ` · 밀린 값 ${info.backfill.count}건 수신 ${ago(info.backfill.at)}` : ""}</small>
      ${avail.length ? `<div class="sn-avail">이 폰의 센서: ${avail.map(s => `<span class="label">${esc(s)}</span>`).join(" ")}</div>` : ""}
      <div class="sn-grid2">
        <div><h5>최신값 <small>${T(L.ts)}${L.temp_src === "battery" ? " · 온도는 배터리 온도 + 보정값(주변 온도 근사)" : ""}</small></h5>
          <table><tbody>${rows || `<tr><td><div class="empty small">아직 값이 없습니다</div></td></tr>`}</tbody></table>
          ${L.lat != null ? `<p class="sub">위치 ${L.lat}, ${L.lon} (±${Math.round(L.loc_acc || 0)}m)${home ? ` · 기준 ${home[0]}, ${home[1]}` : " · 기준 위치 없음"}
            ${A.can("settings") ? ` <button class="btn-sm" data-act="home">지금 위치를 기준으로</button>` : ""}</p>` : ""}</div>
        <div><h5>최근 사진 <small>${(st.snaps || []).length}장${c.snap_on_alert ? " · 경고·위험 때 자동 촬영" : ""}</small></h5>
          ${L.alert_snap ? `<p class="sn-alertsnap">경보 사진 ${T(L.alert_snap_ts)} <a href="/api/sensors/${encodeURIComponent(d.id)}/snap/${encodeURIComponent(L.alert_snap)}" target="_blank" rel="noopener">열기</a></p>` : ""}
          <div class="sn-snaps">${(st.snaps || []).slice(0, 12).map(s => `<a href="/api/sensors/${encodeURIComponent(d.id)}/snap/${encodeURIComponent(s.name)}" target="_blank" rel="noopener" title="${T(s.ts)} · ${esc(s.reason)} · ${Math.round(s.size / 1024)}KB">
            <img loading="lazy" alt="${T(s.ts)}" src="/api/sensors/${encodeURIComponent(d.id)}/snap/${encodeURIComponent(s.name)}"><small>${T(s.ts)}</small></a>`).join("") || `<div class="empty small">${c.sensors.includes("camera") ? "사진 없음 — '지금 촬영' 또는 자동 촬영 간격 설정" : "카메라 꺼짐"}</div>`}</div></div>
      </div>
      ${healthView(d)}
      <h5>추이 <a class="btn-sm" href="/api/sensors/${encodeURIComponent(d.id)}/export.csv?hours=${Math.max(st.hours, 24)}" download>CSV</a> <select id="sn-metric">${CHART.map(k => `<option value="${k}" ${k === st.metric ? "selected" : ""}>${esc(M(k).label)}</option>`).join("")}</select>
        <select id="sn-hours">${[[6, "6시간"], [24, "24시간"], [72, "3일"], [168, "7일"], [720, "30일"]].map(([h, l]) => `<option value="${h}" ${h === st.hours ? "selected" : ""}>${l}</option>`).join("")}</select></h5>
      ${spark(st.series, st.metric)}
      <details ${A.can("settings") ? "" : "open"}><summary>측정 설정·기준값 <small>폰은 다음 전송 때 받아 적용</small></summary>
        <div class="sn-form">
          <label>전송 간격(초) <input type="number" id="sn-int" min="15" max="3600" value="${c.interval_s}"></label>
          <label>자동 촬영(분, 0=끔) <input type="number" id="sn-snapm" min="0" max="1440" value="${c.snap_interval_m}"></label>
          <label>카메라 <select id="sn-cam"><option value="back" ${c.camera === "back" ? "selected" : ""}>후면</option><option value="front" ${c.camera === "front" ? "selected" : ""}>전면</option></select></label>
          <label>온도 기준 <select id="sn-tsrc">${[["auto", "자동(주변 센서 → 배터리)"], ["ambient", "주변 온도 센서만"], ["battery", "배터리 온도"]].map(([v, l]) => `<option value="${v}" ${c.temp_source === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
          <label>배터리 온도 보정(°C) <input type="number" step="0.5" id="sn-toff" value="${c.temp_offset_c}"></label>
          <label>소리 보정(dB) <input type="number" step="1" id="sn-soff" value="${c.sound_offset_db}"></label>
          <label>관련 클러스터 <input id="sn-clu" list="sn-clusters" value="${esc(c.link_cluster || "")}" placeholder="같은 인시던트로 묶을 vSphere 클러스터"></label>
          <label>랙·자리 <input id="sn-rack" value="${esc(c.link_rack || "")}" placeholder="예: A열 03번 랙 위"></label>
          <label>통신 끊김 때 폰에 쌓을 값(건) <input type="number" id="sn-buf" min="0" max="20000" value="${c.buffer_max}"></label>
          <label>출입 감지 조명(lx) 꺼짐 ≤ / 켜짐 ≥ <span class="sn-pair"><input type="number" id="sn-plo" value="${(c.presence_lux || [10, 60])[0]}"><input type="number" id="sn-phi" value="${(c.presence_lux || [10, 60])[1]}"></span></label>
        </div>
        <div class="sn-sens">
          <label class="chk"><input type="checkbox" id="sn-soa" ${c.snap_on_alert ? "checked" : ""}> 경고·위험 때 자동 촬영</label>
          <label class="chk"><input type="checkbox" id="sn-tone" ${c.tone_detect ? "checked" : ""}> 경보음 감지(2~4kHz 반복음)</label>
          <label class="chk"><input type="checkbox" id="sn-pres" ${c.presence_alert ? "checked" : ""}> 출입 감지(꺼진 방 조명이 켜지면)</label>
          <label class="chk"><input type="checkbox" id="sn-local" ${c.local_alarm ? "checked" : ""}> 위험이면 폰에서도 진동·알림(통신 끊겨도)</label>
        </div>
        <datalist id="sn-clusters">${(st.clusters || []).map(x => `<option value="${esc(x)}">`).join("")}</datalist>
        <div class="sn-sens">${(st.meta ? st.meta.sensors : []).map(s => `<label class="chk"><input type="checkbox" data-sens="${s}" ${c.sensors.includes(s) ? "checked" : ""}> ${esc(SENS[s] || s)}</label>`).join("")}</div>
        <table class="sn-th"><thead><tr><th>기준값</th><th>경고 하한</th><th>위험 하한</th><th>경고 상한</th><th>위험 상한</th></tr></thead><tbody>${thRows}</tbody></table>
        <small class="sub">보정값은 같은 자리의 온도계·소음계와 비교해 맞추세요. 배터리 온도는 충전 중 발열이 섞여 주변보다 높게 나옵니다. 소리는 크기(dB 추정)만 재고 녹음·전송하지 않습니다.</small>
        ${A.can("settings") ? `<p><button class="btn-sm solid" data-act="save">설정 저장</button></p>` : ""}
      </details>
    </div>`;
  }

  function draw() {
    const b = $("#sns-body"); if (!b) return;
    if (!st.items) { b.innerHTML = `<div class="empty">${st.err ? esc(st.err) : "불러오는 중…"}</div>`; return; }
    const cnt = s => st.items.filter(x => x.status === s).length;
    const head = `<div class="sn-sum">${["crit", "warn", "offline", "ok", "pending"].map(s => `<span>${chip(s)} ${cnt(s)}</span>`).join("")}
      <small class="sub">무응답 판정 ${Math.round((st.stale || 300) / 60)}분 · 경보는 이상징후·알림 채널로 갑니다(출처 sensor)</small></div>`;
    const sites = [...new Set(st.items.map(x => x.site || ""))];
    const list = st.items.length ? (sites.length > 1
      ? sites.map(si => { const g = st.items.filter(x => (x.site || "") === si); const w = g.filter(x => ["crit", "warn", "offline"].includes(x.status)).length;
          return `<h5 class="sn-site">${esc(si || "위치 미지정")} <small>${g.length}대${w ? ` · 확인 필요 ${w}` : ""}</small></h5><div class="sn-cards">${g.map(card).join("")}</div>`; }).join("")
      : `<div class="sn-cards">${st.items.map(card).join("")}</div>`)
      : `<div class="empty"><p><b>등록된 폰이 없습니다.</b></p><p>안 쓰는 안드로이드 폰(8.0 이상)을 전산실·장비실·지점 통신실에 충전기와 함께 두면 온도·습도·소리·진동·위치·사진을 보냅니다.</p>
         <p>${A.can("settings") ? `<button class="btn-sm solid" id="sns-add2">장치 추가</button>` : "관리자에게 장치 추가를 요청하세요."}</p></div>`;
    const d = st.items.find(x => x.id === st.sel);
    b.innerHTML = head + list + (d ? detailView(d) : "");
  }

  async function addDevice() {
    const v = await A.modal({title: "현장 센서 장치 추가", ok: "등록 코드 만들기", fields: [
      {id: "name", label: "이름", required: true, placeholder: "예: 본점 전산실 A열"},
      {id: "site", label: "위치(사이트)", placeholder: "예: 본점 3층 전산실"},
      {id: "note", label: "메모", placeholder: "예: 항온항습기 앞, 랙 A-03 위"}]});
    if (!v) return;
    try {
      const r = await A.api("POST", "/api/sensors", v);
      st.sel = r.device.id; st.snaps = null; st.series = null; await load(); showEnroll(r.device, r.enroll, r.expires);
    } catch (e) { A.fail("장치 추가", e); }
  }
  function showEnroll(dev, en, exp) {
    A.modal({title: `폰 등록 — ${dev.name}`, ok: "", cancel: "닫기", wide: true, html: `<div class="sn-enroll">
      <div class="sn-qr">${en.qr_svg || ""}</div>
      <div><ol>
        <li>감시에 쓸 안드로이드 폰(8.0 이상)의 <b>기본 카메라로 QR</b>을 찍어 설치 안내 화면을 엽니다.</li>
        <li><b>센서 앱(APK) 받기</b> → 설치(출처를 알 수 없는 앱 허용).</li>
        <li><b>앱에서 등록하기</b>를 누르면 서버 주소·코드가 채워져 등록됩니다.</li>
        <li>앱에서 카메라·마이크·위치·알림 권한을 허용하고, <b>충전기에 꽂아</b> 감시할 자리에 둡니다.</li></ol>
        <p>직접 입력 — 서버 <code>${esc(en.server)}</code><br>등록 코드 <code class="sn-code">${esc(en.code)}</code> <small class="sub">(${T(exp)}까지, 1회용)</small></p>
        <p class="sub">설치 안내 주소: <span class="mono">${esc(en.setup_url)}</span></p></div></div>`});
  }

  function wire() {
    const b = $("#sns-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", async e => {
      const c = e.target.closest("[data-dev]"); if (c) { st.sel = st.sel === c.dataset.dev ? "" : c.dataset.dev; st.series = null; st.snaps = null; draw(); if (st.sel) detail(); return; }
      if (e.target.id === "sns-add2") return addDevice();
      const a = e.target.closest("[data-act]"); if (!a) return;
      const id = st.sel, d = st.items.find(x => x.id === id); if (!d) return;
      try {
        if (a.dataset.act === "snap") { const r = await A.api("POST", `/api/sensors/${id}/snap-now`); A.ok("촬영 요청", `폰이 다음 전송(최대 ${r.next_push_within_s}초 안)에 사진을 보냅니다`); await load(); setTimeout(() => detail(), (r.next_push_within_s + 15) * 1000); }
        if (a.dataset.act === "reenroll") { if (d.enrolled && !await A.confirm("폰 다시 등록", "지금 폰의 장치 토큰을 폐기하고 새 등록 코드를 만듭니다. 폰 앱에서 다시 등록해야 측정이 이어집니다.")) return;
          const r = await A.api("POST", `/api/sensors/${id}/reenroll`); await load(); showEnroll(d, r.enroll, r.expires); }
        if (a.dataset.act === "retire") { if (!await A.confirm("퇴역", "감시를 멈추고 토큰을 폐기합니다. 기록·사진은 남습니다.")) return; await A.api("POST", `/api/sensors/${id}/retire`); await load(); }
        if (a.dataset.act === "delete") { if (!await A.confirm("삭제", "장치와 측정 기록·사진을 모두 지웁니다. 되돌릴 수 없습니다.", true)) return; await A.api("DELETE", `/api/sensors/${id}`); st.sel = ""; await load(); }
        if (a.dataset.act === "home") { await A.api("PUT", `/api/sensors/${id}`, {set_home: true}); A.ok("기준 위치", "지금 위치를 기준으로 정했습니다"); await load(); }
        if (a.dataset.act === "save") {
          const cfg = {interval_s: +$("#sn-int").value, snap_interval_m: +$("#sn-snapm").value, camera: $("#sn-cam").value, temp_source: $("#sn-tsrc").value,
            temp_offset_c: +$("#sn-toff").value, sound_offset_db: +$("#sn-soff").value,
            link_cluster: $("#sn-clu").value.trim(), link_rack: $("#sn-rack").value.trim(), buffer_max: +$("#sn-buf").value,
            presence_lux: [+$("#sn-plo").value, +$("#sn-phi").value], snap_on_alert: $("#sn-soa").checked, tone_detect: $("#sn-tone").checked,
            presence_alert: $("#sn-pres").checked, local_alarm: $("#sn-local").checked,
            sensors: [...b.querySelectorAll("[data-sens]")].filter(x => x.checked).map(x => x.dataset.sens), thresholds: {}};
          b.querySelectorAll("[data-th]").forEach(x => { (cfg.thresholds[x.dataset.th] = cfg.thresholds[x.dataset.th] || {})[x.dataset.f] = x.value === "" ? null : +x.value; });
          await A.api("PUT", `/api/sensors/${id}`, {config: cfg}); A.ok("설정 저장", "폰이 다음 전송 때 적용합니다"); await load();
        }
      } catch (err) { A.fail("현장 센서", err); }
    });
    b.addEventListener("change", e => {
      if (e.target.id === "sn-metric") { st.metric = e.target.value; detail(false); }
      if (e.target.id === "sn-hours") { st.hours = +e.target.value; detail(false); }
    });
  }
  function show() {
    document.querySelectorAll(".drawer").forEach(d => { if (d.id !== "drawer-sns") d.hidden = true; });
    $("#drawer-sns").hidden = false;
    wire(); draw(); load();
    clearInterval(st.timer); st.timer = setInterval(() => $("#drawer-sns").hidden ? clearInterval(st.timer) : load(), 20000);
  }
  const nav = document.getElementById("nav-sns"); if (nav) nav.onclick = show;
  const add = document.getElementById("sns-add"); if (add) add.onclick = addDevice;
  const rl = document.getElementById("sns-reload"); if (rl) rl.onclick = () => { st.snaps = null; load(); };
  A.api("GET", "/api/sensors", undefined, {background: true}).then(r => {       // 메뉴 배지
    const bad = r.items.filter(x => ["crit", "offline", "warn"].includes(x.status)).length, b = $("#sns-badge"); if (b) { b.hidden = !bad; b.textContent = bad; }
  }).catch(() => {});
  window.AIOPS_SENSORS = show;
})();
