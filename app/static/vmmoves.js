/* VM 액티비티 — VM 에 일어난 일을 한 곳에: 생성·복제·배포·등록·삭제·이름 변경 · 전원·구성 변경·스냅샷 · vMotion·DRS·Storage vMotion·HA
   위험 신호(업무 외 변경·대량 삭제/전원 끔·보호 VM·단명 VM) · 사용자별 활동 · VM 일대기(타임라인) · CSV · 규칙(관리자) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const mv = {hours: 24, type: "", flag: "", user: "", q: "", tab: "moves", sum: null, items: [], alarms: [], timer: null, tl: null};
  const n = v => (v || 0).toLocaleString();
  const dt = ts => { const d = new Date(ts * 1000); return `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${d.toTimeString().slice(0, 8)}`; };
  const dfull = ts => new Date(ts * 1000).toLocaleString();
  const ago = ts => { const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.max(0, Math.round(s))}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };
  const dur = s => s >= 86400 ? `${Math.floor(s / 86400)}일` : s >= 3600 ? `${Math.floor(s / 3600)}시간` : `${Math.max(1, Math.floor(s / 60))}분`;
  const S = a => new Set(a);
  const HA = S(["ha_restart", "ha_failed", "ha_reset", "ha_reset_failed", "host_failed", "host_isolated"]);
  const CREATE = S(["created", "cloned", "deployed", "registered", "detected_new"]), DELETE = S(["removed", "detected_gone"]);
  const POWER = S(["power_on", "power_off", "suspended", "reset", "guest_shutdown", "guest_reboot"]);
  const SNAP = S(["snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert"]);
  const CONFIG = S(["reconfigured", "renamed", ...SNAP]);
  const MOVE = S(["vmotion", "drs", "svmotion", "relocate", "detected"]);
  const FAIL = S(["move_failed", "create_failed"]);
  const LIFE = S([...CREATE, ...DELETE, "renamed", "create_failed"]);
  const GROUP = {create: CREATE, delete: DELETE, move: S([...MOVE, "move_failed"]), ha: HA, power: POWER, config: CONFIG, life: LIFE,
                 fail: S([...FAIL, "ha_failed", "ha_reset_failed"])};
  const CAT = t => HA.has(t) ? "ha" : FAIL.has(t) ? "fail" : CREATE.has(t) ? "create" : DELETE.has(t) ? "delete" : POWER.has(t) ? "power" : CONFIG.has(t) ? "config" : "move";
  const COLOR = {move: "#7fb2d0", create: "#5cb85c", delete: "#8a6fb3", power: "#9aa5ad", config: "#3d8fb8", ha: "#d9534f", fail: "#e0a800"};
  const CATL = {create: "생성", delete: "삭제", move: "이동", ha: "HA", power: "전원", config: "구성·스냅샷", fail: "실패"};
  const CLS = t => HA.has(t) ? (["ha_failed", "host_failed", "host_isolated", "ha_reset_failed"].includes(t) ? "ALERT" : "WARN") : FAIL.has(t) ? "WARN"
    : (t === "detected" || t === "detected_new" || t === "detected_gone") ? "NO_DATA" : DELETE.has(t) ? "DEL" : CREATE.has(t) ? "NEW"
    : CONFIG.has(t) ? "PENDING" : POWER.has(t) ? (t === "power_on" ? "OK" : "MUTED") : "OK";
  const ICON = t => CREATE.has(t) ? "＋ " : DELETE.has(t) ? "－ " : t === "renamed" || t === "reconfigured" ? "✎ " : SNAP.has(t) ? "◷ " : POWER.has(t) ? "⏻ " : "";
  const FL = {offhours: ["업무 외", "WARN"], bulk_delete: ["대량 삭제", "ALERT"], bulk_power_off: ["대량 전원 끔", "ALERT"], protected: ["보호 VM", "ALERT"], short_lived: ["단명 VM", "MUTED"],
              unplanned: ["변경 창 밖", "WARN"], in_window: ["변경 창 안", "OK"], pingpong: ["반복 이동", "WARN"]};
  const flags = r => String(r.flags || "").split(",").filter(Boolean);
  const flagHtml = r => flags(r).map(f => `<span class="mon-st ${(FL[f] || [f, "NO_DATA"])[1]} mv-flag">${esc((FL[f] || [f])[0])}</span>`).join("");
  const vmLink = (v, cls = "") => v ? `<a href="#" class="mv-vm ${cls}" data-tl="${esc(v)}" title="이 VM 의 일대기(타임라인)"><b>${esc(v)}</b></a>` : "-";
  const sub = r => r.source ? `<div class="small muted">${r.type === "renamed" ? "이전 이름" : r.type === "deployed" ? "템플릿" : "원본"}: ${esc(r.source)}</div>` : "";
  const detail = r => r.detail ? `<div class="small mv-detail">${esc(r.detail)}</div>` : "";
  const actor = r => esc(r.user || (r.type === "drs" ? "DRS" : HA.has(r.type) ? "vSphere HA" : ""));

  function filterQS() {
    const ty = GROUP[mv.type] ? [...GROUP[mv.type]].join(",") : mv.type;
    return `hours=${mv.hours}&type=${encodeURIComponent(ty)}&q=${encodeURIComponent(mv.q)}&user=${encodeURIComponent(mv.user)}&flag=${encodeURIComponent(mv.flag)}`;
  }
  async function load() {
    try {
      const [s, i, a] = await Promise.all([A.api("GET", `/api/vm/moves/summary?hours=${mv.hours}`, undefined, {background: true}),
        A.api("GET", `/api/vm/moves?${filterQS()}&limit=1000`, undefined, {background: true}),
        A.api("GET", "/api/vm/alarms", undefined, {background: true})]);
      mv.sum = s; mv.items = i.items; mv.alarms = a.items;
    } catch (e) { $("#mv-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }
  function chart(series, step) {
    if (!series.length) return "";
    const ks = ["move", "power", "config", "create", "delete", "fail", "ha"];
    const W = 760, H = 90, bw = W / series.length, mx = Math.max(1, ...series.map(p => ks.reduce((a, k) => a + (p[k] || 0), 0)));
    const bars = series.map((p, i) => { let y = H; return ks.map(k => { const h = (p[k] || 0) / mx * (H - 8); y -= h;
      return h ? `<rect x="${(i * bw).toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h.toFixed(1)}" fill="${COLOR[k]}"><title>${new Date(p.t * 1000).toLocaleString()} — ${ks.filter(x => p[x]).map(x => `${CATL[x]} ${p[x]}`).join(" · ")}</title></rect>` : ""; }).join(""); }).join("");
    return `<svg viewBox="0 0 ${W} ${H}" class="sec-chart" style="height:100px" preserveAspectRatio="none">${bars}</svg>
      <div class="sec-leg small">${ks.map(k => `<i style="background:${COLOR[k]}"></i>${CATL[k]}`).join(" ")} · ${step >= 86400 ? "1일" : step >= 10800 ? "3시간" : step >= 3600 ? "1시간" : "10분"} 단위 · 최대 ${mx}</div>`;
  }
  function render() {
    const s = mv.sum, L = s.labels, bt = s.by_type;
    $("#mv-sub").textContent = `— 최근 ${mv.hours < 48 ? mv.hours + "시간" : mv.hours / 24 + "일"} · ${n(s.total)}건`;
    const kpi = (l, v, subt, c = "", go = "") => `<div class="sec-kpi ${c}${go ? " click" : ""}"${go ? ` data-go="${go}" title="이력에서 이것만 보기"` : ""}><small>${l}</small><b>${n(v)}</b><span>${subt}</span></div>`;
    const red = mv.alarms.filter(a => a.status === "red").length, rc = s.risk_counts || {};
    const tabs = [["moves", `전체 이력 ${n(s.total)}`], ["risk", `위험 신호 ${n(s.risk_total)}`], ["life", `생성·삭제 ${n(s.created_total + s.deleted_total)}`],
      ["config", `구성·전원 ${n(s.config_total + s.power_total)}`], ["actors", `사용자별 ${n((s.actors || []).length)}`], ["ha", `HA 사건 ${s.ha_incidents.length}`],
      ["flows", "호스트 간 흐름"], ["alarms", `발생 중 알람 ${mv.alarms.length}`]];
    $("#mv-body").innerHTML = `
      <div class="sec-bar"><div class="inv-chips">${[[1, "1시간"], [6, "6시간"], [24, "24시간"], [168, "7일"], [720, "30일"]].map(([h, l]) => `<button data-h="${h}" class="${mv.hours === h ? "on" : ""}">${l}</button>`).join("")}</div>
        <div class="inv-chips">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${mv.tab === k ? "on" : ""}${k === "risk" && s.risk_total ? " hot" : ""}">${l}</button>`).join("")}</div></div>
      <div class="sec-kpis">
        ${kpi("VM 생성", s.created_total, `복제 ${n(bt.cloned)} · 배포 ${n(bt.deployed)} · 감지 ${n(bt.detected_new)}`, "", "type:create")}
        ${kpi("VM 삭제", s.deleted_total, `등록 해제 포함 · 감지 ${n(bt.detected_gone)}`, s.deleted_total ? "info" : "", "type:delete")}
        ${kpi("이동", s.move_total, `DRS ${n(bt.drs)} · vMotion ${n(bt.vmotion)} · Storage ${n(bt.svmotion)}`, "", "type:move")}
        ${kpi("HA", s.ha_total, `재시작 ${n(bt.ha_restart)} · 실패 ${n((bt.ha_failed || 0) + (bt.ha_reset_failed || 0))}`, (bt.ha_failed || bt.host_failed) ? "bad" : s.ha_total ? "warn" : "", "type:ha")}
        ${kpi("구성·스냅샷", s.config_total, `구성 ${n(bt.reconfigured)} · 스냅샷 ${n(["snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert"].reduce((a, k) => a + (bt[k] || 0), 0))} · 이름 ${n(bt.renamed)}`, "", "type:config")}
        ${kpi("전원", s.power_total, `켬 ${n(bt.power_on)} · 끔 ${n(bt.power_off)} · 리셋 ${n(bt.reset)}`, "", "type:power")}
        ${kpi("실패", s.fail_total, `이동 ${n(bt.move_failed)} · 생성 ${n(bt.create_failed)}`, s.fail_total ? "warn" : "", "type:fail")}
        ${kpi("업무 외 변경", s.offhours_total, `${esc(s.rules.business_hours)} · ${s.rules.business_days.length === 5 && s.rules.business_days[4] === 5 ? "평일" : "요일 " + s.rules.business_days.join(",")} 밖 사람 작업`, s.offhours_total ? "warn" : "", "flag:offhours")}
        ${kpi("위험 신호", s.risk_total, `대량 ${n((rc.bulk_delete || 0) + (rc.bulk_power_off || 0))} · 보호 VM ${n(rc.protected)} · 단명 ${n(rc.short_lived)}`, (rc.bulk_delete || rc.protected) ? "bad" : s.risk_total ? "warn" : "", "flag:risk")}
        ${kpi("발생 중 알람", mv.alarms.length, `위험(red) ${red}`, red ? "bad" : mv.alarms.length ? "warn" : "", "tab:alarms")}
      </div>
      <section class="sec-sec">${chart(s.series, s.step)}</section>
      ${({moves: movesHtml, risk: riskHtml, life: lifeHtml, config: configHtml, actors: actorsHtml, ha: haHtml, flows: flowsHtml, alarms: alarmsHtml}[mv.tab] || movesHtml)(s)}
      <aside class="mv-tl" id="mv-tl" ${mv.tl ? "" : "hidden"}>${mv.tl ? tlHtml(mv.tl) : ""}</aside>`;
  }
  // 2.45.1 실행 주체의 IP·클라이언트(로그인 이벤트·열린 세션으로 찾음, ESXi 로컬 계정은 호스트 관리 IP)
  const src = r => r.ip || r.client ? `<div class="mv-src" title="${esc(r.via || "")}">${r.ip ? `<a href="#" data-ip="${esc(r.ip)}" class="mono" title="이 IP 만 보기 — ${esc(r.via || "")}">${esc(r.ip)}</a>` : ""}${r.client ? ` <span class="muted">${esc(r.client)}</span>` : ""}</div>`
    : r.user && r.via ? `<div class="mv-src muted" title="${esc(r.via)}">IP 모름</div>` : "";
  function table(rows, L, opt = {}) {
    if (!rows.length) return `<p class="muted small">${opt.empty || "기록이 없습니다."}</p>`;
    return `<div class="tbl-x"><table class="vc-t mv-t"><thead><tr><th>시각</th><th>유형</th><th>VM</th><th>출발·이전</th><th></th><th>도착·현재</th><th>데이터스토어</th><th>클러스터</th><th>실행</th><th>vCenter</th></tr></thead><tbody>
      ${rows.map(r => `<tr class="${flags(r).some(f => f !== "offhours") ? "risk" : ""}"><td class="nowrap small" title="${esc(r.msg)}">${dt(r.ts)}</td><td><span class="mon-st ${CLS(r.type)}">${ICON(r.type)}${esc(L[r.type] || r.type)}</span>${flagHtml(r)}</td>
        <td>${vmLink(r.vm)}${r.vm ? ` <a href="#inv/vm/${encodeURIComponent(r.vm)}" data-inv="${esc(r.vm)}" class="mv-inv" title="인벤토리에서 보기">↗</a>` : ""}${sub(r)}${detail(r)}</td>
        <td class="mono small">${esc(r.from_host || "-")}</td><td>${DELETE.has(r.type) ? "✕" : (r.from_host || r.to_host) && !(POWER.has(r.type) || CONFIG.has(r.type) || CREATE.has(r.type)) ? "→" : ""}</td>
        <td class="mono small">${esc(r.to_host || (DELETE.has(r.type) ? "(삭제됨)" : "-"))}</td>
        <td class="small">${r.from_ds && r.to_ds && r.from_ds !== r.to_ds ? `${esc(r.from_ds)} → ${esc(r.to_ds)}` : esc(r.to_ds || r.from_ds || "")}</td><td class="small">${esc(r.cluster)}</td>
        <td class="small">${r.user ? `<a href="#" data-user="${esc(r.user)}" title="이 사용자만 보기">${actor(r)}</a>` : actor(r)}${src(r)}</td><td class="small">${esc(r.vcenter)}</td></tr>`).join("")}</tbody></table></div>`;
  }
  function movesHtml(s) {
    const chips = [["", "전체"], ["create", "생성"], ["delete", "삭제"], ["move", "이동"], ["ha", "HA"], ["config", "구성·스냅샷"], ["power", "전원"], ["fail", "실패"], ["detected", "위치 변경 감지"]];
    return `<section class="sec-sec"><div class="mon-bar"><div class="inv-chips">${chips.map(([k, l]) => `<button data-ty="${k}" class="${mv.type === k ? "on" : ""}">${l}</button>`).join("")}</div>
      <div class="inv-chips">${[["", "표시 무관"], ["risk", "위험 신호"], ["offhours", "업무 외"], ["in_window", "변경 창 안"], ["unplanned", "변경 창 밖"]].map(([k, l]) => `<button data-fl="${k}" class="${mv.flag === k ? "on" : ""}">${l}</button>`).join("")}</div>
      ${mv.user ? `<span class="label">사용자 ${esc(mv.user)} <a href="#" data-user="">✕</a></span>` : ""}
      <input id="mv-q" placeholder="VM·호스트·사용자·IP·원본·변경 내용 검색" value="${esc(mv.q)}"></div>
      ${table(mv.items, s.labels, {empty: mv.q || mv.type || mv.flag || mv.user ? "조건에 맞는 이력이 없습니다." : "이 기간에 VM 액티비티 기록이 없습니다."})}
      ${mv.items.length >= 1000 ? `<p class="small muted">최근 1,000건만 표시 — 전체는 CSV 로 내려받으세요.</p>` : ""}
      <p class="small muted">vCenter 이벤트로 기록합니다 — 생성(VmCreated·VmCloned·VmDeployed·VmRegistered)·삭제(VmRemoved)·이름 변경(VmRenamed)·생성 실패(VmCloneFailed·VmDeployFailed), 전원(VmPoweredOn/Off·VmSuspended·VmResetting·VmGuestShutdown/Reboot), 구성 변경(VmReconfigured — vCPU·메모리·장치), 스냅샷(작업 요청 TaskEvent), 이동(VmMigrated·DrsVmMigrated·VmRelocated), HA. 이벤트가 없으면 인벤토리 비교로 '위치 변경·새 VM·사라짐 감지'. VM 이름을 누르면 일대기를 봅니다.</p></section>`;
  }
  function riskHtml(s) {
    const r = s.rules, rc = s.risk_counts || {};
    const card = (k, l, txt) => `<div class="mv-risk ${rc[k] ? "on" : ""}" data-flgo="${k}"><b>${n(rc[k])}</b><span>${l}</span><small>${txt}</small></div>`;
    return `<section class="sec-sec"><div class="mv-risks">
        ${card("bulk_delete", "대량 삭제", `한 사용자가 ${r.bulk_delete_minutes}분 안에 ${r.bulk_delete_count}대 이상 삭제 → 위험 이상징후`)}
        ${card("bulk_power_off", "대량 전원 끔", `${r.bulk_power_off_minutes}분 안에 ${r.bulk_power_off_count}대 이상 전원 끔 → 오류 이상징후`)}
        ${card("protected", "보호 VM 변경", r.protected.length ? `${r.protected.slice(0, 4).map(esc).join(", ")}${r.protected.length > 4 ? " …" : ""} — 삭제·전원 끔·구성·스냅샷 되돌림` : "보호 VM 패턴 미설정 — '위험 신호 규칙'에서 지정")}
        ${card("short_lived", "단명 VM", `생성 후 ${r.short_lived_hours}시간 안에 삭제 — 테스트 잔재·의심 작업 확인`)}
        ${card("unplanned", "변경 창 밖", r.change_window_check ? "유지보수 창(설정 › 유지보수 창) 밖의 사람 변경 — 승인 절차 확인" : "변경 창 점검 꺼짐 — '위험 신호 규칙'에서 켬")}
        ${card("pingpong", "반복 이동", r.pingpong_count ? `한 VM 이 ${r.pingpong_minutes}분 안에 ${r.pingpong_count}회 이상 이동 → 경고 이상징후(DRS 규칙·자원 경합)` : "꺼짐")}
      </div>
      <h4>위험 신호 이력</h4>${table(s.risks, s.labels, {empty: "이 기간에 위험 신호가 없습니다."})}
      <h4>업무 외 시간 변경 <small class="muted">(${esc(r.business_hours)}, 요일 ${r.business_days.join(",")}${r.holidays.length ? `, 휴일 ${r.holidays.length}일` : ""} 밖 · 서비스 계정 제외)</small></h4>
      ${table(s.offhours, s.labels, {empty: "업무 외 시간 사람 작업이 없습니다."})}
      <p class="small muted">대량 작업·보호 VM 은 이상징후로도 올라가 알림·인시던트 흐름을 탑니다. 서비스 계정(${r.service_accounts.slice(0, 3).map(esc).join(", ")} …)과 DRS·HA 처럼 사용자가 없는 작업은 업무 외·대량 판정에서 제외됩니다.</p></section>`;
  }
  function lifeHtml(s) {
    const L = s.labels, bt = s.by_type;
    const tbl = (rows, h) => rows.length ? `<table class="vc-t sec-top"><thead><tr><th>${h}</th><th>건수</th></tr></thead><tbody>${rows.map(r => `<tr><td><a href="#" data-user="${esc(r.user)}">${esc(r.user)}</a></td><td>${r.count}</td></tr>`).join("")}</tbody></table>` : `<p class="muted small">없음(사용자 정보가 있는 이벤트 기준)</p>`;
    const types = ["created", "cloned", "deployed", "registered", "detected_new", "removed", "detected_gone", "renamed", "create_failed"];
    const net = (s.created_total || 0) - (s.deleted_total || 0);
    return `<section class="sec-sec"><h4>유형별</h4><div class="inv-chips">${types.map(t => `<button data-ty="${t}" data-gom="1"><span class="mon-st ${CLS(t)}">${ICON(t)}${esc(L[t] || t)}</span> ${n(bt[t])}</button>`).join("")}</div>
      <p class="small muted">순증감 <b>${net >= 0 ? "+" : ""}${n(net)}대</b> (생성 ${n(s.created_total)} − 삭제 ${n(s.deleted_total)}). '감지' 항목은 이벤트 없이 인벤토리 비교로 찾은 것으로, 다른 vCenter 로 옮겨졌거나 인벤토리에서만 빠진 경우도 포함됩니다.</p></section>
      ${s.short_lived.length ? `<section class="sec-sec"><h4>단명 VM <small class="muted">생성 후 ${s.rules.short_lived_hours}시간 안에 삭제</small></h4>${table(s.short_lived, L)}</section>` : ""}
      <div class="sec-two"><section class="sec-sec"><h4>생성한 사용자</h4>${tbl(s.creators || [], "사용자")}</section><section class="sec-sec"><h4>삭제한 사용자</h4>${tbl(s.deleters || [], "사용자")}</section></div>`;
  }
  function configHtml(s) {
    const L = s.labels, rows = mv.items.filter(r => CONFIG.has(r.type) || POWER.has(r.type));
    const top = s.top_config_vms || [];
    return `<div class="sec-two"><section class="sec-sec"><h4>자주 바뀐 VM <small class="muted">구성·이름·스냅샷</small></h4>${top.length ? `<table class="vc-t sec-top"><thead><tr><th>VM</th><th>건수</th></tr></thead><tbody>${top.map(v => `<tr><td>${vmLink(v.vm)}</td><td>${v.count}</td></tr>`).join("")}</tbody></table>` : `<p class="muted small">없음</p>`}</section>
      <section class="sec-sec"><h4>유형별</h4><div class="inv-chips">${["reconfigured", "renamed", "snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert", "power_on", "power_off", "suspended", "reset", "guest_shutdown", "guest_reboot"].map(t => `<button data-ty="${t}" data-gom="1"><span class="mon-st ${CLS(t)}">${ICON(t)}${esc(L[t])}</span> ${n(s.by_type[t])}</button>`).join("")}</div>
      <p class="small muted">구성 변경은 VmReconfiguredEvent 의 configSpec(vCPU·메모리·장치 추가/제거/변경, 디스크 크기)과 configChanges(vSphere 6.5+)로 요약합니다. 스냅샷은 작업 요청 시점(TaskEvent)이라 실패한 요청도 포함될 수 있습니다.</p></section></div>
      <section class="sec-sec"><h4>최근 구성·전원 변경</h4>${mv.type || mv.flag || mv.user || mv.q ? `<p class="small muted">이력 필터가 적용된 상태입니다.</p>` : ""}${table(rows.slice(0, 300), L, {empty: "이 기간에 구성·전원 변경이 없습니다."})}</section>`;
  }
  function actorsHtml(s) {
    const a = s.actors || [];
    if (!a.length) return `<p class="muted small">이 기간에 활동이 없습니다.</p>`;
    const ks = ["create", "delete", "move", "config", "power", "ha", "fail"];
    const mx = Math.max(1, ...a.map(x => x.total));
    return `<section class="sec-sec"><div class="tbl-x"><table class="vc-t"><thead><tr><th>사용자</th><th>접속 IP·클라이언트</th><th>구분</th><th>건수</th><th>분포</th><th>업무 외</th><th>위험</th><th>VM 수</th><th>마지막</th></tr></thead><tbody>
      ${a.map(x => `<tr class="${x.risk ? "risk" : ""}"><td>${x.user ? `<a href="#" data-user="${esc(x.user)}"><b>${esc(x.user)}</b></a>` : `<span class="muted">(사용자 없음 — DRS·HA·시스템)</span>`}</td>
        <td class="small">${(x.ips || []).map(i => `<a href="#" data-ip="${esc(i)}" class="mono">${esc(i)}</a>`).join(", ") || "-"}${(x.clients || []).length ? `<div class="muted">${x.clients.map(esc).join(", ")}</div>` : ""}</td>
        <td class="small">${x.service ? "서비스·시스템" : "사람"}</td><td>${n(x.total)}</td>
        <td><div class="mv-dist" style="width:${Math.max(8, x.total / mx * 100)}%">${ks.filter(k => x.cats[k]).map(k => `<i style="flex:${x.cats[k]};background:${COLOR[k]}" title="${CATL[k]} ${x.cats[k]}"></i>`).join("")}</div></td>
        <td>${x.offhours ? `<span class="mon-st WARN">${x.offhours}</span>` : "-"}</td><td>${x.risk ? `<span class="mon-st ALERT">${x.risk}</span>` : "-"}</td><td>${n(x.vms)}</td><td class="small">${ago(x.last)}</td></tr>`).join("")}</tbody></table></div>
      <div class="sec-leg small">${ks.map(k => `<i style="background:${COLOR[k]}"></i>${CATL[k]}`).join(" ")} · 사용자를 누르면 그 사용자의 이력만 봅니다.</div></section>`;
  }
  function haHtml(s) {
    const inc = s.ha_incidents, L = s.labels;
    if (!inc.length) return `<p class="muted small">이 기간에 vSphere HA 사건이 없습니다.</p>`;
    return `<section class="sec-sec">${inc.map(g => `<div class="mv-inc"><div class="mv-inc-h"><b>${esc(g.host)}</b>${g.cluster ? ` <span class="label">${esc(g.cluster)}</span>` : ""}
        <span class="small muted">${dt(g.first)} ~ ${dt(g.last)} · ${ago(g.last)}</span><span class="gap"></span>${Object.entries(g.types).map(([t, c]) => `<span class="mon-st ${CLS(t)}">${esc(L[t] || t)} ${c}</span>`).join(" ")}</div>
        <div class="small">VM ${g.vm_count}대: ${g.vms.map(v => vmLink(v)).join(", ")}${g.vm_count > g.vms.length ? " …" : ""}</div>
        ${Object.keys(g.targets).length ? `<div class="small muted">재시작 위치: ${Object.entries(g.targets).map(([h, c]) => `${esc(h)}(${c})`).join(", ")}</div>` : ""}</div>`).join("")}</section>`;
  }
  function flowsHtml(s) {
    const mx = Math.max(1, ...s.flows.map(f => f.count));
    return `<div class="sec-two"><section class="sec-sec"><h4>호스트 간 흐름(출발 → 도착)</h4>${s.flows.length ? `<table class="vc-t sec-top"><thead><tr><th>출발</th><th>도착</th><th>건수</th></tr></thead><tbody>${s.flows.map(f => `<tr><td class="mono small">${esc(f.from)}</td><td class="mono small">${esc(f.to)}</td><td><div class="sec-barv"><i style="width:${f.count / mx * 100}%;background:#9cc3dc"></i><span>${f.count}</span></div></td></tr>`).join("")}</tbody></table>` : `<p class="muted small">없음</p>`}</section>
      <section class="sec-sec"><h4>자주 옮겨진 VM</h4>${s.top_vms.length ? `<table class="vc-t sec-top"><thead><tr><th>VM</th><th>건수</th></tr></thead><tbody>${s.top_vms.map(v => `<tr><td>${vmLink(v.vm)}</td><td>${v.count}</td></tr>`).join("")}</tbody></table><p class="small muted">짧은 시간에 자주 옮겨지는 VM 은 DRS 규칙·자원 경합(성능 SLI)을 확인하세요.</p>` : `<p class="muted small">없음</p>`}</section></div>`;
  }
  function alarmsHtml() {
    if (!mv.alarms.length) return `<p class="muted small">발생 중인 vCenter 알람이 없습니다.</p>`;
    return `<section class="sec-sec"><div class="tbl-x"><table class="vc-t"><thead><tr><th>상태</th><th>알람</th><th>대상</th><th>종류</th><th>발생</th><th>확인</th><th>vCenter</th></tr></thead><tbody>
      ${mv.alarms.map(a => `<tr><td><span class="mon-st ${a.status === "red" ? "ALERT" : a.status === "yellow" ? "WARN" : "OK"}">${esc(a.status)}</span></td><td><b>${esc(a.alarm)}</b></td>
        <td>${a.etype === "VirtualMachine" ? vmLink(a.entity) : esc(a.entity)}</td><td class="small">${esc({VirtualMachine: "VM", HostSystem: "호스트", ClusterComputeResource: "클러스터", Datastore: "데이터스토어", Datacenter: "데이터센터", Folder: "폴더"}[a.etype] || a.etype)}</td>
        <td class="small">${dt(a.ts)} · ${ago(a.ts)}</td><td>${a.acknowledged ? "확인됨" : "-"}</td><td class="small">${esc(a.vcenter)}</td></tr>`).join("")}</tbody></table></div></section>`;
  }
  // ---------------------------------------------------------------- VM 일대기
  function tlHtml(t) {
    if (t.loading) return `<div class="mv-tl-h"><b>${esc(t.vm)}</b><button class="x" data-tlx>✕</button></div><p class="muted small">불러오는 중…</p>`;
    const L = t.labels, c = t.current, b = t.born;
    const facts = c ? `<div class="mv-tl-now"><span class="mon-st ${c.power === "poweredOn" ? "OK" : "MUTED"}">${c.power === "poweredOn" ? "켜짐" : c.power === "suspended" ? "일시 중단" : "꺼짐"}</span>
        <span>호스트 <b class="mono">${esc(c.host)}</b></span><span>클러스터 ${esc(c.cluster || "-")}</span><span>vCPU ${c.vcpu ?? "-"} · 메모리 ${c.mem_mb ? Math.round(c.mem_mb / 1024 * 10) / 10 + " GB" : "-"} · 디스크 ${c.disk_gb ?? "-"} GB</span>
        ${c.snapshots ? `<span class="mon-st WARN">스냅샷 ${c.snapshots}</span>` : ""}<span class="small muted">${esc(c.os || "")} · ${esc(c.vcenter)}</span></div>`
      : t.gone ? `<div class="mv-tl-now gone"><span class="mon-st DEL">삭제됨</span><span>${dfull(t.gone.ts)} ${esc(L[t.gone.type])}${t.gone.user ? ` — ${esc(t.gone.user)}${t.gone.ip ? ` (${esc(t.gone.ip)})` : ""}` : ""}</span></div>`
      : `<div class="mv-tl-now"><span class="mon-st NO_DATA">수집된 인벤토리에서 찾지 못함</span><span class="small muted">다른 vCenter·아직 수집 전·이름 변경 가능</span></div>`;
    const birth = b ? `<p class="small">${ICON(b.type)}<b>${esc(L[b.type])}</b> ${dfull(b.ts)}${b.user ? ` · ${esc(b.user)}${b.ip ? ` (${esc(b.ip)})` : ""}` : ""}${b.to_host ? ` · ${esc(b.to_host)}` : ""}${b.source ? ` · ${b.type === "deployed" ? "템플릿" : "원본"} ${esc(b.source)}` : ""}${t.age ? ` · 나이 ${dur(t.age)}` : ""}</p>`
      : `<p class="small muted">최근 ${t.days}일 안에 생성 기록이 없습니다(그 이전 생성 또는 수집 전).</p>`;
    return `<div class="mv-tl-h"><b>${esc(t.vm)}</b>${t.names.length > 1 ? `<span class="small muted">이전 이름 ${t.names.slice(1).map(esc).join(", ")}</span>` : ""}<span class="gap"></span>
        <a href="#inv/vm/${encodeURIComponent(t.vm)}" data-inv="${esc(t.vm)}" class="btn-sm">인벤토리</a><button class="x" data-tlx aria-label="닫기">✕</button></div>
      ${facts}${birth}
      <div class="inv-chips small">${Object.entries(t.cats).map(([k, v]) => `<span class="mv-cat"><i style="background:${COLOR[k]}"></i>${CATL[k]} ${v}</span>`).join("")}</div>
      ${t.children.length ? `<p class="small">이 VM 에서 만든 VM: ${t.children.map(r => vmLink(r.vm)).join(", ")}</p>` : ""}
      <ol class="mv-tl-list">${t.items.map(r => `<li><i style="background:${COLOR[CAT(r.type)]}"></i><time>${dt(r.ts)}</time><div><span class="mon-st ${CLS(r.type)}">${ICON(r.type)}${esc(L[r.type] || r.type)}</span>${flagHtml(r)}
          ${r.vm !== t.vm ? `<span class="small muted">(${esc(r.vm)})</span>` : ""} ${r.from_host || r.to_host ? `<span class="mono small">${esc(r.from_host || "")}${r.from_host && r.to_host && r.from_host !== r.to_host ? " → " : ""}${r.to_host && r.to_host !== r.from_host ? esc(r.to_host) : ""}</span>` : ""}
          <span class="small muted">${actor(r)}</span>${sub(r)}${detail(r)}</div></li>`).join("") || `<li class="muted small">기록 없음</li>`}</ol>`;
  }
  async function openTl(vm) {
    mv.tl = {vm, loading: true};
    const el = $("#mv-tl"); if (el) { el.hidden = false; el.innerHTML = tlHtml(mv.tl); }
    try { mv.tl = await A.api("GET", `/api/vm/activity/timeline?vm=${encodeURIComponent(vm)}&days=90`); }
    catch (e) { mv.tl = null; A.toast("일대기 조회 실패", e.message, "error"); }
    const el2 = $("#mv-tl"); if (el2) { el2.hidden = !mv.tl; el2.innerHTML = mv.tl ? tlHtml(mv.tl) : ""; el2.scrollTop = 0; }
  }
  // ---------------------------------------------------------------- 규칙(관리자)
  async function editRules() {
    let v; try { v = await A.api("GET", "/api/vm/activity/rules"); } catch (e) { A.toast("규칙 조회 실패", e.message, "error"); return; }
    const r = v.rules;
    const out = await A.modal({title: "VM 액티비티 — 위험 신호 규칙", wide: true, ok: "저장",
      html: `<p class="small muted">업무 외 시간·대량 작업·보호 VM·단명 VM 판정 기준입니다. 저장 즉시 새 기록부터 적용됩니다(이미 기록된 행은 바뀌지 않음).${v.updated ? ` 마지막 수정 ${dfull(v.updated)} · ${esc(v.by || "")}` : ""}</p>`,
      fields: [
        {id: "business_hours", label: "업무 시간", value: r.business_hours, placeholder: "09:00-18:00"},
        {id: "business_days", label: "업무 요일(1=월 … 7=일)", value: r.business_days.join(","), placeholder: "1,2,3,4,5"},
        {id: "tz", label: "시간대", value: r.tz, placeholder: "Asia/Seoul"},
        {id: "holidays", label: "휴일(YYYY-MM-DD, 줄바꿈·쉼표 구분)", type: "textarea", rows: 3, value: r.holidays.join("\n"), hint: "공휴일·대체휴일·회사 휴무일 — 이 날은 종일 업무 외"},
        {id: "bulk_delete_count", label: "대량 삭제 — 대수", type: "number", min: 2, value: r.bulk_delete_count},
        {id: "bulk_delete_minutes", label: "대량 삭제 — 시간(분)", type: "number", min: 1, value: r.bulk_delete_minutes},
        {id: "bulk_power_off_count", label: "대량 전원 끔 — 대수", type: "number", min: 2, value: r.bulk_power_off_count},
        {id: "bulk_power_off_minutes", label: "대량 전원 끔 — 시간(분)", type: "number", min: 1, value: r.bulk_power_off_minutes},
        {id: "short_lived_hours", label: "단명 VM — 생성 후 삭제까지(시간, 0=끔)", type: "number", min: 0, value: r.short_lived_hours},
        {id: "change_window_check", label: "변경 창 점검 — 유지보수 창 밖의 사람 변경을 '변경 창 밖'(위험 신호)으로 표시", type: "checkbox", value: r.change_window_check},
        {id: "pingpong_count", label: "반복 이동 — 횟수(0=끔)", type: "number", min: 0, value: r.pingpong_count},
        {id: "pingpong_minutes", label: "반복 이동 — 시간(분)", type: "number", min: 5, value: r.pingpong_minutes},
        {id: "retention_days", label: "VM 액티비티 보관(일, 90~3650)", type: "number", min: 90, max: 3650, value: r.retention_days},
        {id: "protected", label: "보호 VM 이름 패턴(* ? 와일드카드, 줄바꿈 구분)", type: "textarea", rows: 4, value: r.protected.join("\n"), placeholder: "*-prod-*\ndb*\ncorebank-*", hint: "삭제=위험, 전원 끔·스냅샷 되돌림=오류, 구성·이름 변경=경고 이상징후"},
        {id: "service_accounts", label: "서비스 계정 패턴(업무 외·대량 판정 제외)", type: "textarea", rows: 3, value: r.service_accounts.join("\n"), hint: "예: VSPHERE.LOCAL\\svc-backup — 대소문자 무시"}]});
    if (!out) return;
    try { await A.api("PUT", "/api/vm/activity/rules", out); A.toast("규칙 저장", "새 기록부터 적용됩니다.", "ok"); load(); }
    catch (e) { A.toast("규칙 저장 실패", e.message, "error", 9000); }
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-mv")) return;
    const b = $("#mv-body");
    const toHistory = () => { mv.tab = "moves"; load(); };
    b.addEventListener("click", e => {
      const tl = e.target.closest("[data-tl]"); if (tl) { e.preventDefault(); openTl(tl.dataset.tl); return; }
      if (e.target.closest("[data-tlx]")) { mv.tl = null; $("#mv-tl").hidden = true; return; }
      const h = e.target.closest("[data-h]"); if (h) { mv.hours = +h.dataset.h; load(); return; }
      const t = e.target.closest("[data-tab]"); if (t) { mv.tab = t.dataset.tab; render(); return; }
      const y = e.target.closest("[data-ty]"); if (y) { mv.type = y.dataset.ty; if (y.dataset.gom) mv.tab = "moves"; load(); return; }
      const f = e.target.closest("[data-fl]"); if (f) { mv.flag = f.dataset.fl; load(); return; }
      const fg = e.target.closest("[data-flgo]"); if (fg) { mv.flag = fg.dataset.flgo === "short_lived" || fg.dataset.flgo === "protected" || fg.dataset.flgo.startsWith("bulk") ? fg.dataset.flgo : "risk"; mv.type = ""; toHistory(); return; }
      const ip = e.target.closest("[data-ip]"); if (ip) { e.preventDefault(); mv.q = ip.dataset.ip; mv.tab = "moves"; toHistory(); return; }
      const u = e.target.closest("[data-user]"); if (u) { e.preventDefault(); mv.user = u.dataset.user; toHistory(); return; }
      const g = e.target.closest("[data-go]"); if (g) { const [k, v] = g.dataset.go.split(":");
        if (k === "tab") { mv.tab = v; render(); return; }
        if (k === "type") { mv.type = v; mv.flag = ""; } else { mv.flag = v; mv.type = ""; } toHistory(); return; }
      const inv = e.target.closest("[data-inv]"); if (inv) { $("#drawer-mv").hidden = true; }
    });
    let qt; b.addEventListener("input", e => { if (e.target.id !== "mv-q") return; clearTimeout(qt); qt = setTimeout(() => { mv.q = e.target.value; load().then(() => { const i = $("#mv-q"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 350); });
    $("#mv-reload").onclick = load;
    $("#mv-csv").onclick = () => { const a = document.createElement("a"); a.href = `/api/vm/activity.csv?${filterQS()}`; a.download = ""; document.body.append(a); a.click(); a.remove(); };
    const rb = $("#mv-rules"); if (rb) rb.onclick = editRules;
    $("#nav-mv").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-mv") d.hidden = true; });
      $("#drawer-mv").hidden = false; const bd = $("#mv-badge"); if (bd) { bd.hidden = true; bd.textContent = ""; } load();
      clearInterval(mv.timer); mv.timer = setInterval(() => $("#drawer-mv").hidden ? clearInterval(mv.timer) : (document.activeElement && document.activeElement.id === "mv-q") || mv.tl ? null : load(), 20000);
    };
    window.addEventListener("aiops:ws", e => { const m = e.detail; if (!m || m.type !== "vm_move") return;
      const r = m.data, bd = $("#mv-badge"), risky = flags(r).some(f => f !== "offhours");
      if ((HA.has(r.type) || risky) && bd && $("#drawer-mv").hidden) { bd.hidden = false; bd.textContent = (+bd.textContent || 0) + 1; }
      if (!$("#drawer-mv").hidden && !mv.tl) { clearTimeout(mv.lt); mv.lt = setTimeout(load, 800); } });
    const fromHash = () => { if (location.hash === "#mv") A.ready.then(me => { if (me !== null) $("#nav-mv").click(); }); };
    addEventListener("hashchange", fromHash); setTimeout(fromHash, 800);
    window.AIOPS_VM_MOVES = async (vm, hours = 168) => (await A.api("GET", `/api/vm/moves?vm=${encodeURIComponent(vm)}&hours=${hours}&limit=50`)).items;
    window.AIOPS_VM_LABELS = {vmotion: "vMotion", drs: "DRS 자동 이동", svmotion: "Storage vMotion", relocate: "콜드 이전", ha_restart: "HA 재시작", ha_failed: "HA 재시작 실패",
      ha_reset: "HA VM 리셋", ha_reset_failed: "HA 리셋 실패", host_failed: "호스트 장애(HA)", host_isolated: "호스트 격리(HA)", move_failed: "이동 실패", created: "VM 생성", cloned: "VM 복제",
      deployed: "템플릿 배포", registered: "VM 등록", removed: "VM 삭제·등록 해제", renamed: "VM 이름 변경", create_failed: "생성 실패", detected_gone: "VM 사라짐 감지", power_on: "전원 켬",
      power_off: "전원 끔", suspended: "일시 중단", reset: "리셋", guest_shutdown: "게스트 종료", guest_reboot: "게스트 재시작", reconfigured: "구성 변경", snapshot_create: "스냅샷 생성",
      snapshot_remove: "스냅샷 삭제", snapshot_remove_all: "스냅샷 모두 삭제", snapshot_revert: "스냅샷 되돌림"};
    window.AIOPS_VM_TIMELINE = vm => { $("#nav-mv").click(); setTimeout(() => openTl(vm), 300); };
    document.addEventListener("click", e => { const t = e.target.closest("[data-vmtl]"); if (!t) return; e.preventDefault(); window.AIOPS_VM_TIMELINE(t.dataset.vmtl); });
  });
})();
