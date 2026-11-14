/* 경영진 요약 페이지(/noc/exec) — 30일 인시던트·MTTA/MTTR·SLA, 이상징후 추세, 가용성, vSAN, 용량 예측, 적정화 절감, 이번 달 정산, 보안 판독, 수집·알림·SIEM 상태
   관제 월(nocwall.js)의 PAGES 에 등록되어 60초마다 /api/noc/exec 를 다시 읽는다. */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const N = v => (v == null ? "-" : Number(v).toLocaleString());
  const M = (v, cur) => v == null ? "-" : `${Number(v).toLocaleString(undefined, {maximumFractionDigits: 0})}<small class="cur"> ${esc(cur || "")}</small>`;
  const pct = v => v == null ? "-" : `${Math.round(v * 10) / 10}%`;
  const dt = ts => ts ? new Date(ts * 1000).toLocaleString("ko-KR", {month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit"}) : "-";
  const SEV_KO = {critical: "위험", error: "오류", warning: "경고", info: "정보"};
  const ST = {open: "열림", acknowledged: "접수", investigating: "조사 중"};

  function bars(vals, {h = 70, color = "#4fb3e0"} = {}) {
    const v = (vals || []).map(x => Number(x) || 0), mx = Math.max(1, ...v), w = 600, bw = w / Math.max(1, v.length);
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="ex-bars">${v.map((x, i) => `<rect x="${(i * bw + 1).toFixed(1)}" y="${(h - x / mx * (h - 6)).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(x / mx * (h - 6)).toFixed(1)}" fill="${color}" opacity="${i === v.length - 1 ? 1 : .55}"><title>${x}</title></rect>`).join("")}</svg>`;
  }
  function delta(cur, prev, {lowerBetter = true, unit = ""} = {}) {
    if (cur == null || prev == null) return "";
    const d = cur - prev; if (!d) return `<small class="ex-d flat">변동 없음</small>`;
    const good = lowerBetter ? d < 0 : d > 0;
    return `<small class="ex-d ${good ? "good" : "bad"}">${d > 0 ? "▲" : "▼"} ${Math.abs(Math.round(d * 10) / 10)}${unit} <span>전 30일 대비</span></small>`;
  }
  const ring = (v, {label = "", color = "#56b62b"} = {}) => {
    const f = v == null ? 0 : Math.max(0, Math.min(1, v / 100)), r = 42, c = 2 * Math.PI * r;
    return `<svg viewBox="0 0 110 110" class="ex-ring"><circle cx="55" cy="55" r="${r}" fill="none" stroke="#0e1a20" stroke-width="12"/>
      <circle cx="55" cy="55" r="${r}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${(c * f).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 55 55)" style="transition:stroke-dasharray .8s"/>
      <text x="55" y="60" class="gv">${v == null ? "-" : Math.round(v) + "%"}</text><text x="55" y="78" class="gl">${esc(label)}</text></svg>`;
  };

  const EX = {d: null};
  async function load() {
    try { EX.d = await A.api("GET", "/api/noc/exec", undefined, {background: true}); } catch (e) { $("#pg-exec").innerHTML = `<div class="wempty">${esc(e.message)}</div>`; return; }
    render();
  }
  function render() {
    const d = EX.d, inc = d.incidents, an = d.anomalies, av = d.availability, vs = d.vsan, cap = d.capacity, rs = d.rightsizing, bl = d.billing, as = d.assessment, co = d.collection;
    const incOpen = inc.active || 0, crit = (inc.by_severity || {}).critical || 0;
    const score = as.score, scoreCol = score == null ? "#56707c" : score >= 90 ? "#56b62b" : score >= 70 ? "#f2c200" : "#ff5a4f";
    const hostCol = av.host_pct == null ? "#56707c" : av.host_pct >= 99.9 ? "#56b62b" : av.host_pct >= 95 ? "#f2c200" : "#ff5a4f";
    $("#w-sub").textContent = `최근 ${d.period_days}일 · ${dt(d.ts)} 기준 · 60초 갱신`;
    $("#pg-exec").innerHTML = `<div class="ex-wrap">
      <div class="ex-kpis">
        <div class="bign ${crit ? "crit" : incOpen ? "err" : "inc"}"><span>열린 인시던트</span><b>${N(incOpen)}</b><small>위험 ${crit} · 30일 생성 ${N(inc.total)} ${delta(inc.total, inc.prev_total)}</small></div>
        <div class="bign ${inc.sla_breaches ? "warn" : "inc"}"><span>SLA 위반(30일)</span><b>${N(inc.sla_breaches)}</b><small>${delta(inc.sla_breaches, inc.prev_sla_breaches)}</small></div>
        <div class="bign inc"><span>MTTR · MTTA(분)</span><b>${inc.mttr_min ?? "-"}<small style="font-size:22px"> / ${inc.mtta_min ?? "-"}</small></b><small>해결 ${N(inc.resolved)}건 ${delta(inc.mttr_min, inc.prev_mttr_min, {unit: "분"})}</small></div>
        <div class="bign ${av.hosts_bad ? "crit" : "eps"}"><span>호스트 가용</span><b>${av.hosts - av.hosts_bad}<small style="font-size:22px"> / ${av.hosts}</small></b><small>클러스터 ${av.clusters} · VM ${N(av.vms_on)}/${N(av.vms)} 켜짐${av.hosts_maint ? ` · 유지보수 ${av.hosts_maint}` : ""}</small></div>
        <div class="bign ${vs.red ? "crit" : vs.warn ? "warn" : "eps"}"><span>vSAN 클러스터</span><b>${vs.clusters}</b><small>${vs.clusters ? `장애 ${vs.red} · 주의 ${vs.warn} · 사용 ${pct(vs.used_pct)} · 점검 실패 ${vs.tests_bad}` : "vSAN 없음"}</small></div>
        <div class="bign ${(cap.summary || {}).down ? "crit" : (cap.summary || {}).soon ? "warn" : "eps"}"><span>용량 90% 임박(90일)</span><b>${N((cap.summary || {}).soon)}</b><small>클러스터 ${N((cap.summary || {}).clusters)} · 데이터스토어 ${N((cap.summary || {}).datastores)}${cap.error ? ` · ${esc(cap.error)}` : ""}</small></div>
      </div>
      <section class="wcard"><h3>인시던트 · 이상징후 추세 <small>일별 30일</small></h3>
        <div class="ex-trend"><div><span>인시던트 <b>${N(inc.total)}</b></span>${bars(inc.daily, {color: "#ff8a3d"})}</div><div><span>이상징후 <b>${N(an.total)}</b> <small>${Object.entries(an.by_severity || {}).sort((a, b) => (b[1] - a[1])).map(([k, v]) => `${SEV_KO[k] || k} ${v}`).join(" · ")}</small></span>${bars(an.daily, {color: "#4fb3e0"})}</div></div></section>
      <section class="wcard"><h3>열린 인시던트 <small>심각도 순 ${inc.open.length}건</small></h3>
        <div class="ex-list">${inc.open.map(i => `<div class="ex-inc sev-${esc(i.severity)}"><i></i><span class="t">${esc(i.title)}</span><span class="m">${esc(ST[i.status] || i.status)}${i.assignee ? ` · ${esc(i.assignee)}` : ""} · ${dt(i.created)}</span></div>`).join("") || `<div class="wempty">열린 인시던트 없음</div>`}</div></section>
      <section class="wcard"><h3>보안 판독 <small>${as.ts ? `${dt(as.ts)} 실행 · 호스트 ${N(as.hosts)}` : "아직 실행 안 됨(컴플라이언스 › 보안 판독)"}</small></h3>
        <div class="ex-sec"><div class="ex-ring-wrap">${ring(score, {label: "하드닝 준수율", color: scoreCol})}</div>
          <div class="ex-secb"><div><span>점검 실패</span><b class="bad">${N((as.counts || {}).FAIL)}</b></div><div><span>주의</span><b>${N((as.counts || {}).WARN)}</b></div><div><span>통과</span><b class="good">${N((as.counts || {}).PASS)}</b></div>
            <div><span>CVE 취약</span><b class="${(as.cve || {}).vulnerable ? "bad" : ""}">${N((as.cve || {}).vulnerable)}</b></div><div><span>CVE 가능</span><b>${N((as.cve || {}).possible)}</b></div><div><span>CRITICAL</span><b class="${(as.cve || {}).critical ? "bad" : ""}">${N((as.cve || {}).critical)}</b></div>
            <div><span>구성 변경</span><b>${N((as.changes || {}).total)}</b></div><div><span>악화</span><b class="${(as.changes || {}).worse ? "bad" : ""}">${N((as.changes || {}).worse)}</b></div><div><span>개선</span><b class="good">${N((as.changes || {}).better)}</b></div></div>
          <div class="ex-vers">${(as.versions || []).map(v => `<span>${esc(v.product)} ${esc(v.version)}<small> ${esc(v.build || "")} ×${v.count}</small></span>`).join("")}</div></div></section>
      <section class="wcard"><h3>이번 달 정산 <small>${esc(bl.label || "")} · ${bl.error ? esc(bl.error) : `테넌트 ${N((bl.totals || {}).tenants)} · 프로젝트 ${N((bl.totals || {}).projects)} · 미배정 VM ${N(bl.unassigned_vms)}`}</small></h3>
        <div class="ex-bill"><div class="ex-total"><span>월초 ~ 현재 합계</span><b>${M((bl.totals || {}).cost, bl.currency)}</b><small>VM ${N((bl.totals || {}).vms)} · vCPU ${N((bl.totals || {}).vcpu_hours)} 시간</small></div>
          <div class="ex-ten">${(bl.tenants || []).map((t, i, arr) => { const mx = Math.max(1, ...arr.map(x => x.cost || 0)); return `<div><span>${esc(t.name)}</span><i><b style="width:${(t.cost || 0) / mx * 100}%"></b></i><em>${M(t.cost, bl.currency)}</em></div>`; }).join("") || `<div class="wempty">테넌트·요율을 설정하면 표시됩니다(비용 › 정산)</div>`}</div></div></section>
      <section class="wcard"><h3>용량 예측 · 적정화 <small>${rs.error ? esc(rs.error) : `VM ${N(rs.vms_observed)} 관측`}</small></h3>
        <div class="ex-cap"><div class="ex-soon">${(cap.soon || []).map(r => `<div class="${r.days_to_90 <= 30 ? "bad" : r.days_to_90 <= 90 ? "warn" : ""}"><span>${esc(r.name)}<small> ${r.kind === "cluster" ? "클러스터" : "데이터스토어"} · ${esc(r.vcenter)}</small></span><b>${Math.round(r.days_to_90)}일</b><em>90% 도달</em></div>`).join("") || `<div class="wempty">90일 내 90% 도달 예상 없음</div>`}</div>
          <div class="ex-rs"><div><span>과다 할당 VM</span><b>${N(rs.oversized)}</b></div><div><span>유휴 VM</span><b>${N(rs.idle)}</b></div><div><span>장기 꺼짐</span><b>${N(rs.powered_off)}</b></div><div><span>회수 가능 vCPU</span><b>${N(rs.reclaim_vcpu)}</b></div><div><span>회수 가능 메모리</span><b>${N(rs.reclaim_mem_gb)} GB</b></div><div><span>월 절감 추정</span><b class="good">${rs.saving_month != null ? M(rs.saving_month, rs.currency) : "요율 없음"}</b></div></div></div></section>
      <section class="wcard"><h3>플랫폼 상태 <small>수집 ${N(co.total)} · 초당 ${Math.round(d.eps || 0)} 이벤트</small></h3>
        <div class="ex-plat">
          <div class="${co.problems ? "bad" : "good"}"><span>수집 문제</span><b>${N(co.problems)}</b><small>${Object.entries(co.summary || {}).filter(([, v]) => v).map(([k, v]) => `${k} ${v}`).join(" · ")}</small></div>
          <div class="${d.ai.on ? (d.ai.provider_state === "ok" ? "good" : "warn") : ""}"><span>AI 분석</span><b>${d.ai.on ? "켜짐" : "꺼짐"}</b><small>${esc(d.ai.provider || "")} ${esc(d.ai.model || "")}</small></div>
          <div class="${(d.alerts.outbox || {}).dead ? "bad" : "good"}"><span>알림 발송</span><b>${N(d.alerts.sent_total)}</b><small>대기 ${N((d.alerts.outbox || {}).pending)} · 실패함 ${N((d.alerts.outbox || {}).dead)}</small></div>
          <div class="${d.siem && d.siem.enabled ? (d.siem.errors && !d.siem.connected ? "bad" : "good") : ""}"><span>SIEM 전달</span><b>${d.siem && d.siem.enabled ? `${esc(d.siem.protocol)}://${esc(d.siem.host)}` : "꺼짐"}</b><small>${d.siem && d.siem.enabled ? `보냄 ${N(d.siem.sent)} · 대기 ${N(d.siem.queued)} · 유실 ${N(d.siem.drops)}${d.siem.last_error ? ` · ${esc(d.siem.last_error)}` : ""}` : "운영 설정 › SIEM 전달"}</small></div>
        </div></section>
    </div>`;
    const hp = $("#ex-hostpct"); if (hp) hp.style.color = hostCol;
  }
  window.NOCEXEC = {load, render};
})();
