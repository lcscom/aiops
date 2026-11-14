/* DR·보호(2.29.0) — SRM 복구 계획·보호 그룹, VM 스냅숏, Appliance(vCenter·NSX·SDDC Manager) 파일 기반 백업, VM 백업(추정) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const st = {d: null, tab: "sum", q: "", f: ""};
  const V = {ok: "정상", warn: "주의", bad: "문제", unknown: "조회 불가", none: "정보 없음"};
  const vb = v => `<span class="dr-v ${v}">${V[v] || v}</span>`;
  const dt = t => t ? new Date(t * 1000).toLocaleString() : "—";
  const age = h => h == null ? "—" : h < 48 ? `${h.toFixed(h < 10 ? 1 : 0)}시간` : `${(h / 24).toFixed(1)}일`;
  const FL = {"72h": ["72시간 초과", "bad"], chain: ["체인 3개 초과", "warn"], leftover: ["백업 잔여 의심", "bad"], consolidate: ["디스크 통합 필요", "warn"]};

  async function load() {
    try { st.d = await A.api("GET", "/api/dr", undefined, {background: true}); }
    catch (e) { $("#dr-body").innerHTML = `<div class="empty">${esc(e.message || e)}</div>`; return; }
    render(); badge();
  }

  function kpis() {
    const s = st.d.summary;
    const k = (tab, title, big, sub, v) => `<button class="dr-k ${v}" data-drt="${tab}"><small>${title}</small><b>${big}</b><span>${sub}</span></button>`;
    const sv = s.srm.connectors ? (s.srm.plans_bad || s.srm.groups_bad || s.srm.vms_bad ? "bad" : "ok") : "none";
    const ap = s.appliances, av = !ap.total ? "none" : ap.bad ? "bad" : ap.warn || ap.unknown ? "warn" : "ok";
    const sn = s.snapshots, snv = sn.over72 || sn.leftover ? "bad" : sn.violations ? "warn" : "ok";
    const vm = s.vm_backup, known = vm.ok + vm.warn + vm.bad, vv = !vm.vms ? "none" : vm.bad ? "bad" : vm.warn || vm.none ? "warn" : "ok";
    return `<div class="dr-kpis">
      ${k("srm", "DR(SRM) 복구 계획", s.srm.connectors ? `${s.srm.plans - s.srm.plans_bad}/${s.srm.plans}` : "—", s.srm.connectors ? `준비됨 · 보호 그룹 ${s.srm.groups}(문제 ${s.srm.groups_bad}) · 보호 VM ${s.srm.protected_vms}(문제 ${s.srm.vms_bad})` : "SRM 커넥터 없음", sv)}
      ${k("app", "Appliance 백업", ap.total ? `${ap.ok}/${ap.total}` : "—", ap.total ? `정상 · 주의 ${ap.warn} · 문제 ${ap.bad} · 조회 불가 ${ap.unknown}` : "vCenter·NSX·SDDC Manager 커넥터 필요", av)}
      ${k("snap", "스냅숏", sn.snapshots, `VM ${sn.vms} · 72시간 초과 ${sn.over72} · 백업 잔여 ${sn.leftover} · 통합 필요 ${sn.consolidate}`, snv)}
      ${k("vmb", "VM 백업(추정)", vm.vms ? `${vm.ok}/${vm.vms}` : "—", vm.vms ? `26시간 이내 · 오래됨 ${vm.warn + vm.bad} · 정보 없음 ${vm.none}` : "vCenter VM 정보 없음", vv)}
    </div>`;
  }

  function srm() {
    const S = st.d.srm;
    if (!S.length) return `<div class="empty">SRM(VMware Live Site Recovery) 커넥터가 없습니다 — 운영 설정 › 커넥터에서 유형 'srm'(REST API Gateway, 읽기 전용 계정)을 추가하세요.</div>`;
    return S.map(s => `<div class="dr-card"><h4>${esc(s.connector)} <small>갱신 ${dt(s.updated)}${s.error ? ` · <span class="bad">${esc(s.error)}</span>` : ""}</small></h4>
      <div class="dr-pairs">${(s.pairings || []).map(p => `<div class="dr-pair"><b>${esc(p.local_site || "보호 사이트")}</b><i>⇄</i><b>${esc(p.remote_site || "복구 사이트")}</b>
        <small>${esc(p.local_srm || "")} · ${esc(p.remote_srm || "")} · ${esc(p.status || "")}</small></div>`).join("") || `<span class="muted">페어링 없음</span>`}</div>
      <h5>복구 계획</h5><table class="dr-t"><thead><tr><th>판정</th><th>계획</th><th>상태</th><th>보호 사이트</th><th class="r">보호 그룹</th></tr></thead><tbody>
        ${(s.plans || []).map(p => `<tr class="${p.verdict}"><td>${vb(p.verdict)}</td><td><b>${esc(p.name)}</b></td><td>${esc(p.status)}</td><td>${esc(p.protected_site || "")}</td><td class="r">${p.groups || "—"}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">없음</td></tr>`}</tbody></table>
      <h5>보호 그룹</h5><table class="dr-t"><thead><tr><th>판정</th><th>그룹</th><th>복제</th><th>상태</th><th class="r">VM</th><th class="r">문제 VM</th></tr></thead><tbody>
        ${(s.groups || []).map(g => `<tr class="${g.verdict}"><td>${vb(g.verdict)}</td><td><b>${esc(g.name)}</b></td><td>${esc({HBR: "vSphere Replication", ABR: "어레이 복제(SRA)", VVOL: "vVols 복제"}[g.replication] || g.replication || "")}</td>
          <td>${esc(g.status)}</td><td class="r">${g.vms ?? "—"}</td><td class="r ${g.vms_bad ? "bad" : ""}">${g.vms_bad || 0}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">없음</td></tr>`}</tbody></table>
      ${(s.vms || []).some(v => v.verdict !== "ok") ? `<h5>문제 VM</h5><table class="dr-t"><thead><tr><th>VM</th><th>보호 그룹</th><th>상태</th><th>오류</th></tr></thead><tbody>
        ${s.vms.filter(v => v.verdict !== "ok").map(v => `<tr class="${v.verdict}"><td><b>${esc(v.name)}</b></td><td>${esc(v.group)}</td><td>${esc(v.status)}</td><td class="small">${esc(v.errors || "")}</td></tr>`).join("")}</tbody></table>` : ""}</div>`).join("");
  }

  function apps() {
    const L = st.d.appliances;
    if (!L.length) return `<div class="empty">vCenter·NSX·SDDC Manager 커넥터가 있으면 파일 기반 백업 설정·일정·마지막 결과를 1시간마다 확인합니다.</div>`;
    return `<table class="dr-t"><thead><tr><th>판정</th><th>대상</th><th>백업 일정</th><th>위치</th><th>마지막 실행</th><th>마지막 성공</th><th>사유</th></tr></thead><tbody>
      ${L.map(a => { const l = a.last || {}; return `<tr class="${a.verdict}"><td>${vb(a.verdict)}</td><td><b>${esc(a.product || "")}</b><div class="small muted">${esc(a.target || a.connector)}</div></td>
        <td>${esc(a.schedule || (a.configured === false ? "미설정" : "—"))}</td><td class="small">${esc(a.location || "—")}</td>
        <td>${l.status ? `<span class="dr-s ${/SUCCE/.test(l.status) ? "ok" : /FAIL|ERROR/.test(l.status) ? "bad" : "warn"}">${esc(l.status)}</span>` : "—"} <small class="muted">${dt(l.end)}</small>${l.message ? `<div class="small bad">${esc(l.message)}</div>` : ""}</td>
        <td>${dt(a.last_success)}</td><td class="small">${esc(a.why || a.error || "")}</td></tr>`; }).join("")}</tbody></table>
      <p class="small muted">기준: 마지막 성공이 ${st.d.policy.appliance_max_h}시간 이내이고 자동 일정이 있으면 '정상'. vCenter 는 VAMI 백업(/api/appliance/recovery/backup), NSX 는 /api/v1/cluster/backups/overview, SDDC Manager 는 /v1/system/backup-configuration 과 최근 백업 작업으로 판단합니다. 백업 실행·설정 변경은 하지 않습니다.</p>`;
  }

  function snaps() {
    const S = st.d.snapshots, q = st.q.toLowerCase();
    const rows = S.rows.filter(r => (!st.f || r.flags.includes(st.f)) && (!q || `${r.vm} ${r.name} ${r.cluster}`.toLowerCase().includes(q)));
    return `<div class="dr-tools"><input id="dr-q" placeholder="VM·스냅숏 이름·클러스터" value="${esc(st.q)}">
        <select id="dr-f"><option value="">전체</option>${Object.entries(FL).map(([k, [l]]) => `<option value="${k}" ${st.f === k ? "selected" : ""}>${l}</option>`).join("")}</select>
        <span class="small muted">${rows.length}개 · 정책: ${st.d.policy.snap_max_h}시간 이내 · 체인 ${st.d.policy.snap_chain}개 이하(Broadcom KB 318825)</span><button class="btn-sm" id="dr-csv-snap">CSV</button></div>
      <table class="dr-t"><thead><tr><th>VM</th><th>스냅숏</th><th>생성</th><th class="r">경과</th><th class="r">체인</th><th>플래그</th></tr></thead><tbody>
      ${rows.slice(0, 2000).map(r => `<tr class="${r.flags.some(f => (FL[f] || [f, "warn"])[1] === "bad") ? "bad" : r.flags.length ? "warn" : ""}"><td><b>${esc(r.vm)}</b><div class="small muted">${esc(r.cluster || r.vcenter)}${r.host ? " · " + esc(r.host) : ""}</div></td>
        <td>${esc(r.name || "(이름 없음)")}</td><td class="small">${dt(r.created)}</td><td class="r">${age(r.age_h)}</td><td class="r">${r.chain}</td>
        <td>${r.flags.map(f => `<span class="dr-f ${(FL[f] || [f, "warn"])[1]}">${esc((FL[f] || [f])[0])}</span>`).join(" ") || `<span class="muted small">—</span>`}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">스냅숏 없음</td></tr>`}</tbody></table>
      <p class="small muted">'백업 잔여 의심' = 백업 SW(Veeam·Commvault·NetBackup·Cohesity·Rubrik 등)가 만든 임시 스냅숏이 남아 있음 — 백업 작업 실패·정리 실패를 확인하세요. 스냅숏 삭제는 vCenter 에서 하세요(이 화면은 읽기 전용). 목록은 인프라 점검(30분)마다 갱신됩니다.</p>`;
  }

  function vmb() {
    const B = st.d.vm_backups, q = st.q.toLowerCase();
    const rows = B.rows.filter(r => (!st.f || r.status === st.f) && (!q || `${r.vm} ${r.cluster}`.toLowerCase().includes(q)));
    const c = B.count;
    return `<div class="dr-bars">${["ok", "warn", "bad", "none"].map(k => `<button class="dr-bar ${k}${st.f === k ? " on" : ""}" data-drf="${k}" style="flex:${Math.max(c[k], .3)}"><b>${c[k]}</b> ${({ok: "26시간 이내", warn: "1~7일", bad: "7일 초과", none: "정보 없음"})[k]}</button>`).join("")}</div>
      <div class="dr-tools"><input id="dr-q" placeholder="VM·클러스터" value="${esc(st.q)}"><span class="small muted">${rows.length}개${B.fields.length ? ` · 읽은 속성: ${B.fields.map(esc).join(", ")}` : ""}</span><button class="btn-sm" id="dr-csv-vmb">CSV</button></div>
      <table class="dr-t"><thead><tr><th>판정</th><th>VM</th><th>마지막 백업</th><th class="r">경과</th><th>출처</th></tr></thead><tbody>
      ${rows.slice(0, 2000).map(r => `<tr class="${r.status}"><td>${vb(r.status)}</td><td><b>${esc(r.vm)}</b><div class="small muted">${esc(r.cluster || r.vcenter)}${r.power !== "poweredOn" ? " · 꺼짐" : ""}</div></td>
        <td class="small">${dt(r.last)}</td><td class="r">${age(r.age_h)}</td><td class="small">${esc(r.source || "")}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">VM 정보 없음 — 인프라 점검 후 표시(6시간마다, '지금 새로 고침'으로 즉시)</td></tr>`}</tbody></table>
      <p class="small muted">${esc(B.note)}</p>`;
  }

  function render() {
    const box = $("#dr-body"); if (!box || !st.d) return;
    const tabs = [["sum", "개요"], ["srm", "DR(SRM)"], ["app", "Appliance 백업"], ["snap", "스냅숏"], ["vmb", "VM 백업"]];
    const body = st.tab === "srm" ? srm() : st.tab === "app" ? apps() : st.tab === "snap" ? snaps() : st.tab === "vmb" ? vmb()
      : `${kpis()}<div class="dr-two"><div><h4>Appliance 백업</h4>${apps()}</div><div><h4>DR 복구 계획</h4>${st.d.srm.length ? `<table class="dr-t"><tbody>${st.d.srm.flatMap(s => s.plans || []).map(p => `<tr class="${p.verdict}"><td>${vb(p.verdict)}</td><td><b>${esc(p.name)}</b></td><td>${esc(p.status)}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">SRM 커넥터 없음</p>`}</div></div>`;
    box.innerHTML = `<div class="dr-tabs">${tabs.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-drt="${k}">${l}</button>`).join("")}<span class="small muted">갱신 ${dt(st.d.generated)}</span></div>${body}`;
    $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
  }

  function csv(kind) {
    const cell = x => { let t = String(x ?? ""); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
    const rows = kind === "snap" ? [["vcenter", "cluster", "vm", "snapshot", "created", "age_h", "chain", "flags"]].concat(st.d.snapshots.rows.map(r => [r.vcenter, r.cluster, r.vm, r.name, dt(r.created), r.age_h, r.chain, r.flags.join(" ")]))
      : [["vcenter", "cluster", "vm", "status", "last_backup", "age_h", "source"]].concat(st.d.vm_backups.rows.map(r => [r.vcenter, r.cluster, r.vm, V[r.status], dt(r.last), r.age_h, r.source]));
    const b = new Blob(["﻿" + rows.map(r => r.map(cell).join(",")).join("\r\n")], {type: "text/csv"});
    A.download(kind === "snap" ? "snapshots.csv" : "vm-backup.csv", b);
  }

  async function badge() {
    try {
      const d = st.d || await A.api("GET", "/api/dr", undefined, {background: true});
      const s = d.summary, n = s.srm.plans_bad + s.srm.groups_bad + s.appliances.bad + s.snapshots.over72 + s.snapshots.leftover;
      const b = $("#dr-badge"); if (b) { b.hidden = !n; b.textContent = n; b.title = `DR·보호 문제 ${n}건(복구 계획·보호 그룹·Appliance 백업·72시간 초과·백업 잔여 스냅숏)`; }
    } catch { /* 로그인 전 */ }
  }

  function wire() {
    const body = $("#dr-body");
    body.addEventListener("click", ev => {
      const t = ev.target.closest("[data-drt]"); if (t) { st.tab = t.dataset.drt; st.f = ""; st.q = ""; render(); return; }
      const f = ev.target.closest("[data-drf]"); if (f) { st.f = st.f === f.dataset.drf ? "" : f.dataset.drf; render(); return; }
      if (ev.target.id === "dr-csv-snap") csv("snap");
      if (ev.target.id === "dr-csv-vmb") csv("vmb");
    });
    body.addEventListener("change", ev => { if (ev.target.id === "dr-f") { st.f = ev.target.value; render(); } });
    let tm;
    body.addEventListener("input", ev => {
      if (ev.target.id !== "dr-q" || ev.isComposing) return;
      clearTimeout(tm); tm = setTimeout(() => { st.q = ev.target.value; render(); const i = $("#dr-q"); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 250);
    });
    body.addEventListener("compositionend", ev => { if (ev.target.id === "dr-q") ev.target.dispatchEvent(new Event("input", {bubbles: true})); });   // 한글·모바일 자판: 조합이 끝나면 한 번 더
    $("#dr-run").onclick = async () => {
      const b = $("#dr-run"); b.disabled = true; b.textContent = "새로 고치는 중…";
      try { const r = await A.api("POST", "/api/dr/run"); r.errors.length ? A.fail("일부 실패", r.errors.join("\n")) : A.ok("새로 고침 완료", `${r.ran}개 대상`); }
      catch (e) { A.fail("새로 고침 실패", e); }
      b.disabled = false; b.textContent = "지금 새로 고침"; load();
    };
    $("#dr-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-dr")) return;
    wire();
    $("#nav-dr").onclick = () => { open("drawer-dr"); load(); };
    setTimeout(badge, 6000); setInterval(async () => {          // 5분마다 새 값 — 열려 있는 화면도 함께 갱신(검색 입력 중이면 배지만)
      try { st.d = await A.api("GET", "/api/dr", undefined, {background: true}); } catch { return; }
      badge(); if (!$("#drawer-dr").hidden && document.activeElement?.id !== "dr-q") render();
    }, 300000);
  });
  window.AIOPS_DR = {load};
})();
