/* vCenter 인프라 상세 점검(Compute·Storage·Network·Hardware·보안) — core.js(AIOPS) 이후 로드 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const SEV = {critical: "위험", error: "오류", warning: "경고", info: "정보"};
  const ORDER = ["critical", "error", "warning", "info"];
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.round(s)}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : `${Math.round(s / 3600)}시간 전`; };
  const st = {d: null, tab: "find", area: "", min: "", q: "", open: new Set(), hq: ""};

  async function load() {
    try { st.d = await A.api("GET", "/api/vcenter/health", undefined, {background: true}); }
    catch (e) { $("#vc-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }

  const sevChip = s => `<span class="vc-sev ${s}">${SEV[s] || s}</span>`;

  function cards(d) {
    return `<div class="vc-cards">${Object.entries(d.areas).map(([k, label]) => {
      const m = d.summary[k] || {};
      const worst = ORDER.find(s => m[s]) || "ok";
      const n = ORDER.reduce((a, s) => a + (m[s] || 0), 0);
      return `<button class="vc-card ${worst}${st.area === k ? " on" : ""}" data-area="${k}"><b>${esc(label)}</b>
        <span class="vc-n">${n}</span><small>${ORDER.filter(s => m[s]).map(s => `${SEV[s]} ${m[s]}`).join(" · ") || "이상 없음"}</small></button>`;
    }).join("")}</div>`;
  }

  function findings(d) {
    const rows = [];
    for (const v of d.vcenters) {
      for (const f of v.findings) {
        if (st.min && ORDER.indexOf(f.severity) > ORDER.indexOf(st.min)) continue;
        if (st.area && f.area !== st.area) continue;
        const q = st.q.toLowerCase();
        if (q && !`${f.entity} ${f.title} ${f.detail} ${f.id}`.toLowerCase().includes(q)) continue;
        rows.push(f);
      }
    }
    if (!rows.length) return `<div class="empty">조건에 맞는 점검 결과가 없습니다.</div>`;
    return `<table class="vc-t"><thead><tr><th>등급</th><th>항목</th><th>영역</th><th>대상</th><th>내용</th><th>vCenter</th></tr></thead><tbody>${rows.slice(0, 1500).map((f, i) => {
      const k = `${f.vcenter}|${f.id}|${f.entity}|${f.title}`;
      const op = st.open.has(k);
      return `<tr class="vc-r" data-k="${esc(k)}"><td>${sevChip(f.severity)}</td><td><code>${esc(f.id)}</code></td><td>${esc(d.areas[f.area] || f.area)}</td>
        <td class="vc-ent">${esc(f.entity)}</td><td><b>${esc(f.title)}</b>${f.detail ? `<div class="small muted">${esc(f.detail)}</div>` : ""}
        ${op && f.fix ? `<div class="vc-fix">권고: ${esc(f.fix)}</div>` : ""}</td><td class="small">${esc(f.vcenter)}</td></tr>`;
    }).join("")}</tbody></table>${rows.length > 1500 ? `<p class="small muted">상위 1,500건만 표시 — 검색어로 좁히세요.</p>` : ""}`;
  }

  const nicTxt = n => `${n.device} ${n.driver || ""}${n.driver_version ? " " + n.driver_version : ""}${n.firmware ? " · fw " + n.firmware : ""}${n.speed ? "" : " · 링크 다운"}`;

  function hwTable(d) {
    const hw = d.vcenters.flatMap(v => v.hw.map(h => ({...h, vc: v.connector})));
    const q = st.hq.toLowerCase();
    const rows = hw.filter(h => !q || JSON.stringify(h).toLowerCase().includes(q));
    if (!rows.length) return `<div class="empty">하드웨어 정보가 아직 없습니다(첫 점검 후 표시).</div>`;
    return `<table class="vc-t vc-hw"><thead><tr><th>호스트</th><th>클러스터</th><th>모델 · S/N</th><th>ESXi</th><th>BIOS</th><th>BMC</th><th>NIC 드라이버 · 펌웨어</th><th>HBA 드라이버 · 펌웨어</th><th>센서</th></tr></thead><tbody>${rows.map(h => `
      <tr><td><b>${esc(h.host)}</b></td><td>${esc(h.cluster)}</td><td>${esc(`${h.vendor} ${h.model}`)}<div class="small muted">${esc(h.serial || "")} · ${esc(h.cpu || "")} · ${h.cores || "-"}코어 · ${h.mem_gb}GB</div></td>
      <td>${esc(h.esxi)}</td><td>${esc(h.bios)}<div class="small muted">${esc(h.bios_date || "")}</div></td>
      <td>${h.bmc ? `${esc(h.bmc_fw || "-")}<div class="small muted">${esc(h.bmc)} ${esc(h.bmc_health || "")}</div>` : `<span class="muted small">연결된 BMC 커넥터 없음</span>`}</td>
      <td class="small">${h.nics.map(n => `<div class="${n.speed ? "" : "bad"}">${esc(nicTxt(n))}</div>`).join("") || "-"}</td>
      <td class="small">${h.hbas.map(a => `<div>${esc(`${a.device} ${a.model || ""} · ${a.driver || ""}${a.driver_version ? " " + a.driver_version : ""}${a.firmware ? " · fw " + a.firmware : ""}`)}</div>`).join("") || "-"}</td>
      <td>${h.sensors_bad ? `<span class="vc-sev error">${h.sensors_bad}</span>` : "정상"}</td></tr>`).join("")}</tbody></table>
      <p class="small muted">드라이버 버전: vSphere 8.0U1+ 는 NIC 가 직접 보고, 그 이전은 설치된 VIB 버전으로 보완(6시간 주기). 펌웨어: NIC 는 8.0U1+, HBA 는 9.1+ 에서 vCenter 가 보고하며, 그 밖에는 같은 서버의 BMC(Redfish·CIMC) 커넥터 인벤토리를 씁니다(커넥터의 'ESXi 호스트' 칸으로 연결).</p>`;
  }

  function csv(d) {
    const head = ["host", "cluster", "vendor", "model", "serial", "cpu", "cores", "mem_gb", "esxi", "bios", "bios_date", "bmc_fw", "nics", "hbas"];
    const q = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [head.join(",")];
    for (const v of d.vcenters) for (const h of v.hw) {
      lines.push([h.host, h.cluster, h.vendor, h.model, h.serial, h.cpu, h.cores, h.mem_gb, h.esxi, h.bios, h.bios_date, h.bmc_fw,
        h.nics.map(nicTxt).join(" | "), h.hbas.map(a => `${a.device} ${a.driver} ${a.driver_version || ""} fw ${a.firmware || ""}`).join(" | ")].map(q).join(","));
    }
    const b = new Blob(["﻿" + lines.join("\r\n")], {type: "text/csv"});
    window.AIOPS.download(`vcf-aiops-hardware-${new Date().toISOString().slice(0, 10)}.csv`, b);
  }

  function render() {
    const d = st.d;
    if (!d.vcenters.length) {
      $("#vc-body").innerHTML = `<div class="empty">vCenter 커넥터가 없습니다. 운영 설정 › 커넥터에서 vCenter 를 추가하면 30분마다 Compute·Storage·Network·Hardware 를 점검합니다.</div>`;
      return;
    }
    $("#vc-sub").textContent = "— " + d.vcenters.map(v => `${v.connector}: 호스트 ${v.hosts} · 클러스터 ${v.clusters} · DS ${v.datastores} · ${v.updated ? ago(v.updated) : v.error ? "실패" : "첫 점검 대기"}`).join(" · ");
    const errs = d.vcenters.filter(v => v.error).map(v => `<div class="vc-err">${esc(v.connector)}: ${esc(v.error)}</div>`).join("");
    $("#vc-body").innerHTML = `${errs}${cards(d)}
      <div class="vc-tabs"><button data-tab="find" class="${st.tab === "find" ? "on" : ""}">점검 결과</button><button data-tab="hw" class="${st.tab === "hw" ? "on" : ""}">하드웨어 · 드라이버 · 펌웨어</button></div>
      ${st.tab === "find" ? `<div class="vc-ctl"><select id="vc-min"><option value="">전체 등급</option>${ORDER.map(s => `<option value="${s}"${st.min === s ? " selected" : ""}>${s === "critical" ? SEV[s] : SEV[s] + "↑"}</option>`).join("")}</select>
        <input id="vc-q" placeholder="대상·내용 검색(예: esx03, MTU, 스냅숏)" value="${esc(st.q)}">${st.area ? `<button class="btn-sm" id="vc-all">영역 필터 해제</button>` : ""}<span class="small muted">행을 누르면 권고 조치를 표시</span></div>${findings(d)}`
      : `<div class="vc-ctl"><input id="vc-hq" placeholder="모델·드라이버·펌웨어 검색(예: bnxtnet, SR650)" value="${esc(st.hq)}"><button class="btn-sm" id="vc-csv">CSV 내보내기</button></div>${hwTable(d)}`}`;
  }

  function wire() {
    const body = $("#vc-body");
    body.addEventListener("click", ev => {
      const c = ev.target.closest("[data-area]");
      if (c) { st.area = st.area === c.dataset.area ? "" : c.dataset.area; st.tab = "find"; render(); return; }
      const t = ev.target.closest("[data-tab]");
      if (t) { st.tab = t.dataset.tab; render(); return; }
      if (ev.target.id === "vc-all") { st.area = ""; render(); return; }
      if (ev.target.id === "vc-csv") { csv(st.d); return; }
      const r = ev.target.closest(".vc-r");
      if (r) { const k = r.dataset.k; st.open.has(k) ? st.open.delete(k) : st.open.add(k); render(); }
    });
    body.addEventListener("change", ev => { if (ev.target.id === "vc-min") { st.min = ev.target.value; render(); } });
    let tm;
    body.addEventListener("input", ev => {
      if (ev.target.id !== "vc-q" && ev.target.id !== "vc-hq") return;
      const id = ev.target.id, pos = ev.target.selectionStart;
      clearTimeout(tm);
      tm = setTimeout(() => { st[id === "vc-q" ? "q" : "hq"] = ev.target.value; render(); const el = $("#" + id); if (el) { el.focus(); el.setSelectionRange(pos, pos); } }, 250);
    });
    $("#vc-run").onclick = async () => {
      const b = $("#vc-run"); b.disabled = true; b.textContent = "점검 중…";
      try { const r = await A.api("POST", "/api/vcenter/health/run"); r.errors.length ? A.fail("일부 실패", r.errors.join("\n")) : A.ok("점검 완료", `vCenter ${r.ran}개`); }
      catch (e) { A.fail("점검 실패", e); }
      b.disabled = false; b.textContent = "지금 점검";
      load();
    };
    $("#vc-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-vchk")) return;
    wire();
    $("#nav-vchk").onclick = () => { open("drawer-vchk"); load(); };
    const badge = async () => {
      try {
        const d = await A.api("GET", "/api/vcenter/health?limit=0", undefined, {background: true});
        const n = Object.values(d.summary || {}).reduce((a, m) => a + (m.critical || 0) + (m.error || 0), 0);
        const b = $("#vchk-badge"); b.hidden = !n; b.textContent = n; b.title = `위험·오류 ${n}건`;
      } catch { /* 권한·로그인 전 */ }
    };
    setTimeout(badge, 4000); setInterval(badge, 120000);
  });
  window.AIOPS_VCHECK = {load};
})();
