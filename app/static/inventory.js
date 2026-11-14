/* 전체 인벤토리 — 연결된 커넥터가 수집한 모든 개체(VM·호스트·클러스터·DS·네트워크·NSX·ALB·VKS·서버·에이전트·구성요소)
   GET /api/inventory(검색·상태·정렬·페이지) · /api/inventory/item(상세·관련 개체) · /api/inventory.csv */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const ST = {ok: "정상", warn: "주의", down: "장애", maint: "유지보수", unknown: "미확인", off: "꺼짐"};
  const PAGE = 300;
  const iv = {kind: "vm", q: "", state: "", sort: "name", desc: false, d: null, items: [], total: 0, sel: null, timer: null};
  try { const s = JSON.parse(localStorage.getItem("aiops.inv") || "{}"); Object.assign(iv, {kind: s.kind || "vm", sort: s.sort || "name", desc: !!s.desc}); } catch { /* 무시 */ }
  const save = () => { try { localStorage.setItem("aiops.inv", JSON.stringify({kind: iv.kind, sort: iv.sort, desc: iv.desc})); } catch { /* 무시 */ } };
  const fmt = (k, v) => {
    if (v === null || v === undefined || v === "") return "";
    if ((k === "last" || k === "last_ok") && typeof v === "number") return new Date(v * 1000).toLocaleString();
    if (k === "bw" && typeof v === "number") return v >= 1e9 ? `${(v / 1e9).toFixed(2)} Gb/s` : v >= 1e6 ? `${(v / 1e6).toFixed(1)} Mb/s` : `${Math.round(v / 1e3)} kb/s`;
    if (typeof v === "number" && /pct/.test(k)) return `${v}%`;
    return String(v);
  };
  const qs = extra => new URLSearchParams({kind: iv.kind, q: iv.q, state: iv.state, sort: iv.sort, desc: iv.desc, ...extra}).toString();

  async function load(more = false) {
    try {
      const d = await A.api("GET", `/api/inventory?${qs({offset: more ? iv.items.length : 0, limit: PAGE})}`, undefined, {background: true});
      iv.d = d; iv.total = d.total; iv.items = more ? iv.items.concat(d.items) : d.items;
    } catch (e) { $("#inv-main").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }

  function side() {
    const d = iv.d, groups = {};
    Object.entries(d.kinds).forEach(([k, v]) => { (groups[v.group] = groups[v.group] || []).push([k, v]); });
    const total = Object.values(d.counts).reduce((a, b) => a + b, 0);
    return `<div class="inv-tot">개체 <b>${total.toLocaleString()}</b></div>` + Object.entries(groups).map(([g, ks]) => {
      const vis = ks.filter(([k]) => d.counts[k] || k === iv.kind);
      if (!vis.length) return "";
      return `<div class="inv-g"><h6>${esc(g)}</h6>${vis.map(([k, v]) => `<button class="${k === iv.kind ? "on" : ""}" data-kind="${k}"><span>${esc(v.label)}</span><em>${(d.counts[k] || 0).toLocaleString()}</em></button>`).join("")}</div>`;
    }).join("") + (total ? "" : `<p class="small muted pad8">연결된 커넥터가 없습니다. 운영 설정 › 커넥터에서 vCenter·NSX·NSX ALB 등을 추가하면 여기에 모든 개체가 표시됩니다.</p>`);
  }

  function table() {
    const d = iv.d, def = d.kinds[iv.kind] || {cols: [], label: iv.kind};
    const cols = [["name", "이름"], ["state", "상태"], ...def.cols, ["connector", "커넥터"]];
    const th = cols.map(([k, l]) => `<th data-sort="${k}" class="${iv.sort === k ? (iv.desc ? "desc" : "asc") : ""}">${esc(l)}</th>`).join("");
    const rows = iv.items.map((r, i) => `<tr data-i="${i}" class="${iv.sel && iv.sel.kind === r.kind && iv.sel.name === r.name && iv.sel.connector === r.connector ? "sel" : ""}">${cols.map(([k]) =>
      k === "state" ? `<td><span class="inv-st ${esc(r.state)}">${ST[r.state] || esc(r.state)}</span></td>`
        : k === "name" ? `<td class="inv-nm" title="${esc(r.name)}">${esc(r.name)}</td>` : `<td title="${esc(fmt(k, r[k]))}">${esc(fmt(k, r[k]))}</td>`).join("")}</tr>`).join("");
    const stc = Object.entries(d.states || {}).sort((a, b) => ["down", "warn", "unknown", "maint", "off", "ok"].indexOf(a[0]) - ["down", "warn", "unknown", "maint", "off", "ok"].indexOf(b[0]));
    return `<div class="inv-bar"><input id="inv-q" placeholder="${esc(def.label)} 검색 — 이름·IP·OS·호스트·모델… (공백 = AND)" value="${esc(iv.q)}">
        <div class="inv-chips"><button data-st="" class="${!iv.state ? "on" : ""}">전체 ${Object.values(d.states || {}).reduce((a, b) => a + b, 0)}</button>${stc.map(([s, n]) => `<button data-st="${s}" class="${iv.state === s ? "on" : ""}"><i class="inv-st ${s}"></i>${ST[s] || s} ${n}</button>`).join("")}</div>
        <a class="btn-sm" href="/api/inventory.csv?${qs({})}" download>CSV</a></div>
      <div class="inv-tw"><table class="inv-t"><thead><tr>${th}</tr></thead><tbody>${rows || `<tr><td colspan="${cols.length}" class="empty">조건에 맞는 개체가 없습니다.</td></tr>`}</tbody></table>
      ${iv.items.length < iv.total ? `<button class="btn-sm inv-more" id="inv-more">더 보기 (${iv.items.length.toLocaleString()} / ${iv.total.toLocaleString()})</button>` : `<p class="small muted inv-cnt">${iv.total.toLocaleString()}개</p>`}</div>`;
  }

  function render() {
    $("#inv-side").innerHTML = side();
    const f = document.activeElement && document.activeElement.id === "inv-q" ? document.activeElement.selectionStart : null;
    $("#inv-main").innerHTML = table();
    if (f !== null) { const q = $("#inv-q"); q.focus(); q.setSelectionRange(f, f); }
    const lbl = (iv.d.kinds[iv.kind] || {}).label || "";
    $("#inv-sub").textContent = `— ${lbl} ${iv.total.toLocaleString()}개 · 30초 갱신`;
  }

  async function detail(r) {
    iv.sel = {kind: r.kind, name: r.name, connector: r.connector};
    $$("#inv-main tr.sel").forEach(x => x.classList.remove("sel"));
    const p = $("#inv-detail"); p.hidden = false;
    p.innerHTML = `<div class="tp-dh"><b>${esc(r.name)}</b><button class="x" id="inv-dx" aria-label="닫기">✕</button></div><span class="muted small">불러오는 중…</span>`;
    let d;
    try { d = await A.api("GET", `/api/inventory/item?${new URLSearchParams({kind: r.kind, name: r.name, connector: r.connector})}`, undefined, {background: true}); }
    catch (e) { p.innerHTML += `<p class="bad">${esc(e.message)}</p>`; return; }
    const it = d.item, def = iv.d.kinds[it.kind] || {cols: [], label: it.kind};
    const extra = Object.keys(it).filter(k => !["kind", "name", "state", "connector", "parent"].includes(k) && !def.cols.some(([c]) => c === k) && it[k] !== "" && it[k] != null);
    const rel = {};
    d.related.forEach(x => { (rel[x.kind] = rel[x.kind] || []).push(x); });
    const tail = ["vm", "host", "server", "agent", "k8s-node", "nsx-edge", "avi-se"].includes(it.kind) ? (it.kind === "server" ? (it.esxi || it.name) : (it.kind === "vm" && it.hostname ? it.hostname : it.name)) : "";
    p.innerHTML = `<div class="tp-dh"><b>${esc(it.name)}</b><button class="x" id="inv-dx" aria-label="닫기">✕</button></div>
      <div class="small muted">${esc(def.label)} · <span class="inv-st ${esc(it.state)}">${ST[it.state] || esc(it.state)}</span> · ${esc(it.connector)}</div>
      <dl>${def.cols.filter(([k]) => it[k] !== "" && it[k] != null).map(([k, l]) => `<dt>${esc(l)}</dt><dd>${esc(fmt(k, it[k]))}</dd>`).join("")}
        ${extra.map(k => `<dt>${esc(k)}</dt><dd>${esc(fmt(k, it[k]))}</dd>`).join("")}</dl>
      ${tail ? `<div class="tp-dact"><button class="btn-sm" data-tail="${esc(tail)}">실시간 로그 보기</button></div>` : ""}
      ${Object.entries(rel).map(([k, xs]) => `<h5>${esc((iv.d.kinds[k] || {}).label || k)} <span class="muted small">${xs.length}</span></h5>
        <div class="inv-rel">${xs.slice(0, 60).map(x => `<button data-rel='${esc(JSON.stringify({kind: x.kind, name: x.name, connector: x.connector}))}'><i class="inv-st ${esc(x.state)}"></i>${esc(x.name)}</button>`).join("")}${xs.length > 60 ? `<span class="muted small">외 ${xs.length - 60}개</span>` : ""}</div>`).join("")}`;
    if (["vm", "host", "cluster", "datastore"].includes(it.kind) && window.AIOPS_OPS_METRICS) {   // 2.8.0 VCF Ops 최신 지표(같은 이름)
      window.AIOPS_OPS_METRICS(it.name).then(xs => {
        if (!iv.sel || iv.sel.name !== it.name || !xs.length) return;
        const f = v => Math.abs(v) >= 100 ? Math.round(v).toLocaleString() : (+v.toFixed(2)).toLocaleString();
        p.insertAdjacentHTML("beforeend", xs.map(x => `<h5>VCF Ops 지표 <span class="muted small">${esc(x.connector)}${x.health ? " · " + esc(x.health) : ""}</span></h5>
          <ul class="inv-moves">${x.metrics.map(m => `<li><b>${esc(m.name)}</b> ${f(m.value)}${m.unit ? " " + esc(m.unit) : ""} <span class="small muted">${esc(m.key)}</span></li>`).join("") || "<li class='muted'>값 없음</li>"}</ul>`).join(""));
      }).catch(() => {});
    }
    if (it.kind === "vm" && window.AIOPS_VM_MOVES) {               // 이동·HA 이력(최근 7일)
      window.AIOPS_VM_MOVES(it.name).then(ms => {
        if (!iv.sel || iv.sel.name !== it.name) return;
        const LB = {vmotion: "vMotion", drs: "DRS", svmotion: "Storage vMotion", relocate: "콜드 이전", ha_restart: "HA 재시작", ha_failed: "HA 실패", ha_reset: "HA 리셋", ha_reset_failed: "HA 리셋 실패", move_failed: "이동 실패", detected: "위치 변경 감지", created: "VM 생성", cloned: "VM 복제", deployed: "템플릿 배포", registered: "VM 등록", removed: "VM 삭제", renamed: "이름 변경", create_failed: "생성 실패", detected_new: "새 VM 감지", detected_gone: "VM 사라짐", power_on: "전원 켬", power_off: "전원 끔", suspended: "일시 중단", reset: "리셋", guest_shutdown: "게스트 종료", guest_reboot: "게스트 재시작", reconfigured: "구성 변경", snapshot_create: "스냅샷 생성", snapshot_remove: "스냅샷 삭제", snapshot_remove_all: "스냅샷 모두 삭제", snapshot_revert: "스냅샷 되돌림"};
        p.insertAdjacentHTML("beforeend", `<h5>VM 액티비티 <span class="muted small">최근 7일 ${ms.length}</span> ${window.AIOPS_VM_TIMELINE ? `<a href="#" class="btn-sm" data-vmtl="${esc(it.name)}">일대기 보기</a>` : ""}</h5>${ms.length ? `<ul class="inv-moves">${ms.slice(0, 20).map(m => `<li><span class="small muted">${new Date(m.ts * 1000).toLocaleString()}</span> <b>${esc(LB[m.type] || m.type)}</b>${m.detail ? ` <span class="small">${esc(m.detail)}</span>` : ""} ${m.from_host || m.to_host ? `${esc(m.from_host || "-")} → ${esc(m.to_host || "-")}` : ""}${m.user ? ` <span class="small muted">· ${esc(m.user)}</span>` : ""}${m.from_ds && m.to_ds && m.from_ds !== m.to_ds ? ` · ${esc(m.from_ds)} → ${esc(m.to_ds)}` : ""}</li>`).join("")}</ul>` : `<p class="muted small">기록 없음</p>`}`);
      }).catch(() => {});
    }
  }

  function wire() {
    $("#inv-side").addEventListener("click", e => {
      const b = e.target.closest("[data-kind]"); if (!b) return;
      iv.kind = b.dataset.kind; iv.state = ""; iv.sort = "name"; iv.desc = false; save(); load();
    });
    const m = $("#inv-main");
    m.addEventListener("click", e => {
      const h = e.target.closest("th[data-sort]");
      if (h) { if (iv.sort === h.dataset.sort) iv.desc = !iv.desc; else { iv.sort = h.dataset.sort; iv.desc = false; } save(); load(); return; }
      const s = e.target.closest("[data-st]"); if (s) { iv.state = s.dataset.st; load(); return; }
      if (e.target.id === "inv-more") { load(true); return; }
      const tr = e.target.closest("tr[data-i]"); if (tr) { detail(iv.items[+tr.dataset.i]); tr.classList.add("sel"); }
    });
    let t; m.addEventListener("input", e => { if (e.target.id !== "inv-q") return; clearTimeout(t); t = setTimeout(() => { iv.q = e.target.value; load(); }, 250); });
    $("#inv-detail").addEventListener("click", e => {
      if (e.target.id === "inv-dx") { $("#inv-detail").hidden = true; iv.sel = null; return; }
      const tl = e.target.closest("[data-tail]"); if (tl) { $("#drawer-inv").hidden = true; location.hash = ""; location.hash = `#tail/${encodeURIComponent(tl.dataset.tail)}`; return; }
      const r = e.target.closest("[data-rel]"); if (r) { const x = JSON.parse(r.dataset.rel); if (x.kind !== iv.kind) { iv.kind = x.kind; iv.state = ""; iv.q = ""; load(); } detail(x); }
    });
    $("#inv-reload").onclick = () => load();
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-inv")) return;
    wire();
    $("#nav-inv").onclick = () => {
      $$(".drawer").forEach(d => { if (d.id !== "drawer-inv") d.hidden = true; });
      $("#drawer-inv").hidden = false; load();
      clearInterval(iv.timer);
      iv.timer = setInterval(() => $("#drawer-inv").hidden ? clearInterval(iv.timer) : (document.activeElement && document.activeElement.id === "inv-q" ? null : load()), 30000);
    };
    // 딥링크: /#inv/<종류>/<이름>
    const fromHash = () => { const m = location.hash.match(/^#inv\/([^/]+)(?:\/(.+))?$/); if (!m) return; $("#nav-inv").click(); iv.kind = m[1]; if (m[2]) iv.q = decodeURIComponent(m[2]); load(); };
    addEventListener("hashchange", fromHash); setTimeout(fromHash, 900);
  });
})();
