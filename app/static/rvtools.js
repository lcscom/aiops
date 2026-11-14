/* RVTools 분석(2.15.0) — RVTools 'Export all to xlsx' 업로드 → 물리·논리·스토리지 구성도, 전체 컴플라이언스(인프라 점검·KISA·VMSA·RVTools 점검·VCF 9),
   용량·VM·호스트·스토리지·네트워크 분석, 설정된 LLM(PAIS 등) 진단 보고서와 질의응답. 원본 파일은 저장하지 않고 정규화·분석 결과만 보관 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {list: [], id: "", d: null, tab: "sum", g: {}, gk: "physical", tables: {}, tf: "", sev: "", src: "", area: "", kst: "", sel: null, q: "",
              view: {x: 0, y: 0, k: 1}, drag: null, pos: {}, llm: false, asking: false, qa: [], vmLimit: 400, sort: {}, maxMb: 100};
  const SEV = {critical: ["위험", "bad"], error: ["오류", "bad"], warning: ["경고", "warn"], info: ["정보", "inf"]};
  const KST = {PASS: ["적합", "ok"], FAIL: ["부적합", "bad"], WARN: ["주의", "warn"], MANUAL: ["현장 확인", "unk"], "N/A": ["해당 없음", "unk"]};
  const VD = {ready: ["준비됨", "ok"], actions: ["조치 필요", "warn"], not_ready: ["준비 안 됨", "bad"], unknown: ["확인 필요", "unk"]};
  const CST = {pass: ["통과", "ok"], warn: ["주의", "warn"], fail: ["실패", "bad"], unknown: ["확인 불가", "unk"], info: ["참고", "inf"]};
  const AREA = {compute: "컴퓨트", storage: "스토리지", network: "네트워크", vm: "VM", security: "보안", capacity: "용량", license: "라이선스", vcf9: "VCF 9", rvtools: "RVTools", cluster: "클러스터", host: "호스트", hardware: "하드웨어"};
  const TABS = [["sum", "요약"], ["phys", "물리 구성도"], ["logic", "논리 구성도"], ["stor", "스토리지 구성도"], ["comp", "컴플라이언스"], ["vcf9", "VCF 9 준비도"],
                ["vms", "VM"], ["hosts", "호스트·클러스터"], ["ds", "스토리지"], ["net", "네트워크"], ["ai", "AI 분석"]];
  const GK = {phys: "physical", logic: "logical", stor: "storage"};
  const COL = {ok: "#2e7d32", warn: "#c77700", down: "#c21d00", maint: "#8a96a0", unknown: "#8a96a0"};
  const TAG = {vcenter: "VC", datacenter: "DC", cluster: "CL", esxi: "ESX", pnic: "NIC", hba: "HBA", vds: "VDS", vss: "vSS", mpath: "PATH", datastore: "DS", portgroup: "PG",
               vm: "VM", vmk: "VMK", vmgroup: "VM+"};
  const KIND = {vcenter: "vCenter", datacenter: "데이터센터", cluster: "클러스터", esxi: "ESXi 호스트", pnic: "물리 NIC", hba: "HBA", vds: "Distributed Switch", vss: "표준 vSwitch",
                mpath: "스토리지 경로", datastore: "데이터스토어", portgroup: "포트그룹", vm: "가상 머신", vmk: "VMkernel", vmgroup: "VM 묶음"};
  const b = (m, k, lab) => { const x = m[k] || [k, "unk"]; return `<span class="rd-b ${x[1]}">${esc(lab || x[0])}</span>`; };
  const n = (x, d = 0) => x === null || x === undefined || x === "" ? "—" : Number(x).toLocaleString(undefined, {maximumFractionDigits: d});
  const fmt = ts => ts ? new Date(ts * 1000).toLocaleString([], {year: "2-digit", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";
  const gb = mib => mib == null ? "—" : n(mib / 1024, 1);
  const enc = encodeURIComponent;
  const perms = box => { if (A.me && A.can) $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); }); };

  async function loadList() { try { const r = await A.api("GET", "/api/rvtools", undefined, {background: true}); st.list = r.items; st.llm = r.llm; st.maxMb = r.max_mb; } catch (e) { A.fail("RVTools 목록 실패", e); } }
  async function open(id) {
    st.id = id; st.d = null; st.g = {}; st.tables = {}; st.sel = null; st.qa = []; render();
    try { st.d = await A.api("GET", `/api/rvtools/${enc(id)}`); st.llm = st.d.llm; } catch (e) { A.fail("분석 불러오기 실패", e); st.id = ""; }
    render();
  }
  async function table(name) {
    if (!st.tables[name]) { try { st.tables[name] = (await A.api("GET", `/api/rvtools/${enc(st.id)}/table/${name}`, undefined, {background: true})).items; } catch (e) { A.fail("표 불러오기 실패", e); st.tables[name] = []; } }
    return st.tables[name];
  }

  // ------------------------------------------------------------------ 업로드·목록
  function home() {
    return `<div class="rv-drop" id="rv-drop"><b>RVTools 내보내기 파일(.xlsx)을 여기에 끌어다 놓거나</b> <label class="btn-sm solid" data-perm="operate">파일 선택<input type="file" id="rv-file" accept=".xlsx" hidden></label>
        <p class="small muted">RVTools › File › Export all to xlsx 결과(최대 ${st.maxMb}MB). 원본 파일은 저장하지 않고 정규화·분석 결과만 보관합니다. 외부 LLM 으로 보낼 때는 호스트·VM·IP 이름을 가명화합니다.</p>
        <div id="rv-up" class="small"></div></div>
      <div class="rd-card"><h4>분석 목록 <small>최근 ${st.list.length}건</small></h4>${st.list.length ? `<table class="rd-t rd-click-t"><thead><tr><th>파일</th><th>vCenter</th><th>내보낸 시각</th><th>호스트</th><th>VM(켜짐/전체)</th><th>점수</th><th>위험·오류·경고</th><th>KISA</th><th>AI</th><th>올린 사람</th><th></th></tr></thead><tbody>${
        st.list.map(x => { const f = x.findings || {}, c = x.counts || {};
          return `<tr class="rd-click" data-rvo="${esc(x.id)}"><td><b>${esc(x.name)}</b><div class="small muted">${fmt(x.uploaded)} · ${n((x.size || 0) / 1048576, 1)} MB</div></td><td>${esc((x.vcenters || []).join(", "))}</td>
            <td>${fmt(x.exported)}</td><td>${n(c.hosts)}</td><td>${n(c.vms_on)}/${n(c.vms)}</td><td><b class="rv-score ${x.score >= 80 ? "ok" : x.score >= 60 ? "warn" : "bad"}">${n(x.score)}</b></td>
            <td>${(f.critical || 0) + (f.error || 0)} · ${f.warning || 0}</td><td>${x.kisa == null ? "—" : n(x.kisa, 1) + "%"}</td><td>${x.ai ? "✓" : ""}</td><td class="small">${esc(x.by || "")}</td>
            <td><button class="btn-sm" data-rvdel="${esc(x.id)}" data-perm="operate" title="삭제">삭제</button></td></tr>`; }).join("")}</tbody></table>` : `<p class="muted">아직 올린 파일이 없습니다.</p>`}</div>`;
  }
  async function upload(f) {
    if (!f) return;
    if (!/\.xlsx$/i.test(f.name)) { A.fail("xlsx 파일만", new Error(f.name)); return; }
    if (f.size > st.maxMb * 1048576) { A.fail("파일이 너무 큽니다", new Error(`${n(f.size / 1048576, 1)} MB > ${st.maxMb} MB`)); return; }
    const box = $("#rv-up"); if (box) box.innerHTML = `<div class="rd-prog"><i style="width:35%" class="rv-anim"></i></div>${esc(f.name)} 올리는 중·분석 중…`;
    try {
      const r = await fetch(`/api/rvtools/upload?name=${enc(f.name)}`, {method: "POST", body: f, headers: {"X-Requested-With": "aiops", "Content-Type": "application/octet-stream"}});
      const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.status);
      A.ok("분석 완료", `${j.name} · 호스트 ${j.counts.hosts} · VM ${j.counts.vms} · 점수 ${j.score}`);
      await loadList(); await open(j.id);
    } catch (e) { A.fail("업로드·분석 실패", e); if (box) box.textContent = ""; }
  }

  // ------------------------------------------------------------------ 요약
  function bars(title, obj, cls = "") {
    const e = Array.isArray(obj) ? obj : Object.entries(obj || {}); const mx = Math.max(1, ...e.map(x => x[1]));
    return `<div class="rd-db"><h5>${esc(title)}</h5>${e.slice(0, 12).map(([k, v]) => `<div class="rd-bar"><span title="${esc(k)}">${esc(String(k).slice(0, 24))}</span><i class="${cls}" style="width:${v / mx * 100}%"></i><b>${n(v)}</b></div>`).join("") || `<p class="muted small">없음</p>`}</div>`;
  }
  function sumTab() {
    const d = st.d, s = d.summary, c = s.counts, cp = s.compute, sg = s.storage, f = d.counts || {};
    const tiles = [["종합 점수", `${n(d.score)}<small>/100</small>`, d.score >= 80 ? "ok" : d.score >= 60 ? "warn" : "bad"], ["위험·오류", (f.critical || 0) + (f.error || 0), (f.critical || f.error) ? "bad" : "ok"],
      ["경고", f.warning || 0, f.warning ? "warn" : "ok"], [`KISA 적합률 <span title="RVTools 로 자동 판정된 항목만 — 나머지는 현장 확인">(자동 ${(d.hardening.counts.PASS || 0) + (d.hardening.counts.FAIL || 0) + (d.hardening.counts.WARN || 0)}행)</span>`, d.hardening.score == null ? "—" : n(d.hardening.score, 1) + "%", ""], ["VMSA 취약", d.vmsa.db ? d.vmsa.vulnerable : "DB 없음", d.vmsa.vulnerable ? "bad" : ""],
      ["클러스터·호스트", `${c.clusters} · ${c.hosts}`, ""], ["VM 켜짐/전체", `${c.vms_on}/${c.vms}`, ""], ["템플릿", c.templates, ""],
      ["vCPU:코어", cp.ratio == null ? "—" : cp.ratio + ":1", cp.ratio > 5 ? "warn" : ""], ["메모리 할당률", cp.mem_overcommit == null ? "—" : n(cp.mem_overcommit * 100) + "%", cp.mem_overcommit > 1 ? "warn" : ""],
      ["스토리지 사용", sg.used_pct == null ? "—" : sg.used_pct + "%", sg.used_pct > 85 ? "bad" : sg.used_pct > 75 ? "warn" : ""], ["꺼진 VM 디스크", sg.off_prov_tb + " TB", ""]];
    const vc = s.vcenters.map(v => `<b>${esc(v.name)}</b> <span class="small muted">${esc(v.fullname || v.version || "")}</span>`).join(" · ");
    const cls = s.clusters.map(x => `<tr><td><b>${esc(x.name)}</b></td><td>${x.hosts}</td><td>${n(x.cores)}</td><td>${x.vms_on}</td><td>${n(x.vcpu)}</td><td class="${x.ratio > 5 ? "cc-na" : ""}">${x.ratio ?? "—"}:1</td>
      <td>${n(x.mem_gb)}</td><td>${n(x.vram_gb)}</td><td>${x.mem_used_pct ?? "—"}%</td><td class="${x.n1_mem_pct > 90 ? "cc-na" : ""}">${x.n1_mem_pct ?? "—"}%</td><td>${x.cpu_avg ?? "—"}%</td>
      <td>${x.ha ? "켬" : "<b class='cc-na'>끔</b>"}</td><td>${x.drs ? "켬 " + esc(x.drs_behavior || "") : "끔"}</td></tr>`).join("");
    const top = (t, k, u) => `<div class="rd-db"><h5>${t}</h5><table class="rd-t">${(s.top[k] || []).slice(0, 8).map(v => `<tr><td><a href="#" data-rvq="${esc(v.name)}">${esc(v.name)}</a></td><td style="text-align:right">${u(v.value)}</td></tr>`).join("")}</table></div>`;
    const lic = (s.licenses || []).map(l => `<tr><td>${esc(l.name)}</td><td>${n(l.used)} / ${n(l.total)} ${esc(l.unit || "")}</td><td>${esc(l.expires_raw || "")}</td></tr>`).join("");
    return `<div class="rv-head">${vc} · RVTools ${esc((s.rvtools || {}).rvtools || "")} · 내보낸 시각 ${fmt(d.exported)} · 분석 ${fmt(d.evaluated)}</div>
      <div class="rd-tiles">${tiles.map(([k, v, c2]) => `<div class="rd-tile ${c2}"><small>${k}</small><b>${v}</b></div>`).join("")}</div>
      <div class="rd-card"><h4>클러스터 용량 <small>N+1 = 가장 큰 호스트 하나가 빠졌을 때 메모리 사용률</small></h4><table class="rd-t"><thead><tr><th>클러스터</th><th>호스트</th><th>코어</th><th>켜진 VM</th><th>vCPU</th><th>vCPU:코어</th><th>메모리 GB</th><th>VM 메모리 GB</th><th>메모리 사용</th><th>N+1</th><th>CPU 평균</th><th>HA</th><th>DRS</th></tr></thead><tbody>${cls}</tbody></table></div>
      <div class="rd-card"><h4>컴퓨트·스토리지</h4><div class="rv-kv"><span>소켓·코어</span><b>${cp.sockets} · ${n(cp.cores)}</b><span>물리 메모리</span><b>${n(cp.mem_gb)} GB</b><span>vCPU(켜짐/전체)</span><b>${n(cp.vcpu_on)} / ${n(cp.vcpu_all)}</b>
        <span>VM 메모리(켜짐)</span><b>${n(cp.vram_on_gb)} GB</b><span>데이터스토어</span><b>${sg.cap_tb} TB · 여유 ${sg.free_tb} TB · 프로비전 ${sg.prov_tb} TB</b><span>VM 디스크</span><b>프로비전 ${sg.vm_prov_tb} TB · 사용 ${sg.vm_used_tb} TB</b>
        <span>스냅숏</span><b>${c.snapshots}개 · ${n(sg.snap_gb, 1)} GB</b><span>데이터스토어 유형</span><b>${Object.entries(sg.types).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</b></div></div>
      <div class="rd-dist">${bars("게스트 OS", (s.os || []).map(x => [x.os, x.count]))}${bars("가상 HW 버전", s.hw_versions)}${bars("VMware Tools(켜진 VM)", s.tools)}${bars("전원", s.power)}${bars("점검 영역", Object.entries(d.areas).map(([k, v]) => [AREA[k] || k, Object.values(v).reduce((a, x) => a + x, 0)]), "warn")}</div>
      <div class="rd-dist">${top("vCPU 상위", "vcpu", v => n(v))}${top("메모리 상위(GB)", "mem_mb", v => n(v / 1024, 1))}${top("디스크 프로비전 상위(GB)", "prov_mib", v => gb(v))}</div>
      ${lic ? `<div class="rd-card"><h4>라이선스</h4><table class="rd-t"><thead><tr><th>이름</th><th>사용/총</th><th>만료</th></tr></thead><tbody>${lic}</tbody></table></div>` : ""}`;
  }

  // ------------------------------------------------------------------ 구성도(계층형 SVG — 끌기·휠·검색·경로 강조)
  async function graphTab() {
    const k = GK[st.tab];
    if (!st.g[k]) {
      try { st.g[k] = await A.api("GET", `/api/rvtools/${enc(st.id)}/graph/${k}?vm_limit=${st.vmLimit}`, undefined, {background: true}); } catch (e) { A.fail("구성도 실패", e); return `<p class="muted">구성도를 만들지 못했습니다.</p>`; }
      st.sel = null; st.fitPending = true;
    }
    const g = st.g[k], c = g.counts;
    const legend = Object.entries({ok: "정상", warn: "주의", down: "장애·오류", maint: "꺼짐·유지보수"}).map(([s2, l]) => `<i style="background:${COL[s2]}"></i>${l}`).join("");
    const hint = {physical: "vCenter → 데이터센터 → 클러스터 → ESXi(제조사·모델) → 물리 NIC·HBA → 가상 스위치·스토리지 경로 → 데이터스토어·포트그룹",
                  logical: "기존 '물리 → 논리' 스택 구성도 로직 그대로 — ESXi → VDS → VM → 포트그룹(RVTools 로 만든 가상 vCenter 커넥터)",
                  storage: "클러스터 → ESXi → HBA·VMkernel(NFS/vSAN) → 데이터스토어(사용률) → VM(VMDK 위치)"}[k];
    return `<div class="rv-gbar"><input id="rv-gq" placeholder="이름 검색 — Enter" value="${esc(st.q)}" autocomplete="off"><button class="btn-sm" id="rv-gclr">경로 해제</button><button class="btn-sm" id="rv-gfit">화면 맞춤</button>
        ${k !== "physical" ? `<label class="small">VM <select id="rv-vml">${[[0, "숨김"], [100, "100"], [400, "400"], [1500, "1500"], [3000, "전부(최대 3000)"]].map(([v, l]) => `<option value="${v}" ${st.vmLimit === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>` : ""}
        <span class="small muted">노드 ${g.nodes.length} · 연결 ${g.links.length}${c ? ` · ESXi ${c.esxi} · VDS ${c.vds} · VM ${c.vm} · 포트그룹 ${c.portgroup}` : ""}</span><span class="rd-sp"></span><span class="rv-leg">${legend}</span></div>
      <p class="small muted">${hint}. 노드를 누르면 위·아래로 연결된 경로 전체를 강조합니다. 끌기 = 이동, 휠 = 확대·축소.</p>
      <div class="rv-gwrap"><div class="rv-canvas" id="rv-cv"><svg id="rv-svg"><g id="rv-g"></g></svg></div><aside class="rv-side" id="rv-side" hidden></aside></div>`;
  }
  function glayout(nodes, links, W, Hc) {
    const layers = [...new Set(nodes.map(x => x.layer))].sort((a, c) => a - c);
    const cols = layers.map(l => nodes.filter(x => x.layer === l).sort((a, c) => (a.group || "").localeCompare(c.group || "") || a.label.localeCompare(c.label)));
    const idx = {}, nb = {};
    links.forEach(l => { (nb[l.s] = nb[l.s] || []).push(l.t); (nb[l.t] = nb[l.t] || []).push(l.s); });
    cols.forEach(c => c.forEach((x, i) => { idx[x.id] = i / Math.max(1, c.length - 1); }));
    for (let it = 0; it < 8; it++) {                    // 이웃 평균 위치(barycenter) 정렬 — 선 교차 줄이기
      for (const c of (it % 2 ? [...cols].reverse() : cols)) {
        c.forEach(x => { const ns = (nb[x.id] || []).filter(y => idx[y] != null); x._b = ns.length ? ns.reduce((a, y) => a + idx[y], 0) / ns.length : idx[x.id]; });
        c.sort((a, c2) => a._b - c2._b); c.forEach((x, i) => { idx[x.id] = i / Math.max(1, c.length - 1); });
      }
    }
    // 노드가 많은 계층은 여러 줄로 접어 화면 높이에 맞춤(세로로 끝없이 길어지지 않게)
    const H = 30, G = 8, top = 46, maxRows = Math.max(12, Math.floor((Hc - top - 20) / (H + G)));
    const subs = cols.map(c => Math.max(1, Math.ceil(c.length / maxRows)));
    const nCols = subs.reduce((a, x) => a + x, 0), colW = Math.max(230, (W - 40) / Math.max(1, nCols));
    const rows = cols.map((c, i) => Math.ceil(c.length / subs[i])), maxN = Math.max(...rows, 1), totalH = top + maxN * (H + G) + 20, pos = {}, base = [];
    let x0 = 20;
    cols.forEach((c, ci) => { base.push(x0); const rp = rows[ci], off = (maxN - rp) * (H + G) / 2;
      c.forEach((x, i) => { const sc = Math.floor(i / rp), r = i % rp; pos[x.id] = {x: x0 + sc * colW, y: top + off + r * (H + G), w: colW - 56, h: H}; });
      x0 += subs[ci] * colW; });
    return {pos, layers, colW, base, totalH, width: x0};
  }
  function chain(g, id) {
    const up = new Set([id]), down = new Set([id]), L = Object.fromEntries(g.nodes.map(x => [x.id, x.layer]));
    let ch = true;
    while (ch) { ch = false;
      for (const l of g.links) {
        if (down.has(l.s) && !down.has(l.t) && L[l.t] >= L[l.s]) { down.add(l.t); ch = true; }
        if (up.has(l.t) && !up.has(l.s) && L[l.s] <= L[l.t]) { up.add(l.s); ch = true; }
      }
    }
    return new Set([...up, ...down]);
  }
  function drawGraph() {
    const g = st.g[GK[st.tab]], cv = $("#rv-cv"); if (!g || !cv) return;
    if (!g.nodes.length) { cv.innerHTML = `<p class="muted pad">표시할 구성요소가 없습니다.</p>`; return; }
    const W = cv.clientWidth || 1400, Hc = cv.clientHeight || 700, L = glayout(g.nodes, g.links, W, Hc); st.pos = L.pos;
    const hl = st.sel ? chain(g, st.sel) : null, by = Object.fromEntries(g.nodes.map(x => [x.id, x]));
    const hdr = L.layers.map((l, i) => `<text class="rv-lh" x="${L.base[i]}" y="22">${esc(g.layers[l] || "")} <tspan>${g.nodes.filter(x => x.layer === l).length}</tspan></text>
      <line x1="${L.base[i] - 14}" x2="${L.base[i] - 14}" y1="8" y2="${L.totalH}" class="rv-sep"/>`).join("");
    const paths = g.links.map(l => { const a = L.pos[l.s], c = L.pos[l.t]; if (!a || !c) return "";
      const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = c.x, y2 = c.y + c.h / 2, dx = Math.max(30, (x2 - x1) / 2), on = hl && hl.has(l.s) && hl.has(l.t), bad = by[l.t].state === "down" || by[l.s].state === "down";
      return `<path d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}" class="rv-l ${on ? "on" : hl ? "dim" : ""} ${bad ? "bad" : ""}"><title>${esc(by[l.s].label)} → ${esc(by[l.t].label)}${l.k ? " (" + esc(l.k) + ")" : ""}</title></path>`; }).join("");
    const rects = g.nodes.map(x => { const p = L.pos[x.id], on = !hl || hl.has(x.id), lab = x.label.length > 30 ? x.label.slice(0, 29) + "…" : x.label;
      return `<g class="rv-n ${on ? "" : "dim"} ${x.id === st.sel ? "sel" : ""}" data-id="${esc(x.id)}" transform="translate(${p.x},${p.y})"><rect width="${p.w}" height="${p.h}" rx="4"/>
        <rect width="5" height="${p.h}" rx="2" fill="${COL[x.state] || COL.unknown}"/><text class="tg" x="12" y="19">${TAG[x.kind] || ""}</text><text class="lb" x="48" y="19">${esc(lab)}</text>
        <title>${esc(KIND[x.kind] || x.kind)} · ${esc(x.label)}${x.sub ? "\n" + esc(x.sub) : ""}</title></g>`; }).join("");
    const svg = $("#rv-svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${Hc}`); st.L = {W, Hc, w: L.width, h: L.totalH};
    if (st.fitPending) { st.fitPending = false; fit(); }
    $("#rv-g").innerHTML = hdr + paths + rects; applyView(); side(g, by, hl);
  }
  function side(g, by, hl) {
    const p = $("#rv-side"); if (!p) return; if (!st.sel || !by[st.sel]) { p.hidden = true; return; }
    const x = by[st.sel]; p.hidden = false;
    const kv = (k, v) => v === undefined || v === null || v === "" ? "" : `<dt>${k}</dt><dd>${esc(String(v))}</dd>`;
    const per = {}; [...hl].filter(y => y !== x.id && by[y]).forEach(y => { (per[by[y].layer] = per[by[y].layer] || []).push(by[y]); });
    p.innerHTML = `<div class="rv-sh"><b>${esc(x.label)}</b><button class="x" id="rv-sx">✕</button></div><div class="small" style="color:${COL[x.state]}">${esc(KIND[x.kind] || x.kind)}</div>
      <dl>${kv("설명", x.sub)}${kv("그룹", x.group)}${kv("CPU", x.cpu != null ? x.cpu + "%" : "")}${kv("메모리", x.mem != null ? x.mem + "%" : "")}${kv("VM", x.vms)}${kv("CPU 모델", x.cpu_model)}
        ${kv("S/N", x.serial)}${kv("BIOS", x.bios)}${kv("ESXi", x.esx)}${kv("전원", x.power)}${kv("IP", (x.ips || []).join(", ") || x.ip)}${kv("게스트 OS", x.os)}${kv("ESXi 호스트", x.host)}
        ${kv("vCPU·메모리", x.vcpu != null ? `${x.vcpu} vCPU · ${x.mem_gb} GB` : "")}${kv("네트워크", (x.networks || []).join(", "))}${kv("데이터스토어", (x.datastores || []).join(", "))}</dl>
      ${(x.pnics || []).length ? `<h5>물리 NIC</h5><table class="rd-t">${x.pnics.map(y => `<tr><td>${esc(y.name)}</td><td>${y.speed ? (y.speed >= 1000 ? y.speed / 1000 + "G" : y.speed + "M") : "<b class='cc-na'>down</b>"}</td></tr>`).join("")}</table>` : ""}
      <h5>연결된 경로</h5>${Object.keys(per).sort((a, c) => a - c).map(l => `<div class="rv-pl"><span>${esc(g.layers[l] || "")}</span>${per[l].slice(0, 30).map(m => `<button data-go="${esc(m.id)}" style="--sc:${COL[m.state]}">${esc(m.label)}</button>`).join("")}${per[l].length > 30 ? ` <small>외 ${per[l].length - 30}</small>` : ""}</div>`).join("") || `<p class="muted">연결 없음</p>`}
      ${["vm", "esxi", "datastore"].includes(x.kind) ? `<p><button class="btn-sm" data-rvq="${esc(x.label)}">AI 에게 이 개체 묻기</button></p>` : ""}`;
  }
  function fit() { const L = st.L; if (!L) return; const k = Math.max(0.5, Math.min(1, L.Hc / L.h, L.W / L.w)); st.view = {k, x: Math.max(0, (L.W - L.w * k) / 2), y: Math.max(0, (L.Hc - L.h * k) / 2)}; applyView(); }
  function applyView() { const g = $("#rv-g"), v = st.view; if (g) g.setAttribute("transform", `translate(${v.x},${v.y}) scale(${v.k})`); }
  function gpick(q) {
    const g = st.g[GK[st.tab]]; q = String(q || "").trim().toLowerCase(); if (!g || !q) return;
    const x = g.nodes.find(y => y.label.toLowerCase() === q) || g.nodes.find(y => y.label.toLowerCase().includes(q));
    if (!x) { A.fail("찾지 못함", new Error(q)); return; }
    st.sel = x.id; drawGraph(); const p = st.pos[x.id], L = st.L;
    st.view.k = Math.max(st.view.k, 0.9); st.view.x = L.W / 2 - (p.x + p.w / 2) * st.view.k; st.view.y = L.Hc / 3 - p.y * st.view.k; applyView();
  }
  function wireGraph() {
    const cv = $("#rv-cv"); if (!cv) return;
    cv.addEventListener("click", e => { if (st.moved) { st.moved = false; return; } const g = e.target.closest(".rv-n"); st.sel = g ? (st.sel === g.dataset.id ? null : g.dataset.id) : null; drawGraph(); });
    cv.addEventListener("pointerdown", e => { if (e.button === 0) { st.drag = {x: e.clientX, y: e.clientY, vx: st.view.x, vy: st.view.y}; st.moved = false; } });
    cv.addEventListener("wheel", e => { e.preventDefault(); const svg = $("#rv-svg"), r = svg.getBoundingClientRect(), sc = svg.clientWidth / svg.viewBox.baseVal.width;
      const mx = (e.clientX - r.left) / sc, my = (e.clientY - r.top) / sc, k0 = st.view.k, k1 = Math.min(4, Math.max(0.2, k0 * (e.deltaY < 0 ? 1.15 : 1 / 1.15)));
      st.view.x = mx - (mx - st.view.x) * k1 / k0; st.view.y = my - (my - st.view.y) * k1 / k0; st.view.k = k1; applyView(); }, {passive: false});
  }
  addEventListener("pointermove", e => { if (!st.drag) return; const svg = $("#rv-svg"); if (!svg) return; const sc = svg.clientWidth / svg.viewBox.baseVal.width;
    const dx = (e.clientX - st.drag.x) / sc, dy = (e.clientY - st.drag.y) / sc; if (Math.abs(dx) + Math.abs(dy) > 4) st.moved = true; st.view.x = st.drag.vx + dx; st.view.y = st.drag.vy + dy; applyView(); });
  addEventListener("pointerup", () => { st.drag = null; });

  // ------------------------------------------------------------------ 컴플라이언스
  function compTab() {
    const d = st.d, F = d.findings.filter(x => (!st.sev || x.severity === st.sev) && (!st.src || x.source === st.src) && (!st.area || x.area === st.area)
      && (!st.tf || (x.entity + " " + x.title + " " + x.detail + " " + x.id).toLowerCase().includes(st.tf.toLowerCase())));
    const srcs = [...new Set(d.findings.map(x => x.source))], areas = [...new Set(d.findings.map(x => x.area))];
    const H = d.hardening, K = H.rows.filter(r => !st.kst || r.status === st.kst);
    const kisa = (H.kisa || []).map(k => `<tr><td>${esc(k.code)}</td><td>${esc(k.title)}</td><td>${esc(k.importance || "")}</td><td>${b(KST, k.status)}</td><td>${k.checks}</td><td>${k.fail}</td></tr>`).join("");
    const vm = d.vmsa;
    return `<div class="rd-tiles">${["critical", "error", "warning", "info"].map(s => `<div class="rd-tile ${SEV[s][1] === "inf" ? "" : SEV[s][1]} rd-click" data-rvsev="${s}"><small>${SEV[s][0]}</small><b>${d.counts[s] || 0}</b></div>`).join("")}
        ${Object.entries(H.counts).map(([k, v]) => `<div class="rd-tile ${(KST[k] || [0, ""])[1]} rd-click" data-rvkst="${esc(k)}"><small>KISA ${(KST[k] || [k])[0]}</small><b>${v}</b></div>`).join("")}</div>
      <div class="rd-card"><h4>점검 결과 <small>인프라 점검(기존 규칙) · RVTools 점검 · VCF 9 준비도 — ${F.length}/${d.findings.length}건</small></h4>
        <div class="rd-tools"><select id="rv-sev"><option value="">모든 등급</option>${Object.entries(SEV).map(([k, v]) => `<option value="${k}" ${st.sev === k ? "selected" : ""}>${v[0]}</option>`).join("")}</select>
          <select id="rv-src"><option value="">모든 출처</option>${srcs.map(s => `<option ${st.src === s ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
          <select id="rv-area"><option value="">모든 영역</option>${areas.map(s => `<option value="${esc(s)}" ${st.area === s ? "selected" : ""}>${esc(AREA[s] || s)}</option>`).join("")}</select>
          <input id="rv-tf" placeholder="필터(대상·내용)" value="${esc(st.tf)}"></div>
        <div class="rd-scroll"><table class="rd-t"><thead><tr><th>등급</th><th>점검</th><th>영역</th><th>대상</th><th>내용</th><th>상세</th><th>조치</th></tr></thead><tbody>${F.slice(0, 1500).map(x => `<tr><td>${b(SEV, x.severity)}</td>
          <td class="small">${esc(x.id)}<div class="muted">${esc(x.source)}</div></td><td class="small">${esc(AREA[x.area] || x.area)}</td><td><b>${esc(x.entity)}</b></td><td>${esc(x.title)}</td>
          <td class="small">${esc(String(x.detail || "")).slice(0, 300)}</td><td class="small rd-fix">${esc(x.fix || "")}${x.ref ? ` <a href="${esc(x.ref)}" target="_blank" rel="noopener">근거</a>` : ""}</td></tr>`).join("")}</tbody></table></div></div>
      <div class="rd-card"><h4>KISA 하이퍼바이저 보안(HV) <small>${esc(H.note)}</small></h4><table class="rd-t"><thead><tr><th>코드</th><th>항목</th><th>중요도</th><th>결과</th><th>점검</th><th>부적합</th></tr></thead><tbody>${kisa}</tbody></table>
        <h5>세부 행 <select id="rv-kst"><option value="">전체 ${H.rows.length}</option>${Object.keys(KST).map(k => `<option value="${k}" ${st.kst === k ? "selected" : ""}>${KST[k][0]} ${H.counts[k] || 0}</option>`).join("")}</select></h5>
        <div class="rd-scroll" style="max-height:40vh"><table class="rd-t"><thead><tr><th>ID</th><th>KISA</th><th>항목</th><th>대상</th><th>결과</th><th>현재</th><th>기대값</th></tr></thead><tbody>${K.slice(0, 800).map(r => `<tr><td class="small">${esc(r.id)}</td><td class="small">${esc(r.kisa || "")}</td>
          <td>${esc(r.title)}</td><td class="small">${esc(r.target || "")}</td><td>${b(KST, r.status)}</td><td class="small">${esc(String(r.current ?? "")).slice(0, 120)}</td><td class="small">${esc(String(r.expected ?? "")).slice(0, 120)}</td></tr>`).join("")}</tbody></table></div></div>
      <div class="rd-card"><h4>VMSA(보안 권고) 빌드 판정 <small>${vm.db ? `권고 DB ${vm.db}건 · 취약 ${vm.vulnerable} · 가능 ${vm.possible}` : "보안 판독의 VMSA 권고 DB 가 없습니다 — '보안 판독' 화면에서 권고를 받은 뒤 '다시 분석'"}</small></h4>
        ${vm.rows.length ? `<div class="rd-scroll" style="max-height:40vh"><table class="rd-t"><thead><tr><th>대상</th><th>제품·빌드</th><th>권고</th><th>심각도</th><th>판정</th><th>근거</th></tr></thead><tbody>${vm.rows.slice(0, 600).map(r => `<tr><td>${esc(r.target)}</td>
          <td class="small">${esc(r.product)} ${esc(r.version)} (${esc(r.build)})</td><td class="small">${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.vmsa || r.id)}</a>` : esc(r.vmsa || r.id)}<div class="muted">${esc((r.cves || []).slice(0, 4).join(", "))}</div></td>
          <td>${esc(r.severity || "")} ${r.cvss ? n(r.cvss, 1) : ""}</td><td>${r.verdict === "취약" ? b(CST, "fail", "취약") : b(CST, "warn", r.verdict)}</td><td class="small">${esc(r.why || "")}</td></tr>`).join("")}</tbody></table></div>` : ""}</div>`;
  }
  function vcf9Tab() {
    const v = st.d.vcf9;
    return `<div class="rd-tiles">${Object.entries(v.verdicts).map(([k, c]) => `<div class="rd-tile ${(VD[k] || [0, ""])[1]}"><small>${(VD[k] || [k])[0]}</small><b>${c}</b></div>`).join("")}
        <div class="rd-tile"><small>VCF 라이선스 코어(CPU당 최소 16)</small><b>${n(v.licensed_cores)}</b></div>${Object.entries(v.cpu_tiers).map(([k, c]) => `<div class="rd-tile"><small>${esc(k)}</small><b>${c}</b></div>`).join("")}</div>
      <div class="rd-card"><h4>호스트별 VCF 9 준비도 <small>CPU — Broadcom KB 428874·BCG CPU Series(하드웨어 준비도와 같은 규칙) · 업그레이드 경로 — KB 418259·KB 457561</small></h4>
        <table class="rd-t"><thead><tr><th>호스트</th><th>클러스터</th><th>서버</th><th>CPU</th><th>VCF 9 CPU 등급</th><th>ESXi</th><th>최대 NIC</th><th>코어(소켓)</th><th>라이선스 코어</th><th>판정</th></tr></thead><tbody>${v.hosts.map(h => `<tr>
          <td><b>${esc(h.host)}</b></td><td>${esc(h.cluster)}</td><td class="small">${esc(h.vendor)} ${esc(h.model)}</td><td class="small">${esc(h.cpu)}<div class="muted">${esc(h.cpu_family)}</div></td><td>${b(CST, h.cpu_status, h.cpu_tier)}</td>
          <td class="small">${b(CST, h.esx_status, h.esx)}</td><td>${b(CST, h.nic_status, h.nic_gbps ? h.nic_gbps + "Gb" : "?")}</td><td>${h.cores} (${h.sockets})</td><td>${h.licensed_cores}</td><td>${b(VD, h.verdict)}</td></tr>`).join("")}</tbody></table>
        <p class="small muted">RVTools 에는 BMC·펌웨어·메모리 채널·TPM 정보가 없습니다 — 서버 단위 상세(메모리 채널·vSAN ESA·TPM·BIOS 기준선)는 '하드웨어 준비도'에서 BMC 스캔으로 확인하세요.</p></div>
      <div class="rd-card"><h4>VCF 9 점검</h4><table class="rd-t"><tbody>${v.findings.map(x => `<tr><td>${b(SEV, x.severity)}</td><td>${esc(x.id)}</td><td><b>${esc(x.entity)}</b></td><td>${esc(x.title)}</td><td class="small rd-fix">${esc(x.fix || "")}${x.ref ? ` <a href="${esc(x.ref)}" target="_blank" rel="noopener">근거</a>` : ""}</td></tr>`).join("") || `<tr><td class="muted">없음</td></tr>`}</tbody></table></div>`;
  }

  // ------------------------------------------------------------------ 표(VM·호스트·스토리지·네트워크)
  function grid(key, rows, cols, opt = {}) {
    const f = (st.tf || "").toLowerCase(), so = st.sort[key] || {};
    let R = rows.filter(r => !f || cols.some(c => String(c.v(r) ?? "").toLowerCase().includes(f)));
    if (so.i != null) { const c = cols[so.i]; R = [...R].sort((a, b2) => { const x = c.s ? c.s(a) : c.v(a), y = c.s ? c.s(b2) : c.v(b2); return (typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? ""))) * (so.d ? -1 : 1); }); }
    return `<div class="rd-card"><h4>${opt.title} <small>${R.length}/${rows.length}</small></h4>${opt.note ? `<p class="small muted">${opt.note}</p>` : ""}<div class="rd-scroll"><table class="rd-t"><thead><tr>${cols.map((c, i) => `<th class="rd-click" data-rvsort="${key}:${i}">${esc(c.h)}${so.i === i ? (so.d ? " ▼" : " ▲") : ""}</th>`).join("")}</tr></thead>
      <tbody>${R.slice(0, 3000).map(r => `<tr>${cols.map(c => `<td class="${c.c || ""}">${c.f ? c.f(r) : esc(String(c.v(r) ?? ""))}</td>`).join("")}</tr>`).join("")}</tbody></table></div></div>`;
  }
  const filt = () => `<div class="rd-tools"><input id="rv-tf" placeholder="필터 — 모든 열에서 찾기" value="${esc(st.tf)}" style="min-width:320px"><span class="small muted">열 제목을 누르면 정렬</span></div>`;
  async function vmsTab() {
    const vms = await table("vms");
    return filt() + grid("vms", vms, [
      {h: "VM", v: r => r.name, f: r => `<b>${esc(r.name)}</b>${r.template ? ' <span class="rd-b unk">템플릿</span>' : ""}`}, {h: "전원", v: r => r.power, f: r => r.power === "poweredOn" ? b(CST, "pass", "켜짐") : b(CST, "unknown", "꺼짐")},
      {h: "vCPU", v: r => r.vcpu}, {h: "메모리 GB", v: r => r.mem_mb, f: r => n((r.mem_mb || 0) / 1024, 1)}, {h: "프로비전 GB", v: r => r.prov_mib, f: r => gb(r.prov_mib)}, {h: "사용 GB", v: r => r.used_mib, f: r => gb(r.used_mib)},
      {h: "게스트 OS", v: r => r.os_tools || r.os_cfg, c: "small"}, {h: "HW", v: r => r.hw}, {h: "Tools", v: r => r.tools, c: "small"}, {h: "CPU 준비 %", v: r => r.cpu_ready},
      {h: "호스트", v: r => r.host, c: "small"}, {h: "클러스터", v: r => r.cluster, c: "small"}, {h: "IP", v: r => r.ip, c: "small"}, {h: "네트워크", v: r => (r.networks || []).join(", "), c: "small"},
      {h: "", v: () => "", f: r => `<a href="#" data-rvq="${esc(r.name)}" title="AI 에게 묻기">AI</a>`}], {title: "가상 머신"});
  }
  async function hostsTab() {
    const hs = await table("hosts");
    const cl = st.d.summary.clusters;
    return filt() + grid("hosts", hs, [
      {h: "호스트", v: r => r.name, f: r => `<b>${esc(r.name)}</b>${r.maintenance ? ' <span class="rd-b warn">유지보수</span>' : ""}`}, {h: "클러스터", v: r => r.cluster}, {h: "서버", v: r => `${r.vendor} ${r.model}`, c: "small"},
      {h: "CPU", v: r => r.cpu_model, c: "small"}, {h: "소켓×코어", v: r => `${r.sockets}×${r.cores_per_cpu}`}, {h: "메모리 GB", v: r => r.mem_mb, f: r => n((r.mem_mb || 0) / 1024)},
      {h: "CPU %", v: r => r.cpu_pct}, {h: "메모리 %", v: r => r.mem_pct}, {h: "VM", v: r => r.vms}, {h: "vCPU/코어", v: r => r.vcpu_per_core}, {h: "ESXi", v: r => r.esx, c: "small"},
      {h: "BIOS", v: r => `${r.bios || ""} ${r.bios_date || ""}`, c: "small"}, {h: "시리얼", v: r => r.serial, c: "small"},
      {h: "NTP", v: r => (r.ntp || []).join(", "), c: "small"}, {h: "EVC", v: r => r.evc, c: "small"}, {h: "전원 정책", v: r => r.power_policy, c: "small"},
      {h: "인증서 만료", v: r => r.cert_expiry, f: r => r.cert_expiry ? new Date(r.cert_expiry * 1000).toISOString().slice(0, 10) : "—"}], {title: "ESXi 호스트"})
      + `<div class="rd-card"><h4>클러스터</h4><table class="rd-t"><thead><tr><th>클러스터</th><th>호스트</th><th>vCPU:코어</th><th>메모리 사용</th><th>N+1</th><th>HA</th><th>DRS</th></tr></thead><tbody>${cl.map(x => `<tr><td>${esc(x.name)}</td><td>${x.hosts}</td><td>${x.ratio}:1</td><td>${x.mem_used_pct}%</td><td>${x.n1_mem_pct ?? "—"}%</td><td>${x.ha ? "켬" : "끔"}</td><td>${x.drs ? "켬 " + esc(x.drs_behavior || "") : "끔"}</td></tr>`).join("")}</tbody></table></div>`;
  }
  async function dsTab() {
    const [ds, paths, snaps, parts] = await Promise.all([table("datastores"), table("paths"), table("snapshots"), table("partitions")]);
    const low = parts.filter(p => p.free_pct != null && p.free_pct < 15 && p.cap_mib > 1024).sort((a, c) => a.free_pct - c.free_pct);
    return filt() + grid("ds", ds, [
      {h: "데이터스토어", v: r => r.name, f: r => `<b>${esc(r.name)}</b>`}, {h: "유형", v: r => r.type}, {h: "용량 GB", v: r => r.cap_mib, f: r => n(r.cap_mib / 1024)}, {h: "여유 GB", v: r => r.free_mib, f: r => n(r.free_mib / 1024)},
      {h: "사용 %", v: r => r.free_pct == null ? null : 100 - r.free_pct, f: r => r.free_pct == null ? "—" : `<div class="rv-use"><i class="${r.free_pct < 5 ? "bad" : r.free_pct < 15 ? "warn" : ""}" style="width:${100 - r.free_pct}%"></i><b>${n(100 - r.free_pct, 1)}%</b></div>`},
      {h: "프로비전 GB", v: r => r.prov_mib, f: r => n(r.prov_mib / 1024)}, {h: "과할당", v: r => r.cap_mib ? r.prov_mib / r.cap_mib : null, f: r => r.cap_mib ? n(r.prov_mib / r.cap_mib * 100) + "%" : "—"},
      {h: "VM", v: r => r.vms}, {h: "호스트", v: r => (r.hosts || []).length}], {title: "데이터스토어"})
      + grid("paths", paths, [{h: "호스트", v: r => r.host, c: "small"}, {h: "데이터스토어·LUN", v: r => r.datastore || r.disk}, {h: "정책", v: r => r.policy}, {h: "경로", v: r => r.paths, f: r => `${r.active}/${r.paths}${r.dead ? ` <b class="cc-na">dead ${r.dead}</b>` : ""}`},
        {h: "HBA", v: r => (r.hbas || []).join(", ")}, {h: "어레이", v: r => `${r.vendor} ${r.model}`, c: "small"}], {title: "멀티패스"})
      + `<div class="rd-two"><div class="rd-card"><h4>스냅숏 <small>${snaps.length}</small></h4>${snaps.length ? `<table class="rd-t">${snaps.map(x => `<tr><td>${esc(x.vm)}</td><td>${esc(x.name)}</td><td>${fmt(x.created)}</td><td>${gb(x.size_mib)} GB</td></tr>`).join("")}</table>` : `<p class="muted">없음</p>`}</div>
        <div class="rd-card"><h4>게스트 디스크 여유 15% 미만 <small>${low.length}</small></h4>${low.length ? `<table class="rd-t">${low.slice(0, 100).map(x => `<tr><td>${esc(x.vm)}</td><td>${esc(x.disk)}</td><td>${gb(x.free_mib)} / ${gb(x.cap_mib)} GB</td><td><b class="${x.free_pct < 5 ? "cc-na" : ""}">${x.free_pct}%</b></td></tr>`).join("")}</table>` : `<p class="muted">없음</p>`}</div></div>`;
  }
  async function netTab() {
    const [dvs, nets, vmks, pnics] = await Promise.all([table("dvswitches"), table("networks"), table("vmks"), table("pnics")]);
    return filt() + grid("dvs", dvs, [{h: "VDS", v: r => r.name, f: r => `<b>${esc(r.name)}</b>`}, {h: "버전", v: r => r.version}, {h: "MTU", v: r => r.mtu}, {h: "호스트", v: r => (r.hosts || []).length},
        {h: "LACP", v: r => r.lacp}, {h: "VM", v: r => r.vms}, {h: "이웃 탐색", v: r => `${r.discovery || "-"} ${r.discovery_op || ""}`}, {h: "포트", v: r => r.ports}], {title: "Distributed Switch"})
      + grid("nets", nets.filter(x => !x.uplink_pg), [{h: "포트그룹", v: r => r.name}, {h: "유형", v: r => r.kind}, {h: "VDS·vSwitch", v: r => r.dvs || r.vswitch}, {h: "VLAN", v: r => r.vlan},
        {h: "VM", v: r => r.vm_count}, {h: "보안(무차별·MAC·위조)", v: r => [r.promiscuous, r.mac_changes, r.forged].map(x => x == null ? "-" : x ? "허용" : "거부").join(" · "), c: "small"},
        {h: "팀 정책", v: r => r.policy, c: "small"}, {h: "활성 업링크", v: r => r.active, c: "small"}], {title: "포트그룹"})
      + grid("vmks", vmks, [{h: "호스트", v: r => r.host, c: "small"}, {h: "장치", v: r => r.device}, {h: "포트그룹", v: r => r.portgroup}, {h: "IP", v: r => r.ip}, {h: "MTU", v: r => r.mtu},
        {h: "서비스(포트그룹 이름으로 추정)", v: r => (r.services || []).join(", ")}], {title: "VMkernel", note: "RVTools 는 VMkernel 서비스(vMotion·vSAN 등) 태그를 내보내지 않아 포트그룹 이름으로 추정합니다."})
      + grid("pnics", pnics, [{h: "호스트", v: r => r.host, c: "small"}, {h: "NIC", v: r => r.device}, {h: "속도", v: r => r.speed, f: r => r.speed ? r.speed / 1000 + " Gb" : "<b class='cc-na'>미연결</b>"},
        {h: "드라이버", v: r => r.driver}, {h: "스위치", v: r => r.switch}, {h: "MAC", v: r => r.mac, c: "small mono"}], {title: "물리 NIC"});
  }

  // ------------------------------------------------------------------ AI(PAIS 등 설정된 LLM)
  function md(t) {                                        // 제목·표·목록·굵게·코드 — 출력은 모두 이스케이프
    const out = [], tbl = []; const inl = s => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`\n]+)`/g, "<code>$1</code>");
    const flush = () => { if (!tbl.length) return; const rows = tbl.filter(r => !/^\s*\|?[\s:\-|]+\|?\s*$/.test(r)).map(r => r.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim()));
      out.push(`<table class="rd-t"><thead><tr>${rows[0].map(c => `<th>${inl(c)}</th>`).join("")}</tr></thead><tbody>${rows.slice(1).map(r => `<tr>${r.map(c => `<td>${inl(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`); tbl.length = 0; };
    for (const ln of String(t || "").replace(/<think>[\s\S]*?<\/think>/g, "").split("\n")) {
      if (ln.trim().startsWith("|")) { tbl.push(ln); continue; } flush();
      const m = ln.match(/^(#{1,4})\s+(.+)$/);
      if (m) out.push(`<h${Math.min(6, m[1].length + 3)} class="rv-mh">${inl(m[2])}</h${Math.min(6, m[1].length + 3)}>`);
      else if (/^\s*([-*]|\d+\.)\s+/.test(ln)) out.push(`<div class="rv-li">${inl(ln.replace(/^\s*([-*])\s+/, "• "))}</div>`);
      else if (ln.trim()) out.push(`<p>${inl(ln)}</p>`);
    }
    flush(); return out.join("");
  }
  const citedRefs = x => { const c = new Set((String(x.a || "").match(/\[R\d+\]/g) || []).map(y => y.slice(1, -1))); return (x.refs || []).filter(r => c.has(r.ref)); };
  function aiTab() {
    const ai = st.d.meta.ai || {};
    const ex = ["가장 먼저 조치해야 할 3가지는?", "VCF 9 로 업그레이드하려면 어떤 순서로 해야 해?", "회수 가능한 자원(꺼진 VM·좀비 디스크)은 얼마나 돼?", "클러스터에 호스트 1대가 장애 나면 버틸 수 있어?", "지원 종료된 게스트 OS 목록과 대응 방안"];
    return `${st.llm ? "" : `<div class="rd-alert bad">LLM 이 꺼져 있습니다 — 운영 설정 › AI 에서 PAIS 등 공급자를 켜세요.</div>`}
      <div class="rd-card"><h4>AI 진단 보고서 <small>${ai.report ? `${esc(ai.provider || "")} · ${fmt(ai.at)} · ${ai.secs ?? "?"}초 · ${esc(ai.by || "")}` : "분석 집계(환경·용량·점검·KISA·VMSA·VCF 9)를 LLM 에 보내 보고서 작성"}</small></h4>
        <div class="rd-tools"><button class="btn-sm solid" id="rv-air" data-perm="operate" ${st.llm ? "" : "disabled"}>${ai.report ? "다시 작성" : "AI 진단 보고서 작성"}</button><span class="small muted">외부 공급자면 호스트·VM·클러스터·IP 이름을 가명화해 보내고 답을 원래 이름으로 복원합니다.</span></div>
        <div id="rv-aib" class="rv-md">${ai.report ? md(ai.report) : ""}</div></div>
      <div class="rd-card"><h4>질문하기 <small>이 RVTools 분석 전체 + 질문에 나온 VM·호스트·데이터스토어 원본 행 + 사내 KB(있으면)를 근거로 답변</small></h4>
        <div class="rv-qa" id="rv-qa">${st.qa.map(x => `<div class="msg q">${esc(x.q)}</div><div class="msg a rv-md">${md(x.a)}${citedRefs(x).length ? `<div class="chat-refs">인용한 근거: ${citedRefs(x).map(r => r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">[${r.ref}] ${esc(r.title)}</a>` : `[${r.ref}] ${esc(r.title)}`).join(" · ")}</div>` : ""}</div>`).join("")}</div>
        <div class="rv-ex">${ex.map(q => `<button class="btn-sm" data-rvask="${esc(q)}">${esc(q)}</button>`).join("")}</div>
        <form id="rv-askf" class="rv-askf"><input id="rv-ask" placeholder="예: db01 VM 의 성능 문제 가능성은?" autocomplete="off" ${st.llm ? "" : "disabled"}><button class="btn-sm solid" data-perm="operate" ${st.llm ? "" : "disabled"}>보내기</button></form></div>`;
  }
  async function aiReport() {
    const bt = $("#rv-air"), box = $("#rv-aib"); bt.disabled = true; box.innerHTML = `<p class="muted">AI 가 보고서를 쓰는 중… (환경 크기와 모델에 따라 30초~수 분)</p>`;
    try { const ai = await A.api("POST", `/api/rvtools/${enc(st.id)}/ai/report`); st.d.meta.ai = ai; await loadList(); render(); A.ok("AI 보고서 완료", ai.provider || ""); }
    catch (e) { box.innerHTML = ""; A.fail("AI 보고서 실패", e); bt.disabled = false; }
  }
  async function ask(q) {
    if (!q || st.asking) return; st.asking = true;
    if (st.tab !== "ai") { st.tab = "ai"; await render(); }
    const item = {q, a: "…", refs: []}; st.qa.push(item);
    const log = $("#rv-qa"); log.insertAdjacentHTML("beforeend", `<div class="msg q">${esc(q)}</div><div class="msg a rv-md">…</div>`); const out = log.lastElementChild; out.scrollIntoView({block: "nearest"});
    try {
      const r = await fetch(`/api/rvtools/${enc(st.id)}/ask`, {method: "POST", headers: {"Content-Type": "application/json", "X-Requested-With": "aiops"}, body: JSON.stringify({question: q, lang: (window.AIOPS_I18N || {}).lang || "ko"})});
      if (!r.ok) throw new Error(`${r.status} ${(await r.text()).slice(0, 200)}`);
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = "", txt = "";
      for (;;) { const {done, value} = await rd.read(); if (done) break; buf += dec.decode(value, {stream: true}); const ps = buf.split("\n\n"); buf = ps.pop();
        for (const p of ps) { const dd = p.replace(/^data:\s*/, ""); if (dd === "[DONE]") continue;
          try { const j = JSON.parse(dd); if (j.refs) { item.refs = j.refs; continue; } if (j.t) txt += j.t; if (j.error) txt += `\n[오류] ${j.error}`; } catch { /* 조각 */ }
          out.textContent = txt.replace(/<think>[\s\S]*?<\/think>/g, ""); } }
      item.a = txt;
    } catch (e) { item.a = `[오류] ${e.message}`; }
    st.asking = false; if (st.tab === "ai") render();
  }

  // ------------------------------------------------------------------ 화면
  async function render() {
    const box = $("#rv-body"); if (!box) return;
    if (!st.id) { box.innerHTML = home(); perms(box); return; }
    if (!st.d) { box.innerHTML = `<p class="muted">불러오는 중…</p>`; return; }
    const m = st.d.meta;
    const head = `<div class="rv-top"><button class="btn-sm" id="rv-back">← 목록</button><b>${esc(m.name)}</b><span class="small muted">${fmt(m.uploaded)} · ${esc(m.by || "")}</span><span class="rd-sp"></span>
      <a class="btn-sm" href="/api/rvtools/${enc(st.id)}/report.html" target="_blank" rel="noopener">HTML 보고서</a><a class="btn-sm" href="/api/rvtools/${enc(st.id)}/report.html?download=1">HTML 받기</a>
      <a class="btn-sm" href="/api/rvtools/${enc(st.id)}/report.xlsx">Excel</a><button class="btn-sm" id="rv-re" data-perm="operate" title="저장된 정규화 데이터로 최신 규칙·VMSA 권고 DB 로 다시 평가">다시 분석</button></div>
      <div class="rv-tabs">${TABS.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-rvt="${k}">${l}${k === "comp" ? ` <small>${(st.d.counts.critical || 0) + (st.d.counts.error || 0)}·${st.d.counts.warning || 0}</small>` : ""}</button>`).join("")}</div>`;
    let body = "";
    try {
      body = st.tab === "sum" ? sumTab() : GK[st.tab] ? await graphTab() : st.tab === "comp" ? compTab() : st.tab === "vcf9" ? vcf9Tab() : st.tab === "vms" ? await vmsTab()
        : st.tab === "hosts" ? await hostsTab() : st.tab === "ds" ? await dsTab() : st.tab === "net" ? await netTab() : aiTab();
    } catch (e) { body = `<div class="rd-alert bad">${esc(e.message)}</div>`; }
    const keep = document.activeElement && document.activeElement.id === "rv-tf" ? document.activeElement.selectionStart : null;
    box.innerHTML = head + `<div class="rv-pane">${body}</div>`;
    if (keep != null) { const t = $("#rv-tf"); if (t) { t.focus(); t.setSelectionRange(keep, keep); } }
    if (GK[st.tab]) { wireGraph(); drawGraph(); }
    perms(box);
  }
  function wire() {
    const box = $("#rv-body"); if (box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target.closest("[data-rvt],[data-rvo],[data-rvdel],[data-rvq],[data-rvask],[data-rvsort],[data-rvsev],[data-rvkst],[data-go],#rv-back,#rv-re,#rv-air,#rv-gclr,#rv-gfit,#rv-sx"); if (!t) return;
      if (t.tagName === "A" && t.getAttribute("href") === "#") e.preventDefault();
      if (t.dataset.rvt) { st.tab = t.dataset.rvt; st.tf = ""; st.q = ""; render(); return; }
      if (t.dataset.rvdel) { e.stopPropagation(); if (!confirm("이 분석을 삭제할까요?")) return; try { await A.api("DELETE", `/api/rvtools/${enc(t.dataset.rvdel)}`); await loadList(); render(); } catch (x) { A.fail("삭제 실패", x); } return; }
      if (t.dataset.rvo) { open(t.dataset.rvo); return; }
      if (t.dataset.rvq) { ask(`${t.dataset.rvq} 의 상태·문제·권장 조치를 알려줘`); return; }
      if (t.dataset.rvask) { ask(t.dataset.rvask); return; }
      if (t.dataset.rvsort) { const [k, i] = t.dataset.rvsort.split(":"); const so = st.sort[k] || {}; st.sort[k] = {i: +i, d: so.i === +i ? !so.d : false}; render(); return; }
      if (t.dataset.rvsev) { st.sev = st.sev === t.dataset.rvsev ? "" : t.dataset.rvsev; render(); return; }
      if (t.dataset.rvkst) { st.kst = st.kst === t.dataset.rvkst ? "" : t.dataset.rvkst; render(); return; }
      if (t.dataset.go) { st.sel = t.dataset.go; drawGraph(); return; }
      if (t.id === "rv-back") { st.id = ""; st.d = null; await loadList(); render(); return; }
      if (t.id === "rv-re") { try { await A.api("POST", `/api/rvtools/${enc(st.id)}/reanalyze`); await open(st.id); A.ok("다시 분석 완료", ""); } catch (x) { A.fail("다시 분석 실패", x); } return; }
      if (t.id === "rv-air") { aiReport(); return; }
      if (t.id === "rv-gclr" || t.id === "rv-sx") { st.sel = null; drawGraph(); return; }
      if (t.id === "rv-gfit") fit();
    });
    box.addEventListener("change", e => {
      const t = e.target;
      if (t.id === "rv-file") upload(t.files[0]);
      if (t.id === "rv-sev") { st.sev = t.value; render(); } if (t.id === "rv-src") { st.src = t.value; render(); } if (t.id === "rv-area") { st.area = t.value; render(); }
      if (t.id === "rv-kst") { st.kst = t.value; render(); }
      if (t.id === "rv-vml") { st.vmLimit = +t.value; delete st.g[GK[st.tab]]; render(); }
    });
    box.addEventListener("input", e => { if (e.target.id === "rv-tf") { st.tf = e.target.value; clearTimeout(st._t); st._t = setTimeout(render, 250); } });
    box.addEventListener("keydown", e => { if (e.target.id === "rv-gq" && e.key === "Enter") { st.q = e.target.value; gpick(st.q); } });
    box.addEventListener("submit", e => { if (e.target.id === "rv-askf") { e.preventDefault(); const i = $("#rv-ask"); const q = i.value.trim(); i.value = ""; ask(q); } });
    box.addEventListener("dragover", e => { const d = e.target.closest("#rv-drop"); if (d) { e.preventDefault(); d.classList.add("on"); } });
    box.addEventListener("dragleave", e => { const d = e.target.closest("#rv-drop"); if (d) d.classList.remove("on"); });
    box.addEventListener("drop", e => { const d = e.target.closest("#rv-drop"); if (!d) return; e.preventDefault(); d.classList.remove("on"); upload(e.dataTransfer.files[0]); });
    addEventListener("resize", () => { if (GK[st.tab] && !$("#drawer-rv").hidden) drawGraph(); });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-rv") d.hidden = true; });
    $("#drawer-rv").hidden = false; wire(); await loadList(); render();
  }
  const nav = document.getElementById("nav-rv"); if (nav) nav.onclick = show;
  const rl = document.getElementById("rv-reload"); if (rl) rl.onclick = async () => { await loadList(); if (st.id) await open(st.id); else render(); };
  window.AIOPS_RVTOOLS = show;
})();
