/* vSAN ESA 전환 산정(2.43.0) — 성능·용량 › 용량·적정화 › vSAN ESA 전환
   지금 외장 스토리지(VMFS·NFS·vVol) 데이터를 vSAN ESA 로 옮기면: 방법 A 기존 클러스터에 NVMe 추가 / 방법 B 새 ESA 클러스터 — 원시 용량·드라이브·호스트·ReadyNode·vSAN TiB 라이선스 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const st = {src: null, res: null, sel: null, f: {basis: "used", years: 3, growth_pct_year: "", policy: "auto", dr: 1, reserve_pct: 10, host_reserve: true, drive_tb: 7.68,
              drives_per_host: 8, cores_per_host: 64, sockets_per_host: 2}, err: "", root: null};
  try { Object.assign(st.f, JSON.parse(localStorage.getItem("aiops.esa") || "{}")); } catch (e) { /* 기본값 */ }
  const N = (v, d = 1) => v == null ? "—" : Number(v).toLocaleString(undefined, {maximumFractionDigits: d});
  const key = d => `${d.vcenter}/${d.name}`;

  async function load() {
    try { st.src = await A.api("GET", "/api/capacity/esa/sources", undefined, {background: true}); st.err = ""; }
    catch (e) { st.err = String(e.message || e); }
    if (st.src && !st.sel) { const w = st.src.datastores.filter(d => d.vms); st.sel = new Set((w.length ? w : st.src.datastores).map(key)); }
    await calc();
  }
  let t = 0;
  function calc() {
    clearTimeout(t);
    return new Promise(res => { t = setTimeout(async () => {
      try { localStorage.setItem("aiops.esa", JSON.stringify(st.f)); } catch (e) { /* 무시 */ }
      try { st.res = await A.api("POST", "/api/capacity/esa", {...st.f, datastores: [...(st.sel || [])]}, {background: true}); st.err = ""; }
      catch (e) { st.err = String(e.message || e); }
      draw(); res();
    }, 150); });
  }
  const sel = (k, opts) => `<select data-k="${k}">${opts.map(([v, l]) => `<option value="${v}" ${String(st.f[k]) === String(v) ? "selected" : ""}>${l}</option>`).join("")}</select>`;
  const num = (k, step, min, max, w = 70) => `<input type="number" data-k="${k}" value="${esc(st.f[k])}" step="${step}" min="${min}" max="${max}" style="width:${w}px">`;

  function form() {
    const S = st.src;
    return `<div class="es-form">
      <div class="es-ds"><h5>옮길 외장 데이터스토어 <small>${S.datastores.length}개 — VM 이 있는 것만 기본 선택</small></h5>
        ${S.datastores.length ? `<table class="dr-t"><thead><tr><th></th><th>데이터스토어</th><th>장비</th><th class="r">사용</th><th class="r">할당</th><th class="r">VM</th><th>클러스터</th></tr></thead><tbody>
        ${S.datastores.map(d => `<tr><td><input type="checkbox" data-ds="${esc(key(d))}" ${st.sel.has(key(d)) ? "checked" : ""} aria-label="${esc(d.name)} 선택"></td><td class="mono small">${esc(d.name)} <small class="muted">${esc(d.type)}</small></td>
          <td class="small">${esc(d.array || "—")}</td><td class="r nw">${N(d.used_gb / 1000)} TB</td><td class="r nw">${N(d.prov_gb / 1000)} TB</td><td class="r">${d.vms_on}/${d.vms}</td><td class="small">${esc(d.clusters.join(", ") || "—")}</td></tr>`).join("")}
        </tbody></table>` : `<p class="small muted">외장 데이터스토어(VMFS·NFS·vVol)가 없습니다 — 이미 vSAN·로컬만 쓰는 환경입니다.</p>`}</div>
      <div class="es-opts">
        <label>기준 ${sel("basis", [["used", "사용량"], ["prov", "할당량(씬 디스크가 다 찰 때)"]])}</label>
        <label>기간 ${num("years", 1, 0, 10, 56)} 년</label>
        <label>연 증가율 <input type="number" data-k="growth_pct_year" value="${esc(st.f.growth_pct_year)}" placeholder="추세" step="1" min="0" max="200" style="width:70px"> %</label>
        <label>정책 ${sel("policy", [["auto", "RAID-5 적응형(ESA 기본)"], ["r6", "RAID-6 4+2 (FTT=2)"], ["r1", "RAID-1 (FTT=1)"], ["r1f2", "RAID-1 (FTT=2)"]])}</label>
        <label>압축 절감 ${num("dr", 0.1, 1, 4, 60)} 배</label>
        <label>운영 예비 ${num("reserve_pct", 1, 0, 30, 56)} %</label>
        <label><input type="checkbox" data-k="host_reserve" ${st.f.host_reserve ? "checked" : ""}> 호스트 재구축 예비(1대)</label>
        <label>NVMe 1개 ${sel("drive_tb", [[1.92, "1.92 TB"], [3.84, "3.84 TB"], [7.68, "7.68 TB"], [15.36, "15.36 TB"], [30.72, "30.72 TB"]])}</label>
      </div></div>`;
  }
  function result() {
    const r = st.res; if (!r) return "";
    if (r.error) return `<p class="sm-hint">${esc(r.error)}</p>`;
    const I = r.inputs, B = r.new_cluster;
    const lic = x => `<span class="${x.addon_tib ? "es-bad" : "es-ok"}">${N(x.raw_tib)} TiB 필요 / VCF 포함 ${N(x.entitled_tib, 0)} TiB${x.addon_tib ? ` → <b>추가 ${N(x.addon_tib, 0)} TiB</b>` : " → 추가 없음"}</span>`;
    const prof = p => `<span class="es-prof" title="ReadyNode 최소: 코어 ${p.min_cores} · 메모리 ${p.min_mem_gb} GB · 네트워크 ${p.min_gbe} GbE">${esc(p.profile)}</span>${p.gaps.length ? ` <small class="es-bad">지금 호스트 미달: ${esc(p.gaps.join(", "))}</small>` : ""}`;
    return `<div class="es-sum">
        <div><span>지금</span><b>${N(r.now_tb)} TB</b><small>${I.basis === "used" ? "사용량" : "할당량"} · 데이터스토어 ${r.datastores} · VM ${r.vms}</small></div><i>→</i>
        <div><span>${N(I.years, 0)}년 뒤</span><b>${N(r.need_tb)} TB</b><small>연 ${N(I.growth_pct_year)}% (${esc(I.growth_source)})</small></div><i>→</i>
        <div class="hl"><span>vSAN ESA 에 담을 논리 용량</span><b>${N(r.need_tb)} TB</b><small>압축 ${N(I.dr)}배 · 예비 ${N(I.reserve_pct, 0)}%${I.host_reserve ? " + 1대" : ""}</small></div></div>
      <div class="es-ways">
        <section><h5>방법 A — 지금 클러스터 호스트에 NVMe 를 넣어 ESA 로</h5>
          <table class="dr-t"><thead><tr><th>클러스터</th><th>정책</th><th class="r">원시(필요/설치)</th><th class="r">호스트당</th><th>ReadyNode 프로필</th><th>vSAN 라이선스</th></tr></thead><tbody>
          ${r.existing.map(x => x.possible === false && !x.drives_per_host ? `<tr><td>${esc(x.name)} <small class="muted">${x.hosts}대</small></td><td colspan="5" class="small muted">${esc(x.why)}</td></tr>` :
            `<tr class="${x.possible ? "" : "es-no"}"><td><b>${esc(x.name)}</b> <small class="muted">${x.hosts}대${x.osa ? " · 지금 vSAN OSA" : x.already_vsan ? " · 지금 vSAN ESA" : ""}</small></td><td class="small">${esc(x.scheme)}</td>
            <td class="r nw">${N(x.raw_tb)} / ${N(x.installed_tb)} TB</td><td class="r nw"><b>${N(x.per_host_tb)} TB</b><br><small>NVMe ${N(I.drive_tb, 2)} TB × ${x.drives_per_host}</small></td>
            <td>${prof(x.profile)}${x.why ? `<br><small class="${x.possible ? "muted" : "es-bad"}">${esc(x.why)}</small>` : ""}</td><td class="small">${lic(x)}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">클러스터 정보가 없습니다</td></tr>`}
          </tbody></table></section>
        <section><h5>방법 B — 새 vSAN ESA 클러스터</h5>
          <div class="es-opts">
            <label>호스트당 NVMe ${num("drives_per_host", 1, 1, 24, 56)} 개 <small class="muted">= ${N(B.per_host_tb, 2)} TB</small></label>
            <label>CPU ${num("sockets_per_host", 1, 1, 8, 50)} 소켓 × 코어 합계 ${num("cores_per_host", 1, 8, 512, 64)}</label></div>
          ${B.hosts ? `<p class="es-big">호스트 <b>${B.hosts}대</b> <small>(원시 ${N(B.raw_tb)} TB · ${esc((B.table.find(x => x.hosts === B.hosts) || {}).scheme || "")})</small></p>` : `<p class="es-bad">64대 안에서 담지 못합니다 — 호스트당 용량을 늘리세요</p>`}
          <table class="dr-t es-tb"><thead><tr><th>호스트</th><th>정책</th><th class="r">원시</th><th class="r">쓸 수 있는 용량</th><th></th></tr></thead><tbody>
            ${B.table.map(x => `<tr class="${x.hosts === B.hosts ? "on" : ""}"><td>${x.hosts}대</td><td class="small">${esc(x.scheme)}</td><td class="r">${N(x.raw_tb)} TB</td><td class="r">${N(x.usable_tb)} TB</td>
              <td class="small">${x.hosts < x.min_hosts ? `최소 ${x.min_hosts}대` : x.ok ? "충분" : "부족"}</td></tr>`).join("")}</tbody></table>
          <p class="small">ReadyNode: ${prof(B.profile)} · 라이선스: ${lic(B)}${B.too_many_drives ? ` · <span class="es-bad">호스트당 드라이브가 ESA 최대 24개를 넘음</span>` : ""}</p></section></div>
      <ul class="es-notes">${(r.notes || []).map(n => `<li>${esc(n)}</li>`).join("")}
        <li>근거: VCF Specific Program Documentation(라이선스 코어당 vSAN 1 TiB, CPU 당 최소 16코어) · Broadcom KB 313548(vSAN TiB 산정) · vSAN ESA ReadyNode Hardware Guidance(프로필 최소값) · KB 326717(호스트당 장치 수).</li></ul>`;
  }
  function draw() {
    const b = st.root; if (!b || !b.isConnected) return;
    if (!st.src) { b.innerHTML = `<p class="sm-hint">${st.err ? esc(st.err) : "불러오는 중…"}</p>`; return; }
    b.innerHTML = `<div class="es"><p class="small muted es-lead">지금 외장 스토리지(VMFS·NFS·vVol)에 있는 데이터를 vSAN ESA 로 옮기면 무엇이 얼마나 필요한지 — 수집된 데이터스토어 사용량·추세로 계산합니다(읽기 전용).</p>
      ${form()}${st.err ? `<p class="sm-hint">${esc(st.err)}</p>` : ""}<div class="es-res">${result()}</div></div>`;
  }
  function wire(b) {
    if (b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("change", e => {
      const x = e.target;
      if (x.dataset.ds) { x.checked ? st.sel.add(x.dataset.ds) : st.sel.delete(x.dataset.ds); calc(); return; }
      const k = x.dataset.k; if (!k) return;
      st.f[k] = x.type === "checkbox" ? x.checked : x.tagName === "SELECT" && k !== "basis" && k !== "policy" ? Number(x.value) : x.type === "number" ? (x.value === "" ? "" : Number(x.value)) : x.value;
      calc();
    });
  }
  window.AIOPS_ESA = {mount(el) { st.root = el; wire(el); draw(); load(); }};
})();
