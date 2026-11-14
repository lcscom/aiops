/* 가정 분석(What-If, 2.33.0 · 서버 사양 2.34.0 · 피크 기준·교체·장애·저장 비교 2.35.0
   · 2.36.0 vSAN 쓸 수 있는 용량·혼합 세대(EVC)·적정화 반영·분기별 계획·비용 연결 + 클러스터 간 이동·DR 사이트 수용·고객 제출용 보고서 묶음) — 성능·용량 › 용량·적정화 › 가정 분석 탭
   VM·호스트를 더하거나 뺐을 때 클러스터 CPU·메모리 여유, HA 여유를 뺀 수용 가능 여부, 90% 도달까지 남은 기간을 계산(읽기 전용) */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const KEY = "aiops.whatif";
  const st = {cl: null, r: null, err: "", busy: false, seq: 0, sp: null, mgr: false, sc: [], cmp: null, pick: new Set(), mode: "one",
              mv: {src: "", dst: "", vms: [], pick: new Set(), q: "", r: null, err: "", busy: false},
              dr: {groups: null, pick: new Set(), src: "", dst: "", include_off: false, r: null, err: "", busy: false},
              rb: {customer: "", busy: ""},
              f: {key: "", ha_failures: 1, add_vms: 0, remove_vms: 0, vm_vcpu: 4, vm_mem_gb: 16, vm_disk_gb: 100, vm_cpu_util_pct: 25, vm_mem_util_pct: 80, add_hosts: 1, remove_hosts: 0,
                  spec: "", host_cores: "", host_core_ghz: "", host_mem_gb: "", host_sockets: "", host_flash_tb: "", basis: "now", remove_names: [], consume_ha: false,
                  vsan_policy: "", vsan_reserve_pct: 10, vsan_host_reserve: "", vsan_dr: "", growth_pct_year: "", apply_rightsizing: false, perf_factor: 1, v: 37}};
  const CHK = ["consume_ha", "apply_rightsizing"];
  if (!Array.isArray(st.f.remove_names)) st.f.remove_names = [];
  const allSpecs = () => st.sp ? [...st.sp.uploaded, ...st.sp.bmc, ...st.sp.vcenter] : [];
  const specOf = id => allSpecs().find(x => x.id === id);
  const sl = s => `${s.sockets ? `${s.sockets}소켓 × ${Math.round(s.cores / s.sockets)}코어` : `${s.cores}코어`}${s.core_ghz ? ` ${s.core_ghz}GHz` : ""} · ${s.mem_gb}GB${s.flash_tb ? ` · 플래시 ${s.flash_tb}TB` : ""}`;
  try { Object.assign(st.f, JSON.parse(localStorage.getItem(KEY) || "{}")); } catch { /* 무시 */ }
  if ((st.f.v || 0) < 37) { Object.assign(st.f, {vsan_policy: "", vsan_dr: "", vsan_host_reserve: "", v: 37}); }   // 2.37.0 — 빈 값 = vSAN 실측값 사용
  const N = (v, d = 1) => v == null ? "—" : Number(v).toLocaleString(undefined, {maximumFractionDigits: d});
  const VD = {ok: ["수용 가능", "쓸 수 있는 용량의 80% 미만입니다."], warn: ["빠듯함", "쓸 수 있는 용량의 80%를 넘습니다 — 수용은 되지만 여유가 적습니다."], bad: ["수용 불가", "HA 여유를 남기면 용량이 모자랍니다."]};
  const days = d => d == null ? "증가 추세 없음" : d === 0 ? "이미 90% 이상" : d > 730 ? "2년 이상" : `${N(d, 0)}일`;
  const cls = p => p == null ? "bad" : p > 100 ? "bad" : p >= 80 ? "warn" : "";

  function form() {
    const f = st.f, L = st.cl || [];
    const cur = L.find(c => `${c.vcenter}|${c.cluster}` === f.key), ah = cur ? cur.avg_host : null;
    const sp = st.sp || {uploaded: [], bmc: [], vcenter: []}, cs = specOf(f.spec);
    const grp = (title, list) => list.length ? `<optgroup label="${esc(title)}">${list.map(x => `<option value="${esc(x.id)}" ${f.spec === x.id ? "selected" : ""}>${esc(x.name)} — ${esc(sl(x.spec))}</option>`).join("")}</optgroup>` : "";
    const num = (k, label, min, max, step = 1, ph = "") => `<label>${label}<input type="number" name="${k}" min="${min}" max="${max}" step="${step}" value="${esc(f[k])}" placeholder="${esc(ph)}"></label>`;
    return `<form class="wi-form" id="wi-form">
      <label>클러스터<select name="key">${L.map(c => `<option value="${esc(c.vcenter)}|${esc(c.cluster)}" ${`${c.vcenter}|${c.cluster}` === f.key ? "selected" : ""}>${esc(c.cluster)} — ${esc(c.vcenter)} (호스트 ${c.hosts} · VM ${c.vms_on})</option>`).join("")}</select></label>
      <fieldset><legend>VM 더하기·빼기</legend>${num("add_vms", "더할 VM 수", 0, 20000)}${num("remove_vms", "뺄 VM 수(평균 VM 기준)", 0, 20000)}
        ${num("vm_vcpu", "VM당 vCPU", 1, 512)}${num("vm_mem_gb", "VM당 메모리(GB)", 0.5, 4096, 0.5)}
        <label class="full">VM당 디스크(GB)<input type="number" name="vm_disk_gb" min="0" max="100000" value="${esc(f.vm_disk_gb)}"></label>
        ${num("vm_cpu_util_pct", "예상 CPU 사용률(%)", 1, 100)}${num("vm_mem_util_pct", "예상 메모리 사용률(%)", 1, 100)}</fieldset>
      <fieldset><legend>서버(호스트) 더하기·빼기</legend>${num("add_hosts", "더할 서버 수", 0, 256)}${num("remove_hosts", "뺄 서버 수", 0, 256)}
        <label class="full">더할 서버 사양<select name="spec">
          <option value="" ${f.spec === "" ? "selected" : ""}>이 클러스터의 평균 호스트${ah ? ` (${ah.cores}코어 · ${ah.mem_gb}GB)` : ""}</option>
          ${grp("올린 사양(수집 스크립트·직접 입력)", sp.uploaded)}${grp("BMC 스캔(하드웨어 준비도)", sp.bmc)}${grp("기존 ESXi 호스트 유형(vCenter)", sp.vcenter)}
          <option value="manual" ${f.spec === "manual" ? "selected" : ""}>직접 입력…</option></select></label>
        ${f.spec === "manual" ? `${num("host_sockets", "소켓 수", 0, 64)}${num("host_cores", "코어 수(전체)", 0, 1024, 1, ah ? `평균 ${ah.cores}` : "")}
          ${num("host_core_ghz", "코어 속도(GHz)", 0, 8, 0.1, ah ? `평균 ${ah.core_ghz}` : "")}${num("host_mem_gb", "메모리(GB)", 0, 16384, 1, ah ? `평균 ${ah.mem_gb}` : "")}
          <label class="full">플래시 디스크 합계(TB, vSAN 용)<input type="number" name="host_flash_tb" min="0" max="10000" step="0.1" value="${esc(f.host_flash_tb)}"></label>
          <label class="full">CPU 모델(EVC 검토용)<input name="host_cpu_model" maxlength="120" value="${esc(f.host_cpu_model || "")}" placeholder="예: Intel(R) Xeon(R) Gold 6542Y"></label>`
          : cs ? `<p class="full small muted" style="margin:0"><b>${esc(sl(cs.spec))}</b>${cs.spec.cpu_model ? `<br>${esc(cs.spec.cpu_model)}` : ""}${cs.spec.model ? `<br>${esc([cs.spec.vendor, cs.spec.model].filter(Boolean).join(" "))}` : ""}</p>` : ""}
        <details class="full wi-rm" ${f.remove_names.length ? "open" : ""}><summary>뺄 서버를 직접 고르기 <small class="muted">${f.remove_names.length ? `${f.remove_names.length}대 선택` : "교체·장애 가정"}</small></summary>
          ${(cur ? cur.host_list : []).map(h => `<label class="mb-chk"><input type="checkbox" name="rm" value="${esc(h.name)}" ${f.remove_names.includes(h.name) ? "checked" : ""}> ${esc(h.name)} <small class="muted">${h.cores}코어 · ${h.mem_gb}GB</small></label>`).join("")}
          <label class="mb-chk"><input type="checkbox" name="consume_ha" ${f.consume_ha ? "checked" : ""}> 장애로 보기 — 뺀 만큼 HA 여유를 이미 쓴 것으로 계산</label></details>
        <label class="full" title="세대가 다른 서버는 같은 GHz 라도 처리량이 다릅니다 — 벤치마크(SPECrate 등) 비율을 넣으면 CPU 용량에 곱합니다">새 서버 GHz당 성능(기존 = 1)<input type="number" name="perf_factor" min="0.3" max="3" step="0.05" value="${esc(f.perf_factor)}"></label>
        <button type="button" class="btn-sm full" id="wi-mgr">${st.mgr ? "서버 사양 닫기" : "서버 사양 가져오기·관리"}</button></fieldset>
      <fieldset><legend>스토리지·성장·적정화</legend>
        <label class="full">vSAN 저장 정책<select name="vsan_policy">${[["", "자동 — 실측 배수가 있으면 실측, 없으면 클러스터 기본"], ["measured", "실측(지금 객체들의 복제·패리티 비율)"], ["auto", "클러스터 기본(ESA=RAID-5 적응형, OSA=RAID-1)"], ["r1", "FTT=1 RAID-1(미러, 2배)"], ["r5", "FTT=1 RAID-5(ESA 1.25~1.5배·OSA 1.33배)"], ["r6", "FTT=2 RAID-6(1.5배)"], ["r1f2", "FTT=2 RAID-1(3배)"]]
          .map(([v, l]) => `<option value="${v}" ${f.vsan_policy === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        ${num("vsan_reserve_pct", "운영 예비(%)", 0, 30, 1)}${num("vsan_dr", "데이터 절감률(배)", 1, 10, 0.1, "비우면 vSAN 실측")}
        <label class="full">호스트 재구축 예비<select name="vsan_host_reserve">${[["", "vSAN 설정을 따름"], ["true", "빼기(호스트 1대 몫)"], ["false", "빼지 않기"]].map(([v, l]) => `<option value="${v}" ${String(f.vsan_host_reserve) === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="full">연 성장률(%) <input type="number" name="growth_pct_year" min="-50" max="500" step="1" value="${esc(f.growth_pct_year)}" placeholder="비우면 용량 추세(일별 증가율)로"></label>
        <label class="mb-chk full"><input type="checkbox" name="apply_rightsizing" ${f.apply_rightsizing ? "checked" : ""}> 적정화 권고 반영(유휴 VM 끄기·과다 할당 축소)</label></fieldset>
      <label>HA 여유 — 견딜 호스트 장애 수<select name="ha_failures">${[0, 1, 2, 3, 4].map(n => `<option value="${n}" ${+f.ha_failures === n ? "selected" : ""}>${n ? `${n}대(가장 큰 호스트 ${n}대 용량 제외)` : "0 — HA 여유 없이 계산"}</option>`).join("")}</select></label>
      <label>사용량 기준<select name="basis">
        <option value="now" ${f.basis === "now" ? "selected" : ""}>지금 값(vCenter 순간 값)</option>
        ${[7, 14, 28].map(d => `<option value="p95:${d}" ${f.basis === `p95:${d}` ? "selected" : ""}>최근 ${d}일 피크(시간별 평균의 95퍼센타일)</option>`).join("")}</select></label>
      <button class="btn-sm solid" type="submit" ${st.busy ? "disabled" : ""}>계산</button>
      <button class="btn-sm" type="button" id="wi-one">서버 1대만 더하면?</button>
      <button class="btn-sm" type="button" id="wi-fail">가장 큰 서버 1대가 죽으면?</button>
      <p class="small muted">vCenter 에는 아무것도 바꾸지 않습니다.</p></form>`;
  }

  // ------------------------------------------------------------ 서버 사양 가져오기·관리
  function manager() {
    const sp = st.sp || {uploaded: [], bmc: [], vcenter: [], scripts: []}, can = A.can("operate");
    return `<div class="wi-box wi-mgr"><h5>서버 사양 가져오기 <small class="muted">세 가지 길 — 모두 읽기 전용</small></h5>
      <ol class="wi-how">
        <li><b>vCenter 커넥터</b> — 이미 있는 ESXi 호스트 유형 ${sp.vcenter.length}개가 자동으로 목록에 있습니다(같은 사양을 한 대 더 넣는 경우).</li>
        <li><b>BMC(Redfish) 스캔</b> — ESXi 를 올리기 전의 새 서버는 <a href="#go=rd">점검·진단 › 하드웨어 준비도</a>에서 BMC 주소로 스캔하면 여기에 나옵니다(지금 ${sp.bmc.length}대).</li>
        <li><b>수집 스크립트</b> — 서버에서 한 번 실행하고 나온 JSON 을 아래에 붙여 넣습니다. 호스트 이름·IP·시리얼은 담지 않습니다.
          <div class="wi-dl">${(sp.scripts || []).map(x => `<a class="btn-sm" href="/api/capacity/spec-script/${esc(x.name)}" download>${esc(x.name)} <small>(${esc(x.os)})</small></a>`).join("")}</div>
          <pre class="wi-cmd">sh collect-server-spec.sh > spec.json</pre></li></ol>
      ${can ? `<form id="wi-up" class="wi-up"><label>이름<input name="name" maxlength="80" placeholder="예: 신규 R760 (비우면 제조사·모델)"></label>
        <label>JSON <input type="file" id="wi-file" accept=".json,application/json,text/plain"></label>
        <textarea name="spec" rows="4" placeholder='{"schema":"vcf-aiops-server-spec/1","sockets":2,"cores":64,"core_ghz":2.6,"mem_gb":1024,...}' required></textarea>
        <button class="btn-sm solid" type="submit">사양 올리기</button></form>` : `<p class="small muted">사양 올리기는 운영자 이상 권한이 필요합니다.</p>`}
      ${sp.uploaded.length ? `<table class="dr-t"><thead><tr><th>올린 사양</th><th>내용</th><th>라이선스 코어</th><th></th></tr></thead><tbody>${sp.uploaded.map(x => `<tr><td><b>${esc(x.name)}</b><div class="small muted">${esc(x.by || "")} · ${x.created ? new Date(x.created * 1000).toLocaleDateString() : ""}</div></td>
        <td class="small">${esc(sl(x.spec))}<div class="muted">${esc(x.spec.cpu_model || "")}${x.spec.nic_gbps && x.spec.nic_gbps.length ? ` · NIC ${x.spec.nic_gbps.slice(0, 4).join("/")}Gb` : ""}</div></td><td>${x.spec.licensed_cores}</td>
        <td class="r"><button class="btn-sm" data-wiuse="${esc(x.id)}">이 사양으로</button>${can ? ` <button class="btn-sm danger" data-widel="${esc(x.id.slice(3))}">삭제</button>` : ""}</td></tr>`).join("")}</tbody></table>` : ""}</div>`;
  }

  function side(title, s) {
    const bar = (label, x, unitUsed, unitTot) => { const p = x.pct_usable; return `<div class="wi-row"><span>${label}</span><div><div class="wi-bar"><i class="${cls(p)}" style="width:${Math.min(100, p == null ? 100 : p)}%"></i><u style="left:80%"></u><em>${p == null ? "용량 없음" : N(p) + "%"}</em></div>
      <small>${N(unitUsed)} / 쓸 수 있는 ${N(unitTot)} · 전체 대비 ${N(x.pct_total)}%</small></div></div>`; };
    return `<div class="wi-box"><h5>${title} <small class="muted">호스트 ${s.hosts} · 켜진 VM ${N(s.vms, 0)} · vCPU:코어 ${s.vcpu_per_core == null ? "—" : N(s.vcpu_per_core, 2) + ":1"}</small></h5>
      ${bar("CPU", s.cpu, s.cpu.used_ghz, s.cpu.usable_ghz)}${bar("메모리", s.mem, s.mem.used_gb, s.mem.usable_gb)}</div>`;
  }

  function result() {
    if (st.err) return `<div class="empty">${esc(st.err)}</div>`;
    const r = st.r; if (!r) return `<div class="empty">왼쪽에 가정을 넣고 '계산'을 누르세요.</div>`;
    const a = r.after, b = r.before, v = VD[a.verdict], i = r.inputs;
    const d = (x, y, unit, inv) => { if (x == null || y == null) return ""; const z = y - x; return z ? ` <span class="${(z > 0) === !inv ? "up" : "dn"}">${z > 0 ? "+" : ""}${N(z)}${unit}</span>` : ""; };
    const what = [i.add_vms ? `VM ${N(i.add_vms, 0)}대 추가(${i.vm_vcpu} vCPU · ${i.vm_mem_gb} GB)` : "", i.remove_vms ? `VM ${N(i.remove_vms, 0)}대 제거` : "", i.add_hosts ? `호스트 ${i.add_hosts}대 추가(${r.host_spec.cores}코어 · ${r.host_spec.mem_gb} GB${r.host_spec.custom ? "" : ", 평균 사양"})` : "", i.remove_hosts ? `호스트 ${i.remove_hosts}대 제거` : "", i.remove_names.length ? `${i.consume_ha ? "장애" : "제거"}: ${i.remove_names.join(", ")}` : ""].filter(Boolean).join(" · ") || "변경 없음";
    return `<div class="wi-verdict ${a.verdict}"><b>${v[0]}</b><p>${esc(r.cluster)} — ${what}. ${v[1]} ${a.verdict !== "ok" ? `부족한 쪽은 <b style="display:inline;font-size:inherit">${r.limit === "mem" ? "메모리" : "CPU"}</b>입니다.` : ""}</p>
        ${a.verdict !== "ok" ? `<p>${r.hosts_needed == null ? "같은 사양 호스트 64대를 더해도 80% 안에 들지 않습니다 — 입력을 확인하세요." : `80% 안에 들이려면 같은 사양 호스트 <b style="display:inline;font-size:inherit">${r.hosts_needed}대</b>가 더 필요합니다.`}</p>` : ""}</div>
      <div class="wi-cmp">${side("지금", b)}${side("가정 뒤", a)}</div>
      <p class="wi-basis small">${r.basis.kind === "p95" ? `사용량 기준: <b>최근 ${r.basis.days}일 피크</b>(시간별 평균의 95퍼센타일, 표본 ${N(r.basis.samples, 0)}시간) — CPU ${N(st.r.before.cpu.used_ghz)} GHz · 메모리 ${N(st.r.before.mem.used_gb)} GB
          <span class="muted">(지금 값 ${N(r.basis.now_cpu_ghz)} GHz · ${N(r.basis.now_mem_gb)} GB, 기간 최대 ${N(r.basis.max_cpu_ghz)} GHz · ${N(r.basis.max_mem_gb)} GB)</span>`
          : `사용량 기준: <b>지금 값</b>${r.basis.why ? ` — <span class="bad">${esc(r.basis.why)}</span>` : ""}`}${i.consume_ha ? ` · 장애 가정: HA 여유 ${i.ha_failures}대 → ${i.ha_after}대` : ""}
        <span class="wi-acts">${A.can("operate") ? `<button class="btn-sm" type="button" id="wi-save">이 가정 저장</button> ` : ""}<button class="btn-sm" type="button" id="wi-exp">결과 내보내기(.md)</button></span></p>
      <div class="wi-box"><h5>달라지는 것</h5><div class="wi-kv"><span class="h"></span><span class="h">지금</span><span class="h">가정 뒤</span>
        <b>CPU 여유(HA 제외)</b><span>${N(b.cpu.free_ghz)} GHz</span><span>${N(a.cpu.free_ghz)} GHz${d(b.cpu.free_ghz, a.cpu.free_ghz, " GHz", true)}</span>
        <b>메모리 여유(HA 제외)</b><span>${N(b.mem.free_gb)} GB</span><span>${N(a.mem.free_gb)} GB${d(b.mem.free_gb, a.mem.free_gb, " GB", true)}</span>
        <b>CPU 90% 도달</b><span>${days(b.cpu.days_to_90)}</span><span>${days(a.cpu.days_to_90)}</span>
        <b>메모리 90% 도달</b><span>${days(b.mem.days_to_90)}</span><span>${days(a.mem.days_to_90)}</span>
        <b>vCPU:코어</b><span>${b.vcpu_per_core == null ? "—" : N(b.vcpu_per_core, 2) + ":1"}</span><span>${a.vcpu_per_core == null ? "—" : N(a.vcpu_per_core, 2) + ":1"}</span>
        <b>같은 VM 을 더 넣을 수 있는 수</b><span></span><span>80%까지 ${N(r.room.to_80, 0)}대 · 100%까지 ${N(r.room.to_100, 0)}대</span>
        ${r.license && r.license.before != null && r.license.after != null ? `<b>라이선스 코어(소켓당 최소 16)</b><span>${N(r.license.before, 0)}</span><span>${N(r.license.after, 0)}${d(r.license.before, r.license.after, " 코어")}</span>`
          : r.license && r.license.per_new_host ? `<b>라이선스 코어(소켓당 최소 16)</b><span>—</span><span>추가 서버 1대당 ${N(r.license.per_new_host, 0)} 코어</span>` : ""}
        ${r.storage ? `<b>공유 스토리지 사용률${r.storage.vsan ? "(vSAN)" : ""}</b><span>${N(r.storage.pct)}% <small class="muted">${N(r.storage.used_tb)} / ${N(r.storage.total_tb)} TB</small></span>
          <span>${N(r.storage.after_pct)}%${d(r.storage.pct, r.storage.after_pct, "%p")}${r.storage.raw_added_tb ? ` <small class="muted">· 원시 용량 +${N(r.storage.raw_added_tb)} TB(정책 적용 전, 사용률에는 미반영)</small>` : ""}</span>` : ""}</div>
        ${(r.notes || []).length ? `<ul class="wi-notes">${r.notes.map(n => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
        <p class="small muted">VM 1대 = CPU ${N(r.per_vm.cpu_ghz, 2)} GHz · 메모리 ${N(r.per_vm.mem_gb)} GB 로 계산(사양 × 예상 사용률). 막대의 세로선은 80%.
          남은 기간은 용량 예측의 일별 증가율(${r.days_observed ? `${r.days_observed}일 관측` : "관측 부족"})을 그대로 적용한 값입니다${r.slopes.cpu == null && r.slopes.mem == null ? " — 아직 추세가 없어 표시하지 않습니다" : ""}.
          공유 스토리지 줄은 원시 용량 합계 기준이고, vSAN 은 아래 '쓸 수 있는 용량'에서 저장 정책·예비·절감률을 반영합니다. 라이선스 코어는 Broadcom KB 313548 의 소켓당 최소 16코어 규칙으로 셉니다(주문 최소 수량 등 계약 조건은 별도).</p></div>
      ${vsanBox(r)}${evcBox(r)}${rsBox(r)}${quarterBox(r)}${costBox(r)}`;
  }

  // ------------------------------------------------------------ 2.36.0 결과 상자
  function vsanBox(r) {
    const v = r.vsan; if (!v) return "";
    const a = v.after || {};
    const bar = (p, label) => `<div class="wi-row"><span>${label}</span><div><div class="wi-bar"><i class="${cls(p)}" style="width:${Math.min(100, p == null ? 100 : p)}%"></i><u style="left:80%"></u><em>${p == null ? "—" : N(p) + "%"}</em></div></div></div>`;
    const src = v.sources || {}, m = v.measured || {};
    return `<div class="wi-box"><h5>vSAN 쓸 수 있는 용량 <small class="muted">${esc(v.policy_label)} · ${esc(v.scheme)}(원시 ${v.mult}배) · ${v.esa ? "ESA" : "OSA"}</small></h5>
      <p class="small" style="margin:0 0 6px">값의 출처 — 정책 배수 <b>${esc(src.policy || "")}</b>${m.policy_mult ? ` (실측 ${N(m.policy_mult, 2)}배)` : ""} · 절감률 <b>${esc(src.dr || "")}</b> ${N(v.dr, 2)}배 · 호스트 재구축 예비 <b>${esc(src.host_reserve || "")}</b>${v.host_reserve ? " 켬" : " 끔"}
        ${m.ts ? `<span class="muted">· vSAN 공간 보고 ${new Date(m.ts * 1000).toLocaleString()}</span>` : `<span class="muted">· vSAN 공간 보고 없음(vSAN 상태 수집 꺼짐·권한)</span>`}</p>
      ${bar(v.pct, "지금")}${a.pct !== undefined ? bar(a.pct, "가정 뒤") : ""}
      <div class="wi-kv"><span class="h"></span><span class="h">지금</span><span class="h">가정 뒤</span>
        <b>원시 용량</b><span>${N(v.raw_tb)} TB</span><span>${N(a.raw_tb)} TB</span>
        <b>예비(운영 ${N(v.reserve_pct, 0)}%${v.host_reserve ? " + 호스트 1대" : ""})</b><span>${N(v.reserve_tb + v.host_reserve_tb)} TB</span><span></span>
        <b>정책 적용 후 쓸 수 있는 용량</b><span>${N(v.usable_tb)} TB</span><span>${N(a.usable_tb)} TB${a.scheme && a.scheme !== v.scheme ? ` <small class="muted">(${esc(a.scheme)})</small>` : ""}</span>
        <b>VM 데이터(논리)</b><span>${N(v.used_tb)} TB</span><span>${N(a.used_tb)} TB</span>
        <b>남는 용량</b><span class="${v.free_tb < 0 ? "bad" : ""}">${N(v.free_tb)} TB</span><span class="${a.free_tb < 0 ? "bad" : ""}">${N(a.free_tb)} TB</span></div>
      ${!v.hosts_ok || a.hosts_ok === false ? `<p class="small bad">이 정책은 호스트 ${a.min_hosts || v.min_hosts}대 이상이 필요합니다.</p>` : ""}
      ${a.scheme_note ? `<p class="small">${esc(a.scheme_note)}</p>` : ""}${a.note ? `<p class="small muted">${esc(a.note)}</p>` : ""}${a.note2 ? `<p class="small muted">${esc(a.note2)}</p>` : ""}
      <p class="small muted">쓸 수 있는 용량 = (원시 × (1 − 운영 예비) − 호스트 1대) ÷ 정책 배수 × 절감률. 모든 객체가 이 정책이라고 가정합니다 — 정확한 값은 vSAN ReadyNode Sizer 로 확인하세요.</p></div>`;
  }
  function evcBox(r) {
    const e = r.evc; if (!e) return "";
    const V = {ok: ["문제 없음", ""], warn: ["확인 필요", "warn"], bad: ["섞을 수 없음", "bad"], unknown: ["판단 불가", ""]}[e.verdict] || ["", ""];
    return `<div class="wi-box"><h5>혼합 세대(EVC) 검토 <span class="dr-v ${V[1] || "ok"}">${V[0]}</span>
        <small class="muted">기존 ${esc((e.existing || []).join(", ") || "—")} · 새 서버 ${esc(e.new || "—")} · 클러스터 EVC ${esc(e.cluster_evc || "꺼짐")}</small></h5>
      <ul class="wi-notes">${(e.items || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      ${e.core_ghz ? `<p class="small muted">코어 속도 기존 평균 ${N(e.core_ghz.existing, 2)} GHz · 새 서버 ${N(e.core_ghz.new, 2)} GHz · GHz당 성능 보정 ${N(e.core_ghz.perf_factor, 2)}배. 근거: ${esc((e.refs || []).join(", "))}</p>` : ""}</div>`;
  }
  function rsBox(r) {
    const x = r.rightsizing; if (!x) return "";
    return `<div class="wi-box"><h5>적정화 반영 <small class="muted">관측 ${esc(x.observed_days ?? "—")}일 기준</small></h5>
      <p style="margin:0 0 6px">${x.deferred ? `적정화 권고를 적용하면 서버 증설을 <b>${x.deferred}대</b> 미룰 수 있습니다.` : x.hosts_needed_without === 0 ? "적정화 없이도 80% 안에 듭니다 — 돌려받는 자원은 여유로 남습니다." : "적정화만으로는 필요한 서버 수가 줄지 않습니다."}</p>
      <div class="wi-kv" style="grid-template-columns:max-content minmax(0,1fr)">
        <b>유휴 VM 끄기</b><span>${x.idle}대</span><b>과다 할당 축소</b><span>${x.oversized}대</span><b>과소 할당 증설(더함)</b><span>${x.undersized}대</span>
        <b>돌려받는 CPU·메모리</b><span>${N(x.cpu_ghz)} GHz · ${N(x.mem_gb)} GB · vCPU ${N(x.vcpu, 0)}</span>
        <b>장기 꺼짐 VM 디스크</b><span>${N(x.disk_tb, 2)} TB(${x.powered_off}대)</span>
        <b>필요 서버(적정화 전 → 후)</b><span>${x.hosts_needed_without ?? "64대 초과"} → ${x.hosts_needed_with ?? "64대 초과"}</span></div>
      <p class="small muted">과다 할당 축소는 메모리만 돌려받는 것으로 셉니다(CPU 사용량은 그대로). 목록은 <button type="button" class="btn-sm" data-ct="rs">VM 적정화 탭</button>에서 확인하세요.</p></div>`;
  }
  function quarterBox(r) {
    const q = r.quarters; if (!q) return "";
    if (!q.rows.length) return `<div class="wi-box"><h5>분기별 증설 계획</h5><p class="small muted">${esc(q.why || "")}</p></div>`;
    return `<div class="wi-box"><h5>분기별 증설 계획 <small class="muted">${q.basis === "growth" ? `연 ${N(q.growth_pct_year, 0)}% 성장(복리)` : `용량 추세(CPU ${N(q.slopes.cpu, 2)}%p/일 · 메모리 ${N(q.slopes.mem, 2)}%p/일)`} · 추가 서버 ${q.host.cores}코어·${q.host.mem_gb}GB 기준</small></h5>
      <div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>분기</th><th class="r">CPU 수요</th><th class="r">메모리 수요</th><th class="r">필요 서버(누적)</th><th class="r">그 분기 추가</th><th class="r">라이선스 코어</th>${q.rows.some(x => x.storage_pct != null) ? `<th class="r">스토리지</th>` : ""}</tr></thead>
      <tbody>${q.rows.map(x => `<tr><td>${esc(x.label)}<div class="small muted">${esc(x.end)}</div></td><td class="r">${N(x.cpu_ghz)} GHz</td><td class="r">${N(x.mem_gb, 0)} GB</td>
        <td class="r">${x.hosts_add == null ? "64대 초과" : `+${x.hosts_add}대 <small class="muted">(총 ${x.hosts_total})</small>`}</td><td class="r"><b>${x.add_this_q ? `+${x.add_this_q}` : "—"}</b></td>
        <td class="r">${N(x.license_cores, 0)}</td>${q.rows.some(y => y.storage_pct != null) ? `<td class="r ${cls(x.storage_pct)}">${x.storage_pct == null ? "—" : N(x.storage_pct) + "%"}</td>` : ""}</tr>`).join("")}</tbody></table></div>
      <p class="small muted">각 분기 말 수요에서 '쓸 수 있는 용량의 80% 미만'을 지키는 최소 서버 수입니다. 라이선스 코어는 그때의 전체 호스트 기준(소켓당 최소 16).</p></div>`;
  }
  function costBox(r) {
    const c = r.cost; if (!c) return "";
    const v = c.vcf, money = (x, cur) => x == null ? "—" : `${Number(x).toLocaleString()} ${cur}`;
    return `<div class="wi-box"><h5>비용 <small class="muted">${esc(c.hosts_basis || "")} · 클라우드 비용 비교의 원가 모델·단가표</small> <a class="btn-sm" href="#go=cc">비용 비교 열기</a></h5>
      ${v ? `<div class="wi-kv" style="grid-template-columns:max-content minmax(0,1fr)">
          <b>증설 서버·코어</b><span>${v.hosts}대 · 라이선스 코어 ${N(v.license_cores, 0)}</span>
          <b>서버 구매(일회)</b><span>${money(v.capex_hw, v.currency)}</span>
          <b>연 비용</b><span><b>${money(v.annual, v.currency)}</b> <small class="muted">구독 ${money(v.parts.subscription_year, v.currency)} · 서버 감가 ${money(v.parts.hardware_year, v.currency)} · 상면 ${money(v.parts.facility_year, v.currency)}</small></span>
          <b>${v.years}년 합계</b><span>${money(v.tco, v.currency)}</span>
          ${v.per_vm_month != null ? `<b>추가 VM 1대당 월</b><span>${money(v.per_vm_month, v.currency)}</span>` : ""}</div>` : `<p class="small muted">${esc(c.note || "")}</p>`}
      ${c.cloud.length ? `<h5 style="margin-top:10px">같은 VM ${c.vm.count}대(${c.vm.vcpu} vCPU · ${c.vm.mem_gb} GB · 디스크 ${c.vm.disk_gb} GB)를 퍼블릭 클라우드에 올리면 <small class="muted">${esc(c.commit)} · USD</small></h5>
        <table class="dr-t"><thead><tr><th>클라우드</th><th>인스턴스</th><th class="r">월</th><th class="r">${v ? v.years : 5}년 합계</th></tr></thead><tbody>
        ${c.cloud.map(x => `<tr><td>${esc(x.label)}${x.verified === false ? ' <span class="cc-b no">미확인 단가</span>' : ""}</td><td class="mono small">${esc(x.sku || "—")}</td>
          <td class="r">${x.monthly == null ? `<span class="muted">${esc(x.missing || "—")}</span>` : `$${Number(x.monthly).toLocaleString()}`}</td><td class="r">${x.years_total == null ? "—" : `$${Number(x.years_total).toLocaleString()}`}</td></tr>`).join("")}
        ${v && v.monthly_usd != null ? `<tr><td><b>VCF 증설분</b></td><td class="small muted">서버·코어 증설 비용 ÷ 12</td><td class="r"><b>$${Number(v.monthly_usd).toLocaleString()}</b></td><td class="r">$${Number(v.monthly_usd * 12 * v.years).toLocaleString()}</td></tr>` : ""}</tbody></table>` : ""}
      <p class="small muted">${esc(c.caveat || "")}</p></div>`;
  }

  // 결과를 보고서 초안(Markdown)으로 — 고객·내부 검토용
  function report() {
    const r = st.r; if (!r) return "";
    const a = r.after, b = r.before, i = r.inputs, v = VD[a.verdict], p = x => x == null ? "—" : `${N(x)}%`;
    const L = [`# 가정 분석 — ${r.cluster} (${r.vcenter})`, "", `- 작성: ${new Date().toLocaleString()} · VCF AIops`, `- 판정: **${v[0]}** — ${v[1]}`,
      `- 사용량 기준: ${r.basis.kind === "p95" ? `최근 ${r.basis.days}일 피크(시간별 평균의 95퍼센타일, 표본 ${r.basis.samples}시간)` : `지금 값${r.basis.why ? `(${r.basis.why})` : ""}`}${i.consume_ha ? ` · 장애 가정(HA 여유 ${i.ha_failures} → ${i.ha_after}대)` : ""}`,
      i.remove_names.length ? `- ${i.consume_ha ? "장애" : "제거"} 호스트: ${i.remove_names.join(", ")}` : "",
      `- 가정: VM +${i.add_vms}/-${i.remove_vms}대(${i.vm_vcpu} vCPU · ${i.vm_mem_gb} GB, 예상 사용률 CPU ${i.vm_cpu_util_pct}% · 메모리 ${i.vm_mem_util_pct}%), 서버 +${i.add_hosts}/-${i.remove_hosts}대, HA 여유 ${i.ha_failures}대`,
      i.add_hosts ? `- 더할 서버 사양: ${r.host_spec.sockets ? `${r.host_spec.sockets}소켓 · ` : ""}${r.host_spec.cores}코어 · ${r.host_spec.core_ghz} GHz · ${r.host_spec.mem_gb} GB${r.host_spec.cpu_model ? ` (${r.host_spec.cpu_model})` : ""}${r.host_spec.custom ? "" : " — 클러스터 평균 사양"}` : "",
      a.verdict !== "ok" && r.hosts_needed ? `- 80% 안에 들이려면 같은 사양 서버 ${r.hosts_needed}대 추가 필요(부족한 쪽: ${r.limit === "mem" ? "메모리" : "CPU"})` : "", "",
      "| 항목 | 지금 | 가정 뒤 |", "| --- | --- | --- |",
      `| 호스트 · 켜진 VM | ${b.hosts} · ${b.vms} | ${a.hosts} · ${a.vms} |`,
      `| CPU 사용률(쓸 수 있는 용량 대비) | ${p(b.cpu.pct_usable)} (${N(b.cpu.used_ghz)} / ${N(b.cpu.usable_ghz)} GHz) | ${p(a.cpu.pct_usable)} (${N(a.cpu.used_ghz)} / ${N(a.cpu.usable_ghz)} GHz) |`,
      `| 메모리 사용률(쓸 수 있는 용량 대비) | ${p(b.mem.pct_usable)} (${N(b.mem.used_gb)} / ${N(b.mem.usable_gb)} GB) | ${p(a.mem.pct_usable)} (${N(a.mem.used_gb)} / ${N(a.mem.usable_gb)} GB) |`,
      `| CPU 여유(HA 제외) | ${N(b.cpu.free_ghz)} GHz | ${N(a.cpu.free_ghz)} GHz |`, `| 메모리 여유(HA 제외) | ${N(b.mem.free_gb)} GB | ${N(a.mem.free_gb)} GB |`,
      `| CPU 90% 도달 | ${days(b.cpu.days_to_90)} | ${days(a.cpu.days_to_90)} |`, `| 메모리 90% 도달 | ${days(b.mem.days_to_90)} | ${days(a.mem.days_to_90)} |`,
      `| vCPU:코어 | ${b.vcpu_per_core ?? "—"}:1 | ${a.vcpu_per_core ?? "—"}:1 |`,
      r.license && r.license.before != null && r.license.after != null ? `| 라이선스 코어(소켓당 최소 16) | ${r.license.before} | ${r.license.after} (${r.license.delta >= 0 ? "+" : ""}${r.license.delta}) |` : r.license && r.license.per_new_host ? `| 라이선스 코어(소켓당 최소 16) | — | 추가 서버 1대당 ${r.license.per_new_host} |` : "",
      r.storage ? `| 공유 스토리지 사용률 | ${p(r.storage.pct)} (${N(r.storage.used_tb)} / ${N(r.storage.total_tb)} TB) | ${p(r.storage.after_pct)}${r.storage.raw_added_tb ? ` · 원시 +${N(r.storage.raw_added_tb)} TB` : ""} |` : "",
      `| 같은 VM 을 더 넣을 수 있는 수 | | 80%까지 ${r.room.to_80}대 · 100%까지 ${r.room.to_100}대 |`, "",
      ...(r.notes || []).map(n => `- 주의: ${n}`), "",
      ...(r.vsan ? [`## vSAN 쓸 수 있는 용량`, "", `- 정책: ${r.vsan.policy_label} — ${r.vsan.scheme}(원시 ${r.vsan.mult}배), 운영 예비 ${r.vsan.reserve_pct}%${r.vsan.host_reserve ? " + 호스트 1대" : ""}, 절감률 ${r.vsan.dr}배`,
        `- 쓸 수 있는 용량: ${N(r.vsan.usable_tb)} TB → ${N((r.vsan.after || {}).usable_tb)} TB, 사용률 ${p(r.vsan.pct)} → ${p((r.vsan.after || {}).pct)}`, (r.vsan.after || {}).scheme_note ? `- ${r.vsan.after.scheme_note}` : "", ""] : []),
      ...(r.evc && r.evc.items.length ? [`## 혼합 세대(EVC)`, "", ...r.evc.items.map(x => `- ${x}`), ""] : []),
      ...(r.rightsizing ? [`## 적정화 반영`, "", `- 유휴 ${r.rightsizing.idle} · 과다 ${r.rightsizing.oversized} · 과소 ${r.rightsizing.undersized}대 — 돌려받는 CPU ${N(r.rightsizing.cpu_ghz)} GHz · 메모리 ${N(r.rightsizing.mem_gb)} GB`,
        `- 필요 서버 ${r.rightsizing.hosts_needed_without ?? "64+"} → ${r.rightsizing.hosts_needed_with ?? "64+"}대${r.rightsizing.deferred ? ` (${r.rightsizing.deferred}대 미룸)` : ""}`, ""] : []),
      ...(r.quarters && r.quarters.rows.length ? [`## 분기별 증설 계획`, "", "| 분기 | CPU 수요 | 메모리 수요 | 필요 서버(누적) | 그 분기 추가 | 라이선스 코어 |", "| --- | --- | --- | --- | --- | --- |",
        ...r.quarters.rows.map(x => `| ${x.label} | ${N(x.cpu_ghz)} GHz | ${N(x.mem_gb, 0)} GB | ${x.hosts_add ?? "64+"} | ${x.add_this_q ?? "—"} | ${x.license_cores ?? "—"} |`), ""] : []),
      ...(r.cost && (r.cost.vcf || r.cost.cloud.length) ? [`## 비용`, "", r.cost.vcf ? `- 증설 연 비용(VCF 원가 모델): ${Number(r.cost.vcf.annual).toLocaleString()} ${r.cost.vcf.currency} (서버 ${r.cost.vcf.hosts}대 · 코어 ${r.cost.vcf.license_cores})` : `- ${r.cost.note}`,
        ...r.cost.cloud.filter(x => x.monthly != null).map(x => `- 같은 VM 을 ${x.label}(${x.sku})에: 월 $${Number(x.monthly).toLocaleString()}`), ""] : []),
      "계산 기준: 쓸 수 있는 용량 = 전체 − 가장 큰 호스트 N대(HA 여유). 사용량은 vCenter 호스트 요약의 현재 값, 남은 기간은 관측된 일별 증가율 적용. 스토리지는 공유 데이터스토어 합계 기준(저장 정책·중복 제거 미반영). 라이선스 코어는 Broadcom KB 313548 의 CPU당 최소 16코어 규칙(주문 최소 수량 등 계약 조건 별도). 간이 계산이며 VCF Operations 의 예측 결과와 다를 수 있습니다."];
    return L.filter(x => x !== "").join("\n").replace(/\n(\| 항목)/, "\n\n$1").replace(/(\|\n)(- 주의|계산 기준)/, "$1\n$2") + "\n";
  }

  // ------------------------------------------------------------ 저장한 가정·나란히 비교(2.35.0)
  function saved() {
    if (!st.sc.length) return "";
    const can = A.can("operate");
    return `<div class="wi-box"><h5>저장한 가정 <small class="muted">${st.sc.length}개 · 골라서 지금 값으로 다시 계산해 비교</small>
        <button class="btn-sm" type="button" id="wi-cmp" ${st.pick.size >= 2 ? "" : "disabled"}>고른 ${st.pick.size}개 비교</button></h5>
      <table class="dr-t"><tbody>${st.sc.map(x => `<tr><td style="width:28px"><input type="checkbox" data-wipick="${x.id}" ${st.pick.has(x.id) ? "checked" : ""} aria-label="비교에 넣기"></td>
        <td><b>${esc(x.name)}</b><div class="small muted">${esc(x.cluster)} · ${esc(x.by || "")} · ${x.created ? new Date(x.created * 1000).toLocaleDateString() : ""}</div></td>
        <td class="small">${esc(brief(x.inputs))}</td>
        <td class="r"><button class="btn-sm" data-wiload="${x.id}">불러오기</button>${can ? ` <button class="btn-sm danger" data-wiscdel="${x.id}">삭제</button>` : ""}</td></tr>`).join("")}</tbody></table>
      ${st.cmp ? compare() : ""}</div>`;
  }
  const brief = i => [+i.add_vms ? `VM +${i.add_vms}(${i.vm_vcpu || 4}vCPU·${i.vm_mem_gb || 16}GB)` : "", +i.remove_vms ? `VM -${i.remove_vms}` : "", +i.add_hosts ? `서버 +${i.add_hosts}${i.spec_name ? `(${i.spec_name})` : ""}` : "",
    +i.remove_hosts ? `서버 -${i.remove_hosts}` : "", (i.remove_names || []).length ? `${i.consume_ha ? "장애" : "제거"} ${i.remove_names.length}대` : "", i.basis === "p95" ? `${i.basis_days}일 피크` : ""].filter(Boolean).join(" · ") || "변경 없음";
  function compare() {
    const C = st.cmp, row = (label, fn) => `<tr><th>${label}</th>${C.map(c => `<td>${c.err ? "—" : fn(c.r)}</td>`).join("")}</tr>`;
    return `<h5 style="margin-top:14px">비교</h5><div style="overflow-x:auto"><table class="dr-t wi-cmpt"><thead><tr><th></th>${C.map(c => `<th>${esc(c.name)}<div class="small muted">${esc(c.cluster)}</div></th>`).join("")}</tr></thead><tbody>
      ${`<tr><th>판정</th>${C.map(c => c.err ? `<td class="bad">${esc(c.err)}</td>` : `<td><span class="dr-v ${c.r.after.verdict}">${VD[c.r.after.verdict][0]}</span></td>`).join("")}</tr>`}
      ${row("가정", r => esc(brief({...r.inputs, basis: r.basis.kind, basis_days: r.basis.days})))}
      ${row("CPU 사용률", r => `${N(r.before.cpu.pct_usable)}% → <b>${N(r.after.cpu.pct_usable)}%</b>`)}
      ${row("메모리 사용률", r => `${N(r.before.mem.pct_usable)}% → <b>${N(r.after.mem.pct_usable)}%</b>`)}
      ${row("CPU 여유", r => `${N(r.after.cpu.free_ghz)} GHz`)}${row("메모리 여유", r => `${N(r.after.mem.free_gb)} GB`)}
      ${row("메모리 90% 도달", r => days(r.after.mem.days_to_90))}
      ${row("호스트 수", r => `${r.before.hosts} → ${r.after.hosts}`)}
      ${row("라이선스 코어", r => r.license.before != null && r.license.after != null ? `${N(r.license.after, 0)} (${r.license.delta >= 0 ? "+" : ""}${N(r.license.delta, 0)})` : "—")}
      ${row("더 필요한 서버", r => r.after.verdict === "ok" ? "없음" : r.hosts_needed == null ? "64대 초과" : `${r.hosts_needed}대`)}
      ${row("같은 VM 을 더(80%까지)", r => `${N(r.room.to_80, 0)}대`)}</tbody></table></div>`;
  }
  // 화면 입력 → 서버로 보낼 본문
  function payload(f) {
    const [vc, ...rest] = String(f.key).split("|"), cs = specOf(f.spec);
    const body = {...f, vcenter: vc, cluster: rest.join("|")};
    if (f.spec !== "manual") { for (const k of ["host_cores", "host_core_ghz", "host_mem_gb", "host_sockets", "host_flash_tb", "host_cpu_model"]) body[k] = ""; }
    if (cs) Object.assign(body, {host_cores: cs.spec.cores, host_core_ghz: cs.spec.core_ghz || "", host_mem_gb: cs.spec.mem_gb, host_sockets: cs.spec.sockets || "", host_flash_tb: cs.spec.flash_tb || "", host_cpu_model: cs.spec.cpu_model || "", spec_name: cs.name});
    const [bk, bd] = String(f.basis || "now").split(":"); body.basis = bk; body.basis_days = bd ? +bd : "";
    delete body.spec; delete body.key;
    return body;
  }

  const MODES = [["one", "한 클러스터"], ["move", "클러스터 간 이동"], ["dr", "DR 사이트 수용"], ["rb", "보고서 묶음"]];
  function draw(root) {
    if (!root) return;
    if (st.cl === null) { root.innerHTML = `<div class="empty">불러오는 중…</div>`; return; }
    if (!st.cl.length) { root.innerHTML = `<div class="empty">vCenter 클러스터 정보가 아직 없습니다.</div>`; return; }
    const tabs = `<div class="wi-modes" role="tablist">${MODES.map(([k, l]) => `<button type="button" role="tab" aria-selected="${st.mode === k}" class="${st.mode === k ? "on" : ""}" data-wimode="${k}">${l}</button>`).join("")}</div>`;
    root.innerHTML = tabs + (st.mode === "move" ? moveView() : st.mode === "dr" ? drView() : st.mode === "rb" ? rbView()
      : `<div class="wi-wrap">${form()}<div class="wi-res"><div id="wi-res" class="wi-res">${result()}</div>${st.mgr ? manager() : ""}<div id="wi-saved">${saved()}</div></div></div>`);
  }

  // ------------------------------------------------------------ 2.36.0 클러스터 간 이동
  const clOpt = (sel, skip) => (st.cl || []).filter(c => `${c.vcenter}|${c.cluster}` !== skip).map(c => `<option value="${esc(c.vcenter)}|${esc(c.cluster)}" ${`${c.vcenter}|${c.cluster}` === sel ? "selected" : ""}>${esc(c.cluster)} — ${esc(c.vcenter)}</option>`).join("");
  function moveView() {
    const m = st.mv, q = m.q.toLowerCase();
    const shown = m.vms.filter(v => !q || (v.name + " " + v.folder).toLowerCase().includes(q));
    const tot = m.vms.filter(v => m.pick.has(v.name));
    return `<div class="wi-wrap"><form class="wi-form" id="wi-mvf">
      <label>옮길 VM 이 있는 클러스터<select name="src">${clOpt(m.src)}</select></label>
      <label>받을 클러스터<select name="dst">${clOpt(m.dst, m.src)}</select></label>
      <fieldset><legend>옮길 VM <small>${m.pick.size}대 · ${N(tot.reduce((a, v) => a + v.vcpu, 0), 0)} vCPU · ${N(tot.reduce((a, v) => a + v.mem_gb, 0), 0)} GB</small></legend>
        <label class="full">찾기(이름·폴더)<input id="wi-mvq" value="${esc(m.q)}" placeholder="예: card / DC-Seoul/CARD"></label>
        <div class="full wi-btns"><button type="button" class="btn-sm" id="wi-mvall">보이는 ${shown.length}대 모두 고르기</button><button type="button" class="btn-sm" id="wi-mvnone">모두 빼기</button></div>
        <div class="full wi-vmlist">${shown.slice(0, 400).map(v => `<label class="mb-chk"><input type="checkbox" data-wimv="${esc(v.name)}" ${m.pick.has(v.name) ? "checked" : ""}> ${esc(v.name)}
          <small class="muted">${v.power === "on" ? "" : "꺼짐 · "}${v.vcpu} vCPU · ${N(v.mem_gb)} GB · ${N(v.disk_gb, 0)} GB${v.folder ? ` · ${esc(v.folder)}` : ""}</small></label>`).join("") || `<p class="small muted">VM 이 없습니다.</p>`}
          ${shown.length > 400 ? `<p class="small muted">처음 400대만 보입니다 — 찾기로 좁히세요.</p>` : ""}</div></fieldset>
      <label>HA 여유 — 견딜 호스트 장애 수<select name="ha">${[0, 1, 2].map(n => `<option value="${n}" ${n === (m.ha ?? 1) ? "selected" : ""}>${n}대</option>`).join("")}</select></label>
      <label>메모리 사용률 가정(%)<input type="number" name="mu" min="1" max="100" value="${esc(m.mu ?? 80)}"></label>
      <button class="btn-sm solid" type="submit" ${m.busy || !m.pick.size ? "disabled" : ""}>계산</button>
      <p class="small muted">CPU 는 VM 의 지금 사용량(MHz), 메모리는 설정 메모리 × 사용률로 셉니다. vCenter 에는 아무것도 바꾸지 않습니다.</p></form>
      <div class="wi-res">${moveResult()}</div></div>`;
  }
  function moveResult() {
    const m = st.mv;
    if (m.err) return `<div class="empty">${esc(m.err)}</div>`;
    const r = m.r; if (!r) return `<div class="empty">옮길 VM 을 고르고 '계산'을 누르세요.</div>`;
    const sv = r.source.after.verdict, tv = r.target.after.verdict, worst = [sv, tv].includes("bad") ? "bad" : [sv, tv].includes("warn") ? "warn" : "ok";
    const stg = (x, label) => x ? `<b>${label} 스토리지</b><span>${N(x.pct)}% → ${N(x.after_pct)}% <small class="muted">(${x.added_tb >= 0 ? "+" : ""}${N(x.added_tb, 2)} TB)</small></span>` : "";
    return `<div class="wi-verdict ${worst}"><b>${tv === "ok" ? "받을 수 있음" : tv === "warn" ? "받을 수 있지만 빠듯함" : "받을 클러스터 용량 부족"}</b>
        <p>${esc(r.vcenter)} / ${esc(r.source.cluster)} → ${esc(r.dst_vcenter)} / ${esc(r.target.cluster)} — VM ${r.moved.vms}대(켜짐 ${r.moved.powered_on}) · CPU ${N(r.moved.cpu_ghz)} GHz · 메모리 ${N(r.moved.mem_gb)} GB · 디스크 ${N(r.moved.disk_tb, 2)} TB</p>
        ${tv !== "ok" && r.target.hosts_needed != null ? `<p>받는 쪽이 80% 안에 들려면 평균 사양 서버 <b style="display:inline;font-size:inherit">${r.target.hosts_needed}대</b>가 더 필요합니다.</p>` : ""}</div>
      <div class="wi-cmp">${side(`보내는 쪽 — ${esc(r.source.cluster)} (뒤)`, r.source.after)}${side(`받는 쪽 — ${esc(r.target.cluster)} (뒤)`, r.target.after)}</div>
      ${basisLine(r.basis)}
      <div class="wi-box"><h5>확인할 점</h5><ul class="wi-chk">${r.checks.map(c => `<li class="${c.level}">${esc(c.text)}</li>`).join("")}</ul>
        <div class="wi-kv" style="grid-template-columns:max-content minmax(0,1fr)">
          <b>보내는 쪽 사용률</b><span>CPU ${N(r.source.before.cpu.pct_usable)}% → ${N(r.source.after.cpu.pct_usable)}% · 메모리 ${N(r.source.before.mem.pct_usable)}% → ${N(r.source.after.mem.pct_usable)}%</span>
          <b>받는 쪽 사용률</b><span>CPU ${N(r.target.before.cpu.pct_usable)}% → ${N(r.target.after.cpu.pct_usable)}% · 메모리 ${N(r.target.before.mem.pct_usable)}% → ${N(r.target.after.mem.pct_usable)}%</span>
          ${stg(r.source.storage, "보내는 쪽")}${stg(r.target.storage, "받는 쪽")}
          ${r.moved.storage_vmotion_tb ? `<b>스토리지 vMotion</b><span>${N(r.moved.storage_vmotion_tb, 2)} TB</span>` : ""}</div></div>`;
  }

  const basisLine = b => !b ? "" : `<p class="small" style="margin:8px 0">CPU 수요 기준: <b>${b.kind === "p95" ? `VM 별 최근 ${b.days || 14}일 피크(95퍼센타일)` : "VM 의 지금 사용량"}</b>${b.vms ? ` — 이력 있는 VM ${b.vms_with_history || 0}/${b.vms}대` : ""}${b.why ? ` <span class="muted">· ${esc(b.why)}</span>` : ""}</p>`;
  // ------------------------------------------------------------ 2.36.0 DR 사이트 수용
  function drView() {
    const d = st.dr, G = d.groups || [];
    return `<div class="wi-wrap"><form class="wi-form" id="wi-drf">
      <fieldset><legend>복구할 대상</legend>
        ${G.length ? `<div class="full"><b class="small">SRM 보호 그룹</b>${G.map(g => `<label class="mb-chk"><input type="checkbox" data-widr="${esc(g.srm)}|${esc(g.name)}" ${d.pick.has(`${g.srm}|${g.name}`) ? "checked" : ""}> ${esc(g.name)}
          <small class="muted">VM ${g.vms}대 · ${esc(g.status)}${g.protected_site ? ` · ${esc(g.protected_site)}` : ""}</small></label>`).join("")}</div>
          <p class="full small muted">보호 그룹을 고르지 않으면 아래 '원본 클러스터 전체'로 계산합니다.</p>` : `<p class="full small muted">SRM 커넥터가 없어 클러스터 단위로 계산합니다(사이트 전체 장애 가정).</p>`}
        <label class="full">원본 클러스터 전체<select name="src"><option value="">— 고르지 않음 —</option>${clOpt(d.src)}</select></label>
        <label class="mb-chk full"><input type="checkbox" name="include_off" ${d.include_off ? "checked" : ""}> 꺼져 있는 VM 도 복구 때 켠다고 보기</label></fieldset>
      <label>받을(복구 사이트) 클러스터<select name="dst">${clOpt(d.dst)}</select></label>
      <label>HA 여유 — 견딜 호스트 장애 수<select name="ha">${[0, 1, 2].map(n => `<option value="${n}" ${n === (d.ha ?? 1) ? "selected" : ""}>${n}대</option>`).join("")}</select></label>
      <label>메모리 사용률 가정(%)<input type="number" name="mu" min="1" max="100" value="${esc(d.mu ?? 80)}"></label>
      <button class="btn-sm solid" type="submit" ${d.busy ? "disabled" : ""}>계산</button>
      <p class="small muted">보호 VM 의 사양은 보호 사이트 vCenter 인벤토리에서 이름으로 찾습니다. 복구 사이트에서 지금 돌고 있는 VM 은 그대로 둔 채 더합니다.</p></form>
      <div class="wi-res">${drResult()}</div></div>`;
  }
  function drResult() {
    const d = st.dr;
    if (d.err) return `<div class="empty">${esc(d.err)}</div>`;
    const r = d.r; if (!r) return `<div class="empty">복구할 대상과 받을 클러스터를 고르고 '계산'을 누르세요.</div>`;
    const t = r.target, v = t.after.verdict;
    return `<div class="wi-verdict ${v}"><b>${v === "ok" ? "복구 사이트가 버팁니다" : v === "warn" ? "버티지만 빠듯함" : "복구 사이트 용량 부족"}</b>
        <p>${esc(r.source)} → ${esc(r.dst_vcenter)} / ${esc(t.cluster)} — VM ${r.recovered.vms}대 · CPU ${N(r.recovered.cpu_ghz)} GHz · 메모리 ${N(r.recovered.mem_gb)} GB · 디스크 ${N(r.recovered.disk_tb, 2)} TB</p>
        ${r.summary.map(x => `<p>${esc(x)}</p>`).join("")}</div>
      <div class="wi-cmp">${side("복구 사이트 — 지금", t.before)}${side("복구 사이트 — 복구 뒤", t.after)}</div>
      ${basisLine(r.basis)}
      ${r.plan ? `<div class="wi-box"><h5>복구 순서 계획 <small class="muted">고른 순서대로 그룹을 하나씩 복구할 때 — 80% 안 ${r.plan.fit_80}개 · 100% 안 ${r.plan.fit_100}개 그룹</small></h5>
        <table class="dr-t"><thead><tr><th>#</th><th>보호 그룹</th><th class="r">VM</th><th class="r">CPU·메모리 더함</th><th class="r">누적 CPU</th><th class="r">누적 메모리</th><th>판정</th></tr></thead><tbody>
        ${r.plan.rows.map((p, i) => `<tr class="${p.verdict === "bad" ? "bad" : p.verdict === "warn" ? "warn" : ""}"><td>${i + 1}</td><td><b>${esc(p.group)}</b></td><td class="r">${p.vms}</td>
          <td class="r">${N(p.cpu_ghz)} GHz · ${N(p.mem_gb)} GB</td><td class="r ${cls(p.cpu_pct)}">${N(p.cpu_pct)}%</td><td class="r ${cls(p.mem_pct)}">${N(p.mem_pct)}%</td>
          <td><span class="dr-v ${p.verdict}">${VD[p.verdict][0]}</span></td></tr>`).join("")}</tbody></table>
        <p class="small muted">순서는 왼쪽에서 체크한 순서입니다(먼저 고른 그룹이 먼저 복구). 중요 업무 그룹을 먼저 고르세요.</p></div>` : ""}
      ${t.storage ? `<div class="wi-box"><h5>복구 사이트 공유 스토리지</h5><p class="small">${N(t.storage.pct)}% → ${N(t.storage.after_pct)}% (+${N(t.storage.added_tb, 2)} TB) <span class="muted">— ${esc(r.assume.storage)}</span></p></div>` : ""}
      ${r.missing_count ? `<div class="wi-box"><h5>사양을 찾지 못한 보호 VM ${r.missing_count}대</h5><p class="small mono">${r.missing.slice(0, 60).map(esc).join(", ")}${r.missing_count > 60 ? " …" : ""}</p></div>` : ""}
      <p class="small muted">꺼져 있던 VM 은 복구 때 켜진다고 보고 CPU 를 vCPU × 코어 속도 × ${r.assume.off_vm_cpu_pct}% 로 셉니다. 메모리 = 설정 × ${r.assume.mem_util_pct}%.</p>`;
  }

  // ------------------------------------------------------------ 2.36.0 고객 제출용 보고서 묶음
  function rbView() {
    const b = st.rb;
    return `<div class="wi-box wi-rb"><h5>고객 제출용 보고서 묶음 <small class="muted">용량 현황 · 적정화 · 가정 분석(저장한 가정) · 권장 구성 판독 · 보안 판독을 한 파일로</small></h5>
      <form id="wi-rbf" class="wi-form" style="border:0;padding:0">
        <label>고객사 이름(표지)<input name="customer" maxlength="80" value="${esc(b.customer)}" placeholder="비우면 이름 없이"></label>
        <fieldset><legend>넣을 가정 <small>${st.pick.size}개 선택(최대 10)</small></legend>
          ${st.sc.length ? st.sc.map(x => `<label class="mb-chk full"><input type="checkbox" data-wipick="${x.id}" ${st.pick.has(x.id) ? "checked" : ""}> ${esc(x.name)} <small class="muted">${esc(x.cluster)} · ${esc(brief(x.inputs))}</small></label>`).join("")
            : `<p class="full small muted">저장한 가정이 없습니다 — '한 클러스터'에서 계산 뒤 '이 가정 저장'.</p>`}</fieldset>
        <div class="wi-btns">${[["pdf", "PDF"], ["docx", "Word(.docx)"], ["html", "HTML(인쇄용)"]].map(([k, l]) => `<button type="button" class="btn-sm ${k === "pdf" ? "solid" : ""}" data-wirb="${k}" ${b.busy ? "disabled" : ""}>${b.busy === k ? "만드는 중…" : l}</button>`).join("")}</div>
        <p class="small muted">보고서에는 vCenter·클러스터·호스트 이름이 들어갑니다 — 고객에게 보내기 전 공개 범위를 확인하세요. 가정은 만들 때의 지금 값으로 다시 계산합니다.</p></form></div>`;
  }

  // 받을 클러스터 기본값 — 같은 vCenter 의 다른 클러스터 먼저
  const pickDst = src => { const vc = src.split("|")[0], k = c => `${c.vcenter}|${c.cluster}`;
    const o = st.cl.find(c => c.vcenter === vc && k(c) !== src) || st.cl.find(c => k(c) !== src); return o ? k(o) : ""; };
  async function runMove(root) {
    const m = st.mv; if (!m.pick.size) return;
    const [vc, ...cl] = m.src.split("|"), [dvc, ...dcl] = m.dst.split("|");
    m.busy = true; draw(root);
    try { m.r = await A.api("POST", "/api/capacity/whatif/move", {vcenter: vc, cluster: cl.join("|"), dst_vcenter: dvc, dst_cluster: dcl.join("|"), vms: [...m.pick], ha_failures: m.ha ?? 1, vm_mem_util_pct: m.mu ?? 80}, {background: true}); m.err = ""; }
    catch (e) { m.err = String(e.message || e); m.r = null; }
    m.busy = false; draw(root);
  }
  async function loadVms(root) {
    const m = st.mv; if (!m.src) return;
    const [vc, ...cl] = m.src.split("|");
    try { m.vms = (await A.api("GET", `/api/capacity/whatif/vms?vcenter=${encodeURIComponent(vc)}&cluster=${encodeURIComponent(cl.join("|"))}`, undefined, {background: true})).vms; } catch (e) { m.vms = []; m.err = String(e.message || e); }
    m.pick = new Set(); m.r = null; draw(root);
  }
  async function runDr(root) {
    const d = st.dr, [dvc, ...dcl] = d.dst.split("|");
    const body = {dst_vcenter: dvc, dst_cluster: dcl.join("|"), ha_failures: d.ha ?? 1, vm_mem_util_pct: d.mu ?? 80, include_off: d.include_off};
    if (d.pick.size) body.groups = [...d.pick].map(x => { const [srm, ...n] = x.split("|"); return {srm, name: n.join("|")}; });
    else if (d.src) { const [svc, ...scl] = d.src.split("|"); Object.assign(body, {src_vcenter: svc, src_cluster: scl.join("|")}); }
    else { d.err = "보호 그룹이나 원본 클러스터를 고르세요"; d.r = null; draw(root); return; }
    d.busy = true; draw(root);
    try { d.r = await A.api("POST", "/api/capacity/whatif/dr", body, {background: true}); d.err = ""; } catch (e) { d.err = String(e.message || e); d.r = null; }
    d.busy = false; draw(root);
  }
  async function bundle(root, fmt) {
    const b = st.rb; b.busy = fmt; draw(root);
    try {
      const q = new URLSearchParams({format: fmt, scenarios: [...st.pick].slice(0, 10).join(","), customer: b.customer});
      const r = await fetch(`/api/capacity/report-bundle?${q}`, {headers: {"X-Requested-With": "XMLHttpRequest"}});
      if (!r.ok) { let t = await r.text(); try { t = JSON.parse(t).detail || t; } catch {} throw new Error(`${r.status} ${t}`); }
      const cd = r.headers.get("Content-Disposition") || "", nm = (cd.match(/filename="([^"]+)"/) || [])[1] || `vcf-aiops-report.${fmt}`;
      A.download(nm, await r.blob()); A.ok("보고서를 만들었습니다", nm);
    } catch (e) { A.fail("보고서 만들기 실패", e); }
    b.busy = ""; draw(root);
  }

  async function run(root) {
    const f = st.f;
    const my = ++st.seq; st.busy = true;
    try {
      const r = await A.api("POST", "/api/capacity/whatif", payload(f), {background: true});
      if (my !== st.seq) return; st.r = r; st.err = "";
    } catch (e) { if (my !== st.seq) return; st.err = String(e.message || e); st.r = null; }
    st.busy = false;
    const box = $("#wi-res", root); if (box) box.innerHTML = result(); const b = $("#wi-form button[type=submit]", root); if (b) b.disabled = false;
  }

  function read(form) {
    const prevKey = st.f.key;
    for (const el of form.elements) if (el.name && el.name !== "rm" && !CHK.includes(el.name)) st.f[el.name] = el.value;
    st.f.remove_names = st.f.key === prevKey ? [...form.querySelectorAll('input[name="rm"]:checked')].map(x => x.value) : [];
    for (const k of CHK) if (form.elements[k]) st.f[k] = !!form.elements[k].checked;
    try { localStorage.setItem(KEY, JSON.stringify(st.f)); } catch { /* 무시 */ }
  }

  async function scn() {
    try { st.sc = (await A.api("GET", "/api/capacity/whatif/scenarios", undefined, {background: true})).scenarios; } catch { st.sc = st.sc || []; }
  }

  async function specs() {
    try { st.sp = await A.api("GET", "/api/capacity/specs", undefined, {background: true}); } catch { st.sp = st.sp || {uploaded: [], bmc: [], vcenter: [], scripts: []}; }
  }

  async function mount(root) {
    if (!root) return;
    if (!root.dataset.wired) {
      root.dataset.wired = "1";
      root.addEventListener("submit", e => { if (e.target.id !== "wi-form") return; e.preventDefault(); read(e.target); run(root); });
      root.addEventListener("submit", e => {
        const f = e.target;
        if (f.id === "wi-mvf") { e.preventDefault(); st.mv.ha = +f.elements.ha.value; st.mv.mu = +f.elements.mu.value || 80; runMove(root); }
        if (f.id === "wi-drf") { e.preventDefault(); Object.assign(st.dr, {src: f.elements.src.value, dst: f.elements.dst.value, ha: +f.elements.ha.value, mu: +f.elements.mu.value || 80, include_off: f.elements.include_off.checked}); runDr(root); }
        if (f.id === "wi-rbf") e.preventDefault();
      });
      root.addEventListener("input", e => {
        if (e.target.id !== "wi-mvq") return;
        st.mv.q = e.target.value; clearTimeout(st.mv._t);
        st.mv._t = setTimeout(() => { draw(root); const q = $("#wi-mvq", root); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 250);
      });
      root.addEventListener("change", e => {
        if (e.target.id === "wi-file") { const fl = e.target.files[0]; if (fl) fl.text().then(t => { const ta = $("#wi-up textarea", root); if (ta) ta.value = t.trim(); }); return; }
        const mvf = e.target.closest("#wi-mvf");
        if (mvf) {
          if (e.target.name === "src") { st.mv.src = e.target.value; if (st.mv.dst === st.mv.src) st.mv.dst = ""; if (!st.mv.dst) st.mv.dst = pickDst(st.mv.src); loadVms(root); }
          if (e.target.name === "dst") st.mv.dst = e.target.value;
          return;
        }
        const drf = e.target.closest("#wi-drf");
        if (drf) { if (e.target.name === "src" || e.target.name === "dst") st.dr[e.target.name] = e.target.value; if (e.target.name === "include_off") st.dr.include_off = e.target.checked; return; }
        if (e.target.closest("#wi-rbf")) { if (e.target.name === "customer") st.rb.customer = e.target.value; return; }
        const f = e.target.closest("#wi-form"); if (!f) return; read(f);
        if (e.target.name === "key") { st.r = null; draw(root); run(root); } else if (e.target.name === "spec") { draw(root); run(root); }
      });
      root.addEventListener("click", async e => {
        const t = e.target;
        try {
          const md = t.closest("[data-wimode]");
          if (md) {
            st.mode = md.dataset.wimode;
            if (st.mode === "move" && !st.mv.src) { st.mv.src = st.f.key || `${st.cl[0].vcenter}|${st.cl[0].cluster}`; st.mv.dst = pickDst(st.mv.src); draw(root); await loadVms(root); return; }
            if (st.mode === "dr" && st.dr.groups === null) {
              try { st.dr.groups = (await A.api("GET", "/api/capacity/whatif/dr-sources", undefined, {background: true})).groups; } catch { st.dr.groups = []; }
              if (!st.dr.dst) st.dr.dst = `${st.cl[st.cl.length - 1].vcenter}|${st.cl[st.cl.length - 1].cluster}`;
            }
            draw(root); return;
          }
          if (t.id === "wi-mvall") { const q = st.mv.q.toLowerCase(); st.mv.vms.filter(v => !q || (v.name + " " + v.folder).toLowerCase().includes(q)).forEach(v => st.mv.pick.add(v.name)); draw(root); return; }
          if (t.id === "wi-mvnone") { st.mv.pick = new Set(); draw(root); return; }
          if (t.dataset.wimv !== undefined) { t.checked ? st.mv.pick.add(t.dataset.wimv) : st.mv.pick.delete(t.dataset.wimv); const lg = t.closest("fieldset").querySelector("legend small"); if (lg) { const tot = st.mv.vms.filter(v => st.mv.pick.has(v.name)); lg.textContent = `${st.mv.pick.size}대 · ${N(tot.reduce((a, v) => a + v.vcpu, 0), 0)} vCPU · ${N(tot.reduce((a, v) => a + v.mem_gb, 0), 0)} GB`; } const sb = $("#wi-mvf button[type=submit]", root); if (sb) sb.disabled = !st.mv.pick.size; return; }
          if (t.dataset.widr !== undefined) { t.checked ? st.dr.pick.add(t.dataset.widr) : st.dr.pick.delete(t.dataset.widr); return; }
          if (t.dataset.wirb) { const f = $("#wi-rbf", root); if (f) st.rb.customer = f.elements.customer.value; await bundle(root, t.dataset.wirb); return; }
          if (t.id === "wi-exp") { const md = report(); if (md) A.download(`whatif-${String(st.r.cluster).replace(/[^\w.-]+/g, "_")}-${new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 10)}.md`, new Blob([md], {type: "text/markdown"})); return; }
          if (t.id === "wi-fail") {
            read($("#wi-form", root)); const cur = (st.cl || []).find(c => `${c.vcenter}|${c.cluster}` === st.f.key);
            const big = cur && [...cur.host_list].sort((a, b) => b.mem_gb - a.mem_gb || b.cores - a.cores)[0];
            if (!big) return;
            Object.assign(st.f, {add_hosts: 0, remove_hosts: 0, add_vms: 0, remove_vms: 0, remove_names: [big.name], consume_ha: true}); draw(root); run(root); return;
          }
          if (t.id === "wi-save") {
            const v = await A.modal({title: "가정 저장", fields: [{id: "name", label: "이름", placeholder: "예: R760 2대 증설안"}], ok: "저장"});
            if (!v || !v.name) return;
            await A.api("POST", "/api/capacity/whatif/scenarios", {...payload(st.f), name: v.name}); A.ok("저장했습니다", v.name); await scn(); $("#wi-saved", root).innerHTML = saved(); return;
          }
          if (t.dataset.wipick) { const id = +t.dataset.wipick; t.checked ? st.pick.add(id) : st.pick.delete(id); if (st.pick.size > (st.mode === "rb" ? 10 : 4)) { st.pick.delete(id); t.checked = false; A.fail(st.mode === "rb" ? "보고서" : "비교", st.mode === "rb" ? "보고서에는 10개까지 넣습니다." : "한 번에 4개까지 비교합니다."); }
            if (st.mode === "rb") { const lg = t.closest("fieldset") && t.closest("fieldset").querySelector("legend small"); if (lg) lg.textContent = `${st.pick.size}개 선택(최대 10)`; } const b = $("#wi-cmp", root); if (b) { b.disabled = st.pick.size < 2; b.textContent = `고른 ${st.pick.size}개 비교`; } return; }
          if (t.id === "wi-cmp") {
            t.disabled = true;
            st.cmp = await Promise.all(st.sc.filter(x => st.pick.has(x.id)).reverse().map(async x => {
              try { return {name: x.name, cluster: x.cluster, r: await A.api("POST", "/api/capacity/whatif", {...x.inputs, vcenter: x.vcenter, cluster: x.cluster}, {background: true})}; }
              catch (err) { return {name: x.name, cluster: x.cluster, err: String(err.message || err)}; }
            }));
            $("#wi-saved", root).innerHTML = saved(); return;
          }
          if (t.dataset.wiload) {
            const x = st.sc.find(v => v.id === +t.dataset.wiload); if (!x) return;
            const i = x.inputs;
            Object.assign(st.f, {key: `${x.vcenter}|${x.cluster}`, ha_failures: i.ha_failures ?? 1, add_vms: i.add_vms || 0, remove_vms: i.remove_vms || 0, vm_vcpu: i.vm_vcpu || 4, vm_mem_gb: i.vm_mem_gb || 16, vm_disk_gb: i.vm_disk_gb ?? 100,
              vm_cpu_util_pct: i.vm_cpu_util_pct || 25, vm_mem_util_pct: i.vm_mem_util_pct || 80, add_hosts: i.add_hosts || 0, remove_hosts: i.remove_hosts || 0, remove_names: i.remove_names || [], consume_ha: !!i.consume_ha,
              basis: i.basis === "p95" ? `p95:${i.basis_days || 14}` : "now", spec: i.host_cores ? "manual" : "", host_cores: i.host_cores || "", host_core_ghz: i.host_core_ghz || "", host_mem_gb: i.host_mem_gb || "", host_sockets: i.host_sockets || "", host_flash_tb: i.host_flash_tb || "", host_cpu_model: i.host_cpu_model || "",
              vsan_policy: i.vsan_policy ?? "", vsan_reserve_pct: i.vsan_reserve_pct ?? 10, vsan_host_reserve: i.vsan_host_reserve ?? "", vsan_dr: i.vsan_dr ?? "",
              growth_pct_year: i.growth_pct_year ?? "", apply_rightsizing: !!i.apply_rightsizing, perf_factor: i.perf_factor || 1});
            draw(root); run(root); return;
          }
          if (t.dataset.wiscdel) { if (!await A.confirm("가정 삭제", "저장한 가정을 지웁니다.", true)) return; await A.api("DELETE", `/api/capacity/whatif/scenarios/${t.dataset.wiscdel}`); st.pick.delete(+t.dataset.wiscdel); st.cmp = null; await scn(); $("#wi-saved", root).innerHTML = saved(); return; }
          if (t.id === "wi-mgr") { read($("#wi-form", root)); st.mgr = !st.mgr; draw(root); return; }
          if (t.id === "wi-one") { read($("#wi-form", root)); Object.assign(st.f, {add_hosts: 1, remove_hosts: 0, add_vms: 0, remove_vms: 0, remove_names: [], consume_ha: false}); draw(root); run(root); return; }
          if (t.dataset.wiuse) { read($("#wi-form", root)); st.f.spec = t.dataset.wiuse; if (!+st.f.add_hosts) st.f.add_hosts = 1; draw(root); run(root); return; }
          if (t.dataset.widel) { if (!await A.confirm("사양 삭제", "올린 서버 사양을 지웁니다.", true)) return; await A.api("DELETE", `/api/capacity/specs/${t.dataset.widel}`); await specs(); if (!specOf(st.f.spec) && st.f.spec !== "manual") st.f.spec = ""; draw(root); }
        } catch (err) { A.fail("실패", err); }
      });
      root.addEventListener("submit", async e => {
        if (e.target.id !== "wi-up") return; e.preventDefault();
        try {
          const o = await A.api("POST", "/api/capacity/specs", {name: e.target.elements.name.value, spec: e.target.elements.spec.value});
          A.ok("사양을 올렸습니다", o.name); await specs(); read($("#wi-form", root)); st.f.spec = o.id; if (!+st.f.add_hosts) st.f.add_hosts = 1; draw(root); run(root);
        } catch (err) { A.fail("올리기 실패", err); }
      });
    }
    draw(root);
    if (st.cl === null) {
      try { st.cl = (await A.api("GET", "/api/capacity/whatif", undefined, {background: true})).clusters; } catch (e) { st.cl = []; st.err = String(e.message || e); }
      if (st.cl.length && !st.cl.some(c => `${c.vcenter}|${c.cluster}` === st.f.key)) st.f.key = `${st.cl[0].vcenter}|${st.cl[0].cluster}`;
      await Promise.all([specs(), scn()]);
      if (st.f.spec && st.f.spec !== "manual" && !specOf(st.f.spec)) st.f.spec = "";
      draw(root);
      if (st.cl.length) run(root);
    }
  }
  window.AIOPS_WHATIF = {mount};
})();
