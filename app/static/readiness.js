/* 하드웨어 준비도(VCF-R, 2.14.0) — BMC(Redfish 읽기 전용) 스캔 → VCF 9.x CPU·메모리·vSAN ESA·NIC/ToR·부팅/TPM·BMC 보안·BIOS 기준선 판정, 플릿·패브릭·편차·보고서 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {tab: "scan", ov: null, scan: null, sid: "", host: null, sel: new Set(), filter: "", vf: "", obf: false, poll: null, adhoc: {targets: "", username: "", port: ""}};
  const ST = {pass: ["통과", "ok"], fail: ["실패", "bad"], warn: ["주의", "warn"], unknown: ["확인 불가", "unk"], info: ["참고", "inf"], drift: ["편차", "warn"]};
  const V = {ready: ["준비됨", "ok"], actions: ["조치 후 가능", "warn"], not_ready: ["불가", "bad"], unknown: ["확인 필요", "unk"]};
  const AREA = {cpu: "CPU", memory: "메모리", storage: "스토리지", vsan: "vSAN", network: "네트워크", platform: "플랫폼", bios: "BIOS", events: "이벤트"};
  const VS = {esa_ready: "ESA 준비", esa_actions: "ESA 조치 필요", esa_network: "ESA 네트워크 부족", osa_only: "OSA 만", not_supported: "ESA 불가(RAID 뒤 NVMe)", no_vsan: "vSAN 장치 없음"};
  const fmt = ts => ts ? new Date(ts * 1000).toLocaleString([], {year: "2-digit", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"}) : "-";
  const b = (s, lab) => { const x = ST[s] || V[s] || [s, "unk"]; return `<span class="rd-b ${x[1]}">${esc(lab || x[0])}</span>`; };
  const n = (x, d = 0) => x === null || x === undefined || x === "" ? "—" : Number(x).toLocaleString(undefined, {maximumFractionDigits: d});

  async function loadOv() { try { st.ov = await A.api("GET", "/api/readiness/overview", undefined, {background: true}); } catch (e) { A.fail("준비도 불러오기 실패", e); } }
  async function loadScan(sid) {
    if (!sid) { st.scan = null; return; }
    try { st.scan = await A.api("GET", `/api/readiness/scans/${encodeURIComponent(sid)}`, undefined, {background: true}); st.sid = sid; } catch (e) { A.fail("스캔 불러오기 실패", e); }
  }

  // ------------------------------------------------------------------ 스캔 탭
  function scanTab() {
    const o = st.ov || {}, tg = o.targets || [], run = (o.running || [])[0];
    const rows = tg.map(t => `<tr><td><input type="checkbox" data-rdc="${esc(t.name)}" ${st.sel.has(t.name) ? "checked" : ""}></td><td><b>${esc(t.name)}</b><div class="small muted">${esc(t.host)}${t.esxi_host ? " → " + esc(t.esxi_host) : ""}</div></td>
      <td>${esc(t.vendor || "")}</td><td>${t.verdict ? b(t.verdict) : (t.error ? b("fail", "실패") : '<span class="muted small">미스캔</span>')}</td><td class="small">${fmt(t.last_scan)}</td></tr>`).join("");
    return `<div class="rd-two"><div class="rd-card"><h4>등록된 BMC(Redfish 커넥터) <small>저장된 읽기 전용 계정 사용</small></h4>
        ${tg.length ? `<table class="rd-t"><thead><tr><th><input type="checkbox" id="rd-all"></th><th>커넥터</th><th>벤더</th><th>최근 판정</th><th>최근 스캔</th></tr></thead><tbody>${rows}</tbody></table>`
          : `<p class="muted">Redfish(BMC) 커넥터가 없습니다 — 오른쪽에서 일회성 대상으로 스캔하거나 '수집 연동 › 커넥터'에서 BMC 를 등록하세요.</p>`}</div>
      <div class="rd-card"><h4>일회성 대상 <small>계정은 이 스캔에만 쓰고 저장하지 않음</small></h4>
        <label class="rd-f wide"><span>BMC 주소(IP·호스트·범위 10.0.0.1-20·CIDR /24 이하, 쉼표)</span><input id="rd-tg" value="${esc(st.adhoc.targets)}" placeholder="10.10.0.21-24, bmc-esx05.lab"></label>
        <label class="rd-f"><span>읽기 전용 계정</span><input id="rd-u" value="${esc(st.adhoc.username)}" autocomplete="off"></label>
        <label class="rd-f"><span>비밀번호</span><input id="rd-p" type="password" autocomplete="new-password"></label>
        <label class="rd-f"><span>포트(기본 443)</span><input id="rd-port" value="${esc(st.adhoc.port)}" style="width:90px"></label>
        <label class="rd-f"><span>TLS 인증서 검증</span><select id="rd-tls"><option value="0">끔(자체 서명 BMC)</option><option value="1">켬</option></select></label>
        <p class="small muted">BMC 에는 GET 과 세션 생성·종료만 보냅니다(전원·리셋·펌웨어·BIOS·계정 변경 요청은 전송 계층에서 차단).</p></div></div>
      <div class="rd-tools"><input id="rd-label" placeholder="스캔 이름(선택)"><select id="rd-prof"><option value="">프로파일: 설정값</option><option value="full">전체(펌웨어 목록 포함)</option><option value="lean">빠르게</option></select>
        <button class="btn-sm solid" id="rd-start" data-perm="operate" ${run ? "disabled" : ""}>스캔 시작</button>${run ? `<button class="btn-sm" id="rd-cancel" data-perm="operate">취소</button>` : ""}</div>
      ${run ? progress(run) : ""}
      <div class="rd-card"><h4>최근 스캔</h4>${scanList(o.scans || [])}</div>`;
  }
  function progress(j) {
    const hs = Object.entries(j.hosts || {});
    const pct = Math.round((j.done + j.failed) / Math.max(1, j.total) * 100);
    return `<div class="rd-card"><h4>진행 중 ${esc(j.id)} <small>${j.done + j.failed}/${j.total} · 실패 ${j.failed}</small></h4><div class="rd-prog"><i style="width:${pct}%"></i></div>
      <div class="rd-hgrid">${hs.map(([t, h]) => `<div class="rd-hp ${h.stage === "완료" ? (V[h.verdict] || [0, "unk"])[1] : h.stage === "실패" ? "bad" : ""}" title="${esc(h.error || "")}"><b>${esc(h.label || t)}</b><small>${esc(h.stage)}${h.secs ? " · " + h.secs + "s" : ""}${h.model ? " · " + esc(h.model) : ""}</small></div>`).join("")}</div></div>`;
  }
  function scanList(sc) {
    if (!sc.length) return `<p class="muted">아직 스캔이 없습니다.</p>`;
    return `<table class="rd-t"><thead><tr><th>스캔</th><th>시작</th><th>대상</th><th>상태</th><th>준비됨</th><th>조치 후</th><th>불가</th><th></th></tr></thead><tbody>${sc.map(s => {
      const v = s.verdicts || {};
      return `<tr><td><a href="#" data-rdo="${esc(s.id)}">${esc(s.id)}</a><div class="small muted">${esc(s.label || "")} ${esc(s.by || "")}</div></td><td>${fmt(s.created)}</td><td>${s.targets}</td><td>${esc({running: "진행 중", done: "완료", cancelled: "취소", error: "오류"}[s.status] || s.status)}</td>
        <td>${v.ready || 0}</td><td>${v.actions || 0}</td><td>${v.not_ready || 0}</td><td><button class="btn-sm" data-rdo="${esc(s.id)}">결과</button></td></tr>`; }).join("")}</tbody></table>`;
  }

  // ------------------------------------------------------------------ 결과(플릿) 탭
  function fleetTab() {
    const s = st.scan; if (!s) return `<p class="muted">스캔을 고르세요(스캔 탭 › 최근 스캔).</p>`;
    const f = s.fleet || {}, t = f.totals || {}, v = f.verdicts || {};
    const tiles = [["호스트", `${t.hosts || 0}${t.failed ? ` <small class="cc-na">+실패 ${t.failed}</small>` : ""}`], ["준비됨", v.ready || 0, "ok"], ["조치 후 가능", v.actions || 0, "warn"], ["불가", v.not_ready || 0, "bad"],
      ["소켓 · 코어", `${n(t.sockets)} · ${n(t.cores)}`], ["메모리", `${n((t.mem_gib || 0) / 1024, 2)} TB`], ["직결 NVMe", `${n(t.nvme_tb, 2)} TB`], ["소비 전력", `${n((t.power_w || 0) / 1000, 2)} kW`],
      ["ToR 이중 연결", f.tor && f.tor.redundancy_pct != null ? f.tor.redundancy_pct + "%" : "LLDP 없음"], ["BMC 보안 준수", f.security && f.security.compliance != null ? f.security.compliance + "%" : "—"]];
    const nodes = f.nodes || {};
    const q = st.filter.toLowerCase();
    const hs = (s.hosts || []).filter(h => (!st.vf || h.verdict === st.vf || (st.vf === "fail" && !h.ok)) && (!q || JSON.stringify([h.label, h.summary && h.summary.model, h.esxi]).toLowerCase().includes(q)));
    const cell = (h, a) => h.areas ? b(h.areas[a]) : "";
    return `<div class="rd-tools"><select id="rd-scan">${(st.ov && st.ov.scans || []).map(x => `<option value="${esc(x.id)}" ${x.id === s.id ? "selected" : ""}>${esc(x.id)} ${esc(x.label || "")}</option>`).join("")}</select>
        <span class="small muted">${fmt(s.created)} · ${esc(s.by || "")} · ${esc({running: "진행 중", done: "완료", cancelled: "취소", error: "오류"}[s.status] || s.status)}</span>
        <label class="small"><input type="checkbox" id="rd-obf" ${st.obf ? "checked" : ""}> 가명화(공유용)</label>
        ${["html", "xlsx", "zip", "json"].map(k => `<button class="btn-sm" data-rdx="${k}">${{html: "HTML 보고서", xlsx: "Excel", zip: "CSV·전체 묶음", json: "JSON"}[k]}</button>`).join("")}</div>
      <div class="rd-tiles">${tiles.map(([a, x, c]) => `<div class="rd-tile ${c || ""}"><small>${a}</small><b>${x}</b></div>`).join("")}</div>
      <p class="small">VCF 배포 노드 수(조치 후 가능 포함 ${nodes.count || 0}대): Simple vSAN 3대 ${nodes.simple_vsan ? b("pass", "충족") : b("fail", "미충족")} · HA 4대 ${nodes.ha ? b("pass", "충족") : b("fail", "미충족")}
        <a href="${esc(nodes.doc || "#")}" target="_blank" rel="noopener noreferrer" class="small">근거</a></p>
      <div class="rd-dist">${dist("판정", v, V)}${dist("vSAN", f.vsan || {}, Object.fromEntries(Object.entries(VS).map(([k, l]) => [k, [l, k.startsWith("esa_ready") ? "ok" : k === "osa_only" || k === "esa_actions" ? "warn" : k === "no_vsan" ? "unk" : "bad"]])))}
        ${dist("CPU 등급", f.cpu_tiers || {}, null)}</div>
      <div class="rd-tools"><input id="rd-f" placeholder="호스트·모델·ESXi 검색" value="${esc(st.filter)}"><select id="rd-vf"><option value="">전체 판정</option>${Object.entries(V).map(([k, x]) => `<option value="${k}" ${st.vf === k ? "selected" : ""}>${x[0]}</option>`).join("")}<option value="fail" ${st.vf === "fail" ? "selected" : ""}>스캔 실패</option></select></div>
      <div class="rd-scroll"><table class="rd-t rd-mx"><thead><tr><th>호스트</th><th>판정</th><th>모델</th><th>CPU</th>${Object.values(AREA).map(a => `<th>${a}</th>`).join("")}<th>vSAN 판정</th><th>NIC</th><th>BIOS %</th><th>BMC 보안</th></tr></thead><tbody>
        ${hs.map(h => h.ok ? `<tr data-rdh="${esc(h.target)}" class="rd-click"><td><b>${esc(h.label)}</b>${h.esxi ? `<div class="small muted">ESXi ${esc(h.esxi.esxi)}${h.esxi.cluster ? " · " + esc(h.esxi.cluster) : ""}</div>` : ""}</td>
          <td>${b(h.verdict)}</td><td class="small">${esc((h.summary || {}).vendor || "")} ${esc((h.summary || {}).model || "")}</td><td class="small">${esc(((h.summary || {}).cpu || {}).label || "")}<div class="muted">${esc(((h.summary || {}).cpu || {}).family || "")}</div></td>
          ${Object.keys(AREA).map(a => `<td>${cell(h, a)}</td>`).join("")}<td class="small">${esc(VS[((h.summary || {}).storage || {}).verdict] || "")}</td>
          <td class="small">${n(((h.summary || {}).network || {}).max_up_gbps)}Gb</td><td>${n((h.bios || {}).compliance)}</td><td class="small">${esc((h.security || {}).posture || "")} ${(h.security || {}).compliance != null ? h.security.compliance + "%" : ""}</td></tr>`
          : `<tr><td><b>${esc(h.label)}</b></td><td>${b("fail", "스캔 실패")}</td><td colspan="14" class="small">${esc(h.error || "")}</td></tr>`).join("")}</tbody></table></div>`;
  }
  function dist(title, obj, map) {
    const tot = Object.values(obj).reduce((a, x) => a + x, 0) || 1;
    return `<div class="rd-card rd-db"><h5>${esc(title)}</h5>${Object.entries(obj).map(([k, x]) => `<div class="rd-bar"><span>${esc(map && map[k] ? map[k][0] : k || "-")}</span><i class="${map && map[k] ? map[k][1] : "inf"}" style="width:${(x / tot * 100).toFixed(1)}%"></i><b>${x}</b></div>`).join("") || '<p class="muted small">없음</p>'}</div>`;
  }

  // ------------------------------------------------------------------ 패브릭·편차·보안 탭
  function fabricTab() {
    const s = st.scan; if (!s || !s.fleet) return `<p class="muted">스캔을 고르세요.</p>`;
    const t = s.fleet.tor || {}, sw = t.switches || [], hosts = t.hosts || [];
    if (!sw.length) return `<p class="muted">LLDP 이웃 정보가 없습니다 — 스위치의 LLDP 송신과 BMC 의 LLDP 지원(Redfish Port.Ethernet.LLDPReceive·iDRAC DellSwitchConnections)을 확인하세요.</p>`;
    const W = Math.max(720, Math.max(sw.length, hosts.length) * 120), H = 260;
    const pos = (i, k) => k <= 1 ? W / 2 : 70 + i * ((W - 140) / (k - 1));
    const sx = i => pos(i, sw.length), hx = i => pos(i, hosts.length);
    const si = Object.fromEntries(sw.map((x, i) => [x.name, i]));
    const pairOf = {}; (t.pairs || []).forEach((p, i) => { pairOf[p.a] = i; pairOf[p.b] = i; });
    const lines = hosts.flatMap((h, i) => Object.keys(h.switches).filter(k => k in si).map(k => `<line x1="${hx(i)}" y1="200" x2="${sx(si[k])}" y2="56" class="rd-ln ${h.state}"/>`)).join("");
    const swn = sw.map((x, i) => `<g><rect x="${sx(i) - 52}" y="24" width="104" height="32" rx="4" class="rd-sw p${(pairOf[x.name] ?? 9) % 6}"/><text x="${sx(i)}" y="44" text-anchor="middle"><title>${esc(x.name)}</title>${esc(x.name.length > 15 ? x.name.slice(0, 14) + "…" : x.name)}</text></g>`).join("");
    const hn = hosts.map((h, i) => `<g><rect x="${hx(i) - 50}" y="200" width="100" height="30" rx="4" class="rd-hn ${h.state}${h.miscabled ? " mis" : ""}"/><text x="${hx(i)}" y="219" text-anchor="middle"><title>${esc(h.host)}</title>${esc(h.host.length > 14 ? h.host.slice(0, 13) + "…" : h.host)}</text></g>`).join("");
    return `<div class="rd-card"><h4>ToR 패브릭 <small>리프 쌍 ${(t.pairs || []).length}개 · 이중 연결 ${t.redundancy_pct ?? "—"}% · 실선=이중, 주황=단일, 빨강 테두리=한 스위치에 여러 포트(오결선 의심)</small></h4>
        <div class="rd-fab"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${lines}${swn}${hn}</svg></div></div>
      <div class="rd-card"><h4>리프 쌍</h4><table class="rd-t"><thead><tr><th>리프 A</th><th>리프 B</th><th>이중 연결</th><th>A 에만</th><th>B 에만</th></tr></thead><tbody>
        ${(t.pairs || []).map(p => `<tr><td>${esc(p.a)}</td><td>${esc(p.b)}</td><td>${p.dual.map(esc).join(", ")}</td><td class="cc-na">${p.only_a.map(esc).join(", ")}</td><td class="cc-na">${p.only_b.map(esc).join(", ")}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">리프 쌍을 찾지 못함(호스트 2대 이상이 같은 두 스위치에 연결되어야 쌍으로 인식)</td></tr>`}</tbody></table></div>
      <div class="rd-card"><h4>호스트별 연결</h4><table class="rd-t"><thead><tr><th>호스트</th><th>스위치(포트 수)</th><th>상태</th></tr></thead><tbody>
        ${hosts.map(h => `<tr><td>${esc(h.host)}</td><td>${Object.entries(h.switches).map(([k, v]) => `${esc(k)}×${v}`).join(", ") || "—"}</td><td>${h.state === "dual" ? b("pass", "이중") : h.state === "single" ? b("warn", h.miscabled ? "단일(오결선 의심)" : "단일") : b("unknown", "LLDP 없음")}</td></tr>`).join("")}</tbody></table></div>
      <div class="rd-card"><h4>포트 연결</h4><div class="rd-scroll"><table class="rd-t"><thead><tr><th>호스트</th><th>NIC</th><th>속도</th><th>스위치</th><th>포트</th><th>관리 IP</th></tr></thead><tbody>
        ${(t.links || []).map(l => `<tr><td>${esc(l.host)}</td><td>${esc(l.nic)}</td><td>${n(l.speed)}Gb</td><td>${esc(l.switch)}</td><td>${esc(l.port || "")}</td><td>${esc(l.mgmt_ip || "")}</td></tr>`).join("")}</tbody></table></div></div>`;
  }
  function driftTab() {
    const s = st.scan; if (!s || !s.fleet) return `<p class="muted">스캔을 고르세요.</p>`;
    const d = s.fleet.drift || [];
    return `<div class="rd-card"><h4>같은 모델 간 편차 <small>BIOS·BMC·NIC 펌웨어 버전, BIOS 설정 값 — 클러스터 안 호스트는 같게 맞추는 것이 vLCM 이미지·동작 일관성에 유리</small></h4>
      ${d.length ? `<table class="rd-t"><thead><tr><th>모델</th><th>항목</th><th>값 → 호스트</th></tr></thead><tbody>${d.map(x => `<tr><td>${esc(x.model)}</td><td>${esc(x.item)}</td><td>${x.values.map(v => `<div><b>${esc(String(v.value))}</b>: ${v.hosts.map(esc).join(", ")}</div>`).join("")}</td></tr>`).join("")}</tbody></table>` : `<p class="muted">편차 없음(같은 모델 2대 이상일 때 비교)</p>`}</div>`;
  }
  function secTab() {
    const s = st.scan; if (!s || !s.fleet) return `<p class="muted">스캔을 고르세요.</p>`;
    const f = s.fleet.security || {};
    const scg = ["tls", "certificates", "ssh", "security", "authentication", "time", "log", "secureboot"];
    return `<div class="rd-card"><h4>BMC 보안 <small>VCF 9 SCG 하드웨어 관리 항목 + CISA/NSA BMC 하드닝 권고 — 플릿 준수 ${f.compliance ?? "—"}%</small></h4>
      <h5>가장 많이 실패한 항목</h5><table class="rd-t"><thead><tr><th>ID</th><th>항목</th><th>실패 호스트</th></tr></thead><tbody>${(f.top_fail || []).map(x => `<tr><td>${esc(x.id)}</td><td>${esc(x.title)}</td><td>${x.hosts}</td></tr>`).join("") || '<tr><td colspan="3" class="muted">없음</td></tr>'}</tbody></table>
      <h5>호스트 × SCG</h5><div class="rd-scroll"><table class="rd-t"><thead><tr><th>호스트</th><th>상태</th><th>준수</th><th>확인 범위</th>${scg.map(k => `<th class="small">${k}</th>`).join("")}</tr></thead><tbody>
      ${(s.hosts || []).filter(h => h.ok).map(h => { const sc = h.security || {}; return `<tr data-rdh="${esc(h.target)}" class="rd-click"><td>${esc(h.label)}</td><td class="small">${esc(sc.posture || "")}</td><td>${sc.compliance ?? "—"}%</td><td>${sc.coverage ?? "—"}%</td>${scg.map(k => `<td>${b((sc.scg || {})[k] || "unknown")}</td>`).join("")}</tr>`; }).join("")}</tbody></table></div>
      <p class="small muted">'확인 불가'는 BMC 가 Redfish 로 값을 보여 주지 않는 항목(벤더 설정·라이선스·권한)이며 통과로 계산하지 않습니다.</p></div>`;
  }

  // ------------------------------------------------------------------ 설정 탭
  function setTab() {
    const o = st.ov || {}, s = o.settings || {}, h = o.hcl || {}, bc = o.bcg || {};
    const f = (k, l, unit) => `<label class="rd-f"><span>${l}</span><input data-rds="${k}" type="number" value="${esc(String(s[k] ?? ""))}" min="0"> <small>${unit || ""}</small></label>`;
    return `<div class="rd-card"><h4>스캔 설정</h4>${f("schedule_hours", "예약 스캔 주기", "시간(0 = 끔, 등록된 BMC 대상)")}${f("concurrency", "동시 스캔", "대(1–16)")}${f("host_timeout", "호스트 제한 시간", "초")}
        ${f("sel_days", "하드웨어 이벤트 기간", "일")}${f("retention_scans", "보관할 스캔 수", "개")}
        <label class="rd-f"><span>프로파일</span><select data-rds="profile"><option value="full" ${s.profile === "full" ? "selected" : ""}>전체</option><option value="lean" ${s.profile === "lean" ? "selected" : ""}>빠르게(펌웨어 목록 제외)</option></select></label>
        <label class="rd-f"><span>TLS 검증(일회성 기본)</span><select data-rds="verify_tls"><option value="false">끔</option><option value="true" ${s.verify_tls ? "selected" : ""}>켬</option></select></label>
        <button class="btn-sm solid" id="rd-ssave" data-perm="settings">저장</button></div>
      <div class="rd-card"><h4>vSAN HCL(Broadcom Compatibility Guide) <small>${h.loaded ? `항목 ${n(h.entries)} · ESA ${n(h.esa)} · ${esc(h.source || "")} · ${fmt(h.loaded)}` : "없음 — 드라이브·NIC PCI ID 대조를 하지 않습니다"}</small></h4>
        <p class="small muted">자동 다운로드는 하지 않습니다. 인터넷이 되면 '받기'(공개 JSON ${esc("vvs.broadcom.com/service/vsan/all.json.gz")}), 폐쇄망이면 같은 파일을 받아 올리세요.</p>
        <button class="btn-sm" id="rd-hclr" data-perm="settings">최신 HCL 받기</button> <label class="btn-sm" data-perm="settings">파일 올리기<input type="file" id="rd-hclf" accept=".json,.gz" hidden></label></div>
      <div class="rd-card"><h4>BCG CPU 시리즈(CPUID) <small>${esc(bc.source || "")} · ${n(bc.series)}개 시리즈</small></h4>
        <p class="small muted">BCG 'CPU Series' 검색 결과 CSV(열: CPU Series, Cores/Threads, CPUID Info, CPUIDs, Supported Releases)를 올리면 CPUID 대조 기준을 바꿉니다. 목록에 없는 CPU 는 'BCG 확인 필요'로 표시합니다(자동 미지원 판정 아님).</p>
        <label class="btn-sm" data-perm="settings">CSV 올리기<input type="file" id="rd-bcgf" accept=".csv" hidden></label></div>`;
  }

  // ------------------------------------------------------------------ 호스트 상세
  async function openHost(target) {
    try { st.host = await A.api("GET", `/api/readiness/scans/${encodeURIComponent(st.sid)}/hosts/${encodeURIComponent(target)}`); st.tab = "host"; render(); }
    catch (e) { A.fail("호스트 결과 불러오기 실패", e); }
  }
  function dimmGrid(g) {
    return `<div class="rd-dimm">${(g || []).map(s => `<div class="rd-sock"><b>CPU${s.socket}</b>${s.by_slot ? ' <small class="muted">채널 위치 미보고 — 슬롯 번호 순</small>' : ""}<div class="rd-chs">${s.channels.map(c => `<div class="rd-ch">${(c.dimms.length ? c.dimms : [{}]).map(d => {
      const cls = !d.present ? "" : (d.health && d.health !== "OK") ? "bad" : (d.speed && d.rated && d.speed < d.rated) ? "slow" : "on";
      return `<i class="${cls}" title="${esc(String(d.loc || ""))} ${d.present ? `${d.gib}GB ${d.speed || "?"}/${d.rated || "?"} MT/s ${d.health || ""}` : "비어 있음"}">${d.present && d.gib ? Math.round(d.gib) : ""}</i>`; }).join("")}<small>${esc(c.ch)}</small></div>`).join("")}</div></div>`).join("")}
      </div><p class="small muted">파랑=장착 · 주황=정격보다 낮은 속도 · 빨강=비정상 · 빈칸=미장착. 칸 안 숫자=GB.</p>`;
  }
  function hostTab() {
    const x = st.host; if (!x) return "";
    if (!x.ok) return `<p>${b("fail", "스캔 실패")} ${esc(x.error || "")}</p>`;
    const r = x.result, h = x.host, sm = r.summary;
    const grp = Object.keys(AREA).map(a => { const cs = r.checks.filter(c => c.area === a); if (!cs.length) return "";
      return `<h5>${AREA[a]} ${b(r.areas[a])}</h5><table class="rd-t"><tbody>${cs.map(c => `<tr><td style="width:90px">${b(c.status)}</td><td style="width:260px"><b>${esc(c.title)}</b></td><td>${esc(c.detail)}${c.fix ? `<div class="small rd-fix">→ ${esc(c.fix)}</div>` : ""}${c.ref ? ` <a class="small" href="${esc(c.ref)}" target="_blank" rel="noopener noreferrer">근거</a>` : ""}</td></tr>`).join("")}</tbody></table>`; }).join("");
    const drives = (h.storage || {}).drives || [];
    const sec = r.security;
    return `<div class="rd-tools"><button class="btn-sm" id="rd-back">← 목록</button><b class="rd-ht">${esc(x.label || x.target)}</b> ${b(r.verdict)}
        ${x.esxi ? `<span class="small">ESXi <b>${esc(x.esxi.esxi)}</b>${x.esxi.cluster ? " · " + esc(x.esxi.cluster) : ""}</span>` : ""}
        <span class="rd-sp"></span><button class="btn-sm" id="rd-ai">AI에게 묻기</button><button class="btn-sm" id="rd-sr" data-perm="operate">SR 초안</button></div>
      <p class="small muted">${esc(sm.vendor || "")} ${esc(sm.model || "")} · S/N ${esc(sm.serial || "")} · BIOS ${esc(sm.bios || "")} · BMC ${esc(sm.bmc_model || "")} ${esc(sm.bmc_fw || "")} · Redfish 요청 ${h.requests || "?"}회 · ${fmt(x.ts)}</p>
      ${r.blocking.length ? `<div class="rd-alert bad"><b>차단 항목:</b> ${r.blocking.map(esc).join(", ")}</div>` : ""}
      ${r.actions.length ? `<div class="rd-card"><h4>조치 목록</h4><ol>${r.actions.map(a => `<li>${b(a.status)} <b>${esc(a.title)}</b> — ${esc(a.fix)}</li>`).join("")}</ol></div>` : ""}
      <div class="rd-tiles">${Object.entries(AREA).map(([k, l]) => `<div class="rd-tile ${(ST[r.areas[k]] || [0, "unk"])[1]}"><small>${l}</small><b>${(ST[r.areas[k]] || [r.areas[k]])[0]}</b></div>`).join("")}</div>
      <div class="rd-two"><div class="rd-card">${grp}</div><div>
        <div class="rd-card"><h4>메모리 배치 <small>${n(sm.memory.total_gib)}GB · ${sm.memory.dimms}/${sm.memory.slots} 슬롯 · 소켓당 ${sm.memory.channels_per_socket}채널(${esc(sm.cpu.family || "")})</small></h4>${dimmGrid(r.memory_grid)}</div>
        <div class="rd-card"><h4>드라이브</h4><table class="rd-t"><thead><tr><th>이름</th><th>모델</th><th>종류</th><th>용량</th><th>수명</th><th>HCL</th></tr></thead><tbody>${drives.map(d => `<tr><td>${esc(d.name)}<div class="small muted">${esc(d.ctrl)} ${d.role === "boot" ? "· 부트" : ""}</div></td><td class="small">${esc(d.model)}<div class="muted">${esc(d.fw)}</div></td><td class="small">${esc(d.protocol)} ${esc(d.media)}</td><td>${n(d.capacity_gb)}GB</td><td>${d.life_left == null ? "—" : d.life_left + "%"}</td><td class="small">${d.hcl ? (d.hcl.esa ? b("pass", "ESA") : d.hcl.osa ? b("warn", "OSA") : b("unknown", d.hcl.how || "미일치")) : "—"}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">없음</td></tr>'}</tbody></table></div>
        <div class="rd-card"><h4>NIC · LLDP</h4><table class="rd-t"><thead><tr><th>포트</th><th>링크</th><th>속도</th><th>스위치</th><th>스위치 포트</th></tr></thead><tbody>${(h.nics || []).map(p => `<tr><td class="small">${esc(p.model || p.adapter)} / ${esc(p.port)}</td><td>${esc(p.link || "")}</td><td>${n(p.speed_gbps)}${p.max_gbps ? "/" + n(p.max_gbps) : ""}Gb</td><td>${esc((p.lldp || {}).system_name || (p.lldp || {}).chassis_id || "—")}</td><td>${esc((p.lldp || {}).port_id || "")}</td></tr>`).join("")}</tbody></table></div>
      </div></div>
      <div class="rd-card"><h4>BMC 보안 <small>${esc(sec.score.posture)} · 준수 ${sec.score.compliance ?? "—"}% · 확인 범위 ${sec.score.coverage}%</small></h4><table class="rd-t"><thead><tr><th>ID</th><th>항목</th><th>결과</th><th>현재</th><th>기대</th><th>주제</th><th>SCG / NIST</th></tr></thead><tbody>
        ${sec.rows.map(c => `<tr><td>${esc(c.id)}</td><td>${esc(c.title)}${c.fix ? `<div class="small rd-fix">→ ${esc(c.fix)}</div>` : ""}</td><td>${b(c.status)}</td><td class="small">${esc(c.observed)}</td><td class="small">${esc(c.expected)}</td><td class="small">${esc(c.cisa)}</td><td class="small">${esc(c.scg)}<div class="muted">${esc(c.nist)}</div></td></tr>`).join("")}</tbody></table></div>
      <div class="rd-card"><h4>BIOS 기준선 <small>${r.bios.compliance ?? "—"}% (평가 ${r.bios.assessed || 0}개)</small></h4><table class="rd-t"><thead><tr><th>기능</th><th>속성</th><th>현재</th><th>결과</th><th>등급</th><th>이유</th></tr></thead><tbody>
        ${(r.bios.rows || []).map(c => `<tr><td>${esc(c.title)}</td><td class="small">${esc(c.attribute || "—")}</td><td class="small">${esc(c.current)}</td><td>${b(c.status)}</td><td class="small">${esc(c.severity)}</td><td class="small muted">${esc(c.why)}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${esc(r.bios.note || "없음")}</td></tr>`}</tbody></table></div>
      <div class="rd-two"><div class="rd-card"><h4>하드웨어 이벤트(SEL·IML)</h4><div class="rd-scroll" style="max-height:300px"><table class="rd-t"><tbody>${(h.sel || []).slice(0, 80).map(e => `<tr><td class="small">${esc((e.ts || "").replace("T", " ").slice(0, 16))}</td><td>${b(e.severity === "critical" ? "fail" : e.severity === "warning" ? "warn" : "info", e.severity)}</td><td class="small">${esc(e.message)} <span class="muted">${esc(e.message_id || "")}</span></td></tr>`).join("")}</tbody></table></div></div>
        <div class="rd-card"><h4>펌웨어 · 이력</h4><table class="rd-t"><tbody>${(h.firmware || []).slice(0, 40).map(f => `<tr><td class="small">${esc(f.name)}</td><td class="small">${esc(f.version)}</td></tr>`).join("")}</tbody></table>
          <h5>이 대상의 스캔 이력</h5><table class="rd-t"><thead><tr><th>스캔</th><th>판정</th><th>실패/주의</th><th>BMC 보안</th><th>BIOS</th></tr></thead><tbody>${(x.trend || []).map(t => `<tr><td class="small">${fmt(t.ts)}</td><td>${t.verdict ? b(t.verdict) : b("fail", "실패")}</td><td>${t.fail}/${t.warn}</td><td>${t.sec ?? "—"}%</td><td class="small">${esc(t.bios || "")}</td></tr>`).join("")}</tbody></table></div></div>`;
  }

  // ------------------------------------------------------------------ 렌더·이벤트
  function render() {
    const box = $("#rd-body"); if (!box) return;
    const tabs = [["scan", "스캔"], ["fleet", "결과(플릿)"], ["fabric", "ToR 패브릭"], ["drift", "편차"], ["sec", "BMC 보안"], ["set", "설정·HCL"]];
    box.innerHTML = `<div class="tabs rd-tabs">${tabs.map(([k, l]) => `<button class="${st.tab === k || (st.tab === "host" && k === "fleet") ? "on" : ""}" data-rdt="${k}">${l}</button>`).join("")}</div>
      <div class="rd-pane">${({scan: scanTab, fleet: fleetTab, fabric: fabricTab, drift: driftTab, sec: secTab, set: setTab, host: hostTab}[st.tab] || scanTab)()}</div>`;
    $$("[data-perm]", box).forEach(el => { el.hidden = !A.can(el.dataset.perm); });
  }
  function readSel() { return [...st.sel]; }
  function exportUrl(fmt) { return `/api/readiness/scans/${encodeURIComponent(st.sid)}/report.${fmt}${st.obf ? "?obfuscate=1" : ""}`; }
  async function startScan() {
    const tg = ($("#rd-tg") || {}).value || "", u = ($("#rd-u") || {}).value || "", p = ($("#rd-p") || {}).value || "";
    st.adhoc = {targets: tg, username: u, port: ($("#rd-port") || {}).value || ""};
    const body = {connectors: readSel(), label: ($("#rd-label") || {}).value || "", profile: ($("#rd-prof") || {}).value || undefined};
    if (tg.trim()) Object.assign(body, {targets: tg, username: u, password: p, port: st.adhoc.port, verify_tls: ($("#rd-tls") || {}).value === "1"});
    try { const j = await A.api("POST", "/api/readiness/scans", body); const pw = $("#rd-p"); if (pw) pw.value = ""; A.ok("스캔 시작", `${j.id} — ${j.total}대`); await loadOv(); render(); poll(j.id); }
    catch (e) { A.fail("스캔 시작 실패", e); }
  }
  function poll(sid) {
    clearInterval(st.poll);
    st.poll = setInterval(async () => {
      if ($("#drawer-rd").hidden) { clearInterval(st.poll); return; }
      await loadOv();
      const run = (st.ov.running || []).find(j => j.id === sid);
      if (!run) { clearInterval(st.poll); await loadScan(sid); st.tab = "fleet"; A.ok("스캔 완료", sid); }
      if (st.tab === "scan" || !run) render();
    }, 2000);
  }
  function askAi() {
    const x = st.host; if (!x || !x.ok) return;
    const r = x.result, sm = r.summary;
    const bad = r.checks.filter(c => c.status === "fail" || c.status === "warn").slice(0, 10).map(c => `${c.title}: ${c.detail}`);
    const q = `서버 ${x.esxi ? x.esxi.esxi : x.label} (${sm.vendor} ${sm.model}, CPU ${sm.cpu.model} ${sm.cpu.label}, BIOS ${sm.bios}, BMC ${sm.bmc_fw})의 VCF 9.x 하드웨어 준비도 판정은 '${r.verdict_label}'.`
      + (bad.length ? `\n문제 항목: ${bad.join(" | ")}` : "") + "\nVCF 9 로 재사용·업그레이드하려면 무엇을 어떤 순서로 조치해야 하는지, 관련 KB 와 함께 알려줘.";
    const nav = document.getElementById("nav-chat"); if (nav) nav.click();
    setTimeout(() => { const t = document.getElementById("chat-q"); if (t) { t.value = q; t.focus(); }
      const cx = document.getElementById("chat-ctx"); if (cx) cx.textContent = `— 하드웨어 준비도 · ${x.esxi ? x.esxi.esxi : x.label}`; }, 150);
  }
  function wire() {
    const box = $("#rd-body"); if (box.dataset.w) return; box.dataset.w = "1";
    box.addEventListener("click", async e => {
      const t = e.target.closest("[data-rdt],[data-rdo],[data-rdh],[data-rdx],#rd-start,#rd-cancel,#rd-back,#rd-ai,#rd-sr,#rd-ssave,#rd-hclr,#rd-all"); if (!t) return;
      if (t.dataset.rdt) { st.tab = t.dataset.rdt; if (["fleet", "fabric", "drift", "sec"].includes(st.tab) && !st.scan && st.ov && st.ov.scans && st.ov.scans[0]) await loadScan(st.ov.scans[0].id); render(); return; }
      if (t.dataset.rdo) { e.preventDefault(); await loadScan(t.dataset.rdo); st.tab = "fleet"; render(); return; }
      if (t.dataset.rdh) { await openHost(t.dataset.rdh); return; }
      if (t.dataset.rdx) { const a = document.createElement("a"); a.href = exportUrl(t.dataset.rdx); if (t.dataset.rdx === "html") a.target = "_blank"; else a.download = ""; document.body.append(a); a.click(); a.remove(); return; }
      if (t.id === "rd-all") { (st.ov.targets || []).forEach(x => t.checked ? st.sel.add(x.name) : st.sel.delete(x.name)); render(); return; }
      if (t.id === "rd-start") { await startScan(); return; }
      if (t.id === "rd-cancel") { const run = (st.ov.running || [])[0]; if (run) { await A.api("POST", `/api/readiness/scans/${encodeURIComponent(run.id)}/cancel`); A.toast("취소 요청", "진행 중인 호스트가 끝나면 멈춥니다.", "info"); } return; }
      if (t.id === "rd-back") { st.tab = "fleet"; render(); return; }
      if (t.id === "rd-ai") { askAi(); return; }
      if (t.id === "rd-sr") { const x = st.host; if (window.AIOPS_SR_NEW) window.AIOPS_SR_NEW({kind: "readiness", ref: `${st.sid}|${x.target}`}, {label: x.esxi ? x.esxi.esxi : x.label}); return; }
      if (t.id === "rd-ssave") { const body = {}; $$("[data-rds]", box).forEach(i => { body[i.dataset.rds] = i.dataset.rds === "verify_tls" ? i.value === "true" : i.value; });
        try { await A.api("PUT", "/api/readiness/settings", body); A.ok("설정 저장", ""); await loadOv(); render(); } catch (x) { A.fail("설정 저장 실패", x); } return; }
      if (t.id === "rd-hclr") { t.disabled = true; A.toast("HCL 받는 중", "공개 vSAN HCL JSON(수십 MB)을 받습니다.", "info", 4000);
        try { const r = await A.api("POST", "/api/readiness/hcl/refresh"); A.ok("HCL 갱신", `${r.entries}개 항목`); await loadOv(); render(); } catch (x) { A.fail("HCL 받기 실패(인터넷·프록시 확인 또는 파일 올리기)", x); } t.disabled = false; }
    });
    box.addEventListener("change", async e => {
      const t = e.target;
      if (t.dataset.rdc) { t.checked ? st.sel.add(t.dataset.rdc) : st.sel.delete(t.dataset.rdc); return; }
      if (t.id === "rd-scan") { await loadScan(t.value); render(); return; }
      if (t.id === "rd-obf") { st.obf = t.checked; return; }
      if (t.id === "rd-vf") { st.vf = t.value; render(); return; }
      if (t.id === "rd-hclf" || t.id === "rd-bcgf") {
        const f = t.files[0]; if (!f) return;
        const url = t.id === "rd-hclf" ? "/api/readiness/hcl" : "/api/readiness/bcg-cpu";
        try { const r = await fetch(url, {method: "PUT", body: f, headers: {"X-Requested-With": "aiops", "Content-Type": "application/octet-stream"}});
          const j = await r.json(); if (!r.ok) throw new Error(j.detail || r.status); A.ok("가져오기 완료", t.id === "rd-hclf" ? `HCL ${j.entries}개` : `CPU 시리즈 ${j.series}개`); await loadOv(); render(); }
        catch (x) { A.fail("가져오기 실패", x); }
      }
    });
    box.addEventListener("input", e => { if (e.target.id === "rd-f") { st.filter = e.target.value; clearTimeout(st._t); st._t = setTimeout(() => { render(); const q = $("#rd-f"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 250); } });
  }
  async function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-rd") d.hidden = true; });
    $("#drawer-rd").hidden = false;
    wire(); await loadOv();
    if (!st.sel.size) (st.ov.targets || []).forEach(t => st.sel.add(t.name));
    const run = (st.ov.running || [])[0];
    if (run) poll(run.id);
    render();
  }
  const nav = document.getElementById("nav-rd"); if (nav) nav.onclick = show;
  const rl = document.getElementById("rd-reload"); if (rl) rl.onclick = async () => { await loadOv(); if (st.sid) await loadScan(st.sid); render(); };
  window.AIOPS_READINESS = show;
})();
