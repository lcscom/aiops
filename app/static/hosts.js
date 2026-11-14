/* VM·서버 에이전트 현황·등록 / 실시간 로그 보기(Live Tail) — core.js(AIOPS) · app.js(aiops:ws 이벤트) 이후 로드 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const p2 = n => String(n).padStart(2, "0");
  const hms = ts => { const d = new Date(ts * 1000); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };
  const fmt = ts => { if (!ts) return "-"; const d = new Date(ts * 1000); return `${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${hms(ts)}`; };
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.round(s)}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : `${Math.round(s / 3600)}시간 전`; };
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const SEV_KO = {critical: "위험", error: "오류", warning: "경고", info: "정보", debug: "디버그"};
  const ST = {ok: ["정상", "good"], stale: ["무응답", "bad"], unknown: ["미확인", "mid"], retired: ["퇴역", "mid"]};
  const KIND = {vm: "VM 게스트", baremetal: "물리 서버"};

  // ================================================================ 에이전트 현황
  let ag = {items: [], filter: "", kind: "", state: "", timer: null};
  async function loadAgents() {
    let d;
    try { d = await A.api("GET", "/api/agents", undefined, {background: true}); }
    catch (e) { $("#ag-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    ag.items = d.items; ag.blocks = d.blocks || []; ag.dropped = d.blocked_dropped || 0;
    const s = d.summary || {};
    const b = $("#agents-badge"); b.hidden = !s.stale; b.textContent = s.stale || "";
    $("#ag-sub").textContent = `— 전체 ${d.items.length} · 정상 ${s.ok || 0} · 무응답 ${s.stale || 0} · 무응답 기준 ${d.stale_seconds >= 60 ? Math.round(d.stale_seconds / 60) + "분" : d.stale_seconds + "초"}`;
    renderAgents();
    hostList();
  }
  // 삭제(차단)한 호스트 — 다시 보내도 등록·저장하지 않음. 누가 아직 보내는지(주소·경로) 보여 주고 제거 명령 안내
  const PATH_FIX = {"vmx": "ESXi 가 이 VM 의 vmx 로그를 syslog 로 보내는 중 — VM 고급 설정 vmx.log.destination·vmx.log.syslogID 를 지우거나(전원 끄고) VM 이 실제로 지워졌는지 vCenter 에서 확인",
                    "syslog": "그 주소의 rsyslog 가 보내는 중 — 서버에서 sudo bash uninstall-agent.sh 로 /etc/rsyslog.d/90-vcf-aiops.conf 제거",
                    "http": `그 주소의 Fluent Bit 가 보내는 중 — Linux: curl -fsSk ${location.origin}/agents/uninstall-linux.sh | sudo bash · Windows(관리자 PowerShell): Stop-Service fluent-bit; sc.exe delete fluent-bit`};
  const fixOf = p => /vmx/.test(p) ? PATH_FIX.vmx : /syslog/.test(p) ? PATH_FIX.syslog : PATH_FIX.http;
  function blocksHtml() {
    const bl = ag.blocks || [];
    if (!bl.length) return "";
    const live = bl.filter(b => b.sending).length;
    return `<h4 class="ag-bh">삭제·차단한 호스트 <small>${bl.length}대 — 다시 보내도 등록·저장하지 않습니다${ag.dropped ? ` · 이번 기동 후 버린 로그 ${ag.dropped.toLocaleString()}건` : ""}${live ? ` · <b class="bad">${live}대는 아직 무언가 보내는 중</b>` : ""}</small></h4>
      <table class="plat"><thead><tr><th>호스트</th><th>차단</th><th>이후 수신 시도</th><th>보낸 주소 · 경로</th><th>조치</th><th></th></tr></thead><tbody>
      ${bl.map(b => `<tr><td><b>${esc(b.host)}</b></td><td class="nowrap">${fmt(b.since)}<div class="mini">${esc(b.by || "-")}</div></td>
        <td class="nowrap">${b.hits ? `<span class="res ${b.sending ? "bad" : "mid"}">${b.hits.toLocaleString()}건</span><div class="mini">마지막 ${ago(b.last)}</div>` : '<span class="res good">없음</span>'}</td>
        <td>${b.peer ? `<code>${esc(b.peer)}</code>` : "-"}<div class="mini">${esc(b.path || "")}</div></td>
        <td class="mini" style="max-width:420px">${b.hits ? esc(fixOf(b.path || "")) : "보내는 곳이 없습니다 — 그대로 두면 됩니다"}</td>
        <td class="nowrap">${A.can("settings") ? `<button class="btn-sm" data-unblock="${esc(b.host)}" title="다음 수신부터 다시 등록">차단 해제</button>` : ""}</td></tr>`).join("")}
      </tbody></table>`;
  }
  function renderAgents() {
    const q = ag.filter.toLowerCase();
    const rows = ag.items.filter(x => (!ag.kind || x.kind === ag.kind) && (!ag.state || x.state === ag.state)
      && (!q || `${x.host} ${x.role} ${x.os} ${(x.vcenter || {}).host || ""}`.toLowerCase().includes(q)));
    const cnt = {}; ag.items.forEach(x => { cnt[x.state] = (cnt[x.state] || 0) + 1; });
    $("#ag-body").innerHTML = `
      <div class="ag-sum">${Object.entries(ST).filter(([k]) => cnt[k]).map(([k, [l]]) => `<span class="${k}">${l} ${cnt[k]}</span>`).join("") || "<span>등록된 에이전트 없음</span>"}</div>
      <div class="ag-filter"><input id="ag-q" placeholder="호스트·역할·ESXi 검색" value="${esc(ag.filter)}">
        <select id="ag-kind"><option value="">전체 종류</option><option value="vm" ${ag.kind === "vm" ? "selected" : ""}>VM 게스트</option><option value="baremetal" ${ag.kind === "baremetal" ? "selected" : ""}>물리 서버</option></select>
        <select id="ag-state"><option value="">전체 상태</option>${Object.entries(ST).map(([k, [l]]) => `<option value="${k}" ${ag.state === k ? "selected" : ""}>${l}</option>`).join("")}</select>
        ${A.can("settings") ? ["retired", "stale"].filter(k => cnt[k]).map(k => `<button class="btn-sm danger" data-purge-state="${k}" data-label="${ST[k][0]}">${ST[k][0]} ${cnt[k]}건 삭제</button>`).join(" ") : ""}</div>
      ${ag.items.length ? `<table class="plat"><thead><tr><th>호스트</th><th>종류</th><th>OS · 에이전트</th><th>역할</th><th>상태</th><th>분당</th><th>최근 15분</th><th>마지막 수신</th><th>vCenter</th><th></th></tr></thead><tbody>
      ${rows.map(x => { const [lab, c] = ST[x.state] || [x.state, "mid"]; const sv = x.sev15 || {}; const v = x.vcenter;
        return `<tr><td><b>${esc(x.host)}</b>${x.peer && x.peer !== x.host ? `<div class="mini">${esc(x.peer)}</div>` : ""}</td><td>${KIND[x.kind] || esc(x.kind)}</td>
          <td>${esc(x.os || "-")} · ${esc(x.agent || "-")}${x.version ? `<div class="mini">${esc(x.version)}</div>` : ""}</td><td>${esc(x.role || "-")}</td>
          <td><span class="res ${c}">${lab}</span></td><td>${x.per_min}<div class="mini">평균 ${x.avg_per_min}</div></td>
          <td>${["critical", "error", "warning"].filter(k => sv[k]).map(k => `<span class="sev ${k}">${SEV_KO[k]} ${sv[k]}</span>`).join(" ") || "-"}</td>
          <td class="nowrap">${ago(Math.max(x.last_seen || 0, x.last_heartbeat || 0))}<div class="mini">로그 ${fmt(x.last_seen)} · 하트비트 ${fmt(x.last_heartbeat)}</div></td>
          <td>${v ? `${esc(v.vm)}<div class="mini">${esc(v.host || "-")} / ${esc(v.cluster || "-")}</div>` : x.kind === "vm" ? '<span class="mini">VM 매핑 없음</span>' : "-"}</td>
          <td class="nowrap"><button class="btn-sm" data-tail="${esc(x.host)}">실시간 보기</button>${A.can("settings") && x.state !== "retired" ? ` <button class="btn-sm" data-retire="${esc(x.host)}">퇴역</button>` : ""}${A.can("settings") ? ` <button class="btn-sm danger" data-purge="${esc(x.host)}" title="등록 삭제 — 목록·기록에서 제거">삭제</button>` : ""}</td></tr>`; }).join("")}
      </tbody></table>` : `<div class="empty">아직 수신된 에이전트가 없습니다. 오른쪽 위 <b>에이전트 등록</b>에서 설치 명령을 받아 VM·서버에서 실행하세요.</div>`}
      ${blocksHtml()}`;
    const qi = $("#ag-q"); qi.oninput = () => { ag.filter = qi.value; const pos = qi.selectionStart; renderAgents(); const n = $("#ag-q"); n.focus(); n.setSelectionRange(pos, pos); };
    $("#ag-kind").onchange = e => { ag.kind = e.target.value; renderAgents(); };
    $("#ag-state").onchange = e => { ag.state = e.target.value; renderAgents(); };
  }
  $("#ag-body").addEventListener("click", async e => {
    const t = e.target.closest("[data-tail]"); if (t) { openTail(t.dataset.tail); return; }
    const pg = e.target.closest("[data-purge]");
    if (pg && await A.confirm("에이전트 등록 삭제", `${pg.dataset.purge} 의 등록을 삭제하고 차단합니다. 이 호스트가 다시 보내도 등록·저장하지 않고, 아래 '삭제·차단한 호스트'에 보낸 주소와 경로만 기록합니다. 계속할까요?`)) {
      try { await A.api("DELETE", `/api/agents/${encodeURIComponent(pg.dataset.purge)}?purge=true&block=true`); A.ok("등록 삭제·차단됨"); loadAgents(); } catch (err) { A.fail("삭제 실패", err); }
      return;
    }
    const ub = e.target.closest("[data-unblock]");
    if (ub && await A.confirm("차단 해제", `${ub.dataset.unblock} 의 차단을 풉니다. 다음 수신부터 다시 등록됩니다. 계속할까요?`)) {
      try { await A.api("DELETE", `/api/agents/blocks/${encodeURIComponent(ub.dataset.unblock)}`); A.ok("차단 해제됨"); loadAgents(); } catch (err) { A.fail("해제 실패", err); }
      return;
    }
    const pb = e.target.closest("[data-purge-state]");
    if (pb && await A.confirm("에이전트 등록 일괄 삭제", `상태가 '${pb.dataset.label}' 인 등록을 모두 삭제하고 차단합니다(다시 보내도 등록하지 않음). 계속할까요?`)) {
      try { const r2 = await A.api("POST", "/api/agents/purge", {state: pb.dataset.purgeState}); A.ok(`${r2.deleted}건 삭제`); loadAgents(); } catch (err) { A.fail("삭제 실패", err); }
      return;
    }
    const r = e.target.closest("[data-retire]");
    if (r && await A.confirm("에이전트 퇴역", `${r.dataset.retire} 를 퇴역 처리하면 무응답 감시에서 제외됩니다(다시 수신되면 자동 복귀). 계속할까요?`)) {
      try { await A.api("DELETE", `/api/agents/${encodeURIComponent(r.dataset.retire)}`); A.ok("퇴역 처리됨"); loadAgents(); } catch (err) { A.fail("퇴역 실패", err); }
    }
  });
  $("#nav-agents").onclick = () => {
    open("drawer-agents"); loadAgents();
    clearInterval(ag.timer); ag.timer = setInterval(() => $("#drawer-agents").hidden ? clearInterval(ag.timer) : loadAgents(), 10000);
  };
  $("#ag-reload").onclick = loadAgents;

  // ---------------------------------------------------------------- 등록(설치 명령 생성)
  $("#ag-enroll").onclick = async () => {
    const v = await A.modal({title: "에이전트 등록 — 설치 명령 생성", ok: "토큰 발급·명령 생성",
      html: `<p class="modal-text">수집 전용(ingest) API 토큰을 새로 발급하고, 그 토큰이 들어간 설치 명령을 만듭니다. 같은 명령을 여러 VM·서버에 써도 됩니다(호스트 이름으로 구분).</p>`,
      fields: [{id: "kind", label: "대상", type: "select", value: "vm", options: [["vm", "VM 게스트"], ["baremetal", "물리 서버(베어메탈 OS)"]]},
               {id: "role", label: "역할(선택)", placeholder: "예) DB, WAS, AP — 관제 화면 그룹", hint: "영문·숫자·-_ 30자"},
               {id: "days", label: "토큰 유효 기간(일)", type: "number", value: 365, min: 0, max: 3650, hint: "0 = 만료 없음"}]});
    if (!v) return;
    let d;
    try { d = await A.api("POST", "/api/agents/enroll", {kind: v.kind, role: v.role, days: v.days ?? 365}); } catch (err) { A.fail("등록 실패", err); return; }
    const block = (title, cmd, note) => `<h5>${title}</h5><div class="cmd"><pre>${esc(cmd)}</pre><button class="btn-sm" data-copy="${esc(cmd)}">복사</button></div>${note ? `<p class="small muted">${note}</p>` : ""}`;
    A.modal({title: `설치 명령 — ${KIND[d.kind]}${d.role ? ` · ${d.role}` : ""}`, wide: true, ok: "", cancel: "닫기",
      html: `<p class="modal-text"><b>토큰은 이 화면에서만 표시됩니다.</b> 서버: ${esc(d.server)} · 유효 ${d.expires_days ? d.expires_days + "일" : "무기한"}</p>
        ${block("Linux — Fluent Bit (권장: journald 전체 + 하트비트 + 디스크 버퍼)", d.linux, "앱 로그 파일 추가: 명령 끝에 <code>--file '/var/log/app/*.log'</code> · 사내 CA: <code>--insecure</code> 대신 <code>--ca /경로/ca.pem</code> · 망분리: <code>--package fluent-bit_x.deb</code> · Photon OS: 저장소에 Fluent Bit 이 없어 자동으로 rsyslog 모드(TCP 514) 전환, Fluent Bit 은 RHEL 9 rpm 을 <code>--package</code> 로")}
        ${block("Linux — rsyslog (패키지 설치 불가 서버, 토큰 불필요)", d.linux_rsyslog, "TCP 514 로 전송. TLS 는 <code>--syslog-proto tls --ca /경로/ca.pem</code>(rsyslog-gnutls 필요)")}
        ${block("Windows — 관리자 PowerShell (System·Application·Security 핵심 이벤트)", d.windows, "앱 로그: <code>-Files 'D:\\App\\logs\\*.log'</code> · 장애 조치 클러스터: <code>-ExtraChannels 'Microsoft-Windows-FailoverClustering/Operational'</code> · 망분리: <code>-Package C:\\temp\\fluent-bit-5.1.3-win64.zip</code>")}
        ${d.windows_trust ? block("Windows — (선택) -Insecure 대신 이 서버 인증서를 신뢰 루트에 등록", d.windows_trust, `출력된 SHA-256 지문이 <code>${esc(d.cert_sha256 || "-")}</code> 와 같은지 확인한 뒤 위 설치 명령에서 <code>-Insecure</code> 를 빼고 실행하세요.`) : ""}
        <p class="small muted">${esc(d.note)}</p>`,
      onOpen: m => m.addEventListener("click", async ev => {
        const b = ev.target.closest("[data-copy]"); if (!b) return;
        try { await navigator.clipboard.writeText(b.dataset.copy); A.ok("복사됨"); } catch { A.fail("복사 실패", "브라우저가 클립보드를 허용하지 않습니다 — 직접 선택해 복사하세요"); }
      })});
  };

  // ---------------------------------------------------------------- 미설치 VM(커버리지)
  $("#ag-cov").onclick = async () => {
    let c;
    try { c = await A.api("GET", "/api/agents/coverage"); } catch (err) { A.fail("조회 실패", err); return; }
    const pct = c.powered_on_vms ? Math.round(c.with_agent / c.powered_on_vms * 100) : 0;
    A.modal({title: `에이전트 커버리지 — 전원 켜진 VM ${c.powered_on_vms}대 중 ${c.with_agent}대(${pct}%)`, wide: true, ok: "", cancel: "닫기",
      html: c.powered_on_vms ? `<p class="modal-text">vCenter 인벤토리의 전원 켜진 VM 중 로그 수신 기록이 없는 VM 입니다(VM 이름·호스트 이름 비교). 어플라이언스(vCenter·NSX·Edge 등)는 syslog 로 별도 수집되므로 제외해도 됩니다.</p>
        <table class="plat"><thead><tr><th>VM</th><th>ESXi</th><th>클러스터</th><th>vCenter</th></tr></thead><tbody>
        ${c.missing.map(x => `<tr><td>${esc(x.vm)}</td><td>${esc(x.host || "-")}</td><td>${esc(x.cluster || "-")}</td><td>${esc(x.vcenter)}</td></tr>`).join("") || '<tr><td colspan="4">모든 VM 에서 수신 중</td></tr>'}</tbody></table>`
        : `<p class="modal-text">vCenter 커넥터의 토폴로지가 없습니다(운영 설정 > 커넥터에서 vCenter 추가 후 수 분 대기).</p>`});
  };

  // ================================================================ 실시간 로그 보기
  const tl = {on: false, paused: false, buf: [], lines: 0, rate: 0, rateT: Date.now(), spec: null, total: 0};
  const MAXL = 5000;
  let known = {items: [], t: 0};
  const KIND_TAG = {esxi: "ESXi", vm: "VM", agent: "에이전트"};
  async function hostList(force = false) {
    if (!force && Date.now() - known.t < 30000 && known.items.length) return known.items;
    try { known.items = (await A.api("GET", "/api/hosts/known", undefined, {background: true})).items; known.t = Date.now(); }
    catch { known.items = ag.items.map(x => ({host: x.host, sources: [], kind: "agent"})); }
    $("#tl-hosts").innerHTML = known.items.slice(0, 2000).map(h => `<option value="${esc(h.host)}">${esc([KIND_TAG[h.kind] || "", (h.sources || []).join(",")].filter(Boolean).join(" · "))}</option>`).join("");
    return known.items;
  }
  function suggest(note = "") {
    const now = Date.now() / 1000;
    const act = known.items.filter(h => h.last && now - h.last < 900).slice(0, 40);
    $("#tl-sugg").innerHTML = (note ? `<div class="tail-note">${note}</div>` : "")
      + (act.length ? `<div class="tail-chips"><span class="mini">최근 15분 로그 수신 호스트(클릭하면 시작):</span>${act.map(h => `<button class="chip" data-host="${esc(h.host)}" title="${esc((h.sources || []).join(", "))} · ${h.n}줄">${esc(h.host)}</button>`).join("")}</div>`
        : `<div class="tail-note">최근 15분 동안 로그를 보낸 호스트가 없습니다. 장비의 syslog 대상(이 서버 514/udp·tcp)과 방화벽, 에이전트 상태를 확인하세요.</div>`);
  }
  $("#tl-sugg").addEventListener("click", e => {
    const b = e.target.closest("[data-host]"); if (!b) return;
    $("#tl-host").value = b.dataset.host; start();
  });
  function specNow() {
    const hosts = $("#tl-host").value.split(",").map(x => x.trim()).filter(Boolean);
    return {op: "tail", hosts, sources: $("#tl-src").value ? [$("#tl-src").value] : [], min: $("#tl-min").value, q: $("#tl-q").value.trim()};
  }
  function lineHtml(e, hist = false) {
    const ent = e.entity && e.entity !== e.host ? e.entity : "";
    return `<div class="ln ${esc(e.severity)} ${hist ? "hist" : ""}"><span class="t">${hms(e.ts)}</span><span class="v">${SEV_KO[e.severity] || esc(e.severity)}</span>`
      + `<span class="s">${esc(e.source)}</span><span class="h" title="${esc(e.host)}${ent ? " · " + esc(ent) : ""}">${esc(e.host)}${ent ? " · " + esc(ent) : ""}</span><span class="m">${esc(e.message)}</span></div>`;
  }
  function append(html, n) {
    const out = $("#tl-out");
    const em = out.querySelector(".tail-empty"); if (em) em.remove();
    out.insertAdjacentHTML("beforeend", html);
    tl.lines += n;
    while (tl.lines > MAXL && out.firstChild) { out.firstChild.remove(); tl.lines--; }
    if ($("#tl-follow").checked) out.scrollTop = out.scrollHeight;
  }
  function status() {
    const s = tl.spec || {};
    const what = [s.hosts && s.hosts.length ? s.hosts.join(", ") : "모든 호스트", s.sources && s.sources.length ? s.sources[0] : "", s.min && s.min !== "debug" ? SEV_KO[s.min] + "↑" : "", s.q ? `"${s.q}"` : ""].filter(Boolean).join(" · ");
    $("#tl-sub").textContent = tl.on ? `— ${tl.paused ? "일시정지" : "수신 중"} · ${what} · ${tl.rate}줄/초 · 누적 ${tl.total.toLocaleString()}줄${tl.paused && tl.buf.length ? ` · 대기 ${tl.buf.length}` : ""}` : "— 중지됨";
  }
  async function start() {
    const s = specNow();
    if (!s.hosts.length && !s.sources.length && !s.q && s.min === "debug") {
      if (!await A.confirm("필터 없이 시작", "필터 없이 시작하면 모든 로그가 표시됩니다(수집량이 많으면 화면이 빠르게 흐릅니다). 계속할까요?")) return;
    }
    tl.spec = s; tl.on = true; tl.paused = false; tl.total = 0; tl.started = Date.now(); tl.hinted = false;
    const sent = A.wsSend(JSON.stringify(s));
    append(`<div class="sep">— ${hms(Date.now() / 1000)} 실시간 수신 시작${sent ? "" : " (서버 연결 대기 — 연결되면 자동 적용)"}</div>`, 1);
    $("#tl-sugg").innerHTML = "";
    if ($("#tl-prefill").checked) {                  // 기록을 먼저 그리고, 그동안 들어온 실시간 줄은 뒤에 이어 붙임
      tl.prefill = [];
      loadHistory(200, true).finally(() => { const b = tl.prefill || []; tl.prefill = null; if (b.length) append(b.map(x => lineHtml(x)).join(""), b.length); });
    }
    $("#tl-start").textContent = "필터 적용"; $("#tl-pause").disabled = false; $("#tl-pause").textContent = "일시정지";
    status();
  }
  function stop() {
    if (!tl.on) return;
    A.wsSend(JSON.stringify({op: "untail"}));
    tl.on = false; tl.spec = null; $("#tl-start").textContent = "시작"; $("#tl-pause").disabled = true; status();
  }
  $("#tl-start").onclick = start;
  ["tl-host", "tl-q"].forEach(id => $(`#${id}`).addEventListener("keydown", e => { if (e.key === "Enter") start(); }));
  $("#tl-pause").onclick = () => {
    tl.paused = !tl.paused; $("#tl-pause").textContent = tl.paused ? "재개" : "일시정지";
    if (!tl.paused && tl.buf.length) { append(tl.buf.map(e => lineHtml(e)).join(""), tl.buf.length); tl.buf = []; }
    status();
  };
  $("#tl-clear").onclick = () => { $("#tl-out").innerHTML = ""; tl.lines = 0; };
  $("#tl-dl").onclick = () => {                         // 2.11.0 같은 조건으로 파일로
    const s = specNow();
    if (window.AIOPS_LOGS_EXPORT) window.AIOPS_LOGS_EXPORT({host: s.hosts.join(","), source: s.sources.join(","), min_severity: s.min, q: s.q,
      name: s.hosts[0] || "tail", title: "실시간 로그 보기의 조건(호스트·소스·등급·문자열)으로 받습니다."});
  };
  async function loadHistory(limit = 1000, quiet = false) {
    const s = specNow();
    const qs = new URLSearchParams({minutes: 60, limit, min_severity: s.min});
    if (s.hosts[0]) qs.set("host", s.hosts[0]);
    if (s.sources[0]) qs.set("source", s.sources[0]);
    if (s.q) qs.set("q", s.q);
    try {
      const rows = (await A.api("GET", `/api/logs?${qs}`)).reverse();
      if (quiet && !rows.length) return;
      append(`<div class="sep">— 최근 1시간 저장 기록 ${rows.length}줄${s.hosts.length > 1 ? `(첫 호스트 ${esc(s.hosts[0])})` : ""}</div>` + rows.map(e => lineHtml(e, true)).join(""), rows.length + 1);
    } catch (err) { if (!quiet) A.fail("기록 조회 실패", err); }
  }
  $("#tl-hist").onclick = () => loadHistory(1000);
  window.addEventListener("aiops:ws", e => {
    const m = e.detail;
    if (m.type === "snapshot" && tl.on && tl.spec) {          // 재접속 시 필터 재등록(서버는 연결별로 보관)
      A.wsSend(JSON.stringify(tl.spec));
      append(`<div class="sep">— ${new Date().toLocaleTimeString()} 재연결 · 필터 재적용(끊긴 동안의 로그는 '최근 1시간 불러오기'로 확인)</div>`, 1);
    }
    if (m.type !== "tail" || !tl.on) return;
    tl.total += m.data.length;
    tl.rate += m.data.length;
    if (tl.prefill) { tl.prefill.push(...m.data); return; }
    if (tl.paused) { tl.buf.push(...m.data); if (tl.buf.length > 20000) tl.buf.splice(0, tl.buf.length - 20000); }
    else append(m.data.map(x => lineHtml(x)).join(""), m.data.length);
    if (m.truncated) append(`<div class="sep">— 이 구간 ${m.truncated}줄 생략(초당 4,000줄 이상 — 필터를 좁히세요)</div>`, 1);
  });
  setInterval(() => {
    if (!tl.on) return;
    status(); tl.rate = 0;
    if (!tl.total && !tl.hinted && Date.now() - tl.started > 20000) {   // 20초간 수신 없음 → 원인 안내·후보 제시
      tl.hinted = true;
      hostList(true).then(() => suggest(`이 필터로 20초 동안 들어온 로그가 없습니다. 호스트 이름이 장비가 보내는 이름(FQDN·짧은 이름·IP)과 같은지 확인하세요 — 접두어(예: esx0)도 됩니다.`));
    }
  }, 1000);
  function openTail(host) {
    open("drawer-tail");
    hostList().then(() => { if (!tl.on && !host) suggest(); });
    if (host) { $("#tl-host").value = host; start(); }
  }
  $("#nav-tail").onclick = () => openTail("");
  new MutationObserver(() => { if ($("#drawer-tail").hidden && tl.on) stop(); })
    .observe($("#drawer-tail"), {attributes: true, attributeFilter: ["hidden"]});
  // 딥링크: /#tail/<호스트> (관제 화면 상세·에이전트 표에서 새 창으로 열기)
  const fromHash = () => { const m = location.hash.match(/^#tail\/(.+)$/); if (m) openTail(decodeURIComponent(m[1])); };
  addEventListener("hashchange", fromHash);
  A.ready.then(me => {
    if (me === null) return;
    setTimeout(fromHash, 800);
    A.api("GET", "/api/agents", undefined, {background: true}).then(d => {
      ag.items = d.items; hostList();
      const b = $("#agents-badge"); b.hidden = !(d.summary || {}).stale; b.textContent = (d.summary || {}).stale || "";
    }).catch(() => {});
  });
})();
