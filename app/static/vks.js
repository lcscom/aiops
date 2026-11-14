/* VKS — vCenter 에서 자동 발견한 Supervisor·워크로드 클러스터의 노드·파드 상태와 파드 로그 — core.js(AIOPS) 이후 로드 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const age = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 3600 ? `${Math.max(1, Math.round(s / 60))}분` : s < 86400 ? `${Math.round(s / 3600)}시간` : `${Math.round(s / 86400)}일`; };
  const ST = {ok: ["정상", "good"], degraded: ["저하", "mid"], down: ["장애", "bad"], init: ["시작 중", "mid"], disabled: ["꺼짐", "mid"]};
  const BADP = new Set(["CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "Error", "OOMKilled"]);
  let st = {d: null, sel: "", tab: "map", ns: "", q: "", onlyBad: false, timer: null, pods: null};

  async function load() {
    try { st.d = await A.api("GET", "/api/vks", undefined, {background: true}); }
    catch (e) { $("#vks-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (!st.sel && st.d.clusters.length) st.sel = st.d.clusters[0].name;
    render();
    if (st.sel) loadPods();
  }
  async function loadPods() {
    try { st.pods = await A.api("GET", `/api/vks/${encodeURIComponent(st.sel)}/pods`, undefined, {background: true}); }
    catch { st.pods = null; }
    renderDetail();
  }
  function render() {
    const d = st.d;
    const vc = d.vcenters.map(v => `${esc(v.connector)}: ${v.error ? `<span class="bad">발견 실패 — ${esc(v.error)}</span>` : v.updated ? `Supervisor ${(v.supervisors || []).length}개${v.note ? " · " + esc(v.note) : ""}` : "발견 대기"}`).join(" · ");
    $("#vks-sub").innerHTML = `— 클러스터 ${d.clusters.length}개 ${vc ? "· " + vc : ""}`;
    if (!d.clusters.length) {
      $("#vks-body").innerHTML = `<div class="empty">아직 찾은 VKS 클러스터가 없습니다.<br>운영 설정 › 커넥터에 vCenter 를 등록하면 Supervisor 와 워크로드(TKG) 클러스터를 자동으로 찾아 노드·파드 상태와 이벤트·로그를 수집합니다.
        <br><small>vCenter 계정에 vSphere 네임스페이스 VIEW 권한이 필요합니다(커넥터 화면의 '수집 전용 계정 만들기'가 자동 부여). 처음 발견까지 1~2분.</small></div>`;
      return;
    }
    const ovOpen = !!(st.ovOpen);
    $("#vks-body").innerHTML = `<details class="vk-ovd" ${ovOpen ? "open" : ""}><summary>VKS 전체 구성도 — Supervisor · vSphere 네임스페이스 · 클러스터 · VM Service VM</summary><div id="vks-ov"></div></details>
      <div class="vks-grid">${d.clusters.map(card).join("")}</div><div id="vks-detail"></div>`;
    const od = $(".vk-ovd"); od.addEventListener("toggle", () => { st.ovOpen = od.open; if (od.open && window.AIOPS_VKS_OVERVIEW) window.AIOPS_VKS_OVERVIEW($("#vks-ov")); });
    if (ovOpen && window.AIOPS_VKS_OVERVIEW) window.AIOPS_VKS_OVERVIEW($("#vks-ov"));
    st.mapFor = "";
    renderDetail();
  }
  function card(c) {
    const [lab, cls] = ST[c.state] || [c.state || "-", "mid"];
    const nr = c.nodes.filter(n => n.ready === "True").length;
    return `<button class="vks-card ${c.name === st.sel ? "sel" : ""} ${c.pods.problem ? "has-bad" : ""}" data-sel="${esc(c.name)}">
      <div class="vh"><span class="label ${c.role === "supervisor" ? "" : "info"}">${c.role === "supervisor" ? "Supervisor" : "워크로드"}</span><b>${esc(c.cluster)}</b><span class="res ${cls}">${lab}</span></div>
      <div class="vs"><span>노드 <b>${nr}/${c.nodes.length}</b></span><span>파드 <b>${c.pods.running}/${c.pods.total}</b></span>${c.pods.problem ? `<span class="bad">문제 <b>${c.pods.problem}</b></span>` : ""}${c.role === "supervisor" ? `<span>클러스터 <b>${c.clusters.length}</b></span>` : ""}</div>
      <div class="mini">${esc(c.discovered_by ? `자동 발견 · ${c.discovered_by}` : "수동 등록")} · ${esc(c.target || "")}</div>
      ${c.last_error ? `<div class="mini bad">${esc(c.last_error.slice(0, 160))}</div>` : ""}</button>`;
  }
  function renderDetail() {
    const box = $("#vks-detail"); if (!box || !st.d) return;
    const c = st.d.clusters.find(x => x.name === st.sel); if (!c) { box.innerHTML = ""; return; }
    const pods = (st.pods && st.pods.pods) || [];
    const nss = [...new Set(pods.map(p => p.ns))].sort();
    const isBad = p => BADP.has(p.reason) || ["Failed", "Pending", "Unknown"].includes(p.phase) || (p.phase === "Running" && p.ready.split("/")[0] !== p.ready.split("/")[1]);
    const q = st.q.toLowerCase();
    const rows = pods.filter(p => (!st.ns || p.ns === st.ns) && (!st.onlyBad || isBad(p)) && (!q || `${p.ns}/${p.name} ${p.node}`.toLowerCase().includes(q)));
    const tabs = [["map", "구성도"], ["pods", `파드 ${pods.length}`], ["nodes", `노드 ${c.nodes.length}`]].concat(c.role === "supervisor" ? [["clusters", `워크로드 클러스터 ${c.clusters.length}`]] : []);
    if (st.tab === "map" && st.mapFor === c.name && $("#vks-map")) return;          // 구성도는 자동 새로 고침으로 다시 그리지 않음(보던 위치 유지)
    box.innerHTML = `<div class="vks-tabs">${tabs.map(([k, l]) => `<button class="${st.tab === k ? "on" : ""}" data-tab="${k}">${l}</button>`).join("")}
        <span class="mini">${esc(c.cluster)} · 갱신 ${c.updated ? age(c.updated) + " 전" : "-"}${c.log_namespaces && c.log_namespaces.length ? ` · 파드 로그 실시간 수집: ${esc(c.log_namespaces.join(", "))}` : ""}</span></div>
      ${st.tab === "map" ? `<div id="vks-map"></div>` : st.tab === "pods" ? `<div class="vks-filter"><select id="vks-ns"><option value="">전체 네임스페이스</option>${nss.map(n => `<option ${n === st.ns ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
          <input id="vks-q" placeholder="파드·노드 검색" value="${esc(st.q)}"><label class="chk"><input type="checkbox" id="vks-bad" ${st.onlyBad ? "checked" : ""}> 문제 파드만</label></div>
        <table class="plat vks-t"><thead><tr><th>네임스페이스</th><th>파드</th><th>노드</th><th>상태</th><th>준비</th><th>재시작</th><th>경과</th><th></th></tr></thead><tbody>
        ${rows.slice(0, 1500).map(p => `<tr class="${isBad(p) ? "bad-row" : ""}"><td>${esc(p.ns)}</td><td><b>${esc(p.name)}</b>${p.owner ? `<div class="mini">${esc(p.owner)}</div>` : ""}</td><td>${esc(p.node || "-")}</td>
          <td>${esc(p.phase)}${p.reason ? ` <span class="${BADP.has(p.reason) ? "bad" : "mini"}">${esc(p.reason)}</span>` : ""}</td><td>${esc(p.ready)}</td><td>${p.restarts}</td><td>${age(p.age)}</td>
          <td><button class="btn-sm" data-log="${esc(p.ns)}|${esc(p.name)}|${esc((p.containers || []).join(","))}">로그</button></td></tr>`).join("") || '<tr><td colspan="8"><div class="empty small">표시할 파드 없음</div></td></tr>'}</tbody></table>
        ${rows.length > 1500 ? `<div class="mini">1,500개까지 표시(전체 ${rows.length})</div>` : ""}`
      : st.tab === "nodes" ? `<table class="plat vks-t"><thead><tr><th>노드</th><th>역할</th><th>Ready</th><th>압박</th><th>kubelet</th><th>OS</th><th>CPU / 메모리</th><th>경과</th><th></th></tr></thead><tbody>
        ${c.nodes.map(n => `<tr class="${n.ready !== "True" ? "bad-row" : ""}"><td><b>${esc(n.name)}</b>${n.unschedulable ? ' <span class="label warning">cordon</span>' : ""}</td><td>${esc(n.roles.join(", "))}</td>
          <td>${n.ready === "True" ? '<span class="res good">Ready</span>' : `<span class="res bad">${esc(n.ready)}</span>`}</td><td>${n.pressure.length ? `<span class="bad">${esc(n.pressure.join(", "))}</span>` : "-"}</td>
          <td>${esc(n.kubelet)}</td><td class="mini">${esc(n.os)}</td><td>${esc(n.cpu)} / ${esc(n.memory)}</td><td>${age(n.age)}</td>
          <td><button class="btn-sm" data-tail="${esc(n.name)}">로그</button></td></tr>`).join("") || '<tr><td colspan="9"><div class="empty small">노드 정보 없음(권한 또는 수집 대기)</div></td></tr>'}</tbody></table>`
      : `<table class="plat vks-t"><thead><tr><th>네임스페이스</th><th>클러스터</th><th>단계</th><th>Ready</th><th>버전</th><th>API 엔드포인트</th><th>경과</th></tr></thead><tbody>
        ${c.clusters.map(k => `<tr><td>${esc(k.ns)}</td><td><b>${esc(k.name)}</b></td><td>${esc(k.phase)}</td><td>${esc(k.ready || "-")}</td><td>${esc(k.version || "-")}</td><td class="mono">${esc(k.endpoint || "-")}</td><td>${age(k.age)}</td></tr>`).join("") || '<tr><td colspan="7"><div class="empty small">워크로드 클러스터 없음</div></td></tr>'}</tbody></table>`}`;
    if (st.tab === "map" && window.AIOPS_VKS_MAP) { st.mapFor = c.name; window.AIOPS_VKS_MAP($("#vks-map"), c.name); }
    const ns = $("#vks-ns"); if (ns) ns.onchange = e => { st.ns = e.target.value; renderDetail(); };
    const qi = $("#vks-q"); if (qi) qi.oninput = () => { st.q = qi.value; const pos = qi.selectionStart; renderDetail(); const n = $("#vks-q"); n.focus(); n.setSelectionRange(pos, pos); };
    const bd = $("#vks-bad"); if (bd) bd.onchange = e => { st.onlyBad = e.target.checked; renderDetail(); };
  }
  async function showLog(ns, pod, containers) {
    const cs = containers ? containers.split(",").filter(Boolean) : [];
    let cur = cs[0] || "", prev = false;
    const body = () => `<div class="vks-logbar">${cs.length > 1 ? `<select id="lg-c">${cs.map(c => `<option ${c === cur ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>` : `<span class="mini">${esc(cur)}</span>`}
      <label class="chk"><input type="checkbox" id="lg-p" ${prev ? "checked" : ""}> 이전 컨테이너(재시작 전)</label><button type="button" class="btn-sm" id="lg-r">다시 불러오기</button>
      <button type="button" class="btn-sm" id="lg-t">이 파드 실시간 보기</button></div><pre class="vks-log" id="lg-out">불러오는 중…</pre>`;
    const fetchLog = async m => {
      const out = m.querySelector("#lg-out"); out.textContent = "불러오는 중…";
      try {
        const r = await A.api("GET", `/api/vks/${encodeURIComponent(st.sel)}/log?` + new URLSearchParams({ns, pod, container: cur, tail: 500, previous: prev}));
        out.textContent = r.lines.join("\n") || "(로그 없음)"; out.scrollTop = out.scrollHeight;
      } catch (e) { out.textContent = e.message; }
    };
    await A.modal({title: `파드 로그 — ${ns}/${pod}`, wide: true, ok: "닫기", html: body(), onOpen: m => {
      const wire = () => {
        const c = m.querySelector("#lg-c"); if (c) c.onchange = e => { cur = e.target.value; fetchLog(m); };
        m.querySelector("#lg-p").onchange = e => { prev = e.target.checked; fetchLog(m); };
        m.querySelector("#lg-r").onclick = () => fetchLog(m);
        m.querySelector("#lg-t").onclick = () => { m.querySelector("[data-ok]").click(); location.hash = `#tail/${encodeURIComponent(pod)}`; };
      };
      wire(); fetchLog(m);
    }});
  }
  $("#vks-body").addEventListener("click", e => {
    const s = e.target.closest("[data-sel]"); if (s) { st.sel = s.dataset.sel; st.ns = ""; render(); loadPods(); return; }
    const t = e.target.closest("[data-tab]"); if (t) { st.tab = t.dataset.tab; st.mapFor = ""; renderDetail(); return; }
    const l = e.target.closest("[data-log]"); if (l) { const [ns, pod, cs] = l.dataset.log.split("|"); showLog(ns, pod, cs); return; }
    const tl = e.target.closest("[data-tail]"); if (tl) location.hash = `#tail/${encodeURIComponent(tl.dataset.tail)}`;
  });
  $("#vks-disc").onclick = async () => {
    $("#vks-disc").disabled = true;
    try { const r = await A.api("POST", "/api/vks/discover", {}); A.ok(`발견: 추가 ${r.added.length} · 변경 ${r.changed.length} · 제거 ${r.removed.length}`); load(); }
    catch (e) { A.fail("발견 실패", e); } finally { $("#vks-disc").disabled = false; }
  };
  $("#vks-reload").onclick = () => { st.mapFor = ""; load(); };
  window.AIOPS_VKS_SELECT = (name, tab) => { st.sel = name; st.tab = tab || "map"; st.ns = ""; st.mapFor = ""; render(); loadPods(); const d = $("#vks-detail"); if (d) d.scrollIntoView({block: "start"}); };
  $("#nav-vks").onclick = () => {
    open("drawer-vks"); load();
    clearInterval(st.timer); st.timer = setInterval(() => $("#drawer-vks").hidden ? clearInterval(st.timer) : load(), 20000);
  };
})();
