/* 성능 SLI(Isvara 4대 경합 지표) · Isvara iO 질의 — core.js(AIOPS) 이후 로드 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const SIG = [["cpu_ready", "CPU ready", "%", "cpu"], ["mem_latency", "메모리 latency", "%", "memory"],
               ["disk_latency", "디스크 latency", "ms", "storage"], ["net_dropped", "dropped packets", "개", "network"]];
  const BAND = {green: "양호", yellow: "주의", orange: "경고", red: "위험", none: "데이터 없음"};
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 60 ? `${Math.round(s)}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : `${Math.round(s / 3600)}시간 전`; };
  const num = v => v === null || v === undefined ? "-" : (Math.abs(v) >= 100 ? Math.round(v) : Math.round(v * 100) / 100);
  let st = {d: null, cluster: "", q: "", timer: null, iso: null, isoQ: "", isoA: ""};

  const chip = (sc, b) => `<span class="sli-chip ${b || "none"}" title="${BAND[b] || ""}">${sc === null || sc === undefined ? "–" : Math.round(sc)}</span>`;

  async function load() {
    try { st.d = await A.api("GET", `/api/sli?limit=500${st.cluster ? "&cluster=" + encodeURIComponent(st.cluster) : ""}`, undefined, {background: true}); }
    catch (e) { $("#sli-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    render();
  }

  function render() {
    const d = st.d, vc = d.vcenters[0];
    if (!d.vcenters.length) {
      $("#sli-body").innerHTML = `<div class="empty">vCenter 커넥터가 없습니다. 운영 설정 › 커넥터에서 vCenter 를 추가하면 5분마다 VM 성능 카운터로 SLI 를 계산합니다.</div>`;
      return;
    }
    const th = (vc && vc.thresholds) || {};
    const src = d.method.sources;
    const pend = d.vcenters.filter(v => !v.updated && !v.error);
    $("#sli-sub").textContent = `— VM ${d.total_vms}대 · 최근 ${Math.round(((vc && vc.window_s) || 300) / 60)}분 p${(vc && vc.percentile) || 99} · ` +
      d.vcenters.map(v => `${v.connector} ${v.updated ? ago(v.updated) : v.error ? "실패" : "수집 대기"}`).join(" · ");
    const clusters = d.clusters;
    const q = st.q.toLowerCase();
    const vms = d.vms.filter(v => !q || `${v.name} ${v.host} ${v.cluster}`.toLowerCase().includes(q));
    $("#sli-body").innerHTML = `
      <div class="sli-th">
        ${SIG.map(([k, l, u, s]) => `<a href="${esc(src[s])}" target="_blank" rel="noopener" class="sli-thc"><b>${l}</b><span>기준 ${num(th[k])}${u}</span></a>`).join("")}
        <div class="sli-cnt">${["red", "orange", "yellow", "green"].map(b => `<span class="${b}">${BAND[b]} ${d.counts[b] || 0}</span>`).join("")}</div>
      </div>
      ${d.vcenters.filter(v => v.error || (v.missing_counters || []).length).map(v => `<div class="sli-warn">${esc(v.connector)}: ${v.error ? "수집 실패 — " + esc(v.error) : "카운터 없음(해당 신호 제외): " + esc(v.missing_counters.join(", "))}</div>`).join("")}
      ${pend.length ? `<div class="sli-warn info">${pend.map(v => esc(v.connector)).join(", ")}: 첫 계산 대기 중(토폴로지 수집 후 최대 5분)</div>` : ""}
      <h4 class="sli-h">클러스터 KPI <small>평균이 아니라 VM 별 신호로 — 빨강 1대 = 초록 8대 가중 · 페일오버는 가장 큰 호스트 N대 장애 기준(현재 사용량)</small></h4>
      <div class="sli-grid">${clusters.length ? clusters.map(c => clusterCard(c, th)).join("") : '<div class="empty">계산된 클러스터 없음</div>'}</div>
      <h4 class="sli-h">VM <small>점수 낮은 순 · 4개 신호 중 가장 나쁜 값이 VM 점수</small>
        <span class="sli-f"><select id="sli-cl"><option value="">전체 클러스터</option>${[...new Set(clusters.map(c => c.name))].map(n => `<option ${st.cluster === n ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
        <input id="sli-q" placeholder="VM·호스트 검색" value="${esc(st.q)}"></span></h4>
      ${vms.length ? `<table class="plat sli-t"><thead><tr><th>VM</th><th>클러스터 / 호스트</th><th>점수</th>${SIG.map(([, l, u]) => `<th>${l}<div class="mini">${u}</div></th>`).join("")}<th></th></tr></thead><tbody>
        ${vms.map(v => `<tr><td><b>${esc(v.name)}</b><div class="mini">${v.vcpu || "-"} vCPU</div></td><td>${esc(v.cluster || "-")}<div class="mini">${esc(v.host || "-")}</div></td>
          <td>${chip(v.score, v.band)}<div class="mini">${BAND[v.band] || ""}${v.worst ? " · " + esc((SIG.find(s => s[0] === v.worst) || [])[1] || "") : ""}</div></td>
          ${SIG.map(([k]) => { const s = v.signals[k] || {}; return `<td class="${s.band || ""}"><span class="sli-v">${num(s.value)}</span> ${chip(s.score, s.band)}</td>`; }).join("")}
          <td><button class="btn-sm" data-tail="${esc(v.name)}">로그</button></td></tr>`).join("")}
      </tbody></table>${d.total_vms > d.vms.length ? `<div class="mini">하위 ${d.vms.length}대만 표시(전체 ${d.total_vms}대)</div>` : ""}` : '<div class="empty">표시할 VM 없음</div>'}
      ${isoBox()}
      <div class="sli-note">${esc(d.method.formula)} · 밴드 양호 ≥75 · 주의 50–74 · 경고 25–49 · 위험 &lt;25 · dropped packets: ${esc(d.method.dropped_packets)}.
        기준·밴드 출처 <a href="${esc(src.defined_good)}" target="_blank" rel="noopener">Isvara Defined good</a> · <a href="${esc(src.ops_score)}" target="_blank" rel="noopener">Operations Score</a> · <a href="${esc(src.cluster_kpi)}" target="_blank" rel="noopener">Cluster KPI</a>. ${esc(d.method.note)}</div>`;
    $("#sli-cl").onchange = e => { st.cluster = e.target.value; load(); };
    const qi = $("#sli-q"); qi.oninput = () => { st.q = qi.value; const p = qi.selectionStart; render(); const n = $("#sli-q"); n.focus(); n.setSelectionRange(p, p); };
    bindIso();
  }

  function clusterCard(c, th) {
    const b = c.bands || {}, tot = c.vms || 0, fo = c.failover || {};
    const bar = ["red", "orange", "yellow", "green"].map(k => tot && b[k] ? `<i class="${k}" style="flex:${b[k]}" title="${BAND[k]} ${b[k]}"></i>` : "").join("");
    const fov = {ok: ["견딤", "good"], at_risk: ["부족", "bad"], insufficient_hosts: ["호스트 부족", "bad"], standalone: ["단독 호스트", "mid"]}[fo.verdict] || ["-", "mid"];
    const sig = c.signals || {};
    const foTxt = fo.verdict === "standalone" ? `페일오버 <span class="res mid">해당 없음(단독 호스트)</span>` : null;
    return `<div class="sli-card ${c.band}">
      <div class="sli-ch"><b>${esc(c.name)}</b><span class="mini">${esc(c.connector)}</span>${chip(c.score, c.band)}</div>
      <div class="sli-bar">${bar || '<i class="none" style="flex:1"></i>'}</div>
      <div class="mini">VM ${tot} · 위험 ${b.red || 0} · 경고 ${b.orange || 0} · 주의 ${b.yellow || 0}</div>
      <div class="sli-sig">${SIG.map(([k, l, u]) => { const s = sig[k]; return s ? `<span title="최악 ${esc(s.worst_vm)} · 기준 초과 VM ${s.breach}">${l} <b class="${s.worst_score < 75 ? "bad" : ""}">${num(s.worst_value)}${u}</b>${s.breach ? ` <em>${s.breach}대</em>` : ""}</span>` : `<span class="mini">${l} -</span>`; }).join("")}</div>
      <div class="sli-fo">${foTxt || `N+${fo.tolerate || 1} 장애 시 <span class="res ${fov[1]}">${fov[0]}</span>`}
        ${foTxt ? "" : fo.cpu ? ` · CPU ${num(fo.cpu.used_pct_now)}%→${num(fo.cpu.used_pct_after)}% · 메모리 ${num(fo.mem.used_pct_now)}%→${num(fo.mem.used_pct_after)}%` : esc(fo.detail ? " · " + fo.detail : "")}
        ${c.ha ? `<span class="mini"> · HA${c.ha_admission ? "·승인 제어" : " (승인 제어 꺼짐)"}</span>` : '<span class="mini"> · HA 꺼짐</span>'}</div>
    </div>`;
  }

  // ---------------------------------------------------------------- Isvara iO
  function isoBox() {
    const s = st.iso;
    if (!s) return "";
    if (!s.enabled) return `<div class="sli-iso off"><b>Isvara iO 질의</b> — 꺼져 있음. VCF·vSphere·vSAN 성능 가이드(isvara.io) 근거 답변을 쓰려면 다음을 <code>config.yaml</code>에 넣고 재시작하세요:
      <code>isvara: {enabled: true}</code> (외부 전송: 질문 문장만, 사내 프록시는 <code>isvara.proxy</code>). 켜면 AI 질의에도 성능 관련 질문일 때 근거로 붙습니다.</div>`;
    return `<div class="sli-iso"><b>Isvara iO에게 묻기</b> <span class="mini">isvara.io 가이드 근거 · 질문 문장만 외부 전송${s.last_error ? " · 최근 오류: " + esc(s.last_error) : ""}</span>
      <div class="sli-iso-q"><input id="iso-q" placeholder="예) CPU Usage(%)와 Utilization(%)이 다른 이유는?" value="${esc(st.isoQ)}"><button class="btn-sm solid" id="iso-go">묻기</button></div>
      <div id="iso-a">${st.isoA}</div></div>`;
  }
  function bindIso() {
    const go = $("#iso-go"); if (!go) return;
    const ask = async () => {
      const q = $("#iso-q").value.trim(); if (q.length < 3) return;
      st.isoQ = q;
      $("#iso-a").innerHTML = '<div class="mini">iO 답변 대기…</div>';
      try {
        const r = await A.api("POST", "/api/isvara/ask", {question: q});
        st.isoA = `<div class="sli-iso-a">${esc(r.answer).replace(/\n/g, "<br>")}</div>
          ${r.links.length ? `<div class="sli-iso-l">${r.links.map(l => `<a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.title)}</a>`).join("")}</div>` : ""}
          <div class="mini">출처: Isvara iO(isvara.io) — Broadcom/VMware 공식 문서가 아님${r.cached ? " · 캐시" : ""}</div>`;
        $("#iso-a").innerHTML = st.isoA;
      } catch (e) { $("#iso-a").innerHTML = `<div class="sli-warn">${esc(e.message)}</div>`; }
    };
    go.onclick = ask;
    $("#iso-q").onkeydown = e => { if (e.key === "Enter") ask(); };
    $("#iso-q").oninput = e => { st.isoQ = e.target.value; };
  }

  $("#sli-body").addEventListener("click", e => {
    const t = e.target.closest("[data-tail]");
    if (t) location.hash = `#tail/${encodeURIComponent(t.dataset.tail)}`;
  });
  $("#nav-sli").onclick = async () => {
    open("drawer-sli");
    try { st.iso = await A.api("GET", "/api/isvara/status", undefined, {background: true}); } catch { st.iso = null; }
    load();
    clearInterval(st.timer); st.timer = setInterval(() => $("#drawer-sli").hidden ? clearInterval(st.timer) : load(), 30000);
  };
  $("#sli-reload").onclick = load;
})();
