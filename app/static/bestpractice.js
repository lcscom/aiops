/* VMware 권장 구성 판독(2.28.0) — 클러스터별 권장 구성 / 부분 권장 / 권장 아님 + 규칙별 근거 문서 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const open = id => { $$(".drawer").forEach(d => { if (d.id !== id) d.hidden = true; }); $(`#${id}`).hidden = false; };
  const ST = {pass: "준수", partial: "부분", fail: "미준수", na: "판단 불가"};
  const VC = {ok: "권장 구성", partial: "부분 권장", not: "권장 아님"};
  const st = {d: null, sel: "", only: "", openR: new Set()};
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 3600 ? `${Math.round(s / 60)}분 전` : `${Math.round(s / 3600)}시간 전`; };

  async function load() {
    try { st.d = await A.api("GET", "/api/vcenter/bestpractice", undefined, {background: true}); }
    catch (e) { $("#bp-body").innerHTML = `<div class="empty">${esc(e.message || e)}</div>`; return; }
    render(); badge();
  }

  function render() {
    const d = st.d, box = $("#bp-body"); if (!d || !box) return;
    const R = Object.fromEntries(d.rules.map(r => [r.id, r]));
    const cls = d.vcenters.flatMap(v => v.clusters.map(c => ({...c, vc: v.connector})));
    const errs = d.vcenters.filter(v => v.error || (!v.clusters.length));
    if (!cls.length) { box.innerHTML = `<div class="empty">${errs.map(v => `${esc(v.connector)}: ${esc(v.error || "클러스터 없음")}`).join("<br>") || "vCenter 커넥터가 없습니다"}</div>`; return; }
    if (!st.sel || !cls.find(c => c.vc + "/" + c.cluster === st.sel)) st.sel = cls[0].vc + "/" + cls[0].cluster;
    const c = cls.find(x => x.vc + "/" + x.cluster === st.sel);
    const s = d.summary;
    const ring = (sc, v) => `<div class="bp-ring ${v}" style="--p:${sc ?? 0}"><b>${sc ?? "—"}</b><small>점</small></div>`;
    const head = `<div class="bp-sum">
      <div class="bp-k"><small>클러스터</small><b>${s.clusters}</b></div>
      <div class="bp-k ok"><small>권장 구성</small><b>${s.count.ok || 0}</b></div>
      <div class="bp-k partial"><small>부분 권장</small><b>${s.count.partial || 0}</b></div>
      <div class="bp-k not"><small>권장 아님</small><b>${s.count.not || 0}</b></div>
      <div class="bp-k"><small>평균 점수</small><b>${s.avg_score ?? "—"}</b></div>
      <p class="small muted">판정: 필수 항목이 하나라도 어긋나면 '권장 아님', 아니면 가중 점수(필수 3·권장 2·참고 1) 90 이상 '권장 구성'. VM 항목은 클러스터 안 VM 95% 이상 준수면 통과.</p></div>`;
    const list = `<div class="bp-cls">${cls.map(x => `<button class="bp-c ${x.verdict}${x.vc + "/" + x.cluster === st.sel ? " on" : ""}" data-bpc="${esc(x.vc + "/" + x.cluster)}">
        ${ring(x.score, x.verdict)}<div><b>${esc(x.cluster)}</b><small>${esc(x.vc)} · 호스트 ${x.hosts} · VM ${x.vms}${x.vsan ? ` · vSAN ${x.vsan_esa ? "ESA" : "OSA"}` : ""}</small>
        <span class="bp-v ${x.verdict}">${VC[x.verdict]}</span>${x.must_fail.length ? `<small class="bp-mf">필수 미준수 ${x.must_fail.length}</small>` : ""}</div></button>`).join("")}</div>`;
    const rows = c.results.filter(r => !st.only || r.status === st.only || (st.only === "bad" && (r.status === "fail" || r.status === "partial")));
    const lv = {must: "필수", should: "권장", may: "참고"};
    const table = `<div class="bp-tools"><b>${esc(c.cluster)}</b> <span class="bp-v ${c.verdict}">${VC[c.verdict]}</span> <span class="muted small">${c.score ?? "—"}점</span>
        <select id="bp-only"><option value="">전체 항목</option><option value="bad" ${st.only === "bad" ? "selected" : ""}>미준수·부분만</option><option value="na" ${st.only === "na" ? "selected" : ""}>판단 불가만</option></select>
        <button class="btn-sm" id="bp-csv">CSV</button></div>
      <table class="bp-t"><thead><tr><th>결과</th><th>수준</th><th>영역</th><th>권장 사항</th><th>현재</th><th>근거</th></tr></thead><tbody>
      ${rows.map(r => { const k = R[r.id]; const ok = st.openR.has(r.id);
        return `<tr class="bp-r ${r.status}" data-bpr="${r.id}"><td><span class="bp-s ${r.status}">${ST[r.status]}</span></td><td><span class="bp-l ${k.level}">${lv[k.level]}</span></td><td class="small">${esc(k.area)}</td>
          <td><b>${esc(k.title)}</b><div class="small muted">${esc(k.rec)}</div>${ok && r.entities.length ? `<div class="bp-ent">${r.entities.map(e => `<code>${esc(e)}</code>`).join(" ")}${r.n_entities > r.entities.length ? ` <span class="muted">외 ${r.n_entities - r.entities.length}</span>` : ""}</div>` : ""}</td>
          <td class="small">${esc(r.detail)}${r.entities.length ? ` <a href="#" class="small">${ok ? "접기" : `대상 ${r.n_entities}`}</a>` : ""}</td>
          <td class="small"><a href="${/^https?:\/\//.test(k.src[1] || "") ? esc(k.src[1]) : "#"}" target="_blank" rel="noopener noreferrer" title="${esc(k.src[0])}">${esc(k.src[0].length > 34 ? k.src[0].slice(0, 33) + "…" : k.src[0])}</a></td></tr>`; }).join("")}</tbody></table>
      <p class="small muted">점검 ${ago((d.vcenters.find(v => v.connector === c.vc) || {}).updated)} · VM 장치 정보 ${ago((d.vcenters.find(v => v.connector === c.vc) || {}).vm_collected)}(6시간마다, '지금 판독'으로 즉시). 문서 원문은 옮기지 않고 요지만 적었습니다 — 근거 링크에서 확인하세요.</p>`;
    box.innerHTML = head + `<div class="bp-wrap">${list}<div class="bp-main">${table}</div></div>`;
  }

  function csv() {
    const d = st.d, R = Object.fromEntries(d.rules.map(r => [r.id, r]));
    const rows = [["vcenter", "cluster", "verdict", "score", "rule", "level", "title", "status", "detail", "entities", "source"]];
    d.vcenters.forEach(v => v.clusters.forEach(c => c.results.forEach(r => rows.push([v.connector, c.cluster, VC[c.verdict], c.score ?? "", r.id, R[r.id].level, R[r.id].title, ST[r.status], r.detail, r.entities.join(" "), R[r.id].src[1]]))));
    const cell = x => { let t = String(x ?? ""); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
    const b = new Blob(["﻿" + rows.map(r => r.map(cell).join(",")).join("\r\n")], {type: "text/csv"});
    A.download("vmware-best-practice.csv", b);
  }

  async function badge() {
    try {
      const d = st.d || await A.api("GET", "/api/vcenter/bestpractice", undefined, {background: true});
      const n = (d.summary.count || {}).not || 0, b = $("#bp-badge");
      if (b) { b.hidden = !n; b.textContent = n; b.title = `권장 아님 클러스터 ${n}개`; }
    } catch { /* 로그인 전·권한 */ }
  }

  function wire() {
    const body = $("#bp-body");
    body.addEventListener("click", ev => {
      const c = ev.target.closest("[data-bpc]"); if (c) { st.sel = c.dataset.bpc; render(); return; }
      if (ev.target.id === "bp-csv") { csv(); return; }
      const r = ev.target.closest("[data-bpr]");
      if (r && ev.target.tagName === "A" && !ev.target.target) { ev.preventDefault(); const k = r.dataset.bpr; st.openR.has(k) ? st.openR.delete(k) : st.openR.add(k); render(); }
    });
    body.addEventListener("change", ev => { if (ev.target.id === "bp-only") { st.only = ev.target.value; render(); } });
    $("#bp-run").onclick = async () => {
      const b = $("#bp-run"); b.disabled = true; b.textContent = "판독 중…";
      try { const r = await A.api("POST", "/api/vcenter/bestpractice/run"); r.errors.length ? A.fail("일부 실패", r.errors.join("\n")) : A.ok("판독 완료", `vCenter ${r.ran}개`); }
      catch (e) { A.fail("판독 실패", e); }
      b.disabled = false; b.textContent = "지금 판독"; load();
    };
    $("#bp-reload").onclick = load;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("#nav-bp")) return;
    wire();
    $("#nav-bp").onclick = () => { open("drawer-bp"); load(); };
    setTimeout(badge, 5000); setInterval(async () => {          // 10분마다 새 값 — 열려 있는 화면도 함께 갱신
      try { st.d = await A.api("GET", "/api/vcenter/bestpractice", undefined, {background: true}); } catch { return; }
      badge(); if (!$("#drawer-bp").hidden) render();
    }, 600000);
  });
  window.AIOPS_BP = {load};
})();
