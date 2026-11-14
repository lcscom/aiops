/* 지식 — KB·TechDocs 라이브러리(md 묶음 색인) · 관련 문서(이상징후 카드) · 피드백 · 지식 공백
   서버: /api/knowledge(상태) · PUT /upload(zip) · POST /reindex · /search · /doc/{id} · POST /feedback · /gaps */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc, $ = s => document.querySelector(s);
  const CAN = p => A.can(p);
  const N = v => (v || 0).toLocaleString();
  const TYPE = {kb: "KB", techdoc: "TechDocs", doc: "문서", cve: "CVE", vmsa: "VMSA", guide: "가이드"};
  const ago = ts => { if (!ts) return "-"; const s = Date.now() / 1000 - ts; return s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : `${Math.round(s / 86400)}일 전`; };

  // 근거 문서 본문(증상·원인·해결·우회 구역, 코드 블록) → HTML
  const dedent = c => { const ls = c.replace(/^[a-z]*\n/, "").replace(/\s+$/, "").split("\n"); const m = Math.min(...ls.filter(l => l.trim()).map(l => l.match(/^ */)[0].length)); return ls.map(l => l.slice(isFinite(m) ? m : 0)).join("\n").trim(); };
  // 수집기 Markdown 인라인 표기 → HTML(이미 esc 된 문자열): \< 같은 이스케이프, **굵게**, `코드`, *기울임*, [글](https://…) 링크
  const inlineMd = h => h.replace(/\\([\\`*_{}\[\]()#+\-.!|~])/g, "$1").replace(/\\(&lt;|&gt;|&amp;)/g, "$1")
    .replace(/`([^`\n]{1,400})`/g, "<code>$1</code>").replace(/\*\*([^*\n]{1,300}?)\*\*/g, "<b>$1</b>")
    .replace(/(^|[\s(])\*([^*\n<>]{1,200}?)\*(?=[\s).,:;]|$)/gm, "$1<i>$2</i>")
    .replace(/\[([^\]\n]{1,200})\]\((https?:\/\/[^\s)]+)\)/g, (m, t, u) => `<a href="${u}" target="_blank" rel="noopener">${t}</a>`);
  function excerpt(t, max = 4000) {
    const s = String(t || "").slice(0, max);
    const parts = s.split(/```/);
    return parts.map((p, i) => i % 2 ? `<pre class="kn-code">${esc(dedent(p))}</pre>`
      : inlineMd(esc(p)).replace(/^\[(증상|원인|해결|우회|환경|추가 정보)\]\s*/gm, (_, k) => `<b class="kn-sec kn-${k}">${k}</b> `).replace(/\n{2,}/g, "<br>").replace(/\n/g, "<br>")).join("");
  }
  const DT = {"troubleshooting": "문제 해결", "information": "정보", "how-to": "절차", "howto": "절차", "release-notes": "릴리스 노트", "concept": "개념 설명", "reference": "참조", "landing": "목차", "task": "절차", "fix": "수정"};
  const dt = v => DT[String(v || "").replace(/^(kb|td|techdocs)-/, "")] || String(v || "").replace(/^(kb|td)-/, "");
  const badges = r => `${r.kb ? `<span class="label kn-kb">KB ${esc(r.kb)}</span>` : `<span class="label">${esc(TYPE[r.type] || r.type || "문서")}</span>`}
    ${r.product ? `<span class="label">${esc(r.product)}</span>` : ""}${r.doc_type ? `<span class="label kn-dt" title="문서 유형">${esc(dt(r.doc_type))}</span>` : ""}${r.lang && !["en", "ko"].includes(r.lang) ? `<span class="label" title="번역본">${esc(r.lang)}</span>` : ""}${(r.versions || []).length ? `<span class="label kn-ver" title="적용 버전">${esc(r.versions.slice(0, 4).join(" · "))}</span>` : ""}
    ${(r.sections || []).map(x => `<span class="kn-chip kn-${esc(x)}">${esc(x)}</span>`).join("")}`;
  const link = r => /^https?:/.test(r.url || "") ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title)}</a>` : esc(r.title);
  const fb = (r, aid) => String(r.doc_id || "").startsWith("lib:") && CAN("operate")
    ? `<span class="kn-fb"><button type="button" data-kfb="1" data-doc="${esc(r.doc_id)}" data-aid="${esc(aid || "")}" title="이 로그 패턴에 도움이 됨 — 다음 검색부터 위로">도움됨</button><button type="button" data-kfb="-1" data-doc="${esc(r.doc_id)}" data-aid="${esc(aid || "")}" title="관련 없음 — 다음 검색부터 아래로">무관</button></span>` : "";

  // 이상징후 카드의 '근거' 블록
  function refs(ai, a) {
    const r = Array.isArray(ai.references) ? ai.references : [];
    const warn = (ai.unverified_kb || []).length ? `<p class="kn-warn">근거 문서에 없는 KB 번호(${ai.unverified_kb.map(esc).join(", ")})가 답변에 있어 '확인 필요'로 표시했습니다.</p>` : "";
    if (!r.length) {
      const rel = Array.isArray(a.related) ? a.related : [];
      if (rel.length) return warn + `<p><span class="lab">관련 KB(자동)</span> <small style="color:var(--muted)">원문 로그와 비슷한 문서 — AI 판정의 인용 근거는 아님</small></p>
        <ul class="refs kn-refs">${rel.map(x => `<li>${badges(x)} ${link(x)}${String(x.doc_id || "").startsWith("lib:") ? ` <a href="#" data-kdoc="${esc(x.doc_id)}">전문</a>` : ""} ${fb(x, a.id)}</li>`).join("")}</ul>`;
      return warn + (a.refs && a.refs.length ? `<p class="conf">관련 문서 후보 ${a.refs.length}건 검색 · AI 가 증상과 맞지 않는다고 판단 <a href="#" data-kbopen="${esc(a.id)}">후보 보기</a></p>` : "");
    }
    return `<p><span class="lab">근거</span></p><ul class="refs kn-refs">${r.map(x => `<li>${badges(x)} ${link(x)} <small style="color:var(--muted)">· ${esc(x.pack_name || "")}${x.section ? " · 일치 구역 " + esc(x.section) : ""}</small> ${fb(x, a.id)}</li>`).join("")}</ul>${warn}`;
  }

  async function openForAnomaly(a) {
    const box = await A.modal({title: "관련 문서 — KB·TechDocs", ok: "", cancel: "닫기", wide: true,
      html: `<p class="modal-text"><b>${esc(a.title)}</b><br><small>${esc((a.event || {}).source || "")} · ${esc(String((a.event || {}).message || "").slice(0, 200))}</small></p><div id="kn-m" class="kn-list"><div class="empty">검색 중…</div></div>`,
      onOpen: async m => {
        try {
          const hits = await A.api("GET", `/api/knowledge/search?k=8&intent=analyze&anomaly_id=${encodeURIComponent(a.id)}&q=`);
          m.querySelector("#kn-m").innerHTML = hitsHtml(hits, a.id);
        } catch (e) { m.querySelector("#kn-m").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
      }});
    void box;
  }
  function hitsHtml(hits, aid) {
    return hits.length ? hits.map(h => `<div class="kn-hit"><div class="kn-h">${link(h)}<span class="gap"></span>${fb(h, aid)}</div>
      ${h.summary ? `<div class="kn-sum">${esc(h.summary)}</div>` : ""}<div class="kn-b">${badges(h)}<small>${esc(h.pack_name || "")}${h.updated ? " · 갱신 " + esc(h.updated) : ""}${h.relevance != null ? " · 관련도 " + Math.round(h.relevance * 100) + "%" : ""}</small></div>
      <details ${hits.indexOf(h) === 0 ? "open" : ""}><summary>${h.section ? "일치 구역: " + esc(h.section) : "본문"}${String(h.doc_id || "").startsWith("lib:") ? ` · <a href="#" data-kdoc="${esc(h.doc_id)}">전문</a>` : ""}</summary><div class="kn-x">${excerpt(h.text)}</div></details></div>`).join("")
      : `<div class="empty">관련 문서를 찾지 못했습니다. 운영 설정 › 지식에서 KB·TechDocs md 묶음을 올리거나, 아래 '지식 공백'에서 수집할 키워드를 확인하세요.</div>`;
  }
  async function openDoc(did) {
    try {
      const d = await A.api("GET", `/api/knowledge/doc/${encodeURIComponent(did.replace("lib:", ""))}`);
      await A.modal({title: d.kb ? `KB ${d.kb}` : (d.kind === "techdoc" ? "TechDocs" : "문서"), ok: "", cancel: "닫기", wide: true,
        html: `<p class="modal-text"><b>${link(d)}</b><br>${badges({...d, type: d.kind, sections: [...new Set(d.sections.map(x => x.role).filter(r => ["증상", "원인", "해결", "우회"].includes(r)))]})} <small>${d.updated ? "갱신 " + esc(d.updated) : ""}${d.segmentation === "inferred" ? " · 구역은 본문 순서로 추정" : ""}</small></p>
          ${d.summary ? `<p class="kn-sum">${esc(d.summary)}</p>` : ""}${(d.signatures || []).length ? `<div class="kn-sigs"><span class="lab">오류 문구</span>${d.signatures.map(x => `<code>${esc(x)}</code>`).join("")}</div>` : ""}
          <div class="kn-doc">${d.sections.map(s => `<h5>${esc(s.role || s.crumb || "")}</h5><div>${excerpt(s.text, 12000)}</div>`).join("")}</div>`});
    } catch (e) { A.fail("문서 열기 실패", e); }
  }
  document.addEventListener("click", async e => {
    const f = e.target.closest("[data-kfb]");
    if (f) {
      e.preventDefault(); const sib = f.parentElement.querySelectorAll("button");
      try { await A.api("POST", "/api/knowledge/feedback", {doc_id: f.dataset.doc, vote: Number(f.dataset.kfb), anomaly_id: f.dataset.aid || "", q: ($("#rag-q") || {}).value || ""});
        sib.forEach(b => b.classList.toggle("on", b === f)); A.ok(Number(f.dataset.kfb) > 0 ? "도움됨 — 같은 로그 패턴에서 우선 표시" : "무관 — 같은 로그 패턴에서 뒤로"); }
      catch (err) { A.fail("피드백 실패", err); }
      return;
    }
    const d = e.target.closest("[data-kdoc]"); if (d) { e.preventDefault(); openDoc(d.dataset.kdoc); return; }
    const o = e.target.closest("[data-kbopen]");
    if (o) { e.preventDefault(); const a = (window.AIOPS_STATE && window.AIOPS_STATE.anomalies.get(o.dataset.kbopen)) || {id: o.dataset.kbopen, title: "", event: {}}; openForAnomaly(a); }
  });

  // ------------------------------------------------------------ 지식 화면(드로어) — 라이브러리 상태·업로드·색인·지식 공백
  async function loadLib() {
    const el = $("#kn-lib"); if (!el) return;
    let s; try { s = await A.api("GET", "/api/knowledge", undefined, {background: true}); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    const j = s.job || {}, run = j.state === "indexing" || j.state === "embedding";
    const pct = j.total ? Math.round(j.done / j.total * 100) : 0;
    el.innerHTML = `<div class="kn-stat">
        <div><b>${N(s.docs)}</b><span>문서</span></div><div><b>${N(s.kb)}</b><span>KB</span></div><div><b>${N(s.techdoc)}</b><span>TechDocs</span></div>
        <div><b>${N(s.chunks)}</b><span>청크</span></div><div><b>${s.chunks ? Math.round(s.embedded / s.chunks * 100) : 0}%</b><span>벡터(${esc(s.vector_model || "BM25 전용")})</span></div>
        <div><b>${N(s.feedback)}</b><span>피드백</span></div></div>
      <div class="kn-row"><span>제품</span>${Object.entries(s.products || {}).map(([k, v]) => `<span class="label">${esc(k)} ${N(v)}</span>`).join("") || "<small>-</small>"}</div>
      <div class="kn-row"><span>원본</span>${(s.paths || []).map(p => `<code>${esc(p)}</code>`).join(" ") || "<small>없음 — md 묶음(zip)을 올리거나 config knowledge.paths 에 폴더 지정</small>"}</div>
      <div class="kn-row"><span>업로드</span>${Object.keys(s.roots || {}).filter(r => r.startsWith("upload:")).map(r => `<span class="label">${esc(r.slice(7))} ${N(s.roots[r])}${CAN("settings") ? ` <a href="#" data-kdel="${esc(r)}" title="삭제">✕</a>` : ""}</span>`).join("") || "<small>-</small>"}</div>
      <div class="kn-row"><span>색인</span>${run ? `<span class="kn-prog"><i style="width:${pct}%"></i></span> ${j.state === "embedding" ? `임베딩 ${N(j.embedded || 0)}` : `${N(j.done)}/${N(j.total)} · 변경 ${N(j.changed)}`}`
        : `마지막 ${ago(s.last_scan)}${j.changed != null ? ` · 변경 ${N(j.changed)} · 삭제 ${N(j.removed || 0)} · ${j.seconds ?? "-"}초` : ""}${j.errors ? ` · <span style="color:var(--crit)">오류 ${j.errors} (${esc(j.last_error || "")})</span>` : ""}${j.embed_error ? ` · <span style="color:var(--crit)">임베딩: ${esc(j.embed_error)}</span>` : ""}`}
        <small> · DB ${s.db_mb}MB · 벡터 ${s.vec_mb}MB</small></div>
      ${s.link ? `<div class="kn-row"><span>자동 연결</span>${s.link.enabled ? `미확인 이상징후 ${N(s.link.open)}건 중 AI 근거 ${N(s.link.with_ai_refs)} · 자동 연결 ${N(s.link.with_auto)}
        <small> · 지식 세대 ${N(s.gen)} · 마지막 ${ago(s.link.last_run)}${s.link.kb_refresh ? ` · 지식 갱신으로 재분석 ${N(s.link.kb_refresh)}건` : ""}</small>` : "<small>꺼짐(knowledge.auto_link)</small>"}</div>` : ""}`;
    return run;
  }
  async function loadGaps() {
    const el = $("#kn-gaps"); if (!el) return;
    try {
      const g = await A.api("GET", "/api/knowledge/gaps?days=7&limit=20", undefined, {background: true});
      el.innerHTML = g.items.length ? `<table class="kn-tbl"><thead><tr><th>심각도</th><th>패턴(최근 7일)</th><th>소스</th><th>건수</th><th>수집할 키워드</th></tr></thead><tbody>${g.items.map(x => `<tr>
          <td><span class="label solid ${esc(x.severity)}">${esc(x.severity)}</span></td><td title="${esc(x.sample)}">${esc(x.title)}</td><td>${esc(x.source || "")}</td><td>${N(x.count)}</td>
          <td>${(x.keywords || []).map(k => `<code class="kn-kw" data-kq="${esc(k)}">${esc(k)}</code>`).join(" ")}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">최근 7일 동안 근거 문서 없이 판정된 이상징후가 없습니다.</div>`;
    } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  async function loadRecent() {
    const el = $("#kn-recent"); if (!el) return;
    try {
      const mine = ($("#kn-mine") || {}).checked;
      const g = await A.api("GET", `/api/knowledge/recent?days=14&limit=40${mine ? "&mine=true" : ""}`, undefined, {background: true});
      const env = Object.entries(g.env || {}).filter(([, v]) => v.length).map(([k, v]) => `${esc(k)} ${esc(v.filter(x => !x.endsWith(".x")).join("/"))}`).join(" · ");
      el.innerHTML = `<div class="kn-row"><span>운영 버전</span>${env || "<small>수집된 버전 없음(vCenter·NSX·Avi 연결 후 표시)</small>"}</div>` + (g.items.length
        ? `<table class="kn-tbl"><thead><tr><th>갱신</th><th>문서</th><th>제품·버전</th><th>유형</th><th></th></tr></thead><tbody>${g.items.map(x => `<tr class="${x.applies && x.matched.length ? "kn-applies" : ""}">
          <td class="nowrap">${esc(x.updated)}</td><td>${x.kb ? `<span class="label kn-kb">KB ${esc(x.kb)}</span> ` : ""}<a href="#" data-kdoc="${esc(x.doc_id)}">${esc(x.title)}</a>${x.summary ? `<div class="mini">${esc(x.summary)}</div>` : ""}</td>
          <td>${esc(x.product)}${x.versions.length ? `<div class="mini">${esc(x.versions.slice(0, 4).join(" · "))}</div>` : ""}</td><td>${esc(dt(x.doc_type) || "-")}</td>
          <td class="nowrap">${x.applies ? (x.matched.length ? `<span class="res bad" title="운영 중인 제품·버전에 해당">버전 일치 ${esc(x.matched.filter(v => !v.endsWith(".x")).join("/") || x.matched.join("/"))}</span>` : `<span class="res mid" title="운영 중인 제품(문서에 적용 버전 표기 없음)">제품 일치</span>`) : ""}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">${mine ? "최근 14일 동안 운영 버전에 해당하는 갱신 문서가 없습니다." : "최근 14일 동안 갱신된 문서가 없습니다(front matter updated 필드 기준)."}</div>`);
    } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  document.addEventListener("change", e => { if (e.target.id === "kn-mine") loadRecent(); });
  let tmr;
  async function refresh() { const run = await loadLib(); clearTimeout(tmr); if (!$("#drawer-rag").hidden) tmr = setTimeout(refresh, run ? 2000 : 8000); }
  const nav = $("#nav-rag");
  if (nav) nav.addEventListener("click", () => { refresh(); loadGaps(); loadRecent(); });
  // ------------------------------------------------------------ 올리기: md 파일(여러 개)·폴더·zip·끌어다 놓기
  const MD_RX = /\.(md|markdown|mdx|txt)$/i;
  const isMeta = rel => rel.split("/").slice(0, -1).some(x => /^[_.]/.test(x)) || /(^|\/)\./.test(rel);
  async function uploadZip(f) {
    const box = $("#kn-up"); box.hidden = false;
    box.innerHTML = `<div class="kn-up-h">${esc(f.name)} 올리는 중… (${(f.size / 2 ** 20).toFixed(1)}MB)</div>`;
    try {
      const r = await fetch("/api/knowledge/upload", {method: "PUT", headers: {"X-Requested-With": "aiops", "X-Filename": encodeURIComponent(f.name), "Content-Type": "application/zip"}, body: f});
      const j = await r.json(); if (!r.ok) throw new Error(j.detail || r.statusText);
      box.innerHTML = `<div class="kn-up-h">zip <b>${esc(f.name)}</b> — ${j.files.toLocaleString()}개 파일, 색인 시작${j.skipped ? ` (md 아님 ${j.skipped}개 제외)` : ""}</div>`;
      A.ok("zip 업로드 완료 — 색인 중");
    } catch (err) { box.innerHTML = `<div class="kn-up-h bad">zip 업로드 실패: ${esc(err.message)}</div>`; A.fail("업로드 실패", err); }
    refresh();
  }
  // items = [{file, rel}] — 폴더면 rel = 폴더 안 경로, 묶음 이름 = 맨 위 폴더
  async function uploadFiles(items, coll) {
    const box = $("#kn-up"); box.hidden = false;
    const skip = items.filter(x => !MD_RX.test(x.rel) || isMeta(x.rel));
    const todo = items.filter(x => MD_RX.test(x.rel) && !isMeta(x.rel));
    if (!todo.length) { box.innerHTML = `<div class="kn-up-h bad">올릴 md·markdown·txt 파일이 없습니다${skip.length ? ` (제외 ${skip.length}개 — 형식이 다르거나 _catalog 같은 메타 폴더)` : ""}</div>`; return; }
    const res = []; let done = 0, fail = 0;
    const head = () => `<div class="kn-up-h">${done < todo.length ? "올리는 중" : "완료"} <b>${done}/${todo.length}</b>${fail ? ` · <span class="bad">실패 ${fail}</span>` : ""}${skip.length ? ` · 제외 ${skip.length}` : ""} · 묶음 <code>${esc(coll)}</code>
      <span class="kn-prog"><i style="width:${Math.round(done / todo.length * 100)}%"></i></span></div>`;
    const rowHtml = r => r.ok ? `<tr><td>✓</td><td>${r.kb ? `<span class="label kn-kb">KB ${esc(r.kb)}</span> ` : `<span class="label">${esc(TYPE[r.kind] || r.kind || "문서")}</span> `}<a href="#" data-kdoc="${esc(r.doc_id)}">${esc(r.title)}</a><div class="mini">${esc(r.rel)}</div></td>
        <td>${esc(r.product || "-")}${(r.versions || []).length ? `<div class="mini">${esc(r.versions.slice(0, 4).join(" · "))}</div>` : ""}</td>
        <td>${(r.sections || []).map(x => `<span class="kn-chip kn-${esc(x)}">${esc(x)}</span>`).join("") || '<span class="mini">구역 없음</span>'}${r.segmentation === "inferred" ? '<div class="mini">본문 순서로 추정</div>' : ""}</td></tr>`
      : `<tr class="bad"><td>✗</td><td>${esc(r.rel)}</td><td colspan="2">${esc(r.err)}</td></tr>`;
    const paint = () => { box.innerHTML = head() + (res.length ? `<table class="kn-tbl kn-uptbl"><thead><tr><th></th><th>문서</th><th>제품·버전</th><th>구역</th></tr></thead><tbody>${res.slice(-200).reverse().map(rowHtml).join("")}</tbody></table>${res.length > 200 ? `<div class="mini">최근 200건만 표시</div>` : ""}` : ""); };
    paint();
    let i = 0, last = 0;
    const worker = async () => {
      while (i < todo.length) {
        const it = todo[i++];
        try {
          const r = await fetch(`/api/knowledge/file?collection=${encodeURIComponent(coll)}`, {method: "PUT", body: it.file,
            headers: {"X-Requested-With": "aiops", "X-Filename": encodeURIComponent(it.file.name), "X-Relpath": encodeURIComponent(it.rel), "Content-Type": "text/markdown"}});
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(j.detail || r.statusText);
          res.push({ok: true, rel: it.rel, ...j});
        } catch (err) { fail++; res.push({ok: false, rel: it.rel, err: err.message}); }
        done++;
        if (Date.now() - last > 300 || done === todo.length) { last = Date.now(); paint(); }
      }
    };
    await Promise.all(Array.from({length: Math.min(4, todo.length)}, worker));
    paint();
    try { await A.api("POST", "/api/knowledge/reindex"); } catch { /* 임베딩·통계 갱신은 다음 주기에 */ }
    A.ok(`md ${done - fail}개 색인${fail ? ` · 실패 ${fail}` : ""}`);
    refresh(); loadRecent();
  }
  const collOf = items => { const top = (items[0] && items[0].rel.includes("/")) ? items[0].rel.split("/")[0] : ""; return top || "manual"; };
  document.addEventListener("change", async e => {
    const id = e.target.id;
    if (id === "kn-file") { const f = e.target.files[0]; if (f) await uploadZip(f); e.target.value = ""; return; }
    if (id === "kn-md") { const items = [...e.target.files].map(f => ({file: f, rel: f.name})); e.target.value = ""; await uploadFiles(items, "manual"); return; }
    if (id === "kn-dir") {
      const items = [...e.target.files].map(f => ({file: f, rel: f.webkitRelativePath || f.name})); e.target.value = "";
      const coll = collOf(items);
      // 묶음 이름 = 고른 폴더 이름, 저장 경로 = 그 아래 상대 경로(아카이브 구조 유지)
      await uploadFiles(items.map(x => ({file: x.file, rel: x.rel.split("/").slice(1).join("/") || x.rel})), coll);
    }
  });
  // 끌어다 놓기 — 파일·폴더(하위 전체)·zip
  const readEntry = (entry, path = "") => new Promise(res => {
    if (entry.isFile) { entry.file(f => res([{file: f, rel: path + f.name}]), () => res([])); return; }
    if (!entry.isDirectory) { res([]); return; }
    const rd = entry.createReader(), all = [];
    const next = () => rd.readEntries(async ents => {
      if (!ents.length) { const subs = await Promise.all(all.map(x => readEntry(x, path + entry.name + "/"))); res(subs.flat()); return; }
      all.push(...ents); next();
    }, () => res([]));
    next();
  });
  document.addEventListener("dragover", e => { const z = e.target.closest && e.target.closest("#kn-drop"); if (z) { e.preventDefault(); z.classList.add("on"); } });
  document.addEventListener("dragleave", e => { const z = e.target.closest && e.target.closest("#kn-drop"); if (z) z.classList.remove("on"); });
  document.addEventListener("drop", async e => {
    const z = e.target.closest && e.target.closest("#kn-drop"); if (!z) return;
    e.preventDefault(); z.classList.remove("on");
    if (!CAN("settings")) { A.fail("권한 없음", new Error("관리자만 올릴 수 있습니다")); return; }
    const entries = [...(e.dataTransfer.items || [])].map(x => x.webkitGetAsEntry && x.webkitGetAsEntry()).filter(Boolean);
    let items = entries.length ? (await Promise.all(entries.map(x => readEntry(x)))).flat() : [...e.dataTransfer.files].map(f => ({file: f, rel: f.name}));
    const zips = items.filter(x => /\.zip$/i.test(x.rel));
    for (const z2 of zips) await uploadZip(z2.file);
    items = items.filter(x => !/\.zip$/i.test(x.rel));
    if (!items.length) return;
    const dir = entries.length === 1 && entries[0].isDirectory;
    await uploadFiles(dir ? items.map(x => ({file: x.file, rel: x.rel.split("/").slice(1).join("/")})) : items, dir ? entries[0].name : "manual");
  });
  document.addEventListener("click", async e => {
    const b = e.target.closest("#kn-reindex,#kn-full"); if (b) { await A.api("POST", `/api/knowledge/reindex${b.id === "kn-full" ? "?full=true" : ""}`); A.ok("색인 시작"); refresh(); return; }
    const d = e.target.closest("[data-kdel]");
    if (d) { e.preventDefault(); if (!confirm(`업로드 '${d.dataset.kdel.slice(7)}' 와 색인을 삭제할까요?`)) return; await A.api("DELETE", `/api/knowledge/uploads/${encodeURIComponent(d.dataset.kdel.slice(7))}`); refresh(); return; }
    const k = e.target.closest("[data-kq]"); if (k) { const q = $("#rag-q"); if (q) { q.value = k.dataset.kq; q.dispatchEvent(new Event("input")); (A.reveal || (() => {}))(q, {block: "center"}); } }
  });
  // AI 답변 경량 마크다운 — 코드 블록·굵게·인라인 코드·번호 목록, [R#] 인용을 근거 링크로
  function mdLite(t, refs = []) {
    const by = {}; (refs || []).forEach(r => { by[r.ref] = r; });
    const cite = h => h.replace(/\[(R\d+|I\d+|W\d+)\]/g, (m, k) => by[k] ? (/^https?:/.test(by[k].url || "") ? `<a class="kn-cite" href="${esc(by[k].url)}" target="_blank" rel="noopener" title="${esc(by[k].title)}">${m}</a>` : `<span class="kn-cite" title="${esc(by[k].title)}">${m}</span>`) : m);
    return String(t || "").split(/```/).map((p, i) => i % 2 ? `<pre class="kn-code">${esc(dedent(p))}</pre>`
      : cite(esc(p).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`\n]+)`/g, "<code>$1</code>").replace(/^(#{1,4})\s+(.+)$/gm, "<b class='kn-mh'>$2</b>")
        .replace(/\[변경\]/g, "<span class='kn-chg'>변경</span>").replace(/\n/g, "<br>"))).join("");
  }
  window.AIOPS_KNOW = {refs, openForAnomaly, hitsHtml, excerpt, openDoc, mdLite, badges, link};
})();
