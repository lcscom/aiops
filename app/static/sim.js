/* 장애 시뮬레이터(2.39.0 → 2.40.0 단순화) — AI 체크봇 › 장애 시뮬레이터
   왼쪽 인벤토리에서 객체 이름을 누르면 '가상으로' 장애가 나고(⋯ 로 종류 바꾸기), 오른쪽에 영향이 바로 나온다.
   ⚠ 시뮬레이션 전용: 서버의 /api/checkbot/simulate 는 수집 자료의 복사본으로 계산만 한다. 이 화면에는 vCenter·ESXi·NSX 로 가는 명령이 없다. */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const st = {inv: null, fail: [], res: null, scn: null, podf: "", tab: "hc", q: "", open: {}, menu: "", filter: "", pick: "", err: "", seq: 0, pre: []};
  try { st.fail = JSON.parse(localStorage.getItem("aiops.sim") || "[]").slice(0, 12); } catch (e) { st.fail = []; }
  const save = () => { try { localStorage.setItem("aiops.sim", JSON.stringify(st.fail)); } catch (e) { /* 기억 못해도 동작 */ } };
  const ICON = {
    vc: '<path d="M3 4h18v12H3zM8 20h8M12 16v4"/>', dc: '<path d="M4 20V8l8-4 8 4v12M9 20v-6h6v6"/>', cluster: '<path d="M4 5h7v6H4zM13 5h7v6h-7zM4 13h7v6H4zM13 13h7v6h-7z"/>',
    host: '<path d="M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01"/>', vm: '<path d="M4 5h16v11H4zM9 20h6M12 16v4"/>',
    ds: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/>', edge: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    sw: '<rect x="3" y="8" width="18" height="8" rx="1.5"/><path d="M6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01"/>',
    fw: '<path d="M4 5h16v14H4zM4 10h16M4 15h16M10 5v5M14 10v5M8 15v4M16 15v4"/>', rtr: '<circle cx="12" cy="12" r="8"/><path d="M8 12h8M12 8v8M9 9l-1-1M15 15l1 1"/>',
    k8s: '<path d="M12 2.5l8.5 4v9.5L12 21.5 3.5 16V6.5z"/><circle cx="12" cy="12" r="3"/><path d="M12 5v4M12 15v4M6 8.5l3.5 2M14.5 13.5L18 15.5M6 15.5l3.5-2M14.5 10.5L18 8.5"/>',
    sup: '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 8h8v8H8z"/>', node: '<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9z"/>',
    lb: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v10M12 9l-7 8M12 9l7 8"/>',
    arr: '<rect x="4" y="3" width="16" height="18" rx="1.5"/><path d="M4 9h16M4 15h16M8 6h.01M8 12h.01M8 18h.01"/>', srv: '<rect x="4" y="4" width="16" height="7" rx="1"/><rect x="4" y="13" width="16" height="7" rx="1"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  };
  const ic = (k, c = "sm-ic") => `<svg class="${c}" viewBox="0 0 24 24" aria-hidden="true">${ICON[k]}</svg>`;
  // 결과 묶음 — 사람이 바로 읽는 4가지
  const BUCKET = [
    ["stop", "서비스 중단", ["down", "io", "net", "ext"], "다시 켜지지 않거나 I/O·네트워크·외부 통신이 끊김"],
    ["risk", "위험", ["maybe", "blocked"], "용량 부족으로 재시작 불확실 · vMotion 불가"],
    ["boot", "재부팅·잠깐 멈춤", ["restart", "pause"], "HA 가 다른 호스트에서 다시 켬 · I/O·통신이 잠깐 멈춤"],
    ["move", "무중단 이동", ["vmotion"], "vMotion 으로 옮겨짐"],
  ];
  const B_OF = {}; BUCKET.forEach(([b, , ss]) => ss.forEach(s => { B_OF[s] = b; }));
  const key = f => `${f.type}|${f.vcenter || ""}|${f.target}`;
  const has = (t, vc, tg) => st.fail.some(f => f.type === t && (f.vcenter || "") === (vc || "") && f.target === tg);
  const onObj = p => st.fail.find(f => (f.vcenter || "") === (p.vcenter || "") && f.target === p.target && (((st.inv || {}).actions || {})[p.kind] || []).some(a => a.type === f.type));
  const markOf = k => ((st.res || {}).marks || {})[k] || "";
  const OBJ = {failed: "장애", maint: "유지보수·업그레이드", net: "업링크 장애", full: "가득 참", degraded: "호스트 빠짐", affected: "영향", isolated: "업링크 전부 끊김", extlost: "외부 경로 끊김", halfnet: "업링크 1개"};

  async function loadTop() {
    // 지금 체크봇이 '실패'로 본 시나리오 — 처음 화면에서 눌러 바로 시뮬레이터로
    try { const d = await A.api("GET", "/api/checkbot?verdict=fail&limit=8&run=0", undefined, {background: true}); st.top = (d.results || []).map(r => [r, toFails(r)]).filter(x => x[1].length).slice(0, 4); }
    catch (e) { st.top = []; }
  }
  const SIMT = new Set(["host_down", "uplink_loss", "cluster_down", "ds_apd", "ds_full", "vcenter_upgrade", "edge_down", "switch_down", "device_down", "storage_down"]);
  function toFails(r) {
    if (r.type === "maint_plus_fail") { const hs = String(r.target).split(" + "); return hs.map((h, i) => ({type: i ? "host_maint" : "host_down", vcenter: r.vcenter || "", target: h})); }
    if (r.type === "switch_down") return String(r.target).split(" + ").map(t => ({type: "switch_down", vcenter: "", target: t}));
    if (r.type === "host_maint") return [{type: "host_maint", vcenter: r.vcenter || "", target: r.cluster || r.target}];
    return SIMT.has(r.type) ? [{type: r.type, vcenter: r.vcenter || "", target: r.target}] : [];
  }
  async function loadInv(force) {
    if (!st.top || force) loadTop().then(() => { if (!st.fail.length) draw(); });
    if (st.inv && !force) return;
    try { st.inv = await A.api("GET", "/api/checkbot/inventory", undefined, {background: true}); st.err = ""; }
    catch (e) { st.err = String(e.message || e); return; }
    const vcs = st.inv.vcenters, ncl = vcs.reduce((a, v) => a + v.datacenters.reduce((b, d) => b + d.clusters.length, 0), 0);
    vcs.forEach(v => { st.open[`vc:${v.name}`] ??= true; v.datacenters.forEach(d => { st.open[`dc:${v.name}/${d.name}`] ??= true; d.clusters.forEach(c => { st.open[`cluster:${v.name}/${c.name}`] ??= ncl <= 6; }); }); });
  }
  let timer = 0;
  function run() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const my = ++st.seq;
      if (st.scn) {                                       // 2.47.0 시나리오 라이브러리 — 서버가 대상·지식까지 붙여 계산
        try { const r = await A.api("POST", "/api/checkbot/library/run", {id: st.scn.id}, {background: true});
          if (my === st.seq) { st.res = r; st.err = ""; st.fail = (r.failures_in || []).map(f => ({type: f.type, vcenter: f.vcenter || "", target: f.target, label: f.label || f.type})); st.scn = {...st.scn, desc: r.desc, target: r.target, why_na: r.why_na}; } }
        catch (e) { if (my === st.seq) st.err = String(e.message || e); }
        if (my === st.seq) draw();
        return;
      }
      if (!st.fail.length) { st.res = null; draw(); return; }
      try { const r = await A.api("POST", "/api/checkbot/simulate", {failures: st.fail.map(({type, vcenter, target}) => ({type, vcenter, target}))}, {background: true}); if (my === st.seq) { st.res = r; st.err = ""; } }
      catch (e) { if (my === st.seq) st.err = String(e.message || e); }
      if (my === st.seq) draw();
    }, 100);
  }
  function setObj(p, type) {
    // 한 객체에는 장애 하나 — 같은 종류를 다시 고르면 해제, 다른 종류면 바꿔 끼움
    const cur = onObj(p);
    st.scn = null;
    st.fail = st.fail.filter(f => f !== cur);
    if (!cur || cur.type !== type) {
      if (st.fail.length >= 12) { A.fail("시뮬레이터", new Error("한 번에 12개까지 겹칠 수 있습니다")); return; }
      const a = (((st.inv || {}).actions || {})[p.kind] || []).find(x => x.type === type) || {};
      st.fail.push({type, vcenter: p.vcenter || "", target: p.target, label: a.label || type});
    }
    st.menu = ""; st.filter = ""; st.pick = ""; save(); draw(); run();
  }

  /* ---------- 트리 ---------- */
  function worst(vms) {
    let n = 0, b = "";
    const order = BUCKET.map(x => x[0]);
    vms.forEach(v => { const s = markOf(`vm:${v._vc}/${v.name}`); if (s && B_OF[s]) { n++; if (!b || order.indexOf(B_OF[s]) < order.indexOf(b)) b = B_OF[s]; } });
    return n ? `<span class="sm-dot b-${b}" title="영향 VM ${n}대">${n}</span>` : "";
  }
  function row(k, depth, icon, name, o = {}) {
    const m = markOf(k), p = o.pick, cur = p && onObj(p);
    const b = o.vm ? B_OF[m] || (m === "offline" ? "off" : "") : "";
    const caret = o.kids ? `<button type="button" class="sm-caret" data-tog="${esc(k)}" aria-label="${st.open[k] ? "접기" : "펼치기"}" aria-expanded="${!!st.open[k]}">${st.open[k] ? "▾" : "▸"}</button>` : `<span class="sm-caret"></span>`;
    const main = p
      ? `<button type="button" class="sm-name" data-hit='${esc(JSON.stringify(p))}' title="${esc(cur ? `${cur.label} — 눌러서 해제` : `눌러서 '${o.def}' 가정`)}${o.tip ? "\n" + esc(o.tip) : ""}">`
      : `<button type="button" class="sm-name sm-ro" ${o.kids ? `data-tog="${esc(k)}"` : ""} title="${esc(o.tip || name)}">`;
    return `<div class="sm-n ${m ? "m-" + m : ""} ${b ? "b-" + b : ""} ${cur ? "on" : ""}" style="--d:${depth}">${caret}${main}${ic(icon)}<span class="sm-t">${esc(name)}</span>
        ${cur ? `<span class="sm-pill">${esc(cur.label)}</span>` : m && OBJ[m] && !o.vm ? `<span class="sm-pill soft">${OBJ[m]}</span>` : ""}${o.extra || ""}</button>
      ${p && (((st.inv || {}).actions || {})[p.kind] || []).length > 1 ? `<button type="button" class="sm-more" data-menu="${esc(k)}" aria-label="장애 종류 고르기" aria-expanded="${st.menu === k}">⋯</button>` : ""}</div>
      ${st.menu === k && p ? menu(p, depth) : ""}`;
  }
  function menu(p, depth) {
    const acts = ((st.inv || {}).actions || {})[p.kind] || [];
    return `<div class="sm-menu" style="--d:${depth + 1}" role="menu">${acts.map(a => `<button type="button" role="menuitemradio" aria-checked="${has(a.type, p.vcenter, p.target)}" class="${has(a.type, p.vcenter, p.target) ? "on" : ""}" data-set='${esc(JSON.stringify({p, type: a.type}))}'>${has(a.type, p.vcenter, p.target) ? "● " : "○ "}${esc(a.label)}</button>`).join("")}</div>`;
  }
  const DEF = {vcenter: "중단·업그레이드", cluster: "전체 장애", host: "장애(PSOD·전원)", datastore: "APD/PDL", edge: "Edge 장애", switch: "스위치 장애", device: "장애", storage: "어레이 장애",
    supervisor: "컨트롤 플레인 장애", vks: "컨트롤 플레인 장애", vksnode: "노드 장애", avictrl: "노드 장애", avise: "SE 장애"};
  // 2.46.0 플랫폼 — Supervisor · VKS(컨트롤 플레인·워커 노드) · vSphere Pod · Avi(컨트롤러·SE·가상 서비스)
  function treePlat() {
    const P = st.inv.platform || {supervisors: [], vks: [], avi: []};
    let h = "";
    const where = x => x.host ? `<small class="sm-where">${esc(x.host.split(".")[0])}</small>` : `<small class="sm-where muted">VM 없음</small>`;
    if (P.supervisors.length) {
      h += sec("Supervisor", P.supervisors.length);
      for (const s of P.supervisors) {
        const k = `sup:${s.vcenter}/${s.name}`;
        h += row(k, 0, "sup", s.name, {kids: s.cp.length + s.pods.length, pick: {kind: "supervisor", vcenter: s.vcenter, target: s.name}, def: DEF.supervisor,
          extra: `<span class="sm-tag">CP ${s.cp.length}</span>${s.pods.length ? `<span class="sm-tag">Pod ${s.pods.length}</span>` : ""}`,
          tip: `${s.vcenter} · ${s.endpoint || ""}\n네임스페이스 ${s.namespaces.join(", ") || "—"}\nVKS ${s.vks.join(", ") || "—"}`});
        if (!st.open[k]) continue;
        for (const c of s.cp) h += row(`vm:${s.vcenter}/${c.name}`, 1, "vm", c.name, {vm: 1, extra: where(c), tip: "Supervisor 컨트롤 플레인 VM — 호스트 장애로 함께 계산"});
        for (const c of s.pods) h += row(`vm:${s.vcenter}/${c.name}`, 1, "node", c.name, {vm: 1, extra: `<span class="sm-tag">vSphere Pod</span>${where(c)}`});
      }
    }
    if (P.vks.length) {
      h += sec("VKS 클러스터", P.vks.length);
      for (const c of P.vks) {
        const k = `vks:/${c.cluster}`, cp = c.nodes.filter(n => n.cp).length;
        h += row(k, 0, "k8s", c.cluster, {kids: c.nodes.length, pick: {kind: "vks", vcenter: "", target: c.cluster}, def: DEF.vks,
          extra: `<span class="sm-tag">CP ${cp} · 워커 ${c.nodes.length - cp}</span>`,
          tip: `워크로드 ${c.workloads.filter(w => w.kind !== "ds" && w.kind !== "static").length}개 · Pod ${c.workloads.reduce((a, w) => a + w.pods.length, 0)}개${c.vsphere_cluster ? `\nvSphere 클러스터 ${c.vsphere_cluster}` : ""}`});
        if (!st.open[k]) continue;
        for (const n of c.nodes) h += row(`vksnode:/${c.cluster}/${n.name}`, 1, "node", n.name, {pick: {kind: "vksnode", vcenter: "", target: `${c.cluster}/${n.name}`}, def: DEF.vksnode,
          extra: `<span class="sm-tag">${n.cp ? "CP" : "워커"}</span>${where(n)}`, tip: `Pod ${n.pods}개${n.host ? ` · ESXi ${n.host}` : " · vCenter 에서 같은 이름 VM 을 못 찾음"}`});
      }
    }
    if (P.avi.length) {
      h += sec("Avi 로드밸런서", P.avi.length);
      for (const a of P.avi) {
        const k = `avi:/${a.name}`;
        h += row(k, 0, "lb", a.name, {kids: 1, extra: `<span class="sm-tag">VS ${a.vs.length}</span>`, tip: `컨트롤러 클러스터 ${a.state || "—"}`});
        if (!st.open[k]) continue;
        if (a.controllers.length) h += `<div class="sm-sub" style="--d:1">컨트롤러 클러스터</div>`;
        for (const c of a.controllers) h += row(`avictrl:/${a.name}/${c.name}`, 1, "srv", c.name, {pick: {kind: "avictrl", vcenter: "", target: `${a.name}/${c.name}`}, def: DEF.avictrl,
          extra: where(c), tip: `${c.role || ""} ${c.ip || ""}${c.vm ? "" : "\nvCenter 에서 같은 이름·IP 의 VM 을 못 찾음 — 호스트 장애와는 연결 안 됨"}`});
        const g = {};
        a.se.forEach(x => { (g[x.group || "—"] ??= []).push(x); });
        for (const [gn, lst] of Object.entries(g)) {
          h += `<div class="sm-sub" style="--d:1">SE 그룹 ${esc(gn)}</div>`;
          for (const x of lst) {
            const nvs = a.vs.filter(v => (v.ses || []).includes(x.name)).length || (x.vs || []).length;
            h += row(`avise:/${a.name}/${x.name}`, 1, "lb", x.name, {pick: {kind: "avise", vcenter: "", target: `${a.name}/${x.name}`}, def: DEF.avise,
              extra: `<span class="sm-tag">VS ${nvs}</span>${where(x)}`, tip: `가상 서비스 ${a.vs.filter(v => (v.ses || []).includes(x.name)).map(v => v.name).join(", ") || (x.vs || []).join(", ") || "—"}`});
          }
        }
      }
    }
    return h || `<p class="sm-hint">Supervisor·VKS·Avi 정보가 없습니다. vCenter 의 Supervisor 자동 발견, VKS 커넥터, Avi 커넥터를 켜면 나타납니다.</p>`;
  }
  function treeHC() {
    let h = "";
    for (const v of st.inv.vcenters) {
      const kv = `vc:${v.name}`;
      h += row(kv, 0, "vc", v.name, {kids: 1, pick: {kind: "vcenter", vcenter: v.name, target: v.host || v.name}, def: DEF.vcenter, tip: v.host});
      if (!st.open[kv]) continue;
      for (const d of v.datacenters) {
        const kd = `dc:${v.name}/${d.name}`;
        h += row(kd, 1, "dc", d.name || "데이터센터", {kids: 1});
        if (!st.open[kd]) continue;
        for (const c of d.clusters) {
          const kc = `cluster:${v.name}/${c.name}`;
          const all = c.hosts.flatMap(x => x.vms.map(y => ({...y, _vc: v.name})));
          h += row(kc, 2, "cluster", c.name, {kids: 1, pick: {kind: "cluster", vcenter: v.name, target: c.name}, def: DEF.cluster, extra: worst(all) + (c.ha ? "" : `<span class="sm-warn" title="HA 꺼짐">HA 꺼짐</span>`),
            tip: `호스트 ${c.hosts.length}대 · HA ${c.ha ? "켬" : "꺼짐"} · DRS ${c.drs ? "켬" : "꺼짐"}${c.vsan ? " · vSAN" : ""}`});
          if (!st.open[kc]) continue;
          for (const x of c.hosts) {
            const kh = `host:${v.name}/${x.name}`, vms = x.vms.map(y => ({...y, _vc: v.name}));
            h += row(kh, 3, "host", x.name, {kids: x.vms.length, pick: {kind: "host", vcenter: v.name, target: x.name}, def: DEF.host, extra: worst(vms),
              tip: `켜진 VM ${x.vms.filter(y => y.on).length}대${x.maint ? " · 지금 유지보수 중" : ""}${srvTip(x.name)}`});
            if (!st.open[kh]) continue;
            for (const y of x.vms) h += row(`vm:${v.name}/${y.name}`, 4, "vm", y.name, {vm: 1, extra: y.mgmt ? `<span class="sm-tag">${esc(y.mgmt)}</span>` : y.vks ? `<span class="sm-tag">VKS</span>` : "",
              tip: `${y.on ? "켜짐" : "꺼짐"} · ${y.vcpu} vCPU · ${y.mem_gb} GB${y.vks ? ` · VKS ${y.vks}` : ""}`});
          }
        }
      }
    }
    return h;
  }
  const srvTip = hn => { const v = (((st.inv || {}).phys || {}).servers || {})[hn]; return v && (v.model || v.bmc) ? `\n서버 ${[v.vendor, v.model].filter(Boolean).join(" ")}${v.serial ? ` · S/N ${v.serial}` : ""}${v.bmc ? ` · BMC ${v.bmc}` : ""}` : ""; };
  const sec = (t, n) => `<div class="sm-sec">${esc(t)}${n != null ? ` <small>${n}</small>` : ""}</div>`;
  function treeDS() {
    let h = "";
    const arrs = ((st.inv.phys || {}).storage) || [];
    if (arrs.length) {
      h += sec("외부 스토리지", arrs.length);
      for (const a of arrs) {
        const ka = `storage:/${a.name}`;
        h += row(ka, 0, "arr", a.name, {kids: a.datastores.length, pick: {kind: "storage", vcenter: "", target: a.name}, def: DEF.storage,
          extra: `<span class="sm-tag">${esc(a.kind === "nfs" ? "NFS" : "SAN")}${a.note ? " · 추정" : ""}</span>`,
          tip: `${a.kind === "nfs" ? "NFS 서버" : "SAN 어레이"} · 데이터스토어 ${a.datastores.length}개${a.note ? "\n데이터스토어 백엔드로 묶은 추정 — 설정 checkbot.external 로 지정 가능" : ""}${a.source === "설정" ? "\n설정에서 지정" : ""}`});
        if (st.open[ka]) for (const d of a.datastores) h += row(`ds:${d.vcenter}/${d.name}`, 1, "ds", d.name, {pick: {kind: "datastore", vcenter: d.vcenter, target: d.name}, def: DEF.datastore});
      }
      h += sec("데이터스토어");
    }
    for (const v of st.inv.vcenters) {
      h += row(`vcds:${v.name}`, 0, "vc", v.name, {});
      for (const d of v.datastores.filter(x => !x.local)) {
        h += row(`ds:${v.name}/${d.name}`, 1, "ds", d.name, {pick: {kind: "datastore", vcenter: v.name, target: d.name}, def: DEF.datastore,
          extra: `<span class="sm-bar" title="사용률 ${d.used_pct}%"><i style="width:${Math.min(100, d.used_pct)}%" class="${d.used_pct >= 85 ? "hi" : ""}"></i></span>`,
          tip: `${d.type} · ${(d.capacity_gb / 1000).toFixed(1)} TB · ${d.used_pct}% · 호스트 ${d.hosts} · VM ${d.vms}`});
      }
    }
    return h;
  }
  function treeNet() {
    const P = st.inv.phys || {}, ecs = st.inv.edge_clusters || [];
    let h = "";
    if ((P.devices || []).length) {
      h += sec("외부 장비(방화벽·라우터)", P.devices.length);
      for (const d of P.devices) h += row(`device:/${d.name}`, 0, d.kind === "firewall" ? "fw" : d.kind === "router" ? "rtr" : "sw", d.name,
        {pick: {kind: "device", vcenter: "", target: d.name}, def: DEF.device, extra: `<span class="sm-tag">${d.kind === "firewall" ? "방화벽" : d.kind === "router" ? "라우터" : "장비"}</span>`,
         tip: `연결 스위치 ${d.switches.join(", ") || "—"}${d.source === "설정" ? "\n설정에서 지정" : "\nLLDP 이웃으로 발견"}`});
    }
    if ((P.switches || []).length) {
      h += sec("물리 스위치", P.switches.length);
      let dom = null;
      for (const w of P.switches) {
        if (w.mlag && w.mlag !== dom) { h += `<div class="sm-sub" style="--d:0">${/^\d+$/.test(w.mlag) ? "vPC" : "MLAG"} ${esc(w.mlag)} 쌍</div>`; }
        dom = w.mlag || null;
        const kw = `switch:/${w.name}`;
        h += row(kw, w.mlag ? 1 : 0, "sw", w.name, {kids: w.hosts.length, pick: {kind: "switch", vcenter: "", target: w.name}, def: DEF.switch,
          extra: `${w.role ? `<span class="sm-tag">${esc(w.role)}</span>` : ""}`, tip: `${[w.vendor, w.model].filter(Boolean).join(" ")}${w.uplinks.length ? `\n위쪽: ${w.uplinks.join(", ")}` : ""}${w.hosts.length ? `\nESXi 연결 ${new Set(w.hosts.map(x => x.host)).size}대` : ""}`});
        if (st.open[kw]) {
          const by = {};
          w.hosts.forEach(x => { (by[x.host] ??= {vc: x.vcenter, nics: []}).nics.push(`${x.nic}${x.port ? "↔" + x.port : ""}${x.up ? "" : "(다운)"}`); });
          for (const [hn, x] of Object.entries(by)) h += row(`host:${x.vc}/${hn}`, (w.mlag ? 2 : 1), "srv", hn, {pick: {kind: "host", vcenter: x.vc, target: hn}, def: DEF.host,
            extra: `<small class="sm-where">${esc(x.nics.join(" "))}</small>`, tip: `물리 서버 — 누르면 전원·하드웨어 장애${srvTip(hn)}`});
        }
      }
    }
    if (ecs.length) {
      h += sec("NSX Edge", ecs.length);
      h += ecs.map(e => row(`edge:/${e.name}`, 0, "edge", e.name, {pick: {kind: "edge", vcenter: "", target: e.name}, def: DEF.edge, tip: e.edges.map(x => `${x.name} @ ${x.host || "?"}`).join("\n")})).join("");
    }
    return h || `<p class="sm-hint">스위치·방화벽·NSX Edge 정보가 없습니다. 네트워크 커넥터(Arista·Cisco·SNMP)와 vDS LLDP 를 켜면 물리 구성이 나타납니다. 호스트 업링크 장애는 호스트의 ⋯ 에서 고르세요.</p>`;
  }
  function search() {
    const q = st.q.toLowerCase(), out = [];
    for (const v of st.inv.vcenters) {
      for (const d of v.datacenters) for (const c of d.clusters) {
        if (c.name.toLowerCase().includes(q)) out.push(row(`cluster:${v.name}/${c.name}`, 0, "cluster", c.name, {pick: {kind: "cluster", vcenter: v.name, target: c.name}, def: DEF.cluster}));
        for (const x of c.hosts) {
          if (x.name.toLowerCase().includes(q)) out.push(row(`host:${v.name}/${x.name}`, 0, "host", x.name, {pick: {kind: "host", vcenter: v.name, target: x.name}, def: DEF.host}));
          for (const y of x.vms) if (y.name.toLowerCase().includes(q)) out.push(row(`vm:${v.name}/${y.name}`, 0, "vm", y.name, {vm: 1, tip: `${x.name} · ${c.name}`, extra: `<small class="sm-where">${esc(x.name)}</small>`}));
        }
      }
      for (const d of v.datastores) if (!d.local && d.name.toLowerCase().includes(q)) out.push(row(`ds:${v.name}/${d.name}`, 0, "ds", d.name, {pick: {kind: "datastore", vcenter: v.name, target: d.name}, def: DEF.datastore}));
    }
    const P = st.inv.phys || {};
    (P.switches || []).forEach(w => { if (w.name.toLowerCase().includes(q)) out.push(row(`switch:/${w.name}`, 0, "sw", w.name, {pick: {kind: "switch", vcenter: "", target: w.name}, def: DEF.switch})); });
    (P.devices || []).forEach(d => { if (d.name.toLowerCase().includes(q)) out.push(row(`device:/${d.name}`, 0, d.kind === "firewall" ? "fw" : "rtr", d.name, {pick: {kind: "device", vcenter: "", target: d.name}, def: DEF.device})); });
    (P.storage || []).forEach(a => { if (a.name.toLowerCase().includes(q)) out.push(row(`storage:/${a.name}`, 0, "arr", a.name, {pick: {kind: "storage", vcenter: "", target: a.name}, def: DEF.storage})); });
    const PL = st.inv.platform || {supervisors: [], vks: [], avi: []};
    PL.supervisors.forEach(x => { if (x.name.toLowerCase().includes(q)) out.push(row(`sup:${x.vcenter}/${x.name}`, 0, "sup", `Supervisor ${x.name}`, {pick: {kind: "supervisor", vcenter: x.vcenter, target: x.name}, def: DEF.supervisor})); });
    PL.vks.forEach(c => {
      if (c.cluster.toLowerCase().includes(q)) out.push(row(`vks:/${c.cluster}`, 0, "k8s", c.cluster, {pick: {kind: "vks", vcenter: "", target: c.cluster}, def: DEF.vks}));
      c.nodes.forEach(n => { if (n.name.toLowerCase().includes(q)) out.push(row(`vksnode:/${c.cluster}/${n.name}`, 0, "node", n.name, {pick: {kind: "vksnode", vcenter: "", target: `${c.cluster}/${n.name}`}, def: DEF.vksnode})); });
    });
    PL.avi.forEach(a => {
      a.controllers.forEach(c => { if (c.name.toLowerCase().includes(q)) out.push(row(`avictrl:/${a.name}/${c.name}`, 0, "srv", c.name, {pick: {kind: "avictrl", vcenter: "", target: `${a.name}/${c.name}`}, def: DEF.avictrl})); });
      a.se.forEach(x => { if (x.name.toLowerCase().includes(q)) out.push(row(`avise:/${a.name}/${x.name}`, 0, "lb", x.name, {pick: {kind: "avise", vcenter: "", target: `${a.name}/${x.name}`}, def: DEF.avise})); });
    });
    return out.slice(0, 200).join("") || `<p class="sm-hint">찾은 것이 없습니다.</p>`;
  }

  /* ---------- 결과 ---------- */
  const src = tag => { const p = tag.split(" · "); return /합산/.test(p[0]) ? p[0].replace(/^클러스터 /, "") : p.length > 1 ? p.slice(1).join(" · ") : tag; };
  const strip = t => { const m = /^\[(.+?)\]\s*(.*)$/.exec(t); return m ? [m[1], m[2]] : ["", t]; };
  function result() {
    const r = st.res;
    const chips = st.fail.map(f => `<span class="sm-chip">${esc(f.label || f.type)} · <b>${esc(f.target)}</b><button type="button" data-rm="${esc(key(f))}" aria-label="${esc(f.target)} 가정 해제">✕</button></span>`).join("");
    if (!st.fail.length && !st.scn) return empty();
    const scb = st.scn ? `<div class="sm-scn"><small>시나리오 라이브러리 · ${esc(st.scn.id)}</small><b>${esc(st.scn.title)}</b>${st.scn.desc ? `<span>${esc(st.scn.desc)}</span>` : ""}${st.scn.target ? `<span>대상 <b>${esc(st.scn.target)}</b> — 가정을 바꾸면 일반 시뮬레이션으로 바뀝니다</span>` : ""}</div>` : "";
    const head = scb + `<div class="sm-chips">${chips}<button type="button" class="sm-clear" id="sm-clear">모두 해제</button></div>`;
    if (r && r.applicable === false) return head + `<p class="sm-hint">${esc(r.why_na || "이 환경에 해당 없음")}</p>`;
    if (!r) return head + `<p class="sm-hint">계산 중…</p>`;
    const c = r.counts || {}, n = b => BUCKET.find(x => x[0] === b)[2].reduce((a, s) => a + (c[s] || 0), 0);
    const tiles = BUCKET.map(([b, l, , d]) => `<button type="button" class="sm-tile b-${b} ${st.filter === b ? "on" : ""} ${n(b) ? "" : "zero"}" data-flt="${b}" title="${esc(d)}"><b>${n(b)}</b><span>${l}</span></button>`).join("");
    const F = r.findings.filter(f => f.sev === "fail"), W = r.findings.filter(f => f.sev === "warn"), P = r.findings.filter(f => f.sev === "pass");
    const top = (F.length ? F : W).slice(0, 3);
    const line = f => { const [tag, t] = strip(f.text); return `<li class="s-${f.sev}">${tag ? `<span class="sm-src">${esc(src(tag))}</span>` : ""}${esc(t)}</li>`; };
    const vms = r.vms.filter(v => !st.filter || B_OF[v.state] === st.filter);
    const pst = ((r.platform || {}).counts || {}).stop || 0;
    const head2 = n("stop") ? ["bad", `VM ${n("stop")}대 서비스 중단${pst ? ` · 워크로드·VIP ${pst}개 중단` : ""}`] : pst ? ["bad", `워크로드·VIP ${pst}개 중단`] : r.verdict === "fail" ? ["bad", "버티지 못합니다 — 재시작·이중화가 보장되지 않음"]
      : r.verdict === "warn" ? ["warn", "멈추지는 않지만 위험합니다"] : ["ok", "받아냅니다"];
    const pods = (r.vks.clusters || []).reduce((a, k) => a + k.pods, 0);
    return `${head}
      <div class="sm-head ${head2[0]}"><b>${head2[1]}</b><span>켜진 VM ${r.vms_on}대 영향${r.services.length ? ` · 관리 구성요소 ${r.services.length}` : ""}${pods ? ` · VKS 파드 ${pods}` : ""}</span></div>
      <div class="sm-tiles">${tiles}</div>
      ${top.length ? `<h5 class="sm-h">왜</h5><ul class="sm-why">${top.map(line).join("")}</ul>` : ""}
      ${tline(r)}
      ${map(r, vms)}
      ${plat(r)}
      ${r.services.length || (r.vks.clusters || []).length ? `<h5 class="sm-h">함께 영향받는 것</h5><div class="sm-svc">${r.services.map(s => `<span title="${esc(s.impact)}">${esc(s.kind)} <b>${esc(s.name)}</b></span>`).join("")}${(r.vks.clusters || []).map(k => `<span title="${esc(k.namespaces.join(", "))}">VKS <b>${esc(k.cluster)}</b> 노드 ${k.nodes.length}/${k.nodes_total}${k.control_plane_lost.length ? ` · CP ${k.control_plane_lost.length}/${k.control_plane_total}` : ""}</span>`).join("")}</div>` : ""}
      ${r.actions.length ? `<details class="sm-det"><summary>할 일 ${r.actions.length}</summary><ol>${r.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ol></details>` : ""}
      <details class="sm-det"><summary>판단 근거 전체 ${r.findings.length} <small>(실패 ${F.length} · 주의 ${W.length} · 통과 ${P.length})</small></summary><ul class="sm-why all">${F.concat(W, P).map(line).join("")}</ul></details>
      <details class="sm-det"><summary>VM 목록 ${vms.length}${st.filter ? ` <small>(${esc(BUCKET.find(x => x[0] === st.filter)[1])}만)</small>` : ""}</summary>${table(vms)}</details>`;
  }
  const PB = {stop: ["stop", "중단"], risk: ["risk", "위험"], boot: ["boot", "잠깐 중단"], ok: ["move", "계속"]};
  // 2.48.0 시간에 따른 영향 — 즉시 / ~1분 / ~5분 / 복구 전까지 / 복구 후
  function tline(r) {
    const t = r.timeline; if (!t || !t.phases) return "";
    const mx = Math.max(1, ...t.phases.map(p => p.vms + p.pods + p.vips));
    if (!t.phases[0].vms && !t.phases[0].pods && !t.phases[0].vips) return "";
    const fmt = m => m >= 120 ? `${(m / 60).toFixed(m >= 600 ? 0 : 1)}시간` : `${m}분`;
    return `<h5 class="sm-h">시간에 따른 영향 <small>VM 다운타임 합 약 ${fmt(t.vm_minutes[0])}${t.vm_minutes[1] !== t.vm_minutes[0] ? `~${fmt(t.vm_minutes[1])}` : ""} (VM 대수 × 멈춘 시간의 합)</small></h5>
      <div class="sm-tl">${t.phases.map(p => {
        const tot = p.vms + p.pods + p.vips;
        return `<div class="sm-tlc ${tot ? "" : "zero"}" title="${esc(p.desc)}"><small>${esc(p.t)}</small>
          <div class="sm-tlbar"><i class="b-stop" style="height:${Math.round(p.vms / mx * 100)}%"></i><i class="b-pod" style="height:${Math.round(p.pods / mx * 100)}%"></i><i class="b-vip" style="height:${Math.round(p.vips / mx * 100)}%"></i></div>
          <b>${p.vms}</b><span>VM</span>${p.pods ? `<span>Pod ${p.pods}</span>` : ""}${p.vips ? `<span>VIP ${p.vips}</span>` : ""}</div>`; }).join("")}</div>
      <p class="sm-hint">${esc(t.assume)} · 칸에 마우스를 올리면 그 시점 설명</p>`;
  }
  const PODST = {stuck: ["stop", "중단(다시 배치 못 함)"], unsure: ["risk", "재시작 불확실"], frozen: ["risk", "계속(복구·변경 불가)"], gone: ["boot", "노드와 함께 멈춤"],
    back: ["boot", "HA 로 돌아옴"], resched: ["boot", "다른 노드에 다시 배치"], kept: ["move", "계속"]};
  function pods(r) {
    const ps = ((r.platform || {}).pods) || [];
    if (!ps.length) return "";
    const ord = Object.keys(PODST), c = {};
    ps.forEach(p => { c[p.state] = (c[p.state] || 0) + 1; });
    const list = ps.filter(p => !st.podf || p.state === st.podf).sort((a, b) => ord.indexOf(a.state) - ord.indexOf(b.state) || (a.cluster + a.ns + a.pod).localeCompare(b.cluster + b.ns + b.pod));
    return `<details class="sm-det" open><summary>영향받는 Pod ${ps.length}개 <small>${ord.filter(k => c[k]).map(k => `${PODST[k][1]} ${c[k]}`).join(" · ")}</small></summary>
      <div class="sm-podf">${ord.filter(k => c[k]).map(k => `<button type="button" class="${st.podf === k ? "on" : ""}" data-podf="${k}"><span class="sm-st b-${PODST[k][0]}">${PODST[k][1]}</span> ${c[k]}</button>`).join("")}</div>
      <div style="overflow-x:auto;max-height:420px"><table class="dr-t"><thead><tr><th>결과</th><th>클러스터</th><th>네임스페이스/Pod</th><th>워크로드</th><th>노드·호스트</th><th>설명</th></tr></thead><tbody>
      ${list.slice(0, 1000).map(p => `<tr><td><span class="sm-st b-${(PODST[p.state] || ["off"])[0]}">${esc((PODST[p.state] || [, p.state])[1])}</span></td><td class="small">${esc(p.cluster)}</td>
        <td class="mono small">${esc(p.ns ? p.ns + "/" : "")}${esc(p.pod)}</td><td class="small">${esc(p.workload)} <span class="muted">${esc({deploy: "Deployment", sts: "StatefulSet", ds: "DaemonSet", static: "정적", pod: "Pod", "vsphere-pod": ""}[p.kind] || "")}</span></td>
        <td class="mono small">${esc(p.node)}</td><td class="small">${esc(p.text)}</td></tr>`).join("")}</tbody></table></div>
      ${list.length > 1000 ? `<p class="sm-hint">외 ${list.length - 1000}개 — 결과로 걸러 보세요</p>` : ""}</details>`;
  }
  function plat(r) {
    const it = ((r.platform || {}).items) || [];
    if (!it.length) return pods(r);
    const ord = ["stop", "risk", "boot", "ok"], c = (r.platform || {}).counts || {};
    const s2 = it.slice().sort((a, b) => ord.indexOf(a.state) - ord.indexOf(b.state));
    return `<h5 class="sm-h">VKS·Supervisor·Avi 영향 <small>${ord.filter(k => c[k]).map(k => `${PB[k][1]} ${c[k]}`).join(" · ")}</small></h5>
      <ul class="sm-plat">${s2.slice(0, 60).map(i => `<li><span class="sm-st b-${PB[i.state][0]}">${PB[i.state][1]}</span><span class="sm-pk">${esc(i.kind)}</span><b class="mono">${esc(i.name)}</b><small>${esc(i.text)}</small></li>`).join("")}</ul>
      ${s2.length > 60 ? `<p class="sm-hint">외 ${s2.length - 60}개</p>` : ""}${pods(r)}`;
  }
  function map(r, vms) {
    // 영향 지도 — 클러스터 › 호스트 상자 안에 영향받는 VM 을 칸으로. 칸을 누르면 그 VM 의 원인
    if (!vms.length) return "";
    const g = {};
    vms.forEach(v => { ((g[`${v.vcenter}|${v.cluster}`] ??= {})[v.host] ??= []).push(v); });
    const hostMark = (vc, h) => markOf(`host:${vc}/${h}`);
    const sel = st.pick && vms.find(v => `${v.vcenter}/${v.name}` === st.pick);
    return `<h5 class="sm-h">영향 지도 <small>칸 하나 = VM 한 대 · 눌러서 원인 보기</small></h5><div class="sm-map">${Object.entries(g).map(([k, hs]) => {
      const [vc, cl] = k.split("|");
      return `<div class="sm-cl"><div class="sm-cln">${ic("cluster")}${esc(cl || "—")}</div><div class="sm-hosts">${Object.entries(hs).map(([h, list]) => {
        const hm = hostMark(vc, h);
        return `<div class="sm-h1 ${hm ? "m-" + hm : ""}"><div class="sm-hn" title="${esc(h)}">${esc(h.split(".")[0])}${hm && OBJ[hm] ? ` <i>${OBJ[hm]}</i>` : ""}</div><div class="sm-cells">${list.map(v =>
          `<button type="button" class="sm-cell b-${B_OF[v.state] || "off"} ${st.pick === `${v.vcenter}/${v.name}` ? "on" : ""}" data-pick="${esc(`${v.vcenter}/${v.name}`)}" title="${esc(`${v.name} — ${v.state_label}`)}" aria-label="${esc(`${v.name} ${v.state_label}`)}"></button>`).join("")}</div></div>`;
      }).join("")}</div></div>`;
    }).join("")}</div>
    ${sel ? `<div class="sm-pickd"><b class="mono">${esc(sel.name)}</b> <span class="sm-st b-${B_OF[sel.state] || "off"}">${esc(sel.state_label)}</span> <small class="muted">${esc(sel.host)} · ${sel.vcpu} vCPU · ${sel.mem_gb} GB</small><div class="small">${sel.by.map(esc).join("<br>")}</div></div>` : ""}`;
  }
  function table(vms) {
    if (!vms.length) return `<p class="sm-hint">해당 VM 이 없습니다.</p>`;
    return `<div style="overflow-x:auto"><table class="dr-t"><thead><tr><th>VM</th><th>결과</th><th>호스트</th><th>원인</th></tr></thead><tbody>${vms.slice(0, 500).map(v =>
      `<tr><td class="mono small">${esc(v.name)}</td><td><span class="sm-st b-${B_OF[v.state] || "off"}">${esc(v.state_label)}</span></td><td class="small">${esc(v.host)}</td><td class="small">${v.by.map(esc).join("<br>")}</td></tr>`).join("")}</tbody></table></div>`;
  }
  function empty() {
    const inv = st.inv; if (!inv || !inv.vcenters.length) return `<p class="sm-hint">vCenter 토폴로지가 아직 없습니다.</p>`;
    const nh = x => x.datacenters.reduce((a, d) => a + d.clusters.reduce((b, c) => b + c.hosts.length, 0), 0);
    const v = inv.vcenters.slice().sort((a, b) => nh(b) - nh(a))[0], cl = ((v.datacenters[0] || {}).clusters || [])[0];
    const hs = cl ? cl.hosts.slice().sort((a, b) => b.vms.length - a.vms.length) : [];
    const ds = v.datastores.filter(d => !d.local).sort((a, b) => b.vms - a.vms)[0];
    const P = [];
    if (hs[0]) P.push(["호스트 한 대가 꺼지면", `${hs[0].name}`, [{type: "host_down", vcenter: v.name, target: hs[0].name, label: "장애(PSOD·전원)"}]]);
    if (hs[1]) P.push(["패치 중에 다른 호스트가 죽으면", `${hs[1].name} 유지보수 + ${hs[0].name} 장애`, [{type: "host_maint", vcenter: v.name, target: hs[1].name, label: "유지보수 모드"}, {type: "host_down", vcenter: v.name, target: hs[0].name, label: "장애(PSOD·전원)"}]]);
    if (ds) P.push(["스토리지 경로가 다 끊기면", `${ds.name} APD`, [{type: "ds_apd", vcenter: v.name, target: ds.name, label: "APD/PDL"}]]);
    P.push(["vCenter 를 업그레이드하면", v.host || v.name, [{type: "vcenter_upgrade", vcenter: v.name, target: v.host || v.name, label: "중단·업그레이드"}]]);
    if (cl) P.push(["클러스터가 통째로 멈추면", cl.name, [{type: "cluster_down", vcenter: v.name, target: cl.name, label: "전체 장애"}]]);
    const Ph = inv.phys || {}, leaf = (Ph.switches || []).filter(w => w.hosts.length).sort((a, b) => b.hosts.length - a.hosts.length)[0];
    if (leaf) {
      P.push(["ToR 스위치 한 대가 꺼지면", leaf.name, [{type: "switch_down", vcenter: "", target: leaf.name, label: "스위치 장애"}]]);
      const pair = leaf.mlag ? Ph.switches.filter(w => w.mlag === leaf.mlag) : [];
      if (pair.length >= 2) P.push([`${/^\d+$/.test(leaf.mlag) ? "vPC" : "MLAG"} 한 쌍이 다 꺼지면`, pair.map(w => w.name).join(" + "), pair.map(w => ({type: "switch_down", vcenter: "", target: w.name, label: "스위치 장애"}))]);
    }
    const fw = (Ph.devices || []).filter(d => d.kind === "firewall" || d.kind === "router");
    if (fw.length) P.push(["외부 방화벽·라우터가 모두 멈추면", fw.map(d => d.name).join(" + "), fw.map(d => ({type: "device_down", vcenter: "", target: d.name, label: "장애"}))]);
    const arr = (Ph.storage || [])[0];
    if (arr) P.push(["스토리지 장비가 멈추면", arr.name, [{type: "storage_down", vcenter: "", target: arr.name, label: "어레이 장애"}]]);
    const PL = inv.platform || {supervisors: [], vks: [], avi: []};
    const sp = PL.supervisors[0];
    if (sp) P.push(["Supervisor 를 업그레이드하면", sp.name, [{type: "sup_upgrade", vcenter: sp.vcenter, target: sp.name, label: "업그레이드(롤링)"}]]);
    const kc = PL.vks[0];
    if (kc) {
      P.push(["VKS 클러스터를 업그레이드하면", kc.cluster, [{type: "vks_upgrade", vcenter: "", target: kc.cluster, label: "롤링 업그레이드"}]]);
      const wk = kc.nodes.filter(x => !x.cp).sort((a, b) => b.pods - a.pods)[0];
      if (wk) P.push(["워커 노드 하나가 죽으면", wk.name, [{type: "node_down", vcenter: "", target: `${kc.cluster}/${wk.name}`, label: "노드 장애"}]]);
    }
    const av = PL.avi[0];
    if (av && av.se.length) { const se = av.se.slice().sort((a, b) => (b.vs || []).length - (a.vs || []).length)[0];
      P.push(["Avi SE 하나가 죽으면", se.name, [{type: "avi_se_down", vcenter: "", target: `${av.name}/${se.name}`, label: "SE 장애"}]]); }
    st.pre = P.map(p => p[2]);
    return `<div class="sm-empty"><h4>무엇이 고장 나면?</h4><p>왼쪽에서 호스트·클러스터·데이터스토어·VKS 노드·Avi SE 이름을 누르면 그 객체가 <b>가상으로</b> 고장 난 것으로 계산합니다. ⋯ 로 유지보수·업링크 장애 같은 다른 종류를 고르고, 여러 개를 겹칠 수 있습니다.</p>
      <div class="sm-pre">${P.map((p, i) => `<button type="button" data-pre="${i}"><b>${esc(p[0])}</b><small>${esc(p[1])}</small></button>`).join("")}</div>
      ${(st.top || []).length ? `<h5 class="sm-h">AI 체크봇이 지금 '실패'로 본 시나리오</h5><div class="sm-pre bad">${st.top.map(([r], i) => `<button type="button" data-top="${i}"><b>${esc(r.kind)}</b><small>${esc(r.target)}${(r.top || [])[0] ? " — " + esc(r.top[0]) : ""}</small></button>`).join("")}</div>` : ""}</div>`;
  }

  function draw() {
    const b = document.getElementById("sm-body"); if (!b) return;
    const col = ((st.inv || {}).phys || {}).collected || {};
    const tms = Object.values(col.vcenter || {}).filter(Boolean).concat(col.network ? [col.network] : []);
    const base = tms.length ? new Date(Math.min(...tms) * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : "";
    const safe = `<div class="sm-safe" role="note">${ic("lock", "sm-lock")}<span><b>시뮬레이션 전용</b> — 수집해 둔 자료의 복사본으로 계산만 합니다. vCenter·ESXi·NSX·스위치·방화벽·스토리지에 어떤 명령도 보내지 않습니다.</span>
      <span class="sm-base">${st.busyRf ? "현재 구성 다시 받는 중…" : base ? `기준 구성 ${esc(base)} 수집` : ""}</span>
      <button type="button" class="sm-reset" id="sm-reset" ${st.busyRf ? "disabled" : ""} title="가정한 장애를 모두 풀고, 현재 구성(vCenter 토폴로지·인프라 점검·네트워크·스토리지)을 다시 받아 옵니다 — 읽기 전용 조회">초기화</button></div>`;
    if (!st.inv) { b.innerHTML = safe + `<p class="sm-hint">${st.err ? esc(st.err) : "인벤토리를 불러오는 중…"}</p>`; return; }
    const sc = (b.querySelector(".sm-tree") || {}).scrollTop || 0;
    const tabs = [["hc", "host", "호스트·클러스터"], ["ds", "ds", "스토리지"], ["net", "edge", "네트워크"], ["plat", "k8s", "VKS·Avi"]];
    b.innerHTML = `${safe}<div class="sm">
      <aside class="sm-inv"><div class="sm-tabs" role="tablist">${tabs.map(([k, i, l]) => `<button type="button" role="tab" aria-selected="${st.tab === k}" class="${st.tab === k ? "on" : ""}" data-smtab="${k}">${ic(i)}<span>${l}</span></button>`).join("")}</div>
        <input id="sm-q" value="${esc(st.q)}" placeholder="찾기" aria-label="인벤토리 찾기">
        <div class="sm-tree">${st.q ? search() : st.tab === "ds" ? treeDS() : st.tab === "net" ? treeNet() : st.tab === "plat" ? treePlat() : treeHC()}</div></aside>
      <section class="sm-out" aria-live="polite">${st.err ? `<p class="sm-hint">${esc(st.err)}</p>` : ""}${result()}</section></div>`;
    const t = b.querySelector(".sm-tree"); if (t) t.scrollTop = sc;
  }
  function wire(b) {
    if (b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", e => {
      const t = e.target.closest("button"); if (!t) return;
      if (t.dataset.tog) { st.open[t.dataset.tog] = !st.open[t.dataset.tog]; draw(); return; }
      if (t.dataset.hit) { const p = JSON.parse(t.dataset.hit); const cur = onObj(p); setObj(p, cur ? cur.type : (((st.inv || {}).actions || {})[p.kind] || [{}])[0].type); return; }
      if (t.dataset.menu) { st.menu = st.menu === t.dataset.menu ? "" : t.dataset.menu; draw(); return; }
      if (t.dataset.set) { const o = JSON.parse(t.dataset.set); setObj(o.p, o.type); return; }
      if (t.dataset.rm) { st.scn = null; st.fail = st.fail.filter(f => key(f) !== t.dataset.rm); st.pick = ""; save(); draw(); run(); return; }
      if (t.dataset.podf !== undefined) { st.podf = st.podf === t.dataset.podf ? "" : t.dataset.podf; draw(); return; }
      if (t.id === "sm-clear") { st.scn = null; st.fail = []; st.filter = ""; st.pick = ""; save(); draw(); run(); return; }
      if (t.id === "sm-reset") { reset(); return; }
      if (t.dataset.smtab) { st.tab = t.dataset.smtab; st.menu = ""; draw(); return; }
      if (t.dataset.flt) { st.filter = st.filter === t.dataset.flt ? "" : t.dataset.flt; draw(); return; }
      if (t.dataset.pick) { st.pick = st.pick === t.dataset.pick ? "" : t.dataset.pick; draw(); return; }
      if (t.dataset.top !== undefined) { st.scn = null; st.fail = JSON.parse(JSON.stringify(st.top[+t.dataset.top][1])); st.fail.forEach(f => { f.label = label(f); }); st.filter = ""; st.pick = ""; save(); draw(); run(); return; }
      if (t.dataset.pre !== undefined) { st.scn = null; st.fail = JSON.parse(JSON.stringify(st.pre[+t.dataset.pre] || [])); st.filter = ""; st.pick = ""; save(); draw(); run(); }
    });
    b.addEventListener("input", e => {
      if (e.target.id !== "sm-q") return;
      st.q = e.target.value; clearTimeout(st._q);
      st._q = setTimeout(() => { draw(); const q = document.getElementById("sm-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 200);
    });
    b.addEventListener("keydown", e => { if (e.key === "Escape" && st.menu) { st.menu = ""; draw(); } });
  }
  async function reset() {
    // 초기화: 가정 전부 해제 → 서버에 읽기 전용 재수집 요청 → 지금 스냅숏으로 트리 갱신 → 재수집이 끝날 무렵(20초·60초) 한 번 더 갱신
    st.fail = []; st.scn = null; st.filter = ""; st.pick = ""; st.menu = ""; st.res = null; save();
    st.busyRf = true; draw();
    let r = {};
    try { r = await A.api("POST", "/api/checkbot/refresh", {}, {background: true}); } catch (e) { r = {error: String(e.message || e)}; }
    await loadInv(true); draw();
    A.ok("초기화", r.throttled ? `방금 다시 받았습니다 — ${r.wait_s}초 뒤 다시 받을 수 있습니다` : r.error ? "지금 스냅숏으로 초기화했습니다(재수집 요청 실패)" : `현재 구성을 다시 받는 중 — vCenter ${(r.requested || []).length}개`);
    const again = async () => { await loadInv(true); draw(); };
    setTimeout(again, 20000); setTimeout(async () => { await again(); st.busyRf = false; draw(); }, 60000);
    setTimeout(() => { st.busyRf = false; draw(); }, 8000);
  }
  window.AIOPS_SIM = {
    async show(body, failures, scn) {
      wire(body);
      if (scn) { st.scn = scn; st.fail = []; st.res = null; st.filter = ""; st.pick = ""; st.podf = ""; }
      else if (failures) { st.scn = null; st.fail = failures.slice(0, 12); st.filter = ""; st.pick = ""; save(); }
      draw(); await loadInv(); if (st.inv) st.fail.forEach(f => { f.label = f.label || label(f); }); draw(); run();
    },
    reload: async () => { await loadInv(true); draw(); run(); },
  };
  function label(f) {
    if (f.type === "host_maint") return st.inv.vcenters.some(v => v.datacenters.some(d => d.clusters.some(c => c.name === f.target))) ? "롤링 유지보수" : "유지보수 모드";
    const a = Object.values(st.inv.actions || {}).flat().find(x => x.type === f.type);
    return a ? a.label : f.type;
  }
})();
