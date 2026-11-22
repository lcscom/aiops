/* 기능 둘러보기(2.42.0) — 관제 › 대시보드 › 기능 둘러보기
   처음 보는 사람에게 설명하기 쉽게 전체 메뉴를 영역별 타일로. 메뉴 구성은 navgroup.js 의 SECTIONS 를 그대로 읽어 메뉴가 바뀌어도 자동으로 따라감.
   타일 = 아이콘 · 이름 · 무엇을 · 이럴 때 · 핵심 2~3개 · 지금 상태(메뉴 배지) · 열기. 찾기 · 간단히/자세히 · 인쇄(PDF). 권한으로 숨겨진 메뉴는 빠짐 */
(() => {
  "use strict";
  const A = window.AIOPS, esc = A.esc;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const st = {q: "", brief: false};
  try { st.brief = localStorage.getItem("aiops.tour.brief") === "1"; } catch (e) { /* 기억 못해도 됨 */ }

  // 메뉴 키 → [무엇을, 이럴 때, 핵심]
  const D = {
    dash: ["들어오는 로그·이벤트를 AI 가 실시간으로 분류해 이상징후를 띄우는 첫 화면", "지금 무슨 일이 일어나고 있는지 볼 때", ["실시간 이벤트 흐름", "AI 이상 점수", "주요 지표 카드"]],
    mhome: ["인시던트·이상징후·DR·백업·수집·플랫폼 상태를 한 장에", "아침 점검·보고 전 한눈에 상황을 볼 때(폰 첫 화면과 같음)", ["상태 타일", "최근 알림", "폰과 같은 화면"]],
    "#nav-noc": ["vCenter·NSX·NSX ALB·VKS 를 슬롯별로 보여 주는 관제 화면(새 창)", "관제실 대형 화면에 띄워 둘 때", ["자동 순환", "장애 강조", "새 창 전용"]],
    inc: ["비슷한 이상징후를 묶은 인시던트 — 원인 후보·영향·조치 기록", "장애가 났을 때 무엇이 언제 어디서 시작됐는지 정리할 때", ["자동 묶음", "AI 원인 요약", "확인·종료 이력"]],
    sr: ["장애 근거를 모아 Broadcom·AWS·Azure 지원 요청(SR) 양식으로", "벤더에 케이스를 열 때 자료를 한 번에 만들 때", ["보고서·이메일 초안", "로그 묶음", "공유 링크"]],
    mon: ["지표·로그 건수·무수신·커넥터 상태를 임계값으로 감시", "'이 값이 넘으면 알려줘'를 정할 때", ["Datadog 방식 모니터", "그룹별 알림", "음소거"]],
    tail: ["선택한 서버·VM 의 로그를 실시간으로 흘려 보기", "작업 중 로그를 지켜볼 때", ["실시간 스트림", "필터", "일시 정지"]],
    inv: ["커넥터가 모은 전체 개체 목록 — VM·호스트·클러스터·데이터스토어·NSX·VKS·서버", "무엇이 어디에 몇 개 있는지 찾을 때", ["통합 검색", "개체 상세", "CSV"]],
    arch: ["vCenter·NSX·VKS 개체 관계를 그린 토폴로지", "구성을 그림으로 설명할 때", ["관계도", "상태 색", "개체 상세"]],
    "#nav-netmap": ["스위치 LLDP/CDP 로 그린 물리·논리 네트워크 구성도(새 창)", "결선·이중화·BGP 를 확인할 때", ["포트맵", "NSX Edge·BGP", "불일치 점검"]],
    vks: ["Supervisor·워크로드 클러스터의 노드·파드 상태와 파드 로그", "쿠버네티스(VKS) 문제를 볼 때", ["자동 발견", "파드 로그", "구성도"]],
    hd: ["ESXi 연결 끊김 원인을 vCenter 이벤트·vpxd·호스트 로그 한 타임라인으로", "호스트가 not responding·disconnected 일 때", ["끊김 구간", "원인 후보", "로그 근거"]],
    mv: ["VM 생성·삭제·vMotion·DRS·HA 재시작·호스트 장애 이력", "'이 VM 언제 옮겨졌지?'를 찾을 때", ["이동 이력", "HA 이벤트", "발생 중 알람"]],
    pf: ["호스트·VM CPU·메모리·디스크·네트워크 실시간·과거 성능", "느리다는 VM 을 들여다볼 때", ["ready·latency", "LUN·vNIC 별", "추세"]],
    sli: ["CPU ready·메모리·디스크 지연·패킷 드롭 4대 경합 지표로 성능 점수", "성능을 숫자 하나로 설명할 때", ["VM·클러스터 점수", "페일오버 여유", "추세"]],
    st: ["NSX 세그먼트·포트그룹·Avi 가상 서비스별 VM 트래픽", "어느 VM 이 대역폭을 쓰는지 볼 때", ["vNIC 별", "드롭", "DFW 차단"]],
    om: ["VCF Operations 지표를 바로 조회·추세·내보내기", "VCF Ops 의 숫자를 여기서 함께 볼 때", ["메트릭 선택기", "추세", "CSV·JSON"]],
    cap: ["CPU·메모리·스토리지 추세와 80/90% 도달 예상일, VM 적정화, 가정 분석, 외장 스토리지 → vSAN ESA 전환 산정", "증설 시점·필요 서버 수를 정할 때", ["도달 예상일", "가정 분석(What-If)", "vSAN ESA 전환"]],
    dr: ["SRM 복구 계획·보호 그룹, 스냅숏, vCenter·NSX·SDDC 백업, VM 백업 현황", "DR·백업이 제대로 되고 있는지 볼 때", ["보호 밖 VM", "오래된 스냅숏", "백업 실패"]],
    vchk: ["Compute·Storage·Network·Hardware(BIOS·드라이버·펌웨어) 상세 점검", "정기 점검표를 만들 때", ["호스트별 점검", "HCL 대조", "CSV"]],
    bp: ["vSphere·vSAN 구성을 Broadcom 공식 권장 사항과 대조", "'권장 구성 맞나요?'에 답할 때", ["권장/벗어남", "근거 문서", "조치 방법"]],
    life: ["인증서 만료 달력(VKS 우선)·구성 드리프트·버전 지원 종료일", "만료·지원 종료로 터질 일을 미리 막을 때", ["인증서 달력", "구성 변경 이력", "EoGS 날짜"]],
    bot: ["장애·작업 what-if 시나리오를 대량으로 만들어 계속 검증 + 파트별 시나리오 라이브러리(8개 파트 × 20개 이상) + 객체(호스트·스토리지·스위치·Supervisor·VKS 노드·Avi SE)를 눌러 보는 장애 시뮬레이터", "'이 호스트·스위치·스토리지가 죽으면 무엇이 멈추나'를 볼 때", ["서비스 중단 VM", "영향 지도", "실제로는 아무것도 안 함"]],
    rd: ["BMC(Redfish) 스캔으로 VCF 9.x 하드웨어 준비도 판정", "새 버전 올리기 전 서버가 되는지 볼 때", ["CPU·메모리 채널", "vSAN ESA·NIC", "TPM·BIOS"]],
    rv: ["RVTools 엑셀을 올리면 구성도·컴플라이언스·용량·AI 진단", "고객 환경을 처음 받아 분석할 때", ["구성도", "점검 결과", "AI 질의"]],
    assess: ["ESXi·vCenter 하드닝, KISA 가상화 점검, VMSA/CVE 버전 판독", "보안 점검·감사 대응할 때", ["KISA HV-01~25", "VMSA 대조", "읽기 전용"]],
    vuln: ["침해된 업무 VM 이 어디까지 갈 수 있나 — 버전 취약점·노출·망 분리·장비 설정·지원 종료를 묶어 공격 경로를 계속 계산", "내부 보안 약점을 우선순위로 정리할 때", ["공격 경로·끊는 곳", "망 분리 점검", "KEV 대조"]],
    sec: ["FortiGate 방화벽 — 무차별 대입·포트 스캔·IPS 탐지, 트래픽", "외부 공격 징후를 볼 때", ["공격 탐지", "출발지 순위", "트래픽 집계"]],
    bill: ["VM 사용량을 테넌트·프로젝트별로 정산", "부서별 비용을 나눌 때", ["요율표", "기간 보고서", "명세서"]],
    cc: ["지금 VCF 객체를 AWS·Azure·GCP 서비스와 짝지어 월 비용 비교", "클라우드 이전 비용을 물어볼 때", ["구성요소 매핑", "VM 별 인스턴스", "IOPS 반영"]],
    aiops: ["인시던트의 근본 원인을 의존 그래프(스위치→호스트→VM 등)로 추정하고 직전 변경을 찾음, 장애 앞에 늘 나오던 전조 패턴을 학습해 조기 경보, 이상징후에 소음/유용을 표시하면 탐지가 배움", "장애 원인을 빨리 좁히고, 알림 소음을 줄이고, 다음 장애를 미리 알고 싶을 때", ["원인 후보", "직전 변경", "전조·조기 경보", "소음 감소 지표"]],
    save: ["VM 적정화·호스트 줄이기·꺼진 VM·외장 스토리지→vSAN ESA·VCF 코어 맞추기를 금액 순으로(입력 단가), AI 한 장 요약", "비용을 줄일 곳·갱신 협상 근거가 필요할 때", ["연 절감액", "호스트 여유", "AI 요약"]],
    chg: ["작업 계획을 적으면 대상·영향·사전 점검(백업·인증서·인시던트·취약점)·권장 시간대·작업 절차서를 만들어 줌", "패치·펌웨어·교체 같은 변경을 올리기 전", ["영향 VM", "부하 낮은 시간", "절차서 마크다운"]],
    lc: ["공급 데이터·Broadcom CSP·실사용을 프로젝트별로 비교", "라이선스 초과·만료를 점검할 때", ["코어 수 대조", "키 매칭", "만료 알림"]],
    rep: ["일·주·월 운영 리포트와 경영진 요약", "보고서를 내야 할 때", ["자동 생성", "PDF·Word", "AI 요약"]],
    "#nav-exec": ["30일 인시던트·SLA·MTTR·가용성·용량 예측·보안을 한 장에(새 창)", "임원 보고 화면이 필요할 때", ["SLA·MTTR", "용량 예측", "보안 요약"]],
    chat: ["수집한 자료와 지식(KB·문서)을 근거로 묻고 답하기", "'왜 느려?', '이 오류 뭐야?'를 물어볼 때", ["근거 링크", "가명 처리", "내부·외부 AI 선택"]],
    rag: ["Broadcom KB·내부 문서를 올려 AI 답변 근거로 쓰기", "우리 환경 문서를 AI 에 가르칠 때", ["문서 업로드", "검색", "출처 표시"]],
    coll: ["커넥터별 수집 상태·지연·오류", "'왜 안 들어오지?'를 볼 때", ["연결 상태", "마지막 수집", "오류 원인"]],
    conn: ["vCenter·NSX·스위치·BMC·FortiGate 등 연결 추가·시험", "새 장비를 붙일 때", ["읽기 전용 계정", "연결 시험", "주기 설정"]],
    fwd: ["받은 로그를 Splunk·syslog·VCF Logs 로 다시 보내기", "다른 SIEM 과 함께 쓸 때", ["대상별 필터", "형식 변환", "재시도"]],
    agents: ["VM 게스트·물리 서버 OS 로그 에이전트 상태·등록", "게스트 OS 로그까지 모을 때", ["Fluent Bit·rsyslog", "설치 스크립트", "상태"]],
    sns: ["안 쓰는 안드로이드 폰으로 전산실·장비실 온도·습도·소리·진동·위치·사진 감시", "센서 없는 전산실·지점 통신실을 값싸게 볼 때", ["QR 등록", "기준값 경보", "사진"]],
    snmp: ["SNMP 트랩 수신·해석", "SNMP 만 보내는 장비가 있을 때", ["MIB 해석", "이벤트 변환", "필터"]],
    plat: ["처리 지연·대기열·DB·실시간 연결·알림 발송·이중화 상태", "포털 자체가 건강한지 볼 때", ["처리 지연", "DB 크기", "이중화"]],
    sys: ["현재 버전·서명된 패치 적용·롤백·기록", "새 버전을 올릴 때", ["서명 확인", "롤백", "적용 이력"]],
    set: ["탐지 임계·AI 공급자·알림·보존 기간 등 운영 설정", "동작 방식을 바꿀 때", ["AI 공급자", "알림 채널", "보존"]],
    users: ["사용자·역할·API 토큰", "사람·자동화에 권한을 줄 때", ["역할별 권한", "LDAP·SSO", "토큰"]],
    audit: ["누가 언제 무엇을 했는지 감사로그", "감사·사후 확인할 때", ["로그인·변경 기록", "검색", "내보내기"]],
    sp: ["포털 자체 보안 설정 점검", "포털을 운영에 올리기 전", ["TLS·헤더", "비밀번호 정책", "외부 노출"]],
    mobile: ["안드로이드 앱 내려받기·기기 연결", "알림을 폰으로 받을 때", ["푸시 알림", "첫 화면 타일", "QR 연결"]],
  };
  // 처음이라면 이 순서로
  const PATH = [["mhome", "지금 상태를 한 장으로"], ["inc", "문제가 있으면 인시던트로"], ["vchk", "정기 점검·권장 구성"], ["chg", "작업 전 영향·절차서"], ["save", "줄일 수 있는 비용"]];
  const SECD = {ops: "지금 무슨 일이 일어나는지 — 실시간 이벤트·인시던트·알림", infra: "vSphere·vSAN·NSX·VKS 구성과 성능·용량·DR·점검", secu: "보안 점검·방화벽·비용·라이선스·보고",
                ai: "자료와 문서를 근거로 묻고 답하기", adm: "수집 연결·포털 운영·사용자·패치"};

  function nav(m) { return m.startsWith("#") ? $(m) : $(`.vnav a[data-nav="${m}"]`); }
  function item(m) {
    const a = nav(m); if (!a || a.hidden) return null;
    const d = D[m] || [a.title || "", "", []];
    const b = a.querySelector(".nav-badge");
    const badge = b && !b.hidden && b.textContent.trim() && !b.classList.contains("sys-ver") ? b.textContent.trim() : "";
    return {m, a, name: (a.querySelector("span")?.textContent || "").trim(), svg: a.querySelector("svg")?.outerHTML || "", what: d[0], when: d[1], pts: d[2] || [], badge, ext: m.startsWith("#")};
  }
  function tile(x) {
    return `<button type="button" class="tr-tile" data-go="${esc(x.m)}" title="${esc(x.name)} 열기${x.ext ? "(새 창)" : ""}">
      <div class="tr-top"><span class="tr-ic">${x.svg}</span><b>${esc(x.name)}</b>${x.badge ? `<span class="tr-badge" title="지금 확인할 것">${esc(x.badge)}</span>` : ""}${x.ext ? `<span class="tr-ext">새 창 ↗</span>` : ""}</div>
      <p class="tr-what">${esc(x.what)}</p>
      ${st.brief ? "" : `${x.when ? `<p class="tr-when"><i>이럴 때</i> ${esc(x.when)}</p>` : ""}${x.pts.length ? `<div class="tr-pts">${x.pts.map(p => `<span>${esc(p)}</span>`).join("")}</div>` : ""}`}
    </button>`;
  }
  function draw() {
    const b = $("#tour-body"); if (!b) return;
    const NG = window.AIOPS_NAVGROUPS; if (!NG) { b.innerHTML = `<div class="empty">메뉴 정보를 불러오지 못했습니다.</div>`; return; }
    const q = st.q.trim().toLowerCase();
    const hit = x => !q || [x.name, x.what, x.when, ...x.pts].join(" ").toLowerCase().includes(q);
    let total = 0, shown = 0;
    const secs = NG.SECTIONS.map(([sec, key, groups]) => {
      const tiles = [];
      for (const [, gname, , list] of groups) for (const m of list) {
        if (m === "tour") continue;
        const x = item(m); if (!x) continue;
        total++;
        if (!hit(x)) continue;
        shown++; x.group = gname; tiles.push(x);
      }
      return tiles.length ? `<section class="tr-sec" data-sec="${esc(key)}"><h4><span class="tr-dot"></span>${esc(sec)} <small>${esc(SECD[key] || "")}</small></h4><div class="tr-grid">${tiles.map(tile).join("")}</div></section>` : "";
    }).join("");
    const path = PATH.map(([m, t], i) => { const x = item(m); return x ? `<button type="button" class="tr-step" data-go="${m}"><b>${i + 1}</b><span>${esc(x.name)}</span><small>${esc(t)}</small></button>` : ""; }).join("");
    b.innerHTML = `
      <div class="tr-hero">
        <div><h3>VCF AIops 는 무엇을 하나요?</h3>
          <p>vCenter·NSX·vSAN·VKS·스위치·방화벽·서버 BMC 에서 로그와 구성을 <b>읽기 전용</b>으로 모아, AI 가 이상징후를 찾고 원인 후보·영향·조치 근거를 정리해 주는 VCF 운영 포털입니다. 인프라를 바꾸는 명령은 보내지 않습니다.</p>
          <div class="tr-flow"><span>모으기<small>커넥터·로그</small></span><i>→</i><span>찾기<small>AI 이상징후</small></span><i>→</i><span>설명하기<small>원인·영향·근거</small></span><i>→</i><span>대비하기<small>점검·용량·What-If</small></span></div></div>
      </div>
      <h4 class="tr-h">처음이라면 이 순서로</h4><div class="tr-path">${path}</div>
      <div class="tr-bar"><input id="tour-q" value="${esc(st.q)}" placeholder="기능 찾기 — 예: 인증서, 용량, 스위치" aria-label="기능 찾기">
        <label class="tr-tog"><input type="checkbox" id="tour-brief" ${st.brief ? "checked" : ""}> 간단히</label>
        <span class="small muted">${q ? `${shown}/${total}개` : `전체 ${total}개 기능`} · 타일을 누르면 그 화면으로</span>
        <button type="button" class="btn-sm" id="tour-print">인쇄·PDF</button></div>
      ${secs || `<div class="empty">'${esc(st.q)}' 에 맞는 기능이 없습니다.</div>`}`;
  }
  function wire() {
    const b = $("#tour-body"); if (!b || b.dataset.w) return; b.dataset.w = "1";
    b.addEventListener("click", e => {
      const t = e.target.closest("button"); if (!t) return;
      if (t.dataset.go) { const a = nav(t.dataset.go); if (a) { $("#drawer-tour").hidden = true; a.click(); } return; }
      if (t.id === "tour-print") { document.documentElement.classList.add("tour-print"); window.print(); setTimeout(() => document.documentElement.classList.remove("tour-print"), 500); }
    });
    b.addEventListener("input", e => {
      if (e.target.id === "tour-q") { st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(() => { draw(); const q = $("#tour-q"); if (q) { q.focus(); q.setSelectionRange(q.value.length, q.value.length); } }, 150); }
    });
    b.addEventListener("change", e => {
      if (e.target.id === "tour-brief") { st.brief = e.target.checked; try { localStorage.setItem("aiops.tour.brief", st.brief ? "1" : "0"); } catch (x) { /* 무시 */ } draw(); }
    });
  }
  function show() {
    $$(".drawer").forEach(d => { if (d.id !== "drawer-tour") d.hidden = true; });
    $("#drawer-tour").hidden = false;
    wire(); draw();
    try { localStorage.setItem("aiops.tour.seen", "1"); } catch (e) { /* 무시 */ }
    const h = $("#tour-hint"); if (h) h.remove();
  }
  const navA = document.getElementById("nav-tour"); if (navA) navA.onclick = show;
  window.AIOPS_TOUR = show;
  // 처음 들어온 사람에게 한 번만 안내
  if (A.ready) A.ready.then(me => {
    if (me === null) return;
    let seen = "1"; try { seen = localStorage.getItem("aiops.tour.seen"); } catch (e) { /* 무시 */ }
    if (seen || new URLSearchParams(location.search).has("view")) return;
    const d = document.createElement("div");
    d.id = "tour-hint"; d.className = "tour-hint"; d.setAttribute("role", "note");
    d.innerHTML = `<span>처음이신가요? 전체 기능을 타일로 둘러보세요.</span><button type="button" class="btn-sm" data-t="go">기능 둘러보기</button><button type="button" class="x" data-t="x" aria-label="닫기">✕</button>`;
    d.addEventListener("click", e => { const t = e.target.closest("button"); if (!t) return; if (t.dataset.t === "go") show(); try { localStorage.setItem("aiops.tour.seen", "1"); } catch (x) { /* 무시 */ } d.remove(); });
    document.body.append(d);
  });
})();
