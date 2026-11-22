# VCF AIops 기능 명세

버전 2.44.0 · 이 문서는 **전체 기능**을 구성요소별로 정리합니다(처음 작성 2.3.0, 이후 주요 기능 추가분 반영 — 버전별 상세는 변경 이력). 설치·운영 절차는 [GUIDE.md](GUIDE.md), 변경 이력은 [CHANGELOG.md](../CHANGELOG.md), 오픈소스 고지는 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) 에 있습니다.
부록 A(API)·B(탐지 규칙)·C(조치)·D(모니터)는 소스 코드(`app/main.py` OpenAPI, `app/detect.py`, `app/actions.py`, `app/monitors.py`)에서 자동 추출했습니다.

## 목차

1. [개요](#1-개요) · 2. [수집](#2-수집) · 3. [탐지](#3-탐지) · 4. [AI 분석](#4-ai-분석) · 5. [KB·TechDocs 지식 라이브러리](#5-kbtechdocs-지식-라이브러리) · 6. [MCP 서버](#6-mcp-서버)
7. [통합 관제(NOC)](#7-통합-관제noc) · 8. [운영 콘솔](#8-운영-콘솔) · 9. [인시던트·ITSM](#9-인시던트itsm) · 10. [조치 게이트](#10-조치-게이트) · 11. [알림·모니터](#11-알림모니터)
12. [VM·서버 에이전트](#12-vm서버-에이전트) · 12A. [현장 센서(안드로이드 폰)](#12a-현장-센서--안드로이드-폰-2500) · 13. [인프라 점검·성능 SLI·인벤토리](#13-인프라-점검성능-sli인벤토리) · 13A. [정산(Billing)](#13a-정산billing) · 13B. [보안 판독](#13b-보안-판독하드닝kisavmsacve) · 13C. [용량 계획·VM 적정화·가정 분석](#13c-용량-계획vm-적정화) · 14. [보안·접근 통제·감사](#14-보안접근-통제감사) · 15. [플랫폼 운영](#15-플랫폼-운영) · 16. [배포·패치](#16-배포패치) · 13F. [수명 주기 점검](#13f-수명-주기-점검-2360) · 13H. [기능 둘러보기](#13h-기능-둘러보기-2420) · 13I. [vSAN ESA 전환·취약점 검증](#13i-vsan-esa-전환-산정--내부-취약점-검증-2430) · 13J. [비용 절감·변경 사전 검토](#13j-비용-절감-찾기--ai-변경-사전-검토-2440) · 13K. [AIOps 인사이트](#13k-aiops-인사이트-2450) · 13G. [What-If 시나리오](#13g-what-if-시나리오--ai-체크봇장애-시뮬레이터-2380-2411-부터-점검진단-메뉴)
부록 [A. REST·WebSocket API](#부록-a-restwebsocket-api) · [B. 탐지 규칙 98종](#부록-b-탐지-규칙-98종) · [C. 조치 카탈로그](#부록-c-조치-카탈로그) · [D. 모니터](#부록-d-모니터) · [E. 설정 항목](#부록-e-설정-항목)

## 1. 개요

| 항목 | 내용 |
|---|---|
| 목적 | VMware Cloud Foundation 환경(vCenter·ESXi·vSAN·NSX·NSX ALB·VKS·SDDC Manager·VCF Operations/Logs/Automation·SRM)과 서버 BMC·방화벽·VM 게스트의 로그와 상태를 한 곳에 모아 이상을 추리고, KB 근거로 원인·조치를 붙여 알림 |
| 구조 | Python 3.12 · FastAPI 단일 프로세스(asyncio), SQLite(WAL), 정적 웹 화면(외부 CDN 없음) |
| 화면 | 운영 콘솔(`/`) · 통합 관제 월(`/noc`) · 한국어/영어 전환(KO/EN) |
| 배포 | OVA 어플라이언스(Ubuntu 24.04 LTS) · Ubuntu 직접 설치 · Windows Server(서비스) · Docker |
| 원칙 | 수집 계정 읽기 전용 · 관리자 자격 증명 비보관 · 외부 AI 가명화 · 서명 패치 · 해시 체인 감사 |

## 2. 수집

### 2.1 수신기

| 수신기 | 포트·경로 | 기능 |
|---|---|---|
| syslog | UDP/TCP 514, TLS 6514 | RFC3164/5424 파싱, 호스트·앱 이름으로 소스 자동 분류(ESXi·vCenter·NSX Manager/Edge·SRM·VCF Ops·Supervisor·VKS·VM 게스트·FortiGate), 송신 장비별 수신량 |
| SNMP 트랩 | UDP 162 | v1·v2c·v3(USM 인증·암호화), 트랩 목록 화면 |
| HTTP 수집 | `POST /api/ingest` | Fluent Bit http output(json·json_lines·gzip), API 토큰 scope `ingest`, 본문 상한 |
| Redfish 이벤트 | `POST /api/redfish/events/<토큰>` | BMC(iLO·iDRAC·XCC) push 구독 자동 생성, 커넥터별 토큰 |

### 2.2 폴링 커넥터(`type`)

| type | 대상 | 수집 내용 |
|---|---|---|
| `vcenter` | vCenter 8.x/9.x(9.1.1 포함)·ESXi | pyVmomi 이벤트·알람·인벤토리(클러스터·호스트·VM·데이터스토어·VDS), REST 헬스, 성능 카운터(SLI), 버전 수집. 9.x SOAP 스키마 밖 형식(ContentLibrary 등) 보정 |
| `sddc` | SDDC Manager | 작업·이벤트·버전(REST 토큰) |
| `nsx` | NSX Manager·Edge | Policy API 우선(Manager API 대체) — 알람·전송 노드·Edge 상태·T0/T1·버전 |
| `avi` / `nsx-alb` | NSX ALB(Avi) Controller·SE | 전체 테넌트 이벤트·가상 서비스·SE 상태, **VIP 메트릭(테넌트별 `X-Avi-Tenant`)** — 대역폭·연결/초·요청/초·RTT·오류 |
| `vks` / `kubernetes` | Supervisor·워크로드 클러스터 | 이벤트 watch·노드·파드·문제 파드 로그 |
| `vcfops` · `vcflogs` · `vcfa` · `srm` | VCF Operations·Logs·Automation·SRM | REST 알림·감사·상태 |
| `ucsm` | Cisco UCS Manager | XML API — 패브릭 인터커넥트·섀시·블레이드·결함(fault) |
| `redfish` / `ilo` / `idrac` | 서버 BMC(UCS C-Series CIMC·HPE·Dell·Lenovo) | 이벤트(push·SSE)·부품 상태(Thermal·Power·Storage·CPU·메모리, 바뀐 부품만), 구형 CIMC XML·TLS 1.0 호환 |
| `fortigate` | FortiGate | REST 상태·자원(로그는 syslog 수신기에서 자동 인식) |

공통: 화면에서 추가·편집(비밀값 암호화), **연결 테스트**(DNS → TCP → TLS 표준/구형 → 인증 → 엔드포인트별 응답), 커넥터 점검 항목(예: '이벤트 해석', 'VIP 메트릭')에 원인·HTTP 코드, **관리자 계정으로 수집 전용 계정 만들기**(vCenter SSO·NSX·VCF Operations·VCF Operations for Logs·SDDC Manager — 읽기 전용 역할 부여, vCenter 는 유효 권한을 다시 확인해 허용 밖 권한이면 부여를 회수, 관리자 비밀번호 비저장, 생성 비밀 1회 표시), VKS 클러스터 자동 발견.

### 2.3 수집 현황·로그 전송 점검

- **수집 현황**: 항목별 마지막 수신·분당 유입·최근 30분 추이·상태(수집 중/중단/오류/미수신), 전환 시 내부 이벤트 → 알림.
- **로그 전송 설정**: ESXi·vCenter·NSX 가 이 서버로 syslog 를 보내도록 구성됐는지 읽기 전용 점검, 적용은 조치 게이트(승인)로.

## 3. 탐지

| 단계 | 내용 |
|---|---|
| 정규화 | 모든 입력을 LogEvent(소스·호스트·개체·심각도·메시지·속성)로, 우선/일반 큐 분리(경고 이상·알람·플랫폼 이벤트 우선) |
| 규칙 | **113종**(부록 B) — vSphere·vSAN·NSX·Edge·Avi·VKS·SRM·VCF Ops·서버 BMC·게스트 OS(Linux·Windows)·DB·FortiGate·**네트워크 스위치(Arista·Cisco)**·플랫폼 자체. `detection.extra_rules` 로 사내 규칙 추가, `detection.suppress` 정규식으로 노이즈 제외 |
| 신규 패턴 | 숫자·주소·ID 를 가린 템플릿으로 처음 보는 패턴 탐지(기동 후 `warmup_seconds` 학습) |
| 급증 | 패턴별 EWMA z-score |
| 병합 | 같은 지문(소스·패턴·호스트)은 한 이상징후로 — 횟수·최근 시각 갱신, VM·서버·BMC 는 호스트별 구분 |
| 사일런스 | 지문 단위 기한부 억제(기록은 유지), 유지보수 창 |

## 4. AI 분석

| 기능 | 내용 |
|---|---|
| 공급자 | OpenAI 호환(VMware Private AI Services·vLLM·Ollama 등, 기본 사내 Gemma 4 31B), Anthropic Claude, Google Gemini — 작업별 라우팅(analyze·rca·chat·brief·report), 실패 시 대체 순서 |
| 가명화 | 외부 공급자 전송 시 IP·FQDN·호스트명을 `IP_1`·`HOST_1` 로 바꾸고 응답에서 복원(`external_mask`) |
| 프롬프트 격리 | 장비 로그는 `[UNTRUSTED_LOG]` 경계로 감싸 지시로 해석되지 않게 |
| 부하 조절 | 패턴 재사용(같은 패턴 1회 분석), Governor(GPU 온도·vLLM 대기열·시간당 호출 상한·최소 간격), 우선/일반 대기열 |
| 이상징후 판정 | 요약·이상 여부·심각도·추정 원인·조치 단계·근거 문서. 조치는 문서의 명령·메뉴 순서대로, 영향 큰 단계 `[변경]`, 적용 버전 불일치 경고 |
| 환각 방지 | 근거 문서에 없는 KB 번호는 '(근거 문서 없음 — 확인 필요)' 표시·카드 경고 |
| AI 질의 | 스트리밍 답변, 판단 → 원인 → 조치 → 적용 버전 → 참고 순서, `[R#]` 인용 링크, 운영 중 버전 문맥 |
| 관제 브리핑 | NOC 상단 AI 상황 브리핑 |
| AI 운영 화면 | 공급자 상태·연결 시험, 패턴 목록(재분석·고정·무시), 대기열·호출 통계 |
| Isvara iO(선택) | VCF·vSphere·vSAN 성능 가이드 근거 질의(`isvara.enabled`), 질문 문장만 전송 |

## 5. KB·TechDocs 지식 라이브러리

| 기능 | 내용 |
|---|---|
| 넣기 | `knowledge.paths` 폴더(NFS/SMB 마운트, 6시간 증분 색인·삭제 반영) · 화면 **md 파일 올리기**(여러 개, 즉시 색인)·**폴더 올리기**(구조 유지)·**zip 묶음**(최대 4GB)·**끌어다 놓기** |
| 형식 | 사내 수집기 아카이브(`vendor/product/kb/0NNNxxx/NNNNNN.md`) front matter `source`·`article_id`·`vendor`·`product(s)`·`doc_type`·`summary`·`error_signatures`·`updated`·`url`, 일반 md(제목 계층·`**Resolution**` 머리말), TechDocs URL 경로의 버전. `_`·`.` 메타 폴더 제외 |
| 구역 | 증상·환경·원인·해결·우회·추가 정보. 머리말 없는 KB 는 페이지 순서·제품명 줄·문장 단서·명령형 동사로 추정 |
| 검색 | SQLite FTS5(BM25) + 식별자 정확 일치(KB·CVE·VMSA·`vob.*`·`esx.problem.*`·이벤트 ID) + 선택적 임베딩(float16 memmap) RRF 병합 |
| 순위 | 오류 문구 일치 ×1.6 · 제목 덮음 최대 ×1.35 · 소스↔제품 ×1.2/×0.75 · 운영 버전 일치 ×1.15/×0.85 · 의도별 구역 · 문서 유형 · 사업부 ×0.7 · 번역본 ×0.8 · 피드백 |
| 근거 | 문서 단위로 [증상]·[원인]·[해결]·[우회]·[환경] 묶어 AI·화면에(문서당 2,400자) |
| 한국어 질의 | 운영 용어 사전(90여 개)으로 영문 검색어 자동 확장, 영문 구(`not responding` 등) 구 검색, 관련도에서 번역 못 한 한국어 낱말 제외. AI 질의는 사내 LLM 으로 영문 검색어 1줄 추가 생성(8초 제한·캐시) |
| 자동 연결 | 근거 없이 판정된 미확인 이상징후에 '관련 KB(자동)'(20초 주기, 관련도 0.6 이상 3건, LLM 호출 없음), 인시던트 상세 '관련 KB·문서'(AI 인용 근거·자동 연결·원문 로그 검색을 KB 단위 합산) — RCA 근거에도 사용 |
| 지식 세대 | 문서 추가·변경·삭제 때 증가 — 근거 없이 분석된 패턴은 세대가 바뀌면 한 번 다시 분석, 자동 연결도 다시 찾음 |
| 화면 | 라이브러리 상태·검색 시험·문서 전문(구역·오류 문구·요약)·피드백(도움됨/무관)·**지식 공백**(근거 없이 판정된 패턴과 수집 키워드)·**최근 갱신 KB**(운영 버전 일치) |
| RAG 팩 | 별도 지식 팩(`.ragpack`) 가져오기·켜기/끄기·재임베딩, 빌더(`python -m app.rag.builder`) — NVD CVE·KB 번호 목록·URL·PDF |
| 점검 도구 | `python -m app.knowledge inspect <폴더>` |
| 측정 | 16,482개 → 색인 45초, DB 166MB, 질의 10–50ms(임베딩 없음) |

## 6. MCP 서버

`POST /mcp` — Streamable HTTP·JSON-RPC 2.0(프로토콜 2025-06-18), API 토큰 scope `read` 만, 세션 쿠키 불가, 쓰기 도구 없음. 도구: `knowledge_search` · `knowledge_get` · `open_anomalies` · `noc_status`. 문서·로그 텍스트는 `<untrusted_document>` 로 감쌈.

## 7. 통합 관제(NOC)

| 페이지 | 내용 |
|---|---|
| 종합 상황 `/noc` | 도메인 슬롯(vCenter·vSAN·NSX·NSX ALB·VKS·물리 서버·VM 게스트·보안) 상태·사유, 상단 지표 띠, 60분 타임라인, 이벤트 흐름, AI 브리핑, 슬롯 포커스·필터 |
| 인프라 지도 | 클러스터 → 호스트(CPU·메모리·상태) → VM, vMotion·DRS·HA 이동 애니메이션·피드 |
| 물리·논리 토폴로지 | 패브릭 인터커넥트 → 섀시 → 블레이드/서버 → ESXi → VDS → Edge/SE/**VM(이름별)** → **Pod** → Edge 클러스터·SE 그룹 → T0·가상 서비스 → T1·**세그먼트·포트그룹**, 장애 경로 강조, VM 표시 수(호스트당 20·60·200·전부·묶음만)·Pod 표시 수(노드당 10·25·100·전부·문제만) |
| 서비스 흐름도 | 클라이언트(End user 상위 IP) → VIP → SE → 풀 → 풀 멤버(VM guest IP·Pod IP·노드 IP 로 식별) → 세그먼트·포트그룹 → T1·T0 → ESXi → 물리 서버, VIP·VM 기준 조회 |
| VIP 상세 | 처리량(대역폭, 수신/송신 바이트·패킷, 신규·완료·끊긴·열린·최대 연결, 응답/초·2xx·4xx·5xx·오류 비율, 신규 SSL·SSL 오류, RTT·트랜잭션 지연, Apdex — 현재·평균·추이), End user(애플리케이션 로그 표본: 고유 클라이언트·상위 IP·OS·브라우저·기기·위치·응답 코드·도메인·URI·메서드·풀 서버·TLS·지연 p50/p95/p99·RTT), 풀 멤버 |
| vSAN `/noc/d/vsan` | vSAN 로그만(vsan·CLOM·CMMDS·LSOM·DOM·PLOG·osfs — 분당 집계·스트림·패턴·중요·이상징후·인시던트), vSAN 클러스터(**vSAN Health 전체·장애/주의 점검 수·중복제거 비율·객체 상태**)·**vSAN Health 점검 표**(분류·항목·정상/전체·방치 시 위험)·호스트/디스크 그룹(역할·health·디스크 문제)·데이터스토어·알람, 아래 별도 구역 비 vSAN 데이터스토어(로컬 VMFS·외장 공유 VMFS·NFS·vVols). Health 는 `/vsanHealth`(VsanVcClusterHealthSystem·VsanSpaceReportSystem, 읽기 전용) 에서 수집, 변화는 이벤트 |
| 이벤트·인시던트 · 보안 · AI·플랫폼 | 전체 스트림·인시던트, FortiGate 공격 요약, AI 대기열·공급자 |
| 도메인 상세 `/noc/d/<id>` | 상태·심각도 추이·개체 타일·도메인 전용 표(예: Avi VS 테넌트·메트릭)·빠짐없는 실시간 스트림·**패턴 묶음**·상위 호스트·커넥터 점검 |

공통: **전역 검색(Ctrl+K·/)**, **개체 상세 드로어**(상태·AI 판정·60분 추이·최근 이벤트·토폴로지 경로·관련 KB), 자동 순환(`?rotate=60`), 키오스크 계정, 단축키(`?`), 슬롯 구성(`noc.slots`), 낮은 화면에서 페이지 스크롤 전환.

## 8. 운영 콘솔

| 메뉴 | 기능 |
|---|---|
| 실시간 대시보드 | 로그 스트림(소스·등급·문자열 필터, 일시정지, 위로 읽는 동안 위치 유지) + 이상징후 카드(AI 판정·근거 KB·관련 문서·확인·재분석·사일런스) |
| 인시던트 | 9장 |
| 수집 현황 · 플랫폼 상태 | 2.3절 · 15장 |
| VM·서버 에이전트 | 12장 |
| VKS | 클러스터·노드·문제 파드·파드 로그 |
| VKS 구성도 | 클러스터 구성도(Ingress·Service·워크로드·PVC·PV·StorageClass·VIP↔Avi·노드↔VM↔ESXi), Supervisor 전체 구성도, SVG·Mermaid(2.9.0), 개체별 현재 상태·영향 전파·문제 목록·개체 상세(이벤트·로그·변경 이력·연관)·30초 자동 갱신(2.10.0) |
| 지원 요청(SR) | 인시던트·이상징후·VKS 개체·호스트·직접 작성 → Broadcom·AWS·Azure·일반 SR 양식 보고서(12절+부록)·이메일 초안(.eml 첨부 포함)·PDF(한글 내장)·로그 묶음·자체 URL 공유 링크(만료·폐기·로그인 요구)·AI로 다듬기(2.11.0), 한국어·영어 병기(규칙 영문화·AI 번역·미번역 표시, 2.12.0) |
| 클라우드 비용 비교 | VCF 객체 ↔ AWS·Azure·GCP 서비스 매핑(VM → 인스턴스 계열·크기, 디스크 → 블록 스토리지, VKS → 관리형 K8s, NSX ALB VS → L7 LB, 관리 VM·플랫폼 → 포함), VCF TCO(구독 × CPU 당 최소 16코어 + 서버·상면·운영) 또는 요율표 배분, 약정·적정화 기준, VM 별 IOPS 최소·평균·최대, 단가표(출처·확인 여부·수정·Azure/GCP API 갱신), CSV(2.13.0) |
| 하드웨어 준비도(VCF-R) | BMC Redfish 읽기 전용 스캔(커넥터·IP 범위, 읽기 전용 전송 정책) → CPU 지원 등급(KB 428874·BCG CPUID)·메모리 채널·vSAN ESA(HCL)·NIC/ToR 리프 쌍·UEFI/TPM/Secure Boot·PSU·SEL·BMC 보안 24항목(SCG)·BIOS 기준선 판정, 플릿 편차, HTML·Excel·CSV·JSON·가명화 보고서, ESXi 연결·변화 이벤트·SR·비용 연계(2.14.0) |
| RVTools 분석 | 고객 RVTools 'Export all to xlsx' 업로드 → 물리·논리(기존 스택 로직)·스토리지 구성도, 전체 컴플라이언스(기존 vcheck·KISA HV·VMSA + RVTools 점검 RV-01~30 + VCF 9 CPU 등급·업그레이드 경로·라이선스 코어), 클러스터 N+1·데이터스토어·VM 분석, PAIS 등 LLM 진단 보고서·질의(가명화), Excel·HTML 내보내기 — 원본 파일 미저장(2.15.0) |
| 라이선스 관리 | 공급자 엑셀·Broadcom CSP AllLicenseKeys·실사용(vCenter 커넥터·RVTools·VCF Ops 사용량 파일) 프로젝트별 비교, 키 매칭·수량 초과, 영구=CPU·구독=CPU 당 16코어 최소, LIC-01~12 점검(만료·초과·미할당·CSP 미등록·사용량 보고 180일), 키 가림·전체 보기 감사, Excel·AI 요약(2.16.0, VCF-Lic-MGMT MIT 참고) |
| 호스트 분석 | ESXi 연결 끊김(Not Responding·Disconnected) 구간 검출, vCenter 이벤트·작업·vpxd 로그·호스트 hostd/vpxa/vmkernel/vobd(BrowseDiagnosticLog)·ESXi syslog 통합 타임라인(끊김 기준 T±), 원인 후보 12종 점수·증거·확인 명령·KB, syslog 판별·동시 끊김·관리 IP 불일치·반복 패턴, CSV·AI 설명(2.18.0) |
| 메뉴 묶음 | 왼쪽 메뉴 15개 묶음(대시보드·인시던트·SR·모니터·로그·인벤토리·구성도·VKS·장애·변경 분석·성능·용량·점검·진단·보안·비용·라이선스·리포트·AI 질의·지식·수집·연동·시스템·관리), 화면 맨 위 탭 전환·마지막 탭 기억·묶음 배지 합·새 창(2.19.0) |
| 검색·즐겨찾기·단축키 | Ctrl+K 검색·명령(메뉴·설정·명령·호스트·VM·인시던트, 최근 화면), 즐겨찾기 ☆, 메뉴 접기, `[ ]` 탭 이동·`?` 도움말, API 진행 막대, 키보드·화면 낭독기 접근성, 모바일 정리(2.20.0) |
| VM 네트워크 트래픽 | NSX 세그먼트·VDS 포트그룹·표준 vSwitch 포트그룹·Avi 가상 서비스별 모든 VM vNIC 의 수신·송신 bps·pps·드롭(vCenter 실시간 카운터), NSX 게이트웨이·Tier-1·포트 DFW 차단, Avi VIP 대역폭·풀 멤버↔VM 매칭, 상위 VM·차트·5분 추세·CSV·AI(2.21.0) |
| 로그 내려받기 | 실시간 대시보드·실시간 로그 보기·인시던트·VKS(컨테이너 로그·개체 묶음)·SR 에서 기간·등급·형식(CSV·텍스트·NDJSON·ZIP) 선택, 비밀값 가림(2.11.0) |
| VCF Ops 메트릭 | VCF Operations 호스트·VM·클러스터·데이터스토어 최신 지표·추세·메트릭 선택기·CSV/JSON(2.8.0) |
| VM 액티비티 | VM 생성·복제·배포·등록·삭제·이름 변경(2.4.2), 전원·구성 변경·스냅샷·위험 신호(업무 외·대량 삭제·보호 VM·단명 VM)·VM 일대기·사용자별·CSV(2.5.0), 인시던트 직전 VM 변경·AI/RCA 연계·이전→이후·변경 창·반복 이동·리포트(2.6.0), vMotion·DRS·HA 재시작 이력과 요약 |
| 모니터 | 11장 |
| 보안(방화벽) | FortiGate 무차별 대입·스캔·IPS·차단 집계, 출발지별 |
| 인벤토리 | 개체 목록·상세·관련 개체(VM↔호스트↔클러스터↔데이터스토어↔BMC), CSV |
| 인프라 점검 · 성능 SLI | 13장 |
| 실시간 로그 보기 | 호스트 하나의 로그를 서버측 필터로 빠짐없이(`/#tail/<호스트>`), 최근 1시간 불러오기 |
| 로그 전송 설정 · 커넥터 · SNMP 트랩 | 2장 |
| 지식(KB·문서) · AI 질의 | 5장 · 4장 |
| 토폴로지 · 리포트 · 시스템·패치 · 운영 설정 · 사용자·토큰 · 감사로그 | 7장 · 15장 · 16장 · 부록 E · 14장 |
| 정산(Billing) · 보안 판독 · 용량·적정화 | 13A장 · 13B장 · 13C장 |

메뉴 묶음: 관제 · 인프라·워크로드 · 보안·컴플라이언스 · 비용·리포트 · AI·지식 · 수집·연동 · 시스템·관리.
공통: 서랍 Esc 로 닫기, 낮은 화면에서 좌측 메뉴 스크롤, 화면 틀 스크롤 밀림 보호, KO/EN.

## 9. 인시던트·ITSM

- 이상징후를 토폴로지 기반으로 묶어 인시던트 생성(자동·수동), 상태·담당·코멘트, SLA·MTTA/MTTR 요약.
- **AI 근본원인 분석(RCA)**: 근거 묶음(이상징후·로그 타임라인·vCenter 조사·지식) 미리보기 → 인과 사슬과 검증 기준을 갖춘 보고.
- ITSM: ServiceNow Table API(생성·갱신·해결, Basic 또는 OAuth) 또는 일반 웹훅, 포털 링크(`public_url`).

## 10. 조치 게이트

미리보기 → 차단 사유 → (L3 이상) **4-eyes 승인** → 실행 직전 재측정 → 실행. 쓰기 권한 커넥터를 **별도로** 등록해야 동작(수집 커넥터는 읽기 전용). 카탈로그는 부록 C.

## 11. 알림·모니터

- 채널: 화면(WebSocket 토스트·브라우저 알림), 웹훅(Slack·Teams·일반 JSON), SMTP 메일. 지문 단위 cooldown.
- **발송함(outbox)**: SQLite 기록 → 지수 백오프 재시도(30초·2분·5분·15분·30분…, 기본 8회) → 실패 시 'dead' 노출, 채널별 서킷 브레이커, 재기동 후 이어서 발송, HA 리더만 발송.
- 알림에 근거 KB·적용 버전 표시.
- **모니터**(Datadog 방식): 유형 `log`·`nodata`·`metric`·`connector`·`anomaly`, 미리보기·음소거·즉시 평가, 프리셋 13종(부록 D).

## 12. VM·서버 에이전트

- 등록: 수집 전용 토큰 + Linux(Fluent Bit·rsyslog)·Windows(Fluent Bit) 설치 명령 생성, 설치 스크립트가 서버·토큰 사전 시험.
- 무응답 감시(기본 300초) → 경보·복구 시 자동 확인, 미설치 VM 확인(vCenter 전원 켜진 VM 대비).
- 퇴역(감시 제외·기록 유지), **삭제 = 차단**(다시 보내도 등록·저장 안 함, 수신 시도·보낸 주소·경로·제거 방법 표시, 차단 해제).
- ESXi vmx 로그(`vmx.log.destination=syslog-and-disk`)로 VM 하이퍼바이저 로그 수집.

## 12A. 현장 센서 — 안드로이드 폰 (2.50.0)

| 항목 | 내용 |
|---|---|
| 측정 | 온도(주변 온도 센서 있는 기종, 없으면 배터리 온도 + 보정값 근사)·습도·기압·조도·근접(센서 있는 기종), 소리 크기(마이크 dBFS + 보정값 → 추정 dB, 녹음·전송 없음), 진동(선형 가속도 구간 최대), 위치(GPS·네트워크) → 기준 위치에서 거리, 배터리·충전·기기 발열 단계·Wi-Fi 신호 |
| 사진 | 화면 없이 Camera2 촬영(노출 1.5초 맞춘 뒤 JPEG) — 포털의 '지금 촬영' 또는 자동 촬영 간격, 장치당 300장 보관 |
| 등록 | 포털에서 장치 추가 → 1회용 등록 코드(30분)·QR → 폰 카메라로 QR → 설치 안내 화면(코드 있을 때만 열림, APK 받기·앱에서 등록) → 장치 토큰(Keystore 암호화 보관). 사설 인증서는 지문 확인 후 고정 |
| 판정 | 측정값별 경고·위험 상·하한(장치별), 상태가 바뀔 때만 이벤트(source `sensor`) → 이상징후·알림·SIEM, 정상화 시 자동 확인. 무응답(기본 5분 또는 간격 4배) 감시·복구 |
| 설정 | 전송 간격·켤 센서·자동 촬영·전후면 카메라·온도 기준·보정값을 포털에서 바꾸면 폰이 다음 전송 때 적용 |
| 앱 | 별도 APK(VCF AIops Sensor, 운영자 앱과 같은 서명 키), Android 8.0+, 포그라운드 서비스, 재부팅 뒤 자동 시작(카메라·마이크·위치는 앱을 한 번 열면 재개 — Android 14 제약) |
| 고도화(2.51.0) | 통신 끊김 버퍼(폰에 2일치 저장 → 원래 시각으로 채움), 경보음 감지(Goertzel 2~4kHz 반복음·지속음), 온도 급상승(°C/10분), 경고·위험 때 자동 사진 + 인시던트 경보 사진, 출입 감지(조명), 관련 클러스터·사이트 단위 인시던트 묶기, CSV, 15분 서비스 감시 |
| 안정성(2.52.0) | 깊은 잠에도 정확한 측정 간격(충전 중 WakeLock·배터리 알람), 배터리 최적화 제외 기반 자동 재시작, 카메라 정리 순서·콜백 방어, 센서 콜백 스레드 분리, 앱 진단·오류 보고·포털 '앱 상태', 자체 업데이트, 폰 자체 경보, 현장 표시 모드, 배터리 상태. API 수준 점검기·핵심 로직 Java 시험 |
| 원격·수동 설정(2.53.0) | 포털 명령 대기열(폰이 가져가 실행·결과 보고), 기기 소유자면 권한 부여·화면 켜짐 유지·잠금 화면 끄기·표시 모드 고정·밝기·재부팅, 일반 설치면 음량·재시작·서버 주소 변경·'눌러서 설정' 알림, adb 설치·설정 스크립트(.sh·.bat, 무선 내부 IP 페어링), 접속 주소(서버 내부 IP) 선택, 폰 수동 설정(서버 주소·간격·보정값 우선) |
| 평소와 다름·보정·작업 모드(2.54.0) | 시간대별 학습 기준선(14일, 중앙값·강건 변동 폭, 3회 연속 이탈) '평소와 다름' 경고·차트 평소 범위 띠, 보정 도우미(온도계·습도계·소음계 또는 주변 온도 센서 폰 기준), 작업 모드(기존 유지보수 창으로 경보 억제), 여러 대·사이트 일괄 설정·명령·촬영, 7일 환경 요약·주간/월간 보고서 섹션, 장치별 경보 기록 |

## 13. 인프라 점검·성능 SLI·인벤토리

- **인프라 점검(vCheck)**: vCenter PropertyCollector 스냅숏(읽기 전용 System.Read)으로 Compute·Storage·Network·Hardware(드라이버·펌웨어, BMC 펌웨어 인벤토리 대조)·보안·구성 영역 점검 규칙(코드 기준 Compute 16·Storage 10·Network 5·Hardware 3·보안 2 등)을 돌려 심각도·개체·조치 안내를 표시. HCL 대조는 하지 않고 vLCM 호환성 보고서가 있으면 함께 표시.
- **성능 SLI**: VM 4대 경합 지표(CPU ready·메모리 latency·디스크 latency·dropped packets) 최근 5분 p99 점수·밴드, 클러스터 KPI(밴드 가중), Failover Capacity, 밴드 하락 시 `sli_breach` 이벤트.
- **인벤토리**: vCenter·NSX·Avi·UCSM·BMC 개체 통합 목록·상세·관계, CSV.
- **VM 액티비티**(이동·HA·생성·삭제) 이력, **물리↔논리 토폴로지**(BMC 커넥터의 ESXi 호스트 지정으로 연결).

## 13A. 정산(Billing)

| 항목 | 내용 |
|---|---|
| 표본 | vCenter 인벤토리 5분 블록(전원·vCPU·메모리 GB·할당 디스크 GB·CPU 사용률 = quickStats MHz ÷ (vCPU × 코어 MHz)·메모리 사용률 = 게스트 활성 ÷ 구성) → 시간 단위 누적(`bill_usage`, 400일) |
| 매칭 | 프로젝트 조건 클러스터·VM 폴더(경로 접두)·태그·VM 이름 OR, 우선순위 VM > 태그 > 폴더(긴 경로) > 클러스터 > 낮은 프로젝트 번호, 시간 행마다 그 시각의 속성으로 |
| 요율 | vCPU·메모리 GB·디스크 GB 시간 단가, 통화, 사용률 가중(최소 가중치), 꺼진 VM 디스크 과금 선택, 기본 요율표, 테넌트·프로젝트 지정, 단가 변경 = 적용 시작일 버전 |
| 보고서 | 이번 달·7일·30일·월·기간 지정, 테넌트 › 프로젝트 › VM(켜진 시간·평균 사양·사용률·CPU/메모리/디스크 비용), 미할당 VM, 데이터 있는 시간, CSV, 월 명세서(인쇄용 HTML → PDF) |
| 권한 | 조회 view(테넌트 사용자는 자기 테넌트만), 즉시 표본 operate, 테넌트·프로젝트·요율 settings, 감사 기록(명세서·CSV·변경) |

## 13B. 보안 판독(하드닝·KISA·VMSA/CVE)

| 항목 | 내용 |
|---|---|
| 수집 | vCenter 읽기 전용 — 호스트 `config.product`·고급 설정(`OptionManager.QueryOptions`)·`serviceSystem.serviceInfo`·`firewallSystem.firewallInfo`·`config.lockdownMode`·`config.dateTimeInfo`·`config.network.vswitch`, 분산 포트그룹 `defaultPortConfig.securityPolicy`, VM `config.extraConfig`(표본 500)·스냅샷·Tools, vCenter `about` |
| 하드닝 | ESXI-01~31(타임아웃·계정 잠금·비밀번호·syslog·hostd 로그·MOB·BPDU·dvFilter·TPS salting·경고 숨김·execInstalledOnly·구 TLS·배너·SSH·Shell·SLP·CIM·SNMP·NTP·방화벽·허용 IP·잠금 모드·vSwitch 보안·패치), NET-01, VM-01~07, VC-01 — 판정 PASS·FAIL·WARN·MANUAL·N/A, 기대값·현재값·조치 |
| KISA | HV-01~25 대응표(항목별 최악 판정·미흡 수·대상 수), 자동 확인 불가 항목(HV-01·04·15·18·20·23)은 수동 확인 사유 |
| VMSA/CVE | 취약점 목록 = NVD CVE API 2.0(`virtualMatchString` = `cpe:2.3:o:vmware:esxi`·`cpe:2.3:a:vmware:vcenter_server`, 페이지 2,000건, API 키 선택, 프록시) 또는 JSON 가져오기(NVD 응답 · `advisories` 형식: id·title·severity·cvss·cves·fixes[product·branch·fixed_build·fixed_version]). 판정: 고정 빌드 비교 '취약', CPE 버전·업데이트 일치·범위 '가능' |
| 보고 | 준수율·FAIL·WARN·MANUAL, 버전 현황, CSV, 인쇄 보고서, 최근 30회 이력, 24시간 자동 점검, 메뉴 배지(미흡 + 취약) |
| 변경 추적(2.0) | 지난 점검과 비교 — 호스트 추가/제거, ESXi·vCenter 버전/빌드, 고급 설정, 서비스 실행/정책, 잠금 모드, NTP, 방화벽 기본 정책·허용 IP 규칙, vSwitch·분산 포트그룹 보안 정책, VM 고급 설정; 판정 악화/개선 목록. 이벤트(source vcenter, kind config, app config-drift/assessment)로 송출 — 보안 관련 변경·악화는 경고 |

## 13C. 용량 계획·VM 적정화

| 항목 | 내용 |
|---|---|
| 표본 | 5분마다 클러스터 CPU·메모리(호스트 quickStats 합), 공유 데이터스토어 용량(로컬 VMFS 제외) → `cap_usage` 시간 단위 합·횟수(400일) |
| 예측 | 최근 N일(기본 30) 일 평균에 최소제곱 직선 — 기울기(%/일)·R²·80%/90% 도달 예상일·30/90일 뒤 사용률·데이터스토어 GB/일, N-1 호스트 메모리 사용률. 표본 7일 미만은 보류 |
| 적정화 | `bill_usage`(VM 5분 표본) 최근 14일 — 과다(vCPU ≥ 4·피크 CPU < 25% 또는 메모리 ≥ 8GB·피크 < 30%, 권장 = 피크 × 1.5·최소 2), 과소(평균 CPU ≥ 75% 또는 메모리 ≥ 85%, 권장 × 1.5), 유휴(피크 CPU < 3%·메모리 < 10%), 장기 꺼짐(7일 이상 꺼진 채 관측). 회수 가능 vCPU·메모리·디스크, 기본 요율표 × 730시간 월 절감 |
| 화면·API | 좌측 '용량·적정화'(배지 = 위험 + 90일 내 90% 도달), CSV; `GET /api/capacity` · `/api/capacity/rightsizing` · `/api/capacity/report.csv` · `POST /api/capacity/sample` |
| 적정화 화면(2.3) | 요약(회수 가능 vCPU·메모리·디스크·월 절감) → 현재 할당 → 권장 합계 막대(회수·증설) → 판단 결과 분포(적정·과다·유휴·과소·장기 꺼짐·보류(켜진 시간 24시간 미만)) → 클러스터별 표(필터) → VM 행: CPU·메모리 게이지(평균·피크·기준), 현재 → 권장·증감, 조치(`action`), 근거(`why` — 피크 사용량 × 여유 계산식), 판단 신뢰도(`confidence`: 관측 7일 이상 high·3일 이상 medium·미만 low). 정렬 절감액·규모·사용률·이름. API `summary.judged·ok·pending·add_*·alloc_*·rec_*`, `clusters[]`, CSV 조치·근거·신뢰도 |
| 가정 분석(2.33~2.36) | VM·서버 더하기·빼기·교체·장애, 피크(p95) 기준, 서버 사양(vCenter·BMC·수집 스크립트), 라이선스 코어, **vSAN 쓸 수 있는 용량**(정책·예비·절감률·ESA 적응형 RAID-5 — 2.37.0 부터 vSAN 공간 보고 실측값 기본), **혼합 세대 EVC 검토**, **적정화 반영**, **분기별 증설 계획**, **비용 연결**(VCF 원가 ↔ 퍼블릭 클라우드), 저장·비교. 탭: 한 클러스터 · **클러스터 간 이동** · **DR 사이트 수용** · **고객 제출용 보고서 묶음(PDF·Word·HTML)** |

## 13F. 수명 주기 점검 (2.36.0)

| 항목 | 내용 |
|---|---|
| 인증서 달력 | VKS 우선(API 서버·컨트롤 플레인 kubeadm·자동 갱신 설정·kubelet·노드 CSR·cert-manager·커넥터 토큰) + vCenter 머신 SSL·ESXi 호스트·NSX·모든 커넥터 TLS·직접 등록. 석 달 달력·목록·.ics·CSV, 60/14일 전·만료 이상징후, 12시간 자동 스캔 |
| 구성 드리프트 | 기준선(골든) 대비 바뀐 호스트·클러스터 설정 + 같은 클러스터 안 다수와 다른 호스트 + 점검마다 쌓는 변경 이력(180일, 2.37.0)·변경 알림 |
| 버전 수명 | 구성요소 버전 ↔ 일반 지원 종료일·다음 줄·업그레이드 순서. 수명 표는 출처·확인 여부 포함, JSON 교체 |

## 13G. What-If 시나리오 — AI 체크봇·장애 시뮬레이터 (2.38.0, 2.41.1 부터 점검·진단 메뉴)

| 항목 | 내용 |
|---|---|
| 시나리오 | 호스트 장애·업링크 장애(호스트마다) · 롤링 유지보수·유지보수 중 장애·클러스터 전체 장애(클러스터마다) · APD/PDL·가득 참(공유 데이터스토어마다) · vCenter 업그레이드 · NSX Edge · 인증서 만료 · 복합(규칙 + AI 제안) — 인벤토리 전수, 6시간마다 연속 검증 |
| 영향 리소스 | VM(사유 포함)·호스트·관리 VM·NSX Edge·Avi SE·VKS 노드·컨트롤 플레인·파드·네임스페이스·vCenter 의존 기능, 시나리오별 CSV |
| 장애 시뮬레이터(2.39.0) | vSphere Client 형 인벤토리 트리(호스트·클러스터 / 스토리지 / 네트워크)에서 객체를 눌러 장애·작업을 겹치면 VM 상태(멈춤·I/O 멈춤·재시작 못할 수 있음·vMotion 불가·HA 재시작·vMotion 이동)와 관리 서비스·VKS 영향을 즉시 계산·표시 |
| 플랫폼(2.46.0) | 'VKS·Avi' 탭: Supervisor(컨트롤 플레인 장애·업그레이드) · VKS 클러스터(컨트롤 플레인 장애·롤링 업그레이드) · VKS 노드(CP·워커 장애) · Avi 컨트롤러 노드·SE 장애. 직접 가정과 호스트·클러스터 장애로 잃은 VM 둘 다로 쿼럼(과반) 상실, 워크로드별 Pod 배치(중단·잠깐 중단·줄어든 채 계속), vSphere Pod·네임스페이스, 가상 서비스(다른 SE 로 계속·재배치 대기·중단), 같은 호스트에 겹친 CP·컨트롤러 권고 |
| 시나리오 라이브러리(2.47.0) | 8개 파트 × 20개 이상(총 173개) — 컴퓨트·스토리지·물리 네트워크·NSX·관리 서비스·쿠버네티스·Avi·DR. 구성에서 가장 영향 큰 대상을 자동 선택해 한꺼번에 판정, 계산형(VM·Pod·VIP)·지식형(멈추는 것·계속되는 것·확인할 것), 시뮬레이터로 열기 · 영향받는 Pod 하나하나 표 |
| 고도화(2.48.0) | 시간에 따른 영향(즉시·1분·5분·복구 전·복구 후, VM 다운타임 합) · 단일 장애점 순위(객체 하나씩 고장, 점수순) · 6시간 연속 검증·새 실패 알림·기록 추이 · What-If 점검 보고서(.md)·CSV |
| 판정·우선순위 | 실패·주의·통과 + 판단 근거·할 일, 위험 점수(판정 × 발생 가능성(최근 30일 이상징후 이력 가중) × 영향 규모), 새 실패 이상징후 알림, AI 판독(가명화) |

## 13K. AIOps 인사이트 (2.45.0)

| 항목 | 내용 |
|---|---|
| 원인 추정 | 의존 그래프(장비→스위치→ESXi→VM, 스토리지→데이터스토어→VM, VM→VKS, vCenter→클러스터→호스트) 위 증상 → 후보 점수(설명력·자체·먼저·직전 변경 − 범위 벌점)·경로, 별개 문제 안내, AI 원인 설명 |
| 직전 변경 | 6시간 전부터 드리프트·VM 이동·네트워크 구성·재구성·업그레이드·유지보수 → 관련·시간 순 |
| 전조·조기 경보 | 인시던트 2~60분 전 패턴 연관 규칙(지지도·신뢰도·향상도) 학습 6시간, 5분마다 조기 경보 이상징후 |
| 피드백 학습 | 소음/유용 → 패턴 가중치 0.2~1.2 를 탐지 점수에 반영, 소음 감소·MTTA·MTTR 지표 |

## 13J. 비용 절감 찾기 · AI 변경 사전 검토 (2.44.0)

| 항목 | 내용 |
|---|---|
| 비용 절감 찾기 | 호스트 줄이기(p95 − 적정화 회수, 80%+N+1)·꺼진 VM·유휴 VM·외장→vSAN ESA·VCF 코어 맞추기·스냅숏을 입력 단가로 연 금액 순, 클러스터별 여유, AI 한 장 요약, CSV |
| 변경 사전 검토 | 작업 계획 문장 → 대상·작업·일시 해석(규칙+AI) → 영향(시뮬레이터, 순차 최악) · 사전 점검(백업·인증서·구성 변경·인시던트·What-If·취약점) · 부하 낮은 3시간 · 작업 절차서 마크다운 · AI 검토 |

## 13I. vSAN ESA 전환 산정 · 내부 취약점 검증 (2.43.0)

| 항목 | 내용 |
|---|---|
| vSAN ESA 전환 | 외장 데이터스토어 → ESA: 필요량(추세·기간), 방법 A 기존 호스트 NVMe 추가(호스트당 TB·드라이브·OSA 불가 표시)·방법 B 새 클러스터(최소 대수), ReadyNode 프로필·미달 항목, vSAN TiB 대 VCF 포함분(코어당 1 TiB) |
| 내부 취약점 검증 | VMware 버전·하드닝·ESXi 노출·망 분리(VMkernel VLAN = 업무 VM VLAN)·스위치 설정·미사용 포트·인증서·지원 종료·백업·KEV → 공격 경로(확인됨/조건부, 끊는 곳)·위험 점수, 6시간 연속 검증·새 약점 알림, 선택 능동 확인(TCP 연결만) |

## 13H. 기능 둘러보기 (2.42.0)

| 항목 | 내용 |
|---|---|
| 기능 둘러보기 | 전체 기능 46개를 영역별 타일(무엇을·이럴 때·핵심·지금 숫자)로, 처음이라면 이 순서로 5단계, 찾기·간단히·인쇄·PDF, 메뉴 구성 자동 동기화, 첫 방문 안내 |

## 13D. 네트워크(Arista·Cisco) · 전체 구성도 (2.2)

| 항목 | 내용 |
|---|---|
| 커넥터 | `arista`(eAPI JSON-RPC `/command-api`), `cisco`(platform `auto`: NX-API `/ins` → IOS-XE RESTCONF → SNMP), `nxos`, `iosxe`, `snmp-switch`(SNMP v2c/v3 — IF-MIB·LLDP-MIB·CISCO-CDP-MIB). 모두 show/GET 만 사용 |
| 수집 | 장비(호스트명·모델·OS·버전·S/N·가동) · 인터페이스 상태(up/down/disabled·설명·속도) · LLDP/CDP 이웃(상대 이름·포트·관리 주소·설명) · MLAG(Arista)/vPC(NX-OS) · BGP 피어(VRF 전체) |
| 변화 이벤트 | 인터페이스 다운/복구(이웃·설명 있는 포트는 error), 이웃 사라짐·변경, MLAG/vPC 상태, BGP 피어 상태, OS 버전 변경 → 이상징후·인시던트·알림 |
| 로그 | syslog 수신기가 등록 장비 주소·호스트명, Arista 에이전트 이름(Ebra·Lldp·Mlag·Bgp …), `%시설-심각도-니모닉` 형식으로 `arista`/`cisco` 소스 분류. 니모닉의 심각도 사용(UPDOWN … up 은 정보, … down·Established→Idle 은 경고), 인터페이스 이름을 개체로 추출. NX-OS·IOS 의 비표준 헤더(`<189>: 2026 Oct 15 …: %…`, `<187>45: host: *Oct …: %…`) 해석 |
| 탐지 규칙 | `net_if_down`·`net_err_disabled`·`net_flap`·`net_bgp_down`·`net_ospf_down`·`net_mlag`·`net_vpc`·`net_stp`·`net_portchannel`·`net_mac_flap`·`net_xcvr`·`net_system`·`net_storm`·`net_neighbor_lost`·`net_config` (15종) |
| 구성도 | `/noc/network` — 외부·업링크 / 스파인·코어 / 리프·ToR / 호스트·서버 계층 자동 배치(커넥터 `role` > 이름 힌트 > 이웃 구성), 스위치 ↔ 스위치 링크는 양쪽 LLDP 를 한 줄로, ESXi(vCenter 호스트 이름과 LLDP/CDP 이웃 이름 대조)·UCS/BMC 서버·외부 장비 연결, 다운·사라진 링크 빨간 점선, 다중 링크(LAG·MLAG) ×N, 호스트 36대 초과 시 같은 스위치 쌍 기준 묶음, 장비 상세(다운 포트·이웃·MLAG/vPC·BGP) |
| 관제 | 도메인 '네트워크'(`/noc/d/net`) — 실시간 로그·패턴·이상징후·인시던트 + 장비 표·다운/사라진 링크 표 |
| NSX Edge ↔ 물리 BGP(2.3) | NSX 커넥터 `bgp`(기본 켬)·`bgp_interval`(120초): `GET /policy/api/v1/infra/tier-0s` → `…/locale-services` → `/bgp`(local_as_num·enabled) · `/bgp/neighbors`(neighbor_address·remote_as_num·source_addresses·bfd) · `/bgp/neighbors/status`(PolicyBgpNeighborStatus — edge_path·source_address·neighbor_address·remote_as_number·connection_state(INVALID·IDLE·CONNECT·ACTIVE·OPEN_SENT·OPEN_CONFIRM·ESTABLISHED·UNKNOWN)·time_since_established·total_in/out_prefix_count·connection_drop_count·type, INTER_SR 제외) · `/interfaces`(Tier0Interface — type·subnets·edge_path·segment_path·access_vlan_id). 이벤트: ESTABLISHED 이탈 critical·복구 info(source nsx-edge) |
| 구성도 Edge 계층(2.3) | 계층 4 'NSX Edge(T0)'. 링크 `kind`: `phys`(LLDP/CDP) · `bgp`(Edge ↔ 스위치: Edge 업링크 주소가 스위치 BGP 피어 키 → 그 스위치, 스위치 L3 주소(Arista `show ip interface brief`·NX-OS `show ip interface brief vrf all`·IOS-XE ipv4) = 피어 주소 → 그 스위치, 없으면 `bgp-peer` 노드; 상태 = NSX·스위치 모두 Established 여야 up, 다르면 `mismatch`) · `placement`(Edge VM ↔ 실행 ESXi, edge_info.host_moid). 보기: 구성도·포트맵·BGP 피어링(T0 별 Edge × 피어 행렬·세션 표). 관제 패널 `net-bgp` |
| 포트맵(2.3) | `GET /api/network/portmap` — 스위치: 물리·LAG·관리 포트(논리 인터페이스 제외, 자연 정렬), 포트 상태 분류 `peer`·`up`·`alert`(연결·설명 있는 다운)·`down`(미사용)·`disabled`, 상대(스위치·ESXi·장치, LLDP/CDP/ESXi LLDP). ESXi: vmnic(속도·링크·소속 vSS/vDS) → 스위치·포트, 출처(`switch`·`esxi`), 불일치. ESXi 쪽 LLDP/CDP = vCenter `HostNetworkSystem.QueryNetworkHint`(PhysicalNicHintInfo.lldpInfo — chassisId·portId·parameter 'System Name'·'Port Description'·'Management Address' / connectedSwitchPort — devId·portId·address·hardwarePlatform), `net_hint_interval` 900초·`net_hint_max_hosts` 300 |
| 포트 점검(2.3) | down: 연결·설명 있는 스위치 포트 다운, 가상 스위치 업링크 다운 · warn: 업링크가 모두 같은 스위치(이중화 없음), 업링크 속도 혼재, 스위치 포트 ↔ vmnic 속도 불일치, ESXi·스위치 LLDP 불일치, 이웃 사라짐 · info: 연결 정보 없음 |

## 13E. 안정성 (2.2)

| 항목 | 내용 |
|---|---|
| 기동 전 점검 | 설정 범위·형식(포트·보존·세션·알림 등급·웹훅 형식/URL/키·OIDC·LDAP·MFA 역할·SIEM), 데이터 디렉터리 쓰기, 디스크 여유, TLS 인증서 파일·만료 → 로그·플랫폼 상태·시스템 화면 |
| 자가 점검 | 매일 `PRAGMA quick_check`, WAL 이 `wal_max_mb` 넘으면 `wal_checkpoint(TRUNCATE)`, 최신 백업 `integrity_check`(복원 가능 확인)·오래된 백업 경고, 프로세스 메모리·열린 파일·볼륨 사용률, 인증서 D-14 — 문제는 플랫폼 이벤트·Prometheus `aiops_db_*`·`aiops_backup_*`·`aiops_tls_cert_days_left` |
| 세션 유지 | 세션을 DB 에 저장(유휴 시각은 60초마다) — 재시작·패치 뒤에도 로그인 유지(만료분은 복원 안 함), 관리자 세션 강제 종료, 사용자 '내 접속 세션'(다른 세션 모두 종료) |
| 알림 라우팅 | `alerting.routes` — 심각도·소스·분류·커넥터·제목 정규식·시간대(야간 넘김 지원)·요일 조건 → 채널, 첫 일치(stop), `default_channels` |
| 요청 보호 | 일반 API 본문 상한(`server.max_body_mb`, 업로드 경로 제외) 413, 세션당 변경 요청 분당 상한(`auth.write_rate_per_min`) 429, 느린 요청 기록(`server.slow_request_ms`) |

## 14. 보안·접근 통제·감사

| 항목 | 내용 |
|---|---|
| 인증 | 로컬 계정 + AD/LDAP(LDAPS·StartTLS) + **OIDC SSO**(Authorization Code + PKCE, JWKS 서명 검증, 그룹→역할), 최초 비밀번호 변경 강제, 로그인 5회 실패 시 30분 잠금, 유휴 10분 세션 만료, 키오스크(조회 전용) |
| MFA | TOTP(RFC 6238) 2단계 — QR/키 등록, 복구 코드 8개(1회용·해시 저장), 코드 재사용 거부, `auth.mfa.required_roles` 역할 필수(등록 전 API 403 `mfa_enroll`), 관리자 해제, 5분 `mfa_token`·5회 오류 폐기 |
| 권한 | 조회자·감사자·운영자·관리자 RBAC, 경로별 권한(부록 A), 규칙 밖 API 는 GET=조회·그 외=관리(안전 기본값) |
| API 토큰 | scope `ingest`·`metrics`·`read`, 해시 저장·1회 표시·만료·폐기, **허용 IP/CIDR 목록**(불일치 → 거부 + 감사 `ip_denied`) |
| SIEM 전달 | 감사·이상징후·인시던트를 CEF/syslog(RFC 5424, UDP·TCP·TLS)로 실시간 전달, 큐 5,000·재연결·유실 집계·테스트 전송 |
| 웹 보안 | CSRF(`X-Requested-With`)·CSP·HSTS, TLS(사내 CA·자체 서명) |
| 비밀값 | Fernet(Windows DPAPI) 암호화, 화면·로그·감사 마스킹 |
| 감사 | 로그인·설정·조치·AI 질의·업로드·에이전트 삭제·차단 해제 등, 행마다 직전 해시 SHA-256 체인, 무결성 검증·내보내기 |
| 업로드 | zip slip·경로 탈출·형식·크기 검사 |
| 외부 공개 로그인 보호 | 인터넷 쪽(Cloudflare 머리글·외부 이름) 로그인 실패는 계정+IP 단위로 잠금(관리자 계정 잠금 악용 차단), 여러 IP 합계 상한 시 계정 전체 잠금, 한 IP가 여러 아이디로 실패하면 IP 차단(계정 대입), 로그인 국가가 바뀐 세션 끊음, 처음 보는 위치 로그인 알림, 사용자 관리 화면에서 차단·잠금 확인·해제(2.49.0) |
| 공개 표면 점검 | 모든 GET 경로를 외부 비로그인으로 호출해 허용 목록 밖 공개 경로 탐지(보안 점검·테스트), 로그인 화면 전용 사전, 평문 HTTP→HTTPS, `security.txt`(2.48.2·2.49.0) |

## 15. 플랫폼 운영

- 단일 프로세스, 수신 → 큐 → 처리 → 저장(write-behind) → 화면(클라이언트별 송신 큐) 분리 — 한쪽이 느려도 수집 지속.
- 플랫폼 자체 감시(이벤트 루프 지연·수집 과부하·DB 쓰기·내부 작업·알림 발송·이중화) → `source=aiops` 이상징후.
- `/healthz`·`/readyz`·`/api/health`, Prometheus `/metrics`(허용 IP 또는 토큰).
- 2노드 이중화(둘 다 수집·화면, 외부 알림·ITSM·리포트 메일은 리더만, HMAC 서명 상호 확인).
- 야간 DB 백업·보관 개수, 리포트(HTML·일간/주간/월간 메일·AI 요약 — 주간·월간은 정산·용량·적정화·보안 판독 절 포함), 유지보수 창, 운영 설정 화면에서 즉시 반영(일부 재시작 필요 항목 표시).
- systemd `Type=notify`·워치독 60초·하드닝(ProtectSystem=strict·ProtectHome·NoNewPrivileges), Windows 서비스(WinSW)·워치독.

## 16. 배포·패치

| 형태 | 내용 |
|---|---|
| OVA | Ubuntu 24.04 LTS 최소 구성, UEFI 보안 부팅(Canonical 서명 shim·grub·커널), PVSCSI·VMXNET3, 배포 크기 소/중/대, vApp 속성(FQDN·IP·DNS·NTP·OS/웹 비밀번호·PAIS·사내 CA), 첫 부팅 자동 구성(네트워크·데이터 디스크 XFS·계정·인증서·NTP·방화벽·서비스) → `READY` |
| Ubuntu 설치 | `scripts/linux/install.sh`(온라인·오프라인 번들·사내 CA·업그레이드), `vcf-aiopsctl` 운영 명령 |
| Windows | `scripts/windows/setup.ps1`·`service.ps1`(Miniforge·WinSW) |
| Docker | `Dockerfile`·`docker-compose.yml` |
| 서명 패치 | Ed25519 서명 매니페스트, 웹 콘솔 업로드 → 서명·무결성·버전 검사 → 적용(자동 백업·헬스 확인·실패 시 롤백), 이력·수동 롤백. 개인 키는 저장소 밖 |

## 부록 A. REST·WebSocket API

권한: 조회(view) ⊂ 운영(operate) ⊂ 관리. 브라우저는 세션 쿠키 + `X-Requested-With: aiops`, 외부는 `Authorization: Bearer aiops_…`. 전체 스키마는 실행 중 `/api/docs`.

**인증·사용자·토큰**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/auth/config` | 공개 |  |
| POST | `/api/auth/login` | 공개 |  |
| POST | `/api/auth/logout` | 조회 |  |
| GET | `/api/auth/me` | 조회 |  |
| POST | `/api/auth/heartbeat` | 조회 |  |
| POST | `/api/auth/password` | 조회 |  |
| POST | `/api/auth/mfa/verify` | 공개 | 로그인 2단계(`mfa_token` + TOTP/복구 코드 → 세션 쿠키) |
| GET | `/api/auth/mfa` | 조회 | 본인 MFA 상태(등록·복구 코드 잔여·필수 여부) |
| POST | `/api/auth/mfa/enroll` | 조회 | 비밀·otpauth URI·QR(SVG) 발급 |
| POST | `/api/auth/mfa/confirm` | 조회 | 코드 확인 → 사용 전환, 복구 코드 8개 1회 반환 |
| DELETE | `/api/users/{uname}/mfa` | 관리(사용자) | MFA 해제(인증 앱 분실) |
| GET | `/api/auth/oidc/start` | 공개 | IdP 로 302(state·nonce·PKCE) |
| GET | `/api/auth/oidc/callback` | 공개 | code 교환·id_token 검증·세션 |
| POST | `/api/auth/oidc/test` | 관리 | IdP 메타데이터·JWKS·콜백 URL 점검 |
| GET | `/api/users` | 관리(사용자) |  |
| POST | `/api/users` | 관리(사용자) |  |
| POST | `/api/users/{uname}` | 관리(사용자) |  |
| DELETE | `/api/users/{uname}` | 관리(사용자) |  |
| GET | `/api/users/sessions` | 관리(사용자) |  |
| GET | `/api/tokens` | 관리(사용자) |  |
| POST | `/api/tokens` | 관리(사용자) | `allow_ips`(IP/CIDR, 쉼표) |
| DELETE | `/api/tokens/{tid}` | 관리(사용자) |  |

**플랫폼 상태·알림 발송함**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/health` | 조회 | 플랫폼 상세 상태 — 내부 작업(감독자)·파이프라인·DB·실시간 연결·외부 의존·이중화 |
| GET | `/api/outbox` | 조회 | 외부 알림 발송함 — pending·retry·sent·dead·skipped_standby |
| POST | `/api/outbox/retry` | 운영 |  |
| GET | `/api/status` | 조회 |  |
| GET | `/api/llm/health` | 조회 |  |

**수집·로그**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/collection` | 조회 | 항목별 수집 현황(마지막 수신·분당 유입·최근 30분 추이·상태 판정) |
| GET | `/api/logs` | 조회 |  |
| GET | `/api/hosts/known` | 조회 | 실시간 로그 보기용 호스트 목록: 최근 로그 수신 호스트 + vCenter 토폴로지(ESXi·VM) + 에이전트. |
| GET | `/api/live` | 조회 | 메모리 버퍼에서 after_id 이후 로그 (폴링형 외부 연동용). |
| POST | `/api/ingest` | 관리(설정) | HTTP 수집 — Fluent Bit(http output, format json/json_lines, gzip) · 스크립트. VM 게스트·물리 서버 OS 에이전트의 입구. |
| GET | `/api/forwarding` | 운영 | 제품별로 이 서버로 로그를 보내도록 구성됐는지 점검(읽기 전용). 적용은 /api/actions(승인 조치). |

**커넥터**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/connectors` | 조회 |  |
| GET | `/api/connectors/discovered` | 조회 |  |
| PUT | `/api/connectors/discovered/{name}` | 관리(설정) | 허용 필드만 덮어씀: enabled·interval·log_namespaces·problem_logs·username·password·verify_tls·environment·cluster_name |
| DELETE | `/api/connectors/discovered/{name}` | 관리(설정) |  |
| POST | `/api/connectors/discovered/{name}/include` | 관리(설정) |  |
| POST | `/api/connectors/{name}/test` | 운영 |  |
| POST | `/api/connectors/test-all` | 운영 |  |
| POST | `/api/connectors/provision` | 관리(설정) | 관리자 계정으로 수집 전용(읽기 전용) 계정 생성 — 관리자 자격 증명은 저장하지 않음. |
| POST | `/api/connectors/{name}/test-event` | 운영 | Redfish BMC 에 시험 이벤트 발송 요청 → 실시간 수신 경로 확인 |
| POST | `/api/settings/connectors/test` | 관리(설정) | 저장 전 연결 시험 — 화면 입력값(마스킹된 비밀은 기존 값으로 대체)으로 임시 커넥터를 만들어 점검 |

**이상징후·알림·AI 질의**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/alerts/recent` | 조회 |  |
| GET | `/api/anomalies` | 조회 |  |
| POST | `/api/anomalies/{aid}/ack` | 운영 |  |
| POST | `/api/anomalies/{aid}/analyze` | 운영 |  |
| POST | `/api/anomalies/{aid}/silence` | 운영 | 같은 지문(fingerprint)의 이상징후 알림·인시던트 생성을 기한부 억제 (기록은 계속 남음) |
| POST | `/api/alerts/test` | 운영 |  |
| POST | `/api/chat` | 조회 |  |
| GET | `/api/silences` | 조회 |  |
| POST | `/api/silences` | 운영 |  |
| DELETE | `/api/silences/{sid}` | 운영 |  |

**AI 운영**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/ai` | 조회 |  |
| GET | `/api/ai/catalog` | 조회 |  |
| POST | `/api/ai/toggle` | 운영 |  |
| GET | `/api/ai/patterns` | 조회 |  |
| POST | `/api/ai/patterns/{key}/{action}` | 운영 |  |
| POST | `/api/ai/providers/test` | 관리(설정) | 설정 화면 '연결 시험' — 저장 전 입력값(마스킹된 키는 저장된 값으로)으로 임시 클라이언트를 만들어 시험 |

**인시던트·조사**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/incidents` | 조회 |  |
| POST | `/api/incidents` | 운영 |  |
| GET | `/api/incidents/summary` | 조회 |  |
| GET | `/api/incidents/{inc_id}` | 조회 |  |
| POST | `/api/incidents/{inc_id}/status` | 운영 |  |
| POST | `/api/incidents/{inc_id}/assign` | 운영 |  |
| POST | `/api/incidents/{inc_id}/comment` | 운영 |  |
| POST | `/api/incidents/{inc_id}/rca` | 운영 | AI 근본원인 분석(인과 사슬 + 4개 검증 기준). 근거 묶음 → Gemma 4 31B. |
| POST | `/api/incidents/{inc_id}/investigate` | 운영 | RCA 입력 근거 묶음 미리보기(이상징후·로그 타임라인·vCenter 조사·지식) |
| POST | `/api/incidents/{inc_id}/itsm` | 운영 |  |
| GET | `/api/investigate` | 조회 |  |
| GET | `/api/topology/resolve` | 조회 |  |

**조치 게이트**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/actions/catalog` | 조회 |  |
| GET | `/api/actions` | 조회 |  |
| POST | `/api/actions` | 운영(조치 요청) |  |
| POST | `/api/actions/preview` | 운영(조치 요청) |  |
| POST | `/api/actions/{aid}/approve` | 관리(조치 승인) |  |
| POST | `/api/actions/{aid}/reject` | 관리(조치 승인) |  |

**관제(NOC)**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/noc` | 조회 |  |
| GET | `/api/network/map` | 조회 | 전체 네트워크 구성도(노드·링크(kind phys·bgp·placement)·요약·Edge BGP 세션, `?hosts=0` 호스트 제외) |
| GET | `/api/network/devices` | 조회 | 네트워크 장비 표·다운/사라진 링크 |
| GET | `/api/network/portmap` | 조회 | 장비별 포트맵(스위치 포트 ↔ ESXi vmnic)·점검 결과(2.3) |
| GET | `/api/network/bgp` | 조회 | NSX Edge ↔ 물리 스위치 BGP 세션(2.3) |
| GET | `/api/network/device/{name}` | 조회 | 장비 상세(인터페이스·이웃·MLAG/vPC·BGP) |
| GET | `/api/system/selfcheck` | 관리 | 자가 점검(기동 전 점검·DB·WAL·백업·자원·인증서) |
| POST | `/api/system/selfcheck/run` | 관리 | 지금 점검(quick_check·checkpoint·백업 integrity_check) |
| GET | `/api/auth/sessions` | 조회 | 본인 세션 목록 |
| POST | `/api/auth/sessions/revoke` | 조회 | 본인 다른 세션 종료(`{"others":true}`) |
| DELETE | `/api/users/sessions/{prefix}` | 관리(사용자) | 세션 강제 종료 |
| GET | `/api/noc/exec` | 조회 | 경영진 요약(30일 인시던트·SLA·MTTR, 가용성, vSAN, 용량, 정산, 판독, 플랫폼) — 60초 캐시 |
| GET | `/api/noc/exec` | 조회 | 경영진 요약(30일 인시던트·SLA·MTTR, 가용성, vSAN, 용량, 정산, 판독, 플랫폼) — 60초 캐시 |
| GET | `/api/noc/kpi` | 조회 | 관제 상단 지표 띠 — 규모·알람·인시던트·VM 액티비티·AI·보안을 한 번에 |
| GET | `/api/noc/infra` | 조회 | 인프라 지도 — vCenter 클러스터 → 호스트(CPU·메모리·상태) → VM(전원·열린 이상징후) + 이상징후 겹침 |
| GET | `/api/noc/slots` | 조회 | 관제 도메인 탭 목록(설정 noc.slots) — state=1 이면 탭 상태 점(장애·주의·정상)과 미확인 건수 포함 |
| GET | `/api/noc/domain/{sid}` | 조회 | 도메인 상세 탭 — 상태·개체·커넥터 점검·심각도 추이·상위 호스트·최근 이벤트·도메인 전용 패널 |
| GET | `/api/noc/domain/{sid}/events` | 조회 | 도메인 상세 — 특정 호스트·개체의 최근 이벤트(스트림 필터를 걸 때 과거분 채우기) |
| GET | `/api/noc/domain/{sid}/patterns` | 조회 | 도메인 최근 이벤트의 패턴(템플릿)별 묶음 — 건수·최고 심각도·호스트·5분 추이 |
| GET | `/api/noc/entity` | 조회 | 개체 상세(관제 드로어) — 상태·이상징후(AI 판정)·60분 추이·최근 이벤트·물리↔논리 경로·관련 인시던트 |
| GET | `/api/noc/search` | 조회 | 관제 전역 검색(Ctrl+K) — 호스트·VM·Edge·SE·VS·블레이드·장비 이름/설명 |
| GET | `/api/noc/brief` | 조회 |  |

**인벤토리·토폴로지·점검**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/vm/moves` | 조회 |  |
| GET | `/api/vm/moves/summary` | 조회 |  |
| GET | `/api/vm/alarms` | 조회 |  |
| GET | `/api/inventory` | 조회 |  |
| GET | `/api/inventory/item` | 조회 | 한 개체의 전체 필드 + 관련 개체(VM → 호스트·클러스터·데이터스토어 / 호스트 → VM·BMC …) |
| GET | `/api/inventory.csv` | 조회 |  |
| GET | `/api/topology/stack` | 조회 | 물리 → 논리 스택 토폴로지(패브릭·섀시·서버·ESXi·VDS·Edge/SE/VM·Pod·게이트웨이·VS·세그먼트) — `vm_limit`·`pod_limit`·`vms`·`pods` |
| GET | `/api/topology/flow` | 조회 | 서비스 흐름도 — `vs`(uuid·이름) 또는 `vm` |
| GET | `/api/topology/live` | 조회 |  |
| GET | `/api/avi/vips` | 조회 | NSX ALB 가상 서비스(VIP)별 처리량(대역폭·바이트·패킷·연결·응답 코드·SSL·지연·Apdex)·풀 멤버 |
| GET | `/api/avi/vips/{uuid}/endusers` | 조회 | End user 집계(애플리케이션 로그 표본, `minutes`·`limit`) |
| GET | `/api/billing/report` · `/api/billing/report.csv` · `/api/billing/statement` · `/api/billing/config` | 조회 | 정산 보고서·CSV·월 명세서·설정(테넌트 사용자 범위 제한) |
| POST·PUT·DELETE | `/api/billing/tenants[/{id}]` · `/api/billing/projects[/{id}]` · `/api/billing/rates[/{id}]` | 관리(설정) | 테넌트·프로젝트·요율표 |
| POST | `/api/billing/sample` | 운영 | 지금 5분 블록 표본 |
| GET | `/api/assessment` · `/api/assessment/history` · `/api/assessment/report.csv` · `/api/assessment/report.html` · `/api/assessment/advisories` | 조회 | 보안 판독 결과·이력·보고서·취약점 목록 |
| POST | `/api/assessment/run` | 운영 | 지금 점검(변경 추적·이벤트 포함) |
| GET | `/api/capacity` · `/api/capacity/rightsizing` · `/api/capacity/report.csv` | 조회 | 용량 예측(`days`) · VM 적정화(`days`) · CSV |
| POST | `/api/capacity/sample` | 운영 | 지금 5분 블록 표본 |
| POST·DELETE | `/api/assessment/advisories/import` · `/api/assessment/advisories/sync` · `/api/assessment/advisories` | 관리(설정) | JSON 가져오기 · NVD 동기화 · 비우기 |
| GET | `/api/vcenter/health` | 조회 | Compute·Storage·Network·Hardware(드라이버·펌웨어) 점검 결과 — vCenter 커넥터별 |
| POST | `/api/vcenter/health/run` | 운영 | 지금 점검(드라이버 VIB 조회 포함) — 호스트 수에 따라 수십 초 |
| GET | `/api/sli` | 조회 | vCenter 커넥터별 성능 SLI — 클러스터 KPI·페일오버 여유·하위 VM. 점수 방식·기준·출처 포함. |

**VKS**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/vks` | 조회 |  |
| GET | `/api/vks/{name}/pods` | 조회 |  |
| GET | `/api/vks/{name}/log` | 조회 |  |
| POST | `/api/vks/discover` | 운영 |  |

**보안(FortiGate)**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/security/fortigate` | 조회 |  |
| PUT | `/api/security/fortigate/config` | 관리(설정) |  |

**모니터**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/monitors` | 조회 |  |
| POST | `/api/monitors` | 운영 |  |
| GET | `/api/monitors/catalog` | 조회 |  |
| POST | `/api/monitors/preview` | 조회 |  |
| GET | `/api/monitors/{mid}` | 조회 |  |
| PUT | `/api/monitors/{mid}` | 운영 |  |
| DELETE | `/api/monitors/{mid}` | 운영 |  |
| POST | `/api/monitors/{mid}/mute` | 운영 |  |
| POST | `/api/monitors/{mid}/evaluate` | 운영 |  |

**지식 라이브러리·RAG**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/isvara/status` | 조회 |  |
| POST | `/api/isvara/ask` | 조회 |  |
| GET | `/api/rag/packs` | 관리(설정) |  |
| POST | `/api/rag/packs` | 관리(설정) | 본문 = .ragpack(zip) 바이트 (Content-Type: application/octet-stream) |
| POST | `/api/rag/packs/{pid}/enable` | 관리(설정) |  |
| POST | `/api/rag/packs/{pid}/disable` | 관리(설정) |  |
| POST | `/api/rag/packs/{pid}/reembed` | 관리(설정) |  |
| DELETE | `/api/rag/packs/{pid}` | 관리(설정) |  |
| GET | `/api/rag/search` | 조회 |  |
| GET | `/api/knowledge` | 조회 |  |
| PUT | `/api/knowledge/upload` | 관리(설정) | 본문 = md 묶음 zip(스트리밍 저장, 최대 knowledge.max_upload_gb). 풀어서 증분 색인·임베딩을 백그라운드로 시작 |
| PUT | `/api/knowledge/file` | 관리(설정) | md 파일 하나 직접 올리기(본문 = 파일 내용, X-Filename·X-Relpath 헤더). 저장 즉시 색인해 파싱 결과를 돌려준다. |
| POST | `/api/knowledge/reindex` | 관리(설정) |  |
| DELETE | `/api/knowledge/uploads/{name}` | 관리(설정) |  |
| GET | `/api/knowledge/search` | 조회 | 라이브러리 + 팩 검색(관련 문서 패널·검색 시험). anomaly_id 를 주면 그 이상징후 기준(피드백 반영) |
| GET | `/api/knowledge/recent` | 조회 | 최근 갱신 KB·문서 — 운영 중인 제품·버전(vCenter·ESXi·NSX·Avi)에 해당하는 문서를 표시하고 위로 |
| GET | `/api/knowledge/doc/{did}` | 조회 |  |
| POST | `/api/knowledge/feedback` | 운영 | 관련 문서 '도움됨(+1)/무관(-1)/취소(0)' — 같은 로그 패턴의 다음 검색부터 순위에 반영 |
| GET | `/api/knowledge/gaps` | 조회 | 지식 공백 — AI 가 근거 문서를 하나도 쓰지 못한 이상징후 패턴(어떤 KB·문서를 더 모아야 하는지) |
| GET | `/api/rag/embedding/health` | 관리(설정) |  |

**VM·서버 에이전트**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/agents` | 조회 |  |
| GET | `/api/agents/coverage` | 조회 |  |
| DELETE | `/api/agents/{host}` | 관리(설정) | 퇴역(서버 폐기·이관) — 무응답 감시 제외, 다시 수신되면 자동 복귀. |
| POST | `/api/agents/purge` | 관리(설정) | 등록 일괄 삭제 — {hosts:[…]} 또는 {state:"retired"/"stale"}(퇴역·무응답 전부) |
| DELETE | `/api/agents/blocks/{host}` | 관리(설정) | 차단 해제 — 다음 수신부터 다시 등록 |
| POST | `/api/agents/enroll` | 관리(설정) | 에이전트 등록 — ingest 전용 토큰 발급 + Linux·Windows·rsyslog 설치 명령 생성(토큰은 이 응답에서만 표시) |

**설정·유지보수·감사·리포트·백업**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/settings/schema` | 관리(설정) |  |
| GET | `/api/settings/{key}` | 관리(설정) |  |
| PUT | `/api/settings/{key}` | 관리(설정) |  |
| POST | `/api/settings/{key}/reset` | 관리(설정) |  |
| POST | `/api/settings/itsm/test` | 관리(설정) |  |
| POST | `/api/settings/siem/test` | 관리(설정) | 저장 전 값으로 CEF 1건 전송 |
| GET | `/api/settings/siem/status` | 관리(설정) | 보냄·대기·유실·연결·마지막 오류 |
| GET | `/api/maintenance` | 관리(설정) |  |
| POST | `/api/maintenance` | 관리(설정) |  |
| PUT | `/api/maintenance/{mid}` | 관리(설정) |  |
| DELETE | `/api/maintenance/{mid}` | 관리(설정) |  |
| GET | `/api/audit` | 감사 |  |
| GET | `/api/audit/verify` | 감사 |  |
| GET | `/api/audit/export` | 감사 |  |
| GET | `/api/reports` | 조회 |  |
| POST | `/api/reports/generate` | 운영 |  |
| GET | `/api/reports/{name}` | 조회 |  |
| GET | `/api/backup` | 관리(설정) |  |
| POST | `/api/backup/run` | 관리(설정) |  |

**시스템·패치**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/system/version` | 조회 |  |
| PUT | `/api/system/patch` | 관리(시스템) | 본문 = 패치 번들(.tgz). 저장 후 서명·무결성·버전 검사 결과를 돌려준다(적용은 /apply 로 따로) |
| POST | `/api/system/patch/apply` | 관리(시스템) |  |
| POST | `/api/system/patch/rollback` | 관리(시스템) |  |

**MCP**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/mcp` | API 토큰(scope read) |  |
| POST | `/mcp` | API 토큰(scope read) |  |

**화면·기타(공개·세션)**

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| GET | `/healthz` | 공개 | 생존 확인(인증·DB 조회 없음) |
| GET | `/readyz` | 공개 | 준비 상태 — 로드밸런서 헬스 모니터용 |
| GET | `/metrics` | 토큰 metrics·허용 IP | Prometheus 지표 |
| WS | `/ws` | 세션 | 실시간 스트림(snapshot → logs·anomaly·status·incident·tail) |
| GET | `/noc · /noc/{page} · /noc/d/{sid}` | 세션 | 관제 월 페이지·도메인 상세 |
| GET | `/agents/{name}` | 공개 | 에이전트 설치 스크립트(비밀값 없음) |
| POST | `/api/redfish/events/{token}` | 커넥터별 토큰 | BMC Redfish 이벤트 수신(push) |
| GET | `/login` | 공개 | 로그인 화면 |

## 부록 B. 탐지 규칙 113종

`app/detect.py` `DEFAULT_RULES` — 분류·심각도·적용 소스. 2.2 에서 네트워크(Arista·Cisco) 15종 추가(`net_*`, `network`·`config` 분류).

| 분류 | 규칙 수 | 규칙(심각도) | 적용 소스 |
|---|---|---|---|
| network | 21 | `linux_net`(error) · `nsx_tn`(error) · `nsx_bgp`(error) · `nsx_mgr`(critical) · `dfw`(warning) · `link`(error) · `cni`(error) · `net_if_down`(error) · `net_err_disabled`(error) · `net_flap`(warning) · `net_bgp_down`(error) · `net_ospf_down`(error) · `net_mlag`(critical) · `net_vpc`(critical) · `net_stp`(warning) · `net_portchannel`(error) · `net_mac_flap`(warning) · `net_xcvr`(warning) · `net_system`(critical) · `net_storm`(warning) · `net_neighbor_lost`(warning) | arista, baremetal, cisco, esxi, ingest, network, nsx, nsx-edge, syslog, vcenter, vcflogs, vm, 모든 소스 |
| storage | 11 | `linux_fs`(critical) · `linux_scsi`(error) · `linux_multipath`(error) · `linux_nfs`(error) · `win_disk`(error) · `apd_pdl`(critical) · `path_down`(error) · `vmfs_heartbeat`(error) · `vsan`(error) · `datastore_full`(error) · `k8s_volume`(error) | baremetal, ingest, syslog, vm, 모든 소스 |
| service | 11 | `linux_segv`(warning) · `linux_unit_fail`(error) · `win_service_crash`(error) · `win_app_crash`(warning) · `win_sql`(critical) · `db_oracle`(critical) · `db_postgres`(error) · `db_mysql`(error) · `service_down`(error) · `vc_vpxd`(critical) · `vc_db`(error) | baremetal, ingest, syslog, vcenter, vcflogs, vm, 모든 소스 |
| kubernetes | 9 | `k8s_crash`(error) · `k8s_image`(error) · `k8s_oom`(error) · `k8s_evict`(error) · `k8s_node`(critical) · `k8s_sched`(warning) · `etcd`(critical) · `apiserver`(error) · `capi`(error) | 모든 소스 |
| security | 7 | `win_logon_fail`(warning) · `win_lockout`(warning) · `auth_fail`(warning) · `priv_change`(warning) · `cert`(error) · `vc_sso`(error) · `avi_sec`(warning) | avi, baremetal, ingest, syslog, vcenter, vcflogs, vm, 모든 소스 |
| os | 6 | `linux_panic`(critical) · `linux_hung`(error) · `linux_oom`(error) · `linux_time`(warning) · `win_crash_reboot`(critical) · `win_time`(warning) | baremetal, ingest, syslog, vm |
| capacity | 6 | `linux_disk_full`(error) · `win_low_disk`(warning) · `memory`(warning) · `cpu_ready`(warning) · `vc_disk`(error) · `edge_cap`(warning) | baremetal, ingest, nsx, nsx-edge, syslog, vm, 모든 소스 |
| hardware | 6 | `linux_mce`(error) · `disk_fail`(error) · `hw_power`(error) · `hw_thermal`(warning) · `hw_mem`(critical) · `hw_misc`(error) | baremetal, ingest, syslog, vm, 모든 소스 |
| dr | 5 | `replication`(error) · `recovery_plan`(error) · `srm_site`(error) · `srm_array`(error) · `srm_test`(warning) | srm, syslog, 모든 소스 |
| lb | 5 | `avi_vs`(error) · `avi_se`(critical) · `avi_ctrl`(critical) · `avi_health`(warning) · `avi_gslb`(error) | avi, syslog, 모든 소스 |
| vm | 4 | `vmtools`(warning) · `vmx_error`(error) · `vm_crash`(error) · `snapshot`(warning) | baremetal, ingest, syslog, vm, 모든 소스 |
| host | 4 | `psod`(critical) · `host_conn`(error) · `esxi_vob`(error) · `esxi_time`(warning) | 모든 소스 |
| edge | 4 | `edge_dp`(critical) · `edge_ha`(critical) · `edge_nic`(error) · `edge_vpn`(error) | nsx, nsx-edge, syslog, vcflogs |
| operation | 3 | `task_fail`(warning) · `backup`(error) · `upgrade`(warning) | 모든 소스 |
| platform | 2 | `platform_down`(error) · `platform_warn`(warning) | aiops |
| cluster | 2 | `win_cluster`(critical) · `ha`(critical) | baremetal, ingest, vm, 모든 소스 |
| ops | 2 | `ops_node`(error) · `ops_adapter`(warning) | syslog, vcfops |
| collection | 1 | `collection_stop`(error) | aiops |
| agent | 1 | `agent_silent`(warning) | baremetal, vm |
| performance | 1 | `sli_breach`(warning) | vcenter |
| supervisor | 1 | `supervisor`(error) | syslog, vcenter, vcflogs, vks-supervisor |
| config | 1 | `net_config`(warning) | arista, cisco, network, syslog |

합계 113종

## 부록 C. 조치 카탈로그

| ID | 조치 | 수준 | 커넥터 | 되돌릴 수 있음 |
|---|---|---|---|---|
| `vcenter.alarm.ack` | vCenter 알람 확인(Acknowledge) | L2 | vcenter | 예 |
| `vcenter.host.maintenance.enter` | 호스트 유지보수 모드 진입 | L3 | vcenter | 예 |
| `vcenter.host.maintenance.exit` | 호스트 유지보수 모드 해제 | L3 | vcenter | 예 |
| `vcenter.vm.consolidate` | VM 디스크 통합(Consolidate) | L3 | vcenter | 아니오 |
| `vcenter.service.restart` | vCenter 어플라이언스 서비스 재시작 | L3 | vcenter | 아니오 |
| `nsx.alarm.ack` | NSX 알람 확인(ACKNOWLEDGED) | L2 | nsx | 예 |
| `esxi.syslog.add` | ESXi 원격 syslog 에 이 서버 추가 | L3 | vcenter | 예 |
| `vcenter.syslog.forward` | vCenter 원격 syslog 에 이 서버 추가 | L3 | vcenter | 예 |
| `nsx.syslog.add` | NSX Manager/Edge syslog exporter 추가 | L3 | nsx | 예 |

수준 L3 이상은 4-eyes 승인. 로그 전송 조치(`esxi.syslog.add` 등)는 '로그 전송 설정' 화면에서만 노출.

## 부록 D. 모니터

지표(26종): `host.cpu_pct` · `host.mem_pct` · `host.disconnected` · `cluster.cpu_pct` · `cluster.mem_pct` · `cluster.sli_score` · `datastore.used_pct` · `vm.powered_off` · `vcenter.findings_critical` · `connector.latency_ms` · `vip.bandwidth_bps` · `vip.rps` · `vip.error_rps` · `vip.health` · `vip.down` · `vks.problem_pods` · `vks.nodes_not_ready` · `agent.minutes_silent` · `server.unhealthy` · `fortigate.login_failures_5m` · `fortigate.denied_per_min` · `fortigate.ips_per_min` · `platform.ai_queue` · `platform.ingest_eps` · `platform.pipeline_lag_ms` · `platform.disk_free_mb`

프리셋:
- ESXi 호스트 CPU 90% 초과(5분 평균)
- ESXi 호스트 메모리 95% 초과
- 데이터스토어 사용률 90% 초과
- 커넥터 연결 오류 5분 지속
- 에이전트 10분 무수신
- ESXi 오류 로그 급증(5분 50건)
- VIP 오류 응답 초당 10건 초과
- VIP 비정상
- VKS 문제 파드 존재
- FortiGate 무차별 대입(5분 20회 이상, 출발지별)
- 성능 SLI 클러스터 점수 50 미만
- AI 분석 대기열 500건 초과
- 위험 이상징후 3건 이상 미확인

## 부록 E. 설정 항목

`config.yaml`(구조)·`.env`(비밀값). 화면 운영 설정에서 즉시 바꿀 수 있는 키: `connectors` · `alerting` · `monitoring` · `detection` · `incidents` · `itsm` · `reports` · `backup` · `actions` · `vks_overrides` · `fortigate` · `llm` · `knowledge`. 재시작이 필요한 키: `server` · `auth` · `rag` · `syslog` · `snmp` · `ingest`.
최상위 섹션: `server` · `pipeline` · `storage` · `health` · `ha` · `llm` · `detection` · `alerting` · `syslog` · `snmp` · `ingest` · `isvara` · `agents` · `rag` · `knowledge` · `billing` · `assessment` · `capacity` · `monitoring` · `demo` · `auth` · `audit` · `incidents` · `itsm` · `actions` · `reports` · `backup` · `noc` · `metrics` · `connectors` — 항목별 설명은 [config.example.yaml](../config.example.yaml).
