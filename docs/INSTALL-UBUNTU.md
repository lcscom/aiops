# VCF AIops — Ubuntu VM 구축 가이드 (A–Z)

대상: Ubuntu Server 24.04 LTS 또는 26.04 LTS VM 1대(필요 시 2대 이중화)에 VCF AIops 를 설치하고, vCenter·ESXi·NSX·NSX ALB·VKS·물리 서버(BMC)·VM 내부 로그까지 실시간으로 받는 데까지의 전 과정.
표기: `$` 일반 사용자, `#` root(sudo). `aiops.vcf.lab`·IP 는 예시이므로 실제 값으로 바꾸세요.

> **빠른 길 — 원클릭 스크립트**: [DEPLOY-UBUNTU.md](DEPLOY-UBUNTU.md) 의 `deploy.sh` 가 이 문서의 D~H 를 자동으로 합니다.
>
> **빠른 길 — OVA 어플라이언스**: `vcf-aiops-<버전>.ova` 를 배포하면 C~H(VM 생성·OS 설치·설정·프로그램 설치·인증서)가 배포 마법사 입력 + 첫 부팅 자동 구성으로 대체됩니다. [OVA.md](OVA.md) 로 배포한 뒤 이 문서의 **I 절부터** 진행하세요.

```
 ESXi·vCenter·NSX·Edge·SRM·VCF Ops ──syslog UDP/TCP 514 · TLS 6514──┐
 NSX ALB·VKS(Fluent Bit) ─────────────────────────────────────────────┤
 iLO·iDRAC·XCC (Redfish 이벤트 push → HTTPS 8630 / SSE ← AIOps) ───────┤      ┌── PAIS(Gemma 4 31B) HTTPS
 VM 게스트·물리 서버 OS (Fluent Bit → HTTPS 8630 · rsyslog → 514) ──────┼──► aiops VM (Ubuntu 24.04)
 SNMP 트랩 UDP 162 ────────────────────────────────────────────────────┤      ├── vCenter·NSX·Avi·VKS API 폴링(HTTPS)
 브라우저(콘솔·관제 화면) HTTPS 8630 ◄─────────────────────────────────┘      └── 웹훅·메일·ITSM
```

---

## A. 사전 준비 체크리스트

| 항목 | 내용 | 비고 |
|---|---|---|
| 호스트 이름·IP | 예) `aiops.vcf.lab` / 10.10.0.50, DNS A·PTR 등록 | 이중화 시 2대 + (선택) VIP |
| NTP | 장비들과 **같은** NTP 서버 2개 | 시각이 어긋나면 상관 분석·SLA 계산이 틀어짐 |
| 인증서 | 사내 CA 에서 웹 서버 인증서(SAN: FQDN·짧은 이름·IP) | 없으면 자체 서명으로 시작 후 교체 |
| Private AI | PAIS(OpenAI 호환) 주소·API 키·모델 id(`google/gemma-4-31B-it`) | 없어도 규칙 탐지로 동작 |
| 읽기 계정 | vCenter(Read-only + 이벤트·알람 조회), NSX Auditor, Avi read-only, VKS ServiceAccount, BMC 읽기 계정 | 조치 기능용 쓰기 계정은 별도 |
| 방화벽 신청 | [Z-1 포트 표](#z-1-포트-표) 참고 | 망분리 구간은 반입 경로도 함께 |
| 반입 | 인터넷 불가 시 [F-2 오프라인 번들](#f-2-오프라인망분리) 준비 | |

## B. VM 사양 산정

원본 로그는 SQLite 에 `retention_days`(기본 7일)만큼 보관합니다. 실측 저장량은 로그 1건당 약 0.4~0.7KB(인덱스 포함, 메시지 길이에 비례)입니다.

**데이터 디스크(GB) ≈ 평균 EPS × 86,400 × 보존 일수 × 0.6KB ÷ 1,000,000 × 1.3(여유)**

| 규모 | 평균 EPS | vCPU | 메모리 | OS 디스크 | 데이터 디스크(7일) | 백업 디스크 |
|---|---|---|---|---|---|---|
| 소(PoC·관리 도메인) | ~100 | 4 | 8GB | 40GB | 60GB | 데이터 × 3 |
| 중(VI 도메인 1~2개) | ~500 | 8 | 16GB | 40GB | 250GB | 데이터 × 3 |
| 대(다수 도메인·VM 에이전트) | ~1,500 | 8 | 32GB | 40GB | 700GB | 데이터 × 2, 보존 3일 검토 |

- 처리 엔진은 단일 프로세스입니다(수신 스레드·DB 기록 스레드 별도). 시험 VM(2 vCPU) 실측: 3,000 EPS 지속 처리, 위험 로그 화면 반영 p50 3ms. 상시 5,000 EPS 를 넘으면 VM 게스트 등 저가치 로그를 VCF Operations for logs 에서 걸러 보내세요.
- 장기 보관(1년 이상·감사 원본)은 VCF Operations for logs 역할입니다. 이 VM 은 **실시간 탐지·관제**용입니다.
- 백업은 DB 전체 사본이므로 `backup.keep`(기본 14)을 데이터 크기에 맞게 줄이거나(예: 3) 백업 디스크를 NFS 로 분리하세요.

## C. vSphere 에서 VM 만들기

| 설정 | 값 |
|---|---|
| 게스트 OS | Linux · Ubuntu Linux (64-bit) |
| vCPU / 메모리 | B 의 표. 관제용이므로 **메모리 예약 100%** 권장 |
| 디스크 | 디스크1 40GB(OS), 디스크2 데이터(B 의 표), 디스크3 백업(선택). **씩 프로비저닝(Lazy Zeroed)** 권장 — SQLite 쓰기 지연 감소 |
| 컨트롤러 | VMware Paravirtual(PVSCSI) |
| 네트워크 | VMXNET3, 관리망(장비 syslog·API·BMC 와 통신 가능한 포트그룹) |
| 부팅 | EFI + 보안 부팅 |
| 이중화 시 | 두 VM 을 **다른 호스트**에 두도록 DRS VM-VM 반선호(anti-affinity) 규칙 |
| VM 고급 | VMware Tools 시간 동기화 끔(chrony 사용) |

## D. Ubuntu 24.04 LTS 설치

1. Ubuntu Server 24.04.x LTS ISO 로 부팅 → 언어 English(권장, 로그 검색 편의) → 키보드 Korean.
2. 설치 유형 **Ubuntu Server**(minimized 아님).
3. 네트워크: 고정 IP·게이트웨이·DNS·검색 도메인 입력.
4. 디스크: **디스크1만** LVM 으로 OS 설치(디스크2·3 은 E 에서 마운트).
5. 프로필: 관리자 계정 생성, 서버 이름 `aiops`.
6. **Install OpenSSH server** 체크. 추가 스냅(snap) 선택 없음.
7. 설치 후 재부팅 → SSH 접속.

## E. OS 기본 설정

```bash
# 업데이트 · VMware Tools · 기본 도구
sudo apt update && sudo apt -y full-upgrade
sudo apt -y install open-vm-tools chrony vim curl unzip
sudo timedatectl set-timezone Asia/Seoul
sudo hostnamectl set-hostname aiops.vcf.lab          # FQDN

# 데이터 디스크(/dev/sdb) → /var/lib/vcf-aiops   (디바이스 이름은 lsblk 로 확인)
lsblk
sudo mkfs.xfs -L aiops-data /dev/sdb
sudo mkdir -p /var/lib/vcf-aiops
echo 'LABEL=aiops-data /var/lib/vcf-aiops xfs defaults,noatime 0 2' | sudo tee -a /etc/fstab
sudo mount -a && df -h /var/lib/vcf-aiops

# (선택) 백업 디스크(/dev/sdc) → /var/lib/vcf-aiops/backup   — 설치 후 마운트해도 됨
# sudo mkfs.xfs -L aiops-backup /dev/sdc && echo 'LABEL=aiops-backup /var/lib/vcf-aiops/backup xfs defaults,noatime 0 2' | sudo tee -a /etc/fstab

# SSH: 비밀번호 로그인 대신 키(사내 정책에 맞게)
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload ssh
```

NTP 는 설치 스크립트의 `--ntp` 로 설정합니다(G).

## F. 프로그램 반입

### F-1. 온라인

```bash
scp vcf-aiops.zip admin@aiops.vcf.lab:/tmp/        # 작업 PC 에서
ssh admin@aiops.vcf.lab
cd /tmp && unzip -q vcf-aiops.zip                  # → /tmp/vcf-aiops
```

### F-2. 오프라인(망분리)

인터넷이 되는 **같은 버전·아키텍처의 Ubuntu**(24.04 x86_64)에서 번들을 만들어 반입합니다.

```bash
# 인터넷 PC(Ubuntu 24.04)
unzip -q vcf-aiops.zip && bash vcf-aiops/scripts/linux/build-offline.sh --with-agents
#  → /tmp/vcf-aiops-offline.tar.gz  (파이썬 wheel · python3-venv 등 .deb · 프로그램 · Fluent Bit .deb/.zip)

# 반입 후 대상 VM
tar xzf vcf-aiops-offline.tar.gz -C /tmp
```

## G. 설치 스크립트 실행

```bash
sudo bash /tmp/vcf-aiops/scripts/linux/install.sh \
  --fqdn aiops.vcf.lab \
  --ntp 10.10.0.1,10.10.0.2 \
  --pais-url https://pais.vcf.lab/v1 --pais-key '<PAIS API 키>'
# 오프라인:  sudo bash /tmp/vcf-aiops-offline/vcf-aiops/scripts/linux/install.sh --offline /tmp/vcf-aiops-offline --fqdn ... (나머지 동일)
# 사내 CA 인증서가 이미 있으면: --cert /root/aiops.crt --key /root/aiops.key
```

스크립트가 하는 일(재실행해도 안전):

| 단계 | 내용 |
|---|---|
| 1 | python3-venv·sqlite3·chrony·ufw 등 설치 |
| 2 | 서비스 계정 `aiops`(로그인 불가), `/opt/vcf-aiops`(프로그램, root 소유), `/etc/vcf-aiops`(설정, root:aiops 0750), `/var/lib/vcf-aiops`(데이터) |
| 3–4 | 프로그램 배치, 파이썬 가상환경과 패키지 설치, 바이트코드 사전 생성 |
| 5 | `secret.key`(화면 저장 비밀번호 암호화 키), `.env`(PAIS 주소·키·HA 비밀), 자체 서명 인증서, `config.yaml` |
| 6 | sysctl(UDP 수신 버퍼 32MB 등), journald 2GB 상한, chrony |
| 7 | `vcf-aiops.service` — Type=notify, **워치독 60초**(이벤트 루프 정지·5분 이상 준비 안 됨 → 자동 재시작), 하드닝(ProtectSystem=strict 등), 514/162 바인드 권한만 부여 |
| 8 | ufw 규칙 추가(활성화는 `--enable-firewall` 일 때만) |
| 9 | 기동 후 `/readyz` 200 확인 |

확인:

```bash
vcf-aiopsctl status          # 서비스 상태 + Status 줄(EPS·미확인 이상·화면·에이전트)
vcf-aiopsctl ports           # 8630/tcp 514/udp·tcp 6514/tcp 162/udp 리스닝
vcf-aiopsctl logs            # 실시간 서비스 로그(journalctl)
```

## H. 인증서(사내 CA)

```bash
sudo bash /opt/vcf-aiops/scripts/linux/make-cert.sh --fqdn aiops.vcf.lab --csr --out /root/csr \
     --san aiops-vip.vcf.lab                       # VIP 를 쓸 경우 추가
# /root/csr/aiops.csr 를 사내 CA 에 '웹 서버' 템플릿으로 제출 → 발급 PEM 을 /root/csr/aiops.crt 로 저장
sudo install -m 0644 /root/csr/aiops.crt /etc/vcf-aiops/certs/aiops.crt
sudo install -m 0640 -g aiops /root/csr/aiops.key /etc/vcf-aiops/certs/aiops.key
sudo systemctl restart vcf-aiops
```

같은 인증서가 웹(8630)·syslog TLS(6514)에 쓰입니다. 에이전트·BMC 가 검증할 수 있도록 **CA 체인 PEM** 을 보관해 두세요(N·M 에서 사용).

## I. 첫 로그인과 계정

1. `sudo cat /var/lib/vcf-aiops/initial-admin.txt` → `https://aiops.vcf.lab:8630` 로그인 → 비밀번호 변경 강제 → 파일 삭제 `sudo rm /var/lib/vcf-aiops/initial-admin.txt`.
2. **운영 설정 › 인증**: AD/LDAP(LDAPS 권장, 다중 DC, 그룹→역할 매핑: 조회자·감사자·운영자·관리자). 로컬 admin 은 비상용으로 보관.
3. 관제실 벽면 화면용 **관제 전용 계정**: `config.yaml` 의 `auth.kiosk_users: [noc-wall]` → 조회 권한 고정, 유휴 로그아웃 없음.
4. **사용자·토큰**: 외부 연동용 API 토큰(scope: ingest·metrics·read)은 여기서 발급·폐기.

## J. Private AI(PAIS) 연결

```bash
sudo -e /etc/vcf-aiops/.env           # PAIS_BASE_URL=https://pais.vcf.lab/v1, PAIS_API_KEY=...
sudo -e /etc/vcf-aiops/config.yaml    # llm.model 을 PAIS /v1/models 의 id 와 정확히 일치
sudo systemctl restart vcf-aiops
```

콘솔 상단 **Private AI** 표시가 `ok` 인지 확인. LLM 이 응답하지 않으면 3회 실패 후 60초 차단되고 규칙 탐지로 계속 운영됩니다(플랫폼 상태에 표시).

## K. 커넥터 등록(운영 설정 › 커넥터)

| 대상 | 종류 | 권한·메모 |
|---|---|---|
| vCenter | vcenter | Read-only + 이벤트·알람 조회. ESXi 이벤트·토폴로지 포함 |
| NSX Manager | nsx | Auditor. Edge 상태·알람 포함 |
| NSX ALB(Avi) | nsx-alb | read-only |
| VKS Supervisor / 워크로드 | vks | `deploy/vks/vcf-aiops-reader.yaml` 의 읽기 전용 ServiceAccount 토큰 또는 vSphere SSO |
| 서버 BMC | ilo / idrac / redfish | M 참고 |
| SDDC Manager·VCF Ops·SRM | 각 종류 | 읽기 계정 |

저장 전 **연결 시험** → 저장 즉시 반영(변경된 커넥터만 재시작).

## L. 인프라 로그 전송 설정(로그 전송 설정 화면)

콘솔 **로그 전송 설정** 이 ESXi·vCenter·NSX(Manager·Edge·Transport Node) 의 현재 syslog 대상을 읽어 미설정 항목을 보여 주고, **적용 요청 → 관리자 승인 → 실행** 으로 이 서버를 대상에 추가합니다(기존 대상 유지). 수동 설정 예:

```bash
# ESXi (각 호스트 또는 vCenter 호스트 프로파일)
esxcli system syslog config set --loghost='udp://aiops.vcf.lab:514'
esxcli network firewall ruleset set -r syslog -e true
esxcli system syslog reload
```

- vCenter·SRM·VCF Ops: 어플라이언스 관리 `https://<host>:5480` › Syslog › 대상 추가(TLS 6514 권장).
- NSX ALB: Controller › Alert Syslog 설정. VKS Supervisor 는 vCenter 원격 syslog 를 상속(5분 주기), 워크로드 클러스터는 Fluent Bit 패키지 출력 대상을 이 서버로.

## M. 물리 서버 BMC 실시간 이벤트(Redfish)

방식 3가지(커넥터 `events`):

| 방식 | 경로 | 언제 |
|---|---|---|
| **push** | BMC → `https://aiops:8630/api/redfish/events/<커넥터별 토큰>` (Redfish 구독, AIOps 가 자동 생성) | HPE iLO 5/6/7 등. BMC 망 → AIOps 8630 허용 필요 |
| **sse** | AIOps → BMC `EventService.ServerSentEventUri` 상시 연결 | Dell iDRAC9 4.00 이상·XCC. BMC→AIOps 방향 방화벽 불필요 |
| poll | 로그 서비스(IML·IEL·SEL·Lclog) 주기 조회 | 구형·제약 환경 |

`events: auto` 는 SSE 지원 시 sse, `server.public_url` 이 있으면 push, 아니면 poll 입니다. 실시간 방식이어도 300초마다 로그 서비스를 대조해 누락을 보완하고, 120초마다 팬·온도·PSU·이중화·드라이브·CPU·메모리 상태를 읽어 **바뀐 부품만** 이벤트로 냅니다.

```yaml
# config.yaml 또는 화면 — 같은 계정의 BMC 를 한 번에, ESXi 이름을 붙이면 관제 타일이 합쳐짐
- name: ilo
  type: ilo
  username: monitor
  password: ${ILO_PASS}
  events: auto
  hosts:
    - {host: ilo-esx01.vcf.lab, esxi_host: esx01.vcf.lab}
    - {host: ilo-db-bm01.vcf.lab, name: oracle-bm01}      # ESXi 가 아닌 물리 서버
```

- **Dell iDRAC**: 이벤트 서비스 활성(`PATCH /redfish/v1/EventService {"ServiceEnabled": true}`), 사설 인증서면 `RedfishEventing.1.IgnoreCertificateErrors` 를 정책에 맞게 설정.
- 확인: 커넥터 **연결 시험** 에 `이벤트(push|SSE)` 항목 → **시험 이벤트** 버튼(SubmitTestEvent) → 콘솔 **실시간 로그 보기** 에서 서버 이름으로 수신 확인.
- 구독 생성이 권한 부족(403)이면 시험 결과에 표시되고 poll 로 동작합니다.

## N. VM 내부 로그(에이전트)

### N-1. 등록

콘솔 **VM·서버 에이전트 › 에이전트 등록** → 대상(VM 게스트·물리 서버)·역할(DB·WAS 등) → 수집 전용 토큰과 **설치 명령 3종**(Linux Fluent Bit · Linux rsyslog · Windows)이 생성됩니다. 같은 명령을 여러 서버에 써도 되며 호스트 이름으로 구분됩니다.

### N-2. Linux (Fluent Bit — 권장)

```bash
curl -fsSk https://aiops.vcf.lab:8630/agents/install-linux.sh -o install-agent.sh
sudo bash install-agent.sh --server https://aiops.vcf.lab:8630 --token <토큰> --kind vm --role DB \
     --ca /root/corp-ca.pem --file '/u01/app/oracle/diag/rdbms/*/*/trace/alert_*.log'
```

- 수집: journald 전체(커널·systemd·sshd·cron…) + `--file` 로 지정한 앱 로그. 60초 하트비트, 디스크 버퍼 1GB(네트워크·서버 장애 시 보관 후 재전송), gzip.
- 지원: Ubuntu 20.04+/Debian 11+(apt), RHEL·Rocky·Alma·Oracle 8/9(dnf). 망분리: `--package fluent-bit_<버전>_amd64.deb`.
- 설치 전 서버·토큰을 먼저 시험하고, 실패하면 원인(401 토큰·접속 불가·인증서)을 표시하고 중단합니다.

### N-3. Linux (rsyslog — 패키지 설치 불가 서버)

```bash
sudo bash install-agent.sh --mode rsyslog --server https://aiops.vcf.lab:8630 --kind vm --role WAS
#  TLS: --syslog-proto tls --ca /root/corp-ca.pem  (rsyslog-gnutls 필요)
```

OS 기본 rsyslog 로 TCP 514(또는 TLS 6514) 전송, 디스크 큐 1GB, systemd 타이머 하트비트(60초). 토큰 불필요.

### N-4. Windows (관리자 PowerShell)

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12'
Invoke-WebRequest -UseBasicParsing https://aiops.vcf.lab:8630/agents/install-windows.ps1 -OutFile install-agent.ps1
.\install-agent.ps1 -Server https://aiops.vcf.lab:8630 -Token <토큰> -Kind vm -Role WAS -CaFile C:\corp-ca.pem `
    -ExtraChannels 'Microsoft-Windows-FailoverClustering/Operational' -Files 'D:\App\logs\*.log'
# 망분리: -Package C:\temp\fluent-bit-5.1.3-win64.zip
```

System·Application 전체 + Security 핵심 이벤트(로그온 실패 4625·잠금 4740·계정/그룹 변경·감사 로그 삭제 1102 등만 원천 구독 — 대량 성공 이벤트는 읽지 않음), 서비스 자동 시작·실패 시 재시작, 토큰이 든 구성 파일은 SYSTEM·Administrators 만 접근.

### N-5. 대량 배포

- Linux: Ansible 예 — `ansible all -b -m script -a "install-agent.sh --server https://aiops.vcf.lab:8630 --token <토큰> --kind vm --ca /etc/pki/ca.pem"`
- Windows: GPO 시작 스크립트·SCCM/Intune 에서 `install-agent.ps1` 실행(같은 인자).
- 템플릿 VM 에 미리 설치하면 새 VM 은 부팅 즉시 등록됩니다(호스트 이름 자동).

### N-6. 확인과 운영

- **VM·서버 에이전트** 화면: 상태(정상·무응답·퇴역), 분당 유입, 최근 15분 경고/오류/위험, vCenter VM·ESXi 매핑.
- **미설치 VM 확인**: vCenter 전원 켜진 VM 중 로그가 없는 VM 목록(수집 사각지대).
- 하트비트·로그가 5분 없으면 `에이전트 무응답` 경보 → 복구 시 자동 확인. 폐기 서버는 **퇴역**.
- 탐지 규칙(게스트 OS): 커널 패닉·hung task·OOM·파일시스템 오류·디스크 가득·SCSI/멀티패스·NFS·세그폴트·서비스 실패·NIC 다운·시간 동기·MCE/EDAC·VMware Tools / Windows 비정상 재부팅(41·6008·1001)·서비스 중단(7031/7034)·디스크(7·51·129·153·NTFS)·로그온 실패·잠금·클러스터(1135·1069)·SQL Server(823/824/9002) / Oracle ORA-00600·07445·04031 등·PostgreSQL·MySQL.

### N-7. (선택) VM 하이퍼바이저(vmx) 로그

게스트 OS 와 별개로 VM 단위 장치·스냅샷·vMotion 오류는 vmx 로그에 남습니다. VM 고급 설정 `vmx.log.destination = syslog-and-disk`, `vmx.log.syslogID = vmx-<VM 이름>` 을 주면 ESXi syslog 경로로 들어와 그 VM 이름으로 표시됩니다(적용 시점은 VM 재시작 후로 계획).

## O. 알림 채널

**운영 설정 › 알림**: Teams·Slack·일반 웹훅·SMTP. 외부 채널은 내구성 발송함(outbox)을 거쳐 실패 시 30초→1시간 백오프로 재시도하고, 한도를 넘으면 **플랫폼 상태 › 외부 알림 발송함** 에서 재발송합니다. 위험(critical)은 LLM 판정을 기다리지 않고 즉시 발송됩니다. 설정 후 **알림 채널 테스트**.

## P. 통합 관제 화면(벽면)

- 주소 `https://aiops.vcf.lab:8630/noc` — 6개 슬롯: vCenter·ESXi / NSX·Edge / NSX ALB / VKS / **물리 서버** / **VM 게스트**.
- 관제 PC(Windows): `msedge.exe --kiosk https://aiops.vcf.lab:8630/noc --edge-kiosk-type=fullscreen` 바로 가기를 시작 프로그램에 등록, 관제 전용 계정으로 로그인.
- 연결이 끊기면 화면이 흑백으로 바뀌고 "몇 시 기준 정보" 배너가 뜹니다. 서버를 업그레이드하면 열린 화면이 자동 새로고침됩니다.

## Q. 이중화(2노드, 선택)

1. 두 번째 VM 을 C~G 와 같이 설치(`--fqdn aiops-02.vcf.lab`), **같은 `.env` 의 `AIOPS_HA_SECRET`** 를 양쪽에 둡니다.
2. 각 `config.yaml`:
   ```yaml
   ha:
     enabled: true
     role: primary                       # aiops-02 는 standby
     node_name: aiops-01
     peer_url: https://aiops-02.vcf.lab:8630   # aiops-02 는 https://aiops-01.vcf.lab:8630
     shared_secret: ${AIOPS_HA_SECRET}
   ```
3. 두 노드 사이 TCP 8630 허용. 커넥터는 양쪽에 동일 등록, 장비 syslog 대상에 **두 노드 모두** 등록(ESXi `--loghost='udp://aiops-01:514,udp://aiops-02:514'`).
4. 외부 알림·ITSM·리포트 메일은 리더 1대만 보냅니다. primary 무응답 30초 → standby 인계(감사 `ha.takeover`), 복구 60초 후 반납.
5. 화면 접속을 하나로: NSX ALB 가상 서비스(풀 2대, 헬스 모니터 HTTPS `GET /readyz` 응답 200) 또는 노드별 주소.

## R. 백업·복구

| 대상 | 방법 |
|---|---|
| DB | 매일 02:30 온라인 백업(서비스 무중단) → `/var/lib/vcf-aiops/backup`. 수동: `vcf-aiopsctl backup` |
| 설정·키 | `sudo tar czf /root/vcf-aiops-etc-$(date +%F).tgz /etc/vcf-aiops` — **secret.key 분실 시 화면 저장 비밀번호 복구 불가** |
| VM | vSphere 백업 솔루션(이미지). 스냅샷은 작업 전 단기 보호용으로만 |

복구:

```bash
sudo systemctl stop vcf-aiops
sudo tar xzf /root/vcf-aiops-etc-YYYY-MM-DD.tgz -C /
sudo -u aiops cp /var/lib/vcf-aiops/backup/aiops-YYYYMMDD-HHMM.db /var/lib/vcf-aiops/aiops.db
sudo rm -f /var/lib/vcf-aiops/aiops.db-wal /var/lib/vcf-aiops/aiops.db-shm
sudo systemctl start vcf-aiops
```

## S. 감시 연동

- 로드밸런서·감시: `GET /readyz`(200/503, 인증 없음), `GET /healthz`(생존).
- Prometheus: `GET /metrics`(허용 IP 또는 scope=metrics 토큰) — 처리 지연·대기열·폐기·DB·발송함·브레이커·HA 리더 등.
- systemd: `systemctl status vcf-aiops` 의 Status 줄, 워치독 재시작 이력 `journalctl -u vcf-aiops | grep -i watchdog`.
- 플랫폼 자체 이상(처리 지연·DB 실패·디스크 부족·알림 발송 실패·이중화 이상)은 일반 이상징후처럼 화면·알림으로 올라옵니다.

## T. 보안 하드닝 점검

- [ ] `--enable-firewall` 또는 수동 `ufw enable`(22·8630·514·6514·162 만)
- [ ] 사내 CA 인증서 적용(H), 에이전트·BMC 는 `--ca` 로 검증
- [ ] 초기 관리자 파일 삭제, LDAP 그룹 매핑, 로컬 admin 비상용 봉인
- [ ] SNMP `communities: [public]` 변경 또는 v3 사용
- [ ] API 토큰 만료일 설정·미사용 토큰 폐기(사용자·토큰)
- [ ] `/etc/vcf-aiops` 0750·파일 0640 유지, `secret.key` 오프라인 보관
- [ ] 감사로그 **무결성 검증**(SHA-256 체인) 정기 실행

## U. 업그레이드

```bash
vcf-aiopsctl backup && sudo tar czf /root/vcf-aiops-etc-$(date +%F).tgz /etc/vcf-aiops
cd /tmp && unzip -q -o vcf-aiops-new.zip
sudo bash /tmp/vcf-aiops/scripts/linux/install.sh --upgrade        # 설정·데이터 유지, 프로그램·패키지 교체
vcf-aiopsctl status
```

열려 있는 콘솔·관제 화면은 재접속 시 새 빌드를 감지해 자동 새로고침합니다. 이중화면 standby → primary 순서로.

## V. 설치 검증 체크리스트

```bash
# 1) syslog 수신 — 다른 리눅스에서
logger -n aiops.vcf.lab -P 514 -d -t vmkernel "NMP lost access to volume ds-test following connectivity issues"
# → 콘솔 실시간 대시보드에 위험 이상징후, 관제 화면 vCenter 슬롯 '장애'

# 2) SNMP 트랩 (snmp 패키지: sudo apt install snmp)
snmptrap -v 2c -c public aiops.vcf.lab '' 1.3.6.1.4.1.8072.2.3.0.1

# 3) 에이전트 하트비트 — VM·서버 에이전트 화면에 '정상'
# 4) BMC — 커넥터 '시험 이벤트' → 실시간 로그 보기에 수신
# 5) 알림 — '알림 채널 테스트' → 웹훅·메일 수신
# 6) 워치독 — sudo systemctl kill -s SIGSTOP vcf-aiops ; 60~90초 뒤 'Watchdog timeout' 후 자동 재시작(journalctl -u vcf-aiops)
# 7) 이중화 — primary 서비스 중지 → 30초 후 standby '알림 리더' 표시
```

## W. 장애 대응

| 증상 | 확인 | 조치 |
|---|---|---|
| 서비스 기동 실패 | `journalctl -u vcf-aiops -n 100` | `vcf-aiopsctl config` 로 설정 문법 확인 |
| 514/162 바인드 실패 | 로그에 `Permission denied`/`Address in use` | 다른 syslog 데몬 점유 여부(`ss -lunp | grep 514`) — rsyslog 의 imudp 수신 비활성 |
| ESXi 로그 없음 | 로그 전송 설정 화면 | ESXi 방화벽 `syslog` 규칙셋, `esxcli system syslog reload` |
| 에이전트 무응답 | 해당 서버 `systemctl status fluent-bit`·`journalctl -u fluent-bit` | 8630 방화벽·인증서(`--ca`)·토큰 폐기 여부 |
| BMC push 미수신 | 커넥터 시험의 구독 항목 | BMC→AIOps 8630, BMC 의 인증서 검증 설정 — 불가하면 `events: sse`(iDRAC) 또는 poll |
| '수집 과부하' 경고 | 플랫폼 상태 › 처리 대기·폐기 | 저가치 로그 억제(`detection.suppress`)·VM 게스트 로그 필터·용량 증설 |
| '디스크 여유' 장애 | `df -h /var/lib/vcf-aiops` | `retention_days` 축소·`backup.keep` 축소·디스크 확장(xfs_growfs) |
| 'LLM 응답 없음' | 상단 Private AI | PAIS 상태·키·모델 id — 그동안 규칙 탐지로 운영 |
| 화면이 흑백·배너 | 브라우저↔8630 | 서버 상태(`vcf-aiopsctl status`)·네트워크 |

## X. 용량·성능 조정

- `server.retention_days`: 원본 로그 보존(디스크와 비례).
- `detection.suppress`: 반복 노이즈 정규식(수집량·화면 부하 감소).
- `pipeline.low_queue`·`high_queue`: 처리 대기 상한(넘치면 info 부터 폐기·집계, 위험은 우선 처리).
- 에이전트: 앱 로그는 필요한 파일만 `--file`, Windows 는 Security 원천 필터 유지.
- 지표: 플랫폼 상태의 **이벤트 루프 지연 p99**(정상 < 50ms), **처리 대기**, **DB 배치 시간**.

## Y. 제거

```bash
sudo bash /opt/vcf-aiops/scripts/linux/uninstall.sh            # 프로그램만(설정·데이터 보존)
sudo bash /opt/vcf-aiops/scripts/linux/uninstall.sh --purge    # 전부 삭제(되돌릴 수 없음)
# 에이전트: sudo bash uninstall-agent.sh [--purge]   (Windows: Stop-Service fluent-bit; sc.exe delete fluent-bit)
```

## Z. 부록

### Z-1. 포트 표

| 방향 | 포트 | 용도 |
|---|---|---|
| 사용자 → AIOps | TCP 8630 | 콘솔·관제 화면·API (HTTPS) |
| 장비 → AIOps | UDP/TCP 514, TCP 6514 | syslog / syslog TLS |
| 장비 → AIOps | UDP 162 | SNMP 트랩 |
| 에이전트(VM·서버) → AIOps | TCP 8630 | Fluent Bit HTTPS(`/api/ingest`) |
| BMC → AIOps | TCP 8630 | Redfish 이벤트 push |
| AIOps → vCenter·NSX·Avi·SDDC·VCF Ops·SRM | TCP 443 | API 폴링 |
| AIOps → VKS API | TCP 6443 | K8s API |
| AIOps → BMC | TCP 443 | Redfish 조회·SSE |
| AIOps → PAIS | TCP 443 | LLM |
| AIOps → isvara.io(선택) | TCP 443 | Isvara iO 질의(`isvara.enabled`) — 질문 문장만 |
| AIOps → 웹훅·SMTP·ITSM | 443 / 25·587 | 알림 |
| AIOps ↔ AIOps(이중화) | TCP 8630 | 상대 노드 확인 |
| AIOps → NTP·DNS·LDAP | 123/udp · 53 · 636 | 시간·이름·인증 |

### Z-2. 파일 위치

| 경로 | 내용 |
|---|---|
| `/opt/vcf-aiops` | 프로그램·venv·스크립트·에이전트 설치 파일 |
| `/etc/vcf-aiops/config.yaml` · `.env` · `secret.key` · `certs/` | 설정·비밀·인증서 |
| `/var/lib/vcf-aiops/aiops.db` · `backup/` · `reports/` · `ragpacks/` | 데이터 |
| `/etc/systemd/system/vcf-aiops.service` | 서비스 |
| `journalctl -u vcf-aiops` | 서비스 로그 |

### Z-3. 명령 요약

`vcf-aiopsctl status | logs | health | restart | backup | config | ports | version | support`

### Z-4. 참고(1차 자료)

- Fluent Bit — [Ubuntu 설치](https://docs.fluentbit.io/manual/installation/downloads/linux/ubuntu) · [Windows 설치](https://docs.fluentbit.io/manual/installation/downloads/windows) · [winevtlog](https://docs.fluentbit.io/manual/pipeline/inputs/windows-event-log-winevtlog) · [systemd](https://docs.fluentbit.io/manual/pipeline/inputs/systemd) · [http 출력](https://docs.fluentbit.io/manual/pipeline/outputs/http) · [버퍼링](https://docs.fluentbit.io/manual/data-pipeline/buffering) · [TLS](https://docs.fluentbit.io/manual/administration/transport-security) · [재시도](https://docs.fluentbit.io/manual/administration/scheduling-and-retries)
- DMTF Redfish — [EventDestination 스키마](https://redfish.dmtf.org/schemas/v1/EventDestination.v1_14_0.json) · [Event 스키마](https://redfish.dmtf.org/schemas/v1/Event.v1_10_0.json)
- HPE — [The Redfish Event Service (iLO)](https://servermanagementportal.ext.hpe.com/docs/concepts/redfishevents/)
- Dell — [Redfish Eventing for iDRAC Alerts](https://dl.dell.com/manuals/common/dell-emc-redfish-eventing-idrac-alerts.pdf)
- vmx 로그 syslog 전달 설정 — [Google Cloud(Mandiant) VMware 탐지·강화 가이드](https://cloud.google.com/blog/topics/threat-intelligence/vmware-detection-containment-hardening)
