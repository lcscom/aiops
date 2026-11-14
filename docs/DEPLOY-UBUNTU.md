# VCF AIops — Ubuntu 24.04 / 26.04 LTS 배포 가이드

배포 패키지: `vcf-aiops-ubuntu.zip` (GitHub `lcscom/aiops` 의 `dist/` · 무결성: `dist/SHA256SUMS`)
하나의 스크립트 `deploy.sh` 가 **사전 점검 → 설치 → 서비스 기동 → 사후 점검 → 결과 요약**을 모두 합니다.

| 항목 | Ubuntu 24.04 LTS | Ubuntu 26.04 LTS |
|---|---|---|
| 기본 Python | 3.12 | 3.14 |
| 상태 | 지원(Python 3.12 로 전체 테스트 통과) | 지원(Python 3.14 로 전체 테스트 통과) |
| 설치 방법 | 아래 동일 | 아래 동일 |

> 세부 설계(디스크 산정·이중화·장비 연동·인증서)는 [INSTALL-UBUNTU.md](INSTALL-UBUNTU.md), 어플라이언스(OVA)는 [OVA.md](OVA.md) 를 보세요.

---

## 1. 준비

| 항목 | 최소 | 권장 |
|---|---|---|
| vCPU / 메모리 | 2 / 4GB | 4~8 / 8~16GB |
| 디스크(`/var/lib`) | 20GB | 60GB 이상(로그 보존량에 비례) |
| 네트워크 | 장비 관리망에서 이 서버로 514/udp·tcp, 6514/tcp, 162/udp, 8630/tcp | DNS A 레코드, 장비와 같은 NTP |
| 인터넷 | pypi.org(온라인 설치) | 망분리면 [5. 오프라인 설치](#5-망분리오프라인-설치) |

Ubuntu Server 설치 때 **OpenSSH 서버**만 선택하면 됩니다. 나머지 패키지는 스크립트가 설치합니다.

## 2. 가장 빠른 설치 (인터넷 되는 서버)

```bash
curl -fsSLO https://raw.githubusercontent.com/lcscom/aiops/main/scripts/linux/deploy.sh
sudo bash deploy.sh
```

`deploy.sh` 가 GitHub 에서 `vcf-aiops-ubuntu.zip` 을 받아 **SHA-256 을 확인한 뒤** 설치합니다. 질문(FQDN·NTP·PAIS 주소/키·포트·방화벽)에 Enter 만 누르면 기본값으로 진행합니다.

## 3. zip 으로 설치

```bash
sudo apt-get install -y unzip            # 없을 때만
unzip vcf-aiops-ubuntu.zip -d vcf-aiops-ubuntu && cd vcf-aiops-ubuntu
sha256sum -c SHA256SUMS 2>/dev/null || true   # dist/SHA256SUMS 를 같이 받았다면
sudo bash deploy.sh                      # 대화형
```

### 무인(자동) 설치

```bash
cp deploy.env.example deploy.env && vi deploy.env     # FQDN·NTP·PAIS 등
sudo bash deploy.sh --env deploy.env --yes
chmod 600 deploy.env                                  # PAIS 키가 들어 있음
```

명령줄로도 됩니다(파일보다 우선):

```bash
sudo bash deploy.sh --yes --fqdn aiops.corp.local --ntp 10.0.0.1,10.0.0.2 \
     --pais-url https://pais.corp.local/v1 --pais-key '키' --enable-firewall
# 사내 CA 인증서: --cert /root/aiops.crt --key /root/aiops.key
```

## 4. 무엇을 자동으로 하나

| 단계 | 내용 |
|---|---|
| 사전 점검 | OS(24.04·26.04)·아키텍처·Python 버전, vCPU·메모리·디스크, 포트 충돌(8630·514·6514·162), FQDN 이름 풀이, 시간 동기화, pypi.org 연결, 기존 설치 감지(있으면 업그레이드로 전환). 실패가 있으면 무인 모드는 중단 |
| 설치 | OS 패키지(python3-venv·sqlite3·chrony·ufw·logrotate) → 서비스 계정 `aiops` → `/opt/vcf-aiops`(프로그램·venv) → `/etc/vcf-aiops`(config.yaml·.env·secret.key·인증서) → `/var/lib/vcf-aiops`(데이터) → 커널 수신 버퍼·journald·NTP → systemd(하드닝·워치독) → ufw 규칙 → 기동 |
| 사후 점검 | 서비스 상태, `/readyz`, 수신 포트, 설치 버전, 방화벽 |
| 기록 | `/var/log/vcf-aiops-deploy/deploy-<시각>.log`(전체 출력, PAIS 키는 가림) · `summary-<시각>.txt`(접속 주소·초기 관리자 위치·다음 할 일) |

설치가 끝나면:

```bash
sudo cat /var/lib/vcf-aiops/initial-admin.txt     # 초기 관리자 비밀번호(첫 로그인 때 변경 → 파일 삭제)
```

브라우저: `https://<FQDN>:8630/` → **수집·연동**에서 vCenter·NSX·Avi·VKS 커넥터를 추가하고, 장비 syslog 대상을 이 서버(UDP/TCP 514, TLS 6514)로 지정하세요.

## 5. 망분리(오프라인) 설치

1. **인터넷 되는 Ubuntu(대상과 같은 버전: 24.04 면 24.04, 26.04 면 26.04)** 에서 번들을 만듭니다. Python 버전이 달라 wheel 이 다르기 때문입니다.
   ```bash
   unzip vcf-aiops-ubuntu.zip -d pkg && cd pkg
   sudo bash deploy.sh --build-offline            # Fluent Bit 에이전트까지: --with-agents
   # → /var/tmp/vcf-aiops-offline-<버전>.tar.gz
   ```
2. 번들을 대상 서버로 옮겨 설치합니다.
   ```bash
   tar xzf vcf-aiops-offline-24.04.tar.gz
   sudo bash vcf-aiops-offline-24.04/vcf-aiops/scripts/linux/deploy.sh --offline vcf-aiops-offline-24.04
   ```

## 6. 업그레이드 · 패치

| 방법 | 명령 |
|---|---|
| 새 zip 으로 | `sudo bash deploy.sh --upgrade` (설정 백업 → 프로그램·패키지 교체 → 설정·데이터 유지) |
| 서명 패치 번들 | 웹 콘솔 › 시스템·관리 › 패치 업로드, 또는 `sudo vcf-aiopsctl patch vcf-aiops-patch-<버전>.tgz` (Ed25519 서명 확인·자동 롤백) |
| 되돌리기 | `sudo vcf-aiopsctl rollback --list` → `sudo vcf-aiopsctl rollback <백업명>` |

## 7. 제거

```bash
sudo bash deploy.sh --uninstall           # 프로그램만(설정·데이터 보존 — 다시 설치하면 그대로 사용)
sudo bash deploy.sh --uninstall --purge   # 설정·데이터·계정까지(되돌릴 수 없음)
```

## 8. 운영 명령

```bash
vcf-aiopsctl status | logs | health | ports | version
sudo vcf-aiopsctl backup                 # 즉시 백업
sudo vcf-aiopsctl support                # 지원용 진단 묶음(비밀 값 가림)
sudo -e /etc/vcf-aiops/config.yaml && sudo systemctl restart vcf-aiops
```

**반드시 백업할 파일**: `/etc/vcf-aiops/secret.key` — 화면에서 저장한 비밀번호의 암호화 키입니다. 잃으면 복호화할 수 없습니다.

## 9. 문제 해결

| 증상 | 확인 |
|---|---|
| 사전 점검 `pypi.org 에 연결 안 됨` | 프록시면 `sudo https_proxy=http://프록시:포트 bash deploy.sh`, 아니면 오프라인 번들 |
| `다른 프로그램이 사용 중 udp/514` | `sudo systemctl disable --now rsyslog`(이 서버에서 원격 syslog 를 받지 않는다면) 또는 장비 syslog 포트를 바꾸세요 |
| `/readyz 응답 없음` | `journalctl -u vcf-aiops -n 100 --no-pager`, `vcf-aiopsctl health` |
| 26.04 에서 패키지 빌드 오류 | 인터넷 설치는 바이너리 wheel 로 받습니다. 망분리면 **26.04 에서** `--build-offline` 으로 만든 번들인지 확인 |
| 인증서 경고 | 자체 서명 인증서입니다. 사내 CA 인증서로 `--cert/--key` 재실행 또는 웹 콘솔 › 시스템·관리 › 인증서 |

## 10. 확인 범위

- 단위·통합 테스트(513개)를 Python 3.12(24.04 기본)·3.13·3.14(26.04 기본)에서 모두 통과했습니다.
- 이 작업 환경(Ubuntu 24.04 컨테이너)에서 zip 풀기 → 사전 점검 → 설치(systemd 단계 제외) → 설치본 기동(/readyz 200) → 제거(--purge)까지 확인했습니다.
- `deploy.sh` 의 실제 Ubuntu 24.04·26.04 VM 설치는 아직 확인하지 못했습니다(이 문서를 쓴 작업 환경에 systemd VM 이 없음). 첫 설치 때 결과 요약 파일을 같이 보내 주면 반영하겠습니다.
