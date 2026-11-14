# VCF AIops — OVA 어플라이언스 (배포 즉시 자동 구성)

`vcf-aiops-<버전>.ova` 하나를 vCenter 에 배포하면서 **배포 크기**와 **vApp 속성**(호스트 이름·IP·DNS·NTP·비밀번호·PAIS·인증서)만 입력하면, 첫 부팅에 OS·네트워크·데이터 디스크·인증서·서비스까지 자동으로 구성됩니다. 콘솔에 `Status : READY` 가 뜨면 바로 `https://<FQDN>:8630/` 로 접속합니다.

| 항목 | 내용 |
|---|---|
| OS | Ubuntu Server 24.04 LTS(최소 구성), 커널 linux-virtual, open-vm-tools |
| 부팅 | UEFI + **보안 부팅**(Canonical 서명 shim → grub → 커널) |
| 가상 하드웨어 | vmx-17(ESXi 7.0 이상), PVSCSI, VMXNET3, VMware Tools 시간 동기화 끔(chrony 사용), disk.EnableUUID |
| 디스크 | 디스크1 OS 40GB(실사용 약 0.6GB) · 디스크2 데이터(배포 크기별 빈 디스크 → 첫 부팅에 XFS, `/var/lib/vcf-aiops`) |
| 앱 | `/opt/vcf-aiops` + Python venv 사전 설치 → 첫 부팅 구성에 인터넷이 필요 없음(망분리 그대로 배포) · govc 포함(커넥터 화면에서 vCenter 수집 전용 계정 자동 생성) |
| 비밀값 | 이미지에 없음. SSH 호스트 키·machine-id·설정 암호화 키·TLS 인증서·HA 비밀은 VM 마다 첫 부팅에 생성 |

---

## 1. 배포 크기

| 선택 | vCPU | 메모리 | 데이터 디스크 | 대상(보존 7일 기준) |
|---|---|---|---|---|
| 소(Small) | 4 | 8GB | 60GB | PoC·관리 도메인, 평균 ~100 EPS |
| **중(Medium, 기본)** | 8 | 16GB | 250GB | VI 도메인 1~2개, 평균 ~500 EPS |
| 대(Large) | 8 | 32GB | 700GB | 다수 도메인·VM 에이전트, 평균 ~1,500 EPS |

데이터 디스크는 배포 마법사의 *하드웨어 사용자 지정*에서 늘릴 수 있고, 배포 후에 늘려도 재부팅 때 XFS 가 자동 확장됩니다(OS 디스크도 동일 — growpart + resize2fs).

## 2. vSphere Client 로 배포

1. DNS 에 A·PTR 레코드 등록(예: `aiops.corp.example → 10.10.20.50`).
2. 클러스터 우클릭 › **OVF 템플릿 배포** › 로컬 파일 `vcf-aiops-<버전>.ova`.
3. 이름·폴더 › 컴퓨팅 리소스 › 세부 정보 검토 › **구성(배포 크기)** 선택.
4. 스토리지: 가상 디스크 형식 **씩 프로비저닝(Lazy Zeroed)** 권장(SQLite 쓰기 지연 감소) · 네트워크 `Management` → 관리망 포트그룹.
5. **템플릿 사용자 지정**(vApp 속성) — 아래 표. 비밀번호 2개는 12자 이상이어야 다음으로 넘어갑니다.
6. 완료 → 전원 켜기 → VM 콘솔에서 `Status : CONFIGURING` → `READY`(ESXi 에서 보통 2~4분).

### vApp 속성

| 키 | 화면 이름 | 기본값 | 설명 |
|---|---|---|---|
| `net.hostname` | 호스트 이름(FQDN) | — | 예: aiops.corp.example — 인증서 SAN·장비 syslog 대상·에이전트/BMC 접속 주소. DNS A·PTR 레코드를 먼저 등록하세요. |
| `net.ip` | IPv4 주소 | — | 고정 IP(예: 10.10.20.50). 비우면 DHCP — 운영은 고정 IP 권장. |
| `net.prefix` | 서브넷 접두 길이 | 24 | 예: 24 (= 255.255.255.0). DHCP 이면 무시. |
| `net.gateway` | 기본 게이트웨이 | — | 예: 10.10.20.1. DHCP 이면 무시. |
| `net.dns` | DNS 서버 | — | 쉼표 구분, 예: 10.10.0.11,10.10.0.12 |
| `net.search` | DNS 검색 도메인 | — | 쉼표 구분, 예: corp.example |
| `net.ntp` | NTP 서버 | — | 쉼표 구분 — ESXi·vCenter·NSX 와 같은 NTP 를 쓰세요(로그 시각 상관 분석에 필수). |
| `sys.password` | OS 관리자(aiopsadmin) 비밀번호 | — | 콘솔·SSH 로그인 계정 aiopsadmin(sudo). 12자 이상. 최초 로그인 시 변경이 강제됩니다. root 로그인은 막혀 있습니다. |
| `sys.ssh_key` | SSH 공개 키(선택) | — | aiopsadmin 의 authorized_keys 에 넣을 한 줄(ssh-ed25519 … / ssh-rsa …). |
| `sys.ssh` | SSH 사용 | true | 끄면 SSH 서비스를 비활성화합니다(콘솔만 사용). |
| `sys.timezone` | 시간대 | Asia/Seoul | IANA 이름(예: Asia/Seoul, UTC). |
| `sys.firewall` | OS 방화벽(ufw) 사용 | true | 22/tcp, 웹 포트, 514/udp·tcp, 6514/tcp, 162/udp 만 허용. |
| `app.admin_password` | 웹 콘솔 admin 초기 비밀번호 | — | 웹 콘솔 로컬 관리자 admin 의 초기 비밀번호. 12자 이상. 최초 로그인 시 변경이 강제됩니다. |
| `app.port` | 웹·API 포트 | 8630 | 콘솔·관제 화면·에이전트(HTTPS)·Redfish push 수신 포트. |
| `app.pais_url` | Private AI(PAIS) 주소 | — | OpenAI 호환 엔드포인트, 예: https://pais.corp.example/v1 — 비우면 규칙 탐지만 동작(나중에 설정 가능). |
| `app.pais_key` | PAIS API 키 | — | PAIS 에서 발급한 키. 나중에 /etc/vcf-aiops/.env 에서 바꿀 수 있습니다. |
| `app.llm_model` | LLM 모델 id | google/gemma-4-31B-it | PAIS GET /v1/models 의 id 와 정확히 일치해야 합니다. |
| `app.retention_days` | 원본 로그 보존(일) | 7 | 데이터 디스크 크기에 비례 — 배포 크기 표는 7일 기준. |
| `app.snmp_community` | SNMP 트랩 커뮤니티 | public | 운영 전 사내 값으로 변경하세요(v3 는 설치 후 config.yaml). |
| `app.cert_pem` | 서버 인증서(PEM, base64·선택) | — | 사내 CA 발급 인증서(체인 포함 가능) PEM 파일을 base64 한 줄로(`base64 -w0 aiops.crt`). 비우면 자체 서명 인증서를 만듭니다. |
| `app.key_pem` | 서버 개인 키(PEM, base64·선택) | — | 위 인증서의 개인 키(`base64 -w0 aiops.key`). 인증서와 함께 넣으세요. |

사내 CA 인증서를 넣으면 첫 부팅에 인증서·개인 키 짝(공개 키 일치)을 확인한 뒤 설치하고, 맞지 않으면 자체 서명 인증서로 대체합니다(콘솔 배너는 READY, 사유는 `vcf-aiopsctl provision-log`).

## 3. CLI 배포

**ovftool → vCenter**

```bash
ovftool --acceptAllEulas --noSSLVerify --powerOn \
  --name=aiops01 --deploymentOption=medium --diskMode=thick \
  --datastore=vsanDatastore --net:Management="mgmt-pg" \
  --prop:net.hostname=aiops.corp.example --prop:net.ip=10.10.20.50 --prop:net.prefix=24 \
  --prop:net.gateway=10.10.20.1 --prop:net.dns=10.10.0.11,10.10.0.12 --prop:net.search=corp.example \
  --prop:net.ntp=10.10.0.1,10.10.0.2 \
  --prop:sys.password='Os#Admin-2026!' --prop:app.admin_password='Web#Admin-2026!' \
  --prop:app.pais_url=https://pais.corp.example/v1 --prop:app.pais_key='pk-xxxxxxxx' \
  vcf-aiops-1.2.0.ova 'vi://administrator%40vsphere.local@vcsa.corp.example/DC01/host/Cluster01'
```

vCenter 없이 **ESXi 에 직접** 배포하면 ESXi 는 vApp 속성을 VM 에 전달하지 않으므로 ovftool 에 `--X:injectOvfEnv` 를 추가하고 `--powerOn` 과 함께 쓰세요(govc 는 옵션 JSON 의 `"InjectOvfEnv": true`, `"PowerOn": true`).

**govc**

```bash
govc import.spec vcf-aiops-1.2.0.ova > aiops.json      # Deployment·PropertyMapping·NetworkMapping 을 편집
govc import.ova -options aiops.json -name aiops01 -ds vsanDatastore -pool /DC01/host/Cluster01/Resources vcf-aiops-1.2.0.ova
govc vm.power -on aiops01
```

## 4. 첫 부팅에서 일어나는 일

| 단계 | 유닛 | 내용 |
|---|---|---|
| 네트워크 기동 전 (매 부팅) | `vcf-aiops-provision-early` | vApp 속성 읽기(VMware Tools `guestinfo.ovfEnv`) → SSH 호스트 키 생성 → 호스트 이름·`/etc/hosts` → netplan(고정 IP 또는 DHCP, 서브넷 밖 게이트웨이는 on-link) → OS 디스크 확장 → 빈 데이터 디스크 XFS 포맷·마운트(나중에 추가한 디스크면 기존 데이터 이전 후 마운트) |
| 네트워크 이후 (최초 1회) | `vcf-aiops-provision` | 시간대 → `aiopsadmin` 비밀번호·SSH 키(최초 로그인 변경 강제) → SSH 사용 여부 → `install.sh --stage configure`(설정 암호화 키·`.env`·`config.yaml`·인증서·chrony NTP·ufw·서비스 기동) → `/readyz` 확인 → 콘솔 배너 READY |
| 이후 부팅 | 두 유닛 | 변경된 vApp 속성 반영(아래 5절), 디스크 확장, 배너 갱신 |

웹 콘솔 admin 초기 비밀번호는 1회용 환경 파일로만 서비스에 전달하고, 준비 확인 직후 `shred` 로 지웁니다. vApp 속성 캐시(`/run`, 메모리)도 구성 직후 삭제합니다. `sys.password` 를 비운 채 배포하면 임시 비밀번호를 만들어 **VM 콘솔 배너에만** 표시하고, 최초 로그인 때 바꾸면 배너에서 사라집니다. `app.admin_password` 를 비우면 `/var/lib/vcf-aiops/initial-admin.txt` 에 만듭니다.

## 5. 배포 후 vApp 속성을 바꾸면

VM 편집 › **vApp 옵션**에서 값을 바꾸고 재부팅합니다.

| 속성 | 재부팅 시 |
|---|---|
| `net.*`(IP·게이트웨이·DNS·검색 도메인) | 반영 |
| `net.hostname` | 반영 + `config.yaml` 의 `public_url`·`advertise_host` 갱신, 자체 서명 인증서 재발급, 서비스 재시작(사내 CA 인증서는 유지 — 새 이름으로 재발급 필요) |
| `net.ntp` · `sys.timezone` · `sys.ssh` | 반영 |
| 비밀번호·SSH 키·PAIS·인증서·포트·보존·SNMP | 반영 안 함(최초 1회만) — 웹 콘솔 또는 `/etc/vcf-aiops` 에서 변경 |

장비들이 이미 FQDN 으로 syslog 를 보내고 있다면 호스트 이름 변경은 DNS 와 장비 설정을 같이 바꿔야 합니다.

## 6. 배포 후 바로 할 일

1. 웹 콘솔 `admin`·OS `aiopsadmin` 로그인 → 비밀번호 변경(강제). 웹 admin 비밀번호를 잊으면 콘솔/SSH 에서 `sudo vcf-aiopsctl reset-admin`.
2. **vApp 옵션의 비밀값 지우기**: vApp 속성 값은 vCenter 와 게스트의 `guestinfo` 에서 계속 읽힐 수 있습니다. 구성이 끝났으면 `sys.password`·`app.admin_password`·`app.pais_key`·`app.key_pem` 값을 비워 두세요(이미 구성되어 재적용되지 않음).
3. 사내 CA 인증서로 교체(배포 때 넣지 않은 경우): `sudo install -m 0644 aiops.crt /etc/vcf-aiops/certs/` · `sudo install -m 0640 -g aiops aiops.key /etc/vcf-aiops/certs/` · `sudo systemctl restart vcf-aiops`.
4. 관제용이므로 **메모리 예약 100%**, 2노드면 DRS **VM-VM 반선호** 규칙.
5. 커넥터 추가 시 **관리자 계정으로 수집 전용 계정 만들기**로 읽기 전용 계정을 바로 만들 수 있습니다([ACCOUNTS.md](ACCOUNTS.md)). vCenter 를 등록하면 VKS(Supervisor·워크로드 클러스터)는 자동으로 찾습니다.
6. 이후 설정은 [INSTALL-UBUNTU.md](INSTALL-UBUNTU.md) **I 절(첫 로그인)부터** 동일합니다(커넥터·로그 전송·BMC·에이전트·알림·이중화·백업).

## 7. 상태 확인 · 문제 해결

```bash
vcf-aiopsctl status             # 서비스·readyz
vcf-aiopsctl ovf                # 배포 때 입력한 vApp 속성(비밀값 가림)·해석된 네트워크·프로비저닝 상태
vcf-aiopsctl provision-log      # 이번 부팅의 프로비저닝 로그
sudo systemctl restart vcf-aiops-provision     # 최초 구성이 실패했을 때 원인 조치 후 재실행
```

| 증상 | 원인·조치 |
|---|---|
| 배너 `FAILED` | `vcf-aiopsctl provision-log` 의 ✖ 줄 확인 → 조치 후 `systemctl restart vcf-aiops-provision` |
| 속성 출처 `없음` | vCenter 를 거치지 않은 배포(ESXi 직접·복제) — ovftool `--X:injectOvfEnv`, 또는 `/etc/vcf-aiops/ovf-env.xml` 에 같은 형식으로 넣고 재부팅 |
| IP 가 안 바뀜 | VMware Tools 실행 여부(`systemctl status open-vm-tools`), VM 편집 › vApp 옵션 › OVF 환경 전송이 *VMware Tools* 인지 확인 |
| 데이터 디스크가 OS 디스크에 있음 | 두 번째 디스크가 없거나 4GB 미만·이미 파티션이 있음 → 빈 디스크 추가 후 재부팅하면 기존 데이터를 옮기고 마운트 |
| 보안 부팅으로 부팅 실패 | ESXi 6.7 이하 또는 EFI 비활성 — VM 옵션 › 부팅 옵션 › 펌웨어 EFI 확인 |

## 8. 업그레이드

- **현장 업그레이드(권장)**: 새 패키지 zip 을 VM 에 복사 → `sudo bash vcf-aiops/scripts/linux/install.sh --upgrade` (설정·데이터 유지). OS 는 사내 미러로 `apt update && apt upgrade`(커널 갱신 시 grub 설정 자동 재생성).
- **새 OVA 로 교체**: 새 VM 배포 → 기존 VM 에서 `vcf-aiopsctl backup` + `/etc/vcf-aiops` 백업 → 새 VM 에 복원(가이드 R 절).

## 9. OVA 직접 빌드

빌드 PC: Ubuntu 24.04 LTS(권장)·root·여유 15GB, Ubuntu 저장소·PyPI(또는 사내 미러) 접근. 약 10분.

```bash
sudo bash appliance/build-ova.sh --version 1.2.0 --out ./out
#   사내 미러 : --mirror http://mirror.corp.example/ubuntu   ·   PIP_INDEX_URL=https://pypi.corp.example/simple
#   PyPI 차단 : --wheelhouse <build-offline.sh 로 만든 wheelhouse 폴더>
# 결과: out/vcf-aiops-1.2.0.ova (약 270MB) · .ovf · .mf(SHA256) · -disk1.vmdk · .SHA256SUMS
```

구성 파일: `appliance/spec.py`(배포 크기·vApp 속성 단일 정의) · `appliance/provision.py`(첫 부팅 구성) · `appliance/make-ovf.py`(OVF·매니페스트·OVA) · `appliance/systemd/`(프로비저닝 유닛).

## 10. 검증 내역

| 항목 | 방법 | 결과 |
|---|---|---|
| 이미지 빌드 | `build-ova.sh` (Ubuntu 24.04 빌드 호스트) | OVA 268MB(문서·man 제외, 일반 .pyc 제거, 빈 블록 0 채움), OS 실사용 약 600MB |
| 보안 부팅 | 출하 VMDK → QEMU + OVMF(Microsoft 키 등록) | shim → grub → 커널 부팅, `SecureBoot enabled` |
| 드라이버 | QEMU `pvscsi`·`vmxnet3` 장치 | 두 모듈 initramfs 포함·로드, 데이터 디스크(PVSCSI)·NIC(VMXNET3) 동작 |
| 첫 부팅 자동 구성 | vSphere 와 같은 형식의 ovf-env.xml(ISO 전송) | 고정 IP·FQDN·DNS·NTP·시간대·ufw·데이터 디스크 XFS·OS 디스크 확장·인증서 SAN(FQDN·IP)·PAIS·보존일·SNMP 반영, `/readyz` 200, 1회용 비밀 파일 삭제 |
| 계정 | SSH | OS 비밀번호 최초 로그인 변경 강제, 웹 admin 로그인(must_change) |
| 재구성 | FQDN·NTP 변경 후 재부팅 | 설정·인증서 갱신, 비밀번호는 재적용 안 됨 |
| 속성 없음 배포 | ISO·데이터 디스크 없이 부팅 | DHCP·임시 비밀번호 배너·initial-admin.txt, 이후 디스크 추가 시 데이터 이전 |
| OVF 해석 | govc 0.46.3 `import.spec`, vcsim `import.ovf` | 배포 크기 3종(소 4/8GB/60GB, 대 8/32GB/700GB), vApp 속성 21개, PVSCSI·VMXNET3 |

실제 vCenter·ESXi 배포(VMware Tools `guestinfo.ovfEnv` 전송, `vmw:Config` 의 EFI·보안 부팅·시간 동기화 적용, fileRef 없는 빈 데이터 디스크 생성)는 이 환경에서 시험하지 못했습니다. 첫 배포 때 VM 편집 화면에서 펌웨어 EFI·보안 부팅·디스크 2개를 확인하세요.

참고(1차 자료): DMTF [OVF 1.x — Disk 의 fileRef 생략 시 빈 디스크](https://jclouds.apache.org/reference/javadoc/2.6.x/org/jclouds/ovf/Disk.html)(DSP0243 정의 인용) · [Ubuntu 보안 부팅(shim·서명 grub)](https://wiki.ubuntu.com/UEFI/SecureBoot) · [netplan 설정](https://netplan.readthedocs.io/en/stable/netplan-yaml/) · [govc import](https://github.com/vmware/govmomi/blob/main/govc/USAGE.md) · [ESXi 직접 배포 시 --X:injectOvfEnv(William Lam)](https://williamlam.com/2014/05/how-to-finally-inject-ovf-properties-into-vcsa-when-deploying-directly-onto-esxi.html)
