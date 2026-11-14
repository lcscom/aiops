#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops — Ubuntu Server 설치 / 업그레이드 (24.04·26.04 LTS 권장, 22.04 LTS 지원)
#
#  배치
#    /opt/vcf-aiops          프로그램(root 소유·읽기 전용) + venv
#    /etc/vcf-aiops          config.yaml · .env · secret.key · certs/   (root:aiops 0750, 파일 0640)
#    /var/lib/vcf-aiops      데이터(SQLite·백업·리포트·RAG)              (aiops:aiops 0750)
#    systemd vcf-aiops.service — Type=notify, 워치독 60초, 하드닝, 514/162 바인드는 CAP_NET_BIND_SERVICE 만 부여
#
#  사용 예
#    sudo bash scripts/linux/install.sh --fqdn aiops.vcf.lab --ntp 10.10.0.1,10.10.0.2 \
#         --pais-url https://pais.vcf.lab/v1 --pais-key 'xxxxx'
#    sudo bash scripts/linux/install.sh --cert /root/aiops.crt --key /root/aiops.key      # 사내 CA 인증서
#    sudo bash scripts/linux/install.sh --offline /root/vcf-aiops-offline                # 망분리(오프라인 번들)
#    sudo bash scripts/linux/install.sh --upgrade                                        # 프로그램만 교체(설정·데이터 유지)
#
#  옵션
#    --fqdn NAME          이 서버 FQDN(인증서·장비 syslog 대상·에이전트 접속 주소) — 기본 hostname -f
#    --port N             웹/API 포트(기본 8630)
#    --cert F --key F     사내 CA 발급 인증서(PEM). 없으면 자체 서명 인증서 생성(SAN: FQDN·짧은 이름·IP)
#    --ntp a,b            chrony NTP 서버(로그 시각 상관 분석에 필수)
#    --pais-url / --pais-key   VMware Private AI Services(OpenAI 호환) 주소·키 → /etc/vcf-aiops/.env
#    --offline DIR        build-offline.sh 로 만든 번들 폴더(wheelhouse/, debs/)
#    --python BIN         파이썬 실행 파일(기본 python3)
#    --enable-firewall    ufw 규칙 추가 후 ufw 활성화(원격 접속 중이면 22/tcp 허용 포함)
#    --upgrade            설정 파일을 덮어쓰지 않고 프로그램·패키지만 갱신
#    --llm-model ID       PAIS 모델 id(기본 google/gemma-4-31B-it) · --retention-days N(기본 7) · --snmp-community S(기본 public)
#    --stage all|image|configure
#                         all(기본)=전체 · image=프로그램·venv·서비스 파일까지(비밀·인증서·기동 제외, OVA 이미지 빌드용)
#                         configure=설정·비밀 키·인증서·NTP·방화벽·기동만(이미지에 프로그램이 이미 있는 어플라이언스 첫 부팅용)
# =============================================================================================
set -euo pipefail

SRC="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX=/opt/vcf-aiops; ETC=/etc/vcf-aiops; DATA=/var/lib/vcf-aiops; SVC=vcf-aiops; USR=aiops
FQDN=""; PORT=8630; CERT=""; KEY=""; NTP=""; PAIS_URL=""; PAIS_KEY=""; OFFLINE=""; PY=python3; FW=0; UPGRADE=0
NO_SYSTEMD=0; STAGE=all; MODEL="google/gemma-4-31B-it"; RETENTION=7; SNMP_COMM=public

die()  { echo -e "\e[31m✖ $*\e[0m" >&2; exit 1; }
ok()   { echo -e "  \e[32m✔\e[0m $*"; }
warn() { echo -e "  \e[33m!\e[0m $*"; }
step() { echo -e "\n\e[36m▶ $*\e[0m"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fqdn) FQDN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --cert) CERT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --ntp) NTP="$2"; shift 2 ;;
    --pais-url) PAIS_URL="$2"; shift 2 ;;
    --pais-key) PAIS_KEY="$2"; shift 2 ;;
    --offline) OFFLINE="$(cd "$2" && pwd)"; shift 2 ;;
    --python) PY="$2"; shift 2 ;;
    --enable-firewall) FW=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;      # 컨테이너 시험용(서비스 등록·기동 생략)
    --stage) STAGE="$2"; shift 2 ;;
    --llm-model) MODEL="$2"; shift 2 ;;
    --retention-days) RETENTION="$2"; shift 2 ;;
    --snmp-community) SNMP_COMM="$2"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "알 수 없는 옵션: $1 (--help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "root(sudo)로 실행하세요."
case "$STAGE" in all|image|configure) ;; *) die "--stage 는 all|image|configure" ;; esac
[[ "$RETENTION" =~ ^[0-9]+$ && "$RETENTION" -ge 1 ]] || die "--retention-days 는 1 이상 정수"
[[ "$SNMP_COMM" =~ ^[A-Za-z0-9._@:-]{1,64}$ ]] || die "--snmp-community 는 영문·숫자·._@:- (1~64자)"
[[ "$MODEL" =~ ^[A-Za-z0-9._/:-]{1,128}$ ]] || die "--llm-model 형식 오류"
[[ "$STAGE" == image ]] && NO_SYSTEMD=1
[[ -f "$SRC/app/main.py" ]] || die "프로젝트 폴더를 찾을 수 없습니다: $SRC"
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || warn "Ubuntu 가 아닙니다(${PRETTY_NAME:-?}) — 패키지 이름이 다를 수 있습니다."
case "${VERSION_ID:-}" in 24.04|26.04|22.04) ;; *) warn "검증 버전은 Ubuntu 24.04·26.04 입니다(현재 ${VERSION_ID:-?})." ;; esac
FQDN="${FQDN:-$(hostname -f 2>/dev/null || hostname)}"
SHORT="${FQDN%%.*}"
IPADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -n "$CERT" && -z "$KEY" || -z "$CERT" && -n "$KEY" ]] && die "--cert 와 --key 는 함께 지정하세요."
echo "[$STAGE] 설치 원본 $SRC → $PREFIX · FQDN $FQDN ($IPADDR) · 포트 $PORT$([[ $UPGRADE -eq 1 ]] && echo ' · 업그레이드')$([[ -n $OFFLINE ]] && echo " · 오프라인 $OFFLINE")"

# ---------------------------------------------------------------- 1. OS 패키지
if [[ "$STAGE" != configure ]]; then
step "1. OS 패키지"
PKGS=(python3-venv python3-pip sqlite3 curl ca-certificates openssl chrony ufw logrotate)
if [[ -n "$OFFLINE" ]]; then
  if compgen -G "$OFFLINE/debs/*.deb" >/dev/null; then
    dpkg -i "$OFFLINE"/debs/*.deb >/dev/null 2>&1 || apt-get install -f -y --no-download >/dev/null 2>&1 || true
    ok "오프라인 .deb 설치 시도 완료"
  fi
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y "${PKGS[@]}" >/dev/null
  ok "${PKGS[*]}"
fi
"$PY" -c 'import sys,venv,ensurepip; assert sys.version_info>=(3,10), sys.version' 2>/dev/null \
  || die "$PY 에 venv/ensurepip 가 없거나 3.10 미만입니다 — apt install python3-venv (오프라인: 번들 debs/)"
ok "$("$PY" --version)"
fi

# ---------------------------------------------------------------- 2. 계정·폴더
step "2. 서비스 계정·폴더"
getent group "$USR" >/dev/null || groupadd --system "$USR"
id "$USR" >/dev/null 2>&1 || useradd --system --gid "$USR" --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USR"
install -d -m 0755 -o root -g root "$PREFIX"
install -d -m 0750 -o root -g "$USR" "$ETC" "$ETC/certs"
install -d -m 0750 -o "$USR" -g "$USR" "$DATA" "$DATA/backup"
ok "계정 $USR · $PREFIX · $ETC · $DATA"

# ---------------------------------------------------------------- 3. 프로그램 배치
if [[ "$STAGE" != configure ]]; then
step "3. 프로그램 배치"
if [[ "$SRC" != "$PREFIX" ]]; then
  for d in app scripts deploy ragpacks docs tests appliance; do
    [[ -d "$SRC/$d" ]] || continue
    rm -rf "${PREFIX:?}/$d"
    cp -a "$SRC/$d" "$PREFIX/$d"
  done
  for f in requirements.txt requirements-dev.txt config.example.yaml README.md CHANGELOG.md .env.example VERSION LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt; do
    [[ -f "$SRC/$f" ]] && install -m 0644 "$SRC/$f" "$PREFIX/$f"
  done
fi
find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
chown -R root:root "$PREFIX"; chmod -R go-w "$PREFIX"
chmod 0755 "$PREFIX"/scripts/linux/*.sh "$PREFIX"/deploy/agents/linux/*.sh "$PREFIX"/appliance/*.py 2>/dev/null || true
ok "$(du -sh "$PREFIX" | cut -f1) 배치"

# ---------------------------------------------------------------- 4. 파이썬 가상환경
step "4. 파이썬 가상환경 · 패키지"
[[ -x "$PREFIX/venv/bin/python" ]] || "$PY" -m venv "$PREFIX/venv"
PIP=("$PREFIX/venv/bin/python" -m pip --disable-pip-version-check -q)
if [[ -n "$OFFLINE" ]]; then
  [[ -d "$OFFLINE/wheelhouse" ]] || die "$OFFLINE/wheelhouse 없음"
  "${PIP[@]}" install --no-index --find-links "$OFFLINE/wheelhouse" -r "$PREFIX/requirements.txt"
else
  "${PIP[@]}" install --upgrade pip >/dev/null
  "${PIP[@]}" install -r "$PREFIX/requirements.txt"
fi
# 읽기 전용 배치 + python -O 실행 → 최적화(.opt-1.pyc) 바이트코드를 미리 생성(기동 시간 단축)
"$PREFIX/venv/bin/python" -m compileall -q -j 0 -o 1 "$PREFIX/app" "$PREFIX/venv/lib" >/dev/null 2>&1 || true
"$PREFIX/venv/bin/python" -c "import fastapi, uvicorn, httpx, pyVmomi, pysnmp, ldap3, cryptography" \
  && ok "의존 패키지 확인($("$PREFIX/venv/bin/python" -c 'import fastapi,uvicorn;print("fastapi",fastapi.__version__,"· uvicorn",uvicorn.__version__)'))"
fi
[[ -x "$PREFIX/venv/bin/python" ]] || die "$PREFIX/venv 가 없습니다 — --stage configure 는 프로그램이 설치된 이미지에서만 사용"
# govc — 커넥터 화면 '수집 전용 계정 만들기'(vCenter SSO 사용자 생성). 오프라인 번들에 있거나 인터넷이 되면 설치
if [[ "$STAGE" == all && ! -x "$PREFIX/bin/govc" ]]; then
  GOVC_SHA=91f96c35a48cdde8c5e661c6c219bdf1303fbefbedcf13eb078b64a194e56d4a; GT="$(mktemp)"
  if [[ -n "$OFFLINE" && -f "$OFFLINE/govc_Linux_x86_64.tar.gz" ]]; then cp "$OFFLINE/govc_Linux_x86_64.tar.gz" "$GT"
  else curl -fsSL --max-time 60 -o "$GT" https://github.com/vmware/govmomi/releases/download/v0.46.3/govc_Linux_x86_64.tar.gz 2>/dev/null || :; fi
  if echo "$GOVC_SHA  $GT" | sha256sum -c --quiet - 2>/dev/null; then
    install -d "$PREFIX/bin"; tar -xzf "$GT" -C "$PREFIX/bin" govc && chmod 0755 "$PREFIX/bin/govc" && ok "govc 설치(vCenter 수집 전용 계정 자동 생성용)"
  else warn "govc 미설치 — vCenter 수집 전용 계정 자동 생성 불가(나머지 기능 정상). 수동: $PREFIX/bin/govc"; fi
  rm -f "$GT"
fi

# ---------------------------------------------------------------- 5. 설정·비밀키·인증서
if [[ "$STAGE" != image ]]; then
step "5. 설정 · 비밀 키 · 인증서"
if [[ ! -f "$ETC/secret.key" ]]; then
  "$PREFIX/venv/bin/python" -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())" > "$ETC/secret.key"
  ok "설정 암호화 키 생성: $ETC/secret.key (백업 필수 — 분실 시 화면에서 저장한 비밀번호 복호화 불가)"
fi
if [[ ! -f "$ETC/.env" ]]; then
  cat > "$ETC/.env" <<EOF
# VCF AIops 환경 변수 — config.yaml 의 \${이름} 으로 참조
PAIS_BASE_URL=${PAIS_URL:-https://pais.vcf.lab/v1}
PAIS_API_KEY=${PAIS_KEY}
# 이중화(ha.enabled=true) 시 두 노드 동일 값
AIOPS_HA_SECRET=$(openssl rand -hex 24)
EOF
  ok ".env 생성(PAIS 주소·키 $( [[ -n $PAIS_KEY ]] && echo '입력됨' || echo '— 나중에 편집'))"
else
  [[ -n "$PAIS_URL" ]] && sed -i "s#^PAIS_BASE_URL=.*#PAIS_BASE_URL=${PAIS_URL}#" "$ETC/.env"
  [[ -n "$PAIS_KEY" ]] && sed -i "s#^PAIS_API_KEY=.*#PAIS_API_KEY=${PAIS_KEY}#" "$ETC/.env"
fi
if [[ -n "$CERT" ]]; then
  install -m 0644 "$CERT" "$ETC/certs/aiops.crt"; install -m 0640 -g "$USR" "$KEY" "$ETC/certs/aiops.key"
  ok "인증서 설치: $(openssl x509 -in "$ETC/certs/aiops.crt" -noout -subject -enddate | tr '\n' ' ')"
elif [[ ! -f "$ETC/certs/aiops.crt" ]]; then
  bash "$PREFIX/scripts/linux/make-cert.sh" --fqdn "$FQDN" --out "$ETC/certs" >/dev/null 2>&1
  ok "자체 서명 인증서 생성(SAN: $FQDN, $SHORT${IPADDR:+, $IPADDR}) — 운영 전 사내 CA 인증서로 교체 권장"
fi
chown root:"$USR" "$ETC/certs/aiops.key" "$ETC/secret.key" "$ETC/.env"; chmod 0640 "$ETC/certs/aiops.key" "$ETC/secret.key" "$ETC/.env"
if [[ ! -f "$ETC/config.yaml" ]]; then
  cat > "$ETC/config.yaml" <<EOF
# VCF AIops 설정 — Ubuntu 설치본. 전체 항목·설명: $PREFIX/config.example.yaml
# 대부분은 웹 화면(운영 설정)에서 바꿀 수 있고, 화면 저장값이 이 파일보다 우선합니다.
server:
  host: 0.0.0.0
  port: ${PORT}
  db_path: ${DATA}/aiops.db
  retention_days: ${RETENTION}                  # 원본 로그 보존(일) — 디스크 계산은 가이드 참고
  public_url: https://${FQDN}:${PORT}   # 알림 링크·에이전트·BMC(Redfish push) 접속 주소
  tls:
    enabled: auto
    certfile: ${ETC}/certs/aiops.crt
    keyfile: ${ETC}/certs/aiops.key
llm:
  enabled: true
  base_url: \${PAIS_BASE_URL}
  api_key: \${PAIS_API_KEY}
  model: ${MODEL}         # PAIS /v1/models 의 id 와 정확히 일치
  verify_tls: false
syslog:
  enabled: true
  udp_port: 514
  tcp_port: 514
  tls: {enabled: auto, port: 6514, certfile: ${ETC}/certs/aiops.crt, keyfile: ${ETC}/certs/aiops.key}
  advertise_host: ${FQDN}
  advertise_protocol: udp
snmp:
  enabled: true
  port: 162
  communities: ["${SNMP_COMM}"]              # 운영 전 변경(또는 v3_users)
ingest:
  enabled: true                      # Fluent Bit 에이전트(VM 게스트·물리 서버 OS) — API 토큰(scope=ingest)
agents:
  stale_seconds: 300                 # 하트비트·로그 모두 이 시간 없으면 '에이전트 무응답'
backup:
  enabled: true
  time: "02:30"
  keep: 14
  dir: ${DATA}/backup
ha:
  enabled: false                     # 2노드 이중화 시 true + role/peer_url (가이드 참고)
  shared_secret: \${AIOPS_HA_SECRET}
connectors: []                       # vCenter·NSX·Avi·VKS·Redfish 는 화면(운영 설정 > 커넥터)에서 추가
EOF
  ok "config.yaml 생성"
else
  ok "기존 config.yaml 유지"
fi
chown root:"$USR" "$ETC/config.yaml"; chmod 0640 "$ETC/config.yaml"
fi

# ---------------------------------------------------------------- 6. 커널·저널·시간
step "6. 커널 파라미터 · journald · 시간 동기화"
cat > /etc/sysctl.d/90-vcf-aiops.conf <<'EOF'
# VCF AIops — syslog UDP 버스트 흡수(수신 버퍼 상한 32MB), 수신 큐
net.core.rmem_max = 33554432
net.core.rmem_default = 8388608
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
vm.swappiness = 10
EOF
if [[ "$STAGE" == image ]]; then ok "sysctl 파일 배치(부팅 시 적용)"; else
  sysctl -q -p /etc/sysctl.d/90-vcf-aiops.conf 2>/dev/null && ok "sysctl 적용" || warn "sysctl 적용 실패(컨테이너?) — 재부팅 시 적용"
fi
install -d /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/90-vcf-aiops.conf <<'EOF'
[Journal]
SystemMaxUse=2G
MaxRetentionSec=30day
EOF
if [[ -n "$NTP" ]]; then
  install -d /etc/chrony/sources.d
  : > /etc/chrony/sources.d/vcf-aiops.sources
  IFS=',' read -ra _n <<<"$NTP"; for s in "${_n[@]}"; do echo "server ${s} iburst" >> /etc/chrony/sources.d/vcf-aiops.sources; done
  [[ $NO_SYSTEMD -eq 0 ]] && systemctl restart chrony 2>/dev/null || true
  ok "chrony NTP: $NTP"
else
  warn "--ntp 미지정 — 장비들과 같은 NTP 를 쓰도록 /etc/chrony/sources.d 를 설정하세요"
fi

# ---------------------------------------------------------------- 7. systemd 서비스
step "7. systemd 서비스"
cat > /etc/systemd/system/${SVC}.service <<EOF
[Unit]
Description=VCF AIops — real-time log analytics & NOC
Documentation=file://${PREFIX}/README.md
After=network-online.target time-sync.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=notify
NotifyAccess=main
User=${USR}
Group=${USR}
WorkingDirectory=${PREFIX}
Environment=AIOPS_CONFIG=${ETC}/config.yaml
Environment=AIOPS_ENV_FILE=${ETC}/.env
Environment=AIOPS_SECRET_KEY_FILE=${ETC}/secret.key
Environment=AIOPS_WORKDIR=${DATA}
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=${PREFIX}/venv/bin/python -O -X utf8 -m app.serve
# 기동 120초 · 종료 30초(화면 1012 통지 → 큐 소진 → DB 기록) · 워치독 60초(이벤트 루프 정지 또는 5분 이상 '준비 안 됨' → 재시작)
TimeoutStartSec=120
TimeoutStopSec=30
WatchdogSec=60
Restart=always
RestartSec=5
LimitNOFILE=65536
# 514(syslog)·162(SNMP) 바인드에 필요한 권한만
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=${DATA}
ReadOnlyPaths=${ETC}
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
install -m 0755 "$PREFIX/scripts/linux/vcf-aiopsctl" /usr/local/bin/vcf-aiopsctl
[[ -f "$PREFIX/appliance/patch/install-units.sh" ]] && bash "$PREFIX/appliance/patch/install-units.sh" >/dev/null 2>&1 || true
ok "${SVC}.service · vcf-aiops-patch.path(웹 콘솔 패치) · /usr/local/bin/vcf-aiopsctl"

# ---------------------------------------------------------------- 8. 방화벽
step "8. 방화벽(ufw)"
if [[ "$STAGE" == image ]]; then
  warn "이미지 단계: 방화벽은 첫 부팅 구성에서 적용"
elif command -v ufw >/dev/null; then
  for r in "22/tcp" "${PORT}/tcp" "514/udp" "514/tcp" "6514/tcp" "162/udp"; do ufw allow "$r" >/dev/null 2>&1 || true; done
  ok "규칙 추가: 22/tcp(SSH) ${PORT}/tcp(웹·API·에이전트·Redfish) 514/udp·tcp(syslog) 6514/tcp(syslog TLS) 162/udp(SNMP)"
  if [[ $FW -eq 1 ]]; then ufw --force enable >/dev/null && ok "ufw 활성화"; else warn "ufw 는 활성화하지 않았습니다(--enable-firewall). 현재: $(ufw status | head -1)"; fi
fi

# ---------------------------------------------------------------- 9. 기동
if [[ $NO_SYSTEMD -eq 1 ]]; then
  warn "--no-systemd: 서비스 등록·기동 생략"
  exit 0
fi
step "9. 서비스 기동"
systemctl daemon-reload
systemctl restart systemd-journald 2>/dev/null || true
systemctl enable "$SVC" >/dev/null 2>&1
systemctl restart "$SVC"
for i in $(seq 1 60); do
  if curl -fsk --max-time 2 "https://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1 || curl -fs --max-time 2 "http://127.0.0.1:${PORT}/readyz" >/dev/null 2>&1; then
    ok "준비 완료(/readyz 200) — $(systemctl show -p StatusText --value "$SVC")"; break
  fi
  sleep 2
  [[ $i -eq 60 ]] && { journalctl -u "$SVC" -n 40 --no-pager; die "기동 확인 실패 — journalctl -u $SVC"; }
done

echo
echo -e "\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo "  웹 콘솔     https://${FQDN}:${PORT}/        통합 관제  https://${FQDN}:${PORT}/noc"
[[ -f "$DATA/initial-admin.txt" ]] && echo "  초기 관리자 sudo cat $DATA/initial-admin.txt  (최초 로그인 시 비밀번호 변경 → 파일 삭제)"
echo "  상태·로그   vcf-aiopsctl status | logs | health | backup | support"
echo "  설정        sudo -e $ETC/config.yaml ; sudo systemctl restart $SVC"
echo -e "\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
