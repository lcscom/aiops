#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops 에이전트 — VM 게스트 · 물리 서버(Linux) OS 로그 실시간 전송
#
#  모드
#   fluentbit (기본) : Fluent Bit → HTTPS POST /api/ingest (journald + 지정 로그 파일, 60초 하트비트,
#                      디스크 버퍼 1GB — 네트워크·서버 장애 시 보관 후 재전송)
#   rsyslog          : 패키지 추가 설치 없이 OS 기본 rsyslog → syslog TCP(514) 또는 TLS(6514, rsyslog-gnutls 필요)
#                      RFC5424 구조화 데이터 [aiops@32473 kind=… role=…] + 60초 하트비트(systemd 타이머 · logger)
#
#  사용 예 (AIOps 화면 › VM·서버 에이전트 › 등록 이 명령을 생성해 줍니다)
#   sudo bash install-agent.sh --server https://aiops.vcf.lab:8630 --token aiops_xxx --kind vm --role DB
#   sudo bash install-agent.sh --server https://aiops.vcf.lab:8630 --token aiops_xxx --ca /root/corp-ca.pem \
#        --file '/var/log/app/*.log' --file '/opt/was/logs/SystemOut.log'
#   sudo bash install-agent.sh --mode rsyslog --server https://aiops.vcf.lab:8630 --syslog-proto tcp
#   sudo bash install-agent.sh --server … --token … --package /tmp/fluent-bit_5.1.3_amd64.deb     # 망분리(오프라인)
#
#  지원: Ubuntu 20.04+/Debian 11+ (apt) · RHEL/Rocky/Alma/Oracle 8·9 (dnf) · SLES 15 (zypper, --package 권장)
#        Photon OS 3·4·5 (tdnf) — Photon 저장소에 Fluent Bit 패키지가 없어 기본은 rsyslog 모드로 자동 전환,
#        Fluent Bit 을 쓰려면 RHEL 9 용 rpm 을 받아 --package 로 지정(tdnf 가 의존성 해결)
# =============================================================================================
set -euo pipefail

SERVER=""; TOKEN=""; KIND=""; ROLE=""; MODE="fluentbit"; CA=""; INSECURE=0; PACKAGE=""
SYSLOG_PROTO="tcp"; SYSLOG_PORT=""; FILES=(); HOSTNAME_OVERRIDE=""; VMNAME=""; BUFFER="1G"

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
die()   { echo -e "\e[31m✖ $*\e[0m" >&2; exit 1; }
ok()    { echo -e "\e[32m✔\e[0m $*"; }
step()  { echo -e "\n\e[36m▶ $*\e[0m"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --kind) KIND="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --ca) CA="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --package) PACKAGE="$2"; shift 2 ;;
    --file) FILES+=("$2"); shift 2 ;;
    --syslog-proto) SYSLOG_PROTO="$2"; shift 2 ;;
    --syslog-port) SYSLOG_PORT="$2"; shift 2 ;;
    --hostname) HOSTNAME_OVERRIDE="$2"; shift 2 ;;
    --vm-name) VMNAME="$2"; shift 2 ;;
    --buffer) BUFFER="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "알 수 없는 옵션: $1 (--help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "root(sudo)로 실행하세요."
[[ -n "$SERVER" ]] || die "--server https://<AIOps 주소>:8630 가 필요합니다."
[[ "$MODE" == "fluentbit" || "$MODE" == "rsyslog" ]] || die "--mode 는 fluentbit | rsyslog"
[[ "$MODE" == "rsyslog" || -n "$TOKEN" ]] || die "fluentbit 모드는 --token(AIOps API 토큰, scope=ingest)이 필요합니다."
[[ -z "$ROLE" || "$ROLE" =~ ^[A-Za-z0-9_-]{1,30}$ ]] || die "--role 은 영문·숫자·-_ 30자 이내"
[[ -z "$CA" || -r "$CA" ]] || die "--ca 파일을 읽을 수 없습니다: $CA"

# ---------------------------------------------------------------- 환경 판별
. /etc/os-release
OS_ID="${ID:-linux}"; OS_LIKE="${ID_LIKE:-}"
if [[ -z "$KIND" ]]; then        # 가상화 여부로 자동 판별(VMware → vm, 물리 → baremetal)
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  if [[ -z "$virt" || "$virt" == "none" ]]; then KIND="baremetal"; else KIND="vm"; fi
fi
[[ "$KIND" == "vm" || "$KIND" == "baremetal" ]] || die "--kind 는 vm | baremetal"
HOST="${HOSTNAME_OVERRIDE:-$(hostname -f 2>/dev/null || hostname 2>/dev/null || hostnamectl --static 2>/dev/null || cat /proc/sys/kernel/hostname)}"
proto="${SERVER%%://*}"; rest="${SERVER#*://}"; hostport="${rest%%/*}"
SRV_HOST="${hostport%%:*}"
if [[ "$hostport" == *:* ]]; then SRV_PORT="${hostport##*:}"; elif [[ "$proto" == "https" ]]; then SRV_PORT=443; else SRV_PORT=80; fi
[[ -n "$SRV_HOST" ]] || die "--server 형식 오류: $SERVER"

pkg_family() {
  case " $OS_ID $OS_LIKE " in
    *" ubuntu "*|*" debian "*) echo apt ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) echo dnf ;;
    *" sles "*|*" suse "*|*" opensuse"*) echo zypper ;;
    *" photon "*) echo tdnf ;;
    *) echo unknown ;;
  esac
}
FAM="$(pkg_family)"
if [[ "$FAM" == "tdnf" && "$MODE" == "fluentbit" && -z "$PACKAGE" && ! -x /opt/fluent-bit/bin/fluent-bit ]]; then
  echo "  ! Photon OS 저장소에는 Fluent Bit 패키지가 없습니다 → rsyslog 모드로 전환(TCP ${SYSLOG_PORT:-514}, 토큰 불필요)."
  echo "    Fluent Bit 을 쓰려면 RHEL 9 용 fluent-bit rpm 을 받아 --package 로 지정하세요."
  MODE="rsyslog"
fi
echo "대상 서버 ${SRV_HOST}:${SRV_PORT} (${proto}) · 이 호스트 ${HOST} · 종류 ${KIND}${ROLE:+ · 역할 $ROLE} · 모드 ${MODE} · OS ${PRETTY_NAME:-$OS_ID}"

curl_tls() {   # 서버 접속 시험용 curl TLS 옵션
  if [[ -n "$CA" ]]; then echo "--cacert $CA"; elif [[ $INSECURE -eq 1 ]]; then echo "-k"; fi
}

# =============================================================== fluentbit 모드
install_fluentbit() {
  if [[ -x /opt/fluent-bit/bin/fluent-bit ]]; then ok "Fluent Bit 이미 설치됨: $(/opt/fluent-bit/bin/fluent-bit --version 2>/dev/null | head -1)"; return; fi
  step "Fluent Bit 설치"
  if [[ -n "$PACKAGE" ]]; then
    [[ -r "$PACKAGE" ]] || die "--package 파일 없음: $PACKAGE"
    case "$PACKAGE" in
      *.deb) apt-get install -y "$PACKAGE" ;;
      *.rpm) if command -v tdnf >/dev/null; then tdnf install -y "$PACKAGE";
             elif command -v dnf >/dev/null; then dnf install -y "$PACKAGE"; elif command -v zypper >/dev/null; then zypper --non-interactive install --allow-unsigned-rpm "$PACKAGE"; else rpm -Uvh "$PACKAGE"; fi ;;
      *) die "--package 는 .deb 또는 .rpm" ;;
    esac
  elif [[ "$FAM" == "apt" ]]; then
    # 공식 저장소(docs.fluentbit.io › Installation › Ubuntu/Debian)
    apt-get update -y >/dev/null
    apt-get install -y curl gnupg ca-certificates >/dev/null
    curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor > /usr/share/keyrings/fluentbit-keyring.gpg
    codename="${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}"
    echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/${OS_ID}/${codename} ${codename} main" \
      > /etc/apt/sources.list.d/fluent-bit.list
    apt-get update -y >/dev/null
    apt-get install -y fluent-bit
  elif [[ "$FAM" == "dnf" ]]; then
    # 공식 설치 스크립트가 배포판별 저장소를 구성
    curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
  else
    die "자동 설치 미지원 배포판($OS_ID) — Fluent Bit 패키지를 받아 --package 로 지정하세요."
  fi
  [[ -x /opt/fluent-bit/bin/fluent-bit ]] || die "Fluent Bit 설치 실패"
  ok "$(/opt/fluent-bit/bin/fluent-bit --version | head -1)"
}

write_fluentbit_conf() {
  step "구성 파일 작성: /etc/fluent-bit/fluent-bit.conf"
  install -d -m 0750 /etc/fluent-bit /var/lib/fluent-bit/storage
  local tls_lines=""
  if [[ "$proto" == "https" ]]; then
    tls_lines="    tls               On"$'\n'
    if [[ -n "$CA" ]]; then
      install -m 0644 "$CA" /etc/fluent-bit/aiops-ca.pem
      tls_lines+="    tls.verify        On"$'\n'"    tls.verify_hostname On"$'\n'"    tls.ca_file       /etc/fluent-bit/aiops-ca.pem"$'\n'
    elif [[ $INSECURE -eq 1 ]]; then
      tls_lines+="    tls.verify        Off"$'\n'
    else
      tls_lines+="    tls.verify        On"$'\n'
    fi
    tls_lines+="    tls.vhost         ${SRV_HOST}"$'\n'
  fi
  local files_block="" i=0
  for f in "${FILES[@]}"; do
    i=$((i+1))
    files_block+="
[INPUT]
    Name              tail
    Tag               os.file.${i}
    Path              ${f}
    Path_Key          file
    DB                /var/lib/fluent-bit/tail-${i}.db
    Skip_Long_Lines   On
    Refresh_Interval  5
    Rotate_Wait       10
    storage.type      filesystem
"
  done
  umask 077
  cat > /etc/fluent-bit/fluent-bit.conf <<EOF
# VCF AIops 에이전트 — install-agent.sh 가 생성 ($(date '+%F %T'))
# 이 서버: ${HOST} (${KIND}${ROLE:+, ${ROLE}})  →  ${SERVER}/api/ingest
[SERVICE]
    Flush                     1
    Log_Level                 warn
    storage.path              /var/lib/fluent-bit/storage
    storage.sync              normal
    storage.backlog.mem_limit 16M
    scheduler.cap             60

# OS 저널(커널·systemd 서비스·sshd·cron 등 모든 syslog 포함) — 설치 이후 신규분부터
[INPUT]
    Name              systemd
    Tag               os.journal
    DB                /var/lib/fluent-bit/journal.db
    Read_From_Tail    On
    storage.type      filesystem
${files_block}
# 하트비트 60초 — 로그가 조용해도 에이전트 생존을 AIOps 가 판정(5분 무응답 시 경보)
[INPUT]
    Name              dummy
    Tag               aiops.hb
    Dummy             {"aiops_heartbeat":1}
    Interval_Sec      60

# debug(PRIORITY=7) 제외
[FILTER]
    Name              grep
    Match             os.journal
    Exclude           PRIORITY ^7\$

[FILTER]
    Name              record_modifier
    Match             *
    Record            aiops_host ${HOST}
    Record            aiops_kind ${KIND}
    Record            aiops_os linux
    Record            aiops_distro ${OS_ID}
    Record            aiops_agent fluent-bit
${ROLE:+    Record            aiops_role ${ROLE}
}${VMNAME:+    Record            aiops_vm ${VMNAME}
}
[OUTPUT]
    Name              http
    Match             *
    Host              ${SRV_HOST}
    Port              ${SRV_PORT}
    URI               /api/ingest
    Format            json
    json_date_key     date
    json_date_format  double
    Header            X-AIOps-Token ${TOKEN}
    compress          gzip
${tls_lines}    Retry_Limit       no_limits
    storage.total_limit_size ${BUFFER}
EOF
  chmod 600 /etc/fluent-bit/fluent-bit.conf
  # 패키지 버전에 따라 기본 구성 파일(.conf/.yaml)이 달라도 이 파일로 기동되도록 drop-in 고정
  install -d /etc/systemd/system/fluent-bit.service.d
  cat > /etc/systemd/system/fluent-bit.service.d/10-vcf-aiops.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/fluent-bit/bin/fluent-bit -c /etc/fluent-bit/fluent-bit.conf
Restart=always
RestartSec=5
EOF
  /opt/fluent-bit/bin/fluent-bit -c /etc/fluent-bit/fluent-bit.conf --dry-run >/dev/null 2>&1 \
    && ok "구성 문법 검사 통과" || echo "  ! --dry-run 미지원 버전 — 기동 로그로 확인합니다"
}

probe_server() {
  step "AIOps 서버 접속·토큰 시험"
  local code
  code=$(curl -sS --noproxy "$SRV_HOST" -o /tmp/aiops-probe.$$ -w "%{http_code}" $(curl_tls) --max-time 10 -X POST "${SERVER}/api/ingest" \
           -H "X-AIOps-Token: ${TOKEN}" -H 'Content-Type: application/json' \
           -d "[{\"aiops_heartbeat\":1,\"aiops_host\":\"${HOST}\",\"aiops_kind\":\"${KIND}\",\"aiops_os\":\"linux\",\"aiops_agent\":\"fluent-bit\"${ROLE:+,\"aiops_role\":\"${ROLE}\"}}]" || true)
  case "$code" in
    200) ok "접속·토큰 정상 ($(cat /tmp/aiops-probe.$$))" ;;
    401) die "토큰 거부(401) — AIOps 화면에서 ingest 토큰을 다시 발급하세요." ;;
    000) die "서버 접속 불가 — ${SRV_HOST}:${SRV_PORT} 방화벽·DNS·인증서(--ca 또는 --insecure)를 확인하세요." ;;
    *) die "예상치 못한 응답 HTTP ${code}: $(head -c 300 /tmp/aiops-probe.$$ 2>/dev/null)" ;;
  esac
  rm -f /tmp/aiops-probe.$$
}

# =============================================================== rsyslog 모드
install_rsyslog_mode() {
  command -v rsyslogd >/dev/null || {
    step "rsyslog 설치"
    case "$FAM" in apt) apt-get install -y rsyslog ;; dnf) dnf install -y rsyslog ;; zypper) zypper --non-interactive install rsyslog ;;
                   tdnf) tdnf install -y rsyslog ;; *) die "rsyslog 없음" ;; esac
  }
  local port="$SYSLOG_PORT" drv=""
  if [[ "$SYSLOG_PROTO" == "tls" ]]; then
    port="${port:-6514}"
    [[ -n "$CA" ]] || die "TLS 모드는 --ca <AIOps 서버 인증서를 발급한 CA PEM> 이 필요합니다."
    case "$FAM" in apt) dpkg -s rsyslog-gnutls >/dev/null 2>&1 || apt-get install -y rsyslog-gnutls ;;
                   dnf) rpm -q rsyslog-gnutls >/dev/null 2>&1 || dnf install -y rsyslog-gnutls ;;
                   tdnf) : ;;   # Photon: gtls 드라이버가 rsyslog 본 패키지에 포함 ;;
    esac
    install -m 0644 "$CA" /etc/rsyslog.d/aiops-ca.pem
    drv=' StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="'"${SRV_HOST}"'"'
  else
    port="${port:-514}"
  fi
  step "rsyslog 전달 구성: /etc/rsyslog.d/90-vcf-aiops.conf (${SYSLOG_PROTO}/${port})"
  {
    echo "# VCF AIops — install-agent.sh 생성 ($(date '+%F %T')) · ${HOST} (${KIND}${ROLE:+, ${ROLE}})"
    [[ "$SYSLOG_PROTO" == "tls" ]] && echo 'global(DefaultNetstreamDriverCAFile="/etc/rsyslog.d/aiops-ca.pem")'
    [[ -n "$HOSTNAME_OVERRIDE" ]] && echo "global(localHostname=\"${HOSTNAME_OVERRIDE}\")"
    echo "template(name=\"AIOpsRFC5424\" type=\"string\" string=\"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% [aiops@32473 kind=\\\"${KIND}\\\"${ROLE:+ role=\\\"${ROLE}\\\"} os=\\\"linux\\\" distro=\\\"${OS_ID}\\\" agent=\\\"rsyslog\\\"] %msg%\\n\")"
    echo "*.info action(type=\"omfwd\" target=\"${SRV_HOST}\" port=\"${port}\" protocol=\"tcp\" template=\"AIOpsRFC5424\" TCP_Framing=\"octet-counted\"${drv}"
    echo "       queue.type=\"LinkedList\" queue.filename=\"vcf_aiops_fwd\" queue.maxDiskSpace=\"${BUFFER,,}\" queue.saveOnShutdown=\"on\" action.resumeRetryCount=\"-1\")"
  } > /etc/rsyslog.d/90-vcf-aiops.conf
  rsyslogd -N1 >/dev/null 2>&1 && ok "rsyslog 구성 검사 통과" || die "rsyslog 구성 오류 — rsyslogd -N1 로 확인"
  # 하트비트: 60초마다 logger 1줄(AIOps 가 aiops-heartbeat 태그를 에이전트 생존 신호로 처리, 저장하지 않음)
  cat > /etc/systemd/system/aiops-heartbeat.service <<'EOF'
[Unit]
Description=VCF AIops agent heartbeat (rsyslog mode)
[Service]
Type=oneshot
ExecStart=/usr/bin/logger -t aiops-heartbeat -p syslog.info alive
EOF
  cat > /etc/systemd/system/aiops-heartbeat.timer <<'EOF'
[Unit]
Description=VCF AIops agent heartbeat every 60s
[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=5
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now aiops-heartbeat.timer >/dev/null
  systemctl enable rsyslog >/dev/null 2>&1 || true     # Photon 등 기본 비활성 배포판
  systemctl restart rsyslog
  ok "rsyslog 재시작 · 하트비트 타이머 활성"
}

# =============================================================== 실행
if [[ "$MODE" == "fluentbit" ]]; then
  probe_server
  install_fluentbit
  write_fluentbit_conf
  systemctl daemon-reload
  systemctl enable fluent-bit >/dev/null 2>&1 || true
  systemctl restart fluent-bit
  sleep 3
  systemctl is-active --quiet fluent-bit || { journalctl -u fluent-bit -n 30 --no-pager; die "fluent-bit 기동 실패"; }
  ok "fluent-bit 동작 중 — 상태: systemctl status fluent-bit · 로그: journalctl -u fluent-bit -f"
else
  install_rsyslog_mode
fi
logger -t vcf-aiops-agent -p user.notice "VCF AIops agent installed (mode=${MODE}, kind=${KIND}${ROLE:+, role=${ROLE}})" || true
echo
ok "완료 — AIOps 화면 › VM·서버 에이전트 에서 '${HOST}' 가 1분 내 '정상'으로 표시되는지 확인하세요."
