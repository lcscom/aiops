#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops — Ubuntu 24.04 / 26.04 LTS 원클릭 배포
#
#  하는 일(순서): 사전 점검 → (필요 시) 배포 패키지 내려받기·무결성 확인 → install.sh 실행 → 사후 점검 → 결과 요약·기록
#
#  사용 예
#    sudo bash deploy.sh                                   # 대화형(FQDN·NTP·PAIS 를 물어봄, Enter = 기본값)
#    sudo bash deploy.sh --env deploy.env --yes            # 파일로 무인 배포(deploy.env.example 참고)
#    sudo bash deploy.sh --fqdn aiops.corp.local --ntp 10.0.0.1,10.0.0.2 --yes
#    sudo bash deploy.sh --check                           # 사전 점검만(설치 안 함)
#    sudo bash deploy.sh --upgrade                         # 프로그램만 새 버전으로(설정·데이터 유지, 자동 백업 후)
#    sudo bash deploy.sh --offline /root/vcf-aiops-offline # 망분리: build-offline 번들로 설치
#    sudo bash deploy.sh --build-offline [--with-agents]   # 인터넷 되는 '같은 버전' Ubuntu 에서 오프라인 번들 만들기
#    sudo bash deploy.sh --uninstall [--purge]             # 제거(--purge: 설정·데이터·계정까지)
#
#  패키지 없이 이 파일만 있으면 GitHub 에서 최신 배포 zip 을 받아 SHA-256 확인 후 설치합니다.
#    curl -fsSLO https://raw.githubusercontent.com/lcscom/aiops/main/scripts/linux/deploy.sh && sudo bash deploy.sh
#
#  기록: /var/log/vcf-aiops-deploy/deploy-<시각>.log (전체 출력) · 결과 요약 summary-<시각>.txt
# =============================================================================================
set -Eeuo pipefail

REPO_RAW="${AIOPS_REPO_RAW:-https://raw.githubusercontent.com/lcscom/aiops/main}"
SVC=vcf-aiops; PREFIX=/opt/vcf-aiops; ETC=/etc/vcf-aiops; DATA=/var/lib/vcf-aiops
MODE=install; YES=0; ENVFILE=""; OFFLINE=""; PURGE=0; WITH_AGENTS=0; ARGS=()
FQDN=""; NTP=""; PAIS_URL=""; PAIS_KEY=""; CERT=""; KEY=""; PORT=""; FW=""; MODEL=""; RETENTION=""
MIN_CPU=2; MIN_MEM_GB=4; MIN_DISK_GB=20; NOSYSD=0

c() { echo -e "\e[$1m$2\e[0m"; }
die()  { c 31 "✖ $*" >&2; exit 1; }
ok()   { echo -e "  $(c 32 ✔) $*"; }
warn() { echo -e "  $(c 33 !) $*"; WARNS=$((WARNS+1)); }
bad()  { echo -e "  $(c 31 ✖) $*"; FAILS=$((FAILS+1)); }
step() { echo; c 36 "▶ $*"; }
WARNS=0; FAILS=0

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENVFILE="$2"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --check) MODE=check; shift ;;
    --upgrade) MODE=upgrade; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --purge) PURGE=1; shift ;;
    --offline) OFFLINE="$2"; shift 2 ;;
    --build-offline) MODE=build-offline; shift ;;
    --with-agents) WITH_AGENTS=1; shift ;;
    --fqdn) FQDN="$2"; shift 2 ;;
    --ntp) NTP="$2"; shift 2 ;;
    --pais-url) PAIS_URL="$2"; shift 2 ;;
    --pais-key) PAIS_KEY="$2"; shift 2 ;;
    --cert) CERT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --enable-firewall) FW=1; shift ;;
    --llm-model) MODEL="$2"; shift 2 ;;
    --retention-days) RETENTION="$2"; shift 2 ;;
    --no-systemd) NOSYSD=1; shift ;;          # 컨테이너 시험용 — 서비스 등록·기동·사후 점검 생략
    -h|--help) usage ;;
    *) die "알 수 없는 옵션: $1 (--help)" ;;
  esac
done
[[ $EUID -eq 0 ]] || die "root(sudo)로 실행하세요: sudo bash $0 $*"

# deploy.env(KEY=VALUE) — 명령줄 값이 우선
if [[ -n "$ENVFILE" ]]; then
  [[ -f "$ENVFILE" ]] || die "--env 파일 없음: $ENVFILE"
  while IFS='=' read -r k v; do
    [[ -z "$k" || "$k" =~ ^[[:space:]]*# ]] && continue
    k="$(echo "$k" | tr -d '[:space:]')"; v="${v%%#*}"; v="$(echo "$v" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
    case "$k" in
      FQDN) FQDN="${FQDN:-$v}" ;; NTP) NTP="${NTP:-$v}" ;; PAIS_URL) PAIS_URL="${PAIS_URL:-$v}" ;; PAIS_KEY) PAIS_KEY="${PAIS_KEY:-$v}" ;;
      CERT) CERT="${CERT:-$v}" ;; KEY) KEY="${KEY:-$v}" ;; PORT) PORT="${PORT:-$v}" ;; ENABLE_FIREWALL) [[ "$v" =~ ^(1|yes|true)$ ]] && FW="${FW:-1}" ;;
      LLM_MODEL) MODEL="${MODEL:-$v}" ;; RETENTION_DAYS) RETENTION="${RETENTION:-$v}" ;; OFFLINE_DIR) OFFLINE="${OFFLINE:-$v}" ;;
      *) echo "  (무시: 알 수 없는 키 $k)" ;;
    esac
  done < "$ENVFILE"
fi

TS="$(date +%Y%m%d-%H%M%S)"; LOGD=/var/log/vcf-aiops-deploy; install -d -m 0700 "$LOGD"
LOG="$LOGD/deploy-$TS.log"; SUM="$LOGD/summary-$TS.txt"
exec > >(tee -a "$LOG") 2>&1
trap 'c 31 "✖ ${BASH_SOURCE[0]}:${LINENO} 에서 실패 — 전체 기록: $LOG"' ERR
c 1 "VCF AIops 배포 [$MODE] — $(date '+%F %T') · 기록 $LOG"

# ---------------------------------------------------------------- 배포 원본 찾기(이 스크립트 옆 → 상위 폴더 → GitHub)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find_src() {
  for d in "$HERE/../.." "$HERE/vcf-aiops" "$HERE"; do
    [[ -f "$d/app/main.py" && -f "$d/scripts/linux/install.sh" ]] && { (cd "$d" && pwd); return 0; }
  done
  return 1
}
fetch_src() {
  step "배포 패키지 내려받기 ($REPO_RAW/dist)"
  command -v curl >/dev/null || { apt-get update -y >/dev/null && apt-get install -y curl >/dev/null; }
  command -v unzip >/dev/null || { apt-get update -y >/dev/null && apt-get install -y unzip >/dev/null; }
  local W; W="$(mktemp -d /var/tmp/vcf-aiops-deploy.XXXXXX)"
  curl -fsSL --retry 3 -o "$W/vcf-aiops-ubuntu.zip" "$REPO_RAW/dist/vcf-aiops-ubuntu.zip" || die "내려받기 실패 — 인터넷이 안 되면 zip 을 직접 복사해 풀고 그 안의 deploy.sh 를 실행하세요"
  curl -fsSL --retry 3 -o "$W/SHA256SUMS" "$REPO_RAW/dist/SHA256SUMS" || die "SHA256SUMS 내려받기 실패"
  (cd "$W" && grep ' vcf-aiops-ubuntu.zip$' SHA256SUMS | sha256sum -c --quiet -) || die "무결성 확인 실패(SHA-256 불일치) — 설치 중단"
  ok "SHA-256 확인 $(grep ' vcf-aiops-ubuntu.zip$' "$W/SHA256SUMS" | cut -c1-16)…"
  unzip -q "$W/vcf-aiops-ubuntu.zip" -d "$W" && SRC="$W/vcf-aiops"
  [[ -f "$SRC/app/main.py" ]] || die "zip 구조가 예상과 다릅니다"
  ok "버전 $(cat "$SRC/VERSION") → $SRC"
}

# ---------------------------------------------------------------- 사전 점검
preflight() {
  step "사전 점검"
  . /etc/os-release
  case "${ID}-${VERSION_ID:-}" in
    ubuntu-24.04|ubuntu-26.04) ok "OS ${PRETTY_NAME} (지원)" ;;
    ubuntu-22.04) warn "OS ${PRETTY_NAME} — 동작은 하지만 24.04/26.04 권장" ;;
    ubuntu-*) warn "OS ${PRETTY_NAME} — 검증 버전(24.04·26.04)이 아님" ;;
    *) bad "Ubuntu 가 아님(${PRETTY_NAME:-?}) — 이 스크립트는 Ubuntu 전용" ;;
  esac
  [[ "$(uname -m)" == x86_64 ]] && ok "아키텍처 x86_64" || warn "아키텍처 $(uname -m) — x86_64 만 검증(govc·일부 wheel 없음)"
  local py; py="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo 없음)"
  case "$py" in 3.12|3.13|3.14) ok "Python $py" ;; 3.10|3.11) warn "Python $py — 동작하지만 3.12 이상 권장" ;; *) bad "Python $py — 3.10 이상 필요" ;; esac
  local cpu mem disk
  cpu=$(nproc); mem=$(awk '/MemTotal/{printf "%d", $2/1024/1024+0.5}' /proc/meminfo)
  install -d "$(dirname "$DATA")"; disk=$(df -BG --output=avail "$(dirname "$DATA")" | tail -1 | tr -dc 0-9)
  [[ $cpu -ge $MIN_CPU ]] && ok "vCPU $cpu" || bad "vCPU $cpu — 최소 $MIN_CPU(권장 4~8)"
  [[ $mem -ge $MIN_MEM_GB ]] && ok "메모리 ${mem}GB" || bad "메모리 ${mem}GB — 최소 ${MIN_MEM_GB}GB(권장 8~16)"
  [[ $disk -ge $MIN_DISK_GB ]] && ok "$(dirname "$DATA") 여유 ${disk}GB" || bad "$(dirname "$DATA") 여유 ${disk}GB — 최소 ${MIN_DISK_GB}GB(로그 보존량에 따라 60GB 이상 권장)"
  local p="${PORT:-8630}" busy=""
  for spec in "tcp:$p" "udp:514" "tcp:514" "tcp:6514" "udp:162"; do
    local proto="${spec%%:*}" port="${spec##*:}" who
    who="$(ss -H -l${proto:0:1}np "sport = :$port" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2 || true)"
    [[ -n "$who" && "$who" != python* ]] && busy+=" $proto/$port($who)"
  done
  [[ -z "$busy" ]] && ok "포트 비어 있음(${p}/tcp·514·6514·162)" || warn "다른 프로그램이 사용 중:$busy — rsyslog 등이 514 를 쓰면 수신이 안 됩니다"
  local f; f="$(hostname -f 2>/dev/null || hostname)"
  if getent hosts "${FQDN:-$f}" >/dev/null; then ok "이름 풀이 ${FQDN:-$f} → $(getent hosts "${FQDN:-$f}" | awk '{print $1}' | head -1)"; else warn "${FQDN:-$f} 이 DNS·/etc/hosts 에서 풀리지 않음 — 장비 syslog·에이전트가 이름으로 접속하려면 A 레코드 필요"; fi
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then ok "시간 동기화됨"; else warn "시간 동기화 안 됨 — --ntp 로 장비들과 같은 NTP 지정 권장"; fi
  if [[ -z "$OFFLINE" && "$MODE" != uninstall ]]; then
    if curl -fsS --max-time 8 -o /dev/null https://pypi.org/simple/fastapi/ 2>/dev/null; then ok "인터넷(pypi.org) 연결"; else bad "pypi.org 에 연결 안 됨 — 프록시(https_proxy) 설정 또는 --offline 번들 사용"; fi
  fi
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then
    ok "기존 설치 감지: $(cat $PREFIX/VERSION 2>/dev/null || echo '?') 실행 중$([[ $MODE == install ]] && echo ' — 업그레이드로 진행합니다')"
    [[ $MODE == install ]] && MODE=upgrade
  fi
  echo "  점검 결과: 실패 $FAILS · 주의 $WARNS"
}

ask() {   # ask 변수 "질문" 기본값
  local __v="$1" q="$2" d="$3" a
  if [[ -n "${!__v}" ]]; then return 0; fi
  if [[ $YES -eq 1 ]]; then printf -v "$__v" '%s' "$d"; return 0; fi
  if [[ "$__v" == PAIS_KEY ]]; then read -rs -p "  $q: " a </dev/tty || a=""; echo; else read -r -p "  $q [${d}]: " a </dev/tty || a=""; fi
  printf -v "$__v" '%s' "${a:-$d}"
  return 0
}

backup_before_upgrade() {
  [[ -d "$DATA" ]] || return 0
  step "업그레이드 전 백업"
  if command -v vcf-aiopsctl >/dev/null && vcf-aiopsctl backup >/dev/null 2>&1; then ok "vcf-aiopsctl backup 완료($DATA/backup)"
  else
    local b="/var/backups/vcf-aiops-$TS.tgz"; install -d -m 0700 /var/backups
    tar -czf "$b" -C / "${ETC#/}" 2>/dev/null && ok "설정 백업 $b(데이터는 서비스의 일일 백업 사용)" || warn "설정 백업 실패"
  fi
}

postcheck() {
  step "사후 점검"
  local p; p="$(sed -n 's/^  port:[[:space:]]*\([0-9]\+\).*/\1/p' $ETC/config.yaml 2>/dev/null | head -1)"; p="${p:-8630}"
  systemctl is-active --quiet "$SVC" && ok "서비스 실행 중 ($(systemctl show -p StatusText --value $SVC))" || bad "서비스가 실행 중이 아님 — journalctl -u $SVC"
  curl -fsk --max-time 5 "https://127.0.0.1:$p/readyz" >/dev/null 2>&1 && ok "/readyz 200 (https://127.0.0.1:$p)" || bad "/readyz 응답 없음"
  for spec in "tcp:$p" "udp:514" "tcp:514" "tcp:6514" "udp:162"; do
    local proto="${spec%%:*}" port="${spec##*:}"
    ss -H -l${proto:0:1}n "sport = :$port" 2>/dev/null | grep -q . && ok "수신 $proto/$port" || warn "수신 안 함 $proto/$port(설정에서 끈 경우 정상)"
  done
  [[ -f "$PREFIX/VERSION" ]] && ok "설치 버전 $(cat $PREFIX/VERSION)"
  command -v ufw >/dev/null && echo "  방화벽: $(ufw status | head -1)"
}

summary() {
  local f p ip; f="$(sed -n 's#^  public_url: https://\([^:/]*\).*#\1#p' $ETC/config.yaml 2>/dev/null | head -1)"; p="$(sed -n 's/^  port:[[:space:]]*\([0-9]\+\).*/\1/p' $ETC/config.yaml 2>/dev/null | head -1)"
  ip="$(hostname -I | awk '{print $1}')"
  { echo "VCF AIops 배포 결과 — $(date '+%F %T')"
    echo "모드: $MODE · 버전: $(cat $PREFIX/VERSION 2>/dev/null) · 점검 실패 $FAILS · 주의 $WARNS"
    echo "웹 콘솔: https://${f:-$ip}:${p:-8630}/   (IP: https://$ip:${p:-8630}/)"
    [[ -f "$DATA/initial-admin.txt" ]] && echo "초기 관리자: sudo cat $DATA/initial-admin.txt  (첫 로그인 때 비밀번호 변경 → 파일 삭제)"
    echo "장비 syslog 대상: ${f:-$ip} UDP/TCP 514 · TLS 6514 · SNMP 트랩 UDP 162"
    echo "설정: $ETC/config.yaml · 비밀: $ETC/.env · 암호화 키(백업 필수): $ETC/secret.key"
    echo "운영: vcf-aiopsctl status | logs | health | backup | patch <번들.tgz> | rollback"
    echo "다음 할 일: 웹 콘솔 › 수집·연동에서 vCenter·NSX·Avi·VKS 커넥터 추가 → 장비 syslog 를 이 서버로"
    echo "전체 기록: $LOG"
  } | tee "$SUM"
}

# ---------------------------------------------------------------- 실행
case "$MODE" in
  uninstall)
    step "제거"
    [[ $YES -eq 1 ]] || { read -r -p "  $([[ $PURGE -eq 1 ]] && echo '설정·데이터·계정까지 모두 삭제(되돌릴 수 없음)' || echo '프로그램 삭제(설정·데이터 보존)') — 계속할까요? [y/N] " a </dev/tty; [[ "$a" =~ ^[yY] ]] || exit 0; }
    SRC="$(find_src || echo "$PREFIX")"
    bash "$SRC/scripts/linux/uninstall.sh" $([[ $PURGE -eq 1 ]] && echo --purge)
    exit 0 ;;
  build-offline)
    SRC="$(find_src)" || fetch_src
    . /etc/os-release
    step "오프라인 번들 만들기 — ${PRETTY_NAME}용(대상 서버와 같은 Ubuntu 버전에서 실행해야 함)"
    apt-get update -y >/dev/null; apt-get install -y python3-venv python3-pip curl >/dev/null
    OUT="/var/tmp/vcf-aiops-offline-${VERSION_ID}"
    bash "$SRC/scripts/linux/build-offline.sh" --out "$OUT" $([[ $WITH_AGENTS -eq 1 ]] && echo --with-agents)
    ok "결과: ${OUT}.tar.gz → 대상 서버로 복사 후: tar xzf $(basename "$OUT").tar.gz && sudo bash $(basename "$OUT")/vcf-aiops/scripts/linux/deploy.sh --offline $(basename "$OUT")"
    exit 0 ;;
esac

preflight
[[ $MODE == check ]] && { [[ $FAILS -eq 0 ]] && c 32 "사전 점검 통과" || c 31 "사전 점검 실패 $FAILS건"; exit $(( FAILS > 0 )); }
if [[ $FAILS -gt 0 ]]; then
  [[ $YES -eq 1 ]] && die "사전 점검 실패 $FAILS건 — 위 ✖ 항목을 해결하세요(무인 모드라 중단)"
  read -r -p "  사전 점검 실패 $FAILS건 — 그래도 계속할까요? [y/N] " a </dev/tty; [[ "$a" =~ ^[yY] ]] || exit 1
fi
SRC="$(find_src)" || fetch_src
ok "배포 원본 $SRC (버전 $(cat "$SRC/VERSION"))"
[[ -n "$OFFLINE" ]] && OFFLINE="$(cd "$OFFLINE" && pwd)" && ARGS+=(--offline "$OFFLINE")
[[ $NOSYSD -eq 1 ]] && ARGS+=(--no-systemd)

if [[ $MODE == upgrade ]]; then
  backup_before_upgrade
  ARGS+=(--upgrade)
else
  step "설정 입력 (Enter = 기본값)"
  ask FQDN "이 서버 FQDN" "$(hostname -f 2>/dev/null || hostname)"
  ask NTP "NTP 서버(쉼표 구분, 없으면 비움)" ""
  ask PAIS_URL "Private AI(PAIS·OpenAI 호환) 주소(없으면 비움 — 규칙 탐지로 동작)" ""
  [[ -n "$PAIS_URL" ]] && ask PAIS_KEY "PAIS API 키" ""
  ask PORT "웹 포트" "8630"
  ask FW "ufw 방화벽 켜기(1=켬, 0=규칙만 추가)" "0"
  ARGS+=(--fqdn "$FQDN" --port "$PORT")
  [[ -n "$NTP" ]] && ARGS+=(--ntp "$NTP")
  [[ -n "$PAIS_URL" ]] && ARGS+=(--pais-url "$PAIS_URL")
  [[ -n "$PAIS_KEY" ]] && ARGS+=(--pais-key "$PAIS_KEY")
  [[ -n "$CERT" ]] && ARGS+=(--cert "$CERT" --key "$KEY")
  [[ "$FW" == 1 ]] && ARGS+=(--enable-firewall)
  [[ -n "$MODEL" ]] && ARGS+=(--llm-model "$MODEL")
  [[ -n "$RETENTION" ]] && ARGS+=(--retention-days "$RETENTION")
  echo "  → FQDN $FQDN · 포트 $PORT · NTP ${NTP:-없음} · PAIS ${PAIS_URL:-없음} · 인증서 ${CERT:-자체 서명} · 방화벽 $([[ $FW == 1 ]] && echo 켬 || echo '규칙만')"
  if [[ $YES -eq 0 ]]; then read -r -p "  이대로 설치할까요? [Y/n] " a </dev/tty; [[ -z "$a" || "$a" =~ ^[yY] ]] || exit 1; fi
fi

step "설치 ($([[ $MODE == upgrade ]] && echo 업그레이드 || echo 신규))"
# 비밀 값(PAIS 키)이 기록 파일에 남지 않도록 표시용 인자는 가림
SHOW="${ARGS[*]}"; [[ -n "$PAIS_KEY" ]] && SHOW="${SHOW//$PAIS_KEY/****}"
echo "  bash $SRC/scripts/linux/install.sh $SHOW"
bash "$SRC/scripts/linux/install.sh" "${ARGS[@]}"
[[ $NOSYSD -eq 1 ]] && { ok "--no-systemd: 서비스 기동·사후 점검 생략"; summary; exit 0; }
postcheck
summary
[[ $FAILS -eq 0 ]] && c 32 "배포 완료" || { c 31 "배포는 끝났지만 사후 점검 실패 $FAILS건 — 위 ✖ 항목과 $LOG 확인"; exit 1; }
