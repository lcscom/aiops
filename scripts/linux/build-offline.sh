#!/usr/bin/env bash
# 망분리(오프라인) 설치 번들 — 인터넷이 되는 Ubuntu(대상과 같은 버전·아키텍처)에서 실행
#   bash scripts/linux/build-offline.sh [--out /tmp/vcf-aiops-offline] [--with-agents]
#   결과: vcf-aiops-offline.tar.gz  →  대상 서버에서 압축 해제 후
#         sudo bash vcf-aiops/scripts/linux/install.sh --offline <해제 폴더>
#   --with-agents : Fluent Bit 에이전트 패키지(이 Ubuntu 코드네임용 .deb + Windows .zip)도 포함
set -euo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"; OUT="/tmp/vcf-aiops-offline"; AGENTS=0; FBV="${FLUENTBIT_VERSION:-5.1.3}"
while [[ $# -gt 0 ]]; do case "$1" in --out) OUT="$2"; shift 2 ;; --with-agents) AGENTS=1; shift ;; *) echo "옵션 오류 $1"; exit 1 ;; esac; done
. /etc/os-release
PYV="$(python3 -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
rm -rf "$OUT"; mkdir -p "$OUT/wheelhouse" "$OUT/debs" "$OUT/agents"
echo "▶ 파이썬 패키지(wheel) — Python ${PYV}, $(uname -m)"
python3 -m pip download -q -r "$SRC/requirements.txt" -d "$OUT/wheelhouse" --only-binary=:all: \
  || python3 -m pip download -q -r "$SRC/requirements.txt" -d "$OUT/wheelhouse"
python3 -m pip download -q pip setuptools wheel -d "$OUT/wheelhouse"
echo "▶ OS 패키지(.deb) — ${PRETTY_NAME}"
( cd "$OUT/debs" && apt-get download "python${PYV}-venv" python3-venv python3-pip-whl python3-setuptools-whl sqlite3 chrony 2>/dev/null || true )
if [[ $AGENTS -eq 1 ]]; then
  echo "▶ Fluent Bit ${FBV} 에이전트 패키지"
  # Ubuntu: 공식 저장소(docs.fluentbit.io) 구성 후 이 배포판 코드네임용 .deb 를 받는다 — 다른 코드네임은 그 버전 Ubuntu 에서 실행
  curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor | sudo tee /usr/share/keyrings/fluentbit-keyring.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/${VERSION_CODENAME} ${VERSION_CODENAME} main" \
    | sudo tee /etc/apt/sources.list.d/fluent-bit.list >/dev/null
  sudo apt-get update -qq && ( cd "$OUT/agents" && apt-get download fluent-bit ) || echo "  ! Fluent Bit .deb 다운로드 실패"
  curl -fsSL -o "$OUT/agents/fluent-bit-${FBV}-win64.zip" "https://packages.fluentbit.io/windows/fluent-bit-${FBV}-win64.zip" || echo "  ! windows zip 다운로드 실패"
  echo "  (RHEL 계열 .rpm 은 https://packages.fluentbit.io/ 의 배포판별 경로에서 같은 버전을 받아 agents/ 에 넣으세요)"
fi
echo "▶ govc(vCenter 수집 전용 계정 자동 생성)"
curl -fsSL -o "$OUT/govc_Linux_x86_64.tar.gz" https://github.com/vmware/govmomi/releases/download/v0.46.3/govc_Linux_x86_64.tar.gz || echo "  ! govc 다운로드 실패"
echo "▶ 프로그램"
tar --exclude='__pycache__' --exclude='.git' -C "$(dirname "$SRC")" -cf - "$(basename "$SRC")" | tar -C "$OUT" -xf -
tar czf "${OUT}.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
echo "완료: ${OUT}.tar.gz ($(du -h "${OUT}.tar.gz" | cut -f1)) — wheel $(ls "$OUT/wheelhouse" | wc -l)개, deb $(ls "$OUT/debs" | wc -l)개"
echo "대상: tar xzf $(basename "${OUT}").tar.gz && sudo bash $(basename "$OUT")/$(basename "$SRC")/scripts/linux/install.sh --offline $(basename "$OUT")"
