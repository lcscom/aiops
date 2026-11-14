#!/usr/bin/env bash
# 웹 콘솔 패치 업로드용 root 유닛: 서비스(aiops 계정)가 요청 파일을 두면 root 가 서명·해시를 다시 확인하고 적용/롤백.
#   /var/lib/vcf-aiops/patches/request.json 생성 → vcf-aiops-patch.path → vcf-aiops-patch.service(oneshot, root)
#   install-units.sh [--unit-dir DIR] [--data DIR] [--group NAME]   (인자는 apply.sh·시험용 — 기본값이 운영 경로)
set -euo pipefail
DATA=/var/lib/vcf-aiops; UNITD=/etc/systemd/system; GRP=aiops
while [[ $# -gt 0 ]]; do case "$1" in
  --unit-dir) UNITD="$2"; shift 2 ;; --data) DATA="$2"; shift 2 ;; --group) GRP="$2"; shift 2 ;;
  *) echo "알 수 없는 옵션 $1" >&2; exit 2 ;; esac; done
PD=$DATA/patches
install -d -m 0770 -o root -g "$GRP" "$PD" "$PD/incoming"
[[ -d "$PD/backup" && ! -L "$PD/backup" ]] && { chown root:root "$PD/backup"; chmod 0700 "$PD/backup"; }   # (2.30.0) 백업은 root 전용
cat > "$UNITD/vcf-aiops-patch.path" <<U
[Unit]
Description=VCF AIops patch request watcher (web console upload)
[Path]
PathExists=$PD/request.json
Unit=vcf-aiops-patch.service
[Install]
WantedBy=multi-user.target
U
cat > "$UNITD/vcf-aiops-patch.service" <<'U'
[Unit]
Description=VCF AIops patch apply/rollback (requested from web console)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vcf-aiopsctl patch-request
TimeoutStartSec=1800
U
systemctl daemon-reload 2>/dev/null || true                 # 이미지 빌드(chroot)에서는 실패해도 됨
systemctl enable vcf-aiops-patch.path >/dev/null 2>&1 || true
systemctl start vcf-aiops-patch.path >/dev/null 2>&1 || true
