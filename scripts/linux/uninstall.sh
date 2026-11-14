#!/usr/bin/env bash
# VCF AIops 제거 — sudo bash uninstall.sh [--purge]   (--purge: 데이터·설정·계정까지 삭제 — 되돌릴 수 없음)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "root(sudo)로 실행하세요." >&2; exit 1; }
systemctl disable --now vcf-aiops 2>/dev/null || true
rm -f /etc/systemd/system/vcf-aiops.service /usr/local/bin/vcf-aiopsctl /etc/sysctl.d/90-vcf-aiops.conf /etc/systemd/journald.conf.d/90-vcf-aiops.conf
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/vcf-aiops
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /etc/vcf-aiops /var/lib/vcf-aiops /etc/chrony/sources.d/vcf-aiops.sources
  userdel aiops 2>/dev/null || true; groupdel aiops 2>/dev/null || true
  echo "프로그램·설정·데이터·계정 삭제 완료"
else
  echo "프로그램 삭제 완료 — 설정(/etc/vcf-aiops)과 데이터(/var/lib/vcf-aiops)는 보존했습니다(재설치 시 그대로 사용)."
fi
