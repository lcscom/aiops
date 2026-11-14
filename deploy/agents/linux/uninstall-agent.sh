#!/usr/bin/env bash
# VCF AIops 에이전트 제거 — sudo bash uninstall-agent.sh [--purge]   (--purge: Fluent Bit 패키지까지 삭제)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "root(sudo)로 실행하세요." >&2; exit 1; }
PURGE=0; [[ "${1:-}" == "--purge" ]] && PURGE=1
if systemctl list-unit-files fluent-bit.service >/dev/null 2>&1; then
  systemctl disable --now fluent-bit 2>/dev/null || true
  rm -f /etc/systemd/system/fluent-bit.service.d/10-vcf-aiops.conf /etc/fluent-bit/aiops-ca.pem
  [[ -f /etc/fluent-bit/fluent-bit.conf ]] && grep -q "VCF AIops" /etc/fluent-bit/fluent-bit.conf && mv /etc/fluent-bit/fluent-bit.conf /etc/fluent-bit/fluent-bit.conf.aiops-removed
  rm -rf /var/lib/fluent-bit/storage /var/lib/fluent-bit/*.db
fi
if [[ -f /etc/rsyslog.d/90-vcf-aiops.conf ]]; then
  rm -f /etc/rsyslog.d/90-vcf-aiops.conf /etc/rsyslog.d/aiops-ca.pem
  systemctl restart rsyslog || true
fi
systemctl disable --now aiops-heartbeat.timer 2>/dev/null || true
rm -f /etc/systemd/system/aiops-heartbeat.service /etc/systemd/system/aiops-heartbeat.timer
systemctl daemon-reload
if [[ $PURGE -eq 1 ]]; then
  if command -v apt-get >/dev/null; then apt-get purge -y fluent-bit || true; rm -f /etc/apt/sources.list.d/fluent-bit.list /usr/share/keyrings/fluentbit-keyring.gpg
  elif command -v dnf >/dev/null; then dnf remove -y fluent-bit || true; fi
fi
echo "제거 완료 — AIOps 화면 › VM·서버 에이전트에서 이 서버를 '삭제'(차단 포함)하면 목록에서 빠집니다."
