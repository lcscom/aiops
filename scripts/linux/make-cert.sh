#!/usr/bin/env bash
# VCF AIops 서버 인증서 — 자체 서명(기본) 또는 사내 CA 제출용 CSR 생성
#   bash make-cert.sh --fqdn aiops.vcf.lab --out /etc/vcf-aiops/certs              # 자체 서명(825일, RSA 3072)
#   bash make-cert.sh --fqdn aiops.vcf.lab --out /root/csr --csr                   # 키 + CSR → 사내 CA 발급 후 install.sh --cert/--key
#   추가 SAN: --san aiops-vip.vcf.lab --san 10.10.0.50
set -euo pipefail
FQDN="$(hostname -f 2>/dev/null || hostname)"; OUT="."; CSR=0; SANS=()
while [[ $# -gt 0 ]]; do case "$1" in
  --fqdn) FQDN="$2"; shift 2 ;; --out) OUT="$2"; shift 2 ;; --csr) CSR=1; shift ;; --san) SANS+=("$2"); shift 2 ;;
  *) echo "알 수 없는 옵션 $1" >&2; exit 1 ;; esac; done
SHORT="${FQDN%%.*}"; IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
san="DNS:${FQDN},DNS:${SHORT}"; [[ -n "$IP" ]] && san+=",IP:${IP}"
for s in "${SANS[@]}"; do if [[ "$s" =~ ^[0-9.]+$ || "$s" == *:* ]]; then san+=",IP:${s}"; else san+=",DNS:${s}"; fi; done
mkdir -p "$OUT"; umask 077
if [[ $CSR -eq 1 ]]; then
  openssl req -new -newkey rsa:3072 -sha256 -nodes -keyout "$OUT/aiops.key" -out "$OUT/aiops.csr" -subj "/CN=${FQDN}" \
    -addext "subjectAltName=${san}" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth"
  echo "CSR: $OUT/aiops.csr (SAN ${san}) — 사내 CA 에 '웹 서버' 템플릿으로 제출, 발급 PEM 과 $OUT/aiops.key 를 install.sh --cert/--key 로 지정"
else
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -keyout "$OUT/aiops.key" -out "$OUT/aiops.crt" -subj "/CN=${FQDN}" \
    -addext "subjectAltName=${san}" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth" \
    -addext "basicConstraints=critical,CA:FALSE"
  chmod 0644 "$OUT/aiops.crt"
  echo "자체 서명 인증서: $OUT/aiops.crt (SAN ${san}, 825일)"
fi
