#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops 안드로이드 앱 빌드 — Gradle 없이 SDK 기본 도구만 사용(망분리 빌드 서버에서도 가능)
#
#  bash mobile/android/build.sh [버전] [--key <서명 키 .p12>] [--pass-file <비밀번호 파일>] [--sdk-jar <android.jar>]
#    버전 생략 시 저장소 VERSION. versionCode = 주*10000 + 부*100 + 수정 (2.30.0 → 23000)
#  도구(Ubuntu): apt-get install -y aapt apksigner zipalign dalvik-exchange default-jdk-headless
#  android.jar: API 34 (예: Android SDK platforms/android-34/android.jar) — ANDROID_JAR 또는 --sdk-jar
#  결과: app/static/app/vcf-aiops.apk · app/static/app/app.json (패치 번들 payload 의 app/ 에 함께 들어감)
#  서명 키: 기본 ~/.vcf-aiops/android-signing.p12 + android-signing.pass — 저장소에 넣지 않는다.
#           같은 키로 서명해야 기존 설치 위에 업데이트되므로 반드시 따로 보관.
# =============================================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$(cd "$HERE/../.." && pwd)"
VER=""; KEY="${ANDROID_KEY:-$HOME/.vcf-aiops/android-signing.p12}"; PASSF=""; JAR="${ANDROID_JAR:-}"
while [[ $# -gt 0 ]]; do case "$1" in
  --key) KEY="$2"; shift 2 ;; --pass-file) PASSF="$2"; shift 2 ;; --sdk-jar) JAR="$2"; shift 2 ;;
  -*) echo "알 수 없는 옵션 $1" >&2; exit 2 ;; *) VER="$1"; shift ;; esac; done
VER="${VER:-$(cat "$SRC/VERSION")}"
[[ "$VER" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo "버전은 X.Y.Z" >&2; exit 2; }
CODE=$(( BASH_REMATCH[1] * 10000 + BASH_REMATCH[2] * 100 + BASH_REMATCH[3] ))
PASSF="${PASSF:-${KEY%.p12}.pass}"
for t in aapt zipalign apksigner javac keytool; do command -v $t >/dev/null || { echo "$t 없음 — 머리말의 apt-get 참고" >&2; exit 1; }; done
DX="$(command -v dalvik-exchange || command -v dx || true)"; [[ -n "$DX" ]] || { echo "dalvik-exchange(dx) 없음" >&2; exit 1; }
[[ -f "$JAR" ]] || { echo "android.jar(API 34) 경로 필요: --sdk-jar 또는 ANDROID_JAR" >&2; exit 1; }
if [[ ! -f "$KEY" ]]; then
  install -d -m 0700 "$(dirname "$KEY")"
  ( umask 077; openssl rand -hex 24 > "$PASSF" )
  keytool -genkeypair -keystore "$KEY" -storetype PKCS12 -storepass:file "$PASSF" -alias vcfaiops -keyalg RSA -keysize 3072 -validity 10950 \
          -dname "CN=VCF AIops Mobile, O=KRVCF" >/dev/null 2>&1
  chmod 600 "$KEY"; echo "새 앱 서명 키: $KEY (비밀번호 $PASSF) — 반드시 보관하세요"
fi
export JAVA_TOOL_OPTIONS=""
B="$(mktemp -d)"; trap 'rm -rf "$B"' EXIT
mkdir -p "$B/gen" "$B/cls" "$B/dex"
aapt package -f -m -J "$B/gen" -M "$HERE/AndroidManifest.xml" -S "$HERE/res" -I "$JAR" \
     --min-sdk-version 26 --target-sdk-version 34 --version-code "$CODE" --version-name "$VER"
javac -nowarn -source 8 -target 8 -encoding UTF-8 -bootclasspath "$JAR" -d "$B/cls" $(find "$HERE/src" "$B/gen" -name '*.java') 2>&1 | grep -v "^Note:\|bootstrap class path\|warning: \[options\]" || true
[[ -n "$(find "$B/cls" -name 'MainActivity.class')" ]] || { echo "컴파일 실패" >&2; exit 1; }
"$DX" --dex --min-sdk-version=26 --output="$B/dex/classes.dex" "$B/cls"
aapt package -f -M "$HERE/AndroidManifest.xml" -S "$HERE/res" -I "$JAR" -F "$B/u.apk" \
     --min-sdk-version 26 --target-sdk-version 34 --version-code "$CODE" --version-name "$VER"
( cd "$B/dex" && aapt add "$B/u.apk" classes.dex >/dev/null )
zipalign -f 4 "$B/u.apk" "$B/a.apk"
OUT="$SRC/app/static/app"; mkdir -p "$OUT"
apksigner sign --ks "$KEY" --ks-type PKCS12 --ks-pass "file:$PASSF" --ks-key-alias vcfaiops --v1-signing-enabled false --v2-signing-enabled true \
          --v3-signing-enabled true --out "$OUT/vcf-aiops.apk" "$B/a.apk"
rm -f "$OUT/vcf-aiops.apk.idsig"
apksigner verify "$OUT/vcf-aiops.apk"
CERT="$(apksigner verify --print-certs "$OUT/vcf-aiops.apk" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p')"
python3 - "$OUT" "$VER" "$CODE" "$CERT" <<'PY'
import hashlib, json, pathlib, sys, time
out, ver, code, cert = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
apk = out / "vcf-aiops.apk"
(out / "app.json").write_text(json.dumps({"package": "com.krvcf.vcfaiops", "name": ver, "code": code, "size": apk.stat().st_size,
    "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(), "cert_sha256": cert, "min_android": "8.0", "built": time.strftime("%Y-%m-%d")},
    ensure_ascii=False, indent=1) + "\n")
print((out / "app.json").read_text())
PY
echo "APK: $OUT/vcf-aiops.apk ($(du -h "$OUT/vcf-aiops.apk" | cut -f1))"
