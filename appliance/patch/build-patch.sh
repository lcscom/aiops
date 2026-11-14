#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops 패치 번들 만들기 — 기존 설치본(OVA·install.sh)에 적용할 vcf-aiops-patch-<버전>.tgz
#
#  bash appliance/patch/build-patch.sh --version 1.3.0 [--out ./out] [--key ~/.vcf-aiops/patch-signing.key] [--wheels] [--notes "…"]
#    --wheels   requirements.txt 의 패키지 wheel(cp312·manylinux x86_64)을 함께 넣음 — 의존 패키지가 바뀐 패치를 망분리 환경에 적용할 때
#    --genkey   서명 키가 없으면 새로 만듦(공개 키는 appliance/patch/patch-signing.pub 로 저장 → 다음 릴리스부터 신뢰)
#  결과: <out>/vcf-aiops-patch-<버전>.tgz · .sha256
#  번들 구성: apply.sh · manifest.json(product·버전·python_tag·번들 안 모든 파일의 SHA-256) · manifest.sig(Ed25519) · payload.tar.gz · patch-signing.pub · [wheelhouse/] · [govc]
#  서명은 manifest.json 만 덮으므로, 번들에 넣는 파일은 전부 manifest(payload_sha256·apply_sha256·files)에 해시가 있어야 한다 — 적용 쪽이 그 밖의 파일을 거부
# =============================================================================================
set -euo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""; OUT="$SRC/out"; KEY="${PATCH_KEY:-$HOME/.vcf-aiops/patch-signing.key}"; WHEELS=0; NOTES=""; GENKEY=0
PYVER=3.12; PYTAG=cp312                               # wheelhouse 대상(어플라이언스 Ubuntu 24.04 venv) — apply.sh 가 venv 와 비교
# payload 목록 — apply.sh(CODE_DIRS·CODE_FILES) · vcf-aiopsctl(_rollback) · scripts/linux/install.sh 와 같이 고칠 것
PAY_DIRS=(app scripts deploy ragpacks docs tests appliance)
PAY_FILES=(requirements.txt requirements-dev.txt config.example.yaml README.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt .env.example)
SKIP_DIRS=(mobile data out patches .github .git .hypothesis .pytest_cache)        # 의도적으로 싣지 않는 폴더(mobile = Android 소스 — APK 는 app/static/app/ 로 들어감)
SKIP_FILES=(VERSION Dockerfile docker-compose.yml environment.yml .gitignore .dockerignore)   # VERSION 은 --version 값으로 새로 만들어 넣음
while [[ $# -gt 0 ]]; do case "$1" in
  --version) VERSION="$2"; shift 2 ;; --out) OUT="$2"; shift 2 ;; --key) KEY="$2"; shift 2 ;;
  --wheels) WHEELS=1; shift ;; --notes) NOTES="$2"; shift 2 ;; --genkey) GENKEY=1; shift ;;
  *) echo "알 수 없는 옵션 $1" >&2; exit 2 ;; esac; done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?$ ]] || { echo "--version X.Y.Z 필요" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl 필요" >&2; exit 1; }
if [[ ! -f "$KEY" ]]; then
  [[ $GENKEY -eq 1 ]] || { echo "서명 키 없음: $KEY (--genkey 로 생성하거나 --key 지정)" >&2; exit 1; }
  install -d -m 0700 "$(dirname "$KEY")"; openssl genpkey -algorithm ed25519 -out "$KEY"; chmod 600 "$KEY"
  openssl pkey -in "$KEY" -pubout -out "$SRC/appliance/patch/patch-signing.pub"
  echo "새 서명 키 $KEY — 공개 키를 appliance/patch/patch-signing.pub 에 저장했습니다(이 버전부터 신뢰)"
fi
PUB_NOW="$(openssl pkey -in "$KEY" -pubout)"
[[ "$PUB_NOW" == "$(cat "$SRC/appliance/patch/patch-signing.pub")" ]] || { echo "서명 키와 appliance/patch/patch-signing.pub 가 다릅니다" >&2; exit 1; }

# ---- 싣기 전 점검: 목록에서 빠진 폴더·파일 경고, Android 앱(APK)과 app.json 일치
in_list() { local x="$1" y; shift; for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done; return 1; }
for p in "$SRC"/* "$SRC"/.[!.]*; do
  [[ -e "$p" ]] || continue; n="$(basename "$p")"
  if [[ -d "$p" ]]; then
    in_list "$n" "${PAY_DIRS[@]}" "${SKIP_DIRS[@]}" && continue
    if [[ -n "$(find "$p" -name '*.py' -not -path '*/node_modules/*' -print -quit 2>/dev/null)" ]]; then
      echo "경고: 폴더 '$n/' 에 *.py 가 있는데 payload 목록(PAY_DIRS)에 없습니다 — 번들에 들어가지 않습니다(의도면 SKIP_DIRS 에 추가)" >&2; fi
  else
    in_list "$n" "${PAY_FILES[@]}" "${SKIP_FILES[@]}" && continue
    echo "경고: 파일 '$n' 이 payload 목록(PAY_FILES)에 없습니다 — 번들에 들어가지 않습니다(의도면 SKIP_FILES 에 추가)" >&2
  fi
done
APK="$SRC/app/static/app/vcf-aiops.apk"; APJ="$SRC/app/static/app/app.json"
if [[ -f "$APK" ]]; then
  [[ -f "$APJ" ]] || { echo "✖ $APK 는 있는데 app.json 이 없습니다 — Android 앱 메타 없이 번들을 만들지 않습니다" >&2; exit 1; }
  python3 -c '
import hashlib, json, os, sys
apk, j = sys.argv[1], json.load(open(sys.argv[2], encoding="utf-8"))
h, n = hashlib.sha256(open(apk, "rb").read()).hexdigest(), os.path.getsize(apk)
bad = ["%s: app.json %r ≠ APK %r" % (k, j.get(k), v) for k, v in (("sha256", h), ("size", n)) if j.get(k) != v]
if bad: sys.exit("  " + " · ".join(bad))' "$APK" "$APJ" \
    || { echo "✖ app/static/app/app.json 이 APK 와 맞지 않습니다 — APK 를 다시 빌드했으면 app.json(sha256·size)도 갱신" >&2; exit 1; }
fi

NAME="vcf-aiops-patch-$VERSION"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
B="$W/$NAME"; mkdir -p "$B" "$OUT"
echo "$VERSION" > "$W/VERSION"
ITEMS=("${PAY_DIRS[@]}")
for f in "${PAY_FILES[@]}"; do
  if [[ -f "$SRC/$f" ]]; then ITEMS+=("$f")
  elif [[ "$f" != requirements-dev.txt && "$f" != .env.example ]]; then echo "✖ payload 파일 없음: $f" >&2; exit 1; fi
done
( cd "$SRC" && tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' --exclude='docs/images' --owner=0 --group=0 -czf "$B/payload.tar.gz" \
    "${ITEMS[@]}" -C "$W" VERSION )
install -m 0755 "$SRC/appliance/patch/apply.sh" "$B/apply.sh"
cp "$SRC/appliance/patch/patch-signing.pub" "$B/"
if [[ $WHEELS -eq 1 ]]; then
  python3 -m pip download -q -d "$B/wheelhouse" -r "$SRC/requirements.txt" --only-binary=:all: --python-version "$PYVER" \
    --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 --platform any --implementation cp
fi
[[ -n "${GOVC_BIN:-}" && -f "$GOVC_BIN" ]] && install -m 0755 "$GOVC_BIN" "$B/govc"
python3 - "$B" "$VERSION" "$NOTES" "$PYTAG" <<'PY'
import hashlib, json, sys, time, pathlib
b, ver, notes, pytag = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
core = ("payload.tar.gz", "apply.sh")
files = {p.relative_to(b).as_posix(): h(p) for p in sorted(b.rglob("*")) if p.is_file() and p.relative_to(b).as_posix() not in core}
m = {"product": "vcf-aiops", "version": ver, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "min_from": "1.0.0",
     "payload_sha256": h(b / "payload.tar.gz"), "apply_sha256": h(b / "apply.sh"), "python_tag": pytag,
     "files": files,                                   # 그 밖의 모든 파일(patch-signing.pub·wheelhouse/*·govc) — 적용 쪽이 목록 밖 파일을 거부
     "wheels": (b / "wheelhouse").is_dir(), "notes": notes}
(b / "manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=1))
PY
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$B/manifest.json" -out "$B/manifest.sig"
openssl pkeyutl -verify -pubin -inkey "$SRC/appliance/patch/patch-signing.pub" -rawin -in "$B/manifest.json" -sigfile "$B/manifest.sig" >/dev/null
tar --owner=0 --group=0 -czf "$OUT/$NAME.tgz" -C "$W" "$NAME"
( cd "$OUT" && sha256sum "$NAME.tgz" > "$NAME.tgz.sha256" )
echo "패치 번들: $OUT/$NAME.tgz ($(du -h "$OUT/$NAME.tgz" | cut -f1)) · SHA-256 $(cut -d' ' -f1 "$OUT/$NAME.tgz.sha256")"
echo "적용(1.3 이상): sudo vcf-aiopsctl patch $NAME.tgz   또는 웹 콘솔 › 시스템·패치"
echo "적용(1.2 이하): tar xzf $NAME.tgz && sudo bash $NAME/apply.sh"
