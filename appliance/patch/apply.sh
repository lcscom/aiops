#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops 패치 적용기 — 기존 설치(OVA·install.sh, 1.0 이상)를 새 버전으로 교체. 설정·데이터·인증서·계정은 그대로.
#
#  sudo bash apply.sh [--yes] [--no-db-backup] [--skip-health]
#    (1.3 이상은 보통 'sudo vcf-aiopsctl patch <번들.tgz>' 또는 웹 콘솔 › 시스템·패치 업로드로 실행되며,
#     그 경로는 설치된 신뢰 키로 서명을 먼저 확인한 뒤 이 스크립트를 부릅니다)
#
#  순서: 잠금(flock) → 무결성(번들의 모든 파일 SHA-256 = manifest) → 서명(설치된 신뢰 키가 있으면 필수)
#        → 사전 점검(PREFIX·스테이징·DATA 파일시스템별 여유) → 백업(프로그램 + DB 온라인 백업 + pip freeze, root 전용)
#        → 의존 패키지(바뀐 경우만, 번들 wheelhouse 우선·Python 태그 확인) → 새 트리 준비 → 서비스 중지 → 원자적 교체 → 기동
#        → /readyz + VERSION + 10초 안정 확인 → 실패·예상 못 한 오류·중단 신호는 자동 롤백(프로그램 + DB + venv 복원 후 재기동)
#  상태: /var/lib/vcf-aiops/patches/status.json(화면 표시) · history.jsonl · backups.json(백업 색인 사본) · backup/(root 전용, 최근 3개)
#        /etc/vcf-aiops/patch-state/(root 전용: 잠금·백업 색인 원본) · /opt/vcf-aiops/release.json
#  (2.30.0) 2.29.0 이하의 vcf-aiopsctl 이 이 스크립트를 불러도 그대로 동작해야 한다 — 인자·환경 변수 형식 유지
# =============================================================================================
set -eEuo pipefail
umask 022
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/vcf-aiops; ETC=/etc/vcf-aiops; DATA=/var/lib/vcf-aiops; SVC=vcf-aiops; USR=aiops
CTL=/usr/local/bin/vcf-aiopsctl; UNITD=/etc/systemd/system; TMPB=/var/tmp; TICK=2
PD="$DATA/patches"; BK="$PD/backup"; STATUS="$PD/status.json"; HIST="$PD/history.jsonl"; BKPUB="$PD/backups.json"
RS="$ETC/patch-state"; BKIDX="$RS/backups.json"; LOCK="$RS/lock"
YES=0; DBBK=1; HEALTH=1; BY="${AIOPS_PATCH_BY:-$(logname 2>/dev/null || echo root)}"; VERIFIED="${AIOPS_PATCH_VERIFIED:-0}"
# 목록은 build-patch.sh(PAY_DIRS·PAY_FILES) · vcf-aiopsctl(_rollback) · scripts/linux/install.sh 와 같이 고칠 것
CODE_DIRS=(app scripts deploy ragpacks docs tests appliance)
CODE_FILES=(requirements.txt requirements-dev.txt config.example.yaml README.md CHANGELOG.md .env.example VERSION LICENSE NOTICE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt)
BK_EXTRA=(release.json)                               # 번들에는 없지만 백업·롤백 대상인 파일
INWIN=0; ROLLING=0; STARTED=0; PIPCHG=0; PIPOPT=(); STG=""; NEW=""; OLD=""; BKF=""; FRZ=""; NOTES=""

while [[ $# -gt 0 ]]; do case "$1" in
  --yes|-y) YES=1; shift ;; --no-db-backup) DBBK=0; shift ;; --skip-health) HEALTH=0; shift ;;
  *) echo "알 수 없는 옵션 $1" >&2; exit 2 ;; esac; done

# ---------------------------------------------------------------- 도우미(python3: JSON·원자적 쓰기·번들 검사·백업 색인)
PYH="$(cat <<'PY'
import hashlib, json, os, re, shutil, stat, sys, time
NAME = re.compile(r"vcf-aiops-[0-9A-Za-z._-]{1,120}")
def gid(g):
    try:
        import grp; return grp.getgrnam(g).gr_gid
    except Exception:
        return -1
def awrite(path, data, group, mode):                 # 임시 파일(O_EXCL·O_NOFOLLOW) → rename. 심볼릭 링크를 따라가지 않는다
    tmp = os.path.join(os.path.dirname(path), ".%s.%d.%s" % (os.path.basename(path), os.getpid(), os.urandom(4).hex()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data.encode())
        if os.geteuid() == 0: os.fchown(fd, 0, gid(group) if group else 0)
        os.fchmod(fd, mode); os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()
def vt(v): return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v or "0")[:4])
def fail(msg): print(msg, file=sys.stderr); sys.exit(1)
def check(d):                                         # 번들 폴더: manifest 가 모든 파일을 SHA-256 으로 덮는지
    files = {}
    for root, dirs, fs in os.walk(d):
        for n in dirs + fs:
            p = os.path.join(root, n); st = os.lstat(p); rel = os.path.relpath(p, d)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)): fail("번들에 일반 파일·폴더가 아닌 항목: " + rel)
            if stat.S_ISREG(st.st_mode): files[rel] = p
    try:
        m = json.load(open(os.path.join(d, "manifest.json"), encoding="utf-8"))
    except Exception as e:
        fail("manifest.json 형식 오류: %s" % e)
    if not isinstance(m, dict) or m.get("product") != "vcf-aiops": fail("다른 제품의 번들(product)")
    for k in ("version", "payload_sha256", "apply_sha256"):
        if not isinstance(m.get(k), str) or not m[k]: fail("manifest 에 %s 가 없습니다 — 이 번들은 적용하지 않습니다" % k)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?", m["version"]): fail("manifest version 형식 오류")
    extra = m.get("files") or {}
    if not isinstance(extra, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in extra.items()): fail("manifest files 형식 오류")
    exp = dict(extra); exp["payload.tar.gz"] = m["payload_sha256"]; exp["apply.sh"] = m["apply_sha256"]
    for rel, h in exp.items():
        if rel not in files: fail("번들에 없음: " + rel)
        if sha(files[rel]) != h: fail("%s SHA-256 불일치 — 번들 손상·변조" % rel)
    for rel in files:
        if rel not in exp and rel not in ("manifest.json", "manifest.sig"): fail("manifest 에 없는 파일(서명 범위 밖): " + rel)
def trusted_tree(p):                                  # 2.30 이전 백업: root 소유·쓰기 불가·링크 없음일 때만 색인
    me = os.geteuid()
    for root, dirs, fs in os.walk(p):
        for q in [root] + [os.path.join(root, n) for n in dirs + fs]:
            st = os.lstat(q)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)) or st.st_uid != me or st.st_mode & 0o022: return False
    return True
def lock_tree(p):
    for root, dirs, fs in os.walk(p):
        for q in [root] + [os.path.join(root, n) for n in fs]:
            st = os.lstat(q)
            if stat.S_ISLNK(st.st_mode): continue
            if os.geteuid() == 0: os.chown(q, 0, 0)
            os.chmod(q, st.st_mode & 0o700)
def load(idx):
    try:
        j = json.load(open(idx, encoding="utf-8")); return [b for b in j.get("backups", []) if isinstance(b, dict) and NAME.fullmatch(str(b.get("name", "")))]
    except Exception:
        return []
def save(idx, pub, group, bl):
    bl.sort(key=lambda b: b.get("ts", 0), reverse=True)
    s = json.dumps({"v": 1, "updated": int(time.time()), "backups": bl}, ensure_ascii=False, indent=1)
    awrite(idx, s, "", 0o600); awrite(pub, s, group, 0o640)
def entry(bk, name, legacy):
    b = os.path.join(bk, name); e = {"name": name, "legacy": bool(legacy)}
    try: e["version"] = open(os.path.join(b, "VERSION")).read().strip()
    except OSError: e["version"] = ""
    sz = 0
    for root, _, fs in os.walk(b):
        sz += sum(os.lstat(os.path.join(root, f)).st_size for f in fs)
    e["size_mb"] = round(sz / 2**20, 1); e["ts"] = os.lstat(b).st_mtime if legacy else time.time()
    e["db"] = os.path.isfile(os.path.join(b, "aiops.db"))
    for k, f in (("sha256", "code.tar.gz"), ("ctl_sha256", "vcf-aiopsctl"), ("db_sha256", "aiops.db")):
        p = os.path.join(b, f)
        if os.path.isfile(p) and not os.path.islink(p): e[k] = sha(p)
    return e
def bksync(bk, idx, pub, group, newname):             # 권한 이관(root 전용) + 색인 갱신
    old = {b["name"]: b for b in load(idx)}; out = []
    for name in sorted(os.listdir(bk)):
        b = os.path.join(bk, name)
        if not NAME.fullmatch(name) or os.path.islink(b) or not os.path.isdir(b): continue
        if name in old and old[name].get("sha256"): out.append(old[name]); continue
        if name != newname and not trusted_tree(b):
            os.rename(b, os.path.join(bk, "untrusted." + name))
            print("  ! 백업 %s: root 소유·쓰기 금지 상태가 아니라 신뢰하지 않습니다 → untrusted.%s (색인 제외)" % (name, name), file=sys.stderr); continue
        lock_tree(b)
        if not os.path.isfile(os.path.join(b, "code.tar.gz")): continue
        out.append(entry(bk, name, name != newname))
    save(idx, pub, group, out)
def bkprune(bk, idx, pub, group, to, keep):           # 최근 keep 개 + '설치한 버전과 다른 가장 최근 백업'은 항상 보관
    bl = sorted(load(idx), key=lambda b: b.get("ts", 0), reverse=True)
    prot = next((b["name"] for b in bl if b.get("version") != to), None)
    out = []
    for i, b in enumerate(bl):
        if i < keep or b["name"] == prot: out.append(b); continue
        shutil.rmtree(os.path.join(bk, b["name"]), ignore_errors=True); print("  백업 정리: " + b["name"])
    save(idx, pub, group, out)
a = sys.argv[1:]; c = a[0]
if c == "status":
    awrite(a[1], json.dumps({"state": a[3], "step": a[4], "from": a[5], "to": a[6], "ts": int(time.time()), "by": a[7]}, ensure_ascii=False) + "\n", a[2], 0o640)
elif c == "hist":
    e = {"ts": int(time.time()), "from": a[3], "to": a[4], "result": a[5], "detail": a[6], "by": a[7], "backup": a[8], "version": a[4]}
    if a[9]: e["notes"] = a[9]
    fd = os.open(a[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, (json.dumps(e, ensure_ascii=False) + "\n").encode())
        if os.geteuid() == 0: os.fchown(fd, 0, gid(a[2]))
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
elif c == "mf":
    v = json.load(open(a[1], encoding="utf-8")).get(a[2], "")
    print(str(v).lower() if isinstance(v, bool) else v if isinstance(v, (str, int)) else "")
elif c == "check": check(a[1])
elif c == "vcmp": x, y = vt(a[1]), vt(a[2]); print(1 if x > y else -1 if x < y else 0)
elif c == "bksync": bksync(*a[1:6])
elif c == "bkprune": bkprune(a[1], a[2], a[3], a[4], a[5], int(a[6]))
elif c == "release":
    awrite(a[1], json.dumps({"version": a[2], "from": a[3], "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "notes": a[4]}, ensure_ascii=False, indent=1) + "\n", "", 0o644)
else: fail("unknown " + c)
PY
)"
pyh()  { python3 -c "$PYH" "$@"; }
ok()   { echo -e "  \e[32m✔\e[0m $*"; }
warn() { echo -e "  \e[33m!\e[0m $*"; }
step() { echo -e "\n\e[36m▶ $*\e[0m"; status running "$*"; }
status() { [[ -L "$PD" ]] && return 0; install -d -m 0770 -o root -g "$USR" "$PD" 2>/dev/null || true
  pyh status "$STATUS" "$USR" "$1" "$2" "${FROM:-}" "${TO:-}" "$BY" 2>/dev/null || true; }
hist() { pyh hist "$HIST" "$USR" "${FROM:-}" "${TO:-}" "$1" "${2:-}" "$BY" "${BKF:-}" "${NOTES:-}" 2>/dev/null || true
         # 2.36.0 root 전용 원본 기록(서비스 계정이 공개 사본을 고쳐도 남음)
         [[ $EUID -eq 0 ]] && { install -d -m 0700 "$RS" 2>/dev/null; pyh hist "$RS/history.jsonl" "" "${FROM:-}" "${TO:-}" "$1" "${2:-}" "$BY" "${BKF:-}" "${NOTES:-}" 2>/dev/null; } || true; }
die()  { echo -e "\e[31m✖ $*\e[0m" >&2; status failed "$*"; hist failed "$*"; exit 1; }
sha()  { sha256sum "$1" | cut -d' ' -f1; }
mf()   { pyh mf "$HERE/manifest.json" "$1"; }
key_ok() { [[ -f "$1" && ! -L "$1" ]] && find "$1" -maxdepth 0 -user root ! -perm /022 2>/dev/null | grep -q .; }   # root 소유·남이 못 쓰는 키만 신뢰
cfg()  { sed -n '/^server:/,/^[^[:space:]#]/s/^  '"$1"':[[:space:]]*\([^[:space:]#]*\).*/\1/p' "$ETC/config.yaml" 2>/dev/null | head -1 | tr -d "\"'"; }

[[ $EUID -eq 0 ]] || { echo "root 로 실행하세요: sudo bash $0" >&2; exit 1; }
[[ -f "$HERE/manifest.json" && -f "$HERE/payload.tar.gz" ]] || { echo "manifest.json·payload.tar.gz 가 없습니다 — 번들을 풀어 그 폴더의 apply.sh 를 실행하세요" >&2; exit 1; }
[[ -L "$PD" ]] && { echo "$PD 가 심볼릭 링크입니다 — 중단" >&2; exit 1; }
TO="$(mf version)"; NOTES="$(mf notes)"
FROM="$(cat "$PREFIX/VERSION" 2>/dev/null || sed -n 's/^VCF AIops Appliance \([^ ]*\).*/\1/p' /etc/vcf-aiops-appliance-release 2>/dev/null || echo unknown)"
FROM="${FROM:-unknown}"
echo "VCF AIops 패치 $FROM → $TO  ($(mf created))"
[[ -x "$PREFIX/venv/bin/python" && -d "$ETC" ]] || { echo "$PREFIX/venv·$ETC 가 없습니다 — 설치본이 아닙니다(새로 설치는 install.sh 또는 OVA)" >&2; exit 1; }

# ---------------------------------------------------------------- 0. 잠금 — CLI·웹 요청·롤백이 겹치지 않게(root 전용 폴더)
install -d -m 0700 -o root -g root "$RS"
exec 9>"$LOCK"
flock -n 9 || { echo "다른 패치·롤백 작업이 진행 중입니다($LOCK) — 끝난 뒤 다시 시도하세요" >&2; exit 75; }
systemctl cat "$SVC" >/dev/null 2>&1 || die "$SVC.service 가 없습니다"

# ---------------------------------------------------------------- 1. 무결성·서명
step "1. 무결성·서명 확인"
e="$(pyh check "$HERE" 2>&1)" || die "번들 검사 실패 — $e"
[[ "$(sha "$0")" == "$(mf apply_sha256)" ]] || die "apply.sh SHA-256 불일치 — 번들 변조"
ok "manifest 가 번들의 모든 파일(payload·apply.sh·wheelhouse 등)과 일치"
TRUST=()
for k in "$PREFIX/appliance/patch/patch-signing.pub" "$ETC"/patch-trust/*.pub; do
  [[ -e "$k" ]] || continue
  if key_ok "$k"; then TRUST+=("$k"); else warn "신뢰 키 무시(root 소유·쓰기 금지 아님): $k"; fi
done
if [[ ${#TRUST[@]} -gt 0 ]]; then
  good=0
  for k in "${TRUST[@]}"; do
    openssl pkeyutl -verify -pubin -inkey "$k" -rawin -in "$HERE/manifest.json" -sigfile "$HERE/manifest.sig" >/dev/null 2>&1 && { good=1; ok "서명 확인: $(basename "$k")"; break; }
  done
  [[ $good -eq 1 ]] || die "서명 검증 실패 — 신뢰하는 키로 서명된 번들이 아닙니다($PREFIX/appliance/patch/patch-signing.pub, $ETC/patch-trust/*.pub · 키 교체는 docs/PATCH.md)"
elif [[ "$VERIFIED" == 1 ]]; then
  ok "서명은 호출자가 확인함"
else
  warn "이 설치본에는 신뢰 키가 없습니다(1.3 이전). 번들 SHA-256 을 배포처가 알려 준 값과 비교하세요:"
  echo "      manifest $(sha "$HERE/manifest.json") · payload $(mf payload_sha256)"
  if [[ $YES -ne 1 ]]; then read -r -p "  계속할까요? [y/N] " a; [[ "$a" =~ ^[yY]$ ]] || die "사용자 취소"; fi
fi
if [[ "$FROM" != unknown && "$(pyh vcmp "$TO" "$FROM")" != 1 ]]; then
  warn "새 버전이 아닙니다($FROM → $TO) — 같은 버전 재적용 또는 하향"
  if [[ $YES -ne 1 ]]; then read -r -p "  계속할까요? [y/N] " a; [[ "$a" =~ ^[yY]$ ]] || die "사용자 취소"; fi
fi

# ---------------------------------------------------------------- 2. 사전 점검(파일시스템별 여유 — 서비스 중지 전)
step "2. 사전 점검"
DBF="$(sed -n 's/^ *db_path: *//p' "$ETC/config.yaml" 2>/dev/null | head -1)"; DBF="${DBF:-$DATA/aiops.db}"
PM=$(tar -tzvf "$HERE/payload.tar.gz" | awk '{s+=$3} END{printf "%d", s/1048576+1}')          # 풀었을 때 크기(MB)
CM=$(du -sm "$PREFIX" --exclude=venv | cut -f1); DBM=0
[[ $DBBK -eq 1 && -f "$DBF" ]] && DBM=$(du -sm "$DBF" | cut -f1)
declare -A NEED=() FSP=()
need() { local dev; dev="$(stat -c %d "$1")"; NEED[$dev]=$(( ${NEED[$dev]:-0} + $2 )); FSP[$dev]="${FSP[$dev]:-$1}"; }
need "$PREFIX" $(( PM + 100 ))                        # 새 트리(.patch-new) + pyc
need "$TMPB"   $(( PM + 50 ))                         # 스테이징
need "$DATA"   $(( CM + DBM + 100 ))                  # 백업(프로그램 + DB)
msg=""
for dev in "${!NEED[@]}"; do
  free=$(df -Pm "${FSP[$dev]}" | awk 'NR==2{print $4}')
  [[ ${free:-0} -gt ${NEED[$dev]} ]] || die "${FSP[$dev]} 파일시스템 여유 공간 부족(필요 ${NEED[$dev]}MB · 여유 ${free:-0}MB)"
  msg+="${FSP[$dev]} ${free}MB(필요 ${NEED[$dev]}) "
done
PORT="$(cfg port)"; [[ "$PORT" =~ ^[0-9]+$ ]] || PORT=8630
BHOST="$(cfg host)"; case "$BHOST" in ""|0.0.0.0|::|\*|"[::]") BHOST=127.0.0.1 ;; *:*) BHOST="[${BHOST#[}"; BHOST="${BHOST%]}]" ;; esac
HOSTS=("$BHOST"); [[ "$BHOST" == 127.0.0.1 ]] || HOSTS+=(127.0.0.1)        # vcf-aiopsctl url() 과 같은 규칙: 바인드 주소 우선
ready() { local h; for h in "${HOSTS[@]}"; do
    curl -sk --max-time 3 "https://$h:$PORT/readyz" 2>/dev/null | grep -q '"ready":[[:space:]]*true' && return 0
    curl -s --max-time 3 "http://$h:$PORT/readyz" 2>/dev/null | grep -q '"ready":[[:space:]]*true' && return 0
  done; return 1; }
PYTAG="$("$PREFIX/venv/bin/python" -c 'import sys;print("cp%d%d" % sys.version_info[:2])')"
ok "여유 ${msg}· DB $DBF · 상태 확인 ${HOSTS[0]}:$PORT · venv $PYTAG"

# ---------------------------------------------------------------- 3. 백업(root 전용 — 서비스 계정은 색인 사본 backups.json 만 읽음)
step "3. 백업(프로그램 + DB)"
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -L "$BK" ]] || { [[ -e "$BK" ]] && [[ "$(stat -c %u "$BK")" != 0 || ! -d "$BK" ]]; }; then
  mv -T "$BK" "$PD/backup.untrusted-$TS"; warn "기존 백업 폴더가 root 소유 폴더가 아니라 backup.untrusted-$TS 로 옮겼습니다"
fi
install -d -m 0700 -o root -g root "$BK"
BKF="$BK/vcf-aiops-$FROM-$TS"; FRZ="$BKF/pip-freeze.txt"
mkdir -m 0700 "$BKF"
items=(); for d in "${CODE_DIRS[@]}" "${CODE_FILES[@]}" "${BK_EXTRA[@]}"; do [[ -e "$PREFIX/$d" ]] && items+=("$d"); done
tar -czf "$BKF/code.tar.gz" -C "$PREFIX" "${items[@]}"
cp "$CTL" "$BKF/vcf-aiopsctl" 2>/dev/null || true
for u in vcf-aiops.service vcf-aiops-patch.service vcf-aiops-patch.path; do [[ -f "$UNITD/$u" ]] && cp "$UNITD/$u" "$BKF/"; done
cp "$PREFIX/requirements.txt" "$BKF/requirements.txt" 2>/dev/null || true
PIP=("$PREFIX/venv/bin/python" -m pip --disable-pip-version-check -q)
"${PIP[@]}" freeze > "$FRZ" 2>/dev/null || { warn "pip freeze 실패 — 롤백 때 venv 는 복원하지 못합니다"; : > "$FRZ"; }
if [[ $DBBK -eq 1 && -f "$DBF" ]]; then
  if command -v sqlite3 >/dev/null; then sqlite3 "$DBF" ".backup '$BKF/aiops.db'"
  else "$PREFIX/venv/bin/python" -c 'import sqlite3,sys;s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close()' "$DBF" "$BKF/aiops.db"; fi
  ok "DB 온라인 백업 $(du -sh "$BKF/aiops.db" | cut -f1)"
fi
echo "$FROM" > "$BKF/VERSION"
pyh bksync "$BK" "$BKIDX" "$BKPUB" "$USR" "$(basename "$BKF")"          # 기존 백업 권한 이관(0700 root) + 색인(SHA-256)
ok "백업 $BKF ($(du -sh "$BKF" | cut -f1)) — 정리는 새 버전 확인 뒤"

# ---------------------------------------------------------------- 4. 펼치기(스테이징)
step "4. 새 버전 펼치기"
NEW="$PREFIX/.patch-new.$$"; OLD="$PREFIX/.patch-old.$$"
cleanup() {   # EXIT: 교체 구간에서 빠져나온 경우(set -u 오류·exit 등)도 롤백
  local rc=$?
  [[ $INWIN -eq 1 && $ROLLING -eq 0 ]] && rollback "예상치 못한 종료(rc=$rc)"
  rm -rf "$STG" "$NEW" 2>/dev/null || true
  return 0
}
STG="$(mktemp -d "$TMPB/vcf-aiops-patch.XXXXXX")"; trap cleanup EXIT
tar -xzf "$HERE/payload.tar.gz" -C "$STG" --no-same-owner
[[ -f "$STG/app/main.py" ]] || die "payload 에 app/main.py 가 없습니다"
echo "$TO" > "$STG/VERSION"
ok "$(du -sh "$STG" | cut -f1)"

# ---------------------------------------------------------------- 5. 의존 패키지
venv_restore() {   # pip freeze 기록으로 되돌리기(최선 노력) — 같은 wheelhouse·오프라인 옵션 사용
  [[ -s "$FRZ" ]] || { warn "pip freeze 기록이 없어 venv 는 그대로 둡니다"; return 0; }
  local now extra; now="$(mktemp "$TMPB/vcf-aiops-frz.XXXXXX")"
  "${PIP[@]}" freeze > "$now" 2>/dev/null || true
  if cmp -s "$FRZ" "$now"; then rm -f "$now"; ok "venv 패키지 변화 없음"; return 0; fi
  names() { grep -v '^[-#]' "$1" | sed -E 's/[=<>@ ].*//' | tr 'A-Z_' 'a-z-' | sort -u; }
  extra="$(comm -13 <(names "$FRZ") <(names "$now") | tr '\n' ' ')"; rm -f "$now"
  [[ -n "${extra// /}" ]] && { # shellcheck disable=SC2086
    "${PIP[@]}" uninstall -y $extra >/dev/null 2>&1 && echo "  venv: 새로 들어온 패키지 제거 — $extra" || warn "venv: 패키지 제거 실패 — $extra"; }
  if "${PIP[@]}" install --no-deps "${PIPOPT[@]}" -r "$FRZ"; then ok "venv 를 패치 전 패키지 버전으로 복원"; VENVMSG=" · venv 복원"
  else warn "venv 복원 실패(이전 버전 wheel 을 구할 수 없음) — 수동: $PREFIX/venv/bin/python -m pip install --no-deps -r $FRZ"; VENVMSG=" · venv 복원 실패(수동 필요: $FRZ)"; fi
}
VENVMSG=""
step "5. 의존 패키지"
if cmp -s "$STG/requirements.txt" "$PREFIX/requirements.txt"; then ok "변경 없음"
else
  if [[ -d "$HERE/wheelhouse" ]]; then
    WT="$(mf python_tag)"
    [[ -n "$WT" ]] || die "manifest 에 python_tag 가 없어 wheelhouse 를 쓸 수 없습니다"
    [[ "$WT" == "$PYTAG" ]] || die "번들 wheelhouse($WT)와 이 서버 venv Python($PYTAG)이 맞지 않습니다 — $PYTAG 용 번들을 받으세요"
    PIPOPT=(--no-index --only-binary=:all: --find-links "$HERE/wheelhouse")
  fi
  PIPCHG=1
  "${PIP[@]}" install "${PIPOPT[@]}" -r "$STG/requirements.txt" || { venv_restore; die "패키지 설치 실패(망분리면 --wheels 로 만든 번들 필요)$VENVMSG"; }
  now="$(mktemp "$TMPB/vcf-aiops-frz.XXXXXX")"; "${PIP[@]}" freeze > "$now" 2>/dev/null || true
  cmp -s "$FRZ" "$now" && PIPCHG=0; rm -f "$now"
  [[ ${#PIPOPT[@]} -gt 0 ]] && ok "번들 wheelhouse 로 설치($WT)" || ok "PyPI 에서 설치"
fi

# ---------------------------------------------------------------- 6. 교체(여기서부터 상태 확인까지: 실패 = 롤백)
rollback() {   # 각 단계는 실패해도 계속 — 마지막에 서비스는 반드시 기동 시도
  trap - ERR INT TERM HUP; set +eE; ROLLING=1; INWIN=0
  local why="$1" R="$PREFIX/.patch-rb.$$" d f bad="" st=rolled_back
  warn "롤백: $FROM 으로 되돌립니다 — $why"
  status rolling_back "$why"
  systemctl stop "$SVC" 2>/dev/null
  rm -rf "$R"; mkdir -m 0700 "$R"
  if tar -xzf "$BKF/code.tar.gz" -C "$R" 2>/dev/null; then
    mkdir -p "$R/.gone"
    for d in "${CODE_DIRS[@]}"; do
      [[ -e "$PREFIX/$d" ]] && { mv "$PREFIX/$d" "$R/.gone/$d" || bad+=" $d(치우기)"; }
      [[ -d "$R/$d" ]] && { mv "$R/$d" "$PREFIX/$d" || bad+=" $d"; }
    done
    rm -f "$PREFIX/VERSION" "$PREFIX/release.json"            # 1.3 이전 백업에는 VERSION 파일이 없음
    for f in "${CODE_FILES[@]}" "${BK_EXTRA[@]}"; do [[ -f "$R/$f" ]] && { mv -f "$R/$f" "$PREFIX/$f" || bad+=" $f"; }; done
  elif [[ -d "$OLD" ]]; then
    warn "백업 풀기 실패 — 교체 직전에 옮겨 둔 트리($OLD)로 되돌립니다"
    for f in "$OLD"/* "$OLD"/.env.example; do [[ -e "$f" ]] || continue; d="$(basename "$f")"
      rm -rf "${PREFIX:?}/$d"; mv "$f" "$PREFIX/$d" || bad+=" $d"; done
  else bad+=" 백업을 풀 수 없음"; fi
  if [[ -f "$BKF/vcf-aiopsctl" ]]; then install -m 0755 "$BKF/vcf-aiopsctl" "$CTL.rb.$$" && mv -f "$CTL.rb.$$" "$CTL" || bad+=" vcf-aiopsctl"; fi
  if [[ $STARTED -eq 1 && -f "$BKF/aiops.db" ]]; then   # 새 버전이 한 번이라도 기동했을 때만(스키마가 바뀌었을 수 있음) DB 를 백업 시점으로
    install -o "$USR" -g "$USR" -m 0640 "$BKF/aiops.db" "$DBF.rb.$$" && mv -f "$DBF.rb.$$" "$DBF" && rm -f "$DBF-wal" "$DBF-shm" || bad+=" DB"
  fi
  [[ $PIPCHG -eq 1 ]] && venv_restore
  find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null
  chown -R root:root "$PREFIX" 2>/dev/null; chmod -R go-w "$PREFIX" 2>/dev/null
  rm -rf "$R" "$OLD" "$NEW" 2>/dev/null
  systemctl daemon-reload 2>/dev/null
  systemctl start "$SVC" || bad+=" 서비스 기동"
  local i up=0; for i in $(seq 1 30); do sleep "$TICK"; ready && { up=1; break; }; done
  [[ $up -eq 1 ]] || bad+=" /readyz 무응답"
  [[ -n "$bad" ]] && { st=failed; why+=" · 롤백 중 문제:$bad"; }
  why+="$VENVMSG"
  status "$st" "$why"; hist "$st" "$why"
  if [[ $st == rolled_back ]]; then echo -e "\e[31m✖ 패치 실패 — $FROM 으로 복원했습니다: $why\e[0m" >&2
  else echo -e "\e[31m✖ 패치 실패, 롤백도 완전하지 않습니다 — 수동 확인 필요(백업 $BKF · journalctl -u $SVC): $why\e[0m" >&2; fi
  exit 1
}
on_err() { local rc=$?; (( BASH_SUBSHELL == 0 )) || exit "$rc"; [[ $INWIN -eq 1 && $ROLLING -eq 0 ]] && rollback "예상치 못한 오류(apply.sh $1 줄 · rc=$rc)"; return 0; }
trap 'on_err $LINENO' ERR

step "6. 새 트리 준비 · 서비스 중지 · 교체"
rm -rf "$NEW" "$OLD"; mkdir -m 0700 "$NEW" "$OLD"
for d in "${CODE_DIRS[@]}"; do [[ -d "$STG/$d" ]] && mv "$STG/$d" "$NEW/$d"; done            # 중지 전에 같은 파일시스템으로 옮겨 둠
for f in "${CODE_FILES[@]}"; do [[ -f "$STG/$f" ]] && install -m 0644 "$STG/$f" "$NEW/$f"; done
find "$NEW" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
chown -R root:root "$NEW"; chmod -R go-w "$NEW"; chmod 0700 "$NEW"
chmod 0755 "$NEW"/scripts/linux/*.sh "$NEW"/deploy/agents/linux/*.sh "$NEW"/appliance/*.py "$NEW"/appliance/patch/*.sh 2>/dev/null || true
INWIN=1; trap 'rollback "중단 신호(SIGINT·SIGTERM·SIGHUP)"' INT TERM HUP
systemctl stop "$SVC"
for d in "${CODE_DIRS[@]}"; do                        # 폴더 단위 rename 교체: 옛 것 치우기 → 새 것 넣기(옛 것은 성공 뒤 삭제)
  [[ -d "$NEW/$d" ]] || continue
  if [[ -e "$PREFIX/$d" ]]; then mv "$PREFIX/$d" "$OLD/$d"; fi
  mv "$NEW/$d" "$PREFIX/$d"
done
for f in "${CODE_FILES[@]}"; do                       # VERSION 포함 — rename 으로 원자적 교체
  [[ -f "$NEW/$f" ]] || continue
  if [[ -e "$PREFIX/$f" ]]; then cp -p "$PREFIX/$f" "$OLD/$f"; fi
  mv -f "$NEW/$f" "$PREFIX/$f"
done
[[ "$(cat "$PREFIX/VERSION")" == "$TO" ]]
"$PREFIX/venv/bin/python" -m compileall -q -j 0 -o 1 "$PREFIX/app" >/dev/null 2>&1 || true
install -m 0755 "$PREFIX/scripts/linux/vcf-aiopsctl" "$CTL.new.$$"; mv -f "$CTL.new.$$" "$CTL"
# 웹 콘솔 패치 업로드 → root 적용 경로(1.3 이상)
if bash "$PREFIX/appliance/patch/install-units.sh" --unit-dir "$UNITD" --data "$DATA" --group "$USR" >/dev/null 2>&1; then ok "패치 서비스 유닛(vcf-aiops-patch.path) 설치"
else warn "패치 유닛 설치 실패(웹 업로드 적용만 불가, CLI 는 가능)"; fi
# 1.2 이전 OVA: govc 가 없으면 동봉본 설치
if [[ ! -x "$PREFIX/bin/govc" && -f "$HERE/govc" ]]; then install -D -m 0755 "$HERE/govc" "$PREFIX/bin/govc"; ok "govc 설치"; fi
systemctl daemon-reload
ok "$TO 배치 완료"

# ---------------------------------------------------------------- 7. 기동 · 확인
step "7. 기동 · 상태 확인"
STARTED=1
systemctl start "$SVC" || rollback "서비스 기동 실패"
if [[ $HEALTH -eq 1 ]]; then
  up=0
  for i in $(seq 1 90); do
    sleep "$TICK"
    if ready; then up=1; break; fi
    if systemctl is-failed --quiet "$SVC"; then break; fi
  done
  if [[ $up -ne 1 ]]; then journalctl -u "$SVC" -n 40 --no-pager >&2 || true; rollback "180초 안에 /readyz 정상 응답 없음"; fi
  ok "/readyz 정상 (${i}회차)"
  [[ "$(cat "$PREFIX/VERSION" 2>/dev/null || true)" == "$TO" ]] || rollback "설치된 VERSION 이 $TO 가 아님"
  nr0="$(systemctl show -p NRestarts --value "$SVC" 2>/dev/null || echo 0)"
  for _ in 1 2 3 4 5; do                             # 준비 뒤 10초 동안 내려가거나 재시작하지 않아야 함
    sleep "$TICK"
    systemctl is-active --quiet "$SVC" || rollback "기동 뒤 10초 안에 서비스가 내려감"
  done
  nr1="$(systemctl show -p NRestarts --value "$SVC" 2>/dev/null || echo 0)"
  [[ "$nr0" == "$nr1" ]] || rollback "기동 뒤 서비스가 재시작됨(NRestarts $nr0 → $nr1)"
  ready || rollback "안정 확인 중 /readyz 응답 없음"
  ok "버전 $TO · 10초 안정 확인"
fi
INWIN=0; trap - INT TERM HUP ERR; set +e           # ---- 교체 구간 끝: 이후 실패는 경고만
rm -rf "$OLD" 2>/dev/null
pyh release "$PREFIX/release.json" "$TO" "$FROM" "$NOTES" || warn "release.json 기록 실패"
pyh bkprune "$BK" "$BKIDX" "$BKPUB" "$USR" "$TO" 3 || warn "백업 정리 실패"            # 최근 3개 + 다른 버전의 최신 백업
if [[ $HEALTH -eq 1 ]]; then status ok "$FROM → $TO 완료"; hist ok "readyz ok · version $TO"
else status ok "$FROM → $TO 완료(상태 확인 생략)"; hist ok "health skipped"; fi
echo -e "\n\e[32m✔ 패치 완료: $FROM → $TO\e[0m  (되돌리기: sudo vcf-aiopsctl rollback)"
exit 0
