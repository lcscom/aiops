#!/usr/bin/env bash
# VCF AIops — Cloudflare Tunnel 연동 (aiops.krvcf.com → 이 어플라이언스)
#
#  사용법 (어플라이언스 VM 에서 root 로 실행 — 설치본은 sudo vcf-aiopsctl tunnel <옵션> 과 동일):
#    sudo vcf-aiopsctl tunnel --api-token                                       # 권장: 토큰 입력(숨김) → 브라우저 없이 전자동
#    sudo vcf-aiopsctl tunnel --api-token --access-allow @broadcom.com --waf-ratelimit   # + Zero Trust Access·로그인 WAF 제한
#    sudo vcf-aiopsctl tunnel                                                   # 로그인 URL 출력 → 브라우저에서 krvcf.com 승인
#    sudo vcf-aiopsctl tunnel --token <TUNNEL_TOKEN>                            # 대시보드에서 만든 터널 토큰으로 연결만
#    sudo vcf-aiopsctl tunnel --status | --uninstall
#
#  옵션: --hostname aiops.krvcf.com  --name vcf-aiops  --no-app-config(앱 config.yaml 수정 안 함)
#        --access-allow "a@x.com,@corp.com"  허용 이메일·@도메인(쉼표) → Access 앱+정책 생성(API 모드)
#        --waf-ratelimit                       로그인·MFA 경로 IP당 10초 5회 초과 시 10초 차단(API 모드, Free 플랜 호환)
#  API 토큰 권한: Account › Cloudflare Tunnel › Edit,  Zone(krvcf.com) › DNS › Edit
#                 (+ --access-allow: Account › Access: Apps and Policies › Edit,  + --waf-ratelimit: Zone › Zone WAF › Edit)
#  필요 통신: 이 VM → 아웃바운드 443(api/pkg.cloudflare.com) · 7844 TCP/UDP(터널). 인바운드 포트 개방 불필요.
set -euo pipefail

HOST="aiops.krvcf.com"; NAME="vcf-aiops"; MODE="login"; API_TOKEN="${CF_API_TOKEN:-}"; TUN_TOKEN=""; APPCFG=1; ACCESS=""; WAF=0
ETC=/etc/vcf-aiops; CFG="$ETC/config.yaml"; CFD=/etc/cloudflared; SVC_UNIT=/etc/systemd/system/cloudflared.service
API="${CF_API_BASE:-https://api.cloudflare.com/client/v4}"

die() { echo "✗ $*" >&2; exit 1; }
say() { echo "▶ $*"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-token) MODE=api; if [[ -n "${2:-}" && "${2:-}" != --* ]]; then API_TOKEN="$2"; shift 2; else shift; fi ;;
    --token)     TUN_TOKEN="${2:-}"; MODE=token; shift 2 ;;
    --hostname)  HOST="${2:-}"; shift 2 ;;
    --name)      NAME="${2:-}"; shift 2 ;;
    --no-app-config) APPCFG=0; shift ;;
    --access-allow) ACCESS="${2:-}"; shift 2 ;;
    --waf-ratelimit) WAF=1; shift ;;
    --status)    MODE=status; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help)   sed -n 2,18p "$0"; exit 0 ;;
    *) die "알 수 없는 옵션: $1 (--help)" ;;
  esac
done
[[ -n "$API_TOKEN" && "$MODE" == login ]] && MODE=api
[[ -z "$ACCESS" && $WAF -eq 0 || "$MODE" == api ]] || die "--access-allow · --waf-ratelimit 는 --api-token 모드에서만 지원(대시보드에서 직접 설정 가능)"
[[ -z "$ACCESS" || "$ACCESS" =~ ^[A-Za-z0-9@._+,-]+$ ]] || die "--access-allow 형식 오류: $ACCESS"
[[ $EUID -eq 0 ]] || die "sudo 로 실행하세요"
[[ "$HOST" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "hostname 형식 오류: $HOST"
[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || die "tunnel name 형식 오류: $NAME"
export HOME=/root

# ── 어플라이언스 오리진(이 VM 의 웹 포트) ─────────────────────────────────────
PORT="$(sed -n 's/^  port:[[:space:]]*\([0-9]\+\).*/\1/p' "$CFG" 2>/dev/null | head -1)"; PORT="${PORT:-8630}"
if curl -fsk --max-time 3 "https://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then ORIGIN="https://127.0.0.1:${PORT}"
elif curl -fs --max-time 3 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then ORIGIN="http://127.0.0.1:${PORT}"
else ORIGIN="https://127.0.0.1:${PORT}"; echo "! 127.0.0.1:${PORT} 응답 없음 — vcf-aiops 서비스 상태 확인 필요(계속 진행)"; fi

# ── 상태 / 제거 ──────────────────────────────────────────────────────────────
if [[ "$MODE" == status ]]; then
  systemctl --no-pager status cloudflared 2>/dev/null | head -5 || echo "cloudflared 서비스 없음"
  command -v cloudflared >/dev/null && cloudflared --version
  [[ -f "$CFD/config.yml" ]] && { echo "--- $CFD/config.yml"; grep -v credentials "$CFD/config.yml"; }
  grep -n "public_url" "$CFG" 2>/dev/null || true
  echo -n "외부 확인 https://$HOST/healthz → "; curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 "https://$HOST/healthz" || echo "실패"
  exit 0
fi
if [[ "$MODE" == uninstall ]]; then
  command -v cloudflared >/dev/null && cloudflared service uninstall 2>/dev/null || true
  systemctl disable --now cloudflared 2>/dev/null || true
  rm -f "$CFD/config.yml" "$CFD/access.json"
  if [[ -f "$CFG.pre-cloudflare" ]]; then cp -a "$CFG.pre-cloudflare" "$CFG"; systemctl restart vcf-aiops; echo "config.yaml 복원(터널 연동 이전)"; fi
  echo "커넥터 제거 완료. Cloudflare 쪽 터널·DNS(CNAME $HOST)는 대시보드 Networks › Tunnels 에서 삭제하세요."
  exit 0
fi

# ── 1. cloudflared 설치 (Cloudflare 공식 apt 저장소) ─────────────────────────
if ! command -v cloudflared >/dev/null; then
  say "cloudflared 설치"
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
  echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cloudflared
fi
say "$(cloudflared --version | head -1)"
install -d -m 0700 "$CFD"

reinstall_service() {   # $@ = service install 인자
  if [[ -f "$SVC_UNIT" ]]; then cloudflared service uninstall >/dev/null 2>&1 || true; rm -f "$SVC_UNIT"; systemctl daemon-reload; fi
  cloudflared service install "$@"
  systemctl enable --now cloudflared >/dev/null 2>&1 || true
}

# ── 2. 인증 + 터널 + DNS ────────────────────────────────────────────────────
case "$MODE" in
api)  # 전자동: Cloudflare API 로 원격 관리 터널 생성 → ingress → DNS(CNAME, proxied) → 토큰으로 서비스 설치
  [[ -n "$API_TOKEN" ]] || { read -rsp "Cloudflare API 토큰(입력 내용 표시 안 됨): " API_TOKEN; echo; }
  [[ -n "$API_TOKEN" ]] || die "API 토큰이 비었습니다"
  say "Cloudflare API: 터널 '$NAME' · $HOST → $ORIGIN"
  TOKF="$(mktemp /root/.cf-tunnel-token.XXXXXX)"; chmod 600 "$TOKF"; trap 'shred -u "$TOKF" 2>/dev/null || rm -f "$TOKF"' EXIT
  ACCF="$CFD/access.json"
  CF_API_TOKEN="$API_TOKEN" python3 - "$API" "$HOST" "$NAME" "$ORIGIN" "$TOKF" "$ACCESS" "$WAF" "$ACCF" <<'PY'
import json, os, sys, urllib.request, urllib.error, urllib.parse
api, host, name, origin, tokf, access, waf, accf = sys.argv[1:9]
H = {"Authorization": "Bearer " + os.environ["CF_API_TOKEN"], "Content-Type": "application/json"}
class ApiError(Exception): pass
def call(method, path, body=None, soft=False):
    req = urllib.request.Request(api + path, method=method, headers=H,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r: d = json.load(r)
    except urllib.error.HTTPError as e:
        try: d = json.load(e)
        except Exception: d = {"success": False, "errors": [{"code": e.code, "message": f"HTTP {e.code}"}]}
    if not d.get("success"):
        msg = f"API {method} {path.split('?')[0]} → {[(x.get('code'), x.get('message')) for x in d.get('errors') or []]}"
        if soft: raise ApiError(msg)
        sys.exit("✗ " + msg)
    return d["result"]
# 존(zone) 찾기: hostname 의 상위 도메인을 차례로 조회 (aiops.krvcf.com → krvcf.com)
parts = host.split("."); zone = None
for i in range(len(parts) - 1):
    z = call("GET", "/zones?" + urllib.parse.urlencode({"name": ".".join(parts[i:])}))
    if z: zone = z[0]; break
if not zone: sys.exit(f"✗ {host} 의 존을 찾지 못했습니다 — 토큰의 Zone 권한/도메인 확인")
acct, zid = zone["account"]["id"], zone["id"]
print(f"  존 {zone['name']} ({zid[:8]}…) · 계정 {acct[:8]}…")
t = call("GET", f"/accounts/{acct}/cfd_tunnel?" + urllib.parse.urlencode({"name": name, "is_deleted": "false"}))
if t: tid = t[0]["id"]; print(f"  기존 터널 재사용 {name} ({tid})")
else:
    tid = call("POST", f"/accounts/{acct}/cfd_tunnel", {"name": name, "config_src": "cloudflare"})["id"]
    print(f"  터널 생성 {name} ({tid})")
ing = {"hostname": host, "service": origin}
if origin.startswith("https://"): ing["originRequest"] = {"noTLSVerify": True}   # 어플라이언스 자체 서명 인증서
call("PUT", f"/accounts/{acct}/cfd_tunnel/{tid}/configurations",
     {"config": {"ingress": [ing, {"service": "http_status:404"}]}})
print(f"  ingress {host} → {origin}")
rec = {"type": "CNAME", "name": host, "content": f"{tid}.cfargotunnel.com", "proxied": True, "comment": "VCF AIops tunnel"}
ex = call("GET", f"/zones/{zid}/dns_records?" + urllib.parse.urlencode({"name": host}))
if ex:
    if len(ex) > 1 or ex[0]["type"] != "CNAME":
        sys.exit(f"✗ {host} 에 다른 DNS 레코드가 있습니다({[r['type'] for r in ex]}) — 정리 후 재실행")
    call("PUT", f"/zones/{zid}/dns_records/{ex[0]['id']}", rec); print(f"  DNS 갱신 {host} → {tid}.cfargotunnel.com (proxied)")
else:
    call("POST", f"/zones/{zid}/dns_records", rec); print(f"  DNS 생성 {host} → {tid}.cfargotunnel.com (proxied)")
tok = call("GET", f"/accounts/{acct}/cfd_tunnel/{tid}/token")
open(tokf, "w").write(tok if isinstance(tok, str) else tok.get("token", ""))

# ── Zero Trust Access: 허용 이메일·도메인만 통과(그 외는 Cloudflare 엣지에서 차단 — 앱 로그인 화면조차 노출 안 됨)
if access:
    inc = []
    for a in [x.strip() for x in access.split(",") if x.strip()]:
        inc.append({"email_domain": {"domain": a[1:]}} if a.startswith("@") else {"email": {"email": a}})
    pol = {"name": f"VCF AIops allow ({host})", "decision": "allow", "include": inc, "session_duration": "8h"}
    try:
        ps = call("GET", f"/accounts/{acct}/access/policies?per_page=1000", soft=True) or []
        p = next((x for x in ps if x.get("name") == pol["name"]), None)
        pid = call("PUT", f"/accounts/{acct}/access/policies/{p['id']}", pol, soft=True)["id"] if p else \
              call("POST", f"/accounts/{acct}/access/policies", pol, soft=True)["id"]
        app = {"name": "VCF AIops", "domain": host, "type": "self_hosted", "session_duration": "8h",
               "app_launcher_visible": False, "http_only_cookie_attribute": True, "same_site_cookie_attribute": "lax",
               "policies": [{"id": pid, "precedence": 1}]}
        apps = call("GET", f"/accounts/{acct}/access/apps?per_page=1000", soft=True) or []
        a = next((x for x in apps if (x.get("domain") or "").rstrip("/") == host), None)
        if a: res = call("PUT", f"/accounts/{acct}/access/apps/{a['id']}", app, soft=True); print(f"  Access 앱 갱신 {host} — 허용 {access}")
        else: res = call("POST", f"/accounts/{acct}/access/apps", app, soft=True); print(f"  Access 앱 생성 {host} — 허용 {access}")
        aud = (res or {}).get("aud") or (a or {}).get("aud") or ""
        org = call("GET", f"/accounts/{acct}/access/organizations", soft=True) or {}
        team = org.get("auth_domain") or ""
        if aud and team:                     # 원본(앱)이 Access JWT 를 다시 검증하도록 기록 → 3단계에서 config.yaml server.cf_access
            with open(accf, "w") as f: json.dump({"team_domain": team, "aud": aud, "host": host}, f)
            os.chmod(accf, 0o600)
            print(f"  Access 원본 검증 정보: 팀 {team} · AUD {aud[:8]}…")
        else:
            print("  ! Access 팀 도메인·AUD 를 얻지 못해 원본 JWT 검증은 설정하지 않았습니다(대시보드 값으로 server.cf_access 직접 지정 가능)")
    except ApiError as e:
        print(f"  ! Access 설정 실패: {e}\n    → 토큰 권한(Access: Apps and Policies Edit)·Zero Trust 조직(팀 이름) 생성 여부 확인. 터널 연결은 계속 진행합니다.")

# ── WAF 레이트 리밋: 로그인·MFA 경로 — 앱 자체 제한(IP 5분 30회·계정 5회 실패 잠금) 앞단 1차 차단
if waf == "1":
    rule = {"description": f"VCF AIops login rate limit ({host})", "action": "block",
            "expression": f'(http.host eq "{host}" and http.request.uri.path in {{"/api/auth/login" "/api/auth/mfa/verify"}})',
            "ratelimit": {"characteristics": ["cf.colo.id", "ip.src"], "period": 10, "requests_per_period": 5, "mitigation_timeout": 10}}
    try:
        try: rs = call("GET", f"/zones/{zid}/rulesets/phases/http_ratelimit/entrypoint", soft=True)
        except ApiError: rs = None
        if rs is None:
            call("PUT", f"/zones/{zid}/rulesets/phases/http_ratelimit/entrypoint", {"rules": [rule]}, soft=True); print("  WAF 레이트 리밋 규칙 생성")
        else:
            r = next((x for x in rs.get("rules") or [] if x.get("description") == rule["description"]), None)
            if r: call("PATCH", f"/zones/{zid}/rulesets/{rs['id']}/rules/{r['id']}", rule, soft=True); print("  WAF 레이트 리밋 규칙 갱신")
            else: call("POST", f"/zones/{zid}/rulesets/{rs['id']}/rules", rule, soft=True); print("  WAF 레이트 리밋 규칙 추가(기존 규칙 유지)")
    except ApiError as e:
        print(f"  ! WAF 규칙 실패: {e}\n    → 토큰 권한(Zone WAF Edit) 또는 플랜의 레이트 리밋 규칙 개수 한도(Free 1개) 확인. 앱 자체 제한은 그대로 동작합니다.")
PY
  [[ -s "$TOKF" ]] || die "터널 토큰을 받지 못했습니다"
  say "cloudflared 서비스 설치(원격 관리 터널)"
  reinstall_service "$(cat "$TOKF")"
  ;;
token)  # 대시보드(Networks › Tunnels)에서 만든 터널: Public hostname = $HOST → $ORIGIN (TLS › No TLS Verify) 은 대시보드에서 지정
  [[ -n "$TUN_TOKEN" ]] || die "--token 값이 비었습니다"
  say "cloudflared 서비스 설치(대시보드 터널 토큰)"
  reinstall_service "$TUN_TOKEN"
  echo "  ※ 대시보드 Public hostname: $HOST → $ORIGIN, Additional settings › TLS › No TLS Verify = On"
  ;;
login)  # 브라우저 1회 승인: 출력되는 URL 을 아무 PC 브라우저에서 열고 krvcf.com 존 선택 → cert.pem 자동 수신
  if [[ ! -f /root/.cloudflared/cert.pem ]]; then
    say "Cloudflare 로그인 — 아래 URL 을 브라우저에서 열고 '${HOST#*.}' 를 승인하세요(승인되면 자동 진행)"
    cloudflared tunnel login
  fi
  [[ -f /root/.cloudflared/cert.pem ]] || die "인증서(cert.pem) 없음 — 로그인 미완료"
  CRED="$CFD/$NAME.json"
  TID="$(cloudflared tunnel list --name "$NAME" --output json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin) or []; print(d[0]["id"] if d else "")')"
  if [[ -z "$TID" ]]; then
    say "터널 생성 $NAME"; cloudflared tunnel create --credentials-file "$CRED" "$NAME"
    TID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["TunnelID"])' "$CRED")"
  elif [[ ! -f "$CRED" ]]; then
    say "기존 터널 $NAME ($TID) — 자격 증명 재발급"; cloudflared tunnel token --cred-file "$CRED" "$NAME"
  else say "기존 터널 재사용 $NAME ($TID)"; fi
  chmod 600 "$CRED"
  { echo "tunnel: $TID"; echo "credentials-file: $CRED"; echo "ingress:"
    echo "  - hostname: $HOST"; echo "    service: $ORIGIN"
    [[ "$ORIGIN" == https://* ]] && { echo "    originRequest:"; echo "      noTLSVerify: true"; }
    echo "  - service: http_status:404"; } > "$CFD/config.yml"
  chmod 600 "$CFD/config.yml"
  cloudflared tunnel ingress validate --config "$CFD/config.yml" >/dev/null
  say "DNS $HOST → $TID.cfargotunnel.com"
  cloudflared tunnel route dns --overwrite-dns "$NAME" "$HOST"
  say "cloudflared 서비스 설치(/etc/cloudflared/config.yml)"
  reinstall_service
  ;;
esac

# ── 3. 앱 설정: 외부 주소는 public_url, 내부 수신(에이전트·BMC push·syslog)은 기존 내부 주소 유지 ──
if [[ $APPCFG -eq 1 && -f "$CFG" ]]; then
  [[ -f "$CFG.pre-cloudflare" ]] || cp -a "$CFG" "$CFG.pre-cloudflare"
  cp -a "$CFG" "$CFG.bak-tunnel"
  CF_ENFORCE=true
  if [[ -f "$CFD/access.json" ]]; then   # 원본 검증을 켜기 전에 이 서버가 Access 공개키를 받을 수 있는지(못 받으면 외부 접속 전부 403)
    TEAMD="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("team_domain",""))' "$CFD/access.json" 2>/dev/null || true)"
    if [[ -n "$TEAMD" ]] && ! curl -fsS --max-time 8 -o /dev/null "https://$TEAMD/cdn-cgi/access/certs"; then
      CF_ENFORCE=false
      echo "! 이 서버에서 https://$TEAMD/cdn-cgi/access/certs 에 접속할 수 없어 Access 원본 검증을 '검증만(enforce: false)'으로 둡니다."
      echo "  방화벽에서 *.cloudflareaccess.com:443 을 허용한 뒤 다시 실행하세요(엣지 Access 정책은 그대로 동작)."
    fi
  fi
  export CF_ENFORCE
  python3 - "$CFG" "https://$HOST" "$CFD/access.json" <<'PY'
import json, os, re, sys
path, pub = sys.argv[1], sys.argv[2]
accf = sys.argv[3] if len(sys.argv) > 3 else ""
L = open(path, encoding="utf-8").read().split("\n")
def block(top):
    s = next((i for i, l in enumerate(L) if re.match(rf"^{top}:\s*(#.*)?$", l)), None)
    if s is None: return None, None
    e = next((i for i in range(s + 1, len(L)) if L[i] and not L[i].startswith((" ", "#"))), len(L))
    return s, e
def get(top, key):
    s, e = block(top)
    if s is None: return None, None
    for i in range(s + 1, e):
        m = re.match(rf"^  {key}:\s*(.*?)\s*(#.*)?$", L[i])
        if m: return i, m.group(1).strip("'\"")
    return None, None
def children(i):
    """i 번째 줄(  key:) 아래의 하위 줄(더 깊은 들여쓰기·빈 줄) 끝 위치 — 블록형 값(목록·맵)을 통째로 바꾸기 위해"""
    j = i + 1
    while j < len(L) and (L[j].startswith("    ") or (L[j].strip() == "" and j + 1 < len(L) and L[j + 1].startswith("    "))):
        j += 1
    return j
def block_text(top, key):
    i, _ = get(top, key)
    return "" if i is None else "\n".join(L[i:children(i)])
def put(top, key, val, note):
    i, _ = get(top, key)
    line = f"  {key}: {val}   # {note}"
    if i is not None: L[i:children(i)] = [line]; return
    s, _ = block(top)
    if s is None: L.extend([f"{top}:", line])
    else: L.insert(s + 1, line)
from urllib.parse import urlparse
_, old = get("server", "public_url")
old = old or ""
oh = urlparse(old).hostname or ""
if old and old != pub:
    _, ag = get("agents", "public_url")
    if not ag: put("agents", "public_url", old, "내부 수신 주소(에이전트·BMC push) — Cloudflare 경유 아님")
    _, ah = get("syslog", "advertise_host")
    if not ah and oh: put("syslog", "advertise_host", oh, "syslog 는 터널 대상 아님 — 내부 주소")
put("server", "public_url", pub, "Cloudflare Tunnel 외부 주소(알림·ITSM 링크)")
ph = urlparse(pub).hostname
bt = block_text("server", "external_hosts")
cur = [x.strip().strip("'\"") for x in re.findall(r"^\s*-\s*(\S+)", bt, re.M)] or \
      [x.strip().strip("'\"") for x in (get("server", "external_hosts")[1] or "").strip("[]").split(",") if x.strip()]
if ph not in cur: cur.append(ph)
put("server", "external_hosts", "[" + ", ".join(cur) + "]", "외부 이름 — 에이전트·Redfish·HA·수집·메트릭·MCP 경로 404")
enf_env = os.environ.get("CF_ENFORCE", "true")
if accf and os.path.isfile(accf):
    try:
        acc = json.load(open(accf))
        host_ok = acc.get("host", urlparse(pub).hostname) == urlparse(pub).hostname
        if host_ok and re.fullmatch(r"[A-Za-z0-9.-]+", acc.get("team_domain", "")) and re.fullmatch(r"[A-Za-z0-9]+", acc.get("aud", "")):
            prev_blk = block_text("server", "cf_access")
            enforce = "false" if (re.search(r"enforce:\s*false", prev_blk) or enf_env != "true") else "true"
            put("server", "cf_access", "{team_domain: %s, aud: %s, enforce: %s}" % (acc["team_domain"], acc["aud"], enforce),
                "Cloudflare Access JWT 원본 검증 — 토큰 없는 외부 요청 403")
            print(f"  cf_access: {acc['team_domain']} (enforce={enforce})")
        elif not host_ok:
            print(f"  ! access.json 은 다른 이름({acc.get('host')}) 용 — cf_access 는 바꾸지 않음")
    except (OSError, ValueError) as e:
        print(f"  ! access.json 읽기 실패: {e}")
_, tp = get("server", "trusted_proxies")
if not tp: put("server", "trusted_proxies", "127.0.0.1", "cloudflared(로컬) X-Forwarded-For 신뢰")
open(path, "w", encoding="utf-8").write("\n".join(L))
print(f"  public_url: {old or '(없음)'} → {pub}")
PY
  # 고친 설정이 YAML 로 읽히는지 확인 — 깨졌으면 되돌림(서비스가 기동 못 하는 일 방지)
  PYV=/opt/vcf-aiops/venv/bin/python; [[ -x "$PYV" ]] || PYV=python3
  if "$PYV" -c 'import sys, yaml; d = yaml.safe_load(open(sys.argv[1])); assert isinstance(d, dict) and isinstance(d.get("server"), dict)' "$CFG" 2>/dev/null \
     || ! "$PYV" -c 'import yaml' 2>/dev/null; then
    rm -f "$CFG.bak-tunnel"
    systemctl restart vcf-aiops
  else
    cp -a "$CFG.bak-tunnel" "$CFG"; rm -f "$CFG.bak-tunnel"
    die "config.yaml 수정 결과가 YAML 형식이 아니어서 원래대로 되돌렸습니다 — server 블록을 직접 확인하세요"
  fi
fi

# ── 4. 확인 ─────────────────────────────────────────────────────────────────
say "연결 확인"
ok=0; for i in $(seq 1 30); do systemctl is-active --quiet cloudflared && { ok=1; break; }; sleep 2; done
[[ $ok -eq 1 ]] || die "cloudflared 서비스 기동 실패 — journalctl -u cloudflared -n 50"
code=000; for i in $(seq 1 20); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$HOST/healthz" || true)"
  [[ "$code" == 200 ]] && break; sleep 3; done
if [[ "$code" == 200 ]]; then echo "✓ https://$HOST 연결됨 (healthz 200)"
else echo "! https://$HOST/healthz → $code (DNS 전파 대기 중일 수 있음; Access 정책이 있으면 302/403 정상) — journalctl -u cloudflared -n 50"; fi
[[ -n "$ACCESS" ]] || echo "※ 보안: --access-allow 로 Zero Trust Access 를 켜거나 대시보드 Access › Applications 에서 $HOST 를 등록하세요(앱 로그인 앞단 관문)."
