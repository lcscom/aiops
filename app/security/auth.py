"""인증·권한(RBAC)·세션·API 토큰.

역할      viewer(조회) · auditor(조회+감사로그) · operator(처리·조치요청) · admin(설정·승인·사용자)
세션      서버측 세션 + HttpOnly·SameSite=Strict 쿠키, 유휴 타임아웃(사용자 입력 기준), 절대 만료, 동시접속 제한(옵션)
계정      로컬(PBKDF2) / AD·LDAP(그룹→역할), 실패 N회 잠금, 비밀번호 만료·이력, 장기 미사용 잠금, 최초 로그인 시 변경 강제
CSRF      변경 요청은 X-Requested-With: aiops 헤더 필수(+SameSite=Strict)
API 토큰  연동용(ingest·metrics·read) — SHA-256 해시 저장, 만료일, 허용 IP(allow_ips: CIDR 목록)
MFA       TOTP(RFC 6238) 2단계 — auth.mfa.required_roles 역할은 등록 전까지 화면 사용 제한, 복구 코드 8개
SSO       OIDC(Authorization Code + PKCE) — security/oidc.py, 그룹→역할 매핑, source='oidc'
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import ipaddress
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import ldap_auth
from .audit import AuditLog
from .mfa import Mfa
from .passwords import check_policy, generate_password, hash_password, verify_password

ROLES = ["viewer", "auditor", "operator", "admin"]
ROLE_LABEL = {"viewer": "조회자", "auditor": "감사자", "operator": "운영자", "admin": "관리자"}
PERMS: dict[str, set[str]] = {
    "view": {"viewer", "auditor", "operator", "admin"},
    "audit.view": {"auditor", "admin"},
    "operate": {"operator", "admin"},          # 확인 처리·재분석·인시던트 처리·사일런스·리포트 생성·연결 테스트
    "action.request": {"operator", "admin"},
    "action.approve": {"admin"},
    "settings": {"admin"},                     # 커넥터·알림·규칙·RAG 팩·유지보수 창·백업
    "users": {"admin"},
    "system": {"admin"},                       # 패치 업로드·적용·롤백
}

# (메서드, 경로 정규식, 권한) — 위에서부터 첫 일치. 미일치 /api/* 는 GET=view, 그 외=settings(안전 기본값)
ROUTE_RULES: list[tuple[str, str, str]] = [
    ("POST", r"^/api/auth/oidc/test$", "settings"),
    ("*", r"^/api/auth/", "view"),                       # 본인 세션·비밀번호 변경·하트비트·MFA 등록
    ("GET", r"^/api/audit", "audit.view"),
    ("GET", r"^/api/posture", "audit.view"), ("POST", r"^/api/posture/run$", "settings"),   # 2.22.0 보안 상태 점검
    ("GET", r"^/api/perf/", "view"), ("POST", r"^/api/perf/explain$", "operate"), ("POST", r"^/api/perf/rules/preview$", "settings"),
    ("*", r"^/api/perf/rules", "settings"),                                                  # 2.25.0 성능 감시 규칙                                                        # 2.23.0 호스트·VM 성능
    ("GET", r"^/api/ingest-gate$", "view"), ("*", r"^/api/ingest-gate", "settings"),          # 2.22.1 수집 일시정지
    ("GET", r"^/api/support/", "view"), ("PUT", r"^/api/support/profile$", "settings"), ("*", r"^/api/support/", "operate"),   # 2.11.0 지원 요청
    ("GET", r"^/api/readiness/", "view"), ("POST", r"^/api/readiness/scans(/[^/]+/cancel)?$", "operate"), ("DELETE", r"^/api/readiness/scans/", "operate"),
    ("*", r"^/api/readiness/", "settings"),   # 2.14.0 준비도: 스캔=operate, 설정·HCL·BCG=settings
    ("GET", r"^/api/hostdiag/", "view"), ("*", r"^/api/hostdiag/", "operate"),
    ("GET", r"^/api/segtraffic", "view"), ("*", r"^/api/segtraffic", "operate"),          # 2.21.0 세그먼트 트래픽: 조회 view, AI operate   # 2.18.0 호스트 분석: 조회 view, AI operate
    ("GET", r"^/api/license/reveal/", "operate"), ("PUT", r"^/api/license/settings$", "settings"),
    ("GET", r"^/api/license/", "view"), ("*", r"^/api/license/", "operate"),   # 2.16.0 라이선스: 조회 view, 키 전체 보기·업로드·할당·수집 operate, 설정 settings
    ("GET", r"^/api/rvtools(/|$)", "view"), ("*", r"^/api/rvtools(/|$)", "operate"),   # 2.15.0 RVTools: 조회=view, 업로드·AI·재분석·삭제=operate
    ("GET", r"^/api/cloudcost/", "view"), ("*", r"^/api/cloudcost/", "settings"),   # 2.13.0 비용 비교(설정·단가 변경 = settings)
    ("GET", r"^/api/forwarding", "operate"),          # 전 제품 설정 조회(부하·노출) — 운영자 이상
    ("*", r"^/api/users", "users"), ("*", r"^/api/tokens", "users"),
    ("POST", r"^/api/anomalies/[^/]+/(ack|analyze)$", "operate"),
    ("POST", r"^/api/anomalies/[^/]+/silence$", "operate"),
    ("POST", r"^/api/incidents/[^/]+/(assign|status|comment|rca|investigate|itsm)$", "operate"),
    ("POST", r"^/api/incidents$", "operate"),
    ("POST", r"^/api/actions/[^/]+/approve$", "action.approve"),
    ("POST", r"^/api/actions/[^/]+/reject$", "action.approve"),
    ("POST", r"^/api/actions", "action.request"),
    ("POST", r"^/api/connectors/provision$", "settings"), ("POST", r"^/api/vks/discover$", "operate"), ("POST", r"^/api/vcenter/health/run$", "operate"), ("POST", r"^/api/vcenter/bestpractice/run$", "operate"), ("POST", r"^/api/dr/run$", "operate"), ("POST", r"^/api/mobile/(pair/start|test)$", "view"), ("*", r"^/api/mobile/devices/\d+$", "view"),
    ("PUT", r"^/api/mobile/settings$", "settings"),
    ("POST", r"^/api/connectors/[^/]+/(test|test-event)$", "operate"), ("POST", r"^/api/connectors/test-all$", "operate"),
    ("POST", r"^/api/alerts/test$", "operate"), ("POST", r"^/api/outbox/retry$", "operate"),
    ("POST", r"^/api/reports/generate$", "operate"),
    ("POST", r"^/api/opsmetrics/collect$", "operate"),
    ("POST", r"^/api/chat$", "view"), ("POST", r"^/api/isvara/ask$", "view"),
    ("GET", r"^/api/rag/search", "view"),
    ("GET", r"^/api/knowledge", "view"), ("POST", r"^/api/knowledge/feedback$", "operate"), ("*", r"^/api/knowledge", "settings"),
    ("*", r"^/api/rag", "settings"),
    ("*", r"^/api/settings", "settings"), ("*", r"^/api/maintenance", "settings"),
    ("POST", r"^/api/silences", "operate"), ("DELETE", r"^/api/silences", "operate"),
    ("*", r"^/api/backup", "settings"),
    ("GET", r"^/api/system/version$", "view"), ("*", r"^/api/system/", "system"),
    ("GET", r"^/api/monitors", "view"), ("POST", r"^/api/monitors/preview$", "operate"), ("*", r"^/api/monitors", "operate"),
    ("GET", r"^/api/security/", "view"), ("PUT", r"^/api/security/fortigate/config$", "settings"),
    ("GET", r"^/api/ai(/|$)", "view"), ("POST", r"^/api/ai/providers/test$", "settings"), ("POST", r"^/api/ai/", "operate"),
    ("GET", r"^/api/vm/", "view"),
    ("GET", r"^/api/billing/", "view"), ("POST", r"^/api/billing/sample$", "operate"), ("*", r"^/api/billing/", "settings"),
    ("GET", r"^/api/capacity", "view"), ("POST", r"^/api/capacity/sample$", "operate"), ("POST", r"^/api/capacity/whatif$", "view"), ("POST", r"^/api/capacity/whatif/(move|dr)$", "view"), ("POST", r"^/api/capacity/whatif/scenarios$", "operate"), ("DELETE", r"^/api/capacity/whatif/scenarios/\d+$", "operate"), ("POST", r"^/api/capacity/specs$", "operate"), ("DELETE", r"^/api/capacity/specs/\d+$", "operate"),
    ("GET", r"^/api/lifecycle", "view"), ("POST", r"^/api/lifecycle/(certs|drift)/scan$", "operate"), ("POST", r"^/api/lifecycle/drift/baseline$", "operate"),
    ("DELETE", r"^/api/lifecycle/drift/baseline/\d+$", "operate"), ("PUT", r"^/api/lifecycle/versions/table$", "settings"), ("DELETE", r"^/api/lifecycle/versions/table$", "settings"),
    ("PUT", r"^/api/lifecycle/certs/settings$", "settings"),
    ("GET", r"^/api/savings", "view"), ("PUT", r"^/api/savings/prices$", "operate"), ("POST", r"^/api/change/review$", "view"),
    ("GET", r"^/api/aiops/", "view"), ("POST", r"^/api/aiops/(feedback|precursors/learn)$", "operate"),
    ("GET", r"^/api/vuln", "view"), ("POST", r"^/api/vuln/run$", "operate"), ("PUT", r"^/api/vuln/settings$", "settings"), ("POST", r"^/api/vuln/kev$", "operate"),
    ("POST", r"^/api/capacity/esa$", "view"),
    ("GET", r"^/api/checkbot", "view"), ("POST", r"^/api/checkbot/run$", "operate"), ("POST", r"^/api/checkbot/simulate$", "view"), ("POST", r"^/api/checkbot/refresh$", "view"),
    ("POST", r"^/api/checkbot/library/run$", "view"), ("POST", r"^/api/checkbot/library/snapshot$", "operate"),
    ("GET", r"^/api/assessment", "view"), ("POST", r"^/api/assessment/run$", "operate"), ("*", r"^/api/assessment", "settings"),
]
ANON = {"user": "anonymous", "role": "admin", "display": "anonymous"}
PUBLIC = re.compile(r"^/(login|healthz|readyz|robots\.txt|api/ha/peer|agents/[A-Za-z0-9_.-]+|api/redfish/events/[A-Za-z0-9_-]+|favicon\.ico|static/(login\.(js|css|html)|style\.css|i18n(-en)?\.js|fonts/.*)|api/auth/(login|config|mfa/verify|oidc/start|oidc/callback)|share/sr/[A-Za-z0-9_-]{30,64}(/(report\.pdf|logs\.zip))?)$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, display TEXT, email TEXT, role TEXT, source TEXT, pw_hash TEXT, pw_history TEXT,
  pw_changed REAL, must_change INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0,
  disabled INTEGER DEFAULT 0, created REAL, last_login REAL, last_ip TEXT, prev_login REAL, prev_ip TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT UNIQUE, prefix TEXT, scopes TEXT, created_by TEXT,
  created REAL, expires REAL, last_used REAL, revoked INTEGER DEFAULT 0, allow_ips TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY, data TEXT, last REAL);
"""
MIGRATE = ["ALTER TABLE api_tokens ADD COLUMN allow_ips TEXT DEFAULT ''"]


def ip_allowed(ip: str, allow: str) -> bool:
    """allow_ips: 쉼표·공백 구분 IP/CIDR 목록(빈 값=제한 없음)"""
    items = [x.strip() for x in re.split(r"[,\s]+", allow or "") if x.strip()]
    if not items:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for it in items:
        try:
            if a in ipaddress.ip_network(it, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def bad_path(path: str) -> bool:
    """2.30.0 라우팅 경로(scope["path"], 디코딩된 값)가 비정상인지 — '..' 구간·'//'·역슬래시·제어문자, /api/ 밖에서는 '?'·'#' 도.
    (request.url.path 는 디코딩된 '?' 뒤를 잘라 판단이 라우팅과 어긋남 → 미들웨어는 scope 경로로 판단하고 이런 경로는 400)"""
    if not path.startswith("/") or "\\" in path or "//" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return True
    if any(seg == ".." for seg in path.split("/")):
        return True
    return ("?" in path or "#" in path) and not path.startswith("/api/")


_DUMMY_HASH = ""


def _dummy_hash() -> str:
    """없는 계정도 로컬 계정과 같은 PBKDF2 비용을 쓰게 하는 더미 해시(응답 시간으로 계정 유무 구분 방지)"""
    global _DUMMY_HASH
    if not _DUMMY_HASH:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    return _DUMMY_HASH


class AuthManager:
    def __init__(self, store, cfg: dict, audit: AuditLog, data_dir: str):
        self.store = store
        self.cfg = cfg
        self.audit = audit
        self.data_dir = Path(data_dir)
        store.schema(SCHEMA)
        for m in MIGRATE:
            try:
                store.schema(m)
            except Exception:  # noqa: BLE001  (이미 있는 컬럼)
                pass
        self.sessions: dict[str, dict] = {}
        self.mfa = Mfa(store, cfg.get("mfa") or {})
        self._mfa_pending: dict[str, dict] = {}   # 1단계 통과 → 2단계 대기(5분)
        self.oidc_cfg = cfg.get("oidc") or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.idle = float(cfg.get("session_idle_minutes", 10)) * 60
        self.absolute = float(cfg.get("session_absolute_hours", 12)) * 3600
        # 관제 화면(월 디스플레이) 전용 계정: 유휴 만료 없음·조회자 권한 고정·별도 절대 만료
        self.kiosk_users = {str(u).lower() for u in (cfg.get("kiosk_users") or [])}
        self.kiosk_absolute = float(cfg.get("kiosk_absolute_hours", 168)) * 3600
        self.pw_policy = cfg.get("password") or {}
        self.ldap_cfg = cfg.get("ldap") or {}
        self._rate: dict[str, list[float]] = {}
        self._wrate: dict[str, list[float]] = {}
        self._ghost: dict[str, tuple[int, float]] = {}   # 2.30.0 없는 계정의 실패 횟수·잠금(메모리) — 실제 계정과 같은 응답을 주기 위함
        self._rl_n = 0                                    # 로그인 속도 제한 감사 표본(20건에 1건)
        self._load_sessions()                           # 재시작·패치 뒤에도 로그인 유지(2.2)

    # ------------------------------------------------------------------ 세션 영속화(재시작·패치 뒤 유지)
    def _load_sessions(self) -> None:
        try:
            rows = self.store._conn.execute("SELECT sid, data, last FROM sessions").fetchall()
        except Exception:  # noqa: BLE001
            return
        now, n, stale = time.time(), 0, []
        for sid, data, last in rows:
            try:
                s = json.loads(data)
            except Exception:  # noqa: BLE001
                stale.append(sid)
                continue
            s["last"] = float(last) if last else float(s.get("last", 0))     # 유휴 시각은 60초마다 갱신되는 열이 기준
            absolute = self.kiosk_absolute if s.get("kiosk") else self.absolute
            if (now - s["last"] > self.idle and not s.get("kiosk")) or now - float(s.get("created", 0)) > absolute:
                stale.append(sid)
                continue
            self.sessions[sid] = s
            n += 1
        if stale:
            try:
                self.store._conn.executemany("DELETE FROM sessions WHERE sid=?", [(x,) for x in stale])
                self.store._conn.commit()
            except Exception:  # noqa: BLE001
                pass
        if n:
            print(f"[auth] 세션 {n}개 복원(만료 {len(stale)}개 정리)", flush=True)

    def _persist(self, sid: str) -> None:
        s = self.sessions.get(sid)
        if not s:
            return
        data = json.dumps({k: v for k, v in s.items() if k != "sid"}, ensure_ascii=False, default=str)
        asyncio.ensure_future(self.store.x("INSERT INTO sessions(sid,data,last) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET data=excluded.data, last=excluded.last",
                                           (sid, data, s.get("last", time.time()))))

    def _forget(self, sid: str) -> None:
        asyncio.ensure_future(self.store.x("DELETE FROM sessions WHERE sid=?", (sid,)))

    def drop_session(self, sid: str) -> dict | None:
        s = self.sessions.pop(sid, None)
        if s is not None:
            self._forget(sid)
        return s

    async def persist_loop(self, beat=lambda: None) -> None:
        """유휴 시각(last)을 60초마다 한꺼번에 저장 — 요청마다 쓰지 않아 DB 부하 없음"""
        while True:
            await asyncio.sleep(60)
            beat()
            try:
                now = time.time()
                rows = [(sid, s.get("last", now)) for sid, s in self.sessions.items()]
                if rows:
                    await self.store.xm("UPDATE sessions SET last=? WHERE sid=?", [(last, sid) for sid, last in rows])
                await self.store.x("DELETE FROM sessions WHERE last < ?", (now - max(self.absolute, self.kiosk_absolute),))
                self._mfa_pending = {k: v for k, v in self._mfa_pending.items() if v["exp"] > now}
            except Exception as e:  # noqa: BLE001
                print(f"[auth] 세션 저장 오류: {e}", flush=True)

    # ------------------------------------------------------------------ 부트스트랩
    async def bootstrap(self) -> None:
        """사용자가 없으면 로컬 관리자 생성 → 초기 비밀번호를 data/initial-admin.txt 에만 기록(최초 로그인 시 변경 강제)."""
        if not self.enabled:
            return
        row = await self.store.q1("SELECT COUNT(*) AS n FROM users")
        if row and row["n"]:
            return
        pw = os.environ.get("AIOPS_ADMIN_PASSWORD") or generate_password()
        await self._upsert_local("admin", "로컬 관리자", "admin", pw, must_change=True)
        if not os.environ.get("AIOPS_ADMIN_PASSWORD"):
            p = self.data_dir / "initial-admin.txt"
            p.write_text(f"username: admin\npassword: {pw}\n# 최초 로그인 후 비밀번호 변경이 강제됩니다. 확인 후 이 파일을 삭제하세요.\n",
                         encoding="utf-8")
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
            print(f"[auth] 초기 관리자 계정 생성 — 비밀번호: {p}", flush=True)
        await self.audit.log("user.bootstrap", target="admin", detail={"source": "local"})

    async def _upsert_local(self, username: str, display: str, role: str, pw: str, must_change: bool = True,
                            email: str = "") -> None:
        h = await asyncio.to_thread(hash_password, pw)
        await self.store.x(
            "INSERT INTO users(username,display,email,role,source,pw_hash,pw_history,pw_changed,must_change,created) "
            "VALUES(?,?,?,?, 'local', ?, ?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET display=excluded.display, "
            "role=excluded.role, pw_hash=excluded.pw_hash, pw_history=excluded.pw_history, pw_changed=excluded.pw_changed, "
            "must_change=excluded.must_change, failed=0, locked_until=0",
            (username, display, email, role, h, json.dumps([h]), time.time(), int(must_change), time.time()))

    # ------------------------------------------------------------------ 로그인
    def _rate_ok(self, ip: str) -> bool:
        now = time.time()
        q = [t for t in self._rate.get(ip, []) if now - t < 300]
        q.append(now)
        self._rate[ip] = q
        return len(q) <= int(self.cfg.get("rate_limit_per_5min", 30))

    def _write_ok(self, sid: str) -> bool:
        """세션당 변경 요청(POST·PUT·DELETE) 분당 상한(auth.write_rate_per_min, 0=무제한) — 스크립트 폭주·CSRF 우회 시도 완충"""
        lim = int(self.cfg.get("write_rate_per_min", 240))
        if not lim:
            return True
        now = time.time()
        q = [t for t in self._wrate.get(sid, []) if now - t < 60]
        q.append(now)
        self._wrate[sid] = q
        if len(self._wrate) > 5000:
            self._wrate = {k: v for k, v in self._wrate.items() if v and now - v[-1] < 60}
        return len(q) <= lim

    async def login(self, username: str, password: str, ip: str, ua: str) -> dict:
        username = (username or "").strip()[:128]
        uname = (username.split("\\")[-1].split("@")[0].lower() if username else "")[:64]   # 2.30.0 길이 상한(감사·DB 키)
        if not self._rate_ok(ip):
            self._rl_n += 1
            if self._rl_n % 20 == 1:              # 폭주 시 감사로그 과다 방지(20건에 1건)
                await self.audit.log("auth.login", user=uname or "-", ip=ip, result="rate_limited", detail={"count": self._rl_n})
            raise HTTPException(429, "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.")
        u = await self.store.q1("SELECT * FROM users WHERE username = ?", (uname,))
        now = time.time()
        # 없는 계정도 실제 계정과 같은 잠금 응답(계정 유무 추측 방지) — 실패 횟수·잠금 시각을 메모리에 둔다
        g_failed, g_until = (0, 0.0) if u else self._ghost.get(uname, (0, 0.0))
        locked_until = (u["locked_until"] or 0) if u else g_until
        if locked_until > now:
            await self.audit.log("auth.login", user=uname or "-", ip=ip, result="locked" if u else "fail")
            mins = int((locked_until - now) // 60) + 1
            raise HTTPException(423, f"계정이 잠겨 있습니다. {mins}분 후 다시 시도하거나 관리자에게 문의하세요.")

        ok, profile, reason = False, None, "아이디 또는 비밀번호가 올바르지 않습니다."
        if u and u["source"] == "local":
            ok = await asyncio.to_thread(verify_password, password or "", u["pw_hash"] or "")
        elif self.ldap_cfg.get("enabled") and uname:
            try:
                profile = await asyncio.to_thread(ldap_auth.authenticate, self.ldap_cfg, username, password)
                ok = True
            except ldap_auth.LdapError as e:
                # 2.36.0 — 디렉터리 내부 사정(사용자 없음·그룹 매핑 없음·예외 종류)은 화면에 보이지 않게(계정 존재 여부 추측 방지). 자세한 내용은 서버 로그에만
                msg = str(e)
                print(f"[auth] LDAP 로그인 실패({uname}): {msg}", flush=True)
                reason = ("디렉터리 서버에 연결할 수 없습니다 — 관리자에게 문의하세요." if msg.startswith(("디렉터리 서버 연결 실패", "ldap.servers"))
                          else "아이디 또는 비밀번호가 올바르지 않습니다.")
        else:
            await asyncio.to_thread(verify_password, password or "", _dummy_hash())   # 없는 계정도 같은 계산 비용
        if not ok:
            prev = (u["failed"] or 0) if u else g_failed
            if locked_until and locked_until <= now:
                prev = 0                          # 잠금이 풀린 뒤에는 처음부터 다시 센다(1회 오류로 재잠금 방지)
            failed = prev + 1
            lock = int(self.cfg.get("lockout_threshold", 5))
            until = now + float(self.cfg.get("lockout_minutes", 30)) * 60 if failed >= lock else 0
            if u:
                await self.store.x("UPDATE users SET failed=?, locked_until=? WHERE username=?", (failed, until, uname))
            elif uname:
                if len(self._ghost) > 2000:
                    self._ghost = {k: v for k, v in self._ghost.items() if v[1] > now}
                    if len(self._ghost) > 2000:
                        self._ghost = {}
                self._ghost[uname] = (failed, until)
            if until:
                if u:
                    await self.audit.log("auth.lockout", user=uname, ip=ip, result="locked", detail={"failed": failed})
                reason = f"비밀번호 {failed}회 오류로 계정이 잠겼습니다."
            elif self.cfg.get("show_remaining_attempts", False):
                reason += f" (남은 시도 {lock - failed}회)"
            await self.audit.log("auth.login", user=uname or "-", ip=ip, result="disabled" if u and u["disabled"] else "fail")
            await asyncio.sleep(0.6)              # 무차별 대입 지연
            raise HTTPException(401, reason)
        self._ghost.pop(uname, None)
        if u and u["disabled"]:                   # 비활성 안내는 비밀번호가 맞을 때만(계정 상태 노출 방지)
            await self.audit.log("auth.login", user=uname, ip=ip, result="disabled")
            raise HTTPException(403, "비활성화된 계정입니다. 관리자에게 문의하세요.")

        if profile:                               # LDAP 사용자 동기화(역할은 로그인마다 그룹으로 재계산)
            await self.store.x(
                "INSERT INTO users(username,display,email,role,source,created) VALUES(?,?,?,?, 'ldap', ?) "
                "ON CONFLICT(username) DO UPDATE SET display=excluded.display, email=excluded.email, role=excluded.role, source='ldap'",
                (uname, profile["display"], profile["email"], profile["role"], now))
            u = await self.store.q1("SELECT * FROM users WHERE username = ?", (uname,))
            if u["disabled"]:
                raise HTTPException(403, "비활성화된 계정입니다.")

        dormant = float(self.cfg.get("dormant_days", 90))
        if dormant and u["last_login"] and now - u["last_login"] > dormant * 86400 and u["role"] != "admin":
            await self.store.x("UPDATE users SET disabled=1 WHERE username=?", (uname,))
            await self.audit.log("auth.dormant_disable", user=uname, ip=ip, result="disabled")
            raise HTTPException(403, f"{int(dormant)}일 이상 미사용으로 잠긴 계정입니다. 관리자에게 문의하세요.")

        must_change = bool(u["must_change"])
        exp = float(self.pw_policy.get("expire_days", 90))
        if u["source"] == "local" and exp and u["pw_changed"] and now - u["pw_changed"] > exp * 86400:
            must_change = True

        if self.mfa.enabled and (await self.mfa.status(uname))["enrolled"]:
            tok = secrets.token_urlsafe(32)
            self._mfa_pending = {k: v for k, v in self._mfa_pending.items() if v["exp"] > now}
            self._mfa_pending[tok] = {"user": uname, "ip": ip, "ua": ua, "must_change": must_change, "exp": now + 300, "tries": 0}
            await self.audit.log("auth.login", user=uname, ip=ip, result="mfa_pending", detail={"source": u["source"]})
            return {"mfa_required": True, "mfa_token": tok, "user": uname}
        return await self._open_session(u, ip, ua, must_change, method="password")

    async def _open_session(self, u: dict, ip: str, ua: str, must_change: bool, method: str = "password") -> dict:
        now = time.time()
        uname = u["username"]
        if self.cfg.get("single_session", False):
            for sid in [s for s, v in self.sessions.items() if v["user"] == uname]:
                self.drop_session(sid)
        sid = secrets.token_urlsafe(32)
        kiosk = uname in self.kiosk_users
        enrolled = (await self.mfa.status(uname))["enrolled"] if self.mfa.enabled else False
        self.sessions[sid] = {"user": uname, "role": "viewer" if kiosk else u["role"], "kiosk": kiosk,
                              "display": u["display"] or uname, "created": now,
                              "last": now, "ip": ip, "ua": ua[:200], "must_change": must_change, "source": u["source"],
                              "mfa": method.startswith("mfa-"), "auth_method": method,
                              "must_enroll_mfa": self.mfa.must_enroll("viewer" if kiosk else u["role"], enrolled)}
        self._persist(sid)
        await self.store.x("UPDATE users SET failed=0, locked_until=0, prev_login=last_login, prev_ip=last_ip, "
                           "last_login=?, last_ip=? WHERE username=?", (now, ip, uname))
        await self.audit.log("auth.login", user=uname, role=self.sessions[sid]["role"], ip=ip, result="ok",
                             detail={"source": u["source"], "must_change": must_change, "kiosk": kiosk, "method": method})
        return {"sid": sid, "user": uname, "display": u["display"], "role": self.sessions[sid]["role"], "kiosk": kiosk,
                "must_change": must_change, "must_enroll_mfa": self.sessions[sid]["must_enroll_mfa"],
                "prev_login": u["last_login"], "prev_ip": u["last_ip"]}

    async def mfa_verify(self, token: str, code: str, ip: str) -> dict:
        """로그인 2단계 — 1단계에서 받은 mfa_token + TOTP/복구 코드 → 세션"""
        p = self._mfa_pending.get(token or "")
        if not p or p["exp"] < time.time():
            self._mfa_pending.pop(token or "", None)
            raise HTTPException(401, "2단계 인증 시간이 지났습니다. 처음부터 다시 로그인하세요.")
        p["tries"] += 1
        try:
            how = await self.mfa.verify(p["user"], code)
        except ValueError as e:
            if await self._count_failure(p["user"], ip, "mfa"):       # 2.30.0 MFA 실패도 비밀번호 실패처럼 계정 잠금
                raise HTTPException(401, "인증 코드 오류가 반복되어 계정이 잠겼습니다. 처음부터 다시 로그인해야 합니다.")
            if p["tries"] >= 5:
                self._mfa_pending.pop(token, None)
                await self.audit.log("auth.mfa", user=p["user"], ip=ip, result="fail", detail={"exhausted": True})
                raise HTTPException(401, "인증 코드 오류가 반복되어 처음부터 다시 로그인해야 합니다.")
            await self.audit.log("auth.mfa", user=p["user"], ip=ip, result="fail")
            await asyncio.sleep(0.6)
            raise HTTPException(401, str(e))
        self._mfa_pending.pop(token, None)
        u = await self.store.q1("SELECT * FROM users WHERE username=?", (p["user"],))
        if not u or u["disabled"]:
            raise HTTPException(403, "비활성화된 계정입니다.")
        await self.audit.log("auth.mfa", user=p["user"], ip=ip, result="ok", detail={"how": how})
        res = await self._open_session(u, p["ip"], p["ua"], p["must_change"], method="mfa-" + how)
        res["recovery_used"] = how == "recovery"
        return res

    async def _count_failure(self, uname: str, ip: str, what: str) -> bool:
        """인증 실패 1회 누적(MFA·재인증) — 임계 도달이면 계정 잠금·대기 중인 2단계 토큰 폐기 후 True"""
        u = await self.store.q1("SELECT failed, locked_until FROM users WHERE username=?", (uname,))
        if not u:
            return False
        now = time.time()
        failed = (0 if u["locked_until"] and u["locked_until"] <= now else (u["failed"] or 0)) + 1
        until = now + float(self.cfg.get("lockout_minutes", 30)) * 60 if failed >= int(self.cfg.get("lockout_threshold", 5)) else 0
        await self.store.x("UPDATE users SET failed=?, locked_until=? WHERE username=?", (failed, until, uname))
        if until:
            self._mfa_pending = {k: v for k, v in self._mfa_pending.items() if v["user"] != uname}
            await self.audit.log("auth.lockout", user=uname, ip=ip, result="locked", detail={"failed": failed, "by": what})
        return bool(until)

    async def sso_login(self, uname: str, display: str, email: str, role: str, ip: str, ua: str) -> dict:
        """OIDC 콜백 — 사용자 upsert(source=oidc, 역할은 로그인마다 클레임으로 재계산) 후 세션"""
        now = time.time()
        ex = await self.store.q1("SELECT source FROM users WHERE username=?", (uname,))
        if ex and ex["source"] != "oidc":         # 2.30.0 같은 이름의 로컬·LDAP 계정을 SSO 가 덮어쓰지(탈취) 못하게
            await self.audit.log("auth.sso", user=uname, ip=ip, result="conflict", detail={"existing_source": ex["source"], "claimed_role": role})
            raise HTTPException(409, "같은 아이디의 로컬·AD 계정이 이미 있어 SSO 로 로그인할 수 없습니다. 관리자에게 문의하세요.")
        await self.store.x(
            "INSERT INTO users(username,display,email,role,source,created) VALUES(?,?,?,?, 'oidc', ?) "
            "ON CONFLICT(username) DO UPDATE SET display=excluded.display, email=excluded.email, role=excluded.role, source='oidc'",
            (uname, display or uname, email or "", role, now))
        u = await self.store.q1("SELECT * FROM users WHERE username=?", (uname,))
        if u["disabled"]:
            await self.audit.log("auth.login", user=uname, ip=ip, result="disabled", detail={"method": "oidc"})
            raise HTTPException(403, "비활성화된 계정입니다. 관리자에게 문의하세요.")
        if self.mfa.enabled and (await self.mfa.status(uname))["enrolled"]:
            tok = secrets.token_urlsafe(32)
            self._mfa_pending[tok] = {"user": uname, "ip": ip, "ua": ua, "must_change": False, "exp": now + 300, "tries": 0}
            return {"mfa_required": True, "mfa_token": tok, "user": uname}
        return await self._open_session(u, ip, ua, False, method="oidc")

    async def logout(self, sid: str, ip: str) -> None:
        s = self.drop_session(sid)
        if s:
            await self.audit.log("auth.logout", user=s["user"], role=s["role"], ip=ip)

    async def change_password(self, user: str, old: str, new: str, ip: str, sid: str | None = None) -> None:
        u = await self.store.q1("SELECT * FROM users WHERE username = ?", (user,))
        if not u or u["source"] != "local":
            raise HTTPException(400, "AD/LDAP 계정은 사내 디렉터리에서 비밀번호를 변경하세요.")
        if not await asyncio.to_thread(verify_password, old or "", u["pw_hash"]):
            await self.audit.log("auth.password_change", user=user, ip=ip, result="fail")
            raise HTTPException(400, "현재 비밀번호가 올바르지 않습니다.")
        errs = check_policy(new, user, self.pw_policy)
        hist = json.loads(u["pw_history"] or "[]")
        for h in hist[-int(self.pw_policy.get("history", 3)):]:
            if await asyncio.to_thread(verify_password, new, h):
                errs.append(f"최근 {self.pw_policy.get('history', 3)}개 비밀번호는 다시 사용할 수 없습니다")
                break
        if errs:
            raise HTTPException(400, " · ".join(errs))
        nh = await asyncio.to_thread(hash_password, new)
        hist = (hist + [nh])[-10:]
        await self.store.x("UPDATE users SET pw_hash=?, pw_history=?, pw_changed=?, must_change=0 WHERE username=?",
                           (nh, json.dumps(hist), time.time(), user))
        dropped = 0
        for k, s in list(self.sessions.items()):
            if s["user"] != user:
                continue
            if sid and k != sid:                  # 2.30.0 비밀번호를 바꾸면 다른 기기 세션은 종료(탈취된 세션 차단)
                self.drop_session(k)
                dropped += 1
                continue
            s["must_change"] = False
            self._persist(k)
        await self.audit.log("auth.password_change", user=user, ip=ip, detail={"sessions_closed": dropped})

    # ------------------------------------------------------------------ 세션·토큰 검증
    def session(self, request: Request) -> dict | None:
        sid = request.cookies.get("aiops_sid")
        s = self.sessions.get(sid or "")
        if not s:
            return None
        now = time.time()
        idle_exp = (now - s["last"] > self.idle) and not s.get("kiosk")
        if idle_exp or now - s["created"] > (self.kiosk_absolute if s.get("kiosk") else self.absolute):
            self.drop_session(sid)
            asyncio.ensure_future(self.audit.log("auth.session_expired", user=s["user"], role=s["role"], ip=s["ip"]))
            return None
        s["sid"] = sid
        return s

    def touch(self, s: dict) -> None:
        s["last"] = time.time()

    async def create_token(self, name: str, scopes: list[str], days: int, user: str) -> str:
        """API 토큰 발급(원문은 1회만 반환, DB 에는 SHA-256 만 저장) — 에이전트 등록 등 내부 재사용"""
        raw = "aiops_" + secrets.token_urlsafe(32)
        await self.store.x("INSERT INTO api_tokens(name,hash,prefix,scopes,created_by,created,expires) VALUES(?,?,?,?,?,?,?)",
                           (name[:60], hashlib.sha256(raw.encode()).hexdigest(), raw[:12], json.dumps(scopes), user,
                            time.time(), time.time() + days * 86400 if days else 0))
        return raw

    async def token_user(self, raw: str, scope: str, ip: str = "") -> dict | None:
        if not raw:
            return None
        h = hashlib.sha256(raw.encode()).hexdigest()
        t = await self.store.q1("SELECT * FROM api_tokens WHERE hash=? AND revoked=0", (h,))
        if not t or (t["expires"] and t["expires"] < time.time()):
            return None
        scopes = json.loads(t["scopes"] or "[]")
        if scope not in scopes and "admin" not in scopes:
            return None
        if ip and not ip_allowed(ip, t["allow_ips"] if "allow_ips" in t.keys() else ""):
            asyncio.ensure_future(self.audit.log("auth.denied", user=f"token:{t['name']}", ip=ip, target=scope, result="ip_denied"))
            return None
        await self.store.x("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), t["id"]))
        return {"user": f"token:{t['name']}", "role": "viewer" if scope == "read" else "system", "display": t["name"],
                "token": True}

    def allowed(self, role: str, perm: str) -> bool:
        return role in PERMS.get(perm, set())

    @staticmethod
    def required_perm(method: str, path: str) -> str:
        for m, rx, perm in ROUTE_RULES:
            if (m == "*" or m == method) and re.search(rx, path):
                return perm
        return "view" if method in ("GET", "HEAD") else "settings"

    # ------------------------------------------------------------------ 미들웨어
    def middleware(self):
        mgr = self

        async def mw(request: Request, call_next):
            path = request.scope.get("path") or ""           # 2.30.0 라우팅과 같은 경로로 판단(request.url.path 는 디코딩된 '?' 뒤를 자름)
            if bad_path(path):
                return JSONResponse({"detail": "잘못된 요청 경로", "code": "bad_path"}, status_code=400)
            if not mgr.enabled or PUBLIC.match(path):
                return await call_next(request)
            # 연동 엔드포인트: 토큰 인증
            if path == "/api/ingest" or path == "/metrics":
                return await call_next(request)          # 각 라우트에서 토큰 검증
            if path in ("/api/mobile/pair", "/api/mobile/feed", "/api/mobile/app.apk") and request.method in ("GET", "POST"):
                return await call_next(request)          # 2.30.0 모바일 앱 — 라우트가 연결 코드·기기 토큰(또는 세션)으로 직접 인증
            if path == "/mcp":                           # MCP: API 토큰(scope=read)만 — 브라우저 세션 쿠키로는 호출 불가(CSRF 차단)
                raw = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                tu = await mgr.token_user(raw, "read", client_ip(request)) if raw else None
                if not tu:
                    return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "API 토큰(scope=read) 필요"}},
                                        status_code=401, headers={"WWW-Authenticate": "Bearer"})
                request.state.user = tu
                return await call_next(request)
            s = mgr.session(request)
            if s is None:
                raw = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
                if raw and path.startswith("/api/") and request.method == "GET":
                    tu = await mgr.token_user(raw, "read", client_ip(request))
                    if tu:
                        perm = mgr.required_perm(request.method, path)      # 2.30.0 읽기 토큰도 역할(viewer) 권한 확인 — 감사로그·설정·사용자 등은 불가
                        if not mgr.allowed(tu["role"], perm):
                            asyncio.ensure_future(mgr.audit.log("auth.denied", user=tu["user"], role=tu["role"], ip=client_ip(request),
                                                                target=f"{request.method} {path}", result="denied"))
                            return JSONResponse({"detail": f"권한이 없습니다({perm})", "code": "forbidden"}, status_code=403)
                        request.state.user = tu
                        return await call_next(request)
                if path.startswith("/api/") or path == "/ws":
                    return JSONResponse({"detail": "인증이 필요합니다", "code": "auth"}, status_code=401)
                from urllib.parse import quote
                vq = request.query_params.get("view", "")          # 2.17 새 창(/?view=<메뉴>) — 로그인 후 그 메뉴로
                if path in ("/", "") and vq and vq.replace("-", "").replace("_", "").isalnum() and len(vq) <= 40:
                    return RedirectResponse(f"/login?next={quote('/?view=' + vq, safe='')}")
                return RedirectResponse(f"/login?next={quote(path)}" if path not in ("/", "") else "/login")
            request.state.user = s
            if s.get("must_change") and not (path.startswith("/api/auth/") or path == "/" or path.startswith("/static/")):
                return JSONResponse({"detail": "비밀번호를 변경해야 합니다", "code": "must_change"}, status_code=403)
            if s.get("must_enroll_mfa") and path.startswith("/api/") and not path.startswith("/api/auth/"):
                return JSONResponse({"detail": "이 역할은 2단계 인증(MFA) 등록이 필요합니다", "code": "mfa_enroll"}, status_code=403)
            if path.startswith("/api/"):
                if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "aiops":
                    return JSONResponse({"detail": "CSRF 보호: 허용되지 않은 요청", "code": "csrf"}, status_code=403)
                if request.method not in ("GET", "HEAD") and not mgr._write_ok(s.get("sid", "")):
                    asyncio.ensure_future(mgr.audit.log("auth.rate_limited", user=s["user"], role=s["role"], ip=client_ip(request), target=f"{request.method} {path}", result="rate_limited"))
                    return JSONResponse({"detail": "요청이 너무 잦습니다. 잠시 후 다시 시도하세요.", "code": "rate_limited"}, status_code=429,
                                        headers={"Retry-After": "10"})
                perm = mgr.required_perm(request.method, path)
                if not mgr.allowed(s["role"], perm):
                    asyncio.ensure_future(mgr.audit.log("auth.denied", user=s["user"], role=s["role"], ip=client_ip(request),
                                                        target=f"{request.method} {path}", result="denied"))
                    return JSONResponse({"detail": f"권한이 없습니다({perm})", "code": "forbidden"}, status_code=403)
                # 사용자 입력에 의한 요청만 유휴 시간 갱신(백그라운드 폴링은 제외)
                if request.method not in ("GET", "HEAD") or request.headers.get("x-background") != "1":
                    mgr.touch(s)
            return await call_next(request)
        return mw

    def ws_user(self, ws) -> dict | None:
        """WebSocket 핸드셰이크 — 세션 쿠키 + 동일 출처(Origin) 확인"""
        if not self.enabled:
            return {"user": "anonymous", "role": "admin"}
        origin = ws.headers.get("origin", "")
        host = ws.headers.get("host", "")
        if origin and host and origin.split("://", 1)[-1] != host:
            return None

        class _R:
            cookies = ws.cookies
        s = self.session(_R)                         # type: ignore[arg-type]
        if s and (s.get("must_change") or s.get("must_enroll_mfa")):
            return None                              # 2.30.0 비밀번호 변경·MFA 등록 전 세션은 실시간 스트림도 불가
        return s

    # ------------------------------------------------------------------ 라우터
    def router(self) -> APIRouter:
        r = APIRouter()
        mgr = self

        async def _json(request: Request, limit: int = 65536) -> dict:
            """인증 전 본문 — 64KB 상한(청크 전송 포함)·JSON 객체만"""
            buf = b""
            async for chunk in request.stream():
                buf += chunk
                if len(buf) > limit:
                    raise HTTPException(413, "요청 본문이 너무 큽니다")
            try:
                b = json.loads(buf or b"{}")
            except ValueError:
                raise HTTPException(400, "JSON 본문 필요")
            if not isinstance(b, dict):
                raise HTTPException(400, "JSON 객체 필요")
            return b

        def cookie(resp, sid: str, request: Request):
            secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
            resp.set_cookie("aiops_sid", sid, httponly=True, samesite="strict", secure=secure, path="/")

        @r.get("/api/auth/config")
        async def auth_config():
            return {"enabled": mgr.enabled, "ldap": bool(mgr.ldap_cfg.get("enabled")),
                    "ldap_domain": mgr.ldap_cfg.get("domain", ""), "banner": mgr.cfg.get("login_banner", ""),
                    "idle_minutes": mgr.idle / 60, "mfa": mgr.mfa.enabled,
                    "oidc": bool(mgr.oidc_cfg.get("enabled")), "oidc_name": mgr.oidc_cfg.get("display_name") or "SSO"}

        @r.post("/api/auth/login")
        async def login(request: Request):
            if request.headers.get("x-requested-with") != "aiops":
                raise HTTPException(403, "CSRF 보호")
            b = await _json(request)
            res = await mgr.login(str(b.get("username", ""))[:256], str(b.get("password", ""))[:1024], client_ip(request),
                                  request.headers.get("user-agent", ""))
            resp = JSONResponse({k: v for k, v in res.items() if k != "sid"})
            if res.get("sid"):
                cookie(resp, res["sid"], request)
            return resp

        @r.post("/api/auth/mfa/verify")
        async def mfa_verify(request: Request):
            if request.headers.get("x-requested-with") != "aiops":
                raise HTTPException(403, "CSRF 보호")
            b = await _json(request)
            res = await mgr.mfa_verify(str(b.get("mfa_token", ""))[:128], str(b.get("code", ""))[:64], client_ip(request))
            resp = JSONResponse({k: v for k, v in res.items() if k != "sid"})
            cookie(resp, res["sid"], request)
            return resp

        @r.get("/api/auth/mfa")
        async def mfa_status(request: Request):
            s = getattr(request.state, "user", None) or ANON
            st = await mgr.mfa.status(s["user"])
            return {**st, "enabled": mgr.mfa.enabled, "required": s["role"] in mgr.mfa.required_roles,
                    "must_enroll": bool(s.get("must_enroll_mfa")), "issuer": mgr.mfa.issuer}

        @r.post("/api/auth/mfa/enroll")
        async def mfa_enroll(request: Request):
            s = getattr(request.state, "user", None) or ANON
            if not mgr.mfa.enabled:
                raise HTTPException(400, "MFA 비활성")
            if s.get("token"):
                raise HTTPException(403, "API 토큰으로는 등록할 수 없습니다")
            if mgr.enabled and (await mgr.mfa.status(s["user"]))["enrolled"]:
                # 2.30.0 재등록은 본인 재확인 필수 — 현재 인증 앱 코드(code) 또는 로컬 계정의 현재 비밀번호(password)
                try:
                    b = await _json(request)
                except HTTPException:
                    b = {}
                code, pw, ok = str(b.get("code") or "").strip().replace(" ", ""), str(b.get("password") or ""), False
                if not code and not pw:
                    raise HTTPException(400, "이미 등록된 MFA 가 있습니다 — 재등록하려면 현재 인증 코드(code) 또는 현재 비밀번호(password)를 함께 보내세요")
                if code.isdigit():
                    try:
                        ok = await mgr.mfa.verify(s["user"], code) == "totp"
                    except ValueError:
                        ok = False
                elif pw:
                    u = await mgr.store.q1("SELECT source, pw_hash FROM users WHERE username=?", (s["user"],))
                    ok = bool(u and u["source"] == "local" and await asyncio.to_thread(verify_password, pw, u["pw_hash"] or ""))
                if not ok:
                    await mgr.audit.log("auth.mfa_enroll", user=s["user"], role=s["role"], ip=client_ip(request), result="reauth_fail")
                    if await mgr._count_failure(s["user"], client_ip(request), "mfa_reenroll"):
                        for k in [k for k, v in mgr.sessions.items() if v["user"] == s["user"]]:
                            mgr.drop_session(k)
                    await asyncio.sleep(0.6)
                    raise HTTPException(403, "현재 인증 코드 또는 비밀번호가 올바르지 않습니다")
            return await mgr.mfa.enroll(s["user"])

        @r.post("/api/auth/mfa/confirm")
        async def mfa_confirm(request: Request):
            s = getattr(request.state, "user", None) or ANON
            b = await request.json()
            try:
                codes = await mgr.mfa.confirm(s["user"], str(b.get("code", "")))
            except ValueError as e:
                raise HTTPException(400, str(e))
            for k, v in mgr.sessions.items():
                if v["user"] == s["user"]:
                    v["must_enroll_mfa"] = False
                    v["mfa"] = True
                    mgr._persist(k)
            await mgr.audit.log("auth.mfa_enroll", user=s["user"], role=s["role"], ip=client_ip(request))
            return {"ok": True, "recovery_codes": codes, "note": "복구 코드는 다시 표시되지 않습니다. 안전한 곳에 보관하세요."}

        @r.delete("/api/users/{uname}/mfa")
        async def mfa_reset(uname: str, request: Request):
            s = getattr(request.state, "user", None) or ANON
            await mgr.mfa.reset(uname)
            for k, v in mgr.sessions.items():
                if v["user"] == uname:
                    v["must_enroll_mfa"] = mgr.mfa.must_enroll(v["role"], False)
                    mgr._persist(k)
            await mgr.audit.log("auth.mfa_reset", user=s["user"], role=s["role"], ip=client_ip(request), target=uname)
            return {"ok": True}

        @r.post("/api/auth/logout")
        async def logout(request: Request):
            await mgr.logout(request.cookies.get("aiops_sid", ""), client_ip(request))
            resp = JSONResponse({"ok": True})
            resp.delete_cookie("aiops_sid", path="/")
            return resp

        @r.get("/api/auth/me")
        async def me(request: Request):
            s = getattr(request.state, "user", None) or {"user": "anonymous", "role": "admin", "display": "anonymous"}
            perms = sorted(p for p, roles in PERMS.items() if s["role"] in roles)
            u = await mgr.store.q1("SELECT prev_login, prev_ip, source, pw_changed FROM users WHERE username=?", (s["user"],)) or {}
            return {"user": s["user"], "display": s.get("display"), "role": s["role"], "role_label": ROLE_LABEL.get(s["role"]),
                    "perms": perms, "must_change": s.get("must_change", False), "idle_minutes": mgr.idle / 60,
                    "kiosk": bool(s.get("kiosk")), "mfa_enabled": mgr.mfa.enabled, "must_enroll_mfa": bool(s.get("must_enroll_mfa")),
                    "mfa_enrolled": (await mgr.mfa.status(s["user"]))["enrolled"] if mgr.mfa.enabled and not s.get("token") else False,
                    "auth_method": s.get("auth_method", "password"),
                    "prev_login": u.get("prev_login"), "prev_ip": u.get("prev_ip"), "source": u.get("source"),
                    "pw_changed": u.get("pw_changed")}

        @r.post("/api/auth/heartbeat")
        async def heartbeat(request: Request):
            return {"ok": True}

        @r.post("/api/auth/password")
        async def password(request: Request):
            b = await request.json()
            s = getattr(request.state, "user", None)
            if not s:
                raise HTTPException(400, "인증 비활성 상태")
            await mgr.change_password(s["user"], b.get("old", ""), b.get("new", ""), client_ip(request), sid=s.get("sid"))
            return {"ok": True}

        # ---------------- 사용자 관리(admin)
        @r.get("/api/users")
        async def users():
            rows = await mgr.store.q("SELECT username,display,email,role,source,must_change,failed,locked_until,disabled,"
                                     "created,last_login,last_ip,pw_changed FROM users ORDER BY username")
            active = {s["user"] for s in mgr.sessions.values()}
            enrolled = await mgr.mfa.enrolled_users()
            for x in rows:
                x["online"] = x["username"] in active
                x["mfa"] = x["username"] in enrolled
            return rows

        @r.post("/api/users")
        async def user_create(request: Request):
            b = await request.json()
            s = getattr(request.state, "user", None) or ANON
            uname = str(b.get("username", "")).strip().lower()
            if not re.fullmatch(r"[a-z0-9._-]{3,32}", uname):
                raise HTTPException(400, "아이디는 영문 소문자·숫자·._- 3~32자")
            if b.get("role") not in ROLES:
                raise HTTPException(400, "역할 오류")
            if await mgr.store.q1("SELECT 1 FROM users WHERE username=?", (uname,)):
                raise HTTPException(409, "이미 존재하는 아이디")
            pw = b.get("password") or generate_password()
            errs = check_policy(pw, uname, mgr.pw_policy)
            if errs:
                raise HTTPException(400, " · ".join(errs))
            await mgr._upsert_local(uname, b.get("display") or uname, b["role"], pw, must_change=True, email=b.get("email", ""))
            await mgr.audit.log("user.create", user=s["user"], role=s["role"], ip=client_ip(request), target=uname,
                                detail={"role": b["role"]})
            return {"ok": True, "initial_password": pw if not b.get("password") else None}

        @r.post("/api/users/{uname}")
        async def user_update(uname: str, request: Request):
            b = await request.json()
            s = getattr(request.state, "user", None) or ANON
            u = await mgr.store.q1("SELECT * FROM users WHERE username=?", (uname,))
            if not u:
                raise HTTPException(404)
            changes = {}
            if "role" in b and b["role"] in ROLES:
                if uname == s["user"] and b["role"] != "admin":
                    raise HTTPException(400, "자신의 관리자 권한은 해제할 수 없습니다")
                changes["role"] = b["role"]
            if "disabled" in b:
                if uname == s["user"]:
                    raise HTTPException(400, "자신의 계정은 비활성화할 수 없습니다")
                changes["disabled"] = int(bool(b["disabled"]))
            if b.get("unlock"):
                changes.update(failed=0, locked_until=0)
            if "display" in b:
                changes["display"] = str(b["display"])[:60]
            pw = None
            if b.get("reset_password") and u["source"] == "local":
                pw = generate_password()
                changes.update(pw_hash=await asyncio.to_thread(hash_password, pw), must_change=1, pw_changed=time.time())
            if changes:
                sets = ", ".join(f"{k}=?" for k in changes)
                await mgr.store.x(f"UPDATE users SET {sets} WHERE username=?", (*changes.values(), uname))
                if changes.get("disabled") or "role" in changes or pw:
                    for sid in [k for k, v in mgr.sessions.items() if v["user"] == uname]:
                        mgr.drop_session(sid)             # 권한 변경 즉시 반영(재로그인)
            await mgr.audit.log("user.update", user=s["user"], role=s["role"], ip=client_ip(request), target=uname,
                                detail={k: v for k, v in changes.items() if k not in ("pw_hash",)})
            return {"ok": True, "temp_password": pw}

        @r.delete("/api/users/{uname}")
        async def user_delete(uname: str, request: Request):
            s = getattr(request.state, "user", None) or ANON
            if uname == s["user"]:
                raise HTTPException(400, "자신의 계정은 삭제할 수 없습니다")
            await mgr.store.x("DELETE FROM users WHERE username=?", (uname,))
            for sid in [k for k, v in mgr.sessions.items() if v["user"] == uname]:
                mgr.drop_session(sid)
            await mgr.audit.log("user.delete", user=s["user"], role=s["role"], ip=client_ip(request), target=uname)
            return {"ok": True}

        @r.get("/api/users/sessions")
        async def sessions():
            now = time.time()
            return [{"user": v["user"], "role": v["role"], "ip": v["ip"], "since": v["created"], "ua": v.get("ua", "")[:80],
                     "idle_sec": round(now - v["last"]), "sid": k[:8], "mfa": bool(v.get("mfa")), "method": v.get("auth_method", "password")}
                    for k, v in mgr.sessions.items()]

        @r.delete("/api/users/sessions/{prefix}")
        async def session_revoke(prefix: str, request: Request):
            """관리자: 세션 강제 종료(sid 앞 8자)"""
            s = getattr(request.state, "user", None) or ANON
            hits = [k for k in mgr.sessions if k.startswith(prefix)] if len(prefix) >= 8 else []
            for k in hits:
                v = mgr.drop_session(k)
                await mgr.audit.log("auth.session_revoke", user=s["user"], role=s["role"], ip=client_ip(request), target=v["user"] if v else prefix)
            return {"ok": True, "revoked": len(hits)}

        @r.get("/api/auth/sessions")
        async def my_sessions(request: Request):
            """본인 세션 목록(현재 세션 표시) — 다른 기기 로그아웃용"""
            s = getattr(request.state, "user", None) or ANON
            now, cur = time.time(), s.get("sid", "")
            return [{"sid": k[:8], "ip": v["ip"], "ua": v.get("ua", "")[:80], "since": v["created"], "idle_sec": round(now - v["last"]),
                     "method": v.get("auth_method", "password"), "current": k == cur} for k, v in mgr.sessions.items() if v["user"] == s["user"]]

        @r.post("/api/auth/sessions/revoke")
        async def my_sessions_revoke(request: Request):
            """본인 다른 세션 종료 — {"sid": 앞 8자} 또는 {"others": true}"""
            s = getattr(request.state, "user", None) or ANON
            b = await request.json()
            cur = s.get("sid", "")
            hits = [k for k, v in mgr.sessions.items() if v["user"] == s["user"] and k != cur and (b.get("others") or k.startswith(str(b.get("sid", "x"))))]
            for k in hits:
                mgr.drop_session(k)
            await mgr.audit.log("auth.session_revoke", user=s["user"], role=s["role"], ip=client_ip(request), target="self", detail={"n": len(hits)})
            return {"ok": True, "revoked": len(hits)}

        # ---------------- API 토큰(admin)
        @r.get("/api/tokens")
        async def tokens():
            return await mgr.store.q("SELECT id,name,prefix,scopes,created_by,created,expires,last_used,revoked,allow_ips "
                                     "FROM api_tokens ORDER BY id DESC")

        @r.post("/api/tokens")
        async def token_create(request: Request):
            b = await request.json()
            s = getattr(request.state, "user", None) or ANON
            scopes = [x for x in b.get("scopes", []) if x in ("ingest", "metrics", "read")]
            if not scopes:
                raise HTTPException(400, "scope(ingest·metrics·read) 필요")
            raw = "aiops_" + secrets.token_urlsafe(32)
            days = int(b.get("days", 365))
            allow = str(b.get("allow_ips", "") or "")[:500]
            for it in [x for x in re.split(r"[,\s]+", allow) if x]:
                try:
                    ipaddress.ip_network(it, strict=False)
                except ValueError:
                    raise HTTPException(400, f"허용 IP 형식 오류: {it} (예: 10.0.0.0/24, 192.168.1.10)")
            await mgr.store.x("INSERT INTO api_tokens(name,hash,prefix,scopes,created_by,created,expires,allow_ips) VALUES(?,?,?,?,?,?,?,?)",
                              (str(b.get("name", "token"))[:60], hashlib.sha256(raw.encode()).hexdigest(), raw[:12],
                               json.dumps(scopes), s["user"], time.time(), time.time() + days * 86400 if days else 0, allow))
            await mgr.audit.log("token.create", user=s["user"], role=s["role"], ip=client_ip(request),
                                target=b.get("name", "token"), detail={"scopes": scopes, "days": days, "allow_ips": allow})
            return {"token": raw, "note": "이 값은 다시 표시되지 않습니다."}

        @r.delete("/api/tokens/{tid}")
        async def token_revoke(tid: int, request: Request):
            s = getattr(request.state, "user", None) or ANON
            await mgr.store.x("UPDATE api_tokens SET revoked=1 WHERE id=?", (tid,))
            await mgr.audit.log("token.revoke", user=s["user"], role=s["role"], ip=client_ip(request), target=str(tid))
            return {"ok": True}

        return r
