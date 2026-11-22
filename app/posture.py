"""보안 상태 점검(2.22.0) — 운영 중 보안 설정이 조용히 약해지는 것을 주기적으로 찾아 알린다(읽기 전용).

  · 인증       인증 켜짐, 관리자 MFA 강제·등록, 초기 비밀번호·초기 비밀번호 파일, 비밀번호 정책, 세션 만료, 잠금, 장기 미사용 계정,
               최근 24시간 로그인 실패, LDAP 평문
  · API 토큰   만료 없는 토큰, 오래 쓰지 않은 토큰, (외부 공개 시) 허용 IP 없는 토큰
  · 외부 공개  외부 이름(server.external_hosts) 설정 시 — Cloudflare Access 원본 검증 설정·강제·공개키 조회, 외부 이름으로
               내부 연동 경로 404 와 토큰 없는 요청 403(이 프로세스 안에서 확인), 인터넷 쪽에서 Access 관문 동작·엣지 인증서 만료,
               cloudflared 서비스·버전, trusted_proxies
  · 웹 머리글  로그인 화면 응답의 CSP·X-Frame-Options·nosniff·Referrer-Policy·COOP, Server 머리글 없음, 내부 명령어 노출 없음
  · 서버       설정·비밀 키·.env 파일 권한, 원본 TLS 인증서 만료, 감사로그 해시 체인, 백업, /metrics 허용 IP

결과마다 상태(pass·warn·fail·na)·중요도(critical·high·medium·low·info)·근거·조치를 주고 100점 만점 점수를 매긴다.
직전 점검보다 새로 나빠진 항목(alert_min_severity 이상)은 플랫폼 이벤트(source=aiops, kind=security)로 올려 알림 경로를 타고,
해결되면 정상화 이벤트를 보낸다. 이력은 posture_runs 에 남는다(기본 180일).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import ssl
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from .models import LogEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS posture_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, score INTEGER, grade TEXT,
  counts TEXT, bad TEXT, trigger TEXT, ms INTEGER);
CREATE INDEX IF NOT EXISTS posture_runs_ts ON posture_runs(ts);
"""
SEV_W = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CATS = [("auth", "인증·계정"), ("token", "API 토큰"), ("ext", "외부 공개"), ("web", "웹 보안 머리글"), ("server", "서버·파일")]
SELF = "posture"


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"


def score_of(items: list[dict]) -> int:
    lost = 0.0
    for i in items:
        w = SEV_W.get(i["sev"], 0)
        lost += w if i["status"] == "fail" else w / 2 if i["status"] == "warn" else 0
    return max(0, int(round(100 - lost)))


def _mode_world(p: Path) -> bool | None:
    try:
        return bool(p.stat().st_mode & (stat.S_IROTH | stat.S_IWOTH))
    except OSError:
        return None


def parse_cfd_version(out: str) -> tuple[int, int] | None:
    m = re.search(r"version\s+(\d{4})\.(\d{1,2})\.", out or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


class Posture:
    def __init__(self, engine, auth, cfa, cfg: dict | None, app_getter: Callable[[], Any], ext_hosts: set[str], data_dir: str):
        self.e, self.auth, self.cfa = engine, auth, cfa
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.interval = max(1.0, float(cfg.get("interval_hours", 6))) * 3600
        self.external_probe = bool(cfg.get("external_probe", True))
        self.alert_min = str(cfg.get("alert_min_severity", "medium"))
        self.retention_days = int(cfg.get("retention_days", 180))
        self.ignore = {str(x) for x in (cfg.get("ignore") or [])}
        self.app = app_getter
        self.ext_hosts = ext_hosts
        self.data_dir = Path(data_dir)
        self.last: dict | None = None
        self.probe_token = ""
        self._lock = asyncio.Lock()
        self._last_manual = 0.0
        engine.store.schema(SCHEMA)

    # ------------------------------------------------------------------ 공통
    @staticmethod
    def _it(cid: str, cat: str, sev: str, status: str, title: str, evidence: str = "", fix: str = "") -> dict:
        return {"id": cid, "cat": cat, "sev": sev, "status": status, "title": title, "evidence": evidence, "fix": fix}

    async def _run_cmd(self, *args: str, timeout: float = 5) -> tuple[int, str]:
        try:
            p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except (FileNotFoundError, PermissionError, OSError):
            return 127, ""
        try:
            out, _ = await asyncio.wait_for(p.communicate(), timeout)
        except asyncio.TimeoutError:
            p.kill()
            return 124, ""
        return p.returncode or 0, (out or b"").decode(errors="replace").strip()

    # ------------------------------------------------------------------ 인증·계정
    async def _auth(self) -> list[dict]:
        it, out = self._it, []
        acfg = (self.e.cfg.get("auth") or {})
        external = bool(self.ext_hosts)
        if not acfg.get("enabled", True) or not getattr(self.auth, "enabled", True):
            out.append(it("auth_enabled", "auth", "critical", "fail", "웹 콘솔 인증이 꺼져 있음",
                          "auth.enabled: false — 누구나 관리자 권한으로 접근", "config.yaml auth.enabled: true 후 재시작"))
            return out
        out.append(it("auth_enabled", "auth", "critical", "pass", "웹 콘솔 인증 사용"))
        m = acfg.get("mfa") or {}
        req = [str(r) for r in (m.get("required_roles") or [])]
        ok = bool(m.get("enabled")) and "admin" in req
        out.append(it("mfa_admin_required", "auth", "high", "pass" if ok else "fail", "관리자 2단계 인증(MFA) 강제",
                      f"mfa.enabled={bool(m.get('enabled'))}, required_roles={req}",
                      "" if ok else "auth.mfa.enabled: true, required_roles: [admin] (외부 공개 시 operator 도 권장)"))
        try:
            admins = await self.e.store.q("SELECT u.username, COALESCE(m.enabled,0) AS mfa FROM users u LEFT JOIN mfa m ON m.username=u.username "
                                          "WHERE u.role='admin' AND COALESCE(u.disabled,0)=0")
        except Exception:  # noqa: BLE001  (mfa 표 없음)
            admins = await self.e.store.q("SELECT username, 0 AS mfa FROM users WHERE role='admin' AND COALESCE(disabled,0)=0")
        no = [a["username"] for a in admins if not a["mfa"]]
        out.append(it("admin_mfa_enrolled", "auth", "high", "fail" if no and m.get("enabled") else "warn" if no else "pass",
                      "관리자 계정 MFA 등록", f"관리자 {len(admins)}명 중 미등록 {len(no)}명" + (f": {', '.join(no[:5])}" if no else ""),
                      "해당 관리자로 로그인해 인증 앱 등록(오른쪽 위 계정 › 2단계 인증)" if no else ""))
        g = getattr(getattr(self.auth, "guard", None), "cfg", None) or {}     # 2.49.0 외부 로그인 보호
        gok = g.get("external_lockout") == "account_ip" and int(g.get("stuffing_users") or 0) > 0
        out.append(it("login_guard", "auth", "medium", "pass" if gok else "warn", "외부 로그인 보호(잠금 악용·계정 대입 차단)",
                      f"외부 잠금 단위={g.get('external_lockout', '-')}, 계정 대입 차단={g.get('stuffing_users', 0)}개 아이디/"
                      f"{g.get('stuffing_window_minutes', '-')}분, 세션 국가 고정={'켬' if g.get('session_country_bind') else '끔'}",
                      "" if gok else "auth.guard.external_lockout: account_ip, stuffing_users: 5"))
        init = self.data_dir / "initial-admin.txt"
        if init.exists():
            out.append(it("initial_admin_file", "auth", "high", "fail", "초기 관리자 비밀번호 파일이 남아 있음",
                          f"{init} — 초기 비밀번호 평문", "비밀번호 변경 확인 후 파일 삭제(sudo rm)"))
        else:
            out.append(it("initial_admin_file", "auth", "high", "pass", "초기 관리자 비밀번호 파일 없음"))
        r = await self.e.store.q1("SELECT must_change, created FROM users WHERE username='admin' AND source='local' AND COALESCE(disabled,0)=0")
        if r and r["must_change"] and time.time() - float(r["created"] or 0) > 86400:
            out.append(it("default_admin", "auth", "high", "fail", "기본 admin 계정 초기 비밀번호 미변경",
                          "생성 후 하루가 지났는데 최초 변경이 이뤄지지 않음", "admin 으로 로그인해 비밀번호 변경 또는 계정 비활성화"))
        else:
            out.append(it("default_admin", "auth", "high", "pass", "기본 admin 초기 비밀번호 변경됨(또는 계정 없음)"))
        pw = acfg.get("password") or {}
        ml, cl = int(pw.get("min_length", 9)), int(pw.get("classes", 3))
        out.append(it("password_policy", "auth", "medium", "pass" if ml >= 9 and cl >= 3 else "fail", "비밀번호 복잡도",
                      f"최소 {ml}자 · {cl}종 조합", "" if ml >= 9 and cl >= 3 else "auth.password.min_length ≥ 9, classes ≥ 3"))
        idle, absh = float(acfg.get("session_idle_minutes", 10)), float(acfg.get("session_absolute_hours", 12))
        st = "pass" if idle <= 30 and absh <= 24 else "warn" if idle <= 60 else "fail"
        out.append(it("session_timeout", "auth", "medium", st, "세션 유휴·절대 만료", f"유휴 {idle:g}분 · 절대 {absh:g}시간",
                      "" if st == "pass" else "session_idle_minutes ≤ 30, session_absolute_hours ≤ 24"))
        th, lm = int(acfg.get("lockout_threshold", 5)), float(acfg.get("lockout_minutes", 30))
        st = "pass" if 0 < th <= 10 and lm >= 5 else "fail"
        out.append(it("lockout", "auth", "medium", st, "로그인 실패 잠금", f"{th}회 실패 → {lm:g}분 잠금",
                      "" if st == "pass" else "lockout_threshold 3~10, lockout_minutes ≥ 5"))
        if external:
            show = bool(acfg.get("show_remaining_attempts", False))
            out.append(it("remaining_attempts", "auth", "low", "warn" if show else "pass", "로그인 실패 시 남은 시도 숨김(계정 존재 추정 방지)",
                          f"show_remaining_attempts={show}", "auth.show_remaining_attempts: false" if show else ""))
        dd = float(acfg.get("dormant_days", 90) or 0)
        if dd:
            cut = time.time() - dd * 86400
            rows = await self.e.store.q("SELECT username, role FROM users WHERE COALESCE(disabled,0)=0 AND "
                                        "((last_login IS NOT NULL AND last_login < ?) OR (last_login IS NULL AND created < ?))", (cut, cut))
            names = [x["username"] for x in rows]
            out.append(it("dormant_accounts", "auth", "low", "warn" if names else "pass", f"{dd:g}일 이상 미사용 활성 계정",
                          (f"{len(names)}명: " + ", ".join(names[:6])) if names else "없음",
                          "사용자·토큰 화면에서 비활성화(관리자 계정은 자동 잠금 대상 아님)" if names else ""))
        since = time.time() - 86400
        fr = await self.e.store.q1("SELECT COUNT(*) AS n, COUNT(DISTINCT ip) AS ips FROM audit WHERE ts >= ? AND action='auth.login' "
                                   "AND result IN ('fail','locked','rate_limited')", (since,))
        n, ips = int((fr or {}).get("n") or 0), int((fr or {}).get("ips") or 0)
        st = "pass" if n < 30 else "warn" if n < 200 else "fail"
        out.append(it("login_failures_24h", "auth", "medium", st, "최근 24시간 로그인 실패",
                      f"{n}건 · 접속 IP {ips}개", "" if st == "pass" else "감사로그(auth.login fail)에서 IP 확인 → Access 정책·WAF·방화벽 차단"))
        ld = acfg.get("ldap") or {}
        if ld.get("enabled"):
            plain = not ld.get("use_ssl") and not ld.get("start_tls") and not any(str(s).startswith("ldaps://") for s in ld.get("servers") or [])
            nover = (ld.get("use_ssl") or ld.get("start_tls")) and ld.get("verify_tls") is False
            out.append(it("ldap_tls", "auth", "high", "fail" if plain else "warn" if nover else "pass", "AD/LDAP 암호화",
                          "평문 LDAP — 비밀번호가 네트워크에 노출" if plain else "TLS 인증서 검증 꺼짐" if nover else "LDAPS/StartTLS + 인증서 검증",
                          "ldaps:// + use_ssl: true(또는 start_tls) + verify_tls: true + ca_file" if plain or nover else ""))
        return out

    # ------------------------------------------------------------------ API 토큰
    async def _tokens(self) -> list[dict]:
        it, out = self._it, []
        now = time.time()
        rows = await self.e.store.q("SELECT name, prefix, scopes, created, expires, last_used, allow_ips FROM api_tokens "
                                    "WHERE revoked=0 AND (expires IS NULL OR expires=0 OR expires > ?)", (now,))
        noexp = [r for r in rows if not r["expires"]]
        out.append(it("token_expiry", "token", "medium", "warn" if noexp else "pass", "만료 없는 API 토큰",
                      f"{len(noexp)}개" + (": " + ", ".join(f"{r['name']}({r['prefix']}…)" for r in noexp[:5]) if noexp else ""),
                      "만료일(예: 365일)로 다시 발급하고 기존 토큰 폐기" if noexp else ""))
        stale = [r for r in rows if (r["last_used"] and now - r["last_used"] > 90 * 86400) or (not r["last_used"] and now - float(r["created"] or now) > 30 * 86400)]
        out.append(it("token_stale", "token", "low", "warn" if stale else "pass", "오래 쓰지 않은 API 토큰(90일·발급 후 30일 미사용)",
                      f"{len(stale)}개" + (": " + ", ".join(r["name"] for r in stale[:5]) if stale else ""), "쓰지 않으면 폐기" if stale else ""))
        if self.ext_hosts:
            open_ = [r for r in rows if not (r["allow_ips"] or "").strip()]
            out.append(it("token_ip", "token", "low", "warn" if open_ else "pass", "허용 IP 없는 API 토큰(외부 공개 중)",
                          f"{len(open_)}개" + (": " + ", ".join(r["name"] for r in open_[:5]) if open_ else ""),
                          "토큰마다 호출 서버 IP/CIDR 지정(사용자·토큰 › 토큰 › 허용 IP)" if open_ else ""))
        return out

    # ------------------------------------------------------------------ 외부 공개
    async def _probe_internal(self, path: str, host: str | None = None) -> httpx.Response | None:
        try:
            app = self.app()
            tr = httpx.ASGITransport(app=app, client=("127.0.0.1", 40000))
            async with httpx.AsyncClient(transport=tr, base_url="http://posture.internal", timeout=10) as c:
                h = {"x-aiops-probe": self.probe_token} if self.probe_token else {}
                if host:
                    h["host"] = host
                return await c.get(path, headers=h, follow_redirects=False)
        except Exception:  # noqa: BLE001
            return None

    async def _probe_internal_h(self, path: str, headers: dict) -> httpx.Response | None:
        try:
            tr = httpx.ASGITransport(app=self.app(), client=("127.0.0.1", 40000))
            async with httpx.AsyncClient(transport=tr, base_url="http://posture.internal", timeout=10) as c:
                h = {"x-aiops-probe": self.probe_token} if self.probe_token else {}
                return await c.get(path, headers={**h, **headers}, follow_redirects=False)
        except Exception:  # noqa: BLE001
            return None

    async def _edge(self, host: str) -> dict:
        res: dict[str, Any] = {"reachable": False}
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
                r = await c.get(f"https://{host}/")
            loc = r.headers.get("location", "")
            origin_mark = "x-robots-tag" in r.headers or '"cf_access"' in (r.text[:400] if r.status_code in (401, 403) else "")
            redirect = r.status_code in (301, 302, 303, 307, 308) and ("cloudflareaccess.com" in loc or "/cdn-cgi/access/" in loc)
            # 엣지 Access 는 로그인 페이지로 돌려보냄(302). 원본이 내는 403(cf_access)·noindex 표식이 보이면 엣지 정책이 없는 것
            res.update(reachable=True, status=r.status_code, location=loc[:200], gate=redirect,
                       origin_blocked=r.status_code == 403 and origin_mark, cf=bool(r.headers.get("cf-ray")))
        except Exception as e:  # noqa: BLE001
            res["error"] = type(e).__name__

        try:                                               # 2.48.2 http:// 로 들어오면 https 로 넘기는지
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
                rh = await c.get(f"http://{host}/login")
            res["http_status"] = rh.status_code
            res["http_to_https"] = rh.status_code in (301, 302, 307, 308) and rh.headers.get("location", "").startswith("https://")
        except Exception as e:  # noqa: BLE001
            res["http_error"] = type(e).__name__

        def cert_days() -> int | None:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                na = t.getpeercert().get("notAfter")
            return int((ssl.cert_time_to_seconds(na) - time.time()) // 86400) if na else None
        if res["reachable"]:
            try:
                res["cert_days"] = await asyncio.to_thread(cert_days)
            except Exception:  # noqa: BLE001
                res["cert_days"] = None
        return res

    async def _external(self) -> list[dict]:
        it, out = self._it, []
        scfg = self.e.cfg.get("server") or {}
        tp = str(scfg.get("trusted_proxies", "127.0.0.1"))
        wild = tp.strip() in ("*", "0.0.0.0/0", "::/0") or "*" in tp
        out.append(it("trusted_proxies", "ext", "high", "fail" if wild else "pass", "신뢰 프록시 범위",
                      f"trusted_proxies={tp}" + (" — 누구나 X-Forwarded-For 로 접속 IP 위조(감사·레이트 리밋 우회)" if wild else ""),
                      "127.0.0.1(cloudflared·로컬 프록시) 또는 실제 프록시 IP 만" if wild else ""))
        if not self.ext_hosts:
            out.append(it("external", "ext", "info", "na", "외부 공개 안 함", "server.external_hosts 미설정 — 외부 공개 점검 생략",
                          "외부 공개 시: sudo vcf-aiopsctl tunnel --api-token --access-allow @회사도메인 --waf-ratelimit"))
            return out
        hosts = sorted(self.ext_hosts)
        pu = str(scfg.get("public_url") or "")
        out.append(it("public_url_https", "ext", "low", "pass" if pu.startswith("https://") else "warn", "외부 주소 HTTPS",
                      pu or "(public_url 없음)", "" if pu.startswith("https://") else "server.public_url: https://<외부 이름>"))
        c = self.cfa
        out.append(it("cf_access_config", "ext", "high", "pass" if c.enabled else "fail", "Cloudflare Access 원본 검증(JWT)",
                      f"팀 {c.team or '-'} · AUD {'설정' if c.aud else '없음'}",
                      "" if c.enabled else "sudo vcf-aiopsctl tunnel --api-token --access-allow @회사도메인 (team_domain·aud 자동 기록) — "
                                           "Access 정책이 꺼지거나 우회돼도 원본이 막음"))
        if c.enabled:
            out.append(it("cf_access_enforce", "ext", "medium", "pass" if c.enforce else "warn", "Access 토큰 없는 요청 차단",
                          f"enforce={c.enforce}", "" if c.enforce else "server.cf_access.enforce: true"))
            try:
                keys = await c.jwks()
                out.append(it("cf_access_jwks", "ext", "medium", "pass", "Access 공개키 조회", f"키 {len(keys)}개 — https://{c.team}/cdn-cgi/access/certs"))
            except Exception as e:  # noqa: BLE001
                out.append(it("cf_access_jwks", "ext", "medium", "fail", "Access 공개키 조회 실패",
                              f"{str(e)[:120]} — 이 서버에서 {c.team}:443 아웃바운드 필요",
                              "방화벽·프록시에서 *.cloudflareaccess.com:443 허용(실패 시 외부 접속이 모두 403)"))
        h = hosts[0]
        bad = []
        for p in ("/metrics", "/agents", "/api/docs", "/mcp"):
            r = await self._probe_internal(p, h)
            if r is None or r.status_code != 404:
                bad.append(f"{p}→{r.status_code if r is not None else '오류'}")
        out.append(it("ext_block_paths", "ext", "high", "fail" if bad else "pass", "외부 이름으로 내부 연동 경로 차단",
                      ", ".join(bad) if bad else f"{h}: /metrics·/agents·/api/docs·/mcp → 404",
                      "server.external_block_paths 확인(비우면 기본 목록)" if bad else ""))
        if c.enabled and c.enforce:
            r = await self._probe_internal("/", h)
            ok = r is not None and r.status_code == 403
            out.append(it("ext_no_token_denied", "ext", "high", "pass" if ok else "fail", "Access 토큰 없는 외부 요청 403",
                          f"GET / (Host {h}, 토큰 없음) → {r.status_code if r is not None else '오류'}", "" if ok else "server.cf_access 설정 확인"))
        if self.external_probe and not getattr(self, "_quick", False):
            for host in hosts[:3]:
                e = await self._edge(host)
                if not e.get("reachable"):
                    out.append(it(f"edge_gate:{host}", "ext", "high", "na", f"인터넷 쪽 Access 관문({host})",
                                  f"이 서버에서 https://{host} 접속 불가({e.get('error', '-')}) — 외부에서 직접 확인 필요",
                                  "브라우저 시크릿 창으로 접속해 Cloudflare Access 로그인 화면이 먼저 뜨는지 확인"))
                    continue
                gate = bool(e.get("gate"))
                st_ = "pass" if gate else "warn" if e.get("origin_blocked") else "fail"
                out.append(it(f"edge_gate:{host}", "ext", "high", st_, f"인터넷 쪽 Access 관문({host})",
                              f"GET https://{host}/ → {e.get('status')}" + (f" → {e.get('location')}" if e.get("location") else "") +
                              (" — 엣지 Access 없음, 원본 JWT 검증이 막는 중" if st_ == "warn" else "") +
                              ("" if e.get("cf") else " (Cloudflare 경유 아님?)"),
                              "" if gate else "Zero Trust › Access › Applications 에 이 이름 등록(또는 vcf-aiopsctl tunnel --access-allow)"))
                if "http_status" in e:
                    hok = bool(e.get("http_to_https"))
                    out.append(it(f"edge_http:{host}", "ext", "medium", "pass" if hok else "fail", f"인터넷 쪽 HTTP → HTTPS({host})",
                                  f"GET http://{host}/login → {e['http_status']}", "" if hok else "Cloudflare SSL/TLS › Edge Certificates › Always Use HTTPS 켜기"))
                cd = e.get("cert_days")
                if cd is not None:
                    out.append(it(f"edge_cert:{host}", "ext", "medium", "pass" if cd >= 14 else "fail", f"엣지 인증서 만료({host})", f"D-{cd}",
                                  "" if cd >= 14 else "Cloudflare SSL/TLS › Edge Certificates 확인"))
        rc, act = await self._run_cmd("systemctl", "is-active", "cloudflared")
        if rc == 127:
            out.append(it("cloudflared_service", "ext", "high", "na", "cloudflared 서비스", "systemctl 없음(컨테이너·Windows)"))
        else:
            out.append(it("cloudflared_service", "ext", "high", "pass" if act == "active" else "fail", "cloudflared 서비스",
                          f"systemctl is-active → {act or rc}", "" if act == "active" else "sudo systemctl restart cloudflared · journalctl -u cloudflared"))
        rc, ver = await self._run_cmd("cloudflared", "--version")
        v = parse_cfd_version(ver) if rc == 0 else None
        if v:
            now = datetime.now(timezone.utc)
            age = (now.year - v[0]) * 12 + now.month - v[1]
            out.append(it("cloudflared_version", "ext", "low", "pass" if age <= 6 else "warn", "cloudflared 버전",
                          f"{v[0]}.{v[1]} — 약 {age}개월 전 릴리스", "" if age <= 6 else "sudo apt-get update && sudo apt-get install --only-upgrade cloudflared"))
        return out

    # ------------------------------------------------------------------ 웹 머리글
    async def _web(self) -> list[dict]:
        it, out = self._it, []
        r = await self._probe_internal("/login")
        if r is None:
            return [it("web_headers", "web", "medium", "na", "보안 머리글", "로그인 화면 응답을 받지 못함")]
        need = {"content-security-policy": "CSP", "x-frame-options": "X-Frame-Options", "x-content-type-options": "nosniff",
                "referrer-policy": "Referrer-Policy", "cross-origin-opener-policy": "COOP"}
        miss = [v for k, v in need.items() if k not in r.headers]
        out.append(it("web_headers", "web", "medium", "fail" if miss else "pass", "보안 머리글(CSP·X-Frame-Options·nosniff·Referrer·COOP)",
                      (("없음: " + ", ".join(miss)) if miss else "모두 있음") + " (앱 응답 기준 — 앞단 프록시 변경은 인터넷 쪽에서 확인)",
                      "server 보안 머리글 설정 확인" if miss else ""))
        csp = r.headers.get("content-security-policy", "")
        weak = "unsafe-eval" in csp or re.search(r"script-src[^;]*'unsafe-inline'", csp)
        out.append(it("csp_script", "web", "medium", "warn" if weak else "pass", "CSP 스크립트 제한", "script-src 에 unsafe-inline/eval" if weak else "script-src 'self'"))
        body = r.text if r.status_code == 200 else ""
        for sp in re.findall(r'src="(/static/[A-Za-z0-9._-]+\.js)', body):     # 2.48.2 로그인 화면이 부르는 공개 스크립트까지
            rr = await self._probe_internal(sp)
            body += "\n" + (rr.text if rr is not None and rr.status_code == 200 else "")
        leak = [w for w in ("vcf-aiopsctl", "sudo ", "/etc/vcf-aiops", "/opt/vcf-aiops", "ClusterRole", "너는 VMware") if w in body]
        out.append(it("login_leak", "web", "low", "fail" if leak else "pass", "로그인 화면 내부 정보 노출", ", ".join(leak) if leak else "내부 명령어·경로 없음",
                      "login.html·로그인 공개 스크립트에서 제거" if leak else ""))
        # 2.48.2 로그인 전 공개 정적 파일: 전체 화면 사전·앱 스크립트는 로그인 뒤여야 함
        pub = []
        for sp in ("/static/i18n-en.js", "/static/core.js"):
            rr = await self._probe_internal(sp)
            if rr is not None and rr.status_code == 200:
                pub.append(sp)
        out.append(it("static_public", "web", "medium", "fail" if pub else "pass", "로그인 전 정적 파일 노출(전체 사전·앱 스크립트)",
                      ", ".join(pub) + " → 인증 없이 200" if pub else "i18n-en.js·core.js → 로그인 필요(로그인 화면은 i18n-login.js 만 공개)",
                      "auth.PUBLIC 공개 목록 확인" if pub else ""))
        if not getattr(self, "_quick", False):           # 2.49.0 로그인 전 공개 표면 — 모든 GET 경로를 외부 비로그인으로 호출
            from .security import surface
            sf = await surface.scan(self.app(), self.probe_token or "")
            op = sf["open"]
            out.append(it("public_surface", "web", "high", "fail" if op else "pass", "로그인 전 공개 경로(전체 GET 경로 자동 점검)",
                          (f"허용 목록 밖 공개 {len(op)}개: " + ", ".join(f"{r['path']}({r['status']})" for r in op[:6])) if op
                          else f"{sf['checked']}개 경로 확인 — 공개 {len(sf['public'])}개(로그인 화면·헬스·사전 등 허용 목록)만 응답",
                          "새로 공개된 경로의 인증 확인(auth.PUBLIC·라우트 토큰 검사)" if op else ""))
        rr = await self._probe_internal_h("/login", {"cf-visitor": '{"scheme":"http"}'})
        ok = rr is not None and rr.status_code in (301, 308) and rr.headers.get("location", "").startswith("https://")
        off = str((self.e.cfg.get("server") or {}).get("https_redirect", "proxy")).lower() == "off"
        out.append(it("https_redirect", "web", "medium", "warn" if off else "pass" if ok else "fail", "평문 HTTP → HTTPS 전환(앞단 경유)",
                      "server.https_redirect: off" if off else (f"http 방문 → {rr.status_code} {rr.headers.get('location', '')[:60]}" if rr is not None else "응답 없음"),
                      "server.https_redirect 를 proxy 로 + Cloudflare SSL/TLS › Edge Certificates › Always Use HTTPS" if (off or not ok) else ""))
        tls = ((self.e.cfg.get("server") or {}).get("tls") or {})
        on = tls.get("enabled") in (True, "true") or (tls.get("enabled") == "auto" and Path(str(tls.get("certfile", ""))).is_file())
        out.append(it("origin_tls", "web", "low", "pass" if on else "warn", "원본 HTTPS(HSTS)", "HTTPS 직접 서빙" if on else "HTTP — HSTS 미적용",
                      "" if on else "server.tls 인증서 지정(cloudflared → 원본 구간도 암호화)"))
        return out

    # ------------------------------------------------------------------ 서버·파일
    async def _server(self) -> list[dict]:
        it, out = self._it, []
        files = [("config", Path(os.environ.get("AIOPS_CONFIG", "config.yaml")), "medium"),
                 ("secret_key", Path(os.environ.get("AIOPS_SECRET_KEY_FILE", str(self.data_dir / "secret.key"))), "high"),
                 ("env", Path(os.environ.get("AIOPS_ENV_FILE", ".env")), "high")]
        tls = ((self.e.cfg.get("server") or {}).get("tls") or {})
        if tls.get("keyfile"):
            files.append(("tls_key", Path(str(tls["keyfile"])), "high"))
        for k, p, sev in files:
            w = _mode_world(p)
            if w is None:
                continue
            out.append(it(f"perm_{k}", "server", sev, "fail" if w else "pass", f"파일 권한 — {p.name}",
                          f"{p} {oct(p.stat().st_mode & 0o777)}" + (" (다른 사용자 읽기 가능)" if w else ""), f"sudo chmod 640 {p}" if w else ""))
        try:
            v = await self.e.audit.verify(limit=50000)
            out.append(it("audit_chain", "server", "high", "pass" if v.get("ok") else "fail", "감사로그 해시 체인(최근 5만 건)",
                          f"{v.get('checked', 0)}건 확인" + ("" if v.get("ok") else f" — {v.get('broken_at')}번에서 끊김(변조·손상 의심)"),
                          "" if v.get("ok") else "감사로그 화면 › 무결성 검증, 백업과 대조"))
        except Exception as e:  # noqa: BLE001
            out.append(it("audit_chain", "server", "high", "na", "감사로그 해시 체인", type(e).__name__))
        sc = getattr(self.e, "selfcheck", None)
        days = ((sc.state.get("cert") or {}).get("days_left") if sc else None)
        if days is not None:
            out.append(it("origin_cert", "server", "medium", "pass" if days >= 14 else "fail", "원본 TLS 인증서 만료", f"D-{days}",
                          "" if days >= 14 else "make-cert.sh 또는 사내 CA 로 재발급"))
        bc = self.e.cfg.get("backup") or {}
        b = (sc.state.get("backup") or {}) if sc else {}
        if not bc.get("enabled"):
            out.append(it("backup", "server", "low", "warn", "예약 백업", "꺼짐 — 감사로그·설정 복원 불가", "운영 설정 › 백업 켜기"))
        else:
            age = (time.time() - b["mtime"]) / 86400 if b.get("mtime") else None
            ok = age is not None and age <= 2 and b.get("result") in (None, "ok", "none", "")
            out.append(it("backup", "server", "low", "pass" if ok else "warn", "예약 백업",
                          f"최근 {age:.1f}일 전" if age is not None else "백업 파일 없음", "" if ok else "백업 작업·디스크 확인"))
        mc = self.e.cfg.get("metrics") or {}
        if mc.get("enabled", True):
            al = [str(x) for x in (mc.get("allow_ips") or [])]
            wide = any(x in ("0.0.0.0/0", "::/0", "*") for x in al)
            out.append(it("metrics_ips", "server", "medium", "fail" if wide else "pass", "/metrics 허용 IP",
                          ", ".join(al) or "(없음 — 토큰만)", "Prometheus 서버 IP 만" if wide else ""))
        return out

    # ------------------------------------------------------------------ 실행
    async def ensure(self) -> dict:
        """화면 첫 조회: 결과가 없으면 빠른 점검(인터넷 쪽 확인 생략) — 동시 요청은 한 번만 실행"""
        if self.last:
            return self.last
        return await self.run("first-view", quick=True)

    async def run(self, trigger: str = "schedule", quick: bool = False) -> dict:
        async with self._lock:
            if trigger == "first-view" and self.last:
                return self.last
            t0 = time.time()
            self._quick = quick
            items: list[dict] = []
            for fn in (self._auth, self._tokens, self._external, self._web, self._server):
                try:
                    items += await fn()
                except Exception as e:  # noqa: BLE001
                    items.append(self._it(f"error_{fn.__name__.strip('_')}", "server", "info", "na", f"점검 오류({fn.__name__.strip('_')})",
                                          f"{type(e).__name__}: {str(e)[:160]}"))
            for i in items:
                if i["id"] in self.ignore and i["status"] in ("fail", "warn"):
                    i["ignored"] = True
                    i["status"] = "na"
            sc = score_of(items)
            counts = {s: sum(1 for i in items if i["status"] == s) for s in ("pass", "warn", "fail", "na")}
            bad = {i["id"]: i for i in items if i["status"] in ("fail", "warn")}
            prev = self.last or await self._load_prev()
            prev_bad = (prev or {}).get("bad_ids") or {}
            prev_titles = (prev or {}).get("titles") or {}
            passed = {i["id"] for i in items if i["status"] == "pass"}
            new = [] if prev is None else \
                [i for k, i in bad.items() if k not in prev_bad or (prev_bad.get(k) == "warn" and i["status"] == "fail")]   # 첫 점검 = 기준선
            fixed = [k for k in prev_bad if k in passed]          # 실제로 통과한 것만 해결 — 확인 불가(na)·예외·점검 오류는 이전 상태 유지
            carry = {k: v for k, v in prev_bad.items() if k not in bad and k not in passed}
            res = {"ts": t0, "ms": int((time.time() - t0) * 1000), "score": sc, "grade": grade(sc), "counts": counts, "items": items,
                   "cats": CATS, "bad_ids": {**carry, **{k: i["status"] for k, i in bad.items()}},
                   "titles": {**{k: prev_titles.get(k, k) for k in carry}, **{k: i["title"] for k, i in bad.items()}},
                   "new": [i["id"] for i in new], "fixed": [{"id": k, "title": prev_titles.get(k, k)} for k in fixed],
                   "trigger": trigger, "prev_score": (prev or {}).get("score")}
            self.last = res
            await self.e.store.x("INSERT INTO posture_runs(ts,score,grade,counts,bad,trigger,ms) VALUES(?,?,?,?,?,?,?)",
                                 (t0, sc, res["grade"], json.dumps(counts), json.dumps({"s": res["bad_ids"], "t": res["titles"]}, ensure_ascii=False),
                                  trigger, res["ms"]))
            await self.e.store.x("DELETE FROM posture_runs WHERE ts < ?", (t0 - self.retention_days * 86400,))
            if prev is not None:                         # 첫 점검은 기준선(알림 폭주 방지)
                for i in new:
                    if SEV_RANK.get(i["sev"], 0) >= SEV_RANK.get(self.alert_min, 2):
                        self._emit(i, False)
                for k in fixed:
                    self._emit({"id": k, "title": prev_titles.get(k, k), "sev": "info"}, True)
            return res

    async def _load_prev(self) -> dict | None:
        r = await self.e.store.q1("SELECT score, bad FROM posture_runs ORDER BY id DESC LIMIT 1")
        if not r:
            return None
        try:
            b = json.loads(r["bad"] or "{}")
        except ValueError:
            b = {}
        return {"score": r["score"], "bad_ids": b.get("s") or {}, "titles": b.get("t") or {}}

    def _emit(self, i: dict, recovered: bool) -> None:
        sev = "info" if recovered else {"critical": "critical", "high": "error", "medium": "warning"}.get(i["sev"], "info")
        msg = f"보안 점검 정상화: {i['title']}" if recovered else f"보안 점검 {'실패' if i.get('status') == 'fail' else '경고'}: {i['title']} — {i.get('evidence', '')[:160]}"
        try:
            self.e.submit(LogEvent(source="aiops", connector=SELF, message=msg, severity=sev, host="aiops", entity=f"posture:{i['id']}",
                                   kind="security", attrs={"check": i["id"], "recovered": recovered, "sev": i.get("sev")}))
        except Exception as e:  # noqa: BLE001
            print(f"[posture] 이벤트 실패: {e}", flush=True)

    async def history(self, days: int = 30) -> list[dict]:
        rows = await self.e.store.q("SELECT ts, score, grade, counts, trigger FROM posture_runs WHERE ts >= ? ORDER BY ts",
                                    (time.time() - days * 86400,))
        out = []
        for r in rows:
            try:
                c = json.loads(r["counts"] or "{}")
            except ValueError:
                c = {}
            out.append({"ts": r["ts"], "score": r["score"], "grade": r["grade"], "fail": c.get("fail", 0), "warn": c.get("warn", 0), "trigger": r["trigger"]})
        return out

    async def manual(self) -> dict:
        if time.time() - self._last_manual < 20 and self.last:
            return self.last
        self._last_manual = time.time()
        return await self.run("manual")

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(90)
        while True:
            beat()
            if self.enabled:
                try:
                    r = await self.run("schedule")
                    print(f"[posture] 보안 점검 {r['score']}점({r['grade']}) 실패 {r['counts']['fail']} 경고 {r['counts']['warn']} "
                          f"새로 {len(r['new'])} 해결 {len(r['fixed'])} ({r['ms']}ms)", flush=True)
                except Exception as e:  # noqa: BLE001
                    print(f"[posture] 오류: {type(e).__name__}: {e}", flush=True)
            for _ in range(int(self.interval // 600) or 1):
                beat()
                await asyncio.sleep(min(600, self.interval))
