"""외부 공개 로그인 보호(2.49.0) — 인터넷에 노출된 포털을 노린 공격을 막는다.

1) 잠금 악용 차단: 외부(인터넷)에서 틀린 비밀번호로 관리자 계정을 일부러 잠그는 공격을 막기 위해, 외부 실패는
   '계정 + 출발 IP' 단위로 잠근다. 계정 전체 잠금은 여러 IP에서 합계가 상한(external_account_cap)을 넘을 때만.
   내부망 실패는 지금처럼 계정 단위.
2) 계정 대입(credential stuffing) 감지: 한 IP가 짧은 시간에 여러 아이디로 실패하면 그 IP를 일정 시간 차단.
3) 세션 이동 감지: 로그인 때 국가(Cloudflare CF-IPCountry)와 다른 국가에서 같은 세션 쿠키가 쓰이면 세션을 끊는다.
4) 새 위치 로그인: 사용자가 처음 보는 위치(국가 또는 IP 대역)에서 로그인하면 감사 기록 + 이상징후.

모두 메모리 상태(재시작 시 초기화)이며, 새 위치 기록만 DB(login_locations)에 남긴다. 판단 결과는 notify 콜백으로
엔진 이벤트(source=aiops, connector=auth-guard)가 되어 일반 이상징후·알림·SIEM 경로를 탄다.
"""
from __future__ import annotations

import contextvars
import ipaddress
import time
from typing import Any, Callable

# 요청 단위 접속 정보(미들웨어가 채움) — 세션 생성 시 국가·외부 여부를 함께 기록하기 위함
REQ_EDGE: contextvars.ContextVar[dict] = contextvars.ContextVar("aiops_req_edge", default={})

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_locations(
  username TEXT, loc TEXT, first REAL, last REAL, count INTEGER DEFAULT 1, PRIMARY KEY(username, loc));
"""

DEFAULTS = {
    "external_lockout": "account_ip",     # account_ip | account(이전 동작)
    "external_account_cap": 20,           # 외부 실패가 여러 IP 합계로 이 값 이상(창 안)이면 계정 전체 잠금
    "external_window_minutes": 30,
    "stuffing_users": 5,                  # 한 IP가 창 안에서 서로 다른 아이디로 이만큼 실패하면 IP 차단
    "stuffing_window_minutes": 10,
    "ip_block_minutes": 30,
    "session_country_bind": True,
    "new_location_alert": True,
}


def loc_key(ip: str, country: str = "") -> str:
    """위치 키 — 국가 코드가 있으면 국가, 없으면 IP 대역(IPv4 /24, IPv6 /48)"""
    c = (country or "").strip().upper()
    if len(c) == 2 and c.isalpha() and c not in ("XX", "T1"):
        return "CC:" + c
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "IP:-"
    if a.is_loopback:
        return "IP:local"
    net = ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False)
    return "IP:" + str(net)


def _never_block(ip: str) -> bool:
    """출발지를 모를 때(루프백·'-')는 IP 차단하지 않음 — 프록시 설정 오류로 모든 사용자가 한꺼번에 막히는 일 방지"""
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


class LoginGuard:
    def __init__(self, cfg: dict | None = None, notify: Callable[[str, str, str, dict], None] | None = None):
        c = {**DEFAULTS, **(cfg or {})}
        self.cfg = c
        self.notify = notify or (lambda sev, msg, entity, attrs: None)
        self.pairs: dict[tuple[str, str], list] = {}        # (user, ip) → [실패 시각들, 잠금 해제 시각]
        self.acct: dict[str, list[float]] = {}              # user → 외부 실패 시각들(모든 IP)
        self.ip_users: dict[str, dict[str, float]] = {}     # ip → {user: 마지막 실패 시각}
        self.blocked: dict[str, dict] = {}                  # ip → {until, users, since}
        self.events: list[dict] = []                        # 최근 보호 동작(화면용, 최대 200)

    # ------------------------------------------------------------------ 공통
    @property
    def pair_mode(self) -> bool:
        return str(self.cfg.get("external_lockout", "account_ip")) == "account_ip"

    def _log(self, kind: str, **kw: Any) -> None:
        self.events.insert(0, {"ts": time.time(), "kind": kind, **kw})
        del self.events[200:]

    def _gc(self, now: float) -> None:
        if len(self.pairs) > 5000:
            self.pairs = {k: v for k, v in self.pairs.items() if v[1] > now or (v[0] and now - v[0][-1] < 3600)}
        if len(self.ip_users) > 5000:
            w = float(self.cfg["stuffing_window_minutes"]) * 60
            self.ip_users = {ip: {u: t for u, t in us.items() if now - t < w} for ip, us in self.ip_users.items()}
            self.ip_users = {k: v for k, v in self.ip_users.items() if v}
        self.blocked = {k: v for k, v in self.blocked.items() if v["until"] > now}

    # ------------------------------------------------------------------ IP 차단
    def ip_blocked(self, ip: str) -> float:
        b = self.blocked.get(ip)
        if b and b["until"] > time.time():
            b["hits"] = b.get("hits", 0) + 1
            return b["until"]
        return 0.0

    def unblock(self, ip: str = "", user: str = "") -> int:
        n = 0
        if ip and not user:
            n += 1 if self.blocked.pop(ip, None) else 0
            self.ip_users.pop(ip, None)
        for k in [k for k in self.pairs if (not user or k[0] == user) and (not ip or k[1] == ip)]:
            self.pairs.pop(k, None)
            n += 1
        if user and not ip:
            self.acct.pop(user, None)
        return n

    # ------------------------------------------------------------------ 외부 실패(계정+IP)
    def pair_until(self, user: str, ip: str) -> float:
        p = self.pairs.get((user, ip))
        return p[1] if p else 0.0

    def external_fail(self, user: str, ip: str, threshold: int, lock_minutes: float) -> dict:
        """외부 로그인 실패 1건 반영 → {failed, until(계정+IP), account_lock(bool), ip_block(until)}"""
        now = time.time()
        self._gc(now)
        win = float(self.cfg["external_window_minutes"]) * 60
        p = self.pairs.setdefault((user, ip), [[], 0.0])
        if p[1] and p[1] <= now:                          # 잠금이 풀린 뒤에는 처음부터
            p[0], p[1] = [], 0.0
        p[0] = [t for t in p[0] if now - t < win] + [now]
        out: dict[str, Any] = {"failed": len(p[0]), "until": 0.0, "account_lock": False, "ip_block": 0.0}
        if len(p[0]) >= threshold:
            p[1] = now + lock_minutes * 60
            out["until"] = p[1]
            self._log("pair_lock", user=user, ip=ip, until=p[1])
        a = self.acct.setdefault(user, [])
        a[:] = [t for t in a if now - t < win] + [now]
        cap = int(self.cfg["external_account_cap"])
        if cap and len(a) >= cap:
            out["account_lock"] = True
            a.clear()
            self._log("account_lock", user=user, ip=ip, failures=cap)
            self.notify("error", f"외부 로그인 실패가 여러 IP에서 {cap}회 넘게 이어져 계정 '{user}' 을(를) 잠갔습니다(분산 대입 의심)",
                        f"user:{user}", {"user": user, "rule": "external_account_cap"})
        # 계정 대입 — 한 IP가 여러 아이디로 실패
        sw = float(self.cfg["stuffing_window_minutes"]) * 60
        us = self.ip_users.setdefault(ip, {})
        us[user or "-"] = now
        for u in [u for u, t in us.items() if now - t >= sw]:
            us.pop(u, None)
        lim = int(self.cfg["stuffing_users"])
        if lim and len(us) >= lim and ip not in self.blocked and not _never_block(ip):
            until = now + float(self.cfg["ip_block_minutes"]) * 60
            self.blocked[ip] = {"until": until, "users": len(us), "since": now, "hits": 0}
            out["ip_block"] = until
            self._log("ip_block", ip=ip, users=len(us), until=until)
            self.notify("error", f"IP {ip} 가 {int(sw // 60)}분 안에 서로 다른 아이디 {len(us)}개로 로그인에 실패해 "
                        f"{int(self.cfg['ip_block_minutes'])}분 차단했습니다(계정 대입 의심)", f"ip:{ip}",
                        {"ip": ip, "users": len(us), "rule": "stuffing"})
        return out

    def success(self, user: str, ip: str) -> None:
        self.pairs.pop((user, ip), None)

    # ------------------------------------------------------------------ 세션 이동
    def session_moved(self, s: dict, ip: str, country: str) -> str:
        """세션이 로그인 때와 다른 국가에서 쓰이면 사유 문자열('' = 정상). IP 변경은 기록만."""
        c0, c1 = (s.get("country") or "").upper(), (country or "").upper()
        if self.cfg.get("session_country_bind", True) and c0 and c1 and c0 != c1 and "XX" not in (c0, c1):
            self._log("session_moved", user=s.get("user"), ip=ip, from_country=c0, to_country=c1)
            self.notify("critical" if s.get("role") == "admin" else "error",
                        f"사용자 '{s.get('user')}' 의 세션이 {c0} 에서 로그인한 뒤 {c1} 에서 쓰여 끊었습니다(세션 탈취 의심, IP {ip})",
                        f"user:{s.get('user')}", {"user": s.get("user"), "ip": ip, "from": c0, "to": c1, "rule": "session_country"})
            return f"{c0}→{c1}"
        if ip and s.get("ip") and ip != s["ip"]:
            seen = s.setdefault("ips", [])
            if ip not in seen and len(seen) < 20:
                seen.append(ip)
        return ""

    # ------------------------------------------------------------------ 새 위치
    async def note_login(self, store, user: str, role: str, ip: str, country: str) -> dict:
        """로그인 성공 위치 기록 → {loc, new(bool), first_ever(bool)}"""
        loc = loc_key(ip, country)
        now = time.time()
        rows = await store.q("SELECT loc FROM login_locations WHERE username=?", (user,))
        known = {r["loc"] for r in rows}
        new = bool(known) and loc not in known and loc != "IP:local"
        await store.x("INSERT INTO login_locations(username,loc,first,last,count) VALUES(?,?,?,?,1) "
                      "ON CONFLICT(username,loc) DO UPDATE SET last=excluded.last, count=count+1", (user, loc, now, now))
        if new and self.cfg.get("new_location_alert", True):
            self._log("new_location", user=user, ip=ip, loc=loc)
            self.notify("error" if role == "admin" else "warning",
                        f"사용자 '{user}' 가 처음 보는 위치({loc.split(':', 1)[1]}, IP {ip})에서 로그인했습니다",
                        f"user:{user}", {"user": user, "ip": ip, "loc": loc, "rule": "new_location"})
        return {"loc": loc, "new": new, "first_ever": not known}

    # ------------------------------------------------------------------ 화면
    def snapshot(self) -> dict:
        now = time.time()
        self._gc(now)
        return {
            "config": {k: self.cfg[k] for k in DEFAULTS},
            "blocked_ips": sorted(({"ip": k, **v} for k, v in self.blocked.items()), key=lambda x: -x["since"]),
            "locked_pairs": sorted(({"user": k[0], "ip": k[1], "until": v[1], "failed": len(v[0])}
                                    for k, v in self.pairs.items() if v[1] > now), key=lambda x: -x["until"]),
            "events": self.events[:100],
        }
