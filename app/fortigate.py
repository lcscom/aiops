"""FortiGate(FortiOS) syslog 전용 처리 — 대량 트래픽 로그를 집계하고 보안 위협(무차별 대입·스캔·IPS)을 따로 파악.

FortiOS 기본 syslog 형식(7.x):
  <189>date=2026-10-12 time=10:01:02 devname="FGVM01" devid="FGVMSLTM26022394" eventtime=1760230862123456789 tz="+0900"
       logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed"
       sn="0" user="admin" ui="https(203.0.113.7)" method="https" srcip=203.0.113.7 dstip=10.0.0.1 action="login"
       status="failed" reason="name_invalid" msg="Administrator admin login failed from https(203.0.113.7) because of invalid user name"
  (rfc5424 형식 옵션을 켜도 본문은 동일한 key=value)

처리 원칙
  · traffic(forward/local) — 기본 'aggregate': 개별 로그는 저장하지 않고 장비별 분당 카운터(허용/차단, 차단 출발지·포트 상위)만 유지,
    1분 요약 이벤트 1건만 저장. 'store' 는 개별 저장(이상징후 대상 아님), 'drop' 은 카운터만.
  · 로그인 실패(관리자 GUI/SSH, SSL-VPN, 사용자 인증) — 개별 로그는 저장만(이상징후 X). 출발지 IP별 슬라이딩 윈도
    (기본 5분)에서 임계치(10회) 이상이면 '무차별 대입 의심' 이상징후 1건(100회 이상 critical), 15분마다 재알림.
    실패가 쌓인 출발지에서 로그인 '성공'이 나오면 critical('실패 후 로그인 성공').
  · IPS/anomaly/virus — (서명, 출발지)별 첫 건만 이상징후, 이후는 상한(20건)까지 저장만, 그 뒤는 집계.
  · 포트 스캔·차단 폭주 — 1분 안에 한 출발지가 많은 목적지 포트로 차단되면 경고.
  · 그 밖의 event(설정 변경·HA·VPN 터널 등)는 원래대로 분석 파이프라인으로.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import Counter, OrderedDict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import LogEvent

KV = re.compile(r'(\w[\w-]*)=("(?:[^"\\]|\\.)*"|[^\s"]*)')
PRI = re.compile(r"^<(\d{1,3})>")
UI_IP = re.compile(r"\(([0-9a-fA-F:.]+)\)")
LEVEL = {"emergency": "critical", "alert": "critical", "critical": "critical", "error": "error", "warning": "warning",
         "notice": "info", "notification": "info", "information": "info", "informational": "info", "debug": "debug"}
CRLEVEL = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
KEEP = ("logid", "type", "subtype", "level", "vd", "action", "status", "srcip", "srcport", "dstip", "dstport", "proto", "service",
        "policyid", "policyname", "user", "ui", "reason", "logdesc", "attack", "attackid", "severity", "crlevel", "ref",
        "srccountry", "dstcountry", "srcintf", "dstintf", "remip", "tunneltype", "tunnelip", "cfgpath", "cfgobj", "cfgattr",
        "devid", "devname", "sentbyte", "rcvdbyte", "app", "appcat", "url", "hostname", "virus", "profile", "method", "group",
        "sessionid", "count", "ha_role", "vpntunnel", "xauthuser", "dir", "eventtype", "msg")
FAIL_ACTIONS = {"login", "ssl-login-fail", "auth-logon", "authentication", "logon", "auth", "ssh-login", "admin-login"}
FAIL_STATUS = {"failed", "failure", "fail", "negate", "denied", "reject"}
OK_ACTIONS = {"login", "auth-logon", "authentication", "logon", "tunnel-up", "ssl-login"}
FAIL_IDS = {"0100032002", "0101039426", "0102043009", "0102043010", "0100032003"}  # 관리자 로그인 실패·SSL-VPN 로그인 실패·사용자 인증 실패
PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp6", "47": "gre", "50": "esp"}
DENY = {"deny", "blocked", "block", "dropped", "drop", "reset"}
PASS_UTM = {"pass", "passthrough", "monitored", "allow", "permit", "accept"}
BULK_UTM = {"webfilter", "app-ctrl", "dns", "ssl", "file-filter", "ssh", "cifs", "voip", "icap"}
DEFAULTS = {"traffic_mode": "aggregate", "bf_window": 300, "bf_threshold": 10, "bf_critical": 100, "realert": 900,
            "bf_store_max": 200, "ips_dedupe": 600, "ips_store_max": 20, "scan_ports": 50, "deny_flood": 3000,
            "success_after_window": 1800}


def _uq(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def is_fortigate(line: str) -> bool:
    h = line[:400]
    return "devid=" in h and ("logid=" in line or "type=" in h)


def _ts(d: dict, now: float) -> float:
    et = d.get("eventtime", "")
    if et.isdigit():
        n = int(et)
        for div in (1e9, 1e6, 1e3, 1):
            if n / div < 4e9:
                return n / div
    try:
        tz = d.get("tz", "")
        off = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * (-1 if tz[:1] == "-" else 1) if re.fullmatch(r"[+-]\d{4}", tz) else None
        dt = datetime.strptime(f"{d['date']} {d['time']}", "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone(off)).timestamp() if off is not None else dt.timestamp()
    except (KeyError, ValueError):
        return now


def src_ip(a: dict) -> str:
    ip = a.get("fg_srcip") or a.get("fg_remip") or ""
    if not ip:
        m = UI_IP.search(a.get("fg_ui", ""))
        ip = m.group(1) if m else ""
    return ip


def parse_line(line: str, peer: str) -> LogEvent:
    line = line.rstrip("\r\n\x00")
    m = PRI.match(line)
    pri = int(m.group(1)) if m else None
    d = {k: _uq(v) for k, v in KV.findall(line)}
    now = time.time()
    ts = _ts(d, now)
    attrs: dict[str, Any] = {"peer": peer, "app": "fortigate"}
    skew = ts - now
    if skew > 300:
        attrs["clock_skew_sec"] = int(skew)
        ts = now
    for k in KEEP:
        v = d.get(k)
        if v not in (None, "", "N/A"):
            attrs[f"fg_{k}"] = v[:300]
    t, st = d.get("type", ""), d.get("subtype", "")
    lv = d.get("level", "").lower()
    sev = LEVEL.get(lv) or ({0: "critical", 1: "critical", 2: "critical", 3: "error", 4: "warning"}.get(pri & 7, "info") if pri is not None else "info")
    if t == "utm":
        cr = CRLEVEL.get((d.get("crlevel") or d.get("severity") or "").lower())
        if cr:
            sev = cr
    elif t == "traffic" and sev in ("warning", "error"):
        sev = "info"                                  # 트래픽 차단은 정상 동작 — 위협 판단은 집계 규칙으로
    host = d.get("devname") or peer
    act = d.get("action", "")
    if t == "traffic":
        msg = (f"{act or 'traffic'} {d.get('srcip', '')}:{d.get('srcport', '')} → {d.get('dstip', '')}:{d.get('dstport', '')}"
               f"{'/' + d['service'] if d.get('service') else ''} 정책 {d.get('policyid', '-')} {d.get('srcintf', '')}→{d.get('dstintf', '')}")
    elif t == "utm":
        sig = d.get("attack") or d.get("virus") or d.get("url") or d.get("hostname") or d.get("app") or d.get("msg", "")
        msg = f"[{st}] {sig} {act} {d.get('srcip', '')} → {d.get('dstip', '')}:{d.get('dstport', '')}"
        if d.get("msg") and d.get("msg") != sig:
            msg += f" — {d['msg']}"
    else:
        msg = d.get("msg") or d.get("logdesc") or line[line.find("logid="):][:300]
        if d.get("logdesc") and d.get("msg") and d["logdesc"] not in d["msg"]:
            msg = f"{d['logdesc']}: {d['msg']}"
    return LogEvent(source="fortigate", connector="syslog", message=msg.strip(), severity=sev, host=host,
                    entity=f"{t or 'log'}/{st}" if st else (t or "log"), ts=ts, kind="log", attrs=attrs,
                    native_id=f"{d.get('devid', '')}:{d.get('eventtime', '')}:{d.get('logid', '')}" if d.get("eventtime") else "")


class FortiProcessor:
    """엔진 submit 직전에 FortiGate 이벤트를 받아 집계·위협 탐지. handle() 이 None 을 돌려주면 개별 저장 생략."""

    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg: dict[str, Any] = {}
        self.configure(cfg or {})
        self.devices: dict[str, dict[str, Any]] = {}
        self.minute = int(time.time() // 60)
        self.cur: dict[str, Counter] = {}             # 장비 → 현재 분 카운터
        self.series: dict[str, deque] = {}            # 장비 → 분당 이력(최근 3시간)
        self.deny_src: deque = deque(maxlen=60)       # 분당 Counter(차단 출발지)
        self.deny_port: deque = deque(maxlen=60)
        self.cur_src: Counter = Counter()
        self.cur_port: Counter = Counter()
        self.cur_scan: dict[str, set] = {}
        self.fails: dict[str, deque] = {}             # 출발지 → 실패 시각
        self.bf: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.ips: OrderedDict[tuple, dict[str, Any]] = OrderedDict()
        self.flags: dict[str, float] = {}             # 재알림 억제
        self.recent: deque = deque(maxlen=300)
        self.stats: Counter = Counter()

    def configure(self, cfg: dict) -> None:
        c = {**DEFAULTS, **{k: v for k, v in (cfg or {}).items() if k in DEFAULTS and v not in (None, "")}}
        for k, v in DEFAULTS.items():
            if isinstance(v, int):
                try:
                    c[k] = max(1, int(c[k]))
                except (TypeError, ValueError):
                    c[k] = v
        if c["traffic_mode"] not in ("aggregate", "store", "drop"):
            c["traffic_mode"] = "aggregate"
        self.cfg = c

    # ------------------------------------------------------------ 입구
    def handle(self, ev: LogEvent) -> LogEvent | None:
        a = ev.attrs
        if a.get("fg_synthetic"):
            return ev
        now = time.time()
        self._roll(now)
        dev = self._device(ev, now)
        c = self.cur.setdefault(dev, Counter())
        c["total"] += 1
        self.stats["received"] += 1
        t, st = a.get("fg_type", ""), a.get("fg_subtype", "")
        act = (a.get("fg_action") or "").lower()
        if t == "traffic":
            return self._traffic(ev, c, act)
        if t == "utm":
            return self._utm(ev, c, st, act, now)
        c["events"] += 1
        status = (a.get("fg_status") or "").lower()
        lid = a.get("fg_logid", "")
        fail = lid in FAIL_IDS or act == "ssl-login-fail" or (act in FAIL_ACTIONS and status in FAIL_STATUS)
        if fail:
            return self._fail(ev, c, dev, now)
        if (act in OK_ACTIONS and status == "success") or act == "tunnel-up":
            self._success(ev, dev, now)
        if st == "system" and (a.get("fg_cfgpath") or "config" in (a.get("fg_logdesc") or "").lower()):
            self._recent("config", ev, src_ip(a))
        return ev

    # ------------------------------------------------------------ 트래픽
    def _traffic(self, ev: LogEvent, c: Counter, act: str) -> LogEvent | None:
        a = ev.attrs
        c["traffic"] += 1
        try:
            c["bytes"] += int(a.get("fg_sentbyte") or 0) + int(a.get("fg_rcvdbyte") or 0)
        except ValueError:
            pass
        if act in DENY:
            c["denied"] += 1
            ip = a.get("fg_srcip", "")
            pr = a.get("fg_proto", "")
            port = f"{a.get('fg_dstport', '')}/{PROTO.get(pr, pr or '?')}"
            if ip:
                self.cur_src[ip] += 1
                s = self.cur_scan.get(ip)
                if s is None and len(self.cur_scan) < 5000:
                    s = self.cur_scan[ip] = set()
                if s is not None and len(s) <= self.cfg["scan_ports"]:
                    s.add(a.get("fg_dstport", ""))
            self.cur_port[port] += 1
            if a.get("fg_subtype") == "local":
                c["local_denied"] += 1
        mode = self.cfg["traffic_mode"]
        if mode == "store":
            a["no_anomaly"] = 1
            self.stats["stored"] += 1
            return ev
        self.stats["aggregated"] += 1
        return None

    # ------------------------------------------------------------ UTM(IPS 등)
    def _utm(self, ev: LogEvent, c: Counter, st: str, act: str, now: float) -> LogEvent | None:
        a = ev.attrs
        if st in BULK_UTM and act in PASS_UTM:          # 웹필터·앱 제어 통과 로그 = 트래픽과 같은 대량 정상 로그
            c["utm_pass"] += 1
            if self.cfg["traffic_mode"] == "store":
                a["no_anomaly"] = 1
                return ev
            self.stats["aggregated"] += 1
            return None
        c["ips" if st in ("ips", "anomaly") else "utm"] += 1
        sig = a.get("fg_attack") or a.get("fg_virus") or a.get("fg_url") or a.get("fg_hostname") or a.get("fg_app") or ev.message[:80]
        ip = a.get("fg_srcip", "")
        k = (st, sig, ip)
        r = self.ips.get(k)
        if r is None or now - r["last"] > self.cfg["ips_dedupe"]:
            r = self.ips[k] = {"subtype": st, "sig": sig, "srcip": ip, "dst": set(), "count": 0, "first": now, "last": now,
                               "severity": ev.severity, "action": act, "dev": ev.host, "country": a.get("fg_srccountry", ""),
                               "ref": a.get("fg_ref", ""), "attackid": a.get("fg_attackid", "")}
            if len(self.ips) > 3000:
                self.ips.popitem(last=False)
        self.ips.move_to_end(k)
        r["count"] += 1
        r["last"] = now
        r["action"] = act or r["action"]
        if len(r["dst"]) < 20:
            r["dst"].add(a.get("fg_dstip", ""))
        a["fp"] = f"fg-utm|{st}|{sig}|{ip}"
        if r["count"] == 1:
            self._recent(st, ev, ip)
            return ev                                     # 첫 건 → 정상 분석(이상징후)
        if r["count"] <= self.cfg["ips_store_max"]:
            a["no_anomaly"] = 1
            return ev
        self.stats["aggregated"] += 1
        return None

    # ------------------------------------------------------------ 로그인 실패/성공
    def _fail(self, ev: LogEvent, c: Counter, dev: str, now: float) -> LogEvent | None:
        a = ev.attrs
        c["login_fail"] += 1
        ip = src_ip(a) or "unknown"
        kind = "SSL-VPN" if a.get("fg_subtype") == "vpn" or "ssl" in (a.get("fg_action") or "") else \
            ("관리자" if a.get("fg_subtype") == "system" else "사용자 인증")
        dq = self.fails.get(ip)
        if dq is None:
            dq = self.fails[ip] = deque(maxlen=20000)
        dq.append(now)
        w = self.cfg["bf_window"]
        while dq and dq[0] < now - w:
            dq.popleft()
        n = len(dq)
        r = self.bf.get(ip)
        if r is None:
            r = self.bf[ip] = {"srcip": ip, "first": now, "last": now, "total": 0, "users": [], "kinds": [], "devs": [],
                               "country": a.get("fg_srccountry", ""), "level": "", "success_after": None, "peak": 0, "alerts": 0}
            if len(self.bf) > 5000:
                old, _ = self.bf.popitem(last=False)
                self.fails.pop(old, None)
        self.bf.move_to_end(ip)
        r["last"] = now
        r["total"] += 1
        r["peak"] = max(r["peak"], n)
        r["window"] = n
        u = a.get("fg_user") or a.get("fg_xauthuser") or ""
        for key, val in (("users", u), ("kinds", kind), ("devs", dev)):
            if val and val not in r[key] and len(r[key]) < 30:
                r[key].append(val)
        a["no_anomaly"] = 1
        if n >= self.cfg["bf_threshold"]:
            lvl = "critical" if n >= self.cfg["bf_critical"] else "error"
            last = self.flags.get(f"bf|{ip}", 0)
            if now - last >= self.cfg["realert"] or (lvl == "critical" and r["level"] != "critical"):
                self.flags[f"bf|{ip}"] = now
                r["level"] = lvl
                r["alerts"] += 1
                users = ", ".join(r["users"][:5]) + (f" 외 {len(r['users']) - 5}" if len(r["users"]) > 5 else "")
                self._emit(ev, dev, lvl, "brute-force", f"fg-bf|{ip}",
                           f"FortiGate {dev}: 무차별 대입 의심 — {ip}{' (' + r['country'] + ')' if r['country'] else ''} 에서 "
                           f"{'/'.join(r['kinds'])} 로그인 {n}회 실패({w // 60}분){' · 계정 ' + users if users else ''}",
                           {"fg_srcip": ip, "fg_count": n, "fg_users": r["users"][:10], "fg_kind": r["kinds"]})
        if n == 1 or n % 50 == 0:
            self._recent("login_fail", ev, ip)
        if n > self.cfg["bf_store_max"]:                  # 공격 중 개별 실패 로그는 상한 이후 집계만
            self.stats["aggregated"] += 1
            return None
        return ev

    def _success(self, ev: LogEvent, dev: str, now: float) -> None:
        a = ev.attrs
        ip = src_ip(a)
        r = self.bf.get(ip) if ip else None
        if not r or now - r["last"] > self.cfg["success_after_window"] or r["total"] < max(3, self.cfg["bf_threshold"] // 2):
            return
        r["success_after"] = now
        u = a.get("fg_user") or a.get("fg_xauthuser") or "?"
        a["fp"] = f"fg-bf-ok|{ip}"
        self._emit(ev, dev, "critical", "brute-force", f"fg-bf-ok|{ip}",
                   f"FortiGate {dev}: 로그인 실패 {r['total']}회 후 성공 — {ip} 계정 {u} (계정 탈취 가능성, 즉시 확인)",
                   {"fg_srcip": ip, "fg_user": u, "fg_count": r["total"]})
        self._recent("login_success_after_fail", ev, ip)

    # ------------------------------------------------------------ 분 단위 정리
    def _roll(self, now: float) -> None:
        m = int(now // 60)
        if m == self.minute:
            return
        prev, self.minute = self.minute, m
        mode = self.cfg["traffic_mode"]
        top_src = self.cur_src.most_common(5)
        top_port = self.cur_port.most_common(5)
        for dev, c in self.cur.items():
            pt = {"t": prev * 60, **{k: c.get(k, 0) for k in ("total", "traffic", "denied", "local_denied", "login_fail", "ips", "utm", "utm_pass", "events", "bytes")}}
            self.series.setdefault(dev, deque(maxlen=180)).append(pt)
            d = self.devices.get(dev)
            if d:
                d["last_min"] = pt
            if mode == "aggregate" and c.get("traffic"):
                msg = (f"트래픽 1분 요약 — 전체 {c['traffic']:,} · 차단 {c.get('denied', 0):,}"
                       f"{' (장비 대상 ' + format(c['local_denied'], ',') + ')' if c.get('local_denied') else ''}")
                if c.get("denied") and top_src:
                    msg += " · 상위 차단 출발지 " + ", ".join(f"{ip}({n})" for ip, n in top_src[:3])
                if c.get("denied") and top_port:
                    msg += " · 포트 " + ", ".join(f"{p}({n})" for p, n in top_port[:3])
                self._push(LogEvent(source="fortigate", connector="syslog", message=msg, severity="info", host=dev,
                                    entity="traffic/summary", ts=prev * 60 + 59, kind="log",
                                    attrs={"fg_synthetic": 1, "no_anomaly": 1, "fg_summary": 1,
                                           **{f"fg_{k}": v for k, v in pt.items() if k != "t"}}))
        self.cur = {}
        self.deny_src.append(Counter(dict(self.cur_src.most_common(300))))
        self.deny_port.append(Counter(dict(self.cur_port.most_common(300))))
        # 포트 스캔 / 차단 폭주
        for ip, ports in self.cur_scan.items():
            n = self.cur_src.get(ip, 0)
            if len(ports) >= self.cfg["scan_ports"] or n >= self.cfg["deny_flood"]:
                key = f"scan|{ip}"
                if now - self.flags.get(key, 0) >= self.cfg["realert"]:
                    self.flags[key] = now
                    what = f"목적지 포트 {len(ports)}개 이상" if len(ports) >= self.cfg["scan_ports"] else f"차단 {n:,}건"
                    ev = LogEvent(source="fortigate", connector="syslog", message="", host=next(iter(self.devices), "fortigate"),
                                  attrs={"fg_srcip": ip})
                    self._emit(ev, ev.host, "warning", "port-scan", f"fg-scan|{ip}",
                               f"FortiGate: 포트 스캔·차단 폭주 의심 — {ip} 가 1분 동안 {what} 차단됨",
                               {"fg_srcip": ip, "fg_ports": len(ports), "fg_count": n})
                    self.recent.appendleft({"ts": now, "kind": "port_scan", "srcip": ip, "dev": ev.host,
                                            "msg": f"1분 차단 {n}건 · 포트 {len(ports)}개", "severity": "warning"})
        self.cur_src, self.cur_port, self.cur_scan = Counter(), Counter(), {}
        cut = now - 86400
        for ip in [ip for ip, r in self.bf.items() if r["last"] < cut]:
            self.bf.pop(ip, None)
            self.fails.pop(ip, None)
        for k in [k for k, t in self.flags.items() if t < cut]:
            self.flags.pop(k, None)
        for k in [k for k, r in self.ips.items() if r["last"] < cut]:
            self.ips.pop(k, None)

    async def loop(self) -> None:
        while True:
            await asyncio.sleep(10)
            try:
                self.e.sup.beat("fortigate")
                self._roll(time.time())
            except Exception as e:  # noqa: BLE001
                print(f"[fortigate] 정리 오류: {type(e).__name__}: {e}", flush=True)

    # ------------------------------------------------------------ 보조
    def _device(self, ev: LogEvent, now: float) -> str:
        a = ev.attrs
        name = ev.host or a.get("fg_devname") or a.get("peer", "fortigate")
        d = self.devices.get(name)
        if d is None:
            d = self.devices[name] = {"name": name, "devid": a.get("fg_devid", ""), "peer": a.get("peer", ""), "first": now,
                                      "vdoms": [], "events": 0, "last_min": {}}
        d["last"] = now
        d["events"] += 1
        if a.get("fg_devid"):
            d["devid"] = a["fg_devid"]
        vd = a.get("fg_vd")
        if vd and vd not in d["vdoms"] and len(d["vdoms"]) < 50:
            d["vdoms"].append(vd)
        if a.get("fg_ha_role"):
            d["ha_role"] = a["fg_ha_role"]
        return name

    def _recent(self, kind: str, ev: LogEvent, ip: str) -> None:
        a = ev.attrs
        self.recent.appendleft({"ts": ev.ts, "kind": kind, "srcip": ip, "dev": ev.host, "user": a.get("fg_user", ""),
                                "msg": ev.message[:240], "severity": ev.severity, "logid": a.get("fg_logid", ""),
                                "country": a.get("fg_srccountry", "")})

    def _emit(self, base: LogEvent, dev: str, sev: str, category: str, fp: str, msg: str, extra: dict) -> None:
        self.stats["alerts"] += 1
        self._push(LogEvent(source="fortigate", connector=base.connector or "syslog", message=msg, severity=sev, host=dev,
                            entity=f"security/{category}", kind="security",
                            attrs={"fg_synthetic": 1, "force_anomaly": 1, "category": category, "fp": fp,
                                   "peer": base.attrs.get("peer", ""), **extra}))

    def _push(self, ev: LogEvent) -> None:
        try:
            self.e.submit(ev)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------ 조회
    def _last(self, key: str) -> dict[str, float]:
        return {dev: float((s[-1] if s else {}).get(key, 0)) for dev, s in self.series.items()}

    def metric(self, name: str) -> dict[str, float]:
        if name == "fortigate.login_failures_5m":
            now, w = time.time(), self.cfg["bf_window"]
            out = {}
            for ip, dq in self.fails.items():
                n = sum(1 for t in dq if t >= now - w)
                if n:
                    out[ip] = float(n)
            return out
        if name == "fortigate.denied_per_min":
            return self._last("denied")
        if name == "fortigate.ips_per_min":
            return self._last("ips")
        if name == "fortigate.traffic_per_min":
            return self._last("traffic")
        return {}

    def entities(self) -> list[dict[str, Any]]:
        now = time.time()
        out = []
        for d in self.devices.values():
            lm = d.get("last_min") or {}
            att = sum(1 for ip, r in self.bf.items() if r.get("level") and now - r["last"] < self.cfg["bf_window"] and d["name"] in r["devs"])
            st = "warn" if now - d.get("last", 0) > 300 else "ok"
            out.append({"name": d["name"], "kind": "firewall", "state": st, "source": "syslog",
                        "detail": f"{d.get('devid', '')} · 분당 {lm.get('total', 0):,}건 · 차단 {lm.get('denied', 0):,}"
                                  + (f" · 공격 출발지 {att}" if att else "") + (" · 수신 끊김" if st == "warn" else "")})
        return out

    def snapshot(self, minutes: int = 60) -> dict[str, Any]:
        now = time.time()
        w = self.cfg["bf_window"]
        devs = []
        for d in self.devices.values():
            x = {k: v for k, v in d.items()}
            x["online"] = now - d.get("last", 0) < 300
            devs.append(x)
        rest = {}
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") == "fortigate" and getattr(c, "status", None):
                rest[c.status.get("hostname") or c.name] = {**c.status, "connector": c.name}
        for x in devs:
            info = rest.get(x["name"]) or next((v for v in rest.values() if v.get("serial") and v.get("serial") == x.get("devid")), None)
            if info:
                x["rest"] = info
        for name, info in rest.items():
            if not any(x["name"] == name or x.get("devid") == info.get("serial") for x in devs):
                devs.append({"name": name, "devid": info.get("serial", ""), "online": True, "rest": info, "events": 0, "vdoms": []})
        # 분당 합계(전 장비)
        agg: dict[int, Counter] = {}
        for s in self.series.values():
            for p in list(s)[-minutes:]:
                agg.setdefault(p["t"], Counter()).update({k: v for k, v in p.items() if k != "t"})
        series = [{"t": t, **c} for t, c in sorted(agg.items())][-minutes:]
        done = series[-1] if series else {}
        tot = Counter()
        for p in series:
            tot.update({k: v for k, v in p.items() if k != "t"})
        cur = Counter()
        for c in self.cur.values():
            cur.update(c)
        live = series + ([{"t": self.minute * 60, **{k: cur.get(k, 0) for k in ("total", "traffic", "denied", "local_denied", "login_fail", "ips", "utm", "utm_pass", "events", "bytes")}, "partial": True}] if cur else [])
        src, port = Counter(), Counter()
        for c in list(self.deny_src)[-minutes:]:
            src.update(c)
        for c in list(self.deny_port)[-minutes:]:
            port.update(c)
        src.update(self.cur_src)
        port.update(self.cur_port)
        bfl = []
        for ip, r in self.bf.items():
            dq = self.fails.get(ip) or ()
            n = sum(1 for t in dq if t >= now - w)
            if r["total"] >= max(3, self.cfg["bf_threshold"] // 2) or n:
                bfl.append({**r, "window": n, "active": n >= self.cfg["bf_threshold"]})
        bfl.sort(key=lambda r: (not r["active"], -r["window"], -r["last"]))
        ips = sorted(self.ips.values(), key=lambda r: -r["last"])[:100]
        return {
            "config": self.cfg, "devices": devs, "now": now,
            "kpi": {"devices": len(devs), "online": sum(1 for d in devs if d.get("online")),
                    "traffic": tot.get("traffic", 0) + cur.get("traffic", 0), "denied": tot.get("denied", 0) + cur.get("denied", 0),
                    "login_fail": tot.get("login_fail", 0) + cur.get("login_fail", 0), "ips": tot.get("ips", 0) + cur.get("ips", 0),
                    "attackers": sum(1 for r in bfl if r["active"]), "bf_sources": len(bfl), "minutes": minutes,
                    "per_min_last": done},
            "bruteforce": bfl[:200],
            "top_src": [{"srcip": k, "count": v} for k, v in src.most_common(20)],
            "top_port": [{"port": k, "count": v} for k, v in port.most_common(20)],
            "ips": [{**r, "dst": sorted(x for x in r["dst"] if x)[:10]} for r in ips],
            "series": live, "recent": list(self.recent)[:150], "stats": dict(self.stats),
        }
