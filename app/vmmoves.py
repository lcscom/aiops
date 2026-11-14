"""VM 액티비티 — VM 에 일어난 일을 한 곳에: 생성·복제·배포·등록·삭제·이름 변경(2.4.2), 전원·구성 변경·스냅샷(2.5.0),
vMotion·DRS·Storage vMotion·콜드 이전, vSphere HA(재시작·리셋·실패·호스트 장애/격리), 인벤토리 비교(위치 변경·새 VM·사라진 VM).

  · 메모리(최근 20,000건) + SQLite vm_moves(최소 90일 보관)
  · 같은 vCenter 이벤트 키는 한 번만, 이벤트로 확인된 이동·생성·삭제와 겹치는 '인벤토리 비교' 기록은 생략
  · 위험 신호(2.5.0): 업무 외 시간 사람 변경 · 한 사용자의 대량 삭제/전원 끔 · 보호 VM 삭제·전원 끔·구성 변경·스냅샷 되돌림 · 단명 VM
    → 행 flags 로 표시하고, 대량 작업·보호 VM 은 이상징후 이벤트로도 올림(규칙은 화면에서 관리자 수정, DB 저장)
  · 요약: 유형·분류별 건수, 시간대별 추이, 호스트 간 흐름, 많이 옮겨진/자주 바뀐 VM, 사용자별 활동, HA 사건, 위험 신호
"""
from __future__ import annotations

import csv
import fnmatch
import io
import json
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Any

from .models import LogEvent
from .runtime import bg

SCHEMA = """CREATE TABLE IF NOT EXISTS vm_moves(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, vcenter TEXT, vm TEXT, type TEXT, from_host TEXT, to_host TEXT,
  from_ds TEXT, to_ds TEXT, cluster TEXT, user TEXT, msg TEXT, key TEXT UNIQUE);
CREATE INDEX IF NOT EXISTS ix_vm_moves_ts ON vm_moves(ts);
CREATE INDEX IF NOT EXISTS ix_vm_moves_vm ON vm_moves(vm);
CREATE TABLE IF NOT EXISTS vm_activity_rules(id INTEGER PRIMARY KEY, data TEXT, updated REAL, by TEXT);"""
EXTRA_COLS = ("source", "detail", "flags", "ip", "client", "via")   # 2.4.2 source · 2.5.0 detail·flags · 2.45.1 ip·client·via (기존 DB 는 ALTER 로 추가)
COLS = ("ts", "vcenter", "vm", "type", "from_host", "to_host", "from_ds", "to_ds", "cluster", "user", "msg", "key") + EXTRA_COLS

TYPES = {"vmotion": "vMotion", "drs": "DRS 자동 이동", "svmotion": "Storage vMotion", "relocate": "콜드 이전", "ha_restart": "HA 재시작",
         "ha_failed": "HA 재시작 실패", "ha_reset": "HA VM 리셋", "ha_reset_failed": "HA 리셋 실패", "host_failed": "호스트 장애(HA)",
         "host_isolated": "호스트 격리(HA)", "move_failed": "이동 실패", "detected": "위치 변경 감지",
         "created": "VM 생성", "cloned": "VM 복제", "deployed": "템플릿 배포", "registered": "VM 등록", "removed": "VM 삭제·등록 해제",
         "renamed": "VM 이름 변경", "create_failed": "생성 실패", "detected_new": "새 VM 감지", "detected_gone": "VM 사라짐 감지",
         "power_on": "전원 켬", "power_off": "전원 끔", "suspended": "일시 중단", "reset": "리셋", "guest_shutdown": "게스트 종료",
         "guest_reboot": "게스트 재시작", "reconfigured": "구성 변경", "snapshot_create": "스냅샷 생성", "snapshot_remove": "스냅샷 삭제",
         "snapshot_remove_all": "스냅샷 모두 삭제", "snapshot_revert": "스냅샷 되돌림"}
HA_TYPES = {"ha_restart", "ha_failed", "ha_reset", "ha_reset_failed", "host_failed", "host_isolated"}
CREATE_TYPES = {"created", "cloned", "deployed", "registered", "detected_new"}
DELETE_TYPES = {"removed", "detected_gone"}
POWER_TYPES = {"power_on", "power_off", "suspended", "reset", "guest_shutdown", "guest_reboot"}
SNAP_TYPES = {"snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert"}
CONFIG_TYPES = {"reconfigured", "renamed"} | SNAP_TYPES
LIFE_TYPES = CREATE_TYPES | DELETE_TYPES | {"renamed", "create_failed"}
FAIL_TYPES = {"move_failed", "create_failed"}
MOVE_TYPES = {"vmotion", "drs", "svmotion", "relocate", "detected"}
# 사람이 한 '변경'으로 보는 유형(업무 외 시간 판정 대상)
CHANGE_TYPES = CREATE_TYPES - {"detected_new"} | {"removed", "create_failed"} | CONFIG_TYPES | {"power_off", "reset", "suspended", "vmotion", "svmotion", "relocate"}
CATS = {"create": "생성", "delete": "삭제", "move": "이동", "ha": "HA", "power": "전원", "config": "구성·스냅샷", "fail": "실패"}
FLAG_LABEL = {"offhours": "업무 외", "bulk_delete": "대량 삭제", "bulk_power_off": "대량 전원 끔", "protected": "보호 VM", "short_lived": "단명 VM",
              "unplanned": "변경 창 밖", "in_window": "변경 창 안", "pingpong": "반복 이동"}
RISK_FLAGS = {"bulk_delete", "bulk_power_off", "protected", "short_lived", "unplanned", "pingpong"}
# 변경 창(유지보수 창) 판정 대상 — 사람이 한 계획 변경(전원 켬·게스트 재시작·인벤토리 감지는 제외)
WINDOW_TYPES = (CREATE_TYPES - {"detected_new"}) | {"removed", "reconfigured", "renamed", "snapshot_revert", "snapshot_remove_all", "power_off", "reset",
                                                    "suspended", "vmotion", "svmotion", "relocate"}

RULE_DEFAULTS: dict[str, Any] = {
    "tz": "Asia/Seoul", "business_hours": "09:00-18:00", "business_days": [1, 2, 3, 4, 5], "holidays": [],
    "bulk_delete_count": 5, "bulk_delete_minutes": 10, "bulk_power_off_count": 10, "bulk_power_off_minutes": 10,
    "protected": [], "short_lived_hours": 24,
    "change_window_check": False, "pingpong_count": 4, "pingpong_minutes": 60, "retention_days": 400,
    "service_accounts": ["*vpxd-extension*", "*vsphere-webclient*", "com.vmware.*", "*vsan-health*", "*wcp*", "*vlcm*", "*svc-*", "*svc_*"],
}


# ---------------------------------------------------------------- 2.45.1 실행 주체 — 어디서(IP)·무엇으로(클라이언트)
# vCenter 이벤트에는 사용자 이름만 있고 IP 는 없다. 같은 사용자의 로그인 이벤트(UserLoginSessionEvent: ipAddress·userAgent)와
# 지금 열린 세션(SessionManager.sessionList)을 맞춰 붙인다. ESXi 로컬 계정(dcui·vpxuser·root)은 그 호스트에서 직접 한 것 → 호스트 관리 IP.
HOST_LOCAL_USERS = {"dcui", "vpxuser", "root"}


def norm_user(u: str) -> str:
    """'VSPHERE.LOCAL\\admin' · 'admin@vsphere.local' · 'admin' → 'admin'(소문자)"""
    u = str(u or "").strip().lower()
    return u.split("\\")[-1].split("@")[0]


def client_of(agent: str) -> str:
    a = str(agent or "")
    al = a.lower()
    for k, v in (("powercli", "PowerCLI"), ("govc", "govc"), ("terraform", "Terraform"), ("pyvmomi", "pyVmomi(Python)"), ("ansible", "Ansible"),
                 ("vrealize", "VCF Automation·Aria"), ("aria", "VCF Automation·Aria"), ("vim-java", "Java SDK"), ("vsphere-client", "vSphere Client"),
                 ("vsphere client", "vSphere Client"), ("mozilla", "vSphere Client(브라우저)"), ("python", "Python"), ("go-http-client", "Go 클라이언트"),
                 ("curl", "curl"), ("veeam", "Veeam"), ("commvault", "Commvault"), ("rubrik", "Rubrik"), ("cohesity", "Cohesity"), ("nsx", "NSX")):
        if k in al:
            return v
    return a[:40]


def who_of(user: str, ts: float, logins: dict, live: list, host: str = "", host_ip: str = "", window: float = 12 * 3600) -> dict[str, str]:
    """logins = {norm_user: [(login_ts, ip, agent), ...]} · live = [{user, ip, agent, login, last}] → {ip, client, via}"""
    if not user:
        return {}
    n = norm_user(user)
    if n in HOST_LOCAL_USERS:
        return {"ip": host_ip, "client": "ESXi 호스트", "via": f"ESXi 로컬 계정 — {host or '호스트'} 에서 직접(호스트 관리 IP)"}
    cand = sorted((x for x in logins.get(n, []) if ts - window <= x[0] <= ts + 5), key=lambda x: -x[0])
    if cand:
        ips = list(dict.fromkeys(x[1] for x in cand if x[1]))
        via = f"로그인 이벤트 {time.strftime('%m-%d %H:%M', time.localtime(cand[0][0]))}"
        if len(ips) > 1:
            via += f" · 같은 계정 다른 IP {', '.join(ips[1:3])}"
        return {"ip": ips[0] if ips else "", "client": client_of(cand[0][2]), "via": via}
    ses = sorted((x for x in live if norm_user(x.get("user", "")) == n and (x.get("login") or 0) <= ts + 5), key=lambda x: -(x.get("last") or 0))
    if ses:
        ips = list(dict.fromkeys(x.get("ip", "") for x in ses if x.get("ip")))
        via = "현재 열린 세션" + (f" · 세션 {len(ses)}개(IP {', '.join(ips[:3])})" if len(ips) > 1 else "")
        return {"ip": ips[0] if ips else "", "client": client_of(ses[0].get("agent", "")), "via": via}
    return {"ip": "", "client": "", "via": "로그인 기록 없음(로그인이 수집 시작 전이거나 세션 목록 읽기 권한 없음)"}


def category(t: str) -> str:
    return "ha" if t in HA_TYPES else "fail" if t in FAIL_TYPES else "create" if t in CREATE_TYPES else "delete" if t in DELETE_TYPES \
        else "power" if t in POWER_TYPES else "config" if t in CONFIG_TYPES else "move"


def _flags(r: dict) -> set[str]:
    return {f for f in str(r.get("flags") or "").split(",") if f}


def _dur(sec: float) -> str:
    sec = int(max(0, sec))
    return f"{sec // 86400}일 {sec % 86400 // 3600}시간" if sec >= 86400 else f"{sec // 3600}시간 {sec % 3600 // 60}분" if sec >= 3600 else f"{max(1, sec // 60)}분"


def clean_rules(b: dict) -> dict[str, Any]:
    """규칙 입력 검증 — 범위를 벗어나면 ValueError(한국어 메시지)"""
    r = dict(RULE_DEFAULTS)
    for k in RULE_DEFAULTS:
        if k in b and b[k] is not None:
            r[k] = b[k]
    try:
        a, z = str(r["business_hours"]).split("-")
        for x in (a, z):
            h, m = x.strip().split(":")
            if not (0 <= int(h) <= 24 and 0 <= int(m) < 60):
                raise ValueError
        r["business_hours"] = f"{a.strip()}-{z.strip()}"
    except Exception:  # noqa: BLE001
        raise ValueError("업무 시간은 'HH:MM-HH:MM' 형식(예: 09:00-18:00)") from None
    days = r["business_days"]
    if isinstance(days, str):
        days = [int(x) for x in days.replace(" ", "").split(",") if x]
    if not all(isinstance(d, int) and 1 <= d <= 7 for d in days):
        raise ValueError("업무 요일은 1(월)~7(일) 숫자 목록")
    r["business_days"] = sorted(set(days))
    for k in ("holidays", "protected", "service_accounts"):
        v = r[k]
        if isinstance(v, str):
            v = [x.strip() for x in v.replace("\n", ",").split(",")]
        r[k] = [str(x).strip()[:120] for x in v if str(x).strip()][:500]
    for d in r["holidays"]:
        try:
            datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            raise ValueError(f"휴일 날짜 형식 오류: {d} (YYYY-MM-DD)") from None
    v = r["change_window_check"]
    r["change_window_check"] = v.strip().lower() in ("1", "true", "yes", "on", "예") if isinstance(v, str) else bool(v)
    for k, lo, hi in (("bulk_delete_count", 2, 1000), ("bulk_delete_minutes", 1, 1440), ("bulk_power_off_count", 2, 1000),
                      ("bulk_power_off_minutes", 1, 1440), ("short_lived_hours", 0, 24 * 90), ("pingpong_count", 0, 100),
                      ("pingpong_minutes", 5, 1440), ("retention_days", 90, 3650)):
        try:
            r[k] = int(r[k])
        except (TypeError, ValueError):
            raise ValueError(f"{k} 는 숫자") from None
        if not lo <= r[k] <= hi:
            raise ValueError(f"{k} 범위 {lo}~{hi}")
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(str(r["tz"]))
    except Exception:  # noqa: BLE001
        raise ValueError(f"시간대 이름 오류: {r['tz']} (예: Asia/Seoul)") from None
    return r


class MoveTracker:
    def __init__(self, engine):
        self.e = engine
        self.recent: deque = deque(maxlen=20000)
        self.keys: set[str] = set()
        self._schema = False
        self._rules: dict[str, Any] | None = None
        self._rules_meta: dict[str, Any] = {}
        self._win: dict[tuple, deque] = defaultdict(deque)      # (user, 종류) → 최근 ts (대량 작업 판정)
        self._alerted: dict[tuple, float] = {}
        self._tz = None

    # ------------------------------------------------------------------ 규칙
    def rules(self) -> dict[str, Any]:
        if self._rules is None:
            base = dict(RULE_DEFAULTS)
            base.update({k: v for k, v in ((getattr(self.e, "cfg", None) or {}).get("vm_activity") or {}).items() if k in RULE_DEFAULTS})
            try:
                if not self._schema:
                    self._ensure()
                row = self.e.store._conn.execute("SELECT data, updated, by FROM vm_activity_rules WHERE id=1").fetchone()
                if row:
                    base.update({k: v for k, v in json.loads(row[0]).items() if k in RULE_DEFAULTS})
                    self._rules_meta = {"updated": row[1], "by": row[2]}
            except Exception as ex:  # noqa: BLE001
                print(f"[vm-activity] 규칙 읽기 오류: {type(ex).__name__}: {ex}", flush=True)
            try:
                self._rules = clean_rules(base)
            except ValueError:
                self._rules = dict(RULE_DEFAULTS)
            self._tz = None
            self._apply_retention()
        return self._rules

    def _apply_retention(self) -> None:
        try:
            self.e.store.moves_retention = int(self._rules["retention_days"]) * 86400
        except Exception:  # noqa: BLE001
            pass

    def rules_view(self) -> dict[str, Any]:
        return {"rules": self.rules(), "defaults": RULE_DEFAULTS, **self._rules_meta}

    async def save_rules(self, b: dict, by: str) -> dict[str, Any]:
        r = clean_rules(b)
        if not self._schema:
            self._ensure()
        now = time.time()
        await self.e.store.x("INSERT OR REPLACE INTO vm_activity_rules(id, data, updated, by) VALUES(1, ?, ?, ?)", (json.dumps(r, ensure_ascii=False), now, by))
        self._rules, self._rules_meta, self._tz = r, {"updated": now, "by": by}, None
        self._apply_retention()
        return self.rules_view()

    def _zone(self):
        if self._tz is None:
            try:
                from zoneinfo import ZoneInfo
                self._tz = ZoneInfo(self.rules()["tz"])
            except Exception:  # noqa: BLE001
                self._tz = False
        return self._tz or None

    def is_service(self, user: str) -> bool:
        u = (user or "").lower()
        return not u or any(fnmatch.fnmatch(u, p.lower()) for p in self.rules()["service_accounts"])

    def offhours(self, ts: float) -> bool:
        r = self.rules()
        d = datetime.fromtimestamp(ts, self._zone()) if self._zone() else datetime.fromtimestamp(ts)
        if d.isoweekday() not in r["business_days"] or d.strftime("%Y-%m-%d") in r["holidays"]:
            return True
        a, z = r["business_hours"].split("-")
        hm = d.hour * 60 + d.minute
        ah, am = (int(x) for x in a.split(":"))
        zh, zm = (int(x) for x in z.split(":"))
        return not (ah * 60 + am <= hm < zh * 60 + zm)

    def protected(self, vm: str) -> str:
        v = (vm or "").lower()
        for p in self.rules()["protected"]:
            if fnmatch.fnmatch(v, p.lower()):
                return p
        return ""

    def _raise(self, row: dict, sev: str, msg: str, fp: str, flag: str) -> None:
        """위험 신호 → 이상징후 이벤트(같은 fp 는 파이프라인이 하나로 묶음)"""
        try:
            self.e.submit(LogEvent(source="vcenter", connector=row["vcenter"], message=msg, severity=sev, kind="event", entity=row["vm"] or row["user"],
                                   host=row["to_host"] or row["from_host"], ts=row["ts"],
                                   attrs={"eventType": f"AIOpsVmActivity.{flag}", "fp": fp, "user": row["user"], "vm_activity": flag}))
        except Exception as ex:  # noqa: BLE001
            print(f"[vm-activity] 위험 이벤트 오류: {type(ex).__name__}: {ex}", flush=True)

    def _assess(self, row: dict) -> None:
        """행에 flags·detail 보강 + 대량 작업·보호 VM 이벤트"""
        t, r, fl = row["type"], self.rules(), _flags(row)
        human = not self.is_service(row["user"])
        if human and t in CHANGE_TYPES and self.offhours(row["ts"]):
            fl.add("offhours")
        p = self.protected(row["vm"]) if t in DELETE_TYPES | {"power_off", "reconfigured", "snapshot_revert", "snapshot_remove_all", "renamed"} else ""
        if p and t != "detected_gone":
            fl.add("protected")
            sev = "critical" if t == "removed" else "error" if t in ("power_off", "snapshot_revert") else "warning"
            self._raise(row, sev, f"보호 VM {TYPES.get(t, t)}: {row['vm']} — 사용자 {row['user'] or '(시스템)'} (규칙 '{p}')",
                        f"vmact|protected|{row['vm']}|{t}", "protected")
        for kind, types, cnt_k, min_k in (("bulk_delete", {"removed"}, "bulk_delete_count", "bulk_delete_minutes"),
                                          ("bulk_power_off", {"power_off"}, "bulk_power_off_count", "bulk_power_off_minutes")):
            if t not in types or not human:
                continue
            k = (row["vcenter"], row["user"], kind)
            w, win = self._win[k], r[min_k] * 60
            w.append((row["ts"], row["vm"]))
            while w and row["ts"] - w[0][0] > win:
                w.popleft()
            if len(w) >= r[cnt_k]:
                fl.add(kind)
                if row["ts"] - self._alerted.get(k, 0) > win:
                    self._alerted[k] = row["ts"]
                    vms = [v for _, v in w]
                    self._raise(row, "critical" if kind == "bulk_delete" else "error",
                                f"VM {'대량 삭제' if kind == 'bulk_delete' else '대량 전원 끔'} — {row['user']} 가 {r[min_k]}분 안에 {len(w)}대: "
                                + ", ".join(vms[:10]) + (" …" if len(vms) > 10 else ""), f"vmact|{kind}|{row['vcenter']}|{row['user']}", kind)
                    for x in self.recent:                        # 같은 창의 앞선 행에도 표시
                        if x["type"] in types and x["user"] == row["user"] and row["ts"] - x["ts"] <= win and kind not in _flags(x):
                            x["flags"] = ",".join(sorted(_flags(x) | {kind}))
                            bg(self.e.store.x("UPDATE vm_moves SET flags=? WHERE key=?", (x["flags"], x["key"])))
        if human and t in WINDOW_TYPES:                      # 변경 창(유지보수 창) 안/밖
            win = self.change_window(row)
            if win:
                fl.add("in_window")
                row["detail"] = (row.get("detail") + " · " if row.get("detail") else "") + f"변경 창 '{win}'"
            elif r["change_window_check"]:
                fl.add("unplanned")
        if t in MOVE_TYPES - {"detected"} | {"ha_restart"} and r["pingpong_count"] and row["vm"]:   # 짧은 시간 반복 이동(DRS 핑퐁·자원 경합)
            win_s = r["pingpong_minutes"] * 60
            prior = [x for x in self.recent if x["vm"] == row["vm"] and x["vcenter"] == row["vcenter"] and x["type"] in MOVE_TYPES | {"ha_restart"}
                     and row["ts"] - x["ts"] <= win_s]
            if len(prior) + 1 >= r["pingpong_count"]:
                fl.add("pingpong")
                k = (row["vcenter"], row["vm"], "pingpong")
                if row["ts"] - self._alerted.get(k, 0) > win_s:
                    self._alerted[k] = row["ts"]
                    hosts = [h for x in prior + [row] for h in (x["from_host"], x["to_host"]) if h]
                    self._raise(row, "warning", f"VM 반복 이동 — {row['vm']} 가 {r['pingpong_minutes']}분 안에 {len(prior) + 1}회 이동 "
                                f"({' → '.join(dict.fromkeys(hosts))}) · DRS 규칙·자원 경합 확인", f"vmact|pingpong|{row['vcenter']}|{row['vm']}", "pingpong")
        if t in DELETE_TYPES and r["short_lived_hours"]:
            for x in reversed(self.recent):
                if row["ts"] - x["ts"] > r["short_lived_hours"] * 3600:
                    break
                if x["vm"] == row["vm"] and x["vcenter"] == row["vcenter"] and x["type"] in CREATE_TYPES:
                    fl.add("short_lived")
                    row["detail"] = (row.get("detail") + " · " if row.get("detail") else "") + f"수명 {_dur(row['ts'] - x['ts'])} ({TYPES[x['type']]} {x['user'] or ''})".rstrip()
                    break
        row["flags"] = ",".join(sorted(fl))

    def change_window(self, row: dict) -> str:
        """기록 시각에 열려 있고 대상(VM·호스트·클러스터)이 범위에 드는 유지보수 창 이름(인시던트 억제와 같은 창을 '승인된 변경 창'으로 사용)"""
        inc = getattr(self.e, "incidents", None)
        if not inc or not getattr(inc, "maint_cache", None):
            return ""
        host = row["to_host"] or row["from_host"]
        ev = {"host": host, "entity": row["vm"], "source": "vcenter"}
        ctx = {"host": host, "name": row["vm"], "cluster": row["cluster"]}
        for m in inc.maint_cache:
            try:
                if inc._in_window(m, row["ts"]) and inc._scope_match(m.get("scope") or {}, ev, ctx):
                    return str(m.get("name") or m.get("id"))
            except Exception:  # noqa: BLE001
                continue
        return ""

    async def related(self, vms: set[str] | list[str], hosts: set[str] | list[str] = (), clusters: set[str] | list[str] = (),
                      since: float = 0, until: float | None = None, limit: int = 30) -> list[dict[str, Any]]:
        """인시던트·이상징후 직전 VM 변경 — 대상 VM 자체 > 같은 호스트 > 같은 클러스터 순.
        메모리가 기간을 다 담지 못하면(재기동 직후 등) DB 에서 보충. 일상적인 시스템 전원 켬·인벤토리 감지는 제외"""
        vms, hosts, clusters = {v for v in vms if v}, {h for h in hosts if h}, {c for c in clusters if c}
        until = until or time.time()
        src = list(self.recent)
        if not src or src[0]["ts"] > since:
            if not self._schema:
                self._ensure()
            try:
                db = await self.e.store.q(f"SELECT {','.join(COLS)} FROM vm_moves WHERE ts>=? AND ts<=? ORDER BY ts LIMIT 20000", (since, until))
                seen = {r["key"] for r in src}
                src = [dict(r, severity="") for r in db if r["key"] not in seen] + src
            except Exception:  # noqa: BLE001
                pass
        out = []
        for r in reversed(src):
            if r["ts"] < since - 6 * 3600:                   # 기록 순서가 시각 순서와 조금 어긋날 수 있음(폴링 내 최신순) — 여유를 두고 중단
                break
            if r["ts"] > until or r["ts"] < since:
                continue
            if r["type"] in ("detected", "detected_new") or (r["type"] in ("power_on", "guest_reboot") and not r["user"]):
                continue
            rel = "vm" if r["vm"] in vms or (r.get("source") and r["source"] in vms) else \
                "host" if (r["from_host"] in hosts or r["to_host"] in hosts) else "cluster" if r["cluster"] in clusters else ""
            if rel:
                out.append({**r, "relation": rel})
        out.sort(key=lambda r: ({"vm": 0, "host": 1, "cluster": 2}[r["relation"]], -r["ts"]))
        return out[:limit]

    @staticmethod
    def names_of(rows: list[dict]) -> list[str]:
        """외부 AI 전송 시 가명화할 이름(VM·호스트·사용자(도메인\\계정과 계정)·원본·클러스터)"""
        out: set[str] = set()
        for r in rows:
            for k in ("vm", "from_host", "to_host", "user", "source", "cluster"):
                v = str(r.get(k) or "")
                if v:
                    out.add(v)
                    if k == "user" and "\\" in v:
                        out.add(v.split("\\", 1)[1])
        return sorted(out)

    @staticmethod
    def brief(rows: list[dict], now: float | None = None) -> list[str]:
        """AI 입력용 한 줄 요약(시각·관계·유형·VM·호스트·사용자·변경 내용·표시)"""
        rel = {"vm": "대상 VM", "host": "같은 호스트", "cluster": "같은 클러스터"}
        out = []
        for r in rows:
            mv = f"{r['from_host']}→{r['to_host']}" if r["from_host"] and r["to_host"] and r["from_host"] != r["to_host"] else (r["to_host"] or r["from_host"])
            out.append(" ".join(x for x in (time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), f"[{rel.get(r.get('relation'), '')}]", TYPES.get(r["type"], r["type"]),
                                             r["vm"], mv, f"by {r['user']}" if r["user"] else "", r.get("detail") or "",
                                             ("(" + ",".join(FLAG_LABEL.get(f, f) for f in sorted(_flags(r))) + ")") if r.get("flags") else "") if x))
        return out

    # ------------------------------------------------------------------ 기록
    def record(self, ev) -> dict[str, Any] | None:
        mv = dict(ev.attrs.get("move") or {})
        if not mv.get("type"):
            return None
        key = f"{mv.get('vcenter', ev.connector)}:{ev.native_id}" if ev.native_id else f"{mv.get('vcenter', '')}:{mv['type']}:{mv.get('vm')}:{int(ev.ts)}"
        if key in self.keys:
            return None
        if mv["type"] == "detected":
            for r in reversed(self.recent):
                if ev.ts - r["ts"] > 1800:
                    break
                if r["vm"] == mv.get("vm") and r["to_host"] == mv.get("to_host") and r["type"] in MOVE_TYPES | HA_TYPES:
                    return None
                if r["vm"] == mv.get("vm") and r["from_host"] == r["to_host"] and r["type"] in ("vmotion", "drs", "relocate", "ha_restart"):
                    r["from_host"], r["to_host"] = mv.get("from_host", ""), mv.get("to_host", "")   # 이벤트의 호스트 정보가 부족한 경우 보완
                    bg(self.e.store.x("UPDATE vm_moves SET from_host=?, to_host=? WHERE key=?", (r["from_host"], r["to_host"], r["key"])))
                    self.e.hub.publish({"type": "vm_move", "data": {**r, "enriched": True}})
                    return None
        if mv["type"] in ("detected_new", "detected_gone"):        # 이벤트로 이미 기록된 생성·삭제와 겹치면 생략
            want = CREATE_TYPES if mv["type"] == "detected_new" else DELETE_TYPES | {"renamed"}
            for r in reversed(self.recent):
                if ev.ts - r["ts"] > 7200:
                    break
                if r["vm"] == mv.get("vm") and r["type"] in want:
                    return None
        row = {"ts": ev.ts, "vcenter": mv.get("vcenter", ev.connector), "vm": mv.get("vm", ""), "type": mv["type"],
               "from_host": mv.get("from_host", ""), "to_host": mv.get("to_host", ""), "from_ds": mv.get("from_ds", ""), "to_ds": mv.get("to_ds", ""),
               "cluster": mv.get("cluster", ""), "user": mv.get("user", ""), "msg": (ev.attrs.get("vc_message") or ev.message)[:500], "key": key,
               "severity": ev.severity, "source": mv.get("source", "") or "", "detail": (mv.get("detail", "") or "")[:300], "flags": "",
               "ip": str(mv.get("ip", "") or "")[:64], "client": str(mv.get("client", "") or "")[:60], "via": str(mv.get("via", "") or "")[:160]}
        self.keys.add(key)
        if len(self.keys) > 60000:
            self.keys = {r["key"] for r in self.recent}
        try:
            self._assess(row)
        except Exception as ex:  # noqa: BLE001
            print(f"[vm-activity] 판정 오류: {type(ex).__name__}: {ex}", flush=True)
        self.recent.append(row)
        bg(self._save(row))
        self.e.hub.publish({"type": "vm_move", "data": row})
        return row

    def _ensure(self) -> None:
        """스키마 생성 + 추가 열(source·detail·flags) — 기존 DB 호환"""
        st = self.e.store
        st.schema(SCHEMA)
        self._schema = True
        try:
            cols = {r[1] for r in st._conn.execute("PRAGMA table_info(vm_moves)").fetchall()}
            for c in EXTRA_COLS:
                if c not in cols:
                    st.schema(f"ALTER TABLE vm_moves ADD COLUMN {c} TEXT DEFAULT '';")
            st.schema("CREATE INDEX IF NOT EXISTS ix_vm_moves_user ON vm_moves(user);")
        except Exception as e:  # noqa: BLE001
            print(f"[vm-moves] 스키마 갱신 오류: {type(e).__name__}: {e}", flush=True)

    async def _save(self, row: dict) -> None:
        st = self.e.store
        if not self._schema:
            self._ensure()
        try:
            await st.x(f"INSERT OR IGNORE INTO vm_moves({','.join(COLS)}) VALUES({','.join('?' * len(COLS))})", tuple(row.get(k, "") for k in COLS))
        except Exception as e:  # noqa: BLE001
            print(f"[vm-moves] 저장 오류: {type(e).__name__}: {e}", flush=True)

    # ------------------------------------------------------------------ 조회
    async def query(self, hours: float = 24, vm: str = "", types: list[str] | None = None, q: str = "", limit: int = 1000,
                    user: str = "", flag: str = "") -> list[dict[str, Any]]:
        since = time.time() - hours * 3600
        mem = [r for r in self.recent if r["ts"] >= since]
        rows = mem
        if not self.recent or self.recent[0]["ts"] > since:          # 메모리가 기간을 다 담지 못하면 DB
            st = self.e.store
            if not self._schema:
                self._ensure()
            try:
                db = await st.q(f"SELECT {','.join(COLS)} FROM vm_moves WHERE ts>=? ORDER BY ts DESC LIMIT 50000", (since,))
                seen = {r["key"] for r in mem}
                rows = mem + [dict(r, severity="") for r in db if r["key"] not in seen]
            except Exception:  # noqa: BLE001
                pass
        ql = q.lower()
        out = [r for r in rows if (not vm or r["vm"] == vm or (r.get("source") == vm and r["type"] in ("renamed", "cloned", "deployed")))
               and (not types or r["type"] in types) and (not user or (r["user"] or "") == user)
               and (not flag or (flag == "risk" and _flags(r) & RISK_FLAGS) or flag in _flags(r))
               and (not ql or ql in f"{r['vm']} {r['from_host']} {r['to_host']} {r['cluster']} {r['user']} {r['vcenter']} {r.get('source') or ''} {r.get('detail') or ''} {r.get('ip') or ''} {r.get('client') or ''}".lower())]
        out.sort(key=lambda r: -r["ts"])
        return out[:limit]

    async def summary(self, hours: float = 24) -> dict[str, Any]:
        rows = await self.query(hours, limit=50000)
        by_type = Counter(r["type"] for r in rows)
        by_cat = Counter(category(r["type"]) for r in rows)
        flows = Counter((r["from_host"], r["to_host"]) for r in rows if r["type"] in MOVE_TYPES | HA_TYPES and r["from_host"] and r["to_host"] and r["from_host"] != r["to_host"])
        vms = Counter(r["vm"] for r in rows if r["vm"] and r["type"] in MOVE_TYPES | HA_TYPES)
        cfg_vms = Counter(r["vm"] for r in rows if r["vm"] and r["type"] in CONFIG_TYPES)
        life = [r for r in rows if r["type"] in LIFE_TYPES]
        creators = Counter(r["user"] for r in life if r["user"] and r["type"] in CREATE_TYPES)
        deleters = Counter(r["user"] for r in life if r["user"] and r["type"] in DELETE_TYPES)
        step = 3600 if hours <= 72 else 86400 if hours > 24 * 14 else 3 * 3600
        step = 600 if hours <= 6 else step
        now = time.time()
        nb = int(hours * 3600 // step)
        keys = ("move", "ha", "fail", "create", "delete", "power", "config")
        series = [{"t": int((now // step - (nb - 1 - i)) * step), **{k: 0 for k in keys}} for i in range(nb)]
        base = series[0]["t"] if series else now
        for r in rows:
            i = int((r["ts"] - base) // step)
            if 0 <= i < nb:
                series[i][category(r["type"])] += 1
        incidents: dict[str, dict] = {}                      # HA 사건: 출발 호스트(또는 클러스터)별 묶음
        for r in sorted((r for r in rows if r["type"] in HA_TYPES), key=lambda r: r["ts"]):
            k = r["from_host"] or r["cluster"] or r["vcenter"]
            g = incidents.get(k)
            if not g or r["ts"] - g["last"] > 1800:
                g = incidents[k] = {"host": k, "cluster": r["cluster"], "first": r["ts"], "last": r["ts"], "vms": [], "types": Counter(), "targets": Counter()}
            g["last"] = r["ts"]
            g["types"][r["type"]] += 1
            if r["vm"] and r["vm"] not in g["vms"]:
                g["vms"].append(r["vm"])
            if r["to_host"] and r["to_host"] != k:
                g["targets"][r["to_host"]] += 1
        inc = sorted(({**g, "types": dict(g["types"]), "targets": dict(g["targets"].most_common(8)), "vm_count": len(g["vms"]), "vms": g["vms"][:50]}
                      for g in incidents.values()), key=lambda g: -g["last"])
        actors: dict[str, dict] = {}                          # 사용자별 활동(사람·서비스 계정 구분)
        for r in rows:
            u = r["user"] or ""
            a = actors.get(u)
            if a is None:
                a = actors[u] = {"user": u, "service": self.is_service(u), "total": 0, "cats": Counter(), "offhours": 0, "risk": 0, "last": 0.0, "vms": set(), "ips": Counter(), "clients": Counter()}
            a["total"] += 1
            if r.get("ip"):
                a["ips"][r["ip"]] += 1
            if r.get("client"):
                a["clients"][r["client"]] += 1
            a["cats"][category(r["type"])] += 1
            f = _flags(r)
            a["offhours"] += "offhours" in f
            a["risk"] += bool(f & RISK_FLAGS)
            a["last"] = max(a["last"], r["ts"])
            if r["vm"]:
                a["vms"].add(r["vm"])
        act = sorted(({**a, "cats": dict(a["cats"]), "vms": len(a["vms"]), "ips": [i for i, _ in a["ips"].most_common(5)],
                     "clients": [c for c, _ in a["clients"].most_common(3)]} for a in actors.values()), key=lambda a: (a["service"], -a["total"]))
        flagged = [r for r in rows if _flags(r)]
        risk_rows = [r for r in flagged if _flags(r) & RISK_FLAGS]
        offh = [r for r in flagged if "offhours" in _flags(r)]
        short = [r for r in risk_rows if "short_lived" in _flags(r)]
        return {"hours": hours, "total": len(rows), "by_type": dict(by_type), "by_cat": dict(by_cat), "cats": CATS, "labels": TYPES, "flag_labels": FLAG_LABEL,
                "step": step, "series": series,
                "flows": [{"from": a, "to": b, "count": c} for (a, b), c in flows.most_common(30)],
                "top_vms": [{"vm": v, "count": c} for v, c in vms.most_common(15)],
                "top_config_vms": [{"vm": v, "count": c} for v, c in cfg_vms.most_common(15)],
                "ha_incidents": inc[:30], "ha_total": sum(by_type.get(t, 0) for t in HA_TYPES),
                "move_total": sum(by_type.get(t, 0) for t in MOVE_TYPES),
                "created_total": sum(by_type.get(t, 0) for t in CREATE_TYPES),
                "deleted_total": sum(by_type.get(t, 0) for t in DELETE_TYPES),
                "fail_total": sum(by_type.get(t, 0) for t in FAIL_TYPES),
                "power_total": sum(by_type.get(t, 0) for t in POWER_TYPES),
                "config_total": sum(by_type.get(t, 0) for t in CONFIG_TYPES),
                "offhours_total": len(offh), "risk_total": len(risk_rows),
                "risk_counts": dict(Counter(f for r in risk_rows for f in _flags(r) & RISK_FLAGS)),
                "risks": risk_rows[:100], "offhours": offh[:100], "short_lived": short[:50],
                "creators": [{"user": u, "count": c} for u, c in creators.most_common(10)],
                "deleters": [{"user": u, "count": c} for u, c in deleters.most_common(10)],
                "actors": act[:40],
                "groups": {"move": sorted(MOVE_TYPES), "ha": sorted(HA_TYPES), "create": sorted(CREATE_TYPES), "delete": sorted(DELETE_TYPES),
                           "life": sorted(LIFE_TYPES), "fail": sorted(FAIL_TYPES), "power": sorted(POWER_TYPES), "config": sorted(CONFIG_TYPES)},
                "rules": self.rules()}

    def _locate(self, vm: str) -> dict[str, Any] | None:
        for c in self.e.connectors:
            v = ((getattr(c, "topology", None) or {}).get("vms") or {}).get(vm)
            if v:
                return {"vcenter": c.name, "host": v.get("host", ""), "cluster": v.get("cluster", ""), "power": v.get("power", ""),
                        "vcpu": v.get("vcpu"), "mem_mb": v.get("mem_mb"), "os": v.get("os", ""), "disk_gb": v.get("disk_gb"),
                        "snapshots": v.get("snapshots", 0), "datastores": v.get("datastores", [])[:4]}
        return None

    async def timeline(self, vm: str, days: float = 90) -> dict[str, Any]:
        """VM 한 대의 일대기 — 생성(누가·어디서·원본) → 이동·구성·전원·HA → 삭제, 현재 위치"""
        items = await self.query(days * 24, vm=vm, limit=3000)
        # 이름 변경 이전 이름까지 따라감(한 단계씩, 최대 5회)
        names, seen = [vm], {vm}
        for _ in range(5):
            prev = [r["source"] for r in items if r["type"] == "renamed" and r["vm"] in names and r.get("source") and r["source"] not in seen]
            if not prev:
                break
            for p in prev:
                seen.add(p)
                names.append(p)
                items += [r for r in await self.query(days * 24, vm=p, limit=2000) if r["key"] not in {x["key"] for x in items}]
        items.sort(key=lambda r: r["ts"])
        born = next((r for r in items if r["type"] in CREATE_TYPES and r["vm"] in names and not (r["type"] == "cloned" and r.get("source") in names and r["vm"] not in names)), None)
        gone = next((r for r in reversed(items) if r["type"] in DELETE_TYPES and r["vm"] == vm), None)
        cats = Counter(category(r["type"]) for r in items if r["vm"] in names)
        children = [r for r in items if r["type"] in ("cloned", "deployed") and r.get("source") in names and r["vm"] not in names]
        loc = self._locate(vm)
        return {"vm": vm, "names": names, "days": days, "items": items[::-1], "born": born, "gone": gone if not loc else None, "current": loc,
                "cats": dict(cats), "children": children[-20:], "labels": TYPES, "flag_labels": FLAG_LABEL,
                "age": (time.time() - born["ts"]) if born and not gone else None}

    @staticmethod
    def to_csv(rows: list[dict]) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["시각", "유형", "분류", "VM", "출발·이전 호스트", "도착·현재 호스트", "출발 데이터스토어", "도착 데이터스토어", "클러스터", "사용자", "실행 IP", "클라이언트", "IP 근거",
                    "원본·이전 이름", "상세", "표시", "vCenter", "메시지"])
        for r in rows:
            w.writerow([datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"), TYPES.get(r["type"], r["type"]), CATS.get(category(r["type"]), ""),
                        r["vm"], r["from_host"], r["to_host"], r["from_ds"], r["to_ds"], r["cluster"], r["user"], r.get("ip") or "", r.get("client") or "", r.get("via") or "", r.get("source") or "",
                        r.get("detail") or "", " ".join(FLAG_LABEL.get(f, f) for f in sorted(_flags(r))), r["vcenter"], (r.get("msg") or "").replace("\n", " ")])
        return "﻿" + buf.getvalue()

    def alarms(self) -> list[dict[str, Any]]:
        out = []
        for c in self.e.connectors:
            for a in getattr(c, "alarms", None) or []:
                out.append(a)
        out.sort(key=lambda a: ({"red": 0, "yellow": 1}.get(a["status"], 2), -a["ts"]))
        return out

    async def purge(self, days: float) -> None:
        if self._schema:
            await self.e.store.x("DELETE FROM vm_moves WHERE ts < ?", (time.time() - days * 86400,))
