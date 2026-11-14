"""DR·보호(2.29.0) — SRM 복구 계획·보호 그룹, VM 스냅숏, Appliance 파일 기반 백업(vCenter·NSX·SDDC Manager), VM 백업 현황을 한곳에.

모두 읽기 전용 수집 결과를 모아 판정만 한다(스냅숏 삭제·백업 실행 같은 변경은 하지 않음).
  · Appliance 백업: 각 커넥터의 `protection` 속성 {kind:'appliance_backup', product, configured, schedule, last:{status, end, ...}, history:[...]}
  · SRM: SrmConnector.protection {kind:'srm', pairings, plans, groups, vms}
  · 스냅숏: vCenter 인프라 점검 스냅숏(health_snap.vms — 30분) + 권장 구성 판독용 VM 요약(bp_vms)
  · VM 백업: vCenter 사용자 정의 속성·메모(백업 SW 가 남긴 '마지막 백업' 값)를 읽어 추정 — 백업 SW API 를 직접 보지 않음
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

SNAP_MAX_H = 72                 # Broadcom KB 318825 — 한 스냅숏을 72시간 넘게 두지 않음
SNAP_CHAIN = 3                  # 체인 2~3개
APPL_MAX_H = 26                 # Appliance 백업: 마지막 성공이 26시간 이내(일 1회 + 여유)면 정상
VMB_WARN_H, VMB_BAD_H = 26, 7 * 24
# 백업 SW 가 남기는 임시 스냅숏 이름(작업 후 지워져야 함 — 남아 있으면 백업 실패·정리 실패 의심)
LEFTOVER_RX = re.compile(r"(?i)veeam|vadp|commvault|_?cv_snap|netbackup|nbu_snapshot|cohesity|rubrik|avamar|networker|arcserve|"
                         r"data ?protector|spectrum ?protect|tsm|consolidate helper|backup (temporary|temp)|vss.?snap|snapshot for backup|nakivo|vembu|hycu")
BACKUP_FIELD_RX = re.compile(r"(?i)backup|백업|veeam|nb_last|netbackup|commvault|cohesity|rubrik|avamar|nakivo|last ?protected")
_DT_PATTERNS = [
    (re.compile(r"(\d{4})[-./](\d{1,2})[-./](\d{1,2})[ T]+(\d{1,2}):(\d{2})(?::(\d{2}))?"), "ymd"),
    (re.compile(r"(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?", re.I), "mdy"),
    (re.compile(r"(\d{4})[-./](\d{1,2})[-./](\d{1,2})"), "ymd0"),
]


def parse_when(s: str, tz_offset: float = 0.0) -> float | None:
    """백업 SW 가 속성에 남긴 날짜 문자열 → epoch(초). 시간대 표기가 없으면 tz_offset(초, 기본 로컬)로 해석."""
    if not s:
        return None
    s = str(s)
    try:
        if re.match(r"^\d{4}-\d{2}-\d{2}T", s):
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp() - (0 if d.tzinfo else tz_offset)
    except ValueError:
        pass
    for rx, kind in _DT_PATTERNS:
        m = rx.search(s)
        if not m:
            continue
        g = m.groups()
        try:
            if kind == "ymd":
                d = datetime(int(g[0]), int(g[1]), int(g[2]), int(g[3]), int(g[4]), int(g[5] or 0), tzinfo=timezone.utc)
            elif kind == "mdy":
                h = int(g[3]) % 12 + (12 if (g[6] or "").upper() == "PM" else 0) if g[6] else int(g[3])
                d = datetime(int(g[2]), int(g[0]), int(g[1]), h, int(g[4]), int(g[5] or 0), tzinfo=timezone.utc)
            else:
                d = datetime(int(g[0]), int(g[1]), int(g[2]), tzinfo=timezone.utc)
        except ValueError:
            continue
        z = _ZONE_RX.match(s[m.end():]) if kind != "ymd0" else None       # 2.30.0 뒤에 붙은 시간대 표기(UTC·Z·GMT·+09:00)가 있으면 그대로 따름
        if z:
            off = 0.0
            sign, hh, mm = (z.group(2), z.group(3), z.group(4)) if z.group(2) else (z.group(5), z.group(6), z.group(7))
            if sign:
                off = (int(hh) * 3600 + int(mm) * 60) * (-1 if sign == "-" else 1)
            return d.timestamp() - off
        return d.timestamp() - tz_offset
    return None


_ZONE_RX = re.compile(r"\s*(?:(UTC|GMT|Z)(?![A-Za-z])\s*(?:([+-])(\d{2}):?(\d{2})(?!\d))?|([+-])(\d{2}):?(\d{2})(?!\d))", re.I)


def _local_offset() -> float:
    return float(time.localtime().tm_gmtoff)


def appliance_verdict(a: dict[str, Any], now: float, max_h: float = APPL_MAX_H) -> tuple[str, str]:
    """ok(최근 성공) · warn(오래됨·일정 없음) · bad(미설정·최근 실패) · unknown(조회 불가)"""
    if a.get("error"):
        return "unknown", a["error"]
    if a.get("configured") is False:
        return "bad", "백업이 설정되지 않음(백업 위치·일정 없음)"
    last = a.get("last") or {}
    ok_ts = a.get("last_success")
    st = str(last.get("status") or "").upper()
    if st in ("FAILED", "FAILURE", "FALSE", "ERROR"):
        return "bad", f"마지막 백업 실패{(' — ' + str(last.get('message'))[:120]) if last.get('message') else ''}"
    if not ok_ts:
        return ("warn", "일정은 있으나 성공한 백업 기록 없음") if a.get("schedule") else ("bad", "성공한 백업 기록 없음")
    age = (now - ok_ts) / 3600
    if age > max_h:
        return "warn", f"마지막 성공 {age:.0f}시간 전(기준 {max_h:.0f}시간)"
    if not a.get("schedule"):
        return "warn", "최근 성공했지만 자동 일정이 없음(수동 백업)"
    return "ok", f"마지막 성공 {age:.1f}시간 전"


def snapshots(vcs: list[tuple[str, dict]], now: float) -> dict[str, Any]:
    """vCenter 스냅숏 목록 → 행(VM·이름·나이·체인 수·플래그) + 요약"""
    rows = []
    for vc, snap in vcs:
        hosts = {**(snap.get("hosts_dr") or {}), **{k: v for k, v in (snap.get("hosts") or {}).items() if v.get("cluster")}}
        bp = {v["name"]: v for v in (snap.get("bp_vms") or {}).get("vms") or []}
        for v in snap.get("vms") or []:
            ss = v.get("snapshots") or []
            if not ss and not v.get("consolidation"):
                continue
            meta = bp.get(v["name"], {})
            host = meta.get("host", "")
            n = len(ss)
            oldest = min((s.get("created") or now for s in ss), default=now)
            for s in sorted(ss, key=lambda x: x.get("created") or 0) or [{"name": "", "created": None}]:
                age_h = (now - s["created"]) / 3600 if s.get("created") else None
                flags = []
                if age_h is not None and age_h > SNAP_MAX_H:
                    flags.append("72h")
                if n > SNAP_CHAIN:
                    flags.append("chain")
                if s.get("name") and LEFTOVER_RX.search(s["name"]):
                    flags.append("leftover")
                if v.get("consolidation"):
                    flags.append("consolidate")
                rows.append({"vcenter": vc, "vm": v["name"], "host": host, "cluster": (hosts.get(host) or {}).get("cluster", ""), "name": s.get("name", ""),
                             "created": s.get("created"), "age_h": round(age_h, 1) if age_h is not None else None, "chain": n,
                             "vm_oldest_h": round((now - oldest) / 3600, 1) if ss else None, "flags": flags})
    vms = {(r["vcenter"], r["vm"]) for r in rows}
    bad_vms = {(r["vcenter"], r["vm"]) for r in rows if r["flags"]}
    return {"rows": sorted(rows, key=lambda r: -(r["age_h"] or 0)), "vms": len(vms), "snapshots": sum(1 for r in rows if r["created"]),
            "violations": len(bad_vms), "over72": sum(1 for r in rows if "72h" in r["flags"]),
            "leftover": sum(1 for r in rows if "leftover" in r["flags"]), "consolidate": len({k for k in vms if any("consolidate" in r["flags"] for r in rows if (r["vcenter"], r["vm"]) == k)})}


def vm_backups(vcs: list[tuple[str, dict]], now: float) -> dict[str, Any]:
    """vCenter 사용자 정의 속성·메모에 백업 SW 가 남긴 '마지막 백업' → VM 별 경과 시간(추정)"""
    off = _local_offset()
    rows, fields = [], set()
    for vc, snap in vcs:
        hosts = {**(snap.get("hosts_dr") or {}), **{k: v for k, v in (snap.get("hosts") or {}).items() if v.get("cluster")}}
        for v in (snap.get("bp_vms") or {}).get("vms") or []:
            best, src = None, ""
            for k, val in (v.get("backup_fields") or {}).items():
                fields.add(k)
                t = parse_when(val, off)
                if t and t <= now + 3600 and (best is None or t > best):
                    best, src = t, k
            if best is None and v.get("notes_backup"):
                t = parse_when(v["notes_backup"], off)
                if t and t <= now + 3600:
                    best, src = t, "메모(Notes)"
            age = (now - best) / 3600 if best else None
            st = "none" if age is None else "ok" if age <= VMB_WARN_H else "warn" if age <= VMB_BAD_H else "bad"
            rows.append({"vcenter": vc, "vm": v["name"], "power": v.get("power", ""), "host": v.get("host", ""),
                         "cluster": (hosts.get(v.get("host", "")) or {}).get("cluster", ""), "last": best, "age_h": round(age, 1) if age is not None else None,
                         "source": src, "status": st})
    cnt = {k: sum(1 for r in rows if r["status"] == k) for k in ("ok", "warn", "bad", "none")}
    return {"rows": sorted(rows, key=lambda r: (["bad", "warn", "none", "ok"].index(r["status"]), -(r["age_h"] or 0))), "count": cnt,
            "fields": sorted(fields), "vms": len(rows),
            "note": "vCenter 사용자 정의 속성·메모에 백업 SW 가 남긴 '마지막 백업' 값으로 추정합니다(예: Veeam 'Last Backup' 메모, NetBackup 'NB_LAST_BACKUP' 속성). "
                    "값을 남기지 않는 백업 SW 는 '정보 없음'으로 보입니다."}


def build(connectors: list, now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    vcs, appl, srm = [], [], []
    for c in connectors:
        if not getattr(c, "enabled", True):
            continue
        p = getattr(c, "protection", None)
        if getattr(c, "type", "") == "vcenter" and getattr(c, "health_snap", None):
            vcs.append((c.name, c.health_snap))
        if not isinstance(p, dict):
            continue
        if p.get("kind") == "appliance_backup":
            v, why = appliance_verdict(p, now)
            appl.append({**{k: p.get(k) for k in ("product", "target", "configured", "schedule", "location", "last", "last_success", "history", "inventory", "error", "updated")},
                         "connector": c.name, "verdict": v, "why": why})
        elif p.get("kind") == "srm":
            srm.append({**p, "connector": c.name})
    plans = [x for s in srm for x in s.get("plans") or []]
    groups = [x for s in srm for x in s.get("groups") or []]
    pvms = [x for s in srm for x in s.get("vms") or []]
    bad_plan = [x for x in plans if x.get("verdict") == "bad"]
    bad_grp = [x for x in groups if x.get("verdict") == "bad"]
    snap = snapshots(vcs, now)
    vmb = vm_backups(vcs, now)
    ac = {k: sum(1 for a in appl if a["verdict"] == k) for k in ("ok", "warn", "bad", "unknown")}
    return {"generated": now,
            "summary": {"srm": {"connectors": len(srm), "pairings": sum(len(s.get("pairings") or []) for s in srm), "plans": len(plans), "plans_bad": len(bad_plan),
                                "groups": len(groups), "groups_bad": len(bad_grp), "protected_vms": len(pvms),
                                "vms_bad": sum(1 for x in pvms if x.get("verdict") == "bad")},
                        "snapshots": {k: snap[k] for k in ("vms", "snapshots", "violations", "over72", "leftover", "consolidate")},
                        "appliances": {"total": len(appl), **ac}, "vm_backup": {"vms": vmb["vms"], **vmb["count"]}},
            "srm": srm, "appliances": appl, "snapshots": snap, "vm_backups": vmb,
            "policy": {"snap_max_h": SNAP_MAX_H, "snap_chain": SNAP_CHAIN, "appliance_max_h": APPL_MAX_H, "vm_backup_warn_h": VMB_WARN_H, "vm_backup_bad_h": VMB_BAD_H}}


# ----------------------------------------------------------------- 커넥터별 응답 → protection 표준형
def srm_status_verdict(st: str) -> str:
    u = str(st or "").upper()
    if any(w in u for w in ("ERROR", "FAIL", "INCOMPLETE", "NOT_CONFIGURED", "NOT_PROTECTED", "DISCONNECT", "INVALID", "CANCEL")):
        return "bad"
    if any(w in u for w in ("READY", "OK", "PROTECTED", "SHADOWING", "SUCCESS", "RECOVERED", "COMPLETE")):
        return "ok"
    if any(w in u for w in ("RUNNING", "PROGRESS", "TEST", "CLEANUP", "PREPAR", "SYNC", "REPROTECT")):
        return "warn"
    return "unknown" if not u else "warn"


def nsx_overview(js: dict[str, Any], now: float) -> dict[str, Any]:
    """GET /api/v1/cluster/backups/overview → 표준형(판정 = cluster·node 백업, inventory 는 참고)"""
    cfg = js.get("backup_config") or {}
    hist = js.get("backup_operation_history") or {}
    items = []
    for k, label in (("cluster_backup_statuses", "클러스터"), ("node_backup_statuses", "노드"), ("inventory_backup_statuses", "인벤토리")):
        for x in hist.get(k) or []:
            items.append({"part": label, "success": bool(x.get("success")), "end": (x.get("end_time") or 0) / 1000 or None,
                          "start": (x.get("start_time") or 0) / 1000 or None, "message": x.get("error_message") or x.get("error_code") or ""})
    items.sort(key=lambda x: -(x["end"] or 0))
    # 2.30.0 판정은 클러스터·노드 백업만으로 — 자주 도는 인벤토리 백업의 성공이 클러스터·노드 백업 실패를 가리지 않게.
    # 부문별 최신 결과 중 실패가 있으면 그것이 '마지막 상태', 마지막 성공은 부문별(성공 기록이 있는 부문) 마지막 성공 중 가장 오래된 것. 인벤토리는 참고 표시만.
    per = {}
    for x in items:
        if x["part"] != "인벤토리":
            per.setdefault(x["part"], x)
    failed = [x for x in per.values() if not x["success"]]
    last = (failed or list(per.values()) or [{}])[0]
    oks = [max((x["end"] for x in items if x["part"] == part and x["success"] and x["end"]), default=None) for part in per]
    last_success = min((t for t in oks if t), default=None)
    inv = next((x for x in items if x["part"] == "인벤토리"), None)
    sch = cfg.get("backup_schedule") or {}
    sched = ""
    if cfg.get("backup_enabled"):
        if sch.get("resource_type") == "IntervalBackupSchedule" or sch.get("seconds_between_backups"):
            sched = f"{int(sch.get('seconds_between_backups') or 3600) // 60}분마다"
        elif sch.get("resource_type") == "WeeklyBackupSchedule":
            sched = f"매주 {','.join(str(d) for d in sch.get('days_of_week') or [])} {sch.get('hour_of_day', 0):02d}:{sch.get('minute_of_day', 0):02d}"
        else:
            sched = "자동"
    srv = (cfg.get("remote_file_server") or {})
    return {"kind": "appliance_backup", "product": "NSX Manager", "configured": bool(srv.get("server")) or bool(cfg.get("backup_enabled")),
            "schedule": sched, "location": f"{srv.get('protocol', {}).get('protocol_name', 'sftp') if isinstance(srv.get('protocol'), dict) else 'sftp'}://{srv.get('server', '')}{srv.get('directory_path', '')}" if srv.get("server") else "",
            "last": {"status": ("SUCCESS" if last.get("success") else "FAILED") if last else "", "end": last.get("end"), "message": last.get("message", ""),
                     "part": last.get("part", "")},
            "last_success": last_success, "history": items[:10],
            "inventory": ({"status": "SUCCESS" if inv["success"] else "FAILED", "end": inv["end"], "message": inv["message"]} if inv else None),
            "overall": hist.get("overall_backup_status") or "", "updated": now, "error": ""}


def vcenter_backup(schedules: Any, jobs: Any, now: float) -> dict[str, Any]:
    """GET /api/appliance/recovery/backup/schedules · /job/details → 표준형"""
    sch = schedules if isinstance(schedules, dict) else {}
    on = [s for s in sch.values() if isinstance(s, dict) and s.get("enable", True)]
    loc = ""
    sched = ""
    if on:
        s0 = on[0]
        loc = str((s0.get("location") or "")).split("@")[-1]
        rec = s0.get("recurrence_info") or {}
        days = rec.get("days") or []
        sched = (f"{'매일' if not days or len(days) == 7 else '매주 ' + ','.join(str(d)[:3] for d in days)} {int(rec.get('hour', 0)):02d}:{int(rec.get('minute', 0)):02d}"
                 if rec else "일정 있음(반복 정보 없음)")
    items = []
    jl = jobs.items() if isinstance(jobs, dict) else ((j.get("key") or j.get("id"), j.get("value") or j) for j in (jobs or []) if isinstance(j, dict))
    for jid, j in jl:
        if not isinstance(j, dict):
            continue
        end = j.get("end_time") or j.get("start_time")
        try:
            t = datetime.fromisoformat(str(end).replace("Z", "+00:00")).timestamp() if end else None
        except ValueError:
            t = None
        msgs = j.get("messages") or []
        items.append({"id": jid, "status": str(j.get("status") or ""), "end": t, "type": str(j.get("type") or ""), "size": j.get("size"),
                      "message": "; ".join(str((m or {}).get("default_message") or "") for m in msgs if isinstance(m, dict))[:200]})
    items.sort(key=lambda x: -(x["end"] or 0))
    ok = [x for x in items if x["status"].upper() == "SUCCEEDED" and x["end"]]
    last = items[0] if items else {}
    return {"kind": "appliance_backup", "product": "vCenter", "configured": bool(on) or bool(items), "schedule": sched, "location": loc,
            "last": {"status": "SUCCESS" if str(last.get("status", "")).upper() == "SUCCEEDED" else (last.get("status") or ""), "end": last.get("end"),
                     "message": last.get("message", ""), "type": last.get("type", "")},
            "last_success": max((x["end"] for x in ok), default=None), "history": items[:10], "updated": now, "error": ""}


def sddc_backup(cfg: dict[str, Any], last_task: dict[str, Any] | None, now: float) -> dict[str, Any]:
    """GET /v1/system/backup-configuration + 최근 백업 작업(/v1/tasks 중 이름·유형에 BACKUP) → 표준형"""
    sch = [s for s in (cfg.get("backupSchedules") or []) if str(s.get("resourceType", "")).upper() == "SDDC_MANAGER"]
    s0 = sch[0] if sch else {}
    sched = ""
    if s0.get("takeScheduledBackups"):
        sched = (f"{int(s0.get('minuteOfHour', 0))}분마다(매시)" if str(s0.get("frequency", "")).upper() == "HOURLY"
                 else f"매주 {','.join(str(d)[:3] for d in s0.get('daysOfWeek') or [])} {int(s0.get('hourOfDay', 0)):02d}:{int(s0.get('minuteOfHour', 0)):02d}")
    loc = (cfg.get("backupLocations") or [{}])[0]
    lt = last_task or {}
    st = str(lt.get("status") or "").upper()
    return {"kind": "appliance_backup", "product": "SDDC Manager", "configured": bool(cfg.get("isConfigured", bool(loc.get("server")))), "schedule": sched,
            "location": f"sftp://{loc.get('server', '')}{loc.get('directoryPath', '')}" if loc.get("server") else "",
            "last": {"status": "SUCCESS" if st in ("SUCCESSFUL", "COMPLETED") else st, "end": lt.get("end"), "message": lt.get("message", "")},
            "last_success": lt.get("last_success"), "history": [], "updated": now, "error": "",
            "note": "NSX Manager 백업 위치도 SDDC Manager 백업 구성으로 함께 관리됩니다(VCF)."}
