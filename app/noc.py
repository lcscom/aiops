"""통합 관제(NOC) — 도메인 슬롯별(vCenter·ESXi / NSX·Edge / NSX ALB / VKS) 상태·알림 집계.

  GET  /api/noc          슬롯별 상태 판정 재료: 미확인 이상(판정 창), 개체 상태맵, 분당 이벤트, 커넥터, 활성 인시던트,
                         가장 오래 미확인된 위험·오류
  GET  /api/noc/brief    AI 상황 브리핑(Gemma 4 31B, 5분 캐시 — LLM 비활성 시 규칙 기반 요약). ?refresh=1 은 운영자 이상
  에스컬레이션 루프       미확인 위험이 noc.escalate_minutes 를 넘기면 알림 채널로 1회 재발송 + 감사 기록
화면(/noc)은 이후 WebSocket(/ws: anomaly·logs·status·incident·alert·noc_brief)으로 실시간 갱신한다.
슬롯 정의는 config noc.slots 로 바꿀 수 있다: [{id, name, scope, sources: [...], types: [...]}]
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from . import vsan as VS
from .models import SEV_RANK
from .sanitize import clean

DEFAULT_SLOTS: list[dict[str, Any]] = [
    {"id": "vc", "name": "vCenter", "scope": "vCenter 와 ESXi 호스트", "sources": ["vcenter", "esxi"], "types": ["vcenter"]},
    {"id": "vsan", "name": "vSAN", "scope": "vSAN 클러스터·디스크 그룹·vSAN 로그 + 비 vSAN 데이터스토어(로컬·외장·NFS)", "sources": ["vcenter", "esxi"],
     "types": ["vcenter"], "filter": "vsan"},
    {"id": "nsx", "name": "NSX", "scope": "NSX Manager 와 Edge", "sources": ["nsx", "nsx-edge"], "types": ["nsx"]},
    {"id": "avi", "name": "NSX ALB", "scope": "Avi 컨트롤러·서비스 엔진·가상 서비스", "sources": ["avi"], "types": ["avi"]},
    {"id": "vks", "name": "VKS", "scope": "Supervisor 와 워크로드 클러스터", "sources": ["vks", "vks-supervisor"], "types": ["vks"]},
    {"id": "srv", "name": "물리 서버", "scope": "서버 BMC(Redfish 실시간 이벤트·부품) · 물리 서버 OS", "sources": ["redfish", "ucs", "baremetal"],
     "types": ["redfish", "ucsm"], "agents": "baremetal"},
    {"id": "vmg", "name": "VM 게스트", "scope": "VM 내부 OS·애플리케이션 로그(에이전트)", "sources": ["vm"], "types": [], "agents": "vm"},
    {"id": "sec", "name": "보안(방화벽)", "scope": "FortiGate syslog(무차별 대입·스캔·IPS)·REST 상태", "sources": ["fortigate"], "types": ["fortigate"]},
    {"id": "net", "name": "네트워크", "scope": "Arista·Cisco 스위치·라우터 — syslog·LLDP/CDP 이웃·인터페이스·MLAG/vPC·BGP",
     "sources": ["arista", "cisco", "network"], "types": ["arista", "cisco", "nxos", "iosxe", "snmp-switch"]},
]
STATE_KO = {"down": "장애", "warn": "주의", "ok": "정상", "idle": "대기"}
BRIEF_DOMAINS = "vCenter·ESXi / vSAN / NSX·Edge / NSX ALB / VKS / 물리 서버 / VM 게스트 / 보안(방화벽) / 네트워크(Arista·Cisco)"


def _vf(d: dict) -> bool:
    return d.get("filter") == "vsan"


def _rate_srcs(d: dict) -> set[str]:
    """분당 집계 키 — vSAN 도메인은 엔진이 따로 세는 가상 소스 'vsan'"""
    return {"vsan"} if _vf(d) else set(d["sources"])


def _ago(sec: float) -> str:
    return f"{int(sec // 60)}분" if sec < 3600 else f"{int(sec // 3600)}시간 {int(sec % 3600 // 60)}분"


def slots(cfg: dict) -> list[dict]:
    return (cfg.get("noc") or {}).get("slots") or DEFAULT_SLOTS


def _is_open(a: dict, now: float, window: float) -> bool:
    return (not a["ack"] and (a.get("ai") or {}).get("is_anomaly") is not False and not a.get("suppressed")
            and now - a["last_seen"] < window)


def _keys(a: dict) -> set[str]:
    e = a.get("event") or {}
    out = set()
    for v in (e.get("host"), e.get("entity"), (e.get("attrs") or {}).get("node")):
        if v:
            v = str(v).lower()
            out.add(v)
            out.add(v.split("/")[-1])
            out.add(v.split(".")[0])
            if v.startswith(("edge:", "agent:")):
                out.add(v.split(":", 1)[1])
    return out


def _overlay(entities: list[dict], open_: list[dict]) -> list[dict]:
    """개체별 열린 이상 징후를 겹쳐 상태 상향(위험→장애, 오류·경고→주의)"""
    idx: dict[str, dict] = {}
    for en in entities:
        en["base"] = en.get("state", "unknown")          # 화면에서 실시간 재겹침용 원 상태
        en.setdefault("alerts", 0)
        en.setdefault("worst", "")
        n = en["name"].lower()
        for k in (n, n.split(".")[0]):
            idx.setdefault(k, en)
    for a in open_:
        for k in _keys(a):
            en = idx.get(k)
            if not en:
                continue
            en["alerts"] += 1
            if SEV_RANK.get(a["severity"], 0) > SEV_RANK.get(en["worst"] or "debug", 0):
                en["worst"] = a["severity"]
            if a["severity"] == "critical":
                en["state"] = "down"
            elif a["severity"] in ("error", "warning") and en["state"] in ("ok", "unknown"):
                en["state"] = "warn"
            break
    return entities


def _health(s: dict) -> tuple[str, str]:
    c = s["counts"]
    down = sum(1 for x in s["connectors"] if x["state"] == "down")
    deg = sum(1 for x in s["connectors"] if x["state"] == "degraded")
    ents_down = sum(1 for e in s["entities"] if e["state"] == "down")
    stale = s.get("stale")
    if c["critical"] or any(i["severity"] == "critical" for i in s["incidents"]) or ents_down:
        st = "down"
    elif (c["error"] or c["warning"] or down or deg or s["incident_count"] or stale
          or any(e["state"] == "warn" for e in s["entities"])):
        st = "warn"
    elif not s["connectors"] and not s["anomalies"] and not any(s["rate"]):
        st = "idle"
    else:
        st = "ok"
    why = [f"{k} {v}건" for k, v in (("위험", c["critical"]), ("오류", c["error"]), ("경고", c["warning"])) if v]
    if ents_down:
        why.append(f"개체 장애 {ents_down}")
    if down:
        why.append(f"커넥터 오류 {down}")
    if stale:
        why.append(f"데이터 수신 지연 {_ago(s['fresh_age'])}" if s.get("fresh_age") else "데이터 수신 기록 없음")
    return st, ", ".join(why)


async def snapshot(ENGINE, CFG: dict, only: str | None = None) -> dict[str, Any]:
    now = time.time()
    defs = slots(CFG)
    if only:
        defs = [d for d in defs if d["id"] == only]
    window = float((CFG.get("noc") or {}).get("window_minutes", 30)) * 60
    stale_s = float((CFG.get("noc") or {}).get("stale_minutes", 10)) * 60
    inc_rows = await ENGINE.store.q(
        "SELECT id,title,severity,status,assignee,created,updated,last_anomaly,sources,sla,maintenance,itsm "
        "FROM incidents WHERE status IN ('open','acknowledged','investigating') ORDER BY updated DESC LIMIT 300")
    for x in inc_rows:
        for k in ("sources", "sla", "itsm"):
            try:
                x[k] = json.loads(x[k]) if x[k] else ({} if k != "sources" else [])
            except (TypeError, ValueError):
                x[k] = {} if k != "sources" else []
    anoms = sorted((a.to_dict() for a in ENGINE.anomalies.values()), key=lambda a: a["last_seen"], reverse=True)
    out = []
    for d in defs:
        srcs = set(d["sources"])
        rate, syslog5 = ENGINE.minutes.series(_rate_srcs(d))          # 메모리 분당 집계(DB 스캔 없음)
        mine_all = [a for a in anoms if a["event"].get("source") in srcs and (not _vf(d) or VS.is_vsan_anomaly(a))]
        mine = mine_all[:100]
        open_ = [a for a in mine_all if _is_open(a, now, window)]
        counts = {s: sum(1 for a in open_ if a["severity"] == s) for s in ("critical", "error", "warning")}
        conns = [c for c in ENGINE.connectors if getattr(c, "type", "") in d["types"]]
        ents: list[dict] = []
        for c in conns if not _vf(d) else []:
            try:
                ents += [dict(e, source=c.name) for e in c.entities()]
            except Exception:  # noqa: BLE001
                pass
        if _vf(d):
            try:
                ents = VS.entities(ENGINE)
            except Exception:  # noqa: BLE001
                ents = []
        if "fortigate" in srcs and getattr(ENGINE, "fortigate", None):   # syslog 로만 들어오는 FortiGate 장비
            have = {e["name"].lower() for e in ents}
            ents += [e for e in ENGINE.fortigate.entities() if e["name"].lower() not in have]
        if d.get("agents"):                                 # 에이전트 레지스트리(VM 게스트·물리 서버 OS)
            ents += ENGINE.agents.entities(d["agents"])
        ents = _overlay(ents, open_)
        crit_err = [a for a in open_ if a["severity"] in ("critical", "error")]
        oldest = min(crit_err, key=lambda a: a["created"]) if crit_err else None
        incs = [i for i in inc_rows if srcs & set(i["sources"] or []) and (not _vf(d) or VS.is_vsan_text(i.get("title")))]
        # 데이터 신선도: 마지막 수신(로그·이벤트) 또는 커넥터 폴링 성공 중 최신 — '정상'으로 보이는데 사실 끊긴 상태 방지
        last = max([ENGINE.minutes.last_seen(_rate_srcs(d))] + [c.state().get("last_ok") or 0 for c in conns]
                   + [max(a.get("last_seen") or 0, a.get("last_hb") or 0) for a in ENGINE.agents.items.values()
                      if d.get("agents") and a.get("kind") == d["agents"] and not a.get("retired")])
        has_feed = bool(conns) or any(rate) or last > 0
        fresh_age = now - last if last else None
        stale = bool(stale_s and has_feed and (fresh_age is None or fresh_age > stale_s))
        s = {**d, "rate": rate, "last_data": last or None, "fresh_age": fresh_age, "stale": stale, "syslog_5m": syslog5, "counts": counts, "anomalies": mine,
             "incidents": incs[:20], "incident_count": len(incs), "entities": ents,
             "oldest_unack": {"id": oldest["id"], "created": oldest["created"], "severity": oldest["severity"],
                              "title": oldest["title"]} if oldest else None,
             "connectors": [{k: c.state().get(k) for k in ("name", "type", "state", "latency_ms", "last_error", "target", "last_ok")}
                            for c in conns]}
        s["state"], s["why"] = _health(s)
        out.append(s)
    return {"slots": out, "window_minutes": window / 60, "generated": now, "stale_minutes": stale_s / 60,
            "runtime": ENGINE.runtime(),
            "escalate_minutes": float((CFG.get("noc") or {}).get("escalate_minutes", 15)),
            "llm": ENGINE.llm.status if ENGINE.llm else {"state": "disabled"}}


# ---------------------------------------------------------------- 도메인 상세 탭
EV_COLS = "ts,source,connector,severity,host,entity,kind,message,attrs"


async def _recent(ENGINE, srcs: set[str], hours: float, limit: int, sev_min: bool = False, host: str = "", vsan: bool = False) -> list[dict]:
    """소스별로 (source, ts) 인덱스를 역순으로 읽어 합침 — IN(...) 정렬 스캔을 피한다. vsan=True 면 vSAN 관련 메시지만"""
    since = time.time() - hours * 3600
    out: list[dict] = []
    for src in sorted(srcs):
        cond = " AND severity IN ('warning','error','critical')" if sev_min else ""
        args: list = [src, since]
        if vsan:
            cond += VS.sql_cond()
            args += VS.sql_args()
        if host:
            h = host.lower()
            cond += " AND (lower(host)=? OR lower(entity)=? OR lower(host) LIKE ?)"
            args += [h, h, h.split(".")[0] + ".%"]
        try:
            out += await ENGINE.store.q(f"SELECT {EV_COLS} FROM logs WHERE source=? AND ts>?{cond} ORDER BY ts DESC LIMIT ?",
                                        (*args, limit))
        except Exception:  # noqa: BLE001
            pass
    out.sort(key=lambda r: -(r.get("ts") or 0))
    for r in out[:limit]:
        try:
            a = json.loads(r.get("attrs") or "{}")
        except (TypeError, ValueError):
            a = {}
        r["attrs"] = {k: a[k] for k in list(a)[:12] if not str(k).startswith("_") and isinstance(a[k], (str, int, float, bool))}
    return out[:limit]


IMPORTANT_TTL = 45.0


async def _important(ENGINE, srcs: set[str], vsan: bool = False) -> list[dict]:
    """도메인 상세의 '24시간 주요 이벤트' — 화면이 10초마다 다시 부르므로 도메인(소스 묶음)별 45초 캐시 + 동시 요청은 1회만 조회(2.30.0)"""
    key = (tuple(sorted(srcs)), bool(vsan))
    cache = getattr(ENGINE, "_noc_imp", None)
    if cache is None:
        cache = ENGINE._noc_imp = {}
        ENGINE._noc_imp_locks = {}
    hit = cache.get(key)
    if hit and time.time() - hit[0] < IMPORTANT_TTL:
        return hit[1]
    lock = ENGINE._noc_imp_locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = cache.get(key)
        if hit and time.time() - hit[0] < IMPORTANT_TTL:
            return hit[1]
        rows = await _recent(ENGINE, srcs, 24, 60, sev_min=True, vsan=vsan)
        cache[key] = (time.time(), rows)
        return rows


def _panels(ENGINE, sid: str, d: dict, conns: list) -> list[dict]:
    """도메인 전용 표 — [{title, cols:[[key,label]], rows:[{...}], note}]"""
    P: list[dict] = []
    types = set(d.get("types") or [])
    srcs = set(d.get("sources") or [])
    if _vf(d):
        v = VS.collect(ENGINE)
        P.append({"id": "vsan-cl", "title": "vSAN 클러스터", "cols": [["state", "상태"], ["name", "클러스터"], ["health_ko", "vSAN Health"], ["health_red", "장애 점검"], ["health_yellow", "주의 점검"],
                                                                   ["hosts", "호스트"], ["down", "연결 끊김"], ["maint", "유지보수"], ["unhealthy", "비정상 노드"],
                                                                   ["disk_groups", "디스크 그룹"], ["cap_disks", "용량 디스크"], ["issues", "디스크 문제"],
                                                                   ["capacity_gb", "용량 GB"], ["free_gb", "여유 GB"], ["used_pct", "사용 %"], ["dedup", "중복제거·압축 비율"], ["objects", "객체 상태"],
                                                                   ["datastores", "데이터스토어"]],
                  "rows": v["clusters"], "empty": "vSAN 이 켜진 클러스터가 없습니다(클러스터 configurationEx.vsanConfigInfo.enabled)"})
        P.append({"id": "vsan-health", "title": "vSAN Health 점검", "cols": [["health_ko", "상태"], ["cluster", "클러스터"], ["group", "분류"], ["test", "점검 항목"], ["entities", "정상/전체"],
                                                                        ["desc", "설명"], ["risk", "방치 시 위험"]],
                  "rows": v["health_tests"] + [{"health_ko": g["health_ko"], "cluster": g["cluster"], "group": g["group"], "test": f"(분류 전체 {g['tests']}개 점검)", "entities": "",
                                                "desc": g["bad_names"] or "모두 정상", "risk": ""} for g in v["health_groups"] if not g["bad"]],
                  "empty": "vSAN Health 결과 없음 — 커넥터 점검의 'vSAN Health' 항목(/vsanHealth 연결·pyvmomi 8.0.3 이상) 확인"})
        P.append({"id": "vsan-host", "title": "vSAN 호스트·디스크 그룹", "cols": [["state", "상태"], ["name", "호스트"], ["cluster", "클러스터"], ["role", "노드 역할"], ["health", "health"],
                                                                          ["members", "멤버"], ["disk_groups", "디스크 그룹"], ["cache", "캐시"], ["capacity", "용량"], ["issues", "디스크 문제"]],
                  "rows": v["hosts"], "empty": "vSAN 호스트 정보 없음 — vCenter 인벤토리 갱신(5분) 후 표시"})
        P.append({"id": "vsan-ds", "title": "vSAN 데이터스토어", "cols": [["state", "상태"], ["name", "데이터스토어"], ["capacity_gb", "용량 GB"], ["free_gb", "여유 GB"], ["used_pct", "사용 %"],
                                                                    ["prov_gb", "할당 GB"], ["hosts", "호스트"], ["vms", "VM"], ["vcenter", "vCenter"]], "rows": v["datastores"]})
        al = [a for a in ENGINE.moves.alarms() if VS.is_vsan_text(a.get("name"), a.get("entity"))][:80]
        P.append({"id": "vsan-alarms", "title": "vSAN 알람", "cols": [["status", "등급"], ["name", "알람"], ["entity", "대상"], ["ts", "발생"]],
                  "rows": [{k: a.get(k) for k in ("status", "name", "entity", "ts")} for a in al], "empty": "발생 중인 vSAN 관련 vCenter 알람이 없습니다"})
        P.append({"id": "nonvsan", "section": True, "title": "vSAN 이 아닌 데이터스토어 — 로컬 디스크 · 외장 스토리지(SAN) · NFS · vVols",
                  "summary": v["other_summary"],
                  "cols": [["state", "상태"], ["class", "분류"], ["name", "데이터스토어"], ["type", "유형"], ["capacity_gb", "용량 GB"], ["free_gb", "여유 GB"], ["used_pct", "사용 %"],
                           ["hosts", "호스트 수"], ["host_names", "호스트"], ["vms", "VM"], ["backing", "백엔드(LUN·NAS)"], ["vmfs", "VMFS"], ["vcenter", "vCenter"]],
                  "rows": v["other"], "empty": "vSAN 외 데이터스토어가 없습니다"})
        return P
    if "vcenter" in types:
        al = [a for a in ENGINE.moves.alarms()][:80]
        P.append({"id": "alarms", "title": "vCenter 트리거 알람", "cols": [["status", "등급"], ["name", "알람"], ["entity", "대상"], ["etype", "유형"], ["ts", "발생"]],
                  "rows": [{k: a.get(k) for k in ("status", "name", "entity", "etype", "ts")} for a in al],
                  "empty": "현재 발생 중인 vCenter 알람이 없습니다"})
        cl = []
        for c in conns:
            t = getattr(c, "topology", {}) or {}
            hosts, vms = t.get("hosts", {}), t.get("vms", {})
            for cn, x in sorted(t.get("clusters", {}).items()):
                hs = [hosts.get(h, {}) for h in x.get("hosts", [])]
                cpu = sum(h.get("cpu_mhz", 0) for h in hs)
                mem = sum(h.get("mem_mb", 0) for h in hs)
                cl.append({"name": cn, "vcenter": c.name, "hosts": len(hs),
                           "bad": sum(1 for h in hs if h.get("conn") not in ("connected", "")),
                           "maint": sum(1 for h in hs if h.get("maintenance")),
                           "vms": sum(1 for v in vms.values() if v.get("host") in x.get("hosts", [])),
                           "cpu": round(sum(h.get("cpu_used_mhz", 0) for h in hs) / cpu * 100) if cpu else None,
                           "mem": round(sum(h.get("mem_used_mb", 0) for h in hs) / mem * 100) if mem else None})
        P.append({"id": "clusters", "title": "클러스터", "cols": [["name", "클러스터"], ["vcenter", "vCenter"], ["hosts", "호스트"], ["bad", "연결 끊김"],
                                                             ["maint", "유지보수"], ["vms", "VM"], ["cpu", "CPU %"], ["mem", "메모리 %"]], "rows": cl})
        P.append({"id": "moves", "title": "VM 액티비티 (최근)", "kind": "moves", "rows": list(ENGINE.moves.recent)[-40:][::-1]})
    if "nsx" in types:
        rows = []
        moid = {}
        for vc in ENGINE.connectors:                     # vCenter 호스트 moid → ESXi 이름
            if getattr(vc, "type", "") == "vcenter":
                for hn, h in ((getattr(vc, "topology", {}) or {}).get("hosts", {}) or {}).items():
                    if h.get("moid"):
                        moid[h["moid"]] = hn
        for c in conns:
            st = getattr(c, "_edge_state", {}) or {}
            for eid, nm in (getattr(c, "edges", {}) or {}).items():
                i = (getattr(c, "edge_info", {}) or {}).get(eid, {})
                rows.append({"name": nm, "state": st.get(eid, "UNKNOWN"), "cluster": i.get("edge_cluster", ""), "host": moid.get(i.get("host_moid", "")) or i.get("host_moid") or i.get("compute", ""),
                             "ip": i.get("mgmt_ip", ""), "form": i.get("form", ""), "nsx": c.name})
        P.append({"id": "edges", "title": "NSX Edge 노드", "cols": [["state", "상태"], ["name", "Edge"], ["cluster", "Edge 클러스터"], ["host", "ESXi"],
                                                               ["ip", "관리 IP"], ["form", "크기"], ["nsx", "NSX"]], "rows": rows,
                  "empty": "수집된 Edge 가 없습니다 — 커넥터 점검의 'Edge 목록' 항목을 확인하세요"})
        gw = []
        for c in conns:
            inv = getattr(c, "inv", {}) or {}
            for k, lab in (("tier0", "Tier-0"), ("tier1", "Tier-1")):
                for g in inv.get(k, []) or []:
                    if isinstance(g, dict):
                        gw.append({"kind": lab, "name": g.get("name") or g.get("id", ""), "ha": g.get("ha_mode", ""), "ec": g.get("edge_cluster_id", ""), "nsx": c.name})
        if gw:
            P.append({"id": "gateways", "title": "게이트웨이", "cols": [["kind", "유형"], ["name", "이름"], ["ha", "HA 모드"], ["ec", "Edge 클러스터"], ["nsx", "NSX"]], "rows": gw[:200]})
    if "avi" in types:
        vs, se = [], []
        for c in conns:
            try:
                vs += [{**v, "ctrl": c.name, "ses": ", ".join((getattr(c, "vs", {}).get(v.get("uuid"), {}) or {}).get("ses", [])[:4])} for v in c.vips()]
            except Exception:  # noqa: BLE001
                pass
            for n, x in (getattr(c, "se", {}) or {}).items():
                se.append({"name": n, "state": x.get("state", ""), "se_group": x.get("se_group", ""), "host": x.get("host", ""), "ip": x.get("mgmt_ip", ""),
                           "health": x.get("health", ""), "vs": len(x.get("vs") or []), "ctrl": c.name})
        vs.sort(key=lambda v: (str(v.get("state")) == "OPER_UP", v.get("name", "")))
        fmt_b = lambda b: "" if b is None else f"{b / 1e6:.1f} MB/s" if b >= 1e6 else f"{b / 1e3:.1f} kB/s" if b >= 1e3 else f"{b:.0f} B/s"   # noqa: E731
        fmt_n = lambda x: "" if x is None else f"{x:.1f}"   # noqa: E731
        P.append({"id": "vs", "title": "가상 서비스", "cols": [["state", "상태"], ["name", "가상 서비스"], ["tenant", "테넌트"], ["vips", "VIP"], ["ports", "포트"], ["ses", "SE"],
                                                             ["rx", "수신"], ["tx", "송신"], ["cps", "연결/초"], ["rps", "응답/초"], ["r4xx", "4xx/초"], ["r5xx", "5xx/초"],
                                                             ["members", "풀 멤버"], ["metric", "메트릭"], ["ctrl", "컨트롤러"]],
                  "rows": [{**{k: v.get(k) for k in ("state", "name", "ses", "ctrl", "tenant")}, "vips": ", ".join(map(str, v.get("vips") or [])),
                            "rx": fmt_b((v.get("last") or {}).get("rx")), "tx": fmt_b((v.get("last") or {}).get("tx")),
                            "cps": fmt_n((v.get("last") or {}).get("cps")), "rps": fmt_n((v.get("last") or {}).get("rps")),
                            "r4xx": fmt_n((v.get("last") or {}).get("r4xx")), "r5xx": fmt_n((v.get("last") or {}).get("r5xx")),
                            "members": f"{v.get('pool_up') if v.get('pool_up') is not None else '-'}/{v.get('pool_servers') if v.get('pool_servers') is not None else len(v.get('members') or [])}",
                            "metric": ("5초" if v.get("step") == 5 else "5분" if v.get("step") else ("없음 — " + str(v.get("mnote") or "수집 전"))[:80]),
                            "ports": ", ".join(map(str, v.get("ports") or []))} for v in vs[:300]], "empty": "수집된 가상 서비스가 없습니다"})
        P.append({"id": "se", "title": "Service Engine", "cols": [["state", "상태"], ["name", "SE"], ["se_group", "SE 그룹"], ["host", "ESXi"], ["ip", "관리 IP"],
                                                                  ["health", "헬스"], ["vs", "VS 수"], ["ctrl", "컨트롤러"]], "rows": se,
                  "empty": "수집된 Service Engine 이 없습니다 — 커넥터 점검의 'Service Engine' 항목을 확인하세요"})
    if "ucsm" in types or "redfish" in types:
        rows = []
        for c in conns:
            if getattr(c, "type", "") == "ucsm":
                for b in c.servers():
                    rows.append({"state": b.get("state"), "name": b.get("profile") or b.get("dn"), "dn": b.get("dn"), "model": b.get("model"), "serial": b.get("serial"),
                                 "power": b.get("power"), "src": c.name})
            elif getattr(c, "type", "") == "redfish":
                for e in c.entities():
                    if e.get("kind") in ("server", "system", "host", "bmc") or not rows:
                        rows.append({"state": e.get("state"), "name": e.get("name"), "dn": "", "model": e.get("detail", ""), "serial": "", "power": "", "src": c.name})
        P.append({"id": "servers", "title": "물리 서버", "cols": [["state", "상태"], ["name", "서버/프로필"], ["dn", "위치(DN)"], ["model", "모델"], ["serial", "S/N"],
                                                              ["power", "전원"], ["src", "커넥터"]], "rows": rows[:400]})
    if types & {"arista", "cisco", "nxos", "iosxe", "snmp-switch"}:
        from . import netmap as NM
        P.append({"id": "net-dev", "title": "네트워크 장비", "cols": [["state", "상태"], ["name", "장비"], ["vendor", "벤더"], ["model", "모델"], ["os", "OS·버전"],
                                                                 ["mgmt", "관리 주소"], ["ports", "포트 up/전체"], ["down", "다운 포트(연결·설명 있음)"], ["nb", "LLDP/CDP 이웃"],
                                                                 ["mlag", "MLAG/vPC"], ["bgp", "BGP 수립"], ["conn", "커넥터"], ["error", "수집 오류"]],
                  "rows": NM.device_rows(ENGINE), "empty": "등록된 네트워크 장비가 없습니다 — 커넥터에서 Arista(eAPI)·Cisco(NX-API·RESTCONF·SNMP) 추가"})
        P.append({"id": "net-if", "title": "다운·사라진 링크", "cols": [["state", "상태"], ["device", "장비"], ["iface", "인터페이스"], ["raw", "상태 원문"],
                                                                     ["desc", "설명"], ["peer", "상대(LLDP/CDP)"]],
                  "rows": NM.iface_down_rows(ENGINE), "empty": "다운된 연결 포트 없음"})
    if types & {"arista", "cisco", "nxos", "iosxe", "snmp-switch", "nsx"}:
        from . import netmap as NM
        bg = NM.bgp_rows(ENGINE)
        if bg or "nsx" not in types:
            P.append({"id": "net-bgp", "title": "NSX Edge ↔ 물리 BGP", "cols": [["state", "상태"], ["tier0", "T0"], ["edge", "Edge"], ["source", "Edge 업링크"],
                                                                         ["neighbor", "피어"], ["remote_as", "피어 AS"], ["switch", "물리 스위치"], ["sess", "세션(NSX/스위치)"],
                                                                         ["pfx", "수신/광고 경로"], ["up", "수립 후"]],
                      "rows": bg, "empty": "NSX T0 BGP 세션 없음 — NSX 커넥터(Auditor)를 추가하면 Edge ↔ 스위치 BGP 를 표시"})
    if "fortigate" in srcs and getattr(ENGINE, "fortigate", None) and ENGINE.fortigate.devices:
        sn = ENGINE.fortigate.snapshot(15)
        P.append({"id": "bf", "title": "무차별 대입 출발지(15분)", "cols": [["srcip", "출발지"], ["window", "창 내 실패"], ["total", "누적"], ["users", "계정"], ["active", "공격 중"]],
                  "rows": [{"srcip": r.get("srcip"), "window": r.get("window"), "total": r.get("total"), "active": "예" if r.get("active") else "",
                            "users": ", ".join(list(r.get("users") or [])[:3]) if isinstance(r.get("users"), (list, set, tuple)) else r.get("users", "")}
                           for r in sn["bruteforce"][:30]], "empty": "로그인 실패 출발지 없음"})
        P.append({"id": "ports", "title": "상위 차단 포트(15분)", "cols": [["port", "포트"], ["count", "차단"]], "rows": sn["top_port"][:15]})
    return P


_NUM = re.compile(r"[^\s=:,;()\[\]{}\"']*\d[^\s=:,;()\[\]{}\"']*")         # 숫자가 섞인 토큰(IP·ID·호스트명 esx07 …) → #


async def domain_patterns(ENGINE, CFG: dict, sid: str, minutes: int = 60) -> dict[str, Any]:
    """도메인의 최근 이벤트를 패턴(템플릿)별로 묶음 — 같은 로그 수천 줄을 한 줄로 보이게"""
    d = next((x for x in slots(CFG) if x["id"] == sid), None)
    if not d:
        raise HTTPException(404, "알 수 없는 관제 도메인")
    now = time.time()
    since = now - minutes * 60
    rows: list[dict] = []
    trunc = False
    for src in d["sources"]:
        try:
            if _vf(d):
                b = await ENGINE.store.q("SELECT ts,severity,host,message,template FROM logs WHERE source=? AND ts>?" + VS.sql_cond() + " ORDER BY ts DESC LIMIT 4000",
                                         (src, since, *VS.sql_args()))
            else:
                b = await ENGINE.store.q("SELECT ts,severity,host,message,template FROM logs WHERE source=? AND ts>? ORDER BY ts DESC LIMIT 4000",
                                         (src, since))
            trunc = trunc or len(b) >= 4000
            rows += b
        except Exception:  # noqa: BLE001
            pass
    g: dict[str, dict] = {}
    nb = 12
    for r in rows:
        key = _NUM.sub("#", str(r.get("template") or r.get("message") or ""))[:200]      # 템플릿에 남은 숫자·ID 도 한 번 더 정규화
        x = g.get(key)
        if x is None:
            x = g[key] = {"pattern": key[:300], "sample": str(r.get("message") or "")[:400], "count": 0, "sev": "debug", "hosts": {},
                          "first": r["ts"], "last": r["ts"], "spark": [0] * nb}
        x["count"] += 1
        if SEV_RANK.get(r.get("severity"), 0) > SEV_RANK.get(x["sev"], 0):
            x["sev"] = r["severity"]
        h = r.get("host") or ""
        x["hosts"][h] = x["hosts"].get(h, 0) + 1
        x["first"] = min(x["first"], r["ts"])
        x["last"] = max(x["last"], r["ts"])
        b = int((r["ts"] - since) / (minutes * 60 / nb))
        x["spark"][min(nb - 1, max(0, b))] += 1
    out = sorted(g.values(), key=lambda x: (-(SEV_RANK.get(x["sev"], 0) >= 2), -x["count"]))
    for x in out:
        hs = sorted(x["hosts"].items(), key=lambda kv: -kv[1])
        x["host_count"] = len(hs)
        x["hosts"] = [h for h, _ in hs[:4]]
    return {"minutes": minutes, "rows": len(rows), "truncated": trunc, "patterns": out[:60], "total_patterns": len(out)}


def _entity_pool(ENGINE, CFG: dict) -> list[dict]:
    """검색·개체 상세용 — 모든 도메인의 개체(커넥터 entities + vCenter VM + Avi VS + 에이전트)"""
    pool: list[dict] = []
    for d in slots(CFG):
        types = set(d.get("types") or [])
        if _vf(d):
            try:
                pool += [{"name": e["name"], "kind": e["kind"], "state": e["state"], "detail": e.get("detail", ""), "sid": d["id"], "domain": d["name"], "src": "vsan"}
                         for e in VS.entities(ENGINE)]
            except Exception:  # noqa: BLE001
                pass
            continue
        for c in ENGINE.connectors:
            if getattr(c, "type", "") not in types:
                continue
            try:
                for e in c.entities():
                    pool.append({"name": e["name"], "kind": e.get("kind", ""), "state": e.get("state", ""), "detail": e.get("detail", ""),
                                 "sid": d["id"], "domain": d["name"], "src": c.name})
            except Exception:  # noqa: BLE001
                pass
            if c.type == "vcenter":
                for vn, v in list((getattr(c, "topology", {}) or {}).get("vms", {}).items())[:20000]:
                    pool.append({"name": vn, "kind": "vm", "state": "ok" if v.get("power") == "poweredOn" else "idle",
                                 "detail": f"{v.get('host', '')} · {v.get('cluster', '')}", "sid": d["id"], "domain": d["name"], "src": c.name})
        if d.get("agents"):
            try:
                for e in ENGINE.agents.entities(d["agents"]):
                    pool.append({"name": e["name"], "kind": e.get("kind", "agent"), "state": e.get("state", ""), "detail": e.get("detail", ""),
                                 "sid": d["id"], "domain": d["name"], "src": "agent"})
            except Exception:  # noqa: BLE001
                pass
    return pool


def search(ENGINE, CFG: dict, q: str, limit: int = 30) -> list[dict]:
    q = q.strip().lower()
    if len(q) < 2:
        return []
    out, seen = [], set()
    for e in _entity_pool(ENGINE, CFG):
        n = str(e["name"]).lower()
        if q not in n and q not in str(e.get("detail", "")).lower():
            continue
        k = (e["sid"], n)
        if k in seen:
            continue
        seen.add(k)
        e["rank"] = 0 if n == q else 1 if n.startswith(q) else 2 if q in n else 3
        out.append(e)
    out.sort(key=lambda e: (e["rank"], {"down": 0, "warn": 1}.get(e["state"], 2), len(e["name"])))
    return out[:limit]


async def entity_detail(ENGINE, CFG: dict, sid: str, name: str) -> dict[str, Any]:
    """개체 상세 드로어 — 상태·열린/최근 이상징후·60분 추이·최근 이벤트·물리↔논리 경로"""
    d = next((x for x in slots(CFG) if x["id"] == sid), None)
    if not d:
        raise HTTPException(404, "알 수 없는 관제 도메인")
    n = name.strip().lower()
    short = n.split(".")[0]
    ent = next((e for e in _entity_pool(ENGINE, CFG) if e["sid"] == sid and str(e["name"]).lower() == n), None) \
        or next((e for e in _entity_pool(ENGINE, CFG) if str(e["name"]).lower() == n), None)
    now = time.time()
    window = float((CFG.get("noc") or {}).get("window_minutes", 30)) * 60
    anoms = []
    for a in ENGINE.anomalies.values():
        x = a.to_dict()
        ks = _keys(x)
        if n in ks or short in ks:
            anoms.append({k: x.get(k) for k in ("id", "severity", "title", "created", "last_seen", "count", "status", "ack")}
                         | {"open": _is_open(x, now, window), "message": str((x.get("event") or {}).get("message", ""))[:300],
                            "source": (x.get("event") or {}).get("source", ""),
                            "summary": ((x.get("ai") or {}).get("summary") or "")[:400], "cause": str((x.get("ai") or {}).get("probable_cause") or (x.get("ai") or {}).get("cause") or "")[:300],
                            "impact": str((x.get("ai") or {}).get("impact") or "")[:300],
                            "action": ((x.get("ai") or {}).get("action") or (x.get("ai") or {}).get("actions") or "")})
    anoms.sort(key=lambda a: (not a["open"], -(a["last_seen"] or 0)))
    events = await _recent(ENGINE, set(d["sources"]), 6, 200, host=name, vsan=_vf(d))
    sev = {s: sum(1 for e in events if e["severity"] == s) for s in ("critical", "error", "warning", "info")}
    path = None
    try:
        from . import stack
        path = stack.path_of(stack.build(ENGINE), name)
    except Exception:  # noqa: BLE001
        pass
    kn = []
    try:                                              # 관련 KB·TechDocs — 가장 최근 열린 이상징후(없으면 최근 이상징후) 기준
        base = next((a for a in anoms if a["open"]), anoms[0] if anoms else None)
        if base and ENGINE.rag.has_any():
            hits = await ENGINE.rag.search(f"{base['title']} {base['message']}", source=base.get("source") or None, k=3, intent="analyze")
            for h in hits:
                t = h.get("text", "")
                m = re.search(r"\[(해결|우회)\]\n(.{0,600})", t, re.S)
                kn.append({k: h.get(k) for k in ("title", "url", "type", "kb", "doc_id", "sections", "versions", "pack_name", "section")}
                          | {"fix": (m.group(2).strip() if m else t[:400]), "fix_kind": m.group(1) if m else ""})
    except Exception:  # noqa: BLE001
        kn = []
    inc = await ENGINE.store.q("SELECT id,title,severity,status,updated FROM incidents WHERE status IN ('open','acknowledged','investigating') "
                               "AND (title LIKE ? OR title LIKE ?) ORDER BY updated DESC LIMIT 10", (f"%{name}%", f"%{short}%"))
    return {"name": name, "sid": sid, "domain": d["name"], "entity": ent, "anomalies": anoms[:40], "events": events, "sev6h": sev,
            "series": ENGINE.minutes.host_series(name), "path": path, "incidents": inc, "knowledge": kn, "generated": now}


async def domain_detail(ENGINE, CFG: dict, sid: str) -> dict[str, Any]:
    snap = await snapshot(ENGINE, CFG, only=sid)
    if not snap["slots"]:
        raise HTTPException(404, "알 수 없는 관제 도메인")
    s = snap["slots"][0]
    srcs = set(s["sources"])
    conns = [c for c in ENGINE.connectors if getattr(c, "type", "") in s["types"]]
    now = time.time()
    window = snap["window_minutes"] * 60
    checks = {}
    for c in conns:
        ch = (c.state() or {}).get("checks")
        if ch:
            checks[c.name] = dict(list(ch.items())[:20])
    kinds: dict[str, dict[str, int]] = {}
    for e in s["entities"]:
        k = kinds.setdefault(e.get("kind") or "기타", {"total": 0, "down": 0, "warn": 0})
        k["total"] += 1
        if e["state"] in ("down", "warn"):
            k[e["state"]] += 1
    open_ = [a for a in s["anomalies"] if _is_open(a, now, window)]
    return {**{k: s.get(k) for k in ("id", "name", "scope", "sources", "types", "filter", "state", "why", "counts", "rate", "syslog_5m", "incidents", "incident_count",
                                  "oldest_unack", "connectors", "stale", "fresh_age", "last_data")},
            "entities": sorted(s["entities"], key=lambda e: ({"down": 0, "warn": 1}.get(e["state"], 2), -e.get("alerts", 0), e["name"]))[:600],
            "entity_total": len(s["entities"]), "kinds": kinds,
            "open": [{k: a.get(k) for k in ("id", "severity", "title", "created", "last_seen", "count", "status")} | {"host": (a.get("event") or {}).get("host"),
                      "entity": (a.get("event") or {}).get("entity"), "message": str((a.get("event") or {}).get("message", ""))[:300],
                      "summary": ((a.get("ai") or {}).get("summary") or "")[:300]} for a in open_[:60]],
            "sev": ENGINE.minutes.sev_series(_rate_srcs(s)), "top_hosts": ENGINE.minutes.top_hosts(_rate_srcs(s)),
            "recent": await _recent(ENGINE, srcs, 1, 150, vsan=_vf(s)), "important": await _important(ENGINE, srcs, vsan=_vf(s)),
            "match": VS.VSAN_RX.pattern if _vf(s) else "",
            "checks": checks, "panels": _panels(ENGINE, sid, s, conns), "window_minutes": snap["window_minutes"], "generated": now,
            "slots": [{"id": d["id"], "name": d["name"]} for d in slots(CFG)]}


# ---------------------------------------------------------------- AI 상황 브리핑
BRIEF_SYS = ("너는 금융권 VCF 관제실 상황 담당이다. 주어진 도메인(" + BRIEF_DOMAINS + ") 집계만 근거로 "
             "관제 화면 상단에 띄울 한국어 상황 브리핑을 쓴다. 형식: 첫 줄은 전체 상황 한 문장(40자 이내). 이어서 문제 있는 도메인만 "
             "'• 도메인: 무엇이 · 영향 · 먼저 볼 것' 한 줄씩(최대 4줄). 도메인 간 연관(예: Edge 장애와 VKS 노드 NotReady 동시 발생)이 "
             "시각상 보이면 '연관 가능성'으로만 표현하고 단정하지 않는다. 수치는 입력 그대로, 입력에 없는 장비명·원인은 만들지 않는다. "
             "모두 정상이면 첫 줄만 쓴다.")


def _rule_brief(snap: dict) -> str:
    bad = [s for s in snap["slots"] if s["state"] in ("down", "warn")]
    if not bad:
        return f"전 도메인 정상 — 최근 {int(snap['window_minutes'])}분 미확인 이상 없음"
    head = ", ".join(f"{s['name']} {STATE_KO[s['state']]}" for s in bad)
    lines = [head]
    for s in bad:
        top = [a for a in s["anomalies"] if _is_open(a, snap["generated"], snap["window_minutes"] * 60)][:2]
        lines.append(f"• {s['name']}: {s['why'] or '활성 인시던트·커넥터 상태 확인'}" +
                     (f" — 최근: {'; '.join(clean(a['title'], 60) for a in top)}" if top else ""))
    return "\n".join(lines)


async def make_brief(ENGINE, CFG: dict, force: bool = False) -> dict[str, Any]:
    cache = getattr(ENGINE, "_noc_brief", None)
    ttl = float((CFG.get("noc") or {}).get("brief_ttl_seconds", 300))
    if cache and not force and time.time() - cache["ts"] < ttl:
        return cache
    lock = getattr(ENGINE, "_noc_brief_lock", None)
    if lock is None:
        lock = ENGINE._noc_brief_lock = asyncio.Lock()
    async with lock:
        cache = getattr(ENGINE, "_noc_brief", None)
        if cache and not force and time.time() - cache["ts"] < ttl:
            return cache
        snap = await snapshot(ENGINE, CFG)
        basis = []
        for s in snap["slots"]:
            open_ = [a for a in s["anomalies"] if _is_open(a, snap["generated"], snap["window_minutes"] * 60)]
            basis.append({"domain": s["name"], "state": STATE_KO[s["state"]], "reason": s["why"], "counts": s["counts"],
                          "active_incidents": [clean(i["title"], 100) for i in s["incidents"][:3]],
                          "entities_down": [e["name"] for e in s["entities"] if e["state"] == "down"][:8],
                          "connectors_down": [c["name"] for c in s["connectors"] if c["state"] == "down"],
                          "recent_open_anomalies": [{"time": time.strftime("%H:%M", time.localtime(a["last_seen"])),
                                                     "severity": a["severity"], "title": clean(a["title"], 120),
                                                     "target": clean((a["event"] or {}).get("host", ""), 60)} for a in open_[:6]]})
        text, mode = "", "rule"
        if ENGINE.llm and getattr(ENGINE, "ai_on", True) and (CFG.get("noc") or {}).get("ai_brief", True):
            try:
                names = sorted({str(n) for b in basis for n in ([b["domain"]] + b["entities_down"] + b["connectors_down"]
                                                                + [x["target"] for x in b["recent_open_anomalies"]]) if n}
                               | {str((a["event"] or {}).get(k) or "") for s in snap["slots"] for a in s["anomalies"] for k in ("host", "entity")} - {""})
                text = await asyncio.wait_for(ENGINE.llm.complete(BRIEF_SYS, json.dumps(basis, ensure_ascii=False), 500, names=names), 60)   # 2.30.0 외부 공급자 가명화 대상
                mode = "ai"
            except Exception as e:  # noqa: BLE001
                text = _rule_brief(snap) + f"\n(AI 브리핑 실패: {type(e).__name__})"
        if not text:
            text = _rule_brief(snap)
        ENGINE._noc_brief = {"ts": time.time(), "text": text.strip()[:1500], "mode": mode,
                             "model": ((ENGINE.llm.last_used.get("brief") or "").split(":", 1)[-1] if ENGINE.llm and mode == "ai" else ""),
                             "states": {s["id"]: s["state"] for s in snap["slots"]}}
        await ENGINE.broadcast({"type": "noc_brief", "data": ENGINE._noc_brief})
        return ENGINE._noc_brief


# ---------------------------------------------------------------- 미확인 위험 에스컬레이션
async def escalation_loop(ENGINE, CFG: dict) -> None:
    while True:
        await asyncio.sleep(60)
        try:
            mins = float((CFG.get("noc") or {}).get("escalate_minutes", 15))
            if mins <= 0:
                continue
            now = time.time()
            window = float((CFG.get("noc") or {}).get("window_minutes", 30)) * 60
            for a in list(ENGINE.anomalies.values()):
                d = a.to_dict()
                if a.severity != "critical" or a.escalated or not _is_open(d, now, max(window, mins * 60 + 600)):
                    continue
                if now - a.created < mins * 60:
                    continue
                a.escalated = now
                e = a.event
                await ENGINE.alerter.notify_text(
                    f"[에스컬레이션] {int((now - a.created) // 60)}분 미확인 위험 — {a.title}",
                    f"소스 {e.get('source')} · 대상 {e.get('host')} {e.get('entity') or ''}\n인시던트 {a.incident_id or '-'}\n"
                    f"{clean(e.get('message', ''), 400)}", "critical", a.id)
                await ENGINE.audit.log("noc.escalate", target=a.id, detail={"minutes": int((now - a.created) // 60),
                                                                           "incident": a.incident_id})
                await ENGINE.store.save_anomaly(a.to_dict())
                await ENGINE.broadcast({"type": "anomaly", "data": a.to_dict()})
        except Exception as e:  # noqa: BLE001
            print(f"[noc] 에스컬레이션 오류: {e}", flush=True)


async def brief_loop(ENGINE, CFG: dict) -> None:
    """관제 화면이 열려 있을 때(최근 10분 내 조회)만 주기적으로 브리핑 갱신 — 슬롯 상태가 바뀌면 즉시"""
    while True:
        await asyncio.sleep(30)
        try:
            if time.time() - getattr(ENGINE, "_noc_viewed", 0) > 600:
                continue
            cache = getattr(ENGINE, "_noc_brief", None)
            snap = await snapshot(ENGINE, CFG)
            states = {s["id"]: s["state"] for s in snap["slots"]}
            if not cache or (states != cache.get("states") and time.time() - cache["ts"] > 60):
                await make_brief(ENGINE, CFG, force=True)
            else:
                await make_brief(ENGINE, CFG)
        except Exception as e:  # noqa: BLE001
            print(f"[noc] 브리핑 오류: {e}", flush=True)


async def executive(ENGINE, CFG: dict) -> dict[str, Any]:
    """경영진 요약(/noc/exec) — 30일 인시던트·MTTA/MTTR·SLA, 이상징후 추세, 가용성(호스트·클러스터), vSAN 건강,
    용량 예측(90% 도달 임박), 적정화 절감, 이번 달 정산(테넌트별), 보안 판독(하드닝 점수·VMSA·CVE), 수집 상태. 60초 캐시."""
    now = time.time()
    cache = getattr(ENGINE, "_noc_exec", None)
    if cache and now - cache["ts"] < 60:
        return cache["data"]
    day = 86400
    inc30 = await ENGINE.incidents.metrics(now - 30 * day, now)
    inc_prev = await ENGINE.incidents.metrics(now - 60 * day, now - 30 * day)
    rows = await ENGINE.store.q("SELECT created, severity FROM incidents WHERE created>=?", (now - 30 * day,))
    inc_daily = [0] * 30
    for r in rows:
        i = int((now - r["created"]) // day)
        if 0 <= i < 30:
            inc_daily[29 - i] += 1
    arows = await ENGINE.store.q("SELECT created, severity FROM anomalies WHERE created>=?", (now - 30 * day,))
    an_daily = [0] * 30
    an_sev: dict[str, int] = {}
    for r in arows:
        i = int((now - r["created"]) // day)
        if 0 <= i < 30:
            an_daily[29 - i] += 1
        an_sev[r["severity"]] = an_sev.get(r["severity"], 0) + 1
    open_inc = await ENGINE.store.q("SELECT id,title,severity,status,created,assignee FROM incidents WHERE status IN ('open','acknowledged','investigating') "
                                    "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 ELSE 2 END, created DESC LIMIT 8")
    # 가용성(현재 토폴로지)
    hosts = hosts_bad = hosts_maint = vms = vms_on = clusters = 0
    for c in ENGINE.connectors:
        if getattr(c, "type", "") != "vcenter":
            continue
        t = getattr(c, "topology", {}) or {}
        H = t.get("hosts", {}) or {}
        hosts += len(H)
        hosts_bad += sum(1 for h in H.values() if h.get("conn") not in ("connected", ""))
        hosts_maint += sum(1 for h in H.values() if h.get("maintenance"))
        vms += len(t.get("vms", {}))
        vms_on += sum(1 for v in t.get("vms", {}).values() if v.get("power") == "poweredOn")
        clusters += len([k for k in t.get("clusters", {}) if k != "(standalone)"])
    vs = VS.collect(ENGINE)
    # 용량·적정화·정산·판독(각각 실패해도 나머지는 표시)
    async def safe(coro, default):
        try:
            return await asyncio.wait_for(coro, timeout=20)
        except Exception as e:  # noqa: BLE001
            return {**default, "error": f"{type(e).__name__}: {str(e)[:120]}"}
    cap = await safe(ENGINE.capacity.overview(), {"items": [], "summary": {}})
    rs = await safe(ENGINE.capacity.rightsizing(), {"summary": {}})
    from .billing import period_range
    s0, e0, lab = period_range("mtd", now=now)
    bill = await safe(ENGINE.billing.report(s0, e0, lab, vm_detail=False), {"totals": {}, "tenants": []})
    assess = await safe(ENGINE.assess.latest(), {}) or {}
    asum = assess.get("summary") or {}
    coll = ENGINE.collection.summary()
    soon = sorted([r for r in cap.get("items", []) if any((x or {}).get("days_to", {}).get("90") is not None for x in (r.get("forecast"), r.get("forecast_mem")))],
                  key=lambda r: min(v for v in ((r.get("forecast") or {}).get("days_to", {}).get("90"), (r.get("forecast_mem") or {}).get("days_to", {}).get("90")) if v is not None))
    data = {"ts": now, "period_days": 30,
            "incidents": {**inc30, "prev_total": inc_prev["total"], "prev_mttr_min": inc_prev["mttr_min"], "prev_sla_breaches": inc_prev["sla_breaches"],
                          "daily": inc_daily, "open": open_inc},
            "anomalies": {"total": len(arows), "by_severity": an_sev, "daily": an_daily},
            "availability": {"hosts": hosts, "hosts_bad": hosts_bad, "hosts_maint": hosts_maint, "vms": vms, "vms_on": vms_on, "clusters": clusters,
                             "host_pct": round((hosts - hosts_bad) / hosts * 100, 2) if hosts else None},
            "vsan": {"clusters": len(vs["clusters"]), "red": sum(1 for c in vs["clusters"] if c["state"] == "down"), "warn": sum(1 for c in vs["clusters"] if c["state"] == "warn"),
                     "used_pct": round(sum(c["capacity_gb"] - c["free_gb"] for c in vs["clusters"]) / sum(c["capacity_gb"] for c in vs["clusters"]) * 100, 1) if sum(c["capacity_gb"] for c in vs["clusters"]) else None,
                     "tests_bad": len(vs["health_tests"]), "worst": [c["name"] for c in vs["clusters"] if c["state"] != "ok"][:5]},
            "capacity": {"summary": cap.get("summary", {}), "error": cap.get("error"),
                         "soon": [{"name": r["name"], "kind": r["kind"], "vcenter": r["vcenter"], "cpu": r.get("cpu"), "mem": r.get("mem"), "disk": r.get("disk"),
                                   "days_to_90": min(v for v in ((r.get("forecast") or {}).get("days_to", {}).get("90"), (r.get("forecast_mem") or {}).get("days_to", {}).get("90")) if v is not None)}
                                  for r in soon[:6]]},
            "rightsizing": {**(rs.get("summary") or {}), "currency": rs.get("currency"), "vms_observed": rs.get("vms_observed"), "error": rs.get("error")},
            "billing": {"label": lab, "currency": bill.get("currency"), "totals": bill.get("totals", {}), "error": bill.get("error"),
                        "tenants": sorted([{"name": t["name"], "cost": t.get("cost"), "vms": t.get("vms"), "vcpu_hours": t.get("vcpu_hours")} for t in bill.get("tenants", [])],
                                          key=lambda t: -(t["cost"] or 0))[:8],
                        "unassigned_vms": (bill.get("totals") or {}).get("unassigned_vms", 0)},
            "assessment": {"ts": asum.get("ts"), "score": asum.get("score"), "counts": asum.get("counts"), "cve": asum.get("cve"), "hosts": asum.get("hosts"),
                           "changes": asum.get("changes"), "versions": (asum.get("versions") or [])[:6]},
            "collection": coll, "ai": ENGINE.ai_state(), "eps": ENGINE.stats.get("eps", 0),
            "alerts": {"sent_total": ENGINE.alerter.sent_total, "outbox": ENGINE.alerter.outbox_status()},
            "siem": ENGINE.siem.status() if getattr(ENGINE, "siem", None) else None}
    ENGINE._noc_exec = {"ts": now, "data": data}
    return data


def build_router(ENGINE, CFG: dict, can) -> APIRouter:
    r = APIRouter()

    @r.get("/api/noc/exec")
    async def noc_exec():
        return await executive(ENGINE, CFG)

    @r.get("/api/network/map")
    async def network_map(hosts: int = 1, layers: str = "nsx,avi,vpc,vm,pod", vms: int = 12, pods: int = 8):
        """전체 네트워크 구성도 — 스위치(LLDP/CDP·전면 포트)·ESXi·서버·외부 장비 + NSX(Edge·T0·T1·세그먼트·VPC)·Avi(컨트롤러·SE·VS)·VM·Pod
        layers: 쉼표 목록(nsx·avi·vpc·vm·pod, 빈 값 = 물리만) · vms: 호스트당 개별 VM 수(0 = 전부) · pods: 노드당 Pod 수"""
        from . import netmap as NM
        lay = {x for x in layers.split(",") if x in NM.LOGICAL}
        return NM.build(ENGINE, include_hosts=bool(hosts), layers=lay, vm_limit=max(0, min(vms, 500)), pod_limit=max(0, min(pods, 200)))

    @r.get("/api/network/device/{name}/config")
    async def network_device_config(name: str, request: Request):
        """running-config(비밀값 가림) — 운영자 이상. 원문은 메모리에만 있고 DB 에 저장하지 않음"""
        if not can(request, "operate"):
            raise HTTPException(403, "운영자 이상 권한 필요")
        from .connectors.network import NetDevice, short
        for c in ENGINE.connectors:
            if isinstance(c, NetDevice):
                s = c.snapshot()
                if short(s["name"]) == short(name) or c.name == name:
                    cf = c.config or {}
                    return {"name": s["name"], "text": cf.get("text", ""), "updated": cf.get("updated"), "lines": cf.get("lines"), "digest": cf.get("digest"),
                            "error": cf.get("error", ""), "changed_at": cf.get("changed_at"), "diff": cf.get("diff"),
                            "vlans": (cf.get("parsed") or {}).get("vlans") or {}, "global": {k: v for k, v in ((cf.get("parsed") or {}).get("global") or {}).items() if k != "lines"}}
        raise HTTPException(404, "장비 없음")

    @r.get("/api/network/portmap")
    async def network_portmap():
        """장비별 포트맵 — 스위치 포트 ↔ ESXi vmnic(스위치 LLDP/CDP + ESXi LLDP/CDP), 이중화·속도·불일치 점검"""
        from . import portmap as PM
        return PM.build(ENGINE)

    @r.get("/api/network/bgp")
    async def network_bgp():
        """NSX T0 BGP 세션(Edge ↔ 물리 스위치) — NSX 상태 + 스위치가 보는 상태"""
        from . import netmap as NM
        m = NM.build(ENGINE, include_hosts=False)
        return {"sessions": m.get("bgp", []), "summary": {k: m["summary"].get(k) for k in ("bgp_sessions", "bgp_down", "edges")}}

    @r.get("/api/network/devices")
    async def network_devices():
        from . import netmap as NM
        return {"devices": NM.device_rows(ENGINE), "down": NM.iface_down_rows(ENGINE)}

    @r.get("/api/network/device/{name}")
    async def network_device(name: str):
        """장비 상세 — 인터페이스·이웃·MLAG/vPC·BGP 전체"""
        from .connectors.network import NetDevice, short
        for c in ENGINE.connectors:
            if isinstance(c, NetDevice):
                s = c.snapshot()
                if short(s["name"]) == short(name) or c.name == name:
                    return s
        raise HTTPException(404, "장비 없음")

    @r.get("/api/noc")
    async def noc():
        ENGINE._noc_viewed = time.time()
        return await snapshot(ENGINE, CFG)

    @r.get("/api/noc/kpi")
    async def noc_kpi():
        """관제 상단 지표 띠 — 규모·알람·인시던트·VM 액티비티·AI·보안을 한 번에"""
        now = time.time()
        vms = hosts = clusters = vms_on = hosts_bad = hosts_maint = 0
        for c in ENGINE.connectors:
            if getattr(c, "type", "") != "vcenter":
                continue
            t = getattr(c, "topology", {}) or {}
            vms += len(t.get("vms", {}))
            vms_on += sum(1 for v in t.get("vms", {}).values() if v.get("power") == "poweredOn")
            hosts += len(t.get("hosts", {}))
            hosts_bad += sum(1 for h in t.get("hosts", {}).values() if h.get("conn") not in ("connected", "") )
            hosts_maint += sum(1 for h in t.get("hosts", {}).values() if h.get("maintenance"))
            clusters += len([k for k in t.get("clusters", {}) if k != "(standalone)"])
        al = ENGINE.moves.alarms()
        inc = await ENGINE.store.q("SELECT severity, COUNT(*) n FROM incidents WHERE status IN ('open','acknowledged','investigating') GROUP BY severity")
        mv = await ENGINE.moves.query(6, limit=400)
        h1 = [m for m in mv if now - m["ts"] <= 3600]
        HA = {"ha_restart", "ha_failed", "ha_reset", "ha_reset_failed", "host_failed", "host_isolated"}
        fg = getattr(ENGINE, "fortigate", None)
        fk = fg.snapshot(15)["kpi"] if fg and fg.devices else None
        return {"ts": now, "vms": vms, "vms_on": vms_on, "hosts": hosts, "hosts_bad": hosts_bad, "hosts_maint": hosts_maint, "clusters": clusters,
                "alarms": {"red": sum(1 for a in al if a["status"] == "red"), "yellow": sum(1 for a in al if a["status"] == "yellow"), "total": len(al)},
                "incidents": {r["severity"]: r["n"] for r in inc},
                "moves_1h": {"move": sum(1 for m in h1 if m["type"] in ("vmotion", "drs", "svmotion", "relocate", "detected")),
                             "drs": sum(1 for m in h1 if m["type"] == "drs"), "ha": sum(1 for m in h1 if m["type"] in HA),
                             "failed": sum(1 for m in h1 if m["type"] in ("move_failed", "ha_failed", "ha_reset_failed", "create_failed")),
                             "created": sum(1 for m in h1 if m["type"] in ("created", "cloned", "deployed", "registered", "detected_new")),
                             "deleted": sum(1 for m in h1 if m["type"] in ("removed", "detected_gone")),
                             "config": sum(1 for m in h1 if m["type"] in ("reconfigured", "renamed", "snapshot_create", "snapshot_remove", "snapshot_remove_all", "snapshot_revert")),
                             "risk": sum(1 for m in h1 if set(str(m.get("flags") or "").split(",")) & {"bulk_delete", "bulk_power_off", "protected", "short_lived"})},
                "moves": mv[:25], "ha_6h": sum(1 for m in mv if m["type"] in HA),
                "ai": ENGINE.ai_state(), "eps": ENGINE.stats.get("eps", 0),
                "security": {"attackers": fk["attackers"], "denied": fk["denied"], "login_fail": fk["login_fail"]} if fk else None}

    @r.get("/api/noc/infra")
    async def noc_infra():
        """인프라 지도 — vCenter 클러스터 → 호스트(CPU·메모리·상태) → VM(전원·열린 이상징후) + 이상징후 겹침"""
        now = time.time()
        window = float((CFG.get("noc") or {}).get("window_minutes", 30)) * 60
        sev: dict[str, int] = {}
        for a in ENGINE.anomalies.values():
            d = a.to_dict()
            if not _is_open(d, now, window):
                continue
            rk = SEV_RANK.get(d["severity"], 0)
            for k in _keys(d):
                if rk > sev.get(k, 0):
                    sev[k] = rk
        out = []
        for c in ENGINE.connectors:
            if getattr(c, "type", "") != "vcenter":
                continue
            t = getattr(c, "topology", {}) or {}
            hosts, vms = t.get("hosts", {}), t.get("vms", {})
            by_host: dict[str, list] = {}
            for vn, v in vms.items():
                by_host.setdefault(v.get("host", ""), []).append(
                    {"n": vn, "p": 1 if v.get("power") == "poweredOn" else 0, "a": sev.get(vn.lower(), 0)})
            for cn, cl in sorted(t.get("clusters", {}).items()):
                hs = []
                for hn in sorted(cl.get("hosts", [])):
                    h = hosts.get(hn, {})
                    cpu = round(h.get("cpu_used_mhz", 0) / h["cpu_mhz"] * 100) if h.get("cpu_mhz") else None
                    mem = round(h.get("mem_used_mb", 0) / h["mem_mb"] * 100) if h.get("mem_mb") else None
                    a = max(sev.get(hn.lower(), 0), sev.get(hn.split(".")[0].lower(), 0))
                    st = "maint" if h.get("maintenance") else "down" if h.get("conn") not in ("connected", "") else \
                        "down" if a >= 4 else "warn" if a >= 2 or str(h.get("status")) in ("red", "yellow") else "ok"
                    hv = sorted(by_host.get(hn, []), key=lambda x: (-x["a"], -x["p"], x["n"]))
                    hs.append({"name": hn, "state": st, "cpu": cpu, "mem": mem, "alert": a, "vms": hv[:400], "vm_total": len(hv),
                               "vm_on": sum(1 for x in hv if x["p"])})
                out.append({"name": cn, "vcenter": c.name, "drs": cl.get("drs"), "ha": cl.get("ha"), "vsan": cl.get("vsan"), "hosts": hs,
                            "state": "down" if any(h["state"] == "down" for h in hs) else "warn" if any(h["state"] in ("warn", "maint") for h in hs) else "ok"})
        return {"ts": now, "clusters": out, "moves": (await ENGINE.moves.query(1, limit=60))}

    @r.get("/api/noc/slots")
    async def noc_slots(state: bool = False):
        """관제 도메인 탭 목록(설정 noc.slots) — state=1 이면 탭 상태 점(장애·주의·정상)과 미확인 건수 포함"""
        out = [{"id": d["id"], "name": d["name"], "scope": d.get("scope", "")} for d in slots(CFG)]
        if state:
            st = {s["id"]: s for s in (await snapshot(ENGINE, CFG))["slots"]}
            for o in out:
                s = st.get(o["id"]) or {}
                o.update(state=s.get("state", ""), why=s.get("why", ""), n=sum((s.get("counts") or {}).values()))
        return out

    @r.get("/api/noc/domain/{sid}")
    async def noc_domain(sid: str):
        """도메인 상세 탭 — 상태·개체·커넥터 점검·심각도 추이·상위 호스트·최근 이벤트·도메인 전용 패널"""
        ENGINE._noc_viewed = time.time()
        return await domain_detail(ENGINE, CFG, sid)

    @r.get("/api/noc/domain/{sid}/events")
    async def noc_domain_events(sid: str, host: str = "", hours: float = 6, important: bool = False):
        """도메인 상세 — 특정 호스트·개체의 최근 이벤트(스트림 필터를 걸 때 과거분 채우기)"""
        d = next((x for x in slots(CFG) if x["id"] == sid), None)
        if not d:
            raise HTTPException(404, "알 수 없는 관제 도메인")
        return await _recent(ENGINE, set(d["sources"]), max(0.1, min(hours, 72)), 300, sev_min=important, host=host[:200], vsan=_vf(d))

    @r.get("/api/noc/domain/{sid}/patterns")
    async def noc_domain_patterns(sid: str, minutes: int = 60):
        """도메인 최근 이벤트의 패턴(템플릿)별 묶음 — 건수·최고 심각도·호스트·5분 추이"""
        return await domain_patterns(ENGINE, CFG, sid, max(5, min(minutes, 360)))

    @r.get("/api/noc/entity")
    async def noc_entity(sid: str, name: str):
        """개체 상세(관제 드로어) — 상태·이상징후(AI 판정)·60분 추이·최근 이벤트·물리↔논리 경로·관련 인시던트"""
        return await entity_detail(ENGINE, CFG, sid, name[:200])

    @r.get("/api/noc/search")
    async def noc_search(q: str = ""):
        """관제 전역 검색(Ctrl+K) — 호스트·VM·Edge·SE·VS·블레이드·장비 이름/설명"""
        return search(ENGINE, CFG, q[:100])

    @r.get("/api/noc/brief")
    async def noc_brief(request: Request, refresh: bool = False):
        ENGINE._noc_viewed = time.time()
        if refresh and not can(request, "operate"):
            raise HTTPException(403, "즉시 갱신은 운영자 이상")
        return await make_brief(ENGINE, CFG, force=refresh)

    return r
