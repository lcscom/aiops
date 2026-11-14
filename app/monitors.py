"""모니터 — Datadog 모니터 방식의 사용자 정의 감시(임계값·평가 창·그룹별 다중 알림·무수신·음소거·재알림·상태 이력).

유형
  log        로그 건수: 소스·호스트(와일드카드)·최소 등급·포함 문자열(정규식 가능) → 평가 창 동안 건수 (그룹: host·source·entity·none)
  nodata     무수신: 최근 24시간에 로그를 보낸 호스트 중 평가 창 동안 0건인 호스트 (그룹: host 고정)
  metric     지표: 아래 METRICS(인프라·VIP·VKS·플랫폼·FortiGate) — 평가 창 동안 avg|max|min|last
  connector  커넥터 연결 오류: 평가 창 내내 down 이면 경보
  anomaly    열린 이상징후 수(소스·최소 등급)

판정: op(>,>=,<,<=) 와 critical·warning 임계 → OK · WARN · ALERT · NO_DATA. 상태가 바뀔 때만 이벤트(source=monitor)를 내서
기존 이상징후·인시던트·알림 채널 경로를 그대로 탄다(LLM 분석은 생략 — 결정적 규칙). 음소거 중에는 판정만 하고 알리지 않음.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import time
import uuid
from collections import defaultdict, deque

from .models import SEV_RANK, LogEvent
from .perfwatch import safe_regex

REGEX_ROW_CAP = 200_000        # 정규식 로그 모니터가 한 번에 훑는 최대 행(최신 행 우선)

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors(id TEXT PRIMARY KEY, def TEXT, created REAL, updated REAL, created_by TEXT);
CREATE TABLE IF NOT EXISTS monitor_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, monitor_id TEXT, grp TEXT,
  from_state TEXT, to_state TEXT, value REAL);
CREATE INDEX IF NOT EXISTS ix_monev ON monitor_events(monitor_id, ts);
CREATE TABLE IF NOT EXISTS monitor_state(monitor_id TEXT, grp TEXT, state TEXT, since REAL, value REAL, notified REAL,
  PRIMARY KEY(monitor_id, grp));
"""
TYPES = {"log": "로그 건수", "nodata": "무수신(로그 끊김)", "metric": "지표", "connector": "커넥터 연결", "anomaly": "열린 이상징후"}
SEVS = ["debug", "info", "notice", "warning", "error", "critical"]
STATE_SEV = {"ALERT": "critical", "WARN": "warning", "NO_DATA": "warning"}
PRIO_SEV = {"P1": "critical", "P2": "critical", "P3": "error", "P4": "warning", "P5": "warning"}

# 지표 카탈로그: 이름 → (설명, 단위, 그룹 키)
METRICS: dict[str, tuple[str, str, str]] = {
    "host.cpu_pct": ("ESXi 호스트 CPU 사용률", "%", "host"),
    "host.mem_pct": ("ESXi 호스트 메모리 사용률", "%", "host"),
    "host.disconnected": ("ESXi 호스트 연결 끊김(1/0)", "", "host"),
    "cluster.cpu_pct": ("클러스터 CPU 사용률", "%", "cluster"),
    "cluster.mem_pct": ("클러스터 메모리 사용률", "%", "cluster"),
    "cluster.sli_score": ("클러스터 성능 SLI 점수", "점", "cluster"),
    "datastore.used_pct": ("데이터스토어 사용률", "%", "datastore"),
    "vm.powered_off": ("꺼진 VM 수", "대", "vcenter"),
    "vcenter.findings_critical": ("인프라 점검 위험·오류 건수", "건", "vcenter"),
    "connector.latency_ms": ("커넥터 응답 시간", "ms", "connector"),
    "vip.bandwidth_bps": ("NSX ALB VIP 대역폭", "bps", "vip"),
    "vip.rps": ("NSX ALB VIP 요청/초", "/s", "vip"),
    "vip.error_rps": ("NSX ALB VIP 오류 응답/초", "/s", "vip"),
    "vip.health": ("NSX ALB VIP Health", "점", "vip"),
    "vip.down": ("NSX ALB VIP 비정상(1/0)", "", "vip"),
    "vks.problem_pods": ("VKS 문제 파드 수", "개", "cluster"),
    "vks.nodes_not_ready": ("VKS NotReady 노드 수", "개", "cluster"),
    "agent.minutes_silent": ("에이전트 마지막 수신 후 경과", "분", "host"),
    "server.unhealthy": ("서버 BMC 이상(Critical=2·Warning=1)", "", "server"),
    "fortigate.login_failures_5m": ("FortiGate 로그인 실패(5분, 출발지 IP별)", "회", "srcip"),
    "fortigate.denied_per_min": ("FortiGate 차단 트래픽/분(장비별)", "건", "device"),
    "fortigate.ips_per_min": ("FortiGate IPS·이상 탐지/분(장비별)", "건", "device"),
    "platform.ai_queue": ("AI 분석 대기열", "건", "platform"),
    "platform.ingest_eps": ("수집 이벤트/초", "/s", "platform"),
    "platform.pipeline_lag_ms": ("수집→처리 지연", "ms", "platform"),
    "platform.disk_free_mb": ("데이터 디스크 여유", "MB", "platform"),
}

PRESETS = [
    {"name": "ESXi 호스트 CPU 90% 초과(5분 평균)", "type": "metric", "query": {"metric": "host.cpu_pct", "agg": "avg"}, "window": 300, "op": ">", "critical": 90, "warning": 80, "priority": "P2", "tags": ["vsphere"]},
    {"name": "ESXi 호스트 메모리 95% 초과", "type": "metric", "query": {"metric": "host.mem_pct", "agg": "avg"}, "window": 300, "op": ">", "critical": 95, "warning": 85, "priority": "P2", "tags": ["vsphere"]},
    {"name": "데이터스토어 사용률 90% 초과", "type": "metric", "query": {"metric": "datastore.used_pct", "agg": "last"}, "window": 300, "op": ">", "critical": 90, "warning": 80, "priority": "P2", "tags": ["storage"]},
    {"name": "커넥터 연결 오류 5분 지속", "type": "connector", "query": {}, "window": 300, "op": ">=", "critical": 1, "priority": "P2", "tags": ["platform"]},
    {"name": "에이전트 10분 무수신", "type": "metric", "query": {"metric": "agent.minutes_silent", "agg": "last"}, "window": 120, "op": ">", "critical": 10, "warning": 5, "priority": "P3", "tags": ["agent"]},
    {"name": "ESXi 오류 로그 급증(5분 50건)", "type": "log", "query": {"sources": ["esxi"], "min_severity": "error"}, "group_by": "host", "window": 300, "op": ">", "critical": 50, "warning": 20, "priority": "P3", "tags": ["vsphere"]},
    {"name": "VIP 오류 응답 초당 10건 초과", "type": "metric", "query": {"metric": "vip.error_rps", "agg": "avg"}, "window": 120, "op": ">", "critical": 10, "warning": 3, "priority": "P2", "tags": ["alb"]},
    {"name": "VIP 비정상", "type": "metric", "query": {"metric": "vip.down", "agg": "last"}, "window": 60, "op": ">=", "critical": 1, "priority": "P1", "tags": ["alb"]},
    {"name": "VKS 문제 파드 존재", "type": "metric", "query": {"metric": "vks.problem_pods", "agg": "last"}, "window": 300, "op": ">", "critical": 5, "warning": 0, "priority": "P3", "tags": ["vks"]},
    {"name": "FortiGate 무차별 대입(5분 20회 이상, 출발지별)", "type": "metric", "query": {"metric": "fortigate.login_failures_5m", "agg": "last"}, "window": 60, "op": ">=", "critical": 20, "warning": 10, "priority": "P2", "tags": ["security"]},
    {"name": "성능 SLI 클러스터 점수 50 미만", "type": "metric", "query": {"metric": "cluster.sli_score", "agg": "last"}, "window": 600, "op": "<", "critical": 50, "warning": 70, "priority": "P3", "tags": ["performance"]},
    {"name": "AI 분석 대기열 500건 초과", "type": "metric", "query": {"metric": "platform.ai_queue", "agg": "avg"}, "window": 300, "op": ">", "critical": 500, "warning": 200, "priority": "P4", "tags": ["platform"]},
    {"name": "위험 이상징후 3건 이상 미확인", "type": "anomaly", "query": {"min_severity": "critical"}, "window": 60, "op": ">=", "critical": 3, "priority": "P2", "tags": ["platform"]},
]


def _cmp(op: str, v: float, t: float) -> bool:
    return {">": v > t, ">=": v >= t, "<": v < t, "<=": v <= t}.get(op, False)


def normalize(d: dict) -> dict:
    t = d.get("type")
    if t not in TYPES:
        raise ValueError(f"유형 오류: {t}")
    name = str(d.get("name", "")).strip()[:160]
    if not name:
        raise ValueError("이름 필수")
    try:
        crit = float(d["critical"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("위험(critical) 임계값 필수")
    warn = d.get("warning")
    warn = None if warn in (None, "") else float(warn)
    op = d.get("op", ">")
    if op not in (">", ">=", "<", "<="):
        raise ValueError("비교 연산자 오류")
    if warn is not None and _cmp(op, warn, crit) and warn != crit:
        raise ValueError("경고 임계값은 위험 임계값보다 덜 심각해야 합니다")
    q = d.get("query") or {}
    if t == "metric" and q.get("metric") not in METRICS:
        raise ValueError("지표를 선택하세요")
    if t == "log" and q.get("regex") and q.get("text"):
        safe_regex(str(q["text"]), "정규식")          # 2.30.0 100자 이하·중첩 반복·역참조 금지(ReDoS 방지)
    return {"id": d.get("id") or uuid.uuid4().hex[:12], "name": name, "type": t, "enabled": bool(d.get("enabled", True)),
            "query": q, "group_by": d.get("group_by", "host" if t == "nodata" else ""), "window": max(60, min(int(d.get("window", 300)), 86400)),
            "op": op, "critical": crit, "warning": warn, "priority": d.get("priority", "P3") if d.get("priority") in PRIO_SEV else "P3",
            "tags": [str(x)[:40] for x in (d.get("tags") or [])][:10], "message": str(d.get("message", ""))[:1000],
            "renotify_minutes": max(0, int(d.get("renotify_minutes") or 0)), "notify_nodata": bool(d.get("notify_nodata", False)),
            "muted_until": d.get("muted_until"), "mute_reason": d.get("mute_reason", "")}


class MonitorManager:
    def __init__(self, engine):
        self.e = engine
        self.defs: dict[str, dict] = {}
        self.state: dict[str, dict[str, dict]] = defaultdict(dict)       # id → grp → {state, since, value, notified}
        self.series: dict[tuple, deque] = {}                             # (metric, grp) → (ts, value)
        self.last_eval: dict[str, float] = {}
        self.errors: dict[str, str] = {}
        self.interval = 30.0
        engine.store.schema(SCHEMA)

    async def load(self) -> None:
        for r in await self.e.store.q("SELECT id, def FROM monitors"):
            try:
                self.defs[r["id"]] = json.loads(r["def"])
            except ValueError:
                continue
        for r in await self.e.store.q("SELECT * FROM monitor_state"):
            self.state[r["monitor_id"]][r["grp"]] = {"state": r["state"], "since": r["since"], "value": r["value"], "notified": r["notified"] or 0}

    # ---------------------------------------------------------------- CRUD
    async def save(self, d: dict, user: str) -> dict:
        m = normalize(d)
        now = time.time()
        await self.e.store.x("INSERT INTO monitors(id,def,created,updated,created_by) VALUES(?,?,?,?,?) "
                             "ON CONFLICT(id) DO UPDATE SET def=excluded.def, updated=excluded.updated",
                             (m["id"], json.dumps(m, ensure_ascii=False), now, now, user))
        old = self.defs.get(m["id"])
        self.defs[m["id"]] = m
        if old and (old["type"], old["query"], old.get("group_by")) != (m["type"], m["query"], m.get("group_by")):
            self.state.pop(m["id"], None)
            await self.e.store.x("DELETE FROM monitor_state WHERE monitor_id=?", (m["id"],))
        self.last_eval.pop(m["id"], None)
        return m

    async def delete(self, mid: str) -> bool:
        if mid not in self.defs:
            return False
        self.defs.pop(mid)
        self.state.pop(mid, None)
        for sql in ("DELETE FROM monitors WHERE id=?", "DELETE FROM monitor_state WHERE monitor_id=?"):
            await self.e.store.x(sql, (mid,))
        return True

    async def mute(self, mid: str, minutes: float | None, reason: str) -> dict:
        m = self.defs[mid]
        m["muted_until"] = (time.time() + minutes * 60) if minutes else None
        m["mute_reason"] = reason[:200] if minutes else ""
        await self.e.store.x("UPDATE monitors SET def=?, updated=? WHERE id=?", (json.dumps(m, ensure_ascii=False), time.time(), mid))
        return m

    # ---------------------------------------------------------------- 값 계산
    async def values(self, m: dict) -> dict[str, float | None]:
        t, q, w = m["type"], m.get("query") or {}, m["window"]
        now = time.time()
        if t in ("log", "nodata"):
            gb = {"host": "host", "source": "source", "entity": "entity", "connector": "connector"}.get(m.get("group_by") if t == "log" else "host", "")
            where, args = ["ts >= ?"], [now - w]
            srcs = [s for s in (q.get("sources") or []) if s]
            if srcs:
                where.append(f"source IN ({','.join('?' * len(srcs))})")
                args += srcs
            ms = q.get("min_severity") or ""
            if ms in SEVS:
                sv = [s for s in SEVS if SEVS.index(s) >= SEVS.index(ms)]
                where.append(f"severity IN ({','.join('?' * len(sv))})")
                args += sv
            if q.get("text") and not q.get("regex"):
                where.append("message LIKE ?")
                args.append(f"%{q['text']}%")
            sel = f"{gb} AS g, " if gb else "'*' AS g, "
            if q.get("text") and q.get("regex"):
                rx = re.compile(safe_regex(str(q["text"]), "정규식"), re.I)      # 저장된 옛 정의도 실행 전에 다시 검사
                rows = await self.e.store.q(f"SELECT {gb or chr(39) + '*' + chr(39)} AS g, message FROM logs WHERE {' AND '.join(where)} "
                                            f"ORDER BY ts DESC LIMIT {REGEX_ROW_CAP}", args)       # 상한에 걸리면 최신 행부터 남김

                def scan() -> dict[str, float]:
                    c: dict[str, float] = defaultdict(float)
                    for r in rows:
                        if rx.search((r["message"] or "")[:4000]):
                            c[r["g"] or ""] += 1
                    return c
                cnt = await asyncio.to_thread(scan)      # 2.30.0 이벤트 루프 밖에서(수십만 행 정규식)
            else:
                rows = await self.e.store.q(f"SELECT {sel}COUNT(*) AS n FROM logs WHERE {' AND '.join(where)}" + (f" GROUP BY {gb}" if gb else ""), args)
                cnt = {(r["g"] or ""): float(r["n"]) for r in rows}
            hp = (q.get("host") or "").lower()
            if hp and gb == "host":
                cnt = {g: v for g, v in cnt.items() if fnmatch.fnmatch(g.lower(), hp)}
            if t == "nodata" or q.get("zero_fill"):
                seen_where, seen_args = ["ts >= ?"], [now - 86400]
                if srcs:
                    seen_where.append(f"source IN ({','.join('?' * len(srcs))})")
                    seen_args += srcs
                hseen = getattr(self.e, "hostseen", None)
                if hseen is not None and hasattr(self.e.store, "seed_hostseen"):   # 2.30.0 평가 때마다 24시간치 로그를 훑지 않고 메모리 집계에서(기동 후 1회만 DB 로 채움)
                    await self.e.store.seed_hostseen(hseen)
                    seen_rows = [{"g": h} for h, hs in list(hseen.items()) if hs[2] >= now - 86400 and (not srcs or hs[0] & set(srcs))][:5000]
                else:
                    seen_rows = await self.e.store.q(f"SELECT DISTINCT host AS g FROM logs WHERE {' AND '.join(seen_where)} LIMIT 5000", seen_args)
                for r in seen_rows:
                    g = r["g"] or ""
                    if g and (not hp or fnmatch.fnmatch(g.lower(), hp)):
                        cnt.setdefault(g, 0.0)
            if not gb and not cnt:
                cnt = {"*": 0.0}
            return cnt
        if t == "connector":
            out = {}
            for c in self.e.connectors:
                if not c.enabled or c.type in ("demo",):
                    continue
                if q.get("types") and c.type not in q["types"]:
                    continue
                st = c.state()
                down = st.get("state") == "down"
                k = ("connector", c.name)
                dq = self.series.setdefault(k, deque(maxlen=720))
                dq.append((now, 1.0 if down else 0.0))
                win = [(ts, v) for ts, v in dq if ts >= now - w]
                span = now - win[0][0] if win else 0.0
                out[c.name] = 1.0 if win and all(v for _, v in win) and span >= w * 0.8 - self.interval else 0.0   # 창 내내 down
            return out
        if t == "anomaly":
            ms = q.get("min_severity") or "error"
            srcs = set(q.get("sources") or [])
            n = sum(1 for a in self.e.anomalies.values()
                    if not a.ack and SEV_RANK.get(a.severity, 0) >= SEV_RANK.get(ms, 0) and now - a.last_seen < max(w, 1800)
                    and (not srcs or (a.event or {}).get("source") in srcs) and a.status != "suppressed")
            return {"*": float(n)}
        if t == "metric":
            cur = self.sample(q["metric"])
            agg = q.get("agg", "avg")
            out = {}
            flt = (q.get("filter") or "").lower()
            for g, v in cur.items():
                if flt and not fnmatch.fnmatch(str(g).lower(), flt):
                    continue
                k = (q["metric"], g)
                dq = self.series.setdefault(k, deque(maxlen=720))
                if not dq or now - dq[-1][0] >= 5:
                    dq.append((now, v))
                vals = [x for ts, x in dq if ts >= now - w and x is not None]
                if not vals:
                    out[g] = None
                    continue
                out[g] = {"avg": sum(vals) / len(vals), "max": max(vals), "min": min(vals), "last": vals[-1]}.get(agg, vals[-1])
            return out
        return {}

    def sample(self, metric: str) -> dict[str, float]:
        """지표의 현재값(그룹별) — 커넥터·엔진 메모리 상태에서 계산(추가 API 호출 없음)"""
        e, out = self.e, {}
        vcs = [c for c in e.connectors if c.type == "vcenter" and c.enabled]
        if metric.startswith(("host.", "cluster.", "datastore.", "vm.")):
            for c in vcs:
                t = getattr(c, "topology", {}) or {}
                if metric.startswith("host."):
                    for hn, h in (t.get("hosts") or {}).items():
                        if metric == "host.cpu_pct" and h.get("cpu_mhz"):
                            out[hn] = round(h.get("cpu_used_mhz", 0) / h["cpu_mhz"] * 100, 1)
                        elif metric == "host.mem_pct" and h.get("mem_mb"):
                            out[hn] = round(h.get("mem_used_mb", 0) / h["mem_mb"] * 100, 1)
                        elif metric == "host.disconnected":
                            out[hn] = 0.0 if h.get("conn") in ("connected", "") else 1.0
                elif metric in ("cluster.cpu_pct", "cluster.mem_pct"):
                    for cn, cl in (t.get("clusters") or {}).items():
                        hs = [t["hosts"].get(x, {}) for x in cl.get("hosts", [])]
                        a, b = ("cpu_used_mhz", "cpu_mhz") if metric == "cluster.cpu_pct" else ("mem_used_mb", "mem_mb")
                        tot = sum(x.get(b) or 0 for x in hs)
                        if tot:
                            out[cn] = round(sum(x.get(a) or 0 for x in hs) / tot * 100, 1)
                elif metric == "cluster.sli_score":
                    for cn, cl in ((getattr(c, "sli", {}) or {}).get("clusters") or {}).items():
                        if cl.get("score") is not None:
                            out[cn] = float(cl["score"])
                elif metric == "datastore.used_pct":
                    for dn, d in (t.get("datastores") or {}).items():
                        if d.get("used_pct") is not None:
                            out[dn] = float(d["used_pct"])
                elif metric == "vm.powered_off":
                    out[c.name] = float(sum(1 for v in (t.get("vms") or {}).values() if v.get("power") == "poweredOff"))
        elif metric == "vcenter.findings_critical":
            for c in vcs:
                out[c.name] = float(sum(1 for f in (getattr(c, "health", {}) or {}).get("findings", []) if f["severity"] in ("critical", "error")))
        elif metric == "connector.latency_ms":
            for c in e.connectors:
                lm = c.state().get("latency_ms")
                if c.enabled and lm is not None:
                    out[c.name] = float(lm)
        elif metric.startswith("vip."):
            for v in (e.avi_vips() if hasattr(e, "avi_vips") else []):
                L = v.get("last") or {}
                val = {"vip.bandwidth_bps": L.get("bw"), "vip.rps": L.get("rps"), "vip.error_rps": L.get("err"), "vip.health": v.get("health"),
                       "vip.down": 0.0 if v.get("state") in ("OPER_UP", None, "") else 1.0}.get(metric)
                if val is not None:
                    out[v["name"]] = float(val)
        elif metric.startswith("vks."):
            for c in e.connectors:
                if c.type != "vks" or not c.enabled:
                    continue
                inv = getattr(c, "inv", {}) or {}
                lab = getattr(c, "cluster_label", c.name)
                if metric == "vks.problem_pods":
                    out[lab] = float(sum(1 for p in inv.get("pods", []) if p.get("reason") or p.get("phase") not in ("Running", "Succeeded")))
                else:
                    out[lab] = float(sum(1 for n in inv.get("nodes", []) if str(n.get("ready")) not in ("True", "true")))
        elif metric == "agent.minutes_silent":
            items = getattr(getattr(e, "agents", None), "items", {}) or {}
            now = time.time()
            for it in items.values():
                if isinstance(it, dict) and not it.get("retired"):
                    last = max(it.get("last_seen") or 0, it.get("last_hb") or 0)
                    if last:
                        out[it.get("host", "?")] = round((now - last) / 60, 1)
        elif metric == "server.unhealthy":
            for c in e.connectors:
                if c.type == "redfish" and c.enabled:
                    h = (getattr(c, "server", {}) or {}).get("health", "")
                    out[getattr(c, "display", c.name)] = {"Critical": 2.0, "Warning": 1.0}.get(h, 0.0)
        elif metric.startswith("fortigate."):
            fg = getattr(e, "fortigate", None)
            if fg:
                out = fg.metric(metric)
        elif metric.startswith("platform."):
            rt = e.runtime() if hasattr(e, "runtime") else {}
            if metric == "platform.ai_queue":
                aq = getattr(e, "aq", None)
                out["platform"] = float(aq.depth() if aq else e.llm_q.qsize())
            elif metric == "platform.ingest_eps":
                out["platform"] = float(e.stats.get("eps", 0) or 0)
            elif metric == "platform.pipeline_lag_ms":
                out["platform"] = float(((rt.get("pipeline") or {}).get("lag_ms")) or e.pipe.get("lag_ms", 0) or 0)
            elif metric == "platform.disk_free_mb":
                v = (rt.get("store") or {}).get("disk_free_mb")
                if v is not None:
                    out["platform"] = float(v)
        return out

    # ---------------------------------------------------------------- 판정·통지
    def judge(self, m: dict, v: float | None) -> str:
        if v is None:
            return "NO_DATA"
        if _cmp(m["op"], v, m["critical"]):
            return "ALERT"
        if m.get("warning") is not None and _cmp(m["op"], v, m["warning"]):
            return "WARN"
        return "OK"

    async def evaluate(self, m: dict, notify: bool = True) -> dict[str, dict]:
        now = time.time()
        vals = await self.values(m)
        st = self.state[m["id"]]
        muted = bool(m.get("muted_until") and m["muted_until"] > now)
        for g, v in vals.items():
            new = self.judge(m, v)
            cur = st.get(g) or {"state": "OK", "since": now, "value": None, "notified": 0}
            prev = cur["state"]
            cur["value"] = v
            if new != prev:
                cur.update(state=new, since=now)
                await self.e.store.x("INSERT INTO monitor_events(ts,monitor_id,grp,from_state,to_state,value) VALUES(?,?,?,?,?,?)",
                                     (now, m["id"], g, prev, new, v))
                if notify and not muted and (new in ("ALERT", "WARN") or (new == "NO_DATA" and m.get("notify_nodata")) or prev in ("ALERT", "WARN")):
                    self._emit(m, g, v, new, prev)
                    cur["notified"] = now
            elif notify and not muted and new in ("ALERT", "WARN") and m.get("renotify_minutes") and now - (cur.get("notified") or 0) >= m["renotify_minutes"] * 60:
                self._emit(m, g, v, new, prev, renotify=True)
                cur["notified"] = now
            st[g] = cur
            await self.e.store.x("INSERT INTO monitor_state(monitor_id,grp,state,since,value,notified) VALUES(?,?,?,?,?,?) "
                                 "ON CONFLICT(monitor_id,grp) DO UPDATE SET state=excluded.state, since=excluded.since, value=excluded.value, notified=excluded.notified",
                                 (m["id"], g, cur["state"], cur["since"], v, cur.get("notified") or 0))
        for g in [g for g in st if g not in vals]:      # 사라진 그룹(호스트 제거 등) 정리
            st.pop(g, None)
            await self.e.store.x("DELETE FROM monitor_state WHERE monitor_id=? AND grp=?", (m["id"], g))
        self.last_eval[m["id"]] = now
        return st

    def _fmt(self, m: dict, v: float | None) -> str:
        if v is None:
            return "데이터 없음"
        unit = METRICS.get((m.get("query") or {}).get("metric", ""), ("", "", ""))[1] if m["type"] == "metric" else ("건" if m["type"] in ("log", "nodata", "anomaly") else "")
        return f"{round(v, 2):g}{unit}"

    def _emit(self, m: dict, g: str, v: float | None, new: str, prev: str, renotify: bool = False) -> None:
        recovered = new in ("OK",) and prev in ("ALERT", "WARN")
        thr = m["critical"] if new == "ALERT" else m.get("warning")
        tag = {"ALERT": "경보", "WARN": "경고", "NO_DATA": "데이터 없음", "OK": "복구"}[new]
        grp = "" if g in ("*", "") else f" [{g}]"
        body = (m.get("message") or "").replace("{{value}}", self._fmt(m, v)).replace("{{group}}", g).replace("{{name}}", m["name"])
        msg = (f"[모니터 {tag}] {m['name']}{grp}: 현재 {self._fmt(m, v)}"
               + (f" {m['op']} 임계 {round(thr, 2):g}" if thr is not None and not recovered and new != "NO_DATA" else "")
               + (" (재알림)" if renotify else "") + (f" — {body}" if body else ""))
        sev = "info" if recovered else (STATE_SEV.get(new, "warning") if new != "ALERT" else PRIO_SEV.get(m.get("priority", "P3"), "critical"))
        ev = LogEvent(source="monitor", connector="monitor", message=msg, severity=sev, host=g if g not in ("*", "") else "",
                      entity=m["name"], kind="monitor",
                      attrs={"monitor_id": m["id"], "monitor_state": new, "monitor_prev": prev, "value": v, "group": g,
                             "priority": m.get("priority"), "tags": m.get("tags"),
                             **({"force_anomaly": True, "category": "monitor"} if not recovered and new in ("ALERT", "WARN", "NO_DATA") else {})})
        self.e.submit(ev)
        if recovered:                                   # 복구되면 그 모니터·그룹의 열린 이상징후를 자동 확인
            for a in list(self.e.anomalies.values()):
                ea = (a.event or {}).get("attrs") or {}
                if not a.ack and ea.get("monitor_id") == m["id"] and ea.get("group") == g:
                    asyncio.ensure_future(self.e.ack(a.id))

    async def loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            t0 = time.time()
            for m in list(self.defs.values()):
                if not m.get("enabled", True):
                    continue
                every = 60.0 if m["type"] in ("log", "nodata") and m["window"] >= 600 else self.interval
                if t0 - self.last_eval.get(m["id"], 0) < every - 1:
                    continue
                try:
                    await self.evaluate(m)
                    self.errors.pop(m["id"], None)
                except Exception as ex:  # noqa: BLE001
                    self.errors[m["id"]] = f"{type(ex).__name__}: {ex}"[:300]
            if hasattr(self.e, "sup"):
                self.e.sup.beat("monitors")
            await asyncio.sleep(max(5.0, self.interval - (time.time() - t0)))

    # ---------------------------------------------------------------- 조회
    def summary(self, m: dict) -> dict:
        st = self.state.get(m["id"], {})
        cnt = defaultdict(int)
        for x in st.values():
            cnt[x["state"]] += 1
        worst = "ALERT" if cnt["ALERT"] else "WARN" if cnt["WARN"] else "NO_DATA" if cnt["NO_DATA"] else ("OK" if st else "PENDING")
        muted = bool(m.get("muted_until") and m["muted_until"] > time.time())
        return {**m, "status": worst, "muted": muted, "groups": dict(cnt), "group_total": len(st),
                "last_eval": self.last_eval.get(m["id"]), "error": self.errors.get(m["id"], ""),
                "triggered_since": min((x["since"] for x in st.values() if x["state"] in ("ALERT", "WARN")), default=None)}

    async def detail(self, mid: str) -> dict:
        m = self.defs[mid]
        st = self.state.get(mid, {})
        hist = await self.e.store.q("SELECT ts, grp, from_state, to_state, value FROM monitor_events WHERE monitor_id=? ORDER BY ts DESC LIMIT 200", (mid,))
        series = {}
        if m["type"] in ("metric", "connector"):
            key = (m["query"].get("metric") if m["type"] == "metric" else "connector")
            for (k, g), dq in self.series.items():
                if k == key and g in st:
                    series[g] = [[round(ts), v] for ts, v in list(dq)[-120:]]
        groups = sorted(({"group": g, **x} for g, x in st.items()), key=lambda x: (["ALERT", "WARN", "NO_DATA", "OK"].index(x["state"]) if x["state"] in ("ALERT", "WARN", "NO_DATA", "OK") else 9, x["group"]))
        return {"monitor": self.summary(m), "groups": groups[:2000], "history": hist, "series": series}
