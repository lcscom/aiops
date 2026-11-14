"""VKS 관측(2.10.0) — 구성도 개체를 누르면 '지금 상태 · 이벤트 · 로그 · 변경 이력 · 연관'을 한 번에

  · 변경 이력(vks_activity): 구성 수집(기본 5분)·파드 상태(기본 1분) 스냅숏을 비교해 기록
      롤아웃(이미지·리비전) · 스케일(레플리카·HPA) · 생성·삭제 · 준비 상태 변화 · 파드 교체 · 컨테이너 재시작(+종료 사유) ·
      CrashLoop 등 진입·회복 · 노드 Ready·추가·삭제 · Service VIP·유형 · PVC 단계·크기
  · 이벤트: Kubernetes API 에서 그 개체(+소속 파드·ReplicaSet) 이벤트를 즉시 조회(Normal 포함) + 저장된 경고 이벤트
  · 로그: 수집된 파드 로그(k8s-log) + 실시간 tail(기존 /api/vks/{name}/log) — 비밀값 패턴은 가림
  · 연관: 열린 인시던트 · 실행 노드 → vSphere VM → ESXi · VM 액티비티 · VCF Ops 지표 · Avi VS · 스토리지 정책
읽기 전용 — Secret·ConfigMap 내용은 읽지 않는다.
"""
from __future__ import annotations

import asyncio
import collections
import re
import time
from typing import Any

SCHEMA = """CREATE TABLE IF NOT EXISTS vks_activity(ts REAL, connector TEXT, kind TEXT, ns TEXT, name TEXT, action TEXT, detail TEXT, sev TEXT, pod TEXT);
CREATE INDEX IF NOT EXISTS ix_vksa_ts ON vks_activity(connector, ts);
CREATE INDEX IF NOT EXISTS ix_vksa_obj ON vks_activity(connector, ns, name, ts);"""
ACTIONS = {"created": "생성", "deleted": "삭제", "rollout": "롤아웃", "scale": "스케일", "ready": "준비 상태", "pod_replace": "파드 교체",
           "restart": "재시작", "pod_bad": "파드 이상", "pod_ok": "파드 회복", "node": "노드", "network": "네트워크", "storage": "스토리지",
           "hpa": "자동 스케일"}
OBJ_KEYS = (("deployments", "Deployment"), ("statefulsets", "StatefulSet"), ("daemonsets", "DaemonSet"), ("cronjobs", "CronJob"),
            ("services", "Service"), ("ingresses", "Ingress"), ("pvcs", "PersistentVolumeClaim"), ("hpas", "HorizontalPodAutoscaler"))
SECRET_PAT = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1<가림>"),
    (re.compile(r"(?i)\b((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|credential)s?"
                r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',;&]{3,})"), r"\1<가림>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "<JWT 가림>"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "<키 가림>"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s/]+@"), r"\1<가림>@"),
]


def mask_log(line: str) -> str:
    s = str(line)
    for rx, rep in SECRET_PAT:
        s = rx.sub(rep, s)
    return s


def _owner_map(topo: dict) -> dict[tuple, str]:
    return {(r["ns"], r["name"]): r.get("owner", "") for r in topo.get("replicasets") or []}


def pod_owner(p: dict, rs: dict, jobs: dict | None = None) -> tuple[str, str]:
    """파드 → (워크로드 종류, 이름)"""
    ok, on = p.get("owner", ""), p.get("owner_name", "")
    if ok == "ReplicaSet":
        return "Deployment", rs.get((p["ns"], on)) or on.rsplit("-", 1)[0]
    if ok in ("StatefulSet", "DaemonSet"):
        return ok, on
    if ok == "Job":
        cron = (jobs or {}).get((p["ns"], on))
        return ("CronJob", cron) if cron else ("Job", on)
    return "Pod", p["name"]


def diff_topo(prev: dict, cur: dict) -> list[dict[str, Any]]:
    """구성 스냅숏 비교 → 변경 행"""
    out: list[dict] = []

    def row(kind, o, action, detail, sev="info"):
        out.append({"kind": kind, "ns": o.get("ns", ""), "name": o.get("name", ""), "action": action, "detail": detail, "sev": sev, "pod": ""})
    for key, kind in OBJ_KEYS:
        if key not in prev or key not in cur:          # 권한 없음 등으로 한쪽이 비면 비교 안 함
            continue
        a = {(o.get("ns", ""), o["name"]): o for o in prev.get(key) or []}
        b = {(o.get("ns", ""), o["name"]): o for o in cur.get(key) or []}
        added, gone = [k for k in b if k not in a], [k for k in a if k not in b]
        if len(added) + len(gone) > 200:              # 대량(네임스페이스 정리·권한 변화) — 요약 한 줄
            row(kind, {"ns": "", "name": f"({kind})"}, "created" if len(added) >= len(gone) else "deleted", f"{kind} 대량 변경: 생성 {len(added)} · 삭제 {len(gone)}", "warn")
            continue
        for k in added:
            o = b[k]
            d = {"Deployment": f"레플리카 {o.get('want')} · 이미지 {', '.join(o.get('images') or [])}", "StatefulSet": f"레플리카 {o.get('want')}",
                 "Service": f"{o.get('type')} {' '.join(o.get('ports') or [])}", "Ingress": " ".join(o.get("hosts") or []),
                 "PersistentVolumeClaim": f"{o.get('size', '')} {o.get('sc', '')}"}.get(kind, "")
            row(kind, o, "created", f"{kind} 생성" + (f" — {d}" if d.strip() else ""))
        for k in gone:
            row(kind, a[k], "deleted", f"{kind} 삭제", "warn")
        for k in b:
            if k not in a:
                continue
            x, y = a[k], b[k]
            if kind in ("Deployment", "StatefulSet", "DaemonSet"):
                if (x.get("images") or []) != (y.get("images") or []):
                    pairs = [f"{i} → {j}" for i, j in zip(x.get("images") or [], y.get("images") or []) if i != j] or [", ".join(y.get("images") or [])]
                    row(kind, y, "rollout", "이미지 " + "; ".join(pairs) + (f" (리비전 {x.get('rev')} → {y.get('rev')})" if x.get("rev") != y.get("rev") and y.get("rev") else ""))
                elif x.get("rev") and y.get("rev") and x.get("rev") != y.get("rev"):
                    row(kind, y, "rollout", f"리비전 {x.get('rev')} → {y.get('rev')} (파드 템플릿 변경 — 환경변수·설정·리소스 등)")
                if kind != "DaemonSet" and x.get("want") != y.get("want"):
                    row(kind, y, "scale", f"레플리카 {x.get('want')} → {y.get('want')}", "warn" if not y.get("want") else "info")
                if (x.get("cms") or []) != (y.get("cms") or []) or (x.get("secrets") or []) != (y.get("secrets") or []):
                    row(kind, y, "rollout", "참조 ConfigMap·Secret 이름 변경")
                if not x.get("cond") and y.get("cond"):
                    row(kind, y, "rollout", "롤아웃 실패 — " + y["cond"], "error")
                if bool(x.get("paused")) != bool(y.get("paused")):
                    row(kind, y, "rollout", "롤아웃 일시 중지" if y.get("paused") else "롤아웃 재개")
            elif kind == "Service":
                if x.get("type") != y.get("type"):
                    row(kind, y, "network", f"유형 {x.get('type')} → {y.get('type')}", "warn")
                if (x.get("lb") or []) != (y.get("lb") or []):
                    row(kind, y, "network", f"외부 IP {', '.join(x.get('lb') or []) or '없음'} → {', '.join(y.get('lb') or []) or '없음'}", "warn" if not y.get("lb") else "info")
                if (x.get("selector") or {}) != (y.get("selector") or {}):
                    row(kind, y, "network", f"셀렉터 {x.get('selector')} → {y.get('selector')}", "warn")
                if (x.get("ports") or []) != (y.get("ports") or []):
                    row(kind, y, "network", f"포트 {' '.join(x.get('ports') or [])} → {' '.join(y.get('ports') or [])}")
            elif kind == "Ingress":
                if (x.get("services") or []) != (y.get("services") or []) or (x.get("hosts") or []) != (y.get("hosts") or []):
                    row(kind, y, "network", f"규칙 변경 — 호스트 {' '.join(y.get('hosts') or [])} · 백엔드 {', '.join(y.get('services') or [])}")
                if (x.get("lb") or []) != (y.get("lb") or []):
                    row(kind, y, "network", f"주소 {', '.join(x.get('lb') or []) or '없음'} → {', '.join(y.get('lb') or []) or '없음'}")
            elif kind == "PersistentVolumeClaim":
                if x.get("phase") != y.get("phase"):
                    row(kind, y, "storage", f"단계 {x.get('phase')} → {y.get('phase')}", "error" if y.get("phase") == "Lost" else ("info" if y.get("phase") == "Bound" else "warn"))
                if x.get("size") != y.get("size") and x.get("size") and y.get("size"):
                    row(kind, y, "storage", f"크기 {x.get('size')} → {y.get('size')} (확장)")
            elif kind == "HorizontalPodAutoscaler":
                if x.get("current") != y.get("current"):
                    tgt = {"ns": y.get("ns", ""), "name": y.get("target", "")}
                    row(y.get("target_kind") or "Deployment", tgt, "hpa", f"HPA {y['name']} 레플리카 {x.get('current')} → {y.get('current')} (범위 {y.get('min')}–{y.get('max')})",
                        "warn" if y.get("max") and int(y.get("current") or 0) >= int(y["max"]) else "info")
                if (x.get("min"), x.get("max")) != (y.get("min"), y.get("max")):
                    row(y.get("target_kind") or "Deployment", {"ns": y.get("ns", ""), "name": y.get("target", "")}, "hpa",
                        f"HPA 범위 {x.get('min')}–{x.get('max')} → {y.get('min')}–{y.get('max')}")
            elif kind == "CronJob" and bool(x.get("suspend")) != bool(y.get("suspend")):
                row(kind, y, "scale", "일시 중지(suspend)" if y.get("suspend") else "재개", "warn" if y.get("suspend") else "info")
    return out


def diff_pods(prev: list[dict], cur: list[dict], topo: dict) -> list[dict[str, Any]]:
    """파드 스냅숏 비교 → 워크로드 단위 변경 행(교체는 묶음, 재시작·이상 진입·회복은 파드별)"""
    from .vksmap import pod_state
    rs = _owner_map(topo)
    jobs = {(j["ns"], j["name"]): j.get("owner", "") for j in topo.get("jobs") or []}
    a = {(p["ns"], p["name"]): p for p in prev}
    b = {(p["ns"], p["name"]): p for p in cur}
    out: list[dict] = []
    churn: dict[tuple, dict] = {}
    for k in set(a) | set(b):
        p = b.get(k) or a.get(k)
        kind, name = pod_owner(p, rs, jobs)
        if kind == "Job" or kind == "CronJob":            # 배치 파드 생성·종료는 정상 흐름 — 실패만
            if k in b and pod_state(b[k]) == "down" and (k not in a or pod_state(a[k]) != "down"):
                out.append({"kind": kind, "ns": p["ns"], "name": name, "action": "pod_bad", "detail": f"Job 파드 {p['name']} 실패 {b[k].get('reason', '')}".strip(), "sev": "warn", "pod": p["name"]})
            continue
        key = (kind, p["ns"], name)
        if k not in a:
            churn.setdefault(key, {"add": [], "del": []})["add"].append(p["name"])
            continue
        if k not in b:
            churn.setdefault(key, {"add": [], "del": []})["del"].append(p["name"])
            continue
        x, y = a[k], b[k]
        dr = int(y.get("restarts") or 0) - int(x.get("restarts") or 0)
        if dr > 0:
            lt = y.get("last_term") or {}
            why = f" — 직전 종료 {lt.get('reason', '')} (exit {lt.get('exit')})" if lt.get("reason") or lt.get("exit") is not None else ""
            out.append({"kind": kind, "ns": p["ns"], "name": name, "action": "restart", "detail": f"파드 {p['name']} 재시작 +{dr} (누적 {y.get('restarts')}){why}",
                        "sev": "error" if lt.get("reason") == "OOMKilled" else "warn", "pod": p["name"], "n": dr})
        sx, sy = pod_state(x), pod_state(y)
        if sy in ("warn", "down") and sx not in ("warn", "down"):
            out.append({"kind": kind, "ns": p["ns"], "name": name, "action": "pod_bad",
                        "detail": f"파드 {p['name']} {y.get('reason') or y.get('phase')}" + (f" — {y.get('msg')}" if y.get("msg") else ""),
                        "sev": "error" if sy == "down" else "warn", "pod": p["name"]})
        elif sx in ("warn", "down") and sy == "ok":
            out.append({"kind": kind, "ns": p["ns"], "name": name, "action": "pod_ok", "detail": f"파드 {p['name']} 정상화 ({x.get('reason') or x.get('phase')} 해소)", "sev": "info", "pod": p["name"]})
        if x.get("node") and y.get("node") and x["node"] != y["node"]:
            out.append({"kind": kind, "ns": p["ns"], "name": name, "action": "pod_replace", "detail": f"파드 {p['name']} 노드 {x['node']} → {y['node']}", "sev": "info", "pod": p["name"]})
    for (kind, ns, name), c in churn.items():
        if kind == "Pod":
            out.append({"kind": "Pod", "ns": ns, "name": name, "action": "created" if c["add"] else "deleted", "detail": "독립 파드 " + ("생성" if c["add"] else "삭제"),
                        "sev": "info" if c["add"] else "warn", "pod": name})
            continue
        parts = ([f"생성 {len(c['add'])}"] if c["add"] else []) + ([f"삭제 {len(c['del'])}"] if c["del"] else [])
        names = (c["add"] + c["del"])[:4]
        out.append({"kind": kind, "ns": ns, "name": name, "action": "pod_replace", "detail": f"파드 {' · '.join(parts)} — {', '.join(names)}{' …' if len(c['add']) + len(c['del']) > 4 else ''}",
                    "sev": "warn" if c["del"] and not c["add"] else "info", "pod": (c["add"] or c["del"])[0]})
    return out


def diff_nodes(prev: list[dict], cur: list[dict]) -> list[dict[str, Any]]:
    a, b = {n["name"]: n for n in prev}, {n["name"]: n for n in cur}
    out = []
    for k in b:
        if k not in a:
            out.append({"kind": "Node", "ns": "", "name": k, "action": "node", "detail": f"노드 추가 ({', '.join(b[k].get('roles') or [])})", "sev": "info", "pod": ""})
        elif a[k].get("ready") != b[k].get("ready"):
            ok = b[k].get("ready") == "True"
            out.append({"kind": "Node", "ns": "", "name": k, "action": "node", "detail": f"Ready {a[k].get('ready')} → {b[k].get('ready')}", "sev": "info" if ok else "error", "pod": ""})
        elif bool(a[k].get("unschedulable")) != bool(b[k].get("unschedulable")):
            out.append({"kind": "Node", "ns": "", "name": k, "action": "node", "detail": "cordon(스케줄 불가)" if b[k].get("unschedulable") else "uncordon(스케줄 재개)",
                        "sev": "warn" if b[k].get("unschedulable") else "info", "pod": ""})
        elif sorted(a[k].get("pressure") or []) != sorted(b[k].get("pressure") or []):
            out.append({"kind": "Node", "ns": "", "name": k, "action": "node", "detail": f"압박 {', '.join(a[k].get('pressure') or []) or '없음'} → {', '.join(b[k].get('pressure') or []) or '없음'}",
                        "sev": "warn" if b[k].get("pressure") else "info", "pod": ""})
    for k in a:
        if k not in b:
            out.append({"kind": "Node", "ns": "", "name": k, "action": "node", "detail": "노드 삭제(클러스터에서 제거)", "sev": "warn", "pod": ""})
    return out


class VksObserver:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        c = cfg or {}
        self.retention_days = float(c.get("retention_days", 30))
        self._schema = False
        self._snap: dict[str, dict] = {}                 # connector → {topo_ts, pods_ts, topo, pods, nodes}
        self.recent: collections.deque = collections.deque(maxlen=20000)
        self.stats = {"written": 0, "last": 0.0, "error": ""}

    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    def connectors(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vks"]

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(10)
        last_purge = 0.0
        while True:
            beat()
            try:
                await self.tick()
                if time.time() - last_purge > 86400:
                    last_purge = time.time()
                    await self.e.store.x("DELETE FROM vks_activity WHERE ts < ?", (time.time() - self.retention_days * 86400,))
            except Exception as e:  # noqa: BLE001
                self.stats["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(20)

    async def tick(self) -> int:
        self._ensure()
        if not self.recent and not getattr(self, "_seeded", False):     # 재기동 직후 — 최근 1시간 배지용 메모리 복원
            self._seeded = True
            try:
                for r in reversed(await self.e.store.q("SELECT ts,connector,kind,ns,name,action,detail,sev,pod FROM vks_activity WHERE ts>=? ORDER BY ts DESC LIMIT 5000",
                                                       (time.time() - 3600,))):
                    if r["action"] == "restart":
                        m = re.search(r"재시작 \+(\d+)", r["detail"] or "")
                        r["n"] = int(m.group(1)) if m else 1
                    self.recent.append(r)
            except Exception:  # noqa: BLE001
                pass
        rows: list[dict] = []
        for c in self.connectors():
            inv = getattr(c, "inv", {}) or {}
            s = self._snap.get(c.name)
            topo, pods, nodes = inv.get("topo") or {}, inv.get("pods") or [], inv.get("nodes") or []
            tts, pts = inv.get("topo_updated"), inv.get("updated")
            if s is None:                                # 첫 스냅숏(재시작 직후) — 기준만 잡음
                if tts or pts:
                    self._snap[c.name] = {"tts": tts, "pts": pts, "topo": topo, "pods": pods, "nodes": nodes}
                continue
            out: list[dict] = []
            if tts and tts != s["tts"]:
                if s["topo"]:
                    out += diff_topo(s["topo"], topo)
                s.update(tts=tts, topo=topo)
            if pts and pts != s["pts"]:
                if s["pods"] or pods:
                    out += diff_pods(s["pods"], pods, topo)
                if s["nodes"]:
                    out += diff_nodes(s["nodes"], nodes)
                s.update(pts=pts, pods=pods, nodes=nodes)
            now = time.time()
            for r in out:
                r.update(ts=now, connector=c.name)
            rows += out
        if rows:
            await self.record(rows)
        return len(rows)

    async def record(self, rows: list[dict]) -> None:
        self._ensure()
        for r in rows:
            self.recent.append(r)
        await self.e.store.xm("INSERT INTO vks_activity(ts,connector,kind,ns,name,action,detail,sev,pod) VALUES (?,?,?,?,?,?,?,?,?)",
                              [(r["ts"], r["connector"], r["kind"], r["ns"], r["name"], r["action"], r["detail"][:600], r["sev"], r.get("pod", "")) for r in rows])
        self.stats.update(written=self.stats["written"] + len(rows), last=time.time())

    def recent_index(self, connector: str, seconds: float = 3600) -> dict[str, dict]:
        """구성도 배지용 — 노드 id('Deployment:ns/name'·'Node:/name') → {n, restart, last, action}"""
        cut = time.time() - seconds
        out: dict[str, dict] = {}
        for r in reversed(self.recent):
            if r["ts"] < cut:
                break
            if r["connector"] != connector:
                continue
            nid = f"{r['kind']}:{r['ns']}/{r['name']}"
            d = out.setdefault(nid, {"n": 0, "restart": 0, "last": r["ts"], "action": ACTIONS.get(r["action"], r["action"]), "detail": r["detail"][:120]})
            d["n"] += 1
            if r["action"] == "restart":
                d["restart"] += int(r.get("n") or 1)
        return out

    async def query(self, connector: str, kind: str = "", ns: str = "", name: str = "", hours: float = 168, limit: int = 300) -> list[dict]:
        self._ensure()
        sql = "SELECT ts,kind,ns,name,action,detail,sev,pod FROM vks_activity WHERE connector=? AND ts>=?"
        p: list[Any] = [connector, time.time() - hours * 3600]
        if name:
            sql += " AND ns=? AND name=?"
            p += [ns, name]
            if kind:
                sql += " AND kind=?"
                p.append(kind)
        elif ns:
            sql += " AND ns=?"
            p.append(ns)
        sql += " ORDER BY ts DESC LIMIT ?"
        p.append(max(1, min(limit, 2000)))
        rows = await self.e.store.q(sql, p)
        for r in rows:
            r["label"] = ACTIONS.get(r["action"], r["action"])
        return rows

    async def event_counts(self, connector: str, seconds: float = 3600) -> dict[str, int]:
        """저장된 경고(k8s-event·k8s-pod·k8s-node) 개체별 건수"""
        try:
            rows = await self.e.store.q("SELECT entity, COUNT(*) AS n FROM logs WHERE ts>=? AND connector=? AND kind IN ('k8s-event','k8s-pod','k8s-node') "
                                        "AND severity IN ('warning','error','critical') GROUP BY entity", (time.time() - seconds, connector))
        except Exception:  # noqa: BLE001
            return {}
        return {r["entity"]: r["n"] for r in rows if r.get("entity")}

    async def graph(self, name: str, ns: str = "", system: bool = False, q: str = "") -> dict[str, Any]:
        from . import vksmap
        evc = await self.event_counts(name)
        return vksmap.cluster_graph(self.e, name, ns, system, q, evc=evc, recent=self.recent_index(name))

    # ------------------------------------------------------------------ 개체 상세
    async def detail(self, name: str, kind: str, ns: str, obj: str, hours: float = 24) -> dict[str, Any]:
        from . import vksmap
        c = next((x for x in self.connectors() if x.name == name), None)
        if not c:
            raise KeyError(name)
        g = await self.graph(name, ns if kind != "Node" else "", system=True)
        nid = f"{kind}:{ns}/{obj}"
        node = next((n for n in g["nodes"] if n["id"] == nid), None)
        kn = next((k for k in g["k8s_nodes"] if k["name"] == obj), None) if kind == "Node" else None
        if not node and not kn:
            raise LookupError(nid)
        inv = getattr(c, "inv", {}) or {}
        allpods = inv.get("pods") or []
        # 관련 파드
        pod_names: list[str] = []
        if kind == "Node":
            podlist = [{"name": p["name"], "ns": p["ns"], "st": vksmap.pod_state(p), "phase": p.get("phase", ""), "reason": p.get("reason", ""), "ready": p.get("ready", ""),
                        "restarts": int(p.get("restarts") or 0), "node": obj, "containers": p.get("containers") or [], "msg": p.get("msg", ""),
                        "last_term": p.get("last_term"), "age": p.get("age")} for p in allpods if p.get("node") == obj]
        else:
            podlist = list(node.get("podlist") or [])
            downs = [e["to"] for e in g["edges"] if e["from"] == nid]
            if kind in ("Service", "Ingress", "VIP"):                # 하류 워크로드의 파드
                seen, stack = set(), list(downs)
                while stack:
                    x = stack.pop()
                    if x in seen:
                        continue
                    seen.add(x)
                    n2 = next((n for n in g["nodes"] if n["id"] == x), None)
                    if not n2:
                        continue
                    if n2["kind"] in vksmap.WL_KINDS:
                        podlist += [dict(p, workload=n2["name"]) for p in n2.get("podlist") or []]
                    elif n2["kind"] in ("Service", "Ingress"):
                        stack += [e["to"] for e in g["edges"] if e["from"] == x]
            elif kind == "PersistentVolumeClaim":
                users = [e["from"] for e in g["edges"] if e["to"] == nid and e["kind"] == "mount"]
                for u in users:
                    n2 = next((n for n in g["nodes"] if n["id"] == u), None)
                    if n2:
                        podlist += [dict(p, workload=n2["name"]) for p in n2.get("podlist") or []]
            for p in podlist:
                p.setdefault("ns", ns)
        podlist.sort(key=lambda x: (-vksmap.RANK.get(x["st"], 0), x["name"]))
        pod_names = [p["name"] for p in podlist]
        # 이벤트: 실시간(Normal 포함) + 저장된 경고
        names = {obj} | set(pod_names[:200])
        kinds = None
        if kind == "Deployment":
            names |= {r["name"] for r in (inv.get("topo") or {}).get("replicasets") or [] if r.get("ns") == ns and r.get("owner") == obj}
        if kind == "Service":
            names |= {obj}
        live, live_err = [], ""
        try:
            live = await asyncio.wait_for(c.object_events(ns if kind not in ("Node", "PersistentVolume", "StorageClass") else "", names, kinds), 12)
        except Exception as e:  # noqa: BLE001
            live_err = f"{type(e).__name__}: {e}"[:200]
        ents = [f"{kind}/{ns}/{obj}" if ns else f"{kind}/{obj}"] + [f"Pod/{p.get('ns') or ns}/{p['name']}" for p in podlist[:200]]
        stored = await self._stored(name, ents, hours, ("k8s-event", "k8s-pod", "k8s-node"), 200)
        logs = await self._stored(name, [f"Pod/{p.get('ns') or ns}/{p['name']}" for p in podlist[:200]], hours, ("k8s-log",), 300)
        for r in logs:
            r["message"] = mask_log(r["message"])
        act = await self.query(name, "" if kind in ("Service", "Ingress", "VIP", "PersistentVolumeClaim") else kind, ns, obj, hours=max(hours, 168), limit=200)
        if kind in ("Service", "Ingress", "VIP", "PersistentVolumeClaim"):      # 하류 워크로드 변경도 함께
            wls = {(p.get("ns") or ns, p.get("workload")) for p in podlist if p.get("workload")}
            for wns, wn in list(wls)[:10]:
                act += [dict(r, via=wn) for r in await self.query(name, "", wns, wn, hours=max(hours, 168), limit=50)]
            act.sort(key=lambda r: -r["ts"])
        # 연관: 노드 → VM → ESXi · 인시던트 · VM 액티비티 · Ops 지표
        node_names = sorted({p["node"] for p in podlist if p.get("node")} | ({obj} if kind == "Node" else set()))[:12]
        knodes = {k["name"]: k for k in g["k8s_nodes"]}
        infra = [{"node": n, "status": (knodes.get(n) or {}).get("status", ""), "esxi": (knodes.get(n) or {}).get("esxi", ""),
                  "vsphere_cluster": (knodes.get(n) or {}).get("vsphere_cluster", ""), "vm_power": (knodes.get(n) or {}).get("vm_power", ""),
                  "vm": (knodes.get(n) or {}).get("vm", False), "pods": sum(1 for p in podlist if p.get("node") == n),
                  "ops": self._ops(n)} for n in node_names]
        esx = sorted({i["esxi"] for i in infra if i["esxi"]})
        vm_act = []
        mv = getattr(self.e, "moves", None)
        if mv and node_names:
            try:
                vm_act = (await mv.related(node_names, esx, (), time.time() - 7 * 86400, time.time() + 60, 30))[:30]
            except Exception:  # noqa: BLE001
                vm_act = []
        incs = await self._incidents(([obj] if kind == "Node" else [f"{ns}/{obj}" if ns else obj]) + pod_names[:5] + node_names[:5])   # 짧은 일반 이름(worker 등) 단독 검색은 오탐
        target = node or {"id": f"Node:/{obj}", "kind": "Node", "name": obj, "ns": "", "status": kn["status"], "own": kn["status"], "issues": kn["issues"],
                          "abbr": "node", "detail": f"{', '.join(kn.get('roles') or [])} · {kn.get('kubelet', '')} · {kn.get('cpu', '')} vCPU · {kn.get('memory', '')}",
                          "events": kn.get("events", 0), "k8s": kn}
        rel = [{"dir": "→" if e["from"] == nid else "←", "kind": e["kind"], "id": e["to"] if e["from"] == nid else e["from"]}
               for e in g["edges"] if nid in (e["from"], e["to"])]
        nm = {n["id"]: n for n in g["nodes"]}
        for r in rel:
            o = nm.get(r["id"]) or {}
            r.update(name=o.get("name", ""), okind=o.get("kind", ""), status=o.get("status", ""))
        return {"connector": name, "cluster": g["cluster"], "node": target, "pods": podlist[:300], "events": live, "events_error": live_err,
                "stored_events": stored, "logs": logs, "activity": act[:300], "infra": infra, "vm_activity": vm_act, "incidents": incs,
                "related": rel, "generated": time.time()}

    def _ops(self, name: str) -> str:
        om = getattr(self.e, "opsmetrics", None)
        try:
            return om.brief(name) if om else ""
        except Exception:  # noqa: BLE001
            return ""

    async def _stored(self, connector: str, entities: list[str], hours: float, kinds: tuple, limit: int) -> list[dict]:
        ents = [e for e in dict.fromkeys(entities) if e][:400]
        if not ents:
            return []
        try:
            return await self.e.store.q(f"SELECT ts,severity,kind,entity,host,message FROM logs WHERE ts>=? AND connector=? AND kind IN ({','.join('?' * len(kinds))}) "
                                        f"AND entity IN ({','.join('?' * len(ents))}) ORDER BY ts DESC LIMIT ?",
                                        (time.time() - hours * 3600, connector, *kinds, *ents, limit))
        except Exception:  # noqa: BLE001
            return []

    async def _incidents(self, names: list[str]) -> list[dict]:
        inc = getattr(self.e, "incidents", None)
        if not inc:
            return []
        out: dict[str, dict] = {}
        for n in [x for x in dict.fromkeys(names) if x and len(x) >= 3][:10]:
            try:
                for r in await inc.list(None, n, days=14, limit=10):
                    out.setdefault(r["id"], r)
            except Exception:  # noqa: BLE001
                break
        order = {"open": 0, "acknowledged": 1, "investigating": 2}
        return sorted(out.values(), key=lambda r: (order.get(r.get("status"), 3), -(r.get("updated") or 0)))[:15]
