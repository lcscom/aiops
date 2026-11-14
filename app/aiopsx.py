"""AIOps 엔진(2.45.0) — '이상징후 탐지' 다음 단계: 원인·변경·전조·학습. 모두 읽기 전용.

1) 토폴로지 근본 원인(RCA)
   의존 그래프(원인 → 결과): 방화벽·라우터 → 스위치 → ESXi(물리 결선) · 스토리지 장비 → 데이터스토어 → VM · ESXi → VM · VM(노드) → VKS 클러스터 ·
   vCenter → 클러스터 → 호스트. 인시던트의 증상(이상징후가 난 개체)마다 위쪽 조상을 모아 후보로 두고
     점수 = 0.45 × 설명력(후보 아래에 있는 증상 비율) + 0.25 × 자기 증상(후보 자체에 이상징후) + 0.15 × 가장 먼저(증상 중 처음 2분 안)
            + 0.15 × 직전 변경(창 안에 후보에 대한 구성 변경) − 0.05 × log10(1 + 후보 아래 전체 개체 수)   ← 너무 넓은 후보(vCenter 등) 벌점
   상위 3개와 경로(예: dc1-leaf-01 → esx04 → VM 3대)를 근거로 보여 준다.
2) 변경 상관
   인시던트 시작 6시간 전부터: 구성 드리프트(호스트 설정)·VM 이동(vMotion·DRS·Storage vMotion·HA)·네트워크 장비 구성 변경·
   vCenter 재구성·업그레이드·유지보수 이벤트를 모아 '시간이 가깝고 + 증상과 그래프로 이어진' 순으로.
3) 전조 패턴 학습
   최근 30일 인시던트(종류 = 분류)마다 시작 2~60분 전에 같은 범위(클러스터·호스트)에서 난 이상징후 패턴을 모아
     지지도(앞섰던 인시던트 수) ≥ 3(범위 모르는 패턴은 5) · 신뢰도(패턴 뒤 60분 안에 그 종류가 온 비율) ≥ 0.3 · 향상도(신뢰도 ÷ 아무 때나 60분 안에 그 종류가 올 확률) ≥ 3
   을 전조로 저장. 5분마다 최근 이상징후에 전조가 보이면 '조기 경보' 이상징후를 낸다(같은 전조·범위는 1시간에 1번).
4) 피드백 학습·소음 지표
   운영자가 이상징후에 '소음/유용'을 표시하면 패턴별 가중치(0.2~1.2, 베이지안 평활)를 학습해 탐지 점수에 곱한다 — 소음으로 배운 패턴은 덜 올라온다.
   지표: 이벤트 → 이상징후 → 인시던트 압축률, 소음률, MTTA·MTTR, 일별 추이.
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from typing import Any

from .detect import make_template, pattern_key

SCHEMA = ("CREATE TABLE IF NOT EXISTS aiops_feedback(anomaly_id TEXT PRIMARY KEY, pkey TEXT, verdict TEXT, user TEXT, ts REAL)",
          "CREATE TABLE IF NOT EXISTS aiops_precursors(id TEXT PRIMARY KEY, data TEXT, ts REAL)",
          "CREATE TABLE IF NOT EXISTS aiops_warn(key TEXT PRIMARY KEY, ts REAL)")
CHANGE_RX = re.compile(r"reconfigur|재구성|구성 변경|configuration (changed|updated)|config change|upgrade|업그레이드|patch|패치|firmware|펌웨어|"
                       r"maintenance mode|유지보수 모드|entered maintenance|exited maintenance|vib install|image.*appl|remediat|reboot|재부팅", re.I)


def _s(n: str) -> str:
    return str(n or "").split(".")[0].split("(")[0].strip().lower()


def pkey(ev: dict) -> str:
    """패턴 키 — 소스 + 템플릿(이름·숫자 가림)"""
    return pattern_key(ev.get("source", ""), ev.get("template") or make_template(str(ev.get("message") or "")), ev.get("host", ""), ev.get("entity", ""))


# ------------------------------------------------------------------ 1) 의존 그래프
def graph(world: dict) -> dict[str, Any]:
    kids: dict[str, set] = {}
    names: dict[str, set] = {}

    def edge(a, b):
        kids.setdefault(a, set()).add(b)
        kids.setdefault(b, set())

    def nm(node, *alias):
        for x in alias:
            if x:
                names.setdefault(_s(x), set()).add(node)
                names.setdefault(str(x).lower(), set()).add(node)
    for vc in world["vcenters"]:
        V, T = vc["name"], vc["topo"]
        vn = f"vcenter:{V}"
        nm(vn, V, vc.get("host"))
        for cn, c in (T.get("clusters") or {}).items():
            cl = f"cluster:{V}/{cn}"
            edge(vn, cl)
            nm(cl, cn)
            for h in c.get("hosts", []):
                edge(cl, f"host:{V}/{h}")
        for hn in T.get("hosts") or {}:
            nm(f"host:{V}/{hn}", hn)
            kids.setdefault(f"host:{V}/{hn}", set())
        for dn, d in (T.get("datastores") or {}).items():
            nm(f"ds:{V}/{dn}", dn)
            kids.setdefault(f"ds:{V}/{dn}", set())
        for n, v in (T.get("vms") or {}).items():
            node = f"vm:{V}/{n}"
            nm(node, n)
            if v.get("host"):
                edge(f"host:{V}/{v['host']}", node)
            for d in v.get("datastores") or []:
                edge(f"ds:{V}/{d}", node)
    for k in world.get("vks") or []:
        kn = f"vks:{k['cluster']}"
        nm(kn, k["cluster"], k.get("name"))
        for nd in k.get("nodes") or []:
            for vc in world["vcenters"]:
                if nd.get("name") in (vc["topo"].get("vms") or {}):
                    edge(f"vm:{vc['name']}/{nd['name']}", kn)
    ph = world.get("phys") or {}
    for sn, sw in (ph.get("switches") or {}).items():
        node = f"switch:{sn}"
        nm(node, sn)
        kids.setdefault(node, set())
    for dn, d in (ph.get("devices") or {}).items():
        node = f"device:{dn}"
        nm(node, dn)
        for sw in d.get("switches") or []:
            edge(node, f"switch:{sw}")
    for hn, h in (ph.get("hosts") or {}).items():
        for n in (h.get("nics") or {}).values():
            if n.get("switch"):
                edge(f"switch:{n['switch']}", f"host:{h.get('vcenter', '')}/{hn}")
    for an, a in (ph.get("storage") or {}).items():
        node = f"storage:{an}"
        nm(node, an)
        for d in a.get("datastores") or []:
            edge(node, f"ds:{d['vcenter']}/{d['name']}")
    return {"kids": {k: sorted(v) for k, v in kids.items()}, "names": {k: sorted(v) for k, v in names.items()}}


def parents(g: dict) -> dict[str, list]:
    p: dict[str, list] = {}
    for a, bs in g["kids"].items():
        for b in bs:
            p.setdefault(b, []).append(a)
    return p


def resolve(g: dict, ev: dict) -> list[str]:
    """이벤트 → 그래프 개체(entity 우선, 없으면 host). 'perf:vm-ready:vm:ops-jump-01' · 'dc1-leaf-01:Ethernet8' 처럼 ':' 로 이어진 것은 조각마다"""
    for raw in (ev.get("entity"), ev.get("host")):
        if not raw:
            continue
        raw = str(raw)
        parts = raw.split(":")
        for s in [raw] + parts[::-1]:
            if len(s) < 2:
                continue
            hit = g["names"].get(s.lower()) or g["names"].get(_s(s))
            if hit:
                return sorted(set(hit))
    return []


def descendants(g: dict, node: str, cap: int = 5000) -> set:
    seen, todo = set(), [node]
    while todo and len(seen) < cap:
        n = todo.pop()
        for k in g["kids"].get(n, ()):
            if k not in seen:
                seen.add(k)
                todo.append(k)
    return seen


def ancestors(par: dict, node: str) -> set:
    seen, todo = set(), [node]
    while todo:
        n = todo.pop()
        for p in par.get(n, ()):
            if p not in seen:
                seen.add(p)
                todo.append(p)
    return seen


def rca(g: dict, symptoms: list[dict], changes: list[dict] | None = None) -> list[dict]:
    """symptoms = [{node, ts, title}] → 후보 점수 상위"""
    if not symptoms:
        return []
    par = parents(g)
    first: dict[str, float] = {}
    for s in symptoms:
        first[s["node"]] = min(first.get(s["node"], s["ts"]), s["ts"])
    nodes = list(first)
    t0 = min(first.values())
    cand = set(nodes)
    for n in nodes:
        cand |= ancestors(par, n)
    changed = {c.get("node") for c in changes or [] if c.get("node")}
    out = []
    for c in cand:
        desc = descendants(g, c)
        cov = [n for n in nodes if n == c or n in desc]
        if not cov:
            continue
        own = c in first
        early = own and first[c] - t0 <= 120
        score = 0.45 * len(cov) / len(nodes) + 0.25 * own + 0.15 * early + 0.15 * (c in changed) - 0.05 * math.log10(1 + len(desc))
        path = []
        for n in cov[:3]:
            if n != c:
                chain, cur = [n], n
                while cur != c:
                    nxt = next((p for p in par.get(cur, []) if p == c or c in ancestors(par, p)), None)
                    if not nxt:
                        break
                    chain.append(nxt)
                    cur = nxt
                path.append(" → ".join(x.split(":", 1)[1].split("/")[-1] for x in reversed(chain)))
        out.append({"node": c, "kind": c.split(":")[0], "name": c.split(":", 1)[1].split("/")[-1], "score": round(score, 3), "covers": len(cov), "symptoms": len(nodes),
                    "own_symptom": own, "earliest": early, "changed": c in changed, "paths": path})
    out.sort(key=lambda x: (-x["score"], x["kind"] == "vcenter"))
    return out[:5]


# ------------------------------------------------------------------ 3) 전조 학습 — 순수 함수
def learn_precursors(incs: list[dict], anoms: list[dict], days: float, lead=(120, 3600), min_support=3, min_conf=0.3, min_lift=3.0) -> list[dict]:
    """incs = [{id, ts, kind, scope:set}], anoms = [{ts, pkey, scope:set, title}] → 전조 규칙"""
    ts = [i["ts"] for i in incs] + [a["ts"] for a in anoms]
    hours = max(1.0, min(days * 24, (max(ts) - min(ts)) / 3600 if ts else 0))   # 실제 데이터가 있는 기간으로 기준 확률 계산
    by_kind: dict[str, list] = {}
    for i in incs:
        by_kind.setdefault(i["kind"], []).append(i)
    occ: dict[str, list] = {}
    titles: dict[str, str] = {}
    for a in anoms:
        occ.setdefault(a["pkey"], []).append(a)
        titles.setdefault(a["pkey"], a.get("title", ""))
    rules = []
    for kind, lst in by_kind.items():
        p_kind = min(1.0, len(lst) * 1.0 / hours)                        # 아무 1시간에 이 종류가 시작할 확률(근사)
        for pk, aa in occ.items():
            pre = [i for i in lst if any(lead[0] <= i["ts"] - a["ts"] <= lead[1] and (not a["scope"] or not i["scope"] or a["scope"] & i["scope"]) for a in aa)]
            followed = sum(1 for a in aa if any(lead[0] <= i["ts"] - a["ts"] <= lead[1] and (not a["scope"] or not i["scope"] or a["scope"] & i["scope"]) for i in lst))
            sup = min(len(pre), followed)                                    # 앞선 인시던트 수와 뒤따른 패턴 발생 수 중 작은 쪽
            glob = not any(a["scope"] for a in aa)                           # 구성도에 없는 개체(범위 모름) — 어디서든 맞으니 더 많은 근거 요구
            if sup < min_support + (2 if glob else 0):
                continue
            conf = followed / len(aa)
            lift = conf / p_kind if p_kind else 0
            if conf >= min_conf and lift >= min_lift:
                leads = sorted(i["ts"] - max(a["ts"] for a in aa if a["ts"] <= i["ts"] - lead[0]) for i in pre)
                rules.append({"id": f"{kind}|{pk}"[:300], "kind": kind, "example": pre[-1].get("title", ""), "pkey": pk, "title": titles[pk], "support": sup, "occurrences": len(aa), "confidence": round(conf, 2),
                              "lift": round(lift, 1), "lead_min": round(leads[len(leads) // 2] / 60) if leads else None})
    return sorted(rules, key=lambda r: (-r["lift"] * r["confidence"], -r["support"]))[:200]


def learned_weight(useful: int, noise: int) -> float:
    """베이지안 평활 — 표시가 없으면 1.0, 소음만 쌓이면 0.2 까지, 유용이 많으면 1.2 까지"""
    if useful + noise == 0:
        return 1.0
    w = 1.0 - 0.8 * noise / (useful + noise + 1) + 0.2 * useful / (useful + noise + 3)
    return round(max(0.2, min(1.2, w)), 2)


# ------------------------------------------------------------------ 엔진
class AIOpsX:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = {"precursor_days": 30, "min_support": 3, "min_conf": 0.3, "min_lift": 3.0, **(cfg or {})}
        self._ready = False
        self.rules: list[dict] = []
        self.weights: dict[str, float] = {}
        self.state = {"learned": 0, "error": ""}

    async def ensure(self):
        if not self._ready:
            for q in SCHEMA:
                await self.e.store.x(q)
            r = await self.e.store.q1("SELECT data FROM aiops_precursors WHERE id='__rules__'")
            if r:
                try:
                    self.rules = json.loads(r["data"])
                except ValueError:
                    self.rules = []
            r = await self.e.store.q1("SELECT data FROM aiops_precursors WHERE id='__state__'")
            if r:
                try:
                    self.state.update(json.loads(r["data"]))
                except ValueError:
                    pass
            await self._load_weights()
            self._ready = True

    async def _load_weights(self):
        rows = await self.e.store.q("SELECT pkey, SUM(verdict='useful') u, SUM(verdict='noise') n FROM aiops_feedback GROUP BY pkey")
        self.weights = {r["pkey"]: learned_weight(int(r["u"] or 0), int(r["n"] or 0)) for r in rows}
        det = getattr(self.e, "detector", None)
        if det is not None:
            det.learned = {k: v for k, v in self.weights.items() if v != 1.0}

    def world(self) -> dict:
        from .checkbot import build_world
        return build_world(self.e)

    async def _anoms(self, since: float, until: float | None = None, ids: list[str] | None = None) -> list[dict]:
        if ids:
            q = "SELECT id, created, body FROM anomalies WHERE id IN (%s)" % ",".join("?" * len(ids[:500]))
            rows = await self.e.store.q(q, tuple(ids[:500]))
        else:
            rows = await self.e.store.q("SELECT id, created, body FROM anomalies WHERE created>=? AND created<=? ORDER BY created LIMIT 20000", (since, until or time.time()))
        out = []
        for r in rows:
            try:
                b = json.loads(r["body"])
            except (TypeError, ValueError):
                continue
            ev = b.get("event") or {}
            out.append({"id": r["id"], "ts": float(ev.get("ts") or r["created"]), "title": b.get("title", ""), "ev": ev, "category": b.get("category", ""),
                        "severity": b.get("severity", ""), "pkey": pkey(ev)})
        return out

    async def changes(self, g: dict, start: float, end: float, symptoms: list[str]) -> list[dict]:
        out = []
        dw = getattr(self.e, "driftwatch", None)
        if dw:
            for c in getattr(self.e, "connectors", []):
                if getattr(c, "type", "") == "vcenter":
                    try:
                        for r in await dw.history(c.name, days=max(1, int((time.time() - start) / 86400) + 1), limit=1000):
                            if start <= r["ts"] <= end:
                                out.append({"ts": r["ts"], "kind": "구성 드리프트", "what": f"{r['entity']} {r.get('label') or r['key']}: {str(r.get('before'))[:40]} → {str(r.get('after'))[:40]}",
                                            "node": (resolve(g, {"host": r["entity"]}) or [None])[0]})
                    except Exception:  # noqa: BLE001
                        pass
        try:
            rows = await self.e.store.q("SELECT ts, vcenter, vm, type, from_host, to_host, user FROM vm_moves WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT 500", (start, end))
            for r in rows:
                out.append({"ts": r["ts"], "kind": f"VM {r['type']}", "what": f"{r['vm']} {r['from_host'] or ''} → {r['to_host'] or ''}" + (f" ({r['user']})" if r["user"] else ""),
                            "node": (resolve(g, {"entity": r["vm"]}) or [None])[0]})
        except Exception:  # noqa: BLE001
            pass
        try:
            rows = await self.e.store.q("SELECT ts, source, host, entity, message, attrs FROM logs WHERE ts>=? AND ts<=? AND (attrs LIKE '%net_change%' OR source IN ('vcenter','nsx','sddc')) "
                                        "ORDER BY ts DESC LIMIT 5000", (start, end))
            for r in rows:
                msg = str(r["message"] or "")
                if "net_change" in str(r["attrs"] or "") and "config" in str(r["attrs"] or "") or CHANGE_RX.search(msg):
                    out.append({"ts": r["ts"], "kind": "네트워크 장비 구성" if "net_change" in str(r["attrs"] or "") else f"{r['source']} 이벤트", "what": msg[:160],
                                "node": (resolve(g, {"entity": r["entity"], "host": r["host"]}) or [None])[0]})
        except Exception:  # noqa: BLE001
            pass
        par = parents(g)
        sym = set(symptoms)
        related = set(sym)
        for s in sym:
            related |= ancestors(par, s)
        for c in out:
            n = c.get("node")
            if not n:
                c["related"] = False
            elif n.startswith("vcenter:"):                                   # vCenter 전체 수준 변경은 vCenter 자체가 증상일 때만
                c["related"] = n in sym
            else:
                c["related"] = n in related or bool(descendants(g, n) & sym)
            c["minutes_before"] = round((end - c["ts"]) / 60)
            c["rank"] = (1 if c["related"] else 0) * 2 + max(0.0, 1 - (end - c["ts"]) / (6 * 3600))
        out.sort(key=lambda c: -c["rank"])
        ded: dict[tuple, dict] = {}
        for c in out:                                                       # 같은 변경 문구는 한 줄로(횟수)
            k = (c["kind"], c["what"])
            if k in ded:
                ded[k]["count"] += 1
            else:
                ded[k] = c | {"count": 1}
        return list(ded.values())[:40]

    async def analyze(self, incident_id: str, ai: bool = False) -> dict[str, Any]:
        await self.ensure()
        inc = await self.e.store.q1("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            raise KeyError(incident_id)
        try:
            ids = json.loads(inc["anomaly_ids"] or "[]")
        except ValueError:
            ids = []
        A = await self._anoms(0, None, ids) if ids else []
        world = await asyncio.to_thread(self.world)
        g = graph(world)
        sym, unres = [], []
        for a in A:
            nodes = resolve(g, a["ev"])
            if not nodes:
                unres.append(a["ev"].get("entity") or a["ev"].get("host") or "")
            for n in nodes:
                sym.append({"node": n, "ts": a["ts"], "title": a["title"]})
        t0 = min([a["ts"] for a in A] or [inc["created"]])
        ch = await self.changes(g, t0 - 6 * 3600, t0, [s["node"] for s in sym])
        cands = rca(g, sym, [c for c in ch if c["related"]])
        weak = bool(cands) and cands[0]["covers"] / max(1, cands[0]["symptoms"]) < 0.5 and cands[0]["symptoms"] >= 3
        res = {"weak": weak, "incident": {k: inc[k] for k in ("id", "title", "severity", "status", "created", "cluster")}, "symptoms": len({s["node"] for s in sym}), "anomalies": len(A),
               "unresolved": sorted({u for u in unres if u})[:20], "roots": cands, "changes": ch[:20],
               "timeline": sorted([{"ts": a["ts"], "title": a["title"], "entity": a["ev"].get("entity") or a["ev"].get("host") or "", "severity": a["severity"]} for a in A],
                                  key=lambda x: x["ts"])[:60]}
        if ai:
            res["ai"] = await self._ai_rca(res, world)
        return res

    async def _ai_rca(self, res: dict, world: dict) -> dict:
        llm = getattr(self.e, "llm", None)
        try:
            ok = bool(llm and llm.order("report"))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            return {"error": "AI 공급자가 설정되지 않았습니다"}
        names = [vc["name"] for vc in world["vcenters"]] + [r["name"] for r in res["roots"]]
        sys_ = ("너는 VMware VCF SRE 다. 토폴로지 근본 원인 후보·직전 변경·증상 타임라인(JSON)만 근거로 한국어로 쓴다. 형식: **가장 그럴듯한 원인** 1~2줄(후보 이름·점수 근거), "
                "**그렇게 보는 이유** 번호 2~4개(설명력·먼저 발생·직전 변경), **확인할 것** 번호 3개(어디서 무엇을 보면 확정되는지). 없는 사실은 쓰지 않는다.")
        pay = {k: res[k] for k in ("incident", "roots", "symptoms")} | {"changes": [c for c in res["changes"] if c["related"]][:10], "timeline": res["timeline"][:30]}
        try:
            return {"text": await asyncio.wait_for(llm.complete(sys_, json.dumps(pay, ensure_ascii=False, default=str), max_tokens=900, task="report", names=names), 60)}
        except Exception as ex:  # noqa: BLE001
            return {"error": f"AI 설명 실패: {type(ex).__name__}"}

    # ---------------------------------------------------------------- 전조
    def _scope(self, g: dict, ev: dict) -> set:
        """범위 = 개체와 그 위쪽 클러스터·호스트 이름"""
        par = parents(g)
        out = set()
        for n in resolve(g, ev):
            out.add(n)
            out |= {a for a in ancestors(par, n) if a.startswith(("cluster:", "host:"))}
        return out

    async def learn(self) -> list[dict]:
        await self.ensure()
        days = float(self.cfg["precursor_days"])
        since = time.time() - days * 86400
        rows = await self.e.store.q("SELECT id, created, category, title, anomaly_ids, cluster FROM incidents WHERE created>=? AND severity IN ('critical','error','warning')", (since,))
        world = await asyncio.to_thread(self.world)
        g = graph(world)
        inc_ids, incs = set(), []
        for r in rows:
            try:
                aids = json.loads(r["anomaly_ids"] or "[]")
            except ValueError:
                aids = []
            inc_ids |= set(aids)
            A = await self._anoms(0, None, aids[:30]) if aids else []
            sc = set()
            for a in A:
                sc |= self._scope(g, a["ev"])
            kind = (r["category"] or "") or re.sub(r"\s+\S+$", "", str(r["title"] or ""))[:40]
            incs.append({"id": r["id"], "title": str(r["title"] or "")[:120], "ts": min([a["ts"] for a in A] or [r["created"]]), "kind": kind, "scope": sc})
        anoms = []
        for a in await self._anoms(since - 3600):
            if a["ev"].get("connector") == "precursor":
                continue
            anoms.append({"ts": a["ts"], "pkey": a["pkey"], "scope": self._scope(g, a["ev"]), "title": a["title"]})
        self.state.update(learned=time.time(), incidents=len(incs), anomalies=len(anoms))
        self.rules = learn_precursors(incs, anoms, days, min_support=int(self.cfg["min_support"]), min_conf=float(self.cfg["min_conf"]), min_lift=float(self.cfg["min_lift"]))
        await self.e.store.x("INSERT OR REPLACE INTO aiops_precursors(id, data, ts) VALUES('__rules__', ?, ?)", (json.dumps(self.rules, ensure_ascii=False), time.time()))
        await self.e.store.x("INSERT OR REPLACE INTO aiops_precursors(id, data, ts) VALUES('__state__', ?, ?)", (json.dumps(self.state, ensure_ascii=False), time.time()))
        return self.rules

    async def watch(self, now: float | None = None) -> list[dict]:
        """최근 10분 이상징후에 전조가 보이면 조기 경보(같은 전조·범위 1시간 1번)"""
        await self.ensure()
        now = now or time.time()
        if not self.rules:
            return []
        by = {}
        for r in self.rules:
            by.setdefault(r["pkey"], []).append(r)
        fired = []
        recent = await self._anoms(now - 600, now)
        world = None
        for a in recent:
            for r in by.get(a["pkey"], []):
                if world is None:
                    world = await asyncio.to_thread(self.world)
                    g = graph(world)
                ents = resolve(g, a["ev"])
                key = f"{r['id']}|{','.join(ents) or a['ev'].get('host', '')}"[:300]
                hit = await self.e.store.q1("SELECT ts FROM aiops_warn WHERE key=?", (key,))
                if hit and now - hit["ts"] < 3600:
                    continue
                await self.e.store.x("INSERT OR REPLACE INTO aiops_warn(key, ts) VALUES(?,?)", (key, now))
                w = {"rule": r, "entity": a["ev"].get("entity") or a["ev"].get("host") or "", "anomaly": a["id"], "ts": now}
                fired.append(w)
                ingest = getattr(self.e, "ingest", None)
                if ingest:
                    from .models import LogEvent
                    ev = LogEvent(source="aiops", connector="precursor", severity="warning", kind="health", host=a["ev"].get("host", ""),
                                  entity=str(w["entity"])[:120],
                                  message=f"조기 경보: '{a['title'][:80]}' 뒤 약 {r['lead_min'] or '?'}분 안에 '{r['kind']}' 인시던트가 온 적이 많습니다 "
                                          f"(신뢰도 {int(r['confidence'] * 100)}%, 평소의 {r['lift']}배, 과거 {r['support']}번)",
                                  attrs={"app": "precursor", "rule": r["id"], "no_anomaly": 0})
                    x = ingest(ev)
                    if asyncio.iscoroutine(x):
                        await x
        return fired

    # ---------------------------------------------------------------- 피드백·지표
    async def feedback(self, anomaly_id: str, verdict: str, user: str = "") -> dict:
        await self.ensure()
        if verdict not in ("noise", "useful", "clear"):
            raise ValueError("verdict 는 noise·useful·clear")
        A = await self._anoms(0, None, [anomaly_id])
        if not A:
            raise KeyError(anomaly_id)
        if verdict == "clear":
            await self.e.store.x("DELETE FROM aiops_feedback WHERE anomaly_id=?", (anomaly_id,))
        else:
            await self.e.store.x("INSERT OR REPLACE INTO aiops_feedback(anomaly_id, pkey, verdict, user, ts) VALUES(?,?,?,?,?)", (anomaly_id, A[0]["pkey"], verdict, user, time.time()))
        await self._load_weights()
        return {"pkey": A[0]["pkey"], "weight": self.weights.get(A[0]["pkey"], 1.0)}

    async def triage(self, n: int = 30) -> list[dict]:
        """최근 3일 이상징후 중 아직 표시하지 않은 것 — 점수 높은 순"""
        await self.ensure()
        rows = await self.e.store.q("SELECT a.id, a.created, a.body, f.verdict FROM anomalies a LEFT JOIN aiops_feedback f ON f.anomaly_id=a.id WHERE a.created>=? ORDER BY a.created DESC LIMIT 2000",
                                    (time.time() - 3 * 86400,))
        out, seen = [], set()
        for r in rows:
            try:
                b = json.loads(r["body"])
            except (TypeError, ValueError):
                continue
            pk = pkey(b.get("event") or {})
            if pk in seen:
                continue
            seen.add(pk)
            out.append({"id": r["id"], "ts": r["created"], "title": b.get("title", ""), "severity": b.get("severity", ""), "score": b.get("score"), "count": b.get("count", 1),
                        "source": (b.get("event") or {}).get("source", ""), "entity": (b.get("event") or {}).get("entity") or (b.get("event") or {}).get("host") or "",
                        "verdict": r["verdict"], "weight": self.weights.get(pk, 1.0), "pkey": pk})
        out.sort(key=lambda x: (x["verdict"] is not None, -(x["score"] or 0)))
        return out[:n]

    async def kpis(self, days: int = 14) -> dict[str, Any]:
        await self.ensure()
        since = time.time() - days * 86400
        q1 = self.e.store.q1
        ev = (await q1("SELECT COUNT(*) n FROM logs WHERE ts>=?", (since,)) or {"n": 0})["n"]
        an = (await q1("SELECT COUNT(*) n FROM anomalies WHERE created>=?", (since,)) or {"n": 0})["n"]
        inc = await self.e.store.q("SELECT created, acknowledged_at, resolved_at, status, resolution FROM incidents WHERE created>=?", (since,))
        fb = await self.e.store.q("SELECT verdict, COUNT(*) n FROM aiops_feedback WHERE ts>=? GROUP BY verdict", (since,))
        fbd = {r["verdict"]: r["n"] for r in fb}
        mtta = [r["acknowledged_at"] - r["created"] for r in inc if r["acknowledged_at"]]
        mttr = [r["resolved_at"] - r["created"] for r in inc if r["resolved_at"]]
        auto_fp = sum(1 for r in inc if "오탐" in str(r["resolution"] or ""))
        med = lambda xs: round(sorted(xs)[len(xs) // 2] / 60, 1) if xs else None  # noqa: E731
        daily = await self.e.store.q("SELECT CAST(created/86400 AS INT) d, COUNT(*) n FROM anomalies WHERE created>=? GROUP BY d ORDER BY d", (since,))
        dinc = {r["d"]: r["n"] for r in await self.e.store.q("SELECT CAST(created/86400 AS INT) d, COUNT(*) n FROM incidents WHERE created>=? GROUP BY d", (since,))}
        return {"days": days, "events": ev, "anomalies": an, "incidents": len(inc), "event_to_anomaly": round(ev / an, 1) if an else None,
                "anomaly_to_incident": round(an / len(inc), 1) if inc else None, "noise_pct": round(fbd.get("noise", 0) / max(1, fbd.get("noise", 0) + fbd.get("useful", 0)) * 100, 1)
                if fbd else None, "feedback": fbd, "auto_closed_fp": auto_fp, "mtta_min": med(mtta), "mttr_min": med(mttr),
                "learned_patterns": sum(1 for v in self.weights.values() if v != 1.0), "precursors": len(self.rules),
                "daily": [{"day": r["d"] * 86400, "anomalies": r["n"], "incidents": dinc.get(r["d"], 0)} for r in daily]}

    async def loop(self, beat=lambda: None):
        await asyncio.sleep(240)
        last_learn = 0.0
        while True:
            beat()
            try:
                await self.ensure()
                if time.time() - last_learn > 6 * 3600:
                    await self.learn()
                    last_learn = time.time()
                await self.watch()
            except Exception as ex:  # noqa: BLE001
                self.state["error"] = f"{type(ex).__name__}: {ex}"[:200]
            await asyncio.sleep(300)
