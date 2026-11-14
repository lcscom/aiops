"""구성 드리프트(2.36.0) — 저장한 기준선과 지금 구성의 차이, 그리고 같은 클러스터 안 호스트끼리의 차이.

재료: vCenter 커넥터의 인프라 점검 스냅숏(health_snap, 읽기 전용 PropertyCollector)
  호스트    ESXi 버전·빌드 · BIOS · NTP 서버·ntpd · SSH(TSM-SSH)·ESXi Shell · 잠금 모드 · 하이퍼스레딩 · 전원 정책
            물리 NIC(드라이버·드라이버 버전·펌웨어·링크 속도) · vSwitch MTU · VMkernel(MTU·서비스·스위치) · HBA(드라이버 버전·펌웨어)
  클러스터  HA(사용·승인 제어·정책·장애 수·CPU/메모리 예약 %·호스트/VM 감시·격리 응답) · DRS(사용·자동화·이동 임계) · EVC · vSAN(ESA)
보안 판독의 '구성 변경'(직전 점검 대비, 보안 항목 중심)과 달리, 여기서는 사람이 고른 기준선(골든 상태)과 비교하고
기준선 이후 바뀐 것을 계속 보여 준다(되돌리기 전까지 사라지지 않음).
"""
from __future__ import annotations

import inspect
import json
import time
from typing import Any

SCHEMA = """CREATE TABLE IF NOT EXISTS drift_baselines(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, vcenter TEXT NOT NULL, created REAL, by TEXT, data TEXT NOT NULL)"""
HOST_SEV = {"version": "info", "build": "info", "bios": "info", "lockdown": "warning", "ssh": "warning", "shell": "warning", "ntp": "warning", "ntpd": "warning",
            "ht": "warning", "power_policy": "info"}
CL_KEYS = ("ha", "ha_admission", "ha_policy", "ha_failover_level", "ha_cpu_pct", "ha_mem_pct", "ha_host_monitoring", "ha_vm_monitoring", "ha_isolation",
           "drs", "drs_behavior", "drs_rate", "evc", "vsan", "vsan_esa")
LABEL = {"version": "ESXi 버전", "build": "ESXi 빌드", "bios": "BIOS", "lockdown": "잠금 모드", "ssh": "SSH 실행", "shell": "ESXi Shell 실행", "ntp": "NTP 서버",
         "ntpd": "ntpd 실행", "ht": "하이퍼스레딩", "power_policy": "전원 정책", "ha": "HA", "ha_admission": "HA 승인 제어", "ha_policy": "HA 승인 정책",
         "ha_failover_level": "HA 장애 허용 호스트", "ha_cpu_pct": "HA CPU 예약 %", "ha_mem_pct": "HA 메모리 예약 %", "ha_host_monitoring": "HA 호스트 감시",
         "ha_vm_monitoring": "HA VM 감시", "ha_isolation": "HA 격리 응답", "drs": "DRS", "drs_behavior": "DRS 자동화", "drs_rate": "DRS 이동 임계값",
         "evc": "EVC 모드", "vsan": "vSAN", "vsan_esa": "vSAN ESA"}
# 같은 클러스터 호스트끼리 비교할 때 빼는 키(호스트마다 다른 게 정상)
PEER_SKIP = ("bios",)


def normalize(snap: dict[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    """health_snap → {"hosts": {호스트: {키: 값}}, "clusters": {클러스터: {키: 값}}} — 값은 비교용 문자열"""
    H: dict[str, dict[str, str]] = {}
    for n, h in (snap.get("hosts") or {}).items():
        if h.get("conn") and h.get("conn") != "connected":
            continue
        sv = h.get("services") or {}
        d = {"version": str(h.get("version", "")), "build": str(h.get("build", "")), "bios": str(h.get("bios", "")),
             "lockdown": str(h.get("lockdown", "")), "ssh": str(bool(sv.get("TSM-SSH"))), "shell": str(bool(sv.get("TSM"))),
             "ntp": ", ".join(sorted(h.get("ntp_servers") or [])), "ntpd": str(bool(sv.get("ntpd"))), "ht": str(h.get("ht_active")),
             "power_policy": str(h.get("power_policy", ""))}
        for x in h.get("nics") or []:
            dv = x.get("device", "")
            d[f"nic:{dv}:driver"] = f"{x.get('driver', '')} {x.get('driver_version', '')}".strip()
            if x.get("firmware"):
                d[f"nic:{dv}:firmware"] = str(x["firmware"])
            if x.get("speed"):
                d[f"nic:{dv}:speed"] = f"{x['speed']} Mb"
        for x in h.get("vswitches") or []:
            d[f"vswitch:{x.get('name', '')}:mtu"] = str(x.get("mtu", ""))
        for x in h.get("vmks") or []:
            dv = x.get("device", "")
            d[f"vmk:{dv}:mtu"] = str(x.get("mtu", ""))
            d[f"vmk:{dv}:services"] = ", ".join(sorted(x.get("services") or []))
            d[f"vmk:{dv}:switch"] = str(x.get("switch", ""))
        for x in h.get("hbas") or []:
            dv = x.get("device", "")
            d[f"hba:{dv}:driver"] = f"{x.get('driver', '')} {x.get('driver_version', '')}".strip()
            if x.get("firmware"):
                d[f"hba:{dv}:firmware"] = str(x["firmware"])
        d["_cluster"] = str(h.get("cluster", ""))
        H[n] = d
    C = {n: {k: str(c.get(k, "")) for k in CL_KEYS} for n, c in (snap.get("clusters") or {}).items()}
    return {"hosts": H, "clusters": C}


def _label(k: str) -> str:
    if k in LABEL:
        return LABEL[k]
    p = k.split(":")
    if len(p) == 3:
        kind = {"nic": "NIC", "vswitch": "vSwitch", "vmk": "VMkernel", "hba": "HBA"}.get(p[0], p[0])
        what = {"driver": "드라이버", "firmware": "펌웨어", "speed": "링크 속도", "mtu": "MTU", "services": "서비스", "switch": "스위치"}.get(p[2], p[2])
        return f"{kind} {p[1]} {what}"
    return k


def _sev(k: str) -> str:
    if k in HOST_SEV:
        return HOST_SEV[k]
    if k.startswith(("ha", "drs", "evc", "vsan")):
        return "warning"
    if k.endswith((":mtu", ":speed", ":services")):
        return "warning"
    return "info"


def diff(base: dict, cur: dict) -> list[dict[str, Any]]:
    """기준선 ↔ 지금 — 추가·제거된 호스트·클러스터와 값이 바뀐 키"""
    out: list[dict] = []
    for scope in ("hosts", "clusters"):
        a, b = base.get(scope) or {}, cur.get(scope) or {}
        kind = "호스트" if scope == "hosts" else "클러스터"
        for n in sorted(set(a) - set(b)):
            out.append({"scope": kind, "entity": n, "key": "inventory", "label": "인벤토리", "baseline": "있음", "current": "없음", "severity": "warning",
                        "cluster": a[n].get("_cluster", "") if scope == "hosts" else n})
        for n in sorted(set(b) - set(a)):
            out.append({"scope": kind, "entity": n, "key": "inventory", "label": "인벤토리", "baseline": "없음", "current": "추가됨", "severity": "info",
                        "cluster": b[n].get("_cluster", "") if scope == "hosts" else n})
        for n in sorted(set(a) & set(b)):
            for k in sorted((set(a[n]) | set(b[n])) - {"_cluster"}):
                va, vb = a[n].get(k), b[n].get(k)
                if va != vb:
                    out.append({"scope": kind, "entity": n, "key": k, "label": _label(k), "baseline": "(없음)" if va is None else va,
                                "current": "(없음)" if vb is None else vb, "severity": _sev(k), "cluster": b[n].get("_cluster", "") if scope == "hosts" else n})
    out.sort(key=lambda x: (x["severity"] != "warning", x["cluster"], x["entity"], x["key"]))
    return out[:5000]


def peers(cur: dict) -> list[dict[str, Any]]:
    """같은 클러스터 안에서 다수(최빈값)와 다른 호스트 설정 — 기준선 없이도 바로 보이는 드리프트"""
    by: dict[str, list[str]] = {}
    for n, d in (cur.get("hosts") or {}).items():
        by.setdefault(d.get("_cluster", ""), []).append(n)
    out = []
    for cl, names in by.items():
        if len(names) < 2:
            continue
        keys = set().union(*[set(cur["hosts"][n]) for n in names]) - {"_cluster"} - set(PEER_SKIP)
        for k in sorted(keys):
            vals = {n: cur["hosts"][n].get(k) for n in names}
            have = [v for v in vals.values() if v is not None]
            if len(set(have)) < 2:
                continue
            cnt: dict[str, int] = {}
            for v in have:
                cnt[v] = cnt.get(v, 0) + 1
            major, mc = max(cnt.items(), key=lambda kv: kv[1])
            if mc == len(have) - mc and len(cnt) == 2:       # 반반이면 다수가 없다 — 한 줄로
                out.append({"cluster": cl, "key": k, "label": _label(k), "majority": "(반반)", "hosts": sorted(n for n, v in vals.items() if v is not None),
                            "values": {n: v for n, v in vals.items() if v is not None}, "severity": _sev(k)})
                continue
            odd = {n: v for n, v in vals.items() if v is not None and v != major}
            out.append({"cluster": cl, "key": k, "label": _label(k), "majority": major, "majority_n": mc, "hosts": sorted(odd), "values": odd, "severity": _sev(k)})
    out.sort(key=lambda x: (x["severity"] != "warning", x["cluster"], x["key"]))
    return out[:3000]


class DriftStore:
    def __init__(self, store):
        self.store = store
        self._ready = False

    async def ensure(self) -> None:
        if not self._ready:
            await self.store.x(SCHEMA)
            self._ready = True

    async def list(self) -> list[dict]:
        await self.ensure()
        rows = await self.store.q("SELECT id,name,vcenter,created,by,length(data) AS size FROM drift_baselines ORDER BY id DESC LIMIT 200")
        return [dict(r) for r in rows]

    async def get(self, bid: int) -> dict | None:
        await self.ensure()
        r = await self.store.q1("SELECT id,name,vcenter,created,by,data FROM drift_baselines WHERE id=?", (bid,))
        if not r:
            return None
        return {**{k: r[k] for k in ("id", "name", "vcenter", "created", "by")}, "data": json.loads(r["data"])}

    async def latest_for(self, vcenter: str) -> dict | None:
        await self.ensure()
        r = await self.store.q1("SELECT id FROM drift_baselines WHERE vcenter=? ORDER BY id DESC LIMIT 1", (vcenter,))
        return await self.get(r["id"]) if r else None

    async def add(self, name: str, vcenter: str, data: dict, by: str) -> dict:
        await self.ensure()
        name = " ".join(str(name or "").split())[:80] or time.strftime("기준선 %Y-%m-%d %H:%M")
        if ((await self.store.q1("SELECT COUNT(*) AS n FROM drift_baselines WHERE vcenter=?", (vcenter,))) or {}).get("n", 0) >= 50:
            raise ValueError("vCenter 당 기준선은 50개까지 — 오래된 것을 지우세요")
        await self.store.x("INSERT INTO drift_baselines(name,vcenter,created,by,data) VALUES(?,?,?,?,?)",
                           (name, vcenter, time.time(), by, json.dumps(data, ensure_ascii=False)))
        r = await self.store.q1("SELECT MAX(id) AS m FROM drift_baselines")
        return {"id": r["m"], "name": name, "vcenter": vcenter}

    async def remove(self, bid: int) -> bool:
        await self.ensure()
        if not await self.store.q1("SELECT id FROM drift_baselines WHERE id=?", (bid,)):
            return False
        await self.store.x("DELETE FROM drift_baselines WHERE id=?", (bid,))
        return True


# ------------------------------------------------------------------ 2.37.0 변경 이력 — 인프라 점검이 돌 때마다 직전 스냅숏과 비교해 '언제 무엇이 바뀌었나'를 남긴다
HIST_SCHEMA = ("""CREATE TABLE IF NOT EXISTS drift_snaps(vcenter TEXT PRIMARY KEY, ts REAL, data TEXT NOT NULL)""",
               """CREATE TABLE IF NOT EXISTS drift_changes(id INTEGER PRIMARY KEY AUTOINCREMENT, vcenter TEXT, ts REAL, scope TEXT, entity TEXT, cluster TEXT,
                  key TEXT, label TEXT, before TEXT, after TEXT, severity TEXT)""",
               "CREATE INDEX IF NOT EXISTS drift_changes_ts ON drift_changes(vcenter, ts)")


ASSESS_KEYS = {"ntp", "lockdown", "ssh", "shell", "version", "build", "inventory"}


class DriftWatch:
    """vCenter 마다 마지막으로 본 구성(정규화)을 두고, 새 점검 스냅숏이 오면 차이를 변경 이력으로 저장·알림(warning 은 이상징후).
    보관: 이력 180일, 한 번에 500건까지(대량 변경은 요약 한 줄)"""

    def __init__(self, engine, keep_days: int = 180):
        self.e = engine
        self.keep = keep_days
        self._ready = False
        self._seen_upd: dict[str, float] = {}
        self.state: dict[str, Any] = {"last": 0, "changes": 0, "error": ""}

    async def ensure(self) -> None:
        if not self._ready:
            for q in HIST_SCHEMA:
                await self.e.store.x(q)
            self._ready = True

    async def observe(self, vcenter: str, cur: dict, ts: float | None = None) -> list[dict]:
        await self.ensure()
        ts = ts or time.time()
        r = await self.e.store.q1("SELECT data FROM drift_snaps WHERE vcenter=?", (vcenter,))
        await self.e.store.x("INSERT OR REPLACE INTO drift_snaps(vcenter, ts, data) VALUES(?,?,?)", (vcenter, ts, json.dumps(cur, ensure_ascii=False)))
        if not r:
            return []                                        # 처음 본 vCenter — 비교 대상 없음
        ch = diff(json.loads(r["data"]), cur)
        if not ch:
            return []
        rows = ch[:500]
        if len(ch) > 500:
            rows.append({"scope": "요약", "entity": vcenter, "cluster": "", "key": "bulk", "label": "대량 변경", "baseline": "", "current": f"{len(ch)}건 중 500건만 기록",
                         "severity": "warning"})
        await self.e.store.xm("INSERT INTO drift_changes(vcenter, ts, scope, entity, cluster, key, label, before, after, severity) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              [(vcenter, ts, x["scope"], x["entity"], x.get("cluster", ""), x["key"], x["label"], str(x["baseline"])[:300], str(x["current"])[:300], x["severity"])
                               for x in rows])
        await self.e.store.x("DELETE FROM drift_changes WHERE ts < ?", (ts - self.keep * 86400,))
        await self._events(vcenter, rows)
        self.state["changes"] += len(rows)
        return rows

    async def _events(self, vcenter: str, rows: list[dict]) -> None:
        ingest = getattr(self.e, "ingest", None)
        if not ingest:
            return
        import asyncio

        from .models import LogEvent
        for x in [r for r in rows if r["key"] not in ASSESS_KEYS][:50]:    # 보안 판독이 이미 알리는 항목(NTP·잠금 모드·SSH·버전)은 기록만
            ev = LogEvent(source="vcenter", connector="drift", message=f"구성 변경 — {x['entity']} {x['label']}: {x['baseline'] or '(없음)'} → {x['current'] or '(없음)'}",
                          severity=x["severity"], host=x["entity"] if x["scope"] == "호스트" else "", entity=x["entity"], kind="config",
                          attrs={"app": "config-drift", "key": x["key"], "cluster": x.get("cluster", ""), "vcenter": vcenter, "no_anomaly": 0 if x["severity"] == "warning" else 1})
            ingest(ev) if not inspect.iscoroutinefunction(ingest) else await ingest(ev)

    async def history(self, vcenter: str, days: int = 30, entity: str = "", limit: int = 2000) -> list[dict]:
        await self.ensure()
        q, a = "SELECT ts, scope, entity, cluster, key, label, before, after, severity FROM drift_changes WHERE vcenter=? AND ts >= ?", [vcenter, time.time() - days * 86400]
        if entity:
            q += " AND entity=?"
            a.append(entity)
        return [dict(r) for r in await self.e.store.q(q + " ORDER BY ts DESC, id DESC LIMIT ?", (*a, limit))]

    async def tick(self) -> None:
        for c in self.e.connectors:
            if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
                continue
            snap = getattr(c, "health_snap", None) or {}
            upd = float((getattr(c, "health", None) or {}).get("updated") or 0)
            if not snap.get("hosts") or self._seen_upd.get(c.name) == upd:
                continue                                     # 점검이 새로 돌았을 때만
            self._seen_upd[c.name] = upd
            try:
                await self.observe(c.name, normalize(snap), upd or None)
            except Exception as e:  # noqa: BLE001
                self.state["error"] = f"{c.name}: {type(e).__name__}: {e}"[:200]
        self.state["last"] = time.time()

    async def loop(self, beat=lambda: None) -> None:
        import asyncio
        await asyncio.sleep(120)
        while True:
            beat()
            try:
                await self.tick()
            except Exception as e:  # noqa: BLE001
                self.state["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(300)
