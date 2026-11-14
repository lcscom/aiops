"""서버 사양(2.34.0) — 가정 분석에서 '이 서버를 더하면?'에 쓰는 사양 목록

사양을 얻는 길 세 가지(모두 읽기 전용):
  · vCenter 커넥터 — 이미 있는 ESXi 호스트의 사양(같은 사양끼리 묶어 유형으로)
  · BMC(Redfish) 스캔 — 하드웨어 준비도에서 스캔한 서버(아직 ESXi 를 올리지 않은 새 서버도 가능)
  · 수집 스크립트 — scripts/spec/collect-server-spec.sh(.ps1)를 서버에서 돌려 나온 JSON 을 올림(server_specs 테이블에 보관)
라이선스 코어: VCF·VVF 는 CPU(소켓)당 최소 16코어로 센다(Broadcom KB 313548).
"""
from __future__ import annotations

import json
import math
import re
import time
from typing import Any

SCHEMA = """CREATE TABLE IF NOT EXISTS server_specs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, spec TEXT NOT NULL, created REAL, by TEXT)"""
MIN_CORES_PER_CPU = 16
_GHZ = re.compile(r"@\s*([0-9]+(?:\.[0-9]+)?)\s*GHz", re.I)


def licensed_cores(sockets: int, cores: int) -> int:
    """소켓당 max(16, 소켓당 코어) — 소켓 수를 모르면 코어 수 그대로"""
    if sockets <= 0 or cores <= 0:
        return max(0, cores)
    return sockets * max(MIN_CORES_PER_CPU, math.ceil(cores / sockets))


def _f(v: Any, lo: float, hi: float) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0.0
    return x if lo <= x <= hi and not math.isnan(x) else 0.0


def normalize(raw: dict, source: str = "upload") -> dict[str, Any]:
    """스크립트 JSON·직접 입력 → 공통 사양. 코어·메모리가 없으면 ValueError"""
    if not isinstance(raw, dict):
        raise ValueError("JSON 객체가 필요합니다")
    sockets, cores = int(_f(raw.get("sockets"), 0, 64)), int(_f(raw.get("cores"), 0, 4096))
    mem = _f(raw.get("mem_gb"), 0, 65536)
    if cores <= 0 or mem <= 0:
        raise ValueError("코어 수(cores)와 메모리(mem_gb)가 필요합니다 — 수집 스크립트 출력인지 확인하세요")
    if sockets and cores < sockets:
        raise ValueError("코어 수가 소켓 수보다 적습니다")
    cpu_model = " ".join(str(raw.get("cpu_model") or "").split())[:120]
    ghz = _f(raw.get("core_ghz"), 0.5, 8)
    if not ghz:
        m = _GHZ.search(cpu_model)
        ghz = _f(m.group(1), 0.5, 8) if m else 0.0
    disks = []
    for d in (raw.get("disks") or [])[:128]:
        if isinstance(d, dict) and _f(d.get("gb"), 1, 1e6):
            t = str(d.get("type") or "").lower()
            disks.append({"gb": round(_f(d.get("gb"), 1, 1e6)), "type": t if t in ("nvme", "ssd", "hdd") else "hdd"})
    nics = [round(_f(n.get("gbps"), 0.1, 1000)) for n in (raw.get("nics") or [])[:64] if isinstance(n, dict) and _f(n.get("gbps"), 0.1, 1000)]
    flash = sum(d["gb"] for d in disks if d["type"] in ("nvme", "ssd"))
    return {"vendor": str(raw.get("vendor") or "")[:60], "model": str(raw.get("model") or "")[:80], "cpu_model": cpu_model, "sockets": sockets, "cores": cores,
            "threads": int(_f(raw.get("threads"), 0, 8192)), "core_ghz": round(ghz, 2), "mem_gb": round(mem), "disks": disks,
            "flash_tb": round(flash / 1000, 2), "nvme": sum(1 for d in disks if d["type"] == "nvme"), "nic_gbps": sorted(nics, reverse=True)[:8],
            "licensed_cores": licensed_cores(sockets, cores), "os": str(raw.get("os") or "")[:60], "source": source}


def label(s: dict) -> str:
    cpu = f"{s['sockets']}×{s['cores'] // s['sockets']}코어" if s.get("sockets") else f"{s['cores']}코어"
    return f"{cpu}{' ' + format(s['core_ghz'], 'g') + 'GHz' if s.get('core_ghz') else ''} · {s['mem_gb']}GB"


def from_vcenter(connectors) -> list[dict]:
    """기존 ESXi 호스트를 같은 사양끼리 묶은 유형"""
    groups: dict[tuple, dict] = {}
    for c in connectors:
        if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
            continue
        for hn, h in ((getattr(c, "topology", {}) or {}).get("hosts") or {}).items():
            core = float(h.get("core_mhz") or 0)
            if not core or not h.get("cpu_mhz"):
                continue
            cores = round(float(h["cpu_mhz"]) / core)
            mem = round(float(h.get("mem_mb") or 0) / 1024)
            k = (c.name, h.get("cluster") or "", cores, round(core / 100), mem, h.get("cpu_model") or "")
            g = groups.setdefault(k, {"n": 0, "example": hn, "h": h, "cores": cores, "mem": mem, "core": core})
            g["n"] += 1
    out = []
    for (vc, cl, *_), g in sorted(groups.items(), key=lambda x: (x[0][0], x[0][1], -x[1]["n"])):
        h = g["h"]
        s = normalize({"vendor": h.get("hw_vendor"), "model": h.get("hw_model"), "cpu_model": h.get("cpu_model"), "sockets": h.get("sockets") or 0, "cores": g["cores"],
                       "core_ghz": round(g["core"] / 1000, 2), "mem_gb": g["mem"]}, "vcenter")
        out.append({"id": f"vc:{vc}:{g['example']}", "name": f"{cl or '클러스터 없음'} 의 호스트 유형({g['n']}대, 예: {g['example']})", "vcenter": vc, "cluster": cl, "count": g["n"], "spec": s})
    return out


def from_readiness(hosts: list[dict]) -> list[dict]:
    """하드웨어 준비도(BMC Redfish) 스캔 결과 → 사양"""
    out = []
    for h in hosts or []:
        sm = h.get("summary") or {}
        cpu, mem, sto = sm.get("cpu") or {}, sm.get("memory") or {}, sm.get("storage") or {}
        try:
            s = normalize({"vendor": sm.get("vendor"), "model": sm.get("model"), "cpu_model": cpu.get("model"), "sockets": cpu.get("sockets"), "cores": cpu.get("cores"),
                           "threads": cpu.get("threads"), "mem_gb": mem.get("total_gib"),
                           "disks": [{"gb": round(float(sto.get("nvme_tb") or 0) * 1000 / max(1, int(sto.get("direct_nvme") or 1))), "type": "nvme"}] * int(sto.get("direct_nvme") or 0)}, "bmc")
        except (ValueError, TypeError):
            continue
        out.append({"id": f"bmc:{h.get('target')}", "name": f"BMC 스캔 {h.get('target')}" + (f" — {s['model']}" if s["model"] else ""), "ts": h.get("ts"), "spec": s})
    return out


class SpecStore:
    def __init__(self, store):
        self.store = store
        self._ready = False

    async def ensure(self) -> None:
        if not self._ready:
            await self.store.x(SCHEMA)
            self._ready = True

    async def list(self) -> list[dict]:
        await self.ensure()
        out = []
        for r in await self.store.q("SELECT id,name,spec,created,by FROM server_specs ORDER BY id DESC LIMIT 200"):
            try:
                out.append({"id": f"up:{r['id']}", "name": r["name"], "created": r["created"], "by": r["by"], "spec": json.loads(r["spec"])})
            except ValueError:
                continue
        return out

    async def add(self, name: str, raw: dict, by: str) -> dict:
        await self.ensure()
        s = normalize(raw, "script" if str(raw.get("schema") or "").startswith("vcf-aiops-server-spec/") else "manual")
        name = " ".join(str(name or "").split())[:80] or " ".join(x for x in (s["vendor"], s["model"]) if x) or label(s)
        n = await self.store.q1("SELECT COUNT(*) AS n FROM server_specs")
        if (n or {}).get("n", 0) >= 200:
            raise ValueError("저장한 사양은 200개까지 — 안 쓰는 것을 지우세요")
        await self.store.x("INSERT INTO server_specs(name,spec,created,by) VALUES(?,?,?,?)", (name, json.dumps(s, ensure_ascii=False), time.time(), by))
        r = await self.store.q1("SELECT MAX(id) AS m FROM server_specs")
        return {"id": f"up:{r['m']}", "name": name, "spec": s}

    async def remove(self, sid: int) -> bool:
        await self.ensure()
        if not await self.store.q1("SELECT id FROM server_specs WHERE id=?", (sid,)):
            return False
        await self.store.x("DELETE FROM server_specs WHERE id=?", (sid,))
        return True
