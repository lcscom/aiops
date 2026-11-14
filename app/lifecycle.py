"""버전 수명·업그레이드 경로(2.36.0) — 지금 쓰는 구성요소 버전을 일반 지원 종료일(EoGS)과 맞대어 본다.

버전 수집(읽기 전용): vCenter(about) · ESXi(인프라 점검 스냅숏의 호스트 버전·빌드, 클러스터별 개수) · vSAN(ESXi 줄을 따름)
  NSX(/api/v1/node/version — 커넥터가 이미 읽음) · SDDC Manager(GET /v1/sddc-managers) · VCF Operations(GET /suite-api/api/versions/current)
  Avi · VKS(/version gitVersion → Kubernetes 마이너)
수명 표: app/assets/lifecycle.json(출처·확인 여부 포함) — 폐쇄망을 전제로 운영 설정에서 JSON 으로 바꿔 올린다(DB 에 저장, 기본 표로 되돌리기 가능).
다음 버전: 같은 제품에서 지원 종료가 더 늦은 가장 가까운 줄(라인) — 버전 조합은 Interoperability Matrix 로 확인하라고 함께 표시.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import time
from pathlib import Path
from typing import Any

TABLE = Path(__file__).parent / "assets" / "lifecycle.json"
KV = "CREATE TABLE IF NOT EXISTS lifecycle_kv(k TEXT PRIMARY KEY, v TEXT)"


def _line_of(product: str, version: str, lines: list[str]) -> str | None:
    """'8.0.3' → '8', '5.2.1.0' → '5.2', '1.30.1+vmware.1' → '1.30' — 표에 있는 줄 중 가장 길게 맞는 것"""
    v = re.sub(r"^v", "", str(version or "").strip())
    best = None
    for ln in lines:
        if v == ln or v.startswith(ln + ".") or v.startswith(ln + "+") or v.startswith(ln + "-"):
            if best is None or len(ln) > len(best):
                best = ln
    return best


def validate(tab: Any) -> dict[str, Any]:
    if not isinstance(tab, dict) or not isinstance(tab.get("entries"), list) or not tab["entries"]:
        raise ValueError("entries 목록이 필요합니다")
    if len(tab["entries"]) > 2000:
        raise ValueError("항목은 2000개까지")
    out = []
    for i, e in enumerate(tab["entries"]):
        if not isinstance(e, dict) or not e.get("product") or not e.get("line") or not e.get("eogs"):
            raise ValueError(f"{i + 1}번째 항목: product·line·eogs 가 필요합니다")
        for k in ("ga", "eogs", "eotg"):
            if e.get(k):
                try:
                    dt.date.fromisoformat(str(e[k]))
                except ValueError:
                    raise ValueError(f"{i + 1}번째 항목 {k}: YYYY-MM-DD") from None
        out.append({k: (str(e[k])[:200] if k != "verified" else bool(e[k])) for k in ("product", "line", "ga", "eogs", "eotg", "src", "verified") if k in e})
    return {"schema": "vcf-aiops-lifecycle/1", "updated": str(tab.get("updated") or dt.date.today().isoformat())[:20], "note": str(tab.get("note") or "")[:500],
            "products": {str(k)[:30]: str(v)[:80] for k, v in (tab.get("products") or {}).items()} or json.loads(TABLE.read_text(encoding="utf-8"))["products"],
            "entries": out, "order": [str(x)[:80] for x in (tab.get("order") or [])][:20], "order_note": str(tab.get("order_note") or "")[:500]}


def evaluate(found: list[dict], tab: dict, today: dt.date | None = None) -> list[dict[str, Any]]:
    """found = [{"product","system","version","build","count","scope"}] → 행마다 줄·지원 종료·남은 일·다음 줄"""
    today = today or dt.date.today()
    by: dict[str, list[dict]] = {}
    for e in tab["entries"]:
        by.setdefault(e["product"], []).append(e)
    out = []
    for f in found:
        ents = by.get(f["product"], [])
        ln = _line_of(f["product"], f["version"], [e["line"] for e in ents])
        e = next((x for x in ents if x["line"] == ln), None) if ln else None
        row = {**f, "line": ln, "eogs": e.get("eogs") if e else None, "eotg": e.get("eotg") if e else None, "src": e.get("src") if e else "",
               "verified": e.get("verified") if e else None}
        if e:
            d = (dt.date.fromisoformat(e["eogs"]) - today).days
            row["days_left"] = d
            row["state"] = "ended" if d < 0 else "soon" if d < 365 else "ok"
            later = sorted((x for x in ents if x["eogs"] > e["eogs"] and x["eogs"] > today.isoformat()), key=lambda x: (x["eogs"], x["line"]))
            nxt = later[0] if later else None
            if nxt:
                row["next"] = {"line": nxt["line"], "eogs": nxt["eogs"], "verified": nxt.get("verified")}
                best = later[-1]
                if best["line"] != nxt["line"]:
                    row["latest"] = {"line": best["line"], "eogs": best["eogs"], "verified": best.get("verified")}
        else:
            row["state"] = "unknown"
        out.append(row)
    order = {"ended": 0, "soon": 1, "unknown": 2, "ok": 3}
    out.sort(key=lambda r: (order[r["state"]], r.get("days_left") if r.get("days_left") is not None else 99999, r["product"]))
    return out


class Lifecycle:
    def __init__(self, engine):
        self.e = engine

    async def table(self) -> dict[str, Any]:
        try:
            await self.e.store.x(KV)
            r = await self.e.store.q1("SELECT v FROM lifecycle_kv WHERE k='lifecycle.table'")
            if r:
                return {**json.loads(r["v"]), "custom": True}
        except Exception:  # noqa: BLE001
            pass
        return {**json.loads(TABLE.read_text(encoding="utf-8")), "custom": False}

    async def save_table(self, tab: Any) -> dict[str, Any]:
        t = validate(tab)
        await self.e.store.x(KV)
        await self.e.store.x("INSERT OR REPLACE INTO lifecycle_kv(k,v) VALUES('lifecycle.table',?)", (json.dumps(t, ensure_ascii=False),))
        return t

    async def reset_table(self) -> None:
        await self.e.store.x(KV)
        await self.e.store.x("DELETE FROM lifecycle_kv WHERE k='lifecycle.table'")

    async def collect(self) -> tuple[list[dict], list[str]]:
        found: list[dict] = []
        errs: list[str] = []
        for c in self.e.connectors:
            if not getattr(c, "enabled", True):
                continue
            demo = getattr(c, "demo_versions", None)
            if demo is not None:
                found += [dict(x) for x in demo]
                continue
            t = getattr(c, "type", "")
            try:
                if t == "vcenter":
                    ab = getattr(c, "about", {}) or {}
                    if ab.get("version"):
                        found.append({"product": "vcenter", "system": c.name, "version": ab["version"], "build": ab.get("build", ""), "count": 1, "scope": c.host})
                    snap = getattr(c, "health_snap", None) or {}
                    hosts = snap.get("hosts") or {}
                    if not hosts:                                # 점검 전이면 토폴로지 이름만 — 버전 없음
                        errs.append(f"{c.name}: 인프라 점검 전이라 ESXi 버전을 아직 모릅니다")
                    grp: dict[tuple, list[str]] = {}
                    for hn, h in hosts.items():
                        if h.get("version"):
                            grp.setdefault((h.get("cluster", ""), h["version"], h.get("build", "")), []).append(hn)
                    for (cl, v, b), hs in sorted(grp.items()):
                        found.append({"product": "esxi", "system": c.name, "version": v, "build": b, "count": len(hs), "scope": cl or "(클러스터 없음)", "hosts": hs[:50]})
                        if (snap.get("clusters") or {}).get(cl, {}).get("vsan"):
                            found.append({"product": "vsan", "system": c.name, "version": v, "build": b, "count": len(hs), "scope": cl})
                elif t == "nsx" and getattr(c, "version", ""):
                    found.append({"product": "nsx", "system": c.name, "version": c.version, "build": "", "count": 1, "scope": c.host})
                elif t == "sddc":
                    r = await c.http.get("/v1/sddc-managers")
                    if r.status_code < 300:
                        for x in (r.json() or {}).get("elements") or []:
                            found.append({"product": "vcf", "system": c.name, "version": str(x.get("version", "")).split("-")[0], "build": str(x.get("version", "")),
                                          "count": 1, "scope": x.get("fqdn") or c.host})
                    else:
                        errs.append(f"{c.name}: SDDC Manager 버전 조회 HTTP {r.status_code}")
                elif t == "vcfops":
                    r = await c.http.get("/suite-api/api/versions/current")
                    if r.status_code < 300:
                        j = r.json() or {}
                        v = str(j.get("releaseName") or j.get("humanlyReadableReleaseName") or "")
                        m = re.search(r"(\d+\.\d+(?:\.\d+)*)", v)
                        if m:
                            found.append({"product": "aria" if m.group(1).startswith("8.") else "vcf", "system": c.name, "version": m.group(1),
                                          "build": str(j.get("buildNumber", "")), "count": 1, "scope": "VCF Operations"})
                elif t == "avi" and getattr(c, "version", ""):
                    found.append({"product": "avi", "system": c.name, "version": c.version, "build": "", "count": 1, "scope": c.host})
                elif t == "vks":
                    v = str(((getattr(c, "_state", {}) or {}).get("checks") or {}).get("version", "")).removeprefix("ok ").strip()
                    if v:
                        found.append({"product": "k8s", "system": c.name, "version": v.lstrip("v"), "build": v, "count": 1,
                                      "scope": getattr(c, "cluster_label", c.name) + (" (Supervisor)" if getattr(c, "role", "") == "supervisor" else "")})
            except Exception as ex:  # noqa: BLE001
                errs.append(f"{c.name}: {type(ex).__name__}")
        return found, errs

    async def report(self) -> dict[str, Any]:
        tab = await self.table()
        found, errs = await self.collect()
        rows = evaluate(found, tab)
        return {"generated": time.time(), "rows": rows, "errors": errs[:50], "table": {k: tab.get(k) for k in ("updated", "note", "custom", "order", "order_note", "products")},
                "entries": tab["entries"], "summary": {s: sum(1 for r in rows if r["state"] == s) for s in ("ended", "soon", "ok", "unknown")}}
