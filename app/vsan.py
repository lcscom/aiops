"""vSAN 관제 — vCenter·ESXi 로그 중 vSAN 관련만 골라 내고(별도 관제 도메인), vSAN 상태·비 vSAN 데이터스토어를 정리한다.

vSAN 로그 판별(메시지·앱·이벤트 유형):
  · 'vsan' 이 들어간 모든 것(vSAN 이벤트 com.vmware.vsan.*, esx.problem.vob.vsan.*, vsanmgmtd·vsanvpd·vsanperfsvc …)
  · vSAN 내부 구성요소 데몬·모듈: clomd(CLOM), cmmdsd/CMMDS, LSOM, DOM, PLOG, osfsd, epd, rdt
상태 재료(vCenter 커넥터 토폴로지, 읽기 전용):
  · 클러스터 configurationEx.vsanConfigInfo.enabled
  · 호스트 config.vsanHostConfig(디스크 그룹: 캐시·용량 디스크), runtime.vsanRuntimeInfo(diskIssues·멤버), vsanSystem.QueryHostStatus(노드 역할·health)
  · 데이터스토어 summary.type = vsan / VMFS(info.vmfs.local·extent) / NFS·NFS41(info.nas) / VVOL / PMEM
"""
from __future__ import annotations

import re
from typing import Any

VSAN_RX = re.compile(r"vsan|\bclomd?\b|\bcmmds|\blsom\b|\bdom:|\bdom\b(?=\s+(?:owner|client|comp|object))|\bplog\b|\bosfsd?\b|\bepd\b|\brdt\b", re.I)
VSAN_SQL = ("vsan", "clom", "cmmds", "lsom", "dom:", "plog", "osfs")   # 저장 로그 조회(LIKE) — 정규식의 근사
DS_KIND = {"vsan": "vSAN", "vmfs": "VMFS", "nfs": "NFS", "nfs41": "NFS 4.1", "vvol": "vVols", "pmem": "PMem", "cifs": "CIFS"}


def is_vsan_text(*parts: Any) -> bool:
    return any(p and VSAN_RX.search(str(p)) for p in parts)


def is_vsan_event(source: str, message: str, attrs: dict | None = None, entity: str = "") -> bool:
    if source not in ("vcenter", "esxi"):
        return False
    a = attrs or {}
    return is_vsan_text(message, a.get("app"), a.get("eventType"), a.get("event_type_id"), entity)


def is_vsan_anomaly(a: dict) -> bool:
    e = a.get("event") or {}
    return is_vsan_event(e.get("source", ""), e.get("message", ""), e.get("attrs") or {}, e.get("entity", "")) or \
        (e.get("source") in ("vcenter", "esxi") and is_vsan_text(a.get("title")))


def sql_cond() -> str:
    return " AND (" + " OR ".join("lower(message) LIKE ?" for _ in VSAN_SQL) + ")"


def sql_args() -> list[str]:
    return [f"%{k}%" for k in VSAN_SQL]


def ds_class(d: dict) -> str:
    """데이터스토어 분류 — vsan | local(호스트 로컬 VMFS) | san(공유 VMFS: FC·iSCSI·NVMe-oF) | nfs | vvol | other"""
    t = str(d.get("type") or "").lower()
    if t == "vsan":
        return "vsan"
    if t.startswith("nfs") or t == "cifs":
        return "nfs"
    if t == "vvol":
        return "vvol"
    if t == "vmfs":
        if d.get("local") is True or (d.get("local") is None and d.get("shared") is False) or (d.get("local") is None and len(d.get("hosts") or []) == 1):
            return "local"
        return "san"
    return "other"


CLASS_KO = {"vsan": "vSAN", "local": "로컬 디스크(VMFS)", "san": "외장 스토리지(공유 VMFS — FC·iSCSI·NVMe-oF)", "nfs": "NAS(NFS)", "vvol": "vVols", "other": "기타"}


def collect(engine) -> dict[str, Any]:
    """vSAN 클러스터·호스트·데이터스토어 + 비 vSAN 데이터스토어(로컬·외장·NFS·vVols)"""
    clusters, hosts, vds, other, tests, groups = [], [], [], [], [], []
    for c in engine.connectors:
        if getattr(c, "type", "") != "vcenter" or not getattr(c, "enabled", True):
            continue
        t = getattr(c, "topology", {}) or {}
        H = t.get("hosts", {}) or {}
        vsan_cl = {cn for cn, x in (t.get("clusters", {}) or {}).items() if x.get("vsan")}
        for cn in sorted(vsan_cl):
            x = t["clusters"][cn]
            hs = [H.get(h, {}) for h in x.get("hosts", [])]
            ds = [(n, d) for n, d in (t.get("datastores", {}) or {}).items() if ds_class(d) == "vsan" and set(d.get("hosts") or []) & set(x.get("hosts", []))]
            cap = sum(d.get("capacity_gb") or 0 for _, d in ds)
            free = sum(d.get("free_gb") or 0 for _, d in ds)
            issues = sum(len((h.get("vsan") or {}).get("disk_issues") or []) for h in hs)
            unhealthy = sum(1 for h in hs if (h.get("vsan") or {}).get("health") not in ("", None, "healthy", "green"))
            down = sum(1 for h in hs if h.get("conn") not in ("connected", ""))
            maint = sum(1 for h in hs if h.get("maintenance"))
            vh = x.get("vsan_health") or {}
            sp = vh.get("space") or {}
            if sp.get("total_gb"):
                cap, free = sp["total_gb"], sp["free_gb"]
            used = round((1 - free / cap) * 100, 1) if cap else None
            red = sum(1 for t in vh.get("tests_bad") or [] if t["health"] == "red")
            yellow = sum(1 for t in vh.get("tests_bad") or [] if t["health"] == "yellow")
            st = "down" if down or unhealthy or vh.get("overall") == "red" else "warn" if issues or maint or (used or 0) >= 80 or vh.get("overall") == "yellow" else "ok"
            clusters.append({"name": cn, "vcenter": c.name, "state": st, "hosts": len(hs), "down": down, "maint": maint, "unhealthy": unhealthy,
                             "disk_groups": sum((h.get("vsan") or {}).get("disk_groups", 0) for h in hs),
                             "cap_disks": sum((h.get("vsan") or {}).get("capacity_disks", 0) for h in hs),
                             "issues": issues, "capacity_gb": round(cap, 1), "free_gb": round(free, 1), "used_pct": used,
                             "health": vh.get("overall", ""), "health_ko": {"green": "정상", "yellow": "주의", "red": "장애"}.get(vh.get("overall", ""), "미수집" if not vh else vh.get("overall", "")),
                             "health_red": red, "health_yellow": yellow, "health_ts": vh.get("ts"),
                             "dedup": sp.get("ratio"), "objects": ", ".join(f"{k} {v}" for k, v in ((vh.get("objects") or {}).get("detail") or {}).items())[:120],
                             "datastores": ", ".join(n for n, _ in ds)})
            for tb in vh.get("tests_bad") or []:
                tests.append({"cluster": cn, "group": tb.get("group", ""), "test": tb["name"], "health": tb["health"],
                              "health_ko": {"red": "장애", "yellow": "주의"}.get(tb["health"], tb["health"]), "desc": tb["desc"],
                              "entities": f"{tb['healthy']}/{tb['all']}" if tb.get("all") is not None else "", "risk": tb.get("risk", "")})
            for g in vh.get("groups") or []:
                groups.append({"cluster": cn, "group": g["name"], "health": g["health"], "health_ko": {"green": "정상", "yellow": "주의", "red": "장애"}.get(g["health"], g["health"]),
                               "tests": len(g.get("tests") or []), "bad": sum(1 for tg in g.get("tests") or [] if tg["health"] in ("red", "yellow")),
                               "bad_names": ", ".join(tg["name"] for tg in g.get("tests") or [] if tg["health"] in ("red", "yellow"))[:160]})
            for hn in x.get("hosts", []):
                h = H.get(hn, {})
                v = h.get("vsan") or {}
                hst = "down" if h.get("conn") not in ("connected", "") else "maint" if h.get("maintenance") else \
                    "down" if v.get("health") not in ("", None, "healthy", "green") else "warn" if v.get("disk_issues") else "ok" if v else "warn"
                hosts.append({"name": hn, "cluster": cn, "state": hst, "role": v.get("role", ""), "health": v.get("health", "") or ("미수집" if not v else ""),
                              "disk_groups": v.get("disk_groups", ""), "cache": v.get("cache_disks", ""), "capacity": v.get("capacity_disks", ""),
                              "issues": "; ".join(v.get("disk_issues") or [])[:200], "members": v.get("member_uuids") or v.get("members", "")})
        for n, d in sorted((t.get("datastores", {}) or {}).items()):
            k = ds_class(d)
            row = {"name": n, "vcenter": c.name, "class": CLASS_KO[k], "kind": k, "type": DS_KIND.get(str(d.get("type", "")).lower(), d.get("type", "")),
                   "capacity_gb": d.get("capacity_gb"), "free_gb": d.get("free_gb"), "used_pct": d.get("used_pct"), "prov_gb": d.get("prov_gb"),
                   "hosts": len(d.get("hosts") or []), "host_names": ", ".join((d.get("hosts") or [])[:3]) + (" …" if len(d.get("hosts") or []) > 3 else ""),
                   "vms": d.get("vms", ""), "backing": d.get("remote") or ", ".join(d.get("extents") or [])[:120] or d.get("url", "")[:80],
                   "vmfs": d.get("vmfs_version", ""),
                   "state": "down" if d.get("accessible") is False else "maint" if d.get("maintenance") not in ("", None, "normal")
                   else "warn" if (d.get("used_pct") or 0) >= 85 or str(d.get("status")) in ("red", "yellow") else "ok"}
            (vds if k == "vsan" else other).append(row)
    order = {"local": 0, "san": 1, "nfs": 2, "vvol": 3, "other": 4}
    other.sort(key=lambda r: (order.get(r["kind"], 9), r["name"]))
    tests.sort(key=lambda t: (t["health"] != "red", t["cluster"], t["group"]))
    groups.sort(key=lambda g: ({"red": 0, "yellow": 1}.get(g["health"], 2), g["cluster"], g["group"]))
    return {"clusters": clusters, "hosts": hosts, "datastores": vds, "other": other, "health_tests": tests, "health_groups": groups,
            "other_summary": {CLASS_KO[k]: {"count": sum(1 for r in other if r["kind"] == k),
                                            "capacity_gb": round(sum(r["capacity_gb"] or 0 for r in other if r["kind"] == k), 1)}
                              for k in order if any(r["kind"] == k for r in other)}}


def entities(engine) -> list[dict]:
    """vSAN 관제 도메인의 개체 — vSAN 클러스터·호스트·데이터스토어 + 비 vSAN 데이터스토어"""
    d = collect(engine)
    out = [{"name": x["name"], "kind": "vSAN 클러스터", "state": x["state"],
            "detail": f"호스트 {x['hosts']} · 디스크 그룹 {x['disk_groups']} · 사용 {x['used_pct']}%" + (f" · 디스크 문제 {x['issues']}" if x["issues"] else "")}
           for x in d["clusters"]]
    out += [{"name": x["name"], "kind": "vSAN 호스트", "state": x["state"], "detail": f"{x['cluster']} · {x['role'] or '-'} · health {x['health'] or '-'}"}
            for x in d["hosts"]]
    out += [{"name": x["name"], "kind": "vSAN 데이터스토어", "state": x["state"], "detail": f"{x['capacity_gb']} GB · 사용 {x['used_pct']}%"} for x in d["datastores"]]
    out += [{"name": x["name"], "kind": x["class"].split("(")[0].strip(), "state": x["state"], "detail": f"{x['type']} · {x['capacity_gb']} GB · 사용 {x['used_pct']}% · 호스트 {x['hosts']}"}
            for x in d["other"]]
    return out
