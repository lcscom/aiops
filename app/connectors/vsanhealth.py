"""vSAN 상태 — vCenter 의 vSAN 관리 API(/vsanHealth, 읽기 전용 System.Read)로 클러스터 Health 점검·용량·객체 상태를 가져온다.

pyvmomi 8.0.3 이상에 vSAN 바인딩(`vim.cluster.VsanVcClusterHealthSystem` 등)이 들어 있어 별도 SDK 없이 쓴다.
  · Health   : VsanVcClusterHealthSystem('vsan-cluster-health-system').VsanQueryVcClusterHealthSummary(cluster, fetchFromCache=True)
               → overallHealth(green·yellow·red)·그룹(네트워크·물리 디스크·데이터·클러스터·용량·성능 서비스 …)·개별 점검 결과
  · 용량     : VsanSpaceReportSystem('vsan-cluster-space-report-system').VsanQuerySpaceUsage(cluster) → 전체·여유·중복제거/압축 효율
  · 객체     : VsanObjectSystem('vsan-cluster-object-system').VsanQueryObjectIdentities(cluster, includeHealth=True) → 객체 상태별 수
API 버전은 vCenter 의 /sdk/vsanServiceVersions.xml 에서 가장 높은 것을 쓰고, 없으면 후보 목록을 차례로 시도한다.
vSAN 을 쓰지 않거나(vcsim 등) 엔드포인트가 없으면 빈 결과를 돌려주고 커넥터 점검에 사유를 남긴다.
"""
from __future__ import annotations

import re
import ssl
import time
from typing import Any

try:
    from pyVmomi import SoapStubAdapter, vim, vmodl  # noqa: F401
    from pyVmomi import _typeinfo_vsanhealth  # noqa: F401  (vim.cluster.Vsan* 형식 등록)
    HAVE = True
except Exception:  # noqa: BLE001
    HAVE = False

VERSIONS = ["vsan.version.version22", "vsan.version.version18", "vsan.version.version16", "vsan.version.version12",
            "vsan.version.version9", "vim.version.version11"]
H_KO = {"green": "정상", "yellow": "주의", "red": "장애", "unknown": "미확인", "skipped": "생략", "info": "정보"}


def _obj(o, *path, default=None):
    for p in path:
        o = getattr(o, p, None)
        if o is None:
            return default
    return o


def latest_version(host: str, port: int, ctx: ssl.SSLContext, timeout: float = 8.0) -> str:
    """GET /sdk/vsanServiceVersions.xml — <name>urn:vsan</name> 아래 <version> 중 가장 큰 vsan.version.versionN"""
    import http.client
    try:
        c = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        c.request("GET", "/sdk/vsanServiceVersions.xml")
        body = c.getresponse().read().decode("utf-8", "replace")
        c.close()
    except Exception:  # noqa: BLE001
        return ""
    best, bn = "", -1
    for m in re.finditer(r"<version>\s*([^<\s]+)\s*</version>", body):
        v = m.group(1)
        n = re.search(r"vsan\.version\.version(\d+)$", v)
        if n and int(n.group(1)) > bn:
            best, bn = v, int(n.group(1))
    return best


class VsanClient:
    def __init__(self, si, host: str, port: int, ctx: ssl.SSLContext):
        self.si, self.host, self.port, self.ctx = si, host, port, ctx
        self.version = ""
        self.stub = None
        self.error = ""

    def connect(self) -> bool:
        """스텁 준비 — 실제 버전 확인은 첫 클러스터 조회에서(버전 미지원이면 다음 후보로 내려감)"""
        if not HAVE:
            self.error = "pyvmomi 에 vSAN 바인딩 없음(8.0.3 이상 필요)"
            return False
        self._cands = [v for v in [latest_version(self.host, self.port, self.ctx)] if v] + [v for v in VERSIONS]
        self._cands = list(dict.fromkeys(self._cands))
        return self._use(self._cands[0])

    def _use(self, ver: str) -> bool:
        try:
            stub = SoapStubAdapter(host=self.host, port=self.port, path="/vsanHealth", version=ver, sslContext=self.ctx, connectionPoolTimeout=60)
            stub.cookie = self.si._stub.cookie
            self.stub, self.version = stub, ver
            return True
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {str(e)[:120]}"
            return False

    def _call(self, fn):
        """버전 미지원(InvalidRequest·NotSupported·404)이면 다음 후보 버전으로 재시도"""
        last = None
        for ver in [self.version] + [v for v in getattr(self, "_cands", []) if v != self.version]:
            if ver != self.version and not self._use(ver):
                continue
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                last = e
                txt = f"{type(e).__name__} {e}".lower()
                if not any(k in txt for k in ("version", "notsupported", "invalidrequest", "404", "not found", "unsupported", "unexpected")):
                    raise
        raise last if last else RuntimeError("vSAN API 호출 실패")

    def cluster(self, cluster_mo, uuid_of_vm: dict[str, str] | None = None) -> dict[str, Any]:
        """한 클러스터의 Health 요약·점검 목록·용량·객체 상태"""
        out: dict[str, Any] = {"overall": "unknown", "overall_desc": "", "groups": [], "tests_bad": [], "space": {}, "objects": {}, "ts": time.time(), "error": ""}
        try:
            s = self._call(lambda: vim.cluster.VsanVcClusterHealthSystem("vsan-cluster-health-system", self.stub)
                           .VsanQueryVcClusterHealthSummary(cluster=cluster_mo, includeObjUuids=False, fetchFromCache=True))
            out["overall"] = str(getattr(s, "overallHealth", "") or "unknown")
            out["overall_desc"] = str(getattr(s, "overallHealthDescription", "") or "")[:300]
            ts = getattr(s, "timestamp", None)
            if hasattr(ts, "timestamp"):
                out["ts"] = ts.timestamp()
            for g in getattr(s, "groups", None) or []:
                tests = []
                for t in getattr(g, "groupTests", None) or []:
                    row = {"id": str(getattr(t, "testId", "") or ""), "name": str(getattr(t, "testName", "") or ""), "health": str(getattr(t, "testHealth", "") or "unknown"),
                           "desc": str(getattr(t, "testShortDescription", "") or "")[:300], "healthy": getattr(t, "testHealthyEntities", None),
                           "all": getattr(t, "testAllEntities", None), "category": str(getattr(t, "category", "") or ""),
                           "risk": str(getattr(t, "riskIfNotFix", "") or "")[:300]}
                    tests.append(row)
                    if row["health"] in ("red", "yellow"):
                        out["tests_bad"].append({**row, "group": str(getattr(g, "groupName", "") or "")})
                out["groups"].append({"id": str(getattr(g, "groupId", "") or ""), "name": str(getattr(g, "groupName", "") or ""),
                                      "health": str(getattr(g, "groupHealth", "") or "unknown"), "tests": tests})
            oh = _obj(s, "objectHealth")
            if oh is not None:
                det = {}
                for d in getattr(oh, "objectHealthDetail", None) or []:
                    det[str(getattr(d, "health", "") or "")] = len(getattr(d, "objUuids", None) or [])
                out["objects"] = {"overall": str(getattr(oh, "overallHealthState", "") or ""), "detail": det}
        except Exception as e:  # noqa: BLE001
            out["error"] = f"health: {type(e).__name__}: {str(e)[:160]}"
        try:
            u = self._call(lambda: vim.cluster.VsanSpaceReportSystem("vsan-cluster-space-report-system", self.stub).VsanQuerySpaceUsage(cluster=cluster_mo))
            tot, free = int(getattr(u, "totalCapacityB", 0) or 0), int(getattr(u, "freeCapacityB", 0) or 0)
            eff = _obj(u, "efficientCapacity")
            by_type = {}
            prim = ovh = 0
            for x in (_obj(u, "spaceDetail", "spaceUsageByObjectType") or []):
                by_type[str(getattr(x, "objType", "") or "")] = round(int(getattr(x, "physicalUsedB", 0) or 0) / 2**30, 1)
                # 2.37.0 실측 정책 배수 — 주 사본(primaryCapacityB) 대비 복제·패리티(overheadB). 임시 오버헤드(재동기화)는 뺀다
                p_, o_ = int(getattr(x, "primaryCapacityB", 0) or 0), int(getattr(x, "overheadB", 0) or 0)
                if p_ > 0:
                    prim, ovh = prim + p_, ovh + o_
            out["space"] = {"total_gb": round(tot / 2**30, 1), "free_gb": round(free / 2**30, 1), "used_pct": round((1 - free / tot) * 100, 1) if tot else None,
                            "logical_gb": round(int(getattr(eff, "logicalCapacity", 0) or 0) / 2**30, 1) if eff is not None else None,
                            "physical_gb": round(int(getattr(eff, "physicalCapacity", 0) or 0) / 2**30, 1) if eff is not None else None,
                            "ratio": (round(int(eff.logicalCapacity) / int(eff.physicalCapacity), 2) if eff is not None and getattr(eff, "physicalCapacity", 0) else None),
                            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])[:8]),
                            "primary_gb": round(prim / 2**30, 1) if prim else None, "overhead_gb": round(ovh / 2**30, 1) if prim else None,
                            "policy_mult": round((prim + ovh) / prim, 3) if prim else None}
        except Exception as e:  # noqa: BLE001
            out["space_error"] = f"space: {type(e).__name__}: {str(e)[:160]}"
        try:   # 용량 예비 설정(Operations Reserve·Host Rebuild Reserve) — 켜져 있으면 가정 분석 기본값으로
            ci = self._call(lambda: vim.cluster.VsanVcClusterConfigSystem("vsan-cluster-config-system", self.stub).VsanClusterGetConfig(cluster=cluster_mo))
            cr = _obj(ci, "capacityReservationInfo")
            if cr is not None:
                out["reserve"] = {"ops": str(getattr(cr, "vsanOpSpaceReservation", "") or ""), "host_rebuild": str(getattr(cr, "hostRebuildThreshold", "") or "")}
        except Exception as e:  # noqa: BLE001
            out["reserve_error"] = f"reserve: {type(e).__name__}"[:120]
        return out

    def test_rows(self, name: str, h: dict) -> list[dict]:
        """vSAN 점검 결과 → 화면 표 행"""
        rows = []
        for g in h.get("groups") or []:
            for t in g.get("tests") or []:
                rows.append({"cluster": name, "group": g["name"], "test": t["name"], "health": t["health"], "health_ko": H_KO.get(t["health"], t["health"]),
                             "desc": t["desc"], "entities": f"{t['healthy']}/{t['all']}" if t.get("all") is not None else "", "risk": t.get("risk", "")})
        rows.sort(key=lambda r: ({"red": 0, "yellow": 1}.get(r["health"], 2), r["group"], r["test"]))
        return rows
