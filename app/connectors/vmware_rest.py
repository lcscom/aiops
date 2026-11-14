"""REST 기반 VCF 컴포넌트 커넥터: SDDC Manager, NSX, VCF Operations, VCF Operations for logs, VCF Automation, SRM, Avi."""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from ..models import LogEvent, norm_severity
from .base import Connector


def _iso(ts: Any) -> float:
    """ISO8601 / epoch(ms|s) → epoch seconds."""
    if ts is None or ts == "":
        return time.time()
    if isinstance(ts, (int, float)):
        return ts / 1000 if ts > 1e11 else float(ts)
    s = str(ts)
    if s.isdigit():
        return _iso(int(s))
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def _items(data: Any, *keys: str) -> list:
    if isinstance(data, list):
        return data
    for k in keys:
        if isinstance(data, dict) and isinstance(data.get(k), list):
            return data[k]
    return []


_KW_SEV = [(re.compile(r"\b(panic|fatal|emerg|critical|crit)\b", re.I), "critical"),
           (re.compile(r"\b(error|err|fail(ed|ure)?|exception|unable|cannot|denied)\b", re.I), "error"),
           (re.compile(r"\b(warn(ing)?|degraded|timeout|retry)\b", re.I), "warning")]


def sev_from_text(text: str) -> str:
    for rx, s in _KW_SEV:
        if rx.search(text):
            return s
    return "info"


# ===================================================================== SDDC Manager
class SddcManagerConnector(Connector):
    """POST /v1/tokens → Bearer accessToken. GET /v1/tasks (실패·진행 상태 변화), /v1/domains 점검."""
    type = source = "sddc"
    default_interval = 30

    async def login(self):
        r = await self.http.post("/v1/tokens", json={"username": self.cfg["username"], "password": self.cfg["password"]})
        r.raise_for_status()
        self.http.headers["Authorization"] = f"Bearer {r.json()['accessToken']}"

    domains: list[dict[str, Any]] = []
    _dom_at = 0.0
    protection: dict[str, Any] | None = None      # 2.29.0 SDDC Manager 백업 구성·최근 백업 작업
    _bkp_at = 0.0
    _bkp_task: dict[str, Any] | None = None

    async def _refresh_domains(self) -> None:
        """GET /v1/domains — 워크로드 도메인(관리·VI)별 vCenter·NSX·클러스터(토폴로지용, 10분 주기)"""
        r = await self.http.get("/v1/domains")
        if r.status_code >= 300:
            return
        out = []
        for d in _items(r.json(), "elements"):
            nsx = d.get("nsxtCluster") or {}
            out.append({"id": d.get("id", ""), "name": d.get("name", ""), "type": d.get("type", ""), "status": d.get("status", ""),
                        "vcenters": [v.get("fqdn", "") for v in (d.get("vcenters") or []) if v.get("fqdn")],
                        "nsx": nsx.get("vipFqdn") or nsx.get("vip") or "", "clusters": len(d.get("clusters") or [])})
        self.domains = out
        self._dom_at = time.time()

    def entities(self):
        m = {"ACTIVE": "ok", "ERROR": "down", "ACTIVATING": "warn", "DELETING": "maint"}
        return [{"name": d["name"], "kind": "domain", "state": m.get(str(d["status"]).upper(), "unknown"),
                 "detail": f"{d['type']} · vCenter {', '.join(d['vcenters'])} · NSX {d['nsx'] or '-'} · 클러스터 {d['clusters']}"} for d in self.domains]

    async def _backup(self) -> None:
        from .. import protection as PR
        now = time.time()
        try:
            r = await self.http.get("/v1/system/backup-configuration")
            r.raise_for_status()
            self.protection = {**PR.sddc_backup(r.json(), self._bkp_task, now), "target": self.host}
        except Exception as e:  # noqa: BLE001
            self.protection = {"kind": "appliance_backup", "product": "SDDC Manager", "target": self.host, "updated": now, "error": f"조회 불가: {type(e).__name__}: {e}"[:200]}

    async def poll(self):
        if time.time() - self._bkp_at > float(self.cfg.get("backup_interval", 3600)):
            self._bkp_at = time.time()
            await self._backup()
        elif self.protection and not self.protection.get("error") and self._bkp_task:
            from .. import protection as PR
            self.protection.update(last={"status": "SUCCESS" if str(self._bkp_task["status"]).upper() in ("SUCCESSFUL", "COMPLETED") else self._bkp_task["status"],
                                         "end": self._bkp_task["end"], "message": self._bkp_task.get("message", "")}, last_success=self._bkp_task.get("last_success"))
        if time.time() - self._dom_at > float(self.cfg.get("domain_interval", 600)):
            try:
                await self._refresh_domains()
            except Exception:  # noqa: BLE001
                self._dom_at = time.time()
        r = await self.http.get("/v1/tasks")
        r.raise_for_status()
        out = []
        for t in _items(r.json(), "elements"):
            st = str(t.get("status", ""))
            if "BACKUP" in f"{t.get('type', '')} {t.get('name', '')}".upper():          # 2.29.0 가장 최근 백업 작업 기록
                te = _iso(t.get("completionTimestamp") or t.get("creationTimestamp"))
                b = self._bkp_task or {}
                if te >= (b.get("end") or 0):
                    ok_prev = b.get("last_success")
                    self._bkp_task = {"status": st, "end": te, "message": "; ".join(e.get("message", "") for e in (t.get("errors") or [])[:2]),
                                      "last_success": te if st.upper() in ("SUCCESSFUL", "COMPLETED") else ok_prev}
                elif st.upper() in ("SUCCESSFUL", "COMPLETED") and te > (b.get("last_success") or 0):
                    b["last_success"] = te
            if not self.seen.is_new(f"{t.get('id')}:{st}"):
                continue
            ts = _iso(t.get("completionTimestamp") or t.get("creationTimestamp"))
            if self.first_poll and ts < self.since:
                continue
            sev = "error" if "FAIL" in st.upper() else ("warning" if "CANCEL" in st.upper() else "info")
            errs = "; ".join(e.get("message", "") for e in (t.get("errors") or [])[:3])
            out.append(self.ev(f"SDDC Manager 작업 '{t.get('name')}' 상태 {st}" + (f" — {errs}" if errs else ""),
                               severity=sev, kind="task", entity=t.get("type", ""), ts=ts, native_id=str(t.get("id"))))
        return out

    async def checks(self):
        await self.login()
        return {"POST /v1/tokens": "ok", "GET /v1/tasks": await self._probe("GET", "/v1/tasks"),
                "GET /v1/domains": await self._probe("GET", "/v1/domains")}


def _first_ip(obj) -> str:
    import json as _json
    import re as _re
    m = _re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _json.dumps(obj or {}))
    return m.group(0) if m else ""


# ===================================================================== NSX
class NsxConnector(Connector):
    """Basic 인증. GET /api/v1/alarms?status=OPEN, GET /api/v1/cluster/status,
    Edge: GET /api/v1/transport-nodes(EdgeNode 식별) → GET /api/v1/transport-nodes/{id}/status (UP/DEGRADED/DOWN 전환).
    Edge 관련 알람·상태는 source=nsx-edge 로 분리."""
    type = source = "nsx"
    default_interval = 20

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.edges: dict[str, str] = {}          # transport node id → 이름
        self.edge_info: dict[str, dict] = {}     # id → 배치(host moid)·Edge 클러스터·관리 IP·연결 상태
        self._edges_at = 0.0
        self._edge_status_at = 0.0
        self._edge_state: dict[str, str] = {}
        self.protection: dict[str, Any] | None = None   # 2.29.0 NSX Manager 파일 기반 백업
        self._bkp_at = 0.0
        self.cluster_state: dict[str, str] = {}
        self.routing: dict[str, Any] = {}          # 2.3 T0 BGP(세션·업링크) — 네트워크 구성도
        self._bgp_state: dict[str, str] = {}
        self._bgp_at = 0.0

    def entities(self):
        out = []
        if self.cluster_state:
            vals = set(self.cluster_state.values())
            st = "down" if vals & {"UNSTABLE", "DOWN"} else ("warn" if vals - {"STABLE", "CONNECTED"} else "ok")
            out.append({"name": f"Manager 클러스터({self.host.split(':')[0]})", "kind": "manager", "state": st,
                        "detail": ", ".join(f"{k}={v}" for k, v in self.cluster_state.items())})
        m = {"UP": "ok", "DEGRADED": "warn", "DOWN": "down"}
        for tid, name in self.edges.items():
            v = self._edge_state.get(tid, "")
            ei = self.edge_info.get(tid, {})
            out.append({"name": name, "kind": "edge", "state": m.get(v, "unknown"),
                        "detail": " · ".join(x for x in (v or "상태 미수집", ei.get("edge_cluster", ""), ei.get("form", ""), ei.get("mgmt_ip", "")) if x)})
        return out

    POLICY_EDGE = "/policy/api/v1/infra/sites/default/enforcement-points/default/edge-transport-nodes"

    async def _paged(self, path: str, **params) -> tuple[int, list[dict]]:
        out, cursor, code = [], None, 0
        for _ in range(30):
            r = await self.http.get(path, params={"page_size": 1000, **params, **({"cursor": cursor} if cursor else {})})
            code = r.status_code
            if code >= 300:
                return code, out
            j = r.json() or {}
            out += j.get("results") or []
            cursor = j.get("cursor")
            if not cursor:
                break
        return code, out

    # ------------------------------------------------------------------ 2.21.0 세그먼트 트래픽(포트 통계·DFW 차단·VIF↔VM)
    EP = "/infra/sites/default/enforcement-points/default"

    async def _vif_map(self) -> dict[str, dict]:
        """GET /api/v1/fabric/vifs(lport_attachment_id → owner_vm_id·device_key·MAC) + /api/v1/fabric/virtual-machines(external_id → 이름), 5분 캐시"""
        c = getattr(self, "_vifs", None)
        if c and time.time() - c[0] < 300:
            return c[1]
        _, vifs = await self._paged("/api/v1/fabric/vifs")
        _, vms = await self._paged("/api/v1/fabric/virtual-machines")
        names = {v.get("external_id", ""): v.get("display_name", "") for v in vms}
        m = {}
        for v in vifs:
            if v.get("lport_attachment_id"):
                m[v["lport_attachment_id"]] = {"vm": names.get(v.get("owner_vm_id", ""), ""), "vm_id": v.get("owner_vm_id", ""),
                                               "device": str(v.get("device_key", "")), "mac": str(v.get("mac_address", "")).lower(),
                                               "label": v.get("device_name", ""),
                                               "ips": [a for ia in (v.get("ip_address_info") or []) for a in (ia.get("ip_addresses") or []) if ":" not in a][:4]}
        self._vifs = (time.time(), m)
        return m

    async def segment_ports(self, seg: str, max_ports: int = 400, conc: int = 6) -> dict:
        """세그먼트 하나의 포트별 누적 카운터(GET /policy/api/v1/infra/segments/{id}/ports/{port}/statistics) 와 세그먼트 합계(…/statistics).
        누적값이라 이전 조회와의 차이로 bps·pps 를 계산(첫 조회는 누적값만). 읽기 전용."""
        import asyncio as _a
        sid = seg.rsplit("/", 1)[-1]
        q = {"enforcement_point_path": self.EP}
        out: dict = {"segment": sid, "ports": [], "stats": {}, "error": "", "ts": time.time()}
        try:
            r = await self.http.get(f"/policy/api/v1/infra/segments/{sid}/statistics", params=q)
            if r.status_code < 300:
                j = r.json() or {}
                out["stats"] = {k: (j.get(k) or {}) for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")}
            code, ports = await self._paged(f"/policy/api/v1/infra/segments/{sid}/ports")
            if code >= 300:
                out["error"] = f"HTTP {code} — 세그먼트 포트 목록"
                return out
            vif = await self._vif_map()
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {str(e)[:120]}"
            return out
        sem = _a.Semaphore(conc)
        prev = getattr(self, "_portc", {})
        now = time.time()

        def dsum(o) -> int:
            return sum(int(v) for v in (o or {}).values() if isinstance(v, (int, float)) and not isinstance(v, bool)) if isinstance(o, dict) else 0

        async def one(p):
            async with sem:
                try:
                    r = await self.http.get(f"/policy/api/v1/infra/segments/{sid}/ports/{p['id']}/statistics", params=q)
                    st = r.json() if r.status_code < 300 else {}
                except Exception:  # noqa: BLE001
                    st = {}
            att = (p.get("attachment") or {}).get("id", "")
            v = vif.get(att, {})
            row = {"port": p.get("id", ""), "name": p.get("display_name", ""), "attachment": att, "vm": v.get("vm", ""), "device": v.get("device", ""),
                   "mac": v.get("mac", ""), "ips": v.get("ips", []), "label": v.get("label", ""), "admin": p.get("admin_state", ""),
                   "rx_bytes": int((st.get("rx_bytes") or {}).get("total") or 0), "tx_bytes": int((st.get("tx_bytes") or {}).get("total") or 0),
                   "rx_pkts": int((st.get("rx_packets") or {}).get("total") or 0), "tx_pkts": int((st.get("tx_packets") or {}).get("total") or 0),
                   "rx_drop": int((st.get("rx_packets") or {}).get("dropped") or 0), "tx_drop": int((st.get("tx_packets") or {}).get("dropped") or 0),
                   "dfw_drop": dsum(st.get("dropped_by_firewall_packets")), "sec_drop": dsum(st.get("dropped_by_security_packets")), "ok": bool(st)}
            pv = prev.get(f"{sid}/{row['port']}")
            if pv and 5 < now - pv["t"] < 1800:
                dt = now - pv["t"]
                for a, b, mul in (("rx_bytes", "rx_bps", 8), ("tx_bytes", "tx_bps", 8), ("rx_pkts", "rx_pps", 1), ("tx_pkts", "tx_pps", 1)):
                    d = row[a] - pv[a]
                    row[b] = d * mul / dt if d >= 0 else None          # 카운터가 줄면(재설정) 계산하지 않음
                row["interval"] = round(dt)
            return row
        rows = await _a.gather(*[one(p) for p in ports[:max_ports]])
        self._portc = {**{k: v for k, v in prev.items() if now - v["t"] < 3600},
                       **{f"{sid}/{r['port']}": {"t": now, **{k: r[k] for k in ("rx_bytes", "tx_bytes", "rx_pkts", "tx_pkts")}} for r in rows if r["ok"]}}
        out["ports"] = rows
        out["truncated"] = len(ports) > max_ports
        return out

    async def _refresh_edges(self) -> None:
        """Edge 목록 — Policy API(NSX 4.1+·9.x) 우선, 안 되면 Manager API(node_types=EdgeNode). 결과·실패 사유를 점검 화면에 표시.
        Edge VM 배치(vm_deployment_config.host_id = vCenter 호스트 moid)는 물리·논리 토폴로지에서 Edge → ESXi 호스트 연결에 쓴다."""
        info: dict[str, dict] = {}
        if not getattr(self, "version", ""):            # 버전(지식 검색의 적용 버전 가중)
            try:
                rv = await self.http.get("/api/v1/node/version")
                if rv.status_code < 300:
                    self.version = str((rv.json() or {}).get("product_version") or (rv.json() or {}).get("node_version") or "")
            except Exception:  # noqa: BLE001
                pass
        code, items = await self._paged(self.POLICY_EDGE)
        src = "Policy"
        if code < 300 and items:
            for t in items:
                vm = t.get("vm_deployment_config") or {}
                tid = t.get("id") or t.get("unique_id")
                info[tid] = {"name": t.get("display_name") or t.get("hostname") or tid, "host_moid": vm.get("host_id", ""), "compute": vm.get("compute_id", ""),
                             "vc_id": vm.get("vc_id", ""), "form": t.get("form_factor", ""), "mgmt_ip": _first_ip(t.get("management_interface")),
                             "unique_id": t.get("unique_id", ""), "policy": True}
        else:
            pcode = code
            code, items = await self._paged("/api/v1/transport-nodes", node_types="EdgeNode")
            src = "Manager"
            if code >= 300 or not items:                      # 구버전: node_types 미지원 → 전체에서 EdgeNode 만
                code, items = await self._paged("/api/v1/transport-nodes")
            for t in items:
                nd = t.get("node_deployment_info") or {}
                if nd.get("resource_type") != "EdgeNode" and "edge" not in str(t.get("resource_type", "")).lower():
                    continue
                vm = ((nd.get("deployment_config") or {}).get("vm_deployment_config")) or {}
                tid = t.get("id") or t.get("node_id")
                info[tid] = {"name": t.get("display_name") or tid, "host_moid": vm.get("host_id", ""), "compute": vm.get("compute_id", ""),
                             "vc_id": vm.get("vc_id", ""), "form": (nd.get("deployment_config") or {}).get("form_factor", ""),
                             "mgmt_ip": ",".join(nd.get("ip_addresses") or []), "policy": False}
            self._state["checks"]["Edge 목록(Policy API)"] = f"warn: HTTP {pcode} — Manager API 로 대체" if pcode >= 300 else "ok 0개"
        try:
            code_c, ecs = await self._paged("/api/v1/edge-clusters")
            for ec in ecs:
                for m in ec.get("members") or []:
                    tid = m.get("transport_node_id")
                    if tid in info:
                        info[tid]["edge_cluster"] = ec.get("display_name", "")
        except Exception:  # noqa: BLE001
            pass
        self.edge_info = info
        self.edges = {k: v["name"] for k, v in info.items()}
        self._state["checks"][f"Edge 목록({src} API)"] = f"ok {len(info)}개" if info else f"warn: Edge 없음(HTTP {code}) — Edge 미배포이거나 계정 권한(Auditor 이상) 확인"
        self._edges_at = time.time()

    async def _edge_status(self) -> list[LogEvent]:
        out = []
        fails = 0
        for tid, name in list(self.edges.items())[:200]:
            j, st = None, ""
            r = await self.http.get(f"/api/v1/transport-nodes/{tid}/status")
            if r.status_code < 300:
                j = r.json() or {}
                st = str(j.get("status") or (j.get("node_status") or {}).get("status") or "UNKNOWN").upper()
            else:                                              # Manager API 상태 없음(NSX 9 일부) → Policy 상태(overall_state)
                r2 = await self.http.get(f"{self.POLICY_EDGE}/{tid}/state")
                if r2.status_code < 300:
                    s2 = ((r2.json() or {}).get("edge_tn_state") or {})
                    ov = str(s2.get("overall_state") or s2.get("state") or "").lower()
                    st = "UP" if ov in ("success", "up", "realized") else ("DOWN" if ov in ("failed", "error", "down") else (ov.upper() or "UNKNOWN"))
                    j = {}
                else:
                    fails += 1
                    continue
            prev = self._edge_state.get(tid)
            self._edge_state[tid] = st
            if j:
                self.edge_info.setdefault(tid, {})["detail"] = {k: (j.get(k) or {}).get("status") for k in
                                                               ("control_connection_status", "mgmt_connection_status", "tunnel_status", "pnic_status") if isinstance(j.get(k), dict)}
            if prev == st or (prev is None and st == "UP"):
                continue
            parts = []
            for k in ("control_connection_status", "mgmt_connection_status", "tunnel_status", "pnic_status", "agent_status"):
                v = (j or {}).get(k) or {}
                if isinstance(v, dict) and v.get("status") and str(v["status"]).upper() not in ("UP", "STABLE"):
                    parts.append(f"{k.replace('_status', '')}={v['status']}")
            sev = "info" if st == "UP" else ("critical" if st == "DOWN" else "error")
            out.append(self.ev(f"NSX Edge {name} 상태 {prev or '-'} → {st}" + (f" ({', '.join(parts)})" if parts else ""),
                               severity=sev, kind="health", source="nsx-edge", host=name, entity=f"edge:{name}",
                               attrs={"transport_node_id": tid}))
        self._state["checks"]["Edge 상태"] = (f"ok {len(self.edges) - fails}/{len(self.edges)}" if not fails
                                             else f"warn: {fails}개 상태 조회 실패(/api/v1/transport-nodes/{{id}}/status · Policy state)")
        return out

    async def login(self):
        self.http.auth = (self.cfg["username"], self.cfg["password"])
        r = await self.http.get("/api/v1/cluster/status")
        r.raise_for_status()

    async def poll(self):
        out: list[LogEvent] = []
        now = time.time()
        if now - self._edges_at > float(self.cfg.get("edge_refresh", 300)):
            await self._refresh_edges()
        if self.edges and now - self._edge_status_at > float(self.cfg.get("edge_status_interval", 60)):
            self._edge_status_at = now
            out += await self._edge_status()
        if now - self._bkp_at > float(self.cfg.get("backup_interval", 3600)):
            self._bkp_at = now
            out += await self._backup()
        r = await self.http.get("/api/v1/alarms", params={"status": "OPEN", "page_size": 1000})
        r.raise_for_status()
        for a in _items(r.json(), "results"):
            key = f"{a.get('id')}:{a.get('status')}:{a.get('_last_modified_time')}"
            if not self.seen.is_new(key):
                continue
            msg = f"[{a.get('feature_name')}/{a.get('event_type')}] {a.get('description') or a.get('summary') or ''}"
            if a.get("recommended_action"):
                msg += f" | 권고: {str(a['recommended_action'])[:300]}"
            is_edge = ("edge" in str(a.get("node_resource_type", "")).lower() or str(a.get("feature_name", "")).lower().startswith("edge")
                       or a.get("node_id") in self.edges or a.get("entity_id") in self.edges)
            out.append(self.ev(msg, severity=norm_severity(a.get("severity"), "warning"), kind="alarm",
                               source="nsx-edge" if is_edge else "nsx",
                               entity=a.get("entity_id", "") or a.get("node_display_name", ""),
                               host=a.get("node_display_name") or self.host,
                               ts=_iso(a.get("_last_modified_time") or a.get("_create_time")), native_id=str(a.get("id")),
                               attrs={"feature": a.get("feature_name"), "event_type": a.get("event_type")}))
        r = await self.http.get("/api/v1/cluster/status")
        if r.status_code < 300:
            j = r.json()
            for comp, val in (("management", j.get("mgmt_cluster_status", {}).get("status")),
                              ("control", j.get("control_cluster_status", {}).get("status")),
                              ("overall", j.get("detailed_cluster_status", {}).get("overall_status"))):
                if val:
                    self.cluster_state[comp] = str(val)
                if val and self.seen.is_new(f"cluster:{comp}:{val}") and (val not in ("STABLE", "CONNECTED") or not self.first_poll):
                    sev = "info" if val in ("STABLE", "CONNECTED") else ("critical" if val in ("UNSTABLE", "DOWN") else "warning")
                    out.append(self.ev(f"NSX Manager {comp} cluster status = {val}", severity=sev, kind="health",
                                       entity=f"nsx-cluster:{comp}"))
        if time.time() - getattr(self, "_inv_at", 0) > float(self.cfg.get("inventory_interval", 600)):
            try:
                await self._refresh_inventory()
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["인벤토리"] = f"warn: {type(e).__name__}"
            self._inv_at = time.time()
        if self.cfg.get("bgp", True) and time.time() - self._bgp_at > float(self.cfg.get("bgp_interval", 120)):
            self._bgp_at = time.time()
            try:
                out += await self._refresh_routing()
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["T0 BGP"] = f"warn: {type(e).__name__}: {str(e)[:100]}"
        return out

    async def _refresh_inventory(self) -> None:
        """Policy API(읽기 전용 Auditor 로 조회 가능): Tier-0·Tier-1 게이트웨이, 세그먼트, Edge 클러스터 — 인벤토리 화면용(10분)"""
        async def items(path: str, **params) -> list[dict]:
            out, cursor = [], None
            for _ in range(20):
                q = {"page_size": 1000, **params, **({"cursor": cursor} if cursor else {})}
                r = await self.http.get(path, params=q)
                if r.status_code >= 300:
                    break
                j = r.json() or {}
                out += j.get("results") or []
                cursor = j.get("cursor")
                if not cursor:
                    break
            return out
        t0s = [{"name": x.get("display_name", ""), "id": x.get("id", ""), "ha_mode": x.get("ha_mode", ""), "failover": x.get("failover_mode", "")}
               for x in await items("/policy/api/v1/infra/tier-0s")]
        t1s = [{"name": x.get("display_name", ""), "id": x.get("id", ""), "tier0": str(x.get("tier0_path", "")).rsplit("/", 1)[-1],
                "edge_cluster": bool(x.get("edge_cluster_path") or x.get("route_advertisement_types"))} for x in await items("/policy/api/v1/infra/tier-1s")]
        segs = [{"name": x.get("display_name", ""), "id": x.get("id", ""), "type": x.get("type", ""),
                 "vlan": ",".join(str(v) for v in (x.get("vlan_ids") or [])), "gateway": ",".join(sb.get("gateway_address", "") for sb in (x.get("subnets") or [])),
                 "connected_to": str(x.get("connectivity_path", "")).rsplit("/", 1)[-1], "tz": str(x.get("transport_zone_path", "")).rsplit("/", 1)[-1],
                 "admin": x.get("admin_state", "")} for x in await items("/policy/api/v1/infra/segments")]
        ecs = [{"name": x.get("display_name", ""), "id": x.get("id", ""), "members": len(x.get("members") or [])}
               for x in await items("/api/v1/edge-clusters")]
        for kind, lst in (("tier-0s", t0s), ("tier-1s", t1s)):          # 게이트웨이가 올라간 Edge 클러스터(locale-services.edge_cluster_path)
            for g in lst[:100]:
                try:
                    for ls in await items(f"/policy/api/v1/infra/{kind}/{g['id']}/locale-services"):
                        if ls.get("edge_cluster_path"):
                            g["edge_cluster_id"] = str(ls["edge_cluster_path"]).rsplit("/", 1)[-1]
                            break
                except Exception:  # noqa: BLE001
                    break
        for sg in segs:
            sg["tier1"] = sg["connected_to"] if any(t["id"] == sg["connected_to"] for t in t1s) else ""
        # 2.4 NSX VPC(4.2+·9.x) — 프로젝트 › VPC › 서브넷, VPC 에 붙은 VM. 미지원 버전은 404 → 빈 목록
        projects, vpcs = [], []
        if self.cfg.get("vpc", True):
            for pj in (await items("/policy/api/v1/orgs/default/projects"))[:50]:
                pid = pj.get("id", "")
                projects.append({"id": pid, "name": pj.get("display_name") or pid, "tier0s": [str(x).rsplit("/", 1)[-1] for x in (pj.get("tier_0s") or [])]})
                for v in (await items(f"/policy/api/v1/orgs/default/projects/{pid}/vpcs"))[:200]:
                    vid = v.get("id", "")
                    base = f"/policy/api/v1/orgs/default/projects/{pid}/vpcs/{vid}"
                    subs = [{"id": sb.get("id", ""), "name": sb.get("display_name") or sb.get("id", ""), "access": sb.get("access_mode", ""),
                             "cidr": ",".join(sb.get("ip_addresses") or [])} for sb in (await items(f"{base}/subnets"))[:200]]
                    vms = [x.get("display_name", "") for x in (await items(f"{base}/virtual-machines"))[:500] if x.get("display_name")]
                    vpcs.append({"id": vid, "name": v.get("display_name") or vid, "project": pid, "project_name": pj.get("display_name") or pid,
                                 "tier0": str(v.get("default_gateway_path") or "").rsplit("/", 1)[-1], "short_id": v.get("short_id", ""),
                                 "private": ",".join(v.get("private_ips") or v.get("private_ipv4_blocks") or []), "subnets": subs, "vms": vms})
        self.inv = {"tier0": t0s, "tier1": t1s, "segments": segs, "edge_clusters": ecs, "projects": projects, "vpcs": vpcs, "updated": time.time()}

    # ------------------------------------------------------------------ 2.3 Tier-0 BGP(Edge ↔ 물리 스위치)
    def edge_name(self, edge_path: str) -> str:
        """Policy edge_path(.../edge-clusters/{ec}/edge-nodes/{tn-id}) → Edge 이름"""
        tid = str(edge_path or "").rstrip("/").rsplit("/", 1)[-1]
        if tid in self.edges:
            return self.edges[tid]
        for k, v in self.edge_info.items():
            if v.get("unique_id") == tid:
                return v.get("name") or tid
        return tid[:12] if tid else ""

    async def _refresh_routing(self) -> list[LogEvent]:
        """GET /policy/api/v1/infra/tier-0s → 각 T0 locale-services 의
             /bgp (local_as_num·enabled) · /bgp/neighbors (neighbor_address·remote_as_num·source_addresses)
             /bgp/neighbors/status (Edge 별 connection_state·source_address·prefix 수 — PolicyBgpNeighborStatus)
             /interfaces (EXTERNAL 업링크: subnets·edge_path·segment_path·access_vlan_id)
           세션 상태가 바뀌면 이벤트(source=nsx-edge). 읽기 전용(Auditor)."""
        async def items(path: str) -> tuple[int, list[dict]]:
            r = await self.http.get(path, params={"page_size": 1000})
            if r.status_code >= 300:
                return r.status_code, []
            return r.status_code, (r.json() or {}).get("results") or []
        out: list[LogEvent] = []
        code, t0s = await items("/policy/api/v1/infra/tier-0s")
        if code >= 300:
            self._state["checks"]["T0 BGP"] = f"warn: HTTP {code} — /policy/api/v1/infra/tier-0s"
            return out
        segs = {s.get("id"): s for s in (getattr(self, "inv", {}) or {}).get("segments", [])}
        res, nsess, nbad = [], 0, 0
        for t in t0s[:50]:
            tid = t.get("id", "")
            g = {"id": tid, "name": t.get("display_name") or tid, "ha_mode": t.get("ha_mode", ""), "local_as": "", "bgp_enabled": None,
                 "neighbors": [], "sessions": [], "interfaces": []}
            _, lss = await items(f"/policy/api/v1/infra/tier-0s/{tid}/locale-services")
            for ls in lss[:4]:
                base = f"/policy/api/v1/infra/tier-0s/{tid}/locale-services/{ls.get('id')}"
                rb = await self.http.get(f"{base}/bgp")
                if rb.status_code < 300:
                    b = rb.json() or {}
                    g["local_as"] = str(b.get("local_as_num") or g["local_as"])
                    g["bgp_enabled"] = b.get("enabled", True)
                _, nbs = await items(f"{base}/bgp/neighbors")
                for n in nbs:
                    g["neighbors"].append({"id": n.get("id", ""), "name": n.get("display_name") or n.get("id", ""),
                                           "neighbor": str(n.get("neighbor_address", "")).split("/")[0], "remote_as": str(n.get("remote_as_num", "")),
                                           "source": [str(x) for x in (n.get("source_addresses") or [])], "bfd": bool((n.get("bfd") or {}).get("enabled"))})
                _, sts = await items(f"{base}/bgp/neighbors/status")
                for s in sts:
                    if str(s.get("type", "USER")).upper() == "INTER_SR":      # Edge 간 내부 세션은 물리 구성도와 무관
                        continue
                    st = str(s.get("connection_state") or s.get("connection_status") or "UNKNOWN").upper()
                    g["sessions"].append({"edge": self.edge_name(s.get("edge_path", "")), "edge_path": s.get("edge_path", ""),
                                          "source": str(s.get("source_address") or ""), "neighbor": str(s.get("neighbor_address") or ""),
                                          "remote_as": str(s.get("remote_as_number") or ""), "state": st,
                                          "uptime_s": s.get("time_since_established"), "in_prefix": s.get("total_in_prefix_count"),
                                          "out_prefix": s.get("total_out_prefix_count"), "drops": s.get("connection_drop_count"),
                                          "router_id": s.get("neighbor_router_id", "")})
                _, ifs = await items(f"{base}/interfaces")
                for i in ifs:
                    seg = str(i.get("segment_path", "")).rsplit("/", 1)[-1]
                    ips = [f"{a}/{sb.get('prefix_len')}" for sb in (i.get("subnets") or []) for a in (sb.get("ip_addresses") or [])]
                    g["interfaces"].append({"name": i.get("display_name") or i.get("id", ""), "type": i.get("type", "EXTERNAL"), "ips": ips,
                                            "edge": self.edge_name(i.get("edge_path", "")), "segment": seg,
                                            "vlan": i.get("access_vlan_id") or (segs.get(seg) or {}).get("vlan", ""), "mtu": i.get("mtu")})
            for s in g["sessions"]:
                nsess += 1
                key = f"{tid}|{s['edge']}|{s['neighbor']}"
                prev = self._bgp_state.get(key)
                self._bgp_state[key] = s["state"]
                if s["state"] != "ESTABLISHED":
                    nbad += 1
                if prev is not None and prev != s["state"] and (prev == "ESTABLISHED" or s["state"] == "ESTABLISHED"):
                    up = s["state"] == "ESTABLISHED"
                    out.append(self.ev(f"NSX T0 {g['name']} BGP neighbor {s['neighbor']} (AS {s['remote_as']}) on {s['edge']} {prev} -> {s['state']}",
                                       severity="info" if up else "critical", kind="event", source="nsx-edge", host=s["edge"],
                                       entity=f"bgp:{s['edge']}:{s['neighbor']}",
                                       attrs={"tier0": g["name"], "neighbor": s["neighbor"], "source_address": s["source"], "net_change": "bgp"}))
            res.append(g)
        self.routing = {"tier0": res, "updated": time.time()}
        self._state["checks"]["T0 BGP"] = (f"ok T0 {len(res)} · 세션 {nsess - nbad}/{nsess} Established" if not nbad
                                          else f"warn: 세션 {nbad}/{nsess} 비정상(Established 아님)") if nsess else f"ok T0 {len(res)} · BGP 세션 없음"
        return out

    async def checks(self):
        self.http.auth = (self.cfg["username"], self.cfg["password"])
        return {"GET /api/v1/cluster/status": await self._probe("GET", "/api/v1/cluster/status"),
                "GET /api/v1/alarms": await self._probe("GET", "/api/v1/alarms", params={"page_size": 1}),
                "GET /api/v1/transport-nodes": await self._probe("GET", "/api/v1/transport-nodes", params={"page_size": 1}),
                "GET Policy edge-transport-nodes": await self._probe("GET", self.POLICY_EDGE, params={"page_size": 1}),
                "GET /api/v1/edge-clusters": await self._probe("GET", "/api/v1/edge-clusters", params={"page_size": 1}),
                "GET Policy tier-0s(BGP)": await self._probe("GET", "/policy/api/v1/infra/tier-0s", params={"page_size": 1})}


# ===================================================================== VCF Operations
OPS_KINDS = ("HostSystem", "VirtualMachine", "ClusterComputeResource", "Datastore")
# 키를 고르지 않은 종류는 VCF Ops 카탈로그(statkeys)에 실제로 있는 키만 이 순서로 골라 씀(최대 8개)
# HostSystem 앞 4개는 brockpeterson/miscellaneous 'VCF Operations Metrics Picker' README 의 기본 지표
OPS_PREFER = {
    "HostSystem": ["cpu|capacity_usagepct_average", "cpu|coreUtilization_average", "mem|active_average", "mem|consumed_average",
                   "cpu|usage_average", "mem|usage_average", "cpu|readyPct", "badge|health"],
    "VirtualMachine": ["cpu|usage_average", "cpu|readyPct", "cpu|costopPct", "mem|usage_average", "mem|active_average",
                       "virtualDisk|totalLatency", "net|usage_average", "badge|health"],
    "ClusterComputeResource": ["cpu|capacity_usagepct_average", "cpu|usage_average", "cpu|demandPct", "mem|usage_average",
                               "mem|consumed_average", "badge|health"],
    "Datastore": ["capacity|usedSpacePct", "diskspace|used", "capacity|total_capacity", "devices|totalLatency_average",
                  "datastore|totalLatency_average", "badge|health"],
}


class VcfOpsConnector(Connector):
    """POST /suite-api/api/auth/token/acquire → 'Authorization: OpsToken <token>'.
    GET /suite-api/api/alerts?activeOnly=true (+ resources 이름 캐시).
    2.8.0 메트릭: GET /suite-api/api/resources?resourceKind=&adapterKind=VMWARE(페이지) →
    POST /suite-api/api/resources/stats/latest/query {resourceId[≤1000], statKey[], maxSamples:1}(구버전은 GET /resources/stats/latest 로 대체) ·
    지표 이름·단위 GET /suite-api/api/adapterkinds/VMWARE/resourcekinds/{kind}/statkeys"""
    type = source = "vcfops"
    default_interval = 30

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.names: dict[str, str] = {}
        self.metrics_on = cfg.get("metrics", True) is not False
        self.metric_interval = max(60, int(cfg.get("metric_interval", 300)))
        self.metric_kinds = [k for k in (cfg.get("metric_kinds") or OPS_KINDS) if k]
        self.metric_max = int(cfg.get("metric_max_objects", 10000))
        self.adapter_kind = cfg.get("adapter_kind", "VMWARE")
        self.keys_override: dict[str, list[str]] = {}      # 화면 메트릭 선택기 값(엔진이 주입)
        self.catalog: dict[str, dict[str, dict]] = {}       # kind → key → {name, unit}
        self.ops: dict[str, Any] = {"kinds": {}, "updated": 0.0, "error": "", "gen": 0, "took_ms": 0, "api": ""}
        self._res_cache: dict[str, tuple[float, dict]] = {}
        self._last_metrics = 0.0
        self._bulk_ok = True

    async def login(self):
        body = {"username": self.cfg["username"], "password": self.cfg["password"]}
        if self.cfg.get("auth_source"):
            body["authSource"] = self.cfg["auth_source"]
        r = await self.http.post("/suite-api/api/auth/token/acquire", json=body)
        r.raise_for_status()
        scheme = self.cfg.get("token_scheme", "OpsToken")   # 구버전(Aria 8.x)은 vRealizeOpsToken
        self.http.headers["Authorization"] = f"{scheme} {r.json()['token']}"

    async def _resolve(self, ids: list[str]) -> None:
        need = [i for i in ids if i and i not in self.names][:100]
        if not need:
            return
        r = await self.http.get("/suite-api/api/resources", params=[("resourceId", i) for i in need] + [("pageSize", 100)])
        if r.status_code < 300:
            for res in _items(r.json(), "resourceList"):
                self.names[res.get("identifier")] = res.get("resourceKey", {}).get("name", "")

    # ------------------------------------------------------------------ 2.8.0 메트릭
    def metric_keys(self, kind: str) -> list[str]:
        """선택기 값 > config metric_keys > 카탈로그에 있는 선호 키(카탈로그 못 읽으면 선호 키 그대로)"""
        if self.keys_override.get(kind):
            return self.keys_override[kind][:40]
        cfgk = (self.cfg.get("metric_keys") or {}).get(kind)
        if cfgk:
            return list(cfgk)[:40]
        pref = OPS_PREFER.get(kind, ["badge|health"])
        cat = self.catalog.get(kind)
        return [k for k in pref if k in cat][:8] if cat else pref[:8]

    async def _get(self, path: str, **kw):
        r = await self.http.get(path, **kw)
        if r.status_code == 401:                      # 토큰 만료 → 재로그인 1회
            await self.login()
            r = await self.http.get(path, **kw)
        return r

    async def fetch_catalog(self, kind: str) -> dict[str, dict]:
        r = await self._get(f"/suite-api/api/adapterkinds/{self.adapter_kind}/resourcekinds/{kind}/statkeys", params={"_no_links": "true"})
        r.raise_for_status()
        out = {}
        for a in _items(r.json(), "resourceTypeAttributes", "stat-key", "statKeys"):
            k = a.get("key") if isinstance(a, dict) else None
            if k:
                out[k] = {"name": a.get("name") or k, "unit": a.get("unit") or "", "description": (a.get("description") or "")[:200],
                          "instanced": bool(a.get("instanced")), "property": bool(a.get("property"))}
        self.catalog[kind] = out
        return out

    async def _resources(self, kind: str) -> dict[str, dict]:
        hit = self._res_cache.get(kind)
        if hit and time.time() - hit[0] < 1800:
            return hit[1]
        out: dict[str, dict] = {}
        page = 0
        while len(out) < self.metric_max:
            r = await self._get("/suite-api/api/resources", params={"resourceKind": kind, "adapterKind": self.adapter_kind, "page": page,
                                                                     "pageSize": 1000, "_no_links": "true"})
            r.raise_for_status()
            j = r.json()
            batch = _items(j, "resourceList")
            for res in batch:
                rid = res.get("identifier")
                if rid:
                    rk = res.get("resourceKey") or {}
                    out[rid] = {"name": rk.get("name") or rid, "health": res.get("resourceHealth") or "",
                                "status": ((res.get("resourceStatusStates") or [{}])[0] or {}).get("resourceStatus", "")}
                    self.names[rid] = out[rid]["name"]
            total = int(((j.get("pageInfo") or {}).get("totalCount")) or 0)
            page += 1
            if not batch or len(batch) < 1000 or (total and len(out) >= total):
                break
        self._res_cache[kind] = (time.time(), out)
        return out

    async def _latest(self, ids: list[str], keys: list[str]) -> list[dict]:
        if self._bulk_ok:
            r = await self.http.post("/suite-api/api/resources/stats/latest/query", json={"resourceId": ids, "statKey": keys, "maxSamples": 1, "currentOnly": True})
            if r.status_code == 401:
                await self.login()
                r = await self.http.post("/suite-api/api/resources/stats/latest/query", json={"resourceId": ids, "statKey": keys, "maxSamples": 1, "currentOnly": True})
            if r.status_code in (404, 405):
                self._bulk_ok = False                         # 구버전 — GET 으로 대체
            else:
                r.raise_for_status()
                self.ops["api"] = "POST stats/latest/query"
                return _items(r.json(), "values")
        r = await self._get("/suite-api/api/resources/stats/latest", params=[("resourceId", i) for i in ids] + [("statKey", k) for k in keys] + [("maxSamples", 1)])
        r.raise_for_status()
        self.ops["api"] = "GET stats/latest"
        return _items(r.json(), "values")

    async def collect_metrics(self) -> dict[str, Any]:
        """종류마다 개체 목록 → 최신 값(일괄 500개씩). 실패한 종류는 건너뛰고 오류만 기록"""
        t0 = time.time()
        kinds: dict[str, Any] = {}
        errs = []
        for kind in self.metric_kinds:
            try:
                if kind not in self.catalog:
                    try:
                        await self.fetch_catalog(kind)
                    except Exception:  # noqa: BLE001 — 카탈로그 없이도 수집
                        self.catalog[kind] = {}
                keys = self.metric_keys(kind)
                objs = await self._resources(kind)
                vals: dict[str, dict[str, list]] = {}
                ids = list(objs)
                for i in range(0, len(ids), 500):
                    for v in await self._latest(ids[i:i + 500], keys):
                        rid = v.get("resourceId")
                        for st in ((v.get("stat-list") or {}).get("stat") or []):
                            k = (st.get("statKey") or {}).get("key")
                            data, ts = st.get("data") or [], st.get("timestamps") or []
                            if k and data:
                                vals.setdefault(rid, {})[k] = [float(data[-1]), (ts[-1] / 1000) if ts else t0]
                kinds[kind] = {"keys": keys, "objects": objs, "values": vals, "with_data": len(vals),
                               "keys_no_data": [k for k in keys if not any(k in x for x in vals.values())] if vals else keys}
            except Exception as e:  # noqa: BLE001
                errs.append(f"{kind}: {type(e).__name__}: {e}"[:200])
                if kind in self.ops.get("kinds", {}):
                    kinds[kind] = self.ops["kinds"][kind]               # 이전 값 유지
        self.ops = {"kinds": kinds, "updated": time.time(), "error": "; ".join(errs), "gen": self.ops.get("gen", 0) + 1,
                    "took_ms": int((time.time() - t0) * 1000), "api": self.ops.get("api", "")}
        self._state["checks"] = {**self._state.get("checks", {}), "메트릭": ("ok" if not errs else "; ".join(errs))[:200]}
        return self.ops

    async def poll(self):
        if self.metrics_on and time.time() - self._last_metrics >= self.metric_interval:
            self._last_metrics = time.time()
            try:
                await self.collect_metrics()
            except Exception as e:  # noqa: BLE001 — 메트릭 실패가 알림 수집을 막지 않게
                self.ops["error"] = f"{type(e).__name__}: {e}"[:200]
        r = await self.http.get("/suite-api/api/alerts", params={"activeOnly": "true", "pageSize": 1000})
        r.raise_for_status()
        alerts = _items(r.json(), "alerts")
        await self._resolve([a.get("resourceId") for a in alerts])
        out = []
        for a in alerts:
            key = f"{a.get('alertId')}:{a.get('status')}:{a.get('alertLevel')}:{a.get('controlState')}"
            if not self.seen.is_new(key):
                continue
            ent = self.names.get(a.get("resourceId"), a.get("resourceId", ""))
            out.append(self.ev(f"{a.get('alertDefinitionName') or a.get('alertDefinitionId')} "
                               f"[{a.get('alertImpact', '')}/{a.get('type', '')}] status={a.get('status')}",
                               severity=norm_severity(a.get("alertLevel"), "warning"), kind="alert", entity=ent,
                               ts=_iso(a.get("updateTimeUTC") or a.get("startTimeUTC")), native_id=str(a.get("alertId")),
                               attrs={"resourceId": a.get("resourceId"), "controlState": a.get("controlState")}))
        return out

    async def checks(self):
        await self.login()
        return {"POST /suite-api/api/auth/token/acquire": "ok",
                "GET /suite-api/api/alerts": await self._probe("GET", "/suite-api/api/alerts", params={"pageSize": 1}),
                "GET /suite-api/api/versions/current": await self._probe("GET", "/suite-api/api/versions/current"),
                "GET /suite-api/api/resources?resourceKind=HostSystem": await self._probe("GET", "/suite-api/api/resources",
                                                                                         params={"resourceKind": "HostSystem", "pageSize": 1})}


# ===================================================================== VCF Operations for logs
class VcfLogsConnector(Connector):
    """포트 9543. POST /api/v2/sessions → Bearer sessionId.
    GET /api/v2/events/timestamp/>{ms}[/추가 제약] ?limit&order-by-direction=ASC"""
    type = source = "vcflogs"
    default_interval = 10

    def __init__(self, cfg, emit):
        if not cfg.get("base_url") and cfg.get("host"):
            cfg = {**cfg, "base_url": f"https://{cfg['host']}:{cfg.get('port', 9543)}"}
        super().__init__(cfg, emit)

    async def login(self):
        r = await self.http.post("/api/v2/sessions", json={"username": self.cfg["username"], "password": self.cfg["password"],
                                                           "provider": self.cfg.get("provider", "Local")})
        r.raise_for_status()
        self.http.headers["Authorization"] = f"Bearer {r.json()['sessionId']}"

    async def poll(self):
        since_ms = int(self.since * 1000)
        path = f"/api/v2/events/timestamp/{quote('>' + str(since_ms))}"
        if self.cfg.get("constraint"):   # 예: "text/CONTAINS error"
            path += "/" + "/".join(quote(p) for p in self.cfg["constraint"].split("/"))
        r = await self.http.get(path, params={"limit": int(self.cfg.get("limit", 1000)),
                                              "order-by-direction": "ASC", "timeout": 20000})
        r.raise_for_status()
        out = []
        newest = self.since
        for e in _items(r.json(), "events", "results"):
            fields = {f.get("name"): f.get("content") for f in e.get("fields", []) if isinstance(f, dict)}
            ts = _iso(e.get("timestamp"))
            text = e.get("text", "")
            key = f"{e.get('timestamp')}:{hash(text)}"
            if not self.seen.is_new(key):
                continue
            newest = max(newest, ts)
            host = fields.get("hostname") or fields.get("source") or ""
            out.append(LogEvent(source=self.source, connector=self.name, message=text,
                                severity=norm_severity(fields.get("severity") or fields.get("vmw_severity"), sev_from_text(text)),
                                host=host, entity=fields.get("appname", ""), ts=ts, kind="log",
                                attrs={k: v for k, v in fields.items() if k in ("appname", "vmw_product", "vc_details", "procid")}))
        self.since = newest
        return out

    async def checks(self):
        await self.login()
        return {"POST /api/v2/sessions": "ok",
                "GET /api/v2/sessions/current": await self._probe("GET", "/api/v2/sessions/current"),
                "GET /api/v2/events": await self._probe("GET", f"/api/v2/events/timestamp/{quote('>' + str(int((time.time() - 60) * 1000)))}",
                                                        params={"limit": 1})}


# ===================================================================== VCF Automation
class VcfAutomationConnector(Connector):
    """mode:
      provider — VCF Automation 9.x 프로바이더: POST /cloudapi/1.0.0/sessions/provider (Basic user@System)
                 → 응답 헤더 x-vmware-vcloud-access-token. GET /cloudapi/1.0.0/auditTrail (감사 이벤트)
      vmapps   — VCF Automation 9.x VM Apps Org: POST /tm/oauth/tenant/{org}/token (refresh_token)
                 → GET /deployment/api/deployments (배포 상태)
      aria8    — Aria Automation 8.x: /csp/gateway/am/api/login → /iaas/api/login → deployments
    """
    type = source = "vcfa"
    default_interval = 30

    async def login(self):
        mode = self.cfg.get("mode", "provider")
        if mode == "provider":
            ver = self.cfg.get("api_version", "9.0.0")
            self.http.headers["Accept"] = f"application/json;version={ver}"
            user = self.cfg["username"] if "@" in self.cfg["username"] else f"{self.cfg['username']}@System"
            r = await self.http.post("/cloudapi/1.0.0/sessions/provider", auth=(user, self.cfg["password"]))
            r.raise_for_status()
            tok = r.headers.get("x-vmware-vcloud-access-token")
            if not tok:
                raise RuntimeError("x-vmware-vcloud-access-token 헤더 없음")
            self.http.headers["Authorization"] = f"Bearer {tok}"
        elif mode == "vmapps":
            r = await self.http.post(f"/tm/oauth/tenant/{self.cfg['org']}/token",
                                     data={"grant_type": "refresh_token", "refresh_token": self.cfg["api_token"]},
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
            r.raise_for_status()
            self.http.headers["Authorization"] = f"Bearer {r.json()['access_token']}"
        else:
            r = await self.http.post("/csp/gateway/am/api/login", params={"access_token": ""},
                                     json={"username": self.cfg["username"], "password": self.cfg["password"]})
            r.raise_for_status()
            r2 = await self.http.post("/iaas/api/login", json={"refreshToken": r.json()["refresh_token"]})
            r2.raise_for_status()
            self.http.headers["Authorization"] = f"Bearer {r2.json()['token']}"

    async def poll(self):
        if self.cfg.get("mode", "provider") == "provider":
            return await self._audit()
        return await self._deployments()

    async def _audit(self):
        since = datetime.fromtimestamp(self.since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        r = await self.http.get("/cloudapi/1.0.0/auditTrail",
                                params={"filter": f"timestamp=gt={since}", "sortAsc": "timestamp", "pageSize": 128})
        r.raise_for_status()
        out = []
        newest = self.since
        for e in _items(r.json(), "values"):
            if not self.seen.is_new(str(e.get("eventId"))):
                continue
            ts = _iso(e.get("timestamp"))
            newest = max(newest, ts)
            status = str(e.get("eventStatus", ""))
            sev = "error" if status.upper() in ("FAILURE", "FAILED", "ERROR") else "info"
            ent = (e.get("eventEntity") or {}).get("name", "") if isinstance(e.get("eventEntity"), dict) else ""
            user = (e.get("owner") or {}).get("name", "") if isinstance(e.get("owner"), dict) else ""
            out.append(self.ev(f"{e.get('eventType')} {status} user={user} {e.get('details') or ''}"[:2000],
                               severity=sev, kind="event", entity=ent, ts=ts, native_id=str(e.get("eventId"))))
        self.since = newest
        return out

    async def _deployments(self):
        r = await self.http.get("/deployment/api/deployments",
                                params={"$orderby": "lastUpdatedAt desc", "$top": 100, "expand": "lastRequest"})
        r.raise_for_status()
        out = []
        for d in _items(r.json(), "content"):
            st = str(d.get("status", ""))
            if not self.seen.is_new(f"{d.get('id')}:{st}:{d.get('lastUpdatedAt')}"):
                continue
            ts = _iso(d.get("lastUpdatedAt"))
            if self.first_poll and ts < self.since:
                continue
            sev = "error" if "FAILED" in st else ("warning" if "INPROGRESS" in st and "DELETE" in st else "info")
            lr = d.get("lastRequest") or {}
            detail = lr.get("details") or ""
            out.append(self.ev(f"배포 '{d.get('name')}' 상태 {st} {detail}".strip(), severity=sev, kind="task",
                               entity=d.get("name", ""), ts=ts, native_id=str(d.get("id")),
                               attrs={"project": d.get("projectId"), "owner": d.get("ownedBy")}))
        return out

    async def checks(self):
        await self.login()
        mode = self.cfg.get("mode", "provider")
        res = {f"인증({mode})": "ok"}
        if mode == "provider":
            res["GET /cloudapi/1.0.0/auditTrail"] = await self._probe("GET", "/cloudapi/1.0.0/auditTrail", params={"pageSize": 1})
            res["GET /cloudapi/1.0.0/orgs"] = await self._probe("GET", "/cloudapi/1.0.0/orgs", params={"pageSize": 1})
        else:
            res["GET /deployment/api/deployments"] = await self._probe("GET", "/deployment/api/deployments", params={"$top": 1})
        return res


async def _nsx_backup(self) -> list[LogEvent]:
    """GET /api/v1/cluster/backups/overview — 백업 설정·일정·최근 클러스터/노드/인벤토리 백업 결과(비밀 필드는 응답에 없음)"""
    from .. import protection as PR
    now = time.time()
    try:
        r = await self.http.get("/api/v1/cluster/backups/overview")
        r.raise_for_status()
        self.protection = {**PR.nsx_overview(r.json(), now), "target": self.host}
    except Exception as e:  # noqa: BLE001
        self.protection = {"kind": "appliance_backup", "product": "NSX Manager", "target": self.host, "updated": now, "error": f"조회 불가: {type(e).__name__}: {e}"[:200]}
        return []
    v, why = PR.appliance_verdict(self.protection, now)
    if v == "bad" and self.seen.is_new(f"bkp:{v}:{(self.protection.get('last') or {}).get('end')}"):
        return [self.ev(f"NSX Manager 백업 문제 — {why}", severity="error", kind="health", entity=f"backup:nsx:{self.host}")]
    return []


NsxConnector._backup = _nsx_backup


# ===================================================================== SRM / VMware Live Site Recovery
class SrmConnector(Connector):
    """REST API Gateway (/api/rest/srm/v2). POST /session (Basic) → x-dr-session 헤더.
    pairings → (선택)remote-session → srms/{id}/issues, recovery-management/plans(+issues), protection-management/groups"""
    type = source = "srm"
    default_interval = 60

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.prefix = cfg.get("api_prefix", "/api/rest/srm/v2")

    async def login(self):
        r = await self.http.post(f"{self.prefix}/session", auth=(self.cfg["username"], self.cfg["password"]))
        r.raise_for_status()
        sid = r.json().get("session_id") or r.headers.get("x-dr-session")
        self.http.headers["x-dr-session"] = sid
        if self.cfg.get("remote_username"):
            for p in await self._pairings():
                await self.http.post(f"{self.prefix}/pairings/{p}/remote-session",
                                     auth=(self.cfg["remote_username"], self.cfg["remote_password"]))

    async def _pairings(self) -> list[str]:
        r = await self.http.get(f"{self.prefix}/pairings")
        r.raise_for_status()
        return [p.get("pairing_id") or p.get("id") for p in _items(r.json(), "list")]

    protection: dict[str, Any] | None = None       # 2.29.0 DR·보호 화면용 현황

    async def poll(self):
        from .. import protection as PR
        out: list[LogEvent] = []
        now = time.time()
        full = now - getattr(self, "_state_at", 0) > float(self.cfg.get("state_interval", 300))
        st: dict[str, Any] = {"kind": "srm", "pairings": [], "plans": [], "groups": [], "vms": [], "updated": now, "error": ""}
        rp = await self.http.get(f"{self.prefix}/pairings")
        rp.raise_for_status()
        pairs = _items(rp.json(), "list")
        for pr in pairs:
            st["pairings"].append({"id": pr.get("pairing_id") or pr.get("id"), "local_site": (pr.get("local_vc_server") or {}).get("name") or pr.get("local_site_name") or "",
                                   "remote_site": (pr.get("remote_vc_server") or {}).get("name") or pr.get("remote_site_name") or "",
                                   "local_srm": (pr.get("local_srm_server") or {}).get("name", "") if isinstance(pr.get("local_srm_server"), dict) else "",
                                   "remote_srm": (pr.get("remote_srm_server") or {}).get("name", "") if isinstance(pr.get("remote_srm_server"), dict) else "",
                                   "status": str((pr.get("remote_srm_server") or {}).get("connection_status") or pr.get("status") or "") if isinstance(pr.get("remote_srm_server"), dict) else str(pr.get("status") or "")})
        for pid in [p["id"] for p in st["pairings"]]:
            base = f"{self.prefix}/pairings/{pid}"
            # SRM 서버 이슈
            r = await self.http.get(f"{base}/srms")
            for s in _items(r.json(), "list") if r.status_code < 300 else []:
                sid = s.get("id")
                ri = await self.http.get(f"{base}/srms/{sid}/issues")
                for i in _items(ri.json(), "list") if ri.status_code < 300 else []:
                    out += self._issue(i, f"SRM {s.get('name') or sid}")
            # 복구 계획
            r = await self.http.get(f"{base}/recovery-management/plans")
            for p in _items(r.json(), "list") if r.status_code < 300 else []:
                pst = str(p.get("status") or p.get("state") or "")
                st["plans"].append({"pairing": pid, "id": p.get("id"), "name": p.get("name", ""), "status": pst, "verdict": PR.srm_status_verdict(pst),
                                    "location": p.get("location") or "", "protected_site": p.get("protected_site_name") or p.get("protected_site") or "",
                                    "groups": len(p.get("protection_groups") or [])})
                st_ = pst
                if self.seen.is_new(f"plan:{p.get('id')}:{st_}") and (not self.first_poll or st_.upper() not in ("READY", "PROTECTED")):
                    bad = any(w in st_.upper() for w in ("ERROR", "INCOMPLETE", "FAIL", "CANCEL", "DISCONNECT"))
                    out.append(self.ev(f"복구 계획 '{p.get('name')}' 상태 {st_}", severity="error" if bad else "info",
                                       kind="health", entity=p.get("name", "")))
                ri = await self.http.get(f"{base}/recovery-management/plans/{p.get('id')}/issues")
                for i in _items(ri.json(), "list") if ri.status_code < 300 else []:
                    out += self._issue(i, f"Recovery Plan {p.get('name')}")
            # 보호 그룹
            r = await self.http.get(f"{base}/protection-management/groups")
            for g in _items(r.json(), "list") if r.status_code < 300 else []:
                gst = str(g.get("protection_status") or g.get("status") or g.get("state") or "")
                grp = {"pairing": pid, "id": g.get("id"), "name": g.get("name", ""), "status": gst, "verdict": PR.srm_status_verdict(gst),
                       "replication": g.get("replication_type") or g.get("type") or "", "recovery_status": g.get("recovery_status") or "",
                       "protected_site": g.get("protected_site_name") or "", "location": g.get("location") or "", "vms": None, "vms_bad": 0}
                st["groups"].append(grp)
                if self.seen.is_new(f"pg:{g.get('id')}:{gst}") and (not self.first_poll or gst.upper() not in ("OK", "READY", "SHADOWING")):
                    bad = any(w in gst.upper() for w in ("ERROR", "NOT", "FAIL", "INCOMPLETE"))
                    out.append(self.ev(f"보호 그룹 '{g.get('name')}' 상태 {gst}", severity="error" if bad else "info",
                                       kind="health", entity=g.get("name", "")))
                if full and len(st["groups"]) <= int(self.cfg.get("max_groups_vms", 200)):
                    rv = await self.http.get(f"{base}/protection-management/groups/{g.get('id')}/virtual-machines")
                    if rv.status_code < 300:
                        vl = _items(rv.json(), "list")
                        grp["vms"] = len(vl)
                        for v in vl:
                            det = v.get("protection_status_details") or {}
                            vst = str(det.get("status") or v.get("protection_status") or v.get("status") or "")
                            vd = PR.srm_status_verdict(vst)
                            grp["vms_bad"] += vd == "bad"
                            st["vms"].append({"pairing": pid, "group": g.get("name", ""), "name": v.get("name", ""), "status": vst, "verdict": vd,
                                              "errors": "; ".join(str((e or {}).get("message") or e) for e in (det.get("errors") or [])[:2])[:200]})
        if full or not self.protection:
            self._state_at = now
            self.protection = st
        else:                                            # 보호 VM 목록은 5분마다 — 그 사이엔 계획·그룹 상태만 갱신
            for g in st["groups"]:
                old = next((x for x in self.protection.get("groups", []) if x["id"] == g["id"]), None)
                if old:
                    g["vms"], g["vms_bad"] = old.get("vms"), old.get("vms_bad", 0)
            self.protection = {**st, "vms": self.protection.get("vms", [])}
        return out

    def _issue(self, i: dict, scope: str) -> list[LogEvent]:
        key = f"issue:{i.get('id') or i.get('description')}:{i.get('severity')}"
        if not self.seen.is_new(key):
            return []
        return [self.ev(f"{scope}: {i.get('description') or i.get('message') or i}",
                        severity=norm_severity(i.get("severity"), "warning"), kind="alarm", entity=scope)]

    async def checks(self):
        await self.login()
        res = {f"POST {self.prefix}/session": "ok"}
        try:
            ps = await self._pairings()
            res["GET /pairings"] = f"ok ({len(ps)}개)"
            for pid in ps[:1]:
                res["GET recovery-management/plans"] = await self._probe("GET", f"{self.prefix}/pairings/{pid}/recovery-management/plans")
        except Exception as e:  # noqa: BLE001
            res["GET /pairings"] = str(e)[:200]
        return res


# ===================================================================== Avi Load Balancer
def aggregate_app_logs(logs: list[dict], minutes: int = 60) -> dict[str, Any]:
    """Avi 애플리케이션 로그 표본 → End user 지표(클라이언트·OS·브라우저·기기·위치·응답코드·URI·도메인·서버·지연·바이트)"""
    from collections import Counter
    top = lambda c, n=10: [{"k": k or "(미상)", "n": v} for k, v in c.most_common(n)]   # noqa: E731
    ip, os_, br, dev, loc, code, uri, host, srv, meth, ssl = (Counter() for _ in range(11))
    by_ip: dict[str, dict] = {}
    tt, rtt, req_b, resp_b, sig = [], [], 0, 0, 0
    first = last = None
    for x in logs:
        c = str(x.get("client_ip") or "")
        ip[c] += 1
        os_[str(x.get("client_os") or "")] += 1
        br[str(x.get("client_browser") or "")] += 1
        dev[str(x.get("client_device") or "")] += 1
        loc[str(x.get("client_location") or "")] += 1
        rc = x.get("response_code")
        code[f"{str(rc)[0]}xx" if rc else "연결(L4)"] += 1
        if x.get("uri_path"):
            uri[str(x.get("uri_path"))[:120]] += 1
        if x.get("host"):
            host[str(x.get("host"))[:120]] += 1
        if x.get("server_ip"):
            srv[f"{x.get('server_name') or x.get('server_ip')}"] += 1
        if x.get("method"):
            meth[str(x.get("method"))] += 1
        if x.get("ssl_version"):
            ssl[str(x.get("ssl_version"))] += 1
        t = x.get("total_time")
        if isinstance(t, (int, float)):
            tt.append(float(t))
        if isinstance(x.get("client_rtt"), (int, float)):
            rtt.append(float(x["client_rtt"]))
        rq, rs = int(x.get("request_length") or 0), int(x.get("response_length") or 0)
        req_b += rq
        resp_b += rs
        sig += 1 if x.get("significant") else 0
        d = by_ip.setdefault(c, {"ip": c, "n": 0, "bytes": 0, "err": 0, "t": 0.0, "os": x.get("client_os", ""), "browser": x.get("client_browser", ""),
                                 "location": x.get("client_location", "")})
        d["n"] += 1
        d["bytes"] += rq + rs
        d["err"] += 1 if rc and int(rc) >= 400 else 0
        d["t"] += float(t) if isinstance(t, (int, float)) else 0.0
        ts = str(x.get("report_timestamp") or "")
        if ts:
            first = min(first or ts, ts)
            last = max(last or ts, ts)
    tt.sort()
    pct = lambda a, q: round(a[min(len(a) - 1, int(len(a) * q))], 1) if a else None   # noqa: E731
    tops = sorted(by_ip.values(), key=lambda d: (-d["n"], -d["bytes"]))[:15]
    for d in tops:
        d["avg_ms"] = round(d.pop("t") / d["n"], 1) if d["n"] else None
    return {"minutes": minutes, "logs": len(logs), "unique_clients": len([k for k in ip if k]), "significant": sig,
            "req_bytes": req_b, "resp_bytes": resp_b, "latency_ms": {"avg": round(sum(tt) / len(tt), 1) if tt else None, "p50": pct(tt, 0.5),
                                                                     "p95": pct(tt, 0.95), "p99": pct(tt, 0.99)},
            "client_rtt_ms": round(sum(rtt) / len(rtt), 1) if rtt else None, "first": first, "last": last,
            "top_clients": tops, "os": top(os_), "browser": top(br), "device": top(dev), "location": top(loc), "codes": top(code),
            "uris": top(uri), "hosts": top(host), "servers": top(srv), "methods": top(meth), "ssl": top(ssl)}


class AviConnector(Connector):
    """NSX Advanced Load Balancer(Avi). POST /login → 쿠키(sessionid, csrftoken). 헤더 X-Avi-Version, X-CSRFToken, Referer.
    GET /api/alert, /api/analytics/logs?type=2(이벤트), /api/virtualservice-inventory, /api/serviceengine-inventory"""
    type = source = "avi"
    default_interval = 20

    async def login(self):
        r = await self.http.post("/login", json={"username": self.cfg["username"], "password": self.cfg["password"]})
        r.raise_for_status()
        ver = self.cfg.get("api_version") or (r.json().get("version") or {}).get("Version", "")
        self.version = str((r.json().get("version") or {}).get("Version", "") or ver or "")
        if ver:
            self.http.headers["X-Avi-Version"] = ver
        csrf = self.http.cookies.get("csrftoken")
        if csrf:
            self.http.headers["X-CSRFToken"] = csrf
        self.http.headers["Referer"] = self.base_url
        if self.cfg.get("tenant"):
            self.http.headers["X-Avi-Tenant"] = self.cfg["tenant"]
        self._learned = False                               # 재로그인(업그레이드 등) 뒤 거부 지표 다시 판단
        self._bad_metrics = set()

    async def _list(self, path: str, **params) -> tuple[int, list[dict]]:
        """Avi 목록 — page_size 최대 200(API 제한), next 링크로 이어서. 테넌트 미지정이면 X-Avi-Tenant: * 로 전체 테넌트."""
        out, page, code = [], 1, 0
        hdr = {"X-Avi-Tenant": "*"} if not self.cfg.get("tenant") and self.cfg.get("all_tenants", True) else None
        for _ in range(50):
            r = await self.http.get(path, params={"page_size": 200, "page": page, "include_name": "true", **params}, headers=hdr)
            code = r.status_code
            if code == 400 and hdr:                            # 전체 테넌트 조회 미허용 → 기본 테넌트
                hdr = None
                r = await self.http.get(path, params={"page_size": 200, "page": page, "include_name": "true", **params})
                code = r.status_code
            if code == 400 and "include" in params:            # include 미지원 버전 → 기본 필드
                params = {k: v for k, v in params.items() if k != "include"}
                r = await self.http.get(path, params={"page_size": 200, "page": page, "include_name": "true", **params}, headers=hdr)
                code = r.status_code
            if code >= 300:
                if code in (401, 403, 419):
                    r.raise_for_status()
                return code, out
            j = r.json() or {}
            out += _items(j, "results")
            if not j.get("next") or len(out) >= int(j.get("count") or 0):
                break
            page += 1
        return code, out

    async def poll(self):
        out: list[LogEvent] = []
        code, alerts = await self._list("/api/alert", sort="-timestamp")
        if code >= 300:
            self._state["checks"]["알람(/api/alert)"] = f"warn: HTTP {code}"
        for a in alerts:
            if not self.seen.is_new(str(a.get("uuid"))):
                continue
            ts = _iso(a.get("timestamp"))
            if self.first_poll and ts < self.since:
                continue
            out.append(self.ev(f"{a.get('summary') or a.get('description') or a.get('name')}",
                               severity=norm_severity(a.get("level"), "warning"), kind="alert",
                               entity=a.get("obj_name", ""), ts=ts, native_id=str(a.get("uuid"))))
        out += await self._events()
        if time.time() - getattr(self, "_pool_at", 0) > float(self.cfg.get("inventory_interval", 300)):
            self._pool_at = time.time()
            try:
                code, pools = await self._list("/api/pool-inventory")
                if code < 300:
                    self.pools = [{"name": (o.get("config") or {}).get("name", ""), "state": ((o.get("runtime") or {}).get("oper_status") or {}).get("state", ""),
                                   "uuid": (o.get("config") or {}).get("uuid") or o.get("uuid", ""),
                                   # 이 풀을 쓰는 VS·풀 그룹(PoolInventory.virtualservices·poolgroups) — pool_ref 가 없는 VS(AKO L4·풀 그룹·L4 정책) 연결용
                                   "vs_uuids": [str(x).split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1] for x in (o.get("virtualservices") or [])],
                                   "poolgroups": [str(x).rsplit("#", 1)[-1] if "#" in str(x) else str(x).rsplit("/", 1)[-1] for x in (o.get("poolgroups") or [])],
                                   "servers": (o.get("runtime") or {}).get("num_servers") or len((o.get("config") or {}).get("servers") or []),
                                   "up": (o.get("runtime") or {}).get("num_servers_up"),
                                   "health": (o.get("health_score") or {}).get("health_score"),
                                   # 풀 멤버(Server: ip.addr·port·hostname·enabled) — 논리 토폴로지·흐름도에서 VM·Pod IP 와 연결
                                   "members": [{"ip": ((x.get("ip") or {}).get("addr") or ""), "port": x.get("port"), "hostname": x.get("hostname", ""),
                                                "enabled": x.get("enabled", True)} for x in ((o.get("config") or {}).get("servers") or [])][:256]}
                                  for o in pools]
            except Exception:  # noqa: BLE001
                pass
        if not hasattr(self, "inventory"):
            self.inventory = {}
        if not hasattr(self, "se"):
            self.se = {}
        ref = lambda v: str(v or "").rsplit("#", 1)[-1] if "#" in str(v or "") else ""   # noqa: E731  (include_name=true → "…#이름")
        # 2.4 컨트롤러 클러스터 — GET /api/cluster/runtime (node_states[].name·role·state, cluster_state.state)
        if time.time() - getattr(self, "_ctrl_at", 0) > float(self.cfg.get("inventory_interval", 300)):
            self._ctrl_at = time.time()
            try:
                rc = await self.http.get("/api/cluster/runtime")
                if rc.status_code < 300:
                    j = rc.json() or {}
                    self.controllers = {"state": (j.get("cluster_state") or {}).get("state", ""), "version": getattr(self, "version", ""),
                                        "nodes": [{"name": n.get("name", ""), "role": n.get("role", ""), "state": n.get("state", ""), "ip": (n.get("mgmt_ip") or {}).get("addr", "")
                                                   if isinstance(n.get("mgmt_ip"), dict) else str(n.get("mgmt_ip") or "")} for n in (j.get("node_states") or [])][:7]}
                    self._state["checks"]["컨트롤러 클러스터(/api/cluster/runtime)"] = f"ok {self.controllers['state']} · 노드 {len(self.controllers['nodes'])}"
                else:
                    self._state["checks"]["컨트롤러 클러스터(/api/cluster/runtime)"] = f"warn: HTTP {rc.status_code}"
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["컨트롤러 클러스터(/api/cluster/runtime)"] = f"warn: {type(e).__name__}"
        # Service Engine — 상태·SE 그룹·실행 호스트(host_ref = vCenter 호스트)·관리 IP
        code, ses = await self._list("/api/serviceengine-inventory", include="config,runtime,health_score")
        self._state["checks"]["Service Engine(/api/serviceengine-inventory)"] = f"ok {len(ses)}개" if code < 300 else f"warn: HTTP {code} — 계정 역할의 Service Engine 읽기 권한 확인"
        seen_se = set()
        for o in ses:
            cfg, rt = o.get("config") or {}, o.get("runtime") or {}
            name = cfg.get("name", "") or o.get("uuid", "")
            st = (rt.get("oper_status") or {}).get("state", "")
            if not st and rt.get("se_connected") is not None:
                st = "OPER_UP" if rt.get("se_connected") else "OPER_DOWN"
            seen_se.add(name)
            mip = ""
            for vn in ((cfg.get("mgmt_vnic") or {}).get("vnic_networks") or []):
                mip = (((vn.get("ip") or {}).get("ip_addr") or {}).get("addr")) or mip
            self.se[name] = {"name": name, "uuid": cfg.get("uuid") or o.get("uuid", ""), "state": st, "se_group": ref(cfg.get("se_group_ref")),
                             "host": ref(cfg.get("host_ref")), "cloud": ref(cfg.get("cloud_ref")), "mgmt_ip": mip,
                             "power": rt.get("power_state", ""), "health": (o.get("health_score") or {}).get("health_score"),
                             "vs": self.se.get(name, {}).get("vs", [])}
            self.inventory[("SE", name)] = st
            if st and self.seen.is_new(f"se:{name}:{st}") and (st != "OPER_UP" or not self.first_poll):
                reason = ";".join((rt.get("oper_status") or {}).get("reason", []) or [])
                out.append(self.ev(f"Service Engine {name} oper_status={st} {reason}".strip(), severity="info" if st == "OPER_UP" else "critical",
                                   kind="health", entity=name, attrs={"se_group": self.se[name]["se_group"], "esxi": self.se[name]["host"]}))
        if code < 300:
            for k in [k for k in self.se if k not in seen_se]:
                self.se.pop(k, None)
                self.inventory.pop(("SE", k), None)
        # 가상 서비스 — 상태·VIP·풀·SE 배치(vip_summary[].service_engine[])
        code, vss = await self._list("/api/virtualservice-inventory", include="config,runtime,health_score")
        self._state["checks"]["가상 서비스(/api/virtualservice-inventory)"] = f"ok {len(vss)}개" if code < 300 else f"warn: HTTP {code}"
        se_vs: dict[str, list[str]] = {}
        for o in vss:
            name = (o.get("config") or {}).get("name", "")
            st = ((o.get("runtime") or {}).get("oper_status") or {}).get("state", "")
            self.inventory[("VS", name)] = st
            self._vs_meta(o, name, st)
            ses_of = []
            for vsum in ((o.get("runtime") or {}).get("vip_summary") or []):
                for se in vsum.get("service_engine") or []:
                    n = ref(se.get("url")) or ref(se.get("se_ref")) or se.get("uuid", "")
                    if n and n not in ses_of:
                        ses_of.append(n)
                        se_vs.setdefault(n, []).append(name)
            if hasattr(self, "vs"):
                u = (o.get("config") or {}).get("uuid") or o.get("uuid") or name
                if u in self.vs:
                    self.vs[u]["ses"] = ses_of
            if st and self.seen.is_new(f"/api/virtualservice-inventory:{name}:{st}") and (st != "OPER_UP" or not self.first_poll):
                reason = ";".join(((o.get("runtime") or {}).get("oper_status") or {}).get("reason", []) or [])
                out.append(self.ev(f"Virtual Service {name} oper_status={st} {reason}".strip(), severity="info" if st == "OPER_UP" else "error",
                                   kind="health", entity=name))
        for n, lst in se_vs.items():
            if n in self.se:
                self.se[n]["vs"] = lst[:50]
        return out

    # ---------------------------------------------------------------- VIP(가상 서비스)별 실시간 트래픽
    # 수집: POST /api/analytics/metrics/collection (metric_requests, entity_uuid="*") — 실패 시 VS 별
    #       GET /api/analytics/metrics/virtualservice/{uuid}?metric_id=..&step=5&limit=N
    # step=5 는 VS 실시간 메트릭(analytics_policy.metrics_realtime_update)이 켜진 경우에만 값이 있으므로 비면 step=300 으로 내려감
    VIP_METRICS = {"l4_client.avg_bandwidth": "bw", "l4_client.avg_complete_conns": "cps", "l7_client.avg_complete_responses": "rps",
                   "l4_client.avg_total_rtt": "rtt", "l7_client.avg_error_responses": "err", "l4_client.avg_open_conns": "open",
                   # 처리량 상세(1.12) — Avi 메트릭 목록의 l4_client·l7_client 지표
                   "l4_client.avg_rx_bytes": "rx", "l4_client.avg_tx_bytes": "tx", "l4_client.avg_rx_pkts": "rxp", "l4_client.avg_tx_pkts": "txp",
                   "l4_client.avg_new_established_conns": "newc", "l4_client.max_open_conns": "maxopen", "l4_client.avg_connections_dropped": "drop",
                   "l7_client.avg_resp_2xx": "r2xx", "l7_client.avg_resp_4xx": "r4xx", "l7_client.avg_resp_5xx": "r5xx",
                   "l7_client.avg_ssl_handshakes_new": "sslnew", "l7_client.avg_ssl_errors": "sslerr",
                   "l7_client.avg_client_txn_latency": "txlat", "l7_client.apdexr": "apdex", "l7_client.pct_response_errors": "errpct"}
    THROUGHPUT_KEYS = ("bw", "rx", "tx", "rxp", "txp", "cps", "newc", "open", "maxopen", "drop", "rps", "r2xx", "r4xx", "r5xx", "err", "errpct",
                       "sslnew", "sslerr", "rtt", "txlat", "apdex")

    def _vs_meta(self, o: dict, name: str, st: str) -> None:
        if not hasattr(self, "vs"):
            self.vs = {}
        cfg = o.get("config") or {}
        uuid = cfg.get("uuid") or o.get("uuid") or name
        vips = []
        for v in (cfg.get("vip") or []) + (((o.get("vsvip") or {}).get("config") or {}).get("vip") or []):
            a = ((v.get("ip_address") or {}).get("addr")) or ((v.get("floating_ip") or {}).get("addr"))
            if a and a not in vips:
                vips.append(a)
        rt = o.get("runtime") or {}
        for v in rt.get("vip_summary") or []:
            a = ((v.get("ip_address") or {}).get("addr"))
            if a and a not in vips:
                vips.append(a)
        ports = sorted({int(x.get("port")) for x in (cfg.get("services") or []) if x.get("port")})
        hs = (o.get("health_score") or {}).get("health_score")
        cur = self.vs.get(uuid, {})
        tref = str(cfg.get("tenant_ref") or "")
        tenant = tref.rsplit("#", 1)[-1] if "#" in tref else ""
        tenant_uuid = tref.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1] if "/api/tenant/" in tref else ""
        self.vs[uuid] = {**cur, "uuid": uuid, "name": name, "state": st, "vips": vips, "ports": ports,
                         "tenant": tenant or cur.get("tenant", ""), "tenant_uuid": tenant_uuid or cur.get("tenant_uuid", ""),
                         "health": round(hs) if isinstance(hs, (int, float)) else cur.get("health"),
                         "pool": (str(cfg.get("pool_ref", "")).rsplit("#", 1)[-1] if "#" in str(cfg.get("pool_ref", "")) else ""),
                         "pool_group": (str(cfg.get("pool_group_ref", "")).rsplit("#", 1)[-1] if "#" in str(cfg.get("pool_group_ref", "")) else ""),
                         "se_group": str(cfg.get("se_group_ref", "")).rsplit("#", 1)[-1] if "#" in str(cfg.get("se_group_ref", "")) else "",
                         "metrics": cur.get("metrics", {}), "updated": cur.get("updated", 0)}

    def _parse_series(self, lst, into: dict) -> int:
        n = 0
        for x in lst or []:
            mid = (x.get("header") or {}).get("name", "")
            if mid in self.VIP_METRICS:
                vals = [d.get("value") for d in (x.get("data") or [])]
                into[self.VIP_METRICS[mid]] = vals
                n += sum(1 for v in vals if v is not None)
        return n

    def _metric_groups(self) -> list[list[str]]:
        """요청을 L4(l4_client.*)·L7(l7_client.*) 묶음으로 나눔 — L4 VS·구버전 컨트롤러에서 L7 지표가 거부(400)돼도 L4 값은 받도록.
        컨트롤러가 거부한 지표(_bad_metrics)는 빼고 요청."""
        bad = getattr(self, "_bad_metrics", set())
        l4 = [m for m in self.VIP_METRICS if m.startswith("l4_") and m not in bad]
        l7 = [m for m in self.VIP_METRICS if not m.startswith("l4_") and m not in bad]
        return [g for g in (l4, l7) if g]

    async def _learn_bad_metrics(self, v: dict, ids: list[str], step: int) -> set[str]:
        """400 이 난 묶음을 지표 하나씩 다시 물어 컨트롤러가 모르는 metric_id 를 찾는다(연결당 1회, 결과는 점검 화면에 표시).
        모든 지표가 400 이면 지표 문제가 아니므로(권한·step·버전) 표시하지 않는다."""
        t = v.get("tenant") or self.cfg.get("tenant") or "admin"
        bad: set[str] = set()
        for m in ids:
            try:
                r = await self.http.get(f"/api/analytics/metrics/virtualservice/{v['uuid']}", headers={"X-Avi-Tenant": t},
                                        params={"metric_id": m, "step": step, "limit": 1})
            except httpx.HTTPError:
                return set()
            if r.status_code == 400:
                bad.add(m)
        if bad and len(bad) < len(ids):
            self._bad_metrics = getattr(self, "_bad_metrics", set()) | bad
            return bad
        return set()

    async def vip_metrics(self) -> None:
        """VIP 별 트래픽 — 엔진의 avi-metrics 루프가 metrics_interval(기본 10초)마다 호출.
        가상 서비스는 테넌트에 속하므로 테넌트별로 X-Avi-Tenant 헤더를 붙여 조회한다(admin 컨텍스트로는 다른 테넌트 VS 메트릭이 비어 옴).
        ① POST /api/analytics/metrics/collection (entity_uuid="*", 테넌트·지표 묶음별) → ② 값이 없는 VS 만 GET /api/analytics/metrics/virtualservice/{uuid}
        step=5(실시간)가 비면 같은 주기에 step=300(5분 평균)으로 다시 조회.
        2.1.1: 지표를 L4·L7 묶음으로 나눠 요청(한 지표 거부로 전체가 400 이 되던 문제), 거부 지표 자동 제외,
               응답은 정상인데 값이 없는 VS 는 '유휴(트래픽 없음)'로 구분, VS 별 상태(mstate)·사유를 화면에 표시."""
        vs = getattr(self, "vs", {})
        if not vs:
            return
        limit = int(self.cfg.get("metrics_points", 12))
        diag: dict[str, Any] = {"tenants": 0, "with_data": 0, "idle": 0, "empty": 0, "http": {}, "error": "", "method": "", "step": None,
                                "bad_metrics": sorted(getattr(self, "_bad_metrics", set()))}
        by_t: dict[str, list[dict]] = {}
        for v in vs.values():
            by_t.setdefault(v.get("tenant") or self.cfg.get("tenant") or "admin", []).append(v)
        diag["tenants"] = len(by_t)
        series: dict[str, dict[str, list]] = {}
        counts: dict[str, int] = {}
        answered: set[str] = set()                     # 200 으로 응답했고 지표 머리(header)가 온 VS — 값이 없으면 유휴
        errs: dict[str, str] = {}                      # VS 별 마지막 실패 사유

        def note_http(code: int, where: str, body: str = "") -> None:
            k = str(code)
            diag["http"][k] = diag["http"].get(k, 0) + 1
            if code >= 300 and not diag["error"]:
                diag["error"] = f"{where} HTTP {code} {body[:120]}".strip()

        gcount: dict[str, int] = {}                    # 이번 지표 묶음에서 값을 받은 VS — 묶음마다 빈 VS 만 개별 조회

        gans: set[str] = set()                         # 이번 묶음에서 응답(머리)이 온 VS — 값이 없어도 다시 묻지 않음(L4 VS 의 L7 지표 등)

        def take(uuid: str, lst) -> None:
            if lst:
                answered.add(uuid)
                gans.add(uuid)
            m = series.setdefault(uuid, {})
            n = self._parse_series(lst, m)
            counts[uuid] = counts.get(uuid, 0) + n
            gcount[uuid] = gcount.get(uuid, 0) + n

        async def collect(tenant: str, step: int, ids: list[str]) -> int:
            try:
                r = await self.http.post("/api/analytics/metrics/collection", headers={"X-Avi-Tenant": tenant},
                                         json={"metric_requests": [{"id": "vip", "entity_uuid": "*", "metric_id": ",".join(ids), "step": step, "limit": limit,
                                                                    "pad_missing_data": False}]})
            except httpx.HTTPError as e:
                diag["error"] = diag["error"] or f"collection {type(e).__name__}"
                return 0
            if r.status_code in (401, 419):
                r.raise_for_status()
            note_http(r.status_code, f"collection[{tenant}]", r.text if r.status_code >= 300 else "")
            if r.status_code >= 300:
                return r.status_code
            ser = (r.json() or {}).get("series") or {}
            ser = ser.get("vip", ser) if isinstance(ser, dict) else {}
            for uuid, lst in (ser.items() if isinstance(ser, dict) else []):
                if uuid in vs:
                    take(uuid, lst)
            return r.status_code

        async def per_vs(v: dict, step: int, ids: list[str], sem: asyncio.Semaphore) -> int:
            async with sem:
                t = v.get("tenant") or self.cfg.get("tenant") or "admin"
                try:
                    r = await self.http.get(f"/api/analytics/metrics/virtualservice/{v['uuid']}", headers={"X-Avi-Tenant": t},
                                            params={"metric_id": ",".join(ids), "step": step, "limit": limit, "pad_missing_data": "false"})
                except httpx.HTTPError as e:
                    errs[v["uuid"]] = f"{type(e).__name__}"
                    diag["error"] = diag["error"] or f"virtualservice {type(e).__name__}"
                    return 0
                if r.status_code in (401, 419):
                    r.raise_for_status()
                note_http(r.status_code, f"virtualservice[{v['name']}@{t}]", r.text if r.status_code >= 300 else "")
                if r.status_code < 300:
                    take(v["uuid"], (r.json() or {}).get("series"))
                else:
                    errs[v["uuid"]] = f"HTTP {r.status_code} {r.text[:100]}".strip()
                return r.status_code

        base_step = int(getattr(self, "_metrics_step", 5))
        steps = [base_step] + ([300] if base_step == 5 else [])
        used = steps[0]
        for step in steps:
            series.clear(); counts.clear(); answered.clear(); errs.clear()
            used = step
            for ids in self._metric_groups():
                rejected = False
                gcount.clear()
                gans.clear()
                for t in by_t:
                    if await collect(t, step, ids) == 400:
                        rejected = True
                missing = [v for v in vs.values() if not gcount.get(v["uuid"]) and v["uuid"] not in gans]
                if missing:
                    top = sorted(missing, key=lambda v: (v.get("state") != "OPER_UP", v["name"]))[: int(self.cfg.get("metrics_max_vs", 40))]
                    sem = asyncio.Semaphore(6)
                    codes = await asyncio.gather(*[per_vs(v, step, ids, sem) for v in top], return_exceptions=False)
                    rejected = rejected or (codes and all(c == 400 for c in codes))
                    diag["method"] = "collection+virtualservice" if len(missing) < len(vs) else "virtualservice"
                else:
                    diag["method"] = diag["method"] or "collection"
                if rejected and not getattr(self, "_learned", False):
                    self._learned = True                 # 연결(로그인)당 1회 — 거부 지표를 찾아 다음 주기부터 제외
                    bad = await self._learn_bad_metrics(next(iter(vs.values())), ids, step)
                    if bad:
                        diag["bad_metrics"] = sorted(getattr(self, "_bad_metrics", set()))
                        print(f"[avi:{self.name}] 컨트롤러가 거부한 메트릭 제외: {', '.join(sorted(bad))}", flush=True)
            if any(counts.values()):
                break
        if used == 300 and base_step == 5 and any(counts.values()):
            self._metrics_step = 300                     # 실시간 메트릭 꺼짐 → 5분 평균으로 고정(다음부터 바로)
        diag["step"] = used
        now = time.time()
        for uuid, v in vs.items():
            if counts.get(uuid):
                v.update(metrics=series.get(uuid, {}), updated=now, step=used, mnote="", mstate="ok")
            elif uuid in answered:                       # 응답은 정상 — 기간 안에 데이터 점이 없음(트래픽 없음)
                v.update(metrics={}, updated=now, step=used, mstate="idle",
                         mnote=f"최근 {limit * used // 60}분 트래픽 기록 없음 — 컨트롤러 응답은 정상(유휴 VS 이거나 SE 메트릭 미보고)")
            else:
                v["mstate"] = "error" if (errs.get(uuid) or diag["error"]) else "nodata"
                e1 = errs.get(uuid, "")
                v["mnote"] = (" · ".join(x for x in (e1, diag["error"] if diag["error"] and diag["error"] not in e1 else "") if x) or
                              "메트릭 응답에 이 VS 가 없음 — VS 분석(analytics_policy)·계정 테넌트 권한·SE 메트릭 수집 상태 확인")
        diag["with_data"] = sum(1 for v in vs.values() if v.get("mstate") == "ok")
        diag["idle"] = sum(1 for v in vs.values() if v.get("mstate") == "idle")
        diag["empty"] = len(vs) - diag["with_data"] - diag["idle"]
        self.metrics_diag = diag
        self._metrics_at = now
        st = (f"ok 값 {diag['with_data']}·유휴 {diag['idle']}·실패 {diag['empty']} / {len(vs)} VS · {'5초 실시간' if used == 5 else '5분 평균'} · {diag['method']} · 테넌트 {diag['tenants']}"
              if diag["with_data"] or diag["idle"] else f"실패: 값 있는 VS 0/{len(vs)} · {diag['method']} · HTTP {diag['http']} · {diag['error'] or '응답에 값 없음'}")
        if diag["bad_metrics"]:
            st += f" · 컨트롤러 미지원 지표 제외 {len(diag['bad_metrics'])}개"
        if diag["with_data"] and used == 300:
            st += " — VS 분석 정책의 실시간 메트릭(metrics_realtime_update)을 켜면 5초 단위"
        self._state.setdefault("checks", {})["VIP 메트릭"] = st[:300]

    # ---------------------------------------------------------------- End user(클라이언트) 분석 — 애플리케이션 로그 표본 집계
    # GET /api/analytics/logs?type=1&virtualservice=<uuid>&duration=<초>&page_size=N (type=1 = VS 애플리케이션 로그, Broadcom KB 408754)
    # 로그 필드(ApplicationLog): client_ip·client_os·client_browser·client_device·client_location·response_code·method·uri_path·host·
    #   total_time·request_length·response_length·client_rtt·server_ip·server_name·ssl_version·significant
    # 비중요(non-significant) 로그까지 받으려면 VS 분석 정책에서 전체 클라이언트 로그(full client logs)를 켜야 한다.
    async def end_users(self, uuid: str, minutes: int = 60, limit: int = 1000) -> dict[str, Any]:
        v = getattr(self, "vs", {}).get(uuid)
        if not v:
            raise KeyError(uuid)
        cache = getattr(self, "_eu_cache", {})
        key = (uuid, minutes, limit)
        if key in cache and time.time() - cache[key]["ts"] < 60:
            return cache[key]["data"]
        tenant = v.get("tenant") or self.cfg.get("tenant") or "admin"
        base = {"type": 1, "virtualservice": uuid, "duration": int(minutes * 60), "page_size": int(min(max(limit, 50), 10000))}
        r = await self.http.get("/api/analytics/logs", params={**base, "nf": "true", "udf": "true"}, headers={"X-Avi-Tenant": tenant})
        if r.status_code == 400:                           # 비중요·사용자 정의 필터 인자 미지원 버전 → 기본 조회
            r = await self.http.get("/api/analytics/logs", params=base, headers={"X-Avi-Tenant": tenant})
        if r.status_code in (401, 419):
            r.raise_for_status()
        if r.status_code >= 300:
            return {"uuid": uuid, "name": v.get("name"), "error": f"HTTP {r.status_code} {r.text[:160]}", "logs": 0}
        j = r.json() or {}
        data = aggregate_app_logs(_items(j, "results"), minutes)
        data.update(uuid=uuid, name=v.get("name"), tenant=tenant, total_reported=j.get("count"), vips=v.get("vips"), ports=v.get("ports"))
        if not data["logs"]:
            data["note"] = ("최근 로그 없음 — 트래픽이 없거나 VS 분석 정책(analytics_policy)의 클라이언트 로그 수집이 꺼져 있음"
                            "(전체 로그: full_client_logs 활성화). 중요(significant) 로그만 남는 경우 오류 요청만 보입니다.")
        cache[key] = {"ts": time.time(), "data": data}
        if len(cache) > 200:
            cache.pop(next(iter(cache)))
        self._eu_cache = cache
        return data

    def vs_pools(self, v: dict) -> list[dict]:
        """VS 가 쓰는 풀 — ① pool_ref ② 풀 인벤토리의 virtualservices 역참조 ③ pool_group_ref 의 풀 ④ 이름 접두(AKO: '<VS 이름>-<프로토콜>-<포트>')"""
        pools = getattr(self, "pools", []) or []
        hit = [p for p in pools if v.get("pool") and p.get("name") == v["pool"]]
        hit += [p for p in pools if v.get("uuid") in (p.get("vs_uuids") or []) and p not in hit]
        if v.get("pool_group"):
            hit += [p for p in pools if v["pool_group"] in (p.get("poolgroups") or []) and p not in hit]
        if not hit and v.get("name"):
            hit = [p for p in pools if str(p.get("name", "")).startswith(v["name"] + "-")]
        return hit

    def vips(self) -> list[dict[str, Any]]:
        out = []
        for v in getattr(self, "vs", {}).values():
            m = v.get("metrics") or {}
            last = {k: next((x for x in reversed(vals) if x is not None), None) for k, vals in m.items()}
            pls = self.vs_pools(v)
            members = [dict(x, pool=p["name"]) for p in pls for x in (p.get("members") or [])][:256]
            out.append({**{k: v.get(k) for k in ("uuid", "name", "state", "vips", "ports", "health", "se_group", "updated", "step", "tenant", "mnote", "mstate", "ses", "pool_group")},
                        "pool": v.get("pool") or ", ".join(p["name"] for p in pls)[:200],
                        "series": m, "last": last, "connector": self.name, "controller": self.host,
                        "avg": {k: round(sum(x for x in vals if x is not None) / max(1, sum(1 for x in vals if x is not None)), 3)
                                for k, vals in m.items() if any(x is not None for x in vals)},
                        "members": members, "pool_up": sum(p.get("up") or 0 for p in pls) if pls else None,
                        "pool_servers": sum(p.get("servers") or 0 for p in pls) if pls else None})
        return sorted(out, key=lambda x: -(x["last"].get("bw") or 0))

    def entities(self):
        m = {"OPER_UP": "ok", "OPER_DOWN": "down", "OPER_DISABLED": "maint", "OPER_INACTIVE": "maint",
             "OPER_RESOURCES": "warn", "OPER_PARTITIONED": "warn", "OPER_PROCESSING": "warn", "OPER_INITIALIZING": "warn"}
        inv = getattr(self, "inventory", {})
        return [{"name": n, "kind": k, "state": m.get(v, "warn" if v else "unknown"), "detail": v}
                for (k, n), v in sorted(inv.items(), key=lambda x: (x[0][0] != "SE", x[0][1]))][:150]

    async def _events(self) -> list[LogEvent]:
        """이벤트 로그: GET /api/analytics/logs?type=2&duration=… (Avi Monitoring & Operability Guide).
        Controller·SE·VS·Pool·GSLB·인증서·클러스터 이벤트 — 알람으로 승격되지 않은 것까지 수집."""
        if not self.cfg.get("events", True):
            return []
        dur = int(min(3600, max(60, (time.time() - self.since) + 30))) if not self.first_poll else int(self.cfg.get("backfill_seconds", 600))
        r = await self.http.get("/api/analytics/logs", params={"type": 2, "duration": dur, "page_size": 1000})
        if r.status_code >= 300:
            self._state["checks"]["이벤트 로그"] = f"HTTP {r.status_code}"
            return []
        out = []
        newest = self.since
        for e in _items(r.json(), "results"):
            eid = str(e.get("report_timestamp")) + ":" + str(e.get("event_id")) + ":" + str(e.get("obj_uuid", ""))
            if not self.seen.is_new(f"ev:{eid}"):
                continue
            rt = str(e.get("report_timestamp") or "")
            ts = _iso(rt + "Z" if rt and "T" in rt and not rt.endswith("Z") and "+" not in rt[10:] else rt)   # Avi 는 UTC(시간대 표기 없음)
            newest = max(newest, ts)
            evid = str(e.get("event_id", ""))
            desc = e.get("event_description") or e.get("reason_code") or evid
            low = evid.lower()
            sev = ("critical" if any(k in low for k in ("se_down", "cluster", "controller_node", "se_heartbeat")) and "up" not in low
                   else "error" if any(k in low for k in ("down", "fail", "error", "expir", "crash", "lost")) and not low.endswith("_up")
                   else "warning" if any(k in low for k in ("high", "degrad", "exceed", "unavail", "conflict")) else "info")
            out.append(self.ev(f"[{evid}] {e.get('obj_name', '')}: {desc}", severity=sev, kind="event",
                               entity=e.get("obj_name", ""), ts=ts, native_id=eid,
                               attrs={"module": e.get("module", ""), "event_id": evid, "obj_type": e.get("obj_type", ""),
                                      "app": "avi-event"}))
        self.since = newest
        return out

    async def checks(self):
        await self.login()
        hdr = {"X-Avi-Tenant": "*"} if not self.cfg.get("tenant") and self.cfg.get("all_tenants", True) else {}
        vipm = "VS 인벤토리 수집 후 확인"
        if getattr(self, "vs", None):                   # VIP 메트릭 — 테넌트별 실제 조회 결과(값 있는 VS 수·방식·HTTP 코드)
            try:
                await self.vip_metrics()
                vipm = self._state.get("checks", {}).get("VIP 메트릭", "-")
            except Exception as e:  # noqa: BLE001
                vipm = f"실패: {type(e).__name__}: {e}"[:200]
        return {"POST /login": f"ok X-Avi-Version {self.http.headers.get('X-Avi-Version', '-')}", "GET /api/alert": await self._probe("GET", "/api/alert", params={"page_size": 1}),
                "VIP 메트릭(analytics/metrics, 테넌트별)": vipm,
                "GET /api/serviceengine-inventory": await self._probe("GET", "/api/serviceengine-inventory", params={"page_size": 1}, headers=hdr),
                "GET /api/virtualservice-inventory": await self._probe("GET", "/api/virtualservice-inventory", params={"page_size": 1}, headers=hdr),
                "GET /api/analytics/logs?type=2": await self._probe("GET", "/api/analytics/logs", params={"type": 2, "duration": 300, "page_size": 1}),
                "GET /api/cluster/runtime": await self._probe("GET", "/api/cluster/runtime")}
