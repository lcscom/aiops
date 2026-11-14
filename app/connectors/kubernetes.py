"""VKS(vSphere Kubernetes Service) — Supervisor 와 워크로드(게스트) 클러스터 Kubernetes API 수집.

수집 항목
  · Kubernetes 이벤트   GET /api/v1/events (목록 → watch 스트림, 410 Gone 시 재목록)  ※ 기본 Warning 만
  · 노드 상태           Ready / Memory·Disk·PID Pressure / NetworkUnavailable 전환(장애·복구)
  · 파드 장애           CrashLoopBackOff · ImagePullBackOff · OOMKilled · Unschedulable · Failed · 재시작 급증
  · API 서버 헬스       GET /readyz?verbose  ([-]etcd failed 등 항목별)
  · Cluster API(Supervisor)  clusters / machines 단계·조건 → 워커 노드 VM 프로비저닝 실패·삭제 지연
인증
  · token   : ServiceAccount 토큰(읽기 전용 ClusterRole 권장) — 워크로드 클러스터 기본
  · vsphere : vSphere SSO 계정으로 POST https://<Supervisor>/wcp/login (Basic) → session_id(JWT, 기본 10시간)
              워크로드 클러스터는 본문 {"guest_cluster_name": ..., "guest_cluster_namespace": ...}
권한이 클러스터 범위에서 403 이면 namespaces 목록을 네임스페이스 범위로 순회(Supervisor 의 vSphere 네임스페이스 사용자).
Supervisor 컨트롤 플레인 VM 의 시스템 로그는 syslog 경로(vCenter 원격 syslog 상속 또는 Fluent Bit)로 받는다.
"""
from __future__ import annotations

import asyncio
import random
import json
import ssl
import time
from typing import Any

import httpx

from ..models import LogEvent
from .base import Connector
from .vmware_rest import _iso

# 이벤트 reason → 심각도(나머지 Warning 은 warning)
REASON_SEV = {
    "NodeNotReady": "error", "NodeNotSchedulable": "warning", "Rebooted": "error", "SystemOOM": "error",
    "OOMKilling": "error", "Evicted": "error", "Evicting": "error", "EvictionThresholdMet": "error",
    "FreeDiskSpaceFailed": "error", "ImageGCFailed": "warning", "ContainerGCFailed": "warning",
    "FailedCreatePodSandBox": "error", "FailedKillPod": "error", "NetworkNotReady": "error",
    "FailedMount": "error", "FailedAttachVolume": "error", "FailedMapVolume": "error", "VolumeFailedDelete": "warning",
    "ProvisioningFailed": "error", "FailedBinding": "warning", "BackOff": "warning", "Failed": "error",
    "FailedScheduling": "warning", "Unhealthy": "warning", "FailedCreate": "error", "FailedDelete": "warning",
    "FailedSync": "warning", "ReconcileError": "error", "MachineHealthCheckUnhealthy": "error",
    "FailedToDrainNode": "error", "DetachVolumeFailed": "error", "CertificateExpiring": "warning",
}
WAITING_BAD = {"CrashLoopBackOff": "error", "ImagePullBackOff": "error", "ErrImagePull": "error",
               "CreateContainerConfigError": "error", "CreateContainerError": "error", "RunContainerError": "error",
               "InvalidImageName": "error"}
NODE_COND_BAD = {"MemoryPressure": "warning", "DiskPressure": "error", "PIDPressure": "warning",
                 "NetworkUnavailable": "error"}


def _vol_refs(spec: dict) -> dict[str, list[str]]:
    """파드(템플릿) spec → 참조하는 PVC·ConfigMap·Secret 이름(값은 읽지 않음 — Secret 은 이름만)"""
    pvc, cm, sec = set(), set(), set()
    for v in spec.get("volumes") or []:
        if (v.get("persistentVolumeClaim") or {}).get("claimName"):
            pvc.add(v["persistentVolumeClaim"]["claimName"])
        if (v.get("configMap") or {}).get("name"):
            cm.add(v["configMap"]["name"])
        if (v.get("secret") or {}).get("secretName"):
            sec.add(v["secret"]["secretName"])
        for src in ((v.get("projected") or {}).get("sources") or []):
            if (src.get("configMap") or {}).get("name"):
                cm.add(src["configMap"]["name"])
            if (src.get("secret") or {}).get("name"):
                sec.add(src["secret"]["name"])
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        for ef in c.get("envFrom") or []:
            if (ef.get("configMapRef") or {}).get("name"):
                cm.add(ef["configMapRef"]["name"])
            if (ef.get("secretRef") or {}).get("name"):
                sec.add(ef["secretRef"]["name"])
        for e in c.get("env") or []:
            vf = e.get("valueFrom") or {}
            if (vf.get("configMapKeyRef") or {}).get("name"):
                cm.add(vf["configMapKeyRef"]["name"])
            if (vf.get("secretKeyRef") or {}).get("name"):
                sec.add(vf["secretKeyRef"]["name"])
    return {"pvcs": sorted(pvc), "cms": sorted(cm), "secrets": sorted(sec)}


def _sel(o: dict) -> dict:
    return ((o.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}


# 2.9.0 구성도용 리소스(읽기 전용 목록) — (키, 경로, 네임스페이스 범위, 대체 경로)
TOPO_RES = [
    ("namespaces", "/api/v1/namespaces", False, ""), ("deployments", "/apis/apps/v1/deployments", True, ""),
    ("statefulsets", "/apis/apps/v1/statefulsets", True, ""), ("daemonsets", "/apis/apps/v1/daemonsets", True, ""),
    ("replicasets", "/apis/apps/v1/replicasets", True, ""), ("jobs", "/apis/batch/v1/jobs", True, ""),
    ("cronjobs", "/apis/batch/v1/cronjobs", True, ""), ("services", "/api/v1/services", True, ""),
    ("ingresses", "/apis/networking.k8s.io/v1/ingresses", True, ""), ("pvcs", "/api/v1/persistentvolumeclaims", True, ""),
    ("pvs", "/api/v1/persistentvolumes", False, ""), ("storageclasses", "/apis/storage.k8s.io/v1/storageclasses", False, ""),
    ("hpas", "/apis/autoscaling/v2/horizontalpodautoscalers", True, ""), ("netpols", "/apis/networking.k8s.io/v1/networkpolicies", True, ""),
]
SUP_RES = [   # Supervisor 전용(없으면 건너뜀): VM Service VM · TanzuKubernetesCluster
    ("vms", "/apis/vmoperator.vmware.com/v1alpha3/virtualmachines", True, "/apis/vmoperator.vmware.com/v1alpha2/virtualmachines"),
    ("tkcs", "/apis/run.tanzu.vmware.com/v1alpha3/tanzukubernetesclusters", True, ""),
]


def _compact(key: str, o: dict) -> dict[str, Any]:
    md, sp, st = o.get("metadata") or {}, o.get("spec") or {}, o.get("status") or {}
    b = {"ns": md.get("namespace", ""), "name": md.get("name", "")}
    if key == "namespaces":
        return {"name": b["name"], "phase": st.get("phase", ""), "labels": {k: v for k, v in (md.get("labels") or {}).items() if "vmware" in k or "tkg" in k}}
    if key in ("deployments", "statefulsets", "daemonsets"):
        tpl = (sp.get("template") or {}).get("spec") or {}
        want = st.get("desiredNumberScheduled") if key == "daemonsets" else sp.get("replicas", 1)
        ready = st.get("numberReady") if key == "daemonsets" else st.get("readyReplicas", 0)
        updated = st.get("updatedNumberScheduled") if key == "daemonsets" else st.get("updatedReplicas")
        ann = md.get("annotations") or {}
        rev = ann.get("deployment.kubernetes.io/revision") or st.get("updateRevision") or ""
        return {**b, "kind": {"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet"}[key],
                "want": want or 0, "ready": ready or 0, "updated": updated if updated is not None else (want or 0),
                "rev": str(rev)[-24:], "paused": bool(sp.get("paused")),
                "gen_lag": int(md.get("generation") or 0) > int(st.get("observedGeneration") or md.get("generation") or 0),
                "cond": next((f"{c.get('reason', '')}: {c.get('message', '')}"[:200] for c in st.get("conditions") or []
                              if (c.get("type") == "Progressing" and c.get("reason") == "ProgressDeadlineExceeded")
                              or (c.get("type") == "ReplicaFailure" and c.get("status") == "True")), ""),
                "selector": _sel(o), "sa": tpl.get("serviceAccountName", ""),
                "images": [c.get("image", "") for c in tpl.get("containers") or []][:3], **_vol_refs(tpl),
                "pvc_templates": [((t.get("metadata") or {}).get("name", "")) for t in sp.get("volumeClaimTemplates") or []]}
    if key == "replicasets":
        return {**b, "owner": next((r.get("name") for r in md.get("ownerReferences") or [] if r.get("kind") == "Deployment"), "")}
    if key == "jobs":
        return {**b, "owner": next((r.get("name") for r in md.get("ownerReferences") or [] if r.get("kind") == "CronJob"), ""),
                "succeeded": st.get("succeeded", 0), "failed": st.get("failed", 0)}
    if key == "cronjobs":
        return {**b, "schedule": sp.get("schedule", ""), "suspend": bool(sp.get("suspend"))}
    if key == "services":
        lb = [(i.get("ip") or i.get("hostname") or "") for i in ((st.get("loadBalancer") or {}).get("ingress") or [])]
        return {**b, "type": sp.get("type", "ClusterIP"), "cluster_ip": sp.get("clusterIP", ""), "selector": sp.get("selector") or {},
                "ports": [f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in sp.get("ports") or []][:6], "lb": [x for x in lb if x]}
    if key == "ingresses":
        svcs = set()
        dflt = (sp.get("defaultBackend") or {}).get("service") or {}
        if dflt.get("name"):
            svcs.add(dflt["name"])
        hosts = []
        for r in sp.get("rules") or []:
            if r.get("host"):
                hosts.append(r["host"])
            for pth in ((r.get("http") or {}).get("paths") or []):
                n = ((pth.get("backend") or {}).get("service") or {}).get("name")
                if n:
                    svcs.add(n)
        lb = [(i.get("ip") or i.get("hostname") or "") for i in ((st.get("loadBalancer") or {}).get("ingress") or [])]
        return {**b, "class": sp.get("ingressClassName", ""), "hosts": hosts[:6], "services": sorted(svcs), "lb": [x for x in lb if x]}
    if key == "pvcs":
        return {**b, "volume": sp.get("volumeName", ""), "sc": sp.get("storageClassName", ""), "phase": st.get("phase", ""),
                "size": ((st.get("capacity") or {}).get("storage")) or (((sp.get("resources") or {}).get("requests") or {}).get("storage", ""))}
    if key == "pvs":
        cr = sp.get("claimRef") or {}
        return {"name": b["name"], "sc": sp.get("storageClassName", ""), "size": (sp.get("capacity") or {}).get("storage", ""),
                "phase": st.get("phase", ""), "driver": (sp.get("csi") or {}).get("driver", ""), "handle": ((sp.get("csi") or {}).get("volumeHandle", ""))[:80],
                "claim": f"{cr.get('namespace', '')}/{cr.get('name', '')}" if cr else ""}
    if key == "storageclasses":
        prm = o.get("parameters") or {}
        return {"name": b["name"], "provisioner": o.get("provisioner", ""), "policy": prm.get("storagePolicyName") or prm.get("storagepolicyname") or prm.get("svStorageClass") or "",
                "default": (md.get("annotations") or {}).get("storageclass.kubernetes.io/is-default-class") == "true"}
    if key == "hpas":
        tr = sp.get("scaleTargetRef") or {}
        return {**b, "target_kind": tr.get("kind", ""), "target": tr.get("name", ""), "min": sp.get("minReplicas", 1), "max": sp.get("maxReplicas", 0),
                "current": st.get("currentReplicas", 0), "desired": st.get("desiredReplicas", 0)}
    if key == "netpols":
        return {**b, "selector": (sp.get("podSelector") or {}).get("matchLabels") or {}, "types": sp.get("policyTypes") or []}
    if key == "vms":
        return {**b, "power": st.get("powerState", "") or sp.get("powerState", ""), "class": sp.get("className", ""), "image": sp.get("imageName", ""),
                "ip": ((st.get("network") or {}).get("primaryIP4")) or st.get("vmIp", "") or ""}
    if key == "tkcs":
        return {**b, "phase": st.get("phase", ""), "version": ((sp.get("distribution") or {}).get("fullVersion")) or ((sp.get("topology") or {}).get("controlPlane") or {}).get("tkr", {}).get("reference", {}).get("name", "")}
    return b


class VksConnector(Connector):
    type = "vks"
    default_interval = 30

    def __init__(self, cfg: dict, emit):
        super().__init__(cfg, emit)
        self.role = str(cfg.get("role", "workload")).lower()          # supervisor | workload
        self.source = "vks-supervisor" if self.role == "supervisor" else "vks"
        self._state["source"] = self.source
        api = cfg.get("api_url") or (f"https://{self.host}" if self.host else "")
        if ":" not in api.split("//", 1)[-1] and not cfg.get("api_url"):
            api += ":6443"                                              # kube-apiserver 기본 포트
        self.base_url = api.rstrip("/")
        self._state["target"] = self.base_url
        self.auth_mode = str(cfg.get("auth", "token")).lower()
        self.cluster_label = cfg.get("cluster_name") or cfg.get("guest_cluster_name") or self.name
        self.include_normal = bool(cfg.get("include_normal_events", False))
        self.status_interval = float(cfg.get("status_interval", 60))
        self.namespaces: list[str] = list(cfg.get("namespaces") or [])
        self.cluster_scope = True
        self._rv = ""                      # 이벤트 resourceVersion
        self._last_status = 0.0
        self._prev: dict[str, str] = {}    # 상태 키 → 마지막 판정(전환만 이벤트화)
        self._restarts: dict[str, int] = {}
        self._token_exp = 0.0
        # 화면용 인벤토리(노드·파드·CAPI 클러스터) — 상태 점검 주기마다 갱신
        self.inv: dict[str, Any] = {"nodes": [], "pods": [], "clusters": [], "updated": 0}
        self.discovered_by = cfg.get("discovered_by", "")
        # 파드 로그: problem(문제 파드 마지막 로그 자동 첨부, 기본) · log_namespaces 지정 시 해당 네임스페이스 파드 로그 실시간(폴링) 수집
        self.problem_logs = bool(cfg.get("problem_logs", True))
        self.log_namespaces: list[str] = [x for x in (cfg.get("log_namespaces") or []) if x]
        self.log_max_pods = int(cfg.get("log_max_pods", 60))
        self._log_since: dict[str, str] = {}
        self.topo_on = cfg.get("topology", True) is not False           # 2.9.0 구성도용 리소스 수집
        self.topo_interval = max(60.0, float(cfg.get("topology_interval", 300)))
        self._last_topo = 0.0

    # ------------------------------------------------------------------ HTTP / 인증
    def _verify(self):
        if self.cfg.get("ca_file"):
            return ssl.create_default_context(cafile=self.cfg["ca_file"])
        return bool(self.verify)

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(base_url=self.base_url, verify=self._verify(),
                                           timeout=httpx.Timeout(float(self.cfg.get("timeout", 30)), connect=8),
                                           headers={"Accept": "application/json"})
        return self._http

    async def login(self) -> None:
        if self.auth_mode == "vsphere":
            sup = self.cfg.get("supervisor") or self.host.split(":")[0]
            body: dict[str, Any] = {}
            if self.role != "supervisor":
                body["guest_cluster_name"] = self.cfg.get("guest_cluster_name") or self.cluster_label
                if self.cfg.get("guest_cluster_namespace"):
                    body["guest_cluster_namespace"] = self.cfg["guest_cluster_namespace"]
            async with httpx.AsyncClient(verify=self._verify(), timeout=20) as c:
                r = await c.post(f"https://{sup}/wcp/login", auth=(self.cfg["username"], self.cfg["password"]),
                                 json=body or None, headers={"Content-Type": "application/json"})
            r.raise_for_status()
            tok = r.json().get("session_id")
            if not tok:
                raise RuntimeError("/wcp/login 응답에 session_id 없음")
            self.http.headers["Authorization"] = f"Bearer {tok}"
            self._token_exp = time.time() + 9 * 3600                    # 10시간 만료 전 갱신
            self._state["auth"] = "vSphere SSO(/wcp/login)"
        else:
            tok = self.cfg.get("token") or ""
            if not tok and self.cfg.get("token_file"):
                tok = open(self.cfg["token_file"], encoding="utf-8").read().strip()
            if not tok:
                raise RuntimeError("token(ServiceAccount) 또는 auth: vsphere 설정 필요")
            self.http.headers["Authorization"] = f"Bearer {tok}"
            self._state["auth"] = "ServiceAccount token"
        r = await self.http.get("/version")
        r.raise_for_status()
        self._state["checks"]["version"] = "ok " + str(r.json().get("gitVersion", ""))

    # ------------------------------------------------------------------ 공통 목록(클러스터 → 네임스페이스 범위 폴백)
    async def _list(self, path: str, params: dict | None = None, namespaced: bool = True, limit_pages: int = 20) -> list[dict]:
        """path 예: /api/v1/pods. 403 이고 namespaces 설정 시 /api/v1/namespaces/{ns}/pods 로 순회."""
        async def pages(p: str) -> list[dict]:
            out, cont = [], ""
            for _ in range(limit_pages):
                q = dict(params or {}, limit=500)
                if cont:
                    q["continue"] = cont
                r = await self.http.get(p, params=q)
                if r.status_code in (401, 403, 404):
                    raise httpx.HTTPStatusError(str(r.status_code), request=r.request, response=r)
                r.raise_for_status()
                j = r.json()
                out += j.get("items") or []
                cont = (j.get("metadata") or {}).get("continue") or ""
                if not cont:
                    break
            return out
        if not namespaced or (self.cluster_scope and not (self.namespaces and self.cfg.get("namespace_scope_only"))):
            try:
                return await pages(path)
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 403 or not namespaced or not self.namespaces:
                    raise
                self.cluster_scope = False
                self._state["checks"]["범위"] = "warn: 클러스터 범위 403 → 지정 네임스페이스만 수집"
        grp, res = path.rsplit("/", 1)
        out: list[dict] = []
        for ns in self.namespaces:
            try:
                out += await pages(f"{grp}/namespaces/{ns}/{res}")
            except httpx.HTTPStatusError as e:
                if e.response.status_code not in (403, 404):
                    raise
        return out

    def entities(self) -> list[dict[str, Any]]:
        out = []
        for k, v in sorted(self._prev.items()):
            if k.startswith("node:") and k.endswith(":Ready"):
                name = k[5:-6]
                pressure = [c for c in NODE_COND_BAD if self._prev.get(f"node:{name}:{c}") == "True"]
                st = "down" if v != "True" else ("warn" if pressure or f"node:{name}:cordon" in self._prev else "ok")
                out.append({"name": name, "kind": "node", "state": st, "group": self.cluster_label,
                            "detail": f"Ready={v}" + (f" · {', '.join(pressure)}" if pressure else "")})
            elif k.startswith("capi:Cluster:"):
                out.append({"name": k.split("/", 1)[-1], "kind": "cluster", "state": "ok" if v == "ok" else ("down" if v.startswith("error") else "warn"),
                            "group": "VKS 클러스터", "detail": "정상" if v == "ok" else v.split(":", 1)[-1]})
        return out[:200]

    def _transition(self, key: str, state: str) -> str | None:
        """상태가 바뀌었을 때만 이전 상태 반환('' = 최초)."""
        prev = self._prev.get(key)
        if prev == state:
            return None
        self._prev[key] = state
        return prev or ""

    # ------------------------------------------------------------------ 이벤트
    def _event(self, e: dict) -> LogEvent | None:
        md = e.get("metadata") or {}
        typ = e.get("type") or "Normal"
        if typ != "Warning" and not self.include_normal:
            return None
        count = int(e.get("count") or (e.get("series") or {}).get("count") or 1)
        uid = md.get("uid", "")
        if not self.seen.is_new(f"ev:{uid}:{count}"):
            return None
        io = e.get("involvedObject") or e.get("regarding") or {}
        ts = _iso(e.get("lastTimestamp") or e.get("eventTime") or (e.get("series") or {}).get("lastObservedTime")
                  or md.get("creationTimestamp"))
        if self.first_poll and ts < self.since:
            return None
        reason = e.get("reason") or ""
        kind, ns, name = io.get("kind", ""), io.get("namespace") or md.get("namespace", ""), io.get("name", "")
        node = name if kind == "Node" else ((e.get("source") or {}).get("host") or "")
        sev = REASON_SEV.get(reason, "warning" if typ == "Warning" else "info")
        msg = f"[{reason}] {kind} {ns + '/' if ns else ''}{name}: {(e.get('message') or e.get('note') or '').strip()}"
        if count > 1:
            msg += f" (x{count})"
        comp = (e.get("source") or {}).get("component") or e.get("reportingComponent") or ""
        return self.ev(msg, severity=sev, kind="k8s-event", host=node or self.cluster_label,
                       entity=f"{kind}/{ns + '/' if ns else ''}{name}", ts=ts, native_id=uid,
                       attrs={"cluster": self.cluster_label, "role": self.role, "namespace": ns, "reason": reason,
                              "component": comp, "object_kind": kind, "count": count, "app": comp or "k8s-event"})

    def _ev_params(self) -> dict:
        return {} if self.include_normal else {"fieldSelector": "type=Warning"}

    async def _events_list(self) -> None:
        if self.cluster_scope:
            try:
                r = await self.http.get("/api/v1/events", params={**self._ev_params(), "limit": 500})
                if r.status_code == 403 and self.namespaces:
                    raise httpx.HTTPStatusError("403", request=r.request, response=r)
                r.raise_for_status()
                j = r.json()
                self._rv = (j.get("metadata") or {}).get("resourceVersion", "")
                for e in sorted(j.get("items") or [], key=lambda x: x.get("lastTimestamp") or ""):
                    ev = self._event(e)
                    if ev:
                        await self.emit(ev)
                        self._state["events_total"] += 1
                return
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 403:
                    raise
                self.cluster_scope = False
        self._rv = ""
        for e in await self._list("/api/v1/events", self._ev_params()):
            ev = self._event(e)
            if ev:
                await self.emit(ev)
                self._state["events_total"] += 1

    async def _events_watch(self, seconds: float) -> None:
        """watch 스트림으로 seconds 동안 실시간 수신(이벤트는 즉시 emit)."""
        params = {**self._ev_params(), "watch": "1", "allowWatchBookmarks": "true",
                  "timeoutSeconds": str(max(5, int(seconds))), "resourceVersion": self._rv}
        async with self.http.stream("GET", "/api/v1/events", params=params,
                                    timeout=httpx.Timeout(seconds + 15, connect=8)) as r:
            if r.status_code == 410:
                self._rv = ""
                return
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.strip():
                    continue
                try:
                    w = json.loads(line)
                except ValueError:
                    continue
                obj = w.get("object") or {}
                if w.get("type") == "ERROR":
                    if obj.get("code") == 410:          # resourceVersion 만료 → 재목록
                        self._rv = ""
                    return
                rv = (obj.get("metadata") or {}).get("resourceVersion")
                if rv:
                    self._rv = rv
                if w.get("type") in ("ADDED", "MODIFIED"):
                    ev = self._event(obj)
                    if ev:
                        await self.emit(ev)
                        self._state["events_total"] += 1

    # ------------------------------------------------------------------ 상태 점검(노드·파드·CAPI·readyz)
    async def _nodes(self) -> list[LogEvent]:
        out = []
        inv = []
        for n in await self._list("/api/v1/nodes", namespaced=False):
            name = (n.get("metadata") or {}).get("name", "")
            conds = {c.get("type"): c for c in (n.get("status") or {}).get("conditions") or []}
            rd = conds.get("Ready") or {}
            st = rd.get("status", "Unknown")
            labels = (n.get("metadata") or {}).get("labels") or {}
            ni = (n.get("status") or {}).get("nodeInfo") or {}
            cap = (n.get("status") or {}).get("capacity") or {}
            inv.append({"name": name, "ready": st, "roles": sorted(k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")) or ["worker"],
                        "pressure": [c for c in NODE_COND_BAD if (conds.get(c) or {}).get("status") == "True"],
                        "unschedulable": bool((n.get("spec") or {}).get("unschedulable")), "kubelet": ni.get("kubeletVersion", ""),
                        "os": ni.get("osImage", ""), "cpu": cap.get("cpu", ""), "memory": cap.get("memory", ""),
                        "ip": next((a.get("address", "") for a in (n.get("status") or {}).get("addresses") or [] if a.get("type") == "InternalIP"), ""),
                        "age": _iso((n.get("metadata") or {}).get("creationTimestamp"))})
            prev = self._transition(f"node:{name}:Ready", st)
            if prev is not None and (st != "True" or prev not in ("", "True")):
                ok = st == "True"
                out.append(self.ev(f"노드 {name} Ready={st}" + ("" if ok else f" — {rd.get('reason', '')}: {rd.get('message', '')}"),
                                   severity="info" if ok else "error", kind="k8s-node", host=name, entity=f"Node/{name}",
                                   attrs={"cluster": self.cluster_label, "role": self.role, "app": "node-status"}))
            if (n.get("spec") or {}).get("unschedulable"):
                if self._transition(f"node:{name}:cordon", "1") is not None:
                    out.append(self.ev(f"노드 {name} 스케줄 불가(cordon)", severity="warning", kind="k8s-node", host=name,
                                       entity=f"Node/{name}", attrs={"cluster": self.cluster_label, "app": "node-status"}))
            else:
                self._prev.pop(f"node:{name}:cordon", None)
            for ct, sev in NODE_COND_BAD.items():
                c = conds.get(ct)
                if not c:
                    continue
                prev = self._transition(f"node:{name}:{ct}", c.get("status", ""))
                if prev is None:
                    continue
                if c.get("status") == "True":
                    out.append(self.ev(f"노드 {name} {ct} — {c.get('message', '')}", severity=sev, kind="k8s-node", host=name,
                                       entity=f"Node/{name}", attrs={"cluster": self.cluster_label, "app": "node-status"}))
                elif prev == "True":
                    out.append(self.ev(f"노드 {name} {ct} 해소", severity="info", kind="k8s-node", host=name,
                                       entity=f"Node/{name}", attrs={"cluster": self.cluster_label, "app": "node-status"}))
        self.inv["nodes"] = inv
        return out

    async def _pods(self) -> list[LogEvent]:
        out, now, alive = [], time.time(), set()
        inv: list[dict] = []
        want_logs: list[tuple[str, str, str, bool]] = []
        for p in await self._list("/api/v1/pods"):
            md, sp, st = p.get("metadata") or {}, p.get("spec") or {}, p.get("status") or {}
            ns, name, node = md.get("namespace", ""), md.get("name", ""), sp.get("nodeName", "")
            pid = f"{ns}/{name}"
            alive.add(pid)
            css = st.get("containerStatuses") or []
            reason = next((((c.get("state") or {}).get("waiting") or {}).get("reason") for c in css
                           if (c.get("state") or {}).get("waiting")), "") or st.get("reason", "")
            inv.append({"ns": ns, "name": name, "node": node, "phase": st.get("phase", ""), "reason": reason or "",
                        "ip": st.get("podIP", "") or "", "host_ip": st.get("hostIP", "") or "",
                        "ready": f"{sum(1 for c in css if c.get('ready'))}/{len(sp.get('containers') or css)}",
                        "restarts": sum(int(c.get("restartCount") or 0) for c in css),
                        "containers": [c.get("name") for c in sp.get("containers") or []], "age": _iso(md.get("creationTimestamp")),
                        "owner": ((md.get("ownerReferences") or [{}])[0]).get("kind", ""),
                        "owner_name": ((md.get("ownerReferences") or [{}])[0]).get("name", ""),
                        "labels": md.get("labels") or {}, "sa": sp.get("serviceAccountName", ""), **_vol_refs(sp),
                        "msg": next((str(((c.get("state") or {}).get("waiting") or {}).get("message") or "")[:240] for c in css
                                     if ((c.get("state") or {}).get("waiting") or {}).get("message")), "") or str(st.get("message") or "")[:240],
                        "last_term": next(({"reason": t.get("reason", ""), "exit": t.get("exitCode"), "at": _iso(t.get("finishedAt")), "container": c.get("name", "")}
                                           for c in css for t in [((c.get("lastState") or {}).get("terminated") or {})] if t), None)})
            base = {"cluster": self.cluster_label, "role": self.role, "namespace": ns, "app": "pod-status"}
            phase = st.get("phase", "")
            problems: list[tuple[str, str, str]] = []                    # (key, severity, message)
            if phase == "Failed":
                problems.append(("Failed", "error", f"파드 {pid} Failed — {st.get('reason', '')} {st.get('message', '')}".strip()))
            if phase == "Pending":
                created = _iso(md.get("creationTimestamp"))
                sch = next((c for c in st.get("conditions") or [] if c.get("type") == "PodScheduled"), {})
                if sch.get("status") == "False" and now - created > 120:
                    problems.append(("Unschedulable", "warning", f"파드 {pid} 스케줄 불가 — {sch.get('message', '')}"))
                elif now - created > float(self.cfg.get("pending_alert_seconds", 600)):
                    problems.append(("PendingLong", "warning", f"파드 {pid} {int((now - created) / 60)}분째 Pending"))
            for cs in (st.get("containerStatuses") or []) + (st.get("initContainerStatuses") or []):
                cn = cs.get("name", "")
                w = (cs.get("state") or {}).get("waiting") or {}
                if w.get("reason") in WAITING_BAD:
                    problems.append((f"{cn}:{w['reason']}", WAITING_BAD[w["reason"]],
                                     f"파드 {pid} 컨테이너 {cn} {w['reason']} — {(w.get('message') or '')[:300]} (재시작 {cs.get('restartCount', 0)}회)"))
                lt = (cs.get("lastState") or {}).get("terminated") or {}
                rc = int(cs.get("restartCount") or 0)
                k = f"{pid}:{cn}"
                prev_rc = self._restarts.get(k)
                self._restarts[k] = rc
                if prev_rc is not None and rc > prev_rc:
                    if lt.get("reason") == "OOMKilled":
                        problems.append((f"{cn}:OOM:{rc}", "error", f"파드 {pid} 컨테이너 {cn} OOMKilled — 메모리 제한 초과 (재시작 {rc}회)"))
                    elif rc - prev_rc >= int(self.cfg.get("restart_burst", 3)):
                        problems.append((f"{cn}:restart:{rc}", "warning", f"파드 {pid} 컨테이너 {cn} 재시작 급증 +{rc - prev_rc} "
                                                                           f"(마지막 종료 {lt.get('reason', '')} exit {lt.get('exitCode', '')})"))
            state = "|".join(sorted(k for k, _, _ in problems)) or "ok"
            prev = self._transition(f"pod:{pid}", state)
            if prev is None:
                continue
            for key, sev, msg in problems:
                if key not in (prev or "").split("|"):
                    out.append(self.ev(msg, severity=sev, kind="k8s-pod", host=node or self.cluster_label,
                                       entity=f"Pod/{pid}", attrs=base | {"node": node, "reason": key.split(":")[-1]}))
                    cn = key.split(":")[0] if ":" in key else ((sp.get("containers") or [{}])[0].get("name", ""))
                    if cn and self.problem_logs and len(want_logs) < 10 and (":" in key or key == "Failed"):
                        prevc = any(t in key for t in ("CrashLoopBackOff", "OOM", "restart"))
                        want_logs.append((ns, name, cn, prevc))
            if state == "ok" and prev not in ("", "ok"):
                out.append(self.ev(f"파드 {pid} 정상화", severity="info", kind="k8s-pod", host=node or self.cluster_label,
                                   entity=f"Pod/{pid}", attrs=base))
        for k in [k for k in self._prev if k.startswith("pod:") and k[4:] not in alive]:   # 삭제된 파드 정리
            self._prev.pop(k, None)
        for k in [k for k in self._restarts if k.rsplit(":", 1)[0] not in alive]:
            self._restarts.pop(k, None)
        self.inv["pods"] = inv
        self.inv["updated"] = time.time()
        for ns, name, cn, prevc in want_logs:                     # 문제 파드: 마지막 로그 30줄을 이벤트로 첨부(원인 파악용)
            try:
                lines = await self.pod_log(ns, name, cn, tail=30, previous=prevc)
            except Exception:  # noqa: BLE001
                continue
            for ln in lines[-30:]:
                out.append(self._log_event(ns, name, cn, ln, previous=prevc))
        return out

    # ------------------------------------------------------------------ 파드 로그
    async def pod_log(self, ns: str, pod: str, container: str = "", tail: int = 200, previous: bool = False,
                      since_time: str = "", timestamps: bool = False) -> list[str]:
        params: dict[str, Any] = {"tailLines": max(1, min(int(tail), 5000)), "limitBytes": 1_000_000}
        if container:
            params["container"] = container
        if previous:
            params["previous"] = "true"
        if since_time:
            params["sinceTime"] = since_time
            params.pop("tailLines", None)
        if timestamps:
            params["timestamps"] = "true"
        r = await self.http.get(f"/api/v1/namespaces/{ns}/pods/{pod}/log", params=params)
        if r.status_code == 400 and previous:                      # 이전 컨테이너 없음 → 현재 컨테이너
            params.pop("previous", None)
            r = await self.http.get(f"/api/v1/namespaces/{ns}/pods/{pod}/log", params=params)
        r.raise_for_status()
        return r.text.splitlines()

    async def object_events(self, ns: str, names: set[str], kinds: set[str] | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """개체(와 그 파드·ReplicaSet) 이벤트 — Normal 포함(롤아웃·스케일·이미지 풀 등). 네임스페이스 범위는 한 번 목록 후 필터,
        클러스터 범위(Node·PV)는 fieldSelector. 읽기 전용(events list)"""
        out = []
        if ns:
            items = await self._list(f"/api/v1/namespaces/{ns}/events", namespaced=False, limit_pages=3)
        else:
            items = []
            for n in list(names)[:5]:
                items += await self._list("/api/v1/events", {"fieldSelector": f"involvedObject.name={n}"}, namespaced=False, limit_pages=1)
        for e in items:
            io = e.get("involvedObject") or e.get("regarding") or {}
            if io.get("name") not in names or (kinds and io.get("kind") not in kinds):
                continue
            md = e.get("metadata") or {}
            out.append({"ts": _iso(e.get("lastTimestamp") or e.get("eventTime") or (e.get("series") or {}).get("lastObservedTime") or md.get("creationTimestamp")),
                        "first": _iso(e.get("firstTimestamp") or md.get("creationTimestamp")), "type": e.get("type") or "Normal",
                        "reason": e.get("reason") or "", "kind": io.get("kind", ""), "name": io.get("name", ""),
                        "message": (e.get("message") or e.get("note") or "").strip()[:600],
                        "count": int(e.get("count") or (e.get("series") or {}).get("count") or 1),
                        "component": (e.get("source") or {}).get("component") or e.get("reportingComponent") or ""})
        out.sort(key=lambda x: x["ts"] or 0, reverse=True)
        return out[:limit]

    def _log_event(self, ns: str, pod: str, container: str, line: str, previous: bool = False, ts: float | None = None) -> LogEvent:
        from .vmware_rest import sev_from_text
        node = next((p["node"] for p in self.inv["pods"] if p["ns"] == ns and p["name"] == pod), "")
        return self.ev(line[:4000], severity=sev_from_text(line), kind="k8s-log", host=node or self.cluster_label,
                       entity=f"Pod/{ns}/{pod}", ts=ts or time.time(),
                       attrs={"cluster": self.cluster_label, "role": self.role, "namespace": ns, "pod": pod,
                              "container": container, "app": container or "pod", "previous": previous})

    async def _follow_logs(self) -> list[LogEvent]:
        """log_namespaces 의 Running 파드 컨테이너 로그를 지난 조회 이후분만(sinceTime·timestamps) 가져온다."""
        out: list[LogEvent] = []
        pods = [p for p in self.inv["pods"] if p["phase"] == "Running" and (p["ns"] in self.log_namespaces or "*" in self.log_namespaces)]
        for p in pods[: self.log_max_pods]:
            for cn in p["containers"] or [""]:
                k = f"{p['ns']}/{p['name']}/{cn}"
                since = self._log_since.get(k)
                if since is None:                                   # 처음엔 위치만 잡음(과거 재생 안 함)
                    self._log_since[k] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    continue
                try:
                    lines = await self.pod_log(p["ns"], p["name"], cn, since_time=since, timestamps=True)
                except Exception:  # noqa: BLE001
                    continue
                last = since
                for ln in lines:
                    t, _, msg = ln.partition(" ")
                    if t <= since or not msg:
                        continue
                    last = max(last, t)
                    out.append(self._log_event(p["ns"], p["name"], cn, msg, ts=_iso(t)))
                self._log_since[k] = last
        alive = {f"{p['ns']}/{p['name']}" for p in pods}
        for k in [k for k in self._log_since if k.rsplit("/", 1)[0] not in alive]:
            self._log_since.pop(k, None)
        return out

    async def _readyz(self) -> list[LogEvent]:
        r = await self.http.get("/readyz", params={"verbose": "true"})
        bad = [ln[3:].replace(" failed", "").strip() for ln in r.text.splitlines() if ln.startswith("[-]")]
        state = "ok" if r.status_code == 200 else ("fail:" + ",".join(bad) if bad else f"http{r.status_code}")
        prev = self._transition("readyz", state)
        if prev is None or (prev == "" and state == "ok"):
            return []
        if state == "ok":
            return [self.ev(f"kube-apiserver readyz 정상화 ({self.cluster_label})", severity="info", kind="k8s-health",
                            entity="apiserver", attrs={"cluster": self.cluster_label, "app": "kube-apiserver"})]
        return [self.ev(f"kube-apiserver readyz 실패 ({self.cluster_label}): {', '.join(bad) or r.text[:200]}",
                        severity="critical" if any("etcd" in b for b in bad) else "error", kind="k8s-health", entity="apiserver",
                        attrs={"cluster": self.cluster_label, "app": "kube-apiserver", "failed_checks": bad})]

    async def _capi(self) -> list[LogEvent]:
        """Supervisor: VKS 워크로드 클러스터·머신(워커/컨트롤 플레인 VM) 수명주기 이상."""
        out, now = [], time.time()
        clusters_inv: list[dict] = []
        for kind, path in (("Cluster", "/apis/cluster.x-k8s.io/v1beta1/clusters"),
                           ("Machine", "/apis/cluster.x-k8s.io/v1beta1/machines")):
            try:
                items = await self._list(path)
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (403, 404):
                    self._state["checks"][f"CAPI {kind}"] = f"warn: 조회 불가(HTTP {e.response.status_code})"
                    continue
                raise
            for o in items:
                md, st = o.get("metadata") or {}, o.get("status") or {}
                ns, name = md.get("namespace", ""), md.get("name", "")
                phase = st.get("phase", "")
                ready = next((c for c in st.get("conditions") or [] if c.get("type") == "Ready"), {})
                fail = st.get("failureMessage") or st.get("failureReason") or ""
                age = now - _iso(md.get("creationTimestamp"))
                if kind == "Cluster":
                    ep = (o.get("spec") or {}).get("controlPlaneEndpoint") or {}
                    clusters_inv.append({"ns": ns, "name": name, "phase": phase, "ready": ready.get("status", ""),
                                         "endpoint": f"{ep.get('host')}:{ep.get('port') or 6443}" if ep.get("host") else "",
                                         "version": ((o.get("spec") or {}).get("topology") or {}).get("version", ""),
                                         "age": _iso(md.get("creationTimestamp"))})
                sev, why = None, ""
                if phase == "Failed" or fail:
                    sev, why = "error", fail or "phase=Failed"
                elif phase in ("Provisioning", "Pending", "Provisioned") and kind == "Machine" and age > float(self.cfg.get("machine_provision_alert_seconds", 1800)):
                    sev, why = "warning", f"{int(age / 60)}분째 {phase}"
                elif phase == "Deleting" and md.get("deletionTimestamp") and now - _iso(md["deletionTimestamp"]) > 1800:
                    sev, why = "warning", "30분 이상 삭제 지연"
                elif ready.get("status") == "False" and ready.get("severity") in ("Error", "Warning") and age > 600:
                    sev, why = ("error" if ready.get("severity") == "Error" else "warning"), f"{ready.get('reason', '')}: {ready.get('message', '')}"
                state = f"{sev}:{why[:80]}" if sev else "ok"
                prev = self._transition(f"capi:{kind}:{ns}/{name}", state)
                if prev is None:
                    continue
                cl = (md.get("labels") or {}).get("cluster.x-k8s.io/cluster-name", name if kind == "Cluster" else "")
                node = ((st.get("nodeRef") or {}).get("name")) or name
                attrs = {"cluster": cl, "role": "supervisor", "namespace": ns, "app": "cluster-api", "phase": phase}
                if sev:
                    out.append(self.ev(f"VKS {kind} {ns}/{name} ({'클러스터 ' + cl if cl and kind == 'Machine' else 'phase ' + phase}) — {why}",
                                       severity=sev, kind="capi", host=node if kind == "Machine" else cl, entity=f"{kind}/{ns}/{name}",
                                       attrs=attrs))
                elif prev not in ("", "ok"):
                    out.append(self.ev(f"VKS {kind} {ns}/{name} 정상화(phase {phase})", severity="info", kind="capi",
                                       host=node if kind == "Machine" else cl, entity=f"{kind}/{ns}/{name}", attrs=attrs))
        self.inv["clusters"] = clusters_inv
        return out

    # ------------------------------------------------------------------ 2.9.0 구성도
    async def _topology(self) -> None:
        """구성도용 읽기 전용 목록 — 권한 없음(403)·미지원(404)은 건너뛰고 기록. Secret 은 조회하지 않음(파드 참조 이름만)"""
        topo: dict[str, list] = {}
        errs: dict[str, str] = {}
        res = TOPO_RES + (SUP_RES if self.role == "supervisor" else [])
        for key, path, nsd, alt in res:
            items = None
            for pth in [path] + ([alt] if alt else []):
                try:
                    items = await self._list(pth, namespaced=nsd)
                    break
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        raise
                    errs[key] = f"HTTP {e.response.status_code}"
            if items is not None:
                errs.pop(key, None)
                topo[key] = [_compact(key, o) for o in items][:5000]
        self.inv["topo"] = topo
        self.inv["topo_errors"] = errs
        self.inv["topo_updated"] = time.time()
        if errs:
            self._state["checks"]["구성도"] = "warn: " + ", ".join(f"{k} {v}" for k, v in list(errs.items())[:6])

    # ------------------------------------------------------------------ 폴링 루프
    async def poll(self) -> list[LogEvent]:
        if self.auth_mode == "vsphere" and time.time() > self._token_exp:
            await self.login()
        out: list[LogEvent] = []
        now = time.time()
        t_api = time.perf_counter()
        if now - self._last_status >= self.status_interval or self.first_poll:
            self._last_status = now
            for fn in (self._readyz, self._nodes, self._pods) + ((self._capi,) if self.role == "supervisor" or self.cfg.get("capi") else ()):
                try:
                    out += await fn()
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        raise
                    self._state["checks"][fn.__name__.strip("_")] = f"HTTP {e.response.status_code}"
        if self.topo_on and (now - self._last_topo >= self.topo_interval or self.first_poll):
            self._last_topo = now
            try:
                await self._topology()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    raise
                self._state["checks"]["구성도"] = f"HTTP {e.response.status_code}"
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["구성도"] = f"{type(e).__name__}: {e}"[:150]
        if self.log_namespaces and self.inv["pods"]:
            try:
                out += await self._follow_logs()
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["파드 로그"] = f"{type(e).__name__}: {e}"[:150]
        if not self._rv or not self.cluster_scope:
            await self._events_list()
        self._api_ms = int((time.perf_counter() - t_api) * 1000)      # watch 대기 시간 제외한 API 지연
        if self.cluster_scope and self._rv:
            try:
                await self._events_watch(min(self.interval, 55))
            except (httpx.ReadTimeout, httpx.RemoteProtocolError):
                pass
        elif not self.first_poll:
            await asyncio.sleep(self.interval)         # 네임스페이스 범위: watch 없이 주기 목록(첫 회는 바로 상태 반영)
        return out

    async def run(self) -> None:
        """기본 루프와 같되, poll 안의 watch 가 interval 만큼 대기하므로 성공 후 대기는 1초(실시간성 유지)."""
        if not self.enabled:
            return
        backoff, authed = 1.0, False
        while True:
            t0 = time.perf_counter()
            try:
                if not authed:
                    await asyncio.wait_for(self.login(), timeout=self.poll_timeout)
                    authed = True
                for e in await asyncio.wait_for(self.poll(), timeout=self.poll_timeout + self.interval):
                    await self.emit(e)
                    self._state["events_total"] += 1
                self._state["polls"] += 1
                self.first_poll = False
                self._mark(True, t0)
                self._state["latency_ms"] = getattr(self, "_api_ms", self._state["latency_ms"])
                backoff = 1.0
            except asyncio.TimeoutError:
                authed = False
                self._state["timeouts"] = self._state.get("timeouts", 0) + 1
                self._mark(False, t0, f"폴링 시간 초과({int(self.poll_timeout)}초) — API 서버 응답 없음")
                backoff = min(max(backoff * 2, self.interval), 300)
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    authed = False
                    self._state["auth"] = f"재인증 필요({e.response.status_code})"
                self._mark(False, t0, f"HTTP {e.response.status_code} {e.request.url.path}: {e.response.text[:200]}")
                backoff = min(max(backoff * 2, self.interval), 300)
            except Exception as e:  # noqa: BLE001
                authed = False
                self._mark(False, t0, f"{type(e).__name__}: {e}")
                backoff = min(max(backoff * 2, self.interval), 300)
            await asyncio.sleep(backoff if backoff <= 1.0 else backoff * random.uniform(0.8, 1.2))

    async def checks(self) -> dict[str, Any]:
        await self.login()
        res: dict[str, Any] = {"인증": "ok " + self._state["auth"], "GET /version": self._state["checks"].get("version", "ok")}
        res["GET /readyz"] = await self._probe("GET", "/readyz")

        async def probe(path: str, label: str, missing_note: str, namespaced: bool = True) -> None:
            r = await self._probe("GET", path, params={"limit": 1})
            if r != "ok" and namespaced and self.namespaces:
                grp, rs = path.rsplit("/", 1)
                r2 = await self._probe("GET", f"{grp}/namespaces/{self.namespaces[0]}/{rs}", params={"limit": 1})
                r = f"warn: 클러스터 범위 불가({r}) → 네임스페이스 범위 {r2}" if r2 == "ok" else r
            if r != "ok" and not r.startswith("warn") and r.startswith("HTTP 403"):
                r = f"warn: {r} — {missing_note}"
            res[label] = r
        await probe("/api/v1/events", "GET events", "이벤트 수집 불가 — events list/watch 권한 필요")
        await probe("/api/v1/pods", "GET pods", "파드 상태 감시 제외")
        if self.topo_on:
            await probe("/apis/apps/v1/deployments", "GET deployments", "구성도에서 워크로드 제외 — apps list 권한 필요")
            await probe("/api/v1/services", "GET services", "구성도에서 Service 제외")
        await probe("/api/v1/nodes", "GET nodes", "노드 상태 감시 제외 — nodes list 권한(클러스터 범위) 필요", namespaced=False)
        if self.role == "supervisor":
            await probe("/apis/cluster.x-k8s.io/v1beta1/machines", "GET CAPI machines", "워커 VM 수명주기 감시 제외")
        if str(res.get("GET events", "")).startswith("warn: HTTP"):       # 이벤트는 핵심 — 불가하면 실패
            res["GET events"] = res["GET events"].removeprefix("warn: ")
        return res
