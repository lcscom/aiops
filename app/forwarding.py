"""로그 전송 설정 점검·적용 — 각 제품이 이 서버(syslog.advertise_host)로 로그를 실제로 보내도록 구성됐는지 확인.

  ESXi            Syslog.global.logHost(호스트별) + 방화벽 syslog 룰셋          [자동 적용: 승인 조치]
  vCenter         /api/appliance/logging/forwarding (최대 3개)                  [자동 적용: 승인 조치]
  VKS Supervisor  컨트롤 플레인 VM 은 vCenter 원격 syslog 설정을 5분 주기로 상속 + Fluent Bit(fluentbit-config-custom)
  NSX Manager/Edge /api/v1/cluster/{node}/node/services/syslog/exporters ·
                   /api/v1/transport-nodes/{edge}/node/services/syslog/exporters [자동 적용: 승인 조치]
  NSX ALB(Avi)    alertsyslogconfig + Alert Action(Syslog) — 점검 + 절차 안내
  VKS 워크로드     Fluent Bit 표준 패키지(fluent-bit.tanzu.vmware.com) 설치 여부 + data-values 생성
  SRM · VCF Ops   어플라이언스 관리 UI(5480) 원격 syslog — 수신 이력으로 점검 + 절차 안내
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

FWD_ACTIONS = ("esxi.syslog.add", "vcenter.syslog.forward", "nsx.syslog.add")


class ForwardingAuditor:
    def __init__(self, engine):
        self.e = engine

    # ------------------------------------------------------------------ 대상(이 서버)
    def target(self) -> dict[str, Any]:
        sc = self.e.cfg.get("syslog") or {}
        host = sc.get("advertise_host") or ""
        if not host:
            pu = (self.e.cfg.get("server") or {}).get("public_url") or ""
            host = urlparse(pu).hostname or ""
        proto = str(sc.get("advertise_protocol", "udp")).lower()
        port = int((sc.get("tls") or {}).get("port", 6514)) if proto == "tls" else int(sc.get("tcp_port" if proto == "tcp" else "udp_port", 514))
        return {"host": host, "port": port, "protocol": proto,
                "esxi_uri": f"{'ssl' if proto == 'tls' else proto}://{host}:{port}" if host else "",
                "ok": bool(host), "hint": "" if host else "config.yaml syslog.advertise_host(또는 server.public_url) 에 이 서버 주소를 지정하세요"}

    def _match(self, server: str, port: Any = None) -> bool:
        t = self.target()
        s = (server or "").lower().strip()
        if "://" in s:                      # ESXi 형식 udp://host:514
            u = urlparse(s)
            s, port = (u.hostname or ""), u.port
        if not t["host"] or not s:
            return False
        th = t["host"].lower()
        same = s == th or s.split(".")[0] == th.split(".")[0] and (s.count(".") == 0 or th.count(".") == 0)
        return same and (port in (None, "", 0) or int(port) == t["port"])

    def _conns(self, kind: str) -> list:
        return [c for c in self.e.connectors if getattr(c, "type", "") == kind and not c.name.startswith("demo-")]

    def _received(self, names: list[str], within: float = 3600) -> dict[str, float]:
        """syslog 수신 이력(수집 현황) — 이름/IP 일부 일치"""
        now, out = time.time(), {}
        for it in self.e.collection.items.values():
            if it.kind != "syslog" or not it.last or now - it.last > within:
                continue
            for n in names:
                if n and (n.lower().split(".")[0] in it.name.lower() or n.lower() in (it.target or "").lower()):
                    out[n] = it.last
        return out

    # ------------------------------------------------------------------ 개별 점검
    async def _vcenter(self) -> list[dict]:
        rows = []
        for c in self._conns("vcenter"):
            row = {"product": "vCenter", "connector": c.name, "target": c.host, "kind": "vcenter"}
            try:
                cfg = await c.vc_forwarding()
                if cfg is None:
                    row.update(status="error", detail="vCenter REST 세션 없음(/api/session) — 확인 불가")
                else:
                    row["current"] = [f"{x.get('protocol', '')}://{x.get('hostname', '')}:{x.get('port', '')}" for x in cfg]
                    ok = any(self._match(x.get("hostname", ""), x.get("port")) for x in cfg)
                    row.update(status="ok" if ok else "missing",
                               detail="원격 syslog 에 이 서버 등록됨" if ok else "이 서버가 원격 syslog 대상에 없음")
                    if not ok:
                        row["action"] = {"action": "vcenter.syslog.forward", "connector": c.name, "params": {"target": self.target()["host"]}}
            except Exception as e:  # noqa: BLE001
                row.update(status="error", detail=f"{type(e).__name__}: {e}"[:200])
            rows.append(row)
            # Supervisor 컨트롤 플레인 VM: vCenter 원격 syslog 상속(WCP 서비스가 5분 주기로 반영)
            rows.append({"product": "VKS Supervisor(컨트롤 플레인 VM)", "connector": c.name, "target": f"{c.host} 의 Supervisor",
                         "kind": "supervisor-inherit", "status": row.get("status") if row.get("status") in ("ok", "missing") else "unknown",
                         "detail": "vCenter 원격 syslog 설정을 상속(반영까지 5분+). 활성화 후에는 Fluent Bit 가 기본 전달자",
                         "current": row.get("current")})
        return rows

    async def _esxi(self) -> list[dict]:
        rows = []
        t = self.target()
        for c in self._conns("vcenter"):
            try:
                hosts = await asyncio.to_thread(c.esxi_syslog)
            except Exception as e:  # noqa: BLE001
                rows.append({"product": "ESXi", "connector": c.name, "target": "(전체)", "kind": "esxi", "status": "error",
                             "detail": f"{type(e).__name__}: {e}"[:200]})
                continue
            recv = self._received([h["host"] for h in hosts])
            by_cluster: dict[str, list[dict]] = {}
            for h in hosts:
                by_cluster.setdefault(h["cluster"] or "(standalone)", []).append(h)
            for cl, hs in sorted(by_cluster.items()):
                missing = [h for h in hs if h.get("connection") == "connected" and not any(self._match(v) for v in h["loghost"].split(",") if v.strip())]
                fw_off = [h["host"] for h in hs if h.get("firewall") is False]
                err = [h for h in hs if h.get("error")]
                status = "ok" if not missing and not fw_off else "missing"
                row = {"product": "ESXi", "connector": c.name, "target": f"클러스터 {cl} ({len(hs)}대)", "kind": "esxi",
                       "status": status, "hosts": [{**h, "configured": h not in missing, "receiving": h["host"] in recv} for h in hs],
                       "detail": ("전 호스트 전송 설정됨" if status == "ok" else
                                  f"미설정 {len(missing)}대" + (f" · 방화벽 syslog 룰셋 꺼짐 {len(fw_off)}대" if fw_off else ""))
                                 + (f" · 확인 불가 {len(err)}대" if err else "") + f" · 최근 1시간 수신 {sum(1 for h in hs if h['host'] in recv)}대"}
                if status != "ok" and t["ok"]:
                    row["action"] = {"action": "esxi.syslog.add", "connector": c.name, "params": {"scope": cl}}
                rows.append(row)
        return rows

    async def _nsx_nodes(self, c) -> list[dict]:
        """[{kind: manager|edge, id, name, path}]"""
        nodes = []
        r = await c.http.get("/api/v1/cluster")
        if r.status_code < 300:
            for n in r.json().get("nodes") or []:
                if n.get("node_uuid"):
                    nodes.append({"kind": "manager", "id": n["node_uuid"], "name": n.get("fqdn") or n["node_uuid"],
                                  "path": f"/api/v1/cluster/{n['node_uuid']}/node/services/syslog/exporters"})
        if not nodes:
            nodes.append({"kind": "manager", "id": "local", "name": c.host, "path": "/api/v1/node/services/syslog/exporters"})
        if not c.edges:
            await c._refresh_edges()
        for tid, name in c.edges.items():
            nodes.append({"kind": "edge", "id": tid, "name": name, "path": f"/api/v1/transport-nodes/{tid}/node/services/syslog/exporters"})
        return nodes

    async def _nsx(self) -> list[dict]:
        rows = []
        for c in self._conns("nsx"):
            try:
                c.http.auth = (c.cfg["username"], c.cfg["password"])
                nodes = await self._nsx_nodes(c)
                for n in nodes:
                    r = await c.http.get(n["path"])
                    if r.status_code >= 300:
                        n.update(status="error", detail=f"HTTP {r.status_code}")
                        continue
                    ex = r.json().get("results") or []
                    n["current"] = [f"{x.get('protocol', '')}://{x.get('server', '')}:{x.get('port', '')} ({x.get('level', '')})" for x in ex]
                    n["status"] = "ok" if any(self._match(x.get("server", ""), x.get("port")) for x in ex) else "missing"
                for kind, label in (("manager", "NSX Manager"), ("edge", "NSX Edge")):
                    ns = [n for n in nodes if n["kind"] == kind]
                    if not ns:
                        continue
                    miss = [n for n in ns if n.get("status") == "missing"]
                    errs = [n for n in ns if n.get("status") == "error"]
                    row = {"product": label, "connector": c.name, "target": f"{len(ns)}개 노드", "kind": f"nsx-{kind}",
                           "status": "error" if errs and not miss and len(errs) == len(ns) else ("missing" if miss else "ok"),
                           "nodes": ns, "detail": (f"미설정 {len(miss)}개" if miss else "전 노드 전송 설정됨") + (f" · 확인 실패 {len(errs)}개" if errs else "")}
                    if miss and self.target()["ok"]:
                        row["action"] = {"action": "nsx.syslog.add", "connector": c.name, "params": {"scope": kind + "s"}}
                    rows.append(row)
            except Exception as e:  # noqa: BLE001
                rows.append({"product": "NSX", "connector": c.name, "target": c.host, "kind": "nsx", "status": "error",
                             "detail": f"{type(e).__name__}: {e}"[:200]})
        return rows

    async def _avi(self) -> list[dict]:
        rows = []
        t = self.target()
        for c in self._conns("avi"):
            row = {"product": "NSX ALB(Avi)", "connector": c.name, "target": c.host, "kind": "avi"}
            try:
                r = await c.http.get("/api/alertsyslogconfig", params={"page_size": 100})
                if r.status_code == 401:
                    await c.login()
                    r = await c.http.get("/api/alertsyslogconfig", params={"page_size": 100})
                r.raise_for_status()
                cur = []
                for o in r.json().get("results") or []:
                    for s in o.get("syslog_servers") or []:
                        cur.append(f"{o.get('name')}: {'udp' if s.get('udp', True) else 'tcp'}://{s.get('syslog_server')}:{s.get('syslog_server_port', 514)}")
                ok = any(self._match(x.split("://", 1)[-1].rsplit(":", 1)[0], x.rsplit(":", 1)[-1]) for x in cur)
                row.update(current=cur, status="ok" if ok else "missing",
                           detail="Syslog 알림 대상 등록됨 — Alert Action 에 연결됐는지 확인" if ok else "Syslog 알림 대상에 이 서버 없음(이벤트 API 수집은 별도로 동작)")
            except Exception as e:  # noqa: BLE001
                row.update(status="error", detail=f"{type(e).__name__}: {e}"[:200])
            row["guide"] = (f"Operations > Notifications > Syslog: 서버 {t['host'] or '<이 서버>'}, 포트 {t['port'] if t['protocol'] != 'tls' else 514}\n"
                            "Operations > Alerts > Alert Actions: 'Syslog-Audit-Persistence' 를 템플릿으로 위 Syslog 알림 선택\n"
                            "Operations > Alerts > Alert Config: 수집할 이벤트(예: VS_DOWN, SE_DOWN, POOL_DOWN, CONTROLLER_NODE_*) 조건에 Alert Action 연결\n"
                            "(UI 기본 UDP — TCP 는 CLI: configure alertsyslogconfig <이름> → syslog_servers index 1 → no udp → save)")
            rows.append(row)
        return rows

    async def _vks(self) -> list[dict]:
        rows = []
        t = self.target()
        for c in self._conns("vks"):
            if c.role == "supervisor":
                row = {"product": "VKS Supervisor(Fluent Bit)", "connector": c.name, "target": c.cluster_label, "kind": "vks-supervisor"}
                try:
                    r = await c.http.get("/api/v1/namespaces/vmware-system-logging/configmaps/fluentbit-config-custom")
                    if r.status_code == 200:
                        out = (r.json().get("data") or {}).get("outputs-custom.conf", "")
                        ok = bool(t["host"]) and t["host"].lower() in out.lower()
                        row.update(status="ok" if ok else "missing", detail="Fluent Bit 출력에 이 서버 등록됨" if ok else "fluentbit-config-custom 에 이 서버 출력 없음")
                    else:
                        row.update(status="unknown", detail=f"ConfigMap 조회 불가(HTTP {r.status_code}) — SSO 관리자로 확인")
                except Exception as e:  # noqa: BLE001
                    row.update(status="error", detail=f"{type(e).__name__}: {e}"[:200])
                row["guide"] = self.supervisor_snippet()
            else:
                row = {"product": "VKS 워크로드 클러스터(Fluent Bit)", "connector": c.name, "target": c.cluster_label, "kind": "vks-workload"}
                try:
                    r = await c.http.get("/apis/packaging.carvel.dev/v1alpha1/packageinstalls")
                    if r.status_code == 200:
                        fb = [f"{(p.get('metadata') or {}).get('namespace')}/{(p.get('metadata') or {}).get('name')} "
                              f"({((p.get('status') or {}).get('friendlyDescription') or '')})"
                              for p in r.json().get("items") or [] if str((p.get("spec") or {}).get("packageRef", {}).get("refName", "")).startswith("fluent-bit")]
                        row.update(current=fb, status="installed" if fb else "missing",
                                   detail="Fluent Bit 패키지 설치됨 — data-values 의 syslog 출력 대상 확인" if fb else "Fluent Bit 패키지 미설치")
                    elif r.status_code == 404:
                        row.update(status="missing", detail="PackageInstall API 없음(kapp-controller·표준 패키지 저장소 미구성) — Fluent Bit 미설치")
                    else:
                        row.update(status="unknown", detail=f"PackageInstall 조회 불가(HTTP {r.status_code}) — packageinstalls get/list 권한 필요")
                except Exception as e:  # noqa: BLE001
                    row.update(status="error", detail=f"{type(e).__name__}: {e}"[:200])
                recv = self._received([c.cluster_label])
                if recv:
                    row["detail"] += " · 최근 1시간 syslog 수신 있음"
                row["guide"] = self.workload_snippet(c.cluster_label)
            rows.append(row)
        return rows

    async def _appliances(self) -> list[dict]:
        rows = []
        t = self.target()
        for kind, label, path in (("srm", "Site Recovery Manager", "https://<SRM>:5480 > Syslog Configuration(원격 syslog 서버 추가)"),
                                  ("vcfops", "VCF Operations", "관리 UI > 관리 > 로그 전달(외부 syslog) — 또는 각 노드 어플라이언스 설정"),
                                  ("sddc", "SDDC Manager", "SDDC Manager VM rsyslog(/etc/rsyslog.d) 또는 VCF 로그 전달 구성")):
            for c in self._conns(kind):
                host = c.host.split(":")[0]
                recv = self._received([host])
                rows.append({"product": label, "connector": c.name, "target": host, "kind": kind,
                             "status": "receiving" if recv else "not-seen",
                             "detail": "최근 1시간 이 서버로 syslog 수신 중" if recv else "최근 1시간 syslog 수신 이력 없음(API 수집은 별도 동작)",
                             "guide": f"{path}\n대상: {t['host'] or '<이 서버>'}  포트 {t['port']}  프로토콜 {t['protocol'].upper()}"})
        return rows

    async def check_all(self) -> dict[str, Any]:
        parts = await asyncio.gather(self._vcenter(), self._esxi(), self._nsx(), self._avi(), self._vks(), self._appliances(),
                                     return_exceptions=True)
        rows: list[dict] = []
        for p in parts:
            if isinstance(p, Exception):
                rows.append({"product": "점검 오류", "status": "error", "detail": f"{type(p).__name__}: {p}"[:200]})
            else:
                rows += p
        return {"target": self.target(), "rows": rows, "generated": time.time(),
                "summary": {s: sum(1 for r in rows if r.get("status") == s) for s in {r.get("status") for r in rows}}}

    # ------------------------------------------------------------------ 안내 스니펫(그대로 붙여넣기)
    def supervisor_snippet(self) -> str:
        t = self.target()
        mode = "tcp" if t["protocol"] in ("tcp", "tls") else "udp"
        tls = "\n    Tls             on\n    Tls.verify      on\n    Tls.ca_file     /etc/ssl/certs/ca-certificates.crt" if t["protocol"] == "tls" else ""
        return ("# kubectl vsphere login --server=<Supervisor> -u administrator@vsphere.local\n"
                "# kubectl -n vmware-system-logging edit configmap fluentbit-config-custom  → outputs-custom.conf 에 추가\n"
                "[OUTPUT]\n    Name            syslog\n    Match           system*\n"
                f"    Host            {t['host'] or '<이 서버>'}\n    Port            {t['port']}\n    Mode            {mode}\n"
                "    Syslog_Format   rfc5424\n    Syslog_Message_key  log\n    Syslog_Hostname_key hostname\n"
                f"    Syslog_Appname_key  appname\n    Syslog_Msgid_key    filename{tls}\n")

    def workload_snippet(self, cluster: str) -> str:
        t = self.target()
        mode = "tcp" if t["protocol"] in ("tcp", "tls") else "udp"
        return (f"# VKS 워크로드 클러스터 '{cluster}' — Fluent Bit 표준 패키지(fluent-bit.tanzu.vmware.com) data-values\n"
                "# 스키마는 패키지 버전별로 다를 수 있음: kubectl -n tkg-system get packages | grep fluent-bit 후 해당 버전의 values-schema 확인\n"
                "namespace: tanzu-system-logging\n"
                "fluent_bit:\n  config:\n    outputs: |\n      [OUTPUT]\n          Name            syslog\n          Match           kube.*\n"
                f"          Host            {t['host'] or '<이 서버>'}\n          Port            {t['port']}\n          Mode            {mode}\n"
                "          Syslog_Format   rfc5424\n          Syslog_Hostname_key  hostname\n          Syslog_Appname_key   app\n"
                "          Syslog_Message_key   log\n"
                f"# 수신 측 분류: config.yaml syslog.host_map 에 {{match: \"^{cluster}-\", source: vks}} 를 추가하면 확실합니다\n")

    # ------------------------------------------------------------------ 조치(ActionGate 에서 호출) — 미리보기
    def _conn(self, name: str, kind: str):
        for c in self.e.connectors:
            if c.name == name and c.type == kind:
                return c
        raise KeyError(f"{kind} 커넥터 '{name}' 없음")

    async def preview(self, action: str, connector: str, params: dict) -> dict[str, Any]:
        t = self.target()
        br: dict[str, Any] = {"target": f"{t['protocol']}://{t['host']}:{t['port']}"}
        blockers: list[str] = [] if t["ok"] else [t["hint"]]
        if action == "vcenter.syslog.forward":
            c = self._conn(connector, "vcenter")
            cfg = await c.vc_forwarding()
            if cfg is None:
                return {"blast_radius": br, "blockers": blockers + ["vCenter REST 세션 없음 — 설정 불가"]}
            br.update(vcenter=c.host, current=cfg, after=cfg + [{"hostname": t["host"], "port": t["port"], "protocol": t["protocol"].upper()}],
                      note="vCenter 원격 syslog 는 Supervisor 컨트롤 플레인 VM 에도 5분 내 전파됩니다(대량 트래픽 주의)")
            if any(self._match(x.get("hostname", ""), x.get("port")) for x in cfg):
                blockers.append("이미 등록되어 있습니다")
            if len(cfg) >= 3:
                blockers.append("vCenter 원격 syslog 대상은 최대 3개 — 기존 대상을 먼저 정리하세요")
        elif action == "esxi.syslog.add":
            c = self._conn(connector, "vcenter")
            hosts = await asyncio.to_thread(c.esxi_syslog)
            scope = params.get("scope", "")
            sel = [h for h in hosts if h.get("connection") == "connected" and (scope in ("all", "*") or (h["cluster"] or "(standalone)") == scope or h["host"] == scope)]
            todo = [h for h in sel if not any(self._match(v) for v in h["loghost"].split(",") if v.strip()) or h.get("firewall") is False]
            br.update(vcenter=c.host, scope=scope, hosts=[{"host": h["host"], "current": h["loghost"], "firewall_syslog": h.get("firewall")} for h in todo],
                      new_value_example=(todo[0]["loghost"] + "," if todo and todo[0]["loghost"] else "") + t["esxi_uri"],
                      note="기존 logHost 는 유지하고 이 서버만 추가 · 방화벽 'syslog' 룰셋 활성화(아웃바운드 514/1514)")
            if not sel:
                blockers.append(f"대상 호스트 없음(범위 '{scope}')")
            elif not todo:
                blockers.append("모든 대상 호스트에 이미 설정되어 있습니다")
        elif action == "nsx.syslog.add":
            c = self._conn(connector, "nsx")
            c.http.auth = (c.cfg["username"], c.cfg["password"])
            nodes = await self._nsx_nodes(c)
            scope = params.get("scope", "all")
            sel = [n for n in nodes if scope == "all" or n["kind"] + "s" == scope]
            todo = []
            for n in sel:
                r = await c.http.get(n["path"])
                ex = r.json().get("results") or [] if r.status_code < 300 else []
                if r.status_code >= 300:
                    n["error"] = f"HTTP {r.status_code}"
                if not any(self._match(x.get("server", ""), x.get("port")) for x in ex):
                    todo.append({"kind": n["kind"], "name": n["name"], "current": [x.get("server") for x in ex], "error": n.get("error")})
            if t["protocol"] == "tls" and not (self.e.cfg.get("syslog") or {}).get("tls", {}).get("ca_file"):
                blockers.append("TLS 전송은 syslog.tls.ca_file(서버 인증서 발급 CA PEM) 지정 필요")
            br.update(nsx=c.host, scope=scope, nodes=todo,
                      exporter={"exporter_name": "vcf-aiops", "server": t["host"], "port": t["port"],
                                "protocol": t["protocol"].upper(), "level": params.get("level", "INFO")})
            if not todo:
                blockers.append("모든 대상 노드에 이미 설정되어 있습니다")
        else:
            blockers.append(f"지원하지 않는 조치: {action}")
        return {"blast_radius": br, "blockers": blockers}

    async def execute(self, action: str, connector: str, params: dict) -> dict[str, Any]:
        t = self.target()
        if action == "vcenter.syslog.forward":
            c = self._conn(connector, "vcenter")
            cfg = await c.vc_forwarding() or []
            new = [{"hostname": x["hostname"], "port": x["port"], "protocol": x["protocol"]} for x in cfg]
            new.append({"hostname": t["host"], "port": t["port"], "protocol": t["protocol"].upper()})
            return await c.vc_forwarding_set(new)
        if action == "esxi.syslog.add":
            c = self._conn(connector, "vcenter")
            hosts = await asyncio.to_thread(c.esxi_syslog)
            scope = params.get("scope", "")
            sel = [h["host"] for h in hosts if h.get("connection") == "connected"
                   and (scope in ("all", "*") or (h["cluster"] or "(standalone)") == scope or h["host"] == scope)]
            res = await asyncio.to_thread(c.esxi_syslog_add, sel, t["esxi_uri"])
            bad = [r for r in res if r["result"] != "success"]
            return {"result": "success" if not bad else ("error" if len(bad) == len(res) else "success"), "hosts": res,
                    "error": f"{len(bad)}대 실패" if bad else ""}
        if action == "nsx.syslog.add":
            c = self._conn(connector, "nsx")
            c.http.auth = (c.cfg["username"], c.cfg["password"])
            nodes = await self._nsx_nodes(c)
            scope = params.get("scope", "all")
            body: dict[str, Any] = {"exporter_name": "vcf-aiops", "server": t["host"], "port": t["port"],
                                    "protocol": t["protocol"].upper(), "level": params.get("level", "INFO")}
            ca = (self.e.cfg.get("syslog") or {}).get("tls", {}).get("ca_file")
            if t["protocol"] == "tls" and ca:
                body["tls_ca_pem"] = open(ca, encoding="utf-8").read()
            res = []
            for n in [n for n in nodes if scope == "all" or n["kind"] + "s" == scope]:
                g = await c.http.get(n["path"])
                ex = g.json().get("results") or [] if g.status_code < 300 else []
                if any(self._match(x.get("server", ""), x.get("port")) for x in ex):
                    res.append({"node": n["name"], "result": "skip(이미 설정)"})
                    continue
                r = await c.http.post(n["path"], json=body)
                res.append({"node": n["name"], "kind": n["kind"], "result": "success" if r.status_code < 300 else "error",
                            "http": r.status_code, "error": r.text[:200] if r.status_code >= 300 else ""})
            bad = [r for r in res if r["result"] == "error"]
            return {"result": "error" if bad and len(bad) == len(res) else "success", "nodes": res, "error": f"{len(bad)}개 실패" if bad else ""}
        raise ValueError(f"지원하지 않는 조치: {action}")
