"""데모/검증용 합성 로그 생성기 — 실제 장비 없이 UI·탐지·LLM 파이프라인 확인. (demo.enabled 또는 AIOPS_DEMO=1)"""
from __future__ import annotations

import asyncio
import random
import re
import time

from .. import protection as PR
from .. import sli as SLI
from ..models import LogEvent
from .base import Connector

HOSTS = [f"esx{n:02d}.vcf.lab" for n in range(1, 9)]
VMS = ["core-bank-db01", "core-bank-was02", "mobile-api-03", "card-auth-01", "hr-web-01", "ai-infer-01", "edge-gw-01"]

NORMAL = {
    "arista": [("info", "Lldp", "%LLDP-5-NEIGHBOR_NEW: LLDP neighbor with chassisId 0050.56{h} and portId \"vmnic{c}\" added on interface Ethernet{p}"),
               ("info", "Aaa", "%AAA-6-EXEC_CMD: user aiops-ro executed show interfaces status"),
               ("info", "Bgp", "%BGP-5-ADJCHANGE: peer 10.255.1.{c} (VRF default AS 6510{c}) old state OpenConfirm event RecvKeepAlive new state Established")],
    "cisco": [("info", "", "%ETHPORT-5-IF_UP: Interface Ethernet1/{p} is up in mode access"),
              ("info", "", "%VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by aiops-ro on 10.20.0.{c}@pts/0"),
              ("info", "", "%LLDP-5-SERVER_ADDED: Server with Chassis ID 0050.56{h} Port ID vmnic{c} management address 10.10.0.{p} discovered on local port Ethernet1/{p}")],
    "esxi": [("info", "hostd", "Event {n} : User root@127.0.0.1 logged in as pyvmomi Python/3.11"),
             ("info", "vmkernel", "cpu{c}:{p})NetPort: 1632: disabled port 0x{h}"),
             ("info", "vpxa", "[Originator@6876 sub=vpxLro] -- FINISH task-{n} -- -- vim.host.NetworkSystem.queryNetworkHint"),
             ("info", "vobd", "[UserLevelCorrelator] {n}us: [vob.user.vmsyslogd.remote.reconnected] Reconnected to remote syslog")],
    "vcenter": [("info", "", "Task: Migrate virtual machine {vm} completed"),
                ("info", "", "User VSPHERE.LOCAL\\svc-backup logged in from 10.10.{c}.{p}"),
                ("info", "", "Reconfigured {vm} on {host} in Cluster-01"),
                ("info", "", "Created snapshot of {vm} for backup job {n}")],
    "nsx": [("info", "nsx-proxy", "Connected to controller 10.0.0.{p}"),
            ("info", "cfgagent", "Rule section {n} realized on transport node {host}"),
            ("info", "frr", "BGP keepalive received from neighbor 172.16.{c}.1")],
    "vcfops": [("info", "", "Collection cycle completed for adapter VMWARE vCenter-01 ({n} objects)")],
    "vcfa": [("info", "", "배포 'dev-ns-{n}' 상태 CREATE_SUCCESSFUL")],
    "avi": [("info", "", "Virtual Service vs-mobile-api health score 95")],
    "srm": [("info", "", "Recovery plan 'Core-Banking-DR' status READY")],
    "redfish": [("info", "", "[IEL] Server power restored, system check passed")],
    "sddc": [("info", "", "SDDC Manager 작업 'Rotate passwords' 상태 SUCCESSFUL")],
    "nsx-edge": [("info", "datapathd", "Edge datapath stats: rx 1.2Mpps tx 1.1Mpps, drops 0"),
                 ("info", "frr", "BFD session to 172.16.20.{c} Up")],
    "vks-supervisor": [("info", "kube-apiserver", "GET /apis/vmoperator.vmware.com/v1alpha3/virtualmachines 200"),
                       ("info", "wcp", "Supervisor domain-c8 config status RUNNING")],
    "vks": [("info", "kubelet", "Successfully pulled image \"harbor.vcf.lab/bank/core-api:1.{c}\""),
            ("info", "containerd", "StartContainer for \"app\" returns successfully")],
}

INCIDENTS = [
    ("arista", "warning", "Ebra", "%LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet8, changed state to down"),
    ("arista", "critical", "Mlag", "%MLAG-4-INTF_INACTIVE_LOCAL: Local interface Port-Channel1{c} is link down. MLAG 1{c} is inactive."),
    ("cisco", "error", "", "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/50 is down (Link failure)"),
    ("cisco", "critical", "", "%VPC-2-PEER_KEEP_ALIVE_RECV_FAIL: In domain 10, VPC peer keep-alive receive has failed"),
    ("esxi", "critical", "vmkernel", "WARNING: NMP: nmp_DeviceStartLoop:740: NMP Device \"naa.600a098038304{h}\" is blocked. Not starting I/O from device. Device state in doubt"),
    ("esxi", "critical", "vobd", "[vob.storage.apd.start] Device or filesystem with identifier [naa.600a0980383{h}] has entered the All Paths Down state."),
    ("esxi", "error", "vmkernel", "vSAN: DOM object {u} state changed to degraded, absent component on disk naa.5000c50{h}"),
    ("esxi", "error", "vmkernel", "vmnic3: link is down, uplink lost on vDS-Prod"),
    ("vcenter", "critical", "", "vSphere HA detected a host isolation event for {host} in cluster Cluster-01"),
    ("vcenter", "warning", "", "Virtual machine {vm} disks consolidation is needed"),
    ("vcenter", "error", "", "Cannot synchronize host {host}. Host is not responding"),
    ("nsx", "error", "frr", "BGP neighbor 172.16.10.1 state changed from Established to Idle (Hold Timer Expired)"),
    ("nsx", "error", "", "[Transport Node/Tunnel Down] Overlay tunnel from TEP 192.168.50.{p} to 192.168.50.{c} is down"),
    ("vcfops", "critical", "", "Datastore 'vsan-ds-01' is running out of disk space [CRITICAL/HEALTH] status=ACTIVE"),
    ("redfish", "critical", "", "[IML] Uncorrectable Memory Error detected. Processor 1, DIMM 7"),
    ("redfish", "error", "", "[IML] Power Supply Failure - Bay 2. Power redundancy lost"),
    ("avi", "error", "", "Virtual Service vs-card-auth oper_status=OPER_DOWN Pool pool-card-auth all servers down"),
    ("srm", "error", "", "Recovery Plan Core-Banking-DR: RPO violation detected for 3 VMs in protection group PG-Core"),
    ("vcfa", "warning", "", "배포 'prod-k8s-07' 상태 CREATE_FAILED Insufficient capacity in zone az-1"),
    ("sddc", "error", "", "SDDC Manager 작업 'Certificate replacement' 상태 FAILED — certificate for nsx-mgr expired"),
    ("nsx-edge", "critical", "datapathd", "datapathd core dump detected on edge-node-02, restarting dataplane"),
    ("nsx-edge", "critical", "", "T0 gateway T0-Prod service router HA state changed ACTIVE -> STANDBY on edge-node-01"),
    ("vks-supervisor", "critical", "etcd", "etcdserver: request timed out, possibly due to previous leader failure"),
    ("vks-supervisor", "error", "", "VKS Machine prod-ns/wld-bank01-workers-{h} (클러스터 wld-bank01) — VirtualMachine failed: insufficient resources in zone az-1"),
    ("vks", "error", "", "[BackOff] Pod prod-ns/core-api-7d9f{c}: Back-off restarting failed container app (x7)"),
    ("vks", "error", "", "[FailedMount] Pod prod-ns/core-db-0: MountVolume.SetUp failed for volume pvc-{u}: CnsFault"),
    ("vcenter", "critical", "vpxd", "vmon: Service vpxd exited unexpectedly, restarting (exit code 139)"),
    ("avi", "critical", "", "[SE_DOWN] Avi-SE-{h}: Service Engine down — heartbeat failure"),
    ("vcenter", "warning", "", "Failed login attempt for user administrator@vsphere.local from 203.0.113.{p}: invalid credentials"),
]


DEMO_ENTITIES = {
    "vcenter": [{"name": h, "kind": "host", "group": "Cluster-01" if i < 4 else "Cluster-02",
                 "state": "maint" if i == 6 else "ok", "detail": "connected · green" + (" · 유지보수 모드" if i == 6 else "")}
                for i, h in enumerate(HOSTS)],
    "nsx": [{"name": "Manager 클러스터(nsx.vcf.lab)", "kind": "manager", "state": "ok", "detail": "management=STABLE, control=STABLE"}]
           + [{"name": f"edge-node-{n:02d}", "kind": "edge", "state": "ok", "detail": "UP"} for n in range(1, 5)],
    "avi": [{"name": f"Avi-SE-{n}", "kind": "SE", "state": "ok", "detail": "OPER_UP"} for n in range(1, 4)]
           + [{"name": v, "kind": "VS", "state": "ok", "detail": "OPER_UP"} for v in ("vs-mobile-api", "vs-card-auth", "vs-core-bank", "vs-hr-web", "vs-openbank")],
    "vks": [{"name": f"wld-bank01-workers-{x}", "kind": "node", "group": "wld-bank01", "state": "ok", "detail": "Ready=True"} for x in ("xk2p9", "m4q7d", "z8t2c", "b7n1k")]
           + [{"name": f"wld-card01-workers-{x}", "kind": "node", "group": "wld-card01", "state": "ok", "detail": "Ready=True"} for x in ("p2r8s", "q9w3e")],
}


def _fill(t: str) -> str:
    r = random.randint
    return t.format(n=r(1000, 99999), c=r(0, 47), p=r(2, 250), h=f"{r(0, 16**6):06x}",
                    u=f"{r(0, 16**8):08x}-{r(0, 16**4):04x}-4abc-9def-{r(0, 16**12):012x}",
                    vm=random.choice(VMS), host=random.choice(HOSTS))


class DemoGenerator(Connector):
    type = "demo"
    source = "demo"

    def __init__(self, cfg, emit):
        super().__init__({"name": "demo", **cfg}, emit)
        self.rate = float(cfg.get("rate", 4))
        self.fakes = []
        for t in ("vcenter", "sddc", "nsx", "vcfops", "vcflogs", "vcfa", "srm", "avi", "redfish", "vks"):
            c = Connector({"name": f"demo-{t}", "host": f"{t}.vcf.lab"}, emit)
            c.type = t
            c.demo = True
            c._state.update(type=t, source=t, state="ok", auth="ok", latency_ms=random.randint(20, 200),
                            last_ok=time.time(), checks={"데모 모드": "ok"})
            c.entities = (lambda t=t: DEMO_ENTITIES.get(t, []))
            if t == "vcenter":                          # 성능 SLI 화면 데모(합성 카운터, 5분 단위로 천천히 변함)
                c.sli_cfg = {"thresholds": dict(SLI.DEFAULT_THRESHOLDS), "drop_budget": 100.0}
                c.sli_snapshot = demo_sli
                c.topology = demo_topology()
                for _n, _v in demo_platform_vms().items():            # 2.46.0 What-If 플랫폼(Supervisor·VKS 노드·vSphere Pod·Avi) 데모 — 이 커넥터에만
                    c.topology["vms"][_n] = _v
                    c.topology["hosts"][_v["host"]]["vms"] += 1
                c.health_snap = {"hosts": {h: {"vendor": "HPE" if i < 4 else "Lenovo", "model": "ProLiant DL380 Gen11" if i < 4 else "ThinkSystem SR650 V3",
                                                "serial": f"SGH{4100 + i}X{i}", "version": "8.0.3", "build": "24022510" if i != 5 else "23299997",
                                                "bios": "U54 2.30" if i < 4 else "ESE120M", "cpu_model": "Intel(R) Xeon(R) Gold 6430", "cores": 64}
                                           for i, h in enumerate(HOSTS)}}
                c.segment_vnics = demo_seg_vnics                    # 2.21.0 세그먼트 트래픽 데모
                c.vnic_traffic = demo_vnic_traffic
                c.vm_net_history = demo_vm_net_history
                c.perf_series = demo_perf_series                    # 2.23.0 호스트·VM 성능 데모
                c.perf_latest = demo_perf_latest
                c.vks = {"supervisors": [{"name": "Cluster-02", "endpoint": "10.20.0.10", "config_status": "RUNNING",
                                          "kubernetes_status": "READY", "namespaces": ["bank", "card"]}], "updated": time.time()}
            elif t == "sddc":
                c.domains = [{"id": "d1", "name": "vcf-m01", "type": "MANAGEMENT", "status": "ACTIVE", "vcenters": ["vcenter.vcf.lab"],
                              "nsx": "nsx.vcf.lab", "clusters": 2}]
            elif t == "avi":
                c.vips = demo_vips
                vm_ips = [v["ips"][0] for v in demo_topology()["vms"].values() if v["ips"]]
                c.pools = [{"name": f"pool-{n}", "state": "OPER_UP", "servers": 4, "up": 4 if n != "batch" else 0, "health": 90,
                            "members": ([{"ip": f"192.168.50.{10 + k}", "port": 8080, "hostname": "", "enabled": True} for k in range(3)] if n == "openbank"
                                        else [{"ip": vm_ips[(i * 3 + k) % len(vm_ips)], "port": 8443, "hostname": "", "enabled": True} for k in range(3)])}
                           for i, n in enumerate(("mobile-api", "card-auth", "core-bank", "hr-web", "openbank", "batch"))]
                c.se = {f"avi-se-0{k}": {"name": f"avi-se-0{k}", "state": "OPER_UP", "se_group": "Default-Group", "host": HOSTS[k], "mgmt_ip": f"10.20.9.{k}"}
                        for k in (1, 2)}
                c.vs = {v["uuid"]: {**v, "ses": ["avi-se-01"] if i % 3 == 0 else ["avi-se-01", "avi-se-02"]} for i, v in enumerate(demo_vips())}
                c.end_users = demo_end_users
                c.controllers = {"state": "CLUSTER_UP_HA_ACTIVE", "version": "31.1.1", "nodes": [{"name": f"avi-ctrl-0{k}", "role": "CLUSTER_LEADER" if k == 1 else "CLUSTER_FOLLOWER",
                                                                                                "state": "CLUSTER_ACTIVE", "ip": f"10.20.9.{20 + k}"} for k in (1, 2, 3)]}
            elif t == "nsx":
                c.edge_info, c.edges, c.routing = demo_nsx_routing()
                c.segment_ports = demo_segment_ports
                c.inv = {"tier0": [{"id": "t0-vcf-m01", "name": "t0-vcf-m01", "ha_mode": "ACTIVE_STANDBY", "failover": "NON_PREEMPTIVE"}],
                         "tier1": [{"id": f"t1-{n}", "name": f"t1-{n}", "tier0": "t0-vcf-m01", "edge_cluster": n == "lb"} for n in ("app", "db", "lb")],
                         "segments": [{"name": f"seg-{n}", "id": f"seg-{n}", "type": "ROUTED", "connected_to": f"t1-{n if n != 'web' else 'app'}", "gateway": f"10.30.{i}.1/24",
                                       "vlan": "", "tz": "overlay-tz", "admin": "UP"} for i, n in enumerate(("web", "app", "db"))],
                         "edge_clusters": [{"name": "ec-01", "members": 2}, {"name": "ec-02", "members": 2}],
                         "projects": [{"id": "fin-proj", "name": "fin-proj", "tier0s": ["t0-vcf-m01"]}],
                         "vpcs": [{"id": "vpc-card", "name": "vpc-card", "project": "fin-proj", "project_name": "fin-proj", "tier0": "t0-vcf-m01", "short_id": "vpc-1",
                                   "private": "172.20.0.0/16", "subnets": [{"id": "card-web", "name": "card-web", "access": "Public", "cidr": "100.64.10.0/26"},
                                                                          {"id": "card-db", "name": "card-db", "access": "Private", "cidr": "172.20.1.0/24"}],
                                   "vms": ["card-auth-01", "card-auth-01-10"]},
                                  {"id": "vpc-ai", "name": "vpc-ai", "project": "fin-proj", "project_name": "fin-proj", "tier0": "t0-vcf-m01", "short_id": "vpc-2",
                                   "private": "172.21.0.0/16", "subnets": [{"id": "ai-infer", "name": "ai-infer", "access": "Private", "cidr": "172.21.1.0/24"}],
                                   "vms": ["ai-infer-01"]}], "updated": time.time()}
            elif t == "vks":
                c.role, c.cluster_label, c.discovered_by = "workload", "bank/wld-bank01", "demo-vcenter"
                c.cfg["supervisor"] = "10.20.0.10"
                W = [e["name"] for e in DEMO_ENTITIES["vks"][:4]]
                pods = [{"ns": "bank", "name": f"core-api-{i}", "node": W[i % 4], "phase": "Running",
                         "ip": f"192.168.50.{10 + i}", "host_ip": f"10.10.40.{11 + i % 4}",
                         "reason": "CrashLoopBackOff" if i == 3 else "", "ready": "0/1" if i == 3 else "1/1", "restarts": 7 if i == 3 else 0,
                         "containers": ["app"], "age": time.time() - 86400, "owner": "ReplicaSet"} for i in range(12)]
                extra = [("bank", "ledger-6f7d8c9b5-k2x7q", W[0]), ("bank", "payment-gw-5c8d7f6b9-p4m2z", W[1]), ("bank", "payment-gw-5c8d7f6b9-w8r3t", W[1])]
                extra += [("kube-system", f"etcd-{n}", n) for n in VKS_CP] + [("kube-system", f"kube-apiserver-{n}", n) for n in VKS_CP]
                extra += [("kube-system", f"antrea-agent-{x}", n) for x, n in zip(("a1b2c", "d3e4f", "g5h6j", "k7m8n", "p9q2r", "s3t4v", "w5x6z"), VKS_CP + W)]
                pods += [{"ns": ns, "name": nm, "node": nd, "phase": "Running", "ip": "", "host_ip": "", "reason": "", "ready": "1/1", "restarts": 0, "containers": ["c"],
                          "age": time.time() - 86400, "owner": ""} for ns, nm, nd in extra]
                c.inv = {"nodes": [{"name": n, "ready": "True", "roles": ["control-plane"], "ip": f"10.10.40.{2 + k}"} for k, n in enumerate(VKS_CP)]
                         + [{"name": e["name"], "ready": "True", "roles": ["worker"], "ip": f"10.10.40.{11 + k}"} for k, e in enumerate(DEMO_ENTITIES["vks"][:4])],
                         "pods": pods, "clusters": [], "updated": time.time()}
            elif t == "redfish":
                c.cfg["esxi_host"] = HOSTS[2]
                c.display = HOSTS[2]
                c.server = {"model": "ProLiant DL380 Gen11", "bmc_fw": "iLO 6 1.55", "bios": "U54 2.30", "health": "OK"}
            c.demo_certs, c.demo_versions = demo_lifecycle(t)   # 2.36.0 인증서 달력·버전 수명 데모
            if t == "vcenter":
                demo_drift(c.health_snap)
            dp = demo_protection(t)                         # 2.29.0 DR·보호 화면 데모
            if dp:
                c.protection = dp
            if t == "vcenter":
                c.health_snap.update(demo_vm_protection())
            self.fakes.append(c)
        self.fakes += demo_network(emit)               # 2.2 — Arista·Cisco 스위치 구성도 데모

    async def run(self):
        self._state.update(state="ok", auth="n/a", target="synthetic")
        next_incident = time.time() + 20
        while True:
            await asyncio.sleep(1 / self.rate)
            src = random.choice(list(NORMAL))
            sev, app, tmpl = random.choice(NORMAL[src])
            await self._emit(src, sev, app, _fill(tmpl))
            if time.time() > next_incident:
                next_incident = time.time() + random.uniform(15, 45)
                src, sev, app, tmpl = random.choice(INCIDENTS)
                await self._emit(src, sev, app, _fill(tmpl))
                if random.random() < 0.2:   # 인증 실패 폭주 시나리오
                    for _ in range(25):
                        await self._emit("vcenter", "warning", "", _fill(INCIDENTS[-1][3]))
            for f in self.fakes:
                f._state["last_ok"] = time.time()

    async def _emit(self, src, sev, app, msg):
        host = (random.choice(HOSTS) if src in ("esxi", "vcenter") else random.choice(["dc1-leaf-01", "dc1-leaf-02", "dc1-spine-02"]) if src == "arista"
                else random.choice(["dc1-leaf-03", "dc1-leaf-04"]) if src == "cisco" else f"{src}.vcf.lab")
        conn = {"esxi": "syslog", "nsx-edge": "demo-nsx", "vks-supervisor": "demo-vks", "arista": "syslog", "cisco": "syslog"}.get(src, f"demo-{src}")
        await self.emit(LogEvent(source=src, connector=conn, message=msg,
                                 severity=sev, host=host, entity=app or random.choice(VMS + HOSTS), kind="log"))
        self._state["events_total"] += 1


VKS_CP = ["wld-bank01-cp-r7k2m", "wld-bank01-cp-t5w9q", "wld-bank01-cp-h3n8v"]


def demo_platform_vms() -> dict:
    """Supervisor 컨트롤 플레인 VM 3 · VKS 노드(CP 3 + 워커 4) · vSphere Pod 1 · Avi 컨트롤러 3 · SE 2 — 일부러 겹쳐 둔 배치(esx05 에 VKS CP 2대, esx02 에 Avi 컨트롤러 2대)"""
    def vm(h, cl, cpu, mem, os_, ds):
        return {"host": h, "cluster": cl, "power": "poweredOn", "vcpu": cpu, "mem_mb": mem, "os": os_, "ips": [], "tools": "guestToolsRunning", "disk_gb": 40.0,
                "prov_gb": 80.0, "snapshots": 0, "networks": [], "datastores": [ds], "hw": "vmx-21", "cpu_mhz": cpu * 400, "mem_used_mb": mem // 3}
    c2, c1, lin = "Cluster-02", "Cluster-01", "VMware Photon OS (64-bit)"
    out = {f"SupervisorControlPlaneVM ({i + 1})": vm(HOSTS[4 + i], c2, 4, 16384, lin, "vsan-ds-02") for i in range(3)}
    for n, h in zip(VKS_CP, (HOSTS[4], HOSTS[4], HOSTS[5])):
        out[n] = vm(h, c2, 2, 8192, "Ubuntu Linux (64-bit)", "vsan-ds-02")
    for k, e in enumerate(DEMO_ENTITIES["vks"][:4]):
        out[e["name"]] = vm(HOSTS[4 + k], c2, 8, 32768, "Ubuntu Linux (64-bit)", "vsan-ds-02")
    out["bank-batch-7f9c"] = vm(HOSTS[7], c2, 1, 2048, "CRX Pod 1", "vsan-ds-02")
    for n, h in (("avi-ctrl-01", HOSTS[0]), ("avi-ctrl-02", HOSTS[1]), ("avi-ctrl-03", HOSTS[1])):
        out[n] = vm(h, c1, 8, 32768, "Ubuntu Linux (64-bit)", "vsan-ds-01")
    for k in (1, 2):
        out[f"avi-se-0{k}"] = vm(HOSTS[k], c1, 2, 4096, "Ubuntu Linux (64-bit)", "vsan-ds-01")
    return out


def demo_topology() -> dict:
    hosts, vms = {}, {}
    for i, h in enumerate(HOSTS):
        hosts[h] = {"moid": f"host-{i}", "cluster": "Cluster-01" if i < 4 else "Cluster-02", "conn": "connected",
                    "maintenance": i == 6, "status": "yellow" if i == 3 else "green", "vms": 0,
                    # 2.36.0 가정 분석 데모 — 공유 데이터스토어·소켓·CPU 세대(Cluster-01 Sapphire Rapids, Cluster-02 Ice Lake)
                    "datastores": (["vsan-ds-01"] if i < 4 else ["vsan-ds-02", "san-gold-01"]) + ["nfs-backup"],
                    "sockets": 2, "cpu_model": "Intel(R) Xeon(R) Gold 6430" if i < 4 else "Intel(R) Xeon(R) Gold 6338",
                    "cpu_mhz": 64 * 2600, "core_mhz": 2600, "mem_mb": 1024 * 1024, "cpu_used_mhz": int(64 * 2600 * (0.35 + 0.07 * i)), "mem_used_mb": int(1024 * 1024 * (0.45 + 0.05 * i))}
    for j, v in enumerate(VMS * 3):
        h = HOSTS[j % len(HOSTS)]
        osn = "Microsoft Windows Server 2019 (64-bit)" if "web" in v or "hr" in v else "Red Hat Enterprise Linux 9 (64-bit)"
        vms[f"{v}" if j < len(VMS) else f"{v}-{j}"] = {"host": h, "cluster": hosts[h]["cluster"], "power": "poweredOff" if j == 17 else "poweredOn",
                                                      "vcpu": 4 + 4 * (j % 3), "mem_mb": 8192 * (1 + j % 4), "os": osn, "ips": [f"10.10.{20 + j % 4}.{11 + j}"],
                                                      "tools": "guestToolsRunning", "disk_gb": 80.0 + j * 5, "prov_gb": 200.0, "snapshots": 1 if j == 5 else 0,
                                                      "networks": ["pg-app" if j % 2 else "pg-db"], "datastores": ["vsan-ds-01" if hosts[h]["cluster"] == "Cluster-01" else "vsan-ds-02"] + (["san-gold-01"] if hosts[h]["cluster"] == "Cluster-02" and j % 4 == 1 else []),
                                                      "hw": "vmx-21", "cpu_mhz": int((4 + 4 * (j % 3)) * 2600 * (0.08 + 0.05 * (j % 7))),
                                                      "mem_used_mb": int(8192 * (1 + j % 4) * (0.25 + 0.08 * (j % 6)))}
    dss = {"vsan-ds-01": {"capacity_gb": 61440, "free_gb": 9830, "used_pct": 84.0, "type": "vsan", "hosts": HOSTS[:4]},
           "vsan-ds-02": {"capacity_gb": 61440, "free_gb": 30720, "used_pct": 50.0, "type": "vsan", "hosts": HOSTS[4:]},
           "nfs-backup": {"capacity_gb": 102400, "free_gb": 51200, "used_pct": 50.0, "type": "NFS", "hosts": HOSTS, "remote": "nas01.vcf.lab:/vol/backup",
                          "shared": True, "accessible": True},
           "san-gold-01": {"capacity_gb": 20480, "free_gb": 2150, "used_pct": 89.5, "type": "VMFS", "hosts": HOSTS[4:], "shared": True, "local": False,
                           "vmfs_version": "6.82", "extents": ["naa.600a098038314f2d"], "accessible": True, "array": "NETAPP AFF-A400"},
           **{f"local-{h.split('.')[0]}": {"capacity_gb": 446, "free_gb": 410, "used_pct": 8.1, "type": "VMFS", "hosts": [h], "shared": False, "local": True,
                                         "vmfs_version": "6.82", "extents": [f"t10.NVMe____{i}"], "accessible": True} for i, h in enumerate(HOSTS[:3])}}
    def vh(red, yellow):
        G = [("Network", "네트워크", [("Hosts with connectivity issues", "green"), ("vSAN cluster partition", "green"), ("All hosts have a vSAN vmknic configured", "green")]),
             ("Physical disk", "물리 디스크", [("Operation health", "red" if red else "green"), ("Disk capacity", "yellow" if yellow else "green"), ("Congestion", "green")]),
             ("Data", "데이터", [("vSAN object health", "yellow" if red else "green"), ("vSAN object format health", "green")]),
             ("Cluster", "클러스터", [("Advanced vSAN configuration in sync", "green"), ("vSAN CLOMD liveness", "green"), ("Time is synchronized across hosts and VC", "green")]),
             ("Capacity utilization", "용량", [("Disk space", "yellow" if yellow else "green"), ("Component utilization", "green")]),
             ("Hardware compatibility", "하드웨어 호환성", [("vSAN HCL DB up-to-date", "yellow"), ("Controller is VMware certified", "green")])]
        groups, bad = [], []
        for gid, gname, tests in G:
            ts = []
            for name, st in tests:
                t = {"id": name.lower().replace(" ", ""), "name": name, "health": st, "desc": {"red": "vSAN 디스크에 오류가 있어 데이터 중복성이 줄었습니다",
                     "yellow": "임계치에 가깝거나 HCL DB 가 오래되었습니다"}.get(st, "정상"), "healthy": 4 if st == "green" else 3, "all": 4, "category": gname, "risk": ""}
                ts.append(t)
                if st != "green":
                    bad.append({**t, "group": gname})
            groups.append({"id": gid, "name": gname, "health": "red" if any(t["health"] == "red" for t in ts) else "yellow" if any(t["health"] == "yellow" for t in ts) else "green", "tests": ts})
        return {"overall": "red" if red else "yellow" if yellow else "green", "overall_desc": "일부 점검에 문제가 있습니다" if red or yellow else "모든 점검 정상",
                "groups": groups, "tests_bad": bad, "ts": time.time(), "reserve": {"ops": "reported", "host_rebuild": "disabled" if red else "enforced"},
                "space": {"total_gb": 61440, "free_gb": 9830 if red else 30720, "used_pct": 84.0 if red else 50.0, "logical_gb": 92160, "physical_gb": 51610, "ratio": 1.79, "primary_gb": 34400 if red else 20480, "overhead_gb": 17200 if red else 10240, "policy_mult": 1.5,
                          "by_type": {"vmswap": 1200.0, "vdisk": 41000.0, "namespace": 300.0}},
                "objects": {"overall": "yellow" if red else "green", "detail": {"healthy": 1180, "reducedavailabilitywithnorebuild": 2} if red else {"healthy": 1190}}}
    cls = {"Cluster-01": {"hosts": HOSTS[:4], "ha": True, "drs": True, "vsan": True, "vsan_esa": True, "evc": "", "vsan_health": vh(True, True)},
           "Cluster-02": {"hosts": HOSTS[4:], "ha": True, "drs": True, "vsan": True, "vsan_esa": False, "evc": "intel-icelake", "vsan_health": vh(False, True)}}
    for k, e in enumerate(DEMO_ENTITIES["vks"][:4]):              # VKS 워커 노드 VM
        h = HOSTS[4 + k]
        vms[e["name"]] = {"host": h, "cluster": "Cluster-02", "power": "poweredOn", "vcpu": 8, "mem_mb": 32768, "os": "VMware Photon OS (64-bit)",
                          "ips": [f"10.10.40.{11 + k}"], "tools": "guestToolsRunning", "disk_gb": 60.0, "prov_gb": 120.0, "snapshots": 0,
                          "networks": ["seg-app"], "datastores": ["vsan-ds-02"], "hw": "vmx-21"}
    vms["ops-jump-01"] = {"host": HOSTS[0], "cluster": "Cluster-01", "power": "poweredOn", "vcpu": 2, "mem_mb": 8192, "os": "Microsoft Windows Server 2019 (64-bit)",
                          "ips": ["10.10.0.50"], "tools": "guestToolsRunning", "disk_gb": 80.0, "prov_gb": 100.0, "snapshots": 0,
                          "networks": ["pg-mgmt", "pg-app"], "datastores": ["vsan-ds-01"], "hw": "vmx-19"}      # 2.43.0 데모: 관리망 VLAN 에 붙은 업무 VM(망 분리 점검)
    for j, (vn, v) in enumerate(sorted(vms.items())):               # 폴더·태그(정산 프로젝트 매칭 데모)
        team = "bank" if "bank" in vn or "workers" in vn else "card" if "card" in vn or "mobile" in vn else "hr" if "hr" in vn else "platform"
        v["datacenter"], v["folder"] = "DC-Seoul", f"DC-Seoul/{team.upper()}/{'Prod' if j % 3 else 'Dev'}"
        v["tags"] = [f"CostCenter:{team}", f"Env:{'prod' if j % 3 else 'dev'}"]
        v["moid"] = f"vm-{100 + j}"
    for i, h in enumerate(HOSTS):
        hosts[h]["vsan"] = {"enabled": True, "disk_groups": 2, "cache_disks": 2, "capacity_disks": 6, "health": "healthy" if i != 3 else "unhealthy",
                            "role": "master" if i in (0, 4) else "backup" if i in (1, 5) else "agent", "members": 4,
                            "disk_issues": ["52a1f0c3-…: nonCmmdsDisk" ] if i == 3 else []}
        hosts[h]["esx_version"], hosts[h]["esx_build"] = "8.0.3", "24022510" if i != 5 else "23299997"
        # 2.3 포트맵 데모 — vmnic0/1 = dvs-wld 업링크(리프 쌍), vmnic2 = 미사용. ESXi 쪽 LLDP(QueryNetworkHint) 결과 포함
        pair = ("dc1-leaf-01", "dc1-leaf-02") if i < 4 else ("dc1-leaf-03", "dc1-leaf-04")
        pfx = "Ethernet" if i < 4 else "Ethernet1/"
        nics = []
        for j in range(3):
            up = not (i == 3 and j == 1) and j < 2
            sp = 0 if not up else 10000 if (i == 2 and j == 1) else 25000           # esx03 vmnic1 10G(속도 혼재)
            peer = {"switch": pair[j], "port": f"{pfx}{(i % 4) + 5}", "proto": "lldp", "mgmt": f"10.0.0.{13 + j + (2 if i >= 4 else 0)}"} if j < 2 and up else None
            if i == 5 and j == 1:                                                     # esx06 vmnic1: ESXi 와 스위치가 보는 포트가 다름(케이블 기록 불일치)
                peer = {"switch": pair[1], "port": "Ethernet1/9", "proto": "lldp"}
            n = {"name": f"vmnic{j}", "mac": f"00:50:56:{i:02x}:{j:02x}:01", "speed": sp, "up": bool(sp), "driver": "bnxtnet" if i < 4 else "nmlx5_core"}
            if j < 2:
                n["vswitch"] = "dvs-wld"
            if peer:
                n["peer"] = peer
            nics.append(n)
        hosts[h]["pnics"] = nics
        hosts[h]["switches"] = [{"name": "dvs-wld", "kind": "vds", "uplinks": ["vmnic0", "vmnic1"]}]
        hosts[h]["hw_vendor"], hosts[h]["hw_model"] = ("HPE", "ProLiant DL380 Gen11") if i < 4 else ("Lenovo", "ThinkSystem SR650 V3")
    for v in vms.values():
        hosts[v["host"]]["vms"] += 1
    nets = {"pg-mgmt": {"kind": "dvportgroup", "dvs": "dvs-wld", "vlan": 100, "key": "dvportgroup-mgmt", "hosts": 8, "vms": 1, "accessible": True},
            "pg-vsan": {"kind": "dvportgroup", "dvs": "dvs-wld", "vlan": 110, "key": "dvportgroup-vsan", "hosts": 8, "vms": 0, "accessible": True},
            "pg-app": {"kind": "dvportgroup", "dvs": "dvs-wld", "vlan": 120, "hosts": 8, "vms": 10, "accessible": True},
            "pg-db": {"kind": "dvportgroup", "dvs": "dvs-wld", "vlan": 130, "hosts": 8, "vms": 11, "accessible": True},
            "seg-web": {"kind": "opaque", "hosts": 8, "vms": 0, "accessible": True}}
    return {"hosts": hosts, "vms": vms, "datastores": dss, "clusters": cls, "networks": nets, "updated": time.time(), "vcenter": "vcenter.vcf.lab"}


def demo_vips() -> list[dict]:
    import math
    now = time.time()
    out = []
    for i, n in enumerate(("vs-mobile-api", "vs-card-auth", "vs-core-bank", "vs-hr-web", "vs-openbank")):
        ser = {}
        for k, base in (("bw", 6e8 / (i + 1)), ("cps", 1500 / (i + 1)), ("rps", 4200 / (i + 1)), ("rtt", 2.0 + i), ("err", float(i)), ("open", 8000 / (i + 1)),
                        ("rx", 1.2e7 / (i + 1)), ("tx", 6.3e7 / (i + 1)), ("rxp", 21000 / (i + 1)), ("txp", 48000 / (i + 1)), ("newc", 1300 / (i + 1)),
                        ("r2xx", 3900 / (i + 1)), ("r4xx", 120 / (i + 1)), ("r5xx", float(i)), ("sslnew", 300 / (i + 1)), ("txlat", 18.0 + 4 * i), ("apdex", 97.0 - i)):
            ser[k] = [round(base * (1 + 0.4 * math.sin((now - (12 - p) * 5) / 25 + i) + 0.08 * math.sin((now - (12 - p) * 5) / 3.1 + i * 2)), 2) for p in range(12)]
        out.append({"uuid": f"virtualservice-demo-{i}", "name": n, "state": "OPER_UP", "vips": [f"10.30.0.{11 + i}"], "ports": [443],
                    "health": 98 - i * 6, "pool": f"pool-{n[3:]}", "se_group": "Default-Group", "updated": now, "step": 5,
                    "series": ser, "last": {k: v[-1] for k, v in ser.items()}, "connector": "demo-avi", "controller": "avi.vcf.lab",
                    "avg": {k: round(sum(v) / len(v), 2) for k, v in ser.items()}, "ses": ["avi-se-01", "avi-se-02"],
                    "members": [], "pool_up": 4, "pool_servers": 4, "tenant": "admin"})
    return sorted(out, key=lambda x: -x["last"]["bw"])


async def demo_end_users(uuid: str, minutes: int = 60, limit: int = 1000) -> dict:
    """데모 End user — 합성 애플리케이션 로그를 실제 집계 함수로 요약"""
    from .vmware_rest import aggregate_app_logs
    rnd = random.Random(hash(uuid) % 1000 + int(time.time() // 60))
    oses, brs = ["Windows 11", "iOS 18", "Android 15", "macOS 15", "Linux"], ["Chrome", "Safari", "Edge", "Samsung Internet", "okhttp"]
    devs, locs = ["Computer", "Smartphone", "Tablet"], ["KR/Seoul", "KR/Busan", "KR/Incheon", "US/California", "JP/Tokyo"]
    logs = []
    pool = [f"211.234.{rnd.randint(1, 40)}.{rnd.randint(1, 250)}" for _ in range(40)] + ["58.140.12.7"] * 12 + ["121.88.4.31"] * 6
    for _ in range(min(limit, 600)):
        c = rnd.choice(pool)
        code = rnd.choices([200, 200, 200, 304, 401, 404, 500, 502], [50, 20, 10, 6, 4, 5, 3, 2])[0]
        logs.append({"client_ip": c, "client_os": rnd.choice(oses), "client_browser": rnd.choice(brs), "client_device": rnd.choice(devs),
                     "client_location": rnd.choice(locs), "response_code": code, "method": rnd.choice(["GET", "GET", "POST"]),
                     "uri_path": rnd.choice(["/api/v1/accounts", "/api/v1/transfer", "/login", "/static/app.js", "/api/v1/cards"]),
                     "host": "m.bank.example", "total_time": rnd.randint(8, 420), "client_rtt": rnd.randint(2, 40),
                     "request_length": rnd.randint(200, 2400), "response_length": rnd.randint(500, 90000),
                     "server_ip": f"10.10.2{rnd.randint(0, 3)}.{rnd.randint(11, 30)}", "ssl_version": "TLSv1.3", "significant": code >= 400,
                     "report_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - rnd.randint(0, minutes * 60)))})
    d = aggregate_app_logs(logs, minutes)
    d.update(uuid=uuid, name=uuid, tenant="admin", total_reported=len(logs))
    return d


def demo_sli() -> dict:
    """데모용 성능 SLI — 클러스터 3개·VM 60대, 일부 VM 에 CPU ready·디스크 지연 문제를 섞음."""
    rnd = random.Random(int(time.time() // 300))
    groups = {"mgmt-cl01": HOSTS[:2], "wld-core-cl01": HOSTS[2:5], "wld-ai-cl01": HOSTS[5:8]}
    vms, clusters = {}, {}
    for cl, hs in groups.items():
        names = [f"{cl.split('-')[1]}-vm{n:02d}" for n in range(1, 21)]
        if cl == "wld-core-cl01":
            names[:4] = VMS[:4]
        for i, n in enumerate(names):
            hot = cl != "mgmt-cl01" and i < 3
            rd = {"cpu_ready": round(rnd.uniform(4, 11) if hot and i == 0 else rnd.uniform(0.1, 2.2), 2),
                  "mem_latency": round(rnd.uniform(0.6, 1.8) if hot and i == 1 else rnd.uniform(0, 0.2), 2),
                  "disk_latency": round(rnd.uniform(12, 28) if hot and i == 2 else rnd.uniform(0.5, 6), 1),
                  "net_dropped": rnd.choice([0] * 12 + [3, 40])}
            vms[n] = SLI.vm_result(n, rd, host=hs[i % len(hs)], cluster=cl, vcpu=rnd.choice([2, 4, 8, 16]))
        mine = [v for v in vms.values() if v["cluster"] == cl]
        hosts = [{"name": h, "cpu_mhz": 2 * 32 * 2800, "mem_mb": 1024 * 1024, "connected": True,
                  "cpu_used_mhz": rnd.uniform(0.35, 0.6) * 179200, "mem_used_mb": rnd.uniform(0.5, 0.8 if cl == "wld-ai-cl01" else 0.62) * 1048576}
                 for h in hs]
        clusters[cl] = {**SLI.cluster_kpi(mine), "failover": SLI.failover(hosts, 1), "ha": True, "ha_admission": cl != "wld-ai-cl01"}
    return {"updated": time.time() - rnd.uniform(5, 200), "vms": vms, "clusters": clusters, "error": "", "missing_counters": [],
            "vcenter": "vcenter.vcf.lab", "window_s": 300, "thresholds": dict(SLI.DEFAULT_THRESHOLDS), "percentile": 99.0}


def demo_nsx_routing() -> tuple[dict, dict, dict]:
    """데모 NSX T0 BGP — ec-01(edge-node-01·02, Cluster-01) ↔ Arista 리프 01·02, ec-02(edge-node-03·04, Cluster-02) ↔ Cisco 리프 03·04.
    장애 시나리오: edge-node-02 ↔ dc1-leaf-02 세션 ACTIVE(수립 안 됨)"""
    info = {f"tn-edge-{n:02d}": {"name": f"edge-node-{n:02d}", "host_moid": f"host-{[1, 2, 5, 6][n - 1]}", "edge_cluster": "ec-01" if n <= 2 else "ec-02",
                                 "form": "LARGE", "mgmt_ip": f"10.20.8.{10 + n}", "unique_id": f"tn-edge-{n:02d}"} for n in range(1, 5)}
    sess, ifs = [], []
    for n in range(1, 5):
        leaves = (1, 2) if n <= 2 else (3, 4)
        for k, lf in enumerate(leaves):
            src, nbr = f"10.40.{lf}.{10 + n}", f"10.40.{lf}.1"
            ep = f"/infra/sites/default/enforcement-points/default/edge-clusters/{'ec-01' if n <= 2 else 'ec-02'}/edge-nodes/tn-edge-{n:02d}"
            bad = n == 2 and lf == 2
            sess.append({"edge": f"edge-node-{n:02d}", "edge_path": ep, "source": src, "neighbor": nbr, "remote_as": "65101" if lf <= 2 else "65102",
                         "state": "ACTIVE" if bad else "ESTABLISHED", "uptime_s": None if bad else 86400 * 12 + 3600 * n,
                         "in_prefix": 0 if bad else 3, "out_prefix": 0 if bad else 14, "drops": 6 if bad else 0, "router_id": f"10.255.{lf}.1"})
            ifs.append({"name": f"uplink-{n:02d}-{k + 1}", "type": "EXTERNAL", "ips": [f"{src}/24"], "edge": f"edge-node-{n:02d}",
                        "segment": f"seg-uplink-{lf}", "vlan": 100 + lf, "mtu": 9000})
    rt = {"tier0": [{"id": "t0-vcf-m01", "name": "t0-vcf-m01", "ha_mode": "ACTIVE_ACTIVE", "local_as": "65000", "bgp_enabled": True,
                     "neighbors": [{"id": f"leaf{lf}", "name": f"dc1-leaf-0{lf}", "neighbor": f"10.40.{lf}.1", "remote_as": "65101" if lf <= 2 else "65102",
                                    "source": [], "bfd": True} for lf in (1, 2, 3, 4)],
                     "sessions": sess, "interfaces": ifs}], "updated": time.time()}
    return info, {k: v["name"] for k, v in info.items()}, rt


def demo_network(emit) -> list:
    """데모 네트워크: Arista 스파인 2 · Arista 리프(MLAG) 2 · Cisco Nexus 리프(vPC) 2 · 보더 라우터·방화벽(이웃으로만) · ESXi 8대"""
    from .network import AristaEosConnector, CiscoNxosConnector
    now = time.time()
    sw = {"dc1-spine-01": ("arista", "DCS-7050CX3-32S", "4.32.2F", "spine"), "dc1-spine-02": ("arista", "DCS-7050CX3-32S", "4.32.2F", "spine"),
          "dc1-leaf-01": ("arista", "DCS-7050SX3-48YC8", "4.32.2F", "leaf"), "dc1-leaf-02": ("arista", "DCS-7050SX3-48YC8", "4.32.2F", "leaf"),
          "dc1-leaf-03": ("cisco", "N9K-C93180YC-FX", "10.3(4a)", "leaf"), "dc1-leaf-04": ("cisco", "N9K-C93180YC-FX", "10.3(4a)", "leaf")}
    nb: dict[str, list] = {n: [] for n in sw}
    ifs: dict[str, dict] = {n: {} for n in sw}

    def port(dev, p, peer, pport, state="up", desc="", proto="lldp"):
        ifs[dev][p] = {"state": state, "raw": "connected" if state == "up" else "notconnect", "desc": desc or f"{peer.split('.')[0]} {pport}",
                       "speed": 100000 if "spine" in peer or "spine" in dev else 25000, "vlan": None}
        if state == "up":
            nb[dev].append({"local": p, "remote": peer, "remote_port": pport, "proto": proto})
    for si, sp in enumerate(("dc1-spine-01", "dc1-spine-02")):
        for li, lf in enumerate(("dc1-leaf-01", "dc1-leaf-02", "dc1-leaf-03", "dc1-leaf-04")):
            up = not (sp == "dc1-spine-02" and lf == "dc1-leaf-03")     # 장애 시나리오: spine-02 ↔ leaf-03 링크 다운
            port(sp, f"Ethernet{li + 1}/1", lf, f"Ethernet{49 + si}/1" if sw[lf][0] == "arista" else f"Ethernet1/{49 + si}", "up" if up else "down")
            port(lf, f"Ethernet{49 + si}/1" if sw[lf][0] == "arista" else f"Ethernet1/{49 + si}", sp, f"Ethernet{li + 1}/1", "up" if up else "down")
        port(sp, "Ethernet31/1", "dc1-border-01.corp.lab", "TenGigabitEthernet0/0/" + str(si))
        port(sp, "Ethernet32/1", "fg-dc1-01", f"port{si + 9}")
    for a, b, k in (("dc1-leaf-01", "dc1-leaf-02", "Ethernet51/1"), ("dc1-leaf-03", "dc1-leaf-04", "Ethernet1/53")):
        port(a, k, b, k)
        port(b, k, a, k)
    for i, h in enumerate(HOSTS):
        pair = ("dc1-leaf-01", "dc1-leaf-02") if i < 4 else ("dc1-leaf-03", "dc1-leaf-04")
        for j, lf in enumerate(pair):
            p = f"Ethernet{(i % 4) + 5}" if sw[lf][0] == "arista" else f"Ethernet1/{(i % 4) + 5}"
            down = (lf == "dc1-leaf-02" and i == 3)                       # esx04 vmnic1 링크 다운
            port(lf, p, h, f"vmnic{j}", "down" if down else "up", f"{h.split('.')[0]} vmnic{j}")
    ifs["dc1-leaf-01"]["Ethernet6"]["desc"] = "esx05 vmnic0"              # 설명과 실제 연결(esx02) 불일치 시나리오
    out = []
    for name, (vend, model, ver, role) in sw.items():
        cls = AristaEosConnector if vend == "arista" else CiscoNxosConnector
        c = cls({"name": f"demo-{name}", "host": f"10.0.0.{len(out) + 11}", "role": role}, emit)
        c.demo = True
        c.device = {"hostname": name, "model": model, "os": "EOS" if vend == "arista" else "NX-OS", "version": ver, "serial": f"SN{len(out) + 1:04d}", "uptime": 86400 * 41}
        for k in range(1, 33 if "spine" in name else 9):                 # 미사용 포트
            ifs[name].setdefault(f"Ethernet{k}/9" if "spine" in name else f"Ethernet{k + 20}", {"state": "down", "raw": "notconnect", "desc": "", "speed": None, "vlan": None})
        c.ifaces = ifs[name]
        c.known_links = {__import__("app.connectors.network", fromlist=["if_short"]).if_short(n["local"]): {**n, "seen": now, "state": "up"} for n in nb[name]}
        if name == "dc1-leaf-03":
            c.known_links["e1/50"] = {"local": "Ethernet1/50", "remote": "dc1-spine-02", "remote_port": "Ethernet3/1", "proto": "lldp", "seen": now - 900, "state": "lost", "lost_at": now - 600}
        if name == "dc1-leaf-02":
            c.known_links["e8"] = {"local": "Ethernet8", "remote": HOSTS[3], "remote_port": "vmnic1", "proto": "lldp", "seen": now - 1200, "state": "lost", "lost_at": now - 1100}
        if name == "dc1-spine-02":
            c.known_links["e3/1"] = {"local": "Ethernet3/1", "remote": "dc1-leaf-03", "remote_port": "Ethernet1/50", "proto": "lldp", "seen": now - 900, "state": "lost", "lost_at": now - 600}
        c.mlag = ({"kind": "MLAG", "state": "active", "neg": "connected", "peer_link": "up", "domain": "mlag-a"} if name in ("dc1-leaf-01", "dc1-leaf-02")
                  else {"kind": "vPC", "state": "peer-ok", "neg": "peer-alive", "peer_link": "up", "domain": 10} if name in ("dc1-leaf-03", "dc1-leaf-04") else {})
        c.bgp = ({f"10.255.{1 if name.endswith('01') else 2}.{k}": {"state": "Established" if not (name == "dc1-spine-02" and k == 3) else "Idle", "asn": 65100 + k, "vrf": "default"}
                  for k in range(1, 5)} if "spine" in name else {})
        if "leaf" in name:                                                # NSX Edge 업링크 피어(2.3)
            lf = int(name[-1])
            edges = (1, 2) if lf <= 2 else (3, 4)
            c.bgp = {f"10.40.{lf}.{10 + n}": {"state": "Active" if (n == 2 and lf == 2) else "Established", "asn": 65000, "vrf": "default",
                                               "prefixes": 0 if (n == 2 and lf == 2) else 14} for n in edges}
            c.addresses = [f"10.40.{lf}.1", f"10.255.{lf}.1"]
        c.updated = now
        c._state.update(state="ok", auth="ok", last_ok=now, latency_ms=35, checks={"데모 모드": "ok"})

        async def _fixed(c=c):                      # 데모: 실제 장비에 접속하지 않고 같은 상태를 유지
            return {"device": c.device, "ifaces": c.ifaces, "neighbors": [n for n in c.known_links.values() if n.get("state") != "lost"],
                    "mlag": c.mlag, "bgp": c.bgp, "addresses": c.addresses}

        async def _nologin():
            return None
        c.collect, c.login = _fixed, _nologin

        async def _cfg(c=c, name=name, vend=vend):         # 2.4 데모 running-config
            from .. import netconfig as NC
            text = demo_config(name, vend, c.ifaces, c.known_links)
            return text, NC.parse(text)
        c.fetch_config = _cfg
        out.append(c)
    return out


def demo_config(name: str, vend: str, ifaces: dict, links: dict) -> str:
    """데모 스위치 running-config — ESXi 포트 trunk, 피어 링크 LAG, 미사용 포트 일부 열림(점검 시나리오)"""
    from .network import if_short
    L = [f"! device: {name} ({'EOS' if vend == 'arista' else 'NX-OS'})", f"hostname {name}", "username admin privilege 15 role network-admin secret sha512 $6$abc$def",
         "snmp-server community S3cret! ro", "logging host 10.20.0.50", "ntp server 10.20.0.1", "lldp run" if vend == "arista" else "feature lldp",
         "management api http-commands" if vend == "arista" else "feature nxapi", "   no shutdown" if vend == "arista" else "!", "!"]
    for v, n in ((100, "MGMT"), (101, "EDGE-UP1"), (102, "EDGE-UP2"), (110, "VMOTION"), (120, "APP"), (130, "DB")):
        L += [f"vlan {v}", f"   name {n}", "!"]
    for k in sorted(ifaces, key=lambda x: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", x)]):
        i = ifaces[k]
        nb = links.get(if_short(k)) or {}
        r = str(nb.get("remote", ""))
        L.append(f"interface {k}")
        if r:
            desc = f"{r.split('.')[0]} {nb.get('remote_port', '')}"
            if name == "dc1-leaf-01" and k == "Ethernet6":
                desc = "esx05 vmnic0"                                      # 설명과 실제 연결 불일치 시나리오
            L.append(f"   description {desc}")
            if "esx" in r:
                L += ["   switchport mode trunk", "   switchport trunk allowed vlan 100,110,120" + ("" if (name == "dc1-leaf-02" and k == "Ethernet7") else ",130"),
                      "   spanning-tree portfast", "   mtu 9214"]
            elif "leaf" in r and "leaf" in name:
                L += ["   switchport mode trunk", "   channel-group 1000 mode active", "   mtu 9214"]
            elif "spine" in r or "spine" in name:
                L += ["   no switchport", f"   ip address 10.254.{len(name)}.{len(k)}/31", "   mtu " + ("1500" if (name == "dc1-spine-01" and k == "Ethernet3/1") else "9214")]
            else:
                L += ["   no switchport", "   ip address 172.16.0.1/30"]
        elif i.get("desc"):
            L.append(f"   description {i['desc']}")
        elif i.get("state") == "down":
            idx = int(re.sub(r"\D", "", k) or 0)
            if idx % 3 == 0:
                L.append("   shutdown")                                 # 나머지 미사용 포트는 열려 있음(점검 시나리오)
        L.append("!")
    if "leaf" in name:
        lf = name[-1]
        L += ["interface Vlan101", f"   ip address 10.40.{lf}.1/24", "   mtu 9000", "!", "interface Loopback0", f"   ip address 10.255.{lf}.1/32", "!"]
    L += ["router bgp 6510" + name[-1], "   router-id 10.255.0." + name[-1], "!", "end"]
    return "\n".join(L)


# ---------------------------------------------------------------------------------------------- 2.21.0 세그먼트 트래픽 데모
_SEG_OF = {"web": "seg-web", "hr": "seg-web", "mobile": "seg-app", "card": "seg-app", "core-bank-was": "seg-app", "ai": "seg-app",
           "core-bank-db": "seg-db", "edge": "seg-web"}


def _seg_for(vm: str) -> str:
    for k, v in _SEG_OF.items():
        if vm.startswith(k) or k in vm:
            return v
    return "seg-app"


def demo_seg_vnics(scope: str = "nsx") -> dict:
    topo = demo_topology()
    segs = {f"/infra/segments/{n}": {"name": n, "kind": "nsx", "segment_path": f"/infra/segments/{n}", "ls_uuid": f"5f0c{i}a1e-0000-4000-8000-00000000000{i}",
                                     "tz": "overlay-tz", "dvs": "vds-01", "key": f"/infra/segments/{n}"} for i, n in enumerate(("seg-web", "seg-app", "seg-db"))}
    vnics = []
    for j, (vm, v) in enumerate(sorted((k, x) for k, x in topo["vms"].items() if x["ips"])):   # 2.46.0 플랫폼 데모 VM(네트워크 없음)은 제외
        seg = f"/infra/segments/{_seg_for(vm)}"
        vnics.append({"vm": vm, "moid": f"vm-{100 + j}", "power": v["power"], "host": v["host"], "cluster": v["cluster"], "device": 4000,
                      "label": "Network adapter 1", "mac": f"00:50:56:a1:{j // 256:02x}:{j % 256:02x}", "type": "vmxnet3", "connected": v["power"] == "poweredOn",
                      "segment": seg, "ips": v["ips"]})
        if "db" in vm:                                    # DB VM 은 백업망 vNIC 하나 더
            vnics.append({**vnics[-1], "device": 4001, "label": "Network adapter 2", "mac": f"00:50:56:a2:{j // 256:02x}:{j % 256:02x}",
                          "segment": "/infra/segments/seg-db", "ips": [v["ips"][0].replace("10.10.", "10.30.")]})
        if "was" in vm:                                   # 업무 WAS 는 VDS 백업망 vNIC 추가
            vnics.append({**vnics[-1 if "db" not in vm else -2], "device": 4002, "label": "Network adapter 3", "mac": f"00:50:56:b1:{j // 256:02x}:{j % 256:02x}",
                          "segment": "pg-backup", "ips": [v["ips"][0].replace("10.10.", "10.40.")]})
        if vm.startswith("edge-gw"):                       # Edge 게이트웨이 VM 의 관리 vNIC 는 표준 vSwitch
            vnics.append({**vnics[-1], "device": 4003, "label": "Network adapter 2", "mac": f"00:50:56:c1:{j // 256:02x}:{j % 256:02x}",
                          "segment": "std:VM Network", "ips": [v["ips"][0].replace("10.10.", "10.50.")]})
    segs["pg-backup"] = {"name": "pg-backup", "kind": "dvpg", "segment_path": "", "ls_uuid": "", "tz": "", "dvs": "vds-01", "key": "pg-backup"}
    segs["std:VM Network"] = {"name": "VM Network", "kind": "std", "segment_path": "", "ls_uuid": "", "tz": "", "dvs": "vSwitch", "key": "std:VM Network"}
    want = {"nsx": {"nsx"}, "vds": {"dvpg"}, "std": {"std"}, "all": {"nsx", "dvpg", "std"}}.get(scope, {"nsx"})
    keep = {k for k, x in segs.items() if x["kind"] in want}
    return {"vcenter": "demo-vcenter", "segments": {k: x for k, x in segs.items() if k in keep}, "vnics": [x for x in vnics if x["segment"] in keep], "error": ""}


def _rate(seed: int, t: float) -> float:
    import math
    base = [2e6, 8e6, 35e6, 120e6, 4e5, 15e6, 60e6][seed % 7]
    return max(0.0, base * (1 + 0.35 * math.sin(t / 900 + seed) + 0.15 * math.sin(t / 97 + seed * 3)))


def demo_vnic_traffic(vnics: list, samples: int = 15) -> dict:
    now = int(time.time() // 20 * 20)
    ts = [now - 20 * (samples - 1 - i) for i in range(samples)]
    out = {}
    for k, v in enumerate(vnics):
        if v.get("power") != "poweredOn":
            continue
        seed = sum(map(ord, v["vm"])) + int(v["device"])
        rx = [_rate(seed, t) for t in ts]
        tx = [_rate(seed + 3, t) * 0.6 for t in ts]
        drop = [(12.0 if (t // 20) % 9 == 0 else 0.0) if "core-bank-db" in v["vm"] and v["device"] == 4000 else 0.0 for t in ts]
        out[f"{v['moid']}:{v['device']}"] = {"ts": [float(t) for t in ts], "rx_bps": rx, "tx_bps": tx, "rx_pps": [x / 8 / 800 for x in rx],
                                            "tx_pps": [x / 8 / 800 for x in tx], "drop_rx": drop, "drop_tx": [0.0] * samples}
    return {"series": out, "interval": 20, "error": ""}


async def demo_segment_ports(seg: str, max_ports: int = 400, conc: int = 6) -> dict:
    sid = seg.rsplit("/", 1)[-1]
    inv = demo_seg_vnics()
    ports = []
    for v in inv["vnics"]:
        if v["segment"].endswith("/" + sid):
            dfw = 340 if v["vm"].startswith("hr-web") else 0
            ports.append({"port": f"{v['vm']}.vmx@{v['device']}", "name": f"{v['vm']}.vmx@{v['device']}", "attachment": f"att-{v['moid']}-{v['device']}",
                          "vm": v["vm"], "device": str(v["device"]), "mac": v["mac"], "ips": v["ips"], "label": v["label"], "admin": "UP",
                          "rx_bytes": 10**9, "tx_bytes": 6 * 10**8, "rx_pkts": 10**6, "tx_pkts": 6 * 10**5, "rx_drop": 0, "tx_drop": 0, "dfw_drop": dfw,
                          "sec_drop": 0, "ok": True})
    return {"segment": sid, "ports": ports, "stats": {"rx_bytes": {"total": 10**10}, "tx_bytes": {"total": 6 * 10**9}}, "error": "", "ts": time.time()}


def demo_vm_net_history(moid: str, hours: float = 24) -> dict:
    import math
    interval = 300 if hours <= 24 else 1800 if hours <= 168 else 7200
    now = int(time.time() // interval * interval)
    n = int(hours * 3600 // interval)
    seed = sum(map(ord, moid))
    ts = [float(now - interval * (n - 1 - i)) for i in range(n)]
    base = [2e6, 8e6, 35e6, 120e6, 4e5, 15e6, 60e6][seed % 7]
    rx = [max(0.0, base * (1 + 0.6 * math.sin((t / 86400) * 2 * math.pi - 1.2) + 0.15 * math.sin(t / 1700 + seed))) for t in ts]
    tx = [x * 0.6 for x in rx]
    return {"ts": ts, "series": {"usage_bps": [a + b for a, b in zip(rx, tx)], "rx_bps": rx, "tx_bps": tx}, "interval": interval, "error": ""}


# ---------------------------------------------------------------- 2.23.0 호스트·VM 성능 데모(합성 카운터 원자료 → perfcalc)
def _demo_perf_raw(kind: str, moid: str, ts: list[float], interval: int) -> list:
    import math
    seed = sum(map(ord, moid))
    hot = seed % 7 == 0                                    # 일부는 바쁜 VM·호스트
    k = max(1.0, interval / 20)                            # 긴 간격은 천천히(하루 주기) 변하게

    def wave(base, amp, per=900, ph=0.0):
        return [max(0.0, base * (1 + amp * math.sin(t / (per * k) + seed + ph) + 0.1 * math.sin(t / (97 * k) + seed * 3))) for t in ts]
    cpu = wave(5500 if hot else 2200, 0.4)                  # 1/100 %
    raw = [("cpu.usage.average", "", cpu), ("cpu.usagemhz.average", "", [x / 100 * (1660 if kind == "host" else 26) for x in cpu]),
           ("mem.usage.average", "", wave(6800 if hot else 4100, 0.08, 3600)),
           ("mem.active.average", "", wave(3_000_000, 0.2)), ("mem.consumed.average", "", wave(7_500_000, 0.03, 7200)),
           ("mem.vmmemctl.average", "", wave(524288, 0.1) if hot and kind == "vm" else [0.0] * len(ts)),
           ("disk.usage.average", "", wave(18000 if hot else 4000, 0.5, 600)),
           ("disk.maxTotalLatency.latest", "", wave(32 if hot else 2, 0.4, 300)),
           ("net.usage.average", "", wave(9000 if hot else 1500, 0.5, 700))]
    if kind == "vm":
        raw += [("cpu.ready.summation", "", [x * interval / 20 for x in wave(6400 if hot else 150, 0.3, 400)]),     # 바쁜 VM: vCPU 4 기준 약 8%
                ("cpu.costop.summation", "", [x * interval / 20 for x in wave(2800 if hot else 40, 0.3)]), ("mem.latency.average", "", wave(150 if hot else 20, 0.5))]
        for d, f in (("scsi0:0", 0.7), ("scsi0:1", 0.3)):
            raw += [("virtualDisk.numberReadAveraged.average", d, wave(350 * f * (3 if hot else 1), 0.5, 500)),
                    ("virtualDisk.numberWriteAveraged.average", d, wave(200 * f * (3 if hot else 1), 0.5, 450)),
                    ("virtualDisk.read.average", d, wave(9000 * f, 0.5, 500)), ("virtualDisk.write.average", d, wave(6000 * f, 0.5, 450)),
                    ("virtualDisk.totalReadLatency.average", d, wave(24 if hot else 1.5, 0.4, 300)),
                    ("virtualDisk.totalWriteLatency.average", d, wave(31 if hot else 2, 0.4, 330))]
        devs = [("4000", 1.0)]
    else:
        raw += [("mem.swapinRate.average", "", [0.0] * len(ts)), ("mem.swapoutRate.average", "", [0.0] * len(ts))]
        for d, f in (("naa.600508b1001c0001", 0.6), ("naa.600508b1001c0002", 0.4)):
            raw += [("disk.numberReadAveraged.average", d, wave(2500 * f, 0.5, 500)), ("disk.numberWriteAveraged.average", d, wave(1800 * f, 0.5, 450)),
                    ("disk.read.average", d, wave(60000 * f, 0.5, 500)), ("disk.write.average", d, wave(40000 * f, 0.5, 450)),
                    ("disk.totalReadLatency.average", d, wave(3, 0.6, 300)), ("disk.totalWriteLatency.average", d, wave(4, 0.6, 330)),
                    ("disk.deviceLatency.average", d, wave(26 if hot else 2.5, 0.4, 300)), ("disk.kernelLatency.average", d, wave(0.2, 0.5, 300))]
        if hot:
            raw = [(k, i, (wave(24, 0.4, 300) if k == "disk.totalReadLatency.average" else wave(30, 0.4, 330)) if k in ("disk.totalReadLatency.average", "disk.totalWriteLatency.average") else v)
                   for k, i, v in raw]
        devs = [("vmnic0", 0.6), ("vmnic1", 0.4)]
    for d, f in devs:
        raw += [("net.received.average", d, wave(5000 * f, 0.5, 700)), ("net.transmitted.average", d, wave(3000 * f, 0.5, 650)),
                ("net.packetsRx.summation", d, [x * interval / 20 for x in wave(9000 * f, 0.5, 700)]),
                ("net.packetsTx.summation", d, [x * interval / 20 for x in wave(6000 * f, 0.5, 650)]),
                ("net.droppedRx.summation", d, [(15.0 if hot and int(t // interval) % 7 == 0 else 0.0) for t in ts]), ("net.droppedTx.summation", d, [0.0] * len(ts))]
    return raw


def demo_perf_series(kind: str, moid: str, rng: str = "rt", vcpu: int = 1, labels: dict | None = None) -> dict:
    from .. import perfcalc
    interval, span = {"rt": (20, 3600), "1d": (300, 86400), "7d": (1800, 7 * 86400), "30d": (7200, 30 * 86400)}.get(rng, (20, 3600))
    now = int(time.time() // interval * interval)
    n = span // interval
    ts = [float(now - interval * (n - 1 - i)) for i in range(n)]
    out = perfcalc.build(_demo_perf_raw(kind, moid, ts, interval), ts, interval, kind, vcpu, labels)
    out["error"] = ""
    return out


def demo_perf_latest(kind: str, items: list, batch: int = 50, samples: int = 3) -> dict:
    from .. import perfcalc
    now = int(time.time() // 20 * 20)
    ts = [float(now - 20 * (samples - 1 - i)) for i in range(samples)]
    return {n: perfcalc.latest(_demo_perf_raw(kind, m, ts, 20), 20, kind, c) for n, m, c in items}


def demo_protection(t: str) -> dict | None:
    now = time.time()
    if t == "srm":
        groups = [("PG-Core", "HBR", "OK", 12, 0), ("PG-Card", "ABR", "OK", 8, 0), ("PG-Mobile", "HBR", "ERROR", 6, 3), ("PG-AI", "VVOL", "OK", 4, 0)]
        vms = []
        names = sorted(v for v, x in demo_topology()["vms"].items() if not v.startswith("wld-") and x["ips"])   # 2.36.0 DR 수용 가정 데모 — 인벤토리 VM 이름과 맞춘다
        k = 0
        for g, _r, st, n, bad in groups:
            for i in range(n):
                b = i < bad
                nm = names[k % len(names)] if names else f"{g[3:].lower()}-vm{i + 1:02d}"
                k += 1
                vms.append({"pairing": "p1", "group": g, "name": nm, "status": "ERROR" if b else "OK", "verdict": "bad" if b else "ok",
                            "errors": "Replication RPO violation (15 min)" if b else ""})
        return {"kind": "srm", "updated": now, "error": "",
                "pairings": [{"id": "p1", "local_site": "vcenter.vcf.lab (서울 주센터)", "remote_site": "vcenter-dr.vcf.lab (대전 DR센터)",
                              "local_srm": "srm.vcf.lab", "remote_srm": "srm-dr.vcf.lab", "status": "CONNECTED"}],
                "plans": [{"pairing": "p1", "id": f"rp{i}", "name": n, "status": st, "verdict": PR.srm_status_verdict(st), "location": "LOCAL",
                           "protected_site": "서울 주센터", "groups": g} for i, (n, st, g) in enumerate((("Core-Banking-DR", "READY", 2), ("Mobile-DR", "INCOMPLETE", 1),
                                                                                                      ("AI-Infer-DR", "READY", 1)))],
                "groups": [{"pairing": "p1", "id": f"pg{i}", "name": g, "status": st, "verdict": PR.srm_status_verdict(st), "replication": r,
                            "recovery_status": "READY", "protected_site": "서울 주센터", "location": "LOCAL", "vms": n, "vms_bad": bad}
                           for i, (g, r, st, n, bad) in enumerate(groups)], "vms": vms}
    if t == "nsx":
        return {"kind": "appliance_backup", "product": "NSX Manager", "target": "nsx.vcf.lab", "configured": True, "schedule": "60분마다",
                "location": "sftp://backup.vcf.lab/nsx", "last": {"status": "SUCCESS", "end": now - 1800, "message": "", "part": "클러스터"},
                "last_success": now - 1800, "history": [{"part": "클러스터", "success": True, "end": now - 1800 - k * 3600, "message": ""} for k in range(5)],
                "updated": now, "error": ""}
    if t == "sddc":
        return {"kind": "appliance_backup", "product": "SDDC Manager", "target": "sddc-manager.vcf.lab", "configured": True, "schedule": "매주 SUN,WED 02:00",
                "location": "sftp://backup.vcf.lab/sddc", "last": {"status": "FAILED", "end": now - 3 * 86400, "message": "SFTP 서버 인증 실패"},
                "last_success": now - 10 * 86400, "history": [], "updated": now, "error": ""}
    if t == "vcenter":
        return {"kind": "appliance_backup", "product": "vCenter", "target": "vcenter.vcf.lab", "configured": True, "schedule": "매일 01:30",
                "location": "backup.vcf.lab/vcsa", "last": {"status": "SUCCESS", "end": now - 8 * 3600, "message": "", "type": "SCHEDULED"},
                "last_success": now - 8 * 3600, "history": [{"id": f"j{k}", "status": "SUCCEEDED", "end": now - 8 * 3600 - k * 86400, "type": "SCHEDULED"} for k in range(5)],
                "updated": now, "error": ""}
    return None


def demo_vm_protection() -> dict:
    """스냅숏(30분 점검) + VM 요약(백업 속성 포함) 데모"""
    now = time.time()
    names = [n for n, x in demo_topology()["vms"].items() if x["ips"]]          # 2.46.0 플랫폼 데모 VM 제외
    vms, bp = [], []
    for i, n in enumerate(names):
        snaps = []
        if i % 7 == 1:
            snaps = [{"name": "before-patch-2026-11", "created": now - 5 * 86400}]
        elif i % 7 == 3:
            snaps = [{"name": "VEEAM BACKUP TEMPORARY SNAPSHOT", "created": now - 30 * 3600}]
        elif i % 11 == 5:
            snaps = [{"name": f"step-{k}", "created": now - (4 - k) * 3600} for k in range(4)]
        elif i % 13 == 2:
            snaps = [{"name": "pre-upgrade", "created": now - 6 * 3600}]
        if snaps:
            vms.append({"name": n, "snapshots": snaps, "consolidation": i % 17 == 3})
        age = None if i % 9 == 4 else (3 + (i * 7) % 20 if i % 6 else 24 * (2 + i % 9))
        bp.append({"name": n, "host": HOSTS[i % len(HOSTS)], "power": "poweredOn", "vcpu": 4, "nics": ["Vmxnet3"], "cdrom_connected": 1 if i == 4 else 0, "tools": "guestToolsRunning",
                   "passthru": 1 if n.startswith("ai-") else 0, "usb": 0,
                   "snapshots": len(snaps), "snap_oldest": min((s["created"] for s in snaps), default=None),
                   "backup_fields": ({"NB_LAST_BACKUP": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - age * 3600))} if age is not None and i % 2
                                     else {}),
                   "notes_backup": (f"Last backup: {time.strftime('%m/%d/%Y %I:%M:%S %p', time.localtime(now - age * 3600))} [Veeam]" if age is not None and not i % 2 else "")})
    hosts = {h: {"cluster": "wld-bank01" if k < 4 else "wld-card01"} for k, h in enumerate(HOSTS)}
    return {"vms": vms, "bp_vms": {"vms": bp, "collected": now, "error": ""}, "hosts_dr": hosts}



def demo_lifecycle(t: str) -> tuple[list[dict], list[dict]]:
    """2.36.0 인증서 만료 달력·버전 수명 데모(만료일은 지금 기준 상대값)"""
    now = time.time()
    D = 86400
    nm = f"demo-{t}"
    if t == "vks":
        certs = [dict(src="vks", system=nm, cluster="bank/wld-bank01", kind="API 서버", name="10.20.0.21:6443", not_after=now + 41 * D, renew_key="vks-apiserver",
                      subject="kube-apiserver", issuer="kubernetes"),
                 dict(src="vks", system=nm, cluster="bank/wld-bank01", kind="cert-manager", name="bank/core-api-tls", not_after=now + 12 * D, renew_key="vks-certmanager",
                      subject="core-api.bank.vcf.lab", issuer="bank-ca-issuer", ready="False", renewal=now - 18 * D),
                 dict(src="vks", system=nm, cluster="bank/wld-bank01", kind="cert-manager", name="card/auth-gw-tls", not_after=now + 78 * D, renew_key="vks-certmanager",
                      subject="auth.card.vcf.lab", issuer="card-ca-issuer", ready="True", renewal=now + 48 * D),
                 dict(src="vks", system=nm, cluster="bank/wld-bank01", kind="커넥터 토큰", name="vSphere SSO 세션", not_after=now + 8 * 3600, renew_key="vks-token",
                      auto=True, note="커넥터가 만료 전 자동 재발급"),
                 dict(src="vks", system="demo-vks-supervisor", cluster="bank/wld-bank01", kind="컨트롤 플레인(kubeadm)", name="wld-bank01-cp-7x2kq",
                      not_after=now + 41 * D, renew_key="vks-cp", note="자동 갱신 설정 없음(rolloutBefore)"),
                 dict(src="vks", system="demo-vks-supervisor", cluster="card/wld-card01", kind="컨트롤 플레인(kubeadm)", name="wld-card01-cp-9mhv4",
                      not_after=now + 236 * D, renew_key="vks-cp", auto_renew_days=30, note="자동 갱신: 만료 30일 전 롤링")]
        certs += [dict(src="vks", system=nm, cluster="bank/wld-bank01", kind="kubelet 서빙", name=e["name"], not_after=now + (190 + k * 7) * D, renew_key="vks-kubelet",
                       subject=f"system:node:{e['name']}", issuer="kubernetes") for k, e in enumerate(DEMO_ENTITIES["vks"][:4])]
        return certs, [{"product": "k8s", "system": nm, "version": "1.30.1+vmware.1", "build": "v1.30.1+vmware.1", "count": 1, "scope": "bank/wld-bank01"},
                       {"product": "k8s", "system": "demo-vks-supervisor", "version": "1.29.7+vmware.1", "build": "", "count": 1, "scope": "Cluster-02 (Supervisor)"}]
    if t == "vcenter":
        certs = [dict(src="vcenter", system=nm, kind="vCenter 머신 SSL", name="vcenter.vcf.lab:443", not_after=now + 402 * D, renew_key="vcenter",
                      subject="vcenter.vcf.lab", issuer="CA")]
        certs += [dict(src="esxi", system=nm, kind="ESXi 호스트", name=h, cluster="Cluster-01" if i < 4 else "Cluster-02",
                       not_after=now + (9 if i == 5 else 700 + i * 3) * D, renew_key="esxi", subject=h, issuer="CA") for i, h in enumerate(HOSTS)]
        vers = [{"product": "vcenter", "system": nm, "version": "8.0.3", "build": "24322831", "count": 1, "scope": "vcenter.vcf.lab"},
                {"product": "esxi", "system": nm, "version": "8.0.3", "build": "24022510", "count": 4, "scope": "Cluster-01"},
                {"product": "esxi", "system": nm, "version": "8.0.3", "build": "24022510", "count": 3, "scope": "Cluster-02"},
                {"product": "esxi", "system": nm, "version": "8.0.2", "build": "23299997", "count": 1, "scope": "Cluster-02"},
                {"product": "vsan", "system": nm, "version": "8.0.3", "build": "", "count": 8, "scope": "Cluster-01·02"}]
        return certs, vers
    if t == "nsx":
        return ([dict(src="nsx", system=nm, kind="NSX 인증서", name="mp-cluster-cert", not_after=now + 55 * D, renew_key="nsx", subject="nsx.vcf.lab", issuer="CA"),
                 dict(src="nsx", system=nm, kind="관리 TLS", name="nsx.vcf.lab:443", not_after=now + 55 * D, renew_key="nsx", subject="nsx.vcf.lab", issuer="CA")],
                [{"product": "nsx", "system": nm, "version": "4.2.1.0", "build": "", "count": 1, "scope": "nsx.vcf.lab"}])
    if t == "sddc":
        return ([dict(src="sddc", system=nm, kind="관리 TLS", name="sddc.vcf.lab:443", not_after=now + 330 * D, subject="sddc.vcf.lab", issuer="CA")],
                [{"product": "vcf", "system": nm, "version": "5.2.1", "build": "5.2.1.0-24307856", "count": 1, "scope": "sddc.vcf.lab"}])
    if t == "vcfops":
        return ([dict(src="vcfops", system=nm, kind="관리 TLS", name="vcfops.vcf.lab:443", not_after=now + 160 * D, subject="vcfops.vcf.lab", issuer="CA")],
                [{"product": "aria", "system": nm, "version": "8.18.2", "build": "", "count": 1, "scope": "VCF Operations"}])
    if t == "avi":
        return ([dict(src="avi", system=nm, kind="관리 TLS", name="avi.vcf.lab:443", not_after=now - 3 * D, subject="avi.vcf.lab", issuer="avi.vcf.lab")],
                [{"product": "avi", "system": nm, "version": "31.1.1", "build": "", "count": 1, "scope": "avi.vcf.lab"}])
    return ([dict(src=t, system=nm, kind="관리 TLS", name=f"{t}.vcf.lab:443", not_after=now + (250 + len(t) * 20) * D, subject=f"{t}.vcf.lab", issuer="CA")], [])


def demo_drift(snap: dict) -> None:
    """2.36.0 구성 드리프트 데모 — 인프라 점검 스냅숏에 비교할 설정을 채운다(호스트 1대는 다수와 다르게)"""
    for i, (h, x) in enumerate(snap["hosts"].items()):
        x.update(cluster="Cluster-01" if i < 4 else "Cluster-02", conn="connected", sockets=2,
                 cpu_model="Intel(R) Xeon(R) Gold 6430" if i < 4 else "Intel(R) Xeon(R) Gold 6338", ntp_servers=["ntp1.vcf.lab", "ntp2.vcf.lab"] if i != 2 else ["pool.ntp.org"],
                 services={"ntpd": True, "TSM-SSH": i == 6, "TSM": False}, lockdown="lockdownNormal", ht_active=True,
                 power_policy="static" if i != 5 else "dynamic",
                 nics=[{"device": f"vmnic{k}", "driver": "bnxtnet", "driver_version": "226.0.145.0" if i != 5 else "225.0.130.0", "firmware": "226.0.145.0",
                        "speed": 25000} for k in range(2)],
                 vswitches=[{"name": "dvs-wld", "kind": "dvs", "mtu": 9000, "uplinks": ["vmnic0", "vmnic1"]}], vmks=[{"device": "vmk0", "mtu": 1500, "services": ["management"], "switch": "dvs-wld", "pg": "", "pg_key": "dvportgroup-mgmt", "vlan": None},
                                                                                     {"device": "vmk2", "mtu": 9000 if i != 3 else 1500, "services": ["vsan"], "switch": "dvs-wld", "pg": "", "pg_key": "dvportgroup-vsan", "vlan": None}],
                 hbas=[{"device": "vmhba0", "driver": "nvme_pcie", "driver_version": "1.2.4.11", "firmware": ""}])
    snap["clusters"] = {"Cluster-01": {"ha": True, "ha_admission": True, "ha_policy": "ClusterFailoverLevelAdmissionControlPolicy", "ha_failover_level": 1,
                                       "ha_host_monitoring": "enabled", "ha_vm_monitoring": "vmMonitoringDisabled", "ha_isolation": "powerOff",
                                       "drs": True, "drs_behavior": "fullyAutomated", "drs_rate": 3, "evc": "", "vsan": True, "vsan_esa": True},
                        "Cluster-02": {"ha": True, "ha_admission": True, "ha_policy": "ClusterFailoverLevelAdmissionControlPolicy", "ha_failover_level": 1,
                                       "ha_host_monitoring": "enabled", "ha_vm_monitoring": "vmMonitoringDisabled", "ha_isolation": "powerOff",
                                       "drs": True, "drs_behavior": "partiallyAutomated", "drs_rate": 3, "evc": "intel-icelake", "vsan": True, "vsan_esa": False}}
