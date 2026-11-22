"""1·2단계 이상 탐지 (LLM 이전, 실시간·저비용)

1) 규칙: VCF 스택 장애 시그니처(PSOD, APD/PDL, vSAN, NSX, HA, 인증 실패, 하드웨어 등)
2) 통계: 템플릿 마이닝(가변값 마스킹) → 신규 템플릿(novelty), 소스별 분당 발생량 급증(EWMA z-score)
3) 원본 심각도(critical/error) 및 alarm/alert 종류 가중치

점수가 llm_threshold 이상이면 LLM(Gemma 4 31B) 분석 큐로 넘긴다.
"""
from __future__ import annotations

import math
import re
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from .models import SEV_RANK, LogEvent

try:                                  # Python 3.11+
    import re._constants as _sc
    import re._parser as _sp
except ImportError:                   # pragma: no cover
    import sre_constants as _sc       # type: ignore
    import sre_parse as _sp           # type: ignore

_GATE_MIN = 3


def _gate_seq(items) -> set[str] | None:
    """정규식 시퀀스가 매치되려면 반드시 포함해야 하는 소문자 리터럴 후보 집합(그중 하나 이상) — 없으면 None.
    보수적 추출: 리터럴 연속·필수 그룹·전 분기 리터럴만 인정, 문자 클래스·0회 반복은 리터럴을 끊는다."""
    run: list[str] = []
    cands: list[set[str]] = []

    def flush():
        if len(run) >= _GATE_MIN:
            cands.append({"".join(run)})
        run.clear()
    for op, av in items:
        if op is _sc.LITERAL:
            run.append(chr(av).lower())
            continue
        if op is _sc.AT:              # \b ^ $ 는 폭 0
            continue
        flush()
        sub = _gate_node(op, av)
        if sub:
            cands.append(sub)
    flush()
    best = None
    for c in cands:
        if min(map(len, c)) < _GATE_MIN:
            continue
        if best is None or len(c) < len(best):
            best = c
    return best


def _gate_node(op, av) -> set[str] | None:
    if op is _sc.SUBPATTERN:
        return _gate_seq(av[-1])
    if op is _sc.BRANCH:
        out: set[str] = set()
        for b in av[1]:
            s = _gate_seq(b)
            if not s:
                return None
            out |= s
        return out
    if op in (_sc.MAX_REPEAT, _sc.MIN_REPEAT, getattr(_sc, "POSSESSIVE_REPEAT", None)):
        lo, _hi, body = av
        return _gate_seq(body) if lo >= 1 else None
    if op is getattr(_sc, "ATOMIC_GROUP", None):
        return _gate_seq(av)
    return None


def literal_gate(pattern: str) -> tuple[str, ...]:
    """규칙 사전 필터 — 메시지(소문자)에 이 중 하나도 없으면 정규식을 돌릴 필요가 없다(빈 튜플 = 필터 없음)."""
    try:
        return tuple(sorted(_gate_seq(_sp.parse(pattern)) or ()))
    except Exception:  # noqa: BLE001
        return ()


@dataclass
class Rule:
    name: str
    pattern: re.Pattern
    category: str
    severity: str
    weight: float
    sources: tuple[str, ...] = ()
    gate: tuple[str, ...] = field(default=())


NET_SRC = ("arista", "cisco", "network", "syslog")


def _r(name, pat, cat, sev, w, sources=()):
    return Rule(name, re.compile(pat, re.I), cat, sev, w, tuple(sources), literal_gate(pat))


DEFAULT_RULES: list[Rule] = [
    # --- AIOps 자체: 수집 파이프라인 중단
    _r("collection_stop", r"^수집 (중단|오류|미수신):", "collection", "error", 0.85, ("aiops",)),
    # --- AIOps 자체: 플랫폼 상태(이벤트 루프 지연·수집 과부하·DB 쓰기·내부 작업·알림 발송·이중화)
    _r("platform_down", r"^플랫폼 장애:", "platform", "error", 0.9, ("aiops",)),
    _r("platform_warn", r"^플랫폼 경고:", "platform", "warning", 0.7, ("aiops",)),
    # --- 현장 센서(안드로이드 폰, 2.50.0) — 온도·습도·소리·진동·위치 이동·배터리·무응답
    _r("sensor_crit", r"^현장 센서 위험:", "environment", "critical", 0.9, ("sensor",)),
    _r("sensor_warn", r"^현장 센서 경고:", "environment", "warning", 0.65, ("sensor",)),
    _r("sensor_silent", r"^현장 센서 무응답:", "environment", "warning", 0.7, ("sensor",)),
    # --- VM 게스트·물리 서버 OS (Fluent Bit·rsyslog 에이전트) — Linux
    _r("agent_silent", r"^에이전트 무응답:", "agent", "warning", 0.7, ("vm", "baremetal")),
    _r("sli_breach", r"^성능 SLI 위반\((orange|red)\):", "performance", "warning", 0.7, ("vcenter",)),
    _r("linux_panic", r"(Kernel panic|BUG: unable to handle|general protection fault: [0-9a-f]+ \[#|Oops: [0-9a-f]+ \[#|kernel BUG at)", "os", "critical", 0.95, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_hung", r"(soft lockup - CPU#|hard LOCKUP|blocked for more than \d+ seconds|rcu_sched self-detected stall|watchdog: BUG)", "os", "error", 0.85, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_oom", r"(Out of memory: Kill(ed)? process|oom-kill:|invoked oom-killer|Memory cgroup out of memory)", "os", "error", 0.85, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_fs", r"(Remounting filesystem read-only|EXT4-fs (error|warning) \(device|XFS \(\w+\): (Corruption|Internal error|metadata I/O error|log I/O error)|I/O error, dev \w+|Buffer I/O error on dev|blk_update_request: I/O error)", "storage", "critical", 0.9, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_disk_full", r"(No space left on device|Disk quota exceeded|filesystem is full)", "capacity", "error", 0.8, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_scsi", r"(sd \d+:\d+:\d+:\d+: \[\w+\] (tag#\d+ )?(FAILED|timing out|Unhandled error)|scsi_io_completion|task abort on host|rejecting I/O to offline device)", "storage", "error", 0.8, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_multipath", r"(multipathd?: .*(failing path|remaining active paths: 0|mark as failed)|device-mapper: multipath: Failing path)", "storage", "error", 0.8, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_nfs", r"(nfs: server \S+ not responding|NFS: .* timed out|lockd: server \S+ not responding)", "storage", "error", 0.8, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_segv", r"(segfault at [0-9a-f]+|traps: \S+\[\d+\] general protection|\(core dumped\)|systemd-coredump.*dumped core)", "service", "warning", 0.55, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_unit_fail", r"(Failed to start .+\.(service|mount|socket)|\.service: (Main process exited, code=(killed|dumped)|Failed with result '[^']+')|entered failed state|Start request repeated too quickly)", "service", "error", 0.7, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_net", r"(NIC Link is Down|Link is Down|carrier lost|bonding: \S+: link status definitely down|Detected Tx Unit Hang|NETDEV WATCHDOG)", "network", "error", 0.75, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_time", r"(chronyd.*(no selectable sources|System clock wrong|Can't synchronise|clock step)|ntpd.*(no servers can be used|time reset)|systemd-timesyncd.*(Timed out|failed))", "os", "warning", 0.6, ("vm", "baremetal", "syslog", "ingest")),
    _r("linux_mce", r"(mce: \[Hardware Error\]|EDAC \S+: \d+ (CE|UE) |Machine check events logged|Corrected error.*memory)", "hardware", "error", 0.85, ("vm", "baremetal", "syslog", "ingest")),
    _r("vmtools", r"(vmtoolsd.*(error|failed|crash|Core dump)|open-vm-tools.*(fail|error)|VMware Tools .*(not running|failed|out of date))", "vm", "warning", 0.55, ("vm", "baremetal", "syslog", "ingest")),
    # --- Windows 이벤트 로그(Fluent Bit winevtlog → "EventID=<n> <Provider>: <Message>")
    _r("win_crash_reboot", r"EventID=(41 Microsoft-Windows-Kernel-Power|6008 EventLog|1001 (Microsoft-Windows-WER-SystemErrorReporting|BugCheck))\b", "os", "critical", 0.95, ("vm", "baremetal", "ingest")),
    _r("win_service_crash", r"EventID=(7031|7034|7024|7023) Service Control Manager\b", "service", "error", 0.75, ("vm", "baremetal", "ingest")),
    _r("win_disk", r"EventID=(7|11|51|129|153|157) (disk|Disk|storahci|stornvme|storvsc|vmscsi|LSI_SAS\w*|pvscsi|iaStor\w*|Microsoft-Windows-StorPort)\b|EventID=(55|98) (Ntfs|Microsoft-Windows-Ntfs)\b", "storage", "error", 0.85, ("vm", "baremetal", "ingest")),
    _r("win_low_disk", r"EventID=2013 (srv|Srv)\b|EventID=(2004|2019|2020) (Resource-Exhaustion-Detector|Microsoft-Windows-Resource-Exhaustion-Detector|srv)\b", "capacity", "warning", 0.65, ("vm", "baremetal", "ingest")),
    _r("win_logon_fail", r"EventID=(4625|4771|4776) Microsoft-Windows-Security-Auditing\b", "security", "warning", 0.5, ("vm", "baremetal", "ingest")),
    _r("win_lockout", r"EventID=(4740|4720|4732|4728|1102) Microsoft-Windows-(Security-Auditing|Eventlog)\b", "security", "warning", 0.65, ("vm", "baremetal", "ingest")),
    _r("win_app_crash", r"EventID=(1000|1002) Application (Error|Hang)\b", "service", "warning", 0.5, ("vm", "baremetal", "ingest")),
    _r("win_time", r"EventID=(129|134|36|47|50) Microsoft-Windows-Time-Service\b", "os", "warning", 0.55, ("vm", "baremetal", "ingest")),
    _r("win_cluster", r"EventID=(1135|1069|1177|1146|1205) Microsoft-Windows-FailoverClustering\b", "cluster", "critical", 0.9, ("vm", "baremetal", "ingest")),
    _r("win_sql", r"(EventID=(823|824|825|9002|17883|833) MSSQL\S*|MSSQL\S*: .*(Error: (823|824|825|9002)\b|I/O requests taking longer than 15 seconds))", "service", "critical", 0.9, ("vm", "baremetal", "ingest")),
    # --- DB 서버(게스트·물리) — Oracle alert.log · PostgreSQL · MySQL/MariaDB
    _r("db_oracle", r"\bORA-(00600|07445|04031|04030|01578|00257|19809|16038|27072|00353|01110|00494|29740|00470|00471)\b", "service", "critical", 0.9, ("vm", "baremetal", "ingest", "syslog")),
    _r("db_postgres", r"(\bPANIC: |could not write to file .*No space|database system was interrupted|terminating connection due to administrator command|FATAL:  the database system is in recovery mode|out of shared memory)", "service", "error", 0.8, ("vm", "baremetal", "ingest", "syslog")),
    _r("db_mysql", r"(InnoDB: (Database page corruption|Assertion failure|Unable to lock)|\[ERROR\] .*(Table '.*' is marked as crashed|Disk is full)|mysqld got signal (6|11))", "service", "error", 0.8, ("vm", "baremetal", "ingest", "syslog")),
    # --- VM 하이퍼바이저(vmx) 로그(ESXi syslog 경유, vmx.log.destination=syslog-and-disk)
    _r("vmx_error", r"(MsgQuestion|Msg_Question|Monitor panic|Unrecoverable memory allocation failure|VMX has left the building: 0 with error|Checkpoint_Unstun|Snapshot.*(failed|error)|DISKLIB-.*(failed|error|Could not open))", "vm", "error", 0.75, ("vm",)),
    # --- ESXi / vSphere 커널·스토리지
    _r("psod", r"\b(PSOD|purple screen|panic|#PF Exception|Machine Check Exception|MCE)\b", "host", "critical", 1.0),
    _r("apd_pdl", r"(All Paths Down|\bAPD\b|Permanent Device Loss|\bPDL\b|lost access to volume)", "storage", "critical", 0.95),
    _r("path_down", r"(path redundancy .* (lost|degraded)|NMP.*(failed|dead)|state in doubt|H:0x[1-9a-f]|SCSI.*(abort|reset))", "storage", "error", 0.7),
    _r("vmfs_heartbeat", r"(heartbeat.*(timed out|lost)|Lost connectivity to (storage|device))", "storage", "error", 0.8),
    _r("vsan", r"\b(vSAN|VSAN|LSOM|DOM|CMMDS)\b.*(degraded|absent|inaccessible|failed|congestion|partition|resync.*(stuck|slow))", "storage", "error", 0.8),
    _r("disk_fail", r"(disk|drive|nvme|ssd).*(fail|predictive|offline|unhealthy|wear)", "hardware", "error", 0.7),
    _r("ha", r"(vSphere HA|\bFDM\b).*(isolat|failover|failed|cannot|partition|lost)|host isolation", "cluster", "critical", 0.9),
    _r("host_conn", r"(host .* (not responding|disconnected)|lost connection to (the )?host|hostd .*(not responding|crash))", "host", "error", 0.8),
    _r("vm_crash", r"(guest OS (has )?crash|VMX .* (panic|core dump)|vmx\s.*unrecoverable|VM .* (failed to power on|stopped unexpectedly))", "vm", "error", 0.75),
    _r("snapshot", r"(consolidation (is )?(needed|required|failed)|snapshot .*(failed|too many))", "vm", "warning", 0.5),
    _r("datastore_full", r"(datastore .*(full|out of space|usage on disk)|no space left|thin.*overcommit)", "storage", "error", 0.7),
    _r("memory", r"(out of memory|\bOOM\b|memory (exhaust|pressure|ballooning|swap))", "capacity", "warning", 0.55),
    _r("cpu_ready", r"(cpu ready|co-?stop|cpu contention)", "capacity", "warning", 0.45),
    # --- 인증·보안
    _r("auth_fail", r"(authentication fail|failed (password|login)|login fail|invalid credentials|account (locked|lockout)|bad password)", "security", "warning", 0.6),
    _r("priv_change", r"(permission .*(added|changed)|role .* (created|modified)|SSH .* (enabled|started)|lockdown mode .*disabled)", "security", "warning", 0.55),
    _r("cert", r"(certificate .*(expir|invalid|revoked|untrusted)|SSL .*handshake.*fail|x509)", "security", "error", 0.75),
    # --- NSX
    _r("nsx_tn", r"(transport node|TEP|tunnel|BFD).*(down|degraded|failed|unreachable)", "network", "error", 0.8, ("nsx", "nsx-edge", "syslog", "vcflogs")),
    _r("nsx_bgp", r"\bBGP\b.*(down|Idle|Active|reset|notification)", "network", "error", 0.85, ("nsx", "nsx-edge", "vcflogs", "syslog", "vcenter", "esxi")),
    _r("nsx_mgr", r"(manager cluster|CCP|MPA|corfu).*(down|degraded|unstable|disconnect)", "network", "critical", 0.9),
    _r("dfw", r"(firewall .*(drop|deny|reject).*rate|DFW .*(fail|exceed))", "network", "warning", 0.5),
    _r("link", r"(link (is )?down|vmnic\d+ .*(down|disconnect)|uplink .*(lost|down)|LACP .*(down|failed))", "network", "error", 0.75),
    # --- 서비스·플랫폼
    _r("service_down", r"(service .*(stopped|failed|crash|unhealthy|not running)|vmon .*(failed|restart)|vpxd .*(crash|failed))", "service", "error", 0.75),
    _r("task_fail", r"(task .* failed|operation failed|deployment (failed|error)|_FAILED\b)", "operation", "warning", 0.5),
    _r("backup", r"(backup .*(fail|error)|file-based backup.*fail)", "operation", "error", 0.65),
    _r("upgrade", r"(upgrade|precheck|lifecycle|vLCM).*(fail|error|incompatible)", "operation", "warning", 0.55),
    # --- SRM / 복제
    _r("replication", r"(RPO violation|replication .*(error|paused|stalled|not active)|vSphere Replication .*fail)", "dr", "error", 0.8),
    _r("recovery_plan", r"(recovery plan .*(error|fail|incomplete)|protection group .*(not configured|error))", "dr", "error", 0.75),
    # --- Avi
    _r("avi_vs", r"(virtual ?service .*(down|OPER_DOWN)|pool .*(down|all servers down)|server .*down)", "lb", "error", 0.8),
    _r("avi_se", r"(service engine .*(down|disconnect|failed)|SE .*(heartbeat|down))", "lb", "critical", 0.85),
    # --- vCenter 어플라이언스
    _r("vc_vpxd", r"(vpxd.*(exited|crash|core ?dump|restarting|unhandled exception)|vmon.*(vpxd|vsphere-ui|sts).*(failed|exited|restart))", "service", "critical", 0.9, ("vcenter", "syslog", "vcflogs")),
    _r("vc_db", r"(vpostgres|postgres|VCDB|vPostgres).*(FATAL|PANIC|out of (disk|space)|could not (write|extend)|too many connections|deadlock)", "service", "error", 0.85, ("vcenter", "syslog", "vcflogs")),
    _r("vc_disk", r"(/storage/(log|db|seat|core|archive|lvm_snapshot)\b.*(9\d|100)\s?%|(partition|filesystem) .*(full|exceed|9\d\s?% used))", "capacity", "error", 0.8),
    _r("vc_sso", r"\b(STS|SSO|lookup ?service|vmdir|vmafd|identity source)\b.*(fail|error|expired|unreachable|timed out)", "security", "error", 0.7, ("vcenter", "syslog", "vcflogs")),
    # --- ESXi 추가
    _r("esxi_vob", r"vob\.(storage|vmfs|scsi|net|hbr|vsan)\.[\w.]*(lost|down|failed|apd|pdl|degraded|redundancy)", "host", "error", 0.8),
    _r("esxi_time", r"\b(NTP|PTP|time ?sync)\b.*(unsynchroni[sz]ed|not synchroni[sz]ed|drift|offset .* (large|exceed))", "host", "warning", 0.5),
    # --- NSX Edge (데이터플레인·HA·서비스)
    _r("edge_dp", r"(datapath(d)?|dataplane|DPDK|fastpath).*(crash|core|restart|stuck|hang|fail|overload|ring full|high cpu)", "edge", "critical", 0.9, ("nsx-edge", "nsx", "syslog", "vcflogs")),
    _r("edge_ha", r"(edge|tier-?[01]|T[01] gateway|service router|\bSR\b).*(HA (state|status)|failover|split.?brain|became active|standby)", "edge", "critical", 0.85, ("nsx-edge", "nsx", "syslog", "vcflogs")),
    _r("edge_nic", r"\b(fp-eth\d+|vNIC|uplink-\d)\b.*(down|link (lost|failure)|disconnect)", "edge", "error", 0.8, ("nsx-edge", "nsx", "syslog")),
    _r("edge_vpn", r"\b(IPSec|IKE|VPN|L2VPN)\b.*(down|failed|not established|negotiation fail|expired)", "edge", "error", 0.75, ("nsx-edge", "nsx", "syslog")),
    _r("edge_cap", r"(edge|nsx).*(cpu|memory|disk) (usage|utilization) .*(high|above|exceed|9\d\s?%)", "capacity", "warning", 0.55, ("nsx-edge", "nsx", "syslog")),
    # --- NSX ALB(Avi) 추가
    _r("avi_ctrl", r"(controller|cluster) .*(node .*(down|inactive|not ready)|leader .*(change|lost)|quorum|cluster (not ready|degraded))", "lb", "critical", 0.85, ("avi", "syslog")),
    _r("avi_health", r"health ?score (?:is |of |dropped to )?(?:[0-4]?\d)(?!\d)", "lb", "warning", 0.55, ("avi",)),
    _r("avi_sec", r"\b(WAF|DDoS|rate ?limit|bot)\b.*(block|attack|exceed|detect|deny)", "security", "warning", 0.6, ("avi", "syslog")),
    _r("avi_gslb", r"\bGSLB\b.*(down|unreachable|fail|stale)", "lb", "error", 0.75, ("avi", "syslog")),
    # --- SRM 추가
    _r("srm_site", r"(site pairing|remote site|paired site|peer site).*(disconnect|lost|unreachable|fail|broken)", "dr", "error", 0.8, ("srm", "syslog")),
    _r("srm_array", r"(\bSRA\b|array (manager|pair)|storage replication adapter).*(error|fail|not responding)", "dr", "error", 0.75, ("srm", "syslog")),
    _r("srm_test", r"(test recovery|cleanup|reprotect|failover).*(fail|error|incomplete)", "dr", "warning", 0.6, ("srm", "syslog")),
    # --- VCF Operations
    _r("ops_node", r"(analytics|collector|cassandra|gemfire|cluster|node).*(down|offline|not running|failed to start|out of sync|unreachable)", "ops", "error", 0.75, ("vcfops",)),
    _r("ops_adapter", r"(adapter|collector group|cloud proxy).*(not receiving data|collection (failed|down|stopped)|stopped|data receiving.*(fail|stop))", "ops", "warning", 0.6, ("vcfops", "syslog")),
    # --- VKS · Supervisor · Kubernetes
    _r("k8s_crash", r"(CrashLoopBackOff|Back-off restarting failed container)", "kubernetes", "error", 0.8),
    _r("k8s_image", r"(ImagePullBackOff|ErrImagePull|Failed to pull image|manifest unknown|pull access denied)", "kubernetes", "error", 0.75),
    _r("k8s_oom", r"(OOMKill(ed|ing)|Memory cgroup out of memory|java\.lang\.OutOfMemoryError|SystemOOM)", "kubernetes", "error", 0.8),
    _r("k8s_evict", r"(\bEvicted\b|eviction manager|EvictionThresholdMet|DiskPressure|ephemeral-storage .*(exceed|used))", "kubernetes", "error", 0.75),
    _r("k8s_node", r"(NodeNotReady|노드 \S+ Ready=(False|Unknown)|kubelet stopped posting node status|PLEG is not healthy|node .* NotReady)", "kubernetes", "critical", 0.9),
    _r("k8s_sched", r"(FailedScheduling|Insufficient (cpu|memory|nvidia)|untolerated taint|didn't match Pod's node affinity|스케줄 불가)", "kubernetes", "warning", 0.55),
    _r("k8s_volume", r"(FailedMount|FailedAttachVolume|MountVolume\.\w+ failed|AttachVolume\.Attach failed|CnsFault|ProvisioningFailed|volume .* (not attached|attach failed))", "storage", "error", 0.8),
    _r("etcd", r"(etcdserver: (request timed out|leader changed|no leader|too many requests)|apply request took too long|slow fdatasync|database space exceeded|readyz 실패.*etcd)", "kubernetes", "critical", 0.95),
    _r("apiserver", r"(Timeout: request did not complete|kube-apiserver.*(unavailable|readyz 실패|connection refused|too many requests)|the server is currently unable to handle)", "kubernetes", "error", 0.8),
    _r("cni", r"(\bCNI\b|antrea|calico|NetworkReady=false|failed to setup network for sandbox|\bNCP\b|nsx-ncp).*(error|fail|not ready|not initialized)", "network", "error", 0.8),
    _r("capi", r"(VKS (Machine|Cluster) .* — |Machine .*(Failed|CreateError)|VirtualMachine .* failed|MachineHealthCheck\w* .*unhealthy)", "kubernetes", "error", 0.85),
    _r("supervisor", r"\b(Supervisor|WCP|wcpsvc|spherelet|vm-?operator|vmop|image-controller)\b.*(error|fail|not ready|degraded|unhealthy|stuck|timed out)", "supervisor", "error", 0.8, ("vks-supervisor", "vcenter", "syslog", "vcflogs")),
    # --- 네트워크 스위치·라우터(Arista EOS · Cisco NX-OS/IOS-XE · syslog 니모닉 + 커넥터 상태 변화) — 2.2
    _r("net_if_down", r"(%(LINK|LINEPROTO)-\d-UPDOWN:[^\n]*changed state to down|%ETHPORT-\d-IF_DOWN\w*|^인터페이스 \S+ 다운)", "network", "error", 0.75, NET_SRC),
    _r("net_err_disabled", r"(err-?disabled|%PM-\d-ERR_DISABLE|%ETHPORT-\d-IF_ERROR_VLANS_SUSPENDED|%ETHPORT-\d-IF_ERRDIS\w*)", "network", "error", 0.8, NET_SRC),
    _r("net_flap", r"(%PM-\d-(LINK_FLAP|FLAP)\w*|%ETH(PORT)?-\d-\w*FLAP\w*|link[- ]flap)", "network", "warning", 0.75, NET_SRC),
    _r("net_bgp_down", r"(%BGP-\d-ADJCHANGE:[^\n]*(old state Established[^\n]*new state (Idle|Active|Connect|OpenSent)|neighbor \S+ Down|Down )"
       r"|%BGP-\d-(BGP_SESSION_DOWN|NOTIFICATION)\w*|^BGP 피어 \S+\(.*\) Established → )", "network", "error", 0.85, NET_SRC),
    _r("net_ospf_down", r"(%OSPF\w*-\d-ADJ\w*:[^\n]*(from FULL to|to DOWN| Down)|OSPF[^\n]*neighbor[^\n]*(state DOWN|went down))", "network", "error", 0.85, NET_SRC),
    _r("net_mlag", r"(%MLAG-\d-\w+:[^\n]*(inactive|disabled|down|disconnected|timeout|failover)|^MLAG (state|peer_link|neg) .* → (?!active|up|connected))",
       "network", "critical", 0.9, NET_SRC),
    _r("net_vpc", r"(%VPC-\d-(PEER_KEEP_ALIVE_RECV_FAIL|PEER_LINK_DOWN|VPC_PEER_LINK_DOWN|PEERKEEPALIVE_RECV_FAIL|DUAL_ACTIVE|VPC_SUSPENDED)\w*"
       r"|vPC peer-link (is )?down|^vPC (state|peer_link|neg) .* → (?!peer-ok|up|peer-alive))", "network", "critical", 0.9, NET_SRC),
    _r("net_stp", r"(%(SPANTREE|STP|SPANNING_TREE|STPTOPOLOGY)-\d-(TOPOTRAP|ROOTCHANGE|ROOT_CHANGE|BLOCK_PVID\w*|LOOPGUARD\w*|BPDUGUARD\w*|BPDU_GUARD\w*|"
       r"LOOP_GUARD\w*|INCONSISTENT\w*|PORT_INCONSISTENT)|bpdu ?guard|loop[- ]?(detected|guard))", "network", "warning", 0.8, NET_SRC),
    _r("net_portchannel", r"(%(ETH_PORT_CHANNEL|EC|LAG|LACP)-\d-\w*(DOWN|SUSPEND\w*|INDIVIDUAL|NOT_IN\w*|MISMATCH|UNBUNDLE\w*|DETACHED)\w*"
       r"|LACP[^\n]*(timeout|timed out|defaulted))", "network", "error", 0.8, NET_SRC),
    _r("net_mac_flap", r"(%\w*-\d-\w*(MAC_?MOVE|MACFLAP|FLAP_NOTIF|MAC_DUP\w*)\w*|mac address \S+ (is )?(moving|flapping)|flapping between port)", "network", "warning", 0.75, NET_SRC),
    _r("net_xcvr", r"(%(XCVR|TRANSCEIVER|SFP|ETHPORT)-\d-\w*(UNSUPPORTED|NOT_SUPPORTED|RX_POWER|TX_POWER|DOM|SFP_CHECKSUM)\w*|transceiver[^\n]*(unsupported|alarm|power (low|high)))",
       "network", "warning", 0.7, NET_SRC),
    _r("net_system", r"(%(SYS-\d-(RESTART|RELOAD)|SYSMGR-\d-(SERVICE_CRASHED|HEARTBEAT_FAILURE)|SYS-2-WATCHDOG|PLATFORM-\d-MOD_FAIL|PROCMGR-\d-PROCESS_(TERMINATED|RESTART)"
       r"|LAUNCHER-\d-PROCESS_RESTART|SYS-3-CPUHOG|KERNEL-\d-OOM)\w*|core dump|process \S+ (crashed|terminated unexpectedly))", "network", "critical", 0.85, NET_SRC),
    _r("net_storm", r"(%(STORM_CONTROL|STORM-CONTROL|STORMCONTROL)-\d-\w*|storm[- ]control[^\n]*(exceed|shutdown|discard)|%COPP-\d-\w*DROP\w*)", "network", "warning", 0.7, NET_SRC),
    _r("net_neighbor_lost", r"^(LLDP/CDP 이웃 사라짐|포트 \S+ 의 이웃 변경)", "network", "warning", 0.7, NET_SRC),
    _r("net_config", r"(%SYS-5-CONFIG_I|%VSHD-5-VSHD_SYSLOG_CONFIG_I|%SYS-5-CONFIG|Configured from (console|vty|memory|terminal)|%SYSDB-\d-CONFIG\w*)", "config", "warning", 0.5, NET_SRC),
    # --- 하드웨어(iLO/iDRAC/Redfish, IPMI SEL)
    _r("hw_power", r"(power supply|\bPSU\b|AC lost|redundancy lost)", "hardware", "error", 0.8),
    _r("hw_thermal", r"(temperature|thermal|overheat|fan .*(fail|degraded|removed))", "hardware", "warning", 0.6),
    _r("hw_mem", r"(uncorrectable|\bECC\b|DIMM .*(fail|error|degraded)|memory .*error)", "hardware", "critical", 0.9),
    _r("hw_misc", r"(\bIML\b.*(critical|caution)|\bSEL\b.*(critical|assert)|POST error|BIOS .* error|firmware .* (fail|corrupt))", "hardware", "error", 0.7),
]

# 템플릿 마이닝용 마스킹(순서 중요: 긴 패턴 먼저)
_MASKS = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<TS>"),
    (re.compile(r"\b(naa|eui|t10|mpx)\.[\w.:-]+"), "<DEV>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
    (re.compile(r"\b(vm|host|datastore|domain-c|network|dvportgroup|group-[a-z])-\d+\b"), "<MOID>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<N>"),
    (re.compile(r"\s+"), " "),
]


def make_template(msg: str) -> str:
    t = msg[:400]
    for rx, rep in _MASKS:
        t = rx.sub(rep, t)
    return t.strip()


class _LRU(OrderedDict):
    def __init__(self, cap: int):
        super().__init__()
        self.cap = cap

    def touch(self, k, v):
        if k in self:
            self.move_to_end(k)
        self[k] = v
        if len(self) > self.cap:
            self.popitem(last=False)


def pattern_key(source: str, template: str, host: str = "", entity: str = "") -> str:
    """2.45.0 패턴 키 — 소스 + 템플릿(호스트·개체 이름 가림). 피드백 학습·전조 학습이 같이 씀"""
    t = template or ""
    for nm in (host, entity):
        if nm and len(str(nm)) >= 3:
            t = t.replace(str(nm), "<n>")
    return f"{source or ''}|{t[:240]}"


class Detector:
    def __init__(self, cfg: dict):
        self.configure(cfg)
        self.started = time.time()
        self.templates = _LRU(50000)            # template → 누적 횟수
        self.bucket = defaultdict(int)          # source → 현재 분 카운트
        self.bucket_min = int(time.time() // 60)
        self.ewma: dict[str, tuple[float, float]] = {}  # source → (mean, var)
        self.burst_flag: dict[str, float] = {}

    def configure(self, cfg: dict) -> None:
        """설정 화면 핫리로드 — 정규식 검증 후 적용(오류 시 ValueError, 기존 규칙 유지)"""
        rules = list(DEFAULT_RULES)
        for r in cfg.get("extra_rules", []) or []:
            try:
                rules.append(_r(r["name"], r["pattern"], r.get("category", "custom"),
                                r.get("severity", "warning"), float(r.get("weight", 0.6)), r.get("sources", ())))
            except (KeyError, re.error) as e:
                raise ValueError(f"추가 규칙 '{r.get('name')}' 오류: {e}") from e
        try:
            suppress = [re.compile(p, re.I) for p in (cfg.get("suppress") or [])]
        except re.error as e:
            raise ValueError(f"억제 패턴 오류: {e}") from e
        self.cfg, self.rules, self.suppress = cfg, rules, suppress

    def _roll(self, now: float) -> None:
        m = int(now // 60)
        if m == self.bucket_min:
            return
        a = 0.2
        for src in set(list(self.bucket) + list(self.ewma)):
            c = self.bucket.get(src, 0)
            mean, var = self.ewma.get(src, (float(c), 1.0))
            diff = c - mean
            mean += a * diff
            var = (1 - a) * (var + a * diff * diff)
            self.ewma[src] = (mean, max(var, 1.0))
        self.bucket.clear()
        self.bucket_min = m

    def evaluate(self, ev: LogEvent) -> tuple[float, str, str]:
        """returns (score, category, derived_severity) and fills ev.template/reasons."""
        now = time.time()
        self._roll(now)
        msg = ev.message or ""
        ev.template = make_template(msg)
        if any(rx.search(msg) for rx in self.suppress):
            return 0.0, "suppressed", ev.severity

        score = 0.0
        category = "general"
        sev = ev.severity
        reasons: list[str] = []

        # 원본 심각도·종류
        base = {"critical": 0.75, "error": 0.45, "warning": 0.2}.get(ev.severity, 0.0)
        if ev.kind in ("alarm", "alert"):
            base += 0.15
        if base:
            score = max(score, base)
            reasons.append(f"원본 심각도 {ev.severity}/{ev.kind}")

        # 규칙
        best_w = 0.0
        low = msg.lower()
        for rule in self.rules:
            if rule.sources and ev.source not in rule.sources:
                continue
            if rule.gate and not any(k in low for k in rule.gate):   # 필수 키워드 사전 필터(정규식 비용 ~1/5)
                continue
            if rule.pattern.search(msg):
                if rule.weight > best_w:
                    best_w, category = rule.weight, rule.category
                score = rule.weight if rule.weight > score else min(1.0, score + 0.05)
                reasons.append(f"규칙:{rule.name}")
                if SEV_RANK[rule.severity] > SEV_RANK[sev]:
                    sev = rule.severity

        # 신규 템플릿(워밍업 이후)
        n = self.templates.get(ev.template, 0)
        self.templates.touch(ev.template, n + 1)
        warm = now - self.started > float(self.cfg.get("warmup_seconds", 300))
        if warm and n == 0 and ev.kind == "log" and len(msg) > 20:
            score = min(1.0, score + 0.3)
            reasons.append("신규 로그 패턴")

        # 발생량 급증
        self.bucket[ev.source] += 1
        src_known = ev.source in self.ewma          # 최소 1분 이상 기준선이 있는 소스만
        mean, var = self.ewma.get(ev.source, (0.0, 1.0))
        c = self.bucket[ev.source]
        z = (c - mean) / math.sqrt(var)
        if warm and src_known and c >= int(self.cfg.get("burst_min_count", 15)) and z >= float(self.cfg.get("burst_z", 3.5)):
            if now - self.burst_flag.get(ev.source, 0) > 120:   # 소스당 2분에 1회만 버스트 사유 부여
                self.burst_flag[ev.source] = now
                score = min(1.0, score + 0.35)
                reasons.append(f"발생량 급증 z={z:.1f} ({c}/분, 평균 {mean:.1f})")

        # 2.45.0 피드백 학습 — 운영자가 '소음/유용'으로 표시한 패턴의 가중치(0.2~1.2)
        learned = getattr(self, "learned", None)
        if learned and score > 0:
            w = learned.get(pattern_key(ev.source, ev.template, ev.host, ev.entity))
            if w is not None and w != 1.0:
                score = min(1.0, score * w)
                reasons.append(f"피드백 학습 ×{w}")

        ev.score = round(score, 3)
        ev.reasons = reasons
        return ev.score, category, sev

    def rates(self) -> dict[str, dict[str, float]]:
        return {s: {"current": self.bucket.get(s, 0), "mean": round(m, 2)}
                for s, (m, _) in self.ewma.items()} | {
            s: {"current": c, "mean": 0.0} for s, c in self.bucket.items() if s not in self.ewma}
