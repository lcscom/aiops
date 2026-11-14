"""Syslog 수신기(UDP/TCP, RFC3164·RFC5424) — ESXi·vCenter·NSX·VM 게스트·스위치 등 실시간 로그 푸시 경로.

ESXi:   esxcli system syslog config set --loghost='udp://<aiops>:514' && esxcli system syslog reload
NSX:    set logging-server <aiops>:514 proto udp level info   (Manager/Edge CLI)
vCenter: VAMI(5480) > Syslog > 대상 추가
VM 게스트(Linux): rsyslog '*.* @<aiops>:514'  /  Windows: NXLog·Fluent Bit → syslog 또는 /api/ingest
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime

from ..fortigate import is_fortigate, parse_line as fg_parse
from ..models import LogEvent, norm_severity
from .base import Connector
from .vmware_rest import sev_from_text

RFC5424 = re.compile(r"^<(\d{1,3})>\d (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?(.*)$", re.S)
RFC3164 = re.compile(r"^<(\d{1,3})>(?:(\w{3}\s+\d{1,2} \d\d:\d\d:\d\d)|(\d{4}-\d\d-\d\dT\S+))\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:?\s*(.*)$", re.S)
SD_PARAM = re.compile(r'(\w[\w.-]*)="((?:[^"\\]|\\.)*)"')

# ---- 앱(태그) → 소스 분류표. 소문자 비교, 정확 일치 우선 → 접두어
ESXI_APPS = {"vmkernel", "vmkwarning", "vobd", "hostd", "hostd-probe", "vpxa", "fdm", "vmauthd", "sshd", "shell",
             "esxupdate", "clomd", "vsanmgmtd", "vsansystem", "vsandevicemonitord", "osfsd", "cmmdsd", "lsud",
             "vmkdevmgr", "storagerm", "smartd", "ntpd", "ptpd", "crond", "hostprofiletrace", "rhttpproxy",
             "sfcb-vmware_base", "iofilterd-vmwarevmcrypt", "envoy", "settingsd", "esxtokend", "kmxa", "vmkeventd",
             "sdrsinjector", "healthd", "loadesx", "watchdog-hostd", "watchdog-vpxa", "dcui", "vmsyslogd",
             "vsanobserver", "spherelet"}
VC_APPS = {"vpxd", "vpxd-svcs", "vmon", "vsphere-ui", "sts", "vmdird", "envoy-sidecar", "applmgmt", "lookupsvc",
           "vmafdd", "vapi-endpoint", "eam", "vlcm", "trustmanagement", "vcha", "vmcam", "rbd", "content-library",
           "vsan-health", "vstats", "vsm", "sps", "pschealth", "certificatemanagement", "analytics", "observability",
           "infraprofile", "vtsdb", "vpostgres", "postgres", "rhttpproxy-vc", "updatemgr", "vmware-updatemgr",
           "topologysvc", "hvc", "lighttpd", "vmdnsd", "vmcad", "cis-license", "perfcharts", "statsmonitor", "vdtc"}
# Supervisor(WCP) — vCenter 의 wcp 서비스와 Supervisor 컨트롤 플레인 VM 전용 구성요소
SUPERVISOR_APPS = {"wcp", "wcpsvc", "wcp-schedext", "kube-scheduler-ext", "vmop", "vm-operator", "vmop-controller-manager",
                   "capw", "capv", "capi", "capw-controller-manager", "capv-controller-manager", "capi-controller-manager",
                   "nsx-ncp", "ncp", "spherelet", "image-controller", "vmware-system-csi", "vsphere-csi-controller",
                   "tkgs-plugin", "tanzu-addons-manager", "kapp-controller", "registry-agent", "net-operator",
                   "docker-registry", "vmware-system-logging", "fluentbit-supervisor"}
# Kubernetes 공통(워크로드 클러스터 노드·파드 — Fluent Bit 로 전송)
K8S_APPS = {"kube-apiserver", "kube-controller-manager", "kube-scheduler", "kube-proxy", "kubelet", "etcd", "containerd",
            "coredns", "antrea-agent", "antrea-controller", "calico-node", "cloud-provider-vsphere", "vsphere-cloud-controller-manager",
            "vsphere-csi-node", "csi-node", "metrics-server", "kube-vip", "konnectivity-agent", "guest-cluster-auth-svc",
            "fluent-bit", "fluentbit", "systemd", "kernel", "kubeadm", "cloud-init", "pinniped-concierge", "cert-manager"}
VCFOPS_APPS = {"vcops", "vrops", "casa", "vcops-watchdog", "cassandra", "gemfire", "suite-api", "vrlcm",
               "fleet-management", "vcf-ops", "vcfops", "admin-ui", "httpd-north", "vcops-analytics", "vcops-collector"}
SUP_CP_HOST = re.compile(r"^42[0-9a-f]{30}$", re.I)     # Supervisor 컨트롤 플레인 VM 노드 이름(BIOS UUID 형식)
NSX_EDGE_APPS = {"datapathd", "edge-dp", "dispatcher", "frr", "bgpd", "bfdd", "zebra", "ospfd", "nsd", "dhcp",
                 "dnsmasq", "charon", "ipsec", "nginx", "lb", "nsx-edge-nsxa", "nsx-edge-exporter", "nsx-sha", "nsx-edge"}
NSX_MGR_APPS = {"proton", "corfu", "corfu-server", "nsx-proxy", "nsx-opsagent", "nsxa", "cfgagent", "nsx-manager",
                "nsx-policy", "nsx-controller", "ccp", "mpa", "nsx-cfgagent", "nsx-syslog", "search", "idps-reporting"}
SRM_APPS = {"srm-server", "vmware-dr", "dr-configurator", "dr-client", "drconfig", "hms", "hbrsrv", "hbr-agent",
            "vmware-hbr", "vrms", "srm"}

# 네트워크 장비(2.2) — Arista EOS 프로세스(에이전트) 이름과 Cisco/Arista 공통 '%시설-심각도-니모닉' 형식
ARISTA_APPS = {"ebra", "lldp", "stp", "stptopology", "mlag", "bgp", "rib", "fru", "sysdb", "procmgr", "lag", "lagmgr", "lacp", "aaa", "acl",
               "ira", "configagent", "superserver", "powermanager", "thermostat", "xcvr", "eventmgr", "launcher", "smash", "phyethtool",
               "vxlan", "vxlanswfwd", "bfd", "ospf", "isis", "pim", "igmp", "igmpsnooping", "arp", "dot1x", "portsec", "lldpd", "fhrp", "vrrp",
               "forwardingagent", "strataagent", "sandagent", "fap", "agent", "snmp", "accounting", "cli", "conlogger", "tunnel", "routing",
               "ipv6", "mrouting", "qos", "trafficpolicy", "evpn", "macsec", "ptp", "ntp", "eos", "systemd-agent", "kernelfib", "fwd"}
NET_MNEMONIC = re.compile(r"%([A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)?)-([0-7])-([A-Z0-9_]+)")
NET_IF = re.compile(r"\b((?:Ethernet|Eth|GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|HundredGigabitEthernet|"
                    r"FastEthernet|Port-Channel|port-channel|Management|mgmt|Vlan|Loopback|Tunnel|Gi|Te|Fo|Hu|Po|Et|Ma)\s?\d+(?:/\d+)*(?:\.\d+)?)\b")

HOST_MAP: list[tuple[re.Pattern, str]] = []          # syslog.host_map 로 주입(호스트/IP → 소스 강제 지정)


def configure_host_map(rules: list[dict] | None) -> None:
    """config syslog.host_map: [{match: "^sup-cp-|10\\.10\\.50\\.", source: vks-supervisor}, ...]"""
    HOST_MAP.clear()
    for r in rules or []:
        try:
            HOST_MAP.append((re.compile(str(r["match"]), re.I), str(r["source"])))
        except (KeyError, re.error):
            continue


def classify(app: str, host: str, msg: str, sd: dict | None = None, peer: str = "") -> str:
    for rx, src in HOST_MAP:
        if rx.search(host or "") or (peer and rx.search(peer)):
            return src
    from .network import NET_PEERS, short as _short       # 등록된 Arista·Cisco 커넥터 장비에서 온 로그
    for k in (peer, (host or "").lower(), _short(host or "")):
        if k and k in NET_PEERS:
            return NET_PEERS[k]
    a = (app or "").lower().strip()
    sd = sd or {}
    comp = str(sd.get("comp", "")).lower()           # NSX: [nsx@6876 comp="nsx-edge" subcomp="datapathd"]
    if comp:
        if comp.startswith("nsx-edge") or comp == "nsx-edge":
            return "nsx-edge"
        if comp.startswith("nsx"):
            return "nsx"
    k = str(sd.get("kind", "")).lower()                # rsyslog 에이전트 표식 [aiops@32473 kind="vm|baremetal" role="db"]
    if k in ("vm", "guest"):
        return "vm"
    if k in ("baremetal", "physical", "server"):
        return "baremetal"
    if a == "vmx" or a.startswith("vmx-"):            # VM 하이퍼바이저 로그(ESXi 경유, vmx.log.syslogID=vmx-<VM>)
        return "vm"
    h = (host or "").lower()
    if a in SUPERVISOR_APPS or a.startswith(("wcp", "vmware-system-", "capw", "capv-", "vmop")):
        return "vks-supervisor"
    if a in ESXI_APPS or a.startswith("vmk") or a.startswith("vsan") and "health" not in a:
        return "esxi"
    if a in VC_APPS or a.startswith(("vpxd", "vmware-vpx", "vmware-sts")):
        return "vcenter"
    if a in NSX_EDGE_APPS or a.startswith("nsx-edge") or ("edge" in h and (a.startswith("nsx") or a in ("frr", "bgpd", "datapathd"))):
        return "nsx-edge"
    if a in NSX_MGR_APPS or a.startswith("nsx") or a == "nsx":
        return "nsx"
    if a.startswith(("avi", "se_", "se-")) or a in ("se_agent", "se_dp", "se_log_agent", "avi-controller") or h.startswith("avi") \
            or msg.startswith(("Avi ", "Avi-", "[Avi")):
        return "avi"
    if a in SRM_APPS or a.startswith(("srm", "dr-", "hbr", "vrms")):
        return "srm"
    if a in VCFOPS_APPS or a.startswith(("vcops", "vrops", "vcf-ops", "vcfops")):
        return "vcfops"
    if a.startswith("sddc") or a in ("lcm", "domainmanager", "operationsmanager", "commonsvcs", "sddc-manager-ui-app"):
        return "sddc"
    if NET_MNEMONIC.search(msg or ""):                # %LINK-3-UPDOWN · %ETHPORT-5-IF_DOWN… — 네트워크 장비(Arista 에이전트 이름이면 arista)
        return "arista" if a in ARISTA_APPS or a.startswith(("strata", "sand", "eos")) else "cisco"
    if a in K8S_APPS or a.startswith(("kube-", "antrea", "calico", "csi-", "vsphere-csi")) \
            or sd.get("namespace_name") or sd.get("pod_name"):  # Fluent Bit 쿠버네티스 메타데이터
        ns = str(sd.get("namespace_name", ""))
        return "vks-supervisor" if SUP_CP_HOST.match(host or "") or ns.startswith("vmware-system-") else "vks"
    return "syslog"


def _sd_params(sd: str) -> dict:
    if not sd or sd == "-":
        return {}
    return {k: v.replace('\\"', '"') for k, v in SD_PARAM.findall(sd)}


def parse(line: str, peer: str) -> LogEvent:
    line = line.rstrip("\r\n\x00")
    if is_fortigate(line):                        # FortiGate key=value 형식(RFC3164 헤더 없음) — 전용 파서
        return fg_parse(line, peer)
    sd: dict = {}
    m = RFC5424.match(line)
    if m:
        pri, ts_s, host, app, procid, msgid, sd_raw, msg = m.groups()
        sd = _sd_params(sd_raw)
        try:
            ts = datetime.fromisoformat(ts_s.replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts = time.time()
    else:
        msgid = ""
        m = RFC3164.match(line)
        if m:
            pri, _bsd, iso, host, app, procid, msg = m.groups()
            ts = time.time()
            if iso:
                try:
                    ts = datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    pass
        else:
            pri, host, app, procid, msg, ts = None, peer, "", "", line, time.time()
            mp = re.match(r"^<(\d{1,3})>(.*)$", line, re.S)        # NX-OS·IOS: '<189>: 2026 Oct 15 …: %ETHPORT-5-…' / '<189>123: *Oct 15 …: %LINK-3-…'
            if mp:
                pri, rest = mp.group(1), mp.group(2)
                mm = NET_MNEMONIC.search(rest)
                msg = rest[mm.start():] if mm else rest.lstrip(": ")
                hm = re.match(r"^\d*:?\s*([A-Za-z][\w.-]*):\s", rest)       # 'logging origin-id hostname' 이 붙인 장비 이름
                if hm and not re.match(r"^(\*?[A-Z][a-z]{2}|\d{4})$", hm.group(1)):
                    host = hm.group(1)
    msg = re.sub(r"^(?:-\s+)+", "", msg or "")   # RFC5424 nil 필드 잔여 제거
    msg = msg.lstrip("\ufeff")                    # RFC5424 BOM
    sev = norm_severity(str(int(pri) & 7)) if pri else sev_from_text(msg)
    mnet = NET_MNEMONIC.search(msg or "")
    if mnet:                                      # Cisco·Arista 는 니모닉의 심각도(0~7)가 실제 등급(PRI 는 시설 기본값인 경우가 많음)
        sev = norm_severity(mnet.group(2))
        if re.search(r"(changed state to|is now|is|went)\s+up\b|new state Established|to (FULL|Established)", msg or "", re.I):
            sev = "info"                          # %LINK-3-UPDOWN … to up 은 복구(심각도 3 이지만 정상화)
        elif sev in ("info", "debug") and re.search(r"changed state to down|\bis down\b|went down|old state Established|from FULL to|err-?disabled", msg or "", re.I):
            sev = "warning"                       # %LINEPROTO-5-UPDOWN … down · %BGP-5-ADJCHANGE … Established→Idle 은 알림 등급 5 지만 장애 신호
    if sd.get("level"):                           # NSX 등: SD 의 level 우선
        sev = norm_severity(sd["level"], sev)
    if sev == "info":   # ESXi 등은 대부분 info 레벨로 전송 → 본문 키워드로 보정
        s2 = sev_from_text(msg)
        if s2 != "info":
            sev = s2
    host = host if host and host != "-" else peer
    app = app if app and app != "-" else ""
    now = time.time()
    skew = ts - now
    if skew > 300:                                # 송신 장비 시계가 앞서면(NTP 불일치) 수신 시각으로 보정 — 이력 조회에서 누락 방지
        ts = now
    entity = sd.get("subcomp") or app
    attrs = {"peer": peer, "app": app, "procid": procid if procid and procid != "-" else ""}
    if mnet:
        attrs["mnemonic"] = f"{mnet.group(1)}-{mnet.group(2)}-{mnet.group(3)}"
        mi = NET_IF.search(msg)
        if mi:
            attrs["interface"] = mi.group(1)
            entity = f"{host}:{mi.group(1)}"
    if msgid and msgid != "-":
        attrs["msgid"] = msgid
    if skew > 300:
        attrs["clock_skew_sec"] = int(skew)
    for k in ("comp", "subcomp", "s2comp", "sub", "opID", "errorCode", "eventId", "username", "audit", "pod_name",
              "namespace_name", "container_name", "role"):
        if k in sd:
            attrs[k] = sd[k]
    if sd.get("os"):
        attrs["aiops_os"] = sd["os"]
    if sd.get("agent"):
        attrs["aiops_agent"] = sd["agent"]
    if sd.get("distro"):
        attrs["aiops_distro"] = sd["distro"]
    src = classify(app, host, msg, sd, peer)
    if src == "vm" and app.lower().startswith("vmx-"):   # vmx 로그: 호스트 = VM 이름, 실제 송신 ESXi 는 attrs.esxi
        attrs["esxi"] = host
        host, entity = app[4:], "vmx"
    return LogEvent(source=src, connector="syslog", message=msg.strip(), severity=sev,
                    host=host, entity=entity, ts=ts, kind="log", attrs=attrs)


class SyslogReceiver(Connector):
    type = "syslog"
    source = "syslog"

    def __init__(self, cfg, emit):
        super().__init__({"name": "syslog", **cfg}, emit)
        self.bind = cfg.get("bind", "0.0.0.0")
        self.udp_port = int(cfg.get("udp_port", 514))
        self.tcp_port = int(cfg.get("tcp_port", 514))
        self.peers: dict[str, int] = {}
        tls = cfg.get("tls") or {}
        self.tls_port = int(tls.get("port", 6514))
        self.tls_cert, self.tls_key = tls.get("certfile", "certs/aiops.crt"), tls.get("keyfile", "certs/aiops.key")
        en = tls.get("enabled", "auto")
        from pathlib import Path as _P
        self.tls_on = (en is True or str(en).lower() == "true") or (str(en).lower() == "auto" and _P(self.tls_cert).exists() and _P(self.tls_key).exists())
        configure_host_map(cfg.get("host_map"))
        self._state["target"] = f"udp/{self.udp_port} tcp/{self.tcp_port}" + (f" tls/{self.tls_port}" if self.tls_on else "")
        self.q: asyncio.Queue[tuple[str, str]] = asyncio.Queue(maxsize=100000)
        owner = getattr(emit, "__self__", None)          # Engine.ingest 이면 동기 submit 사용(비차단·우선순위)
        self._submit = getattr(owner, "submit", None) if owner is not None else None
        self._owner = owner

    def _push(self, line: str, peer: str):
        self.peers[peer] = self.peers.get(peer, 0) + 1
        gate = getattr(self._owner, "gate", None)
        if gate is not None:                  # 2.22.1 수집 일시정지 — 파싱 전에 버림(CPU 절약)
            gate.tick(peer)
            if gate.paused and gate.drop_raw(peer):
                self._state["paused_dropped"] = self._state.get("paused_dropped", 0) + 1
                return
        sub = self._submit
        if sub is not None:                   # 엔진 우선순위 큐로 직행 — 적체가 FIFO 가 아닌 우선/일반 큐에 쌓이게
            if self._owner.saturated() and "devid=" not in line[:300] and not self._owner.shed_raw(line):   # FortiGate 는 집계로 흡수
                self._state["shed"] = self._state.get("shed", 0) + 1      # 과부하: 파싱 전 저우선 원문 폐기
                return
            try:
                ev = parse(line, peer)
            except Exception as e:  # noqa: BLE001
                self._state["last_error"] = str(e)[:200]
                return
            if not sub(ev):
                self._state["dropped"] = self._state.get("dropped", 0) + 1
            self._state["events_total"] += 1
            self._state["last_ok"] = time.time()
            return
        try:
            self.q.put_nowait((line, peer))
        except asyncio.QueueFull:
            self._state["dropped"] = self._state.get("dropped", 0) + 1   # 수신 버퍼 초과(처리 지연) — 운영 지표로 노출

    async def run(self):
        if not self.enabled:
            return
        loop = asyncio.get_running_loop()
        errors = []
        recv = self

        def on_batch(batch):
            """수신 스레드가 모은 데이터그램 묶음 — 이벤트 루프에서 1회 콜백으로 처리"""
            for data, ip in batch:
                for ln in data.decode("utf-8", "replace").splitlines():
                    if ln.strip():
                        recv._push(ln, ip)
            self._state["udp_batches"] = self._state.get("udp_batches", 0) + 1

        try:
            import socket as _s
            fam = _s.AF_INET6 if ":" in self.bind else _s.AF_INET
            sock = _s.socket(fam, _s.SOCK_DGRAM)
            import sys as _sys
            if _sys.platform == "win32":      # Windows: 다른 프로세스의 같은 포트 바인드(포트 가로채기) 차단
                sock.setsockopt(_s.SOL_SOCKET, getattr(_s, "SO_EXCLUSIVEADDRUSE", -5), 1)
            else:
                sock.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
            want = int(self.cfg.get("rcvbuf", 16 * 1024 * 1024))
            try:                      # 버스트 흡수 — OS 기본(Windows 64KB, Linux 208KB)보다 크게. Linux 는 rmem_max 상한
                sock.setsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF, want)
            except OSError:
                pass
            sock.bind((self.bind, self.udp_port))
            self._state["udp_rcvbuf"] = sock.getsockopt(_s.SOL_SOCKET, _s.SO_RCVBUF)
            # 전용 수신 스레드: 커널 버퍼를 이벤트 루프 부하와 무관하게 비운다(asyncio UDP 는 깨어날 때마다 1건만 읽음)
            import threading
            self._udp_stop = threading.Event()

            def reader():
                sock.settimeout(0.5)
                while not self._udp_stop.is_set():
                    try:
                        data, addr = sock.recvfrom(65535)
                    except (TimeoutError, _s.timeout):
                        continue
                    except OSError:
                        if self._udp_stop.is_set():
                            break
                        continue
                    batch = [(data, addr[0])]
                    sock.setblocking(False)
                    try:
                        while len(batch) < 1024:
                            data, addr = sock.recvfrom(65535)
                            batch.append((data, addr[0]))
                    except (BlockingIOError, InterruptedError):
                        pass
                    except OSError:
                        pass
                    sock.settimeout(0.5)
                    try:
                        loop.call_soon_threadsafe(on_batch, batch)
                    except RuntimeError:          # 루프 종료
                        break
                sock.close()
            threading.Thread(target=reader, name="syslog-udp", daemon=True).start()
        except OSError as e:
            errors.append(f"UDP {self.udp_port}: {e}")

        async def tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            """RFC6587 프레이밍 자동 판별: octet-counting("<길이> <메시지>", Fluent Bit·NSX TLS 등) / 줄바꿈 구분"""
            peer = (writer.get_extra_info("peername") or ["?"])[0]
            try:
                while True:
                    first = await reader.read(1)
                    if not first:
                        break
                    if first in b"\r\n":
                        continue
                    if first.isdigit():
                        head = first + await reader.readuntil(b" ")
                        try:
                            n = int(head.strip())
                        except ValueError:
                            n = -1
                        if 0 < n <= 1_048_576:
                            data = await reader.readexactly(n)
                            s = data.decode("utf-8", "replace")
                        else:                         # 숫자로 시작하는 비표준 줄
                            s = (head + await reader.readline()).decode("utf-8", "replace")
                    else:
                        s = (first + await reader.readline()).decode("utf-8", "replace")
                    s = s.rstrip("\r\n")              # octet-counting 은 여러 줄 메시지도 한 건으로 유지
                    if s.strip():
                        self._push(s, peer)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                pass
            except Exception:  # noqa: BLE001
                pass
            finally:
                writer.close()

        try:
            await asyncio.start_server(tcp_client, self.bind, self.tcp_port)
        except OSError as e:
            errors.append(f"TCP {self.tcp_port}: {e}")
        if self.tls_on:                  # RFC5425 syslog over TLS — NSX(TLS)·Supervisor Fluent Bit(Tls on)·ESXi(ssl://)
            try:
                import ssl as _ssl
                ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(self.tls_cert, self.tls_key, password=(self.cfg.get("tls") or {}).get("keyfile_password") or None)
                ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
                await asyncio.start_server(tcp_client, self.bind, self.tls_port, ssl=ctx)
            except Exception as e:  # noqa: BLE001
                errors.append(f"TLS {self.tls_port}: {type(e).__name__}: {e}")
        self._state.update(state="degraded" if errors else "ok", last_error="; ".join(errors), auth="n/a",
                           last_ok=time.time())
        try:
            await self._consume()
        finally:
            if getattr(self, "_udp_stop", None):
                self._udp_stop.set()

    async def _consume(self):
        n = 0
        while True:
            line, peer = await self.q.get()
            try:
                await self.emit(parse(line, peer))
                self._state["events_total"] += 1
                self._state["last_ok"] = time.time()
            except Exception as e:  # noqa: BLE001
                self._state["last_error"] = str(e)[:200]
            n += 1
            if n % 200 == 0:                  # 큐가 차 있으면 get() 이 양보하지 않으므로 명시적으로 양보(처리 워커 기아 방지)
                await asyncio.sleep(0)

    def state(self):
        self._state["checks"] = {f"송신자 {p}": f"ok {n}건" for p, n in sorted(self.peers.items(), key=lambda x: -x[1])[:20]}
        return self._state

    async def test(self):
        return {"ok": self._state["state"] == "ok", "checks": self.state()["checks"] or {"수신": "아직 수신된 로그 없음"},
                "error": self._state["last_error"]}
