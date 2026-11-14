"""vCenter Server / vSphere 커넥터

수집
- 이벤트: EventHistoryCollector — 최신순(latestPage → ResetCollector → ReadPreviousEvents)으로 읽어
  폭주 시에도 최근 이벤트를 놓치지 않음(오래된 1000건만 돌려주는 QueryEvents 회피). 상한 초과분은 '건너뜀' 이벤트로 보고
- 이벤트 심각도: 이벤트 클래스 사전(VMware-AIops ops/health.py, MIT) + EventEx severity + 알람 상태색
- 알람: rootFolder.triggeredAlarmState (상태 변화만 송출)
- ESXi 호스트 로그(선택): DiagnosticManager.BrowseDiagnosticLog 로 hostd·vmkernel·vpxa 를 '이전 줄 이후'만 증분 수집
  (회전·누락 감지, 읽기 실패도 이벤트로 보고 — VMware-AIops scanner/log_scanner.py 방식). Global.Diagnostics 권한 필요
- 어플라이언스 헬스: REST /api/appliance/health/*
분석 지원
- 토폴로지(호스트↔클러스터↔VM↔데이터스토어, 유지보수 모드) 5분 주기 갱신 → 상관분석·유지보수 억제
- 조사 번들(VM/호스트/데이터스토어): 상태 + 관련 객체 + 알람 + 이벤트 타임라인
조치(승인 게이트 경유): 알람 확인, 호스트 유지보수 진입/해제, VM 디스크 통합, 어플라이언스 서비스 재시작
"""
from __future__ import annotations

import asyncio
import ssl
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import sli as SLI
from .. import vcheck
from ..models import SEV_RANK
from ..models import LogEvent
from ..sanitize import clean
from .base import Connector
from .vmware_rest import sev_from_text
from ..vcheck import driver_version
from . import vmomi_compat

vmomi_compat.install()        # vCenter 9.x 의 SOAP 스키마 밖 형식 이름(예: ContentLibrary)으로 이벤트 수집이 멈추지 않게

try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim, vmodl
except ImportError:  # pragma: no cover
    SmartConnect = Disconnect = None


class VCenterBusy(RuntimeError):
    """pyVmomi 스텁 잠금을 정해진 시간 안에 얻지 못함 — 다른 수집·조회가 오래 걸리거나 vCenter 가 응답하지 않는 중"""


class StubLock:
    """pyVmomi 스텁 직렬화 잠금(재진입) + 대기 상한(2.30.0).
    응답 없는 vCenter 를 붙잡은 스레드 뒤로 화면 요청 스레드가 무한정 쌓이지 않게, 상한을 넘기면 VCenterBusy 로 끝낸다.
    대기 상한은 스레드별(set_wait — 백그라운드 수집은 길게)·호출별(hold) 지정. 기다리는 스레드가 있으면 놓을 때 잠깐 양보한다
    (묶음 단위로 잠그는 긴 수집이 곧바로 다시 잡아 이벤트 읽기를 굶기지 않게)."""

    def __init__(self, wait: float = 45.0, name: str = ""):
        self._l = threading.RLock()
        self._tl = threading.local()
        self._g = threading.Lock()
        self._waiters = 0
        self.wait, self.name = float(wait), name

    def set_wait(self, wait: float | None) -> None:
        self._tl.wait = wait

    def acquire(self, timeout: float | None = None) -> None:
        depth = getattr(self._tl, "depth", 0)
        if depth:
            self._l.acquire()
        else:
            wait = timeout if timeout is not None else (getattr(self._tl, "wait", None) or self.wait)
            with self._g:
                self._waiters += 1
            try:
                ok = self._l.acquire(timeout=wait) if wait > 0 else self._l.acquire()
            finally:
                with self._g:
                    self._waiters -= 1
            if not ok:
                raise VCenterBusy(f"vCenter {self.name} 응답 대기 {wait:g}초 초과 — 다른 수집·조회가 진행 중이거나 vCenter 가 응답하지 않습니다(잠시 후 다시 시도)")
        self._tl.depth = depth + 1

    def release(self) -> None:
        self._tl.depth = depth = getattr(self._tl, "depth", 1) - 1
        self._l.release()
        if depth == 0 and self._waiters:
            time.sleep(0.002)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def hold(self, timeout: float):
        """with lock.hold(초): — 이 호출만 다른 대기 상한"""
        return _Hold(self, timeout)


class _Hold:
    def __init__(self, lock: StubLock, timeout: float):
        self.lock, self.timeout = lock, timeout

    def __enter__(self):
        self.lock.acquire(self.timeout)
        return self.lock

    def __exit__(self, *exc) -> None:
        self.lock.release()

# 이벤트 클래스 → 심각도 (VMware-AIops ops/health.py 의 집합 + 운영 경험 보강)
CRITICAL_EVENTS = {
    # VMware-AIops ops/health.py
    "VmFailedToPowerOnEvent", "HostConnectionLostEvent", "HostShutdownEvent", "VmDiskFailedEvent",
    "DasHostFailedEvent", "DatastoreRemovedOnHostEvent",
    # 보강: HA·격리·자원 부족
    "DasHostIsolatedEvent", "DasClusterIsolatedEvent", "HostIsolationIpPingFailedEvent",
    "VmDasResetFailedEvent", "NotEnoughResourcesToStartVmEvent", "DasAgentUnavailableEvent",
}
WARNING_EVENTS = {
    # VMware-AIops ops/health.py
    "VmFailoverFailed", "DrsSoftRuleViolationEvent", "VmFailedToRebootGuestEvent",
    "DVPortgroupReconfiguredEvent", "VmGuestShutdownEvent", "HostIpChangedEvent", "BadUsernameSessionEvent",
    # 보강
    "VmFailedMigrateEvent", "MigrationErrorEvent", "VmMessageErrorEvent", "VmMessageWarningEvent", "HostCnxFailedEvent",
    "VmDasBeingResetEvent", "HostEnteringMaintenanceModeEvent", "HostExitMaintenanceModeEvent",
}
_ERR_WORDS = ("Failed", "Lost", "Disconnected", "NotResponding", "Error", "Crash", "Isolat", "Unreachable",
              "Fault", "Timeout", "Insufficient", "Degraded")
_WARN_WORDS = ("Warning", "Removed", "Reconnect", "Disabled", "Conflict", "Rejected")
_PAST_THE_END = 999999999


def _safe_name(o) -> str:
    try:
        return str(getattr(o, "name", "") or "")
    except Exception:  # noqa: BLE001  — 스키마 밖 형식(스텁)은 속성 조회 불가
        return str(getattr(o, "_moId", "") or "")


def _dig(o, path: str, d=None):
    for k in path.split("."):
        if o is None:
            return d
        o = getattr(o, k, None)
    return d if o is None else o


def parse_hints(hints) -> dict[str, dict]:
    """HostNetworkSystem.QueryNetworkHint() → {vmnic: {switch, port, mgmt, proto, desc}}
    PhysicalNicHintInfo.connectedSwitchPort(CDP: devId·portId·address·hardwarePlatform·systemName) /
    lldpInfo(LinkLayerDiscoveryProtocolInfo: chassisId·portId·parameter[KeyAnyValue] — 'System Name'·'Port Description'·'Management Address')"""
    out: dict[str, dict] = {}
    for h in hints or []:
        dev = str(getattr(h, "device", "") or "")
        if not dev:
            continue
        ll = getattr(h, "lldpInfo", None)
        cdp = getattr(h, "connectedSwitchPort", None)
        if ll is not None and (getattr(ll, "portId", None) or getattr(ll, "chassisId", None)):
            prm = {str(getattr(x, "key", "")).lower(): getattr(x, "value", "") for x in (getattr(ll, "parameter", None) or [])}
            out[dev] = {"switch": str(prm.get("system name") or getattr(ll, "chassisId", "") or ""), "port": str(getattr(ll, "portId", "") or ""),
                        "port_desc": str(prm.get("port description") or ""), "mgmt": str(prm.get("management address") or ""),
                        "desc": str(prm.get("system description") or "")[:160], "proto": "lldp", "ttl": getattr(ll, "timeToLive", None)}
        elif cdp is not None and (getattr(cdp, "devId", None) or getattr(cdp, "portId", None)):
            out[dev] = {"switch": str(getattr(cdp, "devId", "") or getattr(cdp, "systemName", "") or ""), "port": str(getattr(cdp, "portId", "") or ""),
                        "mgmt": str(getattr(cdp, "address", "") or getattr(cdp, "mgmtAddr", "") or ""), "desc": str(getattr(cdp, "hardwarePlatform", "") or "")[:160],
                        "proto": "cdp"}
    return out


EVENT_CAP = 5000
LIFE_TYPES = {"created", "cloned", "deployed", "registered", "removed", "renamed", "create_failed"}
# 2.5.0 VM 액티비티 확장 — 전원·구성 변경·스냅샷(요청 시점: TaskEvent 는 작업 '생성'을 기록하며 상태는 항상 queued)
POWER_EVENTS = {"VmPoweredOnEvent": "power_on", "VmPoweredOffEvent": "power_off", "VmSuspendedEvent": "suspended", "VmResettingEvent": "reset",
                "VmGuestShutdownEvent": "guest_shutdown", "VmGuestRebootEvent": "guest_reboot"}
SNAP_TASKS = {"VirtualMachine.createSnapshot": "snapshot_create", "VirtualMachineSnapshot.remove": "snapshot_remove",
              "VirtualMachine.removeAllSnapshots": "snapshot_remove_all", "VirtualMachineSnapshot.revert": "snapshot_revert",
              "VirtualMachine.revertToCurrentSnapshot": "snapshot_revert"}
ACT_TYPES = LIFE_TYPES | set(POWER_EVENTS.values()) | set(SNAP_TASKS.values()) | {"reconfigured"}
_DEV_KO = {"VirtualDisk": "디스크", "VirtualCdrom": "CD/DVD", "VirtualFloppy": "플로피", "VirtualUSB": "USB", "VirtualSerialPort": "시리얼",
           "VirtualPCIPassthrough": "PCI 패스스루", "VirtualNVMEController": "NVMe 컨트롤러", "VirtualMachineVideoCard": "비디오",
           "ParaVirtualSCSIController": "PVSCSI 컨트롤러", "VirtualLsiLogicSASController": "SAS 컨트롤러", "VirtualAHCIController": "SATA 컨트롤러"}


def _gb(mb: int) -> str:
    return f"{mb // 1024}" if mb % 1024 == 0 else f"{round(mb / 1024, 1):g}"


def reconfig_detail(e, prev: dict | None = None) -> str:
    """VmReconfiguredEvent → 사람이 읽는 변경 요약(vCPU·메모리 이전 → 이후 · 장치 추가/제거/변경 + configChanges(6.5+) 보조).
    prev = 직전 인벤토리의 VM(vcpu·mem_mb) — 값이 다를 때만 '이전 → ' 를 붙이고, 비교 뒤 새 값으로 갱신"""
    out: list[str] = []
    spec = getattr(e, "configSpec", None)
    if spec is not None:
        if getattr(spec, "numCPUs", None):
            a = (prev or {}).get("vcpu")
            out.append(f"vCPU {a} → {spec.numCPUs}" if a and a != spec.numCPUs else f"vCPU {spec.numCPUs}")
            if prev is not None:
                prev["vcpu"] = int(spec.numCPUs)
        if getattr(spec, "memoryMB", None):
            mb = int(spec.memoryMB)
            a = (prev or {}).get("mem_mb")
            out.append(f"메모리 {_gb(a)} → {_gb(mb)} GB" if a and a != mb else f"메모리 {_gb(mb)} GB")
            if prev is not None:
                prev["mem_mb"] = mb
        for dc in getattr(spec, "deviceChange", None) or []:
            dev = getattr(dc, "device", None)
            if dev is None:
                continue
            tn = type(dev).__name__.split(".")[-1]
            kind = "NIC" if "Ethernet" in tn or tn.startswith("VirtualVmxnet") or tn in ("VirtualE1000", "VirtualE1000e", "VirtualPCNet32", "VirtualSriovEthernetCard") \
                else _DEV_KO.get(tn, tn.replace("Virtual", ""))
            op = {"add": "추가", "remove": "제거", "edit": "변경"}.get(str(getattr(dc, "operation", "") or ""), "변경")
            extra = ""
            if tn == "VirtualDisk" and getattr(dev, "capacityInKB", None):
                extra = f" {round(dev.capacityInKB / 1048576, 1):g} GB"
            out.append(f"{kind} {op}{extra}")
        if getattr(spec, "annotation", None) is not None:
            out.append("메모 변경")
    ch = getattr(e, "configChanges", None)
    if ch is not None and not out:
        for k, lab in (("modified", "변경"), ("added", "추가"), ("deleted", "삭제")):
            txt = str(getattr(ch, k, "") or "").strip()
            if txt:
                lines = [ln.strip() for ln in txt.splitlines() if ln.strip()][:3]
                out.append(f"{lab}: " + " · ".join(lines))
    return ", ".join(out)[:300]


class VCenterConnector(Connector):
    type = "vcenter"
    source = "vcenter"
    default_interval = 15

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.si = None
        self.rest_token = ""
        # pyVmomi 스텁 직렬화 — 화면 요청은 lock_timeout(기본 45초)까지만 기다림
        self._lock = StubLock(float(cfg.get("lock_timeout", 45)), self.name)
        self.soap_timeout = float(cfg.get("soap_timeout", 120))         # SOAP 소켓 상한(연결·응답) — 응답 없는 vCenter 가 스레드를 영구 점유하지 않게
        self.heavy_timeout = float(cfg.get("heavy_timeout", 900))       # 무거운 수집 1회 상한
        self.heavy_retry = float(cfg.get("heavy_retry", 60))            # 실패 후 재시도 간격(주기 전체를 기다리지 않음)
        self.event_lock_wait = float(cfg.get("event_lock_wait", min(20.0, self.poll_timeout / 3)))
        self._thr_busy: dict[str, int] = {}            # 스레드가 아직 도는 수집(시간 초과 후에도 겹쳐 시작하지 않게)
        self._moved: set[str] = set()                  # 직전 토폴로지 갱신 이후 이벤트로 확인한 이동 VM(누적)
        self._state["collectors"] = self._bg_stat      # 수집 종류별 최근 성공·실패(연결 상태 화면)
        self._state["auth"] = "pending"
        self.host_logs: list[str] = [k for k in (cfg.get("host_logs") or []) if k]
        self.host_log_lines = int(cfg.get("host_log_lines", 500))
        self.host_log_interval = float(cfg.get("host_log_interval", 60))
        self._log_pos: dict[tuple[str, str], int] = {}
        self._log_unreadable: dict[tuple[str, str], str] = {}
        self._last_hostlog = 0.0
        self.topology: dict[str, Any] = {"hosts": {}, "vms": {}, "datastores": {}, "clusters": {}, "updated": 0}
        self._last_topo = 0.0
        self.environment = cfg.get("environment", "")
        # 성능 SLI(Isvara 4대 경합 지표) — 실시간 성능 카운터(20초) 최근 5분, VM·클러스터 점수, 페일오버 여유
        sc = cfg.get("sli") if isinstance(cfg.get("sli"), dict) else {}
        self.sli_cfg = {"enabled": bool(sc.get("enabled", True)), "interval": float(sc.get("interval", 300)),
                        "samples": int(sc.get("samples", 15)), "percentile": float(sc.get("percentile", 99)),
                        "thresholds": {**SLI.DEFAULT_THRESHOLDS, **(sc.get("thresholds") or {})},
                        "drop_budget": float(sc.get("drop_budget", 100)), "max_vms": int(sc.get("max_vms", 5000)),
                        "batch": int(sc.get("batch", 100)), "failover_hosts": int(sc.get("failover_hosts", 1)),
                        "alert_band": str(sc.get("alert_band", "orange")), "max_events": int(sc.get("max_events", 30))}
        self.sli: dict[str, Any] = {"updated": 0, "vms": {}, "clusters": {}, "error": ""}
        self._last_sli = 0.0
        self._sli_band: dict[str, str] = {}
        self.vks: dict[str, Any] = {"supervisors": [], "updated": 0, "error": ""}
        # 인프라 상세 점검(Compute·Storage·Network·Hardware) — 기본 30분, 드라이버 VIB 조회는 6시간
        hc = cfg.get("health") if isinstance(cfg.get("health"), dict) else {}
        self.health_cfg = {"enabled": bool(hc.get("enabled", True)), "interval": float(hc.get("interval", 1800)),
                           "vib_interval": float(hc.get("vib_interval", 21600)), "max_vib_hosts": int(hc.get("max_vib_hosts", 300)),
                           "max_events": int(hc.get("max_events", 30)), "thresholds": hc.get("thresholds") or {}}
        self.health: dict[str, Any] = {"updated": 0, "error": "", "findings": [], "summary": {}, "hw": []}
        self.health_snap: dict[str, Any] = {}
        self._last_health = 0.0
        self._vibs: dict[str, dict[str, str]] = {}
        self._last_vib = 0.0
        self.health_cfg["bp_vm_interval"] = float(hc.get("bp_vm_interval", 21600))   # 2.28.0 VM 장치·Tools(권장 구성 판독) 6시간
        self._bp_vms: dict[str, Any] = {}
        self._last_bpvm = 0.0
        self.protection: dict[str, Any] | None = None     # 2.29.0 vCenter 파일 기반 백업(VAMI) 상태
        self._last_bkp = 0.0
        self.rest_token = ""
        # 2.3 포트맵 — ESXi 쪽 LLDP/CDP(HostNetworkSystem.QueryNetworkHint) 15분 간격
        self.hint_interval = float(cfg.get("net_hint_interval", 900))
        self.hint_max_hosts = int(cfg.get("net_hint_max_hosts", 300))
        self._net_hints: dict[str, dict[str, dict]] = {}
        self._last_hint = 0.0
        self._health_seen: dict[str, str] = {}
        self.bmc_provider = None                       # 엔진이 주입: () -> {esxi 호스트: {bmc_fw, bios, firmware[], ...}}
        self.alarms: list[dict[str, Any]] = []         # 현재 발생 중인 알람(rootFolder.triggeredAlarmState)
        self._move_vms: set[str] = set()               # 이번 폴링에서 이벤트로 확인한 이동 VM(인벤토리 비교 중복 방지)
        self._life_vms: dict[str, float] = {}          # 2.4.2 이벤트로 확인한 생성·삭제·이름 변경 VM(최근 1시간, 인벤토리 비교 중복 방지)

    # ------------------------------------------------------------------ 연결
    def _connect(self):
        if SmartConnect is None:
            raise RuntimeError("pyvmomi 미설치")
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with self._lock:
            old = self.si
            self.si = SmartConnect(host=self.host.split(":")[0], user=self.cfg["username"], pwd=self.cfg["password"],
                                   port=int(self.cfg.get("port", self.host.split(":")[1] if ":" in self.host else 443)),
                                   sslContext=ctx, httpConnectionTimeout=int(self.soap_timeout) or None)
            if old is not None and old is not self.si and Disconnect is not None:
                try:                                   # 이전 세션 반납 — 재로그인마다 vCenter 세션이 쌓이지 않게
                    Disconnect(old)
                except Exception:  # noqa: BLE001
                    pass

    def _ensure(self):
        try:
            if self.si and self.si.content.sessionManager.currentSession:
                return
        except Exception:  # noqa: BLE001
            pass
        self._connect()

    def _ensure_locked(self) -> None:
        with self._lock:
            self._ensure()

    async def _tx(self, key: str, fn, *args):
        """무거운 수집용 스레드 실행(전용 풀) — 잠금 대기는 길게(heavy_timeout). 도는 동안 _thr_busy[key] 에 표시해
        시간 초과로 작업이 끝난 뒤에도 스레드가 남아 있으면 같은 수집을 겹쳐 시작하지 않는다(_heavy)."""
        def done() -> None:
            n = self._thr_busy.get(key, 1) - 1
            if n > 0:
                self._thr_busy[key] = n
            else:
                self._thr_busy.pop(key, None)

        def run():
            try:
                if hasattr(self._lock, "set_wait"):
                    self._lock.set_wait(self.heavy_timeout)
                return fn(*args)
            finally:
                if hasattr(self._lock, "set_wait"):
                    self._lock.set_wait(None)
                done()
        self._thr_busy[key] = self._thr_busy.get(key, 0) + 1
        cf = self._pool.submit(run)
        cf.add_done_callback(lambda f: done() if f.cancelled() else None)    # 풀 반납으로 시작도 못 한 경우만(도는 스레드는 스스로 해제)
        return await asyncio.wrap_future(cf)

    async def login(self) -> None:
        """SOAP(pyVmomi)은 필수, REST(/api/session)는 선택 — REST 실패 시 이벤트·토폴로지·조사는 계속 동작하고
        어플라이언스 헬스·서비스 조치만 비활성(상태 점검에 사유 표시)."""
        try:
            await self._t(self._ensure_locked)      # 살아 있는 세션은 재사용(폴링 시간 초과 뒤 재로그인이 세션을 늘리지 않게)
        except VCenterBusy:
            if self.si is None or not (self._bg_busy() or self._thr_busy):
                raise                               # 무거운 수집이 스텁을 쓰는 중이면 세션은 살아 있는 것 — 그대로 진행
        try:                                       # 버전(KB 적용 버전 판단·지식 검색 가중)
            ab = self.si.content.about
            self.about = {"product": str(getattr(ab, "name", "") or "vCenter"), "version": str(getattr(ab, "version", "") or ""),
                          "build": str(getattr(ab, "build", "") or "")}
        except Exception:  # noqa: BLE001
            self.about = {}
        if self.rest_token:                        # 이전 REST 세션 반납(실패해도 무시)
            try:
                await asyncio.wait_for(self.http.delete("/api/session"), 5)
            except Exception:  # noqa: BLE001
                pass
            self.http.headers.pop("vmware-api-session-id", None)
        try:
            r = await self.http.post("/api/session", auth=(self.cfg["username"], self.cfg["password"]))
            r.raise_for_status()
            self.rest_token = r.json()
            self.http.headers["vmware-api-session-id"] = self.rest_token
            self._state["checks"].pop("REST /api/session", None)
        except Exception as e:  # noqa: BLE001
            self.rest_token = ""
            self._state["checks"]["REST /api/session"] = f"비활성(어플라이언스 헬스 수집 제외): {type(e).__name__}"[:150]

    # ------------------------------------------------------------------ 공통: PropertyCollector
    def _collect(self, vimtype, props: list[str]) -> list[tuple[Any, dict]]:
        content = self.si.content
        view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
        try:
            PC = vmodl.query.PropertyCollector
            ts = PC.TraversalSpec(name="tv", path="view", skip=False, type=vim.view.ContainerView)
            fs = PC.FilterSpec(objectSet=[PC.ObjectSpec(obj=view, skip=True, selectSet=[ts])],
                               propSet=[PC.PropertySpec(type=vimtype, pathSet=props, all=False)])
            pc = content.propertyCollector
            res = pc.RetrievePropertiesEx([fs], PC.RetrieveOptions(maxObjects=1000))
            out = []
            while res:
                for o in res.objects:
                    out.append((o.obj, {p.name: p.val for p in (o.propSet or [])}))
                if not res.token:
                    break
                res = pc.ContinueRetrievePropertiesEx(res.token)
            return out
        finally:
            view.Destroy()

    # ------------------------------------------------------------------ 이벤트
    @staticmethod
    def _sev_of(e) -> tuple[str, str]:
        name = type(e).__name__.split(".")[-1]
        kind = "event"
        if isinstance(e, vim.event.AlarmStatusChangedEvent):
            to = str(getattr(e, "to", "")).lower()
            return {"red": "critical", "yellow": "warning", "green": "info"}.get(to, "info"), "alarm"
        if isinstance(e, (vim.event.EventEx, vim.event.ExtendedEvent)):
            sev = str(getattr(e, "severity", "") or "").lower()
            if sev in ("error", "warning", "info"):
                return sev, kind
        if isinstance(e, vim.event.TaskEvent):
            st = str(getattr(getattr(e, "info", None), "state", ""))
            return ("error" if st == "error" else "info"), "task"
        if name in CRITICAL_EVENTS:
            return "critical", kind
        if name in WARNING_EVENTS:
            return "warning", kind
        if any(w in name for w in _ERR_WORDS):
            return "error", kind
        if any(w in name for w in _WARN_WORDS):
            return "warning", kind
        return "info", kind

    @staticmethod
    def _ent_name(e) -> tuple[str, str]:
        ent = ""
        for attr in ("vm", "host", "computeResource", "datastore", "net", "dvs"):
            o = getattr(e, attr, None)
            if o is not None and getattr(o, "name", None):
                ent = o.name
                break
        if not ent and getattr(e, "objectName", None):          # EventEx(콘텐츠 라이브러리·vSAN·확장 이벤트 등)
            ent = str(e.objectName)
        host = e.host.name if getattr(e, "host", None) else ""
        return ent, host

    def _read_events_newest_first(self, spec, cap: int = EVENT_CAP) -> tuple[list, bool]:
        em = self.si.content.eventManager
        coll = em.CreateCollectorForEvents(filter=spec)
        out: list = []
        truncated = False
        self._state.setdefault("checks", {}).pop("이벤트 해석", None)        # 이번 읽기 결과로 다시 판정(지난 경고가 남지 않게)
        try:
            coll.SetCollectorPageSize(1000)
            try:
                out.extend(coll.latestPage or [])
            except (TypeError, KeyError, AttributeError) as e:   # 해석 못 하는 이벤트가 섞인 페이지 → 작은 단위로 다시 읽어 그것만 건너뜀
                out.extend(self._read_tolerant(coll, e))
            coll.ResetCollector()                         # 최신 페이지 직전으로 이동 → 과거 방향으로 읽기
            while len(out) < cap:
                try:
                    page = coll.ReadPreviousEvents(1000)
                except (TypeError, KeyError, AttributeError) as e:
                    self._state["checks"]["이벤트 해석"] = f"warn: 일부 이벤트 형식 해석 실패({type(e).__name__}: {e}) — 해당 페이지 이후 건너뜀"[:200]
                    break
                if not page:
                    break
                out.extend(page)
            else:
                truncated = True
        finally:
            try:
                coll.DestroyCollector()
            except Exception:  # noqa: BLE001
                pass
        if "이벤트 해석" not in self._state["checks"]:
            stubs = sorted(vmomi_compat.STUBS)
            self._state["checks"]["이벤트 해석"] = (f"ok — SOAP 스키마 밖 형식 보정: {', '.join(stubs)[:120]}" if stubs else "ok")
        seen, uniq = set(), []
        for e in out:
            if e.key not in seen:
                seen.add(e.key)
                uniq.append(e)
        return uniq, truncated

    def _read_tolerant(self, coll, err) -> list:
        """최신 페이지 해석 실패 시: 페이지 크기 10 으로 과거 방향 읽기, 실패한 묶음만 건너뜀"""
        self._state["checks"]["이벤트 해석"] = f"warn: 일부 이벤트 형식 해석 실패({type(err).__name__}: {err}) — 해당 묶음만 건너뜀"[:200]
        out: list = []
        try:
            coll.SetCollectorPageSize(10)
            coll.ResetCollector()
            for _ in range(100):
                try:
                    page = coll.ReadPreviousEvents(10)
                except (TypeError, KeyError, AttributeError):
                    continue
                if not page:
                    break
                out.extend(page)
            coll.SetCollectorPageSize(1000)
        except Exception:  # noqa: BLE001
            pass
        return out

    MOVE_SEV = {"ha_restart": "error", "ha_failed": "critical", "ha_reset": "warning", "ha_reset_failed": "error", "host_failed": "critical",
                "host_isolated": "critical", "move_failed": "warning", "vmotion": "info", "drs": "info", "svmotion": "info", "relocate": "info",
                "detected": "info", "created": "info", "cloned": "info", "deployed": "info", "registered": "info", "removed": "info", "renamed": "info",
                "create_failed": "warning", "detected_new": "info", "detected_gone": "info", "reconfigured": "info",
                "snapshot_create": "info", "snapshot_remove": "info", "snapshot_remove_all": "info", "snapshot_revert": "info"}

    def _move_of(self, e) -> dict[str, Any] | None:
        """VM 이동·HA 이벤트 → 구조화(유형·VM·출발/도착 호스트·데이터스토어·클러스터)"""
        name = type(e).__name__.split(".")[-1]
        tid = str(getattr(e, "eventTypeId", "") or "")
        g = lambda o, a: getattr(getattr(o, a, None), "name", "") or ""   # noqa: E731
        vm, to, cl = g(e, "vm"), g(e, "host"), g(e, "computeResource")
        src = from_ds = to_ds = source = detail = ""
        t = ""
        if isinstance(e, vim.event.VmMigratedEvent):              # vMotion 완료(DrsVmMigratedEvent 포함)
            t = "drs" if isinstance(e, vim.event.DrsVmMigratedEvent) else "vmotion"
            src = g(e, "sourceHost")
            from_ds, to_ds = g(e, "sourceDatastore"), g(e, "ds")
            if src and src == to and from_ds and from_ds != to_ds:
                t = "svmotion"
        elif isinstance(e, vim.event.VmRelocatedEvent):           # 콜드 마이그레이션·Storage vMotion
            src, from_ds, to_ds = g(e, "sourceHost"), g(e, "sourceDatastore"), g(e, "ds")
            t = "svmotion" if src and src == to else "relocate"
        elif name == "VmRestartedOnAlternateHostEvent" or tid in ("com.vmware.vc.ha.VmRestartedByHAEvent",):
            t, src = "ha_restart", g(e, "sourceHost")
        elif name == "VmFailoverFailed" or tid.startswith("com.vmware.vc.ha.VmFailover") or tid == "com.vmware.vc.HA.VmFailoverFailed":
            t = "ha_failed"
        elif name in ("VmDasBeingResetEvent", "VmDasBeingResetWithScreenshotEvent"):
            t = "ha_reset"
        elif name == "VmDasResetFailedEvent":
            t = "ha_reset_failed"
        elif name == "DasHostFailedEvent":
            t, src, vm = "host_failed", g(e, "failedHost"), ""
        elif name == "DasHostIsolatedEvent":
            t, src, vm = "host_isolated", g(e, "isolatedHost"), ""
        elif name in ("VmFailedMigrateEvent", "MigrationHostErrorEvent", "MigrationResourceErrorEvent"):
            t, src, to = "move_failed", to, g(e, "destHost") or to
        # ---- 2.4.2 VM 생성·삭제(라이프사이클)
        elif name == "VmCreatedEvent":
            t, to_ds = "created", g(e, "ds")
        elif name == "VmClonedEvent":
            t, to_ds, source = "cloned", g(e, "ds"), g(e, "sourceVm")
        elif name == "VmDeployedEvent":
            t, to_ds, source = "deployed", g(e, "ds"), g(e, "srcTemplate")
        elif name == "VmRegisteredEvent":
            t, to_ds = "registered", g(e, "ds")
        elif name == "VmRemovedEvent":
            t, src, to, from_ds = "removed", to, "", g(e, "ds")
        elif name == "VmRenamedEvent":
            t, source = "renamed", str(getattr(e, "oldName", "") or "")
            vm = str(getattr(e, "newName", "") or vm)
        elif name in POWER_EVENTS and self.cfg.get("activity_power", True):
            t = POWER_EVENTS[name]
        elif name == "VmReconfiguredEvent":
            t, detail = "reconfigured", reconfig_detail(e, (self.topology.get("vms") or {}).get(vm))
        elif name == "TaskEvent" and str(getattr(getattr(e, "info", None), "descriptionId", "") or "") in SNAP_TASKS:
            t = SNAP_TASKS[e.info.descriptionId]
            vm = vm or str(getattr(e.info, "entityName", "") or "")
        elif name in ("VmCloneFailedEvent", "VmDeployFailedEvent"):
            t, source = "create_failed", g(e, "vm") if name == "VmCloneFailedEvent" else ""
            vm = str(getattr(e, "destName", "") or "") or vm
            to = g(e, "destHost") or to
            to_ds = g(e, "destDatastore") if name == "VmDeployFailedEvent" else to_ds
        if not t:
            return None
        if t in ("ha_restart", "ha_failed", "ha_reset") and not src and vm:   # 출발 호스트: 직전 인벤토리 위치
            src = (self.topology.get("vms", {}).get(vm) or {}).get("host", "")
        if not cl:
            cl = (self.topology.get("hosts", {}).get(to or src) or {}).get("cluster", "")
        return {"type": t, "vm": vm, "from_host": src, "to_host": to, "from_ds": from_ds, "to_ds": to_ds, "cluster": cl,
                "user": str(getattr(e, "userName", "") or ""), "vcenter": self.name, "source": source, "detail": detail}

    def _collect_sessions(self, events) -> None:
        """로그인 이벤트(UserLoginSessionEvent: ipAddress·userAgent)를 사용자별로 쌓고, 지금 열린 세션 목록을 읽음.
        sessionList 는 다른 사용자 세션을 보려면 Sessions.TerminateSession 권한이 필요 — 없으면 로그인 이벤트만 씀"""
        from ..vmmoves import norm_user
        lg = getattr(self, "_logins", None)
        if lg is None:
            lg = self._logins = {}
        for e in events:
            if type(e).__name__.split(".")[-1] == "UserLoginSessionEvent":
                try:
                    lst = lg.setdefault(norm_user(getattr(e, "userName", "")), [])
                    lst.append((e.createdTime.timestamp(), str(getattr(e, "ipAddress", "") or ""), str(getattr(e, "userAgent", "") or "")))
                    if len(lst) > 50:
                        del lst[:-50]
                except Exception:  # noqa: BLE001
                    continue
        cut = time.time() - 2 * 86400
        for k in list(lg):
            lg[k] = [x for x in lg[k] if x[0] >= cut]
            if not lg[k]:
                del lg[k]
        if len(lg) > 2000:
            for k in sorted(lg, key=lambda k: lg[k][-1][0])[:len(lg) - 2000]:
                del lg[k]
        live = []
        try:
            for x in self.si.content.sessionManager.sessionList or []:
                live.append({"user": str(x.userName or ""), "ip": str(getattr(x, "ipAddress", "") or ""), "agent": str(getattr(x, "userAgent", "") or ""),
                             "login": x.loginTime.timestamp() if x.loginTime else 0, "last": x.lastActiveTime.timestamp() if x.lastActiveTime else 0})
            self._state["checks"]["세션 목록"] = f"ok — 열린 세션 {len(live)}개(실행 주체 IP 보강)"
        except Exception as ex:  # noqa: BLE001
            self._state["checks"]["세션 목록"] = f"warn: 세션 목록 읽기 불가({type(ex).__name__}) — 로그인 이벤트로만 IP 를 찾음"
        self._live_sessions = live

    def _who(self, user: str, ts: float, host: str) -> dict[str, str]:
        from ..vmmoves import who_of
        h = ((getattr(self, "health_snap", None) or {}).get("hosts") or {}).get(host) or {}
        return who_of(user, ts, getattr(self, "_logins", {}) or {}, getattr(self, "_live_sessions", []) or [], host, str(h.get("mgmt_ip") or ""))

    def _read_events(self) -> list[dict[str, Any]]:
        with (self._lock.hold(self.event_lock_wait) if hasattr(self._lock, "hold") else self._lock):
            self._ensure()
            spec = vim.event.EventFilterSpec()
            spec.time = vim.event.EventFilterSpec.ByTime(
                beginTime=datetime.fromtimestamp(self.since, tz=timezone.utc) - timedelta(seconds=5))
            events, truncated = self._read_events_newest_first(spec)
            out: list[dict[str, Any]] = []
            self._move_vms = set()
            self._collect_sessions(events)                           # 2.45.1 실행 주체 IP — 로그인 이벤트·열린 세션
            for e in events:
                sev, kind = self._sev_of(e)
                ent, host = self._ent_name(e)
                row = {"key": e.key, "ts": e.createdTime.timestamp(), "sev": sev, "kind": kind,
                       "msg": e.fullFormattedMessage or type(e).__name__, "entity": ent, "host": host,
                       "type": getattr(e, "eventTypeId", None) or type(e).__name__.split(".")[-1],
                       "user": getattr(e, "userName", "")}
                try:
                    mv = self._move_of(e)
                except Exception:  # noqa: BLE001
                    mv = None
                if mv:
                    if mv.get("user"):
                        try:
                            mv.update(self._who(mv["user"], row["ts"], mv.get("to_host") or mv.get("from_host") or host))
                        except Exception:  # noqa: BLE001
                            pass
                    row["move"] = mv
                    ms = self.MOVE_SEV.get(mv["type"], sev)
                    row["sev"] = ms if mv["type"] in ("vmotion", "drs", "svmotion", "relocate") or SEV_RANK[ms] > SEV_RANK.get(sev, 1) else sev
                    if mv["vm"] and (mv["type"] in LIFE_TYPES or (mv["type"] not in ACT_TYPES and (mv["from_host"] != mv["to_host"] or mv["type"] == "svmotion"))):
                        self._move_vms.add(mv["vm"])
                        self._moved.add(mv["vm"])
                    if mv["type"] == "renamed" and mv.get("source"):
                        self._move_vms.add(mv["source"])
                        self._moved.add(mv["source"])
                    if mv["type"] in LIFE_TYPES:
                        self._life_vms[mv["vm"]] = time.time()
                out.append(row)
            if truncated:
                out.append({"key": f"trunc:{int(time.time())}", "ts": time.time(), "sev": "warning", "kind": "health",
                            "msg": f"vCenter 이벤트 폭주 — 폴링 1회 상한 {EVENT_CAP}건 초과분(가장 오래된 쪽)은 건너뜀",
                            "entity": "vcenter:events", "host": "", "type": "AIOpsTruncated", "user": ""})
            content = self.si.content
            alarms = []
            for st in content.rootFolder.triggeredAlarmState or []:
                try:
                    alarms.append({"entity": _safe_name(st.entity), "etype": type(st.entity).__name__.split(".")[-1].replace("vim.", ""),
                                   "alarm": st.alarm.info.name, "status": str(st.overallStatus), "ts": st.time.timestamp(),
                                   "acknowledged": bool(st.acknowledged), "vcenter": self.name, "key": str(st.key)})
                except Exception:  # noqa: BLE001
                    pass
                try:
                    out.append({"key": f"alarm:{st.key}:{st.overallStatus}:{st.acknowledged}", "ts": st.time.timestamp(),
                                "sev": {"red": "critical", "yellow": "warning"}.get(str(st.overallStatus), "info"),
                                "kind": "alarm", "msg": f"알람 발생 중: {st.alarm.info.name} ({st.overallStatus})"
                                + (" [확인됨]" if st.acknowledged else ""),
                                "entity": _safe_name(st.entity), "host": "", "type": "TriggeredAlarm",
                                "user": "", "acknowledged": st.acknowledged})
                except Exception:  # noqa: BLE001
                    continue
            self.alarms = alarms
            return out

    # ------------------------------------------------------------------ ESXi 호스트 로그(증분)
    @staticmethod
    def _window(total: int, prior: int | None, lines: int) -> tuple[int, int, int | None]:
        tail_start = max(1, total - lines + 1)
        if prior is None:
            return tail_start, min(lines, total), 0
        if total < prior:
            return tail_start, min(lines, total), None          # 로그 회전
        new = total - prior
        if new > lines:
            return tail_start, lines, new - lines
        return prior + 1, new, 0

    def _scan_host_logs(self, deadline: float | None = None) -> list[LogEvent]:
        out: list[LogEvent] = []
        with self._lock:
            self._ensure()
            content = self.si.content
            diag = content.diagnosticManager
            on_vc = getattr(content.about, "apiType", "") == "VirtualCenter"
            hosts = self._collect(vim.HostSystem, ["name", "runtime.connectionState"])
        for href, props in hosts:
            if deadline and time.time() > deadline:               # 남은 호스트는 다음 주기(위치는 그대로라 이어서 읽음)
                break
            name = props.get("name", "")
            if str(props.get("runtime.connectionState", "connected")) != "connected":
                continue
            scope = {"host": href} if on_vc else {}
            for key in self.host_logs:
                prior = self._log_pos.get((name, key))
                try:
                    with self._lock:
                        probe = diag.BrowseDiagnosticLog(key=key, start=_PAST_THE_END, **scope)
                        total = getattr(probe, "lineEnd", 0) or 0
                        start, count, skipped = self._window(total, prior, self.host_log_lines)
                        text = []
                        if count > 0:
                            data = diag.BrowseDiagnosticLog(key=key, start=start, lines=count, **scope)
                            text = list(data.lineText or []) if data else []
                    self._log_pos[(name, key)] = start + len(text) - 1 if text else total
                    if self._log_unreadable.pop((name, key), None):
                        out.append(self.ev(f"{name}: {key} 로그 읽기 복구", severity="info", kind="health",
                                           host=name, entity=f"hostlog:{key}"))
                    if prior is None:
                        continue                                  # 첫 패스는 위치만 잡고 과거분은 재생하지 않음
                    if skipped:
                        out.append(self.ev(f"{name}: {key} 로그가 한 주기 동안 {self.host_log_lines}줄 이상 증가 — {skipped}줄 미수집"
                                           " (host_log_lines 상향 또는 syslog 전달 권장)", severity="warning", kind="health",
                                           host=name, entity=f"hostlog:{key}"))
                    elif skipped is None:
                        out.append(self.ev(f"{name}: {key} 로그 회전 — 회전 직전 구간 일부 미수집 가능", severity="info",
                                           kind="health", host=name, entity=f"hostlog:{key}"))
                    for line in text:
                        line = line.strip()
                        if line:
                            out.append(LogEvent(source="esxi", connector=self.name, message=clean(line, 2000),
                                                severity=sev_from_text(line), host=name, entity=key, kind="log",
                                                attrs={"via": "BrowseDiagnosticLog"}))
                except (vmodl.MethodFault, OSError) as e:
                    why = ("NoPermission — 호스트 로그 읽기에는 Global.Diagnostics 권한이 필요합니다(읽기 전용 역할 미포함)"
                           if isinstance(e, vim.fault.NoPermission) else f"{type(e).__name__} — 로그를 읽지 못함")
                    if self._log_unreadable.get((name, key)) != why:
                        self._log_unreadable[(name, key)] = why
                        out.append(self.ev(f"{name}: {key} 로그 수집 불가 — {why}", severity="warning", kind="health",
                                           host=name, entity=f"hostlog:{key}"))
        return out

    # ------------------------------------------------------------------ 토폴로지
    def _refresh_topology(self) -> dict[str, Any]:
        with self._lock:
            self._ensure()
            clusters = {c._moId: p.get("name", "") for c, p in self._collect(vim.ComputeResource, ["name"])}
            cl_drs: dict[str, Any] = {}
            for c, p in self._collect(vim.ClusterComputeResource, ["name", "configurationEx", "summary"]):
                cx = p.get("configurationEx")
                drs = getattr(cx, "drsConfig", None)
                vsan = getattr(getattr(cx, "vsanConfigInfo", None), "enabled", False)
                das = getattr(cx, "dasConfig", None)
                acp = getattr(das, "admissionControlPolicy", None)
                cl_drs[p.get("name", "")] = {"drs": bool(getattr(drs, "enabled", False)),
                                             "drs_behavior": str(getattr(drs, "defaultVmBehavior", "") or ""),
                                             "vsan": bool(vsan), "moid": c._moId,
                                             "ha": bool(getattr(das, "enabled", False)),
                                             "ha_admission": bool(getattr(das, "admissionControlEnabled", False)),
                                             "ha_failover_level": int(getattr(acp, "failoverLevel", 0) or 0),
                                             # 2.36.0 가정 분석 — 혼합 세대(EVC)·vSAN ESA(적응형 RAID-5) 판단
                                             "evc": str(getattr(p.get("summary"), "currentEVCModeKey", "") or ""),
                                             "vsan_esa": bool(getattr(getattr(cx, "vsanConfigInfo", None), "vsanEsaEnabled", False))}
            hosts = {}
            hmo = {}
            for h, p in self._collect(vim.HostSystem, ["name", "parent", "runtime.connectionState",
                                                       "runtime.inMaintenanceMode", "overallStatus", "datastore",
                                                       "summary.hardware.cpuMhz", "summary.hardware.numCpuCores",
                                                       "summary.hardware.numCpuPkgs", "summary.hardware.cpuModel", "summary.hardware.model", "summary.hardware.vendor",
                                                       "summary.hardware.memorySize", "summary.quickStats.overallCpuUsage",
                                                       "summary.quickStats.overallMemoryUsage"]):
                cl = clusters.get(p["parent"]._moId, "") if p.get("parent") is not None else ""
                hmo[h._moId] = p.get("name", "")
                hosts[p.get("name", "")] = {"moid": h._moId, "cluster": cl, "conn": str(p.get("runtime.connectionState", "")),
                                            "maintenance": bool(p.get("runtime.inMaintenanceMode")),
                                            "status": str(p.get("overallStatus", "")), "vms": 0,
                                            "datastores": [d.name for d in (p.get("datastore") or [])],
                                            "cpu_mhz": (p.get("summary.hardware.cpuMhz") or 0) * (p.get("summary.hardware.numCpuCores") or 0),
                                            "core_mhz": p.get("summary.hardware.cpuMhz") or 0,
                                            "sockets": int(p.get("summary.hardware.numCpuPkgs") or 0),          # 2.34.0 가정 분석 — 사양·라이선스 코어 계산
                                            "cpu_model": " ".join(str(p.get("summary.hardware.cpuModel") or "").split()),
                                            "hw_model": str(p.get("summary.hardware.model") or ""), "hw_vendor": str(p.get("summary.hardware.vendor") or ""),
                                            "mem_mb": round((p.get("summary.hardware.memorySize") or 0) / 2**20),
                                            "cpu_used_mhz": p.get("summary.quickStats.overallCpuUsage") or 0,
                                            "mem_used_mb": p.get("summary.quickStats.overallMemoryUsage") or 0}
            # 물리·네트워크(물리 → 논리 토폴로지): 하드웨어 식별(UUID·S/N — BMC·UCS 블레이드와 자동 연결), 물리 NIC, 가상 스위치 업링크
            hint_due = self.hint_interval > 0 and time.time() - self._last_hint > self.hint_interval
            hint_done: list[str] = []
            hint_err: list[str] = []
            try:
                for h, p in self._collect_tolerant(vim.HostSystem, ["name", "hardware.systemInfo.uuid", "hardware.systemInfo.serialNumber",
                                                                     "hardware.systemInfo.vendor", "hardware.systemInfo.model",
                                                                     "summary.hardware.otherIdentifyingInfo", "config.network.pnic",
                                                                     "config.network.vswitch", "config.network.proxySwitch",
                                                                     "config.product.version", "config.product.build", "configManager.networkSystem"]):
                    hd = hosts.get(p.get("name", ""))
                    if hd is None:
                        continue
                    ser = str(p.get("hardware.systemInfo.serialNumber") or "")
                    if not ser:
                        for oi in p.get("summary.hardware.otherIdentifyingInfo") or []:
                            if str(getattr(getattr(oi, "identifierType", None), "key", "")) in ("SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag") and oi.identifierValue:
                                ser = str(oi.identifierValue)
                                break
                    pn = {}
                    for n in p.get("config.network.pnic") or []:
                        sp = getattr(getattr(n, "linkSpeed", None), "speedMb", 0) or 0
                        pn[n.key] = {"name": n.device, "mac": str(n.mac or "").lower(), "speed": sp, "up": bool(sp), "driver": str(n.driver or "")}
                    sws = []
                    for vs in p.get("config.network.vswitch") or []:
                        sws.append({"name": vs.name, "kind": "vss", "uplinks": [pn[k]["name"] for k in (vs.pnic or []) if k in pn]})
                    for ps in p.get("config.network.proxySwitch") or []:
                        sws.append({"name": ps.dvsName, "kind": "vds", "uplinks": [pn[k]["name"] for k in (ps.pnic or []) if k in pn]})
                    for sw in sws:
                        for u in sw["uplinks"]:
                            for x in pn.values():
                                if x["name"] == u:
                                    x["vswitch"] = sw["name"]
                    hn_ = p.get("name", "")
                    ns = p.get("configManager.networkSystem")
                    if ns is not None and hint_due and len(hint_done) < self.hint_max_hosts and hd.get("conn") == "connected":
                        hint_done.append(hn_)
                        try:
                            self._net_hints[hn_] = parse_hints(ns.QueryNetworkHint())
                        except Exception as e:  # noqa: BLE001  (권한·구버전·vcsim 미지원 — 스위치 쪽 LLDP 로 대체)
                            hint_err.append(type(e).__name__)
                    for x in pn.values():
                        h = (self._net_hints.get(hn_) or {}).get(x["name"])
                        if h:
                            x["peer"] = h
                    hd.update(uuid=str(p.get("hardware.systemInfo.uuid") or "").lower(), serial=ser,
                              hw_vendor=str(p.get("hardware.systemInfo.vendor") or ""), hw_model=str(p.get("hardware.systemInfo.model") or ""),
                              pnics=list(pn.values())[:16], switches=sws[:12],
                              esx_version=str(p.get("config.product.version") or ""), esx_build=str(p.get("config.product.build") or ""))
            except Exception as e:  # noqa: BLE001  (권한·구버전 — 토폴로지 기본 정보는 유지)
                self._state.setdefault("checks", {})["물리 NIC·스위치"] = f"warn: {type(e).__name__}"[:120]
            if hint_due:
                self._last_hint = time.time()
                nh = sum(1 for h in hint_done if self._net_hints.get(h))
                self._state.setdefault("checks", {})["ESXi LLDP/CDP"] = (f"ok {nh}/{len(hint_done)} 호스트" if not hint_err else
                                                                        f"warn: {len(hint_err)}대 조회 실패({hint_err[0]}) — 스위치 쪽 LLDP 로 포트맵 작성")
            vms = {}
            for v, p in self._collect_tolerant(vim.VirtualMachine, ["name", "runtime.host", "runtime.powerState", "datastore",
                                                                    "runtime.consolidationNeeded", "config.template",
                                                                    "config.hardware.numCPU", "config.hardware.memoryMB", "config.guestFullName",
                                                                    "config.version", "config.uuid", "guest.ipAddress", "guest.hostName",
                                                                    "guest.toolsRunningStatus", "guest.toolsVersionStatus2", "guest.net",
                                                                    "summary.storage.committed", "summary.storage.uncommitted",
                                                                    "summary.quickStats.overallCpuUsage", "summary.quickStats.guestMemoryUsage",
                                                                    "network", "runtime.bootTime", "overallStatus", "snapshot", "parent"]):
                if p.get("config.template"):
                    continue
                hn = hmo.get(p["runtime.host"]._moId, "") if p.get("runtime.host") is not None else ""
                if hn in hosts:
                    hosts[hn]["vms"] += 1
                ips = []
                for n in (p.get("guest.net") or []):
                    for a in (getattr(n, "ipAddress", None) or []):
                        if a and ":" not in a and a not in ips:
                            ips.append(a)
                if p.get("guest.ipAddress") and p["guest.ipAddress"] not in ips and ":" not in p["guest.ipAddress"]:
                    ips.insert(0, p["guest.ipAddress"])
                nsnap, stree = 0, list(getattr(p.get("snapshot"), "rootSnapshotList", None) or [])
                while stree:
                    sn = stree.pop(); nsnap += 1; stree.extend(getattr(sn, "childSnapshotList", None) or [])
                bt = p.get("runtime.bootTime")
                vms[p.get("name", "")] = {"moid": v._moId, "host": hn, "cluster": hosts.get(hn, {}).get("cluster", ""),
                                          "power": str(p.get("runtime.powerState", "")),
                                          "consolidation": bool(p.get("runtime.consolidationNeeded")),
                                          "vcpu": int(p.get("config.hardware.numCPU") or 1),
                                          "mem_mb": int(p.get("config.hardware.memoryMB") or 0),
                                          "os": str(p.get("config.guestFullName") or ""), "hw": str(p.get("config.version") or ""),
                                          "uuid": str(p.get("config.uuid") or ""), "ips": ips[:8], "hostname": str(p.get("guest.hostName") or ""),
                                          "tools": str(p.get("guest.toolsRunningStatus") or ""), "tools_ver": str(p.get("guest.toolsVersionStatus2") or ""),
                                          "disk_gb": round((p.get("summary.storage.committed") or 0) / 2**30, 1),
                                          "prov_gb": round(((p.get("summary.storage.committed") or 0) + (p.get("summary.storage.uncommitted") or 0)) / 2**30, 1),
                                          "cpu_mhz": p.get("summary.quickStats.overallCpuUsage") or 0, "mem_used_mb": p.get("summary.quickStats.guestMemoryUsage") or 0,
                                          "networks": [getattr(n, "name", "") for n in (p.get("network") or [])][:8],
                                          "boot": bt.timestamp() if hasattr(bt, "timestamp") else 0, "status": str(p.get("overallStatus") or ""),
                                          "snapshots": nsnap, "parent_moid": getattr(p.get("parent"), "_moId", ""),
                                          "datastores": [d.name for d in (p.get("datastore") or [])]}
            # VM 폴더 경로(정산 프로젝트 매칭·논리 토폴로지) — 데이터센터/폴더/하위폴더 (데이터센터의 숨은 'vm' 폴더는 뺀다)
            try:
                fold = {f._moId: (p.get("name", ""), p.get("parent")) for f, p in self._collect(vim.Folder, ["name", "parent"])}
                dcs = {d._moId: p.get("name", "") for d, p in self._collect(vim.Datacenter, ["name", "vmFolder"])}
                cache: dict[str, tuple[str, str]] = {}

                def fpath(moid: str) -> tuple[str, str]:
                    if moid in cache:
                        return cache[moid]
                    parts, dc, cur, guard = [], "", moid, 0
                    while cur and guard < 40:
                        guard += 1
                        if cur in dcs:
                            dc = dcs[cur]
                            break
                        nm, par = fold.get(cur, ("", None))
                        if not nm and par is None:
                            break
                        parts.append(nm)
                        cur = getattr(par, "_moId", "")
                    if parts and dc:
                        parts.pop()                              # 데이터센터 바로 아래 'vm' 루트 폴더
                    cache[moid] = (dc, "/".join([dc] + parts[::-1]) if dc else "/".join(parts[::-1]))
                    return cache[moid]
                for v in vms.values():
                    if v.get("parent_moid"):
                        v["datacenter"], v["folder"] = fpath(v["parent_moid"])
            except Exception as e:  # noqa: BLE001
                self._state.setdefault("checks", {})["VM 폴더"] = f"warn: {type(e).__name__}"[:120]
            nets = {}
            for n, p in self._collect_tolerant(vim.Network, ["name", "host", "vm", "summary.accessible"]):
                kind = "dvportgroup" if isinstance(n, vim.dvs.DistributedVirtualPortgroup) else ("opaque" if type(n).__name__.endswith("OpaqueNetwork") else "portgroup")
                nets[p.get("name", "")] = {"moid": n._moId, "kind": kind, "hosts": len(p.get("host") or []), "vms": len(p.get("vm") or []),
                                           "accessible": p.get("summary.accessible")}
            try:
                for pg, p in self._collect_tolerant(vim.dvs.DistributedVirtualPortgroup, ["name", "config.defaultPortConfig", "config.distributedVirtualSwitch", "config.numPorts",
                                                                                       "config.key"]):
                    vl = getattr(getattr(p.get("config.defaultPortConfig"), "vlan", None), "vlanId", None)
                    if p.get("name") in nets:
                        nets[p["name"]].update(vlan=vl if isinstance(vl, int) else ("trunk" if vl else ""), key=str(p.get("config.key") or ""),
                                               dvs=getattr(p.get("config.distributedVirtualSwitch"), "name", ""), ports=p.get("config.numPorts"))
            except Exception:  # noqa: BLE001
                pass
            dss = {}
            for d, p in self._collect_tolerant(vim.Datastore, ["name", "summary.capacity", "summary.freeSpace", "summary.type", "host",
                                                               "summary.uncommitted", "summary.accessible", "summary.multipleHostAccess",
                                                               "summary.maintenanceMode", "overallStatus", "info", "vm"]):
                cap = p.get("summary.capacity") or 0
                free = p.get("summary.freeSpace") or 0
                info = p.get("info")
                vmfs = getattr(info, "vmfs", None)
                nas = getattr(info, "nas", None)
                mounts = [m for m in (p.get("host") or [])]
                dss[p.get("name", "")] = {"moid": d._moId, "capacity_gb": round(cap / 2**30, 1), "free_gb": round(free / 2**30, 1),
                                          "used_pct": round((1 - free / cap) * 100, 1) if cap else None,
                                          "type": p.get("summary.type", ""),
                                          "hosts": [hmo.get(m.key._moId, "") for m in mounts],
                                          "prov_gb": round((cap - free + (p.get("summary.uncommitted") or 0)) / 2**30, 1) if cap else None,
                                          "accessible": p.get("summary.accessible"), "shared": p.get("summary.multipleHostAccess"),
                                          "maintenance": str(p.get("summary.maintenanceMode") or ""), "status": str(p.get("overallStatus") or ""),
                                          "local": getattr(vmfs, "local", None) if vmfs is not None else None,
                                          "vmfs_version": str(getattr(vmfs, "version", "") or "") if vmfs is not None else "",
                                          "ssd": getattr(vmfs, "ssd", None) if vmfs is not None else None,
                                          "extents": [str(getattr(x, "diskName", "")) for x in (getattr(vmfs, "extent", None) or [])][:8] if vmfs is not None else [],
                                          "remote": (f"{getattr(nas, 'remoteHost', '')}:{getattr(nas, 'remotePath', '')}" if nas is not None else ""),
                                          "url": str(getattr(info, "url", "") or ""),
                                          "vms": len(p.get("vm") or [])}
            # vSAN — 호스트별 vSAN 구성(디스크 그룹)·런타임(디스크 문제)·클러스터 멤버 상태(QueryHostStatus, 읽기 전용)
            try:
                for h, p in self._collect_tolerant(vim.HostSystem, ["name", "config.vsanHostConfig", "runtime.vsanRuntimeInfo", "configManager.vsanSystem"]):
                    hd = hosts.get(p.get("name", ""))
                    vc = p.get("config.vsanHostConfig")
                    if hd is None or vc is None or not getattr(vc, "enabled", False):
                        continue
                    maps = list(getattr(getattr(vc, "storageInfo", None), "diskMapping", None) or [])
                    rt = p.get("runtime.vsanRuntimeInfo")
                    vs = {"enabled": True, "cluster_uuid": str(getattr(getattr(vc, "clusterInfo", None), "uuid", "") or ""),
                          "node_uuid": str(getattr(getattr(vc, "clusterInfo", None), "nodeUuid", "") or ""),
                          "disk_groups": len(maps), "cache_disks": sum(1 for m in maps if getattr(m, "ssd", None) is not None),
                          "capacity_disks": sum(len(getattr(m, "nonSsd", None) or []) for m in maps),
                          "disk_issues": [f"{getattr(x, 'diskId', '')}: {getattr(x, 'issue', '')}" for x in (getattr(rt, "diskIssues", None) or [])][:12],
                          "members": len(getattr(rt, "membershipList", None) or []), "health": "", "role": ""}
                    vsys = p.get("configManager.vsanSystem")
                    if vsys is not None:
                        try:
                            st = vsys.QueryHostStatus()
                            vs["health"] = str(getattr(st, "health", "") or "")
                            vs["role"] = str(getattr(getattr(st, "nodeState", None), "state", "") or "")
                            vs["member_uuids"] = len(getattr(st, "memberUuid", None) or [])
                        except Exception:  # noqa: BLE001
                            pass
                    hd["vsan"] = vs
            except Exception as e:  # noqa: BLE001
                self._state.setdefault("checks", {})["vSAN 호스트"] = f"warn: {type(e).__name__}"[:120]
            cls = {}
            for hn, h in hosts.items():
                c = cls.setdefault(h["cluster"] or "(standalone)", {"hosts": [], **cl_drs.get(h["cluster"], {})})
                c["hosts"].append(hn)
            # vSAN Health·용량·객체(/vsanHealth, 읽기 전용) — vSAN 이 켜진 클러스터만, 실패해도 토폴로지는 유지
            prev_vh = {cn: x.get("vsan_health") for cn, x in (self.topology.get("clusters") or {}).items()}
            if self.cfg.get("vsan_health", True) and any(x.get("vsan") for x in cls.values()):
                try:
                    self._vsan_health(cls, cl_drs)
                except Exception as e:  # noqa: BLE001
                    self._state.setdefault("checks", {})["vSAN Health"] = f"warn: {type(e).__name__}: {e}"[:160]
            for cn, x in cls.items():
                if x.get("vsan") and not x.get("vsan_health") and prev_vh.get(cn):
                    x["vsan_health"] = prev_vh[cn]                   # 이번 조회 실패 — 직전 결과 유지(ts 로 오래됨 표시)
        self.topology = {"hosts": hosts, "vms": vms, "datastores": dss, "clusters": cls, "networks": nets, "updated": time.time(),
                         "vcenter": self.host, "environment": self.environment}
        return self.topology

    def _vsan_health(self, cls: dict, cl_drs: dict) -> None:
        from .vsanhealth import VsanClient
        vc = getattr(self, "_vsan", None)
        if vc is None or vc.si is not self.si:
            ctx = ssl.create_default_context()
            if not self.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            vc = VsanClient(self.si, self.host.split(":")[0], int(self.cfg.get("port", self.host.split(":")[1] if ":" in self.host else 443)), ctx)
            if not vc.connect():
                self._state.setdefault("checks", {})["vSAN Health"] = f"비활성: {vc.error}"[:160]
                self._vsan = None
                return
            self._vsan = vc
        moids = {cn: x.get("moid") for cn, x in cl_drs.items() if x.get("moid")}
        by_moid = {c._moId: c for c, _ in self._collect(vim.ClusterComputeResource, ["name"])}
        n_ok, bad = 0, []
        for cn, x in cls.items():
            if not x.get("vsan"):
                continue
            mo = by_moid.get(moids.get(cn, ""))
            if mo is None:
                continue
            h = vc.cluster(mo)
            x["vsan_health"] = h
            if h.get("error") and not h.get("groups"):
                bad.append(f"{cn}: {h['error']}")
            else:
                n_ok += 1
        self._state.setdefault("checks", {})["vSAN Health"] = (f"ok {n_ok}개 클러스터 · API {vc.version}" + (f" · 실패 {'; '.join(bad)[:120]}" if bad else ""))[:200]

    def entities(self) -> list[dict[str, Any]]:
        out = []
        for name, h in sorted(self.topology.get("hosts", {}).items()):
            conn, ov = h.get("conn", ""), h.get("status", "")
            st = ("down" if conn not in ("connected", "") or ov == "red" else "maint" if h.get("maintenance")
                  else "warn" if ov == "yellow" else "ok" if ov in ("green", "gray", "") else "unknown")
            out.append({"name": name, "kind": "host", "state": st, "group": h.get("cluster") or "(standalone)",
                        "detail": f"{conn} · {ov}" + (" · 유지보수 모드" if h.get("maintenance") else "") + f" · VM {h.get('vms', 0)}"})
        return out

    def resolve(self, name: str) -> dict[str, str] | None:
        """엔터티/호스트 이름 → {kind, name, cluster, host}"""
        if not name:
            return None
        n = name.strip()
        t = self.topology
        if n in t["vms"]:
            v = t["vms"][n]
            return {"kind": "vm", "name": n, "host": v["host"], "cluster": v["cluster"], "vcenter": self.host}
        if n in t["hosts"]:
            return {"kind": "host", "name": n, "host": n, "cluster": t["hosts"][n]["cluster"], "vcenter": self.host}
        short = n.split(".")[0].lower()
        for hn, h in t["hosts"].items():
            if hn.split(".")[0].lower() == short:
                return {"kind": "host", "name": hn, "host": hn, "cluster": h["cluster"], "vcenter": self.host}
        if n in t["datastores"]:
            return {"kind": "datastore", "name": n, "host": "", "cluster": "", "vcenter": self.host}
        if n in t["clusters"]:
            return {"kind": "cluster", "name": n, "host": "", "cluster": n, "vcenter": self.host}
        return None

    # ------------------------------------------------------------------ 폴링
    async def poll(self) -> list[LogEvent]:
        """이벤트 읽기(+가벼운 어플라이언스 헬스)만 — 2.30.0. 무거운 수집(토폴로지·SLI·인프라 점검·호스트 로그·백업 조회)은 _kick_heavy 가
        별도 작업으로 돌린다. `seen`·`since` 는 이벤트를 실제로 돌려주기 직전에만 갱신(도중에 취소돼도 다음 주기에 다시 읽힘)."""
        try:
            rows = await self._t(self._read_events)
            self._state["checks"].pop("이벤트 읽기", None)
        except VCenterBusy as e:
            if not (self._bg_busy() or self._thr_busy):
                raise
            rows = []                                   # 무거운 수집이 스텁을 쓰는 중 — 이번 주기는 건너뛰고 다음 주기에 같은 구간을 다시 읽음
            self._state["checks"]["이벤트 읽기"] = f"warn: 무거운 수집 진행 중이라 이번 주기 건너뜀({e})"[:200]
        try:
            health, hkeys = await asyncio.wait_for(self._appliance_health_peek(), timeout=min(20.0, self.poll_timeout / 3))
        except asyncio.TimeoutError:
            health, hkeys = [], []
        # ---- 여기부터 반환까지 await 없음: seen·since 갱신과 반환이 한 덩어리
        events: list[LogEvent] = []
        newest = self.since
        for r in rows:
            if not self.seen.is_new(str(r["key"])):
                continue
            newest = max(newest, r["ts"]) if r["type"] != "AIOpsTruncated" else newest
            attrs = {"eventType": r["type"], "user": r["user"]}
            msg = r["msg"]
            mv = r.get("move")
            if mv:
                attrs["move"] = mv
                if mv["type"] in ("vmotion", "drs", "svmotion", "relocate") or (mv["type"] in LIFE_TYPES and mv["type"] != "create_failed"):   # 정상 운영 이동·생성·삭제: 기록·표시만(이상징후 아님)
                    attrs["no_anomaly"] = 1
                if mv["type"] in ("ha_restart", "ha_failed", "ha_reset", "ha_reset_failed"):   # 한 호스트 장애로 여러 VM 재시작 → 하나의 이상징후로
                    attrs["fp"] = f"{mv['type']}|{mv['from_host'] or mv['cluster'] or mv['vm']}"
                    attrs["vc_message"] = msg
                    msg = {"ha_restart": "vSphere HA 가 VM 을 다른 호스트에서 재시작", "ha_failed": "vSphere HA VM 재시작(페일오버) 실패",
                           "ha_reset": "vSphere HA VM 모니터링이 VM 을 리셋", "ha_reset_failed": "vSphere HA VM 리셋 실패"}[mv["type"]] \
                        + f" — {mv['vm']}: {mv['from_host'] or '?'} → {mv['to_host'] or '?'}" + (f" (클러스터 {mv['cluster']})" if mv["cluster"] else "")
            events.append(self.ev(msg, severity=r["sev"], kind=r["kind"], entity=r["entity"],
                                  host=r["host"] or self.host, ts=r["ts"], native_id=str(r["key"]), attrs=attrs))
        self.since = newest
        for k in hkeys:
            self.seen.is_new(k)
        events += health
        self._kick_heavy()
        return events

    # ------------------------------------------------------------------ 무거운 수집(폴링과 분리된 작업)
    def _heavy(self, key: str, attr: str, interval: float, job, label: str, timeout: float | None = None) -> bool:
        """주기가 됐고 같은 수집이 돌고 있지 않으면 시작. 성공해야 `_last_*` 를 찍고, 실패·시간 초과는 heavy_retry 뒤 다시 시도."""
        if time.time() - getattr(self, attr) <= interval or self._bg_busy(key) or key in self._thr_busy:
            return False

        async def run():
            ok = False
            try:
                ok = (await job()) is not False
                if ok and not str(self._state["checks"].get(label, "")).startswith("ok"):
                    self._state["checks"].pop(label, None)
            except asyncio.CancelledError:
                self._state["checks"][label] = f"warn: 수집 시간 초과·중단 — {int(self.heavy_retry)}초 뒤 재시도"
                raise
            except Exception as e:  # noqa: BLE001
                self._state["checks"][label] = f"{type(e).__name__}: {e}"[:150]
                raise
            finally:
                now = time.time()
                setattr(self, attr, now if ok else now - interval + min(interval, self.heavy_retry))
        return self._bg_start(key, run, timeout or self.heavy_timeout)

    def _kick_heavy(self) -> None:
        cfg = self.cfg
        self._heavy("topology", "_last_topo", float(cfg.get("topology_interval", 300)), self._job_topology, "토폴로지")
        if self.topology.get("updated"):
            if self.sli_cfg["enabled"]:
                self._heavy("sli", "_last_sli", self.sli_cfg["interval"], self._job_sli, "성능 SLI 수집")
            if self.health_cfg["enabled"]:
                self._heavy("health", "_last_health", self.health_cfg["interval"], self._job_health, "인프라 점검 수집")
        if self.rest_token:
            self._heavy("backup", "_last_bkp", float(cfg.get("backup_interval", 3600)), self._job_backup, "백업 조회", timeout=120)
        if self.host_logs:
            self._heavy("hostlog", "_last_hostlog", self.host_log_interval, self._job_hostlog, "호스트 로그 수집")

    async def _job_topology(self):
        prev = {n: v.get("host", "") for n, v in self.topology.get("vms", {}).items()} if self.topology.get("updated") else {}
        acc, self._moved = self._moved, set()
        try:
            await self._tx("topology", self._refresh_topology)
        except BaseException:
            self._moved |= acc                          # 다음 비교 때 다시 쓰도록 되돌림
            raise
        self._last_topo = time.time()                   # 이후 단계(태그)가 늦어도 인벤토리는 갱신된 것
        await self._deliver(self._placement_diff(prev, acc | self._moved | self._move_vms) + self._vsan_health_events())
        self._kick_heavy()                              # 첫 토폴로지 직후 SLI·점검을 바로 시작
        await self._refresh_tags()

    async def _job_sli(self):
        first = not self.sli.get("updated")
        try:
            res = await self._tx("sli", self._collect_sli)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            self.sli = {**self.sli, "error": f"{type(e).__name__}: {e}"[:300]}
            self._state["checks"]["성능 SLI"] = f"수집 실패: {type(e).__name__}: {e}"[:150]
            return False
        self.sli = res
        self._state["checks"].pop("성능 SLI", None)
        await self._deliver(self._sli_events(res, first))

    async def _job_health(self):
        await self._deliver(await self.run_health())
        return not self.health.get("error")

    async def _job_backup(self):
        await self._deliver(await self.collect_backup())
        return not (self.protection or {}).get("error")

    async def _job_hostlog(self):
        budget = max(30.0, self.heavy_timeout - 2 * self.soap_timeout - 30)   # 시간 안에 못 읽은 호스트는 다음 주기에(읽은 줄은 버리지 않음)
        await self._deliver(await self._tx("hostlog", self._scan_host_logs, time.time() + budget))

    def _vsan_health_events(self) -> list[LogEvent]:
        """vSAN Health 점검 상태 변화 → 이벤트(red=오류, yellow=경고, 정상 복귀=정보). 첫 조회는 비정상 항목만."""
        out: list[LogEvent] = []
        seen = getattr(self, "_vsan_seen", None)
        first = seen is None
        if first:
            seen = self._vsan_seen = {}
        for cn, x in (self.topology.get("clusters") or {}).items():
            h = x.get("vsan_health") or {}
            cur = {}
            for g in h.get("groups") or []:
                for t in g.get("tests") or []:
                    cur[f"{cn}|{g['name']}|{t['name']}"] = (t["health"], t.get("desc", ""))
            if h.get("overall"):
                cur[f"{cn}|overall|overall"] = (h["overall"], h.get("overall_desc", ""))
            for k, (st, desc) in cur.items():
                old = seen.get(k)
                seen[k] = st
                if old == st or (first and st not in ("red", "yellow")) or (old is None and st not in ("red", "yellow")):
                    continue
                _, grp, name = k.split("|", 2)
                sev = "error" if st == "red" else "warning" if st == "yellow" else "info"
                what = "vSAN Health 전체" if grp == "overall" else f"vSAN Health [{grp}] {name}"
                out.append(self.ev(f"{what}: {st}{' ← ' + old if old else ''} — {desc}".strip(), severity=sev, kind="health", entity=cn,
                                   host=self.host, attrs={"app": "vsan-health", "cluster": cn, "test": name, "group": grp, "state": st,
                                                          "no_anomaly": 1 if sev == "info" else 0}))
        return out[:200]

    async def _refresh_tags(self) -> None:
        """VM 태그(정산 프로젝트 매칭) — vSphere Automation REST(읽기):
        POST /api/cis/tagging/tag-association?action=list-attached-tags-on-objects {object_ids:[{type:VirtualMachine,id}]}
        GET /api/cis/tagging/tag/{id}(이름·category_id) · GET /api/cis/tagging/category/{id}(이름). 결과는 vms[*].tags = ["카테고리:태그"]"""
        if not self.rest_token or not self.cfg.get("collect_tags", True):
            return
        vms = self.topology.get("vms", {})
        by_moid = {v["moid"]: v for v in vms.values() if v.get("moid")}
        if not by_moid:
            return
        tag_ids: dict[str, list[str]] = {}
        try:
            ids = list(by_moid)
            for i in range(0, len(ids), 500):
                r = await self.http.post("/api/cis/tagging/tag-association", params={"action": "list-attached-tags-on-objects"},
                                         json={"object_ids": [{"type": "VirtualMachine", "id": m} for m in ids[i:i + 500]]})
                if r.status_code >= 300:
                    self._state["checks"]["VM 태그"] = f"warn: HTTP {r.status_code}"
                    return
                for x in r.json() or []:
                    tag_ids[str((x.get("object_id") or {}).get("id", ""))] = [str(t) for t in x.get("tag_ids") or []]
            names = getattr(self, "_tag_names", {})
            cats = getattr(self, "_tag_cats", {})
            for tid in {t for lst in tag_ids.values() for t in lst} - set(names):
                r = await self.http.get(f"/api/cis/tagging/tag/{tid}")
                if r.status_code < 300:
                    j = r.json() or {}
                    cid = str(j.get("category_id", ""))
                    if cid and cid not in cats:
                        rc = await self.http.get(f"/api/cis/tagging/category/{cid}")
                        cats[cid] = (rc.json() or {}).get("name", "") if rc.status_code < 300 else ""
                    names[tid] = f"{cats.get(cid, '')}:{j.get('name', '')}" if cats.get(cid) else str(j.get("name", ""))
            self._tag_names, self._tag_cats = names, cats
            for moid, v in by_moid.items():
                v["tags"] = sorted({names[t] for t in tag_ids.get(moid, []) if names.get(t)})
            self._state["checks"]["VM 태그"] = f"ok 태그 {len(names)}개 · 태그 붙은 VM {sum(1 for x in tag_ids.values() if x)}"
        except Exception as e:  # noqa: BLE001
            self._state["checks"]["VM 태그"] = f"warn: {type(e).__name__}"[:120]

    def _placement_diff(self, prev: dict[str, str], moved: set[str] | None = None) -> list[LogEvent]:
        """인벤토리 갱신 전후 VM 위치 비교 — 이벤트를 놓쳤거나(보존 기간·폭주) 다른 경로로 옮겨진 VM 도 이동 기록에 남김"""
        out: list[LogEvent] = []
        if not prev:
            return out
        moved = self._move_vms if moved is None else moved       # 이벤트로 이미 기록한 VM(직전 갱신 이후 누적)
        cur = self.topology.get("vms", {})
        for vm, v in cur.items():
            a, b = prev.get(vm), v.get("host", "")
            if a and b and a != b and vm not in moved:
                mv = {"type": "detected", "vm": vm, "from_host": a, "to_host": b, "from_ds": "", "to_ds": "", "cluster": v.get("cluster", ""),
                      "user": "", "vcenter": self.name}
                out.append(self.ev(f"VM {vm} 실행 호스트 변경 감지: {a} → {b} (인벤토리 비교)", severity="info", kind="event", entity=vm,
                                   host=b, attrs={"eventType": "AIOpsPlacementChanged", "move": mv, "no_anomaly": 1}))
        # 2.4.2 생성·삭제 — 이벤트를 놓친 경우(보존 기간·폭주·다른 vCenter 경로) 인벤토리 비교로 보완. 대량 변화(재연결·부분 조회)는 건너뜀
        now = time.time()
        self._life_vms = {k: t for k, t in self._life_vms.items() if now - t < 3600}
        new = [vm for vm in cur if vm not in prev and vm not in moved and vm not in self._life_vms]
        gone = [vm for vm in prev if vm not in cur and vm not in moved and vm not in self._life_vms]
        if prev and cur and len(gone) <= max(20, len(prev) // 5) and len(new) <= max(50, len(prev) // 2):   # 첫 수집(비교 기준 없음)은 건너뜀
            for vm in new[:200]:
                v = cur[vm]
                mv = {"type": "detected_new", "vm": vm, "from_host": "", "to_host": v.get("host", ""), "from_ds": "", "to_ds": ",".join(v.get("datastores", [])[:2]),
                      "cluster": v.get("cluster", ""), "user": "", "vcenter": self.name, "source": ""}
                out.append(self.ev(f"새 VM 감지: {vm} ({v.get('host', '')}) — 인벤토리 비교", severity="info", kind="event", entity=vm, host=v.get("host", ""),
                                   attrs={"eventType": "AIOpsVmAppeared", "move": mv, "no_anomaly": 1}))
            for vm in gone[:200]:
                mv = {"type": "detected_gone", "vm": vm, "from_host": prev.get(vm, ""), "to_host": "", "from_ds": "", "to_ds": "", "cluster": "",
                      "user": "", "vcenter": self.name, "source": ""}
                out.append(self.ev(f"VM 사라짐 감지: {vm} (마지막 {prev.get(vm, '')}) — 삭제·등록 해제·다른 vCenter 이동", severity="info", kind="event", entity=vm,
                                   host=prev.get(vm, ""), attrs={"eventType": "AIOpsVmDisappeared", "move": mv, "no_anomaly": 1}))
        return out[:800]

    async def _appliance_health(self) -> list[LogEvent]:
        out, keys = await self._appliance_health_peek()
        for k in keys:
            self.seen.is_new(k)
        return out

    async def _appliance_health_peek(self) -> tuple[list[LogEvent], list[str]]:
        """(이벤트, 반환 시점에 seen 으로 표시할 키) — 도중에 취소돼도 상태 변화 이벤트를 잃지 않게 seen 표시는 호출 쪽에서"""
        out: list[LogEvent] = []
        keys: list[str] = []
        if not self.rest_token:
            return out, keys
        for comp in ("system", "database", "storage", "mem", "load", "swap", "applmgmt"):
            try:
                r = await self.http.get(f"/api/appliance/health/{comp}")
                if r.status_code == 401:
                    r.raise_for_status()
                if r.status_code >= 300:
                    continue
                val = str(r.json()).strip('"').lower()
            except Exception as e:  # noqa: BLE001
                if "401" in str(e):
                    raise
                continue
            k = f"health:{comp}:{val}"
            if k not in self.seen:
                keys.append(k)
                if val not in ("green",) or not self.first_poll:
                    sev = {"green": "info", "yellow": "warning", "orange": "error", "red": "critical",
                           "gray": "warning"}.get(val, "info")
                    out.append(self.ev(f"vCenter 어플라이언스 헬스 {comp} = {val}", severity=sev, kind="health",
                                       entity=f"vcsa:{comp}"))
        return out, keys

    # ------------------------------------------------------------------ 2.13.0 VM IOPS(비용 비교·디스크 성능 등급 판단)
    IOPS_COUNTERS = ("virtualDisk.numberReadAveraged.average", "virtualDisk.numberWriteAveraged.average",       # 가상 디스크별(우선)
                     "datastore.numberReadAveraged.average", "datastore.numberWriteAveraged.average")           # VM 의 데이터스토어별(대체)

    def _iops_env(self, names: list[str]):
        """(PerformanceManager, {VM 이름: 관리 객체}) — 테스트에서 바꿔 끼울 수 있게 분리"""
        self._ensure()
        objs = {v._moId: v for v, p in self._collect(vim.VirtualMachine, ["name"])} if names else {}
        vms = self.topology.get("vms", {})
        return self.si.content.perfManager, {n: objs.get(vms.get(n, {}).get("moid")) for n in names}

    def _iops_spec(self, entity, mids, interval: int, n: int):
        return vim.PerformanceManager.QuerySpec(entity=entity, metricId=mids, intervalId=interval, maxSample=n, format="normal")

    def collect_vm_iops(self, max_vms: int = 3000, batch: int = 50, samples: int = 180) -> dict[str, dict[str, Any]]:
        """전원 켠 VM 의 가상 디스크 읽기+쓰기 IOPS — 실시간(20초) 최근 samples 개(기본 1시간). 디스크(인스턴스)별 값을 시각마다 합산.
        가상 디스크 카운터가 없으면 데이터스토어 카운터, 실시간 통계가 없으면 5분 간격 통계로 대체. 읽기 전용(PerformanceManager.QueryPerf)."""
        with self._lock:
            vms = [n for n, v in self.topology.get("vms", {}).items() if v.get("power") == "poweredOn"][:max_vms]
            pm, objs = self._iops_env(vms)
            ids = {f"{x.groupInfo.key}.{x.nameInfo.key}.{x.rollupType}": x.key for x in pm.perfCounter}
        rev = {v: k for k, v in ids.items()}
        cids = [ids[k] for k in self.IOPS_COUNTERS if k in ids]
        if not cids:
            return {}
        mids = [vim.PerformanceManager.MetricId(counterId=c, instance="*") for c in cids]
        out: dict[str, dict[str, Any]] = {}
        for interval, ns in ((20, samples), (300, max(1, samples // 15))):
            todo = [n for n in vms if n not in out and objs.get(n) is not None]
            for i in range(0, len(todo), batch):
                chunk = todo[i:i + batch]
                names = {objs[n]._moId: n for n in chunk}
                try:
                    with self._lock:                             # 묶음마다 잠금(2.30.0) — 이벤트·토폴로지 수집이 오래 멈추지 않게
                        res = pm.QueryPerf(querySpec=[self._iops_spec(objs[n], mids, interval, ns) for n in chunk]) or []
                except Exception:  # noqa: BLE001
                    continue
                for em in res:
                    vn = names.get(em.entity._moId)
                    by: dict[str, list] = {"virtualDisk": [], "datastore": []}
                    for ser in em.value or []:
                        grp = rev.get(ser.id.counterId, "").split(".")[0]
                        if ser.value and grp in by:
                            by[grp].append([float(x) for x in ser.value])
                    rows = by["virtualDisk"] or by["datastore"]
                    if not vn or not rows:
                        continue
                    n = min(len(r) for r in rows)
                    tot = [sum(max(0.0, r[j]) for r in rows) for j in range(n)]
                    if tot:
                        out[vn] = {"min": min(tot), "max": max(tot), "sum": sum(tot), "n": len(tot), "interval": interval}
        return out

    # ------------------------------------------------------------------ 2.21.0 NSX 세그먼트 트래픽
    SEG_COUNTERS = ("net.received.average", "net.transmitted.average",           # KBps(vNIC 인스턴스별)
                    "net.packetsRx.summation", "net.packetsTx.summation",       # 수집 간격 동안 패킷 수
                    "net.droppedRx.summation", "net.droppedTx.summation")       # 수집 간격 동안 버린 패킷 수

    def segment_vnics(self, scope: str = "nsx") -> dict[str, Any]:
        """네트워크별 VM vNIC 목록 — scope: "nsx" = NSX 백킹 분산 포트그룹(config.backingType == "nsx", segmentId·logicalSwitchUuid)·
        opaque network(N-VDS, summary.opaqueNetworkId), "vds" = NSX 가 아닌 분산 포트그룹, "std" = 표준 vSwitch 포트그룹, "all" = 전부.
        읽기 전용(PropertyCollector)."""
        want_nsx, want_vds, want_std = scope in ("nsx", "all"), scope in ("vds", "all"), scope in ("std", "all")
        with self._lock:
            self._ensure()
            out: dict[str, Any] = {"vcenter": self.name, "segments": {}, "vnics": [], "error": ""}
            pgs, opq = {}, {}
            try:
                for pg, p in self._collect_tolerant(vim.dvs.DistributedVirtualPortgroup, ["name", "config.key", "config.backingType", "config.segmentId",
                                                                                       "config.logicalSwitchUuid", "config.transportZoneName", "config.uplink",
                                                                                       "config.distributedVirtualSwitch"]):
                    if p.get("config.uplink"):
                        continue
                    nsx = str(p.get("config.backingType") or "") == "nsx"
                    if (nsx and not want_nsx) or (not nsx and not want_vds):
                        continue
                    seg = {"name": p.get("name", ""), "kind": "nsx" if nsx else "dvpg", "segment_path": str(p.get("config.segmentId") or ""),
                           "ls_uuid": str(p.get("config.logicalSwitchUuid") or ""), "tz": str(p.get("config.transportZoneName") or ""),
                           "dvs": getattr(p.get("config.distributedVirtualSwitch"), "name", "")}
                    pgs[str(p.get("config.key") or pg._moId)] = seg
            except Exception as e:  # noqa: BLE001
                out["error"] = f"분산 포트그룹: {type(e).__name__}"
            try:
                for n, p in (self._collect_tolerant(vim.OpaqueNetwork, ["name", "summary"]) if want_nsx else []):
                    sm = p.get("summary")
                    nid = str(getattr(sm, "opaqueNetworkId", "") or "")
                    if nid:
                        opq[nid] = {"name": p.get("name", ""), "kind": "nsx", "segment_path": "", "ls_uuid": nid, "tz": "",
                                    "dvs": str(getattr(sm, "opaqueNetworkType", "") or "")}
            except Exception:  # noqa: BLE001
                pass
            hosts = {v.get("moid"): (n, v.get("cluster", "")) for n, v in self.topology.get("hosts", {}).items()}
            for vm, p in self._collect_tolerant(vim.VirtualMachine, ["name", "runtime.powerState", "runtime.host", "config.hardware.device", "guest.net",
                                                                     "config.template"]):
                if p.get("config.template"):
                    continue
                ips = {}
                for g in p.get("guest.net") or []:
                    ips[str(getattr(g, "macAddress", "") or "").lower()] = [a for a in (getattr(g, "ipAddress", None) or []) if ":" not in a][:4]
                hn, cl = hosts.get(getattr(p.get("runtime.host"), "_moId", ""), ("", ""))
                for d in p.get("config.hardware.device") or []:
                    if not isinstance(d, vim.vm.device.VirtualEthernetCard):
                        continue
                    b = d.backing
                    seg = None
                    if isinstance(b, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
                        seg = pgs.get(str(getattr(b.port, "portgroupKey", "") or ""))
                    elif isinstance(b, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
                        seg = opq.get(str(b.opaqueNetworkId or ""))
                    elif want_std and isinstance(b, vim.vm.device.VirtualEthernetCard.NetworkBackingInfo) and b.deviceName:
                        seg = {"name": b.deviceName, "kind": "std", "segment_path": "", "ls_uuid": "", "tz": "", "dvs": "vSwitch", "key": f"std:{b.deviceName}"}
                    if not seg:
                        continue
                    key = seg.get("key") if seg.get("kind") == "std" else (seg["segment_path"] or seg["ls_uuid"] or seg["name"])
                    out["segments"].setdefault(key, {**seg, "key": key})
                    mac = str(d.macAddress or "").lower()
                    out["vnics"].append({"vm": p.get("name", ""), "moid": vm._moId, "power": str(p.get("runtime.powerState") or ""), "host": hn, "cluster": cl,
                                         "device": int(d.key), "label": getattr(d.deviceInfo, "label", "") if d.deviceInfo else "", "mac": mac,
                                         "type": type(d).__name__.split(".")[-1].replace("Virtual", "").lower(),
                                         "connected": bool(getattr(d.connectable, "connected", False)) if d.connectable else False,
                                         "segment": key, "ips": ips.get(mac, [])})
            return out

    def vnic_traffic(self, vnics: list[dict], samples: int = 15, batch: int = 50) -> dict[str, Any]:
        """vNIC 별 실시간(20초) 네트워크 카운터 최근 samples 개 — {"<moid>:<device>": {"ts":[...], "rx_bps":[...], "tx_bps":[...],
        "rx_pps":[...], "tx_pps":[...], "drop_rx":[...], "drop_tx":[...]}}. 성능 카운터 인스턴스 = vNIC 장치 키. 읽기 전용(QueryPerf)."""
        with self._lock:
            self._ensure()
            pm = self.si.content.perfManager
            ids = {f"{x.groupInfo.key}.{x.nameInfo.key}.{x.rollupType}": x.key for x in pm.perfCounter}
            rev = {v: k for k, v in ids.items()}
            cids = [ids[k] for k in self.SEG_COUNTERS if k in ids]
            if not cids:
                return {"series": {}, "interval": 20, "error": "네트워크 성능 카운터 없음"}
            by_vm: dict[str, set] = {}
            for v in vnics:
                if v.get("power") == "poweredOn":
                    by_vm.setdefault(v["moid"], set()).add(str(v["device"]))
            objs = {o._moId: o for o, _ in self._collect(vim.VirtualMachine, ["name"]) if o._moId in by_vm}
            mids = [vim.PerformanceManager.MetricId(counterId=c, instance="*") for c in cids]
            out: dict[str, dict] = {}
            err = ""
            todo = [m for m in by_vm if m in objs]
            for i in range(0, len(todo), batch):
                chunk = todo[i:i + batch]
                try:
                    res = pm.QueryPerf(querySpec=[vim.PerformanceManager.QuerySpec(entity=objs[m], metricId=mids, intervalId=20, maxSample=samples,
                                                                                    format="normal") for m in chunk]) or []
                except Exception as e:  # noqa: BLE001
                    err = f"QueryPerf: {type(e).__name__}"
                    continue
                for em in res:
                    moid = em.entity._moId
                    ts = [x.timestamp.timestamp() for x in (em.sampleInfo or [])]
                    for ser in em.value or []:
                        inst = str(ser.id.instance or "")
                        if inst not in by_vm.get(moid, ()):
                            continue
                        k = rev.get(ser.id.counterId, "")
                        row = out.setdefault(f"{moid}:{inst}", {"ts": ts})
                        vals = [max(0.0, float(x)) for x in (ser.value or [])]
                        if k == "net.received.average":
                            row["rx_bps"] = [x * 8 * 1024 for x in vals]
                        elif k == "net.transmitted.average":
                            row["tx_bps"] = [x * 8 * 1024 for x in vals]
                        elif k == "net.packetsRx.summation":
                            row["rx_pps"] = [x / 20 for x in vals]
                        elif k == "net.packetsTx.summation":
                            row["tx_pps"] = [x / 20 for x in vals]
                        elif k == "net.droppedRx.summation":
                            row["drop_rx"] = vals
                        elif k == "net.droppedTx.summation":
                            row["drop_tx"] = vals
            return {"series": out, "interval": 20, "error": err}

    def vm_net_history(self, moid: str, hours: float = 24) -> dict[str, Any]:
        """VM 한 대의 네트워크 사용량 과거 통계 — net.usage.average(KBps, 수신+송신, 통계 수준 1) 와 있으면 received/transmitted.
        24시간 이하 = 5분 간격, 7일 이하 = 30분, 그 이상 = 2시간. 읽기 전용(QueryPerf)."""
        import datetime as _dt
        with self._lock:
            self._ensure()
            pm = self.si.content.perfManager
            ids = {f"{x.groupInfo.key}.{x.nameInfo.key}.{x.rollupType}": x.key for x in pm.perfCounter}
            keys = [k for k in ("net.usage.average", "net.received.average", "net.transmitted.average") if k in ids]
            if not keys:
                return {"ts": [], "series": {}, "interval": 0, "error": "네트워크 성능 카운터 없음"}
            interval = 300 if hours <= 24 else 1800 if hours <= 168 else 7200
            obj = vim.VirtualMachine(moid, self.si._stub)
            end = _dt.datetime.now(_dt.timezone.utc)
            spec = vim.PerformanceManager.QuerySpec(entity=obj, metricId=[vim.PerformanceManager.MetricId(counterId=ids[k], instance="") for k in keys],
                                                    intervalId=interval, startTime=end - _dt.timedelta(hours=hours), endTime=end, format="normal")
            try:
                res = pm.QueryPerf(querySpec=[spec]) or []
            except Exception as e:  # noqa: BLE001
                return {"ts": [], "series": {}, "interval": interval, "error": f"QueryPerf: {type(e).__name__}"}
            rev = {ids[k]: k for k in keys}
            out: dict[str, list] = {}
            ts: list[float] = []
            for em in res:
                ts = [x.timestamp.timestamp() for x in (em.sampleInfo or [])]
                for ser in em.value or []:
                    k = rev.get(ser.id.counterId, "")
                    if k and (ser.id.instance or "") == "":
                        out[{"net.usage.average": "usage_bps", "net.received.average": "rx_bps", "net.transmitted.average": "tx_bps"}[k]] = \
                            [max(0.0, float(x)) * 8 * 1024 for x in (ser.value or [])]
            if ts:                                                # 시간 오름차순으로(vCenter 가 최신부터 줄 때도 있음)
                order = sorted(range(len(ts)), key=ts.__getitem__)
                ts = [ts[i] for i in order]
                out = {k: [v[i] for i in order if i < len(v)] for k, v in out.items()}
            return {"ts": ts, "series": out, "interval": interval, "error": "" if ts else "과거 통계 없음(vCenter 통계 수준·보관 기간 확인)"}

    # ------------------------------------------------------------------ 2.23.0 호스트·VM 성능 상세
    PERF_RANGES = {"rt": (20, 3600), "1d": (300, 86400), "7d": (1800, 7 * 86400), "30d": (7200, 30 * 86400)}

    def _perf_ids(self, pm) -> dict[str, int]:
        """카운터 이름 → ID (세션별 캐시 — 재연결·vCenter 교체·업그레이드 시 다시 읽음)"""
        c = getattr(self, "_perf_ids_cache", None)
        if not c or c[0] is not self.si:
            ids = {f"{x.groupInfo.key}.{x.nameInfo.key}.{x.rollupType}": x.key for x in pm.perfCounter}
            if not ids:
                return {}
            self._perf_ids_cache = c = (self.si, ids)
        return c[1]

    def perf_series(self, kind: str, moid: str, rng: str = "rt", vcpu: int = 1, labels: dict | None = None) -> dict[str, Any]:
        """호스트·VM 한 대의 CPU·메모리·디스크·네트워크 시계열 — rt=실시간 20초(1시간), 1d=5분, 7d=30분, 30d=2시간 간격.
        인스턴스(가상 디스크·장치·vNIC·vmnic)별 값 포함. 없는 카운터는 missing(과거 통계는 통계 수준에 따라 일부만). 읽기 전용(QueryPerf)."""
        from .. import perfcalc
        interval, span = self.PERF_RANGES.get(rng, self.PERF_RANGES["rt"])
        with self._lock:
            self._ensure()
            pm = self.si.content.perfManager
            ids = self._perf_ids(pm)
            keys = [k for k in (perfcalc.VM_COUNTERS if kind == "vm" else perfcalc.HOST_COUNTERS) if k in ids]
            if not keys:
                return {"ts": [], "series": {}, "instances": {}, "interval": interval, "missing": [], "error": "성능 카운터 없음"}
            obj = (vim.VirtualMachine if kind == "vm" else vim.HostSystem)(moid, self.si._stub)
            mids = [vim.PerformanceManager.MetricId(counterId=ids[k], instance="*") for k in keys]
            if interval == 20:
                spec = vim.PerformanceManager.QuerySpec(entity=obj, metricId=mids, intervalId=20, maxSample=span // 20, format="normal")
            else:
                end = datetime.now(timezone.utc)
                spec = vim.PerformanceManager.QuerySpec(entity=obj, metricId=mids, intervalId=interval, startTime=end - timedelta(seconds=span),
                                                        endTime=end, format="normal")
            try:
                res = pm.QueryPerf(querySpec=[spec]) or []
            except Exception as e:  # noqa: BLE001
                return {"ts": [], "series": {}, "instances": {}, "interval": interval, "missing": [], "error": f"QueryPerf: {type(e).__name__}: {str(e)[:120]}"}
            rev = {v: k for k, v in ids.items()}
            raw, ts = [], []
            for em in res:
                ts = [x.timestamp.timestamp() for x in (em.sampleInfo or [])]
                for ser in em.value or []:
                    raw.append((rev.get(ser.id.counterId, ""), ser.id.instance or "", list(ser.value or [])))
        out = perfcalc.build(raw, ts, interval, kind, vcpu, labels)
        out["error"] = "" if out["ts"] else ("실시간 통계 없음(전원·연결 상태 확인)" if interval == 20 else "과거 통계 없음(vCenter 통계 수준·보관 기간 확인)")
        return out

    def perf_latest(self, kind: str, items: list[tuple[str, str, int]], batch: int = 50, samples: int = 3) -> dict[str, dict]:
        """순위표 — 여러 호스트·VM 의 최근 실시간 표본(기본 3개 = 1분) 평균. items = [(이름, moid, vCPU)]. 읽기 전용(QueryPerf)."""
        from .. import perfcalc
        out: dict[str, dict] = {}
        self.perf_latest_errors = 0
        with self._lock:
            self._ensure()
            pm = self.si.content.perfManager
            ids = self._perf_ids(pm)
            keys = [k for k in perfcalc.LATEST_COUNTERS["vm" if kind == "vm" else "host"] if k in ids]
            if not keys:
                return out
            rev = {v: k for k, v in ids.items()}
            mids = [vim.PerformanceManager.MetricId(counterId=ids[k], instance="") for k in keys] + \
                   [vim.PerformanceManager.MetricId(counterId=ids[k], instance="*") for k in keys if "numberRead" in k or "numberWrite" in k]
        cls = vim.VirtualMachine if kind == "vm" else vim.HostSystem

        def run(chunk) -> list:
            with self._lock:                                     # 묶음마다 잠금 — 토폴로지·이벤트 수집이 오래 멈추지 않게
                self._ensure()
                specs = [vim.PerformanceManager.QuerySpec(entity=cls(m, self.si._stub), metricId=mids, intervalId=20, maxSample=samples, format="normal")
                         for _, m, _ in chunk]
                return self.si.content.perfManager.QueryPerf(querySpec=specs) or []

        for i in range(0, len(items), batch):
            chunk = items[i:i + batch]
            by = {m: (n, c) for n, m, c in chunk}
            try:
                res = run(chunk)
            except Exception:  # noqa: BLE001  (삭제된 VM 하나가 묶음 전체를 실패시킴 — 한 대씩 다시)
                res = []
                for one in chunk:
                    try:
                        res += run([one])
                    except Exception:  # noqa: BLE001
                        self.perf_latest_errors += 1
            for em in res:
                n, c = by.get(em.entity._moId, ("", 1))
                if not n:
                    continue
                raw = [(rev.get(ser.id.counterId, ""), ser.id.instance or "", list(ser.value or [])) for ser in em.value or []]
                out[n] = perfcalc.latest(raw, 20, kind, c)
        return out

    # ------------------------------------------------------------------ 라이선스(2.16.0 라이선스 관리)
    def collect_licenses(self) -> dict[str, Any]:
        """vCenter LicenseManager.licenses(키·제품·costUnit·총량·사용량·만료) + 호스트별 할당 키(LicenseAssignmentManager.QueryAssignedLicenses)
        + 호스트 CPU 소켓·코어. 모두 조회 API(읽기 전용) — 권한이 없으면 해당 부분만 비우고 error 에 이유를 남긴다."""
        with self._lock:
            self._ensure()
            content = self.si.content
            out: dict[str, Any] = {"vcenter": self.name, "version": getattr(content.about, "version", ""), "build": getattr(content.about, "build", ""),
                                   "licenses": [], "hosts": [], "error": ""}
            errs = []
            lm = content.licenseManager
            try:
                for lic in lm.licenses or []:
                    props = {p.key: p.value for p in (lic.properties or [])}
                    exp = props.get("expirationDate")
                    out["licenses"].append({"key": lic.licenseKey or "", "name": props.get("ProductName") or lic.name or "", "edition": lic.editionKey or "",
                                            "cost_unit": lic.costUnit or "", "total": int(lic.total or 0), "used": int(lic.used or 0),
                                            "expires": exp.date().isoformat() if hasattr(exp, "date") else (str(exp)[:10] if exp else None),
                                            "product_version": str(props.get("ProductVersion") or "")})
            except Exception as e:  # noqa: BLE001
                errs.append(f"라이선스 목록: {type(e).__name__}")
            lam = None
            try:
                lam = lm.licenseAssignmentManager
            except Exception as e:  # noqa: BLE001
                errs.append(f"할당 관리자: {type(e).__name__}")
            clusters = {n: x.get("cluster", "") for n, x in self.topology.get("hosts", {}).items()}
            try:
                rows = self._collect(vim.HostSystem, ["name", "hardware.cpuInfo.numCpuPackages", "hardware.cpuInfo.numCpuCores",
                                                      "config.product.version", "runtime.connectionState"])
            except Exception as e:  # noqa: BLE001
                rows = []
                errs.append(f"호스트: {type(e).__name__}")
            denied = 0
            for h, p in rows:
                key = name = cu = ""
                if lam is not None:
                    try:
                        a = lam.QueryAssignedLicenses(entityId=h._moId) or []
                        if a:
                            al = a[0].assignedLicense
                            key, name, cu = al.licenseKey or "", al.name or "", al.costUnit or ""
                    except Exception:  # noqa: BLE001
                        denied += 1
                hn = p.get("name", "")
                out["hosts"].append({"host": hn, "cluster": clusters.get(hn, ""), "sockets": int(p.get("hardware.cpuInfo.numCpuPackages") or 0),
                                     "cores": int(p.get("hardware.cpuInfo.numCpuCores") or 0), "license_key": key, "license_name": name, "cost_unit": cu,
                                     "version": str(p.get("config.product.version") or ""), "conn": str(p.get("runtime.connectionState") or "")})
            if denied:
                errs.append(f"호스트 할당 조회 실패 {denied}대")
            out["error"] = "; ".join(errs)
            return out

    # ------------------------------------------------------------------ 성능 SLI
    SLI_COUNTERS = {"cpu.ready.summation": "", "mem.latency.average": "",
                    "virtualDisk.totalReadLatency.average": "*", "virtualDisk.totalWriteLatency.average": "*",
                    "net.droppedRx.summation": "", "net.droppedTx.summation": ""}

    def _collect_sli(self) -> dict[str, Any]:
        """전원 켠 VM 의 실시간(20초) 카운터 최근 N개 → 신호별 백분위값 → 점수. 카운터가 없는 신호는 점수에서 제외."""
        c = self.sli_cfg
        with self._lock:
            self._ensure()
            pm = self.si.content.perfManager
            ids = {f"{x.groupInfo.key}.{x.nameInfo.key}.{x.rollupType}": x.key for x in pm.perfCounter}
            rev = {v: k for k, v in ids.items()}
            mids = [vim.PerformanceManager.MetricId(counterId=ids[k], instance=i) for k, i in self.SLI_COUNTERS.items() if k in ids]
            missing = [k for k in self.SLI_COUNTERS if k not in ids]
            vms = [(n, v) for n, v in self.topology.get("vms", {}).items() if v.get("power") == "poweredOn"][: c["max_vms"]]
            objs = {v._moId: v for v, p in self._collect(vim.VirtualMachine, ["name"])} if vms else {}
        series: dict[str, dict[str, list[list[float]]]] = {}
        for i in range(0, len(vms), c["batch"]):
            chunk = [(n, objs.get(v["moid"])) for n, v in vms[i:i + c["batch"]]]
            specs = [vim.PerformanceManager.QuerySpec(entity=o, metricId=mids, intervalId=20,
                                                      maxSample=c["samples"], format="normal") for _, o in chunk if o]
            if not specs:
                continue
            names = {o._moId: n for n, o in chunk if o}
            with self._lock:                                     # 묶음마다 잠금(2.30.0) — VM 수천 대 수집 중에도 이벤트 읽기가 끼어들 수 있게
                res = pm.QueryPerf(querySpec=specs) or []
            for em in res:
                vn = names.get(em.entity._moId)
                if not vn:
                    continue
                d = series.setdefault(vn, {})
                for ser in em.value or []:
                    d.setdefault(rev.get(ser.id.counterId, ""), []).append([float(x) for x in ser.value])
        out_vms: dict[str, dict] = {}
        p = c["percentile"]
        for vn, d in series.items():
            meta = self.topology["vms"].get(vn, {})
            ncpu = max(1, int(meta.get("vcpu") or 1))

            def col(key: str, agg=max) -> list[float]:
                rows = d.get(key) or []
                if not rows:
                    return []
                n = min(len(r) for r in rows)
                return [agg([r[j] for r in rows if r[j] >= 0] or [-1]) for j in range(n)]
            rd = {}
            ready = col("cpu.ready.summation", sum)
            rd["cpu_ready"] = SLI.percentile([x / (20000.0 * ncpu) * 100 for x in ready if x >= 0], p) if ready else None
            ml = col("mem.latency.average")
            rd["mem_latency"] = SLI.percentile([x / 100.0 for x in ml if x >= 0], p) if ml else None   # 백분율 카운터 = 1/100 %
            lat = [x for x in (col("virtualDisk.totalReadLatency.average") + col("virtualDisk.totalWriteLatency.average")) if x >= 0]
            rd["disk_latency"] = SLI.percentile(lat, p) if lat else None                           # 디스크·읽기/쓰기 중 최악
            rx, tx = col("net.droppedRx.summation", sum), col("net.droppedTx.summation", sum)
            drops = [max(0, a) + max(0, b) for a, b in zip(rx, tx)] if rx and tx else [x for x in (rx or tx) if x >= 0]
            rd["net_dropped"] = SLI.percentile(drops, p) if drops else None
            out_vms[vn] = SLI.vm_result(vn, rd, c["thresholds"], c["drop_budget"], host=meta.get("host", ""),
                                        cluster=meta.get("cluster", ""), vcpu=ncpu)
        clusters: dict[str, dict] = {}
        for cn, cl in self.topology.get("clusters", {}).items():
            mine = [v for v in out_vms.values() if (v.get("cluster") or "(standalone)") == cn]
            hosts = [{**self.topology["hosts"].get(h, {}), "name": h,
                      "connected": self.topology["hosts"].get(h, {}).get("conn") == "connected"} for h in cl.get("hosts", [])]
            tol = max(1, int(cl.get("ha_failover_level") or c["failover_hosts"]))
            fo = SLI.failover(hosts, tol) if cl.get("moid") else {"tolerate": 0, "hosts": len(hosts), "verdict": "standalone",
                                                                 "detail": "클러스터가 아닌 단독 호스트"}
            clusters[cn] = {**SLI.cluster_kpi(mine), "failover": fo,
                            "ha": cl.get("ha", False), "ha_admission": cl.get("ha_admission", False)}
        return {"updated": time.time(), "vms": out_vms, "clusters": clusters, "error": "",
                "missing_counters": missing, "vcenter": self.host, "window_s": c["samples"] * 20,
                "thresholds": c["thresholds"], "percentile": p}

    def _sli_events(self, res: dict[str, Any], first: bool) -> list[LogEvent]:
        """밴드 변화만 이벤트로(기준 밴드 이하 진입 → warning/error, 회복 → info). 폭주 시 요약 1건."""
        order = ["green", "yellow", "orange", "red"]
        lim = order.index(self.sli_cfg["alert_band"]) if self.sli_cfg["alert_band"] in order else 2
        out: list[LogEvent] = []
        extra = 0
        th, un = self.sli_cfg["thresholds"], SLI.UNIT
        items = [("vm", n, v) for n, v in res["vms"].items()] + [("cluster", n, v) for n, v in res["clusters"].items()]
        for kind, name, r in items:
            b = r.get("band", "none")
            if b == "none":
                continue
            key = f"{kind}:{name}"
            prev = self._sli_band.get(key)
            self._sli_band[key] = b
            bad, was_bad = order.index(b) >= lim, prev in order and order.index(prev) >= lim
            if bad == was_bad or (first and not bad) or prev == b:
                continue
            if len(out) >= self.sli_cfg["max_events"]:
                extra += 1
                continue
            if kind == "vm":
                s = r["worst"]
                sig = r["signals"][s]
                detail = (f"{SLI.LABEL[s]} {sig['value']}{un[s]} (기준 {th[s]}{un[s]}) · 점수 {r['score']}"
                          f" · 호스트 {r.get('host', '')}")
            else:
                detail = (f"클러스터 KPI {r['score']} · VM {r['vms']}대 중 빨강 {r['bands']['red']} · 주황 {r['bands']['orange']}"
                          f" · 노랑 {r['bands']['yellow']}")
            if bad:
                sev = "error" if b == "red" else "warning"
                msg = f"성능 SLI 위반({b}): {'VM' if kind == 'vm' else '클러스터'} {name} — {detail}"
            else:
                sev = "info"
                msg = f"성능 SLI 회복({b}): {'VM' if kind == 'vm' else '클러스터'} {name} — {detail}"
            out.append(self.ev(msg, severity=sev, kind="health", entity=f"sli:{kind}:{name}",
                               host=(r.get("host") if kind == "vm" else "") or self.host,
                               attrs={"sli": {"kind": kind, "name": name, "band": b, "score": r.get("score")}}))
        if extra:
            out.append(self.ev(f"성능 SLI: 밴드가 바뀐 대상 {extra}건 추가(화면 › 성능 SLI)", severity="warning",
                               kind="health", entity="sli:summary"))
        return out

    def sli_snapshot(self) -> dict[str, Any]:
        return self.sli

    # ------------------------------------------------------------------ 인프라 상세 점검
    async def run_health(self) -> list[LogEvent]:
        first = not self.health.get("updated")
        try:
            snap = await self._tx("health", self._collect_health)
            snap["hcl"] = await self._vlcm_reports(snap.get("cluster_moids", {}))
            snap["bmc"] = self._bmc_map(snap)
            if time.time() - self._last_bpvm > self.health_cfg["bp_vm_interval"] or not self._bp_vms:
                try:
                    self._bp_vms = await self._tx("health", self._collect_bp_vms)
                    self._last_bpvm = time.time()
                except Exception as e:  # noqa: BLE001  — 권장 구성 판독용 VM 장치 정보(없으면 VM 규칙만 '판단 불가')
                    self._bp_vms = {"error": f"{type(e).__name__}: {e}"[:200], "vms": []}
            snap["bp_vms"] = self._bp_vms
            res = vcheck.evaluate(snap, self.health_cfg["thresholds"])
            self.health_snap = snap
            self.health = {**res, "updated": time.time(), "error": "", "hw": vcheck.hw_table(snap),
                           "vcenter": self.host, "vibs_at": self._last_vib, "duration_s": snap.get("duration_s")}
            self._state["checks"].pop("인프라 점검", None)
            return self._health_events(res["findings"], first)
        except Exception as e:  # noqa: BLE001
            self.health = {**self.health, "error": f"{type(e).__name__}: {e}"[:300]}
            self._state["checks"]["인프라 점검"] = f"실패: {type(e).__name__}: {e}"[:150]
            return []

    def _bmc_map(self, snap: dict[str, Any]) -> dict[str, Any]:
        try:
            raw = self.bmc_provider() if self.bmc_provider else {}
        except Exception:  # noqa: BLE001
            raw = {}
        out = {}
        for hn in snap.get("hosts", {}):
            short = hn.split(".")[0].lower()
            for k, v in raw.items():
                if k.lower() == hn.lower() or k.split(".")[0].lower() == short:
                    out[hn] = v
                    break
        return out

    async def _vlcm_reports(self, moids: dict[str, str]) -> dict[str, Any]:
        """vLCM 이미지 관리 클러스터의 하드웨어 호환성 보고서(있을 때만, 읽기 전용 GET). 없거나 권한 없으면 조용히 생략"""
        out: dict[str, Any] = {}
        if not self.rest_token:
            return out
        for cn, moid in list(moids.items())[:50]:
            try:
                r = await self.http.get(f"/api/esx/settings/clusters/{moid}/software/reports/hardware-compatibility")
                if r.status_code >= 300:
                    continue
                j = r.json() or {}
                st = j.get("v_sphere_compatibility_status") or j.get("status") or (j.get("hcl_status") or {}).get("status", "")
                if st:
                    out[cn] = {"status": str(st), "detail": str(j.get("notifications") or "")[:300]}
            except Exception:  # noqa: BLE001
                continue
        return out

    def _health_events(self, items: list[dict], first: bool) -> list[LogEvent]:
        out: list[LogEvent] = []
        cur = {f"{x['id']}|{x['entity']}|{x['title'].split(' (')[0]}": x for x in items if x["severity"] != "info"}
        keys = {k: x["severity"] for k, x in cur.items()}
        new = [x for k, x in cur.items() if self._health_seen.get(k) != x["severity"]]
        new.sort(key=lambda x: -vcheck.SEV_ORDER.index(x["severity"]))
        cap = self.health_cfg["max_events"]
        for x in new[:cap]:
            out.append(self.ev(f"[인프라 점검 {x['id']}] {x['entity']}: {x['title']}" + (f" — {x['detail'][:200]}" if x["detail"] else ""),
                               severity=x["severity"], kind="health", entity=x["entity"],
                               host=x["entity"] if x["entity"] in self.topology.get("hosts", {}) else self.host,
                               attrs={"check": x["id"], "area": x["area"], "fix": x["fix"], "first": first}))
        if len(new) > cap:
            out.append(self.ev(f"[인프라 점검] 신규·변경 {len(new)}건 중 {cap}건만 이벤트로 보냄 — 인프라 점검 화면에서 전체 확인",
                               severity="info", kind="health", entity="vcenter-health"))
        for k in [k for k in self._health_seen if k not in keys]:
            if not first:
                cid, ent = k.split("|")[:2]
                out.append(self.ev(f"[인프라 점검 {cid}] {ent}: 해소", severity="info", kind="health", entity=ent, attrs={"check": cid, "resolved": True}))
        self._health_seen = keys
        return out

    def collect_certs(self) -> list[dict[str, Any]]:
        """2.36.0 인증서 달력 — ESXi 호스트 인증서(HostCertificateManager.certificateInfo, System.Read). 호스트마다 한 번 조회"""
        with self._lock:
            self._ensure()
            cl = {c._moId: p.get("name", "") for c, p in self._collect(vim.ComputeResource, ["name"])}
            out = []
            for h, p in self._collect_tolerant(vim.HostSystem, ["name", "parent", "runtime.connectionState", "configManager.certificateManager"]):
                name = p.get("name", "")
                if str(p.get("runtime.connectionState", "")) != "connected":
                    continue
                m = p.get("configManager.certificateManager")
                if m is None:
                    continue
                try:
                    ci = m.certificateInfo
                except Exception as e:  # noqa: BLE001
                    out.append({"host": name, "error": type(e).__name__})
                    continue
                na = getattr(ci, "notAfter", None)
                out.append({"host": name, "not_after": na.timestamp() if hasattr(na, "timestamp") else None, "subject": str(getattr(ci, "subject", "") or ""),
                            "issuer": str(getattr(ci, "issuer", "") or ""), "status": str(getattr(ci, "status", "") or ""),
                            "cluster": cl.get(getattr(p.get("parent"), "_moId", ""), "")})
            return out

    def _collect_health(self) -> dict[str, Any]:
        t0 = time.time()
        g = lambda o, path, d=None: _dig(o, path, d)  # noqa: E731
        with self._lock:
            self._ensure()
            cl_names, cl_moids, cl = {}, {}, {}
            for c, p in self._collect(vim.ClusterComputeResource, ["name", "configurationEx", "summary"]):
                cx = p.get("configurationEx")
                das, drs = getattr(cx, "dasConfig", None), getattr(cx, "drsConfig", None)
                n = p.get("name", "")
                cl_names[c._moId], cl_moids[n] = n, c._moId
                acp = getattr(das, "admissionControlPolicy", None)
                vsc = getattr(cx, "vsanConfigInfo", None)
                cl[n] = {"ha": bool(getattr(das, "enabled", False)), "ha_admission": bool(getattr(das, "admissionControlEnabled", False)),
                         "drs": bool(getattr(drs, "enabled", False)), "drs_behavior": str(getattr(drs, "defaultVmBehavior", "") or ""),
                         "vsan": bool(getattr(vsc, "enabled", False)),
                         "evc": str(getattr(p.get("summary"), "currentEVCModeKey", "") or ""),
                         # 2.28.0 권장 구성 판독용
                         "ha_host_monitoring": str(getattr(das, "hostMonitoring", "") or ""), "ha_vm_monitoring": str(getattr(das, "vmMonitoring", "") or ""),
                         "ha_isolation": str(_dig(das, "defaultVmSettings.isolationResponse", "") or ""),
                         "ha_policy": type(acp).__name__ if acp is not None else "",
                         "ha_failover_level": int(getattr(acp, "failoverLevel", 0) or 0),
                         "ha_cpu_pct": int(getattr(acp, "cpuFailoverResourcesPercent", 0) or 0),
                         "ha_mem_pct": int(getattr(acp, "memoryFailoverResourcesPercent", 0) or 0),
                         "drs_rate": int(getattr(drs, "vmotionRate", 0) or 0),
                         "vsan_esa": bool(getattr(vsc, "vsanEsaEnabled", False))}
            vcpus: dict[str, int] = defaultdict(int)
            vms = []
            now = time.time()
            for v, p in self._collect(vim.VirtualMachine, ["name", "runtime.host", "runtime.powerState", "config.hardware.numCPU",
                                                           "config.template", "snapshot", "runtime.consolidationNeeded"]):
                if p.get("config.template"):
                    continue
                if str(p.get("runtime.powerState")) == "poweredOn" and p.get("runtime.host") is not None:
                    vcpus[p["runtime.host"]._moId] += int(p.get("config.hardware.numCPU") or 1)
                snaps = []
                tree = list(getattr(p.get("snapshot"), "rootSnapshotList", None) or [])
                while tree:
                    sn = tree.pop()
                    ct = getattr(sn, "createTime", None)
                    snaps.append({"name": str(getattr(sn, "name", "")), "created": ct.timestamp() if hasattr(ct, "timestamp") else now})
                    tree.extend(getattr(sn, "childSnapshotList", None) or [])
                if snaps or p.get("runtime.consolidationNeeded"):
                    vms.append({"name": p.get("name", ""), "snapshots": snaps, "consolidation": bool(p.get("runtime.consolidationNeeded"))})
            props = ["name", "parent", "runtime.connectionState", "runtime.inMaintenanceMode", "runtime.bootTime",
                     "summary.hardware", "summary.quickStats.overallMemoryUsage", "hardware.systemInfo", "hardware.biosInfo",
                     "hardware.pciDevice", "config.product", "config.network", "config.virtualNicManagerInfo.netConfig",
                     "config.storageDevice", "config.dateTimeInfo", "config.service", "config.lockdownMode",
                     "config.hyperThread", "runtime.healthSystemRuntime", "configIssue", "configManager.imageConfigManager",
                     "config.powerSystemInfo", "hardware.numaInfo.numNodes"]
            hosts: dict[str, Any] = {}
            img: dict[str, Any] = {}
            for h, p in self._collect_tolerant(vim.HostSystem, props):
                hn = p.get("name", "")
                hw = p.get("summary.hardware")
                si, bi = p.get("hardware.systemInfo"), p.get("hardware.biosInfo")
                prod = p.get("config.product")
                serial = str(getattr(si, "serialNumber", "") or "") or next(
                    (str(x.identifierValue) for x in (getattr(si, "otherIdentifyingInfo", None) or [])
                     if str(g(x, "identifierType.key", "")) in ("SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag")), "")
                pci = {d.id: f"{d.vendorName} {d.deviceName}".strip() for d in (p.get("hardware.pciDevice") or [])}
                net = p.get("config.network")
                vibs = self._vibs.get(hn, {})
                nics = []
                for n in (getattr(net, "pnic", None) or []):
                    ls = getattr(n, "linkSpeed", None)
                    nics.append({"key": n.key, "device": n.device, "driver": str(n.driver or ""), "mac": str(getattr(n, "mac", "") or ""),
                                 "speed": int(ls.speedMb) if ls else 0, "duplex": bool(ls.duplex) if ls else None,
                                 "driver_version": driver_version(n.driver, getattr(n, "driverVersion", "") or "", vibs),
                                 "firmware": str(getattr(n, "firmwareVersion", "") or ""), "pci_name": pci.get(n.pci, ""), "pci": n.pci})
                key2dev = {n["key"]: n["device"] for n in nics}
                pg2sw = {pg.spec.name: pg.spec.vswitchName for pg in (getattr(net, "portgroup", None) or [])}
                pg2vlan = {pg.spec.name: getattr(pg.spec, "vlanId", None) for pg in (getattr(net, "portgroup", None) or [])}   # 2.43.0 VMkernel VLAN(망 분리 점검)
                sws = [{"name": sw.name, "kind": "std", "mtu": int(sw.mtu or 1500), "uplinks": [key2dev.get(k, k) for k in (sw.pnic or [])]}
                       for sw in (getattr(net, "vswitch", None) or [])]
                uuid2sw = {}
                for ps in (getattr(net, "proxySwitch", None) or []):
                    uuid2sw[ps.dvsUuid] = ps.dvsName
                    sws.append({"name": ps.dvsName, "kind": "dvs", "mtu": int(getattr(ps, "mtu", 0) or 1500), "uplinks": [key2dev.get(k, k) for k in (ps.pnic or [])]})
                svc_by_vmk: dict[str, list[str]] = defaultdict(list)
                for nc in (p.get("config.virtualNicManagerInfo.netConfig") or []):
                    keys = set(nc.selectedVnic or [])
                    for vn in (nc.candidateVnic or []):
                        if vn.key in keys:
                            svc_by_vmk[vn.device].append(str(nc.nicType))
                vmks = []
                for vn in (getattr(net, "vnic", None) or []):
                    dvp = g(vn, "spec.distributedVirtualPort")
                    sw = uuid2sw.get(getattr(dvp, "switchUuid", ""), "") if dvp else pg2sw.get(vn.portgroup, "")
                    vmks.append({"device": vn.device, "mtu": int(g(vn, "spec.mtu", 1500) or 1500), "switch": sw, "services": svc_by_vmk.get(vn.device, []),
                                 "pg": str(vn.portgroup or ""), "pg_key": str(getattr(dvp, "portgroupKey", "") or "") if dvp else "",
                                 "vlan": pg2vlan.get(vn.portgroup) if not dvp else None})
                sd = p.get("config.storageDevice")
                hbas = [{"device": a.device, "model": str(a.model or ""), "driver": str(a.driver or ""), "status": str(a.status or ""),
                         "protocol": str(getattr(a, "storageProtocol", "") or ""),
                         "driver_version": driver_version(a.driver, getattr(a, "driverVersion", "") or "", vibs),
                         "firmware": str(getattr(a, "firmwareVersion", "") or "")} for a in (getattr(sd, "hostBusAdapter", None) or [])]
                luns = {l.key: l for l in (getattr(sd, "scsiLun", None) or [])}
                lunv = self.__dict__.setdefault("_lunv", {})            # 2.41.0 LUN → 어레이 제조사·모델(외부 스토리지 묶기, 읽기 전용)
                for l in luns.values():
                    cn = str(getattr(l, "canonicalName", "") or "")
                    if cn and not getattr(l, "localDisk", False):
                        lunv[cn] = f"{str(getattr(l, 'vendor', '') or '').strip()} {str(getattr(l, 'model', '') or '').strip()}".strip()
                dead, dead_luns, single = 0, [], []
                for ml in (g(sd, "multipathInfo.lun") or []):
                    paths = list(ml.path or [])
                    lun = luns.get(ml.lun)
                    nm = str(getattr(lun, "canonicalName", "") or ml.id)
                    d = sum(1 for x in paths if str(getattr(x, "state", getattr(x, "pathState", ""))).lower() == "dead")
                    if d:
                        dead += d
                        dead_luns.append(nm)
                    if len(paths) == 1 and lun is not None and getattr(lun, "lunType", "") == "disk" and not getattr(lun, "localDisk", True):
                        single.append(nm)
                sens, hws = [], []
                hsr = p.get("runtime.healthSystemRuntime")
                for s in (g(hsr, "systemHealthInfo.numericSensorInfo") or []):
                    rd = s.currentReading * (10 ** (s.unitModifier or 0)) if s.currentReading is not None else ""
                    sens.append({"name": s.name, "type": str(s.sensorType or ""), "state": str(g(s, "healthState.key", "")),
                                 "reading": f"{rd:g} {s.baseUnits or ''}".strip() if rd != "" else ""})
                for kind, lst in (("CPU", g(hsr, "hardwareStatusInfo.cpuStatusInfo")), ("메모리", g(hsr, "hardwareStatusInfo.memoryStatusInfo")),
                                  ("스토리지", g(hsr, "hardwareStatusInfo.storageStatusInfo"))):
                    for s in (lst or []):
                        hws.append({"kind": kind, "name": s.name, "state": str(g(s, "status.key", ""))})
                svc = {str(x.key): bool(x.running) for x in (g(p.get("config.service"), "service") or [])}
                ht = p.get("config.hyperThread")
                bt = p.get("runtime.bootTime")
                par = p.get("parent")
                hosts[hn] = {
                    "cluster": cl_names.get(par._moId, "") if par is not None else "",
                    "conn": str(p.get("runtime.connectionState", "")), "maintenance": bool(p.get("runtime.inMaintenanceMode")),
                    "vendor": str(getattr(hw, "vendor", "") or ""), "model": str(getattr(hw, "model", "") or ""), "serial": serial,
                    "cpu_model": str(getattr(hw, "cpuModel", "") or ""), "cores": int(getattr(hw, "numCpuCores", 0) or 0),
                    "sockets": int(getattr(hw, "numCpuPkgs", 0) or 0),
                    "threads": int(getattr(hw, "numCpuThreads", 0) or 0),
                    "mem_mb": round((getattr(hw, "memorySize", 0) or 0) / 2**20), "mem_used_mb": p.get("summary.quickStats.overallMemoryUsage") or 0,
                    "bios": str(getattr(bi, "biosVersion", "") or ""),
                    "bios_date": bi.releaseDate.strftime("%Y-%m-%d") if getattr(bi, "releaseDate", None) else "",
                    "version": str(getattr(prod, "version", "") or ""), "build": str(getattr(prod, "build", "") or ""),
                    "ntp_servers": list(g(p.get("config.dateTimeInfo"), "ntpConfig.server") or []),
                    "services": {"ntpd": svc.get("ntpd"), "TSM-SSH": svc.get("TSM-SSH"), "TSM": svc.get("TSM")},
                    "lockdown": str(p.get("config.lockdownMode") or ""),
                    "ht_available": bool(getattr(ht, "available", False)), "ht_active": bool(getattr(ht, "active", False)) if ht else None,
                    "boot_time": bt.timestamp() if hasattr(bt, "timestamp") else 0,
                    "power_policy": str(_dig(p.get("config.powerSystemInfo"), "currentPolicy.shortName", "") or ""),
                    "numa_nodes": int(p.get("hardware.numaInfo.numNodes") or 0),
                    "config_issues": [str(getattr(x, "fullFormattedMessage", "") or type(x).__name__) for x in (p.get("configIssue") or [])],
                    "vcpus": vcpus.get(h._moId, 0), "nics": nics, "vswitches": sws, "vmks": vmks, "hbas": hbas,
                    "paths": {"dead": dead, "dead_luns": dead_luns, "single": single}, "sensors": sens, "hw_status": hws}
                if p.get("configManager.imageConfigManager") is not None and hosts[hn]["conn"] == "connected":
                    img[hn] = p["configManager.imageConfigManager"]
            dss = {}
            for d, p in self._collect(vim.Datastore, ["name", "summary", "host"]):
                sm = p.get("summary")
                hl = [m.key for m in (p.get("host") or [])]
                dss[p.get("name", "")] = {"capacity": getattr(sm, "capacity", 0) or 0, "free": getattr(sm, "freeSpace", 0) or 0,
                                          "uncommitted": getattr(sm, "uncommitted", 0) or 0, "accessible": getattr(sm, "accessible", None),
                                          "type": str(getattr(sm, "type", "") or ""), "maintenance": str(getattr(sm, "maintenanceMode", "") or ""),
                                          "hosts": [x.name for x in hl if hasattr(x, "name")], "local": len(hl) == 1}
        # 드라이버 버전 보완(VIB) — 8.0U1 미만은 PhysicalNic.driverVersion 이 없으므로 FetchSoftwarePackages
        if time.time() - self._last_vib > self.health_cfg["vib_interval"] and img:
            need = [hn for hn, h in hosts.items() if any(n["driver"] and not n["driver_version"] for n in h["nics"] + h["hbas"])]
            for hn in need[: self.health_cfg["max_vib_hosts"]]:
                try:
                    with self._lock:
                        pk = img[hn].FetchSoftwarePackages()
                    self._vibs[hn] = {str(x.name): str(x.version) for x in (pk or [])}
                except Exception:  # noqa: BLE001  — 권한·버전 미지원
                    self._vibs.setdefault(hn, {})
            self._last_vib = time.time()
            for hn in need:
                for n in hosts[hn]["nics"] + hosts[hn]["hbas"]:
                    if not n["driver_version"]:
                        n["driver_version"] = driver_version(n["driver"], "", self._vibs.get(hn, {}))
        return {"hosts": hosts, "clusters": cl, "datastores": dss, "vms": vms, "cluster_moids": cl_moids,
                "duration_s": round(time.time() - t0, 1)}

    async def collect_backup(self) -> list[LogEvent]:
        """vCenter 파일 기반 백업(VAMI) — GET /api/appliance/recovery/backup/schedules · /job/details. 권한이 없으면 '조회 불가'만 표시."""
        from .. import protection as PR
        now = time.time()
        try:
            rs = await self.http.get("/api/appliance/recovery/backup/schedules")
            rj = await self.http.get("/api/appliance/recovery/backup/job/details")
            if rs.status_code in (401, 403) or rj.status_code in (401, 403):
                raise PermissionError(f"HTTP {rs.status_code}/{rj.status_code} — 백업 정보 조회 권한 없음(어플라이언스 백업 조회는 SSO 관리자 그룹 필요할 수 있음)")
            rs.raise_for_status()
            rj.raise_for_status()
            self.protection = {**PR.vcenter_backup(rs.json(), rj.json(), now), "target": self.host}
        except Exception as e:  # noqa: BLE001
            self.protection = {"kind": "appliance_backup", "product": "vCenter", "target": self.host, "updated": now,
                               "error": f"조회 불가: {type(e).__name__}: {e}"[:200]}
            return []
        v, why = PR.appliance_verdict(self.protection, now)
        key = f"bkp:{v}:{(self.protection.get('last') or {}).get('end')}"
        if v == "bad" and self.seen.is_new(key):
            return [self.ev(f"vCenter 파일 기반 백업 문제 — {why}", severity="error", kind="health", entity=f"backup:vcenter:{self.host}")]
        return []

    def _collect_bp_vms(self) -> dict[str, Any]:
        """권장 구성 판독(2.28.0)용 VM 요약 — vNIC 종류·연결된 CD/DVD·Tools·vCPU·스냅숏(읽기 전용, 장치 목록은 요약만 보관)"""
        now = time.time()
        out = []
        with self._lock:
            self._ensure()
            hosts = {h._moId: p.get("name", "") for h, p in self._collect(vim.HostSystem, ["name"])}
            rows = self._collect_tolerant(vim.VirtualMachine, ["name", "runtime.host", "runtime.powerState", "config.template", "config.hardware.numCPU",
                                                               "config.hardware.memoryMB", "config.hardware.device", "guest.toolsRunningStatus",
                                                               "guest.toolsVersionStatus2", "snapshot", "config.version", "customValue", "config.annotation"])
            fields = {}
            try:                                    # 2.29.0 백업 SW 가 남긴 사용자 정의 속성(예: NB_LAST_BACKUP, Last Backup)
                for f in (self.si.content.customFieldsManager.field or []):
                    fields[f.key] = str(f.name)
            except Exception:  # noqa: BLE001
                fields = {}
        from ..protection import BACKUP_FIELD_RX
        for v, p in rows:
            if p.get("config.template"):
                continue
            nics, cd, ctrls = [], 0, []
            pt = usb = 0                                    # 2.38.0 AI 체크봇 — vMotion·HA 재시작을 막는 장치(PCI 패스스루·vGPU·USB)
            for d in (p.get("config.hardware.device") or []):
                cn = type(d).__name__
                if isinstance(d, vim.vm.device.VirtualPCIPassthrough):
                    pt += 1
                elif isinstance(d, vim.vm.device.VirtualUSB):
                    usb += 1
                if isinstance(d, vim.vm.device.VirtualEthernetCard):
                    nics.append(cn.replace("vim.vm.device.", "").replace("Virtual", ""))
                elif isinstance(d, vim.vm.device.VirtualCdrom) and bool(_dig(d, "connectable.connected", False)):
                    cd += 1
                elif isinstance(d, vim.vm.device.VirtualSCSIController):
                    ctrls.append(cn.replace("vim.vm.device.", "").replace("Virtual", ""))
            snaps = []
            tree = list(getattr(p.get("snapshot"), "rootSnapshotList", None) or [])
            while tree:
                sn = tree.pop()
                ct = getattr(sn, "createTime", None)
                snaps.append(ct.timestamp() if hasattr(ct, "timestamp") else now)
                tree.extend(getattr(sn, "childSnapshotList", None) or [])
            h = p.get("runtime.host")
            out.append({"name": p.get("name", ""), "host": hosts.get(h._moId, "") if h is not None else "", "power": str(p.get("runtime.powerState") or ""),
                        "vcpu": int(p.get("config.hardware.numCPU") or 0), "mem_mb": int(p.get("config.hardware.memoryMB") or 0),
                        "nics": nics, "cdrom_connected": cd, "scsi": ctrls, "passthru": pt, "usb": usb, "tools": str(p.get("guest.toolsRunningStatus") or ""),
                        "tools_version": str(p.get("guest.toolsVersionStatus2") or ""), "hw_version": str(p.get("config.version") or ""),
                        "snapshots": len(snaps), "snap_oldest": min(snaps) if snaps else None,
                        "backup_fields": {fields[cv.key]: str(getattr(cv, "value", "") or "")[:200] for cv in (p.get("customValue") or [])
                                          if fields.get(getattr(cv, "key", None)) and BACKUP_FIELD_RX.search(fields[cv.key]) and getattr(cv, "value", "")},
                        "notes_backup": next((ln.strip()[:200] for ln in str(p.get("config.annotation") or "").splitlines()
                                              if BACKUP_FIELD_RX.search(ln)), "")})
        return {"vms": out, "collected": now, "error": ""}

    def _collect_tolerant(self, vimtype, props: list[str]) -> list[tuple[Any, dict]]:
        """구버전 vCenter 에 없는 속성 경로는 InvalidProperty → 하나씩 빼며 재시도"""
        props = list(props)
        for _ in range(len(props)):
            try:
                return self._collect(vimtype, props)
            except vmodl.query.InvalidProperty as e:
                bad = str(getattr(e, "name", "") or "")
                if bad not in props:
                    raise
                props.remove(bad)
        return self._collect(vimtype, props)

    # ------------------------------------------------------------------ 보안 판독(하드닝·KISA) — 읽기 전용(System.Read)
    ASSESS_HOST_KEYS = ("UserVars.ESXiShellInteractiveTimeOut", "UserVars.ESXiShellTimeOut", "UserVars.DcuiTimeOut", "UserVars.HostClientSessionTimeout",
                        "Security.AccountLockFailures", "Security.AccountUnlockTime", "Security.PasswordQualityControl", "Security.PasswordHistory",
                        "Security.PasswordMaxDays", "Syslog.global.logHost", "Syslog.global.logDir", "Config.HostAgent.plugins.solo.enableMob",
                        "Net.BlockGuestBPDU", "Net.DVFilterBindIpAddress", "Mem.ShareForceSalting", "UserVars.SuppressShellWarning",
                        "UserVars.SuppressHyperthreadWarning", "Config.HostAgent.log.level", "VMkernel.Boot.execInstalledOnly",
                        "Annotations.WelcomeMessage", "Config.Etc.issue", "DCUI.Access", "UserVars.ESXiVPsDisabledProtocols")
    ASSESS_VM_KEYS = ("isolation.tools.copy.disable", "isolation.tools.paste.disable", "isolation.tools.diskShrink.disable",
                      "isolation.tools.diskWiper.disable", "isolation.device.connectable.disable", "RemoteDisplay.maxConnections",
                      "tools.setInfo.sizeLimit", "log.keepOld", "log.rotateSize", "mks.enable3d", "tools.guest.desktop.autolock")

    def assess_collect(self, max_vms: int = 500) -> dict[str, Any]:
        """호스트 고급 설정·서비스·방화벽·잠금 모드·NTP·vSwitch 보안 정책, VM 고급 설정(표본), 분산 포트그룹 보안 정책, vCenter 버전.
        모두 속성 읽기·QueryOptions(System.Read) — 읽기 전용 역할로 수집된다. 호스트 로컬 계정 목록은 vCenter 경유로 볼 수 없어 수동 확인 대상."""
        out: dict[str, Any] = {"vcenter": {**(getattr(self, "about", {}) or {}), "host": self.host, "name": self.name}, "hosts": [], "vms": [], "dvpg": [], "errors": []}
        with self._lock:
            self._ensure()
            want = set(self.ASSESS_HOST_KEYS)
            for h, p in self._collect_tolerant(vim.HostSystem, ["name", "config.product.version", "config.product.build", "config.product.fullName",
                                                                 "runtime.connectionState", "config.lockdownMode", "config.dateTimeInfo",
                                                                 "config.network.vswitch", "configManager.advancedOption",
                                                                 "configManager.serviceSystem", "configManager.firewallSystem", "parent"]):
                hn = p.get("name", "")
                row: dict[str, Any] = {"name": hn, "version": str(p.get("config.product.version") or ""), "build": str(p.get("config.product.build") or ""),
                                       "product": str(p.get("config.product.fullName") or ""), "conn": str(p.get("runtime.connectionState") or ""),
                                       "lockdown": str(p.get("config.lockdownMode") or ""), "adv": {}, "services": {}, "firewall": {}, "ntp": [], "vswitch": []}
                if row["conn"] != "connected":
                    out["hosts"].append(row)
                    continue
                dt = p.get("config.dateTimeInfo")
                row["ntp"] = list(getattr(getattr(dt, "ntpConfig", None), "server", None) or [])
                for vs in p.get("config.network.vswitch") or []:
                    sec = getattr(getattr(getattr(vs, "spec", None), "policy", None), "security", None)
                    row["vswitch"].append({"name": vs.name, "promiscuous": getattr(sec, "allowPromiscuous", None),
                                           "mac_changes": getattr(sec, "macChanges", None), "forged": getattr(sec, "forgedTransmits", None)})
                try:
                    om = p.get("configManager.advancedOption")
                    for o in (om.QueryOptions() if om is not None else []) or []:
                        if o.key in want:
                            row["adv"][o.key] = o.value if isinstance(o.value, (str, int, float, bool)) else str(o.value)
                except Exception as e:  # noqa: BLE001
                    row["adv_error"] = f"{type(e).__name__}"
                    for k in want:                                     # 일부 키만 허용되는 구버전 — 키별 조회
                        try:
                            v = om.QueryOptions(k)
                            if v:
                                row["adv"][k] = v[0].value if isinstance(v[0].value, (str, int, float, bool)) else str(v[0].value)
                        except Exception:  # noqa: BLE001
                            pass
                try:
                    ss = p.get("configManager.serviceSystem")
                    for sv in getattr(getattr(ss, "serviceInfo", None), "service", None) or []:
                        row["services"][sv.key] = {"running": bool(sv.running), "policy": str(sv.policy or ""), "label": str(sv.label or "")}
                except Exception as e:  # noqa: BLE001
                    row["svc_error"] = f"{type(e).__name__}"
                try:
                    fw = getattr(p.get("configManager.firewallSystem"), "firewallInfo", None)
                    dp = getattr(fw, "defaultPolicy", None)
                    row["firewall"] = {"incoming_blocked": getattr(dp, "incomingBlocked", None), "outgoing_blocked": getattr(dp, "outgoingBlocked", None),
                                       "open_all": sorted(rs.key for rs in (getattr(fw, "ruleset", None) or [])
                                                          if rs.enabled and getattr(getattr(rs, "allowedHosts", None), "allIp", False))[:60]}
                except Exception as e:  # noqa: BLE001
                    row["fw_error"] = f"{type(e).__name__}"
                out["hosts"].append(row)
            try:
                for pg, p in self._collect_tolerant(vim.dvs.DistributedVirtualPortgroup, ["name", "config.defaultPortConfig", "config.uplink"]):
                    if p.get("config.uplink"):
                        continue
                    sp = getattr(p.get("config.defaultPortConfig"), "securityPolicy", None)
                    val = lambda x: getattr(getattr(sp, x, None), "value", None)   # noqa: E731
                    out["dvpg"].append({"name": p.get("name", ""), "promiscuous": val("allowPromiscuous"), "mac_changes": val("macChanges"),
                                        "forged": val("forgedTransmits")})
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"분산 포트그룹: {type(e).__name__}")
            vk = set(self.ASSESS_VM_KEYS)
            try:
                n = 0
                for v, p in self._collect_tolerant(vim.VirtualMachine, ["name", "config.template", "config.extraConfig", "runtime.powerState",
                                                                        "config.version", "guest.toolsRunningStatus", "snapshot"]):
                    if p.get("config.template"):
                        continue
                    n += 1
                    if n > max_vms:
                        break
                    ec = {o.key: str(o.value) for o in (p.get("config.extraConfig") or []) if o.key in vk}
                    snaps, oldest = 0, None
                    stree = list(getattr(p.get("snapshot"), "rootSnapshotList", None) or [])
                    while stree:
                        sn = stree.pop()
                        snaps += 1
                        ct = getattr(sn, "createTime", None)
                        if hasattr(ct, "timestamp"):
                            oldest = min(oldest or ct.timestamp(), ct.timestamp())
                        stree.extend(getattr(sn, "childSnapshotList", None) or [])
                    out["vms"].append({"name": p.get("name", ""), "power": str(p.get("runtime.powerState") or ""), "hw": str(p.get("config.version") or ""),
                                       "tools": str(p.get("guest.toolsRunningStatus") or ""), "adv": ec, "snapshots": snaps, "oldest_snapshot": oldest})
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"VM 설정: {type(e).__name__}")
        out["collected"] = time.time()
        return out

    def health_snapshot(self) -> dict[str, Any]:
        return self.health

    # ------------------------------------------------------------------ VKS(Supervisor) 자동 발견
    async def vks_targets(self) -> list[dict[str, Any]]:
        """vCenter REST 로 Supervisor 목록·API 엔드포인트·vSphere 네임스페이스를 찾는다(Supervisor 미사용이면 빈 목록).
        GET /api/vcenter/namespace-management/clusters → /clusters/{cluster}(api_server_cluster_endpoint)
        GET /api/vcenter/namespaces/instances (네임스페이스 → 읽기 전용 계정의 네임스페이스 범위 조회에 사용)"""
        if not self.rest_token:
            await self.login()
            if not self.rest_token:
                raise RuntimeError("vCenter REST 세션 없음(/api/session 실패)")

        async def get(path: str):
            r = await self.http.get(path)
            if r.status_code == 401:
                await self.login()
                r = await self.http.get(path)
            return r
        r = await get("/api/vcenter/namespace-management/clusters")
        if r.status_code in (404, 400):
            self.vks = {"supervisors": [], "updated": time.time(), "error": "", "note": "Supervisor 없음"}
            return []
        r.raise_for_status()
        sups: list[dict[str, Any]] = []
        nsr = await get("/api/vcenter/namespaces/instances")
        nss = nsr.json() if nsr.status_code < 300 else []
        for c in r.json() or []:
            cid = c.get("cluster", "")
            d = await get(f"/api/vcenter/namespace-management/clusters/{cid}")
            info = d.json() if d.status_code < 300 else {}
            cname = c.get("cluster_name") or next((n for n, v in self.topology.get("clusters", {}).items() if v.get("moid") == cid), cid)
            sups.append({"cluster": cid, "name": cname, "endpoint": info.get("api_server_cluster_endpoint") or "",
                         "config_status": c.get("config_status") or info.get("config_status", ""),
                         "kubernetes_status": c.get("kubernetes_status") or info.get("kubernetes_status", ""),
                         "namespaces": sorted(x.get("namespace") for x in nss if x.get("namespace") and x.get("cluster") in (cid, None, ""))})
        self.vks = {"supervisors": sups, "updated": time.time(), "error": ""}
        return sups

    # ------------------------------------------------------------------ 조사 번들
    def _find(self, vimtype, name: str):
        for obj, p in self._collect(vimtype, ["name"]):
            if p.get("name") == name:
                return obj
        return None

    def investigate(self, kind: str, name: str, hours: int = 24) -> dict[str, Any]:
        """VMware-AIops 조사 번들 방식: 대상 상태 + 관련 객체 + 알람 + 이벤트 타임라인(최신순)"""
        vt = {"vm": vim.VirtualMachine, "host": vim.HostSystem, "datastore": vim.Datastore,
              "cluster": vim.ClusterComputeResource}[kind]
        with self._lock:
            self._ensure()
            obj = self._find(vt, name)
            if obj is None:
                return {"error": f"{kind} '{name}' 을(를) {self.host} 에서 찾을 수 없음"}
            t = self.topology
            state: dict[str, Any] = {"kind": kind, "name": name, "vcenter": self.host, "environment": self.environment}
            related: dict[str, Any] = {}
            if kind == "vm":
                rt = obj.runtime
                state.update(power=str(rt.powerState), connection=str(rt.connectionState),
                             host=rt.host.name if rt.host else "", consolidation_needed=bool(rt.consolidationNeeded),
                             overall=str(obj.overallStatus), guest_heartbeat=str(obj.guestHeartbeatStatus),
                             cpu=obj.config.hardware.numCPU if obj.config else None,
                             mem_gb=round(obj.config.hardware.memoryMB / 1024, 1) if obj.config else None,
                             snapshots=self._count_snaps(obj.snapshot.rootSnapshotList) if obj.snapshot else 0,
                             tools=str(getattr(obj.guest, "toolsRunningStatus", "")))
                related["host"] = t["hosts"].get(state["host"], {})
                related["datastores"] = {d.name: t["datastores"].get(d.name, {}) for d in obj.datastore}
            elif kind == "host":
                rt = obj.runtime
                state.update(connection=str(rt.connectionState), maintenance=bool(rt.inMaintenanceMode),
                             power=str(rt.powerState), overall=str(obj.overallStatus),
                             cluster=t["hosts"].get(name, {}).get("cluster", ""),
                             model=getattr(obj.summary.hardware, "model", ""), version=obj.config.product.fullName if obj.config else "",
                             uptime_h=round((obj.summary.quickStats.uptime or 0) / 3600, 1),
                             cpu_pct=self._pct(obj.summary.quickStats.overallCpuUsage, obj.summary.hardware.cpuMhz * obj.summary.hardware.numCpuCores),
                             mem_pct=self._pct(obj.summary.quickStats.overallMemoryUsage, obj.summary.hardware.memorySize / 2**20))
                related["vms"] = sorted([v for v, x in t["vms"].items() if x["host"] == name])[:200]
                related["datastores"] = {d: t["datastores"].get(d, {}) for d in t["hosts"].get(name, {}).get("datastores", [])}
            elif kind == "datastore":
                s = obj.summary
                state.update(capacity_gb=round(s.capacity / 2**30, 1), free_gb=round(s.freeSpace / 2**30, 1),
                             used_pct=self._pct(s.capacity - s.freeSpace, s.capacity), type=s.type,
                             accessible=bool(s.accessible), overall=str(obj.overallStatus))
                related["hosts"] = t["datastores"].get(name, {}).get("hosts", [])
                related["vms"] = sorted(v.name for v in obj.vm)[:200]
            else:
                related["hosts"] = t["clusters"].get(name, {}).get("hosts", [])
                state.update({k: v for k, v in t["clusters"].get(name, {}).items() if k != "hosts"})
            alarms = [{"alarm": st.alarm.info.name, "status": str(st.overallStatus), "time": st.time.isoformat(),
                       "acknowledged": bool(st.acknowledged), "entity": getattr(st.entity, "name", "")}
                      for st in (obj.triggeredAlarmState or [])]
            spec = vim.event.EventFilterSpec(
                entity=vim.event.EventFilterSpec.ByEntity(entity=obj, recursion="all" if kind in ("host", "cluster") else "self"),
                time=vim.event.EventFilterSpec.ByTime(beginTime=datetime.now(timezone.utc) - timedelta(hours=hours)))
            events, truncated = self._read_events_newest_first(spec, cap=300)
            timeline = []
            for e in sorted(events, key=lambda x: x.createdTime, reverse=True)[:300]:
                sev, _ = self._sev_of(e)
                ent, _h = self._ent_name(e)
                timeline.append({"ts": e.createdTime.timestamp(), "severity": sev, "type": type(e).__name__.split(".")[-1],
                                 "entity": ent, "message": clean(e.fullFormattedMessage or "", 400),
                                 "user": getattr(e, "userName", "")})
        return {"state": state, "related": related, "alarms": alarms, "timeline": timeline,
                "timeline_truncated": truncated, "hours": hours, "generated": time.time()}

    # ------------------------------------------------------------------ 호스트 분석(2.18.0) — 연결 끊김 원인 조사, 모두 조회 API
    HOSTDIAG_LOGS = ("hostd", "vpxa", "vmkernel", "vobd")

    def host_diag(self, name: str, start: float, end: float, logs: bool = True, max_lines: int = 20000) -> dict[str, Any]:
        """호스트 하나의 [start, end] 구간: 상태·관리 IP·이벤트(하위 개체 포함)·작업·vCenter vpxd 로그(이 호스트 언급 줄)·
        호스트 hostd/vpxa/vmkernel/vobd 로그(연결돼 있을 때 — 회전 전 최근 분량만). BrowseDiagnosticLog 는 Global.Diagnostics 권한 필요."""
        from ..hostdiag.parse import line_ts
        out: dict[str, Any] = {"vcenter": self.name, "host": name, "state": {}, "events": [], "tasks": [], "logs": [], "gaps": []}
        b, e = datetime.fromtimestamp(start, tz=timezone.utc), datetime.fromtimestamp(end, tz=timezone.utc)
        with self._lock:
            self._ensure()
            content = self.si.content
            h = self._find(vim.HostSystem, name)
            if h is None:
                return {**out, "error": f"호스트 '{name}' 없음"}
            st: dict[str, Any] = {}
            try:
                rt, sm = h.runtime, h.summary
                st.update(connection=str(rt.connectionState), power=str(rt.powerState), maintenance=bool(rt.inMaintenanceMode),
                          overall=str(h.overallStatus), boot_time=rt.bootTime.timestamp() if rt.bootTime else None,
                          uptime_s=int(getattr(sm.quickStats, "uptime", 0) or 0), vc_ip_seen_by_host=str(getattr(sm, "managementServerIp", "") or ""),
                          ha_state=str(getattr(getattr(rt, "dasHostState", None), "state", "") or ""))
                if h.config:
                    st.update(version=h.config.product.fullName, build=h.config.product.build, lockdown=str(getattr(h.config, "lockdownMode", "") or ""))
                    vn = [v for v in (h.config.network.vnic or [])] if h.config.network else []
                    st["vmks"] = [{"device": v.device, "ip": v.spec.ip.ipAddress, "portgroup": v.portgroup or "",
                                   "mtu": v.spec.mtu} for v in vn]
                    st["mgmt_ip"] = next((v.spec.ip.ipAddress for v in vn if v.device == "vmk0"), vn[0].spec.ip.ipAddress if vn else "")
                hw = sm.hardware
                st.update(vendor=getattr(hw, "vendor", ""), model=getattr(hw, "model", ""))
                st["cluster"] = self.topology.get("hosts", {}).get(name, {}).get("cluster", "")
                st["moid"] = h._moId
            except Exception as ex:  # noqa: BLE001
                out["gaps"].append(f"상태 일부: {type(ex).__name__}")
            try:                                                     # vCenter 관리 IP 설정(호스트가 하트비트를 보낼 주소)
                opt = content.setting.QueryOptions("VirtualCenter.AutoManagedIPV4")
                st["vc_managed_ip"] = str(opt[0].value) if opt else ""
            except Exception:  # noqa: BLE001
                st["vc_managed_ip"] = ""
            out["state"] = st
            # 이벤트(이 호스트와 그 아래 VM)
            try:
                spec = vim.event.EventFilterSpec(entity=vim.event.EventFilterSpec.ByEntity(entity=h, recursion="all"),
                                                 time=vim.event.EventFilterSpec.ByTime(beginTime=b, endTime=e))
                evs, trunc = self._read_events_newest_first(spec, cap=3000)
                for ev in evs:
                    sev, _ = self._sev_of(ev)
                    ent, _h = self._ent_name(ev)
                    out["events"].append({"ts": ev.createdTime.timestamp(), "severity": sev, "type": getattr(ev, "eventTypeId", None) or type(ev).__name__.split(".")[-1],
                                          "entity": ent, "message": clean(ev.fullFormattedMessage or "", 600), "user": str(getattr(ev, "userName", "") or "")})
                if trunc:
                    out["gaps"].append("이벤트 3000건 초과 — 최신분만")
            except Exception as ex:  # noqa: BLE001
                out["gaps"].append(f"이벤트: {type(ex).__name__}: {str(ex).splitlines()[0] if str(ex) else ''}"[:200])
            # 작업
            coll = None
            try:
                tspec = vim.TaskFilterSpec(entity=vim.TaskFilterSpec.ByEntity(entity=h, recursion="all"),
                                           time=vim.TaskFilterSpec.ByTime(timeType="queuedTime", beginTime=b, endTime=e))
                coll = content.taskManager.CreateCollectorForTasks(filter=tspec)
                while len(out["tasks"]) < 1000:
                    page = coll.ReadNextTasks(500)
                    if not page:
                        break
                    for t in page:
                        out["tasks"].append({"ts": (t.queueTime or t.startTime).timestamp() if (t.queueTime or t.startTime) else None,
                                             "start": t.startTime.timestamp() if t.startTime else None, "end": t.completeTime.timestamp() if t.completeTime else None,
                                             "name": t.descriptionId or str(t.name or ""), "entity": t.entityName or "", "state": str(t.state),
                                             "user": str(getattr(t.reason, "userName", "") or ""), "error": clean(getattr(t.error, "localizedMessage", "") or "", 300) if t.error else ""})
            except Exception as ex:  # noqa: BLE001
                out["gaps"].append(f"작업: {type(ex).__name__}: {str(ex).splitlines()[0] if str(ex) else ''}"[:200])
            finally:
                if coll is not None:
                    try:
                        coll.DestroyCollector()
                    except Exception:  # noqa: BLE001
                        pass
            if not logs:
                return out
            diag = content.diagnosticManager
            on_vc = getattr(content.about, "apiType", "") == "VirtualCenter"
            needles = {name.lower(), name.split(".")[0].lower(), str(st.get("mgmt_ip") or "").lower(), str(st.get("moid") or "").lower()} - {""}

            def tail(key, host=None, filt=None):
                scope = {"host": host} if host is not None else {}
                probe = diag.BrowseDiagnosticLog(key=key, start=_PAST_THE_END, **scope)
                total = getattr(probe, "lineEnd", 0) or 0
                first = max(1, total - max_lines + 1)
                n_in, oldest = 0, None
                pos = first
                while pos <= total:
                    data = diag.BrowseDiagnosticLog(key=key, start=pos, lines=min(5000, total - pos + 1), **scope)
                    text = list(data.lineText or []) if data else []
                    if not text:
                        break
                    for ln in text:
                        ts = line_ts(ln)
                        if ts is None:
                            continue
                        oldest = ts if oldest is None else min(oldest, ts)
                        if start <= ts <= end and (filt is None or filt(ln)):
                            out["logs"].append({"ts": ts, "source": key.split(":")[0].split("/")[-1][:24], "message": clean(ln.strip(), 1500), "via": "vcenter"})
                            n_in += 1
                    pos += len(text)
                return n_in, oldest
            if on_vc:
                try:
                    keys = [d.key for d in (diag.QueryDescriptions() or [])]
                    vk = next((k for k in keys if k.startswith("vpxd:") and k.split(":", 1)[1].startswith("vpxd") and "profiler" not in k and "alert" not in k), None) \
                        or next((k for k in keys if "vpxd" in k), None)
                    if vk:
                        n_in, oldest = tail(vk, None, lambda ln: any(x in ln.lower() for x in needles))
                        out["vpxd"] = {"key": vk, "lines": n_in, "oldest": oldest}
                        if oldest and oldest > start:
                            out["gaps"].append(f"vpxd 로그는 {datetime.fromtimestamp(oldest).strftime('%m-%d %H:%M')} 이후만 남아 있음(회전)")
                except vim.fault.NoPermission:
                    out["gaps"].append("vpxd 로그: Global.Diagnostics 권한 없음")
                except vmodl.fault.MethodNotFound:
                    out["gaps"].append("vpxd 로그: 이 vCenter 가 DiagnosticManager 로그 읽기를 지원하지 않음")
                except Exception as ex:  # noqa: BLE001
                    out["gaps"].append(f"vpxd 로그: {type(ex).__name__}: {str(ex).splitlines()[0] if str(ex) else ''}"[:200])
            if str(st.get("connection")) == "connected":
                try:
                    keys = [d.key for d in (diag.QueryDescriptions(host=h) if on_vc else diag.QueryDescriptions()) or []]
                except Exception:  # noqa: BLE001
                    keys = list(self.HOSTDIAG_LOGS)
                out["host_logs"] = {}
                for k in self.HOSTDIAG_LOGS:
                    if k not in keys:
                        continue
                    try:
                        n_in, oldest = tail(k, h if on_vc else None)
                        out["host_logs"][k] = {"lines": n_in, "oldest": oldest}
                        if oldest and oldest > start:
                            out["gaps"].append(f"호스트 {k} 로그는 {datetime.fromtimestamp(oldest).strftime('%m-%d %H:%M')} 이후만(회전) — 과거 구간은 syslog 수집분으로")
                    except vim.fault.NoPermission:
                        out["gaps"].append(f"호스트 {k} 로그: Global.Diagnostics 권한 없음")
                        break
                    except vmodl.fault.MethodNotFound:
                        out["gaps"].append("호스트 로그: 이 vCenter 가 DiagnosticManager 로그 읽기를 지원하지 않음")
                        break
                    except Exception as ex:  # noqa: BLE001
                        out["gaps"].append(f"호스트 {k} 로그: {type(ex).__name__}"[:200])
            else:
                out["gaps"].append(f"호스트가 {st.get('connection')} 상태라 vCenter 경유 호스트 로그를 읽을 수 없음 — syslog 수집분으로 분석")
        return out

    @staticmethod
    def _pct(a, b):
        try:
            return round(a / b * 100, 1) if a is not None and b else None
        except Exception:  # noqa: BLE001
            return None

    def _count_snaps(self, tree) -> int:
        return sum(1 + self._count_snaps(s.childSnapshotList) for s in (tree or []))

    # ------------------------------------------------------------------ 조치(게이트 경유로만 호출)
    def action_preview(self, action: str, p: dict) -> dict[str, Any]:
        """쓰기 없이 읽기만으로 영향 범위(blast radius)·차단 사유(blockers) 측정"""
        with self._lock:
            self._ensure()
            if time.time() - self.topology.get("updated", 0) > 60:     # 판단 근거는 항상 최신 상태로(실행 직전 재측정 포함)
                self._refresh_topology()
            br: dict[str, Any] = {"vcenter": self.host, "environment": self.environment}
            blockers: list[str] = []
            if action == "vcenter.alarm.ack":
                matches = [st for st in (self.si.content.rootFolder.triggeredAlarmState or [])
                           if (not p.get("alarm") or st.alarm.info.name == p.get("alarm")) and getattr(st.entity, "name", "") == p.get("entity")]
                br["matches"] = [{"alarm": st.alarm.info.name, "entity": st.entity.name, "status": str(st.overallStatus),
                                  "acknowledged": bool(st.acknowledged)} for st in matches]
                br["note"] = "AcknowledgeAlarm 은 지정 엔터티의 해당 알람만 '확인' 처리(알람 상태·재발 감시는 유지). 일괄 Clear 는 사용하지 않음"
                if not matches:
                    blockers.append("일치하는 발생 중 알람이 없습니다")
                elif all(st.acknowledged for st in matches):
                    blockers.append("이미 확인된 알람입니다")
            elif action in ("vcenter.host.maintenance.enter", "vcenter.host.maintenance.exit"):
                h = self._find(vim.HostSystem, p.get("host", ""))
                if h is None:
                    return {"blast_radius": br, "blockers": [f"호스트 '{p.get('host')}' 없음"]}
                cl = self.topology["hosts"].get(h.name, {}).get("cluster", "")
                cinfo = self.topology["clusters"].get(cl, {})
                running = [v.name for v in h.vm if str(v.runtime.powerState) == "poweredOn"]
                br.update(host=h.name, cluster=cl, in_maintenance=bool(h.runtime.inMaintenanceMode),
                          connection=str(h.runtime.connectionState), running_vms=len(running), running_vm_names=running[:50],
                          drs=cinfo.get("drs"), drs_behavior=cinfo.get("drs_behavior"), vsan=cinfo.get("vsan"),
                          cluster_hosts=len(cinfo.get("hosts", [])),
                          hosts_in_maintenance=sum(1 for x in cinfo.get("hosts", []) if self.topology["hosts"].get(x, {}).get("maintenance")))
                if action.endswith("enter"):
                    if h.runtime.inMaintenanceMode:
                        blockers.append("이미 유지보수 모드입니다")
                    if running and not (cinfo.get("drs") and cinfo.get("drs_behavior") == "fullyAutomated"):
                        blockers.append(f"DRS 완전자동이 아니어서 실행 중 VM {len(running)}대가 자동 이전되지 않습니다 — 먼저 수동 vMotion 필요")
                    if cinfo.get("vsan"):
                        br["vsan_mode"] = "ensureObjectAccessibility (데이터 접근성 보장 모드)"
                    if br["cluster_hosts"] and br["hosts_in_maintenance"] + 1 >= br["cluster_hosts"]:
                        blockers.append("클러스터의 마지막 가용 호스트입니다")
                elif not h.runtime.inMaintenanceMode:
                    blockers.append("유지보수 모드가 아닙니다")
            elif action == "vcenter.vm.consolidate":
                v = self._find(vim.VirtualMachine, p.get("vm", ""))
                if v is None:
                    return {"blast_radius": br, "blockers": [f"VM '{p.get('vm')}' 없음"]}
                dss = {d.name: self.topology["datastores"].get(d.name, {}) for d in v.datastore}
                br.update(vm=v.name, power=str(v.runtime.powerState), consolidation_needed=bool(v.runtime.consolidationNeeded),
                          host=v.runtime.host.name if v.runtime.host else "", datastores=dss,
                          note="통합 중 VM I/O 일시 정지(stun) 발생 가능 — 업무 영향이 적은 시간대 권장")
                if not v.runtime.consolidationNeeded:
                    blockers.append("디스크 통합이 필요하지 않은 VM입니다")
                low = [n for n, d in dss.items() if d.get("used_pct") and d["used_pct"] > 95]
                if low:
                    blockers.append(f"데이터스토어 여유 공간 부족(>95% 사용): {', '.join(low)}")
            else:
                blockers.append(f"지원하지 않는 조치: {action}")
            return {"blast_radius": br, "blockers": blockers}

    def action_execute(self, action: str, p: dict, timeout: float = 900) -> dict[str, Any]:
        with self._lock:
            self._ensure()
            task = None
            if action == "vcenter.alarm.ack":
                am = self.si.content.alarmManager
                n = 0
                for st in self.si.content.rootFolder.triggeredAlarmState or []:
                    if (not p.get("alarm") or st.alarm.info.name == p.get("alarm")) and getattr(st.entity, "name", "") == p.get("entity") \
                            and not st.acknowledged:
                        am.AcknowledgeAlarm(alarm=st.alarm, entity=st.entity)
                        n += 1
                return {"result": "success", "acknowledged": n}
            if action == "vcenter.host.maintenance.enter":
                h = self._find(vim.HostSystem, p["host"])
                cl = self.topology["hosts"].get(h.name, {}).get("cluster", "")
                spec = None
                if self.topology["clusters"].get(cl, {}).get("vsan"):
                    spec = vim.host.MaintenanceSpec(vsanMode=vim.vsan.host.DecommissionMode(objectAction="ensureObjectAccessibility"))
                task = h.EnterMaintenanceMode_Task(timeout=0, evacuatePoweredOffVms=False, maintenanceSpec=spec)
            elif action == "vcenter.host.maintenance.exit":
                task = self._find(vim.HostSystem, p["host"]).ExitMaintenanceMode_Task(timeout=0)
            elif action == "vcenter.vm.consolidate":
                task = self._find(vim.VirtualMachine, p["vm"]).ConsolidateVMDisks_Task()
            else:
                raise ValueError(f"지원하지 않는 조치: {action}")
            task_id = task._moId
        deadline = time.time() + timeout
        while time.time() < deadline:                 # 잠금을 잡지 않고 폴링(수집 폴링 방해 금지)
            with self._lock:
                info = task.info
                st = str(info.state)
                prog = info.progress
                err = info.error.localizedMessage if info.error else ""
            if st in ("success", "error"):
                return {"result": st, "task": task_id, "error": err}
            time.sleep(3)
        return {"result": "running", "task": task_id, "note": f"{int(timeout)}초 내 완료되지 않음 — vCenter 작업에서 계속 확인(재실행 금지)",
                "progress": prog}

    async def service_restart_preview(self, service: str) -> dict[str, Any]:
        if not self.rest_token:
            return {"blast_radius": {"service": service}, "blockers": ["vCenter REST 세션 없음(/api/session 실패) — 서비스 조치 불가"]}
        r = await self.http.get(f"/api/appliance/services/{service}")
        if r.status_code == 404:
            return {"blast_radius": {"service": service}, "blockers": [f"서비스 '{service}' 없음"]}
        r.raise_for_status()
        j = r.json()
        br = {"service": service, "state": j.get("state"), "health": j.get("health"), "description": j.get("description"),
              "vcenter": self.host}
        if service in ("vpxd", "vmware-vpxd", "vapi-endpoint", "sts", "vmdird"):
            br["note"] = "vCenter 핵심 서비스 — 재시작 동안 vSphere Client·API·연동(백업·자동화) 일시 중단"
        return {"blast_radius": br, "blockers": []}

    async def service_restart(self, service: str) -> dict[str, Any]:
        r = await self.http.post(f"/api/appliance/services/{service}", params={"action": "restart"})
        if r.status_code == 401:
            await self.login()
            r = await self.http.post(f"/api/appliance/services/{service}", params={"action": "restart"})
        return {"result": "success" if r.status_code < 300 else "error", "http": r.status_code, "error": r.text[:300] if r.status_code >= 300 else ""}

    # ------------------------------------------------------------------ ESXi 원격 syslog(Syslog.global.logHost) — 전송 설정 점검·적용
    SYSLOG_KEY = "Syslog.global.logHost"

    def esxi_syslog(self) -> list[dict[str, Any]]:
        """호스트별 Syslog.global.logHost 값과 방화벽 'syslog' 룰셋 상태(읽기 전용)."""
        out = []
        with self._lock:
            self._ensure()
            for h, p in self._collect(vim.HostSystem, ["name", "runtime.connectionState", "configManager.advancedOption",
                                                       "configManager.firewallSystem", "parent"]):
                name = p.get("name", "")
                row: dict[str, Any] = {"host": name, "cluster": self.topology["hosts"].get(name, {}).get("cluster", ""),
                                       "connection": str(p.get("runtime.connectionState", "")), "loghost": "", "firewall": None}
                if row["connection"] != "connected":
                    row["error"] = "호스트 연결 안 됨"
                    out.append(row)
                    continue
                try:
                    vals = p["configManager.advancedOption"].QueryOptions(self.SYSLOG_KEY)
                    row["loghost"] = str(vals[0].value or "") if vals else ""
                except vim.fault.InvalidName:
                    row["loghost"] = ""                       # 옵션 미존재 = 미설정
                except Exception as e:  # noqa: BLE001
                    row["error"] = f"{type(e).__name__}"[:80]
                try:
                    fw = p.get("configManager.firewallSystem")
                    rs = [r for r in (fw.firewallInfo.ruleset if fw and fw.firewallInfo else []) if r.key == "syslog"]
                    row["firewall"] = bool(rs[0].enabled) if rs else None
                except Exception:  # noqa: BLE001
                    pass
                out.append(row)
        return out

    def esxi_syslog_add(self, hosts: list[str], target_uri: str) -> list[dict[str, Any]]:
        """지정 호스트의 logHost 목록에 target_uri 추가(기존 대상 유지) + syslog 방화벽 룰셋 활성화."""
        res = []
        with self._lock:
            self._ensure()
            for h, p in self._collect(vim.HostSystem, ["name", "configManager.advancedOption", "configManager.firewallSystem"]):
                name = p.get("name", "")
                if name not in hosts:
                    continue
                try:
                    om = p["configManager.advancedOption"]
                    try:
                        cur = om.QueryOptions(self.SYSLOG_KEY)
                    except vim.fault.InvalidName:
                        cur = []
                    vals = [v.strip() for v in str(cur[0].value or "").split(",") if v.strip()] if cur else []
                    if target_uri.lower() not in [v.lower() for v in vals]:
                        vals.append(target_uri)
                        om.UpdateOptions(changedValue=[vim.option.OptionValue(key=self.SYSLOG_KEY, value=",".join(vals))])
                    fw = p.get("configManager.firewallSystem")
                    if fw:
                        try:
                            fw.EnableRuleset(id="syslog")
                        except Exception:  # noqa: BLE001 — 8.0U2b+ 비표준 포트는 동적 규칙
                            pass
                    res.append({"host": name, "result": "success", "loghost": ",".join(vals)})
                except Exception as e:  # noqa: BLE001
                    res.append({"host": name, "result": "error", "error": f"{type(e).__name__}: {e}"[:200]})
        return res

    # ------------------------------------------------------------------ vCenter 어플라이언스 원격 syslog(/api/appliance/logging/forwarding)
    async def vc_forwarding(self) -> list[dict] | None:
        if not self.rest_token:
            return None
        r = await self.http.get("/api/appliance/logging/forwarding")
        if r.status_code == 401:
            await self.login()
            r = await self.http.get("/api/appliance/logging/forwarding")
        r.raise_for_status()
        return r.json() if isinstance(r.json(), list) else (r.json().get("value") or [])

    async def vc_forwarding_set(self, cfg_list: list[dict]) -> dict[str, Any]:
        r = await self.http.put("/api/appliance/logging/forwarding", json={"cfg_list": cfg_list})
        if r.status_code == 401:
            await self.login()
            r = await self.http.put("/api/appliance/logging/forwarding", json={"cfg_list": cfg_list})
        ok = r.status_code < 300
        test = None
        if ok:
            t = await self.http.post("/api/appliance/logging/forwarding", params={"action": "test"}, json={"send_test_message": True})
            test = t.json() if t.status_code < 300 and t.content else f"HTTP {t.status_code}"
        return {"result": "success" if ok else "error", "http": r.status_code, "error": "" if ok else r.text[:300], "test": test}

    # ------------------------------------------------------------------ 점검
    async def checks(self) -> dict[str, Any]:
        res: dict[str, Any] = {}
        try:
            await self._t(self._connect)
            res["SOAP(pyVmomi) 로그인"] = "ok"
            res["EventManager"] = "ok" if self.si.content.eventManager else "없음"
            topo = await self._t(self._refresh_topology)
            res["토폴로지"] = f"ok 호스트 {len(topo['hosts'])} · VM {len(topo['vms'])} · DS {len(topo['datastores'])}"
            if self.host_logs:
                await self._t(self._scan_host_logs)
                bad = {f"{h}:{k}": v for (h, k), v in self._log_unreadable.items()}
                res["호스트 로그(BrowseDiagnosticLog)"] = "ok" if not bad else f"{len(bad)}건 실패 — {next(iter(bad.values()))}"
        except Exception as e:  # noqa: BLE001
            res["SOAP(pyVmomi) 로그인"] = f"{type(e).__name__}: {e}"[:200]
        try:
            r = await self.http.post("/api/session", auth=(self.cfg["username"], self.cfg["password"]))
            r.raise_for_status()
            self.http.headers["vmware-api-session-id"] = r.json()
            res["REST /api/session"] = "ok"
            res["REST /api/appliance/health/system"] = await self._probe("GET", "/api/appliance/health/system")
        except Exception as e:  # noqa: BLE001
            code = getattr(getattr(e, "response", None), "status_code", None)
            res["REST /api/session"] = (f"warn: REST 세션 실패({f'HTTP {code}' if code else type(e).__name__}) — "
                                        "이벤트·토폴로지·조사·조치는 정상, 어플라이언스 헬스·서비스 재시작만 제외")
        return res
