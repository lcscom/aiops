"""물리 서버 BMC 커넥터 — DMTF Redfish (HPE iLO 5/6/7, Dell iDRAC 9/10, Lenovo XCC/XCC2, Supermicro 등 공통)

실시간 이벤트 (events: auto | push | sse | poll)
- push : BMC 가 AIOps 로 이벤트를 HTTPS POST(EventService 구독) — POST /redfish/v1/EventService/Subscriptions
         {Destination, Protocol:"Redfish", Context, HttpHeaders}. 연결 시 자동 생성·검증, Context="vcf-aiops:<커넥터>".
         수신 주소 = <agents.public_url|server.public_url>/api/redfish/events/<커넥터별 토큰> (BMC→AIOps 8630 허용 필요,
         Redfish 규격상 HTTPS). iDRAC 은 RedfishEventing.1.IgnoreCertificateErrors 로 사설 인증서 허용 여부 결정.
- sse  : AIOps 가 BMC 의 EventService.ServerSentEventUri 에 상시 연결(BMC→AIOps 방향 방화벽 불필요).
         iDRAC9 4.00.00.00 이상(/redfish/v1/SSE), XCC 등. iDRAC 은 1시간 무데이터 시 끊음 → 자동 재연결.
- poll : 로그 서비스(IML·IEL·SEL·Lclog…) 주기 조회만. auto = SSE 지원 시 sse, 수신 주소가 있으면 push, 아니면 poll.
  push·sse 사용 중에도 로그 서비스는 reconcile_interval(기본 300초)마다 조회해 놓친 이벤트를 보완한다.

부품 상태(inventory_interval, 기본 120초): 시스템 Health/전원, CPU·메모리 요약, 팬·온도(Thermal/ThermalSubsystem),
전원 공급 장치·이중화(Power/PowerSubsystem), 드라이브(Storage). 상태가 '바뀔 때만' 이벤트 — 첫 조회는 비정상만.
esxi_host 를 지정하면 이벤트·상태맵이 그 ESXi 호스트 이름으로 표시돼 vCenter 쪽 이상징후와 같은 타일에 겹친다.
"""
from __future__ import annotations

import asyncio
import json
import ssl
import time
from typing import Any

import httpx

from ..models import LogEvent, norm_severity
from ..runtime import bg
from .base import Connector
from .cimc import FAULT_SEV, CimcXml, legacy_ssl
from .vmware_rest import _iso

# 연결 호환 단계: 0 표준 · 1 Connection: close + Basic 인증(세션 수 제한·구형 HTTP 스택) · 2 + 구형 TLS(1.0/1.1·약한 암호군)
COMPAT_ERRORS = (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.ReadTimeout,
                 ssl.SSLError)


def _j(r: httpx.Response) -> dict:
    """BMC 가 빈 본문·HTML 오류 페이지·잘린 JSON 을 돌려줘도 폴링이 멈추지 않게(Lenovo XCC 일부 경로 등)."""
    try:
        v = r.json()
        return v if isinstance(v, dict) else {"Members": v} if isinstance(v, list) else {}
    except ValueError:
        return {}

HEALTH_SEV = {"OK": "info", "Warning": "warning", "Critical": "critical"}


def _health(st: dict | None) -> str:
    st = st or {}
    return str(st.get("HealthRollup") or st.get("Health") or "")


class RedfishConnector(Connector):
    type = "redfish"
    source = "redfish"
    default_interval = 60

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.log_urls: list[str] = []
        self.systems: list[str] = []
        self.chassis: list[str] = []
        self.managers: list[str] = []
        self.session_uri = ""
        self.vendor = cfg.get("vendor", "")
        self.display = cfg.get("esxi_host") or cfg.get("server_name") or cfg.get("name") or self.host
        self.mode = str(cfg.get("events", "auto")).lower()
        self.active_mode = "poll"
        self.inventory_interval = float(cfg.get("inventory_interval", 120))
        self.reconcile_interval = float(cfg.get("reconcile_interval", 300))
        self._last_inv = 0.0
        self._last_logs = 0.0
        self._last_sub_check = time.time()
        self.sse_uri = ""
        self._sse_task: asyncio.Task | None = None
        self.subscription = ""
        self.comp: dict[str, str] = {}                 # 부품 키 → 마지막 Health
        self.server: dict[str, Any] = {}               # 모델·S/N·BIOS·BMC 펌웨어·전원·Health
        self.event_url = ""                            # 엔진이 주입(push 수신 주소)
        self._pushed: dict[str, float] = {}            # MessageId → 실시간 수신 시각(로그 서비스 보완 조회 중복 방지)
        self._state.update({"events_mode": "poll", "events_received": 0, "last_event": None, "subscription": ""})
        c = str(cfg.get("compat", "auto")).lower()
        self.compat_fixed = c in ("0", "1", "2")
        self.compat = int(c) if self.compat_fixed else 0
        self.api_pref = str(cfg.get("api", "auto")).lower()          # auto | redfish | cimc-xml
        self.api_mode = "cimc" if self.api_pref == "cimc-xml" else "redfish"
        self.cimc: CimcXml | None = None
        self.firmware: list[dict[str, Any]] = []                    # 구성요소별 펌웨어(vCenter 하드웨어 점검과 연계)
        self.firmware_interval = float(cfg.get("firmware_interval", 21600))
        self._last_fw = 0.0
        self.nonjson: dict[str, int] = {}

    # ---------------------------------------------------------------- HTTP(호환 단계별)
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            hdr = {"Accept": "application/json"}
            if self.compat >= 1:
                hdr.update({"Connection": "close", "Accept-Encoding": "identity"})
            self._http = httpx.AsyncClient(
                base_url=self.base_url, verify=legacy_ssl(self.verify) if self.compat >= 2 else self.verify, headers=hdr,
                timeout=httpx.Timeout(float(self.cfg.get("timeout", 30)), connect=8),
                limits=httpx.Limits(max_keepalive_connections=0 if self.compat >= 1 else 10))
        return self._http

    def _set_compat(self, lvl: int) -> None:
        if lvl != self.compat or self._http is None:
            if self._http is not None:
                bg(self._http.aclose())
            self._http = None
            self.compat = lvl
        self._state["compat"] = ["표준", "Connection: close + Basic", "구형 TLS 호환"][lvl]

    def _jr(self, r: httpx.Response) -> dict:
        d = _j(r)
        if not d and r.status_code < 300 and r.content:
            p = r.request.url.path
            self.nonjson[p] = self.nonjson.get(p, 0) + 1
            self._state["checks"]["비JSON 응답"] = f"warn: {p} ({len(self.nonjson)}개 경로) — 건너뜀"
        return d

    # ---------------------------------------------------------------- 인증·탐색
    async def login(self):
        if self.api_mode == "cimc":
            await self._cimc_login()
            return
        root, last = {}, None
        levels = [self.compat] if self.compat_fixed else list(range(self.compat, 3))
        for lvl in levels:
            self._set_compat(lvl)
            try:
                r = await self.http.get("/redfish/v1/")
                root = self._jr(r)
                if r.status_code < 300 and root:
                    break
                last = RuntimeError(f"/redfish/v1/ HTTP {r.status_code}{'' if root else ' (JSON 아님)'}")
                if r.status_code in (401, 403):
                    break
            except COMPAT_ERRORS as e:
                last = e
        if not root:
            if self.api_pref in ("auto", "cimc-xml"):
                try:
                    await self._cimc_login()
                    return
                except Exception as e2:  # noqa: BLE001
                    raise RuntimeError(f"Redfish 연결 실패({type(last).__name__}: {last}) · CIMC XML API 도 실패({type(e2).__name__}: {e2}) — "
                                       "BMC 웹 UI 로 Redfish/XML API 사용 여부·TLS 설정을 확인하거나 BMC 원격 syslog 를 이 서버로 지정하세요") from e2
            raise RuntimeError(f"Redfish 연결 실패: {type(last).__name__}: {last}")
        self.vendor = self.vendor or root.get("Vendor") or ",".join((root.get("Oem") or {}).keys())
        if "cisco" in str(self.vendor).lower() and self.compat == 0 and not self.compat_fixed:
            self._set_compat(1)                       # CIMC: 세션 수 제한 → Basic + 연결 재사용 안 함
        if self.session_uri:
            try:
                await self.http.delete(self.session_uri)
            except Exception:  # noqa: BLE001
                pass
            self.session_uri = ""
        if self.compat >= 1:
            r = None
        else:
            try:
                r = await self.http.post("/redfish/v1/SessionService/Sessions",
                                         json={"UserName": self.cfg["username"], "Password": self.cfg["password"]})
            except COMPAT_ERRORS:
                r = None
        if r is None or (r.status_code >= 300 and self.cfg.get("basic_fallback", True)):
            self.http.auth = (self.cfg["username"], self.cfg["password"])   # 세션 생성 미지원 BMC
            self._state["auth"] = "basic"
        else:
            r.raise_for_status()
            self.http.headers["X-Auth-Token"] = r.headers.get("X-Auth-Token", "")
            self.session_uri = r.headers.get("Location", "")
            self._state["auth"] = "session"
        if not self.systems:
            await self._discover()
        await self._setup_events()

    async def _members(self, path: str) -> list[str]:
        try:
            r = await self.http.get(path)
        except httpx.HTTPError:
            return []
        if r.status_code >= 300:
            return []
        return [m["@odata.id"] for m in self._jr(r).get("Members", []) if isinstance(m, dict) and "@odata.id" in m]

    async def _discover(self):
        root = self._jr(await self.http.get("/redfish/v1/"))
        self.vendor = self.vendor or root.get("Vendor") or ",".join((root.get("Oem") or {}).keys())
        self.systems = await self._members("/redfish/v1/Systems")
        self.chassis = await self._members("/redfish/v1/Chassis")
        self.managers = await self._members("/redfish/v1/Managers")
        wanted = [s.lower() for s in self.cfg.get("log_services", [])]   # 비우면 전체
        self.log_urls = []
        for parent in self.managers + self.systems:
            for ls in await self._members(f"{parent}/LogServices"):
                if wanted and ls.rstrip("/").split("/")[-1].lower() not in wanted:
                    continue
                self.log_urls.append(f"{ls.rstrip('/')}/Entries")

    # ---------------------------------------------------------------- 실시간 이벤트 설정
    async def _setup_events(self) -> None:
        if self.mode == "poll":
            self.active_mode = "poll"
        else:
            try:
                es = self._jr(await self.http.get("/redfish/v1/EventService"))
            except Exception:  # noqa: BLE001
                es = {}
            self.sse_uri = es.get("ServerSentEventUri", "") or ""
            if self.mode in ("sse", "auto") and self.sse_uri:
                self.active_mode = "sse"
                if not self._sse_task or self._sse_task.done():
                    self._sse_task = bg(self._sse_loop())
            elif self.mode in ("push", "auto") and self.event_url:
                self.active_mode = "push"
                await self._ensure_subscription()
            else:
                self.active_mode = "poll"
                if self.mode in ("sse", "push"):
                    self._state["last_error"] = (f"요청한 이벤트 방식 {self.mode} 사용 불가 — "
                                                 + ("BMC 가 SSE 미지원" if self.mode == "sse" else "수신 주소(server.public_url) 미설정"))
        self._state["events_mode"] = self.active_mode

    def _context(self) -> str:
        return f"vcf-aiops:{self.name}"

    async def _ensure_subscription(self) -> None:
        """Context 로 기존 구독을 찾고 수신 주소가 다르면 교체. 생성 본문은 규격(필수 Destination·Protocol) → 구형 호환 순서로 시도"""
        ctx = self._context()
        for m in await self._members("/redfish/v1/EventService/Subscriptions"):
            try:
                d = self._jr(await self.http.get(m))
            except Exception:  # noqa: BLE001
                continue
            if d.get("Context") == ctx:
                if d.get("Destination") == self.event_url:
                    self.subscription = m
                    self._state["subscription"] = m
                    return
                await self.http.delete(m)                     # 주소 변경(서버 이전·HA) → 재생성
        token_hdr = [{"X-AIOps-Context": ctx}]
        bodies = [
            {"Destination": self.event_url, "Protocol": "Redfish", "Context": ctx, "HttpHeaders": token_hdr},
            {"Destination": self.event_url, "Protocol": "Redfish", "Context": ctx, "EventTypes": ["Alert"]},     # iDRAC·iLO5 구형
            {"Destination": self.event_url, "Protocol": "Redfish", "Context": ctx,
             "EventTypes": ["Alert", "StatusChange", "ResourceUpdated"]},
        ]
        last = ""
        for b in bodies:
            r = await self.http.post("/redfish/v1/EventService/Subscriptions", json=b)
            if r.status_code < 300:
                self.subscription = r.headers.get("Location", "") or ""
                self._state["subscription"] = self.subscription or "created"
                self.emit_nowait(self.ev(f"Redfish 이벤트 구독 생성 — {self.display} → AIOps", severity="info", kind="event",
                                         attrs={"subscription": self.subscription, "bmc": self.host}))
                return
            last = f"HTTP {r.status_code} {r.text[:160]}"
        self.active_mode = "poll"
        self._state["last_error"] = f"이벤트 구독 생성 실패({last}) — 로그 조회 방식으로 동작"

    def emit_nowait(self, ev: LogEvent) -> None:
        bg(self.emit(ev))

    # ---------------------------------------------------------------- 이벤트 처리(push·sse 공통)
    def events_from(self, payload: dict) -> list[LogEvent]:
        out: list[LogEvent] = []
        recs = payload.get("Events") if isinstance(payload, dict) else None
        if recs is None and isinstance(payload, dict) and payload.get("MessageId"):
            recs = [payload]                                    # 일부 BMC 는 레코드 단건
        for e in recs or []:
            sev_raw = e.get("MessageSeverity") or e.get("Severity") or ""
            sev = HEALTH_SEV.get(str(sev_raw), norm_severity(sev_raw, "info"))
            mid = str(e.get("MessageId", ""))
            msg = e.get("Message") or mid or "Redfish event"
            origin = (e.get("OriginOfCondition") or {}).get("@odata.id", "") if isinstance(e.get("OriginOfCondition"), dict) else str(e.get("OriginOfCondition") or "")
            key = f"evt:{e.get('EventId') or ''}:{mid}:{e.get('EventTimestamp') or ''}"
            if not self.seen.is_new(key):
                continue
            ts = _iso(e.get("EventTimestamp")) if e.get("EventTimestamp") else time.time()
            if mid:
                self._pushed[mid] = time.time()
                if len(self._pushed) > 2000:
                    for k in sorted(self._pushed, key=self._pushed.get)[:500]:
                        self._pushed.pop(k, None)
            out.append(self.ev(f"[{mid.split('.')[0] or 'Event'}] {msg}", severity=sev, kind="alarm" if sev in ("warning", "critical", "error") else "event",
                               ts=ts if abs(ts - time.time()) < 86400 * 7 else time.time(), native_id=str(e.get("EventId") or key),
                               attrs={"MessageId": mid, "MessageArgs": e.get("MessageArgs"), "origin": origin,
                                      "Resolution": e.get("Resolution"), "bmc": self.host, "vendor": self.vendor,
                                      "via": self.active_mode}))
        if out:
            self._state["events_received"] = self._state.get("events_received", 0) + len(out)
            self._state["last_event"] = time.time()
        return out

    async def on_push(self, payload: dict) -> int:
        evs = self.events_from(payload)
        for e in evs:
            await self.emit(e)
        return len(evs)

    async def _sse_loop(self) -> None:
        """SSE 상시 연결 — 끊기면 지수 백오프로 재연결(1→60초). 데이터 줄(data:)마다 JSON 이벤트"""
        delay = 1.0
        while True:
            try:
                url = self.sse_uri
                if self.cfg.get("sse_filter"):
                    url += ("&" if "?" in url else "?") + "$filter=" + self.cfg["sse_filter"]
                async with self.http.stream("GET", url, headers={"Accept": "text/event-stream"},
                                            timeout=httpx.Timeout(connect=10, read=None, write=10, pool=10)) as r:
                    if r.status_code in (401, 403):
                        await self.login()
                        raise RuntimeError(f"SSE 인증 실패 HTTP {r.status_code}")
                    r.raise_for_status()
                    self._state["sse"] = "connected"
                    delay = 1.0
                    buf: list[str] = []
                    async for line in r.aiter_lines():
                        if line.startswith("data:"):
                            buf.append(line[5:].strip())
                        elif line == "" and buf:
                            try:
                                payload = json.loads("\n".join(buf))
                                for e in self.events_from(payload):
                                    await self.emit(e)
                            except ValueError:
                                pass
                            buf = []
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self._state["sse"] = f"재연결 대기({type(e).__name__})"
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)

    # ---------------------------------------------------------------- 폴링(로그 보완 + 부품 상태)
    async def poll(self):
        if self.api_mode == "cimc":
            return await self._cimc_poll()
        out: list[LogEvent] = []
        now = time.time()
        if self.active_mode == "poll" or self.first_poll or now - self._last_logs >= self.reconcile_interval:
            self._last_logs = now
            out += await self._poll_logs()
        if self.first_poll or now - self._last_inv >= self.inventory_interval:
            self._last_inv = now
            out += await self._inventory()
        if self.first_poll or now - self._last_fw >= self.firmware_interval:
            self._last_fw = now
            try:
                await self._firmware()
            except Exception as e:  # noqa: BLE001
                self._state["checks"]["펌웨어 인벤토리"] = f"warn: {type(e).__name__}"
        if self.active_mode == "push" and self.subscription and now - self._last_sub_check >= 1800:   # 30분마다 구독 존재 확인
            self._last_sub_check = now
            r = await self.http.get(self.subscription)
            if r.status_code == 404:
                self.subscription = ""
                await self._ensure_subscription()
        return out

    async def _poll_logs(self) -> list[LogEvent]:
        out: list[LogEvent] = []
        top = int(self.cfg.get("top", 100))
        sem = asyncio.Semaphore(1 if self.compat >= 1 else 4)

        async def fetch(u: str) -> dict:
            async with sem:
                r = await self.http.get(u, params={"$top": top})
                if r.status_code in (401, 403):
                    r.raise_for_status()
                d = self._jr(r) if r.status_code < 300 else {}
                if r.status_code in (400, 501) or (r.status_code < 300 and not d):     # $top 미지원 BMC
                    r = await self.http.get(u)
                    d = self._jr(r) if r.status_code < 300 else {}
                mem = d.get("Members") or []
                cnt = int(d.get("Members@odata.count") or len(mem))
                # 오래된 것부터 주는 BMC(Lenovo XCC 등): 마지막 페이지(최신)를 다시 요청
                if cnt > len(mem) and len(mem) >= 2 and str(mem[0].get("Created", "")) < str(mem[-1].get("Created", "")):
                    r2 = await self.http.get(u, params={"$top": top, "$skip": max(0, cnt - top)})
                    d2 = self._jr(r2) if r2.status_code < 300 else {}
                    if d2.get("Members"):
                        d = d2
                return d
        results = await asyncio.gather(*[fetch(u) for u in self.log_urls], return_exceptions=True)
        for url, d in zip(self.log_urls, results):
            if isinstance(d, httpx.HTTPStatusError):
                raise d
            if isinstance(d, Exception) or not d:
                continue
            svc = url.rstrip("/").split("/")[-2]
            for e in d.get("Members", []):
                if not isinstance(e, dict):
                    continue
                key = e.get("@odata.id") or f"{svc}:{e.get('Id')}"
                if not self.seen.is_new(f"{key}:{e.get('Severity')}"):
                    continue
                ts = _iso(e.get("Created"))
                if self.first_poll and ts < self.since:
                    continue
                pm = self._pushed.get(str(e.get("MessageId") or ""))
                if pm and abs(pm - ts) < 900:               # 실시간(push·SSE)으로 이미 받은 이벤트
                    continue
                msg = e.get("Message") or e.get("Name") or ""
                out.append(self.ev(f"[{svc}] {msg}", severity=norm_severity(e.get("Severity"), "info"),
                                   kind="event", ts=ts, native_id=str(key),
                                   attrs={"MessageId": e.get("MessageId"), "EntryType": e.get("EntryType"), "log": svc,
                                          "vendor": self.vendor, "bmc": self.host}))
        return out

    async def _get(self, path: str) -> dict:
        try:
            r = await self.http.get(path)
            return self._jr(r) if r.status_code < 300 else {}
        except Exception:  # noqa: BLE001
            return {}

    async def _inventory(self) -> list[LogEvent]:
        """부품 Health 수집 → 변화 이벤트. 키: sys·cpu·mem·fan:<이름>·temp:<이름>·psu:<이름>·psu_redundancy·drive:<이름>"""
        comps: dict[str, tuple[str, str]] = {}           # key → (health, 설명)
        info: dict[str, Any] = {}
        for s in self.systems:
            j = await self._get(s)
            if not j:
                continue
            info.update(model=j.get("Model", ""), serial=j.get("SerialNumber", ""), uuid=str(j.get("UUID") or "").lower(), bios=j.get("BiosVersion", ""),
                        power=j.get("PowerState", ""), manufacturer=j.get("Manufacturer", ""), hostname=j.get("HostName", ""))
            comps["sys"] = (_health(j.get("Status")), "시스템")
            comps["cpu"] = (_health((j.get("ProcessorSummary") or {}).get("Status")), "CPU")
            comps["mem"] = (_health((j.get("MemorySummary") or {}).get("Status")), "메모리")
            st = (j.get("Storage") or {}).get("@odata.id")
            if st and self.cfg.get("drives", True):
                for sm in (await self._members(st))[:8]:
                    sj = await self._get(sm)
                    for dref in (sj.get("Drives") or [])[:64]:
                        d = await self._get(dref.get("@odata.id", ""))
                        if d:
                            nm = d.get("Name") or d.get("Id") or dref.get("@odata.id", "").rsplit("/", 1)[-1]
                            comps[f"drive:{nm}"] = (_health(d.get("Status")), f"드라이브 {nm} {d.get('MediaType', '')} {d.get('CapacityBytes', 0) // 10**9 if d.get('CapacityBytes') else ''}GB".strip())
        for c in self.chassis:
            th = await self._get(f"{c}/Thermal")
            for f in th.get("Fans", []) or []:
                nm = f.get("Name") or f.get("FanName") or f.get("MemberId")
                if (f.get("Status") or {}).get("State") in ("Absent",):
                    continue
                comps[f"fan:{nm}"] = (_health(f.get("Status")), f"팬 {nm}")
            for t in th.get("Temperatures", []) or []:
                nm = t.get("Name") or t.get("MemberId")
                if (t.get("Status") or {}).get("State") in ("Absent", "Disabled"):
                    continue
                rd = t.get("ReadingCelsius")
                comps[f"temp:{nm}"] = (_health(t.get("Status")), f"온도 {nm}{f' {rd}°C' if rd is not None else ''}")
            pw = await self._get(f"{c}/Power")
            for p in pw.get("PowerSupplies", []) or []:
                nm = p.get("Name") or p.get("MemberId")
                if (p.get("Status") or {}).get("State") in ("Absent",):
                    continue
                comps[f"psu:{nm}"] = (_health(p.get("Status")), f"전원 공급 장치 {nm}")
            for rd in pw.get("Redundancy", []) or []:
                comps["psu_redundancy"] = (_health(rd.get("Status")), f"전원 이중화({rd.get('Mode', '')})")
            if not th and not pw:                                     # 신형 스키마(ThermalSubsystem/PowerSubsystem)
                for f in (await self._members(f"{c}/ThermalSubsystem/Fans"))[:32]:
                    fj = await self._get(f)
                    comps[f"fan:{fj.get('Name') or f.rsplit('/', 1)[-1]}"] = (_health(fj.get("Status")), f"팬 {fj.get('Name', '')}")
                for p in (await self._members(f"{c}/PowerSubsystem/PowerSupplies"))[:16]:
                    pj = await self._get(p)
                    comps[f"psu:{pj.get('Name') or p.rsplit('/', 1)[-1]}"] = (_health(pj.get("Status")), f"전원 공급 장치 {pj.get('Name', '')}")
        for m in self.managers[:1]:
            mj = await self._get(m)
            info["bmc_fw"] = mj.get("FirmwareVersion", "")
        out: list[LogEvent] = []
        first = not self.comp
        changed = {k for k, (h, _l) in comps.items() if h and k != "sys" and self.comp.get(k) != h and not (first and h == "OK")}
        for k, (h, label) in comps.items():
            if not h:
                continue
            prev = self.comp.get(k)
            self.comp[k] = h
            if prev == h or (first and h == "OK"):
                continue
            if k == "sys" and changed:                       # 시스템 롤업은 원인 부품 이벤트로 충분(중복 경보 방지)
                continue
            sev = HEALTH_SEV.get(h, "warning") if h != "OK" else "info"
            txt = f"부품 상태 {'복구' if h == 'OK' else '이상'}: {label} {h}" + (f" (이전 {prev})" if prev else "")
            out.append(self.ev(txt, severity=sev, kind="health", entity=k.split(":")[0],
                               attrs={"component": k, "health": h, "previous": prev, "bmc": self.host}))
        prev_power = self.server.get("power")
        self.server = {**info, "health": comps.get("sys", ("", ""))[0], "checked": time.time(),
                       "failing": [lab for k, (h, lab) in comps.items() if h and h != "OK"]}
        if prev_power and info.get("power") and prev_power != info.get("power"):
            out.append(self.ev(f"서버 전원 상태 변경: {prev_power} → {info['power']}",
                               severity="critical" if info["power"] == "Off" else "info", kind="health", entity="power",
                               attrs={"bmc": self.host}))
        return out

    # ---------------------------------------------------------------- 펌웨어 인벤토리(Redfish UpdateService)
    async def _firmware(self) -> None:
        fw = []
        for m in (await self._members("/redfish/v1/UpdateService/FirmwareInventory"))[:120]:
            j = await self._get(m)
            if j and j.get("Version"):
                fw.append({"id": j.get("Id") or m.rsplit("/", 1)[-1], "name": j.get("Name", ""), "version": str(j.get("Version", "")),
                           "updateable": j.get("Updateable"), "health": _health(j.get("Status")),
                           "release": j.get("ReleaseDate", ""), "component": (j.get("RelatedItem") or [{}])[0].get("@odata.id", "") if j.get("RelatedItem") else ""})
        if fw:
            self.firmware = fw
            self.server["firmware_count"] = len(fw)

    # ---------------------------------------------------------------- Cisco IMC XML API(구형 C-Series)
    async def _cimc_login(self) -> None:
        last = None
        for legacy in ((self.compat >= 2,) if self.cimc else (False, True)):
            x = CimcXml(self.base_url, self.cfg["username"], self.cfg["password"], bool(self.verify), legacy=legacy,
                        timeout=float(self.cfg.get("timeout", 30)))
            try:
                async with x.session() as s:
                    rack = await s.resolve("computeRackUnit")
                self.cimc, self.api_mode = x, "cimc"
                self.vendor = "Cisco (IMC XML API)"
                self._state.update(auth="CIMC XML API", events_mode="poll", compat="구형 TLS 호환" if legacy else "표준")
                if rack:
                    r0 = rack[0]
                    self.server.update(model=r0.get("model", ""), serial=r0.get("serial", ""), manufacturer="Cisco", uuid=str(r0.get("uuid", "")).lower(),
                                       power=r0.get("operPower", ""), memory_mb=r0.get("totalMemory", ""))
                return
            except Exception as e:  # noqa: BLE001
                last = e
        raise RuntimeError(f"{type(last).__name__}: {last}")

    async def _cimc_poll(self) -> list[LogEvent]:
        out: list[LogEvent] = []
        async with self.cimc.session() as s:
            faults = await s.resolve("faultInst")
            rack = await s.resolve("computeRackUnit")
            if self.first_poll or time.time() - self._last_fw >= self.firmware_interval:
                self._last_fw = time.time()
                fws = await s.resolve("firmwareRunning")
                self.firmware = [{"id": f.get("dn", ""), "name": f.get("dn", "").replace("sys/rack-unit-1/", ""), "version": f.get("version", ""),
                                  "updateable": None, "health": "", "release": "", "component": f.get("type", "")} for f in fws if f.get("version")]
        cur: dict[str, tuple[str, dict]] = {}
        for f in faults:
            sev = str(f.get("severity", "")).lower()
            if sev == "cleared":
                continue
            cur[f.get("dn", f.get("id", ""))] = (sev, f)
        first = not self.comp and self.first_poll
        for dn, (sev, f) in cur.items():
            k = f"fault:{dn}"
            if self.comp.get(k) == sev:
                continue
            self.comp[k] = sev
            out.append(self.ev(f"[CIMC {f.get('code', '')}] {f.get('descr', '')}".strip(), severity=FAULT_SEV.get(sev, "warning"),
                               kind="alarm", entity=f.get("dn", ""), ts=_iso(f.get("created")) if f.get("created") else time.time(),
                               native_id=f.get("id", dn),
                               attrs={"bmc": self.host, "vendor": "Cisco", "code": f.get("code"), "cause": f.get("cause"),
                                      "severity": sev, "dn": dn, "first": first}))
        for k in [k for k in self.comp if k.startswith("fault:") and k[6:] not in cur]:
            self.comp.pop(k, None)
            out.append(self.ev(f"[CIMC] 장애 해소: {k[6:]}", severity="info", kind="event", entity=k[6:], attrs={"bmc": self.host}))
        if rack:
            r0 = rack[0]
            prev = self.server.get("power")
            worst = max((FAULT_SEV.get(sv, "warning") for sv, _ in cur.values()), key=lambda x: ["info", "warning", "error", "critical"].index(x), default="info")
            self.server.update(model=r0.get("model", ""), serial=r0.get("serial", ""), manufacturer="Cisco", power=r0.get("operPower", ""),
                               health={"critical": "Critical", "error": "Warning", "warning": "Warning"}.get(worst, "OK"),
                               failing=[f"{f.get('code')} {f.get('descr', '')[:60]}" for _, f in cur.values()][:10],
                               bios=next((x["version"] for x in self.firmware if "bios" in x["name"].lower()), self.server.get("bios", "")),
                               bmc_fw=next((x["version"] for x in self.firmware if "mgmt" in x["name"].lower() or "cimc" in x["name"].lower()), self.server.get("bmc_fw", "")),
                               checked=time.time())
            if prev and r0.get("operPower") and prev != r0.get("operPower"):
                out.append(self.ev(f"서버 전원 상태 변경: {prev} → {r0['operPower']}", severity="critical" if r0["operPower"] == "off" else "info",
                                   kind="health", entity="power", attrs={"bmc": self.host}))
        return out

    # ---------------------------------------------------------------- 공통 재정의
    def ev(self, message: str, **kw) -> LogEvent:
        kw.setdefault("host", self.display)           # 이벤트 호스트 = 서버(ESXi) 이름, BMC 주소는 attrs.bmc
        return super().ev(message, **kw)

    def entities(self) -> list[dict[str, Any]]:
        s = self.server
        if not s:
            return [{"name": self.display, "kind": "server", "group": "서버(BMC)", "state": "unknown",
                     "detail": f"BMC {self.host} · 상태 미수집 · {self._state.get('last_error', '')[:80]}"}]
        h, pwr = s.get("health"), s.get("power")
        st = "down" if h == "Critical" or pwr == "Off" else "warn" if h == "Warning" or s.get("failing") else "ok"
        detail = " · ".join(x for x in (f"{s.get('manufacturer', '')} {s.get('model', '')}".strip(), f"S/N {s.get('serial', '')}",
                                         f"BIOS {s.get('bios', '')}", f"BMC {s.get('bmc_fw', '')}", f"전원 {pwr}",
                                         f"이벤트 {self.active_mode}") if x.strip())
        if s.get("failing"):
            detail += " · 이상: " + ", ".join(s["failing"][:6])
        return [{"name": self.display, "kind": "server", "group": "서버(BMC)", "state": st, "detail": detail}]

    async def run(self) -> None:
        try:
            await super().run()
        finally:
            if self._sse_task:
                self._sse_task.cancel()

    async def checks(self) -> dict[str, Any]:
        self.systems = []
        await self.login()
        if self.api_mode == "cimc":
            async with self.cimc.session() as s:
                n = len(await s.resolve("faultInst"))
            return {"인증": "ok CIMC XML API(/nuova)", "벤더": f"ok {self.vendor}",
                    "서버": f"ok {self.server.get('model', '')} S/N {self.server.get('serial', '')} 전원 {self.server.get('power', '')}",
                    "활성 장애(faultInst)": f"ok {n}건", "연결": f"ok {self._state.get('compat', '')}",
                    "이벤트": "warn: Redfish 미지원 — 장애 목록 주기 조회(실시간은 CIMC 원격 syslog 를 이 서버 514 로 지정)"}
        res = {"세션 인증": f"ok {self._state.get('auth')}", "벤더": f"ok {self.vendor}", "연결": f"ok {self._state.get('compat', '표준')}",
               "로그 서비스": f"ok {len(self.log_urls)}개 탐색", "Systems": f"ok {len(self.systems)}개",
               "Chassis": f"ok {len(self.chassis)}개"}
        if self.active_mode == "push":
            res["이벤트(push)"] = f"ok 구독 {self.subscription or '생성됨'} → {self.event_url}"
        elif self.active_mode == "sse":
            res["이벤트(SSE)"] = f"ok {self.sse_uri}"
        else:
            res["이벤트"] = "warn: 실시간 이벤트 미사용 — 로그 조회 방식(server.public_url 지정 또는 SSE 지원 BMC 필요)"
        return res

    async def test_event(self) -> dict[str, Any]:
        """BMC 에 시험 이벤트 발송 요청(EventService.SubmitTestEvent) — 벤더별 필수 인자가 달라 표준 최소 본문부터 시도"""
        bodies = [{"EventType": "Alert", "MessageId": "Base.1.0.Success", "Message": "VCF AIops test event", "Severity": "OK",
                   "OriginOfCondition": "/redfish/v1/Systems"},
                  {"MessageId": "Base.1.0.Success"}, {"EventType": "Alert"}]
        last = ""
        for b in bodies:
            r = await self.http.post("/redfish/v1/EventService/Actions/EventService.SubmitTestEvent", json=b)
            if r.status_code < 300:
                return {"ok": True, "mode": self.active_mode}
            last = f"HTTP {r.status_code} {r.text[:200]}"
        return {"ok": False, "error": last}
