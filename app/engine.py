"""이벤트 파이프라인: 수집 → 정규화 → 1차 탐지 → 실시간 스트림 → 이상징후 → LLM 분석 → 알림."""
from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict, deque
from typing import Any

from .alerting import Alerter
from .collection import CollectionMonitor
from .detect import Detector
from .isvara import IsvaraClient
from .llm import LLMClient
from .vsan import is_vsan_event
from .models import SEV_RANK, Anomaly, LogEvent
from .rag.store import RagManager
from .realtime import Hub
from .runtime import Breaker, LoopLag, MinuteCounter, Supervisor, bg
from .security.audit import AuditLog
from .store import Store

_HOT: tuple[str, ...] = ()


def _hot_keywords() -> tuple[str, ...]:
    """위험·오류 규칙의 필수 키워드 — 원본 심각도가 낮아도(ESXi vmkernel 은 대부분 info 로 송신) 우선 처리할지 판단"""
    global _HOT
    if not _HOT:
        from .detect import DEFAULT_RULES
        _HOT = tuple(sorted({k for r in DEFAULT_RULES if r.severity in ("critical", "error") for k in r.gate}))
    return _HOT


class Engine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        pcfg = cfg.get("pipeline") or {}
        self.store = Store(cfg["server"]["db_path"], int(cfg["server"]["retention_days"]), cfg.get("storage") or {})
        self.detector = Detector(cfg["detection"])
        self.llm = LLMClient(cfg["llm"]) if cfg["llm"].get("enabled") else None
        self.isvara = IsvaraClient(cfg.get("isvara") or {})
        self.sup = Supervisor()
        self.lag = LoopLag()
        self.gate = None                                   # 2.22.1 수집 일시정지(main 에서 연결)
        self.hostseen: dict[str, list] = {}                # 호스트 → [소스들, 건수, 마지막 수신]
        self.hub = Hub(cfg["server"])
        self.minutes = MinuteCounter(60)
        self.llm_breaker = Breaker("llm", int(cfg["llm"].get("breaker_threshold", 3)), float(cfg["llm"].get("breaker_reset", 60)))
        self.alerter = Alerter(cfg["alerting"], self.store.save_alert, self.broadcast)
        from pathlib import Path
        self.collection = CollectionMonitor(cfg.get("monitoring") or {}, self.ingest)
        self.rag = RagManager(cfg["rag"], str(Path(cfg["server"]["db_path"]).parent))
        from .knowledge import KnowledgeLibrary, env_versions
        self.knowledge = KnowledgeLibrary(cfg.get("knowledge") or {}, str(Path(cfg["server"]["db_path"]).parent), self.rag.embedder)
        self.rag.library = self.knowledge
        from .kblink import KbLinker
        self.kblink = KbLinker(self, cfg.get("knowledge") or {})          # 이상징후·인시던트 ↔ KB 자동 연결
        from .billing import Billing
        self.billing = Billing(self, cfg.get("billing") or {})             # VM 사용량 5분 표본 → 테넌트·프로젝트 정산
        from .assess import Assessor
        self.assess = Assessor(self, cfg.get("assessment") or {})          # 하드닝·KISA·VMSA/CVE 판독(읽기 전용)
        from .capacity import Capacity
        self.capacity = Capacity(self, cfg.get("capacity") or {})          # 용량 추세 예측·VM 적정화
        self.rag.env_fn = lambda: env_versions(self)
        if self.llm:
            self.llm.cfg.setdefault("max_chars_per_ref", cfg["rag"].get("max_chars_per_ref", 1200))
            self.llm.cfg.setdefault("max_chars_per_lib_ref", (cfg.get("knowledge") or {}).get("max_chars_per_ref", 2400))
        self.buffer: deque[dict] = deque(maxlen=int(cfg["server"]["buffer_size"]))
        self.ctx: OrderedDict[str, deque] = OrderedDict()   # host/source → 최근 로그(LRU 상한)
        self.ctx_cap = int(pcfg.get("context_hosts", 5000))
        self.anomalies: dict[str, Anomaly] = {}             # id → Anomaly
        self.by_fp: dict[str, str] = {}                     # fingerprint → anomaly id
        from .aiqueue import AIQueue
        self.aq = AIQueue(cfg["llm"], on_skip=self._ai_skip)  # 우선순위·병합·부하 차단 분석 대기열
        self.llm_q = self.aq                                 # 호환 별칭(qsize)
        from .aigov import Governor
        from .aipatterns import PatternStore
        self.gov = Governor(cfg["llm"].get("governor") or {})        # GPU 발열·호출량 조절
        self.patterns = PatternStore(self.store, cfg["llm"])           # 로그 패턴별 분석 재사용
        self.ai_on = cfg["llm"].get("analysis_enabled", True) is not False   # 메인 화면 'AI 분석' 토글
        if self.llm:
            self.llm.gov = self.gov
        self.clients = self.hub                              # 호환 별칭
        self._pending_ws: list[dict] = []
        # 수집 파이프라인: 우선(경고 이상·알람·위험 키워드) / 일반 두 단계 큐
        self.q_hi: deque = deque()
        self.q_lo: deque = deque()
        self.q_hi_max = int(pcfg.get("high_queue", 20000))
        self.q_lo_max = int(pcfg.get("low_queue", 100000))
        self.q_classify_at = int(pcfg.get("classify_backlog", 500))
        self._q_wake = asyncio.Event()
        self._pub: OrderedDict[str, bool] = OrderedDict()   # 게시(인시던트·저장·알림) 대기 이상징후 id — 병합
        self._pub_wake = asyncio.Event()
        self._fast_pub: dict[str, float] = {}
        self.pipe = {"accepted": 0, "processed": 0, "high": 0, "dropped_low": 0, "dropped_high": 0, "errors": 0,
                     "last_error": "", "hi_peak": 0, "lo_peak": 0, "pub_backlog": 0, "lag_ms": 0.0}
        self.connectors: list[Any] = []
        self.conn_tasks: dict[str, asyncio.Task] = {}
        self.audit = AuditLog(self.store, int((cfg.get("audit") or {}).get("retention_days", 1825)))
        from .siem import Siem
        from .patching import current_version
        self.siem = Siem(cfg.get("siem") or {}, current_version())      # CEF/syslog — 감사·이상징후·인시던트 전달
        self.audit.sink = self.siem.audit
        self.alerter.on_fire = self.siem.anomaly
        from .incidents import IncidentManager
        self.incidents = IncidentManager(self, cfg.get("incidents") or {})
        self.stats = {"events_total": 0, "eps": 0.0, "anomalies_total": 0, "started": time.time()}
        self._eps_count = 0
        self.incidents_active: dict[str, int] = {}
        from .agents import AgentRegistry
        self.agents = AgentRegistry(self, cfg.get("agents") or {})
        from .monitors import MonitorManager
        self.monitors = MonitorManager(self)          # 사용자 정의 모니터(Datadog 방식)
        from .vmmoves import MoveTracker
        from .opsmetrics import OpsMetrics
        self.opsmetrics = OpsMetrics(self, cfg.get("ops_metrics") or {})   # 2.8.0 VCF Operations 메트릭
        from .vksobs import VksObserver
        self.vksobs = VksObserver(self, cfg.get("vks_observe") or {})       # 2.10.0 VKS 구성도 상태·변경 이력
        from .support import SupportManager
        self.support = SupportManager(self, cfg.get("support") or {})      # 2.11.0 지원 요청(SR) 보고서·공유
        from .cloudcost import CloudCost
        self.cloudcost = CloudCost(self, cfg.get("cloudcost") or {})        # 2.13.0 VCF ↔ AWS·Azure·GCP 비용 비교·VM IOPS
        from .readiness.manager import ReadinessManager
        self.readiness = ReadinessManager(self, cfg.get("readiness") or {})   # 2.14.0 하드웨어 준비도(VCF-R, Redfish 읽기 전용)
        from .rvtools.manager import RvToolsManager
        self.rvtools = RvToolsManager(self, cfg.get("rvtools") or {})         # 2.15.0 RVTools 업로드 분석(구성도·컴플라이언스·AI)
        from .license.manager import LicenseManager
        self.license = LicenseManager(self, cfg.get("license") or {})        # 2.16.0 라이선스 관리(공급자·CSP·실사용 비교)
        from .hostdiag.manager import HostDiag
        self.hostdiag = HostDiag(self, cfg.get("hostdiag") or {})            # 2.18.0 호스트 분석(연결 끊김 원인)
        from .segtraffic.manager import SegTraffic
        self.segtraffic = SegTraffic(self, cfg.get("segtraffic") or {})      # 2.21.0 NSX 세그먼트 트래픽
        from .websearch import WebSearch
        self.websearch = WebSearch(cfg.get("web_search") or {})   # 2.7.0 AI 질의 웹 검색 근거(기본 꺼짐)
        self.moves = MoveTracker(self)                # VM 액티비티(이동·HA·생성·삭제·구성·전원)
        self.moves.rules()                            # 규칙·보관 기간 적용(DB 저장값 우선)
        from .fortigate import FortiProcessor
        self.fortigate = FortiProcessor(self, cfg.get("fortigate") or {})
        self.ha = None                                       # main 에서 HAManager 주입
        self.health = None                                   # main 에서 HealthMonitor 주입

    # ---------------------------------------------------------------- 수집 입구(비차단)
    async def ingest(self, ev: LogEvent) -> None:
        """모든 수집기(syslog·SNMP·폴링·HTTP)의 공통 입구 — 큐에 넣고 즉시 반환(수신기가 처리 지연에 묶이지 않음)"""
        self.submit(ev)

    def submit(self, ev: LogEvent) -> bool:
        g = self.gate
        if g is not None and g.paused and g.drop_event(ev):     # 2.22.1 수집 일시정지
            return True
        if self.agents.blocked and ev.source in ("vm", "baremetal") and ev.connector in ("syslog", "agent") \
                and (ev.host or "").lower() in self.agents.blocked:          # 등록 삭제·차단된 호스트 — 저장·분석하지 않음
            if ev.connector == "syslog":
                self.agents.touch_syslog(ev)                              # 시도 기록(보낸 주소·경로)
            self.agents.dropped += 1
            return True
        if ev.connector == "syslog" and ev.source in ("vm", "baremetal"):
            self.agents.touch_syslog(ev)
            if ev.attrs.get("app") in ("aiops-heartbeat", "rsyslogd-pstats"):   # rsyslog 모드 하트비트(저장·분석 불필요)
                return True
        self.collection.record(ev)
        h = ev.host
        if h:                                              # 2.22.1 최근 송신 호스트(메모리) — /api/hosts/known 이 큰 DB 를 훑지 않게
            hs = self.hostseen.get(h)
            if hs is None:
                if len(self.hostseen) >= 5000:
                    for k in sorted(self.hostseen, key=lambda k: self.hostseen[k][2])[:500]:
                        self.hostseen.pop(k, None)
                hs = self.hostseen[h] = [set(), 0, 0.0]
            hs[0].add(ev.source)
            hs[1] += 1
            hs[2] = ev.ts or time.time()
        self.minutes.add(ev.source, ev.connector, sev=ev.severity, host=ev.host or ev.entity)
        if ev.source in ("vcenter", "esxi") and is_vsan_event(ev.source, ev.message, ev.attrs, ev.entity or ""):
            ev.attrs["vsan"] = 1                          # vSAN 관제 도메인(가상 소스 'vsan' 분당 집계 · 표시 필터)
            self.minutes.add("vsan", ev.connector, sev=ev.severity, host=ev.host or ev.entity)
        self.pipe["accepted"] += 1
        if ev.attrs.get("move"):                      # VM 이동·HA 기록(vMotion·DRS·HA 재시작 …)
            self.moves.record(ev)
        if ev.source == "fortigate" and not ev.attrs.get("fg_synthetic"):   # 방화벽: 대량 트래픽 집계·위협 탐지
            ev = self.fortigate.handle(ev)
            if ev is None:
                self.pipe["aggregated"] = self.pipe.get("aggregated", 0) + 1
                return True
        ev.attrs["_q"] = time.time()                  # 큐 투입 시각(처리 지연 측정 — 장비 시계 오차와 무관)
        hi = SEV_RANK.get(ev.severity, 1) >= 2 or ev.kind != "log" or ev.source == "aiops"
        if not hi and len(self.q_lo) >= self.q_classify_at:            # 적체 시에만 키워드로 우선순위 재분류
            low = (ev.message or "")[:600].lower()
            hi = any(k in low for k in _hot_keywords())
        if hi:
            if len(self.q_hi) >= self.q_hi_max:
                self.pipe["dropped_high"] += 1
                return False
            self.q_hi.append(ev)
            self.pipe["high"] += 1
            if len(self.q_hi) > self.pipe["hi_peak"]:
                self.pipe["hi_peak"] = len(self.q_hi)
        else:
            if len(self.q_lo) >= self.q_lo_max:
                self.pipe["dropped_low"] += 1
                return False
            self.q_lo.append(ev)
            if len(self.q_lo) > self.pipe["lo_peak"]:
                self.pipe["lo_peak"] = len(self.q_lo)
        self._q_wake.set()
        return True

    def saturated(self) -> bool:
        """일반 큐가 90% 이상 — 수신기가 파싱 전에 저우선 원문을 버려 CPU 를 아끼도록(우선순위 판정은 원문으로)"""
        return len(self.q_lo) >= self.q_lo_max * 0.9

    def shed_raw(self, line: str) -> bool:
        """포화 시 원문 1줄의 우선 여부 — syslog PRI 심각도(warning 이상) 또는 위험 키워드. False 면 버림(건수 집계)."""
        sev = 6
        if line.startswith("<"):
            j = line.find(">", 1, 5)
            if j > 1 and line[1:j].isdigit():
                sev = int(line[1:j]) % 8
        if sev <= 4:
            return True
        low = line[:600].lower()
        if any(k in low for k in _hot_keywords()):
            return True
        self.pipe["dropped_low"] += 1
        self.pipe["accepted"] += 1
        return False

    async def pipeline_worker(self) -> None:
        """우선 큐를 먼저 비우고 일반 큐 처리. 15ms 마다 루프에 양보해 HTTP·WebSocket 응답성을 유지."""
        while True:
            if not self.q_hi and not self.q_lo:
                self._q_wake.clear()
                try:
                    await asyncio.wait_for(self._q_wake.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
            self.sup.beat("pipeline")
            n = 0
            t_end = time.perf_counter() + 0.015
            while n < 2000 and (n & 31 or time.perf_counter() < t_end):
                if self.q_hi:
                    ev = self.q_hi.popleft()
                elif self.q_lo:
                    ev = self.q_lo.popleft()
                else:
                    break
                qt = ev.attrs.pop("_q", None)
                try:
                    self._process(ev)
                except Exception as e:  # noqa: BLE001  한 건의 오류가 파이프라인을 멈추지 않게
                    self.pipe["errors"] += 1
                    self.pipe["last_error"] = f"{type(e).__name__}: {e}"[:300]
                n += 1
            self.pipe["processed"] += n
            if n and qt:
                self.pipe["lag_ms"] = round(max(0.0, time.time() - qt) * 1000, 1)
            await asyncio.sleep(0)

    def _process(self, ev: LogEvent) -> None:
        score, category, sev = self.detector.evaluate(ev)
        if ev.attrs.get("fp"):                          # 생성 이벤트(무차별 대입 등): 지정 키로 이상징후 병합(출발지별)
            ev.template = str(ev.attrs["fp"])
        d = ev.to_dict()
        d["raw_severity"] = ev.severity
        if SEV_RANK[sev] > SEV_RANK[ev.severity]:   # 규칙이 원본보다 높게 판정하면 화면/저장 심각도 상향
            d["severity"] = sev
        self.stats["events_total"] += 1
        self._eps_count += 1
        self.buffer.append(d)
        self.store.put_log(d)
        key = ev.host or ev.entity or ev.connector
        dq = self.ctx.get(key)
        if dq is None:
            dq = self.ctx[key] = deque(maxlen=60)
            if len(self.ctx) > self.ctx_cap:
                self.ctx.popitem(last=False)
        else:
            self.ctx.move_to_end(key)
        context = list(dq)[-int(self.cfg["llm"].get("context_lines", 12)):]
        dq.append(d)
        fa = ev.attrs.get("force_anomaly")
        if fa:                                          # 모니터 경보 등: 규칙 점수와 무관하게 이상징후로
            score, category, sev = max(score, 1.0), ev.attrs.get("category", "monitor"), ev.severity
        elif ev.attrs.get("no_anomaly"):                # 대량·집계 대상(방화벽 개별 실패 로그 등): 저장만, 이상징후는 집계 이벤트로
            score = 0.0
        if category != "suppressed" and score >= float(self.cfg["detection"]["llm_threshold"]):
            d["flagged"] = True
            self._raise_anomaly(ev, d, score, category, sev, context)
        if len(self._pending_ws) < 20000:
            self._pending_ws.append(d)

    def _raise_anomaly(self, ev: LogEvent, d: dict, score: float, category: str, sev: str,
                       context: list[dict]) -> None:
        """메모리에서 즉시 생성·병합하고 화면에 바로 푸시. 인시던트·저장·외부 알림은 게시 워커가 이어서 처리."""
        fp = ev.fingerprint()
        now = time.time()
        aid = self.by_fp.get(fp)
        a = self.anomalies.get(aid) if aid else None
        if a and now - a.last_seen < float(self.cfg["detection"]["dedupe_window"]):
            a.count += 1
            a.last_seen = now
            pk = (a.event or {}).get("pattern")
            if pk:                                     # 병합돼도 패턴 연결 유지 + 발생 횟수 집계
                d["pattern"] = pk
                pr = self.patterns.rows.get(pk)
                if pr:
                    pr["count"] += 1
                    pr["last"] = now
                    self.patterns.dirty.add(pk)
            a.event = d
            if ev.source == "monitor" or ev.kind == "security" or ev.attrs.get("move"):   # 요약 문장(횟수·계정·VM 등)이 갱신되는 이벤트
                a.title = self._title(ev, category)
            up = SEV_RANK[sev] > SEV_RANK[a.severity]
            if up:
                a.severity = sev
            d["anomaly_id"] = a.id
            self._fast_push(a, force=up)
            self._enqueue_pub(a)
            return
        a = Anomaly(id=f"A{int(now * 1000)}{ev.id % 1000:03d}", event=d, severity=sev, category=category,
                    title=self._title(ev, category), reasons=ev.reasons, score=score, context=context, fp=fp)
        d["anomaly_id"] = a.id
        self.anomalies[a.id] = a
        self.by_fp[fp] = a.id
        self.stats["anomalies_total"] += 1
        if len(self.anomalies) > 2000:  # 메모리 상한
            for k in sorted(self.anomalies, key=lambda k: self.anomalies[k].last_seen)[:200]:
                old = self.anomalies.pop(k, None)
                if old and self.by_fp.get(old.fp) == k:
                    self.by_fp.pop(old.fp, None)
                self._fast_pub.pop(k, None)
        if ev.source in ("aiops", "monitor") or ev.attrs.get("fg_synthetic"):   # 플랫폼·모니터·방화벽 집계 경보(결정적 규칙)는 LLM 불필요(용량 보존)
            a.status = "rule_only"
        elif self.llm and not self.ai_on:
            a.status = "rule_only"
            a.ai = {"off": True, "error": "AI 분석 꺼짐 — 규칙 탐지로 처리"}
        elif self.llm and self._llm_blocked():
            a.status = "rule_only"
            a.ai = {"error": f"LLM 일시 차단 — 규칙 탐지로 처리({self.llm_breaker.last_error[:120]})"}
        elif self.llm:
            pr = self.patterns.observe(ev.source, ev.template, ev.message, ev.host, ev.entity, sev)   # 패턴별 분류
            d["pattern"] = pr["key"]
            hit = None if pr["excluded"] else self.patterns.cached(pr, sev, self.knowledge.gen if self.knowledge.enabled else 0)
            if pr["excluded"]:
                a.status = "rule_only"
                a.ai = {"error": "이 로그 패턴은 AI 분석 제외로 설정됨", "skipped": True, "pattern": pr["key"]}
            elif hit:                                  # 이미 분석한 패턴 → LLM 호출 없이 재사용
                a.status = "analyzed"
                a.ai = {**hit, "cached": True, "pattern": pr["key"], "pattern_count": pr["count"]}
                if hit.get("category"):
                    a.category = hit["category"]
                s2 = str(hit.get("severity", "")).lower()
                if s2 in SEV_RANK:
                    a.severity = s2
            else:
                a.status = "queued"
                r = self.aq.put(a.id, sev, ev.source, pr["key"])
                if r.startswith("skipped"):
                    a.status = "llm_skipped"
                    a.ai = {"error": r.split(":", 1)[1], "skipped": True, "pattern": pr["key"]}
                elif r == "coalesced":
                    a.ai = {"coalesced": True, "pattern": pr["key"]}
                else:
                    self.patterns.set_state(pr["key"], "queued")
        else:
            a.status = "rule_only"
        self._fast_push(a, force=True)
        self._enqueue_pub(a)

    def _llm_blocked(self) -> bool:
        b = self.llm_breaker
        return b.state == "open" and time.time() - b.opened < b.reset

    def _fast_push(self, a: Anomaly, force: bool = False) -> None:
        """신규·심각도 상향은 즉시, 재발 카운트 갱신은 이상징후당 1초에 1회만 화면에 푸시"""
        now = time.time()
        if force or now - self._fast_pub.get(a.id, 0) >= 1.0:
            self._fast_pub[a.id] = now
            self.hub.publish({"type": "anomaly", "data": a.to_dict()})

    def _enqueue_pub(self, a: Anomaly) -> None:
        self._pub[a.id] = True
        self._pub.move_to_end(a.id)
        self._pub_wake.set()

    async def publisher(self) -> None:
        """이상징후 게시 워커 — 억제 판정·인시던트 상관·저장·외부 알림. DB/외부 지연이 수집 처리를 막지 않는다."""
        while True:
            if not self._pub:
                self._pub_wake.clear()
                try:
                    await asyncio.wait_for(self._pub_wake.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
            self.sup.beat("publisher")
            self.pipe["pub_backlog"] = len(self._pub)
            for _ in range(min(len(self._pub), 100)):
                aid, _v = self._pub.popitem(last=False)
                a = self.anomalies.get(aid)
                if not a:
                    continue
                try:
                    await self._publish_anomaly(a)
                except Exception as e:  # noqa: BLE001
                    self.pipe["errors"] += 1
                    self.pipe["last_error"] = f"publish {type(e).__name__}: {e}"[:300]
            await asyncio.sleep(0)

    def _llm_pending(self, a: Anomaly) -> bool:
        """LLM 판정을 기다렸다가 인시던트·알림을 낼지. 위험(critical)은 기본적으로 기다리지 않는다(실시간 우선)."""
        if a.status not in ("queued", "analyzing"):
            return False
        al = self.cfg["alerting"]
        if al.get("require_llm_confirm"):
            return time.time() - a.created < float(al.get("llm_confirm_max_wait", 300))
        if a.severity == "critical" and al.get("critical_immediate", True):
            return False
        return time.time() - a.created < float(al.get("llm_wait_seconds", 30))

    async def pending_sweeper(self) -> None:
        """LLM 대기 시간이 지났는데 아직 인시던트·알림 단계를 못 거친 이상징후를 게시 큐로 — LLM 적체 시 알림 누락 방지"""
        while True:
            await asyncio.sleep(5)
            self.sup.beat("sweeper")
            for a in list(self.anomalies.values()):
                if not a.notified and not a.ack and a.status in ("queued", "analyzing") and not self._llm_pending(a):
                    self._enqueue_pub(a)
            cut = time.time() - 600
            for k in [k for k, t in self._fast_pub.items() if t < cut]:
                self._fast_pub.pop(k, None)

    @staticmethod
    def _title(ev: LogEvent, category: str) -> str:
        from .models import PER_HOST_SOURCES
        tgt = (ev.host or ev.entity) if ev.source in PER_HOST_SOURCES else (ev.entity or ev.host or ev.connector)
        msg = ev.message.replace("\n", " ")
        if ev.source == "monitor" or ev.kind == "security" or ev.attrs.get("move"):   # 이미 대상이 들어간 요약 문장
            return msg[:110]
        return f"{tgt}: {msg[:70]}"

    async def _publish_anomaly(self, a: Anomaly, fp: str | None = None) -> None:
        fp = fp or a.fp or self._fp_of(a)
        d0 = a.to_dict()
        try:
            a.suppressed = self.incidents.suppression(d0, fp) or ""
        except Exception:  # noqa: BLE001
            a.suppressed = ""
        pending = self._llm_pending(a)
        if not pending:
            try:
                inc = await self.incidents.on_anomaly(a.to_dict(), fp, a.suppressed or None)
                if inc:
                    a.incident_id = inc["id"]
            except Exception as e:  # noqa: BLE001
                print(f"[incidents] 처리 오류: {type(e).__name__}: {e}", flush=True)
            a.notified = True
        ad = a.to_dict()
        await self.store.save_anomaly(ad)
        self.hub.publish({"type": "anomaly", "data": ad})
        if not pending and not a.suppressed and self.alerter.should_alert(ad, fp):
            a.alerted = True
            await self.alerter.fire(ad, fp)

    # ---------------------------------------------------------------- LLM 워커
    def _ai_skip(self, aid: str, why: str) -> None:
        """대기열이 분석을 생략한 이상징후 — 규칙 탐지 결과로 게시"""
        a = self.anomalies.get(aid)
        if a and a.status == "queued":
            a.status = "llm_skipped"
            a.ai = {"error": why, "skipped": True}
            self._fast_push(a, force=True)
            self._enqueue_pub(a)

    def _share(self, rep: Anomaly, fol: list[str], status: str, ai: dict) -> None:
        """병합된 이상징후에 대표 분석 결과 복사(같은 소스·같은 로그 패턴)"""
        for f in fol:
            x = self.anomalies.get(f)
            if not x or x.status not in ("queued", "analyzing"):
                continue
            x.status = status
            x.ai = {**ai, "shared_from": rep.id, "shared_title": rep.title} if status == "analyzed" else dict(ai)
            if status == "analyzed":
                if ai.get("category"):
                    x.category = ai["category"]
                s = str(ai.get("severity", "")).lower()
                if s in SEV_RANK:
                    x.severity = s
            self._enqueue_pub(x)

    async def llm_worker(self, name: str = "llm") -> None:
        tmo = float(self.cfg["llm"].get("timeout", 120)) + 15
        while True:
            ids = await self.aq.get_batch(5.0)
            self.sup.beat(name)
            if not ids:
                continue
            manual = any((self.aq.items.get(i) or {}).get("prio") == 0 for i in ids)
            fol = {i: self.aq.take(i) for i in ids}
            batch = [self.anomalies[i] for i in ids if i in self.anomalies and self.anomalies[i].status == "queued"]
            for i in ids:                                     # 대표가 사라졌거나(정리) 상태가 바뀐 경우 병합분은 다시 대기열로
                if i not in self.anomalies or self.anomalies[i].status != "queued":
                    for f in fol.pop(i, []):
                        x = self.anomalies.get(f)
                        if x and x.status == "queued":
                            r = self.aq.put(f, x.severity, (x.event or {}).get("source", ""), (x.event or {}).get("pattern", ""))
                            if r.startswith("skipped"):
                                self._ai_skip(f, r.split(":", 1)[1])
            if not batch:
                continue
            if not self.llm or (not self.ai_on and not manual):   # 꺼짐(또는 LLM 해제) → 규칙 탐지로 게시
                for a in batch:
                    a.status = "rule_only"
                    a.ai = {"off": True, "error": "AI 분석 꺼짐 — 규칙 탐지로 처리"}
                    self._enqueue_pub(a)
                    self._share(a, fol.get(a.id, []), "rule_only", a.ai)
                continue
            if not self.llm_breaker.allow():                 # LLM 장애 중 → 기다리지 않고 규칙 탐지 결과로 게시
                for a in batch:
                    a.status = "rule_only"
                    a.ai = {"error": f"LLM 일시 차단 — 규칙 탐지로 처리({self.llm_breaker.last_error[:120]})"}
                    self._enqueue_pub(a)
                    self._share(a, fol.get(a.id, []), "rule_only", a.ai)
                continue
            p = self.llm.primary("analyze") if hasattr(self.llm, "primary") else None
            if p:                                             # GPU 발열·호출량 조절(쿨다운·시간당 상한·과열 중지)
                await self.gov.acquire(p, interactive=manual)
            batch = [a for a in batch if a.status == "queued"]
            if not self.ai_on and not manual:
                for a in batch:
                    self._ai_skip(a.id, "AI 분석 꺼짐 — 규칙 탐지로 처리")
                continue
            for a in batch:
                a.status = "analyzing"
                self.hub.publish({"type": "anomaly", "data": a.to_dict()})
            await self._attach_refs(batch)
            t0 = time.time()
            try:
                chg = {a.id: await self.vm_changes_for(a.event) for a in batch}
                res = await asyncio.wait_for(self.llm.analyze([{"id": a.id, "event": a.event, "context": a.context,
                                                                "reasons": a.reasons, "refs": a.refs, "changes": chg[a.id]["lines"],
                                                                "change_names": chg[a.id]["names"]} for a in batch],
                                                              interactive=manual, governed=False), tmo)
                self.llm_breaker.ok()
                self.aq.record(len(batch), time.time() - t0)
                for a in batch:
                    r = res.get(a.id)
                    if not r:
                        a.status = "llm_error"
                        a.ai = {"error": "응답에 해당 id 결과 없음"}
                    else:
                        a.status = "analyzed"
                        used = {str(x) for x in (r.get("references") or [])}
                        from .knowledge import guard_kb_numbers
                        bad = guard_kb_numbers(r, [ref for ref in a.refs if ref["ref"] in used] or a.refs)
                        if bad:
                            r["unverified_kb"] = bad
                        r["references"] = [{k: ref.get(k, "") for k in ("ref", "title", "url", "type", "pack_name", "score", "kb", "doc_id",
                                                                        "section", "sections", "versions", "product")}
                                           for ref in a.refs if ref["ref"] in used]
                        r["_kgen"] = self.knowledge.gen if self.knowledge.enabled else 0     # 분석 당시 지식 세대
                        pk = (a.event or {}).get("pattern")
                        if pk:
                            self.patterns.save_analysis(pk, r, (a.event or {}).get("severity", a.severity))
                            r["pattern"] = pk
                        if fol.get(a.id):
                            r["shared_count"] = len(fol[a.id])
                        a.ai = r
                        if r.get("title"):
                            a.title = r["title"]
                        if r.get("category"):
                            a.category = r["category"]
                        s = str(r.get("severity", "")).lower()
                        if s in SEV_RANK:
                            a.severity = s
                    self._enqueue_pub(a)
                    self._share(a, fol.get(a.id, []), a.status, a.ai)
            except Exception as e:  # noqa: BLE001
                self.llm_breaker.fail(f"{type(e).__name__}: {e}")
                for a in batch:
                    a.status = "llm_error"
                    a.ai = {"error": f"{type(e).__name__}: {e}"[:300]}
                    self._enqueue_pub(a)
                    self._share(a, fol.get(a.id, []), "llm_error", a.ai)
                    pk = (a.event or {}).get("pattern")
                    if pk:
                        self.patterns.set_state(pk, "error")

    async def set_ai(self, on: bool) -> dict:
        """메인 화면 'AI 분석' 토글 — 끄면 대기 중 분석을 규칙 탐지 결과로 즉시 게시(GPU 사용 0)"""
        self.ai_on = bool(on)
        flushed = 0
        if not on:
            for aid in list(self.aq.items):
                fol = self.aq.take(aid)
                for x in [aid] + fol:
                    a = self.anomalies.get(x)
                    if a and a.status == "queued":
                        self._ai_skip(x, "AI 분석 꺼짐 — 규칙 탐지로 처리")
                        flushed += 1
        self.hub.publish({"type": "ai_state", "data": self.ai_state()})
        return {"on": self.ai_on, "flushed": flushed}

    def ai_state(self) -> dict:
        p = self.llm.primary("analyze") if self.llm else None
        q = self.aq.snapshot()
        return {"on": self.ai_on, "available": bool(self.llm), "provider": p.name if p else "", "model": p.model if p else "",
                "provider_state": p.status.get("state") if p else "disabled", "external": bool(p and p.external),
                "queue": q["depth"], "rate_per_min": q["rate_per_min"], "hot": self.gov.hot, "waiting": self.gov.waiting_reason,
                "gpu_temp": (self.gov.gpu or {}).get("temp_max"), "patterns": self.patterns.summary()}

    async def _attach_refs(self, batch: list[Anomaly]) -> None:
        """활성 RAG 팩에서 이벤트 소스에 맞는 팩만 골라 근거 문서를 검색해 후보에 붙인다."""
        if not self.cfg["rag"].get("enabled") or not self.rag.has_any():
            return
        from .knowledge import doc_sig, kb_query_of
        for a in batch:
            e = a.event
            q = kb_query_of(e, a.reasons)
            try:
                hits = await self.rag.search(q, source=e.get("source"), intent="analyze", sig=doc_sig(e))
            except Exception:  # noqa: BLE001
                hits = []
            a.refs = [{**h, "ref": f"R{i}"} for i, h in enumerate(hits, 1)]

    def _fp_of(self, a: Anomaly) -> str:
        if a.fp:
            return a.fp
        for fp, aid in self.by_fp.items():
            if aid == a.id:
                return fp
        return a.id

    async def reanalyze(self, aid: str) -> bool:
        a = self.anomalies.get(aid)
        if not a or not self.llm:
            return False
        a.status = "queued"
        r = self.aq.put(aid, a.severity, (a.event or {}).get("source", ""), manual=True)
        if r.startswith("skipped"):
            a.status = "llm_skipped"
            return False
        self.hub.publish({"type": "anomaly", "data": a.to_dict()})
        return True

    async def ack(self, aid: str) -> bool:
        a = self.anomalies.get(aid)
        if not a:
            return False
        a.ack = True
        ad = a.to_dict()
        await self.store.save_anomaly(ad)
        self.hub.publish({"type": "anomaly", "data": ad})
        return True

    async def silence(self, aid: str, hours: float, reason: str, user: str) -> int:
        a = self.anomalies.get(aid)
        if not a:
            raise KeyError(aid)
        sid = await self.store.x("INSERT INTO silences(match,until,reason,created_by,created) VALUES(?,?,?,?,?)",
                                 (json.dumps({"fingerprint": self._fp_of(a), "sample": a.title}, ensure_ascii=False),
                                  time.time() + hours * 3600, reason[:200], user, time.time()))
        await self.incidents.reload_suppression()
        return sid

    # ---------------------------------------------------------------- 토폴로지·조사(vCenter 커넥터 위임)
    def _vcenters(self) -> list[Any]:
        return [c for c in self.connectors if getattr(c, "type", "") == "vcenter" and hasattr(c, "resolve")]

    def resolve(self, name: str) -> dict | None:
        if not name:
            return None
        for c in self._vcenters():
            r = c.resolve(name)
            if r:
                return r
        return None

    def topology_host(self, name: str) -> dict | None:
        for c in self._vcenters():
            h = c.topology["hosts"].get(name)
            if h:
                return h
        return None

    async def vm_changes_for(self, ev: dict, hours: float = 2, limit: int = 8) -> dict[str, list[str]]:
        """이상징후 직전 VM 변경(대상 VM·같은 호스트) — AI 판정에 '최근 변경' 근거로 전달.
        {"lines": 한 줄 요약, "names": 외부 AI 가명화 대상(VM·호스트·사용자·원본 이름)}"""
        try:
            names = {ev.get("entity") or "", ev.get("host") or ""}
            ctx = self.resolve(ev.get("entity") or "") or self.resolve(ev.get("host") or "") or {}
            hosts = {ctx.get("host") or "", ev.get("host") or ""} if ctx.get("kind") != "cluster" else set()
            if ctx.get("kind") == "host":
                hosts.add(ctx.get("name") or "")
            ts = float(ev.get("ts") or time.time())
            rows = await self.moves.related(names | {ctx.get("name") or ""}, hosts, (), ts - hours * 3600, ts + 60, limit)
            return {"lines": self.moves.brief(rows), "names": self.moves.names_of(rows)}
        except Exception as ex:  # noqa: BLE001
            print(f"[vm-activity] 직전 변경 조회 오류: {type(ex).__name__}: {ex}", flush=True)
            return {"lines": [], "names": []}

    async def investigate(self, kind: str, name: str, hours: int = 24) -> dict:
        for c in self._vcenters():
            if c.resolve(name):
                return await asyncio.to_thread(c.investigate, kind, name, hours)
        return {"error": f"'{name}' 을(를) 토폴로지에서 찾을 수 없습니다(vCenter 커넥터·토폴로지 갱신 확인)"}

    # ---------------------------------------------------------------- 커넥터 수명주기(설정 화면 핫리로드)
    # ---------------------------------------------------------------- Redfish push 수신 토큰
    def _event_key(self) -> bytes:
        import os
        import secrets as _s
        from pathlib import Path
        p = Path(self.cfg["server"]["db_path"]).parent / "redfish-events.key"
        if not p.exists():
            p.write_bytes(_s.token_bytes(32))
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        return p.read_bytes()

    def event_token(self, name: str) -> str:
        import hashlib
        import hmac as _h
        return _h.new(self._event_key(), f"redfish|{name}".encode(), hashlib.sha256).hexdigest()[:40]

    def prepare_connector(self, c) -> None:
        """BMC 가 이벤트를 보낼 수신 주소 주입(push) — agents.public_url 또는 server.public_url 기준"""
        if getattr(c, "type", "") == "redfish":
            base = ((self.cfg.get("agents") or {}).get("public_url") or self.cfg["server"].get("public_url") or "").rstrip("/")
            c.event_url = f"{base}/api/redfish/events/{self.event_token(c.name)}" if base else ""
        if getattr(c, "type", "") == "vcenter":
            c.bmc_provider = self.bmc_inventory

    def bmc_inventory(self) -> dict[str, dict]:
        """ESXi 호스트 이름 → 같은 서버 BMC(Redfish·CIMC) 커넥터의 펌웨어·상태 — vCenter 하드웨어 점검과 연계"""
        from .stack import host_for_hw
        out: dict[str, dict] = {}
        for c in self.connectors:
            if getattr(c, "type", "") != "redfish" or not c.enabled:
                continue
            s = getattr(c, "server", {}) or {}
            keys = {k for k in (c.cfg.get("esxi_host"), c.cfg.get("server_name"), s.get("hostname"), getattr(c, "display", "")) if k}
            v = {"connector": c.name, "bmc": c.host, "bmc_fw": s.get("bmc_fw", ""), "bios": s.get("bios", ""),
                 "health": s.get("health", ""), "model": s.get("model", ""), "serial": s.get("serial", ""),
                 "firmware": list(getattr(c, "firmware", []) or [])}
            for k in keys:
                out[str(k)] = v
            hn = host_for_hw(self.connectors, s.get("uuid", ""), s.get("serial", ""))   # esxi_host 미설정이어도 UUID·S/N 으로 자동 연결
            if hn:
                out.setdefault(hn, v)
        for c in self.connectors:                                            # Cisco UCS Manager 블레이드·랙(서비스 프로필)
            if getattr(c, "type", "") != "ucsm" or not c.enabled:
                continue
            for b in c.servers():
                v = {"connector": c.name, "bmc": c.host, "bmc_fw": "", "bios": "", "model": b.get("model", ""), "serial": b.get("serial", ""),
                     "health": {"down": "Critical", "warn": "Warning"}.get(b.get("state"), "OK"), "firmware": []}
                hn = host_for_hw(self.connectors, b.get("uuid", ""), b.get("serial", "")) or b.get("profile")
                if hn:
                    out.setdefault(hn, v)
        return out

    def _host_for_hw(self, uuid: str, serial: str) -> str:
        from .stack import host_for_hw
        return host_for_hw(self.connectors, uuid, serial)
        for c in self.connectors:
            if getattr(c, "type", "") != "vcenter":
                continue
            for hn, h in (getattr(c, "topology", {}) or {}).get("hosts", {}).items():
                if (us and str(h.get("uuid", "")).lower() in us) or (ser and str(h.get("serial", "")).lower() == ser):
                    return hn
        return ""

    def redfish_by_token(self, token: str):
        import hmac as _h
        for c in self.connectors:
            if getattr(c, "type", "") == "redfish" and _h.compare_digest(self.event_token(c.name), token):
                return c
        return None

    def start_connectors(self) -> None:
        for c in self.connectors:
            self.prepare_connector(c)
            if c.name not in self.conn_tasks and c.enabled:
                self.conn_tasks[c.name] = self.sup.spawn(f"conn:{c.name}", c.run, critical=False)

    async def reload_polling_connectors(self, defs: list[dict]) -> dict:
        """폴링 커넥터만 재구성(syslog·SNMP 수신기는 포트 유지). 변경 없는 커넥터는 그대로 둔다."""
        from . import connectors as reg
        new_objs = reg.build({**self.cfg, "connectors": defs, "syslog": {"enabled": False}, "snmp": {"enabled": False},
                              "demo": {"enabled": False}}, self.ingest)
        new_by = {c.name: c for c in new_objs}
        keep_types = ("syslog", "snmp", "demo")
        old_poll = {c.name: c for c in self.connectors if c.type not in keep_types and not c.name.startswith("demo-")
                    and not getattr(c, "discovered_by", "")}          # VKS 자동 발견 커넥터는 발견 루프가 관리
        changed, added, removed = [], [], []
        for name, c in old_poll.items():
            if name not in new_by or new_by[name].cfg != c.cfg:
                self.conn_tasks.pop(name, None)
                self.sup.cancel(f"conn:{name}")
                self.connectors.remove(c)
                if getattr(c, "_http", None):
                    bg(c._http.aclose())
                (changed if name in new_by else removed).append(name)
        for name, c in new_by.items():
            if name not in old_poll or name in changed:
                self.prepare_connector(c)
                self.connectors.append(c)
                if c.enabled:
                    self.conn_tasks[name] = self.sup.spawn(f"conn:{name}", c.run, critical=False)
                if name not in changed:
                    added.append(name)
        pruned = self.prune_discovered()
        if added or changed or removed:
            bg(self.discover_vks_once())                # 새·바뀐 vCenter 의 Supervisor 를 바로 찾기
        return {"added": added, "changed": changed, "removed": removed, "pruned": pruned}

    def _drop_connector(self, c) -> None:
        self.conn_tasks.pop(c.name, None)
        self.sup.cancel(f"conn:{c.name}")
        if c in self.connectors:
            self.connectors.remove(c)
        if getattr(c, "_http", None):
            bg(c._http.aclose())

    def prune_discovered(self) -> list[str]:
        """자동 발견 커넥터 중 만든 vCenter 가 없어졌거나(삭제·비활성·발견 끔) 제외 목록에 든 것을 즉시 정리"""
        live_vc = {c.name for c in self.connectors if c.type == "vcenter" and c.enabled and c.cfg.get("vks_discovery", True) is not False}
        excl = set((self.cfg.get("vks_overrides") or {}).get("excluded") or [])
        out = []
        for c in [c for c in self.connectors if getattr(c, "discovered_by", "")]:
            if c.discovered_by not in live_vc or c.name in excl:
                self._drop_connector(c)
                out.append(c.name)
        return out

    # ---------------------------------------------------------------- VKS 자동 발견
    async def discover_vks_once(self) -> dict:
        """vCenter 커넥터 → Supervisor(엔드포인트·네임스페이스) → Supervisor 의 CAPI 클러스터(워크로드) 를 찾아
        VKS 커넥터를 자동으로 만들고/갱신/제거한다. 자격 증명은 vCenter 커넥터 계정(vSphere SSO, /wcp/login)."""
        import re as _re
        from .connectors.kubernetes import VksConnector
        safe = lambda x: _re.sub(r"[^A-Za-z0-9._-]+", "-", x).strip("-")[:120]   # noqa: E731
        want: dict[str, dict] = {}
        report: dict[str, Any] = {"vcenters": {}, "added": [], "removed": [], "changed": []}
        by_name = {c.name: c for c in self.connectors}
        for vc in [c for c in self.connectors if c.type == "vcenter" and c.enabled and c.cfg.get("vks_discovery", True) is not False
                   and hasattr(c, "vks_targets")]:          # 데모 가상 커넥터 제외
            try:
                sups = await vc.vks_targets()
                vc._state["checks"].pop("VKS 발견", None)
            except Exception as e:  # noqa: BLE001
                vc.vks = {**getattr(vc, "vks", {}), "error": f"{type(e).__name__}: {e}"[:300]}
                vc._state["checks"]["VKS 발견"] = f"warn: {type(e).__name__}: {e}"[:150]
                report["vcenters"][vc.name] = f"error: {e}"[:200]
                # 실패 시 기존 발견 커넥터는 유지(일시 장애로 지우지 않음)
                for c in self.connectors:
                    if getattr(c, "discovered_by", "") == vc.name:
                        want[c.name] = c.cfg
                continue
            report["vcenters"][vc.name] = f"supervisors {len(sups)}"
            common = {"auth": "vsphere", "username": vc.cfg.get("username", ""), "password": vc.cfg.get("password", ""),
                      "verify_tls": vc.verify, "discovered_by": vc.name, "interval": int(vc.cfg.get("vks_interval", 30)),
                      "log_namespaces": list(vc.cfg.get("vks_log_namespaces") or []), "environment": vc.cfg.get("environment", "")}
            for sp in sups:
                if not sp["endpoint"]:
                    continue
                sn = safe(f"{vc.name}-sv-{sp['name']}")
                want[sn] = {**common, "name": sn, "type": "vks", "role": "supervisor", "host": sp["endpoint"],
                            "api_url": f"https://{sp['endpoint']}:6443", "supervisor": sp["endpoint"],
                            "cluster_name": f"Supervisor {sp['name']}", "namespaces": sp["namespaces"]}
                svc = by_name.get(sn)
                for cl in (getattr(svc, "inv", {}) or {}).get("clusters", []) if svc else []:
                    if not cl.get("endpoint"):
                        continue
                    wn = safe(f"{vc.name}-{cl['ns']}-{cl['name']}")
                    want[wn] = {**common, "name": wn, "type": "vks", "role": "workload", "host": cl["endpoint"],
                                "api_url": f"https://{cl['endpoint']}", "supervisor": sp["endpoint"],
                                "guest_cluster_name": cl["name"], "guest_cluster_namespace": cl["ns"],
                                "cluster_name": f"{cl['ns']}/{cl['name']}"}
        ov = self.cfg.get("vks_overrides") or {}
        for n in list(ov.get("excluded") or []):        # 화면에서 삭제(제외)한 발견 커넥터는 다시 만들지 않음
            want.pop(n, None)
        for n, o in (ov.get("overrides") or {}).items():  # 화면에서 편집한 값(주기·로그 네임스페이스·계정 등)을 덮어씀
            if n in want and isinstance(o, dict):
                want[n] = {**want[n], **{k: v for k, v in o.items() if k not in ("name", "type", "discovered_by", "role")}}
        self.vks_report = {**report, "at": time.time(), "want": sorted(want)}
        existing = {c.name: c for c in self.connectors if getattr(c, "discovered_by", "") and not getattr(c, "demo", False)}   # 데모 개체는 유지
        for name, c in existing.items():
            if name not in want or want[name] != c.cfg:
                self.conn_tasks.pop(name, None)
                self.sup.cancel(f"conn:{name}")
                self.connectors.remove(c)
                if getattr(c, "_http", None):
                    bg(c._http.aclose())
                (report["changed"] if name in want else report["removed"]).append(name)
        for name, cfg in want.items():
            if name in existing and name not in report["changed"]:
                continue
            c = VksConnector(cfg, self.ingest)
            self.prepare_connector(c)
            self.connectors.append(c)
            self.conn_tasks[name] = self.sup.spawn(f"conn:{name}", c.run, critical=False)
            if name not in report["changed"]:
                report["added"].append(name)
        return report

    async def vks_discovery_loop(self) -> None:
        await asyncio.sleep(15)
        while True:
            try:
                rep = await self.discover_vks_once()
                if rep["added"] or rep["removed"] or rep["changed"]:
                    print(f"[vks] 자동 발견: 추가 {rep['added']} 변경 {rep['changed']} 제거 {rep['removed']}", flush=True)
                    if rep["added"]:                    # 새 Supervisor 의 워크로드 클러스터는 CAPI 조회 후 다음 회차에 → 빨리 한 번 더
                        await asyncio.sleep(60)
                        continue
            except Exception as e:  # noqa: BLE001
                print(f"[vks] 자동 발견 오류: {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(float((self.cfg.get("vks") or {}).get("discovery_interval", 600)))

    async def avi_metrics_loop(self) -> None:
        """NSX ALB VIP(가상 서비스)별 실시간 트래픽 — 기본 10초마다 수집해 화면(WebSocket avi_vips)으로 푸시"""
        import httpx
        await asyncio.sleep(10)
        while True:
            iv = 10.0
            for c in [c for c in self.connectors if c.type == "avi" and c.enabled and getattr(c, "vs", None)]:
                iv = min(iv, float(c.cfg.get("metrics_interval", 10)))
                try:
                    await asyncio.wait_for(c.vip_metrics(), timeout=30)
                except httpx.HTTPStatusError:
                    try:
                        await c.login()
                        await asyncio.wait_for(c.vip_metrics(), timeout=30)
                    except Exception as e:  # noqa: BLE001
                        self._vip_fail(c, f"재로그인 후에도 실패: {type(e).__name__}: {e}")
                except Exception as e:  # noqa: BLE001
                    self._vip_fail(c, f"{type(e).__name__}: {e}")
            vips = self.avi_vips()
            if vips:
                self.hub.publish({"type": "avi_vips", "data": [{k: v for k, v in x.items() if k != "members"} for x in vips[:200]]})
            await asyncio.sleep(max(3.0, iv))

    @staticmethod
    def _vip_fail(c, msg: str) -> None:
        c._state.setdefault("checks", {})["VIP 메트릭"] = f"실패: {msg}"[:300]
        for v in (getattr(c, "vs", {}) or {}).values():
            if not v.get("updated"):
                v["mnote"] = msg[:200]

    def avi_vips(self) -> list[dict]:
        out: list[dict] = []
        for c in self.connectors:
            if c.type == "avi" and c.enabled and hasattr(c, "vips"):
                out += c.vips()
        return out

    # ---------------------------------------------------------------- 실시간 푸시
    async def broadcast(self, msg: dict) -> None:
        self.hub.publish(msg)

    async def flusher(self) -> None:
        """로그는 250ms 단위로 묶어 전송(브라우저 부하 감소), 1초마다 상태 전송(화면의 하트비트 겸용)."""
        tick = 0
        while True:
            await asyncio.sleep(0.25)
            tick += 1
            self.sup.beat("flusher")
            if self._pending_ws:
                full, self._pending_ws = self._pending_ws, []
                self.hub.publish({"type": "logs", "data": full[-300:]})   # 대시보드용 표본
                self.hub.publish_tail(full)                               # 실시간 로그 보기: 필터 일치분 전량
            if tick % 40 == 0:
                try:
                    rows = await asyncio.wait_for(self.store.q(
                        "SELECT severity, COUNT(*) AS n FROM incidents WHERE status IN "
                        "('open','acknowledged','investigating') GROUP BY severity"), 5)
                    self.incidents_active = {r["severity"]: r["n"] for r in rows}
                except Exception:  # noqa: BLE001
                    pass
            if tick % 4 == 0:
                self.stats["eps"] = self._eps_count
                self._eps_count = 0
                self.hub.publish({"type": "status", "data": self.status()})

    def _ai_brief(self) -> dict[str, Any]:
        q = self.aq.snapshot()
        return {k: q[k] for k in ("depth", "unique", "rate_per_min", "eta_min", "oldest_wait_s", "by_severity")} | {
            "skipped": sum(q["stats"].get(k, 0) for k in ("shed", "quota", "full", "aged", "dropped")), "coalesced": q["stats"].get("coalesced", 0)}

    def runtime(self) -> dict[str, Any]:
        """플랫폼 자체 상태(화면 상단 '플랫폼' 표시·/api/health)"""
        h = self.health.state if self.health else {"state": "ok", "issues": []}
        return {"state": h["state"], "issues": h["issues"][:6], "lag": self.lag.stats(),
                "pipeline": {"high": len(self.q_hi), "low": len(self.q_lo), "dropped": self.pipe["dropped_low"] + self.pipe["dropped_high"],
                             "lag_ms": self.pipe["lag_ms"], "pub_backlog": len(self._pub),
                             "aggregated": self.pipe.get("aggregated", 0)},
                "store": {k: self.store.stats[k] for k in ("state", "disk_free_mb", "disk_low", "logs_dropped", "write_errors")}
                | {"backlog": self.store.backlog},
                "ws": {"clients": len(self.hub), "kicked": self.hub.stats["kicked_slow"] + self.hub.stats["kicked_dead"]},
                "llm_breaker": self.llm_breaker.state,
                "ai": self._ai_brief(),
                "ha": self.ha.public() if self.ha else {"enabled": False},
                "build": getattr(self, "build", ""), "boot": self.stats["started"]}

    def status(self) -> dict[str, Any]:
        return {
            "stats": self.stats,
            "rates": self.detector.rates(),
            "connectors": [c.state() for c in self.connectors],
            "llm": (self.llm.status | {"breaker": self.llm_breaker.status()}) if self.llm else {"state": "disabled"},
            "queue": self.aq.depth(),
            "ai_queue": self.aq.snapshot(),
            "ai": {"on": self.ai_on, "available": bool(self.llm), "hot": self.gov.hot, "waiting": self.gov.waiting_reason},
            "collection": self.collection.summary(),
            "alerts_sent": self.alerter.sent_total,
            "incidents_active": self.incidents_active,
            "rag": {"enabled_packs": list(self.rag.loaded), "chunks": sum(len(p.chunks) for p in self.rag.loaded.values()),
                    "embedding": self.rag.embedder.status.get("state")},
            "runtime": self.runtime(),
        }

    async def llm_health_loop(self) -> None:
        while True:
            self.sup.beat("llm-health")
            if self.llm:
                try:
                    await asyncio.wait_for(self.llm.health(), 30)
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(60)

    def reconfigure_llm(self, cfg: dict) -> dict:
        """운영 설정 › AI 저장 시 즉시 반영(공급자·라우팅·조절기·패턴·대기열) — 재기동 불필요"""
        self.cfg["llm"] = cfg
        if cfg.get("enabled"):
            if self.llm:
                self.llm.configure(cfg)
            else:
                self.llm = LLMClient(cfg)
                self.llm.cfg.setdefault("max_chars_per_ref", self.cfg["rag"].get("max_chars_per_ref", 1200))
            self.llm.gov = self.gov
        else:
            self.llm = None
        self.aq.configure(cfg)
        self.gov.configure(cfg.get("governor") or {})
        self.patterns.configure(cfg)
        if "analysis_enabled" in cfg:
            self.ai_on = cfg.get("analysis_enabled") is not False
        self.hub.publish({"type": "ai_state", "data": self.ai_state()})
        return {"providers": list(self.llm.providers) if self.llm else [], "routing": self.llm.status["routing"] if self.llm else {}}
