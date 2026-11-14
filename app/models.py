"""공통 데이터 모델 — 모든 커넥터는 LogEvent로 정규화해서 버스에 넣는다."""
from __future__ import annotations

import hashlib
import itertools
import time
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["debug", "info", "warning", "error", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_seq = itertools.count(1)


def norm_severity(value: Any, default: str = "info") -> str:
    """제품마다 다른 심각도 표기를 5단계로 정규화."""
    if value is None:
        return default
    v = str(value).strip().lower()
    table = {
        # syslog 숫자(0~7)
        "0": "critical", "1": "critical", "2": "critical", "3": "error",
        "4": "warning", "5": "info", "6": "info", "7": "debug",
        # 공통 문자열
        "emerg": "critical", "emergency": "critical", "alert": "critical", "crit": "critical",
        "critical": "critical", "fatal": "critical", "red": "critical",
        "err": "error", "error": "error", "major": "error", "high": "error", "immediate": "error",
        "warn": "warning", "warning": "warning", "minor": "warning", "medium": "warning",
        "yellow": "warning", "degraded": "warning",
        "notice": "info", "info": "info", "informational": "info", "information": "info",
        "low": "info", "ok": "info", "green": "info", "none": "info",
        "debug": "debug", "trace": "debug", "verbose": "debug",
        # Avi
        "alert_high": "error", "alert_medium": "warning", "alert_low": "info",
        # VCF Operations criticality
        "symptom": "warning", "automatic": "info",
    }
    return table.get(v, default)


@dataclass
class LogEvent:
    source: str            # 제품 계열: vcenter, nsx, vcfops, vcflogs, vcfa, srm, avi, sddc, redfish, syslog, ingest
    connector: str         # 커넥터 인스턴스 이름(config의 name)
    message: str
    severity: str = "info"
    host: str = ""
    entity: str = ""       # VM/호스트/VS 등 대상 객체
    kind: str = "log"      # log | event | alarm | alert | task | health
    ts: float = field(default_factory=time.time)
    native_id: str = ""    # 원본 시스템의 ID(중복 제거용)
    attrs: dict[str, Any] = field(default_factory=dict)
    id: int = field(default_factory=lambda: next(_seq))
    # 탐지 결과(파이프라인에서 채움)
    template: str = ""
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        # 기기 단위 도메인(VM 게스트·물리 서버 OS·BMC)은 호스트를 항상 포함 — 같은 오류라도 서버마다 별도 이상징후.
        # 인프라 소스는 기존대로 entity(앱·개체) 기준(클러스터 전역 동일 증상은 하나로 묶고 재발 횟수로 표시)
        who = f"{self.host}|{self.entity}" if self.source in PER_HOST_SOURCES else (self.entity or self.host)
        base = f"{self.source}|{who}|{self.template or self.message[:120]}"
        return hashlib.sha1(base.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["message"] = self.message[:4000]
        return d


PER_HOST_SOURCES = frozenset({"vm", "baremetal", "redfish"})


@dataclass
class Anomaly:
    id: str
    event: dict[str, Any]
    severity: str
    category: str
    title: str
    reasons: list[str]
    score: float
    created: float = field(default_factory=time.time)
    status: str = "pending"          # pending → analyzing → analyzed | llm_error
    ack: bool = False
    count: int = 1                   # 같은 fingerprint 재발 횟수
    last_seen: float = field(default_factory=time.time)
    context: list[dict[str, Any]] = field(default_factory=list)
    ai: dict[str, Any] = field(default_factory=dict)
    refs: list[dict[str, Any]] = field(default_factory=list)   # RAG 검색 결과(LLM에 주입된 근거)
    alerted: bool = False
    suppressed: str = ""             # 유지보수·사일런스 등 억제 사유
    incident_id: str = ""
    escalated: float = 0.0           # 미확인 위험 에스컬레이션 발송 시각
    fp: str = ""                     # 중복 제거 지문(재기동 시 복원용)
    notified: bool = False           # 인시던트·알림 단계 처리 완료(LLM 대기 만료 스위퍼 판단용)
    related: list[dict[str, Any]] = field(default_factory=list)   # KB 자동 연결(근거 없이 판정된 이상징후에 비슷한 문서)
    related_gen: int = -1            # 자동 연결 당시 지식 세대(바뀌면 다시 찾음)

    def to_dict(self) -> dict[str, Any]:
        """얕은 복사(asdict 의 깊은 복사는 재발 폭주 시 CPU 를 크게 씀) — 컨테이너는 한 단계만 복사"""
        d = {k: getattr(self, k) for k in _ANOMALY_FIELDS}
        for k in ("event", "ai"):
            d[k] = dict(d[k])
        for k in ("reasons", "context", "refs", "related"):
            d[k] = list(d[k])
        return d


_ANOMALY_FIELDS = tuple(Anomaly.__dataclass_fields__)
