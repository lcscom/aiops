"""config.yaml 로더 — ${ENV_VAR} / ${ENV_VAR:-default} 치환 지원."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _subst(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_subst(v) for v in value]
    if isinstance(value, dict):
        return {k: _subst(v) for k, v in value.items()}
    return value


DEFAULTS: dict[str, Any] = {
    "server": {
        "host": "0.0.0.0",
        "port": 8630,                 # 웹 대시보드 + REST/WebSocket API 단일 포트
        "db_path": "data/aiops.db",
        "buffer_size": 5000,
        "max_body_mb": 8,             # 일반 API 요청 본문 상한(패치·지식 zip·취약점 JSON·ingest 는 제외)
        "slow_request_ms": 5000,      # 이보다 느린 요청은 로그·/api/health requests 에 기록
        "retention_days": 7,
        "tls": {"enabled": "auto", "certfile": "certs/aiops.crt", "keyfile": "certs/aiops.key", "keyfile_password": ""},
        "trusted_proxies": "127.0.0.1",   # 리버스 프록시(IIS ARR 등) 뒤에 둘 때 X-Forwarded-* 신뢰 대상
        "edge_headers_external": True,    # 2.49.0 Cloudflare 머리글(CF-Ray·CF-Connecting-IP)이 붙은 요청도 외부로 판단
        "security_contact": "",           # 2.49.0 /.well-known/security.txt 연락처(mailto:… 또는 https://…). 비우면 404
        "https_redirect": "proxy",        # 2.48.2 앞단(Cloudflare CF-Visitor·외부 이름의 X-Forwarded-Proto)이 http 라고 알리면 https 로 301/308. off 로 끔
        "access_log": False,
        "log_level": "info",
        "timeout_keep_alive": 15,
        "ws_ping_interval": 20,
        "ws_queue": 2000,             # 화면(WebSocket)별 송신 대기 상한 — 넘치면 그 화면만 끊고 재접속·재동기화
        "ws_send_timeout": 15,        # 송신 1건 상한(죽은 TCP 정리)
        "ws_idle_timeout": 0,         # >0: 앱 메시지 무수신 상한(초). 0 = 프로토콜 ping/pong(ws_ping_interval)으로만 정리
        "limit_concurrency": 0,       # 0 = 무제한
        "gzip_min_size": 1024,
    },
    "llm": {
        "enabled": True,
        "base_url": "http://127.0.0.1:8000/v1",
        "api_key": "",
        "model": "google/gemma-4-31B-it",
        "verify_tls": False,
        "timeout": 120,
        "max_tokens": 1200,
        "temperature": 0.1,
        "batch_size": 6,
        "batch_interval": 5,
        "batch_max": 12,              # 대기 많을 때 배치 확대 상한
        "concurrency": 1,             # 동시 LLM 요청 수(1 = 순차, LLM 서버 여력에 맞춰)
        "queue_max": 2000,            # 분석 대기 상한(초과 시 가장 낮은 우선순위를 밀어냄)
        "queue_shed_at": 500,         # 이 이상 쌓이면 warning 이하 신규는 규칙 탐지로만
        "queue_source_quota": 300,    # 소스당 대기 상한(한 소스의 폭주가 다른 소스 분석을 막지 않게)
        "queue_max_age": 900,         # warning 이하가 이보다 오래 기다리면 분석 생략(초)
        "queue_coalesce": True,       # 같은 소스·같은 로그 패턴은 대표 1건만 분석, 결과 공유
        "json_mode": True,
        "extra_body": {},
        "context_lines": 12,
        "breaker_threshold": 3,       # 연속 실패 시 LLM 호출 일시 차단 → 규칙 탐지로 즉시 처리
        "breaker_reset": 60,
    },
    "pipeline": {                     # 수집 처리 큐 — 우선(경고 이상·알람·위험 키워드) / 일반
        "high_queue": 20000,
        "low_queue": 100000,
        "classify_backlog": 500,      # 일반 큐 적체가 이 이상이면 info 로그도 위험 키워드로 우선순위 재분류
        "context_hosts": 5000,        # LLM 문맥용 호스트별 최근 로그 보관 상한(LRU)
    },
    "storage": {"log_queue": 100000, "min_free_mb": 1024},
    "agents": {"stale_seconds": 300, "alert_on_stale": True,   # VM 게스트·물리 서버 OS 에이전트(Fluent Bit·rsyslog) 무응답 감시
               "public_url": ""},                         # 에이전트가 접속할 이 서버 주소(비우면 server.public_url)
    "health": {"loop_lag_warn_ms": 500, "loop_lag_crit_ms": 2000, "ready_lag_ms": 5000,
               "pipeline_lag_warn_s": 30, "outbox_delay_warn_s": 600},
    "selfcheck": {"wal_max_mb": 256, "memory_warn_mb": 3072, "open_files_warn": 4000, "quick_check_hours": 24,
                  "backup_stale_days": 2, "verify_backups": True},   # 자가 점검(DB 무결성·WAL·백업 검증·자원·인증서)
    "ha": {"enabled": False, "role": "primary", "node_name": "", "peer_url": "", "shared_secret": "",
           "failover_seconds": 30, "failback_seconds": 60, "check_interval": 5, "verify_tls": False},
    "detection": {
        "llm_threshold": 0.5,        # 이 점수 이상 후보만 LLM으로 보냄
        "warmup_seconds": 300,       # 신규 템플릿 판정 시작 전 학습 시간
        "burst_z": 3.5,
        "burst_min_count": 15,
        "dedupe_window": 600,
        "extra_rules": [],
        "suppress": [],
    },
    "siem": {                         # CEF/syslog 전달(Splunk·QRadar·ArcSight·Sentinel)
        "enabled": False, "host": "", "port": 514, "protocol": "udp", "min_severity": "warning",
        "audit": True, "anomalies": True, "incidents": True, "verify_tls": True, "ca_file": "",
    },
    "alerting": {
        "min_severity": "error",
        "cooldown": 900,
        "require_llm_confirm": False,
        "critical_immediate": True,   # 위험(critical)은 LLM 판정을 기다리지 않고 즉시 인시던트·알림(AI 결과는 이후 보강)
        "llm_wait_seconds": 30,       # 그 외 등급이 LLM 판정을 기다리는 최대 시간(초과 시 규칙 탐지로 진행)
        "max_attempts": 8,            # 웹훅·메일 재시도 횟수(초과 시 발송 실패함)
        "retry_schedule": [30, 120, 300, 900, 1800, 3600],   # 재시도 간격(초) — 마지막 값 반복
        "channel_breaker_reset": 60,  # 채널 연속 3회 실패 시 이 시간 동안 발송 보류(죽은 채널이 재시도 횟수를 소모하지 않도록)
        "webhooks": [],
        "smtp": {"enabled": False},
        "routes": [],                 # 라우팅 정책 [{name, severities, sources, categories, connectors, match, hours:"09:00-18:00", days:[0..6], channels:[웹훅 이름|smtp], stop}] — 비우면 전 채널
        "default_channels": [],       # 어느 규칙에도 안 맞을 때 채널(비우면 전 채널)
    },
    "syslog": {"enabled": True, "udp_port": 514, "tcp_port": 514, "bind": "0.0.0.0",
               "tls": {"enabled": "auto", "port": 6514, "certfile": "certs/aiops.crt", "keyfile": "certs/aiops.key"},
               "advertise_host": "",            # 장비가 로그를 보낼 이 서버 주소(FQDN/IP) — 전송 설정 점검·적용 기준
               "advertise_protocol": "udp",     # udp | tcp | tls
               "host_map": []},                 # [{match: 정규식(호스트/송신 IP), source: vks-supervisor|vks|nsx-edge|...}]
    "ingest": {"enabled": True, "token": ""},
    # Isvara(isvara.io) iO — VCF·vSphere·vSAN 성능 가이드 근거 Q&A(MCP). 외부 전송이 있으므로 기본 끔(질문 문장만 전송)
    "isvara": {"enabled": False, "url": "https://isvara.io/api/mcp", "timeout": 20, "proxy": "",
               "chat_grounding": True, "verify_tls": True},
    "snmp": {"enabled": True, "bind": "0.0.0.0", "port": 162, "communities": ["public"], "v3_users": [],
             "hosts": [], "oid_map": {}},
    "rag": {
        "enabled": True,
        "top_k": 5,                  # 이상 후보 1건당 주입할 참고 문서 수
        "min_score": 0.3,
        "dense_weight": 0.6,         # 하이브리드 가중치(Dense vs BM25)
        "max_chars_per_ref": 1200,
        "embedding": {"enabled": False, "base_url": "", "model": "BAAI/bge-m3", "api_key": "", "verify_tls": False},
    },
    "billing": {                     # VM 사용량 정산(app/billing.py) — vCenter 인벤토리 5분 표본, 시간 단위 누적
        "enabled": True,
        "retention_days": 400,       # 시간 단위 사용량 보관
        "currency": "KRW",           # 요율표에 통화가 없을 때 표시
    },
    "capacity": {                    # 용량 계획·VM 적정화(app/capacity.py) — 클러스터·데이터스토어 5분 표본, 정산 표본 재사용
        "enabled": True,
        "forecast_days": 30,         # 추세 계산에 쓰는 기간
        "rightsizing_days": 14,      # VM 사용률 판단 기간
        "retention_days": 400,
        "oversized_cpu_pct": 25, "oversized_mem_pct": 30, "undersized_cpu_pct": 75, "undersized_mem_pct": 85,
        "idle_cpu_pct": 3, "idle_mem_pct": 10, "headroom": 1.5, "powered_off_days": 7,
    },
    "assessment": {                  # 보안 판독(app/assess.py) — 하드닝·KISA·VMSA/CVE(읽기 전용)
        "enabled": True,
        "interval_hours": 24,        # 자동 점검 주기
        "max_vms": 500,              # VM 고급 설정 표본 수
        "snapshot_days": 3,          # 이보다 오래된 스냅샷은 미흡
        "nvd": {"enabled": False, "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "api_key": "", "proxy": "",
                "interval_days": 7},   # 외부 전송(제품 CPE 문자열만) — 폐쇄망은 JSON 가져오기
    },
    "knowledge": {                   # KB·TechDocs Markdown 라이브러리(app/knowledge.py)
        "enabled": True,
        "paths": [],                 # md 아카이브 폴더(NFS/SMB 마운트 가능). 화면 업로드(zip)는 data/knowledge/uploads
        "scan_interval": 21600,      # 증분 색인 주기(초)
        "embed": True,               # rag.embedding 이 켜져 있으면 청크 벡터 생성(하이브리드 검색)
        "chunk_size": 1600,
        "chunk_overlap": 150,
        "top_k": 4,                  # 이상징후 1건당 붙일 라이브러리 문서 수
        "min_relevance": 0.4,
        "max_file_mb": 8,
        "max_chars_per_ref": 2400,   # 문서 1건이 AI 에 들어가는 최대 글자(증상·원인·해결·우회 묶음)
        "max_upload_gb": 4,          # 화면 zip 업로드 최대
        "vendors": ["vmware"],            # 우선 사업부(front matter vendor) — 그 밖(ca·symantec·other 의 비 VMware 제품)은 순위 ×0.7
        "languages": ["en", "ko"],        # 우선 언어 — 일본어 등 번역본은 순위 ×0.8(원문이 없으면 그대로 쓰임)
        "skip_dirs": [],
        "auto_link": True,                # 근거 없는 이상징후·인시던트에 비슷한 KB 자동 연결(LLM 호출 없음)
        "link_interval": 20,              # 자동 연결 주기(초)
        "link_min_relevance": 0.6,        # 자동 연결 최소 관련도(0~1)
        "link_top_k": 3,                  # 이상징후당 자동 연결 문서 수                  # 색인 제외 폴더명(_·. 로 시작하는 폴더 — _catalog·_changes·_rag — 는 항상 제외)
    },
    "monitoring": {
        "active_window": 300,        # 이 시간 내 수신이 있으면 '수집 중'
        "check_interval": 30,
        "alert_on_stop": True,       # 중단/오류/미수신 전환 시 내부 이벤트 → 알림
        "max_silence": {"syslog": 900, "ingest": 900, "snmp": 0, "vcflogs": 600},   # 0 = 침묵 감시 안 함
        "expected": [],              # 반드시 들어와야 하는 송신 장비 [{name, kind, match(정규식), max_silence}]
    },
    # 2.50.0 현장 센서(안드로이드 폰) — 무응답 판정·보관 기간·장치당 사진 수·사진 최대 크기
    "sensors": {"stale_seconds": 300, "retention_days": 30, "snaps_per_device": 300, "snap_max_bytes": 3145728},
    "auth": {
        "enabled": True,
        "session_idle_minutes": 10,       # 사용자 입력 기준 유휴 만료
        "session_absolute_hours": 12,
        "kiosk_users": [],                # 통합 관제 화면(월 디스플레이) 전용 계정 — 유휴 만료 없음, 조회자 권한 고정
        "kiosk_absolute_hours": 168,
        "single_session": False,          # true: 동일 계정 동시접속 시 이전 세션 종료
        "lockout_threshold": 5, "lockout_minutes": 30,
        "dormant_days": 90,               # 장기 미사용 계정 자동 잠금(관리자 제외, 0=사용 안 함)
        "rate_limit_per_5min": 30,
        "write_rate_per_min": 240,        # 세션당 변경 요청(POST·PUT·DELETE) 분당 상한(0=무제한)
        # 2.49.0 외부(인터넷) 로그인 보호 — external_lockout: account_ip(외부 실패는 계정+IP 단위로 잠금) | account(이전 동작)
        "guard": {"external_lockout": "account_ip", "external_account_cap": 20, "external_window_minutes": 30,
                  "stuffing_users": 5, "stuffing_window_minutes": 10, "ip_block_minutes": 30,
                  "session_country_bind": True, "new_location_alert": True},
        "login_banner": "본 시스템은 인가된 사용자만 사용할 수 있으며 모든 접속·조작 기록은 감사 목적으로 저장됩니다.",
        "password": {"min_length": 9, "classes": 3, "expire_days": 90, "history": 3},
        "mfa": {"enabled": True, "required_roles": [], "issuer": "VCF AIops"},   # TOTP 2단계 — required_roles 에 admin 을 넣으면 관리자 필수
        "oidc": {"enabled": False, "display_name": "SSO", "issuer": "", "client_id": "", "client_secret": "", "token_auth": "post",
                 "scopes": ["openid", "profile", "email"], "username_claim": "preferred_username", "role_claim": "groups",
                 "group_role_map": {}, "default_role": "", "redirect_base": "", "verify_tls": True, "ca_file": "", "strip_domain": True},
        "ldap": {"enabled": False, "servers": [], "domain": "", "base_dn": "", "use_ssl": True, "start_tls": False,
                 "verify_tls": True, "ca_file": "", "nested_groups": True,
                 "user_filter": "(&(objectClass=user)(sAMAccountName={username}))", "group_role_map": {}},
    },
    "audit": {"retention_days": 1825},
    "incidents": {
        "enabled": True,
        "min_severity": "error",          # 이 등급 이상 이상징후만 인시던트화
        "correlation_window": 900,        # 같은 상관 그룹(클러스터/호스트) 15분 내 → 같은 인시던트
        "auto_resolve_minutes": 120,      # 신규 이상 없이 경과 시 '해결 대기'로 제안
        "sla": {"critical": {"ack": 15, "resolve": 240}, "error": {"ack": 30, "resolve": 480},
                "warning": {"ack": 120, "resolve": 1440}},
    },
    "itsm": {"type": "none", "min_severity": "critical", "servicenow": {}, "webhook": {}},
    "actions": {"enabled": True, "approval_min_level": 3, "deny_environments": [], "task_timeout": 900, "admin_self_approve": True},
    "reports": {"daily": {"enabled": False, "time": "08:30", "recipients": []},
                "weekly": {"enabled": False, "weekday": 0, "time": "08:40", "recipients": []},
                "monthly": {"enabled": False, "day": 1, "time": "08:50", "recipients": []},   # 지난달 1일~말일(정산·용량·적정화·보안 판독 포함)
                "keep_days": 180, "ai_summary": True, "extended": True},
    "backup": {"enabled": True, "time": "02:30", "keep": 14, "dir": "data/backup"},
    "metrics": {"enabled": True, "allow_ips": ["127.0.0.1"]},
    "vm_activity": {},
    "web_search": {"enabled": False, "provider": "searxng", "url": "", "api_key": "", "proxy": "", "verify_tls": True, "timeout": 12, "mode": "auto",
                   "min_kb_refs": 2, "max_results": 8, "fetch_pages": 3, "max_chars_per_page": 3500, "cache_minutes": 60, "language": "",
                   "product_hint": "VMware", "only_preferred": False, "block_domains": [],
                   "prefer_domains": ["knowledge.broadcom.com", "techdocs.broadcom.com", "docs.vmware.com", "community.broadcom.com", "blogs.vmware.com",
                                      "williamlam.com", "core.vmware.com", "github.com", "kb.vmware.com", "support.broadcom.com"]},   # 2.7.0 AI 질의 웹 검색(기본 꺼짐)   # VM 액티비티 위험 신호 규칙 초기값(tz·business_hours·business_days·holidays·bulk_*·protected·short_lived_hours·service_accounts) — 화면 저장값이 우선
    "noc": {"window_minutes": 30, "escalate_minutes": 15, "stale_minutes": 10, "ai_brief": True, "brief_ttl_seconds": 300, "slots": []},   # 통합 관제 — slots 비우면 기본 4슬롯(vc·nsx·avi·vks)
    "demo": {"enabled": False, "rate": 4},
    "connectors": [],
}


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_dotenv(path: str = ".env") -> None:
    """.env(KEY=VALUE) 를 환경변수로 적재 — Docker env_file 없이 Windows/conda로 직접 실행할 때 사용.
    이미 설정된 환경변수는 덮어쓰지 않는다."""
    p = Path(os.environ.get("AIOPS_ENV_FILE", path))
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip().removeprefix("export ").strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ.setdefault(k, v)


def load_config(path: str | None = None) -> dict[str, Any]:
    load_dotenv()
    path = path or os.environ.get("AIOPS_CONFIG", "config.yaml")
    raw: dict[str, Any] = {}
    p = Path(path)
    if p.exists():
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cfg = _merge(DEFAULTS, _subst(raw))
    from .security.secrets import decrypt_tree   # enc:dpapi:/enc:fernet: 값 자동 복호화
    cfg = decrypt_tree(cfg)
    if os.environ.get("AIOPS_DEMO") == "1":
        cfg["demo"]["enabled"] = True
    return cfg
