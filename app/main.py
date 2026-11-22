"""VCF AIops — FastAPI 엔트리포인트 (인증·RBAC·감사·인시던트·조치·설정·리포트 통합)."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import re
import secrets
import ssl
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import connectors, sli
from .actions import ActionGate
from .config import load_config
from .connectors.vmware_rest import sev_from_text
from .engine import Engine
from .httputil import bad_numeric_query, disposition
from .models import SEVERITIES, SEV_RANK, Anomaly, LogEvent, norm_severity
from .reports import Reporter
from .sanitize import wrap
from .security.auth import AuthManager, bad_path, client_ip
from .runtime import bg
from .settings_store import SettingsManager, apply_overlay, load_overlay

BASE_CFG = load_config()
CFG = apply_overlay(BASE_CFG, load_overlay(BASE_CFG["server"]["db_path"]))   # 화면 설정(DB)이 config.yaml 보다 우선
DATA_DIR = str(Path(CFG["server"]["db_path"]).parent)
ENGINE = Engine(CFG)
AUTH = AuthManager(ENGINE.store, CFG["auth"], ENGINE.audit, DATA_DIR)
ENGINE.auth = AUTH
SETTINGS = SettingsManager(ENGINE.store, CFG, copy.deepcopy(BASE_CFG))
ACTIONS = ActionGate(ENGINE, CFG["actions"])
REPORTER = Reporter(ENGINE)
ENGINE.actions = ACTIONS
from .forwarding import ForwardingAuditor  # noqa: E402
from .ha import HAManager, verify as ha_verify  # noqa: E402
from .health import HealthMonitor  # noqa: E402
ENGINE.forwarding = ForwardingAuditor(ENGINE)
ENGINE.ha = HAManager(CFG.get("ha") or {}, ENGINE)
ENGINE.health = HealthMonitor(ENGINE, CFG.get("health") or {})
from .selfcheck import SelfCheck, preflight  # noqa: E402
ENGINE.selfcheck = SelfCheck(ENGINE, CFG.get("selfcheck") or {}, DATA_DIR)      # DB 무결성·WAL·백업 검증·자원·인증서
ENGINE.selfcheck.state["preflight"] = preflight(CFG, DATA_DIR)
for _i in ENGINE.selfcheck.state["preflight"]:
    print(f"[preflight] {_i['level']}: {_i['text']}", flush=True)
ENGINE.alerter.bind_store(ENGINE.store)
ENGINE.alerter.is_leader = ENGINE.ha.is_leader
STATIC = Path(__file__).parent / "static"


def _build_id() -> str:
    """정적 자원 지문 — 배포(파일 교체) 후 재기동하면 바뀐다. 열려 있는 관제 화면이 재접속 시 비교해 자동 새로고침."""
    h = hashlib.sha1()
    for f in sorted(STATIC.glob("*.*")):
        st = f.stat()
        h.update(f"{f.name}:{st.st_size}:{int(st.st_mtime)}".encode())
    return h.hexdigest()[:12]


ENGINE.build = _build_id()
ANOMALY_FIELDS = set(Anomaly.__dataclass_fields__)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'")
# Swagger UI(/api/docs)는 CDN 스크립트·인라인 초기화 스크립트를 쓰므로 해당 경로만 완화(로그인 필요 경로)
CSP_DOCS = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'self'; object-src 'none'")


def who(request: Request) -> dict:
    """요청 주체(세션/토큰). 인증 비활성 시 익명 관리자."""
    return getattr(request.state, "user", None) or {"user": "anonymous", "role": "admin", "display": "anonymous"}


async def audit(request: Request, action: str, target: str = "", result: str = "ok", detail: Any = None) -> None:
    u = who(request)
    await ENGINE.audit.log(action, user=u["user"], role=u.get("role", ""), ip=client_ip(request), target=target,
                           result=result, detail=detail)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await AUTH.bootstrap()
    ENGINE.connectors = connectors.build(CFG, ENGINE.ingest)
    for a in await ENGINE.store.load_recent_anomalies(300):   # 재기동 시 최근 이상징후·중복제거 지문 복원
        try:
            an = Anomaly(**{k: v for k, v in a.items() if k in ANOMALY_FIELDS})
            ENGINE.anomalies[an.id] = an
            if an.fp and an.fp not in ENGINE.by_fp:
                ENGINE.by_fp[an.fp] = an.id
        except TypeError:
            pass
    try:                                                     # 관제 화면 분당 추이를 DB 최근 60분으로 초기화
        ENGINE.minutes.seed(await ENGINE.store.minute_counts(60))
    except Exception as e:  # noqa: BLE001
        print(f"[startup] 분당 집계 복원 실패: {e}", flush=True)
    await ENGINE.agents.load()                               # 에이전트 레지스트리(무응답 감시 대상) 복원
    await ENGINE.monitors.load()                             # 모니터 정의·상태 복원
    await ENGINE.patterns.load()                             # AI 분석 패턴(재사용) 복원
    await ENGINE.rag.load_enabled()                          # 활성화된 RAG 팩 메모리 적재
    await ENGINE.incidents.reload_suppression()
    S = ENGINE.sup
    beat = lambda n: (lambda: S.beat(n))                     # noqa: E731
    # critical=True: 정지 시 /readyz 503. heartbeat: 그 3배 동안 신호가 없으면 '정체'
    S.spawn("pipeline", ENGINE.pipeline_worker, heartbeat=5)
    S.spawn("publisher", ENGINE.publisher, heartbeat=10)
    S.spawn("store-writer", lambda: ENGINE.store.writer(beat("store-writer")), heartbeat=10)
    S.spawn("flusher", ENGINE.flusher, heartbeat=5)
    S.spawn("loop-lag", ENGINE.lag.run, critical=False)
    S.spawn("sweeper", ENGINE.pending_sweeper, heartbeat=20)
    S.spawn("outbox", lambda: ENGINE.alerter.dispatcher(beat("outbox")), heartbeat=30)
    S.spawn("siem", lambda: ENGINE.siem.loop(beat("siem")), critical=False, heartbeat=60)
    S.spawn("sessions", lambda: AUTH.persist_loop(beat("sessions")), critical=False, heartbeat=300)
    S.spawn("selfcheck", lambda: ENGINE.selfcheck.loop(beat("selfcheck")), critical=False, heartbeat=900)
    S.spawn("posture", lambda: POSTURE.loop(beat("posture")), critical=False, heartbeat=1800)
    await GATE.load()
    S.spawn("ingest-gate", lambda: GATE.loop(beat("ingest-gate")), critical=False, heartbeat=60)
    S.spawn("perfwatch", lambda: PW.loop(beat("perfwatch")), critical=False, heartbeat=1200)
    try:                                                     # 2.30.0 모바일 앱: 서버 버전이 바뀌었으면 '업데이트됨' 알림
        from . import patching as _pt
        await MOBILE.check_version(_pt.current_version())
    except Exception as e:  # noqa: BLE001
        print(f"[mobile] 버전 확인 오류: {type(e).__name__}: {e}", flush=True)
    S.spawn("health", lambda: ENGINE.health.loop(beat("health")), heartbeat=30)
    S.spawn("ha", lambda: ENGINE.ha.loop(beat("ha")), critical=False, heartbeat=120)
    S.spawn("agents", lambda: ENGINE.agents.loop(beat("agents")), critical=False, heartbeat=60)
    S.spawn("kb-link", lambda: ENGINE.kblink.loop(beat("kb-link")), critical=False, heartbeat=600)
    S.spawn("billing", lambda: ENGINE.billing.loop(beat("billing")), critical=False, heartbeat=900)
    S.spawn("assessment", lambda: ENGINE.assess.loop(beat("assessment")), critical=False, heartbeat=900)
    S.spawn("capacity", lambda: ENGINE.capacity.loop(beat("capacity")), critical=False, heartbeat=900)
    S.spawn("ops-metrics", lambda: ENGINE.opsmetrics.loop(beat("ops-metrics")), critical=False, heartbeat=300)
    S.spawn("vks-observe", lambda: ENGINE.vksobs.loop(beat("vks-observe")), critical=False, heartbeat=300)
    S.spawn("cloudcost-iops", lambda: ENGINE.cloudcost.loop(beat("cloudcost-iops")), critical=False, heartbeat=7200)
    S.spawn("readiness", lambda: ENGINE.readiness.loop(beat("readiness")), critical=False, heartbeat=1800)
    S.spawn("certs", lambda: ENGINE.certs.loop(beat("certs")), critical=False, heartbeat=1800)      # 2.36.0 인증서 만료 스캔
    S.spawn("drift", lambda: ENGINE.driftwatch.loop(beat("drift")), critical=False, heartbeat=900)   # 2.37.0 구성 변경 이력
    S.spawn("checkbot", lambda: ENGINE.checkbot.loop(beat("checkbot")), critical=False, heartbeat=1800)   # 2.38.0 AI 체크봇
    S.spawn("scnwatch", lambda: ENGINE.scnwatch.loop(beat("scnwatch")), critical=False, heartbeat=1800)   # 2.48.0 What-If 라이브러리 연속 검증
    S.spawn("vulncheck", lambda: ENGINE.vulncheck.loop(beat("vulncheck")), critical=False, heartbeat=1800)   # 2.43.0 내부 취약점 검증
    S.spawn("aiopsx", lambda: ENGINE.aiopsx.loop(beat("aiopsx")), critical=False, heartbeat=900)          # 2.45.0 전조 학습·조기 경보
    from .license.manager import scheduler as _lic_sched
    S.spawn("license", lambda: _lic_sched(ENGINE.license, beat("license")), critical=False, heartbeat=3600)
    S.spawn("collection", lambda: ENGINE.collection.watch(lambda: ENGINE.connectors), critical=False)
    S.spawn("incident-sla", ENGINE.incidents.sla_loop, critical=False)
    S.spawn("vks-discovery", ENGINE.vks_discovery_loop, critical=False)
    S.spawn("avi-metrics", ENGINE.avi_metrics_loop, critical=False)
    S.spawn("segtraffic", ENGINE.segtraffic.loop, critical=False)          # 2.21.0 세그먼트 트래픽 5분 합계 이력
    S.spawn("monitors", ENGINE.monitors.loop, critical=False, heartbeat=120)
    S.spawn("fortigate", ENGINE.fortigate.loop, critical=False, heartbeat=10)
    S.spawn("reports", REPORTER.scheduler, critical=False)
    from .noc import brief_loop, escalation_loop
    S.spawn("noc-escalation", lambda: escalation_loop(ENGINE, CFG), critical=False)
    S.spawn("noc-brief", lambda: brief_loop(ENGINE, CFG), critical=False)
    S.spawn("knowledge", ENGINE.knowledge.loop, critical=False)            # KB·TechDocs md 증분 색인·임베딩
    S.spawn("llm", ENGINE.llm_worker, critical=False, heartbeat=30)      # LLM 은 화면에서 켜고 끌 수 있으므로 항상 대기
    for k in range(2, max(1, min(int(CFG["llm"].get("concurrency", 1) or 1), 8)) + 1):   # LLM 서버 동시 처리 수만큼(기본 1 = 순차)
        S.spawn(f"llm-{k}", lambda n=f"llm-{k}": ENGINE.llm_worker(n), critical=False, heartbeat=30)
    S.spawn("llm-health", ENGINE.llm_health_loop, critical=False)
    S.spawn("ai-governor", lambda: ENGINE.gov.loop(lambda: S.beat("ai-governor")), critical=False, heartbeat=60)
    S.spawn("ai-patterns", lambda: ENGINE.patterns.loop(lambda: S.beat("ai-patterns")), critical=False, heartbeat=30)
    ENGINE.start_connectors()
    from .runtime import SystemdNotifier
    sdn = SystemdNotifier()
    # systemd STATUS 는 VM 콘솔(한글 글꼴 없음)에서도 보이므로 ASCII 영문으로
    S.spawn("systemd", lambda: sdn.loop(ENGINE.health.ready, lambda: (
        f"EPS {ENGINE.stats['eps']:.0f} | events {ENGINE.stats['events_total']:,} | open anomalies "
        f"{sum(1 for a in ENGINE.anomalies.values() if not a.ack)} | screens {len(ENGINE.hub)} | agents {len(ENGINE.agents.items)}"
        f"{' | HA ' + ENGINE.ha.role + (' (leader)' if ENGINE.ha.leader else '') if ENGINE.ha.enabled else ''}"),
        float((CFG.get("health") or {}).get("watchdog_unready_grace", 300)), beat("systemd")), critical=False)
    sdn.send("READY=1")
    await ENGINE.audit.log("system.start", detail={"connectors": [c.name for c in ENGINE.connectors], "build": ENGINE.build,
                                                   "auth": AUTH.enabled, "ldap": bool(AUTH.ldap_cfg.get("enabled")),
                                                   "ha": ENGINE.ha.public()})
    yield
    # ---- 우아한 종료: 화면에 재시작 알림(1012) → 수집 중지 → 처리 대기분 소진 → DB 버퍼 기록
    print("[shutdown] 종료 시작 — 화면 연결 종료·버퍼 기록", flush=True)
    sdn.send("STOPPING=1")
    await ENGINE.hub.close_all(1012, "service restart")
    for name in [n for n in list(S.jobs) if n.startswith("conn:")]:
        S.cancel(name)
    t_end = time.time() + 5
    while (ENGINE.q_hi or ENGINE.q_lo) and time.time() < t_end:
        await asyncio.sleep(0.1)
    try:
        await ENGINE.audit.log("system.stop", detail={"unprocessed": len(ENGINE.q_hi) + len(ENGINE.q_lo)})
    except Exception:  # noqa: BLE001
        pass
    await S.stop()
    await ENGINE.store.flush(10)
    print(f"[shutdown] 완료 — 미기록 {ENGINE.store.backlog}건", flush=True)


app = FastAPI(title="VCF AIops", lifespan=lifespan, docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
# 응답 압축 — JSON 스냅샷·JS/CSS 전송량 감소 (Starlette는 text/event-stream(SSE)을 압축 대상에서 제외)
app.add_middleware(GZipMiddleware, minimum_size=int(CFG["server"].get("gzip_min_size", 1024)), compresslevel=6)


_SVER: dict[str, tuple[float, int, str]] = {}
_INDEX: dict[str, Any] = {"key": None, "html": ""}
_ASSET = re.compile(r'(src|href)="/static/([A-Za-z0-9_.-]+\.(?:js|css))"')


def _static_ver(name: str) -> str:
    """정적 파일(최상위 js·css)의 내용 해시 12자 — 주소에 ?v= 로 붙여 오래 캐시. 없는 파일·하위 폴더는 ''"""
    if "/" in name or not name.endswith((".js", ".css")):
        return ""
    try:
        st = (STATIC / name).stat()
    except OSError:
        return ""
    c = _SVER.get(name)
    if not c or c[0] != st.st_mtime or c[1] != st.st_size:
        c = (st.st_mtime, st.st_size, hashlib.sha256((STATIC / name).read_bytes()).hexdigest()[:12])
        _SVER[name] = c
    return c[2]


def _index_html() -> Response:
    """첫 화면 — 스크립트·스타일 주소에 내용 해시를 붙여 준다(폰에서 다시 열 때 43개 파일을 되묻지 않게)"""
    src = (STATIC / "index.html").read_text(encoding="utf-8")
    names = sorted({m.group(2) for m in _ASSET.finditer(src)})
    key = (hash(src), tuple(_static_ver(n) for n in names))
    if _INDEX["key"] != key:
        _INDEX["html"] = _ASSET.sub(lambda m: f'{m.group(1)}="/static/{m.group(2)}?v={_static_ver(m.group(2))}"' if _static_ver(m.group(2)) else m.group(0), src)
        _INDEX["key"] = key
    return Response(_INDEX["html"], media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def cache_and_security_headers(request: Request, call_next):
    resp = await call_next(request)
    path = request.url.path
    if path.startswith("/static/fonts/"):
        resp.headers["Cache-Control"] = "public, max-age=2592000, immutable"     # 2MB 폰트: 30일 캐시
    elif path.startswith("/static/"):
        v = request.query_params.get("v")
        if v and resp.status_code == 200 and v == _static_ver(path[8:]):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"   # 2.32.0 내용 해시가 붙은 주소 — 다시 묻지 않음(파일이 바뀌면 주소가 바뀜)
        else:
            resp.headers["Cache-Control"] = "no-cache"   # ETag/Last-Modified 재검증 → 변경 없으면 304
    elif path in ("/", "/login", "/noc") or path.startswith(("/api/", "/noc/")):
        resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Content-Security-Policy", CSP_DOCS if path == "/api/docs" else CSP)
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")          # 2.22.0 창 간 참조·교차 출처 격리
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if request.url.scheme == "https":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


# 요청 보호(2.2): 본문 크기 상한(업로드 경로 제외)·느린 요청 기록 — 비정상 클라이언트가 메모리·루프를 잠식하지 못하게
_BIG = ("/api/system/patch", "/api/knowledge/upload", "/api/assessment/import", "/api/ingest", "/api/rag/", "/api/readiness/hcl", "/api/rvtools/upload", "/api/license/upload/")
_MAX_BODY = int(CFG["server"].get("max_body_mb", 8)) * 2**20
_SLOW_MS = float(CFG["server"].get("slow_request_ms", 5000))
REQ_STATS = {"total": 0, "slow": 0, "too_large": 0, "rate_limited": 0, "errors": 0, "last_slow": ""}


@app.middleware("http")
async def request_guard(request: Request, call_next):
    REQ_STATS["total"] += 1
    path = request.scope.get("path") or ""                      # 2.30.0 라우팅과 같은 경로(request.url.path 는 디코딩된 '?' 뒤를 자름)
    if path.startswith("/api/") and request.url.query:          # 2.20 숫자 쿼리의 NaN·Infinity·1e309 → 400(감사로그 저장·JSON 직렬화 오류 방지)
        bad = bad_numeric_query(request.url.query)
        if bad:
            return JSONResponse({"detail": f"'{bad}' 값은 유한한 숫자여야 합니다", "code": "bad_number"}, status_code=400)
    if request.method in ("POST", "PUT", "PATCH") and not path.startswith(_BIG):
        try:
            if int(request.headers.get("content-length") or 0) > _MAX_BODY:
                REQ_STATS["too_large"] += 1
                return JSONResponse({"detail": f"요청 본문이 너무 큽니다(최대 {_MAX_BODY // 2**20}MB)", "code": "too_large"}, status_code=413)
        except ValueError:
            pass
        if "content-length" not in request.headers:             # 2.30.0 청크 전송(길이 머리글 없음)도 같은 상한 — 읽으며 세고, 읽은 본문은 안쪽으로 그대로 전달
            buf = bytearray()
            try:
                async for chunk in request.stream():
                    buf += chunk
                    if len(buf) > _MAX_BODY:
                        REQ_STATS["too_large"] += 1
                        return JSONResponse({"detail": f"요청 본문이 너무 큽니다(최대 {_MAX_BODY // 2**20}MB)", "code": "too_large"}, status_code=413)
            except Exception:  # noqa: BLE001 — 전송 중 끊김
                return JSONResponse({"detail": "요청 본문을 읽지 못했습니다", "code": "bad_body"}, status_code=400)
            request._body = bytes(buf)
    t0 = time.monotonic()
    try:
        resp = await call_next(request)
    except Exception:  # noqa: BLE001
        REQ_STATS["errors"] += 1
        raise
    ms = (time.monotonic() - t0) * 1000
    if ms >= _SLOW_MS and not path.startswith(("/ws", "/api/chat", "/api/isvara", "/api/rvtools/", "/api/hostdiag/", "/api/segtraffic", "/api/system/patch", "/api/reports/generate")):
        REQ_STATS["slow"] += 1
        REQ_STATS["last_slow"] = f"{request.method} {path} {ms:.0f}ms"
        print(f"[slow] {request.method} {path} {ms:.0f}ms", flush=True)
    return resp


# 미들웨어는 나중에 등록할수록 바깥 — 순서(바깥→안): external_guard(2.21.2, 외부 이름 차단·Access 검증, 자체 보안 머리글) → 인증 → 요청 보호 → 보안 머리글
app.middleware("http")(AUTH.middleware())

# 2.21.2 외부 공개 호스트(Cloudflare Tunnel 등) — 내부 연동 경로(에이전트·Redfish push·HA·수집·메트릭·MCP)는 외부 이름으로 접근 불가
_EXT_HOSTS = {str(h).strip().lower() for h in (CFG["server"].get("external_hosts") or []) if str(h).strip()}
_EXT_BLOCK = tuple(CFG["server"].get("external_block_paths") or
                   ("/agents", "/api/redfish/events/", "/api/ha/peer", "/api/ingest", "/metrics", "/mcp", "/api/docs", "/api/openapi.json"))


def host_name(raw: str) -> str:
    """Host 머리글 → 이름만(포트·IPv6 괄호·끝 점 제거, 소문자)"""
    h = (raw or "").strip().lower()
    if h.startswith("["):
        h = h[1:].split("]", 1)[0]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def external_host(request) -> bool:
    return host_name(request.headers.get("host") or "") in _EXT_HOSTS


# 2.49.0 Cloudflare 를 거쳐 들어온 요청(CF-Ray·CF-Connecting-IP)도 외부로 본다 — server.external_hosts 를 비워 둔
# 설치에서도 연동 경로 차단·간략 헬스·외부 로그인 보호가 적용되게. 내부에서 이 머리글을 꾸며 보내면 더 엄격해질 뿐(우회 아님)
_EDGE_HDR = bool(CFG["server"].get("edge_headers_external", True))


def via_edge(request) -> bool:
    if _EXT_HOSTS and external_host(request):
        return True
    return _EDGE_HDR and bool(request.headers.get("cf-ray") or request.headers.get("cf-connecting-ip"))


AUTH.is_external = via_edge


from .security.cfaccess import CfAccess  # noqa: E402
from .mobile import Mobile, PUBLIC_PATHS as MOBILE_PUBLIC  # noqa: E402
MOBILE = Mobile(ENGINE, AUTH, CFG.get("mobile") or {})   # 2.30.0 안드로이드 앱 배포·기기 연결·알림 피드
CFA = CfAccess(CFG["server"].get("cf_access"))          # 2.22.0 Cloudflare Access JWT 원본 검증(Access 우회 차단)
EXT_STATS = {"blocked_path": 0, "access_denied": 0, "requests": 0}
_EXT_H = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Robots-Tag": "noindex, nofollow",
          "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"}
PROBE_TOKEN = secrets.token_urlsafe(24)                  # 보안 점검의 프로세스 내부 요청 표식 — 통계·감사 집계에서만 제외(통과 권한 없음)


def is_probe(request) -> bool:
    return hmac.compare_digest(request.headers.get("x-aiops-probe", ""), PROBE_TOKEN)


@app.middleware("http")
async def external_guard(request: Request, call_next):
    if bad_path(request.scope.get("path") or ""):          # 2.30.0 '..'·'//'·역슬래시·(/api 밖) 디코딩된 '?'·'#' 경로는 400 — 미들웨어 판단과 라우팅 불일치 차단
        return JSONResponse({"detail": "잘못된 요청 경로", "code": "bad_path"}, status_code=400, headers=_EXT_H)
    if via_edge(request):
        probe = is_probe(request)
        if not probe:
            EXT_STATS["requests"] += 1
        p = request.scope.get("path") or ""
        if any(p == b.rstrip("/") or p.startswith(b if b.endswith("/") else b + "/") for b in _EXT_BLOCK):
            if not probe:
                EXT_STATS["blocked_path"] += 1
            return JSONResponse({"detail": "Not Found"}, status_code=404, headers=_EXT_H)
        if CFA.enabled:
            ok, why, claims = await CFA.check(request.headers, request.cookies, count=not probe)
            if not ok and CFA.enforce and p in MOBILE_PUBLIC and request.method in ("GET", "POST") and MOBILE.cfg["allow_without_access"] and MOBILE.cfg["enabled"]:
                return await call_next(request)          # 2.30.0 앱 백그라운드 알림 확인 — 라우트가 기기 토큰·연결 코드로 직접 인증(관리자가 켠 경우만)
            if not ok and CFA.enforce:
                if probe:
                    return JSONResponse({"detail": "Cloudflare Access 인증이 필요합니다", "code": "cf_access"}, status_code=403, headers=_EXT_H)
                EXT_STATS["access_denied"] += 1
                if EXT_STATS["access_denied"] % 50 == 1:          # 폭주 시 감사로그 과다 방지(50건에 1건)
                    asyncio.ensure_future(ENGINE.audit.log("auth.cf_access", user="-", ip=client_ip(request), target=f"{request.method} {p}",
                                                           result="denied", detail={"reason": why[:120], "count": EXT_STATS["access_denied"]}))
                return JSONResponse({"detail": "Cloudflare Access 인증이 필요합니다", "code": "cf_access"}, status_code=403, headers=_EXT_H)
            if ok:
                request.state.cf_email = str(claims.get("email") or "")[:200]
        resp = await call_next(request)
        resp.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        return resp
    return await call_next(request)


# 2.48.2 평문 HTTP → HTTPS 강제. 앞단(Cloudflare·리버스 프록시)이 "방문자는 http 로 왔다"고 알려 준 요청만 돌려보냄.
#   - Cloudflare: CF-Visitor {"scheme":"http"} (터널 포함)  - 그 밖의 프록시: X-Forwarded-Proto: http 이면서 외부 이름(server.external_hosts)
#   - 장비·수집 연동 경로와 내부 직접 접속(앞단 없음)은 그대로. server.https_redirect: off 로 끔.
_HTTPS_REDIRECT = str(CFG["server"].get("https_redirect", "proxy")).strip().lower()
_HTTPS_SKIP = ("/healthz", "/readyz", "/metrics", "/api/ingest", "/agents/", "/api/ha/", "/api/redfish/events/")
_HOST_OK = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")


def plain_http_visitor(request) -> bool:
    cv = (request.headers.get("cf-visitor") or "").replace(" ", "").lower()
    if '"scheme":"http"' in cv:
        return True
    xf = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return xf == "http" and bool(_EXT_HOSTS) and external_host(request)


def https_location(request) -> str | None:
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
    if not _HOST_OK.match(host):
        return None
    if host.endswith(":80"):
        host = host[:-3]
    raw = request.scope.get("raw_path") or (request.scope.get("path") or "/").encode()
    qs = request.scope.get("query_string") or b""
    return f"https://{host}{raw.decode('latin-1')}" + (f"?{qs.decode('latin-1')}" if qs else "")


@app.middleware("http")
async def https_redirect(request: Request, call_next):
    if _HTTPS_REDIRECT != "off" and plain_http_visitor(request):
        p = request.scope.get("path") or ""
        if not (p in ("/healthz", "/readyz", "/metrics", "/api/ingest") or p.startswith(_HTTPS_SKIP)):
            loc = https_location(request)
            if loc:
                code = 301 if request.method in ("GET", "HEAD") else 308      # 308: POST 본문을 평문으로 다시 보내지 않게 메서드 유지
                return Response(status_code=code, headers={"Location": loc, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    return await call_next(request)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.include_router(AUTH.router())
from .security.oidc import Oidc  # noqa: E402
OIDC = Oidc(CFG["auth"].get("oidc") or {}, secrets.token_bytes(32))   # SSO 상태 쿠키 서명 키(프로세스 수명)
app.include_router(OIDC.router(AUTH, ENGINE.audit))


@app.get("/robots.txt", include_in_schema=False)
async def robots():
    """2.22.0 검색 엔진 수집 차단(외부 공개 시 로그인 화면이 검색에 노출되지 않게)"""
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain", headers={"Cache-Control": "public, max-age=86400"})


def _guard_notify(sev: str, msg: str, entity: str, attrs: dict) -> None:
    """2.49.0 외부 로그인 보호 판단 → 엔진 이벤트(이상징후·알림·SIEM 과 같은 경로)"""
    try:
        ENGINE.submit(LogEvent(source="aiops", connector="auth-guard", message=msg, severity=sev, host="aiops",
                               entity=entity, kind="event", attrs={**attrs, "category": "security"}))
    except Exception:  # noqa: BLE001
        pass


AUTH.guard.notify = _guard_notify


@app.get("/.well-known/security.txt", include_in_schema=False)
async def security_txt():
    """2.49.0 RFC 9116 — server.security_contact(mailto:·https:) 를 넣었을 때만 공개. 만료는 응답 시점 + 1년"""
    c = str(CFG["server"].get("security_contact") or "").strip()
    if not c or not re.match(r"^(mailto:[^\s@]+@[^\s@]+|https://[^\s]+)$", c):
        raise HTTPException(404)
    exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 365 * 86400))
    body = f"Contact: {c}\nExpires: {exp}\nPreferred-Languages: ko, en\n"
    return Response(body, media_type="text/plain; charset=utf-8", headers={"Cache-Control": "max-age=86400"})


@app.get("/healthz", include_in_schema=False)
async def healthz(request: Request):
    """생존(liveness) — 프로세스·이벤트 루프가 응답하는지만 (인증·DB 조회 없음) · 외부 이름으로는 ok 만(2.22.0)"""
    if via_edge(request):
        return {"ok": True}
    return {"ok": True, "uptime": round(time.time() - ENGINE.stats["started"], 1),
            "llm": (ENGINE.llm.status.get("state") if ENGINE.llm else "disabled")}


@app.get("/readyz", include_in_schema=False)
async def readyz(request: Request):
    """준비(readiness) — 로드밸런서(Avi/F5) 헬스 모니터·서비스 감시용. 내부 핵심 작업 정지·DB 쓰기 장기 실패·
    이벤트 루프 심각 지연이면 503. 인증 없이 열려 있으므로 세부 내용은 노출하지 않는다(외부에서는 ready 만 — 2.49.0)."""
    ok, why = ENGINE.health.ready()
    if via_edge(request):
        return JSONResponse({"ready": ok}, status_code=200 if ok else 503)
    body = {"ready": ok, "node": ENGINE.ha.node, "leader": ENGINE.ha.leader}
    if not ok:
        body["reasons"] = [w.split(":")[0] for w in why]
    return JSONResponse(body, status_code=200 if ok else 503)


@app.get("/api/ha/peer", include_in_schema=False)
async def ha_peer(request: Request):
    """이중화 상대 노드 확인용(HMAC 서명 헤더 필수)"""
    if not ENGINE.ha.secret or not ha_verify(ENGINE.ha.secret, request.headers.get("x-aiops-ha-ts", ""),
                                             request.headers.get("x-aiops-ha-sig", "")):
        raise HTTPException(401, "invalid HA signature")
    return ENGINE.ha.peer_payload()


@app.get("/api/health")
async def health_detail():
    """플랫폼 상세 상태 — 내부 작업(감독자)·파이프라인·DB·실시간 연결·외부 의존·이중화"""
    ok, why = ENGINE.health.ready()
    return {"ready": ok, "reasons": why, "runtime": ENGINE.runtime(), "jobs": ENGINE.sup.summary(), "requests": REQ_STATS,
            "pipeline": ENGINE.pipe | {"high_queue": len(ENGINE.q_hi), "low_queue": len(ENGINE.q_lo),
                                       "high_max": ENGINE.q_hi_max, "low_max": ENGINE.q_lo_max},
            "store": ENGINE.store.status(), "ws": ENGINE.hub.status(), "outbox": ENGINE.alerter.outbox_status(),
            "llm_breaker": ENGINE.llm_breaker.status(), "ai_queue": ENGINE.aq.snapshot(), "llm_enabled": bool(ENGINE.llm), "ha": ENGINE.ha.public(), "lag": ENGINE.lag.stats(),
            "issues": ENGINE.health.state["issues"], "selfcheck": ENGINE.selfcheck.snapshot(),
            "connectors": [{k: c.state().get(k) for k in ("name", "type", "state", "last_ok", "last_error", "timeouts",
                                                           "consecutive_failures", "dropped")} for c in ENGINE.connectors]}


# 2.23.0 호스트·VM 성능 상세
from .perfview import PerfView  # noqa: E402
PERF = PerfView(ENGINE, CFG.get("perfview") or {})


def _pf_kind(kind: str) -> str:
    if kind not in ("host", "vm"):
        raise HTTPException(400, "kind 는 host 또는 vm")
    return kind


@app.get("/api/perf/entities")
async def perf_entities(kind: str = "vm"):
    return {"kind": _pf_kind(kind), "items": PERF.entities(kind), "vcenters": [c.name for c in PERF.vcenters()]}


@app.get("/api/perf/top")
async def perf_top(kind: str = "vm", fresh: int = 0):
    return await PERF.top(_pf_kind(kind), bool(fresh))


@app.get("/api/perf/detail")
async def perf_detail(kind: str, name: str, vcenter: str = "", range: str = "rt", fresh: int = 0):  # noqa: A002
    try:
        return await PERF.detail(_pf_kind(kind), name[:300], vcenter[:200], range, bool(fresh))
    except KeyError as e:
        raise HTTPException(404, f"{'호스트' if kind == 'host' else 'VM'} '{name}' 을(를) 찾지 못했습니다") from e


# 2.25.0 성능 상시 감시(자체 이력·계절성 이상 탐지·동료 이상치·감시 규칙·호스트 맵)
from .perfstore import METRICS as PW_METRICS  # noqa: E402
from .perfwatch import PerfWatch  # noqa: E402
from .perfwatch import validate_rule as PW_validate  # noqa: E402
PW = PerfWatch(ENGINE, PERF, CFG.get("perfwatch") or {}, DATA_DIR)
ENGINE.perfwatch = PW                                    # 2.35.0 가정 분석의 피크 기준 계산이 성능 이력을 읽음
PERF.watch = PW


@app.get("/api/perf/watch")
async def perf_watch():
    return {"stats": PW.store.stats, "size": await asyncio.to_thread(PW.store.size), "interval": PW.store.interval,
            "alerts": PW.alerts_now(), "rules": sorted(PW.rules.values(), key=lambda r: (r["kind"], r["type"], r["id"])),
            "last_eval": PW.last_eval, "enabled": PW.store.enabled}


@app.get("/api/perf/watch/history")
async def perf_watch_history(hours: float = 24, kind: str = "", name: str = "", vcenter: str = ""):
    eid = PW.store.find(kind, name, vcenter) if kind and name else None
    if kind and name and eid is None:
        return {"items": []}
    return {"items": await PW.history(max(1.0, min(float(hours), 24 * 42)), eid)}


@app.post("/api/perf/rules")
async def perf_rule_save(request: Request):
    b = await request.json()
    if not isinstance(b, dict):
        raise HTTPException(400, "JSON 객체가 필요합니다")
    if b.get("create") and str(b.get("id") or "") in PW.rules:
        raise HTTPException(409, f"같은 ID 의 규칙이 이미 있습니다: {b.get('id')}")
    try:
        r = await asyncio.to_thread(PW.save_rule, b, who(request).get("user", ""))
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    await audit(request, "perf.rule.save", r["id"], detail=r)
    return r


@app.post("/api/perf/rules/preview")
async def perf_rule_preview(request: Request):
    b = await request.json()
    try:
        r = PW_validate(b if isinstance(b, dict) else {})
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    v = await PW.verdicts(r)
    hits = []
    for e, (sev, val, msg) in v.items():
        if sev:
            ent = PW.store.ents.get(e) or {}
            hits.append({"name": ent.get("name"), "kind": ent.get("kind"), "vcenter": ent.get("vc"), "cluster": ent.get("cluster"), "sev": sev, "value": val, "msg": msg})
    return {"evaluated": len(v), "hits": sorted(hits, key=lambda h: (h["sev"] != "critical", h["name"] or ""))[:200]}


@app.delete("/api/perf/rules/{rid}")
async def perf_rule_delete(rid: str, request: Request):
    if rid not in PW.rules:
        raise HTTPException(404, "규칙 없음")
    await asyncio.to_thread(PW.delete_rule, rid)
    await audit(request, "perf.rule.delete", rid)
    return {"ok": True}


@app.post("/api/perf/rules/reset")
async def perf_rule_reset(request: Request):
    await asyncio.to_thread(PW.reset_rules)
    await audit(request, "perf.rule.reset")
    return {"ok": True, "rules": len(PW.rules)}


@app.get("/api/perf/map")
async def perf_map(kind: str = "host"):
    """호스트 맵 — 자체 이력의 최근 5분 값 + 토폴로지(vCPU·메모리) + 지금 경보"""
    _pf_kind(kind)
    lat = PW.store.latest()
    alerts: dict[int, str] = {}
    for (rid, eid), s in PW.state.items():
        if alerts.get(eid) != "critical":
            alerts[eid] = s["sev"]
    ents = {(e["vcenter"], e["name"]): e for e in PERF.entities(kind)}
    items = []
    for eid, m in lat.items():
        en = PW.store.ents.get(eid) or {}
        if en.get("kind") != kind:
            continue
        t = ents.get((en["vc"], en["name"])) or {}
        items.append({"name": en["name"], "vcenter": en["vc"], "cluster": en.get("cluster") or t.get("cluster", ""), "host": en.get("host", ""),
                      "vcpu": t.get("vcpu"), "mem_mb": t.get("mem_mb"), "cpu_mhz": t.get("cpu_mhz"), "maintenance": t.get("maintenance", False),
                      "ts": m["ts"], "alert": alerts.get(eid), **{k: (round(m[k], 3) if isinstance(m.get(k), float) else m.get(k)) for k in PW_METRICS}})
    return {"kind": kind, "items": items, "interval": PW.store.interval, "last": PW.store.stats.get("last", 0)}


@app.post("/api/perf/explain")
async def perf_explain(request: Request):
    b = await request.json()
    if not isinstance(b, dict):
        raise HTTPException(400, "JSON 객체가 필요합니다")
    kind = _pf_kind(str(b.get("kind", "")))
    name = str(b.get("name", ""))[:300]
    try:
        text = await PERF.explain(kind, name, str(b.get("vcenter", ""))[:200])
    except KeyError as e:
        await audit(request, "perf.explain", f"{kind}:{name}", result="not_found")
        raise HTTPException(404, "대상 없음") from e
    except ValueError as e:
        await audit(request, "perf.explain", f"{kind}:{name}", result="fail", detail={"error": str(e)[:200]})
        raise HTTPException(409, str(e)) from e
    except Exception as e:  # noqa: BLE001  (AI 제공자 오류)
        await audit(request, "perf.explain", f"{kind}:{name}", result="fail", detail={"error": type(e).__name__})
        raise HTTPException(502, f"AI 응답 실패: {type(e).__name__}") from e
    await audit(request, "perf.explain", f"{kind}:{name}")
    return {"text": text}


@app.get("/api/perf/detail.csv")
async def perf_detail_csv(kind: str, name: str, vcenter: str = "", range: str = "rt"):  # noqa: A002
    try:
        d = await PERF.detail(_pf_kind(kind), name[:300], vcenter[:200], range)
    except KeyError as e:
        raise HTTPException(404, "대상 없음") from e
    return Response(PERF.csv(d), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": disposition(f"perf-{kind}-{name}-{d['range']}-{time.strftime('%Y%m%d-%H%M')}.csv")})


# 2.22.1 수집 일시정지 스위치(수동·자동)
from .ingestgate import IngestGate  # noqa: E402
GATE = IngestGate(ENGINE, CFG.get("ingest_gate") or {}, DATA_DIR)
ENGINE.gate = GATE


@app.get("/api/ingest-gate")
async def ingest_gate_get():
    return GATE.status()


@app.post("/api/ingest-gate")
async def ingest_gate_set(request: Request):
    b = await request.json()
    u = who(request).get("user", "")
    act = str(b.get("action", ""))
    try:
        if act == "pause":
            mins = b.get("minutes")
            mins = float(mins) if mins not in (None, "", 0, "0") else None
            if mins is not None and not (0 < mins <= 7 * 1440):
                raise ValueError("기간은 1분~7일")
            senders = [str(x)[:120] for x in (b.get("senders") or []) if str(x).strip()][:50]
            res = await GATE.pause(mins, str(b.get("scope") or "syslog"), senders, by=u, reason=str(b.get("reason") or "")[:300])
        elif act == "resume":
            res = await GATE.resume(u, str(b.get("reason") or "직접 재개")[:300])
        else:
            raise ValueError("action 은 pause 또는 resume")
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    await audit(request, f"ingest.{act}", res.get("scope_text") or "", detail={"minutes": b.get("minutes"), "senders": b.get("senders")})
    return res


@app.put("/api/ingest-gate/auto")
async def ingest_gate_auto(request: Request):
    b = await request.json()
    try:
        a = await GATE.set_auto(b if isinstance(b, dict) else {}, who(request).get("user", ""))
    except (TypeError, ValueError) as e:
        raise HTTPException(400, f"값 오류: {e}") from e
    await audit(request, "ingest.auto", detail=a)
    return GATE.status()


# 2.22.0 보안 상태 점검 — 주기 실행·회귀 알림·이력
from .posture import Posture  # noqa: E402
POSTURE = Posture(ENGINE, AUTH, CFA, CFG.get("posture") or {}, lambda: app, _EXT_HOSTS, DATA_DIR)
POSTURE.probe_token = PROBE_TOKEN


@app.get("/api/posture")
async def posture_get(days: int = 30):
    res = await POSTURE.ensure()
    return {**res, "history": await POSTURE.history(max(1, min(int(days), 180))), "cf_access": CFA.snapshot(),
            "external": {"hosts": sorted(_EXT_HOSTS), **EXT_STATS}, "interval_hours": POSTURE.interval / 3600,
            "alert_min_severity": POSTURE.alert_min}


@app.post("/api/posture/run")
async def posture_run(request: Request):
    res = await POSTURE.manual()
    await audit(request, "system.posture", result="ok", detail={"score": res["score"], "fail": res["counts"]["fail"], "warn": res["counts"]["warn"]})
    return {**res, "history": await POSTURE.history(30), "cf_access": CFA.snapshot(), "external": {"hosts": sorted(_EXT_HOSTS), **EXT_STATS},
            "interval_hours": POSTURE.interval / 3600, "alert_min_severity": POSTURE.alert_min}


def csv_cell(v) -> str:
    """CSV 수식 주입 방지 — =,+,-,@,탭,CR 로 시작하면 ' 를 붙임"""
    v = str(v if v is not None else "")
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.get("/api/posture.csv")
async def posture_csv():
    import csv
    import io
    res = await POSTURE.ensure()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["category", "id", "severity", "status", "title", "evidence", "fix"])
    for i in res["items"]:
        w.writerow([csv_cell(x) for x in (i["cat"], i["id"], i["sev"], i["status"], i["title"], i["evidence"], i["fix"])])
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": disposition(f"aiops-posture-{time.strftime('%Y%m%d-%H%M')}.csv")})


@app.get("/api/system/selfcheck")
async def selfcheck_get():
    """자가 점검 — 기동 전 점검 결과·DB 크기/표별 행 수/WAL·quick_check·백업 검증·자원·인증서"""
    ENGINE.selfcheck.checks()
    return ENGINE.selfcheck.snapshot()


@app.post("/api/system/selfcheck/run")
async def selfcheck_run(request: Request):
    """지금 점검 — DB quick_check + WAL checkpoint + 최신 백업 integrity_check(관리자)"""
    sc = ENGINE.selfcheck
    qc = await sc.quick_check()
    left = await sc.checkpoint()
    bk = await sc.verify_backup()
    await sc.refresh()
    await audit(request, "system.selfcheck", result="ok" if qc["result"] == "ok" and bk.get("result") in ("ok", "none") else "fail",
                detail={"quick_check": qc["result"][:200], "wal_left": left, "backup": bk.get("result", "")[:200]})
    return {"quick_check": qc, "wal_frames_left": left, "backup": bk, "snapshot": sc.snapshot()}


@app.get("/api/outbox")
async def outbox(state: str = "", limit: int = 200):
    """외부 알림 발송함 — pending·retry·sent·dead·skipped_standby"""
    sql, p = "SELECT id,created,channel,ref,title,state,attempts,next_at,last_error,sent_at FROM outbox", []
    if state:
        sql += " WHERE state = ?"
        p.append(state)
    sql += " ORDER BY id DESC LIMIT ?"
    p.append(min(limit, 2000))
    return {"items": await ENGINE.store.q(sql, p), "status": ENGINE.alerter.outbox_status()}


@app.post("/api/outbox/retry")
async def outbox_retry(request: Request):
    b = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    n = await ENGINE.alerter.retry_dead([int(x) for x in (b.get("ids") or [])] or None)
    await audit(request, "outbox.retry", detail={"count": n})
    return {"ok": True, "count": n}


@app.get("/")
async def index():
    return _index_html()


@app.get("/noc", include_in_schema=False)
async def noc_page():
    """통합 관제 화면(월 디스플레이용) — vCenter·ESXi / NSX·Edge / NSX ALB / VKS 슬롯"""
    return FileResponse(STATIC / "noc.html")


@app.get("/noc/{page}", include_in_schema=False)
async def noc_wall(page: str):
    """관제 월 추가 페이지 — 인프라 지도 · 토폴로지 · 이벤트·인시던트 · 보안 · AI·플랫폼 · 경영진 요약(exec) (페이지 자동 순환 지원)"""
    if page not in ("infra", "events", "security", "ai", "topology", "exec", "network"):
        raise HTTPException(404)
    return FileResponse(STATIC / "nocwall.html")


@app.get("/noc/d/{sid}", include_in_schema=False)
async def noc_domain_page(sid: str):
    """관제 도메인 상세 탭(vCenter·NSX·NSX ALB·VKS·물리 서버·VM 게스트·보안) — 실시간 이벤트 스트림 포함"""
    if not sid.replace("-", "").replace("_", "").isalnum() or len(sid) > 40:
        raise HTTPException(404)
    return FileResponse(STATIC / "nocwall.html")


@app.get("/login", include_in_schema=False)
async def login_page():
    return FileResponse(STATIC / "login.html")


def _snapshot(seq: int) -> str:
    return json.dumps({"type": "snapshot", "seq": seq, "build": ENGINE.build, "boot": ENGINE.stats["started"], "data": {
        "logs": list(ENGINE.buffer)[-800:],
        "anomalies": sorted((a.to_dict() for a in ENGINE.anomalies.values()), key=lambda x: x["last_seen"], reverse=True)[:300],
        "status": ENGINE.status()}}, ensure_ascii=False, default=str)


@app.websocket("/ws")
async def ws(sock: WebSocket):
    # 2.22.0 외부 이름: Access 토큰 확인(HTTP 미들웨어는 WebSocket 을 거치지 않음) · 교차 출처 WebSocket 차단(CSWSH)
    origin = sock.headers.get("origin", "")
    if origin and CFG["server"].get("ws_origin_check", True):
        from urllib.parse import urlsplit
        oh = (urlsplit(origin).hostname or "").rstrip(".")
        allowed = {host_name(sock.headers.get("host") or ""), host_name(sock.headers.get("x-forwarded-host") or "")} - {""}
        if oh and allowed and oh not in allowed:
            await sock.close(code=4403)
            return
    if _EXT_HOSTS and external_host(sock) and CFA.enabled and CFA.enforce:
        ok, _, _ = await CFA.check(sock.headers, sock.cookies)
        if not ok:
            EXT_STATS["access_denied"] += 1
            await sock.close(code=4403)
            return
    user = AUTH.ws_user(sock)
    if user is None:
        await sock.close(code=4401)          # 세션 만료/미인증 → 클라이언트가 /login 으로 이동
        return
    await sock.accept()
    ENGINE.hub.add(sock, user, _snapshot)    # 스냅샷은 클라이언트 송신 큐 맨 앞(이후 메시지와 공백 없음)
    try:
        while True:
            # 반쯤 끊긴 연결은 uvicorn 프로토콜 ping/pong(ws_ping_interval·timeout)과 송신 시간 초과로 정리된다.
            # ws_idle_timeout>0 이면 앱 메시지(브라우저 'ping' 25초) 무수신도 끊는다 — 외부 연동 클라이언트는 0(기본) 유지
            try:
                if ENGINE.hub.idle_timeout > 0:
                    txt = await asyncio.wait_for(sock.receive_text(), timeout=ENGINE.hub.idle_timeout)
                else:
                    txt = await sock.receive_text()
            except asyncio.TimeoutError:
                await sock.close(code=1001)
                break
            if txt == "resync":              # 클라이언트가 seq 누락을 감지 → 스냅샷 재전송
                ENGINE.hub.resync(sock, _snapshot)
            elif txt.startswith("{"):        # {"op":"tail", hosts, sources, q, min} | {"op":"untail"}
                try:
                    op = json.loads(txt)
                except ValueError:
                    op = {}
                if op.get("op") == "tail":
                    ENGINE.hub.set_tail(sock, op)
                elif op.get("op") == "untail":
                    ENGINE.hub.set_tail(sock, None)
            if AUTH.enabled and user.get("sid") and user["sid"] not in AUTH.sessions:
                await sock.close(code=4401)   # 로그아웃·만료·권한 변경 시 실시간 스트림도 차단
                break
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        ENGINE.hub.discard(sock)


# ------------------------------------------------------------------ 커넥터
@app.get("/api/collection")
async def collection():
    """항목별 수집 현황(마지막 수신·분당 유입·최근 30분 추이·상태 판정)"""
    return ENGINE.collection.snapshot(ENGINE.connectors)


@app.get("/api/connectors")
async def list_connectors():
    return [c.state() for c in ENGINE.connectors]


# ------------------------------------------------------------------ 자동 발견 커넥터(VKS) — 편집(덮어쓰기)·삭제(제외)·다시 포함
def _vks_ov() -> dict:
    o = copy.deepcopy(CFG.get("vks_overrides") or {})
    o.setdefault("excluded", [])
    o.setdefault("overrides", {})
    return o


@app.get("/api/connectors/discovered")
async def discovered_list():
    from .security.secrets import mask_tree
    ov = CFG.get("vks_overrides") or {}
    items = []
    for c in ENGINE.connectors:
        if not getattr(c, "discovered_by", ""):
            continue
        cfg = {k: v for k, v in c.cfg.items() if k not in ("password", "token")}
        items.append({**c.state(), "discovered_by": c.discovered_by, "role": getattr(c, "role", ""),
                      "cluster": getattr(c, "cluster_label", c.name), "cfg": cfg,
                      "override": mask_tree((ov.get("overrides") or {}).get(c.name) or {})})
    return {"items": sorted(items, key=lambda x: (x["discovered_by"], x["role"] != "supervisor", x["name"])),
            "excluded": list(ov.get("excluded") or []), "report": getattr(ENGINE, "vks_report", {})}


@app.put("/api/connectors/discovered/{name}")
async def discovered_edit(name: str, request: Request):
    """허용 필드만 덮어씀: enabled·interval·log_namespaces·problem_logs·username·password·verify_tls·environment·cluster_name"""
    b = await request.json()
    allow = {"enabled", "interval", "log_namespaces", "problem_logs", "username", "password", "verify_tls", "environment",
             "cluster_name", "include_normal", "timeout"}
    o = _vks_ov()
    new = {k: v for k, v in (b.get("override") or {}).items() if k in allow and v not in (None, "")}
    if new:
        o["overrides"][name] = new
    else:
        o["overrides"].pop(name, None)
    await SETTINGS.put("vks_overrides", o, who(request).get("user", ""))
    rep = await ENGINE.discover_vks_once()
    await audit(request, "connector.discovered_edit", name, detail={"fields": sorted(new)})
    return {"ok": True, "report": rep}


@app.delete("/api/connectors/discovered/{name}")
async def discovered_delete(name: str, request: Request):
    o = _vks_ov()
    if name not in o["excluded"]:
        o["excluded"].append(name)
    await SETTINGS.put("vks_overrides", o, who(request).get("user", ""))
    pr = ENGINE.prune_discovered()
    await audit(request, "connector.discovered_exclude", name)
    return {"ok": True, "pruned": pr}


@app.post("/api/connectors/discovered/{name}/include")
async def discovered_include(name: str, request: Request):
    o = _vks_ov()
    o["excluded"] = [x for x in o["excluded"] if x != name]
    await SETTINGS.put("vks_overrides", o, who(request).get("user", ""))
    rep = await ENGINE.discover_vks_once()
    await audit(request, "connector.discovered_include", name)
    return {"ok": True, "report": rep}


@app.post("/api/connectors/{name}/test")
async def test_connector(name: str, request: Request):
    for c in ENGINE.connectors:
        if c.name == name:
            res = await c.test()
            await audit(request, "connector.test", name, "ok" if res.get("ok") else "fail")
            return res
    raise HTTPException(404, "connector not found")


@app.post("/api/connectors/test-all")
async def test_all(request: Request):
    targets = [c for c in ENGINE.connectors if c.enabled]
    res = await asyncio.gather(*[c.test() for c in targets], return_exceptions=True)
    await audit(request, "connector.test_all", detail={"count": len(targets)})
    return {c.name: (r if not isinstance(r, Exception) else {"ok": False, "error": str(r)}) for c, r in zip(targets, res)}


# ------------------------------------------------------------------ 로그/이상징후
@app.get("/api/logs")
async def logs(minutes: int = 60, source: str | None = None, q: str | None = None,
               min_severity: str = "debug", limit: int = 1000, host: str | None = None):
    sev = [s for s in SEVERITIES if SEV_RANK[s] >= SEV_RANK.get(min_severity, 0)]
    now = time.time()
    return await ENGINE.store.query_logs(now - max(1, min(minutes, 10080)) * 60, now, source, q, sev, min(limit, 10000), host=host)   # 2.30.0 조회 범위 상한 7일


_KNOWN: dict[str, Any] = {"t": 0.0, "rows": []}


@app.get("/api/hosts/known")
async def hosts_known(hours: int = 24):
    """실시간 로그 보기용 호스트 목록: 최근 로그 수신 호스트 + vCenter 토폴로지(ESXi·VM) + 에이전트."""
    now = time.time()
    if now - _KNOWN["t"] > 30:
        if not _KNOWN.get("seeded"):                     # 기동 후 1회만 DB(최근 1시간) — 이후는 수신 시 메모리 집계(2.22.1, 큰 DB 전체 훑기 제거)
            for r in await ENGINE.store.known_hosts(now - 3600):
                hs = ENGINE.hostseen.setdefault(r["host"], [set(), 0, 0.0])
                hs[0].update(x for x in (r["sources"] or "").split(",") if x)
                hs[1] += int(r["n"] or 0)
                hs[2] = max(hs[2], float(r["last"] or 0))
            _KNOWN["seeded"] = True
        cut = now - min(hours, 168) * 3600
        merged: dict[str, dict] = {}
        for h, (srcs, n, last) in list(ENGINE.hostseen.items()):
            if last < cut:
                continue
            r = merged.setdefault(h.lower(), {"host": h.lower(), "sources": [], "n": 0, "last": 0.0, "kind": ""})
            r["sources"] = sorted(set(r["sources"]) | srcs)
            r["n"] += n
            r["last"] = max(r["last"], last)
        rows = merged
        for c in ENGINE.connectors:
            topo = getattr(c, "topology", None)
            if not isinstance(topo, dict):
                continue
            for h in topo.get("hosts", {}):
                rows.setdefault(h.lower(), {"host": h.lower(), "sources": [], "n": 0, "last": None, "kind": ""})["kind"] = "esxi"
            for v, vv in topo.get("vms", {}).items():
                if vv.get("power") == "poweredOn":
                    rows.setdefault(v.lower(), {"host": v.lower(), "sources": [], "n": 0, "last": None, "kind": ""})["kind"] = "vm"
        for a in ENGINE.agents.items.values() if isinstance(getattr(ENGINE.agents, "items", None), dict) else []:
            hn = str(a.get("host", "")).lower() if isinstance(a, dict) else ""
            if hn:
                rows.setdefault(hn, {"host": hn, "sources": [], "n": 0, "last": None, "kind": ""})["kind"] = "agent"
        _KNOWN.update(t=now, rows=sorted(rows.values(), key=lambda r: (-(r["last"] or 0), r["host"])))
    return {"items": _KNOWN["rows"][:3000], "active_window_s": 900}


@app.get("/api/live")
async def live(after_id: int = 0, limit: int = 500):
    """메모리 버퍼에서 after_id 이후 로그 (폴링형 외부 연동용)."""
    out = [e for e in ENGINE.buffer if e["id"] > after_id]
    return out[-min(limit, 5000):]


@app.get("/api/alerts/recent")
async def recent_alerts(after_seq: int = 0):
    return [a for a in ENGINE.alerter.recent if a["seq"] > after_seq]


@app.get("/api/anomalies")
async def anomalies(limit: int = 300):
    return sorted((a.to_dict() for a in ENGINE.anomalies.values()), key=lambda x: x["last_seen"], reverse=True)[:limit]


@app.post("/api/anomalies/{aid}/ack")
async def ack(aid: str, request: Request):
    if not await ENGINE.ack(aid):
        raise HTTPException(404)
    await audit(request, "anomaly.ack", aid)
    return {"ok": True}


@app.post("/api/anomalies/{aid}/analyze")
async def reanalyze(aid: str, request: Request):
    if not await ENGINE.reanalyze(aid):
        raise HTTPException(400, "LLM 비활성 또는 대상 없음")
    await audit(request, "anomaly.reanalyze", aid)
    return {"ok": True}


@app.post("/api/anomalies/{aid}/silence")
async def silence(aid: str, request: Request):
    """같은 지문(fingerprint)의 이상징후 알림·인시던트 생성을 기한부 억제 (기록은 계속 남음)"""
    b = await request.json()
    hours = max(0.25, min(float(b.get("hours", 4)), 24 * 30))
    reason = str(b.get("reason") or "").strip()
    if not reason:
        raise HTTPException(400, "사유를 입력하세요")
    try:
        sid = await ENGINE.silence(aid, hours, reason, who(request)["user"])
    except KeyError:
        raise HTTPException(404)
    await audit(request, "silence.create", aid, detail={"id": sid, "hours": hours, "reason": reason})
    return {"ok": True, "id": sid}


@app.get("/api/status")
async def status():
    return ENGINE.status()


@app.get("/api/llm/health")
async def llm_health():
    if not ENGINE.llm:
        return {"state": "disabled"}
    return await ENGINE.llm.health()


@app.post("/api/alerts/test")
async def alert_test(request: Request):
    res = await ENGINE.alerter.test()
    await audit(request, "alert.test")
    return res


# ------------------------------------------------------------------ AI 질의(스트리밍)
@app.post("/api/chat")
async def chat(req: Request):
    if not ENGINE.llm:
        raise HTTPException(400, "LLM 비활성")
    body = await req.json()
    question = str(body.get("question", ""))[:4000]
    aid = body.get("anomaly_id")
    await audit(req, "ai.chat", aid or "", detail={"q": question[:200]})
    parts = []
    from . import chatctx
    ents = chatctx.find_entities(ENGINE, question)          # 질문 대상 개체(호스트·VM·데이터스토어·클러스터·장비)
    if not ents and aid and aid in ENGINE.anomalies:
        ev0 = ENGINE.anomalies[aid].event
        ents = chatctx.find_entities(ENGINE, f"{ev0.get('host', '')} {ev0.get('entity', '')}", limit=2)
    briefs = [chatctx.entity_brief(ENGINE, e) for e in ents]
    for e, b in zip(ents, briefs):
        parts.append(f"## 질문 대상: {e['name']} ({ {'host': 'ESXi 호스트', 'vm': 'VM', 'datastore': '데이터스토어', 'cluster': '클러스터'}.get(e['kind'], '장비·개체') }"
                     f"{', ' + e['vcenter'] if e.get('vcenter') else ''}) — 이 절을 최우선 근거로 사용\n" + wrap(b["text"], 7000))
    if aid and aid in ENGINE.anomalies:
        a = ENGINE.anomalies[aid]
        parts.append("## 선택한 이상징후\n" + wrap(json.dumps({"event": a.event, "ai": a.ai, "reasons": a.reasons,
                                                         "context": [c["message"][:300] for c in a.context]},
                                                        ensure_ascii=False, default=str), 6000))
    recent = sorted(ENGINE.anomalies.values(), key=lambda x: x.last_seen, reverse=True)[:25]
    parts.append("## 최근 이상징후\n" + wrap("\n".join(
        f"- {time.strftime('%H:%M:%S', time.localtime(a.last_seen))} [{a.severity}] {a.event['source']} "
        f"{a.title} (x{a.count})" for a in recent), 6000))
    warn_logs = [e for e in list(ENGINE.buffer)[-400:] if SEV_RANK.get(e["severity"], 0) >= 2][-40:]
    parts.append("## 최근 경고 이상 로그\n" + wrap("\n".join(
        f"- {time.strftime('%H:%M:%S', time.localtime(e['ts']))} [{e['severity']}] {e['source']} {e['host']} {e['message'][:200]}"
        for e in warn_logs), 8000))

    try:                                          # 운영 중 버전 — 문서 적용 버전과 비교하도록
        from .knowledge import env_versions
        ev = {k: sorted(x for x in v if not x.endswith(".x")) for k, v in env_versions(ENGINE).items() if v}
        if ev:
            parts.append("## 운영 중 제품 버전(수집값)\n" + ", ".join(f"{k} {'/'.join(v)}" for k, v in ev.items()))
    except Exception:  # noqa: BLE001
        pass
    sli_txt = _sli_context()
    if sli_txt:
        parts.append("## 성능 SLI 현황(Isvara 4대 경합 지표, 로컬 계산)\n" + wrap(sli_txt, 3000))
    iso = None
    if ENGINE.isvara.enabled and ENGINE.isvara.chat_grounding and ENGINE.isvara.relevant(question):
        try:
            iso = await asyncio.wait_for(ENGINE.isvara.ask(question), ENGINE.isvara.timeout + 2)
            parts.append("## Isvara iO 답변(isvara.io 가이드 근거 — 답변에 [I1]로 인용, 링크 그대로 제시)\n[I1] "
                         + wrap(iso["answer"], 4000, "UNTRUSTED_DOC") + "\n링크: " + " ".join(l["url"] for l in iso["links"]))
        except Exception as e:  # noqa: BLE001 — 외부 근거는 선택 사항(실패해도 답변은 계속)
            iso = None
            print(f"[isvara] 근거 생략: {e}", flush=True)

    src = ENGINE.anomalies[aid].event.get("source") if aid and aid in ENGINE.anomalies else None
    refs, queries = [], []
    en = await ENGINE.kblink.en_query(question) if (ENGINE.rag.has_any() or ENGINE.websearch.enabled) else ""   # 한국어 질문 → 영문 검색어
    if ENGINE.rag.has_any():
        # 2.6.1: 개체 이름·FQDN·일반어를 뺀 질문 + 대상의 실제 증상으로 여러 번 검색 → 순위 병합 → 관련도 낮은 문서 제외
        refs, queries = await chatctx.search_refs(ENGINE, question, en, ents, briefs, src,
                                                  extra=ENGINE.anomalies[aid].event.get("message", "")[:400] if aid and aid in ENGINE.anomalies else "")
        if aid and aid in ENGINE.anomalies:                  # 선택한 이상징후에 이미 붙은 근거·자동 연결 문서도 함께
            a0 = ENGINE.anomalies[aid]
            have = {r.get("doc_id") or r.get("url") for r in refs}
            for h in (a0.ai or {}).get("references") or []:
                if (h.get("doc_id") or h.get("url")) not in have and len(refs) < 8:
                    more = await ENGINE.rag.search(f"{h.get('title', '')} KB {h.get('kb', '')}", source=src, intent="chat", k=1)
                    refs += [m for m in more if (m.get("doc_id") or m.get("url")) not in have]
    web, web_q = [], []
    wt = body.get("web")
    if ENGINE.websearch.want(len(refs), wt if isinstance(wt, bool) else None):
        # 2.7.0 웹 검색 — 밖으로는 정리된 검색어만(개체 이름·FQDN·IP·이메일·숫자 제거): 영문 질문 > 질문 > 대상의 첫 증상
        names = [e["name"] for e in ents]
        wq = []
        for cand in (en, question):
            qx = chatctx.keywords(chatctx.clean_query(cand, names))
            if qx and chatctx.meaningful(qx) and qx not in wq:
                wq.append(qx)
                break
        for b in briefs:
            for s_ in b["symptoms"][:1]:
                qx = chatctx.keywords(chatctx.clean_query(s_, names))
                if qx and chatctx.meaningful(qx) and qx not in wq:
                    wq.append(qx)
        try:
            web, web_q = await asyncio.wait_for(ENGINE.websearch.gather(wq[:2]), ENGINE.websearch.cfg["timeout"] * 2 + 8)
        except Exception as e:  # noqa: BLE001 — 웹 근거는 선택 사항
            print(f"[web] 근거 생략: {type(e).__name__}: {e}", flush=True)
        if web:
            parts.append("## 웹 검색 근거 (공개 웹 — 답변에 [W#]로 인용하고 URL 그대로 제시. 사내 KB·로그보다 신뢰 낮음, 공식 Broadcom 문서 우선)\n" + "\n\n".join(
                f"[{w['ref']}] {w['title']} ({w['domain']}, {w['url']})\n" + wrap(w["text"], 3500, "UNTRUSTED_DOC") for w in web))
        await audit(req, "ai.web_search", ",".join(web_q)[:200], detail={"queries": web_q, "results": len(web)})
    if refs:
        parts.append("## 참고 지식 (KB·TechDocs 라이브러리·RAG 팩 — 답변에 [R#]로 인용, 여기 없는 KB/CVE 번호는 만들지 말 것)\n" + "\n\n".join(
            f"[R{i}] {r['title']} ({r['type']}{', KB ' + r['kb'] if r.get('kb') else ''}"
            f"{', 적용 버전 ' + '/'.join(r['versions']) if r.get('versions') else ''}, {r['url']})\n"
            + wrap(r["text"], 2400 if r.get("pack") == "library" else 1200, "UNTRUSTED_DOC")
            for i, r in enumerate(refs, 1)))

    async def gen():
        rl = [{"ref": f"R{i}", "title": r["title"], "url": r["url"], "type": r["type"], "pack": r["pack_name"], "kb": r.get("kb", ""),
               "doc_id": r.get("doc_id", ""), "sections": r.get("sections") or [], "versions": r.get("versions") or []}
              for i, r in enumerate(refs, 1)]
        rl += [{"ref": w["ref"], "title": w["title"], "url": w["url"], "type": "web", "pack": "웹 검색", "domain": w["domain"],
                "preferred": w.get("preferred", False)} for w in web]
        if iso:
            rl += [{"ref": "I1", "title": "Isvara iO · " + l["title"], "url": l["url"], "type": "isvara", "pack": "isvara.io"}
                   for l in (iso["links"] or [{"url": "https://isvara.io/", "title": "isvara.io"}])]
        yield "data: " + json.dumps({"refs": rl, "queries": queries, "web_queries": web_q, "entities": [e["name"] for e in ents],
                                     "web": ENGINE.websearch.status()["enabled"]}, ensure_ascii=False) + "\n\n"
        try:
            mask_names = sorted({str(x) for x in [e["name"] for e in ents] + [a.event.get(k) for a in recent for k in ("host", "entity")]   # 2.30.0 외부 공급자 가명화 대상
                                 + [e.get(k) for e in warn_logs for k in ("host", "entity")] if x})
            async for tok in ENGINE.llm.chat_stream(question, "\n\n".join(parts), lang=str(body.get("lang") or ""), names=mask_names):
                yield f"data: {json.dumps({'t': tok}, ensure_ascii=False)}\n\n"
        except Exception as e:  # noqa: BLE001
            yield f"data: {json.dumps({'error': f'{type(e).__name__}: {e}'}, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


# ------------------------------------------------------------------ 모니터(Datadog 방식)
# ---------------------------------------------------------------- VM 액티비티(이동·HA·생성·삭제)
@app.get("/api/vm/moves")
async def vm_moves(hours: float = 24, vm: str = "", type: str = "", q: str = "", limit: int = 1000, user: str = "", flag: str = ""):
    types = [t for t in type.split(",") if t] or None
    return {"items": await ENGINE.moves.query(max(0.1, min(hours, 24 * 90)), vm, types, q, max(1, min(limit, 5000)), user=user, flag=flag)}


@app.get("/api/vm/moves/summary")
async def vm_moves_summary(hours: float = 24):
    return await ENGINE.moves.summary(max(1.0, min(hours, 24 * 30)))


@app.get("/api/vm/activity.csv")
async def vm_activity_csv(request: Request, hours: float = 24, vm: str = "", type: str = "", q: str = "", user: str = "", flag: str = ""):
    """VM 액티비티 CSV(Excel 호환 UTF-8 BOM) — 화면 필터와 같은 조건, 최대 50,000행"""
    types = [t for t in type.split(",") if t] or None
    rows = await ENGINE.moves.query(max(0.1, min(hours, 24 * 90)), vm, types, q, 50000, user=user, flag=flag)
    await audit(request, "vm_activity.export", f"{len(rows)} rows", detail={"hours": hours, "type": type, "flag": flag})
    return Response(ENGINE.moves.to_csv(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": disposition(f'vm-activity-{time.strftime("%Y%m%d-%H%M")}.csv')})


@app.get("/api/vm/activity/timeline")
async def vm_activity_timeline(vm: str, days: float = 90):
    if not vm.strip():
        raise HTTPException(400, "vm 필요")
    return await ENGINE.moves.timeline(vm.strip()[:200], max(1.0, min(days, 400)))


@app.get("/api/vm/activity/rules")
async def vm_activity_rules():
    return ENGINE.moves.rules_view()


@app.put("/api/vm/activity/rules")
async def vm_activity_rules_put(request: Request):
    """위험 신호 규칙(업무 시간·휴일·대량 작업 임계·보호 VM·서비스 계정) — 관리자(settings)"""
    b = await request.json()
    try:
        r = await ENGINE.moves.save_rules(b if isinstance(b, dict) else {}, who(request)["user"])
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    await audit(request, "vm_activity.rules", "update", detail=r["rules"])
    return r


@app.get("/api/vm/alarms")
async def vm_alarms():
    return {"items": ENGINE.moves.alarms()}


# ---------------------------------------------------------------- AI 분석: 토글·공급자·조절기·패턴
@app.get("/api/ai")
async def ai_overview():
    from .llm import TASKS
    return {"state": ENGINE.ai_state(), "queue": ENGINE.aq.snapshot(), "governor": ENGINE.gov.snapshot(),
            "providers": (ENGINE.llm.status.get("providers") if ENGINE.llm else {}), "routing": (ENGINE.llm.status.get("routing") if ENGINE.llm else {}),
            "last_used": (ENGINE.llm.last_used if ENGINE.llm else {}), "patterns": ENGINE.patterns.summary(), "tasks": list(TASKS),
            "breaker": ENGINE.llm_breaker.status()}


@app.get("/api/ai/catalog")
async def ai_catalog():
    from .llm import DEFAULT_MODEL, DEFAULT_URL, TASKS, TYPES
    from .aigov import DEFAULTS as GOV
    return {"types": TYPES, "default_url": DEFAULT_URL, "default_model": DEFAULT_MODEL, "tasks": list(TASKS), "governor": GOV,
            "task_labels": {"analyze": "이상징후 판정", "rca": "인시던트 근본원인", "chat": "AI 질의", "brief": "관제 브리핑", "report": "리포트 요약"}}


@app.post("/api/ai/toggle")
async def ai_toggle(request: Request):
    b = await request.json()
    on = bool(b.get("on"))
    res = await ENGINE.set_ai(on)
    cur = dict(CFG.get("llm") or {})
    cur["analysis_enabled"] = on
    await SETTINGS.put("llm", cur, who(request).get("user", ""))     # 재기동 후에도 유지
    await audit(request, "ai.toggle", "llm", detail=res)
    return {**res, "state": ENGINE.ai_state()}


@app.get("/api/ai/patterns")
async def ai_patterns(q: str = "", state: str = "", limit: int = 300):
    return {"items": ENGINE.patterns.list(q, state, max(1, min(limit, 2000))), "summary": ENGINE.patterns.summary()}


@app.post("/api/ai/patterns/{key}/{action}")
async def ai_pattern_action(key: str, action: str, request: Request):
    pt = ENGINE.patterns
    if key not in pt.rows:
        raise HTTPException(404, "패턴 없음")
    if action == "exclude":
        b = await request.json()
        pt.exclude(key, bool(b.get("on", True)))
    elif action == "forget":
        pt.forget(key)
    elif action == "reanalyze":
        pt.forget(key)
        cand = sorted((a for a in ENGINE.anomalies.values() if (a.event or {}).get("pattern") == key), key=lambda a: -a.last_seen)
        if not cand:
            raise HTTPException(409, "이 패턴의 최근 이상징후가 메모리에 없습니다 — 다음 발생 때 다시 분석합니다")
        if not await ENGINE.reanalyze(cand[0].id):
            raise HTTPException(409, "재분석 요청 실패(LLM 미설정 또는 대기열 상한)")
    else:
        raise HTTPException(400, "action: exclude | forget | reanalyze")
    await audit(request, f"ai.pattern.{action}", key)
    await pt.flush()
    r = pt.rows[key]
    return {"ok": True, "key": key, "state": r["state"], "excluded": r["excluded"], "analyzed": bool(r.get("analysis"))}


@app.post("/api/ai/providers/test")
async def ai_provider_test(request: Request):
    """설정 화면 '연결 시험' — 저장 전 입력값(마스킹된 키는 저장된 값으로)으로 임시 클라이언트를 만들어 시험"""
    from .llm import LLMClient
    from .settings_store import _keep_secrets
    b = await request.json()
    name = str(b.get("name") or "")
    val = b.get("value")
    if isinstance(val, dict):
        from .llm import provider_defs
        from .security.secrets import mask_redirect
        bad = mask_redirect(val, {**(CFG.get("llm") or {}), "providers": provider_defs(CFG.get("llm") or {})}, "llm")
        if bad:                                              # 2.30.0 저장된 API 키('********')를 다른 주소로 보내는 시험은 거부
            raise HTTPException(400, f"주소({bad})가 저장된 값과 다릅니다 — 저장된 API 키는 다른 주소로 보낼 수 없으니 키를 다시 입력한 뒤 시험하세요")
        merged = _keep_secrets(val, CFG.get("llm") or {})
        cli = LLMClient(merged)
        try:
            return await cli.test(name)
        finally:
            for p in cli.providers.values():
                await p.close()
    if not ENGINE.llm:
        return {"ok": False, "error": "LLM 사용 안 함(enabled=false)"}
    return await ENGINE.llm.test(name)


# ---------------------------------------------------------------- 보안: FortiGate(syslog 집계·위협 탐지)
@app.get("/api/security/fortigate")
async def security_fortigate(minutes: int = 60):
    return ENGINE.fortigate.snapshot(max(5, min(int(minutes), 180)))


@app.put("/api/security/fortigate/config")
async def security_fortigate_config(request: Request):
    from .fortigate import DEFAULTS
    body = await request.json()
    val = {k: body[k] for k in DEFAULTS if k in body}
    ENGINE.fortigate.configure(val)
    await SETTINGS.put("fortigate", ENGINE.fortigate.cfg, who(request).get("user", ""))
    await audit(request, "fortigate.config", "fortigate", detail=ENGINE.fortigate.cfg)
    return {"ok": True, "config": ENGINE.fortigate.cfg}


@app.get("/api/monitors")
async def monitors_list():
    from . import monitors as M
    items = [ENGINE.monitors.summary(m) for m in ENGINE.monitors.defs.values()]
    cnt: dict[str, int] = {}
    for x in items:
        k = "MUTED" if x["muted"] else x["status"]
        cnt[k] = cnt.get(k, 0) + 1
    order = {"ALERT": 0, "WARN": 1, "NO_DATA": 2, "PENDING": 3, "OK": 4}
    items.sort(key=lambda x: (x["muted"], order.get(x["status"], 9), x["priority"], x["name"]))
    return {"items": items, "summary": cnt, "types": M.TYPES, "interval": ENGINE.monitors.interval}


@app.get("/api/monitors/catalog")
async def monitors_catalog():
    from . import monitors as M
    srcs = sorted({c.source for c in ENGINE.connectors} | {"esxi", "vcenter", "nsx", "nsx-edge", "avi", "vks", "vks-supervisor", "vm", "baremetal",
                                                          "redfish", "fortigate", "syslog", "snmp", "sddc", "vcfops", "vcflogs"})
    return {"types": M.TYPES, "metrics": {k: {"label": v[0], "unit": v[1], "group": v[2]} for k, v in M.METRICS.items()},
            "presets": M.PRESETS, "sources": srcs, "severities": M.SEVS, "priorities": list(M.PRIO_SEV)}


@app.post("/api/monitors/preview")
async def monitors_preview(request: Request):
    from . import monitors as M
    try:
        m = M.normalize(await request.json())
    except ValueError as e:
        raise HTTPException(400, str(e))
    vals = await ENGINE.monitors.values(m)
    rows = sorted(({"group": g, "value": v, "state": ENGINE.monitors.judge(m, v)} for g, v in vals.items()),
                  key=lambda x: (["ALERT", "WARN", "NO_DATA", "OK"].index(x["state"]), x["group"]))
    return {"groups": rows[:500], "total": len(rows)}


@app.post("/api/monitors")
async def monitors_create(request: Request):
    b = await request.json()
    b.pop("id", None)
    try:
        m = await ENGINE.monitors.save(b, who(request).get("user", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    await audit(request, "monitor.create", m["name"], detail={"id": m["id"], "type": m["type"]})
    return m


@app.get("/api/monitors/{mid}")
async def monitors_get(mid: str):
    if mid not in ENGINE.monitors.defs:
        raise HTTPException(404)
    return await ENGINE.monitors.detail(mid)


@app.put("/api/monitors/{mid}")
async def monitors_update(mid: str, request: Request):
    if mid not in ENGINE.monitors.defs:
        raise HTTPException(404)
    b = await request.json()
    b["id"] = mid
    for k in ("muted_until", "mute_reason"):
        b.setdefault(k, ENGINE.monitors.defs[mid].get(k))
    try:
        m = await ENGINE.monitors.save(b, who(request).get("user", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    await audit(request, "monitor.update", m["name"], detail={"id": mid})
    return m


@app.delete("/api/monitors/{mid}")
async def monitors_delete(mid: str, request: Request):
    name = (ENGINE.monitors.defs.get(mid) or {}).get("name", mid)
    if not await ENGINE.monitors.delete(mid):
        raise HTTPException(404)
    await audit(request, "monitor.delete", name, detail={"id": mid})
    return {"ok": True}


@app.post("/api/monitors/{mid}/mute")
async def monitors_mute(mid: str, request: Request):
    if mid not in ENGINE.monitors.defs:
        raise HTTPException(404)
    b = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    mins = b.get("minutes")
    m = await ENGINE.monitors.mute(mid, float(mins) if mins else None, str(b.get("reason", "")))
    await audit(request, "monitor.mute" if mins else "monitor.unmute", m["name"], detail={"minutes": mins})
    return ENGINE.monitors.summary(m)


@app.post("/api/monitors/{mid}/evaluate")
async def monitors_eval(mid: str):
    if mid not in ENGINE.monitors.defs:
        raise HTTPException(404)
    await ENGINE.monitors.evaluate(ENGINE.monitors.defs[mid])
    return await ENGINE.monitors.detail(mid)


# ------------------------------------------------------------------ 시스템: 버전·패치(웹 업로드 → root 유닛 적용)
@app.get("/api/system/version")
async def system_version():
    from . import patching
    return patching.info()


@app.put("/api/system/patch")
async def system_patch_upload(request: Request):
    """본문 = 패치 번들(.tgz). 저장 후 서명·무결성·버전 검사 결과를 돌려준다(적용은 /apply 로 따로)"""
    from . import patching
    try:
        f = await patching.save_upload(request.stream(), request.headers.get("x-filename", "patch.tgz"))
    except ValueError as e:
        raise HTTPException(413, str(e))
    try:
        m = await asyncio.to_thread(patching.verify_bundle, f)
    except ValueError as e:
        f.unlink(missing_ok=True)
        await audit(request, "system.patch_upload", f.name, "fail", detail={"error": str(e)})
        raise HTTPException(400, str(e))
    await audit(request, "system.patch_upload", m.get("version", ""), "ok", detail={"sha256": m["sha256"], "signed_by": m["signed_by"]})
    return {"file": str(f), "manifest": m, "current": patching.current_version(), "newer": patching.newer(m)}


@app.post("/api/system/patch/apply")
async def system_patch_apply(request: Request):
    from . import patching
    b = await request.json()
    f = Path(str(b.get("file", "")))
    inc = (patching.pdir() / "incoming").resolve()
    if not f.is_file() or f.resolve().parent != inc:
        raise HTTPException(400, "업로드한 번들이 아닙니다 — 다시 업로드하세요")
    m = await asyncio.to_thread(patching.verify_bundle, f)          # 업로드 뒤 바뀌지 않았는지 다시 확인
    if not patching.newer(m) and not b.get("force"):
        raise HTTPException(409, f"현재 {patching.current_version()} 보다 새 버전이 아닙니다({m.get('version')}) — 같은 버전 재적용·하향은 force")
    try:
        r = patching.request("apply", str(f), who(request).get("user", ""), force=bool(b.get("force")))
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    await audit(request, "system.patch_apply", m.get("version", ""), "queued", detail={"from": patching.current_version(), "sha256": m.get("sha256")})
    return r


@app.post("/api/system/patch/rollback")
async def system_patch_rollback(request: Request):
    from . import patching
    cur = patching.current_version()
    b = next((x for x in patching.info()["backups"] if x["version"] != cur), None)
    if not b:
        raise HTTPException(409, "현재 버전과 다른 백업이 없습니다")
    try:
        r = patching.request("rollback", b["name"], who(request).get("user", ""))
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    await audit(request, "system.patch_rollback", f"{cur} → {b['version']}", "queued", detail={"backup": b["name"]})
    r["to"] = b["version"]
    return r


# ------------------------------------------------------------------ 전체 인벤토리
_INV: dict[str, Any] = {"t": 0.0, "rows": []}


def _inv_rows() -> list[dict]:
    from . import inventory
    if time.time() - _INV["t"] > 5:                 # 화면이 페이지·정렬을 바꿀 때마다 다시 모으지 않도록 5초 캐시
        _INV.update(t=time.time(), rows=inventory.build(ENGINE))
    return _INV["rows"]


@app.get("/api/inventory")
async def inventory_list(kind: str = "", q: str = "", state: str = "", connector: str = "", sort: str = "name", desc: bool = False,
                         offset: int = 0, limit: int = 500):
    from . import inventory
    return inventory.query(_inv_rows(), kind, q, state, connector, sort, desc, max(0, offset), max(1, min(limit, 5000)))


@app.get("/api/inventory/item")
async def inventory_item(kind: str, name: str, connector: str = ""):
    """한 개체의 전체 필드 + 관련 개체(VM → 호스트·클러스터·데이터스토어 / 호스트 → VM·BMC …)"""
    rows = _inv_rows()
    it = next((r for r in rows if r["kind"] == kind and r["name"] == name and (not connector or r["connector"] == connector)), None)
    if not it:
        raise HTTPException(404)
    rel: list[dict] = []
    n = name.lower()
    for r in rows:
        if r is it:
            continue
        if kind == "vm" and ((r["kind"] == "host" and r["name"] == it.get("host")) or (r["kind"] == "cluster" and r["name"] == it.get("cluster"))
                             or (r["kind"] == "datastore" and r["name"] in str(it.get("datastores", "")).split(", "))
                             or (r["kind"] == "network" and r["name"] in str(it.get("networks", "")).split(", "))
                             or (r["kind"] == "agent" and r["name"].split(".")[0] in (n.split(".")[0], str(it.get("hostname", "")).lower().split(".")[0]))):
            rel.append(r)
        elif kind == "host" and ((r["kind"] == "vm" and r.get("host") == name) or (r["kind"] == "server" and r.get("esxi", "").split(".")[0].lower() == n.split(".")[0])
                                 or (r["kind"] == "cluster" and r["name"] == it.get("cluster"))):
            rel.append(r)
        elif kind == "cluster" and r["kind"] in ("host", "vm") and r.get("cluster") == name:
            rel.append(r)
        elif kind in ("datastore", "network") and r["kind"] == "vm" and name in str(r.get("datastores" if kind == "datastore" else "networks", "")).split(", "):
            rel.append(r)
        elif kind == "vks-cluster" and r["kind"] in ("k8s-node", "pod") and r.get("cluster") == name:
            rel.append(r)
        elif kind in ("nsx-t0",) and r["kind"] == "nsx-t1" and r.get("tier0") == it.get("name"):
            rel.append(r)
        elif kind in ("nsx-t0", "nsx-t1") and r["kind"] == "nsx-segment" and r.get("connected_to") in (name,):
            rel.append(r)
        elif kind == "server" and r["kind"] == "host" and r["name"].split(".")[0].lower() == str(it.get("esxi", "")).split(".")[0].lower():
            rel.append(r)
    return {"item": it, "related": rel[:500]}


@app.get("/api/inventory.csv")
async def inventory_csv(kind: str = "vm", q: str = "", state: str = "", connector: str = ""):
    from fastapi.responses import Response
    from . import inventory
    res = inventory.query(_inv_rows(), kind, q, state, connector, "name", False, 0, 1_000_000)
    return Response(inventory.to_csv(res["items"], kind), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": disposition(f'vcf-aiops-inventory-{kind or "all"}-{time.strftime("%Y%m%d")}.csv')})


# ------------------------------------------------------------------ 고객 환경 토폴로지(연결된 커넥터 기준)
@app.get("/api/topology/stack")
async def topology_stack(vm_limit: int = 60, pod_limit: int = 25, vms: bool = True, pods: bool = True):
    """물리 → 논리 스택 토폴로지(패브릭·섀시·서버·ESXi·VDS·Edge/SE/VM·Pod·게이트웨이·VS·세그먼트).
    vm_limit: 호스트당 개별 VM 수(0=전부), pod_limit: 노드당 Pod 수(0=전부)"""
    from . import stack
    return stack.build(ENGINE, vm_limit=max(0, min(vm_limit, 5000)), pod_limit=max(0, min(pod_limit, 2000)), vms=vms, pods=pods)


@app.get("/api/topology/live")
async def topology_live():
    from . import topology
    return topology.build(ENGINE)


@app.get("/api/topology/flow")
async def topology_flow(vs: str = "", vm: str = ""):
    """서비스 흐름도 — 클라이언트 → VIP(VS) → SE → 풀 → 멤버(VM·Pod) → 세그먼트/포트그룹 → ESXi → 물리 서버.
    vs(가상 서비스 uuid·이름) 또는 vm(VM 이름) 하나, 둘 다 없으면 전체 VS 요약 흐름"""
    from . import stack
    return stack.flow(ENGINE, vs=vs[:200], vm=vm[:200])


@app.get("/api/avi/vips")
async def avi_vips():
    """NSX ALB 가상 서비스(VIP)별 최근 트래픽(대역폭·수신/송신 바이트·패킷·연결·응답코드·SSL·지연·Apdex)"""
    return {"items": ENGINE.avi_vips(), "updated": time.time()}


@app.get("/api/avi/vips/{uuid}/endusers")
async def avi_vip_endusers(uuid: str, minutes: int = 60, limit: int = 1000):
    """VIP End user 분석 — 애플리케이션 로그 표본 집계(고유 클라이언트·상위 IP·OS·브라우저·기기·위치·응답코드·URI·도메인·지연)"""
    for c in ENGINE.connectors:
        if getattr(c, "type", "") == "avi" and c.enabled and uuid in (getattr(c, "vs", {}) or {}):
            try:
                mins, lim = max(5, min(minutes, 1440)), max(50, min(limit, 5000))
                d = await asyncio.wait_for(c.end_users(uuid, mins, lim), 30)
                cache = getattr(c, "_eu_cache", None)
                if cache is None:
                    cache = c._eu_cache = {}
                cache.setdefault((uuid, mins, lim), {"ts": time.time(), "data": d})     # 흐름도가 상위 클라이언트를 펼칠 때 사용
                return d
            except httpx.HTTPStatusError:
                await c.login()
                return await asyncio.wait_for(c.end_users(uuid, max(5, min(minutes, 1440)), max(50, min(limit, 5000))), 30)
            except (asyncio.TimeoutError, httpx.HTTPError) as e:
                raise HTTPException(504, f"Avi 로그 조회 실패: {type(e).__name__}")
    raise HTTPException(404, "가상 서비스를 찾을 수 없습니다")


# ------------------------------------------------------------------ vCenter 인프라 상세 점검
@app.get("/api/vcenter/health")
async def vcenter_health(area: str = "", severity: str = "", q: str = "", limit: int = 2000):
    """Compute·Storage·Network·Hardware(드라이버·펌웨어) 점검 결과 — vCenter 커넥터별"""
    from . import vcheck
    minr = vcheck.SEV_ORDER.index(severity) if severity in vcheck.SEV_ORDER else 0
    ql = q.lower()
    out, tot = [], {a: {s: 0 for s in vcheck.SEV_ORDER} for a in vcheck.AREAS}
    for c in ENGINE.connectors:
        if c.type != "vcenter" or not c.enabled or not hasattr(c, "health_snapshot"):
            continue
        h = c.health_snapshot()
        for a, m in (h.get("summary") or {}).items():
            for sv, n in m.items():
                tot.setdefault(a, {}).setdefault(sv, 0)
                tot[a][sv] += n
        fs = [dict(x, vcenter=c.name) for x in h.get("findings", [])
              if (not area or x["area"] == area) and vcheck.SEV_ORDER.index(x["severity"]) >= minr
              and (not ql or ql in f"{x['entity']} {x['title']} {x['detail']}".lower())]
        out.append({"connector": c.name, "vcenter": c.host, "updated": h.get("updated", 0), "error": h.get("error", ""),
                    "hosts": h.get("hosts", 0), "clusters": h.get("clusters", 0), "datastores": h.get("datastores", 0),
                    "duration_s": h.get("duration_s"), "interval": c.health_cfg["interval"], "findings": fs[:limit], "hw": h.get("hw", [])})
    return {"vcenters": out, "summary": tot, "areas": vcheck.AREAS, "thresholds": vcheck.DEFAULTS}


@app.post("/api/vcenter/health/run")
async def vcenter_health_run(request: Request):
    """지금 점검(드라이버 VIB 조회 포함) — 호스트 수에 따라 수십 초"""
    n, errs = 0, []
    for c in [c for c in ENGINE.connectors if c.type == "vcenter" and c.enabled and hasattr(c, "run_health")]:
        c._last_vib = 0.0
        evs = await c.run_health()
        for e in evs:
            ENGINE.submit(e)
        c._last_health = time.time()
        n += 1
        if c.health.get("error"):
            errs.append(f"{c.name}: {c.health['error']}")
    await audit(request, "vcenter.health_run", str(n), "ok" if not errs else "fail")
    return {"ran": n, "errors": errs}


# ------------------------------------------------------------------ 2.28.0 VMware 권장 구성 판독
@app.get("/api/vcenter/bestpractice")
async def vcenter_bestpractice():
    """인프라 점검 스냅숏을 Broadcom 공식 권장 사항과 대조 — 클러스터별 권장 구성 / 부분 권장 / 권장 아님"""
    from . import bestpractice as BP
    out = []
    for c in ENGINE.connectors:
        if c.type != "vcenter" or not c.enabled or not getattr(c, "health_snap", None):
            if c.type == "vcenter" and c.enabled:
                out.append({"connector": c.name, "vcenter": getattr(c, "host", ""), "clusters": [], "error": (getattr(c, "health", None) or {}).get("error") or "아직 인프라 점검 전(최대 30분) — '지금 판독'을 누르세요"})
            continue
        r = await asyncio.to_thread(BP.evaluate, c.health_snap)
        hh = getattr(c, "health", None) or {}
        out.append({"connector": c.name, "vcenter": getattr(c, "host", ""), "updated": hh.get("updated", 0), "error": hh.get("error", ""),
                    "vm_error": r["vm_error"], "vm_collected": r["vm_collected"], "clusters": r["clusters"]})
    allc = [x for v in out for x in v["clusters"]]
    cnt = {k: sum(1 for x in allc if x["verdict"] == k) for k in BP.VERDICT}
    sc = [x["score"] for x in allc if x["score"] is not None]
    return {"vcenters": out, "rules": BP.RULES, "levels": {k: v[0] for k, v in BP.LEVELS.items()}, "verdicts": BP.VERDICT,
            "summary": {"clusters": len(allc), "count": cnt, "avg_score": round(sum(sc) / len(sc)) if sc else None}}


@app.post("/api/vcenter/bestpractice/run")
async def vcenter_bestpractice_run(request: Request):
    """지금 판독 — 인프라 점검 + VM 장치·Tools 정보 다시 수집"""
    n, errs = 0, []
    for c in [c for c in ENGINE.connectors if c.type == "vcenter" and c.enabled and hasattr(c, "run_health")]:
        c._last_bpvm = 0.0
        for e in await c.run_health():
            ENGINE.submit(e)
        c._last_health = time.time()
        n += 1
        if c.health.get("error"):
            errs.append(f"{c.name}: {c.health['error']}")
    await audit(request, "vcenter.bestpractice_run", str(n), "ok" if not errs else "fail")
    return {"ran": n, "errors": errs}


# ------------------------------------------------------------------ 2.29.0 DR·보호
@app.get("/api/dr")
async def dr_overview():
    """SRM 복구 계획·보호 그룹·보호 VM, 스냅숏(72시간·체인·백업 잔여), Appliance 백업(vCenter·NSX·SDDC Manager), VM 백업(추정)"""
    from . import protection as PR
    return await asyncio.to_thread(PR.build, list(ENGINE.connectors))


@app.post("/api/dr/run")
async def dr_run(request: Request):
    """지금 새로 고침 — Appliance 백업 조회·SRM 보호 VM·vCenter VM 요약(스냅숏·백업 속성)을 다시 모음(읽기 전용)"""
    n, errs = 0, []
    for c in [c for c in ENGINE.connectors if c.enabled]:
        try:
            if c.type == "vcenter" and hasattr(c, "collect_backup"):
                if c.rest_token:
                    for e in await c.collect_backup():
                        ENGINE.submit(e)
                c._last_bpvm = 0.0
                for e in await c.run_health():
                    ENGINE.submit(e)
                c._last_health = time.time()
                n += 1
            elif c.type == "nsx" and hasattr(c, "_backup"):
                for e in await c._backup():
                    ENGINE.submit(e)
                n += 1
            elif c.type == "sddc" and hasattr(c, "_backup"):
                await c._backup()
                n += 1
            elif c.type == "srm" and hasattr(c, "protection") and not getattr(c, "demo", False):
                c._state_at = 0
                n += 1
        except Exception as e:  # noqa: BLE001
            errs.append(f"{c.name}: {type(e).__name__}: {e}"[:200])
    await audit(request, "dr.refresh", str(n), "ok" if not errs else "fail")
    return {"ran": n, "errors": errs}


# ------------------------------------------------------------------ 2.30.0 모바일 앱(안드로이드) — 배포·기기 연결·알림 피드
def _mobile_hook() -> None:
    prev = ENGINE.alerter.on_fire

    def fire(a: dict) -> None:
        if prev:
            try:
                prev(a)
            except Exception:  # noqa: BLE001
                pass
        MOBILE.on_anomaly(a)
    ENGINE.alerter.on_fire = fire
    orig_text = ENGINE.alerter.notify_text

    async def notify_text(title: str, body: str, severity: str = "warning", ref: str = "") -> None:
        MOBILE.on_text(title, severity)
        await orig_text(title, body, severity, ref)
    ENGINE.alerter.notify_text = notify_text


_mobile_hook()


def _is_admin(request: Request) -> bool:
    return AUTH.allowed(who(request).get("role", ""), "settings") if AUTH.enabled else True


def _bearer(request: Request) -> str:
    return request.headers.get("authorization", "").removeprefix("Bearer ").strip()


@app.get("/api/mobile/info")
async def mobile_info(request: Request):
    from . import mobile as MB
    from . import patching
    u = who(request)
    adm = _is_admin(request)
    return {"app": MB.app_meta(), "server": patching.current_version(), "settings": MOBILE.settings(), "kinds": MB.KINDS, "admin": adm,
            "devices": await MOBILE.devices(u, adm), "me": u["user"], "stats": MOBILE.stats if adm else None,
            "access": {"enabled": CFA.enabled, "enforce": bool(CFA.enabled and CFA.enforce)},
            "external": via_edge(request)}


@app.post("/api/mobile/pair/start")
async def mobile_pair_start(request: Request):
    b = await request.json()
    origin = str((b or {}).get("origin") or "")
    m = re.match(r"^(https?)://([^/?#@]+)$", origin)
    if not m or m.group(2).lower() != (request.headers.get("host") or "").lower():
        raise HTTPException(400, "주소가 올바르지 않습니다")
    u = who(request)
    if u.get("token"):
        raise HTTPException(403, "API 토큰으로는 기기를 연결할 수 없습니다")
    try:
        r = await MOBILE.pair_start(u, origin)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    await audit(request, "mobile.pair_start", u["user"])
    return r


@app.get("/api/mobile/install-qr")
async def mobile_install_qr(request: Request, origin: str = ""):
    m = re.match(r"^(https?)://([^/?#@]+)$", origin)
    if not m or m.group(2).lower() != (request.headers.get("host") or "").lower():
        raise HTTPException(400, "주소가 올바르지 않습니다")
    return MOBILE.install_qr(origin)


@app.post("/api/mobile/pair", include_in_schema=False)
async def mobile_pair(request: Request):
    """앱이 호출 — 일회용 코드로 기기 토큰 발급(세션 없음)"""
    try:
        b = await request.json()
        if not isinstance(b, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(400, "JSON 객체가 필요합니다")
    ip = client_ip(request)
    try:
        r = await MOBILE.pair(b, ip, auth_enabled=AUTH.enabled)
    except PermissionError as e:
        await ENGINE.audit.log("mobile.pair", user="-", ip=ip, target=str(b.get("name") or "")[:60], result="denied", detail={"reason": str(e)[:80]})
        raise HTTPException(403, str(e))
    await ENGINE.audit.log("mobile.pair", user=r["user"], ip=ip, target=f"device:{r['device_id']} {str(b.get('name') or '')[:60]}", result="ok")
    from . import patching
    return {"token": r["token"], "device_id": r["device_id"], "cursor": r["cursor"], "server": {"version": patching.current_version()}}


@app.get("/api/mobile/feed", include_in_schema=False)
async def mobile_feed(request: Request, since: int = 0, app: int = 0, wait: int = 0):   # noqa: A002
    d = await MOBILE.device_by_token(_bearer(request), auth_enabled=AUTH.enabled)
    if not d:
        raise HTTPException(401, "기기 토큰이 유효하지 않습니다")
    from . import patching
    try:
        r = await MOBILE.feed_wait(d, since, app, client_ip(request), patching.current_version(), wait)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    return r | {"brief": await _mobile_brief()}


_BRIEF: dict[str, Any] = {"ts": 0.0, "v": {}}


async def _mobile_brief() -> dict:
    """홈 화면 위젯용 숫자 몇 개 — 30초 캐시"""
    now = time.time()
    if now - _BRIEF["ts"] > 30:
        _BRIEF["ts"] = now
        try:
            inc = await ENGINE.incidents.list("active", None, 30, 500)
            _BRIEF["v"] = {"inc": len(inc), "inc_crit": sum(1 for i in inc if i.get("severity") == "critical"), "inc_open": sum(1 for i in inc if i.get("status") == "open"),
                           "anom_crit": sum(1 for a in ENGINE.anomalies.values() if not a.ack and not a.suppressed and a.severity == "critical" and now - a.last_seen < 86400),
                           "ts": int(now)}
        except Exception:  # noqa: BLE001
            _BRIEF["ts"] = 0.0
    return _BRIEF["v"]


_SUM_CACHE: dict[str, Any] = {"ts": 0.0, "v": None}


@app.get("/api/mobile/summary")
async def mobile_summary(request: Request):
    """폰 첫 화면 — 지금 상태 한눈에(인시던트·이상 징후·DR·백업·수집 연결·플랫폼) + 최근 알림. 공통 부분은 15초 캐시"""
    from . import patching
    from . import protection as PR
    now = time.time()
    if not _SUM_CACHE["v"] or now - _SUM_CACHE["ts"] > 15:
        _SUM_CACHE["ts"] = now                                       # 겹쳐 들어온 요청이 같이 계산하지 않게 먼저 찍음
        try:
            an = [a for a in ENGINE.anomalies.values() if not a.ack and not a.suppressed and now - a.last_seen < 86400]
            by = {s: sum(1 for a in an if a.severity == s) for s in ("critical", "error", "warning")}
            top = sorted(an, key=lambda a: (-SEV_RANK.get(a.severity, 0), -a.last_seen))[:5]
            inc = await ENGINE.incidents.list("active", None, 30, 200)
            conns = [c.state() for c in ENGINE.connectors if c.enabled]
            bad = [c for c in conns if c.get("state") in ("down", "degraded", "error")]
            try:
                dr = (await asyncio.to_thread(PR.build, list(ENGINE.connectors)))["summary"]
            except Exception:  # noqa: BLE001  — DR 요약 실패가 첫 화면을 막지 않게
                dr = None
            ok, why = ENGINE.health.ready()
            life = None                                              # 2.37.0 수명 주기 — 인증서(마지막 스캔)·7일 구성 변경
            try:
                cs = (getattr(ENGINE, "certs", None) and ENGINE.certs.last) or {}
                sm = cs.get("summary") or {}
                soon = [x for x in cs.get("items") or [] if x.get("band") in ("expired", "crit")][:3]
                dch = 0
                if getattr(ENGINE, "driftwatch", None):
                    await ENGINE.driftwatch.ensure()
                    r = await ENGINE.store.q1("SELECT COUNT(*) AS n FROM drift_changes WHERE ts >= ? AND severity='warning'", (now - 7 * 86400,))
                    dch = (r or {}).get("n", 0)
                life = {"scanned": bool(cs.get("ts")), "expired": sm.get("expired", 0), "crit": sm.get("crit", 0), "warn": sm.get("warn", 0),
                        "top": [{"kind": x["kind"], "name": x["name"], "days_left": x.get("days_left"), "system": x["system"]} for x in soon], "drift7": dch}
            except Exception:  # noqa: BLE001
                life = None
            bot = None                                               # 2.38.0 AI 체크봇 — 마지막 실행(실패·새 실패·가장 위험한 것)
            try:
                if getattr(ENGINE, "checkbot", None):
                    lr = await ENGINE.checkbot.latest()
                    if lr:
                        sm = lr["summary"]
                        bot = {"ts": sm["ts"], "scenarios": sm["scenarios"], **sm["by_verdict"], "new_fail": sm.get("new_fail", 0),
                               "top": [{"kind": x["kind"], "target": x["target"]} for x in lr["results"] if x["verdict"] == "fail"][:2]}
            except Exception:  # noqa: BLE001
                bot = None
            _SUM_CACHE["v"] = {
                "ts": now, "server": patching.current_version(), "life": life, "bot": bot,
                "platform": {"ok": ok, "reasons": why[:3]},
                "incidents": {"active": len(inc), "critical": sum(1 for i in inc if i.get("severity") == "critical"),
                              "top": [{k: i.get(k) for k in ("id", "title", "severity", "status_label", "updated")} for i in inc[:5]]},
                "anomalies": {**by, "top": [{"id": a.id, "title": a.title, "severity": a.severity, "last_seen": a.last_seen, "count": a.count,
                                             "target": (a.event or {}).get("host") or (a.event or {}).get("entity") or ""} for a in top]},
                "connectors": {"total": len(conns), "bad": len(bad), "names": [str(c.get("name")) for c in bad[:5]]},
                "dr": dr and {"plans": dr["srm"]["plans"], "plans_bad": dr["srm"]["plans_bad"] + dr["srm"]["groups_bad"], "srm": bool(dr["srm"]["connectors"]),
                              "app_total": dr["appliances"]["total"], "app_bad": dr["appliances"]["bad"], "app_warn": dr["appliances"]["warn"] + dr["appliances"]["unknown"],
                              "snap_bad": dr["snapshots"]["over72"] + dr["snapshots"]["leftover"]},
            }
        except Exception:
            _SUM_CACHE["ts"] = 0.0
            raise
    return _SUM_CACHE["v"] | {"notices": await MOBILE.recent(who(request), 15), "user": who(request).get("user", "")}


@app.get("/api/mobile/app.apk", include_in_schema=False)
async def mobile_apk(request: Request):
    """패치에 들어 있는 안드로이드 앱 — 로그인 세션 또는 기기 토큰"""
    from . import mobile as MB
    s = AUTH.session(request) if AUTH.enabled else {"user": "anonymous"}
    if not s and not await MOBILE.device_by_token(_bearer(request), auth_enabled=AUTH.enabled):
        raise HTTPException(401, "로그인 또는 기기 토큰이 필요합니다")
    meta = MB.app_meta()
    if not meta:
        raise HTTPException(404, "이 설치본에 앱 파일이 없습니다")
    return FileResponse(MB.STATIC_APP / "vcf-aiops.apk", media_type="application/vnd.android.package-archive",
                        filename=f"vcf-aiops-{meta['name']}.apk", headers={"Content-Encoding": "identity", "Cache-Control": "no-store",
                                                                          "X-Checksum-Sha256": str(meta["sha256"])})


@app.put("/api/mobile/devices/{did}")
async def mobile_device_update(did: int, request: Request):
    try:
        r = await MOBILE.update_device(did, await request.json(), who(request), _is_admin(request))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))
    return r


@app.delete("/api/mobile/devices/{did}")
async def mobile_device_delete(did: int, request: Request):
    try:
        await MOBILE.revoke(did, who(request), _is_admin(request))
    except LookupError as e:
        raise HTTPException(404, str(e))
    await audit(request, "mobile.device_revoke", f"device:{did}")
    return {"ok": True}


@app.post("/api/mobile/test")
async def mobile_test(request: Request):
    u = who(request)
    n = len([d for d in await MOBILE.devices(u, False)])
    if not n:
        raise HTTPException(409, "연결한 기기가 없습니다")
    await MOBILE.emit("test", "시험 알림", f"{u['user']} 님이 보낸 시험 알림입니다. 앱은 최대 {MOBILE.cfg['poll_minutes']}분 안에 확인합니다.", "info", "mobile", user=u["user"])
    return {"ok": True, "devices": n, "poll_minutes": MOBILE.cfg["poll_minutes"]}


@app.put("/api/mobile/settings")
async def mobile_settings(request: Request):
    try:
        r = await MOBILE.save_settings(await request.json(), who(request).get("user", ""))
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e))
    await audit(request, "mobile.settings", "", detail={k: r[k] for k in ("enabled", "poll_minutes", "allow_without_access")})
    return r


# ------------------------------------------------------------------ 성능 SLI · Isvara
def _sli_all() -> list[tuple[Any, dict]]:
    return [(c, c.sli_snapshot()) for c in ENGINE.connectors if hasattr(c, "sli_snapshot") and c.enabled]


def _sli_context() -> str:
    rows = []
    for c, s in _sli_all():
        for cn, cl in sorted(s.get("clusters", {}).items(), key=lambda kv: (kv[1].get("score") is None, kv[1].get("score") or 0)):
            if cl.get("score") is None:
                continue
            fo = cl.get("failover", {})
            rows.append(f"- {c.name}/{cn}: KPI {cl['score']}({cl['band']}) VM {cl['vms']} 빨강 {cl['bands']['red']} "
                        f"주황 {cl['bands']['orange']} · 페일오버 {fo.get('verdict')}")
        worst = sorted((v for v in s.get("vms", {}).values() if v.get("score") is not None and v["score"] < 75),
                       key=lambda v: v["score"])[:10]
        for v in worst:
            sg = v["signals"][v["worst"]]
            rows.append(f"  · VM {v['name']}({v.get('cluster')}) {v['score']} {sli.LABEL[v['worst']]}={sg['value']}{sli.UNIT[v['worst']]}")
    return "\n".join(rows[:40])


@app.get("/api/sli")
async def sli_view(cluster: str = "", limit: int = 200):
    """vCenter 커넥터별 성능 SLI — 클러스터 KPI·페일오버 여유·하위 VM. 점수 방식·기준·출처 포함."""
    out = {"vcenters": [], "clusters": [], "vms": [], "counts": {b: 0 for b in sli.BAND_WEIGHT},
           "method": {"formula": "score = max(0, 100 − 25 × 측정값 ÷ 기준) · VM = 4개 신호 중 최저 · 클러스터 = 밴드 가중(1·2·4·8) 평균",
                      "bands": {"green": "≥75", "yellow": "50–74", "orange": "25–49", "red": "<25"},
                      "dropped_packets": "0 → 100, 초과 시 75 − 25 × 값 ÷ drop_budget(이 포털 규칙)",
                      "sources": sli.SOURCES,
                      "note": "Isvara 공개 밴드·예시와 일치하는 해석이며 Broadcom/VMware 공식 평가가 아닙니다."}}
    vms = []
    for c, s in _sli_all():
        out["vcenters"].append({"connector": c.name, "vcenter": s.get("vcenter", c.host), "updated": s.get("updated") or None,
                                "error": s.get("error", ""), "missing_counters": s.get("missing_counters", []),
                                "thresholds": s.get("thresholds") or c.sli_cfg["thresholds"], "window_s": s.get("window_s"),
                                "percentile": s.get("percentile"), "drop_budget": c.sli_cfg["drop_budget"]})
        for cn, cl in s.get("clusters", {}).items():
            out["clusters"].append({"connector": c.name, "name": cn, **cl})
        for v in s.get("vms", {}).values():
            if cluster and v.get("cluster") != cluster:
                continue
            vms.append({"connector": c.name, **v})
            if v.get("band") in out["counts"]:
                out["counts"][v["band"]] += 1
    out["clusters"].sort(key=lambda x: (x.get("score") is None, x.get("score") if x.get("score") is not None else 999))
    vms.sort(key=lambda v: (v.get("score") is None, v.get("score") if v.get("score") is not None else 999))
    out["vms"] = vms[:max(1, min(limit, 2000))]
    out["total_vms"] = len(vms)
    return out


@app.post("/api/connectors/provision")
async def connectors_provision(req: Request):
    """관리자 계정으로 수집 전용(읽기 전용) 계정 생성 — 관리자 자격 증명은 저장하지 않음."""
    from .provision import SUPPORTED, provision
    b = await req.json()
    t = str(b.get("type", ""))
    if t not in SUPPORTED:
        raise HTTPException(400, f"지원 유형: {', '.join(SUPPORTED)}")
    params = {k: b.get(k) for k in ("type", "host", "admin_user", "admin_password", "new_user", "new_password",
                                    "verify_tls", "reset_password", "no_diagnostics", "auth_source", "provider")}
    params["host"] = str(params.get("host") or "").strip()
    res = await provision(params)
    await audit(req, "connector.provision_account", f"{t}:{params['host']}", result="ok" if res.get("ok") else "fail",
                detail={"new_user": res.get("username") or params.get("new_user"), "admin_user": params.get("admin_user"),
                        "steps": [f"{s['step']}:{'ok' if s['ok'] else ('warn' if s['ok'] is None else 'fail')}" for s in res.get("steps", [])],
                        "error": res.get("error", "")})
    return res


# ------------------------------------------------------------------ VKS(Supervisor·워크로드 클러스터·노드·파드)
def _vks(name: str):
    c = next((c for c in ENGINE.connectors if c.name == name and c.type in ("vks", "kubernetes")), None)
    if not c:
        raise HTTPException(404, f"VKS 커넥터 없음: {name}")
    return c


@app.get("/api/vks")
async def vks_list():
    out = []
    for c in ENGINE.connectors:
        if c.type not in ("vks", "kubernetes"):
            continue
        inv = getattr(c, "inv", {"nodes": [], "pods": [], "clusters": []})
        pods = inv.get("pods", [])
        bad = [p for p in pods if p.get("phase") in ("Failed", "Pending", "Unknown") or p.get("reason") in
               ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError", "Error", "OOMKilled")
               or (p.get("phase") == "Running" and "/" in str(p.get("ready", "")) and p["ready"].split("/")[0] != p["ready"].split("/")[1])]
        st = c.state()
        out.append({"name": c.name, "role": getattr(c, "role", ""), "cluster": getattr(c, "cluster_label", c.name),
                    "discovered_by": getattr(c, "discovered_by", ""), "state": st.get("state"), "last_error": st.get("last_error", ""),
                    "auth": st.get("auth"), "target": st.get("target"), "updated": inv.get("updated") or None,
                    "nodes": inv.get("nodes", []), "clusters": inv.get("clusters", []),
                    "pods": {"total": len(pods), "running": sum(1 for p in pods if p.get("phase") == "Running"),
                             "pending": sum(1 for p in pods if p.get("phase") == "Pending"),
                             "failed": sum(1 for p in pods if p.get("phase") == "Failed"), "problem": len(bad)},
                    "problem_pods": bad[:200], "log_namespaces": getattr(c, "log_namespaces", [])})
    vcs = [{"connector": c.name, "vcenter": c.host, **{k: v for k, v in getattr(c, "vks", {}).items()}}
           for c in ENGINE.connectors if c.type == "vcenter"]
    return {"clusters": sorted(out, key=lambda x: (x["discovered_by"], x["role"] != "supervisor", x["cluster"])), "vcenters": vcs}


@app.get("/api/vks/map")
async def vks_map_overview():
    """2.9.0 VKS 전체 구성 — Supervisor → vSphere 네임스페이스 → VKS 클러스터·VM Service VM"""
    from . import vksmap
    return vksmap.overview(ENGINE)


@app.get("/api/vks/{name}/map")
async def vks_map(name: str, ns: str = "", system: bool = False, q: str = ""):
    _vks(name)
    try:
        g = await ENGINE.vksobs.graph(name, ns[:120], system, q[:120])
    except KeyError as e:
        raise HTTPException(404, "VKS 커넥터 없음") from e
    g.pop("pod_wid", None)
    return g


@app.get("/api/vks/{name}/map.mmd")
async def vks_map_mermaid(name: str, ns: str = "", system: bool = False):
    from . import vksmap
    try:
        g = await ENGINE.vksobs.graph(name, ns[:120], system)
    except KeyError as e:
        raise HTTPException(404, "VKS 커넥터 없음") from e
    return Response(vksmap.mermaid(g), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": disposition(f'vks-{name}-{ns or "all"}.mmd')})


@app.get("/api/vks/{name}/object")
async def vks_object(name: str, kind: str, obj: str, ns: str = "", hours: float = 24):
    """2.10.0 구성도 개체 상세 — 상태·문제·파드·이벤트(실시간+저장)·로그·변경 이력·연관(노드→VM→ESXi·인시던트·VM 액티비티)"""
    _vks(name)
    try:
        return await ENGINE.vksobs.detail(name, kind[:40], ns[:120], obj[:253], max(1.0, min(hours, 24 * 14)))
    except KeyError as e:
        raise HTTPException(404, "VKS 커넥터 없음") from e
    except LookupError as e:
        raise HTTPException(404, f"개체 없음: {e}") from e


@app.get("/api/vks/{name}/activity")
async def vks_activity(name: str, ns: str = "", kind: str = "", obj: str = "", hours: float = 168, limit: int = 500):
    _vks(name)
    return {"items": await ENGINE.vksobs.query(name, kind[:40], ns[:120], obj[:253], max(1.0, min(hours, 24 * 90)), limit)}


@app.get("/api/vks/{name}/pods")
async def vks_pods(name: str, ns: str = "", q: str = "", limit: int = 2000):
    c = _vks(name)
    pods = [p for p in getattr(c, "inv", {}).get("pods", []) if (not ns or p["ns"] == ns) and (not q or q.lower() in f"{p['ns']}/{p['name']} {p['node']}".lower())]
    return {"pods": pods[: max(1, min(limit, 5000))], "total": len(pods), "nodes": getattr(c, "inv", {}).get("nodes", [])}


@app.get("/api/vks/{name}/log")
async def vks_log(name: str, ns: str, pod: str, container: str = "", tail: int = 300, previous: bool = False):
    c = _vks(name)
    try:
        lines = await asyncio.wait_for(c.pod_log(ns, pod, container, tail=tail, previous=previous), 30)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"파드 로그 조회 실패: {type(e).__name__}: {e}"[:300]) from e
    from .vksobs import mask_log
    return {"lines": [mask_log(x) for x in lines[-5000:]], "container": container, "previous": previous, "masked": True}


@app.get("/api/vks/{name}/log/download")
async def vks_log_download(name: str, ns: str, pod: str, container: str = "", previous: bool = False, tail: int = 100000):
    """2.11.0 파드 로그 파일(최대 10만 줄·1MB×10 — 비밀값 가림)"""
    from .vksobs import mask_log
    c = _vks(name)
    try:
        lines = await asyncio.wait_for(c.pod_log(ns, pod, container, tail=max(1, min(tail, 100000)), previous=previous, timestamps=True), 60)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"파드 로그 조회 실패: {type(e).__name__}: {e}"[:300]) from e
    fn = f"{ns}_{pod}_{container or 'default'}{'_previous' if previous else ''}.log"
    return Response("\n".join(mask_log(x) for x in lines) + "\n", media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": disposition(fn), "Cache-Control": "private, no-store"})


@app.get("/api/vks/{name}/object/logs.zip")
async def vks_object_logs(name: str, kind: str, obj: str, request: Request, ns: str = "", hours: float = 24):
    """2.11.0 개체 로그 묶음 — 관련 파드 전부(컨테이너별 현재·이전 로그) + 이벤트·변경 이력 CSV + AIOps 수집 로그"""
    import csv as _csv
    import io as _io
    import zipfile as _zip
    from .logexport import LogQuery, fmt_ts, rows as _rows, line_txt
    from .vksobs import mask_log
    c = _vks(name)
    try:
        d = await ENGINE.vksobs.detail(name, kind[:40], ns[:120], obj[:253], max(1.0, min(hours, 24 * 14)))
    except (KeyError, LookupError) as e:
        raise HTTPException(404, f"개체 없음: {e}") from e
    mem = _io.BytesIO()
    total = 0
    with _zip.ZipFile(mem, "w", _zip.ZIP_DEFLATED) as z:
        for p in d["pods"][:60]:
            for cn in (p.get("containers") or [""])[:6]:
                for prev in ((False, True) if p.get("restarts") else (False,)):
                    try:
                        lines = await asyncio.wait_for(c.pod_log(p.get("ns") or ns, p["name"], cn, tail=20000, previous=prev, timestamps=True), 20)
                    except Exception as e:  # noqa: BLE001
                        lines = [f"(조회 실패: {type(e).__name__}: {str(e)[:200]})"]
                    txt = "\n".join(mask_log(x) for x in lines) + "\n"
                    total += len(txt)
                    z.writestr(f"pods/{p.get('ns') or ns}/{p['name']}/{cn or 'default'}{'.previous' if prev else ''}.log", txt)
                    if total > 150_000_000:
                        break
        for fn, cols, items in (("events.csv", ["time", "type", "reason", "kind", "name", "count", "component", "message"],
                                 [[fmt_ts(e["ts"]), e["type"], e["reason"], e["kind"], e["name"], e["count"], e.get("component", ""), e["message"]] for e in d["events"]]),
                                ("activity.csv", ["time", "action", "kind", "name", "pod", "severity", "detail"],
                                 [[fmt_ts(a["ts"]), a["label"], a["kind"], a["name"], a.get("pod", ""), a["sev"], a["detail"]] for a in d["activity"]])):
            b = _io.StringIO()
            w = _csv.writer(b)
            w.writerow(cols)
            w.writerows(items)
            z.writestr(fn, "\ufeff" + b.getvalue())
        ents = [f"{kind}/{ns}/{obj}" if ns else f"{kind}/{obj}"] + [f"Pod/{p.get('ns') or ns}/{p['name']}" for p in d["pods"][:300]]
        lq = LogQuery(time.time() - hours * 3600, time.time(), connectors=[name], entities=ents, max_rows=200000)
        out = [line_txt(r) async for r in _rows(ENGINE.store, lq)]
        z.writestr("aiops-collected.log", "\n".join(out) + "\n")
        z.writestr("README.txt", f"VKS {d['cluster']} {kind} {ns}/{obj}\n생성 {fmt_ts(time.time())}\n파드 {len(d['pods'])}개 · 이벤트 {len(d['events'])}건 · 변경 {len(d['activity'])}건 · 수집 로그 {len(out)}줄\n비밀값 패턴(password·token·Bearer·JWT 등)은 가림\n")
    await audit(request, "logs.export", detail={"vks": name, "kind": kind, "ns": ns, "obj": obj, "bytes": mem.tell()})
    fn = f"vks-{name}-{kind}-{ns or 'cluster'}-{obj}.zip".replace("/", "_")
    return Response(mem.getvalue(), media_type="application/zip", headers={"Content-Disposition": disposition(fn), "Cache-Control": "private, no-store"})


@app.post("/api/vks/discover")
async def vks_discover(req: Request):
    rep = await ENGINE.discover_vks_once()
    await audit(req, "vks.discover", detail={k: v for k, v in rep.items() if k != "vcenters"})
    return rep


# ---------------------------------------------------------------- 2.8.0 VCF Operations 메트릭
@app.get("/api/opsmetrics")
async def opsmetrics_summary():
    return ENGINE.opsmetrics.summary()


@app.get("/api/opsmetrics/objects")
async def opsmetrics_objects(kind: str = "HostSystem", connector: str = "", q: str = "", sort: str = "", desc: bool = True, limit: int = 500):
    return ENGINE.opsmetrics.objects(kind[:80], connector, q[:200], sort[:200], desc, limit)


@app.get("/api/opsmetrics/series")
async def opsmetrics_series(kind: str, name: str, key: str, hours: float = 24):
    return await ENGINE.opsmetrics.series(kind, name, key, max(1.0, min(hours, 24 * 30)))


@app.get("/api/opsmetrics/entity")
async def opsmetrics_entity(name: str):
    return {"items": ENGINE.opsmetrics.for_entity(name.strip()[:200])}


@app.get("/api/opsmetrics/catalog")
async def opsmetrics_catalog(kind: str, connector: str = "", q: str = "", refresh: bool = False):
    try:
        return await asyncio.wait_for(ENGINE.opsmetrics.catalog(connector, kind[:80], q[:100], refresh), 40)
    except KeyError as e:
        raise HTTPException(404, str(e)) from None
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"VCF Ops 카탈로그 조회 실패: {type(e).__name__}: {e}"[:300]) from None


@app.put("/api/opsmetrics/keys")
async def opsmetrics_keys(request: Request):
    """메트릭 선택기 저장(관리자) — 종류별 stat key 목록, 다음 수집부터 적용"""
    b = await request.json()
    try:
        r = await ENGINE.opsmetrics.save_keys(str(b.get("connector") or ""), str(b.get("kind") or ""), list(b.get("keys") or []), who(request)["user"])
    except KeyError as e:
        raise HTTPException(404, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    await audit(request, "opsmetrics.keys", f"{r['connector']}/{r['kind']}", detail={"keys": r["keys"]})
    return r


@app.post("/api/opsmetrics/collect")
async def opsmetrics_collect(request: Request):
    """지금 수집(운영자) — 선택기 저장 직후 확인용"""
    b = await request.json()
    c = ENGINE.opsmetrics._conn(str(b.get("connector") or ""))
    if not c:
        raise HTTPException(404, "VCF Operations 커넥터 없음")
    ENGINE.opsmetrics.push_keys()
    try:
        ops = await asyncio.wait_for(c.collect_metrics(), 300)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"수집 실패: {type(e).__name__}: {e}"[:300]) from None
    await ENGINE.opsmetrics.persist()
    await audit(request, "opsmetrics.collect", c.name)
    return {"ok": not ops.get("error"), "error": ops.get("error", ""), "took_ms": ops.get("took_ms"),
            "kinds": {k: {"objects": len(v.get("objects") or {}), "with_data": v.get("with_data", 0)} for k, v in ops.get("kinds", {}).items()}}


@app.get("/api/opsmetrics/export")
async def opsmetrics_export(request: Request, kind: str = "HostSystem", fmt: str = "csv", connector: str = "", q: str = ""):
    body, ct = ENGINE.opsmetrics.export(kind[:80], "json" if fmt == "json" else "csv", connector, q[:200])
    await audit(request, "opsmetrics.export", kind, detail={"fmt": fmt})
    return Response(body, media_type=ct, headers={"Content-Disposition": disposition(f'vcfops-{kind}-{time.strftime("%Y%m%d-%H%M")}.{"json" if fmt == "json" else "csv"}')})


@app.get("/api/web_search/status")
async def web_search_status():
    return ENGINE.websearch.status()


@app.post("/api/settings/web_search/test")
async def web_search_test(request: Request):
    """저장 전 시험 — 폼 값(비밀값 ******** 은 저장된 값 유지)으로 검색 1회"""
    from .websearch import WebSearch
    b = await request.json()
    v = dict(b.get("value") or {})
    if v.get("api_key") == "********":
        v["api_key"] = ENGINE.websearch.cfg.get("api_key", "")
    v["enabled"] = True
    r = await WebSearch(v).test(str(b.get("query") or "ESXi host not responding vCenter")[:200])
    await audit(request, "settings.web_search.test", v.get("provider", ""), "ok" if r.get("ok") else "fail")
    return r


@app.get("/api/isvara/status")
async def isvara_status():
    return ENGINE.isvara.status()


@app.post("/api/isvara/ask")
async def isvara_ask(req: Request):
    if not ENGINE.isvara.enabled:
        raise HTTPException(400, "Isvara 연동이 꺼져 있습니다(config.yaml isvara.enabled)")
    body = await req.json()
    q = str(body.get("question", "")).strip()
    if len(q) < 3:
        raise HTTPException(400, "질문을 입력하세요")
    await audit(req, "isvara.ask", detail={"q": q[:200]})
    try:
        return await ENGINE.isvara.ask(q, (str(body.get("chapter") or "") or None))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Isvara 응답 실패: {e}") from e


# ------------------------------------------------------------------ RAG 팩
@app.get("/api/rag/packs")
async def rag_packs():
    from .rag.builder import PRESETS
    return {"packs": ENGINE.rag.list(), "status": ENGINE.rag.status(), "presets": PRESETS}


@app.post("/api/rag/packs")
async def rag_import(req: Request, filename: str = "upload.ragpack", enable: bool = False):
    """본문 = .ragpack(zip) 바이트 (Content-Type: application/octet-stream)"""
    data = await req.body()
    try:
        info = await ENGINE.rag.import_pack(data, filename)
        if enable:
            await ENGINE.rag.enable(info["id"])
            info["enabled"] = True
    except Exception as e:  # noqa: BLE001
        await audit(req, "rag.import", filename, "fail", {"error": str(e)[:200]})
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    await audit(req, "rag.import", info.get("id", filename), detail={"enable": enable, "chunks": info.get("chunks")})
    return info


@app.post("/api/rag/packs/{pid}/enable")
async def rag_enable(pid: str, request: Request):
    try:
        res = await ENGINE.rag.enable(pid)
    except KeyError:
        raise HTTPException(404)
    await audit(request, "rag.enable", pid)
    return res


@app.post("/api/rag/packs/{pid}/disable")
async def rag_disable(pid: str, request: Request):
    ENGINE.rag.disable(pid)
    await audit(request, "rag.disable", pid)
    return {"ok": True}


@app.post("/api/rag/packs/{pid}/reembed")
async def rag_reembed(pid: str, request: Request):
    if not ENGINE.rag.embedder.enabled:
        raise HTTPException(400, "rag.embedding 비활성")
    bg(ENGINE.rag.reembed(pid))
    await audit(request, "rag.reembed", pid)
    return {"ok": True}


@app.delete("/api/rag/packs/{pid}")
async def rag_delete(pid: str, request: Request):
    await ENGINE.rag.delete(pid)
    await audit(request, "rag.delete", pid)
    return {"ok": True}


@app.get("/api/rag/search")
async def rag_search(q: str, source: str | None = None, k: int = 5, pack: str | None = None):
    return await ENGINE.rag.search(q, source=source, k=k, pack_ids=[pack] if pack else None)


# ------------------------------------------------------------------ KB·TechDocs 지식 라이브러리
@app.get("/api/knowledge")
async def knowledge_stats(request: Request):
    st = await asyncio.to_thread(ENGINE.knowledge.stats)
    if not AUTH.allowed(who(request).get("role", ""), "settings"):     # 서버 경로는 운영 설정 권한자만(2.20)
        from pathlib import PurePath
        st["paths"] = [PurePath(p).name or p for p in st.get("paths") or []]
        st["configured_paths"] = [PurePath(str(p)).name or str(p) for p in st.get("configured_paths") or []]
        st["roots"] = {PurePath(k).name or k: v for k, v in (st.get("roots") or {}).items()}
    open_ = [a for a in ENGINE.anomalies.values() if not a.ack]
    st["link"] = {**ENGINE.kblink.stats, "enabled": ENGINE.kblink.enabled, "open": len(open_),
                  "with_ai_refs": sum(1 for a in open_ if (a.ai or {}).get("references")),
                  "with_auto": sum(1 for a in open_ if not (a.ai or {}).get("references") and a.related),
                  "kb_refresh": ENGINE.patterns.stats.get("kb_refresh", 0)}
    return st


@app.put("/api/knowledge/upload")
async def knowledge_upload(request: Request):
    """본문 = md 묶음 zip(스트리밍 저장, 최대 knowledge.max_upload_gb). 풀어서 증분 색인·임베딩을 백그라운드로 시작"""
    from urllib.parse import unquote
    name = unquote(request.headers.get("x-filename", "upload.zip"))
    limit = float((CFG.get("knowledge") or {}).get("max_upload_gb", 4)) * 2**30
    tmp = ENGINE.knowledge.root / f".up-{int(time.time() * 1000)}.zip"
    n = 0
    try:
        with open(tmp, "wb") as f:
            async for part in request.stream():
                n += len(part)
                if n > limit:
                    raise HTTPException(413, "업로드 크기 초과")
                f.write(part)
        info = await asyncio.to_thread(ENGINE.knowledge.import_zip, tmp, name)
    except (zipfile.BadZipFile, ValueError) as e:
        raise HTTPException(400, f"zip 해석 실패: {e}")
    finally:
        tmp.unlink(missing_ok=True)
    bg(ENGINE.knowledge.refresh())
    await audit(request, "knowledge.upload", name, detail={**info, "bytes": n})
    return info


@app.put("/api/knowledge/file")
async def knowledge_file(request: Request, collection: str = "manual"):
    """md 파일 하나 직접 올리기(본문 = 파일 내용, X-Filename·X-Relpath 헤더). 저장 즉시 색인해 파싱 결과를 돌려준다.
    여러 파일·폴더는 화면이 파일마다 호출하고 끝에 POST /reindex(임베딩) — 같은 경로는 덮어씀"""
    from urllib.parse import unquote
    name = unquote(request.headers.get("x-filename", ""))
    rel = unquote(request.headers.get("x-relpath", "")) or name
    limit = ENGINE.knowledge.max_file
    data = bytearray()
    async for part in request.stream():
        data += part
        if len(data) > limit:
            raise HTTPException(413, f"파일이 너무 큽니다(최대 {limit // 2**20}MB)")
    try:
        r = await asyncio.to_thread(ENGINE.knowledge.save_file, bytes(data), name, rel, collection)
    except ValueError as e:
        raise HTTPException(400, str(e))
    await audit(request, "knowledge.file", f"{r['collection']}/{r['saved']}"[:300], detail={"kb": r.get("kb"), "bytes": len(data)})
    return r


@app.post("/api/knowledge/reindex")
async def knowledge_reindex(request: Request, full: bool = False):
    bg(ENGINE.knowledge.refresh(full))
    await audit(request, "knowledge.reindex", "full" if full else "incremental")
    return {"started": True}


@app.delete("/api/knowledge/uploads/{name}")
async def knowledge_remove(name: str, request: Request):
    try:
        await asyncio.to_thread(ENGINE.knowledge.remove_upload, name)
    except ValueError as e:                                  # 2.30.0 이름 검증('..' 등 거부)
        raise HTTPException(400, str(e))
    bg(ENGINE.knowledge.refresh())
    await audit(request, "knowledge.remove", name)
    return {"ok": True}


@app.get("/api/knowledge/search")
async def knowledge_search(q: str, source: str | None = None, intent: str = "chat", k: int = 8, anomaly_id: str = ""):
    """라이브러리 + 팩 검색(관련 문서 패널·검색 시험). anomaly_id 를 주면 그 이상징후 기준(피드백 반영)"""
    from .knowledge import doc_sig
    sig = None
    if anomaly_id and anomaly_id in ENGINE.anomalies:
        ev = ENGINE.anomalies[anomaly_id].event or {}
        sig, source = doc_sig(ev), source or ev.get("source")
        q = q or ev.get("message", "")
    return await ENGINE.rag.search(q[:2000], source=source, k=max(1, min(k, 20)), intent=intent, sig=sig)


@app.get("/api/knowledge/recent")
async def knowledge_recent(days: float = 14, limit: int = 40, mine: bool = False):
    """최근 갱신 KB·문서 — 운영 중인 제품·버전(vCenter·ESXi·NSX·Avi)에 해당하는 문서를 표시하고 위로"""
    from .knowledge import env_versions
    return {"env": {k: sorted(v) for k, v in env_versions(ENGINE).items()},
            "items": await asyncio.to_thread(ENGINE.knowledge.recent, max(1.0, min(days, 365)), max(1, min(limit, 200)), env_versions(ENGINE), mine)}


@app.get("/api/knowledge/doc/{did}")
async def knowledge_doc(did: int):
    d = await asyncio.to_thread(ENGINE.knowledge.doc, did)
    if not d:
        raise HTTPException(404)
    d.pop("path", None)
    return d


@app.post("/api/knowledge/feedback")
async def knowledge_feedback(request: Request):
    """관련 문서 '도움됨(+1)/무관(-1)/취소(0)' — 같은 로그 패턴의 다음 검색부터 순위에 반영"""
    from .knowledge import doc_sig
    b = await request.json()
    doc = str(b.get("doc_id", ""))
    if not doc.startswith("lib:"):
        raise HTTPException(400, "라이브러리 문서만 피드백할 수 있습니다")
    aid = str(b.get("anomaly_id", ""))
    a = ENGINE.anomalies.get(aid)
    sig = doc_sig(a.event or {}) if a else hashlib.sha1(str(b.get("q", "")).lower().encode()).hexdigest()[:20]
    vote = int(b.get("vote", 0))
    await asyncio.to_thread(ENGINE.knowledge.feedback, sig, int(doc[4:]), vote, who(request).get("user", ""))
    await audit(request, "knowledge.feedback", doc, detail={"vote": vote, "anomaly": aid})
    return {"ok": True}


@app.get("/api/knowledge/gaps")
async def knowledge_gaps(days: float = 7, limit: int = 30):
    """지식 공백 — AI 가 근거 문서를 하나도 쓰지 못한 이상징후 패턴(어떤 KB·문서를 더 모아야 하는지)"""
    from .knowledge import KnowledgeLibrary
    since = time.time() - days * 86400
    g: dict[str, dict] = {}
    for a in ENGINE.anomalies.values():
        if a.last_seen < since or a.status != "analyzed" or (a.ai or {}).get("is_anomaly") is False:
            continue
        if (a.ai or {}).get("references"):
            continue
        e = a.event or {}
        key = e.get("pattern") or a.title
        x = g.setdefault(key, {"title": a.title, "source": e.get("source"), "severity": a.severity, "count": 0, "last": 0,
                               "sample": str(e.get("message", ""))[:300], "candidates": len(a.refs or []), "anomaly_id": a.id})
        x["count"] += a.count
        x["last"] = max(x["last"], a.last_seen)
        if SEV_RANK.get(a.severity, 0) > SEV_RANK.get(x["severity"], 0):
            x["severity"] = a.severity
    out = sorted(g.values(), key=lambda x: (-SEV_RANK.get(x["severity"], 0), -x["count"]))[:max(1, min(limit, 200))]
    for x in out:
        words, ids = KnowledgeLibrary.query_terms(x["sample"], 8)
        x["keywords"] = sorted(ids)[:4] + [w for w in words if w not in ids and not any(ch.isdigit() for ch in w)][:6]
    return {"days": days, "items": out}


@app.get("/api/rag/embedding/health")
async def rag_embed_health():
    return await ENGINE.rag.embedder.health()


# ------------------------------------------------------------------ HTTP 수집(에이전트/Fluent Bit/스크립트)
@app.post("/api/ingest")
async def ingest(req: Request):
    """HTTP 수집 — Fluent Bit(http output, format json/json_lines, gzip) · 스크립트. VM 게스트·물리 서버 OS 에이전트의 입구.
    인증: X-AIOps-Token 또는 Authorization: Bearer <API 토큰(scope=ingest)>"""
    if not CFG["ingest"].get("enabled"):
        raise HTTPException(404)
    got = req.headers.get("x-aiops-token") or req.headers.get("authorization", "").removeprefix("Bearer ").strip()
    legacy = CFG["ingest"].get("token")
    ok = bool(legacy) and bool(got) and hmac.compare_digest(got, legacy)
    if not ok and AUTH.enabled:
        ok = bool(await AUTH.token_user(got, "ingest", client_ip(req)))
    if not ok and (legacy or AUTH.enabled):
        raise HTTPException(401, "ingest 토큰 필요(설정 → API 토큰, scope=ingest)")
    raw = await req.body()
    if len(raw) > int(CFG["ingest"].get("max_body_mb", 32)) * 1024 * 1024:
        raise HTTPException(413, "요청 본문이 너무 큽니다(ingest.max_body_mb)")
    if req.headers.get("content-encoding", "").lower() == "gzip" or raw[:2] == b"\x1f\x8b":
        import gzip
        try:
            raw = await asyncio.to_thread(gzip.decompress, raw)
        except OSError:
            raise HTTPException(400, "gzip 해제 실패")
    text = raw.decode("utf-8", "replace").strip()
    try:
        data: Any = json.loads(text) if text else []
    except ValueError:                                 # json_lines / NDJSON
        data = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except ValueError:
                    continue
    items = data if isinstance(data, list) else data.get("events", [data]) if isinstance(data, dict) else []
    from .agents import normalize
    peer = req.client.host if req.client else ""
    n = hb = dropped = 0
    reg = ENGINE.agents
    for it in items[:20000]:
        if not isinstance(it, dict):
            continue
        form, ev, meta = normalize(it, peer, sev_from_text)
        if form == "heartbeat":
            reg.heartbeat(meta)
            hb += 1
            continue
        if ev is None:
            continue
        if ev.connector == "agent":
            reg.seen(meta, ev.severity)
        if ENGINE.submit(ev):
            n += 1
        else:
            dropped += 1
    return {"accepted": n, "heartbeats": hb, "dropped": dropped}


# ------------------------------------------------------------------ VM 게스트·물리 서버 OS 에이전트
AGENT_DIR = Path(__file__).resolve().parent.parent / "deploy" / "agents"
AGENT_FILES = {"install-linux.sh": AGENT_DIR / "linux" / "install-agent.sh",
               "install-windows.ps1": AGENT_DIR / "windows" / "install-agent.ps1",
               "uninstall-linux.sh": AGENT_DIR / "linux" / "uninstall-agent.sh"}


@app.post("/api/redfish/events/{token}", include_in_schema=False)
async def redfish_event(token: str, request: Request):
    """BMC(iLO·iDRAC·XCC) Redfish 이벤트 수신(push) — 경로의 커넥터별 토큰으로 인증(BMC 는 세션·헤더 인증 불가)"""
    c = ENGINE.redfish_by_token(token)
    if c is None:
        raise HTTPException(404)
    try:
        payload = json.loads((await request.body()) or b"{}")
    except ValueError:
        raise HTTPException(400, "JSON 아님")
    n = await c.on_push(payload if isinstance(payload, dict) else {"Events": payload})
    return {"accepted": n}


@app.post("/api/connectors/{name}/test-event")
async def connector_test_event(name: str, request: Request):
    """Redfish BMC 에 시험 이벤트 발송 요청 → 실시간 수신 경로 확인"""
    for c in ENGINE.connectors:
        if c.name == name and hasattr(c, "test_event"):
            res = await c.test_event()
            await audit(request, "connector.test_event", name, "ok" if res.get("ok") else "fail")
            return res
    raise HTTPException(404, "Redfish 커넥터 없음")


@app.get("/agents/{name}", include_in_schema=False)
async def agent_file(name: str):
    """에이전트 설치 스크립트 배포(비밀값 없음 — 토큰은 설치 인자로 전달)"""
    if name == "aiops.crt":                     # 서버 인증서(공개 정보) — 에이전트 신뢰 등록용
        c = _cert_path()
        if not c:
            raise HTTPException(404)
        return FileResponse(c, media_type="application/x-pem-file", filename="aiops.crt")
    f = AGENT_FILES.get(name)
    if not f or not f.exists():
        raise HTTPException(404)
    return FileResponse(f, media_type="text/plain; charset=utf-8", filename=name)


@app.get("/api/agents")
async def agents_list():
    items = ENGINE.agents.list()
    cnt: dict[str, int] = {}
    for x in items:
        cnt[x["state"]] = cnt.get(x["state"], 0) + 1
    return {"items": items, "summary": cnt, "stale_seconds": ENGINE.agents.stale,
            "blocks": ENGINE.agents.blocks(), "blocked_dropped": ENGINE.agents.dropped}


@app.get("/api/agents/coverage")
async def agents_coverage():
    return ENGINE.agents.coverage()


@app.delete("/api/agents/{host}")
async def agent_retire(host: str, request: Request, purge: bool = False, block: bool = True):
    """퇴역(서버 폐기·이관) — 무응답 감시 제외, 다시 수신되면 자동 복귀.
    purge=true 면 등록 삭제(목록·DB 에서 제거) + block=true(기본)면 차단 — 다시 보내도 등록·저장하지 않고 시도만 기록"""
    if purge:
        if not await ENGINE.agents.purge(host, block=block, by=who(request).get("user", "")):
            raise HTTPException(404)
        await audit(request, "agent.delete", host, detail={"block": block})
        return {"ok": True, "deleted": True, "blocked": block}
    if not await ENGINE.agents.retire(host):
        raise HTTPException(404)
    await audit(request, "agent.retire", host)
    return {"ok": True}


@app.post("/api/agents/purge")
async def agents_purge(request: Request):
    """등록 일괄 삭제 — {hosts:[…]} 또는 {state:"retired"|"stale"}(퇴역·무응답 전부)"""
    b = await request.json()
    hosts = [str(h) for h in (b.get("hosts") or [])][:2000]
    st = str(b.get("state") or "")
    if st in ("retired", "stale"):
        hosts += [x["host"] for x in ENGINE.agents.list() if x.get("state") == st]
    blk = bool(b.get("block", True))
    by = who(request).get("user", "")
    done = [h for h in dict.fromkeys(hosts) if await ENGINE.agents.purge(h, block=blk, by=by)]
    await audit(request, "agent.delete", ",".join(done)[:500], detail={"count": len(done), "state": st, "block": blk})
    return {"deleted": len(done), "hosts": done, "blocked": blk}


@app.delete("/api/agents/blocks/{host}")
async def agent_unblock(host: str, request: Request):
    """차단 해제 — 다음 수신부터 다시 등록"""
    if not await ENGINE.agents.unblock(host):
        raise HTTPException(404)
    await audit(request, "agent.unblock", host)
    return {"ok": True}


def _server_url(request: Request) -> str:
    u = (CFG.get("agents") or {}).get("public_url") or CFG["server"].get("public_url") or ""
    return (u or f"{request.url.scheme}://{request.url.netloc}").rstrip("/")


# Windows PowerShell 5.1 다운로드 부트스트랩
#  · 스크립트블록 인증서 콜백({$true})은 .NET I/O 스레드에서 호출되면 "There is no Runspace available" 로 실패하고
#    겉으로는 "The underlying connection was closed: An unexpected error occurred on a send" 로 보인다 → C# ICertificatePolicy 사용
#  · 시스템(IE) 프록시가 내부 AIOps 주소를 가로채는 경우가 많아 이 다운로드는 프록시를 쓰지 않음
#  · 실패 시 curl.exe(Windows 10 1803·Server 2019 이상 내장)로 재시도 — 오류가 Schannel 코드로 구체적으로 나온다
_WIN_TRUST_CS = ("using System.Net;using System.Security.Cryptography.X509Certificates;"
                 "public class AiopsTrust:ICertificatePolicy{public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int p){return true;}}")


def _win_bootstrap(srv: str, args: str, https: bool) -> str:
    """Windows PowerShell 5.1(Desktop) 기준, PowerShell 7(Core) 에서 붙여 넣어도 동작. 메시지는 ASCII(콘솔 코드 페이지 무관)"""
    trust = (f"if(-not('AiopsTrust' -as [type])){{Add-Type '{_WIN_TRUST_CS}'}}; [Net.ServicePointManager]::CertificatePolicy=New-Object AiopsTrust; "
             if https else "")
    k = "k" if https else ""
    skip = " -SkipCertificateCheck" if https else ""
    return ("$ErrorActionPreference='Stop'; $s='" + srv + "'; $f=Join-Path $PWD 'install-agent.ps1'; "
            "try{if($PSVersionTable.PSEdition -eq 'Core'){"
            f"Invoke-WebRequest \"$s/agents/install-windows.ps1\" -OutFile $f -NoProxy{skip}}}else{{"
            "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; " + trust +
            "$w=New-Object Net.WebClient; $w.Proxy=$null; $w.DownloadFile(\"$s/agents/install-windows.ps1\",$f)}}"
            "catch{Write-Host \"download failed: $($_.Exception.InnerException.Message) $($_.Exception.Message) - retrying with curl.exe\"; "
            f"curl.exe -fsS{k} --noproxy '*' \"$s/agents/install-windows.ps1\" -o $f; if($LASTEXITCODE){{throw \"download failed (curl.exe exit $LASTEXITCODE)\"}}}}; "
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f -Server $s {args}" + (" -Insecure" if https else ""))


def _win_trust(srv: str) -> str:
    """-Insecure 대신 이 서버 인증서를 Windows 신뢰 루트에 등록(지문 확인 후)"""
    return ("$s='" + srv + "'; curl.exe -fsSk --noproxy '*' \"$s/agents/aiops.crt\" -o \"$env:TEMP\\aiops.crt\"; "
            "'SHA256 ' + ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash((Get-PfxCertificate \"$env:TEMP\\aiops.crt\").RawData)) -replace '-'); "
            "Import-Certificate -FilePath \"$env:TEMP\\aiops.crt\" -CertStoreLocation Cert:\\LocalMachine\\Root")


def _cert_path() -> Path | None:
    f = Path(((CFG["server"].get("tls") or {}).get("certfile")) or "")
    return f if f.is_file() else None


def _cert_fp() -> str:
    f = _cert_path()
    if not f:
        return ""
    try:
        der = ssl.PEM_cert_to_DER_cert(f.read_text())
    except (ValueError, OSError):
        return ""
    return hashlib.sha256(der).hexdigest().upper()


@app.post("/api/agents/enroll")
async def agent_enroll(request: Request):
    """에이전트 등록 — ingest 전용 토큰 발급 + Linux·Windows·rsyslog 설치 명령 생성(토큰은 이 응답에서만 표시)"""
    b = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    kind = "baremetal" if str(b.get("kind", "vm")) in ("baremetal", "physical", "server") else "vm"
    role = "".join(ch for ch in str(b.get("role", ""))[:30] if ch.isalnum() or ch in "-_")
    days = max(0, min(int(b.get("days", 365)), 3650))
    u = who(request)
    token = await AUTH.create_token(f"agent-{kind}{'-' + role if role else ''}-{time.strftime('%Y%m%d')}", ["ingest"], days, u["user"])
    srv = _server_url(request)
    https = srv.startswith("https")
    ra = f" --role {role}" if role else ""
    wa = f" -Role {role}" if role else ""
    k_flag = "-k " if https else ""
    out = {
        "server": srv, "token": token, "kind": kind, "role": role, "expires_days": days,
        "linux": f"curl -fsS{k_flag.strip() and 'k'} {srv}/agents/install-linux.sh -o install-agent.sh && "
                 f"sudo bash install-agent.sh --server {srv} --token {token} --kind {kind}{ra}" + (" --insecure" if https else ""),
        "linux_rsyslog": f"curl -fsS{k_flag.strip() and 'k'} {srv}/agents/install-linux.sh -o install-agent.sh && "
                         f"sudo bash install-agent.sh --mode rsyslog --server {srv} --kind {kind}{ra}",
        "windows": _win_bootstrap(srv, f"-Token {token} -Kind {kind}{wa}", https),
        "windows_trust": _win_trust(srv) if https else "",
        "cert_sha256": _cert_fp() if https else "",
        "note": "토큰은 이 화면에서만 표시됩니다. 사내 CA 인증서를 쓰면 --insecure/-Insecure 대신 --ca <PEM>/-CaFile 을 권장합니다. "
                "Windows 에서 다운로드가 실패하면 curl.exe -vk <서버>/readyz 로 TLS·프록시 원인을 확인하세요.",
    }
    await audit(request, "agent.enroll", kind, detail={"role": role, "days": days})
    return out


# ------------------------------------------------------------------ 엔터프라이즈 API(인시던트·조치·설정·감사·리포트·백업·메트릭)
from .api_enterprise import build_router  # noqa: E402

app.include_router(build_router(ENGINE, AUTH, SETTINGS, ACTIONS, REPORTER, CFG, who, audit))
from .noc import build_router as build_noc  # noqa: E402

app.include_router(build_noc(ENGINE, CFG, lambda req, perm: AUTH.allowed(who(req).get("role", ""), perm)))
from .api_billing import build_router as build_billing  # noqa: E402

app.include_router(build_billing(ENGINE, CFG, who, audit, lambda req, perm: AUTH.allowed(who(req).get("role", ""), perm)))
from .api_capacity import build_router as build_capacity  # noqa: E402

app.include_router(build_capacity(ENGINE, CFG, who, audit))
from .api_assess import build_router as build_assess  # noqa: E402

app.include_router(build_assess(ENGINE, CFG, who, audit))
from .api_support import build_router as build_support  # noqa: E402

app.include_router(build_support(ENGINE, AUTH, CFG, who, audit))   # 2.11.0 지원 요청(SR)·로그 내보내기·공유 링크
from .api_cloudcost import build_router as build_cloudcost  # noqa: E402

app.include_router(build_cloudcost(ENGINE, CFG, who, audit))       # 2.13.0 클라우드 비용 비교
from .api_readiness import build_router as build_readiness  # noqa: E402

app.include_router(build_readiness(ENGINE, CFG, who, audit))       # 2.14.0 하드웨어 준비도(VCF-R)
from .api_rvtools import build_router as build_rvtools  # noqa: E402

app.include_router(build_rvtools(ENGINE, CFG, who, audit))         # 2.15.0 RVTools 분석
from .certs import CertScanner  # noqa: E402
from .api_lifecycle import build_router as build_lifecycle  # noqa: E402

CERTS = CertScanner(ENGINE, CFG.get("certs") or {})
ENGINE.certs = CERTS
from .drift import DriftWatch  # noqa: E402

ENGINE.driftwatch = DriftWatch(ENGINE)                             # 2.37.0 구성 변경 이력
app.include_router(build_lifecycle(ENGINE, CERTS, who, audit))      # 2.36.0 인증서 달력·구성 드리프트·버전 수명
from .checkbot import CheckBot  # noqa: E402
from .api_checkbot import build_router as build_checkbot  # noqa: E402

ENGINE.checkbot = CheckBot(ENGINE, CFG.get("checkbot") or {})
from .scenlib import LibWatch  # noqa: E402

ENGINE.scnwatch = LibWatch(ENGINE, float(((CFG.get("checkbot") or {}).get("library_interval_h")) or 6))   # 2.48.0 What-If 연속 검증
app.include_router(build_checkbot(ENGINE, ENGINE.checkbot, who, audit))   # 2.38.0 AI 체크봇(what-if 시나리오 연속 검증)
from .vulnscan import VulnCheck  # noqa: E402
from .api_vuln import build_router as build_vuln  # noqa: E402

ENGINE.vulncheck = VulnCheck(ENGINE, CFG.get("vulncheck") or {})
app.include_router(build_vuln(ENGINE, ENGINE.vulncheck, who, audit))       # 2.43.0 내부 취약점 검증 · vSAN ESA 전환 산정
from .practice import Practice  # noqa: E402
from .api_practice import build_router as build_practice  # noqa: E402

ENGINE.practice = Practice(ENGINE)
app.include_router(build_practice(ENGINE, ENGINE.practice, who, audit))     # 2.44.0 비용 절감 찾기 · AI 변경 사전 검토
from .aiopsx import AIOpsX  # noqa: E402
from .api_aiopsx import build_router as build_aiopsx  # noqa: E402

ENGINE.aiopsx = AIOpsX(ENGINE, CFG.get("aiops") or {})
app.include_router(build_aiopsx(ENGINE, ENGINE.aiopsx, who, audit))         # 2.45.0 AIOps 인사이트
from .api_license import build_router as build_license  # noqa: E402

app.include_router(build_license(ENGINE, CFG, who, audit))         # 2.16.0 라이선스 관리
from .api_hostdiag import build_router as build_hostdiag  # noqa: E402
from .api_segtraffic import build_router as build_segtraffic  # noqa: E402

app.include_router(build_hostdiag(ENGINE, CFG, who, audit))        # 2.18.0 호스트 분석
app.include_router(build_segtraffic(ENGINE, CFG, who, audit))      # 2.21.0 NSX 세그먼트 트래픽
from .mcp_server import build_router as build_mcp  # noqa: E402

app.include_router(build_mcp(ENGINE, CFG))           # POST /mcp — KB·TechDocs 지식·관제 상태(읽기 전용, API 토큰)
