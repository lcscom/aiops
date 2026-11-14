"""운영 런처 — config.yaml 의 server 섹션으로 uvicorn 을 튜닝해 단일 프로세스로 실행.

  python -m app.serve                 (Windows 서비스/리눅스 systemd 공통 진입점)

단일 프로세스(workers=1)인 이유
  수집기(syslog UDP/TCP 514, SNMP UDP 162)와 이상징후·WebSocket 상태가 프로세스 메모리에 있으므로
  워커를 늘리면 포트 바인드 충돌·상태 분산이 생긴다. I/O 는 asyncio 로 동시 처리되고,
  CPU 비중이 큰 LLM·임베딩은 PAIS(GPU)에서 수행되므로 단일 프로세스로 충분하다.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import uvicorn

from .config import load_config


def _http_impl() -> str:
    try:
        import httptools  # noqa: F401  C 파서 — h11 대비 HTTP 파싱 오버헤드 감소
        return "httptools"
    except ImportError:
        return "h11"


def main() -> None:
    # syslog UDP 수신 스레드가 GIL 을 자주 얻도록(기본 5ms → 1ms) — 처리 스레드 포화 시에도 커널 버퍼를 비워
    # 유실이 OS(무차별)가 아닌 앱 큐(우선순위 보존)에서 일어나게 한다
    sys.setswitchinterval(float(os.environ.get("AIOPS_GIL_SWITCH", "0.001")))
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    # 작업 폴더 고정 — Windows 서비스: 프로젝트 폴더 / Linux(systemd): AIOPS_WORKDIR(/var/lib/vcf-aiops, 상대 경로 기준)
    os.chdir(os.environ.get("AIOPS_WORKDIR") or root)
    cfg = load_config()
    s = cfg["server"]
    tls = s.get("tls") or {}
    kw: dict = {}
    en = str(tls.get("enabled", "auto")).lower()
    # auto: 인증서 파일(export-cert.ps1 결과)이 있으면 HTTPS, 없으면 HTTP
    tls_on = en in ("true", "1", "yes") or (en == "auto" and Path(tls.get("certfile", "")).is_file()
                                              and Path(tls.get("keyfile", "")).is_file())
    tls["enabled"] = tls_on
    if tls_on:
        kw.update(ssl_certfile=tls["certfile"], ssl_keyfile=tls["keyfile"])
        if tls.get("keyfile_password"):
            kw["ssl_keyfile_password"] = tls["keyfile_password"]
        if tls.get("ciphers"):                       # 기본은 OpenSSL 기본값(TLS 1.2+ ECDHE-GCM — Windows Server 2016+ Schannel 과 협상 확인)
            kw["ssl_ciphers"] = str(tls["ciphers"])
    logging.basicConfig(level=getattr(logging, str(s.get("log_level", "info")).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    scheme = "https" if tls.get("enabled") else "http"
    print(f"VCF AIops → {scheme}://{s['host']}:{s['port']}  (pid {os.getpid()}, python {sys.version.split()[0]}, "
          f"http={_http_impl()}, platform={sys.platform})", flush=True)
    uvicorn.run(
        "app.main:app",
        host=s["host"], port=int(s["port"]),
        workers=1,
        # Windows: Proactor 루프(UDP 수신 지원, uvloop 미지원) / Linux: uvloop(설치돼 있으면) — server.loop 로 강제 가능
        loop=str(s.get("loop") or ("asyncio" if sys.platform == "win32" else "auto")),
        http=_http_impl(),
        ws="auto",                          # websockets(-sansio) 자동 선택 — uvicorn 버전 간 호환
        ws_ping_interval=float(s.get("ws_ping_interval", 20)),
        ws_ping_timeout=float(s.get("ws_ping_timeout", 20)),
        ws_max_size=int(s.get("ws_max_size", 4 * 1024 * 1024)),
        timeout_keep_alive=int(s.get("timeout_keep_alive", 15)),
        limit_concurrency=int(s["limit_concurrency"]) if s.get("limit_concurrency") else None,
        backlog=int(s.get("backlog", 2048)),
        proxy_headers=True,
        forwarded_allow_ips=s.get("trusted_proxies", "127.0.0.1"),
        server_header=False,
        date_header=True,
        access_log=bool(s.get("access_log", False)),   # 운영 기본 off — 폴링·정적 요청 로그로 디스크 I/O 낭비 방지
        log_level=str(s.get("log_level", "info")),
        **kw,
    )


if __name__ == "__main__":
    main()
