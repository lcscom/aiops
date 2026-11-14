"""자가 점검·DB 관리(2.2) — 운영 중 조용히 망가지는 것을 미리 잡는다.

  · 기동 전 점검(preflight)  config 형식·범위, 데이터 디렉터리 쓰기, 디스크 여유, TLS 인증서 파일·만료, 포트 범위 → 경고 목록(기동은 계속)
  · DB 관리(dbcare)           매일 PRAGMA quick_check(손상 조기 발견), WAL 이 wal_max_mb 를 넘으면 checkpoint(TRUNCATE), 표별 행 수·크기 집계
  · 백업 검증                 최신 백업 파일을 읽기 전용으로 열어 integrity_check — 복원 가능한 백업인지(백업이 켜져 있는데 2일 이상 없으면 경고)
  · 자원 감시                 프로세스 RSS(경고 기준 memory_warn_mb), 열린 파일 수, 데이터 볼륨 사용률, 인증서 만료 D-14
결과는 /api/health 의 checks 와 Prometheus(aiops_selfcheck_*)에 노출되고, 문제는 플랫폼 이벤트(health 와 같은 경로)로 올라간다.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import ssl
import time
from pathlib import Path
from typing import Any


def _rss_mb() -> float | None:
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    return round(int(ln.split()[1]) / 1024, 1)
    except OSError:
        pass
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except Exception:  # noqa: BLE001
        return None


def _open_files() -> int | None:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return None


def cert_days_left(certfile: str) -> int | None:
    """PEM 인증서 만료까지 남은 일수(없거나 못 읽으면 None)"""
    p = Path(certfile)
    if not p.is_file():
        return None
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(p.read_bytes())
        exp = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return int((exp.timestamp() - time.time()) // 86400)
    except Exception:  # noqa: BLE001
        try:
            d = ssl._ssl._test_decode_cert(str(p))  # type: ignore[attr-defined]
            return int((ssl.cert_time_to_seconds(d["notAfter"]) - time.time()) // 86400)
        except Exception:  # noqa: BLE001
            return None


# ---------------------------------------------------------------- 기동 전 점검
_RANGES = {
    "server.port": (1, 65535), "server.retention_days": (1, 3650), "server.buffer_size": (100, 10_000_000),
    "auth.session_idle_minutes": (1, 1440), "auth.session_absolute_hours": (1, 720), "auth.lockout_threshold": (1, 100),
    "alerting.cooldown": (0, 86400), "alerting.max_attempts": (1, 50), "storage.log_queue": (1000, 10_000_000),
    "siem.port": (1, 65535), "incidents.correlation_window": (0, 86400), "backup.keep": (1, 365),
}


def _get(cfg: dict, path: str):
    cur: Any = cfg
    for k in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def preflight(cfg: dict, data_dir: str) -> list[dict]:
    """설정·환경 점검 — [{key, level(warning|error), text}]. error 라도 기동은 계속(화면·로그에 표시)."""
    out: list[dict] = []
    add = lambda key, level, text: out.append({"key": key, "level": level, "text": text})  # noqa: E731
    for path, (lo, hi) in _RANGES.items():
        v = _get(cfg, path)
        if v is None:
            continue
        try:
            fv = float(v)
        except (TypeError, ValueError):
            add(f"cfg:{path}", "error", f"설정 {path} 가 숫자가 아님: {v!r}")
            continue
        if not lo <= fv <= hi:
            add(f"cfg:{path}", "warning", f"설정 {path}={v} 가 권장 범위({lo}~{hi}) 밖")
    sev = _get(cfg, "alerting.min_severity")
    if sev not in (None, "info", "warning", "error", "critical"):
        add("cfg:alerting.min_severity", "error", f"alerting.min_severity 값 오류: {sev!r}")
    for i, wh in enumerate(_get(cfg, "alerting.webhooks") or []):
        f = (wh or {}).get("format", "generic")
        if f not in ("teams", "slack", "generic", "pagerduty", "opsgenie"):
            add(f"cfg:alerting.webhooks[{i}]", "error", f"웹훅 형식 오류: {f!r}")
        elif f in ("pagerduty", "opsgenie") and not (wh.get("secret") or wh.get("key")):
            add(f"cfg:alerting.webhooks[{i}]", "warning", f"{wh.get('name') or f}: {f} 키(secret) 없음 — 발송 실패함")
        elif f not in ("pagerduty", "opsgenie") and not wh.get("url"):
            add(f"cfg:alerting.webhooks[{i}]", "error", f"{wh.get('name') or f}: URL 없음")
    oidc = _get(cfg, "auth.oidc") or {}
    if oidc.get("enabled") and not (oidc.get("issuer") and oidc.get("client_id")):
        add("cfg:auth.oidc", "error", "auth.oidc.enabled 인데 issuer·client_id 가 비어 SSO 버튼이 동작하지 않음")
    if oidc.get("enabled") and not oidc.get("group_role_map") and not oidc.get("default_role"):
        add("cfg:auth.oidc", "warning", "auth.oidc: group_role_map·default_role 둘 다 없음 — 모든 SSO 로그인이 거부됨")
    ldap = _get(cfg, "auth.ldap") or {}
    if ldap.get("enabled") and not ldap.get("servers"):
        add("cfg:auth.ldap", "error", "auth.ldap.enabled 인데 servers 가 비어 있음")
    mfa = _get(cfg, "auth.mfa") or {}
    bad_roles = [r for r in (mfa.get("required_roles") or []) if r not in ("viewer", "auditor", "operator", "admin")]
    if bad_roles:
        add("cfg:auth.mfa", "warning", f"auth.mfa.required_roles 에 모르는 역할: {bad_roles}")
    siem = _get(cfg, "siem") or {}
    if siem.get("enabled") and not siem.get("host"):
        add("cfg:siem", "error", "siem.enabled 인데 host 가 비어 있음")
    if siem.get("protocol") not in (None, "udp", "tcp", "tls"):
        add("cfg:siem", "error", f"siem.protocol 값 오류: {siem.get('protocol')!r}")
    # 환경
    d = Path(data_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        t = d / ".write-test"
        t.write_text("ok", encoding="utf-8")
        t.unlink()
    except OSError as e:
        add("env:data_dir", "error", f"데이터 디렉터리 쓰기 불가 {d}: {e}")
    try:
        free = shutil.disk_usage(d).free // 2**20
        if free < int(_get(cfg, "storage.min_free_mb") or 1024) * 2:
            add("env:disk", "warning", f"데이터 볼륨 여유 {free}MB — 곧 원본 로그 저장이 중지됨(storage.min_free_mb 의 2배 미만)")
    except OSError:
        pass
    tls = _get(cfg, "server.tls") or {}
    if tls.get("enabled") in (True, "auto", "true"):
        cf, kf = tls.get("certfile", ""), tls.get("keyfile", "")
        if tls.get("enabled") is True and (not Path(cf).is_file() or not Path(kf).is_file()):
            add("env:tls", "error", f"TLS 인증서/키 파일 없음: {cf} · {kf}")
        days = cert_days_left(cf)
        if days is not None and days < 14:
            add("env:tls_expiry", "error" if days < 0 else "warning", f"TLS 인증서 만료 {'지남' if days < 0 else f'D-{days}'} ({cf})")
    return out


# ---------------------------------------------------------------- 런타임 자가 점검
class SelfCheck:
    def __init__(self, engine, cfg: dict | None = None, data_dir: str = "data"):
        self.e = engine
        c = cfg or {}
        self.data_dir = data_dir
        self.wal_max_mb = float(c.get("wal_max_mb", 256))
        self.memory_warn_mb = float(c.get("memory_warn_mb", 3072))
        self.fd_warn = int(c.get("open_files_warn", 4000))
        self.quick_check_hours = float(c.get("quick_check_hours", 24))
        self.backup_stale_days = float(c.get("backup_stale_days", 2))
        self.verify_backups = bool(c.get("verify_backups", True))
        self.state: dict[str, Any] = {"preflight": [], "db": {}, "backup": {}, "resources": {}, "cert": {}, "checked": 0.0,
                                      "quick_check": {"result": "", "ts": 0.0, "ms": 0}, "wal_checkpoints": 0}
        self.issues: list[dict] = []
        self._last_quick = 0.0
        self._verified: dict[str, dict] = {}

    # ---- DB
    def _db_stats(self) -> dict:
        p = Path(self.e.store.path)
        wal = p.with_name(p.name + "-wal")
        info = {"db_mb": round(p.stat().st_size / 2**20, 1) if p.exists() else 0,
                "wal_mb": round(wal.stat().st_size / 2**20, 1) if wal.exists() else 0, "tables": {}}
        try:
            c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
            c.execute("PRAGMA busy_timeout=3000")
            names = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for n in names[:60]:
                try:
                    info["tables"][n] = c.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0]
                except sqlite3.Error:
                    info["tables"][n] = None
            try:
                ps, pc, fl = (c.execute(f"PRAGMA {k}").fetchone()[0] for k in ("page_size", "page_count", "freelist_count"))
                info["free_mb"] = round(ps * fl / 2**20, 1)
                info["used_mb"] = round(ps * (pc - fl) / 2**20, 1)
            except sqlite3.Error:
                pass
            c.close()
        except sqlite3.Error as e:
            info["error"] = str(e)[:120]
        return info

    async def quick_check(self) -> dict:
        t0 = time.time()

        def run():
            c = sqlite3.connect(f"file:{self.e.store.path}?mode=ro", uri=True, timeout=10)
            c.execute("PRAGMA busy_timeout=10000")
            r = c.execute("PRAGMA quick_check(5)").fetchall()
            c.close()
            return [x[0] for x in r]
        try:
            rows = await asyncio.to_thread(run)
            res = {"result": "ok" if rows == ["ok"] else "; ".join(rows)[:400], "ts": time.time(), "ms": int((time.time() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001
            res = {"result": f"error: {type(e).__name__}: {str(e)[:120]}", "ts": time.time(), "ms": int((time.time() - t0) * 1000)}
        self.state["quick_check"] = res
        self._last_quick = time.time()
        return res

    async def checkpoint(self) -> int:
        """WAL 을 본 파일로 밀어 넣고 잘라낸다(TRUNCATE) — 반환: 남은 WAL 프레임 수"""
        def run():
            r = self.e.store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            return int(r[1]) if r else 0
        async with self.e.store._lock:
            n = await asyncio.to_thread(run)
        self.state["wal_checkpoints"] += 1
        return n

    # ---- 백업 검증
    def _latest_backup(self) -> Path | None:
        d = Path((self.e.cfg.get("backup") or {}).get("dir", "data/backup"))
        files = sorted(d.glob("aiops-*.db"), key=lambda p: p.stat().st_mtime) if d.exists() else []
        return files[-1] if files else None

    async def verify_backup(self, path: Path | None = None) -> dict:
        p = path or self._latest_backup()
        if not p:
            self.state["backup"] = {"file": "", "result": "none"}
            return self.state["backup"]
        key = f"{p.name}:{p.stat().st_size}"
        if key in self._verified and not path:
            return self._verified[key]

        def run():
            c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=10)
            r = c.execute("PRAGMA integrity_check").fetchall()
            n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] if c.execute("SELECT 1 FROM sqlite_master WHERE name='audit'").fetchone() else None
            c.close()
            return [x[0] for x in r], n
        t0 = time.time()
        try:
            rows, n = await asyncio.to_thread(run)
            res = {"file": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime, "result": "ok" if rows == ["ok"] else "; ".join(rows)[:300],
                   "audit_rows": n, "ms": int((time.time() - t0) * 1000), "ts": time.time()}
        except Exception as e:  # noqa: BLE001
            res = {"file": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime, "result": f"error: {type(e).__name__}: {str(e)[:120]}", "ts": time.time()}
        self._verified = {key: res}
        self.state["backup"] = res
        return res

    # ---- 점검(health 가 5초마다 호출) — 가벼운 것만 동기, 무거운 것은 loop 에서
    def checks(self) -> list[dict]:
        out: list[dict] = []
        add = lambda key, level, text: out.append({"key": key, "level": level, "text": text})  # noqa: E731
        for i in self.state["preflight"]:
            add(i["key"], i["level"], i["text"])
        r = self.state["resources"]
        if r.get("rss_mb") and r["rss_mb"] >= self.memory_warn_mb:
            add("memory_high", "warning", f"프로세스 메모리 {r['rss_mb']:.0f}MB — 기준 {self.memory_warn_mb:.0f}MB 초과(수집량·AI 대기열 확인)")
        if r.get("open_files") and r["open_files"] >= self.fd_warn:
            add("open_files", "warning", f"열린 파일·소켓 {r['open_files']}개 — 기준 {self.fd_warn} 초과(연결 누수 의심)")
        if r.get("disk_used_pct") is not None and r["disk_used_pct"] >= 90:
            add("disk_pct", "warning", f"데이터 볼륨 사용률 {r['disk_used_pct']}%")
        qc = self.state["quick_check"]
        if qc["result"] and qc["result"] != "ok":
            add("db_integrity", "critical", f"DB 무결성 점검 실패 — {qc['result'][:160]} (백업에서 복원 검토)")
        db = self.state["db"]
        if self.wal_max_mb > 0 and db.get("wal_mb", 0) >= self.wal_max_mb * 2:
            add("db_wal", "warning", f"WAL 파일 {db['wal_mb']}MB — checkpoint 가 밀림(긴 읽기 트랜잭션·디스크 지연 의심)")
        b = self.state["backup"]
        bc = self.e.cfg.get("backup") or {}
        if bc.get("enabled") and b.get("mtime") and time.time() - b["mtime"] > self.backup_stale_days * 86400:
            add("backup_stale", "warning", f"최근 백업이 {(time.time() - b['mtime']) / 86400:.1f}일 전 — 예약 백업 실패 여부 확인")
        if b.get("result") and b["result"] not in ("ok", "none"):
            add("backup_corrupt", "error", f"최신 백업 {b.get('file')} 무결성 실패 — {b['result'][:120]}")
        c = self.state["cert"]
        if c.get("days_left") is not None and c["days_left"] < 14:
            add("tls_expiry", "error" if c["days_left"] < 0 else "warning", f"TLS 인증서 만료 {'지남' if c['days_left'] < 0 else 'D-' + str(c['days_left'])}")
        self.issues = out
        return out

    async def refresh(self) -> None:
        """무거운 수집(파일 stat·COUNT·백업 열기) — 5분마다"""
        try:
            free = shutil.disk_usage(Path(self.e.store.path).parent)
            pct = round((1 - free.free / free.total) * 100, 1) if free.total else None
        except OSError:
            pct = None
        self.state["resources"] = {"rss_mb": _rss_mb(), "open_files": _open_files(), "disk_used_pct": pct,
                                   "threads": len(asyncio.all_tasks()) if asyncio.get_event_loop().is_running() else 0}
        self.state["db"] = await asyncio.to_thread(self._db_stats)
        tls = (self.e.cfg.get("server") or {}).get("tls") or {}
        self.state["cert"] = {"file": tls.get("certfile", ""), "days_left": cert_days_left(tls.get("certfile", ""))}
        if self.state["db"].get("wal_mb", 0) >= self.wal_max_mb:
            try:
                left = await self.checkpoint()
                print(f"[selfcheck] WAL {self.state['db']['wal_mb']}MB → checkpoint(TRUNCATE), 남은 프레임 {left}", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"[selfcheck] checkpoint 실패: {e}", flush=True)
        if time.time() - self._last_quick >= self.quick_check_hours * 3600:
            r = await self.quick_check()
            print(f"[selfcheck] DB quick_check {r['result']} ({r['ms']}ms)", flush=True)
            await self.e.audit.log("system.db_check", result="ok" if r["result"] == "ok" else "fail", detail={"result": r["result"][:200], "ms": r["ms"]})
        if self.verify_backups:
            await self.verify_backup()
        self.state["checked"] = time.time()

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(20)
        while True:
            beat()
            try:
                await self.refresh()
            except Exception as e:  # noqa: BLE001
                print(f"[selfcheck] 오류: {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(300)

    def snapshot(self) -> dict:
        return {**self.state, "issues": self.issues, "limits": {"wal_max_mb": self.wal_max_mb, "memory_warn_mb": self.memory_warn_mb,
                                                                 "open_files_warn": self.fd_warn, "quick_check_hours": self.quick_check_hours}}
