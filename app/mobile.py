"""모바일 앱(2.30.0) — 안드로이드 앱 배포·기기 연결·알림 피드.

  앱은 포털 화면을 WebView 로 그대로 보여 주고, 백그라운드에서 15분마다 알림 피드를 확인한다(외부 푸시 서비스 없이 폐쇄망에서도 동작).
  알림 종류: update(서버 패키지가 새 버전으로 패치됨) · alert(이상 징후) · dr(DR·백업) · perf(성능 감시) · system(시스템 알림) · test

  GET    /api/mobile/info            (세션, view)     앱 파일 정보·내 기기·설정
  POST   /api/mobile/pair/start      (세션, view)     일회용 연결 코드(10분) + QR(vcfaiops://connect?url=…&code=…)
  POST   /api/mobile/pair            (공개, 코드 인증) 코드 → 기기 토큰(원문은 이때 1회만, DB 에는 SHA-256)
  GET    /api/mobile/feed            (공개, 기기 토큰) 새 알림·서버 버전·앱 새 버전
  GET    /api/mobile/app.apk         (세션 또는 기기 토큰) 패치에 들어 있는 APK
  PUT    /api/mobile/devices/{id}    (세션, 본인·관리자) 받을 알림 종류·최소 심각도
  DELETE /api/mobile/devices/{id}    (세션, 본인·관리자) 기기 지우기(토큰 폐기)
  POST   /api/mobile/test            (세션, view)     내 기기로 시험 알림
  PUT    /api/mobile/settings        (세션, settings) 사용 여부·확인 주기·기본 종류·Access 없이 허용

  기기 토큰은 알림 피드와 APK 받기에만 쓰인다(포털 API 권한 없음). 알림 본문은 제목·대상 한 줄만 담는다.
  기기를 연결한 사용자가 비활성·삭제되면 그 기기의 토큰은 거부된다.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from collections import deque
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS mobile_devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, name TEXT, os TEXT, app_code INTEGER DEFAULT 0, token_hash TEXT UNIQUE NOT NULL,
  created REAL, last_seen REAL DEFAULT 0, last_ip TEXT DEFAULT '', prefs TEXT DEFAULT '{}', revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS mobile_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, sev TEXT DEFAULT 'info', title TEXT, body TEXT, view TEXT DEFAULT '',
  user TEXT DEFAULT '', dkey TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS mobile_events_dkey ON mobile_events(dkey, ts);
"""
KINDS = {"update": "서버 업데이트", "alert": "이상 징후", "dr": "DR·백업", "perf": "성능 감시", "system": "시스템 알림"}
SEV = {"info": 0, "warning": 1, "error": 2, "critical": 3}
DEFAULTS = {"enabled": True, "poll_minutes": 15, "kinds": ["update", "alert", "dr"], "min_sev": "critical", "allow_without_access": False,
            "max_devices_per_user": 5}
STATIC_APP = Path(__file__).parent / "static" / "app"
ROOT = Path(__file__).resolve().parent.parent
PUBLIC_PATHS = ("/api/mobile/pair", "/api/mobile/feed", "/api/mobile/app.apk")          # 인증 미들웨어 통과 — 각 라우트가 코드·기기 토큰으로 확인


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def app_meta() -> dict[str, Any] | None:
    """패치에 들어 있는 APK 정보(app.json). 파일이 없거나 해시가 다르면 None — 앱 배포 화면에 '앱 파일 없음'"""
    try:
        m = json.loads((STATIC_APP / "app.json").read_text(encoding="utf-8"))
        apk = STATIC_APP / "vcf-aiops.apk"
        if not apk.is_file() or apk.stat().st_size != int(m.get("size", -1)):
            return None
        return {k: m.get(k) for k in ("package", "name", "code", "size", "sha256", "cert_sha256", "min_android", "built")}
    except (OSError, ValueError, TypeError):
        return None


def release_notes(version: str, limit: int = 6) -> list[str]:
    """CHANGELOG.md 의 '## <버전>' 절에서 굵게 쓴 항목 이름을 뽑아 알림 본문으로(없으면 빈 목록)"""
    try:
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    except OSError:
        return []
    m = re.search(r"^## " + re.escape(version) + r"\b([^\n]*)\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not m:
        return []
    head = m.group(1).strip(" —-")
    items = [re.sub(r"\s+", " ", x).strip() for x in re.findall(r"^\|\s*\*\*(.+?)\*\*\s*\|", m.group(2), re.M)]
    out = ([head] if head else []) + [i for i in items if i and i != "항목"]
    return out[:limit]


class Mobile:
    def __init__(self, engine, auth, cfg: dict | None = None):
        self.e = engine
        self.auth = auth
        self.store = engine.store
        self.cfg = {**DEFAULTS, **{k: v for k, v in (cfg or {}).items() if k in DEFAULTS}}
        self.codes: dict[str, dict] = {}                 # 일회용 연결 코드(메모리, 10분)
        self._pair_hits: dict[str, deque] = {}           # IP 별 연결 시도(무차별 대입 방지)
        self._feed_hits: dict[str, deque] = {}
        self._ready = False
        self._last_prune = 0.0
        self._recent: dict[str, float] = {}
        self._wake = asyncio.Event()                     # 새 알림이 기록되면 켜짐 — 실시간 연결(long-poll)을 깨운다
        self.waiters = 0
        self.stats = {"feeds": 0, "pairs": 0, "denied": 0, "events": 0}

    # ------------------------------------------------------------------ 준비·설정
    async def ensure(self) -> None:
        if self._ready:
            return
        for stmt in [s for s in SCHEMA.split(";") if s.strip()]:
            await self.store.x(stmt)
        await self.store.x("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT, updated REAL, updated_by TEXT)")   # settings_store 와 같은 정의
        r = await self.store.q1("SELECT value FROM settings WHERE key='mobile'")
        if r and r.get("value"):
            try:
                self.cfg.update({k: v for k, v in json.loads(r["value"]).items() if k in DEFAULTS})
            except ValueError:
                pass
        self._ready = True

    def settings(self) -> dict[str, Any]:
        return dict(self.cfg)

    async def save_settings(self, body: dict, user: str) -> dict[str, Any]:
        cur = dict(self.cfg)
        for k, v in (body or {}).items():
            if k not in DEFAULTS:
                continue
            if k in ("enabled", "allow_without_access"):
                v = bool(v)
            elif k == "poll_minutes":
                v = int(v)
                if not 15 <= v <= 720:
                    raise ValueError("확인 주기는 15~720분(안드로이드 최소 주기 15분)")
            elif k == "max_devices_per_user":
                v = int(v)
                if not 1 <= v <= 20:
                    raise ValueError("사용자당 기기는 1~20대")
            elif k == "kinds":
                v = [x for x in (v or []) if x in KINDS]
            elif k == "min_sev":
                if v not in SEV:
                    raise ValueError("최소 심각도 값 오류")
            cur[k] = v
        self.cfg = cur
        await self.store.x("INSERT INTO settings(key,value,updated,updated_by) VALUES('mobile',?,?,?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
                           (json.dumps(cur), time.time(), user))
        return cur

    # ------------------------------------------------------------------ 알림 만들기
    async def emit(self, kind: str, title: str, body: str = "", sev: str = "info", view: str = "", user: str = "", dkey: str = "",
                   dedup: float = 900.0) -> int | None:
        """알림 기록. dkey 가 같으면 dedup 초 안의 반복은 건너뜀(같은 문제가 계속 울리지 않게)"""
        now = time.time()
        if dkey:                                        # 같은 순간에 겹쳐 들어온 같은 알림(동시 태스크)은 메모리에서 먼저 거른다
            if now - self._recent.get(dkey, 0) < min(dedup, 60.0):
                return None
            self._recent[dkey] = now
            if len(self._recent) > 2000:
                for k in [k for k, t in self._recent.items() if now - t > 60][:1500] or list(self._recent)[:1000]:
                    self._recent.pop(k, None)
        await self.ensure()
        if dkey:
            r = await self.store.q1("SELECT id FROM mobile_events WHERE dkey=? AND ts>? LIMIT 1", (dkey, now - dedup))
            if r:
                return None
        await self.store.x("INSERT INTO mobile_events(ts,kind,sev,title,body,view,user,dkey) VALUES(?,?,?,?,?,?,?,?)",
                           (now, kind, sev if sev in SEV else "info", title[:160], body[:600], view[:40], user, dkey[:200]))
        self.stats["events"] += 1
        w, self._wake = self._wake, asyncio.Event()
        w.set()
        if now - self._last_prune > 3600:
            self._last_prune = now
            await self.store.x("DELETE FROM mobile_events WHERE ts < ? OR id <= (SELECT MAX(id) FROM mobile_events) - 2000", (now - 30 * 86400,))
        r = await self.store.q1("SELECT MAX(id) AS m FROM mobile_events")
        return int(r["m"]) if r and r.get("m") else None

    def on_anomaly(self, a: dict) -> None:
        """알림 발송(alerter.fire) 훅 — 동기 호출이라 기록은 태스크로"""
        if not self.cfg["enabled"]:
            return
        ev = a.get("event") or {}
        ent = str(ev.get("entity") or "")
        kind = "dr" if ent.startswith("backup:") or ev.get("source") == "srm" else "perf" if ent.startswith("perf:") or ev.get("connector") == "perfmon" else "alert"
        tgt = ev.get("host") or ent or ev.get("connector") or ""
        view = {"dr": "dr", "perf": "pf"}.get(kind, "inc")
        asyncio.ensure_future(self._safe(self.emit(kind, f"[{str(a.get('severity', '')).upper()}] {a.get('title', '')}",
                                                   f"대상: {tgt}" if tgt else "", str(a.get("severity") or "info"), view,
                                                   dkey=f"a:{a.get('fp') or a.get('id')}")))

    def on_text(self, title: str, severity: str) -> None:
        if self.cfg["enabled"]:
            asyncio.ensure_future(self._safe(self.emit("system", title, "", severity, "", dkey=f"s:{title[:80]}")))

    @staticmethod
    async def _safe(coro) -> None:
        try:
            await coro
        except Exception as e:  # noqa: BLE001  — 알림 기록 실패가 탐지·발송을 막지 않게
            print(f"[mobile] 알림 기록 오류: {type(e).__name__}: {e}", flush=True)

    async def check_version(self, current: str) -> str | None:
        """기동 때: 서버 버전이 바뀌었으면 update 알림. 반환 = 이전 버전(바뀐 경우)"""
        await self.ensure()
        r = await self.store.q1("SELECT value FROM settings WHERE key='mobile_last_version'")
        prev = (r or {}).get("value") or ""
        if prev == current or current in ("", "unknown"):
            return None
        await self.store.x("INSERT INTO settings(key,value,updated,updated_by) VALUES('mobile_last_version',?,?,'system') "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated", (current, time.time()))
        if not prev:                                   # 첫 기동(이 기능이 처음 들어온 패치 포함) — 기준만 기록
            r2 = await self.store.q1("SELECT COUNT(*) AS n FROM mobile_devices")
            if not (r2 or {}).get("n"):
                return None
        notes = release_notes(current)
        await self.emit("update", f"서버가 {current} 로 업데이트되었습니다", (f"이전 {prev} → {current}\n" if prev else "") + "\n".join(f"· {n}" for n in notes),
                        "info", "sys", dkey=f"u:{current}", dedup=30 * 86400)
        return prev or None

    # ------------------------------------------------------------------ 기기 연결
    def _limited(self, table: dict[str, deque], ip: str, n: int, per: float) -> bool:
        now = time.time()
        q = table.setdefault(ip, deque())
        while q and q[0] < now - per:
            q.popleft()
        if len(table) > 5000:                           # 메모리 상한
            for k in list(table)[:2500]:
                table.pop(k, None)
        if len(q) >= n:
            return True
        q.append(now)
        return False

    async def pair_start(self, user: dict, origin: str) -> dict[str, Any]:
        await self.ensure()
        if not self.cfg["enabled"]:
            raise PermissionError("모바일 앱 사용이 꺼져 있습니다(관리자: 모바일 앱 › 설정)")
        now = time.time()
        for k in [k for k, v in self.codes.items() if v["exp"] < now]:
            self.codes.pop(k, None)
        mine = [k for k, v in self.codes.items() if v["user"] == user["user"]]
        for k in mine[:-2]:                             # 사용자당 미사용 코드 3개까지
            self.codes.pop(k, None)
        code = secrets.token_urlsafe(24)
        self.codes[_hash(code)] = {"user": user["user"], "exp": now + 600}
        from urllib.parse import quote
        link = f"vcfaiops://connect?url={quote(origin, safe='')}&code={code}"
        svg = ""
        try:
            import io
            import segno
            buf = io.BytesIO()
            segno.make(link, error="m").save(buf, kind="svg", scale=4, border=2, xmldecl=False, svgns=True, nl=False, omitsize=True)
            svg = buf.getvalue().decode()
        except Exception:  # noqa: BLE001
            svg = ""
        return {"code": code, "link": link, "qr_svg": svg, "expires": now + 600}

    @staticmethod
    def install_qr(origin: str) -> dict[str, Any]:
        """폰에서 이 포털의 '모바일 앱' 화면을 여는 QR(로그인 후 APK 내려받기) — 비밀 값 없음"""
        link = f"{origin}/#go=mobile"
        try:
            import io
            import segno
            buf = io.BytesIO()
            segno.make(link, error="m").save(buf, kind="svg", scale=4, border=2, xmldecl=False, svgns=True, nl=False, omitsize=True)
            return {"link": link, "qr_svg": buf.getvalue().decode()}
        except Exception:  # noqa: BLE001
            return {"link": link, "qr_svg": ""}

    async def pair(self, body: dict, ip: str, auth_enabled: bool = True) -> dict[str, Any]:
        await self.ensure()
        if self._limited(self._pair_hits, ip, 10, 600):
            raise PermissionError("시도가 너무 잦습니다 — 10분 뒤 다시 시도하세요")
        c = self.codes.pop(_hash(str(body.get("code") or "")), None)
        if not c or c["exp"] < time.time() or not self.cfg["enabled"]:
            self.stats["denied"] += 1
            raise PermissionError("연결 코드가 틀렸거나 만료되었습니다 — 포털에서 다시 만드세요")
        if auth_enabled and not await self._user_ok(c["user"]):
            raise PermissionError("사용할 수 없는 계정입니다")
        n = await self.store.q1("SELECT COUNT(*) AS n FROM mobile_devices WHERE user=? AND revoked=0", (c["user"],))
        if (n or {}).get("n", 0) >= int(self.cfg["max_devices_per_user"]):
            raise PermissionError(f"기기는 사용자당 {self.cfg['max_devices_per_user']}대까지 — 안 쓰는 기기를 지우세요")
        raw = "aiopsm_" + secrets.token_urlsafe(32)
        prefs = {"kinds": list(self.cfg["kinds"]), "min_sev": self.cfg["min_sev"]}
        await self.store.x("INSERT INTO mobile_devices(user,name,os,app_code,token_hash,created,last_seen,last_ip,prefs) VALUES(?,?,?,?,?,?,?,?,?)",
                           (c["user"], str(body.get("name") or "Android")[:60], str(body.get("os") or "")[:30], int(body.get("app") or 0),
                            _hash(raw), time.time(), time.time(), ip, json.dumps(prefs)))
        d = await self.store.q1("SELECT id FROM mobile_devices WHERE token_hash=?", (_hash(raw),))
        cur = await self.store.q1("SELECT MAX(id) AS m FROM mobile_events")
        self.stats["pairs"] += 1
        return {"token": raw, "device_id": d["id"], "user": c["user"], "cursor": int((cur or {}).get("m") or 0)}

    async def _user_ok(self, username: str) -> bool:
        u = await self.store.q1("SELECT disabled FROM users WHERE username=?", (username,))
        return bool(u) and not u.get("disabled")

    async def device_by_token(self, raw: str, auth_enabled: bool = True) -> dict | None:
        if not raw.startswith("aiopsm_"):
            return None
        await self.ensure()
        d = await self.store.q1("SELECT * FROM mobile_devices WHERE token_hash=? AND revoked=0", (_hash(raw),))
        if not d or not self.cfg["enabled"] or (auth_enabled and not await self._user_ok(d["user"])):
            return None
        return d

    # ------------------------------------------------------------------ 피드
    MAX_WAIT, MAX_WAITERS = 55, 300

    async def feed_wait(self, d: dict, since: int, app_code: int, ip: str, version: str, wait: int = 0) -> dict[str, Any]:
        """실시간 연결 — 줄 알림이 없으면 새 알림이 기록될 때까지 최대 wait 초 기다렸다 답한다(없으면 빈 응답).
        동시에 기다리는 연결이 너무 많으면 기다리지 않고 바로 답한다(앱은 주기 확인으로 돌아감)."""
        r = await self.feed(d, since, app_code, ip, version)
        wait = max(0, min(int(wait or 0), self.MAX_WAIT))
        if r["events"] or not wait or r["cursor"] < since or self.waiters >= self.MAX_WAITERS:
            return r | {"live": bool(wait) and self.waiters < self.MAX_WAITERS}
        end = time.time() + wait
        self.waiters += 1
        try:
            while True:
                left = end - time.time()
                if left <= 0:
                    return r | {"live": True}
                ev = self._wake
                try:
                    await asyncio.wait_for(ev.wait(), left)
                except asyncio.TimeoutError:
                    return r | {"live": True}
                if not await self.device_by_token_id(d["id"]):      # 기다리는 사이 연결 해제·사용 중지
                    raise PermissionError("기기 연결이 해제되었습니다")
                r = await self.feed(d, r["cursor"], app_code, ip, version)
                if r["events"]:
                    return r | {"live": True}
        finally:
            self.waiters -= 1

    async def device_by_token_id(self, did: int) -> bool:
        return bool(self.cfg["enabled"] and await self.store.q1("SELECT id FROM mobile_devices WHERE id=? AND revoked=0", (did,)))

    async def recent(self, user: dict, limit: int = 30) -> list[dict]:
        """포털 화면의 알림함 — 최근 7일, 남의 시험 알림 제외(기기별 종류·심각도 거르기는 하지 않음)"""
        await self.ensure()
        rows = await self.store.q("SELECT id,ts,kind,sev,title,body,view,user FROM mobile_events WHERE ts>? ORDER BY id DESC LIMIT ?",
                                  (time.time() - 7 * 86400, max(1, min(limit, 100)) * 2))
        return [{k: r[k] for k in ("id", "ts", "kind", "sev", "title", "body", "view")} for r in rows
                if r["kind"] != "page" and (r["kind"] != "test" or r["user"] == user["user"])][:limit]

    async def feed(self, d: dict, since: int, app_code: int, ip: str, version: str) -> dict[str, Any]:
        self.stats["feeds"] += 1
        try:
            prefs = json.loads(d.get("prefs") or "{}")
        except ValueError:
            prefs = {}
        kinds = set(prefs.get("kinds") or self.cfg["kinds"])
        floor = SEV.get(prefs.get("min_sev") or self.cfg["min_sev"], 3)
        rows = await self.store.q("SELECT id,ts,kind,sev,title,body,view,user FROM mobile_events WHERE id>? AND ts>? ORDER BY id LIMIT 200",
                                  (max(0, since), time.time() - 3 * 86400))
        cur = since
        out = []
        for r in rows:
            cur = max(cur, r["id"])
            if r["kind"] == "page":                                     # 회수한 2.32.0 을 적용했던 설치본에 남은 호출(page) 기록 — 내보내지 않음
                continue
            if r["kind"] == "test":
                if r["user"] != d["user"]:
                    continue
            elif r["kind"] not in kinds or (r["kind"] != "update" and SEV.get(r["sev"], 0) < floor):
                continue
            out.append({k: r[k] for k in ("id", "ts", "kind", "sev", "title", "body", "view")})
        if not rows and since > 0:
            m = await self.store.q1("SELECT MAX(id) AS m FROM mobile_events")
            cur = min(since, int((m or {}).get("m") or 0))          # DB 를 새로 만들어 커서가 앞서 있으면 지금 끝으로 맞춤(이후 알림을 놓치지 않게)
        await self.store.x("UPDATE mobile_devices SET last_seen=?, last_ip=?, app_code=? WHERE id=?", (time.time(), ip, int(app_code or 0), d["id"]))
        meta = app_meta()
        return {"server": {"version": version}, "events": out[-20:], "cursor": cur, "poll": int(self.cfg["poll_minutes"]) * 60,
                "app": {k: meta[k] for k in ("name", "code", "sha256", "size")} if meta else None}

    # ------------------------------------------------------------------ 기기 관리
    async def devices(self, user: dict, all_users: bool) -> list[dict]:
        await self.ensure()
        rows = await self.store.q("SELECT id,user,name,os,app_code,created,last_seen,last_ip,prefs FROM mobile_devices WHERE revoked=0"
                                  + ("" if all_users else " AND user=?") + " ORDER BY id DESC", () if all_users else (user["user"],))
        for r in rows:
            try:
                r["prefs"] = json.loads(r.get("prefs") or "{}")
            except ValueError:
                r["prefs"] = {}
            r["mine"] = r["user"] == user["user"]
        return rows

    async def _own(self, did: int, user: dict, admin: bool) -> dict:
        d = await self.store.q1("SELECT * FROM mobile_devices WHERE id=? AND revoked=0", (did,))
        if not d or (d["user"] != user["user"] and not admin):
            raise LookupError("기기를 찾을 수 없습니다")
        return d

    async def update_device(self, did: int, body: dict, user: dict, admin: bool) -> dict:
        d = await self._own(did, user, admin)
        try:
            prefs = json.loads(d.get("prefs") or "{}")
        except ValueError:
            prefs = {}
        if "kinds" in body:
            prefs["kinds"] = [k for k in (body["kinds"] or []) if k in KINDS]
        if "min_sev" in body:
            if body["min_sev"] not in SEV:
                raise ValueError("최소 심각도 값 오류")
            prefs["min_sev"] = body["min_sev"]
        name = str(body.get("name") or d["name"] or "")[:60]
        await self.store.x("UPDATE mobile_devices SET prefs=?, name=? WHERE id=?", (json.dumps(prefs), name, did))
        return {"id": did, "prefs": prefs, "name": name}

    async def revoke(self, did: int, user: dict, admin: bool) -> None:
        await self._own(did, user, admin)
        await self.store.x("UPDATE mobile_devices SET revoked=1 WHERE id=?", (did,))

    async def revoke_user(self, username: str) -> None:
        await self.ensure()
        await self.store.x("UPDATE mobile_devices SET revoked=1 WHERE user=?", (username,))
