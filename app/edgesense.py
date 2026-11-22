"""현장 센서(2.50.0) — 안 쓰는 안드로이드 폰을 데이터센터·전산실·지점 장비실의 감시 소스로.

폰 앱(VCF AIops Sensor, 별도 APK)이 주기적으로 측정값을 보낸다.
- 온도: 주변 온도 센서(있는 기종만) 또는 배터리 온도(주변 온도 근사 — 장치별 보정값 offset 적용)
- 습도·기압·조도·근접: 센서가 있는 기종만
- 소리: 마이크 음량(dBFS → 보정값 더해 추정 dB). 소리 자체는 녹음·전송하지 않음
- 진동·움직임: 가속도 변화량(m/s²) — 랙 흔들림·지진·폰 이동
- 위치: GPS·네트워크 위치 → 기준 위치에서 벗어나면 경보(폰 이동·분실)
- 카메라: 정해진 간격 또는 화면의 '지금 촬영' 요청 때 사진 1장(JPEG)
- 배터리·충전·Wi-Fi 신호·기기 발열 상태

흐름: 관리자가 장치를 만들면 1회용 등록 코드(30분) + QR(vcfaiops-sensor://enroll?...) → 폰 앱이 코드를 장치 토큰으로 교환 →
토큰(Bearer)으로 /api/sensor/push(측정값) · /api/sensor/snap(사진). 응답으로 설정(간격·켤 센서·보정값)과 '지금 촬영' 요청을 받는다.
서버는 기준값 판정 → 상태가 바뀔 때만 이벤트(source=sensor) — 일반 이상징후·알림·SIEM 경로. 폰에 명령을 보내 인프라를 바꾸는 일은 없다.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .models import LogEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS sensor_devices(id TEXT PRIMARY KEY, name TEXT, site TEXT, note TEXT, token_hash TEXT,
  enroll_hash TEXT, enroll_until REAL, created REAL, enrolled REAL, last_seen REAL, last_ip TEXT, info TEXT, config TEXT,
  state TEXT, latest TEXT, retired INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sensor_samples(dev TEXT, ts REAL, m TEXT, v REAL);
CREATE INDEX IF NOT EXISTS ix_sensor_samples ON sensor_samples(dev, m, ts);
CREATE TABLE IF NOT EXISTS sensor_snaps(dev TEXT, ts REAL, name TEXT, size INTEGER, reason TEXT);
CREATE INDEX IF NOT EXISTS ix_sensor_snaps ON sensor_snaps(dev, ts);
"""

# 측정값 정의 — 이름, 단위, 표시, 숫자 범위(이 밖은 버림)
METRICS: dict[str, dict] = {
    "temp_c":      {"label": "온도", "unit": "°C", "range": (-40, 90)},
    "ambient_c":   {"label": "주변 온도(센서)", "unit": "°C", "range": (-40, 90)},
    "battery_c":   {"label": "배터리 온도", "unit": "°C", "range": (-40, 90)},
    "humidity":    {"label": "습도", "unit": "%", "range": (0, 100)},
    "pressure":    {"label": "기압", "unit": "hPa", "range": (300, 1200)},
    "light":       {"label": "조도", "unit": "lx", "range": (0, 200000)},
    "sound_db":    {"label": "소리(추정)", "unit": "dB", "range": (0, 140)},
    "sound_peak":  {"label": "소리 최대(추정)", "unit": "dB", "range": (0, 140)},
    "vibration":   {"label": "진동", "unit": "m/s²", "range": (0, 100)},
    "battery_pct": {"label": "배터리", "unit": "%", "range": (0, 100)},
    "charging":    {"label": "충전 중", "unit": "", "range": (0, 1)},
    "wifi_rssi":   {"label": "Wi-Fi 신호", "unit": "dBm", "range": (-120, 0)},
    "thermal":     {"label": "기기 발열 단계", "unit": "", "range": (0, 6)},
    "proximity":   {"label": "근접", "unit": "cm", "range": (0, 100)},
    "lat":         {"label": "위도", "unit": "", "range": (-90, 90)},
    "lon":         {"label": "경도", "unit": "", "range": (-180, 180)},
    "loc_acc":     {"label": "위치 정확도", "unit": "m", "range": (0, 100000)},
    "moved_m":     {"label": "기준 위치에서 거리", "unit": "m", "range": (0, 1e7)},
}
SENSORS = ("temperature", "humidity", "pressure", "light", "sound", "motion", "location", "camera", "battery", "wifi", "proximity")

# 기본 기준값 — 데이터센터 권장 범위(흡기 18~27°C, ASHRAE)를 감안한 보수적 초기값. 장치별로 바꿀 수 있음
DEFAULT_THRESHOLDS: dict[str, dict] = {
    "temp_c":      {"warn_hi": 30, "crit_hi": 35, "warn_lo": 10, "crit_lo": 5},
    "humidity":    {"warn_hi": 70, "crit_hi": 80, "warn_lo": 20, "crit_lo": 10},
    "sound_db":    {"warn_hi": 85, "crit_hi": 95},
    "vibration":   {"warn_hi": 0.8, "crit_hi": 3.0},
    "battery_pct": {"warn_lo": 20, "crit_lo": 10},
    "moved_m":     {"warn_hi": 200, "crit_hi": 1000},
    "thermal":     {"warn_hi": 3, "crit_hi": 5},
}
DEFAULT_CONFIG: dict[str, Any] = {
    "interval_s": 60,                  # 측정·전송 간격
    "sensors": list(SENSORS),          # 켤 센서(폰에 없는 건 무시)
    "snap_interval_m": 0,              # 자동 촬영 간격(분, 0=끔 — 화면의 '지금 촬영'만)
    "camera": "back",                  # back | front
    "snap_quality": 70,                # JPEG 품질
    "sound_window_s": 3,               # 음량 측정 시간(초)
    "sound_offset_db": 90,             # dBFS → 추정 dB 보정(기종마다 다름 — 소음계와 비교해 조정)
    "temp_source": "auto",             # auto(주변 센서 있으면 그것, 없으면 배터리) | ambient | battery
    "temp_offset_c": -3.0,             # 배터리 온도 → 주변 온도 근사 보정(충전 중 발열 감안, 온도계와 비교해 조정)
    "thresholds": DEFAULT_THRESHOLDS,
}
ID_RX = re.compile(r"^[a-z0-9][a-z0-9-]{2,40}$")


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def haversine_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    d = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371000 * 2 * math.asin(min(1.0, math.sqrt(d)))


def level(v: float, th: dict | None) -> str:
    """기준값 판정 → ok | warn | crit"""
    if not th or v is None:
        return "ok"
    if th.get("crit_hi") is not None and v >= th["crit_hi"] or th.get("crit_lo") is not None and v <= th["crit_lo"]:
        return "crit"
    if th.get("warn_hi") is not None and v >= th["warn_hi"] or th.get("warn_lo") is not None and v <= th["warn_lo"]:
        return "warn"
    return "ok"


def clean_samples(raw: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for k, v in (raw or {}).items():
        if k not in METRICS or isinstance(v, bool) and k != "charging":
            continue
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        lo, hi = METRICS[k]["range"]
        if math.isfinite(f) and lo <= f <= hi:
            out[k] = round(f, 6 if k in ("lat", "lon") else 2)
    return out


def merge_config(cfg: dict | None) -> dict:
    c = json.loads(json.dumps(DEFAULT_CONFIG))
    for k, v in (cfg or {}).items():
        if k == "thresholds" and isinstance(v, dict):
            for m, t in v.items():
                if m in METRICS and isinstance(t, dict):
                    c["thresholds"][m] = {kk: float(vv) for kk, vv in t.items()
                                          if kk in ("warn_hi", "crit_hi", "warn_lo", "crit_lo") and vv not in (None, "")}
        elif k in DEFAULT_CONFIG:
            c[k] = v
    c["interval_s"] = max(15, min(3600, int(c["interval_s"])))
    c["snap_interval_m"] = max(0, min(1440, int(c["snap_interval_m"])))
    c["snap_quality"] = max(30, min(95, int(c["snap_quality"])))
    c["sound_window_s"] = max(1, min(10, int(c["sound_window_s"])))
    c["sound_offset_db"] = max(40.0, min(140.0, float(c["sound_offset_db"])))
    c["temp_offset_c"] = max(-20.0, min(20.0, float(c["temp_offset_c"])))
    c["sensors"] = [s for s in c["sensors"] if s in SENSORS]
    c["camera"] = "front" if c.get("camera") == "front" else "back"
    if c.get("temp_source") not in ("auto", "ambient", "battery"):
        c["temp_source"] = "auto"
    return c


class EdgeSense:
    def __init__(self, engine, cfg: dict | None = None, data_dir: str | Path = "data"):
        self.e = engine
        self.cfg = cfg or {}
        self.store = engine.store
        self.store.schema(SCHEMA)
        self.dir = Path(data_dir) / "sensor"
        self.stale = int(self.cfg.get("stale_seconds", 300))
        self.keep_days = int(self.cfg.get("retention_days", 30))
        self.snap_keep = int(self.cfg.get("snaps_per_device", 300))
        self.snap_max = int(self.cfg.get("snap_max_bytes", 3 * 1024 * 1024))
        self.devs: dict[str, dict] = {}
        self.snap_req: dict[str, float] = {}           # 장치 → '지금 촬영' 요청 시각
        self._loaded = False
        self._enroll_fail: dict[str, list[float]] = {}

    # ------------------------------------------------------------------ 적재
    async def load(self) -> None:
        for r in await self.store.q("SELECT * FROM sensor_devices"):
            d = dict(r)
            d["info"] = json.loads(d.get("info") or "{}")
            d["config"] = merge_config(json.loads(d.get("config") or "{}"))
            d["state"] = json.loads(d.get("state") or "{}")
            d["latest"] = json.loads(d.get("latest") or "{}")
            self.devs[d["id"]] = d
        self._loaded = True

    async def _save(self, d: dict) -> None:
        await self.store.x(
            "INSERT INTO sensor_devices(id,name,site,note,token_hash,enroll_hash,enroll_until,created,enrolled,last_seen,last_ip,info,config,state,latest,retired) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, site=excluded.site, note=excluded.note, "
            "token_hash=excluded.token_hash, enroll_hash=excluded.enroll_hash, enroll_until=excluded.enroll_until, enrolled=excluded.enrolled, "
            "last_seen=excluded.last_seen, last_ip=excluded.last_ip, info=excluded.info, config=excluded.config, state=excluded.state, "
            "latest=excluded.latest, retired=excluded.retired",
            (d["id"], d["name"], d.get("site", ""), d.get("note", ""), d.get("token_hash", ""), d.get("enroll_hash", ""),
             d.get("enroll_until", 0), d.get("created", 0), d.get("enrolled", 0), d.get("last_seen", 0), d.get("last_ip", ""),
             json.dumps(d.get("info") or {}, ensure_ascii=False), json.dumps(d.get("config") or {}, ensure_ascii=False),
             json.dumps(d.get("state") or {}, ensure_ascii=False), json.dumps(d.get("latest") or {}, ensure_ascii=False),
             1 if d.get("retired") else 0))

    # ------------------------------------------------------------------ 관리(사람)
    async def create(self, name: str, site: str = "", note: str = "", config: dict | None = None) -> dict:
        if not self._loaded:
            await self.load()
        name = (name or "").strip()[:60]
        if not name:
            raise ValueError("이름 필요")
        base = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:30] or "phone"
        did = base if len(base) >= 3 else f"phone-{base}"
        while did in self.devs:
            did = f"{base[:24]}-{secrets.token_hex(2)}"
        d = {"id": did, "name": name, "site": (site or "").strip()[:60], "note": (note or "").strip()[:200],
             "created": time.time(), "info": {}, "config": merge_config(config), "state": {}, "latest": {}}
        code = await self._new_code(d)
        await self._save(d)
        self.devs[did] = d
        return {"device": self.public(d), "code": code, "expires": d["enroll_until"]}

    async def _new_code(self, d: dict) -> str:
        code = "-".join(secrets.token_hex(2).upper() for _ in range(3))        # 예: 3F1A-09BC-77D2
        d["enroll_hash"], d["enroll_until"] = _h(code.replace("-", "")), time.time() + 1800
        return code

    async def reenroll(self, did: str) -> dict:
        d = self._get(did)
        code = await self._new_code(d)
        d["token_hash"] = ""                                              # 기존 폰 토큰 폐기
        await self._save(d)
        return {"code": code, "expires": d["enroll_until"]}

    async def update(self, did: str, b: dict) -> dict:
        d = self._get(did)
        for k in ("name", "site", "note"):
            if k in b:
                d[k] = str(b[k] or "").strip()[:200 if k == "note" else 60] or d.get(k, "")
        if isinstance(b.get("config"), dict):
            cur = dict(d["config"])
            cur.update({k: v for k, v in b["config"].items() if k != "thresholds"})
            if isinstance(b["config"].get("thresholds"), dict):
                cur["thresholds"] = {**d["config"]["thresholds"], **b["config"]["thresholds"]}
            d["config"] = merge_config(cur)
        if b.get("set_home"):                                              # 기준 위치 = 지금 위치
            la, lo = d["latest"].get("lat"), d["latest"].get("lon")
            if la is None or lo is None:
                raise ValueError("아직 위치 값이 없습니다")
            d["info"]["home"] = [la, lo]
        if b.get("clear_home"):
            d["info"].pop("home", None)
        await self._save(d)
        return self.public(d)

    async def retire(self, did: str) -> None:
        d = self._get(did)
        d["retired"], d["token_hash"], d["enroll_hash"] = True, "", ""
        await self._save(d)
        for a in list(self.e.anomalies.values()):
            if not a.ack and (a.event or {}).get("entity") == f"sensor:{did}":
                await self.e.ack(a.id)

    async def delete(self, did: str) -> None:
        self._get(did)
        await self.store.x("DELETE FROM sensor_devices WHERE id=?", (did,))
        await self.store.x("DELETE FROM sensor_samples WHERE dev=?", (did,))
        await self.store.x("DELETE FROM sensor_snaps WHERE dev=?", (did,))
        for f in (self.dir / did).glob("*.jpg") if (self.dir / did).is_dir() else []:
            f.unlink(missing_ok=True)
        self.devs.pop(did, None)

    def request_snap(self, did: str) -> None:
        self._get(did)
        self.snap_req[did] = time.time()

    def _get(self, did: str) -> dict:
        d = self.devs.get(did)
        if not d:
            raise KeyError(did)
        return d

    # ------------------------------------------------------------------ 폰(장치 토큰)
    def _enroll_rate_ok(self, ip: str) -> bool:
        now = time.time()
        a = [t for t in self._enroll_fail.get(ip, []) if now - t < 600]
        self._enroll_fail[ip] = a
        return len(a) < 10

    async def enroll(self, code: str, info: dict, ip: str) -> dict:
        if not self._loaded:
            await self.load()
        if not self._enroll_rate_ok(ip):
            raise PermissionError("등록 시도가 너무 많습니다. 10분 뒤 다시 시도하세요.")
        hc = _h(re.sub(r"[^0-9A-Fa-f]", "", code or "").upper())
        now = time.time()
        for d in self.devs.values():
            if d.get("enroll_hash") and secrets.compare_digest(d["enroll_hash"], hc) and not d.get("retired"):
                if d.get("enroll_until", 0) < now:
                    break
                token = "sns_" + secrets.token_urlsafe(32)
                d.update(token_hash=_h(token), enroll_hash="", enroll_until=0, enrolled=now, last_ip=ip)
                d["info"].update(self._info(info))
                await self._save(d)
                await self._emit(d, "info", f"현장 센서 등록: {d['name']} — {d['info'].get('model', '기기')} (Android {d['info'].get('android', '?')})",
                                 kind="event")
                return {"device_id": d["id"], "name": d["name"], "token": token, "config": d["config"]}
        self._enroll_fail.setdefault(ip, []).append(now)
        raise PermissionError("등록 코드가 맞지 않거나 만료되었습니다")

    def code_device(self, code: str) -> dict | None:
        """유효한(만료 전) 등록 코드의 장치 — 설치 안내 화면·APK 내려받기용(코드를 쓰지는 않음)"""
        hc = _h(re.sub(r"[^0-9A-Fa-f]", "", code or "").upper())
        now = time.time()
        for d in self.devs.values():
            if d.get("enroll_hash") and secrets.compare_digest(d["enroll_hash"], hc) and d.get("enroll_until", 0) > now and not d.get("retired"):
                return d
        return None

    def auth(self, bearer: str) -> dict | None:
        if not bearer or not bearer.startswith("sns_"):
            return None
        h = _h(bearer)
        for d in self.devs.values():
            if d.get("token_hash") and not d.get("retired") and secrets.compare_digest(d["token_hash"], h):
                return d
        return None

    @staticmethod
    def _info(info: dict) -> dict:
        keep = ("model", "maker", "android", "app", "sensors", "camera", "mic", "gps")
        out = {}
        for k in keep:
            v = (info or {}).get(k)
            if isinstance(v, list):
                out[k] = [str(x)[:40] for x in v[:30]]
            elif v is not None:
                out[k] = str(v)[:60]
        return out

    async def push(self, d: dict, body: dict, ip: str) -> dict:
        now = time.time()
        s = clean_samples(body.get("samples") or {})
        cfg = d["config"]
        # 온도 — 주변 온도 센서 우선(auto), 없으면 배터리 온도 + 보정값
        src, tsrc = cfg.get("temp_source", "auto"), ""
        if "ambient_c" in s and src in ("auto", "ambient"):
            s["temp_c"], tsrc = s["ambient_c"], "ambient"
        elif "battery_c" in s and src in ("auto", "battery"):
            s["temp_c"], tsrc = round(s["battery_c"] + float(cfg.get("temp_offset_c", 0)), 2), "battery"
        home = d["info"].get("home")
        if "lat" in s and "lon" in s:
            if not home and s.get("loc_acc", 999) <= 100:                   # 첫 정확한 위치를 기준으로
                d["info"]["home"] = home = [s["lat"], s["lon"]]
            if home:
                s["moved_m"] = round(haversine_m((home[0], home[1]), (s["lat"], s["lon"])), 1)
                if s.get("loc_acc", 0) > 150 and s["moved_m"] < s["loc_acc"]:   # 부정확한 위치로 이동 오판 방지
                    s["moved_m"] = 0.0
        if body.get("info"):
            d["info"].update(self._info(body["info"]))
        keep = {k: d["latest"][k] for k in ("snap", "snap_ts") if k in (d.get("latest") or {})}
        d["latest"] = {**keep, **s, "ts": now, **({"temp_src": tsrc} if tsrc else {})}
        self._tsrc = tsrc
        d["last_seen"], d["last_ip"] = now, ip
        rows = [(d["id"], now, k, v) for k, v in s.items()]
        if rows:
            await self.store.xm("INSERT INTO sensor_samples(dev,ts,m,v) VALUES(?,?,?,?)", rows)
        await self._judge(d, s)
        if d["state"].get("_offline"):
            d["state"].pop("_offline")
            await self._emit(d, "info", f"현장 센서 복구: {d['name']} — 측정값 수신 재개", kind="health")
            await self._ack(d, "offline")
        await self._save(d)
        snap = False
        if self.snap_req.get(d["id"]):
            snap = True
        elif cfg["snap_interval_m"] and "camera" in cfg["sensors"]:
            last = await self.store.q1("SELECT MAX(ts) t FROM sensor_snaps WHERE dev=?", (d["id"],))
            snap = not last or not last["t"] or now - last["t"] >= cfg["snap_interval_m"] * 60
        return {"ok": True, "config": cfg, "snap": snap, "server_time": now}

    async def snap(self, d: dict, data: bytes, reason: str = "") -> dict:
        if len(data) > self.snap_max:
            raise ValueError("사진이 너무 큽니다")
        if not data.startswith(b"\xff\xd8\xff"):
            raise ValueError("JPEG 가 아닙니다")
        now = time.time()
        p = self.dir / d["id"]
        p.mkdir(parents=True, exist_ok=True)
        name = time.strftime("%Y%m%d-%H%M%S", time.localtime(now)) + f"-{secrets.token_hex(2)}.jpg"
        (p / name).write_bytes(data)
        why = "요청" if self.snap_req.pop(d["id"], None) else (reason[:20] or "주기")
        await self.store.x("INSERT INTO sensor_snaps(dev,ts,name,size,reason) VALUES(?,?,?,?,?)", (d["id"], now, name, len(data), why))
        d["latest"]["snap"] = name
        d["latest"]["snap_ts"] = now
        await self._prune_snaps(d["id"])
        return {"ok": True, "name": name}

    async def _prune_snaps(self, did: str) -> None:
        rows = await self.store.q("SELECT name FROM sensor_snaps WHERE dev=? ORDER BY ts DESC LIMIT -1 OFFSET ?", (did, self.snap_keep))
        for r in rows:
            (self.dir / did / r["name"]).unlink(missing_ok=True)
        if rows:
            await self.store.x("DELETE FROM sensor_snaps WHERE dev=? AND name IN (%s)" % ",".join("?" * len(rows)),
                               (did, *[r["name"] for r in rows]))

    def snap_path(self, did: str, name: str) -> Path | None:
        if did not in self.devs or not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{4}\.jpg", name or ""):
            return None
        p = self.dir / did / name
        return p if p.is_file() else None

    # ------------------------------------------------------------------ 판정·이벤트
    async def _judge(self, d: dict, s: dict) -> None:
        th = d["config"].get("thresholds") or {}
        st = d["state"]
        for m, t in th.items():
            if m not in s:
                continue
            if m == "battery_pct" and s.get("charging"):
                lv = "ok"
            else:
                lv = level(s[m], t)
            prev = st.get(m, "ok")
            if lv == prev:
                continue
            st[m] = lv
            meta = METRICS[m]
            val = f"{s[m]:g}{meta['unit']}"
            label = meta["label"] + ("(배터리 기반 추정)" if m == "temp_c" and getattr(self, "_tsrc", "") == "battery" else "")
            if lv == "ok":
                await self._emit(d, "info", f"현장 센서 정상화: {d['name']} {label} {val}", kind="alarm", metric=m)
                await self._ack(d, m)
            else:
                limit = self._limit_text(t, lv, s[m])
                where = f" — {d['site']}" if d.get("site") else ""
                await self._emit(d, "critical" if lv == "crit" else "warning",
                                 f"현장 센서 {'위험' if lv == 'crit' else '경고'}: {d['name']}{where} {label} {val} ({limit})",
                                 kind="alarm", metric=m, value=s[m])

    @staticmethod
    def _limit_text(t: dict, lv: str, v: float) -> str:
        k = "crit" if lv == "crit" else "warn"
        hi, lo = t.get(f"{k}_hi"), t.get(f"{k}_lo")
        if hi is not None and v >= hi:
            return f"기준 상한 {hi:g}"
        return f"기준 하한 {lo:g}" if lo is not None else "기준 초과"

    async def _emit(self, d: dict, sev: str, msg: str, kind: str = "alarm", **attrs: Any) -> None:
        try:
            self.e.submit(LogEvent(source="sensor", connector="edgesense", message=msg, severity=sev, host=d["name"],
                                   entity=f"sensor:{d['id']}", kind=kind,
                                   attrs={"device": d["id"], "site": d.get("site", ""), "category": "environment", **attrs}))
        except Exception:  # noqa: BLE001
            pass

    async def _ack(self, d: dict, metric: str) -> None:
        for a in list(getattr(self.e, "anomalies", {}).values()):
            ev = a.event or {}
            if not a.ack and ev.get("entity") == f"sensor:{d['id']}" and \
                    ((ev.get("attrs") or {}).get("metric") == metric or (metric == "offline" and ev.get("kind") == "health")):
                await self.e.ack(a.id)

    async def loop(self, beat=lambda: None) -> None:
        if not self._loaded:
            await self.load()
        last_prune = 0.0
        while True:
            await asyncio.sleep(20)
            beat()
            now = time.time()
            for d in list(self.devs.values()):
                if d.get("retired") or not d.get("enrolled"):
                    continue
                stale = max(self.stale, int(d["config"]["interval_s"]) * 4)
                if d.get("last_seen") and now - d["last_seen"] > stale and not d["state"].get("_offline"):
                    d["state"]["_offline"] = True
                    await self._emit(d, "warning", f"현장 센서 무응답: {d['name']} — {int((now - d['last_seen']) // 60)}분 동안 측정값 없음 "
                                     f"(마지막 {time.strftime('%H:%M', time.localtime(d['last_seen']))}, 배터리 "
                                     f"{d['latest'].get('battery_pct', '?')}%)", kind="health")
                    await self._save(d)
            if now - last_prune > 3600:
                last_prune = now
                await self.store.x("DELETE FROM sensor_samples WHERE ts < ?", (now - self.keep_days * 86400,))

    # ------------------------------------------------------------------ 조회
    def public(self, d: dict) -> dict:
        now = time.time()
        if d.get("retired"):
            status = "retired"
        elif not d.get("enrolled"):
            status = "pending"
        elif d["state"].get("_offline") or not d.get("last_seen") or now - d["last_seen"] > max(self.stale, d["config"]["interval_s"] * 4):
            status = "offline"
        elif any(v == "crit" for k, v in d["state"].items() if not k.startswith("_")):
            status = "crit"
        elif any(v == "warn" for k, v in d["state"].items() if not k.startswith("_")):
            status = "warn"
        else:
            status = "ok"
        return {"id": d["id"], "name": d["name"], "site": d.get("site", ""), "note": d.get("note", ""), "status": status,
                "created": d.get("created"), "enrolled": d.get("enrolled") or 0, "last_seen": d.get("last_seen") or 0,
                "last_ip": d.get("last_ip", ""), "info": d.get("info") or {}, "config": d["config"],
                "latest": d.get("latest") or {}, "levels": {k: v for k, v in d["state"].items() if not k.startswith("_")},
                "enroll_pending": bool(d.get("enroll_hash")) and (d.get("enroll_until") or 0) > now,
                "snap_requested": d["id"] in self.snap_req}

    def list(self) -> list[dict]:
        order = {"crit": 0, "offline": 1, "warn": 2, "pending": 3, "ok": 4, "retired": 5}
        return sorted((self.public(d) for d in self.devs.values()), key=lambda x: (order[x["status"]], x["site"], x["name"]))

    async def series(self, did: str, metric: str, hours: float = 24) -> list[list[float]]:
        self._get(did)
        since = time.time() - max(0.25, min(24 * 30, hours)) * 3600
        rows = await self.store.q("SELECT ts, v FROM sensor_samples WHERE dev=? AND m=? AND ts>=? ORDER BY ts", (did, metric, since))
        pts = [[r["ts"], r["v"]] for r in rows]
        if len(pts) > 720:                                                  # 화면용 축약(구간 평균)
            step = len(pts) / 720
            out, i = [], 0.0
            while int(i) < len(pts):
                seg = pts[int(i):int(i + step) or int(i) + 1]
                out.append([seg[-1][0], round(sum(p[1] for p in seg) / len(seg), 3)])
                i += step
            pts = out
        return pts

    async def snaps(self, did: str, limit: int = 60) -> list[dict]:
        self._get(did)
        rows = await self.store.q("SELECT ts, name, size, reason FROM sensor_snaps WHERE dev=? ORDER BY ts DESC LIMIT ?", (did, max(1, min(300, limit))))
        return [dict(r) for r in rows]
