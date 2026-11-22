"""2.50.0 — 현장 센서(안드로이드 폰): 등록·전송·판정·무응답·사진·권한·공개 경로·앱 소스"""
import asyncio
import json
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
H = {"x-requested-with": "aiops"}


class _Ctx:
    """독립 엔진 + 현장 센서 라우터만 올린 앱 — 이벤트는 기록, 이상징후 확인(ack)도 기록"""
    def __init__(self, tmp):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from types import SimpleNamespace as NS
        from app.config import DEFAULTS, _merge
        from app.engine import Engine
        from app.edgesense import EdgeSense
        from app.api_sensor import build_router
        self.e = Engine(_merge(DEFAULTS, {"server": {"db_path": str(tmp / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}}))
        self.events, self.acked = [], []
        self.e.submit = lambda ev: self.events.append(ev) or True

        async def ack(aid):
            self.acked.append(aid)
            self.e.anomalies[aid].ack = True
            return True
        self.e.ack = ack
        self.e.anomalies = {}
        self.NS = NS
        self.S = EdgeSense(self.e, {}, tmp)
        app = FastAPI()

        async def audit(req, action, target="", result="ok", detail=None):
            pass
        app.include_router(build_router(self.e, self.S, lambda r: {"user": "admin", "role": "admin"}, audit, lambda r: "testclient",
                                        lambda r: "http://testserver"))
        self.c = TestClient(app)

    def promote(self):
        """기록된 경고·위험 이벤트를 열린 이상징후처럼 등록(정상화 때 자동 확인 시험용)"""
        for i, ev in enumerate(self.events):
            if ev.severity in ("warning", "critical"):
                self.e.anomalies[f"a{i}"] = self.NS(id=f"a{i}", ack=False, event={"entity": ev.entity, "kind": ev.kind, "attrs": ev.attrs, "message": ev.message})


def _client(tmp):
    return _Ctx(tmp)


def _enroll(c, name="전산실 테스트", site="본점"):
    c = c.c if isinstance(c, _Ctx) else c
    r = c.post("/api/sensors", json={"name": name, "site": site}, headers=H)
    assert r.status_code == 200, r.text
    j = r.json()
    assert re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", j["code"])
    assert j["enroll"]["setup_url"].endswith("/sensor-setup?c=" + j["code"]) and j["enroll"]["uri"].startswith("vcfaiops-sensor://enroll?")
    e = c.post("/api/sensor/enroll", json={"code": j["code"].lower(), "info": {"model": "Pixel 4a", "android": "13", "sensors": ["light"]}}, headers=H)
    assert e.status_code == 200, e.text
    assert c.post("/api/sensor/enroll", json={"code": j["code"]}, headers=H).status_code == 403          # 1회용
    return e.json()


def test_enroll_push_thresholds_and_events(tmp_path):
    x = _client(tmp_path)
    c, ENGINE = x.c, x.e
    ENGINE.sensors = x.S
    if True:
        e = _enroll(c)
        A = {**H, "authorization": "Bearer " + e["token"]}
        did = e["device_id"]
        r = c.post("/api/sensor/push", json={"samples": {"battery_c": 30, "humidity": 50, "lat": 37.5, "lon": 127.0, "loc_acc": 10,
                                                         "bogus": 1, "sound_db": 999}}, headers=A)
        assert r.status_code == 200 and r.json()["config"]["interval_s"] == 60 and r.json()["snap"] is False
        d = ENGINE.sensors.devs[did]
        assert d["latest"]["temp_c"] == 27.0 and d["latest"]["temp_src"] == "battery"      # 배터리 + 보정 -3
        assert "bogus" not in d["latest"] and "sound_db" not in d["latest"]                  # 범위 밖·모르는 값 버림
        assert d["info"]["home"] == [37.5, 127.0]
        c.post("/api/sensor/push", json={"samples": {"ambient_c": 36, "battery_c": 50, "humidity": 85, "lat": 37.52, "lon": 127.0, "loc_acc": 10}}, headers=A)
        lv = c.get("/api/sensors").json()["items"]
        me = next(x for x in lv if x["id"] == did)
        assert me["status"] == "crit" and me["levels"]["temp_c"] == "crit" and me["levels"]["humidity"] == "crit" and me["levels"]["moved_m"] == "crit"
        assert me["latest"]["temp_c"] == 36                                                  # 주변 온도 센서 우선
        msgs = [ev.message for ev in x.events if ev.entity == f"sensor:{did}"]
        assert any("온도 36°C (기준 상한 35)" in m for m in msgs) and any("습도 85% (기준 상한 80)" in m for m in msgs)
        assert any("현장 센서 등록:" in m for m in msgs)
        assert all(ev.source == "sensor" for ev in x.events)
        x.promote()
        # 정상화 → 해당 이상징후 자동 확인
        c.post("/api/sensor/push", json={"samples": {"ambient_c": 22, "humidity": 50, "lat": 37.5, "lon": 127.0, "loc_acc": 10}}, headers=A)
        open_ = [a for a in ENGINE.anomalies.values() if (a.event or {}).get("entity") == f"sensor:{did}" and not a.ack
                 and (a.event.get("attrs") or {}).get("metric") in ("temp_c", "humidity")]
        assert not open_ and x.acked
        assert any(a.event["attrs"].get("metric") == "moved_m" and a.ack for a in ENGINE.anomalies.values())   # 위치도 정상화
        ser = c.get(f"/api/sensors/{did}/series?metric=temp_c&hours=1").json()["points"]
        assert [p[1] for p in ser] == [27.0, 36.0, 22.0]


def test_battery_low_only_when_not_charging_and_bad_token(tmp_path):
    x = _client(tmp_path)
    c, ENGINE = x.c, x.e
    ENGINE.sensors = x.S
    if True:
        e = _enroll(c, "배터리 시험")
        A = {**H, "authorization": "Bearer " + e["token"]}
        c.post("/api/sensor/push", json={"samples": {"battery_pct": 5, "charging": 1}}, headers=A)
        assert ENGINE.sensors.devs[e["device_id"]]["state"].get("battery_pct", "ok") == "ok"
        c.post("/api/sensor/push", json={"samples": {"battery_pct": 5, "charging": 0}}, headers=A)
        assert ENGINE.sensors.devs[e["device_id"]]["state"].get("battery_pct") == "crit"
        assert c.post("/api/sensor/push", json={}, headers={**H, "authorization": "Bearer sns_nope"}).status_code == 401
        assert c.post("/api/sensor/push", json={}, headers=H).status_code == 401


def test_snap_request_flow_and_validation(tmp_path):
    c = _client(tmp_path).c
    if True:
        e = _enroll(c, "카메라 시험")
        A = {**H, "authorization": "Bearer " + e["token"]}
        did = e["device_id"]
        assert c.post(f"/api/sensors/{did}/snap-now", headers=H).json()["ok"]
        assert c.post("/api/sensor/push", json={"samples": {}}, headers=A).json()["snap"] is True
        assert c.post("/api/sensor/snap", content=b"GIF89a", headers={**A, "content-type": "image/jpeg"}).status_code == 400
        assert c.post("/api/sensor/snap", content=b"\xff\xd8\xff" + b"0" * (4 * 1024 * 1024), headers={**A, "content-type": "image/jpeg"}).status_code == 400
        r = c.post("/api/sensor/snap", content=b"\xff\xd8\xff\xe0" + b"1" * 500, headers={**A, "content-type": "image/jpeg"})
        assert r.status_code == 200
        s = c.get(f"/api/sensors/{did}/snaps").json()["items"]
        assert s[0]["reason"] == "요청" and s[0]["size"] == 504
        img = c.get(f"/api/sensors/{did}/snap/{s[0]['name']}")
        assert img.status_code == 200 and img.headers["content-type"] == "image/jpeg"
        assert c.get(f"/api/sensors/{did}/snap/..%2F..%2Fetc%2Fpasswd").status_code == 404
        assert c.post("/api/sensor/push", json={"samples": {}}, headers=A).json()["snap"] is False


def test_config_update_merge_and_limits(tmp_path):
    from app.edgesense import merge_config
    c = merge_config({"interval_s": 1, "snap_quality": 500, "sensors": ["camera", "evil"], "camera": "x",
                      "thresholds": {"temp_c": {"warn_hi": "28", "crit_hi": ""}, "nope": {"warn_hi": 1}}})
    assert c["interval_s"] == 15 and c["snap_quality"] == 95 and c["sensors"] == ["camera"] and c["camera"] == "back"
    assert c["thresholds"]["temp_c"] == {"warn_hi": 28.0} and "nope" not in c["thresholds"]
    cl = _client(tmp_path).c
    if True:
        e = _enroll(cl, "설정 시험")
        did = e["device_id"]
        r = cl.put(f"/api/sensors/{did}", json={"config": {"interval_s": 120, "thresholds": {"sound_db": {"warn_hi": 70}}}}, headers=H).json()
        assert r["config"]["interval_s"] == 120 and r["config"]["thresholds"]["sound_db"] == {"warn_hi": 70.0}
        assert r["config"]["thresholds"]["temp_c"]["crit_hi"] == 35                  # 다른 기준값은 유지
        A = {**H, "authorization": "Bearer " + e["token"]}
        assert cl.post("/api/sensor/push", json={"samples": {}}, headers=A).json()["config"]["interval_s"] == 120
        assert cl.put(f"/api/sensors/{did}", json={"set_home": True}, headers=H).status_code == 400   # 위치 없음


def test_offline_detection_and_recovery(tmp_path):
    x = _client(tmp_path)
    S, c = x.S, x.c
    if True:
        e = _enroll(c, "무응답 시험")
        A = {**H, "authorization": "Bearer " + e["token"]}
        c.post("/api/sensor/push", json={"samples": {"battery_pct": 80}}, headers=A)
        d = S.devs[e["device_id"]]
        d["last_seen"] = time.time() - 3600

        async def one():
            S.stale = 300
            t = asyncio.create_task(S.loop())
            await asyncio.sleep(21)
            t.cancel()
        asyncio.run(one())
        assert d["state"].get("_offline") and S.public(d)["status"] == "offline"
        c.post("/api/sensor/push", json={"samples": {"battery_pct": 80}}, headers=A)
        assert not d["state"].get("_offline")
        assert [ev.message.split(":")[0] for ev in x.events][-2:] == ["현장 센서 무응답", "현장 센서 복구"]


def test_reenroll_revokes_token_and_retire(tmp_path):
    c = _client(tmp_path).c
    if True:
        e = _enroll(c, "재등록 시험")
        A = {**H, "authorization": "Bearer " + e["token"]}
        did = e["device_id"]
        r = c.post(f"/api/sensors/{did}/reenroll", headers=H).json()
        assert c.post("/api/sensor/push", json={}, headers=A).status_code == 401
        e2 = c.post("/api/sensor/enroll", json={"code": r["code"]}, headers=H).json()
        A2 = {**H, "authorization": "Bearer " + e2["token"]}
        assert c.post("/api/sensor/push", json={}, headers=A2).status_code == 200
        c.post(f"/api/sensors/{did}/retire", headers=H)
        assert c.post("/api/sensor/push", json={}, headers=A2).status_code == 401
        assert c.delete(f"/api/sensors/{did}", headers=H).json()["ok"]


def test_enroll_rate_limit(tmp_path):
    x = _client(tmp_path)
    j = x.c.post("/api/sensors", json={"name": "대입 시험"}, headers=H).json()
    codes = [x.c.post("/api/sensor/enroll", json={"code": "0000-0000-0000"}, headers=H).status_code for _ in range(10)]
    assert codes == [403] * 10
    r = x.c.post("/api/sensor/enroll", json={"code": j["code"]}, headers=H)                 # 맞는 코드도 막힘(대입 차단)
    assert r.status_code == 403 and "너무 많습니다" in r.json()["detail"]


def test_setup_page_and_apk_need_valid_code(tmp_path):
    c = _client(tmp_path).c
    if True:
        j = c.post("/api/sensors", json={"name": "설치 시험"}, headers=H).json()
        assert c.get("/sensor-setup?c=" + j["code"]).status_code == 200
        assert "앱에서 등록하기" in c.get("/sensor-setup?c=" + j["code"]).text
        assert c.get("/sensor-setup?c=1111-2222-3333").status_code == 404 and c.get("/sensor-setup").status_code == 404
        assert c.get("/api/sensor/app.apk").status_code == 404
        r = c.get("/api/sensor/app.apk?c=" + j["code"])
        assert r.status_code == 200 and r.content[:2] == b"PK"


def test_auth_rules_and_public():
    from app.security.auth import PUBLIC
    for p in ("/api/sensor/enroll", "/api/sensor/push", "/api/sensor/snap", "/api/sensor/app.apk", "/sensor-setup"):
        assert PUBLIC.match(p)
    assert not PUBLIC.match("/api/sensors") and not PUBLIC.match("/api/sensors/x/snap/a.jpg")
    src = (ROOT / "app/security/auth.py").read_text(encoding="utf-8")
    assert '("POST", r"^/api/sensors/[a-z0-9-]+/snap-now$", "operate")' in src and '("POST", r"^/api/sensors", "settings")' in src
    assert src.index("snap-now$") < src.index('("POST", r"^/api/sensors", "settings")')            # 먼저 맞는 규칙이 이김


def test_detector_rules():
    from app.detect import DEFAULT_RULES
    by = {r.name: r for r in DEFAULT_RULES}
    assert by["sensor_crit"].pattern.search("현장 센서 위험: 폰 온도 40°C") and by["sensor_crit"].sources == ("sensor",)
    assert by["sensor_silent"].pattern.search("현장 센서 무응답: 폰 — 10분")


def test_android_sensor_app_sources():
    m = (ROOT / "mobile/sensor/AndroidManifest.xml").read_text(encoding="utf-8")
    for p in ("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "FOREGROUND_SERVICE_CAMERA", "FOREGROUND_SERVICE_MICROPHONE", "FOREGROUND_SERVICE_LOCATION"):
        assert f"android.permission.{p}" in m
    assert 'android:scheme="vcfaiops-sensor"' in m and 'package="com.krvcf.aiopssensor"' in m
    src = ROOT / "mobile/sensor/src/com/krvcf/aiopssensor"
    sm = (src / "SoundMeter.java").read_text(encoding="utf-8")
    assert "Net." not in sm and "FileOutputStream" not in sm                                     # 소리는 크기만 — 저장·전송 안 함
    svc = (src / "SensorService.java").read_text(encoding="utf-8")
    assert '"/api/sensor/push"' in svc and '"/api/sensor/snap"' in svc and "FOREGROUND_SERVICE_TYPE_CAMERA" in svc
    assert "setToken" in (src / "MainActivity.java").read_text(encoding="utf-8")
    pr = (src / "Prefs.java").read_text(encoding="utf-8")
    assert "Vault.enc" in pr and 'put(c, "token"' not in pr                                    # 토큰 평문 저장 없음


def test_sensor_apk_built_for_this_version():
    info = json.loads((ROOT / "app/static/app/sensor.json").read_text())
    ver = (ROOT / "VERSION").read_text().strip()
    assert info["name"] == ver and info["package"] == "com.krvcf.aiopssensor"
    apk = ROOT / "app/static/app/vcf-aiops-sensor.apk"
    import hashlib
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == info["sha256"]
    main = json.loads((ROOT / "app/static/app/app.json").read_text())
    assert main["cert_sha256"] == info["cert_sha256"]                                           # 같은 서명 키


def test_ui_wired():
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="nav-sns"' in html and 'id="drawer-sns"' in html and "/static/sensors.js" in html
    assert '"sns"' in (ROOT / "app/static/navgroup.js").read_text(encoding="utf-8")
