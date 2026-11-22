"""2.54.0 — 현장 센서: 평소와 다름(학습 기준선)·보정 도우미·작업 모드(유지보수 창)·여러 대 한 번에·주간 환경 요약"""
import asyncio
import time

from test_v2500_sensor import H, _client, _enroll


def _auth(e):
    return {**H, "authorization": "Bearer " + e["token"]}


def _seed(x, did, metric, value, days=5, step=600, jitter=0.3):
    now = time.time()
    rows, i = [], 0
    t = now - days * 86400
    while t < now - 60:
        rows.append((did, t, metric, value + (jitter if i % 2 else -jitter)))
        t += step
        i += 1
    asyncio.run(x.S.store.xm("INSERT INTO sensor_samples(dev,ts,m,v) VALUES(?,?,?,?)", rows))


def test_baseline_unusual_and_recover(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did, A = e["device_id"], _auth(e)
    _seed(x, did, "temp_c", 22.0)
    b = x.c.post(f"/api/sensors/{did}/baseline/rebuild", headers=H).json()
    assert b["days"] >= 5 and b["metrics"]["temp_c"] == 24
    bl = x.c.get(f"/api/sensors/{did}/baseline?metric=temp_c", headers=H).json()
    med, sp = bl["hours"][str(time.localtime().tm_hour)]
    assert abs(med - 22) < 0.5 and sp == 0.7                                       # 최소 폭(센서 잡음보다 작은 차이로 울리지 않게)
    for _ in range(2):
        x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 26.5}}, headers=A)
    assert not any("평소와 다름" in v.message for v in x.events)                   # 연속 3번부터
    x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 26.5}}, headers=A)
    ev = [v for v in x.events if "평소와 다름" in v.message]
    assert len(ev) == 1 and ev[0].message.startswith("현장 센서 경고:") and ev[0].attrs["metric"] == "base_temp_c"
    assert x.S.devs[did]["state"]["base_temp_c"] == "warn" and x.c.get("/api/sensors", headers=H).json()["items"][0]["status"] == "warn"
    x.promote()
    for _ in range(3):
        x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 22.1}}, headers=A)
    assert x.S.devs[did]["state"]["base_temp_c"] == "ok" and x.acked                     # 정상화 → 확인 처리
    # 기준값 경보(30°C)가 이미 울리면 '평소와 다름'은 겹쳐 울리지 않음
    n = len([v for v in x.events if "평소와 다름" in v.message])
    for _ in range(4):
        x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 31}}, headers=A)
    assert len([v for v in x.events if "평소와 다름" in v.message]) == n
    # 끄면 정리
    x.c.put(f"/api/sensors/{did}", json={"config": {"baseline": False, "baseline_k": 99}}, headers=H)
    assert x.S.devs[did]["config"]["baseline_k"] == 10.0


def test_baseline_needs_enough_days(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    _seed(x, e["device_id"], "humidity", 45, days=1)
    b = x.c.post(f"/api/sensors/{e['device_id']}/baseline/rebuild", headers=H).json()
    assert b["metrics"] == {}                                                      # 하루치로는 판정하지 않음
    assert x.c.get(f"/api/sensors/{e['device_id']}/baseline?metric=light", headers=H).status_code == 400


def test_calibration_helper(tmp_path):
    x = _client(tmp_path)
    a = _enroll(x.c, "배터리폰", "본점")
    b = _enroll(x.c, "센서폰", "본점")
    Aa, Ab = _auth(a), _auth(b)
    x.c.post("/api/sensor/push", json={"samples": {"battery_c": 35, "sound_db": 60, "humidity": 40}}, headers=Aa)
    assert x.S.devs[a["device_id"]]["latest"]["temp_c"] == 32.0                    # 기본 -3
    r = x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "temp", "reference": 24}, headers=H).json()
    assert r["key"] == "temp_offset_c" and r["old"] == -3.0 and r["new"] == -11.0
    x.c.post("/api/sensor/push", json={"samples": {"battery_c": 35}}, headers=Aa)
    assert x.S.devs[a["device_id"]]["latest"]["temp_c"] == 24.0
    r = x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "sound", "reference": 55}, headers=H)
    assert r.status_code == 400                                                    # 마지막 전송에 소리 없음 — 아래에서 다시
    x.c.post("/api/sensor/push", json={"samples": {"battery_c": 35, "sound_db": 60, "humidity": 40}}, headers=Aa)
    assert x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "sound", "reference": 55}, headers=H).json()["new"] == 85.0
    assert x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "humidity", "reference": 50}, headers=H).json()["new"] == 10.0
    x.c.post("/api/sensor/push", json={"samples": {"battery_c": 35, "humidity": 40}}, headers=Aa)
    assert x.S.devs[a["device_id"]]["latest"]["humidity"] == 50.0
    # 주변 온도 센서 폰 — 보정 후 다음 값부터
    x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 23}}, headers=Ab)
    assert x.c.post(f"/api/sensors/{b['device_id']}/calibrate", json={"what": "temp", "reference": 22}, headers=H).json()["key"] == "ambient_offset_c"
    x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 23}}, headers=Ab)
    assert x.S.devs[b["device_id"]]["latest"]["temp_c"] == 22.0
    # 같은 사이트의 주변 온도 센서 폰을 기준으로
    info = x.c.get(f"/api/sensors/{a['device_id']}/calibrate", headers=H).json()
    assert [c["id"] for c in info["candidates"]] == [b["device_id"]] and len(info["history"]) == 3
    r = x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "temp", "from_device": b["device_id"]}, headers=H).json()
    assert r["reference"] == 22.0 and r["from"] == "센서폰" and r["new"] == -13.0
    assert x.c.post(f"/api/sensors/{b['device_id']}/calibrate", json={"what": "temp", "from_device": a["device_id"]}, headers=H).status_code == 400
    for bad in ({"what": "x", "reference": 1}, {"what": "temp"}, {"what": "temp", "reference": 500}):
        assert x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json=bad, headers=H).status_code == 400
    # 폰 수동 설정 우선이면 소리 보정은 폰에서
    x.c.post("/api/sensor/push", json={"samples": {"sound_db": 60}, "diag": {"local": {"lock": True}}}, headers=Aa)
    assert "폰 앱" in x.c.post(f"/api/sensors/{a['device_id']}/calibrate", json={"what": "sound", "reference": 50}, headers=H).json()["detail"]
    # 오래된 값으로는 보정하지 않음
    x.S.devs[b["device_id"]]["latest"]["ts"] = time.time() - 3600
    assert x.c.post(f"/api/sensors/{b['device_id']}/calibrate", json={"what": "temp", "reference": 22}, headers=H).status_code == 400


def test_work_mode_uses_maintenance_window(tmp_path):
    x = _client(tmp_path)
    a = _enroll(x.c, "A열", "본점 전산실")
    b = _enroll(x.c, "B열", "본점 전산실")
    c = _enroll(x.c, "지점", "강남")
    r = x.c.post("/api/sensors/maint", json={"site": "본점 전산실", "minutes": 5, "reason": "항온항습기 필터"}, headers=H).json()
    assert set(r["ids"]) == {a["device_id"], b["device_id"]} and r["end"] - time.time() > 590     # 최소 10분
    items = {i["id"]: i for i in x.c.get("/api/sensors", headers=H).json()["items"]}
    assert items[a["device_id"]]["maint"]["sensor"] and "항온항습기 필터" in items[a["device_id"]]["maint"]["name"]
    assert "maint" not in items[c["device_id"]]
    inc = x.e.incidents
    ev = lambda did, name: {"event": {"source": "sensor", "host": name, "entity": f"sensor:{did}", "message": "현장 센서 위험: x"}}  # noqa: E731
    assert "유지보수 창" in inc.suppression(ev(a["device_id"], "A열"), "f")
    assert inc.suppression(ev(c["device_id"], "지점"), "f") is None
    assert inc.suppression({"event": {"source": "vcenter", "host": "A열", "entity": f"sensor:{a['device_id']}"}}, "f") is None   # 출처 sensor 만
    assert x.c.post(f"/api/sensors/maint/{r['id']}/end", headers=H).json()["ok"]
    assert "maint" not in {i["id"]: i for i in x.c.get("/api/sensors", headers=H).json()["items"]}[a["device_id"]]
    # 일반 유지보수 창은 여기서 끝낼 수 없음
    mid = asyncio.run(x.e.store.x("INSERT INTO maintenance(name,start,end,weekly,scope,enabled,created_by,created) VALUES(?,?,?,?,?,?,?,?)",
                                  ("vSAN 작업", 0, time.time() + 600, None, '{"hosts_regex": "esx", "clusters": [], "sources": []}', 1, "a", 0)))
    assert x.c.post(f"/api/sensors/maint/{mid}/end", headers=H).status_code == 404
    assert x.c.post("/api/sensors/maint", json={"site": "없는 곳"}, headers=H).status_code == 400
    r2 = x.c.post("/api/sensors/maint", json={"ids": [c["device_id"], "evil|.*"], "minutes": 99999}, headers=H).json()
    assert r2["ids"] == [c["device_id"]] and r2["end"] - time.time() <= 86400 + 5


def test_bulk_actions(tmp_path):
    x = _client(tmp_path)
    a = _enroll(x.c, "A열")
    b = _enroll(x.c, "B열")
    p = x.c.post("/api/sensors", json={"name": "미등록"}, headers=H).json()["device"]["id"]
    r = x.c.post("/api/sensors/bulk", json={"ids": [a["device_id"], b["device_id"], "nope"], "action": "config",
                                             "config": {"interval_s": 120, "thresholds": {"temp_c": {"warn_hi": 28, "crit_hi": 33}}}}, headers=H).json()
    assert r["ok"] == 2 and r["failed"] == 1
    for d in (a, b):
        c = x.S.devs[d["device_id"]]["config"]
        assert c["interval_s"] == 120 and c["thresholds"]["temp_c"]["warn_hi"] == 28 and c["thresholds"]["temp_c"]["warn_lo"] == 10   # 다른 기준 유지
    r = x.c.post("/api/sensors/bulk", json={"ids": [a["device_id"], p], "action": "command", "op": "restart"}, headers=H).json()
    assert [i["ok"] for i in r["items"]] == [True, False]
    assert x.c.post("/api/sensor/push", json={"samples": {}}, headers=_auth(a)).json()["commands"][0]["op"] == "restart"
    x.c.put(f"/api/sensors/{b['device_id']}", json={"config": {"sensors": ["temperature"]}}, headers=H)
    r = x.c.post("/api/sensors/bulk", json={"ids": [a["device_id"], b["device_id"]], "action": "snap"}, headers=H).json()
    assert [i["ok"] for i in r["items"]] == [True, False] and a["device_id"] in x.S.snap_req
    for bad in ({"ids": [a["device_id"]], "action": "shell"}, {"ids": [], "action": "snap"}, {"ids": [a["device_id"]], "action": "command", "op": "rm"},
                {"ids": [a["device_id"]], "action": "config"}):
        assert x.c.post("/api/sensors/bulk", json=bad, headers=H).status_code == 400


def test_summary_events_and_report(tmp_path):
    from app.reports import Reporter
    x = _client(tmp_path)
    a = _enroll(x.c, "A열", "본점")
    A = _auth(a)
    _seed(x, a["device_id"], "temp_c", 24.0, days=2)
    for t in (24, 31, 36, 24):
        x.c.post("/api/sensor/push", json={"samples": {"ambient_c": t, "battery_pct": 90}}, headers=A)
    evs = x.c.get(f"/api/sensors/{a['device_id']}/events", headers=H).json()["items"]
    assert [v["sev"] for v in evs][:3] == ["info", "critical", "warning"] and evs[1]["metric"] == "temp_c"
    s = x.c.get("/api/sensors/summary?days=7", headers=H).json()
    it = s["items"][0]
    assert it["stats"]["temp_c"]["max"] == 36 and it["alerts"] == {"critical": 1, "warning": 1} and it["top"][0][0] == "temp_c"
    assert it["temp_over_min"] >= 1 and 0 <= it["coverage"] <= 100 and s["totals"]["devices"] == 1
    html = Reporter.render_extended({"sensors": s})
    assert "현장 센서 환경" in html and "A열" in html and "<b>36</b>" in html


def test_reserved_ids_and_auth_rules():
    from app.security import auth
    import re as _re
    rule = next(r for r in auth.ROUTE_RULES if r[0] == "POST" and "maint" in r[1])
    assert rule[2] == "operate" and _re.match(rule[1], "/api/sensors/maint") and _re.match(rule[1], "/api/sensors/maint/12/end")
    from app.edgesense import RESERVED
    assert {"maint", "bulk", "summary"} <= RESERVED


def test_reserved_name_gets_other_id(tmp_path):
    x = _client(tmp_path)
    j = x.c.post("/api/sensors", json={"name": "summary"}, headers=H).json()
    assert j["device"]["id"] != "summary" and j["device"]["id"].startswith("summary-")
