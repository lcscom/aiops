"""2.51.0 — 현장 센서 고도화: 밀린 값 묶음, 온도 상승 속도, 경보음, 출입 감지, 경보 자동 촬영, 클러스터 상관, CSV, 앱 대기열·감시"""
import time
from pathlib import Path

from test_v2500_sensor import H, _client, _enroll

ROOT = Path(__file__).resolve().parents[1]


def test_backfill_batch_stored_with_timestamps(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    A = {**H, "authorization": "Bearer " + e["token"]}
    now = time.time()
    batch = [{"ts": now - 600 + i * 60, "samples": {"battery_c": 30 + i, "humidity": 40}} for i in range(5)]
    batch += [{"ts": now - 30 * 86400, "samples": {"humidity": 1}}, {"ts": "x"}, {"samples": {}}]          # 범위 밖·잘못된 항목은 버림
    r = x.c.post("/api/sensor/push", json={"samples": {"battery_c": 35, "queued": 5}, "batch": batch}, headers=A).json()
    assert r["backfilled"] == 5
    pts = x.c.get(f"/api/sensors/{e['device_id']}/series?metric=humidity&hours=1").json()["points"]
    assert len(pts) == 5 and all(abs(p[0] - b["ts"]) < 1 for p, b in zip(pts, batch))
    assert any("밀린 값 수신" in ev.message and "5건" in ev.message for ev in x.events)
    d = x.S.devs[e["device_id"]]
    assert d["latest"]["queued"] == 5 and d["info"]["backfill"]["count"] == 5
    assert d["state"].get("humidity", "ok") == "ok"                       # 묶음 값으로는 경보를 만들지 않음(최신값만 판정)


def test_temp_rate_warning_before_absolute(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    A = {**H, "authorization": "Bearer " + e["token"]}
    now = time.time()
    batch = [{"ts": now - 900, "samples": {"ambient_c": 22}}, {"ts": now - 600, "samples": {"ambient_c": 23}}]
    x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 26.5}, "batch": batch}, headers=A)
    d = x.S.devs[e["device_id"]]
    assert 2.5 <= d["latest"]["temp_rate"] <= 3.2 and d["state"]["temp_rate"] == "warn" and d["state"].get("temp_c", "ok") == "ok"
    assert any("온도 급상승" in ev.message and ev.severity == "warning" for ev in x.events)


def test_alarm_tone_and_auto_snapshot(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    A = {**H, "authorization": "Bearer " + e["token"]}
    did = e["device_id"]
    r = x.c.post("/api/sensor/push", json={"samples": {"alarm_tone": 1, "tone_hz": 3100, "tonal_pct": 52, "sound_db": 70}}, headers=A).json()
    ev = [v for v in x.events if v.severity == "critical"]
    assert ev and "경보음 감지(약 3100Hz, 52%)" in ev[0].message and ev[0].attrs["metric"] == "alarm_tone"
    assert x.S.snap_req.get(did)                                           # 경보 → 자동 촬영 요청
    assert x.c.post("/api/sensor/push", json={"samples": {"alarm_tone": 1}}, headers=A).json()["snap"] is True
    x.c.post("/api/sensor/snap", content=b"\xff\xd8\xff\xe0" + b"2" * 200, headers={**A, "content-type": "image/jpeg"})
    snaps = x.c.get(f"/api/sensors/{did}/snaps").json()["items"]
    assert snaps[0]["reason"].startswith("경보음")
    pic = [v for v in x.events if "경보 사진" in v.message]
    assert pic and pic[0].attrs["snap_url"].endswith(snaps[0]["name"]) and x.S.devs[did]["latest"]["alert_snap"] == snaps[0]["name"]
    assert r["snap"] is True                                               # 판정이 응답 전에 끝나 같은 응답에서 바로 촬영 요청


def test_snap_on_alert_off_and_camera_off(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    x.c.put(f"/api/sensors/{did}", json={"config": {"snap_on_alert": False}}, headers=H)
    A = {**H, "authorization": "Bearer " + e["token"]}
    x.c.post("/api/sensor/push", json={"samples": {"humidity": 95}}, headers=A)
    assert not x.S.snap_req.get(did)


def test_presence_detection(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    A = {**H, "authorization": "Bearer " + e["token"]}
    x.c.post("/api/sensor/push", json={"samples": {"light": 2}}, headers=A)
    x.c.post("/api/sensor/push", json={"samples": {"light": 300}}, headers=A)
    assert not any("출입" in v.message for v in x.events)                    # 기본은 끔
    x.c.put(f"/api/sensors/{did}", json={"config": {"presence_alert": True, "presence_lux": [5, 100]}}, headers=H)
    x.c.post("/api/sensor/push", json={"samples": {"light": 3}}, headers=A)
    x.c.post("/api/sensor/push", json={"samples": {"light": 250}}, headers=A)
    ev = [v for v in x.events if "출입 의심" in v.message]
    assert len(ev) == 1 and "3 → 250 lx" in ev[0].message and x.S.snap_why.get(did) == "출입"


def test_cluster_link_correlation_and_csv(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    x.c.put(f"/api/sensors/{did}", json={"config": {"link_cluster": "cl-prod-01", "link_rack": "A-03"}}, headers=H)
    A = {**H, "authorization": "Bearer " + e["token"]}
    x.c.post("/api/sensor/push", json={"samples": {"ambient_c": 40}}, headers=A)
    ev = [v for v in x.events if v.severity == "critical"][0]
    assert ev.attrs["cluster"] == "cl-prod-01"
    from app.incidents import IncidentManager as Incidents
    inc = Incidents.__new__(Incidents)
    inc.e = x.e
    assert inc.correlation(ev.to_dict())[:2] == ("cluster:cl-prod-01", "cl-prod-01")
    ev2 = ev.to_dict()
    ev2["attrs"] = {"site": "본점 3층"}
    assert inc.correlation(ev2)[0] == "site:본점 3층"
    csv = x.c.get(f"/api/sensors/{did}/export.csv?hours=1")
    assert csv.status_code == 200 and "attachment" in csv.headers["content-disposition"]
    assert csv.text.startswith("﻿time,metric,label,value,unit") and "ambient_c,주변 온도(센서),40.0,°C" in csv.text
    assert x.c.get("/api/sensors/clusters").json() == {"items": []}


def test_config_new_keys_clamped():
    from app.edgesense import merge_config
    c = merge_config({"presence_lux": [500, 2], "buffer_max": 10 ** 9, "link_cluster": "x" * 200, "tone_detect": 0})
    assert c["presence_lux"] == [500.0, 501.0] and c["buffer_max"] == 20000 and len(c["link_cluster"]) == 80 and c["tone_detect"] is False
    d = merge_config({})
    assert d["thresholds"]["temp_rate"] == {"warn_hi": 2.0, "crit_hi": 4.0} and d["thresholds"]["alarm_tone"] == {"crit_hi": 1}


def test_android_queue_watchdog_tone_sources():
    src = ROOT / "mobile/sensor/src/com/krvcf/aiopssensor"
    q = (src / "Queue.java").read_text(encoding="utf-8")
    assert "queue.jsonl" in q and "renameTo" in q                       # 원자적 교체
    svc = (src / "SensorService.java").read_text(encoding="utf-8")
    assert 'body.put("batch", batch)' in svc and "Queue.drop(this, batch.length())" in svc and 'Queue.add(this' in svc
    sm = (src / "SoundMeter.java").read_text(encoding="utf-8")
    assert "goertzel" in sm and "Net." not in sm and "FileOutputStream" not in sm
    m = (ROOT / "mobile/sensor/AndroidManifest.xml").read_text(encoding="utf-8")
    assert ".Watchdog" in m and "BIND_JOB_SERVICE" in m
    assert "Watchdog.schedule" in (src / "BootReceiver.java").read_text(encoding="utf-8")


def test_tone_algorithm_python_port():
    """SoundMeter 의 Goertzel 판정을 그대로 옮겨 반복음·지속음은 잡고 잡음·팬 소리는 거르는지"""
    import math
    import random
    RATE = 16000

    def gz(x, off, n, hz):
        w = 2 * math.pi * hz / RATE
        c, s1, s2 = 2 * math.cos(w), 0.0, 0.0
        for i in range(off, off + n):
            s0 = x[i] + c * s1 - s2
            s2, s1 = s1, s0
        return s1 * s1 + s2 * s2 - c * s1 * s2

    def tonal(buf):
        best = max(sum(gz(buf, k * 160, 160, hz) for k in range(10)) for hz in range(1500, 4501, 100))
        tot = sum(v * v for v in buf) * 160 / 2
        return best / tot > 0.3
    rnd = random.Random(3)
    t = [i / RATE for i in range(1600)]
    assert tonal([6000 * math.sin(2 * math.pi * 2950 * x) + rnd.gauss(0, 800) for x in t])
    assert not tonal([rnd.gauss(0, 4000) for _ in t])
    assert not tonal([4000 * math.sin(2 * math.pi * 120 * x) + 2500 * math.sin(2 * math.pi * 360 * x) + rnd.gauss(0, 2000) for x in t])
