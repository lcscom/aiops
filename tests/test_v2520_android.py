"""2.52.0 — 안드로이드 안정성: API 수준 점검(두 앱), 핵심 로직 Java 실행 시험, 깨우기·카메라·자동 재시작 방어, 앱 진단·오류 보고·자체 업데이트"""
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from test_v2500_sensor import H, _client, _enroll

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "mobile/sensor/src/com/krvcf/aiopssensor"
HAS_SDK = Path("/home/claude/work/android-sdk/android-34.jar").is_file() and Path("/usr/lib/android-sdk/platforms/android-23/android.jar").is_file() \
    and shutil.which("aapt") and shutil.which("javac")


def _api_check(app):
    import importlib.util
    spec = importlib.util.spec_from_file_location("apicheck", ROOT / "scripts/dev/android-api-check.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.main(app)


@pytest.mark.skipif(not HAS_SDK, reason="android.jar(23·34)·aapt·javac 필요")
@pytest.mark.parametrize("app", ["mobile/sensor", "mobile/android"])
def test_no_unguarded_new_api(app):
    r = _api_check(app)
    assert r["ok"], json.dumps({"unknown": r.get("unknown"), "unguarded": r.get("unguarded")}, ensure_ascii=False)


@pytest.mark.skipif(not HAS_SDK, reason="android.jar(23·34)·aapt·javac 필요")
def test_api_checker_catches_unguarded_call(tmp_path):
    """점검기 자체 시험 — 8.x 에 없는 getLongVersionCode 를 확인 없이 부르면 잡아야 함(2.52.0 에서 운영자 앱에서 실제로 찾은 결함)"""
    app = tmp_path / "sensor"
    shutil.copytree(ROOT / "mobile/sensor", app)
    p = app / "src/com/krvcf/aiopssensor/Prefs.java"
    t = p.read_text(encoding="utf-8").replace("getPackageInfo(c.getPackageName(), 0).versionCode;", "getPackageInfo(c.getPackageName(), 0).getLongVersionCode();")
    t = t.replace('@SuppressWarnings("deprecation")\n', "")
    p.write_text(t, encoding="utf-8")
    r = _api_check(str(app))
    assert not r["ok"] and any(x["member"] == "getLongVersionCode" for x in r["unguarded"])


@pytest.mark.skipif(not shutil.which("javac"), reason="javac 필요")
def test_core_java_logic_runs(tmp_path):
    srcs = [str(p) for p in (SRC / "core").glob("*.java")] + [str(ROOT / "tests/java/CoreTest.java")]
    r = subprocess.run(["javac", "-encoding", "UTF-8", "-d", str(tmp_path), *srcs], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["java", "-Dstdout.encoding=UTF-8", "-cp", str(tmp_path), "CoreTest"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "ALL PASS" in r.stdout, r.stdout + r.stderr


def test_core_has_no_android_dependency():
    for p in (SRC / "core").glob("*.java"):
        assert "import android." not in p.read_text(encoding="utf-8"), p.name


def test_stability_defenses_in_source():
    svc = (SRC / "SensorService.java").read_text(encoding="utf-8")
    assert "setAndAllowWhileIdle" in svc and "PARTIAL_WAKE_LOCK" in svc and "aiops:sensor-keep" in svc     # 깊은 잠에서도 깨움
    assert 'new HandlerThread("sensor-events")' in svc                                                 # 센서 콜백 분리
    assert "catch (Throwable e)" in svc and "lateMax" in svc
    sn = (SRC / "Snapper.java").read_text(encoding="utf-8")
    i_quit, i_close = sn.index("ht.quitSafely();"), sn.index("if (jpeg != null) jpeg.close()")
    assert sn.index("dev[0].close()") < i_quit < sn.index("ht.join(3000)") < i_close                    # 닫는 순서
    assert "finished.get()" in sn
    wd = (SRC / "Watchdog.java").read_text(encoding="utf-8")
    assert "isIgnoringBatteryOptimizations" in wd and "SDK_INT < 31" in wd and "remind()" in wd
    app = (SRC / "App.java").read_text(encoding="utf-8")
    assert "setDefaultUncaughtExceptionHandler" in app and "crash.txt" in app and "prev.uncaughtException" in app
    m = (ROOT / "mobile/sensor/AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:name=".App"' in m and ".DisplayActivity" in m and ".InstallReceiver" in m and "REQUEST_INSTALL_PACKAGES" in m
    main = (SRC / "MainActivity.java").read_text(encoding="utf-8")
    assert "!SensorService.running || !SensorService.fullMode" in main                                  # 화면 열 때마다 재시작하지 않음
    pr = (ROOT / "mobile/android/src/com/krvcf/vcfaiops/Prefs.java").read_text(encoding="utf-8")
    assert "SDK_INT >= 28 ? (int) p.getLongVersionCode() : p.versionCode" in pr                          # 운영자 앱 8.x 결함 수정


def test_diag_crash_health_and_update(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    A = {**H, "authorization": "Bearer " + e["token"]}
    meta = x.S.app_meta()
    diag = {"app_code": int(meta["code"]) - 1, "app": "old", "sdk": 34, "battery_exempt": False, "plugged": False, "full": False,
            "late_s": 900, "restarts": 4, "queue": 12, "free_mb": 50, "perms": {"camera": False, "mic": True, "location": True, "notify": False},
            "last_error": "x" * 500, "evil": "<script>"}
    crash = "thread=main app=2.52.0 sdk=34 time=1\njava.lang.IllegalStateException: closed\n\tat a.b(c)\n"
    r = x.c.post("/api/sensor/push", json={"samples": {"battery_health": 2}, "diag": diag, "crash": crash}, headers=A).json()
    assert r["app"]["code"] == meta["code"] and r["app"]["sha256"] == meta["sha256"]
    d = x.S.devs[did]
    assert "evil" not in d["info"]["diag"] and len(d["info"]["diag"]["last_error"]) == 200
    assert d["info"]["crash"]["first"].startswith("java.lang.IllegalStateException") and d["info"]["crashes"] == 1
    assert any("현장 센서 앱 오류" in v.message for v in x.events)
    assert d["state"]["battery_health"] == "crit" and any("배터리 상태" in v.message and v.severity == "critical" for v in x.events)
    h = x.c.get("/api/sensors").json()["items"][0]["health"]
    codes = {i["code"] for i in h["issues"]}
    assert h["level"] == "warn" and {"battery_opt", "unplugged", "perms", "notify", "late", "restarts", "queue", "storage", "crash", "update", "last_error"} <= codes
    # 상태가 좋아지면 경고가 사라짐
    good = {**diag, "app_code": meta["code"], "battery_exempt": True, "plugged": True, "full": True, "late_s": 3, "restarts": 0, "queue": 0,
            "free_mb": 5000, "perms": {"camera": True, "mic": True, "location": True, "notify": True}}
    good.pop("last_error")
    x.S.devs[did]["info"].pop("crash")
    r = x.c.post("/api/sensor/push", json={"samples": {}, "diag": good}, headers=A).json()
    assert "app" not in r and x.c.get("/api/sensors").json()["items"][0]["health"] == {**x.S.health(x.S.devs[did])} and \
        x.S.health(x.S.devs[did])["level"] == "ok"


def test_apk_download_with_device_token(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    assert x.c.get("/api/sensor/app.apk").status_code == 404
    assert x.c.get("/api/sensor/app.apk", headers={"authorization": "Bearer sns_wrong"}).status_code == 404
    r = x.c.get("/api/sensor/app.apk", headers={"authorization": "Bearer " + e["token"]})
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == x.S.app_meta()["sha256"]


def test_local_alarm_default_on():
    from app.edgesense import merge_config
    assert merge_config({})["local_alarm"] is True and merge_config({"local_alarm": 0})["local_alarm"] is False
