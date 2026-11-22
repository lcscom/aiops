"""2.53.0 — 폰 원격 설정(명령 대기열·결과), 기기 소유자 진단, 설치·설정 스크립트(adb), 접속 주소(내부 IP), 폰 수동 설정"""
import re
from pathlib import Path

from test_v2500_sensor import H, _client, _enroll

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "mobile/sensor/src/com/krvcf/aiopssensor"


def test_command_queue_roundtrip(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    A = {**H, "authorization": "Bearer " + e["token"]}
    x.c.post("/api/sensor/push", json={"samples": {}, "diag": {"app_code": 25300, "owner": False, "caps": ["restart", "battery_prompt", "evil"]}}, headers=A)
    assert x.S.devs[did]["info"]["diag"]["caps"] == ["restart", "battery_prompt"]
    r = x.c.post(f"/api/sensors/{did}/commands", json={"op": "grant_perms"}, headers=H).json()
    assert "기기 소유자가 아니라" in r["warn"]
    r2 = x.c.post(f"/api/sensors/{did}/commands", json={"op": "alarm_volume", "args": {"percent": 500, "x": 1}}, headers=H).json()
    assert r2["args"] == {"percent": 100}
    assert x.c.post(f"/api/sensors/{did}/commands", json={"op": "rm -rf"}, headers=H).status_code == 400
    assert x.c.post(f"/api/sensors/{did}/commands", json={"op": "server", "args": {"url": "http://x;reboot"}}, headers=H).status_code == 400
    r3 = x.c.post(f"/api/sensors/{did}/commands", json={"op": "server", "args": {"url": "http://10.10.1.20:8443"}}, headers=H).json()
    c3 = x.c.post(f"/api/sensors/{did}/commands", json={"op": "restart"}, headers=H).json()
    assert x.c.delete(f"/api/sensors/{did}/commands/{c3['id']}", headers=H).json()["ok"]
    p = x.c.post("/api/sensor/push", json={"samples": {}}, headers=A).json()
    assert [c["op"] for c in p["commands"]] == ["grant_perms", "alarm_volume", "server"] and p["commands"][2]["args"]["url"] == "http://10.10.1.20:8443"
    assert "commands" not in x.c.post("/api/sensor/push", json={"samples": {}}, headers=A).json()      # 한 번만 내려감
    assert x.c.delete(f"/api/sensors/{did}/commands/{r['id']}", headers=H).status_code == 409             # 이미 가져감
    res = [{"id": r["id"], "ok": False, "msg": "기기 소유자가 아님"}, {"id": r3["id"], "ok": True, "msg": "서버 주소 변경"}, {"id": "nope", "ok": True}]
    x.c.post("/api/sensor/push", json={"samples": {}, "cmd_results": res}, headers=A)
    lst = {c["id"]: c for c in x.c.get(f"/api/sensors/{did}/commands", headers=H).json()["items"]}
    assert lst[r["id"]]["state"] == "done" and lst[r["id"]]["ok"] == 0 and lst[r3["id"]]["ok"] == 1 and lst[r2["id"]]["state"] == "sent"
    assert any("원격 설정 완료" in v.message and "서버 주소" in v.message for v in x.events)
    assert any("원격 설정 실패" in v.message for v in x.events)
    meta = x.c.get("/api/sensors/commands/meta", headers=H).json()["commands"]
    assert meta["reboot"]["owner"] and not meta["restart"]["owner"]


def test_health_owner_and_local_and_interval(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    did = e["device_id"]
    A = {**H, "authorization": "Bearer " + e["token"]}
    x.c.post("/api/sensor/push", json={"samples": {}, "diag": {"app_code": 25300, "owner": False, "local": {"lock": True, "interval_s": 900, "x": 1}}}, headers=A)
    d = x.S.devs[did]
    codes = {i["code"] for i in x.S.health(d)["issues"]}
    assert {"not_owner", "local"} <= codes and d["info"]["diag"]["local"] == {"lock": True, "interval_s": 900}
    assert x.S.interval(d) == 900                                               # 무응답 판정도 폰 간격으로


def test_provision_scripts(tmp_path):
    x = _client(tmp_path)
    j = x.c.post("/api/sensors", json={"name": "설치 시험", "server": "http://10.10.1.20:8443"}, headers=H).json()
    assert j["enroll"]["server"] == "http://10.10.1.20:8443" and "u=http%3A%2F%2F10.10.1.20%3A8443" in j["enroll"]["setup_url"]
    page = x.c.get(j["enroll"]["setup_url"].replace("http://10.10.1.20:8443", "")).text
    assert "http://10.10.1.20:8443" in page and "vcfaiops-sensor://enroll?u=http%3A%2F%2F10.10.1.20%3A8443" in page.replace("&amp;", "&")
    did = j["device"]["id"]
    r = x.c.post(f"/api/sensors/{did}/provision", json={"server": "http://10.10.1.20:8443", "owner": True, "stay_awake": True,
                                                        "phone_ip": "10.10.1.57", "phone_port": "37017", "pair_port": "41234", "pair_code": "123456"}, headers=H).json()
    sh, bat = r["sh"]["text"], r["bat"]["text"]
    assert r["has_code"] and "adb" in sh
    for must in ('"$ADB" pair 10.10.1.57:41234 123456', '"$ADB" connect 10.10.1.57:37017', "install -r -g", "dumpsys deviceidle whitelist +$PKG",
                 "RUN_ANY_IN_BACKGROUND allow", "stay_on_while_plugged_in 7", "dpm set-device-owner $PKG/.Admin", "vcfaiops-sensor://enroll?u=http%3A%2F%2F10.10.1.20%3A8443&c="):
        assert must in sh, must
    assert "%%3A" in bat and "\r\n" in bat and "dpm set-device-owner %PKG%/.Admin" in bat
    code = re.search(r"app\.apk\?c=([0-9A-F-]+)", sh).group(1)
    assert x.c.get(f"/api/sensor/app.apk?c={code}").status_code == 200              # 스크립트의 코드로 APK 받기
    for bad in ({"server": "http://a;rm -rf /"}, {"phone_ip": "1.2.3.4;reboot"}, {"pair_code": "12ab"}):
        assert x.c.post(f"/api/sensors/{did}/provision", json=bad, headers=H).status_code == 400
    r2 = x.c.post(f"/api/sensors/{did}/provision", json={}, headers=H).json()
    assert "connect" not in r2["sh"]["text"] and "dpm set-device-owner" not in r2["sh"]["text"]   # USB·기본


def test_provision_enrolled_device_keeps_token(tmp_path):
    x = _client(tmp_path)
    e = _enroll(x.c)
    A = {**H, "authorization": "Bearer " + e["token"]}
    r = x.c.post(f"/api/sensors/{e['device_id']}/provision", json={"owner": True}, headers=H).json()
    assert not r["has_code"] and "install" not in r["sh"]["text"] and "monkey -p $PKG" in r["sh"]["text"]
    assert x.c.post("/api/sensor/push", json={"samples": {}}, headers=A).status_code == 200


def test_addresses_include_internal(tmp_path):
    from app.sensorprov import addresses

    class Req:
        class url:
            scheme, netloc, port = "http", "aiops.example.com:8700", 8700
        headers = {}
    items = addresses("https://aiops.example.com", Req())
    assert items[0] == {"url": "https://aiops.example.com", "kind": "public", "note": items[0]["note"]}
    assert any(i["kind"] == "current" for i in items)
    assert all(i["url"].startswith("http") for i in items)


def test_android_remote_sources():
    m = (ROOT / "mobile/sensor/AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:name=".Admin"' in m and "BIND_DEVICE_ADMIN" in m and "@xml/device_admin" in m and 'lockTaskMode="if_whitelisted"' in m
    rm = (SRC / "Remote.java").read_text(encoding="utf-8")
    for op in ("grant_perms", "stay_awake", "keyguard", "kiosk", "reboot", "brightness", "battery_prompt", "perm_prompt", "alarm_volume", "restart",
               "clear_queue", "display", "server"):
        assert f'case "{op}"' in rm, op
    assert "isDeviceOwnerApp" in rm and "setPermissionGrantState" in rm and "STAY_ON_WHILE_PLUGGED_IN" in rm
    assert 'Prefs.put(c, "server", old)' in rm                                  # 새 주소 실패 시 되돌림
    svc = (SRC / "SensorService.java").read_text(encoding="utf-8")
    assert 'j.optJSONArray("commands")' in svc and '"cmd_results"' in svc and 'd.put("owner", Remote.owner(this))' in svc
    ma = (SRC / "MainActivity.java").read_text(encoding="utf-8")
    assert "수동 설정" in ma and "changeServer" in ma and 'Prefs.put(MainActivity.this, "local"' in ma
    from app.edgesense import COMMANDS
    assert set(COMMANDS) == {"grant_perms", "stay_awake", "keyguard", "kiosk", "brightness", "reboot", "battery_prompt", "perm_prompt",
                             "alarm_volume", "restart", "clear_queue", "display", "server"}
