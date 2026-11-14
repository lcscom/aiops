"""2.31.0 모바일 앱 완성도 — 실시간 알림(long-poll)·알림함·한눈에 보기·앱 잠금·토큰 암호화 저장"""
import asyncio
import re
import subprocess
import time
from pathlib import Path

import pytest

from app import mobile as MB
from app.security.auth import AuthManager
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"
J = ROOT / "mobile" / "android" / "src" / "com" / "krvcf" / "vcfaiops"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


async def _paired(m, user="kim"):
    s = await m.pair_start({"user": user}, "http://h")
    r = await m.pair({"code": s["code"]}, "1.1.1.1", auth_enabled=False)
    return await m.device_by_token(r["token"], auth_enabled=False), r


def test_long_poll_wakes_on_event_and_times_out(tmp_path):
    m = MB.Mobile(_engine(tmp_path), None, {})

    async def main():
        d, r = await _paired(m)
        t = time.time()
        f = await m.feed_wait(d, r["cursor"], 1, "1.1.1.1", "v", wait=1)        # 알림 없음 → 기다렸다 빈 응답
        assert f["events"] == [] and f["live"] is True and 0.9 < time.time() - t < 4 and m.waiters == 0
        task = asyncio.ensure_future(m.feed_wait(d, r["cursor"], 1, "1.1.1.1", "v", wait=30))
        await asyncio.sleep(0.2)
        assert m.waiters == 1
        await m.emit("alert", "경고만", sev="warning")                            # 이 기기 기준에 안 맞는 알림 — 계속 기다림
        await asyncio.sleep(0.2)
        assert not task.done()
        t = time.time()
        await m.emit("alert", "심각", sev="critical")
        f = await asyncio.wait_for(task, 3)
        assert [e["title"] for e in f["events"]] == ["심각"] and time.time() - t < 2 and m.waiters == 0
        assert (await m.feed_wait(d, r["cursor"], 1, "1.1.1.1", "v", wait=0)).get("live") is False       # wait 없으면 기존 동작
        t = time.time()
        assert len((await m.feed_wait(d, r["cursor"], 1, "1.1.1.1", "v", wait=30))["events"]) == 1 and time.time() - t < 1.5   # 줄 것이 있으면 바로
        f2 = await m.feed_wait(d, 10 ** 9, 1, "1.1.1.1", "v", wait=30)            # 커서가 앞서 있음(DB 새로 만듦) → 기다리지 않고 바로 맞춰 줌
        assert f2["cursor"] < 10 ** 9
        m.waiters = m.MAX_WAITERS                                                 # 대기 연결이 꽉 차면 기다리지 않음
        t = time.time()
        f3 = await m.feed_wait(d, f["cursor"], 1, "1.1.1.1", "v", wait=30)
        assert f3["events"] == [] and f3["live"] is False and time.time() - t < 1.5
        m.waiters = 0
    _run(main())


def test_long_poll_ends_when_device_revoked(tmp_path):
    m = MB.Mobile(_engine(tmp_path), None, {})

    async def main():
        d, r = await _paired(m)
        task = asyncio.ensure_future(m.feed_wait(d, r["cursor"], 1, "1.1.1.1", "v", wait=30))
        await asyncio.sleep(0.2)
        await m.revoke(d["id"], {"user": "kim"}, False)
        await m.emit("alert", "심각", sev="critical")
        with pytest.raises(PermissionError):                                      # 해제된 기기에는 알림을 주지 않고 끊음(라우트가 401)
            await asyncio.wait_for(task, 3)
        assert m.waiters == 0
    _run(main())


def test_recent_notices(tmp_path):
    m = MB.Mobile(_engine(tmp_path), None, {})

    async def main():
        await m.emit("alert", "a", sev="warning", view="inc")
        await m.emit("test", "남의 시험", user="lee")
        await m.emit("test", "내 시험", user="kim")
        await m.emit("update", "서버가 2.31.0 로 업데이트되었습니다", view="sys")
        n = await m.recent({"user": "kim"}, 10)
        assert [x["title"] for x in n] == ["서버가 2.31.0 로 업데이트되었습니다", "내 시험", "a"] and n[2]["view"] == "inc" and "user" not in n[0]
        assert len(await m.recent({"user": "kim"}, 1)) == 1
    _run(main())


def test_summary_route():
    from fastapi.testclient import TestClient

    import app.main as M
    assert AuthManager.required_perm("GET", "/api/mobile/summary") == "view"
    with TestClient(M.app) as cl:
        r = cl.get("/api/mobile/summary")
        if M.AUTH.enabled:
            assert r.status_code == 401
            assert cl.get("/api/mobile/summary", headers={"Authorization": "Bearer aiopsm_" + "x" * 40}).status_code == 401   # 기기 토큰으로는 못 봄
            return
        j = r.json()
        assert {"platform", "incidents", "anomalies", "connectors", "dr", "notices", "server"} <= set(j)
    src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert "not a.ack and not a.suppressed" in src                                # 확인·억제한 이상 징후는 세지 않음


def test_android_lock_vault_live_sources():
    man = (ROOT / "mobile" / "android" / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:name=".LiveService" android:exported="false" android:foregroundServiceType="specialUse"' in man
    assert "FOREGROUND_SERVICE_SPECIAL_USE" in man and "PROPERTY_SPECIAL_USE_FGS_SUBTYPE" in man and "USE_BIOMETRIC" in man
    assert "CAMERA" not in man and "WAKE_LOCK" not in man
    vault = (J / "Vault.java").read_text(encoding="utf-8")
    assert '"AndroidKeyStore"' in vault and "AES/GCM/NoPadding" in vault and "setKeySize(256)" in vault
    prefs = (J / "Prefs.java").read_text(encoding="utf-8")
    assert 'ed.putString("token_e", e).remove("token")' in prefs and "Vault.dec(e)" in prefs
    for f in J.glob("*.java"):
        t = f.read_text(encoding="utf-8")
        assert 'Prefs.put(' not in t or '"token"' not in "".join(x for x in t.splitlines() if "Prefs.put(" in x), f.name   # 토큰은 setToken 으로만
        assert "->" not in re.sub(r'"(?:[^"\\]|\\.)*"|//[^\n]*|/\*.*?\*/', "", t, flags=re.S), f.name                       # dx 는 람다 미지원
    lock = (J / "Lock.java").read_text(encoding="utf-8")
    assert "isDeviceSecure()" in lock and "BiometricPrompt" in lock and "createConfirmDeviceCredentialIntent" in lock
    main = (J / "MainActivity.java").read_text(encoding="utf-8")
    assert "FLAG_SECURE" in main and "(unlocked || !Lock.on(MainActivity.this))" in main          # 잠긴 동안 화면 가림 + 브리지 차단
    live = (J / "LiveService.java").read_text(encoding="utf-8")
    assert "Poller.poll(getApplicationContext(), 50)" in live and "Math.min(backoff * 2, 300000L)" in live and "0x40000000" in live
    assert 'Prefs.on(c, "live")' in live                                           # 기본 꺼짐(선택)
    poller = (J / "Poller.java").read_text(encoding="utf-8")
    assert "private static synchronized String handle(" in poller and "static synchronized String poll(" not in poller   # 대기 중에 다른 확인을 막지 않음
    apk = (S / "app" / "vcf-aiops.apk").read_bytes()
    for cls in (b"Lcom/krvcf/vcfaiops/Lock;", b"Lcom/krvcf/vcfaiops/Vault;", b"Lcom/krvcf/vcfaiops/LiveService;", b"Lcom/krvcf/vcfaiops/BootReceiver;"):
        import zipfile, io
        assert cls in zipfile.ZipFile(io.BytesIO(apk)).read("classes.dex"), cls


def test_home_wiring():
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-mhome"' in html and 'id="drawer-mhome"' in html
    assert re.search(r'"g-dash".*\["dash", "mhome", "tour", "#nav-noc"\]', (S / "navgroup.js").read_text(encoding="utf-8"))       # PC 기본 화면은 그대로 대시보드
    js = (S / "mobile.js").read_text(encoding="utf-8")
    for k in ("/api/mobile/summary", "homeOpen", "data-mgo", 'matchMedia("(max-width:900px)")', "secure_store"):
        assert k in js
    assert ".mh-tile" in (S / "style.css").read_text(encoding="utf-8")
    assert subprocess.run(["node", "--check", str(S / "mobile.js")], capture_output=True).returncode == 0
