"""2.30.0 모바일 앱 — 기기 연결(일회용 코드)·알림 피드·서버 업데이트 알림·권한·APK 배포·좁은 화면 틀"""
import asyncio
import hashlib
import json
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


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _mobile(tmp_path, **cfg):
    e = _engine(tmp_path)
    return MB.Mobile(e, None, cfg)


def test_pair_code_is_one_time_and_limited(tmp_path):
    m = _mobile(tmp_path, max_devices_per_user=2)

    async def main():
        s = await m.pair_start({"user": "kim"}, "https://aiops.vcf.lab")
        assert s["link"].startswith("vcfaiops://connect?url=https%3A%2F%2Faiops.vcf.lab&code=") and "<svg" in s["qr_svg"] and "viewBox" in s["qr_svg"]
        assert s["code"] not in json.dumps(list(m.codes))                       # 코드는 해시로만 보관
        r = await m.pair({"code": s["code"], "name": "Pixel", "os": "14", "app": 23000}, "10.0.0.5", auth_enabled=False)
        assert r["token"].startswith("aiopsm_") and r["user"] == "kim"
        row = await m.store.q1("SELECT token_hash FROM mobile_devices WHERE id=?", (r["device_id"],))
        assert row["token_hash"] == hashlib.sha256(r["token"].encode()).hexdigest() and r["token"] not in row["token_hash"]   # 토큰 원문은 저장 안 함
        with pytest.raises(PermissionError):                                    # 같은 코드 재사용 불가
            await m.pair({"code": s["code"]}, "10.0.0.5", auth_enabled=False)
        with pytest.raises(PermissionError):
            await m.pair({"code": "틀린코드"}, "10.0.0.5", auth_enabled=False)
        s2 = await m.pair_start({"user": "kim"}, "https://aiops.vcf.lab")
        await m.pair({"code": s2["code"]}, "10.0.0.5", auth_enabled=False)
        s3 = await m.pair_start({"user": "kim"}, "https://aiops.vcf.lab")
        with pytest.raises(PermissionError, match="2대"):                        # 사용자당 기기 수
            await m.pair({"code": s3["code"]}, "10.0.0.5", auth_enabled=False)
        m.codes[MB._hash("old")] = {"user": "kim", "exp": time.time() - 1}
        with pytest.raises(PermissionError):                                    # 만료
            await m.pair({"code": "old"}, "10.0.0.6", auth_enabled=False)
        for _ in range(12):                                                     # 무차별 대입 제한(IP 당 10분 10회)
            try:
                await m.pair({"code": "x"}, "10.9.9.9", auth_enabled=False)
            except PermissionError as e:
                last = str(e)
        assert "잦습니다" in last
    _run(main())


def test_feed_filter_cursor_and_revoke(tmp_path):
    m = _mobile(tmp_path)

    async def main():
        s = await m.pair_start({"user": "kim"}, "http://h")
        await m.emit("alert", "연결 전 알림", sev="critical")
        r = await m.pair({"code": s["code"]}, "1.1.1.1", auth_enabled=False)
        d = await m.device_by_token(r["token"], auth_enabled=False)
        assert d and await m.device_by_token("aiopsm_wrong", auth_enabled=False) is None and await m.device_by_token("aiops_apitoken", auth_enabled=False) is None
        f = await m.feed(d, r["cursor"], 23000, "1.1.1.1", "2.30.0")
        assert f["events"] == [] and f["poll"] == 900                           # 연결 전 알림은 오지 않음
        await m.emit("alert", "경고 수준", sev="warning")                        # 기본 최소 심각도 critical → 제외
        await m.emit("alert", "심각", sev="critical", view="inc")
        await m.emit("perf", "성능", sev="critical")                             # 기본 종류에 없음
        await m.emit("update", "서버가 2.30.1 로 업데이트되었습니다", sev="info", view="sys")   # 업데이트는 심각도 무관
        await m.emit("test", "남의 시험", user="lee")
        await m.emit("test", "내 시험", user="kim")
        f = await m.feed(d, r["cursor"], 23000, "1.1.1.1", "2.30.0")
        assert [e["title"] for e in f["events"]] == ["심각", "서버가 2.30.1 로 업데이트되었습니다", "내 시험"]
        assert f["events"][0]["view"] == "inc" and f["server"]["version"] == "2.30.0"
        f2 = await m.feed(d, f["cursor"], 23000, "1.1.1.1", "2.30.0")
        assert f2["events"] == [] and f2["cursor"] == f["cursor"]
        assert (await m.feed(d, 10 ** 9, 0, "1.1.1.1", "x"))["cursor"] == f["cursor"]   # DB 를 새로 만든 경우 커서를 끝으로 되돌림
        assert await m.emit("alert", "중복", sev="critical", dkey="a:1") and await m.emit("alert", "중복", sev="critical", dkey="a:1") is None
        m._recent.clear()                                                       # 재기동 뒤에도 DB 기록으로 중복을 거른다
        assert await m.emit("alert", "중복", sev="critical", dkey="a:1") is None
        await m.update_device(d["id"], {"kinds": ["perf", "없는종류"], "min_sev": "warning"}, {"user": "kim"}, False)
        d = await m.device_by_token(r["token"], auth_enabled=False)
        await m.emit("perf", "성능2", sev="warning")
        assert [e["title"] for e in (await m.feed(d, f["cursor"], 0, "1.1.1.1", "x"))["events"]] == ["성능2"]
        with pytest.raises(LookupError):                                        # 남의 기기는 못 건드림
            await m.update_device(d["id"], {"kinds": []}, {"user": "lee"}, False)
        with pytest.raises(LookupError):
            await m.revoke(d["id"], {"user": "lee"}, False)
        assert len(await m.devices({"user": "lee"}, False)) == 0 and len(await m.devices({"user": "lee"}, True)) == 1
        await m.revoke(d["id"], {"user": "lee"}, True)                          # 관리자는 가능
        assert await m.device_by_token(r["token"], auth_enabled=False) is None
        await m.save_settings({"enabled": False}, "admin")
        with pytest.raises(PermissionError):
            await m.pair_start({"user": "kim"}, "http://h")
        with pytest.raises(ValueError):
            await m.save_settings({"poll_minutes": 5}, "admin")
    _run(main())


def test_disabled_user_loses_device(tmp_path):
    m = _mobile(tmp_path)

    async def main():
        await m.ensure()
        await m.store.x("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, disabled INTEGER DEFAULT 0)")
        await m.store.x("INSERT INTO users(username) VALUES('kim')")
        s = await m.pair_start({"user": "ghost"}, "http://h")
        with pytest.raises(PermissionError, match="계정"):                       # 없는 계정
            await m.pair({"code": s["code"]}, "1.1.1.1", auth_enabled=True)
        s = await m.pair_start({"user": "kim"}, "http://h")
        r = await m.pair({"code": s["code"]}, "1.1.1.1", auth_enabled=True)
        assert await m.device_by_token(r["token"]) is not None
        await m.store.x("UPDATE users SET disabled=1 WHERE username='kim'")     # 계정을 끄면 기기 토큰도 즉시 무효
        assert await m.device_by_token(r["token"]) is None
        await m.store.x("DELETE FROM users WHERE username='kim'")
        assert await m.device_by_token(r["token"]) is None
    _run(main())


def test_version_change_emits_update(tmp_path):
    m = _mobile(tmp_path)

    async def main():
        assert await m.check_version("2.29.0") is None                          # 첫 기동(기기 없음) — 기준만 기록
        assert (await m.store.q1("SELECT COUNT(*) AS n FROM mobile_events"))["n"] == 0
        assert await m.check_version("2.29.0") is None
        assert await m.check_version("2.30.0") == "2.29.0"
        ev = await m.store.q("SELECT kind,title,body,view FROM mobile_events")
        assert len(ev) == 1 and ev[0]["kind"] == "update" and "2.30.0" in ev[0]["title"] and "2.29.0 → 2.30.0" in ev[0]["body"] and ev[0]["view"] == "sys"
        assert await m.check_version("2.30.0") is None and await m.check_version("unknown") is None
    _run(main())
    notes = MB.release_notes((ROOT / "VERSION").read_text().strip())
    assert isinstance(notes, list) and all(isinstance(n, str) and len(n) < 400 for n in notes)


def test_anomaly_kinds(tmp_path):
    m = _mobile(tmp_path)

    async def main():
        await m.ensure()
        m.on_anomaly({"severity": "critical", "title": "백업 실패", "fp": "f1", "event": {"entity": "backup:vcenter", "host": "vc01"}})
        m.on_anomaly({"severity": "critical", "title": "CPU ready", "fp": "f2", "event": {"entity": "perf:host:esx1"}})
        m.on_anomaly({"severity": "error", "title": "호스트 끊김", "fp": "f3", "event": {"host": "esx2"}})
        m.on_anomaly({"severity": "error", "title": "호스트 끊김", "fp": "f3", "event": {"host": "esx2"}})   # 같은 지문 = 한 번
        m.on_text("디스크 여유 부족", "critical")
        await asyncio.sleep(0.3)
        ev = await m.store.q("SELECT kind,view,title FROM mobile_events ORDER BY id")
        assert sorted((e["kind"], e["view"]) for e in ev) == sorted([("dr", "dr"), ("perf", "pf"), ("alert", "inc"), ("system", "")])
    _run(main())


def test_route_rules_and_public_paths():
    rp = AuthManager.required_perm
    assert rp("POST", "/api/mobile/pair/start") == "view" and rp("POST", "/api/mobile/test") == "view"
    assert rp("PUT", "/api/mobile/devices/3") == "view" and rp("DELETE", "/api/mobile/devices/3") == "view"
    assert rp("PUT", "/api/mobile/settings") == "settings" and rp("GET", "/api/mobile/info") == "view"
    assert MB.PUBLIC_PATHS == ("/api/mobile/pair", "/api/mobile/feed", "/api/mobile/app.apk")
    src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert 'MOBILE.cfg["allow_without_access"] and MOBILE.cfg["enabled"]' in src       # 외부 우회는 설정을 켠 때만
    assert MB.DEFAULTS["allow_without_access"] is False


def test_routes_need_token_or_session():
    from fastapi.testclient import TestClient

    import app.main as M
    with TestClient(M.app) as cl:
        if M.AUTH.enabled:
            assert cl.get("/api/mobile/info").status_code == 401
            assert cl.post("/api/mobile/pair/start", json={"origin": "http://testserver"}, headers={"X-Requested-With": "aiops"}).status_code == 401
            assert cl.get("/api/mobile/app.apk").status_code == 401
        assert cl.get("/api/mobile/feed").status_code == 401
        assert cl.get("/api/mobile/feed", headers={"Authorization": "Bearer aiopsm_" + "x" * 40}).status_code == 401
        assert cl.post("/api/mobile/pair", json={"code": "없는코드"}, headers={"X-Requested-With": "aiops"}).status_code == 403
        assert cl.post("/api/mobile/pair", content="[]", headers={"X-Requested-With": "aiops", "Content-Type": "application/json"}).status_code == 400
        # 코드 → 토큰 → 피드 → APK(토큰) — 실제 경로로
        user = "anonymous"
        if M.AUTH.enabled:
            row = cl.portal.call(_first_user, M)
            if not row:
                return
            user = row
        cl.portal.call(_drop_test_devices, M)                                   # 이전 실행이 남긴 시험 기기(사용자당 기기 수 제한)
        code = cl.portal.call(M.MOBILE.pair_start, {"user": user}, "http://testserver")["code"]
        r = cl.post("/api/mobile/pair", json={"code": code, "name": "t", "app": 1}, headers={"X-Requested-With": "aiops"})
        assert r.status_code == 200, r.text
        tok = r.json()["token"]
        h = {"Authorization": f"Bearer {tok}"}
        f = cl.get(f"/api/mobile/feed?since={r.json()['cursor']}&app=1", headers=h)
        assert f.status_code == 200 and f.json()["events"] == [] and f.json()["app"]["code"] == MB.app_meta()["code"]
        a = cl.get("/api/mobile/app.apk", headers=h)
        assert a.status_code == 200 and hashlib.sha256(a.content).hexdigest() == MB.app_meta()["sha256"] == a.headers["x-checksum-sha256"]
        assert a.headers["content-type"] == "application/vnd.android.package-archive"
        if M.AUTH.enabled:
            assert cl.get("/api/mobile/info", headers=h).status_code == 401      # 기기 토큰으로 다른 API 는 못 씀
            assert cl.get("/api/anomalies", headers=h).status_code == 401
        cl.portal.call(M.MOBILE.revoke, r.json()["device_id"], {"user": user}, True)
        assert cl.get("/api/mobile/feed", headers=h).status_code == 401


async def _first_user(M):
    r = await M.ENGINE.store.q1("SELECT username FROM users WHERE disabled=0 ORDER BY created LIMIT 1")
    return (r or {}).get("username")


def test_apk_matches_manifest_and_version():
    meta = json.loads((S / "app" / "app.json").read_text(encoding="utf-8"))
    apk = (S / "app" / "vcf-aiops.apk").read_bytes()
    assert meta["size"] == len(apk) and meta["sha256"] == hashlib.sha256(apk).hexdigest() and meta["package"] == "com.krvcf.vcfaiops"
    ver = (ROOT / "VERSION").read_text().strip()
    a, b, c = (int(x) for x in ver.split("."))
    assert meta["name"] == ver and meta["code"] == a * 10000 + b * 100 + c         # 릴리스마다 앱도 다시 빌드
    assert re.fullmatch(r"[0-9a-f]{64}", meta["cert_sha256"])
    assert apk[:2] == b"PK" and b"classes.dex" in apk and b"AndroidManifest.xml" in apk
    assert MB.app_meta()["sha256"] == meta["sha256"]


def test_android_source_guards():
    src = ROOT / "mobile" / "android"
    man = (src / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:allowBackup="false"' in man and "REQUEST_INSTALL_PACKAGES" in man and 'android:scheme="vcfaiops"' in man
    assert "WRITE_EXTERNAL_STORAGE" not in man and "READ_EXTERNAL_STORAGE" not in man and "ACCESS_FINE_LOCATION" not in man
    main = (src / "src/com/krvcf/vcfaiops/MainActivity.java").read_text(encoding="utf-8")
    assert '"#go=" + view' in main and "saveFile" in main and "pageHost.equals(Prefs.host(MainActivity.this))" in main   # 브리지는 같은 서버 화면만
    assert "->" not in re.sub(r'"(?:[^"\\]|\\.)*"|//[^\n]*', "", main)             # dx 는 람다 미지원
    assert not list(ROOT.glob("**/*.p12")) and not list(ROOT.glob("**/*.jks")) and not list(ROOT.glob("**/android-signing*"))   # 서명 키는 저장소 밖
    build = (src / "build.sh").read_text(encoding="utf-8")
    assert "apksigner sign" in build and "--v2-signing-enabled true" in build
    assert subprocess.run(["bash", "-n", str(src / "build.sh")]).returncode == 0


def test_web_shell_wiring():
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-mobile"' in html and 'id="drawer-mobile"' in html and html.index("/static/mobile.js") < html.index("/static/navgroup.js")
    assert '"mobile"]' in (S / "navgroup.js").read_text(encoding="utf-8")
    js = (S / "mobile.js").read_text(encoding="utf-8")
    for k in ("window.AIOPS_MOBILE", "#go=", "/api/mobile/pair/start", "/api/mobile/install-qr", "installUpdate", "allow_without_access", "btn-menu"):
        assert k in js
    assert "innerHTML" in js and "esc(" in js and "eval(" not in js
    core = (S / "core.js").read_text(encoding="utf-8")
    assert "A.download" in core and "saveFile" in core
    for f in ("dr.js", "bestpractice.js", "vcheck.js", "vksmap.js"):
        assert "createObjectURL" not in (S / f).read_text(encoding="utf-8")       # 앱에서도 내려받기가 되도록 공용 함수 사용
    assert "st.d = null; badge()" not in (S / "dr.js").read_text(encoding="utf-8") + (S / "bestpractice.js").read_text(encoding="utf-8")
    css = (S / "style.css").read_text(encoding="utf-8")
    assert "html.nav-open .vnav" in css and "html.is-app" in css and "@media (pointer:coarse)" in css
    en = (S / "i18n-en.js").read_text(encoding="utf-8")
    assert '"모바일 앱": "Mobile app"' in en and '"연결 QR 만들기"' in en
    for f in ("mobile.js", "core.js", "dr.js", "bestpractice.js", "navgroup.js", "i18n-en.js"):
        assert subprocess.run(["node", "--check", str(S / f)], capture_output=True).returncode == 0, f


async def _drop_test_devices(M):
    await M.MOBILE.ensure()
    await M.ENGINE.store.x("UPDATE mobile_devices SET revoked=1 WHERE name='t'")
    M.MOBILE._pair_hits.clear()
