"""2.21.2 외부 공개(Cloudflare Tunnel) 보안 — 외부 이름으로 내부 연동 경로 404, 로그인 화면 내부 명령어 제거,
남은 시도 횟수 기본 숨김, vApp FQDN 변경 시 외부 public_url 유지, 터널 스크립트 설정 편집(멱등)"""
import asyncio
import re
import subprocess
from pathlib import Path

from starlette.requests import Request
from starlette.responses import Response

ROOT = Path(__file__).resolve().parents[1]


def _req(path, host):
    return Request({"type": "http", "method": "GET", "path": path, "query_string": b"", "headers": [(b"host", host.encode())],
                    "client": ("127.0.0.1", 1), "server": ("t", 443), "scheme": "https", "root_path": ""})


def test_external_guard(monkeypatch):
    import app.main as M

    async def nxt(req):
        return Response("ok")

    monkeypatch.setattr(M, "_EXT_HOSTS", {"aiops.krvcf.com"})
    run = lambda p, h: asyncio.run(M.external_guard(_req(p, h), nxt)).status_code  # noqa: E731
    for p in ("/agents", "/agents/install.sh", "/api/redfish/events/abc", "/api/ha/peer", "/api/ingest", "/metrics", "/mcp",
              "/api/docs", "/api/openapi.json"):
        assert run(p, "aiops.krvcf.com") == 404, p
        assert run(p, "AIOPS.krvcf.com:443") == 404, p
        assert run(p, "aiops.vcf.lab:8630") == 200, p                   # 내부 이름은 그대로
    for p in ("/", "/login", "/api/auth/login", "/api/agentsx", "/metricsx", "/api/ingestion", "/share/sr/" + "a" * 32, "/healthz"):
        assert run(p, "aiops.krvcf.com") == 200, p
    monkeypatch.setattr(M, "_EXT_HOSTS", set())
    assert run("/metrics", "aiops.krvcf.com") == 200                   # 미설정이면 영향 없음


def test_login_page_no_internal_command():
    html = (ROOT / "app/static/login.html").read_text(encoding="utf-8")
    assert "vcf-aiopsctl" not in html and "sudo" not in html and "reset-admin" not in html
    assert "시스템 관리자에게 비밀번호 초기화를 요청하세요." in (ROOT / "app/static/i18n-en.js").read_text(encoding="utf-8")


def test_remaining_attempts_hidden(tmp_path, monkeypatch):
    import pytest
    from fastapi import HTTPException

    from app.security import auth as A
    from tests.test_v2110_support import _engine
    _sleep = asyncio.sleep
    monkeypatch.setattr(A.asyncio, "sleep", lambda *_: _sleep(0))

    async def go(show):
        e = _engine(tmp_path / f"s{show}")
        m = A.AuthManager(e.store, {"enabled": True, "lockout_threshold": 5, "show_remaining_attempts": show}, e.audit, tmp_path)
        await m._upsert_local("bob", "Bob", "viewer", "Abcdef12!x")
        with pytest.raises(HTTPException) as ex:
            await m.login("bob", "wrong", "10.0.0.9", "t")
        known = ex.value.detail
        with pytest.raises(HTTPException) as ex:
            await m.login("nobody", "wrong", "10.0.0.9", "t")
        return known, ex.value.detail
    known, unknown = asyncio.run(go(False))
    assert known == unknown and "남은 시도" not in known               # 있는 계정·없는 계정 응답 동일
    known, _ = asyncio.run(go(True))
    assert "남은 시도 4회" in known


def test_refresh_fqdn_keeps_external(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("prov", ROOT / "appliance/provision.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "config.yaml").write_text("server:\n  public_url: https://aiops.krvcf.com   # 외부\nsyslog:\n  advertise_host: old.lab\n"
                                     "agents:\n  public_url: https://old.lab:8630\n", encoding="utf-8")
    monkeypatch.setattr(P, "ETC", etc)
    monkeypatch.setattr(P, "write", lambda p, t, *a: Path(p).write_text(t, encoding="utf-8"))
    monkeypatch.setattr(P.subprocess, "run", lambda *a, **k: None)
    P.refresh_fqdn("old.lab", {"fqdn": "new.lab"}, 8630)
    t = (etc / "config.yaml").read_text(encoding="utf-8")
    assert "public_url: https://aiops.krvcf.com" in t and "advertise_host: new.lab" in t and "public_url: https://new.lab:8630" in t


def _cfg_editor():
    s = (ROOT / "scripts/linux/cloudflare-tunnel.sh").read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", s, re.S)
    assert len(blocks) == 2
    return blocks[1]


def test_tunnel_script_config_idempotent(tmp_path):
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts/linux/cloudflare-tunnel.sh")]).returncode == 0
    ed = tmp_path / "ed.py"
    ed.write_text(_cfg_editor(), encoding="utf-8")
    cfg = tmp_path / "config.yaml"
    cfg.write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    import yaml
    for _ in range(2):
        subprocess.run(["python3", str(ed), str(cfg), "https://aiops.krvcf.com"], check=True, capture_output=True)
        d = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        assert d["server"]["public_url"] == "https://aiops.krvcf.com"
        assert d["server"]["external_hosts"] == ["aiops.krvcf.com"]
        assert d["server"]["trusted_proxies"] == "127.0.0.1"
        assert d["agents"]["public_url"] == "https://aiops.vcf.lab:8630"      # 내부 수신 주소 보존
        assert d["syslog"]["advertise_host"] == "aiops.vcf.lab"
    ctl = (ROOT / "scripts/linux/vcf-aiopsctl").read_text(encoding="utf-8")
    assert "cloudflare-tunnel.sh" in ctl and "|tunnel|" in ctl
