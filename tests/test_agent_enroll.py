"""에이전트 설치 명령 — Windows PowerShell 5.1 부트스트랩(스크립트블록 인증서 콜백 금지·curl.exe 재시도)·인증서 지문."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app.main as m  # noqa: E402


def test_windows_bootstrap_https():
    c = m._win_bootstrap("https://aiops.rangers.lab:8630", "-Token t -Kind vm", True)
    assert "{$true}" not in c and "ServerCertificateValidationCallback" not in c   # .NET I/O 스레드에서 Runspace 없음 → send 오류
    assert "ICertificatePolicy" in c and "$w.Proxy=$null" in c and "curl.exe -fsSk --noproxy '*'" in c
    assert "-SkipCertificateCheck" in c and c.rstrip().endswith("-Insecure")
    assert "-ExecutionPolicy Bypass" in c
    assert all(ord(ch) < 128 for ch in c)                                            # 콘솔 코드 페이지 무관


def test_windows_bootstrap_http_and_trust():
    c = m._win_bootstrap("http://10.0.0.5:8630", "-Token t -Kind vm", False)
    assert "AiopsTrust" not in c and "-Insecure" not in c and "curl.exe -fsS " in c
    t = m._win_trust("https://a:8630")
    assert "Import-Certificate" in t and "SHA256" in t and "GetCertHashString" not in t   # .NET 4.7.2(Server 2019 기본) 호환


def test_cert_download_route(tmp_path, monkeypatch):
    import asyncio
    crt = tmp_path / "aiops.crt"
    crt.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    monkeypatch.setitem(m.CFG["server"], "tls", {"certfile": str(crt)})
    r = asyncio.run(m.agent_file("aiops.crt"))               # /agents/{name} 가 먼저 매칭되므로 같은 핸들러에서 처리
    assert str(r.path) == str(crt)
