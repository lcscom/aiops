"""2.48.1 — Ubuntu 24.04/26.04 배포 자동화(deploy.sh) · 배포 zip"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
L = ROOT / "scripts" / "linux"


def test_shell_syntax():
    for f in ("deploy.sh", "install.sh", "uninstall.sh", "build-offline.sh"):
        subprocess.run(["bash", "-n", str(L / f)], check=True)


def test_deploy_supports_both_lts_and_modes():
    s = (L / "deploy.sh").read_text(encoding="utf-8")
    assert "ubuntu-24.04|ubuntu-26.04" in s and "24.04|26.04|22.04" in (L / "install.sh").read_text(encoding="utf-8")
    for opt in ("--check", "--upgrade", "--uninstall", "--purge", "--offline", "--build-offline", "--env", "--yes|-y"):
        assert f"{opt})" in s, opt
    assert "sha256sum -c" in s and "dist/vcf-aiops-ubuntu.zip" in s                  # 내려받은 zip 은 SHA-256 확인 후 사용
    assert '"${SHOW//$PAIS_KEY/****}"' in s or "SHOW//$PAIS_KEY/****" in s           # 기록에 PAIS 키 가림
    assert "read -rs" in s                                                             # 키 입력은 화면에 안 보이게


def test_env_example_keys_are_understood():
    s = (L / "deploy.sh").read_text(encoding="utf-8")
    keys = re.findall(r"^([A-Z_]+)=", (ROOT / "deploy.env.example").read_text(encoding="utf-8"), re.M)
    assert keys and all(f"{k})" in s for k in keys), keys


def test_docs():
    d = (ROOT / "docs" / "DEPLOY-UBUNTU.md").read_text(encoding="utf-8")
    for k in ("26.04", "24.04", "--build-offline", "--upgrade", "--uninstall", "secret.key"):
        assert k in d
