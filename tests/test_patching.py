"""패치 번들 검사 — 신뢰 키 서명·payload 무결성·apply.sh 변조·다른 키·버전 비교."""
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import patching  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
KEY = Path.home() / ".vcf-aiops" / "patch-signing.key"


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    if not KEY.exists() or not shutil.which("openssl"):
        pytest.skip("서명 키·openssl 없음")
    out = tmp_path_factory.mktemp("p")
    subprocess.run(["bash", str(ROOT / "appliance/patch/build-patch.sh"), "--version", "9.9.9", "--out", str(out)], check=True, capture_output=True)
    return out / "vcf-aiops-patch-9.9.9.tgz"


def _rewrite(src: Path, dst: Path, member: str, data: bytes):
    with tarfile.open(src) as t, tarfile.open(dst, "w:gz") as o:
        for m in t.getmembers():
            f = t.extractfile(m) if m.isfile() else None
            b = f.read() if f else None
            if m.name.endswith(member):
                b = data
                m.size = len(b)
            o.addfile(m, io.BytesIO(b) if b is not None else None)


def test_good_bundle(bundle):
    m = patching.verify_bundle(bundle)
    assert m["version"] == "9.9.9" and m["signed_by"] == "patch-signing.pub" and patching.newer(m)


def test_tampered_payload(bundle, tmp_path):
    bad = tmp_path / "bad.tgz"
    _rewrite(bundle, bad, "/payload.tar.gz", b"evil")
    with pytest.raises(ValueError, match="payload"):
        patching.verify_bundle(bad)


def test_tampered_apply(bundle, tmp_path):
    bad = tmp_path / "bad2.tgz"
    _rewrite(bundle, bad, "/apply.sh", b"#!/bin/sh\nrm -rf /\n")
    with pytest.raises(ValueError, match="apply.sh"):
        patching.verify_bundle(bad)


def test_manifest_edit_breaks_signature(bundle, tmp_path):
    with tarfile.open(bundle) as t:
        mf = json.loads(t.extractfile(next(m for m in t.getmembers() if m.name.endswith("manifest.json"))).read())
    mf["version"] = "10.0.0"
    bad = tmp_path / "bad3.tgz"
    _rewrite(bundle, bad, "/manifest.json", json.dumps(mf).encode())
    with pytest.raises(ValueError, match="서명"):
        patching.verify_bundle(bad)


def test_not_a_bundle(tmp_path):
    p = tmp_path / "x.tgz"
    p.write_bytes(b"hello")
    with pytest.raises(ValueError):
        patching.verify_bundle(p)


def test_version_compare(monkeypatch):
    monkeypatch.setattr(patching, "current_version", lambda: "1.2.0")
    assert patching.newer({"version": "1.3.0"}) and patching.newer({"version": "1.2.1"}) and not patching.newer({"version": "1.2.0"})


# ------------------------------------------------------------------ (2.30.0) 서명 범위·필수 필드·지문·백업 색인
def _resign(src: Path, dst: Path, work: Path, mutate):
    """번들을 풀어 mutate(폴더, manifest dict) 한 뒤 manifest 를 다시 쓰고 '진짜 키'로 다시 서명 — 서명은 맞지만 내용이 이상한 번들"""
    with tarfile.open(src) as t:
        t.extractall(work, filter="data") if hasattr(tarfile, "data_filter") else t.extractall(work)
    top = next(p for p in work.iterdir() if p.is_dir())
    m = json.loads((top / "manifest.json").read_text())
    mutate(top, m)
    (top / "manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=1))
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(KEY), "-rawin", "-in", str(top / "manifest.json"),
                    "-out", str(top / "manifest.sig")], check=True, capture_output=True)
    with tarfile.open(dst, "w:gz") as o:
        o.add(top, arcname=top.name)
    return dst


def test_manifest_fields(bundle):
    m = patching.verify_bundle(bundle)
    assert m["product"] == "vcf-aiops" and m["python_tag"] == "cp312" and len(m["apply_sha256"]) == 64
    assert "patch-signing.pub" in m["files"]                 # payload·apply.sh 밖의 파일도 전부 해시가 있어야 함


def test_apply_sha256_is_mandatory(bundle, tmp_path):
    bad = _resign(bundle, tmp_path / "noapply.tgz", tmp_path / "w", lambda top, m: m.pop("apply_sha256"))
    with pytest.raises(ValueError, match="apply_sha256"):    # 서명은 유효 — 그래도 거부
        patching.verify_bundle(bad)


def test_file_outside_manifest_refused(bundle, tmp_path):
    def add(top, m):
        (top / "wheelhouse").mkdir()
        (top / "wheelhouse" / "evil-1.0.tar.gz").write_bytes(b"sdist with setup.py")
    bad = _resign(bundle, tmp_path / "extra.tgz", tmp_path / "w", add)
    with pytest.raises(ValueError, match="manifest 에 없는 파일"):
        patching.verify_bundle(bad)


def test_other_product_refused(bundle, tmp_path):
    bad = _resign(bundle, tmp_path / "other.tgz", tmp_path / "w", lambda top, m: m.update(product="something-else"))
    with pytest.raises(ValueError, match="다른 제품"):
        patching.verify_bundle(bad)


def test_info_fingerprints(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_WORKDIR", str(tmp_path))
    i = patching.info()
    assert i["trusted_keys"] == ["patch-signing.pub"]         # 이름 목록은 그대로(화면 호환)
    k = i["trusted_keys_info"][0]
    assert k["name"] == "patch-signing.pub" and k["source"] == "installed" and len(k["sha256"]) == 64
    if shutil.which("openssl"):                               # vcf-aiopsctl trust-key list 와 같은 값(DER 의 SHA-256)
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(ROOT / "appliance/patch/patch-signing.pub"), "-outform", "DER"],
                             check=True, capture_output=True).stdout
        import hashlib
        assert k["sha256"] == hashlib.sha256(der).hexdigest()
    assert patching.key_fingerprint(tmp_path / "missing.pub") == ""


def test_info_backups_from_index(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_WORKDIR", str(tmp_path))
    p = patching.pdir()
    b = p / "backup" / "vcf-aiops-1.0.0-20250101-000000"      # 색인이 없으면(이관 전) 예전처럼 폴더를 읽는다
    b.mkdir(parents=True)
    (b / "VERSION").write_text("1.0.0\n")
    (b / "code.tar.gz").write_bytes(b"x" * 10)
    got = patching.info()["backups"]
    assert [x["name"] for x in got] == [b.name] and got[0]["version"] == "1.0.0"
    (p / "backups.json").write_text(json.dumps({"v": 1, "backups": [                       # 색인이 있으면 색인만 — 읽을 수 없는 root 전용 폴더를 뒤지지 않음
        {"name": "vcf-aiops-2.29.0-20261110-010101", "version": "2.29.0", "ts": 200, "size_mb": 9.5, "db": True, "sha256": "ab" * 32},
        {"name": "vcf-aiops-2.28.0-20260101-010101", "version": "2.28.0", "ts": 100, "size_mb": 9.1, "db": False, "sha256": "cd" * 32, "legacy": True},
        {"name": "../../etc", "version": "x", "ts": 300}, "junk"]}))
    got = patching.info()["backups"]
    assert [x["name"] for x in got] == ["vcf-aiops-2.29.0-20261110-010101", "vcf-aiops-2.28.0-20260101-010101"]
    assert got[0]["db"] is True and got[0]["sha256"] == "ab" * 32 and got[1]["legacy"] is True
    (p / "backups.json").write_text("{broken")                # 깨진 색인 → 폴더 읽기로 되돌아감
    assert [x["name"] for x in patching.info()["backups"]] == [b.name]


def test_request_carries_force(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_WORKDIR", str(tmp_path))
    unit = tmp_path / "unit"
    unit.write_text("")
    monkeypatch.setattr(patching, "UNIT", unit)
    patching.request("apply", "/x/incoming/1-a.tgz", "admin", force=True)
    rq = json.loads((patching.pdir() / "request.json").read_text())
    assert rq["force"] is True and set(rq) == {"action", "file", "by", "force", "ts"}       # root 쪽(patch-request)이 허용하는 필드와 같아야 함


# ------------------------------------------------------------------ vcf-aiopsctl(bash) — 가짜 PREFIX/ETC/DATA 로 검증 경로만 실행(root 불필요, 적용은 하지 않음)
@pytest.fixture()
def ctl(tmp_path):
    if not sys.platform.startswith("linux") or not shutil.which("openssl") or not shutil.which("bash"):
        pytest.skip("Linux·bash·openssl 필요")
    r = tmp_path / "root"
    for d in ("opt/appliance/patch", "etc", "data", "tmp"):
        (r / d).mkdir(parents=True)
    (r / "opt/VERSION").write_text("2.29.0\n")
    grp = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
    src = (ROOT / "scripts/linux/vcf-aiopsctl").read_text(encoding="utf-8")
    head = "SVC=vcf-aiops; ETC=/etc/vcf-aiops; DATA=/var/lib/vcf-aiops; PREFIX=/opt/vcf-aiops\n"
    assert head in src and 'TMPB=/var/tmp; RS="$ETC/patch-state"' in src and "USR=aiops " in src and "\n_need_root() {" in src
    src = src.replace(head, f"SVC=vcf-aiops; ETC={r}/etc; DATA={r}/data; PREFIX={r}/opt\n")
    src = src.replace('TMPB=/var/tmp; RS="$ETC/patch-state"', f'TMPB={r}/tmp; RS="$ETC/patch-state"').replace("USR=aiops ", f"USR={grp} ")
    src = "\n".join("_need_root() { :; }" if ln.startswith("_need_root() {") else ln for ln in src.split("\n"))   # 시험 사본에서만: root 확인 생략
    exe = tmp_path / "vcf-aiopsctl"
    exe.write_text(src, encoding="utf-8")

    def run(*args, stdin=""):
        return subprocess.run(["bash", str(exe), *map(str, args)], capture_output=True, text=True, input=stdin, timeout=120)
    run.root = r
    return run


def _gen_pub(path: Path, alg="ed25519", *opts):
    key = subprocess.run(["openssl", "genpkey", "-algorithm", alg, *opts], check=True, capture_output=True).stdout
    path.write_bytes(subprocess.run(["openssl", "pkey", "-pubout"], input=key, check=True, capture_output=True).stdout)
    return path


def test_ctl_refuses_tampered_apply(ctl, bundle, tmp_path):
    shutil.copy(ROOT / "appliance/patch/patch-signing.pub", ctl.root / "opt/appliance/patch/patch-signing.pub")
    ok = ctl("_verify-bundle", bundle)
    d = Path(ok.stdout.strip())
    assert ok.returncode == 0 and (d / "apply.sh").is_file() and str(d).startswith(str(ctl.root / "tmp"))
    assert oct(d.parent.parent.stat().st_mode & 0o777) == "0o700"          # 검증·실행은 소유자 전용 사본에서
    bad = tmp_path / "tampered.tgz"
    _rewrite(bundle, bad, "/apply.sh", b"#!/bin/sh\ntouch /tmp/pwned\n")     # manifest·서명은 그대로(유효)
    r = ctl("_verify-bundle", bad)
    assert r.returncode != 0 and r.stdout.strip() == "" and "apply.sh" in r.stderr and "불일치" in r.stderr
    bad2 = _resign(bundle, tmp_path / "noapply.tgz", tmp_path / "w", lambda top, m: m.pop("apply_sha256"))
    r = ctl("_verify-bundle", bad2)
    assert r.returncode != 0 and "apply_sha256" in r.stderr                # 필드가 없으면 서명이 맞아도 거부
    left = [p.name for p in (ctl.root / "tmp").iterdir()]
    assert left == [d.parent.parent.name]                                  # 거부된 번들의 임시 폴더는 남기지 않음


def test_ctl_trust_key_rotation(ctl, bundle, tmp_path):
    _gen_pub(ctl.root / "opt/appliance/patch/patch-signing.pub")           # 설치본은 '옛 키'만 신뢰
    r = ctl("_verify-bundle", bundle)
    assert r.returncode != 0 and "서명 검증 실패" in r.stderr
    new = ROOT / "appliance/patch/patch-signing.pub"
    no = ctl("trust-key", "add", new, "--name", "vcf-aiops-2026", stdin="no\n")
    assert no.returncode != 0 and not (ctl.root / "etc/patch-trust/vcf-aiops-2026.pub").exists()   # yes 를 입력해야 추가
    add = ctl("trust-key", "add", new, "--name", "vcf-aiops-2026", stdin="yes\n")
    fp = patching.key_fingerprint(new)
    assert add.returncode == 0 and fp in add.stdout
    inst = ctl.root / "etc/patch-trust/vcf-aiops-2026.pub"
    assert inst.read_bytes() == new.read_bytes() and oct(inst.stat().st_mode & 0o777) == "0o644"
    assert oct(inst.parent.stat().st_mode & 0o777) == "0o755"              # 웹 서비스 계정이 읽을 수 있어야 함
    hist = [json.loads(ln) for ln in (ctl.root / "data/patches/history.jsonl").read_text().splitlines()]
    assert hist[-1]["result"] == "trust_add" and fp in hist[-1]["detail"]
    ls = ctl("trust-key", "list")
    assert f"vcf-aiops-2026" in ls.stdout and f"SHA256:{fp}" in ls.stdout and ls.stdout.count("SHA256:") == 2
    r = ctl("_verify-bundle", bundle)
    assert r.returncode == 0 and Path(r.stdout.strip(), "manifest.json").is_file()
    rm = ctl("trust-key", "remove", "vcf-aiops-2026", "--yes")
    assert rm.returncode == 0 and not inst.exists()
    assert ctl("_verify-bundle", bundle).returncode != 0                   # 키를 빼면 다시 거부


def test_ctl_trust_key_rejects_bad_input(ctl, tmp_path):
    g = tmp_path / "garbage.pub"
    g.write_bytes(b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n")
    r = ctl("trust-key", "add", g, "--yes")
    assert r.returncode != 0 and "Ed25519" in r.stdout
    rsa = _gen_pub(tmp_path / "rsa.pub", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
    r = ctl("trust-key", "add", rsa, "--yes")
    assert r.returncode != 0 and "Ed25519" in r.stdout
    sp = _gen_pub(tmp_path / "bad name.pub")
    r = ctl("trust-key", "add", sp, "--yes")
    assert r.returncode != 0 and "이름" in r.stdout
    r = ctl("trust-key", "add", sp, "--yes", "--name", "../../x")
    assert r.returncode != 0
    assert not (ctl.root / "etc/patch-trust").exists()                     # 거부된 것은 아무것도 설치되지 않음
    assert ctl("trust-key", "remove", "nope", "--yes").returncode != 0


def test_build_refuses_stale_app_json(tmp_path):
    """APK 가 있는데 app.json 이 없거나 sha256·size 가 다르면 번들을 만들지 않는다"""
    if not KEY.exists() or not shutil.which("openssl"):
        pytest.skip("서명 키·openssl 없음")
    apk = ROOT / "app/static/app/vcf-aiops.apk"
    if not apk.exists():
        pytest.skip("APK 없음")
    src = tmp_path / "src"
    for d in ("appliance/patch", "app/static/app"):
        (src / d).mkdir(parents=True)
    for f in ("build-patch.sh", "apply.sh", "patch-signing.pub"):
        shutil.copy(ROOT / "appliance/patch" / f, src / "appliance/patch" / f)
    shutil.copy(apk, src / "app/static/app/vcf-aiops.apk")
    run = lambda: subprocess.run(["bash", str(src / "appliance/patch/build-patch.sh"), "--version", "9.9.9", "--out", str(tmp_path / "o"),  # noqa: E731
                                 "--key", str(KEY)], capture_output=True, text=True)
    r = run()
    assert r.returncode != 0 and "app.json 이 없습니다" in r.stderr
    j = json.loads((ROOT / "app/static/app/app.json").read_text())
    j["sha256"] = "0" * 64
    (src / "app/static/app/app.json").write_text(json.dumps(j))
    r = run()
    assert r.returncode != 0 and "맞지 않습니다" in r.stderr and not (tmp_path / "o" / "vcf-aiops-patch-9.9.9.tgz").exists()
