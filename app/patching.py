"""웹 콘솔 패치 — 업로드한 번들을 서비스 계정이 먼저 검사(서명·무결성·버전)하고, 적용은 root 유닛이 서명을 다시 확인한 뒤 수행.

  PUT  /api/system/patch          번들 업로드(본문 = .tgz) → incoming/ 저장 + 검사 결과(매니페스트)
  POST /api/system/patch/apply    {"file": 업로드 결과의 file} → patches/request.json → vcf-aiops-patch.path → root: vcf-aiopsctl patch-request
  POST /api/system/patch/rollback 직전 백업으로 되돌리기 요청
  GET  /api/system/version        현재 버전·이미지·패치 상태·기록·백업

서비스 계정(aiops)은 /opt/vcf-aiops 에 쓸 수 없다(ProtectSystem=strict). 그래서 적용 권한은 root 유닛에만 있고, root 쪽은
설치된 신뢰 공개 키(appliance/patch/patch-signing.pub, /etc/vcf-aiops/patch-trust/*.pub)로 서명을 확인한 번들만 실행한다.
(2.30.0) 서명은 manifest.json 만 덮으므로 번들 안의 모든 파일은 manifest 의 SHA-256(payload_sha256·apply_sha256·files)과 같아야 한다
— apply_sha256 은 필수. 백업 폴더는 root 전용(0700)이라 목록은 root 가 써 주는 색인 사본 patches/backups.json 으로 읽는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ETC = Path(os.environ.get("AIOPS_ETC", "/etc/vcf-aiops"))
MAX_BYTES = 400 * 1024 * 1024
UNIT = Path("/etc/systemd/system/vcf-aiops-patch.path")


def data_dir() -> Path:
    return Path(os.environ.get("AIOPS_WORKDIR") or os.getcwd())


def pdir() -> Path:
    p = data_dir() / "patches"
    (p / "incoming").mkdir(parents=True, exist_ok=True)
    return p


def current_version() -> str:
    try:
        return (ROOT / "VERSION").read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def _vt(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v or "0")[:4])


def trusted_keys() -> list[Path]:
    ks = [ROOT / "appliance" / "patch" / "patch-signing.pub"]
    try:
        ks += sorted((ETC / "patch-trust").glob("*.pub"))
    except OSError:
        pass
    return [k for k in ks if k.is_file()]


def key_fingerprint(path: Path) -> str:
    """공개 키 지문 = DER(SubjectPublicKeyInfo)의 SHA-256 — `vcf-aiopsctl trust-key list` 와 같은 값. 읽을 수 없으면 ''"""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
    try:
        der = load_pem_public_key(path.read_bytes()).public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except (OSError, ValueError, TypeError):
        return ""
    return hashlib.sha256(der).hexdigest()


def _member_sha(tf: tarfile.TarFile, m: tarfile.TarInfo) -> str:
    h = hashlib.sha256()
    f = tf.extractfile(m)
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def verify_bundle(path: Path) -> dict[str, Any]:
    """번들 구조·서명(Ed25519)·product·모든 파일의 SHA-256(manifest 기준) 확인. 실패하면 ValueError(사유)"""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    try:
        tf = tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise ValueError(f"tar.gz 아님: {e}") from e
    with tf:
        names = {m.name: m for m in tf.getmembers()}
        bad = [n for n in names if n.startswith("/") or ".." in n.split("/")]
        if bad:
            raise ValueError(f"허용되지 않는 경로: {bad[0]}")
        mf = next((n for n in names if n.endswith("/manifest.json") and n.count("/") == 1), None)
        if not mf:
            raise ValueError("manifest.json 이 없습니다 — VCF AIops 패치 번들이 아닙니다")
        top = mf.split("/")[0]
        need = [f"{top}/manifest.sig", f"{top}/payload.tar.gz", f"{top}/apply.sh"]
        miss = [n for n in need if n not in names]
        if miss:
            raise ValueError(f"번들에 없음: {', '.join(m.split('/')[-1] for m in miss)}")
        mbytes = tf.extractfile(names[mf]).read()
        sig = tf.extractfile(names[f"{top}/manifest.sig"]).read()
        keys = trusted_keys()
        if not keys:
            raise ValueError("이 설치본에 신뢰 공개 키가 없습니다 — CLI(sudo bash apply.sh)로 적용하세요")
        who = ""
        for k in keys:
            try:
                load_pem_public_key(k.read_bytes()).verify(sig, mbytes)
                who = k.name
                break
            except (InvalidSignature, ValueError, TypeError):
                continue
        if not who:
            raise ValueError("서명 검증 실패 — 신뢰하는 키로 서명된 번들이 아닙니다")
        try:
            m = json.loads(mbytes)
        except ValueError as e:
            raise ValueError(f"manifest.json 형식 오류: {e}") from e
        if not isinstance(m, dict) or m.get("product") != "vcf-aiops":
            raise ValueError(f"다른 제품의 번들: {m.get('product') if isinstance(m, dict) else ''}")
        for k in ("version", "payload_sha256", "apply_sha256"):          # (2.30.0) apply_sha256 필수 — 없으면 apply.sh 가 서명 범위 밖
            if not isinstance(m.get(k), str) or not m[k]:
                raise ValueError(f"manifest 에 {k} 가 없습니다 — 이 번들은 적용할 수 없습니다")
        extra = m.get("files") or {}
        if not isinstance(extra, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in extra.items()):
            raise ValueError("manifest files 형식 오류")
        exp = {**extra, "payload.tar.gz": m["payload_sha256"], "apply.sh": m["apply_sha256"]}
        label = {"payload.tar.gz": "payload SHA-256 불일치 — 번들 손상", "apply.sh": "apply.sh SHA-256 불일치 — 번들 변조"}
        for rel, want in exp.items():
            mem = names.get(f"{top}/{rel}")
            if mem is None or not mem.isfile():
                raise ValueError(f"번들에 없음: {rel}")
            if _member_sha(tf, mem) != want:
                raise ValueError(label.get(rel, f"{rel} SHA-256 불일치 — 번들 변조"))
        for n, mem in names.items():                                     # manifest 가 덮지 않는 파일·링크·장치 파일은 거부
            rel = n[len(top) + 1:] if n.startswith(top + "/") else ("" if n == top else None)
            if rel is None or not (mem.isdir() or mem.isfile()):
                raise ValueError(f"허용되지 않는 항목: {n}")
            if mem.isfile() and rel not in exp and rel not in ("manifest.json", "manifest.sig"):
                raise ValueError(f"manifest 에 없는 파일(서명 범위 밖): {rel}")
    return {**m, "signed_by": who, "size": path.stat().st_size, "sha256": _sha(path)}


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def save_upload(stream, filename: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename or "patch.tgz").name)[:120] or "patch.tgz"
    if not safe.endswith((".tgz", ".tar.gz")):
        safe += ".tgz"
    d = pdir() / "incoming"
    for old in d.glob("*"):                          # 이전 업로드 정리(한 번에 하나)
        if time.time() - old.stat().st_mtime > 60:
            old.unlink(missing_ok=True)
    dst = d / f"{int(time.time())}-{safe}"
    n = 0
    with dst.open("wb") as f:
        async for chunk in stream:
            n += len(chunk)
            if n > MAX_BYTES:
                f.close()
                dst.unlink(missing_ok=True)
                raise ValueError(f"번들이 너무 큽니다(최대 {MAX_BYTES // 2**20}MB)")
            f.write(chunk)
    os.chmod(dst, 0o640)
    return dst


def request(action: str, file: str = "", by: str = "", force: bool = False) -> dict[str, Any]:
    """root 유닛에 넘길 요청. force=True 는 같은 버전 재적용·하향 허용 — root 쪽(vcf-aiopsctl patch-request)도 다시 확인한다"""
    if not UNIT.exists():
        raise RuntimeError("이 설치본에는 웹 패치 적용 유닛(vcf-aiops-patch.path)이 없습니다 — 서버에서 sudo vcf-aiopsctl patch <번들> 로 적용하세요")
    rq = pdir() / "request.json"
    if rq.exists():
        raise RuntimeError("이미 처리 중인 패치 요청이 있습니다")
    st = status()
    if st.get("state") in ("running", "rolling_back") and time.time() - float(st.get("ts") or 0) < 1800:
        raise RuntimeError("패치가 진행 중입니다")
    tmp = rq.with_suffix(".tmp")
    tmp.write_text(json.dumps({"action": action, "file": file, "by": by, "force": bool(force), "ts": time.time()}))
    os.chmod(tmp, 0o640)
    tmp.replace(rq)
    st_tmp = pdir() / "status.json.web"
    st_tmp.write_text(json.dumps({"state": "queued", "step": "적용 대기(root 패치 서비스)" if action == "apply" else "롤백 대기(root 패치 서비스)",
                                  "ts": time.time(), "by": f"web:{by}"}))
    st_tmp.replace(pdir() / "status.json")            # root 소유 파일도 디렉터리 쓰기 권한으로 교체
    return {"queued": True}


def status() -> dict[str, Any]:
    try:
        return json.loads((pdir() / "status.json").read_text())
    except (OSError, ValueError):
        return {}


def _backups(p: Path) -> list[dict[str, Any]]:
    """백업 목록 — (2.30.0) root 가 쓰는 색인 사본 patches/backups.json. 없으면(아직 이관 전) 예전처럼 backup/ 을 직접 읽는다"""
    try:
        j = json.loads((p / "backups.json").read_text(encoding="utf-8"))
        out = []
        for b in j.get("backups", []):
            if isinstance(b, dict) and re.fullmatch(r"vcf-aiops-[0-9A-Za-z._-]+", str(b.get("name", ""))):
                out.append({"name": b["name"], "version": str(b.get("version", "")), "size_mb": b.get("size_mb", 0), "db": bool(b.get("db")),
                            "ts": b.get("ts", 0), "sha256": str(b.get("sha256", "")), "legacy": bool(b.get("legacy"))})
        return sorted(out, key=lambda x: x["ts"] or 0, reverse=True)
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    backups = []
    try:
        for b in sorted((p / "backup").glob("vcf-aiops-*"), key=lambda x: x.stat().st_mtime, reverse=True):
            sz = sum(f.stat().st_size for f in b.rglob("*") if f.is_file())
            backups.append({"name": b.name, "version": (b / "VERSION").read_text().strip() if (b / "VERSION").exists() else "",
                            "size_mb": round(sz / 2**20, 1), "db": (b / "aiops.db").exists(), "ts": b.stat().st_mtime})
    except OSError:
        pass
    return backups


def _release() -> dict[str, Any]:
    """apply.sh 가 성공 뒤 쓰는 /opt/vcf-aiops/release.json {version, from, applied_at, notes}"""
    try:
        j = json.loads((ROOT / "release.json").read_text(encoding="utf-8"))
        return j if isinstance(j, dict) else {}
    except (OSError, ValueError):
        return {}


def info() -> dict[str, Any]:
    p = pdir()
    hist = []
    try:
        for ln in (p / "history.jsonl").read_text().splitlines()[-30:]:
            try:
                hist.append(json.loads(ln))
            except ValueError:
                pass
    except OSError:
        pass
    backups = _backups(p)
    rel = ""
    try:
        rel = Path("/etc/vcf-aiops-appliance-release").read_text().splitlines()[0]
    except (OSError, IndexError):
        pass
    keys = trusted_keys()
    return {"version": current_version(), "appliance": rel, "status": status(), "history": list(reversed(hist)), "backups": backups,
            "web_apply": UNIT.exists(), "release": _release(),
            "trusted_keys": [k.name for k in keys],                       # 이름 목록(이전 화면 호환)
            "trusted_keys_info": [{"name": k.name, "sha256": key_fingerprint(k),
                                   "source": "installed" if k.parent != ETC / "patch-trust" else "trust-dir"} for k in keys]}


def newer(m: dict) -> bool:
    return _vt(m.get("version", "")) > _vt(current_version())
