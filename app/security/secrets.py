"""비밀값 암호화 저장.

  Windows : DPAPI(CryptProtectData, LOCAL_MACHINE 범위) — 키 관리 불필요, 같은 서버에서만 복호화
  기타 OS : Fernet(AES-128-CBC+HMAC) — data/secret.key (0600)
저장 형식  "enc:dpapi:<base64>" / "enc:fernet:<token>"
config.yaml · .env · 운영 설정(DB) 어디에 있든 로드 시 자동 복호화.

CLI:  python -m app.security.secrets encrypt        (입력값 암호화 → 붙여넣을 문자열 출력)
"""
from __future__ import annotations

import base64
import ctypes
import os
import sys
from pathlib import Path
from typing import Any

PREFIX = "enc:"
_ENTROPY = b"vcf-aiops/v1"


# ------------------------------------------------------------------ Windows DPAPI (ctypes, pywin32 불필요)
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(b: bytes) -> _BLOB:
    buf = ctypes.create_string_buffer(b, len(b))
    return _BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    crypt32 = ctypes.windll.crypt32          # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32        # type: ignore[attr-defined]
    CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_LOCAL_MACHINE = 0x1, 0x4
    out = _BLOB()
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    args = (ctypes.byref(_blob(data)), None, ctypes.byref(_blob(_ENTROPY)), None, None,
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ctypes.byref(out))
    if not fn(*args):
        raise OSError(f"DPAPI {'암호화' if encrypt else '복호화'} 실패 (Win32 오류 {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


# ------------------------------------------------------------------ Fernet (비 Windows)
def _key_path() -> Path:
    return Path(os.environ.get("AIOPS_SECRET_KEY_FILE", "data/secret.key"))


def _fernet():
    from cryptography.fernet import Fernet
    p = _key_path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(Fernet.generate_key())
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return Fernet(p.read_bytes().strip())


def encrypt(plain: str) -> str:
    if not plain or str(plain).startswith(PREFIX):
        return plain
    if sys.platform == "win32":
        return PREFIX + "dpapi:" + base64.b64encode(_dpapi(plain.encode("utf-8"), True)).decode()
    return PREFIX + "fernet:" + _fernet().encrypt(plain.encode("utf-8")).decode()


def decrypt(value: Any) -> Any:
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    kind, _, data = value[len(PREFIX):].partition(":")
    if kind == "dpapi":
        if sys.platform != "win32":
            raise ValueError("DPAPI로 암호화된 값은 해당 Windows 서버에서만 복호화할 수 있습니다")
        return _dpapi(base64.b64decode(data), False).decode("utf-8")
    if kind == "fernet":
        return _fernet().decrypt(data.encode()).decode("utf-8")
    raise ValueError(f"알 수 없는 암호화 형식: {kind}")


def decrypt_tree(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: decrypt_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decrypt_tree(v) for v in obj]
    return decrypt(obj)


SECRET_FIELDS = ("password", "remote_password", "api_key", "api_token", "token", "auth_key", "priv_key", "community",
                 "keyfile_password", "bind_password", "client_secret", "secret")


MASK = "********"
URL_PARENTS = ("webhooks", "webhook")          # 이 키 아래의 url 은 비밀(Slack·Teams 웹훅 주소 = 자격 증명)
DEST_FIELDS = ("host", "hosts", "supervisor", "base_url", "url", "instance")   # 비밀값이 전송되는 대상


def is_secret(k: Any, parent: str = "") -> bool:
    """2.30.0 비밀 필드 판정 — 이름(SECRET_FIELDS) + headers 딕셔너리의 모든 값 + 웹훅 url(alerting.webhooks[].url · itsm.webhook.url)"""
    return k in SECRET_FIELDS or parent == "headers" or (k == "url" and parent in URL_PARENTS)


def encrypt_tree(obj: Any, _parent: str = "") -> Any:
    """비밀 필드(is_secret)인 값만 암호화. communities 목록 등은 그대로. (복호화는 enc: 접두사 기준이라 평문으로 저장된 기존 값도 그대로 읽힘)"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and v and is_secret(k, _parent) and not v.startswith("${"):
                out[k] = encrypt(v)
            else:
                out[k] = encrypt_tree(v, str(k))
        return out
    if isinstance(obj, list):
        return [encrypt_tree(v, _parent) for v in obj]
    return obj


def mask_tree(obj: Any, _parent: str = "") -> Any:
    """화면 전송용 — 비밀 필드는 존재 여부만 표시"""
    if isinstance(obj, dict):
        return {k: (MASK if is_secret(k, _parent) and v else mask_tree(v, str(k))) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_tree(v, _parent) for v in obj]
    return obj


def _pair(new: list, old: Any) -> list:
    """목록 항목 ↔ 저장된 항목 짝(이름이 있으면 이름, 없으면 순서)"""
    ol = old if isinstance(old, list) else []
    if new and all(isinstance(x, dict) and x.get("name") for x in new):
        by = {x.get("name"): x for x in ol if isinstance(x, dict)}
        return [by.get(x["name"]) for x in new]
    return [ol[i] if i < len(ol) else None for i in range(len(new))]


def keep_masked(new: Any, old: Any, parent: str = "") -> Any:
    """화면에서 '********' 그대로 온 headers 값·웹훅 url → 저장된 값 유지(이름 기준 비밀 필드는 settings_store._keep_secrets 가 처리).
    저장된 값이 없으면 ValueError(다시 입력 요청) — 마스크 문자열이 실제 값으로 저장되는 일 방지"""
    if isinstance(new, dict):
        o = old if isinstance(old, dict) else {}
        out = {}
        for k, v in new.items():
            if v == MASK and is_secret(k, parent) and k not in SECRET_FIELDS:
                if not o.get(k):
                    raise ValueError(f"'{parent}.{k}' 의 저장된 값이 없습니다 — 값을 다시 입력하세요(이름을 바꿨다면 URL·헤더도 다시 입력)")
                out[k] = o[k]
            else:
                out[k] = keep_masked(v, o.get(k), str(k))
        return out
    if isinstance(new, list):
        return [keep_masked(x, o, parent) for x, o in zip(new, _pair(new, old))]
    return new


def _norm(v: Any) -> Any:
    if isinstance(v, list):
        return sorted(str(x or "").strip().lower().rstrip("/") for x in v)
    return str(v if v is not None else "").strip().lower().rstrip("/")


def mask_redirect(new: Any, old: Any, parent: str = "") -> str | None:
    """2.30.0 연결 시험 보호 — '********'(저장된 비밀로 대체될 값)를 보내면서 대상(host·url 등)을 저장된 것과 다르게 바꿨으면 그 필드 이름.
    저장된 비밀이 요청 본문이 지정한 다른 서버로 전송되는 것을 막는다(None = 문제 없음)"""
    if isinstance(new, dict):
        o = old if isinstance(old, dict) else {}
        hd = new.get("headers")
        if any(v == MASK and is_secret(k, parent) for k, v in new.items()) or (isinstance(hd, dict) and MASK in hd.values()):
            for f in DEST_FIELDS:
                if (f in new or f in o) and new.get(f) != MASK:
                    a, b = _norm(new.get(f)), _norm(o.get(f))
                    if (not set(a) <= set(b)) if isinstance(a, list) and isinstance(b, list) else a != b:
                        return f
        for k, v in new.items():
            if isinstance(v, (dict, list)):
                bad = mask_redirect(v, o.get(k), str(k))
                if bad:
                    return bad
        return None
    if isinstance(new, list):
        for x, o in zip(new, _pair(new, old)):
            bad = mask_redirect(x, o, parent)
            if bad:
                return bad
    return None


if __name__ == "__main__":
    import getpass
    if len(sys.argv) > 1 and sys.argv[1] == "encrypt":
        v = getpass.getpass("암호화할 값: ")
        print(encrypt(v))
    else:
        print("사용법: python -m app.security.secrets encrypt")
