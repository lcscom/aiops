"""비밀번호 해시·정책 — 외부 의존성 없이 PBKDF2-HMAC-SHA256 (OWASP 권고 600,000회)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import string

ITER = 600_000
ALGO = "pbkdf2_sha256"


def hash_password(pw: str, iterations: int = ITER) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
    return f"{ALGO}${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != ALGO:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), base64.b64decode(salt), int(it))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:  # noqa: BLE001
        return False


def check_policy(pw: str, username: str, policy: dict) -> list[str]:
    """정책 위반 사유 목록(빈 리스트면 통과). 기본: 9자 이상 · 영대/영소/숫자/특수 중 3종 · 아이디 포함 금지
    · 동일 문자 3회 연속 금지 · 연속 문자열(abc/123) 4자 금지."""
    errs: list[str] = []
    min_len = int(policy.get("min_length", 9))
    if len(pw) < min_len:
        errs.append(f"{min_len}자 이상이어야 합니다")
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    need = int(policy.get("classes", 3))
    if classes < need:
        errs.append(f"영문 대문자·소문자·숫자·특수문자 중 {need}종류 이상 조합해야 합니다")
    if username and len(username) >= 3 and username.lower() in pw.lower():
        errs.append("아이디를 포함할 수 없습니다")
    if re.search(r"(.)\1\1", pw):
        errs.append("같은 문자를 3번 이상 연속 사용할 수 없습니다")
    low = pw.lower()
    for seq in ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"):
        if any(seq[i:i + 4] in low or seq[::-1][i:i + 4] in low for i in range(len(seq) - 3)):
            errs.append("연속된 문자·숫자·키보드 배열(4자 이상)을 사용할 수 없습니다")
            break
    return errs


def generate_password(length: int = 16) -> str:
    """정책을 만족하는 임의 비밀번호(초기 관리자·재설정용)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if not check_policy(pw, "", {"min_length": length, "classes": 4}):
            return pw
