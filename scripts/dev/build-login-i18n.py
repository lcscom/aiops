#!/usr/bin/env python3
"""로그인 화면 전용 영어 사전(app/static/i18n-login.js) 생성 — 2.48.2

i18n-en.js(전체 사전)는 로그인 뒤에서만 내려가므로, 로그인 화면(login.html·login.js)에
실제로 나오는 한국어 문구만 골라 공개 사전을 따로 만든다.
사용: python3 scripts/dev/build-login-i18n.py   (i18n-en.js 나 로그인 화면 문구를 바꾼 뒤 실행)
"""
import json
import re
from pathlib import Path

S = Path(__file__).resolve().parents[2] / "app" / "static"
HANGUL = re.compile(r"[가-힣]")
# 공개 사전에 절대 들어가면 안 되는 문구(내부 명령·경로·프롬프트)
DENY = re.compile(r"vcf-aiopsctl|sudo |/etc/|/opt/|/api/|너는 |ClusterRole|apply\.sh")


def full_dict() -> dict:
    src = (S / "i18n-en.js").read_text(encoding="utf-8")
    body = src[src.index("{"): src.rindex("}") + 1]
    body = re.sub(r"(?m)^\s*/\*.*?\*/\s*$", "", body)        # 구역 표시 주석 줄
    body = re.sub(r",\s*}", "}", body)                           # 끝 쉼표
    return json.loads(body)


# 로그인 화면이 보여 주는 문구의 출처: 화면 파일 + 서버가 로그인 단계에서 돌려주는 메시지·기본 배너
SOURCES = ("static/login.html", "static/login.js", "security/auth.py", "security/oidc.py", "security/mfa.py",
           "security/passwords.py", "security/ldap_auth.py")


# 서버 코드에서는 화면으로 돌아가는 메시지만(HTTPException·detail·reason·message·error) — 감사·설정 문구는 넣지 않음
MSG = re.compile(r'(?:HTTPException\(\s*\d+\s*,\s*|"(?:detail|reason|message|error|msg)"\s*:\s*|ValueError\(\s*)f?"([^"]*[가-힣][^"]*)"')


def login_text() -> str:
    app = S.parent
    out = []
    for p in SOURCES:
        fp = app / p
        if not fp.is_file():
            continue
        t = fp.read_text(encoding="utf-8")
        out += [t] if p.startswith("static/") else MSG.findall(t)
    cfg = (app / "config.py").read_text(encoding="utf-8")
    out += re.findall(r'"login_banner":\s*"([^"]*)"', cfg)
    return "\n".join(out)


def build() -> dict:
    d, text = full_dict(), login_text()
    return {k: v for k, v in d.items() if HANGUL.search(k) and k in text and not DENY.search(k) and not DENY.search(v)}


def render(d: dict) -> str:
    lines = ",\n".join(f"{json.dumps(k, ensure_ascii=False)}: {json.dumps(v, ensure_ascii=False)}" for k, v in sorted(d.items()))
    return ("/* 자동 생성(scripts/dev/build-login-i18n.py): 로그인 화면 전용 한국어 → 영어 사전.\n"
            " * 전체 사전(i18n-en.js)은 로그인 뒤에서만 내려갑니다. 이 파일은 인증 없이 공개되므로 로그인 화면 문구만 담습니다. */\n"
            "window.AIOPS_I18N_EN = {\n" + lines + "\n};\n")


if __name__ == "__main__":
    d = build()
    (S / "i18n-login.js").write_text(render(d), encoding="utf-8")
    print(f"i18n-login.js: {len(d)} 문구")
