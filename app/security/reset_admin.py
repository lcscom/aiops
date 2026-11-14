"""웹 콘솔 로컬 관리자 비밀번호 긴급 재설정(break-glass) — 다른 관리자가 없거나 admin 이 잠겼을 때.

  Ubuntu : sudo vcf-aiopsctl reset-admin [사용자]          (서비스 중지 → 재설정 → 기동을 자동으로)
  Windows: 서비스 중지 후  .\\venv\\Scripts\\python.exe -m app.security.reset_admin [--user admin] → 서비스 시작

동작: 로컬 계정 비밀번호 교체 · 잠금 해제 · 실패 횟수 초기화 · 비활성 해제 · 역할 admin · 최초 로그인 시 변경 강제.
      계정이 없으면 로컬 관리자로 새로 만든다. LDAP 계정은 대상 아님. 감사 로그(해시 체인)에 기록.
      서비스가 실행 중이면 거부(실행 중 프로세스가 감사 체인 마지막 해시를 메모리에 들고 있어 체인이 깨지므로).
비밀번호: 대화형 입력(2회) · --password-stdin · --generate(정책 충족 16자 생성 후 1회 표시)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.config import load_config  # noqa: E402
from app.security.audit import _digest  # noqa: E402
from app.security.passwords import check_policy, generate_password, hash_password  # noqa: E402


def _service_running(port: int) -> bool:
    import socket
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="VCF AIops 로컬 관리자 비밀번호 긴급 재설정")
    ap.add_argument("user", nargs="?", default="admin", help="대상 로컬 계정(기본 admin)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="정책에 맞는 임의 비밀번호 생성 후 1회 표시")
    g.add_argument("--password-stdin", action="store_true", help="표준 입력 첫 줄을 비밀번호로 사용")
    ap.add_argument("--no-must-change", action="store_true", help="최초 로그인 시 변경 강제를 하지 않음(비권장)")
    ap.add_argument("--force", action="store_true", help="서비스 실행 여부 확인 생략(이미 중지한 경우만)")
    o = ap.parse_args()

    cfg = load_config()
    db = Path(cfg["server"]["db_path"])
    if not db.is_absolute():
        db = Path(os.environ.get("AIOPS_WORKDIR", ".")) / db
    if not db.exists():
        print(f"✖ DB 없음: {db} — 서비스를 한 번 이상 기동한 뒤 사용하세요", file=sys.stderr)
        return 2
    port = int(cfg["server"].get("port", 8630))
    if not o.force and _service_running(port):
        print(f"✖ 서비스가 실행 중입니다(포트 {port}). 먼저 중지하세요: sudo systemctl stop vcf-aiops "
              "(또는 sudo vcf-aiopsctl reset-admin 이 자동 처리)", file=sys.stderr)
        return 3
    policy = (cfg.get("auth") or {}).get("password") or {}
    user = o.user.strip()

    if o.generate:
        pw, shown = generate_password(), True
    elif o.password_stdin:
        pw, shown = sys.stdin.readline().rstrip("\r\n"), False
    else:
        pw = getpass.getpass(f"{user} 새 비밀번호: ")
        if pw != getpass.getpass("한 번 더: "):
            print("✖ 두 입력이 다릅니다", file=sys.stderr)
            return 4
        shown = False
    errs = check_policy(pw, user, policy)
    if errs:
        print("✖ 비밀번호 정책 위반: " + " / ".join(errs), file=sys.stderr)
        return 5

    con = sqlite3.connect(str(db), timeout=30)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA busy_timeout=30000")
        row = con.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
        if row and row["source"] != "local":
            print(f"✖ {user} 는 {row['source']} 계정입니다 — 로컬 계정만 재설정할 수 있습니다", file=sys.stderr)
            return 6
        h = hash_password(pw)
        now = time.time()
        must = 0 if o.no_must_change else 1
        if row:
            hist = (json.loads(row["pw_history"] or "[]") + [h])[-10:]
            con.execute("UPDATE users SET pw_hash=?, pw_history=?, pw_changed=?, must_change=?, failed=0, locked_until=0, "
                        "disabled=0, role='admin' WHERE username=?", (h, json.dumps(hist), now, must, user))
            action = "user.reset_admin_cli"
        else:
            con.execute("INSERT INTO users(username,display,email,role,source,pw_hash,pw_history,pw_changed,must_change,created) "
                        "VALUES(?,?,?,?,'local',?,?,?,?,?)",
                        (user, "로컬 관리자", "", "admin", h, json.dumps([h]), now, must, now))
            action = "user.create_admin_cli"
        # 감사 로그(해시 체인 이어서)
        last = con.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "GENESIS"
        who = "cli:" + (os.environ.get("SUDO_USER") or getpass.getuser())
        detail = json.dumps({"must_change": bool(must), "generated": shown}, ensure_ascii=False)
        ts = time.time()
        con.execute("INSERT INTO audit(ts,user,role,ip,action,target,result,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (ts, who, "admin", "local", action, user, "ok", detail, prev,
                     _digest(prev, ts, who, action, user, "ok", detail)))
        con.commit()
    finally:
        con.close()

    print(f"✔ {user} 비밀번호 {'생성' if action.startswith('user.create') else '재설정'} · 잠금 해제 · 역할 admin"
          + (" · 최초 로그인 시 변경 강제" if must else ""))
    if shown:
        print(f"  임시 비밀번호: {pw}   (지금만 표시)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
