#!/usr/bin/env python3
"""안드로이드 API 수준 점검(2.52.0) — 앱이 minSdk(26)보다 새 API 를 SDK_INT 확인 없이 부르면 실패.

방법: 앱 소스를 android-34.jar 로 컴파일 → 각 .class 의 상수 풀에서 android.* 호출·필드 참조를 뽑음(우리 클래스를 거친 호출은
상속을 따라 실제 안드로이드 클래스로 바꿈) → android-23.jar(Debian android-sdk-platform-23)에 없는 멤버만 골라
KNOWN(이 앱이 쓰는 API 24+ 목록과 도입 수준)과 대조. KNOWN 에 없는 새 API 는 '검토 필요'로 실패,
도입 수준 > minSdk 인 것은 그 소스 파일에 'SDK_INT >= N'(또는 '< N') 확인이 있어야 통과.
사용: python3 scripts/dev/android-api-check.py [mobile/sensor|mobile/android]  — 결과 JSON 출력, 문제 있으면 종료 코드 1
"""
import functools
import glob
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
J34 = "/home/claude/work/android-sdk/android-34.jar"
J23 = "/usr/lib/android-sdk/platforms/android-23/android.jar"
MIN_SDK = 26
# 이 앱들이 쓰는 API 23 이후 멤버와 도입 수준(developer.android.com 레퍼런스의 'Added in API level')
KNOWN = {
    ("android/app/NotificationChannel", "*"): 26,
    ("android/app/NotificationManager", "createNotificationChannel"): 26,
    ("android/app/NotificationManager", "getNotificationChannel"): 26,
    ("android/app/NotificationManager", "areNotificationsEnabled"): 24,
    ("android/app/Notification$Builder", "<init>"): 26,              # (Context, channelId) 생성자
    ("android/content/Context", "startForegroundService"): 26,
    ("android/content/ContextWrapper", "startForegroundService"): 26,
    ("android/app/Service", "startForeground"): 29,                  # (int, Notification, int) — 2개짜리는 API 5
    ("android/os/PowerManager", "getCurrentThermalStatus"): 29,
    ("android/content/pm/PackageInfo", "getLongVersionCode"): 28,
    ("android/app/job/JobInfo$Builder", "setPeriodic"): 21,
    ("android/os/HandlerThread", "join"): 1,                         # Thread 상속(오탐 방지)
    ("android/os/HandlerThread", "start"): 1,
    # 2.53.0 기기 소유자 원격 설정
    ("android/app/admin/DevicePolicyManager", "setPermissionGrantState"): 23,
    ("android/app/admin/DevicePolicyManager", "setKeyguardDisabled"): 23,
    ("android/app/admin/DevicePolicyManager", "reboot"): 24,
    ("android/app/admin/DevicePolicyManager", "setSystemSetting"): 28,
    # 운영자 앱(mobile/android)
    ("android/app/Activity", "getMainExecutor"): 28,
    ("android/content/Context", "getMainExecutor"): 28,
    ("android/app/job/JobScheduler", "getPendingJob"): 24,
    ("android/hardware/biometrics/BiometricPrompt", "*"): 28,
    ("android/hardware/biometrics/BiometricPrompt$AuthenticationCallback", "*"): 28,
    ("android/hardware/biometrics/BiometricPrompt$AuthenticationResult", "*"): 28,
    ("android/hardware/biometrics/BiometricPrompt$Builder", "*"): 28,
    ("android/hardware/biometrics/BiometricPrompt$Builder", "setAllowedAuthenticators"): 30,
    ("android/hardware/biometrics/BiometricPrompt$Builder", "setDeviceCredentialAllowed"): 29,
    ("android/net/http/SslCertificate", "getX509Certificate"): 29,
    ("android/provider/MediaStore$Downloads", "*"): 29,
    ("android/webkit/WebResourceRequest", "isRedirect"): 24,
}


def javap(args):
    return subprocess.run(["javap", *args], capture_output=True, text=True).stdout


_SIG: dict = {}


def prefetch(cp, classes):
    """여러 클래스를 javap 한 번으로 읽어 둠(JVM 을 클래스마다 띄우면 수 분 걸림). 없는 클래스는 None"""
    todo = sorted({c for c in classes if (cp, c) not in _SIG})
    for i in range(0, len(todo), 200):
        part = todo[i:i + 200]
        out = subprocess.run(["javap", "-public", "-classpath", cp, *[c.replace("/", ".") for c in part]], capture_output=True, text=True).stdout
        blocks = re.split(r"(?m)^(?=Compiled from )", out)
        got = {}
        for b in blocks:
            m = re.search(r"(?m)^(?:public |protected )?(?:abstract |final |static )*(?:class|interface|enum) ([\w.$]+)", b)
            if m:
                got[m.group(1).replace(".", "/")] = b
        for c in part:
            _SIG[(cp, c)] = got.get(c)


def sig(cp, cls):
    if (cp, cls) not in _SIG:
        prefetch(cp, [cls])
    return _SIG[(cp, cls)]


@functools.lru_cache(None)
def has_member(cp, cls, name):
    """cls 또는 그 상위 클래스·인터페이스에 name 멤버가 있는가(cp 기준)"""
    while cls:
        t = sig(cp, cls)
        if t is None:
            return False
        if name == "<init>" or re.search(r"[\s.]" + re.escape(name) + r"\(|\s" + re.escape(name) + r";", t):
            return True
        m = re.search(r"(?:class|interface) [\w.$]+(?:<[^>]*>)? extends ([\w.$]+)", t)
        cls = m.group(1).replace(".", "/") if m and m.group(1) != "java.lang.Object" else None
    return False


def main(app="mobile/sensor"):
    app_dir = Path(app) if Path(app).is_absolute() else ROOT / app
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "gen").mkdir()
        (td / "cls").mkdir()
        subprocess.run(["aapt", "package", "-f", "-m", "-J", str(td / "gen"), "-M", str(app_dir / "AndroidManifest.xml"), "-S", str(app_dir / "res"),
                        "-I", J34], check=True, capture_output=True)
        srcs = [str(p) for p in app_dir.rglob("*.java")] + [str(p) for p in (td / "gen").rglob("*.java")]
        r = subprocess.run(["javac", "-Xlint:all", "-Xlint:-options", "-source", "8", "-target", "8", "-encoding", "UTF-8", "-bootclasspath", J34,
                            "-d", str(td / "cls"), *srcs], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr)
            return {"ok": False, "error": "compile"}
        warns = [w for w in r.stderr.splitlines() if ": warning:" in w and "[options]" not in w]
        ours = {}                                                       # 우리 클래스 → 상위 클래스
        refs = set()
        files = glob.glob(str(td / "cls" / "**" / "*.class"), recursive=True)
        allv = javap(["-v", *files])                                    # 한 번에(파일마다 JVM 을 띄우지 않음)
        chunks = re.split(r"(?m)^(?=Classfile )", allv)
        for out in chunks:
            hm = re.match(r"Classfile (\S+)", out)
            if not hm:
                continue
            c = hm.group(1)
            me = re.search(r"this_class: #\d+\s+// ([\w/$]+)", out)
            su = re.search(r"super_class: #\d+\s+// ([\w/$]+)", out)
            if me and su:
                ours[me.group(1)] = su.group(1)
            for m in re.finditer(r"= (?:Methodref|InterfaceMethodref|Fieldref)\s+#\d+\.#\d+\s+// ([\w/$]+)\.(\"?<?[\w$]+>?\"?):", out):
                refs.add((m.group(1), m.group(2).strip('"'), Path(c).name.split("$")[0].replace(".class", "")))
            for m in re.finditer(r"= Class\s+#\d+\s+// (android/[\w/$]+)", out):
                refs.add((m.group(1), "*", Path(c).name.split("$")[0].replace(".class", "")))
        need = {o for o, _, _ in refs if o.startswith("android/")} | {v for v in ours.values() if v.startswith("android/")}
        for cp in (J23, J34):
            prefetch(cp, need)
            for _ in range(6):                                          # 상위 클래스도 미리
                sup = set()
                for c in need:
                    t = sig(cp, c) or ""
                    m = re.search(r"(?:class|interface) [\w.$]+(?:<[^>]*>)? extends ([\w.$]+)", t)
                    if m and m.group(1).startswith("android."):
                        sup.add(m.group(1).replace(".", "/"))
                sup -= {c for (p, c) in _SIG if p == cp}
                if not sup:
                    break
                prefetch(cp, sup)
                need |= sup
        found, unknown, unguarded = [], [], []
        for owner, name, src in sorted(refs):
            cls = owner
            while cls in ours:                                          # 우리 클래스를 거친 호출 → 실제 안드로이드 상위 클래스
                cls = ours[cls]
            if not cls.startswith("android/"):
                continue
            if name == "*":
                if sig(J23, cls) is not None:
                    continue
            elif has_member(J23, cls, name) and not (cls, name) in KNOWN:
                continue
            if name != "*" and not has_member(J34, cls, name):
                continue
            api = KNOWN.get((cls, name)) or KNOWN.get((cls, "*"))
            if api is None:
                # 상위 클래스 이름으로도 찾기(ContextWrapper·Activity → Context 등)
                for (kc, kn), v in KNOWN.items():
                    if kn == name and has_member(J34, cls, name) and sig(J34, kc) and kc.split("/")[-1] in javap(["-public", "-classpath", J34, cls.replace("/", ".")]):
                        api = v
                        break
            item = {"class": cls, "member": name, "in": src, "api": api}
            if api is None:
                unknown.append(item)
                continue
            found.append(item)
            if api > MIN_SDK:
                text = "\n".join(Path(p).read_text(encoding="utf-8") for p in srcs if Path(p).stem == src)
                guards = [(op, int(n)) for op, n in re.findall(r"SDK_INT\s*(>=|==|>|<)\s*(\d+)", text)]
                ok = any((op in (">=", "==", "<") and n >= api) or (op == ">" and n >= api - 1) for op, n in guards)
                if not ok:
                    unguarded.append(item)
        res = {"ok": not unknown and not unguarded, "min_sdk": MIN_SDK, "new_api": found, "unknown": unknown,
               "unguarded": unguarded, "lint_warnings": warns}
        return res


if __name__ == "__main__":
    out = main(sys.argv[1] if len(sys.argv) > 1 else "mobile/sensor")
    print(json.dumps(out, ensure_ascii=False, indent=1))
    sys.exit(0 if out.get("ok") else 1)
