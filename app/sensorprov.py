"""현장 센서 설치·설정 스크립트(2.53.0) — PC 에서 adb 로 폰 하나를 한 번에 준비.

포털은 스크립트를 만들어 줄 뿐 실행하지 않는다(폰에 접속하는 것은 사용자의 PC). 스크립트가 하는 일:
  1) 센서 앱 내려받기(등록 코드로) → adb install -r -g (-g: 앱이 선언한 실행 권한을 설치 때 모두 허용)
  2) 배터리 최적화 제외(dumpsys deviceidle whitelist +패키지), 백그라운드 실행 허용(appops RUN_ANY_IN_BACKGROUND)
  3) (선택) 충전 중 화면 켜짐 유지(settings global stay_on_while_plugged_in 7)
  4) (선택) 기기 소유자 지정(dpm set-device-owner) — 계정이 없는 폰에서만 됨(초기화한 폰 권장). 지정하면 포털에서 권한·화면·잠금·재부팅 원격 설정
  5) 등록 링크 열기(vcfaiops-sensor://enroll?...) — 폰 화면에서 '등록'을 한 번 누름
무선(내부 IP): 폰과 PC 가 같은 내부망이면 USB 없이 — Android 11+ 는 개발자 옵션 › 무선 디버깅의 페어링 IP:포트·코드로 adb pair 후 connect,
그 이하는 USB 로 한 번 `adb tcpip 5555` 뒤 IP 로 connect.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import quote, urlsplit

PKG = "com.krvcf.aiopssensor"
IP_RX = re.compile(r"^[0-9A-Fa-f.:]{3,45}$")


def _ips() -> list[str]:
    out: list[str] = []
    try:                                                    # 기본 경로 인터페이스 IP(패킷은 보내지 않음)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        out.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(socket.gethostname(), None):
            if fam == socket.AF_INET:
                out.append(sa[0])
    except OSError:
        pass
    keep = []
    for ip in out:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not a.is_loopback and not a.is_link_local and ip not in keep:
            keep.append(ip)
    return keep


def addresses(public: str, request) -> list[dict]:
    """폰이 쓸 서버 주소 후보 — [{url, kind, note}]"""
    items: list[dict] = []

    def add(url: str, kind: str, note: str) -> None:
        url = url.rstrip("/")
        if url and all(i["url"] != url for i in items):
            items.append({"url": url, "kind": kind, "note": note})
    add(public, "public", "포털 공개 주소(설정의 public_url 또는 지금 접속한 주소)")
    here = f"{request.url.scheme}://{request.url.netloc}"
    add(here, "current", "지금 브라우저가 접속한 주소")
    port = request.url.port
    scheme = request.url.scheme
    for ip in _ips():
        p = f":{port}" if port and port not in (80, 443) else ""
        add(f"{scheme}://{ip}{p}", "internal", "서버 내부 IP — 폰이 같은 내부망(Wi-Fi)일 때")
    return items


def _q(v: str) -> str:
    """셸·배치에 넣을 값 — 허용 문자만(따옴표·명령 구분자 없음)"""
    if not re.fullmatch(r"[A-Za-z0-9:/._\-?=&%\[\]]*", v or ""):
        raise ValueError("허용하지 않는 문자가 들어 있습니다")
    return v


def scripts(d: dict, server: str, code: str, opts: dict, wl: dict) -> dict:
    server = _q(server.rstrip("/"))
    host = urlsplit(server).hostname or ""
    code = _q(code)
    ip = wl.get("phone_ip") or ""
    if ip and not IP_RX.match(ip):
        raise ValueError("폰 IP 형식이 맞지 않습니다")
    for k in ("phone_port", "pair_port", "pair_code"):
        if wl.get(k) and not re.fullmatch(r"\d{1,6}", wl[k]):
            raise ValueError(f"{k} 는 숫자만")
    port = wl.get("phone_port") or "5555"
    insecure = bool(opts.get("insecure"))
    apk_url = f"{server}/api/sensor/app.apk?c={quote(code)}" if code else ""
    link = f"vcfaiops-sensor://enroll?u={quote(server, safe='')}&c={quote(code)}" if code else ""
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", d["id"])[:30]

    sh = ["#!/usr/bin/env bash",
          f"# VCF AIops 현장 센서 — '{d['id']}' 폰 준비 스크립트(포털 › 현장 센서 › 설치 스크립트로 만듦)",
          "# 준비: PC 에 adb(Android platform-tools)·curl, 폰은 개발자 옵션 › USB 디버깅(또는 무선 디버깅) 켜기",
          "set -euo pipefail", 'ADB="${ADB:-adb}"', f'PKG="{PKG}"', ""]
    bat = ["@echo off", "chcp 65001 >nul", f"rem VCF AIops 현장 센서 — '{d['id']}' 폰 준비 스크립트",
           "rem 준비: adb(Android platform-tools)·curl(Windows 10 이상 기본), 폰은 USB 디버깅(또는 무선 디버깅) 켜기",
           "setlocal", 'if "%ADB%"=="" set ADB=adb', f"set PKG={PKG}", ""]
    if ip:
        sh += ["# 무선(내부 IP) 연결"]
        bat += ["rem 무선(내부 IP) 연결"]
        if wl.get("pair_port") and wl.get("pair_code"):
            sh.append(f'"$ADB" pair {ip}:{wl["pair_port"]} {wl["pair_code"]}')
            bat.append(f'"%ADB%" pair {ip}:{wl["pair_port"]} {wl["pair_code"]} || goto :err')
        sh.append(f'"$ADB" connect {ip}:{port}')
        bat.append(f'"%ADB%" connect {ip}:{port} || goto :err')
        sh.append(f'export ANDROID_SERIAL={ip}:{port}')
        bat.append(f"set ANDROID_SERIAL={ip}:{port}")
    sh += ['"$ADB" wait-for-device', 'echo "폰: $("$ADB" shell getprop ro.product.model) / Android $("$ADB" shell getprop ro.build.version.release)"', ""]
    bat += ['"%ADB%" wait-for-device || goto :err', ""]
    if apk_url:
        k = " -k" if insecure else ""
        sh += ["# 1) 센서 앱 설치(실행 권한 모두 허용)", f'curl -fsSL{k} -o /tmp/vcf-aiops-sensor-{name}.apk "{apk_url}"',
               f'"$ADB" install -r -g /tmp/vcf-aiops-sensor-{name}.apk', ""]
        bat += ["rem 1) 센서 앱 설치(실행 권한 모두 허용)", f'curl -fsSL{k} -o "%TEMP%\\vcf-aiops-sensor-{name}.apk" "{apk_url}" || goto :err',
                f'"%ADB%" install -r -g "%TEMP%\\vcf-aiops-sensor-{name}.apk" || goto :err', ""]
    steps_sh = ["# 2) 배터리 최적화 제외·백그라운드 실행 허용·알림 허용",
                '"$ADB" shell dumpsys deviceidle whitelist +$PKG',
                '"$ADB" shell cmd appops set $PKG RUN_ANY_IN_BACKGROUND allow || true',
                '"$ADB" shell pm grant $PKG android.permission.POST_NOTIFICATIONS 2>/dev/null || true']
    steps_bat = ["rem 2) 배터리 최적화 제외·백그라운드 실행 허용·알림 허용",
                 '"%ADB%" shell dumpsys deviceidle whitelist +%PKG%',
                 '"%ADB%" shell cmd appops set %PKG% RUN_ANY_IN_BACKGROUND allow',
                 '"%ADB%" shell pm grant %PKG% android.permission.POST_NOTIFICATIONS 2>nul']
    if opts.get("stay_awake"):
        steps_sh += ["# 3) 충전 중 화면 켜짐 유지", '"$ADB" shell settings put global stay_on_while_plugged_in 7']
        steps_bat += ["rem 3) 충전 중 화면 켜짐 유지", '"%ADB%" shell settings put global stay_on_while_plugged_in 7']
    if opts.get("owner"):
        steps_sh += ["# 4) 기기 소유자 지정 — 폰에 Google 등 계정이 없어야 됨(실패하면 설정 › 계정에서 모두 지운 뒤 다시)",
                     '"$ADB" shell dpm set-device-owner $PKG/.Admin || echo "기기 소유자 지정 실패 — 계정이 있으면 지우거나 초기화 후 다시(나머지 설정은 적용됨)"']
        steps_bat += ["rem 4) 기기 소유자 지정 — 폰에 Google 등 계정이 없어야 됨",
                      '"%ADB%" shell dpm set-device-owner %PKG%/.Admin || echo 기기 소유자 지정 실패 - 계정을 지우거나 초기화 후 다시']
    sh += steps_sh + [""]
    bat += steps_bat + [""]
    if link:
        sh += ["# 5) 등록 링크 열기 — 폰 화면에서 '등록'을 누르세요", f'"$ADB" shell am start -a android.intent.action.VIEW -d "{link}"']
        bat += ["rem 5) 등록 링크 열기 - 폰 화면에서 '등록'을 누르세요", f'"%ADB%" shell am start -a android.intent.action.VIEW -d "{link.replace("%", "%%")}"']
    else:
        sh += ["# 이미 등록된 폰 — 앱만 다시 열어 카메라·마이크·위치까지 켬", '"$ADB" shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null']
        bat += ["rem 이미 등록된 폰 - 앱 다시 열기", '"%ADB%" shell monkey -p %PKG% -c android.intent.category.LAUNCHER 1 >nul']
    sh += ['echo "완료 — 포털 › 현장 센서에서 이 폰의 앱 상태를 확인하세요"', ""]
    bat += ["echo 완료 - 포털 현장 센서에서 앱 상태를 확인하세요", "goto :eof", ":err", "echo 실패 - 위 메시지를 확인하세요", "exit /b 1", ""]
    note = []
    if code:
        note.append("등록 코드가 스크립트에 들어 있습니다(30분 안 1회용). 다 쓰면 지우세요.")
    if host and not re.fullmatch(r"[0-9.]+|\[?[0-9A-Fa-f:]+\]?", host):
        note.append(f"폰이 '{host}' 이름을 풀 수 있어야 합니다. 내부망이면 서버 내부 IP 주소를 고르세요.")
    if server.startswith("https://") and not insecure:
        note.append("서버가 사설 인증서면 '인증서 확인 건너뛰기'를 켜야 APK 를 받을 수 있습니다(앱은 처음 연결 때 지문을 보여 줌).")
    return {"server": server, "has_code": bool(code), "notes": note,
            "sh": {"name": f"sensor-setup-{name}.sh", "text": "\n".join(sh)},
            "bat": {"name": f"sensor-setup-{name}.bat", "text": "\r\n".join(bat)}}
