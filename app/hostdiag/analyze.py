"""호스트 분석(2.18.0) — 연결 끊김 구간(에피소드) 찾기 → 직전·직후 증거로 원인 후보 판정

근거(1차 출처, Broadcom KB):
  344682 'Troubleshooting an ESXi host in a "not responding"/"disconnected" state' — 일반 점검 순서, vpxd 로그 표식
  318647 'ESXi host disconnects intermittently from vCenter Server' — UDP 902 하트비트(10초 간격, 60초 안에 못 받으면 not responding,
         60초마다 반복되면 방화벽 차단 가능성), tcpdump·pktcap-uw 확인
  377738 'Troubleshooting Mass ESXi Host "Not Responding" States' — 다수 호스트 동시: 네트워크·스토리지·DNS·시간·vCenter·hostd/vpxa
  433257 'ESXi host shows "Not Responding" … hostd unresponsiveness' — vmkwarning 'hostd detected to be non-responsive'
  320280 관리 에이전트 재시작(Restarting the Management agents in ESXi)
"""
from __future__ import annotations

import re
import statistics
from typing import Any

from .parse import USER_RX, is_down, is_up

KB = {"general": "https://knowledge.broadcom.com/external/article/344682", "heartbeat": "https://knowledge.broadcom.com/external/article/318647",
      "mass": "https://knowledge.broadcom.com/external/article/377738", "hostd": "https://knowledge.broadcom.com/external/article/433257",
      "agents": "https://knowledge.broadcom.com/external/article/320280"}

# (원인 ID, 이름, [(정규식, 가중치)], 확인 방법, 근거 KB)
RULES: list[tuple[str, str, list[tuple[str, float]], list[str], str]] = [
    ("user", "사용자·작업에 의한 연결 해제", [(r"disconnect(ed)? host|DisconnectHost|userRequest|by user|\bremove host\b|ReconnectHost|enter(ing)? maintenance", 3)],
     ["작업(Task) 목록에서 실행 사용자·시각 확인", "자동화(PowerCLI·백업·패치 도구) 계정이면 해당 작업 일정 확인"], "general"),
    ("reboot", "호스트 재부팅·종료·전원 차단", [(r"HostShutdownEvent|shut ?down|reboot(ing|ed)?|power(ed)? off|Loading VMkernel|Boot complete|vmkernel: cpu0:.*Initializing|"
                                         r"esx\.audit\.(host\.boot|dcui\.host\.reboot|net\.firewall)|host.*powered on|BootStop|UEFI", 2.5)],
     ["vmkernel.log·vobd.log 부팅 시각과 직전 마지막 줄 확인", "BMC(SEL·IML) 전원·리셋 기록 확인 — '하드웨어 준비도'·Redfish 이벤트"], "general"),
    ("psod", "PSOD(퍼플 스크린)·커널 패닉", [(r"@BlueScreen|PSOD|PANIC|panic|NMI|Machine Check|MCE|coredump|vmkdump", 3)],
     ["/var/core 의 vmkernel-zdump 확인, `esxcli system coredump file list`", "펌웨어·드라이버 호환성(HCL) 확인 후 SR"], "general"),
    ("agent", "관리 에이전트(hostd·vpxa) 무응답·재시작", [(r"hostd detected to be non-responsive|hostd.*(not responding|unresponsive|crash|restart|exit|watchdog)|"
                                                  r"vpxa.*(crash|restart|exit|not responding|unresponsive|stopp)|Watchdog.*hostd|Restarting hostd|"
                                                  r"/etc/init\.d/(hostd|vpxa)|services\.sh restart|hostd.*started|vpxa.*started|ALERT:.*hostd", 2.5),
                                                 (r"hostd.*(blocked|timed out|timeout)|Task Created.*hostd", 1)],
     ["`/var/log/hostd.log`·`vpxa.log` 의 마지막 오류와 재시작 시각", "[변경] 관리 에이전트 재시작(DCUI › Troubleshooting Options › Restart Management Agents)"], "hostd"),
    ("heartbeat", "vCenter↔호스트 하트비트(UDP 902) 유실", [(r"heartbeat|NO_RESPONSE|not responding|udp.*902|902", 1.5), (r"HostConnectionLostEvent", 1)],
     ["ESXi: `pktcap-uw --uplink vmnicX --capture UplinkSndKernel --udpport 902 -o - | tcpdump-uw -enr -` 로 10초마다 송신 확인",
      "vCenter: `tcpdump src host <ESXi IP> and udp port 902` 로 수신 확인", "방화벽·ACL 의 UDP 902(호스트→vCenter) 허용 확인"], "heartbeat"),
    ("network", "관리 네트워크(링크·업링크·vmk0) 장애", [(r"link (is )?down|NIC Link is Down|linkstate\.down|link state down|esx\.problem\.net\.(vmnic\.linkstate\.down|connectivity\.lost|redundancy\.lost|"
                                                   r"dvport\.connectivity\.lost|dvport\.redundancy\.lost)|lost (uplink )?redundancy|lost network connectivity|vmk0.*(down|lost)|"
                                                   r"Duplicate IP|duplicate ip|LACP.*(down|fail)|beacon.*(fail|lost)|uplink.*(down|fail)", 3),
                                                  (r"vmnic\d+.*(down|reset|timeout|tx hang)|NETDEV WATCHDOG|tx (queue )?timeout", 2)],
     ["`esxcli network nic list`·`esxcli network ip interface list`(vmk0)", "물리 스위치 포트·LACP·VLAN(관리망) 로그 확인 — 인프라 점검 N01·N02", "vobd.log 의 중복 IP 경고 확인"], "general"),
    ("storage", "스토리지 APD/PDL 로 hostd 응답 지연", [(r"All Paths Down|\bAPD\b|apd\.start|esx\.problem\.storage\.apd|permanent device loss|\bPDL\b|"
                                                   r"Lost access to volume|lost connectivity to storage|path.*dead|state in doubt|NMP.*(failed|dead)|"
                                                   r"scsi.*(timeout|abort)|H:0x[1-9]", 2.5)],
     ["`esxcli storage core path list`·`esxcli storage core device list` 에서 dead·off 경로", "vobd.log 의 esx.problem.storage.* 시각과 끊김 시각 비교"], "mass"),
    ("resource", "호스트 자원 고갈(메모리·램디스크·파일 핸들)", [(r"out of memory|Memory exceeds hard limit|admission (control|check) fail|ramdisk.*full|"
                                                       r"visorfs.*(full|out of)|No space left|inode|resource pool.*(fail|limit)|cannot allocate|alloc.*fail", 2.5)],
     ["`vdf -h`(램디스크)·`localcli system visorfs ramdisk list`", "hostd 메모리 사용량·`/var/log/vmkernel.log` 의 할당 실패"], "general"),
    ("auth", "인증서·vpxuser 인증·SSL 문제", [(r"vpxuser|incorrect user name or password|Login failure|SSL|certificate|thumbprint|handshake|"
                                         r"HostCnxFailedBadUsernameEvent|HostCnxFailedNoAccessEvent|HostCnxFailedAccountFailedEvent", 2)],
     ["호스트 인증서 만료일(인프라 점검·RVTools)과 vCenter 'Certificate' 경고", "잠금 모드·vpxuser 비밀번호 변경 여부"], "general"),
    ("ha", "vSphere HA 격리·장애 판정", [(r"DasHostIsolatedEvent|isolat(ed|ion)|DasHostFailedEvent|vSphere HA.*(failed|isolat)|das\.host|fdm.*(isolat|fail)", 2.5)],
     ["HA 격리 주소 ping·하트비트 데이터스토어 확인", "격리 응답(종료·전원 끄기)으로 VM 영향 여부 — VM 액티비티"], "general"),
    ("time", "시간·DNS 문제", [(r"NTP|ntpd|clock (skew|drift|jump)|time ?sync|time.*out of sync|DNS|name resolution|could not resolve|resolv", 1.2)],
     ["`esxcli system ntp get`·`esxcli network ip dns server list`", "vCenter·ESXi 시각 차이"], "mass"),
    ("hardware", "하드웨어 오류(전원·메모리·IPMI)", [(r"IPMI|SEL|power supply|PSU|ECC|uncorrectable|memory (error|fault)|fan|thermal|temperature|CPU.*(error|throttl)", 1.5)],
     ["BMC SEL/IML·하드웨어 상태(vCenter Hardware Health)", "서버 벤더 진단"], "general"),
]
_RX = [(cid, name, [(re.compile(p, re.I), w) for p, w in pats], checks, kb) for cid, name, pats, checks, kb in RULES]


def episodes(items: list[dict], end: float, flap_merge: float = 0) -> list[dict]:
    """연결 끊김 구간 — DOWN 표식에서 시작, UP 표식에서 끝(없으면 진행 중)"""
    eps: list[dict] = []
    cur: dict | None = None
    for it in sorted(items, key=lambda x: x["ts"]):
        if it.get("kind") not in ("event", "vpxd"):          # 끊김 판정은 vCenter 쪽 기록(이벤트·vpxd)으로만 — 호스트 자신의 로그 문구는 증거로만
            continue
        if is_down(it):
            if cur is None:
                cur = {"start": it["ts"], "end": None, "trigger": it, "markers": [it]}
                eps.append(cur)
            else:
                cur["markers"].append(it)
        elif is_up(it) and cur is not None:
            cur["end"] = it["ts"]
            cur["recover"] = it
            cur = None
    for e in eps:
        e["duration"] = (e["end"] or end) - e["start"]
        e["ongoing"] = e["end"] is None
        tr = e["trigger"]
        e["user_initiated"] = bool(tr.get("type") == "HostDisconnectedEvent" and (tr.get("user") or USER_RX.search(tr.get("message") or "")))
    return eps


def judge(ep: dict, items: list[dict], before: float = 1800, after: float = 600, peers: list[dict] | None = None,
          state: dict | None = None, syslog_rate: dict | None = None) -> dict:
    """한 에피소드: [시작-before, 시작+after](재부팅 증거는 복구 후 10분까지) 증거로 원인 점수"""
    s0 = ep["start"]
    hi = (ep["end"] or s0) + after
    win = [it for it in items if s0 - before <= it["ts"] <= hi]
    scores: dict[str, dict] = {}
    for it in win:
        txt = f"{it.get('type', '')} {it.get('message', '')}"
        near = 1.0 if abs(it["ts"] - s0) <= 300 else (0.6 if it["ts"] < s0 else 0.4)     # 끊김 직전·직후 5분 가중
        for cid, name, pats, checks, kb in _RX:
            for rx, w in pats:
                if rx.search(txt):
                    sc = scores.setdefault(cid, {"id": cid, "title": name, "score": 0.0, "evidence": [], "checks": checks, "kb": KB[kb]})
                    if len(sc["evidence"]) < 12:
                        sc["evidence"].append({k: it.get(k) for k in ("ts", "kind", "source", "message", "type", "user")})
                    sc["score"] += w * near
                    break
    notes: list[str] = []
    # 사용자 작업
    if ep.get("user_initiated"):
        sc = scores.setdefault("user", {"id": "user", "title": "사용자·작업에 의한 연결 해제", "score": 0.0, "evidence": [ep["trigger"]],
                                        "checks": _RX[0][3], "kb": KB["general"]})
        sc["score"] += 6
    tasks = [it for it in win if it.get("kind") == "task" and it.get("user") and re.search(r"disconnect|reconnect|reboot|shutdown|maintenance|remove", it.get("message", ""), re.I)
             and s0 - 300 <= it["ts"] <= s0 + 60]
    if tasks:
        sc = scores.setdefault("user", {"id": "user", "title": "사용자·작업에 의한 연결 해제", "score": 0.0, "evidence": [], "checks": _RX[0][3], "kb": KB["general"]})
        sc["score"] += 4
        sc["evidence"] = tasks[:5] + sc["evidence"]
    # 부팅 시각이 구간 안 → 재부팅 확정
    bt = (state or {}).get("boot_time")
    if bt and s0 - 300 <= bt <= (ep["end"] or s0 + 3600) + 300:      # 끊김 직전 ~ 복구 사이에 부팅
        sc = scores.setdefault("reboot", {"id": "reboot", "title": "호스트 재부팅·종료·전원 차단", "score": 0.0, "evidence": [], "checks": _RX[1][3], "kb": KB["general"]})
        sc["score"] += 6
        sc["evidence"].insert(0, {"ts": bt, "kind": "state", "source": "vcenter", "message": "호스트 부팅 시각(runtime.bootTime)이 이 구간 안"})
    # syslog: 끊김 중에도 들어왔으면 호스트·관리망은 살아 있음 → 하트비트·에이전트 쪽, 끊겼으면 네트워크·전원 쪽
    sl = [it for it in items if it.get("kind") == "log" and it.get("via") == "syslog"]
    if sl and not ep.get("user_initiated") and "user" not in scores:
        during = [it for it in sl if s0 + 30 <= it["ts"] <= (ep["end"] or s0 + 630) - 30]     # 끊김·복구 경계 30초 제외
        prior = [it for it in sl if s0 - 1800 <= it["ts"] < s0]
        if prior and not during and (ep["end"] or 0) - s0 > 90:
            notes.append("끊김 동안 이 호스트의 syslog 도 끊김 → 관리망 단절·호스트 정지 쪽 가능성(하트비트만의 문제는 아님)")
            for k, add in (("network", 2.0), ("reboot", 1.0), ("psod", 0.5)):
                if k in scores:
                    scores[k]["score"] += add
        elif during:
            notes.append(f"끊김 동안에도 syslog {len(during)}줄 수신 → 호스트·네트워크(수집 서버 방향)는 살아 있음 → 하트비트(UDP 902) 경로·vpxa/hostd 쪽 가능성")
            for k, add in (("heartbeat", 2.5), ("agent", 1.5)):
                sc = scores.setdefault(k, {"id": k, "title": next(x[1] for x in _RX if x[0] == k), "score": 0.0, "evidence": [],
                                           "checks": next(x[3] for x in _RX if x[0] == k), "kb": KB[next(x[4] for x in _RX if x[0] == k)]})
                sc["score"] += add
    elif syslog_rate is not None and not syslog_rate.get("lines_24h"):
        notes.append("이 호스트의 syslog 를 받고 있지 않아 끊김 당시 호스트 쪽 로그가 없습니다 — '로그 전송 설정'에서 ESXi syslog 를 이 서버로 지정하면 다음부터 근거가 남습니다")
    # 다수 호스트 동시
    if peers:
        notes.append(f"같은 시각(±2분) 다른 호스트 {len(peers)}대도 끊김: {', '.join(sorted({p['host'] for p in peers})[:8])} → 공통 원인(네트워크·vCenter·스토리지·DNS) 우선(KB 377738)")
        for k, add in (("network", 1.5), ("storage", 1.0), ("time", 0.8)):
            if k in scores:
                scores[k]["score"] += add
        sc = scores.setdefault("mass", {"id": "mass", "title": "다수 호스트 동시 끊김(공통 원인)", "score": 0.0, "evidence": [], "kb": KB["mass"],
                                        "checks": ["vCenter 자체 상태(vpxd 재시작·CPU·DB)·관리망 스위치·방화벽", "같은 시각 스토리지 어레이·DNS·NTP 이벤트"]})
        sc["score"] += 2 + len(peers)
        sc["evidence"] = [{"ts": p["ts"], "kind": "peer", "source": "vcenter", "message": f"{p['host']}: {p['message']}"} for p in peers[:8]]
    # 관리 IP 불일치(KB 344682 — 관리 IP 확인)
    st = state or {}
    if st.get("vc_managed_ip") and st.get("vc_ip_seen_by_host") and st["vc_managed_ip"] != st["vc_ip_seen_by_host"]:
        notes.append(f"vCenter 관리 IP 설정({st['vc_managed_ip']})과 호스트가 아는 vCenter IP({st['vc_ip_seen_by_host']})가 다름 → 하트비트가 다른 주소로 감(KB 344682)")
        sc = scores.setdefault("heartbeat", {"id": "heartbeat", "title": _RX[4][1], "score": 0.0, "evidence": [], "checks": _RX[4][3], "kb": KB["heartbeat"]})
        sc["score"] += 4
    ranked = sorted(scores.values(), key=lambda x: -x["score"])
    top = ranked[0]["score"] if ranked else 0
    for r in ranked:
        r["score"] = round(r["score"], 1)
        r["confidence"] = "높음" if r["score"] >= 6 and r["score"] >= top * 0.8 else ("중간" if r["score"] >= 3 else "낮음")
    if not ranked:
        notes.append("구간 안에 원인을 가리키는 로그가 없습니다 — vpxd·hostd·vobd 로그가 회전됐거나 syslog 미수집일 수 있음. 아래 기본 점검(KB 344682) 순서로 확인")
    return {"start": s0, "end": ep["end"], "duration": round(ep["duration"]), "ongoing": ep["ongoing"], "user_initiated": ep["user_initiated"],
            "trigger": {k: ep["trigger"].get(k) for k in ("ts", "kind", "source", "type", "message", "user")},
            "recover": {k: (ep.get("recover") or {}).get(k) for k in ("ts", "type", "message")} if ep.get("recover") else None,
            "causes": ranked[:5], "notes": notes, "window": [s0 - before, hi], "items_in_window": len(win)}


def pattern(eps: list[dict]) -> list[str]:
    """반복 패턴 — 60초 주기(방화벽 UDP 902, KB 318647)·잦은 짧은 끊김·같은 시각대"""
    out = []
    if len(eps) >= 3:
        gaps = [b["start"] - a["start"] for a, b in zip(eps, eps[1:])]
        durs = [e["duration"] for e in eps if not e["ongoing"]]
        if gaps and 40 <= statistics.median(gaps) <= 90:
            out.append(f"끊김이 약 {int(statistics.median(gaps))}초 간격으로 반복 — UDP 902 하트비트가 막혔을 때의 전형(KB 318647: 60초마다 반복 시 방화벽 차단 가능성)")
        if durs and statistics.median(durs) <= 180:
            out.append(f"대부분 {int(statistics.median(durs))}초 안에 복구되는 짧은 끊김 {len(eps)}회 — 하트비트 손실(혼잡·순간 단절)·에이전트 지연 쪽")
        hours = [int((e["start"] % 86400) // 3600) for e in eps]
        top = max(set(hours), key=hours.count)
        if hours.count(top) >= max(3, len(eps) * 0.6):
            out.append(f"주로 같은 시간대(UTC {top}시)에 발생 — 백업·스냅숏·보안 스캔·배치 작업 일정과 겹치는지 확인(KB 318647: 스냅숏 stun 도 원인)")
    return out


def timeline(vc: dict | None, stored: list[dict], name: str) -> list[dict]:
    """vCenter API(이벤트·작업·vpxd·호스트 로그) + 저장 로그(이 제품이 수집한 vCenter 이벤트·ESXi syslog·호스트 로그) → 중복 제거 타임라인"""
    out: list[dict] = []
    seen: set = set()

    def add(it):
        k = (int(it["ts"]), (it.get("message") or "")[:90])
        if k in seen:
            return
        seen.add(k)
        out.append(it)
    for x in (vc or {}).get("events", []):
        add({"ts": x["ts"], "kind": "event", "source": "vcenter", "type": x["type"], "severity": x["severity"], "message": x["message"],
             "entity": x.get("entity"), "user": x.get("user"), "via": "api"})
    for x in (vc or {}).get("tasks", []):
        if x.get("ts"):
            add({"ts": x["ts"], "kind": "task", "source": "vcenter", "type": "Task", "severity": "error" if x.get("error") else "info",
                 "message": f"작업 {x['name']} · {x['state']}" + (f" · {x['error']}" if x.get("error") else "") + (f" · {x['entity']}" if x.get("entity") else ""),
                 "user": x.get("user"), "via": "api", "end": x.get("end")})
    for x in (vc or {}).get("logs", []):
        kind = "vpxd" if x["source"].startswith("vpxd") else "hostlog"
        add({"ts": x["ts"], "kind": kind, "source": x["source"], "message": x["message"], "via": "vcenter", "severity": _sev(x["message"])})
    for r in stored:
        try:
            import json as _j
            at = _j.loads(r.get("attrs") or "{}") if isinstance(r.get("attrs"), str) else (r.get("attrs") or {})
        except Exception:  # noqa: BLE001
            at = {}
        src = r.get("source") or ""
        if src == "vcenter":
            kind, typ = "event", at.get("eventType") or ""
        elif src == "esxi":
            kind, typ = "log", ""
        else:
            kind, typ = "log", ""
        via = "syslog" if src == "esxi" and at.get("via") != "BrowseDiagnosticLog" else ("hostlog" if at.get("via") == "BrowseDiagnosticLog" else "pipeline")
        add({"ts": r["ts"], "kind": kind, "source": (r.get("entity") if via == "hostlog" else src) or src, "type": typ,
             "severity": r.get("severity") or "info", "message": r.get("message") or "", "user": at.get("user"), "via": via,
             "host": r.get("host"), "id": r.get("id")})
    out.sort(key=lambda x: x["ts"])
    return out


def _sev(msg: str) -> str:
    m = (msg or "").lower()
    if re.search(r"\b(panic|critical|alert|emerg)\b", m):
        return "critical"
    if re.search(r"\b(error|fail|failed|lost|down|dead)\b", m):
        return "error"
    if re.search(r"\b(warn|warning|timeout|retry)\b", m):
        return "warning"
    return "info"


def analyze(name: str, vc: dict | None, stored: list[dict], start: float, end: float, peers_fn=None, syslog_rate: dict | None = None,
            before: float = 1800, after: float = 600) -> dict[str, Any]:
    items = timeline(vc, stored, name)
    eps = episodes(items, end)
    out_eps = []
    for ep in eps[-50:]:
        peers = peers_fn(ep["start"]) if peers_fn else []
        out_eps.append(judge(ep, items, before, after, peers, (vc or {}).get("state"), syslog_rate))
    srcs: dict[str, int] = {}
    for it in items:
        k = f"{it['kind']}:{it.get('via')}"
        srcs[k] = srcs.get(k, 0) + 1
    return {"host": name, "start": start, "end": end, "items": items, "episodes": out_eps[::-1], "patterns": pattern(eps),
            "counts": {"episodes": len(eps), "items": len(items), "by_source": srcs,
                       "downtime_s": round(sum(e["duration"] for e in eps)), "ongoing": any(e["ongoing"] for e in eps)}}
