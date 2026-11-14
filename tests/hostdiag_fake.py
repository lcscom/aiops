"""합성 '호스트 연결 끊김' 시나리오(시험·개발용) — 실제 고객 데이터 없음

esx05.lab.example 에서 세 번 끊김 + 같은 시각 esx06 도 끊김:
  ① now-6h  관리망 링크 다운(vmnic0 link down → vobd connectivity lost) → not responding 5분, 그 동안 syslog 도 끊김, esx06 동시
  ② now-3h  hostd 무응답(vmkwarning 'hostd detected to be non-responsive' → hostd 재시작) → 3분, syslog 는 계속 들어옴
  ③ now-1h  사용자 admin 이 연결 해제(작업 + HostDisconnectedEvent Reason: userRequest) → 2분 뒤 재연결
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

H, PEER, CL = "esx05.lab.example", "esx06.lab.example", "Cluster-01"


def _z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "123Z"


def rows(now: float | None = None, host: str = H, peer: str = PEER) -> list[dict]:
    now = now or time.time()
    H, PEER = host, peer  # noqa: N806
    t0, t1, t2 = now - 6 * 3600, now - 3 * 3600, now - 3600
    out: list[dict] = []

    def ev(ts, msg, typ, host=None, sev="error", user=""):
        host = host or H
        out.append({"ts": ts, "source": "vcenter", "severity": sev, "host": host, "entity": host, "kind": "event", "message": msg,
                    "attrs": json.dumps({"eventType": typ, "user": user})})

    def sl(ts, prog, msg, sev="info", host=None):
        host = host or H
        out.append({"ts": ts, "source": "esxi", "severity": sev, "host": host, "entity": prog, "kind": "log",
                    "message": f"{_z(ts)} {prog}: {msg}", "attrs": "{}"})
    # 배경 syslog(30초마다) — ① 끊김 동안은 없음
    t = now - 8 * 3600
    while t < now:
        if not (t0 + 20 <= t <= t0 + 300):
            sl(t, "hostd", "Task Completed : haTask-ha-host-vim.HostSystem.retrieveInternalCapability")
        t += 30
    # ① 네트워크
    sl(t0 - 40, "vmkernel", "cpu12:2098)vmnic0: NIC Link is Down", "error")
    sl(t0 - 35, "vobd", "[netCorrelator] esx.problem.net.vmnic.linkstate.down: Physical NIC vmnic0 linkstate is down", "error")
    sl(t0 - 30, "vobd", "esx.problem.net.connectivity.lost: Lost network connectivity on virtual switch vSwitch0. Physical NIC vmnic0 is down. Affected portgroups: Management Network", "error")
    ev(t0, f"Host {H} in {CL} is not responding", "HostConnectionLostEvent")
    ev(t0 + 40, f"Host {PEER} in {CL} is not responding", "HostConnectionLostEvent", host=PEER)
    sl(t0 + 305, "vmkernel", "cpu12:2098)vmnic0: NIC Link is Up 25000 Mbps", "info")
    ev(t0 + 310, f"Connected to {H} in {CL}", "HostConnectedEvent", sev="info")
    ev(t0 + 330, f"Connected to {PEER} in {CL}", "HostConnectedEvent", host=PEER, sev="info")
    # ② hostd
    sl(t1 - 120, "vmkwarning", "cpu3:2097)ALERT: hostd detected to be non-responsive", "critical")
    sl(t1 - 60, "hostd", "Watchdog: hostd not responding, restarting", "error")
    ev(t1, f"Host {H} in {CL} is not responding", "HostConnectionLostEvent")
    sl(t1 + 60, "hostd", "hostd started — version 8.0.3", "info")
    ev(t1 + 180, f"Connected to {H} in {CL}", "HostConnectedEvent", sev="info")
    # ③ 사용자
    ev(t2 - 2, f"Task: Disconnect host {H}", "TaskEvent", sev="info", user="LAB\\admin")
    ev(t2, f"Disconnected from {H} in {CL}. Reason: userRequest", "HostDisconnectedEvent", user="LAB\\admin")
    ev(t2 + 120, f"Connected to {H} in {CL}", "HostConnectedEvent", sev="info", user="LAB\\admin")
    return out


async def seed(store, now: float | None = None, start_id: int = 900000000, host: str = H, peer: str = PEER) -> int:
    rs = rows(now, host, peer)
    for i, r in enumerate(rs):
        await store.x("INSERT INTO logs(id,ts,source,connector,severity,host,entity,kind,message,score,template,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (start_id + i, r["ts"], r["source"], "lab-vc" if r["source"] == "vcenter" else "syslog", r["severity"], r["host"], r["entity"], r["kind"],
                       r["message"], 0, "", r["attrs"]))
    return len(rs)
