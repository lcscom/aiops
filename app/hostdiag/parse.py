"""호스트 분석(2.18.0) — 로그 줄 시각 해석·연결 끊김/복구 표식"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_TS = re.compile(r"^\s*(?:<\d+>\d?\s*)?(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?")


def line_ts(line: str) -> float | None:
    """ESXi(UTC 'Z')·vpxd(+09:00 등)·syslog(RFC5424) 줄 앞 ISO 시각 → epoch. 시간대 없으면 UTC"""
    m = _TS.match(line or "")
    if not m:
        return None
    try:
        dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{(m.group(3) or '')[:7]}")
        z = m.group(4)
        if not z or z == "Z":
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            z = z if ":" in z else z[:3] + ":" + z[3:]
            dt = datetime.fromisoformat(dt.isoformat() + z)
        return dt.timestamp()
    except ValueError:
        return None


# 연결 끊김(시작) — vCenter 이벤트 클래스·메시지, vpxd 로그(KB 344682: 'connection state changed to NO_RESPONSE / [DISCONNECTED]')
DOWN_TYPES = {"HostConnectionLostEvent", "HostDisconnectedEvent", "HostReconnectionFailedEvent", "HostCnxFailedTimeoutEvent",
              "HostCnxFailedNetworkErrorEvent", "HostCnxFailedNoConnectionEvent", "HostCnxFailedEvent", "HostSyncFailedEvent",
              "HostCnxFailedBadUsernameEvent", "HostCnxFailedNoAccessEvent", "HostCnxFailedAccountFailedEvent", "HostCnxFailedBadVersionEvent",
              "HostCnxFailedCcagentUpgradeEvent", "HostCnxFailedNotFoundEvent", "HostCnxFailedNoLicenseEvent", "HostCnxFailedAlreadyManagedEvent",
              "HostShutdownEvent"}
UP_TYPES = {"HostConnectedEvent", "HostReconnectedEvent"}
DOWN_RX = re.compile(r"(is not responding|not responding|connection (?:to .* )?lost|lost connection|disconnected from host|cannot synchronize host|"
                     r"connection state changed to \[?(?:NO_RESPONSE|DISCONNECTED)|host .* disconnected|cannot contact the specified host|"
                     r"host connection and power state.*(?:red|→ ?red|to red))", re.I)
UP_RX = re.compile(r"(connected to .*host|host .* (?:re)?connected|connection state changed to \[?CONNECTED|reconnected host|"
                   r"host connection and power state.*(?:green|to green))", re.I)
USER_RX = re.compile(r"(userRequest|by user|user request|사용자)", re.I)


def is_down(item: dict) -> bool:
    t = item.get("type") or ""
    if t in DOWN_TYPES:
        return True
    if t in UP_TYPES:
        return False
    return bool(DOWN_RX.search(item.get("message") or "")) and not UP_RX.search(item.get("message") or "")


def is_up(item: dict) -> bool:
    t = item.get("type") or ""
    if t in UP_TYPES:
        return True
    if t in DOWN_TYPES:
        return False
    return bool(UP_RX.search(item.get("message") or "")) and not DOWN_RX.search(item.get("message") or "")
