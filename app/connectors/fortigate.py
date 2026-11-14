"""FortiGate REST API(선택) — 장비 상태·자원 사용률 조회. 로그 자체는 syslog 로 받는다(대량·실시간).

인증: REST API 관리자(System > Administrators > REST API Admin)의 API 토큰 → Authorization: Bearer <token>
권한: 읽기 전용 관리자 프로필(accprofile 의 모든 항목 read) — 이 커넥터는 GET 만 사용한다. Trusted Hosts 에 AIops 주소 등록.
  GET /api/v2/monitor/system/status                 hostname·serial·version·build·model
  GET /api/v2/monitor/system/resource/usage         cpu·mem·session(현재값)
  GET /api/v2/monitor/system/ha-checksums           HA 구성원(선택)
  GET /api/v2/monitor/vpn/ssl                       SSL-VPN 접속 세션 수(선택)
"""
from __future__ import annotations

import time
from typing import Any

from ..models import LogEvent
from .base import Connector


def _cur(v: Any) -> float | None:
    if isinstance(v, list) and v:
        v = v[0]
    if isinstance(v, dict):
        v = v.get("current")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class FortiGateConnector(Connector):
    type = source = "fortigate"
    default_interval = 60

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.status: dict[str, Any] = {}
        self._state["auth"] = "token"

    async def login(self):
        tok = self.cfg.get("api_token") or self.cfg.get("password") or ""
        if not tok:
            raise ValueError("API 토큰(api_token)이 필요합니다")
        self.http.headers["Authorization"] = f"Bearer {tok}"
        if self.cfg.get("vdom"):
            self.http.params = self.http.params.merge({"vdom": self.cfg["vdom"]})

    async def _get(self, path: str, **params) -> dict:
        r = await self.http.get(path, params=params or None)
        r.raise_for_status()
        return r.json()

    async def poll(self) -> list[LogEvent]:
        out: list[LogEvent] = []
        j = await self._get("/api/v2/monitor/system/status")
        res = j.get("results") or {}
        st = {"hostname": res.get("hostname") or j.get("hostname") or self.host, "serial": j.get("serial", ""),
              "version": j.get("version", ""), "build": j.get("build", ""), "model": res.get("model_name") or res.get("model") or "",
              "model_number": res.get("model_number", ""), "ts": time.time()}
        try:
            u = (await self._get("/api/v2/monitor/system/resource/usage", interval="1-min")).get("results") or {}
            st.update(cpu=_cur(u.get("cpu")), mem=_cur(u.get("mem")), session=_cur(u.get("session")),
                      disk=_cur(u.get("disk")), setuprate=_cur(u.get("setuprate")))
        except Exception as e:  # noqa: BLE001
            st["resource_error"] = f"{type(e).__name__}: {e}"[:160]
        try:
            v = (await self._get("/api/v2/monitor/vpn/ssl")).get("results")
            st["sslvpn_sessions"] = len(v) if isinstance(v, list) else None
        except Exception:  # noqa: BLE001
            pass
        try:
            ha = (await self._get("/api/v2/monitor/system/ha-checksums")).get("results")
            if isinstance(ha, list) and ha:
                st["ha_members"] = [{"serial": m.get("serial_no", ""), "primary": bool(m.get("is_manage_primary") or m.get("is_root_primary"))} for m in ha]
        except Exception:  # noqa: BLE001
            pass
        prev = self.status
        self.status = st
        name = st["hostname"]
        if prev and prev.get("version") and prev.get("version") != st["version"]:
            out.append(self.ev(f"FortiGate {name} 펌웨어 변경 {prev['version']} → {st['version']} build{st['build']}",
                               severity="warning", kind="event", host=name, entity="system/firmware"))
        th = {"cpu": float(self.cfg.get("cpu_warn", 90)), "mem": float(self.cfg.get("mem_warn", 90))}
        for k, lim in th.items():
            v = st.get(k)
            key = f"{k}-high"
            if v is not None and v >= lim:
                if self.seen.is_new(f"{key}:{int(time.time() // 900)}"):
                    out.append(self.ev(f"FortiGate {name} {k.upper()} 사용률 {v:.0f}% (임계 {lim:.0f}%)", severity="warning",
                                       kind="health", host=name, entity=f"system/{k}"))
        pm = {m["serial"]: m["primary"] for m in prev.get("ha_members") or []}
        for m in st.get("ha_members") or []:
            if m["serial"] in pm and pm[m["serial"]] != m["primary"]:
                out.append(self.ev(f"FortiGate HA 역할 변경 — {m['serial']} {'primary' if m['primary'] else 'secondary'}",
                                   severity="warning", kind="event", host=name, entity="system/ha"))
        return out

    async def checks(self) -> dict[str, Any]:
        await self.login()
        res = {"auth": await self._probe("GET", "/api/v2/monitor/system/status")}
        res["resource"] = await self._probe("GET", "/api/v2/monitor/system/resource/usage")
        return res

    def entities(self) -> list[dict[str, Any]]:
        s = self.status
        if not s:
            return []
        warn = (s.get("cpu") or 0) >= 90 or (s.get("mem") or 0) >= 90
        return [{"name": s.get("hostname") or self.name, "kind": "firewall", "state": "warn" if warn else "ok",
                 "detail": f"{s.get('model', '')} {s.get('version', '')} build{s.get('build', '')} · CPU {s.get('cpu') or '-'}% · MEM {s.get('mem') or '-'}%"}]
