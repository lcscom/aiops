"""네트워크 스위치·라우터 커넥터(2.2) — Arista EOS · Cisco NX-OS · Cisco IOS-XE · 공통 SNMP. 모두 읽기 전용.

로그는 syslog 수신기(514/6514)로 받고(장비에서 logging host 설정), 이 커넥터는 주기적으로 상태·이웃(LLDP/CDP)을 읽어
전체 네트워크 구성도와 인터페이스·MLAG/vPC·BGP 상태 변화 이벤트를 만든다.

  Arista EOS  eAPI  POST https://<장비>/command-api  JSON-RPC {"method":"runCmds","params":{"version":1,"cmds":[…],"format":"json"}}
              show version · show hostname · show interfaces status · show lldp neighbors detail · show mlag · show ip bgp summary vrf all
              (lldpNeighbors{포트: {lldpNeighborInfo[{systemName, neighborInterfaceInfo{interfaceId_v2}}]}} — ANTA VerifyLLDPNeighbors 와 같은 키)
  Cisco NX-OS NX-API POST https://<장비>/ins  {"ins_api":{"type":"cli_show","input":"cmd1 ;cmd2","output_format":"json"}}
              show version · show hostname · show interface brief · show lldp neighbors detail(TABLE_nbor_detail/ROW_nbor_detail)
              · show cdp neighbors(TABLE_cdp_neighbor_brief_info) · show vpc brief · show ip bgp summary vrf all
  Cisco IOS-XE RESTCONF GET https://<장비>/restconf/data/…  (Accept: application/yang-data+json)
              Cisco-IOS-XE-native:native/hostname·version · Cisco-IOS-XE-interfaces-oper:interfaces (없으면 ietf-interfaces:interfaces-state)
              · Cisco-IOS-XE-lldp-oper:lldp-entries(lldp-intf-details/lldp-neighbor-details) · Cisco-IOS-XE-cdp-oper:cdp-neighbor-details
  SNMP(공통)  v2c/v3 — SNMPv2-MIB sysName·sysDescr, IF-MIB ifName·ifAlias·ifOperStatus·ifHighSpeed,
              LLDP-MIB lldpRemSysName·lldpRemPortId, CISCO-CDP-MIB cdpCacheDeviceId·DevicePort·Platform (API 를 못 쓰는 구형 장비)

장비 계정 권장: Arista `role network-operator`, NX-OS `network-operator`, IOS-XE privilege 1~15 중 show 만 허용(RESTCONF 는 15 필요 시 AAA 명령 권한으로 제한),
SNMP 는 읽기 전용 커뮤니티/USM.
"""
from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Any, Iterable

import httpx

from ..models import LogEvent
from .base import Connector

# syslog 수신기가 '어느 장비에서 왔는지' 알 수 있도록 커넥터 주소·호스트명을 등록(peer IP → 소스)
NET_PEERS: dict[str, str] = {}

UP_WORDS = {"connected", "up", "if-oper-state-ready", "ready", "1"}
DOWN_WORDS = {"notconnect", "down", "errdisabled", "err-disabled", "if-oper-state-no-pass", "if-oper-state-lower-layer-down", "lowerlayerdown",
              "2", "7", "sfp-absent", "xcvr-absent", "link-not-connected", "suspended", "suspnd", "nolink"}


def short(name: str) -> str:
    """이웃 이름 정규화 — FQDN·괄호 일련번호(NX-OS CDP 'n9k(FDO123)')·대소문자 제거"""
    n = str(name or "").strip().lower()
    n = re.sub(r"\(.*\)$", "", n)
    return n.split(".")[0] if n and not re.fullmatch(r"[\d.]+", n) else n


def if_short(name: str) -> str:
    """인터페이스 이름 표준화 — Ethernet1/1 · Eth1/1 · GigabitEthernet0/1 → 같은 키(e1/1, gi0/1 …)"""
    n = str(name or "").strip().lower().replace(" ", "")
    for full, ab in (("hundredgigabitethernet", "hu"), ("hundredgige", "hu"), ("fortygigabitethernet", "fo"), ("twentyfivegige", "twe"),
                     ("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("ethernet", "e"), ("eth", "e"),
                     ("port-channel", "po"), ("portchannel", "po"), ("management", "ma"), ("mgmt", "mgmt")):
        if n.startswith(full):
            return ab + n[len(full):]
    return n


def link_state(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in UP_WORDS or s.startswith("up"):
        return "up"
    if s in DOWN_WORDS or s.startswith(("down", "notconn", "err", "disabled", "admin")):
        return "disabled" if s in ("disabled", "admin-down", "administratively down", "if-state-down") else "down"
    return "unknown"


def rows(obj: Any, table: str, row: str) -> list[dict]:
    """NX-API TABLE_x/ROW_x — 한 행이면 dict, 여러 행이면 list 로 온다"""
    if not isinstance(obj, dict):
        return []
    t = obj.get(table)
    if isinstance(t, list):
        out = []
        for x in t:
            out += rows({table: x}, table, row)
        return out
    r = (t or {}).get(row) if isinstance(t, dict) else None
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


def find_dicts(obj: Any, need: Iterable[str]) -> list[dict]:
    """중첩 JSON 에서 지정 키를 모두 가진 dict 전부(NX-OS BGP 처럼 VRF·AF 표가 깊게 중첩된 경우)"""
    need = tuple(need)
    out, stack = [], [obj]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            if all(k in x for k in need):
                out.append(x)
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return out


class NetDevice(Connector):
    """공통: collect() 가 {device, ifaces, neighbors, mlag, bgp} 를 돌려주면 변화 이벤트·구성도 자료를 만든다."""
    type = "network"
    source = "network"
    vendor = ""
    default_interval = 60

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.device: dict[str, Any] = {}
        self.ifaces: dict[str, dict] = {}
        self.neighbors: list[dict] = []
        self.mlag: dict[str, Any] = {}
        self.bgp: dict[str, dict] = {}
        self.addresses: list[str] = []                   # 2.3 L3 주소(SVI 등)
        self.config: dict[str, Any] = {}                 # 2.4 running-config(마스킹)·포트별 구성·변경 감지
        self._cfg_at = 0.0
        self.known_links: dict[str, dict] = {}          # 로컬 포트 → 마지막으로 본 이웃(사라진 링크를 구성도에 빨간 선으로 남김)
        self.updated = 0.0
        self.role = str(cfg.get("role", "") or "")       # spine | leaf | core | border | access | (빈 값=자동)
        self.site = str(cfg.get("site", "") or "")
        self._register(self.host)

    def _register(self, name: str) -> None:
        if not name:
            return
        h = str(name).split(":")[0].strip().lower()
        NET_PEERS[h] = self.source
        NET_PEERS[short(h)] = self.source
        try:
            for ai in socket.getaddrinfo(h, None)[:4]:
                NET_PEERS[ai[4][0]] = self.source
        except (OSError, UnicodeError):
            pass

    async def collect(self) -> dict[str, Any]:            # 하위 클래스
        raise NotImplementedError

    async def fetch_config(self) -> tuple[str, dict] | None:   # 하위 클래스 — (구성 원문, parse 결과) 또는 None(미지원)
        return None

    async def _refresh_config(self, name: str) -> list[LogEvent]:
        from .. import netconfig as NC
        out: list[LogEvent] = []
        try:
            got = await asyncio.wait_for(self.fetch_config(), timeout=60)
        except Exception as e:  # noqa: BLE001
            self.config = {**self.config, "error": f"{type(e).__name__}: {str(e)[:160]}", "tried": time.time()}
            self._state["checks"]["구성(running-config)"] = f"warn: {self.config['error']}"
            return out
        if not got:
            return out
        raw, parsed = got
        text = NC.mask(raw)
        dg = NC.digest(text)
        prev = self.config
        now = time.time()
        cfg = {"text": text, "digest": dg, "updated": now, "lines": len(text.splitlines()), "parsed": parsed, "error": "",
               "changed_at": prev.get("changed_at"), "diff": prev.get("diff")}
        if prev.get("digest") and prev["digest"] != dg:
            d = NC.diff_summary(prev.get("text", ""), text)
            cfg["changed_at"], cfg["diff"] = now, d
            out.append(self.ev(f"{name} 구성 변경 감지 — 추가 {d['added']}줄 · 삭제 {d['removed']}줄"
                               + (f" ({', '.join(d['blocks'][:6])})" if d["blocks"] else ""), severity="warning", kind="event", host=name,
                               entity=f"{name}:config", attrs={"net_change": "config", "blocks": d["blocks"][:20], "sample": d["sample"][:20]}))
        self.config = cfg
        self._state["checks"]["구성(running-config)"] = f"ok {cfg['lines']}줄 · 인터페이스 {len(parsed.get('interfaces') or {})}"
        return out

    # ---------------------------------------------------------------- 변화 → 이벤트
    async def poll(self) -> list[LogEvent]:
        d = await self.collect()
        out: list[LogEvent] = []
        now = time.time()
        name = d["device"].get("hostname") or self.name
        self._register(name)
        prev_if, prev_mlag, prev_bgp = self.ifaces, self.mlag, self.bgp
        nb_by_port = {if_short(n["local"]): n for n in d["neighbors"]}
        if prev_if and not self.first_poll:
            for k, i in d["ifaces"].items():
                p = prev_if.get(k)
                if not p or p.get("state") == i.get("state") or i.get("state") == "unknown":
                    continue
                nb = nb_by_port.get(if_short(k)) or self.known_links.get(if_short(k))
                important = bool(nb or i.get("desc") or k.lower().startswith(("po", "port-channel")))
                peer = f" (→ {nb['remote']} {nb.get('remote_port', '')})" if nb else (f" [{i['desc']}]" if i.get("desc") else "")
                if i["state"] == "up":
                    out.append(self.ev(f"인터페이스 {k} 복구(up){peer}", severity="info", kind="event", host=name, entity=f"{name}:{k}",
                                       attrs={"interface": k, "peer": (nb or {}).get("remote", ""), "net_change": "if_up"}))
                elif i["state"] in ("down", "disabled") and p.get("state") == "up":
                    out.append(self.ev(f"인터페이스 {k} 다운({i.get('raw') or i['state']}){peer}", severity="error" if important else "warning",
                                       kind="event", host=name, entity=f"{name}:{k}",
                                       attrs={"interface": k, "peer": (nb or {}).get("remote", ""), "net_change": "if_down"}))
        # 이웃: 사라진 이웃(장애) · 새 이웃
        cur_ports = set(nb_by_port)
        for port, n in list(self.known_links.items()):
            if port not in cur_ports and not self.first_poll and n.get("state") != "lost" and now - n.get("seen", now) < 86400:
                n["state"] = "lost"
                n["lost_at"] = now
                out.append(self.ev(f"LLDP/CDP 이웃 사라짐 — {n.get('local')} → {n.get('remote')} {n.get('remote_port', '')}".strip(), severity="warning",
                                   kind="event", host=name, entity=f"{name}:{n.get('local')}", attrs={"interface": n.get("local"), "peer": n.get("remote"), "net_change": "nb_lost"}))
        for port, n in nb_by_port.items():
            old = self.known_links.get(port)
            self.known_links[port] = {**n, "seen": now, "state": "up"}
            if old and old.get("remote") and short(old["remote"]) != short(n["remote"]) and not self.first_poll:
                out.append(self.ev(f"포트 {n['local']} 의 이웃 변경 {old['remote']} → {n['remote']}", severity="warning", kind="event", host=name,
                                   entity=f"{name}:{n['local']}", attrs={"interface": n["local"], "peer": n["remote"], "net_change": "nb_change"}))
        for port in [p for p, n in self.known_links.items() if n.get("state") == "lost" and now - n.get("lost_at", now) > 86400]:
            self.known_links.pop(port, None)              # 하루 지나도 안 돌아오면 구성도에서 제거
        # MLAG / vPC
        ml = d.get("mlag") or {}
        if prev_mlag and ml and not self.first_poll:
            for k in ("state", "peer_link", "neg"):
                if ml.get(k) != prev_mlag.get(k) and ml.get(k):
                    bad = str(ml.get(k)).lower() not in ("active", "up", "connected", "peer-ok", "ok", "success", "peer-alive", "alive")
                    out.append(self.ev(f"{ml.get('kind', 'MLAG')} {k} {prev_mlag.get(k) or '-'} → {ml.get(k)}", severity="critical" if bad else "info",
                                       kind="event", host=name, entity=f"{name}:{ml.get('kind', 'mlag').lower()}", attrs={"net_change": "mlag"}))
        # BGP
        bg = d.get("bgp") or {}
        if prev_bgp and not self.first_poll:
            for peer, b in bg.items():
                pb = prev_bgp.get(peer)
                if pb and pb.get("state") != b.get("state"):
                    est = str(b.get("state", "")).lower() == "established"
                    out.append(self.ev(f"BGP 피어 {peer}(AS {b.get('asn', '-')}, VRF {b.get('vrf', 'default')}) {pb.get('state')} → {b.get('state')}",
                                       severity="info" if est else "error", kind="event", host=name, entity=f"{name}:bgp:{peer}",
                                       attrs={"peer": peer, "net_change": "bgp"}))
            for peer in set(prev_bgp) - set(bg):
                out.append(self.ev(f"BGP 피어 {peer} 사라짐(설정 삭제 또는 VRF 변경)", severity="warning", kind="event", host=name,
                                   entity=f"{name}:bgp:{peer}", attrs={"peer": peer, "net_change": "bgp"}))
        if self.device.get("version") and d["device"].get("version") and self.device["version"] != d["device"]["version"]:
            out.append(self.ev(f"{name} OS 버전 변경 {self.device['version']} → {d['device']['version']}", severity="warning", kind="event",
                               host=name, entity=f"{name}:system", attrs={"net_change": "version"}))
        self.device, self.ifaces, self.neighbors, self.mlag, self.bgp = d["device"], d["ifaces"], d["neighbors"], ml, bg
        self.addresses = list(d.get("addresses") or [])[:200]
        self.updated = now
        if self.cfg.get("config", True) and now - self._cfg_at > float(self.cfg.get("config_interval", 900)):
            self._cfg_at = now
            out += await self._refresh_config(name)
        self._state["checks"]["수집"] = (f"ok 인터페이스 {len(self.ifaces)} · 이웃 {len(self.neighbors)}"
                                        f"{' · ' + ml.get('kind', 'MLAG') + ' ' + str(ml.get('state')) if ml.get('state') else ''}"
                                        f"{' · BGP ' + str(sum(1 for b in bg.values() if str(b.get('state', '')).lower() == 'established')) + '/' + str(len(bg)) if bg else ''}")
        return out

    # ---------------------------------------------------------------- 화면·구성도
    def snapshot(self) -> dict[str, Any]:
        ifs = self.ifaces
        up = sum(1 for i in ifs.values() if i.get("state") == "up")
        down_imp = [k for k, i in ifs.items() if i.get("state") == "down" and (i.get("desc") or if_short(k) in self.known_links)]
        bgp_bad = [p for p, b in self.bgp.items() if str(b.get("state", "")).lower() != "established"]
        ml = self.mlag or {}
        ml_bad = bool(ml.get("state")) and str(ml.get("state")).lower() not in ("active", "peer-ok", "ok", "up")
        st = ("down" if self._state.get("state") == "down" else "down" if ml_bad else
              "warn" if down_imp or bgp_bad or self._state.get("state") == "degraded" else "ok" if self.updated else "unknown")
        return {"name": self.device.get("hostname") or self.name, "connector": self.name, "vendor": self.vendor, "type": self.type,
                "model": self.device.get("model", ""), "os": self.device.get("os", ""), "version": self.device.get("version", ""),
                "serial": self.device.get("serial", ""), "mgmt": self.host, "uptime": self.device.get("uptime"), "role": self.role, "site": self.site,
                "state": st, "ifs_total": len(ifs), "ifs_up": up, "ifs_down_important": down_imp[:50],
                "ifaces": [{"name": k, **{x: v.get(x) for x in ("state", "raw", "desc", "speed", "vlan")}} for k, v in sorted(ifs.items())][:600],
                "neighbors": [dict(n) for n in self.known_links.values()][:600],
                "mlag": ml, "bgp": [{"peer": p, **b} for p, b in sorted(self.bgp.items())][:200], "updated": self.updated, "addresses": self.addresses,
                "port_cfg": {k: {x: v for x, v in i.items() if x != "lines"} for k, i in ((self.config.get("parsed") or {}).get("interfaces") or {}).items()},
                "config": {k: self.config.get(k) for k in ("updated", "digest", "lines", "error", "changed_at", "diff")} if self.config else {},
                "cfg_global": {k: v for k, v in (((self.config.get("parsed") or {}).get("global")) or {}).items() if k != "lines"},
                "vlans": (self.config.get("parsed") or {}).get("vlans") or {},
                "error": self._state.get("last_error", "") if self._state.get("state") != "ok" else ""}

    def entities(self) -> list[dict[str, Any]]:
        s = self.snapshot()
        if not self.updated:
            return []
        out = [{"name": s["name"], "kind": f"{self.vendor} 스위치", "state": s["state"],
                "detail": f"{s['model']} {s['os']} {s['version']} · 포트 up {s['ifs_up']}/{s['ifs_total']} · 이웃 {len(s['neighbors'])}"
                          + (f" · {s['mlag'].get('kind', 'MLAG')} {s['mlag'].get('state')}" if s["mlag"].get("state") else "")}]
        for k in s["ifs_down_important"][:20]:
            nb = self.known_links.get(if_short(k)) or {}
            out.append({"name": f"{s['name']}:{k}", "kind": "인터페이스", "state": "down",
                        "detail": f"{self.ifaces.get(k, {}).get('raw') or 'down'}{' → ' + nb.get('remote', '') if nb else ''} {self.ifaces.get(k, {}).get('desc') or ''}".strip()})
        for b in s["bgp"]:
            if str(b.get("state", "")).lower() != "established":
                out.append({"name": f"{s['name']}:bgp:{b['peer']}", "kind": "BGP 피어", "state": "down", "detail": f"AS {b.get('asn', '-')} · {b.get('state')}"})
        return out


# ====================================================================== Arista EOS (eAPI)
def _chain(e: BaseException | None) -> str:
    out, n = [], 0
    while e is not None and n < 6:
        out.append(f"{type(e).__name__}: {e}")
        e, n = e.__cause__ or e.__context__, n + 1
    return " | ".join(out)


def _refused(e: BaseException | None) -> bool:
    """httpx 는 'All connection attempts failed' 로 감싸므로 원인 사슬에서 ConnectionRefusedError·errno 111/10061 확인"""
    n = 0
    while e is not None and n < 6:
        if isinstance(e, ConnectionRefusedError) or getattr(e, "errno", None) in (111, 61, 10061) or "refused" in str(e).lower():
            return True
        for sub in getattr(e, "exceptions", ()) or ():                 # ExceptionGroup(여러 주소 시도)
            if _refused(sub):
                return True
        e, n = e.__cause__ or e.__context__, n + 1
    return False


class SshCli:
    """eAPI·NX-API 를 쓸 수 없는 장비용 SSH CLI(읽기 전용 show 만). EOS·NX-OS 는 'show … | json' 으로 API 와 같은 JSON 을 돌려준다.
    호스트 키: 처음 본 지문을 기억(TOFU)하고 이후 바뀌면 접속 거부 — 설정 ssh_host_key 로 지문을 고정할 수 있다."""

    def __init__(self, host: str, port: int, user: str, password: str, pinned: str = "", timeout: float = 20):
        self.host, self.port, self.user, self.password = host, port, user, password
        self.pinned, self.timeout = pinned, timeout
        self.fingerprint = ""
        self._conn = None

    async def _connect(self):
        import asyncssh
        if self._conn is not None:
            return self._conn
        conn = await asyncio.wait_for(asyncssh.connect(self.host, port=self.port, username=self.user, password=self.password, known_hosts=None,
                                                       client_keys=None, agent_path=None, preferred_auth="password,keyboard-interactive"), self.timeout)
        key = conn.get_server_host_key()
        fp = key.get_fingerprint("sha256") if key else ""
        if self.pinned and fp and fp != self.pinned:
            conn.close()
            raise RuntimeError(f"SSH 호스트 키가 바뀜({fp}) — 기억한 지문 {self.pinned}. 장비 교체가 아니면 중간자 공격 가능성")
        self.fingerprint = self.pinned = fp or self.pinned
        self._conn = conn
        return conn

    async def run(self, cmd: str) -> str:
        for attempt in range(2):
            try:
                conn = await self._connect()
                r = await asyncio.wait_for(conn.run(cmd, check=False), self.timeout)
                return str(r.stdout or "") + (str(r.stderr or "") if not r.stdout else "")
            except (OSError, asyncio.TimeoutError) as e:
                self.close()
                if attempt:
                    raise RuntimeError(f"SSH {type(e).__name__}: {str(e)[:120]}") from e
            except Exception as e:  # noqa: BLE001  (asyncssh.Error — 연결이 끊긴 경우 한 번 다시)
                self.close()
                if attempt or "auth" in type(e).__name__.lower() or "permission" in str(e).lower():
                    raise RuntimeError(f"SSH {type(e).__name__}: {str(e)[:160]}") from e
        return ""

    async def json(self, cmd: str) -> dict:
        out = (await self.run(f"{cmd} | json")).strip()
        if not out or out.startswith("%") or "Invalid input" in out[:200] or "Syntax error" in out[:200]:
            raise RuntimeError(f"eAPI 1002: CLI '{cmd}' 실패: {out[:160] or '출력 없음'}")
        i = out.find("{")
        try:
            return __import__("json").loads(out[i:] if i >= 0 else out)
        except ValueError as e:
            raise RuntimeError(f"eAPI 1003: '{cmd} | json' 결과를 JSON 으로 읽지 못함") from e

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
        self._conn = None


async def _port_open(host: str, port: int, timeout: float = 4) -> bool:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


class AristaEosConnector(NetDevice):
    type = source = "arista"
    vendor = "Arista"

    EAPI_HINT = ("장비 설정: management api http-commands › no shutdown (관리 인터페이스가 VRF 에 있으면 그 아래 'vrf MGMT' › no shutdown) · "
                 "ACL(ip access-group)에 AIops 주소 허용")

    async def login(self):
        self.http.auth = httpx.BasicAuth(self.cfg.get("username", ""), self.cfg.get("password", ""))
        self._state["auth"] = "basic"

    def _to_http(self) -> bool:
        """HTTPS 443 이 닫혀 있고 eAPI 가 'protocol http' 로만 켜진 장비 → http:// 로 한 번 전환(주소에 스킴·base_url 을 지정하지 않은 경우만)"""
        if self.cfg.get("base_url") or not self.base_url.startswith("https://") or getattr(self, "_http_tried", False):
            return False
        self._http_tried = True
        self.base_url = "http://" + self.base_url[len("https://"):]
        self._http = None
        self._state["checks"]["eAPI 프로토콜"] = "warn: HTTPS 연결 거부 → HTTP 로 접속(장비 'protocol https' 권장)"
        return True

    def _ssh_cli(self) -> SshCli:
        if getattr(self, "_ssh", None) is None:
            h = str(self.cfg.get("host", "")).split(":")[0]
            self._ssh = SshCli(h, int(self.cfg.get("ssh_port", 22)), self.cfg.get("username", ""), self.cfg.get("password", ""),
                               pinned=str(self.cfg.get("ssh_host_key", "") or ""))
        return self._ssh

    @property
    def transport(self) -> str:
        return getattr(self, "_transport", None) or str(self.cfg.get("transport", "auto")).lower()

    async def _use_ssh(self, why: str) -> bool:
        """eAPI 를 못 쓰면(연결 거부·꺼짐) SSH 22 가 열려 있는지 보고 SSH CLI 로 전환 — transport: auto 일 때만"""
        if self.transport != "auto":
            return False
        h = str(self.cfg.get("host", "")).split(":")[0]
        if not await _port_open(h, int(self.cfg.get("ssh_port", 22))):
            return False
        self._transport = "ssh"
        self._state["checks"]["전송"] = f"warn: eAPI 사용 불가({why}) → SSH CLI 로 수집(show … | json). eAPI 를 켜면 더 빠르고 가벼움"
        return True

    async def _ssh_cmds(self, cmds: list[str], fmt: str) -> list[dict]:
        cli = self._ssh_cli()
        out = []
        for c in cmds:
            if fmt == "text":
                out.append({"output": await cli.run(c)})
            else:
                out.append(await cli.json(c))
        return out

    async def _post(self, cmds: list[str], fmt: str = "json") -> httpx.Response:
        body = {"jsonrpc": "2.0", "method": "runCmds", "params": {"version": 1, "cmds": cmds, "format": fmt}, "id": "aiops"}
        for _ in range(3):
            try:
                if not self.http.auth:
                    await self.login()
                return await self.http.post(self.cfg.get("eapi_path", "/command-api"), json=body)
            except httpx.ConnectError as e:
                if self.switch_legacy_tls(e) and "WRONG_VERSION_NUMBER" not in _chain(e):
                    continue
                if (_refused(e) or "WRONG_VERSION_NUMBER" in _chain(e)) and self._to_http():   # HTTPS 포트 닫힘·평문 HTTP 포트
                    self._https_refused = True
                    continue
                if getattr(self, "_https_refused", False) and self.base_url.startswith("http://"):
                    raise RuntimeError(f"eAPI 연결 실패 — HTTPS·HTTP 모두 {'연결 거부' if _refused(e) else str(e)[:80]}: 장비에 닿지만 이 주소에서 eAPI 가 열려 있지 않음. "
                                       f"{self.EAPI_HINT}. 장비에서 'show management api http-commands' 로 Enabled·HTTPS·VRF 확인") from e
                raise RuntimeError(f"eAPI 연결 실패({'연결 거부' if _refused(e) else type(e).__name__ + ': ' + str(e)[:120]}) — {self.EAPI_HINT}") from e
        raise RuntimeError("eAPI 연결 실패")

    async def run_cmds(self, cmds: list[str], fmt: str = "json") -> list[dict]:
        if self.transport == "ssh":
            return await self._ssh_cmds(cmds, fmt)
        try:
            r = await self._post(cmds, fmt)
        except RuntimeError as e:
            if "eAPI 연결 실패" in str(e) and await self._use_ssh("연결 거부" if "거부" in str(e) else "연결 실패"):
                return await self._ssh_cmds(cmds, fmt)
            raise RuntimeError(f"{e} · SSH(22)도 닫혀 있음" if self.transport == "auto" and "eAPI 연결 실패" in str(e) else str(e)) from e
        if r.status_code == 404 and await self._use_ssh("HTTP 404"):
            return await self._ssh_cmds(cmds, fmt)
        if r.status_code in (401, 403):
            raise RuntimeError(f"eAPI HTTP {r.status_code} — 계정·비밀번호 확인(로컬 또는 AAA 계정), eAPI ACL 에 AIops 주소가 허용됐는지 확인")
        if r.status_code == 404:
            raise RuntimeError(f"eAPI HTTP 404 {r.url.path} — eAPI 가 꺼져 있거나 다른 웹 서비스가 응답. {self.EAPI_HINT}")
        r.raise_for_status()
        try:
            j = r.json()
        except ValueError:
            raise RuntimeError(f"eAPI 응답이 JSON 이 아님(HTTP {r.status_code}, {r.headers.get('content-type', '')}) — eAPI 가 아닌 웹 서비스이거나 리디렉션. {self.EAPI_HINT}")
        if j.get("error"):
            e = j["error"]
            msg = str(e.get("message"))
            hint = (" — 권한 부족: 계정 role 에 show 명령 허용(예: role network-operator) 또는 'aaa authorization exec default local'"
                    if any(k in msg.lower() for k in ("authoriz", "permission", "denied")) else "")
            raise RuntimeError(f"eAPI {e.get('code')}: {msg[:200]}{hint}")
        return j.get("result") or []

    async def _opt(self, cmd: str) -> dict:
        try:
            return (await self.run_cmds([cmd]))[0]
        except (RuntimeError, httpx.HTTPStatusError, IndexError):
            return {}

    async def _batch(self, cmds: list[str], required: tuple[str, ...]) -> list[dict]:
        """한 번에 보내고, 어느 한 명령이 실패하면(구버전 EOS·JSON 미지원 명령 등) 명령별로 다시 — required 가 실패할 때만 오류"""
        try:
            out = await self.run_cmds(cmds)
            if len(out) == len(cmds):
                return out
        except RuntimeError as e:
            if "eAPI 연결 실패" in str(e) or "HTTP 40" in str(e) or "JSON 이 아님" in str(e):
                raise
        out = []
        for c in cmds:
            if c in required:
                out.append((await self.run_cmds([c]))[0])
            else:
                out.append(await self._opt(c))
                if not out[-1] and c.endswith("detail"):
                    out[-1] = await self._opt(c.rsplit(" ", 1)[0])           # show lldp neighbors detail → show lldp neighbors
        return out

    async def collect(self) -> dict[str, Any]:
        ver, hn, st, ll = await self._batch(["show version", "show hostname", "show interfaces status", "show lldp neighbors detail"],
                                            required=("show version",))
        dev = {"hostname": hn.get("hostname") or self.name, "fqdn": hn.get("fqdn", ""), "model": ver.get("modelName", ""), "os": "EOS",
               "version": ver.get("version", ""), "serial": ver.get("serialNumber", ""),
               "uptime": ver.get("uptime") if isinstance(ver.get("uptime"), (int, float)) else None}
        ifs = {}
        for k, i in (st.get("interfaceStatuses") or {}).items():
            raw = i.get("linkStatus", "")
            ifs[k] = {"state": link_state(raw), "raw": raw, "desc": i.get("description", ""),
                      "speed": int(i["bandwidth"] / 1e6) if isinstance(i.get("bandwidth"), (int, float)) and i["bandwidth"] else None,
                      "vlan": (i.get("vlanInformation") or {}).get("vlanId")}
        nbs = []
        lln = ll.get("lldpNeighbors") or {}
        if isinstance(lln, dict):                      # detail 형식
            for port, v in lln.items():
                for n in (v or {}).get("lldpNeighborInfo") or []:
                    nii = n.get("neighborInterfaceInfo") or {}
                    mg = [a.get("address") for a in (n.get("managementAddresses") or []) if a.get("address")]
                    nbs.append({"local": port, "remote": n.get("systemName") or n.get("chassisId", ""), "remote_port": nii.get("interfaceId_v2") or nii.get("interfaceId", ""),
                                "remote_port_desc": nii.get("interfaceDescription", ""), "remote_mgmt": mg[0] if mg else "",
                                "remote_desc": str(n.get("systemDescription", ""))[:200], "proto": "lldp"})
        elif isinstance(lln, list):                    # 'show lldp neighbors'(요약) 형식
            for n in lln:
                nbs.append({"local": n.get("port", ""), "remote": n.get("neighborDevice", ""), "remote_port": n.get("neighborPort", ""), "proto": "lldp"})
        ml = await self._opt("show mlag")
        mlag = {}
        if ml.get("state") and ml.get("state") != "disabled":
            mlag = {"kind": "MLAG", "state": ml.get("state"), "neg": ml.get("negStatus"), "peer_link": ml.get("peerLinkStatus"),
                    "local_if": ml.get("localIntfStatus"), "peer": ml.get("peerAddress"), "domain": ml.get("domainId"),
                    "ports": ml.get("mlagPorts") if isinstance(ml.get("mlagPorts"), dict) else {}}
        bg = await self._opt("show ip bgp summary vrf all") or await self._opt("show ip bgp summary")
        bgp = {}
        for vrf, v in (bg.get("vrfs") or {}).items():
            for peer, p in (v.get("peers") or {}).items():
                bgp[peer] = {"state": p.get("peerState", ""), "asn": p.get("asn"), "vrf": vrf, "prefixes": p.get("prefixReceived"),
                             "since": p.get("upDownTime")}
        ipi = await self._opt("show ip interface brief")            # 2.3 SVI·L3 주소(NSX BGP neighbor_address 매칭)
        addrs = sorted({str(x["address"]) for x in find_dicts(ipi, ("address", "maskLen")) if x.get("address") not in (None, "", "0.0.0.0")})
        return {"device": dev, "ifaces": ifs, "neighbors": nbs, "mlag": mlag, "bgp": bgp, "addresses": addrs}

    async def fetch_config(self):
        from .. import netconfig as NC
        out = (await self.run_cmds(["show running-config"], fmt="text"))[0]
        text = out.get("output", "") if isinstance(out, dict) else str(out)
        return text, NC.parse(text)

    async def checks(self):
        await self.login()
        res: dict[str, Any] = {}
        ver = (await self.run_cmds(["show version"]))[0]          # 실패하면 예외 → 연결 테스트가 DNS·TCP·TLS 단계 진단을 함께 표시
        res.update({k: v for k, v in self._state.get("checks", {}).items() if k in ("TLS", "eAPI 프로토콜")})
        res.update({k: v for k, v in self._state.get("checks", {}).items() if k == "전송"})
        via = "ssh" if self.transport == "ssh" else self.base_url.split("://")[0]
        res["eAPI show version" if via != "ssh" else "SSH show version"] = f"ok {ver.get('modelName', '')} EOS {ver.get('version', '')} · {via}"
        if via == "ssh":
            res["SSH 호스트 키"] = f"ok {self._ssh_cli().fingerprint or '-'} (처음 본 지문을 기억 — 바뀌면 접속 거부)"
        for c in ("show hostname", "show interfaces status", "show lldp neighbors detail", "show mlag", "show ip bgp summary vrf all"):
            try:
                await self.run_cmds([c])
                res[c] = "ok"
            except Exception as e:  # noqa: BLE001
                res[c] = f"warn: {e}"[:160]
        return res


# ====================================================================== Cisco NX-OS (NX-API)
class CiscoNxosConnector(NetDevice):
    type = "nxos"
    source = "cisco"
    vendor = "Cisco"

    async def login(self):
        self.http.auth = httpx.BasicAuth(self.cfg.get("username", ""), self.cfg.get("password", ""))
        self._state["auth"] = "basic"

    async def show(self, cmds: list[str]) -> list[dict]:
        """cli_show — 명령별 결과 body(dict). 실패한 명령은 {} (code≠200)"""
        r = await self.http.post(self.cfg.get("nxapi_path", "/ins"), json={"ins_api": {"version": "1.0", "type": "cli_show", "chunk": "0", "sid": "1",
                                                                                  "input": " ;".join(cmds), "output_format": "json"}},
                                 headers={"Content-Type": "application/json"})
        if r.status_code in (401, 403):
            r.raise_for_status()
        r.raise_for_status()
        outs = ((r.json() or {}).get("ins_api") or {}).get("outputs", {}).get("output")
        outs = outs if isinstance(outs, list) else [outs] if outs else []
        res = []
        for o in outs:
            ok = str((o or {}).get("code", "200")) == "200"
            body = (o or {}).get("body") if ok else {}
            res.append(body if isinstance(body, dict) else {})
        while len(res) < len(cmds):
            res.append({})
        return res

    async def fetch_config(self):
        from .. import netconfig as NC
        r = await self.http.post(self.cfg.get("nxapi_path", "/ins"), json={"ins_api": {"version": "1.0", "type": "cli_show_ascii", "chunk": "0", "sid": "1",
                                                                                  "input": "show running-config", "output_format": "json"}},
                                 headers={"Content-Type": "application/json"})
        r.raise_for_status()
        o = ((r.json() or {}).get("ins_api") or {}).get("outputs", {}).get("output") or {}
        o = o[0] if isinstance(o, list) else o
        if str(o.get("code", "200")) != "200":
            raise RuntimeError(f"NX-API show running-config: {o.get('msg', '')}")
        text = o.get("body") if isinstance(o.get("body"), str) else ""
        return text, NC.parse(text)

    async def collect(self) -> dict[str, Any]:
        ver, hn, ib, lldp, cdp, vpc, bg = await self.show(["show version", "show hostname", "show interface brief", "show lldp neighbors detail",
                                                           "show cdp neighbors", "show vpc brief", "show ip bgp summary vrf all"])
        if not ver and not ib:
            raise RuntimeError("NX-API 응답에 결과 없음 — 'feature nxapi' 와 계정 권한(network-operator) 확인")
        dev = {"hostname": hn.get("hostname") or ver.get("host_name") or self.name, "model": ver.get("chassis_id", ""), "os": "NX-OS",
               "version": ver.get("nxos_ver_str") or ver.get("sys_ver_str") or ver.get("kickstart_ver_str", ""), "serial": ver.get("proc_board_id", ""),
               "uptime": (int(ver.get("kern_uptm_days", 0) or 0) * 86400 + int(ver.get("kern_uptm_hrs", 0) or 0) * 3600) if ver.get("kern_uptm_days") is not None else None}
        ifs = {}
        for t, r in (("TABLE_interface", "ROW_interface"), ("TABLE_mgmt", "ROW_mgmt")):
            for i in rows(ib, t, r):
                n = i.get("interface")
                if not n:
                    continue
                raw = i.get("state", "")
                rsn = i.get("state_rsn_desc") or i.get("state_rsn") or ""
                ifs[n] = {"state": link_state(raw if raw != "down" or "admin" not in rsn.lower() else "disabled"), "raw": f"{raw} {rsn}".strip(),
                          "desc": i.get("desc") or i.get("description") or "", "speed": i.get("speed"), "vlan": i.get("vlan")}
        nbs = []
        for n in rows(lldp, "TABLE_nbor_detail", "ROW_nbor_detail"):
            nbs.append({"local": n.get("l_port_id", ""), "remote": n.get("sys_name") or n.get("chassis_id", ""), "remote_port": n.get("port_id", ""),
                        "remote_port_desc": n.get("port_desc", ""), "remote_mgmt": n.get("mgmt_addr", ""), "remote_desc": str(n.get("sys_desc", ""))[:200], "proto": "lldp"})
        seen = {(if_short(n["local"]), short(n["remote"])) for n in nbs}
        for n in rows(cdp, "TABLE_cdp_neighbor_brief_info", "ROW_cdp_neighbor_brief_info"):
            key = (if_short(n.get("intf_id", "")), short(n.get("device_id", "")))
            if key in seen:
                continue
            nbs.append({"local": n.get("intf_id", ""), "remote": n.get("device_id", ""), "remote_port": n.get("port_id", ""),
                        "remote_desc": n.get("platform_id", ""), "proto": "cdp"})
        mlag = {}
        if vpc.get("vpc-domain-id") or vpc.get("vpc-peer-status"):
            mlag = {"kind": "vPC", "state": vpc.get("vpc-peer-status", ""), "peer_link": vpc.get("peer-link-status") or vpc.get("vpc-peer-link-status", ""),
                    "neg": vpc.get("vpc-peer-keepalive-status", ""), "domain": vpc.get("vpc-domain-id"), "role": vpc.get("vpc-role", "")}
            for pl in rows(vpc, "TABLE_peerlink", "ROW_peerlink"):
                mlag["peer_link"] = pl.get("peer-link-port-state") or mlag["peer_link"]
        bgp = {}
        for n in find_dicts(bg, ("neighborid", "state")):
            bgp[n["neighborid"]] = {"state": n.get("state", ""), "asn": n.get("neighboras"), "vrf": n.get("vrf-name-out", "") or "default",
                                    "prefixes": n.get("prefixreceived"), "since": n.get("time")}
        addrs: list[str] = []
        try:                                                           # 2.3 SVI·L3 주소(TABLE_intf/ROW_intf.prefix)
            ipb = (await self.show(["show ip interface brief vrf all"]))[0]
            addrs = sorted({str(r.get("prefix")) for r in rows(ipb, "TABLE_intf", "ROW_intf") if r.get("prefix")})
        except Exception:  # noqa: BLE001
            pass
        return {"device": dev, "ifaces": ifs, "neighbors": nbs, "mlag": mlag, "bgp": bgp, "addresses": addrs}

    async def checks(self):
        await self.login()
        try:
            ver, = await self.show(["show version"])
        except Exception as e:  # noqa: BLE001
            return {"NX-API show version": f"{type(e).__name__}: {e}"[:200]}
        res = {"NX-API show version": f"ok {ver.get('chassis_id', '')} {ver.get('nxos_ver_str') or ver.get('sys_ver_str', '')}" if ver else "warn: 결과 없음"}
        outs = await self.show(["show interface brief", "show lldp neighbors detail", "show cdp neighbors"])
        for c, o in zip(("show interface brief", "show lldp neighbors detail", "show cdp neighbors"), outs):
            res[c] = "ok" if o else "warn: 결과 없음(기능 비활성 또는 권한)"
        return res


# ====================================================================== Cisco IOS-XE (RESTCONF)
class CiscoIosxeConnector(NetDevice):
    type = "iosxe"
    source = "cisco"
    vendor = "Cisco"

    async def login(self):
        self.http.auth = httpx.BasicAuth(self.cfg.get("username", ""), self.cfg.get("password", ""))
        self.http.headers["Accept"] = "application/yang-data+json"
        self._state["auth"] = "basic"

    async def rc(self, path: str) -> dict:
        r = await self.http.get(f"/restconf/data/{path}")
        if r.status_code in (401, 403):
            r.raise_for_status()
        if r.status_code >= 300:
            return {}
        try:
            return r.json() or {}
        except ValueError:
            return {}

    async def fetch_config(self):
        from .. import netconfig as NC
        j = await self.rc("Cisco-IOS-XE-native:native/interface")
        if not j:
            return None
        return NC.from_iosxe_native(j)

    async def collect(self) -> dict[str, Any]:
        hn = await self.rc("Cisco-IOS-XE-native:native/hostname")
        if not hn:
            r = await self.http.get("/restconf/data/Cisco-IOS-XE-native:native/hostname")
            r.raise_for_status()
        ver = await self.rc("Cisco-IOS-XE-native:native/version")
        hw = await self.rc("Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory")
        inv = (hw.get("Cisco-IOS-XE-device-hardware-oper:device-inventory") or [])
        chassis = next((x for x in inv if str(x.get("hw-type", "")).endswith("chassis")), inv[0] if inv else {})
        dev = {"hostname": hn.get("Cisco-IOS-XE-native:hostname") or self.name, "model": chassis.get("part-number", ""), "os": "IOS-XE",
               "version": str(ver.get("Cisco-IOS-XE-native:version", "")), "serial": chassis.get("serial-number", "")}
        ifs = {}
        xe_addrs: list[str] = []
        io = await self.rc("Cisco-IOS-XE-interfaces-oper:interfaces")
        for i in ((io.get("Cisco-IOS-XE-interfaces-oper:interfaces") or {}).get("interface") or []):
            raw = i.get("oper-status", "")
            adm = str(i.get("admin-status", ""))
            ifs[i.get("name", "")] = {"state": "disabled" if adm.endswith("down") else link_state(raw), "raw": raw.replace("if-oper-state-", ""),
                                      "desc": i.get("description", ""), "speed": int(i["speed"]) // 1_000_000 if str(i.get("speed", "")).isdigit() else None}
            if i.get("ipv4") and i.get("ipv4") != "0.0.0.0":
                xe_addrs.append(str(i["ipv4"]))
        if not ifs:
            st = await self.rc("ietf-interfaces:interfaces-state")
            for i in ((st.get("ietf-interfaces:interfaces-state") or {}).get("interface") or []):
                ifs[i.get("name", "")] = {"state": link_state(i.get("oper-status")), "raw": i.get("oper-status", ""), "desc": "",
                                          "speed": int(i["speed"]) // 1_000_000 if str(i.get("speed", "")).isdigit() else None}
        nbs = []
        ll = (await self.rc("Cisco-IOS-XE-lldp-oper:lldp-entries")).get("Cisco-IOS-XE-lldp-oper:lldp-entries") or {}
        for itf in ll.get("lldp-intf-details") or []:
            for n in itf.get("lldp-neighbor-details") or []:
                ma = n.get("mgmt-addrs") or {}
                ma = ma.get("mgmt-addr") if isinstance(ma, dict) else ma
                mg = [x.get("mgmt-addr") if isinstance(x, dict) else x for x in (ma if isinstance(ma, list) else [ma] if ma else [])]
                nbs.append({"local": itf.get("if-name", ""), "remote": n.get("system-name") or n.get("chassis-id", ""), "remote_port": n.get("port-id", ""),
                            "remote_port_desc": n.get("port-desc", ""), "remote_mgmt": (mg[0] if mg else "") or "", "remote_desc": str(n.get("system-desc", ""))[:200],
                            "proto": "lldp"})
        if not nbs:
            for n in ll.get("lldp-entry") or []:
                nbs.append({"local": n.get("local-interface", ""), "remote": n.get("device-id", ""), "remote_port": n.get("connecting-interface", ""), "proto": "lldp"})
        cd = (await self.rc("Cisco-IOS-XE-cdp-oper:cdp-neighbor-details")).get("Cisco-IOS-XE-cdp-oper:cdp-neighbor-details") or {}
        seen = {(if_short(n["local"]), short(n["remote"])) for n in nbs}
        for n in cd.get("cdp-neighbor-detail") or []:
            rem = n.get("device-name") or n.get("device-id", "")
            if (if_short(n.get("local-intf-name", "")), short(rem)) in seen:
                continue
            nbs.append({"local": n.get("local-intf-name", ""), "remote": rem, "remote_port": n.get("port-id", ""), "remote_desc": n.get("platform-name", ""),
                        "remote_mgmt": n.get("ip-address") or n.get("mgmt-address") or "", "proto": "cdp"})
        bgp = {}
        b = await self.rc("Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors")
        for n in find_dicts(b, ("neighbor-id", "session-state")):
            bgp[n["neighbor-id"]] = {"state": str(n.get("session-state", "")).replace("fsm-", "").capitalize(), "asn": n.get("as"),
                                     "vrf": n.get("vrf-name", "default") or "default"}
        return {"device": dev, "ifaces": ifs, "neighbors": nbs, "mlag": {}, "bgp": bgp, "addresses": sorted(set(xe_addrs))}

    async def checks(self):
        await self.login()
        res = {"RESTCONF native/hostname": await self._probe("GET", "/restconf/data/Cisco-IOS-XE-native:native/hostname")}
        for p in ("Cisco-IOS-XE-interfaces-oper:interfaces", "Cisco-IOS-XE-lldp-oper:lldp-entries", "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"):
            v = await self._probe("GET", f"/restconf/data/{p}")
            res[p.split(":")[0]] = v if v == "ok" else f"warn: {v}"
        return res


# ====================================================================== SNMP(공통 — 구형 IOS·기타 벤더)
OID = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysName": "1.3.6.1.2.1.1.5.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
       "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifAdmin": "1.3.6.1.2.1.2.2.1.7", "ifOper": "1.3.6.1.2.1.2.2.1.8",
       "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18", "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
       "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3", "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
       "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7", "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
       "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9", "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
       "cdpDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6", "cdpDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7", "cdpPlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8"}
IF_OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


class SnmpSwitchConnector(NetDevice):
    """SNMP v2c/v3 폴링 — 장비 종류와 무관(벤더는 sysDescr 로 추정). 실제 호출은 _walk/_get(테스트에서 교체 가능)."""
    type = "snmp-switch"
    source = "network"
    vendor = ""

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.base_url = ""
        self._state["target"] = f"udp://{self.host}:{cfg.get('port', 161)}"

    def _auth(self):
        from pysnmp.hlapi.v3arch import asyncio as h
        if self.cfg.get("snmp_user"):
            ap = {"sha": h.usmHMACSHAAuthProtocol, "sha256": h.usmHMAC192SHA256AuthProtocol, "md5": h.usmHMACMD5AuthProtocol}.get(str(self.cfg.get("auth_proto", "sha")).lower(), h.usmHMACSHAAuthProtocol)
            pp = {"aes": h.usmAesCfb128Protocol, "aes128": h.usmAesCfb128Protocol, "des": h.usmDESPrivProtocol}.get(str(self.cfg.get("priv_proto", "aes")).lower(), h.usmAesCfb128Protocol)
            return h.UsmUserData(self.cfg["snmp_user"], authKey=self.cfg.get("auth_key") or None, privKey=self.cfg.get("priv_key") or None,
                                 authProtocol=ap if self.cfg.get("auth_key") else h.usmNoAuthProtocol,
                                 privProtocol=pp if self.cfg.get("priv_key") else h.usmNoPrivProtocol)
        return h.CommunityData(self.cfg.get("community") or "public", mpModel=1)

    async def _target(self):
        from pysnmp.hlapi.v3arch import asyncio as h
        loop = asyncio.get_running_loop()
        if getattr(self, "_eng_loop", None) is not loop:   # SnmpEngine 은 만든 이벤트 루프에 묶임(루프가 바뀌면 새로)
            self._eng = h.SnmpEngine()
            self._eng_loop = loop
        tgt = await h.UdpTransportTarget.create((self.host.split(":")[0], int(self.cfg.get("port", 161))), timeout=float(self.cfg.get("timeout", 3)), retries=1)
        return h, tgt

    async def _get(self, oids: list[str]) -> dict[str, Any]:
        h, tgt = await self._target()
        err, st, _idx, binds = await h.get_cmd(self._eng, self._auth(), tgt, h.ContextData(), *[h.ObjectType(h.ObjectIdentity(o)) for o in oids])
        if err or st:
            raise RuntimeError(f"SNMP get: {err or st.prettyPrint()}")
        return {str(n): v.prettyPrint() for n, v in binds}

    async def _walk(self, oid: str) -> dict[str, str]:
        h, tgt = await self._target()
        out: dict[str, str] = {}
        async for err, st, _i, binds in h.bulk_walk_cmd(self._eng, self._auth(), tgt, h.ContextData(), 0, 25, h.ObjectType(h.ObjectIdentity(oid)),
                                                       lexicographicMode=False):
            if err or st:
                break
            for n, v in binds:
                out[str(n)] = v.prettyPrint()
            if len(out) > 20000:
                break
        return out

    async def login(self):
        self._state["auth"] = "snmpv3" if self.cfg.get("snmp_user") else "snmpv2c"

    @staticmethod
    def _idx(table: dict[str, str], base: str) -> dict[str, str]:
        return {k[len(base) + 1:]: v for k, v in table.items() if k.startswith(base + ".")}

    async def collect(self) -> dict[str, Any]:
        g = await self._get([OID["sysName"], OID["sysDescr"], OID["sysUpTime"]])
        descr = g.get(OID["sysDescr"], "")
        vendor = "Arista" if "arista" in descr.lower() else "Cisco" if "cisco" in descr.lower() else (self.cfg.get("vendor") or "기타")
        self.vendor = vendor
        if vendor == "Arista":
            self.source = "arista"
        elif vendor == "Cisco":
            self.source = "cisco"
        ver = re.search(r"(?:Version|EOS version|NX-OS.*?version)\s+([\w.()\-]+)", descr, re.I)
        try:
            up = int(g.get(OID["sysUpTime"], "0")) // 100
        except ValueError:
            up = None
        dev = {"hostname": g.get(OID["sysName"]) or self.name, "model": "", "os": descr.split(",")[0][:60], "version": ver.group(1) if ver else "", "uptime": up}
        names = self._idx(await self._walk(OID["ifName"]), OID["ifName"]) or self._idx(await self._walk(OID["ifDescr"]), OID["ifDescr"])
        oper = self._idx(await self._walk(OID["ifOper"]), OID["ifOper"])
        adm = self._idx(await self._walk(OID["ifAdmin"]), OID["ifAdmin"])
        alias = self._idx(await self._walk(OID["ifAlias"]), OID["ifAlias"])
        spd = self._idx(await self._walk(OID["ifHighSpeed"]), OID["ifHighSpeed"])
        ifs = {}
        for ix, n in names.items():
            o = int(oper.get(ix, "4") or 4) if str(oper.get(ix, "4")).isdigit() else 4
            a = str(adm.get(ix, "1"))
            ifs[n] = {"state": "disabled" if a == "2" else "up" if o == 1 else "down" if o in (2, 7) else "unknown", "raw": IF_OPER.get(o, str(o)),
                      "desc": alias.get(ix, ""), "speed": int(spd[ix]) if str(spd.get(ix, "")).isdigit() and int(spd[ix]) else None, "ifindex": ix}
        nbs = []
        locid = self._idx(await self._walk(OID["lldpLocPortId"]), OID["lldpLocPortId"])
        locdesc = self._idx(await self._walk(OID["lldpLocPortDesc"]), OID["lldpLocPortDesc"])
        rname = self._idx(await self._walk(OID["lldpRemSysName"]), OID["lldpRemSysName"])
        rport = self._idx(await self._walk(OID["lldpRemPortId"]), OID["lldpRemPortId"])
        rpdesc = self._idx(await self._walk(OID["lldpRemPortDesc"]), OID["lldpRemPortDesc"])
        rdesc = self._idx(await self._walk(OID["lldpRemSysDesc"]), OID["lldpRemSysDesc"])
        ifkeys = {if_short(n): n for n in ifs}
        for idx, sysn in rname.items():                 # 인덱스: timeMark.localPortNum.remIndex
            parts = idx.split(".")
            if len(parts) < 3:
                continue
            lp = parts[1]
            loc = locid.get(lp) or locdesc.get(lp) or lp
            loc = ifkeys.get(if_short(loc)) or ifkeys.get(if_short(locdesc.get(lp, ""))) or names.get(lp) or loc
            nbs.append({"local": loc, "remote": sysn, "remote_port": rport.get(idx, ""), "remote_port_desc": rpdesc.get(idx, ""),
                        "remote_desc": rdesc.get(idx, "")[:200], "proto": "lldp"})
        seen = {(if_short(n["local"]), short(n["remote"])) for n in nbs}
        cid = self._idx(await self._walk(OID["cdpDeviceId"]), OID["cdpDeviceId"])
        cport = self._idx(await self._walk(OID["cdpDevicePort"]), OID["cdpDevicePort"]) if cid else {}
        cplat = self._idx(await self._walk(OID["cdpPlatform"]), OID["cdpPlatform"]) if cid else {}
        for idx, dvc in cid.items():                     # 인덱스: ifIndex.deviceIndex
            loc = names.get(idx.split(".")[0], idx.split(".")[0])
            if (if_short(loc), short(dvc)) in seen:
                continue
            nbs.append({"local": loc, "remote": dvc, "remote_port": cport.get(idx, ""), "remote_desc": cplat.get(idx, ""), "proto": "cdp"})
        return {"device": dev, "ifaces": ifs, "neighbors": nbs, "mlag": {}, "bgp": {}}

    async def checks(self):
        await self.login()
        try:
            g = await self._get([OID["sysName"], OID["sysDescr"]])
            res = {"SNMP sysName/sysDescr": f"ok {g.get(OID['sysName'], '')} — {g.get(OID['sysDescr'], '')[:80]}"}
        except Exception as e:  # noqa: BLE001
            return {"SNMP sysName/sysDescr": f"{type(e).__name__}: {e}"[:200]}
        for k in ("ifName", "lldpRemSysName", "cdpDeviceId"):
            try:
                n = len(await self._walk(OID[k]))
                res[f"SNMP {k}"] = f"ok {n}개" if n or k != "ifName" else "warn: 0개"
            except Exception as e:  # noqa: BLE001
                res[f"SNMP {k}"] = f"warn: {e}"[:120]
        return res


class CiscoAutoConnector(NetDevice):
    """type: cisco — platform: auto(기본) | nxos | iosxe | snmp. auto 는 NX-API → RESTCONF → SNMP(community 설정 시) 순서로 시험해 결정."""
    type = "cisco"
    source = "cisco"
    vendor = "Cisco"

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self._impl: NetDevice | None = None

    def _make(self, plat: str) -> NetDevice:
        cls = {"nxos": CiscoNxosConnector, "iosxe": CiscoIosxeConnector, "snmp": SnmpSwitchConnector}[plat]
        c = cls(self.cfg, self.emit)
        c._state = self._state
        c.legacy_tls = self.legacy_tls
        return c

    def switch_legacy_tls(self, e: BaseException) -> bool:
        ok = super().switch_legacy_tls(e)
        if ok and self._impl is not None:
            self._impl.legacy_tls, self._impl._http = True, None
        return ok

    async def login(self):
        plat = str(self.cfg.get("platform", "auto")).lower()
        if plat != "auto":
            self._impl = self._impl or self._make(plat)
            await self._impl.login()
            return
        if self._impl:
            await self._impl.login()
            return
        errs = []
        for p in ("nxos", "iosxe") + (("snmp",) if self.cfg.get("community") or self.cfg.get("snmp_user") else ()):
            for _ in range(2):                                  # 구형 TLS(TLS 1.0/1.1) 장비면 구형 호환으로 같은 플랫폼 재시도
                c = self._make(p)
                try:
                    await c.login()
                    await asyncio.wait_for(c.collect(), timeout=30)
                    self._impl = c
                    self._state["checks"]["플랫폼"] = f"ok {p} 자동 판별" + (" · 구형 TLS 호환" if c.legacy_tls else "")
                    return
                except Exception as e:  # noqa: BLE001
                    if p != "snmp" and self.switch_legacy_tls(e):
                        continue
                    errs.append(f"{p}: {type(e).__name__} {str(e)[:90]}")
                    break
        raise RuntimeError("Cisco 플랫폼 자동 판별 실패 — " + " · ".join(errs) + " (NX-OS: feature nxapi / IOS-XE: restconf / 구형: SNMP 커뮤니티)")

    async def fetch_config(self):
        return await self._impl.fetch_config() if self._impl else None

    async def collect(self):
        if not self._impl:
            await self.login()
        d = await self._impl.collect()
        return d

    async def checks(self):
        await self.login()
        return {**self._state.get("checks", {}), **(await self._impl.checks())}
