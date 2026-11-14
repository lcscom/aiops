"""스위치·라우터 running-config 해석(2.4) — 포트별 구성(설명·셧다운·access/trunk·VLAN·LAG·L3·MTU)과 사용 여부, 구성 점검, 변경 감지.

수집(읽기 전용)
  Arista EOS : eAPI runCmds format=text  'show running-config'
  Cisco NX-OS: NX-API type=cli_show_ascii 'show running-config'
  Cisco IOS-XE: RESTCONF Cisco-IOS-XE-native:native/interface (JSON) → 같은 형식으로 변환
비밀값(secret·password·community·key …)은 저장·표시 전에 가린다. 원문은 메모리에만(마지막 1개) 두고 DB 에 쓰지 않는다.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any

SECRET_RE = re.compile(r"(?i)\b(secret|password|community|key(?:-string)?|passphrase|auth(?:entication)?-key|md5|sha\d*|priv|psk|pre-shared-key|"
                       r"encrypted|hash|ssh-rsa|ssh-ed25519)\b(\s+(?:\d\s+|sha512\s+|md5\s+|7\s+|5\s+|8\s+|9\s+)?)(\S+)")


def mask(text: str) -> str:
    """비밀값 토큰을 '<가림>' 으로 — 줄 구조는 유지(차이 비교용)"""
    out = []
    for ln in str(text or "").splitlines():
        if re.search(r"(?i)^\s*(username|enable\s+(secret|password)|snmp-server\s+(community|user)|tacacs|radius|aaa\s+.*key|"
                     r"crypto\s+(key|pki)|key\s+\d|ntp\s+authentication-key|feature\s+password)", ln) or SECRET_RE.search(ln):
            ln = SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<가림>", ln)
            ln = re.sub(r"(?i)(snmp-server\s+community\s+)\S+", r"\1<가림>", ln)
        out.append(ln)
    return "\n".join(out)


def vlan_list(spec: str) -> set[int] | None:
    """'1-10,20,30-32' → {…} · 'all' → None(전부) · 'none' → 빈 집합"""
    s = str(spec or "").strip().lower()
    if not s or s == "all":
        return None
    if s == "none":
        return set()
    out: set[int] = set()
    for part in s.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and int(b) - int(a) < 4096:
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def _canon(name: str) -> str:
    return re.sub(r"\s+", "", str(name or ""))


def parse(text: str) -> dict[str, Any]:
    """IOS 계열 문법(EOS·NX-OS·IOS/IOS-XE CLI) running-config → {hostname, interfaces{이름: {...}}, vlans{id: 이름}, logging[], ntp[], lldp, …}"""
    ifs: dict[str, dict] = {}
    vlans: dict[int, str] = {}
    g: dict[str, Any] = {"hostname": "", "logging": [], "ntp": [], "snmp": False, "lldp": None, "eapi": None, "nxapi": None, "restconf": False, "lines": 0}
    cur: dict | None = None
    cur_vlan: int | None = None
    block = ""
    for raw in str(text or "").splitlines():
        if not raw.strip():
            continue
        g["lines"] += 1
        if raw.lstrip().startswith("!") or raw.startswith("#") or raw.lower().startswith(("version ", "boot ")):
            if not raw.startswith((" ", "\t")):
                cur, cur_vlan, block = None, None, ""
            continue
        indented = raw.startswith((" ", "\t"))
        ln = raw.strip()
        low = ln.lower()
        if not indented:
            cur, cur_vlan, block = None, None, low.split(" ")[0]
            m = re.match(r"(?i)^interface\s+(.+)$", ln)
            if m:
                nm = _canon(m.group(1))
                cur = ifs.setdefault(nm, {"name": nm, "desc": "", "shutdown": False, "mode": "", "access_vlan": None, "trunk_vlans": "", "native_vlan": None,
                                          "channel_group": "", "lacp_mode": "", "ip": "", "vrf": "", "mtu": None, "speed": "", "routed": False,
                                          "portfast": False, "vpc": "", "mlag": "", "lines": []})
                continue
            m = re.match(r"(?i)^vlan\s+([\d,\-]+)$", ln)
            if m:
                ids = vlan_list(m.group(1)) or set()
                for v in ids:
                    vlans.setdefault(v, "")
                cur_vlan = min(ids) if len(ids) == 1 else None
                continue
            if low.startswith("hostname "):
                g["hostname"] = ln.split(None, 1)[1]
            elif re.match(r"(?i)^logging\s+(host|server)\s+", ln):
                g["logging"].append(ln.split()[2])
            elif re.match(r"(?i)^ntp\s+server\s+", ln):
                g["ntp"].append(ln.split()[2] if len(ln.split()) > 2 else "")
            elif low.startswith("snmp-server"):
                g["snmp"] = True
            elif low in ("lldp run", "feature lldp"):
                g["lldp"] = True
            elif low in ("no lldp run",):
                g["lldp"] = False
            elif low == "feature nxapi":
                g["nxapi"] = True
            elif low == "restconf":
                g["restconf"] = True
            elif low.startswith("management api http-commands"):
                g["eapi"] = False                         # 블록 안 'no shutdown' 이면 True
            continue
        # ---- 들여쓴 줄
        if cur_vlan is not None and low.startswith("name "):
            vlans[cur_vlan] = ln.split(None, 1)[1]
            continue
        if block == "management" and g["eapi"] is not None and low == "no shutdown":
            g["eapi"] = True
            continue
        if cur is None:
            continue
        cur["lines"].append(ln)
        if low.startswith("description "):
            cur["desc"] = ln.split(None, 1)[1]
        elif low == "shutdown":
            cur["shutdown"] = True
        elif low == "no shutdown":
            cur["shutdown"] = False
        elif low == "no switchport":
            cur["routed"] = True
        elif low.startswith("switchport mode "):
            cur["mode"] = low.split()[2]
        elif low.startswith("switchport access vlan "):
            v = low.split()[3]
            cur["access_vlan"] = int(v) if v.isdigit() else None
            cur["mode"] = cur["mode"] or "access"
        elif low.startswith("switchport trunk allowed vlan "):
            rest = low.split("switchport trunk allowed vlan ", 1)[1].strip()
            if rest.startswith("add "):
                cur["trunk_vlans"] = (cur["trunk_vlans"] + "," if cur["trunk_vlans"] else "") + rest[4:]
            elif rest.startswith("remove ") or rest.startswith("except "):
                cur["trunk_vlans"] = cur["trunk_vlans"] or "all"
            else:
                cur["trunk_vlans"] = rest
        elif low.startswith("switchport trunk native vlan "):
            v = low.split()[-1]
            cur["native_vlan"] = int(v) if v.isdigit() else None
        elif low.startswith("channel-group "):
            p = low.split()
            cur["channel_group"] = p[1]
            cur["lacp_mode"] = p[3] if len(p) > 3 and p[2] == "mode" else ""
        elif low.startswith(("ip address ", "ipv4 address ")) and "dhcp" not in low:
            p = ln.split()
            cur["ip"] = p[2] if "/" in p[2] or len(p) < 4 else f"{p[2]}/{sum(bin(int(x)).count('1') for x in p[3].split('.') if x.isdigit())}"
            cur["routed"] = cur["routed"] or not cur["name"].lower().startswith(("vlan", "loopback", "lo", "mgmt", "management"))
        elif low.startswith(("vrf forwarding ", "vrf member ", "vrf ")) and not low.startswith("vrf definition"):
            cur["vrf"] = ln.split()[-1]
        elif low.startswith("mtu "):
            v = low.split()[1]
            cur["mtu"] = int(v) if v.isdigit() else None
        elif low.startswith("speed "):
            cur["speed"] = low.split()[1]
        elif low.startswith(("spanning-tree portfast", "spanning-tree port type edge")):
            cur["portfast"] = True
        elif low.startswith("vpc "):
            cur["vpc"] = low.split()[1]
        elif low.startswith("mlag "):
            cur["mlag"] = low.split()[1]
    for i in ifs.values():
        i["lines"] = i["lines"][:40]
        if not i["mode"] and (i["trunk_vlans"] or i["native_vlan"]):
            i["mode"] = "trunk"
    return {"hostname": g["hostname"], "interfaces": ifs, "vlans": vlans, "global": g}


def from_iosxe_native(native: dict) -> tuple[str, dict[str, Any]]:
    """RESTCONF Cisco-IOS-XE-native:native/interface JSON → (CLI 비슷한 텍스트, parse 결과)"""
    itf = (native or {}).get("Cisco-IOS-XE-native:interface") or (native or {}).get("interface") or {}
    lines: list[str] = []
    for typ, lst in itf.items():
        for i in (lst if isinstance(lst, list) else [lst]):
            nm = f"{typ}{i.get('name', '')}"
            lines.append(f"interface {nm}")
            if i.get("description"):
                lines.append(f" description {i['description']}")
            if "shutdown" in i:
                lines.append(" shutdown")
            sw = i.get("switchport") or i.get("Cisco-IOS-XE-switch:switchport") or {}
            mode = (sw.get("Cisco-IOS-XE-switch:mode") or sw.get("mode") or {})
            if isinstance(mode, dict) and mode:
                lines.append(f" switchport mode {next(iter(mode))}")
            acc = ((sw.get("Cisco-IOS-XE-switch:access") or sw.get("access") or {}).get("vlan") or {}).get("vlan")
            if acc:
                lines.append(f" switchport access vlan {acc}")
            tr = sw.get("Cisco-IOS-XE-switch:trunk") or sw.get("trunk") or {}
            alw = ((tr.get("allowed") or {}).get("vlan") or {})
            vl = alw.get("vlans") or (alw.get("add") if isinstance(alw.get("add"), str) else "")
            if vl:
                lines.append(f" switchport trunk allowed vlan {vl}")
            nat = ((tr.get("native") or {}).get("vlan") or {})
            if isinstance(nat, dict) and nat.get("vlan-id"):
                lines.append(f" switchport trunk native vlan {nat['vlan-id']}")
            ch = i.get("Cisco-IOS-XE-ethernet:channel-group") or i.get("channel-group") or {}
            if ch.get("number"):
                lines.append(f" channel-group {ch['number']} mode {ch.get('mode', 'on')}")
            ip = (((i.get("ip") or {}).get("address") or {}).get("primary") or {})
            if ip.get("address"):
                lines.append(f" ip address {ip['address']} {ip.get('mask', '')}".rstrip())
            if i.get("mtu"):
                lines.append(f" mtu {i['mtu']}")
            lines.append("!")
    text = "\n".join(lines)
    return text, parse(text)


def diff_summary(old: str, new: str) -> dict[str, Any]:
    """마스킹된 두 구성의 차이 — 추가·삭제 줄 수와 바뀐 interface·최상위 블록 이름"""
    a, b = str(old or "").splitlines(), str(new or "").splitlines()
    added = removed = 0
    blocks: list[str] = []
    ctx = ""
    cur_new = {i: ln for i, ln in enumerate(b)}
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        removed += i2 - i1
        added += j2 - j1
        idx = j1 if j1 < len(b) else max(0, len(b) - 1)
        ctx = ""
        for k in range(idx, -1, -1):
            ln = cur_new.get(k, "")
            if ln and not ln.startswith((" ", "\t", "!")):
                ctx = ln.strip()
                break
        if ctx and ctx not in blocks:
            blocks.append(ctx)
    sample = [ln for ln in difflib.unified_diff(a, b, lineterm="", n=0) if ln[:1] in "+-" and not ln.startswith(("+++", "---"))][:40]
    return {"added": added, "removed": removed, "blocks": blocks[:20], "sample": sample}


def digest(text: str) -> str:
    """시각·가동 시간처럼 매번 바뀌는 줄을 빼고 해시"""
    t = "\n".join(ln for ln in str(text or "").splitlines()
                  if not re.match(r"(?i)^\s*(!\s*(time|last configuration change|nvram config last updated|running configuration)|!Command:|!Running configuration last done|!Time:)", ln))
    return hashlib.sha256(t.encode()).hexdigest()[:16]


USAGE = {"in_use": "사용 중", "configured": "구성됨·미연결", "shut": "미사용·닫힘", "open": "미사용·열림", "err": "오류(err-disabled)"}


def port_usage(state: str, raw: str, cfg: dict | None, has_peer: bool) -> str:
    """링크 상태 + 구성 → 사용 구분(in_use·configured·shut·open·err)"""
    r = str(raw or "").lower()
    if "err" in r and "disab" in r:
        return "err"
    if state == "up":
        return "in_use"
    if state == "disabled" or (cfg or {}).get("shutdown"):
        return "shut"
    c = cfg or {}
    if has_peer or c.get("desc") or c.get("channel_group") or c.get("ip") or c.get("access_vlan") not in (None, 1) or c.get("trunk_vlans") or c.get("mode") == "trunk":
        return "configured"
    return "open"
