"""내부 취약점 검증(2.43.0) — 보안·비용 › 보안 › 취약점 검증

'내부에 들어온 공격자(침해된 업무 VM)가 어디까지 갈 수 있나'를 계속 다시 계산한다. 공격 도구를 쓰지 않는 읽기 전용 검증.

1) 자산·약점 모으기(이미 수집된 자료)
   · VMware 버전 취약점      보안 판독(VMSA/NVD 대조) 결과의 '취약'·'가능'
   · 하드닝 실패             보안 판독의 FAIL(상) — SSH·셸·잠금 모드·SLP·방화벽 등
   · 호스트 노출             인프라 점검 스냅숏: TSM-SSH·ESXi Shell 실행, 잠금 모드 꺼짐
   · 망 분리                 관리(vmk management)·vSAN·vMotion VMkernel 의 VLAN 이 업무 VM 포트그룹 VLAN 과 같은지 — 같으면 업무 VM 에서 관리망이 L2 로 바로 보임
   · 네트워크 장비 구성      스위치 running-config: telnet·HTTP 관리·SNMP v1/v2c 기본 커뮤니티(public·private)·평문 enable 비밀번호·원격 로그 없음
   · 물리 포트               열려 있는 미사용 포트(설명·이웃 없음, no shutdown)
   · 인증서                  만료됐거나 임박한 인증서
   · 지원 종료 버전          수명 주기 점검: 일반 지원 종료(EoGS)가 지난 제품 — 보안 패치 없음
   · 복구 수단               vCenter 파일 기반 백업 없음·오래됨(랜섬웨어 복구)
   · 알려진 악용(KEV)        CISA KEV 목록(JSON 가져오기) 과 CVE·제품 대조 — 악용 중인 취약점이면 등급을 올림
2) 공격 경로(알고리즘)
   출발 = 침해된 업무 VM → [관리망 도달] → [ESXi·vCenter 장악] → [영향 범위]
   · 도달: 같은 VLAN 이면 '확인됨', 다른 VLAN 이면 '조건부'(방화벽·ACL 은 수집하지 않아 확인 못 함)
   · 장악: 그 자산의 가장 심각한 약점(취약 CVE > 하드닝 실패·SSH 노출)
   · 영향: ESXi = 그 호스트의 VM, vCenter = 그 vCenter 의 모든 VM
   · 경로 위험 = 장악 심각도 × 도달 확실성 × (1 + log 영향 VM 수) × (KEV 면 1.5)
   · 끊는 지점: 경로의 고리 중 가장 싸게 끊을 곳(망 분리 > 노출 끄기 > 패치)을 표시
3) 계속 검증
   · 6시간마다(보안 판독이 새로 돌면 그 다음 주기) 다시 계산, 이력 보관, 새로 생긴 높음·치명 약점과 새 공격 경로는 이상징후로 알림
   · 선택(기본 꺼짐) 능동 확인: 노출로 판단한 서비스 포트(ESXi 22·427·5989)에 TCP 연결만 해 실제로 열렸는지 확인 — 데이터 전송·로그인 없음
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from typing import Any

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_KO = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음"}
SCHEMA = ("CREATE TABLE IF NOT EXISTS vuln_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, summary TEXT, data TEXT)",
          "CREATE TABLE IF NOT EXISTS vuln_kev(cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, added TEXT, ransomware TEXT)",
          "CREATE TABLE IF NOT EXISTS vuln_kv(k TEXT PRIMARY KEY, v TEXT)")
PRODUCT_KEV = {"esxi": ("vmware", "esxi"), "vcenter": ("vmware", "vcenter"), "fortios": ("fortinet", "fortios"), "eos": ("arista", "eos"),
               "nxos": ("cisco", "nx-os"), "nsx": ("vmware", "nsx")}


def _f(fid, layer, asset, title, sev, evidence, fix, source="구성", **kw) -> dict:
    return {"id": fid, "layer": layer, "asset": asset, "title": title, "sev": sev, "evidence": evidence, "fix": fix, "source": source, **kw}


# ------------------------------------------------------------------ 1) 약점 모으기 — 순수 함수(시험 쉬움)
def switch_config_findings(name: str, text: str) -> list[dict]:
    out = []
    low = text.lower()
    lines = [ln.strip() for ln in low.splitlines()]
    if any(re.match(r"^(feature telnet|ip telnet server|management telnet|transport input (all|telnet))", ln) for ln in lines):
        out.append(_f(f"sw-telnet:{name}", "네트워크", name, "telnet 관리 접속이 켜져 있음", "high", "running-config 에 telnet 설정", "telnet 끄고 SSH 만 허용"))
    if any(re.match(r"^(ip http server|feature http-server|management http)", ln) for ln in lines) and not any(ln.startswith("no ip http server") for ln in lines):
        out.append(_f(f"sw-http:{name}", "네트워크", name, "평문 HTTP 관리가 켜져 있음", "medium", "ip http server(또는 동등 설정)", "HTTP 끄고 HTTPS·API 는 관리망 ACL 로 제한"))
    comm = re.findall(r"snmp-server community\s+(\S+)", low)
    if any(c in ("public", "private") for c in comm):
        out.append(_f(f"sw-snmp-default:{name}", "네트워크", name, "SNMP 기본 커뮤니티(public/private)", "high", f"snmp-server community {', '.join(sorted(set(comm)))[:60]}",
                      "기본 커뮤니티 삭제, SNMPv3(인증·암호화)로 전환"))
    elif comm and "snmp-server user" not in low:
        out.append(_f(f"sw-snmp-v2:{name}", "네트워크", name, "SNMP v1/v2c 만 사용(평문 커뮤니티)", "medium", f"커뮤니티 {len(comm)}개, SNMPv3 사용자 없음", "SNMPv3 로 전환하거나 ACL 로 수집기만 허용"))
    if re.search(r"^enable password\s", low, re.M):
        out.append(_f(f"sw-enable:{name}", "네트워크", name, "enable password(약한 해시·평문)", "medium", "enable password 사용", "enable secret(강한 해시) 사용"))
    if not re.search(r"^logging (host|server)\s", low, re.M):
        out.append(_f(f"sw-nolog:{name}", "네트워크", name, "원격 로그 전송 없음 — 침해 흔적이 남지 않음", "low", "logging host 설정 없음", "syslog 서버(이 포털·SIEM) 지정"))
    return out


def segmentation(world: dict) -> list[dict]:
    """관리·vSAN·vMotion VMkernel VLAN 과 업무 VM 포트그룹 VLAN 이 같은 곳"""
    out = []
    for vc in world["vcenters"]:
        nets = vc["topo"].get("networks") or {}
        key2 = {n.get("key"): (nm, n) for nm, n in nets.items() if n.get("key")}
        vm_vlans: dict[int, list] = {}
        for vn, v in (vc["topo"].get("vms") or {}).items():
            for nm in v.get("networks") or []:
                vl = (nets.get(nm) or {}).get("vlan")
                if isinstance(vl, int):
                    vm_vlans.setdefault(vl, []).append((vn, nm))
        seen = set()
        for hn, h in vc["health"].items():
            for k in h.get("vmks") or []:
                svc = set(k.get("services") or [])
                kind = "management" if "management" in svc else "vsan" if "vsan" in svc else "vmotion" if "vmotion" in svc else ""
                if not kind:
                    continue
                vl = k.get("vlan")
                pgname = k.get("pg") or ""
                if vl is None and k.get("pg_key") in key2:
                    pgname, n = key2[k["pg_key"]]
                    vl = n.get("vlan")
                if not isinstance(vl, int) or vl not in vm_vlans:
                    continue
                vms = sorted({x[0] for x in vm_vlans[vl] if x[1] != pgname} | {x[0] for x in vm_vlans[vl] if x[1] == pgname})
                key = (vc["name"], kind, vl)
                if key in seen:
                    continue
                seen.add(key)
                label = {"management": "관리망", "vsan": "vSAN 망", "vmotion": "vMotion 망"}[kind]
                out.append(_f(f"seg-{kind}:{vc['name']}:{vl}", "망 분리", f"{vc['name']} VLAN {vl}", f"업무 VM 이 {label}(VLAN {vl})과 같은 L2 에 있음",
                              "critical" if kind == "management" else "high",
                              f"VMkernel {k.get('device')}({kind}, {pgname or '포트그룹 ?'}) 와 VM {len(vms)}대가 같은 VLAN: {', '.join(vms[:5])}",
                              f"{label}을 전용 VLAN·포트그룹으로 분리하고 업무 VM 이 붙지 못하게 하세요", vlan=vl, kind=kind, vms=vms[:200], vcenter=vc["name"]))
    return out


def host_exposure(world: dict) -> list[dict]:
    out = []
    for vc in world["vcenters"]:
        for hn, h in vc["health"].items():
            sv = h.get("services") or {}
            if sv.get("TSM-SSH"):
                out.append(_f(f"esx-ssh:{hn}", "ESXi", hn, "ESXi SSH 가 실행 중", "high", "TSM-SSH 실행", "작업 때만 켜고 끝나면 끄기(시작 정책 '수동')",
                              vcenter=vc["name"], port=22))
            if sv.get("TSM"):
                out.append(_f(f"esx-shell:{hn}", "ESXi", hn, "ESXi Shell 이 실행 중", "medium", "TSM 실행", "ESXi Shell 끄기", vcenter=vc["name"]))
            if str(h.get("lockdown", "")).lower() in ("lockdowndisabled", "disabled"):
                out.append(_f(f"esx-lock:{hn}", "ESXi", hn, "잠금 모드(lockdown) 꺼짐 — 호스트에 직접 로그인 가능", "medium", f"lockdown={h.get('lockdown')}",
                              "잠금 모드 '일반' 이상으로", vcenter=vc["name"]))
    return out


def evaluate(world: dict, assess: dict | None, certs: list[dict], life: list[dict], backups: dict, sw_cfg: dict[str, str], portmap_findings: list[dict],
             kev: dict[str, dict], kev_products: dict[str, int]) -> list[dict]:
    F: list[dict] = []
    vc_of = {}
    for vc in world["vcenters"]:
        for hn in vc["topo"].get("hosts") or {}:
            vc_of[hn] = vc["name"]
        vc_of[vc.get("host") or vc["name"]] = vc["name"]
    # VMware 버전 취약점·하드닝(보안 판독)
    if assess:
        for r in assess.get("cve") or []:
            if r.get("verdict") not in ("취약", "가능"):
                continue
            cves = [c for c in (r.get("cves") or []) if c]
            k = [c for c in cves if c in kev]
            sev = str(r.get("severity") or "").lower()
            sev = sev if sev in SEV else ("critical" if (r.get("cvss") or 0) >= 9 else "high" if (r.get("cvss") or 0) >= 7 else "medium")
            if r["verdict"] == "가능":
                sev = {"critical": "high", "high": "medium"}.get(sev, "low")
            if k:
                sev = "critical"
            prod = r.get("product", "")
            tg = r.get("target", "")
            F.append(_f(f"cve:{r.get('id')}:{tg}", "ESXi" if prod == "esxi" else "vCenter", tg,
                        f"{r.get('vmsa') or r.get('id')} {str(r.get('title') or '')[:80]}", sev, f"{r['verdict']} — 실행 {r.get('version', '')} {r.get('build', '')} · {str(r.get('why') or '')[:80]}",
                        "권고의 고정 빌드로 패치", "버전 대조", cves=cves[:10], kev=k, cvss=r.get("cvss"), vcenter=vc_of.get(tg, ""), product=prod))
        for r in assess.get("rows") or []:
            if r.get("status") == "FAIL" and r.get("severity") == "상":
                F.append(_f(f"hard:{r.get('id')}:{r.get('target')}", "ESXi" if str(r.get("id", "")).startswith("ESXI") else "vCenter", r.get("target", ""),
                            f"하드닝 실패 — {r.get('title')}", "high", f"현재 {str(r.get('current', ''))[:60]} / 기대 {str(r.get('expected', ''))[:60]}", r.get("fix") or "",
                            "보안 판독", vcenter=r.get("vcenter", "")))
    F += host_exposure(world)
    F += segmentation(world)
    for name, text in sw_cfg.items():
        F += switch_config_findings(name, text or "")
    for p in portmap_findings:
        if p.get("kind") == "unused-open":
            F.append(_f(f"port-open:{p.get('device')}", "물리 포트", p.get("device", ""), "미사용 포트가 열려 있음(no shutdown·설명 없음)", "low", str(p.get("text", ""))[:160],
                        "미사용 포트 shutdown, 포트 보안·802.1X"))
    for c in certs:
        if c.get("band") == "expired":
            F.append(_f(f"cert:{c.get('system')}:{c.get('name')}", "인증서", f"{c.get('system')} {c.get('name')}", f"만료된 인증서 — {c.get('kind')}", "high",
                        f"{-int(c.get('days_left') or 0)}일 전 만료", c.get("renew") or "인증서 갱신"))
    for x in life:
        if x.get("eogs_passed"):
            F.append(_f(f"eol:{x.get('product')}:{x.get('version')}:{x.get('where')}", "지원 종료", x.get("where") or x.get("product", ""), f"{x.get('product')} {x.get('version')} 일반 지원 종료 — 보안 패치 없음",
                        "high", f"EoGS {x.get('eogs')}", "지원되는 버전으로 업그레이드"))
    for vcn, b in backups.items():
        if not b.get("configured"):
            F.append(_f(f"bkp:{vcn}", "복구", vcn, "vCenter 파일 기반 백업이 없음 — 랜섬웨어·장애 때 되돌릴 수 없음", "medium", "백업 일정 미설정", "vCenter 백업 일정 설정(다른 망의 저장소)"))
        elif not b.get("last_success") or time.time() - float(b["last_success"]) > 7 * 86400:
            F.append(_f(f"bkp:{vcn}", "복구", vcn, "vCenter 백업이 7일 넘게 성공하지 않음", "medium", "마지막 성공 백업 7일 초과", "백업 실패 원인 확인"))
    for prod, n in kev_products.items():
        F.append(_f(f"kev-prod:{prod}", "알려진 악용", prod, f"이 환경의 제품({prod})에 실제 악용 중인 취약점이 {n}건 목록에 있음 — 버전 확인 필요", "medium",
                    "CISA KEV 목록 대조(제품 단위)", "제조사 권고에서 지금 버전이 해당되는지 확인", "KEV"))
    ssh_hard = {f["asset"] for f in F if f["id"].startswith("hard:") and "SSH" in f["title"]}
    F = [f for f in F if not (f["id"].startswith("esx-ssh:") and f["asset"] in ssh_hard)]
    seen, out = set(), []
    for f in F:
        if f["id"] not in seen:
            seen.add(f["id"])
            out.append(f)
    out.sort(key=lambda f: (-SEV[f["sev"]], f["layer"], f["asset"]))
    return out


# ------------------------------------------------------------------ 2) 공격 경로
def attack_paths(world: dict, F: list[dict]) -> list[dict]:
    seg = {(f["vcenter"]): f for f in F if f["id"].startswith("seg-management:")}
    by_asset: dict[str, list] = {}
    for f in F:
        if f["layer"] in ("ESXi", "vCenter"):
            by_asset.setdefault(f["asset"], []).append(f)
    paths = []
    for vc in world["vcenters"]:
        T = vc["topo"]
        V = T.get("vms") or {}
        s = seg.get(vc["name"])
        reach = ("확인됨", 1.0, f"업무 VM 이 관리망과 같은 VLAN {s['vlan']} ({len(s['vms'])}대)") if s else \
            ("조건부", 0.5, "관리망은 다른 VLAN — 라우팅·방화벽 정책에 따라 도달 가능(이 포털은 방화벽 정책을 수집하지 않음)")
        targets = [(hn, "ESXi", sum(1 for v in V.values() if v.get("host") == hn)) for hn in (T.get("hosts") or {})]
        targets.append((vc.get("host") or vc["name"], "vCenter", len(V)))
        for asset, kind, blast in targets:
            weak = sorted(by_asset.get(asset, []), key=lambda f: -SEV[f["sev"]])
            if not weak and s and kind == "vCenter":                  # 관리망이 열려 있으면 약점이 없어도 vCenter 로그인 시도가 가능
                weak = [_f(f"vc-login:{asset}", "vCenter", asset, "vSphere Client·API 로그인 화면에 바로 닿음(계정 대입·피싱한 계정 사용)", "medium",
                           "관리망 L2 도달", "관리망 분리, MFA(ID 페더레이션), 계정 잠금 정책", "경로 추론")]
            if not weak:
                continue
            w = weak[0]
            kev = any(f.get("kev") for f in weak)
            score = SEV[w["sev"]] * reach[1] * (1 + math.log10(1 + blast)) * (1.5 if kev else 1.0)
            brk = ("망 분리", s["fix"]) if s else (("노출 끄기", w["fix"]) if w["source"] != "버전 대조" else ("패치", w["fix"]))
            paths.append({"id": f"path:{vc['name']}:{asset}", "vcenter": vc["name"], "target": asset, "kind": kind, "score": round(score, 2),
                          "reach": reach[0], "steps": [{"t": "출발", "x": "침해된 업무 VM"}, {"t": "관리망 도달", "x": reach[2], "state": reach[0]},
                                                       {"t": f"{kind} 장악", "x": f"{w['title']} ({SEV_KO[w['sev']]}{', 악용 중(KEV)' if kev else ''})", "n": len(weak)},
                                                       {"t": "영향", "x": f"VM {blast}대" + (" — 이 vCenter 의 모든 VM·호스트 관리권" if kind == "vCenter" else " — 이 호스트의 VM")}],
                          "break": {"at": brk[0], "how": brk[1]}, "weak": [x["id"] for x in weak[:6]], "kev": kev, "blast": blast})
    paths.sort(key=lambda p: -p["score"])
    return paths[:30]


def risk_score(F: list[dict], paths: list[dict]) -> int:
    """0(좋음)~100(나쁨) — 약점 가중 합과 상위 경로를 섞어 포화 곡선으로"""
    w = sum({4: 10, 3: 5, 2: 2, 1: 0.5}[SEV[f["sev"]]] for f in F) + sum(p["score"] for p in paths[:5]) * 2
    return int(round(100 * (1 - math.exp(-w / 60))))


# ------------------------------------------------------------------ 3) 계속 검증
class VulnCheck:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = {"interval_h": 6, "active": False, "keep": 90, **(cfg or {})}
        self.last: dict | None = None
        self._ready = False
        self.state = {"running": False, "error": ""}

    async def ensure(self):
        if not self._ready:
            for q in SCHEMA:
                await self.e.store.x(q)
            r = await self.e.store.q1("SELECT v FROM vuln_kv WHERE k='active'")
            if r:
                self.cfg["active"] = r["v"] == "1"
            self._ready = True

    async def set_active(self, on: bool):
        await self.ensure()
        self.cfg["active"] = bool(on)
        await self.e.store.x("INSERT OR REPLACE INTO vuln_kv(k, v) VALUES('active', ?)", ("1" if on else "0",))

    async def import_kev(self, data: dict) -> int:
        """CISA KEV JSON(known_exploited_vulnerabilities.json) — vulnerabilities[{cveID, vendorProject, product, vulnerabilityName, dateAdded, knownRansomwareCampaignUse}]"""
        await self.ensure()
        rows = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise ValueError("CISA KEV 형식이 아닙니다(vulnerabilities 목록 없음)")
        n = 0
        for v in rows:
            cve = str(v.get("cveID") or "").strip()
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
                continue
            await self.e.store.x("INSERT OR REPLACE INTO vuln_kev(cve, vendor, product, name, added, ransomware) VALUES(?,?,?,?,?,?)",
                                 (cve, str(v.get("vendorProject") or "")[:80], str(v.get("product") or "")[:120], str(v.get("vulnerabilityName") or "")[:200],
                                  str(v.get("dateAdded") or "")[:20], str(v.get("knownRansomwareCampaignUse") or "")[:20]))
            n += 1
        return n

    async def _kev(self) -> dict[str, dict]:
        return {r["cve"]: dict(r) for r in await self.e.store.q("SELECT * FROM vuln_kev")}

    def _gather(self) -> dict[str, Any]:
        from .checkbot import build_world
        world = build_world(self.e)
        sw_cfg, pm_f, products = {}, [], set()
        for c in getattr(self.e, "connectors", []):
            t = getattr(c, "type", "")
            cf = getattr(c, "config", None)
            if isinstance(cf, dict) and cf.get("text") and t not in ("vcenter",):
                sw_cfg[getattr(c, "display", "") or c.name] = cf["text"]
            if t == "fortigate":
                products.add("fortios")
            elif t == "arista":
                products.add("eos")
            elif t == "nxos":
                products.add("nxos")
            elif t == "nsx":
                products.add("nsx")
        try:
            from . import portmap as PM
            pm_f = PM.build(self.e).get("findings") or []
        except Exception:  # noqa: BLE001
            pm_f = []
        cs = getattr(getattr(self.e, "certs", None), "last", None) or {}
        backups = {c.name: c.protection for c in getattr(self.e, "connectors", [])
                   if getattr(c, "type", "") == "vcenter" and isinstance(getattr(c, "protection", None), dict) and c.protection.get("kind") == "appliance_backup"}
        return {"world": world, "sw_cfg": sw_cfg, "pm": pm_f, "certs": cs.get("items") or [], "backups": backups, "products": products}

    async def _life(self) -> list[dict]:
        try:
            from .lifecycle import Lifecycle
            rep = await asyncio.wait_for(Lifecycle(self.e).report(), 60)
        except Exception:  # noqa: BLE001
            return []
        return [{"product": r.get("product"), "version": r.get("version"), "where": r.get("system") or r.get("product"), "eogs": r.get("eogs"), "eogs_passed": True}
                for r in rep.get("rows", []) if r.get("state") == "ended"]

    async def _active_check(self, F: list[dict], world: dict) -> None:
        """노출로 판단한 서비스 포트에 TCP 연결만(2초) — 열림·닫힘을 근거에 덧붙임"""
        if not self.cfg.get("active"):
            return
        tasks = []
        for f in F:
            if f.get("port") and f["layer"] == "ESXi":
                tasks.append(f)
        sem = asyncio.Semaphore(16)

        async def probe(f):
            async with sem:
                try:
                    _, w = await asyncio.wait_for(asyncio.open_connection(f["asset"], int(f["port"])), 2)
                    w.close()
                    f["verified"] = "열림(TCP 연결 확인)"
                except Exception:  # noqa: BLE001
                    f["verified"] = "연결 안 됨(방화벽·서비스 꺼짐)"
                    f["sev"] = {"high": "medium", "medium": "low"}.get(f["sev"], f["sev"])
        await asyncio.gather(*(probe(f) for f in tasks[:200]))

    async def run(self, by: str = "schedule") -> dict:
        await self.ensure()
        if self.state["running"]:
            return self.last or {}
        self.state["running"] = True
        try:
            g = await asyncio.to_thread(self._gather)
            assess = None
            try:
                assess = await self.e.assess.latest() if getattr(self.e, "assess", None) else None
            except Exception:  # noqa: BLE001
                assess = None
            kev = await self._kev()
            kprod = {}
            for p in g["products"] | {"esxi", "vcenter"}:
                vend, prod = PRODUCT_KEV.get(p, ("", ""))
                n = sum(1 for k in kev.values() if k["vendor"].lower().startswith(vend) and prod in k["product"].lower())
                if n and p not in ("esxi", "vcenter"):          # VMware 는 버전 대조로 정확히 판정
                    kprod[p] = n
            F = evaluate(g["world"], assess, g["certs"], await self._life(), g["backups"], g["sw_cfg"], g["pm"], kev, kprod)
            await self._active_check(F, g["world"])
            F.sort(key=lambda f: (-SEV[f["sev"]], f["layer"], f["asset"]))
            P = attack_paths(g["world"], F)
            prev = self.last or await self.latest()
            pids = {f["id"] for f in (prev or {}).get("findings", [])}
            ppaths = {p["id"] for p in (prev or {}).get("paths", [])}
            new = [f for f in F if prev and f["id"] not in pids]
            gone = [x for x in (prev or {}).get("findings", []) if x["id"] not in {f["id"] for f in F}]
            newp = [p for p in P if prev and p["id"] not in ppaths and p["reach"] == "확인됨"]
            summ = {"ts": time.time(), "by": by, "score": risk_score(F, P), "findings": len(F), "by_sev": {k: sum(1 for f in F if f["sev"] == k) for k in SEV},
                    "by_layer": {}, "paths": len(P), "paths_confirmed": sum(1 for p in P if p["reach"] == "확인됨"), "new": len(new), "fixed": len(gone),
                    "assess_ts": (assess or {}).get("summary", {}).get("ts") if assess else None, "assess": bool(assess), "kev": len(kev), "active": bool(self.cfg.get("active"))}
            for f in F:
                summ["by_layer"][f["layer"]] = summ["by_layer"].get(f["layer"], 0) + 1
            self.last = {"summary": summ, "findings": F, "paths": P, "new": [f["id"] for f in new], "fixed": [{"id": x["id"], "title": x["title"], "asset": x["asset"]} for x in gone]}
            await self.e.store.x("INSERT INTO vuln_runs(ts, summary, data) VALUES(?,?,?)", (summ["ts"], json.dumps(summ, ensure_ascii=False), json.dumps(self.last, ensure_ascii=False, default=str)))
            await self.e.store.x("DELETE FROM vuln_runs WHERE id NOT IN (SELECT id FROM vuln_runs ORDER BY id DESC LIMIT ?)", (int(self.cfg["keep"]),))
            await self._events([f for f in new if SEV[f["sev"]] >= 3], newp)
            self.state["error"] = ""
            return self.last
        except Exception as ex:  # noqa: BLE001
            self.state["error"] = f"{type(ex).__name__}: {ex}"[:200]
            raise
        finally:
            self.state["running"] = False

    async def _events(self, fs: list[dict], ps: list[dict]):
        ingest = getattr(self.e, "ingest", None)
        if not ingest or not (fs or ps):
            return
        from .models import LogEvent
        for f in fs[:20]:
            ev = LogEvent(source="aiops", connector="vulncheck", message=f"취약점 검증: 새 {SEV_KO[f['sev']]} 약점 — {f['asset']}: {f['title']}", severity="warning",
                          host="", entity=str(f["asset"])[:120], kind="health", attrs={"app": "vulncheck", "finding": f["id"], "layer": f["layer"]})
            r = ingest(ev)
            if asyncio.iscoroutine(r):
                await r
        for p in ps[:10]:
            ev = LogEvent(source="aiops", connector="vulncheck", message=f"취약점 검증: 새 공격 경로(확인됨) — 업무 VM → {p['kind']} {p['target']} (영향 VM {p['blast']}대)",
                          severity="warning", host="", entity=str(p["target"])[:120], kind="health", attrs={"app": "vulncheck", "path": p["id"]})
            r = ingest(ev)
            if asyncio.iscoroutine(r):
                await r

    async def latest(self) -> dict | None:
        if self.last:
            return self.last
        await self.ensure()
        r = await self.e.store.q1("SELECT data FROM vuln_runs ORDER BY id DESC LIMIT 1")
        self.last = json.loads(r["data"]) if r else None
        return self.last

    async def history(self, n: int = 60) -> list[dict]:
        await self.ensure()
        return [json.loads(r["summary"]) for r in await self.e.store.q("SELECT summary FROM vuln_runs ORDER BY id DESC LIMIT ?", (n,))][::-1]

    async def loop(self, beat=lambda: None):
        await asyncio.sleep(420)
        while True:
            beat()
            try:
                await self.ensure()
                last = (await self.latest() or {}).get("summary", {}).get("ts") or 0
                ats = 0
                try:
                    ats = ((await self.e.assess.latest()) or {}).get("summary", {}).get("ts") or 0
                except Exception:  # noqa: BLE001
                    pass
                if time.time() - last > float(self.cfg["interval_h"]) * 3600 or (ats and ats > last):
                    await self.run("schedule")
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(600)
