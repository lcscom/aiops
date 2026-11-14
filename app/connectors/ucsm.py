"""Cisco UCS Manager(패브릭 인터커넥트가 관리하는 B-Series 블레이드·UCSM 관리 C-Series) — UCSM XML API.

블레이드는 개별 CIMC/Redfish 로 접근할 수 없고 UCS Manager(패브릭 인터커넥트 VIP)를 통해서만 상태·장애를 본다.
POST https://<UCSM VIP>/nuova
  <aaaLogin inName=".." inPassword=".."/> → outCookie(폴링마다 로그아웃 — 세션 수 제한)
  configResolveClass: topSystem · networkElement(FI A/B) · mgmtEntity(FI 리더십) · equipmentChassis · computeBlade ·
                      computeRackUnit · lsServer(서비스 프로필) · faultInst(활성 장애) · adaptorHostEthIf(vNIC MAC, 10분)
  configResolveDn sys/mgmt/fw-system → UCSM 버전
읽기 전용 계정: UCSM 로컬 사용자에 'read-only' 역할만 부여하면 된다. UCSM 2.x/3.x 의 TLS 1.0/1.1 은 자동으로 구형 호환 접속.
ESXi 호스트와는 서비스 프로필 UUID·S/N(= vCenter hardware.systemInfo.uuid/serialNumber)으로 자동 연결된다.
"""
from __future__ import annotations

import time
from typing import Any
from xml.sax.saxutils import quoteattr

from ..models import LogEvent
from .base import Connector
from .cimc import FAULT_SEV, CimcXml

OK_STATES = {"ok", "operable", "on", "up", "power-off", "unassociated", "discovery"}


def _bad(v: str) -> str:
    v = str(v or "").lower()
    if not v or v in ("ok", "operable", "on", "up"):
        return "ok"
    if v in ("power-off", "power-problem", "off"):
        return "warn" if v != "power-problem" else "down"
    if any(k in v for k in ("inoperable", "fault", "fail", "removed", "unsupported", "inaccessible", "thermal-problem", "voltage-problem")):
        return "down"
    return "warn"


class UcsManagerConnector(Connector):
    type = "ucsm"
    source = "ucs"
    default_interval = 60

    def __init__(self, cfg, emit):
        super().__init__(cfg, emit)
        self.x: CimcXml | None = None
        self.ucs: dict[str, Any] = {"system": {}, "fis": [], "chassis": [], "blades": [], "racks": [], "profiles": {}, "macs": {}, "updated": 0}
        self.comp: dict[str, str] = {}
        self._inv_at = 0.0
        self._legacy = False
        self._state["auth"] = "pending"

    async def login(self) -> None:
        last = None
        for legacy in ((self._legacy,) if self.x else (False, True)):
            x = CimcXml(self.base_url, self.cfg["username"], self.cfg["password"], bool(self.verify), legacy=legacy,
                        timeout=float(self.cfg.get("timeout", 30)))
            try:
                async with x.session() as s:
                    top = await s.resolve("topSystem")
                    ver = await self._dn(s, "sys/mgmt/fw-system")
                self.x, self._legacy = x, legacy
                t = top[0] if top else {}
                self.ucs["system"] = {"name": t.get("name", ""), "address": t.get("address", ""), "mode": t.get("mode", ""),
                                      "uptime": t.get("systemUpTime", ""), "version": ver.get("version", "")}
                self._state.update(auth="UCSM XML API", compat="구형 TLS 호환" if legacy else "표준")
                return
            except Exception as e:  # noqa: BLE001
                last = e
        raise RuntimeError(f"UCS Manager XML API 로그인 실패: {type(last).__name__}: {last}")

    @staticmethod
    async def _dn(s, dn: str) -> dict[str, Any]:
        try:
            root = await s.x._post(s.c, f"<configResolveDn cookie={quoteattr(s.x.cookie)} dn={quoteattr(dn)} inHierarchical=\"false\"/>")
            out = root.find("outConfig")
            el = list(out)[0] if out is not None and len(out) else None
            return dict(el.attrib) if el is not None else {}
        except Exception:  # noqa: BLE001
            return {}

    async def poll(self) -> list[LogEvent]:
        out: list[LogEvent] = []
        inv = time.time() - self._inv_at >= float(self.cfg.get("inventory_interval", 600)) or self.first_poll
        async with self.x.session() as s:
            faults = await s.resolve("faultInst")
            fis = await s.resolve("networkElement")
            mgmt = await s.resolve("mgmtEntity")
            chassis = await s.resolve("equipmentChassis")
            blades = await s.resolve("computeBlade")
            racks = await s.resolve("computeRackUnit")
            profiles = await s.resolve("lsServer") if inv else None
            vnics = await s.resolve("adaptorHostEthIf") if inv else None
        lead = {m.get("id"): m.get("leadership", "") for m in mgmt}
        prof = self.ucs["profiles"]
        if profiles is not None:
            prof = {p.get("dn", ""): {"name": p.get("name", ""), "uuid": str(p.get("uuid", "")).lower(), "assoc": p.get("assocState", ""),
                                      "oper": p.get("operState", ""), "pn": p.get("pnDn", "")} for p in profiles}
            self._inv_at = time.time()
        macs = self.ucs["macs"]
        if vnics is not None:
            macs = {}
            for v in vnics:
                dn = v.get("dn", "")
                srv = dn.split("/adaptor-")[0]
                if v.get("mac"):
                    macs[v["mac"].lower()] = {"server": srv, "vnic": v.get("name", "") or dn.rsplit("/", 1)[-1], "fabric": v.get("switchId", "")}

        def server(b: dict, kind: str) -> dict[str, Any]:
            sp = prof.get(b.get("assignedToDn", ""), {})
            if sp.get("uuid") in ("derived", "", None):          # 서비스 프로필이 하드웨어 UUID 를 그대로 쓰는 경우
                sp = {**sp, "uuid": ""}
            return {"dn": b.get("dn", ""), "kind": kind, "chassis": b.get("chassisId", ""), "slot": b.get("slotId", ""), "id": b.get("id", ""),
                    "model": b.get("model", ""), "serial": b.get("serial", ""), "uuid": (sp.get("uuid") or str(b.get("uuid", ""))).lower(),
                    "hw_uuid": str(b.get("uuid", "")).lower(), "oper": b.get("operState", ""), "power": b.get("operPower", ""),
                    "assoc": b.get("association", ""), "profile": sp.get("name") or b.get("assignedToDn", "").rsplit("/ls-", 1)[-1],
                    "mem_mb": b.get("totalMemory", ""), "cpus": b.get("numOfCpus", ""), "cores": b.get("numOfCores", ""), "label": b.get("usrLbl", "") or b.get("name", ""),
                    "state": _bad(b.get("operState", ""))}
        self.ucs.update(
            fis=[{"id": f.get("id", ""), "dn": f.get("dn", ""), "model": f.get("model", ""), "serial": f.get("serial", ""), "ip": f.get("oobIfIp", ""),
                  "oper": f.get("operability", ""), "thermal": f.get("thermal", ""), "leadership": lead.get(f.get("id"), ""),
                  "state": _bad(f.get("operability", ""))} for f in fis],
            chassis=[{"id": c.get("id", ""), "dn": c.get("dn", ""), "model": c.get("model", ""), "serial": c.get("serial", ""), "oper": c.get("operState", ""),
                      "power": c.get("power", ""), "thermal": c.get("thermal", ""), "state": _bad(c.get("operState", "") or c.get("operability", ""))} for c in chassis],
            blades=[server(b, "blade") for b in blades], racks=[server(r, "rack") for r in racks], profiles=prof, macs=macs, updated=time.time())
        # 장애(faultInst) — 새로 생기거나 심각도가 바뀐 것만, 해소되면 정보 이벤트
        cur: dict[str, tuple[str, dict]] = {}
        for f in faults:
            sev = str(f.get("severity", "")).lower()
            if sev == "cleared" or (self.cfg.get("skip_acked", False) and f.get("ack") == "yes"):
                continue
            cur[f.get("dn", f.get("id", ""))] = (sev, f)
        first = self.first_poll
        for dn, (sev, f) in cur.items():
            k = f"fault:{dn}"
            if self.comp.get(k) == sev:
                continue
            self.comp[k] = sev
            obj = dn.split("/fault-")[0]
            out.append(self.ev(f"[UCS {f.get('code', '')}] {obj}: {f.get('descr', '')}".strip(), severity=FAULT_SEV.get(sev, "warning"),
                               kind="alarm", entity=obj, host=self._host_of(obj), native_id=f.get("id", dn),
                               attrs={"ucs": self.name, "code": f.get("code"), "cause": f.get("cause"), "severity": sev, "dn": dn,
                                      "type": f.get("type"), "first": first, "ack": f.get("ack")}))
        for k in [k for k in self.comp if k.startswith("fault:") and k[6:] not in cur]:
            self.comp.pop(k, None)
            obj = k[6:].split("/fault-")[0]
            out.append(self.ev(f"[UCS] 장애 해소: {obj}", severity="info", kind="event", entity=obj, host=self._host_of(obj)))
        # 구성요소 상태 전환(FI·섀시·블레이드·랙)
        for kind, items, key in (("FI", self.ucs["fis"], "oper"), ("섀시", self.ucs["chassis"], "oper"), ("블레이드", self.ucs["blades"], "oper"),
                                 ("랙 서버", self.ucs["racks"], "oper")):
            for it in items:
                k = f"st:{it['dn']}"
                v = it.get(key, "")
                prev = self.comp.get(k)
                self.comp[k] = v
                if prev is None or prev == v:
                    continue
                st = _bad(v)
                out.append(self.ev(f"UCS {kind} {it['dn']}{' (' + it.get('profile', '') + ')' if it.get('profile') else ''} 상태 {prev} → {v}",
                                   severity={"down": "critical", "warn": "warning"}.get(st, "info"), kind="health", entity=it["dn"],
                                   host=self._host_of(it["dn"])))
        return out

    def _host_of(self, dn: str) -> str:
        """장애 DN → 서비스 프로필 이름(ESXi 호스트 이름과 같은 경우가 많음)"""
        for b in self.ucs["blades"] + self.ucs["racks"]:
            if dn.startswith(b["dn"]) and b.get("profile"):
                return b["profile"]
        return self.ucs["system"].get("name") or self.host

    def servers(self) -> list[dict[str, Any]]:
        return self.ucs["blades"] + self.ucs["racks"]

    def entities(self) -> list[dict[str, Any]]:
        out = []
        for f in self.ucs["fis"]:
            out.append({"name": f"FI-{f['id']}", "kind": "fabric-interconnect", "state": f["state"],
                        "detail": f"{f['model']} {f['ip']} {f['leadership']} {f['oper']}".strip()})
        for c in self.ucs["chassis"]:
            out.append({"name": f"chassis-{c['id']}", "kind": "chassis", "state": c["state"], "detail": f"{c['model']} {c['oper']} 전원 {c['power']}"})
        for b in self.servers():
            out.append({"name": b["profile"] or b["dn"], "kind": "blade" if b["kind"] == "blade" else "server", "state": b["state"],
                        "detail": f"{b['dn']} {b['model']} {b['oper']} 전원 {b['power']}"})
        return out[:300]

    async def checks(self) -> dict[str, Any]:
        await self.login()
        async with self.x.session() as s:
            n = {c: len(await s.resolve(c)) for c in ("networkElement", "equipmentChassis", "computeBlade", "computeRackUnit", "faultInst")}
        sy = self.ucs["system"]
        return {"aaaLogin(/nuova)": f"ok {self._state.get('compat', '')} · {sy.get('name', '')} UCSM {sy.get('version', '')}".strip(),
                "패브릭 인터커넥트": f"ok {n['networkElement']}대", "섀시·블레이드": f"ok 섀시 {n['equipmentChassis']} · 블레이드 {n['computeBlade']}",
                "랙 서버(UCSM 관리)": f"ok {n['computeRackUnit']}대", "활성 장애(faultInst)": f"ok {n['faultInst']}건"}
