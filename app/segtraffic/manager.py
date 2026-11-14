"""2.21.0 NSX 세그먼트 트래픽 — NSX 세그먼트에 붙은 모든 VM(vNIC)의 수신·송신 대역폭·패킷·드롭

데이터(모두 읽기 전용)
 · vCenter: NSX 백킹 분산 포트그룹(config.backingType=nsx, segmentId·logicalSwitchUuid)·opaque network 에 연결된 vNIC 목록,
   vNIC 별 실시간(20초) 성능 카운터 net.received/transmitted.average(KBps)·packetsRx/Tx·droppedRx/Tx(summation) — 최근 5분·15분·1시간
 · NSX Manager(있으면): 세그먼트(게이트웨이·Tier-1·종류·관리 상태), 세그먼트를 고르면 포트별 누적 카운터·DFW/보안 차단 패킷,
   VIF(lport_attachment_id ↔ VM·장치 키·MAC)
 · 이력: 5분마다 세그먼트별 합계를 저장(기본 14일) — 24시간·7일 추세
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import time

SCHEMA = """CREATE TABLE IF NOT EXISTS segtraffic(ts REAL, vcenter TEXT, segment TEXT, name TEXT, vms INTEGER, vnics INTEGER,
  rx_bps REAL, tx_bps REAL, rx_pps REAL, tx_pps REAL, drops REAL, kind TEXT);
CREATE INDEX IF NOT EXISTS segtraffic_ts ON segtraffic(segment, ts);"""

WINDOWS = {300: 15, 900: 45, 3600: 180}            # 화면 기간(초) → 20초 표본 수


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


def _sum_series(rows: list[list[float]]) -> list[float]:
    """끝(최근)에 맞춰 시계열 합산 — vNIC 마다 표본 수가 다를 수 있음"""
    rows = [r for r in rows if r]
    if not rows:
        return []
    n = max(len(r) for r in rows)
    out = [0.0] * n
    for r in rows:
        off = n - len(r)
        for i, v in enumerate(r):
            out[off + i] += v or 0.0
    return out


def _down(xs: list[float], n: int = 60) -> list[float]:
    if len(xs) <= n:
        return [round(x, 1) for x in xs]
    step = len(xs) / n
    return [round(_avg(xs[int(i * step):int((i + 1) * step)]), 1) for i in range(n)]


class SegTraffic:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self._ready = False
        self._inv: dict[str, tuple[float, dict]] = {}
        self._tr: dict[tuple, tuple[float, dict]] = {}
        self._lock = asyncio.Lock()

    def db(self):
        if not self._ready:
            self.e.store.schema(SCHEMA)
            try:                                                  # 개발판에서 만든 표(종류 열 없음) 보정
                self.e.store.schema("ALTER TABLE segtraffic ADD COLUMN kind TEXT")
            except Exception:  # noqa: BLE001
                pass
            self.e.store.schema("UPDATE segtraffic SET kind = CASE WHEN segment LIKE 'std:%' THEN 'std' "      # 종류가 빈 예전 행은 키로 채움
                                "WHEN segment LIKE '/infra/%' OR segment LIKE '/orgs/%' OR length(segment) = 36 AND segment LIKE '%-%-%-%-%' THEN 'nsx' "
                                "ELSE 'dvpg' END WHERE kind IS NULL OR kind = ''")
            self._ready = True
        return self.e.store

    # ------------------------------------------------------------------ 원천
    def vcenters(self) -> list:
        return [c for c in self.e.connectors if c.type == "vcenter" and getattr(c, "enabled", True) and hasattr(c, "segment_vnics")]

    def nsx(self) -> list:
        return [c for c in self.e.connectors if c.type == "nsx" and getattr(c, "enabled", True)]

    def nsx_segments(self) -> dict[str, dict]:
        """NSX 인벤토리 세그먼트(id·이름 → 게이트웨이·Tier-1·종류·관리 상태)"""
        out = {}
        for c in self.nsx():
            for s in (getattr(c, "inv", None) or {}).get("segments", []) or []:
                info = {**s, "nsx": c.name}
                if s.get("id"):
                    out[f"id:{s['id']}"] = info
                if s.get("name"):
                    out[f"name:{s['name']}"] = info
        return out

    def avi_index(self) -> tuple[list[dict], dict[str, list[dict]]]:
        """NSX ALB(Avi) 가상 서비스와 백엔드 풀 멤버 IP → [VS] — VM vNIC IP 와 맞춰 'Avi 뒤에 있는 VM' 을 찾음"""
        vips = []
        try:
            vips = self.e.avi_vips() if hasattr(self.e, "avi_vips") else []
        except Exception:  # noqa: BLE001
            vips = []
        pools = {}
        for c in self.e.connectors:
            if c.type == "avi" and getattr(c, "enabled", True):
                for pl in getattr(c, "pools", None) or []:
                    pools[pl.get("name")] = pl
        by_ip: dict[str, list[dict]] = {}
        out = []
        for v in vips:
            mem = list(v.get("members") or [])
            if not mem:                                         # 풀 멤버가 VS 에 안 붙어 오면 풀 인벤토리에서
                for pn in [x.strip() for x in str(v.get("pool") or "").split(",") if x.strip()]:
                    mem += [dict(m, pool=pn) for m in (pools.get(pn) or {}).get("members") or []]
            v = {**v, "members": mem}
            out.append(v)
            for m in mem:
                if m.get("ip"):
                    by_ip.setdefault(m["ip"], []).append({"vs": v.get("name", ""), "uuid": v.get("uuid", ""), "pool": m.get("pool") or v.get("pool", ""),
                                                          "port": m.get("port"), "state": v.get("state", ""), "health": v.get("health")})
        return out, by_ip

    async def _call(self, fn, *a, timeout: float = 120):
        r = fn(*a)
        if asyncio.iscoroutine(r):
            return await asyncio.wait_for(r, timeout)
        return r

    async def inventory(self, scope: str = "nsx", fresh: bool = False) -> list[dict]:
        out = []
        for c in self.vcenters():
            k = f"{c.name}|{scope}"
            hit = self._inv.get(k)
            ttl = 30 if hit and hit[1].get("error") else float(self.cfg.get("inventory_ttl", 300))      # 실패는 짧게 캐시
            if hit and not fresh and time.time() - hit[0] < ttl:
                out.append(hit[1]); continue
            try:
                inv = await asyncio.wait_for(asyncio.to_thread(c.segment_vnics, scope), 180)
            except Exception as e:  # noqa: BLE001
                inv = {"vcenter": c.name, "segments": {}, "vnics": [], "error": f"{type(e).__name__}: {str(e)[:150]}"}
            inv["vcenter"] = c.name
            self._inv[k] = (time.time(), inv)
            out.append(inv)
        return out

    async def traffic(self, inv: dict, window: int, fresh: bool = False) -> dict:
        c = next((x for x in self.vcenters() if x.name == inv["vcenter"]), None)
        if not c or not inv.get("vnics"):
            return {"series": {}, "error": ""}
        ids = tuple(sorted(f"{v['moid']}:{v['device']}" for v in inv["vnics"]))
        k = (c.name, window, hash(ids))                           # 같은 수의 다른 vNIC 묶음(VDS·표준 vSwitch)이 캐시를 공유하지 않게
        hit = self._tr.get(k)
        if hit and not fresh and time.time() - hit[0] < 50:
            return hit[1]
        try:
            tr = await asyncio.wait_for(asyncio.to_thread(c.vnic_traffic, inv["vnics"], WINDOWS.get(window, 15)), 240)
        except Exception as e:  # noqa: BLE001
            tr = {"series": {}, "error": f"{type(e).__name__}: {str(e)[:150]}"}
        self._tr[k] = (time.time(), tr)
        return tr

    # ------------------------------------------------------------------ 합성
    @staticmethod
    def _vnic_row(v: dict, s: dict | None, vc: str) -> dict:
        s = s or {}
        rx, tx = s.get("rx_bps") or [], s.get("tx_bps") or []
        tot = _sum_series([rx, tx])
        return {"vcenter": vc, "vm": v["vm"], "moid": v["moid"], "device": v["device"], "label": v.get("label", ""), "mac": v.get("mac", ""),
                "ips": v.get("ips", []), "host": v.get("host", ""), "cluster": v.get("cluster", ""), "power": v.get("power", ""),
                "connected": v.get("connected", True), "segment": v["segment"], "type": v.get("type", ""),
                "rx_bps": _avg(rx), "tx_bps": _avg(tx), "rx_last": rx[-1] if rx else None, "tx_last": tx[-1] if tx else None,
                "peak_bps": max(tot) if tot else 0.0, "rx_pps": _avg(s.get("rx_pps") or []), "tx_pps": _avg(s.get("tx_pps") or []),
                "drop_rx": sum(s.get("drop_rx") or []), "drop_tx": sum(s.get("drop_tx") or []), "samples": len(rx),
                "has_data": bool(rx or tx)}

    async def overview(self, window: int = 300, scope: str = "nsx", fresh: bool = False) -> dict:
        window = window if window in WINDOWS else 300
        avi_mode = scope == "avi"
        invs = await self.inventory("all" if avi_mode else scope, fresh)
        vips, by_ip = self.avi_index()
        nsx = self.nsx_segments()
        segs: dict[str, dict] = {}
        vnics: list[dict] = []
        series: dict[str, dict] = {}
        errors = []
        for inv in invs:
            if inv.get("error"):
                errors.append(f"{inv['vcenter']}: {inv['error']}")
            tr = await self.traffic(inv, window, fresh)
            if tr.get("error"):
                errors.append(f"{inv['vcenter']}: {tr['error']}")
            for key, sg in (inv.get("segments") or {}).items():
                sid = (sg.get("segment_path") or "").rsplit("/", 1)[-1]
                meta = nsx.get(f"id:{sid}") or nsx.get(f"name:{sg.get('name')}") or {}
                segs.setdefault(key, {"key": key, "name": meta.get("name") or sg.get("name", ""), "pg": sg.get("name", ""), "kind": sg.get("kind", ""),
                                      "segment_id": sid or meta.get("id", ""), "path": sg.get("segment_path", ""), "ls_uuid": sg.get("ls_uuid", ""),
                                      "tz": meta.get("tz") or sg.get("tz", ""), "dvs": sg.get("dvs", ""), "gateway": meta.get("gateway", ""),
                                      "connected_to": meta.get("connected_to", ""), "seg_type": meta.get("type", ""), "admin": meta.get("admin", ""),
                                      "nsx": meta.get("nsx", ""), "vcenters": [], "vms": set(), "vnics": 0, "on": 0,
                                      "_rx": [], "_tx": [], "_rxp": [], "_txp": [], "drops": 0.0})
                if inv["vcenter"] not in segs[key]["vcenters"]:
                    segs[key]["vcenters"].append(inv["vcenter"])
            for v in inv.get("vnics") or []:
                s = (tr.get("series") or {}).get(f"{v['moid']}:{v['device']}")
                row = self._vnic_row(v, s, inv["vcenter"])
                hits = {}
                for ip in row["ips"] or []:
                    for h in by_ip.get(ip, []):
                        hits[h["uuid"]] = {**h, "ip": ip}
                row["avi"] = list(hits.values())
                row["network"] = (inv.get("segments") or {}).get(v["segment"], {}).get("name", "")
                vnics.append(row)
                series[f"{inv['vcenter']}|{v['moid']}:{v['device']}"] = s or {}
                g = segs.get(v["segment"])
                if not g:
                    continue
                g["vms"].add(v["vm"]); g["vnics"] += 1
                g["on"] += v.get("power") == "poweredOn"
                if s:
                    g["_rx"].append(s.get("rx_bps") or []); g["_tx"].append(s.get("tx_bps") or [])
                    g["_rxp"].append(s.get("rx_pps") or []); g["_txp"].append(s.get("tx_pps") or [])
                g["drops"] += row["drop_rx"] + row["drop_tx"]
        if avi_mode:                                            # Avi 가상 서비스별로 다시 묶음(백엔드 풀 멤버 IP = VM vNIC IP)
            segs, rows = {}, []
            for vs in vips:
                k = f"avi:{vs.get('uuid')}"
                a, last = vs.get("avg") or {}, vs.get("last") or {}
                segs[k] = {"key": k, "name": vs.get("name", ""), "pg": "", "kind": "avi", "segment_id": "", "path": "", "ls_uuid": "", "tz": "", "dvs": "",
                           "gateway": ", ".join(f"{ip}:{','.join(map(str, vs.get('ports') or []))}" if vs.get("ports") else ip for ip in vs.get("vips") or []),
                           "connected_to": vs.get("pool", ""), "seg_type": vs.get("state", ""), "admin": "", "nsx": vs.get("connector", ""), "vcenters": [],
                           "vms": set(), "vnics": 0, "on": 0, "_rx": [], "_tx": [], "_rxp": [], "_txp": [], "drops": 0.0,
                           "avi": {"health": vs.get("health"), "state": vs.get("state"), "controller": vs.get("controller", ""), "se_group": vs.get("se_group", ""),
                                   "bw": a.get("bw"), "bw_last": last.get("bw"), "rx_bps": (a.get("rx") or 0) * 8, "tx_bps": (a.get("tx") or 0) * 8,
                                   "rps": a.get("rps"), "cps": a.get("cps"), "open": a.get("open"), "rtt": a.get("rtt"), "step": vs.get("step"),
                                   "bw_series": list((vs.get("series") or {}).get("bw") or []), "members": len(vs.get("members") or []),
                                   "external": []}}
            matched_ips = set()
            for row in vnics:
                for h in row["avi"]:
                    g = segs.get(f"avi:{h['uuid']}")
                    if not g:
                        continue
                    matched_ips.add(h["ip"])
                    r2 = {**row, "segment": g["key"], "pool": h.get("pool", ""), "member_port": h.get("port")}
                    rows.append(r2)
                    s = series.get(f"{row['vcenter']}|{row['moid']}:{row['device']}") or {}
                    g["vms"].add(row["vm"]); g["vnics"] += 1; g["on"] += row["power"] == "poweredOn"
                    if g["key"] not in g["vcenters"] and row["vcenter"] not in g["vcenters"]:
                        g["vcenters"].append(row["vcenter"])
                    if s:
                        g["_rx"].append(s.get("rx_bps") or []); g["_tx"].append(s.get("tx_bps") or [])
                        g["_rxp"].append(s.get("rx_pps") or []); g["_txp"].append(s.get("tx_pps") or [])
                    g["drops"] += row["drop_rx"] + row["drop_tx"]
            for vs in vips:                                     # VM 이 아닌 백엔드(물리 서버·파드·다른 vCenter)
                g = segs[f"avi:{vs.get('uuid')}"]
                g["avi"]["external"] = [{"ip": m.get("ip"), "port": m.get("port"), "pool": m.get("pool", "")} for m in vs.get("members") or []
                                        if m.get("ip") and m["ip"] not in matched_ips][:100]
            vnics = rows
        out_segs = []
        for g in segs.values():
            rx, tx = _sum_series(g.pop("_rx")), _sum_series(g.pop("_tx"))
            rxp, txp = _sum_series(g.pop("_rxp")), _sum_series(g.pop("_txp"))
            tot = _sum_series([rx, tx])
            g.update(vms=len(g["vms"]), has_data=bool(rx or tx), rx_bps=_avg(rx), tx_bps=_avg(tx), peak_bps=max(tot) if tot else 0.0, rx_pps=_avg(rxp), tx_pps=_avg(txp),
                     spark=_down(tot, 30))
            out_segs.append(g)
        out_segs.sort(key=lambda x: -(x["rx_bps"] + x["tx_bps"]))
        vnics.sort(key=lambda x: -(x["rx_bps"] + x["tx_bps"]))
        tot = {"segments": len(out_segs), "vms": len({(v["vcenter"], v["vm"]) for v in vnics}), "vnics": len(vnics),
               "rx_bps": sum(x["rx_bps"] for x in out_segs), "tx_bps": sum(x["tx_bps"] for x in out_segs),
               "drops": sum(x["drops"] for x in out_segs), "no_data": sum(1 for v in vnics if v["power"] == "poweredOn" and not v["has_data"])}
        if avi_mode:
            tot["avi_bw"] = sum(x["avi"].get("bw") or 0 for x in out_segs)
        return {"window": window, "scope": scope, "updated": time.time(), "segments": out_segs, "vnics": vnics, "totals": tot, "errors": errors,
                "sources": {"vcenter": [c.name for c in self.vcenters()], "nsx": [c.name for c in self.nsx()],
                            "avi": sorted({v.get("connector", "") for v in vips if v.get("connector")})}, "_series": series}

    async def segment(self, key: str, window: int = 300, scope: str = "nsx", ports: bool = True) -> dict:
        ov = await self.overview(window, scope)
        seg = next((s for s in ov["segments"] if s["key"] == key), None)
        if not seg:
            raise KeyError(key)
        rows = [v for v in ov["vnics"] if v["segment"] == key]
        ser = ov["_series"]
        for v in rows:
            s = ser.get(f"{v['vcenter']}|{v['moid']}:{v['device']}") or {}
            v["spark"] = _down(_sum_series([s.get("rx_bps") or [], s.get("tx_bps") or []]), 30)
        allser = [ser.get(f"{v['vcenter']}|{v['moid']}:{v['device']}") or {} for v in rows]
        ts = max((s.get("ts") or [] for s in allser), key=len, default=[])
        crx, ctx = _sum_series([s.get("rx_bps") or [] for s in allser]), _sum_series([s.get("tx_bps") or [] for s in allser])
        n = max(len(crx), len(ctx))
        chart = {"ts": list(ts[-n:]) if n and len(ts) >= n else [], "rx_bps": crx, "tx_bps": ctx,
                 "drops": _sum_series([[(a or 0) + (b or 0) for a, b in zip(s.get("drop_rx") or [], s.get("drop_tx") or [])] for s in allser])}
        nsx_ports: dict = {}
        if ports and seg.get("segment_id"):
            c = next((x for x in self.nsx() if x.name == seg.get("nsx")), None) or (self.nsx()[0] if self.nsx() else None)
            if c and hasattr(c, "segment_ports"):
                try:
                    nsx_ports = await self._call(c.segment_ports, seg["segment_id"], timeout=90)
                except Exception as e:  # noqa: BLE001
                    nsx_ports = {"error": f"{type(e).__name__}: {str(e)[:150]}", "ports": []}
                by = {}
                for p in nsx_ports.get("ports") or []:
                    if p.get("mac"):
                        by[p["mac"]] = p
                    if p.get("vm") and p.get("device"):
                        by[f"{p['vm']}#{p['device']}"] = p
                for v in rows:
                    p = by.get(v.get("mac", "")) or by.get(f"{v['vm']}#{v['device']}")
                    if p:
                        v["nsx"] = {k: p.get(k) for k in ("port", "name", "admin", "rx_drop", "tx_drop", "dfw_drop", "sec_drop", "rx_bps", "tx_bps", "interval")}
        return {"segment": seg, "vnics": rows, "chart": chart, "window": ov["window"], "updated": ov["updated"],
                "nsx": {k: nsx_ports.get(k) for k in ("error", "stats", "truncated")} if nsx_ports else {}, "errors": ov["errors"]}

    # ------------------------------------------------------------------ VM 한 대
    async def vm(self, name: str, window: int = 300, ports: bool = True, vcenter: str = "") -> dict:
        """VM 한 대의 모든 vNIC(네트워크 종류 무관) 트래픽 — vNIC 별 시계열·합계, 붙은 네트워크 정보, Avi 가상 서비스, NSX 포트 DFW 차단"""
        ov = await self.overview(window, "all")
        rows = [dict(v) for v in ov["vnics"] if v["vm"] == name and (not vcenter or v["vcenter"] == vcenter)]
        if not rows:
            raise KeyError(name)
        vc0 = rows[0]["vcenter"]                                  # 같은 이름이 여러 vCenter 에 있으면 하나만(목록은 vCenter 별로 따로)
        rows = sorted([v for v in rows if v["vcenter"] == vc0], key=lambda v: int(v.get("device") or 0))
        ser, segs = ov["_series"], {s["key"]: s for s in ov["segments"]}
        allser = []
        for v in rows:
            s = ser.get(f"{v['vcenter']}|{v['moid']}:{v['device']}") or {}
            allser.append(s)
            g = segs.get(v["segment"], {})
            v["net"] = {k: g.get(k) for k in ("key", "name", "kind", "gateway", "connected_to", "seg_type", "tz", "segment_id", "nsx")}
            v["chart"] = {"ts": list(s.get("ts") or [])[-len(s.get("rx_bps") or []):] if s.get("rx_bps") else [], "rx_bps": s.get("rx_bps") or [],
                          "tx_bps": s.get("tx_bps") or [], "drops": [(a or 0) + (b or 0) for a, b in zip(s.get("drop_rx") or [], s.get("drop_tx") or [])]}
            v["spark"] = _down(_sum_series([v["chart"]["rx_bps"], v["chart"]["tx_bps"]]), 30)
        if ports:                                                 # NSX 세그먼트 vNIC 는 포트 통계(DFW 차단)를 붙임
            done: dict[str, dict] = {}
            for v in rows:
                sid, nsxn = v["net"].get("segment_id"), v["net"].get("nsx")
                if v["net"].get("kind") != "nsx" or not sid:
                    continue
                if sid not in done:
                    c = next((x for x in self.nsx() if x.name == nsxn), None) or (self.nsx()[0] if self.nsx() else None)
                    try:
                        done[sid] = await self._call(c.segment_ports, sid, timeout=60) if c and hasattr(c, "segment_ports") else {}
                    except Exception as e:  # noqa: BLE001
                        done[sid] = {"error": f"{type(e).__name__}", "ports": []}
                p = next((x for x in (done[sid].get("ports") or []) if x.get("mac") and x["mac"] == v.get("mac")), None)
                if p:
                    v["nsx"] = {k: p.get(k) for k in ("port", "name", "admin", "rx_drop", "tx_drop", "dfw_drop", "sec_drop", "rx_bps", "tx_bps", "interval")}
        crx = _sum_series([s.get("rx_bps") or [] for s in allser])
        ctx = _sum_series([s.get("tx_bps") or [] for s in allser])
        ts = max((s.get("ts") or [] for s in allser), key=len, default=[])
        n = max(len(crx), len(ctx))
        tot = _sum_series([crx, ctx])
        first = rows[0]
        avi = {}
        for v in rows:
            for a in v.get("avi") or []:
                avi[a["uuid"]] = a
        return {"vm": name, "vcenter": first["vcenter"], "moid": first["moid"], "host": first["host"], "cluster": first["cluster"], "power": first["power"],
                "ips": sorted({ip for v in rows for ip in v.get("ips") or []}), "vnics": rows, "avi": list(avi.values()), "window": ov["window"],
                "totals": {"rx_bps": sum(v["rx_bps"] for v in rows), "tx_bps": sum(v["tx_bps"] for v in rows), "peak_bps": max(tot) if tot else 0.0,
                           "rx_pps": sum(v["rx_pps"] for v in rows), "tx_pps": sum(v["tx_pps"] for v in rows),
                           "drops": sum(v["drop_rx"] + v["drop_tx"] for v in rows), "dfw": sum((v.get("nsx") or {}).get("dfw_drop") or 0 for v in rows),
                           "has_data": any(v["has_data"] for v in rows)},
                "chart": {"ts": list(ts[-n:]) if n and len(ts) >= n else [], "rx_bps": crx, "tx_bps": ctx,
                          "drops": _sum_series([[(a or 0) + (b or 0) for a, b in zip(s.get("drop_rx") or [], s.get("drop_tx") or [])] for s in allser])},
                "updated": ov["updated"], "errors": ov["errors"]}

    def vm_list(self, ov: dict) -> list[dict]:
        by: dict[tuple, dict] = {}
        for v in ov["vnics"]:
            k = (v["vcenter"], v["vm"])
            r = by.setdefault(k, {"vm": v["vm"], "vcenter": v["vcenter"], "host": v["host"], "power": v["power"], "vnics": 0, "rx_bps": 0.0, "tx_bps": 0.0,
                                  "drops": 0.0, "kinds": set(), "avi": set(), "has_data": False, "ips": set()})
            r["vnics"] += 1; r["rx_bps"] += v["rx_bps"]; r["tx_bps"] += v["tx_bps"]; r["drops"] += v["drop_rx"] + v["drop_tx"]
            r["has_data"] |= v["has_data"]; r["ips"] |= set(v.get("ips") or [])
            r["avi"] |= {a["vs"] for a in v.get("avi") or []}
        kinds = {s["key"]: s["kind"] for s in ov["segments"]}
        for v in ov["vnics"]:
            by[(v["vcenter"], v["vm"])]["kinds"].add(kinds.get(v["segment"], ""))
        out = [{**r, "kinds": sorted(x for x in r["kinds"] if x), "avi": sorted(r["avi"]), "ips": sorted(r["ips"])[:4]} for r in by.values()]
        return sorted(out, key=lambda r: -(r["rx_bps"] + r["tx_bps"]))

    async def vm_history(self, name: str, hours: float = 24, vcenter: str = "") -> dict:
        hours = max(1.0, min(float(hours), 24 * 31))
        ov = await self.overview(300, "all")
        v = next((x for x in ov["vnics"] if x["vm"] == name and (not vcenter or x["vcenter"] == vcenter)), None)
        if not v:
            raise KeyError(name)
        c = next((x for x in self.vcenters() if x.name == v["vcenter"]), None)
        if not c or not hasattr(c, "vm_net_history"):
            return {"vm": name, "hours": hours, "ts": [], "series": {}, "interval": 0, "error": "이 vCenter 는 과거 통계 조회를 지원하지 않음"}
        try:
            r = await asyncio.wait_for(asyncio.to_thread(c.vm_net_history, v["moid"], hours), 120)
        except Exception as e:  # noqa: BLE001
            r = {"ts": [], "series": {}, "interval": 0, "error": f"{type(e).__name__}: {str(e)[:120]}"}
        return {"vm": name, "hours": hours, **r}

    # ------------------------------------------------------------------ 이력(5분 합계)
    async def sample(self) -> int:
        ov = await self.overview(300, "all", fresh=False)          # NSX·VDS·표준 vSwitch 모두(키는 범위와 무관하게 같음)
        st = self.db()
        now = time.time()
        rows = [(now, ",".join(s["vcenters"]), s["key"], s["name"], s["vms"], s["vnics"], s["rx_bps"], s["tx_bps"], s["rx_pps"], s["tx_pps"], s["drops"], s["kind"])
                for s in ov["segments"]]
        if rows:
            await st.xm("INSERT INTO segtraffic(ts, vcenter, segment, name, vms, vnics, rx_bps, tx_bps, rx_pps, tx_pps, drops, kind) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        await st.x("DELETE FROM segtraffic WHERE ts < ?", (now - float(self.cfg.get("retention_days", 14)) * 86400,))
        return len(rows)

    async def history(self, key: str = "", hours: float = 24, scope: str = "all") -> dict:
        hours = max(1.0, min(float(hours), 24 * 31))
        st = self.db()
        since = time.time() - hours * 3600
        kinds = {"nsx": ("nsx",), "vds": ("dvpg",), "std": ("std",)}.get(scope)
        if scope == "avi" and not key:
            return {"segment": key, "hours": hours, "scope": scope, "points": [], "note": "Avi 범위는 추세를 저장하지 않음"}
        if key:
            rows = await st.q("SELECT ts, rx_bps, tx_bps, drops, vms FROM segtraffic WHERE segment=? AND ts>=? ORDER BY ts", (key, since))
        else:
            # 5분 구간 안에서 세그먼트별로 먼저 평균(같은 구간 표본이 둘이어도 두 배가 되지 않게) → 구간별 합계
            rows = await st.q("SELECT b*300 AS ts, SUM(rx) AS rx_bps, SUM(tx) AS tx_bps, SUM(dr) AS drops, SUM(vm) AS vms FROM "
                              "(SELECT CAST(ts/300 AS INTEGER) AS b, segment, AVG(rx_bps) AS rx, AVG(tx_bps) AS tx, AVG(drops) AS dr, MAX(vms) AS vm "
                              f" FROM segtraffic WHERE ts>=? {'AND kind IN (' + ','.join('?' * len(kinds)) + ')' if kinds else ''} GROUP BY b, segment) GROUP BY b ORDER BY b",
                              (since, *(kinds or ())))
        return {"segment": key, "hours": hours, "scope": scope, "points": rows}

    async def loop(self) -> None:
        await asyncio.sleep(float(self.cfg.get("start_delay", 90)))
        while True:
            iv = max(60.0, float(self.cfg.get("interval", 300)))
            if self.cfg.get("enabled", True) and self.vcenters():
                try:
                    await self.sample()
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(iv)

    # ------------------------------------------------------------------ 내보내기 · AI
    @staticmethod
    def csv(ov: dict, key: str = "") -> bytes:
        b = io.StringIO()
        w = csv.writer(b)
        w.writerow(["segment", "vm", "vnic", "mac", "ips", "host", "cluster", "power", "rx_mbps_avg", "tx_mbps_avg", "peak_mbps", "rx_pps", "tx_pps",
                    "drop_rx", "drop_tx", "nsx_dfw_drop", "vcenter"])
        names = {s["key"]: s["name"] for s in ov.get("segments", [])}
        for v in ov.get("vnics", []):
            if key and v["segment"] != key:
                continue
            d = v.get("has_data", True)
            m = (lambda x, k=1e6, r=3: round(x / k, r)) if d else (lambda x, k=1, r=0: "")        # 성능 데이터가 없으면 0 이 아니라 빈 칸
            w.writerow([names.get(v["segment"], v["segment"]), v["vm"], v.get("label", ""), v.get("mac", ""), " ".join(v.get("ips") or []), v.get("host", ""),
                        v.get("cluster", ""), v.get("power", ""), m(v["rx_bps"]), m(v["tx_bps"]), m(v["peak_bps"]),
                        m(v["rx_pps"], 1, 1), m(v["tx_pps"], 1, 1), m(v["drop_rx"], 1, 0), m(v["drop_tx"], 1, 0),
                        "" if not v.get("nsx") else int(v["nsx"].get("dfw_drop") or 0), v["vcenter"]])
        return ("﻿" + b.getvalue()).encode("utf-8")

    async def ai(self, window: int = 300, key: str = "", scope: str = "nsx") -> str:
        ov = await self.overview(window, scope)
        segs = [s for s in ov["segments"] if not key or s["key"] == key][:20]
        mb = lambda x: round((x or 0) / 1e6, 2)   # noqa: E731
        digest = {"기간초": ov["window"], "합계": {"세그먼트": ov["totals"]["segments"], "VM": ov["totals"]["vms"], "수신Mbps": mb(ov["totals"]["rx_bps"]),
                                             "송신Mbps": mb(ov["totals"]["tx_bps"]), "드롭": ov["totals"]["drops"]},
                  "세그먼트": [{"이름": s["name"], "게이트웨이": s["gateway"], "Tier1": s["connected_to"], "VM": s["vms"], "수신Mbps": mb(s["rx_bps"]),
                            "송신Mbps": mb(s["tx_bps"]), "최대Mbps": mb(s["peak_bps"]), "드롭": s["drops"]} for s in segs],
                  "상위VM": [{"VM": v["vm"], "세그먼트": v["segment"].rsplit("/", 1)[-1], "수신Mbps": mb(v["rx_bps"]), "송신Mbps": mb(v["tx_bps"]),
                            "최대Mbps": mb(v["peak_bps"]), "드롭": v["drop_rx"] + v["drop_tx"], "호스트": v["host"]}
                           for v in ov["vnics"] if not key or v["segment"] == key][:25]}
        names = sorted({v["vm"] for v in ov["vnics"]} | {v["host"] for v in ov["vnics"] if v["host"]} | {s["name"] for s in segs if s["name"]})
        if scope == "avi":
            digest["가상서비스"] = [{"이름": s["name"], "VIP": s["gateway"], "풀": s["connected_to"], "VIP_Mbps": mb((s.get("avi") or {}).get("bw")),
                                 "요청초": (s.get("avi") or {}).get("rps"), "헬스": (s.get("avi") or {}).get("health"), "백엔드VM": s["vms"],
                                 "VM못찾은멤버": len((s.get("avi") or {}).get("external") or [])} for s in segs]
        system = ("너는 VMware NSX·vSphere·NSX ALB(Avi) 네트워크 운영 전문가다. 아래는 네트워크(NSX 세그먼트·VDS·표준 vSwitch 포트그룹 또는 Avi 가상 서비스)별·VM vNIC 별 트래픽(vCenter 실시간 성능 카운터 net.received/transmitted·"
                  "packets·dropped) 요약이다. 한국어로 ① 트래픽이 몰린 세그먼트·VM(상위 소비자) ② 드롭이 있는 곳과 가능한 원인(게스트 링 버퍼·CPU 경합·"
                  "업링크 포화·DFW 차단) ③ 확인 순서(읽기 전용 명령 먼저: esxtop n·%DRPRX, net-stats -l, vsish, NSX 포트 통계) ④ 개선 제안을 간결히 써라. "
                  "수치를 지어내지 말고 데이터에 없는 것은 '확인 필요'라고 써라.")
        return await self.e.llm.complete(system, json.dumps(digest, ensure_ascii=False), max_tokens=1500, task="report", names=names)
