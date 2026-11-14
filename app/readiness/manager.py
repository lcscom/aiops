"""하드웨어 준비도(VCF-R) 관리자 — 대상·스캔 작업·결과 저장·이력·변화 이벤트·ESXi 매핑·예약 스캔

대상
  · 등록된 Redfish(BMC) 커넥터 — 저장된 읽기 전용 계정을 그대로 사용
  · 일회성 대상 — IP·호스트·범위(10.0.0.1-20)·CIDR(최대 /24) + 그 스캔에만 쓰는 계정(저장하지 않음)
결과는 정규화 dict + 평가 결과만 저장(BMC 원본 응답·비밀번호 없음). 같은 시리얼의 직전 스캔과 비교해 판정·BIOS·펌웨어 변화를 이벤트로 보낸다.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import secrets
import time
import zlib
from pathlib import Path
from typing import Any

from . import rules as R
from .assess import assess_host, fleet
from .collect import collect
from .hcl import HCL_URL, Hcl
from .rfclient import RfClient

SCHEMA = """CREATE TABLE IF NOT EXISTS rd_scans(id TEXT PRIMARY KEY, created REAL, finished REAL, by TEXT, status TEXT, label TEXT, targets TEXT, fleet TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS rd_hosts(scan_id TEXT, target TEXT, source TEXT, ok INTEGER, error TEXT, serial TEXT, data BLOB, ts REAL, PRIMARY KEY(scan_id, target));
CREATE INDEX IF NOT EXISTS ix_rd_hosts_serial ON rd_hosts(serial, ts);
CREATE TABLE IF NOT EXISTS rd_doc(k TEXT PRIMARY KEY, v TEXT, ts REAL, by TEXT);"""
SETTINGS = {"schedule_hours": 0, "concurrency": 4, "host_timeout": 300, "sel_days": 30, "verify_tls": False, "connectors": [], "profile": "full", "retention_scans": 50}
META_IP = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}


def _pack(d: dict) -> bytes:
    return zlib.compress(json.dumps(d, ensure_ascii=False, default=str).encode(), 6)


def _unpack(b) -> dict:
    try:
        return json.loads(zlib.decompress(b))
    except Exception:  # noqa: BLE001
        return {}


def expand_targets(text: str, limit: int = 256) -> list[str]:
    """'10.0.0.5, bmc01.lab, 10.0.1.10-20, 10.0.2.0/28' → 목록(최대 limit). 메타데이터 주소·루프백·멀티캐스트 거부"""
    out: list[str] = []
    for tok in re.split(r"[\s,;]+", str(text or "").strip()):
        if not tok:
            continue
        m = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", tok)
        if m:
            a, b = int(m.group(2)), int(m.group(3))
            if not (0 <= a <= b <= 255):
                raise ValueError(f"범위 오류: {tok}")
            out += [f"{m.group(1)}{i}" for i in range(a, b + 1)]
        elif "/" in tok:
            net = ipaddress.ip_network(tok, strict=False)
            if net.num_addresses > 256:
                raise ValueError(f"CIDR 는 /24 이하만: {tok}")
            out += [str(x) for x in (net.hosts() if net.num_addresses > 2 else net)]
        elif re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{1,253}", tok):
            out.append(tok.strip("[]"))
        else:
            raise ValueError(f"대상 형식 오류: {tok}")
        if len(out) > limit:
            raise ValueError(f"대상은 한 번에 {limit}개까지")
    for t in out:
        try:
            ip = ipaddress.ip_address(t)
            if t in META_IP or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                raise ValueError(f"허용하지 않는 주소: {t}")
        except ValueError as e:
            if "허용하지" in str(e):
                raise
    return list(dict.fromkeys(out))


class ReadinessManager:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self._schema = False
        data_dir = Path(getattr(getattr(engine, "store", None), "path", "data/aiops.db") or "data/aiops.db").parent
        self.hcl = Hcl(data_dir / "readiness" / "vsan_hcl.json.gz")
        self.jobs: dict[str, dict[str, Any]] = {}
        self.transport = None                      # 시험용(httpx MockTransport 또는 대상별 dict)
        self._bcg_loaded = False

    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    async def _doc(self, k: str, default: Any) -> Any:
        self._ensure()
        r = await self.e.store.q1("SELECT v FROM rd_doc WHERE k=?", (k,))
        try:
            return json.loads(r["v"]) if r and r.get("v") else default
        except ValueError:
            return default

    async def _put(self, k: str, v: Any, by: str = "") -> None:
        self._ensure()
        await self.e.store.x("INSERT INTO rd_doc(k,v,ts,by) VALUES(?,?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, ts=excluded.ts, by=excluded.by",
                             (k, json.dumps(v, ensure_ascii=False), time.time(), by))

    async def settings(self) -> dict:
        return {**SETTINGS, **{k: v for k, v in (self.cfg or {}).items() if k in SETTINGS}, **(await self._doc("settings", {}))}

    async def save_settings(self, p: dict, by: str = "") -> dict:
        cur = await self.settings()
        for k in ("schedule_hours", "concurrency", "host_timeout", "sel_days", "retention_scans"):
            if k in p:
                try:
                    cur[k] = max(0, int(p[k]))
                except (TypeError, ValueError):
                    raise ValueError(f"{k}: 정수가 아닙니다") from None
        cur["concurrency"] = min(16, max(1, cur["concurrency"]))
        cur["host_timeout"] = min(1800, max(30, cur["host_timeout"]))
        cur["sel_days"] = min(365, max(1, cur["sel_days"]))
        if "verify_tls" in p:
            cur["verify_tls"] = bool(p["verify_tls"])
        if "profile" in p:
            if p["profile"] not in ("full", "lean"):
                raise ValueError("profile: full | lean")
            cur["profile"] = p["profile"]
        if "connectors" in p:
            cur["connectors"] = [str(x)[:120] for x in p["connectors"] or []][:500]
        await self._put("settings", {k: cur[k] for k in SETTINGS}, by)
        return cur

    async def load_bcg(self) -> None:
        if self._bcg_loaded:
            return
        d = await self._doc("bcg_cpu", None)
        if d:
            R.set_bcg_cpu(d)
        self._bcg_loaded = True

    async def import_bcg_csv(self, text: str, by: str = "") -> dict:
        d = R.parse_bcg_csv(text)
        await self._put("bcg_cpu", d, by)
        R.set_bcg_cpu(d)
        return R.bcg_info()

    # ------------------------------------------------------------------ 대상
    def bmc_connectors(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "redfish" and (c.cfg.get("api") or "auto") != "cimc-xml"]

    async def targets(self) -> list[dict]:
        last = await self.latest_by_target()
        out = []
        for c in self.bmc_connectors():
            t = f"connector:{c.name}"
            lr = last.get(t) or {}
            out.append({"target": t, "name": c.name, "host": c.cfg.get("host", ""), "esxi_host": c.cfg.get("esxi_host", ""), "vendor": getattr(c, "vendor", ""),
                        "last_scan": lr.get("ts"), "verdict": lr.get("verdict"), "error": lr.get("error")})
        return out

    async def latest_by_target(self) -> dict[str, dict]:
        self._ensure()
        rows = await self.e.store.q("SELECT h.target, h.ok, h.error, h.ts, h.data FROM rd_hosts h JOIN (SELECT target, MAX(ts) AS mt FROM rd_hosts GROUP BY target) m "
                                    "ON h.target=m.target AND h.ts=m.mt")
        out = {}
        for r in rows:
            d = _unpack(r["data"]) if r["ok"] else {}
            out[r["target"]] = {"ts": r["ts"], "ok": r["ok"], "error": r["error"], "verdict": (d.get("result") or {}).get("verdict")}
        return out

    # ------------------------------------------------------------------ 스캔
    async def start(self, spec: dict, by: str = "") -> dict:
        """spec: {connectors:[이름…]|'all', targets:'10.0.0.1-5', username, password, port, verify_tls, label, profile}"""
        await self.load_bcg()
        st = await self.settings()
        items: list[dict] = []
        names = spec.get("connectors")
        conns = self.bmc_connectors()
        if names == "all":
            names = [c.name for c in conns]
        for c in conns:
            if c.name in (names or []):
                items.append({"target": f"connector:{c.name}", "host": c.cfg.get("base_url") or c.cfg.get("host", ""), "user": c.cfg.get("username", ""), "pw": c.cfg.get("password", ""),
                              "verify": bool(c.cfg.get("verify_ssl", c.cfg.get("verify", False))), "port": c.cfg.get("port"), "source": "connector", "label": c.name,
                              "esxi_host": c.cfg.get("esxi_host", "")})
        if spec.get("targets"):
            if not spec.get("username") or not spec.get("password"):
                raise ValueError("일회성 대상에는 BMC 읽기 전용 계정이 필요합니다(저장하지 않음)")
            for t in expand_targets(spec["targets"]):
                items.append({"target": t, "host": t, "user": str(spec["username"]), "pw": str(spec["password"]), "verify": bool(spec.get("verify_tls", st["verify_tls"])),
                              "port": int(spec["port"]) if str(spec.get("port") or "").isdigit() else None, "source": "adhoc", "label": t, "esxi_host": ""})
        if not items:
            raise ValueError("스캔할 대상이 없습니다(BMC 커넥터를 고르거나 대상을 입력)")
        if len(items) > 512:
            raise ValueError("한 번에 512대까지")
        if any(j["status"] == "running" for j in self.jobs.values()):
            raise RuntimeError("이미 진행 중인 스캔이 있습니다")
        sid = time.strftime("RD-%Y%m%d-%H%M%S-") + secrets.token_hex(2)
        self._ensure()
        await self.e.store.x("INSERT INTO rd_scans(id,created,by,status,label,targets) VALUES(?,?,?,?,?,?)",
                             (sid, time.time(), by, "running", str(spec.get("label") or "")[:120], json.dumps([i["target"] for i in items])))
        job = {"id": sid, "status": "running", "total": len(items), "done": 0, "failed": 0, "hosts": {i["target"]: {"stage": "대기", "label": i["label"]} for i in items},
               "started": time.time(), "by": by, "cancel": False}
        self.jobs[sid] = job
        profile = spec.get("profile") or st["profile"]
        task = asyncio.create_task(self._run(job, items, st, profile))
        job["_task"] = task
        return self.job_view(sid)

    def job_view(self, sid: str) -> dict:
        j = self.jobs.get(sid)
        if not j:
            return {}
        return {k: v for k, v in j.items() if not k.startswith("_")}

    async def cancel(self, sid: str) -> bool:
        j = self.jobs.get(sid)
        if not j or j["status"] != "running":
            return False
        j["cancel"] = True
        return True

    async def _run(self, job: dict, items: list[dict], st: dict, profile: str) -> None:
        sem = asyncio.Semaphore(st["concurrency"])
        results: list[dict] = []

        async def one(it: dict) -> None:
            async with sem:
                if job["cancel"]:
                    job["hosts"][it["target"]] = {"stage": "취소", "label": it["label"]}
                    return
                hs = job["hosts"][it["target"]]
                hs["stage"] = "수집 중"
                t0 = time.time()
                rec = {"target": it["target"], "source": it["source"], "label": it["label"], "esxi_host": it["esxi_host"]}
                try:
                    tr = self.transport.get(it["host"]) if isinstance(self.transport, dict) else self.transport
                    async with RfClient(it["host"], it["user"], it["pw"], verify=it["verify"], port=it["port"], transport=tr) as c:
                        h = await asyncio.wait_for(collect(c, profile=profile), st["host_timeout"])
                    hs["stage"] = "평가 중"
                    rec.update(host=h, result=assess_host(h, self.hcl, st["sel_days"]), ok=True, secs=round(time.time() - t0, 1))
                    self._map_esxi([rec])
                    hs.update(stage="완료", verdict=rec["result"]["verdict"], model=h["system"].get("model"), secs=rec["secs"])
                    job["done"] += 1
                except Exception as e:  # noqa: BLE001
                    msg = "BMC 인증 실패" if isinstance(e, PermissionError) else (f"시간 초과({st['host_timeout']}초)" if isinstance(e, asyncio.TimeoutError) else f"{type(e).__name__}: {e}"[:300])
                    rec.update(ok=False, error=msg)
                    hs.update(stage="실패", error=msg)
                    job["failed"] += 1
                results.append(rec)
                await self._save_host(job["id"], rec)

        try:
            await asyncio.gather(*(one(i) for i in items))
            fl = fleet([{"target": r["label"], "host": r["host"], "result": r["result"]} if r.get("ok") else {"target": r["label"]} for r in results])
            status = "cancelled" if job["cancel"] else "done"
            await self.e.store.x("UPDATE rd_scans SET status=?, finished=?, fleet=? WHERE id=?", (status, time.time(), json.dumps(fl, ensure_ascii=False, default=str), job["id"]))
            job["status"] = status
            await self._changes(job["id"], results)
            await self._prune(st["retention_scans"])
        except Exception as e:  # noqa: BLE001
            job["status"] = "error"
            job["error"] = f"{type(e).__name__}: {e}"[:300]
            await self.e.store.x("UPDATE rd_scans SET status='error', finished=?, error=? WHERE id=?", (time.time(), job["error"], job["id"]))
        finally:
            job["finished"] = time.time()

    async def _save_host(self, sid: str, rec: dict) -> None:
        serial = ((rec.get("host") or {}).get("system") or {}).get("serial", "") if rec.get("ok") else ""
        body = {k: rec.get(k) for k in ("label", "source", "esxi_host", "host", "result", "secs", "esxi")}
        await self.e.store.x("INSERT OR REPLACE INTO rd_hosts(scan_id,target,source,ok,error,serial,data,ts) VALUES(?,?,?,?,?,?,?,?)",
                             (sid, rec["target"], rec["source"], 1 if rec.get("ok") else 0, rec.get("error", ""), serial, _pack(body), time.time()))

    def _map_esxi(self, results: list[dict]) -> None:
        """BMC 시리얼·UUID ↔ vCenter ESXi 호스트(hardware.systemInfo) 연결"""
        idx = {}
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") != "vcenter":
                continue
            for hn, h in ((getattr(c, "topology", None) or {}).get("hosts") or {}).items():
                for k in (str(h.get("serial") or "").upper(), str(h.get("uuid") or "").lower()):
                    if k:
                        idx[k] = {"esxi": hn, "vcenter": c.name, "cluster": h.get("cluster", ""), "version": h.get("version") or h.get("build", "")}
            for hn, h in ((getattr(c, "health_snap", None) or {}).get("hosts") or {}).items():
                s = str(h.get("serial") or "").upper()
                if s and s not in idx:
                    idx[s] = {"esxi": hn, "vcenter": c.name, "cluster": h.get("cluster", "")}
        for r in results:
            if not r.get("ok"):
                continue
            s = r["host"]["system"]
            m = idx.get(str(s.get("serial") or "").upper()) or idx.get(str(s.get("uuid") or "").lower())
            if m:
                r["esxi"] = m
            elif r.get("esxi_host"):
                r["esxi"] = {"esxi": r["esxi_host"], "vcenter": "", "cluster": "", "by": "커넥터 설정"}

    async def _changes(self, sid: str, results: list[dict]) -> None:
        """같은 시리얼 직전 스캔과 비교 → 판정·BIOS 버전·BMC 펌웨어·실패 점검 변화 이벤트"""
        ingest = getattr(self.e, "ingest", None)
        if not ingest:
            return
        from ..models import LogEvent
        for r in results:
            if not r.get("ok"):
                continue
            serial = r["host"]["system"].get("serial")
            if not serial:
                continue
            prev = await self.e.store.q1("SELECT data FROM rd_hosts WHERE serial=? AND scan_id<>? AND ok=1 ORDER BY ts DESC LIMIT 1", (serial, sid))
            if not prev:
                continue
            p = _unpack(prev["data"])
            pr, cr = p.get("result") or {}, r["result"]
            name = (r.get("esxi") or {}).get("esxi") or r["label"]
            msgs = []
            if pr.get("verdict") != cr["verdict"]:
                worse = ["ready", "actions", "unknown", "not_ready"].index(cr["verdict"]) > ["ready", "actions", "unknown", "not_ready"].index(pr.get("verdict") or "ready")
                msgs.append(("warning" if worse else "info", f"VCF 준비도 판정 변경 — {name}: {pr.get('verdict_label')} → {cr['verdict_label']}"))
            for key, lab in (("bios", "BIOS"), ("bmc_fw", "BMC 펌웨어")):
                a, b = (pr.get("summary") or {}).get(key), cr["summary"].get(key)
                if a and b and a != b:
                    msgs.append(("info", f"{lab} 변경 — {name}: {a} → {b}"))
            pf = {c["id"] for c in pr.get("checks") or [] if c["status"] == "fail"}
            new = [c for c in cr["checks"] if c["status"] == "fail" and c["id"] not in pf]
            for c in new[:10]:
                msgs.append(("warning", f"하드웨어 준비도 새 실패 — {name}: {c['title']} ({c['detail'][:120]})"))
            for sev, m in msgs:
                ev = LogEvent(source="redfish", connector="readiness", message=m, severity=sev, host=name, entity=name, kind="config",
                              attrs={"app": "vcf-readiness", "scan": sid, "serial": serial, "no_anomaly": 0 if sev == "warning" else 1})
                await ingest(ev) if asyncio.iscoroutinefunction(ingest) else ingest(ev)

    async def _prune(self, keep: int) -> None:
        if keep <= 0:
            return
        rows = await self.e.store.q("SELECT id FROM rd_scans ORDER BY created DESC LIMIT -1 OFFSET ?", (keep,))
        for r in rows:
            await self.e.store.x("DELETE FROM rd_hosts WHERE scan_id=?", (r["id"],))
            await self.e.store.x("DELETE FROM rd_scans WHERE id=?", (r["id"],))

    # ------------------------------------------------------------------ 조회
    async def scans(self, limit: int = 50) -> list[dict]:
        self._ensure()
        rows = await self.e.store.q("SELECT id, created, finished, by, status, label, targets, fleet, error FROM rd_scans ORDER BY created DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            fl = json.loads(r["fleet"]) if r.get("fleet") else {}
            out.append({**{k: r[k] for k in ("id", "created", "finished", "by", "status", "label", "error")}, "targets": len(json.loads(r["targets"] or "[]")),
                        "verdicts": fl.get("verdicts"), "totals": fl.get("totals"), "live": self.job_view(r["id"]) if r["id"] in self.jobs and r["status"] == "running" else None})
        return out

    async def scan(self, sid: str) -> dict | None:
        self._ensure()
        s = await self.e.store.q1("SELECT * FROM rd_scans WHERE id=?", (sid,))
        if not s:
            return None
        hosts = await self.e.store.q("SELECT target, source, ok, error, ts, data FROM rd_hosts WHERE scan_id=? ORDER BY target", (sid,))
        items = []
        for h in hosts:
            d = _unpack(h["data"]) if h["ok"] else _unpack(h["data"])
            res = d.get("result") or {}
            items.append({"target": h["target"], "label": d.get("label") or h["target"], "source": h["source"], "ok": bool(h["ok"]), "error": h["error"], "ts": h["ts"],
                          "esxi": d.get("esxi"), "verdict": res.get("verdict"), "verdict_label": res.get("verdict_label"), "summary": res.get("summary"),
                          "areas": res.get("areas"), "counts": res.get("counts"), "security": (res.get("security") or {}).get("score"),
                          "bios": {k: (res.get("bios") or {}).get(k) for k in ("status", "compliance", "drift")}})
        return {**{k: s[k] for k in ("id", "created", "finished", "by", "status", "label", "error")}, "fleet": json.loads(s["fleet"]) if s.get("fleet") else None,
                "hosts": items, "live": self.job_view(sid) if sid in self.jobs else None}

    async def host(self, sid: str, target: str) -> dict | None:
        self._ensure()
        r = await self.e.store.q1("SELECT * FROM rd_hosts WHERE scan_id=? AND target=?", (sid, target))
        if not r:
            return None
        d = _unpack(r["data"])
        hist = await self.e.store.q("SELECT scan_id, ts, ok, data FROM rd_hosts WHERE target=? ORDER BY ts DESC LIMIT 12", (target,))
        trend = []
        for x in hist:
            dd = _unpack(x["data"]) if x["ok"] else {}
            rr = dd.get("result") or {}
            trend.append({"scan": x["scan_id"], "ts": x["ts"], "verdict": rr.get("verdict"), "fail": (rr.get("counts") or {}).get("fail", 0),
                          "warn": (rr.get("counts") or {}).get("warn", 0), "sec": ((rr.get("security") or {}).get("score") or {}).get("compliance"),
                          "bios": (rr.get("summary") or {}).get("bios")})
        return {"scan_id": sid, "target": target, "ok": bool(r["ok"]), "error": r["error"], "ts": r["ts"], **d, "trend": trend}

    async def records(self, sid: str) -> tuple[dict | None, list[dict]]:
        """보고서용 전체 레코드"""
        self._ensure()
        s = await self.e.store.q1("SELECT * FROM rd_scans WHERE id=?", (sid,))
        if not s:
            return None, []
        rows = await self.e.store.q("SELECT target, ok, error, data FROM rd_hosts WHERE scan_id=? ORDER BY target", (sid,))
        recs = []
        for r in rows:
            d = _unpack(r["data"])
            recs.append({"target": r["target"], "ok": bool(r["ok"]), "error": r["error"], **d, "label": d.get("label") or r["target"]})
        meta = {**{k: s[k] for k in ("id", "created", "finished", "by", "status", "label")}, "fleet": json.loads(s["fleet"]) if s.get("fleet") else {}}
        return meta, recs

    async def latest_hosts(self) -> list[dict]:
        """대상별 최신 성공 결과(비용 비교·SR·NOC 연계용)"""
        self._ensure()
        rows = await self.e.store.q("SELECT h.target, h.scan_id, h.ts, h.data FROM rd_hosts h JOIN (SELECT target, MAX(ts) mt FROM rd_hosts WHERE ok=1 GROUP BY target) m "
                                    "ON h.target=m.target AND h.ts=m.mt WHERE h.ok=1")
        out = []
        for r in rows:
            d = _unpack(r["data"])
            out.append({"target": r["target"], "scan_id": r["scan_id"], "ts": r["ts"], **d})
        return out

    # ------------------------------------------------------------------ HCL
    async def hcl_refresh(self, by: str = "", transport=None) -> dict:
        import httpx
        async with httpx.AsyncClient(timeout=120, transport=transport, follow_redirects=True) as c:
            r = await c.get(HCL_URL)
            if r.status_code >= 400:
                r = await c.get(HCL_URL[:-3])
            r.raise_for_status()
            meta = self.hcl.load_bytes(r.content, source=HCL_URL)
        await self._put("hcl_meta", meta, by)
        return meta

    async def hcl_upload(self, raw: bytes, by: str = "") -> dict:
        meta = self.hcl.load_bytes(raw, source="upload")
        await self._put("hcl_meta", meta, by)
        return meta

    # ------------------------------------------------------------------ 예약
    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(120)
        while True:
            beat()
            try:
                st = await self.settings()
                hrs = st["schedule_hours"]
                if hrs > 0 and self.bmc_connectors():
                    last = await self.e.store.q1("SELECT MAX(created) AS t FROM rd_scans WHERE by='schedule'")
                    if not last or not last.get("t") or time.time() - last["t"] >= hrs * 3600:
                        names = st["connectors"] or "all"
                        await self.start({"connectors": names, "label": "예약 스캔"}, "schedule")
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(600)
