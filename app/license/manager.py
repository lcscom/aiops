"""라이선스 관리(2.16.0) — 프로젝트(고객·사이트) 단위로 ① 공급자 데이터 ② Broadcom CSP 데이터 ③ 실사용(vCenter 커넥터·RVTools·VCF Operations 사용량)을 모아 비교

실사용 소스
  · vcenter:<커넥터>   — 등록된 vCenter 커넥터(읽기 전용 계정)로 LicenseManager·호스트 할당 수집(수동·예약)
  · rvtools:<분석 ID> — RVTools 분석의 vLicense·vHost(Assigned License) — 커넥터 없이 고객 파일로
  · vcfops:<보고서 ID> — VCF Operations 9.x 사용량 파일(업로드) 또는 VCF Ops 커넥터에서 받기(내부 API — 설정에서 켤 때만)
판정: 키 매칭(실사용 ↔ CSP), 수량 초과·만료·만료 예정·미할당(평가 모드)·CSP 미등록·코어 16 최소 영향·사용량 보고 주기(180일) 등 LIC-01~12
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections import defaultdict
from datetime import date, datetime

from . import util as U

SCHEMA = """CREATE TABLE IF NOT EXISTS lic_projects(id TEXT PRIMARY KEY, name TEXT UNIQUE, description TEXT, location TEXT, created REAL, by TEXT);
CREATE TABLE IF NOT EXISTS lic_batches(id TEXT PRIMARY KEY, kind TEXT, name TEXT, uploaded REAL, by TEXT, rows INTEGER, errors TEXT);
CREATE TABLE IF NOT EXISTS lic_supplier(serial TEXT PRIMARY KEY, batch TEXT, project TEXT, parent_customer TEXT, customer TEXT, license_key TEXT, license_type TEXT,
  product TEXT, quantity INTEGER, contract_status TEXT, start_date TEXT, end_date TEXT, erp_site_id TEXT, enduser TEXT, part_number TEXT, division TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS lic_csp(id INTEGER PRIMARY KEY AUTOINCREMENT, batch TEXT, project TEXT, license_key TEXT, product TEXT, quantity INTEGER, unit TEXT,
  folder TEXT, end_date TEXT);
CREATE TABLE IF NOT EXISTS lic_sources(id TEXT PRIMARY KEY, kind TEXT, name TEXT, project TEXT, collected REAL, by TEXT, version TEXT, error TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS lic_doc(k TEXT PRIMARY KEY, v TEXT, ts REAL, by TEXT);
CREATE INDEX IF NOT EXISTS ix_lic_csp_batch ON lic_csp(batch);
CREATE INDEX IF NOT EXISTS ix_lic_sup_batch ON lic_supplier(batch);"""
SETTINGS = {"schedule_hours": 24, "vcfops_usage_api": False, "expiry_warn_days": 90, "usage_report_days": 150}
SEV_ORDER = ["critical", "error", "warning", "info"]
KB = {"core16": "https://knowledge.broadcom.com/external/article/313548", "usage": "https://knowledge.broadcom.com/external/article/448518"}


def _today() -> date:
    return date.today()


def _days(d: str | None) -> int | None:
    if not d:
        return None
    try:
        return (date.fromisoformat(d[:10]) - _today()).days
    except ValueError:
        return None


class LicenseManager:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self._ready = False
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------------------------------- 기본
    async def db(self):
        st = self.e.store
        if not self._ready:
            st.schema(SCHEMA)
            self._ready = True
        return st

    async def settings(self) -> dict:
        st = await self.db()
        r = await st.q1("SELECT v FROM lic_doc WHERE k='settings'")
        base = dict(SETTINGS, **{k: v for k, v in self.cfg.items() if k in SETTINGS})
        if r:
            try:
                base.update({k: v for k, v in json.loads(r["v"]).items() if k in SETTINGS})
            except Exception:  # noqa: BLE001
                pass
        return base

    async def save_settings(self, b: dict, by: str) -> dict:
        cur = await self.settings()
        cur["schedule_hours"] = max(0, min(int(b.get("schedule_hours", cur["schedule_hours"])), 24 * 30))
        cur["expiry_warn_days"] = max(7, min(int(b.get("expiry_warn_days", cur["expiry_warn_days"])), 730))
        cur["usage_report_days"] = max(30, min(int(b.get("usage_report_days", cur["usage_report_days"])), 179))
        cur["vcfops_usage_api"] = bool(b.get("vcfops_usage_api", cur["vcfops_usage_api"]))
        st = await self.db()
        await st.x("INSERT INTO lic_doc(k,v,ts,by) VALUES('settings',?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, ts=excluded.ts, by=excluded.by",
                   (json.dumps(cur), time.time(), by))
        return cur

    # ------------------------------------------------------------------------------------------- 프로젝트
    async def projects(self) -> list[dict]:
        st = await self.db()
        return await st.q("SELECT id,name,description,location,created,by FROM lic_projects ORDER BY name")

    async def save_project(self, b: dict, by: str, pid: str | None = None) -> dict:
        name = str(b.get("name") or "").strip()[:120]
        if not name:
            raise ValueError("프로젝트 이름 필요")
        st = await self.db()
        dup = await st.q1("SELECT id FROM lic_projects WHERE name=? AND id<>?", (name, pid or ""))
        if dup:
            raise ValueError("같은 이름의 프로젝트가 있습니다")
        desc, loc = str(b.get("description") or "")[:500], str(b.get("location") or "")[:200]
        if pid:
            if not await st.q1("SELECT id FROM lic_projects WHERE id=?", (pid,)):
                raise KeyError(pid)
            await st.x("UPDATE lic_projects SET name=?, description=?, location=? WHERE id=?", (name, desc, loc, pid))
        else:
            pid = "p-" + secrets.token_hex(4)
            await st.x("INSERT INTO lic_projects(id,name,description,location,created,by) VALUES(?,?,?,?,?,?)", (pid, name, desc, loc, time.time(), by))
        return {"id": pid, "name": name, "description": desc, "location": loc}

    async def delete_project(self, pid: str) -> bool:
        st = await self.db()
        r = await st.q1("SELECT id FROM lic_projects WHERE id=?", (pid,))
        if not r:
            return False
        for t in ("lic_supplier", "lic_csp", "lic_sources"):
            await st.x(f"UPDATE {t} SET project=NULL WHERE project=?", (pid,))   # noqa: S608 — 고정 테이블 이름
        await st.x("DELETE FROM lic_projects WHERE id=?", (pid,))
        return True

    async def assign(self, pid: str | None, kind: str, ids: list, by_filter: dict | None = None) -> int:
        """kind: supplier(serial) · csp(id) · source(id). pid=None 이면 할당 해제. by_filter: {'folder': …} · {'customer': …} 로 일괄"""
        st = await self.db()
        if pid and not await st.q1("SELECT id FROM lic_projects WHERE id=?", (pid,)):
            raise KeyError(pid)
        n = 0
        if kind == "supplier":
            if by_filter and by_filter.get("customer"):
                n = await st.x("UPDATE lic_supplier SET project=? WHERE customer=? OR enduser=?", (pid, by_filter["customer"], by_filter["customer"]))
                return int((await st.q1("SELECT COUNT(*) c FROM lic_supplier WHERE project IS ?", (pid,)))["c"])
            for i in ids[:20000]:
                await st.x("UPDATE lic_supplier SET project=? WHERE serial=?", (pid, str(i)))
                n += 1
        elif kind == "csp":
            if by_filter and by_filter.get("folder") is not None:
                await st.x("UPDATE lic_csp SET project=? WHERE folder=?", (pid, by_filter["folder"]))
                return int((await st.q1("SELECT COUNT(*) c FROM lic_csp WHERE folder=?", (by_filter["folder"],)))["c"])
            for i in ids[:20000]:
                await st.x("UPDATE lic_csp SET project=? WHERE id=?", (pid, int(i)))
                n += 1
        elif kind == "source":
            for i in ids[:500]:
                await st.x("UPDATE lic_sources SET project=? WHERE id=?", (pid, str(i)))
                n += 1
        else:
            raise ValueError("kind = supplier | csp | source")
        return n

    # ------------------------------------------------------------------------------------------- 업로드
    async def upload(self, kind: str, raw: bytes, name: str, by: str) -> dict:
        if len(raw) > 50 * 1024 * 1024:
            raise ValueError("파일이 50MB 를 넘습니다")
        st = await self.db()
        bid = f"{kind[:3]}-{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
        if kind == "vcfops":
            rep = await asyncio.to_thread(U.parse_usage, raw)
            return await self._save_usage(rep, name, by)
        if raw[:2] != b"PK":
            raise ValueError("xlsx 파일이 아닙니다")
        if kind == "supplier":
            rows, errs = await asyncio.to_thread(U.parse_supplier, raw)
            ins = upd = 0
            for x in rows:
                old = await st.q1("SELECT project FROM lic_supplier WHERE serial=?", (x["serial"],))
                cols = ["serial", "parent_customer", "customer", "license_key", "license_type", "product", "quantity", "contract_status", "start_date",
                        "end_date", "erp_site_id", "enduser", "part_number", "division"]
                if old:
                    await st.x("UPDATE lic_supplier SET batch=?, updated=?, " + ", ".join(f"{c}=?" for c in cols[1:]) + " WHERE serial=?",
                               (bid, time.time(), *[x[c] for c in cols[1:]], x["serial"]))
                    upd += 1
                else:
                    await st.x(f"INSERT INTO lic_supplier(batch,updated,{','.join(cols)}) VALUES(?,?,{','.join('?' * len(cols))})",   # noqa: S608
                               (bid, time.time(), *[x[c] for c in cols]))
                    ins += 1
            res = {"inserted": ins, "updated": upd}
        elif kind == "csp":
            rows, errs = await asyncio.to_thread(U.parse_csp, raw)
            # 같은 파일 이름으로 다시 올리면 이전 묶음을 지우고 대체(행마다 고유 식별자가 없는 내보내기 — 같은 키가 여러 행일 수 있음).
            # 지우기 전 프로젝트 할당은 (키·폴더) 기준으로 이어 받음
            keep: dict[tuple, str] = {}
            for b in await st.q("SELECT id FROM lic_batches WHERE kind='csp' AND name=?", (U.s(name),)):
                for r in await st.q("SELECT license_key, folder, project FROM lic_csp WHERE batch=? AND project IS NOT NULL", (b["id"],)):
                    keep[(r["license_key"], r["folder"])] = r["project"]
                await self.delete_batch(b["id"])
            for x in rows:
                await st.x("INSERT INTO lic_csp(batch,project,license_key,product,quantity,unit,folder,end_date) VALUES(?,?,?,?,?,?,?,?)",
                           (bid, keep.get((x["license_key"], x["folder"])), x["license_key"], x["product"], x["quantity"], x["unit"], x["folder"], x["end_date"]))
            res = {"inserted": len(rows), "updated": 0, "replaced": bool(keep) or None}
        else:
            raise ValueError("kind = supplier | csp | vcfops")
        await st.x("INSERT INTO lic_batches(id,kind,name,uploaded,by,rows,errors) VALUES(?,?,?,?,?,?,?)",
                   (bid, kind, U.s(name)[:160], time.time(), by, len(rows), json.dumps(errs[:200], ensure_ascii=False)))
        return {"id": bid, "kind": kind, "name": U.s(name)[:160], "rows": len(rows), "skipped": len(errs), "errors": errs[:20], **res}

    async def batches(self) -> list[dict]:
        st = await self.db()
        return [dict(b, errors=len(json.loads(b["errors"] or "[]"))) for b in await st.q("SELECT id,kind,name,uploaded,by,rows,errors FROM lic_batches ORDER BY uploaded DESC")]

    async def delete_batch(self, bid: str) -> bool:
        st = await self.db()
        b = await st.q1("SELECT kind FROM lic_batches WHERE id=?", (bid,))
        if not b:
            return False
        if b["kind"] == "supplier":
            await st.x("DELETE FROM lic_supplier WHERE batch=?", (bid,))
        elif b["kind"] == "csp":
            await st.x("DELETE FROM lic_csp WHERE batch=?", (bid,))
        await st.x("DELETE FROM lic_batches WHERE id=?", (bid,))
        return True

    # ------------------------------------------------------------------------------------------- 실사용 수집
    def vcenters(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcenter" and hasattr(c, "collect_licenses")]

    def vcfops(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcfops"]

    async def _save_source(self, sid: str, kind: str, name: str, data: dict, by: str, error: str = "", version: str = "") -> None:
        st = await self.db()
        await st.x("INSERT INTO lic_sources(id,kind,name,project,collected,by,version,error,data) VALUES(?,?,?,NULL,?,?,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET name=excluded.name, collected=excluded.collected, by=excluded.by, version=excluded.version, "
                   "error=excluded.error, data=excluded.data",
                   (sid, kind, name, time.time(), by, version, error[:500], json.dumps(data, ensure_ascii=False, default=str)))

    async def collect_vcenter(self, names: list[str] | None = None, by: str = "") -> list[dict]:
        out = []
        for c in self.vcenters():
            if names and c.name not in names:
                continue
            try:
                d = await asyncio.wait_for(asyncio.to_thread(c.collect_licenses), 180)
                await self._save_source(f"vcenter:{c.name}", "vcenter", c.name, {"licenses": d["licenses"], "hosts": d["hosts"]}, by,
                                        d.get("error", ""), d.get("version", ""))
                out.append({"source": f"vcenter:{c.name}", "licenses": len(d["licenses"]), "hosts": len(d["hosts"]), "error": d.get("error", "")})
            except Exception as e:  # noqa: BLE001
                msg = f"{type(e).__name__}: {e}"[:300]
                st = await self.db()
                if await st.q1("SELECT id FROM lic_sources WHERE id=?", (f"vcenter:{c.name}",)):
                    await st.x("UPDATE lic_sources SET error=? WHERE id=?", (msg, f"vcenter:{c.name}"))     # 직전 수집값은 유지
                else:
                    await self._save_source(f"vcenter:{c.name}", "vcenter", c.name, {"licenses": [], "hosts": []}, by, msg)
                out.append({"source": f"vcenter:{c.name}", "error": msg})
        return out

    async def import_rvtools(self, iid: str, by: str) -> dict:
        rv = getattr(self.e, "rvtools", None)
        g = await rv.get(iid) if rv else None
        if not g:
            raise KeyError(iid)
        meta, inv, _ = g
        if inv["licenses"] and not any(x.get("key") for x in inv["licenses"]):
            raise ValueError("이 RVTools 분석은 2.16 이전에 올린 것이라 라이선스 키가 없습니다 — RVTools 분석에 파일을 다시 올리세요")
        lic = [{"key": x.get("key", ""), "name": x["name"], "cost_unit": x["unit"], "total": x["total"] or 0, "used": x["used"] or 0,
                "expires": (datetime.fromtimestamp(x["expires"]).date().isoformat() if x.get("expires") else None), "vcenter": x.get("vcenter", "")}
               for x in inv["licenses"]]
        names = {x["key"]: (x["name"], x["cost_unit"]) for x in lic if x["key"]}
        hosts = [{"host": hn, "cluster": h["cluster"], "vcenter": h["vcenter"], "sockets": h["sockets"] or 0, "cores": h["cores"] or 0,
                  "license_key": h.get("license", ""), "license_name": names.get(h.get("license", ""), ("", ""))[0],
                  "cost_unit": names.get(h.get("license", ""), ("", ""))[1], "version": h["version"]} for hn, h in inv["hosts"].items()]
        vcs = ", ".join(inv["vcenters"])
        await self._save_source(f"rvtools:{iid}", "rvtools", f"{meta['name']} ({vcs})", {"licenses": lic, "hosts": hosts,
                                "exported": inv["meta"].get("exported")}, by, "", inv["meta"].get("rvtools", ""))
        return {"source": f"rvtools:{iid}", "licenses": len(lic), "hosts": len(hosts)}

    async def _save_usage(self, rep: dict, name: str, by: str, source: str = "upload") -> dict:
        sid = f"vcfops:{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
        await self._save_source(sid, "vcfops", U.s(name)[:160] or "usage", dict(rep, origin=source), by)
        return {"source": sid, "products": len(rep["products"]), "assets": rep["assets"], "timestamp": rep["timestamp"]}

    async def pull_vcfops(self, cname: str, by: str) -> dict:
        """VCF Ops 커넥터 계정으로 사용량 보고서 받기 — 내부(비지원) API 라서 설정 'vcfops_usage_api' 를 켰을 때만.
        경로: KB 448518 의 'POST /internal/license-manager/usage/report'(X-Ops-API-use-unsupported: true), 안 되면 9.0 의
        '/internal/extension/vcf-license-cloud-integration/usage/offline/report'. 라이선스·구성을 바꾸지 않고 보고서 내용만 받는다."""
        if not (await self.settings())["vcfops_usage_api"]:
            raise PermissionError("설정 › VCF Ops 사용량 API 가 꺼져 있습니다 — 사용량 파일을 올리거나 설정에서 켜세요")
        c = next((x for x in self.vcfops() if x.name == cname), None)
        if not c:
            raise KeyError(cname)
        if not getattr(c, "token", None) and hasattr(c, "login"):
            await c.login()
        now = int(time.time() * 1000)
        hdr = {"X-Ops-API-use-unsupported": "true", "Accept": "application/json", "Content-Type": "application/json"}
        last = ""
        for path, params in (("/suite-api/internal/license-manager/usage/report", None),
                             ("/suite-api/internal/extension/vcf-license-cloud-integration/usage/offline/report",
                              {"startDate": now + 86400000, "endDate": now + 30 * 86400000})):
            try:
                r = await c.http.post(path, headers=hdr, params=params)
                if r.status_code == 200 and r.content:
                    rep = await asyncio.to_thread(U.parse_usage, r.content)
                    out = await self._save_usage(rep, f"{cname} (API)", by, "api")
                    return dict(out, api=path)
                last = f"{path} → HTTP {r.status_code}"
            except Exception as e:  # noqa: BLE001
                last = f"{path} → {type(e).__name__}: {e}"[:200]
        raise RuntimeError(f"사용량 보고서를 받지 못했습니다 — {last}")

    async def sources(self) -> list[dict]:
        st = await self.db()
        out = []
        for r in await st.q("SELECT id,kind,name,project,collected,by,version,error,data FROM lic_sources ORDER BY kind, name"):
            d = json.loads(r["data"] or "{}")
            out.append({k: r[k] for k in ("id", "kind", "name", "project", "collected", "by", "version", "error")} |
                       {"hosts": len(d.get("hosts") or []), "licenses": len(d.get("licenses") or []), "products": len(d.get("products") or []),
                        "timestamp": d.get("timestamp") or d.get("exported")})
        have = {x["id"] for x in out}
        for c in self.vcenters():                          # 아직 수집 안 한 커넥터도 목록에
            if f"vcenter:{c.name}" not in have:
                out.append({"id": f"vcenter:{c.name}", "kind": "vcenter", "name": c.name, "project": None, "collected": None, "pending": True,
                            "hosts": 0, "licenses": 0, "products": 0})
        return out

    async def delete_source(self, sid: str) -> bool:
        st = await self.db()
        r = await st.q1("SELECT id FROM lic_sources WHERE id=?", (sid,))
        if r:
            await st.x("DELETE FROM lic_sources WHERE id=?", (sid,))
        return bool(r)

    # ------------------------------------------------------------------------------------------- 조회·분석
    async def _load(self, project: str | None) -> dict:
        """project: None = 전체, '' = 미할당, 그 밖 = 해당 프로젝트"""
        st = await self.db()

        def flt(col="project"):
            if project is None:
                return "", ()
            if project == "":
                return f" WHERE {col} IS NULL", ()
            return f" WHERE {col}=?", (project,)
        w, p = flt()
        sup = await st.q("SELECT * FROM lic_supplier" + w + " ORDER BY customer, product", p)        # noqa: S608
        csp = await st.q("SELECT * FROM lic_csp" + w + " ORDER BY folder, product", p)               # noqa: S608
        srcs = await st.q("SELECT id,kind,name,project,collected,version,error,data FROM lic_sources" + w, p)   # noqa: S608
        hosts, lics, usage = [], [], []
        for r in srcs:
            d = json.loads(r["data"] or "{}")
            for h in d.get("hosts") or []:
                cat = U.category(h.get("cost_unit")) if h.get("license_key") and h["license_key"] != U.EVAL_KEY else "unlicensed"
                hosts.append(dict(h, source=r["id"], source_name=r["name"], vcenter=h.get("vcenter") or (r["name"] if r["kind"] == "vcenter" else ""),
                                  category=cat, licensed_cores=U.licensed_cores(h.get("sockets"), h.get("cores")),
                                  qty=(h.get("sockets") or 0) if cat == "perpetual" else (U.licensed_cores(h.get("sockets"), h.get("cores")) if cat == "term" else 0)))
            for x in d.get("licenses") or []:
                lics.append(dict(x, source=r["id"], source_name=r["name"], category=U.category(x.get("cost_unit"))))
            if r["kind"] == "vcfops":
                usage.append({"source": r["id"], "name": r["name"], "collected": r["collected"], "timestamp": d.get("timestamp"),
                              "usage_end": d.get("usage_end"), "products": d.get("products") or [], "assets": d.get("assets"), "origin": d.get("origin")})
        return {"supplier": sup, "csp": csp, "sources": srcs, "hosts": hosts, "licenses": lics, "usage": usage}

    async def overview(self, project: str | None = None) -> dict:
        d = await self._load(project)
        cfg = await self.settings()
        return {"summary": summarize(d), "checks": checks(d, cfg), "match": match(d)["stats"], "projects": await self.project_summaries()}

    async def project_summaries(self) -> list[dict]:
        out = []
        for p in await self.projects() + [{"id": "", "name": "(미할당)"}]:
            d = await self._load(p["id"])
            s_ = summarize(d)
            if p["id"] == "" and not (s_["supplier"]["rows"] or s_["csp"]["rows"] or s_["inventory"]["hosts"] or s_["usage"]["reports"]):
                continue
            out.append({**{k: p.get(k) for k in ("id", "name", "description", "location")}, **s_})
        return out

    async def data(self, what: str, project: str | None, full: bool = False) -> list[dict]:
        d = await self._load(project)
        if what == "match":
            rows = match(d)["rows"]
        elif what in ("supplier", "csp", "hosts", "licenses", "usage"):
            rows = d[what]
        else:
            raise KeyError(what)
        if not full:
            rows = [mask_row(r) for r in rows]
        return rows


# ================================================================================================ 계산(순수 함수)
def mask_row(r: dict) -> dict:
    x = dict(r)
    for k in ("license_key", "key"):
        if k in x and x[k]:
            x[k] = U.mask_key(x[k])
    return x


def _expired(d: str | None) -> bool:
    n = _days(d)
    return n is not None and n < 0


def summarize(d: dict) -> dict:
    sup, csp, hosts, lics = d["supplier"], d["csp"], d["hosts"], d["licenses"]
    st = defaultdict(lambda: {"active": 0, "expired": 0})
    for x in sup:
        st[x["license_type"] or "(미상)"]["expired" if _expired(x["end_date"]) else "active"] += x["quantity"] or 0
    cu = defaultdict(lambda: {"active": 0, "expired": 0})
    for x in csp:
        cu[x["unit"] or "(미상)"]["expired" if _expired(x["end_date"]) else "active"] += x["quantity"] or 0
    cat = defaultdict(lambda: {"hosts": 0, "qty": 0, "cores": 0, "licensed_cores": 0, "sockets": 0})
    for h in hosts:
        c = cat[h["category"] if h.get("license_key") and h["license_key"] != U.EVAL_KEY else "unlicensed"]
        c["hosts"] += 1
        c["qty"] += h["qty"]
        c["cores"] += h.get("cores") or 0
        c["licensed_cores"] += h["licensed_cores"]
        c["sockets"] += h.get("sockets") or 0
    prods = defaultdict(int)
    for u in d["usage"]:
        for p in u["products"]:
            prods[f"{p['product']} ({p['uom']})"] += p["quantity"]
    return {"supplier": {"rows": len(sup), "by_type": dict(st), "vsphere_qty": sum(x["quantity"] or 0 for x in sup if U.is_vsphere(x["product"])),
                         "customers": len({x["customer"] for x in sup if x["customer"]})},
            "csp": {"rows": len(csp), "by_unit": dict(cu), "keys": len({x["license_key"] for x in csp}), "folders": len({x["folder"] for x in csp})},
            "inventory": {"hosts": len(hosts), "vcenters": len({h["vcenter"] for h in hosts}), "sources": len({h["source"] for h in hosts}),
                          "by_category": dict(cat), "licenses": len(lics)},
            "usage": {"reports": len(d["usage"]), "products": dict(prods)}}


def match(d: dict) -> dict:
    """실사용 키(호스트 할당 + vCenter/RVTools 라이선스 목록) ↔ CSP 키 — 매칭 · 실사용만 · CSP만, 수량 비교"""
    inv: dict[str, dict] = {}
    for h in d["hosts"]:
        k = (h.get("license_key") or "").strip()
        if not k or k == U.EVAL_KEY:
            continue
        e = inv.setdefault(k, {"qty": 0, "hosts": 0, "category": h["category"], "name": h.get("license_name") or "", "total": None, "used": None, "expires": None,
                               "sources": set()})
        e["qty"] += h["qty"]
        e["hosts"] += 1
        e["sources"].add(h["source_name"])
    for x in d["licenses"]:
        k = (x.get("key") or "").strip()
        if not k or k == U.EVAL_KEY:
            continue
        e = inv.setdefault(k, {"qty": 0, "hosts": 0, "category": x["category"], "name": x.get("name") or "", "total": None, "used": None, "expires": None,
                               "sources": set()})
        e["total"] = (e["total"] or 0) + (x.get("total") or 0)
        e["used"] = (e["used"] or 0) + (x.get("used") or 0)
        e["expires"] = x.get("expires") or e["expires"]
        e["name"] = e["name"] or x.get("name") or ""
        e["sources"].add(x["source_name"])
    cspm: dict[str, dict] = {}
    for x in d["csp"]:
        e = cspm.setdefault(x["license_key"], {"qty": 0, "units": set(), "product": x["product"], "end": x["end_date"], "folders": set()})
        e["qty"] += x["quantity"] or 0
        e["units"].add(x["unit"] or "-")
        e["folders"].add(x["folder"] or "")
        if x["end_date"] and (not e["end"] or x["end_date"] > e["end"]):
            e["end"] = x["end_date"]
    sup = {x["license_key"]: x for x in d["supplier"] if x["license_key"]}
    rows = []
    for k in sorted(set(inv) | set(cspm)):
        a, c = inv.get(k), cspm.get(k)
        status = "matched" if a and c else ("inventory_only" if a else "csp_only")
        used = (a["used"] if a and a["used"] is not None else (a["qty"] if a else 0))
        row = {"license_key": k, "status": status, "name": (a or {}).get("name") or (c or {}).get("product") or "", "category": (a or {}).get("category", ""),
               "inv_qty": a["qty"] if a else None, "inv_hosts": a["hosts"] if a else None, "vc_total": a["total"] if a else None, "vc_used": a["used"] if a else None,
               "expires": (a or {}).get("expires"), "csp_qty": c["qty"] if c else None, "csp_unit": (", ".join(sorted(c["units"])) if c else None),
               "csp_end": c["end"] if c else None, "csp_folders": sorted(c["folders"]) if c else [], "sources": sorted(a["sources"]) if a else [],
               "supplier": bool(k in sup)}
        row["over"] = bool(a and c and used and c["qty"] and used > c["qty"])
        rows.append(row)
    n = len(rows)
    mt = sum(1 for r in rows if r["status"] == "matched")
    return {"rows": rows, "stats": {"total": n, "matched": mt, "inventory_only": sum(1 for r in rows if r["status"] == "inventory_only"),
                                    "csp_only": sum(1 for r in rows if r["status"] == "csp_only"), "over": sum(1 for r in rows if r["over"]),
                                    "rate": round(mt / n * 100) if n and d["csp"] else None}}       # CSP 데이터가 없으면 매칭률 없음


def checks(d: dict, cfg: dict) -> list[dict]:
    out: list[dict] = []

    def add(cid, sev, entity, title, detail="", fix="", ref=""):
        out.append({"id": cid, "severity": sev, "entity": entity, "title": title, "detail": detail, "fix": fix, "ref": ref})
    warn = int(cfg.get("expiry_warn_days", 90))
    used_keys = defaultdict(list)
    for h in d["hosts"]:
        if h.get("license_key"):
            used_keys[h["license_key"]].append(h["host"])
    for x in d["licenses"]:
        k, n = x.get("key") or "", _days(x.get("expires"))
        ent = f"{x.get('name') or '-'} [{U.mask_key(k)}] · {x['source_name']}"
        if k == U.EVAL_KEY:
            continue
        if n is not None and n < 0 and (used_keys.get(k) or (x.get("used") or 0) > 0):
            add("LIC-01", "critical", ent, f"만료된 라이선스가 사용 중({-n}일 지남)", f"호스트 {len(used_keys.get(k, []))}대 · 사용 {x.get('used')}",
                "갱신 키(또는 VCF 9 솔루션 라이선스)로 교체")
        elif n is not None and 0 <= n <= warn and ((x.get("used") or 0) > 0 or used_keys.get(k)):
            add("LIC-02", "error" if n <= 30 else "warning", ent, f"{n}일 후 만료", f"만료일 {x['expires']} · 사용 {x.get('used')}/{x.get('total')}",
                "갱신·전환 일정 확인(Broadcom·공급자)")
        if (x.get("total") or 0) and (x.get("used") or 0) > x["total"]:
            add("LIC-03", "error", ent, f"할당 초과 {x['used']} > {x['total']}", x.get("cost_unit", ""), "추가 구매 또는 할당 정리")
    nolic = [h for h in d["hosts"] if not h.get("license_key") or h["license_key"] == U.EVAL_KEY]
    if nolic:
        add("LIC-04", "error", f"호스트 {len(nolic)}대", "라이선스 미할당(평가 모드)", ", ".join(h["host"] for h in nolic[:10]), "정식 키 할당")
    m = match(d)
    if d["csp"]:
        inv_only = [r for r in m["rows"] if r["status"] == "inventory_only" and (r["inv_hosts"] or r["vc_used"])]
        if inv_only:
            add("LIC-05", "warning", f"키 {len(inv_only)}개", "실사용 키가 CSP 데이터에 없음", ", ".join(f"{U.mask_key(r['license_key'])}({r['name']})" for r in inv_only[:8]),
                "CSP 'AllLicenseKeys' 최신 내보내기 업로드·프로젝트 할당 확인 — 계약 외 키일 수 있음")
        for r in m["rows"]:
            if r["over"]:
                add("LIC-06", "error", f"{r['name']} [{U.mask_key(r['license_key'])}]", "실사용이 CSP 수량 초과",
                    f"사용 {r['vc_used'] if r['vc_used'] is not None else r['inv_qty']} > CSP {r['csp_qty']} {r['csp_unit']}", "추가 구매·재할당")
    for x in d["csp"]:
        n = _days(x["end_date"])
        if n is not None and n < 0 and used_keys.get(x["license_key"]):
            add("LIC-07", "error", f"{x['product']} [{U.mask_key(x['license_key'])}]", "CSP 계약 종료 키가 호스트에 할당됨", f"계약 종료 {x['end_date']}", "갱신 키로 교체")
    under16 = [h for h in d["hosts"] if h["category"] == "term" and h["licensed_cores"] > (h.get("cores") or 0)]
    if under16:
        extra = sum(h["licensed_cores"] - (h.get("cores") or 0) for h in under16)
        add("LIC-08", "info", f"호스트 {len(under16)}대", f"CPU 당 16코어 최소 적용으로 +{extra}코어 과금", ", ".join(h["host"] for h in under16[:8]),
            "코어 단위 구독은 CPU 당 최소 16코어 — 저코어 CPU 서버는 통합 검토", KB["core16"])
    perp = [h for h in d["hosts"] if h["category"] == "perpetual"]
    if perp:
        add("LIC-09", "info", f"호스트 {len(perp)}대", "영구(CPU 단위) 라이선스 사용 중", ", ".join(sorted({h.get('license_name') or '' for h in perp}))[:200],
            "지원(SnS) 종료 여부와 VCF 9 구독 전환 계획 확인")
    lim = int(cfg.get("usage_report_days", 150))
    for u in d["usage"]:
        ts = u.get("usage_end") or u.get("timestamp")
        if ts and (time.time() - ts) / 86400 > lim:
            add("LIC-10", "warning", u["name"], f"사용량 보고 후 {int((time.time() - ts) / 86400)}일 경과",
                "VCF 9 라이선스는 약 180일마다 사용량 보고가 필요(롤링 유효 기간)", "VCF Operations 에서 사용량 보고(연결 모드) 또는 사용량 파일 제출(비연결 모드)", KB["usage"])
    for x in d["supplier"]:
        n = _days(x["end_date"])
        if n is not None and 0 <= n <= warn:
            add("LIC-11", "warning", f"{x['customer'] or '-'} · {x['product']} (S/N {x['serial']})", f"공급자 계약 {n}일 후 종료", f"종료 {x['end_date']} · 수량 {x['quantity']}",
                "공급자와 갱신 협의")
        st = (x["contract_status"] or "").lower()
        if st and st not in ("active", "활성") and not _expired(x["end_date"]) and x["license_key"] in used_keys:
            add("LIC-12", "warning", f"{x['product']} (S/N {x['serial']})", f"계약 상태 '{x['contract_status']}' 인 키가 사용 중", "", "공급자 확인")
    out.sort(key=lambda c: (SEV_ORDER.index(c["severity"]), c["id"]))
    return out


async def scheduler(mgr: LicenseManager, beat=lambda: None) -> None:
    await asyncio.sleep(180)
    while True:
        beat()
        try:
            hrs = (await mgr.settings())["schedule_hours"]
            if hrs > 0 and mgr.vcenters():
                st = await mgr.db()
                last = await st.q1("SELECT MIN(collected) AS t FROM lic_sources WHERE kind='vcenter'")
                n_src = (await st.q1("SELECT COUNT(*) AS c FROM lic_sources WHERE kind='vcenter'"))["c"]
                if n_src < len(mgr.vcenters()) or not last or not last["t"] or time.time() - last["t"] >= hrs * 3600:
                    await mgr.collect_vcenter(by="schedule")
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(900)

