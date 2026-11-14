"""클라우드 비용 비교(2.13.0) — 지금 쓰는 VCF 객체를 AWS·Azure·GCP 의 대응 서비스와 짝지어 월 비용을 비교

짝짓기(구성요소 매핑)
  · VM(vCPU·메모리·OS)        → EC2 / Azure VM / Compute Engine — 메모리:vCPU 비율로 계열(연산·범용·메모리) 선택 후 vCPU·메모리를 모두 만족하는 가장 작은 크기
  · VM 디스크(할당 GB)         → EBS gp3 / Premium SSD v2 / pd-balanced, 최대 IOPS 가 기본 제공(3,000)을 넘으면 추가 IOPS 단가가 있는 곳은 가산
  · VKS 클러스터               → EKS / AKS(Standard) / GKE 관리 요금(클러스터-시간), 워커 노드 VM 은 위 VM 으로, 컨트롤 플레인 VM 은 관리형으로 대체(클라우드 쪽 제외)
  · NSX ALB(Avi) 가상 서비스   → ALB / Application Gateway v2 / Cloud Load Balancing
  · ESXi·vSAN·NSX·vCenter·SDDC Manager·관리 VM(vCLS·NSX Edge·Avi SE·Supervisor 등) → 클라우드에서는 서비스 요금에 포함(별도 항목 없음),
    VCF 쪽은 플랫폼 원가로 업무 VM 에 배분
VCF 쪽 원가
  · TCO 모델: VCF 구독(코어당·연) × 라이선스 코어(CPU 당 최소 16코어 — Broadcom KB 313548) + 서버 감가상각 + 상면·전력 + 운영 인력 + 기타 → 월 비용을
    업무 VM 에 vCPU·메모리 가중치로 배분
  · 또는 정산(Billing) 기본 요율표(vCPU·메모리·디스크 시간 단가)
단가: app/assets/cloud_prices.json(공개 정가·출처·확인 여부) + 관리자 수정분(DB). Azure Retail Prices API·Google Cloud Billing Catalog API(키)로 갱신 가능.
확인하지 못한 단가는 '미입력'으로 두고 합계에서 빠진 항목을 표시한다 — 추정값을 채워 넣지 않는다.
IOPS: vCenter 실시간 성능(가상 디스크 읽기+쓰기 횟수/초)을 1시간마다 모아 VM 별 최소·평균·최대(기본 7일).
"""
from __future__ import annotations

import asyncio
import copy
import csv
import io
import json
import math
import re
import time
from pathlib import Path
from typing import Any

SCHEMA = """CREATE TABLE IF NOT EXISTS cc_iops(hour INTEGER, vc TEXT, vm TEXT, mn REAL, mx REAL, sm REAL, n INTEGER, PRIMARY KEY(hour, vc, vm));
CREATE INDEX IF NOT EXISTS ix_cc_iops_hour ON cc_iops(hour);
CREATE TABLE IF NOT EXISTS cc_doc(k TEXT PRIMARY KEY, v TEXT, ts REAL, by TEXT);"""
CATALOG = Path(__file__).parent / "assets" / "cloud_prices.json"
PROVIDERS = ("aws", "azure", "gcp")
MGMT_RX = re.compile(r"(?i)^(vcls|vCLS-)|SupervisorControlPlaneVM|^nsx-?(mgr|manager|edge|unified)|nsx[-_]?edge|^edge-?\d|^vcsa|^vcenter|vcf-?vc|sddc-?manager|"
                     r"^avi-?(se|controller)|^se-|vrops|vrli|vcf-?ops|aria-|^vcfa|^ops-|^opsfm|^fleet-")
SETTINGS_DEFAULT: dict[str, Any] = {
    "vcf_mode": "tco",                       # tco | rate | none
    "subscription_per_core_year": 0.0,       # VCF 구독 단가(코어당·연) — 계약 단가 입력
    "hw_per_host": 0.0, "amort_years": 5, "facility_per_host_year": 0.0, "ops_per_year": 0.0, "other_per_year": 0.0,
    "cpu_weight": 50,                        # 배분 가중치(vCPU %, 나머지 메모리)
    "currency": "USD", "fx_krw_per_usd": 0.0, "vcf_currency": "USD",
    "commit": "ondemand", "basis": "allocated", "include_off": False, "disk_basis": "provisioned", "iops_days": 7,
    "mgmt_patterns": [], "iops_baseline": 3000,
    # 2.27.0 Red Hat OpenShift(자체 운영, 같은 서버 재사용) 비교 · 여러 해 누적 TCO
    "os_mode": "auto",                       # auto | ove | oke | ocp | opp | none
    "os_support": "premium",                 # premium(24x7) | standard(8x5)
    "os_currency": "KRW",                    # KRW | USD | JPY — 아래 구독 단가의 통화
    "os_fx_krw_per_100jpy": 0.0,             # 엔화 단가를 쓸 때 원/100엔
    "os_price_ove": 0.0, "os_price_oke": 0.0, "os_price_ocp": 0.0, "os_price_opp": 0.0,   # Bare Metal Node(소켓 쌍) 1개·연 — 견적 단가
    "os_storage": "odf",                     # odf(vSAN 대체 HCI) | external(외부 스토리지)
    "os_odf_per_node_year": 0.0,             # ODF 단가(서버당·연, 위 통화) — Platform Plus 는 ODF Essentials 포함(클러스터당 256TB)
    "os_storage_per_year": 0.0,              # 외부 스토리지 연 비용(위 통화)
    "os_cp_nodes": 3,                        # 컨트롤 플레인 전용 서버(구독 제외, 서버·상면 비용만)
    "os_ops_delta_pct": 0.0,                 # 운영 인력 증감 %(전환 후 기술 스택 변화)
    "os_migration_once": 0.0,                # 전환 일회성 비용(컨설팅·이관·재교육, 위 통화)
    "cloud_migration_once": 0.0,             # 클라우드 전환 일회성 비용(USD)
    "tco_years": 5,                          # 누적 비교 기간(년)
}
OS_PRICES = Path(__file__).parent / "assets" / "openshift_prices.json"
OS_EDITIONS = {
    "ove": ("OpenShift Virtualization Engine", "VM 전용 — 사용자 컨테이너 앱은 포함 안 됨"),
    "oke": ("OpenShift Kubernetes Engine", "VM + 컨테이너(핵심 Kubernetes)"),
    "ocp": ("OpenShift Container Platform", "VM + 컨테이너 + 개발·서비스메시·서버리스 등"),
    "opp": ("OpenShift Platform Plus", "OCP + 다중 클러스터 관리(ACM)·보안(ACS)·레지스트리(Quay)·ODF Essentials(클러스터당 256TB)"),
}
CLASS = {1: "compute", 2: "compute", 4: "general", 8: "memory"}


def _class_of(vcpu: float, mem: float) -> str:
    r = (mem or 0) / max(1.0, vcpu or 1)
    return "compute" if r <= 3 else "general" if r <= 6 else "memory"


class CloudCost:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self._schema = False
        self.iops_interval = float(self.cfg.get("iops_interval", 3600))
        self.retention_days = float(self.cfg.get("iops_retention_days", 90))
        self.stats = {"iops_last": 0.0, "iops_vms": 0, "error": ""}

    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    # ------------------------------------------------------------------ 저장 문서(설정·단가 수정분)
    async def _doc(self, k: str, default: Any) -> Any:
        self._ensure()
        r = await self.e.store.q1("SELECT v FROM cc_doc WHERE k=?", (k,))
        try:
            return json.loads(r["v"]) if r and r.get("v") else copy.deepcopy(default)
        except (TypeError, ValueError):
            return copy.deepcopy(default)

    async def _put(self, k: str, v: Any, by: str = "") -> None:
        self._ensure()
        await self.e.store.x("INSERT INTO cc_doc(k,v,ts,by) VALUES(?,?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, ts=excluded.ts, by=excluded.by",
                             (k, json.dumps(v, ensure_ascii=False), time.time(), by))

    async def settings(self) -> dict[str, Any]:
        return {**SETTINGS_DEFAULT, **(await self._doc("settings", {}))}

    async def save_settings(self, p: dict, by: str = "") -> dict[str, Any]:
        cur = await self.settings()
        num = ("subscription_per_core_year", "hw_per_host", "amort_years", "facility_per_host_year", "ops_per_year", "other_per_year", "cpu_weight",
               "fx_krw_per_usd", "iops_days", "iops_baseline", "os_fx_krw_per_100jpy", "os_price_ove", "os_price_oke", "os_price_ocp", "os_price_opp",
               "os_odf_per_node_year", "os_storage_per_year", "os_cp_nodes", "os_ops_delta_pct", "os_migration_once", "cloud_migration_once", "tco_years")
        for k in SETTINGS_DEFAULT:
            if k not in p:
                continue
            v = p[k]
            if k in num:
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    raise ValueError(f"{k}: 숫자가 아닙니다") from None
                if not math.isfinite(v):
                    raise ValueError(f"{k}: 숫자가 아닙니다")
                v = max(-90.0, min(300.0, v)) if k == "os_ops_delta_pct" else max(0.0, v)
            cur[k] = v
        cur["cpu_weight"] = min(100.0, cur["cpu_weight"])
        cur["amort_years"] = max(1.0, cur["amort_years"])
        cur["iops_days"] = max(1.0, min(90.0, cur["iops_days"]))
        cur["tco_years"] = int(max(1.0, min(10.0, cur["tco_years"])))
        cur["os_cp_nodes"] = int(min(cur["os_cp_nodes"], 50))
        if cur["os_mode"] not in ("auto", "ove", "oke", "ocp", "opp", "none") or cur["os_support"] not in ("premium", "standard") \
                or cur["os_currency"] not in ("KRW", "USD", "JPY") or cur["os_storage"] not in ("odf", "external"):
            raise ValueError("OpenShift 선택 값 오류")
        if cur["vcf_mode"] not in ("tco", "rate", "none") or cur["commit"] not in ("ondemand", "1y", "3y") or cur["basis"] not in ("allocated", "rightsized") \
                or cur["currency"] not in ("USD", "KRW") or cur["vcf_currency"] not in ("USD", "KRW") or cur["disk_basis"] not in ("provisioned", "used"):
            raise ValueError("선택 값 오류")
        cur["mgmt_patterns"] = [str(x)[:120] for x in (cur.get("mgmt_patterns") or []) if str(x).strip()][:30]
        for x in cur["mgmt_patterns"]:
            re.compile(x)
        cur["include_off"] = bool(cur["include_off"])
        await self._put("settings", {k: cur[k] for k in SETTINGS_DEFAULT}, by)
        return cur

    # ------------------------------------------------------------------ 단가
    def base_catalog(self) -> dict[str, Any]:
        return json.loads(CATALOG.read_text(encoding="utf-8"))

    async def prices(self) -> dict[str, Any]:
        cat = self.base_catalog()
        ov = await self._doc("prices", {})
        for path, rec in ov.items():
            _set_path(cat["providers"], path, rec["value"], rec)
        cat["overrides"] = ov
        return cat

    async def save_prices(self, changes: dict[str, Any], by: str = "", source: str = "manual") -> dict[str, Any]:
        """changes: {'aws.compute.m7i.linux': 0.12, 'gcp.compute.n2-standard.vcpu_hour': 0.04, 'aws.storage.gb_month': 0.0912, 'aws.commit.1y': 30}"""
        cat = self.base_catalog()
        ov = await self._doc("prices", {})
        for path, val in changes.items():
            if val in ("", None):
                ov.pop(path, None)
                continue
            try:
                val = float(val)
            except (TypeError, ValueError):
                raise ValueError(f"{path}: 숫자가 아닙니다") from None
            if val < 0:
                raise ValueError(f"{path}: 음수 불가")
            _get_path(cat["providers"], path)         # 존재하는 항목만
            ov[path] = {"value": val, "by": by, "ts": time.time(), "source": source}
        await self._put("prices", ov, by)
        return await self.prices()

    async def reset_prices(self, by: str = "") -> None:
        await self._put("prices", {}, by)

    async def refresh_azure(self, by: str = "", region: str = "koreacentral", transport=None) -> dict[str, Any]:
        """Azure Retail Prices API(인증 없음) — 계열 기본 SKU·Premium SSD v2·AKS Standard·Application Gateway Standard v2"""
        import httpx
        cat = self.base_catalog()["providers"]["azure"]
        base = "https://prices.azure.com/api/retail/prices"
        ch: dict[str, float] = {}
        async with httpx.AsyncClient(timeout=30, transport=transport) as c:
            async def items(flt: str) -> list[dict]:
                out, url, params = [], base, {"$filter": flt}
                for _ in range(10):
                    r = await c.get(url, params=params)
                    r.raise_for_status()
                    j = r.json()
                    out += j.get("Items") or []
                    url, params = j.get("NextPageLink"), None
                    if not url:
                        break
                return out
            for f in cat["compute"]:
                sku = "Standard_" + f["sizes"][0][0]
                for it in await items(f"armRegionName eq '{region}' and armSkuName eq '{sku}'"):
                    name, prod = it.get("skuName", ""), it.get("productName", "")
                    if "Spot" in name or "Low Priority" in name:
                        continue
                    if it.get("type") == "Consumption":
                        ch[f"compute.{f['family']}.{'windows' if prod.endswith('Windows') else 'linux'}"] = float(it["retailPrice"])
                    elif it.get("type") == "Reservation" and not prod.endswith("Windows"):
                        ch[f"compute.{f['family']}.ri_{'1y' if it.get('reservationTerm') == '1 Year' else '3y'}_total"] = float(it["retailPrice"])
            for it in await items(f"armRegionName eq '{region}' and productName eq 'Azure Premium SSD v2'"):
                if it.get("meterName") == "Premium LRS Provisioned Capacity" and it.get("type") == "Consumption":
                    ch["storage.gb_month"] = round(float(it["retailPrice"]) * 730, 6)
            for it in await items(f"armRegionName eq '{region}' and productName eq 'Azure Kubernetes Service'"):
                if it.get("meterName") == "Standard Uptime SLA":
                    ch["k8s.cluster_hour"] = float(it["retailPrice"])
            for it in await items(f"armRegionName eq '{region}' and serviceName eq 'Application Gateway'"):
                if it.get("productName") == "Application Gateway Standard v2" and it.get("type") == "Consumption":
                    ch["lb.hour" if "Fixed" in it.get("meterName", "") else "lb.unit_hour"] = float(it["retailPrice"])
        if not ch:
            raise RuntimeError("Azure Retail Prices API 에서 값을 찾지 못했습니다")
        await self.save_prices({f"azure.{k}": v for k, v in ch.items()}, by, source=f"Azure Retail Prices API {region}")
        return {"provider": "azure", "updated": len(ch), "items": ch}

    async def refresh_gcp(self, api_key: str, by: str = "", region_desc: str = "Seoul", transport=None) -> dict[str, Any]:
        """Google Cloud Billing Catalog API(API 키 필요, 키는 저장하지 않음) — Compute Engine N2 코어·메모리·Balanced PD"""
        import httpx
        if not re.fullmatch(r"[A-Za-z0-9_\-]{20,80}", api_key or ""):
            raise ValueError("API 키 형식 오류")
        url = "https://cloudbilling.googleapis.com/v1/services/6F81-5844-456A/skus"
        found: dict[str, float] = {}
        async with httpx.AsyncClient(timeout=60, transport=transport, headers={"X-goog-api-key": api_key}) as c:   # 키는 헤더로(URL·접근 로그에 남지 않게)
            tok = ""
            for _ in range(60):
                r = await c.get(url, params={"currencyCode": "USD", "pageSize": 5000, **({"pageToken": tok} if tok else {})})
                r.raise_for_status()
                j = r.json()
                for s in j.get("skus") or []:
                    d = s.get("description", "")
                    if (s.get("category") or {}).get("usageType") != "OnDemand" or f"in {region_desc}" not in d:
                        continue
                    try:
                        tr = s["pricingInfo"][0]["pricingExpression"]["tieredRates"][-1]["unitPrice"]
                        price = int(tr.get("units") or 0) + int(tr.get("nanos") or 0) / 1e9
                        unit = s["pricingInfo"][0]["pricingExpression"].get("usageUnit", "")
                    except (KeyError, IndexError, ValueError):
                        continue
                    if re.match(r"^N2 Instance Core running in ", d):
                        found["vcpu_hour"] = price
                    elif re.match(r"^N2 Instance Ram running in ", d):
                        found["gb_hour"] = price
                    elif re.match(r"^Balanced PD Capacity in ", d):
                        found["pd"] = price * (730 if unit.endswith(".h") else 1)
                tok = j.get("nextPageToken") or ""
                if not tok or len(found) == 3:
                    break
        if "vcpu_hour" not in found or "gb_hour" not in found:
            raise RuntimeError(f"N2 코어·메모리 SKU({region_desc})를 찾지 못했습니다")
        ch = {}
        for fam in ("n2-standard", "n2-highcpu", "n2-highmem"):
            ch[f"gcp.compute.{fam}.vcpu_hour"] = found["vcpu_hour"]
            ch[f"gcp.compute.{fam}.gb_hour"] = found["gb_hour"]
        if "pd" in found:
            ch["gcp.storage.gb_month"] = round(found["pd"], 6)
        await self.save_prices(ch, by, source=f"Cloud Billing Catalog API ({region_desc})")
        return {"provider": "gcp", "updated": len(ch), "items": found}

    # ------------------------------------------------------------------ IOPS 수집
    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(60)
        last_purge = 0.0
        while True:
            beat()
            try:
                await self.collect_iops()
                if time.time() - last_purge > 86400:
                    last_purge = time.time()
                    await self.e.store.x("DELETE FROM cc_iops WHERE hour < ?", (int((time.time() - self.retention_days * 86400) // 3600),))
            except Exception as e:  # noqa: BLE001
                self.stats["error"] = f"{type(e).__name__}: {e}"[:200]
            await asyncio.sleep(self.iops_interval)

    async def collect_iops(self) -> int:
        self._ensure()
        hour = int(time.time() // 3600)
        rows = []
        for c in [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcenter" and hasattr(c, "collect_vm_iops")]:
            try:
                # 2.30.0 커넥터 전용 스레드 풀에서(기본 실행기·저장소 스레드를 붙잡지 않게), 이전 수집 스레드가 남아 있으면 건너뜀
                if getattr(c, "_thr_busy", None) is None:
                    run = asyncio.to_thread(c.collect_vm_iops)
                elif c._thr_busy.get("iops"):
                    continue
                else:
                    run = c._tx("iops", c.collect_vm_iops)
                res = await asyncio.wait_for(run, 300)
            except Exception as e:  # noqa: BLE001
                self.stats["error"] = f"{c.name}: {type(e).__name__}: {e}"[:200]
                continue
            for vm, v in res.items():
                rows.append((hour, c.name, vm, v["min"], v["max"], v["sum"], v["n"]))
        if rows:
            await self.e.store.xm("INSERT INTO cc_iops(hour,vc,vm,mn,mx,sm,n) VALUES(?,?,?,?,?,?,?) ON CONFLICT(hour,vc,vm) DO UPDATE SET "
                                  "mn=MIN(mn,excluded.mn), mx=MAX(mx,excluded.mx), sm=sm+excluded.sm, n=n+excluded.n", rows)
        self.stats.update(iops_last=time.time(), iops_vms=len(rows))
        return len(rows)

    async def iops(self, days: float = 7) -> dict[str, dict[str, Any]]:
        self._ensure()
        rows = await self.e.store.q("SELECT vm, MIN(mn) AS mn, MAX(mx) AS mx, SUM(sm) AS sm, SUM(n) AS n, COUNT(*) AS hours FROM cc_iops WHERE hour>=? GROUP BY vm",
                                    (int((time.time() - days * 86400) // 3600),))
        return {r["vm"]: {"min": round(r["mn"], 1), "max": round(r["mx"], 1), "avg": round(r["sm"] / r["n"], 1) if r["n"] else None, "hours": r["hours"]} for r in rows}

    # ------------------------------------------------------------------ 짝짓기
    @staticmethod
    def match(prov: dict, vcpu: float, mem: float, windows: bool, commit: str) -> dict[str, Any]:
        """vCPU·메모리를 모두 만족하는 가장 작은 크기. 계열은 메모리:vCPU 비율로, 맞는 크기가 없으면 다른 계열·최대 크기(초과 표시)"""
        want = _class_of(vcpu, mem)
        fams = prov.get("compute") or []
        order = sorted(fams, key=lambda f: (CLASS.get(f.get("ratio"), "general") != want, abs((f.get("ratio") or 4) - (mem / max(1.0, vcpu)))))
        pick, fam, over = None, None, False
        for f in order:
            for sz in f["sizes"]:
                if sz[1] >= vcpu and sz[2] >= mem:
                    pick, fam = sz, f
                    break
            if pick:
                break
        if not pick:
            fam = max(fams, key=lambda f: f["sizes"][-1][2]) if fams else None
            pick, over = (fam["sizes"][-1] if fam else None), True
        if not pick:
            return {"sku": None, "missing": "계열 없음"}
        sv, sm = pick[1], pick[2]
        if fam.get("per_vcpu"):
            if fam.get("vcpu_hour") is None or fam.get("gb_hour") is None:
                return {"sku": pick[0], "family": fam["family"], "vcpu": sv, "mem": sm, "hourly": None, "missing": "단가 미입력", "class": want, "over": over}
            hourly = sv * fam["vcpu_hour"] + sm * fam["gb_hour"]
            if windows:
                if fam.get("windows_core_hour") is None:
                    return {"sku": pick[0], "family": fam["family"], "vcpu": sv, "mem": sm, "hourly": None, "missing": "Windows 라이선스 단가 미입력", "class": want, "over": over}
                hourly += sv * fam["windows_core_hour"]
            lic = sv * (fam.get("windows_core_hour") or 0) if windows else 0.0
        else:
            k = sv / (fam.get("unit") or 2)
            base = fam.get("windows" if windows else "linux")
            if base is None:
                return {"sku": pick[0], "family": fam["family"], "vcpu": sv, "mem": sm, "hourly": None, "missing": "단가 미입력", "class": want, "over": over}
            hourly = base * k
            lic = (fam.get("windows", 0) - fam.get("linux", 0)) * k if windows and fam.get("windows") is not None and fam.get("linux") is not None else 0.0
        note = ""
        if commit in ("1y", "3y"):
            tot = fam.get(f"ri_{commit}_total")
            if tot and not fam.get("per_vcpu"):              # 예약 인스턴스 단가(컴퓨트) + Windows 라이선스는 종량
                hourly = tot / (8760 if commit == "1y" else 26280) * (sv / (fam.get("unit") or 2)) + lic
                note = f"RI {commit}"
            else:
                pct = (prov.get("commit") or {}).get(commit)
                if pct is None:
                    note = "약정 할인율 미입력 — 온디맨드"
                else:
                    hourly = (hourly - lic) * (1 - float(pct) / 100) + lic
                    note = f"약정 {commit} {float(pct):g}%"
        return {"sku": pick[0], "family": fam["family"], "vcpu": sv, "mem": sm, "hourly": hourly, "class": want, "over": over, "note": note,
                "verified": bool(fam.get("verified"))}

    # ------------------------------------------------------------------ 보고서
    def _vcenters(self) -> list:
        return [c for c in getattr(self.e, "connectors", []) if getattr(c, "type", "") == "vcenter" and isinstance(getattr(c, "topology", None), dict)]

    def _vks_cp_names(self) -> set[str]:
        out = set()
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") != "vks":
                continue
            for n in (getattr(c, "inv", {}) or {}).get("nodes") or []:
                if any(r in ("control-plane", "master") for r in n.get("roles") or []):
                    out.add(n.get("name", ""))
        return out

    async def report(self, opts: dict | None = None) -> dict[str, Any]:
        st = {**(await self.settings()), **{k: v for k, v in (opts or {}).items() if v not in (None, "")}}
        cat = await self.prices()
        H = float(cat.get("hours_per_month") or 730)
        fx = float(st.get("fx_krw_per_usd") or 0)
        commit, basis = st["commit"], st["basis"]
        mgmt_rx = [re.compile(x) for x in st.get("mgmt_patterns") or []]
        cp_names = self._vks_cp_names()
        iops = await self.iops(float(st["iops_days"]))
        rs = {}
        if basis == "rightsized" and getattr(self.e, "capacity", None):
            try:
                r = await self.e.capacity.rightsizing()
                for x in (r.get("oversized") or []) + (r.get("undersized") or []):
                    rs[x["vm"]] = (x.get("rec_vcpu") or x["vcpu"], x.get("rec_mem_gb") or x.get("mem_gb"))
            except Exception:  # noqa: BLE001
                rs = {}
        # 2.14.0 하드웨어 준비도(BMC 실측) — ESXi 이름으로 코어·소켓 보완, 재사용 판정
        rd: dict[str, dict] = {}
        if getattr(self.e, "readiness", None):
            try:
                for x in await self.e.readiness.latest_hosts():
                    ex = (x.get("esxi") or {}).get("esxi")
                    if ex and x.get("result"):
                        rd[ex] = x["result"]
            except Exception:  # noqa: BLE001
                rd = {}
        # 인벤토리
        vms, hosts = [], []
        for c in self._vcenters():
            t = c.topology
            snap = (getattr(c, "health_snap", {}) or {}).get("hosts", {})
            for hn, h in (t.get("hosts") or {}).items():
                hs = snap.get(hn, {})
                cores, sockets = int(hs.get("cores") or 0), int(hs.get("sockets") or 0)
                rr = rd.get(hn) or {}
                rc = (rr.get("summary") or {}).get("cpu") or {}
                if not cores and rc.get("cores"):
                    cores, sockets = int(rc["cores"]), int(rc.get("sockets") or 0)
                lic = (max(16, math.ceil(cores / sockets)) * sockets) if sockets else max(16, cores)
                hosts.append({"name": hn, "cluster": h.get("cluster", ""), "cores": cores, "sockets": sockets, "licensed_cores": lic, "known": bool(cores), "vcenter": c.name,
                              "readiness": rr.get("verdict"), "readiness_label": rr.get("verdict_label"), "cpu_tier": rc.get("label")})
            for vn, v in (t.get("vms") or {}).items():
                if v.get("template"):
                    continue
                on = v.get("power") == "poweredOn"
                if not on and not st["include_off"]:
                    continue
                cat_ = "workload"
                if vn in cp_names or re.search(r"-control-plane-|SupervisorControlPlaneVM", vn):
                    cat_ = "vks_cp" if vn in cp_names or "-control-plane-" in vn else "mgmt"
                elif MGMT_RX.search(vn) or any(r.search(vn) for r in mgmt_rx):
                    cat_ = "mgmt"
                disk = float((v.get("prov_gb") if st["disk_basis"] == "provisioned" else v.get("disk_gb")) or v.get("disk_gb") or 0)
                vms.append({"name": vn, "vcenter": c.name, "cluster": v.get("cluster", ""), "host": v.get("host", ""), "power": v.get("power", ""),
                            "os": v.get("os", ""), "windows": "windows" in str(v.get("os", "")).lower(), "vcpu": float(v.get("vcpu") or 0),
                            "mem_gb": round(float(v.get("mem_mb") or 0) / 1024, 2), "disk_gb": round(disk, 1), "category": cat_, "iops": iops.get(vn)})
        if st.get("cluster"):
            vms = [v for v in vms if v["cluster"] == st["cluster"]]
            hosts = [h for h in hosts if h["cluster"] == st["cluster"]]
        # VCF 원가
        vcf = await self._vcf_cost(st, hosts, vms, H, fx)
        # 클라우드
        provs = cat["providers"]
        totals = {p: {"compute": 0.0, "storage": 0.0, "iops": 0.0, "k8s": 0.0, "lb": 0.0, "missing": [], "unverified": set()} for p in PROVIDERS}
        for v in vms:
            v["vcf_monthly"] = vcf["per_vm"].get(v["name"])
            v["cloud"] = {}
            if v["category"] != "workload":
                continue
            cv, cm = rs.get(v["name"], (v["vcpu"], v["mem_gb"]))
            v["sized"] = {"vcpu": cv, "mem_gb": cm, "rightsized": v["name"] in rs}
            for p in PROVIDERS:
                pr = provs[p]
                m = self.match(pr, cv, cm, v["windows"], commit)
                stor = pr.get("storage") or {}
                sgb = stor.get("gb_month")
                storage = v["disk_gb"] * sgb if sgb is not None else None
                extra = 0.0
                mx = (v.get("iops") or {}).get("max") or 0
                if mx > st["iops_baseline"] and stor.get("iops_month") is not None:
                    extra = (mx - st["iops_baseline"]) * stor["iops_month"]
                comp = m["hourly"] * H if m.get("hourly") is not None else None
                v["cloud"][p] = {**{k: m.get(k) for k in ("sku", "family", "vcpu", "mem", "over", "note", "class", "missing")},
                                 "compute": _r(comp), "storage": _r(storage), "iops": _r(extra) if extra else 0.0,
                                 "monthly": _r((comp or 0) + (storage or 0) + extra) if comp is not None and storage is not None else None,
                                 "iops_over": bool(mx > st["iops_baseline"])}
                t = totals[p]
                if comp is None:
                    t["missing"].append(f"{v['name']}: {m.get('missing')}")
                else:
                    t["compute"] += comp
                if storage is None:
                    t["missing"].append("스토리지 단가 미입력")
                else:
                    t["storage"] += storage
                t["iops"] += extra
                if not m.get("verified", True):
                    t["unverified"].add("컴퓨트")
                if not stor.get("verified"):
                    t["unverified"].add("스토리지")
        # VKS 클러스터 → 관리형 Kubernetes
        k8s_rows = []
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") != "vks" or getattr(c, "role", "") == "supervisor":
                continue
            inv = getattr(c, "inv", {}) or {}
            row = {"name": getattr(c, "cluster_label", c.name), "nodes": len(inv.get("nodes") or []), "cloud": {}}
            for p in PROVIDERS:
                k = provs[p].get("k8s") or {}
                fee = k.get("cluster_hour") * H if k.get("cluster_hour") is not None else None
                row["cloud"][p] = {"sku": k.get("name"), "monthly": _r(fee)}
                if fee is None:
                    totals[p]["missing"].append("관리형 Kubernetes 단가 미입력")
                else:
                    totals[p]["k8s"] += fee
            k8s_rows.append(row)
        # Avi VS → 클라우드 L7 LB
        lb_rows = []
        for c in getattr(self.e, "connectors", []):
            if getattr(c, "type", "") != "avi":
                continue
            for vs in (getattr(c, "vs", None) or {}).values():
                row = {"name": vs.get("name", ""), "vips": vs.get("vips") or [], "state": vs.get("state", ""), "cloud": {}}
                for p in PROVIDERS:
                    lb = provs[p].get("lb") or {}
                    fee = (lb["hour"] + (lb.get("unit_hour") or 0) * (lb.get("units") or 1)) * H if lb.get("hour") is not None else None
                    row["cloud"][p] = {"sku": lb.get("name"), "monthly": _r(fee)}
                    if fee is None:
                        totals[p]["missing"].append("로드밸런서 단가 미입력")
                    else:
                        totals[p]["lb"] += fee
                        if not lb.get("verified"):
                            totals[p]["unverified"].add("로드밸런서")
                lb_rows.append(row)
        osr = self._openshift_cost(st, hosts, vms, k8s_rows, vcf, fx)
        for v in vms:
            v["os_monthly"] = osr["per_vm"].get(v["name"])
        out_tot = {}
        for p, t in totals.items():
            tot = t["compute"] + t["storage"] + t["iops"] + t["k8s"] + t["lb"]
            miss = sorted(set(t["missing"]))
            out_tot[p] = {"label": provs[p]["label"], "region": provs[p]["region"], "compute": _r(t["compute"]), "storage": _r(t["storage"]), "iops": _r(t["iops"]),
                          "k8s": _r(t["k8s"]), "lb": _r(t["lb"]), "total": _r(tot), "complete": not miss, "missing": miss[:20], "missing_count": len(miss),
                          "unverified": sorted(t["unverified"])}
        work = [v for v in vms if v["category"] == "workload"]
        mapping = _mapping(provs, len(work), sum(1 for v in vms if v["category"] == "mgmt"), sum(1 for v in vms if v["category"] == "vks_cp"),
                           len(k8s_rows), len(lb_rows), len(hosts), out_tot, vcf)
        cur = st["currency"]
        conv = (lambda x: x) if cur == "USD" else ((lambda x: None if x is None else round(x * fx, 0)) if fx else None)
        years = int(st.get("tco_years") or 5)
        tco = {"years": years, "rows": []}
        for key, label, mo, once, ok in ([("vcf", "VCF", vcf.get("monthly"), 0.0, vcf.get("monthly") is not None),
                                          ("openshift", "OpenShift", osr.get("monthly"), osr.get("once") or 0.0, osr.get("complete", False))]
                                         + [(p, out_tot[p]["label"], out_tot[p]["total"], float(st.get("cloud_migration_once") or 0), out_tot[p]["complete"]) for p in PROVIDERS]):
            tco["rows"].append({"key": key, "label": label, "monthly": mo, "once": _r(once),
                                "total": _r(mo * 12 * years + once) if mo is not None else None, "complete": bool(ok),
                                "by_year": [_r(mo * 12 * y + once) for y in range(1, years + 1)] if mo is not None else []})
        return {"settings": st, "currency": cur, "fx": fx, "convert_ok": conv is not None, "hours_per_month": H, "commit": commit, "basis": basis,
                "as_of": cat.get("as_of"), "vcf": {k: v for k, v in vcf.items() if k != "per_vm"}, "openshift": {k: v for k, v in osr.items() if k != "per_vm"},
                "tco": tco, "totals": out_tot, "vms": vms, "k8s": k8s_rows, "lb": lb_rows,
                "hosts": hosts, "mapping": mapping, "counts": {"workload": len(work), "mgmt": sum(1 for v in vms if v["category"] == "mgmt"),
                                                                "vks_cp": sum(1 for v in vms if v["category"] == "vks_cp"), "hosts": len(hosts)},
                "iops": {"vms": len(iops), "days": st["iops_days"], "last": self.stats["iops_last"] or None, "error": self.stats["error"]},
                "clusters": sorted({v["cluster"] for v in vms if v["cluster"]}), "generated": time.time(),
                "hardware": {"assessed": sum(1 for h in hosts if h.get("readiness")), "hosts": len(hosts),
                             "verdicts": {k: sum(1 for h in hosts if h.get("readiness") == k) for k in ("ready", "actions", "not_ready", "unknown")},
                             "refresh": [{"host": h["name"], "verdict": h["readiness_label"], "cpu": h.get("cpu_tier")} for h in hosts if h.get("readiness") == "not_ready"],
                             "note": "하드웨어 준비도(BMC 실측) 스캔 결과 — '불가' 호스트는 VCF 9 유지 시 교체 비용이 추가로 듭니다"}}

    @staticmethod
    def os_reference() -> dict[str, Any]:
        return json.loads(OS_PRICES.read_text(encoding="utf-8"))

    def _openshift_cost(self, st: dict, hosts: list[dict], vms: list[dict], k8s_rows: list, vcf: dict, fx: float) -> dict[str, Any]:
        """Red Hat OpenShift(자체 운영) — 같은 서버를 그대로 쓰고 하이퍼바이저·플랫폼만 바꾼다고 보고 월 비용을 계산(USD).
        구독 규칙(Red Hat Self-managed OpenShift subscription guide): Bare Metal 소켓 쌍 1개 = 1~2소켓·최대 128코어 서버 1대(쌓기 가능, 서버를 넘을 수 없음),
        컨트롤 플레인·인프라 전용 노드는 구독 제외, Virtualization Engine 은 소켓 쌍으로만·VM 무제한·사용자 컨테이너 불가·게스트 RHEL 미포함."""
        mode = st.get("os_mode") or "auto"
        if mode == "none":
            return {"mode": "none", "monthly": None, "per_vm": {}, "complete": False, "note": "OpenShift 비교 안 함"}
        containers = bool(k8s_rows)
        ed = mode if mode != "auto" else ("opp" if containers else "ove")
        auto_why = "" if mode != "auto" else ("VKS 워크로드 클러스터가 있어 컨테이너·다중 클러스터 관리가 되는 Platform Plus" if containers else "VM 만 있어 VM 전용 Virtualization Engine")
        cur = st.get("os_currency") or "KRW"
        missing: list[str] = []
        if cur == "USD":
            k = 1.0
        elif cur == "KRW":
            k = (1 / fx) if fx else None
            if k is None:
                missing.append("환율(원/달러) 미입력")
        else:
            j = float(st.get("os_fx_krw_per_100jpy") or 0)
            k = (j / 100 / fx) if (j and fx) else None
            if k is None:
                missing.append("환율(원/100엔·원/달러) 미입력")
        units = []
        unknown = 0
        for h in hosts:
            sk, co = int(h.get("sockets") or 0), int(h.get("cores") or 0)
            if not co:
                unknown += 1
            units.append(max(1, math.ceil(max(sk, 1) / 2), math.ceil(co / 128) if co else 1))
        n_units = sum(units)
        price = float(st.get(f"os_price_{ed}") or 0)
        if not price:
            missing.append(f"{OS_EDITIONS[ed][0]} 구독 단가 미입력")
        if ed == "ove" and containers:
            missing.append("Virtualization Engine 은 사용자 컨테이너를 포함하지 않음 — VKS 워크로드가 있으면 OKE·OCP·Platform Plus 를 고르세요")
        storage_y = 0.0
        storage_note = ""
        if st.get("os_storage") == "external":
            storage_y = float(st.get("os_storage_per_year") or 0)
            storage_note = "외부 스토리지(입력한 연 비용)"
        elif ed == "opp":
            storage_note = "ODF Essentials 포함(Platform Plus, 클러스터당 256TB까지 — 넘으면 ODF Advanced 추가 필요)"
        else:
            odf = float(st.get("os_odf_per_node_year") or 0)
            if not odf:
                missing.append("ODF(vSAN 대체 HCI 스토리지) 단가 미입력 — 또는 '외부 스토리지'를 고르세요")
            storage_y = odf * len(hosts)
            storage_note = f"ODF 서버 {len(hosts)}대 × 단가"
        cp = int(st.get("os_cp_nodes") or 0)
        sub_y = n_units * price
        once = float(st.get("os_migration_once") or 0)
        # 서버·상면·운영은 VCF 와 같은 원가 모델(같은 서버 재사용) + 컨트롤 플레인 서버 + 운영 인력 증감
        to_usd_vcf = 1.0 if st["vcf_currency"] == "USD" else ((1 / fx) if fx else None)
        if to_usd_vcf is None:
            missing.append("VCF 원가가 원화 — 환율(원/달러) 미입력")
        n_srv = len(hosts) + cp
        hw_y = n_srv * float(st["hw_per_host"]) / float(st["amort_years"] or 1)
        fac_y = n_srv * float(st["facility_per_host_year"])
        ops_y = float(st["ops_per_year"]) * (1 + float(st.get("os_ops_delta_pct") or 0) / 100)
        oth_y = float(st["other_per_year"])
        if not (st["hw_per_host"] or st["facility_per_host_year"] or st["ops_per_year"]):
            missing.append("서버·상면·운영 원가 미입력(원가·기준 설정의 VCF 원가 모델 값을 함께 씀)")
        info = {"mode": mode, "edition": ed, "edition_name": OS_EDITIONS[ed][0], "edition_desc": OS_EDITIONS[ed][1], "auto_why": auto_why,
                "support": st.get("os_support"), "units": n_units, "hosts": len(hosts), "hosts_unknown_cores": unknown, "cp_nodes": cp,
                "storage_note": storage_note, "currency": cur, "missing": missing, "complete": not missing}
        if k is None or to_usd_vcf is None:
            return {**info, "monthly": None, "per_vm": {}, "note": "환율 미입력 — 계산할 수 없습니다"}
        parts_y = {"subscription": sub_y * k, "storage": storage_y * k, "hardware": hw_y * to_usd_vcf, "facility": fac_y * to_usd_vcf,
                   "operations": ops_y * to_usd_vcf, "other": oth_y * to_usd_vcf}
        monthly = sum(parts_y.values()) / 12
        work = [v for v in vms if v["category"] == "workload"]
        sv = sum(v["vcpu"] for v in work) or 1.0
        smem = sum(v["mem_gb"] for v in work) or 1.0
        w = st["cpu_weight"] / 100
        per = {v["name"]: _r(monthly * (w * v["vcpu"] / sv + (1 - w) * v["mem_gb"] / smem)) for v in work}
        d = ((monthly - vcf["monthly"]) / vcf["monthly"] * 100) if vcf.get("monthly") else None
        return {**info, "monthly": _r(monthly), "per_vm": per, "once": _r(once * k), "parts": {x: _r(y / 12) for x, y in parts_y.items()},
                "vs_vcf_pct": _r(d) if d is not None and not missing else None,
                "note": f"{OS_EDITIONS[ed][0]} {'Premium' if st.get('os_support') == 'premium' else 'Standard'} · 소켓 쌍 구독 {n_units}개(서버 {len(hosts)}대)"
                        + (f" · 컨트롤 플레인 서버 {cp}대(구독 제외)" if cp else "") + (f" · 코어 수 미확인 {unknown}대는 1개로 계산" if unknown else ""),
                "mapping": [
                    {"vcf": "vSphere(ESXi·vCenter)", "os": "OpenShift Virtualization(KubeVirt) · 웹 콘솔", "note": "VM 이관은 Migration Toolkit for Virtualization"},
                    {"vcf": "vSAN", "os": "OpenShift Data Foundation(Ceph)" if st.get("os_storage") != "external" else "외부 스토리지(CSI)", "note": storage_note},
                    {"vcf": "NSX(분산 방화벽·오버레이)", "os": "OVN-Kubernetes · NetworkPolicy·AdminNetworkPolicy", "note": "분산 라우팅·Edge 서비스·IDS/IPS 는 기능이 다름"},
                    {"vcf": "VKS(Kubernetes)", "os": "OpenShift(컨테이너)" if ed != "ove" else "포함 안 됨(OVE)", "note": "OVE 는 사용자 컨테이너 불가"},
                    {"vcf": "VCF Operations·Automation", "os": "Advanced Cluster Management" if ed == "opp" else "별도(ACM 추가 구독)", "note": "Platform Plus 에 포함"},
                    {"vcf": "NSX ALB(Avi)", "os": "OpenShift Ingress(HAProxy 라우터)", "note": "L7 기능·GSLB 는 다름 — 필요 시 별도 제품"},
                    {"vcf": "게스트 OS", "os": "양쪽 모두 별도", "note": "OVE 는 RHEL 게스트 권한 미포함 — 비교에서 제외"},
                ]}

    async def _vcf_cost(self, st: dict, hosts: list[dict], vms: list[dict], H: float, fx: float) -> dict[str, Any]:
        """VCF 쪽 월 비용과 VM 별 배분(업무 VM 만 — 관리 VM·플랫폼 원가는 업무 VM 이 나눠 짐). 금액은 USD 로 환산(원화 입력은 환율 필요)"""
        work = [v for v in vms if v["category"] in ("workload",)]
        to_usd = 1.0 if st["vcf_currency"] == "USD" else ((1 / fx) if fx else None)
        if st["vcf_mode"] == "none":
            return {"mode": "none", "monthly": None, "per_vm": {}, "note": "VCF 원가 계산 안 함"}
        if st["vcf_mode"] == "rate":
            rate = None
            try:
                rates = await self.e.billing.rates()
                rate = next((r["current"] for r in rates if r["is_default"] and r.get("current")), None)
                cur = next((r.get("currency") for r in rates if r["is_default"]), "USD")
            except Exception:  # noqa: BLE001
                cur = "USD"
            if not rate:
                return {"mode": "rate", "monthly": None, "per_vm": {}, "note": "정산(Billing) 기본 요율표가 없습니다"}
            k = 1.0 if (cur or "USD").upper() == "USD" else ((1 / fx) if fx and (cur or "").upper() == "KRW" else None)
            if k is None:
                return {"mode": "rate", "monthly": None, "per_vm": {}, "note": f"요율표 통화 {cur} — 환율(원/달러)을 입력하세요"}
            per = {v["name"]: _r((v["vcpu"] * rate["vcpu_hour"] + v["mem_gb"] * rate["mem_gb_hour"] + v["disk_gb"] * rate["disk_gb_hour"]) * H * k) for v in work}
            return {"mode": "rate", "monthly": _r(sum(x for x in per.values() if x)), "per_vm": per, "note": f"정산 기본 요율표({cur}) × 730시간", "rate": rate}
        lic = sum(h["licensed_cores"] for h in hosts)
        unknown = sum(1 for h in hosts if not h["known"])
        annual = lic * st["subscription_per_core_year"] + len(hosts) * (st["hw_per_host"] / st["amort_years"] + st["facility_per_host_year"]) \
            + st["ops_per_year"] + st["other_per_year"]
        if not annual:
            return {"mode": "tco", "monthly": None, "per_vm": {}, "note": "VCF 원가 모델 값을 입력하세요(구독 단가·서버·상면·운영)", "licensed_cores": lic, "hosts": len(hosts)}
        if to_usd is None:
            return {"mode": "tco", "monthly": None, "per_vm": {}, "note": "원화로 입력한 원가 — 환율(원/달러)을 입력하세요", "licensed_cores": lic, "hosts": len(hosts)}
        monthly = annual / 12 * to_usd
        sv = sum(v["vcpu"] for v in work) or 1.0
        smem = sum(v["mem_gb"] for v in work) or 1.0
        w = st["cpu_weight"] / 100
        per = {v["name"]: _r(monthly * (w * v["vcpu"] / sv + (1 - w) * v["mem_gb"] / smem)) for v in work}
        return {"mode": "tco", "monthly": _r(monthly), "per_vm": per, "licensed_cores": lic, "hosts": len(hosts), "hosts_unknown_cores": unknown,
                "annual": _r(annual * to_usd), "parts": {"subscription": _r(lic * st["subscription_per_core_year"] / 12 * to_usd),
                                                        "hardware": _r(len(hosts) * st["hw_per_host"] / st["amort_years"] / 12 * to_usd),
                                                        "facility": _r(len(hosts) * st["facility_per_host_year"] / 12 * to_usd),
                                                        "operations": _r(st["ops_per_year"] / 12 * to_usd), "other": _r(st["other_per_year"] / 12 * to_usd)},
                "note": "라이선스 코어 = CPU 당 최소 16코어(Broadcom KB 313548)" + (f" · 코어 수 미확인 호스트 {unknown}대는 16코어로 계산" if unknown else "")}

    async def csv(self, opts: dict | None = None) -> str:
        r = await self.report(opts)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["vm", "cluster", "category", "os", "vcpu", "mem_gb", "disk_gb", "iops_min", "iops_avg", "iops_max", "vcf_monthly_usd", "openshift_monthly_usd"]
                   + [f"{p}_{k}" for p in PROVIDERS for k in ("sku", "compute", "storage", "iops", "monthly")])
        for v in r["vms"]:
            io_ = v.get("iops") or {}
            w.writerow([v["name"], v["cluster"], v["category"], v["os"], v["vcpu"], v["mem_gb"], v["disk_gb"], io_.get("min"), io_.get("avg"), io_.get("max"), v.get("vcf_monthly"), v.get("os_monthly")]
                       + [x for p in PROVIDERS for x in ((v["cloud"].get(p) or {}).get("sku"), (v["cloud"].get(p) or {}).get("compute"), (v["cloud"].get(p) or {}).get("storage"),
                                                         (v["cloud"].get(p) or {}).get("iops"), (v["cloud"].get(p) or {}).get("monthly"))])
        return "﻿" + buf.getvalue()


def _mapping(provs, n_work, n_mgmt, n_cp, n_k8s, n_lb, n_hosts, tot, vcf) -> list[dict[str, Any]]:
    """구성요소 매핑 표 — VCF 객체 종류 → 각 클라우드 서비스"""
    def svc(p, key, default=""):
        return (provs[p].get(key) or {}).get("name", default) if isinstance(provs[p].get(key), dict) else default
    fam = lambda p: " · ".join(f["family"] for f in provs[p].get("compute") or [])   # noqa: E731
    return [
        {"vcf": "업무 VM (vCPU·메모리·OS)", "count": n_work, "rule": "메모리:vCPU 비율 → 연산(≤3)·범용(≤6)·메모리 계열, vCPU·메모리를 모두 만족하는 가장 작은 크기",
         "aws": f"EC2 {fam('aws')}", "azure": f"Virtual Machines {fam('azure')}", "gcp": f"Compute Engine {fam('gcp')}", "key": "compute"},
        {"vcf": "VM 디스크(vSAN·VMFS)", "count": n_work, "rule": "할당 용량 GB × 블록 스토리지 단가, 최대 IOPS > 기본 제공 시 추가 IOPS 단가(있는 곳만)",
         "aws": svc("aws", "storage"), "azure": svc("azure", "storage"), "gcp": svc("gcp", "storage"), "key": "storage"},
        {"vcf": "VKS 워크로드 클러스터", "count": n_k8s, "rule": "클러스터당 관리 요금(워커 노드는 업무 VM 으로 계산)",
         "aws": svc("aws", "k8s"), "azure": svc("azure", "k8s"), "gcp": svc("gcp", "k8s"), "key": "k8s"},
        {"vcf": "VKS 컨트롤 플레인 VM", "count": n_cp, "rule": "클라우드는 관리형 컨트롤 플레인 — 위 관리 요금에 포함(별도 VM 없음)",
         "aws": "EKS 관리형", "azure": "AKS 관리형", "gcp": "GKE 관리형", "key": "included"},
        {"vcf": "NSX ALB(Avi) 가상 서비스", "count": n_lb, "rule": "가상 서비스당 L7 로드밸런서 1개(시간 요금 + 처리 단위 1)",
         "aws": svc("aws", "lb"), "azure": svc("azure", "lb"), "gcp": svc("gcp", "lb"), "key": "lb"},
        {"vcf": "관리 VM (vCenter·NSX Manager/Edge·SDDC Manager·vCLS·Avi SE·Supervisor 등)", "count": n_mgmt, "rule": "클라우드는 사업자가 운영 — 서비스 요금에 포함",
         "aws": "포함", "azure": "포함", "gcp": "포함", "key": "included"},
        {"vcf": "ESXi 호스트·vSAN·NSX·vSphere 라이선스", "count": n_hosts, "rule": "VCF 쪽 플랫폼 원가(구독·서버·상면·운영)로 업무 VM 에 배분 / 클라우드는 인스턴스 요금에 포함",
         "aws": "포함", "azure": "포함", "gcp": "포함", "key": "included"},
    ]


def _r(x):
    return None if x is None else round(float(x), 2)


def _split(path: str) -> list[str]:
    parts = path.split(".")
    if len(parts) >= 3 and parts[1] == "compute":     # aws.compute.m7i.linux / gcp.compute.n2-standard.vcpu_hour
        return parts[:2] + [".".join(parts[2:-1]), parts[-1]]
    return parts


def _get_path(provs: dict, path: str):
    p = _split(path)
    if p[0] not in PROVIDERS:
        raise ValueError(f"알 수 없는 항목: {path}")
    node = provs[p[0]]
    if p[1] == "compute":
        f = next((f for f in node["compute"] if f["family"] == p[2]), None)
        if not f or p[3] not in ("linux", "windows", "vcpu_hour", "gb_hour", "windows_core_hour", "ri_1y_total", "ri_3y_total"):
            raise ValueError(f"알 수 없는 항목: {path}")
        return f
    if p[1] in ("storage", "k8s", "lb", "commit") and len(p) == 3 and p[2] in ("gb_month", "iops_month", "cluster_hour", "hour", "unit_hour", "units", "1y", "3y"):
        return node[p[1]]
    raise ValueError(f"알 수 없는 항목: {path}")


def _set_path(provs: dict, path: str, value: float, rec: dict) -> None:
    try:
        obj = _get_path(provs, path)
    except ValueError:
        return
    key = _split(path)[-1]
    obj[key] = value
    obj.setdefault("edited", {})[key] = {"by": rec.get("by"), "ts": rec.get("ts"), "source": rec.get("source")}
    if key in ("linux", "vcpu_hour", "gb_hour", "gb_month", "cluster_hour", "hour"):
        obj["verified"] = True                         # 관리자 입력·공식 API 값 = 이 환경에서 확인된 단가
        obj["src"] = rec.get("source") or obj.get("src")
