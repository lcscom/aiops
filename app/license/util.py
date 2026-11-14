"""라이선스 관리(2.16.0) — 파일 파싱·키 가림·비용 단위 분류·VCF Operations 사용량 파일 해석

설계 참고: postout7979/VCF-Lic-MGMT(MIT, Copyright (c) 2026 postout7979) — 공급자·CSP 엑셀 열 이름, CSP 'Quantity'(“1432 Core”) 분해,
vCenter costUnit(cpuPackage = Perpetual·CPU 단위) 구분, VCF Operations 사용량 보고서(gzip → JWS → jws_child_asset_usages) 해석 방식.
이 제품 구조(표준 라이브러리 xlsx 판독기·SQLite·RBAC)에 맞게 새로 작성했다.
"""
from __future__ import annotations

import base64
import gzip
import json
import re
from datetime import date, datetime
from typing import Any

from ..rvtools import xlsx as X

# 공급자(총판·리셀러) 라이선스 엑셀 — 열 이름이 정확히 일치해야 함(VCF-Lic-MGMT 와 같은 머리글)
SUPPLIER_COLS = {"Serial Number": "serial", "Parent Customer": "parent_customer", "Customer Name": "customer", "License Key": "license_key",
                 "License Type": "license_type", "Product Name": "product", "Quantity - ENT": "quantity", "Contract Status": "contract_status",
                 "Start Date": "start_date", "End Date": "end_date", "ERP Site ID": "erp_site_id", "Enduser Account Name": "enduser",
                 "Part Number": "part_number", "Division": "division"}
SUPPLIER_REQUIRED = {"Serial Number", "License Key", "Product Name", "Quantity - ENT"}
# Broadcom Support Portal 'AllLicenseKeys' 내보내기
CSP_COLS = {"License Key": "license_key", "Product Name": "product", "Quantity": "quantity", "Folder Name": "folder", "Contract End Date": "end_date"}
CSP_REQUIRED = {"License Key", "Product Name", "Quantity"}
DATE_FMTS = ("%m/%d/%y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%y", "%m/%d/%Y", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%d-%b-%Y")
KEY_RX = re.compile(r"^[0-9A-Z]{5}(-[0-9A-Z]{5}){4}$")
EVAL_KEY = "00000-00000-00000-00000-00000"


def mask_key(k: str | None) -> str:
    """5x5 키는 마지막 묶음만 보이게(*****-*****-*****-*****-AB12C), 그 밖은 앞 3·뒤 4자"""
    k = str(k or "").strip()
    if not k:
        return ""
    if KEY_RX.match(k.upper()):
        return "*****-*****-*****-*****-" + k[-5:]
    return k if len(k) <= 8 else k[:3] + "…" + k[-4:]


def to_date(v: Any) -> str | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.date().isoformat()
    if isinstance(v, date):
        return v.isoformat()
    t = str(v).strip()
    if t.lower() in ("never", "perpetual", "n/a", "-"):
        return None
    for f in DATE_FMTS:
        try:
            return datetime.strptime(t, f).date().isoformat()
        except ValueError:
            continue
    return None


def to_int(v: Any) -> int:
    if v is None or v == "":
        return 0
    try:
        return int(float(str(v).replace(",", "").strip()))
    except ValueError:
        return 0


def split_qty(v: Any) -> tuple[int, str]:
    """CSP 'Quantity' — '1432 Core' · '48 Instance' · '32 TiB' → (수량, 단위)"""
    t = str(v if v is not None else "").strip()
    m = re.match(r"^([\d,\.]+)\s*(.*)$", t)
    if not m:
        return 0, t
    return to_int(m.group(1)), m.group(2).strip()


def s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def category(cost_unit: str | None, expires: str | None = None) -> str:
    """vCenter costUnit → perpetual(CPU 단위) · term(코어 단위 구독) · other(server·vm·instance 등)
    RVTools 는 'cpuPackage:32core'·'cpuCore:16core' 처럼 뒤에 한도를 붙인다."""
    u = str(cost_unit or "").lower()
    if u.startswith("cpupackage"):
        return "perpetual"
    if u.startswith("cpucore") or u == "core":
        return "term"
    return "other"


def licensed_cores(sockets: int | None, cores: int | None) -> int:
    """코어 단위 구독 — CPU 당 최소 16코어(Broadcom KB 313548): Σ max(16, CPU 당 코어)"""
    sk, co = int(sockets or 0), int(cores or 0)
    if sk <= 0:
        return max(16, co) if co else 0
    per = -(-co // sk) if co else 0
    return sk * max(16, per)


def is_vsphere(product: str | None) -> bool:
    p = str(product or "").strip().lower()
    return p.startswith(("vmware vsphere", "vsphere"))


def is_vcf(name: str | None) -> bool:
    p = str(name or "").strip().lower()
    return p.startswith(("vmware cloud foundation", "vcf ", "vmware vsphere foundation"))


def _sheet_with(raw: bytes, required: set[str]) -> list[dict]:
    sh = X.read(raw)
    for _, rows in sh.items():
        if rows and required <= set(rows[0].keys()):
            return rows
    # 머리글이 1행이 아닌 내보내기(제목 줄) — 앞 10행 안에서 머리글 찾기
    for _, rows in sh.items():
        for i, r in enumerate(rows[:10]):
            vals = {s(v) for v in r.values()}
            if required <= vals:
                hdr = [s(v) for v in r.values()]
                return [{hdr[j]: v for j, v in enumerate(x.values()) if j < len(hdr)} for x in rows[i + 1:]]
    raise ValueError(f"필수 열이 없습니다: {', '.join(sorted(required))} — 첫 행(또는 상단 10행)에 열 이름이 정확히 있어야 합니다")


def parse_supplier(raw: bytes) -> tuple[list[dict], list[str]]:
    rows = _sheet_with(raw, SUPPLIER_REQUIRED)
    out, errs = [], []
    for i, r in enumerate(rows, 2):
        serial = s(r.get("Serial Number"))
        if not serial:
            errs.append(f"{i}행: Serial Number 없음 — 건너뜀")
            continue
        x = {v: s(r.get(k)) for k, v in SUPPLIER_COLS.items()}
        x["quantity"] = to_int(r.get("Quantity - ENT"))
        x["start_date"], x["end_date"] = to_date(r.get("Start Date")), to_date(r.get("End Date"))
        x["license_type"] = x["license_type"].upper()
        out.append(x)
    return out, errs


def parse_csp(raw: bytes) -> tuple[list[dict], list[str]]:
    rows = _sheet_with(raw, CSP_REQUIRED)
    out, errs = [], []
    for i, r in enumerate(rows, 2):
        key = s(r.get("License Key"))
        if not key:
            errs.append(f"{i}행: License Key 없음 — 건너뜀")
            continue
        q, unit = split_qty(r.get("Quantity"))
        out.append({"license_key": key, "product": s(r.get("Product Name")), "quantity": q, "unit": unit, "folder": s(r.get("Folder Name")),
                    "end_date": to_date(r.get("Contract End Date"))})
    return out, errs


# ------------------------------------------------------------------------------------------- VCF Operations 사용량 파일
def _jws_payload(compact: str) -> dict:
    """compact JWS 의 payload(서명 검증 안 함 — 신뢰하는 내부 시스템이 만든 사용량 파일을 읽기만 함)"""
    parts = compact.strip().split(".")
    if len(parts) < 2:
        raise ValueError("JWS 형식이 아닙니다")
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def parse_usage(raw: bytes) -> dict:
    """VCF Operations 9.x 사용량 보고서 → {products:[{product, uom, quantity, assets}], assets, timestamp, generated}
    입력: ① suite-api 응답 JSON {"gzipJwsEncodedData": base64, "fileName", "timestamp"} ② 그 base64 를 푼 gzip 파일 ③ gzip 을 푼 JWS 텍스트.
    보고서 안의 jws_child_asset_usages(자산별 JWS) → license_usage_data 의 (asset_id, allocation_id)별 최신 usage_end_time 값만 합산."""
    meta: dict[str, Any] = {}
    data = raw
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("사용량 파일이 너무 큽니다")
    txt = None
    if raw[:2] == b"\x1f\x8b":
        data = gzip.decompress(raw)
    else:
        try:
            j = json.loads(raw.decode("utf-8"))
            if isinstance(j, dict) and j.get("gzipJwsEncodedData"):
                meta = {"file": j.get("fileName"), "timestamp": j.get("timestamp")}
                data = gzip.decompress(base64.b64decode(j["gzipJwsEncodedData"]))
            elif isinstance(j, dict) and "jws_child_asset_usages" in j:
                return _usage_from_report(j, meta)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    if len(data) > 256 * 1024 * 1024:
        raise ValueError("압축 해제 크기가 너무 큽니다")
    txt = data.decode("utf-8", "replace").strip()
    if txt.startswith("{"):
        j = json.loads(txt)
        return _usage_from_report(j if "jws_child_asset_usages" in j else _jws_payload(j.get("jws", "")), meta)
    return _usage_from_report(_jws_payload(txt), meta)


def _usage_from_report(rep: dict, meta: dict) -> dict:
    latest: dict[tuple, dict] = {}
    assets: dict[str, dict] = {}
    for child in rep.get("jws_child_asset_usages") or []:
        a = _jws_payload(child) if isinstance(child, str) else child
        aid = str(a.get("asset_id") or "")
        assets.setdefault(aid, {"asset_id": aid, "type": a.get("asset_type") or a.get("type") or "", "name": a.get("asset_name") or a.get("name") or ""})
        for e in a.get("license_usage_data") or []:
            k = (aid, str(e.get("allocation_id")))
            if k not in latest or (e.get("usage_end_time") or 0) > (latest[k].get("usage_end_time") or 0):
                latest[k] = dict(e, asset_id=aid)
    prod: dict[tuple, dict] = {}
    last_end = 0
    for e in latest.values():
        k = (str(e.get("product_name") or ""), str(e.get("uom") or ""))
        p = prod.setdefault(k, {"product": k[0], "uom": k[1], "quantity": 0, "assets": set()})
        p["quantity"] += to_int(e.get("quantity"))
        p["assets"].add(e["asset_id"])
        last_end = max(last_end, int(e.get("usage_end_time") or 0))
    ts = meta.get("timestamp") or rep.get("timestamp") or rep.get("report_generated_time") or last_end
    ts = float(ts) / 1000 if ts and float(ts) > 1e11 else (float(ts) if ts else None)
    return {"products": sorted(({**p, "assets": len(p["assets"])} for p in prod.values()), key=lambda x: (-x["quantity"], x["product"])),
            "assets": len(assets), "allocations": len(latest), "timestamp": ts, "file": meta.get("file") or "",
            "usage_end": (last_end / 1000 if last_end > 1e11 else last_end) or None}
