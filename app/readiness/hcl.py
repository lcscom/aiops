"""vSAN HCL(Broadcom Compatibility Guide) 대조 — PCI quad(VID:DID:SVID:SSID) 정확 일치 → VID:DID → 모델 이름

데이터는 관리자가 명시적으로 넣을 때만 갖는다(자동 다운로드 없음):
  · 화면 '최신 HCL 받기' = 공개 JSON https://vvs.broadcom.com/service/vsan/all.json.gz (인터넷 가능한 경우)
  · 폐쇄망 = 같은 파일(.json·.json.gz)을 업로드
구조가 바뀌어도 견디도록 JSON 을 훑어 PCI ID·모델·vsanSupport·릴리스가 있는 항목을 모은다. 일치하지 않으면 '미등재'가 아니라 '대조 불가/미확인'으로 표시한다.
"""
from __future__ import annotations

import gzip
import json
import re
import time
from pathlib import Path
from typing import Any

HCL_URL = "https://vvs.broadcom.com/service/vsan/all.json.gz"
KEYS = {"vid": ("vendorId", "vid", "VID", "vendor_id"), "did": ("deviceId", "did", "DID", "device_id"),
        "svid": ("subVendorId", "svid", "SVID", "subvendorId", "subsystemVendorId"), "ssid": ("subDeviceId", "ssid", "SSID", "subdeviceId", "subsystemId")}


def _hx(v) -> str:
    s = str(v or "").strip().lower()
    s = s[2:] if s.startswith("0x") else s
    return s.zfill(4) if re.fullmatch(r"[0-9a-f]{1,4}", s) else ""


def _pick(d: dict, names) -> Any:
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return None


def _strings(o, depth=0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(o, str):
        return [o]
    if isinstance(o, dict):
        return [s for k, v in o.items() for s in ([str(k)] + _strings(v, depth + 1))]
    if isinstance(o, list):
        return [s for v in o[:200] for s in _strings(v, depth + 1)]
    return []


def _norm_model(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(s or "").upper())


class Hcl:
    def __init__(self, path: Path):
        self.path = path
        self.quads: dict[str, dict] = {}
        self.pairs: dict[str, list[dict]] = {}
        self.models: dict[str, dict] = {}
        self.meta: dict[str, Any] = {}
        self.loaded = False
        if path.exists():
            try:
                self.load_bytes(path.read_bytes(), save=False)
            except Exception:  # noqa: BLE001
                self.loaded = False

    def load_bytes(self, raw: bytes, save: bool = True, source: str = "upload") -> dict:
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        if len(raw) > 400 * 1024 * 1024:
            raise ValueError("파일이 너무 큽니다")
        data = json.loads(raw)
        entries = []
        self._walk(data, "", entries, 0)
        if not entries:
            raise ValueError("PCI ID·모델이 있는 HCL 항목을 찾지 못했습니다(vSAN HCL JSON 이 맞는지 확인)")
        self.quads, self.pairs, self.models = {}, {}, {}
        for e in entries:
            if e["vid"] and e["did"]:
                if e["svid"] and e["ssid"]:
                    self.quads.setdefault(f"{e['vid']}:{e['did']}:{e['svid']}:{e['ssid']}", e)
                self.pairs.setdefault(f"{e['vid']}:{e['did']}", []).append(e)
            if e["model"]:
                self.models.setdefault(_norm_model(e["model"]), e)
        upd = data.get("updatedTime") or data.get("timestamp") or (data.get("payload") or {}).get("updatedTime") if isinstance(data, dict) else None
        self.meta = {"entries": len(entries), "quads": len(self.quads), "models": len(self.models), "loaded": time.time(), "source": source,
                     "data_time": str(upd or ""), "esa": sum(1 for e in entries if e["esa"])}
        self.loaded = True
        if save:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(gzip.compress(json.dumps(data).encode()) if not str(self.path).endswith(".json") else json.dumps(data).encode())
        return self.meta

    def _walk(self, o, cat: str, out: list, depth: int) -> None:
        if depth > 8 or len(out) > 400000:
            return
        if isinstance(o, list):
            for v in o:
                self._walk(v, cat, out, depth + 1)
            return
        if not isinstance(o, dict):
            return
        vid, did = _hx(_pick(o, KEYS["vid"])), _hx(_pick(o, KEYS["did"]))
        model = _pick(o, ("model", "Model", "productName", "name"))
        if (vid and did) or (model and any(k in o for k in ("vsanSupport", "tier", "usedFor", "releases", "supportedReleases", "partNumber"))):
            txt = " ".join(_strings({k: o.get(k) for k in ("vsanSupport", "tier", "usedFor", "mode", "type")})).upper()
            rel = " ".join(_strings(o.get("releases") or o.get("supportedReleases") or ""))
            out.append({"cat": cat, "vid": vid, "did": did, "svid": _hx(_pick(o, KEYS["svid"])), "ssid": _hx(_pick(o, KEYS["ssid"])),
                        "model": str(model or "")[:120], "partner": str(_pick(o, ("partner", "vendor", "brand", "manufacturer")) or "")[:60],
                        "id": str(_pick(o, ("id", "productId")) or ""), "esa": "ESA" in txt, "cyber": "CYBER" in txt,
                        "osa": bool(re.search(r"AF-CACHE|AF-CAP|HY-CACHE|HY-CAP|OSA", txt)),
                        "rel91": bool(re.search(r"9\.1", rel)), "rel90": bool(re.search(r"9\.0", rel)), "tier": txt[:80]})
            return
        for k, v in o.items():
            if isinstance(v, (list, dict)):
                self._walk(v, k if k in ("ssd", "hdd", "controller", "nic", "drives", "io") else cat, out, depth + 1)

    def _verdict(self, e: dict, how: str) -> dict:
        return {"how": how, "model": e["model"], "partner": e["partner"], "esa": e["esa"] or e["cyber"], "osa": e["osa"], "rel91": e["rel91"], "rel90": e["rel90"],
                "tier": e["tier"], "link": f"https://compatibilityguide.broadcom.com/detail?program=vsanio&productId={e['id']}&persona=live" if e["id"] else ""}

    def match_pci(self, vid: str, did: str, svid: str = "", ssid: str = "", model: str = "") -> dict | None:
        if not self.loaded:
            return None
        if vid and did and svid and ssid:
            e = self.quads.get(f"{vid}:{did}:{svid}:{ssid}")
            if e:
                return self._verdict(e, "PCI quad 일치")
        if vid and did and f"{vid}:{did}" in self.pairs:
            r = self._verdict(self.pairs[f"{vid}:{did}"][0], "VID:DID 만 일치(SSID 불일치 — 확인 필요)")
            r["partial"] = True
            return r
        if model:
            nm = _norm_model(model)
            e = self.models.get(nm) or next((v for k, v in self.models.items() if len(k) >= 8 and (k in nm or nm in k)), None)
            if e:
                r = self._verdict(e, "모델 이름 일치")
                r["partial"] = True
                return r
        return {"how": "미일치", "esa": False, "osa": False, "missing": True}

    def match_drive(self, d: dict) -> dict | None:
        return self.match_pci(d.get("vid", ""), d.get("did", ""), d.get("svid", ""), d.get("ssid", ""), d.get("model", ""))
