"""준비도 보고서 내보내기 — 자체 포함 HTML(플릿+호스트), Excel(.xlsx, 표준 라이브러리 OpenXML), CSV 묶음(.zip), JSON, 가명화 사본

가명화(obfuscate): 시리얼·UUID·MAC·IP·호스트/BMC 이름·LLDP 스위치 이름·포트·섀시 ID·계정 이름을 내보내기마다 새 솔트로 같은 값→같은 토큰 치환.
대응표(실제↔토큰)는 묶음 안 별도 파일로만 넣고(선택), 공유용 파일에는 넣지 않는다. 자유 문장(SEL 메시지)의 IP·MAC·시리얼도 치환.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import secrets
import time
import zipfile
from typing import Any
from xml.sax.saxutils import escape as xesc

ST_KO = {"pass": "통과", "fail": "실패", "warn": "주의", "unknown": "확인 불가", "info": "참고", "drift": "편차"}
VS_KO = {"esa_ready": "ESA 준비", "esa_actions": "ESA 조치 필요", "esa_network": "ESA 네트워크 부족", "osa_only": "OSA 만", "not_supported": "ESA 불가(RAID 뒤 NVMe)", "no_vsan": "vSAN 장치 없음"}
AREA_KO = {"cpu": "CPU", "memory": "메모리", "storage": "스토리지", "vsan": "vSAN", "network": "네트워크", "platform": "플랫폼", "bios": "BIOS", "events": "이벤트"}
ST_COL = {"pass": "#2e7d32", "fail": "#c21d00", "warn": "#b26a00", "unknown": "#6b7780", "info": "#0072a3", "drift": "#b26a00"}
V_COL = {"ready": "#2e7d32", "actions": "#b26a00", "not_ready": "#c21d00", "unknown": "#6b7780"}
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RX = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")


class Obf:
    def __init__(self):
        self.salt = secrets.token_hex(8)
        self.map: dict[str, str] = {}

    def tok(self, v: Any, prefix: str) -> Any:
        if v in (None, "") or not isinstance(v, str):
            return v
        k = f"{prefix}:{v}"
        if k not in self.map:
            hx = hashlib.sha256(f"{self.salt}:{v}".encode()).hexdigest()
            if prefix == "IP":
                self.map[k] = f"192.0.2.{int(hx[:4], 16) % 254 + 1}"
            elif prefix == "MAC":
                self.map[k] = "02:" + ":".join(hx[i:i + 2] for i in range(0, 10, 2))
            else:
                self.map[k] = f"{prefix}-{hx[:6].upper()}"
        return self.map[k]

    def text(self, s: Any) -> Any:
        if not isinstance(s, str):
            return s
        s = IP_RX.sub(lambda m: self.tok(m.group(0), "IP"), s)
        s = MAC_RX.sub(lambda m: self.tok(m.group(0).lower(), "MAC"), s)
        for k, v in list(self.map.items()):
            pfx, _, real = k.partition(":")
            if pfx in ("SN", "HOST", "SW") and len(real) >= 5:
                s = s.replace(real, v)
        return s

    def host_rec(self, rec: dict, i: int) -> dict:
        r = json.loads(json.dumps(rec, default=str))
        alias = f"Host-{i:02d}"
        self.map[f"HOST:{rec.get('target')}"] = alias
        self.map[f"HOST:{rec.get('label')}"] = alias
        r["target"] = r["label"] = alias
        h = r.get("host") or {}
        s = h.get("system") or {}
        for k, p in (("serial", "SN"), ("uuid", "UUID"), ("sku", "SKU"), ("hostname", "HOST")):
            if s.get(k):
                s[k] = self.tok(s[k], p)
        for c in h.get("chassis") or []:
            c["serial"] = self.tok(c.get("serial"), "SN")
        for d in (h.get("storage") or {}).get("drives") or []:
            d["serial"] = self.tok(d.get("serial"), "SN")
        for p in h.get("nics") or []:
            p["mac"] = self.tok(str(p.get("mac") or "").lower(), "MAC")
            l = p.get("lldp") or {}
            for k, pf in (("system_name", "SW"), ("chassis_id", "MAC"), ("port_id", "PORT"), ("mgmt_ip", "IP")):
                if l.get(k):
                    l[k] = self.tok(str(l[k]).lower() if pf == "MAC" else l[k], pf)
        b = h.get("bmc") or {}
        for a in b.get("accounts") or []:
            a["user"] = self.tok(a.get("user"), "USER")
        b["ntp_servers"] = [self.tok(x, "IP" if IP_RX.fullmatch(x) else "NTP") for x in b.get("ntp_servers") or []]
        for i2 in b.get("ifaces") or []:
            i2["mac"] = self.tok(str(i2.get("mac") or "").lower(), "MAC")
            i2["ipv4"] = [self.tok(x, "IP") for x in i2.get("ipv4") or []]
        for c in b.get("certificates") or []:
            c["subject"] = self.tok(c.get("subject"), "CN")
        for e in h.get("sel") or []:
            e["message"] = self.text(e.get("message"))
        res = r.get("result") or {}
        sm = res.get("summary") or {}
        for k, p in (("serial", "SN"), ("uuid", "UUID"), ("hostname", "HOST")):
            if sm.get(k):
                sm[k] = self.tok(sm[k], p)
        if (sm.get("network") or {}).get("switches"):
            sm["network"]["switches"] = [self.tok(x, "SW") for x in sm["network"]["switches"]]
        for c in res.get("checks") or []:
            c["detail"] = self.text(c.get("detail"))
            c.pop("evidence", None)
        for c in (res.get("security") or {}).get("rows") or []:
            c["observed"] = self.text(c.get("observed"))
        if r.get("esxi"):
            r["esxi"] = {**r["esxi"], "esxi": self.tok(r["esxi"].get("esxi"), "HOST"), "vcenter": self.tok(r["esxi"].get("vcenter"), "VC")}
        return r

    def fleet(self, fl: dict) -> dict:
        f = json.loads(json.dumps(fl or {}, default=str))
        def hn(x):
            return self.map.get(f"HOST:{x}", self.tok(x, "HOST"))
        t = f.get("tor") or {}
        for s in t.get("switches") or []:
            s["name"] = self.tok(s["name"], "SW")
            s["hosts"] = [hn(x) for x in s["hosts"]]
        for p in t.get("pairs") or []:
            p["a"], p["b"] = self.tok(p["a"], "SW"), self.tok(p["b"], "SW")
            for k in ("dual", "only_a", "only_b"):
                p[k] = [hn(x) for x in p.get(k) or []]
        for h in t.get("hosts") or []:
            h["host"] = hn(h["host"])
            h["switches"] = {self.tok(k, "SW"): v for k, v in (h.get("switches") or {}).items()}
        for l in t.get("links") or []:
            l["host"], l["switch"], l["port"], l["mgmt_ip"] = hn(l["host"]), self.tok(l["switch"], "SW"), self.tok(l.get("port"), "PORT"), self.tok(l.get("mgmt_ip"), "IP")
        for d in f.get("drift") or []:
            for v in d.get("values") or []:
                v["hosts"] = [hn(x) for x in v.get("hosts") or []]
                v["value"] = self.text(v.get("value"))
        return f


# ------------------------------------------------------------------------------------------ 행 데이터(CSV·Excel 공통)
def rows_summary(recs: list[dict]) -> list[list]:
    hdr = ["대상", "ESXi", "판정", "제조사", "모델", "시리얼", "BIOS", "BMC 펌웨어", "CPU", "CPU 등급", "소켓", "코어", "메모리 GB", "DIMM/슬롯", "직결 NVMe", "NVMe TB",
           "vSAN", "NIC 최대 Gb(연결)", "ToR 스위치", "TPM", "Secure Boot", "부팅", "BIOS 기준선 %", "BMC 보안 %", "실패", "주의", "확인 불가"]
    out = [hdr]
    for r in recs:
        if not r.get("ok"):
            out.append([r.get("label") or r["target"], "", "스캔 실패: " + str(r.get("error") or "")] + [""] * (len(hdr) - 3))
            continue
        res, h = r["result"], r["host"]
        sm = res["summary"]
        ck = {c["id"]: c for c in res["checks"]}
        out.append([r.get("label") or r["target"], (r.get("esxi") or {}).get("esxi", ""), res["verdict_label"], sm.get("vendor"), sm.get("model"), sm.get("serial"), sm.get("bios"),
                    sm.get("bmc_fw"), sm["cpu"].get("model"), sm["cpu"].get("label"), sm["cpu"].get("sockets"), sm["cpu"].get("cores"), sm["memory"].get("total_gib"),
                    f"{sm['memory'].get('dimms', '')}/{sm['memory'].get('slots', '')}", sm["storage"].get("direct_nvme"), sm["storage"].get("nvme_tb"),
                    VS_KO.get(sm["storage"].get("verdict"), sm["storage"].get("verdict")), sm["network"].get("max_up_gbps"), ", ".join(sm["network"].get("switches") or []),
                    ST_KO.get((ck.get("tpm") or {}).get("status"), ""), ST_KO.get((ck.get("secureboot") or {}).get("status"), ""), (h.get("system") or {}).get("boot_mode"),
                    res["bios"].get("compliance"), res["security"]["score"].get("compliance"), res["counts"].get("fail", 0), res["counts"].get("warn", 0), res["counts"].get("unknown", 0)])
    return out


def rows_checks(recs):
    out = [["대상", "영역", "점검", "결과", "내용", "조치", "근거"]]
    for r in recs:
        for c in (r.get("result") or {}).get("checks") or []:
            out.append([r.get("label") or r["target"], c["area"], c["title"], ST_KO.get(c["status"], c["status"]), c["detail"], c.get("fix", ""), c.get("ref", "")])
    return out


def rows_dimms(recs):
    out = [["대상", "위치", "소켓", "채널", "슬롯", "장착", "용량 GB", "종류", "동작 MT/s", "정격 MT/s", "랭크", "제조사", "부품 번호", "상태"]]
    for r in recs:
        for d in (r.get("host") or {}).get("dimms") or []:
            out.append([r.get("label") or r["target"], d.get("locator"), d.get("socket"), d.get("channel"), d.get("slot"), "예" if d.get("present") else "", d.get("size_gib") or "",
                        d.get("type"), d.get("speed"), d.get("rated"), d.get("ranks"), d.get("manufacturer"), d.get("part"), d.get("health")])
    return out


def rows_drives(recs):
    out = [["대상", "컨트롤러", "드라이브", "역할", "모델", "제조사", "시리얼", "펌웨어", "프로토콜", "매체", "용량 GB", "남은 수명 %", "PCI quad", "HCL", "상태"]]
    for r in recs:
        for d in ((r.get("host") or {}).get("storage") or {}).get("drives") or []:
            hc = d.get("hcl") or {}
            out.append([r.get("label") or r["target"], d.get("ctrl"), d.get("name"), d.get("role", ""), d.get("model"), d.get("manufacturer"), d.get("serial"), d.get("fw"), d.get("protocol"),
                        d.get("media"), d.get("capacity_gb"), d.get("life_left"), ":".join(x for x in (d.get("vid"), d.get("did"), d.get("svid"), d.get("ssid")) if x),
                        ("ESA" if hc.get("esa") else ("OSA" if hc.get("osa") else hc.get("how", ""))) if hc else "", d.get("health")])
    return out


def rows_nics(recs):
    out = [["대상", "어댑터", "모델", "포트", "링크", "속도 Gb", "최대 Gb", "MAC", "펌웨어", "LLDP 스위치", "스위치 포트", "섀시 ID", "스위치 관리 IP"]]
    for r in recs:
        for p in (r.get("host") or {}).get("nics") or []:
            l = p.get("lldp") or {}
            out.append([r.get("label") or r["target"], p.get("adapter"), p.get("model"), p.get("port"), p.get("link"), p.get("speed_gbps"), p.get("max_gbps"), p.get("mac"), p.get("fw"),
                        l.get("system_name"), l.get("port_id"), l.get("chassis_id"), l.get("mgmt_ip")])
    return out


def rows_security(recs):
    out = [["대상", "ID", "항목", "결과", "현재", "기대", "분류", "CISA/NSA 주제", "심각도", "SCG ID", "NIST 800-53r5", "조치"]]
    for r in recs:
        for c in ((r.get("result") or {}).get("security") or {}).get("rows") or []:
            out.append([r.get("label") or r["target"], c["id"], c["title"], ST_KO.get(c["status"], c["status"]), c["observed"], c["expected"], c["group"], c["cisa"], c["severity"], c["scg"], c["nist"], c.get("fix", "")])
    return out


def rows_bios(recs):
    out = [["대상", "기능", "속성", "현재", "결과", "등급", "범주", "이유"]]
    for r in recs:
        for c in ((r.get("result") or {}).get("bios") or {}).get("rows") or []:
            out.append([r.get("label") or r["target"], c["title"], c["attribute"], c["current"], ST_KO.get(c["status"], c["status"]), c["severity"], c["category"], c["why"]])
    return out


def rows_fw(recs):
    out = [["대상", "구성요소", "버전", "업데이트 가능", "릴리스 날짜"]]
    for r in recs:
        for f in (r.get("host") or {}).get("firmware") or []:
            out.append([r.get("label") or r["target"], f.get("name"), f.get("version"), f.get("updateable"), f.get("date")])
    return out


def rows_sel(recs):
    out = [["대상", "로그", "시각", "등급", "메시지", "MessageId"]]
    for r in recs:
        for e in (r.get("host") or {}).get("sel") or []:
            out.append([r.get("label") or r["target"], e.get("svc"), e.get("ts"), e.get("severity"), e.get("message"), e.get("message_id")])
    return out


SHEETS = [("요약", rows_summary), ("점검", rows_checks), ("메모리", rows_dimms), ("드라이브", rows_drives), ("NIC·ToR", rows_nics), ("BMC 보안", rows_security),
          ("BIOS 기준선", rows_bios), ("펌웨어", rows_fw), ("하드웨어 이벤트", rows_sel)]


# ------------------------------------------------------------------------------------------ Excel(OpenXML)
def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def xlsx(sheets: list[tuple[str, list[list]]]) -> bytes:
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    n = len(sheets)
    z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
               '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
               '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
               '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
               + "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(n))
               + "</Types>")
    z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    z.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
               'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
               + "".join(f'<sheet name="{xesc(nm[:31])}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, (nm, _) in enumerate(sheets)) + "</sheets></workbook>")
    z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>' for i in range(n))
               + f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    z.writestr("xl/styles.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<fonts count="2"><font><sz val="10"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Malgun Gothic"/></font></fonts>'
               '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1D428A"/></patternFill></fill></fills>'
               '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
               '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
               '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
    for i, (_, rows) in enumerate(sheets):
        x = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>']
        if rows:
            x.append("<cols>" + "".join(f'<col min="{j + 1}" max="{j + 1}" width="{min(60, max(8, max(len(str(r[j]) if j < len(r) and r[j] is not None else "") for r in rows[:200]) + 2))}" customWidth="1"/>' for j in range(len(rows[0]))) + "</cols>")
        x.append("<sheetData>")
        for ri, row in enumerate(rows):
            x.append(f'<row r="{ri + 1}">')
            for ci, v in enumerate(row):
                ref = f"{_col(ci)}{ri + 1}"
                st = ' s="1"' if ri == 0 else ""
                if isinstance(v, bool) or v is None or v == "":
                    if v not in (None, ""):
                        x.append(f'<c r="{ref}" t="inlineStr"{st}><is><t>{"예" if v else "아니오"}</t></is></c>')
                    continue
                if isinstance(v, (int, float)):
                    x.append(f'<c r="{ref}"{st}><v>{v}</v></c>')
                else:
                    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(v))[:32000]
                    x.append(f'<c r="{ref}" t="inlineStr"{st}><is><t xml:space="preserve">{xesc(s)}</t></is></c>')
            x.append("</row>")
        x.append("</sheetData>")
        if rows and len(rows) > 1:
            x.append(f'<autoFilter ref="A1:{_col(len(rows[0]) - 1)}{len(rows)}"/>')
        x.append("</worksheet>")
        z.writestr(f"xl/worksheets/sheet{i + 1}.xml", "".join(x))
    z.close()
    return buf.getvalue()


def csv_zip(recs: list[dict], fl: dict, meta: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for nm, fn in SHEETS:
            s = io.StringIO()
            csv.writer(s).writerows(fn(recs))
            z.writestr(f"{nm}.csv", "﻿" + s.getvalue())
        z.writestr("fleet.json", json.dumps(fl, ensure_ascii=False, indent=1, default=str))
        z.writestr("MANIFEST.json", json.dumps(meta, ensure_ascii=False, indent=1))
    return buf.getvalue()


# ------------------------------------------------------------------------------------------ HTML
CSS = """body{font:13px/1.5 "Malgun Gothic","Noto Sans KR",system-ui,sans-serif;color:#1f2a33;margin:0;background:#f4f6f8}main{max-width:1280px;margin:0 auto;padding:20px}
h1{font-weight:400;margin:0 0 4px}h2{font-weight:500;border-bottom:2px solid #1d428a;padding-bottom:4px;margin-top:28px}h3{margin:18px 0 6px}
.muted{color:#6b7780}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.tile{background:#fff;border:1px solid #d7dde2;border-top:4px solid #1d428a;padding:10px 12px;border-radius:4px}
.tile b{display:block;font-size:22px;font-weight:400}table{border-collapse:collapse;width:100%;background:#fff;margin:6px 0 12px;font-size:12px}th,td{border:1px solid #dde3e8;padding:4px 7px;text-align:left;vertical-align:top}
th{background:#eef2f6}td:nth-child(3),th:nth-child(3){white-space:nowrap}.b{display:inline-block;padding:0 7px;border-radius:9px;color:#fff;font-size:11px;white-space:nowrap}.host{background:#fff;border:1px solid #d7dde2;border-radius:4px;padding:12px 16px;margin:14px 0}
.grid{display:flex;gap:14px;flex-wrap:wrap}.sock{border:1px solid #c8d1d9;border-radius:4px;padding:6px}.ch{display:inline-flex;flex-direction:column;align-items:center;margin:2px}
.dimm{width:22px;height:34px;border:1px solid #8a99a6;border-radius:2px;margin:1px;font-size:9px;display:flex;align-items:center;justify-content:center}.dimm.on{background:#1d428a;color:#fff}
.dimm.bad{background:#c21d00}.dimm.slow{background:#b26a00;color:#fff}nav a{margin-right:10px}@media print{.host{page-break-inside:avoid}}"""


def _b(st: str, label: str | None = None) -> str:
    return f'<span class="b" style="background:{ST_COL.get(st, V_COL.get(st, "#6b7780"))}">{html.escape(label or ST_KO.get(st, st))}</span>'


def _t(rows: list[list], cls: str = "") -> str:
    if len(rows) <= 1:
        return '<p class="muted">없음</p>'
    e = html.escape
    return f'<table class="{cls}"><tr>' + "".join(f"<th>{e(str(h))}</th>" for h in rows[0]) + "</tr>" + "".join(
        "<tr>" + "".join(f"<td>{e('' if v is None else str(v))}</td>" for v in r) + "</tr>" for r in rows[1:]) + "</table>"


def dimm_html(grid: list[dict]) -> str:
    out = ['<div class="grid">']
    for s in grid:
        out.append(f'<div class="sock"><b>CPU{s["socket"]}</b><br>')
        for c in s["channels"]:
            cells = "".join(f'<div class="dimm {"bad" if d.get("health") not in ("", "OK", None) and d.get("present") else ("slow" if d.get("present") and d.get("speed") and d.get("rated") and d["speed"] < d["rated"] else ("on" if d.get("present") else ""))}" '
                            f'title="{html.escape(str(d.get("loc")))} {d.get("gib") or ""}GB {d.get("speed") or ""}/{d.get("rated") or ""}">{int(d["gib"]) if d.get("present") and d.get("gib") else ""}</div>' for d in c["dimms"])
            out.append(f'<div class="ch">{cells or "<div class=dimm></div>"}<small>{html.escape(c["ch"])}</small></div>')
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def report_html(scan: dict, recs: list[dict], fl: dict, obfuscated: bool = False) -> str:
    e = html.escape
    t = (fl or {}).get("totals") or {}
    v = (fl or {}).get("verdicts") or {}
    nodes = (fl or {}).get("nodes") or {}
    tor = (fl or {}).get("tor") or {}
    tiles = [("호스트", f"{t.get('hosts', 0)}" + (f" (+실패 {t['failed']})" if t.get("failed") else "")), ("준비됨", v.get("ready", 0)), ("조치 후 가능", v.get("actions", 0)),
             ("불가", v.get("not_ready", 0)), ("소켓·코어", f"{t.get('sockets', 0)} · {t.get('cores', 0)}"), ("메모리", f"{round((t.get('mem_gib') or 0) / 1024, 2)} TB"),
             ("직결 NVMe", f"{t.get('nvme_tb', 0)} TB"), ("소비 전력", f"{round((t.get('power_w') or 0) / 1000, 2)} kW"),
             ("ToR 이중 연결", f"{tor.get('redundancy_pct')}%" if tor.get("redundancy_pct") is not None else "LLDP 없음"),
             ("BMC 보안 준수", f"{(fl.get('security') or {}).get('compliance')}%" if (fl.get("security") or {}).get("compliance") is not None else "-")]
    hs = []
    for r in recs:
        if not r.get("ok"):
            hs.append(f'<div class="host" id="h-{e(r["target"])}"><h3>{e(r.get("label") or r["target"])} {_b("fail", "스캔 실패")}</h3><p>{e(str(r.get("error")))}</p></div>')
            continue
        res, h = r["result"], r["host"]
        sm = res["summary"]
        esx = r.get("esxi") or {}
        areas = " ".join(f"{AREA_KO.get(k, k)} {_b(s)}" for k, s in res["areas"].items())
        hs.append(f'''<div class="host" id="h-{e(r["target"])}"><h3>{e(r.get("label") or r["target"])} {_b(res["verdict"], res["verdict_label"])}
<small class="muted">{e(str(sm.get("vendor")))} {e(str(sm.get("model")))} · S/N {e(str(sm.get("serial")))} · BIOS {e(str(sm.get("bios")))} · BMC {e(str(sm.get("bmc_fw")))}{" · ESXi " + e(esx.get("esxi", "")) if esx else ""}</small></h3>
<p>{areas}</p>{("<p><b>차단:</b> " + e(", ".join(res["blocking"])) + "</p>") if res["blocking"] else ""}
{_t([["영역", "점검", "결과", "내용", "조치"]] + [[AREA_KO.get(c["area"], c["area"]), c["title"], ST_KO.get(c["status"]), c["detail"], c.get("fix", "")] for c in res["checks"]])}
<h4>메모리 배치</h4>{dimm_html(res.get("memory_grid") or [])}
<h4>BMC 보안 {res["security"]["score"]["posture"]} (준수 {res["security"]["score"].get("compliance")}%, 확인 {res["security"]["score"].get("coverage")}%)</h4>
{_t([["ID", "항목", "결과", "현재", "기대", "SCG"]] + [[c["id"], c["title"], ST_KO.get(c["status"]), c["observed"], c["expected"], c["scg"]] for c in res["security"]["rows"]])}
<h4>BIOS 기준선 {e(str(res["bios"].get("compliance")))}%</h4>{_t([["기능", "속성", "현재", "결과", "등급"]] + [[c["title"], c["attribute"], c["current"], ST_KO.get(c["status"]), c["severity"]] for c in res["bios"].get("rows") or []])}
</div>''')
    pairs = _t([["리프 A", "리프 B", "이중 연결 호스트", "A 에만", "B 에만"]] + [[p["a"], p["b"], ", ".join(p["dual"]), ", ".join(p["only_a"]), ", ".join(p["only_b"])] for p in tor.get("pairs") or []])
    single = _t([["호스트", "연결 스위치", "상태"]] + [[x["host"], ", ".join(f"{k}×{n}" for k, n in x["switches"].items()), {"dual": "이중", "single": "단일" + (" (한 스위치에 여러 포트 — 오결선 의심)" if x["miscabled"] else ""), "unknown": "LLDP 없음"}[x["state"]]] for x in tor.get("hosts") or []])
    drift = _t([["모델", "항목", "값 → 호스트"]] + [[d["model"], d["item"], " / ".join(f"{x['value']}: {', '.join(x['hosts'])}" for x in d["values"])] for d in fl.get("drift") or []])
    summ = rows_summary(recs)
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VCF 하드웨어 준비도 {e(scan.get("id", ""))}</title><style>{CSS}</style></head><body><main>
<h1>VCF 9.x 하드웨어 준비도 보고서</h1><p class="muted">스캔 {e(scan.get("id", ""))} · {time.strftime("%Y-%m-%d %H:%M", time.localtime(scan.get("created") or time.time()))} · VCF AIOps{" · 가명화 사본" if obfuscated else ""}</p>
<div class="tiles">{"".join(f'<div class="tile"><small>{e(a)}</small><b>{e(str(b))}</b></div>' for a, b in tiles)}</div>
<p>VCF 노드 수: {nodes.get("count", 0)}대 — Simple(vSAN 3대) {"충족" if nodes.get("simple_vsan") else "미충족"} · HA(4대) {"충족" if nodes.get("ha") else "미충족"} <small class="muted">({e(nodes.get("note", ""))})</small></p>
<h2>호스트별 요약</h2>{_t([summ[0][:5] + summ[0][8:12] + summ[0][14:19]] + [r[:5] + r[8:12] + r[14:19] for r in summ[1:]])}
<h2>ToR 스위치 패브릭(LLDP)</h2>{pairs}{single}
<h2>같은 모델 간 펌웨어·BIOS 편차</h2>{drift}
<h2>호스트 상세</h2>{"".join(hs)}
<p class="muted">판정 근거: CPU — Broadcom KB 428874 / BCG CPU Series, 부팅 — KB 313152, vSAN ESA — ReadyNode 최소 사양(2025-11), 노드 수 — VCF 9.1 Supported and Not Supported Configurations, BMC 보안 — VCF 9 SCG 하드웨어 관리 항목.
이 보고서는 평가 보조 자료이며 Broadcom 호환성 인증이 아닙니다. 확인 불가 항목은 BMC 가 값을 주지 않은 것으로 통과로 치지 않았습니다.</p></main></body></html>"""
