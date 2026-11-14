"""표준 라이브러리만 쓰는 .xlsx 읽기(RVTools 내보내기용) — 공유 문자열·인라인 문자열·숫자·불리언·날짜(셀 서식) 처리

안전: 압축 해제 총량·시트 수·행 수 상한(압축 폭탄 방지), XML 은 xml.etree(외부 엔터티 미해석). 매크로·수식은 실행하지 않고 저장된 값만 읽는다.
"""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timedelta
from xml.etree import ElementTree as ET

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "pr": "http://schemas.openxmlformats.org/package/2006/relationships"}
M = "{" + NS["m"] + "}"
DATE_IDS = set(range(14, 23)) | {27, 30, 36, 45, 46, 47, 50, 57}
EPOCH = datetime(1899, 12, 30)
MAX_UNCOMPRESSED = 600 * 1024 * 1024


class XlsxError(ValueError):
    pass


def _col(ref: str) -> int:
    n = 0
    for ch in ref:
        if "A" <= ch <= "Z":
            n = n * 26 + ord(ch) - 64
        else:
            break
    return n - 1


def _text(el) -> str:
    """<si>/<is> 안의 <t>·리치 텍스트 <r><t> 를 이어 붙임(발음 표기 rPh 제외)"""
    out = []
    for node in el.iter():
        if node.tag == M + "t":
            out.append(node.text or "")
        elif node.tag == M + "rPh":
            break
    return "".join(out)


def read(raw: bytes, sheets: set[str] | None = None, max_rows: int = 300000) -> dict[str, list[dict]]:
    """→ {시트 이름: [ {헤더: 값} … ]} (첫 행 = 헤더). sheets 를 주면 그 시트만"""
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise XlsxError("xlsx(zip) 형식이 아닙니다 — RVTools 의 Export all to xlsx 파일을 올리세요") from None
    infos = z.infolist()
    if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED or len(infos) > 2000:
        raise XlsxError("압축 해제 크기가 너무 큽니다")
    names = {i.filename for i in infos}
    if "xl/workbook.xml" not in names:
        raise XlsxError("엑셀 통합 문서가 아닙니다(xl/workbook.xml 없음)")
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels")) if "xl/_rels/workbook.xml.rels" in names else None
    target = {}
    if rels is not None:
        for r in rels:
            t = r.get("Target", "")
            t = t.lstrip("/")
            target[r.get("Id")] = t if t.startswith("xl/") else "xl/" + t
    shared: list[str] = []
    if "xl/sharedStrings.xml" in names:
        for _, el in ET.iterparse(io.BytesIO(z.read("xl/sharedStrings.xml"))):
            if el.tag == M + "si":
                shared.append(_text(el))
                el.clear()
    date_xf: list[bool] = []
    if "xl/styles.xml" in names:
        st = ET.fromstring(z.read("xl/styles.xml"))
        custom = {int(n.get("numFmtId")): n.get("formatCode", "") for n in st.iter(M + "numFmt")}
        xfs = st.find(M + "cellXfs")
        for xf in (xfs if xfs is not None else []):
            fid = int(xf.get("numFmtId", "0"))
            code = re.sub(r'"[^"]*"|\[[^\]]*\]', "", custom.get(fid, "")).lower()
            date_xf.append(fid in DATE_IDS or (fid in custom and bool(re.search(r"[ymdhs]", code)) and "0.0" not in code))
    out: dict[str, list[dict]] = {}
    sh = wb.find(M + "sheets")
    for s in (sh if sh is not None else []):
        nm = s.get("name", "")
        if sheets and nm not in sheets:
            continue
        path = target.get(s.get("{%s}id" % NS["r"]), "")
        if path not in names:
            continue
        rows: list[list] = []
        for _, el in ET.iterparse(io.BytesIO(z.read(path))):
            if el.tag != M + "row":
                continue
            row: list = []
            for c in el.findall(M + "c"):
                idx = _col(c.get("r", "")) if c.get("r") else len(row)
                t = c.get("t", "n")
                v = c.find(M + "v")
                val = None
                if t == "s" and v is not None and v.text is not None:
                    i = int(v.text)
                    val = shared[i] if 0 <= i < len(shared) else ""
                elif t == "inlineStr":
                    isel = c.find(M + "is")
                    val = _text(isel) if isel is not None else ""
                elif t == "b" and v is not None:
                    val = v.text == "1"
                elif t in ("str", "e") and v is not None:
                    val = v.text
                elif v is not None and v.text is not None:
                    try:
                        f = float(v.text)
                        si = int(c.get("s", "0"))
                        if si < len(date_xf) and date_xf[si] and 0 < f < 2958466:
                            val = EPOCH + timedelta(seconds=round(f * 86400))
                        else:
                            val = int(f) if f.is_integer() and abs(f) < 2**53 else f
                    except ValueError:
                        val = v.text
                while len(row) < idx:
                    row.append(None)
                if idx < len(row):
                    row[idx] = val
                else:
                    row.append(val)
            rows.append(row)
            el.clear()
            if len(rows) > max_rows + 1:
                raise XlsxError(f"{nm} 시트 행이 {max_rows}개를 넘습니다")
        if not rows:
            out[nm] = []
            continue
        hdr = [str(h).strip() if h is not None else f"col{i}" for i, h in enumerate(rows[0])]
        out[nm] = [{hdr[i]: (r[i] if i < len(r) else None) for i in range(len(hdr))} for r in rows[1:] if any(x not in (None, "") for x in r)]
    return out
