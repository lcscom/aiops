"""텍스트 정규화·청킹·토큰화 유틸 (빌더/검색 공용)."""
from __future__ import annotations

import html
import re

# 검색에서 정확 일치로 가중할 식별자: KB번호, CVE, VMSA, VOB, 에러코드, 버전/빌드
ID_PATTERNS = [
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    re.compile(r"\bVMSA-\d{4}-\d{4}\b", re.I),
    re.compile(r"\bKB\s?#?\d{5,7}\b", re.I),
    re.compile(r"\bvob\.[a-z0-9_.]+", re.I),
    re.compile(r"\b(?:esx\.problem|esx\.audit|esx\.clear)\.[a-z0-9_.]+", re.I),
    re.compile(r"\b0x[0-9a-f]{4,8}\b", re.I),
    re.compile(r"\b(?:H|D|P):0x[0-9a-f]+\b", re.I),
]

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.\-:]*[a-z0-9]|[가-힣]{2,}", re.I)
STOP = set("""a an the and or of to in on for with is are was were be been by as at from this that it its not no if then
than into via can will may should could has have had do does did you your we our they their there here when which what who
""".split())


def tokenize(text: str) -> list[str]:
    toks = [t.lower() for t in _TOKEN.findall(text or "")]
    out = [t for t in toks if t not in STOP and len(t) > 1]
    for rx in ID_PATTERNS:   # 식별자는 정규화된 형태로 한 번 더(가중치 효과)
        out += [m.lower().replace(" ", "").replace("#", "") for m in rx.findall(text or "")]
    return out


def extract_ids(text: str) -> set[str]:
    ids: set[str] = set()
    for rx in ID_PATTERNS[:5]:
        ids |= {m.lower().replace(" ", "").replace("#", "") for m in rx.findall(text or "")}
    return ids


def html_to_text(raw: str) -> tuple[str, str]:
    """(title, text). BeautifulSoup 있으면 사용, 없으면 정규식."""
    title = ""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(raw, "html.parser")
        for t in soup(["script", "style", "nav", "header", "footer", "noscript", "svg", "form"]):
            t.decompose()
        title = (soup.title.string or "").strip() if soup.title else ""
        main = soup.find("article") or soup.find("main") or soup.body or soup
        text = main.get_text("\n")
    except Exception:  # noqa: BLE001
        m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.S | re.I)
        title = html.unescape(m.group(1).strip()) if m else ""
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
        text = html.unescape(re.sub(r"<[^>]+>", "\n", text))
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return title, text


def chunk(text: str, title: str = "", size: int = 1400, overlap: int = 200) -> list[str]:
    """문단 경계 우선 청킹. 각 청크 앞에 제목을 붙여 검색·LLM 문맥 보존."""
    text = (text or "").strip()
    if not text:
        return []
    paras = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        while len(p) > size:                       # 매우 긴 문단은 강제 분할
            head, p = p[:size], p[size - overlap:]
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(head)
        if len(cur) + len(p) + 2 <= size:
            cur = f"{cur}\n\n{p}" if cur else p
        else:
            if cur:
                chunks.append(cur)
            tail = cur[-overlap:] if cur else ""
            cur = f"{tail}\n\n{p}" if tail else p
    if cur:
        chunks.append(cur)
    prefix = f"[{title}]\n" if title else ""
    return [prefix + c for c in chunks]
