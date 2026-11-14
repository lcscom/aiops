"""HTTP 응답 머리글 공통 처리(2.20.0)

disposition(name) — 내려받기 파일 이름을 안전하게: ASCII 대체 이름(따옴표·;·제어문자·비 ASCII 제거) + RFC 6266/5987 filename*(UTF-8)
NUMERIC_PARAMS / bad_numeric_query() — 기간·개수 숫자 쿼리의 NaN·Infinity·1e309 를 400 으로(저장·직렬화 오류 방지)
"""
from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, quote

_UNSAFE = re.compile(r'[^A-Za-z0-9._()\-]+')


def safe_filename(name: str, default: str = "download") -> str:
    """경로 구분자·따옴표·세미콜론·제어문자·비 ASCII 를 '_' 로 바꾼 ASCII 파일 이름(최대 150자)"""
    s = _UNSAFE.sub("_", str(name or "")).strip("._-") or default
    return s[:150]


def disposition(name: str, inline: bool = False) -> str:
    raw = str(name or "download").replace("\r", " ").replace("\n", " ").replace("\x00", "")
    raw = "".join(ch for ch in raw if ch.isprintable())[:200] or "download"
    return f"{'inline' if inline else 'attachment'}; filename=\"{safe_filename(raw)}\"; filename*=UTF-8''{quote(raw, safe='')}"


NUMERIC_PARAMS = frozenset({"hours", "days", "minutes", "since", "until", "start", "end", "before", "after", "limit", "offset",
                            "tail", "max_rows", "window", "step", "period", "seconds", "top", "page", "size"})


def bad_numeric_query(query: str) -> str | None:
    """숫자 쿼리 값이 NaN·±Infinity(또는 1e309 처럼 넘치는 수)면 그 이름을 돌려줌"""
    for k, v in parse_qsl(query or "", keep_blank_values=True):
        if k not in NUMERIC_PARAMS or not v:
            continue
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(f):
            return k
    return None


def finite(obj):
    """JSON 직렬화 전에 NaN·Infinity 를 None 으로(감사로그 detail 등)"""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: finite(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [finite(v) for v in obj]
    return obj
