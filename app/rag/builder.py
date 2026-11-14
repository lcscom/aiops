"""RAG 팩 빌더 CLI

  python -m app.rag.builder build ragpacks/vsphere.yaml        # 스펙 → dist/*.ragpack
  python -m app.rag.builder inspect dist/vsphere.ragpack       # 팩 요약

소스 타입
  local     로컬 폴더의 md/txt/html/pdf (사내 가이드, 다운로드해 둔 KB·VMSA·릴리스노트 등)
  kb        Broadcom KB 문서 번호 목록 → URL 템플릿으로 수집 (ids / ids_file)
  urls      임의 URL 목록 파일 (VMSA, 릴리스노트, 보안 하드닝 가이드 등)
  nvd       NVD CVE API 2.0 — keywordSearch + CPE 필터로 제품 취약점(CVE·CVSS·VMSA 링크) 수집
  pgvector  기존 RAG DB(예: vmware_rag_v2)에서 SQL로 문서 export (psycopg 필요)
  jsonl     {title,url,text,type,published} 행 파일 (다른 수집기 결과 재사용)
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
import numpy as np
import yaml

from ..config import _subst
from .embed import Embedder
from .store import FORMAT
from .textutil import chunk, extract_ids, html_to_text

# 제품 → 기본 적용 이벤트 소스 (AIOps 수집 source 값)
PRESETS = {
    "vsphere": ["esxi", "vcenter", "vcfops", "vcflogs", "syslog", "snmp"],
    "esxi": ["esxi", "vcenter", "syslog", "snmp", "vcflogs"],
    "vcenter": ["vcenter", "vcflogs", "vcfops"],
    "vsan": ["esxi", "vcenter", "vcfops", "vcflogs"],
    "nsx": ["nsx", "nsx-edge", "vcflogs", "vcfops"],
    "nsx-edge": ["nsx-edge", "nsx"],
    "vcf": ["sddc", "vcenter", "nsx", "nsx-edge", "vcfops"],
    "vcfops": ["vcfops"], "vcflogs": ["vcflogs"],
    "vcfa": ["vcfa"], "srm": ["srm"], "avi": ["avi"], "nsx-alb": ["avi"],
    "vks": ["vks", "vks-supervisor", "vcenter"],
    "hardware": ["redfish", "snmp", "esxi"],
    "general": ["*"],
}

UA = "VCF-AIOps-RagBuilder/1.0 (+internal knowledge pack)"


def _doc(title: str, text: str, url: str = "", dtype: str = "doc", published: str = "", doc_id: str = "") -> dict:
    return {"title": title.strip()[:300], "text": text, "url": url, "type": dtype, "published": published,
            "doc_id": doc_id or hashlib.sha1((url or title or text[:200]).encode()).hexdigest()[:16]}


# ------------------------------------------------------------------------ sources
async def src_local(s: dict) -> AsyncIterator[dict]:
    root = Path(s["path"])
    for p in sorted(root.glob(s.get("glob", "**/*"))):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        try:
            if ext in (".md", ".txt", ".log", ".rst"):
                text, title = p.read_text(encoding="utf-8", errors="replace"), p.stem
                m = re.match(r"#\s+(.+)", text)
                title = m.group(1) if m else title
            elif ext in (".html", ".htm"):
                title, text = html_to_text(p.read_text(encoding="utf-8", errors="replace"))
                title = title or p.stem
            elif ext == ".pdf":
                from pypdf import PdfReader
                r = PdfReader(str(p))
                text = "\n\n".join((pg.extract_text() or "") for pg in r.pages)
                title = (r.metadata.title if r.metadata and r.metadata.title else p.stem)
            else:
                continue
        except Exception as e:  # noqa: BLE001
            print(f"  ! {p}: {e}", file=sys.stderr)
            continue
        kb = re.search(r"(?:article|kb)[/_-]?(\d{5,7})", p.name, re.I)
        yield _doc(title, text, s.get("url_prefix", "") + p.name if s.get("url_prefix") else str(p),
                   s.get("doc_type", "guide"), doc_id=f"kb{kb.group(1)}" if kb else "")


async def _fetch_pages(urls: list[str], s: dict, dtype: str) -> AsyncIterator[dict]:
    delay = float(s.get("delay", 1.0))
    async with httpx.AsyncClient(headers={"User-Agent": UA}, timeout=30, follow_redirects=True,
                                 verify=s.get("verify_tls", True)) as http:
        for i, u in enumerate(urls, 1):
            try:
                r = await http.get(u)
                r.raise_for_status()
                title, text = html_to_text(r.text)
                if len(text) < 200:
                    print(f"  ! 본문 부족(동적 페이지?) {u}", file=sys.stderr)
                pub = ""
                m = re.search(r"(Updated On|Published|Last Updated)[:\s]*([A-Za-z0-9 ,\-/]{6,30})", text)
                if m:
                    pub = m.group(2).strip()
                kb = re.search(r"/article/(\d+)", u)
                yield _doc(title or u, text, u, dtype, pub, f"kb{kb.group(1)}" if kb else "")
                print(f"  [{i}/{len(urls)}] {title[:70] or u}")
            except Exception as e:  # noqa: BLE001
                print(f"  ! {u}: {e}", file=sys.stderr)
            await asyncio.sleep(delay)


async def src_kb(s: dict) -> AsyncIterator[dict]:
    ids = [str(x) for x in s.get("ids", [])]
    if s.get("ids_file"):
        ids += [ln.strip() for ln in Path(s["ids_file"]).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    tpl = s.get("url_template", "https://knowledge.broadcom.com/external/article/{id}")
    async for d in _fetch_pages([tpl.format(id=i) for i in dict.fromkeys(ids)], s, "kb"):
        yield d


async def src_urls(s: dict) -> AsyncIterator[dict]:
    urls = list(s.get("urls", []))
    if s.get("file"):
        urls += [ln.strip() for ln in Path(s["file"]).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    async for d in _fetch_pages(list(dict.fromkeys(urls)), s, s.get("doc_type", "doc")):
        yield d


async def src_nvd(s: dict) -> AsyncIterator[dict]:
    """NVD CVE API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0 (resultsPerPage ≤ 2000, 헤더 apiKey)"""
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": UA}
    if s.get("api_key"):
        headers["apiKey"] = s["api_key"]
    delay = 0.7 if s.get("api_key") else 6.1           # 키 없음 5req/30s, 키 있음 50req/30s
    cpe_filter = [c.lower() for c in s.get("cpe_filter", [])]
    since = s.get("since", "")
    keywords = s.get("keywords") or [s.get("keyword", "VMware ESXi")]
    seen: set[str] = set()
    async with httpx.AsyncClient(headers=headers, timeout=60) as http:
        for kw in keywords:
            start = 0
            while True:
                params = {"keywordSearch": kw, "resultsPerPage": 2000, "startIndex": start}
                r = await http.get(base, params=params)
                r.raise_for_status()
                j = r.json()
                for v in j.get("vulnerabilities", []):
                    c = v["cve"]
                    cid = c["id"]
                    if cid in seen or (since and c.get("published", "") < since):
                        continue
                    conf = json.dumps(c.get("configurations", [])).lower()
                    if cpe_filter and not any(f in conf for f in cpe_filter):
                        continue
                    seen.add(cid)
                    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
                    met = (c.get("metrics", {}).get("cvssMetricV31") or c.get("metrics", {}).get("cvssMetricV30") or [{}])[0]
                    cv = met.get("cvssData", {})
                    refs = [rf["url"] for rf in c.get("references", [])]
                    vmsa = sorted({m.upper() for rf in refs for m in re.findall(r"VMSA-\d{4}-\d{4}", rf, re.I)})
                    cwe = [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])]
                    products = sorted(set(re.findall(r"cpe:2\.3:[aoh]:vmware:([a-z0-9_]+)", conf)))
                    text = (f"{cid} ({cv.get('baseSeverity', 'N/A')} {cv.get('baseScore', '')}, {cv.get('vectorString', '')})\n"
                            f"영향 제품: {', '.join(products) or '-'}\n권고: {', '.join(vmsa) or '-'}\n"
                            f"CWE: {', '.join(cwe) or '-'}\n게시: {c.get('published', '')[:10]}\n\n{desc}\n\n참조:\n" + "\n".join(refs[:12]))
                    d = _doc(f"{cid} {' '.join(vmsa)} {cv.get('baseSeverity', '')}".strip(), text,
                             f"https://nvd.nist.gov/vuln/detail/{cid}", "cve", c.get("published", "")[:10], cid.lower())
                    d["ids"] = [cid.lower()] + [x.lower() for x in vmsa]
                    yield d
                total = j.get("totalResults", 0)
                start += j.get("resultsPerPage", 0) or 2000
                print(f"  NVD '{kw}': {min(start, total)}/{total}")
                if start >= total:
                    break
                await asyncio.sleep(delay)
            await asyncio.sleep(delay)


async def src_pgvector(s: dict) -> AsyncIterator[dict]:
    import psycopg  # pip install "psycopg[binary]"
    with psycopg.connect(s["dsn"]) as conn, conn.cursor() as cur:
        cur.execute(s["sql"])
        cols = [c.name for c in cur.description]
        for row in cur:
            r = dict(zip(cols, row))
            yield _doc(str(r.get("title") or ""), str(r.get("text") or r.get("content") or ""), str(r.get("url") or ""),
                       str(r.get("type") or s.get("doc_type", "doc")), str(r.get("published") or ""),
                       str(r.get("doc_id") or ""))


async def src_jsonl(s: dict) -> AsyncIterator[dict]:
    with open(s["path"], encoding="utf-8") as f:
        for ln in f:
            if ln.strip():
                r = json.loads(ln)
                d = _doc(r.get("title", ""), r.get("text", ""), r.get("url", ""), r.get("type", "doc"),
                         r.get("published", ""), r.get("doc_id", ""))
                if r.get("ids"):
                    d["ids"] = r["ids"]
                yield d


SOURCES = {"local": src_local, "kb": src_kb, "urls": src_urls, "nvd": src_nvd, "pgvector": src_pgvector, "jsonl": src_jsonl}


# ------------------------------------------------------------------------ build
async def build(spec_path: str) -> Path:
    spec = _subst(yaml.safe_load(Path(spec_path).read_text(encoding="utf-8")))
    product = spec.get("product", "general")
    chunks: list[dict] = []
    src_stats = []
    docs = 0
    seen_docs: set[str] = set()
    for s in spec.get("sources", []):
        fn = SOURCES[s["type"]]
        n_before = docs
        print(f"▶ {s['type']} {s.get('path') or s.get('keyword') or s.get('file') or ''}")
        async for d in fn(s):
            if d["doc_id"] in seen_docs or len(d["text"].strip()) < 40:
                continue
            seen_docs.add(d["doc_id"])
            docs += 1
            for j, c in enumerate(chunk(d["text"], d["title"], int(spec.get("chunk_size", 1400)), int(spec.get("chunk_overlap", 200)))):
                chunks.append({"id": f"{d['doc_id']}-{j}", "doc_id": d["doc_id"], "title": d["title"], "url": d["url"],
                               "text": c, "type": d["type"], "product": product, "published": d["published"],
                               "ids": sorted(set(d.get("ids", [])) | extract_ids(d["title"] + " " + c))})
        src_stats.append({"type": s["type"], "detail": s.get("path") or s.get("keyword") or s.get("file") or s.get("dsn", "")[:40],
                          "documents": docs - n_before})
    if not chunks:
        raise SystemExit("수집된 문서가 없습니다.")

    vec_bytes = None
    emb_meta = None
    if (spec.get("embedding") or {}).get("base_url"):
        emb = Embedder({**spec["embedding"], "enabled": True})
        print(f"▶ 임베딩 {emb.model} — {len(chunks)} chunks")
        parts = []
        for i in range(0, len(chunks), 256):
            parts.append((await emb.embed([c["text"] for c in chunks[i:i + 256]])).astype(np.float16))
            print(f"  {min(i + 256, len(chunks))}/{len(chunks)}")
        vec = np.concatenate(parts)
        buf = io.BytesIO()
        np.save(buf, vec)
        vec_bytes = buf.getvalue()
        emb_meta = {"model": emb.model, "dim": int(vec.shape[1])}

    manifest = {
        "format": FORMAT, "id": spec["id"], "name": spec.get("name", spec["id"]), "product": product,
        "version": str(spec.get("version", datetime.now().strftime("%Y.%m.%d"))), "description": spec.get("description", ""),
        "applies_to": spec.get("applies_to") or PRESETS.get(product, ["*"]),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "embedding": emb_meta,
        "stats": {"documents": docs, "chunks": len(chunks),
                  "by_type": {t: sum(1 for c in chunks if c["type"] == t) for t in sorted({c["type"] for c in chunks})}},
        "sources": src_stats, "license_note": spec.get("license_note", "내부 운영 목적. 원문 저작권은 각 게시자에 있음."),
    }
    out = Path(spec.get("output", f"dist/{spec['id']}.ragpack"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
        z.writestr("chunks.jsonl", "\n".join(json.dumps(c, ensure_ascii=False) for c in chunks) + "\n")
        if vec_bytes:
            z.writestr("vectors.npy", vec_bytes)
    print(f"✔ {out}  문서 {docs} · 청크 {len(chunks)} · 벡터 {'있음' if vec_bytes else '없음(임포트 시 생성)'}")
    return out


def inspect(path: str) -> None:
    with zipfile.ZipFile(path) as z:
        m = json.loads(z.read("manifest.json"))
        print(json.dumps(m, ensure_ascii=False, indent=1))
        first = z.read("chunks.jsonl").decode().split("\n", 1)[0]
        print("\n첫 청크:", first[:500])


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m app.rag.builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("spec")
    i = sub.add_parser("inspect")
    i.add_argument("pack")
    a = ap.parse_args(argv)
    if a.cmd == "build":
        t = time.time()
        asyncio.run(build(a.spec))
        print(f"({time.time() - t:.1f}s)")
    else:
        inspect(a.pack)


if __name__ == "__main__":
    main()
