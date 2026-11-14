"""RAG 팩 저장소 — import / enable / disable / 하이브리드 검색(Dense + BM25 + 식별자 일치).

.ragpack (zip) 포맷  format = "vcf-aiops-ragpack/1"
  manifest.json   {id, name, product, version, description, applies_to[], created, embedding{model,dim}|null,
                   stats{documents,chunks}, sources[], license_note}
  chunks.jsonl    {id, doc_id, title, url, text, type(kb|vmsa|cve|doc|guide), product, published, ids[]}
  vectors.npy     (선택) float16 N×dim, chunks.jsonl 행 순서와 동일. 없거나 임베딩 모델이 다르면 import 후 재임베딩
"""
from __future__ import annotations

import asyncio
import io
import json
import math
import shutil
import time
import zipfile
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from .embed import Embedder
from .textutil import extract_ids, tokenize

FORMAT = "vcf-aiops-ragpack/1"
ALLOWED = {"manifest.json", "chunks.jsonl", "vectors.npy"}
MAX_PACK_BYTES = 4 * 1024 ** 3


class _BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.4, b: float = 0.72):
        self.k1, self.b = k1, b
        self.n = len(docs)
        self.dl = np.array([len(d) for d in docs], dtype=np.float32)
        self.avg = float(self.dl.mean()) if self.n else 1.0
        post: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for i, d in enumerate(docs):
            tf: dict[str, int] = defaultdict(int)
            for t in d:
                tf[t] += 1
            for t, c in tf.items():
                post[t].append((i, c))
        self.post = {t: (np.array([p[0] for p in v], dtype=np.int32), np.array([p[1] for p in v], dtype=np.float32))
                     for t, v in post.items()}

    def scores(self, q: list[str]) -> np.ndarray:
        s = np.zeros(self.n, dtype=np.float32)
        for t in set(q):
            if t not in self.post:
                continue
            idx, tf = self.post[t]
            idf = math.log(1 + (self.n - len(idx) + 0.5) / (len(idx) + 0.5))
            s[idx] += idf * tf * (self.k1 + 1) / (tf + self.k1 * (1 - self.b + self.b * self.dl[idx] / self.avg))
        return s


class LoadedPack:
    def __init__(self, path: Path, manifest: dict):
        self.path = path
        self.manifest = manifest
        self.chunks: list[dict] = []
        self.vectors: np.ndarray | None = None
        self.bm25: _BM25 | None = None
        self.ids: list[set[str]] = []

    def load(self) -> None:
        with open(self.path / "chunks.jsonl", encoding="utf-8") as f:
            self.chunks = [json.loads(line) for line in f if line.strip()]
        vp = self.path / "vectors.npy"
        if vp.exists():
            v = np.load(vp, mmap_mode="r")
            self.vectors = v if v.shape[0] == len(self.chunks) else None
        self.ids = [set(c.get("ids") or []) | extract_ids(c.get("title", "")) for c in self.chunks]
        self.bm25 = _BM25([tokenize(f"{c.get('title', '')} {c['text']}") for c in self.chunks])


class RagManager:
    def __init__(self, cfg: dict, data_dir: str):
        self.cfg = cfg or {}
        self.root = Path(data_dir) / "ragpacks"
        self.root.mkdir(parents=True, exist_ok=True)
        self.reg_path = self.root / "registry.json"
        self.registry: dict[str, dict] = json.loads(self.reg_path.read_text()) if self.reg_path.exists() else {}
        self.embedder = Embedder(self.cfg.get("embedding") or {})
        self.loaded: dict[str, LoadedPack] = {}
        self.jobs: dict[str, dict] = {}
        self.k = int(self.cfg.get("top_k", 6))
        self.min_score = float(self.cfg.get("min_score", 0.25))
        self.w_dense = float(self.cfg.get("dense_weight", 0.6))
        self._qcache: OrderedDict[str, np.ndarray] = OrderedDict()
        self.library = None                   # app.knowledge.KnowledgeLibrary (KB·TechDocs md) — engine 이 주입
        self.env_fn = None                    # () → 운영 중 제품 버전 {product: {"8.0","8.x"}}

    def has_any(self) -> bool:
        return bool(self.loaded) or bool(self.library and self.library.enabled and self.library.has_chunks())

    # ------------------------------------------------------------------ registry
    def _save(self):
        self.reg_path.write_text(json.dumps(self.registry, ensure_ascii=False, indent=1))

    def _manifest(self, pid: str) -> dict:
        return json.loads((self.root / pid / "manifest.json").read_text(encoding="utf-8"))

    def list(self) -> list[dict]:
        out = []
        for pid, r in self.registry.items():
            try:
                m = self._manifest(pid)
            except FileNotFoundError:
                continue
            has_vec = (self.root / pid / "vectors.npy").exists()
            emb = (m.get("embedding") or {}).get("model")
            out.append({**{k: m.get(k) for k in ("id", "name", "product", "version", "description", "applies_to",
                                                 "created", "stats", "sources", "license_note")},
                        "enabled": r.get("enabled", False), "imported": r.get("imported"),
                        "loaded": pid in self.loaded, "vectors": has_vec, "embedding_model": emb,
                        "embedding_match": bool(has_vec and emb == self.embedder.model),
                        "job": self.jobs.get(pid), "size_mb": round(sum(f.stat().st_size for f in (self.root / pid).iterdir()) / 1e6, 1)})
        return sorted(out, key=lambda x: (not x["enabled"], x["product"] or "", x["name"] or ""))

    # ------------------------------------------------------------------ import / delete
    async def import_pack(self, data: bytes, filename: str = "") -> dict:
        if len(data) > MAX_PACK_BYTES:
            raise ValueError("팩 크기 초과(4GB)")
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = {Path(n).name: n for n in zf.namelist() if not n.endswith("/")}
        if "manifest.json" not in names or "chunks.jsonl" not in names:
            raise ValueError("manifest.json / chunks.jsonl 이 없는 팩")
        m = json.loads(zf.read(names["manifest.json"]))
        if m.get("format") != FORMAT:
            raise ValueError(f"지원하지 않는 팩 포맷: {m.get('format')}")
        pid = "".join(ch for ch in str(m.get("id", "")) if ch.isalnum() or ch in "-_.")
        if not pid:
            raise ValueError("manifest.id 누락")
        was_enabled = self.registry.get(pid, {}).get("enabled", False)
        self.loaded.pop(pid, None)
        dest = self.root / pid
        tmp = self.root / f".{pid}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        for base, full in names.items():      # 허용 파일명만, 경로 무시(zip slip 방지)
            if base in ALLOWED:
                with zf.open(full) as src, open(tmp / base, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
        n = sum(1 for _ in open(tmp / "chunks.jsonl", encoding="utf-8"))
        vp = tmp / "vectors.npy"
        if vp.exists():
            v = np.load(vp, mmap_mode="r")
            if v.shape[0] != n:
                vp.unlink()
                m["embedding"] = None
        shutil.rmtree(dest, ignore_errors=True)
        tmp.rename(dest)
        (dest / "manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")
        self.registry[pid] = {"enabled": was_enabled, "imported": time.time(), "file": filename}
        self._save()
        info = {"id": pid, "chunks": n, "replaced": was_enabled}
        if self._needs_embedding(pid):
            if self.embedder.enabled:
                info["embedding_job"] = True
                asyncio.create_task(self.reembed(pid))
            else:
                info["warning"] = "벡터 없음/모델 불일치 — 임베딩 엔드포인트가 없어 키워드(BM25) 검색만 사용"
        if was_enabled:
            await self.enable(pid)
        return info

    def _needs_embedding(self, pid: str) -> bool:
        m = self._manifest(pid)
        return not (self.root / pid / "vectors.npy").exists() or (m.get("embedding") or {}).get("model") != self.embedder.model

    async def reembed(self, pid: str) -> None:
        job = self.jobs[pid] = {"state": "embedding", "done": 0, "total": 0, "error": ""}
        try:
            path = self.root / pid
            with open(path / "chunks.jsonl", encoding="utf-8") as f:
                texts = [json.loads(line)["text"] for line in f if line.strip()]
            job["total"] = len(texts)
            parts = []
            step = 256
            for i in range(0, len(texts), step):
                parts.append((await self.embedder.embed(texts[i:i + step])).astype(np.float16))
                job["done"] = min(i + step, len(texts))
            vec = np.concatenate(parts) if parts else np.zeros((0, 1), np.float16)
            np.save(path / "vectors.npy.tmp.npy", vec)
            (path / "vectors.npy.tmp.npy").replace(path / "vectors.npy")
            m = self._manifest(pid)
            m["embedding"] = {"model": self.embedder.model, "dim": int(vec.shape[1])}
            (path / "manifest.json").write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")
            job["state"] = "done"
            if self.registry.get(pid, {}).get("enabled"):
                self.loaded.pop(pid, None)
                await self.enable(pid)
        except Exception as e:  # noqa: BLE001
            job.update(state="error", error=f"{type(e).__name__}: {e}"[:300])

    async def delete(self, pid: str) -> None:
        self.loaded.pop(pid, None)
        self.registry.pop(pid, None)
        self._save()
        shutil.rmtree(self.root / pid, ignore_errors=True)

    # ------------------------------------------------------------------ enable / disable
    async def enable(self, pid: str) -> dict:
        if pid not in self.registry:
            raise KeyError(pid)
        lp = LoadedPack(self.root / pid, self._manifest(pid))
        await asyncio.to_thread(lp.load)
        self.loaded[pid] = lp
        self.registry[pid]["enabled"] = True
        self._save()
        return {"id": pid, "chunks": len(lp.chunks), "dense": lp.vectors is not None}

    def disable(self, pid: str) -> None:
        self.loaded.pop(pid, None)
        if pid in self.registry:
            self.registry[pid]["enabled"] = False
            self._save()

    async def load_enabled(self) -> None:
        for pid, r in list(self.registry.items()):
            if r.get("enabled"):
                try:
                    await self.enable(pid)
                except Exception as e:  # noqa: BLE001
                    self.jobs[pid] = {"state": "error", "error": f"로드 실패: {e}"}

    # ------------------------------------------------------------------ search
    def packs_for(self, source: str | None) -> list[LoadedPack]:
        out = []
        for lp in self.loaded.values():
            at = lp.manifest.get("applies_to") or ["*"]
            if source is None or "*" in at or source in at:
                out.append(lp)
        return out

    async def _qvec(self, q: str) -> np.ndarray | None:
        if not self.embedder.enabled:
            return None
        if q in self._qcache:
            return self._qcache[q]
        try:
            v = (await self.embedder.embed([q]))[0]
        except Exception:  # noqa: BLE001
            return None
        self._qcache[q] = v
        if len(self._qcache) > 2000:
            self._qcache.popitem(last=False)
        return v

    async def search(self, query: str, source: str | None = None, k: int | None = None,
                     pack_ids: list[str] | None = None, intent: str = "analyze", sig: str | None = None,
                     library: bool = True) -> list[dict]:
        """팩(하이브리드) + KB·TechDocs 라이브러리 결과를 순위 병합"""
        k = k or self.k
        if not query.strip():
            return []
        qv = None
        lib = []
        use_lib = library and not pack_ids and self.library and self.library.enabled
        if use_lib:
            qv = await self._qvec(query[:2000])
            try:
                env = self.env_fn() if self.env_fn else None
                lib = await asyncio.to_thread(self.library.search_sync, query, source, max(k, self.library.k), intent, sig, env, qv)
            except Exception:  # noqa: BLE001
                lib = []
        packs_res = await self._search_packs(query, source, k, pack_ids, qv)
        if not lib:
            return packs_res
        if not packs_res:
            return lib[:k]
        from ..knowledge import rrf_merge
        return rrf_merge(lib, packs_res, k=k)

    async def _search_packs(self, query: str, source: str | None, k: int, pack_ids: list[str] | None, qv=None) -> list[dict]:
        packs = [self.loaded[p] for p in pack_ids if p in self.loaded] if pack_ids else self.packs_for(source)
        if not packs or not query.strip():
            return []
        qv = qv if qv is not None else await self._qvec(query)
        qtok = tokenize(query)
        qids = extract_ids(query)
        results = []
        for lp in packs:
            if not lp.chunks:
                continue
            bm = lp.bm25.scores(qtok) if lp.bm25 else np.zeros(len(lp.chunks), np.float32)
            bm_n = bm / (bm.max() + 1e-9) if bm.max() > 0 else bm
            dense_ok = qv is not None and lp.vectors is not None and lp.vectors.shape[1] == qv.shape[0]
            if dense_ok:
                dn = np.asarray(lp.vectors @ qv.astype(lp.vectors.dtype), dtype=np.float32)
                score = self.w_dense * dn + (1 - self.w_dense) * bm_n
            else:
                score = bm_n.copy()
            if qids:
                for i, ids in enumerate(lp.ids):
                    if ids & qids:
                        score[i] += 1.0
            top = np.argsort(-score)[: k * 2]
            for i in top:
                if score[i] < self.min_score:
                    continue
                c = lp.chunks[int(i)]
                results.append({"pack": lp.manifest.get("id"), "pack_name": lp.manifest.get("name"),
                                "score": round(float(score[i]), 3), "title": c.get("title", ""), "url": c.get("url", ""),
                                "type": c.get("type", "doc"), "doc_id": c.get("doc_id", ""), "published": c.get("published", ""),
                                "text": c["text"], "mode": "hybrid" if dense_ok else "bm25"})
        results.sort(key=lambda r: -r["score"])
        seen, out = set(), []
        for r in results:                      # 같은 문서 중복 청크는 1개만
            key = (r["pack"], r["doc_id"] or r["title"])
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
            if len(out) >= k:
                break
        return out

    def status(self) -> dict:
        return {"packs_total": len(self.registry), "enabled": [p for p in self.loaded],
                "chunks_loaded": sum(len(p.chunks) for p in self.loaded.values()),
                "embedding": self.embedder.status, "jobs": self.jobs}
