"""임베딩 클라이언트 — OpenAI 호환 /v1/embeddings (PAIS / vLLM 의 BAAI/bge-m3 등)."""
from __future__ import annotations

from typing import Any

import httpx
import numpy as np


class Embedder:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled") and self.cfg.get("base_url"))
        self.model = self.cfg.get("model", "BAAI/bge-m3")
        self.batch = int(self.cfg.get("batch_size", 32))
        self.max_chars = int(self.cfg.get("max_chars", 6000))
        headers = {"Content-Type": "application/json"}
        if self.cfg.get("api_key"):
            headers["Authorization"] = f"Bearer {self.cfg['api_key']}"
        self.base = str(self.cfg.get("base_url", "")).rstrip("/")
        self.http = httpx.AsyncClient(headers=headers, verify=bool(self.cfg.get("verify_tls")),
                                      timeout=httpx.Timeout(float(self.cfg.get("timeout", 120)), connect=10))
        self.status: dict[str, Any] = {"state": "disabled" if not self.enabled else "unknown", "model": self.model,
                                       "dim": None, "last_error": ""}

    async def embed(self, texts: list[str]) -> np.ndarray:
        """L2 정규화된 float32 행렬 반환."""
        if not self.enabled:
            raise RuntimeError("임베딩 엔드포인트 비활성")
        out = []
        for i in range(0, len(texts), self.batch):
            part = [t[: self.max_chars] or " " for t in texts[i:i + self.batch]]
            r = await self.http.post(f"{self.base}/embeddings", json={"model": self.model, "input": part})
            r.raise_for_status()
            data = sorted(r.json()["data"], key=lambda d: d["index"])
            out.extend(d["embedding"] for d in data)
        m = np.asarray(out, dtype=np.float32)
        m /= np.linalg.norm(m, axis=1, keepdims=True) + 1e-9
        self.status.update(state="ok", dim=int(m.shape[1]), last_error="")
        return m

    async def health(self) -> dict[str, Any]:
        if not self.enabled:
            return self.status
        try:
            await self.embed(["health check"])
        except Exception as e:  # noqa: BLE001
            self.status.update(state="down", last_error=f"{type(e).__name__}: {e}"[:300])
        return self.status
