"""blkChain embed + rerank server (localhost, single-user).

Serves the dense embedder (Qwen3-Embedding-0.6B-8bit via mlx-embeddings) and the
jina-reranker-v3 listwise reranker (blkchain/reranker.py). Kept resident on its
own port so oMLX serves only the LLM (see RAG-BUILD-PLAN sections 9.2/9.4).
Inference is serialized (MLX is not thread-safe) and the Metal cache is released
after large batches. Stdlib http.server only, so no extra web dependency.

Endpoints:
  GET  /health              -> {"status": "ok", "embedder": true, "reranker": bool}
  POST /embed   {"texts": [...]}                 -> {"embeddings": [[...], ...], "dim": n}
  POST /rerank  {"query": "...", "documents":[...]} -> {"scores": [...]}
"""
from __future__ import annotations
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import mlx.core as mx

from blkchain import config
from blkchain.httputil import max_body_bytes, read_json_body, send_json

# /embed legitimately posts many texts in one batch, so allow a larger body
# than the retrieval API while still bounding it against a memory-DoS.
_MAX_BODY_BYTES = max_body_bytes(32 * 1024 * 1024)  # 32 MiB

# MLX forward passes are not thread-safe; serialize all inference.
_INFER_LOCK = threading.Lock()

# --- load embedder once at startup ------------------------------------------
print(f"[embed_server] loading embedder: {config.EMBEDDER_PATH}", flush=True)
from mlx_embeddings import load as _mlx_load, generate as _mlx_generate  # noqa: E402
_EMB_MODEL, _EMB_TOK = _mlx_load(str(config.EMBEDDER_PATH))
print("[embed_server] embedder ready", flush=True)

# --- optional reranker (implemented in blkchain/reranker.py) ----------------
try:
    from blkchain.reranker import rerank_documents  # (query:str, docs:list[str]) -> list[float]
    _RERANKER_OK = True
    print("[embed_server] reranker ready", flush=True)
except Exception as e:  # not implemented yet
    _RERANKER_OK = False
    _RERANK_ERR = f"{type(e).__name__}: {e}"
    print(f"[embed_server] reranker unavailable: {_RERANK_ERR}", flush=True)


def _embed(texts: list[str]) -> list[list[float]]:
    # Split into bounded forward passes so a large request never becomes one
    # multi-minute MLX forward. Inference stays serialized under the lock.
    rows: list[np.ndarray] = []
    with _INFER_LOCK:
        for i in range(0, len(texts), config.EMBED_SUBBATCH):
            out = _mlx_generate(_EMB_MODEL, _EMB_TOK, texts[i:i + config.EMBED_SUBBATCH])
            embs = out.text_embeds if hasattr(out, "text_embeds") else out
            arr = np.array(embs).astype("float32")
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            rows.append(arr)
        # Release Metal buffers after a large (index-time) batch so memory does
        # not accumulate across a big re-index; small queries skip this.
        if len(texts) >= config.EMBED_CACHE_RELEASE_AFTER:
            mx.clear_cache()
    return np.vstack(rows).tolist()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, obj: dict):
        send_json(self, code, obj)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "embedder": True, "reranker": _RERANKER_OK})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        req, err_code, err_msg = read_json_body(self, _MAX_BODY_BYTES)
        if err_code is not None:
            return self._send(err_code, {"error": err_msg})

        if self.path == "/embed":
            texts = req.get("texts")
            if not isinstance(texts, list) or not texts:
                return self._send(400, {"error": "texts must be a non-empty list"})
            try:
                embs = _embed([str(t) for t in texts])
                return self._send(200, {"embeddings": embs, "dim": len(embs[0]) if embs else 0})
            except Exception as e:
                return self._send(500, {"error": f"embed failed: {type(e).__name__}: {e}"})

        if self.path == "/rerank":
            if not _RERANKER_OK:
                return self._send(503, {"error": f"reranker not available: {_RERANK_ERR}"})
            query = req.get("query")
            docs = req.get("documents")
            if not isinstance(query, str) or not isinstance(docs, list) or not docs:
                return self._send(400, {"error": "need query:str and documents:non-empty list"})
            try:
                with _INFER_LOCK:
                    scores = rerank_documents(query, [str(d) for d in docs])
                return self._send(200, {"scores": list(scores)})
            except Exception as e:
                return self._send(500, {"error": f"rerank failed: {type(e).__name__}: {e}"})

        self._send(404, {"error": "not found"})


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True   # rebind immediately after a restart
    daemon_threads = True        # don't block shutdown on in-flight requests


def main():
    addr = (config.EMBED_SERVER_HOST, config.EMBED_SERVER_PORT)
    httpd = _Server(addr, Handler)
    print(f"[embed_server] listening on http://{addr[0]}:{addr[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())
