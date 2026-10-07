"""blkChain embed + rerank server (localhost, single-user).

Serves the dense embedder (Qwen3-Embedding-0.6B-4bit-DWQ via mlx-embeddings) and
a pluggable reranker (blkchain/reranker.py; gte-reranker-modernbert-base by
default, jina optional). Kept resident on its own port so oMLX serves only the
LLM (see RAG-BUILD-PLAN sections 9.2/9.4).
Inference is serialized (MLX is not thread-safe) and the Metal cache is released
after large batches. Stdlib http.server only, so no extra web dependency.

Endpoints:
  GET  /health              -> {"status": "ok", "embedder": true, "reranker": bool}
  POST /embed   {"texts": [...]}                 -> {"embeddings": [[...], ...], "dim": n}
  POST /rerank  {"query": "...", "documents":[...]} -> {"scores": [...]}
"""
from __future__ import annotations
import sys
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import mlx.core as mx

from blkchain import config, embed_wire
from blkchain.httputil import max_body_bytes, read_json_body, send_error, send_json

# /embed legitimately posts many texts in one batch, so allow a larger body
# than the retrieval API while still bounding it against a memory-DoS.
_MAX_BODY_BYTES = max_body_bytes(32 * 1024 * 1024)  # 32 MiB
# Defense-in-depth cap on element count per request (the body-byte cap above is
# the primary bound); a request over this is rejected before any inference.
_MAX_ELEMENTS = 200_000

# MLX forward passes are not thread-safe; serialize all inference.
_INFER_LOCK = threading.Lock()

# The server binds loopback by default (single-user localhost model). If it is
# bound to a wildcard address, warn once: it then has no auth in front of it.
if config.EMBED_SERVER_HOST not in ("127.0.0.1", "::1", "localhost"):
    print(f"[embed_server] WARNING: bound to {config.EMBED_SERVER_HOST!r}, not loopback; "
          "this server has no authentication and must not be exposed", flush=True)


def _scalar_texts(values: list) -> list[str] | None:
    """Coerce a list of request elements to strings, rejecting non-scalar
    elements (a nested list/dict/None) rather than str()-ing them into junk.
    Returns None when any element is not a str/int/float."""
    out: list[str] = []
    for v in values:
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            return None
        out.append(str(v))
    return out

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


def _validate_embed_arr(arr) -> None:
    """Raise ValueError if a batch's embedding array is degenerate: non-finite
    (NaN/Inf), or a width other than EMBED_DIM. A degenerate vector must be a hard
    error, never a silently-shipped bad vector; the Go client decodes a sanitized
    null to 0.0, which would corrupt retrieval without a trace."""
    if not np.isfinite(arr).all():
        raise ValueError("embedder produced a non-finite vector")
    if arr.shape[1] != config.EMBED_DIM:
        raise ValueError(f"embedder produced dim {arr.shape[1]}, expected {config.EMBED_DIM}")


def _embed(texts: list[str]) -> list[list[float]]:
    # Split into bounded forward passes so a large request never becomes one
    # multi-minute MLX forward. Inference stays serialized under the lock.
    rows: list[np.ndarray] = []
    with _INFER_LOCK:
        for i in range(0, len(texts), config.EMBED_SUBBATCH):
            out = _mlx_generate(_EMB_MODEL, _EMB_TOK, texts[i:i + config.EMBED_SUBBATCH])
            embs = out.text_embeds if hasattr(out, "text_embeds") else out
            # Cast in MLX first: some models (e.g. 4-bit DWQ) emit bfloat16, which
            # numpy cannot read directly ("bfloat16 is not a valid PEP 3118 buffer").
            arr = np.array(mx.array(embs).astype(mx.float32))
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            _validate_embed_arr(arr)
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
            self._send(200, embed_wire.health_response(_RERANKER_OK))
        else:
            self._send(404, {"error": "not found"})

    def _content_type_ok(self) -> bool:
        """On a non-loopback bind, require an application/json Content-Type so a
        cross-origin form/simple POST is rejected. On loopback (the default
        single-user model) any content type is accepted, preserving callers that
        do not set the header."""
        if config.EMBED_SERVER_HOST in ("127.0.0.1", "::1", "localhost"):
            return True
        ctype = str(self.headers.get("Content-Type", "")).split(";")[0].strip().lower()
        return ctype == "application/json"

    def do_POST(self):
        if not self._content_type_ok():
            return self._send(415, {"error": "Content-Type must be application/json"})
        req, err_code, err_msg = read_json_body(self, _MAX_BODY_BYTES)
        if err_code is not None:
            return self._send(err_code, {"error": err_msg})

        if self.path == "/embed":
            texts = req.get(embed_wire.EMBED_TEXTS_KEY)
            if not isinstance(texts, list) or not texts:
                return self._send(400, {"error": "texts must be a non-empty list"})
            if len(texts) > _MAX_ELEMENTS:
                return self._send(413, {"error": f"too many texts (>{_MAX_ELEMENTS})"})
            coerced = _scalar_texts(texts)
            if coerced is None:
                return self._send(400, {"error": "texts must all be strings"})
            try:
                embs = _embed(coerced)
                body = embed_wire.embed_response(embs)
            except Exception as e:
                return send_error(self, 500, "internal error during embed", exc=e)
            return self._send(200, body)  # build inside try, send outside (no double-write)

        if self.path == "/rerank":
            if not _RERANKER_OK:
                # The import-failure detail was already logged to stderr at startup
                # (see _RERANK_ERR above); never leak it to the client.
                return send_error(self, 503, "reranker unavailable")
            query = req.get(embed_wire.RERANK_QUERY_KEY)
            docs = req.get(embed_wire.RERANK_DOCUMENTS_KEY)
            if not isinstance(query, str) or not isinstance(docs, list) or not docs:
                return self._send(400, {"error": "need query:str and documents:non-empty list"})
            if len(docs) > _MAX_ELEMENTS:
                return self._send(413, {"error": f"too many documents (>{_MAX_ELEMENTS})"})
            coerced = _scalar_texts(docs)
            if coerced is None:
                return self._send(400, {"error": "documents must all be strings"})
            try:
                with _INFER_LOCK:
                    scores = rerank_documents(query, coerced)
                body = embed_wire.rerank_response(scores)
            except Exception as e:
                return send_error(self, 500, "internal error during rerank", exc=e)
            return self._send(200, body)  # build inside try, send outside (no double-write)

        self._send(404, {"error": "not found"})


class _Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6 if ":" in config.EMBED_SERVER_HOST else socket.AF_INET
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
