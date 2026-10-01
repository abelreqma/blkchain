"""Pure embed-server wire contract: request keys and response builders.

This module is deliberately dependency-free (stdlib only, no MLX / numpy /
requests), so the embed_server's JSON shapes live in one importable place. That
lets the contract be unit-tested without loading a model, and lets the Go
retrieval client (cli/internal/retrieval) bind its structs against a single
source of truth. embed_server.py calls into these builders; do not inline the
shapes there again.

The wire contract (kept stable, in lockstep with the Go client):
  GET  /health -> {"status": "ok", "embedder": true, "reranker": bool}
  POST /embed  {"texts": [str]}                    -> {"embeddings": [[float]], "dim": int}
  POST /rerank {"query": str, "documents": [str]}  -> {"scores": [float]}
"""
from __future__ import annotations

from typing import Any, Sequence

# --- request body keys ------------------------------------------------------
EMBED_TEXTS_KEY = "texts"
RERANK_QUERY_KEY = "query"
RERANK_DOCUMENTS_KEY = "documents"

EMBED_REQUEST_KEYS = (EMBED_TEXTS_KEY,)
RERANK_REQUEST_KEYS = (RERANK_QUERY_KEY, RERANK_DOCUMENTS_KEY)


# --- response builders ------------------------------------------------------
def health_response(reranker_ok: bool) -> dict[str, Any]:
    """GET /health body. embedder is always loaded when the server is up."""
    return {"status": "ok", "embedder": True, "reranker": bool(reranker_ok)}


def embed_response(embeddings: Sequence[Sequence[float]]) -> dict[str, Any]:
    """POST /embed 200 body. dim is the width of the first row, 0 when empty."""
    return {"embeddings": embeddings, "dim": len(embeddings[0]) if embeddings else 0}


def rerank_response(scores: Sequence[float]) -> dict[str, Any]:
    """POST /rerank 200 body. Coerces the score sequence to a plain list."""
    return {"scores": list(scores)}
