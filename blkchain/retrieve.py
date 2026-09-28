"""Hybrid retrieval for the blkChain RAG (RAG-BUILD-PLAN sections 6.4, 6.5).

kb_search embeds the query, runs one Qdrant hybrid query (dense + BM25 sparse,
fused by native RRF) to pull a deep pool, then reranks the pool via the embed
server's /rerank endpoint and returns the top_k results.
"""
from __future__ import annotations

import requests
from qdrant_client import QdrantClient, models

from blkchain import config

_qdrant: QdrantClient | None = None
_sparse_model: models.SparseTextEmbedding | None = None


def _client() -> QdrantClient:
    global _qdrant
    if _qdrant is None:
        _qdrant = QdrantClient(url=config.QDRANT_URL)
    return _qdrant


def _sparse() -> models.SparseTextEmbedding:
    global _sparse_model
    if _sparse_model is None:
        _sparse_model = models.SparseTextEmbedding(model_name=config.SPARSE_MODEL)
    return _sparse_model


def _embed_query(query: str) -> list[float]:
    resp = requests.post(f"{config.EMBED_SERVER_URL}/embed", json={"texts": [query]}, timeout=30)
    resp.raise_for_status()
    return resp.json()["embeddings"][0]


def _rerank(query: str, documents: list[str]) -> list[float]:
    resp = requests.post(
        f"{config.EMBED_SERVER_URL}/rerank",
        json={"query": query, "documents": documents},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["scores"]


def kb_search(
    query: str,
    filters: models.Filter | None = None,
    top_k: int | None = None,
    collection: str | None = None,
) -> list[dict]:
    """Hybrid dense+sparse retrieval with native RRF fusion, then rerank."""
    collection = collection or config.QDRANT_COLLECTION
    top_k = top_k or config.TOP_K

    dense_vector = _embed_query(query)
    sparse_embedding = next(_sparse().embed([query]))
    sparse_vector = models.SparseVector(
        indices=sparse_embedding.indices.tolist(),
        values=sparse_embedding.values.tolist(),
    )

    result = _client().query_points(
        collection_name=collection,
        prefetch=[
            models.Prefetch(
                query=dense_vector,
                using=config.DENSE_VECTOR_NAME,
                filter=filters,
                limit=config.POOL_SIZE,
            ),
            models.Prefetch(
                query=sparse_vector,
                using=config.SPARSE_VECTOR_NAME,
                filter=filters,
                limit=config.POOL_SIZE,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        query_filter=filters,
        limit=config.POOL_SIZE,
        with_payload=True,
    )
    points = result.points
    if not points:
        return []

    documents = [p.payload.get("text", "") for p in points]
    scores = _rerank(query, documents)

    ranked = sorted(zip(points, scores), key=lambda pair: pair[1], reverse=True)
    return [
        {"id": p.id, "score": score, "payload": p.payload}
        for p, score in ranked[:top_k]
    ]
