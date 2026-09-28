"""Qdrant index builder for blkChain (RAG-BUILD-PLAN section 6.3).

Creates the hybrid (named dense + BM25 sparse) collection and upserts chunks
in resumable sub-batches. Dense vectors come from the embed server over HTTP
(blkchain/embed_server.py) -- this module never loads an embedding model
itself. Sparse (BM25) vectors are computed client-side with FastEmbed, the
optional dependency bundled by qdrant-client[fastembed].
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import requests
from fastembed import SparseTextEmbedding
from qdrant_client import QdrantClient, models

from blkchain import config
from blkchain.schema import content_hash


def _point_id(chunk_id: str) -> str:
    """Map a chunk id to a valid Qdrant point id.

    Qdrant point ids must be an unsigned integer or a UUID. schema.chunk_id()
    returns a sha256 hex digest (64 hex chars), which is neither. Folding the
    first 128 bits of that digest into a UUID keeps the mapping deterministic
    (same chunk id always yields the same point id, so resume/upsert stays
    idempotent) while satisfying Qdrant's id format.
    """
    return str(uuid.UUID(hex=chunk_id[:32]))


def _embed_dense(texts: list[str]) -> list[list[float]]:
    resp = requests.post(
        f"{config.EMBED_SERVER_URL}/embed",
        json={"texts": texts},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    embeddings = data.get("embeddings")
    if not isinstance(embeddings, list) or len(embeddings) != len(texts):
        got = len(embeddings) if isinstance(embeddings, list) else type(embeddings).__name__
        raise RuntimeError(f"embed server returned {got} vectors for {len(texts)} texts")
    return embeddings


def ensure_collection(collection: str | None = None) -> None:
    """Create the Qdrant collection if it does not already exist."""
    collection = collection or config.QDRANT_COLLECTION
    client = QdrantClient(url=config.QDRANT_URL)
    if client.collection_exists(collection):
        return

    client.create_collection(
        collection_name=collection,
        vectors_config={
            config.DENSE_VECTOR_NAME: models.VectorParams(
                size=config.EMBED_DIM,
                distance=models.Distance(config.DENSE_DISTANCE),
            ),
        },
        sparse_vectors_config={
            config.SPARSE_VECTOR_NAME: models.SparseVectorParams(
                modifier=models.Modifier.IDF,  # BM25 needs the IDF term added at index time
            ),
        },
    )
    for field_name in ("source", "type", "cwe_class"):
        client.create_payload_index(
            collection_name=collection,
            field_name=field_name,
            field_schema=models.PayloadSchemaType.KEYWORD,
        )


def _existing_hashes(client: QdrantClient, collection: str) -> dict[str, str | None]:
    """Map each existing point id to its stored content_hash (None for a legacy
    point that predates content hashing). Lets resume skip unchanged chunks and
    re-embed changed ones; since the id is stable, a re-embed overwrites the same
    point rather than creating a duplicate."""
    out: dict[str, str | None] = {}
    offset = None
    while True:
        records, offset = client.scroll(
            collection_name=collection,
            limit=1000,
            offset=offset,
            with_payload=["content_hash"],
            with_vectors=False,
        )
        for r in records:
            out[str(r.id)] = (r.payload or {}).get("content_hash")
        if offset is None:
            break
    return out


def build_index(
    chunks=None,
    snapshot_version: str | None = None,
    resume: bool = True,
    collection: str | None = None,
) -> dict:
    """Embed and upsert chunks into `collection` (default config.QDRANT_COLLECTION).

    Returns {"indexed": n, "updated": u, "skipped": m, "batches": b}, where
    `updated` counts re-embedded chunks whose content changed (a subset of
    `indexed`, since they overwrite their existing point).
    """
    collection = collection or config.QDRANT_COLLECTION
    if snapshot_version is None:
        snapshot_version = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if chunks is None:
        from blkchain import ingest  # lazy: ingest.py may not exist yet
        chunks = ingest.iter_chunks()

    client = QdrantClient(url=config.QDRANT_URL)
    sparse_model = SparseTextEmbedding(model_name=config.SPARSE_MODEL)
    existing = _existing_hashes(client, collection) if resume else {}

    indexed = 0
    updated = 0
    skipped = 0
    batches = 0
    pending: list = []

    def flush(pending_chunks: list) -> None:
        nonlocal indexed, batches
        if not pending_chunks:
            return
        texts = [c.text for c in pending_chunks]
        dense_vecs = _embed_dense(texts)
        sparse_vecs = list(sparse_model.embed(texts))
        points = [
            models.PointStruct(
                id=_point_id(chunk.id),
                vector={
                    config.DENSE_VECTOR_NAME: dense,
                    config.SPARSE_VECTOR_NAME: models.SparseVector(
                        indices=sparse.indices.tolist(),
                        values=sparse.values.tolist(),
                    ),
                },
                payload=chunk.payload(snapshot_version),
            )
            for chunk, dense, sparse in zip(pending_chunks, dense_vecs, sparse_vecs)
        ]
        client.upsert(collection_name=collection, points=points)
        indexed += len(points)
        batches += 1

    for chunk in chunks:
        if resume:
            pid = _point_id(chunk.id)
            if pid in existing:
                stored = existing[pid]
                # Skip unchanged chunks (and legacy points with no stored hash);
                # re-embed when the content changed, overwriting the same id.
                if stored is None or stored == content_hash(chunk.text):
                    skipped += 1
                    continue
                updated += 1
        pending.append(chunk)
        if len(pending) >= config.UPSERT_BATCH:
            flush(pending)
            pending = []
    flush(pending)

    return {"indexed": indexed, "updated": updated, "skipped": skipped, "batches": batches}
