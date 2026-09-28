"""Qdrant index builder for blkChain (RAG-BUILD-PLAN section 6.3).

Creates the hybrid (named dense + BM25 sparse) collection and upserts chunks
in resumable sub-batches. Dense vectors come from the embed server over HTTP
(blkchain/embed_server.py) -- this module never loads an embedding model
itself. Sparse (BM25) vectors are computed client-side with FastEmbed, the
optional dependency bundled by qdrant-client[fastembed].
"""
from __future__ import annotations

import html
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastembed import SparseTextEmbedding
from qdrant_client import QdrantClient, models

from blkchain import config
from blkchain.schema import Chunk, chunk_id, content_hash


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


def _index_chunks(
    client: QdrantClient,
    sparse_model: SparseTextEmbedding,
    collection: str,
    chunks,
    existing: dict[str, str | None],
    resume: bool,
    snapshot_version: str,
) -> dict:
    """Embed + upsert an iterable of chunks into `collection`, resumably.

    Shared by build_index (full corpus re-ingest) and add_path (incremental
    add of a single file/dir/URL) so the flush/embed/upsert/resume logic lives
    in exactly one place. Returns {"indexed", "updated", "skipped", "batches"};
    see build_index's docstring for field semantics.
    """
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

    return _index_chunks(client, sparse_model, collection, chunks, existing, resume, snapshot_version)


# --- blk add: load arbitrary content (file/dir/URL) into the live index ----

# Extensions skipped when walking a directory: not text, and not one of the
# kinds add_path knows how to chunk (markdown/pdf/plain).
_ADD_SKIP_DIR_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".bz2",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".class", ".o",
}

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MAX_URL_BYTES = 5 * 1024 * 1024  # bound a fetched body to 5 MiB (DoS guard)
_URL_FETCH_TIMEOUT = 30

_HTML_SKIP_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _infer_kind(ext: str) -> str:
    """Map a file extension to an add_path chunking kind."""
    ext = ext.lower()
    if ext in (".md", ".markdown"):
        return "markdown"
    if ext == ".pdf":
        return "pdf"
    return "plain"


def _chunk_file(file_path: Path, source: str, kind: str, base_dir: Path):
    """Chunk one file using the SAME chunkers ingest.py uses for the corpus."""
    from blkchain import ingest

    if kind == "markdown":
        yield from ingest._chunk_markdown_file(file_path, source, "doc")
    elif kind == "pdf":
        spec = config.SourceSpec(name=source, path=file_path, kind="pdf")
        yield from ingest._chunk_pdf(spec)
    else:
        yield from ingest._chunk_plain_file(file_path, source, "doc", base_dir)


def _chunk_dir(root: Path, source: str, kind: str | None):
    """Walk a directory and chunk each supported file, inferring kind per file
    from its extension unless `kind` forces one kind for everything."""
    from blkchain import ingest

    for file_path in ingest._iter_files(root, None, (".git",)):
        if file_path.suffix.lower() in _ADD_SKIP_DIR_EXTS:
            continue
        file_kind = kind or _infer_kind(file_path.suffix)
        yield from _chunk_file(file_path, source, file_kind, root)


def _html_to_text(markup: str) -> str:
    """Minimal HTML->text: drop script/style blocks, strip remaining tags,
    unescape entities, and collapse blank lines. Good enough for indexing a
    web page's prose; not a full HTML parser."""
    text = _HTML_SKIP_RE.sub(" ", markup)
    text = _HTML_TAG_RE.sub(" ", text)
    text = html.unescape(text)
    lines = (line.strip() for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def _chunk_text(text: str, source: str, path_str: str, markdown: bool):
    """Chunk in-memory text (a fetched URL's body) into Chunks, reusing the
    same splitting primitives (_markdown_sections / _recursive_split /
    _extract_identifiers) the file-based chunkers in ingest.py use — there is
    no file on disk here, so the file-based chunkers themselves don't apply."""
    from blkchain import ingest

    if not text.strip():
        return
    cwe = ingest._cwe_class_from_path(path_str)
    sections = ingest._markdown_sections(text) if markdown else [("", text)]
    idx = 0
    for breadcrumb, section_text in sections:
        for piece in ingest._recursive_split(section_text):
            piece = piece.strip()
            if not piece:
                continue
            yield Chunk(
                id=chunk_id(path_str, str(idx)),
                text=piece,
                source=source,
                path=path_str,
                section=breadcrumb,
                type="doc",
                identifiers=ingest._extract_identifiers(piece),
                cwe_class=cwe,
            )
            idx += 1


def _fetch_url(url: str) -> tuple[str, str]:
    """GET url with a timeout and a bound on body size. Returns (text,
    content_type). Reads at most _MAX_URL_BYTES of the body."""
    resp = requests.get(url, timeout=_URL_FETCH_TIMEOUT, stream=True)
    resp.raise_for_status()
    content_type = resp.headers.get("content-type", "")
    body = bytearray()
    for piece in resp.iter_content(chunk_size=65536):
        body.extend(piece)
        if len(body) >= _MAX_URL_BYTES:
            break
    resp.close()
    return bytes(body[:_MAX_URL_BYTES]).decode("utf-8", errors="ignore"), content_type


def _chunk_url(url: str, source: str, kind: str | None):
    if kind == "pdf":
        raise ValueError("add: fetching a PDF over http(s) is not supported; download it first")
    raw, content_type = _fetch_url(url)
    if "html" in content_type.lower():
        text = _html_to_text(raw)
        markdown = False
    else:
        text = raw
        markdown = True
    if kind == "plain":
        markdown = False
    elif kind == "markdown":
        markdown = True
    yield from _chunk_text(text, source, url, markdown)


def derive_source_label(path: str, source: str | None = None) -> str:
    """Default `source` label for add_path: the explicit override if given,
    else the URL host, or the file stem / directory name."""
    if source:
        return source
    if _URL_RE.match(path):
        return urlparse(path).netloc or path
    p = Path(path).expanduser()
    return p.name if p.is_dir() else p.stem


def add_path(
    path: str,
    *,
    source: str | None = None,
    kind: str | None = None,
    collection: str | None = None,
    resume: bool = True,
) -> dict:
    """Load a file, directory, or http(s) URL into the live index.

    Reuses the same chunkers build_index's corpus ingestion uses (see
    ingest.py) and the same embed/upsert path (_index_chunks), so re-adding
    unchanged content is a no-op under resume=True and only new/changed
    chunks are (re-)embedded. Upserts into `collection` (default
    config.QDRANT_COLLECTION), the same collection build_index writes to.

    `kind` forces the chunking strategy ("markdown", "plain", or "pdf")
    instead of inferring it from the file extension / URL content-type.
    `source` defaults to a label derived from the path (file stem / dir name
    / URL host). Returns the same stats dict as build_index.
    """
    collection = collection or config.QDRANT_COLLECTION
    snapshot_version = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    label = derive_source_label(path, source)

    if _URL_RE.match(path):
        chunks = list(_chunk_url(path, label, kind))
    else:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"add: no such file or directory: {path}")
        if p.is_dir():
            chunks = list(_chunk_dir(p, label, kind))
        else:
            file_kind = kind or _infer_kind(p.suffix)
            chunks = list(_chunk_file(p, label, file_kind, p.parent))

    ensure_collection(collection)
    client = QdrantClient(url=config.QDRANT_URL)
    sparse_model = SparseTextEmbedding(model_name=config.SPARSE_MODEL)
    existing = _existing_hashes(client, collection) if resume else {}

    return _index_chunks(client, sparse_model, collection, chunks, existing, resume, snapshot_version)
