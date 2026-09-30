"""Qdrant index builder for blkChain (RAG-BUILD-PLAN section 6.3).

Creates the hybrid (named dense + BM25 sparse) collection and upserts chunks
in resumable sub-batches. Dense vectors come from the embed server over HTTP
(blkchain/embed_server.py) -- this module never loads an embedding model
itself. Sparse (BM25) vectors are computed client-side with FastEmbed, the
optional dependency bundled by qdrant-client[fastembed].
"""
from __future__ import annotations

import contextlib
import html
import ipaddress
import os
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

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
    index_scope: str | None = None,
    index_generation: str | None = None,
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
    seen_ids: list[str] = []

    def mark_seen() -> None:
        if index_scope is None or not seen_ids:
            return
        client.set_payload(
            collection_name=collection,
            payload={"snapshot_version": snapshot_version, "index_scope": index_scope,
                     "index_generation": index_generation},
            points=seen_ids.copy(),
        )
        seen_ids.clear()

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
                payload=chunk.payload(snapshot_version, index_scope, index_generation),
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
                    if index_scope is not None:
                        seen_ids.append(pid)
                        if len(seen_ids) >= 1000:
                            mark_seen()
                    skipped += 1
                    continue
                updated += 1
        pending.append(chunk)
        if len(pending) >= config.UPSERT_BATCH:
            flush(pending)
            pending = []
    flush(pending)
    mark_seen()

    return {"indexed": indexed, "updated": updated, "skipped": skipped, "batches": batches}


def _reconcile_corpus(
    client: QdrantClient,
    collection: str,
    index_generation: str,
    prune_missing_sources: bool = False,
) -> int:
    """Delete stale configured-corpus points after a complete successful ingest."""
    from blkchain import ingest

    # A missing configured source may mean an unmounted corpus volume. Preserve
    # its points instead of treating an unavailable source as an empty snapshot.
    managed_sources = {
        ingest._source_name(spec) for spec in config.CORPUS_SOURCES
        if prune_missing_sources or spec.path.exists()
    }
    stale: list[str] = []
    offset = None
    while True:
        records, offset = client.scroll(
            collection_name=collection,
            limit=1000,
            offset=offset,
            with_payload=["source", "path", "index_scope", "index_generation"],
            with_vectors=False,
        )
        for record in records:
            payload = record.payload or {}
            source = payload.get("source")
            if not isinstance(source, str) or source not in managed_sources:
                continue
            scope = payload.get("index_scope")
            path = str(payload.get("path") or "")
            legacy_corpus_point = scope is None and not (
                Path(path).is_absolute() or _URL_RE.match(path)
            )
            if ((scope == "corpus" or legacy_corpus_point)
                    and payload.get("index_generation") != index_generation):
                stale.append(str(record.id))
        if offset is None:
            break

    for start in range(0, len(stale), 1000):
        client.delete(collection_name=collection, points_selector=stale[start:start + 1000])
    return len(stale)


def build_index(
    chunks=None,
    snapshot_version: str | None = None,
    resume: bool = True,
    collection: str | None = None,
    prune_missing_sources: bool = False,
) -> dict:
    """Embed and upsert chunks into `collection` (default config.QDRANT_COLLECTION).

    Returns index counts; full manifest builds also report `deleted` for stale
    points removed after a successful complete pass. `updated` counts changed
    chunks re-embedded over their existing point. Set `prune_missing_sources`
    only when configured source roots were intentionally removed, not unmounted.
    """
    collection = collection or config.QDRANT_COLLECTION
    if snapshot_version is None:
        snapshot_version = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    reconcile = chunks is None
    if chunks is None:
        from blkchain import ingest  # lazy: ingest.py may not exist yet
        chunks = ingest.iter_chunks()

    client = QdrantClient(url=config.QDRANT_URL)
    ensure_collection(collection)  # create on a fresh Qdrant before scrolling for existing hashes
    sparse_model = SparseTextEmbedding(model_name=config.SPARSE_MODEL)
    existing = _existing_hashes(client, collection) if resume else {}

    generation = uuid.uuid4().hex if reconcile else None
    stats = _index_chunks(client, sparse_model, collection, chunks, existing, resume,
                          snapshot_version, "corpus" if reconcile else None, generation)
    if reconcile:
        stats["deleted"] = _reconcile_corpus(
            client, collection, generation, prune_missing_sources=prune_missing_sources
        )
    return stats


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
_MAX_URL_REDIRECTS = 5  # follow this many redirects, re-checking the host each hop

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
    from its extension unless `kind` forces one kind for everything.

    Enforces BLKCHAIN_ADD_MAX_FILES (default 5000) and BLKCHAIN_ADD_MAX_BYTES
    (default 512 MiB) during the walk (DoS guard) so a huge tree cannot exhaust
    memory/time on a single add. Read from env at call time; raise a clear
    ValueError when either cap is exceeded."""
    from blkchain import ingest

    max_files = int(os.environ.get("BLKCHAIN_ADD_MAX_FILES", "5000"))
    max_bytes = int(os.environ.get("BLKCHAIN_ADD_MAX_BYTES", str(512 * 1024 * 1024)))
    files = 0
    total_bytes = 0
    for file_path in ingest._iter_files(root, None, (".git",)):
        if file_path.suffix.lower() in _ADD_SKIP_DIR_EXTS:
            continue
        files += 1
        if files > max_files:
            raise ValueError(
                f"add: directory {root} exceeds BLKCHAIN_ADD_MAX_FILES ({max_files}); "
                f"narrow the path or raise the cap"
            )
        try:
            total_bytes += file_path.stat().st_size
        except OSError:
            pass
        if total_bytes > max_bytes:
            raise ValueError(
                f"add: directory {root} exceeds BLKCHAIN_ADD_MAX_BYTES ({max_bytes} bytes); "
                f"narrow the path or raise the cap"
            )
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


def _reject_unsafe_addr(addr: str, url: str, host: str) -> None:
    """Raise ValueError if addr is a private, loopback, link-local, reserved,
    multicast, or unspecified IP (SSRF guard). Blocks internal services and
    cloud metadata endpoints such as 169.254.169.254."""
    ip = ipaddress.ip_address(addr)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise ValueError(
            f"add: refusing to fetch {url!r} — host {host!r} resolves to "
            f"a non-public address ({addr})"
        )


def _resolve_safe_host(url: str) -> tuple[str, tuple]:
    """Resolve url's host ONCE, validate EVERY returned address, and return
    (host, addrinfo) for the first validated address.

    Resolving a single time and pinning the returned address (see
    _pin_resolution) closes the DNS-rebinding / TOCTOU window: without it,
    requests re-resolves the host at connect time, so a resolver returning a
    public IP at check time and a private IP at connect time would bypass the
    guard. Rejecting when ANY resolved address is non-public also stops a
    round-robin resolver from smuggling in a private record.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"add: could not parse a host from url: {url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"add: could not resolve host {host!r}: {exc}") from exc
    if not infos:
        raise ValueError(f"add: could not resolve host {host!r}")
    for info in infos:
        _reject_unsafe_addr(info[4][0], url, host)
    return host, infos[0]  # every address validated; pin the first for the fetch


def _reject_unsafe_host(url: str) -> None:
    """Back-compat wrapper: resolve + validate url's host, discarding the
    pinned address. Raises ValueError on an unsafe or unresolvable host."""
    _resolve_safe_host(url)


@contextlib.contextmanager
def _pin_resolution(host: str, addrinfo: tuple):
    """Force socket.getaddrinfo to return only `addrinfo` for `host` while the
    fetch runs, so requests/urllib3 connect to the exact validated IP instead
    of independently re-resolving (DNS-rebinding / TOCTOU guard). Other hosts
    resolve normally. Only the address is pinned; the URL hostname is left
    intact, so TLS SNI and certificate verification still validate against the
    hostname."""
    real_getaddrinfo = socket.getaddrinfo

    def pinned(node, *args, **kwargs):
        if node == host:
            return [addrinfo]
        return real_getaddrinfo(node, *args, **kwargs)

    socket.getaddrinfo = pinned
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo


def _fetch_url(url: str) -> tuple[str, str]:
    """GET url with a timeout and a bound on body size. Returns (text,
    content_type). Reads at most _MAX_URL_BYTES of the body.

    Redirects are followed manually (up to _MAX_URL_REDIRECTS). EACH hop
    resolves + validates its own host and pins that validated IP for the
    connection, so a legitimate redirect (http->https, CDN) works while a
    redirect to a private/internal address (SSRF) is rejected at that hop.
    """
    for _ in range(_MAX_URL_REDIRECTS + 1):
        host, addrinfo = _resolve_safe_host(url)  # resolve once + validate all
        with _pin_resolution(host, addrinfo):     # connect only to that IP
            resp = requests.get(url, timeout=_URL_FETCH_TIMEOUT, stream=True, allow_redirects=False)
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get("location", "")
                resp.close()
                if not location:
                    raise ValueError(f"add: {url!r} returned a redirect with no Location")
                url = urljoin(url, location)  # resolve relative redirects; re-validated next loop
                continue
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            body = bytearray()
            for piece in resp.iter_content(chunk_size=65536):
                body.extend(piece)
                if len(body) >= _MAX_URL_BYTES:
                    break
            resp.close()
            return bytes(body[:_MAX_URL_BYTES]).decode("utf-8", errors="ignore"), content_type
    raise ValueError(f"add: too many redirects fetching {url!r} (>{_MAX_URL_REDIRECTS})")


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

    # Stream chunks (generators, not materialized lists) into _index_chunks so
    # memory stays bounded on a large add; _index_chunks consumes and batches.
    if _URL_RE.match(path):
        chunks = _chunk_url(path, label, kind)
    else:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"add: no such file or directory: {path}")
        if p.is_dir():
            chunks = _chunk_dir(p, label, kind)
        else:
            file_kind = kind or _infer_kind(p.suffix)
            chunks = _chunk_file(p, label, file_kind, p.parent)

    ensure_collection(collection)
    client = QdrantClient(url=config.QDRANT_URL)
    sparse_model = SparseTextEmbedding(model_name=config.SPARSE_MODEL)
    existing = _existing_hashes(client, collection) if resume else {}

    return _index_chunks(client, sparse_model, collection, chunks, existing, resume,
                         snapshot_version, "manual")
