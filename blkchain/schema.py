"""Shared data contract for ingest -> index -> retrieve.

The Chunk is the single unit passed from chunking to indexing; its Qdrant
payload is what retrieval reads back. Keep this stable: ingest.py, index.py,
and retrieve.py all depend on it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

# Allowed vocabularies (documented for producers/consumers; not enforced here).
SOURCES = (
    "vault", "hacktricks", "hacktricks-cloud", "payloads",
    "ai-pentest", "wstg", "skills", "seclists", "web",
)
TYPES = ("note", "finding", "http", "code", "payload", "wordlist", "doc", "template")


def chunk_id(source_path: str, span: str) -> str:
    """Deterministic chunk id: stable across re-ingest, so upserts are idempotent
    and resumable (PROSE lesson 7). `span` is any stable locator within the file
    (e.g. a char range "1024-1536" or a section id)."""
    return hashlib.sha256(f"{source_path}#{span}".encode()).hexdigest()


def content_hash(text: str) -> str:
    """Hash of a chunk's text, stored in the payload so resume can detect when a
    chunk's content changed (same id, new text) and re-embed it, rather than
    skipping it as already-indexed."""
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass
class Chunk:
    id: str                                   # chunk_id(...)
    text: str                                 # the content to embed / index
    source: str                               # one of SOURCES
    path: str                                 # file path or url (relative preferred)
    section: str = ""                         # heading breadcrumb / WSTG id
    type: str = "doc"                         # one of TYPES
    identifiers: dict[str, list[str]] = field(default_factory=dict)  # cve/attack/endpoint/param/product/tool
    cwe_class: str | None = None              # concept tag, e.g. "sqli"
    blurb: str | None = None                  # optional situating context for sparse + rerank
    extra: dict[str, Any] = field(default_factory=dict)  # line_count, size_bytes, worked, date, program, ...

    def payload(
        self,
        snapshot_version: str,
        index_scope: str | None = None,
        index_generation: str | None = None,
    ) -> dict[str, Any]:
        """Qdrant point payload (RAG-BUILD-PLAN section 6.2)."""
        p = {
            "source": self.source,
            "path": self.path,
            "section": self.section,
            "type": self.type,
            "identifiers": self.identifiers,
            "cwe_class": self.cwe_class,
            "blurb": self.blurb,
            "text": self.text,
            "snapshot_version": snapshot_version,
            "content_hash": content_hash(self.text),
        }
        p.update(self.extra)
        if index_scope is not None:
            p["index_scope"] = index_scope
        if index_generation is not None:
            p["index_generation"] = index_generation
        return p


def chunk_from_payload(point_id: str, payload: dict[str, Any]) -> Chunk:
    """Reconstruct a Chunk from a Qdrant payload (for retrieval results)."""
    known = {"source", "path", "section", "type", "identifiers", "cwe_class", "blurb", "text"}
    extra = {k: v for k, v in payload.items()
             if k not in known and k not in ("snapshot_version", "content_hash", "index_scope", "index_generation")}
    return Chunk(
        id=str(point_id),
        text=payload.get("text", ""),
        source=payload.get("source", ""),
        path=payload.get("path", ""),
        section=payload.get("section", ""),
        type=payload.get("type", "doc"),
        identifiers=payload.get("identifiers", {}) or {},
        cwe_class=payload.get("cwe_class"),
        blurb=payload.get("blurb"),
        extra=extra,
    )


def as_dict(chunk: Chunk) -> dict[str, Any]:
    return asdict(chunk)
