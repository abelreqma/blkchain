"""Central configuration for the blkChain offensive-security RAG system.

The project is self-contained: code defaults to project-relative paths, and any
machine-specific location (corpora, models, wordlists) is supplied via the
environment or a gitignored `.env` at the project root. No path assumes a
particular parent or sibling directory. Secrets are read from the environment
only (never hardcoded). See `.env.example` for every override.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

# --- Layout -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent          # .../blkChain


def _strip_unquoted_comment(val: str) -> str:
    """Cut an inline comment from an unquoted value: a '#' at the start of the
    value or following whitespace begins a comment; a '#' inside a token (e.g. a
    URL fragment) is kept."""
    for i, ch in enumerate(val):
        if ch == "#" and (i == 0 or val[i - 1].isspace()):
            return val[:i].strip()
    return val.strip()


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into the environment.

    No dependency; an already-set environment variable always wins (setdefault),
    so real env > .env > code default. Accepts an optional leading 'export ',
    strips an inline comment from an unquoted value, and keeps a quoted value
    verbatim (so a '#' inside quotes is part of the value). Malformed lines are
    ignored.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export"):].lstrip()
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]  # quoted: verbatim content, an inline '#' is kept
        else:
            val = _strip_unquoted_comment(val)
        os.environ.setdefault(key, val)


def _int_env(name: str, default: int, *, minimum: int | None = None,
             maximum: int | None = None) -> int:
    """Read an integer env var, falling back to `default` (with a stderr note) on
    a missing, unparsable, or out-of-range value, so a bad override cannot crash
    a later int(...) or produce a degenerate config (e.g. SUBBATCH=0)."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw.strip())
    except ValueError:
        print(f"[config] WARNING: {name}={raw!r} is not an integer; using {default}",
              file=sys.stderr, flush=True)
        return default
    if (minimum is not None and val < minimum) or (maximum is not None and val > maximum):
        print(f"[config] WARNING: {name}={val} out of range; using {default}",
              file=sys.stderr, flush=True)
        return default
    return val


_load_dotenv(ROOT / ".env")


def _path_env(name: str, default: Path | None) -> Path | None:
    """Resolve a path from env (with ~ expansion), or fall back to default."""
    v = os.environ.get(name, "").strip()
    if v:
        return Path(v).expanduser().resolve()
    return default


# Data locations. Defaults are project-relative and self-contained; point them
# at real corpora/models via .env or the environment (see .env.example).
# The two optional corpora (SecLists, agent skills) are simply skipped when unset.
MODELS_DIR = _path_env("BLKCHAIN_MODELS_DIR", ROOT / "models")
SOURCES_DIR = _path_env("BLKCHAIN_SOURCES_DIR", ROOT / "corpus")
WSTG_PDF = _path_env("BLKCHAIN_WSTG_PDF", SOURCES_DIR / "wstg-v4.2.pdf")
SECLISTS_DIR = _path_env("BLKCHAIN_SECLISTS_DIR", None)
SKILLS_DIR = _path_env("BLKCHAIN_SKILLS_DIR", None)


def corpus_roots() -> tuple[Path, ...]:
    """Base directories under which corpus files live, most specific first.

    Used to render stored document paths relative to a data root (readable and
    portable) instead of relative to any fixed parent directory.
    """
    roots = [r for r in (SECLISTS_DIR, SKILLS_DIR, SOURCES_DIR, WSTG_PDF.parent) if r]
    return tuple(dict.fromkeys(roots))  # de-dupe, preserve order

# --- LLM (oMLX, serves the Gemma4 MoE) --------------------------------------
LLM_BASE_URL = os.environ.get("OMLX_BASE_URL", "http://127.0.0.1:8000/v1")
LLM_MODEL = os.environ.get("OMLX_MODEL", "supergemma4-26b-uncensored-mlx-4bit-v2")
# Local oMLX API key: read from env; falls back to the oMLX settings file so
# the LLM key lives in exactly one place (never hardcoded here).
def omlx_api_key() -> str:
    # Secrets come from the environment only (project invariant); no settings-file
    # fallback. Returns "" when unset (the local endpoint may be keyless).
    return os.environ.get("OMLX_API_KEY", "")

# --- Embedder + reranker (served by embed_server on its own port) -----------
# EMBEDDER_PATH is env-overridable so embed_server can serve an alternate model
# (e.g. an A/B against Qwen3-Embedding-0.6B-4bit-DWQ) without editing code. A
# swapped embedder must keep EMBED_DIM (1024) or a new Qdrant collection is
# needed. BLKCHAIN_EMBEDDER_PATH may be absolute or relative to MODELS_DIR.
def _embedder_path() -> Path:
    v = os.environ.get("BLKCHAIN_EMBEDDER_PATH", "").strip()
    if not v:
        return MODELS_DIR / "Qwen3-Embedding-0.6B-4bit-DWQ"
    p = Path(v).expanduser()
    return p if p.is_absolute() else (MODELS_DIR / p)


EMBEDDER_PATH = _embedder_path()
EMBED_DIM = 1024  # Qwen3-Embedding-0.6B native dim (MRL-truncatable later)

# Select the reranker backend. ModernBERT and Qwen3 use Apache-2.0 models.
# Jina uses a CC-BY-NC-4.0 model. Each backend exposes rerank_documents.
RERANKER_KIND = os.environ.get("BLKCHAIN_RERANKER_KIND", "modernbert").strip().lower()


def _reranker_path() -> Path:
    v = os.environ.get("BLKCHAIN_RERANKER_PATH", "").strip()
    if v:
        p = Path(v).expanduser()
        return p if p.is_absolute() else (MODELS_DIR / p)
    if RERANKER_KIND == "modernbert":
        default = "gte-reranker-modernbert-base-mlx"
    elif RERANKER_KIND == "qwen3":
        default = "Qwen3-Reranker-0.6B-4bit"
    else:
        default = "jina-reranker-v3-4bit-mxfp4"
    return MODELS_DIR / default


RERANKER_PATH = _reranker_path()

EMBED_SERVER_HOST = os.environ.get("BLKCHAIN_EMBED_HOST", "").strip() or "127.0.0.1"
EMBED_SERVER_PORT = _int_env("BLKCHAIN_EMBED_PORT", 8100, minimum=1, maximum=65535)
_EMBED_URL_HOST = f"[{EMBED_SERVER_HOST}]" if ":" in EMBED_SERVER_HOST else EMBED_SERVER_HOST
EMBED_SERVER_URL = f"http://{_EMBED_URL_HOST}:{EMBED_SERVER_PORT}"
# Max texts per MLX forward pass inside the embed server, so a large /embed
# request is split into bounded forward passes (avoids multi-minute batches).
EMBED_SUBBATCH = _int_env("BLKCHAIN_EMBED_SUBBATCH", 32, minimum=1)
# Release the MLX Metal cache after an embed request of at least this many texts
# (i.e. index-time batches), so a big re-index does not bloat resident memory.
# Small interactive queries stay below it, keeping their speed.
EMBED_CACHE_RELEASE_AFTER = _int_env("BLKCHAIN_EMBED_CACHE_RELEASE_AFTER", 64, minimum=1)

# --- Qdrant -----------------------------------------------------------------
QDRANT_URL = os.environ.get("QDRANT_URL", "http://127.0.0.1:6333")
QDRANT_COLLECTION = os.environ.get("BLKCHAIN_COLLECTION", "blkchain")
DENSE_VECTOR_NAME = "dense"
SPARSE_VECTOR_NAME = "sparse"
DENSE_DISTANCE = "Cosine"
SPARSE_MODEL = "Qdrant/bm25"          # FastEmbed sparse model for the lexical leg
UPSERT_BATCH = 256                       # sub-batched, resumable (PROSE lesson 6)

# --- Chunking + retrieval params --------------------------------------------
CHUNK_TARGET_TOKENS = 400
CHUNK_OVERLAP_TOKENS = 60
RRF_K = 60                               # Qdrant native RRF fusion constant
# Payload/code files are indexed as content; wordlist-scale files are catalog-only.
CONTENT_FILE_MAX_BYTES = 256 * 1024
CONTENT_FILE_MAX_LINES = 2000
# Memory-safety bound on how many bytes any single text file (markdown/plain) is
# read into memory before chunking, so a pathologically large file cannot be
# fully materialized. Far above normal prose; wordlist-scale files take the
# seclists catalog-only path instead.
MAX_TEXT_FILE_BYTES = _int_env("BLKCHAIN_MAX_TEXT_FILE_BYTES", 8 * 1024 * 1024, minimum=1)
# Skip an Arsenal JSON file larger than this (a technique file is small; a huge
# one is malformed or hostile and could exhaust memory / recursion on parse).
MAX_JSON_FILE_BYTES = _int_env("BLKCHAIN_MAX_JSON_FILE_BYTES", 4 * 1024 * 1024, minimum=1)

# --- Corpus manifest --------------------------------------------------------
# Single source of truth for WHAT to ingest. No module hardcodes a document
# path; ingestion iterates CORPUS_SOURCES, all derived from the paths above.
# kind drives the chunking strategy (implemented in the ingest module):
#   markdown_vault | markdown | pdf | payloads | skills | seclists | json
from dataclasses import dataclass, field  # noqa: E402


@dataclass(frozen=True)
class SourceSpec:
    name: str
    path: Path
    kind: str
    # Fragments to skip, matched by ingest._is_excluded RELATIVE to `path`: a
    # fragment equal to a whole path component (a dir/file name like "docs" or
    # "LICENSE.md") excludes that component; a dot-prefixed fragment (".png") also
    # excludes a file whose name ends with it. Fragments are NOT substring-matched,
    # so a multi-component ("a/b") or infix fragment will not match.
    exclude: tuple[str, ...] = field(default_factory=tuple)


AI_PENTEST_DIR = SOURCES_DIR / "AI-penetration-testing"

# Sources under SOURCES_DIR are always listed; ingestion skips any that are
# absent (see ingest._iter_files / _chunk_pdf), so a partial corpus is fine.
_CORPUS: list[SourceSpec] = [
    SourceSpec("vault", SOURCES_DIR / "notes", "markdown_vault", exclude=(".obsidian",)),
    SourceSpec("hacktricks", SOURCES_DIR / "hacktricks" / "hacktricks", "markdown"),
    SourceSpec("hacktricks-cloud", SOURCES_DIR / "hacktricks" / "hacktricks-cloud", "markdown"),
    SourceSpec("payloads", SOURCES_DIR / "payloadsallthethings", "payloads",
               exclude=(".png", ".jpg", ".jpeg", ".zip", ".gz", ".tar.gz")),
    SourceSpec("ai-pentest", AI_PENTEST_DIR, "markdown"),
    SourceSpec("arc-pi-taxonomy", SOURCES_DIR / "arc_pi_taxonomy", "markdown", exclude=("docs", "LICENSE.md")),
    SourceSpec("wstg", WSTG_PDF, "pdf"),
    SourceSpec("ai-pentest-pdf", AI_PENTEST_DIR / "AI_ML_LLM_pentesting_resources.pdf", "pdf"),
    SourceSpec("arsenal-json", SOURCES_DIR / "arsenal" / "curated-en", "json"),
    SourceSpec("arsenal-checklists", SOURCES_DIR / "arsenal" / "checklists-en", "markdown"),
    SourceSpec("violin-skills", SOURCES_DIR / "violin-skills", "skills"),
    SourceSpec("offensive-skills", SOURCES_DIR / "skills", "skills"),
    SourceSpec("cai", SOURCES_DIR / "cai", "markdown"),
]
# Optional corpora: included only when their location is configured (else skipped).
if SKILLS_DIR is not None:
    _CORPUS.append(SourceSpec("skills", SKILLS_DIR, "skills"))
if SECLISTS_DIR is not None:
    _CORPUS.append(SourceSpec("seclists", SECLISTS_DIR, "seclists",
                              exclude=(".png", ".jpg", ".jpeg", ".zip", ".gz", ".tar.gz")))

CORPUS_SOURCES: tuple[SourceSpec, ...] = tuple(_CORPUS)
