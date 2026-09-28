"""Central configuration for the blkChain offensive-security RAG system.

The project is self-contained: code defaults to project-relative paths, and any
machine-specific location (corpora, models, wordlists) is supplied via the
environment or a gitignored `.env` at the project root. No path assumes a
particular parent or sibling directory. Secrets are read from the environment
only (never hardcoded). See `.env.example` for every override.
"""
from __future__ import annotations
import os
from pathlib import Path

# --- Layout -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent          # .../blkChain


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into the environment.

    No dependency; an already-set environment variable always wins (setdefault),
    so real env > .env > code default. Malformed lines are ignored.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


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
    ''
    roots = [r for r in (SECLISTS_DIR, SKILLS_DIR, SOURCES_DIR, WSTG_PDF.parent) if r]
    return tuple(dict.fromkeys(roots))  # de-dupe, preserve order

# --- LLM (oMLX, serves the Gemma4 MoE) --------------------------------------
LLM_BASE_URL = os.environ.get("OMLX_BASE_URL", "http://127.0.0.1:8000/v1")
LLM_MODEL = os.environ.get("OMLX_MODEL", "supergemma4-26b-uncensored-mlx-4bit-v2")
# Local oMLX API key: read from env; falls back to the oMLX settings file so
# the LLM key lives in exactly one place (never hardcoded here).
def omlx_api_key() -> str:
    v = os.environ.get("OMLX_API_KEY")
    if v:
        return v
    try:
        import json
        s = json.loads((Path.home() / ".omlx" / "settings.json").read_text())
        return s.get("auth", {}).get("api_key") or ""
    except Exception:
        return ""

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
RERANKER_PATH = MODELS_DIR / "jina-reranker-v3-4bit-mxfp4"
EMBED_DIM = 1024  # Qwen3-Embedding-0.6B native dim (MRL-truncatable later)

EMBED_SERVER_HOST = os.environ.get("BLKCHAIN_EMBED_HOST", "127.0.0.1")
EMBED_SERVER_PORT = int(os.environ.get("BLKCHAIN_EMBED_PORT", "8100"))
EMBED_SERVER_URL = f"http://{EMBED_SERVER_HOST}:{EMBED_SERVER_PORT}"
# Max texts per MLX forward pass inside the embed server, so a large /embed
# request is split into bounded forward passes (avoids multi-minute batches).
EMBED_SUBBATCH = int(os.environ.get("BLKCHAIN_EMBED_SUBBATCH", "32"))
# Release the MLX Metal cache after an embed request of at least this many texts
# (i.e. index-time batches), so a big re-index does not bloat resident memory and
# starve the LLM. Small interactive queries stay below it, keeping their speed.
EMBED_CACHE_RELEASE_AFTER = int(os.environ.get("BLKCHAIN_EMBED_CACHE_RELEASE_AFTER", "64"))

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
POOL_SIZE = 50                           # deep pool before rerank (PROSE lesson 4)
TOP_K = 5                                # final results after rerank
RRF_K = 60                               # Qdrant native RRF fusion constant
# Payload/code files are indexed as content; wordlist-scale files are catalog-only.
CONTENT_FILE_MAX_BYTES = 256 * 1024
CONTENT_FILE_MAX_LINES = 2000

# --- Answer generation caps (agent.py) --------------------------------------
# These bound the answer/grading prefill so it stays under oMLX's prefill memory
# guard (the ~24 GB machine is tight with the ~13 GB LLM resident). They are
# env-overridable: after raising the oMLX guard tier / freeing RAM, widen
# ANSWER_MAX_CHUNKS for richer synthesis without editing code.
GRADE_MAX_TOKENS = int(os.environ.get("BLKCHAIN_GRADE_MAX_TOKENS", "200"))
ANSWER_MAX_TOKENS = int(os.environ.get("BLKCHAIN_ANSWER_MAX_TOKENS", "700"))
CONTEXT_CHARS_PER_CHUNK = int(os.environ.get("BLKCHAIN_CONTEXT_CHARS_PER_CHUNK", "1200"))
ANSWER_MAX_CHUNKS = int(os.environ.get("BLKCHAIN_ANSWER_MAX_CHUNKS", "4"))

# --- Web search (Tavily); key lives in ~/.zshrc as TAVILY_SETUP_TOKEN -------
TAVILY_API_KEY_ENV = "TAVILY_SETUP_TOKEN"
def tavily_api_key() -> str:
    return os.environ.get(TAVILY_API_KEY_ENV, "")

# --- API server (retrieval HTTP API the Go CLI + MCP call) ------------------
API_HOST = os.environ.get("BLKCHAIN_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("BLKCHAIN_API_PORT", "8200"))
API_URL = f"http://{API_HOST}:{API_PORT}"

# --- Corpus manifest --------------------------------------------------------
# Single source of truth for WHAT to ingest. No module hardcodes a document
# path; ingestion iterates CORPUS_SOURCES, all derived from the paths above.
# kind drives the chunking strategy (implemented in the ingest module):
#   markdown_vault | markdown | pdf | payloads | skills | seclists
from dataclasses import dataclass, field  # noqa: E402


@dataclass(frozen=True)
class SourceSpec:
    name: str
    path: Path
    kind: str
    exclude: tuple[str, ...] = field(default_factory=tuple)  # glob fragments to skip


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
]
# Optional corpora: included only when their location is configured (else skipped).
if SKILLS_DIR is not None:
    _CORPUS.append(SourceSpec("skills", SKILLS_DIR, "skills"))
if SECLISTS_DIR is not None:
    _CORPUS.append(SourceSpec("seclists", SECLISTS_DIR, "seclists",
                              exclude=(".png", ".jpg", ".jpeg", ".zip", ".gz", ".tar.gz")))

CORPUS_SOURCES: tuple[SourceSpec, ...] = tuple(_CORPUS)
