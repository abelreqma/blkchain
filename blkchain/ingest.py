"""Ingestion + structure-aware chunking for the blkChain corpus.

Every corpus path comes from `config.CORPUS_SOURCES`; nothing here hardcodes
a document path. See RAG-BUILD-PLAN.md sections 6.1 (structure-aware
chunking) and 6.1a (SecLists catalog-only indexing) for the design this
implements.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

import pypdf
from langchain_text_splitters import Language, MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from . import config
from .schema import Chunk, chunk_id

# --- token length -------------------------------------------------------
try:
    import tiktoken

    _ENCODER = tiktoken.get_encoding("cl100k_base")

    def _count_tokens(text: str) -> int:
        # disallowed_special=() so literal special-token strings in the corpus
        # (e.g. "<|endoftext|>", common in prompt-injection payloads) are counted
        # as normal text instead of raising ValueError.
        return len(_ENCODER.encode(text, disallowed_special=()))
except Exception:
    def _count_tokens(text: str) -> int:  # offline fallback: ~4 chars/token
        return max(1, len(text) // 4)

# --- cheap regex identifier extraction -----------------------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# path-keyword -> concept tag (checked against the lowercased full path)
_CWE_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("nosql injection", "nosqli"),
    ("cross site scripting", "xss"),
    ("xss", "xss"),
    ("server side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("local file inclusion", "lfi"),
    ("lfi", "lfi"),
    ("remote file inclusion", "rfi"),
    ("xxe", "xxe"),
    ("xml external entity", "xxe"),
    ("server side template injection", "ssti"),
    ("ssti", "ssti"),
    ("csrf", "csrf"),
    ("cross site request forgery", "csrf"),
    ("idor", "idor"),
    ("insecure direct object", "idor"),
    ("remote code execution", "rce"),
    ("command injection", "command_injection"),
    ("deserialization", "deserialization"),
    ("open redirect", "open_redirect"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("privilege escalation", "privesc"),
    ("privesc", "privesc"),
    ("jwt", "jwt"),
    ("sqlmap", "sqli"),
    ("clickjacking", "clickjacking"),
    ("prompt injection", "prompt_injection"),
)

# --- SecLists content-vs-catalog thresholds (RAG-BUILD-PLAN 6.1a) -------
_SECLISTS_CONTENT_DIRS = {"Web-Shells", "Payloads"}
_SECLISTS_CONTENT_EXTS = {".php", ".jsp", ".asp", ".py", ".sh", ".xml", ".svg"}

_PAYLOAD_CONTENT_EXTS = {".txt", ".php", ".py", ".xml", ".xsl", ".svg"}

_MD_HEADERS: list[tuple[str, str]] = [
    ("#", "h1"), ("##", "h2"), ("###", "h3"), ("####", "h4"), ("#####", "h5"),
]


def _extract_identifiers(text: str) -> dict[str, list[str]]:
    ids: dict[str, list[str]] = {}
    cves = sorted({m.upper() for m in _CVE_RE.findall(text)})
    if cves:
        ids["cve"] = cves
    attacks = sorted(set(_ATTACK_RE.findall(text)))
    if attacks:
        ids["attack"] = attacks
    return ids


def _cwe_class_from_path(path_str: str) -> str | None:
    low = path_str.lower()
    for keyword, tag in _CWE_KEYWORDS:
        if keyword in low:
            return tag
    return None


def _rel_path(file_path: Path) -> str:
    """Render a file path relative to whichever configured corpus root contains
    it (portable, readable), falling back to the absolute path."""
    for base in config.corpus_roots():
        try:
            return str(file_path.relative_to(base))
        except ValueError:
            continue
    return str(file_path)


def _source_name(spec: config.SourceSpec) -> str:
    # ai-pentest-pdf is the same corpus as ai-pentest, just its PDF file.
    return "ai-pentest" if spec.name == "ai-pentest-pdf" else spec.name


def _is_excluded(path: Path, exclude: tuple[str, ...]) -> bool:
    s = str(path)
    return any(frag in s for frag in exclude)


def _iter_files(root: Path, exts: set[str] | None, exclude: tuple[str, ...]) -> Iterator[Path]:
    if not root.exists():
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if _is_excluded(p, exclude):
            continue
        if exts is not None and p.suffix.lower() not in exts:
            continue
        yield p


# Map a file extension to a langchain Language for code-aware splitting. Names
# are resolved via getattr so an extension whose Language is absent in the
# installed langchain-text-splitters simply falls back to the generic splitter.
_LANG_BY_EXT: dict[str, str] = {
    ".py": "PYTHON", ".php": "PHP", ".js": "JS", ".ts": "TS", ".go": "GO",
    ".rb": "RUBY", ".rs": "RUST", ".java": "JAVA", ".c": "C", ".cpp": "CPP",
    ".cc": "CPP", ".cs": "CSHARP", ".sol": "SOL", ".html": "HTML", ".htm": "HTML",
    ".pl": "PERL", ".lua": "LUA", ".ps1": "POWERSHELL", ".swift": "SWIFT",
    ".kt": "KOTLIN", ".scala": "SCALA",
}


def _language_for(ext: str | None):
    """Return the langchain Language for a file extension, or None if unmapped."""
    if not ext:
        return None
    name = _LANG_BY_EXT.get(ext.lower())
    return getattr(Language, name, None) if name else None


def _recursive_split(text: str, ext: str | None = None) -> list[str]:
    """Split text into ~CHUNK_TARGET_TOKENS pieces. For a recognized code
    extension, use language-aware separators so functions/classes stay intact;
    otherwise use the generic prose separators (unchanged default behavior)."""
    lang = _language_for(ext)
    if lang is not None:
        splitter = RecursiveCharacterTextSplitter.from_language(
            language=lang,
            chunk_size=config.CHUNK_TARGET_TOKENS,
            chunk_overlap=config.CHUNK_OVERLAP_TOKENS,
            length_function=_count_tokens,
        )
    else:
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=config.CHUNK_TARGET_TOKENS,
            chunk_overlap=config.CHUNK_OVERLAP_TOKENS,
            length_function=_count_tokens,
            separators=["\n\n", "\n", " ", ""],
        )
    return splitter.split_text(text)


def _markdown_sections(text: str) -> list[tuple[str, str]]:
    """Split markdown into (heading breadcrumb, section_text) pairs."""
    splitter = MarkdownHeaderTextSplitter(headers_to_split_on=_MD_HEADERS, strip_headers=False)
    docs = splitter.split_text(text)
    if not docs:
        return [("", text)] if text.strip() else []
    out = []
    for doc in docs:
        breadcrumb = " > ".join(str(v) for v in doc.metadata.values() if v)
        out.append((breadcrumb, doc.page_content))
    return out


def _chunk_markdown_file(file_path: Path, source: str, chunk_type: str) -> Iterator[Chunk]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    if not text.strip():
        return
    path_str = _rel_path(file_path)
    cwe = _cwe_class_from_path(path_str)
    idx = 0
    for breadcrumb, section_text in _markdown_sections(text):
        for piece in _recursive_split(section_text):
            piece = piece.strip()
            if not piece:
                continue
            yield Chunk(
                id=chunk_id(path_str, str(idx)),
                text=piece,
                source=source,
                path=path_str,
                section=breadcrumb,
                type=chunk_type,
                identifiers=_extract_identifiers(piece),
                cwe_class=cwe,
            )
            idx += 1


def _chunk_markdown_dir(spec: config.SourceSpec) -> Iterator[Chunk]:
    chunk_type = "note" if spec.kind == "markdown_vault" else "doc"
    source = _source_name(spec)
    for file_path in _iter_files(spec.path, {".md", ".markdown"}, spec.exclude):
        yield from _chunk_markdown_file(file_path, source, chunk_type)


def _chunk_plain_file(file_path: Path, source: str, chunk_type: str, base_dir: Path) -> Iterator[Chunk]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    if not text.strip():
        return
    path_str = _rel_path(file_path)
    cwe = _cwe_class_from_path(path_str)
    try:
        rel_parts = file_path.relative_to(base_dir).parts
    except ValueError:
        rel_parts = ()
    section = rel_parts[0] if len(rel_parts) > 1 else ""
    for i, piece in enumerate(_recursive_split(text, file_path.suffix)):
        piece = piece.strip()
        if not piece:
            continue
        yield Chunk(
            id=chunk_id(path_str, str(i)),
            text=piece,
            source=source,
            path=path_str,
            section=section,
            type=chunk_type,
            identifiers=_extract_identifiers(piece),
            cwe_class=cwe,
        )


def _chunk_payloads(spec: config.SourceSpec) -> Iterator[Chunk]:
    source = _source_name(spec)
    allowed = _PAYLOAD_CONTENT_EXTS | {".md"}
    for file_path in _iter_files(spec.path, allowed, spec.exclude):
        if file_path.suffix.lower() == ".md":
            yield from _chunk_markdown_file(file_path, source, "doc")
        else:
            yield from _chunk_plain_file(file_path, source, "payload", spec.path)


_WSTG_SECTION_RE = re.compile(r"WSTG-[A-Z]+-\d+")


def _chunk_pdf(spec: config.SourceSpec) -> Iterator[Chunk]:
    source = _source_name(spec)
    file_path = spec.path
    if not file_path.exists():
        return
    path_str = _rel_path(file_path)
    cwe = _cwe_class_from_path(path_str)
    reader = pypdf.PdfReader(str(file_path))
    for page_num, page in enumerate(reader.pages, start=1):
        try:
            text = (page.extract_text() or "").strip()
        except Exception:
            continue
        if not text:
            continue
        m = _WSTG_SECTION_RE.search(text)
        section = f"{m.group(0)} (p.{page_num})" if m else f"page {page_num}"
        for i, piece in enumerate(_recursive_split(text)):
            piece = piece.strip()
            if not piece:
                continue
            yield Chunk(
                id=chunk_id(path_str, f"{page_num}-{i}"),
                text=piece,
                source=source,
                path=path_str,
                section=section,
                type="doc",
                identifiers=_extract_identifiers(piece),
                cwe_class=cwe,
            )


def _chunk_skills(spec: config.SourceSpec) -> Iterator[Chunk]:
    source = _source_name(spec)
    for file_path in _iter_files(spec.path, {".md"}, spec.exclude):
        yield from _chunk_markdown_file(file_path, source, "doc")


def _nearest_readme_snippet(dir_path: Path, root: Path) -> str:
    d = dir_path
    while True:
        for cand in ("README.md", "readme.md", "Readme.md"):
            f = d / cand
            if f.is_file():
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    text = ""
                for line in text.splitlines():
                    line = line.strip().lstrip("#").strip()
                    if line:
                        return line[:200]
        if d == root or d.parent == d:
            return ""
        d = d.parent


def _infer_purpose(file_path: Path, root: Path) -> str:
    name_guess = file_path.stem.replace("_", " ").replace("-", " ")
    readme_snip = _nearest_readme_snippet(file_path.parent, root)
    return f"{readme_snip} ({name_guess})" if readme_snip else name_guess


def _file_stats(file_path: Path, max_sample: int = 5) -> tuple[int, int, list[str]]:
    """Stream a file for (size_bytes, line_count, sample_lines) without
    ever loading a multi-GB wordlist fully into memory."""
    size_bytes = file_path.stat().st_size
    line_count = 0
    sample_lines: list[str] = []
    try:
        with file_path.open("rb") as f:
            for raw_line in f:
                line_count += 1
                if len(sample_lines) < max_sample:
                    sample_lines.append(raw_line.decode("utf-8", errors="ignore").rstrip())
    except OSError:
        pass
    return size_bytes, line_count, sample_lines


def _manifest_card(path_str: str, category: str, name: str, purpose: str, line_count: int,
                    size_bytes: int, sample_lines: list[str]) -> str:
    lines = [
        f"Wordlist: {name}",
        f"Path: {path_str}",
        f"Category: {category}",
        f"Purpose: {purpose}",
        f"Lines: {line_count}",
        f"Size: {size_bytes} bytes",
        "Sample:",
    ]
    lines.extend(f"  {s}" for s in sample_lines)
    return "\n".join(lines)


def _chunk_seclists_file(file_path: Path, source: str, root: Path) -> Iterator[Chunk]:
    path_str = _rel_path(file_path)
    cwe = _cwe_class_from_path(path_str)
    try:
        rel_parts = file_path.relative_to(root).parts
    except ValueError:
        rel_parts = ()
    category = rel_parts[0] if len(rel_parts) > 1 else ""
    ext = file_path.suffix.lower()
    size_bytes = file_path.stat().st_size

    content_eligible = (
        (category in _SECLISTS_CONTENT_DIRS or ext in _SECLISTS_CONTENT_EXTS)
        and size_bytes <= config.CONTENT_FILE_MAX_BYTES
    )
    if content_eligible:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = None
        if text is not None and text.strip():
            line_count = text.count("\n") + (1 if not text.endswith("\n") else 0)
            if line_count <= config.CONTENT_FILE_MAX_LINES:
                for i, piece in enumerate(_recursive_split(text, ext)):
                    piece = piece.strip()
                    if not piece:
                        continue
                    yield Chunk(
                        id=chunk_id(path_str, str(i)),
                        text=piece,
                        source=source,
                        path=path_str,
                        section=category,
                        type="payload",
                        identifiers=_extract_identifiers(piece),
                        cwe_class=cwe,
                    )
                return

    # catalog-only manifest card (over the cap, or not content-eligible)
    size_bytes, line_count, sample_lines = _file_stats(file_path)
    purpose = _infer_purpose(file_path, root)
    card = _manifest_card(path_str, category, file_path.name, purpose, line_count, size_bytes, sample_lines)
    yield Chunk(
        id=chunk_id(path_str, "manifest"),
        text=card,
        source=source,
        path=path_str,
        section=category,
        type="wordlist",
        identifiers={},
        cwe_class=cwe,
        extra={"line_count": line_count, "size_bytes": size_bytes},
    )


def _chunk_seclists(spec: config.SourceSpec) -> Iterator[Chunk]:
    source = _source_name(spec)
    for file_path in _iter_files(spec.path, None, spec.exclude):
        yield from _chunk_seclists_file(file_path, source, spec.path)


_DISPATCH = {
    "markdown_vault": _chunk_markdown_dir,
    "markdown": _chunk_markdown_dir,
    "payloads": _chunk_payloads,
    "pdf": _chunk_pdf,
    "skills": _chunk_skills,
    "seclists": _chunk_seclists,
}


def chunk_source(spec: config.SourceSpec) -> Iterator[Chunk]:
    """Chunk one SourceSpec according to its `kind`."""
    handler = _DISPATCH.get(spec.kind)
    if handler is None:
        raise ValueError(f"unknown source kind: {spec.kind!r}")
    yield from handler(spec)


def iter_chunks(sources: Iterable[config.SourceSpec] | None = None) -> Iterator[Chunk]:
    """Chunk all sources (default: config.CORPUS_SOURCES)."""
    for spec in (sources if sources is not None else config.CORPUS_SOURCES):
        yield from chunk_source(spec)
