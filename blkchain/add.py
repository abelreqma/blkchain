"""CLI entry point for `blk add`: python -m blkchain.add <path|url> [flags].

Wraps index.add_path so the Go CLI can shell out to it. Prints exactly one
JSON line of stats to stdout (for the Go side to parse); anything else
(errors, diagnostics) goes to stderr, keeping stdout machine-readable.
"""
from __future__ import annotations

import argparse
import json
import sys

from blkchain import index

# CLI --type values map to index.add_path's internal chunking-kind names.
_TYPE_MAP = {"md": "markdown", "txt": "plain", "pdf": "pdf"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m blkchain.add",
        description="Add a file, directory, or http(s) URL to the blkChain index.",
    )
    parser.add_argument("path", help="file, directory, or http(s) URL to index")
    parser.add_argument("--source", default=None, help="source label (default: derived from path)")
    parser.add_argument(
        "--type", dest="type_", choices=sorted(_TYPE_MAP), default=None,
        help="force chunking as md, txt, or pdf instead of inferring it",
    )
    parser.add_argument("--collection", default=None, help="Qdrant collection (default: config.QDRANT_COLLECTION)")
    args = parser.parse_args(argv)

    kind = _TYPE_MAP.get(args.type_) if args.type_ else None
    try:
        stats = index.add_path(args.path, source=args.source, kind=kind, collection=args.collection)
    except Exception as exc:  # noqa: BLE001 - report cleanly to the Go caller, no traceback noise
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # add_path's return stays the documented {indexed,updated,skipped,batches}
    # shape; "source" is added only here, for the Go CLI's success message.
    out = dict(stats)
    out["source"] = index.derive_source_label(args.path, args.source)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
