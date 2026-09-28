#!/bin/sh
# Start the resident embed + rerank server (localhost:8100).
# Run from the blkChain project root.
cd "$(dirname "$0")/.." || exit 1
exec .venv/bin/python -m blkchain.embed_server
