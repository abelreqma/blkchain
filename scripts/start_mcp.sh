#!/bin/sh
# Hermes MCP stdio server for the blkChain RAG (kb_search / kb_answer).
# Runs from the project root so `-m blkchain.mcp_server` resolves; exec keeps
# stdin/stdout wired straight through for the MCP JSON-RPC transport.
cd "$(dirname "$0")/.." || exit 1
exec .venv/bin/python -m blkchain.mcp_server
