"""MCP server exposing the blkChain RAG to the Hermes agent.

Thin stdio client over the blkChain HTTP API (blkchain/api.py). Does NOT
import the retrieval/embedding/reranking modules or load any model in this
process, so Hermes can spawn it as a lightweight subprocess.

Tools:
  kb_search(query, top_k?, filters?) -> POST {API_URL}/search
  kb_answer(query)                   -> POST {API_URL}/answer
"""
from __future__ import annotations

import httpx

from blkchain import config
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

mcp = MCPServer("blkchain")


def _post(path: str, payload: dict) -> dict:
    try:
        resp = httpx.post(f"{config.API_URL}{path}", json=payload, timeout=60.0)
    except httpx.ConnectError as e:
        raise ToolError(f"blkChain API not reachable at {config.API_URL}") from e
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("error", resp.text)
        except Exception:
            detail = resp.text
        raise ToolError(f"blkChain API error ({resp.status_code}): {detail}")
    return resp.json()


@mcp.tool(
    description=(
        "Fast lookup in the blkChain offensive-security knowledge base. "
        "Hybrid dense+sparse retrieval with reranking, no generation, "
        "returns in well under a second. Use this as the daily driver for "
        "looking up notes, payloads, hacktricks entries, and pentest "
        "methodology. Prefer this over kb_answer unless synthesis across "
        "multiple sources is actually needed."
    )
)
def kb_search(query: str, top_k: int = config.TOP_K, filters: dict | None = None) -> list[dict]:
    """Search the blkChain knowledge base.

    Args:
        query: Natural-language or keyword query.
        top_k: Number of ranked results to return.
        filters: Optional {field: value} map to restrict results
            (e.g. {"source": "vault", "type": "payload"}).
    """
    data = _post("/search", {"query": query, "top_k": top_k, "filters": filters})
    results = []
    for r in data.get("results", []):
        payload = r.get("payload", {})
        text = payload.get("text", "")
        snippet = text if len(text) <= 500 else text[:500] + "..."
        results.append(
            {
                "id": r.get("id"),
                "score": r.get("score"),
                "source": payload.get("source"),
                "path": payload.get("path"),
                "section": payload.get("section"),
                "type": payload.get("type"),
                "text": snippet,
            }
        )
    return results


@mcp.tool(
    description=(
        "Synthesized answer from the blkChain knowledge base, with an "
        "agentic retrieval loop that can fall back to the web. Slower than "
        "kb_search (a few seconds, involves LLM generation), so use it for "
        "questions that need synthesis across sources rather than a quick "
        "lookup. Returns the answer text plus a Sources list and whether "
        "web search was used."
    )
)
def kb_answer(query: str) -> dict:
    """Get a synthesized answer from the blkChain knowledge base.

    Args:
        query: The question to answer.
    """
    data = _post("/answer", {"query": query})
    citations = data.get("citations", [])
    sources = [
        f"{c.get('source')}: {c.get('path')}" + (f" ({c.get('section')})" if c.get("section") else "")
        for c in citations
    ]
    return {
        "answer": data.get("answer", ""),
        "sources": sources,
        "used_web": data.get("used_web", False),
    }


if __name__ == "__main__":
    mcp.run()
