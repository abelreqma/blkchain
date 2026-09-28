"""blkChain retrieval HTTP API (localhost).

Thin JSON wrapper over the RAG core so the Go CLI and the Hermes MCP server
share one contract. Stdlib http.server only (no extra web dependency).

  GET  /health  -> {"status":"ok"}
  POST /search  {"query":str,"top_k":int?,"filters":{field:value}?}
                -> {"results":[{"id","score","payload":{...}}]}
  POST /answer  {"query":str}
                -> {"answer":str,"citations":[...],"used_web":bool,"results":[...]}

`filters` is a simple {field: value} map (e.g. {"source":"vault","type":"payload"})
translated to a Qdrant must-match filter; omit for no filtering.
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from blkchain import config
from blkchain.httputil import max_body_bytes, read_json_body, send_json
from blkchain.retrieve import kb_search

# Retrieval requests are small (a query plus optional filters); cap the body at
# a modest size so a malformed or oversized POST is rejected, not allocated.
_MAX_BODY_BYTES = max_body_bytes(4 * 1024 * 1024)  # 4 MiB


def _probe(url: str, timeout: float = 1.5) -> bool:
    """True if GET url returns a 2xx/3xx, else False. Never raises."""
    try:
        return requests.get(url, timeout=timeout).ok
    except Exception:
        return False


def health_status() -> dict:
    """API liveness plus reachability of its dependencies, so a caller can tell
    'up' from 'up but /search would 500'. Returns status ok only when Qdrant and
    the embed server both answer."""
    qdrant = _probe(config.QDRANT_URL.rstrip("/") + "/")
    embed = _probe(config.EMBED_SERVER_URL.rstrip("/") + "/health")
    return {
        "status": "ok" if (qdrant and embed) else "degraded",
        "qdrant": qdrant,
        "embed_server": embed,
    }


def _build_filter(filters: dict | None):
    """Translate a simple {field: value} map to a Qdrant Filter (must-match)."""
    if not filters:
        return None
    from qdrant_client import models
    conditions = [
        models.FieldCondition(key=k, match=models.MatchValue(value=v))
        for k, v in filters.items()
    ]
    return models.Filter(must=conditions)


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, obj: dict):
        send_json(self, code, obj)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, health_status())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        req, err_code, err_msg = read_json_body(self, _MAX_BODY_BYTES)
        if err_code is not None:
            return self._send(err_code, {"error": err_msg})

        query = req.get("query")
        if not isinstance(query, str) or not query.strip():
            return self._send(400, {"error": "query (non-empty string) required"})

        if self.path == "/search":
            try:
                results = kb_search(
                    query,
                    filters=_build_filter(req.get("filters")),
                    top_k=req.get("top_k"),
                )
                return self._send(200, {"results": results})
            except Exception as e:
                return self._send(500, {"error": f"search failed: {type(e).__name__}: {e}"})

        if self.path == "/answer":
            try:
                from blkchain.agent import kb_answer  # lazy: available once agent.py exists
            except Exception as e:
                return self._send(503, {"error": f"answer unavailable: {type(e).__name__}: {e}"})
            try:
                return self._send(200, kb_answer(query))
            except Exception as e:
                return self._send(500, {"error": f"answer failed: {type(e).__name__}: {e}"})

        self._send(404, {"error": "not found"})


def main():
    addr = (config.API_HOST, config.API_PORT)
    httpd = _Server(addr, Handler)
    print(f"[api] listening on http://{addr[0]}:{addr[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())
