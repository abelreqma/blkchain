"""Shared HTTP helpers for the localhost stdlib servers (api + embed_server).

Both servers subclass http.server.BaseHTTPRequestHandler and read a JSON POST
body. This module centralizes the two things that must not go wrong on that
path: a JSON response writer, and a body reader that treats Content-Length as
untrusted input (never raising, always bounded) instead of the naive
``int(Content-Length)`` + unbounded ``rfile.read`` that killed the handler
thread on a bad header and allowed a memory-DoS on a huge one.
"""
from __future__ import annotations

import json
import os


def max_body_bytes(default: int) -> int:
    """Body-size cap in bytes, overridable via env BLKCHAIN_MAX_BODY_BYTES.

    A non-integer or non-positive override is ignored in favor of `default`.
    """
    raw = os.environ.get("BLKCHAIN_MAX_BODY_BYTES")
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return val if val > 0 else default


def send_json(handler, code: int, obj: dict) -> None:
    """Write a JSON response (Content-Type + Content-Length + body)."""
    body = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json_body(handler, max_bytes: int):
    """Read and parse a JSON POST body. Never raises.

    Returns (obj, error_code, error_msg):
      - missing Content-Length            -> treated as 0 (empty body -> {})
      - non-integer / negative length     -> (None, 400, "invalid Content-Length")
      - length > max_bytes                -> (None, 413, "request body too large")
      - malformed JSON                    -> (None, 400, "bad json: ...")
      - success                           -> (obj, None, None)
    """
    try:
        length = int(handler.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        return None, 400, "invalid Content-Length"
    if length < 0:
        return None, 400, "invalid Content-Length"
    if length > max_bytes:
        return None, 413, "request body too large"
    try:
        req = json.loads(handler.rfile.read(length) or b"{}")
    except Exception as e:
        return None, 400, f"bad json: {e}"
    return req, None, None
