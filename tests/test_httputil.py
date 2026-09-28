"""Unit tests for blkchain.httputil.read_json_body.

Stdlib unittest only (no pytest dependency). These tests import ONLY
blkchain.httputil, never blkchain.embed_server, so no MLX model is loaded and
no server has to run. A fake handler stands in for BaseHTTPRequestHandler: its
`.headers` is a plain dict and its `.rfile` is an io.BytesIO.

Together they show the bug is closed: read_json_body RETURNS an error tuple for
a bogus Content-Length and for an oversized body, where the old inline
`int(self.headers.get("Content-Length", 0))` + unbounded `rfile.read(length)`
would raise (killing the handler thread) or over-allocate.
"""
import io
import unittest

from blkchain.httputil import read_json_body

MAX = 1024  # small cap so an "oversized" body is cheap to construct


class FakeHandler:
    """Minimal stand-in: dict headers + BytesIO body, like the real handler."""

    def __init__(self, body: bytes, content_length):
        self.rfile = io.BytesIO(body)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length


class ReadJsonBodyTest(unittest.TestCase):
    def test_valid_json(self):
        body = b'{"query": "hello", "top_k": 3}'
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(obj, {"query": "hello", "top_k": 3})
        self.assertIsNone(code)
        self.assertIsNone(msg)

    def test_missing_content_length_is_empty_dict(self):
        h = FakeHandler(b"", None)
        obj, code, msg = read_json_body(h, MAX)
        self.assertEqual(obj, {})
        self.assertIsNone(code)
        self.assertIsNone(msg)

    def test_non_numeric_content_length(self):
        # Old code: int("abc") raised ValueError before the try -> dead thread.
        h = FakeHandler(b'{"query": "x"}', "abc")
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertEqual(msg, "invalid Content-Length")

    def test_negative_content_length(self):
        h = FakeHandler(b'{"query": "x"}', "-5")
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertEqual(msg, "invalid Content-Length")

    def test_oversized_body_413(self):
        # Claim a length past the cap; helper rejects BEFORE reading/allocating.
        h = FakeHandler(b"", str(MAX + 1))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 413)
        self.assertEqual(msg, "request body too large")

    def test_malformed_json_400(self):
        body = b"{not valid json"
        h = FakeHandler(body, str(len(body)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(obj)
        self.assertEqual(code, 400)
        self.assertTrue(msg.startswith("bad json:"))

    def test_oversized_body_not_over_read(self):
        # A body exactly at the cap is accepted and read in full.
        payload = b'{"k": "' + b"a" * (MAX - 10) + b'"}'
        self.assertLessEqual(len(payload), MAX)
        h = FakeHandler(payload, str(len(payload)))
        obj, code, msg = read_json_body(h, MAX)
        self.assertIsNone(code)
        self.assertEqual(obj["k"], "a" * (MAX - 10))


if __name__ == "__main__":
    unittest.main()
