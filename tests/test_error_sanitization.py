"""Unit tests for 500-response error sanitization.

Confirms unexpected exceptions no longer leak their class name or message to
the client on /search and /answer. The real detail must still reach stderr
(via httputil.send_error's traceback log), but the HTTP body must contain
only the generic public message.

Stdlib unittest only. This module imports blkchain.api, which is light (only
config/httputil/retrieve, no model load) -- it must NOT import
blkchain.embed_server, which loads MLX models at import time.
"""
import io
import json
import sys
import types
import unittest
from unittest import mock

from blkchain import api, httputil


class FakeHandler:
    """Stand-in for BaseHTTPRequestHandler: captures the response instead of
    writing to a real socket. Same pattern as tests/test_httputil.py."""

    def __init__(self, body: bytes, path: str = "/x"):
        self.rfile = io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body))}
        self.path = path
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, code):
        self.status = code

    def send_header(self, *a):
        pass

    def end_headers(self):
        pass


class SendErrorTest(unittest.TestCase):
    """httputil.send_error must return only the public message, never the
    exception type or str(e)."""

    def test_hides_exception_detail(self):
        h = FakeHandler(b"")
        try:
            raise RuntimeError("db password is hunter2")
        except RuntimeError as e:
            httputil.send_error(h, 500, "internal error during search", exc=e)
        self.assertEqual(h.status, 500)
        body = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(body), {"error": "internal error during search"})
        self.assertNotIn("hunter2", body)
        self.assertNotIn("RuntimeError", body)

    def test_no_exc_still_sends_public_message(self):
        h = FakeHandler(b"")
        httputil.send_error(h, 503, "answer unavailable")
        self.assertEqual(h.status, 503)
        self.assertEqual(json.loads(h.wfile.getvalue()), {"error": "answer unavailable"})


def _drive_post(body: bytes, path: str) -> FakeHandler:
    h = FakeHandler(body, path)
    h._send = types.MethodType(api.Handler._send, h)
    api.Handler.do_POST(h)
    return h


class SearchErrorSanitizationTest(unittest.TestCase):
    def test_search_500_is_sanitized(self):
        def boom(*a, **kw):
            raise RuntimeError("qdrant api key sk-secret123")

        with mock.patch.object(api, "kb_search", side_effect=boom):
            h = _drive_post(b'{"query": "test"}', "/search")

        self.assertEqual(h.status, 500)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "internal error during search"})
        self.assertNotIn("sk-secret123", raw)
        self.assertNotIn("RuntimeError", raw)


class AnswerErrorSanitizationTest(unittest.TestCase):
    def test_answer_500_is_sanitized(self):
        fake_agent = types.ModuleType("blkchain.agent")

        def boom(query):
            raise RuntimeError("internal token abc123secret")

        fake_agent.kb_answer = boom

        with mock.patch.dict(sys.modules, {"blkchain.agent": fake_agent}):
            h = _drive_post(b'{"query": "test"}', "/answer")

        self.assertEqual(h.status, 500)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "internal error during answer"})
        self.assertNotIn("abc123secret", raw)
        self.assertNotIn("RuntimeError", raw)

    def test_answer_503_is_sanitized(self):
        # None in sys.modules makes the lazy `from blkchain.agent import
        # kb_answer` raise ImportError, exercising the import-failure branch.
        with mock.patch.dict(sys.modules, {"blkchain.agent": None}):
            h = _drive_post(b'{"query": "test"}', "/answer")

        self.assertEqual(h.status, 503)
        self.assertEqual(json.loads(h.wfile.getvalue()), {"error": "answer unavailable"})


if __name__ == "__main__":
    unittest.main()
