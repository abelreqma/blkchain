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


class RerankImportFailureSanitizationTest(unittest.TestCase):
    """embed_server's /rerank 503 (reranker import/startup failure) must return
    only a generic public message, never the underlying import-failure detail.

    embed_server loads MLX models at import time, so mlx / mlx_embeddings are
    faked and the reranker import is forced to raise with a secret-bearing
    message. The 503 body must not echo that message or the exception type."""

    def test_rerank_503_is_sanitized(self):
        secret = "reranker weights at /opt/secret/model.bin"

        fake_mlx = types.ModuleType("mlx")
        fake_mlx_core = types.ModuleType("mlx.core")
        fake_mlx.core = fake_mlx_core

        fake_mlx_embeddings = types.ModuleType("mlx_embeddings")
        fake_mlx_embeddings.load = lambda *a, **kw: (object(), object())
        fake_mlx_embeddings.generate = lambda *a, **kw: None

        fake_reranker = types.ModuleType("blkchain.reranker")

        def _raise(name):
            raise RuntimeError(secret)

        fake_reranker.__getattr__ = _raise

        patched = {
            "mlx": fake_mlx,
            "mlx.core": fake_mlx_core,
            "mlx_embeddings": fake_mlx_embeddings,
            "blkchain.reranker": fake_reranker,
            "blkchain.embed_server": None,  # force a fresh import under the fakes
        }
        with mock.patch.dict(sys.modules, patched):
            import importlib

            del sys.modules["blkchain.embed_server"]  # drop the None sentinel
            embed_server = importlib.import_module("blkchain.embed_server")

            self.assertFalse(embed_server._RERANKER_OK)

            h = FakeHandler(b'{"query": "q", "documents": ["d"]}', "/rerank")
            h._send = types.MethodType(embed_server.Handler._send, h)
            embed_server.Handler.do_POST(h)

        self.assertEqual(h.status, 503)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "reranker unavailable"})
        self.assertNotIn(secret, raw)
        self.assertNotIn("RuntimeError", raw)


if __name__ == "__main__":
    unittest.main()
