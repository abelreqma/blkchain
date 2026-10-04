"""Unit tests for 500-response error sanitization on the embed server.

Confirms unexpected exceptions and startup failures no longer leak their class
name or message to the client on /embed and /rerank. The real detail must still
reach stderr (via httputil.send_error's traceback log), but the HTTP body must
contain only the generic public message.

Stdlib unittest only. embed_server loads MLX models at import time, so the
tests import it fresh under fake mlx / mlx_embeddings / reranker modules.
"""
import contextlib
import importlib
import io
import json
import sys
import types
import unittest
from unittest import mock

from blkchain import httputil


class FakeHandler:
    """Stand-in for BaseHTTPRequestHandler: captures the response instead of
    writing to a real socket. Same pattern as tests/test_httputil.py."""

    def __init__(self, body: bytes, path: str = "/x", content_length=None):
        self.rfile = io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body) if content_length is None else content_length)}
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


@contextlib.contextmanager
def _embed_server(reranker, generate=None):
    """Yield a fresh blkchain.embed_server imported under fake MLX modules.

    `reranker` stands in for blkchain.reranker. `generate` stands in for
    mlx_embeddings.generate."""
    fake_mlx = types.ModuleType("mlx")
    fake_mlx_core = types.ModuleType("mlx.core")
    fake_mlx.core = fake_mlx_core

    fake_mlx_embeddings = types.ModuleType("mlx_embeddings")
    fake_mlx_embeddings.load = lambda *a, **kw: (object(), object())
    fake_mlx_embeddings.generate = generate or (lambda *a, **kw: None)

    patched = {
        "mlx": fake_mlx,
        "mlx.core": fake_mlx_core,
        "mlx_embeddings": fake_mlx_embeddings,
        "blkchain.reranker": reranker,
        "blkchain.embed_server": None,  # force a fresh import under the fakes
    }
    with mock.patch.dict(sys.modules, patched):
        del sys.modules["blkchain.embed_server"]  # drop the None sentinel
        yield importlib.import_module("blkchain.embed_server")


def _post(embed_server, path: str, body: bytes, content_length=None) -> FakeHandler:
    h = FakeHandler(body, path, content_length)
    h._send = types.MethodType(embed_server.Handler._send, h)
    h._content_type_ok = types.MethodType(embed_server.Handler._content_type_ok, h)
    embed_server.Handler.do_POST(h)
    return h


def _raising_reranker(exc):
    """A blkchain.reranker stand-in whose import fails with `exc`."""
    module = types.ModuleType("blkchain.reranker")

    def _raise(name):
        raise exc

    module.__getattr__ = _raise
    return module


def _working_reranker(fn):
    module = types.ModuleType("blkchain.reranker")
    module.rerank_documents = fn
    return module


class RerankImportFailureSanitizationTest(unittest.TestCase):
    """embed_server's /rerank 503 (reranker import/startup failure) must return
    only a generic public message, never the underlying import-failure detail."""

    def test_rerank_503_is_sanitized(self):
        secret = "reranker weights at /opt/secret/model.bin"

        with _embed_server(_raising_reranker(RuntimeError(secret))) as embed_server:
            self.assertFalse(embed_server._RERANKER_OK)
            h = _post(embed_server, "/rerank", b'{"query": "q", "documents": ["d"]}')

        self.assertEqual(h.status, 503)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "reranker unavailable"})
        self.assertNotIn(secret, raw)
        self.assertNotIn("RuntimeError", raw)


class EmbedServerErrorSanitizationTest(unittest.TestCase):
    def test_embed_500_is_sanitized(self):
        def boom(*a, **kw):
            raise RuntimeError("internal token abc123secret")

        with _embed_server(_working_reranker(lambda q, d: [0.0]), generate=boom) as embed_server:
            h = _post(embed_server, "/embed", b'{"texts": ["hello"]}')

        self.assertEqual(h.status, 500)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "internal error during embed"})
        self.assertNotIn("abc123secret", raw)
        self.assertNotIn("RuntimeError", raw)

    def test_rerank_500_is_sanitized(self):
        def boom(query, docs):
            raise RuntimeError("qdrant api key sk-secret123")

        with _embed_server(_working_reranker(boom)) as embed_server:
            h = _post(embed_server, "/rerank", b'{"query": "q", "documents": ["d"]}')

        self.assertEqual(h.status, 500)
        raw = h.wfile.getvalue().decode()
        self.assertEqual(json.loads(raw), {"error": "internal error during rerank"})
        self.assertNotIn("sk-secret123", raw)
        self.assertNotIn("RuntimeError", raw)


class EmbedServerWireTest(unittest.TestCase):
    """Strict JSON and bounded bodies on the embed server endpoints."""

    def test_rerank_nan_score_is_strict_json(self):
        def reject(token):
            raise ValueError(f"non-strict JSON constant {token}")

        with _embed_server(_working_reranker(lambda q, d: [float("nan"), 0.5])) as embed_server:
            h = _post(embed_server, "/rerank", b'{"query": "q", "documents": ["a", "b"]}')

        self.assertEqual(h.status, 200)
        self.assertEqual(json.loads(h.wfile.getvalue(), parse_constant=reject), {"scores": [None, 0.5]})

    def test_oversized_body_is_rejected_with_413(self):
        with _embed_server(_working_reranker(lambda q, d: [0.0])) as embed_server:
            too_big = embed_server._MAX_BODY_BYTES + 1
            h = _post(embed_server, "/embed", b"", content_length=too_big)

        self.assertEqual(h.status, 413)
        self.assertEqual(json.loads(h.wfile.getvalue()), {"error": "request body too large"})


class EmbedFinitenessTest(unittest.TestCase):
    """_validate_embed_arr rejects a degenerate batch (non-finite or wrong dim)
    so a bad vector is never shipped as a sanitized 0.0 (P5)."""

    def test_rejects_non_finite(self):
        import numpy as np
        from blkchain import config
        with _embed_server(_working_reranker(lambda q, d: [0.0])) as embed_server:
            good = np.zeros((1, config.EMBED_DIM), dtype="float32")
            embed_server._validate_embed_arr(good)  # no raise
            bad = good.copy()
            bad[0, 0] = np.nan
            with self.assertRaises(ValueError):
                embed_server._validate_embed_arr(bad)

    def test_rejects_wrong_dim(self):
        import numpy as np
        with _embed_server(_working_reranker(lambda q, d: [0.0])) as embed_server:
            with self.assertRaises(ValueError):
                embed_server._validate_embed_arr(np.zeros((1, 7), dtype="float32"))


class EmbedElementValidationTest(unittest.TestCase):
    """Non-scalar request elements are rejected with 400 before any inference."""

    def test_embed_rejects_non_scalar_element(self):
        with _embed_server(_working_reranker(lambda q, d: [0.0])) as embed_server:
            h = _post(embed_server, "/embed", b'{"texts": [["nested"]]}')
        self.assertEqual(h.status, 400)

    def test_rerank_rejects_non_scalar_element(self):
        with _embed_server(_working_reranker(lambda q, d: [0.0])) as embed_server:
            h = _post(embed_server, "/rerank", b'{"query": "q", "documents": [{"x": 1}]}')
        self.assertEqual(h.status, 400)


if __name__ == "__main__":
    unittest.main()
