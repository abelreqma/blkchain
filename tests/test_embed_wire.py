"""Unit tests for blkchain.embed_wire: the pure embed-server wire contract.

This module must import WITHOUT loading MLX/numpy (embed_server.py loads models
at import; the wire keys/response builders live here so the contract is
importable and testable independently). Stdlib unittest only.
"""
import unittest

from blkchain import embed_wire


class WireConstantsTest(unittest.TestCase):
    def test_request_key_constants(self):
        self.assertEqual(embed_wire.EMBED_TEXTS_KEY, "texts")
        self.assertEqual(embed_wire.RERANK_QUERY_KEY, "query")
        self.assertEqual(embed_wire.RERANK_DOCUMENTS_KEY, "documents")
        self.assertEqual(embed_wire.EMBED_REQUEST_KEYS, ("texts",))
        self.assertEqual(embed_wire.RERANK_REQUEST_KEYS, ("query", "documents"))


class WireResponseTest(unittest.TestCase):
    def test_health_response(self):
        self.assertEqual(embed_wire.health_response(True),
                         {"status": "ok", "embedder": True, "reranker": True})
        self.assertEqual(embed_wire.health_response(0),
                         {"status": "ok", "embedder": True, "reranker": False})

    def test_embed_response_reports_dim(self):
        self.assertEqual(embed_wire.embed_response([[1.0, 2.0, 3.0]]),
                         {"embeddings": [[1.0, 2.0, 3.0]], "dim": 3})

    def test_embed_response_empty_dim_zero(self):
        self.assertEqual(embed_wire.embed_response([]), {"embeddings": [], "dim": 0})

    def test_rerank_response_coerces_to_list(self):
        self.assertEqual(embed_wire.rerank_response((0.1, 0.2)), {"scores": [0.1, 0.2]})


if __name__ == "__main__":
    unittest.main()
