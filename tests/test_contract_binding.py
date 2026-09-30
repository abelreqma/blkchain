''
import json
import os
import unittest
from pathlib import Path

from blkchain import config, schema

_ROOT = Path(__file__).resolve().parent.parent
_RAG_JSON = _ROOT / "blkchain" / "contract" / "rag.json"


class RagJsonMatchesConfigTest(unittest.TestCase):
    ''

    def setUp(self):
        self.rag = json.loads(_RAG_JSON.read_text())

    def test_vector_names_and_sparse_model_match(self):
        self.assertEqual(config.DENSE_VECTOR_NAME, self.rag["dense_vector_name"])
        self.assertEqual(config.SPARSE_VECTOR_NAME, self.rag["sparse_vector_name"])
        self.assertEqual(config.SPARSE_MODEL, self.rag["sparse_model"])

    def test_embed_server_url_matches_default(self):
        # EMBED_SERVER_URL is derived from BLKCHAIN_EMBED_HOST/PORT; only assert
        # the contract default when neither is overridden (as the Go builtin
        # default is a fixed constant).
        if os.environ.get("BLKCHAIN_EMBED_HOST") or os.environ.get("BLKCHAIN_EMBED_PORT"):
            self.skipTest("embed host/port overridden in env")
        self.assertEqual(config.EMBED_SERVER_URL, self.rag["embed_server_url"])


class PayloadContractKeysTest(unittest.TestCase):
    """Chunk.payload() must carry every key the Go retrieval.Payload reads,
    reciprocal to TestPayloadContractKeys. Extra keys (identifiers, blurb,
    snapshot_version, content_hash, an optional origin, ...) are allowed."""

    GO_READ_KEYS = {"source", "path", "section", "type", "text", "cwe_class"}

    def test_payload_has_every_go_read_key(self):
        chunk = schema.Chunk(
            id="i", text="t", source="wstg", path="a.md",
            section="s", type="doc", cwe_class="ssrf",
        )
        keys = set(chunk.payload(snapshot_version="v1"))
        missing = self.GO_READ_KEYS - keys
        self.assertFalse(missing, f"payload is missing Go-read keys: {missing}")


class EmbedWireContractTest(unittest.TestCase):
    ''

    def setUp(self):
        try:
            from blkchain import embed_wire  # noqa: F401
        except ImportError:
            self.skipTest("blkchain.embed_wire is unavailable")
        self.embed_wire = embed_wire

    def test_request_keys(self):
        self.assertEqual(set(self.embed_wire.EMBED_REQUEST_KEYS), {"texts"})
        self.assertEqual(set(self.embed_wire.RERANK_REQUEST_KEYS), {"query", "documents"})

    def test_response_keys(self):
        self.assertEqual(set(self.embed_wire.health_response(True)), {"status", "embedder", "reranker"})
        self.assertEqual(set(self.embed_wire.embed_response([[0.1, 0.2]])), {"embeddings", "dim"})
        self.assertEqual(set(self.embed_wire.rerank_response([0.5])), {"scores"})

    def test_embed_response_dim(self):
        self.assertEqual(self.embed_wire.embed_response([[0.1, 0.2, 0.3]])["dim"], 3)
        self.assertEqual(self.embed_wire.embed_response([])["dim"], 0)


if __name__ == "__main__":
    unittest.main()
