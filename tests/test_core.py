"""Core RAG unit tests: pure logic and the resume/retrieval seams, exercised
with mocks so nothing here needs Qdrant, the embed server, or the LLM."""
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

import numpy as np

from blkchain import agent, api, index, ingest, retrieve
from blkchain.schema import Chunk, chunk_from_payload, chunk_id, content_hash


class SchemaTest(unittest.TestCase):
    def test_chunk_id_deterministic(self):
        a = chunk_id("path/to/doc.md", "3")
        b = chunk_id("path/to/doc.md", "3")
        c = chunk_id("path/to/doc.md", "4")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_content_hash_tracks_text(self):
        self.assertEqual(content_hash("abc"), content_hash("abc"))
        self.assertNotEqual(content_hash("abc"), content_hash("abd"))

    def test_payload_has_hash_and_roundtrip_excludes_meta(self):
        pl = Chunk(id="x", text="hi", source="s", path="p", extra={"line_count": 5}).payload("v1")
        self.assertEqual(pl["content_hash"], content_hash("hi"))
        back = chunk_from_payload("pid", pl)
        self.assertNotIn("content_hash", back.extra)
        self.assertNotIn("snapshot_version", back.extra)
        self.assertEqual(back.extra.get("line_count"), 5)


class PointIdTest(unittest.TestCase):
    def test_point_id_is_deterministic_uuid(self):
        cid = chunk_id("doc", "1")
        pid = index._point_id(cid)
        self.assertEqual(pid, index._point_id(cid))
        uuid.UUID(pid)  # raises if not a valid UUID


class IngestHelpersTest(unittest.TestCase):
    def test_extract_identifiers(self):
        ids = ingest._extract_identifiers("See CVE-2021-44228 and technique T1190 and T1059.001")
        self.assertEqual(ids["cve"], ["CVE-2021-44228"])
        self.assertIn("T1190", ids["attack"])
        self.assertIn("T1059.001", ids["attack"])

    def test_cwe_class_from_path(self):
        # matcher keys on contiguous substrings (the acronym, or space phrases)
        self.assertEqual(ingest._cwe_class_from_path("notes/sqli/dump.md"), "sqli")
        self.assertEqual(ingest._cwe_class_from_path("web/ssrf/metadata.md"), "ssrf")
        self.assertEqual(ingest._cwe_class_from_path("a/prompt injection/b.md"), "prompt_injection")
        self.assertIsNone(ingest._cwe_class_from_path("misc/notes.md"))

    def test_language_for_extension(self):
        self.assertEqual(ingest._language_for(".py").name, "PYTHON")
        self.assertEqual(ingest._language_for(".php").name, "PHP")
        self.assertIsNone(ingest._language_for(".txt"))
        self.assertIsNone(ingest._language_for(None))

    def test_recursive_split_code_vs_generic_both_chunk(self):
        code = "\n\n".join(f"def f{i}(x):\n    return x + {i}" for i in range(60))
        self.assertTrue(ingest._recursive_split(code))
        self.assertTrue(ingest._recursive_split(code, ".py"))

    def test_chunk_source_unknown_kind_raises(self):
        spec = ingest.config.SourceSpec("x", Path("/nope"), "bogus-kind")
        with self.assertRaises(ValueError):
            list(ingest.chunk_source(spec))

    def test_markdown_file_chunks(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "doc.md"
            f.write_text("# Title\n\nSome body text about XSS.\n\n## Sub\n\nMore text.\n")
            chunks = list(ingest._chunk_markdown_file(f, "vault", "note"))
        self.assertTrue(chunks)
        self.assertTrue(all(c.source == "vault" and c.type == "note" for c in chunks))
        self.assertTrue(any("XSS" in c.text or "text" in c.text for c in chunks))


class AgentPureTest(unittest.TestCase):
    def test_parse_grade_valid_and_embedded(self):
        g = agent._parse_grade('prose {"sufficient": true, "rewrite": "x", "use_web": false} tail')
        self.assertTrue(g["sufficient"])
        self.assertEqual(g["rewrite"], "x")
        self.assertFalse(g["use_web"])

    def test_parse_grade_garbage_defaults(self):
        g = agent._parse_grade("no json here")
        self.assertEqual(g, {"sufficient": False, "rewrite": "", "use_web": False})

    def test_parse_grade_malformed_json_defaults(self):
        g = agent._parse_grade("{not: valid, json}")
        self.assertFalse(g["sufficient"])

    def test_looks_like_cve_or_poc(self):
        self.assertTrue(agent._looks_like_cve_or_poc("exploit for CVE-2023-1234"))
        self.assertTrue(agent._looks_like_cve_or_poc("is there a PoC?"))
        self.assertFalse(agent._looks_like_cve_or_poc("how does xss work"))

    def test_format_context_tags_and_truncates(self):
        long_text = "A" * (agent._CONTEXT_CHARS_PER_CHUNK + 500)
        results = [
            {"payload": {"source": "web", "path": "u", "section": "s", "text": long_text}},
            {"payload": {"source": "vault", "path": "p", "section": "s2", "text": "short"}},
        ]
        out = agent._format_context(results)
        self.assertIn("UNTRUSTED WEB RESULT", out)
        self.assertIn("local knowledge base", out)
        # web chunk text truncated to the cap (not the full oversized string)
        self.assertNotIn("A" * (agent._CONTEXT_CHARS_PER_CHUNK + 1), out)


class RetrieveOrderingTest(unittest.TestCase):
    def test_kb_search_reranks_and_slices_top_k(self):
        
        def point(i):
            return types.SimpleNamespace(id=f"p{i}", payload={"text": f"doc {i}", "source": "s"})
        pooled = types.SimpleNamespace(points=[point(1), point(2), point(3)])

        fake_client = types.SimpleNamespace(query_points=lambda **kw: pooled)
        fake_sparse = types.SimpleNamespace(
            embed=lambda xs: iter([types.SimpleNamespace(
                indices=np.array([1]), values=np.array([0.5]))]))

        with mock.patch.object(retrieve, "_embed_query", return_value=[0.1, 0.2]), \
             mock.patch.object(retrieve, "_sparse", return_value=fake_sparse), \
             mock.patch.object(retrieve, "_client", return_value=fake_client), \
             mock.patch.object(retrieve, "_rerank", return_value=[0.2, 0.1, 0.9]):
            out = retrieve.kb_search("q", top_k=2)

        self.assertEqual([r["id"] for r in out], ["p3", "p1"])   # reranked, top-2
        self.assertAlmostEqual(out[0]["score"], 0.9)


class BuildIndexResumeTest(unittest.TestCase):
    def test_resume_skips_unchanged_updates_changed_indexes_new(self):
        unchanged = Chunk(id=chunk_id("a", "0"), text="alpha", source="s", path="a")
        changed = Chunk(id=chunk_id("b", "0"), text="bravo-new", source="s", path="b")
        fresh = Chunk(id=chunk_id("c", "0"), text="charlie", source="s", path="c")

        existing = {
            index._point_id(unchanged.id): content_hash("alpha"),      # same -> skip
            index._point_id(changed.id): content_hash("bravo-OLD"),     # differ -> update
            # fresh.id absent -> new
        }

        upserted = []

        class FakeClient:
            def __init__(self, *a, **k): pass
            def upsert(self, collection_name, points): upserted.extend(points)

        class FakeSparse:
            def __init__(self, *a, **k): pass
            def embed(self, texts):
                return [types.SimpleNamespace(indices=np.array([0]), values=np.array([1.0]))
                        for _ in texts]

        with mock.patch.object(index, "QdrantClient", FakeClient), \
             mock.patch.object(index, "SparseTextEmbedding", FakeSparse), \
             mock.patch.object(index, "_existing_hashes", return_value=existing), \
             mock.patch.object(index, "_embed_dense", side_effect=lambda texts: [[0.0] * config_dim() for _ in texts]):
            stats = index.build_index(chunks=[unchanged, changed, fresh], snapshot_version="v1")

        self.assertEqual(stats["skipped"], 1)   # unchanged
        self.assertEqual(stats["updated"], 1)   # changed
        self.assertEqual(stats["indexed"], 2)   # changed + new upserted
        self.assertEqual(len(upserted), 2)


def config_dim():
    from blkchain import config
    return config.EMBED_DIM


class HealthStatusTest(unittest.TestCase):
    def test_ok_when_both_up(self):
        with mock.patch.object(api, "_probe", side_effect=[True, True]):
            h = api.health_status()
        self.assertEqual(h["status"], "ok")
        self.assertTrue(h["qdrant"] and h["embed_server"])

    def test_degraded_when_dependency_down(self):
        with mock.patch.object(api, "_probe", side_effect=[True, False]):
            h = api.health_status()
        self.assertEqual(h["status"], "degraded")
        self.assertFalse(h["embed_server"])


if __name__ == "__main__":
    unittest.main()
