"""Core unit tests: pure logic and the indexing seams, exercised with mocks so
nothing here needs Qdrant, the embed server, or the LLM."""
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

import numpy as np

from blkchain import index, ingest
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


class AddPathTest(unittest.TestCase):
    def test_add_path_chunks_markdown_file_and_upserts_into_given_collection(self):
        import tempfile

        upserted = []
        collections_used = []

        class FakeClient:
            def __init__(self, *a, **k): pass
            def collection_exists(self, name): return True
            def upsert(self, collection_name, points):
                collections_used.append(collection_name)
                upserted.extend(points)

        class FakeSparse:
            def __init__(self, *a, **k): pass
            def embed(self, texts):
                return [types.SimpleNamespace(indices=np.array([0]), values=np.array([1.0]))
                        for _ in texts]

        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "notes.md"
            f.write_text("# Title\n\nA distinctive phrase about purple widgets.\n")

            with mock.patch.object(index, "QdrantClient", FakeClient), \
                 mock.patch.object(index, "SparseTextEmbedding", FakeSparse), \
                 mock.patch.object(index, "_existing_hashes", return_value={}), \
                 mock.patch.object(index, "_embed_dense",
                                    side_effect=lambda texts: [[0.0] * config_dim() for _ in texts]):
                stats = index.add_path(str(f), source="mydocs", collection="testcol")

        self.assertEqual(stats, {"indexed": 1, "updated": 0, "skipped": 0, "batches": 1})
        self.assertEqual(collections_used, ["testcol"])
        self.assertEqual(len(upserted), 1)
        self.assertIn("purple widgets", upserted[0].payload["text"])
        self.assertEqual(upserted[0].payload["source"], "mydocs")
        self.assertEqual(upserted[0].payload["index_scope"], "manual")

    def test_add_path_infers_kind_from_extension_and_labels_source_from_stem(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "myreport.txt"
            f.write_text("Some plain-text findings about SSRF.\n")

            with mock.patch.object(index, "ensure_collection"), \
                 mock.patch.object(index, "QdrantClient"), \
                 mock.patch.object(index, "SparseTextEmbedding"), \
                 mock.patch.object(index, "_existing_hashes", return_value={}), \
                 mock.patch.object(index, "_index_chunks") as fake_index_chunks:
                fake_index_chunks.return_value = {"indexed": 0, "updated": 0, "skipped": 0, "batches": 0}
                index.add_path(str(f))

            (_, _, _, chunks_arg, *_rest), _ = fake_index_chunks.call_args
            chunks = list(chunks_arg)
        self.assertTrue(chunks)
        self.assertEqual(chunks[0].source, "myreport")  # derived from the file stem
        self.assertEqual(chunks[0].type, "doc")

    def test_add_path_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            index.add_path("/nonexistent/path/does-not-exist.md")


class FetchUrlSSRFTest(unittest.TestCase):
    def test_rejects_cloud_metadata_ip(self):
        with self.assertRaises(ValueError):
            index._fetch_url("http://169.254.169.254/")

    def test_rejects_loopback_ip(self):
        with self.assertRaises(ValueError):
            index._fetch_url("http://127.0.0.1/")


def config_dim():
    from blkchain import config
    return config.EMBED_DIM


if __name__ == "__main__":
    unittest.main()
