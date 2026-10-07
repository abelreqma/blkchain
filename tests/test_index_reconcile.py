import types
import numpy as np
import unittest
import uuid
from pathlib import Path
from unittest import mock

from blkchain import config, index
from qdrant_client import QdrantClient, models


class CorpusReconciliationTest(unittest.TestCase):
    def test_deletes_only_stale_full_corpus_points(self):
        managed_source = "hacktricks"
        records = [
            types.SimpleNamespace(id="stale", payload={"source": managed_source, "path": "old/doc.md",
                                                        "index_scope": "corpus", "index_generation": "old"}),
            types.SimpleNamespace(id="fresh", payload={"source": managed_source, "path": "new/doc.md",
                                                         "index_scope": "corpus", "index_generation": "now"}),
            types.SimpleNamespace(id="manual", payload={"source": managed_source, "path": "/tmp/doc.md",
                                                          "index_scope": "manual", "index_generation": "old"}),
            types.SimpleNamespace(id="legacy", payload={"source": managed_source, "path": "old/legacy.md",
                                                          "index_generation": "old"}),
            types.SimpleNamespace(id="url", payload={"source": managed_source, "path": "https://example.test/",
                                                       "index_generation": "old"}),
            types.SimpleNamespace(id="malformed", payload={"source": [managed_source], "path": "old/doc.md"}),
        ]

        class FakeClient:
            def __init__(self):
                self.deleted = []

            def scroll(self, **kwargs):
                return records, None

            def delete(self, **kwargs):
                self.deleted.extend(kwargs["points_selector"])

        client = FakeClient()

        with mock.patch.object(config, "CORPUS_SOURCES", (config.SourceSpec(managed_source, Path("/tmp"), "markdown"),)):
            deleted = index._reconcile_corpus(client, "collection", "now")

        self.assertEqual(deleted, 2)
        self.assertEqual(client.deleted, ["stale", "legacy"])

    def test_legacy_manual_absolute_paths_are_not_claimed_as_corpus(self):
        managed_source = "hacktricks"
        client = mock.Mock()
        client.scroll.return_value = ([types.SimpleNamespace(
            id="manual", payload={"source": managed_source, "path": "/outside/corpus.md", "index_generation": "old"}
        )], None)

        with mock.patch.object(config, "CORPUS_SOURCES", (config.SourceSpec(managed_source, Path("/tmp"), "markdown"),)):
            deleted = index._reconcile_corpus(client, "collection", "now")

        self.assertEqual(deleted, 0)
        client.delete.assert_not_called()

    def test_missing_source_is_preserved_unless_explicitly_pruned(self):
        source = "hacktricks"
        missing = Path("/definitely/missing/blkchain-source")
        client = mock.Mock()
        client.scroll.return_value = ([types.SimpleNamespace(
            id="stale", payload={"source": source, "path": "removed-root/doc.md", "index_generation": "old"}
        )], None)
        with mock.patch.object(config, "CORPUS_SOURCES", (config.SourceSpec(source, missing, "markdown"),)):
            self.assertEqual(index._reconcile_corpus(client, "collection", "current"), 0)
            self.assertEqual(index._reconcile_corpus(client, "collection", "current", prune_missing_sources=True), 1)

        client.delete.assert_called_once_with(collection_name="collection", points_selector=["stale"])

    def test_full_build_reconciles_only_after_iterator_finishes(self):
        client = mock.Mock()
        stats = {"indexed": 0, "updated": 0, "skipped": 0, "batches": 0}
        with mock.patch.object(index, "QdrantClient", return_value=client), \
             mock.patch.object(index, "SparseTextEmbedding"), \
             mock.patch.object(index, "_existing_hashes", return_value={}), \
             mock.patch("blkchain.ingest.iter_chunks", return_value=iter(())), \
             mock.patch.object(index, "_index_chunks", side_effect=lambda *args: (list(args[3]), stats)[1]) as consume, \
             mock.patch.object(index, "_reconcile_corpus", return_value=3) as reconcile:
            result = index.build_index(snapshot_version="complete")

        self.assertEqual(result["deleted"], 3)
        self.assertEqual(consume.call_args.args[-2], "corpus")
        self.assertEqual(consume.call_args.args[-1], reconcile.call_args.args[-1])
        reconcile.assert_called_once_with(
            client, config.QDRANT_COLLECTION, consume.call_args.args[-1], prune_missing_sources=False
        )

    def test_failed_full_build_does_not_reconcile(self):
        client = mock.Mock()

        def interrupted_chunks():
            yield None
            raise RuntimeError("interrupted indexing")

        def consume_until_error(*args):
            list(args[3])
            return {"indexed": 0, "updated": 0, "skipped": 0, "batches": 0}

        with mock.patch.object(index, "QdrantClient", return_value=client), \
             mock.patch.object(index, "SparseTextEmbedding"), \
             mock.patch.object(index, "_existing_hashes", return_value={}), \
             mock.patch("blkchain.ingest.iter_chunks", return_value=interrupted_chunks()), \
             mock.patch.object(index, "_index_chunks", side_effect=consume_until_error), \
             mock.patch.object(index, "_reconcile_corpus") as reconcile:
            with self.assertRaisesRegex(RuntimeError, "interrupted indexing"):
                index.build_index(snapshot_version="incomplete")

        reconcile.assert_not_called()

    def test_high_stale_ratio_requires_prune_flag(self):
        """P9: if deleting would remove more than 20% of a source's managed
        points, refuse unless prune_missing_sources is set (a bad ingest should
        not silently wipe most of the corpus)."""
        source = "hacktricks"
        # 60 reconcilable points (>= the ratio-guard floor), 45 stale (75% > 20%).
        stale = [types.SimpleNamespace(id=f"s{i}", payload={
            "source": source, "path": f"old{i}.md", "index_scope": "corpus",
            "index_generation": "old"}) for i in range(45)]
        fresh = [types.SimpleNamespace(id=f"f{i}", payload={
            "source": source, "path": f"new{i}.md", "index_scope": "corpus",
            "index_generation": "now"}) for i in range(15)]

        class FakeClient:
            def __init__(self):
                self.deleted = []

            def scroll(self, **kwargs):
                return stale + fresh, None

            def delete(self, **kwargs):
                self.deleted.extend(kwargs["points_selector"])

        with mock.patch.object(config, "CORPUS_SOURCES",
                               (config.SourceSpec(source, Path("/tmp"), "markdown"),)):
            guarded = FakeClient()
            self.assertEqual(index._reconcile_corpus(guarded, "col", "now"), 0)  # 75% stale -> refused
            self.assertEqual(guarded.deleted, [])
            forced = FakeClient()
            self.assertEqual(
                index._reconcile_corpus(forced, "col", "now", prune_missing_sources=True), 45)


class ManualReconcileTest(unittest.TestCase):
    """P8: re-adding a shrunk source via add_path deletes the manual points that
    were not seen this pass (orphan chunks), scoped to that source label."""

    def test_readding_shrunk_source_deletes_orphans(self):
        ns = types.SimpleNamespace
        records = [
            ns(id="a", payload={"source": "docs", "index_root": "/docs", "index_scope": "manual", "index_generation": "gen2"}),
            ns(id="b", payload={"source": "docs", "index_root": "/docs", "index_scope": "manual", "index_generation": "gen2"}),
            ns(id="c", payload={"source": "docs", "index_root": "/docs", "index_scope": "manual", "index_generation": "gen1"}),  # orphan
            ns(id="other", payload={"source": "notes", "index_scope": "manual", "index_generation": "gz"}),
            ns(id="corp", payload={"source": "docs", "index_scope": "corpus", "index_generation": "gen1"}),
        ]

        class FakeClient:
            def __init__(self):
                self.deleted = []

            def scroll(self, **kwargs):
                return records, None

            def delete(self, **kwargs):
                self.deleted.extend(kwargs["points_selector"])

        client = FakeClient()
        deleted = index._reconcile_manual_source(client, "col", "docs", "gen2", "/docs")
        self.assertEqual(deleted, 1)
        self.assertEqual(client.deleted, ["c"])  # only the stale 'docs' manual point


class ReconcileWithQdrantBackendTest(unittest.TestCase):
    def test_reconciliation_with_qdrant_local_backend(self):
        source = "hacktricks"
        client = QdrantClient(":memory:")
        client.create_collection(
            collection_name="reconcile-test",
            vectors_config=models.VectorParams(size=2, distance=models.Distance.COSINE),
        )
        ids = {name: str(uuid.uuid4()) for name in ("stale", "fresh", "manual")}
        client.upsert(
            collection_name="reconcile-test",
            points=[
                models.PointStruct(id=ids["stale"], vector=[0.1, 0.2], payload={
                    "source": source, "path": "old.md", "index_scope": "corpus", "index_generation": "old",
                }),
                models.PointStruct(id=ids["fresh"], vector=[0.2, 0.3], payload={
                    "source": source, "path": "new.md", "index_scope": "corpus", "index_generation": "current",
                }),
                models.PointStruct(id=ids["manual"], vector=[0.3, 0.4], payload={
                    "source": source, "path": "/tmp/manual.md", "index_scope": "manual", "index_generation": "old",
                }),
            ],
        )

        with mock.patch.object(config, "CORPUS_SOURCES", (config.SourceSpec(source, Path("/tmp"), "markdown"),)):
            deleted = index._reconcile_corpus(client, "reconcile-test", "current")

        self.assertEqual(deleted, 1)
        records, _ = client.scroll(collection_name="reconcile-test", with_payload=True, with_vectors=False)
        self.assertEqual({str(record.id) for record in records}, {ids["fresh"], ids["manual"]})
        client.close()


class ManualInputIsolationTest(unittest.TestCase):
    def setUp(self):
        self.client = QdrantClient(":memory:")
        self.client.create_collection(
            collection_name="manual-test",
            vectors_config={config.DENSE_VECTOR_NAME: models.VectorParams(
                size=2, distance=models.Distance.COSINE)},
            sparse_vectors_config={config.SPARSE_VECTOR_NAME: models.SparseVectorParams()},
        )
        self.addCleanup(self.client.close)
        self.bodies = {}

    def add(self, url):
        from blkchain.schema import Chunk, chunk_id

        def chunks(path, source, kind):
            for number, text in enumerate(self.bodies[path]):
                yield Chunk(id=chunk_id(source, path, str(number)), text=text,
                            source=source, path=path)

        sparse = types.SimpleNamespace(embed=lambda texts: [types.SimpleNamespace(
            indices=np.array([1]), values=np.array([1.0])) for _ in texts])
        with mock.patch.object(index, "ensure_collection"), \
             mock.patch.object(index, "QdrantClient", return_value=self.client), \
             mock.patch.object(index, "SparseTextEmbedding", return_value=sparse), \
             mock.patch.object(index, "_embed_dense", side_effect=lambda texts: [[0.1, 0.2] for _ in texts]), \
             mock.patch.object(index, "_chunk_url", side_effect=chunks), \
             mock.patch.object(self.client, "close"):
            return index.add_path(url, collection="manual-test")

    def paths(self):
        rows, _ = self.client.scroll(collection_name="manual-test", limit=100,
                                     with_payload=True, with_vectors=False)
        return [row.payload["path"] for row in rows]

    def test_distinct_urls_with_the_same_label_are_preserved(self):
        first, second = "https://example.test/first", "https://example.test/second"
        self.bodies = {first: ["first note"], second: ["second note"]}
        self.add(first)
        result = self.add(second)
        self.assertEqual(result["deleted"], 0)
        self.assertCountEqual(self.paths(), [first, second])

    def test_readding_one_url_prunes_only_its_orphan_chunks(self):
        first, second = "https://example.test/first", "https://example.test/second"
        self.bodies = {first: ["first note", "old section"], second: ["second note"]}
        self.add(first)
        self.add(second)
        self.bodies[first] = ["first note"]
        result = self.add(first)
        self.assertEqual(result["deleted"], 1)
        self.assertCountEqual(self.paths(), [first, second])

    def test_empty_ingestion_preserves_previous_content(self):
        url = "https://example.test/first"
        self.bodies[url] = ["first note"]
        self.add(url)
        self.bodies[url] = []
        with self.assertRaisesRegex(ValueError, "no indexable chunks"):
            self.add(url)
        self.assertEqual(self.paths(), [url])


class ResumeMetadataTest(unittest.TestCase):
    def test_unchanged_text_refreshes_metadata_and_preserves_vectors(self):
        from blkchain.schema import Chunk, chunk_id, content_hash

        client = QdrantClient(":memory:")
        self.addCleanup(client.close)
        client.create_collection(
            collection_name="resume-metadata",
            vectors_config={config.DENSE_VECTOR_NAME: models.VectorParams(
                size=2, distance=models.Distance.COSINE)},
            sparse_vectors_config={config.SPARSE_VECTOR_NAME: models.SparseVectorParams()},
        )
        chunk = Chunk(id=chunk_id("notes", "note.md", "0"), text="Same text",
                      source="notes", path="note.md", section="Updated heading",
                      cwe_class="encoding", blurb="Updated context",
                      identifiers={"product": ["current"]}, extra={"origin": "url"})
        point_id = index._point_id(chunk.id)
        client.upsert(collection_name="resume-metadata", points=[models.PointStruct(
            id=point_id,
            vector={config.DENSE_VECTOR_NAME: [0.1, 0.2],
                    config.SPARSE_VECTOR_NAME: models.SparseVector(indices=[1], values=[2.0])},
            payload={"text": chunk.text, "content_hash": content_hash(chunk.text),
                     "section": "Old heading", "retired": "old metadata", "origin": "old",
                     "index_scope": "manual", "index_generation": "old", "index_root": "/old"},
        )])
        before = client.retrieve(collection_name="resume-metadata", ids=[point_id], with_vectors=True)[0].vector
        for scope in (None, "corpus", "manual"):
            with self.subTest(scope=scope), mock.patch.object(index, "_embed_dense") as embed:
                sparse = mock.Mock()
                stats = index._index_chunks(client, sparse, "resume-metadata", [chunk],
                                             {point_id: content_hash(chunk.text)}, True,
                                             "current", scope, "generation" if scope else None,
                                             "/current" if scope == "manual" else None)
                after = client.retrieve(collection_name="resume-metadata", ids=[point_id], with_vectors=True)[0]
                self.assertEqual(after.payload, chunk.payload("current", scope,
                                 "generation" if scope else None,
                                 "/current" if scope == "manual" else None))
                self.assertEqual(after.vector, before)
                self.assertEqual(stats["skipped"], 1)
                self.assertEqual(stats["indexed"], 0)
                embed.assert_not_called()
                sparse.embed.assert_not_called()
        chunk.extra = {}
        index._index_chunks(client, mock.Mock(), "resume-metadata", [chunk],
                            {point_id: content_hash(chunk.text)}, True, "last")
        self.assertNotIn("origin", client.retrieve(collection_name="resume-metadata", ids=[point_id])[0].payload)

    def test_resume_reembeds_points_without_a_content_hash(self):
        from blkchain.schema import Chunk, chunk_id

        chunk = Chunk(id=chunk_id("notes", "note.md", "0"), text="Current text", source="notes", path="note.md")
        point_id = index._point_id(chunk.id)
        client = mock.Mock()
        sparse = mock.Mock()
        sparse.embed.return_value = [types.SimpleNamespace(indices=np.array([1]), values=np.array([2.0]))]
        with mock.patch.object(index, "_embed_dense", return_value=[[0.1, 0.2]]) as embed:
            stats = index._index_chunks(client, sparse, "fixture", [chunk], {point_id: None}, True, "current")
        self.assertEqual(stats["skipped"], 0)
        self.assertEqual(stats["updated"], 1)
        self.assertEqual(stats["indexed"], 1)
        embed.assert_called_once_with([chunk.text])
        self.assertEqual(client.upsert.call_args.kwargs["points"][0].payload, chunk.payload("current"))

    def test_resume_payload_updates_are_bounded(self):
        from blkchain.schema import Chunk, chunk_id, content_hash

        chunks = [Chunk(id=chunk_id("notes", str(i), "0"), text="Same text", source="notes", path=str(i)) for i in range(1001)]
        existing = {index._point_id(chunk.id): content_hash(chunk.text) for chunk in chunks}
        sizes = []
        client = mock.Mock()
        client.batch_update_points.side_effect = lambda **kwargs: sizes.append(len(kwargs["update_operations"]))
        sparse = mock.Mock()
        with mock.patch.object(index, "_embed_dense") as embed:
            stats = index._index_chunks(client, sparse, "fixture", iter(chunks), existing, True, "current")
        self.assertEqual(sizes, [1000, 1])
        self.assertEqual(stats["skipped"], 1001)
        embed.assert_not_called()
        sparse.embed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
