import types
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
        ''
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
    ''

    def test_readding_shrunk_source_deletes_orphans(self):
        ns = types.SimpleNamespace
        records = [
            ns(id="a", payload={"source": "docs", "index_scope": "manual", "index_generation": "gen2"}),
            ns(id="b", payload={"source": "docs", "index_scope": "manual", "index_generation": "gen2"}),
            ns(id="c", payload={"source": "docs", "index_scope": "manual", "index_generation": "gen1"}),  # orphan
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
        deleted = index._reconcile_manual_source(client, "col", "docs", "gen2")
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


if __name__ == "__main__":
    unittest.main()
