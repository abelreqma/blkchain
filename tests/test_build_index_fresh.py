''
import unittest
from unittest import mock

from blkchain import index


class BuildIndexFreshCollectionTest(unittest.TestCase):
    def test_creates_collection_before_reading_existing_hashes(self):
        manager = mock.Mock()
        manager._existing_hashes.return_value = {}
        with mock.patch.object(index, "QdrantClient"), \
             mock.patch.object(index, "SparseTextEmbedding"), \
             mock.patch.object(index, "ensure_collection", manager.ensure_collection), \
             mock.patch.object(index, "_existing_hashes", manager._existing_hashes), \
             mock.patch.object(index, "_index_chunks",
                               return_value={"indexed": 0, "updated": 0, "skipped": 0, "batches": 0}):
            index.build_index(chunks=[], snapshot_version="v1", resume=True, collection="testcol")

        names = [c[0] for c in manager.mock_calls]
        self.assertIn("ensure_collection", names)
        self.assertIn("_existing_hashes", names)
        # ordering: the collection is ensured before any scroll for existing hashes
        self.assertLess(names.index("ensure_collection"), names.index("_existing_hashes"))
        manager.ensure_collection.assert_called_once_with("testcol")


if __name__ == "__main__":
    unittest.main()
