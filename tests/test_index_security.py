"""Security regression tests for blkchain.index: SSRF DNS-rebinding / TOCTOU
pinning and the directory-add resource caps. Fully offline -- no Qdrant, no
embed server, no live network (socket + requests are mocked)."""
import os
import socket
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

from blkchain import index


def _addrinfo(addr: str, port: int):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port))


def _fake_response(body: bytes = b"hello", content_type: str = "text/plain"):
    resp = mock.Mock()
    resp.is_redirect = False
    resp.is_permanent_redirect = False
    resp.raise_for_status = lambda: None
    resp.headers = {"content-type": content_type}
    resp.iter_content = lambda chunk_size=65536: [body]
    resp.close = lambda: None
    return resp


class SSRFRebindingTest(unittest.TestCase):
    PUBLIC = "8.8.8.8"          # public, not reserved
    PRIVATE = "127.0.0.1"       # loopback, must never be connected to

    def test_rebind_cannot_introduce_private_ip(self):
        """First resolution (guard check) returns a public IP; every later
        resolution (what a re-resolving client does at connect time) returns a
        private IP -- classic DNS rebinding. The fetch must connect to the
        pinned public IP, proving the second resolution cannot slip in a
        private address."""
        calls = {"n": 0}

        def rebinding(host, port, *a, **k):
            calls["n"] += 1
            addr = self.PUBLIC if calls["n"] == 1 else self.PRIVATE
            return [_addrinfo(addr, port or 80)]

        connected = {}

        def fake_get(url, **kwargs):
            # Simulate urllib3 re-resolving the host at connect time.
            host = urlparse(url).hostname
            connected["ip"] = socket.getaddrinfo(host, 80)[0][4][0]
            return _fake_response()

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=rebinding), \
             mock.patch.object(index.requests, "get", side_effect=fake_get):
            text, ctype = index._fetch_url("http://rebind.test/")

        self.assertEqual(text, "hello")
        self.assertEqual(connected["ip"], self.PUBLIC)  # pinned, not the rebound private IP

    def test_pin_resolution_returns_only_validated_ip(self):
        """Directly prove the pin: inside the context, a second differing
        resolution of the same host still yields the pinned address."""
        calls = {"n": 0}

        def rebinding(host, port, *a, **k):
            calls["n"] += 1
            addr = self.PUBLIC if calls["n"] == 1 else self.PRIVATE
            return [_addrinfo(addr, port or 80)]

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=rebinding):
            host, addrinfo = index._resolve_safe_host("http://rebind.test/")
            self.assertEqual(addrinfo[4][0], self.PUBLIC)
            with index._pin_resolution(host, addrinfo):
                again = socket.getaddrinfo(host, 80)
            self.assertEqual(again[0][4][0], self.PUBLIC)  # not PRIVATE

    def test_host_resolving_to_private_ip_is_rejected(self):
        def priv(host, port, *a, **k):
            return [_addrinfo("127.0.0.1", port or 80)]

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=priv):
            with self.assertRaises(ValueError):
                index._fetch_url("http://internal.test/")

    def test_metadata_ip_is_rejected(self):
        def meta(host, port, *a, **k):
            return [_addrinfo("169.254.169.254", port or 80)]

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=meta):
            with self.assertRaises(ValueError):
                index._fetch_url("http://metadata.test/")

    def test_any_private_record_rejects_even_if_first_is_public(self):
        """A round-robin resolver returning one public and one private record
        must be rejected -- every returned address is validated."""
        def mixed(host, port, *a, **k):
            return [_addrinfo(self.PUBLIC, port or 80), _addrinfo("169.254.169.254", port or 80)]

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=mixed):
            with self.assertRaises(ValueError):
                index._fetch_url("http://roundrobin.test/")


class DirCapTest(unittest.TestCase):
    def test_chunk_dir_raises_when_file_count_cap_exceeded(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(5):
                (Path(d) / f"f{i}.txt").write_text(f"finding {i}\n")
            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_FILES": "2"}):
                with self.assertRaises(ValueError) as cm:
                    list(index._chunk_dir(Path(d), "src", None))
            self.assertIn("BLKCHAIN_ADD_MAX_FILES", str(cm.exception))

    def test_chunk_dir_raises_when_byte_cap_exceeded(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "big.txt").write_text("x" * 5000)
            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_BYTES": "100"}):
                with self.assertRaises(ValueError) as cm:
                    list(index._chunk_dir(Path(d), "src", None))
            self.assertIn("BLKCHAIN_ADD_MAX_BYTES", str(cm.exception))

    def test_chunk_dir_ok_under_cap(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text("alpha SSRF findings\n")
            (Path(d) / "b.txt").write_text("beta XSS findings\n")
            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_FILES": "10",
                                              "BLKCHAIN_ADD_MAX_BYTES": str(10 * 1024 * 1024)}):
                chunks = list(index._chunk_dir(Path(d), "src", None))
        self.assertTrue(chunks)

    def test_add_path_dir_streams_generator_and_indexes_under_cap(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.txt").write_text("alpha SSRF findings\n")
            (Path(d) / "b.txt").write_text("beta XSS findings\n")
            captured = {}

            def fake_index_chunks(client, sparse_model, collection, chunks,
                                  existing, resume, snapshot_version, index_scope=None):
                # Prove a generator (streamed), not a materialized list, is passed.
                captured["is_generator"] = isinstance(chunks, types.GeneratorType)
                n = sum(1 for _ in chunks)
                return {"indexed": n, "updated": 0, "skipped": 0, "batches": 1}

            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_FILES": "10"}), \
                 mock.patch.object(index, "ensure_collection"), \
                 mock.patch.object(index, "QdrantClient"), \
                 mock.patch.object(index, "SparseTextEmbedding"), \
                 mock.patch.object(index, "_existing_hashes", return_value={}), \
                 mock.patch.object(index, "_index_chunks", side_effect=fake_index_chunks):
                stats = index.add_path(d, source="docs", collection="testcol")

        self.assertTrue(captured["is_generator"])
        self.assertGreaterEqual(stats["indexed"], 2)

    def test_add_path_dir_over_cap_raises_when_streamed(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(5):
                (Path(d) / f"f{i}.txt").write_text(f"c{i}\n")

            def consume(client, sparse_model, collection, chunks, *a, **k):
                for _ in chunks:  # streaming consumption trips the cap mid-walk
                    pass
                return {"indexed": 0, "updated": 0, "skipped": 0, "batches": 0}

            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_FILES": "2"}), \
                 mock.patch.object(index, "ensure_collection"), \
                 mock.patch.object(index, "QdrantClient"), \
                 mock.patch.object(index, "SparseTextEmbedding"), \
                 mock.patch.object(index, "_existing_hashes", return_value={}), \
                 mock.patch.object(index, "_index_chunks", side_effect=consume):
                with self.assertRaises(ValueError):
                    index.add_path(d)


if __name__ == "__main__":
    unittest.main()
