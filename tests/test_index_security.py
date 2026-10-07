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

from blkchain import index, ingest


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

        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = fake_get

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=rebinding), \
             mock.patch.object(index, "_no_proxy_session", return_value=session):
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


class SSRFAddressRangeTest(unittest.TestCase):
    """P1: the guard must reject shared/CGNAT/6to4 space and IPv4-mapped IPv6,
    not only the old private/loopback/link-local set."""

    def _reject(self, addr: str):
        def resolver(host, port, *a, **k):
            return [_addrinfo(addr, port or 80)]
        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver):
            with self.assertRaises(ValueError, msg=f"{addr} should be rejected"):
                index._fetch_url("http://target.test/")

    def test_rejects_cgnat_shared_space(self):
        self._reject("100.64.0.1")        # RFC 6598 CGNAT (not is_private, not is_global)

    def test_rejects_6to4_relay_anycast(self):
        self._reject("192.88.99.1")        # RFC 7526 (not is_private, not is_global)

    def test_rejects_ipv4_mapped_metadata(self):
        self._reject("::ffff:169.254.169.254")  # IPv4-mapped link-local metadata

    def test_rejects_ipv4_mapped_private(self):
        self._reject("::ffff:10.0.0.5")    # IPv4-mapped RFC1918

    def test_rejects_6to4_prefix(self):
        # 2002:V4::/48 embeds an IPv4 address and is deprecated (RFC 7526); Python
        # marks 2002::/16 as global, so it is denied explicitly.
        self._reject("2002:a9fe:a9fe::1")  # 6to4 wrapping 169.254.169.254

    def test_public_ipv4_still_allowed(self):
        # Sanity: a genuine public address is NOT rejected during validation.
        def resolver(host, port, *a, **k):
            return [_addrinfo("8.8.8.8", port or 80)]
        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver):
            host, addrinfo = index._resolve_safe_host("http://ok.test/")
        self.assertEqual(addrinfo[4][0], "8.8.8.8")


class IdnaPinTest(unittest.TestCase):
    """P2: an IDN host must resolve/pin under the IDNA (punycode) form urllib3
    actually resolves, or the pin is bypassed."""

    def test_idn_host_normalized_to_punycode(self):
        def resolver(host, port, *a, **k):
            return [_addrinfo("8.8.8.8", port or 80)]
        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver):
            host, addrinfo = index._resolve_safe_host("http://bücher.test/")
        self.assertEqual(host, "xn--bcher-kva.test")

    def test_pin_keys_on_punycode_form(self):
        def resolver(host, port, *a, **k):
            return [_addrinfo("8.8.8.8", port or 80)]
        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver):
            host, addrinfo = index._resolve_safe_host("http://bücher.test/")
            with index._pin_resolution(host, addrinfo):
                again = socket.getaddrinfo("xn--bcher-kva.test", 80)
        self.assertEqual(again[0][4][0], "8.8.8.8")

    def test_ascii_host_unchanged(self):
        def resolver(host, port, *a, **k):
            return [_addrinfo("8.8.8.8", port or 80)]
        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver):
            host, _ = index._resolve_safe_host("http://example.test/")
        self.assertEqual(host, "example.test")

    def test_divergent_idn_host_fetches_the_validated_ascii_host(self):
        """A host whose IDNA-2008 (what requests uses) and IDNA-2003 (stdlib)
        forms DIVERGE must be validated, pinned, AND fetched under the SAME ascii
        form, so requests cannot re-encode to an unvalidated host and slip past
        the pin. 'fa<sharp-s>.test' -> idna-2008 'xn--fa-hia.test' vs stdlib
        'fass.test'."""
        try:
            import idna  # noqa: F401
        except ImportError:
            self.skipTest("idna package not installed")
        resolved_hosts = []

        def resolver(host, port, *a, **k):
            resolved_hosts.append(host)
            return [_addrinfo("8.8.8.8", port or 80)]

        got = {}

        def fake_get(url, **kwargs):
            got["url"] = url
            return _fake_response()

        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = fake_get

        with mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver), \
             mock.patch.object(index, "_no_proxy_session", return_value=session):
            index._fetch_url("http://faß.test/")

        self.assertIn("xn--fa-hia.test", got["url"])   # fetched the idna-2008 form
        self.assertNotIn("fass.test", got["url"])       # not the divergent stdlib form
        self.assertIn("xn--fa-hia.test", resolved_hosts)  # validated the same host


class ProxyBypassTest(unittest.TestCase):
    """P3: fetch and embed must use a trust_env-disabled session so a set proxy
    cannot bypass the SSRF pin, and a set proxy is warned about."""

    def test_no_proxy_session_disables_trust_env(self):
        s = index._no_proxy_session()
        try:
            self.assertFalse(s.trust_env)
            self.assertEqual(s.proxies, {})
        finally:
            s.close()

    def test_fetch_warns_when_proxy_env_set(self):
        import io
        import contextlib as _c

        def resolver(host, port, *a, **k):
            return [_addrinfo("8.8.8.8", port or 80)]
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = lambda url, **kw: _fake_response()
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.test:8080"}), \
             mock.patch.object(index.socket, "getaddrinfo", side_effect=resolver), \
             mock.patch.object(index, "_no_proxy_session", return_value=session), \
             _c.redirect_stderr(err):
            index._fetch_url("http://ok.test/")
        self.assertIn("proxy", err.getvalue().lower())


class HtmlToTextTest(unittest.TestCase):
    """P7: HTML->text must not use a catastrophic-backtracking regex and must
    strip script/style content."""

    def test_strips_script_and_style(self):
        html_doc = "<p>keep this</p><script>evil()</script><style>.x{}</style><p>and this</p>"
        out = index._html_to_text(html_doc)
        self.assertIn("keep this", out)
        self.assertIn("and this", out)
        self.assertNotIn("evil()", out)
        self.assertNotIn(".x{}", out)

    def test_adversarial_input_completes_quickly(self):
        import time
        # Many unclosed script tags + long runs: a quadratic regex would hang.
        adversarial = ("<script>" + "a" * 200) * 4000
        start = time.monotonic()
        out = index._html_to_text(adversarial)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 5.0)
        self.assertNotIn("aaaa", out)  # script bodies dropped


class IterFilesSafetyTest(unittest.TestCase):
    """P6/PI8: the ingest iterator must not follow symlinks out of the tree or
    ingest dotfiles / credential-looking files."""

    def test_skips_symlinked_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            root.mkdir()
            outside = Path(d) / "secret.txt"
            outside.write_text("SECRET OUTSIDE")
            (root / "real.txt").write_text("real content")
            os.symlink(outside, root / "link.txt")
            names = {p.name for p in ingest._iter_files(root, None, ())}
        self.assertIn("real.txt", names)
        self.assertNotIn("link.txt", names)

    def test_does_not_descend_symlinked_dir(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            root.mkdir()
            outside = Path(d) / "outside"
            outside.mkdir()
            (outside / "leak.txt").write_text("LEAK")
            (root / "ok.txt").write_text("ok")
            os.symlink(outside, root / "sub")
            names = {p.name for p in ingest._iter_files(root, None, ())}
        self.assertIn("ok.txt", names)
        self.assertNotIn("leak.txt", names)

    def test_skips_secret_like_and_dotfiles(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".env").write_text("SECRET=1")
            (root / "id_rsa").write_text("PRIVATE KEY")
            (root / "server.pem").write_text("CERT")
            (root / "doc.md").write_text("# doc")
            names = {p.name for p in ingest._iter_files(root, None, ())}
        self.assertEqual(names, {"doc.md"})


class SingleFileAddCapTest(unittest.TestCase):
    def test_single_file_over_byte_cap_raises(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "big.txt"
            f.write_text("x" * 5000)
            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_BYTES": "100"}), \
                 mock.patch.object(index, "ensure_collection"), \
                 mock.patch.object(index, "QdrantClient"), \
                 mock.patch.object(index, "SparseTextEmbedding"), \
                 mock.patch.object(index, "_existing_hashes", return_value={}):
                with self.assertRaises(ValueError) as cm:
                    index.add_path(str(f))
        self.assertIn("BLKCHAIN_ADD_MAX_BYTES", str(cm.exception))


class SourceLabelTest(unittest.TestCase):
    def test_file_label_is_stem(self):
        self.assertEqual(index.derive_source_label("/tmp/report.md"), "report")

    def test_explicit_source_wins(self):
        self.assertEqual(index.derive_source_label("/tmp/x.md", "custom"), "custom")


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
                                  existing, resume, snapshot_version,
                                  index_scope=None, index_generation=None, index_root=None):
                # Prove a generator (streamed), not a materialized list, is passed.
                captured["is_generator"] = isinstance(chunks, types.GeneratorType)
                n = sum(1 for _ in chunks)
                return {"indexed": n, "updated": 0, "skipped": 0, "batches": 1}

            with mock.patch.dict(os.environ, {"BLKCHAIN_ADD_MAX_FILES": "10"}), \
                 mock.patch.object(index, "ensure_collection"), \
                 mock.patch.object(index, "QdrantClient"), \
                 mock.patch.object(index, "SparseTextEmbedding"), \
                 mock.patch.object(index, "_existing_hashes", return_value={}), \
                 mock.patch.object(index, "_reconcile_manual_source", return_value=0), \
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
