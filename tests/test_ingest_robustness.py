"""Ingest robustness regressions: PI1 (Arsenal JSON), PI2 (file stats bounds),
PI3 (content byte cap), PI7 (exclude matching), PI10 (PDF errors)."""
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from blkchain import config, ingest


class ArsenalJsonRobustnessTest(unittest.TestCase):
    def test_non_str_title_is_coerced(self):
        fixture = {"category": "Injection",
                   "entries": [{"subcategory": "U", "title": ["not", "a", "string"],
                                "body": "payload body here"}]}
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x.json").write_text(json.dumps(fixture), encoding="utf-8")
            chunks = list(ingest.chunk_source(config.SourceSpec("arsenal", Path(d), "json")))
        self.assertTrue(chunks)
        self.assertIn("payload body here", chunks[0].text)

    def test_deeply_nested_json_does_not_abort_source(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a-broken.json").write_text("[" * 6000, encoding="utf-8")
            good = {"category": "C", "entries": [{"title": "T", "body": "good body"}]}
            (Path(d) / "z-good.json").write_text(json.dumps(good), encoding="utf-8")
            chunks = list(ingest.chunk_source(config.SourceSpec("arsenal", Path(d), "json")))
        self.assertTrue(any("good body" in c.text for c in chunks))

    def test_oversized_json_file_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            big = {"category": "C", "entries": [{"title": "T", "body": "x" * 100}]}
            payload = json.dumps(big) + "\n" + " " * (5 * 1024 * 1024)  # pad past the cap
            (Path(d) / "big.json").write_text(payload, encoding="utf-8")
            good = {"category": "C", "entries": [{"title": "T", "body": "small good"}]}
            (Path(d) / "ok.json").write_text(json.dumps(good), encoding="utf-8")
            chunks = list(ingest.chunk_source(config.SourceSpec("arsenal", Path(d), "json")))
        self.assertTrue(any("small good" in c.text for c in chunks))
        self.assertFalse(any(c.path.endswith("big.json") for c in chunks))

    def test_long_body_is_split(self):
        long_body = "\n\n".join(f"paragraph number {i} with some content" for i in range(400))
        fixture = {"category": "C", "entries": [{"title": "T", "body": long_body}]}
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x.json").write_text(json.dumps(fixture), encoding="utf-8")
            chunks = list(ingest.chunk_source(config.SourceSpec("arsenal", Path(d), "json")))
        self.assertGreater(len(chunks), 1)


class FileStatsBoundsTest(unittest.TestCase):
    def test_sample_line_length_capped(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "big.txt"
            f.write_text("x" * 10000 + "\n" + "y" * 10000 + "\n")
            size, lines, samples = ingest._file_stats(f)
        self.assertTrue(samples)
        for s in samples:
            self.assertLessEqual(len(s), 200)

    def test_binary_file_returns_no_samples(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "bin"
            f.write_bytes(b"abc\x00def\x00" + b"\x01" * 100)
            size, lines, samples = ingest._file_stats(f)
        self.assertEqual(samples, [])


class ContentByteCapTest(unittest.TestCase):
    def test_plain_file_read_is_byte_capped(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "big.txt"
            f.write_text("STARTMARKER\n" + ("filler line\n" * 5000) + "ENDMARKER\n")
            with mock.patch.object(config, "MAX_TEXT_FILE_BYTES", 1000):
                chunks = list(ingest._chunk_plain_file(f, "src", "payload", Path(d)))
        joined = "\n".join(c.text for c in chunks)
        self.assertIn("STARTMARKER", joined)
        self.assertNotIn("ENDMARKER", joined)  # tail beyond the cap not read

    def test_capped_read_never_materializes_the_whole_file(self):
        """The cap must be applied by the read itself. Path.read_bytes() loads
        the entire file before any slice runs, so a multi-gigabyte corpus file
        would consume that much memory however small the cap is. Patching
        read_bytes to fail pins that the implementation does not use it."""
        def refuse(self):
            raise AssertionError("read_bytes materializes the whole file")

        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "big.txt"
            f.write_text("A" * 5000)
            with mock.patch.object(Path, "read_bytes", refuse):
                with mock.patch.object(config, "MAX_TEXT_FILE_BYTES", 1000):
                    text = ingest._read_text_capped(f)
        self.assertEqual(len(text), 1000)


class ExcludeMatchingTest(unittest.TestCase):
    def _names(self, root, exclude):
        return {p.name for p in ingest._iter_files(root, None, exclude)}

    def test_dir_fragment_matches_component_not_substring(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "docs").mkdir()
            (root / "docs" / "a.md").write_text("x")
            (root / "mydocs").mkdir()
            (root / "mydocs" / "b.md").write_text("y")
            names = self._names(root, ("docs",))
        self.assertNotIn("a.md", names)   # under a 'docs' component -> excluded
        self.assertIn("b.md", names)      # 'mydocs' is not the 'docs' component

    def test_ext_fragment_matches_suffix_not_infix(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "real.png").write_text("x")
            (root / "notes.png.md").write_text("y")
            names = self._names(root, (".png",))
        self.assertNotIn("real.png", names)
        self.assertIn("notes.png.md", names)   # .png is infix, not the suffix


class PdfErrorHandlingTest(unittest.TestCase):
    def test_corrupt_pdf_reader_yields_nothing(self):
        spec = config.SourceSpec("wstg", Path("/tmp/does-not-matter.pdf"), "pdf")
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(ingest.pypdf, "PdfReader", side_effect=Exception("corrupt")):
            self.assertEqual(list(ingest._chunk_pdf(spec)), [])

    def test_per_page_extract_error_is_skipped(self):
        good_page = types.SimpleNamespace(extract_text=lambda: "WSTG-INFO-01 real page text")
        bad_page = types.SimpleNamespace(extract_text=lambda: (_ for _ in ()).throw(Exception("bad")))
        reader = types.SimpleNamespace(pages=[bad_page, good_page])
        spec = config.SourceSpec("wstg", Path("/tmp/x.pdf"), "pdf")
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(ingest.pypdf, "PdfReader", return_value=reader):
            chunks = list(ingest._chunk_pdf(spec))
        self.assertTrue(any("real page text" in c.text for c in chunks))


if __name__ == "__main__":
    unittest.main()
