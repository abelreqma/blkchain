"""Regression tests for the fence-aware markdown section splitter (PI4).

The old MarkdownHeaderTextSplitter treated a '#' comment inside a fenced code
block as a heading and stripped code-fence indentation. The scanner must keep
raw lines (indentation intact) and never split on a '#' inside a fence.
"""
import unittest

from blkchain.ingest import _markdown_sections, _chunk_markdown_file


class MarkdownSectionsTest(unittest.TestCase):
    def test_hash_inside_fence_is_not_a_header(self):
        text = (
            "# Real Title\n\n"
            "```python\n"
            "# this is a code comment, not a heading\n"
            "    indented = 1\n"
            "```\n\n"
            "trailing prose\n"
        )
        sections = _markdown_sections(text)
        breadcrumbs = " || ".join(b for b, _ in sections)
        self.assertNotIn("this is a code comment", breadcrumbs)

    def test_fence_indentation_preserved(self):
        text = "# T\n\n```python\n    indented = 1\n```\n"
        joined = "\n".join(t for _, t in _markdown_sections(text))
        self.assertIn("    indented = 1", joined)

    def test_real_headers_build_breadcrumbs(self):
        text = "# H1\n\nbody one\n\n## H2\n\nbody two\n"
        sections = _markdown_sections(text)
        breadcrumbs = [b for b, _ in sections]
        self.assertTrue(any("H1" in b for b in breadcrumbs))
        self.assertTrue(any(b == "H1 > H2" for b in breadcrumbs))

    def test_preamble_before_first_header(self):
        text = "intro line\n\n# H1\n\nbody\n"
        sections = _markdown_sections(text)
        self.assertEqual(sections[0][0], "")
        self.assertIn("intro line", sections[0][1])

    def test_tilde_fence_also_respected(self):
        text = "# T\n\n~~~\n# not a header\n~~~\n"
        breadcrumbs = " || ".join(b for b, _ in _markdown_sections(text))
        self.assertNotIn("not a header", breadcrumbs)


class ChunkMarkdownFileTest(unittest.TestCase):
    def test_code_comment_stays_in_body_not_section(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "doc.md"
            f.write_text("# Title\n\n```\n# inside fence\n    keepindent\n```\n")
            chunks = list(_chunk_markdown_file(f, "vault", "doc"))
        self.assertTrue(chunks)
        self.assertFalse(any("inside fence" in c.section for c in chunks))


if __name__ == "__main__":
    unittest.main()
