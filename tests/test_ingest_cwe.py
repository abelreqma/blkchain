"""Regression tests for the CWE-concept path tagger (PI5).

Fixes: `sql injection` no longer shadows `nosql injection` (dead `nosqli`
revived); bare-substring false positives are killed by word boundaries
(`selfie` no longer -> lfi, `corridor` no longer -> idor); hyphen/underscore
separators normalize so `sql-injection` matches the phrase.
"""
import unittest

from blkchain.ingest import _cwe_class_from_path as tag


class CweTaggerTest(unittest.TestCase):
    def test_existing_behavior_preserved(self):
        self.assertEqual(tag("notes/sqli/dump.md"), "sqli")
        self.assertEqual(tag("web/ssrf/metadata.md"), "ssrf")
        self.assertEqual(tag("a/prompt injection/b.md"), "prompt_injection")
        self.assertIsNone(tag("misc/notes.md"))

    def test_nosql_no_longer_shadowed_by_sql(self):
        self.assertEqual(tag("payloads/nosql injection/x.md"), "nosqli")
        self.assertEqual(tag("payloads/nosql-injection/x.md"), "nosqli")

    def test_word_boundary_kills_false_positives(self):
        self.assertIsNone(tag("notes/selfie.md"))     # was -> lfi
        self.assertIsNone(tag("docs/corridor.md"))    # was -> idor

    def test_hyphen_and_underscore_separators_match_phrases(self):
        self.assertEqual(tag("web/sql-injection/x.md"), "sqli")
        self.assertEqual(tag("web/cross_site_scripting/x.md"), "xss")

    def test_leaf_filename_is_matched(self):
        self.assertEqual(tag("cheatsheets/xss.md"), "xss")


if __name__ == "__main__":
    unittest.main()
