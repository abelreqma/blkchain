import json
import tempfile
import unittest
from pathlib import Path

from blkchain import config, ingest


class ArsenalJsonIngestTest(unittest.TestCase):
    def test_chunks_curated_json(self):
        fixture = {
            "category": "Injection",
            "source": "arsenal",
            "entries": [
                {"subcategory": "Union", "title": "Union select", "language": "en",
                 "tags": ["sqli"], "body": "' UNION SELECT NULL,NULL-- -"},
                {"subcategory": "Union", "title": "", "language": "en", "tags": [],
                 "body": "  ", "meta": {"caption": "Column count probe"}},
                {"subcategory": "Union", "title": "", "language": "en", "tags": [], "body": ""},
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sql-injection.json").write_text(json.dumps(fixture), encoding="utf-8")
            (root / "broken.json").write_text("{not valid json", encoding="utf-8")
            spec = config.SourceSpec("arsenal-json", root, "json")
            chunks = list(ingest.chunk_source(spec))

        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0].text, "Union select\n\n' UNION SELECT NULL,NULL-- -")
        self.assertEqual(chunks[1].text, "Column count probe")
        self.assertEqual(len({c.id for c in chunks}), 2)
        for c in chunks:
            self.assertEqual(c.source, "arsenal-json")
            self.assertEqual(c.type, "technique")
            self.assertEqual(c.section, "Injection > Union")
            self.assertEqual(c.cwe_class, "sqli")
            self.assertTrue(c.path.endswith("sql-injection.json"))

    def test_broken_json_yields_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "broken.json").write_text("{not valid json", encoding="utf-8")
            (Path(d) / "list.json").write_text("[1, 2]", encoding="utf-8")
            spec = config.SourceSpec("arsenal-json", Path(d), "json")
            self.assertEqual(list(ingest.chunk_source(spec)), [])


if __name__ == "__main__":
    unittest.main()
