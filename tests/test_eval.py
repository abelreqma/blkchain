import unittest

from blkchain.eval.run import Case, build_report, evaluate_retrieval


class RetrievalEvaluationTest(unittest.TestCase):
    def test_source_and_cwe_must_match_same_substring_result(self):
        case = Case("q", ["metadata"], expected_sources=["skills"], expected_cwe="ssrf")
        results = [
            {"payload": {"text": "metadata endpoint", "source": "hacktricks", "cwe_class": "ssrf"}},
            {"payload": {"text": "other content", "source": "skills", "cwe_class": "ssrf"}},
        ]

        result = evaluate_retrieval(case, results)

        self.assertIsNone(result.first_rank)
        self.assertEqual(result.first_text_rank, 1)
        self.assertIsNone(result.first_source_rank)
        self.assertFalse(result.hit_at(5))

    def test_correct_source_substring_and_cwe_match(self):
        case = Case("q", ["metadata"], expected_sources=["skills"], expected_cwe="ssrf")
        results = [{"payload": {"text": "metadata endpoint", "source": "Skills", "cwe_class": "SSRF"}}]

        result = evaluate_retrieval(case, results)

        self.assertEqual(result.first_rank, 1)
        self.assertEqual(result.matched_source, "Skills")
        self.assertTrue(result.hit_at(5))

    def test_report_names_source_constraint_in_results(self):
        case = Case("q", ["metadata"], expected_sources=["skills"])
        results = [{"payload": {"text": "metadata endpoint", "source": "skills"}}]

        report = build_report([evaluate_retrieval(case, results)], 5, [], None, True)

        self.assertIn("matched source", report)
        self.assertIn("| skills | metadata |", report)


if __name__ == "__main__":
    unittest.main()
