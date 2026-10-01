import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from blkchain.eval import run
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


_SEARCH_JSON = {
    "results": [
        {"id": "a", "score": 0.9,
         "payload": {"source": "skills", "path": "p/ssrf.md", "section": "s", "type": "doc",
                     "text": "metadata endpoint", "cwe_class": "ssrf"}},
    ]
}

# A query that would run commands if it ever reached a shell.
HOSTILE_QUERY = "$(touch pwned) ; `id` && echo 'q' | cat"


class FakeBlkTestCase(unittest.TestCase):
    """Runs the harness against a fake `blk` script selected through BLK_BIN."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.log = self.dir / "call.json"
        self.out = self.dir / "out.json"

    def fake_blk(self, body: str) -> None:
        script = self.dir / "blk"
        script.write_text(f"#!{sys.executable}\nimport json, os, sys, time\n{textwrap.dedent(body)}")
        script.chmod(0o755)
        env = {"BLK_BIN": str(script), "FAKE_BLK_LOG": str(self.log), "FAKE_BLK_OUT": str(self.out)}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def emit(self, obj) -> None:
        """Fake blk that logs its argv and env, then prints `obj` as JSON."""
        self.out.write_text(json.dumps(obj))
        self.fake_blk("""
            open(os.environ["FAKE_BLK_LOG"], "w").write(json.dumps(
                {"argv": sys.argv[1:], "coll": os.environ.get("BLKCHAIN_COLLECTION")}))
            sys.stdout.write(open(os.environ["FAKE_BLK_OUT"]).read())
        """)


class BlkSearchTest(FakeBlkTestCase):
    def test_success_passes_query_as_single_argv_element(self):
        self.emit(_SEARCH_JSON)

        results = run.blk_search(HOSTILE_QUERY, 10, collection="altcol")

        self.assertEqual(results[0]["id"], "a")
        call = json.loads(self.log.read_text())
        self.assertEqual(call["argv"], ["search", "--json", "--top-k", "10", "--", HOSTILE_QUERY])
        self.assertEqual(call["coll"], "altcol")
        self.assertFalse(Path("pwned").exists())

    def test_run_retrieval_scores_a_hit(self):
        self.emit(_SEARCH_JSON)
        case = Case("q", ["metadata"], expected_sources=["skills"], expected_cwe="ssrf")

        (result,) = run.run_retrieval([case], 5)

        self.assertIsNone(result.error)
        self.assertEqual(result.first_rank, 1)
        self.assertTrue(result.cwe_field_seen)

    def test_nonzero_exit_is_recorded_not_raised(self):
        self.fake_blk("""
            sys.stderr.write("qdrant unreachable\\x1b[31m")
            sys.exit(3)
        """)

        (result,) = run.run_retrieval([Case("q", ["metadata"])], 5)

        self.assertIn("status 3", result.error)
        self.assertIn("qdrant unreachable", result.error)
        self.assertNotIn("\x1b", result.error)
        self.assertFalse(result.hit_at(5))
        report = build_report([result], 5, [], None, True)
        self.assertIn("blk call failed", report)

    def test_failed_case_does_not_stop_the_run(self):
        self.fake_blk("""
            if "boom" in sys.argv[-1]:
                sys.exit(1)
            print(json.dumps({"results": [{"payload": {"text": "metadata", "source": "s"}}]}))
        """)
        cases = [Case("boom", ["metadata"]), Case("fine", ["metadata"])]

        results = run.run_retrieval(cases, 5)

        self.assertIsNotNone(results[0].error)
        self.assertIsNone(results[1].error)
        self.assertTrue(results[1].hit_at(5))

    def test_timeout(self):
        self.fake_blk("time.sleep(30)")
        with self.assertRaises(run.BlkError) as cm:
            run.blk_search("q", 5, timeout=0.5)
        self.assertIn("timed out", str(cm.exception))

    def test_invalid_json(self):
        self.fake_blk('print("not json {")')
        with self.assertRaises(run.BlkError) as cm:
            run.blk_search("q", 5)
        self.assertIn("invalid JSON", str(cm.exception))

    def test_invalid_json_is_recorded_per_case(self):
        self.fake_blk('print("not json {")')
        (result,) = run.run_retrieval([Case("q", ["metadata"])], 5)
        self.assertIn("invalid JSON", result.error)

    def test_non_object_json(self):
        self.fake_blk("print('[1, 2]')")
        with self.assertRaises(run.BlkError):
            run.blk_search("q", 5)

    def test_oversized_output(self):
        self.fake_blk("""
            sys.stdout.write("x" * 200000)
            sys.stdout.flush()
        """)
        with mock.patch.object(run, "_OUTPUT_CAP", 1024):
            with self.assertRaises(run.BlkError) as cm:
                run.blk_search("q", 5)
        self.assertIn("exceeded", str(cm.exception))

    def test_odd_result_shapes_are_tolerated(self):
        self.emit({"results": [None, 7, {"payload": None}, {"payload": {"text": 5, "source": None}},
                               {"payload": {"text": "metadata", "source": "s"}}]})

        (result,) = run.run_retrieval([Case("q", ["metadata"])], 5)

        self.assertIsNone(result.error)
        self.assertEqual(result.first_rank, 3)  # non-dict entries are dropped

    def test_results_field_wrong_type_yields_no_results(self):
        self.emit({"results": "nope"})
        self.assertEqual(run.blk_search("q", 5), [])

    def test_missing_cwe_field_is_flagged(self):
        self.emit({"results": [{"payload": {"text": "reflected", "source": "s"}}]})
        case = Case("q", ["reflected"], expected_cwe="xss")

        (result,) = run.run_retrieval([case], 5)

        self.assertFalse(result.hit_at(5))
        self.assertEqual(run._cwe_unverifiable([result]), [result])
        self.assertIn("cwe_class", build_report([result], 5, [], None, True))


class MissingBinaryTest(unittest.TestCase):
    def test_bad_blk_bin(self):
        with mock.patch.dict(os.environ, {"BLK_BIN": "/nonexistent/blk"}):
            with self.assertRaises(run.BlkError) as cm:
                run.find_blk()
        self.assertIn("BLK_BIN", str(cm.exception))

    def test_not_on_path_names_the_build_command(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.dict(os.environ, {"PATH": empty}):
            os.environ.pop("BLK_BIN", None)
            with self.assertRaises(run.BlkError) as cm:
                run.blk_search("q", 5)
        self.assertIn("cd cli && go build -o blk .", str(cm.exception))

    def test_run_retrieval_records_failure_when_missing(self):
        with mock.patch.dict(os.environ, {"BLK_BIN": "/nonexistent/blk"}):
            (result,) = run.run_retrieval([Case("q", ["x"])], 5)
        self.assertIn("BLK_BIN", result.error)

    def test_main_exits_2_with_message(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"BLK_BIN": "/nonexistent/blk"}), \
             mock.patch.object(sys, "argv", ["run", "--no-judge"]), \
             mock.patch.object(sys, "stderr", err):
            self.assertEqual(run.main(), 2)
        self.assertIn("go build", err.getvalue())

    def test_judge_reports_unavailable_when_missing(self):
        with mock.patch.dict(os.environ, {"BLK_BIN": "/nonexistent/blk"}):
            results, reason = run.run_judge([Case("q", ["x"])], 1)
        self.assertEqual(results, [])
        self.assertIn("BlkError", reason)


class MainExitCodeTest(FakeBlkTestCase):
    """PI11: main() must return non-zero on any case error or below --min-hit5,
    guard n==0, and reject a negative --limit/--judge-limit."""

    def _run_main(self, argv, dataset):
        report = self.dir / "report.md"
        with mock.patch.object(run, "load_dataset", return_value=dataset), \
             mock.patch.object(run, "REPORT_PATH", report), \
             mock.patch.object(sys, "argv", ["run", *argv]):
            return run.main()

    def test_nonzero_when_a_case_errors(self):
        self.fake_blk("sys.exit(1)")
        rc = self._run_main(["--no-judge"], [Case("q", ["metadata"])])
        self.assertNotEqual(rc, 0)

    def test_zero_when_all_hit_and_no_error(self):
        self.emit(_SEARCH_JSON)
        rc = self._run_main(["--no-judge"], [Case("q", ["metadata"])])
        self.assertEqual(rc, 0)

    def test_min_hit5_below_threshold_is_nonzero(self):
        self.emit({"results": [{"payload": {"text": "unrelated", "source": "s"}}]})
        rc = self._run_main(["--no-judge", "--min-hit5", "0.9"], [Case("q", ["metadata"])])
        self.assertNotEqual(rc, 0)

    def test_empty_dataset_does_not_zerodivide(self):
        rc = self._run_main(["--no-judge"], [])
        self.assertNotEqual(rc, 0)  # nothing evaluated is a failure, not a crash

    def test_negative_limit_rejected(self):
        with mock.patch.object(sys, "argv", ["run", "--no-judge", "--limit", "-1"]):
            rc = run.main()
        self.assertEqual(rc, 2)

    def test_negative_judge_limit_rejected(self):
        with mock.patch.object(sys, "argv", ["run", "--judge-limit", "-1"]):
            rc = run.main()
        self.assertEqual(rc, 2)


class BlkAnswerTest(FakeBlkTestCase):
    def test_success(self):
        self.emit({"answer": "a [1]", "citations": [{"source": "s", "path": "p", "section": ""}],
                   "used_web": True, "results": _SEARCH_JSON["results"]})

        out = run.blk_answer("why", collection="altcol")

        self.assertEqual(out["answer"], "a [1]")
        self.assertTrue(out["used_web"])
        self.assertEqual(out["citations"][0]["source"], "s")
        call = json.loads(self.log.read_text())
        self.assertEqual(call["argv"], ["ask", "--json", "--rag", "--", "why"])
        self.assertEqual(call["coll"], "altcol")

    def test_fields_are_defensive(self):
        self.emit({"answer": 5, "citations": "x", "results": [1, {"payload": []}]})

        out = run.blk_answer("why")

        self.assertEqual(out, {"answer": "", "citations": [], "used_web": False,
                               "results": [{"payload": []}]})

    def test_nonzero_exit(self):
        self.fake_blk("sys.exit(1)")
        with self.assertRaises(run.BlkError):
            run.blk_answer("why")

    def test_timeout(self):
        self.fake_blk("time.sleep(30)")
        with self.assertRaises(run.BlkError):
            run.blk_answer("why", timeout=0.5)

    def test_invalid_json(self):
        self.fake_blk('print("<html>")')
        with self.assertRaises(run.BlkError):
            run.blk_answer("why")

    def test_oversized_output(self):
        self.fake_blk('sys.stdout.write("x" * 200000)')
        with mock.patch.object(run, "_OUTPUT_CAP", 1024):
            with self.assertRaises(run.BlkError):
                run.blk_answer("why")


if __name__ == "__main__":
    unittest.main()
