"""Release tag verification against a controlled GitHub CLI response."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "verify-release-ci.sh"


class ReleaseCITest(unittest.TestCase):
    def setUp(self):
        self.sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()

    def run_gate(self, response, exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$@" > "$MOCK_ARGS"\n'
                'printf "%s\\n" "$MOCK_RESPONSE"\n'
                'exit "$MOCK_EXIT"\n'
            )
            gh.chmod(0o700)
            args = root / "args"
            env = os.environ.copy()
            env.update({
                "PATH": str(root) + os.pathsep + env.get("PATH", ""),
                "GH_REPO": "owner/repo",
                "MOCK_ARGS": str(args),
                "MOCK_RESPONSE": response,
                "MOCK_EXIT": str(exit_code),
            })
            result = subprocess.run(
                ["/bin/sh", str(SCRIPT)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=15,
            )
            calls = args.read_text().splitlines() if args.exists() else []
            return result, calls

    def test_successful_main_push_ci_allows_release(self):
        result, args = self.run_gate(f"{self.sha} main completed success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:2], ["run", "list"])
        for flag, value in (
            ("--repo", "owner/repo"), ("--workflow", "ci.yml"),
            ("--commit", self.sha), ("--branch", "main"),
            ("--event", "push"), ("--limit", "1"),
        ):
            self.assertEqual(args[args.index(flag) + 1], value)

    def test_other_ci_states_fail_closed(self):
        for response in (
            "", f"{self.sha} main completed failure",
            f"{self.sha} main in_progress ",
            f"{'0' * 40} main completed success",
            f"{self.sha} feature completed success",
        ):
            with self.subTest(response=response):
                result, _ = self.run_gate(response)
                self.assertNotEqual(result.returncode, 0)

    def test_github_api_failure_stops_release(self):
        result, _ = self.run_gate("", exit_code=1)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
