"""Tests for the worker command launcher's environment handling.

cli/runner/execute.py replaces the environment of every command it starts. The
worker container receives the environment variable names the operator declared
for a foothold carrier, so the launcher must copy those values into the command
environment or a carrier never sees the value it authenticates with.

The script hardcodes /work, the worker's tmpfs, which does not exist on a test
host. These tests rewrite that one path to a temporary directory and run the real
script, so the environment logic under test is the shipped code.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "cli" / "runner" / "execute.py"

PRINT_ENV = (
    "import json, os, sys;"
    "sys.stdout.write(json.dumps({k: os.environ.get(k) for k in sys.argv[1:]}))"
)


class RunnerExecuteEnvTest(unittest.TestCase):
    def setUp(self):
        self.work = self.enterContext(tempfile.TemporaryDirectory(prefix="blk-runner-"))
        source = SCRIPT.read_text()
        self.assertIn('dir="/work"', source)
        self.assertIn('cwd="/work"', source)
        self.script = source.replace('dir="/work"', f'dir={self.work!r}').replace(
            'cwd="/work"', f"cwd={self.work!r}"
        )

    def run_launcher(self, request, env_extra=None):
        """Run the launcher with request on stdin, returning (proc, parsed-or-None)."""
        env = dict(os.environ)
        env.update(env_extra or {})
        proc = subprocess.run(
            [sys.executable, "-c", self.script],
            input=json.dumps(request).encode(),
            capture_output=True,
            env=env,
            timeout=60,
        )
        if proc.returncode != 0:
            return proc, None
        return proc, json.loads(proc.stdout.decode())

    def stage(self, *names):
        return {"binary": sys.executable, "args": ["-c", PRINT_ENV, *names]}

    def command_env(self, result):
        """The environment dict the launched command reported."""
        self.assertEqual(result["error"], "", msg=result)
        self.assertFalse(result["timed_out"], msg=result)
        return json.loads(result["stages"][0]["stdout"])

    def test_declared_name_reaches_the_command(self):
        request = {
            "stages": [self.stage("BLK_TEST_TOKEN")],
            "limit": 65536,
            "timeout": 30,
            "env": ["BLK_TEST_TOKEN"],
        }
        proc, result = self.run_launcher(request, {"BLK_TEST_TOKEN": "carrier-secret-value"})
        self.assertIsNotNone(result, msg=proc.stderr)
        self.assertEqual(
            self.command_env(result)["BLK_TEST_TOKEN"], "carrier-secret-value"
        )

    def test_undeclared_name_does_not_reach_the_command(self):
        """Only declared names cross; nothing else from the container environment."""
        request = {
            "stages": [self.stage("BLK_TEST_TOKEN", "BLK_TEST_OTHER")],
            "limit": 65536,
            "timeout": 30,
            "env": ["BLK_TEST_TOKEN"],
        }
        proc, result = self.run_launcher(
            request, {"BLK_TEST_TOKEN": "declared", "BLK_TEST_OTHER": "undeclared"}
        )
        self.assertIsNotNone(result, msg=proc.stderr)
        reported = self.command_env(result)
        self.assertEqual(reported["BLK_TEST_TOKEN"], "declared")
        self.assertIsNone(reported["BLK_TEST_OTHER"])

    def test_request_without_env_key_still_runs(self):
        request = {"stages": [self.stage("PATH")], "limit": 65536, "timeout": 30}
        proc, result = self.run_launcher(request)
        self.assertIsNotNone(result, msg=proc.stderr)
        self.assertEqual(
            self.command_env(result)["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin"
        )

    def test_declared_name_cannot_redirect_path_or_home(self):
        """The fixed base is applied last, so a declaration cannot repoint lookup."""
        request = {
            "stages": [self.stage("PATH", "HOME", "LANG")],
            "limit": 65536,
            "timeout": 30,
            "env": ["PATH", "HOME", "LANG"],
        }
        proc, result = self.run_launcher(
            request, {"PATH": "/attacker/bin", "HOME": "/attacker", "LANG": "xx_XX"}
        )
        self.assertIsNotNone(result, msg=proc.stderr)
        reported = self.command_env(result)
        self.assertEqual(reported["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(reported["LANG"], "C")
        self.assertTrue(reported["HOME"].startswith(self.work), msg=reported["HOME"])

    def test_unset_declared_name_contributes_nothing(self):
        request = {
            "stages": [self.stage("BLK_TEST_ABSENT")],
            "limit": 65536,
            "timeout": 30,
            "env": ["BLK_TEST_ABSENT"],
        }
        env = {k: v for k, v in os.environ.items() if k != "BLK_TEST_ABSENT"}
        proc = subprocess.run(
            [sys.executable, "-c", self.script],
            input=json.dumps(request).encode(),
            capture_output=True,
            env=env,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        result = json.loads(proc.stdout.decode())
        self.assertIsNone(self.command_env(result)["BLK_TEST_ABSENT"])

    def test_malformed_declared_environment_is_rejected(self):
        for env in (
            "BLK_TEST_TOKEN",  # not a list
            ["BAD-NAME"],  # hyphen is not a name character
            ["9LEADING"],  # a digit cannot lead
            ["WITH SPACE"],
            ["NAME=VALUE"],  # an assignment, not a name
            [""],
            ["\u00c4NAME"],  # non-ASCII
            [123],
            ["X" * 257],
            ["N%d" % i for i in range(65)],  # over the count cap
        ):
            with self.subTest(env=env):
                request = {
                    "stages": [self.stage("PATH")],
                    "limit": 65536,
                    "timeout": 30,
                    "env": env,
                }
                proc, result = self.run_launcher(request)
                self.assertIsNone(result, msg=f"{env!r} was accepted")
                self.assertNotEqual(proc.returncode, 0)

    def test_rejected_request_leaves_no_scratch_directory(self):
        request = {
            "stages": [self.stage("PATH")],
            "limit": 65536,
            "timeout": 30,
            "env": ["BAD-NAME"],
        }
        proc, result = self.run_launcher(request)
        self.assertIsNone(result, msg=proc.stderr)
        self.assertEqual(sorted(os.listdir(self.work)), [])


if __name__ == "__main__":
    unittest.main()
