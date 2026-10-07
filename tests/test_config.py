"""Hermetic tests for blkchain.config parsing (P10 + int-env / api-key minors).

Imports only blkchain.config (stdlib-light), so no MLX/transformers load.
"""
import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from blkchain import config

_K = "BLKCHAIN_TEST_DOTENV_KEY"


class LoadDotenvTest(unittest.TestCase):
    """P10: inline comments on unquoted values, optional 'export ', quotes."""

    def _parse(self, line: str) -> str | None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text(f"{line}\n", encoding="utf-8")
            env = dict(os.environ)
            env.pop(_K, None)
            with mock.patch.dict(os.environ, env, clear=True):
                config._load_dotenv(p)
                return os.environ.get(_K)

    def test_unquoted_inline_comment_stripped(self):
        self.assertEqual(self._parse(f"{_K}=bar # trailing comment"), "bar")

    def test_value_that_is_only_a_comment_is_empty(self):
        self.assertEqual(self._parse(f"{_K}=      # just a comment"), "")

    def test_export_prefix_accepted(self):
        self.assertEqual(self._parse(f"export {_K}=baz"), "baz")

    def test_quoted_value_keeps_hash(self):
        self.assertEqual(self._parse(f'{_K}="a # b"'), "a # b")

    def test_single_quoted_value(self):
        self.assertEqual(self._parse(f"{_K}='quux'"), "quux")

    def test_hash_inside_token_kept(self):
        self.assertEqual(self._parse(f"{_K}=http://h/x#frag"), "http://h/x#frag")


class IntEnvTest(unittest.TestCase):
    def test_valid_value(self):
        with mock.patch.dict(os.environ, {"BLKCHAIN_TEST_INT": "7"}):
            self.assertEqual(config._int_env("BLKCHAIN_TEST_INT", 3, minimum=1), 7)

    def test_non_integer_falls_back(self):
        with mock.patch.dict(os.environ, {"BLKCHAIN_TEST_INT": "notint"}):
            self.assertEqual(config._int_env("BLKCHAIN_TEST_INT", 3), 3)

    def test_below_minimum_falls_back(self):
        with mock.patch.dict(os.environ, {"BLKCHAIN_TEST_INT": "0"}):
            self.assertEqual(config._int_env("BLKCHAIN_TEST_INT", 32, minimum=1), 32)

    def test_above_maximum_falls_back(self):
        with mock.patch.dict(os.environ, {"BLKCHAIN_TEST_INT": "99999"}):
            self.assertEqual(config._int_env("BLKCHAIN_TEST_INT", 8100, minimum=1, maximum=65535), 8100)

    def test_unset_uses_default(self):
        env = dict(os.environ)
        env.pop("BLKCHAIN_TEST_INT", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(config._int_env("BLKCHAIN_TEST_INT", 5), 5)


class OmlxApiKeyTest(unittest.TestCase):
    def test_reads_env_only(self):
        with mock.patch.dict(os.environ, {"OMLX_API_KEY": "sk-from-env"}):
            self.assertEqual(config.omlx_api_key(), "sk-from-env")

    def test_absent_env_returns_empty(self):
        env = dict(os.environ)
        env.pop("OMLX_API_KEY", None)
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(config.omlx_api_key(), "")


class EmbeddingAddressTest(unittest.TestCase):
    def test_bind_settings_and_index_url_agree(self):
        cases = [
            ({}, ["127.0.0.1", 8100, "http://127.0.0.1:8100"]),
            ({"BLKCHAIN_EMBED_HOST": "localhost", "BLKCHAIN_EMBED_PORT": "8199"},
             ["localhost", 8199, "http://localhost:8199"]),
            ({"BLKCHAIN_EMBED_PORT": "8198"}, ["127.0.0.1", 8198, "http://127.0.0.1:8198"]),
            ({"BLKCHAIN_EMBED_HOST": "::1", "BLKCHAIN_EMBED_PORT": "8196"},
             ["::1", 8196, "http://[::1]:8196"]),
            ({"BLKCHAIN_EMBED_HOST": " localhost ", "BLKCHAIN_EMBED_PORT": "bad"},
             ["localhost", 8100, "http://localhost:8100"]),
            ({"BLKCHAIN_EMBED_PORT": "99999"}, ["127.0.0.1", 8100, "http://127.0.0.1:8100"]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blkchain" / "config.py"
            path.parent.mkdir()
            path.write_text(Path(config.__file__).read_text() +
                            '\nimport json\nprint(json.dumps([EMBED_SERVER_HOST, EMBED_SERVER_PORT, EMBED_SERVER_URL]))\n')
            for env, expected in cases:
                with self.subTest(env=env):
                    result = subprocess.run([sys.executable, str(path)], env=env,
                                            capture_output=True, text=True, timeout=10, check=True)
                    self.assertEqual(json.loads(result.stdout), expected)


if __name__ == "__main__":
    unittest.main()
