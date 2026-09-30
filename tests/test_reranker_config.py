"""Hermetic tests for reranker backend selection/path wiring.

Runs blkchain.config in a fresh subprocess with env set, so it neither loads a
model nor mutates the parent process's already-imported config module. Only
config.py is imported (stdlib-light: os, pathlib, json), so no MLX/transformers.
"""
import os
import subprocess
import sys
import unittest

_CODE = "from blkchain import config as c; print(c.RERANKER_KIND); print(c.RERANKER_PATH.name)"


def _run(env_extra: dict) -> tuple[str, str]:
    env = {**os.environ, **env_extra}
    env.pop("BLKCHAIN_RERANKER_PATH", None)  # test defaults unless overridden
    for k, v in env_extra.items():
        env[k] = v
    r = subprocess.run([sys.executable, "-c", _CODE], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    kind, name = r.stdout.strip().splitlines()[-2:]
    return kind, name


class TestRerankerPathWiring(unittest.TestCase):
    def test_qwen3_kind_resolves_qwen3_model_dir(self):
        kind, name = _run({"BLKCHAIN_RERANKER_KIND": "qwen3"})
        self.assertEqual(kind, "qwen3")
        self.assertEqual(name, "Qwen3-Reranker-0.6B-4bit")

    def test_bare_default_is_modernbert(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("BLKCHAIN_RERANKER_KIND", "BLKCHAIN_RERANKER_PATH")}
        r = subprocess.run([sys.executable, "-c", _CODE], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        kind, name = r.stdout.strip().splitlines()[-2:]
        self.assertEqual(kind, "modernbert")
        self.assertEqual(name, "gte-reranker-modernbert-base-mlx")

    def test_modernbert_still_selectable(self):
        kind, name = _run({"BLKCHAIN_RERANKER_KIND": "modernbert"})
        self.assertEqual(kind, "modernbert")
        self.assertEqual(name, "gte-reranker-modernbert-base-mlx")

    def test_jina_still_selectable(self):
        kind, name = _run({"BLKCHAIN_RERANKER_KIND": "jina"})
        self.assertEqual(kind, "jina")
        self.assertEqual(name, "jina-reranker-v3-4bit-mxfp4")

    def test_explicit_path_override_wins(self):
        env = {**os.environ, "BLKCHAIN_RERANKER_KIND": "qwen3",
               "BLKCHAIN_RERANKER_PATH": "custom-reranker-dir"}
        r = subprocess.run([sys.executable, "-c", _CODE], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], "custom-reranker-dir")


if __name__ == "__main__":
    unittest.main()
