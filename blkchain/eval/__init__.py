"""Evaluation harness for the blkChain RAG system.

Retrieval quality uses deterministic hit-rate and reciprocal-rank metrics.
Answer quality is a best-effort LLM-judged pass using the same local oMLX model.

The harness is fully local: no Confident AI login, no telemetry, no external
API key. The opt-out env flag is set here so it applies before deepeval is
imported anywhere in the process.
"""
from __future__ import annotations

import os

# Fully local / offline: disable deepeval telemetry and any login attempt.
os.environ.setdefault("DEEPEVAL_TELEMETRY_OPT_OUT", "YES")
os.environ.setdefault("ERROR_REPORTING", "NO")
