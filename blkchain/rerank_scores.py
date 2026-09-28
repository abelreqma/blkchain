"""Pure score-sanitization for the cross-encoder reranker (stdlib only).

The cross-encoder can emit two kinds of bad scores:

- a degenerate row: an empty or whitespace-only document, whose pooled
  representation is dominated by the query tokens alone, yields a meaningless
  relevance score that can land anywhere in the distribution (observed: an
  empty document scored 0.62, whitespace 0.49, above a lower relevant doc);
- a genuine non-finite score (NaN / +-Inf) that can slip through numerically.

Both must be ranked LAST, not silently coerced to a mid-distribution 0.0 that
hides a real ranking defect (a good doc buried, or junk floated up). Model scores
are sigmoid outputs in [0, 1], so SENTINEL_SCORE = -1.0 sorts below every valid
score. Non-finite and blank cases are logged to stderr so a real defect surfaces.

This module has no heavy imports so the logic is unit-testable without loading
MLX, transformers, or any model (reranker_modernbert imports mlx at module top).
"""
from __future__ import annotations

import math
import sys
from collections.abc import Sequence

# Model scores are sigmoid(logit) in [0, 1]; this sorts strictly below all of them.
SENTINEL_SCORE = -1.0


def is_blank_document(doc: str) -> bool:
    """True for an empty or whitespace-only document (a degenerate row)."""
    return not doc or not doc.strip()


def partition_blank(documents: Sequence[str]) -> tuple[list[int], list[int]]:
    """Split document indices into (scorable, blank); warn about blanks.

    Blank documents are excluded from scoring and get SENTINEL_SCORE by the
    caller. Warning names the count and indices so a stream of blank inputs is
    visible rather than silently ranked last.
    """
    scorable: list[int] = []
    blank: list[int] = []
    for i, doc in enumerate(documents):
        (blank if is_blank_document(doc) else scorable).append(i)
    if blank:
        print(f"[reranker] WARNING: {len(blank)} blank/whitespace document(s) at "
              f"indices {blank}; ranked last (score {SENTINEL_SCORE})",
              file=sys.stderr, flush=True)
    return scorable, blank


def sanitize_scores(scores: Sequence[float], *,
                    sentinel: float = SENTINEL_SCORE) -> list[float]:
    """Return scores with any non-finite value mapped to `sentinel`.

    Finite scores pass through unchanged. A NaN/+-Inf is mapped to the sort-last
    sentinel (never to a mid-distribution 0.0) and the count and indices are
    logged to stderr, so a genuine numeric defect surfaces instead of hiding.
    """
    out: list[float] = []
    bad: list[int] = []
    for i, s in enumerate(scores):
        v = float(s)
        if math.isfinite(v):
            out.append(v)
        else:
            out.append(sentinel)
            bad.append(i)
    if bad:
        print(f"[reranker] WARNING: {len(bad)} non-finite score(s) at indices "
              f"{bad}; mapped to {sentinel} (ranked last)",
              file=sys.stderr, flush=True)
    return out
