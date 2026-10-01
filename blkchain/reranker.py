"""Reranker dispatcher.

Selects the reranker backend at import time from config.RERANKER_KIND and
re-exports its rerank_documents(query, documents) -> list[float]. Only the
selected backend is imported, so only its model is loaded. Consumers keep
importing `from blkchain.reranker import rerank_documents` unchanged.

  jina       -> reranker_jina        (jina-reranker-v3 listwise, CC-BY-NC-4.0)
  modernbert -> reranker_modernbert  (gte-reranker-modernbert-base, Apache-2.0)
  qwen3      -> reranker_qwen3        (Qwen3-Reranker-0.6B causal LM, Apache-2.0)
"""
from __future__ import annotations

from blkchain import config

if config.RERANKER_KIND == "modernbert":
    from blkchain.reranker_modernbert import rerank_documents
elif config.RERANKER_KIND == "qwen3":
    from blkchain.reranker_qwen3 import rerank_documents
elif config.RERANKER_KIND == "jina":
    from blkchain.reranker_jina import rerank_documents
else:
    # An unknown kind must fail loudly, never silently fall through to jina
    # (CC-BY-NC-4.0, non-commercial) as the old `else` branch did (PI14).
    raise ValueError(
        f"unknown BLKCHAIN_RERANKER_KIND: {config.RERANKER_KIND!r}; "
        "expected one of: modernbert, qwen3, jina"
    )

__all__ = ["rerank_documents"]
