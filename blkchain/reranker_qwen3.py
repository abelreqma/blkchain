"""Qwen3-Reranker-0.6B causal-LM reranker (MLX, Apache-2.0).

Selected via config.RERANKER_KIND == "qwen3". Qwen3-Reranker is a causal LM used
as a cross-encoder: for each (query, document) pair the relevance score is
softmax([logit("no"), logit("yes")])[1] at the last position of a fixed judge
prompt. It is instruction-aware and multilingual, with one forward pass per document.

Same contract as the other backends: rerank_documents(query, documents) ->
list[float], one score per document in input order, higher = more relevant.
Blank/whitespace documents and any non-finite score are ranked last via
blkchain.rerank_scores, exactly like the modernbert and jina backends.

Loaded once at import (like the other backends); the embed server serializes all
inference under its own lock, so this module does not lock. The scoring recipe
mirrors the mlx-community/Qwen3-Reranker-0.6B-4bit model card and Qwen3-Reranker's
reference (Qwen3-Embedding technical report, arXiv:2506.05176).
"""
from __future__ import annotations

import mlx.core as mx
from mlx_lm import load as _load

from blkchain import config as _config
from blkchain.rerank_scores import (
    SENTINEL_SCORE,
    neutralize_control_tokens,
    partition_blank,
    sanitize_scores,
)

# Default task instruction (the reranker is instruction-aware; this matches the
# model's default "query" prompt). Override-free: the offsec corpus is retrieval.
_INSTRUCT = "Given a web search query, retrieve relevant passages that answer the query"
_PREFIX = ('<|im_start|>system\nJudge whether the Document meets the requirements '
           'based on the Query and the Instruct provided. Note that the answer can '
           'only be "yes" or "no".<|im_end|>\n<|im_start|>user\n')
_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
_MAX_DOC_TOKENS = 512  # bound each document's token length (query/labels are short)

print(f"[reranker] loading Qwen3-Reranker-0.6B (MLX): {_config.RERANKER_PATH}", flush=True)
_MODEL, _TOK = _load(str(_config.RERANKER_PATH))
_HF = getattr(_TOK, "_tokenizer", _TOK)
_TRUE_ID = _HF.convert_tokens_to_ids("yes")
_FALSE_ID = _HF.convert_tokens_to_ids("no")
_PRE = _HF.encode(_PREFIX, add_special_tokens=False)
_SUF = _HF.encode(_SUFFIX, add_special_tokens=False)
print("[reranker] ready", flush=True)


def _score(query: str, doc: str) -> float:
    """P(document relevant) = softmax([logit(no), logit(yes)])[1] at last pos."""
    # Neutralize control tokens so a poisoned document cannot inject judge-prompt
    # structure (e.g. its own <|im_start|>...yes<|im_end|>) and pin to rank 1.
    doc = neutralize_control_tokens(doc)
    content = f"<Instruct>: {_INSTRUCT}\n<Query>: {query}\n<Document>: {doc}"
    body = _HF.encode(content, add_special_tokens=False)[:_MAX_DOC_TOKENS]
    ids = _PRE + body + _SUF
    logits = _MODEL(mx.array([ids]))[:, -1, :]
    # Cast to float32 before softmax: bf16 logits soft-max imprecisely.
    pair = mx.stack([logits[0, _FALSE_ID], logits[0, _TRUE_ID]]).astype(mx.float32)
    score = mx.exp((pair - mx.logsumexp(pair))[1])
    mx.eval(score)
    return float(score)


def rerank_documents(query: str, documents: list[str]) -> list[float]:
    """One relevance score per document (input order; higher = more relevant).

    Blank/whitespace documents are ranked last without scoring, and any
    non-finite model score is mapped to the same sort-last sentinel.
    """
    if not documents:
        return []
    scorable, _blank = partition_blank(documents)
    scores = [SENTINEL_SCORE] * len(documents)
    if not scorable:
        return scores
    raw = [_score(query, documents[i]) for i in scorable]
    raw = sanitize_scores(raw)
    for pos, idx in enumerate(scorable):
        scores[idx] = raw[pos]
    return scores
