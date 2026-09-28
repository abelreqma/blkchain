"""gte-reranker-modernbert-base cross-encoder reranker (MLX, Apache-2.0).

Alternative to the jina-reranker-v3 backend (CC-BY-NC), selected via
config.RERANKER_KIND == "modernbert". It scores each (query, document) pair with
a ModernBERT sequence-classification head: one relevance logit per pair. The MLX
path returns sigmoid(logit), which is monotonic, so ranking order is unchanged.
Same contract as the jina backend: rerank_documents(query, documents) ->
list[float], one score per document in input order, higher = more relevant.

Loaded once at import (like the jina backend); the embed server serializes all
inference under its own lock, so this module does not lock.
"""
from __future__ import annotations

import json
from pathlib import Path

import mlx.core as mx
import mlx.nn as nn
import numpy as np
from mlx_embeddings.models.modernbert import Model, ModelArgs
from transformers import AutoTokenizer

from blkchain import config as _config
from blkchain.rerank_scores import SENTINEL_SCORE, partition_blank, sanitize_scores

_MODEL_PATH = Path(_config.RERANKER_PATH)
_MAX_LENGTH = 512   # gte-reranker-modernbert recommended max sequence length
_SUBBATCH = 16      # bound each forward pass (query, doc) pairs


def _load_model() -> Model:
    cfg = json.loads((_MODEL_PATH / "config.json").read_text())
    args = ModelArgs.from_dict(cfg)
    model = Model(args)

    weights: dict = {}
    for wf in sorted(_MODEL_PATH.glob("model*.safetensors")):
        weights.update(mx.load(str(wf)))
    if hasattr(model, "sanitize"):
        weights = model.sanitize(weights)

    quant = cfg.get("quantization")  # this checkpoint ships fp16 (no quant block)
    if quant:
        def class_predicate(p, m):
            return hasattr(m, "to_quantized") and f"{p}.scales" in weights
        nn.quantize(model, group_size=quant["group_size"], bits=quant["bits"],
                    mode=quant.get("mode", "affine"), class_predicate=class_predicate)

    model.load_weights(list(weights.items()))
    mx.eval(model.parameters())
    model.eval()
    return model


print(f"[reranker] loading gte-reranker-modernbert (MLX): {_MODEL_PATH}", flush=True)
_MODEL = _load_model()
_TOKENIZER = AutoTokenizer.from_pretrained(str(_MODEL_PATH))
print("[reranker] ready", flush=True)


def _score_batch(query: str, docs: list[str]) -> list[float]:
    # tokenizer(text=queries, text_pair=docs) -> "[CLS] query [SEP] doc [SEP]"
    enc = _TOKENIZER([query] * len(docs), docs, padding=True, truncation=True,
                     max_length=_MAX_LENGTH)
    ids = mx.array(enc["input_ids"])
    mask = mx.array(enc["attention_mask"])
    out = _MODEL(ids, attention_mask=mask)
    scores = mx.array(out.pooler_output).astype(mx.float32).reshape(-1)
    mx.eval(scores)
    return np.array(scores).tolist()


def rerank_documents(query: str, documents: list[str]) -> list[float]:
    """One relevance score per document (input order; higher = more relevant).

    Blank/whitespace documents are ranked last without scoring (a degenerate row
    yields a meaningless mid-distribution score). Any non-finite score from the
    model is mapped to the same sort-last sentinel rather than a masked 0.0.
    """
    if not documents:
        return []
    scorable, _blank = partition_blank(documents)
    scores = [SENTINEL_SCORE] * len(documents)
    if not scorable:
        return scores
    kept = [documents[i] for i in scorable]
    raw: list[float] = []
    for i in range(0, len(kept), _SUBBATCH):
        raw.extend(_score_batch(query, kept[i:i + _SUBBATCH]))
    raw = sanitize_scores(raw)
    for pos, idx in enumerate(scorable):
        scores[idx] = raw[pos]
    return scores
