"""jina-reranker-v3 listwise reranker, served locally via MLX.

Loads the local 4-bit MLX build (blkchain.config.RERANKER_PATH) once at
import time and exposes rerank_documents(query, documents) -> list[float].

Why not mlx_embeddings.load(): the generic Qwen3 loader in mlx-embeddings
knows only the backbone. jina-reranker-v3 adds a `projector` head on top
(two Linear layers, no bias) that turns the backbone's hidden states at two
special token positions into the listwise relevance score. Loading the
checkpoint with mlx_embeddings.load() fails with "Received 4 parameters not
in model: model.projector.layers.0.scales, ...weight, ...layers.2.scales,
...weight" because its Model class has no `projector` attribute.

This module defines a small MLX model -- the same Qwen3 backbone class from
mlx_embeddings plus a matching `projector` -- so the checkpoint's weights
(backbone + projector, both mxfp4-quantized) load and quantize cleanly. The
scoring itself mirrors jina's reference `JinaForRanking.rerank()` (see the
model repo's modeling.py, which is a torch/transformers implementation we do
not use): build one prompt containing the query and all documents, run one
forward pass, pull the hidden state at each document's <|embed_token|> and
the query's <|rerank_token|>, project both through the projector head, and
score by cosine similarity. Documents are processed in blocks so a very long
document list stays within the model's context window; block query
embeddings are then combined with the reference's weighted average.
"""
from __future__ import annotations

import json
from pathlib import Path

import mlx.core as mx
import mlx.nn as nn
import numpy as np
from mlx_embeddings.models.qwen3 import ModelArgs as _Qwen3Args
from mlx_embeddings.models.qwen3 import Qwen3Model as _Qwen3Model
from transformers import AutoTokenizer

from blkchain import config as _config

_MODEL_PATH = Path(_config.RERANKER_PATH)

_DOC_TOKEN = "<|embed_token|>"
_QUERY_TOKEN = "<|rerank_token|>"
_PROJECTOR_DIM = 512

_MAX_QUERY_TOKENS = 512
_MAX_DOC_TOKENS = 2048
_MAX_DOCS_PER_BLOCK = 125

_SYSTEM_PROMPT = (
    "You are a search relevance expert who can determine a ranking of the passages based on how relevant they are to the query. "
    "If the query is a question, how relevant a passage is depends on how well it answers the question. "
    "If not, try to analyze the intent of the query and assess how well each passage satisfies the intent. "
    "If an instruction is provided, you should follow the instruction when determining the ranking."
)


class _RerankModel(nn.Module):
    """Qwen3 backbone (reused from mlx_embeddings) + jina's projector head."""

    def __init__(self, args: _Qwen3Args):
        super().__init__()
        self.model = _Qwen3Model(args)
        hidden = args.hidden_size
        self.projector = nn.Sequential(
            nn.Linear(hidden, hidden // 2, bias=False),
            nn.ReLU(),
            nn.Linear(hidden // 2, _PROJECTOR_DIM, bias=False),
        )

    def __call__(self, input_ids: mx.array) -> mx.array:
        return self.model(input_ids)


def _load_model() -> _RerankModel:
    cfg = json.loads((_MODEL_PATH / "config.json").read_text())
    args = _Qwen3Args.from_dict(cfg)
    model = _RerankModel(args)

    weights = {}
    for wf in sorted(_MODEL_PATH.glob("model*.safetensors")):
        weights.update(mx.load(str(wf)))

    quant = cfg["quantization"]

    def class_predicate(p, m):
        if not hasattr(m, "to_quantized"):
            return False
        return f"{p}.scales" in weights

    nn.quantize(
        model,
        group_size=quant["group_size"],
        bits=quant["bits"],
        mode=quant.get("mode", "affine"),
        class_predicate=class_predicate,
    )

    model.load_weights(list(weights.items()))
    mx.eval(model.parameters())
    model.eval()
    return model


print(f"[reranker] loading jina-reranker-v3 (MLX): {_MODEL_PATH}", flush=True)
_MODEL = _load_model()
_TOKENIZER = AutoTokenizer.from_pretrained(str(_MODEL_PATH))
if _TOKENIZER.pad_token is None:
    _TOKENIZER.pad_token = _TOKENIZER.eos_token
_DOC_TOKEN_ID = _TOKENIZER.convert_tokens_to_ids(_DOC_TOKEN)
_QUERY_TOKEN_ID = _TOKENIZER.convert_tokens_to_ids(_QUERY_TOKEN)
_MAX_LENGTH = _TOKENIZER.model_max_length
print("[reranker] ready", flush=True)


def _truncate(text: str, max_tokens: int) -> tuple[str, int]:
    ids = _TOKENIZER(text, truncation=True, max_length=max_tokens)["input_ids"]
    if len(ids) >= max_tokens:
        text = _TOKENIZER.decode(ids)
    return text, len(ids)


def _build_prompt(query: str, docs: list[str]) -> str:
    prefix = f"<|im_start|>system\n{_SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n"
    suffix = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
    body = (
        f"I will provide you with {len(docs)} passages, each indicated by a numerical identifier. "
        f"Rank the passages based on their relevance to query: {query}\n"
    )
    body += "\n".join(f'<passage id="{i}">\n{d}{_DOC_TOKEN}\n</passage>' for i, d in enumerate(docs)) + "\n"
    body += f"<query>\n{query}{_QUERY_TOKEN}\n</query>"
    return prefix + body + suffix


def _score_block(query: str, docs: list[str]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """One forward pass over (query, docs). Returns (doc_embeds, query_embed, scores)."""
    prompt = _build_prompt(query, docs)
    ids = _TOKENIZER(prompt)["input_ids"]
    input_ids = mx.array([ids])

    hidden = _MODEL(input_ids)[0]  # (seq, hidden)

    doc_positions = [i for i, t in enumerate(ids) if t == _DOC_TOKEN_ID]
    query_positions = [i for i, t in enumerate(ids) if t == _QUERY_TOKEN_ID]
    assert len(doc_positions) == len(docs), "doc token count mismatch"
    assert len(query_positions) == 1, "expected exactly one query token"

    doc_hidden = hidden[mx.array(doc_positions)]
    query_hidden = hidden[mx.array(query_positions)]

    doc_embeds = _MODEL.projector(doc_hidden)
    query_embed = _MODEL.projector(query_hidden)[0]
    mx.eval(doc_embeds, query_embed)

    doc_embeds = np.array(doc_embeds)
    query_embed = np.array(query_embed)

    scores = np.dot(doc_embeds, query_embed) / (
        np.linalg.norm(doc_embeds, axis=1) * np.linalg.norm(query_embed) + 1e-12
    )
    return doc_embeds, query_embed, scores


def rerank_documents(query: str, documents: list[str]) -> list[float]:
    """Return one relevance score per document (same order as input; higher = more relevant)."""
    if not documents:
        return []

    query, query_length = _truncate(query, _MAX_QUERY_TOKENS)

    docs: list[str] = []
    doc_lengths: list[int] = []
    for d in documents:
        d2, length = _truncate(d, _MAX_DOC_TOKENS)
        docs.append(d2)
        doc_lengths.append(length)

    length_capacity = _MAX_LENGTH - 2 * query_length

    all_doc_embeds: list[np.ndarray] = []
    block_query_embeds: list[np.ndarray] = []
    block_weights: list[float] = []

    def _run_block(block_docs: list[str]) -> None:
        doc_e, q_e, scores = _score_block(query, block_docs)
        all_doc_embeds.extend(doc_e)
        block_query_embeds.append(q_e)
        block_weights.append(float(np.max((1.0 + scores) / 2.0)))

    block_docs: list[str] = []
    for length, doc in zip(doc_lengths, docs):
        block_docs.append(doc)
        length_capacity -= length
        if len(block_docs) >= _MAX_DOCS_PER_BLOCK or length_capacity <= _MAX_DOC_TOKENS:
            _run_block(block_docs)
            block_docs = []
            length_capacity = _MAX_LENGTH - 2 * query_length

    if block_docs:
        _run_block(block_docs)

    doc_embeds = np.array(all_doc_embeds)
    query_embed = np.average(np.array(block_query_embeds), axis=0, weights=np.array(block_weights))

    scores = np.dot(doc_embeds, query_embed) / (
        np.linalg.norm(doc_embeds, axis=1) * np.linalg.norm(query_embed) + 1e-12
    )
    return scores.tolist()
