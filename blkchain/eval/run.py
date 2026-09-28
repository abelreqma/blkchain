"""Evaluation runner: `python -m blkchain.eval.run`.

Two independent layers:

1. RETRIEVAL METRICS (primary gate, deterministic, no LLM). For each labeled
   case, kb_search is called once for a pool of max(top_k, 10) results. A case
   is a HIT@k when one result in the top-k matches an expected substring, an
   expected source (when labeled), and an expected CWE (when labeled). All
   labels must match the same result. We report hit_rate@5, hit_rate@10 and MRR.

2. ANSWER METRICS (best-effort, LLM-judged with the local oMLX model). Wraps
   deepeval Faithfulness / AnswerRelevancy against agent.kb_answer output. If
   the local judge is unavailable or unreliable it is reported as
   judge_unavailable and the process still exits 0.
"""
from __future__ import annotations

import blkchain.eval  # noqa: F401  -- sets telemetry opt-out before deepeval import

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from blkchain import config
from blkchain.retrieve import kb_search

DATASET_PATH = Path(__file__).resolve().parent / "dataset.jsonl"
REPORT_PATH = config.ROOT / ".reports" / "eval-report.md"

# Retrieval is pooled to at least this depth so hit@5, hit@10 and MRR all come
# from a single kb_search call per case.
_METRIC_DEPTH = 10


# --- Dataset ---------------------------------------------------------------
@dataclass
class Case:
    query: str
    expected_substrings: list[str]
    expected_sources: list[str] = field(default_factory=list)
    expected_cwe: str | None = None
    notes: str = ""
    difficulty: str = "core"  # "core" (on-topic) or "hard" (paraphrase/typo/multi-hop)


def load_dataset(path: Path = DATASET_PATH) -> list[Case]:
    cases: list[Case] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        cases.append(
            Case(
                query=obj["query"],
                expected_substrings=[s.lower() for s in obj["expected_substrings"]],
                expected_sources=obj.get("expected_sources", []),
                expected_cwe=obj.get("expected_cwe"),
                notes=obj.get("notes", ""),
                difficulty=obj.get("difficulty", "core"),
            )
        )
    return cases


def _breakdown_by_difficulty(case_results: list["CaseResult"]) -> list[tuple[str, int, int]]:
    """Per-difficulty (label, hits@5, total), so a 'hard' subset can discriminate
    retriever configs even when the 'core' subset saturates at 100%."""
    out = []
    for label in ("core", "hard"):
        group = [c for c in case_results if c.case.difficulty == label]
        if group:
            out.append((label, sum(1 for c in group if c.hit_at(5)), len(group)))
    return out


# --- Retrieval metrics -----------------------------------------------------
@dataclass
class CaseResult:
    case: Case
    n_results: int
    first_rank: int | None       # 1-based rank of first complete labeled match
    first_text_rank: int | None
    first_source_rank: int | None
    matched_substring: str | None
    matched_source: str | None

    def hit_at(self, k: int) -> bool:
        return self.first_rank is not None and self.first_rank <= k

    @property
    def mrr(self) -> float:
        # Reciprocal rank of the first result satisfying every case label.
        if self.first_rank is None or self.first_rank > _METRIC_DEPTH:
            return 0.0
        return 1.0 / self.first_rank


def evaluate_retrieval(case: Case, results: list[dict]) -> CaseResult:
    first_rank: int | None = None
    first_text_rank: int | None = None
    first_source_rank: int | None = None
    matched: str | None = None
    matched_source: str | None = None
    for i, r in enumerate(results, start=1):
        payload = r.get("payload", {})
        haystack = ((payload.get("text") or "") + " " + str(payload.get("path") or "")).lower()
        source = str(payload.get("source") or "")
        sub = next((s for s in case.expected_substrings if s in haystack), None)
        if sub is None:
            continue
        if first_text_rank is None:
            first_text_rank = i
        source_ok = not case.expected_sources or source.casefold() in {s.casefold() for s in case.expected_sources}
        if source_ok and first_source_rank is None:
            first_source_rank = i
        cwe_ok = not case.expected_cwe or (payload.get("cwe_class") or "").casefold() == case.expected_cwe.casefold()
        if source_ok and cwe_ok:
            first_rank = i
            matched = sub
            matched_source = source
            break
    return CaseResult(
        case=case,
        n_results=len(results),
        first_rank=first_rank,
        first_text_rank=first_text_rank,
        first_source_rank=first_source_rank,
        matched_substring=matched,
        matched_source=matched_source,
    )


def run_retrieval(cases: list[Case], top_k: int, collection: str | None = None) -> list[CaseResult]:
    depth = max(top_k, _METRIC_DEPTH)
    out: list[CaseResult] = []
    for case in cases:
        results = kb_search(case.query, top_k=depth, collection=collection)
        out.append(evaluate_retrieval(case, results))
    return out


# --- Local oMLX judge (deepeval custom model) ------------------------------
def _build_judge():
    """Construct a deepeval model wrapping the local oMLX endpoint.

    Imported lazily so the retrieval gate never depends on deepeval.
    """
    from deepeval.models import DeepEvalBaseLLM

    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - openai is a pinned dep
        raise RuntimeError(f"openai client unavailable: {exc}") from exc

    _THINKING_OFF = {"chat_template_kwargs": {"enable_thinking": False}}

    class OMLXJudge(DeepEvalBaseLLM):
        """Wraps oMLX exactly like agent._chat (temperature 0, thinking off)."""

        def __init__(self) -> None:
            self._client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.omlx_api_key())
            super().__init__(config.LLM_MODEL)

        def load_model(self):
            return None

        def get_model_name(self) -> str:
            return config.LLM_MODEL

        def _complete(self, prompt: str, max_tokens: int = 1024) -> str:
            resp = self._client.chat.completions.create(
                model=config.LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=max_tokens,
                extra_body=_THINKING_OFF,
            )
            choices = resp.choices
            if not choices:
                raise RuntimeError("oMLX returned no choices")
            return choices[0].message.content or ""

        def generate(self, prompt: str, schema=None):
            if schema is None:
                return self._complete(prompt)
            # deepeval wants a pydantic object: instruct JSON-only and parse.
            instruction = (
                "\n\nRespond with ONLY a single JSON object, no prose and no code "
                "fences, matching this JSON schema:\n"
                f"{json.dumps(schema.model_json_schema())}"
            )
            # Verdict lists (one entry per claim) can be long; a small cap
            # truncates the JSON mid-object and fails the parse. Give structured
            # generation a generous budget (output tokens are cheap on oMLX).
            raw = self._complete(prompt + instruction, max_tokens=4096)
            start, end = raw.find("{"), raw.rfind("}")
            if start == -1 or end == -1 or end < start:
                raise ValueError(f"judge returned no JSON object: {raw[:200]!r}")
            try:
                data = json.loads(raw[start : end + 1])
            except json.JSONDecodeError as exc:
                raise ValueError(f"judge JSON parse failed: {exc}; raw={raw[:200]!r}") from exc
            return schema.model_validate(data)

        async def a_generate(self, prompt: str, schema=None):
            return self.generate(prompt, schema=schema)

    return OMLXJudge()


@dataclass
class JudgeResult:
    query: str
    faithfulness: float | None = None
    relevancy: float | None = None
    error: str | None = None


def run_judge(cases: list[Case], judge_limit: int) -> tuple[list[JudgeResult], str | None]:
    """Best-effort LLM-judged answer metrics. Returns (results, unavailable_reason)."""
    subset = cases[:judge_limit]
    if not subset:
        return [], None
    try:
        from blkchain.agent import kb_answer
        from deepeval.metrics import AnswerRelevancyMetric, FaithfulnessMetric
        from deepeval.test_case import LLMTestCase

        judge = _build_judge()
    except Exception as exc:  # deepeval/openai import or judge construction failed
        return [], f"{type(exc).__name__}: {exc}"

    results: list[JudgeResult] = []
    any_scored = False
    last_error: str | None = None
    for case in subset:
        jr = JudgeResult(query=case.query)
        try:
            answer = kb_answer(case.query)
            # Cap judged context (count + chars per chunk) so the faithfulness
            # prompt stays bounded.
            max_ctx = int(os.environ.get("BLKCHAIN_JUDGE_MAX_CONTEXTS", "4"))
            max_chars = int(os.environ.get("BLKCHAIN_JUDGE_CONTEXT_CHARS", "800"))
            context = [
                (r.get("payload", {}).get("text") or "")[:max_chars]
                for r in answer.get("results", [])[:max_ctx]
                if (r.get("payload", {}).get("text") or "").strip()
            ]
            test_case = LLMTestCase(
                input=case.query,
                actual_output=answer.get("answer", ""),
                retrieval_context=context or ["(no retrieval context)"],
            )
            faith = FaithfulnessMetric(model=judge, async_mode=False, include_reason=False)
            rel = AnswerRelevancyMetric(model=judge, async_mode=False, include_reason=False)
            faith.measure(test_case)
            rel.measure(test_case)
            jr.faithfulness = faith.score
            jr.relevancy = rel.score
            any_scored = True
        except Exception as exc:
            jr.error = f"{type(exc).__name__}: {exc}"
            last_error = jr.error
        results.append(jr)

    unavailable = None if any_scored else (last_error or "no cases judged")
    return results, unavailable


# --- Reporting -------------------------------------------------------------
def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def build_report(
    case_results: list[CaseResult],
    top_k: int,
    judge_results: list[JudgeResult],
    judge_unavailable: str | None,
    judge_skipped: bool,
    collection: str | None = None,
) -> str:
    n = len(case_results)
    hit5 = sum(1 for c in case_results if c.hit_at(5))
    hit10 = sum(1 for c in case_results if c.hit_at(10))
    mrr = sum(c.mrr for c in case_results) / n if n else 0.0

    lines: list[str] = []
    lines.append("# blkChain RAG evaluation report")
    lines.append("")
    lines.append(f"- dataset: `{DATASET_PATH}` ({n} cases)")
    lines.append(f"- collection: `{collection or config.QDRANT_COLLECTION}`  |  pool depth: {max(top_k, _METRIC_DEPTH)}  |  --top-k: {top_k}")
    lines.append(f"- llm model: `{config.LLM_MODEL}`")
    lines.append("")
    lines.append("## Retrieval metrics (primary gate, deterministic)")
    lines.append("")
    lines.append(f"- hit_rate@5:  **{_fmt_pct(hit5 / n)}** ({hit5}/{n})")
    lines.append(f"- hit_rate@10: **{_fmt_pct(hit10 / n)}** ({hit10}/{n})")
    lines.append(f"- MRR:         **{mrr:.3f}**")
    for label, h, t in _breakdown_by_difficulty(case_results):
        lines.append(f"- hit_rate@5 ({label}): {_fmt_pct(h / t)} ({h}/{t})")
    lines.append("")
    lines.append("| # | query | hit@5 | rank | matched source | matched substring |")
    lines.append("|---|-------|-------|------|----------------|-------------------|")
    for i, c in enumerate(case_results, start=1):
        rank = str(c.first_rank) if c.first_rank is not None else "-"
        matched = c.matched_substring or ""
        source = (c.matched_source or "").replace("|", "\\|")
        query = c.case.query.replace("|", "\\|")
        lines.append(f"| {i} | {query} | {'Y' if c.hit_at(5) else 'N'} | {rank} | {source} | {matched} |")
    lines.append("")

    misses = [c for c in case_results if not c.hit_at(5)]
    if misses:
        lines.append("### Missed queries (not hit@5)")
        lines.append("")
        for c in misses:
            reason = "no expected substring in top-10 pool"
            if c.first_text_rank is not None and c.case.expected_sources and c.first_source_rank is None:
                reason = "expected substring appears, but not from an expected source"
            elif c.first_source_rank is not None and c.case.expected_cwe and c.first_rank is None:
                reason = f"expected substring/source match appears, but not with CWE '{c.case.expected_cwe}'"
            elif c.first_rank is not None and c.first_rank > 5:
                reason = f"complete labeled match first appears at rank {c.first_rank} (below top-5)"
            lines.append(f"- {c.case.query}: {reason}")
        lines.append("")

    lines.append("## Answer metrics (best-effort, local LLM judge)")
    lines.append("")
    if judge_skipped:
        lines.append("_skipped (--no-judge)_")
    elif judge_unavailable:
        lines.append(f"**judge_unavailable:** {judge_unavailable}")
        lines.append("")
        lines.append("Retrieval metrics above stand on their own; the answer layer is best-effort.")
    else:
        lines.append("| query | faithfulness | relevancy | note |")
        lines.append("|-------|--------------|-----------|------|")
        for jr in judge_results:
            q = jr.query.replace("|", "\\|")
            if jr.error:
                lines.append(f"| {q} | - | - | {jr.error.replace('|', '\\|')} |")
            else:
                f = f"{jr.faithfulness:.3f}" if jr.faithfulness is not None else "-"
                r = f"{jr.relevancy:.3f}" if jr.relevancy is not None else "-"
                lines.append(f"| {q} | {f} | {r} | |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="blkChain RAG evaluation harness")
    parser.add_argument("--top-k", type=int, default=5, help="final top-k for hit@k table (default 5)")
    parser.add_argument("--limit", type=int, default=None, help="evaluate only the first N cases")
    parser.add_argument("--no-judge", action="store_true", help="skip LLM answer metrics")
    parser.add_argument("--judge-limit", type=int, default=3, help="judge only the first N cases (default 3)")
    parser.add_argument("--collection", default=None,
                        help="Qdrant collection to evaluate (default config.QDRANT_COLLECTION); "
                             "use to A/B an alternate-embedder index")
    args = parser.parse_args()

    cases = load_dataset()
    if args.limit is not None:
        cases = cases[: args.limit]

    print(f"Loaded {len(cases)} case(s) from {DATASET_PATH}")
    print(f"Running retrieval (pool depth {max(args.top_k, _METRIC_DEPTH)}) ...\n")

    case_results = run_retrieval(cases, args.top_k, collection=args.collection)

    # Console table
    print(f"{'#':>2}  {'hit@5':^5}  {'rank':>4}  {'matched':<24}  query")
    print("-" * 100)
    for i, c in enumerate(case_results, start=1):
        rank = str(c.first_rank) if c.first_rank is not None else "-"
        matched = (c.matched_substring or "")[:24]
        print(f"{i:>2}  {('Y' if c.hit_at(5) else 'N'):^5}  {rank:>4}  {matched:<24}  {c.case.query}")

    n = len(case_results)
    hit5 = sum(1 for c in case_results if c.hit_at(5))
    hit10 = sum(1 for c in case_results if c.hit_at(10))
    mrr = sum(c.mrr for c in case_results) / n if n else 0.0
    print("-" * 100)
    print(f"hit_rate@5 = {_fmt_pct(hit5 / n)} ({hit5}/{n})   "
          f"hit_rate@10 = {_fmt_pct(hit10 / n)} ({hit10}/{n})   MRR = {mrr:.3f}")
    breakdown = _breakdown_by_difficulty(case_results)
    if len(breakdown) > 1:
        print("  by difficulty:  " + "   ".join(
            f"{label} {_fmt_pct(h / t)} ({h}/{t})" for label, h, t in breakdown))

    misses = [c for c in case_results if not c.hit_at(5)]
    if misses:
        print("\nMissed@5:")
        for c in misses:
            rank = c.first_rank if c.first_rank is not None else "none"
            print(f"  - {c.case.query} (first substring rank: {rank})")

    judge_results: list[JudgeResult] = []
    judge_unavailable: str | None = None
    if not args.no_judge:
        print(f"\nRunning LLM judge on first {min(args.judge_limit, len(cases))} case(s) "
              f"(local generation is slow) ...")
        judge_results, judge_unavailable = run_judge(cases, args.judge_limit)
        if judge_unavailable:
            print(f"judge_unavailable: {judge_unavailable}")
        else:
            for jr in judge_results:
                if jr.error:
                    print(f"  - {jr.query}: ERROR {jr.error}")
                else:
                    print(f"  - {jr.query}: faithfulness={jr.faithfulness:.3f} relevancy={jr.relevancy:.3f}")

    report = build_report(case_results, args.top_k, judge_results, judge_unavailable,
                          args.no_judge, collection=args.collection)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"\nReport written to {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
