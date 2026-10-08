# Architecture

This document is for people changing blkChain. For installing and running it, see the README.

## The language boundary

Go is the single implementation for search, ask, health, and MCP. The `blk` binary owns retrieval
orchestration (Qdrant over gRPC plus the embedding server) and the bounded answer loop in
`cli/rag.go`.

Python serves the MLX models (`blkchain/embed_server.py`) and builds the index offline
(`ingest.py`, `index.py`, `add.py`, reached through `blk add`). Python has no query-time code: there
is no Python search, answer, HTTP API, or MCP server. Do not add one.

## Repository layout

| Path | Contents |
| --- | --- |
| `cli/` | The `blk` terminal client: retrieval, the answer loop, the engagement harness, policy enforcement, web analysis, storage, reports, and the MCP server. |
| `cli/internal/` | Packages the binary shares: `secgate` (the command gate), `engagement` (the store), `histstore` (conversation memory and the session listing), `ragconfig` (the parameter contract), `retrieval` (the Qdrant and embedding clients), and the web analysis packages. |
| `cli/runner/` | The isolated runner image: `Dockerfile`, the `execute.py` launcher, and the package locks. |
| `blkchain/` | The MLX embedding and reranking service, offline indexing, and the evaluation harness. |
| `blkchain/contract/rag.json` | The RAG parameter contract both languages read. |
| `tests/` | Python unit tests. |

Models and corpus live outside the repository and are ignored by git. Nothing here bundles model
weights or corpus data.

## The cross-language contracts

Two contracts are load-bearing. Both must stay stable and in lockstep across Go and Python.

### The embedding server wire contract

`embed_server` is the only Python HTTP server. The Go client (`cli/internal/retrieval`) and
`index.py` consume it.

```
GET  /health  -> {"status": "ok", "embedder": true, "reranker": bool}
POST /embed   {"texts": [str]} -> {"embeddings": [[float]], "dim": int}
POST /rerank  {"query": str, "documents": [str]} -> {"scores": [float]}
```

Rules:

- Responses must be strict, spec-valid JSON. Python's `json.dumps` emits bare `NaN`, `Infinity`, and
  `-Infinity` by default, which strict parsers such as Go's `encoding/json` reject.
  `httputil.send_json` sanitizes non-finite floats to `null` and passes `allow_nan=False`. A
  non-finite score anywhere in a payload must not corrupt the whole response.
- Request bodies are bounded. `httputil.read_json_body` parses Content-Length defensively, rejects
  an oversized body with 413 before allocating, and returns 400 on malformed JSON.
- A 500 never returns the exception type or message. Use
  `httputil.send_error(handler, code, public_message, exc=e)`, which logs the detail to stderr and
  sends only the generic message.
- Do not change field names or shapes without updating the Go client in the same commit.

### The RAG parameter contract

`blkchain/contract/rag.json` holds the parameters shared across languages: `top_k`, `pool_size`,
`max_loops`, the answer and grade token and chunk caps, the temperatures, the answer sampling
settings, the dense and sparse vector names, the sparse model, the Qdrant gRPC URL, the embedding
server URL, and the reputable-domain and proof-of-concept domain lists.

The Go client loads it through `cli/internal/ragconfig` with precedence environment, then
`rag.json`, then a compiled-in fallback. The fallback must match `rag.json` byte for byte;
`TestBuiltinDefaultsMatchContractFile` enforces that, so a standalone `blk` binary behaves the same
as one run from the repository. When you change a value in `rag.json`, update `builtinDefaults()` in
the same commit or that test fails.

Python does not read `rag.json`. It keeps its own copies of the few shared values it still needs for
indexing: `SPARSE_MODEL`, the dense and sparse vector names, and the embedding server URL, all in
`config.py`. No test checks that they agree with `rag.json`, so change the matching Python constant
in the same commit.

### The command output contracts

The JSON that `blk` prints is produced by Go. The evaluation harness parses it, so these shapes are
a contract too.

- `blk search --json`: `{"results": [{"id", "score", "payload": {source, path, section, type, text,
  cwe_class, origin?}}]}`. `origin` is the indexer's provenance tag, present only on content that
  `blk add <url>` fetched, so it is read when present rather than required. The answer path treats
  any non-empty origin as external, so a tag added later cannot default to trusted.
- `blk ask --json`: requires `--agent`; without it the command is a usage error and exits 2. The
  payload carries the answer, citations, the web-use flag, the model, the agent, per-call LLM
  metrics, and the results. `untrusted` is true on a web citation and omitted on a local one.
- `blk sources --json`: the collection, the total chunk count, and per-source counts, sorted by
  count descending then name. It reads one Qdrant facet, so it is read-only.
- `blk health --json`: `{"ok": bool, "qdrant": bool, "embed_server": bool, "llm": bool}`. `ok` is
  true only when all three are up, and the command exits 1 when any is down.

Every payload carries `cwe_class`, as `""` when the indexed chunk has no concept tag.

## Security invariants

Do not weaken these.

### Authorization and operator safety

`blk engage` is an autonomous assessment tool. The operator's authorization is the premise for
target testing; the active engagement's rules of engagement define the allowed targets, actions,
time window, and rate. When the policy authorizes active or state-changing testing, the tool may
perform it autonomously within those bounds. Per-action human confirmation is not a universal
security control. Require an operator decision when the policy does not authorize an action or when
its bounds are ambiguous.

Protect the operator and the runner from the target. Treat pages, responses, files, and tool output
from a target as hostile data. They must not choose a target, arm a task, execute as code, or reach
operator files, credentials, local services, or unrelated network destinations. Enforce scope at the
network boundary as well as in the application, including on DNS resolution, redirects, and
subresources. A private or internal address is allowed only when the policy includes its own IP or
CIDR entry: a hostname entry does not authorize the address it resolves to. An empty or ambiguous
scope fails closed.

The declared foothold is the one deliberate exception to the network half, and it is bounded. A
command carried to an operator-declared foothold runs on a host whose egress is not ours to filter,
so its scope is enforced by the command gate alone. The carrier still runs inside the guarded
worker, the foothold's own address must be in scope and is pinned into the guard's accept list, the
declaration is sealed into the policy so a resume with a different foothold is refused, the surface
of a task decides whether it pivots so no model or corpus text can move execution, and every pivoted
action records its destination. One consequence runs the other way: this host's PATH and symlinks
describe this host, so a check that establishes a file's identity by resolving a path cannot speak
for a file on the foothold. Such a check compares lexically for a pivoted command and fails closed
on a spelling it cannot resolve. Do not widen this exception to a destination the operator did not
declare.

Bound requests, output, rate, duration, and total work, and provide a reliable operator stop
control. Credential use must be limited to the authorized target and must not leak through logs or
unrelated requests.

### Specific controls

- The SSRF guard in `index.py` for `blk add <url>` resolves and validates the host once, rejects
  private, loopback, link-local, reserved, multicast, and unspecified addresses, pins the validated
  address into the connection for the fetch, and revalidates at every redirect hop. The hostname is
  kept for TLS SNI and certificate verification. Do not replace this with a plain `requests.get`.
- `add_path` streams chunks and caps directory ingestion with `BLKCHAIN_ADD_MAX_FILES` and
  `BLKCHAIN_ADD_MAX_BYTES`.
- The embedding server binds loopback only and has no authentication. That is the single-user local
  model. Exposing it is a security decision to raise, not to implement quietly.
- Secrets come from the environment only. Never hardcode or log a token. The local `.env` is
  untracked.
- Pin dependencies. Python dependencies are `==` pinned in `pyproject.toml`. Model downloads are
  pinned to a revision in the README. The Qdrant image is pinned to a digest.
- The corpus is adversarial: it holds payloads, prompt-injection strings, and special tokens. Local
  chunks carry trusted-corpus provenance and web results carry unverified-external provenance.
  Prompt instructions treat embedded instructions in both as data. No retrieved text may set
  targets, authorize actions, arm tasks, or execute as code.
- Exploit-candidate detection is retrieval-grounded rather than capped by a hardcoded catalog
  (`cli/correlate.go` and `cli/recon_live.go`). A discovered service becomes a candidate either
  through the code-owned catalog fast path or, for an uncatalogued product, when the corpus-grounded
  selector returns a technique backed by a corpus citation. It fails closed: no citation, no
  candidate. The corpus and the model supply only the advisory technique label and the citation.
  Every candidate field is code-derived in `candidateTask`, and no gate, scope, tier, classifier, or
  denylist verdict reads the technique or citation, so a gate verdict is identical whether the
  grounding fields are set or not. Candidates start unarmed. Only code may arm them, from the
  operator-approved policy. This is the chain-wide standard: ground decisions in retrieval while
  keeping execution authority code-derived and corpus-independent.

## Runtime behavior

- MLX inference is serialized. `embed_server` runs all inference under a single lock and sub-batches
  forward passes. Do not add concurrent MLX calls.
- `embed_server` releases the Metal cache after large index-time batches. Do not clear the LLM cache
  per request; its prefix and key-value cache speed up repeated answer-loop prompts.
- The evaluation judge degrades rather than crashing when the LLM returns an error. A failed `blk`
  call in the harness is recorded against its case and reported, never fatal. Keep the timeout and
  the stdout cap.

## Indexing behavior

- A chunk id is deterministic: the first 128 bits of the chunk sha256, folded into a UUID.
- Each chunk carries a `content_hash` in its payload. Re-indexing skips unchanged chunks, re-embeds
  changed ones by overwriting the same id, and inserts new ones.
- Changing the stored `path` format changes chunk ids, so a path-scheme change needs a clean rebuild.
  Drop the collection first or you get duplicate points.

## Sessions and conversation memory

A session is one append-only JSONL transcript under the blk data directory. The listing the resume
and history pickers read is a row per session in the history database, so a picker does not open
every transcript.

The sessions directory is shared by every blk process, so these writes are cross-process. A turn
appends its transcript lines and then commits the memory rows together with the transcript length
they account for, in one transaction. That transaction is the turn's only commit point: bytes past
the committed watermark belong to a turn that never committed, and the reader reconciles them away
when the session is next opened. A listing row with no watermark recorded means the length is
unknown, and then the whole transcript counts as committed and is never truncated.

## Testing

Run the Python suite before claiming anything works. It uses the standard library `unittest`
runner; pytest is not a project dependency. Sync the virtual environment first, or the modules that
import the engine fail with `ModuleNotFoundError`.

```sh
.venv/bin/python -m unittest discover tests
```

Go tests are `cd cli && go test ./...`.

The default suites are hermetic. Opt-in browser, runner, MCP, and local-model integration tests
require provisioned services or containers and are gated behind environment variables. Add a
regression test with every fix, in the file that matches its area.

## Evaluation

```sh
(cd cli && go build -o blk .)
export BLK_BIN="$PWD/cli/blk"
.venv/bin/python -m blkchain.eval.run --no-judge
```

The harness runs `blk search --json` per case, and `blk ask --json` for the judge, so Qdrant and
`embed_server` must be running. The dataset holds labeled regression cases, and the run reports hit
rates and reciprocal rank.

## Coding standards

- State assumptions. If two readings of a task exist, surface both.
- Simplicity first: the minimum code that solves the problem. No speculative abstractions, no
  configuration for fixed values, no error handling for impossible states.
- Surgical changes. Touch only what the task needs and match the surrounding style. Remove the
  imports and names your own change orphaned, and nothing else.
- Turn a task into a verifiable check and prove it by running the command.
- Prose and comments read as if a human wrote them: plain ASCII punctuation, direct and concise.
- Comments are minimal and factual. A comment states what the code does, or why a non-obvious
  choice is necessary, in plain present tense. If the code already says it, delete the comment.
  Objective identifiers that describe a real contract stay: protocol version strings, spec ids such
  as WSTG and CWE, CVE ids, RFC numbers, and algorithm names.
- Validate untrusted input at the boundary, bound every resource, keep secrets in the environment,
  and pin dependencies.

## Commit conventions

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, plus a scope such as
`config:` or `eval:`). Stage files explicitly by path.

## Gotchas

- Non-finite floats break strict JSON clients. Keep responses strict JSON.
- A model swap that changes the embedding dimension needs a new collection. The default embedder is
  1024-dimensional and drop-in; a 768-dimensional model is not.
- The 4-bit DWQ embedder emits bfloat16, so the float32 cast in `embed_server` is required.
- After a path-scheme change, rebuild the index from a clean collection or you get duplicate points.
- Building the full index re-embeds many chunks and takes real time. Run it in the background and
  watch the collection point count.
