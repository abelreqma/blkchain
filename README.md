# blkChain

Local, offline, agentic **hybrid RAG over offensive-security / bug-bounty knowledge**, built for
Apple Silicon beside a locally served LLM. Ask or search for security information and get a
synthesized, **cited** answer. Machine retrieval through `kb_search` or `blk search --json` returns
ranked source chunks. The knowledge base and inference can run locally
and privately. The separate `blk engage` harness can connect to authorized target systems included in
the engagement scope.

> Tested on an Apple Silicon Mac (arm64, 24 GB unified memory, macOS 27).

## What it does
- **`kb_search`**: hybrid retrieval (dense + BM25 sparse, fused by Qdrant RRF) then a cross-encoder
  rerank, returning the top few chunks with source pointers. Sub-second. Your fast recall tool.
- **`kb_answer`**: a bounded agentic loop that retrieves, grades sufficiency, optionally rewrites or
  web-searches (Tavily), then synthesizes a grounded, source-cited answer.
- **`blk engage`**: a Go harness for autonomous penetration testing within an operator-approved
  engagement scope.

Both are reachable from the `blk` terminal client and from the Hermes agent through the MCP server
`blk mcp`.

**Architecture.** The Go `blk` binary is the single implementation for search, ask, health, and MCP.
It owns retrieval orchestration and the answer loop. Python serves the MLX models (`embed_server`)
and builds the index offline (`blk add` and the indexing scripts). There is no Python query path,
HTTP API, or Python MCP server.

## Engagement security model

The operator's authorization is the premise for target testing. The engagement's rules of engagement
(RoE) define allowed targets and actions. When the RoE authorizes active testing, `blk engage` is
designed to run those actions autonomously within the RoE, rate, time, and resource limits. Per-action
confirmation is not a universal security requirement. Capabilities may still require confirmation in
the current implementation; check the capability's actual gate behavior before relying on unattended
execution.

The runner and operator environment are protected boundaries. Target-controlled pages, responses,
files, and tool output are hostile input. Target-facing workers must not gain access to unrelated host
files, credentials, local services, or network destinations. Scope enforcement must cover DNS
resolution, redirects, and browser subresources. Private or internal targets are allowed when the RoE
explicitly includes them; target network actions with missing or ambiguous scope fail closed. Target
content cannot choose the target, authorize an action, or arm a task.

## Services
Local processes, started on demand (nothing autostarts). Retrieval needs only Qdrant and
`embed_server`. The LLM is an external process you run separately.

| Service | Port | What |
|---|---|---|
| Qdrant | 6333 (HTTP), 6334 (gRPC) | vector store (hardened image), hybrid dense+sparse collection |
| embed_server | 8100 | dense embedder (Qwen3-Embedding-0.6B-4bit-DWQ) + reranker (default gte-reranker-modernbert-base; Qwen3-Reranker-0.6B or jina-v3 optional), MLX, resident |
| LLM | 8000 | any OpenAI-compatible local model, run separately (e.g. via the oMLX app or CLI) |

## Quickstart
Use the pinned Apple Silicon setup below. It locks the Python interpreter, Python dependency graph,
Go modules, Qdrant image, and model revisions. The corpus and synthesis LLM remain user supplied.
```sh
# 1. Install the pinned tools: uv 0.12.16, Go 1.27.1, and Docker Engine 29.8.1.
#    Install Python 3.12.14 through uv, then install the locked Python graph.
uv python install 3.12.14
uv venv .venv --python 3.12.14
uv sync --locked

# 2. Verify/install Go dependencies from the checked-in go.mod and go.sum.
cd cli && go mod download && cd ..

# 3. Point blkChain at your models and corpus. Keep API keys in the ignored .env.
cp .env.example .env    # then edit (see Configuration)

# 4. Start Qdrant (pinned by digest; loopback only; storage under ./data)
docker run -d --name blkchain-qdrant --restart unless-stopped \
  -p 127.0.0.1:6333:6333 -p 127.0.0.1:6334:6334 \
  -v "$PWD/data/qdrant_storage:/qdrant/storage" \
  dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba

# 5. Start the embed + rerank server (:8100)
.venv/bin/python -m blkchain.embed_server &

# 6. Build or reconcile the index after changing configured corpus sources
.venv/bin/python -c "from blkchain import index; print(index.build_index(snapshot_version='v1'))"

# 7. Build the Go client and query it
(cd cli && go build -o blk .)
cli/blk search --top-k 5 stacked queries sqli
cli/blk ask what is reflected XSS
```
The synthesis LLM (:8000) is brought up separately (e.g. via the oMLX app or its CLI). The `blk`
terminal client is a first-class way to drive the stack; see [Terminal client](#terminal-client-blk).

The lock files are part of the setup contract: `uv.lock` records exact Python transitive versions
and package hashes, and `cli/go.mod` plus `cli/go.sum` pin and verify Go modules. Use `uv sync --locked`;
do not install with an unlocked `uv pip install -e .`. The setup requires macOS on Apple
Silicon for MLX. The Python tests and Go tests run without live Qdrant, embedding models, or an LLM.

## Layout
```
blkchain/                Python 3.12: MLX model server, offline indexing, evaluation harness
  config.py              central config + corpus manifest (all paths/params via env; secrets via env only)
  contract/rag.json      shared RAG parameter contract, read by the Go CLI (Python keeps its own copies of what it needs)
  schema.py              the Chunk + Qdrant payload contract
  httputil.py            shared HTTP helpers (strict-JSON writer, bounded body reader, sanitized errors)
  embed_server.py        resident embed + rerank HTTP server (:8100), MLX
  reranker.py            reranker dispatcher (selects the backend via BLKCHAIN_RERANKER_KIND)
  reranker_qwen3.py      Qwen3-Reranker-0.6B causal-LM reranker (Apache-2.0, instruction-aware)
  reranker_modernbert.py gte-reranker-modernbert-base cross-encoder (default, Apache-2.0, fastest)
  reranker_jina.py       jina-reranker-v3 listwise backend (CC-BY-NC-4.0, non-commercial)
  rerank_scores.py       score sanitization (ranks empty or non-finite scores last)
  ingest.py              structure-aware chunking of the corpus
  index.py               embed + BM25 sparse -> Qdrant, resumable; add_path for `blk add`; SSRF guard
  add.py                 `blk add` backend surface (file, directory, or URL into the live index)
  eval/                  evaluation harness + labeled dataset (retrieval gate, optional LLM judge); drives the Go `blk` binary
cli/                     Go `blk` client: retrieval, answer loop, health, MCP server, stack control (see Terminal client)
scripts/                 helper scripts (rendering utilities)
tests/                   Python unit tests (hermetic: no live services, models, or network)
pyproject.toml           pinned direct dependencies and Python runtime
uv.lock                  full transitive Python lock with artifact hashes
```

## Configuration
The project is self-contained: `blkchain/config.py` defaults every path to a project-relative
location, and machine-specific locations come from the environment or a gitignored `.env` at the
project root (`cp .env.example .env`). Nothing assumes a parent or sibling directory. Precedence is
**environment > `.env` > built-in default**. **Secrets are read from the environment only, never
hardcoded.** See [`.env.example`](.env.example) for every variable; the essentials:

- **Data:** `BLKCHAIN_MODELS_DIR` (dense embedder + reranker; default `<project>/models`),
  `BLKCHAIN_SOURCES_DIR` (corpus root; default `<project>/corpus`), `BLKCHAIN_WSTG_PDF`.
- **Optional corpora** (omit to skip): `BLKCHAIN_SECLISTS_DIR`, `BLKCHAIN_SKILLS_DIR`.
- **Services:** `QDRANT_URL`, `BLKCHAIN_EMBED_HOST/PORT`, `BLKCHAIN_COLLECTION`.
- **LLM:** `OMLX_BASE_URL`, `OMLX_MODEL`, `OMLX_API_KEY` (read by `blk` and the eval judge).
- **Engagement convergence:** `BLKCHAIN_ENGAGE_MAX_ROUNDS` (default 32, clamped to 1..256),
  `BLKCHAIN_ENGAGE_MAX_CALLS` (128, 1..2048), and `BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS` (3, 1..32).
  Unset or invalid integers use defaults. These settings apply to orchestration in the CLI,
  REPL/TUI, and MCP. New evidence, task changes or completions, and recon coverage reset the idle
  counter. Repeated identical updates, duplicate evidence, and dispatch bookkeeping do not.
  A capped or stalled run makes one final report call with tools disabled; if it fails, the run
  returns a report from stored evidence. This extra call falls outside the orchestration caps and
  has a 2048-token output cap. Saved CLI reports mark capped or stalled runs as paused.
  Executor loop limits remain separate.
  `BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL` selects a separate model ID for orchestration and final
  synthesis. Executors keep the `--model` selection, REPL/TUI model selection, or MCP model
  argument. An unset override uses that same model for both roles. The model must be available
  on the configured LLM server.
  The whole engagement also has an action budget (default 512 model and tool calls) and a
  wall-clock deadline (default 1800 seconds). Set `engage_max_actions` and
  `engage_wall_seconds` in the project's `.blkchain/config.yaml`; the corresponding
  `BLKCHAIN_ENGAGE_MAX_ACTIONS` and `BLKCHAIN_ENGAGE_WALL_SECONDS` environment variables
  take precedence. The start time and action count are stored in the engagement database, so
  resuming the same workspace does not reset either limit. Budget exhaustion stops the run and
  returns a report from the store.
- **Answer sampling** (read by `blk`): `BLKCHAIN_SYNTH_TEMPERATURE` (default 0.7),
  `BLKCHAIN_SYNTH_TOP_P` (0.95), `BLKCHAIN_SYNTH_TOP_K` (64), `BLKCHAIN_SYNTH_PRESENCE_PENALTY` (0.5).
  The answer call sends `temperature`, `top_p`, `top_k`, and `presence_penalty`. LangChainGo drops
  `top_p` and `top_k`, so the `blk` HTTP transport adds them as top-level fields. The grade call
  sends only `temperature` 0, so grading stays deterministic. An unparsable value is ignored, and an
  out-of-range one falls back to the default, with a one-line note on stderr.
- **Web provider:** `BLKCHAIN_WEB_PROVIDER=auto|duckduckgo|tavily` overrides the saved selection.
- **Secrets:** `TAVILY_API_KEY` or `TAVILY_SETUP_TOKEN` configures Tavily. `NVD_API_KEY` increases
  the NVD request allowance for direct CVE lookups. Credentials alone do not
  authorize web access.

The corpus is defined by `config.CORPUS_SOURCES` (source dirs + handling kind), all derived from the
paths above; no module hardcodes a document path, and sources whose directory is absent are skipped.
Full `build_index()` reconciles removed or changed files only for configured source paths that are
present, and only after ingestion completes successfully. Missing source roots are preserved because
they may be offline or unmounted. `blk add` entries are marked as manual content and survive corpus
reconciliation.
When a configured root was intentionally removed, pass `prune_missing_sources=True` to `build_index()`
to delete its old points. Use this only when the corpus is not temporarily offline.

## Usage
```sh
blk search --top-k 5 stacked queries sqli
blk search --json --source hacktricks LFI to RCE
blk ask what is reflected XSS
blk sources
blk health
```
**Hermes:** the MCP server is `blk mcp`. Register it under `mcp_servers.blkchain` in your Hermes
config with `blk` as the command and `mcp` as its argument; the agent then calls `kb_search` /
`kb_answer` as tools. An older entry that runs `python -m blkchain.mcp_server` must be changed to
run `blk mcp`, because that Python module no longer exists. `blk mcp` also exposes `route_skill`, a
read-only skill playbook lookup by domain. No Hermes config change is needed; the tool appears on the
next connect.

## Terminal client (`blk`)
`blk` is the Go terminal client for the stack and the single implementation of search, ask, health,
and MCP. It performs retrieval natively (reading Qdrant over gRPC on :6334 and calling `embed_server`
on :8100 directly) and runs its own bounded, cited answer loop. It shares the same Qdrant
collection, the same `embed_server`, and the RAG parameter contract in `blkchain/contract/rag.json`
(the Go build carries a compiled-in fallback that a test keeps byte-for-byte in sync with that file).

Build and install:
```sh
cd cli && go build -o blk . && ./blk install   # install onto PATH; run once, from the project
```
Common commands (run `blk help` for the full list):

| Command | What |
|---|---|
| `blk ask <query>` | synthesized, cited answer (streamed); `--agent` routes through the Hermes agent; `--json` adds `model` and marks web citations `untrusted` |
| `blk search <query>` | synthesized, cited answer; `--json` returns raw ranked chunks; supports `--top-k`, `--source`, `--type`, `--filter`, `--json` |
| `blk add <path>` | index your own file, directory, or URL into the live KB |
| `blk sources` | list each indexed source with its chunk count, largest first, and the total; `--json` prints `{collection, total_chunks, sources: [{source, chunks}]}` |
| `blk web <verb> [targets]` | collect, analyze, inspect, import, archive, export, or replay JavaScript/API evidence; also `blk engage web` and `/web`; [usage and limits](cli/web-analysis.md) |
| `blk repl` | interactive REPL (bare `blk` too) for repeated search/ask |
| `blk up / down / status` | start, stop, or check the local services (Qdrant and `embed_server`) |
| `blk health` | check Qdrant, `embed_server`, and the LLM; `--json` prints `{ok, qdrant, embed_server, llm}`; exits 0 when all are up, 1 when any is down |

| `blk doctor` | diagnose the whole stack, including Hermes MCP wiring |
| `blk models` | readiness and live performance of the chat, embed, and rerank models |
| `blk mcp` | native Go MCP stdio server exposing `kb_search` / `kb_answer` / `route_skill` |
| `blk open <path>` | open a source file in `$PAGER` or `$EDITOR`; opens at the cited section when your pager is less (`--section`, or `/open N` in the TUI) |
| `blk logs [service]` | tail a service log (`embed_server`) |
JSON answers include `llm_calls` with the stage, requested model, elapsed milliseconds,
cache status, and reported token usage. Missing usage remains unavailable. The record list
is bounded; `llm_calls_partial` indicates omitted calls. `/cost` shows these details in both
terminal interfaces. Prompts, retrieved content, credentials, and error messages are excluded.

Exact deterministic routing and RAG grading responses use a bounded, in-process cache.
Entries expire after five minutes. Model, endpoint, credential, response-format, thinking,
sampling, and evidence changes separate cached results. Generation, reconnaissance
decisions, command execution, and authorization remain uncached.

Structured graders request JSON mode. `blk analyze` uses a dedicated strict JSON-schema
client while retaining local field validation and bounded retries. The model endpoint must
support the requested response format. Prose and tool-calling clients retain their formats.


`blk help <command>` (or `blk <command> --help`) shows one command's flags and examples, and
`blk help env` lists every environment variable blk reads. A usage
error (unknown command, missing argument, bad flag) exits with code 2; any other failure exits 1.

**Typing.** The draft wraps to the terminal width and grows to six rows. Up/down move through
wrapped drafts; they recall command history on a single unwrapped line. Enter submits, Ctrl-J
inserts a newline, Ctrl-V pastes, and Ctrl-G opens `$VISUAL` or `$EDITOR`. Pasted text and editor
results stay editable until Enter. Left/right, Backspace, Delete, and Ctrl-T preserve joined
emoji and accented characters. Press `?` with an empty draft for the editing keys. Drafts have
a 64 KiB UTF-8 limit and a 10,000-line limit; truncated input shows a notice.

Unicode output renders emoji shortcodes such as `:thumbsup:` outside code blocks. The rich
status ribbon uses standard Nerd Font icons. Terminals without that font use Unicode or ASCII
fallbacks with `BLKCHAIN_POWERLINE=0` or `NO_COLOR=1`, respectively.

The plain REPL supports `/history` to list saved sessions and `/history <number>` to reopen one,
`/editor` to prepare a multiline draft, `/init` to reload project context, `/copy`, and `/clear`.
`/engage [flags] <goal>` uses the same gated entry as `blk engage`. Unknown slash commands show
an error; commands that require a picker identify the interactive TUI requirement.
CLI and interactive engagements save `report.md` and `report.json` in their workspace. The final
assessment is included in both files, and the Markdown report shows evidence from unfinished
tasks. A capped or stalled TUI run displays a paused marker and the report paths.
Each new engagement also saves `checkpoint.json` and a private copy of its `ROE.md` or scope file.
`blk engage resume --workspace <dir>` and `/engage resume <dir>` reopen its goal, open tasks,
evidence, and vantage under that saved scope. Omit the directory to select the latest engagement.
The project's `.blkchain/config.yaml` remains the source for general options on resume. Ctrl+C
or SIGTERM cancels an active CLI run and writes an interrupted report.
The workspace `audit.jsonl` records typed model decisions, tool calls, gate verdicts, and
command execution attempts. Eight gate denials within one minute halt the engagement and leave a paused
report with the reason and report paths. An audit write failure stops the run.
Target-facing IPv4 commands with a verifiable, in-scope remote address run in a pinned Docker
runner. Its network namespace admits only the command's resolved destination IPs, and its tool
process drops all capabilities after the firewall is installed. The runner receives a read-only
copy of task scratch inputs and a 64 MiB temporary work filesystem; files it creates are not
persisted after the command. Capture stdout or stderr for evidence. Loopback, link-local,
operator-host interfaces, Docker host gateways, broadcast, and IPv6 destinations fail closed.
Commands with no extracted network target run under the macOS file and network sandbox; local
host execution on other operating systems fails closed. The pinned runner image must already
exist locally and includes a limited tool set; an unavailable tool reports a command error.

An engagement `ROE.md` can authorize specific unattended action classes with `## Autonomous Actions`.
Each entry is `phase/surface host`, for example `exploit/network 192.0.2.1` or
`recon/local local`. The host must be an exact in-scope host; `local` requires an `In Scope`
entry of `local`. A rule covers that action class on the host, not other hosts. Exploit and
post-ex tasks auto-arm only when a stored basis task has evidence. Every proposed command
still passes the gate, scope, denylists, and rate limit. The project's
`.blkchain/config.yaml` sets reusable binary bounds: `allowed_binaries` for external Auto
and `local_unattended_binaries` for LOCAL. LOCAL runs without a confirmer only when both a
matching RoE rule and a listed local binary permit the command. Commands outside that pair
still need a confirmer.

**Models panel.** In the interactive session, `/models` lists every model: the chat models the LLM
server serves, the embedder, the reranker, and web search. Keys: up/down move, space turns the
selected row on or off, `l` loads and `u` unloads a chat model (the active model needs a second
`u`), enter uses a chat model for the rest of the session, `r` refreshes, esc closes. The same
actions work as `/models on|off|load|unload <name>` in both REPLs, with `<name>` a chat model id (or
a unique prefix), `reranker`, or `web`.

- A chat model switched off is hidden from the `/model` picker; the active model cannot be hidden.
- The reranker switch turns the cross-encoder rerank on or off; the web switch grants or revokes
  permission for automatic web search in answers. Both apply to the CLI and interactive sessions;
  `kb_answer` over MCP also respects the web permission.
- Load and unload ask the LLM server's admin API to load or unload a chat model.
- The switches are saved in `models.json` in `$XDG_CONFIG_HOME/blkchain` (default
  `~/.config/blkchain`).

**Web access.** A fresh configuration keeps automatic web search off. `blk web on` or `/web on`
saves permission for answers to search the internet. `blk web off` or `/web off` revokes it. Existing
saved web settings remain in effect. `blk web` and `/web` report permission and the selected provider.

```sh
blk web provider auto
blk web on
blk web search --top-k 5 "OWASP XSS prevention"
blk web search --json "current security guidance"
blk ask --web "current security guidance"
blk web off
```

Use `/web provider auto|duckduckgo|tavily`, `/web search <query>`, and `/ask --web <question>` in the
plain REPL or TUI. `/search`, bare requests, and text search commands
retrieve evidence and synthesize an answer. `/web search` uses web evidence and also synthesizes an
answer. Internet requests require the saved web permission, including explicit web searches and
`ask --web`; these commands do not change that permission. Text searches need the LLM, and local
search also needs the retrieval services. `blk search --json` retains raw local retrieval output for
scripts and evaluation, and `blk web search --json` returns raw web evidence when web is enabled.
The TUI retains the evidence for `/generate` and citations for `/open`.

`auto` uses Tavily when a key is configured, otherwise DuckDuckGo. It falls back to DuckDuckGo on an
empty or failed Tavily search. Explicit `tavily` or `duckduckgo` selection uses only that provider.
DuckDuckGo uses HTML search and can require a CAPTCHA; blk reports that failure. Tavily reads
`TAVILY_API_KEY` first, then `TAVILY_SETUP_TOKEN`. Search requests reject redirects, time out after
20 seconds per provider, read at most 2 MiB, and return at most 20 results. Web content remains
untrusted evidence, and answer citations identify web sources as untrusted. These commands provide
search and cited answers; target browser automation belongs to the engagement browser tooling.

With web access enabled, a question containing an exact CVE ID fetches its NVD record directly and
searches for matching public PoC leads on GitHub, Exploit-DB, and Sploitus. The CVE researcher
uses the NVD description, score, affected-product hints, and references to explain prerequisites and
give a scoped payload or validation playbook. Search results are leads, not verified exploits. The
NVD lookup reads `NVD_API_KEY` from the environment when present and works without a key at the
public rate limit. NVD and web citations are marked untrusted. `blk ask`, bare interactive questions,
the plain REPL, the TUI, and `kb_answer` use the same answer loop.

**Status line.** The interactive session's status line shows the mode (`rag` or `agent`), the model
a turn uses (the `/model` pick, else `OMLX_MODEL`, else the first model the LLM server lists), the
reasoning level, the embedder and reranker state in rag mode, the service health (or the Hermes
gateway state in agent mode), the session title, and any queued questions.

`BLKCHAIN_ROOT` locates the project when `blk` runs from outside the repo; `NO_COLOR` disables colored output; `BLK_THEME=light|dark|auto` forces the palette when the terminal
background cannot be detected (tmux, SSH), and `auto` falls back to `COLORFGBG`. Go tests run with
`cd cli && go test ./...`.

## Corpus
blkChain indexes a corpus **you supply**; no documents are distributed with this repository. Point
`BLKCHAIN_SOURCES_DIR` at a directory of your chosen sources and build the index. It is designed for
public offensive-security references such as:

- HackTricks: https://github.com/HackTricks-wiki/hacktricks
- HackTricks Cloud: https://github.com/HackTricks-wiki/hacktricks-cloud
- PayloadsAllTheThings: https://github.com/swisskyrepo/payloadsallthethings
- AI-penetration-testing: https://github.com/Mr-Infect/AI-penetration-testing
- OWASP Web Security Testing Guide (WSTG v4.2): https://owasp.org/www-project-web-security-testing-guide/
- SecLists: https://github.com/danielmiessler/SecLists (indexed **catalog-only**: one manifest card per wordlist, never line-by-line)
- Arsenal: https://github.com/inflictx/Arsenal (a curated web-security technique database; two subtrees are indexed: `seed/curated-en/*.json`, 60+ vulnerability classes read by the `json` ingest kind, and `seed/checklists-en/*.md`, operational and research methodology)
- violin: https://github.com/Strategic-Automation/violin (its `skills/` methodology subtree)
- A curated, deduplicated snapshot of your own offensive-* Claude skills, staged into the corpus (about 79 skills covering the wider offensive surface: AD, wifi/RF, mobile, exploit development, and more)
- CAI: https://github.com/aliasrobotics/CAI (two cherry-picked docs only, `research.md` and the prompt-injection doc, not the whole framework)

Markdown, plain-text/code, JSON, and PDF sources are chunked structurally; wordlist-scale trees are indexed
catalog-only. CVE/PoC lookups use the live Tavily web route rather than a local clone (e.g.
https://github.com/nomi-sec/PoC-in-GitHub). Stored document paths are relative to the corpus root, so
the index is portable across machines.

## Models & licenses
blkChain references models by name and you download them at setup; **no model weights are bundled or
redistributed in this repository** (the models directory is external and gitignored). Each model
keeps its own license:

| Role | Model | License |
|---|---|---|
| Dense embedder | [`mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ`](https://huggingface.co/mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ) (1024-dim) | Apache-2.0 |
| Reranker (default) | [`afanjul/gte-reranker-modernbert-base-mlx`](https://huggingface.co/afanjul/gte-reranker-modernbert-base-mlx) | Apache-2.0 |
| Reranker (alternatives) | [`mlx-community/Qwen3-Reranker-0.6B-4bit`](https://huggingface.co/mlx-community/Qwen3-Reranker-0.6B-4bit) (instruction-aware) / `jina-reranker-v3` | Apache-2.0 / CC-BY-NC-4.0 |
| Synthesis LLM | any OpenAI-compatible local model, served separately | its own license; referenced, not bundled |

**The default stack is fully commercial-clean (Apache-2.0).** The default reranker
(`gte-reranker-modernbert-base`) and the `qwen3` alternative are both Apache-2.0; only the optional
`jina-reranker-v3` backend (`BLKCHAIN_RERANKER_KIND=jina`) is CC-BY-NC-4.0 and **not**
commercial-clean. Fetch the models into `BLKCHAIN_MODELS_DIR` (default `<project>/models`):
```sh
hf download mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ --revision 6c3ae70858513f1a78e9cdca3cae330d9075cd2a --local-dir "$MODELS/Qwen3-Embedding-0.6B-4bit-DWQ"
hf download afanjul/gte-reranker-modernbert-base-mlx --revision 0b1cfb9141dd1452e07a328a0dec430f2324da12 --local-dir "$MODELS/gte-reranker-modernbert-base-mlx"   # default reranker
# instruction-aware alternative (then set BLKCHAIN_RERANKER_KIND=qwen3):
# hf download mlx-community/Qwen3-Reranker-0.6B-4bit --revision 5f324548f1d20c2b5a450f126fc6ef2fb1126524 --local-dir "$MODELS/Qwen3-Reranker-0.6B-4bit"
```
The **corpus** is user-supplied and not distributed here; see [Corpus](#corpus) and
[Configuration](#configuration). blkChain's own code is licensed under Apache-2.0 (see
[LICENSE](LICENSE) and [NOTICE](NOTICE)); that is independent of the model and corpus licenses.

## Evaluation
The harness drives the Go binary: it runs `blk search --json` per case and `blk ask --json` for the
judge. It finds the binary through `BLK_BIN`, else `blk` on `PATH`; build it with
`cd cli && go build -o blk .`. Each call is bounded by a timeout and a 16 MiB stdout cap. A failed
call (non-zero exit, timeout, invalid JSON) counts as a miss for that case and is listed in the
report; it does not stop the run.
```sh
export BLK_BIN="$PWD/cli/blk"    # or put blk on PATH
# retrieval gate (deterministic; needs qdrant + embed_server). Primary quality metric.
.venv/bin/python -m blkchain.eval.run --no-judge
# with a local LLM judge (faithfulness + answer relevancy; needs the LLM running)
.venv/bin/python -m blkchain.eval.run --judge-limit 3
```
`blkchain/eval/dataset.jsonl` holds hand-labeled cases tagged `difficulty` (`core` on-topic, `hard`
paraphrase/typo/multi-hop); the run reports hit_rate@5/@10 and MRR overall and split by difficulty.
Labeled expected source and CWE requirements must match the same result as the expected text. This
keeps unrelated CWE tags or source matches from making a case pass. The dataset is a compact
regression gate; it does not measure exploit validity, safety policy, or broad adversarial behavior.
Flags: `--top-k`, `--limit`, `--no-judge`, `--judge-limit`, `--collection`.

**Embedder A/B:** build a second collection with an alternate embedder, then compare with
`--collection`:
```sh
BLKCHAIN_EMBEDDER_PATH=... .venv/bin/python -m blkchain.embed_server &
BLKCHAIN_COLLECTION=blkchain_alt .venv/bin/python -c "from blkchain import index; index.build_index(snapshot_version='ab')"
.venv/bin/python -m blkchain.eval.run --no-judge --collection blkchain_alt
```

## Notes
- **Nothing autostarts.** Start the services when you need them and stop them when you are done.
- **Re-indexing.** The index is resumable (content-hash based): re-running skips unchanged chunks and
  re-embeds changed ones. A completed full corpus build also deletes stale manifest-owned points;
  interrupted/failed ingestion never runs this deletion step. Changing the stored path scheme changes
  chunk ids, so rebuild cleanly (drop the collection or delete `data/qdrant_storage`, then reindex).
- **Retrieved content.** Corpus and web text are serialized as JSON evidence records and labeled
  untrusted before they enter grading or synthesis prompts. This reduces delimiter spoofing and
  prompt-injection risk; it does not make an LLM a security boundary. Retrieved text is never run as
  a command.
- **Saved data.** Session transcripts, session indexes, REPL history, stack logs, and saved install
  paths use private directories and owner-only file permissions on Unix-like systems.
