# blkChain

blkChain is a security research and authorized assessment framework. It combines a searchable security knowledge base, model-assisted task orchestration, isolated command execution, browser and API analysis, and a persistent engagement evidence store. Its assessment core, `blk engage`, coordinates bounded tasks under operator-defined rules of engagement. The `blk` terminal client provides one-shot commands, an interactive session, and an MCP server.

Use it to research techniques, understand an application's exposed sources and traffic, run scoped assessment tasks, and inspect the evidence behind a conclusion.

Start with the [complete setup guide](#complete-setup-guide). For an existing installation, see [answer modes](#research-and-answer-modes), [web analysis](#web-application-analysis), and the [engagement store](#engagement-store-and-findings).

## Capabilities

| Area | Current implementation |
| --- | --- |
| Security research | Local dense and BM25 retrieval, RRF fusion, cross-encoder reranking, source filters, bounded answers, specialist prompts, and optional public web research. |
| Assessment orchestration | Task dependencies, specialized executors, Auto and Safe modes, operator-defined rules of engagement, isolated runners, action capture, stop, and resume. |
| Web application analysis | Source and traffic collection, JavaScript and source-map analysis, API operation reconstruction, role sessions, workers, cached responses, WebSockets, and scoped replay. |
| Engagement evidence | SQLite tasks, exact quotes, action records, coverage records, finding review states, provenance relationships, and local answers citing selected records. |
| Operator interfaces | Keyboard-driven terminal UI, plain REPL, history, draft editing, context attachments, queued questions, source inspection, model controls, and service diagnostics. |
| Integration | Native MCP tools and schema-validated JSON generation through the same Go implementation. |

## Research and answer modes

The research index combines dense embeddings and BM25 sparse vectors in Qdrant. Go queries both vectors, fuses their results with Qdrant RRF, and optionally reranks the candidate pool with a local cross-encoder. Source, type, and payload filters constrain retrieval.

The native answer loop grades source sufficiency, can rewrite the query, and synthesizes an answer from bounded source passages. It supports conversation context, specialist prompts, streaming, per-call usage metrics, and an explicit no-results response. Exact-CVE research can add NVD details and public research when web permission is enabled.

Default answers use Hermes. Select native routing explicitly when you want blkChain's local answer loop or structured answer output:

| Entry point | Behavior |
| --- | --- |
| `blk ask QUESTION` | Runs a Hermes turn using the external Hermes configuration. |
| `blk ask --agent auto QUESTION` | Uses native answer routing and selects a research specialist dynamically. |
| `blk ask --agent web QUESTION` | Uses the native web specialist prompt. The specialist name does not itself enable internet access. |
| `blk ask --agent auto --rag QUESTION` | Forces the native knowledge-base answer path. |
| `blk search QUERY` | Synthesizes a native answer grounded in the search results. |
| `blk search --json QUERY` | Returns ranked chunks without answer synthesis. |
| `blk ask --agent auto --json QUESTION` | Returns structured native answer output, citations, results, and available call metrics. |

`--json` and `--sources` on `ask` require an explicit native `--agent` selection. In the interactive session, `/agent auto` or `/agent NAME` selects native answers; `/mode` switches between native answers and Hermes. Research specialists change answer guidance. Engagement executors are selected separately from task kind and surface.

Native web research is off by default. `blk web on` permits it and `blk web off` revokes it. Providers include DuckDuckGo and Tavily; Tavily reads `TAVILY_API_KEY` or `TAVILY_SETUP_TOKEN`. Use `blk web provider duckduckgo`, `blk web provider tavily`, or `blk web provider auto` to choose a provider. Permission and provider settings persist locally. A research query can leave the machine when web research is enabled.

Hermes has its own provider, tools, permissions, and conversation state. Native web settings and engagement Safe/Auto settings do not control Hermes's own tool execution.

## Engagement harness

`blk engage` plans and executes tasks under an operator-owned rules of engagement (RoE) policy. The model proposes tasks and structured tool arguments. Code applies scope checks, action permissions, command denials, resource limits, and execution routing. Retrieved techniques and citations supply advisory context; they do not grant authority.

Auto is the default and runs actions permitted by the RoE without per-action prompts. Safe requires an interactive approval channel. The RoE names in-scope and excluded targets, permitted action classes, command denials, resource caps, and runner settings. A goal such as "recon only" does not replace those policy permissions. Use explicit action and command restrictions for the intended assessment.

If no policy is found, `blk engage` writes a commented `ROE.md` template in the current directory and stops. Configure its targets and allowed actions before starting a run. Existing policies are not overwritten. `--roe PATH` selects a policy kept elsewhere.

The harness stores tasks, dependencies, provenance, exact evidence quotes, action transcripts, policy decisions, and coverage records in a workspace. Command workers have destination filtering, a read-only root filesystem, bounded writable scratch space, a restricted environment, and CPU, memory, process, output, and time limits. Commands needing raw sockets use a separate worker with that capability. Resume retains the sealed policy, original deadline, and recorded usage. `blk engage --resume WORKSPACE` resumes a run; `blk engage stop --workspace PATH` stops one.

### Executor coverage

| Surface | Current behavior |
| --- | --- |
| Network | Tiered asset and service discovery, fingerprinting, finding parsers, and evidence-linked candidate tasks. |
| Web | HTTP and browser collection, source analysis, role-aware observations, and replay through the scoped broker. |
| Local | Identity, privilege, permission, capability, scheduled-task, and service enumeration; focused executable inspection. Without a declared foothold, local work describes the isolated runner. |
| Active Directory | Domain discovery and anonymous, authenticated, and finding-driven task paths using the shared gated tools. Requires an appropriate access vantage. |
| Cloud | AWS, Azure, and GCP reconnaissance ladders over shared gated tools. |
| Container | Container and Kubernetes task paths through specialized reconnaissance and shared execution. |
| AI application | Endpoint and model discovery, capability checks, and evidence-derived follow-on candidates. |

### Foothold execution

An optional RoE `Foothold` declaration names a host the operator already controls and the surfaces that execute there. Supported carriers include SSH and an operator-supplied command prefix. Credentials can be supplied through named environment references. The declaration, covered surfaces, and target scope are sealed into the policy.

Commands on those surfaces execute on the declared foothold. The runner filters its connection to the foothold, the command gate applies scope checks, and actions record their execution destination.

## Web application analysis

`blk engage web` provides `collect`, `analyze`, `inspect`, `import`, `archive`, `export`, and `replay`. Collection, archive acquisition, and replay make network requests under the RoE. HAR import also requires policy context. Analysis, inspection, and export work from saved workspace data.

The collector processes HTML references, scripts, frames, module dependencies, manifests, source maps, and selected framework chunk patterns. An isolated browser adds rendered pages, runtime and generated scripts, worker sources, cached responses, observed requests, and WebSocket traffic. Role sessions use supplied credentials through environment references bound to their configured origin.

Analysis uses JavaScript and TypeScript syntax trees, lexical binding checks, common HTTP-client patterns, and source locations to reconstruct operations and parameters. It identifies credential candidates and library advisory matches and records them as leads for review.

Saved HTTP examples retain request-body representations for replay. Structured operations can also be replayed with supplied values. WebSocket exchange validation compares an operator-supplied bounded transcript with expected opcodes and bytes. Discovery, observed responses, cached responses, handshakes, messages, advisory matches, and matched exchanges have distinct evidence grades.

Collection records supplied roles and visited states under configured asset, page-state, request, byte, and time budgets.

Browser collection requires a separately provisioned pinned Playwright driver and container. `PLAYWRIGHT_DRIVER_PATH` and `BLKCHAIN_PLAYWRIGHT_CONTAINER` identify them; headed assistance also requires `BLKCHAIN_PLAYWRIGHT_CDP` to name its loopback CDP endpoint. The adapter verifies package integrity and container
isolation and does not install a browser on demand. `blk engage setup` builds the command runner, not the browser environment.

Inspect saved operations without contacting a target:
```sh
blk engage web inspect --workspace ./assessment --view apis
blk engage web inspect --workspace ./assessment --view coverage
blk engage web help
```

## Engagement store and findings

`blk store` opens saved engagements for inspection and review. It provides engagement selection, surface filters, paginated records, finding filters, an interactive navigator, and local answers about the stored evidence.

```sh
blk store list
blk store show --workspace ./assessment
blk store records --workspace ./assessment --kind evidence --limit 20
blk store findings --workspace ./assessment --status validated
blk store ask --workspace ./assessment "Which observations remain unvalidated?"
blk store --interactive --workspace ./assessment
```

The default catalog lists workspaces under the blkChain configuration directory. Use `--workspace` for a workspace stored elsewhere, or `--id` to select a catalog entry.

Findings have explicit `lead`, `observed`, `validated`, and `dismissed` states. Detector and parsed records start as leads. Operator `add` and `review` actions persist conclusions and review events. Validated findings require exact evidence IDs belonging to the selected task.

`store ask` uses a loopback model endpoint and a bounded selection of engagement records. Answers cite supplied `[R1]` references and flag partial selection. When synthesis fails or references are invalid, it returns selected records for inspection. It does not run assessment tools or web search.

`blk kg` and the `kg_query` MCP tool expose task, asset, and evidence relationships, including dependencies and provenance. The graph refreshes from the engagement store.

A workspace includes `engagement.db`, captured artifacts under `evidence/`, `actions.jsonl`, `audit.jsonl`, policy/checkpoint data, and Markdown/JSON reports. Reports include completed and unfinished tasks, persisted finding review states, and exact evidence IDs. Use `blk store findings` to inspect those conclusions and their review history.

## Terminal and MCP interfaces

Bare `blk` starts the interactive session. A terminal uses the keyboard-driven UI; redirected input
uses the plain REPL. Finished answers remain in normal terminal scrollback. The UI supports
multiline drafts, external editing, history search, context previews, source inspection, model
controls, cancellation, and bounded queues.

| Interactive command | Purpose |
| --- | --- |
| `/agent auto` or `/agent NAME` | Select native answer routing and a research specialist. |
| `/model` | Select the model and reasoning level for the current answer mode. |
| `/models` | Inspect and administer native chat models, reranking, and web settings. |
| `/attach PATH` or `/context` | Queue, preview, or remove bounded context for the next question. URLs are references and are not fetched. |
| `/queue` | Review, edit, pause, resume, or remove queued questions in the UI. |
| `/history`, `/clear`, `/undo` | Inspect or change blk's local conversation state. |
| `/store ACTION` | Inspect engagement records and findings. |
| `/help` | Show the current command surface and keyboard help. |

The plain REPL uses text commands. The terminal UI adds picker overlays and asynchronous question
queues. Model and web preferences, conversation history, and engagement state are separate stores.

`blk mcp` serves these tools over stdio:

| Tool | Purpose |
| --- | --- |
| `kb_search` | Ranked local retrieval with source pointers. |
| `kb_answer` | Bounded native research answers. |
| `route_skill` | Deterministic domain-based playbook selection. |
| `engage` | Run under the operator-approved RoE configured by `BLKCHAIN_MCP_ROE_PATH`. The supplied inline RoE must match that policy. |
| `kg_query` | Query an engagement's task, asset, and evidence graph. |

MCP engagement defaults to Auto. `confirm=elicit` requires compatible client elicitation support.
The tool returns workspace, transcript, report, and policy references. `blk analyze --schema NAME`
provides schema-validated JSON generation.

## Architecture

| Component | Responsibility |
| --- | --- |
| `cli/` | Go retrieval, answers, terminal interfaces, engagement orchestration, policy enforcement, web analysis, storage, reports, and MCP. |
| `blkchain/` | Python MLX embedding/reranking service, offline ingestion/indexing, and evaluation harnesses. |
| Qdrant | Persistent dense and sparse index. |
| OpenAI-compatible LLM endpoint | Separately managed native answer and engagement inference. |
| Hermes | Separately configured agent backend for default conversational turns. |

Go owns query-time retrieval, answering, engagement execution, and MCP. Python serves the MLX models
and builds the index offline. Models and corpus content are supplied by the operator.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) documents what a change has to hold to: the language
boundary, the two cross-language contracts, the command output shapes the evaluation harness parses,
the security invariants, and the testing and commit conventions. Read it before changing the
retrieval path, the engagement harness, or the embedding service.

## Complete setup guide

This guide targets macOS on Apple Silicon. Run the core steps first to get local retrieval and
native answers working. Add Hermes for default conversational turns, the command runner for
engagements, and the browser container for runtime web collection.

| Component | Required for |
| --- | --- |
| Apple Silicon, Python 3.12.14, uv, Go 1.27.2, Xcode Command Line Tools | Building blk and running the MLX embedding service. |
| Docker Desktop | Qdrant and the isolated execution containers. |
| Embedder and reranker model files | Local retrieval. |
| OpenAI-compatible chat server and chat model | Native answers and model-driven engagements. |
| Hermes | Default `blk ask` and interactive agent mode. |
| Pinned Playwright package and browser container | Runtime browser collection. |

Choose a chat model that fits alongside the embedder, reranker, Docker, and the operating system.
Long contexts also consume memory. The guide uses a small MLX chat model for initial setup; select a
larger model when your hardware and workload support it. Reserve disk space for weights, corpus
files, Qdrant storage, evidence, and the chat server's cache.

### 1. Install the host prerequisites

Install [Homebrew](https://brew.sh/) if it is not already available. Install the command-line tools
and build dependencies:

```sh
xcode-select --install
brew install uv go
```

If Xcode Command Line Tools are already installed, skip the installer. Check the compiler and
package tools:

```sh
xcode-select -p
clang --version
uv --version
go version
```

The Go module requires Go 1.27.2. Use that version or a compatible newer toolchain. Go's automatic
toolchain selection can obtain the module's required version when enabled. See the
[Go installation guide](https://go.dev/doc/install) and
[uv installation guide](https://docs.astral.sh/uv/getting-started/installation/) for other methods.

Install [Docker Desktop for Apple Silicon](https://docs.docker.com/desktop/setup/install/mac-install/),
move it to Applications, and open it. Wait for the engine to start:

```sh
docker version
docker info
```

Both the client and server must answer. A Docker CLI without a running engine is not sufficient.
Container images and model downloads require internet access during provisioning.

### 2. Get the repository and build blk

Download or clone this repository from its distribution location, then enter the checkout. Replace
the path below with your own. Keep this shell in the repository root for the remaining core steps:

```sh
cd /absolute/path/to/blkChain
export BLKCHAIN_ROOT="$PWD"
uv python install 3.12.14
uv venv .venv --python 3.12.14
uv sync --locked
(cd cli && go mod download && go build -o blk .)
.venv/bin/python --version
cli/blk version
```

`uv sync --locked` installs the repository's pinned Python dependencies. `cli/go.mod` and
`cli/go.sum` provide the Go module versions and checksums. Keep CGO enabled; the Go client uses
SQLite and syntax-tree dependencies that need the C compiler.

Install the binary and add its directory to your shell path:

```sh
cli/blk install
export PATH="$HOME/.local/bin:$PATH"
blk version
```

Add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile if needed. For the default macOS
shell, use `~/.zshrc`. Optional shell completion is available through `blk completion zsh` or
`blk completion bash`.

### 3. Configure paths and the native provider

Create the local configuration template without replacing an existing file:

```sh
if [ ! -e .env ]; then
  (umask 077; cp .env.example .env)
fi
mkdir -p models/chat corpus/notes data/qdrant_storage
```

For the guide's default layout, export these settings in the current shell:

```sh
export BLKCHAIN_MODELS_DIR="$PWD/models"
export BLKCHAIN_SOURCES_DIR="$PWD/corpus"
export BLKCHAIN_COLLECTION=blkchain
export OMLX_BASE_URL=http://127.0.0.1:8000/v1
export OMLX_MODEL=Qwen3-4B-Instruct-2507-4bit
```

Copy non-secret settings into `.env` if you want them loaded by blk on later runs. Use absolute paths
for custom model and corpus directories. Process environment values take precedence over `.env`.
Keep credentials in the process environment or a secret manager and leave `.env` untracked.

The default endpoint layout is:

| Service | Endpoint |
| --- | --- |
| Qdrant HTTP | `http://127.0.0.1:6333` |
| Qdrant gRPC | `127.0.0.1:6334` |
| Embedding/reranking | `http://127.0.0.1:8100` |
| Native chat server | `http://127.0.0.1:8000/v1` |
| Hermes gateway | `http://127.0.0.1:8642` |

Keep these defaults for the initial setup. To use another embedding endpoint, set
`BLKCHAIN_EMBED_HOST` and `BLKCHAIN_EMBED_PORT`. These settings configure the Python service,
Python indexing client, Go retrieval client, and stack lifecycle checks together. Keep the service
bound to loopback for local operation. The Go retrieval parameters live in
`blkchain/contract/rag.json`; Python indexing settings live in `blkchain/config.py`.

These settings are read but are not part of the guide's path above. Leave them unset unless you need
the behavior described.

| Setting | Default | Effect |
| --- | --- | --- |
| `BLKCHAIN_DOCKER_BIN` | `docker` | Container runtime binary used to run and inspect the isolated browser and proxy. Changing it changes what executes the sandbox. |
| `BLKCHAIN_REPUTABLE_DOMAINS` | the list in `blkchain/contract/rag.json` | Comma-separated replacement for the domains a web result is treated as reputable from. |
| `BLKCHAIN_POC_DOMAINS` | the list in `blkchain/contract/rag.json` | Comma-separated replacement for the domains permitted as proof-of-concept destinations. |
| `BLKCHAIN_WEB_FALLBACK` | unset | Set to `duckduckgo` to use DuckDuckGo when no Tavily key is configured. |
| `BLKCHAIN_PLAYWRIGHT_HEADED` | unset | Must be `1` to permit a headed browser run, alongside an operator-provisioned headed container. |
| `BLKCHAIN_ANALYZE_MAX_INPUT_BYTES` | 1048576 | Subject size cap for `blk analyze`. |
| `BLKCHAIN_MAX_TEXT_FILE_BYTES` | 8388608 | Largest text file the indexer reads. |
| `BLKCHAIN_MAX_JSON_FILE_BYTES` | 4194304 | Largest JSON file the indexer reads. |
| `BLKCHAIN_EMBED_SUBBATCH` | 32 | Forward-pass sub-batch size in the embedding service. |
| `BLKCHAIN_EMBED_CACHE_RELEASE_AFTER` | 64 | Batches processed before the embedding service releases the Metal cache. |
| `BLKCHAIN_MMDFLUX` | `mmdflux` on `PATH` | Path to the diagram renderer used by the engagement views. |
| `BLKCHAIN_POWERLINE` | unset | Set to `0` to force plain unicode status separators instead of powerline glyphs. |
| `HERMES_HOME` | `~/.hermes` | Hermes configuration directory that `blk doctor` and the gateway setup read. |

### 4. Download the pinned models

The locked Python environment already includes the Hugging Face download library. Run this from
the repository root with `BLKCHAIN_MODELS_DIR` set as above:

```sh
.venv/bin/python - <<'MODELS'
import os
from pathlib import Path
from huggingface_hub import snapshot_download

root = Path(os.environ['BLKCHAIN_MODELS_DIR']).expanduser()
models = [
    ('mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ',
     '6c3ae70858513f1a78e9cdca3cae330d9075cd2a',
     root / 'Qwen3-Embedding-0.6B-4bit-DWQ'),
    ('afanjul/gte-reranker-modernbert-base-mlx',
     '0b1cfb9141dd1452e07a328a0dec430f2324da12',
     root / 'gte-reranker-modernbert-base-mlx'),
    ('mlx-community/Qwen3-4B-Instruct-2507-4bit',
     '50d427756c6b1b2fe0c0a10f67fbda1fc8e82c1b',
     root / 'chat' / 'Qwen3-4B-Instruct-2507-4bit'),
]
for repo, revision, destination in models:
    snapshot_download(repo_id=repo, revision=revision, local_dir=str(destination))
    print(f'Ready: {destination}')
MODELS
```

These directory names match the default embedder/reranker paths and the guide's chat model ID.
The downloads use full commit revisions. The
[Hugging Face download guide](https://huggingface.co/docs/huggingface_hub/en/guides/download)
describes resumable snapshots. The
[starter chat model](https://huggingface.co/mlx-community/Qwen3-4B-Instruct-2507-4bit) is an
Apache-2.0 MLX conversion with a tool-aware chat template. Review licenses for other models.

The embedder produces 1024-dimensional vectors. A different embedding dimension requires a
compatible Qdrant collection. `BLKCHAIN_RERANKER_KIND` selects an alternative reranker; its model
path and weights must match that choice.

Both default models are Apache-2.0. The reranker alternatives are not equivalent in licensing:
`BLKCHAIN_RERANKER_KIND=qwen3` uses Qwen3-Reranker-0.6B, which is Apache-2.0, and
`BLKCHAIN_RERANKER_KIND=jina` uses jina-reranker-v3, which is CC-BY-NC-4.0 and permits
non-commercial use only. Select the jina backend only where that license fits your use. See NOTICE.

### 5. Start Qdrant and the embedding service

Start the local retrieval stack:

```sh
blk up
blk status
curl --fail --silent --show-error http://127.0.0.1:8100/health
```

`blk up` creates or starts `blkchain-qdrant` using the image digest pinned in `cli/stack.go` and
starts the Python embedding service. Qdrant ports bind to loopback. Its persistent data lives under
`data/qdrant_storage`. The embedding service loads the downloaded embedder and reranker and writes
its log under `.run/`.

Expected embedding health includes `status: "ok"`, `embedder: true`, and `reranker: true`. Initial
model loading can take time. Use `blk logs embed_server` to inspect startup and `blk status` to check
both managed services.

If image access is denied, authenticate with `docker login dhi.io`, then retry `blk up`. Keep the
repository's digest rather than substituting a floating image tag.

### 6. Add your corpus and build the index

blkChain does not download a security corpus automatically. Start with your own Markdown notes.
The manifest reads the `notes/` directory below `BLKCHAIN_SOURCES_DIR`.

For a fresh setup, create a small document to verify indexing:

```sh
cat > "$BLKCHAIN_SOURCES_DIR/notes/setup-example.md" <<'NOTE'
# Contextual output encoding

Encode untrusted text for the output context where it is rendered.
HTML text, HTML attributes, JavaScript, and URLs require different handling.
Input validation checks business constraints and does not replace output encoding.
NOTE
.venv/bin/python -c "from blkchain import index; print(index.build_index(snapshot_version='v1'))"
blk sources --json
blk search --json --top-k 5 "contextual output encoding"
```

Confirm that `sources` reports indexed chunks and that search returns the setup document with its
source pointer. Re-running the indexer resumes by content hash.

Populate the source directories you use before building a larger index:

| Location under the corpus root | Content |
| --- | --- |
| `notes/` | Personal Markdown notes. |
| `hacktricks/hacktricks/`, `hacktricks/hacktricks-cloud/` | Supplied HackTricks checkouts. |
| `payloadsallthethings/` | Supplied payload/reference files. |
| `arsenal/curated-en/`, `arsenal/checklists-en/` | Supported technique JSON and checklists. |
| `skills/`, `violin-skills/` | Skill/reference Markdown. |
| `AI-penetration-testing/`, `arc_pi_taxonomy/`, `cai/` | Additional supported source directories. |

`BLKCHAIN_WSTG_PDF` selects an existing WSTG PDF. `BLKCHAIN_SECLISTS_DIR` adds catalog-style
wordlist metadata, and `BLKCHAIN_SKILLS_DIR` adds another skill directory. Unconfigured or absent
sources are skipped. The full manifest is in `blkchain/config.py`.

For an individual file or directory outside the manifest, use an absolute path and a distinct
source label:

```sh
blk add /absolute/path/to/my-notes --source my-notes
```

### 7. Start the native chat server

The guide uses oMLX. Install it with its
[official macOS app or Homebrew instructions](https://github.com/jundot/omlx):

```sh
brew tap jundot/omlx https://github.com/jundot/omlx
brew install jundot/omlx/omlx
omlx serve --help
```

For a fresh foreground server, create an API key in your password manager and enter it securely.
The following `read` hides the value while you type it; press Enter when finished:

```sh
read -r -s OMLX_API_KEY
export OMLX_API_KEY
omlx serve --model-dir "$BLKCHAIN_MODELS_DIR/chat" --host 127.0.0.1 --port 8000
```

Keep that terminal open. In a second terminal, enter the repository, repeat the exports from step 3,
and export the same `OMLX_API_KEY` from your secret manager. An existing oMLX installation can use
its configured API key and model directory instead. Confirm the server's actual model ID before
setting `OMLX_MODEL`.

Inspect the model list without printing the key:

```sh
.venv/bin/python - <<'CHECK'
import json
import os
import urllib.request

base = os.environ['OMLX_BASE_URL'].rstrip('/')
request = urllib.request.Request(base + '/models')
key = os.environ.get('OMLX_API_KEY', '')
if key:
    request.add_header('Authorization', 'Bearer ' + key)
with urllib.request.urlopen(request, timeout=15) as response:
    data = response.read((1 << 20) + 1)
if len(data) > 1 << 20:
    raise SystemExit('Model list exceeds the size limit')
models = json.loads(data)
print('\n'.join(item['id'] for item in models.get('data', [])))
CHECK
blk health --json
blk ask --agent auto --rag "Explain contextual output encoding"
```

The model list must include the ID configured in `OMLX_MODEL`. `health --json` should report
`ok: true` with all three native services available. The answer command should return text and
source references from your corpus. This verifies the native answer path without requiring Hermes.
Use a tool-calling model and a supporting server configuration for engagement orchestration.

### 8. Set up Hermes and connect the knowledge base

Hermes provides the default conversational backend. Install it using the
[official quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart/).
This CLI installer is pinned to a source commit and verified before execution:

```sh
hermes_installer="$(mktemp -t blkchain-hermes-install)"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
  https://raw.githubusercontent.com/NousResearch/hermes-agent/354724fb085162678964c116ceb4c40fc57c717c/scripts/install.sh \
  --output "$hermes_installer"
printf '14b4c89518cf0e4e71841708dd5d8a28f1f494d22cd20e12f4d5eeb29c7d2fdb  %s\n' \
  "$hermes_installer" | shasum -a 256 -c - && \
  bash "$hermes_installer" --commit 354724fb085162678964c116ceb4c40fc57c717c
```

Open a new terminal after installation, enter the repository, and restore the path/provider exports
and API key. Run `hermes setup` for initial configuration, then `hermes model`. Choose the custom
OpenAI-compatible endpoint and enter:

| Setting | Value for this guide |
| --- | --- |
| Base URL | `http://127.0.0.1:8000/v1` |
| Model | The actual ID from the server model list. |
| API key | The same local server key. |
| Context | At least 64,000 tokens, supported by the selected model and server. |

Add this server entry to `~/.hermes/config.yaml` under `mcp_servers`. Merge it into any existing
mapping rather than replacing the file. Replace the root path with your checkout:

```yaml
mcp_servers:
  blkchain:
    command: "${userHome}/.local/bin/blk"
    args: ["mcp"]
    enabled: true
    env:
      BLKCHAIN_ROOT: "/absolute/path/to/blkChain"
      OMLX_BASE_URL: "http://127.0.0.1:8000/v1"
      OMLX_MODEL: "Qwen3-4B-Instruct-2507-4bit"
      OMLX_API_KEY: "${OMLX_API_KEY}"
    tools:
      include: [kb_search, kb_answer, route_skill, kg_query]
```

Hermes resolves environment references from its secret scope or the process environment. Keep the
key in that scope rather than writing it into the YAML. The
[Hermes MCP reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference)
explains server fields and tool selection.

Verify the integration:

```sh
blk doctor
blk ask "Use kb_search to explain contextual output encoding from my local notes"
```

`doctor` should recognize the Hermes CLI and the enabled blkChain MCP entry. The default answer
should use Hermes and retrieve from the connected knowledge base.

For streaming gateway turns in the interactive UI, run these commands in a terminal with the native
API key exported:

```sh
blk gateway --setup-only
export API_SERVER_KEY="$OMLX_API_KEY"
export HERMES_API_URL=http://127.0.0.1:8642
blk gateway
```

`blk gateway` configures the API server in Hermes's private environment file, preserving unrelated
settings, then runs the gateway in the foreground. The two keys it writes there are
`API_SERVER_ENABLED` and `API_SERVER_KEY`; both belong to Hermes, and blk keeps a backup when a
value changes. In the terminal running `blk`, export `API_SERVER_KEY` with the same value and use
the same `HERMES_API_URL`. The client uses the gateway when available and can use the Hermes CLI
fallback otherwise. `blk up` does not start Hermes.

### 9. Provision the isolated command runner

Build the runner after Docker is available:

```sh
blk engage setup
blk help engage
```

The build uses the embedded Dockerfile, a digest-pinned base, and architecture-specific package
locks with verified download hashes. Re-run setup after rebuilding blk when the runner assets change.
Verify packaged tool availability with the local image check:

```sh
(cd cli && BLKCHAIN_ENGAGE_DOCKER_E2E=1 go test -run '^TestCatalogToolsRunInTheImage$' -v -count=1 -timeout 10m .)
```

Create an operator-owned `ROE.md` for each engagement. At first use in a fresh directory without a
policy, blk writes the commented template and stops. Fill in the actual authorized targets,
exclusions, action permissions, command denials, resource caps, and any foothold declaration before
starting target-facing work. Safe mode requires an interactive approval channel; Auto follows the
operator's policy.

The MCP `engage` tool additionally requires `BLKCHAIN_MCP_ROE_PATH` to point to that approved file.
Its supplied inline policy must match. Configure that tool separately when the operator chooses to
expose engagement execution; the knowledge-base MCP example above exposes research tools.

### 10. Provision the isolated browser

The browser is a separate optional container. The following headless setup matches the repository's
Apple Silicon driver and image checks. It does not require Node on the host.

Set the driver location and container identity:

```sh
export PLAYWRIGHT_DRIVER_PATH="$HOME/.local/share/blkchain/playwright-1.62.1"
export BLKCHAIN_PLAYWRIGHT_CONTAINER=blk-web-browser
export BLKCHAIN_PLAYWRIGHT_CDP=http://127.0.0.1:9222
```

Download and verify the driver before extracting it:

```sh
(
  set -eu
  mkdir -p "$PLAYWRIGHT_DRIVER_PATH"
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120 \
    https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz \
    --output "$PLAYWRIGHT_DRIVER_PATH/playwright-core-1.62.1.tgz"
  .venv/bin/python - <<'INTEGRITY'
import base64
import hashlib
import os
from pathlib import Path

archive = Path(os.environ['PLAYWRIGHT_DRIVER_PATH']) / 'playwright-core-1.62.1.tgz'
expected = 'wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw=='
with archive.open('rb') as file:
    actual = base64.b64encode(hashlib.file_digest(file, 'sha512').digest()).decode()
if actual != expected:
    raise SystemExit('Playwright integrity check failed')
print('Playwright integrity verified')
INTEGRITY
  tar -xzf "$PLAYWRIGHT_DRIVER_PATH/playwright-core-1.62.1.tgz" -C "$PLAYWRIGHT_DRIVER_PATH"
  chmod -R a+rX "$PLAYWRIGHT_DRIVER_PATH/package"
  cp cli/playwright-container-node.sh "$PLAYWRIGHT_DRIVER_PATH/node"
  chmod 700 "$PLAYWRIGHT_DRIVER_PATH/node"
  printf '5021d5f31f68d772f4e5c0e2f418ef63e181ba314500f5b1fabdaa6174de1aa3  %s\n' \
    "$PLAYWRIGHT_DRIVER_PATH/node" | shasum -a 256 -c -
)
```

Keep the verified archive beside `package/`. blk compares every extracted file against it and
checks the launcher hash. The package is public code; its read permissions allow the container's
non-root user to read the bind mount.

Pull the pinned browser image and start Chromium:

```sh
docker pull dhi.io/playwright@sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851
docker run -d --name "$BLKCHAIN_PLAYWRIGHT_CONTAINER" \
  --network none --user 1000:1000 --read-only --memory 1g --cpus 2 \
  --pids-limit 256 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --mount "type=bind,src=$PLAYWRIGHT_DRIVER_PATH/package,dst=/opt/blkchain-playwright/package,readonly" \
  --entrypoint /ms-playwright/chromium-1243/chrome-linux-arm64/chrome \
  dhi.io/playwright@sha256:362a6b32631204936ec45c03f5c0f0b75bab6489a05031d59f51665fef3d7851 \
  --headless=new --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir=/tmp/blk-profile about:blank
docker inspect --format '{{.State.Running}}' "$BLKCHAIN_PLAYWRIGHT_CONTAINER"
```

CDP is container loopback, not a host-published port. The launcher starts Node inside the container,
so it reaches that endpoint there. Browser target traffic crosses the Go broker. Do not add a Docker
socket, home-directory mount, or direct network access to this container.

Verify the real browser adapter against the repository's local fixture:

```sh
(cd cli && BLKCHAIN_PW_E2E=1 go test -run '^TestWebPlaywrightE2E$' -v -count=1 -timeout 120s .)
```

Require a named `PASS`, not a skipped test. Keep the driver/container exports in the environment
that launches blk or its MCP server. The browser container is started separately from `blk up`.
For collection, select `--browser` through `blk engage web`; use `blk engage web help` for the
operator-policy and workspace arguments.

#### Optional local library advisories

Library matching uses a pinned local [RetireJS advisory repository](https://github.com/RetireJS/retire.js).
Provision its snapshot and integrity manifest from the repository root:

```sh
.venv/bin/python - <<'ADVISORIES'
import hashlib
import json
import os
from pathlib import Path
import urllib.request

os.umask(0o077)
revision = 'e644a46aa9d2bde1f7f9c82fea7ebc3a19660aa5'
expected = '557465843feee5d84b0a6d440448be44984ffa5c534b07f5bce5c7b95ff7fbd5'
url = f'https://raw.githubusercontent.com/RetireJS/retire.js/{revision}/repository/jsrepository.json'
with urllib.request.urlopen(url, timeout=30) as response:
    data = response.read((4 << 20) + 1)
if len(data) > 4 << 20 or hashlib.sha256(data).hexdigest() != expected:
    raise SystemExit('Advisory snapshot integrity check failed')
json.loads(data)
root = Path('data/advisories').resolve()
root.mkdir(parents=True, exist_ok=True)
snapshot = root / f'retire-{revision}.json'
snapshot.write_bytes(data)
manifest = {'path': str(snapshot), 'sha256': expected,
            'date': '2026-10-06', 'revision': revision}
(root / 'retire-manifest.json').write_text(json.dumps(manifest) + '\n')
print('Local advisory snapshot ready')
ADVISORIES
export BLKCHAIN_RETIRE_MANIFEST="$PWD/data/advisories/retire-manifest.json"
```

Keep the manifest path in the environment used by blk. Add it as a non-secret setting to `.env` if
needed. Snapshot updates require a new immutable revision, digest, and date.

### 11. Verify the installation and manage its lifecycle

With the native services running:

```sh
blk version
blk health --json
blk sources --json
blk search --json --top-k 5 "contextual output encoding"
blk ask --agent auto --rag "Explain contextual output encoding"
blk doctor
```

Start bare `blk` to open the terminal UI. `/agent auto` selects native research and `/help` lists
commands. Once Hermes is configured, the default mode uses its backend.

| Data or process | Location or control |
| --- | --- |
| Qdrant index | `<checkout>/data/qdrant_storage/` |
| Embedding log and PID | `<checkout>/.run/` |
| Preferences and default engagements | `~/.config/blkchain/`, or `XDG_CONFIG_HOME` |
| Conversation history and sessions | `~/.local/share/blk/`, or `XDG_DATA_HOME` |
| Command runner | Built by `blk engage setup`; engagement workers are managed by the harness. |
| Browser container | `docker start blk-web-browser` / `docker stop blk-web-browser` |
| Native chat server | Its own foreground terminal or provider's service manager. |
| Hermes gateway | Its own foreground terminal; `blk gateway` configures and starts it. |

`blk down` stops Qdrant and the embedding service without deleting the index. `blk up` starts them
again. `blk engage stop --workspace PATH` requests an engagement stop. Keep evidence directories
when they are needed for review or resume.

#### Optional public research

Enable native web research explicitly when you want it:

```sh
blk web provider duckduckgo
blk web on
blk web status
```

For Tavily, export `TAVILY_API_KEY` or `TAVILY_SETUP_TOKEN` from your secret manager, then select
`blk web provider tavily`. `blk web off` revokes native web permission. `NVD_API_KEY` is optional for
CVE lookups. Hermes provider and tool permissions are configured separately.

### Setup troubleshooting

| Symptom | Check and action |
| --- | --- |
| `blk` is not found | Add `~/.local/bin` to `PATH`, or use `cli/blk` from the checkout. |
| Go build cannot find a C compiler | Install Xcode Command Line Tools and keep CGO enabled. |
| Docker reports it cannot connect | Open Docker Desktop and wait for `docker info` to answer. |
| An image pull is denied | Authenticate to `dhi.io` and confirm access to the exact pinned image. |
| The embedding service does not become ready | Check configured model paths and `blk logs embed_server`; confirm the weights finished downloading. |
| Retrieval has no results | Check `blk sources --json`, corpus paths, collection name, and the completed indexing output. |
| Chat returns 401 or an unknown-model error | Supply the server's actual API key and use an ID returned by its `/v1/models` endpoint. |
| A default answer cannot start | Configure Hermes or select native routing with `--agent auto` / `/agent auto`. |
| The gateway is unauthorized | Export the same `API_SERVER_KEY` used by the gateway in the client terminal. |
| Browser provisioning is rejected | Check all driver exports, archive/launcher hashes, the read-only package mount, and the required container settings. |

## Ingestion and data handling

The indexer accepts supplied Markdown, code/text, PDFs, supported JSON techniques, and catalog-only
wordlist metadata. Stable chunk identifiers and content hashes support resumable indexing. Resume
refreshes metadata for unchanged text while retaining its vectors. Directory adds have file and byte
limits. Public URL ingestion validates destinations, pins resolution,
rechecks redirects, and records external provenance.

Use `blk add /absolute/path/to/notes --source my-notes` for a separately managed addition. Relative
paths resolve against your current directory. Re-adding an input updates that input's chunks while
preserving other inputs with the same source label. The completion message reports additions,
updates, skipped embeddings, and deletions.

Target data, retrieved content, model text, and command output are untrusted inputs. Prompts frame
embedded instructions as data. The execution gate and broker enforce authority independently of
research text. Public URL ingestion rejects private destinations, while an engagement can authorize
private targets through explicit IP/CIDR scope. A hostname alone does not authorize its private
resolved address.

Engagement artifacts can contain raw responses, request bodies, credentials, and candidate secrets.
Display redaction does not make every saved artifact or exact export safe to share. Review selected
records and exported files before distribution and apply an appropriate retention policy.

## License

blkChain code is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Models,
corpus content, target data, and external services retain their own terms. Review those terms before
redistribution or commercial use.
