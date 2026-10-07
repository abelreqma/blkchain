# blkChain

blkChain is a local-first framework for authorized security assessment. Its core is `blk engage`, a
Go harness that plans and executes bounded assessment tasks under an operator-defined rules of
engagement (RoE) policy. A local security knowledge base supplies retrieval, cited answers, and
technique context during an engagement. The terminal client and interactive session expose the
harness; the MCP server provides retrieval and RoE-bound engagement tools.

The project is under active development. It already supports scoped engagement runs, evidence
collection, web application analysis, local research, and saved reports. It does not claim to find
or verify every vulnerability. The sections below distinguish current behavior from intended work.

## Product model

An engagement starts with an operator-approved RoE and a goal. The harness creates a task graph,
selects an executor for each reachable surface, runs permitted actions, captures exact evidence, and
writes a report that preserves completed and unfinished work. The model can propose tasks, tool
arguments, and advisory techniques. Code owns scope, action authorization, task identity, resource
limits, and execution.

The intended end state is a repeatable assessment workflow that can move from asset discovery
through focused testing, evidence-backed validation, and reporting while keeping the operator's
authorization and the target's data separate. The knowledge base supports that workflow; it is also
available as a standalone research tool.

| Status | Scope |
| --- | --- |
| Available | Local hybrid retrieval and cited answers; CLI, interactive, and MCP access; RoE-gated engagements; isolated command execution; persistent tasks, evidence, and reports; bounded web collection and replay. |
| In development | Deeper finding correlation and validation across assessment surfaces; more consistent evidence grades and report semantics; broader end-to-end engagement evaluation. |
| Planned direction | A unified web assessment workflow, richer surface-specific testing, and release processes that make behavior and limits reproducible across supported installations. These are goals, not commands or guarantees in the current release. |

## Current capabilities

### Authorized engagement harness

`blk engage` runs multi-step assessments in Auto or Safe mode. Auto executes actions allowed by the
RoE without a prompt for every action. Safe requests interactive approval. The policy specifies
in-scope and excluded targets, allowed and denied action types, command denials, rate limits,
resource caps, and the isolated runner. Empty or ambiguous scope fails closed.

The policy is a file you own. Running `blk engage` in a directory with no `ROE.md` writes a commented
template there and stops, so the sections and their syntax are in front of you rather than recalled;
fill in `Targets` and `In Scope` and run again. The template is never overwritten once it exists, and
on its own it authorizes nothing, because an unfilled scope is an empty scope. Pass `--roe PATH` to use
a policy kept elsewhere.

The harness records tasks, dependencies, evidence, coverage gaps, policy decisions, and action
transcripts in an engagement workspace. It supports stop and resume. Resume requires the same sealed
policy and retains the original deadline and usage counters. A run that reaches a limit or cannot
finish produces an incomplete report rather than claiming completion.

The current executor registry covers network, web, local host, container, Active Directory, cloud,
and AI application assessment paths. Depth differs by surface:

| Surface | Current implementation |
| --- | --- |
| Network | Tiered asset and service discovery, fingerprinting, and evidence-backed candidate tasks. A candidate is an investigation lead, not a verified exploit. |
| Web | Bounded browser and HTTP collection, source analysis, role-aware observations, and scoped replay. The detailed workflow appears below. |
| Local host | Read-only enumeration of identity, privileges, file permissions, capabilities, scheduled tasks, and services, with focused analysis of a selected executable. Runs on a declared foothold when the RoE names one, and in the isolated runner otherwise. |
| Container | Container and Kubernetes reconnaissance through a specialized tier ladder and the shared gated executor. |
| Active Directory | Domain-controller discovery and staged anonymous, authenticated, and finding-driven enumeration through the shared executor. |
| Cloud | Shared metadata, storage, and identity reconnaissance with AWS, Azure, and GCP-specific ladders. These are not three independent cloud API engines. |
| AI application | Endpoint and model discovery, capability and prompt-injection probes, and evidence-derived follow-on candidates. |

Reconnaissance, candidate generation, and task execution are separate steps. A retrieved technique
or model suggestion does not establish a vulnerability or authorize execution. Candidate targets and
armed state are derived by code and remain subject to the RoE gate.

Reports distinguish what ran from what was shown. A completed task is one that ran, recorded an exact
quote of its output, and was completed on a stated basis naming the evidence that meets its `done_when`
condition; blkChain checks that the cited evidence exists and belongs to that task, not that it proves
the condition, so completed work appears under `Completed tasks` rather than as findings. A matched
secret pattern appears under `Secret candidates` with its detector and evidence grade, because a match
is a lead and not a credential anyone has shown to work.

#### External to internal pivot

An engagement that reaches internal access can execute on it. An optional `Foothold` section of the
RoE names one host the operator already controls, and tasks on the surfaces it covers run there
instead of in the isolated runner. The default covered surface is the local host; `surfaces=` extends
it to Active Directory, container, or network work. Without a foothold every command runs in the
runner, and a local-host task therefore describes the runner rather than a target.

The carrier is selected by how the access was acquired, not fixed to one client. `transport=ssh`
needs a user and a key. `transport=command` takes an argv prefix of the operator's own, such as
`kubectl exec -i web-0 --`, for access ssh cannot reach. Key material is named by environment
variable and read at setup, never written into the policy or a prompt, and is delivered to the worker
as an owner-only file rather than mounted from the operator's filesystem. A carrier that authenticates
with something other than a key file names it with `env=A,B`: those variables, and nothing else from
the operator's environment, reach the environment of every command the worker starts. `PATH`, `HOME`,
and `LANG` are fixed by the worker, so a declaration cannot repoint command lookup.

A pivoted command runs on a filesystem that is not this host's, so a check that identifies a file by
resolving a path cannot speak for it. Name an inspection tool by absolute path when a task analyzes an
executable on the foothold: a bare name matching the analysis target's own base name is refused,
because there it could resolve to the file the task exists to read rather than run.

The declaration is authorization data. It is sealed into the policy, so a resume with a different
foothold is refused; its host must also be in scope, so the runner's firewall permits the connection;
and the surface of a task, not the model, decides where that task's commands run. Declaring a
foothold starts the engagement at the internal-foothold vantage, which is what opens the local and
Active Directory surfaces.

### Web application analysis

`blk engage web` provides `collect`, `analyze`, `inspect`, `import`, `archive`, `export`, and
`replay` actions. Collection and replay require the operator RoE; inspection and export can read
saved evidence without contacting a target.

The collector follows a bounded discovery frontier and can use an isolated browser to capture
rendered pages, runtime scripts, frames, workers, WebSocket traffic, and observed requests. Analysis
processes JavaScript, TypeScript, JSX, source maps, and selected framework patterns to recover API
operations, parameters, GraphQL calls, and source locations. It records unresolved dependencies and
exhausted limits as coverage gaps. Role sessions use credentials supplied through environment
references and keep them bound to the configured origin.

The web workflow supports HAR import, historical source collection, structured HTTP replay, and
operator-supplied exact WebSocket exchanges. Operations and findings carry evidence grades that
distinguish discovery, an observed response, an advisory match, and a validated exchange. A static
match or detected credential is a lead until its relevance and impact are checked. The workspace
retains captured artifacts and exact request data; treat its files and JSON exports as sensitive.

Run `blk engage web help` for current flags. See [web analysis details](cli/web-analysis.md) for
limits and data formats.

### Local knowledge and research

The offline indexer accepts user-supplied Markdown, code and text files, supported JSON content,
PDFs, and catalog-style wordlist metadata. It chunks content structurally, creates dense and BM25
sparse vectors, and reconciles changed content by hash. Go queries Qdrant using hybrid retrieval,
then optionally reranks the candidate pool with a local cross-encoder.

`blk search --json` and the `kb_search` MCP tool return ranked source chunks. `blk ask` and
`kb_answer` run a bounded answer loop that can grade context, rewrite a query, and synthesize a
cited response. Optional public web research is controlled separately by the saved web permission.
Retrieved text is evidence for the model, never an instruction or executable command. Cited answers
still require human review when accuracy matters.

The knowledge base is not the execution authority for an engagement. It can supply an advisory
technique and citation; the command gate makes its decision from code-owned task and RoE fields.

### Operator interfaces and integration

The `blk` binary provides one-shot commands, a keyboard-driven interactive session, a plain REPL,
model controls, history, context attachments, queued questions, source viewing, and service
diagnostics. `blk mcp` exposes `kb_search`, `kb_answer`, `route_skill`, `engage`, and `kg` over
stdio. MCP engagement requires an operator-owned RoE file named by `BLKCHAIN_MCP_ROE_PATH`; a
caller-supplied policy must match it.

`blk health`, `blk doctor`, `blk models`, and `blk status` report the state of the local stack.
`blk up` and `blk down` manage Qdrant and the embedding server. The synthesis LLM is served
separately through an OpenAI-compatible local endpoint.

## Authorization and data boundaries

Use blkChain only on systems and applications you are authorized to assess. The RoE is the authority
for target-facing actions. Authorized private and internal targets are supported when they appear in
scope, which for a loopback, RFC1918, or link-local address means its own IP or CIDR entry: a hostname
entry does not authorize the address it resolves to, so a name that resolves inward cannot reach an
internal service by accident. The isolated command runner restricts host access, network destinations, CPU, memory,
processes, output, and time. A command carried to a declared foothold is the one exception to the
network restriction: it executes on a host whose egress is not the runner's to filter, so its scope
is enforced by the command gate alone, and every such action records the host it ran on. The web request broker checks destinations on resolution and redirect,
and the browser runs in an isolated container. Target responses, retrieved documents, and tool
output are untrusted data.

The workspace can contain raw responses, request bodies, tokens, and credential candidates. It uses
owner-only permissions on supported Unix systems, but operators remain responsible for storage,
retention, and sharing. Web exports and `--json` output can contain exact values. Do not publish an
engagement workspace or a report without reviewing it.

Web research for answers is a separate permission from engagement authorization. Enabling it can
send a research query to a configured provider. It does not expand engagement scope.

## Architecture

| Component | Responsibility |
| --- | --- |
| `cli/` | Go terminal client, engagement orchestration, policy gate, executors, web workflow, retrieval client, answer loop, reports, and MCP server. |
| `cli/internal/engagement/` | Persistent task, evidence, and graph state. |
| `cli/internal/secgate/` | Scope, action, command, and resource policy. |
| `cli/internal/webcollect/`, `webanalysis/`, `webacquire/` | Web acquisition, analysis, and scoped HTTP/WebSocket access. |
| `blkchain/` | Python MLX embedding and reranking server, offline ingestion and indexing, and evaluation tools. |
| Qdrant | Local dense and sparse index queried by Go. |
| Local LLM server | Separately managed OpenAI-compatible inference endpoint. |

Go owns query-time retrieval, answering, engagement execution, and MCP. Python serves embeddings and
reranking over localhost and builds the index offline. The corpus and model weights are supplied by
the operator and are not distributed in this repository.

| Service | Default endpoint | Role |
| --- | --- | --- |
| Qdrant | `127.0.0.1:6333` HTTP, `127.0.0.1:6334` gRPC | Persistent hybrid index. |
| Embedding server | `127.0.0.1:8100` | Resident MLX embedder and reranker. |
| Local LLM | `127.0.0.1:8000/v1` | Separately managed answer and engagement model. |

## Requirements and setup

The MLX model service requires macOS on Apple Silicon. The repository pins Python 3.12.14 in
`pyproject.toml`, Go 1.27.1 in `cli/go.mod`, Python packages in `uv.lock`, and Go modules in
`cli/go.sum`. Docker is required for Qdrant and the isolated engagement runner. A local
OpenAI-compatible LLM is required for answers and model-driven engagements; raw search does not
require it.

From the repository root:

```sh
uv python install 3.12.14
uv venv .venv --python 3.12.14
uv sync --locked
(cd cli && go mod download && go build -o blk .)
cp .env.example .env
```

Set corpus and model locations in `.env` or the process environment. The default model paths under
`BLKCHAIN_MODELS_DIR` expect `Qwen3-Embedding-0.6B-4bit-DWQ` and `gte-reranker-modernbert-base-mlx`.
Download the model revisions appropriate to the configured paths before starting the embedding
server. No model weights or corpus files ship with blkChain. Keep credentials in the environment and
leave `.env` untracked.

With the Hugging Face `hf` CLI installed, provision the default model revisions:

```sh
export BLKCHAIN_MODELS_DIR="${BLKCHAIN_MODELS_DIR:-$PWD/models}"
mkdir -p "$BLKCHAIN_MODELS_DIR"
hf download mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ \
  --revision 6c3ae70858513f1a78e9cdca3cae330d9075cd2a \
  --local-dir "$BLKCHAIN_MODELS_DIR/Qwen3-Embedding-0.6B-4bit-DWQ"
hf download afanjul/gte-reranker-modernbert-base-mlx \
  --revision 0b1cfb9141dd1452e07a328a0dec430f2324da12 \
  --local-dir "$BLKCHAIN_MODELS_DIR/gte-reranker-modernbert-base-mlx"
```

The optional Qwen3 and Jina rerankers use different model paths and licenses. Select one with
`BLKCHAIN_RERANKER_KIND` only after reviewing its upstream terms. A different embedding dimension
requires a new Qdrant collection.

Start the local retrieval services and index your supplied corpus:

```sh
mkdir -p data/qdrant_storage
docker run -d --name blkchain-qdrant --restart unless-stopped \
  -p 127.0.0.1:6333:6333 -p 127.0.0.1:6334:6334 \
  -v "$PWD/data/qdrant_storage:/qdrant/storage" \
  dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba
.venv/bin/python -m blkchain.embed_server &
.venv/bin/python -c "from blkchain import index; print(index.build_index(snapshot_version='v1'))"
cli/blk search --json --top-k 5 "server-side request forgery"
```

Start the synthesis LLM separately, then run `cli/blk doctor` and `cli/blk ask "What is SSRF?"`.
`cli/blk install` copies the built binary to a directory on `PATH` if you want to use `blk` from
other directories. Run `blk help env` for current environment variables and `blk help <command>` for
command flags.

For an engagement, prepare an RoE for the authorized target, then build the isolated runner image:

```markdown
# Rules of Engagement

## In Scope
- 192.0.2.10
- *.example.com

## Out of Scope
- 192.0.2.11

## Rate
2/s

## Allowed Actions
- command
- api-read
- browser-read
```

The addresses above are documentation examples. Replace them with the actual authorized scope.
A `*.` entry matches subdomains of that suffix and not the bare apex, so list the apex
separately when it is in scope. A wildcard command resolves its own targets and runs behind a
guard limited to those checked addresses.

To run local-host work on a host you already control, add the host to `In Scope` by name and declare
it as the foothold:

```markdown
## Foothold
- 192.0.2.10 user=svc-deploy key=$BLKCHAIN_FOOTHOLD_KEY
```

```sh
cli/blk engage setup
cli/blk engage --roe ROE.md --workspace ./assessment \
  "Enumerate the authorized target and report the observed services"
```

`ROE.md` must name the actual authorized scope. The command will not infer authority from a goal or
a model response. `blk engage web collect TARGET --roe ROE.md --workspace ./assessment --browser`
runs the web collector under the same policy. Browser collection also requires its provisioned
Playwright container and driver. Inspect `blk engage web help` for the available modes and flags.

## Common commands

| Command | Purpose |
| --- | --- |
| `blk search --json <query>` | Return ranked local evidence without answer synthesis. |
| `blk ask <question>` | Produce a cited answer from local evidence and optional permissioned web research. `--agent <name>` selects the answer specialist. |
| `blk add <path-or-url>` | Add a file, directory, or public URL to the local index. URL ingestion rejects unsafe destinations. |
| `blk sources` | List indexed sources and chunk counts. |
| `blk engage --roe ROE.md <goal>` | Start an RoE-gated assessment. |
| `blk engage --resume <workspace>` | Resume under the original policy and remaining limits. |
| `blk engage stop --workspace <path>` | Stop a running engagement. |
| `blk engage web <action>` | Collect, analyze, inspect, import, archive, export, or replay web evidence. |
| `blk kg --workspace <path>` | Query the engagement task and evidence graph. |
| `blk mcp` | Serve retrieval and engagement tools over MCP stdio. |
| `blk doctor` | Diagnose local services and configuration. |

The interactive session starts with bare `blk`. Use `/help` for its commands. Model and web-search
settings persist in the local configuration directory.

## Development and evaluation

The default test suites use fixtures and do not require live models or target services:

```sh
(cd cli && go test ./... && go vet ./...)
.venv/bin/python -m unittest discover tests
```

The retrieval evaluation drives the built Go binary against labeled queries and reports hit rate and
reciprocal rank. It measures retrieval against its dataset, not answer accuracy or vulnerability
detection:

```sh
export BLK_BIN="$PWD/cli/blk"
.venv/bin/python -m blkchain.eval.run --no-judge
```

Browser, runner, MCP, and local-model integration tests are opt-in because they require provisioned
services or containers. Evaluation output depends on the supplied corpus, model, and lab conditions;
the repository does not present a general detection or exploit-success rate.

## Planned development

These items describe product direction. They are not available as a complete command today.

1. **Unified web assessment:** connect existing collection, role-aware analysis, replay, focused checks,
   and reporting into one bounded workflow. Require direct evidence before calling a finding verified.
2. **Deeper surface-specific analysis:** expand native finding parsers and validation paths for network,
   web, local, container, AD, cloud, and AI assessments. Preserve code-owned scope and task identity.
3. **Evidence-led reporting:** distinguish observations, candidate leads, and confirmed impact in the
   task store, terminal output, and exported reports.
4. **Repeatable quality gates:** measure discovery coverage, task completion, detection quality, false
   positives, and policy behavior on controlled targets before broader effectiveness claims.
5. **Operational maturity:** improve installation, controlled integration testing, and release checks
   for the multi-service stack.

The local execution and operator-controlled policy boundaries remain part of the product model.

## License

blkChain code is licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Models,
corpus content, target data, and optional external services retain their own terms. Review those
terms before redistribution or commercial use.
