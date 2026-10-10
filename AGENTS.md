# AGENTS.md

Guidance for coding agents working in this repository. Humans changing the code want the same
information, so nothing here is agent-specific beyond the format.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing the retrieval path, the engagement
harness, or the embedding service. It holds the contracts a change has to keep: the language
boundary, the embedding-server wire contract, the parameter contract in `blkchain/contract/rag.json`,
the command output shapes the evaluation harness parses, and the security invariants. This file is
the short version and defers to it on every detail.

## What this is

blkChain is a local-first framework for authorized security assessment. Its core, `blk engage`, is a
Go harness that plans and executes bounded tasks under an operator-defined rules of engagement
policy. A local retrieval system supplies research tools to the harness and works on its own as a
security knowledge base.

The tool executes real commands against real targets. The operator's authorization is the premise,
and the engagement's policy defines the permitted targets, actions, time window and rate. Code owns
scope, action authorization, task identity, resource limits and execution; retrieved text is advisory
context and never grants authority.

## Before you change anything

- Go is the single implementation for search, ask, health and MCP. Python serves the MLX models and
  builds the index offline. Python has no query-time code, and none should be added.
- The two cross-language contracts must stay in lockstep. Changing a value in
  `blkchain/contract/rag.json` without updating the compiled-in Go fallback in the same commit fails
  a test that exists to catch exactly that.
- No retrieved or target-controlled text may set a target, authorize an action, arm a task, or
  execute as code. Every candidate field is code-derived, and no gate verdict reads a model-supplied
  technique or citation.
- Scope fails closed. An empty or ambiguous scope permits nothing, and a hostname entry does not
  authorize the address it resolves to.
- Bound every resource: requests, output, rate, duration and total work. Secrets come from the
  environment only.
- Dependencies are pinned. Python with `==`, models to a revision, container images to a digest, and
  CI actions to a commit SHA.

The full list, with the reasoning each one rests on, is in the security invariants section of
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Treat it as a floor, not a checklist: a change that
keeps the letter of an invariant while defeating its purpose is a regression.

## Building and testing

```sh
cd cli && go build -o blk .
cd cli && go test ./...
cd cli && go test -race ./...
uv sync --locked
.venv/bin/python -m unittest discover tests
uvx ruff check blkchain tests
```

Run both suites before claiming a change works. CI gates on more than the suites: `gofmt`,
`go vet`, staticcheck, the race detector, ruff, `govulncheck`, `pip-audit`, a workflow lint over
anything under `.github`, a secret-shaped-string scan over the whole history, and a check that no
local-only path is tracked. Read `.github/workflows` for the current set rather than this list.
The analyzer versions are pinned in the workflow that runs each one, which is the authority on
them.

The default suites are hermetic. The browser, runner, MCP and local-model suites need provisioned
services or a local model and are gated behind their own environment variables, so a green default
run does not cover them.

Add a regression test with every fix, in the file that matches its area. A test that cannot fail
proves nothing: for a security boundary in particular, confirm the test fails when the control is
removed.

## Style

- Simplicity first. The minimum code that solves the problem, no speculative abstractions, no
  configuration for fixed values, and no error handling for impossible states.
- Surgical changes. Touch what the task needs, match the surrounding style, and remove only the
  names your own change orphaned.
- Comments state what the code does, or why a non-obvious choice is necessary, in plain present
  tense. If the code already says it, delete the comment. Objective identifiers that describe a real
  contract stay: spec ids, CVE ids, RFC numbers, algorithm names.
- Prose and comments are plain ASCII, direct and concise.
- Conventional Commits, with a scope where one applies. Stage files explicitly by path.
