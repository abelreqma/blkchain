# CLAUDE.md

Read [AGENTS.md](AGENTS.md). It is the project's guidance for coding agents and it applies here
unchanged: what this repository is, the contracts a change has to keep, the security invariants, the
build and test commands, and the style.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing the retrieval path, the engagement
harness, or the embedding service.

Both suites before claiming a change works, plus the race detector and the Python lint, which CI
gates on as well:

```sh
cd cli && go test ./...
cd cli && go test -race ./...
.venv/bin/python -m unittest discover tests
uvx ruff check blkchain tests
```
