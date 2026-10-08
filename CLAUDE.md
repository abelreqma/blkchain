# CLAUDE.md

Read [AGENTS.md](AGENTS.md). It is the project's guidance for coding agents and it applies here
unchanged: what this repository is, the contracts a change has to keep, the security invariants, the
build and test commands, and the style.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing the retrieval path, the engagement
harness, or the embedding service.

Both suites before claiming a change works:

```sh
cd cli && go test ./...
.venv/bin/python -m unittest discover tests
```
