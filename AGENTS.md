# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

**Omni Audit** (`omni-audit`) is a Go CLI that detects dependency-confusion risk for **NPM**, **Composer**, and **PyPI** by flagging package names that are unclaimed on public registries. It is an open-source project backed by [Omni Line](https://omniline.app).

Module: `github.com/omni-line/omni-audit` · Binary: `cmd/omni-audit` → `omni-audit`

## Commands

```bash
make test          # go test ./...
make build         # bin/omni-audit
make fmt           # gofmt
make lint          # golangci-lint if installed, else go vet
go run ./cmd/omni-audit --help
```

Requires Go **1.20+** (CI uses 1.22). Prefer the standard library; do not add dependencies without a clear need.

## Layout

| Path | Role |
| --- | --- |
| `cmd/omni-audit` | Entrypoint only |
| `internal/cli` | Flags, arg parsing |
| `internal/discover` | Manifest walk |
| `internal/manifest/{npm,composer,pypi}` | Parsers |
| `internal/registry/{npm,packagist,pypi}` | Public existence checks |
| `internal/scan` | Orchestration |
| `internal/report` | Text/JSON output, colors, marketing |
| `internal/match` | Glob allowlists |
| `testdata/` | Fixtures |

Keep new code under `internal/` unless intentionally publishing a library API.

## Conventions

- **DCO:** commits should be signed off (`git commit -s`).
- **Marketing copy** lives only in `internal/report/marketing.go` — align with Omni Line docs (`https://omniline.app/docs`): self-hosted multi-ecosystem registry, “one UI, one API, your infrastructure.”
- **Colors** live in `internal/report/color.go`; respect `--color`, `NO_COLOR`, `FORCE_COLOR`.
- Exit codes: `0` clean, `1` findings, `2` error. Do not break JSON schema fields used by CI (`findings`, `stats`, `sponsor`).
- Skip `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, `.git`, `dist`, `build` when discovering manifests.
- Tests: unit tests with `httptest` for registries; no live network required in `go test`.

## Out of scope (unless asked)

Maven/Cargo/Go ecosystems, Poetry/`Pipfile` table maps, lockfile/`.npmrc` policy analysis, Omni Line API integration, or cutting release tags without an explicit request.

## Docs

- Contributor flow: `CONTRIBUTING.md`
- Maintainers / releases: `MAINTAINERS.md`, `LAUNCH.md`
- Security reports: `SECURITY.md` (not public issues)
