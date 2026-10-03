# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

**Omni Audit** (`omni-audit`) is a Go CLI that detects dependency-confusion risk for **NPM**, **Composer**, **PyPI**, **Go**, **Cargo**, **RubyGems**, **Maven**, **Conan**, and **Docker Hub** by flagging package names that are unclaimed on public registries; audits lockfile resolution URLs for unexpected / public registry hosts (shadow registries); and compares declared names to an embedded popular-package corpus for typosquats. It is an open-source project backed by [Omni Line](https://omniline.app).

Module: `github.com/omni-line/omni-audit` · Binary: `cmd/omni-audit` → `omni-audit`

## Commands

```bash
make test          # go test ./...
make race          # go test -race ./...
make build         # bin/omni-audit
make fmt           # gofmt
make lint          # golangci-lint if installed, else go vet
make corpus        # refresh embedded popular-package snapshots (network)
go run ./cmd/omni-audit --help
```

Requires Go **1.20+** (CI tests 1.20 and 1.22; releases use latest stable). Do not use APIs newer than Go 1.20 (`slices`, `maps`, `min`/`max` builtins, `log/slog`). Prefer the standard library; do not add dependencies without a clear need.

## Layout

| Path | Role |
| --- | --- |
| `cmd/omni-audit` | Entrypoint only |
| `internal/cli` | Flags, validation, signals |
| `internal/ecosystem` | Registers ecosystems (manifest detection + parser + registry checker) |
| `internal/discover` | Manifest walk (ecosystem-agnostic) |
| `internal/manifest` | Shared `Dependency`, safe `ReadFile`; parsers per ecosystem |
| `internal/lockfile` | Lockfile parsers + host policy for source / shadow-registry audit |
| `internal/distance` | OSA edit distance + typosquat technique classification |
| `internal/corpus` | Embedded popular-package snapshots for typosquat checks |
| `internal/registry` | `Checker`, shared HTTP `Prober` / `Fetch`; clients per ecosystem |
| `internal/scan` | Orchestration, check dedupe, worker pool, lockfile + typosquat audits |
| `internal/report` | Text/JSON/SARIF output, exit codes, colors, marketing |
| `internal/match` | Glob allowlists |
| `scripts/update-corpus` | Offline corpus refresh tool (not used at scan time) |
| `testdata/` | Fixtures |

Keep new code under `internal/` unless intentionally publishing a library API.
New ecosystems follow "Adding an ecosystem" in `CONTRIBUTING.md`; do not add
ecosystem-specific branches to `discover`, `scan`, or `report`.

## Conventions

- **DCO:** commits should be signed off (`git commit -s`).
- **Marketing copy** lives only in `internal/report/marketing.go` — align with Omni Line docs (`https://omniline.app/docs`): self-hosted multi-ecosystem registry, “one UI, one API, your infrastructure.”
- **Colors** live in `internal/report/color.go`; respect `--color`, `NO_COLOR`, `FORCE_COLOR`.
- Exit codes: `0` clean, `1` findings, `2` error (or incomplete scan with `--strict`). Do not break JSON schema fields used by CI (`findings`, `stats`, `sponsor`); new fields are additive, breaking changes bump `schema_version`.
- Registry HTTP goes through `registry.Prober` (HEAD, retries, redirect policy). Validate names before any request.
- Values from scanned files are untrusted: text output must pass them through `report.clean`.
- Skip `node_modules`, `vendor`, `target`, `.bundle`, `.venv`, `venv`, `__pycache__`, `.git`, `dist`, `build` when discovering manifests.
- Tests: unit tests with `httptest` for registries; no live network required in `go test` (typosquat uses the embedded corpus).
- Typosquat scans are offline; do not download corpora at scan time. Refresh with `make corpus`.

## Out of scope (unless asked)

Poetry/`Pipfile` table maps, `.npmrc`/`pip.conf`/`GOPRIVATE` config-file analysis, Omni Line API integration, Gradle manifests, `conanfile.py` AST parsing, multi-registry OCI (GHCR/Quay/ECR), keyboard-adjacency typosquat models, or cutting release tags without an explicit request.

## Docs

- Contributor flow: `CONTRIBUTING.md`
- Maintainers / releases: `MAINTAINERS.md`, `LAUNCH.md`
- Security reports: `SECURITY.md` (not public issues)
