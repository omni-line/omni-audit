# Contributing to Omni Audit

Thanks for helping improve Omni Audit. This guide covers local setup, how we
review changes, and the Developer Certificate of Origin (DCO).

## Prerequisites

- Go **1.20+** (CI tests 1.20 and 1.22; releases build with the latest stable Go)
- `make` (optional but recommended)
- `golangci-lint` for local linting (CI installs it)

## Setup

```bash
git clone git@github.com:omni-line/omni-audit.git
cd omni-audit
make test
make build
./bin/omni-audit --help
```

## Development workflow

1. Open an issue (or claim an existing one) before large changes.
2. Create a branch from `main`.
3. Keep PRs focused: one concern per PR when practical.
4. Add or update tests for behavior changes.
5. Run:

```bash
make fmt
make lint
make race
```

6. Open a pull request using the template. Fill in the checklist.

### Commit messages

Prefer short, imperative subjects that explain *why*:

```text
scan: skip php and ext-* composer platform deps
```

### Developer Certificate of Origin (DCO)

By contributing, you certify that you have the right to submit the work under
the MIT license. Sign off each commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by:` trailer. See https://developercertificate.org/.

## Project layout

| Path | Role |
| --- | --- |
| `cmd/omni-audit` | CLI entrypoint |
| `internal/cli` | Flags, validation, signal handling |
| `internal/ecosystem` | Binds each manifest format to its registry (the only place ecosystems are registered) |
| `internal/discover` | Manifest discovery (ecosystem-agnostic) |
| `internal/manifest` | Shared `Dependency` type, safe file reads; parsers per ecosystem |
| `internal/lockfile` | Lockfile parsers and host policy for source / shadow-registry auditing |
| `internal/registry` | `Checker` interface and the shared HTTP `Prober` (HEAD/Fetch, retries, redirects); clients per ecosystem |
| `internal/scan` | Orchestration: dedupes checks, runs the worker pool, lockfile source audit |
| `internal/report` | Text / JSON / SARIF output, exit codes, marketing |
| `testdata` | Fixtures |

## Adding an ecosystem

Discovery, scanning, and reporting do not know about specific ecosystems. To
add one (for example Cargo):

1. **Parser** — `internal/manifest/cargo`: return `[]manifest.Dependency` with
   `Name`, `Version`, `Group` (manifest section), and `Line` when known. Drop
   dependencies that do not resolve through the public registry (path, git).
2. **Registry client** — `internal/registry/cargo`: validate the name locally
   (never send invalid names over the network), build the URL, and call
   `Prober.Probe`. Export `Normalize` if the registry treats names
   case- or separator-insensitively, and `PackageURL` for the public page.
3. **Wiring** — `internal/ecosystem/cargo.go`: one constructor returning an
   `Ecosystem{...}` with `IsManifest`, `Parse`, `Normalize`, `PackageURL`,
   `Remediation`, and `Checker`; add it to `Default`.
4. **Tests** — parser table tests, a registry test with `httptest` (no live
   network), and a manifest-detection case in `ecosystem_test.go`.

The `ecosystem` JSON value you choose becomes part of the output schema; do not
rename it later.

## Code style

- Prefer the standard library; avoid new dependencies unless justified.
- Keep packages under `internal/` unless we intentionally publish a library API.
- User-facing marketing copy lives only in `internal/report/marketing.go`.

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Questions

- Bugs and features: GitHub Issues
- Usage help: [SUPPORT.md](SUPPORT.md)
- Commercial / Omni Line product: https://omniline.app
