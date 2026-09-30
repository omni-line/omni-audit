# Contributing to Omni Audit

Thanks for helping improve Omni Audit. This guide covers local setup, how we
review changes, and the Developer Certificate of Origin (DCO).

## Prerequisites

- Go **1.20+** (CI uses Go 1.22)
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
make test
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
| `internal/discover` | Manifest discovery |
| `internal/manifest` | NPM / Composer parsers |
| `internal/registry` | Public registry clients |
| `internal/scan` | Orchestration |
| `internal/report` | Text / JSON output and marketing |
| `testdata` | Fixtures |

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
