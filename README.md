# Omni Audit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml)
[![Powered by Omni Line](https://img.shields.io/badge/Powered%20by-Omni%20Line-FF4B4B?style=flat)](https://omniline.app/)

**Omni Audit** is a fast, zero-config CLI that scans your project for **dependency confusion** risk. It discovers NPM, Composer, and PyPI manifests, checks whether each declared package name exists on the public registry, and reports names that are still **unclaimed** — names an attacker could publish.

Distributed as a **standalone Go binary**. No Node or PHP runtime required.

## The problem

If your team uses private packages alongside public registries (npmjs.com, Packagist), a build can resolve a **malicious public package** that reuses an internal name. Omni Audit flags unclaimed public names before they are hijacked.

Auditing is the first step. [Omni Line](https://omniline.app) is the durable fix: a self-hosted registry that routes internal packages correctly across ecosystems.

## Install

### Prebuilt binaries

Download the latest release from
[GitHub Releases](https://github.com/omni-line/omni-audit/releases).

### From source

Requires Go 1.20+:

```bash
go install github.com/omni-line/omni-audit/cmd/omni-audit@latest
```

Or clone and build:

```bash
git clone https://github.com/omni-line/omni-audit.git
cd omni-audit
make build
./bin/omni-audit --help
```

## Quick start

```bash
# Scan the current directory
omni-audit

# Scan a path
omni-audit ./apps/api

# JSON for CI
omni-audit --format json --no-marketing

# Suppress false positives for claimed org scopes
omni-audit --safe-namespace '@acme/*,acme/*'
```

Example text output (colors when the terminal supports them):

```text
omni-audit v0.1.0 — Dependency confusion audit
Backed by Omni Line — one registry for every package your team ships

[!] npm @acme/internal-utils (1.0.0) in package.json — reason=unclaimed
[!] composer acme/internal-sdk (^1.0) in composer.json — reason=unclaimed

Scanned 2 manifest(s), 8 package(s): 2 finding(s), 0 skipped, 0 error(s)

───
Unclaimed names can be published by anyone on the public registry.
Prevent confusion at install time with Omni Line — a self-hosted package
registry for npm, Composer, Docker, PyPI, Go, Cargo, Maven, and more.
One UI, one API, your infrastructure.
https://omniline.app  ·  docs: https://omniline.app/docs
```

## How it works

1. Walks the tree for `package.json`, `composer.json`, `requirements*.txt`, and `pyproject.toml` (skips `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, `.git`, `dist`, `build`)
2. Collects declared dependencies (NPM: `dependencies` / `devDependencies` / `optionalDependencies` / `peerDependencies`; Composer: `require` / `require-dev`, skipping `php` and `ext-*` / `lib-*`; PyPI: requirements lines and PEP 621 `[project]` / optional-dependencies)
3. Concurrently queries the public npm registry, Packagist, and PyPI
4. Reports packages that return **404** as `reason=unclaimed`

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings (or `--fail-on none`) |
| `1` | One or more findings (`--fail-on any`, default) |
| `2` | Usage or runtime error |

### Flags

| Flag | Description |
| --- | --- |
| `--format text\|json` | Output format (default `text`) |
| `--safe-namespace` | Glob allowlist (repeatable / comma-separated) |
| `--ignore` | Skip package name globs |
| `--timeout` | Per-request timeout (default `5s`) |
| `--concurrency` | Parallel checks (default `16`) |
| `--fail-on any\|none` | Whether findings fail the process |
| `-q` / `--quiet` | Findings only; no banner or marketing |
| `--no-marketing` | Hide Omni Line CTA / JSON `sponsor` |
| `--marketing` | Force marketing even when non-TTY |
| `--color auto\|always\|never` | ANSI colors (default `auto` on TTY) |
| `-v` / `--verbose` | Extra detail |
| `--version` | Print version |

Environment:

- `OMNI_AUDIT_NO_MARKETING=1` — same as `--no-marketing` (handy in CI)
- `NO_COLOR=1` — disable colors ([no-color.org](https://no-color.org))
- `FORCE_COLOR=1` — enable colors when not a TTY

JSON includes an optional top-level `sponsor` object by default. Use `--no-marketing` or `-q` for a silent machine payload.

## CI example

```yaml
- name: Dependency confusion audit
  run: |
    curl -sL https://github.com/omni-line/omni-audit/releases/latest/download/omni-audit_Linux_x86_64.tar.gz | tar xz
    ./omni-audit --format json --no-marketing --safe-namespace '@your-org/*'
```

## Roadmap (not in v1)

- Additional ecosystems (Maven, Cargo, Go modules)
- Lockfile / `.npmrc` / `auth.json` / `pip.conf` policy analysis
- Optional Omni Line registry URL to verify private existence
- Poetry/`Pipfile` table-style dependency maps (requirements + PEP 621 covered today)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [MAINTAINERS.md](MAINTAINERS.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) · Copyright Omni Line and contributors · See [NOTICE](NOTICE).

---

<div align="center">
  <a href="https://omniline.app/">
    <img src="https://omniline.app/omni-line-icon.png" alt="Omni Line" width="120">
  </a>
  <p><b>Omni Audit</b> is built and maintained by <a href="https://omniline.app/"><b>Omni Line</b></a> — one self-hosted registry for every package your team ships.</p>
</div>
