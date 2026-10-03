# Omni Audit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml)
[![Powered by Omni Line](https://img.shields.io/badge/Powered%20by-Omni%20Line-FF4B4B?style=flat)](https://omniline.app/)

**Omni Audit** is a fast, zero-config CLI that scans your project for **dependency confusion**, **typosquatting**, and **shadow registry** risk. It discovers NPM, Composer, PyPI, Go, Cargo, RubyGems, Maven, Conan, and Docker Hub manifests, checks whether each declared name exists on the public registry, and reports names that are still **unclaimed**. It compares names to an embedded popular-package corpus for 1–2-edit near-misses, and audits lockfile resolution URLs that pull from public registries instead of your internal proxy.

Distributed as a **standalone Go binary**. No Node or PHP runtime required.

## The problem

If your team uses private packages alongside public registries (npmjs.com, Packagist, PyPI, crates.io, Maven Central, and others), a build can resolve a **malicious public package** that reuses an internal name. Omni Audit flags unclaimed public names before they are hijacked.

Attackers also publish packages whose names look like popular libraries (`react-domm`, `crossenv`). A single typo in a manifest can install malware. Omni Audit flags those near-misses offline against a high-download corpus.

Separately, developers often bypass the company registry proxy — a misconfigured `.npmrc`, or a lockfile copied from outside the org — so installs hit `registry.npmjs.org` / `pypi.org` directly and skip your security perimeter. Omni Audit flags those lockfile resolutions too.

Auditing is the first step. [Omni Line](https://omniline.app) is the durable fix: a self-hosted registry with Virtual Registries that route internal and external packages through one URL.

## Install

### Prebuilt binaries

Download the latest release from
[GitHub Releases](https://github.com/omni-line/omni-audit/releases).
See [SECURITY.md](SECURITY.md#verifying-releases) for cosign, attestation, and
checksum verification commands.

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

# Scan a single manifest
omni-audit ./services/billing/requirements.txt

# JSON for CI
omni-audit --format json --no-marketing

# SARIF for GitHub code scanning / security dashboards
omni-audit --format sarif > omni-audit.sarif

# Skip names you own and fixture directories
omni-audit --safe-namespace '@acme/*,acme/*' --exclude testdata,fixtures
```

Example text output (colors when the terminal supports them):

```text
omni-audit v0.7.0 — Dependency audit
Backed by Omni Line — one registry for every package your team ships

✗ 2 unclaimed package names found
✗ 1 suspected typosquat found
✗ Audit failed: 14 dependencies resolving outside your expected registry proxy

  SEVERITY  ECOSYSTEM  PACKAGE               VERSION  LOCATION                   SECTION              REASON
  critical  composer   acme/internal-sdk     ^1.0     composer.json:7            require              unclaimed
  critical  npm        @acme/internal-utils  1.0.0    package.json:5             dependencies         unclaimed
  critical  npm        crossenv              7.0.3    package.json:12            dependencies         typosquat
  high      npm        lodash                4.17.21  package-lock.json:842      registry.npmjs.org   shadow_registry

Anyone can publish these names on the public registry. If a build resolves
them there instead of your private source, it installs the publisher's code.

These names are 1–2 edits away from popular packages. A single typo in a
manifest can install malware that steals env vars and CI tokens.

These installs bypass your internal registry proxy and its security controls.
Lockfiles that embed public registry URLs pull directly from the internet.

How to fix
  composer  Register the vendor name on Packagist so nobody else can publish under it, ...
  npm       Claim the name (or its @scope as an npm organization) on npmjs.com, ...
  typosquat Confirm the package name is intentional. If it is a typo, correct it ...
  sources   Point the package manager at your internal registry proxy and regenerate the lockfile ...

Scanned 2 manifests · 1 lockfile · 8 packages · 14 resolved deps · 17 findings · 0 skipped · 0 errors in 412ms

───
Unclaimed names, typosquats, and lockfiles that bypass your proxy are supply-chain gaps.
Omni Line Virtual Registries give you one URL that routes internal and
external packages correctly — so developers cannot misconfigure the source.
One UI, one API, your infrastructure.
https://omniline.app  ·  docs: https://omniline.app/docs
```

## How it works

1. Walks the tree for supported manifests (skips `node_modules`, `vendor`, `target`, `.bundle`, `.venv`, `venv`, `__pycache__`, `.git`, `dist`, `build`, and other dependency/cache dirs, plus anything matched by `--exclude`)
2. Collects declared dependencies with their section and line number:
   - **npm**: `package.json` dependency sections; local/VCS specs skipped; aliases checked under the real name
   - **Composer**: `composer.json` `require` / `require-dev` (platform packages skipped)
   - **PyPI**: `requirements*.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 / PEP 735)
   - **Go**: `go.mod` `require` paths via `proxy.golang.org`
   - **Cargo**: `Cargo.toml` dependency tables (path/git/workspace skipped) via crates.io
   - **RubyGems**: `Gemfile` / `*.gemspec` via rubygems.org
   - **Maven**: `pom.xml` `groupId:artifactId` via Maven Central
   - **Conan**: `conanfile.txt` requires via ConanCenter
   - **Docker**: `Dockerfile` `FROM` and Compose `image:` refs via Docker Hub (unqualified / `docker.io` only)
3. Checks each distinct name once per ecosystem against its public registry (lightweight `HEAD` / search where needed), with retries and backoff
4. For npm scopes and Packagist vendors, also checks whether the **namespace** itself is claimed, and assigns severity (`critical` / `high` / `low`)
5. Reports names that return **404** as `reason=unclaimed`; checks that fail are warnings, never treated as clean
6. Compares each declared name to an embedded popular-package corpus (and to namespace peers) and reports 1–2-edit near-misses as `reason=typosquat` — offline, no network
7. Walks supported lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `poetry.lock`, `composer.lock`), extracts resolution URLs, and flags known public registry hosts (or any host outside `--expected-host`) as `reason=shadow_registry` — offline, no network

### Security properties

- Only package names are sent, and only to the public registries above (HTTPS, TLS 1.2+, no HTTPS→HTTP redirects). Names that are not valid for the registry are never sent. Lockfile source auditing and typosquat checks are offline (no network).
- Manifests and lockfiles are read with a 10 MiB cap; FIFOs/devices and symlinks that resolve outside the scan root are skipped.
- Values from scanned files are escaped before being printed, so a crafted manifest cannot inject terminal escape sequences.
- `HTTPS_PROXY` / `NO_PROXY` are honored for locked-down networks.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings (or `--fail-on none`) |
| `1` | One or more findings at or above `--min-severity` (`--fail-on any`, default) |
| `2` | Usage or runtime error, or an incomplete scan with `--strict` |

Without `--strict`, registry failures and unreadable manifests are reported as warnings and do not change the exit code. Use `--strict` in CI when an unverified package should block the pipeline. Use `--min-severity high` (or `critical`) to ignore low-severity scoped findings when the scope/vendor is already claimed.

### Flags

| Flag | Description |
| --- | --- |
| `--format text\|json\|sarif` | Output format (default `text`) |
| `--safe-namespace` | Globs for namespaces you own; matches are skipped (repeatable / comma-separated) |
| `--ignore` | Skip package name globs |
| `--allow` | Exact package names treated as safe for typosquat checks |
| `--expected-host` | Internal registry hostname or URL; lockfile resolutions outside these hosts are findings (repeatable / comma-separated). Without this flag, only known public registry hosts are flagged. |
| `--exclude` | Skip paths: directory/file names or globs relative to the scan root |
| `--no-typosquat` | Disable offline typosquat checks |
| `--distance` | Maximum edit distance for typosquat matches (`1` or `2`, default `2`) |
| `--scope` | Namespace to peer-check for typosquats (e.g. `@acme`; repeatable) |
| `--no-scope-peers` | Disable automatic namespace peer typosquat checks |
| `--strict` | Exit `2` if any manifest or package could not be verified |
| `--timeout` | Per-request timeout (default `10s`) |
| `--retries` | Retries for 429 / 5xx / network errors (default `2`, max `10`) |
| `--concurrency` | Parallel checks (default `16`, max `256`) |
| `--fail-on any\|none` | Whether findings fail the process |
| `--min-severity low\|medium\|high\|critical` | Minimum severity that exits `1` (default `low`) |
| `-q` / `--quiet` | Findings table only; no banner, warnings, summary, or marketing |
| `--no-marketing` | Hide Omni Line CTA / JSON `sponsor` |
| `--marketing` | Force marketing even when non-TTY |
| `--color auto\|always\|never` | ANSI colors (default `auto` on TTY) |
| `-v` / `--verbose` | Show package URLs and all warnings |
| `--version` | Print version |

### JSON output

```json
{
  "schema_version": 1,
  "version": "0.3.0",
  "complete": true,
  "findings": [
    {
      "ecosystem": "npm",
      "package": "@acme/internal-utils",
      "version": "1.0.0",
      "manifest": "package.json",
      "line": 5,
      "group": "dependencies",
      "reason": "unclaimed",
      "severity": "critical",
      "namespace": "acme",
      "namespace_status": "unclaimed",
      "registry": "registry.npmjs.org",
      "url": "https://www.npmjs.com/package/@acme/internal-utils",
      "remediation": "Claim the name (or its @scope as an npm organization) ..."
    }
  ],
  "stats": { "manifests": 1, "packages": 4, "unique_packages": 4, "findings": 1, "skipped": 0, "errors": 0, "duration_ms": 412 }
}
```

`complete` is `false` when any warning was raised (see `warnings[]`, each with a `kind` of `walk`, `manifest`, `registry`, or `namespace`). New fields may be added; breaking changes bump `schema_version`.

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
    ./omni-audit --format json --no-marketing --strict --safe-namespace '@your-org/*'
```

GitHub code scanning (findings appear as alerts with file/line annotations):

```yaml
- name: Dependency confusion audit
  run: ./omni-audit --format sarif --fail-on none > omni-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: omni-audit.sarif
```

Run from the repository root so SARIF paths are repository-relative.

## Roadmap

- `.npmrc` / `auth.json` / `pip.conf` / `GOPRIVATE` config-file policy analysis
- Optional Omni Line registry URL to verify private existence
- Poetry/`Pipfile` table-style dependency maps (requirements + PEP 621 covered today)
- Gradle manifests, `conanfile.py`, and non-Hub OCI registries (GHCR, Quay, ECR)

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
