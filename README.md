# Omni Audit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/omni-line/omni-audit/actions/workflows/ci.yml)
[![Powered by Omni Line](https://img.shields.io/badge/Powered%20by-Omni%20Line-FF4B4B?style=flat)](https://omniline.app/)

**Omni Audit** is a fast, zero-config CLI that scans your project for **dependency confusion**, **typosquatting**, **known malicious packages**, **shadow registry** risk, **risky registry settings**, and **install-time payloads**. It discovers NPM, Composer, PyPI, Go, Cargo, RubyGems, Maven, Conan, and Docker Hub manifests, checks whether each declared name exists on the public registry, and reports names that are still **unclaimed**. It compares names to an embedded popular-package corpus for 1–2-edit near-misses, checks names and locked versions against the OpenSSF malicious-packages database, audits lockfile resolution URLs that pull from public registries instead of your internal proxy, and audits package-manager config files (`.npmrc`, `pip.conf`, `composer.json`, `Gemfile`, Dockerfiles, CI pipelines, …) for settings that let a public package replace an internal one.

Distributed as a **standalone Go binary**. No Node or PHP runtime required.

Every check, flag, and output field is documented in the [wiki](https://github.com/omni-line/omni-audit/wiki).

## The problem

If your team uses private packages alongside public registries (npmjs.com, Packagist, PyPI, crates.io, Maven Central, and others), a build can resolve a **malicious public package** that reuses an internal name. Omni Audit flags unclaimed public names before they are hijacked.

Attackers also publish packages whose names look like popular libraries (`react-domm`, `crossenv`). A single typo in a manifest can install malware. Omni Audit flags those near-misses offline against a high-download corpus.

Some packages need no typo at all: they were published as malware outright, or a legitimate package (`nx`, `chalk`, `axios`) shipped malicious releases from a hijacked maintainer account. Omni Audit checks every declared name and locked version against the 239k OpenSSF malicious-packages (`MAL-`) advisories, offline, using the database from [mal-check](https://github.com/omni-line/mal-check).

Separately, developers often bypass the company registry proxy — a misconfigured `.npmrc`, or a lockfile copied from outside the org — so installs hit `registry.npmjs.org` / `pypi.org` directly and skip your security perimeter. Omni Audit flags those lockfile resolutions too.

Often the cause is one line of configuration. `pip install --extra-index-url` asks every index and installs the **highest version** it finds, so a public upload of your internal name with version `99.0` wins; that is how the 2022 `torchtriton` compromise reached PyTorch nightly users. Composer repositories marked `"canonical": false`, a Gemfile with two global `source` lines, and uv's `unsafe-best-match` index strategy open the same door. Omni Audit flags those settings, plus registry tokens committed in plain text and registries reached over plain HTTP, offline.

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

### With an AI agent

Paste this into Claude Code, Codex, or Cursor at the repository root:

```text
Read https://raw.githubusercontent.com/omni-line/omni-audit/main/skills/omni-audit/SKILL.md and follow it to set up Omni Audit for this repository.
```

The agent installs a pinned, checksum-verified release, runs a first scan, proposes
flags from what it finds in the repo, and drafts a CI step for you to approve.

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

# Ask whether a name is safe before adding it
omni-audit check --ecosystem npm --agent crossenv

# Compact JSON for an agent, ignoring findings already accepted
omni-audit --agent --baseline .omni-audit-baseline.json

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
8. Audits package-manager configuration files and reports risky settings as `reason=registry_config`, with the risk in `kind` (offline, no network; table below)
9. Checks every lockfile resolution and every declared dependency against an embedded snapshot of [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) (`MAL-` advisories, via [mal-check](https://github.com/omni-line/mal-check)'s `pkg/maldb`) and reports matches as `reason=malicious`: `critical` when the locked version (or every version) is malware, `high` when only some versions are and the declaration is not pinned. Lockfile versions win over manifest ranges; clean versions of once-hijacked packages are not reported — offline, no network
10. Audits install-time code already in the tree and reports it as `reason=install_hook` (offline, no network; nothing is executed). Project files are always scanned: npm lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) and the one local file they invoke, plus `setup.py`, `*.pth`, and `binding.gyp`. A hit requires a payload pattern, not merely the presence of a script. `--installed` also walks `node_modules` and virtualenvs (`.venv`, `venv`, `site-packages`), which the default walk skips, and compares each installed npm package to the nearest `package-lock.json`, `npm-shrinkwrap.json`, or `yarn.lock`. Disable with `--no-install-hook`

#### Install-hook patterns

| `kind` | Severity | What it flags |
| --- | --- | --- |
| `shell_exec` | high | `curl`, `wget`, `certutil`, `bash -c` / `sh -c`, a pipe into a shell, PowerShell, or `cmd /c`, in a script that runs at install (or next to an exec API in a source file) |
| `decode_exec` | high | `eval` / `exec` / `Function` next to `base64`, `atob`, or `Buffer.from` |
| `credential_exfil` | high | a credential path (`.npmrc`, `.ssh`, `.aws`, `.env`, `id_rsa`) or a named token (`NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, …) next to a network call. `process.env` alone is not a credential |
| `version_mismatch` | high | `--installed` only. The installed npm version is not the version in the nearest lockfile |
| `not_in_lockfile` | high | `--installed` only. The installed npm package is not named by the nearest lockfile |

Findings quote the pattern, never the script body. `--ignore` skips a package name; `--safe-namespace` does not, because a namespace you own can still ship a malicious install script. A bare lifecycle script (`node-gyp rebuild`, `husky`) is not a finding.

#### Registry configuration checks

| `kind` | Severity | Flagged in |
| --- | --- | --- |
| `extra_index` | high | `--extra-index-url` / `extra-index-url` / `PIP_EXTRA_INDEX_URL` in `pip.conf`, `pip.ini`, requirements and constraints files, Dockerfiles, CI pipelines (`.github/workflows`, `.gitlab-ci.yml`, CircleCI, Bitbucket, Azure, `Jenkinsfile`), `Makefile`, `*.sh`; `install_search_all_sources = true` in a `Pipfile`. `uv pip install --extra-index-url` is not flagged: uv's default `first-index` strategy is not affected |
| `unsafe_index_strategy` | high | uv `index-strategy = "unsafe-…"` in `pyproject.toml` / `uv.toml`, `--index-strategy unsafe-…`, `UV_INDEX_STRATEGY=unsafe-…` |
| `non_canonical_repository` | high | `composer.json` repositories with `"canonical": false` |
| `multiple_global_sources` | high | a `Gemfile` / `gems.rb` with more than one global `source` (block sources are fine) |
| `plaintext_credential` | high | literal tokens and passwords in `.npmrc`, `.yarnrc.yml`, Composer `auth.json`, `.cargo/config.toml` / `credentials.toml`, Maven `settings.xml`, and registry URLs (`https://user:pass@…`). `${VAR}` references, Maven-encrypted `{…}` passwords, and files excluded by a `.gitignore` are not flagged |
| `insecure_transport` | medium | plain-HTTP registry URLs (loopback hosts excepted), `strict-ssl=false`, `enableStrictSsl: false`, `unsafeHttpWhitelist`, `--trusted-host`, `verify_ssl = false`, `"secure-http": false` |

Secret values are never printed or written to JSON/SARIF; URLs are redacted (`https://deploy:xxxxx@…`). Go has no file-level equivalent (`GOPRIVATE` lives in the environment), so it is not covered.

### Security properties

- Only package names are sent, and only to the public registries above (HTTPS, TLS 1.2+, no HTTPS→HTTP redirects). Names that are not valid for the registry are never sent. Lockfile source auditing, typosquat, malicious-package, registry configuration, and install-hook checks are offline (no network). Install hooks are read, never executed.
- Manifests and lockfiles are read with a 10 MiB cap; FIFOs/devices and symlinks that resolve outside the scan root are skipped.
- Values from scanned files are escaped before being printed, so a crafted manifest cannot inject terminal escape sequences.
- `HTTPS_PROXY` / `NO_PROXY` are honored for locked-down networks.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings (or `--fail-on none`) |
| `1` | One or more findings at or above `--min-severity` (`--fail-on any`, default) |
| `2` | Usage or runtime error, an incomplete scan with `--strict`, or a failed `check` lookup |

`check` uses the same codes: `0` allow, `1` block, `2` the registry lookup failed or the arguments are invalid. A failed lookup is never a clean name, including with `--fail-on none`.

Without `--strict`, registry failures and unreadable manifests are reported as warnings and do not change the exit code. Use `--strict` in CI when an unverified package should block the pipeline. Use `--min-severity high` (or `critical`) to ignore low-severity scoped findings when the scope/vendor is already claimed.

### Flags

| Flag | Description |
| --- | --- |
| `--format text\|json\|sarif` | Output format (default `text`) |
| `--agent` | Compact JSON for agents: no marketing, plus `decision` (`allow` / `block` / `unknown`) and `actions`. Do not combine with `--format text` or `--format sarif` |
| `--baseline` | Hide findings whose `fingerprint` appears in a previous JSON report, or in `{"fingerprints":[...]}`. The report lists only what remains; keep the baseline file |
| `check --ecosystem` | With the `check` command: ecosystem of the names to look up (`npm`, `composer`, `pypi`, `go`, `cargo`, `rubygems`, `maven`, `conan`, `docker`) |
| `--safe-namespace` | Globs for namespaces you own; matches are skipped (repeatable / comma-separated) |
| `--ignore` | Skip package name globs |
| `--allow` | Exact package names treated as safe for typosquat checks |
| `--expected-host` | Internal registry hostname or URL; lockfile resolutions outside these hosts are findings (repeatable / comma-separated). Without this flag, only known public registry hosts are flagged. |
| `--exclude` | Skip paths: directory/file names or globs relative to the scan root |
| `--only` | Run only these checks: `unclaimed`, `shadow_registry`, `typosquat`, `malicious`, `registry_config`, `install_hook` (repeatable / comma-separated; the same names as `reason`). `--only malicious,typosquat,registry_config,install_hook` makes no network requests |
| `--no-unclaimed` | Disable the public-registry checks for unclaimed names (the only check that uses the network) |
| `--no-sources` | Disable the lockfile audit for resolutions outside the expected registry hosts (lockfiles are still read for the malicious-package check) |
| `--no-typosquat` | Disable offline typosquat checks |
| `--no-malicious` | Disable the offline known-malicious-package check |
| `--no-registry-config` | Disable the offline audit of package-manager config files |
| `--no-install-hook` | Disable the offline install-hook audit |
| `--installed` | Also scan `node_modules` and virtualenvs for install hooks, and flag npm packages whose name or version is not in the nearest lockfile |
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
      "id": "OA001",
      "fingerprint": "6a3565302a9133a7fc65b76b818a5d11",
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

`complete` is `false` when any warning was raised (see `warnings[]`, each with a `kind` of `walk`, `manifest`, `registry`, `namespace`, `lockfile`, `config`, or `installed`). `checks` lists the checks that ran. `id` is the SARIF rule (`OA001` unclaimed, `OA002` shadow registry, `OA003` typosquat, `OA004` malicious, `OA005` registry config, `OA006` install hook). `fingerprint` ignores the dependency version and line number, so `--baseline` still matches after a constraint bump in the same file. New fields may be added; breaking changes bump `schema_version`.

### For agents

`check` does not walk a tree. Pass the package name, not a version spec:

```bash
omni-audit check --ecosystem npm --agent crossenv
```

```json
{
  "schema_version": 1,
  "decision": "block",
  "findings": [
    {
      "id": "OA003",
      "ecosystem": "npm",
      "package": "crossenv",
      "reason": "typosquat",
      "severity": "critical",
      "distance": 1,
      "suggestions": ["cross-env"]
    }
  ],
  "actions": [
    {
      "type": "rename",
      "ecosystem": "npm",
      "package": "crossenv",
      "replacement": "cross-env",
      "confidence": "high"
    }
  ]
}
```

`decision` is `allow` (claimed, not a typosquat at or above `--min-severity`, and not known malware), `block` (act on the findings), or `unknown` (the lookup failed; do not add the name). A `rename` action is included only when a typosquat has one suggestion at edit distance 1. Unclaimed names and known malware have no rename: claim the name on the registry, or remove the package.

`--agent` on a tree scan uses the same compact document. `--baseline .omni-audit-baseline.json` drops findings already listed in that report. `stats.suppressed` counts how many were hidden. The output contains only the findings that remain, so keep the baseline file instead of replacing it with the filtered report.

Environment:

- `OMNI_AUDIT_NO_MARKETING=1` — same as `--no-marketing` (handy in CI)
- `NO_COLOR=1` — disable colors ([no-color.org](https://no-color.org))
- `FORCE_COLOR=1` — enable colors when not a TTY

JSON includes an optional top-level `sponsor` object by default. Use `--no-marketing` or `-q` for a silent machine payload.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: omni-line/omni-audit@v0.10.0
  with:
    args: --safe-namespace '@your-org/*' --strict
```

The action downloads the release binary for the runner (Linux, macOS, or
Windows; x64 or arm64), verifies it against `checksums.txt`, and runs it. It
fails the step on findings, like the CLI.

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory or manifest to scan |
| `args` | | Extra flags, parsed like a shell command line |
| `version` | the action's tag | Release to run; the latest release when the action is used at a branch or SHA |
| `sarif` | `false` | Write SARIF to `sarif-file` instead of text to the log |
| `sarif-file` | `omni-audit.sarif` | SARIF output path |

Outputs: `exit-code` and `sarif-file`. For GitHub code scanning:

```yaml
- uses: omni-line/omni-audit@v0.10.0
  with:
    sarif: true
    args: --fail-on none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: omni-audit.sarif
```

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

- Scope-aware `.npmrc` policy (internal `@scope` without a `@scope:registry` mapping)
- Optional Omni Line registry URL to verify private existence
- Poetry/`Pipfile` table-style dependency maps (requirements + PEP 621 covered today)
- Gradle manifests, `conanfile.py`, and non-Hub OCI registries (GHCR, Quay, ECR)
- Malicious-package checks for `pnpm-lock.yaml`, `Gemfile.lock`, `Cargo.lock`, and NuGet lockfiles (use [mal-check](https://github.com/omni-line/mal-check) for those today)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [MAINTAINERS.md](MAINTAINERS.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) · Copyright Omni Line and contributors · See [NOTICE](NOTICE).
The embedded malicious-package database is derived from [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [Apache-2.0](LICENSES/Apache-2.0.txt).

---

<div align="center">
  <a href="https://omniline.app/">
    <img src="https://omniline.app/omni-line-icon.png" alt="Omni Line" width="120">
  </a>
  <p><b>Omni Audit</b> is built and maintained by <a href="https://omniline.app/"><b>Omni Line</b></a> — one self-hosted registry for every package your team ships.</p>
</div>
