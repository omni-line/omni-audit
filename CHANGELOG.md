# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-09-30

### Added

- `--format sarif` (SARIF 2.1.0) for GitHub code scanning and security dashboards
- Findings include `line`, `group` (manifest section), `registry`, `url`, and `remediation`; JSON adds `schema_version`, `complete`, `stats.unique_packages`, `stats.duration_ms`, and `warnings[].kind`
- Text output: aligned findings table with clickable `path:line`, per-ecosystem "How to fix" guidance, scan duration, and an explicit "incomplete" state instead of a green check when checks failed
- `--strict` (exit 2 on an incomplete scan), `--exclude` path globs, `--retries`
- `-v` / `--verbose` now shows package URLs and all warnings (previously a no-op)
- PyPI: PEP 735 `[dependency-groups]`, `requirements/*.txt`, line continuations, inline comments
- npm: aliases (`npm:real-pkg@^1`) are checked under the real package name
- Scanning a single manifest file (`omni-audit path/to/package.json`)

### Changed

- Registry checks use `HEAD` (falling back to `GET`) instead of downloading full metadata — e.g. 15 MB less per check for `typescript` on npm
- Each distinct package name is checked once per ecosystem, however many manifests declare it
- Transient registry errors (429 / 5xx / network) are retried with exponential backoff and `Retry-After`
- A malformed or unreadable manifest is now a warning instead of aborting the whole scan
- Findings and warnings are sorted deterministically
- Default `--timeout` is now `10s`; `--concurrency`, `--retries`, and `--timeout` are range-checked; malformed globs are rejected
- `-h` exits 0; SIGINT/SIGTERM cancel in-flight checks
- Internal: new `ecosystem` package so adding a registry needs no changes to discovery, scanning, or reporting
- Release binaries are built with the latest stable Go (`-trimpath`, reproducible timestamps); CI tests Go 1.20 and 1.22 on Linux, macOS, and Windows with `-race`, and runs `govulncheck`

### Fixed

- Security: values from scanned manifests are escaped in text output (terminal escape / bidi injection)
- Security: symlinked manifests resolving outside the scan root are skipped; FIFOs/devices are refused; manifests are capped at 10 MiB
- Security: package names are validated before any request (e.g. an npm name of `..` resolved to the registry root and was reported as claimed); HTTPS→HTTP redirects are refused
- npm: `file:`, `workspace:`, `link:`, git, and `user/repo` specs are no longer reported (they never resolve from the registry)
- Packagist: packages with only dev branches (`~dev` metadata) are no longer reported as unclaimed
- PyPI: PEP 503 normalization (`.` and runs of separators), strings in inline tables (`{include-group = ...}`) or comments inside TOML arrays are no longer treated as dependencies, `[[array.tables]]` headers end the previous section
- An explicit scan root named `build`, `dist`, `vendor`, etc. is scanned instead of silently skipped
- Version banner no longer shows `vv` for `v`-prefixed versions; `go install …@vX` builds report their module version

## [0.2.0] — 2026-09-30

### Added

- PyPI support: scan `requirements*.txt` and PEP 621 `pyproject.toml`, check package names on https://pypi.org
- Skip Python virtualenv / cache dirs (`.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`)

## [0.1.0] — 2026-09-30

### Added

- Initial Omni Audit CLI: dependency confusion checks for NPM (`package.json`) and Composer (`composer.json`)
- Text and JSON output formats with CI-friendly exit codes
- `--safe-namespace` and `--ignore` globs
- Omni Line marketing footer / JSON `sponsor` (suppressible via `--no-marketing`, `-q`, or `OMNI_AUDIT_NO_MARKETING`)
- ANSI terminal colors (`--color auto|always|never`, respects `NO_COLOR` / `FORCE_COLOR`)
- OSS project docs, CI, and GoReleaser release workflow
- `AGENTS.md` for AI coding agents

### Notes

- Marketing copy aligned with Omni Line docs positioning (self-hosted multi-ecosystem registry; links to https://omniline.app/docs)
