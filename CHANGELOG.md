# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
