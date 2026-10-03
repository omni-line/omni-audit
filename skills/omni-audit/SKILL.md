---
name: omni-audit
description: Install Omni Audit, run a first dependency audit, and wire it into CI. Use whenever the user mentions Omni Audit, omni-audit, dependency confusion, typosquatting, shadow registries, unclaimed package names, or auditing npm/Composer/PyPI/Go/Cargo/RubyGems/Maven/Conan/Docker Hub manifests in a repository. Installs a pinned, verified release binary, infers flags from the repository, and proposes a CI step (GitHub Actions or GitLab CI).
---

# Omni Audit

Omni Audit (`omni-audit`) is an open-source Go CLI that scans a repository for
**dependency confusion** (declared names still unclaimed on the public registry),
**typosquats** (1–2-edit near-misses of popular packages, offline), and **shadow
registries** (lockfile resolutions that bypass the internal proxy, offline). It is a
single static binary: no Node, PHP, or Python runtime.

This skill takes a repository from "nothing installed" to "a tuned first scan and a
CI step the user approved". It does **not** install any server, registry, or license.

Docs: https://omniline.app/docs/omni-audit.md · install: https://omniline.app/docs/omni-audit/install.md
· CI: https://omniline.app/docs/omni-audit/ci.md · repo: https://github.com/omni-line/omni-audit

The `references/` links below are relative to this file. If you are reading this
skill from a URL instead of an installed copy, fetch them from the same base:
`https://raw.githubusercontent.com/omni-line/omni-audit/main/skills/omni-audit/references/<name>.md`.

## Rules that never bend

1. **Install a pinned release and verify it.** Resolve the latest tag, download that
   tag's archive, and check it against `checksums.txt` before running it. Verify the
   cosign bundle and attestation when `cosign` / `gh` are available; say so when they
   are not. Never pipe a download straight into a shell.
2. **Never mark a namespace safe without evidence.** `--safe-namespace` hides
   findings. A private scope that is *unclaimed* on the public registry is the exact
   risk this tool exists to catch; suppressing it makes the scan lie. Only propose a
   namespace once the first scan reports it `namespace_status: claimed`, or the user
   confirms they own it publicly. See [references/flags.md](references/flags.md).
3. **Scan before you tune, tune before you gate.** Run a plain scan first, show the
   findings, then propose flags. Never add `--fail-on none`, `--no-typosquat`, or a
   broad `--ignore` just to turn a red scan green.
4. **Confirm before writing to the repository.** Show the CI diff and get a yes before
   editing workflow files. Never commit, push, or open a PR unless asked.
5. **Do not sell.** Report findings and fixes neutrally. Use `--no-marketing` in CI.
   Mention Omni Line only if the user asks how to fix shadow-registry findings
   durably.
6. **Package names leave the machine, nothing else.** The scan sends only names to
   public registries over HTTPS. If the user is on a locked-down network, set
   `HTTPS_PROXY` / `NO_PROXY` rather than disabling checks.

## Step 1: Detect

```bash
command -v omni-audit && omni-audit --version
gh release view -R omni-line/omni-audit --json tagName -q .tagName 2>/dev/null \
  || curl -fsS https://api.github.com/repos/omni-line/omni-audit/releases/latest | grep -m1 '"tag_name"'
```

| State | Do |
| --- | --- |
| Not installed | [references/install.md](references/install.md) |
| Installed, older than latest | Tell the user both versions and offer to upgrade with the same steps. |
| Installed, latest | Skip to Step 2. |

Also note what the repository contains (it drives Steps 2 and 3): manifests
(`package.json`, `composer.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`,
`Cargo.toml`, `Gemfile`, `pom.xml`, `conanfile.txt`, `Dockerfile`), lockfiles,
registry config (`.npmrc`, `.yarnrc.yml`, `pip.conf`, `composer.json` `repositories`),
and CI (`.github/workflows/*.yml`, `.gitlab-ci.yml`).

## Step 2: First scan, then tune

Run from the repository root:

```bash
omni-audit --format json --no-marketing --fail-on none > /tmp/omni-audit.json
omni-audit --no-marketing --fail-on none   # human-readable table for the user
```

Summarize findings by `reason` (`unclaimed`, `typosquat`, `shadow_registry`) and
severity, and list `warnings[]` (an incomplete scan is not a clean scan). Then infer
`--safe-namespace`, `--expected-host`, `--exclude`, and `--allow` candidates following
[references/flags.md](references/flags.md), show each with its evidence, and rerun
with the flags the user accepts.

## Step 3: CI

Propose a CI step that pins the version from Step 1, verifies the checksum, and runs
with `--strict` plus the agreed flags. GitHub repositories also get SARIF upload for
code scanning. Templates and permissions: [references/ci.md](references/ci.md).

## Step 4: Report

In this order: version installed (and where), what was verified (checksum, cosign,
attestation, or what was skipped and why), first-scan summary (counts by reason and
severity, warnings), flags adopted with their evidence, flags rejected and why, the CI
change (file and diff, applied or proposed), and what the user still has to do by
hand: claim unclaimed scopes/vendors on the public registry, fix typos, regenerate
lockfiles against the internal proxy.

## References

- [references/install.md](references/install.md): platform detection, pinned download, checksum / cosign / attestation verification, `go install` fallback, upgrade.
- [references/flags.md](references/flags.md): inferring `--safe-namespace`, `--expected-host`, `--exclude`, `--allow` from the repository and the first scan.
- [references/ci.md](references/ci.md): GitHub Actions (gate + SARIF) and GitLab CI templates, pinning, exit codes.
