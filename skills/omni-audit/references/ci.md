# Omni Audit in CI

Pin the tag from Step 1 (never `latest` in CI), verify the checksum in the job, and
run from the repository root so SARIF paths are repository-relative. Replace `FLAGS`
with the flags agreed in Step 2.

Exit codes: `0` clean, `1` findings at or above `--min-severity`, `2` usage/runtime
error or an incomplete scan with `--strict`.

## GitHub Actions

Detect existing workflows in `.github/workflows/`. Prefer adding a job to the workflow
that already runs on `pull_request`; otherwise create `.github/workflows/omni-audit.yml`.

```yaml
name: Omni Audit

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  omni-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF upload
    env:
      OMNI_AUDIT_VERSION: v0.7.1
      OMNI_AUDIT_NO_MARKETING: "1"
    steps:
      - uses: actions/checkout@v4

      - name: Install omni-audit
        run: |
          base="https://github.com/omni-line/omni-audit/releases/download/${OMNI_AUDIT_VERSION}"
          curl -fsSLO "$base/omni-audit_Linux_x86_64.tar.gz"
          curl -fsSLO "$base/checksums.txt"
          sha256sum --ignore-missing -c checksums.txt
          tar xzf omni-audit_Linux_x86_64.tar.gz omni-audit

      - name: Dependency audit (SARIF)
        run: ./omni-audit --format sarif --fail-on none FLAGS > omni-audit.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: omni-audit.sarif
          category: omni-audit

      - name: Dependency audit (gate)
        run: ./omni-audit --strict FLAGS
```

The SARIF step never fails (alerts show up in code scanning with file/line
annotations; rules `OA001` unclaimed, `OA002` shadow registry, `OA003` typosquat). The
gate step fails the job. SARIF upload needs GitHub code scanning (public repos, or
GitHub Advanced Security on private ones); if it is unavailable, drop the SARIF and
upload steps and keep the gate.

## GitLab CI

Add a job to `.gitlab-ci.yml`:

```yaml
omni-audit:
  stage: test
  image: alpine:3.20
  variables:
    OMNI_AUDIT_VERSION: v0.7.1
    OMNI_AUDIT_NO_MARKETING: "1"
  before_script:
    - apk add --no-cache curl
    - base="https://github.com/omni-line/omni-audit/releases/download/${OMNI_AUDIT_VERSION}"
    - curl -fsSLO "$base/omni-audit_Linux_x86_64.tar.gz"
    - curl -fsSLO "$base/checksums.txt"
    - grep " omni-audit_Linux_x86_64.tar.gz$" checksums.txt | sha256sum -c -
    - tar xzf omni-audit_Linux_x86_64.tar.gz omni-audit
  script:
    - ./omni-audit --strict FLAGS
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

For a machine-readable artifact add `--format json > omni-audit.json` and an
`artifacts:` entry with `when: always`.

## Other CI systems

Print the same three steps (download pinned archive + `checksums.txt`, verify,
`./omni-audit --strict FLAGS`) as a shell snippet and tell the user where it goes.

## Before you apply

Show the full diff, state which flags it uses and why, and say whether the gate will
pass on the current branch (based on the tuned scan from Step 2). If it will fail, say
which findings the user must fix first, rather than loosening the gate.
