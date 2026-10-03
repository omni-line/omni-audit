# Inferring flags from the repository

Every flag here changes what the scan reports. Propose each one with the evidence
that justifies it, and let the user accept or reject it. A flag without evidence is a
silenced finding.

## `--expected-host` (shadow registry)

Without it, only known public registry hosts are flagged. With it, any lockfile
resolution outside these hosts is a finding, which is what you want when the team uses
an internal proxy.

Evidence, in order of strength:

| Source | What to read |
| --- | --- |
| `.npmrc` (repo, then `~/.npmrc`) | `registry=` and `@scope:registry=` URLs |
| `.yarnrc.yml` | `npmRegistryServer`, `npmScopes.*.npmRegistryServer` |
| `pip.conf` / `pip.ini` / `PIP_INDEX_URL` | `index-url`, `extra-index-url` |
| `pyproject.toml` | `[[tool.poetry.source]]` / `[[tool.uv.index]]` URLs |
| `composer.json` | `repositories[].url` of type `composer` |
| Lockfiles | `resolved` / `dist.url` hosts that are not public registries |

Use the hostname only (`registry.example.com`), repeatable or comma-separated. If no
internal host is evidenced, leave the flag out; do not invent one.

## `--safe-namespace` (unclaimed names)

Matches are skipped entirely, so this is the most dangerous flag.

1. Collect candidates: npm scopes and Composer vendors of packages this repository
   publishes (`name` in `package.json` / `composer.json`, workspace packages), and
   scopes routed to a private registry in `.npmrc` / `.yarnrc.yml`.
2. Check each against the first scan's JSON: for findings in that namespace, read
   `namespace_status`.
   - `claimed`: the org owns the scope/vendor publicly. Safe to propose.
   - `unclaimed`: **do not propose it.** Tell the user anyone can register this scope
     and publish under it; the fix is to claim it on the public registry
     (npm organization, Packagist vendor), then re-scan.
   - `unknown`: the check failed. Rerun; do not propose until it resolves.
3. Propose globs as `'@acme/*,acme/*'`.

## `--exclude` (paths)

Propose directories that hold fake or intentionally broken manifests: `testdata`,
`fixtures`, `__fixtures__`, `examples`, `e2e/fixtures`. Evidence is a finding whose
`manifest` path sits under one of them. Never exclude application or service
directories to hide findings. The default walk already skips `node_modules`, `vendor`,
`target`, `.venv`, `dist`, `build`, and similar.

## `--allow` (typosquat near-misses)

Only for exact names the user confirms are intentional (an internal fork, a package
that is legitimately one edit from a popular name). Show the popular package it was
matched against. If it looks like a typo, the fix is the manifest, not the flag.

## Noise controls

- `--min-severity medium|high`: when low-severity scoped findings remain after claiming
  the namespace.
- `--distance 1`: when 2-edit typosquat matches are noisy on short names.
- `--timeout` / `--concurrency`: for flaky public registries. Keep `--strict` in CI so an
  incomplete scan never looks green.

Do not propose `--no-typosquat`, `--fail-on none` for the gate, or a broad `--ignore`
unless the user asks and accepts that those checks stop.
