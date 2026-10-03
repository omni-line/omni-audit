# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| latest release on `main` / newest `v*` tag | Yes |
| older releases | Best effort only |

## Reporting a vulnerability

**Do not file a public GitHub issue** for security vulnerabilities in Omni Audit.

Please report privately via one of:

1. [GitHub Security Advisories](https://github.com/omni-line/omni-audit/security/advisories/new) (preferred)
2. Email: **security@omniline.app**

Include:

- A description of the issue and impact
- Steps to reproduce or a proof of concept if available
- Affected versions / commit if known

We will acknowledge receipt within a few business days and coordinate a fix and
disclosure timeline. Please give us reasonable time before any public disclosure.

## Verifying releases

Release binaries are built with GoReleaser. Each tag publishes archives,
`checksums.txt`, a Sigstore cosign bundle for the checksums file, SPDX SBOMs
(`*.sbom.json`), and GitHub build provenance attestations.

```bash
# Replace VERSION and the archive name as needed.
VERSION=v0.5.0
ARCHIVE=omni-audit_Linux_x86_64.tar.gz

gh release download "$VERSION" -R omni-line/omni-audit -p "$ARCHIVE" -p checksums.txt -p checksums.txt.sigstore.json

# Build provenance (GitHub Attestations)
gh attestation verify "$ARCHIVE" -R omni-line/omni-audit

# Cosign keyless signature over checksums.txt
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/omni-line/omni-audit/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
```

## Scope notes

Omni Audit queries public package registries over HTTPS. Findings about
*unclaimed* package names are informational risk signals, not proof of an
active compromise. Misconfiguration of private registries in your environment
is out of scope for this project's security process unless it stems from a bug
in Omni Audit itself.
