# Install Omni Audit

## Platform

Release archives are named `omni-audit_<Os>_<Arch>.<ext>`:

| `uname -s` / `uname -m` | Archive |
| --- | --- |
| Linux / x86_64 | `omni-audit_Linux_x86_64.tar.gz` |
| Linux / aarch64, arm64 | `omni-audit_Linux_arm64.tar.gz` |
| Darwin / x86_64 | `omni-audit_Darwin_x86_64.tar.gz` |
| Darwin / arm64 | `omni-audit_Darwin_arm64.tar.gz` |
| Windows / x86_64 | `omni-audit_Windows_x86_64.zip` |

There is no Windows arm64 build; use `go install` there (see below).

## Download and verify

```bash
VERSION=v0.7.1   # the tag resolved in Step 1 of SKILL.md
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$ARCH" in aarch64|arm64) ARCH=arm64 ;; x86_64|amd64) ARCH=x86_64 ;; esac
ARCHIVE="omni-audit_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/omni-line/omni-audit/releases/download/${VERSION}"

WORK="$(mktemp -d)"; cd "$WORK"
curl -fsSLO "$BASE/$ARCHIVE"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sigstore.json"

# Required: archive matches the published checksum
(sha256sum --ignore-missing -c checksums.txt 2>/dev/null || shasum -a 256 --ignore-missing -c checksums.txt)
```

Then, when the tools exist on the host (say which ones ran in the final report):

```bash
# Cosign keyless signature over checksums.txt
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/omni-line/omni-audit/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# GitHub build provenance
gh attestation verify "$ARCHIVE" -R omni-line/omni-audit
```

If the checksum fails, stop and report it. Do not retry with `latest` or another
mirror.

## Place the binary

```bash
tar xzf "$ARCHIVE" omni-audit
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR" && install -m 0755 omni-audit "$BIN_DIR/omni-audit"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "add $BIN_DIR to PATH" ;; esac
omni-audit --version
```

Prefer a user bin dir over `/usr/local/bin` (no `sudo`). Do not drop the binary inside
the repository being scanned. On Windows, extract the `.zip` into a directory on
`PATH` (for example `%USERPROFILE%\bin`).

## Fallback: from source

Requires Go 1.20+. Pin the same tag:

```bash
go install github.com/omni-line/omni-audit/cmd/omni-audit@v0.7.1
```

This builds from the module proxy; there is no release checksum or cosign bundle to
verify, so say that in the report.

## Upgrade

Same steps with the newer tag; `install` overwrites the old binary in place. Read the
release notes (`gh release view <tag> -R omni-line/omni-audit`) and call out new
checks or flags that may change CI results.
