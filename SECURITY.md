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

## Scope notes

Omni Audit queries public package registries over HTTPS. Findings about
*unclaimed* package names are informational risk signals, not proof of an
active compromise. Misconfiguration of private registries in your environment
is out of scope for this project's security process unless it stems from a bug
in Omni Audit itself.
