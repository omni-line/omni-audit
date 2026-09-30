# Public launch checklist

Use this when cutting the first public release of Omni Audit.

## Before making the repo public

- [ ] `make test` and `make lint` pass on `main`
- [ ] README install / usage / exit codes reviewed
- [ ] `LICENSE` (MIT), `SECURITY.md`, `SUPPORT.md`, `MAINTAINERS.md` present
- [ ] GitHub Actions CI green on a test PR or push
- [ ] Homepage set to `https://omniline.app`
- [ ] Topics: `security`, `supply-chain`, `dependency-confusion`, `cli`, `npm`, `composer`, `golang`

## Publish

```bash
# After merging to main:
gh repo edit omni-line/omni-audit --visibility public --homepage https://omniline.app
gh repo edit omni-line/omni-audit --add-topic security --add-topic supply-chain \
  --add-topic dependency-confusion --add-topic cli --add-topic npm \
  --add-topic composer --add-topic golang

git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
# GoReleaser workflow creates GitHub Release artifacts
```

## After launch

- [ ] Verify release binaries download and `omni-audit --version` works
- [ ] Enable GitHub Security Advisories / private vulnerability reporting
- [ ] Optional: Discussions for Q&A
- [ ] Announce with link to https://omniline.app
