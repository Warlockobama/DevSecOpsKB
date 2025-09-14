# Contributing

Thanks for your interest in contributing! We aim to keep contributions simple and low‑friction.

## Ground Rules
- Be respectful and constructive.
- Prefer small, focused PRs.
- Add or update docs when behavior changes.

## Developer Certificate of Origin (DCO)
This project uses the Developer Certificate of Origin (DCO) to certify contributions.
By contributing, you agree to the DCO 1.1. Sign your commits using `-s` or `--signoff`:

```
git commit -s -m "feat: add awesome thing"
```

The Signed‑off‑by trailer certifies the DCO terms in `DCO` at the repository root.

## Development
- Build and test the `zap-kb` module:
  - `cd zap-kb && go build ./... && go vet ./...`
  - `gofmt -s -w .` for formatting
- Keep generated artifacts out of git (see `.gitignore`).

## Pull Requests
- Include a clear description and rationale.
- Reference related issues when applicable.
- Ensure CI passes.

