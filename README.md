# DevSecOps KB (Monorepo)

This repository hosts the DevSecOps KB. It is a gradual, tool-agnostic knowledge base designed to normalize and publish security findings across tools. The first module is `zap-kb`, which focuses on OWASP ZAP.

## Structure
- `zap-kb/`: ZAP module (Go). Fetches alerts, normalizes to an entities model, and can publish an Obsidian vault.
- Other modules can be added alongside over time (e.g., Burp, SAST, SBOM importers).
 - `archive/`: Legacy experiments and prior folder attempts consolidated to keep the root clean. Safe to delete if not needed.

## Getting Started (zap-kb)
See `zap-kb/README.md` for usage, flags, and examples. A GitHub Actions workflow is provided to build/vet the module on pushes and PRs.

## Contributing
- Keep modules self-contained under their own directory.
- Prefer normalized exchange formats (entities) and deterministic outputs to support versioning and diffs.
- Avoid committing generated data; keep examples concise under `docs/examples`.

## License
- Code: Apache-2.0 (see `LICENSE`).
- Docs/KB content: CC BY 4.0 (see `zap-kb/docs/LICENSE` and `zap-kb/kb-new/obsidian/LICENSE`).
- Examples: CC0 (see `zap-kb/docs/examples/LICENSE`).

See `NOTICE` for attribution and trademark notes. Contributions require DCO sign‑off (see `CONTRIBUTING.md`).
