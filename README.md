# DevSecOps KB (Monorepo)

This repository hosts the DevSecOps KB. It is a gradual, tool-agnostic knowledge base designed to normalize and publish security findings across tools. The first module is `zap-kb`, which focuses on OWASP ZAP.

## Structure
- `zap-kb/`: ZAP module (Go). Fetches alerts, normalizes to an entities model, and can publish an Obsidian vault (INDEX/DASHBOARD/triage-board/by-domain) plus reports.
- Other modules can be added alongside over time (e.g., Burp, SAST, SBOM importers).
- `archive/`: Legacy experiments and prior folder attempts consolidated to keep the root clean. Safe to delete if not needed.

Doc map:
- `zap-kb/README.md` – CLI usage, flags, behaviors.
- `zap-kb/docs/concepts.md` – IDs, scan labels, timestamps, dedup rules, safety.
- `zap-kb/docs/triage.md` – how triage/status persists.
- `zap-kb/docs/architecture.md` – updated flow diagram.
- `zap-kb/docs/schema/entities-v1.md` – entity schema.

## Getting Started (zap-kb)
See `zap-kb/README.md` for usage, flags, and examples. A GitHub Actions workflow is provided to build/vet the module on pushes and PRs.

## Automation
- `.github/workflows/zap-kb.yml`: build, format, vet, unit tests, tagged e2e test, and package build on push/PR.
- `.github/workflows/zap-kb-run.yml`: manual ZAP-to-KB artifact generation using repository secrets.
- `.github/workflows/zap-kb-smoke.yml`: manual offline pipeline smoke test, with optional live ZAP API smoke when `ZAP_URL` is available.
- `.github/workflows/zap-kb-release.yml`: tagged/manual release build for Linux, macOS, and Windows binaries with checksums.

## Current Scope
`zap-kb` is the active source module. Additional adapters for tools such as Burp, SAST, SBOM, dependency scanners, or cloud findings are intentionally deferred until a shared importer contract is designed.

## Contributing
- Keep modules self-contained under their own directory.
- Prefer normalized exchange formats (entities) and deterministic outputs to support versioning and diffs.
- Avoid committing generated data; keep examples concise under `docs/examples`.

## License
- Code: Apache-2.0 (see `LICENSE`).
- Docs/KB content: CC BY 4.0 (see `zap-kb/docs/LICENSE` and `zap-kb/kb-new/obsidian/LICENSE`).
- Examples: CC0 (see `zap-kb/docs/examples/LICENSE`).

See `NOTICE` for attribution and trademark notes. Contributions require DCO sign‑off (see `CONTRIBUTING.md`).
