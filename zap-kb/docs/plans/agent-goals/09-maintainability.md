# 09 — Extract stable responsibilities after reliability fixes

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Sol / High** (`gpt-5.6-sol`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G7 orchestration and renderer maintainability. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The CLI and Obsidian/Confluence output modules carry much of the production code. Broad code moves during reliability fixes would increase conflicts and make behavioral review harder.

Model rationale: Substantial refactoring is appropriate for Sol High once behavior and ownership contracts are fixed. New semantics during extraction require separate review.

## Dependencies and ownership

01–07 before structural edits integrate. Coordinate CI with 08; 10 validates the resulting product walkthrough.

Starting paths: `cmd/zap-kb/main.go`, existing command helpers, `internal/output/obsidian/`, `internal/output/confluence/`, and the shared interfaces introduced by preceding assignments.

## Assigned work

- Extract configuration resolution, validated input loading, enrichment, persistence, and sink orchestration into clear responsibilities while preserving the preceding interfaces.
- Keep one cancellation context and top-level process-exit boundary. Reuse 04's results, 03's sanitization, 02's validator, and 07's state contract.
- Separate renderer view construction, templates, analyst preservation, transport/upsert, and indexes using small cohesive changes. Preserve serialized output and public CLI behavior unless an earlier accepted fix intentionally changes them.
- Add or retain representative public-boundary regression fixtures for analyst blocks, encoded links, artifact round trips, and output stability. Avoid tests tied to private helper layout.
- Update architecture and module navigation to reflect the actual boundaries, including Forgejo. Leave speculative UI/importer expansion outside this change.

## Acceptance evidence

- Relevant fixtures produce compatible content, links, IDs, analyst data, error outcomes, and cancellation behavior before/after extraction.
- Full Go tests, vet, formatting, build, and available designated renderer/integration tests pass on the integrated revision.
- Each extraction has a clear owner/responsibility and preserves error/context propagation. The review can separate behavior-preserving movement from intentional earlier fixes.
- Report deferred structural work explicitly; fewer lines in main.go alone does not establish maintainability.

## Escalation and handoff

Escalate to Astra High if extraction reveals a new ownership, concurrency, or schema decision. Isolate that issue rather than slipping a semantic rewrite into a large move-only patch.

Deliver small reviewable extractions, updated architecture, public-boundary compatibility evidence, and any deliberately deferred areas. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
