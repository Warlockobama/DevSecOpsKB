# 07 — Separate scan input from mutable publication state

Status: ready to assign, subject to the dependencies below.

Model: **GPT-6 Astra / High** (`gpt-6-astra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G7 input/state ownership and firing-range handoff. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The firing-range source atomically replaces /ingest/entities.json and advances its watermark after handoff. The issue publisher may write ticket references into that same file. Schedule offsets reduce normal overlap but do not guarantee exclusion. No actual data-loss event was established by the review.

Model rationale: Atomic file replacement does not resolve competing writers. Correct recovery spans producer checkpoints, ticket references, and two repositories.

## Dependencies and ownership

02 and 04 before implementing the final contract. Trace writers and reproduce the race earlier. 09 must preserve the resulting boundaries; 10 consumes the handoff.

Starting paths: Primary: `cmd/zap-kb/forgejo_sync.go`, merge/input persistence and run-artifact code. Companion `F:/projects/devsecopsfiringranve`: `workers/publisher-worker/internal/kbsource/kbsource.go` and `infra/k8s/kb-sink/`.

## Assigned work

- Trace all readers/writers and create a deterministic local interleaving that demonstrates whether an old publisher snapshot can overwrite a newer source handoff. Distinguish verified races from conjecture.
- Choose and document immutable input batches plus separate publication state, or a versioned compare-and-swap/locking approach with clear recovery semantics. Prefer the smallest contract that preserves inputs, watermarks, dedup, and current operator workflows.
- Cover a source arrival during publish, crashes around handoff and checkpoint, retries, restart, stale state, and partial destination success. Ticket references must not disappear or attach to the wrong finding.
- Define compatibility and migration for existing entities/run artifacts, firing-range staging, and Cactus publication metadata. Preserve optional workflow writeback policy and analyst ownership.
- Implement changes in the owning repositories with linked diffs and tests. Update the handoff contract, keeping existing sink configuration and provenance gates.

## Acceptance evidence

- Deterministic tests exercise overlapping old/new batches and interrupted handoff without losing newer evidence or previously recorded publication references.
- Retry/restart converges without duplicate issues; checkpoint advancement cannot silently skip undelivered input.
- Old supported local artifacts and existing producer paths remain accepted or have an explicit tested migration.
- No live shared ingest file is overwritten during testing. Both repositories' affected tests and compatibility examples are reported.

## Escalation and handoff

Use Astra XHigh for an unresolved consistency or migration tradeoff supported by a failing interleaving. Do not substitute a schedule delay or broad file mutex without proving all participating writers obey it.

Deliver writer/state diagram or concise contract, race reproduction, selected design, cross-repository patches, compatibility/migration evidence, and recovery procedure. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
