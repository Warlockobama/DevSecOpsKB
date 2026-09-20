# 11 — Coordinate integration and verify the combined result

Status: ready to assign, subject to the dependencies below.

Model: **GPT-6 Astra / High** (`gpt-6-astra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G1–G7 overall completion. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The dispatch index assigns overlapping main.go, serialization, and result-contract work in a conservative merge order. Model choice is a starting hypothesis; acceptance evidence determines whether a patch is ready.

Model rationale: Individually passing patches can break each other at shared pipeline boundaries. This task needs a complete view of configuration, validation, redaction, publication, state, and performance.

## Dependencies and ownership

Can coordinate incremental reviews from the start. Final assessment follows 01–10 available scope; external tenant acceptance remains a separate status when unavailable.

Starting paths: The integrated source and tests from 01–10, this dispatch index, the parent goals, live review, and any linked companion changes.

## Assigned work

- Track assignment ownership, base revisions, dependencies and status. Make sure goal documents are present in each worktree. Review shared interfaces early and integrate local changes in the documented order.
- Check the original five failures through the combined CLI after relevant integration. Verify config resolution, validation-before-side-effects, enrichment order, redaction-before-emission, identity stability, and truthful multi-sink outcomes together.
- Review 07's source/publisher race tests and 06's fixed-dataset performance evidence. Preserve the distinction between read-only production observations and disposable write acceptance.
- Run the combined required checks on the final candidate revision, including affected cross-repository integration. Do not accept a list of tests run only on each agent's separate branch.
- Produce a completion matrix for G1–G7 with implementation revision, regression evidence, runtime evidence, pending external acceptance, and remaining risks.
- Report Forgejo demo readiness separately from Jira/Confluence workplace live readiness. Provide the reviewed release/rollback steps; actual production rollout is separate.

## Acceptance evidence

- Every original finding is either fixed with a reproducer/regression or explicitly still open with a concrete cause. No undocumented scope loss occurs during task splitting.
- Combined tests and designated integrations pass where available; unavailable checks are named with runnable procedures.
- Redaction, validation, deduplication, analyst ownership, cancellation, and state consistency survive interactions between patches.
- Readiness claims match evidence: a mock pass is not Cloud validation; an unchanged commit count is not no-op throughput; a new source build is not the existing deployed image.
- The final report lists remaining external prerequisites and does not automatically treat them as completed or block unrelated Forgejo work.

## Escalation and handoff

Use Astra XHigh for a specific disputed cross-component invariant or release decision. For a concrete implementation defect, return the reproducer to its owner rather than rewriting every assignment centrally.

Deliver integrated revision(s), final test and goal matrix, remaining acceptance boundaries, and a concrete reviewable release recommendation. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
