# 06 — Make large-wiki publication measurable and efficient

Status: ready to assign, subject to the dependencies below.

Model: **GPT-6 Astra / High** (`gpt-6-astra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G6. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The read-only review is already complete. The scheduled wiki had 2,047 tracked files and 11,791 commits; a default-size listing exceeded a 20-second observation budget. The separate demo returned 50 pages in 15.671 seconds. These were startup samples, not write-throughput benchmarks. Current code lists twice and reads every existing page; inspected Forgejo handlers perform per-page Git history lookup.

Model rationale: The task needs experimental design, algorithm choices, remote-state correctness, and bounded recovery. More workers or a longer timeout is not an adequate demonstrated fix.

## Dependencies and ownership

03 and 04 before final publisher integration. A disposable benchmark harness and source analysis can start earlier. Coordinate release metadata with 08 and renderer boundaries with 09.

Starting paths: `internal/output/forgejo/wiki.go`, `internal/output/synccore/synccore.go`, Forgejo integration tests/harness, and the linked live review. Companion historical performance records are context only.

## Assigned work

- Build a reproducible disposable workload at 100, 1,000, and 5,000 pages, with realistic page size, encoded links, and a documented history shape. Avoid benchmarking against the existing production repository.
- Measure fresh publish, unchanged rerun, one-page change, 10% change, cancellation and recovery. Record stage duration, requests by endpoint/method, latency distribution, retries, mutations, and resource use where available.
- Use 04's result contract. Reduce redundant full traversals and unnecessary work while preserving server-issued paths, concurrent-state correctness, no-op behavior, and link repair. Bound retries/cancellation and explain cache invalidation if introducing a manifest.
- Compare a supported Forgejo release with the baseline on the same disposable dataset, recording revision/storage and cold/warm conditions. Use the documented upgrade path and a restore test for a disposable copy. An upgrade alone is not an assumed algorithm fix.
- Evaluate the batch Git backend proposal only if measurements justify it. Before adoption, test filename/branch/link encoding, preservation of non-KB pages, no-op commits, conflicts, failed pushes, and bounded credentials. Keep this an explicit design choice rather than an automatic backend replacement.
- Commit the chosen optimization and reproducible benchmark summary; keep raw results local and sanitized. Define a measured runtime target that fits the actual scheduling budget.

## Acceptance evidence

- Publish/readback and encoded cross-links pass for the selected backend; unchanged reruns create no issues, duplicates, or wiki commits.
- A one-page change changes only rendered content and dependent indexes/links that actually differ. Cancellation returns a truthful partial result, stops work, and a rerun converges.
- Compare before/after request counts and duration with a fixed dataset. Separate synthetic tests, disposable live tests, and historical production observations.
- Document the selected optimization, alternatives considered, measured tradeoff, and remaining limits. Full production write throughput remains unclaimed unless separately tested.

## Escalation and handoff

Use Astra XHigh for a concrete unresolved remote-state/cache/conflict design decision. If service behavior is unavailable, retain the harness and report the missing measurement instead of inventing an SLO.

Deliver optimization patch, result metrics, reproducible scale harness, before/after report, supported-version comparison, and a proposed rollout/rollback procedure for later execution. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
