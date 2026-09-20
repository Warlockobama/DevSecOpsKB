# Shared execution contract

Read this file and your assigned numbered goal before editing. The [dispatch index](README.md) contains dependency order and model recommendations. Implement the assigned outcome; the goal pack is not a request to carry out all assignments in one task.

## Repository context

Primary repository: `F:\projects\devsecopskb`, origin `https://github.com/Warlockobama/DevSecOpsKB.git`. Go commands run from `zap-kb`. Paths in numbered assignments are relative to that module unless explicitly marked repository-root or companion.

The September 12 assessment used commit `1a5a478`, whose tree matched main merge `b44ba02` at review time. Check your actual revision, worktree status, applicable repository instructions, and the current implementation. Do not reset another person's work or treat a historical line number as authoritative.

The companion checkout is `F:\projects\devsecopsfiringranve`. Its existing controller-to-kb-source-to-Forgejo handoff should be reused. Only 07 and 10 include companion implementation within their described scope; 06 may inspect its retained performance evidence. Changes in two repositories need separate, linked diffs and validation.

Read the relevant section of the [parent goals](../reliability-goals-2026-09.md). For runtime work also read the [live review](../../production-publishing-review-2026-09.md). Local diagnostics under `out/evaluation-2026-09-12/` are optional supporting evidence, not portable test dependencies. Reproduce the behavior in tracked synthetic fixtures/tests.

## Product and compatibility

Forgejo is the self-hosted demonstration destination. Jira/Confluence is the workplace DAST destination. No personal Atlassian Cloud tenant exists. Build local contract coverage and record live acceptance as pending when no designated test tenant is available.

Preserve rule/finding/occurrence identities, detection traces, source/scan identity, analyst-owned fields, and Jira-owned workflow. Any intentional schema/default/identity change must include a documented compatibility decision and regression evidence. A taxonomy improvement must not silently create duplicate issues.

Use existing sink infrastructure. This implementation scope covers code, tests, documentation, and disposable test instances. Production upgrades, a new live scan/publish, pruning, workflow changes, and shared ingest replacement are separate rollout actions; preparing a patch does not execute them. Read-only runtime checks must remain bounded. Keep secrets out of logs, files, command arguments, and reports; clean up any temporary forwards.

## Work and tests

Reproduce the assigned failure, make the smallest cohesive fix, then verify behavior through a public boundary. Use synthetic sensitive markers and isolated destinations. Do not solve test failures by weakening redaction, validation, deduplication, cancellation, or analyst preservation.

Run affected package tests while iterating. Before handoff, run `go test ./...`, `go vet ./...`, `go build ./cmd/zap-kb`, and formatting checks from `zap-kb` when Go code changed. Record environment limitations. Run tagged/service integration suites only in their designated environment; an unrun suite is not a pass. For documentation-only work, check links/commands and avoid needless full test reruns.

Store benchmark raw output under ignored local artifacts; commit a sanitized summary and reproducible fixture/harness. A measurement must name revision, dataset, server/runtime, and cold/warm conditions. Do not infer successful no-op processing from an unchanged remote commit count.

Follow the file ownership and dependency order in the dispatch index. Finish package-local work while awaiting an interface; do not independently replace a shared contract. Escalate with a small reproducer, choices, and their consequences when the task outgrows its scope.

## Required handoff

Report assignment ID, base/head revision or local diff state, behavior changed, paths touched, exact validation performed and results, compatibility implications, and remaining limitations. Distinguish implemented, verified locally, verified live, and pending external acceptance.

Mark only your assignment's available acceptance as complete. For any pending runtime step, identify the concrete missing environment and give the already prepared test procedure. Do not invent a live result or automatically dispatch another task. An agent can complete local engineering while the overall workplace acceptance remains pending.
