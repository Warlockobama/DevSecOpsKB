# Agent assignments for DevSecOpsKB reliability

Date: 12 September 2026. Status: execution started after the owner's launch instruction. See [assignment progress and integrated evidence](execution-status.md).

Use these assignments with the [original reliability goals](../reliability-goals-2026-09.md) and [live publishing review](../../production-publishing-review-2026-09.md). The original document defines product outcomes; this directory divides delivery responsibility. Assignment numbers are identifiers, not severity rankings.

## Recommended allocation

Use Astra High where a mistake can cross output boundaries, change ownership semantics, or compromise recovery. Use Sol for substantial but more contained implementation, and Terra for well-specified configuration/build work. These task assignments and reasoning levels are engineering judgments, not measured model benchmarks on this repository.

OpenAI describes Astra as its most capable model for difficult end-to-end work, Sol for complex professional work, Terra as balancing capability and cost, and Luna for cost-sensitive workloads. The named models and High/Medium settings are also available in this app's current model catalog. [Official model catalog](https://developers.openai.com/api/docs/models), [Astra model documentation](https://developers.openai.com/api/docs/models/gpt-6-astra)

| Assignment | Goal coverage | Suggested model / effort | Why |
|---|---|---|---|
| [01 Configuration precedence](01-configuration.md) | G5 | GPT-5.6 Terra / High | Reproduced failure, explicit precedence contract |
| [02 Artifact validation](02-artifact-validation.md) | G3 | GPT-5.6 Sol / High | Compatibility and import-path integration |
| [03 Output redaction](03-output-redaction.md) | G2 | GPT-6 Astra / High | Sensitive data across artifacts, logs, and sinks |
| [04 Jira and publication outcomes](04-jira-and-outcomes.md) | G1; G7 result contract | GPT-6 Astra / High | Remote API ambiguity, deduplication, partial failure |
| [05 Taxonomy integration](05-taxonomy.md) | G4 | GPT-5.6 Sol / High | Bounded pipeline work with semantic mapping review |
| [06 Wiki performance](06-wiki-performance.md) | G6 | GPT-6 Astra / High | Algorithm, server behavior, cancellation, measurement |
| [07 Input and publication state](07-publication-state.md) | G7 handoff ownership | GPT-6 Astra / High | Concurrent writers and compatibility across two repos |
| [08 CI and release provenance](08-ci-and-release.md) | G7 build/release | GPT-5.6 Terra / High | Concrete build paths, test wiring, image metadata |
| [09 Maintainability](09-maintainability.md) | G7 structural work | GPT-5.6 Sol / High | Behavior-preserving extraction after contracts settle |
| [10 Demonstration and workplace pilot](10-demo-and-workplace.md) | Demo outcome; G1 workplace acceptance | GPT-5.6 Sol / Medium | Existing infrastructure and explicit walkthrough criteria |
| [11 Integration and final review](11-integration-review.md) | G1–G7 overall | GPT-6 Astra / High | Cross-assignment interactions and release evidence |

Do not default every task to maximum reasoning. Start with the settings above. Escalate a bounded Sol/Terra task when it requires a new compatibility or ownership decision, or when repeated focused attempts leave the same unexplained failure. Preserve its reproducer and findings so escalation does not restart discovery. More reasoning cannot supply a missing Cloud tenant or replace a live measurement.

Luna Medium is an optional choice for polishing an already verified runbook or checking links. It has no sole ownership of a core reliability fix in this plan. Do not create a separate agent just to fill a model tier.

## Dispatch and integration

Each implementing agent receives its assignment and [shared execution contract](SHARED.md). The numbered document includes its starting context, owned work, dependencies, acceptance evidence, and escalation rule. Configure the model in the agent/task settings; putting a model name in a prompt does not itself select that model.

The goals were snapshotted in signed documentation commit `c847100` before implementation agents started. The original checkout still contains its uncommitted documentation draft; implementation branches inherit the snapshot and subsequent clarifications. Before starting another worktree, ensure it includes the current documents. Do not assume default main already contains them or commit unrelated local changes.

Use one worktree/branch per assignment, with a `codex/` branch prefix. One coordinator handles integration; assignment 11 defines that role. It can operate from the start, then perform the final review after implementation. A second review task is unnecessary unless the implementer also owns the coordinator role and an independent review is wanted.

| Assignment | Delivery dependency | Work that can start earlier |
|---|---|---|
| 01 | None | Full bounded fix |
| 02 | 01 before CLI wiring merges | Validator design, fixtures, package implementation |
| 03 | 02 before artifact-boundary integration | Output inventory and synthetic leak fixtures |
| 04 | 01 and 03 before final integration | API contract tests and common result design |
| 05 | 02 and 03 before pipeline integration | Review PR #94, mapping evidence, alias fixtures |
| 06 | 03 and 04 before final publisher integration | Disposable benchmark harness and algorithm analysis |
| 07 | 02 and 04 before implementing the final handoff contract | Trace writers and demonstrate the race locally |
| 08 | Final release wiring after 01–07 and 09 | Repair existing CI paths and record current build metadata |
| 09 | 01–07 | Identify extraction boundaries; defer broad code moves |
| 10 | 01–09 available local acceptance complete | Draft walkthrough and identify test prerequisites |
| 11 | Final assessment after 01–10 available scope | Coordination and review of each incremental patch |

This is a conservative merge order, not a requirement to leave all agents idle. A useful first pair is 01 and the initial CI work in 08. Once 01 lands, 02 can integrate while 04 investigates Jira contracts and 06 builds its disposable benchmark. Avoid launching all eleven at once.

The highest collision areas are `cmd/zap-kb/main.go`, run-artifact serialization, shared HTTP/result helpers, and rendering. Queue integration of those changes in the order above. Agents may prepare package-local work independently but must rebase and rerun the affected CLI acceptance after preceding changes land. Separate branches do not eliminate semantic conflicts.

## Shared decisions and completion

- 01 owns configuration precedence. 04 owns Jira deployment dialect and the common publication-result contract. They agree on the interface instead of each inventing a resolver.
- 02 owns input compatibility and validation placement. 03 owns output redaction policy. Validation must precede side effects; redaction must preserve the accepted input identities.
- 04 owns sanitized stage results. 06 supplies wiki timing/request metrics using that contract.
- 07 owns immutable input versus mutable publication state. 09 consumes that decision without redesigning it.
- 08 owns CI/release workflows. Other assignments supply commands and fixtures; they do not independently restructure the same workflow files.
- 10 uses implemented behavior and measured results. It cannot close missing runtime acceptance with prose.

Require each delivery to include changed behavior, tests/results, compatibility effects, and unresolved external acceptance. Use assignment 11's final matrix to distinguish Forgejo readiness, mock-tested Atlassian behavior, and workplace live acceptance. No personal Atlassian tenant is required to complete the local Forgejo demonstration.

The owner's launch instruction authorizes the bounded local implementation described in the shared contract. Deployment, production publication and changes to a running sink remain separate rollout actions.
