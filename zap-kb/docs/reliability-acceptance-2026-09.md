# Reliability integration acceptance

Status: work in progress; this is not a release approval. The coordinator is
integrating the [agent goal pack](plans/agent-goals/README.md) on
`codex/reliability-integration-20260912`. The original source baseline is
`1a5a478`. See [execution status](plans/agent-goals/execution-status.md) for
assignment ownership and the latest integration checkpoint.

## Goal matrix

| Goal | Implemented and verified so far | Remaining acceptance |
| --- | --- | --- |
| G1 Jira and sink outcomes | Jira package `6dea1c9` and final CLI outcomes `050846a`; combined failure matrix passes and corrected source passed the isolated container contract before integration | Re-run corrected container on the eventual final candidate; designated Jira/Confluence tenant |
| G2 Shared redaction | `f817a36`; combined marker tests pass across preview, JSON, raw alerts, metadata, Markdown, remote payloads, diagnostics and ZIP | Live destination acceptance remains external |
| G3 Input and state integrity | Validator `0e55b2b`, unsafe-ID guard `b6d586b`, journal `c18bca5`; companion durable handoff `158826a`, monotonic guard `59880d0` | CLI journal wiring, source/output aliases and paused-create source-race regression |
| G4 Taxonomy | Mappings/aliases `bf8138b` and production pipeline `d88c8a1`; combined entities/run/render/repeat-import acceptance passes | Unsupported collection-rule mappings remain explicit gaps pending evidence |
| G5 Configuration | `24ee34a`, `0803341`; explicit flag/environment/default, gateway and safe-error tests pass | Re-run final container combination after G3/G7 completion |
| G6 Production and wiki review | [Read-only production review](production-publishing-review-2026-09.md); disposable/synthetic tests and [measured limits](wiki-performance-2026-09.md), integrated through `1da68cc` | Large-wiki performance remains open; no production upgrade or throughput claim |
| G7 Maintainability and release | Provenance/CI `5313680`, `f4aae32`, `58e3aff`; shared validation/policy/result/journal packages; combined handoff checks pass | Assignment 09 has no implementation; final suite/container/demo rerun follows state wiring |

Forgejo demonstration acceptance is separate from workplace acceptance. The
disposable walkthrough is being prepared; no live tenant is available, and no
personal Atlassian subscription is required to finish the local demonstration.

## Verified integration checkpoints

- At `f817a36`, the complete uncached Go suite, vet and CLI build passed in the
  combined primary worktree. This includes validation, redaction, the journal
  package, wiki changes and a public regression for findings with zero occurrences.
- At companion `158826a`, full uncached worker tests, vet and kb-source build
  passed. At `59880d0`, the source package passed again after adding the monotonic
  checkpoint guard and public backfill regression.
- At combined primary `f32871b`, formatting against tracked content, the complete
  Go suite, uncached race-enabled suite, vet, all-package build and tagged offline
  e2e suite passed. All 34 commits over refreshed `origin/main` carry matching
  `Signed-off-by` trailers; the branch contains no merge commit or rewritten
  individual-agent history.
- The current Cactus exporter at repository revision `e5b70f8` generated a fresh
  synthetic artifact accepted by the combined CLI at `f817a36`. Finding,
  definition and occurrence IDs, the complete detection trace and source bytes
  survived; the synthetic query marker was redacted. This exercised export and
  import only, without collecting or publishing any live data. The exporter file
  was clean and last changed in `183a4d0`.

The original CLI cases now run together in the combined suite. The final
candidate must still rerun the container and disposable Forgejo integrations
after publication-state wiring and the selected maintainability work. Separate
branch service passes do not substitute for that final candidate.

## Jira image evidence and release boundary

The controlled [published-image review](published-image-jira-review-2026-09.md)
pins the observed GitHub `latest` image. It creates an issue against a synthetic
normal Cloud endpoint, but returns zero after a rejected create and selects the
wrong dialect for automatic gateway routing. Those observations establish image
defects; they do not establish the historical cause inside the workplace tenant.

Changing this local branch does not update the published image or any deployed
Job. The [release procedure](ci-and-release.md) and
[designated-tenant procedure](jira-cloud-acceptance.md) describe the later image,
provenance, create/readback, repeat and rejection checks. Production rollout,
workflow writes, shared-ingest replacement and image/Git pushes have not occurred.

## Measured limits and product direction

The real 1,000-page workload did not finish within its bounded run. At 5,000
pages, initial listing exhausted request deadlines on both tested Forgejo
versions before any page-content work. An unchanged Git head is not a completed
no-op run. The [batch-backend proposal](wiki-batch-backend-proposal.md) is a future
implementation plan, not a delivered backend. Source snapshots also have
documented cumulative storage growth; no automatic pruning is implemented.

The workplace pilot prepares developer triage in Jira/Confluence using readable
case bodies, explicit evidence/history links and preserved analyst decisions.
A later human/LLM/assisted comparison can use an Atlassian connector and immutable
JSON replay. Bedrock is a possible model platform reported by the owner; the
actual workplace agent application and authentication remain unconfirmed.
Neither a database migration nor an automated triage experiment is part of this
repair pack.
