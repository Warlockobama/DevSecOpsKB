# Goal pack execution

Started: 12 September 2026. Integration branch: `codex/reliability-integration-20260912`.

The original checkout remains available at `F:/projects/devsecopskb`. Implementation work is isolated under `F:/projects/devsecopskb/.codex/goal-pack-20260912/`. The integration worktree is the `integration` directory there. The goal documents were snapshotted in commit `c847100` before workers started.

The coordinator owns assignment 11 and integrates reviewed commits. At most three implementing agents run concurrently. Completion below requires evidence, not merely agent dispatch.

| Assignment | Model / reasoning | Current state | Integrated evidence |
|---|---|---|---|
| 01 Configuration | Terra High | Integrated; local acceptance passed | `24ee34a`, `0803341`; combined CLI tests pass |
| 02 Validation | Sol High | Integrated; local acceptance passed | `0e55b2b`, `b6d586b`; invalid graphs and path-unsafe identities fail before side effects |
| 03 Redaction | Astra High | Integrated; combined local acceptance passed | `f817a36`; output policy and marker regressions pass |
| 04 Jira/outcomes | Astra High | Integrated; combined local acceptance passed | `6dea1c9`, `050846a`; required sink failures persist truthful outcomes and return nonzero |
| 05 Taxonomy | Sol High | Integrated; combined local acceptance passed | `bf8138b`, `d88c8a1`; CLI entities/run/render acceptance preserves identities and reviewed mappings |
| 06 Wiki | Astra High | Bounded engineering/review integrated; large-wiki performance remains open | `3713743`, `23e1f50`, `1da68cc`; real 1,000/5,000-page passes remain incomplete |
| 07 Publication state | Astra High | Integrated; local acceptance passed across both repositories | Primary `c18bca5`, `2c847c6`; companion `158826a`, `0b3376f`; paused-create regression preserves newer input and confirmed refs |
| 08 CI/release | Terra High | Integrated; final candidate container contract passed locally | `5313680`, `f4aae32`, `58e3aff`, `2b78dfc`; Cloud create/readback, rejected-create and gateway cases passed on an internal Docker network |
| 09 Maintainability | Sol High | Integrated; local acceptance and independent review passed | `38238f8`; input, entity/enrichment and primary-output responsibilities extracted with public compatibility and cancellation coverage |
| 10 Demo/workplace | Sol Medium | Disposable acceptance passed; workplace acceptance remains external | `f32871b`, `ae80463`; real local Forgejo replay preserved immutable input, separate journal, stable issue identity and analyst label |
| 11 Integration | Astra High | Local engineering signoff passed; external/live signoff remains open | Full uncached tests, race tests, vet, build, formatting, offline e2e, container Jira contract and disposable Forgejo acceptance pass |

No production scan, publication, deployment, shared-ingest replacement, or external hosting is part of this implementation run. Disposable local test instances may be used. Source code changes, tests, and documentation will be delivered with explicit local/live acceptance boundaries.

The [published image Jira review](../../published-image-jira-review-2026-09.md) records the pinned GitHub `latest` image and controlled create/rejection/gateway results. It does not claim a live workplace root cause.

Coordinator checkpoint `4e3a5be`: combined `go test ./...` passed from `zap-kb`.
Checkpoint `bf8138b`: uncached combined CLI, run-artifact, entity and taxonomy
package tests passed. Redaction and final outcome/state integration are pending.
Checkpoint `f817a36`: complete uncached Go suite, vet and CLI build passed with
03 redaction and 07 journal packages integrated. Final CLI outcome/state changes
and the corrected container remain pending.

The local state race used one synthetic finding and a loopback Jira stub. The
publisher read source A; the stub paused the create response; a simulated producer
atomically replaced the input with source B containing a new occurrence; the stub
then accepted creation. The publisher exited zero and persisted `TEST-1`, but the
newer occurrence disappeared from the shared input. This verifies the stale-write
interleaving through the CLI without touching live ingest. It is not evidence of
historical production data loss. The ignored reproducer and result are under
`integration/out/goal-pack/probe_state_race.py` and `state-race-baseline/result.json`;
assignment 07 must turn this into a portable regression and preserve source B.

Coordinator checkpoint `158826a` in the companion integration worktree: full
uncached worker tests, vet and kb-source build passed. The reference journal
package alone did not fix the CLI source rewrite; `2c847c6` now supplies that
final wiring.
The source retains cumulative snapshots with documented storage growth and no
automatic pruning. Follow-up `8255102` verifies the existing manual-backfill
behavior through Render, persisted plan and Commit: older evidence is admitted
while the cursor and boundary IDs remain unchanged. It also rejects malformed
normal plans that would regress the checkpoint, before changing durable files.

An additional valid-input boundary regression found during 03 review is fixed
in `958f14b`: a finding with zero occurrences now renders instead of panicking.
The public WriteVault regression and complete Obsidian package pass.

Handoff review on 19 September 2026 integrated the completed 02, 04 and 10
branches as `b6d586b`, `050846a` and `f32871b`. On that combined revision,
`gofmt` produced no normalized Git diff, `go test ./...`, uncached
`go test -race -count=1 ./...`, `go vet ./...`, `go build ./...`, and
`go test -tags e2e ./e2e` all passed. Every commit between `origin/main` and the
integration head carries a matching DCO sign-off. Assignments 07 and 09 are now
complete locally; final candidate container/demo reruns remain before release
signoff.

Assignment 07 checkpoint `2c847c6`, with companion manifest commit `0b3376f`,
wires the journal into Jira and Forgejo publication. The CLI applies stored refs
before output, records exporter-confirmed refs immediately after the issue
stage, never rewrites `-entities-in` or `-run-in`, and rejects direct or hard-link
source/output aliases. A synthetic Forgejo response was paused while a newer
source batch replaced the input; publication completed, the newer bytes and
occurrence survived, and `acme/kb#7` replayed from state. Full Go tests, vet,
CLI build, race-enabled publication-state/CLI tests, and the companion
Kubernetes render passed. No live sink, ingest path, or deployment was touched.

Assignment 09 checkpoint `38238f8` extracts validated input loading, optional
ZAP fetch, entity construction/enrichment/validation, and initial output
persistence from `main.go`. The process entry point retains signal cancellation,
sink ordering, final artifact completion, and exit ownership. Architecture docs
now name each runtime and destination boundary, including Forgejo and separate
publication state. Public CLI coverage proves run-wrapper alert compatibility,
explicit alert-file precedence, graph validation, analyst/identity retention,
output dispatch, and cancellation of a blocked ZAP request. Full uncached Go
tests, vet, CLI build, focused race tests, formatting, tagged offline e2e, and
three read-only reviews passed. Broad Obsidian/Confluence file splitting is
deferred until stronger golden serialized-output fixtures exist.

Final local candidate checks found and fixed one integration defect: implicit
publication state initially followed a read-only mounted input, causing otherwise
successful container publication to exit nonzero. Commit `2b78dfc` prefers the
writable derived-output location and retains explicit shared-volume configuration.
The isolated publisher-image contract then passed normal Cloud create/readback,
truthful rejected-create failure and scoped-gateway routing. Disposable Forgejo
acceptance at `ae80463` published the portable fixture twice plus a changed
replay, retained one stable grouped issue, preserved the analyst-owned accepted
label, read back both scan identities, proved the source artifact byte-identical
after publication, and found a separate journal event. Sanitized local evidence
reported artifact SHA-256
`19532203f1a47933c4ec750da4cc414e5ae24e11a7ead54cb10d49ac7319b023`.
