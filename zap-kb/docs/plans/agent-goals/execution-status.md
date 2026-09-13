# Goal pack execution

Started: 12 September 2026. Integration branch: `codex/reliability-integration-20260912`.

The original checkout remains available at `F:/projects/devsecopskb`. Implementation work is isolated under `F:/projects/devsecopskb/.codex/goal-pack-20260912/`. The integration worktree is the `integration` directory there. The goal documents were snapshotted in commit `c847100` before workers started.

The coordinator owns assignment 11 and integrates reviewed commits. At most three implementing agents run concurrently. Completion below requires evidence, not merely agent dispatch.

| Assignment | Model / reasoning | Current state | Integrated evidence |
|---|---|---|---|
| 01 Configuration | Terra High | Integrated; local acceptance passed | `24ee34a`, `0803341`; combined CLI tests pass |
| 02 Validation | Sol High | Integrated; local acceptance passed | `0e55b2b`; combined CLI/import/entity/taxonomy tests pass |
| 03 Redaction | Astra High | Running from validated input boundary | Based on `bf8138b` |
| 04 Jira/outcomes | Astra High | API/result contract integrated; CLI phase waits for 03 | `6dea1c9`; published-image failures reproduced with local mocks |
| 05 Taxonomy | Sol High | Reviewed package changes integrated; pipeline phase waits for 03 | `bf8138b`; preserves imported taxonomy and exposes unsupported mapping gaps |
| 06 Wiki | Astra High | Bounded engineering/review integrated; large-wiki performance remains open | `3713743`, `23e1f50`, `1da68cc`; real 1,000/5,000-page passes remain incomplete |
| 07 Publication state | Astra High | Reference journal and durable producer handoff integrated; final CLI wiring waits for 04 | Primary `c18bca5`, companion `158826a`; stale-source CLI regression still pending |
| 08 CI/release | Terra High | CI preparation integrated; final corrected image acceptance pending | `5313680`, `f4aae32`, `58e3aff`; portable container harness reproduces the two pending 04 defects |
| 09 Maintainability | Sol High | Queued after behavioral contracts | Pending |
| 10 Demo/workplace | Sol Medium | Walkthrough and disposable acceptance preparation running | Final local signoff waits for behavioral integration; workplace acceptance needs designated tenant access |
| 11 Integration | Astra High | Coordinating | Final combined checks pending |

No production scan, publication, deployment, shared-ingest replacement, or external hosting is part of this implementation run. Disposable local test instances may be used. Source code changes, tests, and documentation will be delivered with explicit local/live acceptance boundaries.

The [published image Jira review](../../published-image-jira-review-2026-09.md) records the pinned GitHub `latest` image and controlled create/rejection/gateway results. It does not claim a live workplace root cause.

Coordinator checkpoint `4e3a5be`: combined `go test ./...` passed from `zap-kb`.
Checkpoint `bf8138b`: uncached combined CLI, run-artifact, entity and taxonomy
package tests passed. Redaction and final outcome/state integration are pending.

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
package alone does not fix the CLI source rewrite; final wiring remains pending.
The source retains cumulative snapshots with documented storage growth and no
automatic pruning. Follow-up `8255102` verifies the existing manual-backfill
behavior through Render, persisted plan and Commit: older evidence is admitted
while the cursor and boundary IDs remain unchanged. It also rejects malformed
normal plans that would regress the checkpoint, before changing durable files.

An additional valid-input boundary regression found during 03 review is fixed
in `958f14b`: a finding with zero occurrences now renders instead of panicking.
The public WriteVault regression and complete Obsidian package pass.
