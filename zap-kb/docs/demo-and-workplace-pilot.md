# Firing-range demonstration and workplace pilot

This runbook has two independent tracks. The local track demonstrates a retained
scan artifact becoming grouped Forgejo cases and navigable evidence. The workplace
track applies the same artifact contract to Jira and Confluence after a designated
tenant is available. The firing range is not required in the workplace.

## What is ready to demonstrate

The portable boundary is a validated `zap-kb/run/v1` JSON artifact. Keep the
accepted artifact immutable for replay. A cumulative producer view may add later
runs, while destination references and publication results belong in the separate
publication journal described in [Publication state and immutable
input](publication-state.md).

Forgejo presents two related views:

- Issues are grouped analyst cases. Labels, comments, assignment and open/closed
  state are analyst-owned.
- The wiki is generated evidence. Start at **Home**, use **Scans** for run history,
  then follow **Findings**, **Rules**, and **Occurrences** links for the
  rule-to-finding-to-observation chain.

The repository root [README](../../README.md) points clean operators here. The
companion firing-range checkout documents its source-to-artifact handoff in
`docs/runbooks/kb-forgejo-demo.md`.

## Disposable local acceptance

Prerequisites are Go, Docker Engine, PowerShell 7 or Windows PowerShell 5.1, and
network access to pull the explicitly selected Forgejo image. From `zap-kb` run:

```powershell
./scripts/run-forgejo-demo-acceptance.ps1
```

The harness starts one uniquely named Forgejo container and volume, binds it to a
random loopback-only port, creates a random-password administrator and token,
publishes only a synthetic authorized fixture, and removes its container and
volume in `finally`. The token exists only in process output/memory and the test
process environment. It is not printed, written to evidence, or passed as a
command argument.

The real CLI publishes a `zap-kb/run/v1` artifact to a uniquely named private
repository. The test reads back one grouped issue representing two findings plus
the Home, Scans, and Definition wiki pages through Forgejo's API. It then verifies:

1. The first publish creates cases and wiki evidence with visible run identity.
2. The identical replay creates no duplicate case.
3. A second scan occurrence updates history without changing case identity.
4. An analyst-owned `accepted` label survives the changed replay.

The immutable synthetic input and sanitized result are written under
`out/demo-acceptance/<UTC>/accepted-run.json` and `forgejo-readback.json`. The
result records the original artifact SHA-256, readback surfaces, counts and scope;
it contains no token or evidence body. If the destination is unavailable, retain
the accepted input artifact and sanitized publication result, fix the destination,
and replay that exact artifact. Do not advance a producer cursor from a remote
publication result.

The harness uses the supported Forgejo 15.0.8 image by default. Override `-Image`
only to test an explicitly reviewed image. It is intentionally small; it does not
simulate the firing-range cluster, run a scanner, contact a production sink, or
establish a service-level objective.

## Firing-range walkthrough

Use an existing authorized completed run. The companion handoff is:

`controller run projections -> render/provenance gate -> immutable retained batch -> cumulative ingest view -> independent issue/wiki publishers`

Before presenting, record the companion revision, DevSecOpsKB binary revision,
Forgejo image digest, source run ID, scan label, target authorization and artifact
SHA-256. Confirm the range targets have no route through the presentation endpoint.
For a local k3s demonstration, expose Forgejo with a short-lived loopback
`kubectl port-forward`; for any external presentation URL, require a separately
approved ingress, HTTPS certificate, authentication, authorization and backup
plan. This runbook does not publish Forgejo externally.

Present the flow in this order:

1. Show the immutable run artifact and its source, scan label and detection trace.
2. Run the existing companion publish handoff for that run; do not create a new
   scanner adapter.
3. Open Forgejo **Home**. Show the summary and the short drill-down links.
4. Open one grouped issue, follow its KB reference to the Rule page, then follow a
   Finding to a concrete Occurrence with redacted evidence.
5. Open **Scans** and identify the run. Replay the same retained artifact and show
   zero duplicate cases and no wiki mutation.
6. Add an analyst comment or workflow label, publish a later authorized scan with
   the same finding identity, and show the earlier instance plus the new occurrence
   while the analyst decision remains.
7. In a disposable destination, inject an issue or wiki failure. Show the nonzero
   outcome, the successful independent stage if any, and the retained sanitized
   artifact used for convergence.

For wiki sizing, use the measured assignment 06 bound: 100 approximately 4 KiB
pages with encoded links completed a fresh disposable Forgejo 9.0.3 publish in
78.18 seconds under a 120-second pass budget. A 60-second pass stopped during link
repair. The 1,000- and 5,000-page real-Forgejo trials did not complete within
their experimental budgets, and upgrading the server alone did not remove the
history-listing cost. See [Wiki publication performance](wiki-performance-2026-09.md)
for the dataset, images, limits and exact results. Measure the actual demo vault;
do not present the small bound as production throughput.

## Workplace Jira and Confluence pilot

This procedure is runnable when an approved test project and space exist. Until
then, local contract checks are evidence of preparation only.

1. Confirm Cloud or Data Center, approved test account, API root and separate
   human-facing site root, project key, issue type ID, required create fields,
   parent/component rules, Confluence space and parent page, permissions, and
   evidence-retention/cleanup policy. Keep credentials only in the job secret
   environment.
2. Pin and record the publisher image digest and binary version. Run the bounded
   read-only readiness check. A readiness pass is not a create/readback pass.
3. Select one sanitized scanner-native DAST artifact with stable IDs and a unique
   run label. Record its SHA-256 and retain it unchanged for replay.
4. Publish one eligible finding. Read Jira back through the API and verify project,
   issue type, required fields, stable identity labels, ADF evidence, and explicit
   Confluence/history links. Read Confluence storage/API bodies, not only browser
   rendering; any context required by a connector must be present outside macros.
5. Add a marked analyst note in Confluence and update Jira-owned workflow or
   assignment. Replay the identical artifact. Verify one Jira case, preserved Jira
   workflow/assignment, preserved analyst block, unchanged evidence page content,
   and a recorded page version.
6. Publish a changed artifact with another occurrence. Verify the earlier instance,
   prior decision, new occurrence, and cross-links are all readable. Record the
   Jira issue version/update timestamp and Confluence page IDs and versions that
   were consulted.
7. Reject Jira and Confluence separately in approved tests. Each requested sink
   must report complete, partial, failed or skipped honestly; one failure must not
   erase the other's result or the retained artifact.

Jira remains the workflow source of truth. Confluence holds generated evidence and
preserved analyst blocks. An AI output is a recommendation with model/version,
prompt/configuration, tool access, consulted issue/page versions and artifact hash;
only an explicit human action becomes an accepted analyst decision. A future
human-only, model-only and human-with-model comparison can replay the same JSON
artifact against recorded versions. Scanner responses, issue text and wiki bodies
are untrusted evidence, never agent instructions. The future evaluation must
include a synthetic instruction-shaped evidence case and verify that it cannot
trigger a workflow write. It does not require a new database or changes to this
pilot. Amazon Bedrock plus an MCP-capable agent and Atlassian connector is a
candidate, not a verified workplace architecture.

## Readiness

| Capability | Implemented | Verified locally | Verified live | Remaining dependency |
| --- | --- | --- | --- | --- |
| Portable run artifact and validation | Yes | Existing package coverage | No new production run | Final 02/03/07/09 integration |
| Disposable artifact-to-Forgejo harness | Prepared | Compile and small live result recorded at handoff | Disposable only | Re-run after final CLI integration |
| Identical and changed replay | Prepared | Disposable test | Disposable only | Final publication-state CLI behavior |
| Analyst decision preservation | Prepared | Forgejo label readback | Disposable only | Final 04 outcomes integration |
| Destination failure evidence | Existing focused fixtures; walkthrough prepared | Existing e2e fault tests | No production write | Final common outcome/redaction wiring |
| 100-page wiki bound | Yes | Real disposable Forgejo measurement | Disposable only | Re-measure integrated image |
| 1,000/5,000-page production readiness | No | Bounded trials failed to complete | No | Next wiki algorithm and controlled acceptance |
| Jira/Confluence workplace pilot | Procedure prepared | Contract mocks only | No | Designated tenant, approved project/space and 04 integration |
| AI triage comparison | Procedure prerequisites only | No | No | Future evaluation design and verified agent application |

Final signoff must repeat this harness after assignments 03, 04, 07 and 09 are
integrated, assert that the source artifact bytes remain unchanged, verify the
separate publication journal/result, and run the designated-tenant procedure when
access exists. Do not turn missing tenant access into a claimed live pass.
