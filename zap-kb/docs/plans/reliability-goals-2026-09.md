# DevSecOpsKB reliability goals

Date: 12 September 2026. Status: implementation in progress; see the
[integration acceptance report](../reliability-acceptance-2026-09.md) for verified
results and remaining work. This document defines the acceptance reference.

For assignment to individual agents, use the [agent goal documents](agent-goals/README.md). They preserve the outcomes below while dividing ownership, recommending models/reasoning levels, and specifying integration order. This document remains the product acceptance reference.

Objective: make unattended ingestion and publication trustworthy, with Jira Cloud working against its actual project configuration, redaction covering every shared output, validated input contracts, complete enrichment, and predictable configuration. Preserve the existing evidence model and analyst ownership rules while improving maintainability.

Product direction clarified by the owner: Forgejo is the primary self-hosted demonstration sink, fed by the DevSecOps firing-range pipeline. The owner has no personal Atlassian Cloud tenant. Jira Cloud remains a supported compatibility target, with live Cloud acceptance conditional on access to an external test tenant; it must not block a working Forgejo demonstration or be described as live-validated without that tenant.

The second adoption path is workplace DAST scans published into Jira and Confluence. Keep those integrations first-class: the shared artifact is the product boundary, Forgejo demonstrates it publicly or locally, and Atlassian provides the workplace workflow/evidence destination. Confirm the workplace deployment type before tenant-specific acceptance. A workplace pilot needs approved test-project access, project/issue-type metadata, evidence-retention rules, and a small representative DAST report; do not require the owner to purchase or maintain a personal Cloud tenant.

The baseline evaluation reproduced findings 1–5 against the source tree shared by `1a5a478` and main merge `b44ba02`. Reproduction artifacts are retained locally under `out/evaluation-2026-09-12/`. The user's report that Jira Cloud appears broken is an additional diagnostic requirement: changing the exit status alone does not complete the Jira goal.

| Goal | Outcome | Sequence |
|---|---|---|
| G1 | Jira Cloud creates the intended tickets and every requested sink reports failure honestly | First |
| G2 | Requested redaction covers all shared representations | First, alongside G1 |
| G3 | Invalid or incompatible artifacts cannot enter publishing or overwrite valid state | Next |
| G4 | Curated custom taxonomy reaches final outputs without changing existing identities unexpectedly | After G3; reconcile PR #94 |
| G5 | Configuration consistently follows explicit flag, environment, then default | Small early fix; shared configuration follows |
| G6 | Production diagnosis and large-wiki performance have measured evidence | Read-only review now; controlled acceptance after fixes |
| G7 | Orchestration and rendering are easier to change and verify | Targeted extraction during G1–G5, remaining work last |

**G1 — Restore Jira Cloud publication and truthful outcomes**

Confirmed baseline: the Cloud API mock rejects the eligible issue with HTTP 400, the summary records one error, and the CLI exits 0. Individual create errors are counted in `internal/output/jira/exporter.go` but their useful error details are discarded. The existing `atlassian check` only examines configuration completeness; it does not prove authentication, permissions, connectivity, or ticket creation readiness.

Implementation work:

- Retain bounded, sanitized per-finding failure details: stage, finding ID, HTTP status, actionable error category, and retryability. Include Jira's required-field errors without exposing tokens, captured evidence, or sensitive server responses.
- Diagnose the user's actual Cloud path: selected authentication method, API base URL, account visibility, project access, Browse Projects/Create Issues permissions, issue type, required create fields, ADF description, and supported parent/component/assignee fields. Keep project-specific field requirements configurable or report them explicitly before publishing.
- Cover both site URLs and the scoped-token gateway form `api.atlassian.com/ex/jira/{cloudId}`. Current auto-detection recognizes only `*.atlassian.net` as Cloud, so the gateway is a specific compatibility risk to test. Keep API and human-facing URLs distinct where necessary.
- Preserve dedup safety: failed lookup must not become a blind create. Classify 400/401/403/404 distinctly from bounded 429/5xx/transport retry cases. For an ambiguous create timeout, reconcile remote state before retrying a non-idempotent create.
- Aggregate outcomes from every explicitly requested destination into a common run result. Record success, partial, failed, and deliberately skipped stages. Save sanitized diagnostics and available run artifacts before returning nonzero for a required failure; one sink must not terminate unrelated requested work through an early process exit.
- Extend readiness checks to offer bounded, read-only remote checks. Report configuration completeness separately from remote readiness and distinguish the permissions needed to publish from those needed only by an optional diagnostic endpoint.
- Keep Jira and Confluence responsibilities clear for workplace adoption: Jira owns case workflow and assignment; Confluence owns the generated evidence pages and preserved analyst-authored blocks. Test links between them, Jira-owned status, re-publish preservation, and partial success when either destination is unavailable. Support a CI handoff from an existing DAST scan without requiring the workplace to deploy the firing range.

Acceptance criteria:

- The reproduced rejected-create case returns nonzero and identifies the rejected finding and useful cause; the source evidence is retained.
- CLI tests cover all-success, one-of-many failure, all-failed, failed dedup, invalid credentials, missing permission, missing required field, throttling, exhausted retries, cancellation, and two requested sinks with one failing. Tests assert output artifacts and exit status, not just helper return values.
- When a Jira Cloud test tenant becomes available, its designated project passes create, readback, and identical rerun without duplicates. Returned key, evidence description, project, issue type, and configured parent are verified. An intentional rejection also produces a truthful run failure. Until then, report Cloud support as contract-tested with live acceptance pending; this does not block the Forgejo release.
- Data Center tests continue to pass; Cloud-specific assumptions do not change the Data Center dialect.
- A written diagnostic states the observed causes supported by local reproduction and available logs, and records that no personal Cloud tenant is available. A mock-only pass cannot establish live Cloud compatibility.

Starting points: `cmd/zap-kb/main.go`, `atlassian_cmd.go`, `atlassian_config.go`, `jira_sync.go`, and `internal/output/jira/{exporter.go,deployment.go,adf.go,pull.go}`.

Official behavior to verify during implementation: [Jira Cloud create and create-field metadata](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/) and [Atlassian token URL requirements](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account). Required fields vary by project and issue type; scoped tokens use the documented gateway URL.

**G2 — Enforce redaction across output boundaries**

Confirmed baseline: `-redact query,cookies,auth` scrubs a synthetic cookie from entities but leaves it in `run.json` raw alerts; preview logs retain a synthetic query marker.

Implementation work:

- Define a single output policy covering entities, raw alerts, run metadata, preview/error logs, Markdown, destination payloads, and ZIP members. Preserve an internal evidence representation and derive the authorized output view from it.
- Keep existing Forgejo default publication redaction at least as protective. Applying additional redaction must not silently disable sink defaults or alter identity/dedup keys.
- Make raw evidence retention explicit. Document compatibility when changing artifact defaults; a raw-retention choice must never silently negate requested redaction for a shared representation.
- Reject unknown redaction modes instead of accepting an apparent protection that does nothing. Preserve meaningful nonsensitive evidence and explain any intentional evidence omission.

Acceptance criteria:

- Synthetic cookie, authorization, query, body, header, note, and metadata markers are absent from every applicable emitted representation, including captured stdout/stderr and unzipped artifacts, when their mode is requested.
- Nonsensitive evidence, finding IDs, occurrence IDs, and scan labels remain useful and stable; input files remain unchanged unless an explicit persistence operation requires otherwise.
- The existing Forgejo redaction and ownership regressions pass. Include CLI round-trip tests and error-path redaction tests.

Starting points: `internal/entities/redact.go`, `internal/output/runartifact/`, `internal/output/ziputil/`, CLI preview/artifact creation, and `cmd/zap-kb/forgejo_sync.go`.

**G3 — Validate the evidence contract before side effects**

Confirmed baseline: `{}`, an unsupported `schemaVersion: v999`, and a finding with a missing definition reference all pass through `-entities-in` with exit 0.

Implementation work:

- Introduce a shared validation result for bare entities and run wrappers. Validate supported versions, nonempty/unique IDs, collection shape, foreign references, compatible timestamp fields, and wrapper/entity consistency.
- Define valid zero-finding scans separately from missing data. A declared, well-formed empty scan may be valid; an arbitrary empty object is not.
- Preserve documented compatibility normalizations, including external risk-code/header forms and current detection traces. Report applied normalizations where useful. Allow additive unknown fields only according to a documented forward-compatibility policy.
- Run validation before replacing persistent files, generating publishable views, or contacting destinations. Do not silently repair dangling references, invent findings, or coerce unsupported versions to v1.

Acceptance criteria:

- The three reproduced invalid inputs fail with location-specific diagnostics and zero destination writes; a preexisting valid output remains intact.
- Valid empty scans, definitions-only initialization, native ZAP data, supported legacy inputs, and representative Cactus/firing-range run artifacts still pass.
- Truncated JSON, trailing documents, duplicate IDs, mismatched wrapper versions, missing references, and wrong collection types have deterministic behavior tested through both import flags.
- A documented compatibility matrix accompanies the validator. Validation errors do not expose raw sensitive payloads.

Starting points: `internal/output/runartifact/runartifact.go`, `internal/entities/normalize.go`, entity types, `cmd/zap-kb/main.go`, and `docs/schema/entities-v1.md`.

**G4 — Connect and verify custom taxonomy enrichment**

Confirmed baseline: a definition matching the existing curated `zap-authenticated-basket-item-enumeration` entry exits the CLI without taxonomy although the helper test expects CWE 639. `EnrichCustomTaxonomy` is not called by the production pipeline. PR #94 is open and conflicted as of this review.

Implementation work:

- Reconcile [PR #94](https://github.com/Warlockobama/DevSecOpsKB/pull/94) against current main and reuse its relevant work after review. Verify each mapping against detection semantics and authoritative taxonomy sources.
- Specify enrichment order and ownership: scanner-native taxonomy, curated custom mappings, reviewed analyst/advisory values, and derived labels. Unknown custom rules must show incomplete context rather than inherit an unjustified classification.
- Normalize lookup aliases without silently changing stored definition/finding identity or creating duplicate remote issues. Any identity migration must have an explicit mapping and rerun strategy.
- Preserve attribution, mapping confidence, detection traces, and existing analyst fields through artifact and destination round trips.

Acceptance criteria:

- The exact failing CLI fixture receives the intended taxonomy in entities, run artifacts, and rendered output; helper-only assertions are insufficient.
- Fixtures cover current source-prefixed aliases, unmapped custom rules, ordinary numeric ZAP rules, already reviewed taxonomy, and repeat imports.
- Existing finding and occurrence identity remains stable unless a separately tested migration is selected. Native/custom definition separation remains intact.
- Reviewers can trace changed mappings to evidence; passing compilation alone does not approve taxonomy content.

Starting points: `internal/entities/{enrich.go,taxonomy.go}`, `internal/zapmeta/{custom_taxonomy.go,zapmeta.go}`, `cmd/zap-kb/main.go`, and taxonomy renderers.

**G5 — Make configuration precedence predictable**

Confirmed baseline: the nonempty localhost default prevents `ZAP_URL` from being applied. An explicit URL succeeds against the same controlled endpoint.

Implementation work:

- Resolve explicit flags first, environment second, defaults last. Track whether a flag was actually provided, especially for booleans, durations, and deliberately empty values.
- Consolidate configuration resolution and source reporting across CLI commands, helper scripts, and containers. Keep credential values out of diagnostics while showing whether they came from a flag or environment.
- Document the treatment of whitespace, malformed URLs, invalid deployment modes, and disabled destinations. Avoid silently guessing after a clearly invalid explicit setting.

Acceptance criteria:

- CLI tests prove default-only, environment-only, explicit override, and invalid-value behavior; the environment-only ZAP test reaches the intended mock.
- Tests verify Cloud gateway classification or explicit Cloud selection, Data Center selection, zero/false overrides, and the absence of secrets in resolved-config output.
- Container examples behave as documented without requiring redundant explicit flags to activate environment values.

Starting points: global flag registration, environment fallbacks, `atlassian_config.go`, and container entrypoints/examples.

**G6 — Review live publishing and establish large-wiki acceptance**

A live instance is necessary to measure actual service, storage, and network behavior. Local synthetic tests can establish request growth, correctness, and cancellation behavior but cannot establish production latency. Use the existing Kubernetes Forgejo sink when available. Live Jira Cloud/Confluence measurement is deferred because the owner has no personal Cloud tenant.

Read-only production review:

- Inventory the actual running images, resource limits, restart/OOM state, recent Job outcomes, scheduling overlap, and available metrics. Inspect sanitized recent publish summaries and failure messages.
- Identify the configured sink and compare it with the code and job arguments. Read metadata and measure a bounded sequence of health, issue-list, wiki-list, and a few existing wiki-page requests. Record endpoint class, status, duration, response size, and pagination counts; do not copy evidence bodies or secrets into the report.
- Bound requests, avoid concurrent expensive wiki listings, and stop escalation when the service is already unhealthy. Reuse the configured credentials only in the short-lived diagnostic process; stop every temporary loopback port-forward.
- Report issue publication and wiki publication independently. Do not overwrite the shared ingest file, round-trip workflow state, prune pages, or publish new analyst work as part of diagnosis.

Controlled acceptance after diagnosis:

- Exercise fresh publish, identical rerun, one-page change, 10% change, interruption/retry, and encoded cross-links at 100, 1,000, and 5,000 generated pages in a disposable local/test instance. Use a representative production-size case where different.
- Record total duration, stage duration, request count by method/endpoint, p50/p95 request latency, memory/CPU where available, rate-limit/retry counts, and remote mutations. Record image, storage type, resource allocation, page/body size, and concurrency with the results.
- An identical rerun must create no issues, issue duplicates, or wiki commits and must preserve page/link correctness. A one-page change should update only content whose rendered bytes actually change, including dependent indexes/links where required.
- Cancellation must stop scheduling work and return a truthful partial result; rerun must converge. Set a measured runtime budget comfortably within the configured schedule and whole-run deadline. Do not invent a production service-level promise from a mock benchmark.
- Prefer eliminating redundant work and improving observability over raising timeouts blindly. Derive optimization choices from the measured dominant stage.

Deliverable: [production publishing review](../production-publishing-review-2026-09.md), with confirmed observations, hypotheses, unavailable measurements, and a ranked performance backlog. Read-only measurement cannot prove write throughput; full publication acceptance requires the controlled test above or a separately scoped live canary.

Live review update, 12 September: the existing scheduled Forgejo has 2,047 tracked wiki files and 11,791 commits; a default-size listing exceeded the 20-second measurement budget while health and issue reads took milliseconds. A focused two-entry listing succeeded in about 3 seconds. The separate demo instance lists 50 of 1,346 pages in about 15.7 seconds. Both report Forgejo 9.0.3, and the scheduled publisher uses the August 9-tagged image. The detailed review separates these fresh observations from older throughput records. Add an isolated, backed-up upgrade comparison against a supported Forgejo release, current publisher-image provenance, and removal of redundant listing/history work to the performance backlog. The inspected newer LTS handler still performs per-page history lookups, so an upgrade alone is not a demonstrated performance fix. No live upgrade was performed during review.

**Demonstration outcome — firing range to a self-hosted evidence sink**

The primary product walkthrough should show a bounded authorized firing-range scan producing a versioned run artifact, the KB validating/enriching/redacting it, and Forgejo presenting grouped rule issues with links to evidence and scan history. A second identical publish should visibly produce no duplicates; a subsequent changed scan should demonstrate updated evidence or recurrence while retaining analyst decisions.

Reuse the existing Forgejo deployment and importer/exporter infrastructure. Inspect the firing-range producer's actual artifact path and schema, source/scan labels, detection traces, traffic coverage, and handoff before writing a new adapter. Keep the range's vulnerable targets separate from the public presentation endpoint. Show only intended, redacted demonstration evidence.

Demonstration acceptance: one documented command/job handoff, a recognizable landing/index page, rule-to-finding-to-occurrence navigation, useful evidence, visible run identity, truthful failure summaries, repeatability, and a portable artifact available even when the sink is down. Forgejo is the default hosting target; an additional sink needs a concrete capability gap to justify the integration cost.

Existing implementation to reuse: the companion firing-range repository already has `workers/kb-source`, `infra/k8s/kb-sink`, and `scripts/publish-to-forgejo-kb.ps1`. Its in-cluster path is controller run projections -> render/provenance gate -> KB merge -> atomic `/ingest/entities.json` handoff -> hourly issues and daily wiki. Validate this existing path before proposing another feed or sink.

**G7 — Maintainability and release completion**

Make small extractions while fixing behavior, then finish structural work after the regressions pass:

- Extract configuration resolution, input loading/validation, enrichment, artifact persistence, and sink orchestration from `main.go`. Pass one cancellation context through the run. Keep process exit at the top-level boundary.
- Use common stage results and sanitized diagnostics across Jira, Confluence, and Forgejo while retaining destination-specific API contracts. Separate immutable scan evidence from mutable publication references and analyst state.
- Split Obsidian rendering and Confluence export by responsibility: view construction, templates, local analyst preservation, remote transport/upsert, and indexes. Protect output compatibility with representative fixtures; avoid tests that merely reproduce private implementation details.
- Repair the obsolete Makefile/build-workflow e2e paths, explain which integration suites run per event, and add the CLI failure-contract suite to required checks. Update the architecture/README to include Forgejo and mark superseded plans accurately.
- Pin release/deployment images reproducibly and record the running revision. Add stage metrics and a common sanitized publish report so a future operator can identify the failing destination without reproducing it from scratch.

Overall completion requires goals G1–G5 to pass their available acceptance tests, G6 to have a measured report with explicit live-test limits, and the selected G7 extractions to preserve behavior. Track live Jira Cloud acceptance separately until a test tenant is available. Run the relevant tests, the full Go suite, vet, formatting, and build from `zap-kb`; run service integration suites in their designated environment. Keep a rollback path and input/artifact compatibility notes with the release. More importers or a new analyst UI are deferred until these reliability contracts hold.
