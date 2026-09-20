# 10 — Demonstrate the firing-range feed and prepare workplace adoption

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Sol / Medium** (`gpt-5.6-sol`, reasoning `medium`). This is a recommendation; select it in task settings.

Parent coverage: Demonstration outcome and G1 workplace acceptance. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

Forgejo is the owner's self-hosted showcase. The existing companion has kb-source, Kubernetes sink manifests, and a host publication script. Jira/Confluence is intended for workplace DAST without requiring deployment of the firing range there.

Model rationale: The infrastructure already exists and the acceptance flow is explicit. Integration debugging can escalate, while verified prose can be polished with Luna if useful.

## Dependencies and ownership

01–09 available local acceptance complete before end-to-end signoff. Draft the walkthrough and test prerequisites earlier. Live workplace acceptance requires designated tenant access.

Starting paths: Main repository usage/concepts/release docs and bounded integration fixtures. Companion `F:/projects/devsecopsfiringranve`: `workers/kb-source/`, `infra/k8s/kb-sink/`, and `scripts/publish-to-forgejo-kb.ps1`.

## Assigned work

- Reuse the existing producer/provenance/merge/publication path and the state contract from 07. Provide one documented command or Job handoff in an isolated demo setup; do not create a second scanner adapter without a demonstrated gap.
- Show a representative authorized scan artifact arriving in Forgejo as grouped cases and evidence with run identity, rule/finding/occurrence links, and useful scan history.
- Demonstrate an identical rerun, a changed scan, retained analyst decisions, and a destination failure with portable local evidence and an honest outcome.
- Make the landing page concise with drill-down navigation. Document intended external URL, HTTPS/access setup, and separation of vulnerable range targets from the presentation endpoint; do not publish the service externally as part of writing the runbook.
- Prepare workplace steps for an existing DAST report: test project/space, metadata/permissions, redaction, Jira workflow, Confluence analyst blocks, cross-links, repeat publish and partial failure. Use 04's verified API behavior.
- Use a disposable instance for write acceptance. If no tenant exists, complete the local walkthrough and runnable workplace procedure while leaving tenant acceptance pending.

### Product clarification from the owner

The workplace goal is triage where developers already work: Jira/Confluence,
with detection history, earlier instances, prior decisions and supporting
evidence readily available. A later experiment will compare human-only,
LLM-only and human-with-LLM triage. The agent may use an Atlassian connector to
investigate the published issues and pages. A separate database is not a
prerequisite and is not an implementation requirement for this pack.

Prepare the pilot around connector-readable page bodies, explicit evidence and
history links, and a clear distinction between an AI recommendation and an
accepted analyst decision. Check what information an API reader receives when
a browser normally renders a macro; required context must remain retrievable.
Keep immutable JSON artifacts for replay and record consulted issue/page
versions in the proposed evaluation procedure. Evaluation implementation is a
future phase; this assignment prepares its prerequisites without contacting a
workplace tenant or changing workflow automatically.

The owner believes the workplace uses Amazon Bedrock; its exact agent application
and connector support are unconfirmed. Keep the pilot independent of model
provider. A Bedrock-hosted model plus an MCP-capable agent and Atlassian connector
is a candidate integration, not a verified workplace setup. Record the chosen
model/version and tool-access configuration when the evaluation is implemented.

## Acceptance evidence

- A clean operator can follow the documented demo using the stated revisions/configuration. Record actual artifact-to-issue/wiki readback, not just a successful Job status.
- Repeat and changed runs behave as intended without duplicates or analyst loss. Failure leaves usable sanitized evidence.
- The walkthrough names measured wiki limits and links to 06's results. It does not claim unmeasured production throughput.
- Workplace status clearly separates local mocks from designated-tenant results. No personal Cloud subscription is required to mark the Forgejo demonstration locally complete.

## Escalation and handoff

Escalate to Sol High for integration debugging. Route new validation/redaction/identity defects to their owning assignment, and architectural changes to Astra High. More effort cannot replace unavailable tenant access.

Deliver reproducible demo procedure and observed readback, concise landing/navigation improvements, workplace pilot procedure, and an honest readiness table. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
