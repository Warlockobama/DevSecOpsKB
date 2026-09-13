# 04 — Repair Jira publication and report every sink outcome honestly

Status: ready to assign, subject to the dependencies below.

Model: **GPT-6 Astra / High** (`gpt-6-astra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G1 and the G7 shared publication-result contract. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

A mocked Jira Cloud create returns HTTP 400; the summary counts one error but the CLI exits 0 and discards useful per-create error detail. Existing readiness checks inspect configuration, not remote readiness. The owner has no personal Cloud tenant.

Model rationale: This combines real API contracts, ambiguous creates, deduplication, partial success, cancellation, and process-level behavior. A status-code-only patch would leave the reported Jira problem unresolved.

## Dependencies and ownership

01 and 03 before final integration. API fixtures and result-contract design can begin earlier; expose the result interface to 06 and 07 promptly.

Starting paths: `cmd/zap-kb/main.go`, `atlassian_cmd.go`, `atlassian_config.go`, `jira_sync.go` under `cmd/zap-kb/`, `internal/output/jira/`, and shared publication helpers where warranted.

## Assigned work

- Introduce a common result for explicitly requested destinations: successful, partial, failed, or deliberately skipped. Persist available artifacts and sanitized failure details, then return nonzero for required failure after unrelated requested work has had its defined chance to finish.
- Retain finding ID, stage, status/category, retryability, and actionable required-field diagnostics. Reuse 03's sanitization policy and keep process exit at the top level.
- Verify current official Atlassian contracts for site and scoped-token gateway URLs, API versus browser URLs, Cloud detection, ADF, project/issue-type metadata, required fields, parent/component/assignee behavior, and supported auth methods. Preserve Data Center behavior.
- Do not create after a failed dedup lookup. Classify rejection/auth/permission/not-found, rate limiting, transient server failures, and transport failures. Reconcile an ambiguous create outcome before retrying.
- Add bounded optional remote readiness checks with clear permission requirements. Keep configuration completeness distinct from publish readiness.
- Cover Jira-owned workflow, preserved Confluence analyst blocks and cross-links, and partial success when either workplace destination fails. 10 owns the later walkthrough/live pilot.

## Acceptance evidence

- Rejected create returns nonzero and identifies the failed finding and useful sanitized cause; evidence remains available.
- CLI tests cover all-success, one/all destinations failed, failed lookup, invalid credentials, permissions, missing required field, 429, exhausted retries, ambiguous create, cancellation, and persisted output.
- Cloud gateway and site URLs select the correct dialect without breaking Data Center. Readiness output states exactly what was checked.
- Prepare a designated-tenant create/readback/repeat/no-duplicate and intentional-rejection procedure. Execute it only when test access is available; record local contract completion and live Cloud acceptance separately.

## Escalation and handoff

Escalate effort for an unresolved API/identity/retry invariant with a concrete trace. Missing tenant access is an external acceptance limit, not a reason to guess or spend more reasoning.

Deliver observed local causes, shared result interface, API/compatibility decisions, CLI acceptance evidence, and a runnable workplace test procedure with pending access stated explicitly. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
