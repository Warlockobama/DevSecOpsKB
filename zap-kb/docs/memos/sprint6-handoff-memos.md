# Handoff Memos — Sprint 6 / run-20260403143540 Review

Generated: 2026-04-03
Source: SME review of Confluence sink output against firing-range Juice Shop scan.

---

## Memo 1 — To: Firing Range / nemoclaw-triage pipeline team

**Re: Severity misclassification — unauthenticated admin config endpoint**

During review of run `run-20260403143540`, the finding at `GET /rest/admin/application-configuration` was classified as **Medium / confirm** by the nemoclaw triage agent. This is incorrect.

The endpoint returns the full server configuration JSON unauthenticated, including internal base URL, domain, application name, and integration metadata. There are no auth headers in the request. An unauthenticated admin endpoint exposing server internals is functionally equivalent to credential/config disclosure and maps directly to **CWE-200 / A05:2021-Security Misconfiguration** at High severity.

The triage agent appears to weight HTTP status code and content-type over endpoint path semantics. A 200 JSON response at `/rest/admin/` with no `Authorization` header in the request should trigger automatic escalation regardless of content analysis.

**Ask:** Add an escalation rule to the nemoclaw severity classifier — any finding on a path matching `/admin/`, `/config`, `/internal/`, or `/actuator/` with an unauthenticated request (no `Authorization` or `Cookie` session header present) should be auto-elevated to **High / escalate**.

Contact: KB team via the DevSecOps KB repo issue tracker.

---

## Memo 2 — To: Threat Intelligence / Security Engineering team

**Re: CVSS scoring absent from High-severity Confluence pages**

The KB entities model (`internal/entities/entities.go`) has a `Taxonomy` struct that currently holds `CWEID`, `CWEURI`, OWASP Top 10, CAPEC IDs, and ATT&CK mappings. There is no CVSS field.

High-severity findings exported to Confluence display a risk lozenge (HIGH) with no CVSS score or exploitability context. Developers receiving escalate-tier tickets have no standard severity metric to prioritise against other engineering work and cannot feed the finding into a risk register or vulnerability management platform without manual CVSS scoring.

**Ask:** Provide one of the following so the KB can populate `Taxonomy.CVSSBase string` at enrichment time:

1. A CVSS base score mapping for the top ~50 ZAP plugin IDs and the most common Nuclei template IDs (CSV or JSON is fine), **or**
2. A read-only API endpoint that accepts a CWE ID or plugin ID and returns the CVSS base vector.

The KB enrichment pipeline (`internal/entities/enrich.go`) can consume either format. The field would be rendered as a Page Properties row on Confluence finding pages and included in the JSON entities output for downstream consumers.

Contact: KB team via the DevSecOps KB repo issue tracker.

---

## Memo 3 — To: Security Operations / Triage Workflow team

**Re: Body redaction hazard — escalate findings lose evidence in Confluence**

The KB `--redact` flag supports a `body` mode that zeros `BodySnippet` on all occurrences before export. If `--redact=body` (or any combination that includes `body`) is active during a Confluence vault export, the evidence field on occurrence pages is stripped.

This creates a specific hazard for the following finding class: **JWT Token Contains Password Hash** (`zap-jwt-password-hash-disclosure`). The proof of exploitation — the MD5 hash value `dd00510c9c75a85d9e43e1920b31d8e4` — exists only in `response.bodySnippet`. With body redaction active, the Confluence occurrence page shows a HIGH risk lozenge with the triage decision **escalate** but contains no supporting evidence. A developer receiving the ticket cannot verify the finding without access to raw scan artifacts.

The same hazard applies to any finding where the evidence string is derived from a response body snippet (SQLi error text, stack traces, leaked config values).

**Ask — Runbook update (immediate):** Add the following warning to the scan export runbook:

> ⚠ Do not use `--redact=body` when exporting escalate-tier findings to Confluence. Body redaction removes evidence from occurrence pages. Use `--redact=domain,auth,cookies` to protect PII while preserving evidence.

**Ask — KB team backlog (future sprint):** Implement a `--redact=body-except-evidence` mode that zeros `BodySnippet` globally but preserves it on occurrences where `Occurrence.Evidence` is derived from the body snippet. Filed as a future enhancement — the operations team should not wait for this before updating the runbook.

Contact: KB team via the DevSecOps KB repo issue tracker.

---

## Items deferred to KB Sprint 6

The following gaps from the SME review are within the KB team's scope but were too large for this sprint:

| Gap | Description | Planned Sprint |
|-----|-------------|---------------|
| G-2 | Endpoint-grouping "By Endpoint" summary page in Confluence | Sprint 6 |
| G-5 | Retest-due date derived from firstSeen + SLA on confirmed findings | Sprint 6 |
| G-6 (partial) | Multi-step reproduce sequences (`Reproduce.Steps` entity field added; Confluence rendering of steps as ordered list deferred) | Sprint 6 |

Items fixed in this sprint: G-1 (Source Tool in Page Properties), G-3 (Accepted Reason label on accept-risk occurrences), G-6 (scanner-provided curl preferred over synthesized), schema normalization for external pipeline imports.
