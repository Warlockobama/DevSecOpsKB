# Curated taxonomy mapping evidence

Reviewed: 2026-09-12

This note records the evidence for custom-rule mappings changed by the G4
taxonomy integration. Lookup aliases never rewrite `pluginId`, `definitionId`,
`findingId`, or `occurrenceId`.

## Precedence

Taxonomy enrichment uses this order:

1. Imported taxonomy is retained unless its confidence is a known generated
   value: `scanner-cwe`, `curated`, `curated-cwe-derived`, or
   `unmapped-custom`. Historical blank, `high`, manual, analyst, advisory, and
   unknown confidence values are treated as owned data because older artifacts
   did not record field provenance consistently.
2. A curated mapping replaces taxonomy with a known generated confidence for a
   definition classified as `origin: custom`.
3. Native tool definitions retain scanner taxonomy. Curated custom mappings do
   not apply to `origin: tool`, even when a lookup alias happens to match.
4. Generic CWE-to-OWASP/CAPEC and MITRE reference expansion fill remaining
   fields after custom enrichment.
5. An unmapped custom rule receives the additive
   `taxonomy-unmapped-custom` tag. Imported classification fields remain intact;
   the gap list and tag carry the incomplete status separately.

## Authenticated object-access rules

The detector review separates direct object-reference behavior from collection
exposure:

| Stable slug | Historical lookup alias | Detector evidence |
| --- | --- | --- |
| `auth-basket-items-enumeration` | `authenticated-basket-item-enumeration` | The authenticated basket-items detector requests a collection. It can report multiple basket IDs without confirming a foreign user, so it remains unmapped. |
| `auth-basket-object-reference` | `authenticated-basket-object-reference-exposure` | The detector requests `/rest/basket/1` and reports only when the returned owner differs from the authenticated user. This is curated as CWE-639. |
| `auth-complaints-exposure` | `authenticated-complaints-exposure` | The detector requests the complaints collection and reports a record whose `UserId` differs. It preserves the producer's CWE-200 when present but is not upgraded to CWE-639. |
| `auth-user-directory-exposure` | `authenticated-user-directory-exposure` | The detector requests the users collection and reports a foreign user. It preserves the producer's CWE-200 when present but is not upgraded to CWE-639. |

The detector implementations are in the companion repository under
`workers/zap-worker/internal/worker.go` and
`workers/nuclei-worker/internal/worker.go`. The producer can emit legacy
`zap-...`, current `zap-...` or `nuclei-...`, and explicit
`custom-<source>-...` forms; only the metadata lookup key is normalized.

The curated object-reference mapping is:

- CWE-639, Authorization Bypass Through User-Controlled Key. MITRE describes an
  authenticated user accessing another user's record through a controllable
  record key, and lists the weakness in OWASP Top 10 2021 A01 Broken Access
  Control: <https://cwe.mitre.org/data/definitions/639.html>.
- CAPEC-122, Privilege Abuse. MITRE describes a lower-privileged account gaining
  access to sensitive information reserved for more trusted users:
  <https://capec.mitre.org/data/definitions/122.html>.
- OWASP Top 10 2021 A01 Broken Access Control, supported by the CWE-639 OWASP
  membership above.

ATT&CK remains unresolved for this rule. T1078 Valid Accounts concerns
obtaining or abusing credentials for access, persistence, privilege escalation,
or defense evasion. These detectors establish an object-authorization failure
with an authenticated test session; they do not establish credential
compromise: <https://attack.mitre.org/techniques/T1078/>. A narrow compatibility
migration removes the old generated singleton `T1078` only when the saved
confidence is exactly `curated`; imported or unknown-confidence ATT&CK data is
retained.

## PR 94 reconciliation

PR 94 was still open and conflicted on 2026-09-12 at commit `da0fdd1`. This
implementation reuses its lookup-only prefix normalization and current stable
slugs. It does not reuse the PR's unconditional taxonomy replacement or blanket
unmapped clearing because those operations could overwrite historical owned
values without field provenance. The baseline helper expectation of CWE-639 for
the basket-items collection was not treated as mapping evidence; that rule now
receives the explicit unmapped tag when no justified imported taxonomy exists.
