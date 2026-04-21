# Entities Schema v1

Goals
- Tool-agnostic: ZAP today, expand to Burp, SAST/DAST later.
- Stable deterministic IDs for reproducibility.
- Avoid duplication by separating Definition (static) / Finding (endpoint) / Occurrence (instance).
- Support enrichment (CWE → MITRE CAPEC/ATT&CK/NIST/OWASP) and remediation guidance.
- Preserve room for request/response summaries and analyst notes.

Top-level
- schemaVersion: "v1"
- generatedAt: RFC3339 UTC
- sourceTool: e.g., "zap"
- definitions: shared metadata for a rule/check
- findings: grouped by (pluginId, url, method)
- occurrences: individual instances

IDs (deterministic, short)
- definitionId = "def-"+pluginId
- findingId = "fin-"+sha1_8(pluginId|url|method)
- occurrenceId = "occ-"+sha1_8(pluginId|url|method|param|riskcode|confidence|attack|evidence|scanLabel)
- `attack` and `evidence` are normalized before hashing to strip scanner-injected
  dynamic content (ISO timestamps, UUIDs, long hex runs, long digit runs). The
  raw values remain on the Occurrence for display; only the key input is
  sanitized so repeated scans of the same logical issue produce the same ID.

Definition
- definitionId
- pluginId
- origin: `tool|custom`
- alert, name, wascid
- taxonomy: { cweid, cweUri, capecIds[], attack[], owaspTop10[], nist80053[], tags[] }
- remediation: { summary, references[], guidance[], exampleFixes[], falsePositiveConditions[] }
- detection (optional): { logicType, pluginRef, ruleSource, docsUrl, sourceUrl, matchReason, summary, signals[], defaults{threshold,strength} }
- epicRef (optional): Jira Epic key grouping all findings for this detection; set by Jira export when `-jira-detection-epic` is enabled.

Definition rules
- `origin=tool` means the definition comes from the source scanner/tool.
- `origin=custom` means the definition is project-owned detection logic.
- Custom and tool definitions must not be merged solely because taxonomy or names overlap.

Finding
- definitionId, pluginId, url, method
- name (human-readable, e.g., "GET https://example.com/login")
- risk, riskcode, confidence (rollup)
- occurrenceCount
- firstSeen, lastSeen
- analyst { status, owner, tags[], notes, rationale, ticketRefs[], updatedAt, priorStatus, acceptedUntil, history[] } (optional)
- suppression { scope, reason, decidedBy, decidedAt, expiresAt, occurrenceRef } (optional)
- recurrence { priorStatus, recurredAt, recurredInScan } (optional; set by Merge when a previously fixed/accepted finding reappears)

Finding analyst conventions
- The finding is the primary analyst workflow object.
- `analyst.ticketRefs[]` stores analyst case references, not full Jira workflow state.
- `analyst.tags[]` may include `case-ticket` to opt low/info findings into Jira export.
- `analyst.tags[]` may include `tune-scan` to mark a recurring false positive for scan-tuning follow-up.

Analyst lifecycle fields (epic #71; additive, pipeline-owned)
- `analyst.priorStatus` — the `analyst.status` value immediately before the most recent transition. Populated by the pipeline (e.g. reopen-on-recurrence); not set by hand.
- `analyst.acceptedUntil` — RFC3339. Analyst *intent* for when an `accepted` disposition should lapse. When `status` transitions to `accepted`, the pipeline copies `acceptedUntil` into `suppression.expiresAt` (one-way flow: intent → enforced date). If they disagree after the copy, `suppression.expiresAt` is authoritative for enforcement.
- `analyst.history[]` — append-only audit trail. Each entry: `{ entryId, seq, scanLabel, status, priorStatus, owner, notes, updatedAt }`. `entryId` is `sha1(scanLabel|status|owner|notesHash)` so re-merging the same file is idempotent. `seq` is monotonic within a single scan to preserve order when `updatedAt` collides at second granularity.
- **Auto-reopen on recurrence** (slice 1b / issue #57): when `Merge()` detects new occurrences for a finding whose prior `analyst.status` is `fp` or `fixed`, it transitions `status` back to `open`, stashes the prior value on `analyst.priorStatus`, bumps `analyst.updatedAt` to the recurrence timestamp, inherits the prior `analyst.owner`, and appends a deterministic `AnalystHistoryEntry` (`notes="auto-reopened: recurrence in scan <label>"`). Re-merging the same entities file is idempotent — the history entry's `entryId` collapses duplicates. `accepted` findings get a `Recurrence` advisory but are **not** auto-reopened; that decision is time-bounded by `acceptedUntil` (slice 2).
- Inbound sync (Confluence pull, Jira pull) MUST NOT populate `priorStatus`, `acceptedUntil`, or `history`. These are the pipeline's internal audit trail; external systems do not have authority over them. Enforced by `pull_allowlist_test.go`.
- Obsidian YAML frontmatter MUST NOT surface these fields. Adding them would churn every vault markdown file on every scan (see `lifecycle_frontmatter_test.go`). History is rendered in Confluence page bodies instead (slice 2 of epic #71).
- `recurrence.priorStatus` mirrors `analyst.priorStatus` at the moment a recurrence is detected; `analyst.priorStatus` is the source of truth going forward.

Occurrence
- occurrenceId, definitionId, findingId
- scanLabel, observedAt
- name (human-readable, e.g., "GET /login param=user ev="..."")
- url, method, param, attack, evidence, other, risk, riskcode, confidence, sourceid
- request { headers[], rawHeader, rawHeaderBytes, bodyHash, bodyBytes, bodySnippet } (optional)
- response { statusCode, headers[], rawHeader, rawHeaderBytes, bodyHash, bodyBytes, bodySnippet } (optional)
- analyst { status, owner, tags[], notes, rationale, ticketRefs[], updatedAt, priorStatus, acceptedUntil, history[] } (optional; lifecycle fields follow the same rules as on findings)
- reproduce { curl, steps[] } (optional)

Occurrence rules
- Occurrences are scan-aware evidence records, not the primary workflow object.
- The same finding may have many occurrences across scans.

Large payloads
- By default, store only hashes and sizes for bodies; snippets are opt-in with future flags and redaction.

Enrichment
- A future enrichment step populates taxonomy mappings and expands remediation guidance.
- Optional detection enrichment can link a rule to its implementation and docs:
  - logicType: passive|active|unknown (inferred from rule path)
  - ruleSource: repo-like path in zap-extensions or `custom` for project-owned detection logic
  - sourceUrl: GitHub blob URL to the Java class
  - docsUrl: ZAP alert documentation page
  - summary/signals/defaults: best-effort hints parsed from the rule class (headers checked, regexes, threshold/strength)
