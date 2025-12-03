# Analyst Guide (How to update findings/occurrences)

Where to edit
- Edit front matter (YAML at top) in occurrence files; findings inherit rollups automatically.
- Never change IDs (`id`, `occurrenceId`, `findingId`, `definitionId`) or `scan.label`/`observedAt`.

Fields to fill (add them if they are not present yet)
- `analyst.status`: open | triaged | fp | accepted | fixed (drives triage board and status chips).
- `analyst.owner`: your name/handle for queueing.
- `analyst.tags`: short labels for routing (e.g., “webapp”, “pci”, “p1”).
- `analyst.notes`: concise notes or investigation summary (markdown ok).
- `analyst.ticketRefs`: one or more ticket IDs (JIRA, etc.).
- `analyst.updatedAt`: set to an ISO/RFC3339 timestamp when you change status/notes (`2025-12-03T15:04:05Z`).

If the fields are missing, add a block like this to the occurrence front matter:
```yaml
analyst.status: open
analyst.owner: ""
analyst.tags: []
analyst.notes: ""
analyst.ticketRefs: []
analyst.updatedAt: ""
```
Then set the values as needed.

Optional context (only if you have verified it)
- `domain` override: use only if you know the sanitized domain label is wrong.
- Do not edit `url`, `risk*`, `observedAt`, or traffic blocks unless you are correcting a clear extraction error.

How to use statuses
- `open`: default/untriaged.
- `triaged`: validated, awaiting remediation ticket.
- `fp`: false positive; add a short note in `analyst.notes` and a ticket reference if required.
- `accepted`: risk acknowledged; include justification in `analyst.notes` and a ticket reference.
- `fixed`: verified remediated; note evidence in `analyst.notes`.

Quick workflow
1) Set `analyst.status`, `analyst.owner`, and `analyst.updatedAt`.
2) Add `analyst.ticketRefs` when you file/attach to a ticket.
3) Add a brief `analyst.notes` (what you validated, evidence, next step).
4) Leave IDs, timestamps (`observedAt`), and `scan.label` untouched.

Safety notes
- Links in “Next actions” may be neutered; use the traffic snippets and curl repro carefully in non-production test contexts.
- If redaction is enabled, do not attempt to restore redacted hosts/queries in the vault.
