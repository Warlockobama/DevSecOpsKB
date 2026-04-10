# Analyst Guide (How to update findings/occurrences)

Where to edit
- Edit finding pages for primary workflow state only when you are intentionally using a Confluence-driven workflow.
- In the Jira-integrated path, treat Confluence as read-oriented evidence and Jira as workflow.
- Occurrence pages remain useful for scan-specific notes and evidence.
- Never change IDs (`id`, `occurrenceId`, `findingId`, `definitionId`) or `scan.label`/`observedAt`.

Fields to fill
- `analyst.status`: `open | triaged | fp | accepted | fixed`.
- `analyst.owner`: your name/handle for queueing.
- `analyst.tags`: routing and workflow tags.
- `analyst.notes`: concise notes or investigation summary (markdown ok).
- `analyst.ticketRefs`: analyst case references or other linked tracking IDs.
- `analyst.updatedAt`: set to an ISO/RFC3339 timestamp when you change status/notes (`2025-12-03T15:04:05Z`).

Recommended tags
- `case-ticket`: export a low/info finding into the analyst Jira project. Medium/high findings are exported automatically.
- `tune-scan`: mark a recurring false positive for detection-tuning follow-up.

If the fields are missing, add a block like this to the finding or occurrence front matter:
```yaml
analyst.status: open
analyst.owner: ""
analyst.tags: []
analyst.notes: ""
analyst.ticketRefs: []
analyst.updatedAt: ""
```

How to use statuses
- `open`: default/untriaged.
- `triaged`: validated and ready for analyst case management.
- `fp`: false positive. Add a short note. If it recurs and needs scanner tuning, add `tune-scan`.
- `accepted`: risk acknowledged; include justification in `analyst.notes`.
- `fixed`: verified remediated; note evidence in `analyst.notes`.

Quick workflow
1. Update the finding-level `analyst.status`, `analyst.owner`, and `analyst.updatedAt`.
2. Add `case-ticket` in `analyst.tags` if a low/info finding should still become an analyst Jira case.
3. Add `tune-scan` in `analyst.tags` if a recurring false positive needs detection-tuning follow-up.
4. Add `analyst.ticketRefs` when you file or link a case or follow-up item.
5. Add a brief `analyst.notes` summary.
6. Leave IDs, `observedAt`, and `scan.label` untouched.

Safety notes
- Links in “Next actions” may be neutered; use the traffic snippets and curl repro carefully in non-production test contexts.
- If redaction is enabled, do not attempt to restore redacted hosts/queries in the vault.
