# Triage & Workflow (Obsidian)

- **Where to edit**: Front matter in occurrence files (and findings if needed). Fields: `analyst.status`, `analyst.owner`, `analyst.tags`, `analyst.notes`, `analyst.ticketRefs`, `analyst.updatedAt`.
- **Persistence**: Regeneration reads existing occurrence front matter first, so triage changes stick.
- **Statuses**: open | triaged | fp | accepted | fixed (roll up to INDEX/DASHBOARD/triage-board).
- **Link safety**: “Next actions” and some endpoints are neutered (no http/https) to avoid accidental clicks on live targets.
- **Redaction**: Run CLI with `-redact domain,query,cookies,auth,headers,body` (or a subset) to scrub sensitive fields before publishing.
- **Scan awareness**: Each occurrence carries `scan.label` and `observedAt`; identical alerts across scans stay separate if labels differ.
- **Quick refs**: `triage-board.md` shows status counts; `by-domain.md` shows per-domain rollups; findings list occurrences with status/seen dates.
