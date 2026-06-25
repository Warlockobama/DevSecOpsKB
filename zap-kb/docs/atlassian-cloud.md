# Atlassian Cloud References

This project can publish KB artifacts to Atlassian Cloud through the
Confluence and Jira REST APIs.

## Required Configuration

- `CONFLUENCE_URL`: Confluence base URL, normally `https://<tenant>.atlassian.net/wiki`.
- `CONFLUENCE_USER`: Atlassian account email used for Confluence API calls.
- `CONFLUENCE_TOKEN`: Atlassian API token for Confluence API calls.
- `CONFLUENCE_SPACE`: target Confluence space key, for example `KB2`.
- `JIRA_URL`: Jira site URL, normally `https://<tenant>.atlassian.net`.
- `JIRA_PROJECT`: Jira project key used for analyst cases.
- `JIRA_USER`: optional Atlassian account email used for Jira API calls. When unset, the CLI falls back to `CONFLUENCE_USER`.
- `JIRA_API_TOKEN`: optional Atlassian API token for Jira API calls. When unset, the CLI falls back to `CONFLUENCE_TOKEN`.
- `JIRA_SERVER_ID`: optional Confluence application-link UUID for rendering the live Jira Issues macro.
- `JIRA_SERVER_NAME`: optional Confluence application-link display name for rendering the live Jira Issues macro.

Flags override environment variables. URL, space, and project values only use
their matching environment variables; the CLI does not infer Jira URL from
Confluence URL.

## Supported Publish Flow

Run a redacted readiness check before publishing:

```powershell
go run ./cmd/zap-kb atlassian check
```

The check prints JSON with `ready`, `missing`, target identifiers, and credential
source labels. It never prints usernames or tokens. A host with one shared
Atlassian token can set `CONFLUENCE_USER` and `CONFLUENCE_TOKEN`, then omit
`JIRA_USER` and `JIRA_API_TOKEN`.

Publish through the Atlassian sink with the PowerShell helper:

```powershell
.\scripts\kb.ps1 publish-atlassian -Entities docs\data\entities.json
```

The existing `publish` task remains a local Obsidian render. Use
`publish-atlassian` for Confluence publishing, Jira issue export, Jira status
pull, evidence-link sync, and a redacted publish summary.

## Stable Entry Points

- Confluence Cloud: `https://<tenant>.atlassian.net/wiki`
- Jira issue URL pattern: `https://<tenant>.atlassian.net/browse/<KEY>`
- KB index URL pattern: `https://<tenant>.atlassian.net/spaces/<SPACE>/pages/<PAGE_ID>/<PAGE_TITLE>`

## Local Evidence

Generated publish summaries may contain the active Atlassian tenant and project
used for a run, but not usernames or tokens. Look under the configured publish
output root for:

- `exports/kb-publish/runs/<run-id>/publish-summary.json`
- `exports/kb-publish/campaigns/<campaign-id>/publish-summary.json`

Generated Obsidian finding pages can also contain analyst ticket references in
frontmatter or the `Analyst Cases` property.

## Notes For Future Sessions

- Do not store API tokens, passwords, account emails, tenant names, or private page IDs in this file.
- Prefer environment variables or local ignored helper scripts for tenant-specific defaults.
- For KB2 work, inspect only the configured KB2 Confluence space unless the user explicitly broadens scope.
- Jira should remain the workflow source of truth; the KB should link to Jira cases and published evidence without mirroring live ticket status by default.
