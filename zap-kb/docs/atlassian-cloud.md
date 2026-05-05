# Atlassian Cloud References

This project can publish KB artifacts to Atlassian Cloud through the
Confluence and Jira REST APIs.

## Required Configuration

- `CONFLUENCE_URL`: Confluence base URL, normally `https://<tenant>.atlassian.net/wiki`.
- `CONFLUENCE_USER`: Atlassian account email used for Confluence API calls.
- `CONFLUENCE_TOKEN`: Atlassian API token for Confluence API calls.
- `CONFLUENCE_SPACE`: target Confluence space key, for example `KB2`.
- `JIRA_URL`: Jira site URL, normally `https://<tenant>.atlassian.net`.
- `JIRA_USER`: Atlassian account email used for Jira API calls. Falls back to `CONFLUENCE_USER` in some helper scripts.
- `JIRA_API_TOKEN`: Atlassian API token for Jira API calls. Falls back to `CONFLUENCE_TOKEN` in some helper scripts.
- `JIRA_PROJECT`: Jira project key used for analyst cases.
- `JIRA_SERVER_ID`: optional Confluence application-link UUID for rendering the live Jira Issues macro.
- `JIRA_SERVER_NAME`: optional Confluence application-link display name for rendering the live Jira Issues macro.

## Stable Entry Points

- Confluence Cloud: `https://<tenant>.atlassian.net/wiki`
- Jira issue URL pattern: `https://<tenant>.atlassian.net/browse/<KEY>`
- KB index URL pattern: `https://<tenant>.atlassian.net/spaces/<SPACE>/pages/<PAGE_ID>/<PAGE_TITLE>`

## Local Evidence

Generated publish summaries may contain the active Atlassian tenant and project
used for a run. Look under the configured publish output root for:

- `exports/kb-publish/runs/<run-id>/publish-summary.json`
- `exports/kb-publish/campaigns/<campaign-id>/publish-summary.json`

Generated Obsidian finding pages can also contain analyst ticket references in
frontmatter or the `Analyst Cases` property.

## Notes For Future Sessions

- Do not store API tokens, passwords, account emails, tenant names, or private page IDs in this file.
- Prefer environment variables or local ignored helper scripts for tenant-specific defaults.
- For KB2 work, inspect only the configured KB2 Confluence space unless the user explicitly broadens scope.
- Jira should remain the workflow source of truth; the KB should link to Jira cases and published evidence without mirroring live ticket status by default.
