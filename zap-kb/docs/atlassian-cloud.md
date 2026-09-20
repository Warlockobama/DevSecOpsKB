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

## Configuration precedence

Each advertised setting resolves in this order: an explicit flag, its matching
environment variable, then the built-in default (where one exists). Whitespace
environment values are treated as unset. A supplied empty flag is deliberate:
for example, `-jira-url=` disables `JIRA_URL` for that invocation rather than
silently using it. The same rule prevents an explicit empty Jira credential
flag from using the shared Confluence credential fallback. This makes an
environment-configured destination easy to turn off in a local or container
command.

| Flag | Environment variable | Default |
|---|---|---|
| `-zap-url` | `ZAP_URL` | `http://127.0.0.1:8090` |
| `-api-key` | `ZAP_API_KEY` | unset |
| `-confluence-url` | `CONFLUENCE_URL` | unset |
| `-confluence-space` | `CONFLUENCE_SPACE` | unset |
| `-confluence-user` | `CONFLUENCE_USER` | unset |
| `-confluence-token` | `CONFLUENCE_TOKEN` | unset |
| `-confluence-deployment` | `CONFLUENCE_DEPLOYMENT` | `auto` |
| `-jira-url` | `JIRA_URL` | unset |
| `-jira-project` | `JIRA_PROJECT` | unset |
| `-jira-user` | `JIRA_USER` | falls back to Confluence user when unset |
| `-jira-token` | `JIRA_API_TOKEN` | falls back to Confluence token when unset |
| `-jira-deployment` | `JIRA_DEPLOYMENT` | `auto` |
| `-jira-server-id` | `JIRA_SERVER_ID` | unset |
| `-jira-server-name` | `JIRA_SERVER_NAME` | unset |
| `-forgejo-token` | `FORGEJO_TOKEN` | unset |

URL, space, and project values only use their matching environment variables;
the CLI does not infer Jira URL from Confluence URL. URLs must be absolute
`http` or `https` URLs. Deployment values must be `auto`, `cloud`, or
`datacenter` (with `dc` and `server` retained as aliases); an invalid explicit
value fails before network work begins. A destination with no resolved URL is
disabled. `atlassian check` prints the non-secret source labels for its targets
and credentials, never their credential values.

## Self-Hosted (Data Center / Server)

Both sinks also work against self-hosted Atlassian Data Center. The CLI
auto-detects the deployment from the URL (`*.atlassian.net` is Cloud, anything
else is Data Center); override with `JIRA_DEPLOYMENT` / `CONFLUENCE_DEPLOYMENT`
(`auto|cloud|datacenter`). Differences from Cloud:

- `CONFLUENCE_URL` has no `/wiki` suffix, e.g. `https://confluence.example.com`.
- Credentials are either username + password (Basic) or a personal access
  token: leave the user unset and put the PAT in the token variable — it is
  sent as a `Bearer` header. On Data Center the user is optional in
  `atlassian check` when a token is present.
- Jira uses REST v2 with wiki-markup issue descriptions (Cloud uses REST v3
  with ADF). Content is identical; only the serialization differs.
- `-jira-detection-epic` is not supported on Data Center (Cloud links Epic
  children via the `parent` field; DC classic projects use a per-instance
  Epic Link custom field). The exporter warns and creates flat findings.
- `-jira-user-map` values are Data Center usernames instead of Cloud
  accountIds.

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
