# Atlassian Cloud References

This project has published KB artifacts to Atlassian Cloud.

## Entry Points

- Atlassian site: `https://jameslerud.atlassian.net`
- Confluence Cloud: `https://jameslerud.atlassian.net/wiki`
- Jira issue URL pattern: `https://jameslerud.atlassian.net/browse/<KEY>`
- Observed Jira project key: `KAN`

## Confirmed Cloud Pages

- DevSecOps home: `https://jameslerud.atlassian.net/spaces/DEVSECOPS/overview`
- KB index, space `KB1`: `https://jameslerud.atlassian.net/spaces/KB1/pages/2850819/KB+Index`
- KB index, space `KB2`: `https://jameslerud.atlassian.net/spaces/KB2/pages/24117249/KB+Index`
- Definitions, space `KB1`: `https://jameslerud.atlassian.net/spaces/KB1/pages/2785490/Definitions`
- Security Rule Definitions, space `KB2`: `https://jameslerud.atlassian.net/spaces/KB2/pages/24412161/Security+Rule+Definitions`

## Confirmed Jira Access

- Atlassian API identity: `james.lerud` / `james.lerud@gmail.com`
- Visible Jira project: `KAN: DevSecOps`
- Recent observed issues include `KAN-203`, `KAN-204`, `KAN-208`, `KAN-209`, `KAN-210`, and epics `KAN-211`, `KAN-212`, `KAN-213`.

## Local Evidence

These local generated files contain references to the Atlassian Cloud tenant:

- `zap-kb/docs/obsidian/findings/*.md` include analyst case links such as `KAN-189`.
- `_ext_devsecopsfiringranve/exports/kb-publish/runs/run-20260412234358-243efbf0/publish-summary.json` records:
  - `confluence_url`: `https://jameslerud.atlassian.net/wiki`
  - `jira_url`: `https://jameslerud.atlassian.net`
- `_ext_devsecopsfiringranve/scripts/publish-to-confluence-via-kb.ps1` defaults `JiraUrl` to `https://jameslerud.atlassian.net`.

## Notes For Future Sessions

- Do not store API tokens, passwords, or Atlassian API keys in this file.
- If browser login is needed, open Confluence Cloud at `https://jameslerud.atlassian.net/wiki`.
- If looking for the published DevSecOps KB in Atlassian Cloud, start from Confluence search or the recent pages under the site above.
