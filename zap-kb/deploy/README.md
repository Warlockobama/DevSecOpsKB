# `zap-kb` — ZAP → Atlassian publisher image

A minimal image of the `zap-kb` CLI for one job in your DAST pipeline: run it
**after a ZAP scan**, pull the results, and init/update the **Jira** and
**Confluence** sinks (findings → Jira issues, KB → Confluence). It carries no
scanner — point it at a live ZAP API or a saved ZAP report.

| File | Purpose |
|------|---------|
| [`Dockerfile`](Dockerfile) | The image: static `zap-kb` binary on Alpine, non-root, ~32 MB |
| [`zap-kb-atlassian-job.yaml`](zap-kb-atlassian-job.yaml) | Post-scan publish Job (ConfigMap + Secret + Job, with an `atlassian check` preflight) |

## Image reference

| | |
|---|---|
| **Base / size** | `alpine:3.20`, ~32 MB |
| **User** | `65532` (`kb`), non-root |
| **Workdir** | `/work` (mount a volume for outputs) |
| **Entrypoint / CMD** | `zap-kb` / `-h` |
| **Preflight** | `zap-kb atlassian check` — redacted publish-readiness JSON (exit 1 if not ready) |
| **Ports** | none (one-shot CLI) |
| **Included** | static `zap-kb` binary, `ca-certificates` (HTTPS to Atlassian Cloud), `tzdata` |
| **Platform** | `linux/amd64` (rebuild with `buildx --platform` for arm64) |

## Build

From the module dir (`zap-kb/`):

```bash
docker build -f deploy/Dockerfile -t zap-kb:atlassian .
# pin Go: --build-arg GO_VERSION=1.24   multi-arch: docker buildx build --platform linux/amd64,linux/arm64 ...
```

Push and pin by digest for reproducible deploys:

```bash
docker tag zap-kb:atlassian ghcr.io/<org>/zap-kb-atlassian:1.0.0
docker push ghcr.io/<org>/zap-kb-atlassian:1.0.0
```

**CI:** [`.github/workflows/zap-kb-image.yml`](../../.github/workflows/zap-kb-image.yml)
builds this image (multi-arch `linux/amd64,linux/arm64`) and pushes it to
`ghcr.io/<owner>/zap-kb-atlassian` on a `v*` tag or manual *Run workflow*. Pull
the published image with:

```bash
docker pull ghcr.io/warlockobama/zap-kb-atlassian:latest
```

## Configuration (environment)

Targets and credentials come from env (a ConfigMap + Secret); flags override env.
Setting `JIRA_URL` enables the Jira sink; setting `CONFLUENCE_URL` enables
Confluence.

| Env var | For | Notes |
|---------|-----|-------|
| `ZAP_URL` | input | Live ZAP API base (default `http://127.0.0.1:8090`) |
| `ZAP_API_KEY` | input | ZAP API key, if the daemon enforces one |
| `JIRA_URL` | Jira | **Enables** Jira issue export |
| `JIRA_PROJECT` | Jira | Project key (e.g. `SEC`) |
| `JIRA_USER` | Jira | Account email; falls back to `CONFLUENCE_USER` |
| `JIRA_API_TOKEN` | Jira | API token; falls back to `CONFLUENCE_TOKEN` |
| `CONFLUENCE_URL` | Confluence | **Enables** Confluence export (`…/wiki`) |
| `CONFLUENCE_SPACE` | Confluence | Target space key |
| `CONFLUENCE_USER` | Confluence | Account email |
| `CONFLUENCE_TOKEN` | Confluence | API token |
| `JIRA_SERVER_ID` / `JIRA_SERVER_NAME` | Confluence | Optional — render the live Jira macro on the Triage Board page |
| `JIRA_DEPLOYMENT` | Jira | `auto`\|`cloud`\|`datacenter`; auto-detects `*.atlassian.net` as cloud |
| `CONFLUENCE_DEPLOYMENT` | Confluence | Same values; controls whether the user is required (see below) |

Behavior flags: `-include-mitre` (default on), `-include-traffic`,
`-confluence-full`, `-jira-min-risk`, `-jira-detection-epic`,
`-{jira,confluence}-dry-run`, `-publish-summary-out`. Full list: `docker run --rm zap-kb:atlassian -h`.

For a disposable CI workspace, publish each completed ZAP scan directly with a
unique `-scan-label` and `-confluence-full`. Do not pass an earlier KB file via
`-entities-in`: that selects enrich-only input and skips the live ZAP fetch.
The Atlassian exporters look up existing Jira findings and Confluence pages
remotely; the Scans page retains earlier scan rows across runs. An identical
scan-label rerun replaces that scan's row rather than adding another run.
Definition pages omit an all-time open-finding count until a Jira-backed count
is available; finding and export-summary counts are explicitly per export.

HTTP traffic is stored as code blocks. `-traffic-max-bytes` defaults to 2048
for ordinary request/response snippets, and all captured bodies now have a
hard 16 KiB ceiling (including high/critical responses and `0` input).
The occurrence-count controls apply in `-traffic-scope first`; `all` enriches
every occurrence. Use both the scope and count controls for bounded CI runs.

## Examples

### ZAP input — two ways

```bash
# (a) live ZAP daemon still up after the scan:
zap-kb -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY"  ...publish flags...

# (b) a saved ZAP alerts report exported by the scan step:
zap-kb -in /work/zap-alerts.json                    ...publish flags...
```

### Atlassian publish (full command)

```bash
docker run --rm -v "$PWD/work:/work" \
  -e ZAP_URL -e ZAP_API_KEY \
  -e JIRA_URL -e JIRA_PROJECT \
  -e CONFLUENCE_URL -e CONFLUENCE_SPACE -e CONFLUENCE_USER -e CONFLUENCE_TOKEN \
  zap-kb:atlassian \
  -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY" \
  -include-mitre -include-traffic \
  -format obsidian -obsidian-dir /work/vault \
  -confluence-full -jira-min-risk medium \
  -publish-summary-out /work/publish-summary.json
```

Outputs under `/work`: `entities.json` (normalized KB), `vault/` (rendered
pages), `publish-summary.json` (redacted run summary).

### Self-hosted Jira/Confluence (Data Center)

The same image publishes to self-hosted Atlassian — e.g. `jira.example.com` +
`confluence.example.com`. Deployment is auto-detected from the URL (anything
that isn't `*.atlassian.net` is treated as Data Center):

```bash
docker run --rm -v "$PWD/work:/work" \
  -e JIRA_URL=https://jira.example.com -e JIRA_PROJECT=SEC \
  -e CONFLUENCE_URL=https://confluence.example.com -e CONFLUENCE_SPACE=SECKB \
  -e JIRA_API_TOKEN -e CONFLUENCE_TOKEN \
  zap-kb:atlassian \
  -in /work/zap-alerts.json \
  -out /work/entities.json -jira-min-risk medium
```

Data Center notes:

- **No `/wiki` suffix** on `CONFLUENCE_URL` — that's a Cloud path.
- **Auth**: either set the user vars for Basic username+password, or leave the
  user vars **unset** and supply a personal access token — it is sent as
  `Authorization: Bearer`. `atlassian check` does not require the user on
  Data Center.
- Jira issues are created via REST v2 with wiki-markup descriptions
  (identical content to the Cloud ADF bodies).
- `-jira-detection-epic` is Cloud-only; on Data Center the exporter warns and
  creates flat findings.

### Rehearse first (no writes)

```bash
zap-kb atlassian check                         # readiness JSON, exit 1 if creds/targets missing
zap-kb ...same publish flags... -jira-dry-run -confluence-dry-run
```

## Run in the pipeline (Kubernetes)

ZAP runs as a long-lived daemon Service; your pipeline runs the scan, then fires
this Job as the next stage. Edit the targets/creds in the manifest, then:

```bash
kubectl apply -f deploy/zap-kb-atlassian-job.yaml          # ConfigMap + Secret + Job
kubectl wait --for=condition=complete job/zap-kb-publish --timeout=300s
kubectl logs job/zap-kb-publish
# re-run per scan:
kubectl create job --from=job/zap-kb-publish zap-kb-publish-$(date +%s)
```

The `atlassian check` initContainer fails the Job fast (redacted readiness
report) if any target/credential is missing, before any publish call.

> A normal ZAP scan (`sourceTool: zap`) publishes as-is. A `zap-agent` or
> custom-definition input additionally needs `-allow-agent-publish` /
> `-allow-custom-publish`. See [`../docs/atlassian-cloud.md`](../docs/atlassian-cloud.md).

## Security

Hardened by the manifest: non-root (uid 65532), `readOnlyRootFilesystem`, all
capabilities dropped, `RuntimeDefault` seccomp; writes confined to mounted
`/work` and `/tmp`. The image is just a static binary + CA certs. The publish
summary is redacted (names the tenant/project, never usernames or tokens). Keep
tokens in a Secret or external secret manager — never in the image or ConfigMap.

## Exit codes

`0` success · non-zero on publish failure (a **partial** publish fails the run,
not a green no-op) or `atlassian check` not-ready · `2` flag/usage error.
