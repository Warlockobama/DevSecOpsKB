# DevSecOpsKB sink on Kubernetes (Forgejo)

Plain-manifest deployment of the **open-source Atlassian analog** for DevSecOpsKB:
a self-hosted **Forgejo** instance (issue tracker + wiki — replacing Jira +
Confluence) plus a **publisher CronJob** that pushes the normalized KB into it.

Everything lives in a greenfield `devsecops-kb` namespace and is labeled
`app.kubernetes.io/part-of: devsecops-kb` so it can later be wired into a firing
range and a link-intelligence service (see *Hooks* below).

## Why this shape

The sink consumes the **entities model** (`internal/entities`), which is
source-agnostic. So ZAP, YARA, Snort, or the Link Intelligence service all feed
the same publisher — each just writes a normalized `entities.json` into the
shared `kb-ingest` volume. No per-source sink code.

## Layout

| File | Purpose |
|------|---------|
| `00-namespace.yaml` | `devsecops-kb` namespace |
| `10-forgejo-pvc.yaml` / `11-forgejo-deployment.yaml` / `12-forgejo-service.yaml` | Forgejo sink target (issues + wiki) |
| `13-forgejo-ingress.yaml` | optional external UI access (disabled) |
| `20-kb-secret.yaml` | `FORGEJO_TOKEN` for the publisher |
| `21-kb-config.yaml` | publisher config (target repo, min-risk, ingest path) |
| `30-ingest-pvc.yaml` | shared **ingest** volume (the source integration seam) |
| `22-kb-cronjob.yaml` | the DevSecOpsKB publisher |
| `40-firing-range-netpol.yaml` | **hook**: egress to a firing-range namespace |
| `41-link-intel-source.yaml` | **hook**: link-intelligence source slot |
| `Dockerfile` | builds the publisher image |

## Build the publisher image

From the **repository root**:

```bash
docker build -f deploy/k8s/Dockerfile -t ghcr.io/warlockobama/devsecopskb:latest .
docker push ghcr.io/warlockobama/devsecopskb:latest   # or load into your cluster
```

## Deploy

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
kubectl apply -f deploy/k8s/            # applies the rest (commented hooks are no-ops)
kubectl -n devsecops-kb rollout status deploy/forgejo
```

## One-time Forgejo setup

The instance starts headless (install page locked, SQLite). Create an admin user
and a repo + wiki, then mint an API token:

```bash
# admin user
kubectl -n devsecops-kb exec deploy/forgejo -- \
  forgejo admin user create --username devsecops --admin \
  --email kb@example.com --password 'change-me'

# API token for the publisher
kubectl -n devsecops-kb exec deploy/forgejo -- \
  forgejo admin user generate-access-token --username devsecops \
  --scopes write:issue,write:repository --raw
```

Put the token in `20-kb-secret.yaml` (`FORGEJO_TOKEN`) and re-apply it. Create a
repo named `kb` under the `devsecops` owner (UI or API) and enable its Wiki.

## Publish

Drop a normalized entities file onto the ingest volume, then trigger the job:

```bash
# (any detection source can do this; here we copy a sample in by hand)
kubectl -n devsecops-kb cp ./entities.json \
  "$(kubectl -n devsecops-kb get pod -l app.kubernetes.io/component=publisher -o name | head -1)":/ingest/entities.json

kubectl -n devsecops-kb create job --from=cronjob/kb-publisher kb-publish-now
kubectl -n devsecops-kb logs job/kb-publish-now -f
```

You should see `Forgejo: created=… skipped=…` and `Forgejo wiki: created=…`.
Re-running is idempotent — findings dedup via a hidden marker on KB-managed
issues, and unchanged wiki pages are updated in place.

## Adding a detection source (the input contract)

A source integrates by writing the **entities model** to `/ingest/entities.json`
on the `kb-ingest` PVC — that's the entire contract. Minimal shape:

```json
{
  "schemaVersion": "v1",
  "sourceTool": "yara",
  "definitions": [{ "definitionId": "def-...", "pluginId": "...", "name": "..." }],
  "findings":    [{ "findingId": "fin-...", "definitionId": "def-...", "url": "...", "risk": "high" }],
  "occurrences": [{ "occurrenceId": "occ-...", "findingId": "fin-...", "url": "..." }]
}
```

Label source pods `devsecopskb.io/source: <name>` for observability.

## Hooks (wire in later)

- **Firing range** — uncomment `40-firing-range-netpol.yaml` and label your
  vulnerable-target namespace `app.kubernetes.io/part-of: firing-range` to allow
  scanner pods (labeled `devsecopskb.io/role: scanner`) to reach it.
- **Link Intelligence** — uncomment `41-link-intel-source.yaml` and point it at
  your service image; it just needs to emit `entities.json` into `kb-ingest`.
