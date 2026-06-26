# Standalone `zap-kb` container

A minimal, **sink-agnostic** image of the `zap-kb` CLI plus a portable Job
manifest you can drop into any Kubernetes cluster. Nothing here is tied to the
Forgejo stack in [`../../deploy/k8s`](../../deploy/k8s) — every behaviour is
chosen at run time via args/env, so the same image normalizes, enriches, dumps,
or publishes to any sink (Forgejo, Jira, Confluence, JSON).

| File | Purpose |
|------|---------|
| [`Dockerfile`](Dockerfile) | Minimal image: just the `zap-kb` binary on Alpine, non-root, no scanner |
| [`zap-kb-job.yaml`](zap-kb-job.yaml) | Self-contained ConfigMap + Secret + Job; offline self-test by default |

## How it differs from the other images

| Image | Base | Contains | Use |
|-------|------|----------|-----|
| `../Dockerfile` | OWASP ZAP | ZAP + `zap-kb` + scan scripts | scan **and** publish in one fat image |
| `../../deploy/k8s/Dockerfile` | Alpine | `zap-kb` | the Forgejo-coupled publisher CronJob |
| **`deploy/Dockerfile`** (this) | Alpine | `zap-kb` only | **portable**, sink chosen per-run |

## Build

From the module dir (`zap-kb/`):

```bash
docker build -f deploy/Dockerfile -t zap-kb:standalone .
```

Smoke-test it locally (offline, non-root, writes to `/work`):

```bash
docker run --rm zap-kb:standalone -h
docker run --rm -v "$PWD/out:/work" zap-kb:standalone \
  -init -format entities -plugins 10038,10020,10016 -out /work/entities.json
```

## Run in a pod

1. **Get the image to the cluster.** Either push to a registry and edit the
   `image:` in `zap-kb-job.yaml`, or load the local image:

   ```bash
   # kind:
   kind load docker-image zap-kb:standalone
   # docker-desktop's built-in k8s already sees local images (imagePullPolicy: IfNotPresent)
   ```

2. **Apply the Job.** The default args run an offline self-test — no external
   service needed:

   ```bash
   kubectl apply -f deploy/zap-kb-job.yaml
   kubectl wait --for=condition=complete job/zap-kb --timeout=120s
   kubectl logs job/zap-kb
   ```

   You should see `Init summary: defs total=… ` and the Job complete. That
   proves the image runs `zap-kb` in a pod.

3. **Do real work.** Edit the container `args` in `zap-kb-job.yaml` (a commented
   Forgejo publish block is included), fill the ConfigMap/Secret, and re-apply.
   For a real publish the pod needs an `entities.json` to read — mount a PVC at
   `/work` shared with whatever produced it (a scanner pod, or
   `kubectl cp`-ed in), instead of the `emptyDir`.

### Ad-hoc one-off (no manifest)

```bash
kubectl run zap-kb --rm -it --restart=Never --image=zap-kb:standalone -- \
  -init -format entities -plugins 10038 -out /work/entities.json
```

## Security posture

The manifest runs the container hardened: non-root (uid 65532),
`readOnlyRootFilesystem`, all capabilities dropped, `RuntimeDefault` seccomp.
Writes are confined to the mounted `/work` (outputs) and `/tmp` (a redacted
vault is staged here during `-forgejo-wiki` publish). Published content is
redacted by default; see the main docs for `-forgejo-redact`.
