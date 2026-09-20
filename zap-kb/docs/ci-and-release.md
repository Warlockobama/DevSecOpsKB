# CI suites and release provenance

Run the commands in this document from `zap-kb/`. They use only fixtures or
ephemeral services unless a prerequisite is called out explicitly.

## Suite map

| Event | Required suites | Prerequisites | What it proves |
| --- | --- | --- | --- |
| Pull request and main push | `make test`, `make test-offline-e2e`, `make test-cli-contract`, formatting, vet, and a provenance build | Go version from `go.mod` | Go package regression coverage, the fixture-only vault/Confluence dry-run integration, and all CLI contract tests in `cmd/zap-kb` |
| Pull request and main push | `make test-wiki-scale` | Synthetic in-process HTTP fixture only | 100/1,000/5,000-page wiki fresh, no-op, change, cancellation, and recovery behavior; this is not a Forgejo throughput claim |
| Pull request and main push | `go test -tags e2e -count=1 -timeout 20m ./internal/e2e/forgejo/...` | Ephemeral Forgejo plus `E2E_FORGEJO_URL` and `E2E_FORGEJO_TOKEN`, supplied by `zap-kb-e2e.yml` | Forgejo API assumptions, retry, idempotency, redaction, and partial-outcome behavior |
| Pull request and main push | `kubeconform -strict -summary deploy/k8s/*.yaml` | Downloaded kubeconform binary | Kubernetes manifest schema only |
| Scheduled or manual `zap-kb-e2e.yml` | Disposable Kind cluster publisher job | Docker, Kind, kubectl, and an ephemeral Forgejo | The real CronJob image, ingest PVC seam, and an isolated publication path |
| Manual `zap-kb-smoke.yml` | Offline smoke; optional live-ZAP smoke | Fixture only; `ZAP_URL` and `ZAP_API_KEY` only when `run_live_zap=true` | Portable artifact generation and, when selected, a bounded ZAP API fetch |
| Manual `zap-kb-container-jira.yml` | Publisher image Jira contract | Local Docker only; an internal network, synthetic data, and synthetic credentials | Normal image entrypoint, environment-only Jira configuration, Cloud v3 create/readback, truthful rejected-create outcome, gateway routing, saved artifacts, and image revision identity |
| Manual credentialed browser check | `npm ci && npm test` in `tests/e2e/` | Designated Confluence test tenant, credentials, and approved fixture parent | Rendered Confluence pages in a real browser; it can create or update fixture pages and is never a default PR check |

`make test-offline-e2e` names the actual tagged package (`./e2e/...`); it is
not conditional. `make test-forgejo-e2e` names the service-dependent package
and deliberately fails if its required ephemeral-service environment is absent.
Do not replace a missing service with a skip: report that suite as unrun.

The suite names above are the initial release baseline. The pending failure
contracts from assignments 03–04 belong under `cmd/zap-kb`; the explicit
`make test-cli-contract` required step will collect them when those changes
land. Assignment 06's synthetic scale command is required because it is fast,
fixture-only, and bounded. Its Docker-backed disposable workload remains an
explicit local opt-in (`WIKI_DISPOSABLE=1`): it creates its own container and
volume and is not a default pull-request check. Passing either harness does not
establish readiness for a large production wiki; publication outcomes and the
documented live constraints still govern that decision.

`zap-kb-container-jira.yml` provides the **published-container contract** for
assignment 04. It builds `deploy/Dockerfile` from the reviewed tree, starts a
minimal Jira fixture on an internal-only Docker network, and invokes the normal
`zap-kb` entrypoint with Jira configuration supplied only through the container
environment. It asserts Cloud v3 create/readback, a nonzero rejected-create
result with sanitized run/summary artifacts, scoped-gateway Cloud routing, and
matching OCI/binary revisions. The integrated local candidate passes all three
cases; future failures are release blockers, never a reason to relax the harness.
Do not substitute a personal Jira tenant. The historical image review remains separate
in [published-image-jira-review-2026-09.md](published-image-jira-review-2026-09.md).

## Local verification

```bash
gofmt -l .
go vet ./...
make test
make test-offline-e2e
make test-cli-contract
make build VERSION=local REVISION="$(git rev-parse HEAD)"
./bin/zap-kb -version
```

The last command must show the reviewed commit in `revision=`. A local default
build reports `revision=unknown` only when Git metadata was unavailable; it
must not claim a guessed source revision.

## Release and rollback

1. Start from the reviewed commit and complete the required PR suites. Record
   its full SHA as `REVISION`.
2. Create and push a signed release tag. `zap-kb-release.yml` builds every
   archive with the tag, SHA, and commit timestamp. It also publishes
   `BUILD-INFO.txt` and checksums. Run `<archive>/zap-kb -version` after
   extraction to compare its revision with the reviewed SHA.
3. The image workflow passes the same SHA to `deploy/Dockerfile`, publishes OCI
   revision/version labels, and records the pushed manifest digest in its job
   summary. Use the digest, never a mutable tag, in an actual deployment:

   ```bash
   IMAGE=ghcr.io/<owner>/zap-kb-atlassian@sha256:<published-digest>
   kubectl -n <namespace> set image cronjob/<publisher> <container>="$IMAGE"
   ```

   This updates future Jobs; an existing Job's pod template is immutable.
   Validate a new canary Job in an isolated test destination using the reviewed
   input and state paths before enabling scheduled production publication. A
   canary copied from a production CronJob must have its destination and volumes
   changed before creation; otherwise it will publish to production.

   The canary binary's `-version` output must match the release SHA and its pod's
   configured image must be the recorded `@sha256:` reference. Record the
   runtime `imageID` too; for a multi-platform image, the platform manifest
   digest can differ from the pinned index digest. OCI labels can be inspected
   on the pulled platform image with `docker image inspect "$IMAGE"`.
4. Retain the previous reviewed `image@sha256` and its release SHA. To roll
   back, set the CronJob's container image to that exact prior digest and verify
   a new isolated canary. Updating a CronJob does not replace a running Job;
   coordinate any running publication separately to avoid overlapping writers.
   Do not roll back by retagging `latest`.

The checked-in Kubernetes example still uses a mutable demonstration image
reference because this change does not publish a new digest. A release operator
must patch it with the verified digest as shown above; assigning an invented
digest to the manifest would make it unusable.
