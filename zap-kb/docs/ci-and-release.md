# CI suites and release provenance

Run the commands in this document from `zap-kb/`. They use only fixtures or
ephemeral services unless a prerequisite is called out explicitly.

## Suite map

| Event | Required suites | Prerequisites | What it proves |
| --- | --- | --- | --- |
| Pull request and main push | `make test`, `make test-offline-e2e`, `make test-cli-contract`, formatting, vet, and a provenance build | Go version from `go.mod` | Go package regression coverage, the fixture-only vault/Confluence dry-run integration, and all CLI contract tests in `cmd/zap-kb` |
| Pull request and main push | `go test -tags e2e -count=1 -timeout 20m ./internal/e2e/forgejo/...` | Ephemeral Forgejo plus `E2E_FORGEJO_URL` and `E2E_FORGEJO_TOKEN`, supplied by `zap-kb-e2e.yml` | Forgejo API assumptions, retry, idempotency, redaction, and partial-outcome behavior |
| Pull request and main push | `kubeconform -strict -summary deploy/k8s/*.yaml` | Downloaded kubeconform binary | Kubernetes manifest schema only |
| Scheduled or manual `zap-kb-e2e.yml` | Disposable Kind cluster publisher job | Docker, Kind, kubectl, and an ephemeral Forgejo | The real CronJob image, ingest PVC seam, and an isolated publication path |
| Manual `zap-kb-smoke.yml` | Offline smoke; optional live-ZAP smoke | Fixture only; `ZAP_URL` and `ZAP_API_KEY` only when `run_live_zap=true` | Portable artifact generation and, when selected, a bounded ZAP API fetch |
| Manual credentialed browser check | `npm ci && npm test` in `tests/e2e/` | Designated Confluence test tenant, credentials, and approved fixture parent | Rendered Confluence pages in a real browser; it can create or update fixture pages and is never a default PR check |

`make test-offline-e2e` names the actual tagged package (`./e2e/...`); it is
not conditional. `make test-forgejo-e2e` names the service-dependent package
and deliberately fails if its required ephemeral-service environment is absent.
Do not replace a missing service with a skip: report that suite as unrun.

The suite names above are the initial release baseline. The pending failure
contracts from assignments 01–05 belong under `cmd/zap-kb`; the explicit
`make test-cli-contract` required step will collect them when those changes
land. The bounded benchmark/smoke command from assignment 06 has not been
specified yet, so no placeholder workflow silently passes in its place. Add it
only after 06 supplies its reproducible command, fixture, timeout, and expected
evidence.

The final release matrix also needs a **published-container contract** from
assignment 04. Build the `deploy/Dockerfile` image with the reviewed revision,
start 04's controlled Jira create/rejection stub on the same isolated network,
and invoke the image through its normal `zap-kb` entrypoint with only the
documented environment inputs. Assert both a successful create and a rejected
create's nonzero, sanitized outcome. This is distinct from a host `go run` or
`go test` pass: it verifies the image entrypoint, static binary, certificate
bundle, and environment-to-CLI configuration path actually used in a publisher
job. Do not substitute a personal Jira tenant. If the historical deployed tag
or digest becomes available, capture its `zap-kb -version` and run the same
bounded stub cases as a separate comparison; it is not evidence for the
reviewed source image.

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
   kubectl -n <namespace> set image job/<job> <container>="$IMAGE"
   kubectl -n <namespace> exec <pod> -- zap-kb -version
   ```

   The running binary's `revision=` must match the release SHA and the running
   image reference must be the recorded `@sha256:` digest. OCI labels can be
   read before deployment with `docker buildx imagetools inspect "$IMAGE"`.
4. Retain the previous reviewed `image@sha256` and its release SHA. To roll
   back, set the same workload container image to that exact prior digest, wait
   for the workload to become ready, then repeat `zap-kb -version`. Do not roll
   back by retagging `latest`.

The checked-in Kubernetes example still uses a mutable demonstration image
reference because this change does not publish a new digest. A release operator
must patch it with the verified digest as shown above; assigning an invented
digest to the manifest would make it unusable.
