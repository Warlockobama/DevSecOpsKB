# Adversarial E2E: Forgejo sync layer

This suite exists to **find where the sync layer breaks**, not to confirm it
works. Every test attacks one assumption the implementation makes that the
environment does not guarantee (see the test-file headers in
`zap-kb/internal/e2e/forgejo/`).

## Layout

| Where | What |
|---|---|
| `zap-kb/internal/e2e/forgejo/` | the tagged (`-tags e2e`) suite, organized by attacked assumption |
| `zap-kb/internal/e2e/forgejo/harness/` | per-test ephemeral repos, fault-injection proxy, fixtures, CLI runner |
| `zap-kb/internal/e2e/deploypolicy/` | untagged manifest policy tests (run in every `go test ./...`) |
| `test/e2e/e2e-job.yaml` | Tier-1 as an in-cluster pod (Forgejo sidecar + provision + runner) |
| `.github/workflows/zap-kb-e2e.yml` | CI: per-PR Tier 1 + kubeconform; nightly kind CronJob run |

## Test ↔ assumption map

| File | Attacks |
|---|---|
| `idempotency_test.go` | A1 label-name dedup query, A2 marker round-trip, A3 wiki no-op republish, A4 stable ticket refs |
| `conflict_test.go` | A5 create-only issue content freeze (pinned drift), A6 KB-wins wiki clobber |
| `partial_test.go` | A8 crash-mid-run convergence, A9 non-zero exit on partial failure |
| `concurrency_test.go` | A11/A13 two-writer races (**KnownBug**), A24 first-marker-wins pin |
| `unavailability_test.go` | A14 no 5xx retry, A15 GET paths bypass retry (**KnownBug**) |
| `redaction_test.go` | A18 secrets never reach issues/wiki by default, A19 token/secret never in logs |
| `sor_test.go` | A20 truncated ingest fails cleanly, A22 wiki-disabled hard error |

**KnownBug tests fail when the filed follow-up bugs reproduce.** CI runs them
in a `continue-on-error` lane so they stay loud without blocking merges. Do
not "fix" them by weakening assertions — fix the layer (follow-ups: retry on
transient 5xx/conn errors; cross-process dedup guard; atomic entities
write-back).

## Running locally

Any disposable Forgejo works; the suite creates and deletes its own repos.

```bash
docker run -d --name forgejo -p 3000:3000 \
  -e FORGEJO__security__INSTALL_LOCK=true codeberg.org/forgejo/forgejo:9
docker exec -u 1000 forgejo forgejo admin user create \
  --admin --username e2e-admin --password 'e2e-Passw0rd!' --email e2e@example.invalid
TOKEN=$(docker exec -u 1000 forgejo forgejo admin user generate-access-token \
  --username e2e-admin --token-name e2e --scopes all --raw)

cd zap-kb
E2E_FORGEJO_URL=http://127.0.0.1:3000 E2E_FORGEJO_TOKEN="$TOKEN" \
  go test -tags e2e -count=1 ./internal/e2e/forgejo/...
```

Without the env vars every test skips, so `go test -tags e2e ./...` is always
safe.

## Running in a cluster (pod-based Tier 1)

```bash
RUNID=$(date +%s)
kubectl create ns e2e-$RUNID
kubectl -n e2e-$RUNID apply -f test/e2e/e2e-job.yaml
kubectl -n e2e-$RUNID wait --for=condition=complete --timeout=30m job/forgejo-sync-e2e
kubectl delete ns e2e-$RUNID    # teardown is namespace deletion — run it always
```

All state (Forgejo SQLite, token, workdir) lives in `emptyDir` volumes and
dies with the pod; `ttlSecondsAfterFinished` reclaims the Job even if the
namespace delete is missed.

## Compliance notes

- The Forgejo token is generated per run, passed via env/file, masked in CI
  (`::add-mask::`), and asserted absent from publisher output by
  `redaction_test.go` (A19).
- Published content is redacted **by default** (`-forgejo-redact`, layer fix);
  `redaction_test.go` proves both the default and the opt-out.
- Fixtures are synthetic; no real scan data enters the test infrastructure.
