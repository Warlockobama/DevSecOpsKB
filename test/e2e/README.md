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
| `concurrency_test.go` | A11/A13 two-writer convergence + clean label race, A24 stable lowest-number winner |
| `unavailability_test.go` | A14 transient 5xx retried, A15 GET paths retry via DoWithRetryRaw |
| `redaction_test.go` | A18 secrets never reach issues/wiki by default, A19 token/secret never in logs |
| `sor_test.go` | A20 truncated ingest fails cleanly, A22 wiki-disabled hard error |

The assumptions that were originally filed as known bugs (A11/A13 dedup +
label race, A14/A15 retry coverage, A10 atomic write) are now **fixed in the
layer and asserted as regressions** — these tests fail if the fix is reverted.
The convergence approach: two racing publishers may briefly create duplicate
issues, but the post-create reconcile keeps the lowest-numbered issue per
finding and closes the rest, so the steady state is at most one open issue per
finding.

## Running locally

Any disposable Forgejo/Gitea works; the suite creates and deletes its own
repos. **Server version matters**: Gitea 1.22's wiki REST API is broken on
API-created repos (`wiki_branch` NULL — writes commit but every read 404s, and
the column cannot be repaired via API). The sink detects this and fails fast
with upgrade guidance; run the suite against Gitea >= 1.23 or Forgejo. When
codeberg.org / docker.io are unreachable, `mirror.gcr.io` mirrors Docker Hub:

```bash
docker run -d --name forgejo -p 3000:3000 \
  -e GITEA__security__INSTALL_LOCK=true mirror.gcr.io/gitea/gitea:1.24
docker exec -u 1000 forgejo gitea admin user create \
  --admin --username e2e-admin --password 'e2e-Passw0rd!' --email e2e@example.invalid
TOKEN=$(docker exec -u 1000 forgejo gitea admin user generate-access-token \
  --username e2e-admin --token-name e2e --scopes all --raw)

cd zap-kb
E2E_FORGEJO_URL=http://127.0.0.1:3000 E2E_FORGEJO_TOKEN="$TOKEN" \
  go test -tags e2e -count=1 ./internal/e2e/forgejo/...
```

Without the env vars every test skips, so `go test -tags e2e ./...` is always
safe.

## What the first live runs caught (kept as regression tests)

The suite's first execution against a real server (Gitea 1.22/1.24) found
three implementation-breaking facts no mock had surfaced:

1. **Label names are not unique** — two racing publishers both 201 their
   label create, and the server's `?labels=<name>` query then returns
   *nothing*, blinding the dedup index into duplicating every finding on
   every run. Fixed: the dedup index lists all issues and matches the hidden
   marker (labels are cosmetic), and `ensureLabels` canonicalizes/deletes
   duplicate names.
2. **Gitea 1.22 wiki API is server-broken for API-created repos** —
   `wiki_branch` NULL: writes commit but are unreadable, and PATCHing the
   column is a silent no-op. Fixed: a serial canary write fails the export
   fast with one descriptive error instead of N identical 404s.
3. **Wiki page names with `/` don't round-trip via client-side escaping**
   (`Findings/fin-1` → server stores sub_url `Findings%2Ffin-1.-`). Fixed:
   pages are discovered via `GET /wiki/pages` and addressed by the
   server-issued `sub_url`, never by guessed escaping.

## CronJob-equivalent container validation

The publisher image was also exercised with the exact `22-kb-cronjob.yaml`
args (env-injected token, `/ingest` volume, `-forgejo-wiki`) against a live
server. Findings worth knowing as an operator:

- **`fsGroup: 1000` in the pod securityContext is load-bearing**: the
  container runs non-root and `mkdir /work/vault` fails without it (observed
  when emulating with a root-owned docker volume). Don't remove it.
- **Convergence shape**: run 1 creates issues + wiki and persists ticket refs
  into the ingest `entities.json`; run 2 updates the handful of wiki pages
  whose content legitimately gained the issue link; run 3+ is a true no-op
  (`created=0`, all wiki pages skipped). Vault generation itself is
  byte-deterministic for identical entities (verified by diffing two runs).
- The read-only status pull leaves `analyst.status` and `analyst.history`
  untouched in the persisted entities (R2/R5 verified end-to-end).

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
