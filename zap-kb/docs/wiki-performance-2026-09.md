# Wiki publication performance: assignment 06

Date: 12 September 2026. Baseline publisher: `c84710039a33cc5208107a5c1ed022a26d9da220`.
This is incremental package-local acceptance. Shared publication-result integration,
full disposable scale acceptance and release rollout remain separate phases.

## Selected change

Reuse the initial server-issued title/path snapshot when every desired page was
already present and every first-pass operation succeeded. In that case, omit the
second complete listing and the redundant file reads/link rendering. If any target
was initially absent, or any first-pass operation failed, retain the second listing
and existing link-repair behavior. Acquire worker capacity before starting each
goroutine, so cancellation stops scheduling and worker allocation is bounded.

Every existing page is still read on every run. No persistent manifest, cache,
content-hash assumption, changed identity, new backend or shared result contract is
introduced. Server-issued paths remain authoritative. An out-of-band content edit
is detected. Concurrent rename/delete between listing and use reports failure;
the next run can recreate the desired title without touching the renamed analyst
page. A wiki REST pass is still not an atomic snapshot: changes after a successful
GET or final listing can require another run. This optimization does not add a
stronger concurrency guarantee than the existing REST API provides.

The second traversal is especially expensive on Forgejo versions whose list
handler looks up Git history for every page. This removes one traversal; it does
not remove the initial traversal, content reads, server Git history lookup cost,
or fresh-publish link repair.

## Reproducible synthetic workload

From `zap-kb`, in PowerShell:

```powershell
New-Item -ItemType Directory -Force ../out/wiki-performance | Out-Null
$env:WIKI_SCALE = '1'
go test ./internal/output/forgejo -run '^TestWikiScale$' -count=1 -v -timeout 10m *> ../out/wiki-performance/synthetic.log
Remove-Item Env:WIKI_SCALE
```

`wiki_scale_test.go` creates disposable HTTP servers and vaults at 100, 1,000 and
5,000 pages. Each page contains approximately 4 KiB of synthetic Markdown and one
ring link. The names exercise hierarchy, spaces, plus and percent characters;
links include fragments. The server deliberately returns paths that differ from
client escaping. Readback verifies every page and independently checks the expected
encoded next-page link. There is **no Git history or real Forgejo** in this test.

Each workload runs fresh publish, identical rerun, one-page change, 10% change,
cancellation after ten committed mock mutations, recovery, and recovery no-op.
Each call is bounded at 90 seconds. Cancellation permits only the ten mutations
plus already in-flight workers. One-page and 10% cases must mutate exactly the
changed pages; both no-op scenarios must read/skip every page and mutate nothing.

Measurements below are single observations on Go 1.24.7, Windows/amd64, loopback
HTTP, three workers, a 1 ns request delay to isolate client work, and warm process
state between scenarios. They include client file/HTTP/render work; reported
endpoint latencies are mock handler time, not real service latency. Allocated
bytes are cumulative client-plus-in-process-server allocations, not peak memory.
They are not production throughput or an SLO. The same test source was run against
baseline and optimized publisher code. Raw JSON test lines are in ignored local
`out/wiki-performance/baseline.log` and `optimized.log`.

| Pages | Scenario | Before ms | After ms | Before/after list requests | Before/after mutations |
|---:|---|---:|---:|---:|---:|
| 100 | Fresh | 278.4 | 289.0 | 4 / 4 | 199 / 199 |
| 100 | Unchanged | 80.7 | 44.0 | 6 / 3 | 0 / 0 |
| 100 | One page | 73.6 | 48.0 | 6 / 3 | 1 / 1 |
| 100 | 10% | 92.0 | 71.0 | 6 / 3 | 10 / 10 |
| 1,000 | Fresh | 2,420.9 | 2,762.7 | 22 / 22 | 1,999 / 1,999 |
| 1,000 | Unchanged | 610.5 | 382.5 | 42 / 21 | 0 / 0 |
| 1,000 | One page | 621.4 | 289.0 | 42 / 21 | 1 / 1 |
| 1,000 | 10% | 798.9 | 437.5 | 42 / 21 | 100 / 100 |
| 5,000 | Fresh | 12,443.4 | 13,439.3 | 102 / 102 | 9,999 / 9,999 |
| 5,000 | Unchanged | 3,239.8 | 1,512.6 | 202 / 101 | 0 / 0 |
| 5,000 | One page | 3,305.8 | 1,869.5 | 202 / 101 | 1 / 1 |
| 5,000 | 10% | 4,069.9 | 2,534.8 | 202 / 101 | 500 / 500 |

At 5,000 pages the optimized unchanged call still makes 5,000 content GETs;
total requests fall from 5,203 to 5,102. Allocation falls from 696.9 to 437.4 MiB.
The optimized interrupted call committed ten mock mutations in 140.7 ms, recovery
updated the other 4,990 pages in 10,370.9 ms, and the next call skipped all pages
without mutation in 1,409.8 ms. The baseline cancellation allowed eleven in-flight
mutations and also converged. Fresh publish has no demonstrated improvement.

## Available acceptance and remaining limits

Package tests cover unchanged quirky paths, new-page link repair, deadline stop,
remote content changes, concurrent rename failure/recovery and preservation of
the renamed page. The synthetic scale workloads passed all scenarios. The full
Go suite, vet, build and diff whitespace check passed for the package-local change.

The default 250 ms request spacing still implies about 21 minutes 15 seconds of
request-start spacing for an unchanged 5,000-page wiki, before server processing.
That is an analytical floor, not measured completion under the 45-minute wiki
budget. No production runtime target can be approved from these measurements.

A durable manifest was rejected for this incremental change because remote edits,
renames, deletes and ephemeral publishers require explicit invalidation. Raising
concurrency/timeouts does not remove the initial sequential listing. A batch Git
backend remains an explicit future choice requiring conflict/push/encoding and
credential tests; this patch does not adopt it.

Disposable real-Forgejo measurements, supported-version snapshot comparison and
restore validation are being recorded separately. Shared result mapping must use
assignment 04's `publication` contract after it lands. Production publication,
upgrade, pruning and shared-input replacement are outside this implementation.

## Proposed rollout and rollback

After integration with redaction/results, build a revision-labelled publisher and
repeat the disposable suite against the supported release. Require complete
encoded-link readback, no-op commits, bounded interruption and convergent recovery
before selecting a runtime budget. Later production rollout must use a controlled
canary and the existing issue/wiki separation. Roll back by restoring the previous
publisher image; no local cache, manifest, schema or remote format needs migration.
Server rollback must restore a pre-upgrade backup into separate storage, never
start an older Forgejo binary against an upgraded database.
