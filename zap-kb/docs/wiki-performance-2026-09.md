# Wiki publication performance: assignment 06

Date: 12 September 2026. Baseline publisher: `c84710039a33cc5208107a5c1ed022a26d9da220`.
This report covers package-local optimization, metrics and bounded disposable
measurements. Large-wiki scheduling acceptance remains incomplete. CLI integration
and release rollout are owned by the coordinating assignments.

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

`WikiSummary` additionally carries total `DurationMS`, `Requests`, and `Phases`.
Each phase has only a static phase name, wall duration, outer HTTP attempt count,
and retry-attempt count. Actual calls to the HTTP doer are counted, including
attempts stopped by request spacing/context cancellation before reaching the wire;
this is not a TCP packet count. Each logical request uses a short-lived observer,
so no headers, URLs, page titles, bodies or credentials are retained for metrics.
Preflight/discovery failure and cancellation retain their available phase timing.
There are no phase entries for an unexecuted repair/prune pass. Local collection
time is included in total duration but not assigned to a network phase. Assignment
04 maps these fields into its common publication result; this package does not
create a competing result contract. Tests cover successful retries, exact attempts,
backoff duration, cancellation timing and absence of request data in phase output.

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
restore validation are described below. Shared result mapping must use
assignment 04's `publication` contract after it lands. Production publication,
upgrade, pruning and shared-input replacement are outside this implementation.

## Disposable real-Forgejo harness

`wiki_disposable_test.go` is opt-in. It creates uniquely named containers and
volumes, publishes only generated synthetic data, and removes those resources on
normal/failure cleanup. It does not accept a pre-existing destination. The token
and randomly generated password are kept in subprocess response/process memory;
they are not logged, put in command arguments, or written to harness artifacts.
Every server gets three CPUs and 1 GiB memory, SQLite, a Linux Docker named volume,
and a randomly allocated loopback-only host port. Docker Engine was 29.3.1.

From `zap-kb`, after downloading the two explicit images:

```powershell
$env:WIKI_DISPOSABLE = '1'
$env:WIKI_IMAGE = 'codeberg.org/forgejo/forgejo:9'
$env:WIKI_UPGRADE_IMAGE = 'codeberg.org/forgejo/forgejo:15.0.8'
go test ./internal/output/forgejo -run '^TestWikiDisposable$' -count=1 -v -timeout 50m *> ../out/wiki-performance/live.log
Remove-Item Env:WIKI_DISPOSABLE,Env:WIKI_IMAGE,Env:WIKI_UPGRADE_IMAGE
```

Use `WIKI_SIZES=100`, `WIKI_BUDGET=120s` for the bounded complete small fresh
publish. `WIKI_SKIP_FRESH=1` initializes just two synthetic pages through the API
before importing a full history; it must not be reported as a fresh publish.
`WIKI_READS_ONLY=1` stops after the seeded cold/warm comparison and optional
upgrade/restore comparison. Defaults are 100/1,000/5,000 pages, a 60-second pass,
15-second request timeout and three workers, with 1 ns request spacing to isolate
server/client cost. `WIKI_BUDGET` is capped at five minutes. Upgrade/restore
comparisons each have their own three-minute cap. These shorter experimental
bounds do not test a full 45-minute production run or its 90-second request limit.
To reproduce the latter request setting in a separately bounded follow-up, set
`WIKI_REQUEST_TIMEOUT=90s` (maximum allowed: two minutes); leave the pass budget
explicit. Increasing that request value is an experimental variable, not an
assumed fix or a measured production scheduling guarantee.

Fresh scenarios use the actual REST publisher on an empty wiki. Before the seeded
cold/warm scenarios, fast-import installs an explicitly synthetic history: five
rounds, one page per commit, five versions of each page, and exact desired rendered
content in the final round. Thus sizes 100/1,000/5,000 have 500/5,000/25,000 commits.
The resulting Git objects are packed. This is not production's history shape or
loose-object storage, and seeding time is excluded from publish duration. The
harness validates its filename encoding against an actual server-issued path.
The synthetic filename conversion follows the relevant behavior in Forgejo's
[wiki path conversion](https://codeberg.org/forgejo/forgejo/src/tag/v9.0.3/services/wiki/wiki_path.go);
it is a fixture encoder, not a replacement for authoritative production paths.
Only the disposable SQLite fixture receives a known `wiki_branch=main` setup
repair to bypass v9's API-created-repository initialization bug before measuring
publication. No real repository setting is changed.

"Cold" means a restarted server process, not flushed VM/OS caches. "Warm" follows
that run. Copies used for supported-version and restore comparisons have identical
content/history and fresh server processes; copied storage may be cache-warm.
All-byte Git readback and representative encoded API reads accompany completed
runs. The benchmark's pass/fail indicates harness integrity; each record's
`completed`, summary, history and mutation counters establish publication outcome.
An unchanged history count after a deadline is not a completed no-op.

The proxy records every request in a deferred handler, including aborted response
copies, with method/endpoint counts and full response latency. This avoids an
instrumentation undercount found in initial exploratory logs. Those earlier logs
are excluded from request-count comparisons. `retryable_responses` is a status
count, not actual retries: canceled proxy requests can emit 502 without being
retried. The package's `WikiPhaseMetric.Retries` separately counts real retry
attempts. CPU, resident memory and block-I/O lines are post-phase snapshots, not
peak resource measurements. No service response bodies or credentials are emitted.

The image identities used were:

| Release | Bundled Git | Image digest |
|---|---|---|
| 9.0.3+gitea-1.22.0 | 2.45.2 | `sha256:3c34f11fe8b9983096eef3f8f25c2d2c21c4ae7504960cb203f0b075d1d8ed73` |
| 15.0.8 | 2.52.0 | `sha256:0a2e377fd3c5af3451bfa1f44e6f198f322b6d5e03f04a028b8e672f1ccddc9f` |

Forgejo lists 15.0.8 as its supported LTS and 9.x as discontinued in the
[release listing](https://forgejo.org/releases/). The disposable upgrade follows
the [upgrade guide](https://forgejo.org/docs/latest/admin/upgrade/): flush queues,
stop the instance, copy all SQLite/repository storage, start the new image on a
copy, and verify publication/readback. The restore test starts v9 against another
copy of the original snapshot, never the upgraded database. It checks exact
rendered content and that a completed unchanged publish leaves HEAD unchanged.
This is API/Git acceptance, not an exhaustive Forgejo UI/administrator audit.

### Real measurements and completion

Publisher comparison: baseline `c847100` versus the algorithm committed as
`be995878`. The fixed 100-page, 500-commit v9 seeded warm no-op fell from 3.388 s
and six list requests to 2.767 s and three list requests; both read/skip all 100
pages with zero commits. One-page change fell from 4.107 s to 3.422 s and mutated
one page; 10% change was 6.561 s versus 6.338 s and mutated ten. These are single
matched-dataset observations, not latency distributions across repeated runs.
The repeated 5,000-page seeded trial also includes the phase observer committed as
`6a78a5af`; its publication algorithm is unchanged.

The bounded optimized matrix below comes from `live-scale-final.log` in ignored
local output. **Ack C/U/S/L** means returned created/updated/skipped/link-fix counts;
**Git delta** is independently observed new wiki commits. A canceled response can
leave a committed write unacknowledged. Partial means required publication did not
complete; it must not be presented as a completed no-op even when Git delta is zero.

| Pages | Scenario | Seconds | Completion | Ack C/U/S/L | Git delta |
|---:|---|---:|---|---|---:|
| 100 | Fresh, 60 s bound | 60.000 | Partial repair | 100/0/0/53 | 154 |
| 100 | Fresh, separate 120 s trial | 78.177 | Complete | 100/0/0/99 | 199 |
| 100 | Seeded cold | 3.132 | Complete no-op | 0/0/100/0 | 0 |
| 100 | Seeded warm | 2.767 | Complete no-op | 0/0/100/0 | 0 |
| 100 | One page | 3.422 | Complete | 0/1/99/0 | 1 |
| 100 | 10% | 6.338 | Complete | 0/10/90/0 | 10 |
| 100 | Cancel after ten acknowledged PATCHes | 4.316 | Partial as injected | 0/10/0/0 | 10 |
| 100 | Recovery | 33.044 | Complete | 0/90/10/0 | 90 |
| 100 | Recovery rerun | 4.072 | Complete no-op | 0/0/100/0 | 0 |
| 1,000 | Fresh | 60.000 | Partial | 172/0/0/0 | 172 |
| 1,000 | Seeded cold | 60.000 | Partial, not no-op | 0/0/46/0 | 0 |
| 1,000 | Seeded warm | 60.001 | Partial, not no-op | 0/0/25/0 | 0 |
| 1,000 | One page | 60.001 | Partial; change not reached | 0/0/43/0 | 0 |
| 1,000 | 10% | 60.000 | Partial | 0/7/0/0 | 9 |
| 1,000 | Cancellation scenario | 60.001 | Deadline before ten acknowledgements | 0/4/0/0 | 5 |
| 1,000 | Recovery | 60.000 | Discovery incomplete | 0/0/0/0 | 0 |
| 1,000 | Recovery rerun | 60.000 | Discovery incomplete, not no-op | 0/0/0/0 | 0 |
| 5,000 | Fresh | 60.000 | Partial | 171/0/0/0 | 172 |
| 5,000 | Seeded cold | 51.041 | Initial listing failed | 0/0/0/0 | 0 |
| 5,000 | Seeded warm | 51.037 | Initial listing failed, not no-op | 0/0/0/0 | 0 |
| 5,000 | One page | 51.037 | Initial listing failed; change not reached | 0/0/0/0 | 0 |
| 5,000 | 10% | 51.052 | Initial listing failed; change not reached | 0/0/0/0 | 0 |
| 5,000 | Cancellation scenario | 51.048 | Request retries exhausted before writes | 0/0/0/0 | 0 |
| 5,000 | Recovery | 51.043 | Initial listing failed | 0/0/0/0 | 0 |
| 5,000 | Recovery rerun | 51.045 | Initial listing failed, not no-op | 0/0/0/0 | 0 |

At 1,000 pages, the first complete listing took 53.937 s cold and 56.797 s warm
(21 requests each), leaving time for only 49/28 content requests before the
60-second limit. Warm listing p50/p95 response latency was 3.000/3.946 s. These
samples isolate the initial traversal as a bottleneck that the first patch does
not remove. The ten-percent and cancellation cases show two/one remote commits
whose responses were not acknowledged. Returning the source artifact and a partial
outcome matters more than pretending those counts identify every remote mutation.

Supported-version comparison used identical offline snapshots, with three-minute
publication limits and the same 15-second request timeout:

| Pages / commits | Copy started with | Seconds | Content GETs / acknowledged skips | Publication outcome | Wiki HEAD |
|---|---|---:|---|---|---|
| 100 / 500 | 15.0.8 upgrade | 1.687 | 100 / 100 | Complete no-op | Unchanged |
| 100 / 500 | Restored 9.0.3 snapshot | 3.038 | 100 / 100 | Complete no-op | Unchanged |
| 1,000 / 5,000 | 15.0.8 upgrade | 180.000 | 671 / 668 | Partial | Unchanged |
| 1,000 / 5,000 | Restored 9.0.3 snapshot | 180.001 | 730 / 727 | Partial | Unchanged |
| 5,000 / 25,000 | 15.0.8 upgrade | 51.024 | 0 / 0 | Initial listing failed | Unchanged |
| 5,000 / 25,000 | Restored 9.0.3 snapshot | 51.037 | 0 / 0 | Initial listing failed | Unchanged |

Both 1,000-page copies passed exact Git content readback after startup, establishing
that the snapshot upgraded/restored the intended data. Their publisher runs did
not complete. The supported copy still spent 56.983 s listing; the restored baseline
spent 53.298 s. Upgrade alone has not demonstrated removal of the history cost.

The initial 5,000-page seed exceeded the harness's separate 60-second setup-command
cap after its valid fresh sample. Its server/volume were removed. The tracked
harness gives only `git fast-import` a 180-second setup cap; subsequent seeded
measurements use that same five-round, 25,000-commit dataset. Seeding is never
counted as a successful publisher run.
That seeded rerun (`live-5000-seeded-final.log`) completed the bounded matrix, with
all publication outcomes explicitly failed. Both server images exhausted three
15-second attempts at the very first 50-page listing. The package observer and
proxy agree: one preflight attempt, three discovery attempts, two retries, zero
content reads and zero mutations. The hard listing failure returns an error even
though page-level `Errors` is zero; a caller must inspect the returned error too.
This does not test whether a 90-second request limit would complete that listing,
and no claim is made that an unchanged remote commit means successful processing.

The 5,000-page seed contains one pack with 75,000 objects and 62,974 KiB of pack
storage, plus five loose bootstrap objects (20 KiB). All 5,000 page blobs, totaling
21,909,956 bytes including Git batch framing, were read through local Docker/Git
in 2.793 s on the upgraded copy and 2.409 s on the restored baseline copy. These
are local bulk-read measurements with warm copied storage, excluding authenticated
fetch, rendering and push; they are evidence for a prototype, not a benchmark of
an implemented Git publication backend.

A final two-page harness smoke check (`live-harness-smoke.log`) verified the new
90-second request-timeout option, exact phase/proxy attempt agreement, supported
15.0.8 encoded-title create/PATCH/GET readback on the upgraded disposable copy, and
baseline snapshot restoration. The canary is outside the timed no-op comparison
and changes only the upgraded copy. It is compatibility coverage, not another
large-wiki throughput claim. Final Docker inventory confirmed no benchmark
containers or volumes remained. Cleanup is registered before creation so startup
and readiness failures also reach owned-resource cleanup.

### Why a next algorithm is still needed

The complete large-wiki scheduling target is not established by this incremental
patch or by a server upgrade. The proposed next step is the explicit opt-in
[Git batch backend](wiki-batch-backend-proposal.md), with a remote revision check,
bounded conflict reconciliation and no-op commit prevention. That proposal is
not an implemented backend and does not authorize production rollout.

### Partial-publication risks and a small demonstration bound

A fresh pass first commits links using the paths known at that point. Where a
new hierarchical target needs the server's escaping, cancellation before or during
repair can leave durable pages with broken encoded links. A positive created
count is therefore not a successful publication. Keep the source artifact,
report the required wiki stage as partial/failed, and rerun the same accepted
vault. The new interrupted-fresh-repair regression confirms that the next pass's
remote content comparisons repair remaining links with the now-known server paths;
a third pass is a no-op. No rollback deletes those partially published pages.

This remains eventual convergence, not an atomic transaction. A concurrent remote
edit/delete/rename can require another pass; an ambiguous canceled write may have
committed before its response was lost. The REST client still has no conditional
write revision, and its retry helper is not a transaction mechanism. These are
residual correctness/operational limits, not claims fixed by faster listing.

For assignment 10, the demonstrated small fixture bound is **100 approximately
4 KiB pages with encoded links under a 120-second pass budget**: the real v9 fresh
publish completed in 78.18 seconds, while the same 60-second budget left repair
incomplete. Use that as a bounded lab starting point and verify the actual demo's
page sizes, rendered links, current image revision and completion result. It is
not a guarantee for the existing large Home page, a different corpus, or the
production server. Large-wiki performance readiness remains pending.

## Proposed rollout and rollback

After integration with redaction/results, build a revision-labelled publisher and
repeat the disposable suite against the supported release. Require complete
encoded-link readback, no-op commits, bounded interruption and convergent recovery
before selecting a runtime budget. Later production rollout must use a controlled
canary and the existing issue/wiki separation. Roll back by restoring the previous
publisher image; no local cache, manifest, schema or remote format needs migration.
Server rollback must restore a pre-upgrade backup into separate storage, never
start an older Forgejo binary against an upgraded database.
