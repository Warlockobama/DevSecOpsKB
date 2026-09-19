# Publication state and immutable input

Assignment 07 implementation, including final CLI wiring after assignments 03
and 04.

Producer artifacts and publication references have separate owners:

`producer -> immutable retained batches -> cumulative input -> validated publish view`

`destination confirmed refs + publication.Result -> append-only publication journal`

The producer never reads the journal. The journal never writes an input path.
`publicationstate.Store.Record` accepts validated entities, confirmed finding/epic
references and the shared `publication.Result`; it writes a private temporary file,
flushes it and renames to a unique event. Concurrent publisher processes cannot
truncate each other's events. Uncommitted `.pending-*` files are ignored.

`Store.Apply` validates the current entities and all matching destination events
before overlaying ticket/epic references. Finding IDs must still match their
recorded definition IDs. Missing old findings are ignored. Existing analyst
status, owner, suppression, history and occurrence evidence remain authoritative.
Conflicting epic references fail closed; conflicting finding references are kept
for the remote reconciler to resolve rather than selecting an arbitrary winner.
A corrupt event blocks reuse without modifying the input or any valid event.

`Destination(kind, baseURL, scope)` hashes tracker kind, credential-free endpoint,
and project/repository scope. Journal files store this opaque destination key,
a digest of the validated entities view, IDs, confirmed refs and typed stage
outcomes. They exclude captured evidence, raw API diagnostics and credentials.
The digest describes the supplied validated view; it is not a raw-file manifest
hash and does not replace Cactus's artifact hash.

References from a successful issue stage are recorded even if wiki or another
required stage fails. There is no global completion cursor or deletion. Each
saved result retains independent destination/stage status for that attempt.
Random event filenames and union replay do not define chronological or current
remote status; the journal is an audit collection. A failure is never
converted to a global acknowledgment. A lost response is resolved by the existing
remote identity reconciler before a confirmed ref is recorded. Concurrent create
idempotency remains the destination exporter's responsibility.

The companion source retains content-addressed handoffs before replacing its
cumulative view and advancing its producer cursor. Routine merges read its SHA256-verified latest complete snapshot plus new native
reports. A missing head triggers verified full archive replay for recovery; a
corrupt head fails closed. Consequently, daily wiki and hourly issue
schedules cannot miss an unpublished batch solely because a later scan arrived.
Retaining cumulative snapshots for n equal additions of b bytes uses about
b*n*(n+1)/2 bytes; normal merges read about b*n bytes plus the new batch. Full
archive replay is reserved for missing-head recovery. No automatic pruning is
implemented. See the companion `workers/kb-source/durable-handoff.md`.

| Case | Package behavior / integration requirement |
| --- | --- |
| Old publisher snapshot, newer atomic input replacement | Journal record touches only state. Reloading newer input and applying refs preserves both occurrences. The CLI no longer writes `-entities-in` or `-run-in`. |
| Concurrent publishers | Unique atomic events retain all confirmed refs; no shared JSON rewrite. |
| Crash before event rename | Ignore pending file; exporter reconciliation finds any remotely created issue on retry. |
| Crash after event rename | Apply restores confirmed references on restart. |
| Partial issues/wiki result | Persist confirmed issue refs and both stage outcomes; retry unfinished destination. |
| Corrupt/stale destination state | Corruption or matching finding/definition mismatch fails closed before mutation; unknown old findings do not attach to new IDs. |
| Legacy entities or Cactus wrapper | Existing ticket/epic refs seed the publish view; original artifact bytes/meta/alerts remain producer-owned. Export enriched derivatives to explicit output paths. |
| Optional workflow writeback | Default journal overlays refs only. Explicit status synchronization must use an explicit derivative destination, never silently overwrite source input. |
| Additive exportPolicy | Modeled on EntitiesFile; equal merge policies survive, mixed/unstamped policies clear the claim. Other unknown additive fields remain accepted but unmodeled in typed derivatives; original immutable bytes remain retained. |

No live publication or migration was executed. The package and CLI-layer tests
use strict input validation, synthetic references, temporary directories and
channels to pause a remote completion while replacing input. Direct and
hard-link source/output aliases fail before output or remote work. Filesystem/volume
backups remain required; file sync does not promise directory-entry durability
across host power loss on every filesystem.

Companion implementation: `devsecopsfiringranve` commit
`f0c4411beb67a8739e7466b585402ec4b849a8e4`, branch
`codex/reliability-state-20260912` (base `2f3032a`). Its producer-owned exclusive
Commit lock compares Render's expected head and cursor hashes before writing;
stale plans/backfills must re-render. Abandoned locks require operator inspection.

Locally verified implementation: primary `go test ./...`, `go vet ./...`,
`go build ./cmd/zap-kb`, `go test -race ./internal/output/publicationstate
./cmd/zap-kb`, and format/diff checks passed. Companion affected and full
workers tests, full vet, `go build ./publisher-worker/cmd/kb-source`, affected
`-race`, and the current Kubernetes render passed.
The CLI applies destination state before rendering or publishing, records
exporter-confirmed refs immediately after the issue stage, and refreshes only
explicit derived outputs. `-publication-state-dir` / `PUBLICATION_STATE_DIR`
selects the journal root; otherwise it defaults beside the selected input.
External rollout remains intentionally unclaimed.
