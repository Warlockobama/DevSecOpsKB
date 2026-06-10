# Forgejo Sink Remediation — Master Plan

Status: ready for execution
Target branch: `claude/forgejo-sync-layer` (or a child branch of it)
Source: analyst/code review of the Forgejo sink, 2026-06-10

## What this is

A security/code review of the Forgejo sink found 7 defects and 6 improvements.
This directory contains five workstream plans. Each plan is **self-contained**:
an executor can complete one workstream knowing nothing but that plan file and
the repository.

| Plan | Workstream | Fixes |
|------|-----------|-------|
| [01-dedup-integrity.md](01-dedup-integrity.md) | Dedup & rendering integrity | Marker spoofing, markdown fence escape, pagination under-read, UTF-8 truncation |
| [02-issue-lifecycle.md](02-issue-lifecycle.md) | Issue lifecycle | Reopen-on-recurrence, severity labels, body refresh, accurate dry-run, missing description, wiki cross-link |
| [03-status-pull-correctness.md](03-status-pull-correctness.md) | Status pull correctness | Cross-repo URL refs, stale duplicate ticket refs |
| [04-wiki-navigation.md](04-wiki-navigation.md) | Wiki navigation | Broken cross-links after publish, stale page pruning |
| [05-redaction-and-pipeline.md](05-redaction-and-pipeline.md) | Redaction & pipeline robustness | Silent evidence deletion under default redaction, `log.Fatalf` killing the multi-sink pipeline |

## Execution order

Run the workstreams **sequentially in numeric order**. 01 and 02 touch the same
files (`issues.go`, `render.go`); 02 builds on types added in 01. 03–05 are
mostly independent of each other but rebase cleanly only if done after 02.

Do **not** run two workstreams in parallel in the same worktree.

## Ground rules for every executor (read before starting)

1. **Locate code by function name, not line number.** Line numbers in the plans
   were correct at planning time and will drift as earlier workstreams land.
   Use `grep -n "func <name>"` to find the real location.
2. **Module root is `zap-kb/`.** All `go` commands run from there:
   ```bash
   cd zap-kb
   go build ./...
   go test ./...
   gofmt -l .        # must print nothing
   go vet ./...
   ```
3. **All four commands above must pass before you commit.** If a pre-existing
   test fails before you change anything, stop and report — do not "fix" it.
4. **Commits**: one commit per workstream, DCO sign-off required:
   `git commit -s -m "<message from the plan>"`.
5. **Determinism**: outputs (issue bodies, wiki pages) must be deterministic —
   no timestamps, random ordering, or map-iteration ordering in rendered text.
   When iterating a map to produce output, sort keys first.
6. **Do not refactor beyond the plan.** If you see adjacent code you think is
   wrong, note it in your final report; do not change it.
7. **Style**: tabs for Go (EditorConfig), match the surrounding comment voice.
   The package already explains *why* in comments; keep that habit for new
   tricky code, skip comments that narrate *what*.
8. **Never commit generated data** (`out/` dirs, test scratch dirs).

## Architecture you need (2-minute version)

- The KB normalizes scanner output into an **entities model**
  (`internal/entities/entities.go`): `Definitions` (what a vuln class is),
  `Findings` (a vuln class observed at a URL), `Occurrences` (one observation
  with evidence). `Finding.Analyst` carries triage state incl. `TicketRefs`
  (strings like `owner/repo#42` or Jira keys) and `Status`.
- The **Forgejo sink** (`internal/output/forgejo/`) publishes findings as
  Forgejo/Gitea issues (`issues.go`, `render.go`, `labels.go`), pulls issue
  state back into analyst status (`pull.go`, `status.go`), and publishes the
  generated Obsidian markdown vault as wiki pages (`wiki.go`).
- Dedup across runs: every issue body ends with a hidden HTML comment
  `<!-- devsecopskb-finding:<findingID> -->`. Re-runs list all repo issues,
  group by that marker, and skip findings that already have an issue. The
  lowest-numbered issue per finding is the canonical "winner".
- Shared HTTP plumbing (throttle, retry, error sanitizing) lives in
  `internal/output/synccore/synccore.go`. `DoWithRetry` errors on non-2xx;
  `DoWithRetryRaw` returns non-2xx responses as data.
- CLI wiring is in `cmd/zap-kb/forgejo_sync.go` (`runForgejoPublish`) and flag
  parsing in `cmd/zap-kb/main.go`.
- Unit tests for the sink: `internal/output/forgejo/forgejo_test.go` (uses
  `httptest`-style stub servers). E2E suite with a fake Forgejo server:
  `internal/e2e/forgejo/` (`harness/harness.go`).

## Definition of done (whole effort)

- All five workstream acceptance checklists pass.
- `go build ./... && go test ./... && go vet ./...` green, `gofmt -l .` empty.
- Five commits on the branch, each scoped to one workstream.
