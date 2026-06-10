# Workstream 03 — Status Pull Correctness

Read `00-OVERVIEW.md` first. Run after Workstream 02.
All files below are under `zap-kb/` unless stated otherwise.

Two defects:

- **D7 (cross-repo refs)**: `extractIssueNumber` in
  `internal/output/forgejo/pull.go` accepts *any* URL containing `/issues/N`
  without checking that it belongs to the configured repo. A GitHub or other
  Forgejo-repo link an analyst pasted into `TicketRefs` is misread as this
  repo's issue `#N`, and a stranger's issue state is written into KB analyst
  status.
- **D8 (stale duplicate refs)**: ticket refs are persisted by appending
  (`mergeFindingTicketKeys` in `cmd/zap-kb/jira_sync.go` skips only exact
  duplicates). When a duplicate issue is later closed by the reconcile pass, a
  ref persisted in an *earlier* run still points at the closed duplicate; the
  next status pull reads it as closed → maps to `fixed` → KB marks a finding
  fixed whose winning issue is still open.

## Task 1 — Validate the repo in URL-form refs (D7)

File: `internal/output/forgejo/pull.go`, function `extractIssueNumber`.

Replace the browse-URL branch (the `strings.Contains(ref, "/issues/")` block)
with a version that requires the path segment immediately before `/issues/` to
be `owner/repo`:

```go
// Browse URL form: …/<owner>/<repo>/issues/42 — only accepted when
// <owner>/<repo> matches this repo, so refs pasted from other trackers
// (GitHub, another Forgejo repo) are never misread as local issue numbers.
if i := strings.LastIndex(ref, "/issues/"); i >= 0 {
	head := strings.TrimRight(ref[:i], "/")
	if !strings.HasSuffix(strings.ToLower(head), "/"+strings.ToLower(repoPrefix)) {
		return 0, false
	}
	seg := strings.TrimRight(ref[i+len("/issues/"):], "/")
	return parsePositiveInt(seg)
}
```

Keep the `owner/repo#42`, bare `#42`, and bare `42` branches exactly as they
are. Update the function's doc comment to state the URL form now requires the
repo to match.

## Task 2 — Repoint persisted refs at the reconcile winner (D8)

### 2a. New Forgejo-specific merge helper

File: `cmd/zap-kb/forgejo_sync.go`. Add:

```go
// mergeForgejoTicketRefs records this run's findingID→issueRef map on the
// findings. Unlike the generic append-only Jira merge, any existing ref that
// parses as an issue of the SAME Forgejo repo but differs from the new ref is
// removed first: the new ref is always the reconcile winner, and a stale ref
// left pointing at a closed duplicate would make the next status pull mark the
// finding "fixed" while the winning issue is still open. Refs belonging to
// other trackers (Jira keys, other repos) are preserved untouched.
// Returns the number of findings whose refs changed.
func mergeForgejoTicketRefs(ent *entities.EntitiesFile, ticketRefs map[string]string, repoPrefix string) int {
	if ent == nil || len(ticketRefs) == 0 {
		return 0
	}
	changed := 0
	for i := range ent.Findings {
		ref := strings.TrimSpace(ticketRefs[ent.Findings[i].FindingID])
		if ref == "" {
			continue
		}
		if ent.Findings[i].Analyst == nil {
			ent.Findings[i].Analyst = &entities.Analyst{}
		}
		old := ent.Findings[i].Analyst.TicketRefs
		kept := make([]string, 0, len(old)+1)
		present := false
		mutated := false
		for _, existing := range old {
			if existing == ref {
				kept = append(kept, existing)
				present = true
				continue
			}
			if _, ok := forgejo.ExtractIssueNumber(existing, repoPrefix); ok {
				// Some other ref into this repo — either a stale duplicate
				// (different number) or a different spelling of the same issue;
				// the canonical new ref replaces it either way.
				mutated = true
				continue
			}
			kept = append(kept, existing) // foreign tracker ref — preserve
		}
		if !present {
			kept = append(kept, ref)
			mutated = true
		}
		ent.Findings[i].Analyst.TicketRefs = kept
		if mutated {
			changed++
		}
	}
	return changed
}
```

### 2b. Export the parser

File: `internal/output/forgejo/pull.go`. The helper above needs
`extractIssueNumber` from outside the package. Add a thin exported wrapper
(keep the unexported one as the implementation):

```go
// ExtractIssueNumber reports whether ref denotes an issue of the repo
// identified by repoPrefix ("owner/repo"), and its number. See
// extractIssueNumber for accepted forms.
func ExtractIssueNumber(ref, repoPrefix string) (int64, bool) {
	return extractIssueNumber(ref, repoPrefix)
}
```

### 2c. Use the new merge in the publish path

File: `cmd/zap-kb/forgejo_sync.go`, function `runForgejoPublish`. Replace

```go
addedTicketKeys = mergeFindingTicketKeys(ent, sum.TicketRefs)
```

with

```go
addedTicketKeys = mergeForgejoTicketRefs(ent, sum.TicketRefs, opts.Owner+"/"+opts.Repo)
```

(The variable keeps its name; everything downstream — the
`addedTicketKeys > 0` persistence trigger — is unchanged.)
`mergeFindingTicketKeys` itself stays as-is; the Jira path still uses it.

## Task 3 (small, same files) — deduplicate concurrent status fetches

File: `internal/output/forgejo/pull.go`, in `PullStatus`. The per-issue cache
is checked before the semaphore, so N goroutines referencing the same issue
all miss and fetch it N times. Cheap fix: pre-group refs by issue number and
fetch each number once, then fan results back out. Concretely: build
`numbers := sorted unique ref.number values`, fetch statuses for those (keep
the existing semaphore pattern over `numbers`), store into `statusCache`, then
process `refs` sequentially reading only from the cache. Delete the
per-goroutine cache check. Behavior must remain identical except for the
number of HTTP calls.

## Tests (required)

File: `internal/output/forgejo/forgejo_test.go` (or `pull_test.go` in the same
package if you prefer a new file):

1. `TestExtractIssueNumber_URLMustMatchRepo` — table test, `repoPrefix` =
   `"owner/repo"`:
   | ref | want ok | want n |
   |---|---|---|
   | `https://forge.example/owner/repo/issues/42` | true | 42 |
   | `https://forge.example/other/repo/issues/42` | false | — |
   | `https://github.com/foo/bar/issues/42` | false | — |
   | `https://forge.example/OWNER/REPO/issues/7/` | true | 7 |
   | `owner/repo#9` | true | 9 |
   | `other/repo#9` | false | — |
   | `#5` | true | 5 |
   | `12` | true | 12 |
   | `SEC-123` | false | — |
2. `TestPullStatus_FetchesEachIssueOnce` — three findings whose refs all point
   at issue `#1`; stub server counts GETs to `/issues/1`. Assert exactly one
   GET (after Task 3) and that all three findings receive the status.

File: `cmd/zap-kb/forgejo_sync_test.go`:

3. `TestMergeForgejoTicketRefs_ReplacesStaleSameRepoRef` — finding with
   existing refs `["owner/repo#5", "SEC-123"]`, new map `{F: "owner/repo#3"}`.
   Assert resulting refs are exactly `["SEC-123", "owner/repo#3"]` and the
   function returned 1.
4. `TestMergeForgejoTicketRefs_NoChangeWhenRefAlreadyCurrent` — existing refs
   `["owner/repo#3"]`, new map `{F: "owner/repo#3"}`. Assert refs unchanged
   and return value 0.

## Acceptance checklist

- [ ] URL-form refs are rejected unless `<owner>/<repo>` precedes `/issues/`.
- [ ] `ExtractIssueNumber` exported; `mergeForgejoTicketRefs` used by `runForgejoPublish`; Jira path untouched.
- [ ] Status pull fetches each distinct issue number once.
- [ ] Tests 1–4 pass; full suite green; `gofmt -l .` empty.
- [ ] Commit: `git commit -s -m "fix(forgejo): validate pull refs against repo, repoint stale duplicate ticket refs"`

## Out of scope

Issue creation/reopen (02), wiki (04), redaction (05).
