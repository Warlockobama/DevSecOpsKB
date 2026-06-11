# Workstream 02 — Issue Lifecycle

Read `00-OVERVIEW.md` first. Requires Workstream 01 to be merged (it changes
`markerFindingID`, fences, and pagination in the same files).
All files below are under `zap-kb/` unless stated otherwise.

Defects/improvements fixed here, all in `internal/output/forgejo/` plus CLI
wiring in `cmd/zap-kb/`:

- **D5 (reopen-on-recurrence)**: a finding whose issue was closed is skipped
  forever, even when the scanner still detects it. A vuln "fixed" in the
  tracker but live on the site never resurfaces.
- **D6 (dry-run lies)**: dry-run ignores the dedup index and claims it would
  create an issue for every candidate, including ones that already exist.
- **I1**: issues never say what the vulnerability *is* — `def.Description`
  is not rendered.
- **I2**: no severity labels, so analysts cannot filter by risk in the UI.
- **I3**: issue bodies are frozen at creation; new evidence/occurrence counts
  never reach the ticket.
- **I4**: no cross-link from the issue to the KB wiki definition page.

## Design decisions (already made — do not revisit)

1. The issue **description is machine-owned**: the sink may overwrite it on any
   run. Analyst commentary belongs in issue comments and labels. This is what
   makes I3 safe.
2. Reopen only fires when the closed issue maps to status `fixed` per
   `mapForgejoStatus` (i.e. closed with **no** false-positive/accepted label).
   Analyst dispositions (`fp`, `accepted`) are never overridden.
3. Severity labels are named `risk/high`, `risk/medium`, `risk/low`,
   `risk/info`. Unknown/empty risk gets no risk label.
4. Dry-run is allowed to perform **GET** requests (build the dedup index) but
   never POST/PATCH/DELETE.

---

## Task 1 — Carry labels and body in the dedup index

File: `internal/output/forgejo/issues.go`.

Extend `issueInfo`:

```go
// issueInfo is the dedup- and lifecycle-relevant slice of an issue.
type issueInfo struct {
	Number int64
	State  string   // "open" | "closed"
	Labels []string // label names, for fp/accepted detection on reopen
	Body   string   // current body, for refresh comparison
}
```

In `listFindingIssues`, extend the decoded batch struct with

```go
Labels []struct {
	Name string `json:"name"`
} `json:"labels"`
```

and populate the new fields when appending:

```go
names := make([]string, 0, len(iss.Labels))
for _, l := range iss.Labels {
	names = append(names, l.Name)
}
out[fid] = append(out[fid], issueInfo{Number: iss.Number, State: strings.ToLower(iss.State), Labels: names, Body: iss.Body})
```

## Task 2 — New client helpers

File: `internal/output/forgejo/issues.go`. Add alongside `closeIssue` (model
all three on its existing shape — `newRequest` + `synccore.DoWithRetry` +
`drain`):

```go
// reopenIssue PATCHes an issue back to state=open.
func (c *client) reopenIssue(ctx context.Context, number int64) error
// body: {"state":"open"} — otherwise identical to closeIssue.

// updateIssueBody PATCHes an issue's body.
func (c *client) updateIssueBody(ctx context.Context, number int64, body string) error
// PATCH {repoAPI}/issues/{number} with {"body": body}.

// addComment POSTs a comment to an issue.
func (c *client) addComment(ctx context.Context, number int64, body string) error
// POST {repoAPI}/issues/{number}/comments with {"body": body}.
```

## Task 3 — Severity labels

File: `internal/output/forgejo/labels.go`.

Add:

```go
// riskLabelColors maps the per-risk labels to their colors; ensureLabels uses
// these when it has to create one, falling back to defaultLabelColor.
var riskLabelColors = map[string]string{
	"risk/high":   "#d73a4a",
	"risk/medium": "#e36209",
	"risk/low":    "#dbab09",
	"risk/info":   "#6a737d",
}

// riskLabel returns the severity label for a finding risk, or "" when the
// risk is unknown.
func riskLabel(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return "risk/high"
	case "medium":
		return "risk/medium"
	case "low":
		return "risk/low"
	case "info", "informational":
		return "risk/info"
	}
	return ""
}
```

In `ensureLabels`, when creating a missing label, pick the color:

```go
color := defaultLabelColor
if c, ok := riskLabelColors[strings.ToLower(name)]; ok {
	color = c
}
lbl, err := c.createLabel(ctx, name, color)
```

## Task 4 — Rework the body of `Export`

File: `internal/output/forgejo/issues.go`, function `Export`. This is the bulk
of the workstream. Target flow (top-to-bottom); steps marked NEW or MOVED:

1. Validate options, resolve concurrency/floor/optInTag — unchanged.
2. Build `defByID`, `latestOcc`, `candidates` — unchanged. **Remove** the old
   early dry-run block that sits before label resolution.
3. Build the dedup index `byFinding` via `listFindingIssues` — MOVED up, now
   *before* dry-run and label resolution (it is GET-only). Keep the
   `existing`/`initialDups` derivation, but also keep `byFinding` itself in
   scope — later steps need the winner's `State`/`Labels`/`Body`.
4. NEW — dry-run block (replaces the removed one):

```go
if opts.DryRun {
	sum := Summary{TicketRefs: map[string]string{}}
	for _, f := range candidates {
		if issues, ok := byFinding[f.FindingID]; ok {
			w := issues[0]
			sum.Skipped++
			sum.TicketRefs[f.FindingID] = c.issueRef(w.Number)
			if w.State == "closed" && mapForgejoStatus(w.State, w.Labels) == "fixed" {
				fmt.Printf("[forgejo] dry-run: would reopen %s for finding %s (recurred)\n", c.issueRef(w.Number), f.FindingID)
			} else {
				fmt.Printf("[forgejo] dry-run: finding %s already tracked as %s\n", f.FindingID, c.issueRef(w.Number))
			}
			continue
		}
		sum.Created++
		fmt.Printf("[forgejo] dry-run: would create issue for finding %s (risk=%s url=%s)\n", f.FindingID, f.Risk, f.URL)
	}
	return sum, nil
}
```

5. Label resolution — extend the requested set with every risk label any
   candidate needs (sorted for determinism):

```go
labelNames := append([]string{dedupLabel}, opts.ExtraLabels...)
riskSet := map[string]struct{}{}
for _, f := range candidates {
	if rl := riskLabel(f.Risk); rl != "" {
		riskSet[rl] = struct{}{}
	}
}
for rl := range riskSet {
	labelNames = append(labelNames, rl)
}
sort.Strings(labelNames[1:]) // keep dedupLabel first, rest deterministic
labelIDs, err := c.ensureLabels(ctx, labelNames)
```

Replace the old flat `createLabelIDs` with a per-finding helper (top-level
function in the same file):

```go
// labelIDsForFinding returns the base labels (dedup + extras) plus the
// finding's risk label, sorted ascending for deterministic payloads.
func labelIDsForFinding(f entities.Finding, labelIDs map[string]int64, extras []string) []int64 {
	ids := []int64{labelIDs[dedupLabel]}
	for _, e := range extras {
		if id, ok := labelIDs[strings.TrimSpace(e)]; ok {
			ids = append(ids, id)
		}
	}
	if rl := riskLabel(f.Risk); rl != "" {
		if id, ok := labelIDs[rl]; ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
```

6. The per-candidate loop. Replace the current "skip if exists" shortcut with
   a three-way branch. For each candidate `f` (still inside the existing
   semaphore/goroutine pattern — move the *whole* branch into the goroutine so
   reopen/refresh PATCHes also respect the concurrency cap):

   - **Not in `byFinding`** → create (existing code path), counts `created`.
   - **Winner is closed AND `mapForgejoStatus(w.State, w.Labels) == "fixed"`**
     → reopen: call `reopenIssue`, then `addComment` with exactly this body
     (deterministic — no timestamps):

     ```go
     fmt.Sprintf("Reopened by DevSecOpsKB: this finding recurred in the latest scan (risk: %s). If it was intentionally dismissed, label the issue `false-positive` or `accepted` to prevent automatic reopening.", titleCase(f.Risk))
     ```

     then fall through to the body-refresh check below. Count `reopened`. If
     `reopenIssue` fails, count an error and continue to the next finding (do
     not also attempt the comment).
   - **Winner exists otherwise** (open, or closed-as-fp/accepted):
     - If closed-as-fp/accepted → `skipped++`, record ticket ref, done.
     - If open (or just reopened) → body refresh: render
       `desired := buildIssueBody(f, defByID[f.DefinitionID], latestOcc[f.FindingID], opts.WikiURLBase)`
       (signature change in Task 5); if `desired != w.Body`, call
       `updateIssueBody`, count `bodiesUpdated`; else `skipped++`. Either way
       record the ticket ref.

   Keep all counter mutations under the existing `mu` mutex.

7. Duplicate reconcile — unchanged, but the trigger condition becomes
   `if created > 0 || reopened > 0 || initialDups {`.

8. Extend `Summary`:

```go
Reopened      int // closed-as-fixed issues reopened because the finding recurred
BodiesUpdated int // open issues whose description was refreshed
```

## Task 5 — Description section and wiki cross-link in the body

File: `internal/output/forgejo/render.go`.

Change the signature:

```go
func buildIssueBody(f entities.Finding, def *entities.Definition, occ *entities.Occurrence, wikiURLBase string) string
```

(update every caller, including tests). Insert **after** the
Risk/URL/Method header block and **before** the Remediation section:

```go
if def != nil && strings.TrimSpace(def.Description) != "" {
	b.WriteString("## Description\n\n")
	b.WriteString(sanitizeUntrusted(truncate(strings.TrimSpace(def.Description), 1500)))
	b.WriteString("\n\n")
}
```

At the end of the `def != nil` block (after the classification section), add
the cross-link when a wiki base is configured:

```go
if def != nil && strings.TrimSpace(wikiURLBase) != "" {
	page := "Definitions/" + def.DefinitionID
	fmt.Fprintf(&b, "**KB reference:** [%s](%s/%s)\n\n", page,
		strings.TrimRight(wikiURLBase, "/"), url.PathEscape(page))
}
```

Add `"net/url"` to imports. `url.PathEscape` escapes the `/` in the page name
to `%2F`, which is how Forgejo addresses hierarchical wiki pages.

File: `internal/output/forgejo/issues.go` — add to `Options`:

```go
WikiURLBase string // e.g. https://forge.example.com/owner/repo/wiki; "" disables the KB-reference link
```

## Task 6 — CLI wiring

File: `cmd/zap-kb/forgejo_sync.go`, function `runForgejoPublish`.

- Pass the wiki base only when wiki publishing is on, so issues never link to
  a wiki that was not published:

```go
wikiURLBase := ""
if opts.Wiki {
	wikiURLBase = fmt.Sprintf("%s/%s/%s/wiki", strings.TrimRight(opts.BaseURL, "/"), opts.Owner, opts.Repo)
}
```

  and set `WikiURLBase: wikiURLBase` in the `forgejo.Options` literal.
- Extend the summary print to include the new counters:

```go
fmt.Printf("Forgejo: created=%d reopened=%d updated=%d skipped=%d errors=%d duplicates_closed=%d\n",
	sum.Created, sum.Reopened, sum.BodiesUpdated, sum.Skipped, sum.Errors, sum.DuplicatesClosed)
```

No new CLI flags.

## Tests (required)

In `internal/output/forgejo/` — model stub servers on the existing patterns in
`forgejo_test.go` (they spin an `httptest.Server` whose handler switches on
method+path and records requests). Each test below states the scenario and the
assertions; the stub must record every request so you can assert on absence.

1. `TestExport_ReopensClosedFixedOnRecurrence` — index returns one closed
   issue (labels: only `kb-finding`) whose body carries the marker for finding
   F. Export with F as a candidate. Assert: a `PATCH …/issues/N` with
   `{"state":"open"}` happened; a `POST …/issues/N/comments` happened; no
   issue-create POST; `Summary.Reopened == 1`, `Created == 0`;
   `TicketRefs["F"]` points at issue N.
2. `TestExport_NeverReopensFPOrAccepted` — same as above but the closed issue
   has label `false-positive` (run again with `accepted`). Assert: zero PATCH
   requests, `Reopened == 0`, `Skipped == 1`.
3. `TestExport_CreatesWithRiskLabel` — finding with risk `high`; server has no
   labels. Assert the label-create POSTs include `risk/high` with color
   `#d73a4a`, and the issue-create payload's `labels` array contains both the
   `kb-finding` and `risk/high` IDs in ascending order.
4. `TestExport_RefreshesStaleOpenBody` — open issue for F whose body is the
   marker plus stale text. Assert `PATCH …/issues/N` with the freshly rendered
   body; `BodiesUpdated == 1`. Assert the new body still ends with the marker
   (use `markerFindingID`).
5. `TestExport_IdenticalBodyNoPatch` — open issue whose body equals exactly
   what `buildIssueBody` renders for the same inputs. Assert zero PATCH
   requests and `Skipped == 1`. (Easiest construction: call `buildIssueBody`
   in the test to produce the stub's stored body.)
6. `TestExport_DryRunCountsExisting` — two candidates, index knows one.
   Assert `Summary{Created: 1, Skipped: 1}` and that the server received
   **only GET** requests.
7. `TestBuildIssueBody_DescriptionAndWikiLink` — definition with
   `Description: "Reflected XSS happens when…"`, `DefinitionID: "def-1"`,
   `wikiURLBase: "https://forge.example/o/r/wiki"`. Assert the body contains
   `## Description`, the description text, and
   `https://forge.example/o/r/wiki/Definitions%2Fdef-1`.
8. Update every existing test that calls `buildIssueBody` for the new fourth
   argument (pass `""`).

Also check `internal/e2e/forgejo/` compiles (`go build ./...` covers it); the
e2e tests drive `Export` through its public surface and should not need
changes, but if `idempotency_test.go` asserts exact summary structs, extend
the expectations with the new zero-valued fields.

## Acceptance checklist

- [ ] `issueInfo` carries `Labels` and `Body`; `listFindingIssues` fills them.
- [ ] `reopenIssue`, `updateIssueBody`, `addComment` helpers exist.
- [ ] Risk labels created with the specified names/colors; per-finding label sets sorted.
- [ ] Export flow matches the 8-step order above; reopen guard is `mapForgejoStatus(...) == "fixed"`.
- [ ] Dry-run consults the index, performs only GETs, and its `Summary` matches reality.
- [ ] `buildIssueBody` renders Description and the wiki KB-reference link.
- [ ] Summary/CLI print `reopened=` and `updated=`.
- [ ] Tests 1–8 pass; full suite green; `gofmt -l .` empty.
- [ ] Commit: `git commit -s -m "feat(forgejo): issue lifecycle — reopen on recurrence, risk labels, body refresh, honest dry-run"`

## Out of scope

`pull.go`, ticket-ref persistence semantics (Workstream 03), wiki content
(Workstream 04), redaction (Workstream 05).
