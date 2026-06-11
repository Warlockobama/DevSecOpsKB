package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// Options controls Forgejo issue export.
type Options struct {
	BaseURL      string // e.g. https://forge.example.com
	Token        string // personal access token
	Owner        string // repo owner (user or org)
	Repo         string // repo name
	ExtraLabels  []string
	MinRisk      string // info|low|medium|high (default "medium")
	OptInTag     string // analyst tag that forces export below MinRisk (default "case-ticket")
	DryRun       bool
	Concurrency  int           // max parallel requests (default 3, capped at 5)
	Timeout      time.Duration // default 30s
	RequestDelay time.Duration
	WikiURLBase  string // e.g. https://forge.example.com/owner/repo/wiki; "" disables the KB-reference link
}

// Summary reports the outcome of an export run.
type Summary struct {
	Created int
	Skipped int // already existed
	Errors  int
	// DuplicatesClosed counts duplicate open issues (same finding marker)
	// closed by the post-create reconcile pass. Duplicates appear when two
	// publishers race the dedup index or a retried create double-lands; the
	// reconcile converges on the lowest-numbered issue per finding.
	DuplicatesClosed int
	// Reopened counts closed-as-fixed issues reopened because the finding
	// recurred in this run.
	Reopened int
	// BodiesUpdated counts open issues whose machine-owned description was
	// refreshed because the rendered body changed.
	BodiesUpdated int
	// TicketRefs maps findingID → issue reference ("owner/repo#42"). Persisted
	// back onto analyst.ticketRefs so subsequent runs short-circuit dedup.
	TicketRefs map[string]string
}

// issueRef formats the stable cross-run reference for an issue number.
func (c *client) issueRef(number int64) string {
	return fmt.Sprintf("%s/%s#%d", c.owner, c.repo, number)
}

// Export creates Forgejo issues for findings at or above opts.MinRisk (or with
// the analyst opt-in tag). Findings whose issue already exists — detected via
// the hidden body marker on KB-managed issues — are skipped. Issues are created
// in parallel up to opts.Concurrency.
func Export(ctx context.Context, ef entities.EntitiesFile, opts Options) (Summary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.Token) == "" ||
		strings.TrimSpace(opts.Owner) == "" || strings.TrimSpace(opts.Repo) == "" {
		return Summary{}, fmt.Errorf("forgejo export: missing required fields (base URL, token, owner, repo)")
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}
	floor := synccore.SeverityFloor(opts.MinRisk)
	if strings.TrimSpace(opts.MinRisk) == "" {
		floor = synccore.SeverityFloor("medium")
	}
	optInTag := strings.TrimSpace(opts.OptInTag)
	if optInTag == "" {
		optInTag = "case-ticket"
	}

	c := newClient(defaultHTTP(opts.Timeout, opts.RequestDelay), opts.BaseURL, opts.Token, opts.Owner, opts.Repo)

	// Index definitions and pick the latest occurrence per finding for evidence.
	defByID := make(map[string]*entities.Definition, len(ef.Definitions))
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		defByID[d.DefinitionID] = d
	}
	latestOcc := make(map[string]*entities.Occurrence, len(ef.Findings))
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		if cur, ok := latestOcc[o.FindingID]; !ok || occurrenceIsNewer(o, cur) {
			latestOcc[o.FindingID] = o
		}
	}

	// Candidate findings: risk floor or explicit analyst opt-in.
	var candidates []entities.Finding
	for _, f := range ef.Findings {
		if synccore.SeverityFloor(f.Risk) >= floor || findingHasTag(f, optInTag) {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return Summary{TicketRefs: map[string]string{}}, nil
	}

	// Build the dedup index first (GET-only): all open+closed KB-managed issues
	// keyed by finding marker, winner = lowest issue number. Needed by dry-run
	// (to report accurately) and by the create/reopen/refresh branch below.
	byFinding, err := c.listFindingIssues(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("build dedup index: %w", err)
	}
	initialDups := false
	for _, issues := range byFinding {
		if len(issues) > 1 {
			initialDups = true
		}
	}

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

	// Resolve label IDs once: shared dedup label + extras + every risk label any
	// candidate needs. Sorted (after the leading dedupLabel) for deterministic
	// payloads.
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
	labelIDByName, err := c.ensureLabels(ctx, labelNames)
	if err != nil {
		return Summary{}, fmt.Errorf("ensure labels: %w", err)
	}

	ticketRefs := make(map[string]string)
	var mu sync.Mutex
	var created, skipped, reopened, bodiesUpdated, errCount int

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, f := range candidates {
		wg.Add(1)
		go func(f entities.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			def := defByID[f.DefinitionID]
			occ := latestOcc[f.FindingID]

			issues, exists := byFinding[f.FindingID]
			if !exists {
				number, cerr := c.createIssue(ctx, f, def, occ, labelIDsForFinding(f, labelIDByName, opts.ExtraLabels), opts.WikiURLBase)
				mu.Lock()
				defer mu.Unlock()
				if cerr != nil {
					fmt.Printf("[forgejo] error creating issue for %s: %v\n", f.FindingID, cerr)
					errCount++
					return
				}
				created++
				ticketRefs[f.FindingID] = c.issueRef(number)
				return
			}

			w := issues[0]
			ref := c.issueRef(w.Number)

			// Closed as fp/accepted is an analyst disposition — never override it.
			if w.State == "closed" && mapForgejoStatus(w.State, w.Labels) != "fixed" {
				mu.Lock()
				skipped++
				ticketRefs[f.FindingID] = ref
				mu.Unlock()
				return
			}

			// Closed as fixed but the finding recurred → reopen + explain.
			justReopened := false
			if w.State == "closed" {
				if rerr := c.reopenIssue(ctx, w.Number); rerr != nil {
					mu.Lock()
					fmt.Printf("[forgejo] error reopening #%d for %s: %v\n", w.Number, f.FindingID, rerr)
					errCount++
					mu.Unlock()
					return
				}
				comment := fmt.Sprintf("Reopened by DevSecOpsKB: this finding recurred in the latest scan (risk: %s). If it was intentionally dismissed, label the issue `false-positive` or `accepted` to prevent automatic reopening.", titleCase(f.Risk))
				if cerr := c.addComment(ctx, w.Number, comment); cerr != nil {
					mu.Lock()
					fmt.Printf("[forgejo] warning: reopened #%d but failed to comment: %v\n", w.Number, cerr)
					mu.Unlock()
				}
				justReopened = true
			}

			// Open (or just reopened): refresh the machine-owned body if it drifted.
			desired := buildIssueBody(f, def, occ, opts.WikiURLBase)
			bodyChanged := desired != w.Body
			if bodyChanged {
				if uerr := c.updateIssueBody(ctx, w.Number, desired); uerr != nil {
					mu.Lock()
					fmt.Printf("[forgejo] error updating body #%d for %s: %v\n", w.Number, f.FindingID, uerr)
					errCount++
					mu.Unlock()
					return
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if justReopened {
				reopened++
			}
			if bodyChanged {
				bodiesUpdated++
			} else if !justReopened {
				skipped++
			}
			ticketRefs[f.FindingID] = ref
		}(f)
	}
	wg.Wait()

	// Reconcile duplicates. A concurrent publisher racing the dedup index (or
	// a retried POST that double-landed) leaves two open issues for one
	// finding; converge by keeping the lowest-numbered issue and closing the
	// rest. Skipped when nothing changed and the initial index was clean —
	// the common steady-state re-run costs no extra API calls.
	dupsClosed := 0
	if created > 0 || reopened > 0 || initialDups {
		closed, winners, rerr := c.reconcileDuplicates(ctx)
		if rerr != nil {
			fmt.Printf("[forgejo] warning: duplicate reconcile failed: %v\n", rerr)
			errCount++
		} else {
			dupsClosed = closed
			// Repoint refs at the surviving winner so persisted ticketRefs
			// never reference an issue the reconcile just closed.
			for fid, ref := range winners {
				if _, ours := ticketRefs[fid]; ours {
					ticketRefs[fid] = ref
				}
			}
		}
	}

	return Summary{
		Created:          created,
		Skipped:          skipped,
		Reopened:         reopened,
		BodiesUpdated:    bodiesUpdated,
		Errors:           errCount,
		DuplicatesClosed: dupsClosed,
		TicketRefs:       ticketRefs,
	}, nil
}

// labelIDsForFinding returns the base labels (dedup + extras) plus the finding's
// risk label, sorted ascending for deterministic payloads. Names absent from
// labelIDByName (e.g. an extra that failed to resolve) are skipped.
func labelIDsForFinding(f entities.Finding, labelIDByName map[string]int64, extras []string) []int64 {
	ids := make([]int64, 0, len(extras)+2)
	if id, ok := labelIDByName[dedupLabel]; ok {
		ids = append(ids, id)
	}
	for _, e := range extras {
		if id, ok := labelIDByName[strings.TrimSpace(e)]; ok {
			ids = append(ids, id)
		}
	}
	if rl := riskLabel(f.Risk); rl != "" {
		if id, ok := labelIDByName[rl]; ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// createIssue POSTs a new issue for the finding and returns its number.
func (c *client) createIssue(ctx context.Context, f entities.Finding, def *entities.Definition, occ *entities.Occurrence, labelIDs []int64, wikiURLBase string) (int64, error) {
	payload := map[string]any{
		"title":  issueTitle(f),
		"body":   buildIssueBody(f, def, occ, wikiURLBase),
		"labels": labelIDs,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal issue: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, c.repoAPI()+"/issues", data)
	if err != nil {
		return 0, err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var created struct {
		Number int64 `json:"number"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, fmt.Errorf("decode created issue: %w", err)
	}
	return created.Number, nil
}

// issueInfo is the dedup- and lifecycle-relevant slice of an issue.
type issueInfo struct {
	Number int64
	State  string   // "open" | "closed"
	Labels []string // label names, for fp/accepted detection on reopen
	Body   string   // current body, for refresh comparison
}

// listFindingIssues lists ALL issues in the repo and groups the KB-managed
// ones (recognized by the hidden body marker) by findingID, each group sorted
// ascending by issue number (so index 0 is the deterministic winner).
//
// Deliberately NOT filtered by the kb-finding label: Forgejo/Gitea allow
// duplicate label names, and once two same-named labels exist (e.g. from a
// first-run create race) the `?labels=<name>` query silently returns NOTHING —
// which would blind the dedup index and duplicate every finding on every run.
// The label stays attached for humans; correctness rides on the marker only.
func (c *client) listFindingIssues(ctx context.Context) (map[string][]issueInfo, error) {
	out := make(map[string][]issueInfo)
	seen := make(map[int64]bool)
	page := 1
	for {
		q := url.Values{}
		q.Set("state", "all")
		q.Set("type", "issues")
		q.Set("limit", "50")
		q.Set("page", fmt.Sprintf("%d", page))
		req, err := c.newRequest(ctx, http.MethodGet, c.repoAPI()+"/issues?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := synccore.DoWithRetry(c.http, req, 3)
		if err != nil {
			return nil, err
		}
		var batch []struct {
			Number int64  `json:"number"`
			Body   string `json:"body"`
			State  string `json:"state"`
			Labels []struct {
				Name string `json:"name"`
			} `json:"labels"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode issues: %w", err)
		}
		resp.Body.Close()
		// Progress-based termination: stop when a page adds no issue numbers we
		// have not already seen. This is robust both to servers that cap `limit`
		// below our requested 50 (a "full" page can be short — the old
		// len<50 break would stop early and blind the dedup index) and to
		// servers that ignore `page` entirely (which would otherwise loop
		// forever). Dedup is keyed on the issue number.
		added := 0
		for _, iss := range batch {
			if seen[iss.Number] {
				continue
			}
			seen[iss.Number] = true
			added++
			if fid := markerFindingID(iss.Body); fid != "" {
				names := make([]string, 0, len(iss.Labels))
				for _, l := range iss.Labels {
					names = append(names, l.Name)
				}
				out[fid] = append(out[fid], issueInfo{Number: iss.Number, State: strings.ToLower(iss.State), Labels: names, Body: iss.Body})
			}
		}
		if added == 0 {
			break
		}
		page++
		if page > 1000 {
			return nil, fmt.Errorf("forgejo: issue pagination exceeded 1000 pages — aborting (server ignoring page param?)")
		}
	}
	for fid := range out {
		sort.Slice(out[fid], func(i, j int) bool { return out[fid][i].Number < out[fid][j].Number })
	}
	return out, nil
}

// reconcileDuplicates re-lists KB-managed issues and, for every finding with
// more than one issue, keeps the lowest-numbered one and closes the other OPEN
// ones. Returns (closedCount, findingID → winning issue ref). Closing an
// already-closed duplicate is a no-op, so concurrent reconciles converge.
func (c *client) reconcileDuplicates(ctx context.Context) (int, map[string]string, error) {
	byFinding, err := c.listFindingIssues(ctx)
	if err != nil {
		return 0, nil, err
	}
	winners := make(map[string]string, len(byFinding))
	closed := 0
	for fid, issues := range byFinding {
		winners[fid] = c.issueRef(issues[0].Number)
		for _, dup := range issues[1:] {
			if dup.State != "open" {
				continue
			}
			if cerr := c.closeIssue(ctx, dup.Number); cerr != nil {
				return closed, winners, fmt.Errorf("close duplicate #%d for %s: %w", dup.Number, fid, cerr)
			}
			fmt.Printf("[forgejo] closed duplicate issue #%d for finding %s (winner %s)\n", dup.Number, fid, winners[fid])
			closed++
		}
	}
	return closed, winners, nil
}

// closeIssue PATCHes an issue to state=closed.
func (c *client) closeIssue(ctx context.Context, number int64) error {
	payload, err := json.Marshal(map[string]string{"state": "closed"})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", c.repoAPI(), number), payload)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// reopenIssue PATCHes an issue back to state=open.
func (c *client) reopenIssue(ctx context.Context, number int64) error {
	payload, err := json.Marshal(map[string]string{"state": "open"})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", c.repoAPI(), number), payload)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// updateIssueBody PATCHes an issue's body.
func (c *client) updateIssueBody(ctx context.Context, number int64, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", c.repoAPI(), number), payload)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// addComment POSTs a comment to an issue.
func (c *client) addComment(ctx context.Context, number int64, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", c.repoAPI(), number), payload)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// markerFindingID extracts the findingID from a body's hidden marker, or "".
// The LAST marker wins: the sink appends the genuine marker at the very end of
// every body it writes, after the Evidence section. Evidence is content
// controlled by the scanned site, so an earlier (forged) marker embedded in a
// response snippet must never shadow the real one.
func markerFindingID(body string) string {
	const open = "<!-- devsecopskb-finding:"
	const closeTok = "-->"
	idx := strings.LastIndex(body, open)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(open):]
	end := strings.Index(rest, closeTok)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

// findingHasTag reports whether the finding's analyst tags include tag.
func findingHasTag(f entities.Finding, tag string) bool {
	if f.Analyst == nil {
		return false
	}
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return false
	}
	for _, c := range f.Analyst.Tags {
		if strings.ToLower(strings.TrimSpace(c)) == tag {
			return true
		}
	}
	return false
}

// occurrenceIsNewer reports whether a should replace b as the latest occurrence.
// Compares ObservedAt as RFC3339 when both parse, else string order; ties break
// on OccurrenceID so the choice is deterministic across runs.
func occurrenceIsNewer(a, b *entities.Occurrence) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	ta, errA := time.Parse(time.RFC3339, strings.TrimSpace(a.ObservedAt))
	tb, errB := time.Parse(time.RFC3339, strings.TrimSpace(b.ObservedAt))
	aOK, bOK := errA == nil, errB == nil
	switch {
	case aOK && bOK:
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
	case aOK && !bOK:
		return true
	case !aOK && bOK:
		return false
	default:
		if a.ObservedAt != b.ObservedAt {
			return a.ObservedAt > b.ObservedAt
		}
	}
	return a.OccurrenceID > b.OccurrenceID
}
