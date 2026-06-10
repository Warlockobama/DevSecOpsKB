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

	if opts.DryRun {
		for _, f := range candidates {
			fmt.Printf("[forgejo] dry-run: would create issue for finding %s (risk=%s url=%s)\n", f.FindingID, f.Risk, f.URL)
		}
		return Summary{Created: len(candidates), TicketRefs: map[string]string{}}, nil
	}

	// Resolve label IDs once (shared dedup label + extras).
	labelNames := append([]string{dedupLabel}, opts.ExtraLabels...)
	labelIDs, err := c.ensureLabels(ctx, labelNames)
	if err != nil {
		return Summary{}, fmt.Errorf("ensure labels: %w", err)
	}
	createLabelIDs := make([]int64, 0, len(labelIDs))
	for _, id := range labelIDs {
		createLabelIDs = append(createLabelIDs, id)
	}

	// Build the dedup index once: all open+closed issues carrying the shared
	// dedup label, keyed by the finding marker found in their body. The winner
	// per finding is the lowest issue number — deterministic regardless of
	// list pagination order.
	byFinding, err := c.listFindingIssues(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("build dedup index: %w", err)
	}
	existing := make(map[string]string, len(byFinding))
	initialDups := false
	for fid, issues := range byFinding {
		existing[fid] = c.issueRef(issues[0].Number)
		if len(issues) > 1 {
			initialDups = true
		}
	}

	ticketRefs := make(map[string]string)
	var mu sync.Mutex
	var created, skipped, errCount int

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, f := range candidates {
		if ref, ok := existing[f.FindingID]; ok {
			mu.Lock()
			skipped++
			ticketRefs[f.FindingID] = ref
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(f entities.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			number, cerr := c.createIssue(ctx, f, defByID[f.DefinitionID], latestOcc[f.FindingID], createLabelIDs)
			mu.Lock()
			defer mu.Unlock()
			if cerr != nil {
				fmt.Printf("[forgejo] error creating issue for %s: %v\n", f.FindingID, cerr)
				errCount++
				return
			}
			created++
			ticketRefs[f.FindingID] = c.issueRef(number)
		}(f)
	}
	wg.Wait()

	// Reconcile duplicates. A concurrent publisher racing the dedup index (or
	// a retried POST that double-landed) leaves two open issues for one
	// finding; converge by keeping the lowest-numbered issue and closing the
	// rest. Skipped when nothing was created and the initial index was clean —
	// the common steady-state re-run costs no extra API calls.
	dupsClosed := 0
	if created > 0 || initialDups {
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

	return Summary{Created: created, Skipped: skipped, Errors: errCount, DuplicatesClosed: dupsClosed, TicketRefs: ticketRefs}, nil
}

// createIssue POSTs a new issue for the finding and returns its number.
func (c *client) createIssue(ctx context.Context, f entities.Finding, def *entities.Definition, occ *entities.Occurrence, labelIDs []int64) (int64, error) {
	payload := map[string]any{
		"title":  issueTitle(f),
		"body":   buildIssueBody(f, def, occ),
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

// issueInfo is the dedup-relevant slice of an issue.
type issueInfo struct {
	Number int64
	State  string // "open" | "closed"
}

// listFindingIssues lists all issues carrying the shared dedup label and
// groups them by the findingID in their hidden body marker, each group sorted
// ascending by issue number (so index 0 is the deterministic winner).
func (c *client) listFindingIssues(ctx context.Context) (map[string][]issueInfo, error) {
	out := make(map[string][]issueInfo)
	page := 1
	for {
		q := url.Values{}
		q.Set("labels", dedupLabel)
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
		}
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode issues: %w", err)
		}
		resp.Body.Close()
		for _, iss := range batch {
			if fid := markerFindingID(iss.Body); fid != "" {
				out[fid] = append(out[fid], issueInfo{Number: iss.Number, State: strings.ToLower(iss.State)})
			}
		}
		if len(batch) < 50 {
			break
		}
		page++
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

// markerFindingID extracts the findingID from a body's hidden marker, or "".
func markerFindingID(body string) string {
	const open = "<!-- devsecopskb-finding:"
	const closeTok = "-->"
	idx := strings.Index(body, open)
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
