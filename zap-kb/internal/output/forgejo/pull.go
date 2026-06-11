package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// PullOptions configures the Forgejo status pull.
type PullOptions struct {
	BaseURL  string
	Token    string
	Owner    string
	Repo     string
	ReadOnly bool // when true, do not mutate KB entity state
	Timeout  time.Duration
}

// PullResult reports what the pull did.
type PullResult struct {
	Updated   int
	Unchanged int
	NotFound  int
	Unmapped  int
	Errors    int
}

// PullStatusResult bundles the updated entities with the operation summary.
type PullStatusResult struct {
	Updated     entities.EntitiesFile
	Result      PullResult
	RawStatuses map[string]string // issue ref → "open"/"closed"
	SyncedAt    string            // RFC3339 fetch time
}

// PullStatus fetches the current state+labels for every finding/occurrence that
// has a Forgejo TicketRef, maps it to a canonical KB status, and (unless
// ReadOnly) writes it back into Analyst.Status. Refs that don't look like a
// Forgejo issue ref ("owner/repo#N") are ignored so Jira refs in the same KB
// are left untouched.
func PullStatus(ctx context.Context, ef entities.EntitiesFile, opts PullOptions) (PullStatusResult, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.Token) == "" ||
		strings.TrimSpace(opts.Owner) == "" || strings.TrimSpace(opts.Repo) == "" {
		return PullStatusResult{}, fmt.Errorf("forgejo pull: missing required fields (base URL, token, owner, repo)")
	}
	c := newClient(defaultHTTP(opts.Timeout, 0), opts.BaseURL, opts.Token, opts.Owner, opts.Repo)
	repoPrefix := opts.Owner + "/" + opts.Repo

	type ticketRef struct {
		number int64
		kind   string // "finding" | "occurrence"
		idx    int
	}
	var refs []ticketRef
	for i, f := range ef.Findings {
		if f.Analyst == nil {
			continue
		}
		for _, t := range f.Analyst.TicketRefs {
			if n, ok := extractIssueNumber(t, repoPrefix); ok {
				refs = append(refs, ticketRef{number: n, kind: "finding", idx: i})
			}
		}
	}
	for i, o := range ef.Occurrences {
		if o.Analyst == nil {
			continue
		}
		for _, t := range o.Analyst.TicketRefs {
			if n, ok := extractIssueNumber(t, repoPrefix); ok {
				refs = append(refs, ticketRef{number: n, kind: "occurrence", idx: i})
			}
		}
	}
	if len(refs) == 0 {
		return PullStatusResult{Updated: ef, SyncedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}

	type cached struct {
		mapped string
		raw    string
		found  bool
		err    error
	}

	// Fetch each DISTINCT issue number exactly once. Multiple findings and
	// occurrences can carry the same ticket ref; the previous per-goroutine
	// cache check raced (every goroutine missed the empty cache before any had
	// populated it) and re-fetched the same issue N times.
	uniq := make(map[int64]struct{}, len(refs))
	for _, ref := range refs {
		uniq[ref.number] = struct{}{}
	}
	numbers := make([]int64, 0, len(uniq))
	for n := range uniq {
		numbers = append(numbers, n)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })

	statusCache := make(map[int64]cached, len(numbers))
	var cacheMu sync.Mutex
	const concurrency = 3
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, n := range numbers {
		wg.Add(1)
		go func(n int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mapped, raw, found, err := c.fetchIssueStatus(ctx, n)
			cacheMu.Lock()
			statusCache[n] = cached{mapped: mapped, raw: raw, found: found, err: err}
			cacheMu.Unlock()
		}(n)
	}
	wg.Wait()

	var res PullResult
	rawStatuses := make(map[string]string)
	for _, ref := range refs {
		hit := statusCache[ref.number]
		if hit.err != nil {
			fmt.Printf("[forgejo pull] warning: #%d: %v\n", ref.number, hit.err)
			res.Errors++
			continue
		}
		if !hit.found {
			res.NotFound++
			continue
		}
		if hit.raw != "" {
			rawStatuses[c.issueRef(ref.number)] = hit.raw
		}
		if hit.mapped == "" {
			res.Unmapped++
			continue
		}
		if opts.ReadOnly {
			res.Unchanged++
			continue
		}
		switch ref.kind {
		case "finding":
			f := &ef.Findings[ref.idx]
			if f.Analyst == nil {
				f.Analyst = &entities.Analyst{}
			}
			if f.Analyst.Status == hit.mapped {
				res.Unchanged++
			} else {
				f.Analyst.Status = hit.mapped
				res.Updated++
			}
		case "occurrence":
			o := &ef.Occurrences[ref.idx]
			if o.Analyst == nil {
				o.Analyst = &entities.Analyst{}
			}
			if o.Analyst.Status == hit.mapped {
				res.Unchanged++
			} else {
				o.Analyst.Status = hit.mapped
				res.Updated++
			}
		}
	}
	return PullStatusResult{
		Updated:     ef,
		Result:      res,
		RawStatuses: rawStatuses,
		SyncedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// fetchIssueStatus returns (mappedStatus, rawState, found, err) for an issue.
func (c *client) fetchIssueStatus(ctx context.Context, number int64) (string, string, bool, error) {
	url := fmt.Sprintf("%s/issues/%d", c.repoAPI(), number)
	req, err := c.newRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", false, err
	}
	// Raw variant: transient 429/5xx are retried, but a terminal 404 still
	// reaches us as data ("issue not found") rather than an error.
	resp, err := synccore.DoWithRetryRaw(c.http, req, 3)
	if err != nil {
		return "", "", false, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return "", "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false, synccore.HTTPError("forgejo", resp)
	}
	var issue struct {
		State  string `json:"state"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return "", "", false, fmt.Errorf("decode issue: %w", err)
	}
	labels := make([]string, 0, len(issue.Labels))
	for _, l := range issue.Labels {
		labels = append(labels, l.Name)
	}
	return mapForgejoStatus(issue.State, labels), strings.TrimSpace(issue.State), true, nil
}

// ExtractIssueNumber reports whether ref denotes an issue of the repo
// identified by repoPrefix ("owner/repo"), and its number. See
// extractIssueNumber for the accepted forms.
func ExtractIssueNumber(ref, repoPrefix string) (int64, bool) {
	return extractIssueNumber(ref, repoPrefix)
}

// extractIssueNumber parses a Forgejo issue ref into its number. Accepts the
// canonical "owner/repo#42" form (matching repoPrefix), a bare "#42", a bare
// "42", or a browse URL ".../<owner>/<repo>/issues/42". Both the owner/repo#N
// and the URL forms must name THIS repo (repoPrefix); refs for other repos or
// other trackers (Jira keys, a pasted GitHub link) return ok=false so a
// cross-tracker KB stays clean.
func extractIssueNumber(ref, repoPrefix string) (int64, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, false
	}
	// Browse URL form: …/<owner>/<repo>/issues/42 — only accepted when
	// <owner>/<repo> matches this repo, so a URL pasted from another tracker
	// is never misread as a local issue number.
	if i := strings.LastIndex(ref, "/issues/"); i >= 0 {
		head := strings.TrimRight(ref[:i], "/")
		if !strings.HasSuffix(strings.ToLower(head), "/"+strings.ToLower(repoPrefix)) {
			return 0, false
		}
		seg := strings.TrimRight(ref[i+len("/issues/"):], "/")
		return parsePositiveInt(seg)
	}
	// owner/repo#42 form.
	if i := strings.Index(ref, "#"); i >= 0 {
		prefix := strings.TrimSpace(ref[:i])
		num := strings.TrimSpace(ref[i+1:])
		if prefix != "" && !strings.EqualFold(prefix, repoPrefix) {
			return 0, false // belongs to a different repo
		}
		return parsePositiveInt(num)
	}
	// Bare number.
	return parsePositiveInt(ref)
}

func parsePositiveInt(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int64(r-'0')
	}
	if n == 0 {
		return 0, false
	}
	return n, true
}
