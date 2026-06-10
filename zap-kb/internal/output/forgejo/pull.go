package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	}
	statusCache := make(map[int64]cached)
	var cacheMu sync.Mutex
	const concurrency = 3
	sem := make(chan struct{}, concurrency)

	type refResult struct {
		ref    ticketRef
		mapped string
		raw    string
		found  bool
		err    error
	}
	results := make([]refResult, len(refs))
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref ticketRef) {
			defer wg.Done()
			cacheMu.Lock()
			if hit, ok := statusCache[ref.number]; ok {
				cacheMu.Unlock()
				results[i] = refResult{ref: ref, mapped: hit.mapped, raw: hit.raw, found: hit.found}
				return
			}
			cacheMu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()
			mapped, raw, found, err := c.fetchIssueStatus(ctx, ref.number)
			if err != nil {
				results[i] = refResult{ref: ref, err: err}
				return
			}
			cacheMu.Lock()
			statusCache[ref.number] = cached{mapped: mapped, raw: raw, found: found}
			cacheMu.Unlock()
			results[i] = refResult{ref: ref, mapped: mapped, raw: raw, found: found}
		}(i, ref)
	}
	wg.Wait()

	var res PullResult
	rawStatuses := make(map[string]string)
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("[forgejo pull] warning: #%d: %v\n", r.ref.number, r.err)
			res.Errors++
			continue
		}
		if !r.found {
			res.NotFound++
			continue
		}
		if r.raw != "" {
			rawStatuses[c.issueRef(r.ref.number)] = r.raw
		}
		if r.mapped == "" {
			res.Unmapped++
			continue
		}
		if opts.ReadOnly {
			res.Unchanged++
			continue
		}
		switch r.ref.kind {
		case "finding":
			f := &ef.Findings[r.ref.idx]
			if f.Analyst == nil {
				f.Analyst = &entities.Analyst{}
			}
			if f.Analyst.Status == r.mapped {
				res.Unchanged++
			} else {
				f.Analyst.Status = r.mapped
				res.Updated++
			}
		case "occurrence":
			o := &ef.Occurrences[r.ref.idx]
			if o.Analyst == nil {
				o.Analyst = &entities.Analyst{}
			}
			if o.Analyst.Status == r.mapped {
				res.Unchanged++
			} else {
				o.Analyst.Status = r.mapped
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
	resp, err := c.http.Do(req)
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

// extractIssueNumber parses a Forgejo issue ref into its number. Accepts the
// canonical "owner/repo#42" form (matching repoPrefix), a bare "#42", a bare
// "42", or a browse URL ending in "/issues/42". Returns ok=false for refs that
// don't belong to this repo (e.g. Jira keys) so cross-tracker KBs stay clean.
func extractIssueNumber(ref, repoPrefix string) (int64, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return 0, false
	}
	// Browse URL form: .../issues/42
	if strings.Contains(ref, "/issues/") {
		seg := ref[strings.LastIndex(ref, "/issues/")+len("/issues/"):]
		seg = strings.TrimRight(seg, "/")
		if n, ok := parsePositiveInt(seg); ok {
			return n, true
		}
		return 0, false
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
