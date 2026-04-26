package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// PullOptions configures the Jira status pull operation.
type PullOptions struct {
	BaseURL  string
	Username string
	Token    string
}

// PullResult reports what the pull operation did.
type PullResult struct {
	Updated   int
	Unchanged int
	NotFound  int
	Errors    int
}

// PullStatusResult bundles the updated EntitiesFile with the operation summary.
type PullStatusResult struct {
	Updated      entities.EntitiesFile
	Result       PullResult
	RawStatuses  map[string]string // Jira issue key -> raw Jira status name
	RawAssignees map[string]string // Jira issue key -> assignee display name ("" when unassigned)
	SyncedAt     string            // RFC3339 time when Jira status data was fetched
}

// PullStatus fetches the current Jira ticket status for every finding and
// occurrence that has a TicketRef, and merges the mapped status back into
// Analyst.Status. Jira wins on status; all other analyst fields are preserved.
//
// Status mapping (case-insensitive):
//
//	"to do" / "open" / "backlog"           → open
//	"in progress" / "triaged" / "review"   → triaged
//	"done" / "closed" / "fixed" / "resolved" → fixed
//	"won't fix" / "risk accepted" / "accepted" / "wont fix" → accepted
//	"false positive" / "fp"                → fp
//
// Tickets whose status doesn't match any mapping are left unchanged.
func PullStatus(ctx context.Context, ef entities.EntitiesFile, opts PullOptions) (PullStatusResult, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.Token) == "" {
		return PullStatusResult{}, fmt.Errorf("jira pull: missing required fields (base URL, username, token)")
	}

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(opts.Username+":"+opts.Token))
	base := strings.TrimRight(opts.BaseURL, "/")
	client := newThrottledClient(&http.Client{Timeout: 30 * time.Second}, 250*time.Millisecond)

	// Collect all unique ticket keys referenced by findings and occurrences.
	type ticketRef struct {
		key  string // e.g. "KAN-133"
		kind string // "finding" or "occurrence"
		idx  int
	}
	var refs []ticketRef
	for i, f := range ef.Findings {
		if f.Analyst == nil {
			continue
		}
		for _, t := range f.Analyst.TicketRefs {
			if k := extractTicketKey(t); k != "" {
				refs = append(refs, ticketRef{key: k, kind: "finding", idx: i})
			}
		}
	}
	for i, o := range ef.Occurrences {
		if o.Analyst == nil {
			continue
		}
		for _, t := range o.Analyst.TicketRefs {
			if k := extractTicketKey(t); k != "" {
				refs = append(refs, ticketRef{key: k, kind: "occurrence", idx: i})
			}
		}
	}

	if len(refs) == 0 {
		return PullStatusResult{Updated: ef, Result: PullResult{}}, nil
	}

	// Deduplicate ticket keys to avoid redundant API calls.
	type cachedFields struct {
		mapped   string
		raw      string
		assignee string
		found    bool
	}
	statusCache := make(map[string]cachedFields)
	var cacheMu sync.Mutex

	const concurrency = 3
	sem := make(chan struct{}, concurrency)

	type refResult struct {
		ref      ticketRef
		status   string // mapped status; "" = not found or unmapped
		raw      string // raw Jira status name
		assignee string // Jira assignee display name; "" when unassigned
		found    bool
		err      error
	}
	results := make([]refResult, len(refs))

	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref ticketRef) {
			defer wg.Done()

			cacheMu.Lock()
			if cached, ok := statusCache[ref.key]; ok {
				cacheMu.Unlock()
				results[i] = refResult{ref: ref, status: cached.mapped, raw: cached.raw, assignee: cached.assignee, found: cached.found}
				return
			}
			cacheMu.Unlock()

			sem <- struct{}{}
			defer func() { <-sem }()

			mapped, raw, assignee, found, err := fetchJiraFields(ctx, client, auth, base, ref.key)
			if err != nil {
				results[i] = refResult{ref: ref, err: err}
				return
			}
			cacheMu.Lock()
			statusCache[ref.key] = cachedFields{mapped: mapped, raw: raw, assignee: assignee, found: found}
			cacheMu.Unlock()
			results[i] = refResult{ref: ref, status: mapped, raw: raw, assignee: assignee, found: found}
		}(i, ref)
	}
	wg.Wait()

	var res PullResult
	rawStatuses := make(map[string]string)
	rawAssignees := make(map[string]string)
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("[jira pull] warning: %s: %v\n", r.ref.key, r.err)
			res.Errors++
			continue
		}
		if !r.found {
			res.NotFound++
			continue
		}
		if strings.TrimSpace(r.raw) != "" {
			rawStatuses[r.ref.key] = r.raw
		}
		// Capture assignee even when the status is unmapped so live Owner
		// display still works. Empty string means the Jira issue is unassigned.
		rawAssignees[r.ref.key] = strings.TrimSpace(r.assignee)

		// Owner write-back (#61): non-destructive — fill analyst.Owner when
		// the KB side is empty and Jira reports an assignee. This MUST run
		// before the r.status == "" early-continue so the write-back fires
		// even for tickets with custom/unmapped Jira workflow states.
		if assignee := strings.TrimSpace(r.assignee); assignee != "" {
			switch r.ref.kind {
			case "finding":
				f := &ef.Findings[r.ref.idx]
				if f.Analyst == nil {
					f.Analyst = &entities.Analyst{}
				}
				if strings.TrimSpace(f.Analyst.Owner) == "" {
					f.Analyst.Owner = assignee
				}
			case "occurrence":
				o := &ef.Occurrences[r.ref.idx]
				if o.Analyst == nil {
					o.Analyst = &entities.Analyst{}
				}
				if strings.TrimSpace(o.Analyst.Owner) == "" {
					o.Analyst.Owner = assignee
				}
			}
		}

		if r.status == "" {
			res.NotFound++
			continue
		}

		switch r.ref.kind {
		case "finding":
			f := &ef.Findings[r.ref.idx]
			if f.Analyst == nil {
				f.Analyst = &entities.Analyst{}
			}
			if f.Analyst.Status == r.status {
				res.Unchanged++
			} else {
				f.Analyst.Status = r.status
				res.Updated++
			}
		case "occurrence":
			o := &ef.Occurrences[r.ref.idx]
			if o.Analyst == nil {
				o.Analyst = &entities.Analyst{}
			}
			if o.Analyst.Status == r.status {
				res.Unchanged++
			} else {
				o.Analyst.Status = r.status
				res.Updated++
			}
		}
	}
	return PullStatusResult{Updated: ef, Result: res, RawStatuses: rawStatuses, RawAssignees: rawAssignees, SyncedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}

// fetchJiraFields retrieves the Jira issue status and assignee for the given
// key. Returns (mappedStatus, rawStatus, assigneeDisplayName, found, err).
// Returns found=false when the issue is not found. mappedStatus may be "" when
// the Jira status does not map to a canonical value; assignee may be "" when
// the issue is unassigned.
func fetchJiraFields(ctx context.Context, client httpDoer, auth, base, key string) (string, string, string, bool, error) {
	url := base + "/rest/api/3/issue/" + key + "?fields=status,assignee"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", "", false, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", "", "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		io.Copy(io.Discard, resp.Body)
		return "", "", "", false, nil
	}
	if resp.StatusCode != 200 {
		return "", "", "", false, jiraHTTPErr(resp)
	}

	const maxBody = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", "", "", false, fmt.Errorf("read response: %w", err)
	}

	var result struct {
		Fields struct {
			Status struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee *struct {
				DisplayName  string `json:"displayName"`
				EmailAddress string `json:"emailAddress"`
			} `json:"assignee"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", "", "", false, fmt.Errorf("decode issue: %w", err)
	}

	rawStatus := strings.TrimSpace(result.Fields.Status.Name)
	mapped := mapJiraStatus(rawStatus)
	assignee := ""
	if result.Fields.Assignee != nil {
		assignee = strings.TrimSpace(result.Fields.Assignee.DisplayName)
		if assignee == "" {
			assignee = strings.TrimSpace(result.Fields.Assignee.EmailAddress)
		}
	}
	return mapped, rawStatus, assignee, true, nil
}

// mapJiraStatus converts a Jira status name to one of the canonical values:
// open, triaged, fixed, accepted, fp. Returns "" for unknown statuses.
func mapJiraStatus(jiraStatus string) string {
	switch strings.ToLower(strings.TrimSpace(jiraStatus)) {
	case "to do", "open", "backlog", "new":
		return "open"
	case "in progress", "triaged", "in review", "review", "under review":
		return "triaged"
	case "done", "closed", "fixed", "resolved", "completed":
		return "fixed"
	case "won't fix", "wont fix", "risk accepted", "accepted", "mitigated":
		return "accepted"
	case "false positive", "fp", "not a bug", "not applicable":
		return "fp"
	}
	return ""
}

// extractTicketKey extracts a bare issue key (e.g. "KAN-133") from a ticket
// ref that may be a plain key or a URL like ".../browse/KAN-133".
func extractTicketKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	// If it looks like a URL, take the last path segment.
	if strings.Contains(ref, "/") {
		parts := strings.Split(ref, "/")
		ref = parts[len(parts)-1]
	}
	// Validate: must look like PROJ-NNN (letters, hyphen, digits).
	ref = strings.TrimSpace(ref)
	if len(ref) == 0 {
		return ""
	}
	hyphen := strings.LastIndex(ref, "-")
	if hyphen < 1 || hyphen == len(ref)-1 {
		return ""
	}
	return ref
}
