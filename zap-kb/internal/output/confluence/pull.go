package confluence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// PullOptions configures the pull operation.
type PullOptions struct {
	BaseURL  string
	SpaceKey string
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

// PullAnalystData fetches analyst triage data from Confluence occurrence pages
// and merges it back into the provided EntitiesFile. Returns modified EntitiesFile.
//
// For each occurrence, it looks up the Confluence page by title (using
// occurrencePageTitle), fetches the storage body, and parses the Workflow
// section for Status/Owner/Tags/Tickets lines.
//
// Merge rule: Confluence value wins when non-empty (Confluence is source of truth
// for analyst edits). Existing entities.Analyst values are used as fallback.
func PullAnalystData(ctx context.Context, ef entities.EntitiesFile, opts PullOptions) (entities.EntitiesFile, PullResult, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.SpaceKey) == "" ||
		strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.Token) == "" {
		return ef, PullResult{}, fmt.Errorf("pull: missing required fields (base URL, space key, username, token)")
	}

	auth := basicAuth(opts.Username, opts.Token)
	base := strings.TrimRight(opts.BaseURL, "/")
	client := newThrottledClient(&http.Client{Timeout: 30 * time.Second}, 250*time.Millisecond)

	ei := buildEntityIndex(&ef)

	const concurrency = 3
	sem := make(chan struct{}, concurrency)

	type occResult struct {
		idx     int
		analyst *entities.Analyst
		found   bool
		err     error
	}

	results := make([]occResult, len(ef.Occurrences))
	var wg sync.WaitGroup

	for i := range ef.Occurrences {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			o := &ef.Occurrences[i]
			title := occurrencePageTitle(o, &ei)
			if title == "" {
				results[i] = occResult{idx: i, err: fmt.Errorf("could not derive page title for occurrence %s", o.OccurrenceID)}
				return
			}

			body, err := fetchPageBody(ctx, client, auth, base, opts.SpaceKey, title)
			if err != nil {
				// Page not found is not a fatal error — just mark as not found.
				results[i] = occResult{idx: i, found: false}
				return
			}

			fields := parseWorkflowFromStorage(body)
			confluenceAnalyst := fieldsToAnalyst(fields)

			merged := mergeAnalystConfluenceWins(confluenceAnalyst, o.Analyst)
			results[i] = occResult{idx: i, analyst: merged, found: true}
		}(i)
	}
	wg.Wait()

	var res PullResult
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("[pull] warning: occurrence index %d: %v\n", r.idx, r.err)
			res.Errors++
			continue
		}
		if !r.found {
			res.NotFound++
			continue
		}
		// Determine if anything actually changed.
		before := ef.Occurrences[r.idx].Analyst
		if analystEqual(before, r.analyst) {
			res.Unchanged++
		} else {
			ef.Occurrences[r.idx].Analyst = r.analyst
			res.Updated++
		}
	}

	return ef, res, nil
}

// fetchPageBody retrieves the Confluence storage body for a page with the given title.
// Returns an error if the page is not found (0 results) or the API call fails.
func fetchPageBody(ctx context.Context, client httpDoer, auth, base, spaceKey, title string) (string, error) {
	q := url.Values{}
	q.Set("title", title)
	q.Set("spaceKey", spaceKey)
	q.Set("expand", "body.storage")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/content?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	var result struct {
		Results []struct {
			Body struct {
				Storage struct {
					Value string `json:"value"`
				} `json:"storage"`
			} `json:"body"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode page response: %w", err)
	}
	if len(result.Results) == 0 {
		return "", fmt.Errorf("page not found: %q", title)
	}
	return result.Results[0].Body.Storage.Value, nil
}

// reHTMLTag matches any HTML tag.
var reHTMLTag = regexp.MustCompile(`<[^>]+>`)

// stripHTMLTags removes all HTML tags from s.
func stripHTMLTags(s string) string {
	return reHTMLTag.ReplaceAllString(s, "")
}

// parseWorkflowFromStorage parses the Workflow section from a Confluence storage body.
// It extracts Status, Owner, Tags, and Tickets fields from lines of the form "- Key: value".
// HTML tags are stripped from each line before parsing.
func parseWorkflowFromStorage(storageBody string) map[string]string {
	fields := make(map[string]string)
	lines := strings.Split(storageBody, "\n")
	for _, line := range lines {
		plain := strings.TrimSpace(stripHTMLTags(line))
		if !strings.HasPrefix(plain, "- ") {
			continue
		}
		rest := plain[2:] // strip "- "
		idx := strings.IndexByte(rest, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(rest[:idx])
		val := strings.TrimSpace(rest[idx+1:])
		switch strings.ToLower(key) {
		case "status", "owner", "tags", "tickets":
			fields[strings.ToLower(key)] = val
		}
	}
	return fields
}

// fieldsToAnalyst builds an Analyst struct from parsed workflow fields.
func fieldsToAnalyst(fields map[string]string) *entities.Analyst {
	a := &entities.Analyst{}
	if v := fields["status"]; v != "" {
		a.Status = v
	}
	if v := fields["owner"]; v != "" {
		a.Owner = v
	}
	if v := fields["tags"]; v != "" {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				a.Tags = append(a.Tags, t)
			}
		}
	}
	if v := fields["tickets"]; v != "" {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				a.TicketRefs = append(a.TicketRefs, t)
			}
		}
	}
	if a.Status == "" && a.Owner == "" && len(a.Tags) == 0 && len(a.TicketRefs) == 0 {
		return nil
	}
	return a
}

// mergeAnalystConfluenceWins merges two Analyst structs where Confluence (conf) wins
// on any non-empty field. Existing (exist) is used as fallback for empty Confluence fields.
func mergeAnalystConfluenceWins(conf, exist *entities.Analyst) *entities.Analyst {
	if conf == nil && exist == nil {
		return nil
	}
	if conf == nil {
		if exist == nil {
			return nil
		}
		cp := *exist
		return &cp
	}
	if exist == nil {
		cp := *conf
		return &cp
	}
	out := *exist // start from existing as fallback
	if conf.Status != "" {
		out.Status = conf.Status
	}
	if conf.Owner != "" {
		out.Owner = conf.Owner
	}
	if conf.Notes != "" {
		out.Notes = conf.Notes
	}
	if len(conf.Tags) > 0 {
		out.Tags = unionStringsPull(conf.Tags, exist.Tags)
	}
	if len(conf.TicketRefs) > 0 {
		out.TicketRefs = unionStringsPull(conf.TicketRefs, exist.TicketRefs)
	}
	return &out
}

// unionStringsPull returns a deduplicated union of a and b, with a first (a wins order).
func unionStringsPull(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// analystEqual returns true if two Analyst pointers represent equal data.
func analystEqual(a, b *entities.Analyst) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Status != b.Status || a.Owner != b.Owner || a.Notes != b.Notes {
		return false
	}
	if !stringSlicesEqual(a.Tags, b.Tags) || !stringSlicesEqual(a.TicketRefs, b.TicketRefs) {
		return false
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
