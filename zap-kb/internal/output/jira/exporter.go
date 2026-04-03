package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// Options controls Jira issue export.
type Options struct {
	BaseURL      string
	Username     string // email for Jira Cloud
	APIToken     string
	ProjectKey   string
	IssueType    string   // default "Bug"
	Component    string   // optional component name
	ExtraLabels  []string // additional labels beyond zap-finding:<id>
	MinRisk      string   // minimum risk to export: info|low|medium|high (default "low")
	DryRun       bool
	Concurrency  int           // max parallel requests (default 3, capped at 5)
	Timeout      time.Duration // default 30s
	RequestDelay time.Duration // minimum delay between API requests; default 250ms
}

// httpDoer abstracts HTTP request execution for throttling and testing.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// throttledClient wraps an http.Client with a minimum delay between requests.
type throttledClient struct {
	inner *http.Client
	mu    sync.Mutex
	last  time.Time
	delay time.Duration
}

func newThrottledClient(inner *http.Client, delay time.Duration) *throttledClient {
	return &throttledClient{inner: inner, delay: delay}
}

func (tc *throttledClient) Do(req *http.Request) (*http.Response, error) {
	tc.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(tc.last)
	if elapsed < tc.delay {
		remaining := tc.delay - elapsed
		tc.last = now.Add(remaining)
		tc.mu.Unlock()
		select {
		case <-time.After(remaining):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	} else {
		tc.last = now
		tc.mu.Unlock()
	}
	return tc.inner.Do(req)
}

// Summary reports the outcome of an export run.
type Summary struct {
	Created int
	Skipped int // already existed
	Errors  int
}

// Export creates Jira issues for each Finding at or above opts.MinRisk.
// Findings that already have a matching issue (by label zap-finding:<findingID>) are skipped.
// Issues are created in parallel up to opts.Concurrency.
func Export(ctx context.Context, ef entities.EntitiesFile, opts Options) (Summary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.ProjectKey) == "" ||
		strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.APIToken) == "" {
		return Summary{}, fmt.Errorf("jira export: missing required fields (base URL, project key, username, api token)")
	}

	issueType := opts.IssueType
	if strings.TrimSpace(issueType) == "" {
		issueType = "Bug"
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}

	rawClient := &http.Client{Timeout: opts.Timeout}
	if rawClient.Timeout == 0 {
		rawClient.Timeout = 30 * time.Second
	}
	delay := opts.RequestDelay
	if delay == 0 {
		delay = 250 * time.Millisecond
	}
	httpClient := newThrottledClient(rawClient, delay)
	auth := "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(strings.TrimSpace(opts.Username)+":"+strings.TrimSpace(opts.APIToken)),
	)
	base := strings.TrimRight(opts.BaseURL, "/")
	floor := severityFloor(opts.MinRisk)
	if opts.MinRisk == "" {
		floor = severityFloor("low")
	}

	// Index definitions for quick lookup
	defByID := make(map[string]*entities.Definition, len(ef.Definitions))
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		defByID[d.DefinitionID] = d
	}

	// Filter findings by minimum risk
	var candidates []entities.Finding
	for _, f := range ef.Findings {
		if severityFloor(f.Risk) >= floor {
			candidates = append(candidates, f)
		}
	}

	if len(candidates) == 0 {
		return Summary{}, nil
	}

	if opts.DryRun {
		for _, f := range candidates {
			label := findingLabel(f.FindingID)
			fmt.Printf("[jira] dry-run: would create issue for finding %s (risk=%s url=%s) label=%s\n",
				f.FindingID, f.Risk, f.URL, label)
		}
		return Summary{Created: len(candidates)}, nil
	}

	// Phase 1 (batch parallel): dedup check — find which findings already have issues
	type dedupResult struct {
		idx      int
		exists   bool
		issueKey string
		err      error
	}
	dedupResults := make([]dedupResult, len(candidates))
	{
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i, f := range candidates {
			wg.Add(1)
			go func(i int, f entities.Finding) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				key, err := findExistingIssue(ctx, httpClient, auth, base, f.FindingID)
				dedupResults[i] = dedupResult{idx: i, exists: key != "", issueKey: key, err: err}
			}(i, f)
		}
		wg.Wait()
	}

	// Separate into to-create and skipped
	var toCreate []entities.Finding
	var skipped int
	for i, r := range dedupResults {
		if r.err != nil {
			// dedup check failed: proceed with create (best-effort)
			toCreate = append(toCreate, candidates[i])
			continue
		}
		if r.exists {
			skipped++
		} else {
			toCreate = append(toCreate, candidates[i])
		}
	}

	// Phase 2 (batch parallel): create issues
	type createResult struct {
		err error
	}
	createResults := make([]createResult, len(toCreate))
	{
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i, f := range toCreate {
			wg.Add(1)
			go func(i int, f entities.Finding) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				err := createIssue(ctx, httpClient, auth, base, issueType, f, defByID[f.DefinitionID], opts)
				createResults[i] = createResult{err: err}
			}(i, f)
		}
		wg.Wait()
	}

	var created, errCount int
	for _, r := range createResults {
		if r.err != nil {
			errCount++
		} else {
			created++
		}
	}
	return Summary{Created: created, Skipped: skipped, Errors: errCount}, nil
}

// findExistingIssue searches for an issue with label zap-finding:<findingID>.
// Returns the issue key if found, empty string if not found.
func findExistingIssue(ctx context.Context, client httpDoer, auth, base, findingID string) (string, error) {
	label := findingLabel(findingID)
	jql := fmt.Sprintf(`labels = "%s"`, label)
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("maxResults", "1")
	q.Set("fields", "id,key")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/3/search?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Total  int `json:"total"`
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode search: %w", err)
	}
	if result.Total > 0 && len(result.Issues) > 0 {
		return result.Issues[0].Key, nil
	}
	return "", nil
}

// createIssue POSTs a new Jira issue for the given Finding.
func createIssue(ctx context.Context, client httpDoer, auth, base, issueType string, f entities.Finding, def *entities.Definition, opts Options) error {
	labels := []string{findingLabel(f.FindingID)}
	if def != nil && def.Taxonomy != nil {
		labels = append(labels, def.Taxonomy.OWASPTop10...)
		labels = append(labels, def.Taxonomy.Tags...)
	}
	labels = append(labels, opts.ExtraLabels...)

	fields := map[string]any{
		"project":     map[string]string{"key": opts.ProjectKey},
		"summary":     issueSummary(f),
		"issuetype":   map[string]string{"name": issueType},
		"priority":    map[string]string{"name": riskToPriority(f.Risk)},
		"labels":      labels,
		"description": buildDescription(f, def),
	}
	if strings.TrimSpace(opts.Component) != "" {
		fields["components"] = []map[string]string{{"name": opts.Component}}
	}

	body := map[string]any{"fields": fields}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal issue: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/issue", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return fmt.Errorf("post issue: %w", err)
	}
	resp.Body.Close()
	return nil
}

// issueSummary returns a concise Jira issue summary for a Finding.
func issueSummary(f entities.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = f.FindingID
	}
	// Trim to 255 chars (Jira summary limit)
	if len(name) > 255 {
		name = name[:252] + "..."
	}
	return name
}

// findingLabel returns the dedup label for a finding.
func findingLabel(findingID string) string {
	return "zap-finding:" + findingID
}

// doWithRetry executes a request, retrying on 429 with exponential backoff.
func doWithRetry(client httpDoer, req *http.Request, maxAttempts int) (*http.Response, error) {
	backoff := 2 * time.Second
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 429 && attempt < maxAttempts-1 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs := parseRetryAfter(ra); secs > 0 {
					backoff = time.Duration(secs) * time.Second
				} else {
					backoff = 100 * time.Millisecond
				}
			}
			fmt.Printf("[jira] rate limited, retrying in %s (attempt %d/%d)\n", backoff, attempt+1, maxAttempts)
			select {
			case <-time.After(backoff):
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := jiraHTTPErr(resp)
			resp.Body.Close()
			return nil, err
		}
		return resp, nil
	}
	return nil, fmt.Errorf("jira: max retries exceeded")
}

func parseRetryAfter(val string) int {
	n := 0
	for _, c := range strings.TrimSpace(val) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// jiraHTTPErr reads the response body and returns a descriptive error.
// The body is truncated to 200 chars and stripped of credential-like patterns
// before being included in the error string, which may appear in CI logs.
func jiraHTTPErr(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := sanitizeErrorBody(strings.TrimSpace(string(body)))
	if msg == "" {
		return fmt.Errorf("jira: http %d", resp.StatusCode)
	}
	return fmt.Errorf("jira: http %d: %s", resp.StatusCode, msg)
}

// sanitizeErrorBody truncates an API error response body to 200 chars and
// redacts substrings that look like credentials before the message is logged.
func sanitizeErrorBody(s string) string {
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	for _, pat := range []string{"Authorization", "authorization", "token=", "apikey=", "api_key=", "password="} {
		if idx := strings.Index(s, pat); idx >= 0 {
			s = s[:idx] + "<redacted>…"
			break
		}
	}
	return s
}
