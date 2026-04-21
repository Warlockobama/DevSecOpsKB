package jira

import (
	"bytes"
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

// Options controls Jira issue export.
type Options struct {
	BaseURL      string
	Username     string // email for Jira Cloud
	APIToken     string
	ProjectKey   string
	IssueType    string   // default "Bug"
	Component    string   // optional component name
	ExtraLabels  []string // additional labels beyond zap-finding:<id>
	MinRisk      string   // minimum risk to export: info|low|medium|high (default "medium")
	DryRun       bool
	Concurrency  int           // max parallel requests (default 3, capped at 5)
	Timeout      time.Duration // default 30s
	RequestDelay time.Duration // minimum delay between API requests; default 250ms
	OptInTag     string        // analyst tag that forces Jira export below MinRisk (default "case-ticket")

	// DetectionEpic, when true, creates (or reuses) a parent Epic per Definition
	// and links each finding issue to it via the `parent` field. Epics are
	// dedup'd via the label zap-definition-<definitionID>.
	DetectionEpic bool
	// EpicIssueType overrides the Epic issue type name for projects that use
	// "Initiative" or a custom type. Default "Epic".
	EpicIssueType string
	// EpicComponent is an optional component name applied to detection Epics.
	EpicComponent string
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
	Created    int
	Skipped    int // already existed
	Errors     int
	TicketKeys map[string]string // findingID → Jira issue key (KAN-42)
	// EpicKeys maps definitionID → Epic issue key when DetectionEpic is on.
	// Empty when the feature is disabled or Epic creation failed gracefully.
	EpicKeys map[string]string
	// Relinked counts existing findings whose `parent` field was retroactively
	// set to a newly-created or pre-existing detection Epic. Useful when an
	// older run created findings before -jira-detection-epic was enabled.
	Relinked int
}

// Export creates Jira issues for each Finding at or above opts.MinRisk, or when an analyst opt-in tag is present.
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
	if strings.TrimSpace(opts.MinRisk) == "" {
		floor = severityFloor("medium")
	}
	optInTag := strings.TrimSpace(opts.OptInTag)
	if optInTag == "" {
		optInTag = "case-ticket"
	}

	// Index definitions for quick lookup
	defByID := make(map[string]*entities.Definition, len(ef.Definitions))
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		defByID[d.DefinitionID] = d
	}

	// Pick the most recent occurrence per finding — that becomes the evidence
	// sample rendered into the issue description. Ties fall back to OccurrenceID
	// so the choice is deterministic across runs.
	latestOccByFind := make(map[string]*entities.Occurrence, len(ef.Findings))
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		cur, ok := latestOccByFind[o.FindingID]
		if !ok || occurrenceIsNewer(o, cur) {
			latestOccByFind[o.FindingID] = o
		}
	}

	// Filter findings by minimum risk or explicit analyst opt-in.
	var candidates []entities.Finding
	for _, f := range ef.Findings {
		if severityFloor(f.Risk) >= floor || findingHasOptInTag(f, optInTag) {
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
		if opts.DetectionEpic {
			seen := make(map[string]struct{})
			for _, f := range candidates {
				if _, ok := seen[f.DefinitionID]; ok {
					continue
				}
				seen[f.DefinitionID] = struct{}{}
				def := defByID[f.DefinitionID]
				fmt.Printf("[jira] dry-run: would ensure epic for definition %s (%s) label=%s\n",
					f.DefinitionID, epicSummary(def), definitionLabel(f.DefinitionID))
			}
		}
		return Summary{Created: len(candidates)}, nil
	}

	// Detection Epics (opt-in). Resolve one Epic key per distinct definition
	// among the candidates so findings can be linked via `parent` below.
	// Failures are logged but never block finding creation — fall back to flat.
	epicKeys := make(map[string]string)
	if opts.DetectionEpic {
		// Pre-bucket findings + occurrences by definitionId so the Epic body
		// can show a scan-time evidence rollup (counts, scans, top URLs).
		findingsByDef := make(map[string][]entities.Finding)
		for _, f := range ef.Findings {
			findingsByDef[f.DefinitionID] = append(findingsByDef[f.DefinitionID], f)
		}
		seen := make(map[string]struct{})
		for _, f := range candidates {
			if _, ok := seen[f.DefinitionID]; ok {
				continue
			}
			seen[f.DefinitionID] = struct{}{}
			// Reuse cached Epic key from prior runs (persisted on Definition.EpicRef)
			// before round-tripping Jira.
			if def := defByID[f.DefinitionID]; def != nil && strings.TrimSpace(def.EpicRef) != "" {
				epicKeys[f.DefinitionID] = strings.TrimSpace(def.EpicRef)
				continue
			}
			ev := buildEpicEvidence(findingsByDef[f.DefinitionID], ef.Occurrences)
			key, err := ensureEpicForDefinition(ctx, httpClient, auth, base, defByID[f.DefinitionID], ev, opts)
			if err != nil {
				fmt.Printf("[jira] warning: epic ensure failed for %s: %v (falling back to flat)\n", f.DefinitionID, err)
				continue
			}
			if key == "" {
				fmt.Printf("[jira] warning: project does not accept detection epic for %s — creating flat findings instead\n", f.DefinitionID)
				continue
			}
			epicKeys[f.DefinitionID] = key
		}
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

	ticketKeys := make(map[string]string)

	// Separate into to-create and skipped; record keys for already-existing issues.
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
			ticketKeys[candidates[i].FindingID] = r.issueKey
		} else {
			toCreate = append(toCreate, candidates[i])
		}
	}

	// Phase 1.5 (batch parallel): retroactively link skipped (already-existing)
	// findings to their detection Epic when one is now available. Without this,
	// findings created before -jira-detection-epic was enabled stay orphaned
	// and the Epic shows zero child work items.
	relinked := 0
	if !opts.DryRun {
		type relinkResult struct{ ok bool }
		var (
			relinkSem = make(chan struct{}, concurrency)
			relinkWg  sync.WaitGroup
			relinkMu  sync.Mutex
		)
		for i, r := range dedupResults {
			if r.err != nil || !r.exists || r.issueKey == "" {
				continue
			}
			f := candidates[i]
			epicKey := strings.TrimSpace(epicKeys[f.DefinitionID])
			if epicKey == "" {
				continue
			}
			relinkWg.Add(1)
			go func(issueKey, epic, fid string) {
				defer relinkWg.Done()
				relinkSem <- struct{}{}
				defer func() { <-relinkSem }()
				updated, err := ensureIssueParent(ctx, httpClient, auth, base, issueKey, epic)
				if err != nil {
					fmt.Printf("[jira] warning: could not relink %s to epic %s: %v\n", issueKey, epic, err)
					return
				}
				if updated {
					relinkMu.Lock()
					relinked++
					relinkMu.Unlock()
				}
			}(r.issueKey, epicKey, f.FindingID)
		}
		relinkWg.Wait()
	}

	// Phase 2 (batch parallel): create issues
	type createResult struct {
		findingID string
		issueKey  string
		err       error
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
				key, err := createIssue(ctx, httpClient, auth, base, issueType, f, defByID[f.DefinitionID], latestOccByFind[f.FindingID], epicKeys[f.DefinitionID], opts)
				createResults[i] = createResult{findingID: f.FindingID, issueKey: key, err: err}
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
			if r.issueKey != "" {
				ticketKeys[r.findingID] = r.issueKey
			}
		}
	}
	return Summary{Created: created, Skipped: skipped, Errors: errCount, TicketKeys: ticketKeys, EpicKeys: epicKeys, Relinked: relinked}, nil
}

// ensureIssueParent reads the current `parent` field on issueKey and PUTs an
// update setting it to epicKey when missing or different. Returns updated=true
// only when an actual write happened. Errors from the read step are returned;
// errors from the write step are returned with the read result lost.
func ensureIssueParent(ctx context.Context, client httpDoer, auth, base, issueKey, epicKey string) (bool, error) {
	issueKey = strings.TrimSpace(issueKey)
	epicKey = strings.TrimSpace(epicKey)
	if issueKey == "" || epicKey == "" {
		return false, nil
	}

	// 1. Read current parent.
	getURL := base + "/rest/api/3/issue/" + issueKey + "?fields=parent"
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return false, err
	}
	getReq.Header.Set("Authorization", auth)
	getReq.Header.Set("Accept", "application/json")
	getResp, err := doWithRetry(client, getReq, 3)
	if err != nil {
		return false, fmt.Errorf("get parent: %w", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if getResp.StatusCode != http.StatusOK {
		return false, jiraHTTPErr(getResp)
	}
	raw, err := io.ReadAll(io.LimitReader(getResp.Body, 64*1024))
	if err != nil {
		return false, fmt.Errorf("read parent response: %w", err)
	}
	var read struct {
		Fields struct {
			Parent *struct {
				Key string `json:"key"`
			} `json:"parent"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &read); err != nil {
		return false, fmt.Errorf("decode parent response: %w", err)
	}
	if read.Fields.Parent != nil && strings.EqualFold(strings.TrimSpace(read.Fields.Parent.Key), epicKey) {
		return false, nil // already linked
	}

	// 2. PUT the parent update.
	putBody := map[string]any{
		"fields": map[string]any{
			"parent": map[string]string{"key": epicKey},
		},
	}
	data, err := json.Marshal(putBody)
	if err != nil {
		return false, err
	}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/rest/api/3/issue/"+issueKey, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	putReq.Header.Set("Authorization", auth)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := doWithRetry(client, putReq, 3)
	if err != nil {
		return false, fmt.Errorf("put parent: %w", err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent && putResp.StatusCode != http.StatusOK {
		return false, jiraHTTPErr(putResp)
	}
	return true, nil
}

// occurrenceIsNewer reports whether a should replace b as the "latest"
// occurrence for a finding. Compares ObservedAt as RFC3339 when both parse,
// otherwise falls back to string ordering; ties break on OccurrenceID so the
// choice is deterministic across runs.
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

func findingHasOptInTag(f entities.Finding, tag string) bool {
	if f.Analyst == nil {
		return false
	}
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return false
	}
	for _, candidate := range f.Analyst.Tags {
		if strings.ToLower(strings.TrimSpace(candidate)) == tag {
			return true
		}
	}
	return false
}

// findExistingIssue searches for an issue with either the current or legacy
// dedup label for a finding. This keeps exports backward-compatible across
// label scheme changes and avoids duplicate issues for already-exported findings.
// Returns the issue key if found, empty string if not found.
// Uses POST /rest/api/3/search/jql (Jira Cloud v3 current endpoint).
func findExistingIssue(ctx context.Context, client httpDoer, auth, base, findingID string) (string, error) {
	labels := []string{findingLabel(findingID), legacyFindingLabel(findingID)}
	var quoted []string
	for _, label := range labels {
		quoted = append(quoted, fmt.Sprintf(`"%s"`, label))
	}
	jql := fmt.Sprintf("labels in (%s)", strings.Join(quoted, ", "))

	body := map[string]any{
		"jql":        jql,
		"maxResults": 1,
		"fields":     []string{"id", "key"},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal search: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/search/jql", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode search: %w", err)
	}
	if len(result.Issues) > 0 {
		return result.Issues[0].Key, nil
	}
	return "", nil
}

// createIssue POSTs a new Jira issue for the given Finding.
// Returns the new issue key (e.g. "KAN-42") and any error.
func createIssue(ctx context.Context, client httpDoer, auth, base, issueType string, f entities.Finding, def *entities.Definition, occ *entities.Occurrence, epicKey string, opts Options) (string, error) {
	labels := []string{findingLabel(f.FindingID)}
	if def != nil && def.Taxonomy != nil {
		for _, l := range def.Taxonomy.OWASPTop10 {
			labels = append(labels, sanitizeLabel(l))
		}
		for _, l := range def.Taxonomy.Tags {
			labels = append(labels, sanitizeLabel(l))
		}
	}
	for _, l := range opts.ExtraLabels {
		labels = append(labels, sanitizeLabel(l))
	}

	fields := map[string]any{
		"project":     map[string]string{"key": opts.ProjectKey},
		"summary":     issueSummary(f),
		"issuetype":   map[string]string{"name": issueType},
		"priority":    map[string]string{"name": riskToPriority(f.Risk)},
		"labels":      labels,
		"description": buildDescription(f, def, occ),
	}
	if strings.TrimSpace(opts.Component) != "" {
		fields["components"] = []map[string]string{{"name": opts.Component}}
	}
	if ek := strings.TrimSpace(epicKey); ek != "" {
		// Next-gen / team-managed Jira Cloud projects link Epics via `parent`.
		// Classic projects use customfield_10014; that variant can be added later
		// if users hit compatibility issues.
		fields["parent"] = map[string]string{"key": ek}
	}

	body := map[string]any{"fields": fields}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal issue: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/issue", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", fmt.Errorf("post issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", jiraHTTPErr(resp)
	}

	var created struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	return created.Key, nil
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
// Uses hyphen separator — Jira labels cannot contain colons.
func findingLabel(findingID string) string {
	return "zap-finding-" + findingID
}

// legacyFindingLabel returns the pre-migration dedup label used by older
// exporter versions. Jira lookup still searches for it to avoid duplicates.
func legacyFindingLabel(findingID string) string {
	return "zap-finding:" + findingID
}

// sanitizeLabel makes s safe for use as a Jira label:
//   - Replaces spaces, colons, slashes, and backslashes with hyphens.
//   - Strips ASCII control characters (< 0x20) and DEL (0x7F).
//   - Truncates to 255 bytes (Jira Cloud label length limit), avoiding split of multi-byte runes.
func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7F: // control chars / DEL — strip
			continue
		case r == ' ' || r == ':' || r == '/' || r == '\\':
			b.WriteRune('-')
		default:
			b.WriteRune(r)
		}
	}
	result := b.String()
	// Truncate to 255 bytes without splitting a multi-byte rune.
	if len(result) > 255 {
		result = result[:255]
		for len(result) > 0 && result[len(result)-1]&0xC0 == 0x80 {
			result = result[:len(result)-1]
		}
	}
	return result
}

// doWithRetry executes a request, retrying on 429 with exponential backoff.
// bodyData must be the raw request body bytes so each retry can construct a
// fresh reader — http.Request bodies are consumed after the first Do() call
// and cannot be replayed without this.
func doWithRetry(client httpDoer, req *http.Request, maxAttempts int) (*http.Response, error) {
	// Snapshot the body bytes once so we can replay on 429 retries.
	var bodyData []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyData, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("jira: read request body: %w", err)
		}
		req.Body.Close()
	}

	backoff := 2 * time.Second
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Attach a fresh body reader for each attempt.
		if bodyData != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyData))
			req.ContentLength = int64(len(bodyData))
		}

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
				}
				// On unparseable Retry-After keep existing backoff (don't reset to 100ms).
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
	// Apply all redactions (not just first match) so multiple credential patterns
	// in the same response body are all scrubbed.
	for _, pat := range []string{"Authorization", "authorization", "token=", "apikey=", "api_key=", "password="} {
		if idx := strings.Index(s, pat); idx >= 0 {
			s = s[:idx] + "<redacted>…"
		}
	}
	return s
}
