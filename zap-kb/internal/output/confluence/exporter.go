package confluence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options controls Confluence export of a single markdown page (e.g., INDEX.md).
// This is a minimal helper aimed at pushing the KB index into Confluence Server/DC
// via the REST API using a markdown macro wrapper.
type Options struct {
	BaseURL      string
	Username     string
	APIToken     string
	SpaceKey     string
	ParentPageID string
	TitlePrefix  string
	MarkdownPage string // markdown file to upload; default = INDEX.md
	DryRun       bool
	Timeout      time.Duration
}

// VaultOptions controls full-vault export to Confluence.
type VaultOptions struct {
	BaseURL      string
	Username     string
	APIToken     string
	SpaceKey     string
	DryRun       bool
	Concurrency  int           // default 3, capped at 5
	Timeout      time.Duration // per-request timeout; default 30s
	RequestDelay time.Duration // minimum delay between API requests; default 250ms
}

// VaultSummary reports what the vault export did.
type VaultSummary struct {
	Created int
	Updated int
	Skipped int
	Errors  int
}

// Export uploads the specified markdown page (default INDEX.md in vault root) to Confluence.
// Content is wrapped in a markdown macro so existing markdown renders without conversion.
// If a page with the same title already exists in the space, it is updated (upsert).
func Export(ctx context.Context, vaultRoot string, opts Options) error {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.SpaceKey) == "" || strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.APIToken) == "" {
		return fmt.Errorf("confluence export: missing required fields (base URL, space key, username, api token)")
	}

	page := strings.TrimSpace(opts.MarkdownPage)
	if page == "" {
		page = "INDEX.md"
	}
	mdPath := filepath.Join(vaultRoot, page)
	bodyBytes, err := os.ReadFile(mdPath)
	if err != nil {
		return fmt.Errorf("read markdown: %w", err)
	}
	title := strings.TrimSpace(opts.TitlePrefix + " " + strings.TrimSuffix(page, filepath.Ext(page)))
	title = strings.TrimSpace(title)
	if title == "" {
		title = "KB Index"
	}

	// Wrap markdown in Confluence markdown macro
	markdown := string(bodyBytes)
	macro := mdToStorage(markdown)

	if opts.DryRun {
		fmt.Printf("[confluence] dry-run: would upsert %d bytes to %s (title=%q space=%q parent=%q)\n", len(bodyBytes), opts.BaseURL, title, opts.SpaceKey, strings.TrimSpace(opts.ParentPageID))
		return nil
	}

	httpClient := &http.Client{Timeout: opts.Timeout}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}
	auth := basicAuth(opts.Username, opts.APIToken)
	base := strings.TrimRight(opts.BaseURL, "/")

	_, _, err = upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, title, macro, "")
	return err
}

// ExportVault pushes the full obsidian vault to Confluence as a page tree:
//
//	KB Root (INDEX.md)
//	├── DASHBOARD
//	├── Triage Board
//	├── By Domain
//	└── Definitions/
//	    ├── 100002-server-is-running-...
//	    ├── 100003-cookie-set-without-...
//	    └── ...
//
// All pages use the markdown macro so markdown renders natively.
// Definitions are upserted in parallel (bounded by Concurrency).
func ExportVault(ctx context.Context, vaultRoot string, opts VaultOptions) (VaultSummary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.SpaceKey) == "" ||
		strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.APIToken) == "" {
		return VaultSummary{}, fmt.Errorf("confluence vault export: missing required fields (base URL, space key, username, api token)")
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	delay := opts.RequestDelay
	if delay == 0 {
		delay = 250 * time.Millisecond
	}

	auth := basicAuth(opts.Username, opts.APIToken)
	base := strings.TrimRight(opts.BaseURL, "/")
	httpClient := newThrottledClient(&http.Client{Timeout: timeout}, delay)

	var summary VaultSummary

	// Phase 1: Upsert the root page (INDEX.md)
	rootContent, err := readMarkdownFile(filepath.Join(vaultRoot, "INDEX.md"))
	if err != nil {
		return summary, fmt.Errorf("read INDEX.md: %w", err)
	}

	if opts.DryRun {
		return dryRunVault(vaultRoot)
	}

rootID, rootAction, err := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, "KB Index", mdToStorage(rootContent), "")
	if err != nil {
		return summary, fmt.Errorf("upsert INDEX: %w", err)
	}
	countAction(&summary, rootAction)

	// Phase 2: Upsert top-level pages as children of root
	topPages := []struct {
		file  string
		title string
	}{
		{"DASHBOARD.md", "KB Dashboard"},
		{"triage-board.md", "Triage Board"},
		{"by-domain.md", "By Domain"},
		{"latest-scan.md", "Latest Scan"},
	}

	for _, tp := range topPages {
		content, ferr := readMarkdownFile(filepath.Join(vaultRoot, tp.file))
		if ferr != nil {
			continue // skip missing files
		}
		_, action, uerr := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, tp.title, mdToStorage(content), rootID)
		if uerr != nil {
			fmt.Printf("[confluence] error upserting %s: %v\n", tp.title, uerr)
			summary.Errors++
			continue
		}
		countAction(&summary, action)
	}

	// Phase 3: Upsert "Definitions" parent page
defsID, defsAction, err := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, "Definitions",
		mdToStorage("# Definitions\n\nAuto-generated ZAP plugin definitions from the DevSecOps KB."), rootID)
	if err != nil {
		return summary, fmt.Errorf("upsert Definitions parent: %w", err)
	}
	countAction(&summary, defsAction)

	// Phase 4: Parallel upsert of definition pages
	defsDir := filepath.Join(vaultRoot, "definitions")
	entries, err := os.ReadDir(defsDir)
	if err != nil {
		// No definitions dir is not fatal
		return summary, nil
	}

	var mdFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			mdFiles = append(mdFiles, e.Name())
		}
	}

	type result struct {
		action string
		err    error
	}
	results := make([]result, len(mdFiles))

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, fname := range mdFiles {
		wg.Add(1)
		go func(i int, fname string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, ferr := readMarkdownFile(filepath.Join(defsDir, fname))
			if ferr != nil {
				results[i] = result{err: ferr}
				return
			}
			title := defTitleFromContent(content)
			if title == "" {
				title = defTitleFromFilename(fname)
			}
			_, action, uerr := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, title, mdToStorage(content), defsID)
			results[i] = result{action: action, err: uerr}
		}(i, fname)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			fmt.Printf("[confluence] error upserting definition %s: %v\n", mdFiles[i], r.err)
			summary.Errors++
		} else {
			countAction(&summary, r.action)
		}
	}

	// Phase 5: Upsert Findings parent + all finding pages
	upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "findings", "Findings", rootID, concurrency, &summary)

	// Phase 6: Upsert Occurrences parent + all occurrence pages
	upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "occurrences", "Occurrences", rootID, concurrency, &summary)

	return summary, nil
}

// upsertDir upserts all .md files in a vault subdirectory as child pages
// under a named parent page (itself a child of parentID).
func upsertDir(ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot, subdir, parentTitle, grandParentID string, concurrency int, summary *VaultSummary) {
	dir := filepath.Join(vaultRoot, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // subdir missing is not fatal
	}

	var mdFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			mdFiles = append(mdFiles, e.Name())
		}
	}
	if len(mdFiles) == 0 {
		return
	}

	// Upsert parent page
	parentContent := "# " + parentTitle + "\n\nGenerated by DevSecOps KB."
	parentID, action, err := upsertPage(ctx, client, auth, base, spaceKey, parentTitle, mdToStorage(parentContent), grandParentID)
	if err != nil {
		fmt.Printf("[confluence] error upserting %s parent: %v\n", parentTitle, err)
		summary.Errors++
		return
	}
	countAction(summary, action)

	// Parallel upsert of child pages
	type result struct {
		action string
		err    error
	}
	results := make([]result, len(mdFiles))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, fname := range mdFiles {
		wg.Add(1)
		go func(i int, fname string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, ferr := readMarkdownFile(filepath.Join(dir, fname))
			if ferr != nil {
				results[i] = result{err: ferr}
				return
			}
			title := defTitleFromContent(content)
			if title == "" {
				title = defTitleFromFilename(fname)
			}
			_, act, uerr := upsertPage(ctx, client, auth, base, spaceKey, title, mdToStorage(content), parentID)
			results[i] = result{action: act, err: uerr}
		}(i, fname)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			fmt.Printf("[confluence] error upserting %s/%s: %v\n", subdir, mdFiles[i], r.err)
			summary.Errors++
		} else {
			countAction(summary, r.action)
		}
	}
}

// --- helpers ---

// httpDoer abstracts HTTP request execution for throttling and testing.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// throttledClient wraps an http.Client with a minimum delay between requests
// to avoid overwhelming the server. Safe for concurrent use.
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


func basicAuth(user, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(strings.TrimSpace(user)+":"+strings.TrimSpace(token)))
}

// readMarkdownFile reads and returns the content of a markdown file, stripping YAML frontmatter.
func readMarkdownFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return stripFrontmatter(string(data)), nil
}

// stripFrontmatter removes YAML frontmatter delimited by "---\n" from markdown content.
// Requires the opening delimiter to be exactly "---\n" at position 0, and the closing
// delimiter to be "\n---\n" (not just "\n---" which could match horizontal rules).
func stripFrontmatter(s string) string {
	if !strings.HasPrefix(s, "---\n") && !strings.HasPrefix(s, "---\r\n") {
		return s
	}
	// Find closing delimiter: must be \n---\n (full line boundary)
	closeMarkers := []string{"\n---\n", "\n---\r\n"}
	for _, marker := range closeMarkers {
		idx := strings.Index(s[3:], marker)
		if idx >= 0 {
			return strings.TrimLeft(s[3+idx+len(marker):], "\r\n")
		}
	}
	return s
}

// defTitleFromContent extracts the H1 heading from markdown content.
// Returns empty string if no H1 found.
func defTitleFromContent(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(line[2:])
		}
	}
	return ""
}

// defTitleFromFilename is the filename-based fallback for defTitle.
func defTitleFromFilename(filename string) string {
	name := strings.TrimSuffix(filename, ".md")
	parts := strings.SplitN(name, "-", 2)
	if len(parts) < 2 {
		return name
	}
	words := strings.Split(parts[1], "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.TrimSpace(parts[0] + " " + strings.Join(words, " "))
}

// upsertPage creates or updates a Confluence page. Returns (pageID, action, error).
// action is "created", "updated", or "skipped".
func upsertPage(ctx context.Context, client httpDoer, auth, base, spaceKey, title, storageBody, parentID string) (string, string, error) {
	existingID, existingVersion, err := findPage(ctx, client, auth, base, spaceKey, title)
	if err != nil {
		return "", "", fmt.Errorf("find page %q: %w", title, err)
	}

	body := map[string]any{
		"type":  "page",
		"title": title,
		"space": map[string]string{"key": spaceKey},
		"body": map[string]any{
			"storage": map[string]string{
				"value":          storageBody,
				"representation": "storage",
			},
		},
	}

	if existingID != "" {
		// Update
		body["id"] = existingID
		body["version"] = map[string]int{"number": existingVersion + 1}
		if parentID != "" {
			body["ancestors"] = []map[string]string{{"id": parentID}}
		}
		data, err := json.Marshal(body)
		if err != nil {
			return "", "", fmt.Errorf("marshal update: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/rest/api/content/"+existingID, bytes.NewReader(data))
		if err != nil {
			return "", "", fmt.Errorf("build update request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		if err := doRequest(client, req); err != nil {
			return "", "", err
		}
		return existingID, "updated", nil
	}

	// Create
	if parentID != "" {
		body["ancestors"] = []map[string]string{{"id": parentID}}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("marshal create: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/content", bytes.NewReader(data))
	if err != nil {
		return "", "", fmt.Errorf("build create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", "", fmt.Errorf("decode create response: %w", err)
	}
	return created.ID, "created", nil
}

func countAction(s *VaultSummary, action string) {
	switch action {
	case "created":
		s.Created++
	case "updated":
		s.Updated++
	case "skipped":
		s.Skipped++
	}
}

func dryRunVault(vaultRoot string) (VaultSummary, error) {
	var count int
	for _, f := range []string{"INDEX.md", "DASHBOARD.md", "triage-board.md", "by-domain.md", "latest-scan.md"} {
		if _, err := os.Stat(filepath.Join(vaultRoot, f)); err == nil {
			count++
		}
	}
	// Parent pages for each subdir
	for _, subdir := range []string{"definitions", "findings", "occurrences"} {
		dir := filepath.Join(vaultRoot, subdir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		count++ // parent page
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				count++
			}
		}
	}
	fmt.Printf("[confluence] dry-run: would upsert %d pages\n", count)
	return VaultSummary{Skipped: count}, nil
}

// findPage searches for an existing page by title and space key.
// Returns (pageID, versionNumber, error). pageID is empty if not found.
func findPage(ctx context.Context, client httpDoer, auth, base, spaceKey, title string) (string, int, error) {
	q := url.Values{}
	q.Set("title", title)
	q.Set("spaceKey", spaceKey)
	q.Set("expand", "version")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/content?"+q.Encode(), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", auth)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			ID      string `json:"id"`
			Version struct {
				Number int `json:"number"`
			} `json:"version"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("decode search response: %w", err)
	}
	if len(result.Results) == 0 {
		return "", 0, nil
	}
	r := result.Results[0]
	return r.ID, r.Version.Number, nil
}

// doRequest executes req with retry on 429 (rate limit). Up to 3 attempts with exponential backoff.
func doRequest(client httpDoer, req *http.Request) error {
	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// doWithRetry executes a request, retrying on 429 with exponential backoff.
// Returns the successful response (caller must close body).
func doWithRetry(client httpDoer, req *http.Request, maxAttempts int) (*http.Response, error) {
	backoff := 2 * time.Second
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("http: %w", err)
		}
		if resp.StatusCode == 429 && attempt < maxAttempts-1 {
			// Read and discard body so connection can be reused
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// Respect Retry-After header if present
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := parseRetryAfter(ra); err == nil {
					if secs <= 0 {
						backoff = 100 * time.Millisecond
					} else {
						backoff = time.Duration(secs) * time.Second
					}
				}
			}
			fmt.Printf("[confluence] rate limited, retrying in %s (attempt %d/%d)\n", backoff, attempt+1, maxAttempts)
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
			err := httpErr(resp)
			resp.Body.Close()
			return nil, err
		}
		return resp, nil
	}
	return nil, fmt.Errorf("confluence: max retries exceeded")
}

// parseRetryAfter parses the Retry-After header value as seconds.
func parseRetryAfter(val string) (int, error) {
	val = strings.TrimSpace(val)
	n := 0
	for _, c := range val {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-numeric")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// httpErr reads the response body and returns a descriptive error.
func httpErr(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("confluence: http %d", resp.StatusCode)
	}
	return fmt.Errorf("confluence: http %d: %s", resp.StatusCode, msg)
}
