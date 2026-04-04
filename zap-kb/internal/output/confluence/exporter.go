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

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
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
	Concurrency  int                    // default 3, capped at 5
	Timeout      time.Duration          // per-request timeout; default 30s
	RequestDelay time.Duration          // minimum delay between API requests; default 250ms
	Entities     *entities.EntitiesFile // optional; enables structured metadata (labels, properties, risk lozenges)
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

// ExportVault pushes the full obsidian vault to Confluence as a page tree.
// When an EntitiesFile is provided, findings and occurrences are nested under
// their parent definition pages:
//
//	KB Root (INDEX.md)
//	├── KB Dashboard
//	├── Triage Board
//	├── By Domain
//	└── Definitions/
//	    ├── CSP Header Not Set (Plugin 10038)
//	    │   └── [Finding] CSP Header Not Set — /api — abc1
//	    │       ├── [Occurrence] CSP Header Not Set — /api/1 — xyz1
//	    │       └── [Occurrence] CSP Header Not Set — /api/2 — xyz2
//	    └── ...
//
// Without an EntitiesFile, findings and occurrences are exported flat under
// top-level "Findings" and "Occurrences" parent pages.
// All pages are upserted in parallel (bounded by Concurrency).
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

	// Build entity indexes for structured enrichment
	ei := buildEntityIndex(opts.Entities)

	// Build title map: vault-relative path → actual Confluence page title
	titleMap := buildTitleMap(vaultRoot)

	var summary VaultSummary

	// Phase 1: Upsert the root page (INDEX.md)
	rootContent, err := readMarkdownFile(filepath.Join(vaultRoot, "INDEX.md"))
	if err != nil {
		return summary, fmt.Errorf("read INDEX.md: %w", err)
	}

	if opts.DryRun {
		return dryRunVault(vaultRoot)
	}

	rootID, rootAction, err := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, "KB Index", mdToStorageWithTitles(rootContent, titleMap), "")
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
		_, action, uerr := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, tp.title, mdToStorageWithTitles(content, titleMap), rootID)
		if uerr != nil {
			fmt.Printf("[confluence] error upserting %s: %v\n", tp.title, uerr)
			summary.Errors++
			continue
		}
		countAction(&summary, action)
	}

	// Phase 2b: Upsert scan-level posture summary page (requires EntitiesFile)
	if opts.Entities != nil {
		_, postureAction, postureErr := upsertPostureSummary(ctx, httpClient, auth, base, opts.SpaceKey, rootID, opts.Entities)
		if postureErr != nil {
			fmt.Printf("[confluence] error upserting posture summary: %v\n", postureErr)
			summary.Errors++
		} else {
			countAction(&summary, postureAction)
		}
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

	// Phase 4 result captures the Confluence pageID per definition so Phases 5+6 can
	// nest findings and occurrences under the correct parent.
	type defResult struct {
		action string
		err    error
		pageID string
		defID  string
	}
	defResults := make([]defResult, len(mdFiles))

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
				defResults[i] = defResult{err: ferr}
				return
			}
			title := defTitleFromContent(content)
			if title == "" {
				title = defTitleFromFilename(fname)
			}

			// Enrich with entity metadata
			def := ei.defByFilename(fname)
			storageBody := mdToStorageWithTitles(content, titleMap)
			storageBody = prependDefProperties(storageBody, def)

			pageID, action, uerr := upsertPage(ctx, httpClient, auth, base, opts.SpaceKey, title, storageBody, defsID)
			if uerr == nil && def != nil {
				applyLabels(ctx, httpClient, auth, base, pageID, defLabels(def))
			}
			did := ""
			if def != nil {
				did = def.DefinitionID
			}
			defResults[i] = defResult{action: action, err: uerr, pageID: pageID, defID: did}
		}(i, fname)
	}
	wg.Wait()

	// Build definitionID → pageID map for hierarchical nesting
	defPageIDs := make(map[string]string)
	for i, r := range defResults {
		if r.err != nil {
			fmt.Printf("[confluence] error upserting definition %s: %v\n", mdFiles[i], r.err)
			summary.Errors++
		} else {
			countAction(&summary, r.action)
			if r.defID != "" && r.pageID != "" {
				defPageIDs[r.defID] = r.pageID
			}
		}
	}

	// Phase 5+6: Hierarchical export when entity data is available.
	// Findings nest under their definition pages; occurrences nest under their finding pages.
	// Falls back to flat export when entity data is absent.
	if opts.Entities != nil {
		findingPageIDs := upsertFindingsHierarchical(ctx, httpClient, auth, base, opts.SpaceKey,
			vaultRoot, concurrency, &ei, titleMap, defPageIDs, defsID, &summary)
		upsertOccurrencesHierarchical(ctx, httpClient, auth, base, opts.SpaceKey,
			vaultRoot, concurrency, &ei, titleMap, findingPageIDs, defsID, &summary)
	} else {
		upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "findings", "Findings", rootID, concurrency, &ei, titleMap, &summary)
		upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "occurrences", "Occurrences", rootID, concurrency, &ei, titleMap, &summary)
	}

	return summary, nil
}

// upsertFindingsHierarchical upserts finding pages as children of their definition pages.
// Returns a map of findingID → Confluence pageID for use by upsertOccurrencesHierarchical.
// Findings whose definition page ID is not in defPageIDs are parented to fallbackParentID.
func upsertFindingsHierarchical(
	ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot string,
	concurrency int, ei *entityIndex, titleMap map[string]string,
	defPageIDs map[string]string, fallbackParentID string,
	summary *VaultSummary,
) map[string]string {
	dir := filepath.Join(vaultRoot, "findings")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var mdFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			mdFiles = append(mdFiles, e.Name())
		}
	}
	if len(mdFiles) == 0 {
		return nil
	}

	type result struct {
		action    string
		err       error
		pageID    string
		findingID string
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

			f := ei.findingByFilename(fname)
			content = stripFindingBodyForConfluence(content)

			title := findingPageTitle(f, ei)
			if title == "" {
				title = defTitleFromContent(content)
			}
			if title == "" {
				title = defTitleFromFilename(fname)
			}

			// Parent: definition page if known, else fallback
			parentID := fallbackParentID
			if f != nil {
				if id, ok := defPageIDs[f.DefinitionID]; ok && id != "" {
					parentID = id
				}
			}

			storageBody := mdToStorageWithTitles(content, titleMap)
			storageBody = prependFindingProperties(storageBody, f, ei)
			labels := findingLabels(f)

			pageID, act, uerr := upsertPage(ctx, client, auth, base, spaceKey, title, storageBody, parentID)
			if uerr == nil && len(labels) > 0 {
				applyLabels(ctx, client, auth, base, pageID, labels)
			}
			fid := ""
			if f != nil {
				fid = f.FindingID
			}
			results[i] = result{action: act, err: uerr, pageID: pageID, findingID: fid}
		}(i, fname)
	}
	wg.Wait()

	findingPageIDs := make(map[string]string)
	for i, r := range results {
		if r.err != nil {
			fmt.Printf("[confluence] error upserting finding %s: %v\n", mdFiles[i], r.err)
			summary.Errors++
		} else {
			countAction(summary, r.action)
			if r.findingID != "" && r.pageID != "" {
				findingPageIDs[r.findingID] = r.pageID
			}
		}
	}
	return findingPageIDs
}

// upsertOccurrencesHierarchical upserts occurrence pages as children of their finding pages.
// Occurrences whose finding page ID is not in findingPageIDs are parented to fallbackParentID.
func upsertOccurrencesHierarchical(
	ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot string,
	concurrency int, ei *entityIndex, titleMap map[string]string,
	findingPageIDs map[string]string, fallbackParentID string,
	summary *VaultSummary,
) {
	dir := filepath.Join(vaultRoot, "occurrences")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
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

			o := ei.occurrenceByFilename(fname)
			content = stripOccurrenceBodyForConfluence(content)

			title := occurrencePageTitle(o, ei)
			if title == "" {
				title = defTitleFromContent(content)
			}
			if title == "" {
				title = defTitleFromFilename(fname)
			}

			// Parent: finding page if known, else fallback
			parentID := fallbackParentID
			if o != nil {
				if id, ok := findingPageIDs[o.FindingID]; ok && id != "" {
					parentID = id
				}
			}

			storageBody := mdToStorageWithTitles(content, titleMap)
			storageBody = prependOccurrenceProperties(storageBody, o, ei)
			labels := occurrenceLabels(o)

			pageID, act, uerr := upsertPage(ctx, client, auth, base, spaceKey, title, storageBody, parentID)
			if uerr == nil && len(labels) > 0 {
				applyLabels(ctx, client, auth, base, pageID, labels)
			}
			results[i] = result{action: act, err: uerr}
		}(i, fname)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			fmt.Printf("[confluence] error upserting occurrence %s: %v\n", mdFiles[i], r.err)
			summary.Errors++
		} else {
			countAction(summary, r.action)
		}
	}
}

// upsertDir upserts all .md files in a vault subdirectory as child pages
// under a named parent page (itself a child of parentID).
func upsertDir(ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot, subdir, parentTitle, grandParentID string, concurrency int, ei *entityIndex, titleMap map[string]string, summary *VaultSummary) {
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

			// Fetch entity data early (needed for title and body stripping)
			var findingEnt *entities.Finding
			var occEnt *entities.Occurrence
			switch subdir {
			case "findings":
				findingEnt = ei.findingByFilename(fname)
				content = stripFindingBodyForConfluence(content)
			case "occurrences":
				occEnt = ei.occurrenceByFilename(fname)
				content = stripOccurrenceBodyForConfluence(content)
			}

			// Determine page title: use entity data for findings/occurrences, H1 for definitions
			var title string
			switch subdir {
			case "findings":
				title = findingPageTitle(findingEnt, ei)
			case "occurrences":
				title = occurrencePageTitle(occEnt, ei)
			}
			if title == "" {
				title = defTitleFromContent(content)
			}
			if title == "" {
				title = defTitleFromFilename(fname)
			}

			storageBody := mdToStorageWithTitles(content, titleMap)

			// Enrich based on entity type
			var labels []string
			switch subdir {
			case "findings":
				storageBody = prependFindingProperties(storageBody, findingEnt, ei)
				labels = findingLabels(findingEnt)
			case "occurrences":
				storageBody = prependOccurrenceProperties(storageBody, occEnt, ei)
				labels = occurrenceLabels(occEnt)
			}

			pageID, act, uerr := upsertPage(ctx, client, auth, base, spaceKey, title, storageBody, parentID)
			if uerr == nil && len(labels) > 0 {
				applyLabels(ctx, client, auth, base, pageID, labels)
			}
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

// sanitizeErrorBody truncates an API error response body to 200 chars and
// redacts substrings that look like credentials (Authorization headers,
// token/key query params) before the message is printed to stdout/logs.
func sanitizeErrorBody(s string) string {
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	// Redact patterns like: "Authorization: Bearer xxx", "token=xxx", "apikey=xxx"
	for _, pat := range []string{"Authorization", "authorization", "token=", "apikey=", "api_key=", "password="} {
		if idx := strings.Index(s, pat); idx >= 0 {
			s = s[:idx] + "<redacted>" + "…"
			break
		}
	}
	return s
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
// The body is truncated to 200 chars and stripped of any credential-like patterns
// before being included in the error string, which may appear in CI logs.
func httpErr(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := sanitizeErrorBody(strings.TrimSpace(string(body)))
	if msg == "" {
		return fmt.Errorf("confluence: http %d", resp.StatusCode)
	}
	return fmt.Errorf("confluence: http %d: %s", resp.StatusCode, msg)
}

// --- Title map for wikilink resolution ---

// buildTitleMap scans all .md files in the vault and builds a map from
// vault-relative paths to their Confluence page titles (derived from H1 headings).
// This enables wikilinks like [[definitions/10038-csp.md|CSP]] to resolve to
// the actual page title "Content Security Policy (CSP) Header Not Set (Plugin 10038)".
func buildTitleMap(vaultRoot string) map[string]string {
	tm := make(map[string]string)
	for _, subdir := range []string{"", "definitions", "findings", "occurrences"} {
		dir := vaultRoot
		if subdir != "" {
			dir = filepath.Join(vaultRoot, subdir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			content := stripFrontmatter(string(data))
			title := defTitleFromContent(content)
			if title == "" {
				title = defTitleFromFilename(e.Name())
			}
			// Map the vault-relative path to the page title
			if subdir != "" {
				tm[subdir+"/"+e.Name()] = title
			}
			tm[e.Name()] = title
		}
	}
	return tm
}

// --- Entity index and structured enrichment ---

// obsRange holds the first and last observed timestamps for a finding's occurrences.
type obsRange struct {
	First string
	Last  string
}

// entityIndex provides fast lookup from filenames to entity structs.
type entityIndex struct {
	defs       map[string]*entities.Definition // pluginID → definition
	finds      map[string]*entities.Finding    // findingID → finding
	occs       map[string]*entities.Occurrence // occurrenceID → occurrence
	findingObs map[string]obsRange             // findingID → {first, last} ObservedAt
}

func buildEntityIndex(ef *entities.EntitiesFile) entityIndex {
	ei := entityIndex{
		defs:       make(map[string]*entities.Definition),
		finds:      make(map[string]*entities.Finding),
		occs:       make(map[string]*entities.Occurrence),
		findingObs: make(map[string]obsRange),
	}
	if ef == nil {
		return ei
	}
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		ei.defs[d.DefinitionID] = d
		ei.defs[d.PluginID] = d // also index by pluginID for filename matching
	}
	for i := range ef.Findings {
		f := &ef.Findings[i]
		ei.finds[f.FindingID] = f
	}
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		ei.occs[o.OccurrenceID] = o
		// Accumulate first/last ObservedAt per finding
		if o.FindingID != "" && o.ObservedAt != "" {
			ts, err := time.Parse(time.RFC3339, strings.TrimSpace(o.ObservedAt))
			if err == nil {
				cur := ei.findingObs[o.FindingID]
				if cur.First == "" {
					cur.First = o.ObservedAt
					cur.Last = o.ObservedAt
				} else {
					firstTs, _ := time.Parse(time.RFC3339, cur.First)
					lastTs, _ := time.Parse(time.RFC3339, cur.Last)
					if ts.Before(firstTs) {
						cur.First = o.ObservedAt
					}
					if ts.After(lastTs) {
						cur.Last = o.ObservedAt
					}
				}
				ei.findingObs[o.FindingID] = cur
			}
		}
	}
	return ei
}

// defByFilename resolves a definition filename like "10038-csp-header.md" to its entity.
func (ei *entityIndex) defByFilename(fname string) *entities.Definition {
	base := strings.TrimSuffix(fname, ".md")
	// Extract pluginID (digits before first dash)
	parts := strings.SplitN(base, "-", 2)
	if len(parts) > 0 {
		if d, ok := ei.defs["def-"+parts[0]]; ok {
			return d
		}
		if d, ok := ei.defs[parts[0]]; ok {
			return d
		}
	}
	return nil
}

// findingByFilename resolves "fin-1234abcd.md" to its entity.
func (ei *entityIndex) findingByFilename(fname string) *entities.Finding {
	id := strings.TrimSuffix(fname, ".md")
	if f, ok := ei.finds[id]; ok {
		return f
	}
	return nil
}

// occurrenceByFilename resolves "occ-1234abcd.md" to its entity.
func (ei *entityIndex) occurrenceByFilename(fname string) *entities.Occurrence {
	id := strings.TrimSuffix(fname, ".md")
	if o, ok := ei.occs[id]; ok {
		return o
	}
	return nil
}

// defByID returns a definition by its ID.
func (ei *entityIndex) defByID(id string) *entities.Definition {
	if d, ok := ei.defs[id]; ok {
		return d
	}
	return nil
}

// --- Confluence-specific content stripping ---

// stripFindingBodyForConfluence removes content from finding pages that is
// redundant with the Page Properties table or only meaningful in Obsidian.
// Strips: severity callout, Endpoint line, Quick triage shortcuts, Analyst notebook.
func stripFindingBodyForConfluence(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	inSkipSection := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Strip H1 — Confluence page title is already set; the "# Issue fin-xxx — alias" body
		// heading is Obsidian-only and redundant.
		if strings.HasPrefix(line, "# ") {
			// also skip the blank line after it
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}

		// Strip "- Definition: [[...]]" bullet — duplicated in Page Properties table.
		if strings.HasPrefix(line, "- Definition:") {
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}

		// Obsidian-only sections: Quick triage shortcuts, Analyst notebook,
		// and the Workflow status/metadata lines (Status/Owners/Tags/Tickets/Updated).
		// These are either Obsidian template scaffolding or plain-text duplicates of
		// the Page Properties table — not useful in Confluence.
		skipSections := []string{
			"### Quick triage shortcuts",
			"### Analyst notebook",
			"## Workflow",
		}
		isSectionStart := false
		for _, s := range skipSections {
			if line == s {
				isSectionStart = true
				break
			}
		}
		if isSectionStart {
			inSkipSection = true
			continue
		}

		if inSkipSection {
			// Resume at the next ## or ### heading that is NOT a skip target,
			// e.g. "### Analyst Notes" which contains real analyst content.
			isSkipTarget := false
			for _, s := range skipSections {
				if line == s {
					isSkipTarget = true
					break
				}
			}
			if (strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ")) && !isSkipTarget {
				inSkipSection = false
				out = append(out, line)
			}
			continue
		}

		// Skip callout blocks (> [!TYPE] ...) — duplicates Properties table Risk/Confidence
		if strings.HasPrefix(line, "> [!") {
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], ">") {
				i++
			}
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}
		// Skip **Endpoint:** line — duplicates URL+Method in Properties table
		if strings.HasPrefix(line, "**Endpoint:**") {
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// stripOccurrenceBodyForConfluence removes Obsidian-specific content from occurrence pages.
// Strips: severity callout and Endpoint line (both duplicated in Properties table).
func stripOccurrenceBodyForConfluence(content string) string {
	// Sections that are Obsidian-only scaffolding and should not appear in Confluence.
	// "### Checklist" is intentionally NOT in this list — it contains task list items
	// that render as clickable checkboxes in Confluence.
	skipSections := []string{
		"## Workflow",
		"### Analyst notebook (from front matter)",
		"### Governance",
		"## Triage guidance",
	}

	lines := strings.Split(content, "\n")
	var out []string
	inSkipSection := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Strip H1 — Confluence page title already set; body H1 is redundant.
		if strings.HasPrefix(line, "# ") {
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}

		// Strip Definition and Issue bullets — duplicated in Page Properties table.
		if strings.HasPrefix(line, "- Definition:") || strings.HasPrefix(line, "- Issue:") {
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}

		// Obsidian-only sections
		isSectionStart := false
		for _, s := range skipSections {
			if line == s {
				isSectionStart = true
				break
			}
		}
		if isSectionStart {
			inSkipSection = true
			continue
		}
		if inSkipSection {
			isSkipTarget := false
			for _, s := range skipSections {
				if line == s {
					isSkipTarget = true
					break
				}
			}
			if (strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ")) && !isSkipTarget {
				inSkipSection = false
				out = append(out, line)
			}
			continue
		}

		// Strip callout blocks — duplicates Properties table Risk/Confidence
		if strings.HasPrefix(line, "> [!") {
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], ">") {
				i++
			}
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}
		// Strip **Endpoint:** line — duplicates URL+Method in Properties table
		if strings.HasPrefix(line, "**Endpoint:**") {
			if i+1 < len(lines) && lines[i+1] == "" {
				i++
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// sourceToolFromDef derives a human-readable source tool name from definition
// taxonomy tags (e.g. "nuclei" → "Nuclei", "zap" → "OWASP ZAP").
func sourceToolFromDef(def *entities.Definition) string {
	if def == nil || def.Taxonomy == nil {
		return ""
	}
	for _, tag := range def.Taxonomy.Tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "nuclei":
			return "Nuclei"
		case "zap":
			return "OWASP ZAP"
		case "burp":
			return "Burp Suite"
		case "semgrep":
			return "Semgrep"
		case "trivy":
			return "Trivy"
		}
	}
	return ""
}

// --- Finding/occurrence page title generation ---

// findingPageTitle returns a human-readable Confluence page title for a finding:
// "[Rule Name] — [URL path] — [short hash]"
func findingPageTitle(f *entities.Finding, ei *entityIndex) string {
	if f == nil {
		return ""
	}
	ruleName := ""
	if def := ei.defByID(f.DefinitionID); def != nil {
		ruleName = firstNonEmptyStr(def.Alert, def.Name)
	}
	if ruleName == "" {
		return ""
	}
	parts := []string{ruleName}
	if p := urlPathSegment(f.URL); p != "" {
		parts = append(parts, p)
	}
	if h := tailChars(f.FindingID, 4); h != "" {
		parts = append(parts, h)
	}
	return strings.Join(parts, " \u2014 ")
}

// occurrencePageTitle returns a human-readable Confluence page title for an occurrence:
// "[Rule Name] — [URL path] — [short hash]"
func occurrencePageTitle(o *entities.Occurrence, ei *entityIndex) string {
	if o == nil {
		return ""
	}
	ruleName := ""
	if def := ei.defByID(o.DefinitionID); def != nil {
		ruleName = firstNonEmptyStr(def.Alert, def.Name)
	}
	if ruleName == "" {
		return ""
	}
	parts := []string{ruleName}
	if p := urlPathSegment(o.URL); p != "" {
		parts = append(parts, p)
	}
	if h := tailChars(o.OccurrenceID, 4); h != "" {
		parts = append(parts, h)
	}
	return strings.Join(parts, " \u2014 ")
}

// urlPathSegment extracts the URL path (excluding scheme/host) for use in page titles.
func urlPathSegment(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	return u.Path
}

// tailChars returns the last n characters of s.
func tailChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// firstNonEmptyStr returns the first non-empty string from the arguments.
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// --- Posture Summary ---

// postureCounts holds aggregated counts for the posture summary page.
type postureCounts struct {
	TotalFindings int
	TotalOccs     int
	ByRisk        map[string]int // "high" → count of findings
	ByStatus      map[string]int // "open" → count of occurrences
	ScanLabel     string
	GeneratedAt   string
	SourceTool    string
}

// computePostureCounts aggregates findings and occurrences from an EntitiesFile.
func computePostureCounts(ef *entities.EntitiesFile) postureCounts {
	pc := postureCounts{
		ByRisk:   make(map[string]int),
		ByStatus: make(map[string]int),
	}
	if ef == nil {
		return pc
	}
	pc.GeneratedAt = ef.GeneratedAt
	pc.SourceTool = ef.SourceTool
	pc.TotalFindings = len(ef.Findings)
	pc.TotalOccs = len(ef.Occurrences)

	for _, f := range ef.Findings {
		key := strings.ToLower(strings.TrimSpace(f.Risk))
		if key == "" {
			key = "unknown"
		}
		pc.ByRisk[key]++
	}

	// Derive scan label deterministically: use the label from the occurrence with
	// the latest ObservedAt timestamp. Falls back to first non-empty label if no
	// timestamps are present. This avoids Go map iteration non-determinism.
	var latestObsTime time.Time
	latestScanLabel := ""
	for _, o := range ef.Occurrences {
		status := "open"
		if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
			status = strings.ToLower(strings.TrimSpace(o.Analyst.Status))
		}
		pc.ByStatus[status]++
		if sl := strings.TrimSpace(o.ScanLabel); sl != "" {
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(o.ObservedAt)); err == nil {
				if t.After(latestObsTime) {
					latestObsTime = t
					latestScanLabel = sl
				}
			} else if latestScanLabel == "" {
				latestScanLabel = sl // fallback: first non-empty when no timestamps
			}
		}
	}
	pc.ScanLabel = latestScanLabel
	return pc
}

// buildPostureStorageBody renders the posture summary as Confluence storage format.
// Output is deterministic so repeated exports produce identical pages.
func buildPostureStorageBody(pc postureCounts) string {
	// Page Properties table for Confluence search/reporting
	var props [][2]string
	if pc.GeneratedAt != "" {
		props = append(props, [2]string{"Generated", escapeHTML(pc.GeneratedAt)})
	}
	if pc.SourceTool != "" {
		props = append(props, [2]string{"Source Tool", escapeHTML(pc.SourceTool)})
	}
	if pc.ScanLabel != "" {
		props = append(props, [2]string{"Scan", escapeHTML(pc.ScanLabel)})
	}
	props = append(props, [2]string{"Total Findings", fmt.Sprintf("%d", pc.TotalFindings)})
	props = append(props, [2]string{"Total Occurrences", fmt.Sprintf("%d", pc.TotalOccs)})

	// Risk breakdown in Properties (ordered)
	for _, level := range []string{"critical", "high", "medium", "low", "info"} {
		if n, ok := pc.ByRisk[level]; ok && n > 0 {
			props = append(props, [2]string{
				strings.Title(level),
				fmt.Sprintf("%s %d", riskStatusMacro(strings.Title(level)), n),
			})
		}
	}

	var b strings.Builder
	b.WriteString(pagePropertiesMacro(props))

	// Risk summary table
	b.WriteString(`<h2>Risk Summary</h2>`)
	b.WriteString(`<table><tbody>`)
	b.WriteString(`<tr><th>Risk Level</th><th>Finding Count</th></tr>`)
	for _, level := range []string{"critical", "high", "medium", "low", "info"} {
		n := pc.ByRisk[level]
		b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`,
			riskStatusMacro(strings.Title(level)), n))
	}
	b.WriteString(`</tbody></table>`)

	// Triage status table
	b.WriteString(`<h2>Triage Status</h2>`)
	b.WriteString(`<table><tbody>`)
	b.WriteString(`<tr><th>Status</th><th>Occurrence Count</th></tr>`)
	for _, status := range []string{"open", "triaged", "accepted", "fp", "fixed"} {
		n := pc.ByStatus[status]
		b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`,
			triageStatusMacro(status), n))
	}
	b.WriteString(`</tbody></table>`)

	return b.String()
}

// upsertPostureSummary creates or updates the "Security Posture" page under rootID.
// The page title is always "Security Posture" so analysts can bookmark it;
// the scan label appears inside the Page Properties table, not in the title.
func upsertPostureSummary(ctx context.Context, client httpDoer, auth, base, spaceKey, rootID string, ef *entities.EntitiesFile) (string, string, error) {
	pc := computePostureCounts(ef)
	body := buildPostureStorageBody(pc)
	return upsertPage(ctx, client, auth, base, spaceKey, "Security Posture", body, rootID)
}

// --- Page Properties and Status Macros ---

// prependDefProperties adds a Page Properties macro with taxonomy metadata to definition pages.
func prependDefProperties(storageBody string, def *entities.Definition) string {
	if def == nil {
		return storageBody
	}
	var props [][2]string
	if def.Taxonomy != nil {
		if def.Taxonomy.CWEID > 0 {
			link := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
			props = append(props, [2]string{"CWE", link})
		}
		if len(def.Taxonomy.OWASPTop10) > 0 {
			props = append(props, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
		}
		if len(def.Taxonomy.ATTACK) > 0 {
			props = append(props, [2]string{"ATT&CK", escapeHTML(strings.Join(def.Taxonomy.ATTACK, ", "))})
		}
		if len(def.Taxonomy.NIST80053) > 0 {
			props = append(props, [2]string{"NIST 800-53", escapeHTML(strings.Join(def.Taxonomy.NIST80053, ", "))})
		}
	}
	if def.Detection != nil && def.Detection.LogicType != "" {
		props = append(props, [2]string{"Detection", escapeHTML(def.Detection.LogicType)})
	}
	macro := pagePropertiesMacro(props)
	if macro == "" {
		return storageBody
	}
	return macro + storageBody
}

// prependFindingProperties adds a Page Properties macro to finding pages.
// Field order: Risk, Confidence, Definition, CWE, OWASP, URL, Method, Occurrences.
func prependFindingProperties(storageBody string, f *entities.Finding, ei *entityIndex) string {
	if f == nil {
		return storageBody
	}
	var props [][2]string
	props = append(props, [2]string{"Risk", riskStatusMacro(f.Risk)})
	props = append(props, [2]string{"Confidence", escapeHTML(f.Confidence)})

	// Definition — linked page
	def := ei.defByID(f.DefinitionID)
	if def != nil {
		defTitle := firstNonEmptyStr(def.Alert, def.Name)
		if defTitle != "" {
			defLink := fmt.Sprintf(`<ac:link><ri:page ri:content-title="%s"/><ac:plain-text-link-body><![CDATA[%s]]></ac:plain-text-link-body></ac:link>`,
				escapeAttr(defTitle), defTitle)
			props = append(props, [2]string{"Definition", defLink})
		}
	}

	// Taxonomy from linked definition
	if def != nil && def.Taxonomy != nil {
		if def.Taxonomy.CWEID > 0 {
			link := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
			props = append(props, [2]string{"CWE", link})
		}
		if len(def.Taxonomy.OWASPTop10) > 0 {
			props = append(props, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
		}
	}

	// Source tool (derived from definition tags: "nuclei", "zap", "burp", etc.)
	if src := sourceToolFromDef(def); src != "" {
		props = append(props, [2]string{"Source Tool", escapeHTML(src)})
	}

	props = append(props, [2]string{"URL", escapeHTML(f.URL)})
	props = append(props, [2]string{"Method", escapeHTML(f.Method)})
	props = append(props, [2]string{"Occurrences", fmt.Sprintf("%d", f.Occurrences)})

	// firstSeen / lastSeen computed from occurrence ObservedAt timestamps
	if obs, ok := ei.findingObs[f.FindingID]; ok {
		if obs.First != "" {
			props = append(props, [2]string{"First Seen", escapeHTML(obs.First)})
		}
		if obs.Last != "" && obs.Last != obs.First {
			props = append(props, [2]string{"Last Seen", escapeHTML(obs.Last)})
		}
	}

	return pagePropertiesMacro(props) + storageBody
}

// triageStatusMacro returns a Confluence status lozenge for analyst triage status.
func triageStatusMacro(status string) string {
	if status == "" {
		return ""
	}
	color := "Grey"
	switch status {
	case "open":
		color = "Blue"
	case "triaged":
		color = "Yellow"
	case "fp", "fixed":
		color = "Green"
	case "accepted":
		color = "Red"
	}
	return fmt.Sprintf(`<ac:structured-macro name="status"><ac:parameter name="colour">%s</ac:parameter><ac:parameter name="title">%s</ac:parameter></ac:structured-macro>`,
		color, escapeAttr(strings.ToUpper(status)))
}

// prependOccurrenceProperties adds a Page Properties macro to occurrence pages.
// Both the risk lozenge and triage status lozenge are row values inside the table.
// CWE and OWASP taxonomy are pulled from the linked definition when available.
func prependOccurrenceProperties(storageBody string, o *entities.Occurrence, ei *entityIndex) string {
	if o == nil {
		return storageBody
	}
	var props [][2]string
	props = append(props, [2]string{"Risk", riskStatusMacro(o.Risk)})
	props = append(props, [2]string{"Confidence", escapeHTML(o.Confidence)})

	// Definition link + taxonomy (CWE, OWASP) from the parent definition
	def := ei.defByID(o.DefinitionID)
	if def != nil {
		defTitle := firstNonEmptyStr(def.Alert, def.Name)
		if defTitle != "" {
			defLink := fmt.Sprintf(`<ac:link><ri:page ri:content-title="%s"/><ac:plain-text-link-body><![CDATA[%s]]></ac:plain-text-link-body></ac:link>`,
				escapeAttr(defTitle), defTitle)
			props = append(props, [2]string{"Definition", defLink})
		}
		if def.Taxonomy != nil {
			if def.Taxonomy.CWEID > 0 {
				cweLink := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
				props = append(props, [2]string{"CWE", cweLink})
			}
			if len(def.Taxonomy.OWASPTop10) > 0 {
				props = append(props, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
			}
		}
	}

	// Source tool (derived from definition tags)
	if src := sourceToolFromDef(def); src != "" {
		props = append(props, [2]string{"Source Tool", escapeHTML(src)})
	}

	props = append(props, [2]string{"URL", escapeHTML(o.URL)})
	if o.Param != "" {
		props = append(props, [2]string{"Parameter", escapeHTML(o.Param)})
	}
	if o.ScanLabel != "" {
		props = append(props, [2]string{"Scan", escapeHTML(o.ScanLabel)})
	}
	if o.ObservedAt != "" {
		props = append(props, [2]string{"Observed", escapeHTML(o.ObservedAt)})
	}

	// Analyst triage metadata — Status lozenge replaces the plain-text "Status" row
	if o.Analyst != nil {
		if o.Analyst.Status != "" {
			props = append(props, [2]string{"Status", triageStatusMacro(o.Analyst.Status)})
		}
		if o.Analyst.Owner != "" {
			props = append(props, [2]string{"Owner", escapeHTML(o.Analyst.Owner)})
		}
		if len(o.Analyst.TicketRefs) > 0 {
			var links []string
			for _, ref := range o.Analyst.TicketRefs {
				if strings.HasPrefix(ref, "http") {
					links = append(links, fmt.Sprintf(`<a href="%s">%s</a>`, escapeAttr(ref), escapeHTML(ref)))
				} else {
					links = append(links, escapeHTML(ref))
				}
			}
			props = append(props, [2]string{"Tickets", strings.Join(links, ", ")})
		}
		if o.Analyst.Notes != "" {
			notesLabel := "Notes"
			if strings.EqualFold(strings.TrimSpace(o.Analyst.Status), "accept-risk") {
				notesLabel = "Accepted Reason"
			}
			props = append(props, [2]string{notesLabel, escapeHTML(o.Analyst.Notes)})
		}
	}

	return pagePropertiesMacro(props) + storageBody
}

// --- Confluence Labels API ---

// applyLabels adds labels to a Confluence page via the Labels API.
// Errors are logged but not returned (best-effort).
func applyLabels(ctx context.Context, client httpDoer, auth, base, pageID string, labels []string) {
	if pageID == "" || len(labels) == 0 {
		return
	}
	type label struct {
		Prefix string `json:"prefix"`
		Name   string `json:"name"`
	}
	payload := make([]label, 0, len(labels))
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l != "" {
			// Confluence labels: lowercase, no spaces, max 255 chars
			l = strings.ToLower(l)
			l = strings.ReplaceAll(l, " ", "-")
			if len(l) > 255 {
				l = l[:255]
			}
			payload = append(payload, label{Prefix: "global", Name: l})
		}
	}
	if len(payload) == 0 {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/content/"+pageID+"/label", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[confluence] warning: failed to apply labels to page %s: %v\n", pageID, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// --- Label builders ---

func defLabels(def *entities.Definition) []string {
	if def == nil {
		return nil
	}
	labels := []string{"definition", "plugin-" + def.PluginID}
	if def.Taxonomy != nil {
		if def.Taxonomy.CWEID > 0 {
			labels = append(labels, fmt.Sprintf("cwe-%d", def.Taxonomy.CWEID))
		}
		for _, o := range def.Taxonomy.OWASPTop10 {
			labels = append(labels, strings.ToLower(o))
		}
		labels = append(labels, def.Taxonomy.Tags...)
	}
	return labels
}

func findingLabels(f *entities.Finding) []string {
	if f == nil {
		return nil
	}
	labels := []string{"finding", "risk-" + strings.ToLower(f.Risk), "plugin-" + f.PluginID}
	return labels
}

func occurrenceLabels(o *entities.Occurrence) []string {
	if o == nil {
		return nil
	}
	labels := []string{"occurrence", "risk-" + strings.ToLower(o.Risk)}
	if o.ScanLabel != "" {
		labels = append(labels, "scan-"+strings.ToLower(o.ScanLabel))
	}
	if o.Analyst != nil && o.Analyst.Status != "" {
		labels = append(labels, "status-"+o.Analyst.Status)
	}
	return labels
}
