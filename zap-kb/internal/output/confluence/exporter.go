package confluence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// pageHashStore persists SHA-256 hashes of page storage bodies and their
// Confluence page IDs to avoid re-pushing unchanged pages on every export run.
// By caching page IDs alongside hashes, the skip path requires zero API calls.
type pageHashStore struct {
	mu   sync.Mutex
	path string
	data map[string]pageHashEntry // title → {hash, pageID}
}

type pageHashEntry struct {
	Hash   string `json:"hash"`   // hex(sha256(storageBody))
	PageID string `json:"pageId"` // Confluence page ID for child-parenting
}

func loadHashStore(path string) *pageHashStore {
	s := &pageHashStore{path: path, data: make(map[string]pageHashEntry)}
	b, err := os.ReadFile(path)
	if err == nil {
		// Try new format first
		var newData map[string]pageHashEntry
		if json.Unmarshal(b, &newData) == nil {
			s.data = newData
			return s
		}
		// Fall back to legacy format (title → hash string)
		var legacyData map[string]string
		if json.Unmarshal(b, &legacyData) == nil {
			for title, hash := range legacyData {
				s.data[title] = pageHashEntry{Hash: hash}
			}
		}
	}
	return s
}

func (s *pageHashStore) unchanged(title, storageBody string) bool {
	h := sha256.Sum256([]byte(storageBody))
	hash := hex.EncodeToString(h[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[title].Hash == hash
}

// cachedPageID returns the cached Confluence page ID for the given title,
// or "" if not cached. Used by the skip path to avoid a findPage API call.
func (s *pageHashStore) cachedPageID(title string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[title].PageID
}

func (s *pageHashStore) record(title, storageBody, pageID string) {
	h := sha256.Sum256([]byte(storageBody))
	hash := hex.EncodeToString(h[:])
	s.mu.Lock()
	s.data[title] = pageHashEntry{Hash: hash, PageID: pageID}
	s.mu.Unlock()
}

func (s *pageHashStore) save() error {
	s.mu.Lock()
	b, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
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
	titleMap := buildTitleMap(vaultRoot, &ei)

	// Load content hash store — used to skip pages that haven't changed.
	hashStorePath := filepath.Join(vaultRoot, ".confluence-hashes.json")
	hs := loadHashStore(hashStorePath)

	var summary VaultSummary

	// Phase 1: Upsert the root page (INDEX.md)
	rootContent, err := readMarkdownFile(filepath.Join(vaultRoot, "INDEX.md"))
	if err != nil {
		return summary, fmt.Errorf("read INDEX.md: %w", err)
	}

	if opts.DryRun {
		return dryRunVault(vaultRoot)
	}

	rootID, rootAction, err := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, "KB Index", mdToStorageWithTitles(rootContent, titleMap), "", hs)
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
		storageBody := mdToStorageWithTitles(content, titleMap)
		// The Page Properties Report macro is intentionally NOT appended here —
		// it depends on the page-properties macro which fails in Confluence Cloud
		// via REST API. Triage is done by editing individual occurrence pages.
		_, action, uerr := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, tp.title, storageBody, rootID, hs)
		if uerr != nil {
			fmt.Printf("[confluence] error upserting %s: %v\n", tp.title, uerr)
			summary.Errors++
			continue
		}
		countAction(&summary, action)
	}

	// Phase 2b: Upsert scan-level posture summary page (requires EntitiesFile)
	if opts.Entities != nil {
		_, postureAction, postureErr := upsertPostureSummary(ctx, httpClient, auth, base, opts.SpaceKey, rootID, opts.Entities, hs)
		if postureErr != nil {
			fmt.Printf("[confluence] error upserting posture summary: %v\n", postureErr)
			summary.Errors++
		} else {
			countAction(&summary, postureAction)
		}
	}

	// Phase 3: Upsert "Security Rule Definitions" parent page (built-in ZAP rules)
	// and "Custom Detections" sibling page (project-specific custom rules).
	defsBody := `<p>Auto-generated security rule definitions from the DevSecOps KB.</p>` + childrenMacro()
	defsID, defsAction, err := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, "Security Rule Definitions",
		defsBody, rootID, hs)
	if err != nil {
		return summary, fmt.Errorf("upsert Security Rule Definitions parent: %w", err)
	}
	countAction(&summary, defsAction)

	customDefsBody := `<p>Project-specific custom detection rules — not built-in ZAP plugins. Written for this application&#39;s known attack surface.</p>` + childrenMacro()
	customDefsID, customDefsAction, err := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, "Custom Detections",
		customDefsBody, rootID, hs)
	if err != nil {
		return summary, fmt.Errorf("upsert Custom Detections parent: %w", err)
	}
	countAction(&summary, customDefsAction)

	// Phase 4: Parallel upsert of definition pages
	defsDir := filepath.Join(vaultRoot, "definitions")
	entries, err := os.ReadDir(defsDir)
	if err != nil {
		// No definitions dir is not fatal — still write the summary page.
		upsertExportSummary(ctx, httpClient, auth, base, opts, rootID, hs, &summary)
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

			// Route custom definitions to the "Custom Detections" folder.
			parentID := defsID
			if def != nil && isConfluenceCustomRule(def.PluginID, def.Detection) {
				parentID = customDefsID
			}

			pageID, action, uerr := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, title, storageBody, parentID, hs)
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

	// Phase 5: Create "Findings" folder page as a top-level sibling of "Security Rule Definitions".
	// Findings are parented here (not buried under individual definition pages) so they
	// appear in the sidebar and are reachable from Quick navigation.
	findingsBody := `<p>All active security findings. Each finding groups one or more occurrences of the same rule at the same endpoint.</p>` + childrenMacro()
	findingsID, findingsAction, err := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, "Findings",
		findingsBody, rootID, hs)
	if err != nil {
		return summary, fmt.Errorf("upsert Findings parent: %w", err)
	}
	countAction(&summary, findingsAction)

	// Phase 5b: Create "Occurrences" folder page as a sibling (for flat fallback path
	// and for consistency — hierarchical path nests occurrences under findings).
	occurrencesBody := `<p>All occurrence instances. Each occurrence is a single observed instance of a finding at a specific URL.</p>` + childrenMacro()
	occurrencesID, occurrencesAction, occErr := upsertPageCached(ctx, httpClient, auth, base, opts.SpaceKey, "Occurrences",
		occurrencesBody, rootID, hs)
	if occErr != nil {
		fmt.Printf("[confluence] error upserting Occurrences parent: %v\n", occErr)
		summary.Errors++
	} else {
		countAction(&summary, occurrencesAction)
	}
	_ = occurrencesID // used in flat fallback path below

	// Phase 6: Hierarchical export — findings under "Findings", occurrences under their finding.
	// Falls back to flat upsertDir when entity data is absent.
	if opts.Entities != nil {
		findingPageIDs := upsertFindingsHierarchical(ctx, httpClient, auth, base, opts.SpaceKey,
			vaultRoot, concurrency, &ei, titleMap, defPageIDs, findingsID, &summary, hs)
		upsertOccurrencesHierarchical(ctx, httpClient, auth, base, opts.SpaceKey,
			vaultRoot, concurrency, &ei, titleMap, findingPageIDs, findingsID, &summary, hs)
	} else {
		upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "findings", "Findings", rootID, concurrency, &ei, titleMap, &summary, hs)
		upsertDir(ctx, httpClient, auth, base, opts.SpaceKey, vaultRoot, "occurrences", "Occurrences", rootID, concurrency, &ei, titleMap, &summary, hs)
	}

	// Persist updated hashes for next run.
	if err := hs.save(); err != nil {
		fmt.Printf("[confluence] warning: could not save hash store: %v\n", err)
	}

	// Phase 7: Upsert the "KB Export Summary" page as a child of root.
	upsertExportSummary(ctx, httpClient, auth, base, opts, rootID, hs, &summary)

	return summary, nil
}

// upsertExportSummary writes (or dry-logs) the "KB Export Summary" page as a child of rootID.
func upsertExportSummary(ctx context.Context, client httpDoer, auth, base string, opts VaultOptions, rootID string, hs *pageHashStore, summary *VaultSummary) {
	var defCount, findCount, occCount int
	if opts.Entities != nil {
		defCount = len(opts.Entities.Definitions)
		findCount = len(opts.Entities.Findings)
		occCount = len(opts.Entities.Occurrences)
	}
	summaryBody := buildExportSummaryBody(time.Now().UTC(), defCount, findCount, occCount, summary)
	if opts.DryRun {
		fmt.Printf("[confluence] dry-run: KB Export Summary — defs=%d findings=%d occurrences=%d created=%d updated=%d skipped=%d errors=%d\n",
			defCount, findCount, occCount, summary.Created, summary.Updated, summary.Skipped, summary.Errors)
	} else {
		_, _, _ = upsertPageCached(ctx, client, auth, base, opts.SpaceKey, "KB Export Summary", summaryBody, rootID, hs)
	}
}

// buildExportSummaryBody constructs the storage XML body for the KB Export Summary page.
func buildExportSummaryBody(exportedAt time.Time, defs, findings, occurrences int, s *VaultSummary) string {
	var b strings.Builder
	b.WriteString("<h1>KB Export Summary</h1>")
	b.WriteString(fmt.Sprintf("<p><strong>Export timestamp (UTC):</strong> %s</p>", exportedAt.Format(time.RFC3339)))
	b.WriteString("<h2>Entity counts</h2>")
	b.WriteString("<table><tbody>")
	b.WriteString(fmt.Sprintf("<tr><th>Definitions</th><td>%d</td></tr>", defs))
	b.WriteString(fmt.Sprintf("<tr><th>Findings</th><td>%d</td></tr>", findings))
	b.WriteString(fmt.Sprintf("<tr><th>Occurrences</th><td>%d</td></tr>", occurrences))
	b.WriteString("</tbody></table>")
	b.WriteString("<h2>Page export results</h2>")
	b.WriteString("<table><tbody>")
	b.WriteString(fmt.Sprintf("<tr><th>Created</th><td>%d</td></tr>", s.Created))
	b.WriteString(fmt.Sprintf("<tr><th>Updated</th><td>%d</td></tr>", s.Updated))
	b.WriteString(fmt.Sprintf("<tr><th>Skipped (unchanged)</th><td>%d</td></tr>", s.Skipped))
	b.WriteString(fmt.Sprintf("<tr><th>Errors</th><td>%d</td></tr>", s.Errors))
	b.WriteString("</tbody></table>")
	return b.String()
}

// upsertFindingsHierarchical upserts finding pages as children of their definition pages.
// Returns a map of findingID → Confluence pageID for use by upsertOccurrencesHierarchical.
// Findings whose definition page ID is not in defPageIDs are parented to fallbackParentID.
func upsertFindingsHierarchical(
	ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot string,
	concurrency int, ei *entityIndex, titleMap map[string]string,
	defPageIDs map[string]string, fallbackParentID string,
	summary *VaultSummary, hs *pageHashStore,
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

			// Parent: always the Findings folder page so findings are visible in the sidebar.
			// The Definition link is already shown in the Page Properties table.
			parentID := fallbackParentID
			_ = defPageIDs // retained for signature compatibility

			storageBody := mdToStorageWithTitles(content, titleMap)
			storageBody = prependFindingProperties(storageBody, f, ei)
			labels := findingLabels(f)

			pageID, act, uerr := upsertPageCached(ctx, client, auth, base, spaceKey, title, storageBody, parentID, hs)
			if uerr == nil && len(labels) > 0 && act != "skipped" {
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
	summary *VaultSummary, hs *pageHashStore,
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

			pageID, act, uerr := upsertPageCached(ctx, client, auth, base, spaceKey, title, storageBody, parentID, hs)
			if uerr == nil && len(labels) > 0 && act != "skipped" {
				applyLabels(ctx, client, auth, base, pageID, labels)
			}
			if uerr == nil && pageID != "" {
				if err := addPageLabel(ctx, client, auth, base, pageID, "kb-occurrence"); err != nil {
					fmt.Printf("[confluence] warning: could not add kb-occurrence label to page %s: %v\n", pageID, err)
				}
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
func upsertDir(ctx context.Context, client httpDoer, auth, base, spaceKey, vaultRoot, subdir, parentTitle, grandParentID string, concurrency int, ei *entityIndex, titleMap map[string]string, summary *VaultSummary, hs *pageHashStore) {
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

	// Upsert parent page — include children macro for findings/occurrences folders.
	var parentStorageBody string
	switch subdir {
	case "findings":
		parentStorageBody = `<p>All active security findings. Each finding groups one or more occurrences of the same rule at the same endpoint.</p>` + childrenMacro()
	case "occurrences":
		parentStorageBody = `<p>All occurrence instances. Each occurrence is a single observed instance of a finding at a specific URL.</p>` + childrenMacro()
	default:
		parentStorageBody = mdToStorage("# " + parentTitle + "\n\nGenerated by DevSecOps KB.")
	}
	parentID, action, err := upsertPageCached(ctx, client, auth, base, spaceKey, parentTitle, parentStorageBody, grandParentID, hs)
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

			pageID, act, uerr := upsertPageCached(ctx, client, auth, base, spaceKey, title, storageBody, parentID, hs)
			if uerr == nil && len(labels) > 0 && act != "skipped" {
				applyLabels(ctx, client, auth, base, pageID, labels)
			}
			if uerr == nil && pageID != "" && subdir == "occurrences" {
				if err := addPageLabel(ctx, client, auth, base, pageID, "kb-occurrence"); err != nil {
					fmt.Printf("[confluence] warning: could not add kb-occurrence label to page %s: %v\n", pageID, err)
				}
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

// upsertPageCached wraps upsertPage: if the page already exists and the
// storage body hash is unchanged, it skips the API call and returns "skipped".
// On any create/update, the hash is recorded.
func upsertPageCached(ctx context.Context, client httpDoer, auth, base, spaceKey, title, storageBody, parentID string, hs *pageHashStore) (string, string, error) {
	if hs != nil && hs.unchanged(title, storageBody) {
		// Use cached page ID — zero API calls on the skip path.
		if cachedID := hs.cachedPageID(title); cachedID != "" {
			return cachedID, "skipped", nil
		}
		// Page ID not cached (legacy hash store or first run after migration).
		// Fall back to a single GET to resolve it.
		existingID, _, err := findPage(ctx, client, auth, base, spaceKey, title)
		if err != nil {
			return "", "", fmt.Errorf("find page %q: %w", title, err)
		}
		if existingID != "" {
			// Backfill the page ID into the cache for next run.
			hs.record(title, storageBody, existingID)
			return existingID, "skipped", nil
		}
		// Page doesn't exist yet despite hash match (edge case) — fall through.
	}
	id, action, err := upsertPage(ctx, client, auth, base, spaceKey, title, storageBody, parentID)
	if err == nil && hs != nil && (action == "created" || action == "updated") {
		hs.record(title, storageBody, id)
	}
	return id, action, err
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
// vault-relative paths to their Confluence page titles.
//
// For definitions: title is derived from H1 heading (same as Confluence page title).
// For findings/occurrences: title is derived from findingPageTitle/occurrencePageTitle
// because those functions produce the Confluence page title, and the H1 is stripped
// from the body before export (so the H1 in the vault file does NOT match the page title).
func buildTitleMap(vaultRoot string, ei *entityIndex) map[string]string {
	tm := make(map[string]string)

	// definitions and root: use H1 heading
	for _, subdir := range []string{"", "definitions"} {
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
			if subdir != "" {
				tm[subdir+"/"+e.Name()] = title
			}
			tm[e.Name()] = title
		}
	}

	// findings: use findingPageTitle — the H1 is stripped before export so it
	// does NOT match the Confluence page title.
	if ei != nil {
		findEntries, _ := os.ReadDir(filepath.Join(vaultRoot, "findings"))
		for _, e := range findEntries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			f := ei.findingByFilename(e.Name())
			title := findingPageTitle(f, ei)
			if title == "" {
				title = defTitleFromFilename(e.Name())
			}
			tm["findings/"+e.Name()] = title
			tm[e.Name()] = title
		}

		// occurrences: use occurrencePageTitle for the same reason
		occEntries, _ := os.ReadDir(filepath.Join(vaultRoot, "occurrences"))
		for _, e := range occEntries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			o := ei.occurrenceByFilename(e.Name())
			title := occurrencePageTitle(o, ei)
			if title == "" {
				title = defTitleFromFilename(e.Name())
			}
			tm["occurrences/"+e.Name()] = title
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
	defs                map[string]*entities.Definition // pluginID → definition
	finds               map[string]*entities.Finding    // findingID → finding
	occs                map[string]*entities.Occurrence // occurrenceID → occurrence
	findingObs          map[string]obsRange             // findingID → {first, last} ObservedAt
	findingTriageStatus map[string]string               // findingID → dominant triage status
	findingScans        map[string][]string             // findingID → distinct scan labels (ordered by first seen)
}

func buildEntityIndex(ef *entities.EntitiesFile) entityIndex {
	ei := entityIndex{
		defs:                make(map[string]*entities.Definition),
		finds:               make(map[string]*entities.Finding),
		occs:                make(map[string]*entities.Occurrence),
		findingObs:          make(map[string]obsRange),
		findingTriageStatus: make(map[string]string),
		findingScans:        make(map[string][]string),
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
	// statusPriority defines dominance order for aggregate triage status.
	// Lower index = higher priority (open wins over fixed, etc.).
	statusPriority := map[string]int{"open": 0, "triaged": 1, "accepted": 2, "fp": 3, "fixed": 4}
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		ei.occs[o.OccurrenceID] = o
		// Accumulate dominant triage status per finding (open takes priority)
		if o.FindingID != "" {
			oStatus := "open"
			if o.Analyst != nil && o.Analyst.Status != "" {
				oStatus = o.Analyst.Status
			}
			cur, exists := ei.findingTriageStatus[o.FindingID]
			if !exists {
				ei.findingTriageStatus[o.FindingID] = oStatus
			} else {
				if statusPriority[oStatus] < statusPriority[cur] {
					ei.findingTriageStatus[o.FindingID] = oStatus
				}
			}
		}
		// Accumulate distinct scan labels per finding
		if o.FindingID != "" && o.ScanLabel != "" {
			labels := ei.findingScans[o.FindingID]
			found := false
			for _, l := range labels {
				if l == o.ScanLabel {
					found = true
					break
				}
			}
			if !found {
				ei.findingScans[o.FindingID] = append(labels, o.ScanLabel)
			}
		}
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
	// "### Checklist" is excluded: Confluence Cloud does not persist ac:task clicks
	// on API-created pages, so the section was removed from occurrence pages entirely.
	skipSections := []string{
		"## Workflow",
		"### Analyst notebook (from front matter)",
		"### Checklist",
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
func upsertPostureSummary(ctx context.Context, client httpDoer, auth, base, spaceKey, rootID string, ef *entities.EntitiesFile, hs *pageHashStore) (string, string, error) {
	pc := computePostureCounts(ef)
	body := buildPostureStorageBody(pc)
	return upsertPageCached(ctx, client, auth, base, spaceKey, "Security Posture", body, rootID, hs)
}

// --- Page Properties and Status Macros ---

// prependDefProperties adds a Page Properties macro with taxonomy metadata to definition pages.
// Canonical field order: Plugin ID, CWE, OWASP, Tags (Detection logic type), ATT&CK, NIST 800-53.
func prependDefProperties(storageBody string, def *entities.Definition) string {
	if def == nil {
		return storageBody
	}
	var props [][2]string
	// 1. Plugin ID
	if def.PluginID != "" {
		props = append(props, [2]string{"Plugin ID", escapeHTML(def.PluginID)})
	}
	// 2. CWE
	if def.Taxonomy != nil && def.Taxonomy.CWEID > 0 {
		link := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
		props = append(props, [2]string{"CWE", link})
	}
	// 3. OWASP
	if def.Taxonomy != nil && len(def.Taxonomy.OWASPTop10) > 0 {
		props = append(props, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
	}
	// 3b. CAPEC
	if def.Taxonomy != nil && len(def.Taxonomy.CAPECIDs) > 0 {
		capecStrs := make([]string, len(def.Taxonomy.CAPECIDs))
		for i, id := range def.Taxonomy.CAPECIDs {
			capecStrs[i] = fmt.Sprintf("CAPEC-%d", id)
		}
		props = append(props, [2]string{"CAPEC", escapeHTML(strings.Join(capecStrs, ", "))})
	}
	// 4. Tags — represented by Detection logic type; ATT&CK and NIST follow
	if def.Detection != nil && def.Detection.LogicType != "" {
		props = append(props, [2]string{"Detection", escapeHTML(def.Detection.LogicType)})
	}
	if def.Taxonomy != nil {
		if len(def.Taxonomy.ATTACK) > 0 {
			props = append(props, [2]string{"ATT&CK", escapeHTML(strings.Join(def.Taxonomy.ATTACK, ", "))})
		}
		if len(def.Taxonomy.NIST80053) > 0 {
			props = append(props, [2]string{"NIST 800-53", escapeHTML(strings.Join(def.Taxonomy.NIST80053, ", "))})
		}
	}
	macro := pagePropertiesMacro(props)
	if macro == "" {
		return storageBody
	}
	return macro + storageBody
}

// prependFindingProperties adds a Page Properties macro to finding pages.
// Canonical field order: Severity, Status, CWE, OWASP, Domain, Last Seen, Occurrences.
// Additional contextual fields (Confidence, Definition, Source Tool, URL, Method, First Seen)
// follow in supplementary positions.
func prependFindingProperties(storageBody string, f *entities.Finding, ei *entityIndex) string {
	if f == nil {
		return storageBody
	}
	var props [][2]string

	// 1. Severity
	props = append(props, [2]string{"Severity", riskStatusMacro(f.Risk)})

	// 2. Status — aggregate triage status derived from occurrence analyst data
	if status, ok := ei.findingTriageStatus[f.FindingID]; ok && status != "" {
		props = append(props, [2]string{"Status", triageStatusMacro(status)})
	}

	def := ei.defByID(f.DefinitionID)

	// 3. CWE
	if def != nil && def.Taxonomy != nil && def.Taxonomy.CWEID > 0 {
		link := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
		props = append(props, [2]string{"CWE", link})
	}

	// 4. OWASP
	if def != nil && def.Taxonomy != nil && len(def.Taxonomy.OWASPTop10) > 0 {
		props = append(props, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
	}

	// 5. Domain — extracted from the finding URL host
	if f.URL != "" {
		props = append(props, [2]string{"Domain", escapeHTML(hostFromURL(f.URL))})
	}

	// 6. Last Seen — always emit when non-empty; annotate with "(same run)" when equal to First
	if obs, ok := ei.findingObs[f.FindingID]; ok {
		if obs.Last != "" {
			lastSeenVal := obs.Last
			if obs.Last == obs.First {
				lastSeenVal = obs.Last + " (same run)"
			}
			props = append(props, [2]string{"Last Seen", escapeHTML(lastSeenVal)})
		}
	}

	// 7. Occurrences
	props = append(props, [2]string{"Occurrences", fmt.Sprintf("%d", f.Occurrences)})

	// --- Supplementary fields ---
	props = append(props, [2]string{"Confidence", escapeHTML(f.Confidence)})

	// Definition — linked page. Title must match the Confluence page title format:
	// "<Alert> (Plugin <pluginID>)" — same as the H1 written by obsidian WriteVault.
	if def != nil {
		baseTitle := firstNonEmptyStr(def.Alert, def.Name)
		defTitle := baseTitle
		if def.PluginID != "" && baseTitle != "" {
			defTitle = fmt.Sprintf("%s (Plugin %s)", baseTitle, def.PluginID)
		}
		if defTitle != "" {
			defLink := fmt.Sprintf(`<ac:link><ri:page ri:content-title="%s"/><ac:plain-text-link-body><![CDATA[%s]]></ac:plain-text-link-body></ac:link>`,
				escapeAttr(defTitle), baseTitle)
			props = append(props, [2]string{"Definition", defLink})
		}
	}

	// Source tool (derived from definition tags: "nuclei", "zap", "burp", etc.)
	if src := sourceToolFromDef(def); src != "" {
		props = append(props, [2]string{"Source Tool", escapeHTML(src)})
	}

	props = append(props, [2]string{"URL", escapeHTML(f.URL)})
	props = append(props, [2]string{"Method", escapeHTML(f.Method)})

	// First Seen (supplementary — appears after Occurrences)
	if obs, ok := ei.findingObs[f.FindingID]; ok {
		if obs.First != "" {
			props = append(props, [2]string{"First Seen", escapeHTML(obs.First)})
		}
	}

	// Scans — distinct scan labels from contributing occurrences
	if scans, ok := ei.findingScans[f.FindingID]; ok && len(scans) > 0 {
		props = append(props, [2]string{"Scans", escapeHTML(strings.Join(scans, ", "))})
	}

	return pagePropertiesMacro(props) + storageBody
}

// hostFromURL extracts the hostname from a raw URL without importing net/url.
func hostFromURL(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
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
	return fmt.Sprintf(`<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">%s</ac:parameter><ac:parameter ac:name="title">%s</ac:parameter></ac:structured-macro>`,
		color, escapeAttr(strings.ToUpper(status)))
}

// prependOccurrenceProperties adds structured metadata to occurrence pages.
// Triage fields (Status, Owner) come first in the table so they are immediately
// visible and easy to edit. Informational fields follow.
// NOTE: The Confluence page-properties macro ("Error loading the extension!") is
// intentionally NOT used — it fails to render in Confluence Cloud via REST API.
// The pull command reads Status/Owner from this plain table directly.
func prependOccurrenceProperties(storageBody string, o *entities.Occurrence, ei *entityIndex) string {
	if o == nil {
		return storageBody
	}

	def := ei.defByID(o.DefinitionID)

	status := "open"
	owner := ""
	if o.Analyst != nil {
		if o.Analyst.Status != "" {
			status = o.Analyst.Status
		}
		owner = o.Analyst.Owner
	}

	// Edit instruction — appears before the table
	editInstruction := `<p><em>To triage: <strong>Edit this page</strong> → update Status/Owner in the table below → Save → run <code>zap-kb pull</code> to sync back. Valid status values: open | triaged | fp | accepted | fixed</em></p>`

	// --- Single plain table: triage fields first, then informational ---
	var infoProps [][2]string
	infoProps = append(infoProps, [2]string{"Status", escapeHTML(status)})
	infoProps = append(infoProps, [2]string{"Owner", escapeHTML(owner)})
	infoProps = append(infoProps, [2]string{"Risk", escapeHTML(o.Risk)})
	infoProps = append(infoProps, [2]string{"Confidence", escapeHTML(o.Confidence)})

	// Definition link + taxonomy (CWE, OWASP) from the parent definition
	if def != nil {
		// The Confluence page title for a definition is "<Alert> (Plugin <pluginID>)" —
		// matching the H1 written by obsidian WriteVault: "# <title> (Plugin <pluginID>)".
		// Using just def.Alert produces a broken createpage link.
		baseTitle := firstNonEmptyStr(def.Alert, def.Name)
		defTitle := baseTitle
		if def.PluginID != "" && baseTitle != "" {
			defTitle = fmt.Sprintf("%s (Plugin %s)", baseTitle, def.PluginID)
		}
		if defTitle != "" {
			defLink := fmt.Sprintf(`<ac:link><ri:page ri:content-title="%s"/><ac:plain-text-link-body><![CDATA[%s]]></ac:plain-text-link-body></ac:link>`,
				escapeAttr(defTitle), baseTitle)
			infoProps = append(infoProps, [2]string{"Definition", defLink})
		}
		if def.Taxonomy != nil {
			if def.Taxonomy.CWEID > 0 {
				cweLink := fmt.Sprintf(`<a href="%s">CWE-%d</a>`, escapeAttr(def.Taxonomy.CWEURI), def.Taxonomy.CWEID)
				infoProps = append(infoProps, [2]string{"CWE", cweLink})
			}
			if len(def.Taxonomy.OWASPTop10) > 0 {
				infoProps = append(infoProps, [2]string{"OWASP Top 10", escapeHTML(strings.Join(def.Taxonomy.OWASPTop10, ", "))})
			}
		}
	}

	// Source tool (derived from definition tags)
	if src := sourceToolFromDef(def); src != "" {
		infoProps = append(infoProps, [2]string{"Source Tool", escapeHTML(src)})
	}

	infoProps = append(infoProps, [2]string{"URL", escapeHTML(o.URL)})
	if o.Param != "" {
		infoProps = append(infoProps, [2]string{"Parameter", escapeHTML(o.Param)})
	}
	if o.ScanLabel != "" {
		infoProps = append(infoProps, [2]string{"Scan", escapeHTML(o.ScanLabel)})
	}
	if o.ObservedAt != "" {
		infoProps = append(infoProps, [2]string{"Observed", escapeHTML(o.ObservedAt)})
	}

	// Analyst supplementary fields (ticket refs, notes, tags, updated)
	if o.Analyst != nil {
		if len(o.Analyst.TicketRefs) > 0 {
			var links []string
			for _, ref := range o.Analyst.TicketRefs {
				if strings.HasPrefix(ref, "http") {
					links = append(links, fmt.Sprintf(`<a href="%s">%s</a>`, escapeAttr(ref), escapeHTML(ref)))
				} else {
					links = append(links, escapeHTML(ref))
				}
			}
			infoProps = append(infoProps, [2]string{"Tickets", strings.Join(links, ", ")})
		}
		if o.Analyst.Notes != "" {
			notesLabel := "Notes"
			if strings.EqualFold(strings.TrimSpace(o.Analyst.Status), "accept-risk") {
				notesLabel = "Accepted Reason"
			}
			infoProps = append(infoProps, [2]string{notesLabel, escapeHTML(o.Analyst.Notes)})
		}
		if len(o.Analyst.Tags) > 0 {
			infoProps = append(infoProps, [2]string{"Tags", escapeHTML(strings.Join(o.Analyst.Tags, ", "))})
		}
		if o.Analyst.UpdatedAt != "" {
			infoProps = append(infoProps, [2]string{"Updated", escapeHTML(o.Analyst.UpdatedAt)})
		}
	}

	var infoTable strings.Builder
	infoTable.WriteString(`<table><tbody>`)
	for _, kv := range infoProps {
		infoTable.WriteString("<tr><th>")
		infoTable.WriteString(escapeHTML(kv[0]))
		infoTable.WriteString("</th><td>")
		infoTable.WriteString(kv[1])
		infoTable.WriteString("</td></tr>")
	}
	infoTable.WriteString(`</tbody></table>`)

	return editInstruction + infoTable.String() + storageBody
}

// --- Confluence Labels API ---

// addPageLabel adds a single label to a Confluence page (best-effort).
// Errors are logged but not returned so a label failure never blocks export.
func addPageLabel(ctx context.Context, client httpDoer, auth, base, pageID, label string) error {
	if pageID == "" || label == "" {
		return nil
	}
	label = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(label, " ", "-")))
	if len(label) > 255 {
		label = label[:255]
	}
	type labelEntry struct {
		Prefix string `json:"prefix"`
		Name   string `json:"name"`
	}
	payload := []labelEntry{{Prefix: "global", Name: label}}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/content/"+pageID+"/label", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

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

// isConfluenceCustomRule returns true when a definition is a project-specific custom
// rule rather than a built-in ZAP plugin. Mirrors the obsidian isCustomRule logic.
func isConfluenceCustomRule(pluginID string, det *entities.Detection) bool {
	if strings.HasPrefix(pluginID, "zap-") {
		return true
	}
	if det != nil && strings.TrimSpace(det.RuleSource) == "custom" {
		return true
	}
	if det == nil {
		for _, r := range pluginID {
			if r < '0' || r > '9' {
				return true
			}
		}
	}
	return false
}
