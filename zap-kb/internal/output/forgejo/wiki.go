package forgejo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// WikiOptions controls publishing the Obsidian markdown vault to a Forgejo wiki.
type WikiOptions struct {
	BaseURL       string
	Token         string
	Owner         string
	Repo          string
	DryRun        bool
	Concurrency   int
	Timeout       time.Duration
	RequestDelay  time.Duration
	CommitMessage string // default "DevSecOpsKB publish"
}

// WikiSummary reports what the wiki export did.
type WikiSummary struct {
	Created int
	Updated int
	Skipped int
	Errors  int
}

// topLevelWikiPages maps known vault files to friendly wiki page names. INDEX.md
// becomes "Home" — the wiki landing page. Missing files are skipped silently.
var topLevelWikiPages = []struct {
	file string
	page string
}{
	{"INDEX.md", "Home"},
	{"DASHBOARD.md", "Dashboard"},
	{"triage-board.md", "Triage Board"},
	{"tuning-candidates.md", "Tuning Candidates"},
	{"by-domain.md", "By Domain"},
	{"by-scan.md", "Scans"},
	{"LEGEND.md", "Alias Legend"},
	{"TRIAGE-GUIDE.md", "Triage Workflow Guide"},
	{"EXECUTIVE-SUMMARY.md", "Executive Summary"},
	{"latest-scan.md", "Latest Scan"},
}

// wikiSubdirs are the entity directories nested as wiki subpages. Slashes in the
// page name render as a hierarchy in Forgejo.
var wikiSubdirs = []string{"definitions", "findings", "occurrences"}

// ExportWiki walks the generated Obsidian vault at vaultRoot and upserts each
// markdown file as a Forgejo wiki page. Because Forgejo renders markdown (and
// [[wikilinks]]) natively, the vault content is pushed verbatim (frontmatter
// stripped) — no XHTML conversion. Pages are upserted in parallel up to
// opts.Concurrency.
func ExportWiki(ctx context.Context, vaultRoot string, opts WikiOptions) (WikiSummary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.Token) == "" ||
		strings.TrimSpace(opts.Owner) == "" || strings.TrimSpace(opts.Repo) == "" {
		return WikiSummary{}, fmt.Errorf("forgejo wiki: missing required fields (base URL, token, owner, repo)")
	}
	if strings.TrimSpace(vaultRoot) == "" {
		return WikiSummary{}, fmt.Errorf("forgejo wiki: vault path is required")
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}
	msg := strings.TrimSpace(opts.CommitMessage)
	if msg == "" {
		msg = "DevSecOpsKB publish"
	}
	c := newClient(defaultHTTP(opts.Timeout, opts.RequestDelay), opts.BaseURL, opts.Token, opts.Owner, opts.Repo)

	// Collect (pageName → file path) for every page to publish.
	type page struct {
		name string
		path string
	}
	var pages []page
	for _, tp := range topLevelWikiPages {
		p := filepath.Join(vaultRoot, tp.file)
		if _, err := os.Stat(p); err == nil {
			pages = append(pages, page{name: tp.page, path: p})
		}
	}
	for _, sub := range wikiSubdirs {
		dir := filepath.Join(vaultRoot, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			name := titleCaseWord(sub) + "/" + strings.TrimSuffix(e.Name(), ".md")
			pages = append(pages, page{name: name, path: filepath.Join(dir, e.Name())})
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].name < pages[j].name })

	if opts.DryRun {
		fmt.Printf("[forgejo wiki] dry-run: would upsert %d page(s)\n", len(pages))
		return WikiSummary{Skipped: len(pages)}, nil
	}

	var (
		summary WikiSummary
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
	)
	for _, p := range pages {
		wg.Add(1)
		go func(p page) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			content, err := readVaultMarkdown(p.path)
			if err != nil {
				mu.Lock()
				summary.Errors++
				mu.Unlock()
				fmt.Printf("[forgejo wiki] error reading %s: %v\n", p.path, err)
				return
			}
			action, err := c.upsertWikiPage(ctx, p.name, content, msg)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				summary.Errors++
				fmt.Printf("[forgejo wiki] error upserting %q: %v\n", p.name, err)
			case action == "created":
				summary.Created++
			case action == "updated":
				summary.Updated++
			default:
				summary.Skipped++
			}
		}(p)
	}
	wg.Wait()
	return summary, nil
}

// upsertWikiPage creates the wiki page or, if it already exists, updates it.
// Returns "created" or "updated".
func (c *client) upsertWikiPage(ctx context.Context, name, content, message string) (string, error) {
	exists, err := c.wikiPageExists(ctx, name)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{
		"title":          name,
		"content_base64": base64.StdEncoding.EncodeToString([]byte(content)),
		"message":        message,
	})
	if err != nil {
		return "", err
	}

	if exists {
		u := c.repoAPI() + "/wiki/page/" + url.PathEscape(name)
		req, err := c.newRequest(ctx, http.MethodPatch, u, body)
		if err != nil {
			return "", err
		}
		resp, err := synccore.DoWithRetry(c.http, req, 3)
		if err != nil {
			return "", err
		}
		drain(resp)
		return "updated", nil
	}

	req, err := c.newRequest(ctx, http.MethodPost, c.repoAPI()+"/wiki/new", body)
	if err != nil {
		return "", err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return "", err
	}
	drain(resp)
	return "created", nil
}

// wikiPageExists reports whether a wiki page with the given name already exists.
func (c *client) wikiPageExists(ctx context.Context, name string) (bool, error) {
	u := c.repoAPI() + "/wiki/page/" + url.PathEscape(name)
	req, err := c.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	return false, synccore.HTTPError("forgejo", resp)
}

// readVaultMarkdown reads a vault markdown file and strips YAML frontmatter so
// the wiki renders clean content.
func readVaultMarkdown(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return stripFrontmatter(string(data)), nil
}

// stripFrontmatter removes a leading YAML frontmatter block ("---\n…\n---\n").
func stripFrontmatter(s string) string {
	if !strings.HasPrefix(s, "---\n") && !strings.HasPrefix(s, "---\r\n") {
		return s
	}
	for _, marker := range []string{"\n---\n", "\n---\r\n"} {
		if idx := strings.Index(s[3:], marker); idx >= 0 {
			return strings.TrimLeft(s[3+idx+len(marker):], "\r\n")
		}
	}
	return s
}

// titleCaseWord upper-cases the first rune of a single word ("definitions" →
// "Definitions") for readable wiki subpage prefixes.
func titleCaseWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
