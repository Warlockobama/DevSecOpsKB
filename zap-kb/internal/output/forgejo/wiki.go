package forgejo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
	Prune         bool   // delete KB-owned entity pages absent from this publish
}

// WikiSummary reports what the wiki export did.
type WikiSummary struct {
	Created int
	Updated int
	Skipped int
	Errors  int
	Pruned  int
	// LinkFixes counts pages re-PATCHed by the second pass because the
	// server-issued sub_url for a linked page differed from the client-side
	// escaping used on first publish.
	LinkFixes int
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
	// Section pages split out of INDEX — Home's quick-navigation links target
	// these, so omitting them leaves dead links on the wiki landing page.
	{"issues.md", "Issues"},
	{"occurrences.md", "Occurrences"},
	{"rules.md", "Rules"},
}

// wikiSubdirs are the entity directories nested as wiki subpages. Slashes in the
// page name render as a hierarchy in Forgejo.
var wikiSubdirs = []string{"definitions", "findings", "occurrences"}

// ExportWiki walks the generated Obsidian vault at vaultRoot and upserts each
// markdown file as a Forgejo wiki page (frontmatter stripped — no XHTML
// conversion). Forgejo renders plain markdown but NOT Obsidian [[wikilinks]],
// so internal links are rewritten to standard markdown links between wiki
// pages (see rewriteVaultLinks). Publishing is two-pass: pages are upserted
// with link targets taken from the pre-publish listing's server-issued
// sub_urls (client-side escaping only for pages that don't exist yet), then
// the page list is re-fetched and any page whose links differ under the
// post-publish sub_urls is PATCHed — the server's page-name escaping is the
// only authoritative source for addressing hierarchical titles
// ("Findings/fin-1"), and rendering with known sub_urls up front keeps
// steady-state re-publishes byte-identical (skipped, no git churn). Pages are
// upserted in parallel up to opts.Concurrency.
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

	// Preflight: a repo without its wiki enabled 404s every wiki call, which
	// would otherwise surface as N per-page errors. Fail hard with a clear
	// message instead so operators fix the repo settings once. Also repairs an
	// unset wiki_branch (see ensureWikiReady) — without it every wiki write
	// "fails" with 404 even though the content was committed.
	if !opts.DryRun {
		if err := c.ensureWikiReady(ctx); err != nil {
			return WikiSummary{}, fmt.Errorf("forgejo wiki: %w", err)
		}
	}

	// Collect (pageName → file path) for every page to publish. pageNames maps
	// each vault-relative file path to its published wiki page name, so internal
	// links (which target FILE names) can be rewritten to PAGE names below.
	type page struct {
		name   string
		path   string
		relDir string // file's dir relative to vaultRoot ("." for top-level)
	}
	var pages []page
	pageNames := make(map[string]string)
	for _, tp := range topLevelWikiPages {
		p := filepath.Join(vaultRoot, tp.file)
		if _, err := os.Stat(p); err == nil {
			pages = append(pages, page{name: tp.page, path: p, relDir: "."})
			pageNames[tp.file] = tp.page
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
			pages = append(pages, page{name: name, path: filepath.Join(dir, e.Name()), relDir: sub})
			pageNames[sub+"/"+e.Name()] = name
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].name < pages[j].name })

	// Snapshot the full page set BEFORE the canary consumes pages[0]: the prune
	// pass needs the published names, and the link-repair pass revisits every
	// page.
	allPages := append([]page(nil), pages...)
	publishedNames := make(map[string]bool, len(pages))
	for _, p := range pages {
		publishedNames[p.name] = true
	}

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

	// Discover existing pages once. Pages are addressed by the SERVER-issued
	// sub_url token, never by client-side escaping of the title: page names
	// containing '/' (our Findings/… hierarchy) round-trip through an escaping
	// scheme ("Findings%2Ffin-1.-") that url.PathEscape cannot reproduce, so
	// guessing the URL makes every existence probe 404 and every re-publish
	// collide with "wiki page already exists".
	existing, err := c.listWikiPages(ctx)
	if err != nil {
		if isWikiBranchBug(err) {
			return summary, fmt.Errorf("forgejo wiki: %s: %w", wikiBranchBugAdvice, err)
		}
		return summary, fmt.Errorf("forgejo wiki: list pages: %w", err)
	}

	// Render links with the server-issued sub_urls already known from the
	// pre-publish listing, falling back to client-side escaping for pages that
	// do not exist yet. On a steady-state re-publish every link target is a
	// known sub_url, so rendered content matches the remote byte-for-byte and
	// the upsert skips — using PathEscape here would diff against the repaired
	// remote content and churn the wiki's git history on every run.
	linkFor := func(name string) string {
		if su := existing[name]; su != "" {
			return su
		}
		return escapePageName(name)
	}

	// Canary: publish the first page serially. A server hit by the Gitea 1.22
	// wiki_branch bug fails EVERY write the same way — one descriptive hard
	// error beats N identical per-page 404s, and aborting here avoids
	// committing further unreadable content.
	if len(pages) > 0 {
		p := pages[0]
		pages = pages[1:]
		content, err := readVaultMarkdown(p.path)
		if err != nil {
			summary.Errors++
			fmt.Printf("[forgejo wiki] error reading %s: %v\n", p.path, err)
		} else {
			content = rewriteVaultLinks(content, p.relDir, pageNames, linkFor)
			action, err := c.upsertWikiPage(ctx, p.name, content, msg, existing)
			switch {
			case isWikiBranchBug(err):
				return summary, fmt.Errorf("forgejo wiki: %s: %w", wikiBranchBugAdvice, err)
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
		}
	}

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
			content = rewriteVaultLinks(content, p.relDir, pageNames, linkFor)
			action, err := c.upsertWikiPage(ctx, p.name, content, msg, existing)
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

	// Pass 2: link repair. Re-list to obtain server-issued sub_urls for the
	// pages just created, re-render every page's links against those tokens,
	// and PATCH the pages whose content changed. On servers whose page-name
	// escaping matches url.PathEscape this finds nothing and costs one listing
	// call; on servers with a divergent scheme it is the only way hierarchical
	// cross-links ("Findings/fin-1") resolve instead of 404ing.
	subURLs, lerr := c.listWikiPages(ctx)
	if lerr != nil {
		summary.Errors++
		fmt.Printf("[forgejo wiki] error listing pages for link repair (links may use client-side escaping): %v\n", lerr)
	} else {
		linkForSub := func(name string) string {
			if su := subURLs[name]; su != "" {
				return su
			}
			return escapePageName(name)
		}
		for _, p := range allPages {
			su := subURLs[p.name]
			if su == "" {
				continue // page never landed; already counted as an error
			}
			raw, rerr := readVaultMarkdown(p.path)
			if rerr != nil {
				continue // unreadable file was already counted in pass 1
			}
			pass1 := rewriteVaultLinks(raw, p.relDir, pageNames, linkFor)
			pass2 := rewriteVaultLinks(raw, p.relDir, pageNames, linkForSub)
			if pass2 == pass1 {
				continue
			}
			if perr := c.patchWikiPage(ctx, su, p.name, pass2, msg); perr != nil {
				summary.Errors++
				fmt.Printf("[forgejo wiki] error repairing links on %q: %v\n", p.name, perr)
				continue
			}
			summary.LinkFixes++
		}
	}

	// Prune stale KB-owned entity pages. Only the three entity prefixes are
	// KB-managed by convention; Home and any analyst-authored page are never
	// touched. Candidates come from the pre-publish listing (pages created this
	// run are current by definition). Sorted for deterministic output.
	if opts.Prune {
		var stale []string
		for title := range existing {
			if !publishedNames[title] && isEntityWikiPage(title) {
				stale = append(stale, title)
			}
		}
		sort.Strings(stale)
		for _, title := range stale {
			if derr := c.deleteWikiPage(ctx, existing[title]); derr != nil {
				summary.Errors++
				fmt.Printf("[forgejo wiki] error pruning %q: %v\n", title, derr)
				continue
			}
			summary.Pruned++
			fmt.Printf("[forgejo wiki] pruned stale page %q\n", title)
		}
	}
	return summary, nil
}

// isEntityWikiPage reports whether a wiki page title is one of the KB-owned
// entity pages (safe to prune). Matches the wikiSubdirs hierarchy prefixes.
func isEntityWikiPage(title string) bool {
	return strings.HasPrefix(title, "Definitions/") ||
		strings.HasPrefix(title, "Findings/") ||
		strings.HasPrefix(title, "Occurrences/")
}

// deleteWikiPage removes a wiki page via its server-issued sub_url.
func (c *client) deleteWikiPage(ctx context.Context, subURL string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, c.repoAPI()+"/wiki/page/"+subURL, nil)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// wikiBranchBugAdvice is the operator guidance attached to the hard error for
// the server-side Gitea 1.22 wiki breakage.
const wikiBranchBugAdvice = "server rejected the wiki operation with the Gitea 1.22 wiki_branch bug (writes commit but are unreadable; client-side repair is impossible) — upgrade the server to Gitea >= 1.23 / Forgejo, or initialize the wiki once via the web UI"

// listWikiPages returns title → server-issued sub_url for every existing wiki
// page. The sub_url is the only reliable way to address a page whose title
// contains characters the server escapes (e.g. '/').
func (c *client) listWikiPages(ctx context.Context) (map[string]string, error) {
	out := make(map[string]string)
	page := 1
	for {
		u := fmt.Sprintf("%s/wiki/pages?limit=50&page=%d", c.repoAPI(), page)
		req, err := c.newRequest(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := synccore.DoWithRetryRaw(c.http, req, 3)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			// No wiki repo yet — nothing published before.
			drain(resp)
			return out, nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := synccore.HTTPError("forgejo", resp)
			drain(resp)
			return nil, err
		}
		var batch []struct {
			Title  string `json:"title"`
			SubURL string `json:"sub_url"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode wiki pages: %w", err)
		}
		resp.Body.Close()
		// Progress-based termination (see listFindingIssues): stop when a page
		// adds no page titles we have not already seen. Robust to servers that
		// cap `limit` below 50 and to servers that ignore `page`.
		added := 0
		for _, p := range batch {
			if p.Title == "" || p.SubURL == "" {
				continue
			}
			if _, ok := out[p.Title]; !ok {
				added++
			}
			out[p.Title] = p.SubURL
		}
		if added == 0 {
			return out, nil
		}
		page++
		if page > 1000 {
			return nil, fmt.Errorf("forgejo: wiki-page pagination exceeded 1000 pages — aborting (server ignoring page param?)")
		}
	}
}

// upsertWikiPage creates the wiki page, updates it when the content changed, or
// skips it when the remote content is already identical. Returns "created",
// "updated", or "skipped". existing maps page titles to server-issued sub_urls
// (from listWikiPages). The remote-content compare keeps re-publishes
// idempotent without local state — important because the publisher runs in
// ephemeral pods where a local hash cache would not survive between runs.
func (c *client) upsertWikiPage(ctx context.Context, name, content, message string, existing map[string]string) (string, error) {
	subURL, exists := existing[name]
	if exists {
		remote, err := c.getWikiPageBySubURL(ctx, subURL)
		if err != nil {
			return "", err
		}
		if remote == content {
			return "skipped", nil
		}
	}
	if exists {
		if err := c.patchWikiPage(ctx, subURL, name, content, message); err != nil {
			return "", err
		}
		return "updated", nil
	}

	body, err := json.Marshal(map[string]string{
		"title":          name,
		"content_base64": base64.StdEncoding.EncodeToString([]byte(content)),
		"message":        message,
	})
	if err != nil {
		return "", err
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

// patchWikiPage overwrites a wiki page's content via its server-issued
// sub_url (already escaped — appended verbatim).
func (c *client) patchWikiPage(ctx context.Context, subURL, title, content, message string) error {
	body, err := json.Marshal(map[string]string{
		"title":          title,
		"content_base64": base64.StdEncoding.EncodeToString([]byte(content)),
		"message":        message,
	})
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPatch, c.repoAPI()+"/wiki/page/"+subURL, body)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// getWikiPageBySubURL fetches a wiki page's decoded content via its
// server-issued sub_url (appended verbatim — it is already escaped). Returns
// "" (without error) when the body cannot be decoded, so the caller falls
// through to a PATCH rather than failing the publish.
func (c *client) getWikiPageBySubURL(ctx context.Context, subURL string) (string, error) {
	u := c.repoAPI() + "/wiki/page/" + subURL
	req, err := c.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := synccore.DoWithRetryRaw(c.http, req, 3)
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		// Listed a moment ago but gone now (concurrent delete) — treat as
		// unknown content so the caller PATCHes/creates rather than erroring.
		return "", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", synccore.HTTPError("forgejo", resp)
	}
	var page struct {
		ContentBase64 string `json:"content_base64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return "", nil
	}
	decoded, err := base64.StdEncoding.DecodeString(page.ContentBase64)
	if err != nil {
		return "", nil
	}
	return string(decoded), nil
}

// ensureWikiReady verifies the target repository exists with its wiki enabled.
func (c *client) ensureWikiReady(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, c.repoAPI(), nil)
	if err != nil {
		return err
	}
	resp, err := synccore.DoWithRetryRaw(c.http, req, 3)
	if err != nil {
		return fmt.Errorf("preflight repo check: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("repository %s/%s not found", c.owner, c.repo)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return synccore.HTTPError("forgejo", resp)
	}
	var repo struct {
		HasWiki bool `json:"has_wiki"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		return fmt.Errorf("decode repo: %w", err)
	}
	if !repo.HasWiki {
		return fmt.Errorf("wiki is not enabled on %s/%s — enable it in repo settings (has_wiki) or via PATCH /repos/%s/%s", c.owner, c.repo, c.owner, c.repo)
	}
	return nil
}

// isWikiBranchBug recognizes the Gitea 1.22 server bug where the wiki REST API
// is unusable on API-created repos (wiki_branch column NULL): writes commit
// but every read — including the write API's own post-write re-read — 404s
// with "object does not exist [id: refs/heads/<branch>]". Attempting to PATCH
// wiki_branch is a silent no-op on affected servers, so there is no
// client-side repair; the only fixes are a server upgrade (Gitea >= 1.23,
// Forgejo) or initializing the wiki once via the web UI.
func isWikiBranchBug(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "http 404") && strings.Contains(msg, "refs/heads/")
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
