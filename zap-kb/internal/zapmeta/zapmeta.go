package zapmeta

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Result holds detection metadata scraped from ZAP docs and inferred paths.
type Result struct {
	LogicType   string   // passive|active|unknown
	PluginRef   string   // add-on or rule ref if known
	RuleSource  string   // repo-like path (zap-extensions/addOns/<addon>/src/main/java/.../Class.java)
	DocsURL     string   // https://www.zaproxy.org/docs/alerts/{id}/
	SourceURL   string   // GitHub blob URL for the class
	MatchReason string   // how we matched
	AlertTitle  string   // Human-readable alert title from docs
	References  []string // External references listed in the docs page
}

// ScrapeDetection best-effort scrapes ZAP alert docs for a plugin id and identifies
// the implementing Java class path and logic type. Network failures return (nil, nil).
func ScrapeDetection(ctx context.Context, pluginID string) (*Result, error) {
	pid := strings.TrimLeft(strings.TrimSpace(pluginID), "0")
	if pid == "" {
		return nil, nil
	}
	docsURL := fmt.Sprintf("https://www.zaproxy.org/docs/alerts/%s/", pid)

	// HTTP client with short timeout
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, docsURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; zap-kb/0.1; +https://github.com/devsecopsidian)")
	hc := &http.Client{Timeout: 20 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil // best-effort only
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
	html := string(body)

	// Extract alert title for display
	title := scrapeAlertTitle(html)

	// Strategy 1: look for a repo-like path to a Java source file
	// e.g., zap-extensions/addOns/pscanrules/src/main/java/.../Class.java
	var repoPath, blobURL string
	reRepo := regexp.MustCompile(`(?i)(zap-extensions/[^\s"']*?/src/main/java/[^\s"']*?\.java)`) // repo path (may include blob/main)
	if m := reRepo.FindStringSubmatch(html); len(m) == 2 {
		repoPath = normalizeRepoPath(m[1])
		blobURL = toGitHubBlobURL(repoPath)
	} else {
		// Strategy 2: look for a direct GitHub blob URL then normalize to repo-like path
		reBlob := regexp.MustCompile(`https://github.com/zaproxy/zap-extensions/blob/[^\s"']*?/addOns/[^\s"']*?/src/main/java/[^\s"']*?\.java`)
		if m := reBlob.FindStringSubmatch(html); len(m) >= 1 {
			blob := m[0]
			blobURL = blob
			if i := strings.Index(blob, "/addOns/"); i >= 0 {
				path := blob[i+1:]
				repoPath = normalizeRepoPath("zap-extensions/" + path)
			}
		} else {
			// Strategy 3: community-scripts code link (not Java). Example:
			// https://github.com/zaproxy/community-scripts/blob/main/passive/clacks.js
			reCS := regexp.MustCompile(`https://github.com/zaproxy/community-scripts/blob/[^\s"']*?/(passive|active)/[^\s"']+`)
			if m := reCS.FindStringSubmatch(html); len(m) >= 1 {
				blob := m[0]
				blobURL = blob
				// Derive a repo-like path for display/reference, e.g., community-scripts/passive/clacks.js
				const prefix = "https://github.com/zaproxy/community-scripts/blob/"
				if strings.HasPrefix(blob, prefix) {
					rest := blob[len(prefix):]
					// Trim branch name (e.g., main/) if present
					if i := strings.Index(rest, "/"); i >= 0 {
						rest = rest[i+1:]
					}
					repoPath = "community-scripts/" + rest
				} else {
					repoPath = "community-scripts"
				}
			} else {
				// Strategy 4: other add-on repos (org may vary), e.g.,
				// https://github.com/SasanLabs/owasp-zap-fileupload-addon/blob/main/src/main/java/.../FileUploadScanRule.java
				reOther := regexp.MustCompile(`https://github.com/[^/]+/(owasp-zap-[^/]+)/blob/[^\s"']*?/src/main/java/[^\s"']*?\.java`)
				if m := reOther.FindStringSubmatch(html); len(m) >= 1 {
					blob := m[0]
					blobURL = blob
					repo := ""
					if len(m) >= 2 {
						repo = m[1]
					}
					// Build a repo-like path starting with repo name
					// Extract the path after "/blob/<branch>/"
					rest := ""
					const marker = "/blob/"
					if i := strings.Index(blob, marker); i >= 0 {
						rest = blob[i+len(marker):]
						if j := strings.Index(rest, "/"); j >= 0 {
							rest = rest[j+1:]
						}
					}
					if repo != "" && rest != "" {
						repoPath = repo + "/" + rest
					} else if repo != "" {
						repoPath = repo
					}
				}
			}
		}
	}

	// Try to infer logic type from docs sidebar if we did not get it from source path
	docLogic := inferLogicFromDocs(html)
	if repoPath == "" && blobURL == "" {
		// No strong signal to source; return docs info and title
		return &Result{LogicType: docLogic, PluginRef: "", RuleSource: "", DocsURL: docsURL, SourceURL: "", MatchReason: "No source reference in docs", AlertTitle: title}, nil
	}

	logic := "unknown"
	lp := strings.ToLower(repoPath)
	switch {
	case strings.Contains(lp, "pscanrules") || strings.Contains(lp, "pscan"):
		logic = "passive"
	case strings.Contains(lp, "ascanrules") || strings.Contains(lp, "ascan"):
		logic = "active"
	case strings.Contains(lp, "/passive/"):
		logic = "passive"
	case strings.Contains(lp, "/active/"):
		logic = "active"
	}
	if logic == "unknown" && docLogic != "" {
		logic = docLogic
	}

	// Extract add-on folder as pluginRef if present: addOns/<addon>/...
	pref := ""
	if i := strings.Index(repoPath, "/addOns/"); i >= 0 {
		rest := repoPath[i+len("/addOns/"):]
		if j := strings.Index(rest, "/"); j > 0 {
			pref = rest[:j]
		}
	} else if strings.HasPrefix(lp, "community-scripts/") || lp == "community-scripts" {
		pref = "community-scripts"
	}

	// Scrape references from docs (best-effort)
	refs := scrapeReferences(html)

	return &Result{
		LogicType:   logic,
		PluginRef:   pref,
		RuleSource:  repoPath,
		DocsURL:     docsURL,
		SourceURL:   blobURL,
		MatchReason: "Scraped from ZAP Alerts docs",
		AlertTitle:  title,
		References:  refs,
	}, nil
}

// toGitHubBlobURL converts a repo-like path to a GitHub blob URL in main branch.
func toGitHubBlobURL(repoPath string) string {
	p := normalizeRepoPath(repoPath)
	lp := strings.ToLower(p)
	if strings.HasPrefix(lp, "zap-extensions/addons/") {
		parts := strings.Split(p, "/")
		if len(parts) > 3 {
			repo := parts[2]
			rest := strings.Join(parts[3:], "/")
			return "https://github.com/zaproxy/zap-extensions/blob/main/addOns/" + repo + "/" + rest
		}
	}
	if strings.HasPrefix(lp, "community-scripts/") {
		// community-scripts/<passive|active>/path
		parts := strings.SplitN(p, "/", 2)
		tail := ""
		if len(parts) == 2 {
			tail = parts[1]
		}
		return "https://github.com/zaproxy/community-scripts/blob/main/" + tail
	}
	if strings.HasPrefix(lp, "owasp-zap-") {
		name := p
		if i := strings.Index(p, "/src/main/java/"); i > 0 {
			name = p[:i]
		}
		repo := name
		if i := strings.Index(repo, "/"); i >= 0 {
			repo = repo[:i]
		}
		return "https://github.com/zaproxy/" + repo + "/blob/main/" + p[len(repo)+1:]
	}
	return ""
}

// normalizeRepoPath removes GitHub blob segment if present and normalizes casing of addOns.
func normalizeRepoPath(p string) string {
	// drop "/blob/main/" if embedded
	p = strings.Replace(p, "/blob/main/", "/", 1)
	// unify addOns casing heuristically by replacing /addons/ with /addOns/
	// (we keep original otherwise)
	p = strings.Replace(p, "/addons/", "/addOns/", 1)
	// normalize community-scripts blob to path
	p = strings.Replace(p, "https://github.com/zaproxy/community-scripts/", "community-scripts/", 1)
	return p
}

// scrapeAlertTitle extracts a reasonable alert title from the HTML body.
func scrapeAlertTitle(html string) string {
	// Prefer H1
	re := regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)
	if m := re.FindStringSubmatch(html); len(m) == 2 {
		return strings.TrimSpace(stripTags(m[1]))
	}
	// Fallback to <title>
	re = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	if m := re.FindStringSubmatch(html); len(m) == 2 {
		return strings.TrimSpace(stripTags(m[1]))
	}
	return ""
}

// stripTags removes HTML tags for basic text extraction.
func stripTags(s string) string {
	re := regexp.MustCompile(`<[^>]+>`)
	return strings.TrimSpace(re.ReplaceAllString(s, " "))
}

// inferLogicFromDocs parses the docs details table for "Alert Type" row to infer active/passive.
func inferLogicFromDocs(html string) string {
	re := regexp.MustCompile(`(?is)<td>\s*<strong>\s*Alert\s*Type\s*</strong>\s*</td>\s*<td>\s*([^<]+)\s*</td>`)
	if m := re.FindStringSubmatch(html); len(m) == 2 {
		v := strings.ToLower(strings.TrimSpace(m[1]))
		if strings.Contains(v, "active") {
			return "active"
		}
		if strings.Contains(v, "passive") {
			return "passive"
		}
	}
	return ""
}

// scrapeReferences extracts external reference URLs from the ZAP docs page.
// It targets the <ul data-attr="references"> section and collects hrefs.
func scrapeReferences(html string) []string {
	// Find the references block
	reBlock := regexp.MustCompile(`(?is)<ul[^>]*data-attr\s*=\s*"references"[^>]*>(.*?)</ul>`)
	m := reBlock.FindStringSubmatch(html)
	if len(m) != 2 {
		return nil
	}
	block := m[1]
	// Extract all hrefs
	reHref := regexp.MustCompile(`href\s*=\s*"([^"]+)"`)
	var out []string
	seen := map[string]struct{}{}
	for _, h := range reHref.FindAllStringSubmatch(block, -1) {
		if len(h) == 2 {
			u := strings.TrimSpace(h[1])
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

// FetchRuleCode downloads the Java source for a rule either from SourceURL (GitHub blob)
// or by synthesizing a raw URL from RuleSource. Returns code string on success.
func FetchRuleCode(ctx context.Context, ruleSource, sourceURL string) (string, error) {
	raw := ""
	if strings.TrimSpace(sourceURL) != "" {
		raw = toRawGitURL(sourceURL)
	} else if strings.TrimSpace(ruleSource) != "" {
		raw = toRawGitURL(fromRuleSource(ruleSource))
	}
	if raw == "" {
		return "", nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; zap-kb/0.1; +https://github.com/devsecopsidian)")
	hc := &http.Client{Timeout: 20 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB
	return string(b), nil
}

// toRawGitURL converts a GitHub blob or http URL to raw.githubusercontent.com
func toRawGitURL(u string) string {
	// Examples:
	// https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/.../Class.java
	// -> https://raw.githubusercontent.com/zaproxy/zap-extensions/main/addOns/pscanrules/.../Class.java
	s := strings.TrimSpace(u)
	if strings.HasPrefix(s, "https://github.com/") {
		s = strings.Replace(s, "https://github.com/", "https://raw.githubusercontent.com/", 1)
		s = strings.Replace(s, "/blob/", "/", 1)
		return s
	}
	return s
}

// fromRuleSource maps a repo-like path to a GitHub blob URL on the main branch
func fromRuleSource(ruleSource string) string {
	p := normalizeRepoPath(ruleSource)
	lp := strings.ToLower(p)
	if strings.HasPrefix(lp, "zap-extensions/") {
		parts := strings.Split(p, "/")
		if len(parts) >= 3 {
			repo := parts[0]
			branch := "main"
			path := strings.Join(parts[1:], "/")
			return "https://github.com/zaproxy/" + repo + "/blob/" + branch + "/" + path
		}
	}
	if strings.HasPrefix(lp, "owasp-zap-") {
		// owasp-zap-xxx/addon/src/main/java/... -> assume zaproxy org
		idx := strings.Index(p, "/")
		if idx > 0 {
			repo := p[:idx]
			branch := "main"
			path := p[idx+1:]
			return "https://github.com/zaproxy/" + repo + "/blob/" + branch + "/" + path
		}
	}
	return ""
}

// RuleSummary holds heuristic extraction from a Java scan rule
type RuleSummary struct {
	Headers   []string
	Patterns  []string
	Evidence  bool
	Threshold string
	Strength  string
}

// SummarizeRule scans Java code for common ZAP rule heuristics
func SummarizeRule(code string) RuleSummary {
	var rs RuleSummary
	if strings.TrimSpace(code) == "" {
		return rs
	}
	// Headers like getHeader("X-Frame-Options")
	reHdr := regexp.MustCompile(`getHeader\(\s*"([^"]{1,60})"\s*\)`) // limit length
	seenH := map[string]struct{}{}
	for _, m := range reHdr.FindAllStringSubmatch(code, -1) {
		if len(m) == 2 {
			h := strings.TrimSpace(m[1])
			if h != "" {
				if _, ok := seenH[h]; !ok {
					rs.Headers = append(rs.Headers, h)
					seenH[h] = struct{}{}
				}
			}
		}
	}
	// Headers via HttpHeader constants (e.g., HttpHeader.X_CONTENT_TYPE_OPTIONS)
	reConst := regexp.MustCompile(`HttpHeader\.([A-Z_]{3,60})`)
	for _, m := range reConst.FindAllStringSubmatch(code, -1) {
		if len(m) == 2 {
			name := strings.TrimSpace(m[1])
			if name == "" {
				continue
			}
			hdr := strings.ReplaceAll(name, "_", "-")
			// Normalize casing: Title-Case tokens
			toks := strings.Split(strings.ToLower(hdr), "-")
			for i, t := range toks {
				if t != "" {
					toks[i] = strings.ToUpper(t[:1]) + t[1:]
				}
			}
			h := strings.Join(toks, "-")
			if _, ok := seenH[h]; !ok {
				rs.Headers = append(rs.Headers, h)
				seenH[h] = struct{}{}
			}
		}
	}
	// Patterns
	rePat := regexp.MustCompile(`Pattern\.compile\(\s*"([^"]{1,120})"`)
	for _, m := range rePat.FindAllStringSubmatch(code, -1) {
		if len(m) == 2 {
			rs.Patterns = append(rs.Patterns, m[1])
		}
	}
	// Evidence setters
	if strings.Contains(code, ".setEvidence(") || strings.Contains(code, "setEvidence(") {
		rs.Evidence = true
	}
	// Defaults: AlertThreshold / AttackStrength
	reThr := regexp.MustCompile(`AlertThreshold\.([A-Z_]+)`) // MEDIUM, HIGH, LOW
	if m := reThr.FindStringSubmatch(code); len(m) == 2 {
		rs.Threshold = strings.ToLower(m[1])
	}
	reStr := regexp.MustCompile(`AttackStrength\.([A-Z_]+)`) // e.g., MEDIUM
	if m := reStr.FindStringSubmatch(code); len(m) == 2 {
		rs.Strength = strings.ToLower(m[1])
	}
	return rs
}
