package zapmeta

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ListAllPluginIDs returns plugin IDs discovered from the ZAP Alerts index/sitemap.
// Best-effort; returns a deduplicated sorted list of numeric IDs as strings.
func ListAllPluginIDs(ctx context.Context) []string {
	base := "https://www.zaproxy.org"
	// Try index page first
	ids := extractFromAlertsIndex(ctx, base+"/docs/alerts/")
	if len(ids) == 0 {
		// Fallback to sitemap
		ids = extractFromSitemap(ctx, base+"/sitemap.xml")
	}
	sort.Strings(ids)
	return ids
}

func httpGet(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; zap-kb/0.1; +https://github.com/devsecopsidian)")
	hc := &http.Client{Timeout: 20 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", io.EOF
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), nil
}

func extractFromAlertsIndex(ctx context.Context, url string) []string {
	body, err := httpGet(ctx, url)
	if err != nil || strings.TrimSpace(body) == "" {
		return nil
	}
	// Links like href="/docs/alerts/10020/"
	re := regexp.MustCompile(`href=["'](/docs/alerts/([0-9]{2,6})/)["']`)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if len(m) == 3 {
			id := strings.TrimLeft(m[2], "0")
			if id == "" {
				id = m[2]
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func extractFromSitemap(ctx context.Context, url string) []string {
	body, err := httpGet(ctx, url)
	if err != nil || strings.TrimSpace(body) == "" {
		return nil
	}
	// Full URLs like https://www.zaproxy.org/docs/alerts/10020/
	re := regexp.MustCompile(`https?://[^\s<]*/docs/alerts/([0-9]{2,6})/`)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if len(m) == 2 {
			id := strings.TrimLeft(m[1], "0")
			if id == "" {
				id = m[1]
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}
