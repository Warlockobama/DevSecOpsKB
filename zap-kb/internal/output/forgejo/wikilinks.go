package forgejo

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Vault markdown links target FILES (relative paths, often with .md); the
// published wiki addresses PAGES (renamed, hierarchical, no extension).
// rewriteVaultLinks converts every internal link whose target resolves to a
// published page into a standard markdown link to that page; anything that
// does not resolve (external URLs, images, unpublished files) is left
// untouched, so a partial vault never produces broken rewrites.
//
// Live-server caveat: url.PathEscape produces "Findings%2Ffin-1"-style targets.
// The Forgejo/Gitea web UI is expected to resolve these against
// /{owner}/{repo}/wiki/, but server-side sub_url generation has known quirks
// (see the comment above listWikiPages). If escaped hierarchical links 404 on a
// real server, the fallback is a two-pass publish (upsert, re-list to obtain
// server sub_urls, rewrite with those, PATCH changed pages) — file an issue
// rather than implementing it speculatively.

var (
	// [[target]] or [[target|alias]] — Obsidian wikilink.
	wikilinkRe = regexp.MustCompile(`\[\[([^\]|]+)(?:\|([^\]]+))?\]\]`)
	// [text](target.md) or [text](target.md#frag) — markdown link to a vault file.
	mdLinkRe = regexp.MustCompile(`(\[[^\]]*\])\(([^)#\s]+\.md)(#[^)\s]*)?\)`)
)

// rewriteVaultLinks rewrites the internal links of one vault file's content.
// relDir is the file's directory relative to the vault root ("." for top-level
// files); pageNames maps vault-relative file paths to wiki page names (see
// ExportWiki).
func rewriteVaultLinks(content, relDir string, pageNames map[string]string) string {
	resolve := func(target string) (string, bool) {
		target = strings.TrimSpace(target)
		if target == "" || strings.Contains(target, "://") {
			return "", false
		}
		// Vault links appear in two flavors: vault-root-relative (Obsidian
		// wikilinks like "findings/fin-1.md", emitted with the leading dirs
		// pre-collapsed) and file-relative (standard md links like "../INDEX.md").
		// Try root-relative first, then relative to the linking file's directory;
		// accept whichever names a published page. Wikilinks may omit ".md".
		for _, cand := range []string{path.Clean(target), path.Clean(path.Join(relDir, target))} {
			if name, ok := pageNames[cand]; ok {
				return url.PathEscape(name), true
			}
			if !strings.HasSuffix(cand, ".md") {
				if name, ok := pageNames[cand+".md"]; ok {
					return url.PathEscape(name), true
				}
			}
		}
		return "", false
	}

	out := wikilinkRe.ReplaceAllStringFunc(content, func(m string) string {
		sub := wikilinkRe.FindStringSubmatch(m)
		target, frag := sub[1], ""
		if i := strings.Index(target, "#"); i >= 0 {
			target, frag = target[:i], target[i:]
		}
		esc, ok := resolve(target)
		if !ok {
			return m
		}
		alias := strings.TrimSpace(sub[2])
		if alias == "" {
			alias = strings.TrimSuffix(path.Base(strings.TrimSpace(target)), ".md")
		}
		return "[" + alias + "](" + esc + frag + ")"
	})
	return mdLinkRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := mdLinkRe.FindStringSubmatch(m)
		esc, ok := resolve(sub[2])
		if !ok {
			return m
		}
		return sub[1] + "(" + esc + sub[3] + ")"
	})
}
