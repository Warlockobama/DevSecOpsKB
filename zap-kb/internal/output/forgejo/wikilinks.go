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
// published page into a standard markdown link to that page. Links that do
// NOT resolve are degraded to their plain display text: Forgejo does not
// render Obsidian [[wikilinks]], and a markdown link to an unpublished .md
// file 404s on the wiki — literal link syntax or a dead link would both read
// as breakage to analysts. External URLs and embeds are left untouched.
//
// linkFor maps a wiki page name to the URL token used in the rewritten link.
// Pass escapePageName for a best-effort first publish; pass a server-issued
// sub_url lookup for the repair pass (see ExportWiki) — server-side page-name
// escaping is not guaranteed to match url.PathEscape, so only the sub_url is
// authoritative.

var (
	// [[target]] or [[target|alias]] — Obsidian wikilink. A leading "!" marks
	// an embed, which is preserved verbatim.
	wikilinkRe = regexp.MustCompile(`(!?)\[\[([^\]|]+)(?:\|([^\]]+))?\]\]`)
	// [text](target.md) or [text](target.md#frag) — markdown link to a vault file.
	mdLinkRe = regexp.MustCompile(`(\[[^\]]*\])\(([^)#\s]+\.md)(#[^)\s]*)?\)`)
)

// escapePageName is the default linkFor: client-side escaping of the page
// name, matching what the Forgejo web UI uses for same-wiki relative links.
func escapePageName(name string) string {
	return url.PathEscape(name)
}

// rewriteVaultLinks rewrites the internal links of one vault file's content.
// relDir is the file's directory relative to the vault root ("." for top-level
// files); pageNames maps vault-relative file paths to wiki page names (see
// ExportWiki); linkFor maps a resolved page name to its link target.
func rewriteVaultLinks(content, relDir string, pageNames map[string]string, linkFor func(string) string) string {
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
				return linkFor(name), true
			}
			if !strings.HasSuffix(cand, ".md") {
				if name, ok := pageNames[cand+".md"]; ok {
					return linkFor(name), true
				}
			}
		}
		return "", false
	}

	out := wikilinkRe.ReplaceAllStringFunc(content, func(m string) string {
		sub := wikilinkRe.FindStringSubmatch(m)
		if sub[1] == "!" {
			return m // embed — not a navigation link
		}
		target, frag := sub[2], ""
		if i := strings.Index(target, "#"); i >= 0 {
			target, frag = target[:i], target[i:]
		}
		alias := strings.TrimSpace(sub[3])
		if alias == "" {
			alias = strings.TrimSuffix(path.Base(strings.TrimSpace(target)), ".md")
		}
		esc, ok := resolve(target)
		if !ok {
			return alias // unpublished target — plain text beats literal [[..]]
		}
		// Square brackets in the alias would nest link syntax in the rendered
		// markdown ("[a [b](x)]") — swap for parentheses.
		alias = strings.NewReplacer("[", "(", "]", ")").Replace(alias)
		return "[" + alias + "](" + esc + frag + ")"
	})
	return mdLinkRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := mdLinkRe.FindStringSubmatch(m)
		if strings.Contains(sub[2], "://") {
			return m // external URL that happens to end in .md
		}
		esc, ok := resolve(sub[2])
		if !ok {
			// Unpublished vault file — degrade to the display text.
			return strings.TrimSuffix(strings.TrimPrefix(sub[1], "["), "]")
		}
		return sub[1] + "(" + esc + sub[3] + ")"
	})
}
