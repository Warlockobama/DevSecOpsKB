# Workstream 04 — Wiki Navigation

Read `00-OVERVIEW.md` first. Run after Workstream 02 (no hard code dependency,
but keeps merges clean).
All files below are under `zap-kb/` unless stated otherwise.

Two problems in `internal/output/forgejo/wiki.go`:

- **D9 (broken cross-links)**: `ExportWiki` renames pages on upload
  (`INDEX.md` → `Home`, `triage-board.md` → `Triage Board`,
  `findings/<id>.md` → `Findings/<id>`, …) but pushes file content verbatim.
  Every internal vault link — `[Triage board](triage-board.md)`,
  `[[definitions/def-x.md|Title]]`, `[[occurrences/../findings/fin-x.md|fin-x]]`,
  `[[tuning-candidates|Tuning Candidates]]` — still references the *file*
  names, so navigating the published wiki 404s. Links must be rewritten to the
  page names at publish time.
- **I5 (no pruning)**: the wiki only upserts. Pages for findings/occurrences
  that no longer exist in the KB accumulate forever. (The Obsidian sink
  already prunes — see `internal/output/obsidian/prune.go` for the precedent.)

## Background you need

- The vault is a directory of markdown files: top-level files (`INDEX.md`,
  `DASHBOARD.md`, …) plus three subdirs `definitions/`, `findings/`,
  `occurrences/` of one file per entity.
- Vault links come in two syntaxes, both with **forward-slash relative paths**
  (relative to the *linking file's directory*), optionally with a `#fragment`,
  and the wikilink form sometimes omits the `.md` suffix:
  - Obsidian wikilinks: `[[target|alias]]` or `[[target]]`
  - Standard markdown: `[text](target.md)` / `[text](target.md#frag)`
- Wiki page names: the table `topLevelWikiPages` and `wikiSubdirs` in
  `wiki.go` define the renaming. Hierarchical page names contain `/`
  (`Findings/fin-x`); in a link URL the `/` must be percent-encoded (`%2F`),
  which is what `url.PathEscape` produces.

## Task 1 — Build a relpath → page-name index in `ExportWiki`

In `ExportWiki`, the loop that collects `pages` already computes each page's
vault-relative file path and page name. Capture them in a map while doing so:

```go
pageNames := make(map[string]string) // vault-relative forward-slash path → wiki page name
```

- Top-level loop: `pageNames[tp.file] = tp.page`
- Subdir loop: `pageNames[sub+"/"+e.Name()] = name`

Also extend the `page` struct with the file's directory relative to the vault
root (`relDir string`): `"."` for top-level pages, `sub` for subdir pages.
Populate it in both loops.

## Task 2 — The link rewriter

New file: `internal/output/forgejo/wikilinks.go`. Full implementation —
copy as written (imports: `net/url`, `path`, `regexp`, `strings`):

```go
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

var (
	// [[target]] or [[target|alias]] — Obsidian wikilink.
	wikilinkRe = regexp.MustCompile(`\[\[([^\]|]+)(?:\|([^\]]+))?\]\]`)
	// [text](target.md) or [text](target.md#frag) — markdown link to a vault file.
	mdLinkRe = regexp.MustCompile(`(\[[^\]]*\])\(([^)#\s]+\.md)(#[^)\s]*)?\)`)
)

// rewriteVaultLinks rewrites the internal links of one vault file's content.
// relDir is the file's directory relative to the vault root ("." for
// top-level files); pageNames maps vault-relative file paths to wiki page
// names (see ExportWiki).
func rewriteVaultLinks(content, relDir string, pageNames map[string]string) string {
	resolve := func(target string) (string, bool) {
		target = strings.TrimSpace(target)
		if target == "" || strings.Contains(target, "://") {
			return "", false
		}
		// Vault links come in two flavors: vault-root-relative (Obsidian
		// wikilinks like "findings/fin-1.md" — obsidian.go emits these with the
		// leading dirs already collapsed via filepath.Join) and file-relative
		// (standard md links like "../INDEX.md"). Try root-relative first, then
		// relative to the linking file's dir; accept whichever names a page.
		for _, cand := range []string{path.Clean(target), path.Clean(path.Join(relDir, target))} {
			if name, ok := pageNames[cand]; ok {
				return url.PathEscape(name), true
			}
			if !strings.HasSuffix(cand, ".md") {
				if name, ok := pageNames[cand+".md"]; ok { // wikilinks may omit .md
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
```

Wire it in `ExportWiki`: everywhere a page's content is produced
(`readVaultMarkdown(p.path)` — the canary block AND the parallel loop), follow
with:

```go
content = rewriteVaultLinks(content, p.relDir, pageNames)
```

The idempotency property (`upsertWikiPage` compares remote content) is
preserved automatically because the rewrite is deterministic.

## Task 3 — Pruning stale entity pages

### 3a. Sink side

File: `internal/output/forgejo/wiki.go`.

- Add to `WikiOptions`: `Prune bool // delete KB-owned entity pages absent from this publish`.
- Add to `WikiSummary`: `Pruned int`.
- Add a method (model the request on `closeIssue` in `issues.go` — DELETE has
  no body):

```go
// deleteWikiPage removes a wiki page via its server-issued sub_url.
func (c *client) deleteWikiPage(ctx context.Context, subURL string) error
// DELETE {repoAPI}/wiki/page/{subURL}; use synccore.DoWithRetry + drain.
```

- At the end of `ExportWiki`, after `wg.Wait()` and only when
  `opts.Prune` is true: walk the **pre-publish** `existing` map (title →
  sub_url, fetched before any upsert; pages created this run are by definition
  current, so the pre-publish snapshot is exactly the candidate set). Delete
  every page whose title starts with `Definitions/`, `Findings/`, or
  `Occurrences/` **and** is not a page name published this run. Only those
  three prefixes are KB-owned by convention — never delete anything else
  (`Home`, analyst-authored pages, …). Iterate in sorted title order
  (determinism). On delete error: `summary.Errors++`, log with the existing
  `fmt.Printf("[forgejo wiki] …")` style, continue. On success:
  `summary.Pruned++`.
- Build the "published this run" set from the `pages` slice **before** the
  canary block consumes `pages[0]` (the canary mutates the slice — take the
  set first).

### 3b. CLI side

File: `cmd/zap-kb/main.go`. Find the existing Forgejo flag block
(`grep -n "forgejo-wiki" cmd/zap-kb/main.go`). Add alongside it:

```go
forgejoWikiPrune := flag.Bool("forgejo-wiki-prune", false, "delete KB-owned Forgejo wiki pages (Definitions/Findings/Occurrences) that are absent from the current publish")
```

Thread it: `forgejoPublishOptions` in `cmd/zap-kb/forgejo_sync.go` gets
`WikiPrune bool`; `runForgejoPublish` passes `Prune: opts.WikiPrune` in the
`forgejo.WikiOptions` literal; the call site in `main.go` that fills
`forgejoPublishOptions` sets `WikiPrune: *forgejoWikiPrune`. Extend the wiki
summary print with `pruned=%d`.

Default is **off** — pruning deletes remote content; operators opt in.

## Tests (required)

File: `internal/output/forgejo/wikilinks_test.go` (new):

1. `TestRewriteVaultLinks_Table` — single table test over one `pageNames`
   fixture: `{"INDEX.md": "Home", "triage-board.md": "Triage Board",
   "definitions/def-1.md": "Definitions/def-1", "findings/fin-1.md":
   "Findings/fin-1", "tuning-candidates.md": "Tuning Candidates"}`. Cases
   (input content, relDir, expected output):
   | content | relDir | expected |
   |---|---|---|
   | `[Triage board](triage-board.md)` | `.` | `[Triage board](Triage%20Board)` |
   | `[[definitions/def-1.md\|XSS]]` | `.` | `[XSS](Definitions%2Fdef-1)` |
   | `[[findings/fin-1.md\|fin-1]]` (root-relative, as obsidian.go emits) | `occurrences` | `[fin-1](Findings%2Ffin-1)` |
   | `[[../INDEX.md#issues\|see full list]]` | `findings` | `[see full list](Home#issues)` |
   | `[[tuning-candidates\|Tuning Candidates]]` | `.` | `[Tuning Candidates](Tuning%20Candidates)` |
   | `[[findings/fin-1.md]]` | `.` | `[fin-1](Findings%2Ffin-1)` |
   | `[ext](https://example.com/a.md)` | `.` | unchanged |
   | `[gone](missing.md)` | `.` | unchanged |
2. `TestRewriteVaultLinks_Idempotent` — rewriting the output of case 2 again
   yields the same string.

File: `internal/output/forgejo/forgejo_test.go` (extend, using the existing
wiki stub-server pattern):

3. `TestExportWiki_RewritesLinks` — vault with `INDEX.md` containing
   `[Triage board](triage-board.md)` plus `triage-board.md`. Assert the
   uploaded (base64-decoded) Home content contains `](Triage%20Board)` and not
   `](triage-board.md)`.
4. `TestExportWiki_PruneDeletesStaleEntityPages` — stub server lists existing
   pages `Findings/fin-old` and `Home`; vault publishes only `INDEX.md`.
   With `Prune: true` assert exactly one DELETE (for `Findings/fin-old`'s
   sub_url), `Pruned == 1`, and no DELETE for `Home`. With `Prune: false`
   assert zero DELETEs. NOTE: read the deleted sub_url from `r.RequestURI`, not
   `r.URL.Path` — net/http decodes the `%2F` in the escaped sub_url back to `/`
   on `r.URL.Path`, so the last path segment would read `fin-old` instead of
   `Findings%2Ffin-old`.

## Live-server caveat (record, don't solve)

`url.PathEscape(pageName)` produces `Findings%2Ffin-1`-style relative link
targets. The Forgejo/Gitea web UI is expected to resolve these against
`/{owner}/{repo}/wiki/`, but server-side sub_url generation has known quirks
(see the comment block above `listWikiPages`). After this lands, whoever runs
the next live deployment must click through Home → a finding → its definition
on the real server. If escaped links 404 there, the fallback design is a
two-pass publish (upsert pages, re-list to obtain server sub_urls, rewrite
with those, PATCH changed pages) — file an issue rather than implementing it
speculatively. Add this caveat as a short comment above `rewriteVaultLinks`.

## Acceptance checklist

- [ ] `pageNames` index and `relDir` captured in `ExportWiki`.
- [ ] `rewriteVaultLinks` exists as specified and is applied to canary + parallel paths.
- [ ] Prune deletes only `Definitions/`/`Findings/`/`Occurrences/` pages, only when `-forgejo-wiki-prune` is set.
- [ ] CLI flag threaded end-to-end; wiki summary prints `pruned=`.
- [ ] Tests 1–4 pass; full suite green; `gofmt -l .` empty.
- [ ] Commit: `git commit -s -m "fix(forgejo): rewrite vault links to wiki page names; add opt-in wiki pruning"`

## Out of scope

Issue rendering (02), pull (03), redaction (05). Do not change the Obsidian
sink's link generation — the vault must keep working locally in Obsidian;
rewriting is strictly a publish-time transform.
