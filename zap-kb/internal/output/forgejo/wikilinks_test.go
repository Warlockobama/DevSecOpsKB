package forgejo

import "testing"

func wikiFixture() map[string]string {
	return map[string]string{
		"INDEX.md":             "Home",
		"triage-board.md":      "Triage Board",
		"definitions/def-1.md": "Definitions/def-1",
		"findings/fin-1.md":    "Findings/fin-1",
		"tuning-candidates.md": "Tuning Candidates",
	}
}

func TestRewriteVaultLinks_Table(t *testing.T) {
	pn := wikiFixture()
	cases := []struct {
		content string
		relDir  string
		want    string
	}{
		{"[Triage board](triage-board.md)", ".", "[Triage board](Triage%20Board)"},
		{"[[definitions/def-1.md|XSS]]", ".", "[XSS](Definitions%2Fdef-1)"},
		// Root-relative wikilink from an occurrence file (as obsidian.go emits).
		{"[[findings/fin-1.md|fin-1]]", "occurrences", "[fin-1](Findings%2Ffin-1)"},
		// File-relative md/wikilink with a fragment.
		{"[[../INDEX.md#issues|see full list]]", "findings", "[see full list](Home#issues)"},
		{"[[tuning-candidates|Tuning Candidates]]", ".", "[Tuning Candidates](Tuning%20Candidates)"},
		{"[[findings/fin-1.md]]", ".", "[fin-1](Findings%2Ffin-1)"},
		{"[ext](https://example.com/a.md)", ".", "[ext](https://example.com/a.md)"},
		// Unpublished targets degrade to plain text: Forgejo renders neither
		// literal [[wikilinks]] nor links to pages that don't exist.
		{"[gone](missing.md)", ".", "gone"},
		{"[[missing.md|Gone]]", ".", "Gone"},
		{"[[missing.md]]", ".", "missing"},
		// Embeds are not navigation links — leave them alone.
		{"![[missing.png]]", ".", "![[missing.png]]"},
	}
	for _, c := range cases {
		got := rewriteVaultLinks(c.content, c.relDir, pn, escapePageName)
		if got != c.want {
			t.Errorf("rewriteVaultLinks(%q, relDir=%q) = %q, want %q", c.content, c.relDir, got, c.want)
		}
	}
}

func TestRewriteVaultLinks_Idempotent(t *testing.T) {
	pn := wikiFixture()
	in := "[[definitions/def-1.md|XSS]]"
	once := rewriteVaultLinks(in, ".", pn, escapePageName)
	twice := rewriteVaultLinks(once, ".", pn, escapePageName)
	if once != twice {
		t.Fatalf("not idempotent: once=%q twice=%q", once, twice)
	}
}

// A wikilink inside a markdown table cell must never survive rewriting: the
// raw "|" inside [[link|alias]] would split the cell in any CommonMark
// renderer. Resolved links become standard md links; unresolved become text.
func TestRewriteVaultLinks_NoWikilinkSurvives(t *testing.T) {
	pn := wikiFixture()
	in := "| [[findings/fin-1.md|F1]] | x |\n| [[missing.md|M]] | y |\n"
	got := rewriteVaultLinks(in, ".", pn, escapePageName)
	if want := "| [F1](Findings%2Ffin-1) | x |\n| M | y |\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Square brackets inside a wikilink alias must not survive into the rendered
// markdown link text — "[GET /search [q](url)]" nests a bogus inner link and
// only the "[q]" fragment renders as clickable.
func TestRewriteVaultLinks_BracketsInAliasNeutralized(t *testing.T) {
	pn := wikiFixture()
	got := rewriteVaultLinks("[[findings/fin-1.md|GET /search [q)]]", ".", pn, escapePageName)
	if want := "[GET /search (q)](Findings%2Ffin-1)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The repair pass swaps the link target source: server-issued sub_urls take
// precedence over client-side escaping when provided.
func TestRewriteVaultLinks_LinkForOverride(t *testing.T) {
	pn := wikiFixture()
	sub := map[string]string{"Findings/fin-1": "Findings%2Ffin-1.-"}
	linkFor := func(name string) string {
		if s := sub[name]; s != "" {
			return s
		}
		return escapePageName(name)
	}
	got := rewriteVaultLinks("[[findings/fin-1.md|fin-1]]", ".", pn, linkFor)
	if want := "[fin-1](Findings%2Ffin-1.-)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
