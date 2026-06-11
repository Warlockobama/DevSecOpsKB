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
		{"[gone](missing.md)", ".", "[gone](missing.md)"},
	}
	for _, c := range cases {
		got := rewriteVaultLinks(c.content, c.relDir, pn)
		if got != c.want {
			t.Errorf("rewriteVaultLinks(%q, relDir=%q) = %q, want %q", c.content, c.relDir, got, c.want)
		}
	}
}

func TestRewriteVaultLinks_Idempotent(t *testing.T) {
	pn := wikiFixture()
	in := "[[definitions/def-1.md|XSS]]"
	once := rewriteVaultLinks(in, ".", pn)
	twice := rewriteVaultLinks(once, ".", pn)
	if once != twice {
		t.Fatalf("not idempotent: once=%q twice=%q", once, twice)
	}
}
