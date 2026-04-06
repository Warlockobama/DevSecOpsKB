package zapmeta

import (
	"strings"
	"testing"
)

func TestScrapeCWEID_LinkInHTML(t *testing.T) {
	html := `<a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79</a>`
	got := scrapeCWEID(html, "40012")
	if got != 79 {
		t.Errorf("expected 79, got %d", got)
	}
}

func TestScrapeCWEID_TextPattern(t *testing.T) {
	html := `<p>This vulnerability is mapped to CWE-89 (SQL Injection).</p>`
	got := scrapeCWEID(html, "40014")
	if got != 89 {
		t.Errorf("expected 89, got %d", got)
	}
}

func TestScrapeCWEID_StaticFallback(t *testing.T) {
	// No CWE in HTML, should fall back to static map
	got := scrapeCWEID("<html><body>No CWE here</body></html>", "10035")
	if got != 319 {
		t.Errorf("expected 319 (HSTS), got %d", got)
	}
}

func TestScrapeCWEID_UnknownPlugin(t *testing.T) {
	got := scrapeCWEID("<html><body>Nothing</body></html>", "99999")
	if got != 0 {
		t.Errorf("expected 0 for unknown plugin, got %d", got)
	}
}

func TestScrapeCWEID_LinkTakesPrecedenceOverFallback(t *testing.T) {
	// Plugin 10035 is in static map as 319, but page says 311 — page wins
	html := `<a href="https://cwe.mitre.org/data/definitions/311.html">CWE-311</a>`
	got := scrapeCWEID(html, "10035")
	if got != 311 {
		t.Errorf("expected 311 (from link), got %d", got)
	}
}

// TestTriageGuidance_KnownPlugin_CSP verifies that plugin 10038 (CSP header not
// set) returns plugin-specific tips mentioning Content-Security-Policy.
func TestTriageGuidance_KnownPlugin_CSP(t *testing.T) {
	tips := TriageGuidance("10038")
	if len(tips) == 0 {
		t.Fatal("expected non-empty tips for plugin 10038")
	}
	found := false
	for _, tip := range tips {
		if strings.Contains(tip, "Content-Security-Policy") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected at least one tip mentioning Content-Security-Policy for plugin 10038, got: %v", tips)
	}
}

// TestTriageGuidance_KnownPlugin_Clickjacking verifies that plugin 10020
// (Missing Anti-clickjacking header) returns plugin-specific tips.
func TestTriageGuidance_KnownPlugin_Clickjacking(t *testing.T) {
	tips := TriageGuidance("10020")
	if len(tips) == 0 {
		t.Fatal("expected non-empty tips for plugin 10020")
	}
	found := false
	for _, tip := range tips {
		if strings.Contains(tip, "X-Frame-Options") || strings.Contains(tip, "frame-ancestors") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tips mentioning X-Frame-Options or frame-ancestors for plugin 10020, got: %v", tips)
	}
}

// TestTriageGuidance_UnknownPlugin verifies that an unknown plugin ID returns
// nil (no generic tips — callers omit the section entirely).
func TestTriageGuidance_UnknownPlugin(t *testing.T) {
	tips := TriageGuidance("99999")
	if len(tips) != 0 {
		t.Fatalf("expected nil/empty tips for unknown plugin 99999, got: %v", tips)
	}
}

// TestTriageGuidance_WithLeadingTrailingSpaces verifies that whitespace in the
// plugin ID is tolerated (TrimSpace applied).
func TestTriageGuidance_WithLeadingTrailingSpaces(t *testing.T) {
	tipsWithSpaces := TriageGuidance("  10038  ")
	tipsClean := TriageGuidance("10038")
	if len(tipsWithSpaces) != len(tipsClean) {
		t.Errorf("TriageGuidance should be whitespace-tolerant: got %d tips with spaces, %d without", len(tipsWithSpaces), len(tipsClean))
	}
}

func TestAtoi(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"79", 79},
		{"0", 0},
		{"942", 942},
		{"abc", 0},
		{"12x", 0},
		{"", 0},
	}
	for _, c := range cases {
		got := atoi(c.in)
		if got != c.want {
			t.Errorf("atoi(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
