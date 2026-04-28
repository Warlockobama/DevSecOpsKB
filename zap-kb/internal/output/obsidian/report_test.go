package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateReportWritesRelativeToVaultAndFilters(t *testing.T) {
	root := t.TempDir()
	occDir := filepath.Join(root, "occurrences")
	if err := os.MkdirAll(occDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeOccurrence := func(name, observed, scan, risk string) {
		t.Helper()
		body := `---
analyst.status: "open"
domain: "example.test"
findingId: "fin-` + name + `"
method: "GET"
observedAt: "` + observed + `"
occurrenceId: "occ-` + name + `"
risk: "` + risk + `"
scan.label: "` + scan + `"
url: "https://example.test/` + name + `"
---
`
		if err := os.WriteFile(filepath.Join(occDir, name+".md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeOccurrence("in", "2026-01-02T00:00:00Z", "scan-a", "Medium")
	writeOccurrence("wrong-scan", "2026-01-02T00:00:00Z", "scan-b", "High")
	writeOccurrence("old", "2025-12-31T00:00:00Z", "scan-a", "Low")

	err := GenerateReport(root, ReportOptions{
		OutPath:   "reports/smoke.md",
		Title:     "Smoke Report",
		Since:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Until:     time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
		ScanLabel: "scan-a",
	})
	if err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(root, "reports", "smoke.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"# Smoke Report", "- Occurrences: 1", "## Occurrences", "fin-in", "Medium"} {
		if !strings.Contains(got, want) {
			t.Fatalf("report missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fin-wrong-scan") || strings.Contains(got, "fin-old") {
		t.Fatalf("report included filtered occurrence:\n%s", got)
	}
}
