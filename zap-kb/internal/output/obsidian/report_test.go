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

func TestGenerateReportTreatsDateOnlyUntilAsEndOfDay(t *testing.T) {
	root := t.TempDir()
	occDir := filepath.Join(root, "occurrences")
	if err := os.MkdirAll(occDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `---
observedAt: "2026-01-03T23:30:00Z"
occurrenceId: "occ-end-day"
findingId: "fin-end-day"
risk: "Medium"
---
`
	if err := os.WriteFile(filepath.Join(occDir, "end-day.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	err := GenerateReport(root, ReportOptions{
		OutPath: "reports/window.md",
		Since:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Until:   time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "reports", "window.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "fin-end-day") {
		t.Fatalf("date-only until should include the full until day:\n%s", b)
	}
	if !strings.Contains(string(b), "- Window: 2026-01-01T00:00:00Z to 2026-01-03T23:59:59Z") {
		t.Fatalf("displayed window should match normalized until:\n%s", b)
	}
}
