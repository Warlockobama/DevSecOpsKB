package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDashboardOmitsLocalStatusSummary(t *testing.T) {
	root := t.TempDir()
	occDir := filepath.Join(root, "occurrences")
	defDir := filepath.Join(root, "definitions")
	if err := os.MkdirAll(occDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(defDir, 0o755); err != nil {
		t.Fatal(err)
	}

	def := `---
id: "def-1"
name: "Test Rule"
pluginId: "10001"
---
`
	if err := os.WriteFile(filepath.Join(defDir, "def-1.md"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}

	occ := `---
analyst.status: "open"
definitionId: "def-1"
domain: "example.test"
findingId: "find-1"
occurrenceId: "occ-1"
risk: "High"
scan.label: "scan-a"
url: "https://example.test/"
---
`
	if err := os.WriteFile(filepath.Join(occDir, "occ-1.md"), []byte(occ), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := GenerateDashboard(root); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(root, "DASHBOARD.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, "## Status") || strings.Contains(got, "| Open |") {
		t.Fatalf("dashboard should not summarize KB-local analyst.status:\n%s", got)
	}
	if !strings.Contains(got, "## Snapshot") || !strings.Contains(got, "## By Scan") {
		t.Fatalf("dashboard missing expected non-status sections:\n%s", got)
	}
}
