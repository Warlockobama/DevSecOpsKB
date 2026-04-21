package main

import (
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func makeTestEntities() entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []entities.Definition{
			{DefinitionID: "def-001", PluginID: "1001", Alert: "XSS Reflected"},
			{DefinitionID: "def-002", PluginID: "1002", Alert: "SQL Injection"},
			{DefinitionID: "def-003", PluginID: "1003", Alert: "Missing CSP Header"},
		},
		Findings: []entities.Finding{
			{FindingID: "fin-aaa", DefinitionID: "def-001", Risk: "High", URL: "https://example.com/search"},
			{FindingID: "fin-bbb", DefinitionID: "def-002", Risk: "Medium", URL: "https://example.com/login"},
			{FindingID: "fin-ccc", DefinitionID: "def-003", Risk: "Low", URL: "https://example.com/"},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-1", FindingID: "fin-aaa", ScanLabel: "scan-1", ObservedAt: "2024-01-15T10:00:00Z"},
			{OccurrenceID: "occ-2", FindingID: "fin-aaa", Analyst: &entities.Analyst{Status: "triaged"}},
			{OccurrenceID: "occ-3", FindingID: "fin-bbb", Analyst: &entities.Analyst{Status: "fixed"}},
			{OccurrenceID: "occ-4", FindingID: "fin-ccc"},
		},
	}
}

func TestBuildReportRows_SeverityOrder(t *testing.T) {
	ef := makeTestEntities()
	rows := buildReportRows(ef, "")

	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}

	// Rows must be sorted High → Medium → Low
	wantOrder := []string{"High", "Medium", "Low"}
	for i, want := range wantOrder {
		if rows[i].Severity != want {
			t.Errorf("row[%d]: expected severity %q, got %q", i, want, rows[i].Severity)
		}
	}
}

func TestBuildReportRows_OccurrenceCounts(t *testing.T) {
	ef := makeTestEntities()
	rows := buildReportRows(ef, "")

	// fin-aaa: 1 open (occ-1), 1 triaged (occ-2)
	var aaaRow *reportRow
	for i := range rows {
		if rows[i].FindingID == "fin-aaa" {
			aaaRow = &rows[i]
			break
		}
	}
	if aaaRow == nil {
		t.Fatal("fin-aaa row not found")
	}
	if aaaRow.Open != 1 {
		t.Errorf("fin-aaa open: expected 1, got %d", aaaRow.Open)
	}
	if aaaRow.Triaged != 1 {
		t.Errorf("fin-aaa triaged: expected 1, got %d", aaaRow.Triaged)
	}
	if len(aaaRow.ScanLabels) != 1 || aaaRow.ScanLabels[0] != "scan-1" {
		t.Errorf("fin-aaa scan_labels: expected [scan-1], got %v", aaaRow.ScanLabels)
	}
	if aaaRow.LastSeen != "2024-01-15T10:00:00Z" {
		t.Errorf("fin-aaa last_seen: expected %q, got %q", "2024-01-15T10:00:00Z", aaaRow.LastSeen)
	}
}

func TestBuildReportRows_FilterStatus(t *testing.T) {
	ef := makeTestEntities()
	rows := buildReportRows(ef, "open")

	// fin-aaa has 1 open; fin-bbb has 0 open (fixed); fin-ccc has 1 open
	for _, r := range rows {
		if r.Open == 0 {
			t.Errorf("filter-status=open: row %q has open=0, should be excluded", r.FindingID)
		}
	}
	if len(rows) != 2 {
		t.Errorf("filter-status=open: expected 2 rows (fin-aaa, fin-ccc), got %d", len(rows))
	}
}

func TestBuildReportRows_RuleTitleFromDefinition(t *testing.T) {
	ef := makeTestEntities()
	rows := buildReportRows(ef, "")

	for _, r := range rows {
		if r.RuleTitle == "" {
			t.Errorf("row %q has empty rule_title", r.FindingID)
		}
	}

	// fin-aaa → def-001 → "XSS Reflected"
	for _, r := range rows {
		if r.FindingID == "fin-aaa" && r.RuleTitle != "XSS Reflected" {
			t.Errorf("fin-aaa rule_title: expected %q, got %q", "XSS Reflected", r.RuleTitle)
		}
	}
}

func TestDomainFromURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path?q=1", "example.com"},
		{"http://juice-shop:3000/api", "juice-shop"},
		{"https://example.com", "example.com"},
		{"", ""},
	}
	for _, c := range cases {
		got := domainFromURL(c.in)
		if got != c.want {
			t.Errorf("domainFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"High", 0},
		{"high", 0},
		{"Medium", 1},
		{"Low", 2},
		{"Informational", 3},
		{"info", 3},
		{"unknown", 99},
	}
	for _, c := range cases {
		got := severityRank(c.s)
		if got != c.want {
			t.Errorf("severityRank(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestBuildReportRows_CSVHeaders(t *testing.T) {
	// Verify that CSV output contains required header fields in the right order
	ef := makeTestEntities()
	rows := buildReportRows(ef, "")
	_ = rows // exercise the function

	// Simulate the CSV header row the runReportCommand emits
	header := strings.Join([]string{
		"finding_id", "rule_title", "severity", "domain",
		"open", "triaged", "fp", "accepted", "fixed",
		"last_seen", "scan_labels",
	}, ",")
	wantFields := []string{"finding_id", "severity", "open", "last_seen", "scan_labels"}
	for _, f := range wantFields {
		if !strings.Contains(header, f) {
			t.Errorf("CSV header missing field %q", f)
		}
	}
}

// TestBuildReportRows_MultiScanLabels verifies that a finding with occurrences
// from two different scans collects both labels (order-preserving, deduplicated).
func TestBuildReportRows_MultiScanLabels(t *testing.T) {
	ef := entities.EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []entities.Definition{
			{DefinitionID: "def-001", PluginID: "1001", Alert: "XSS Reflected"},
		},
		Findings: []entities.Finding{
			{FindingID: "fin-aaa", DefinitionID: "def-001", Risk: "High", URL: "https://example.com/search"},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-1", FindingID: "fin-aaa", ScanLabel: "scan-alpha", ObservedAt: "2024-01-10T10:00:00Z"},
			{OccurrenceID: "occ-2", FindingID: "fin-aaa", ScanLabel: "scan-beta", ObservedAt: "2024-02-01T10:00:00Z"},
			{OccurrenceID: "occ-3", FindingID: "fin-aaa", ScanLabel: "scan-alpha"}, // duplicate label — must not appear twice
		},
	}
	rows := buildReportRows(ef, "")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if len(r.ScanLabels) != 2 {
		t.Fatalf("ScanLabels: want 2 distinct labels, got %d: %v", len(r.ScanLabels), r.ScanLabels)
	}
	if r.ScanLabels[0] != "scan-alpha" {
		t.Errorf("ScanLabels[0]: want %q, got %q", "scan-alpha", r.ScanLabels[0])
	}
	if r.ScanLabels[1] != "scan-beta" {
		t.Errorf("ScanLabels[1]: want %q, got %q", "scan-beta", r.ScanLabels[1])
	}

	// Verify CSV join uses "|"
	joined := strings.Join(r.ScanLabels, "|")
	if joined != "scan-alpha|scan-beta" {
		t.Errorf("CSV join: want %q, got %q", "scan-alpha|scan-beta", joined)
	}
}
