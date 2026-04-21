package confluence

import (
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestBuildScanRows_AggregatesByLabel(t *testing.T) {
	ef := &entities.EntitiesFile{
		Findings: []entities.Finding{
			{FindingID: "f1", DefinitionID: "d1", URL: "https://a/x"},
			{FindingID: "f2", DefinitionID: "d1", URL: "https://a/y"},
			{FindingID: "f3", DefinitionID: "d2", URL: "https://b/z"},
		},
		Occurrences: []entities.Occurrence{
			{FindingID: "f1", ScanLabel: "scan-a", ObservedAt: "2026-04-01T00:00:00Z"},
			{FindingID: "f1", ScanLabel: "scan-a", ObservedAt: "2026-04-03T00:00:00Z"},
			{FindingID: "f2", ScanLabel: "scan-a", ObservedAt: "2026-04-02T00:00:00Z"},
			{FindingID: "f3", ScanLabel: "scan-b", ObservedAt: "2026-04-05T00:00:00Z"},
			{FindingID: "f1", ScanLabel: "", ObservedAt: "2026-03-30T00:00:00Z"}, // unlabeled
		},
	}
	rows := buildScanRows(ef)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (scan-a, scan-b, (unlabeled)), got %d", len(rows))
	}
	// Most-recent (scan-b, last=2026-04-05) sorts first.
	if rows[0].Label != "scan-b" {
		t.Errorf("rows[0].Label = %q, want scan-b", rows[0].Label)
	}
	// scan-a aggregate: 3 occurrences, 2 findings (f1+f2), 1 def, 2 URLs.
	var a *scanRow
	for i := range rows {
		if rows[i].Label == "scan-a" {
			a = &rows[i]
		}
	}
	if a == nil {
		t.Fatal("scan-a row missing")
	}
	if a.Occurrences != 3 || a.Findings != 2 || a.Definitions != 1 || a.URLs != 2 {
		t.Errorf("scan-a metrics: occ=%d find=%d def=%d urls=%d (want 3/2/1/2)", a.Occurrences, a.Findings, a.Definitions, a.URLs)
	}
	if a.First != "2026-04-01T00:00:00Z" || a.Last != "2026-04-03T00:00:00Z" {
		t.Errorf("scan-a first/last = %q/%q", a.First, a.Last)
	}
	// (unlabeled) bucket must be present so analysts can see the gap.
	found := false
	for _, r := range rows {
		if r.Label == "(unlabeled)" {
			found = true
		}
	}
	if !found {
		t.Error("expected (unlabeled) bucket for occurrence with empty ScanLabel")
	}
}

func TestBuildScansIndexBody_RendersTable(t *testing.T) {
	rows := []scanRow{
		{Label: "prod-20260401", First: "2026-04-01T00:00:00Z", Last: "2026-04-01T08:00:00Z", Occurrences: 11, Findings: 6, Definitions: 4, URLs: 5},
	}
	body := buildScansIndexBody(rows)
	for _, want := range []string{"<h1>Scans</h1>", "prod-20260401", "<th>Scan label</th>", "<td>11</td>", "<td>6</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestBuildScansIndexBody_EmptyRows(t *testing.T) {
	body := buildScansIndexBody(nil)
	if !strings.Contains(body, "No scans recorded") {
		t.Errorf("expected empty-state copy, got %q", body)
	}
}
