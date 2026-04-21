package jira

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestDefinitionLabel(t *testing.T) {
	got := definitionLabel("def-abc123")
	if got != "zap-definition-def-abc123" {
		t.Errorf("got %q, want %q", got, "zap-definition-def-abc123")
	}
}

func TestEpicSummary_PrefersAlertOverName(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-1", PluginID: "10020", Alert: "X-Frame-Options Header Not Set", Name: "XFO"}
	got := epicSummary(def)
	want := "[ZAP] X-Frame-Options Header Not Set (Plugin 10020)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEpicSummary_FallsBackToDefinitionID(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-xyz"}
	got := epicSummary(def)
	if got != "[ZAP] def-xyz" {
		t.Errorf("got %q", got)
	}
}

func TestEpicSummary_Truncates(t *testing.T) {
	long := strings.Repeat("X", 300)
	def := &entities.Definition{Alert: long, PluginID: "1"}
	got := epicSummary(def)
	if len(got) != 255 {
		t.Errorf("expected 255 chars, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected trailing ellipsis, got suffix %q", got[len(got)-5:])
	}
}

func TestBuildEpicDescription_ContainsKeyParts(t *testing.T) {
	def := &entities.Definition{
		DefinitionID: "def-10020",
		PluginID:     "10020",
		Alert:        "X-Frame-Options Header Not Set",
		Description:  "Missing header allows clickjacking.",
		Taxonomy:     &entities.Taxonomy{CWEID: 1021},
		Remediation:  &entities.Remediation{Summary: "Set X-Frame-Options: DENY."},
		Detection:    &entities.Detection{DocsURL: "https://www.zaproxy.org/docs/alerts/10020/"},
	}
	doc := buildEpicDescription(def, epicEvidence{})
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		"Missing header allows clickjacking.",
		"CWE-1021",
		"cwe.mitre.org/data/definitions/1021",
		"zaproxy.org/docs/alerts/10020",
		"Set X-Frame-Options: DENY.",
		"Child issues",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in description JSON", want)
		}
	}
}

func TestBuildEpicDescription_NilDefinition(t *testing.T) {
	doc := buildEpicDescription(nil, epicEvidence{})
	if doc.Type != "doc" || doc.Version != 1 {
		t.Errorf("expected empty doc scaffold, got %+v", doc)
	}
}

func TestBuildEpicEvidence_AggregatesAcrossOccurrences(t *testing.T) {
	findings := []entities.Finding{
		{FindingID: "f1", DefinitionID: "d1"},
		{FindingID: "f2", DefinitionID: "d1"},
	}
	occs := []entities.Occurrence{
		{FindingID: "f1", URL: "https://a/x", Method: "GET", ScanLabel: "scan-a", ObservedAt: "2026-04-01T00:00:00Z"},
		{FindingID: "f1", URL: "https://a/x", Method: "GET", ScanLabel: "scan-b", ObservedAt: "2026-04-05T00:00:00Z"},
		{FindingID: "f2", URL: "https://a/y", Method: "POST", ScanLabel: "scan-a", ObservedAt: "2026-04-03T00:00:00Z"},
		{FindingID: "other", URL: "https://b/z", Method: "GET", ScanLabel: "scan-c"}, // unrelated, must be ignored
	}
	ev := buildEpicEvidence(findings, occs)
	if ev.FindingCount != 2 {
		t.Errorf("FindingCount = %d, want 2", ev.FindingCount)
	}
	if ev.OccurrenceCount != 3 {
		t.Errorf("OccurrenceCount = %d, want 3", ev.OccurrenceCount)
	}
	if got, want := strings.Join(ev.ScanLabels, ","), "scan-a,scan-b"; got != want {
		t.Errorf("ScanLabels = %q, want %q", got, want)
	}
	if ev.FirstSeen != "2026-04-01T00:00:00Z" {
		t.Errorf("FirstSeen = %q", ev.FirstSeen)
	}
	if ev.LastSeen != "2026-04-05T00:00:00Z" {
		t.Errorf("LastSeen = %q", ev.LastSeen)
	}
	// "GET https://a/x (×2)" has the highest occurrence count and should rank first.
	if len(ev.TopURLs) == 0 || !strings.Contains(ev.TopURLs[0], "GET https://a/x") || !strings.Contains(ev.TopURLs[0], "×2") {
		t.Errorf("TopURLs[0] should be GET https://a/x ×2, got %v", ev.TopURLs)
	}
}

func TestBuildEpicDescription_RendersEvidenceRollup(t *testing.T) {
	def := &entities.Definition{DefinitionID: "d1", PluginID: "10038", Alert: "CSP missing"}
	ev := epicEvidence{
		FindingCount:    3,
		OccurrenceCount: 7,
		ScanLabels:      []string{"scan-a", "scan-b"},
		FirstSeen:       "2026-04-01T00:00:00Z",
		LastSeen:        "2026-04-05T00:00:00Z",
		TopURLs:         []string{"GET https://a/x (×4)", "POST https://a/y (×3)"},
	}
	doc := buildEpicDescription(def, ev)
	data, _ := json.Marshal(doc)
	s := string(data)
	for _, want := range []string{
		"Evidence rollup",
		"Findings: 3",
		"Occurrences: 7",
		"Scans: scan-a, scan-b",
		"First seen: 2026-04-01T00:00:00Z",
		"Last seen: 2026-04-05T00:00:00Z",
		"Top affected endpoints",
		"GET https://a/x (×4)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in description JSON", want)
		}
	}
}

func TestBuildEpicDescription_OmitsRollupWhenEmpty(t *testing.T) {
	def := &entities.Definition{DefinitionID: "d1", Alert: "X"}
	doc := buildEpicDescription(def, epicEvidence{})
	data, _ := json.Marshal(doc)
	if strings.Contains(string(data), "Evidence rollup") {
		t.Errorf("rollup section should be omitted for empty evidence")
	}
}
