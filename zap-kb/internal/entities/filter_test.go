package entities

import "testing"

func TestFilterZAPAlertsOnlyKeepsNumericPluginIDs(t *testing.T) {
	ef := EntitiesFile{
		SchemaVersion: "v1",
		SourceTool:    "multi",
		Definitions: []Definition{
			{DefinitionID: "def-10021", PluginID: "10021", Alert: "X-Content-Type-Options Header Missing"},
			{DefinitionID: "def-zap-legacy", PluginID: "zap-legacy-ftp-surface", Alert: "Legacy FTP Surface Exposed Over Web"},
			{DefinitionID: "def-nuclei", PluginID: "missing-hsts-header", Alert: "Missing HSTS Header"},
		},
		Findings: []Finding{
			{FindingID: "fin-10021", DefinitionID: "def-10021", PluginID: "10021", Occurrences: 2, FirstSeen: "old", LastSeen: "old"},
			{FindingID: "fin-legacy", DefinitionID: "def-zap-legacy", PluginID: "zap-legacy-ftp-surface", Occurrences: 1},
			{FindingID: "fin-nuclei", DefinitionID: "def-nuclei", PluginID: "missing-hsts-header", Occurrences: 1},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-10021-a", FindingID: "fin-10021", DefinitionID: "def-10021", ObservedAt: "2026-04-01T00:00:00Z"},
			{OccurrenceID: "occ-10021-b", FindingID: "fin-10021", DefinitionID: "def-10021", ObservedAt: "2026-04-02T00:00:00Z"},
			{OccurrenceID: "occ-legacy", FindingID: "fin-legacy", DefinitionID: "def-zap-legacy", ObservedAt: "2026-04-01T00:00:00Z"},
			{OccurrenceID: "occ-nuclei", FindingID: "fin-nuclei", DefinitionID: "def-nuclei", ObservedAt: "2026-04-01T00:00:00Z"},
		},
	}

	got := FilterZAPAlertsOnly(ef)

	if got.SourceTool != "zap" {
		t.Fatalf("SourceTool = %q, want zap", got.SourceTool)
	}
	if len(got.Definitions) != 1 || got.Definitions[0].PluginID != "10021" {
		t.Fatalf("definitions = %+v, want only numeric ZAP definition", got.Definitions)
	}
	if len(got.Findings) != 1 || got.Findings[0].FindingID != "fin-10021" {
		t.Fatalf("findings = %+v, want only numeric ZAP finding", got.Findings)
	}
	if got.Findings[0].Occurrences != 2 {
		t.Fatalf("Occurrences = %d, want 2", got.Findings[0].Occurrences)
	}
	if got.Findings[0].FirstSeen != "2026-04-01T00:00:00Z" || got.Findings[0].LastSeen != "2026-04-02T00:00:00Z" {
		t.Fatalf("first/last seen not recomputed: %+v", got.Findings[0])
	}
	if len(got.Occurrences) != 2 {
		t.Fatalf("occurrences = %+v, want 2 numeric ZAP occurrences", got.Occurrences)
	}
}
