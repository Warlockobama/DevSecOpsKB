package entities

import "testing"

func analystPtr(status string) *Analyst {
	return &Analyst{Status: status}
}

// TestMergeAnalyst_BothNil ensures nil+nil returns nil.
func TestMergeAnalyst_BothNil(t *testing.T) {
	if got := mergeAnalyst(nil, nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestMergeAnalyst_FieldLevelFill verifies base wins on non-empty fields,
// add fills gaps, and tags are unioned.
func TestMergeAnalyst_FieldLevelFill(t *testing.T) {
	base := &Analyst{Status: "open", Notes: "", Tags: []string{"tag-a"}}
	add := &Analyst{Status: "triaged", Notes: "confirmed", Tags: []string{"tag-b"}}
	got := mergeAnalyst(base, add)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Status != "open" {
		t.Errorf("Status: want %q, got %q", "open", got.Status)
	}
	if got.Notes != "confirmed" {
		t.Errorf("Notes: want %q, got %q", "confirmed", got.Notes)
	}
	if len(got.Tags) != 2 {
		t.Errorf("Tags: want 2, got %d: %v", len(got.Tags), got.Tags)
	}
}

// TestMergeAnalyst_TagUnion verifies both slices are unioned with deduplication.
func TestMergeAnalyst_TagUnion(t *testing.T) {
	base := &Analyst{Status: "open", Tags: []string{"alpha", "shared"}}
	add := &Analyst{Tags: []string{"shared", "beta"}}
	got := mergeAnalyst(base, add)
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	want := map[string]bool{"alpha": true, "shared": true, "beta": true}
	if len(got.Tags) != 3 {
		t.Errorf("Tags: want 3 distinct tags, got %d: %v", len(got.Tags), got.Tags)
	}
	for _, tag := range got.Tags {
		if !want[tag] {
			t.Errorf("unexpected tag %q in result", tag)
		}
	}
}

// TestMerge_AnalystFieldLevel_ViaOccurrence tests field-level merge through the
// Merge() function: base has {status:"open", notes:""}, add has
// {status:"triaged", notes:"confirmed"} — merged must have status:"open" (base
// wins) and notes:"confirmed" (add fills empty).
func TestMerge_AnalystFieldLevel_ViaOccurrence(t *testing.T) {
	base := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-x", FindingID: "fin-1", Analyst: &Analyst{Status: "open", Notes: ""}},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-x", FindingID: "fin-1", Analyst: &Analyst{Status: "triaged", Notes: "confirmed"}},
		},
	}
	merged := Merge(base, add)
	if len(merged.Occurrences) != 1 {
		t.Fatalf("expected 1 occurrence, got %d", len(merged.Occurrences))
	}
	got := merged.Occurrences[0].Analyst
	if got == nil {
		t.Fatal("expected non-nil Analyst")
	}
	if got.Status != "open" {
		t.Errorf("Status: want %q (base wins), got %q", "open", got.Status)
	}
	if got.Notes != "confirmed" {
		t.Errorf("Notes: want %q (add fills empty), got %q", "confirmed", got.Notes)
	}
}

func TestMerge_AnalystConflict_BaseWins(t *testing.T) {
	// Base occurrence has a non-nil Analyst with a non-empty Status.
	// Add occurrence has a different Analyst. Base should win.
	base := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-aaa", FindingID: "fin-1", URL: "https://example.com", Analyst: analystPtr("triaged")},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-aaa", FindingID: "fin-1", URL: "https://example.com", Analyst: analystPtr("fp")},
		},
	}
	merged := Merge(base, add)
	if len(merged.Occurrences) != 1 {
		t.Fatalf("expected 1 occurrence, got %d", len(merged.Occurrences))
	}
	got := merged.Occurrences[0].Analyst
	if got == nil || got.Status != "triaged" {
		t.Errorf("expected base analyst status 'triaged', got %v", got)
	}
}

// TestMerge_DetectionFieldLevelFill verifies that when base has a partial Detection
// (LogicType set, RuleSource empty), add's RuleSource is copied into base.
func TestMerge_DetectionFieldLevelFill(t *testing.T) {
	base := EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Detection:    &Detection{LogicType: "passive"},
			},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Detection:    &Detection{RuleSource: "zap-extensions/addOns/pscanrules/src/main/java/Rule.java"},
			},
		},
	}
	merged := Merge(base, add)
	if len(merged.Definitions) != 1 {
		t.Fatalf("expected 1 definition, got %d", len(merged.Definitions))
	}
	d := merged.Definitions[0]
	if d.Detection == nil {
		t.Fatal("expected non-nil Detection")
	}
	if d.Detection.LogicType != "passive" {
		t.Errorf("LogicType: want %q (base), got %q", "passive", d.Detection.LogicType)
	}
	if d.Detection.RuleSource == "" {
		t.Errorf("RuleSource: want non-empty (from add), got empty")
	}
}

// TestMerge_TaxonomyFieldLevelFill verifies that when base has CWEID=89 and add has
// OWASPTop10 set, the merged result has both.
func TestMerge_TaxonomyFieldLevelFill(t *testing.T) {
	base := EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []Definition{
			{
				DefinitionID: "def-40014",
				PluginID:     "40014",
				Taxonomy:     &Taxonomy{CWEID: 89},
			},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []Definition{
			{
				DefinitionID: "def-40014",
				PluginID:     "40014",
				Taxonomy:     &Taxonomy{CWEID: 89, OWASPTop10: []string{"A03:2021"}},
			},
		},
	}
	merged := Merge(base, add)
	if len(merged.Definitions) != 1 {
		t.Fatalf("expected 1 definition, got %d", len(merged.Definitions))
	}
	d := merged.Definitions[0]
	if d.Taxonomy == nil {
		t.Fatal("expected non-nil Taxonomy")
	}
	if d.Taxonomy.CWEID != 89 {
		t.Errorf("CWEID: want 89 (base), got %d", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) == 0 || d.Taxonomy.OWASPTop10[0] != "A03:2021" {
		t.Errorf("OWASPTop10: want [A03:2021] (from add), got %v", d.Taxonomy.OWASPTop10)
	}
}

func TestMerge_AnalystConflict_AddFillsNil(t *testing.T) {
	// Base occurrence has nil Analyst; add has a non-nil Analyst.
	// Add's Analyst should be adopted.
	base := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-bbb", FindingID: "fin-1", URL: "https://example.com", Analyst: nil},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-bbb", FindingID: "fin-1", URL: "https://example.com", Analyst: analystPtr("open")},
		},
	}
	merged := Merge(base, add)
	if len(merged.Occurrences) != 1 {
		t.Fatalf("expected 1 occurrence, got %d", len(merged.Occurrences))
	}
	got := merged.Occurrences[0].Analyst
	if got == nil || got.Status != "open" {
		t.Errorf("expected adopted analyst status 'open', got %v", got)
	}
}

// TestMergeAnalyst_BaseNil verifies that when base is nil and add is non-nil,
// the result is a copy of add.
func TestMergeAnalyst_BaseNil(t *testing.T) {
	add := &Analyst{Status: "triaged", Notes: "confirmed", Tags: []string{"cve"}}
	got := mergeAnalyst(nil, add)
	if got == nil {
		t.Fatal("expected non-nil result when base is nil")
	}
	if got.Status != "triaged" {
		t.Errorf("Status: want %q, got %q", "triaged", got.Status)
	}
	if got.Notes != "confirmed" {
		t.Errorf("Notes: want %q, got %q", "confirmed", got.Notes)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "cve" {
		t.Errorf("Tags: want [cve], got %v", got.Tags)
	}
	// Ensure it's a copy, not same pointer.
	if got == add {
		t.Error("expected a copy of add, not the same pointer")
	}
}

// TestMergeAnalyst_AddNil verifies that when add is nil and base is non-nil,
// the result is a copy of base.
func TestMergeAnalyst_AddNil(t *testing.T) {
	base := &Analyst{Status: "fp", Notes: "false positive", Tags: []string{"whitelist"}}
	got := mergeAnalyst(base, nil)
	if got == nil {
		t.Fatal("expected non-nil result when add is nil")
	}
	if got.Status != "fp" {
		t.Errorf("Status: want %q, got %q", "fp", got.Status)
	}
	if got.Notes != "false positive" {
		t.Errorf("Notes: want %q, got %q", "false positive", got.Notes)
	}
	if got == base {
		t.Error("expected a copy of base, not the same pointer")
	}
}

// TestMerge_FirstSeenLastSeen verifies that Merge() recomputes FirstSeen and
// LastSeen on findings from the merged occurrence set. Base has one occurrence
// with ObservedAt="2024-01-01T00:00:00Z"; add contributes a new occurrence with
// ObservedAt="2024-06-01T00:00:00Z". The merged finding must have
// FirstSeen="2024-01-01T00:00:00Z" and LastSeen="2024-06-01T00:00:00Z".
func TestMerge_FirstSeenLastSeen(t *testing.T) {
	const early = "2024-01-01T00:00:00Z"
	const late = "2024-06-01T00:00:00Z"

	base := EntitiesFile{
		SchemaVersion: "v1",
		Findings: []Finding{
			{FindingID: "fin-ts", PluginID: "10001", URL: "https://example.com/"},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-ts-1", FindingID: "fin-ts", ObservedAt: early},
		},
	}
	add := EntitiesFile{
		SchemaVersion: "v1",
		Findings:      []Finding{},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-ts-2", FindingID: "fin-ts", ObservedAt: late},
		},
	}

	merged := Merge(base, add)

	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(merged.Findings))
	}
	f := merged.Findings[0]
	if f.FirstSeen != early {
		t.Errorf("FirstSeen: want %q, got %q", early, f.FirstSeen)
	}
	if f.LastSeen != late {
		t.Errorf("LastSeen: want %q, got %q", late, f.LastSeen)
	}
	if f.Occurrences != 2 {
		t.Errorf("Occurrences count: want 2, got %d", f.Occurrences)
	}
}

// TestMerge_FirstSeenLastSeen_SingleOccurrence verifies that when a finding has
// only one occurrence, FirstSeen and LastSeen are both set to that occurrence's
// ObservedAt.
func TestMerge_FirstSeenLastSeen_SingleOccurrence(t *testing.T) {
	const ts = "2024-03-15T12:00:00Z"

	base := EntitiesFile{
		SchemaVersion: "v1",
		Findings: []Finding{
			{FindingID: "fin-single", PluginID: "10001", URL: "https://example.com/"},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-single-1", FindingID: "fin-single", ObservedAt: ts},
		},
	}

	merged := Merge(base, EntitiesFile{SchemaVersion: "v1"})
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(merged.Findings))
	}
	f := merged.Findings[0]
	if f.FirstSeen != ts {
		t.Errorf("FirstSeen: want %q, got %q", ts, f.FirstSeen)
	}
	if f.LastSeen != ts {
		t.Errorf("LastSeen: want %q, got %q", ts, f.LastSeen)
	}
}

// TestMerge_FirstSeenLastSeen_EmptyObservedAt verifies that occurrences with
// empty ObservedAt are skipped when computing FirstSeen/LastSeen.
func TestMerge_FirstSeenLastSeen_EmptyObservedAt(t *testing.T) {
	base := EntitiesFile{
		SchemaVersion: "v1",
		Findings: []Finding{
			{FindingID: "fin-empty-ts", PluginID: "10001", URL: "https://example.com/"},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-no-ts", FindingID: "fin-empty-ts", ObservedAt: ""},
		},
	}

	merged := Merge(base, EntitiesFile{SchemaVersion: "v1"})
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(merged.Findings))
	}
	f := merged.Findings[0]
	// Both should remain empty because no occurrence has a non-empty ObservedAt.
	if f.FirstSeen != "" {
		t.Errorf("FirstSeen: want empty, got %q", f.FirstSeen)
	}
	if f.LastSeen != "" {
		t.Errorf("LastSeen: want empty, got %q", f.LastSeen)
	}
}
