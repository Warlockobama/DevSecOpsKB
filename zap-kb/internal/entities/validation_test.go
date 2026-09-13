package entities

import "testing"

func TestValidateAcceptsDeclaredEmptyAndDefinitionsOnly(t *testing.T) {
	tests := []EntitiesFile{
		{
			SchemaVersion: "v1",
			GeneratedAt:   "2026-09-12T12:00:00Z",
			SourceTool:    "zap",
			Definitions:   []Definition{},
			Findings:      []Finding{},
			Occurrences:   []Occurrence{},
		},
		{
			SchemaVersion: "v1",
			Definitions:   []Definition{{DefinitionID: "def-1", PluginID: "1"}},
			Findings:      []Finding{},
			Occurrences:   []Occurrence{},
		},
	}
	for i, input := range tests {
		if result := Validate(input); !result.OK() {
			t.Fatalf("case %d: %v", i, result.Err())
		}
	}
}

func TestValidateChecksNestedTimestampsAndReferences(t *testing.T) {
	input := EntitiesFile{
		SchemaVersion: "v1",
		Definitions:   []Definition{{DefinitionID: "def-1", PluginID: "1"}},
		Findings: []Finding{{
			FindingID:    "fin-1",
			DefinitionID: "def-1",
			PluginID:     "1",
			FirstSeen:    "2026-09-12T13:00:00Z",
			LastSeen:     "2026-09-12T12:00:00Z",
			Analyst: &Analyst{
				UpdatedAt: "not-a-time",
				History: []AnalystHistoryEntry{
					{EntryID: "history-1", UpdatedAt: "also-not-a-time"},
					{EntryID: "history-1"},
				},
			},
			Suppression: &Suppression{Scope: "occurrence", OccurrenceRef: "occ-other"},
			Recurrence:  &RecurrenceInfo{RecurredAt: "not-a-time"},
		}},
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-1",
			DefinitionID: "def-1",
			FindingID:    "fin-1",
			ObservedAt:   "not-a-time",
		}},
	}
	result := Validate(input)
	wants := map[string]bool{
		"findings[0].firstSeen/findings[0].lastSeen: timestamp range is reversed": false,
		"findings[0].analyst.updatedAt: invalid RFC3339 timestamp":                false,
		"findings[0].analyst.history[0].updatedAt: invalid RFC3339 timestamp":     false,
		"findings[0].analyst.history[1].entryId: duplicate ID":                    false,
		"findings[0].recurrence.recurredAt: invalid RFC3339 timestamp":            false,
		"occurrences[0].observedAt: invalid RFC3339 timestamp":                    false,
		"findings[0].suppression.occurrenceRef: dangling reference":               false,
	}
	for _, issue := range result.Issues {
		if _, ok := wants[issue.Error()]; ok {
			wants[issue.Error()] = true
		}
	}
	for issue, seen := range wants {
		if !seen {
			t.Errorf("missing issue %q in %+v", issue, result.Issues)
		}
	}
}
