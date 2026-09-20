package entities

import (
	"strings"
	"testing"
)

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

func TestValidateIdentityPathSafetyRejectsPortableFilesystemHazards(t *testing.T) {
	base := func() EntitiesFile {
		return EntitiesFile{
			SchemaVersion: "v1",
			Definitions:   []Definition{{DefinitionID: "def-safe", PluginID: "plugin-safe"}},
			Findings: []Finding{{
				FindingID:    "fin-safe",
				DefinitionID: "def-safe",
				PluginID:     "plugin-safe",
			}},
			Occurrences: []Occurrence{{
				OccurrenceID: "occ-safe",
				DefinitionID: "def-safe",
				FindingID:    "fin-safe",
			}},
		}
	}
	tests := []struct {
		name string
		path string
		edit func(*EntitiesFile)
	}{
		{name: "forward slash traversal", path: "findings[0].findingId", edit: func(ef *EntitiesFile) {
			ef.Findings[0].FindingID = "../../outside"
			ef.Occurrences[0].FindingID = "../../outside"
		}},
		{name: "backslash traversal", path: "occurrences[0].occurrenceId", edit: func(ef *EntitiesFile) {
			ef.Occurrences[0].OccurrenceID = `..\..\outside`
		}},
		{name: "control character", path: "occurrences[0].occurrenceId", edit: func(ef *EntitiesFile) {
			ef.Occurrences[0].OccurrenceID = "occ-\x01hidden"
		}},
		{name: "Windows metacharacter", path: "definitions[0].pluginId", edit: func(ef *EntitiesFile) {
			ef.Definitions[0].PluginID = "plugin:stream"
			ef.Findings[0].PluginID = "plugin:stream"
		}},
		{name: "Windows device name", path: "findings[0].findingId", edit: func(ef *EntitiesFile) {
			ef.Findings[0].FindingID = "CON"
			ef.Occurrences[0].FindingID = "CON"
		}},
		{name: "definition graph ID", path: "definitions[0].definitionId", edit: func(ef *EntitiesFile) {
			ef.Definitions[0].DefinitionID = "def/bad"
			ef.Findings[0].DefinitionID = "def/bad"
			ef.Occurrences[0].DefinitionID = "def/bad"
		}},
		{name: "analyst history graph ID", path: "findings[0].analyst.history[0].entryId", edit: func(ef *EntitiesFile) {
			ef.Findings[0].Analyst = &Analyst{History: []AnalystHistoryEntry{{EntryID: "history/bad"}}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.edit(&input)
			result := Validate(input)
			want := tc.path + ": unsafe path component"
			found := false
			for _, issue := range result.Issues {
				if issue.Error() == want {
					found = true
				}
				if strings.Contains(issue.Error(), "outside") || strings.Contains(issue.Error(), "hidden") || strings.Contains(issue.Error(), "stream") {
					t.Fatalf("diagnostic leaked unsafe identity: %q", issue.Error())
				}
			}
			if !found {
				t.Fatalf("missing %q in %+v", want, result.Issues)
			}
		})
	}
}

func TestValidateIdentityPathSafetyPreservesSupportedProducerCharacters(t *testing.T) {
	input := EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []Definition{{
			DefinitionID: "def-ümlaut [v2]",
			PluginID:     "custom.rule@v2",
		}},
		Findings: []Finding{{
			FindingID:    "fin_漢字+1",
			DefinitionID: "def-ümlaut [v2]",
			PluginID:     "custom.rule@v2",
		}},
		Occurrences: []Occurrence{{
			OccurrenceID: "occ_é=1",
			DefinitionID: "def-ümlaut [v2]",
			FindingID:    "fin_漢字+1",
		}},
	}
	if result := Validate(input); !result.OK() {
		t.Fatalf("supported producer identity characters rejected: %+v", result.Issues)
	}
}
