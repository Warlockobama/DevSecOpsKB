package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func testEntitiesFile() entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		GeneratedAt:   "2026-04-06T12:00:00Z",
		Definitions: []entities.Definition{{
			DefinitionID: "def-1",
			PluginID:     "10038",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-1",
			DefinitionID: "def-1",
			PluginID:     "10038",
			URL:          "https://example.com/login",
			Method:       "GET",
		}},
	}
}

func TestMergeFindingTicketKeys_DedupesAndCountsAdds(t *testing.T) {
	ent := testEntitiesFile()
	ent.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"SEC-1"}}

	added := mergeFindingTicketKeys(&ent, map[string]string{
		"fin-1": "SEC-2",
	})
	if added != 1 {
		t.Fatalf("expected 1 added ticket ref, got %d", added)
	}
	if len(ent.Findings[0].Analyst.TicketRefs) != 2 {
		t.Fatalf("expected 2 ticket refs after merge, got %v", ent.Findings[0].Analyst.TicketRefs)
	}
	added = mergeFindingTicketKeys(&ent, map[string]string{
		"fin-1": "SEC-2",
	})
	if added != 0 {
		t.Fatalf("expected duplicate ticket merge to add 0 refs, got %d", added)
	}
}

func TestCollectFindingTicketRefs_DedupesByFinding(t *testing.T) {
	ent := testEntitiesFile()
	ent.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"SEC-1", " SEC-1 ", "https://example.atlassian.net/browse/SEC-2", ""}}
	ent.Findings = append(ent.Findings, entities.Finding{
		FindingID: "fin-2",
		Analyst:   &entities.Analyst{TicketRefs: []string{"SEC-3"}},
	})

	got := collectFindingTicketRefs(ent)
	if len(got) != 2 {
		t.Fatalf("expected refs for 2 findings, got %#v", got)
	}
	if strings.Join(got["fin-1"], ",") != "SEC-1,https://example.atlassian.net/browse/SEC-2" {
		t.Fatalf("unexpected fin-1 refs: %#v", got["fin-1"])
	}
	if strings.Join(got["fin-2"], ",") != "SEC-3" {
		t.Fatalf("unexpected fin-2 refs: %#v", got["fin-2"])
	}
}

func TestShouldPersistJiraEntities_IncludesEpicRefUpdates(t *testing.T) {
	ent := testEntitiesFile()
	if !shouldPersistJiraEntities(0, 1, false, ent) {
		t.Fatal("expected definition Epic ref updates to require persistence")
	}
	if shouldPersistJiraEntities(0, 0, false, ent) {
		t.Fatal("did not expect persistence with no Jira state changes")
	}
	ent.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"SEC-42"}}
	if !shouldPersistJiraEntities(0, 0, true, ent) {
		t.Fatal("expected legacy KB status sync mode with ticket refs to require persistence")
	}
}

func TestMergeDefinitionEpicRefs_SetsAndSkipsExisting(t *testing.T) {
	ent := testEntitiesFile()
	ent.Definitions = []entities.Definition{
		{DefinitionID: "def-1", PluginID: "10038"},
		{DefinitionID: "def-2", PluginID: "10020", EpicRef: "SEC-100"},
	}
	n := mergeDefinitionEpicRefs(&ent, map[string]string{
		"def-1": "SEC-50",
		"def-2": "SEC-100", // already set — should be a no-op
	})
	if n != 1 {
		t.Fatalf("expected 1 update, got %d", n)
	}
	if ent.Definitions[0].EpicRef != "SEC-50" {
		t.Errorf("expected def-1.EpicRef=SEC-50, got %q", ent.Definitions[0].EpicRef)
	}
	if ent.Definitions[1].EpicRef != "SEC-100" {
		t.Errorf("def-2.EpicRef should remain SEC-100, got %q", ent.Definitions[1].EpicRef)
	}
	// Re-merge with a changed key updates it.
	n = mergeDefinitionEpicRefs(&ent, map[string]string{"def-1": "SEC-51"})
	if n != 1 {
		t.Fatalf("expected 1 update on re-merge, got %d", n)
	}
	if ent.Definitions[0].EpicRef != "SEC-51" {
		t.Errorf("expected updated EpicRef=SEC-51, got %q", ent.Definitions[0].EpicRef)
	}
}

func TestPersistJiraEntities_BothWritesEntitiesOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "alerts.json")
	ent := testEntitiesFile()

	savePath, err := persistJiraEntities(jiraSyncContext{Format: "both", Out: out}, ent)
	if err != nil {
		t.Fatalf("persistJiraEntities: %v", err)
	}
	want := out + ".entities.json"
	if savePath != want {
		t.Fatalf("savePath = %q, want %q", savePath, want)
	}
	raw, err := os.ReadFile(savePath)
	if err != nil {
		t.Fatalf("read persisted entities: %v", err)
	}
	var persisted entities.EntitiesFile
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("decode persisted entities: %v", err)
	}
	if persisted.SchemaVersion != ent.SchemaVersion {
		t.Fatalf("persisted entities schemaVersion = %q, want %q", persisted.SchemaVersion, ent.SchemaVersion)
	}
}

func TestPersistJiraEntities_ObsidianLeavesSourceArtifactsImmutable(t *testing.T) {
	ent := testEntitiesFile()
	savePath, err := persistJiraEntities(jiraSyncContext{
		Format: "obsidian",
		Out:    filepath.Join(t.TempDir(), "alerts.json"),
	}, ent)
	if err != nil {
		t.Fatalf("persistJiraEntities: %v", err)
	}
	if savePath != "" {
		t.Fatalf("savePath = %q, want no source write", savePath)
	}
}

func TestValidatePublishSource_RejectsAgentDataByDefault(t *testing.T) {
	ent := entities.EntitiesFile{SourceTool: "zap-agent"}
	err := validatePublishSource(ent, true, true, false, false)
	if err == nil {
		t.Fatal("expected agent publish rejection")
	}
	if !strings.Contains(err.Error(), `sourceTool="zap-agent"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePublishSource_AllowsScannerData(t *testing.T) {
	for _, source := range []string{"zap", "nuclei", "burp", ""} {
		if err := validatePublishSource(entities.EntitiesFile{SourceTool: source}, true, true, false, false); err != nil {
			t.Fatalf("source %q unexpectedly rejected: %v", source, err)
		}
	}
}

func TestValidatePublishSource_AllowsAgentOverride(t *testing.T) {
	if err := validatePublishSource(entities.EntitiesFile{SourceTool: "zap-agent"}, true, false, true, false); err != nil {
		t.Fatalf("expected override to allow agent publish, got %v", err)
	}
}

func TestHasFindingTicketRefs(t *testing.T) {
	ent := testEntitiesFile()
	if hasFindingTicketRefs(ent) {
		t.Fatal("expected no ticket refs")
	}
	ent.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"SEC-42"}}
	if !hasFindingTicketRefs(ent) {
		t.Fatal("expected finding ticket refs to be detected")
	}
}
func TestValidatePublishSource_RejectsCustomDefinitionsByDefault(t *testing.T) {
	ent := entities.EntitiesFile{
		SourceTool: "zap",
		Definitions: []entities.Definition{{
			DefinitionID: "def-zap-custom-rule",
			PluginID:     "zap-custom-rule",
			Origin:       entities.DefinitionOriginCustom,
		}},
	}
	if err := validatePublishSource(ent, true, true, false, false); err == nil {
		t.Fatal("expected custom definition publish rejection")
	} else if !strings.Contains(err.Error(), "custom definitions") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePublishSource_AllowsCustomOverride(t *testing.T) {
	ent := entities.EntitiesFile{
		SourceTool: "zap",
		Definitions: []entities.Definition{{
			DefinitionID: "def-zap-custom-rule",
			PluginID:     "zap-custom-rule",
			Origin:       entities.DefinitionOriginCustom,
		}},
	}
	if err := validatePublishSource(ent, true, true, false, true); err != nil {
		t.Fatalf("expected custom publish override, got %v", err)
	}
}

func TestContainsCustomDefinitions(t *testing.T) {
	if containsCustomDefinitions(entities.EntitiesFile{Definitions: []entities.Definition{{PluginID: "10038", Origin: entities.DefinitionOriginTool}}}) {
		t.Fatal("unexpected custom definition detection for native tool definition")
	}
	if !containsCustomDefinitions(entities.EntitiesFile{Definitions: []entities.Definition{{PluginID: "zap-custom-rule", Origin: entities.DefinitionOriginCustom}}}) {
		t.Fatal("expected custom definition detection")
	}
}

func TestParseJiraUserMap(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single pair", "alice=acc1", map[string]string{"alice": "acc1"}},
		{
			"multiple pairs with whitespace",
			"alice=acc1, bob = acc2 ,carol=acc3",
			map[string]string{"alice": "acc1", "bob": "acc2", "carol": "acc3"},
		},
		{"skips malformed", "alice=acc1,bad,=missing,key=,ok=v", map[string]string{"alice": "acc1", "ok": "v"}},
		{"all malformed returns nil", ",,bad,=,", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseJiraUserMap(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("size mismatch: got %v want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q: got %q want %q", k, got[k], v)
				}
			}
		})
	}
}
