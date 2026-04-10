package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

func testEntitiesFile() entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		GeneratedAt:   "2026-04-06T12:00:00Z",
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

func TestPersistJiraEntities_ObsidianRunArtifactPreservesEnvelope(t *testing.T) {
	runPath := filepath.Join(t.TempDir(), "run.json")
	original := runartifact.Artifact{
		Schema: "zap-kb/run/v1",
		Meta: runartifact.Meta{
			ScanLabel:  "scan-2026-04-06",
			SiteLabel:  "prod",
			SourceTool: "zap",
		},
		Entities: testEntitiesFile(),
		Alerts: []zapclient.Alert{{
			Alert:    "CSP Header Not Set",
			PluginID: "10038",
			URL:      "https://example.com/login",
		}},
	}
	if err := runartifact.Write(runPath, original); err != nil {
		t.Fatalf("seed run artifact: %v", err)
	}

	updated := testEntitiesFile()
	updated.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"SEC-42"}}
	savePath, err := persistJiraEntities(jiraSyncContext{
		Format:           "obsidian",
		RunIn:            runPath,
		RunInputArtifact: &original,
	}, updated)
	if err != nil {
		t.Fatalf("persistJiraEntities: %v", err)
	}
	if savePath != runPath {
		t.Fatalf("savePath = %q, want %q", savePath, runPath)
	}

	readBack, err := runartifact.Read(runPath)
	if err != nil {
		t.Fatalf("read updated run artifact: %v", err)
	}
	if readBack.Meta.ScanLabel != original.Meta.ScanLabel || readBack.Meta.SiteLabel != original.Meta.SiteLabel {
		t.Fatalf("run artifact metadata was not preserved: %+v", readBack.Meta)
	}
	if len(readBack.Alerts) != 1 || readBack.Alerts[0].PluginID != "10038" {
		t.Fatalf("run artifact alerts were not preserved: %+v", readBack.Alerts)
	}
	if readBack.Entities.Findings[0].Analyst == nil || len(readBack.Entities.Findings[0].Analyst.TicketRefs) != 1 || readBack.Entities.Findings[0].Analyst.TicketRefs[0] != "SEC-42" {
		t.Fatalf("updated finding ticket refs not written back: %+v", readBack.Entities.Findings[0].Analyst)
	}
}

func TestPersistJiraEntities_ObsidianRejectsOutFallback(t *testing.T) {
	ent := testEntitiesFile()
	_, err := persistJiraEntities(jiraSyncContext{
		Format: "obsidian",
		Out:    filepath.Join(t.TempDir(), "alerts.json"),
	}, ent)
	if err == nil {
		t.Fatal("expected error when obsidian writeback only has -out available")
	}
	if got := err.Error(); got != "persistJiraEntities: obsidian format requires -run-in or -entities-in to persist finding ticket keys safely" {
		t.Fatalf("unexpected error: %v", err)
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
