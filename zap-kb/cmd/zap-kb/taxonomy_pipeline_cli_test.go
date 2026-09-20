package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

const taxonomyTraceFixture = `{"schema":"detection-trace.v1","signals":[{"rule":"basket-items-collection","weight":3}]}`

func TestCLICustomTaxonomyAcrossEntitiesRunAndRenderedOutput(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.run.json")
	fixture := taxonomyPipelineFixture()
	if err := runartifact.Write(input, runartifact.Artifact{
		Schema:   runartifact.SchemaV1,
		Meta:     runartifact.Meta{SourceTool: fixture.SourceTool, GeneratedAt: fixture.GeneratedAt, ScanLabel: "taxonomy-synthetic"},
		Entities: fixture,
	}); err != nil {
		t.Fatalf("write input fixture: %v", err)
	}

	entitiesOut := filepath.Join(dir, "entities.json")
	runOut := filepath.Join(dir, "first.run.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities", "-run-in="+input,
		"-out="+entitiesOut, "-run-out="+runOut,
		"-include-mitre=false", "-include-cvss=false",
	)

	first, _, err := runartifact.ReadEntities(entitiesOut)
	if err != nil {
		t.Fatalf("read entities output: %v", err)
	}
	firstRun, err := runartifact.Read(runOut)
	if err != nil {
		t.Fatalf("read run output: %v", err)
	}
	assertTaxonomyPipelineResult(t, first)
	assertTaxonomyPipelineResult(t, firstRun.Entities)

	vault := filepath.Join(dir, "vault")
	secondRunOut := filepath.Join(dir, "second.run.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=obsidian", "-entities-in="+entitiesOut,
		"-obsidian-dir="+vault, "-run-out="+secondRunOut,
		"-include-mitre=false", "-include-cvss=false",
	)
	secondRun, err := runartifact.Read(secondRunOut)
	if err != nil {
		t.Fatalf("read repeated-import run output: %v", err)
	}
	assertTaxonomyPipelineResult(t, secondRun.Entities)
	if !reflect.DeepEqual(entityIdentities(first), entityIdentities(secondRun.Entities)) {
		t.Fatalf("identities changed on repeated import:\nfirst=%v\nsecond=%v", entityIdentities(first), entityIdentities(secondRun.Entities))
	}

	assertRenderedDefinition(t, vault, secondRun.Entities.Definitions[0], "CWE-200", "taxonomy-unmapped-custom")
	assertRenderedDefinitionExcludes(t, vault, secondRun.Entities.Definitions[0], "CWE-639")
	assertRenderedDefinition(t, vault, secondRun.Entities.Definitions[1], "CWE-639", "CAPEC: 122")
	assertRenderedDefinition(t, vault, secondRun.Entities.Definitions[2], "CWE-639", "CAPEC: 122")
	tracePage, err := os.ReadFile(filepath.Join(vault, "occurrences", "occurrence-a.md"))
	if err != nil {
		t.Fatalf("read rendered detection trace: %v", err)
	}
	if !strings.Contains(string(tracePage), `"schema":"detection-trace.v1"`) || !strings.Contains(string(tracePage), `"rule":"basket-items-collection"`) {
		t.Fatalf("rendered occurrence lost detection trace: %s", tracePage)
	}
}

func taxonomyPipelineFixture() entities.EntitiesFile {
	definitions := []entities.Definition{
		{
			DefinitionID: "def-basket-items-original",
			PluginID:     "zap-authenticated-basket-item-enumeration",
			Origin:       entities.DefinitionOriginTool,
			Alert:        "Authenticated basket item enumeration",
			Taxonomy: &entities.Taxonomy{
				CWEID:             200,
				CWEName:           "Exposure of Sensitive Information to an Unauthorized Actor",
				CWEURI:            "https://cwe.mitre.org/data/definitions/200.html",
				CAPECIDs:          []int{118},
				OWASPTop10:        []string{"A05:2021"},
				Tags:              []string{"portable-fixture"},
				MappingConfidence: "analyst-reviewed",
				Sources:           []entities.TaxonomySource{{Name: "Imported analyst review", Version: "fixture-v1"}},
			},
		},
		{
			DefinitionID: "def-basket-object-legacy",
			PluginID:     "zap-authenticated-basket-object-reference-exposure",
			Alert:        "Authenticated basket object reference exposure",
		},
		{
			DefinitionID: "def-basket-object-current",
			PluginID:     "custom-zap-auth-basket-object-reference",
			Origin:       entities.DefinitionOriginCustom,
			Alert:        "Authenticated basket object reference",
			Taxonomy:     &entities.Taxonomy{CWEID: 200, MappingConfidence: "scanner-cwe"},
		},
		{
			DefinitionID: "def-native-zap",
			PluginID:     "zap-10038",
			Alert:        "Content Security Policy Header Not Set",
		},
	}
	findings := make([]entities.Finding, 0, len(definitions))
	occurrences := make([]entities.Occurrence, 0, len(definitions))
	for i, definition := range definitions {
		findingID := "finding-" + string(rune('a'+i))
		occurrenceID := "occurrence-" + string(rune('a'+i))
		finding := entities.Finding{
			FindingID: findingID, DefinitionID: definition.DefinitionID, PluginID: definition.PluginID,
			URL: "https://fixture.invalid/rule/" + definition.PluginID, Method: "GET", Risk: "Medium", RiskCode: "2", Occurrences: 1,
		}
		occurrence := entities.Occurrence{
			OccurrenceID: occurrenceID, DefinitionID: definition.DefinitionID, FindingID: findingID,
			ScanLabel: "taxonomy-synthetic", ObservedAt: "2026-09-12T16:00:00Z",
			URL: finding.URL, Method: finding.Method, Risk: finding.Risk, RiskCode: finding.RiskCode,
		}
		if i == 0 {
			finding.Analyst = &entities.Analyst{
				Status: "triaged", Owner: "fixture-analyst", Tags: []string{"reviewed"}, Notes: "Imported review remains authoritative.",
				UpdatedAt: "2026-09-12T15:00:00Z",
				History:   []entities.AnalystHistoryEntry{{EntryID: "history-taxonomy-review", Status: "triaged", ScanLabel: "taxonomy-synthetic", UpdatedAt: "2026-09-12T15:00:00Z"}},
			}
			occurrence.Other = taxonomyTraceFixture
		}
		findings = append(findings, finding)
		occurrences = append(occurrences, occurrence)
	}
	return entities.EntitiesFile{
		SchemaVersion: "v1", GeneratedAt: "2026-09-12T16:00:00Z", SourceTool: "zap",
		Definitions: definitions, Findings: findings, Occurrences: occurrences,
	}
}

func assertTaxonomyPipelineResult(t *testing.T, got entities.EntitiesFile) {
	t.Helper()
	if len(got.Definitions) != 4 || len(got.Findings) != 4 || len(got.Occurrences) != 4 {
		t.Fatalf("graph shape changed: definitions=%d findings=%d occurrences=%d", len(got.Definitions), len(got.Findings), len(got.Occurrences))
	}

	basket := got.Definitions[0]
	if basket.DefinitionID != "def-basket-items-original" || basket.PluginID != "zap-authenticated-basket-item-enumeration" || basket.Origin != entities.DefinitionOriginCustom {
		t.Fatalf("basket-items identity/origin changed incorrectly: %+v", basket)
	}
	wantImported := entities.Taxonomy{
		CWEID: 200, CWEName: "Exposure of Sensitive Information to an Unauthorized Actor", CWEURI: "https://cwe.mitre.org/data/definitions/200.html",
		CAPECIDs: []int{118}, OWASPTop10: []string{"A05:2021"}, Tags: []string{"portable-fixture", "taxonomy-unmapped-custom"},
		MappingConfidence: "analyst-reviewed", Sources: []entities.TaxonomySource{{Name: "Imported analyst review", Version: "fixture-v1"}},
	}
	if basket.Taxonomy == nil || !reflect.DeepEqual(*basket.Taxonomy, wantImported) {
		t.Fatalf("basket-items imported taxonomy was not preserved with an explicit gap:\n got=%+v\nwant=%+v", basket.Taxonomy, wantImported)
	}

	for _, index := range []int{1, 2} {
		definition := got.Definitions[index]
		if definition.Origin != entities.DefinitionOriginCustom || definition.Taxonomy == nil || definition.Taxonomy.CWEID != 639 ||
			!reflect.DeepEqual(definition.Taxonomy.CAPECIDs, []int{122}) || len(definition.Taxonomy.ATTACK) != 0 || len(definition.Taxonomy.ATTACKTechniques) != 0 {
			t.Fatalf("object-reference mapping/origin is incomplete for %q: %+v", definition.PluginID, definition)
		}
	}
	if native := got.Definitions[3]; native.DefinitionID != "def-native-zap" || native.PluginID != "zap-10038" || native.Origin != entities.DefinitionOriginTool {
		t.Fatalf("numeric native ZAP identity/origin changed: %+v", native)
	}
	analyst := got.Findings[0].Analyst
	if analyst == nil || analyst.Status != "triaged" || analyst.Owner != "fixture-analyst" || !reflect.DeepEqual(analyst.Tags, []string{"reviewed"}) || len(analyst.History) != 1 || analyst.History[0].EntryID != "history-taxonomy-review" {
		t.Fatalf("reviewed analyst data changed: %+v", analyst)
	}
	if got.Occurrences[0].Other != taxonomyTraceFixture {
		t.Fatalf("detection trace changed: %q", got.Occurrences[0].Other)
	}
}

func entityIdentities(ef entities.EntitiesFile) []string {
	identities := make([]string, 0, len(ef.Definitions)+len(ef.Findings)+len(ef.Occurrences))
	for _, definition := range ef.Definitions {
		identities = append(identities, definition.DefinitionID+"|"+definition.PluginID)
	}
	for _, finding := range ef.Findings {
		identities = append(identities, finding.FindingID+"|"+finding.DefinitionID+"|"+finding.PluginID)
	}
	for _, occurrence := range ef.Occurrences {
		identities = append(identities, occurrence.OccurrenceID+"|"+occurrence.DefinitionID+"|"+occurrence.FindingID)
	}
	return identities
}

func assertRenderedDefinition(t *testing.T, vault string, definition entities.Definition, markers ...string) {
	t.Helper()
	path := filepath.Join(vault, "definitions", obsidian.DefinitionPageName(definition)+".md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rendered definition %q: %v", definition.PluginID, err)
	}
	for _, marker := range markers {
		if !strings.Contains(string(raw), marker) {
			t.Errorf("rendered definition %q does not contain %q", definition.PluginID, marker)
		}
	}
}

func assertRenderedDefinitionExcludes(t *testing.T, vault string, definition entities.Definition, marker string) {
	t.Helper()
	path := filepath.Join(vault, "definitions", obsidian.DefinitionPageName(definition)+".md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rendered definition %q: %v", definition.PluginID, err)
	}
	if strings.Contains(string(raw), marker) {
		t.Errorf("rendered definition %q unexpectedly contains %q", definition.PluginID, marker)
	}
}
