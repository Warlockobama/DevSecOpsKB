package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestFreshSnapshotCarriesMatchingAnalystThenRedacts(t *testing.T) {
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "findings"), 0700); err != nil {
		t.Fatal(err)
	}
	prior := "---\nfindingId: finding-policy\nanalyst.status: triaged\nanalyst.owner: safe-owner\nanalyst.notes: PRIVATE_NOTE\nanalyst.ticketRefs: TEST-1\n---\nIgnored body PRIVATE_OLD_PAGE\n"
	os.WriteFile(filepath.Join(source, "findings", "prior.md"), []byte(prior), 0600)
	os.WriteFile(filepath.Join(source, "old.md"), []byte("PRIVATE_OLD_PAGE"), 0600)
	e := entities.EntitiesFile{SchemaVersion: "v1", SourceTool: "cactus", Definitions: []entities.Definition{{DefinitionID: "def-policy", PluginID: "1", Alert: "Useful rule"}}, Findings: []entities.Finding{{FindingID: "finding-policy", DefinitionID: "def-policy", PluginID: "1", URL: "https://example.invalid/a"}}, Occurrences: []entities.Occurrence{{OccurrenceID: "occ-policy", FindingID: "finding-policy", DefinitionID: "def-policy", URL: "https://example.invalid/a", ObservedAt: "2026-09-12T12:00:00Z", ScanLabel: "scan-policy"}}}
	for _, notes := range []bool{false, true} {
		t.Run(map[bool]string{false: "retain", true: "redact"}[notes], func(t *testing.T) {
			output := t.TempDir()
			if err := WriteVault(output, e, Options{CarryForwardFindingMeta: true, CarryForwardRoot: source, JiraBaseURL: "https://jira.invalid", JiraAssigneeByKey: map[string]string{"TEST-1": "PRIVATE_REMOTE_OWNER@example.invalid"}, Redact: entities.RedactOptions{Notes: notes, Query: true, Secrets: true}}); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(filepath.Join(output, "findings", "*.md"))
			if len(files) != 1 {
				t.Fatal("missing finding page")
			}
			raw, _ := os.ReadFile(files[0])
			text := string(raw)
			for _, safe := range []string{"triaged", "safe-owner", "TEST-1"} {
				if !strings.Contains(text, safe) {
					t.Errorf("analyst field lost: %s", safe)
				}
			}
			if strings.Contains(text, "PRIVATE_NOTE") == notes {
				t.Fatal("notes policy not applied after carry-forward")
			}
			if strings.Contains(text, "PRIVATE_REMOTE_OWNER") {
				t.Fatal("remote metadata leaked")
			}
			if strings.Contains(text, "PRIVATE_OLD_PAGE") {
				t.Fatal("stale body admitted")
			}
			if e.Findings[0].Analyst != nil {
				t.Fatal("input entities mutated")
			}
		})
	}
	after, _ := os.ReadFile(filepath.Join(source, "findings", "prior.md"))
	if string(after) != prior {
		t.Fatal("source vault changed")
	}
}
