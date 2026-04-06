package obsidian

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// minimalEF returns a small but valid EntitiesFile with one definition, one
// finding, and one occurrence. Callers can mutate before passing to WriteVault.
func minimalEF(occurrenceID string) entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-1", PluginID: "10001", Alert: "Test Alert"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-1", DefinitionID: "def-1", PluginID: "10001", URL: "http://example.com/", Method: "GET"},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: occurrenceID,
				FindingID:    "find-1",
				DefinitionID: "def-1",
				URL:          "http://example.com/",
				Method:       "GET",
			},
		},
	}
}

// TestWriteVault_loadOccurrenceMeta_preservesAnalystStatus verifies that
// analyst.status written in a first vault pass is preserved after a second
// WriteVault call (confirming loadOccurrenceMeta runs before RemoveAll).
func TestWriteVault_loadOccurrenceMeta_preservesAnalystStatus(t *testing.T) {
	t.Helper()

	root := t.TempDir()
	const occID = "occ-preserve-test"

	ef := minimalEF(occID)

	// First write — no analyst status yet.
	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("first WriteVault: %v", err)
	}

	// Inject analyst.status directly into the written occurrence file,
	// simulating an analyst triaging inside Obsidian.
	occDir := filepath.Join(root, "occurrences")
	entries, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir occurrences: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one occurrence file after first WriteVault")
	}

	var occFile string
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			occFile = filepath.Join(occDir, e.Name())
			break
		}
	}
	if occFile == "" {
		t.Fatal("no .md file found in occurrences dir")
	}

	raw, err := os.ReadFile(occFile)
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}

	// Replace the existing analyst.status value in the frontmatter with "confirm",
	// simulating an analyst triaging the occurrence inside Obsidian.
	content := string(raw)
	if !strings.HasPrefix(content, "---") {
		t.Fatal("occurrence file does not start with YAML frontmatter delimiter")
	}
	if !strings.Contains(content, "analyst.status:") {
		t.Fatal("occurrence file frontmatter does not contain analyst.status key")
	}
	// Replace whatever value analyst.status currently holds with "confirm".
	re := strings.NewReplacer(
		`analyst.status: "open"`, `analyst.status: confirm`,
		`analyst.status: open`, `analyst.status: confirm`,
	)
	content = re.Replace(content)
	if !strings.Contains(content, "analyst.status: confirm") {
		t.Fatal("failed to inject analyst.status: confirm into occurrence frontmatter")
	}
	if err := os.WriteFile(occFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile inject analyst.status: %v", err)
	}

	// Second WriteVault — same entities, no Analyst field set in the struct.
	// loadOccurrenceMeta must run before RemoveAll; otherwise the injected
	// analyst.status will be lost.
	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("second WriteVault: %v", err)
	}

	// Find the re-written occurrence file.
	entries2, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir after second WriteVault: %v", err)
	}
	var occFile2 string
	for _, e := range entries2 {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			occFile2 = filepath.Join(occDir, e.Name())
			break
		}
	}
	if occFile2 == "" {
		t.Fatal("no .md file found in occurrences dir after second WriteVault")
	}

	raw2, err := os.ReadFile(occFile2)
	if err != nil {
		t.Fatalf("ReadFile after second WriteVault: %v", err)
	}

	// writeYAML quotes string values, so we accept both quoted and unquoted forms.
	out2 := string(raw2)
	if !strings.Contains(out2, `analyst.status: "confirm"`) && !strings.Contains(out2, "analyst.status: confirm") {
		t.Errorf("expected analyst.status: confirm in re-written occurrence frontmatter, got:\n%s", out2)
	}
}

// --- Story 2.1: WriteVault happy path ---

func minimalEF2(occIDs []string) entities.EntitiesFile {
	occs := make([]entities.Occurrence, len(occIDs))
	for i, id := range occIDs {
		occs[i] = entities.Occurrence{
			OccurrenceID: id,
			FindingID:    "find-1",
			DefinitionID: "def-1",
			URL:          "http://example.com/",
			Method:       "GET",
		}
	}
	// Second occurrence gets an analyst status.
	if len(occs) >= 2 {
		occs[1].Analyst = &entities.Analyst{Status: "confirm"}
	}
	return entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-1", PluginID: "10001", Alert: "Test Alert"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-1", DefinitionID: "def-1", PluginID: "10001", URL: "http://example.com/", Method: "GET"},
		},
		Occurrences: occs,
	}
}

func TestWriteVault_HappyPath(t *testing.T) {
	tests := []struct {
		name   string
		occIDs []string
	}{
		{
			name:   "two occurrences one open one confirmed",
			occIDs: []string{"occ-happyaaa", "occ-happybbb"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ef := minimalEF2(tc.occIDs)

			if err := WriteVault(root, ef, Options{}); err != nil {
				t.Fatalf("WriteVault: %v", err)
			}

			// Definition page exists.
			defEntries, err := os.ReadDir(filepath.Join(root, "definitions"))
			if err != nil {
				t.Fatalf("ReadDir definitions: %v", err)
			}
			if len(defEntries) == 0 {
				t.Fatal("expected at least one definition page")
			}

			// Finding page exists.
			findEntries, err := os.ReadDir(filepath.Join(root, "findings"))
			if err != nil {
				t.Fatalf("ReadDir findings: %v", err)
			}
			if len(findEntries) == 0 {
				t.Fatal("expected at least one finding page")
			}

			// Both occurrence pages exist.
			occEntries, err := os.ReadDir(filepath.Join(root, "occurrences"))
			if err != nil {
				t.Fatalf("ReadDir occurrences: %v", err)
			}
			if len(occEntries) != len(tc.occIDs) {
				t.Fatalf("expected %d occurrence pages, got %d", len(tc.occIDs), len(occEntries))
			}

			// INDEX.md exists.
			indexPath := filepath.Join(root, "INDEX.md")
			if _, err := os.Stat(indexPath); err != nil {
				t.Fatalf("INDEX.md missing: %v", err)
			}

			// triage-board.md exists.
			tbPath := filepath.Join(root, "triage-board.md")
			if _, err := os.Stat(tbPath); err != nil {
				t.Fatalf("triage-board.md missing: %v", err)
			}

			// Finding page contains the finding ID.
			findData, err := os.ReadFile(filepath.Join(root, "findings", findEntries[0].Name()))
			if err != nil {
				t.Fatalf("ReadFile finding page: %v", err)
			}
			if !strings.Contains(string(findData), "find-1") {
				t.Errorf("finding page does not contain finding ID 'find-1':\n%s", string(findData))
			}

			// INDEX.md contains the definition name.
			indexData, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatalf("ReadFile INDEX.md: %v", err)
			}
			if !strings.Contains(string(indexData), "Test Alert") {
				t.Errorf("INDEX.md does not contain definition name 'Test Alert':\n%s", string(indexData))
			}
		})
	}
}

// --- Story: TriageGuidanceFn injection ---

// TestWriteVault_TriageGuidanceFn_InjectsSection verifies that when
// Options.TriageGuidanceFn is set, the returned tips appear in the occurrence
// page under a "Triage guidance" heading.
func TestWriteVault_TriageGuidanceFn_InjectsSection(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-guidance-test")

	const expectedTip = "Check the plugin documentation before triaging."
	opts := Options{
		TriageGuidanceFn: func(pluginID string) []string {
			return []string{expectedTip}
		},
	}

	if err := WriteVault(root, ef, opts); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	occDir := filepath.Join(root, "occurrences")
	entries, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir occurrences: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no occurrence files written")
	}

	data, err := os.ReadFile(filepath.Join(occDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "Triage guidance") {
		t.Errorf("occurrence page missing 'Triage guidance' heading:\n%s", content)
	}
	if !strings.Contains(content, expectedTip) {
		t.Errorf("occurrence page missing injected tip %q:\n%s", expectedTip, content)
	}
}

// TestWriteVault_TriageGuidanceFn_NilFn_NoSection verifies that when
// Options.TriageGuidanceFn is nil (not injected), the "Triage guidance" section
// is absent from the occurrence page.
func TestWriteVault_TriageGuidanceFn_NilFn_NoSection(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-no-guidance-test")

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	occDir := filepath.Join(root, "occurrences")
	entries, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir occurrences: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no occurrence files written")
	}

	data, err := os.ReadFile(filepath.Join(occDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}
	if strings.Contains(string(data), "Triage guidance") {
		t.Errorf("occurrence page should not contain 'Triage guidance' when TriageGuidanceFn is nil")
	}
}

// TestWriteVault_TriageGuidanceFn_EmptyTips_NoSection verifies that when
// TriageGuidanceFn returns an empty slice, the "Triage guidance" section is
// not written (avoids an empty heading in the output).
func TestWriteVault_TriageGuidanceFn_EmptyTips_NoSection(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-empty-tips-test")

	opts := Options{
		TriageGuidanceFn: func(_ string) []string { return nil },
	}
	if err := WriteVault(root, ef, opts); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	occDir := filepath.Join(root, "occurrences")
	entries, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir occurrences: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no occurrence files written")
	}

	data, err := os.ReadFile(filepath.Join(occDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}
	if strings.Contains(string(data), "Triage guidance") {
		t.Errorf("occurrence page should not contain 'Triage guidance' when fn returns empty tips")
	}
}

// --- Story 2.3: Triage board counts ---

func makeOccurrence(id, findingID, definitionID, status string) entities.Occurrence {
	o := entities.Occurrence{
		OccurrenceID: id,
		FindingID:    findingID,
		DefinitionID: definitionID,
		URL:          "http://example.com/",
		Method:       "GET",
	}
	if status != "" {
		o.Analyst = &entities.Analyst{Status: status}
	}
	return o
}

func TestWriteVault_TriageBoardCounts(t *testing.T) {
	// 5 open, 3 triaged, 2 fp — all under the same finding/definition.
	var occs []entities.Occurrence
	for i := 0; i < 5; i++ {
		occs = append(occs, makeOccurrence(fmt.Sprintf("occ-open%04d", i), "find-tb", "def-tb", ""))
	}
	for i := 0; i < 3; i++ {
		occs = append(occs, makeOccurrence(fmt.Sprintf("occ-tria%04d", i), "find-tb", "def-tb", "triaged"))
	}
	for i := 0; i < 2; i++ {
		occs = append(occs, makeOccurrence(fmt.Sprintf("occ-fp%04d", i), "find-tb", "def-tb", "fp"))
	}

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-tb", PluginID: "99001", Alert: "TB Alert"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-tb", DefinitionID: "def-tb", PluginID: "99001", URL: "http://example.com/", Method: "GET"},
		},
		Occurrences: occs,
	}

	root := t.TempDir()
	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	tbData, err := os.ReadFile(filepath.Join(root, "triage-board.md"))
	if err != nil {
		t.Fatalf("ReadFile triage-board.md: %v", err)
	}
	tb := string(tbData)

	// The triage board table rows are "| Label | issueCount | occCount |"
	// Check that "open" and count 5 appear on the same line.
	checkCountInBoard := func(label string, count int) {
		t.Helper()
		needle := strconv.Itoa(count)
		for _, line := range strings.Split(tb, "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, strings.ToLower(label)) && strings.Contains(line, needle) {
				return
			}
		}
		t.Errorf("triage-board.md: expected a line containing %q and %d\nboard content:\n%s", label, count, tb)
	}

	checkCountInBoard("open", 5)
	checkCountInBoard("triaged", 3)
	checkCountInBoard("false positive", 2) // statusOrder uses "False positive" label for "fp"
}

// TestWriteVault_DefinitionPage_FalsePositiveConditions verifies that a definition
// with FalsePositiveConditions renders a "## False Positive Conditions" section
// containing both condition strings.
func TestWriteVault_DefinitionPage_FalsePositiveConditions(t *testing.T) {
	root := t.TempDir()

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-fp",
				PluginID:     "10098",
				Alert:        "Cross-Domain Misconfiguration",
				Remediation: &entities.Remediation{
					Summary: "Configure CORS correctly.",
					FalsePositiveConditions: []string{
						"Public CDN endpoints with wildcard CORS are expected.",
						"Third-party analytics scripts are legitimate cross-domain access.",
					},
				},
			},
		},
		Findings:    []entities.Finding{},
		Occurrences: []entities.Occurrence{},
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	defEntries, err := os.ReadDir(filepath.Join(root, "definitions"))
	if err != nil {
		t.Fatalf("ReadDir definitions: %v", err)
	}
	if len(defEntries) == 0 {
		t.Fatal("no definition files written")
	}

	defFile := filepath.Join(root, "definitions", defEntries[0].Name())
	raw, err := os.ReadFile(defFile)
	if err != nil {
		t.Fatalf("ReadFile definition: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "## False Positive Conditions") {
		t.Errorf("expected '## False Positive Conditions' section in definition page, got:\n%s", body)
	}
	if !strings.Contains(body, "Public CDN endpoints with wildcard CORS are expected.") {
		t.Errorf("expected first FP condition in definition page, got:\n%s", body)
	}
	if !strings.Contains(body, "Third-party analytics scripts are legitimate cross-domain access.") {
		t.Errorf("expected second FP condition in definition page, got:\n%s", body)
	}
}
