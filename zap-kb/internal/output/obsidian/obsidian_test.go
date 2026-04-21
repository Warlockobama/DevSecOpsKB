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
	if err := WriteVault(root, ef, Options{CarryForwardOccurrenceMeta: true}); err != nil {
		t.Fatalf("first WriteVault: %v", err)
	}

	// Inject analyst.status directly into the written occurrence file,
	// simulating an analyst triaging inside Obsidian with a legacy alias.
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

	// Replace the existing analyst.status value in the frontmatter with the legacy
	// alias "confirm"; the rewritten file should canonicalize it to "triaged".
	content := string(raw)
	if !strings.HasPrefix(content, "---") {
		t.Fatal("occurrence file does not start with YAML frontmatter delimiter")
	}
	if !strings.Contains(content, "analyst.status:") {
		t.Fatal("occurrence file frontmatter does not contain analyst.status key")
	}
	// Replace whatever value analyst.status currently holds with the legacy alias "confirm".
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
	if err := WriteVault(root, ef, Options{CarryForwardOccurrenceMeta: true}); err != nil {
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
	if !strings.Contains(out2, `analyst.status: "triaged"`) && !strings.Contains(out2, "analyst.status: triaged") {
		t.Errorf("expected analyst.status to be canonicalized to triaged in re-written occurrence frontmatter, got:\n%s", out2)
	}
}

func TestWriteVault_DefaultDoesNotCarryForwardOccurrenceMeta(t *testing.T) {
	root := t.TempDir()
	const occID = "occ-no-carry-test"

	ef := minimalEF(occID)
	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("first WriteVault: %v", err)
	}

	occDir := filepath.Join(root, "occurrences")
	entries, err := os.ReadDir(occDir)
	if err != nil {
		t.Fatalf("ReadDir occurrences: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one occurrence file after first WriteVault")
	}

	occFile := filepath.Join(occDir, entries[0].Name())
	raw, err := os.ReadFile(occFile)
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}
	content := strings.NewReplacer(
		`analyst.status: "open"`, `analyst.status: confirm`,
		`analyst.status: open`, `analyst.status: confirm`,
	).Replace(string(raw))
	if err := os.WriteFile(occFile, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile inject analyst.status: %v", err)
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("second WriteVault: %v", err)
	}

	raw2, err := os.ReadFile(filepath.Join(occDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile after second WriteVault: %v", err)
	}
	out2 := string(raw2)
	if strings.Contains(out2, `analyst.status: "triaged"`) || strings.Contains(out2, "analyst.status: triaged") {
		t.Fatalf("expected stale analyst status to be dropped when carry-forward is disabled, got:\n%s", out2)
	}
	if !strings.Contains(out2, `analyst.status: "open"`) && !strings.Contains(out2, "analyst.status: open") {
		t.Fatalf("expected default open status after rebuild, got:\n%s", out2)
	}
}

// TestWriteVault_loadFindingMeta_preservesAnalystStatus verifies that hand-edits
// to finding-page YAML survive a vault rebuild when CarryForwardFindingMeta is
// enabled. Mirrors the occurrence-side test.
func TestWriteVault_loadFindingMeta_preservesAnalystStatus(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-finding-carry")

	if err := WriteVault(root, ef, Options{CarryForwardFindingMeta: true}); err != nil {
		t.Fatalf("first WriteVault: %v", err)
	}

	findDir := filepath.Join(root, "findings")
	entries, err := os.ReadDir(findDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected finding files; err=%v entries=%d", err, len(entries))
	}
	var findFile string
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			findFile = filepath.Join(findDir, e.Name())
			break
		}
	}
	if findFile == "" {
		t.Fatal("no .md file in findings dir")
	}
	raw, err := os.ReadFile(findFile)
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	// Inject analyst frontmatter lines between `---` fences. The first write
	// produced a minimal page (no analyst), so we prepend our keys to the
	// frontmatter block.
	content := string(raw)
	injected := "---\n" +
		"analyst.status: confirm\n" +
		"analyst.owner: alice@example.com\n" +
		"analyst.tags: hand-edit, important\n" +
		"analyst.ticketRefs: SEC-42\n" +
		"analyst.notes: kept across rebuild\n"
	content = strings.Replace(content, "---\n", injected, 1)
	if err := os.WriteFile(findFile, []byte(content), 0o644); err != nil {
		t.Fatalf("inject analyst frontmatter: %v", err)
	}

	// Second pass — no analyst data in the entities struct. Carry-forward must
	// rehydrate from the edited markdown and canonicalize the legacy alias.
	if err := WriteVault(root, ef, Options{CarryForwardFindingMeta: true}); err != nil {
		t.Fatalf("second WriteVault: %v", err)
	}
	out, err := os.ReadFile(findFile)
	if err != nil {
		t.Fatalf("re-read finding: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`analyst.owner`,
		`alice@example.com`,
		`SEC-42`,
		`kept across rebuild`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q preserved across rebuild; full page:\n%s", want, s)
		}
	}
	if !strings.Contains(s, `analyst.status: "triaged"`) && !strings.Contains(s, `analyst.status: triaged`) {
		t.Errorf("expected status canonicalized to triaged; got:\n%s", s)
	}
}

// TestWriteVault_DefaultDoesNotCarryForwardFindingMeta verifies that without
// the opt-in flag, hand-edits to finding YAML are overwritten. Matches the
// safety-by-default posture of CarryForwardOccurrenceMeta.
func TestWriteVault_DefaultDoesNotCarryForwardFindingMeta(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-finding-no-carry")

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("first WriteVault: %v", err)
	}
	findDir := filepath.Join(root, "findings")
	entries, _ := os.ReadDir(findDir)
	if len(entries) == 0 {
		t.Fatal("expected a finding file")
	}
	findFile := filepath.Join(findDir, entries[0].Name())
	raw, _ := os.ReadFile(findFile)
	content := strings.Replace(string(raw), "---\n", "---\nanalyst.owner: alice@example.com\n", 1)
	if err := os.WriteFile(findFile, []byte(content), 0o644); err != nil {
		t.Fatalf("inject owner: %v", err)
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("second WriteVault: %v", err)
	}
	out, _ := os.ReadFile(findFile)
	if strings.Contains(string(out), "alice@example.com") {
		t.Errorf("default mode should not carry forward finding owner; got:\n%s", string(out))
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
			name:   "two occurrences one open one canonicalized triaged",
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

// --- Issue #39: Triage board open findings queue ---

// TestWriteVault_TriageBoardOpenFindingsQueue verifies that triage-board.md
// contains a "## Open findings queue" section with severity-ordered finding
// links for open/untriaged findings.
func TestWriteVault_TriageBoardOpenFindingsQueue(t *testing.T) {
	root := t.TempDir()

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-h", PluginID: "40012", Alert: "XSS Reflected"},
			{DefinitionID: "def-m", PluginID: "10020", Alert: "X-Frame-Options Missing"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-h", DefinitionID: "def-h", PluginID: "40012", URL: "http://example.com/search", Method: "GET", Risk: "High", RiskCode: "3"},
			{FindingID: "find-m", DefinitionID: "def-m", PluginID: "10020", URL: "http://example.com/home", Method: "GET", Risk: "Medium", RiskCode: "2"},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-h1", FindingID: "find-h", DefinitionID: "def-h", URL: "http://example.com/search", Method: "GET", Risk: "High", RiskCode: "3"},
			{OccurrenceID: "occ-m1", FindingID: "find-m", DefinitionID: "def-m", URL: "http://example.com/home", Method: "GET", Risk: "Medium", RiskCode: "2"},
		},
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	tbData, err := os.ReadFile(filepath.Join(root, "triage-board.md"))
	if err != nil {
		t.Fatalf("ReadFile triage-board.md: %v", err)
	}
	tb := string(tbData)

	if !strings.Contains(tb, "## Open findings queue") {
		t.Errorf("triage-board.md missing '## Open findings queue' section:\n%s", tb)
	}
	if !strings.Contains(tb, "### High") {
		t.Errorf("triage-board.md missing '### High' band in open findings queue:\n%s", tb)
	}
	if !strings.Contains(tb, "### Medium") {
		t.Errorf("triage-board.md missing '### Medium' band in open findings queue:\n%s", tb)
	}

	// High must appear before Medium.
	highIdx := strings.Index(tb, "### High")
	medIdx := strings.Index(tb, "### Medium")
	if highIdx < 0 || medIdx < 0 {
		t.Fatalf("could not locate severity bands")
	}
	if highIdx >= medIdx {
		t.Errorf("High severity band must appear before Medium; highIdx=%d medIdx=%d", highIdx, medIdx)
	}

	// Both finding links must appear.
	if !strings.Contains(tb, "find-h") {
		t.Errorf("triage-board.md missing High finding link:\n%s", tb)
	}
	if !strings.Contains(tb, "find-m") {
		t.Errorf("triage-board.md missing Medium finding link:\n%s", tb)
	}
}

// --- Issue #43: Definition truncation notice navigation link ---

// TestWriteVault_DefinitionTruncationLink verifies that when findings are
// truncated, the notice includes the navigation link to INDEX.md#issues.
func TestWriteVault_DefinitionTruncationLink(t *testing.T) {
	root := t.TempDir()

	// maxFindingsPerSeverity in the definition page is 10; create 11 to trigger truncation.
	def := entities.Definition{DefinitionID: "def-trunc", PluginID: "10001", Alert: "Test Alert"}
	findings := make([]entities.Finding, 11)
	occs := make([]entities.Occurrence, 11)
	for i := 0; i < 11; i++ {
		fid := fmt.Sprintf("find-trunc%02d", i)
		oid := fmt.Sprintf("occ-trunc%02d", i)
		findings[i] = entities.Finding{
			FindingID:    fid,
			DefinitionID: "def-trunc",
			PluginID:     "10001",
			URL:          fmt.Sprintf("http://example.com/path%d", i),
			Method:       "GET",
			Risk:         "High",
			RiskCode:     "3",
		}
		occs[i] = entities.Occurrence{
			OccurrenceID: oid,
			FindingID:    fid,
			DefinitionID: "def-trunc",
			URL:          fmt.Sprintf("http://example.com/path%d", i),
			Method:       "GET",
			Risk:         "High",
			RiskCode:     "3",
		}
	}

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      findings,
		Occurrences:   occs,
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

	const wantLink = "[[../INDEX.md#issues|see full list]]"
	if !strings.Contains(body, wantLink) {
		t.Errorf("definition page missing truncation navigation link %q:\n%s", wantLink, body)
	}
}

// --- Issue #46: defaultBodyTruncateBytes ---

// TestDefaultBodyTruncateBytes verifies the constant value is 4096.
func TestDefaultBodyTruncateBytes(t *testing.T) {
	if defaultBodyTruncateBytes != 4096 {
		t.Errorf("defaultBodyTruncateBytes = %d, want 4096", defaultBodyTruncateBytes)
	}
}

// --- Issue #48: Operational rules segregated in INDEX.md ---

// TestWriteVault_OperationalRulesSegregated verifies that a finding with
// pluginID 10116 appears in the operational section and not in the main issues table.
func TestWriteVault_OperationalRulesSegregated(t *testing.T) {
	root := t.TempDir()

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-normal", PluginID: "10020", Alert: "X-Frame-Options Missing"},
			{DefinitionID: "def-op", PluginID: "10116", Alert: "ZAP is Out of Date"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-normal", DefinitionID: "def-normal", PluginID: "10020", URL: "http://example.com/", Method: "GET", Risk: "Medium", RiskCode: "2"},
			{FindingID: "find-op", DefinitionID: "def-op", PluginID: "10116", URL: "http://example.com/", Method: "GET", Risk: "Informational", RiskCode: "0"},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-normal", FindingID: "find-normal", DefinitionID: "def-normal", URL: "http://example.com/", Method: "GET"},
			{OccurrenceID: "occ-op", FindingID: "find-op", DefinitionID: "def-op", URL: "http://example.com/", Method: "GET"},
		},
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	indexData, err := os.ReadFile(filepath.Join(root, "INDEX.md"))
	if err != nil {
		t.Fatalf("ReadFile INDEX.md: %v", err)
	}
	index := string(indexData)

	// Operational section must exist.
	if !strings.Contains(index, "## Operational / Tool info") {
		t.Errorf("INDEX.md missing '## Operational / Tool info' section:\n%s", index)
	}

	// find-op must appear in the operational section.
	opIdx := strings.Index(index, "## Operational / Tool info")
	if opIdx < 0 {
		t.Fatal("could not locate operational section")
	}
	opSection := index[opIdx:]
	if !strings.Contains(opSection, "find-op") {
		t.Errorf("operational section missing 'find-op':\n%s", opSection)
	}

	// find-op must NOT appear in the main issues table (before the operational section).
	mainSection := index[:opIdx]
	issuesIdx := strings.Index(mainSection, "## Issues")
	if issuesIdx < 0 {
		t.Fatalf("INDEX.md missing '## Issues' section before operational section:\n%s", mainSection)
	}
	issuesTable := mainSection[issuesIdx:]
	if strings.Contains(issuesTable, "find-op") {
		t.Errorf("main issues table must NOT contain 'find-op' (operational finding), got:\n%s", issuesTable)
	}

	// Normal finding must remain in the main issues table.
	if !strings.Contains(issuesTable, "find-normal") {
		t.Errorf("main issues table missing 'find-normal':\n%s", issuesTable)
	}
}

// TestOccurrenceWorkflow_ScanLabel verifies that the Workflow section of an
// occurrence page contains "- Scan: <label>" when ScanLabel is set.
func TestOccurrenceWorkflow_ScanLabel(t *testing.T) {
	root := t.TempDir()
	ef := minimalEF("occ-workflow-scan")
	ef.Occurrences[0].ScanLabel = "my-scan-label"
	ef.Occurrences[0].ObservedAt = "2026-04-05T00:00:00Z"

	if err := WriteVault(root, ef, Options{ScanLabel: "my-scan-label"}); err != nil {
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

	raw, err := os.ReadFile(filepath.Join(occDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile occurrence: %v", err)
	}
	body := string(raw)

	// Locate the Workflow section.
	workflowIdx := strings.Index(body, "## Workflow")
	if workflowIdx < 0 {
		t.Fatalf("## Workflow section not found in occurrence page:\n%s", body)
	}
	workflowSection := body[workflowIdx:]
	if !strings.Contains(workflowSection, "- Scan: my-scan-label") {
		t.Errorf("Workflow section missing '- Scan: my-scan-label':\n%s", workflowSection)
	}
}

// TestByDomain_PerScanBreakdown verifies that by-domain.md contains a
// "## Per scan breakdown" section when 2+ distinct scan labels are present,
// and that both scan label names appear in that section.
func TestByDomain_PerScanBreakdown(t *testing.T) {
	root := t.TempDir()

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-05T00:00:00Z",
		Definitions: []entities.Definition{
			{DefinitionID: "def-1", PluginID: "10001", Alert: "Test Alert"},
		},
		Findings: []entities.Finding{
			{FindingID: "find-1", DefinitionID: "def-1", PluginID: "10001", URL: "http://example.com/path", Method: "GET"},
			{FindingID: "find-2", DefinitionID: "def-1", PluginID: "10001", URL: "http://example.com/other", Method: "GET"},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-scan-a",
				FindingID:    "find-1",
				DefinitionID: "def-1",
				URL:          "http://example.com/path",
				Method:       "GET",
				ScanLabel:    "scan-alpha",
				ObservedAt:   "2026-04-03T10:00:00Z",
			},
			{
				OccurrenceID: "occ-scan-b",
				FindingID:    "find-2",
				DefinitionID: "def-1",
				URL:          "http://example.com/other",
				Method:       "GET",
				ScanLabel:    "scan-beta",
				ObservedAt:   "2026-04-04T10:00:00Z",
			},
		},
	}

	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(root, "by-domain.md"))
	if err != nil {
		t.Fatalf("ReadFile by-domain.md: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "## Per scan breakdown") {
		t.Errorf("by-domain.md missing '## Per scan breakdown' section:\n%s", body)
	}
	if !strings.Contains(body, "scan-alpha") {
		t.Errorf("by-domain.md Per scan breakdown missing 'scan-alpha':\n%s", body)
	}
	if !strings.Contains(body, "scan-beta") {
		t.Errorf("by-domain.md Per scan breakdown missing 'scan-beta':\n%s", body)
	}
}

// --- Custom rule labeling ---

// TestWriteVault_CustomRuleDefinitionHasCallout verifies that a definition whose
// pluginID starts with "zap-" receives the custom rule callout on its definition page.
func TestWriteVault_CustomRuleDefinitionHasCallout(t *testing.T) {
	root := t.TempDir()

	const customPluginID = "zap-authenticated-basket-item-enumeration"

	ef := entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-custom-1",
				PluginID:     customPluginID,
				Alert:        "Authenticated Basket Item Enumeration",
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "find-custom-1",
				DefinitionID: "def-custom-1",
				PluginID:     customPluginID,
				URL:          "http://example.com/basket",
				Method:       "GET",
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-custom-1",
				FindingID:    "find-custom-1",
				DefinitionID: "def-custom-1",
				URL:          "http://example.com/basket",
				Method:       "GET",
			},
		},
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

	data, err := os.ReadFile(filepath.Join(root, "definitions", defEntries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile definition page: %v", err)
	}
	body := string(data)

	if !strings.Contains(body, "Custom rule") {
		t.Errorf("definition page for custom pluginID %q missing 'Custom rule' callout:\n%s", customPluginID, body)
	}
	if !strings.Contains(body, "project-specific detection rule") {
		t.Errorf("definition page for custom pluginID %q missing callout body text:\n%s", customPluginID, body)
	}
}

func TestWriteVault_FindingWorkflowUsesFindingAnalystData(t *testing.T) {
	root := t.TempDir()
	findingAnalyst := &entities.Analyst{
		Status:     "triaged",
		Owner:      "James",
		Tags:       []string{"internet-facing", "case-ticket"},
		Notes:      "Use Jira as the workflow source of truth.",
		TicketRefs: []string{"SEC-42"},
		UpdatedAt:  "2026-04-06T14:00:00Z",
	}
	occAnalyst := &entities.Analyst{Status: "open", TicketRefs: []string{"LEGACY-1"}}
	def := entities.Definition{DefinitionID: "def-flow", PluginID: "10038", Alert: "CSP Header Not Set"}
	finding := entities.Finding{
		FindingID:    "find-flow",
		DefinitionID: def.DefinitionID,
		PluginID:     def.PluginID,
		URL:          "https://example.com/api/login",
		Method:       "GET",
		Risk:         "Medium",
		Analyst:      findingAnalyst,
	}
	occ := entities.Occurrence{
		OccurrenceID: "occ-flow",
		FindingID:    finding.FindingID,
		DefinitionID: def.DefinitionID,
		URL:          finding.URL,
		Method:       finding.Method,
		Risk:         "Medium",
		Analyst:      occAnalyst,
	}
	if err := WriteVault(root, entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-06T14:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      []entities.Finding{finding},
		Occurrences:   []entities.Occurrence{occ},
	}, Options{JiraBaseURL: "https://example.atlassian.net/jira/software/projects/KAN", JiraStatusByKey: map[string]string{"SEC-42": "In Review", "LEGACY-1": "To Do"}, JiraStatusSynced: "2026-04-08T21:00:00Z"}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "findings"))
	if err != nil {
		t.Fatalf("ReadDir findings: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 finding page, got %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(root, "findings", entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile finding page: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"- Status: Triaged (open:1)",
		"- Owners: James",
		"- Tags: internet-facing, case-ticket",
		"- Analyst cases: [SEC-42](https://example.atlassian.net/jira/software/projects/KAN/browse/SEC-42), [LEGACY-1](https://example.atlassian.net/jira/software/projects/KAN/browse/LEGACY-1)",
		"- Jira status: In Review",
		"- Workflow source: Jira analyst case (synced at publish time)",
		"- Jira sync: 2026-04-08T21:00:00Z",
		"Use Jira as the workflow source of truth.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page missing %q:\n%s", want, body)
		}
	}
}

func TestWriteVault_OccurrenceTrafficRendersHTTPBlocks(t *testing.T) {
	root := t.TempDir()
	def := entities.Definition{DefinitionID: "def-traffic", PluginID: "10001", Alert: "Traffic Alert"}
	finding := entities.Finding{FindingID: "fin-traffic", DefinitionID: def.DefinitionID, PluginID: def.PluginID, URL: "https://example.com/api/login", Method: "POST", Risk: "High"}
	occ := entities.Occurrence{
		OccurrenceID: "occ-traffic",
		FindingID:    finding.FindingID,
		DefinitionID: def.DefinitionID,
		URL:          finding.URL,
		Method:       finding.Method,
		Risk:         "High",
		Request:      &entities.HTTPRequest{Headers: []entities.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Authorization", Value: "Bearer secret-token"}}, BodySnippet: "{\"username\":\"admin\"}", BodyBytes: 20},
		Response:     &entities.HTTPResponse{StatusCode: 401, Headers: []entities.Header{{Name: "Content-Type", Value: "application/json"}, {Name: "Set-Cookie", Value: "sid=abc"}}, BodySnippet: "{\"error\":\"unauthorized\"}", BodyBytes: 24},
	}
	if err := WriteVault(root, entities.EntitiesFile{SchemaVersion: "1", GeneratedAt: "2026-04-08T21:00:00Z", Definitions: []entities.Definition{def}, Findings: []entities.Finding{finding}, Occurrences: []entities.Occurrence{occ}}, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "occurrences", "occ-traffic.md"))
	if err != nil {
		t.Fatalf("ReadFile occurrence page: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"## Traffic",
		"```http",
		"POST /api/login HTTP/1.1",
		"Host: example.com",
		"Authorization: <redacted>",
		"HTTP/1.1 401 Unauthorized",
		"Set-Cookie: <cookie>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("occurrence page missing %q:\n%s", want, body)
		}
	}
}

func TestWriteVault_TriageBoardUsesFindingStatusForIssueCounts(t *testing.T) {
	root := t.TempDir()
	def := entities.Definition{DefinitionID: "def-board", PluginID: "10001", Alert: "Board Alert"}
	finding := entities.Finding{
		FindingID:    "find-board",
		DefinitionID: def.DefinitionID,
		PluginID:     def.PluginID,
		URL:          "https://example.com/board",
		Method:       "GET",
		Risk:         "High",
		Analyst:      &entities.Analyst{Status: "triaged"},
	}
	occ := entities.Occurrence{
		OccurrenceID: "occ-board",
		FindingID:    finding.FindingID,
		DefinitionID: def.DefinitionID,
		URL:          finding.URL,
		Method:       finding.Method,
		Risk:         "High",
		Analyst:      &entities.Analyst{Status: "open"},
	}
	if err := WriteVault(root, entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-06T14:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      []entities.Finding{finding},
		Occurrences:   []entities.Occurrence{occ},
	}, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	boardData, err := os.ReadFile(filepath.Join(root, "triage-board.md"))
	if err != nil {
		t.Fatalf("ReadFile triage-board.md: %v", err)
	}
	board := string(boardData)
	if !strings.Contains(board, "| Triaged | 1 | 0 |") {
		t.Errorf("triage-board should count the issue as triaged:\n%s", board)
	}
	if !strings.Contains(board, "| Open | 0 | 1 |") {
		t.Errorf("triage-board should keep the occurrence history open:\n%s", board)
	}
}

func TestWriteVault_RecurringFalsePositiveSurfacesTuningCandidate(t *testing.T) {
	root := t.TempDir()
	def := entities.Definition{DefinitionID: "def-tuning", PluginID: "10001", Alert: "Tuning Alert"}
	finding := entities.Finding{
		FindingID:    "find-tuning",
		DefinitionID: def.DefinitionID,
		PluginID:     def.PluginID,
		URL:          "https://example.com/tuning",
		Method:       "GET",
		Risk:         "Low",
		Analyst:      &entities.Analyst{Status: "fp"},
	}
	occs := []entities.Occurrence{
		{OccurrenceID: "occ-tuning-1", FindingID: finding.FindingID, DefinitionID: def.DefinitionID, URL: finding.URL, Method: finding.Method, Risk: "Low", ScanLabel: "scan-a", Analyst: &entities.Analyst{Status: "fp"}},
		{OccurrenceID: "occ-tuning-2", FindingID: finding.FindingID, DefinitionID: def.DefinitionID, URL: finding.URL, Method: finding.Method, Risk: "Low", ScanLabel: "scan-b", Analyst: &entities.Analyst{Status: "fp"}},
	}
	if err := WriteVault(root, entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-07T12:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      []entities.Finding{finding},
		Occurrences:   occs,
	}, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	findEntries, err := os.ReadDir(filepath.Join(root, "findings"))
	if err != nil {
		t.Fatalf("ReadDir findings: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "findings", findEntries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile finding page: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "- Tuning candidate: yes (false positive across 2 scans)") || !strings.Contains(body, "add `tune-scan` to `analyst.tags`") {
		t.Fatalf("finding page missing tuning candidate note:\n%s", body)
	}

	boardData, err := os.ReadFile(filepath.Join(root, "triage-board.md"))
	if err != nil {
		t.Fatalf("ReadFile triage-board.md: %v", err)
	}
	board := string(boardData)
	if !strings.Contains(board, "## Tuning candidates") || !strings.Contains(board, "false positive across 2 scans") {
		t.Fatalf("triage board missing tuning candidates section:\n%s", board)
	}
	if !strings.Contains(board, "[[tuning-candidates|Tuning Candidates]]") {
		t.Fatalf("triage board missing link to tuning-candidates page:\n%s", board)
	}

	tcData, err := os.ReadFile(filepath.Join(root, "tuning-candidates.md"))
	if err != nil {
		t.Fatalf("ReadFile tuning-candidates.md: %v", err)
	}
	tc := string(tcData)
	for _, want := range []string{"# Tuning Candidates", "Total: **1**", finding.FindingID, "GET https://example.com/tuning"} {
		if !strings.Contains(tc, want) {
			t.Fatalf("tuning-candidates.md missing %q:\n%s", want, tc)
		}
	}
}

func TestWriteVault_TuneScanTagAppearsOnRollupPageWithoutRecurrence(t *testing.T) {
	root := t.TempDir()
	def := entities.Definition{DefinitionID: "def-tune-tag", PluginID: "20001", Alert: "Tag Only Alert"}
	finding := entities.Finding{
		FindingID:    "find-tune-tag",
		DefinitionID: def.DefinitionID,
		PluginID:     def.PluginID,
		URL:          "https://example.com/tagonly",
		Method:       "POST",
		Risk:         "Medium",
		Analyst:      &entities.Analyst{Status: "open", Tags: []string{"tune-scan"}},
	}
	occ := entities.Occurrence{
		OccurrenceID: "occ-tune-tag-1",
		FindingID:    finding.FindingID,
		DefinitionID: def.DefinitionID,
		URL:          finding.URL,
		Method:       finding.Method,
		Risk:         "Medium",
		ScanLabel:    "scan-1",
	}
	if err := WriteVault(root, entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-07T12:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      []entities.Finding{finding},
		Occurrences:   []entities.Occurrence{occ},
	}, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "tuning-candidates.md"))
	if err != nil {
		t.Fatalf("ReadFile tuning-candidates.md: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, finding.FindingID) {
		t.Fatalf("tune-scan tagged finding missing from rollup:\n%s", body)
	}
	if !strings.Contains(body, "| yes |") {
		t.Fatalf("expected `tune-scan` column = yes in rollup:\n%s", body)
	}
}

func TestWriteVault_TuningCandidatesPageEmittedWhenEmpty(t *testing.T) {
	root := t.TempDir()
	if err := WriteVault(root, minimalEF("occ-empty"), Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "tuning-candidates.md"))
	if err != nil {
		t.Fatalf("ReadFile tuning-candidates.md: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "_No tuning candidates at this time._") {
		t.Fatalf("empty tuning-candidates page missing placeholder:\n%s", body)
	}
}

func TestWriteVault_IndexQuickNavigationPublishesCompanionPages(t *testing.T) {
	root := t.TempDir()
	def := entities.Definition{DefinitionID: "def-nav", PluginID: "10001", Alert: "Navigation Alert"}
	finding := entities.Finding{
		FindingID:    "find-nav",
		DefinitionID: def.DefinitionID,
		PluginID:     def.PluginID,
		URL:          "https://example.com/nav",
		Method:       "GET",
		Risk:         "High",
	}
	occ := entities.Occurrence{
		OccurrenceID: "occ-nav",
		FindingID:    finding.FindingID,
		DefinitionID: def.DefinitionID,
		URL:          finding.URL,
		Method:       finding.Method,
		Risk:         "High",
	}
	if err := WriteVault(root, entities.EntitiesFile{
		SchemaVersion: "1",
		GeneratedAt:   "2026-04-08T12:00:00Z",
		Definitions:   []entities.Definition{def},
		Findings:      []entities.Finding{finding},
		Occurrences:   []entities.Occurrence{occ},
	}, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	indexData, err := os.ReadFile(filepath.Join(root, "INDEX.md"))
	if err != nil {
		t.Fatalf("ReadFile INDEX.md: %v", err)
	}
	indexBody := string(indexData)
	for _, want := range []string{
		"- [Issues](issues.md)",
		"- [Occurrences](occurrences.md)",
		"- [Rules](rules.md)",
		"## Priority queue",
	} {
		if !strings.Contains(indexBody, want) {
			t.Fatalf("INDEX.md missing %q:\n%s", want, indexBody)
		}
	}
	if strings.Contains(indexBody, "- [ ]") {
		t.Fatalf("INDEX.md should not contain task checkboxes in the priority queue:\n%s", indexBody)
	}
	for _, name := range []string{"issues.md", "occurrences.md", "rules.md"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("expected companion page %s to exist: %v", name, err)
		}
	}
}
