package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// TestWriteVault_DoesNotLeakLifecycleFieldsToFrontmatter guards the epic-#71
// contract: priorStatus, acceptedUntil, and history are pipeline-only fields.
// If they leak into YAML frontmatter, every scan re-writes the frontmatter
// block and blows up git diffs in vault repos. This test fails loudly if a
// future change exposes any of the three lifecycle fields as a YAML key.
func TestWriteVault_DoesNotLeakLifecycleFieldsToFrontmatter(t *testing.T) {
	ef := minimalEF("occ-lifecycle-1")
	ef.Findings[0].Analyst = &entities.Analyst{
		Status:        "fp",
		Owner:         "alice",
		PriorStatus:   "open",
		AcceptedUntil: "2026-12-31T00:00:00Z",
		History: []entities.AnalystHistoryEntry{
			entities.NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "routine triage", "2026-04-21T10:00:00Z"),
		},
	}
	ef.Occurrences[0].Analyst = &entities.Analyst{
		Status:        "fp",
		PriorStatus:   "open",
		AcceptedUntil: "2026-12-31T00:00:00Z",
		History: []entities.AnalystHistoryEntry{
			entities.NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "routine triage", "2026-04-21T10:00:00Z"),
		},
	}

	root := t.TempDir()
	if err := WriteVault(root, ef, Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	// Walk every markdown file and inspect the YAML frontmatter block.
	var filesChecked int
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fm := frontmatterBlock(string(data))
		if fm == "" {
			return nil
		}
		filesChecked++
		for _, banned := range []string{
			"analyst.priorStatus",
			"analyst.acceptedUntil",
			"analyst.history",
			"priorStatus:",
			"acceptedUntil:",
			"history:",
		} {
			if strings.Contains(fm, banned) {
				t.Errorf("frontmatter in %s leaks lifecycle field %q:\n%s", path, banned, fm)
			}
		}
		return nil
	})
	if filesChecked == 0 {
		t.Fatal("no markdown files with frontmatter checked")
	}
}

// frontmatterBlock extracts the YAML block between the first pair of `---`
// delimiters at the top of a markdown file. Returns "" if absent.
func frontmatterBlock(md string) string {
	md = strings.TrimLeft(md, "\r\n")
	if !strings.HasPrefix(md, "---") {
		return ""
	}
	rest := strings.TrimPrefix(md, "---")
	rest = strings.TrimLeft(rest, "\r\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return ""
	}
	return rest[:end]
}
