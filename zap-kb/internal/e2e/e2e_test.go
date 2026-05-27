package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/confluence"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
)

func loadFixture(t *testing.T) entities.EntitiesFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_entities.json"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	var ef entities.EntitiesFile
	if err := json.Unmarshal(raw, &ef); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return ef
}

// TestE2E_IngestVaultConfluenceDryRun exercises the full pipeline:
// fixture entities → Obsidian vault → Confluence dry-run export.
func TestE2E_IngestVaultConfluenceDryRun(t *testing.T) {
	ef := loadFixture(t)
	vaultDir := t.TempDir()

	// Step 1: write vault.
	if err := obsidian.WriteVault(vaultDir, ef, obsidian.Options{}); err != nil {
		t.Fatalf("WriteVault: %v", err)
	}

	// Step 2: assert all 3 finding pages exist under findings/.
	findDir := filepath.Join(vaultDir, "findings")
	findEntries, err := os.ReadDir(findDir)
	if err != nil {
		t.Fatalf("read findings dir: %v", err)
	}
	if got := countMD(findEntries); got != 3 {
		t.Errorf("findings: want 3 .md pages, got %d", got)
	}

	// Step 3: assert INDEX.md contains both definition names.
	indexPath := filepath.Join(vaultDir, "INDEX.md")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read INDEX.md: %v", err)
	}
	indexContent := string(indexBytes)
	for _, defName := range []string{
		"Content Security Policy (CSP) Header Not Set",
		"X-Content-Type-Options Header Missing",
	} {
		if !strings.Contains(indexContent, defName) {
			t.Errorf("INDEX.md does not contain definition name %q", defName)
		}
	}

	// Step 4: assert triage-board.md uses Jira workflow buckets, not local KB status.
	// The fixture has no Jira cases, so all generated issues and occurrences are
	// counted under the explicit coverage bucket.
	triagePath := filepath.Join(vaultDir, "triage-board.md")
	triageBytes, err := os.ReadFile(triagePath)
	if err != nil {
		t.Fatalf("read triage-board.md: %v", err)
	}
	if !triageBoardWorkflowCount(string(triageBytes), "No Jira case", 3, 5) {
		t.Errorf("triage-board.md: expected No Jira case counts 3 issues / 5 occurrences\ncontent:\n%s", triageBytes)
	}

	// Step 5: confluence dry-run — assert no error.
	opts := confluence.VaultOptions{
		BaseURL:  "https://confluence.example.com",
		Username: "test-user",
		APIToken: "test-token",
		SpaceKey: "KB",
		DryRun:   true,
		Entities: &ef,
	}
	if _, err := confluence.ExportVault(context.Background(), vaultDir, opts); err != nil {
		t.Errorf("ExportVault dry-run: %v", err)
	}
}

// countMD counts .md files in a directory listing.
func countMD(entries []os.DirEntry) int {
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			n++
		}
	}
	return n
}

// triageBoardWorkflowCount returns true when the triage-board markdown contains
// a Jira workflow row whose issue and occurrence columns match.
// Row format written by obsidian.WriteVault:
//
//	| <workflow bucket> | <issueCount> | <occCount> |
func triageBoardWorkflowCount(content, bucket string, wantIssueCount, wantOccCount int) bool {
	wantIssues := fmt.Sprintf("%d", wantIssueCount)
	wantOccs := fmt.Sprintf("%d", wantOccCount)
	for _, line := range strings.Split(content, "\n") {
		cols := strings.Split(line, "|")
		// Split on "|" yields: ["", " bucket ", " issueCount ", " occCount ", ""]
		if len(cols) < 4 {
			continue
		}
		if strings.TrimSpace(cols[1]) != bucket {
			continue
		}
		if strings.TrimSpace(cols[2]) == wantIssues && strings.TrimSpace(cols[3]) == wantOccs {
			return true
		}
	}
	return false
}
