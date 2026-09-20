package obsidian

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteVaultRejectsUnsafeIdentityBeforeVaultPreparation(t *testing.T) {
	caseDir := t.TempDir()
	vault := filepath.Join(caseDir, "vault")
	keptPath := filepath.Join(vault, "findings", "kept.md")
	indexPath := filepath.Join(vault, "INDEX.md")
	siblingPath := filepath.Join(caseDir, "outside-vault.md")
	sentinels := map[string][]byte{
		keptPath:    []byte("existing finding must survive\n"),
		indexPath:   []byte("existing index must survive\n"),
		siblingPath: []byte("existing sibling must survive\n"),
	}
	for path, contents := range sentinels {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	input := minimalEF("occ-safe")
	input.Findings[0].FindingID = "../../outside-vault"
	input.Occurrences[0].FindingID = "../../outside-vault"
	err := WriteVault(vault, input, Options{})
	if err == nil {
		t.Fatal("WriteVault accepted a path-unsafe finding ID")
	}
	diagnostic := err.Error()
	if !strings.Contains(diagnostic, "findings[0].findingId: unsafe path component") {
		t.Fatalf("unexpected diagnostic: %s", diagnostic)
	}
	if strings.Contains(diagnostic, "outside-vault") {
		t.Fatalf("diagnostic leaked rejected identity: %s", diagnostic)
	}
	for path, before := range sentinels {
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read sentinel %s: %v", path, readErr)
		}
		if string(after) != string(before) {
			t.Fatalf("sentinel %s changed: %q", path, after)
		}
	}
}
