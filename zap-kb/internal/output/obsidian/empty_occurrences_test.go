package obsidian

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestWriteVaultFindingWithoutOccurrences(t *testing.T) {
	ef := minimalEF("unused")
	ef.SchemaVersion = "v1"
	ef.Occurrences = []entities.Occurrence{}
	if err := entities.Validate(ef).Err(); err != nil {
		t.Fatalf("fixture must be valid input: %v", err)
	}
	root := t.TempDir()
	if err := WriteVault(root, ef, Options{ScanLabel: "snapshot-only"}); err != nil {
		t.Fatal(err)
	}
	finding := readOptionalVaultFile(t, root, filepath.Join("findings", "find-1.md"))
	if !strings.Contains(finding, "- Occurrences: 0") {
		t.Fatalf("missing honest zero occurrence count: %s", finding)
	}
	index := readOptionalVaultFile(t, root, "INDEX.md")
	if !strings.Contains(index, "find-1.md") || !strings.Contains(index, "snapshot-only") {
		t.Fatalf("finding and fallback scan context missing from index: %s", index)
	}
}
