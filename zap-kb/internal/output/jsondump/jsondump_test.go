package jsondump

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Pins the atomic-write guarantee (assumption A10): the entities file is the
// KB system of record, persisted via this path — a crash mid-write must never
// leave a truncated file, and no temp files may linger after success.
func TestWritePrettyIsAtomicAndTidy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entities.json")

	// Seed an existing file so the write is an overwrite (the dangerous case).
	if err := WritePretty(path, map[string]string{"v": "old"}); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if err := WritePretty(path, map[string]string{"v": "new"}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if got["v"] != "new" {
		t.Fatalf("content = %q, want new", got["v"])
	}

	// No temp droppings.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}

	// Failure path (unencodable value) must not corrupt the existing file or
	// leave temp files.
	if err := WritePretty(path, map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("want error for unencodable value")
	}
	raw2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw2) != string(raw) {
		t.Fatal("failed write modified the existing file")
	}
	entries, _ = os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("failed write left temp file: %s", e.Name())
		}
	}
}
