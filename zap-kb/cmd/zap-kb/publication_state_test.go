package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateImmutableInputPathsRejectsDirectAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entities.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := validateImmutableInputPaths(
		map[string]string{"-entities-in": path},
		map[string]string{"-out": path},
	)
	if err == nil || !strings.Contains(err.Error(), "aliases immutable") {
		t.Fatalf("error = %v, want immutable alias rejection", err)
	}
}

func TestValidateImmutableInputPathsRejectsHardLinkAlias(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "entities.json")
	output := filepath.Join(dir, "derived.json")
	if err := os.WriteFile(input, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, output); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := validateImmutableInputPaths(map[string]string{"input": input}, map[string]string{"output": output}); err == nil {
		t.Fatal("expected hard-link alias rejection")
	}
}

func TestDefaultPublicationStateDirUsesInputSibling(t *testing.T) {
	input := filepath.Join("ingest", "entities.json")
	want := filepath.Join("ingest", ".zap-kb-publication-state")
	if got := defaultPublicationStateDir("", "", input); got != want {
		t.Fatalf("state dir = %q, want %q", got, want)
	}
	if got := defaultPublicationStateDir("explicit", input); got != "explicit" {
		t.Fatalf("explicit state dir = %q", got)
	}
}

func TestCLIRejectsSourceOutputAliasBeforeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entities.json")
	raw, err := json.Marshal(testEntitiesFile())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"zap-kb", "-wizard=false", "-init", "-entities-in=" + path, "-format=entities", "-out=" + path}
	if code := executeCLI(runMain); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatal("aliased source was mutated before rejection")
	}
}
