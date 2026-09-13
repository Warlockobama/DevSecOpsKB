package ziputil

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestZipExcludesItselfAndKeepsFiles(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "output.zip")
	if err := os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := Zip(out, dir); err != nil {
			t.Fatal(err)
		}
		z, err := zip.OpenReader(out)
		if err != nil {
			t.Fatal(err)
		}
		if len(z.File) != 1 || z.File[0].Name != "safe.txt" {
			t.Fatalf("unexpected members: %+v", z.File)
		}
		z.Close()
	}
	before, _ := os.ReadFile(out)
	if err := Zip(out, out); err == nil {
		t.Fatal("self input accepted")
	}
	after, _ := os.ReadFile(out)
	if string(before) != string(after) {
		t.Fatal("self input truncated existing archive")
	}
}

func TestZipRejectsMissingBeforeReplacingOutput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "output.zip")
	os.WriteFile(out, []byte("existing"), 0600)
	if err := Zip(out, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing accepted")
	}
	after, _ := os.ReadFile(out)
	if string(after) != "existing" {
		t.Fatal("inventory failure truncated output")
	}
}
