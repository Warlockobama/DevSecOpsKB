package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultPolicy: defaults must be non-zero on every field — they're the
// safety net when no YAML is present, and a zero default would silently
// disable a behavior nobody asked to disable.
func TestDefaultPolicy(t *testing.T) {
	d := DefaultPolicy()
	if !d.AutoReopenOnRecurrence {
		t.Error("AutoReopenOnRecurrence default must be true (slice 1b shipped enabled)")
	}
	if d.FindingFPSuppressionThreshold <= 0 {
		t.Errorf("FindingFPSuppressionThreshold default must be >0, got %d", d.FindingFPSuppressionThreshold)
	}
	if d.FindingFPSuppressionExpiryDays <= 0 {
		t.Errorf("FindingFPSuppressionExpiryDays default must be >0, got %d", d.FindingFPSuppressionExpiryDays)
	}
	if d.RuleTuneScanThreshold <= 0 {
		t.Errorf("RuleTuneScanThreshold default must be >0, got %d", d.RuleTuneScanThreshold)
	}
	if d.AcceptedDefaultExpiryDays <= 0 {
		t.Errorf("AcceptedDefaultExpiryDays default must be >0, got %d", d.AcceptedDefaultExpiryDays)
	}
}

// TestLoadPolicy_NoFile: with no YAML on disk and projectRoot pointing at an
// empty dir, LoadPolicy must return DefaultPolicy() and an empty source path.
// Use t.TempDir for projectRoot AND override HOME so the user-config-dir branch
// also resolves to a known-empty location.
func TestLoadPolicy_NoFile(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	p, src, err := LoadPolicy(root)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if src != "" {
		t.Errorf("source: want empty (defaults), got %q", src)
	}
	if p != DefaultPolicy() {
		t.Errorf("policy: want defaults %+v, got %+v", DefaultPolicy(), p)
	}
}

// TestLoadPolicy_ProjectRootWins: when both the project root and the user
// config dir contain a triage-policy.yaml, the project-root copy must win.
// This is the "vault travels with the policy" guarantee — checked-in YAML
// is always authoritative over a user's per-machine override.
func TestLoadPolicy_ProjectRootWins(t *testing.T) {
	root := t.TempDir()
	home := withCleanHome(t)

	// User-home copy says threshold=99
	userDir := filepath.Join(home, ".config", "devsecopskb")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(userDir, PolicyFileName),
		"findingFPSuppressionThreshold: 99\n")

	// Project-root copy says threshold=7 — this should win
	projPath := filepath.Join(root, PolicyFileName)
	mustWrite(t, projPath, "findingFPSuppressionThreshold: 7\n")

	p, src, err := LoadPolicy(root)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if src != projPath {
		t.Errorf("source: want %q, got %q", projPath, src)
	}
	if p.FindingFPSuppressionThreshold != 7 {
		t.Errorf("threshold: project-root must win (want 7), got %d", p.FindingFPSuppressionThreshold)
	}
}

// TestLoadPolicy_PartialYAMLPreservesDefaults: a YAML that only sets one field
// must NOT zero-out the others. This is the whole point of mergeOntoDefaults
// — a user who overrides one knob shouldn't accidentally disable everything.
func TestLoadPolicy_PartialYAMLPreservesDefaults(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	mustWrite(t, filepath.Join(root, PolicyFileName),
		"findingFPSuppressionThreshold: 11\n")

	p, _, err := LoadPolicy(root)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	d := DefaultPolicy()
	if p.FindingFPSuppressionThreshold != 11 {
		t.Errorf("override field: want 11, got %d", p.FindingFPSuppressionThreshold)
	}
	if p.AutoReopenOnRecurrence != d.AutoReopenOnRecurrence {
		t.Errorf("AutoReopenOnRecurrence: partial YAML must not clobber default (want %v, got %v)",
			d.AutoReopenOnRecurrence, p.AutoReopenOnRecurrence)
	}
	if p.RuleTuneScanThreshold != d.RuleTuneScanThreshold {
		t.Errorf("RuleTuneScanThreshold: partial YAML must not clobber default (want %d, got %d)",
			d.RuleTuneScanThreshold, p.RuleTuneScanThreshold)
	}
	if p.AcceptedDefaultExpiryDays != d.AcceptedDefaultExpiryDays {
		t.Errorf("AcceptedDefaultExpiryDays: partial YAML must not clobber default (want %d, got %d)",
			d.AcceptedDefaultExpiryDays, p.AcceptedDefaultExpiryDays)
	}
}

// TestLoadPolicy_InvalidYAML: a malformed YAML must surface as an error
// rather than silently dropping back to defaults — operator needs to know
// their config is broken before pipelines drift.
func TestLoadPolicy_InvalidYAML(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	mustWrite(t, filepath.Join(root, PolicyFileName), "this: : is not: valid: yaml:::\n  - bad")
	_, _, err := LoadPolicy(root)
	if err == nil {
		t.Fatal("expected parse error for malformed YAML, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parse failure, got %v", err)
	}
}

// TestWriteCommentedDefault_RoundTrip: the YAML written by WriteCommentedDefault
// must round-trip cleanly back through LoadPolicy and produce DefaultPolicy().
// This is the contract `zap-kb config init` promises — what you get out the
// box matches what the binary uses when no file is present.
func TestWriteCommentedDefault_RoundTrip(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	path := filepath.Join(root, PolicyFileName)
	if err := WriteCommentedDefault(path); err != nil {
		t.Fatalf("WriteCommentedDefault: %v", err)
	}
	// File should exist and contain comment lines (operator-readable).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if !strings.Contains(string(data), "#") {
		t.Error("written file must contain operator-readable comments")
	}
	p, src, err := LoadPolicy(root)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if src != path {
		t.Errorf("source: want %q, got %q", path, src)
	}
	if p != DefaultPolicy() {
		t.Errorf("round-trip: want defaults %+v, got %+v", DefaultPolicy(), p)
	}
}

// TestWriteCommentedDefault_RefusesOverwrite: must not clobber an existing file.
// Policy is org-level state; an accidental `config init` shouldn't blow away
// hand-tuned thresholds.
func TestWriteCommentedDefault_RefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, PolicyFileName)
	mustWrite(t, path, "autoReopenOnRecurrence: false\n")
	err := WriteCommentedDefault(path)
	if err == nil {
		t.Fatal("expected error when target file exists, got nil")
	}
	// File must be untouched
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "autoReopenOnRecurrence: false") {
		t.Error("existing file was modified despite refusal")
	}
}

// TestWritePolicy_Overwrites: WritePolicy must succeed even when the target
// file already exists (the user just confirmed values in the wizard).
func TestWritePolicy_Overwrites(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	path := filepath.Join(root, PolicyFileName)
	mustWrite(t, path, "autoReopenOnRecurrence: false\n")

	p := DefaultPolicy()
	p.AutoReopenOnRecurrence = true
	p.FindingFPSuppressionThreshold = 7

	if err := WritePolicy(path, p); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after write: %v", err)
	}
	if !strings.Contains(string(data), "autoReopenOnRecurrence: true") {
		t.Errorf("written file should contain updated value, got:\n%s", data)
	}
	if !strings.Contains(string(data), "#") {
		t.Error("written file must contain operator-readable comments")
	}
}

// TestWritePolicy_RoundTrip: the YAML written by WritePolicy must round-trip
// cleanly back through LoadPolicy and reproduce the same TriagePolicy values.
// This locks the "byte-for-byte same shape" contract stated in the doc comment.
func TestWritePolicy_RoundTrip(t *testing.T) {
	root := t.TempDir()
	withCleanHome(t)
	path := filepath.Join(root, PolicyFileName)

	want := TriagePolicy{
		AutoReopenOnRecurrence:         false,
		FindingFPSuppressionThreshold:  7,
		FindingFPSuppressionExpiryDays: 45,
		RuleTuneScanThreshold:          10,
		AcceptedDefaultExpiryDays:      365,
	}
	if err := WritePolicy(path, want); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	got, src, err := LoadPolicy(root)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if src != path {
		t.Errorf("source: want %q, got %q", path, src)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n  want %+v\n   got %+v", want, got)
	}
}

// withCleanHome points HOME / XDG_CONFIG_HOME / APPDATA at a fresh temp dir
// so tests never accidentally pick up a real user's triage-policy.yaml.
// Returns the temp HOME path so tests can plant fixtures inside it when
// they want to exercise the user-config-dir branch.
func withCleanHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	return home
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
