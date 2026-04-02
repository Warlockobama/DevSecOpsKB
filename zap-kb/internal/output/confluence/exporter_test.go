package confluence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExport_CreateNewPage(t *testing.T) {
	// Search returns no existing page; POST creates it.
	var gotPOST bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			gotPOST = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "123"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Hello")

	err := Export(context.Background(), dir, Options{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotPOST {
		t.Error("expected POST for new page")
	}
}

func TestExport_UpdateExistingPage(t *testing.T) {
	// Search returns one existing page; PUT updates it with bumped version.
	var gotPUT bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"results": []any{
					map[string]any{
						"id":      "42",
						"version": map[string]any{"number": 3},
					},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/content/42":
			gotPUT = true
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			v := body["version"].(map[string]any)["number"].(float64)
			if v != 4 {
				t.Errorf("expected version 4, got %v", v)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Updated")

	err := Export(context.Background(), dir, Options{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotPUT {
		t.Error("expected PUT request for existing page")
	}
}

func TestExport_ErrorBodyCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"message":"space does not exist"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Hi")

	err := Export(context.Background(), dir, Options{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "NOPE",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "space does not exist") {
		t.Errorf("expected error body in message, got: %v", err)
	}
}

func TestExport_DryRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call in dry-run: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Dry")

	err := Export(context.Background(), dir, Options{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExport_MissingRequiredFields(t *testing.T) {
	err := Export(context.Background(), t.TempDir(), Options{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExportVault_FullTree(t *testing.T) {
	// Track all pages created/updated by title.
	created := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			// Always say page doesn't exist (all creates)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			created[title] = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "page-" + title})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Index")
	mustWriteFile(t, filepath.Join(dir, "DASHBOARD.md"), "# Dashboard")
	mustWriteFile(t, filepath.Join(dir, "triage-board.md"), "# Triage")
	mustWriteFile(t, filepath.Join(dir, "by-domain.md"), "# Domains")
	defsDir := filepath.Join(dir, "definitions")
	os.MkdirAll(defsDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "100003-cookie-httponly.md"), "---\nid: def-100003\n---\n# Cookie Set Without HttpOnly Flag (Plugin 100003)")
	mustWriteFile(t, filepath.Join(defsDir, "10016-missing-headers.md"), "# Missing Security Headers (Plugin 10016)")

	sum, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:     srv.URL,
		Username:    "user",
		APIToken:    "token",
		SpaceKey:    "KB",
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect: INDEX + DASHBOARD + Triage + By Domain + Definitions parent + 2 defs = 7
	total := sum.Created + sum.Updated
	if total != 7 {
		t.Errorf("expected 7 pages created, got created=%d updated=%d", sum.Created, sum.Updated)
	}
	// Verify key pages exist
	for _, title := range []string{"KB Index", "KB Dashboard", "Triage Board", "Definitions"} {
		if !created[title] {
			t.Errorf("expected page %q to be created", title)
		}
	}
}

func TestExportVault_DryRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call in dry-run: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Index")
	mustWriteFile(t, filepath.Join(dir, "DASHBOARD.md"), "# Dash")
	defsDir := filepath.Join(dir, "definitions")
	os.MkdirAll(defsDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "10001-test.md"), "# Test")

	sum, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
		DryRun:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Skipped == 0 {
		t.Error("expected skipped count in dry-run")
	}
}

func TestExport_RetryOn429(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		attempts++
		if attempts <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			w.Write([]byte("rate limited"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": "456"})
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Retry test")

	err := Export(context.Background(), dir, Options{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
	})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

func TestStripFrontmatter(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"# No frontmatter", "# No frontmatter"},
		{"---\nid: foo\n---\n# Title", "# Title"},
		{"---\na: 1\nb: 2\n---\n\nBody", "Body"},
		// Horizontal rule in body should NOT be treated as frontmatter close
		{"---\nid: x\n---\n# Title\n\n---\n\nMore content", "# Title\n\n---\n\nMore content"},
	}
	for _, c := range cases {
		got := stripFrontmatter(c.in)
		if got != c.want {
			t.Errorf("stripFrontmatter(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefTitleFromContent(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"# Cookie Set Without HttpOnly Flag (Plugin 100003)\n\n## Details", "Cookie Set Without HttpOnly Flag (Plugin 100003)"},
		{"---\nid: x\n---\n# My Alert (Plugin 999)\n\nBody", "My Alert (Plugin 999)"},
		{"No heading here", ""},
	}
	for _, c := range cases {
		got := defTitleFromContent(c.content)
		if got != c.want {
			t.Errorf("defTitleFromContent(%q) = %q, want %q", c.content, got, c.want)
		}
	}
}

func TestDefTitleFromFilename(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"100003-cookie-set-without-httponly-flag.md", "100003 Cookie Set Without Httponly Flag"},
		{"10016-missing-headers.md", "10016 Missing Headers"},
		{"100006-info-disclosure-persistence-.md", "100006 Info Disclosure Persistence"},
	}
	for _, c := range cases {
		got := defTitleFromFilename(c.in)
		if got != c.want {
			t.Errorf("defTitleFromFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
