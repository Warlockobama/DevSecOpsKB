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
			w.WriteHeader(http.StatusOK)
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

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
