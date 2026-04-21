package confluence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
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
		case strings.Contains(r.URL.Path, "/property"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		case strings.Contains(r.URL.Path, "/rest/api/content/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/property"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": ""}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/label"):
			w.WriteHeader(http.StatusNoContent)
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
		case strings.Contains(r.URL.Path, "/property"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		case strings.Contains(r.URL.Path, "/rest/api/content/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/property"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": ""}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/label"):
			w.WriteHeader(http.StatusNoContent)
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

	// Expect (counted in VaultSummary, excludes KB Export Summary which uses _, _, _):
	// INDEX + DASHBOARD + Triage + By Domain + Security Rule Definitions + Custom Detections +
	// 2 defs = 8 (empty Findings/Occurrences stubs are no longer created).
	total := sum.Created + sum.Updated
	if total != 8 {
		t.Logf("created pages: %v", created)
		t.Errorf("expected 8 pages created, got created=%d updated=%d", sum.Created, sum.Updated)
	}
	// Verify key pages exist (server-side, including KB Export Summary)
	for _, title := range []string{"KB Index", "KB Dashboard", "Triage Board", "Security Rule Definitions", "Custom Detections", "KB Export Summary"} {
		if !created[title] {
			t.Errorf("expected page %q to be created", title)
		}
	}
}

func TestExportVault_HierarchicalExportOmitsTopLevelFindingAndOccurrenceStubs(t *testing.T) {
	created := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			created[title] = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "page-" + title})
		case strings.Contains(r.URL.Path, "/property"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		case strings.Contains(r.URL.Path, "/rest/api/content/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/property"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": ""}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/label"):
			w.WriteHeader(http.StatusNoContent)
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
	findDir := filepath.Join(dir, "findings")
	occDir := filepath.Join(dir, "occurrences")
	os.MkdirAll(defsDir, 0o755)
	os.MkdirAll(findDir, 0o755)
	os.MkdirAll(occDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "10016-missing-headers.md"), "# Missing Security Headers (Plugin 10016)")
	mustWriteFile(t, filepath.Join(findDir, "fin-1.md"), "# Missing Security Headers")
	mustWriteFile(t, filepath.Join(occDir, "occ-1.md"), "# Missing Security Headers occurrence")

	ef := &entities.EntitiesFile{
		SchemaVersion: "v1",
		GeneratedAt:   "2026-04-08T00:00:00Z",
		SourceTool:    "zap",
		Definitions: []entities.Definition{{
			DefinitionID: "def-10016",
			PluginID:     "10016",
			Alert:        "Missing Security Headers",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-1",
			DefinitionID: "def-10016",
			PluginID:     "10016",
			URL:          "http://example.com/",
			Method:       "GET",
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-1",
			FindingID:    "fin-1",
			DefinitionID: "def-10016",
			URL:          "http://example.com/",
			Method:       "GET",
		}},
	}

	sum, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:     srv.URL,
		Username:    "user",
		APIToken:    "token",
		SpaceKey:    "KB",
		Concurrency: 1,
		Entities:    ef,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if created["Findings"] || created["Occurrences"] {
		t.Fatalf("did not expect top-level Findings/Occurrences pages in hierarchical export, got: %v", created)
	}
	for _, title := range []string{"KB Index", "KB Dashboard", "Triage Board", "Security Posture", "Security Rule Definitions", "Custom Detections", "Missing Security Headers (Plugin 10016)", "KB Export Summary"} {
		if !created[title] {
			t.Errorf("expected page %q to be created", title)
		}
	}
	if sum.Errors != 0 {
		t.Fatalf("expected no export errors, got %d", sum.Errors)
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

// --- Entity index tests ---

func TestEntityIndex_Lookup(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
				Taxonomy:     &entities.Taxonomy{CWEID: 693, CWEURI: "https://cwe.mitre.org/data/definitions/693.html"},
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "fin-aabbccdd",
				DefinitionID: "def-10038",
				PluginID:     "10038",
				URL:          "https://example.com/",
				Method:       "GET",
				Risk:         "Medium",
				Confidence:   "High",
				Occurrences:  3,
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-11223344",
				DefinitionID: "def-10038",
				FindingID:    "fin-aabbccdd",
				URL:          "https://example.com/",
				Method:       "GET",
				Risk:         "Medium",
			},
		},
	}

	ei := buildEntityIndex(ef)

	t.Run("defByFilename_with_pluginID_prefix", func(t *testing.T) {
		d := ei.defByFilename("10038-csp-header-not-set.md")
		if d == nil {
			t.Fatal("expected definition, got nil")
		}
		if d.DefinitionID != "def-10038" {
			t.Errorf("expected def-10038, got %q", d.DefinitionID)
		}
	})

	t.Run("defByFilename_def_prefixed_id", func(t *testing.T) {
		// buildEntityIndex also indexes by "def-"+pluginID
		d := ei.defByFilename("10038-anything.md")
		if d == nil {
			t.Fatal("expected definition for pluginID prefix, got nil")
		}
	})

	t.Run("defByFilename_unknown_returns_nil", func(t *testing.T) {
		d := ei.defByFilename("99999-unknown-plugin.md")
		if d != nil {
			t.Errorf("expected nil for unknown filename, got %+v", d)
		}
	})

	t.Run("findingByFilename_found", func(t *testing.T) {
		f := ei.findingByFilename("fin-aabbccdd.md")
		if f == nil {
			t.Fatal("expected finding, got nil")
		}
		if f.FindingID != "fin-aabbccdd" {
			t.Errorf("expected fin-aabbccdd, got %q", f.FindingID)
		}
	})

	t.Run("findingByFilename_unknown_returns_nil", func(t *testing.T) {
		f := ei.findingByFilename("fin-xxxxxxxx.md")
		if f != nil {
			t.Errorf("expected nil for unknown finding, got %+v", f)
		}
	})

	t.Run("occurrenceByFilename_found", func(t *testing.T) {
		o := ei.occurrenceByFilename("occ-11223344.md")
		if o == nil {
			t.Fatal("expected occurrence, got nil")
		}
		if o.OccurrenceID != "occ-11223344" {
			t.Errorf("expected occ-11223344, got %q", o.OccurrenceID)
		}
	})

	t.Run("occurrenceByFilename_unknown_returns_nil", func(t *testing.T) {
		o := ei.occurrenceByFilename("occ-xxxxxxxx.md")
		if o != nil {
			t.Errorf("expected nil for unknown occurrence, got %+v", o)
		}
	})

	t.Run("nil_entities_file_returns_empty_index", func(t *testing.T) {
		empty := buildEntityIndex(nil)
		if empty.defByFilename("10038-test.md") != nil {
			t.Error("expected nil from empty index")
		}
		if empty.findingByFilename("fin-abc.md") != nil {
			t.Error("expected nil from empty index")
		}
		if empty.occurrenceByFilename("occ-abc.md") != nil {
			t.Error("expected nil from empty index")
		}
	})
}

// --- Label builder tests ---

func TestDefLabels(t *testing.T) {
	t.Run("nil_returns_nil", func(t *testing.T) {
		labels := defLabels(nil)
		if labels != nil {
			t.Errorf("expected nil for nil def, got %v", labels)
		}
	})

	t.Run("basic_labels", func(t *testing.T) {
		def := &entities.Definition{
			DefinitionID: "def-10038",
			PluginID:     "10038",
		}
		labels := defLabels(def)
		if !contains(labels, "definition") {
			t.Errorf("expected 'definition' label, got %v", labels)
		}
		if !contains(labels, "plugin-10038") {
			t.Errorf("expected 'plugin-10038' label, got %v", labels)
		}
	})

	t.Run("with_taxonomy_cwe", func(t *testing.T) {
		def := &entities.Definition{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Taxonomy: &entities.Taxonomy{
				CWEID: 693,
			},
		}
		labels := defLabels(def)
		if !contains(labels, "cwe-693") {
			t.Errorf("expected 'cwe-693' label, got %v", labels)
		}
	})

	t.Run("with_owasp_labels", func(t *testing.T) {
		def := &entities.Definition{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Taxonomy: &entities.Taxonomy{
				OWASPTop10: []string{"A05:2021", "A03:2021"},
			},
		}
		labels := defLabels(def)
		if !contains(labels, "a05:2021") {
			t.Errorf("expected 'a05:2021' label, got %v", labels)
		}
		if !contains(labels, "a03:2021") {
			t.Errorf("expected 'a03:2021' label, got %v", labels)
		}
	})
}

func TestFindingLabels(t *testing.T) {
	t.Run("nil_returns_nil", func(t *testing.T) {
		labels := findingLabels(nil)
		if labels != nil {
			t.Errorf("expected nil for nil finding, got %v", labels)
		}
	})

	t.Run("standard_labels", func(t *testing.T) {
		f := &entities.Finding{
			FindingID: "fin-aabbccdd",
			PluginID:  "10038",
			Risk:      "Medium",
		}
		labels := findingLabels(f)
		if !contains(labels, "finding") {
			t.Errorf("expected 'finding' label, got %v", labels)
		}
		if !contains(labels, "risk-medium") {
			t.Errorf("expected 'risk-medium' label, got %v", labels)
		}
		if !contains(labels, "plugin-10038") {
			t.Errorf("expected 'plugin-10038' label, got %v", labels)
		}
	})

	t.Run("risk_lowercased", func(t *testing.T) {
		cases := []struct {
			risk      string
			wantLabel string
		}{
			{"High", "risk-high"},
			{"MEDIUM", "risk-medium"},
			{"Low", "risk-low"},
			{"Informational", "risk-informational"},
		}
		for _, c := range cases {
			f := &entities.Finding{FindingID: "fin-x", PluginID: "1", Risk: c.risk}
			labels := findingLabels(f)
			if !contains(labels, c.wantLabel) {
				t.Errorf("findingLabels risk=%q: expected %q, got %v", c.risk, c.wantLabel, labels)
			}
		}
	})

	t.Run("with_analyst_status", func(t *testing.T) {
		f := &entities.Finding{
			FindingID: "fin-x",
			PluginID:  "10038",
			Risk:      "High",
			Analyst:   &entities.Analyst{Status: "triaged"},
		}
		labels := findingLabels(f)
		if !contains(labels, "status-triaged") {
			t.Errorf("expected status label from finding analyst, got %v", labels)
		}
	})
}

func TestOccurrenceLabels(t *testing.T) {
	t.Run("nil_returns_nil", func(t *testing.T) {
		labels := occurrenceLabels(nil)
		if labels != nil {
			t.Errorf("expected nil for nil occurrence, got %v", labels)
		}
	})

	t.Run("basic_labels", func(t *testing.T) {
		o := &entities.Occurrence{
			OccurrenceID: "occ-11223344",
			Risk:         "Low",
		}
		labels := occurrenceLabels(o)
		if !contains(labels, "occurrence") {
			t.Errorf("expected 'occurrence' label, got %v", labels)
		}
		if !contains(labels, "risk-low") {
			t.Errorf("expected 'risk-low' label, got %v", labels)
		}
	})

	t.Run("with_scan_label", func(t *testing.T) {
		o := &entities.Occurrence{
			OccurrenceID: "occ-11223344",
			Risk:         "Medium",
			ScanLabel:    "prod-2024-01",
		}
		labels := occurrenceLabels(o)
		if !contains(labels, "scan-prod-2024-01") {
			t.Errorf("expected scan label, got %v", labels)
		}
	})

	t.Run("with_analyst_status", func(t *testing.T) {
		o := &entities.Occurrence{
			OccurrenceID: "occ-11223344",
			Risk:         "High",
			Analyst:      &entities.Analyst{Status: "triaged"},
		}
		labels := occurrenceLabels(o)
		if !contains(labels, "status-triaged") {
			t.Errorf("expected 'status-triaged' label, got %v", labels)
		}
	})

	t.Run("without_analyst_no_status_label", func(t *testing.T) {
		o := &entities.Occurrence{
			OccurrenceID: "occ-11223344",
			Risk:         "High",
		}
		labels := occurrenceLabels(o)
		for _, l := range labels {
			if strings.HasPrefix(l, "status-") {
				t.Errorf("unexpected status label %q when no analyst, got %v", l, labels)
			}
		}
	})
}

// --- Full integration test with entities ---

func TestExportVault_WithEntities(t *testing.T) {
	// Track which API calls were made
	var mu sync.Mutex
	labelCalls := map[string][]string{} // pageID → label names posted
	pageBodies := map[string]string{}   // page title → storage body

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})

		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			storageVal := ""
			if b, ok := body["body"].(map[string]any); ok {
				if s, ok := b["storage"].(map[string]any); ok {
					storageVal, _ = s["value"].(string)
				}
			}
			pageBodies[title] = storageVal
			pageID := "page-" + title
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": pageID})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/label"):
			// Extract page ID from path: /rest/api/content/{id}/label
			parts := strings.Split(r.URL.Path, "/")
			pageID := ""
			for i, p := range parts {
				if p == "content" && i+1 < len(parts) {
					pageID = parts[i+1]
					break
				}
			}
			var payload []map[string]any
			json.NewDecoder(r.Body).Decode(&payload)
			var names []string
			for _, l := range payload {
				if n, ok := l["name"].(string); ok {
					names = append(names, n)
				}
			}
			labelCalls[pageID] = append(labelCalls[pageID], names...)
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	// Create vault structure
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# KB Index")
	mustWriteFile(t, filepath.Join(dir, "DASHBOARD.md"), "# Dashboard")

	defsDir := filepath.Join(dir, "definitions")
	os.MkdirAll(defsDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "10038-csp-header-not-set.md"),
		"# CSP Header Not Set (Plugin 10038)\n\n## Overview\n\nContent Security Policy missing.")

	// Build entities file with taxonomy data
	ef := &entities.EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
				Taxonomy: &entities.Taxonomy{
					CWEID:      693,
					CWEURI:     "https://cwe.mitre.org/data/definitions/693.html",
					OWASPTop10: []string{"A05:2021"},
				},
			},
		},
		Findings:    []entities.Finding{},
		Occurrences: []entities.Occurrence{},
	}

	_, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:      srv.URL,
		Username:     "user",
		APIToken:     "token",
		SpaceKey:     "KB",
		Concurrency:  1,
		RequestDelay: 0,
		Entities:     ef,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify the definition page body contains Page Properties macro
	defTitle := "CSP Header Not Set (Plugin 10038)"
	defBody, ok := pageBodies[defTitle]
	if !ok {
		t.Fatalf("definition page %q was not created; pages created: %v", defTitle, pageKeys(pageBodies))
	}
	if !strings.Contains(defBody, `name="details"`) {
		t.Errorf("definition page body missing page properties macro; body snippet: %.200s", defBody)
	}

	// Verify Label API was called for the definition page
	defPageID := "page-" + defTitle
	labels, hasLabels := labelCalls[defPageID]
	if !hasLabels || len(labels) == 0 {
		t.Errorf("expected label API call for definition page %q, got: %v", defPageID, labelCalls)
	}
	// Should include "definition" and CWE label
	if !containsStr(labels, "definition") {
		t.Errorf("expected 'definition' label, got: %v", labels)
	}
	if !containsStr(labels, "cwe-693") {
		t.Errorf("expected 'cwe-693' label, got: %v", labels)
	}
}

func TestComputePostureCounts(t *testing.T) {
	ef := &entities.EntitiesFile{
		GeneratedAt: "2026-04-02T12:00:00Z",
		SourceTool:  "zap",
		Findings: []entities.Finding{
			{FindingID: "f1", Risk: "High"},
			{FindingID: "f2", Risk: "High"},
			{FindingID: "f3", Risk: "Medium"},
			{FindingID: "f4", Risk: "Low"},
			{FindingID: "f5", Risk: ""},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "o1", ScanLabel: "scan-001", ObservedAt: "2026-04-01T10:00:00Z", Analyst: &entities.Analyst{Status: "open"}},
			{OccurrenceID: "o2", ScanLabel: "scan-002", ObservedAt: "2026-04-02T10:00:00Z", Analyst: &entities.Analyst{Status: "triaged"}},
			{OccurrenceID: "o3", Analyst: &entities.Analyst{Status: "fixed"}},
			{OccurrenceID: "o4", Analyst: nil}, // defaults to "open"
		},
	}

	pc := computePostureCounts(ef)

	if pc.TotalFindings != 5 {
		t.Errorf("TotalFindings: want 5, got %d", pc.TotalFindings)
	}
	if pc.TotalOccs != 4 {
		t.Errorf("TotalOccs: want 4, got %d", pc.TotalOccs)
	}
	if pc.ByRisk["high"] != 2 {
		t.Errorf("ByRisk[high]: want 2, got %d", pc.ByRisk["high"])
	}
	if pc.ByRisk["medium"] != 1 {
		t.Errorf("ByRisk[medium]: want 1, got %d", pc.ByRisk["medium"])
	}
	if pc.ByStatus["open"] != 2 { // o1 + o4
		t.Errorf("ByStatus[open]: want 2, got %d", pc.ByStatus["open"])
	}
	if pc.ByStatus["triaged"] != 1 {
		t.Errorf("ByStatus[triaged]: want 1, got %d", pc.ByStatus["triaged"])
	}
	if pc.ByStatus["fixed"] != 1 {
		t.Errorf("ByStatus[fixed]: want 1, got %d", pc.ByStatus["fixed"])
	}
	// scan-002 has the latest ObservedAt (2026-04-02) so it wins
	if pc.ScanLabel != "scan-002" {
		t.Errorf("ScanLabel: want scan-002 (latest ObservedAt), got %q", pc.ScanLabel)
	}
	if pc.GeneratedAt != "2026-04-02T12:00:00Z" {
		t.Errorf("GeneratedAt: want 2026-04-02T12:00:00Z, got %q", pc.GeneratedAt)
	}
}

func TestComputePostureCounts_DeterministicScanLabel(t *testing.T) {
	// The scan label should come from the occurrence with the latest ObservedAt,
	// not from arbitrary iteration order.
	ef := &entities.EntitiesFile{
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "o1", ScanLabel: "old-scan", ObservedAt: "2026-01-01T00:00:00Z"},
			{OccurrenceID: "o2", ScanLabel: "latest-scan", ObservedAt: "2026-04-02T00:00:00Z"},
			{OccurrenceID: "o3", ScanLabel: "middle-scan", ObservedAt: "2026-02-01T00:00:00Z"},
		},
	}
	// Run multiple times to surface any non-determinism
	for i := 0; i < 10; i++ {
		pc := computePostureCounts(ef)
		if pc.ScanLabel != "latest-scan" {
			t.Errorf("run %d: ScanLabel = %q, want latest-scan", i, pc.ScanLabel)
		}
	}
}

func TestComputePostureCounts_NilEntities(t *testing.T) {
	pc := computePostureCounts(nil)
	if pc.TotalFindings != 0 || pc.TotalOccs != 0 {
		t.Error("nil entities should produce zero counts")
	}
}

func TestBuildPostureStorageBody(t *testing.T) {
	pc := postureCounts{
		GeneratedAt:   "2026-04-02T12:00:00Z",
		SourceTool:    "zap",
		ScanLabel:     "scan-001",
		TotalFindings: 3,
		TotalOccs:     5,
		ByRisk:        map[string]int{"high": 2, "medium": 1},
		ByStatus:      map[string]int{"open": 3, "fixed": 2},
	}
	body := buildPostureStorageBody(pc)

	if !strings.Contains(body, `name="details"`) {
		t.Error("body should contain Page Properties macro")
	}
	if !strings.Contains(body, "scan-001") {
		t.Error("body should contain scan label")
	}
	if !strings.Contains(body, "Risk Summary") {
		t.Error("body should contain Risk Summary heading")
	}
	if !strings.Contains(body, "Triage Status") {
		t.Error("body should contain Triage Status heading")
	}
	// Risk lozenge for High should appear
	if !strings.Contains(body, `name="status"`) {
		t.Error("body should contain status macro (risk lozenge)")
	}
	// Deterministic: same counts → same output
	body2 := buildPostureStorageBody(pc)
	if body != body2 {
		t.Error("buildPostureStorageBody should be deterministic")
	}
}

func TestOccurrenceProperties_CWEAndDefinition(t *testing.T) {
	// #21: CWE and Definition link should appear on occurrence pages
	ei := entityIndex{
		defs: map[string]*entities.Definition{
			"def-10038": {
				DefinitionID: "def-10038",
				Alert:        "CSP Header Not Set",
				Taxonomy: &entities.Taxonomy{
					CWEID:      693,
					CWEURI:     "https://cwe.mitre.org/data/definitions/693.html",
					OWASPTop10: []string{"A05:2021"},
				},
			},
		},
		finds:      map[string]*entities.Finding{},
		occs:       map[string]*entities.Occurrence{},
		findingObs: map[string]obsRange{},
	}
	o := &entities.Occurrence{
		OccurrenceID: "occ-aabb",
		DefinitionID: "def-10038",
		FindingID:    "fin-1234",
		Risk:         "Medium",
		Confidence:   "Low",
		URL:          "https://example.com/api",
	}
	out := prependOccurrenceProperties("BODY", o, &ei, "", nil, nil, "", "")

	if !strings.Contains(out, "CWE-693") {
		t.Error("CWE link should appear on occurrence page")
	}
	if !strings.Contains(out, "A05:2021") {
		t.Error("OWASP Top 10 should appear on occurrence page")
	}
	if !strings.Contains(out, "CSP Header Not Set") {
		t.Error("Definition link should appear on occurrence page")
	}
	if !strings.Contains(out, "ri:page") {
		t.Error("Definition should be a Confluence page link")
	}
}

func TestFindingProperties_FirstLastSeen(t *testing.T) {
	// #20: firstSeen/lastSeen computed from occurrence ObservedAt
	ei := buildEntityIndex(&entities.EntitiesFile{
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			Alert:        "CSP Header Not Set",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-abc",
			DefinitionID: "def-10038",
			Risk:         "Medium",
			Confidence:   "Low",
			URL:          "https://example.com",
			Method:       "GET",
		}},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-1", FindingID: "fin-abc", ObservedAt: "2026-01-15T10:00:00Z"},
			{OccurrenceID: "occ-2", FindingID: "fin-abc", ObservedAt: "2026-03-20T10:00:00Z"},
			{OccurrenceID: "occ-3", FindingID: "fin-abc", ObservedAt: "2026-02-01T10:00:00Z"},
		},
	})
	f := ei.finds["fin-abc"]
	out := prependFindingProperties("BODY", f, &ei, "", nil, nil, "", "", "")

	if !strings.Contains(out, "First Seen") {
		t.Error("First Seen should appear in finding properties")
	}
	if !strings.Contains(out, "Last Seen") {
		t.Error("Last Seen should appear in finding properties")
	}
	// First should be the earliest, Last the most recent
	if !strings.Contains(out, "2026-01-15") {
		t.Errorf("First Seen should be 2026-01-15, output: %.300s", out)
	}
	if !strings.Contains(out, "2026-03-20") {
		t.Errorf("Last Seen should be 2026-03-20, output: %.300s", out)
	}
}

func TestFindingProperties_SingleOccurrence_LastSeenSameRun(t *testing.T) {
	// When only one occurrence exists, Last Seen should appear with a "(same run)" annotation.
	ei := buildEntityIndex(&entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", Alert: "CSP"}},
		Findings:    []entities.Finding{{FindingID: "fin-solo", DefinitionID: "def-10038", Risk: "Low", URL: "https://x.com", Method: "GET"}},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-only", FindingID: "fin-solo", ObservedAt: "2026-03-01T00:00:00Z"},
		},
	})
	f := ei.finds["fin-solo"]
	out := prependFindingProperties("BODY", f, &ei, "", nil, nil, "", "", "")

	if !strings.Contains(out, "First Seen") {
		t.Error("First Seen should appear")
	}
	if !strings.Contains(out, "Last Seen") {
		t.Error("Last Seen should appear even when first == last")
	}
	if !strings.Contains(out, "(same run)") {
		t.Error("Last Seen should include (same run) annotation when first == last")
	}
}

func TestTriageStatusMacro_XmlEscaping(t *testing.T) {
	// Analyst-controlled status values containing XML special characters must be escaped.
	// Note: status is uppercased before escaping, so <script> → &lt;SCRIPT&gt;
	cases := []struct {
		status  string
		wantNot string // must NOT appear as a raw tag in output
		want    string // must appear (escaped uppercased form)
	}{
		{"<script>", "<script>", "&lt;SCRIPT&gt;"},
		{`"quoted"`, `"quoted"`, "&quot;QUOTED&quot;"},
		{"open&close", "open&close", "OPEN&amp;CLOSE"},
	}
	for _, tc := range cases {
		got := triageStatusMacro(tc.status)
		// The raw unescaped tag must not be a free-standing element in the output
		// (it's fine for it to appear as part of the macro name attribute, but
		// the ac:parameter value must be escaped)
		if strings.Contains(got, `<ac:parameter ac:name="title">`+tc.wantNot) {
			t.Errorf("triageStatusMacro(%q): unescaped %q found in title param: %s", tc.status, tc.wantNot, got)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("triageStatusMacro(%q): expected escaped form %q in output: %s", tc.status, tc.want, got)
		}
	}
}

func TestRiskStatusMacro_XmlEscaping(t *testing.T) {
	// Risk values from entity data should be escaped in macro attributes.
	// Input "High<inject>" → uppercased "HIGH<INJECT>" → escaped "HIGH&lt;INJECT&gt;"
	got := riskStatusMacro(`High<inject>`)
	if strings.Contains(got, `<ac:parameter name="title">HIGH<INJECT>`) {
		t.Errorf("riskStatusMacro: unescaped tag found in title param: %s", got)
	}
	if !strings.Contains(got, "HIGH&lt;INJECT&gt;") {
		t.Errorf("riskStatusMacro: expected escaped form HIGH&lt;INJECT&gt; in output: %s", got)
	}
}

func TestExportVault_HierarchicalNesting(t *testing.T) {
	// Track pageID → parentID to verify nesting
	var mu sync.Mutex
	pageParents := map[string]string{} // title → parent pageID used in creation

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			ancestors, _ := body["ancestors"].([]any)
			parentID := ""
			if len(ancestors) > 0 {
				if a, ok := ancestors[len(ancestors)-1].(map[string]any); ok {
					parentID, _ = a["id"].(string)
				}
			}
			pageParents[title] = parentID
			json.NewEncoder(w).Encode(map[string]any{"id": "pid-" + title})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/label"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# Index")

	defsDir := filepath.Join(dir, "definitions")
	findsDir := filepath.Join(dir, "findings")
	occsDir := filepath.Join(dir, "occurrences")
	os.MkdirAll(defsDir, 0o755)
	os.MkdirAll(findsDir, 0o755)
	os.MkdirAll(occsDir, 0o755)

	mustWriteFile(t, filepath.Join(defsDir, "10038-csp-header.md"),
		"# CSP Header Not Set (Plugin 10038)\n\nDescription here.")
	mustWriteFile(t, filepath.Join(findsDir, "fin-aabbccdd.md"),
		"# Issue fin-aabbccdd\n\n- Definition: [[definitions/10038-csp-header.md|CSP]]\n\n**Endpoint:** GET /api/login\n\n## Workflow\n\n- Status: open\n")
	mustWriteFile(t, filepath.Join(occsDir, "occ-11223344.md"),
		"# Occurrence occ-11223344\n\n> [!Note]\n> Risk: Medium\n\n**Endpoint:** GET /api/login\n\n## Evidence\n\n```\nevidence\n```\n")

	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Alert:        "CSP Header Not Set",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-aabbccdd",
			DefinitionID: "def-10038",
			Risk:         "Medium",
			Confidence:   "Low",
			URL:          "https://example.com/api/login",
			Method:       "GET",
			Occurrences:  1,
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-11223344",
			FindingID:    "fin-aabbccdd",
			DefinitionID: "def-10038",
			Risk:         "Medium",
			URL:          "https://example.com/api/login",
		}},
	}

	_, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:      srv.URL,
		Username:     "user",
		APIToken:     "token",
		SpaceKey:     "KB",
		Concurrency:  1,
		RequestDelay: 0,
		Entities:     ef,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Definition page should be a child of "Security Rule Definitions" parent page
	defTitle := "CSP Header Not Set (Plugin 10038)"
	defsParentID := "pid-Security Rule Definitions"
	if pageParents[defTitle] != defsParentID {
		t.Errorf("definition page parent: want %q, got %q", defsParentID, pageParents[defTitle])
	}

	// Finding page should be nested under the definition page.
	findingTitle := "Issue: CSP Header Not Set - /api/login - ccdd"
	findingParentID := "pid-" + defTitle
	if pageParents[findingTitle] != findingParentID {
		t.Errorf("finding page parent: want %q, got %q", findingParentID, pageParents[findingTitle])
	}

	// Occurrence page should be nested under the finding page.
	occurrenceTitle := "Occurrence: CSP Header Not Set - /api/login - 3344"
	occurrenceParentID := "pid-" + findingTitle
	if pageParents[occurrenceTitle] != occurrenceParentID {
		t.Errorf("occurrence page parent: want %q, got %q", occurrenceParentID, pageParents[occurrenceTitle])
	}
}

func TestStripFindingBodyForConfluence(t *testing.T) {
	input := `# Issue fin-abc — Some Rule

> [!Note]
> Risk: Medium — Confidence: Low

- Definition: [[definitions/10038-csp.md|CSP Header Not Set]]

**Endpoint:** GET /api/v1/users

## Rollup

- Occurrences: 3

## Workflow

- Status: open
- Owners: alice

### Analyst Notes

- Risk accepted: internal network only.

### Quick triage shortcuts

- Set ` + "`analyst.status`" + ` to: open | triaged | fp | accepted | fixed
- Add ticket IDs under ` + "`analyst.ticketRefs`" + ` (YAML list)
- Assign ` + "`analyst.owner`" + ` and ` + "`analyst.tags`" + ` to drive queues

### Analyst notebook

- Notes:
- Evidence links:
- Next steps:

`
	out := stripFindingBodyForConfluence(input)
	// Callout stripped
	if strings.Contains(out, "> [!Note]") {
		t.Error("callout block should be stripped")
	}
	// Endpoint stripped
	if strings.Contains(out, "**Endpoint:**") {
		t.Error("Endpoint line should be stripped")
	}
	// Triage shortcuts stripped
	if strings.Contains(out, "Quick triage shortcuts") {
		t.Error("Quick triage shortcuts section should be stripped")
	}
	if strings.Contains(out, "analyst.status") {
		t.Error("triage shortcut content should be stripped")
	}
	// Analyst notebook stripped
	if strings.Contains(out, "Analyst notebook") {
		t.Error("Analyst notebook section should be stripped")
	}
	// Useful content preserved
	if !strings.Contains(out, "## Rollup") {
		t.Error("Rollup section should be preserved")
	}
	// Definition bullet stripped — duplicated in Page Properties table
	if strings.Contains(out, "Definition:") {
		t.Error("Definition bullet should be stripped (already in Page Properties)")
	}
	// H1 stripped — Confluence page title already set
	if strings.Contains(out, "# Issue fin-abc") {
		t.Error("H1 heading should be stripped")
	}
	// Workflow section and its plain-text status lines stripped — not interactive in Confluence
	if strings.Contains(out, "## Workflow") {
		t.Error("Workflow section should be stripped")
	}
	if strings.Contains(out, "- Status: open") {
		t.Error("Workflow status line should be stripped")
	}
	// Analyst Notes survive — contains real analyst content
	if !strings.Contains(out, "### Analyst Notes") {
		t.Error("Analyst Notes section should be preserved")
	}
	if !strings.Contains(out, "Risk accepted") {
		t.Error("Analyst Notes content should be preserved")
	}
}

func TestStripOccurrenceBodyForConfluence(t *testing.T) {
	input := `# Occurrence occ-abc — Some Rule

> [!Warning]
> Risk: High (3) — Confidence: Medium

- Definition: [[definitions/10038-csp.md|CSP Header Not Set]]

**Endpoint:** GET /api/v1/data

## Evidence

` + "```" + `
<script>alert(1)</script>
` + "```" + `
`
	out := stripOccurrenceBodyForConfluence(input)
	if strings.Contains(out, "> [!Warning]") {
		t.Error("callout block should be stripped")
	}
	if strings.Contains(out, "**Endpoint:**") {
		t.Error("Endpoint line should be stripped")
	}
	if !strings.Contains(out, "## Evidence") {
		t.Error("Evidence section should be preserved")
	}
	// Definition and Issue bullets stripped — duplicated in Page Properties
	if strings.Contains(out, "Definition:") {
		t.Error("Definition bullet should be stripped")
	}
}

func TestFindingPageTitle(t *testing.T) {
	ei := entityIndex{
		defs: map[string]*entities.Definition{
			"def-10038": {
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "Content Security Policy Header Not Set",
			},
		},
		finds: map[string]*entities.Finding{},
		occs:  map[string]*entities.Occurrence{},
	}

	f := &entities.Finding{
		FindingID:    "fin-abc12345",
		DefinitionID: "def-10038",
		URL:          "https://example.com/api/v1/users",
		Method:       "GET",
	}
	title := findingPageTitle(f, &ei)
	if !strings.HasPrefix(title, "Issue: ") {
		t.Errorf("title should start with Issue:, got: %s", title)
	}
	if !strings.Contains(title, "Content Security Policy Header Not Set") {
		t.Errorf("title should contain rule name, got: %s", title)
	}
	if !strings.Contains(title, "/api/v1/users") {
		t.Errorf("title should contain URL path, got: %s", title)
	}
	if !strings.HasSuffix(title, "2345") {
		t.Errorf("title should end with last 4 chars of finding ID, got: %s", title)
	}

	// No entity — returns empty
	if got := findingPageTitle(nil, &ei); got != "" {
		t.Errorf("nil finding should return empty, got: %s", got)
	}
}

func TestOccurrencePageTitle(t *testing.T) {
	ei := entityIndex{
		defs: map[string]*entities.Definition{
			"def-10038": {
				DefinitionID: "def-10038",
				Alert:        "CSP Header Not Set",
			},
		},
		finds: map[string]*entities.Finding{},
		occs:  map[string]*entities.Occurrence{},
	}
	o := &entities.Occurrence{
		OccurrenceID: "occ-deadbeef",
		DefinitionID: "def-10038",
		URL:          "https://example.com/main.js",
	}
	title := occurrencePageTitle(o, &ei)
	if !strings.HasPrefix(title, "Occurrence: ") {
		t.Errorf("title should start with Occurrence:, got: %s", title)
	}
	if !strings.Contains(title, "CSP Header Not Set") {
		t.Errorf("title should contain rule name, got: %s", title)
	}
	if !strings.Contains(title, "/main.js") {
		t.Errorf("title should contain URL path, got: %s", title)
	}
	if !strings.HasSuffix(title, "beef") {
		t.Errorf("title should end with last 4 chars of occurrence ID, got: %s", title)
	}
}

func TestTriageStatusMacro(t *testing.T) {
	cases := []struct{ status, wantColor string }{
		{"open", "Blue"},
		{"triaged", "Yellow"},
		{"fp", "Green"},
		{"fixed", "Green"},
		{"accepted", "Red"},
		{"other", "Grey"},
	}
	for _, tc := range cases {
		got := triageStatusMacro(tc.status)
		if !strings.Contains(got, tc.wantColor) {
			t.Errorf("triageStatusMacro(%q): want color %s, got: %s", tc.status, tc.wantColor, got)
		}
		if !strings.Contains(got, `name="status"`) {
			t.Errorf("triageStatusMacro(%q): missing status macro, got: %s", tc.status, got)
		}
	}
	if got := triageStatusMacro(""); got != "" {
		t.Errorf("empty status should return empty string, got: %s", got)
	}
}

func TestFindingPropertiesFieldOrder(t *testing.T) {
	ei := entityIndex{
		defs: map[string]*entities.Definition{
			"def-10038": {
				DefinitionID: "def-10038",
				Alert:        "CSP Header Not Set",
				Taxonomy: &entities.Taxonomy{
					CWEID:      693,
					CWEURI:     "https://cwe.mitre.org/data/definitions/693.html",
					OWASPTop10: []string{"A05:2021"},
				},
			},
		},
		finds: map[string]*entities.Finding{},
		occs:  map[string]*entities.Occurrence{},
	}
	f := &entities.Finding{
		FindingID:    "fin-abc",
		DefinitionID: "def-10038",
		Risk:         "Medium",
		Confidence:   "Low",
		URL:          "https://example.com/api",
		Method:       "GET",
		Occurrences:  2,
	}
	out := prependFindingProperties("BODY", f, &ei, "", nil, nil, "", "", "")
	// Finding ID should not appear
	if strings.Contains(out, "Finding ID") {
		t.Error("Finding ID row should be removed")
	}
	// Definition link should appear
	if !strings.Contains(out, "CSP Header Not Set") {
		t.Error("Definition row should contain rule name")
	}
	if !strings.Contains(out, "ri:page") {
		t.Error("Definition row should be a Confluence page link")
	}
	// Risk lozenge (status macro) should be the Risk row value
	if !strings.Contains(out, `name="status"`) {
		t.Error("Risk row should contain a status lozenge macro")
	}
	// CWE and OWASP should appear
	if !strings.Contains(out, "CWE-693") {
		t.Error("CWE should appear in properties")
	}
	if !strings.Contains(out, "A05:2021") {
		t.Error("OWASP Top 10 should appear in properties")
	}
}

// --- #33: Traffic and Evidence section preservation ---

func TestStripOccurrenceBody_TrafficAndEvidenceSurvive(t *testing.T) {
	input := "# Occurrence occ-abc\n\n" +
		"> [!Warning]\n> Risk: High\n\n" +
		"**Endpoint:** GET /api/v1/data\n\n" +
		"## Evidence\n\n" +
		"```\n<script>alert(1)</script>\n```\n\n" +
		"## Traffic\n\n" +
		"<details>\n<summary>Show traffic</summary>\n\n" +
		"### Request\n\nGET /api/v1/data\n\n" +
		"- Content-Type: application/json\n\n" +
		"```http\n{\"key\":\"value\"}\n```\n\n" +
		"### Response\n\nStatus: 200\n\n" +
		"```http\n{\"result\":\"ok\"}\n```\n\n" +
		"</details>\n"

	out := stripOccurrenceBodyForConfluence(input)

	if strings.Contains(out, "> [!Warning]") {
		t.Error("callout should be stripped")
	}
	if strings.Contains(out, "**Endpoint:**") {
		t.Error("Endpoint line should be stripped")
	}
	if !strings.Contains(out, "## Evidence") {
		t.Error("Evidence section should be preserved")
	}
	if !strings.Contains(out, "## Traffic") {
		t.Error("Traffic section should be preserved")
	}
	if !strings.Contains(out, "<details>") {
		t.Error("details block should be preserved (converted to expand macro in storage layer)")
	}
	if !strings.Contains(out, "```http") {
		t.Error("body snippet code blocks should be preserved")
	}
}

func TestStripFindingBody_MostRecentTrafficSurvivesAfterAnalystNotebook(t *testing.T) {
	input := "# Finding fin-abc\n\n" +
		"> [!Note]\n> Risk: Medium\n\n" +
		"**Endpoint:** GET /api/v1/data\n\n" +
		"## Workflow\n\n" +
		"- Status: open\n\n" +
		"### Quick triage shortcuts\n\n" +
		"- [ ] Verify\n- [ ] Reproduce\n\n" +
		"### Analyst notebook\n\n" +
		"- Notes:\n- Evidence links:\n- Next steps:\n\n" +
		"## Most recent occurrence traffic\n\n" +
		"### Request\n\n" +
		"- Method: GET\n- Host: example.com\n- Path: /api/v1/data\n- Headers captured: 3\n\n" +
		"### Response\n\n" +
		"- Status: 200\n- Headers captured: 5\n\n" +
		"```http\n{\"ok\":true}\n```\n"

	out := stripFindingBodyForConfluence(input)

	if strings.Contains(out, "> [!Note]") {
		t.Error("callout should be stripped")
	}
	if strings.Contains(out, "**Endpoint:**") {
		t.Error("Endpoint line should be stripped")
	}
	if strings.Contains(out, "Quick triage shortcuts") {
		t.Error("Quick triage shortcuts section should be stripped")
	}
	if strings.Contains(out, "Analyst notebook") {
		t.Error("Analyst notebook section should be stripped")
	}
	if !strings.Contains(out, "## Most recent occurrence traffic") {
		t.Error("Most recent occurrence traffic section must survive after Analyst notebook")
	}
	if !strings.Contains(out, "### Request") {
		t.Error("Request subsection should be preserved")
	}
	if !strings.Contains(out, "### Response") {
		t.Error("Response subsection should be preserved")
	}
	if !strings.Contains(out, "```http") {
		t.Error("body snippet code block should be preserved")
	}
}

// --- Helper for integration test ---

func pageKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// contains checks if a string slice contains a value.
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// containsStr is an alias kept for clarity in label assertion contexts.
func containsStr(ss []string, s string) bool {
	return contains(ss, s)
}

// --- Story 2.2: buildTitleMap occurrence resolves to page title ---

func TestBuildTitleMap_OccurrenceResolvesToPageTitle(t *testing.T) {
	dir := t.TempDir()

	// Create occurrences subdir with a fake occurrence file.
	occDir := filepath.Join(dir, "occurrences")
	if err := os.MkdirAll(occDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const occFilename = "occ-aabb1122.md"
	mustWriteFile(t, filepath.Join(occDir, occFilename), "# Occurrence occ-aabb1122 — H foo\n\nSome body\n")

	// Build an EntitiesFile whose occurrence matches the filename.
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{DefinitionID: "def-10042", PluginID: "10042", Alert: "Foo Header Missing"},
		},
		Findings: []entities.Finding{
			{FindingID: "fin-ccdd3344", DefinitionID: "def-10042", PluginID: "10042", URL: "https://example.com/foo", Method: "GET"},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-aabb1122",
				DefinitionID: "def-10042",
				FindingID:    "fin-ccdd3344",
				URL:          "https://example.com/foo",
				Method:       "GET",
			},
		},
	}

	ei := buildEntityIndex(ef)
	titleMap := buildTitleMap(dir, &ei)

	o := ei.occurrenceByFilename(occFilename)
	if o == nil {
		t.Fatal("occurrenceByFilename returned nil — check occurrenceID matches")
	}
	want := occurrencePageTitle(o, &ei)
	if want == "" {
		t.Fatal("occurrencePageTitle returned empty string — check definition Alert and occurrence URL")
	}

	got, ok := titleMap["occurrences/"+occFilename]
	if !ok {
		t.Fatalf("titleMap missing key %q; map keys: %v", "occurrences/"+occFilename, titleMapKeys(titleMap))
	}
	if got != want {
		t.Errorf("titleMap[%q] = %q, want %q (occurrencePageTitle)", "occurrences/"+occFilename, got, want)
	}

	// The title must NOT equal the H1 heading from the file body.
	h1 := "Occurrence occ-aabb1122 — H foo"
	if got == h1 {
		t.Errorf("titleMap entry equals raw H1 %q; expected structured occurrencePageTitle instead", h1)
	}
}

// titleMapKeys returns sorted keys from a title map for diagnostics.
func titleMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// --- Story 2.4: pageHashStore unit tests ---

func TestPageHashStore(t *testing.T) {
	t.Run("unchanged_returns_false_for_unknown_title", func(t *testing.T) {
		hs := loadHashStore(filepath.Join(t.TempDir(), "hashes.json"))
		if hs.unchanged("Unknown Page", "some body") {
			t.Error("expected unchanged=false for a title never recorded")
		}
	})

	t.Run("record_then_unchanged_same_body_returns_true", func(t *testing.T) {
		hs := loadHashStore(filepath.Join(t.TempDir(), "hashes.json"))
		hs.record("My Page", "body content", "pg-1")
		if !hs.unchanged("My Page", "body content") {
			t.Error("expected unchanged=true after recording same body")
		}
	})

	t.Run("record_then_unchanged_different_body_returns_false", func(t *testing.T) {
		hs := loadHashStore(filepath.Join(t.TempDir(), "hashes.json"))
		hs.record("My Page", "original body", "pg-2")
		if hs.unchanged("My Page", "different body") {
			t.Error("expected unchanged=false after body changed")
		}
	})

	t.Run("round_trip_record_save_load_unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hashes.json")
		hs := loadHashStore(path)
		hs.record("Round Trip Page", "stable content", "pg-3")
		if err := hs.save(); err != nil {
			t.Fatalf("save: %v", err)
		}
		// Load from disk into a fresh store.
		hs2 := loadHashStore(path)
		if !hs2.unchanged("Round Trip Page", "stable content") {
			t.Error("expected unchanged=true after round-trip save+load")
		}
	})
}

func TestUpsertPageCached_SkipWhenUnchanged(t *testing.T) {
	// Track which HTTP methods are called.
	var putCalled bool
	getByIDCalled := 0
	getByTitleCalled := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content/page-99":
			getByIDCalled++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "page-99"})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			getByTitleCalled++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"results": []any{
					map[string]any{
						"id":      "page-99",
						"version": map[string]any{"number": 1},
					},
				},
			})
		case r.Method == http.MethodPut:
			putCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	// Pre-record the hash so unchanged() returns true.
	storePath := filepath.Join(t.TempDir(), "hashes.json")
	hs := loadHashStore(storePath)
	const title = "Cached Page"
	const body = "<p>stable content</p>"
	hs.record(title, body, "page-99")

	client := srv.Client()
	auth := "Basic dXNlcjp0b2tlbg==" // user:token
	base := srv.URL

	pageID, action, err := upsertPageCached(
		context.Background(),
		client,
		auth,
		base,
		"KB",
		title,
		body,
		"",
		hs,
	)
	if err != nil {
		t.Fatalf("upsertPageCached: %v", err)
	}
	if action != "skipped" {
		t.Errorf("expected action=skipped, got %q", action)
	}
	if pageID != "page-99" {
		t.Errorf("expected pageID=page-99, got %q", pageID)
	}
	if putCalled {
		t.Error("expected no PUT when page body is unchanged")
	}
	if getByIDCalled != 1 {
		t.Errorf("expected one GET to validate the cached page ID, got %d", getByIDCalled)
	}
	if getByTitleCalled != 0 {
		t.Errorf("expected zero title lookups when cached page still exists, got %d", getByTitleCalled)
	}
}
func TestUpsertPageCached_RefindsWhenCachedPageIDDeleted(t *testing.T) {
	getByTitleCalled := 0
	getByIDCalled := 0
	putCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content/page-stale":
			getByIDCalled++
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"missing"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			getByTitleCalled++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"results": []any{
					map[string]any{
						"id":      "page-live",
						"version": map[string]any{"number": 3},
					},
				},
			})
		case r.Method == http.MethodPut:
			putCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	storePath := filepath.Join(t.TempDir(), "hashes.json")
	hs := loadHashStore(storePath)
	const title = "Deleted Cached Page"
	const body = "<p>stable content</p>"
	hs.record(title, body, "page-stale")

	pageID, action, err := upsertPageCached(
		context.Background(),
		srv.Client(),
		"Basic dXNlcjp0b2tlbg==",
		srv.URL,
		"KB",
		title,
		body,
		"",
		hs,
	)
	if err != nil {
		t.Fatalf("upsertPageCached: %v", err)
	}
	if action != "skipped" {
		t.Fatalf("action = %q, want skipped", action)
	}
	if pageID != "page-live" {
		t.Fatalf("pageID = %q, want page-live", pageID)
	}
	if getByIDCalled != 1 {
		t.Fatalf("cached page ID should be revalidated once, got %d", getByIDCalled)
	}
	if getByTitleCalled != 1 {
		t.Fatalf("expected refind by title after stale cached ID, got %d", getByTitleCalled)
	}
	if putCalled {
		t.Fatal("expected no PUT when live page was refound and body is unchanged")
	}
	if cached := hs.cachedPageID(title); cached != "page-live" {
		t.Fatalf("cached page ID = %q, want page-live", cached)
	}
}

// --- Story 5.3: KB Export Summary page ---

func TestExportVault_KBExportSummaryPage(t *testing.T) {
	var mu sync.Mutex
	created := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
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
			// Ignore label calls and other auxiliary requests
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# KB Index")

	_, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !created["KB Export Summary"] {
		var titles []string
		for k := range created {
			titles = append(titles, k)
		}
		t.Errorf("expected 'KB Export Summary' page to be upserted; pages created: %v", titles)
	}
}

func TestBuildExportSummaryBody(t *testing.T) {
	s := &VaultSummary{Created: 10, Updated: 3, Skipped: 5, Errors: 1}
	fixedTime, _ := time.Parse(time.RFC3339, "2026-04-05T12:00:00Z")
	body := buildExportSummaryBody(fixedTime, 7, 42, 130, s)

	wantContains := []string{
		"KB Export Summary",
		"2026-04-05T12:00:00Z",
		"<td>7</td>",   // definitions
		"<td>42</td>",  // findings
		"<td>130</td>", // occurrences
		"<td>10</td>",  // created
		"<td>3</td>",   // updated
		"<td>5</td>",   // skipped
		"<td>1</td>",   // errors
	}
	for _, want := range wantContains {
		if !strings.Contains(body, want) {
			t.Errorf("buildExportSummaryBody: expected %q in output\ngot: %.500s", want, body)
		}
	}
}

// --- Story 5.4: Page Properties field order ---

func TestFindingProperties_FieldOrder(t *testing.T) {
	ei := buildEntityIndex(&entities.EntitiesFile{
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			Alert:        "CSP Header Not Set",
			Taxonomy: &entities.Taxonomy{
				CWEID:      693,
				CWEURI:     "https://cwe.mitre.org/data/definitions/693.html",
				OWASPTop10: []string{"A05:2021"},
			},
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-order",
			DefinitionID: "def-10038",
			Risk:         "High",
			URL:          "https://example.com/login",
			Occurrences:  2,
		}},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-a", FindingID: "fin-order", ObservedAt: "2026-01-01T00:00:00Z"},
			{OccurrenceID: "occ-b", FindingID: "fin-order", ObservedAt: "2026-04-01T00:00:00Z", Analyst: &entities.Analyst{Status: "triaged"}},
		},
	})
	f := ei.finds["fin-order"]
	out := prependFindingProperties("BODY", f, &ei, "", nil, nil, "", "", "")

	// Verify canonical field order: Severity before CWE before OWASP before Last Seen before Occurrences
	positions := map[string]int{
		"Severity":     strings.Index(out, "<th>Severity</th>"),
		"CWE":          strings.Index(out, "<th>CWE</th>"),
		"OWASP Top 10": strings.Index(out, "<th>OWASP Top 10</th>"),
		"Last Seen":    strings.Index(out, "<th>Last Seen</th>"),
		"Occurrences":  strings.Index(out, "<th>Occurrences</th>"),
	}

	for field, pos := range positions {
		if pos < 0 {
			t.Errorf("field %q not found in output: %.400s", field, out)
		}
	}

	order := []string{"Severity", "CWE", "OWASP Top 10", "Last Seen", "Occurrences"}
	for i := 1; i < len(order); i++ {
		prev, curr := order[i-1], order[i]
		if positions[prev] >= positions[curr] {
			t.Errorf("field order violated: %q (pos %d) must appear before %q (pos %d)",
				prev, positions[prev], curr, positions[curr])
		}
	}
}

func TestBuildEntityIndex_PrefersFindingStatusOverOccurrences(t *testing.T) {
	ef := &entities.EntitiesFile{
		Findings: []entities.Finding{{
			FindingID:    "fin-status",
			DefinitionID: "def-status",
			Analyst:      &entities.Analyst{Status: "accepted"},
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-status",
			FindingID:    "fin-status",
			DefinitionID: "def-status",
			Analyst:      &entities.Analyst{Status: "open"},
		}},
	}
	ei := buildEntityIndex(ef)
	if got := ei.findingTriageStatus["fin-status"]; got != "accepted" {
		t.Fatalf("findingTriageStatus = %q, want accepted", got)
	}
}

func TestAppendJiraOverviewSection_RendersLinkedCases(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", Alert: "CSP Header Not Set"}},
		Findings: []entities.Finding{{
			FindingID:    "fin-workflow",
			DefinitionID: "def-10038",
			Risk:         "High",
			Analyst: &entities.Analyst{
				Status:     "triaged",
				TicketRefs: []string{"SEC-42"},
			},
		}},
	}
	ei := buildEntityIndex(ef)
	out := appendJiraOverviewSection("Triage Board", "<h1>Triage board</h1>", &ei, "https://example.atlassian.net/jira/software/projects/SEC", map[string]string{"SEC-42": "In Review"}, "2026-04-08T21:00:00Z")
	for _, want := range []string{"Linked Jira Cases", "browse/SEC-42", "In Review</ac:parameter>", "TRIAGED</ac:parameter>", "HIGH</ac:parameter>", "Last Jira sync: 2026-04-08T21:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Fatalf("appendJiraOverviewSection missing %q:\n%s", want, out)
		}
	}
}
func TestPrependFindingProperties_UsesFindingWorkflowFields(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", Alert: "CSP Header Not Set"}},
		Findings: []entities.Finding{{
			FindingID:    "fin-workflow",
			DefinitionID: "def-10038",
			Risk:         "Medium",
			URL:          "https://example.com/login",
			Method:       "GET",
			Occurrences:  2,
			Analyst: &entities.Analyst{
				Status:     "accepted",
				Owner:      "James",
				TicketRefs: []string{"SEC-42"},
				Tags:       []string{"jira", "internet-facing"},
				Notes:      "Business exception approved.",
				UpdatedAt:  "2026-04-06T14:00:00Z",
			},
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-workflow-a",
			FindingID:    "fin-workflow",
			DefinitionID: "def-10038",
			ObservedAt:   "2026-04-01T00:00:00Z",
			Analyst:      &entities.Analyst{Status: "open"},
		}},
	}
	ei := buildEntityIndex(ef)
	out := prependFindingProperties("BODY", ei.finds["fin-workflow"], &ei, "https://example.atlassian.net/jira/software/projects/SEC", map[string]string{"SEC-42": "In Review"}, nil, "2026-04-08T21:00:00Z", "", "")
	// Status row is intentionally absent — Jira owns workflow state.
	// Workflow Source row is intentionally absent — removed as noise.
	for _, want := range []string{"<th>Owner</th><td>James</td>", "browse/SEC-42", "data-card-appearance=\"inline\"", "<th>Analyst Cases</th>", "<th>Jira Status</th><td><ac:structured-macro ac:name=\"status\"", "In Review</ac:parameter>", "data-card-appearance=\"block\"", "<h2>Jira Workflow</h2>", "internet-facing", "Business exception approved.", "2026-04-06T14:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("prependFindingProperties missing %q:\n%s", want, out)
		}
	}
}
func TestDefProperties_FieldOrder(t *testing.T) {
	def := &entities.Definition{
		DefinitionID: "def-10038",
		PluginID:     "10038",
		Taxonomy: &entities.Taxonomy{
			CWEID:      693,
			CWEURI:     "https://cwe.mitre.org/data/definitions/693.html",
			OWASPTop10: []string{"A05:2021"},
		},
	}
	out := prependDefProperties("BODY", def, "")

	positions := map[string]int{
		"Plugin ID":    strings.Index(out, "<th>Plugin ID</th>"),
		"CWE":          strings.Index(out, "<th>CWE</th>"),
		"OWASP Top 10": strings.Index(out, "<th>OWASP Top 10</th>"),
	}

	for field, pos := range positions {
		if pos < 0 {
			t.Errorf("field %q not found in output: %.400s", field, out)
		}
	}

	// Plugin ID must appear before CWE, CWE before OWASP
	if positions["Plugin ID"] >= positions["CWE"] {
		t.Errorf("Plugin ID (pos %d) must appear before CWE (pos %d)", positions["Plugin ID"], positions["CWE"])
	}
	if positions["CWE"] >= positions["OWASP Top 10"] {
		t.Errorf("CWE (pos %d) must appear before OWASP Top 10 (pos %d)", positions["CWE"], positions["OWASP Top 10"])
	}
}

// --- KB core requirement tests ---

// Test 1 — Tool-agnostic: page titles contain no ZAP-specific strings derived from pluginId alone.
func TestFindingPageTitle_ToolAgnostic(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-nuclei-sqli",
				PluginID:     "nuclei-sqli",
				Alert:        "SQL Injection via GET parameter",
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "fin-aabb1122",
				DefinitionID: "def-nuclei-sqli",
				PluginID:     "nuclei-sqli",
				URL:          "https://example.com/search",
				Method:       "GET",
				Risk:         "High",
			},
		},
	}
	ei := buildEntityIndex(ef)
	f := ei.finds["fin-aabb1122"]

	title := findingPageTitle(f, &ei)

	if title == "" {
		t.Fatal("findingPageTitle returned empty string")
	}
	// Title must not contain "Plugin" or "zap" derived from the pluginId alone.
	// The pluginId "nuclei-sqli" should not introduce those strings.
	lowerTitle := strings.ToLower(title)
	if strings.Contains(lowerTitle, "plugin") {
		t.Errorf("findingPageTitle contains 'plugin' which is ZAP-specific: %q", title)
	}
	// Title must be derived from Alert, not from the PluginID.
	if !strings.Contains(title, "SQL Injection") {
		t.Errorf("findingPageTitle should contain the rule name 'SQL Injection', got %q", title)
	}
	// The raw pluginId string should not appear verbatim unless it is also the rule name.
	if strings.Contains(title, "nuclei-sqli") {
		t.Errorf("findingPageTitle should not embed the raw pluginId %q, got %q", "nuclei-sqli", title)
	}
}

func TestOccurrencePageTitle_ToolAgnostic(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-nuclei-sqli",
				PluginID:     "nuclei-sqli",
				Alert:        "SQL Injection via GET parameter",
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-ccdd3344",
				DefinitionID: "def-nuclei-sqli",
				FindingID:    "fin-aabb1122",
				URL:          "https://example.com/search",
			},
		},
	}
	ei := buildEntityIndex(ef)
	o := ei.occs["occ-ccdd3344"]

	title := occurrencePageTitle(o, &ei)

	if title == "" {
		t.Fatal("occurrencePageTitle returned empty string")
	}
	lowerTitle := strings.ToLower(title)
	if strings.Contains(lowerTitle, "plugin") {
		t.Errorf("occurrencePageTitle contains 'plugin' which is ZAP-specific: %q", title)
	}
	// Must be based on the rule name, not on the pluginId.
	if !strings.Contains(title, "SQL Injection") {
		t.Errorf("occurrencePageTitle should contain the rule name, got %q", title)
	}
	// The short ID suffix should come from OccurrenceID tail chars.
	if !strings.Contains(title, "3344") {
		t.Errorf("occurrencePageTitle should contain the OccurrenceID suffix '3344', got %q", title)
	}
}

// Test 2 — Deterministic titles: same entity → same title on every call.
func TestPageTitles_Deterministic(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "fin-aabb1122",
				DefinitionID: "def-10038",
				PluginID:     "10038",
				URL:          "https://example.com/api",
				Risk:         "Medium",
			},
			{
				FindingID:    "fin-ccdd3344",
				DefinitionID: "def-10038",
				PluginID:     "10038",
				URL:          "https://example.com/login",
				Risk:         "Medium",
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-11223344",
				DefinitionID: "def-10038",
				FindingID:    "fin-aabb1122",
				URL:          "https://example.com/api/v1",
			},
		},
	}
	ei := buildEntityIndex(ef)
	f1 := ei.finds["fin-aabb1122"]
	f2 := ei.finds["fin-ccdd3344"]
	o := ei.occs["occ-11223344"]

	// Same finding → same title across 3 calls.
	first := findingPageTitle(f1, &ei)
	for i := 1; i < 3; i++ {
		got := findingPageTitle(f1, &ei)
		if got != first {
			t.Errorf("findingPageTitle call %d returned %q, want %q", i+1, got, first)
		}
	}

	// Same occurrence → same title across 3 calls.
	firstOcc := occurrencePageTitle(o, &ei)
	for i := 1; i < 3; i++ {
		got := occurrencePageTitle(o, &ei)
		if got != firstOcc {
			t.Errorf("occurrencePageTitle call %d returned %q, want %q", i+1, got, firstOcc)
		}
	}

	// Two different findings of the same rule at different URLs must produce different titles.
	title1 := findingPageTitle(f1, &ei)
	title2 := findingPageTitle(f2, &ei)
	if title1 == title2 {
		t.Errorf("different findings produced identical titles: %q", title1)
	}
}

// Test 3 — Scan identity on occurrence pages.
func TestPrependOccurrenceProperties_ScanIdentity(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
			},
		},
	}
	ei := buildEntityIndex(ef)

	o := &entities.Occurrence{
		OccurrenceID: "occ-aabb1122",
		DefinitionID: "def-10038",
		FindingID:    "fin-aabb1122",
		URL:          "https://example.com/",
		ScanLabel:    "scan-2026-04-01",
		ObservedAt:   "2026-04-01T12:00:00Z",
	}

	out := prependOccurrenceProperties("BODY", o, &ei, "", nil, nil, "", "")

	if !strings.Contains(out, "scan-2026-04-01") {
		t.Errorf("occurrence properties should contain the scan label, got: %.500s", out)
	}
	if !strings.Contains(out, "2026-04-01T12:00:00Z") {
		t.Errorf("occurrence properties should contain the observed timestamp, got: %.500s", out)
	}
}

// Test 4 — Analyst triage fields on occurrence pages.
func TestPrependOccurrenceProperties_AnalystFields(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
			},
		},
	}
	ei := buildEntityIndex(ef)

	o := &entities.Occurrence{
		OccurrenceID: "occ-aabb1122",
		DefinitionID: "def-10038",
		FindingID:    "fin-aabb1122",
		URL:          "https://example.com/",
		Risk:         "Medium",
		Analyst: &entities.Analyst{
			Status: "triaged",
			Owner:  "alice",
			Notes:  "confirmed",
		},
	}

	out := prependOccurrenceProperties("BODY", o, &ei, "", nil, nil, "", "")

	if !strings.Contains(strings.ToUpper(out), "TRIAGED") {
		t.Errorf("occurrence properties should contain 'triaged', got: %.500s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("occurrence properties should contain owner 'alice', got: %.500s", out)
	}
	if !strings.Contains(out, "confirmed") {
		t.Errorf("occurrence properties should contain notes 'confirmed', got: %.500s", out)
	}
}

func TestPrependOccurrenceProperties_IncludesFindingTickets(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Alert:        "CSP Header Not Set",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-aabb1122",
			DefinitionID: "def-10038",
			Analyst:      &entities.Analyst{TicketRefs: []string{"SEC-42"}},
		}},
	}
	ei := buildEntityIndex(ef)
	o := &entities.Occurrence{
		OccurrenceID: "occ-aabb1122",
		DefinitionID: "def-10038",
		FindingID:    "fin-aabb1122",
		URL:          "https://example.com/",
		Risk:         "Medium",
	}

	out := prependOccurrenceProperties("BODY", o, &ei, "", nil, nil, "", "")
	if !strings.Contains(out, "SEC-42") {
		t.Errorf("occurrence properties should include inherited finding ticket refs, got: %.500s", out)
	}
}

// Test 5 — firstSeen/lastSeen on finding pages derived from occurrences.
func TestPrependFindingProperties_FirstLastSeen(t *testing.T) {
	ef := &entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "fin-aabb1122",
				DefinitionID: "def-10038",
				PluginID:     "10038",
				URL:          "https://example.com/",
				Risk:         "Medium",
				Occurrences:  2,
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-11111111",
				DefinitionID: "def-10038",
				FindingID:    "fin-aabb1122",
				ObservedAt:   "2026-01-01T00:00:00Z",
			},
			{
				OccurrenceID: "occ-22222222",
				DefinitionID: "def-10038",
				FindingID:    "fin-aabb1122",
				ObservedAt:   "2026-03-01T00:00:00Z",
			},
		},
	}
	ei := buildEntityIndex(ef)
	f := ei.finds["fin-aabb1122"]

	out := prependFindingProperties("BODY", f, &ei, "", nil, nil, "", "", "")

	// First Seen must appear (the earlier date).
	if !strings.Contains(out, "2026-01-01T00:00:00Z") {
		t.Errorf("finding properties should contain first-seen date '2026-01-01T00:00:00Z', got: %.600s", out)
	}
	// Last Seen must appear (the later date) since they differ.
	if !strings.Contains(out, "2026-03-01T00:00:00Z") {
		t.Errorf("finding properties should contain last-seen date '2026-03-01T00:00:00Z', got: %.600s", out)
	}
	// Both dates must be present, proving the range is built from occurrences.
	firstPos := strings.Index(out, "2026-01-01T00:00:00Z")
	lastPos := strings.Index(out, "2026-03-01T00:00:00Z")
	if firstPos < 0 || lastPos < 0 {
		t.Error("both first and last observed dates must appear in finding properties")
	}
}

// Test 6 — Enrichment: taxonomy is written to definition pages.
func TestPrependDefProperties_TaxonomyWritten(t *testing.T) {
	def := &entities.Definition{
		DefinitionID: "def-sqli",
		PluginID:     "nuclei-sqli",
		Alert:        "SQL Injection",
		Taxonomy: &entities.Taxonomy{
			CWEID:      89,
			CWEURI:     "https://cwe.mitre.org/data/definitions/89.html",
			OWASPTop10: []string{"A03:2021"},
		},
	}

	out := prependDefProperties("BODY", def, "")

	if !strings.Contains(out, "89") {
		t.Errorf("def properties should contain CWE ID '89', got: %.500s", out)
	}
	if !strings.Contains(out, "A03") {
		t.Errorf("def properties should contain OWASP category 'A03', got: %.500s", out)
	}
	if !strings.Contains(out, "BODY") {
		t.Error("original storage body should be preserved after prepending properties")
	}
}

// Test 7 — Enrichment: nil taxonomy does not panic.
func TestPrependDefProperties_NilTaxonomyNoPanic(t *testing.T) {
	def := &entities.Definition{
		DefinitionID: "def-10038",
		PluginID:     "10038",
		Alert:        "CSP Header Not Set",
		Taxonomy:     nil,
	}

	// Must not panic.
	out := prependDefProperties("BODY", def, "")

	// The original body must be present.
	if !strings.Contains(out, "BODY") {
		t.Error("storage body should be present even when taxonomy is nil")
	}
	// The definition ID or alert name must appear somewhere in the output
	// OR the body is returned unchanged — both are acceptable.
	// The key invariant is no panic and content is not lost.
	if out == "" {
		t.Error("prependDefProperties returned empty string for nil taxonomy def")
	}
}

// Test 8 — ExportVault phase completeness: required pages are upserted.
func TestExportVault_RequiredPagesUpserted(t *testing.T) {
	var mu sync.Mutex
	upserted := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			// Always say page does not exist — all calls are creates.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})

		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			upserted[title] = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "page-" + title})

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/label"):
			// Discard label calls — not under test here.
			w.WriteHeader(http.StatusOK)

		case strings.Contains(r.URL.Path, "/property"):
			// Page property API (kb-state-sig) — return 404 on GET (new property),
			// 200 on POST (create). Not under test here.
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/rest/api/content/"):
			// Fetch page body for analyst log extraction — return empty body.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"body": map[string]any{
					"storage": map[string]string{"value": ""},
				},
			})

		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# KB Index")
	mustWriteFile(t, filepath.Join(dir, "DASHBOARD.md"), "# KB Dashboard")
	mustWriteFile(t, filepath.Join(dir, "triage-board.md"), "# Triage Board")

	defsDir := filepath.Join(dir, "definitions")
	os.MkdirAll(defsDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "10038-csp-header-not-set.md"),
		"---\nid: def-10038\n---\n# CSP Header Not Set (Plugin 10038)\n\nBody text.")

	findingsDir := filepath.Join(dir, "findings")
	os.MkdirAll(findingsDir, 0o755)
	mustWriteFile(t, filepath.Join(findingsDir, "fin-aabb1122.md"),
		"# CSP Header Not Set — /api — 1122\n\nFinding body.")

	occDir := filepath.Join(dir, "occurrences")
	os.MkdirAll(occDir, 0o755)
	mustWriteFile(t, filepath.Join(occDir, "occ-ccdd3344.md"),
		"# Occurrence occ-ccdd3344\n\nOccurrence body.")

	ef := &entities.EntitiesFile{
		SchemaVersion: "v1",
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-10038",
				PluginID:     "10038",
				Alert:        "CSP Header Not Set",
			},
		},
		Findings: []entities.Finding{
			{
				FindingID:    "fin-aabb1122",
				DefinitionID: "def-10038",
				PluginID:     "10038",
				URL:          "https://example.com/api",
				Risk:         "Medium",
				Occurrences:  1,
			},
		},
		Occurrences: []entities.Occurrence{
			{
				OccurrenceID: "occ-ccdd3344",
				DefinitionID: "def-10038",
				FindingID:    "fin-aabb1122",
				URL:          "https://example.com/api",
				Risk:         "Medium",
			},
		},
	}

	_, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:      srv.URL,
		Username:     "user",
		APIToken:     "token",
		SpaceKey:     "KB",
		Concurrency:  1,
		RequestDelay: time.Millisecond,
		Entities:     ef,
	})
	if err != nil {
		t.Fatalf("ExportVault returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	required := []string{"KB Index", "KB Dashboard", "Triage Board", "Security Rule Definitions", "Custom Detections"}
	for _, title := range required {
		if !upserted[title] {
			t.Errorf("expected page %q to be upserted, but it was not; all upserted: %v", title, upserted)
		}
	}
}

func TestPrependDefProperties_IncludesOrigin(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-custom", PluginID: "zap-custom-rule", Origin: entities.DefinitionOriginCustom}
	out := prependDefProperties("BODY", def, "")
	if !strings.Contains(out, "<th>Origin</th>") {
		t.Fatalf("expected Origin property in definition properties: %.300s", out)
	}
	if !strings.Contains(out, ">custom<") {
		t.Fatalf("expected custom origin value in definition properties: %.300s", out)
	}
}

func TestUpsertPage_RetriesConflictOnce(t *testing.T) {
	var getCount, putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			getCount++
			w.Header().Set("Content-Type", "application/json")
			version := 1
			if getCount > 1 {
				version = 2
			}
			json.NewEncoder(w).Encode(map[string]any{
				"results": []any{map[string]any{"id": "page-1", "version": map[string]any{"number": version}}},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/content/page-1":
			putCount++
			if putCount == 1 {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"version conflict"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	pageID, action, err := upsertPage(context.Background(), srv.Client(), "Basic dXNlcjp0b2tlbg==", srv.URL, "KB", "Retry Page", "<p>body</p>", "")
	if err != nil {
		t.Fatalf("upsertPage: %v", err)
	}
	if pageID != "page-1" || action != "updated" {
		t.Fatalf("got (%q, %q), want (page-1, updated)", pageID, action)
	}
	if getCount < 2 {
		t.Fatalf("expected second GET after conflict, got %d", getCount)
	}
	if putCount != 2 {
		t.Fatalf("expected two PUT attempts, got %d", putCount)
	}
}

func TestPrependOccurrenceProperties_JiraWorkflowGuidance(t *testing.T) {
	ef := &entities.EntitiesFile{Definitions: []entities.Definition{{DefinitionID: "def-1", PluginID: "10001", Alert: "Test Alert"}}}
	ei := buildEntityIndex(ef)
	out := prependOccurrenceProperties("BODY", &entities.Occurrence{OccurrenceID: "occ-1", DefinitionID: "def-1", FindingID: "fin-1", URL: "https://example.com", Analyst: &entities.Analyst{Status: "confirm"}}, &ei, "", nil, nil, "", "")
	if !strings.Contains(out, "Workflow is managed in Jira") {
		t.Fatalf("expected Jira workflow guidance, got: %.400s", out)
	}
	if strings.Contains(out, "run <code>zap-kb pull</code>") {
		t.Fatalf("expected legacy pull guidance to be removed, got: %.400s", out)
	}
	if !strings.Contains(out, "<th>Status</th><td>triaged</td>") {
		t.Fatalf("expected legacy confirm status to be canonicalized, got: %.400s", out)
	}
}

func TestExportVault_PublishesQuickNavigationCompanionPages(t *testing.T) {
	created := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/content":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			title, _ := body["title"].(string)
			created[title] = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"id": "page-" + title})
		case strings.Contains(r.URL.Path, "/property"):
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		case strings.Contains(r.URL.Path, "/rest/api/content/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/property"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": ""}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/label"):
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "INDEX.md"), "# KB Index")
	mustWriteFile(t, filepath.Join(dir, "DASHBOARD.md"), "# KB Dashboard")
	mustWriteFile(t, filepath.Join(dir, "triage-board.md"), "# Triage Board")
	mustWriteFile(t, filepath.Join(dir, "issues.md"), "# Issues")
	mustWriteFile(t, filepath.Join(dir, "occurrences.md"), "# Occurrences")
	mustWriteFile(t, filepath.Join(dir, "rules.md"), "# Rules")
	mustWriteFile(t, filepath.Join(dir, "by-domain.md"), "# By Domain")
	mustWriteFile(t, filepath.Join(dir, "LEGEND.md"), "# Alias Legend")
	mustWriteFile(t, filepath.Join(dir, "TRIAGE-GUIDE.md"), "# Triage Workflow Guide")
	mustWriteFile(t, filepath.Join(dir, "by-scan.md"), "# Scans")
	mustWriteFile(t, filepath.Join(dir, "EXECUTIVE-SUMMARY.md"), "# Executive Summary")
	defsDir := filepath.Join(dir, "definitions")
	os.MkdirAll(defsDir, 0o755)
	mustWriteFile(t, filepath.Join(defsDir, "10001-nav.md"), "# Navigation Alert (Plugin 10001)")

	_, err := ExportVault(context.Background(), dir, VaultOptions{
		BaseURL:  srv.URL,
		Username: "user",
		APIToken: "token",
		SpaceKey: "KB",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, title := range []string{"Issues", "Occurrences", "Rules", "Alias Legend", "Triage Workflow Guide", "Scans", "Executive Summary"} {
		if !created[title] {
			t.Fatalf("expected companion page %q to be created; got %v", title, created)
		}
	}
}
