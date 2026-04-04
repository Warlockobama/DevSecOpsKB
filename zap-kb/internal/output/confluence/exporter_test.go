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
	out := prependOccurrenceProperties("BODY", o, &ei)

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
	out := prependFindingProperties("BODY", f, &ei)

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

func TestFindingProperties_SingleOccurrence_NoLastSeen(t *testing.T) {
	// When only one occurrence exists, Last Seen should not be shown (redundant with First Seen)
	ei := buildEntityIndex(&entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", Alert: "CSP"}},
		Findings:    []entities.Finding{{FindingID: "fin-solo", DefinitionID: "def-10038", Risk: "Low", URL: "https://x.com", Method: "GET"}},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-only", FindingID: "fin-solo", ObservedAt: "2026-03-01T00:00:00Z"},
		},
	})
	f := ei.finds["fin-solo"]
	out := prependFindingProperties("BODY", f, &ei)

	if !strings.Contains(out, "First Seen") {
		t.Error("First Seen should appear")
	}
	if strings.Contains(out, "Last Seen") {
		t.Error("Last Seen should not appear when first == last")
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

	// Definition page should be a child of "Definitions" parent page
	defTitle := "CSP Header Not Set (Plugin 10038)"
	defsParentID := "pid-Definitions"
	if pageParents[defTitle] != defsParentID {
		t.Errorf("definition page parent: want %q, got %q", defsParentID, pageParents[defTitle])
	}

	// Finding page should be a child of the definition page
	defPageID := "pid-" + defTitle
	findingTitle := ""
	for title, parent := range pageParents {
		if parent == defPageID {
			findingTitle = title
			break
		}
	}
	if findingTitle == "" {
		t.Errorf("no finding page found as child of definition page %q; all parents: %v", defPageID, pageParents)
	}

	// Occurrence page should be a child of the finding page
	if findingTitle != "" {
		findingPageID := "pid-" + findingTitle
		occFound := false
		for title, parent := range pageParents {
			if parent == findingPageID {
				occFound = true
				_ = title
				break
			}
		}
		if !occFound {
			t.Errorf("no occurrence page found as child of finding page %q; all parents: %v", findingPageID, pageParents)
		}
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
	if !strings.Contains(out, "Definition:") {
		t.Error("Definition link should be preserved")
	}
	if !strings.Contains(out, "## Rollup") {
		t.Error("Rollup section should be preserved")
	}
	if !strings.Contains(out, "## Workflow") {
		t.Error("Workflow heading should be preserved")
	}
	if !strings.Contains(out, "- Status: open") {
		t.Error("Status line inside Workflow should be preserved")
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
	if !strings.Contains(out, "Definition:") {
		t.Error("Definition link should be preserved")
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
	out := prependFindingProperties("BODY", f, &ei)
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
