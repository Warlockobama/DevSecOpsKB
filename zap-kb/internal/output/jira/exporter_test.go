package jira

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func makeEntities(findings ...entities.Finding) entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		Findings:      findings,
		Definitions:   []entities.Definition{},
		Occurrences:   []entities.Occurrence{},
	}
}

func makeFinding(id, risk, url string) entities.Finding {
	return entities.Finding{
		FindingID:    id,
		DefinitionID: "def-10016",
		URL:          url,
		Method:       "GET",
		Risk:         risk,
		Confidence:   "medium",
		Name:         "Test Finding " + id,
		Occurrences:  1,
	}
}

func defaultOpts(baseURL string) Options {
	return Options{
		BaseURL:    baseURL,
		Username:   "user@example.com",
		APIToken:   "token",
		ProjectKey: "SEC",
		MinRisk:    "low",
	}
}

func TestExport_CreatesBatchInParallel(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/rest/api/3/search"):
			// No existing issues
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"total": 0, "issues": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			atomic.AddInt64(&createCount, 1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	ef := makeEntities(
		makeFinding("fin-001", "high", "https://example.com/a"),
		makeFinding("fin-002", "medium", "https://example.com/b"),
		makeFinding("fin-003", "low", "https://example.com/c"),
	)

	sum, err := Export(context.Background(), ef, defaultOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Created != 3 {
		t.Errorf("expected 3 created, got %d", sum.Created)
	}
	if sum.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", sum.Skipped)
	}
	if int(atomic.LoadInt64(&createCount)) != 3 {
		t.Errorf("expected 3 POST calls, got %d", createCount)
	}
}

func TestExport_SkipsExistingIssues(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/rest/api/3/search"):
			// All findings already exist
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"total":  1,
				"issues": []any{map[string]string{"key": "SEC-99"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			atomic.AddInt64(&createCount, 1)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	ef := makeEntities(
		makeFinding("fin-001", "high", "https://example.com/a"),
		makeFinding("fin-002", "high", "https://example.com/b"),
	)

	sum, err := Export(context.Background(), ef, defaultOpts(srv.URL))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Skipped != 2 {
		t.Errorf("expected 2 skipped, got %d", sum.Skipped)
	}
	if int(atomic.LoadInt64(&createCount)) != 0 {
		t.Errorf("expected 0 POST calls, got %d", createCount)
	}
}

func TestExport_MinRiskFiltersFindings(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"total": 0, "issues": []any{}})
			return
		}
		atomic.AddInt64(&createCount, 1)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
	}))
	defer srv.Close()

	ef := makeEntities(
		makeFinding("fin-high", "high", "https://example.com/h"),
		makeFinding("fin-med", "medium", "https://example.com/m"),
		makeFinding("fin-low", "low", "https://example.com/l"),
		makeFinding("fin-info", "info", "https://example.com/i"),
	)

	opts := defaultOpts(srv.URL)
	opts.MinRisk = "medium"
	sum, err := Export(context.Background(), ef, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only high and medium should be created
	if sum.Created != 2 {
		t.Errorf("expected 2 created (high+medium), got %d", sum.Created)
	}
	if int(atomic.LoadInt64(&createCount)) != 2 {
		t.Errorf("expected 2 POST calls, got %d", createCount)
	}
}

func TestExport_DryRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call in dry-run: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	ef := makeEntities(makeFinding("fin-001", "high", "https://example.com/a"))
	opts := defaultOpts(srv.URL)
	opts.DryRun = true

	sum, err := Export(context.Background(), ef, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Created != 1 {
		t.Errorf("dry-run should report 1 would-create, got %d", sum.Created)
	}
}

func TestExport_MissingRequiredFields(t *testing.T) {
	_, err := Export(context.Background(), makeEntities(), Options{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExport_ErrorBodyCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"total": 0, "issues": []any{}})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errorMessages":["project does not exist"]}`))
	}))
	defer srv.Close()

	ef := makeEntities(makeFinding("fin-001", "high", "https://example.com/a"))
	sum, err := Export(context.Background(), ef, defaultOpts(srv.URL))
	if err != nil {
		t.Fatalf("Export itself should not error; per-issue errors are counted: %v", err)
	}
	if sum.Errors != 1 {
		t.Errorf("expected 1 error in summary, got %d", sum.Errors)
	}
}

func TestFindingLabel(t *testing.T) {
	label := findingLabel("fin-abc123")
	if label != "zap-finding:fin-abc123" {
		t.Errorf("unexpected label: %s", label)
	}
}
