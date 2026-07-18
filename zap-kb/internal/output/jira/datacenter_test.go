package jira

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// TestExport_DataCenter_UsesV2AndWikiMarkup drives a full DC-mode export:
// dedup search hits POST /rest/api/2/search, issue create hits
// POST /rest/api/2/issue with a wiki-markup *string* description, and the
// empty Username sends the token as a Bearer PAT.
func TestExport_DataCenter_UsesV2AndWikiMarkup(t *testing.T) {
	var createCount int64
	var gotAuth string
	var gotCreateBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/search":
			gotAuth = r.Header.Get("Authorization")
			json.NewEncoder(w).Encode(searchResponse(""))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue":
			atomic.AddInt64(&createCount, 1)
			gotCreateBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"key": "SEC-7"})
		default:
			t.Errorf("unexpected %s %s (v3 endpoint reached in DC mode?)", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	ef := makeEntities(makeFinding("fin-dc1", "high", "https://example.com/a"))
	opts := Options{
		BaseURL:    srv.URL,
		Username:   "", // Bearer PAT mode
		APIToken:   "pat-token",
		Deployment: DeploymentDataCenter,
		ProjectKey: "SEC",
		MinRisk:    "medium",
	}
	sum, err := Export(context.Background(), ef, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Created != 1 {
		t.Fatalf("expected 1 created, got %d (errors=%d)", sum.Created, sum.Errors)
	}
	if atomic.LoadInt64(&createCount) != 1 {
		t.Fatalf("expected 1 create POST, got %d", createCount)
	}
	if gotAuth != "Bearer pat-token" {
		t.Errorf("Authorization = %q, want Bearer pat-token", gotAuth)
	}

	var body struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(gotCreateBody, &body); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	var desc string
	if err := json.Unmarshal(body.Fields["description"], &desc); err != nil {
		t.Fatalf("DC description must be a wiki-markup string, got: %s", body.Fields["description"])
	}
	if !strings.Contains(desc, "Risk: High") {
		t.Errorf("description missing risk line: %q", desc)
	}
	if !strings.Contains(desc, "[https://example.com/a|https://example.com/a]") {
		t.Errorf("description missing wiki link: %q", desc)
	}
	if _, ok := body.Fields["parent"]; ok {
		t.Errorf("DC create must not set parent, body: %s", gotCreateBody)
	}
}

// TestExport_DataCenter_DisablesDetectionEpic verifies DC mode falls back to
// flat findings without touching any epic endpoint.
func TestExport_DataCenter_DisablesDetectionEpic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/search":
			json.NewEncoder(w).Encode(searchResponse(""))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"key": "SEC-8"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	ef := makeEntities(makeFinding("fin-dc2", "high", "https://example.com/b"))
	opts := Options{
		BaseURL:       srv.URL,
		Username:      "svc-account",
		APIToken:      "password",
		Deployment:    "dc", // alias
		ProjectKey:    "SEC",
		MinRisk:       "medium",
		DetectionEpic: true,
	}
	sum, err := Export(context.Background(), ef, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Created != 1 {
		t.Fatalf("expected 1 created, got %d (errors=%d)", sum.Created, sum.Errors)
	}
	if len(sum.EpicKeys) != 0 {
		t.Errorf("expected no epics on DC, got %v", sum.EpicKeys)
	}
}

// TestPullStatus_DataCenter_UsesV2 verifies the status pull reads
// /rest/api/2/issue/<key> in DC mode.
func TestPullStatus_DataCenter_UsesV2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/rest/api/2/issue/SEC-11" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"fields": map[string]any{
				"status":   map[string]string{"name": "Done"},
				"assignee": map[string]string{"displayName": "Alice Analyst"},
			},
		})
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-dc3",
		Risk:      "high",
		Analyst:   &entities.Analyst{TicketRefs: []string{"SEC-11"}},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:    srv.URL,
		Token:      "pat-token",
		Deployment: DeploymentDataCenter,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RawStatuses["SEC-11"] != "Done" {
		t.Errorf("RawStatuses[SEC-11] = %q, want Done", res.RawStatuses["SEC-11"])
	}
	if got := res.Updated.Findings[0].Analyst.Status; got != "fixed" {
		t.Errorf("mapped status = %q, want fixed", got)
	}
}
