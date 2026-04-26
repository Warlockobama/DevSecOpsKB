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
		MinRisk:    "medium",
		OptInTag:   "case-ticket",
	}
}

// searchResponse returns a JSON body for POST /rest/api/3/search/jql
// with zero or one matching issue.
func searchResponse(key string) map[string]any {
	if key == "" {
		return map[string]any{"issues": []any{}, "isLast": true}
	}
	return map[string]any{
		"issues": []any{map[string]string{"key": key}},
		"isLast": true,
	}
}

func TestExport_CreatesBatchInParallel(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql":
			// No existing issues
			json.NewEncoder(w).Encode(searchResponse(""))
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

	opts := defaultOpts(srv.URL)
	opts.MinRisk = "low"
	sum, err := Export(context.Background(), ef, opts)
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
	// TicketKeys must map each findingID to the key returned by the mock.
	for _, id := range []string{"fin-001", "fin-002", "fin-003"} {
		if sum.TicketKeys[id] != "SEC-1" {
			t.Errorf("TicketKeys[%s] = %q, want SEC-1", id, sum.TicketKeys[id])
		}
	}
}

func TestExport_SkipsExistingIssues(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql":
			// All findings already exist
			json.NewEncoder(w).Encode(searchResponse("SEC-99"))
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
	// Skipped findings must also appear in TicketKeys.
	for _, id := range []string{"fin-001", "fin-002"} {
		if sum.TicketKeys[id] != "SEC-99" {
			t.Errorf("TicketKeys[%s] = %q, want SEC-99", id, sum.TicketKeys[id])
		}
	}
}

func TestExport_DryRun_TicketKeysNil(t *testing.T) {
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
	// Dry-run returns no real keys — TicketKeys should be nil or empty (not populated).
	if len(sum.TicketKeys) != 0 {
		t.Errorf("dry-run should have no TicketKeys, got %v", sum.TicketKeys)
	}
}

func TestExport_MinRiskFiltersFindings(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql" {
			json.NewEncoder(w).Encode(searchResponse(""))
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
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql" {
			json.NewEncoder(w).Encode(searchResponse(""))
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

func TestFindExistingIssue_SearchesCurrentAndLegacyLabels(t *testing.T) {
	var gotJQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/rest/api/3/search/jql" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			JQL string `json:"jql"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		gotJQL = body.JQL
		json.NewEncoder(w).Encode(searchResponse("SEC-42"))
	}))
	defer srv.Close()

	key, err := findExistingIssue(context.Background(), srv.Client(), "Basic test", srv.URL, "fin-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "SEC-42" {
		t.Fatalf("findExistingIssue returned %q, want SEC-42", key)
	}
	if !strings.Contains(gotJQL, `"zap-finding-fin-001"`) {
		t.Errorf("search JQL missing current label: %q", gotJQL)
	}
	if !strings.Contains(gotJQL, `"zap-finding:fin-001"`) {
		t.Errorf("search JQL missing legacy label: %q", gotJQL)
	}
}

func TestFindingLabel(t *testing.T) {
	label := findingLabel("fin-abc123")
	if label != "zap-finding-fin-abc123" {
		t.Errorf("unexpected label: %s", label)
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"A02:2021-Cryptographic Failures", "A02-2021-Cryptographic-Failures"},
		{"jwt", "jwt"},
		{"path/traversal", "path-traversal"},
		{"back\\slash", "back-slash"},
		{"A02 Failure", "A02-Failure"},                       // pure space
		{strings.Repeat("x", 300), strings.Repeat("x", 255)}, // length cap
		{"ctrl\x01char", "ctrlchar"},                         // control char stripped
	}
	for _, c := range cases {
		if got := sanitizeLabel(c.in); got != c.want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIssueSummary_Truncation(t *testing.T) {
	long := strings.Repeat("x", 300)
	f := makeFinding("fin-1", "high", "https://example.com")
	f.Name = long
	s := issueSummary(f)
	if len(s) > 255 {
		t.Errorf("summary too long: %d chars", len(s))
	}
	if !strings.HasSuffix(s, "...") {
		t.Errorf("truncated summary should end with '...': %s", s)
	}
}

func TestExport_OptInTagAllowsLowSeverityFinding(t *testing.T) {
	var createCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql" {
			json.NewEncoder(w).Encode(searchResponse(""))
			return
		}
		atomic.AddInt64(&createCount, 1)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
	}))
	defer srv.Close()

	low := makeFinding("fin-low-optin", "low", "https://example.com/l")
	low.Analyst = &entities.Analyst{Tags: []string{"case-ticket"}}
	ef := makeEntities(low, makeFinding("fin-low-skip", "low", "https://example.com/skip"))
	opts := defaultOpts(srv.URL)
	sum, err := Export(context.Background(), ef, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sum.Created != 1 {
		t.Fatalf("expected 1 created issue from opt-in tag, got %d", sum.Created)
	}
	if int(atomic.LoadInt64(&createCount)) != 1 {
		t.Fatalf("expected 1 POST call, got %d", createCount)
	}
}

// TestExport_AssigneeFromUsernameMap verifies #61 AC3: when a finding's
// analyst.owner has a mapping in opts.UsernameMap, the create-issue payload
// includes assignee.accountId. When no mapping exists, the payload omits
// assignee (issue created unassigned + warning logged).
func TestExport_AssigneeFromUsernameMap(t *testing.T) {
	var capturedPayload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql":
			_ = json.NewEncoder(w).Encode(searchResponse(""))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			capturedPayload, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	f := makeFinding("fin-mapped", "high", "https://example.com/x")
	f.Analyst = &entities.Analyst{Owner: "alice"}
	ef := makeEntities(f)

	opts := defaultOpts(srv.URL)
	opts.UsernameMap = map[string]string{"alice": "5e3fabc"}
	if _, err := Export(context.Background(), ef, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(capturedPayload), `"assignee":{"accountId":"5e3fabc"}`) {
		t.Errorf("expected assignee accountId in payload; got: %s", capturedPayload)
	}
}

func TestExport_OwnerWithoutMappingOmitsAssignee(t *testing.T) {
	var capturedPayload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/search/jql":
			_ = json.NewEncoder(w).Encode(searchResponse(""))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue":
			capturedPayload, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1"})
		}
	}))
	defer srv.Close()

	f := makeFinding("fin-unmapped", "high", "https://example.com/x")
	f.Analyst = &entities.Analyst{Owner: "carol"} // not in map
	ef := makeEntities(f)

	opts := defaultOpts(srv.URL)
	opts.UsernameMap = map[string]string{"alice": "5e3fabc"}
	if _, err := Export(context.Background(), ef, opts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(capturedPayload), `"assignee"`) {
		t.Errorf("expected NO assignee in payload (no mapping for 'carol'); got: %s", capturedPayload)
	}
}
