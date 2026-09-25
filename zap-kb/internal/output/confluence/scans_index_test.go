package confluence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestBuildScanRows_AggregatesByLabel(t *testing.T) {
	ef := &entities.EntitiesFile{
		Findings: []entities.Finding{
			{FindingID: "f1", DefinitionID: "d1", URL: "https://a/x"},
			{FindingID: "f2", DefinitionID: "d1", URL: "https://a/y"},
			{FindingID: "f3", DefinitionID: "d2", URL: "https://b/z"},
		},
		Occurrences: []entities.Occurrence{
			{FindingID: "f1", ScanLabel: "scan-a", ObservedAt: "2026-04-01T00:00:00Z"},
			{FindingID: "f1", ScanLabel: "scan-a", ObservedAt: "2026-04-03T00:00:00Z"},
			{FindingID: "f2", ScanLabel: "scan-a", ObservedAt: "2026-04-02T00:00:00Z"},
			{FindingID: "f3", ScanLabel: "scan-b", ObservedAt: "2026-04-05T00:00:00Z"},
			{FindingID: "f1", ScanLabel: "", ObservedAt: "2026-03-30T00:00:00Z"}, // unlabeled
		},
	}
	rows := buildScanRows(ef)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (scan-a, scan-b, (unlabeled)), got %d", len(rows))
	}
	// Most-recent (scan-b, last=2026-04-05) sorts first.
	if rows[0].Label != "scan-b" {
		t.Errorf("rows[0].Label = %q, want scan-b", rows[0].Label)
	}
	// scan-a aggregate: 3 occurrences, 2 findings (f1+f2), 1 def, 2 URLs.
	var a *scanRow
	for i := range rows {
		if rows[i].Label == "scan-a" {
			a = &rows[i]
		}
	}
	if a == nil {
		t.Fatal("scan-a row missing")
	}
	if a.Occurrences != 3 || a.Findings != 2 || a.Definitions != 1 || a.URLs != 2 {
		t.Errorf("scan-a metrics: occ=%d find=%d def=%d urls=%d (want 3/2/1/2)", a.Occurrences, a.Findings, a.Definitions, a.URLs)
	}
	if a.First != "2026-04-01T00:00:00Z" || a.Last != "2026-04-03T00:00:00Z" {
		t.Errorf("scan-a first/last = %q/%q", a.First, a.Last)
	}
	// (unlabeled) bucket must be present so analysts can see the gap.
	found := false
	for _, r := range rows {
		if r.Label == "(unlabeled)" {
			found = true
		}
	}
	if !found {
		t.Error("expected (unlabeled) bucket for occurrence with empty ScanLabel")
	}
}

func TestScansIndexPreservesRemoteRunsAndSkipsRerun(t *testing.T) {
	remoteBody := buildScansIndexBody([]scanRow{{Label: "earlier", First: "2026-04-01T00:00:00Z", Last: "2026-04-01T00:00:00Z", Findings: 1, Definitions: 1, URLs: 1, Occurrences: 1}})
	version := 1
	puts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": "page-1", "version": map[string]int{"number": version}}}})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content/page-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": remoteBody}}})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/content/page-1":
			var payload struct {
				Version struct {
					Number int `json:"number"`
				} `json:"version"`
				Body struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				} `json:"body"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Version.Number != version+1 {
				t.Errorf("invalid update: %v, version %d", err, payload.Version.Number)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			remoteBody = payload.Body.Storage.Value
			version++
			puts++
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	current := &entities.EntitiesFile{
		Findings:    []entities.Finding{{FindingID: "new-finding", DefinitionID: "new-definition", URL: "https://example.test/new"}},
		Occurrences: []entities.Occurrence{{FindingID: "new-finding", ScanLabel: "new-run", ObservedAt: "2026-04-02T00:00:00Z"}},
	}
	for run := 0; run < 2; run++ {
		_, action, err := upsertScansIndex(context.Background(), srv.Client(), "Basic test", srv.URL, "KB", "root", current, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"updated", "skipped"}[run]; action != want {
			t.Fatalf("run %d action = %q, want %q", run, action, want)
		}
	}
	rows, err := parseScansIndexBody(remoteBody)
	if err != nil || len(rows) != 2 || puts != 1 {
		t.Fatalf("remote scans = %+v, puts=%d, err=%v", rows, puts, err)
	}
}

func TestUpsertPageCachedSkipsUnchangedRemoteWithoutLocalCache(t *testing.T) {
	puts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": "definition-1", "version": map[string]int{"number": 3}}}})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content/definition-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": "<p>unchanged</p>"}}})
		case r.Method == http.MethodPut:
			puts++
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	_, action, err := upsertPageCached(context.Background(), srv.Client(), "Basic test", srv.URL, "KB", "Definition", "<p>unchanged</p>", "parent", nil)
	if err != nil || action != "skipped" || puts != 0 {
		t.Fatalf("action=%q puts=%d err=%v", action, puts, err)
	}
}

func TestScansIndexRemergesAfterVersionConflict(t *testing.T) {
	remoteBody := buildScansIndexBody([]scanRow{{Label: "old", Last: "2026-04-01", Findings: 1}})
	version := 1
	puts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content":
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"id": "page-1", "version": map[string]int{"number": version}}}})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/content/page-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"body": map[string]any{"storage": map[string]string{"value": remoteBody}}})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/content/page-1":
			puts++
			if puts == 1 {
				remoteBody = buildScansIndexBody([]scanRow{{Label: "old", Last: "2026-04-01", Findings: 1}, {Label: "concurrent", Last: "2026-04-02", Findings: 1}})
				version++
				w.WriteHeader(http.StatusConflict)
				return
			}
			var payload struct {
				Body struct {
					Storage struct {
						Value string `json:"value"`
					} `json:"storage"`
				} `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			remoteBody = payload.Body.Storage.Value
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	current := &entities.EntitiesFile{
		Findings:    []entities.Finding{{FindingID: "f", DefinitionID: "d", URL: "https://example.test"}},
		Occurrences: []entities.Occurrence{{FindingID: "f", ScanLabel: "new", ObservedAt: "2026-04-03"}},
	}
	_, action, err := upsertScansIndex(context.Background(), srv.Client(), "Basic test", srv.URL, "KB", "root", current, nil, false)
	if err != nil || action != "updated" || puts != 2 {
		t.Fatalf("action=%q puts=%d err=%v", action, puts, err)
	}
	rows, err := parseScansIndexBody(remoteBody)
	if err != nil || len(rows) != 3 {
		t.Fatalf("concurrent row lost: rows=%+v err=%v", rows, err)
	}
}

func TestJiraClosedStatusRequiresRecurrenceReview(t *testing.T) {
	for _, status := range []string{"Done", "Closed", "Fixed", "Resolved", "Completed"} {
		if !jiraStatusNeedsRecurrenceReview(status) {
			t.Fatalf("status %q not flagged", status)
		}
	}
	if jiraStatusNeedsRecurrenceReview("In Progress") {
		t.Fatal("open issue flagged as recurrence")
	}
}

func TestBuildScansIndexBody_RendersTable(t *testing.T) {
	rows := []scanRow{
		{Label: "prod-20260401", First: "2026-04-01T00:00:00Z", Last: "2026-04-01T08:00:00Z", Occurrences: 11, Findings: 6, Definitions: 4, URLs: 5},
	}
	body := buildScansIndexBody(rows)
	for _, want := range []string{"prod-20260401", "<th>Scan label</th>", "<td>11</td>", "<td>6</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, "<h1>Scans</h1>") {
		t.Errorf("body should not duplicate the Confluence page title: %s", body)
	}
}

func TestBuildScansIndexBody_EmptyRows(t *testing.T) {
	body := buildScansIndexBody(nil)
	if !strings.Contains(body, "No scans recorded") {
		t.Errorf("expected empty-state copy, got %q", body)
	}
}
