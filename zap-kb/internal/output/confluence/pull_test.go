package confluence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestPullAnalystData_DefaultDoesNotPullWorkflow(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings:    []entities.Finding{{FindingID: "fin-1", Analyst: &entities.Analyst{Status: "triaged"}}},
		Occurrences: []entities.Occurrence{{OccurrenceID: "occ-1", Analyst: &entities.Analyst{Status: "open"}}},
	}
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatalf("unexpected HTTP call when PullWorkflow is disabled: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	updated, res, err := PullAnalystData(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		SpaceKey: "KB",
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("PullAnalystData: %v", err)
	}
	if called {
		t.Fatal("server should not have been called")
	}
	if res.Updated != 0 || res.NotFound != 0 || res.Errors != 0 || res.Unchanged != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if updated.Findings[0].Analyst.Status != "triaged" || updated.Occurrences[0].Analyst.Status != "open" {
		t.Fatalf("analyst data should remain unchanged: %+v %+v", updated.Findings[0].Analyst, updated.Occurrences[0].Analyst)
	}
}

func TestPullAnalystData_UpdatesFindingsAndOccurrences(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Alert:        "CSP Header Not Set",
		}},
		Findings: []entities.Finding{{
			FindingID:    "fin-a1b2",
			DefinitionID: "def-10038",
			PluginID:     "10038",
			URL:          "https://example.com/api/login",
			Method:       "GET",
			Analyst:      &entities.Analyst{Status: "open"},
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-c3d4",
			FindingID:    "fin-a1b2",
			DefinitionID: "def-10038",
			URL:          "https://example.com/api/login",
			Method:       "GET",
			Analyst:      &entities.Analyst{Status: "open"},
		}},
	}
	ei := buildEntityIndex(&ef)
	findingTitle := findingPageTitle(&ef.Findings[0], &ei)
	occurrenceTitle := occurrencePageTitle(&ef.Occurrences[0], &ei)
	pages := map[string]string{
		findingTitle:    "<p>- Status: triaged</p>\n<p>- Owner: James</p>\n<p>- Tickets: SEC-42</p>",
		occurrenceTitle: "<p>- Status: fixed</p>\n<p>- Owner: Jamie</p>\n<p>- Tickets: OCC-7</p>",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/rest/api/content" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		title := r.URL.Query().Get("title")
		body, ok := pages[title]
		if !ok {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"results": []any{map[string]any{
				"body": map[string]any{
					"storage": map[string]any{"value": body},
				},
			}},
		})
	}))
	defer srv.Close()

	updated, res, err := PullAnalystData(context.Background(), ef, PullOptions{
		BaseURL:      srv.URL,
		SpaceKey:     "KB",
		Username:     "user",
		Token:        "token",
		PullWorkflow: true,
	})
	if err != nil {
		t.Fatalf("PullAnalystData: %v", err)
	}
	if res.Updated != 2 {
		t.Fatalf("Updated = %d, want 2", res.Updated)
	}
	if updated.Findings[0].Analyst == nil || updated.Findings[0].Analyst.Status != "triaged" {
		t.Fatalf("finding analyst status = %#v, want triaged", updated.Findings[0].Analyst)
	}
	if updated.Findings[0].Analyst.Owner != "James" {
		t.Fatalf("finding owner = %q, want James", updated.Findings[0].Analyst.Owner)
	}
	if len(updated.Findings[0].Analyst.TicketRefs) != 1 || updated.Findings[0].Analyst.TicketRefs[0] != "SEC-42" {
		t.Fatalf("finding tickets = %#v, want [SEC-42]", updated.Findings[0].Analyst.TicketRefs)
	}
	if updated.Occurrences[0].Analyst == nil || updated.Occurrences[0].Analyst.Status != "fixed" {
		t.Fatalf("occurrence analyst status = %#v, want fixed", updated.Occurrences[0].Analyst)
	}
	if updated.Occurrences[0].Analyst.Owner != "Jamie" {
		t.Fatalf("occurrence owner = %q, want Jamie", updated.Occurrences[0].Analyst.Owner)
	}
	if len(updated.Occurrences[0].Analyst.TicketRefs) != 1 || updated.Occurrences[0].Analyst.TicketRefs[0] != "OCC-7" {
		t.Fatalf("occurrence tickets = %#v, want [OCC-7]", updated.Occurrences[0].Analyst.TicketRefs)
	}
}

func TestPullAnalystData_EmptyPageBody(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", PluginID: "10038", Alert: "CSP Header Not Set"}},
		Findings: []entities.Finding{{
			FindingID: "fin-zzzz", DefinitionID: "def-10038", PluginID: "10038",
			URL: "https://example.com/empty", Method: "GET",
			Analyst: &entities.Analyst{Status: "triaged", Owner: "James"},
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": []any{map[string]any{
				"body": map[string]any{"storage": map[string]any{"value": ""}},
			}},
		})
	}))
	defer srv.Close()

	updated, res, err := PullAnalystData(context.Background(), ef, PullOptions{
		BaseURL: srv.URL, SpaceKey: "KB", Username: "u", Token: "t", PullWorkflow: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Unchanged != 1 {
		t.Errorf("empty body: want 1 unchanged, got %d", res.Unchanged)
	}
	if updated.Findings[0].Analyst == nil || updated.Findings[0].Analyst.Status != "triaged" {
		t.Errorf("existing analyst should be preserved on empty body, got %#v", updated.Findings[0].Analyst)
	}
}

func TestFieldsToAnalyst_StatusAllowlist(t *testing.T) {
	cases := []struct {
		status string
		want   string
	}{
		{"open", "open"},
		{"triaged", "triaged"},
		{"fixed", "fixed"},
		{"fp", "fp"},
		{"accepted", "accepted"},
		{"TRIAGED", "triaged"}, // case-insensitive
		{"hacked", ""},         // not in allowlist — rejected
		{"<script>", ""},       // not in allowlist
		{"", ""},
	}
	for _, c := range cases {
		a := fieldsToAnalyst(map[string]string{"status": c.status, "owner": "admin"})
		got := ""
		if a != nil {
			got = a.Status
		}
		if got != c.want {
			t.Errorf("status %q → %q, want %q", c.status, got, c.want)
		}
	}
}

func TestFieldsToAnalyst_LengthCaps(t *testing.T) {
	longOwner := strings.Repeat("a", 300)
	longTicket := strings.Repeat("b", 100)
	a := fieldsToAnalyst(map[string]string{
		"status":  "open",
		"owner":   longOwner,
		"tickets": longTicket + "," + longTicket,
	})
	if a == nil {
		t.Fatal("expected non-nil analyst")
	}
	if len(a.Owner) > 200 {
		t.Errorf("owner too long: %d bytes", len(a.Owner))
	}
	for _, ref := range a.TicketRefs {
		if len(ref) > 64 {
			t.Errorf("ticket ref too long: %d bytes", len(ref))
		}
	}
}

func TestFieldsToAnalyst_TicketRefCountCap(t *testing.T) {
	tickets := make([]string, 100)
	for i := range tickets {
		tickets[i] = fmt.Sprintf("SEC-%d", i)
	}
	a := fieldsToAnalyst(map[string]string{
		"status":  "open",
		"tickets": strings.Join(tickets, ","),
	})
	if a == nil {
		t.Fatal("expected non-nil analyst")
	}
	if len(a.TicketRefs) > 50 {
		t.Errorf("ticket refs not capped: %d entries", len(a.TicketRefs))
	}
}

func TestPullAnalystData_PageNotFound(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{{DefinitionID: "def-10038", PluginID: "10038", Alert: "CSP Header Not Set"}},
		Findings: []entities.Finding{{
			FindingID: "fin-yyyy", DefinitionID: "def-10038", PluginID: "10038",
			URL: "https://example.com/notfound", Method: "GET",
		}},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-wwww", FindingID: "fin-yyyy", DefinitionID: "def-10038",
			URL: "https://example.com/notfound", Method: "GET",
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
	}))
	defer srv.Close()

	_, res, err := PullAnalystData(context.Background(), ef, PullOptions{
		BaseURL: srv.URL, SpaceKey: "KB", Username: "u", Token: "t", PullWorkflow: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.NotFound != 2 {
		t.Errorf("want 2 not-found (1 finding + 1 occurrence), got %d", res.NotFound)
	}
	if res.Updated != 0 {
		t.Errorf("want 0 updated when pages not found, got %d", res.Updated)
	}
}

func TestFieldsToAnalyst_StatusAliasCanonicalized(t *testing.T) {
	got := fieldsToAnalyst(map[string]string{"status": "confirm", "owner": "James"})
	if got == nil {
		t.Fatal("expected analyst from alias status")
	}
	if got.Status != "triaged" {
		t.Fatalf("status = %q, want triaged", got.Status)
	}
}
