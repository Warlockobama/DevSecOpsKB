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

// issueStatusResponse returns a minimal Jira issue API body with the given status.
func issueStatusResponse(status string) map[string]any {
	return map[string]any{
		"fields": map[string]any{
			"status": map[string]string{"name": status},
		},
	}
}

func TestMapJiraStatus_AllMappings(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// open
		{"TO DO", "open"},
		{"to do", "open"},
		{"Open", "open"},
		{"Backlog", "open"},
		{"New", "open"},
		// triaged
		{"In Progress", "triaged"},
		{"IN PROGRESS", "triaged"},
		{"In Review", "triaged"},
		{"Review", "triaged"},
		{"Under Review", "triaged"},
		{"triaged", "triaged"},
		// fixed
		{"Done", "fixed"},
		{"DONE", "fixed"},
		{"Closed", "fixed"},
		{"Fixed", "fixed"},
		{"Resolved", "fixed"},
		{"Completed", "fixed"},
		// accepted
		{"Won't Fix", "accepted"},
		{"Wont Fix", "accepted"},
		{"wont fix", "accepted"},
		{"Risk Accepted", "accepted"},
		{"Accepted", "accepted"},
		{"Mitigated", "accepted"},
		{"mitigated", "accepted"},
		// fp
		{"False Positive", "fp"},
		{"FP", "fp"},
		{"Not A Bug", "fp"},
		{"Not Applicable", "fp"},
		// unknown
		{"Unknown Status", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := mapJiraStatus(tc.input)
		if got != tc.want {
			t.Errorf("mapJiraStatus(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractTicketKey(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"KAN-133", "KAN-133"},
		{"https://jira.example.com/browse/KAN-133", "KAN-133"},
		{"SEC-42", "SEC-42"},
		{"", ""},
		{"notakey", ""},
		{"KAN-", ""},
	}
	for _, tc := range cases {
		got := extractTicketKey(tc.input)
		if got != tc.want {
			t.Errorf("extractTicketKey(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func TestPullStatus_StatusMappingAllFour(t *testing.T) {
	cases := []struct {
		jiraStatus  string
		ticketKey   string
		wantAnalyst string
	}{
		{"TO DO", "KAN-1", "open"},
		{"IN PROGRESS", "KAN-2", "triaged"},
		{"IN REVIEW", "KAN-3", "triaged"},
		{"DONE", "KAN-4", "fixed"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.jiraStatus, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("unexpected method: got %q; want GET", r.Method)
					http.Error(w, "unexpected method", http.StatusBadRequest)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/"+tc.ticketKey) {
					t.Errorf("unexpected path: %q", r.URL.Path)
				}
				if got := r.URL.Query().Get("fields"); got != "status,assignee" {
					t.Errorf("unexpected fields query: got %q; want status,assignee", got)
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(issueStatusResponse(tc.jiraStatus))
			}))
			defer srv.Close()

			ef := makeEntities(entities.Finding{
				FindingID: "fin-1",
				Name:      "Test Finding",
				Analyst: &entities.Analyst{
					Status:     "open",
					TicketRefs: []string{tc.ticketKey},
				},
			})
			res, err := PullStatus(context.Background(), ef, PullOptions{
				BaseURL:  srv.URL,
				Username: "user",
				Token:    "token",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(res.Updated.Findings) == 0 {
				t.Fatal("no findings in result")
			}
			got := res.Updated.Findings[0].Analyst.Status
			if got != tc.wantAnalyst {
				t.Errorf("Jira status %q: got analyst.Status=%q; want %q", tc.jiraStatus, got, tc.wantAnalyst)
			}
		})
	}
}

func TestPullStatus_SkipsFindingWithNoTicketRef(t *testing.T) {
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-no-ticket",
		Name:      "No Ticket",
		Analyst:   &entities.Analyst{Status: "open"},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 0 {
		t.Error("expected no HTTP call for findings without TicketRefs")
	}
	if res.Result.Updated != 0 {
		t.Errorf("expected 0 updates; got %d", res.Result.Updated)
	}
	if got := res.Updated.Findings[0].Analyst.Status; got != "open" {
		t.Errorf("expected status unchanged 'open'; got %q", got)
	}
}

func TestPullStatus_NilAnalystSkipped(t *testing.T) {
	var called atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-nil-analyst",
		Name:      "Nil Analyst",
		Analyst:   nil,
	})
	_, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 0 {
		t.Error("expected no HTTP call for finding with nil analyst")
	}
}

func TestPullStatus_UnchangedWhenStatusSame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %q", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issueStatusResponse("TO DO"))
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-same",
		Name:      "Same Status",
		Analyst: &entities.Analyst{
			Status:     "open", // same as TO DO → open
			TicketRefs: []string{"KAN-99"},
		},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Result.Updated != 0 {
		t.Errorf("expected 0 updates (status already matches); got %d", res.Result.Updated)
	}
	if res.Result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged; got %d", res.Result.Unchanged)
	}
}

func TestPullStatus_MissingFieldsError(t *testing.T) {
	ef := makeEntities()
	_, err := PullStatus(context.Background(), ef, PullOptions{})
	if err == nil {
		t.Fatal("expected error for missing required fields")
	}
	if !strings.Contains(err.Error(), "missing required fields") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPullStatus_OwnerWriteBackFillsEmptyOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Issue body with both status and assignee
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fields": map[string]any{
				"status":   map[string]string{"name": "In Progress"},
				"assignee": map[string]string{"displayName": "Alice Example"},
			},
		})
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-empty-owner",
		Name:      "Empty Owner",
		Analyst: &entities.Analyst{
			Status:     "open",
			Owner:      "", // empty — should be filled
			TicketRefs: []string{"KAN-7"},
		},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Updated.Findings[0].Analyst.Owner; got != "Alice Example" {
		t.Errorf("expected owner='Alice Example'; got %q", got)
	}
}

func TestPullStatus_OwnerWriteBackFillsEmptyOwnerWithUnmappedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Unmapped status — write-back must still fire because AC4 only
		// depends on assignee presence, not status mapping.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fields": map[string]any{
				"status":   map[string]string{"name": "Custom Workflow State"},
				"assignee": map[string]string{"displayName": "Alice Example"},
			},
		})
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-empty-owner-unmapped",
		Name:      "Empty Owner Unmapped Status",
		Analyst: &entities.Analyst{
			Status:     "open",
			Owner:      "",
			TicketRefs: []string{"KAN-9"},
		},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Updated.Findings[0].Analyst.Owner; got != "Alice Example" {
		t.Errorf("expected owner='Alice Example' for unmapped status; got %q", got)
	}
}

func TestPullStatus_OwnerWriteBackPreservesExistingOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"fields": map[string]any{
				"status":   map[string]string{"name": "In Progress"},
				"assignee": map[string]string{"displayName": "Alice Example"},
			},
		})
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-existing-owner",
		Name:      "Existing Owner",
		Analyst: &entities.Analyst{
			Status:     "open",
			Owner:      "bob", // pre-set; must NOT be overwritten
			TicketRefs: []string{"KAN-8"},
		},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.Updated.Findings[0].Analyst.Owner; got != "bob" {
		t.Errorf("expected owner unchanged='bob'; got %q", got)
	}
}

func TestPullStatus_RawStatusesPopulated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %q", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/SEC-5") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("fields"); got != "status,assignee" {
			t.Errorf("unexpected fields query: got %q; want status,assignee", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issueStatusResponse("In Progress"))
	}))
	defer srv.Close()

	ef := makeEntities(entities.Finding{
		FindingID: "fin-raw",
		Name:      "Raw Status Check",
		Analyst: &entities.Analyst{
			Status:     "open",
			TicketRefs: []string{"SEC-5"},
		},
	})
	res, err := PullStatus(context.Background(), ef, PullOptions{
		BaseURL:  srv.URL,
		Username: "user",
		Token:    "token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RawStatuses["SEC-5"] != "In Progress" {
		t.Errorf("expected RawStatuses[SEC-5]='In Progress'; got %q", res.RawStatuses["SEC-5"])
	}
	if res.SyncedAt == "" {
		t.Error("expected SyncedAt to be populated")
	}
}
