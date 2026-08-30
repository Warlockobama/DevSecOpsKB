package forgejo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// TestExportGroupsByDefinition: with GroupByDefinition the two findings sharing
// def-1 collapse into ONE issue titled by the rule, listing both endpoints, and
// every finding's ticket ref points at that one issue.
func TestExportGroupsByDefinition(t *testing.T) {
	var created int32
	var mu sync.Mutex
	var postedBody, postedTitle string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			json.NewEncoder(w).Encode([]map[string]any{}) // fresh repo
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			atomic.AddInt32(&created, 1)
			body, _ := io.ReadAll(r.Body)
			var p map[string]any
			json.Unmarshal(body, &p)
			mu.Lock()
			postedBody, _ = p["body"].(string)
			postedTitle, _ = p["title"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"number": 1})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	// MinRisk info so both the High and Low finding qualify; grouping collapses
	// them into a single per-definition issue.
	opts := Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", MinRisk: "info", GroupByDefinition: true}
	sum, err := Export(context.Background(), sampleEntities(), opts)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := atomic.LoadInt32(&created); got != 1 {
		t.Fatalf("created %d issues, want exactly 1 (one per definition)", got)
	}
	if sum.Created != 1 {
		t.Fatalf("sum.Created=%d, want 1", sum.Created)
	}

	mu.Lock()
	defer mu.Unlock()
	// Title leads with the rule name, not a URL.
	if !strings.Contains(postedTitle, "CSP Header Not Set") {
		t.Fatalf("group title %q must name the rule", postedTitle)
	}
	if !strings.Contains(postedTitle, "occurrence") {
		t.Fatalf("group title %q must state scale", postedTitle)
	}
	// Body lists both affected endpoints and carries the definition-group marker.
	if !strings.Contains(postedBody, "## Affected endpoints") {
		t.Fatalf("group body missing endpoints table:\n%s", postedBody)
	}
	if !strings.Contains(postedBody, "https://t/a") || !strings.Contains(postedBody, "https://t/b") {
		t.Fatalf("group body must list every endpoint:\n%s", postedBody)
	}
	if got := markerFindingID(postedBody); got != "defgroup:def-1" {
		t.Fatalf("group marker key = %q, want defgroup:def-1", got)
	}
	// Every finding in the group points at the single group issue.
	if sum.TicketRefs["fin-high"] != "acme/kb#1" || sum.TicketRefs["fin-low"] != "acme/kb#1" {
		t.Fatalf("both findings must ref the group issue; got %v", sum.TicketRefs)
	}
}

// TestExportGroupsDistinctDefinitions: two definitions yield two issues, even in
// group mode.
func TestExportGroupsDistinctDefinitions(t *testing.T) {
	ef := sampleEntities()
	ef.Definitions = append(ef.Definitions, entities.Definition{
		DefinitionID: "def-2", PluginID: "10020", Name: "X-Frame-Options Missing",
	})
	ef.Findings = append(ef.Findings,
		entities.Finding{FindingID: "fin-xfo", DefinitionID: "def-2", URL: "https://t/c", Method: "GET", Risk: "Medium", Occurrences: 3},
	)

	var created int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			n := atomic.AddInt32(&created, 1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"number": int(n)})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), ef, Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", MinRisk: "info", GroupByDefinition: true})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := atomic.LoadInt32(&created); got != 2 {
		t.Fatalf("created %d issues, want 2 (one per definition)", got)
	}
	if sum.Created != 2 {
		t.Fatalf("sum.Created=%d, want 2", sum.Created)
	}
}

// TestExportReconcilesDuplicateGroupIssues: in group mode a duplicate pair for
// one definition-group reconciles to the lowest issue, and EVERY finding in the
// group is repointed at the winner — the reconcile winner key is the
// "defgroup:" marker key, not a findingID, so the repoint must fan out per
// finding (the bug this guards against left findings pointing at the closed
// loser).
func TestExportReconcilesDuplicateGroupIssues(t *testing.T) {
	ef := sampleEntities()

	// Mirror Export's unit construction so #5 already holds the canonical group
	// body (only PATCH should be the reconcile close of #9).
	defByID := map[string]*entities.Definition{}
	for i := range ef.Definitions {
		defByID[ef.Definitions[i].DefinitionID] = &ef.Definitions[i]
	}
	latestOcc := map[string]*entities.Occurrence{}
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		if cur, ok := latestOcc[o.FindingID]; !ok || occurrenceIsNewer(o, cur) {
			latestOcc[o.FindingID] = o
		}
	}
	groupBody := buildUnitBody(buildUnits(ef.Findings, defByID, latestOcc, true)[0], "")

	var closed []string
	var getIssues int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			// First call = dedup index build: empty, so the unit CREATES (#9) and
			// its ticket refs start on #9. The reconcile re-list then surfaces a
			// concurrent publisher's lower-numbered #5 as the winner, so the
			// refs must be moved off the now-closed #9.
			if atomic.AddInt32(&getIssues, 1) == 1 {
				json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 9, "state": "open", "body": groupBody},
				{"number": 5, "state": "open", "body": groupBody},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"number": 9})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
			mu.Lock()
			closed = append(closed, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			mu.Unlock()
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), ef, Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", MinRisk: "info", GroupByDefinition: true})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.DuplicatesClosed != 1 {
		t.Fatalf("DuplicatesClosed=%d, want 1", sum.DuplicatesClosed)
	}
	// BOTH findings in the group must point at the surviving winner #5.
	if sum.TicketRefs["fin-high"] != "acme/kb#5" || sum.TicketRefs["fin-low"] != "acme/kb#5" {
		t.Fatalf("findings not repointed at winner; got %v", sum.TicketRefs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 1 || closed[0] != "9" {
		t.Fatalf("closed issues = %v, want exactly [9]", closed)
	}
}

// TestGroupBodyCappedToMaxBytes: an oversized body is truncated but the dedup
// marker still survives at the end.
func TestGroupBodyCappedToMaxBytes(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-1", PluginID: "1", Name: "Noisy Rule"}
	var fs []entities.Finding
	for i := 0; i < 5000; i++ {
		fs = append(fs, entities.Finding{
			FindingID:    "f" + strings.Repeat("x", 20),
			DefinitionID: "def-1",
			URL:          "https://target.example/some/long/path/" + strings.Repeat("a", 40),
			Method:       "GET",
			Risk:         "Info",
			Occurrences:  1,
		})
	}
	body := buildGroupBody(def, fs, nil, "", defGroupPrefix+"def-1")
	if len(body) > maxBodyBytes+500 {
		t.Fatalf("body not capped: %d bytes", len(body))
	}
	if markerFindingID(body) != "defgroup:def-1" {
		t.Fatalf("marker did not survive truncation: %q", markerFindingID(body))
	}
}
