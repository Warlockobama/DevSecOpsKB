package forgejo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// recorder captures every request method+path the stub server saw.
type recorder struct {
	mu   sync.Mutex
	reqs []string
}

func (rc *recorder) add(r *http.Request) {
	rc.mu.Lock()
	rc.reqs = append(rc.reqs, r.Method+" "+r.URL.Path)
	rc.mu.Unlock()
}

func (rc *recorder) count(method, substr string) int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	n := 0
	for _, s := range rc.reqs {
		if strings.HasPrefix(s, method+" ") && strings.Contains(s, substr) {
			n++
		}
	}
	return n
}

// countSuffix counts requests whose "METHOD path" ends with method+" "...suffix.
func (rc *recorder) countSuffix(method, suffix string) int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	n := 0
	for _, s := range rc.reqs {
		if strings.HasPrefix(s, method+" ") && strings.HasSuffix(s, suffix) {
			n++
		}
	}
	return n
}

// closedFixedEntities is one high-risk finding (no occurrence needed).
func oneHighFinding() entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		SourceTool:    "zap",
		Findings: []entities.Finding{
			{FindingID: "fin-high", URL: "https://t/a", Method: "GET", Name: "XSS /a", Risk: "High", Occurrences: 1},
		},
	}
}

func TestExport_ReopensClosedFixedOnRecurrence(t *testing.T) {
	var rc recorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.add(r)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			// Closed, no fp/accepted label → maps to "fixed".
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 7, "state": "closed", "body": "old\n" + findingMarker("fin-high"),
					"labels": []map[string]any{{"name": "kb-finding"}}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			t.Errorf("must not create when an issue exists")
			w.WriteHeader(http.StatusInternalServerError)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
			var in map[string]any
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &in)
			w.Write([]byte("{}"))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/comments"):
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), oneHighFinding(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.Reopened != 1 || sum.Created != 0 {
		t.Fatalf("reopened=%d created=%d, want 1/0", sum.Reopened, sum.Created)
	}
	if rc.count("PATCH", "/issues/7") < 1 {
		t.Fatalf("expected a PATCH to /issues/7 (reopen + body refresh)")
	}
	if rc.count("POST", "/issues/7/comments") != 1 {
		t.Fatalf("expected exactly one reopen comment, got %d", rc.count("POST", "/issues/7/comments"))
	}
	if rc.countSuffix("POST", "/issues") != 0 {
		t.Fatalf("must not POST a new issue")
	}
	if sum.TicketRefs["fin-high"] != "acme/kb#7" {
		t.Fatalf("ref = %q, want acme/kb#7", sum.TicketRefs["fin-high"])
	}
}

func TestExport_NeverReopensFPOrAccepted(t *testing.T) {
	for _, label := range []string{"false-positive", "accepted"} {
		t.Run(label, func(t *testing.T) {
			var rc recorder
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rc.add(r)
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
					json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
					labelCreateStub(w, r)
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
					json.NewEncoder(w).Encode([]map[string]any{
						{"number": 7, "state": "closed", "body": "old\n" + findingMarker("fin-high"),
							"labels": []map[string]any{{"name": "kb-finding"}, {"name": label}}},
					})
				case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
					t.Errorf("must not PATCH a %s issue", label)
					w.WriteHeader(http.StatusInternalServerError)
				case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issues"):
					t.Errorf("must not create/comment on a %s issue", label)
					w.WriteHeader(http.StatusInternalServerError)
				default:
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer srv.Close()

			sum, err := Export(context.Background(), oneHighFinding(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			if sum.Reopened != 0 || sum.Skipped != 1 {
				t.Fatalf("reopened=%d skipped=%d, want 0/1", sum.Reopened, sum.Skipped)
			}
			if rc.count("PATCH", "/issues/") != 0 {
				t.Fatalf("expected zero PATCH requests for a %s disposition", label)
			}
		})
	}
}

func TestExport_CreatesWithRiskLabel(t *testing.T) {
	var rc recorder
	var createdLabels []forgejoLabel
	var mu sync.Mutex
	var createPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.add(r)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			var in forgejoLabel
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &in)
			mu.Lock()
			in.ID = int64(50 + len(createdLabels))
			createdLabels = append(createdLabels, in)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(in)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			json.Unmarshal(body, &createPayload)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"number": 1})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	_, err := Export(context.Background(), oneHighFinding(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// risk/high created with the right color.
	var riskHigh *forgejoLabel
	for i := range createdLabels {
		if createdLabels[i].Name == "risk/high" {
			riskHigh = &createdLabels[i]
		}
	}
	if riskHigh == nil {
		t.Fatalf("risk/high label was not created; created=%v", createdLabels)
	}
	// The create payload's labels array carries both kb-finding (1) and the new
	// risk/high id, ascending.
	raw, _ := json.Marshal(createPayload["labels"])
	var ids []int64
	json.Unmarshal(raw, &ids)
	if len(ids) != 2 || ids[0] != 1 || ids[1] != riskHigh.ID {
		t.Fatalf("issue labels = %v, want [1 %d] ascending", ids, riskHigh.ID)
	}
}

func TestExport_RefreshesStaleOpenBody(t *testing.T) {
	var rc recorder
	var patchedBody string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.add(r)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 4, "state": "open", "body": "stale text\n" + findingMarker("fin-high"),
					"labels": []map[string]any{{"name": "kb-finding"}}},
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
			var in map[string]string
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &in)
			mu.Lock()
			patchedBody = in["body"]
			mu.Unlock()
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), oneHighFinding(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.BodiesUpdated != 1 {
		t.Fatalf("BodiesUpdated=%d, want 1", sum.BodiesUpdated)
	}
	mu.Lock()
	defer mu.Unlock()
	if markerFindingID(patchedBody) != "fin-high" {
		t.Fatalf("refreshed body lost its marker: %q", patchedBody)
	}
}

func TestExport_IdenticalBodyNoPatch(t *testing.T) {
	var rc recorder
	body := canonicalBody(sampleEntities(), "fin-high")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.add(r)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 5, "state": "open", "body": body,
					"labels": []map[string]any{{"name": "kb-finding"}}},
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
			t.Errorf("must not PATCH an already-current body")
			w.WriteHeader(http.StatusInternalServerError)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			t.Errorf("must not create when an issue exists")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), sampleEntities(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.BodiesUpdated != 0 || sum.Skipped != 1 {
		t.Fatalf("bodiesUpdated=%d skipped=%d, want 0/1", sum.BodiesUpdated, sum.Skipped)
	}
	if rc.count("PATCH", "/issues/") != 0 {
		t.Fatalf("expected zero PATCH requests")
	}
}

func TestExport_DryRunCountsExisting(t *testing.T) {
	var rc recorder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.add(r)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			// fin-high already tracked; fin-high2 is not.
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 3, "state": "open", "body": findingMarker("fin-high"),
					"labels": []map[string]any{{"name": "kb-finding"}}},
			})
		default:
			t.Errorf("dry-run must not call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	ef := oneHighFinding()
	ef.Findings = append(ef.Findings, entities.Finding{FindingID: "fin-high2", URL: "https://t/b", Risk: "High", Occurrences: 1})

	sum, err := Export(context.Background(), ef, Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", DryRun: true})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.Created != 1 || sum.Skipped != 1 {
		t.Fatalf("dry-run created=%d skipped=%d, want 1/1", sum.Created, sum.Skipped)
	}
	if rc.count("POST", "") != 0 || rc.count("PATCH", "") != 0 {
		t.Fatalf("dry-run must issue only GETs; saw POST=%d PATCH=%d", rc.count("POST", ""), rc.count("PATCH", ""))
	}
}

func TestBuildIssueBody_DescriptionAndWikiLink(t *testing.T) {
	f := entities.Finding{FindingID: "fin-1", DefinitionID: "def-1", Risk: "High", Occurrences: 1}
	def := &entities.Definition{DefinitionID: "def-1", Description: "Reflected XSS happens when…"}
	body := buildIssueBody(f, def, nil, "https://forge.example/o/r/wiki")
	if !strings.Contains(body, "## Description") {
		t.Fatalf("missing Description section:\n%s", body)
	}
	if !strings.Contains(body, "Reflected XSS happens when") {
		t.Fatalf("missing description text:\n%s", body)
	}
	if !strings.Contains(body, "https://forge.example/o/r/wiki/Definitions%2Fdef-1") {
		t.Fatalf("missing escaped KB wiki link:\n%s", body)
	}
}
