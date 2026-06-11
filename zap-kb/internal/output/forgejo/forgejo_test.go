package forgejo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestMarkerFindingID(t *testing.T) {
	body := "Some text\n\n<!-- devsecopskb-finding:fin-abc123 -->\n"
	if got := markerFindingID(body); got != "fin-abc123" {
		t.Fatalf("markerFindingID = %q, want fin-abc123", got)
	}
	if got := markerFindingID("no marker here"); got != "" {
		t.Fatalf("markerFindingID(no marker) = %q, want empty", got)
	}
	// Round-trips with the renderer.
	rendered := findingMarker("fin-xyz")
	if got := markerFindingID("body\n" + rendered); got != "fin-xyz" {
		t.Fatalf("round-trip = %q, want fin-xyz", got)
	}
}

func TestMapForgejoStatus(t *testing.T) {
	cases := []struct {
		state  string
		labels []string
		want   string
	}{
		{"open", nil, "open"},
		{"closed", nil, "fixed"},
		{"open", []string{"triaged"}, "triaged"},
		{"open", []string{"false-positive"}, "fp"},
		{"closed", []string{"false-positive"}, "fp"},    // label wins over closed
		{"open", []string{"risk-accepted"}, "accepted"}, // separator-insensitive
		{"open", []string{"Risk Accepted"}, "accepted"}, // case/space-insensitive
		{"closed", []string{"wontfix"}, "accepted"},     // accepted wins over closed→fixed
		{"open", []string{"kb-finding", "in progress"}, "triaged"},
		{"", nil, ""},
	}
	for _, c := range cases {
		if got := mapForgejoStatus(c.state, c.labels); got != c.want {
			t.Errorf("mapForgejoStatus(%q,%v) = %q, want %q", c.state, c.labels, got, c.want)
		}
	}
}

func TestExtractIssueNumber(t *testing.T) {
	const prefix = "acme/kb"
	cases := []struct {
		ref    string
		wantN  int64
		wantOK bool
	}{
		{"acme/kb#42", 42, true},
		{"#7", 7, true},
		{"13", 13, true},
		{"https://forge/acme/kb/issues/99", 99, true},
		{"other/repo#42", 0, false}, // different repo
		{"SEC-123", 0, false},       // Jira key
		{"", 0, false},
		{"acme/kb#0", 0, false},
	}
	for _, c := range cases {
		n, ok := extractIssueNumber(c.ref, prefix)
		if ok != c.wantOK || (ok && n != c.wantN) {
			t.Errorf("extractIssueNumber(%q) = (%d,%v), want (%d,%v)", c.ref, n, ok, c.wantN, c.wantOK)
		}
	}
}

func sampleEntities() entities.EntitiesFile {
	return entities.EntitiesFile{
		SchemaVersion: "v1",
		SourceTool:    "zap",
		Definitions: []entities.Definition{{
			DefinitionID: "def-1",
			PluginID:     "10038",
			Name:         "CSP Header Not Set",
			Taxonomy:     &entities.Taxonomy{CWEID: 693, CWEName: "Protection Mechanism Failure"},
			Remediation:  &entities.Remediation{Summary: "Set a Content-Security-Policy header."},
		}},
		Findings: []entities.Finding{
			{FindingID: "fin-high", DefinitionID: "def-1", URL: "https://t/a", Method: "GET", Name: "CSP /a", Risk: "High", Occurrences: 1},
			{FindingID: "fin-low", DefinitionID: "def-1", URL: "https://t/b", Method: "GET", Name: "CSP /b", Risk: "Low", Occurrences: 1},
		},
		Occurrences: []entities.Occurrence{
			{OccurrenceID: "occ-1", FindingID: "fin-high", DefinitionID: "def-1", URL: "https://t/a", ObservedAt: "2026-01-01T00:00:00Z", Evidence: "no CSP"},
		},
	}
}

// canonicalBody renders the exact issue body Export would write for the named
// finding (mirroring its def + latest-occurrence selection), so dedup-index
// stubs can store a body that Export sees as already current — letting the
// body-refresh path skip rather than PATCH.
func canonicalBody(ef entities.EntitiesFile, findingID string) string {
	defByID := map[string]*entities.Definition{}
	for i := range ef.Definitions {
		defByID[ef.Definitions[i].DefinitionID] = &ef.Definitions[i]
	}
	var occ *entities.Occurrence
	for i := range ef.Occurrences {
		if ef.Occurrences[i].FindingID == findingID {
			occ = &ef.Occurrences[i]
			break
		}
	}
	var f entities.Finding
	for _, ff := range ef.Findings {
		if ff.FindingID == findingID {
			f = ff
		}
	}
	return buildIssueBody(f, defByID[f.DefinitionID], occ, "")
}

// labelCreateStub handles POST /labels for stubs that don't otherwise care about
// label creation (risk/<sev> labels are created on demand). Returns 201 with a
// synthetic id echoing the requested name.
func labelCreateStub(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &in)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(forgejoLabel{ID: 99, Name: in["name"]})
}

func TestExportCreatesAndDedups(t *testing.T) {
	var created int32
	var nextNum int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			// Dedup index: no existing KB issues on first run.
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			atomic.AddInt32(&created, 1)
			n := atomic.AddInt64(&nextNum, 1)
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "devsecopskb-finding:") {
				t.Errorf("issue body missing finding marker: %s", body)
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"number": n})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	opts := Options{BaseURL: srv.URL, Token: "tok", Owner: "acme", Repo: "kb", MinRisk: "medium"}
	sum, err := Export(context.Background(), sampleEntities(), opts)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	// Only the High finding clears the medium floor.
	if sum.Created != 1 || sum.Skipped != 0 {
		t.Fatalf("first run: created=%d skipped=%d, want created=1 skipped=0", sum.Created, sum.Skipped)
	}
	if ref := sum.TicketRefs["fin-high"]; ref != "acme/kb#1" {
		t.Fatalf("ticket ref = %q, want acme/kb#1", ref)
	}
}

func TestExportSkipsExisting(t *testing.T) {
	// Existing open issue whose body is already exactly what Export would
	// render — so the body-refresh path skips rather than PATCHing.
	currentBody := canonicalBody(sampleEntities(), "fin-high")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case strings.HasSuffix(r.URL.Path, "/labels") && r.Method == http.MethodPost:
			labelCreateStub(w, r)
		case strings.HasSuffix(r.URL.Path, "/issues") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 5, "state": "open", "body": currentBody},
			})
		case strings.HasSuffix(r.URL.Path, "/issues") && r.Method == http.MethodPost:
			t.Errorf("should not POST a new issue when one exists")
			w.WriteHeader(http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/issues/") && r.Method == http.MethodPatch:
			t.Errorf("should not PATCH an unchanged issue body")
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
	if sum.Created != 0 || sum.Skipped != 1 {
		t.Fatalf("created=%d skipped=%d, want created=0 skipped=1", sum.Created, sum.Skipped)
	}
	if sum.TicketRefs["fin-high"] != "acme/kb#5" {
		t.Fatalf("ref = %q, want acme/kb#5", sum.TicketRefs["fin-high"])
	}
}

// Fix A13: losing the label-create race (another publisher created it between
// our list and our POST) must resolve to the winner's label, not fail the run.
func TestEnsureLabelsSurvivesCreateRace(t *testing.T) {
	var listCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			// First list: empty (label "missing"). Re-list after the failed
			// create: the racing winner's label is there.
			if atomic.AddInt32(&listCalls, 1) == 1 {
				json.NewEncoder(w).Encode([]forgejoLabel{})
				return
			}
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 7, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			w.WriteHeader(http.StatusConflict) // lost the race
			w.Write([]byte(`{"message":"label already exists"}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := newClient(http.DefaultClient, srv.URL, "tok", "acme", "kb")
	ids, err := c.ensureLabels(context.Background(), []string{"kb-finding"})
	if err != nil {
		t.Fatalf("ensureLabels failed on a lost create race: %v", err)
	}
	if ids["kb-finding"] != 7 {
		t.Fatalf("label id = %d, want the race winner's 7", ids["kb-finding"])
	}
}

// Fix A11/A24: when the dedup index holds duplicate issues for one finding,
// Export converges — lowest number wins, other open duplicates are closed,
// and the returned ticket ref points at the winner.
func TestExportReconcilesDuplicateIssues(t *testing.T) {
	var closed []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			json.NewEncoder(w).Encode([]forgejoLabel{{ID: 1, Name: "kb-finding"}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			labelCreateStub(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
			// Duplicate pair for fin-high; list deliberately returns the
			// HIGHER number first to prove winner choice is number-based,
			// not order-based (A24). The winner (#5) already holds the canonical
			// body so the only PATCH is the reconcile close of #9.
			json.NewEncoder(w).Encode([]map[string]any{
				{"number": 9, "state": "open", "body": "dup\n" + findingMarker("fin-high")},
				{"number": 5, "state": "open", "body": canonicalBody(sampleEntities(), "fin-high")},
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/"):
			mu.Lock()
			closed = append(closed, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			mu.Unlock()
			w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
			t.Errorf("must not create: finding already has issues")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := Export(context.Background(), sampleEntities(), Options{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if sum.Skipped != 1 || sum.Created != 0 {
		t.Fatalf("created=%d skipped=%d, want 0/1", sum.Created, sum.Skipped)
	}
	if sum.DuplicatesClosed != 1 {
		t.Fatalf("DuplicatesClosed=%d, want 1", sum.DuplicatesClosed)
	}
	if sum.TicketRefs["fin-high"] != "acme/kb#5" {
		t.Fatalf("ticket ref = %q, want lowest-numbered winner acme/kb#5", sum.TicketRefs["fin-high"])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(closed) != 1 || closed[0] != "9" {
		t.Fatalf("closed issues = %v, want exactly [9]", closed)
	}
}

func TestPullStatusWriteBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/issues/5") {
			json.NewEncoder(w).Encode(map[string]any{
				"state":  "closed",
				"labels": []map[string]any{{"name": "kb-finding"}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ef := sampleEntities()
	ef.Findings[0].Analyst = &entities.Analyst{TicketRefs: []string{"acme/kb#5"}}

	res, err := PullStatus(context.Background(), ef, PullOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("PullStatus: %v", err)
	}
	if res.Result.Updated != 1 {
		t.Fatalf("updated=%d, want 1", res.Result.Updated)
	}
	if got := res.Updated.Findings[0].Analyst.Status; got != "fixed" {
		t.Fatalf("status = %q, want fixed", got)
	}
}

func TestPullStatusReadOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"state": "closed"})
	}))
	defer srv.Close()

	ef := sampleEntities()
	ef.Findings[0].Analyst = &entities.Analyst{Status: "open", TicketRefs: []string{"acme/kb#5"}}

	res, err := PullStatus(context.Background(), ef, PullOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", ReadOnly: true})
	if err != nil {
		t.Fatalf("PullStatus: %v", err)
	}
	if got := res.Updated.Findings[0].Analyst.Status; got != "open" {
		t.Fatalf("read-only mutated status to %q, want open", got)
	}
	if res.RawStatuses["acme/kb#5"] != "closed" {
		t.Fatalf("raw status not captured: %v", res.RawStatuses)
	}
}

func TestExportWiki(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("---\ntitle: x\n---\n# Home\n\nhi"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# Finding 1"), 0o644)

	var creates int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			// no pages yet — everything is "created"
			json.NewEncoder(w).Encode([]map[string]any{})
		case strings.HasSuffix(r.URL.Path, "/wiki/new") && r.Method == http.MethodPost:
			atomic.AddInt32(&creates, 1)
			body, _ := io.ReadAll(r.Body)
			var payload map[string]string
			json.Unmarshal(body, &payload)
			if dec, _ := base64.StdEncoding.DecodeString(payload["content_base64"]); strings.Contains(string(dec), "---\ntitle:") {
				t.Errorf("frontmatter not stripped: %s", dec)
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("ExportWiki: %v", err)
	}
	if sum.Created != 2 {
		t.Fatalf("created=%d, want 2 (Home + Findings/fin-1)", sum.Created)
	}
}

// Fix A3: republishing identical content must be a no-op (skipped), not a
// PATCH that churns the wiki's git history on every run.
func TestExportWikiSkipsUnchangedContent(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("# Home\n\nhi"), 0o644)

	var patches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			json.NewEncoder(w).Encode([]map[string]any{{"title": "Home", "sub_url": "Home"}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/wiki/page/"):
			// Remote already holds exactly the local content.
			json.NewEncoder(w).Encode(map[string]string{
				"content_base64": base64.StdEncoding.EncodeToString([]byte("# Home\n\nhi")),
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/wiki/page/"):
			atomic.AddInt32(&patches, 1)
			w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	sum, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("ExportWiki: %v", err)
	}
	if sum.Skipped != 1 || sum.Updated != 0 || sum.Created != 0 {
		t.Fatalf("created=%d updated=%d skipped=%d, want 0/0/1", sum.Created, sum.Updated, sum.Skipped)
	}
	if atomic.LoadInt32(&patches) != 0 {
		t.Fatalf("unchanged content still PATCHed %d time(s)", patches)
	}
}

// Fix A22: a repo without its wiki enabled must fail the export hard with a
// clear message, not degrade into N silent per-page 404 warnings.
func TestExportWikiDisabledIsHardError(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("# Home"), 0o644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb" {
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": false})
			return
		}
		t.Errorf("unexpected request past preflight: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err == nil || !strings.Contains(err.Error(), "wiki is not enabled") {
		t.Fatalf("err = %v, want hard 'wiki is not enabled' error", err)
	}
}

// Live finding (Gitea 1.22): on API-created repos the wiki REST API is broken
// server-side — writes commit but every read 404s with "object does not exist
// [id: refs/heads/...]", and PATCHing wiki_branch is a silent no-op, so no
// client-side repair exists. The export must fail FAST on the first (canary)
// write with one descriptive error, not 13 identical per-page 404s.
func TestExportWikiFailsFastOnWikiBranchBug(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("# Home"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# F1"), 0o644)

	var wikiPosts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": ""})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wiki/new"):
			atomic.AddInt32(&wikiPosts, 1)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":["object does not exist [id: refs/heads/master, rel_path: ]"],"message":"The target couldn't be found."}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	_, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err == nil || !strings.Contains(err.Error(), "wiki_branch bug") {
		t.Fatalf("err = %v, want descriptive wiki_branch-bug hard error", err)
	}
	if got := atomic.LoadInt32(&wikiPosts); got != 1 {
		t.Fatalf("wiki POSTs = %d, want 1 (fail fast after the canary, no per-page error spam)", got)
	}
}

// Live finding (Gitea 1.22): label names are NOT unique — two racing creates
// both 201 and the server's name-based label queries then return nothing.
// After a successful create that turns out to be a duplicate, ensureLabels
// must adopt the lowest-id label and delete its own duplicate.
func TestEnsureLabelsCanonicalizesDuplicateNames(t *testing.T) {
	var listCalls int32
	var deleted []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
			// First list: empty. Re-list after our create: the racing winner's
			// label (id 7) AND ours (id 9) both exist with the same name.
			if atomic.AddInt32(&listCalls, 1) == 1 {
				json.NewEncoder(w).Encode([]forgejoLabel{})
				return
			}
			json.NewEncoder(w).Encode([]forgejoLabel{
				{ID: 9, Name: "kb-finding"},
				{ID: 7, Name: "kb-finding"},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/labels"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(forgejoLabel{ID: 9, Name: "kb-finding"})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/labels/"):
			mu.Lock()
			deleted = append(deleted, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := newClient(http.DefaultClient, srv.URL, "tok", "acme", "kb")
	ids, err := c.ensureLabels(context.Background(), []string{"kb-finding"})
	if err != nil {
		t.Fatalf("ensureLabels: %v", err)
	}
	if ids["kb-finding"] != 7 {
		t.Fatalf("label id = %d, want canonical lowest 7", ids["kb-finding"])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "9" {
		t.Fatalf("deleted labels = %v, want exactly [9] (our duplicate)", deleted)
	}
}
