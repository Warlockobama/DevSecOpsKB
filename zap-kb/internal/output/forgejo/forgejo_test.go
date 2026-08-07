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

func TestClassificationMarkdown_SkipsEchoedCWEName(t *testing.T) {
	// An unresolved CWE name that echoes the id must not render "CWE-552: CWE-552".
	def := &entities.Definition{
		Taxonomy: &entities.Taxonomy{CWEID: 552, CWEName: "CWE-552"},
	}
	got := classificationMarkdown(def)
	if strings.Contains(got, "CWE-552: CWE-552") {
		t.Errorf("rendered echoed CWE name:\n%s", got)
	}
	if !strings.Contains(got, "CWE-552") {
		t.Errorf("expected CWE-552 id in output:\n%s", got)
	}
}

func TestClassificationMarkdown_KeepsResolvedCWEName(t *testing.T) {
	def := &entities.Definition{
		Taxonomy: &entities.Taxonomy{CWEID: 552, CWEName: "Files or Directories Accessible to External Parties"},
	}
	got := classificationMarkdown(def)
	if !strings.Contains(got, "CWE-552: Files or Directories Accessible to External Parties") {
		t.Errorf("expected resolved CWE name in output:\n%s", got)
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

// WS04: internal vault links must be rewritten from file names to published
// wiki page names, or every cross-link 404s on the live wiki.
func TestExportWiki_RewritesLinks(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("see [Triage board](triage-board.md)"), 0o644)
	os.WriteFile(filepath.Join(vault, "triage-board.md"), []byte("# Triage"), 0o644)

	var homeContent string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wiki/new"):
			body, _ := io.ReadAll(r.Body)
			var p map[string]string
			json.Unmarshal(body, &p)
			if p["title"] == "Home" {
				dec, _ := base64.StdEncoding.DecodeString(p["content_base64"])
				mu.Lock()
				homeContent = string(dec)
				mu.Unlock()
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if _, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"}); err != nil {
		t.Fatalf("ExportWiki: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(homeContent, "](Triage%20Board)") {
		t.Fatalf("link not rewritten to page name; Home content = %q", homeContent)
	}
	if strings.Contains(homeContent, "](triage-board.md)") {
		t.Fatalf("stale file-name link survived; Home content = %q", homeContent)
	}
}

// WS05: Forgejo does not render Obsidian [[wikilinks]]; any wikilink whose
// target is not a published page must be degraded to plain text, never pushed
// as literal [[..]] syntax.
func TestExportWiki_NoLiteralWikilinkPublished(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"),
		[]byte("see [[findings/fin-1.md|F1]] and [[scans/missing.md|old scan]]"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# F1"), 0o644)

	var mu sync.Mutex
	published := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			json.NewEncoder(w).Encode([]map[string]any{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wiki/new"):
			body, _ := io.ReadAll(r.Body)
			var p map[string]string
			json.Unmarshal(body, &p)
			dec, _ := base64.StdEncoding.DecodeString(p["content_base64"])
			mu.Lock()
			published[p["title"]] = string(dec)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if _, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"}); err != nil {
		t.Fatalf("ExportWiki: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	home := published["Home"]
	if strings.Contains(home, "[[") {
		t.Fatalf("literal wikilink syntax published:\n%s", home)
	}
	if !strings.Contains(home, "[F1](Findings%2Ffin-1)") {
		t.Fatalf("resolved wikilink not rewritten:\n%s", home)
	}
	if !strings.Contains(home, "old scan") || strings.Contains(home, "missing.md") {
		t.Fatalf("unresolved wikilink should degrade to its alias text:\n%s", home)
	}
}

// WS06: the second pass must repair links whose server-issued sub_url differs
// from client-side url.PathEscape — the only authoritative addressing for
// hierarchical page names on servers with a divergent escaping scheme.
func TestExportWiki_SecondPassRepairsLinksWithServerSubURLs(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("see [[findings/fin-1.md|F1]]"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# F1"), 0o644)

	var mu sync.Mutex
	var listCalls int
	patched := map[string]string{} // sub_url -> decoded content
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			mu.Lock()
			listCalls++
			first := listCalls == 1
			mu.Unlock()
			if first {
				// Pre-publish listing: nothing exists yet.
				json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
			// Post-publish listing: the server escapes "Findings/fin-1" with
			// its own scheme that PathEscape cannot reproduce.
			json.NewEncoder(w).Encode([]map[string]any{
				{"title": "Home", "sub_url": "Home"},
				{"title": "Findings/fin-1", "sub_url": "Findings%2Ffin-1.-"},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wiki/new"):
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/wiki/page/"):
			body, _ := io.ReadAll(r.Body)
			var p map[string]string
			json.Unmarshal(body, &p)
			dec, _ := base64.StdEncoding.DecodeString(p["content_base64"])
			sub := strings.TrimPrefix(r.RequestURI, "/api/v1/repos/acme/kb/wiki/page/")
			mu.Lock()
			patched[sub] = string(dec)
			mu.Unlock()
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
	mu.Lock()
	defer mu.Unlock()
	if sum.LinkFixes != 1 {
		t.Fatalf("LinkFixes = %d, want 1 (only Home links to the quirky page)", sum.LinkFixes)
	}
	home, ok := patched["Home"]
	if !ok {
		t.Fatalf("Home was not re-PATCHed; patched = %v", patched)
	}
	if !strings.Contains(home, "](Findings%2Ffin-1.-)") {
		t.Fatalf("repaired Home must use the server sub_url:\n%s", home)
	}
	if _, ok := patched["Findings%2Ffin-1.-"]; ok {
		t.Fatalf("fin-1 has no internal links and must not be re-PATCHed")
	}
}

// WS07 (A3 for link repair): on a steady-state re-publish against a server
// whose sub_url escaping differs from url.PathEscape, pass 1 must render with
// the known sub_urls so every page compares equal to the remote and is
// skipped — no PATCH, no wiki git churn from the repair pass.
func TestExportWiki_RepublishWithQuirkySubURLsIsNoOp(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("see [[findings/fin-1.md|F1]]"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# F1"), 0o644)

	// Remote state after a previous publish + repair: Home already links via
	// the server's quirky sub_url.
	remote := map[string]string{
		"Home":               "see [F1](Findings%2Ffin-1.-)",
		"Findings%2Ffin-1.-": "# F1",
	}
	var mu sync.Mutex
	var writes int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"title": "Home", "sub_url": "Home"},
				{"title": "Findings/fin-1", "sub_url": "Findings%2Ffin-1.-"},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/wiki/page/"):
			sub := strings.TrimPrefix(r.RequestURI, "/api/v1/repos/acme/kb/wiki/page/")
			mu.Lock()
			content := remote[sub]
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{
				"content_base64": base64.StdEncoding.EncodeToString([]byte(content)),
			})
		case r.Method == http.MethodPost || r.Method == http.MethodPatch:
			atomic.AddInt32(&writes, 1)
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
	if sum.Skipped != 2 || sum.Updated != 0 || sum.Created != 0 || sum.LinkFixes != 0 {
		t.Fatalf("created=%d updated=%d skipped=%d link_fixes=%d, want 0/0/2/0",
			sum.Created, sum.Updated, sum.Skipped, sum.LinkFixes)
	}
	if n := atomic.LoadInt32(&writes); n != 0 {
		t.Fatalf("steady-state re-publish performed %d write(s); link repair must not churn the wiki", n)
	}
}

// WS04: with -forgejo-wiki-prune, KB-owned entity pages absent from the publish
// are deleted; non-entity pages (Home) are never touched.
func TestExportWiki_PruneDeletesStaleEntityPages(t *testing.T) {
	run := func(prune bool) []string {
		vault := t.TempDir()
		os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("# Home"), 0o644)

		var deleted []string
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
				json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
				json.NewEncoder(w).Encode([]map[string]any{
					{"title": "Home", "sub_url": "Home"},
					{"title": "Findings/fin-old", "sub_url": "Findings%2Ffin-old"},
				})
			case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/wiki/page/"):
				// Home already exists with identical content → skipped.
				json.NewEncoder(w).Encode(map[string]string{
					"content_base64": base64.StdEncoding.EncodeToString([]byte("# Home")),
				})
			case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/wiki/page/"):
				// Use RequestURI so the still-escaped sub_url (%2F) is preserved;
				// r.URL.Path decodes %2F to '/'.
				mu.Lock()
				deleted = append(deleted, r.RequestURI[strings.LastIndex(r.RequestURI, "/")+1:])
				mu.Unlock()
				w.Write([]byte("{}"))
			default:
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer srv.Close()

		sum, err := ExportWiki(context.Background(), vault, WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", Prune: prune})
		if err != nil {
			t.Fatalf("ExportWiki: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if prune && sum.Pruned != len(deleted) {
			t.Fatalf("Pruned=%d but %d deletes", sum.Pruned, len(deleted))
		}
		return append([]string(nil), deleted...)
	}

	if got := run(true); len(got) != 1 || got[0] != "Findings%2Ffin-old" {
		t.Fatalf("prune=true deleted = %v, want exactly [Findings%%2Ffin-old]", got)
	}
	if got := run(false); len(got) != 0 {
		t.Fatalf("prune=false deleted = %v, want none", got)
	}
}
