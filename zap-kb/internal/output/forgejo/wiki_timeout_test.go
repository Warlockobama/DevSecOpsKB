package forgejo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExportWikiStopsLinkRepairAfterPassDeadline(t *testing.T) {
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("see [[findings/fin-1.md|F1]]"), 0o644)
	os.WriteFile(filepath.Join(vault, "DASHBOARD.md"), []byte("see [[findings/fin-1.md|F1]]"), 0o644)
	os.MkdirAll(filepath.Join(vault, "findings"), 0o755)
	os.WriteFile(filepath.Join(vault, "findings", "fin-1.md"), []byte("# F1"), 0o644)

	var listCalls atomic.Int32
	var patchCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			if listCalls.Add(1) == 1 {
				json.NewEncoder(w).Encode([]map[string]any{})
				return
			}
			json.NewEncoder(w).Encode([]map[string]any{
				{"title": "Dashboard", "sub_url": "Dashboard"},
				{"title": "Home", "sub_url": "Home"},
				{"title": "Findings/fin-1", "sub_url": "Findings%2Ffin-1.-"},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/wiki/new"):
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/wiki/page/"):
			patchCalls.Add(1)
			_, _ = io.ReadAll(r.Body)
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sum, err := ExportWiki(ctx, vault, WikiOptions{
		BaseURL:      srv.URL,
		Token:        "t",
		Owner:        "acme",
		Repo:         "kb",
		Timeout:      5 * time.Second,
		RequestDelay: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("ExportWiki: %v", err)
	}
	if sum.Errors != 1 {
		t.Fatalf("errors=%d, want one aggregate deadline failure", sum.Errors)
	}
	if got := patchCalls.Load(); got != 1 {
		t.Fatalf("link repair PATCH calls=%d, want 1 before cancellation stopped the pass", got)
	}
}

// The wiki pass has two limits and they are not the same limit. The caller's
// context bounds the whole pass; WikiOptions.Timeout bounds a single API
// request. Both matter, and the second one is easy to miss: a wiki large enough
// that listing its pages takes longer than this client's 30s default kills the
// publish while the pass deadline is barely touched, because the listing's cost
// is the size of the wiki rather than the size of the publish. Until now
// nothing set Timeout, so nothing tested it either.
func TestDefaultHTTPUsesTheCallersRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	// A nanosecond delay rather than zero: this test is about the timeout, and
	// the 250ms throttle default would otherwise dominate it.
	impatient := defaultHTTP(20*time.Millisecond, time.Nanosecond)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if resp, err := impatient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("a 20ms timeout accepted a 150ms response; the caller's value is being ignored")
	}

	patient := defaultHTTP(10*time.Second, time.Nanosecond)
	req, _ = http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := patient.Do(req)
	if err != nil {
		t.Fatalf("a 10s timeout rejected a 150ms response: %v", err)
	}
	resp.Body.Close()
}

// The wiring the timeout travels through: WikiOptions.Timeout has existed all
// along and had no caller, so this asserts ExportWiki actually hands it to the
// client rather than dropping it. The slow endpoint is the page listing, which
// is the call that fails in the field.
func TestExportWikiAppliesTheRequestTimeout(t *testing.T) {
	vault := t.TempDir()
	if err := os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("# Home\n\nhi"), 0o644); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/repos/acme/kb":
			json.NewEncoder(w).Encode(map[string]any{"has_wiki": true, "wiki_branch": "main"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/wiki/pages"):
			time.Sleep(400 * time.Millisecond)
			json.NewEncoder(w).Encode([]map[string]any{})
		default:
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		}
	}))
	defer srv.Close()

	opts := WikiOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb", RequestDelay: time.Nanosecond}

	opts.Timeout = 25 * time.Millisecond
	sum, err := ExportWiki(context.Background(), vault, opts)
	if err == nil && sum.Errors == 0 {
		t.Fatalf("a 25ms request timeout published cleanly (%+v); the option is not reaching the client", sum)
	}

	opts.Timeout = 10 * time.Second
	sum, err = ExportWiki(context.Background(), vault, opts)
	if err != nil {
		t.Fatalf("a 10s request timeout failed on a 400ms listing: %v", err)
	}
	if sum.Errors != 0 {
		t.Fatalf("errors=%d on a publish that had time to finish", sum.Errors)
	}
}
