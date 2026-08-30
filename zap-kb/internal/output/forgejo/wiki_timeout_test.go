package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
