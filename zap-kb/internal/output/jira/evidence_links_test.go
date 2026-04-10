package jira

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSyncFindingEvidenceLinks_AddsMissingRemoteLink(t *testing.T) {
	var getCount, postCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-1/remotelink":
			atomic.AddInt64(&getCount, 1)
			_ = json.NewEncoder(w).Encode([]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SEC-1/remotelink":
			atomic.AddInt64(&postCount, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	sum, err := SyncFindingEvidenceLinks(context.Background(), map[string]string{"fin-1": "SEC-1"}, map[string]string{"fin-1": "https://example/wiki/spaces/KB/pages/123"}, Options{BaseURL: srv.URL, Username: "u", APIToken: "t"})
	if err != nil {
		t.Fatalf("SyncFindingEvidenceLinks: %v", err)
	}
	if sum.Added != 1 || sum.Skipped != 0 || sum.Errors != 0 {
		t.Fatalf("unexpected summary: %#v", sum)
	}
	if atomic.LoadInt64(&getCount) != 1 || atomic.LoadInt64(&postCount) != 1 {
		t.Fatalf("expected 1 GET and 1 POST, got %d GET %d POST", getCount, postCount)
	}
}

func TestSyncFindingEvidenceLinks_SkipsExistingRemoteLink(t *testing.T) {
	var postCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-1/remotelink":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"object": map[string]any{"url": "https://example/wiki/spaces/KB/pages/123"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SEC-1/remotelink":
			atomic.AddInt64(&postCount, 1)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	sum, err := SyncFindingEvidenceLinks(context.Background(), map[string]string{"fin-1": "SEC-1"}, map[string]string{"fin-1": "https://example/wiki/spaces/KB/pages/123"}, Options{BaseURL: srv.URL, Username: "u", APIToken: "t"})
	if err != nil {
		t.Fatalf("SyncFindingEvidenceLinks: %v", err)
	}
	if sum.Added != 0 || sum.Skipped != 1 || sum.Errors != 0 {
		t.Fatalf("unexpected summary: %#v", sum)
	}
	if atomic.LoadInt64(&postCount) != 0 {
		t.Fatalf("expected no POST when link already exists, got %d", postCount)
	}
}
