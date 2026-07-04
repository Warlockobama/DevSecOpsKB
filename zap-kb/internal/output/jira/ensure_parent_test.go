package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func basicAuth(t *testing.T) string {
	t.Helper()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("u:t"))
}

func TestEnsureIssueParent_AddsMissingParent(t *testing.T) {
	var putCount int64
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/KAN-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"fields": map[string]any{}})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/3/issue/KAN-1":
			atomic.AddInt64(&putCount, 1)
			b, _ := io.ReadAll(r.Body)
			lastBody = string(b)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	updated, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "KAN-1", "KAN-99")
	if err != nil {
		t.Fatalf("ensureIssueParent: %v", err)
	}
	if !updated {
		t.Fatalf("expected updated=true when parent was missing")
	}
	if atomic.LoadInt64(&putCount) != 1 {
		t.Fatalf("expected 1 PUT, got %d", putCount)
	}
	if !strings.Contains(lastBody, `"parent"`) || !strings.Contains(lastBody, `"KAN-99"`) {
		t.Fatalf("PUT body missing parent/key: %s", lastBody)
	}
}

func TestEnsureIssueParent_NoOpWhenAlreadyLinked(t *testing.T) {
	var putCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/KAN-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"fields": map[string]any{
					"parent": map[string]string{"key": "KAN-99"},
				},
			})
		case r.Method == http.MethodPut:
			atomic.AddInt64(&putCount, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	updated, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "KAN-1", "KAN-99")
	if err != nil {
		t.Fatalf("ensureIssueParent: %v", err)
	}
	if updated {
		t.Fatalf("expected updated=false when parent already matched")
	}
	if atomic.LoadInt64(&putCount) != 0 {
		t.Fatalf("expected no PUT when parent already matched, got %d", putCount)
	}
}

func TestEnsureIssueParent_ReplacesDifferentParent(t *testing.T) {
	var putCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/KAN-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"fields": map[string]any{
					"parent": map[string]string{"key": "KAN-50"},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/rest/api/3/issue/KAN-1":
			atomic.AddInt64(&putCount, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	updated, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "KAN-1", "KAN-99")
	if err != nil {
		t.Fatalf("ensureIssueParent: %v", err)
	}
	if !updated {
		t.Fatalf("expected updated=true when parent differs")
	}
	if atomic.LoadInt64(&putCount) != 1 {
		t.Fatalf("expected 1 PUT, got %d", putCount)
	}
}

func TestEnsureIssueParent_EmptyKeysAreNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server should not be hit, got %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()
	if u, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "", "KAN-99"); err != nil || u {
		t.Fatalf("expected no-op for empty issue key, got updated=%v err=%v", u, err)
	}
	if u, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "KAN-1", ""); err != nil || u {
		t.Fatalf("expected no-op for empty epic key, got updated=%v err=%v", u, err)
	}
}

func TestEnsureIssueParent_DeletedIssueIsSilentNoOp(t *testing.T) {
	// A 404 on the parent read means the issue was deleted since the dedup
	// search — that's a quiet skip (false, nil), not an error. Regression test
	// for the dead 404 check before the synccore migration.
	var putCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/KAN-1":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errorMessages":["Issue does not exist"]}`))
		case r.Method == http.MethodPut:
			atomic.AddInt64(&putCount, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			// t.Fatalf is illegal off the test goroutine — record and fail the request.
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	updated, err := ensureIssueParent(context.Background(), srv.Client(), basicAuth(t), srv.URL, "KAN-1", "KAN-99")
	if err != nil {
		t.Fatalf("404 must not be an error, got: %v", err)
	}
	if updated {
		t.Fatalf("expected updated=false for deleted issue")
	}
	if atomic.LoadInt64(&putCount) != 0 {
		t.Fatalf("expected no PUT for deleted issue, got %d", putCount)
	}
}
