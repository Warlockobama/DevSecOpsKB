package synccore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fastReq builds a request with a context so retry sleeps can be bounded.
func fastReq(t *testing.T, method, url string, body string) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// A14: a transient 503 must be retried (with the request body replayed) and
// succeed on the next attempt.
func TestDoWithRetryRetriesTransient503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	resp, err := DoWithRetry(http.DefaultClient, fastReq(t, http.MethodPost, srv.URL, `{"x":1}`), 3)
	if err != nil {
		t.Fatalf("DoWithRetry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("server saw %d calls, want 2 (one retry)", got)
	}
}

// Plain 500 is deliberately NOT retried — it is usually deterministic.
func TestDoWithRetryDoesNotRetry500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := DoWithRetry(http.DefaultClient, fastReq(t, http.MethodPost, srv.URL, ""), 3)
	if err == nil {
		t.Fatal("want error on terminal 500")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("server saw %d calls, want 1 (no retry on 500)", got)
	}
}

// Transport-level blips (connection refused/reset) are retried too.
func TestDoWithRetryRetriesTransportError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	flaky := doerFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("connection reset by peer")
		}
		return http.DefaultClient.Do(req)
	})
	resp, err := DoWithRetry(flaky, fastReq(t, http.MethodGet, srv.URL, ""), 3)
	if err != nil {
		t.Fatalf("DoWithRetry: %v", err)
	}
	resp.Body.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("doer saw %d calls, want 2", got)
	}
}

// The Raw variant must hand terminal non-2xx back as data so callers can keep
// their 404-means-missing logic while still getting transient retries.
func TestDoWithRetryRawReturns404AsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resp, err := DoWithRetryRaw(http.DefaultClient, fastReq(t, http.MethodGet, srv.URL, ""), 3)
	if err != nil {
		t.Fatalf("DoWithRetryRaw: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 passed through", resp.StatusCode)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }
