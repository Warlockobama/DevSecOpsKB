package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWikiMetricsCountRetryAttempts(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n == 1 {
			w.WriteHeader(503)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
			w.Write([]byte("[]"))
			return
		}
		w.Write([]byte(`{"has_wiki":true}`))
	}))
	defer srv.Close()
	sum, err := ExportWiki(context.Background(), t.TempDir(), WikiOptions{BaseURL: srv.URL, Token: "synthetic-secret", Owner: "synthetic-owner", Repo: "synthetic-repo", RequestDelay: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Requests != 3 || len(sum.Phases) != 3 {
		t.Fatalf("metrics=%+v", sum)
	}
	if p := sum.Phases[0]; p.Phase != "preflight" || p.Requests != 2 || p.Retries != 1 || p.DurationMS < 1900 {
		t.Fatalf("preflight=%+v", p)
	}
	if p := sum.Phases[1]; p.Phase != "discovery" || p.Requests != 1 || p.Retries != 0 {
		t.Fatalf("discovery=%+v", p)
	}
	if sum.DurationMS < sum.Phases[0].DurationMS {
		t.Fatal("total time omitted retry backoff")
	}
	encoded, _ := json.Marshal(sum.Phases)
	for _, marker := range []string{"synthetic", "http", "token"} {
		if strings.Contains(string(encoded), marker) {
			t.Fatal("phase metrics retained request data")
		}
	}
}

func TestWikiMetricsSurviveDiscoveryCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
			<-r.Context().Done()
			return
		}
		w.Write([]byte(`{"has_wiki":true}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sum, err := ExportWiki(ctx, t.TempDir(), WikiOptions{BaseURL: srv.URL, Token: "synthetic", Owner: "scale", Repo: "disposable", RequestDelay: time.Nanosecond})
	if err == nil {
		t.Fatal("canceled discovery returned success")
	}
	if sum.Requests != 2 || len(sum.Phases) != 2 || sum.DurationMS < 40 {
		t.Fatalf("early-failure metrics=%+v", sum)
	}
	if p := sum.Phases[1]; p.Phase != "discovery" || p.Requests != 1 || p.Retries != 0 || p.DurationMS < 30 {
		t.Fatalf("discovery=%+v", p)
	}
}
