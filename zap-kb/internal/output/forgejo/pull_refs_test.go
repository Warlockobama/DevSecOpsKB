package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestExtractIssueNumber_URLMustMatchRepo(t *testing.T) {
	const prefix = "owner/repo"
	cases := []struct {
		ref   string
		wantN int64
		wOK   bool
	}{
		{"https://forge.example/owner/repo/issues/42", 42, true},
		{"https://forge.example/other/repo/issues/42", 0, false},
		{"https://github.com/foo/bar/issues/42", 0, false},
		{"https://forge.example/OWNER/REPO/issues/7/", 7, true},
		{"owner/repo#9", 9, true},
		{"other/repo#9", 0, false},
		{"#5", 5, true},
		{"12", 12, true},
		{"SEC-123", 0, false},
	}
	for _, c := range cases {
		n, ok := extractIssueNumber(c.ref, prefix)
		if ok != c.wOK || (ok && n != c.wantN) {
			t.Errorf("extractIssueNumber(%q) = (%d,%v), want (%d,%v)", c.ref, n, ok, c.wantN, c.wOK)
		}
	}
}

func TestPullStatus_FetchesEachIssueOnce(t *testing.T) {
	var getsTo1 int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/issues/1") {
			atomic.AddInt32(&getsTo1, 1)
			json.NewEncoder(w).Encode(map[string]any{
				"state":  "closed",
				"labels": []map[string]any{{"name": "kb-finding"}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Three findings all reference issue #1.
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			{FindingID: "a", Analyst: &entities.Analyst{TicketRefs: []string{"acme/kb#1"}}},
			{FindingID: "b", Analyst: &entities.Analyst{TicketRefs: []string{"acme/kb#1"}}},
			{FindingID: "c", Analyst: &entities.Analyst{TicketRefs: []string{"acme/kb#1"}}},
		},
	}

	res, err := PullStatus(context.Background(), ef, PullOptions{BaseURL: srv.URL, Token: "t", Owner: "acme", Repo: "kb"})
	if err != nil {
		t.Fatalf("PullStatus: %v", err)
	}
	if got := atomic.LoadInt32(&getsTo1); got != 1 {
		t.Fatalf("GET /issues/1 happened %d times, want exactly 1", got)
	}
	for i := range res.Updated.Findings {
		if res.Updated.Findings[i].Analyst.Status != "fixed" {
			t.Fatalf("finding %s status = %q, want fixed", res.Updated.Findings[i].FindingID, res.Updated.Findings[i].Analyst.Status)
		}
	}
}
