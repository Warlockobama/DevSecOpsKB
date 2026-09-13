package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestExportDiagnosticsAndDedupSafety(t *testing.T) {
	for _, stage := range []string{"lookup", "create"} {
		for _, status := range []int{400, 401, 403, 404, 429, 500} {
			t.Run(fmt.Sprintf("%s/%d", stage, status), func(t *testing.T) {
				var creates atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					isCreate := strings.HasSuffix(r.URL.Path, "/issue")
					if isCreate {
						creates.Add(1)
					}
					if (stage == "lookup" && !isCreate) || (stage == "create" && isCreate) {
						w.Header().Set("Retry-After", "0")
						w.WriteHeader(status)
						io.WriteString(w, `{"errorMessages":["SENSITIVE_AUTH_TOKEN"],"errors":{"customfield_10042":"Account SENSITIVE_PERSON is required","SENSITIVE_FIELD_NAME":"SENSITIVE_BODY"}}`)
						return
					}
					json.NewEncoder(w).Encode(searchResponse(""))
				}))
				defer srv.Close()
				opts := defaultOpts(srv.URL)
				opts.RequestDelay = -1
				sum, err := Export(context.Background(), makeEntities(makeFinding("fin-diag", "high", "https://example.test")), opts)
				if err != nil {
					t.Fatal(err)
				}
				if sum.Errors != 1 || len(sum.Diagnostics) != 1 || sum.Diagnostics[0].FindingID != "fin-diag" || sum.Diagnostics[0].Stage != stage {
					t.Fatalf("unexpected result: %+v", sum)
				}
				if stage == "lookup" && creates.Load() != 0 {
					t.Fatal("created after failed dedup")
				}
				if stage == "create" && status != 429 && creates.Load() != 1 {
					t.Fatal("blindly replayed create")
				}
				if stage == "create" && status == 429 && creates.Load() != 3 {
					t.Fatal("429 retry bound not honored")
				}
				data, _ := json.Marshal(sum.Diagnostics)
				if strings.Contains(string(data), "SENSITIVE") {
					t.Fatalf("sensitive response leaked: %s", data)
				}
				if status < 500 && sum.Diagnostics[0].HTTPStatus != status {
					t.Fatalf("lost status: %+v", sum.Diagnostics)
				}
			})
		}
	}
}

type failingCreateClient struct {
	calls       int
	searchCalls int
	resolved    bool
	failure     string
}

func (c *failingCreateClient) Do(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/issue") {
		c.calls++
		switch c.failure {
		case "transport":
			return nil, errors.New("transport SENSITIVE_URL")
		case "500":
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{"errors":{}}`))}, nil
		case "missing_key":
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		default:
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{broken`))}, nil
		}
	}
	c.searchCalls++
	body := `{"issues":[]}`
	if c.resolved {
		body = `{"issues":[{"key":"SEC-42"}]}`
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestCreateAmbiguityReconcilesWithoutReplay(t *testing.T) {
	for _, failure := range []string{"transport", "500", "missing_key", "malformed"} {
		for _, resolved := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/%v", failure, resolved), func(t *testing.T) {
				c := &failingCreateClient{resolved: resolved, failure: failure}
				key, err := createIssue(context.Background(), c, "synthetic", "https://jira.example", false, "Bug", makeFinding("fin", "high", "https://example.test"), nil, nil, "", Options{ProjectKey: "SEC"})
				if c.calls != 1 || c.searchCalls < 1 {
					t.Fatalf("unexpected attempts: %+v", c)
				}
				if resolved {
					if err != nil || key != "SEC-42" {
						t.Fatalf("reconciliation failed: %q %v", key, err)
					}
				} else {
					if err == nil || diagnostic("create", "fin", err).Category != "ambiguous_create" {
						t.Fatalf("ambiguity lost: %v", err)
					}
				}
			})
		}
	}
}

func TestMalformedLookupNeverCreates(t *testing.T) {
	for _, body := range []string{`{}`, `{"issues":null}`, `{"issues":[{}]}`, `{broken`} {
		var creates atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/issue") {
				creates.Add(1)
			}
			io.WriteString(w, body)
		}))
		opts := defaultOpts(srv.URL)
		opts.RequestDelay = -1
		sum, err := Export(context.Background(), makeEntities(makeFinding("fin", "high", "https://example.test")), opts)
		srv.Close()
		if err != nil || sum.Errors != 1 || creates.Load() != 0 {
			t.Fatalf("unsafe malformed lookup: %+v %v", sum, err)
		}
	}
}

func TestExportCancellationRecorded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := defaultOpts("http://unused.invalid")
	opts.RequestDelay = -1
	sum, err := Export(ctx, makeEntities(makeFinding("fin", "high", "https://example.test")), opts)
	if err != nil || sum.Errors != 1 || sum.Diagnostics[0].Category != "canceled" {
		t.Fatalf("cancellation lost: %+v %v", sum, err)
	}
}

func TestRequestedEpicFailureRemainsPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/jql") {
			json.NewEncoder(w).Encode(searchResponse(""))
			return
		}
		var req struct {
			Fields map[string]any `json:"fields"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Fields["issuetype"].(map[string]any)["name"] == "Epic" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"key":"SEC-1"}`)
	}))
	defer srv.Close()
	ef := makeEntities(makeFinding("fin", "high", "https://example.test"))
	ef.Definitions = []entities.Definition{{DefinitionID: "def-10016"}}
	opts := defaultOpts(srv.URL)
	opts.RequestDelay = -1
	opts.DetectionEpic = true
	sum, err := Export(context.Background(), ef, opts)
	if err != nil || sum.Created != 1 || sum.Errors != 1 || sum.Diagnostics[0].Stage != "epic" {
		t.Fatalf("epic failure lost: %+v %v", sum, err)
	}
}

func TestCloudURLsAndBrowserRoot(t *testing.T) {
	for _, raw := range []string{"https://tenant.atlassian.net", "https://api.atlassian.com/ex/jira/cloud-id", "http://api.atlassian.com:8080/ex/jira/mock"} {
		if !IsCloudURL(raw) {
			t.Errorf("Cloud URL not recognized: %s", raw)
		}
	}
	for _, raw := range []string{"https://jira.example", "https://tenant.atlassian.net.evil.test", "https://api.atlassian.com/ex/confluence/id", "https://api.atlassian.com/ex/jira"} {
		if IsCloudURL(raw) {
			t.Errorf("unexpected Cloud URL: %s", raw)
		}
	}
	if BrowserBase("https://api.atlassian.com/ex/jira/id", "") != "" || BrowserBase("https://api.atlassian.com/ex/jira/id", "https://tenant.atlassian.net/") != "https://tenant.atlassian.net" {
		t.Fatal("API gateway used as browser URL")
	}
}

func TestCreate429ThenSuccessAndCancellation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"key":"SEC-1"}`)
	}))
	defer srv.Close()
	key, err := createIssue(context.Background(), srv.Client(), "synthetic", srv.URL, false, "Bug", makeFinding("fin", "high", "https://example.test"), nil, nil, "", Options{ProjectKey: "SEC"})
	if err != nil || key != "SEC-1" || calls.Load() != 2 {
		t.Fatalf("429 recovery: %q %v attempts %d", key, err, calls.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	_, err = createIssue(ctx, srv.Client(), "synthetic", srv.URL, false, "Bug", makeFinding("fin", "high", "https://example.test"), nil, nil, "", Options{ProjectKey: "SEC"})
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 2 {
		t.Fatal("sent canceled create")
	}
}
