//go:build e2e

// Package harness provides the plumbing for adversarial E2E tests of the
// Forgejo sync layer: per-test ephemeral repositories on a real Forgejo
// instance, a programmable fault-injection reverse proxy, typed entity
// fixtures, and a builder/runner for the real zap-kb binary.
//
// Configuration comes from the environment:
//
//	E2E_FORGEJO_URL    base URL of a disposable Forgejo instance (required)
//	E2E_FORGEJO_TOKEN  admin API token for that instance (required)
//
// Tests skip when the variables are unset so `go test -tags e2e` stays safe
// to run anywhere. The instance is assumed disposable: tests create and
// delete repositories freely.
package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// Env holds the resolved test-environment configuration.
type Env struct {
	BaseURL string
	Token   string
	Owner   string // login of the token's user, resolved once
}

// FromEnv resolves the E2E environment or skips the test.
func FromEnv(t *testing.T) *Env {
	t.Helper()
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("E2E_FORGEJO_URL")), "/")
	token := strings.TrimSpace(os.Getenv("E2E_FORGEJO_TOKEN"))
	if base == "" || token == "" {
		t.Skip("E2E_FORGEJO_URL / E2E_FORGEJO_TOKEN not set; skipping live Forgejo e2e test")
	}
	e := &Env{BaseURL: base, Token: token}
	var me struct {
		Login string `json:"login"`
	}
	if err := e.apiJSON(context.Background(), http.MethodGet, "/api/v1/user", nil, &me); err != nil {
		t.Fatalf("harness: resolve token user: %v", err)
	}
	if me.Login == "" {
		t.Fatalf("harness: token user has empty login")
	}
	e.Owner = me.Login
	return e
}

// apiJSON performs an authenticated JSON request against the instance and
// decodes the response into out (when non-nil). 4xx/5xx become errors with the
// body included (the token is never echoed).
func (e *Env) apiJSON(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+e.Token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: http %d: %s", method, path, resp.StatusCode, truncate(string(raw), 300))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// CreateRepo provisions a fresh repository (auto-init, wiki per wantWiki) and
// registers cleanup. Returns the repo name.
func (e *Env) CreateRepo(t *testing.T, wantWiki bool) string {
	t.Helper()
	name := "e2e-" + randHex(6)
	err := e.apiJSON(context.Background(), http.MethodPost, "/api/v1/user/repos", map[string]any{
		"name":      name,
		"auto_init": true,
		"private":   true,
	}, nil)
	if err != nil {
		t.Fatalf("harness: create repo: %v", err)
	}
	t.Cleanup(func() {
		_ = e.apiJSON(context.Background(), http.MethodDelete, "/api/v1/repos/"+e.Owner+"/"+name, nil, nil)
	})
	// auto_init repos start with has_wiki=true on Forgejo; set it explicitly
	// either way so each test states its precondition.
	err = e.apiJSON(context.Background(), http.MethodPatch, "/api/v1/repos/"+e.Owner+"/"+name, map[string]any{
		"has_wiki": wantWiki,
	}, nil)
	if err != nil {
		t.Fatalf("harness: set has_wiki=%v: %v", wantWiki, err)
	}
	return name
}

// Issue is the subset of a Forgejo issue the tests assert on.
type Issue struct {
	Number int64  `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
}

// ListIssues returns all issues (open+closed) of a repo.
func (e *Env) ListIssues(t *testing.T, repo string) []Issue {
	t.Helper()
	var all []Issue
	page := 1
	for {
		var batch []Issue
		path := fmt.Sprintf("/api/v1/repos/%s/%s/issues?state=all&type=issues&limit=50&page=%d", e.Owner, repo, page)
		if err := e.apiJSON(context.Background(), http.MethodGet, path, nil, &batch); err != nil {
			t.Fatalf("harness: list issues: %v", err)
		}
		all = append(all, batch...)
		if len(batch) < 50 {
			return all
		}
		page++
	}
}

// MarkerFindingID extracts the findingID from the hidden dedup marker in an
// issue body ("" when absent). Mirrors the sink's marker contract so tests
// verify the round-trip against the real server, not the sink's own parser.
func MarkerFindingID(body string) string {
	const open = "<!-- devsecopskb-finding:"
	idx := strings.Index(body, open)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(open):]
	end := strings.Index(rest, "-->")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

// GetWikiPage fetches a wiki page's decoded content ("" + false when missing).
func (e *Env) GetWikiPage(t *testing.T, repo, page string) (string, bool) {
	t.Helper()
	var resp struct {
		ContentBase64 string `json:"content_base64"`
	}
	path := "/api/v1/repos/" + e.Owner + "/" + repo + "/wiki/page/" + url.PathEscape(page)
	err := e.apiJSON(context.Background(), http.MethodGet, path, nil, &resp)
	if err != nil {
		if strings.Contains(err.Error(), "http 404") {
			return "", false
		}
		t.Fatalf("harness: get wiki page %q: %v", page, err)
	}
	raw, derr := decodeB64(resp.ContentBase64)
	if derr != nil {
		t.Fatalf("harness: decode wiki page %q: %v", page, derr)
	}
	return raw, true
}

// EditWikiPage overwrites a wiki page out-of-band (simulating a human edit in
// the Forgejo UI between publishes).
func (e *Env) EditWikiPage(t *testing.T, repo, page, content string) {
	t.Helper()
	path := "/api/v1/repos/" + e.Owner + "/" + repo + "/wiki/page/" + url.PathEscape(page)
	err := e.apiJSON(context.Background(), http.MethodPatch, path, map[string]string{
		"title":          page,
		"content_base64": encodeB64(content),
		"message":        "human edit (e2e)",
	}, nil)
	if err != nil {
		t.Fatalf("harness: edit wiki page %q: %v", page, err)
	}
}

// --- fault-injection proxy -------------------------------------------------

// Rule decides whether to intercept a request and how. Return (status, true)
// to short-circuit with that status; return (0, false) to pass through.
type Rule func(r *http.Request) (int, bool)

// FaultProxy is a hand-rolled reverse proxy in front of the real Forgejo that
// applies fault rules. No third-party dependency.
type FaultProxy struct {
	srv   *httptest.Server
	mu    sync.Mutex
	rules []Rule
	// POSTCount counts proxied (not intercepted) POSTs, for kill-point logic.
	POSTCount atomic.Int64
}

// NewFaultProxy starts a proxy in front of target. Closed via t.Cleanup.
func NewFaultProxy(t *testing.T, target string) *FaultProxy {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("harness: parse proxy target: %v", err)
	}
	fp := &FaultProxy{}
	rp := httputil.NewSingleHostReverseProxy(u)
	fp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		rules := append([]Rule(nil), fp.rules...)
		fp.mu.Unlock()
		for _, rule := range rules {
			if status, hit := rule(r); hit {
				http.Error(w, fmt.Sprintf("fault-proxy injected %d", status), status)
				return
			}
		}
		if r.Method == http.MethodPost {
			fp.POSTCount.Add(1)
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(fp.srv.Close)
	return fp
}

// URL is the proxy's base URL; point the sink here instead of at Forgejo.
func (fp *FaultProxy) URL() string { return fp.srv.URL }

// AddRule registers a fault rule (applied in order; first hit wins).
func (fp *FaultProxy) AddRule(r Rule) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.rules = append(fp.rules, r)
}

// FailNTimes returns a rule that responds with status to the first n requests
// matching method + path-substring, then passes everything through.
func FailNTimes(method, pathContains string, status, n int) Rule {
	var count atomic.Int64
	return func(r *http.Request) (int, bool) {
		if r.Method != method || !strings.Contains(r.URL.Path, pathContains) {
			return 0, false
		}
		if count.Add(1) <= int64(n) {
			return status, true
		}
		return 0, false
	}
}

// FailAfterN returns a rule that lets the first n matching requests through
// and fails every later one with status — simulating a publisher that loses
// its backend mid-run.
func FailAfterN(method, pathContains string, status, n int) Rule {
	var count atomic.Int64
	return func(r *http.Request) (int, bool) {
		if r.Method != method || !strings.Contains(r.URL.Path, pathContains) {
			return 0, false
		}
		if count.Add(1) > int64(n) {
			return status, true
		}
		return 0, false
	}
}

// --- fixtures ----------------------------------------------------------------

// FixtureOptions tweaks the generated entity fixture.
type FixtureOptions struct {
	NumHighFindings int    // default 2
	Secret          string // when set, embedded as Authorization header + raw header in occurrence evidence
	EvidenceText    string // default "missing CSP header"
}

// Fixture builds a deterministic entities file for publishing tests. Finding
// IDs are stable across calls with the same options (R1), so re-publish tests
// can compare ticket refs run-to-run.
func Fixture(opts FixtureOptions) entities.EntitiesFile {
	n := opts.NumHighFindings
	if n <= 0 {
		n = 2
	}
	evidence := opts.EvidenceText
	if evidence == "" {
		evidence = "missing CSP header"
	}
	ef := entities.EntitiesFile{
		SchemaVersion: "v1",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		SourceTool:    "e2e-fixture",
		Definitions: []entities.Definition{{
			DefinitionID: "def-10038",
			PluginID:     "10038",
			Name:         "CSP Header Not Set",
			Origin:       "tool",
			Remediation:  &entities.Remediation{Summary: "Set a Content-Security-Policy header."},
			Taxonomy:     &entities.Taxonomy{CWEID: 693, CWEName: "Protection Mechanism Failure"},
		}},
	}
	for i := 0; i < n; i++ {
		fid := fmt.Sprintf("fin-e2e%04d", i)
		u := fmt.Sprintf("https://target.example/app/%d", i)
		ef.Findings = append(ef.Findings, entities.Finding{
			FindingID:    fid,
			DefinitionID: "def-10038",
			Name:         fmt.Sprintf("CSP Header Not Set — /app/%d", i),
			URL:          u,
			Method:       "GET",
			Risk:         "High",
			Confidence:   "High",
			Occurrences:  1,
		})
		occ := entities.Occurrence{
			OccurrenceID: fmt.Sprintf("occ-e2e%04d", i),
			FindingID:    fid,
			DefinitionID: "def-10038",
			URL:          u,
			Method:       "GET",
			Risk:         "High",
			ObservedAt:   "2026-01-01T00:00:00Z",
			ScanLabel:    "e2e",
			Evidence:     evidence,
		}
		if opts.Secret != "" {
			// The request line MUST match the occurrence URL/method — the CLI
			// pipeline's DropMismatchedTraffic pass (entities/enrich.go) strips
			// traffic samples whose start line disagrees with the occurrence,
			// and a dropped sample would make redaction tests pass vacuously.
			occ.Request = &entities.HTTPRequest{
				RawHeader: fmt.Sprintf("GET /app/%d HTTP/1.1\nHost: target.example\nAuthorization: %s\n", i, opts.Secret),
				Headers: []entities.Header{
					{Name: "Authorization", Value: opts.Secret},
					{Name: "Cookie", Value: "session=" + opts.Secret},
				},
			}
		}
		ef.Occurrences = append(ef.Occurrences, occ)
	}
	return ef
}

// WriteFixture marshals a fixture to dir/entities.json and returns the path.
func WriteFixture(t *testing.T, dir string, ef entities.EntitiesFile) string {
	t.Helper()
	raw, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		t.Fatalf("harness: marshal fixture: %v", err)
	}
	p := filepath.Join(dir, "entities.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("harness: write fixture: %v", err)
	}
	return p
}

// WriteVault writes a minimal markdown vault for wiki tests.
func WriteVault(t *testing.T, dir string, pages map[string]string) {
	t.Helper()
	for rel, content := range pages {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("harness: mkdir vault: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("harness: write vault page: %v", err)
		}
	}
}

// --- CLI binary -------------------------------------------------------------

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// Binary builds the real zap-kb binary once per test process and returns its
// path. CLI-level tests exercise the same entrypoint the CronJob runs.
func Binary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zap-kb-e2e-bin-")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "zap-kb")
		cmd := exec.Command("go", "build", "-o", binPath, "github.com/Warlockobama/DevSecOpsKB/zap-kb/cmd/zap-kb")
		out, err := cmd.CombinedOutput()
		if err != nil {
			binErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatalf("harness: build binary: %v", binErr)
	}
	return binPath
}

// RunCLI executes the zap-kb binary with the given args, the Forgejo token
// passed via environment (never argv), and a timeout. Returns combined output
// and the exit code (-1 when the process failed to run at all).
func RunCLI(t *testing.T, env *Env, timeout time.Duration, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, Binary(t), args...)
	cmd.Env = append(os.Environ(), "FORGEJO_TOKEN="+env.Token)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return string(out), code
}

// --- small helpers -----------------------------------------------------------

func encodeB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func decodeB64(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	return string(raw), err
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable for unique naming
		panic(err)
	}
	return hex.EncodeToString(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
