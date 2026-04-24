package onboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// newTestServer wires up a Handler against an httptest.Server. The results
// channel and a no-op shutdown are injected so tests can observe outcomes
// without starting a real listener or opening a browser.
func newTestServer(t *testing.T, start config.TriagePolicy, outPath string) (*httptest.Server, chan Result) {
	t.Helper()
	results := make(chan Result, 1)
	srv := httptest.NewServer(NewHandler(start, outPath, results, func() {}))
	t.Cleanup(srv.Close)
	return srv, results
}

func TestHandler_GET_RendersForm(t *testing.T) {
	srv, _ := newTestServer(t, config.DefaultPolicy(), filepath.Join(t.TempDir(), "p.yaml"))
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "triage policy onboarding") {
		t.Error("form page should contain heading text")
	}
	if !strings.Contains(s, "autoReopenOnRecurrence") {
		t.Error("form page should include autoReopenOnRecurrence field")
	}
	if !strings.Contains(s, "findingFPSuppressionThreshold") {
		t.Error("form page should include findingFPSuppressionThreshold field")
	}
}

func TestHandler_GET_PreFillsDefaults(t *testing.T) {
	d := config.DefaultPolicy()
	srv, _ := newTestServer(t, d, filepath.Join(t.TempDir(), "p.yaml"))
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	// Default AutoReopenOnRecurrence=true → checkbox should be checked
	if !strings.Contains(s, "checked") {
		t.Error("autoReopenOnRecurrence default=true should render checkbox as checked")
	}
	// Default threshold=3 should appear as input value
	if !strings.Contains(s, `value="3"`) {
		t.Errorf("default FP threshold 3 should appear in form, body snippet: %q", s[strings.Index(s, "findingFP"):strings.Index(s, "findingFP")+200])
	}
}

func TestHandler_POST_ValidSavesAndSendsResult(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "triage-policy.yaml")
	srv, results := newTestServer(t, config.DefaultPolicy(), outPath)

	form := url.Values{
		"autoReopenOnRecurrence":         {"true"},
		"findingFPSuppressionThreshold":  {"7"},
		"findingFPSuppressionExpiryDays": {"45"},
		"ruleTuneScanThreshold":          {"10"},
		"acceptedDefaultExpiryDays":      {"365"},
	}
	resp, err := http.PostForm(srv.URL+"/", form)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}

	// Result channel should have received a saved result.
	select {
	case res := <-results:
		if !res.Saved {
			t.Errorf("result.Saved: want true, got false (err=%v)", res.Err)
		}
		if res.SavedTo != outPath {
			t.Errorf("result.SavedTo: want %q, got %q", outPath, res.SavedTo)
		}
	default:
		t.Fatal("expected result on channel, got none")
	}

	// The YAML must have been written with the submitted values.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read written YAML: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "findingFPSuppressionThreshold: 7") {
		t.Errorf("YAML should contain threshold 7, got:\n%s", s)
	}
	if !strings.Contains(s, "acceptedDefaultExpiryDays: 365") {
		t.Errorf("YAML should contain expiry 365, got:\n%s", s)
	}
}

func TestHandler_POST_ValidRoundTripsThroughLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "triage-policy.yaml")
	srv, _ := newTestServer(t, config.DefaultPolicy(), outPath)

	form := url.Values{
		"autoReopenOnRecurrence":         {}, // absent = false
		"findingFPSuppressionThreshold":  {"2"},
		"findingFPSuppressionExpiryDays": {"60"},
		"ruleTuneScanThreshold":          {"8"},
		"acceptedDefaultExpiryDays":      {"120"},
	}
	resp, err := http.PostForm(srv.URL+"/", form)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	resp.Body.Close()

	// Load through the real LoadPolicy to verify the round-trip.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), ".config"))
	t.Setenv("APPDATA", filepath.Join(t.TempDir(), "AppData", "Roaming"))
	got, src, err := config.LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if src != outPath {
		t.Errorf("source: want %q, got %q", outPath, src)
	}
	want := config.TriagePolicy{
		AutoReopenOnRecurrence:         false,
		FindingFPSuppressionThreshold:  2,
		FindingFPSuppressionExpiryDays: 60,
		RuleTuneScanThreshold:          8,
		AcceptedDefaultExpiryDays:      120,
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n  want %+v\n   got %+v", want, got)
	}
}

func TestHandler_POST_InvalidIntShowsErrorAndStaysOnForm(t *testing.T) {
	srv, results := newTestServer(t, config.DefaultPolicy(), filepath.Join(t.TempDir(), "p.yaml"))

	form := url.Values{
		"autoReopenOnRecurrence":         {"true"},
		"findingFPSuppressionThreshold":  {"abc"}, // invalid
		"findingFPSuppressionExpiryDays": {"90"},
		"ruleTuneScanThreshold":          {"5"},
		"acceptedDefaultExpiryDays":      {"180"},
	}
	resp, err := http.PostForm(srv.URL+"/", form)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "non-negative integer") {
		t.Errorf("error response should describe the validation failure, got:\n%s", s)
	}
	// No result should have been sent.
	select {
	case res := <-results:
		t.Errorf("expected no result on invalid input, got %+v", res)
	default:
	}
}

func TestHandler_POST_NegativeIntShowsError(t *testing.T) {
	srv, results := newTestServer(t, config.DefaultPolicy(), filepath.Join(t.TempDir(), "p.yaml"))

	form := url.Values{
		"autoReopenOnRecurrence":         {"true"},
		"findingFPSuppressionThreshold":  {"-1"}, // negative
		"findingFPSuppressionExpiryDays": {"90"},
		"ruleTuneScanThreshold":          {"5"},
		"acceptedDefaultExpiryDays":      {"180"},
	}
	resp, err := http.PostForm(srv.URL+"/", form)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "non-negative integer") {
		t.Error("negative int should surface validation error")
	}
	select {
	case res := <-results:
		t.Errorf("expected no result on invalid input, got %+v", res)
	default:
	}
}

func TestHandler_Cancel(t *testing.T) {
	srv, results := newTestServer(t, config.DefaultPolicy(), filepath.Join(t.TempDir(), "p.yaml"))

	resp, err := http.Get(srv.URL + "/cancel")
	if err != nil {
		t.Fatalf("GET /cancel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "cancelled") {
		t.Errorf("cancel page should say cancelled, got:\n%s", string(body))
	}

	select {
	case res := <-results:
		if res.Saved {
			t.Error("cancel must not set Saved=true")
		}
		if res.Err != nil {
			t.Errorf("cancel must not set Err, got %v", res.Err)
		}
	default:
		t.Fatal("expected result on cancel, got none")
	}
}

func TestHandler_DonePageContainsPath(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "triage-policy.yaml")
	srv, _ := newTestServer(t, config.DefaultPolicy(), outPath)

	form := url.Values{
		"autoReopenOnRecurrence":         {"true"},
		"findingFPSuppressionThreshold":  {"3"},
		"findingFPSuppressionExpiryDays": {"90"},
		"ruleTuneScanThreshold":          {"5"},
		"acceptedDefaultExpiryDays":      {"180"},
	}
	resp, err := http.PostForm(srv.URL+"/", form)
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), outPath) {
		t.Errorf("done page should show the written path %q", outPath)
	}
}
