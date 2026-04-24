// Package onboard implements a local-HTTP-server onboarding UI for
// triage-policy.yaml — the browser-based mirror of internal/tui/onboard.
// Slice 1c-iv of epic #71.
//
// Usage (via the CLI):
//
//	zap-kb onboard -web [-port 7979] [-path ./triage-policy.yaml]
//
// The server binds to 127.0.0.1 only, picks an OS-assigned port when -port is
// 0, prints the URL, attempts to open the system browser, then blocks until
// the user saves or cancels. One save closes the server — it is not a
// persistent daemon.
package onboard

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// Result is sent on the channel returned by Handler once the user saves or
// cancels. Err is non-nil only when the HTTP server itself fails; a user
// cancellation sets Saved=false with Err=nil.
type Result struct {
	Saved   bool
	SavedTo string
	Err     error
}

// fieldData is the per-knob view model passed to the HTML template.
type fieldData struct {
	Title   string
	Para    string
	Name    string
	IsBool  bool
	BoolVal bool
	IntVal  int
}

// pageData is the top-level template context for the form page.
type pageData struct {
	Path   string
	ErrMsg string
	Fields []fieldData
}

func buildFields(p config.TriagePolicy) []fieldData {
	return []fieldData{
		{
			Title: "Auto-reopen on recurrence",
			Para: "When enabled, findings you've marked false-positive (fp) or fixed are\n" +
				"automatically flipped back to \"open\" if a later scan rediscovers them.\n" +
				"An audit trail entry is appended so you can see why.\n\n" +
				"Disable only if you want recurrence to be advisory and re-triage by hand.\n" +
				"\"accepted\" findings are NEVER auto-reopened (they're time-bounded by\n" +
				"acceptedUntil instead).",
			Name:    "autoReopenOnRecurrence",
			IsBool:  true,
			BoolVal: p.AutoReopenOnRecurrence,
		},
		{
			Title: "False-positive auto-suppression threshold",
			Para: "How many \"analyst-said-fp → detection-found-it-again\" cycles to tolerate\n" +
				"on a single finding before zap-kb auto-suppresses it. Each cycle is one\n" +
				"history entry. After this many cycles, the finding stops appearing in\n" +
				"triage queues until the suppression expires.\n\n" +
				"Recommended: 3. Set 0 to disable auto-suppression entirely.",
			Name:   "findingFPSuppressionThreshold",
			IntVal: p.FindingFPSuppressionThreshold,
		},
		{
			Title: "Auto-suppression expiry (days)",
			Para: "How long an auto-written suppression lasts before the finding returns to\n" +
				"the triage queue for reconfirmation. Bounds the \"hide and forget\" risk\n" +
				"so a noisy finding can't disappear forever if the underlying app code\n" +
				"changes.\n\n" +
				"Recommended: 90 days.",
			Name:   "findingFPSuppressionExpiryDays",
			IntVal: p.FindingFPSuppressionExpiryDays,
		},
		{
			Title: "Rule tune-scan threshold",
			Para: "Aggregate fp count across every finding sharing a detection rule (same\n" +
				"pluginId). When the rule-wide total crosses this number, the detection\n" +
				"definition is tagged \"tune-scan\" so security engineering knows it's a\n" +
				"high-noise rule worth retuning.\n\n" +
				"Recommended: 5. Set 0 to disable rule-level tagging.",
			Name:   "ruleTuneScanThreshold",
			IntVal: p.RuleTuneScanThreshold,
		},
		{
			Title: "Accepted-risk default expiry (days)",
			Para: "When an analyst marks a finding \"accepted\" without specifying their own\n" +
				"acceptedUntil date, zap-kb stamps an expiry this many days out. The\n" +
				"acceptance-expired report (slice 2) flags findings whose acceptance has\n" +
				"lapsed so risk decisions get periodically revisited.\n\n" +
				"Recommended: 180 days.",
			Name:   "acceptedDefaultExpiryDays",
			IntVal: p.AcceptedDefaultExpiryDays,
		},
	}
}

var formTmpl = template.Must(template.New("form").Parse(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8">
  <title>zap-kb triage policy onboarding</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:700px;margin:2rem auto;padding:0 1rem;color:#222}
    h1{color:#1a1a2e;margin-bottom:.25rem}
    .intro{color:#555;margin-bottom:1.5rem}
    .path{font-family:monospace;font-size:.85rem;color:#555;margin-bottom:1.5rem}
    .field{margin:1.5rem 0;padding:1rem 1.25rem;border:1px solid #ddd;border-radius:6px;background:#fafafa}
    .field h2{margin:.0 0 .5rem;font-size:1rem;color:#111}
    .field p{color:#555;font-size:.875rem;white-space:pre-wrap;margin:.5rem 0 1rem}
    label{display:flex;align-items:center;gap:.5rem;font-weight:500;font-size:.95rem}
    input[type=number]{width:9ch;padding:.3rem .4rem;font-size:1rem;border:1px solid #aaa;border-radius:4px}
    input[type=checkbox]{width:1rem;height:1rem;cursor:pointer}
    .error{color:#b91c1c;background:#fef2f2;border:1px solid #fca5a5;padding:.75rem 1rem;border-radius:4px;margin:1rem 0}
    .actions{display:flex;gap:1rem;margin-top:2rem;padding-top:1rem;border-top:1px solid #eee}
    button{padding:.6rem 1.5rem;border:none;border-radius:4px;font-size:1rem;cursor:pointer;font-weight:500}
    .btn-save{background:#2563eb;color:#fff}.btn-save:hover{background:#1d4ed8}
    .btn-cancel{background:#e5e7eb;color:#374151}.btn-cancel:hover{background:#d1d5db}
  </style>
</head>
<body>
  <h1>zap-kb triage policy onboarding</h1>
  <p class="intro">Configure the operator-tunable knobs that control how zap-kb auto-triages
recurring findings. Values are pre-filled from your current policy (or built-in defaults).
Click <strong>Save policy</strong> to write the YAML and close this server.</p>
  <p class="path">Writing to: <code>{{.Path}}</code></p>
  {{if .ErrMsg}}<div class="error">{{.ErrMsg}}</div>{{end}}
  <form method="POST" action="/">
    {{range .Fields}}
    <div class="field">
      <h2>{{.Title}}</h2>
      <p>{{.Para}}</p>
      {{if .IsBool}}
      <label>
        <input type="checkbox" name="{{.Name}}" value="true"{{if .BoolVal}} checked{{end}}>
        Enabled
      </label>
      {{else}}
      <label>
        Value: <input type="number" name="{{.Name}}" value="{{.IntVal}}" min="0" required>
      </label>
      {{end}}
    </div>
    {{end}}
    <div class="actions">
      <button type="submit" class="btn-save">Save policy</button>
      <button type="button" class="btn-cancel" onclick="window.location='/cancel'">Cancel</button>
    </div>
  </form>
</body></html>
`))

var doneTmpl = template.Must(template.New("done").Parse(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8">
  <title>zap-kb — policy saved</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:500px;margin:4rem auto;padding:0 1rem;color:#222}
    .ok{color:#15803d;font-size:1.1rem;font-weight:600}
    code{font-family:monospace;background:#f1f5f9;padding:.1rem .3rem;border-radius:3px}
  </style>
</head>
<body>
  <p class="ok">✓ Triage policy saved to <code>{{.}}</code></p>
  <p>zap-kb will pick this up automatically on the next run.<br>
  Run <code>zap-kb config show</code> to confirm.<br><br>
  You can close this tab.</p>
</body></html>
`))

var cancelTmpl = template.Must(template.New("cancel").Parse(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8"><title>zap-kb — cancelled</title>
  <style>body{font-family:system-ui,sans-serif;max-width:500px;margin:4rem auto;padding:0 1rem;color:#222}</style>
</head>
<body>
  <p>Onboarding cancelled. No changes were written.</p>
  <p>You can close this tab.</p>
</body></html>
`))

func renderForm(w http.ResponseWriter, p config.TriagePolicy, outPath, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = formTmpl.Execute(w, pageData{
		Path:   outPath,
		ErrMsg: errMsg,
		Fields: buildFields(p),
	})
}

func renderDone(w http.ResponseWriter, outPath string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = doneTmpl.Execute(w, outPath)
}

func renderCancel(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = cancelTmpl.Execute(w, nil)
}

func parseForm(r *http.Request) (config.TriagePolicy, error) {
	var p config.TriagePolicy
	p.AutoReopenOnRecurrence = r.FormValue("autoReopenOnRecurrence") == "true"

	intFields := []struct {
		name string
		dest *int
	}{
		{"findingFPSuppressionThreshold", &p.FindingFPSuppressionThreshold},
		{"findingFPSuppressionExpiryDays", &p.FindingFPSuppressionExpiryDays},
		{"ruleTuneScanThreshold", &p.RuleTuneScanThreshold},
		{"acceptedDefaultExpiryDays", &p.AcceptedDefaultExpiryDays},
	}
	for _, f := range intFields {
		raw := strings.TrimSpace(r.FormValue(f.name))
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return p, fmt.Errorf("%s: must be a non-negative integer (got %q)", f.name, raw)
		}
		*f.dest = v
	}
	return p, nil
}

// NewHandler returns an http.Handler for the onboarding web UI pre-filled
// with start and writing to outPath on save. results receives exactly one
// Result; shutdown is called (once, asynchronously) after it is sent.
//
// Exported for use with httptest.NewServer in tests.
func NewHandler(start config.TriagePolicy, outPath string, results chan<- Result, shutdown func()) http.Handler {
	mux := http.NewServeMux()
	var once sync.Once
	send := func(res Result) {
		once.Do(func() {
			results <- res
			go shutdown()
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			renderForm(w, start, outPath, "")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form data", http.StatusBadRequest)
			return
		}
		p, parseErr := parseForm(r)
		if parseErr != nil {
			renderForm(w, start, outPath, parseErr.Error())
			return
		}
		if err := config.WritePolicy(outPath, p); err != nil {
			renderForm(w, p, outPath, "write failed: "+err.Error())
			return
		}
		renderDone(w, outPath)
		send(Result{Saved: true, SavedTo: outPath})
	})

	mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
		renderCancel(w)
		send(Result{})
	})

	return mux
}

// Run starts a local HTTP server on 127.0.0.1, attempts to open the system
// browser, prints the URL to stdout, and blocks until the user saves or
// cancels. port=0 lets the OS assign a free port.
func Run(start config.TriagePolicy, outPath string, port int) (Result, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return Result{}, fmt.Errorf("listen: %w", err)
	}
	addr := fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)

	results := make(chan Result, 1)
	srv := &http.Server{}
	srv.Handler = NewHandler(start, outPath, results, func() {
		_ = srv.Shutdown(context.Background())
	})

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			results <- Result{Err: err}
		}
	}()

	fmt.Printf("Triage policy onboarding: %s\n", addr)
	openBrowser(addr)

	return <-results, nil
}

// openBrowser attempts to open url in the system default browser.
// Failures are ignored — the URL is always printed to stdout so the user
// can open it manually.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
