package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// This regression reproduces both original G2 leaks through the public CLI:
// raw alert cookies in the run artifact and URL query values in the preview.
func TestCLIOutputRedactionBaseline(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	raw := `[{"pluginId":"10001","alert":"Synthetic rule","risk":"High","riskcode":"3","url":"https://example.invalid/test?q=QUERY_G2_MARKER","method":"GET","requestHeader":"GET /test?q=QUERY_G2_MARKER HTTP/1.1\r\nCookie: session=COOKIE_G2_MARKER\r\nAuthorization: Bearer AUTH_G2_MARKER\r\n","evidence":"SQLITE_ERROR: useful evidence"}]`
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	out, run := filepath.Join(dir, "out.json"), filepath.Join(dir, "run.json")
	cmd := exec.Command(binary, "-wizard=false", "-in="+input, "-format=both", "-out="+out, "-run-out="+run, "-redact=query,cookies,auth", "-include-mitre=false", "-include-cvss=false", "-scan-label=synthetic-scan")
	cmd.Env = cleanCLIEnvironment()
	logs, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %s", logs)
	}
	surfaces := map[string][]byte{"preview": logs}
	for _, name := range []string{out, out + ".entities.json", run} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		surfaces[filepath.Base(name)] = b
	}
	for name, b := range surfaces {
		for _, marker := range []string{"QUERY_G2_MARKER", "COOKIE_G2_MARKER", "AUTH_G2_MARKER"} {
			if strings.Contains(string(b), marker) {
				t.Errorf("%s leaked %s", name, marker)
			}
		}
	}
	after, _ := os.ReadFile(input)
	if string(after) != raw {
		t.Error("source changed")
	}
}

const allOutputModes = "query,cookies,auth,headers,body,notes,secrets"

var privateOutputMarkers = []string{"QUERY_POLICY_MARKER", "COOKIE_POLICY_MARKER", "AUTH_POLICY_MARKER", "HEADER_POLICY_MARKER", "BODY_POLICY_MARKER", "NOTE_POLICY_MARKER", "META_POLICY_MARKER", "SERVER_POLICY_MARKER"}

func policyFixture() runartifact.Artifact {
	e := entities.EntitiesFile{SchemaVersion: "v1", SourceTool: "zap", GeneratedAt: "2026-09-12T12:00:00Z",
		Definitions: []entities.Definition{{DefinitionID: "def-policy", PluginID: "10001", Alert: "Useful SQL rule", Description: "Nonsensitive explanation; META_POLICY_MARKER@example.invalid"}},
		Findings:    []entities.Finding{{FindingID: "finding-policy", DefinitionID: "def-policy", PluginID: "10001", URL: "https://example.invalid/a?q=QUERY_POLICY_MARKER", Name: "Query at /a?q=QUERY_POLICY_MARKER", Risk: "High", RiskCode: "3", Occurrences: 1, Analyst: &entities.Analyst{Status: "triaged", Tags: []string{"case-ticket"}, Notes: "NOTE_POLICY_MARKER", Rationale: "NOTE_POLICY_MARKER", History: []entities.AnalystHistoryEntry{{EntryID: "entry-policy", Status: "open", ScanLabel: "scan-policy", Notes: "NOTE_POLICY_MARKER"}}}}},
		Occurrences: []entities.Occurrence{{OccurrenceID: "occ-policy", DefinitionID: "def-policy", FindingID: "finding-policy", ScanLabel: "scan-policy", ObservedAt: "2026-09-12T12:00:00Z", URL: "https://example.invalid/a?q=QUERY_POLICY_MARKER", Risk: "High", RiskCode: "3", Attack: "BODY_POLICY_MARKER", Evidence: "BODY_POLICY_MARKER", Other: `{"schema":"detection-trace.v1","signals":[{"rule":"useful-rule","weight":3,"url":"https://example.invalid/a?q=QUERY_POLICY_MARKER","notes":"NOTE_POLICY_MARKER","body":"BODY_POLICY_MARKER","owner":"META_POLICY_MARKER@example.invalid"}]}`, Request: &entities.HTTPRequest{Headers: []entities.Header{{Name: "Cookie", Value: "COOKIE_POLICY_MARKER"}, {Name: "Authorization", Value: "AUTH_POLICY_MARKER"}, {Name: "X-Api-Key", Value: "HEADER_POLICY_MARKER"}, {Name: "Content-Type", Value: "text/plain"}}, BodySnippet: "BODY_POLICY_MARKER", BodyBytes: 18, RawHeader: "GET /a?q=QUERY_POLICY_MARKER HTTP/1.1\r\nCookie: COOKIE_POLICY_MARKER\r\nAuthorization: AUTH_POLICY_MARKER\r\nX-Api-Key: HEADER_POLICY_MARKER\r\n"}, Reproduce: &entities.Reproduce{Curl: `curl -H 'Cookie: COOKIE_POLICY_MARKER' https://example.invalid/a?q=QUERY_POLICY_MARKER`, Steps: []string{"NOTE_POLICY_MARKER"}}}},
	}
	return runartifact.Artifact{Schema: runartifact.SchemaV1, Meta: runartifact.Meta{SourceTool: e.SourceTool, GeneratedAt: e.GeneratedAt, ScanLabel: "scan-policy", SiteLabel: "policy-site", BaseURL: "https://example.invalid/a?q=QUERY_POLICY_MARKER", ZapBaseURL: "https://example.invalid/a?q=QUERY_POLICY_MARKER"}, Entities: e}
}

func assertPrivateMarkersAbsent(t *testing.T, name string, b []byte) {
	t.Helper()
	for _, marker := range privateOutputMarkers {
		if strings.Contains(string(b), marker) {
			t.Errorf("%s leaked %s", name, marker)
		}
	}
}

func TestCLIOutputPolicyArchiveAndIdentity(t *testing.T) {
	binary := buildTestCLI(t)
	for _, format := range []string{"entities", "obsidian"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.json")
			fixture := policyFixture()
			if err := runartifact.Write(input, fixture); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(input)
			out, run, vault := filepath.Join(dir, "output.json"), filepath.Join(dir, "run.json"), filepath.Join(dir, "vault")
			if err := os.MkdirAll(vault, 0700); err != nil {
				t.Fatal(err)
			}
			// An unrelated historical file and unused -out cannot become ZIP members.
			os.WriteFile(filepath.Join(vault, "old-private.txt"), []byte("SERVER_POLICY_MARKER"), 0600)
			os.WriteFile(out, []byte("SERVER_POLICY_MARKER"), 0600)
			archive := filepath.Join(vault, "bundle.zip")
			cmd := exec.Command(binary, "-wizard=false", "-run-in="+input, "-format="+format, "-out="+out, "-run-out="+run, "-obsidian-dir="+vault, "-zip-out="+archive, "-redact="+allOutputModes, "-include-mitre=false", "-include-cvss=false")
			cmd.Env = cleanCLIEnvironment()
			logs, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI failed: %s", logs)
			}
			assertPrivateMarkersAbsent(t, "logs", logs)
			art, err := runartifact.Read(run)
			if err != nil {
				t.Fatal(err)
			}
			if art.Entities.Findings[0].FindingID != "finding-policy" || art.Entities.Occurrences[0].OccurrenceID != "occ-policy" || art.Entities.Definitions[0].DefinitionID != "def-policy" {
				t.Fatal("IDs changed")
			}
			if art.Meta.ScanLabel != "scan-policy" || art.Meta.SourceTool != "zap" {
				t.Fatal("labels changed")
			}
			for _, path := range []string{run} {
				b, _ := os.ReadFile(path)
				assertPrivateMarkersAbsent(t, path, b)
			}
			if format == "entities" {
				b, _ := os.ReadFile(out)
				assertPrivateMarkersAbsent(t, "entities", b)
			} else {
				filepath.WalkDir(vault, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !d.IsDir() && strings.HasSuffix(path, ".md") {
						b, _ := os.ReadFile(path)
						assertPrivateMarkersAbsent(t, path, b)
					}
					return nil
				})
			}
			zr, err := zip.OpenReader(archive)
			if err != nil {
				t.Fatal(err)
			}
			defer zr.Close()
			if len(zr.File) == 0 {
				t.Fatal("empty archive")
			}
			hasFindingDirectory := false
			for _, f := range zr.File {
				if strings.Contains(f.Name, "/findings/") {
					hasFindingDirectory = true
				}
				if strings.Contains(f.Name, "bundle.zip") || strings.Contains(f.Name, "old-private") {
					t.Errorf("unexpected archive member %s", f.Name)
				}
				r, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				assertPrivateMarkersAbsent(t, "archive member "+f.Name, b)
			}
			if format == "obsidian" && !hasFindingDirectory {
				t.Fatal("archive flattened the vault hierarchy")
			}
			after, _ := os.ReadFile(input)
			if string(after) != string(before) {
				t.Fatal("source input changed")
			}
		})
	}
}

func TestCLISinkFailurePayloadsAndDiagnostics(t *testing.T) {
	binary := buildTestCLI(t)
	for _, sink := range []string{"jira", "confluence", "forgejo"} {
		t.Run(sink, func(t *testing.T) {
			var mu sync.Mutex
			var payloads [][]byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				payloads = append(payloads, body)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" && (strings.HasSuffix(r.URL.Path, "/issue") || strings.HasSuffix(r.URL.Path, "/issues") || strings.HasSuffix(r.URL.Path, "/content")) {
					w.WriteHeader(400)
					io.WriteString(w, `{"message":"SERVER_POLICY_MARKER","errors":{"description":"SERVER_POLICY_MARKER"}}`)
					return
				}
				if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/labels") {
					io.WriteString(w, `{"id":1,"name":"synthetic"}`)
					return
				}
				if strings.Contains(r.URL.Path, "search") {
					io.WriteString(w, `{"issues":[],"total":0,"isLast":true}`)
					return
				}
				if strings.Contains(r.URL.Path, "/rest/api/content") {
					io.WriteString(w, `{"results":[]}`)
					return
				}
				io.WriteString(w, `[]`)
			}))
			defer server.Close()
			dir := t.TempDir()
			input := filepath.Join(dir, "input.json")
			if err := runartifact.Write(input, policyFixture()); err != nil {
				t.Fatal(err)
			}
			args := []string{"-wizard=false", "-run-in=" + input, "-format=entities", "-out=" + filepath.Join(dir, "out.json"), "-obsidian-dir=" + filepath.Join(dir, "vault"), "-redact=" + allOutputModes, "-include-mitre=false", "-include-cvss=false"}
			switch sink {
			case "jira":
				args = append(args, "-jira-url="+server.URL, "-jira-project=TEST", "-jira-user=synthetic", "-jira-token=synthetic", "-jira-deployment=datacenter")
			case "confluence":
				args = append(args, "-confluence-url="+server.URL, "-confluence-space=TEST", "-confluence-user=synthetic", "-confluence-token=synthetic")
			case "forgejo":
				args = append(args, "-forgejo-url="+server.URL, "-forgejo-owner=synthetic", "-forgejo-repo=synthetic", "-forgejo-token=synthetic", "-forgejo-redact=query")
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = cleanCLIEnvironment()
			logs, _ := cmd.CombinedOutput()
			assertPrivateMarkersAbsent(t, "failure logs", logs)
			mu.Lock()
			defer mu.Unlock()
			hasCreate := false
			for _, b := range payloads {
				assertPrivateMarkersAbsent(t, "captured payload", b)
				if strings.Contains(string(b), "Useful SQL rule") || strings.Contains(string(b), "finding-policy") {
					hasCreate = true
				}
			}
			if !hasCreate {
				t.Fatalf("did not exercise destination create payload: %s", logs)
			}
		})
	}
}

func TestCLIRetentionAndUnknownModes(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "alerts.json")
	os.WriteFile(input, []byte(`[{"pluginId":"1","url":"https://example.invalid/?q=QUERY_POLICY_MARKER","alert":"safe"}]`), 0600)
	for _, retention := range []string{"keep", "omit"} {
		run := filepath.Join(dir, retention+".json")
		runCLI(t, binary, nil, "-wizard=false", "-in="+input, "-out="+filepath.Join(dir, "out.json"), "-run-out="+run, "-run-alerts="+retention, "-redact=query", "-include-mitre=false", "-include-cvss=false")
		a, err := runartifact.Read(run)
		if err != nil {
			t.Fatal(err)
		}
		if (len(a.Alerts) > 0) != (retention == "keep") {
			t.Fatal("retention mismatch")
		}
		b, _ := json.Marshal(a)
		assertPrivateMarkersAbsent(t, "retained alerts", b)
	}
	for _, flag := range []string{"-redact=PRIVATE_UNKNOWN_MODE", "-forgejo-redact=PRIVATE_UNKNOWN_MODE"} {
		out := filepath.Join(dir, "untouched.json")
		cmd := exec.Command(binary, "-wizard=false", flag, "-in="+input, "-out="+out)
		cmd.Env = cleanCLIEnvironment()
		logs, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(logs), "PRIVATE_UNKNOWN_MODE") {
			t.Fatalf("mode validation failed: %s", logs)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("invalid mode wrote output")
		}
	}
}

func TestForgejoWikiOutputPolicyDecodedPayloads(t *testing.T) {
	var mu sync.Mutex
	var captured []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/wiki/new") || r.Method == http.MethodPatch {
			var p struct {
				Content string `json:"content_base64"`
			}
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			b, err := base64.StdEncoding.DecodeString(p.Content)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			captured = append(captured, string(b))
			mu.Unlock()
			w.WriteHeader(201)
			w.Write([]byte(`{}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`{"has_wiki":true,"wiki_branch":"main"}`))
	}))
	defer server.Close()
	original := policyFixture().Entities
	before, _ := json.Marshal(original)
	vault := t.TempDir()
	os.WriteFile(filepath.Join(vault, "INDEX.md"), []byte("SERVER_POLICY_MARKER"), 0600)
	failures := runForgejoPublish(&original, forgejoPublishOptions{BaseURL: server.URL, Token: "synthetic", Owner: "synthetic", Repo: "synthetic", Issues: false, Wiki: true, Vault: vault, Redact: "query", SharedRedact: entities.ParseRedactOptionList(allOutputModes), ScanLabel: "scan-policy", SiteLabel: "policy-site"})
	if failures != 0 {
		t.Fatalf("wiki failed: %d", failures)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("no wiki payload captured")
	}
	joined := strings.Join(captured, "\n")
	assertPrivateMarkersAbsent(t, "decoded wiki payloads", []byte(joined))
	if !strings.Contains(joined, "Useful SQL rule") || !strings.Contains(joined, "scan-policy") {
		t.Fatal("useful wiki context lost")
	}
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("wiki-only publish mutated source entities")
	}
}

func TestCLIRawAlertAllOutputModes(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	raw := `[{"pluginId":"10001","sourceid":"source-policy","alert":"Useful SQL rule","url":"https://example.invalid/a?q=QUERY_POLICY_MARKER","name":"/a?q=QUERY_POLICY_MARKER","risk":"High","method":"GET","requestHeader":"GET /a?q=QUERY_POLICY_MARKER HTTP/1.1\r\nCookie: COOKIE_POLICY_MARKER\r\nAuthorization: AUTH_POLICY_MARKER\r\nX-Api-Key: HEADER_POLICY_MARKER\r\nContent-Type: text/plain\r\n","responseHeader":"HTTP/1.1 200 OK\r\nSet-Cookie: COOKIE_POLICY_MARKER\r\n","requestBody":"BODY_POLICY_MARKER","responseBody":"BODY_POLICY_MARKER","attack":"BODY_POLICY_MARKER","evidence":"BODY_POLICY_MARKER","desc":"META_POLICY_MARKER@example.invalid Useful SQL context","other":"{\"schema\":\"detection-trace.v1\",\"notes\":\"NOTE_POLICY_MARKER\",\"body\":{\"nested\":\"BODY_POLICY_MARKER\"},\"owner\":\"META_POLICY_MARKER@example.invalid\"}"}]`
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	out, run, archive := filepath.Join(dir, "flat.json"), filepath.Join(dir, "run.json"), filepath.Join(dir, "bundle.zip")
	cmd := exec.Command(binary, "-wizard=false", "-in="+input, "-format=both", "-out="+out, "-run-out="+run, "-zip-out="+archive, "-redact="+allOutputModes, "-include-mitre=false", "-include-cvss=false")
	cmd.Env = cleanCLIEnvironment()
	logs, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %s", logs)
	}
	assertPrivateMarkersAbsent(t, "raw preview", logs)
	for _, file := range []string{out, out + ".entities.json", run} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateMarkersAbsent(t, file, b)
		if !strings.Contains(string(b), "Useful SQL") {
			t.Fatal("useful evidence dropped")
		}
	}
	zr, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, member := range zr.File {
		r, err := member.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateMarkersAbsent(t, "raw ZIP member", b)
	}
	a, err := runartifact.Read(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Alerts) != 1 || a.Alerts[0].SourceID != "source-policy" {
		t.Fatal("raw retention or source identity changed")
	}
	after, _ := os.ReadFile(input)
	if string(after) != raw {
		t.Fatal("source changed")
	}
}

func TestCLIZAPFailureDiagnosticOmitsServerAndRequestContext(t *testing.T) {
	binary := buildTestCLI(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, "SERVER_POLICY_MARKER opaque server message")
	}))
	defer server.Close()
	cmd := exec.Command(binary, "-wizard=false", "-zap-url="+server.URL, "-api-key=AUTH_POLICY_MARKER", "-base-url=https://example.invalid/a?q=QUERY_POLICY_MARKER", "-redact="+allOutputModes, "-out="+filepath.Join(t.TempDir(), "out.json"))
	cmd.Env = cleanCLIEnvironment()
	logs, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected failed fetch")
	}
	assertPrivateMarkersAbsent(t, "ZAP failure", logs)
}
