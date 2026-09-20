package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

const validationSensitiveMarker = "SYNTHETIC_SENSITIVE_MARKER"

func TestCLIValidationRejectsBeforeWritesAndDestinationContact(t *testing.T) {
	binary := buildTestCLI(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tests := []struct {
		name       string
		fixture    string
		contents   string
		wantDetail string
	}{
		{name: "missing document", fixture: "invalid-empty-object.json", wantDetail: "definitions: missing required collection"},
		{name: "unsupported version", fixture: "invalid-unsupported-version.json", wantDetail: "schemaVersion: unsupported version"},
		{name: "dangling reference", fixture: "invalid-dangling-reference.json", wantDetail: "findings[0].definitionId: dangling reference"},
		{name: "truncated JSON", contents: `{"schemaVersion":"v1",`, wantDetail: "document: invalid JSON object"},
		{name: "trailing JSON", contents: `{"schemaVersion":"v1","definitions":[],"findings":[],"occurrences":[]} {}`, wantDetail: "document: trailing JSON value"},
		{name: "duplicate ID", contents: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"},{"definitionId":"def-1","pluginId":"1"}],"findings":[],"occurrences":[]}`, wantDetail: "definitions[1].definitionId: duplicate ID"},
		{name: "whitespace ID", contents: `{"schemaVersion":"v1","definitions":[{"definitionId":" def-1","pluginId":"1"}],"findings":[],"occurrences":[]}`, wantDetail: "definitions[0].definitionId: surrounding whitespace"},
		{name: "wrong collection type", contents: `{"schemaVersion":"v1","definitions":{},"findings":[],"occurrences":[]}`, wantDetail: "definitions: wrong collection type"},
		{name: "invalid timestamp", contents: `{"schemaVersion":"v1","generatedAt":"` + validationSensitiveMarker + `","definitions":[],"findings":[],"occurrences":[]}`, wantDetail: "generatedAt: invalid RFC3339 timestamp"},
		{name: "inconsistent references", contents: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"},{"definitionId":"def-2","pluginId":"2"}],"findings":[{"findingId":"fin-1","definitionId":"def-1","pluginId":"1"}],"occurrences":[{"occurrenceId":"occ-1","definitionId":"def-2","findingId":"fin-1"}]}`, wantDetail: "occurrences[0].definitionId: inconsistent with finding reference"},
	}
	for _, inputFlag := range []string{"-entities-in", "-run-in"} {
		for _, tc := range tests {
			t.Run(strings.TrimPrefix(inputFlag, "-")+"/"+tc.name, func(t *testing.T) {
				hits.Store(0)
				out := filepath.Join(t.TempDir(), "preexisting.json")
				before := []byte("PREEXISTING_OUTPUT_BYTES\n")
				if err := os.WriteFile(out, before, 0o600); err != nil {
					t.Fatal(err)
				}
				inputPath := ""
				if tc.fixture != "" {
					inputPath = validationFixturePath(t, tc.fixture)
				} else {
					inputPath = filepath.Join(t.TempDir(), "invalid.json")
					if err := os.WriteFile(inputPath, []byte(tc.contents), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{
					"-wizard=false",
					"-format=entities",
					"-out=" + out,
					inputFlag + "=" + inputPath,
					"-include-mitre=false",
					"-include-cvss=false",
					"-forgejo-url=" + server.URL,
					"-forgejo-owner=synthetic-owner",
					"-forgejo-repo=synthetic-repo",
				}
				cmd := exec.Command(binary, args...)
				cmd.Env = cleanCLIEnvironment()
				output, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("CLI accepted invalid input:\n%s", output)
				}
				diagnostic := string(output)
				if !strings.Contains(diagnostic, tc.wantDetail) {
					t.Fatalf("diagnostic %q does not contain %q", diagnostic, tc.wantDetail)
				}
				if strings.Contains(diagnostic, validationSensitiveMarker) || strings.Contains(diagnostic, "sensitive-marker.invalid") {
					t.Fatalf("diagnostic leaked rejected input: %s", diagnostic)
				}
				if got := hits.Load(); got != 0 {
					t.Fatalf("destination received %d request(s) for invalid input", got)
				}
				after, readErr := os.ReadFile(out)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(after) != string(before) {
					t.Fatalf("preexisting output changed: %q", after)
				}
			})
		}
	}
}

func TestCLIRunInRejectsInvalidWrapperWithoutBareFallback(t *testing.T) {
	binary := buildTestCLI(t)
	input := filepath.Join(t.TempDir(), "wrapper.json")
	contents := `{"schema":"zap-kb/run/v999-` + validationSensitiveMarker + `","meta":{},"entities":{},"schemaVersion":"v1","definitions":[],"findings":[],"occurrences":[]}`
	if err := os.WriteFile(input, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	cmd := exec.Command(binary, "-wizard=false", "-format=entities", "-run-in="+input, "-out="+out, "-include-mitre=false", "-include-cvss=false")
	cmd.Env = cleanCLIEnvironment()
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("CLI accepted incompatible wrapper:\n%s", output)
	}
	if got := string(output); !strings.Contains(got, "schema: unsupported version") || strings.Contains(got, validationSensitiveMarker) {
		t.Fatalf("unexpected diagnostic: %s", got)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("output exists after rejected wrapper: %v", statErr)
	}
}

func TestCLIValidationAcceptsCompatibilityMatrix(t *testing.T) {
	binary := buildTestCLI(t)
	tests := []struct {
		name      string
		inputFlag string
		fixture   string
	}{
		{name: "empty entities", inputFlag: "-entities-in", fixture: "valid-empty-entities.json"},
		{name: "definitions only legacy", inputFlag: "-entities-in", fixture: "valid-definitions-only-legacy.json"},
		{name: "Cactus wrapper", inputFlag: "-run-in", fixture: "valid-cactus-run.json"},
		{name: "firing range wrapper", inputFlag: "-run-in", fixture: "valid-firing-range-run.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "entities.json")
			runCLI(t, binary, nil,
				"-wizard=false",
				"-format=entities",
				"-out="+out,
				tc.inputFlag+"="+validationFixturePath(t, tc.fixture),
				"-include-mitre=false",
				"-include-cvss=false",
			)
			ent, _, err := runartifact.ReadEntities(out)
			if err != nil {
				t.Fatalf("output did not pass public reader: %v", err)
			}
			if tc.fixture == "valid-empty-entities.json" && (ent.GeneratedAt != "2026-09-12T12:00:00Z" || ent.SourceTool != "zap") {
				t.Fatalf("empty scan metadata changed: %+v", ent)
			}
			if tc.fixture == "valid-cactus-run.json" && !strings.Contains(ent.Occurrences[0].Other, "detection-trace.v1") {
				t.Fatal("Cactus detection trace was not preserved")
			}
		})
	}
}

func TestCLIRunInputAlertsReachFlatOutputAndExplicitInputWins(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	runPath := filepath.Join(dir, "run.json")
	artifact := runartifact.Artifact{
		Schema: "zap-kb/run/v1",
		Entities: entities.EntitiesFile{
			SchemaVersion: "v1", GeneratedAt: "2026-09-19T12:00:00Z", SourceTool: "zap",
			Definitions: []entities.Definition{}, Findings: []entities.Finding{}, Occurrences: []entities.Occurrence{},
		},
		Alerts: []zapclient.Alert{{Alert: "wrapper-alert", PluginID: "1", Risk: "Low", URL: "https://wrapper.invalid"}},
	}
	if err := runartifact.Write(runPath, artifact); err != nil {
		t.Fatalf("write run artifact: %v", err)
	}

	readFlat := func(path string) []zapclient.Alert {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var alerts []zapclient.Alert
		if err := json.Unmarshal(raw, &alerts); err != nil {
			t.Fatalf("decode flat output: %v", err)
		}
		return alerts
	}

	fromWrapper := filepath.Join(dir, "wrapper-alerts.json")
	runCLI(t, binary, nil, "-wizard=false", "-run-in="+runPath, "-format=flat", "-out="+fromWrapper)
	if got := readFlat(fromWrapper); len(got) != 1 || got[0].Alert != "wrapper-alert" {
		t.Fatalf("embedded run alerts changed: %+v", got)
	}

	explicitPath := filepath.Join(dir, "explicit-alerts.json")
	if err := os.WriteFile(explicitPath, []byte(`[{"alert":"explicit-alert","pluginId":"2","risk":"High","url":"https://explicit.invalid"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	fromExplicit := filepath.Join(dir, "explicit-output.json")
	runCLI(t, binary, nil, "-wizard=false", "-run-in="+runPath, "-in="+explicitPath, "-format=flat", "-out="+fromExplicit)
	if got := readFlat(fromExplicit); len(got) != 1 || got[0].Alert != "explicit-alert" {
		t.Fatalf("explicit -in did not replace embedded run alerts: %+v", got)
	}
}

func TestCLIGeneratedEmptyEntitiesReimport(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	alerts := filepath.Join(dir, "alerts.json")
	if err := os.WriteFile(alerts, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(dir, "first.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities", "-in="+alerts, "-out="+first,
		"-scan-label=empty-synthetic", "-generated-at=2026-09-12T12:05:00Z",
		"-include-mitre=false", "-include-cvss=false",
	)
	second := filepath.Join(dir, "second.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities", "-entities-in="+first, "-out="+second,
		"-include-mitre=false", "-include-cvss=false",
	)
	ent, _, err := runartifact.ReadEntities(second)
	if err != nil {
		t.Fatalf("reimport generated empty entities: %v", err)
	}
	if ent.GeneratedAt != "2026-09-12T12:05:00Z" || ent.SourceTool != "zap" {
		t.Fatalf("generated empty metadata changed: %+v", ent)
	}
}

func TestCLIDefinitionsOnlyReimport(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities",
		"-entities-in="+validationFixturePath(t, "valid-definitions-only-legacy.json"),
		"-out="+first, "-include-mitre=false", "-include-cvss=false",
	)
	second := filepath.Join(dir, "second.json")
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities", "-entities-in="+first, "-out="+second,
		"-include-mitre=false", "-include-cvss=false",
	)
	ent, _, err := runartifact.ReadEntities(second)
	if err != nil {
		t.Fatalf("reimport definitions-only entities: %v", err)
	}
	if len(ent.Definitions) != 1 || len(ent.Findings) != 0 || len(ent.Occurrences) != 0 {
		t.Fatalf("definitions-only shape changed: %+v", ent)
	}
}

func TestCLINativeZAPAlertsStillPass(t *testing.T) {
	binary := buildTestCLI(t)
	out := filepath.Join(t.TempDir(), "entities.json")
	alerts, err := filepath.Abs(filepath.Join("..", "..", "testdata", "alerts_smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	runCLI(t, binary, nil,
		"-wizard=false", "-format=entities", "-in="+alerts, "-out="+out,
		"-scan-label=native-zap-synthetic", "-generated-at=2026-09-12T12:06:00Z",
		"-include-mitre=false", "-include-cvss=false",
	)
	ent, _, err := runartifact.ReadEntities(out)
	if err != nil {
		t.Fatalf("native ZAP output failed validation: %v", err)
	}
	if len(ent.Findings) == 0 || len(ent.Occurrences) == 0 {
		t.Fatalf("native ZAP fixture produced no evidence: %+v", ent)
	}
}

func TestCLIMergeValidatesCombinedGraphBeforeReplacingOutput(t *testing.T) {
	binary := buildTestCLI(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	add := filepath.Join(dir, "add.json")
	baseJSON := `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"}],"findings":[{"findingId":"fin-shared","definitionId":"def-1","pluginId":"1"}],"occurrences":[]}`
	addJSON := `{"schemaVersion":"v1","definitions":[{"definitionId":"def-2","pluginId":"2"}],"findings":[{"findingId":"fin-shared","definitionId":"def-2","pluginId":"2"}],"occurrences":[{"occurrenceId":"occ-2","definitionId":"def-2","findingId":"fin-shared"}]}`
	if err := os.WriteFile(base, []byte(baseJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(add, []byte(addJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "merged.json")
	before := []byte("PREEXISTING_MERGE_OUTPUT\n")
	if err := os.WriteFile(out, before, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "merge", "-inputs="+base+","+add, "-out="+out)
	cmd.Env = cleanCLIEnvironment()
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("merge accepted inconsistent combined graph:\n%s", output)
	}
	if !strings.Contains(string(output), "occurrences[0].definitionId: inconsistent with finding reference") {
		t.Fatalf("unexpected merge diagnostic: %s", output)
	}
	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("merge replaced output before validation: %q", after)
	}
}

func TestCLIRejectsUnsafeIdentityBeforeVaultOutputOrDestinationSideEffects(t *testing.T) {
	binary := buildTestCLI(t)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	bare := `{"schemaVersion":"v1","sourceTool":"zap","definitions":[{"definitionId":"def-one","pluginId":"10001","alert":"Synthetic"}],"findings":[{"findingId":"../../outside-vault","definitionId":"def-one","pluginId":"10001","url":"https://example.test/","method":"GET","risk":"High"}],"occurrences":[]}`
	for _, inputFlag := range []string{"-entities-in", "-run-in"} {
		t.Run(strings.TrimPrefix(inputFlag, "-"), func(t *testing.T) {
			hits.Store(0)
			caseDir := t.TempDir()
			vault := filepath.Join(caseDir, "vault")
			out := filepath.Join(caseDir, "output.json")
			sentinels := map[string][]byte{
				filepath.Join(vault, "INDEX.md"):            []byte("PREEXISTING_INDEX\n"),
				filepath.Join(vault, "findings", "kept.md"): []byte("PREEXISTING_FINDING\n"),
				filepath.Join(caseDir, "outside-vault.md"):  []byte("PREEXISTING_SIBLING\n"),
				out: []byte("PREEXISTING_OUTPUT\n"),
			}
			for path, contents := range sentinels {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			contents := bare
			if inputFlag == "-run-in" {
				contents = `{"schema":"zap-kb/run/v1","meta":{"sourceTool":"zap"},"entities":` + bare + `}`
			}
			input := filepath.Join(caseDir, "unsafe.json")
			if err := os.WriteFile(input, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary,
				"-wizard=false",
				"-format=obsidian",
				"-obsidian-dir="+vault,
				"-out="+out,
				inputFlag+"="+input,
				"-include-mitre=false",
				"-include-cvss=false",
				"-forgejo-url="+server.URL,
				"-forgejo-owner=synthetic-owner",
				"-forgejo-repo=synthetic-repo",
				"-forgejo-min-risk=info",
			)
			cmd.Env = cleanCLIEnvironment()
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("CLI accepted path-unsafe identity:\n%s", output)
			}
			diagnostic := string(output)
			if !strings.Contains(diagnostic, "findings[0].findingId: unsafe path component") {
				t.Fatalf("unexpected diagnostic: %s", diagnostic)
			}
			if strings.Contains(diagnostic, "outside-vault") {
				t.Fatalf("diagnostic leaked rejected identity: %s", diagnostic)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("destination received %d request(s) for invalid input", got)
			}
			for path, before := range sentinels {
				after, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("read sentinel %s: %v", path, readErr)
				}
				if string(after) != string(before) {
					t.Fatalf("sentinel %s changed: %q", path, after)
				}
			}
		})
	}
}

func validationFixturePath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", "validation", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
