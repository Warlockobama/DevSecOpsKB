//go:build e2e

package forgejoe2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

// TestDemoArtifactToForgejo is the small, disposable public-boundary check used
// by the demo runbook. It deliberately uses the real CLI and a real Forgejo,
// then reads issues and wiki pages back through the server API.
func TestDemoArtifactToForgejo(t *testing.T) {
	if os.Getenv("DEMO_FORGEJO_ACCEPTANCE") != "1" {
		t.Skip("set DEMO_FORGEJO_ACCEPTANCE=1 through the disposable demo harness")
	}
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	dir := t.TempDir()
	vault := filepath.Join(dir, "vault")
	artifactPath := filepath.Join(dir, "demo.run.json")

	fixture := harness.Fixture(harness.FixtureOptions{NumHighFindings: 2})
	fixture.GeneratedAt = "2026-09-12T12:00:00Z"
	for i := range fixture.Findings {
		fixture.Findings[i].PluginID = "10038"
	}
	for i := range fixture.Occurrences {
		fixture.Occurrences[i].ScanLabel = "demo-run-001"
		fixture.Occurrences[i].ObservedAt = "2026-09-12T12:00:00Z"
		fixture.Occurrences[i].Request = &entities.HTTPRequest{
			RawHeader: "GET /authorized-demo HTTP/1.1\nHost: target.example\nAccept: text/html\n",
			Headers:   []entities.Header{{Name: "Accept", Value: "text/html"}},
		}
		fixture.Occurrences[i].Response = &entities.HTTPResponse{
			StatusCode: 200,
			Headers:    []entities.Header{{Name: "Content-Type", Value: "text/html"}},
		}
	}
	artifact := runartifact.Artifact{
		Schema: runartifact.SchemaV1,
		Meta: runartifact.Meta{
			SourceTool:  fixture.SourceTool,
			GeneratedAt: fixture.GeneratedAt,
			ScanLabel:   "demo-run-001",
			SiteLabel:   "authorized-demo-target",
			PipelineRun: "firing-range/demo-run-001",
			Commit:      "fixture-replay",
		},
		Entities: fixture,
	}
	if err := runartifact.Write(artifactPath, artifact); err != nil {
		t.Fatalf("write portable run artifact: %v", err)
	}
	original, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read portable run artifact: %v", err)
	}
	evidenceDir := strings.TrimSpace(os.Getenv("DEMO_EVIDENCE_DIR"))
	if evidenceDir != "" {
		if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
			t.Fatalf("create evidence directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(evidenceDir, "accepted-run.json"), original, 0o644); err != nil {
			t.Fatalf("retain accepted run artifact: %v", err)
		}
	}

	run := func() string {
		out, code := harness.RunCLI(t, env, 4*time.Minute,
			"-run-in", artifactPath,
			"-format", "obsidian",
			"-obsidian-dir", vault,
			"-forgejo-url", env.BaseURL,
			"-forgejo-owner", env.Owner,
			"-forgejo-repo", repo,
			"-forgejo-min-risk", "medium",
			"-forgejo-wiki",
			"-forgejo-wiki-timeout", "120s",
			"-forgejo-wiki-request-timeout", "30s",
		)
		if code != 0 {
			t.Fatalf("publish exited %d:\n%s", code, out)
		}
		return out
	}

	first := run()
	if !strings.Contains(first, "Forgejo: created=1") || !strings.Contains(first, "Forgejo wiki: created=") {
		t.Fatalf("first publish did not report issue and wiki creation:\n%s", first)
	}
	issues := env.ListIssues(t, repo)
	if len(issues) != 1 {
		t.Fatalf("grouped issue readback count = %d, want 1", len(issues))
	}
	home, ok := env.GetWikiPage(t, repo, "Home")
	if !ok || !strings.Contains(home, "demo-run-001") || !strings.Contains(home, "Findings") {
		t.Fatalf("Home readback lacks run identity or finding navigation: %q", home)
	}
	if _, ok := env.GetWikiPage(t, repo, "Definitions/10038-csp-header-not-set"); !ok {
		t.Fatal("definition wiki page was not readable through the server API")
	}

	second := run()
	if !strings.Contains(second, "created=0") || !strings.Contains(second, "skipped=1") {
		t.Fatalf("identical rerun was not an issue no-op:\n%s", second)
	}
	if !strings.Contains(second, "Forgejo wiki: created=0 updated=0") || !strings.Contains(second, "link_fixes=0 errors=0") {
		t.Fatalf("identical rerun was not a wiki no-op:\n%s", second)
	}
	if got := len(env.ListIssues(t, repo)); got != 1 {
		t.Fatalf("identical rerun produced %d grouped issues, want 1", got)
	}

	env.AddIssueLabel(t, repo, issues[0].Number, "accepted")
	updated, _, err := runartifact.ReadValidated(artifactPath)
	if err != nil {
		t.Fatalf("read publisher derivative: %v", err)
	}
	updated.Meta.GeneratedAt = "2026-09-12T13:00:00Z"
	updated.Meta.ScanLabel = "demo-run-002"
	updated.Meta.PipelineRun = "firing-range/demo-run-002"
	updated.Entities.GeneratedAt = updated.Meta.GeneratedAt
	extra := updated.Entities.Occurrences[0]
	extra.OccurrenceID = "occ-e2e-changed"
	extra.ScanLabel = "demo-run-002"
	extra.ObservedAt = updated.Meta.GeneratedAt
	extra.Evidence = "CSP header still absent on the authorized changed replay"
	updated.Entities.Occurrences = append(updated.Entities.Occurrences, extra)
	for i := range updated.Entities.Findings {
		if updated.Entities.Findings[i].FindingID == extra.FindingID {
			updated.Entities.Findings[i].Occurrences++
		}
	}
	if err := runartifact.Write(artifactPath, updated); err != nil {
		t.Fatalf("write changed replay artifact: %v", err)
	}
	run()
	issues = env.ListIssues(t, repo)
	if len(issues) != 1 {
		t.Fatalf("changed replay produced %d issues, want 1 stable grouped case", len(issues))
	}
	foundAccepted := false
	for _, issue := range issues {
		for _, label := range issue.Labels {
			if label.Name == "accepted" {
				foundAccepted = true
			}
		}
	}
	if !foundAccepted {
		t.Fatal("changed replay discarded the analyst-owned accepted label")
	}
	scans, ok := env.GetWikiPage(t, repo, "Scans")
	if !ok || !strings.Contains(scans, "demo-run-001") || !strings.Contains(scans, "demo-run-002") {
		t.Fatalf("scan history readback lacks both replay identities: %q", scans)
	}

	evidence := map[string]any{
		"schema":              "devsecopskb/demo-acceptance/v1",
		"artifact_sha256":     sha256Hex(original),
		"repository":          env.Owner + "/" + repo,
		"issue_count":         len(issues),
		"identical_rerun":     "no duplicate issues or wiki mutations",
		"changed_run_history": []string{"demo-run-001", "demo-run-002"},
		"analyst_decision":    "accepted label preserved",
		"readback":            []string{"issues", "Home", "Scans", "Definitions/10038-csp-header-not-set"},
		"scope":               "disposable local Forgejo; synthetic authorized fixture",
	}
	if evidenceDir != "" {
		raw, _ := json.MarshalIndent(evidence, "", "  ")
		if err := os.WriteFile(filepath.Join(evidenceDir, "forgejo-readback.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatalf("write sanitized readback: %v", err)
		}
	}
	t.Logf("disposable readback: issues=%d scans=2 analyst_label=preserved artifact_sha256=%s", len(issues), sha256Hex(original))
	if holdText := strings.TrimSpace(os.Getenv("DEMO_REVIEW_HOLD")); holdText != "" {
		hold, err := time.ParseDuration(holdText)
		if err != nil || hold <= 0 || hold > 2*time.Minute {
			t.Fatalf("DEMO_REVIEW_HOLD must be between 1ns and 2m")
		}
		if !strings.HasPrefix(env.BaseURL, "http://127.0.0.1:") && !strings.HasPrefix(env.BaseURL, "http://localhost:") {
			t.Fatal("visual review hold is allowed only for a loopback disposable Forgejo")
		}
		env.SetRepoPrivate(t, repo, false)
		t.Logf("visual review URL: %s/%s/%s/wiki", env.BaseURL, env.Owner, repo)
		time.Sleep(hold)
	}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
