//go:build e2e

// Adversarial E2E: redaction & secrets (assumptions A18, A19; layer fix 1).
//
// Forgejo is a shared export surface — once a credential lands in an issue
// body or wiki page it is in the instance's database and git history. These
// tests inject a known secret into the entities evidence and assert it never
// crosses the wire by default (and that the documented opt-out works).
package forgejoe2e

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
)

const plantedSecret = "Bearer e2e-PLANTED-SECRET-c4f3b00c"

// A18 (fix 1): with default flags, a credential captured in scanner evidence
// must not appear in any published issue body or wiki page.
func TestSecretsNeverReachForgejoByDefault(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	dir := t.TempDir()
	fixture := harness.WriteFixture(t, dir, harness.Fixture(harness.FixtureOptions{
		NumHighFindings: 1, Secret: plantedSecret,
	}))

	out, code := harness.RunCLI(t, env, 3*time.Minute,
		"-entities-in", fixture,
		"-format", "obsidian",
		"-obsidian-dir", filepath.Join(dir, "vault"),
		"-forgejo-url", env.BaseURL,
		"-forgejo-owner", env.Owner,
		"-forgejo-repo", repo,
		"-forgejo-min-risk", "medium",
		"-forgejo-wiki",
	)
	if code != 0 {
		t.Fatalf("publish exited %d:\n%s", code, out)
	}

	for _, iss := range env.ListIssues(t, repo) {
		if strings.Contains(iss.Body, plantedSecret) || strings.Contains(iss.Title, plantedSecret) {
			t.Errorf("A18/R4 VIOLATED: planted secret reached issue #%d on the default publish path", iss.Number)
		}
	}
	for _, page := range []string{"Home", "Occurrences/occ-e2e0000", "Findings/fin-e2e0000"} {
		if content, ok := env.GetWikiPage(t, repo, page); ok && strings.Contains(content, plantedSecret) {
			t.Errorf("A18/R4 VIOLATED: planted secret reached wiki page %q", page)
		}
	}
	// A19: the secret must not leak into the publisher's own output either.
	if strings.Contains(out, plantedSecret) {
		t.Errorf("A19/R4 VIOLATED: planted secret printed to publisher logs")
	}
	if strings.Contains(out, env.Token) {
		t.Errorf("A19/R4 VIOLATED: Forgejo API token printed to publisher logs")
	}
}

// The opt-out must actually opt out — otherwise the flag is theater and tests
// of the default prove nothing (the secret might be dropped for an unrelated
// reason, e.g. the evidence section not rendering at all).
func TestRedactionOptOutPublishesRawEvidence(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	dir := t.TempDir()
	fixture := harness.WriteFixture(t, dir, harness.Fixture(harness.FixtureOptions{
		NumHighFindings: 1, Secret: plantedSecret,
	}))

	out, code := harness.RunCLI(t, env, 3*time.Minute,
		"-entities-in", fixture,
		"-format", "obsidian",
		"-obsidian-dir", filepath.Join(dir, "vault"),
		"-forgejo-url", env.BaseURL,
		"-forgejo-owner", env.Owner,
		"-forgejo-repo", repo,
		"-forgejo-min-risk", "medium",
		"-forgejo-redact", "off",
	)
	if code != 0 {
		t.Fatalf("publish exited %d:\n%s", code, out)
	}
	found := false
	for _, iss := range env.ListIssues(t, repo) {
		if strings.Contains(iss.Body, plantedSecret) {
			found = true
		}
	}
	if !found {
		t.Errorf("-forgejo-redact=off did not publish raw evidence — the redaction toggle (or the evidence render path) is broken, so the default-redaction test cannot be trusted")
	}
}
