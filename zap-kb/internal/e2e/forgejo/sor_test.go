//go:build e2e

// Adversarial E2E: system-of-record & environment (assumptions A20, A22).
//
// The ingest seam (entities.json on a shared volume) is where the user's
// intelligence pipelines will hand data to the publisher — a half-written or
// truncated file must fail loudly, never publish a silent subset.
package forgejoe2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
)

// A20: a truncated entities.json (e.g. the CronJob fired mid-write by a
// detection source) must exit non-zero and publish nothing.
func TestTruncatedEntitiesFailsCleanly(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	dir := t.TempDir()

	// Take a valid fixture and chop it mid-structure.
	full := harness.WriteFixture(t, dir, harness.Fixture(harness.FixtureOptions{NumHighFindings: 2}))
	raw, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.json")
	if err := os.WriteFile(truncated, raw[:len(raw)/2], 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := harness.RunCLI(t, env, 2*time.Minute,
		"-entities-in", truncated,
		"-format", "obsidian",
		"-obsidian-dir", filepath.Join(dir, "vault"),
		"-forgejo-url", env.BaseURL,
		"-forgejo-owner", env.Owner,
		"-forgejo-repo", repo,
		"-forgejo-min-risk", "medium",
	)
	if code == 0 {
		t.Errorf("A20 VIOLATED: truncated entities input exited 0\noutput:\n%s", out)
	}
	if issues := env.ListIssues(t, repo); len(issues) != 0 {
		t.Errorf("A20 VIOLATED: truncated input still published %d issue(s) — partial SoR was treated as truth", len(issues))
	}
}

// A22 (layer fix 4): publishing the wiki against a repo whose wiki is disabled
// must be a hard, descriptive failure (non-zero exit), not N silent per-page
// warnings with a green exit.
func TestWikiDisabledFailsHard(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, false) // wiki explicitly disabled
	dir := t.TempDir()
	fixture := harness.WriteFixture(t, dir, harness.Fixture(harness.FixtureOptions{NumHighFindings: 1}))

	out, code := harness.RunCLI(t, env, 2*time.Minute,
		"-entities-in", fixture,
		"-format", "obsidian",
		"-obsidian-dir", filepath.Join(dir, "vault"),
		"-forgejo-url", env.BaseURL,
		"-forgejo-owner", env.Owner,
		"-forgejo-repo", repo,
		"-forgejo-min-risk", "medium",
		"-forgejo-wiki",
	)
	if code == 0 {
		t.Errorf("A22 VIOLATED: wiki-disabled publish exited 0\noutput:\n%s", out)
	}
	if !strings.Contains(out, "wiki is not enabled") {
		t.Errorf("A22: missing descriptive error; operators get no hint to flip has_wiki.\noutput:\n%s", out)
	}
}
