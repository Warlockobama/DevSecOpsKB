//go:build e2e

// Adversarial E2E: partial failure (assumptions A8, A9, A10).
package forgejoe2e

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A9 (layer fix 2): when some issue creates fail, the CLI must exit non-zero
// so the CronJob/CI sees the partial failure instead of a green run. Routed
// through the fault proxy, which 500s every issue POST.
func TestPartialCreateFailureExitsNonZero(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	proxy := harness.NewFaultProxy(t, env.BaseURL)
	proxy.AddRule(harness.FailNTimes(http.MethodPost, "/issues", http.StatusInternalServerError, 1000))

	dir := t.TempDir()
	fixture := harness.WriteFixture(t, dir, harness.Fixture(harness.FixtureOptions{NumHighFindings: 2}))

	out, code := harness.RunCLI(t, env, 3*time.Minute,
		"-entities-in", fixture,
		"-format", "obsidian",
		"-obsidian-dir", filepath.Join(dir, "vault"),
		"-forgejo-url", proxy.URL(),
		"-forgejo-owner", env.Owner,
		"-forgejo-repo", repo,
		"-forgejo-min-risk", "medium",
	)
	if code == 0 {
		t.Errorf("A9 VIOLATED: CLI exited 0 despite failed issue creates.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "errors=") {
		t.Errorf("output does not report errors: %s", out)
	}
}

// A8: a publisher that loses its backend mid-run (some issues created, refs
// never persisted) must converge on the next clean run with no duplicates —
// the remote dedup index is the only recovery path.
func TestCrashMidRunThenRerunConverges(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 3})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Run 1: backend dies after the first successful create.
	proxy := harness.NewFaultProxy(t, env.BaseURL)
	proxy.AddRule(harness.FailAfterN(http.MethodPost, "/issues", http.StatusBadGateway, 1))
	brokenOpts := forgejo.Options{
		BaseURL: proxy.URL(), Token: env.Token, Owner: env.Owner, Repo: repo,
		MinRisk: "medium", Concurrency: 1, // serialize so exactly 1 create lands
	}
	sum1, err := forgejo.Export(ctx, ef, brokenOpts)
	if err != nil {
		t.Fatalf("broken export returned hard error (expected partial): %v", err)
	}
	if sum1.Created == 0 || sum1.Errors == 0 {
		t.Fatalf("test setup: wanted a partial run, got created=%d errors=%d", sum1.Created, sum1.Errors)
	}

	// Run 2: clean. Must create exactly the missing issues, duplicating none —
	// even though run 1's ticket refs were never persisted anywhere.
	cleanOpts := forgejo.Options{
		BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo,
		MinRisk: "medium",
	}
	sum2, err := forgejo.Export(ctx, ef, cleanOpts)
	if err != nil {
		t.Fatalf("recovery export: %v", err)
	}
	issues := env.ListIssues(t, repo)
	if len(issues) != 3 {
		t.Errorf("A8 VIOLATED: %d issues after crash+recovery, want 3 (created run1=%d run2=%d, skipped run2=%d)",
			len(issues), sum1.Created, sum2.Created, sum2.Skipped)
	}
}
