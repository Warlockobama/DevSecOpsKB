//go:build e2e

// Adversarial E2E: Forgejo unavailability (assumptions A14, A15, A16).
//
// synccore.DoWithRetry now retries transient failures (429 + 502/503/504 +
// transport errors), and the GET-heavy paths (status pull, wiki existence,
// repo preflight) route through DoWithRetryRaw. These tests assert that a
// single transient blip — e.g. Forgejo restarting mid-sync — is absorbed
// rather than dropping work. They REGRESS (fail) if retry coverage narrows.
package forgejoe2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A14: one transient 503 on an issue POST (server restarting) must be absorbed
// by a retry, not lose that finding's create.
func TestTransient5xxIsRetried(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	proxy := harness.NewFaultProxy(t, env.BaseURL)
	// Exactly one 503, then healthy — the canonical "blip" a retry absorbs.
	proxy.AddRule(harness.FailNTimes(http.MethodPost, "/issues", http.StatusServiceUnavailable, 1))

	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sum, err := forgejo.Export(ctx, ef, forgejo.Options{
		BaseURL: proxy.URL(), Token: env.Token, Owner: env.Owner, Repo: repo,
		MinRisk: "medium", Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("export hard error: %v", err)
	}
	if sum.Errors != 0 {
		t.Errorf("A14 REGRESSION: a single transient 503 lost a finding (created=%d errors=%d); DoWithRetry should absorb 503", sum.Created, sum.Errors)
	}
	if got := env.ListIssues(t, repo); len(got) != 2 {
		t.Errorf("A14 REGRESSION: %d issues after a transient 503, want 2", len(got))
	}
}

// A15: the status-pull GET path now goes through DoWithRetryRaw, so a single
// transient 503 is retried instead of failing the pull.
func TestStatusPullRetriesTransient(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Publish directly so an issue + ticket ref exists.
	sum, err := forgejo.Export(ctx, ef, forgejo.Options{
		BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo, MinRisk: "medium",
	})
	if err != nil || len(sum.TicketRefs) != 1 {
		t.Fatalf("setup export: sum=%+v err=%v", sum, err)
	}
	for i := range ef.Findings {
		if ref, ok := sum.TicketRefs[ef.Findings[i].FindingID]; ok {
			ef.Findings[i].Analyst = withTicketRef(ef.Findings[i].Analyst, ref)
		}
	}

	// Pull through a proxy that 503s the first issue GET, then recovers.
	proxy := harness.NewFaultProxy(t, env.BaseURL)
	proxy.AddRule(harness.FailNTimes(http.MethodGet, "/issues/", http.StatusServiceUnavailable, 1))
	res, err := forgejo.PullStatus(ctx, ef, forgejo.PullOptions{
		BaseURL: proxy.URL(), Token: env.Token, Owner: env.Owner, Repo: repo, ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("pull hard error: %v", err)
	}
	if res.Result.Errors > 0 {
		t.Errorf("A15 REGRESSION: a transient 503 on the GET path failed the status pull (errors=%d); fetchIssueStatus should retry via DoWithRetryRaw", res.Result.Errors)
	}
}
