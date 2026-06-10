//go:build e2e

// Adversarial E2E: Forgejo unavailability (assumptions A14, A15, A16).
//
// KNOWN-BUG tests: synccore.DoWithRetry retries only HTTP 429 (follow-up fix
// #5) and several GET paths bypass retry entirely. A single transient 5xx —
// e.g. Forgejo restarting mid-sync — aborts work that one retry would save.
// These FAIL while the gap exists; CI runs them continue-on-error.
package forgejoe2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A14: one transient 503 on an issue POST (server restarting) should be
// absorbed by a retry; today it fails that finding's create outright.
func TestKnownBugNoRetryOnTransient5xx(t *testing.T) {
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
	if sum.Errors > 0 {
		t.Errorf("KNOWN BUG (follow-up #5/A14) reproduced: a single transient 503 lost a finding (created=%d errors=%d); DoWithRetry only retries 429", sum.Created, sum.Errors)
	}
}

// A15: the status-pull GET path bypasses retry entirely — even a 429 (which
// the create path *does* retry) fails the pull immediately.
func TestKnownBugStatusPullBypassesRetry(t *testing.T) {
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

	// Pull through a proxy that 429s the first issue GET, then recovers.
	proxy := harness.NewFaultProxy(t, env.BaseURL)
	proxy.AddRule(harness.FailNTimes(http.MethodGet, "/issues/", http.StatusTooManyRequests, 1))
	res, err := forgejo.PullStatus(ctx, ef, forgejo.PullOptions{
		BaseURL: proxy.URL(), Token: env.Token, Owner: env.Owner, Repo: repo, ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("pull hard error: %v", err)
	}
	if res.Result.Errors > 0 {
		t.Errorf("KNOWN BUG (follow-up #5/A15) reproduced: one 429 on the GET path failed the status pull (errors=%d); fetchIssueStatus bypasses DoWithRetry", res.Result.Errors)
	}
}
