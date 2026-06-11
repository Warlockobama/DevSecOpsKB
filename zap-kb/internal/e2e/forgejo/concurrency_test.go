//go:build e2e

// Adversarial E2E: concurrency (assumptions A11, A13, A24).
//
// The dedup path now reconciles duplicates: it keeps the lowest-numbered issue
// per finding and closes the rest, and the label-create race resolves to the
// winner instead of erroring. So two racing publishers may briefly create
// duplicate issues, but the run converges — at most one OPEN issue per finding.
// These tests assert that convergence (and a clean label race).
package forgejoe2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A11/A13: two publishers racing on a fresh repo must both succeed (no
// label-create failure, A13) and converge to exactly one open issue per
// finding after reconcile (A11). A second, serial run must then be a clean
// dedup with zero duplicates remaining.
func TestConcurrentPublishersConverge(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 4})
	opts := forgejo.Options{
		BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo,
		MinRisk: "medium",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = forgejo.Export(ctx, ef, opts)
		}(i)
	}
	wg.Wait()

	// A13: neither publisher may fail outright (label-create race is handled).
	for i, err := range errs {
		if err != nil {
			t.Errorf("A13 REGRESSION: concurrent publisher %d failed hard: %v", i, err)
		}
	}

	// A reconciling run settles any duplicates the race created.
	if _, err := forgejo.Export(ctx, ef, opts); err != nil {
		t.Fatalf("reconcile run: %v", err)
	}

	// A11: at most one OPEN issue per finding marker.
	openByFinding := map[string]int{}
	for _, iss := range env.ListIssues(t, repo) {
		if iss.State != "open" {
			continue
		}
		if fid := harness.MarkerFindingID(iss.Body); fid != "" {
			openByFinding[fid]++
		}
	}
	if len(openByFinding) != 4 {
		t.Errorf("want 4 findings tracked, got %d (%v)", len(openByFinding), openByFinding)
	}
	for fid, n := range openByFinding {
		if n != 1 {
			t.Errorf("A11 REGRESSION: finding %s has %d OPEN issues after reconcile, want exactly 1", fid, n)
		}
	}
}

// A24: the dedup winner is the lowest-numbered issue, deterministically, and a
// steady-state re-run neither creates nor closes anything.
func TestDedupWinnerIsStableLowestNumber(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 1})
	opts := forgejo.Options{BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo, MinRisk: "medium"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	first, err := forgejo.Export(ctx, ef, opts)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	winner := first.TicketRefs["fin-e2e0000"]
	if winner == "" {
		t.Fatal("no ticket ref recorded")
	}

	for i := 0; i < 2; i++ {
		sum, err := forgejo.Export(ctx, ef, opts)
		if err != nil {
			t.Fatalf("re-publish %d: %v", i, err)
		}
		if sum.Skipped != 1 || sum.Created != 0 || sum.DuplicatesClosed != 0 {
			t.Fatalf("re-publish %d: created=%d skipped=%d dupsClosed=%d, want 0/1/0", i, sum.Created, sum.Skipped, sum.DuplicatesClosed)
		}
		if sum.TicketRefs["fin-e2e0000"] != winner {
			t.Fatalf("A24 REGRESSION: winner ref changed across runs: %q → %q", winner, sum.TicketRefs["fin-e2e0000"])
		}
	}
}
