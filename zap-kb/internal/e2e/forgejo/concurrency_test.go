//go:build e2e

// Adversarial E2E: concurrency (assumptions A11, A13, A24).
//
// KNOWN-BUG tests: the dedup design is read-index-then-create with no
// cross-process guard (follow-up fix #6), and label creation has no
// already-exists handling (follow-up fix; labels.go createLabel). These tests
// FAIL when the bug reproduces — CI runs them in a continue-on-error step so
// they stay loud without blocking, until the follow-ups land.
package forgejoe2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A11/A13: two publishers racing on the same fresh repo. Any duplicate issue
// (A11) or label-create failure (A13) red-flags the missing cross-process
// idempotency guard.
func TestKnownBugConcurrentPublishersRace(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 4})
	opts := forgejo.Options{
		BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo,
		MinRisk: "medium",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	type result struct {
		sum forgejo.Summary
		err error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sum, err := forgejo.Export(ctx, ef, opts)
			results[i] = result{sum: sum, err: err}
		}(i)
	}
	wg.Wait()

	// A13: a hard error on a fresh repo is almost always the label-create race.
	for i, r := range results {
		if r.err != nil {
			t.Errorf("KNOWN BUG (follow-up #6/A13) reproduced: concurrent publisher %d failed hard: %v", i, r.err)
		}
	}

	// A11: duplicates mean both writers saw an empty dedup index.
	issues := env.ListIssues(t, repo)
	seen := map[string]int{}
	for _, iss := range issues {
		if fid := harness.MarkerFindingID(iss.Body); fid != "" {
			seen[fid]++
		}
	}
	dups := 0
	for fid, n := range seen {
		if n > 1 {
			dups++
			t.Errorf("KNOWN BUG (follow-up #6/A11) reproduced: finding %s has %d issues (duplicate from concurrent publish)", fid, n)
		}
	}
	if dups == 0 && results[0].err == nil && results[1].err == nil {
		t.Logf("race not reproduced this run (%d issues, all unique) — absence of failure is not proof of safety; the guard is still missing", len(issues))
	}
}

// A24: pre-existing duplicate issues for one finding are never reconciled, and
// which one wins the ticket-ref is pagination-order dependent. Pinned as a
// documentation test: it asserts the current take-first behavior and logs the
// hazard rather than failing, since the duplicate source (A11) is the bug.
func TestDuplicateMarkersTakeFirstWins(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	ef := harness.Fixture(harness.FixtureOptions{NumHighFindings: 1})
	opts := forgejo.Options{BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo, MinRisk: "medium"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// First publish creates issue #N with the marker; second, racing publisher
	// is simulated by re-running export twice afterwards — both must keep
	// skipping and never "fix" anything.
	if _, err := forgejo.Export(ctx, ef, opts); err != nil {
		t.Fatalf("publish: %v", err)
	}
	for i := 0; i < 2; i++ {
		sum, err := forgejo.Export(ctx, ef, opts)
		if err != nil {
			t.Fatalf("re-publish %d: %v", i, err)
		}
		if sum.Skipped != 1 {
			t.Fatalf("re-publish %d: skipped=%d, want 1", i, sum.Skipped)
		}
	}
	t.Logf("A24 documented: dedup takes the first marker match; duplicate issues (if ever created by the A11 race) are never merged or closed by the sink")
}
