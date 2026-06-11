//go:build e2e

// Adversarial E2E: conflict handling (assumptions A5, A6).
//
// Resolved semantics: content flows one-directionally KB→Forgejo. The KB owns
// content; Forgejo owns workflow status. These tests pin those semantics so a
// change in either direction is a deliberate decision, not drift.
package forgejoe2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/e2e/forgejo/harness"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
)

// A5 (updated): issue bodies are machine-owned and RECONCILE on re-publish.
// When a finding's evidence changes after its issue exists, the next export
// refreshes the issue body (a single PATCH on the existing issue — no
// duplicate, no new issue) rather than freezing the content at create time.
//
// This flips the original pin-test, which documented the old create-only
// "content freezes" drift and explicitly said to update it consciously once
// reconciliation was added. The issue-lifecycle work added that PATCH path
// (Summary.BodiesUpdated), so the assertion now pins the reconciling behavior.
func TestIssueBodyRefreshesOnReexport(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	opts := forgejo.Options{BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo, MinRisk: "medium"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	before := harness.Fixture(harness.FixtureOptions{NumHighFindings: 1, EvidenceText: "evidence-v1"})
	if _, err := forgejo.Export(ctx, before, opts); err != nil {
		t.Fatalf("first export: %v", err)
	}

	// Same finding IDs, changed evidence — simulates a later scan observing
	// the same finding with different details.
	after := harness.Fixture(harness.FixtureOptions{NumHighFindings: 1, EvidenceText: "evidence-v2-ESCALATED"})
	sum, err := forgejo.Export(ctx, after, opts)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if sum.Created != 0 || sum.BodiesUpdated != 1 || sum.Skipped != 0 {
		t.Fatalf("second export created=%d bodiesUpdated=%d skipped=%d, want 0/1/0 (body refresh)",
			sum.Created, sum.BodiesUpdated, sum.Skipped)
	}

	issues := env.ListIssues(t, repo)
	if len(issues) != 1 {
		t.Fatalf("%d issues, want 1 (refresh must reuse the existing issue, not duplicate)", len(issues))
	}
	body := issues[0].Body
	if !strings.Contains(body, "evidence-v2-ESCALATED") || strings.Contains(body, "evidence-v1") {
		t.Errorf("issue body did not reconcile to v2 evidence: %q", body)
	}
}

// A6: KB owns wiki content — an out-of-band human edit in the Forgejo wiki is
// clobbered by the next publish, cleanly (no error, no merge).
func TestWikiClobbersRemoteEdits(t *testing.T) {
	env := harness.FromEnv(t)
	repo := env.CreateRepo(t, true)
	vault := t.TempDir()
	const kbContent = "# KB Home\n\nKB-owned content."
	harness.WriteVault(t, vault, map[string]string{"INDEX.md": kbContent})
	opts := forgejo.WikiOptions{BaseURL: env.BaseURL, Token: env.Token, Owner: env.Owner, Repo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := forgejo.ExportWiki(ctx, vault, opts); err != nil {
		t.Fatalf("first wiki export: %v", err)
	}

	// Human edits the page in the UI between publishes.
	env.EditWikiPage(t, repo, "Home", "# Edited by a human\n\nLocal wisdom that will be lost.")

	sum, err := forgejo.ExportWiki(ctx, vault, opts)
	if err != nil {
		t.Fatalf("re-publish over human edit errored: %v (must clobber cleanly)", err)
	}
	if sum.Errors != 0 {
		t.Fatalf("re-publish reported %d errors, want 0", sum.Errors)
	}
	got, ok := env.GetWikiPage(t, repo, "Home")
	if !ok {
		t.Fatal("Home page missing after re-publish")
	}
	if !strings.Contains(got, "KB-owned content") {
		t.Errorf("R3 VIOLATED: KB did not win the content conflict; page = %q", got)
	}
}
