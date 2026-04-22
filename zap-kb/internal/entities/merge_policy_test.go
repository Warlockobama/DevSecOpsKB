package entities

import (
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// findingWithFPReopens builds a finding whose History contains n synthetic
// "auto-reopened from fp" entries — each one represents one full cycle of
// "analyst said fp, detection found it again." Used to drive the auto-
// suppression and tune-scan tagging tests without standing up a full multi-
// merge fixture.
func findingWithFPReopens(findingID, pluginID string, n int) Finding {
	hist := make([]AnalystHistoryEntry, 0, n)
	for i := 0; i < n; i++ {
		// Use distinct scanLabels so EntryIDs don't collide and we genuinely
		// see n entries after history-union dedup.
		entry := NewAnalystHistoryEntry(
			"scan-fp-cycle-"+itoa(i),
			"open", "fp",
			"alice",
			"auto-reopened: recurrence in scan scan-fp-cycle-"+itoa(i),
			"2026-04-2"+itoa(i%9)+"T10:00:00Z",
		)
		hist = append(hist, entry)
	}
	return Finding{
		FindingID: findingID,
		PluginID:  pluginID,
		URL:       "https://example.com/x",
		Method:    "GET",
		Analyst:   &Analyst{Status: "fp", Owner: "alice", History: hist},
	}
}

// TestMergeWithPolicy_AutoReopenGate: with AutoReopenOnRecurrence=false,
// a recurring fp finding gets the advisory Recurrence record but status
// stays "fp" and no history is appended. Mirrors slice 1b's "do not reopen
// accepted" guarantee — but applied org-wide via policy.
func TestMergeWithPolicy_AutoReopenGate(t *testing.T) {
	base, add := reopenFixture("fp", "alice", "scan-2026-04-21", "2026-04-21T10:00:00Z")
	policy := config.DefaultPolicy()
	policy.AutoReopenOnRecurrence = false
	merged := MergeWithPolicy(base, add, policy)
	f := merged.Findings[0]
	if f.Analyst.Status != "fp" {
		t.Errorf("Status: gate=false must preserve fp, got %q", f.Analyst.Status)
	}
	if len(f.Analyst.History) != 0 {
		t.Errorf("History: gate=false must not append entries, got %+v", f.Analyst.History)
	}
	if f.Recurrence == nil {
		t.Error("Recurrence advisory must still be set even when reopen disabled")
	}
}

// TestApplyAutoSuppression_WritesAfterThreshold: a finding with N fp-reopen
// history entries (where N == threshold) gets a pipeline-written Suppression
// scoped to the finding, with expiresAt set N days out.
func TestApplyAutoSuppression_WritesAfterThreshold(t *testing.T) {
	policy := config.DefaultPolicy() // threshold=3, expiry=90
	ef := EntitiesFile{
		SchemaVersion: "v1",
		Findings:      []Finding{findingWithFPReopens("fin-1", "10001", 3)},
	}
	applyFindingFPAutoSuppression(&ef, policy)
	s := ef.Findings[0].Suppression
	if s == nil {
		t.Fatal("Suppression must be set when fp-reopens >= threshold")
	}
	if s.Scope != "finding" {
		t.Errorf("Scope: want finding, got %q", s.Scope)
	}
	if s.DecidedBy != pipelineAutoSuppressDecidedBy {
		t.Errorf("DecidedBy: want %q, got %q", pipelineAutoSuppressDecidedBy, s.DecidedBy)
	}
	if s.ExpiresAt == "" {
		t.Error("ExpiresAt must be set (expiry days > 0)")
	}
	exp, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		t.Fatalf("ExpiresAt not RFC3339: %v", err)
	}
	delta := time.Until(exp)
	wantMin := time.Duration(policy.FindingFPSuppressionExpiryDays-1) * 24 * time.Hour
	wantMax := time.Duration(policy.FindingFPSuppressionExpiryDays+1) * 24 * time.Hour
	if delta < wantMin || delta > wantMax {
		t.Errorf("ExpiresAt should be ~%d days out, got delta=%v", policy.FindingFPSuppressionExpiryDays, delta)
	}
}

// TestApplyAutoSuppression_BelowThresholdNoOp: under threshold, no Suppression.
func TestApplyAutoSuppression_BelowThresholdNoOp(t *testing.T) {
	policy := config.DefaultPolicy() // threshold=3
	ef := EntitiesFile{Findings: []Finding{findingWithFPReopens("fin-1", "10001", 2)}}
	applyFindingFPAutoSuppression(&ef, policy)
	if ef.Findings[0].Suppression != nil {
		t.Errorf("Suppression must NOT be set below threshold, got %+v", ef.Findings[0].Suppression)
	}
}

// TestApplyAutoSuppression_DisabledByZeroThreshold: threshold<=0 must short
// circuit even with abundant history, so operators can opt out cleanly.
func TestApplyAutoSuppression_DisabledByZeroThreshold(t *testing.T) {
	policy := config.DefaultPolicy()
	policy.FindingFPSuppressionThreshold = 0
	ef := EntitiesFile{Findings: []Finding{findingWithFPReopens("fin-1", "10001", 99)}}
	applyFindingFPAutoSuppression(&ef, policy)
	if ef.Findings[0].Suppression != nil {
		t.Error("Suppression must NOT be written when threshold disabled")
	}
}

// TestApplyAutoSuppression_RespectsAnalystSuppression: an analyst-written
// Suppression (DecidedBy != pipeline) is NEVER overwritten — humans always
// win.
func TestApplyAutoSuppression_RespectsAnalystSuppression(t *testing.T) {
	policy := config.DefaultPolicy()
	f := findingWithFPReopens("fin-1", "10001", 5)
	f.Suppression = &Suppression{
		Scope: "occurrence", DecidedBy: "alice@example.com", Reason: "intentional",
	}
	ef := EntitiesFile{Findings: []Finding{f}}
	applyFindingFPAutoSuppression(&ef, policy)
	got := ef.Findings[0].Suppression
	if got == nil || got.DecidedBy != "alice@example.com" {
		t.Errorf("analyst suppression must be preserved, got %+v", got)
	}
}

// TestApplyAutoSuppression_RefreshesOnlyAfterExpiry: an existing pipeline-
// written suppression with a future expiry is left alone (no field churn);
// once it has expired, the next pass refreshes it.
func TestApplyAutoSuppression_RefreshesOnlyAfterExpiry(t *testing.T) {
	policy := config.DefaultPolicy()
	f := findingWithFPReopens("fin-1", "10001", 5)
	future := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	f.Suppression = &Suppression{
		Scope: "finding", DecidedBy: pipelineAutoSuppressDecidedBy,
		DecidedAt: "2026-01-01T00:00:00Z", ExpiresAt: future,
	}
	ef := EntitiesFile{Findings: []Finding{f}}
	applyFindingFPAutoSuppression(&ef, policy)
	if ef.Findings[0].Suppression.DecidedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("in-window pipeline suppression must not be churned, got DecidedAt=%q",
			ef.Findings[0].Suppression.DecidedAt)
	}

	// Now expire it and re-run; DecidedAt should advance.
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	ef.Findings[0].Suppression.ExpiresAt = past
	applyFindingFPAutoSuppression(&ef, policy)
	if ef.Findings[0].Suppression.DecidedAt == "2026-01-01T00:00:00Z" {
		t.Error("expired pipeline suppression must be refreshed (DecidedAt advances)")
	}
}

// TestApplyTuneScanTags_AggregatesAcrossFindings: fp-reopen counts across
// findings sharing a pluginId roll up into one rule-level total. When the
// total meets RuleTuneScanThreshold (default 5), the matching Definition's
// Taxonomy.Tags receives "tune-scan".
func TestApplyTuneScanTags_AggregatesAcrossFindings(t *testing.T) {
	policy := config.DefaultPolicy() // ruleTuneScan=5
	ef := EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-10001", PluginID: "10001"}},
		Findings: []Finding{
			findingWithFPReopens("fin-a", "10001", 3),
			findingWithFPReopens("fin-b", "10001", 2),
		},
	}
	applyRuleTuneScanTags(&ef, policy)
	d := ef.Definitions[0]
	if d.Taxonomy == nil {
		t.Fatal("Taxonomy must be initialized when tag added")
	}
	if !contains(d.Taxonomy.Tags, "tune-scan") {
		t.Errorf("tune-scan tag missing, got tags=%v", d.Taxonomy.Tags)
	}
}

// TestApplyTuneScanTags_BelowThresholdNoTag: 4 fp reopens total < 5 threshold.
func TestApplyTuneScanTags_BelowThresholdNoTag(t *testing.T) {
	policy := config.DefaultPolicy()
	ef := EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-10001", PluginID: "10001"}},
		Findings:    []Finding{findingWithFPReopens("fin-a", "10001", 4)},
	}
	applyRuleTuneScanTags(&ef, policy)
	if ef.Definitions[0].Taxonomy != nil && contains(ef.Definitions[0].Taxonomy.Tags, "tune-scan") {
		t.Error("tune-scan tag must NOT be added below threshold")
	}
}

// TestApplyTuneScanTags_Idempotent: running the pass twice does not produce
// duplicate "tune-scan" tags (unionStrings handles dedup).
func TestApplyTuneScanTags_Idempotent(t *testing.T) {
	policy := config.DefaultPolicy()
	ef := EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-10001", PluginID: "10001"}},
		Findings:    []Finding{findingWithFPReopens("fin-a", "10001", 5)},
	}
	applyRuleTuneScanTags(&ef, policy)
	applyRuleTuneScanTags(&ef, policy)
	count := 0
	for _, tag := range ef.Definitions[0].Taxonomy.Tags {
		if tag == "tune-scan" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("tune-scan must appear exactly once after idempotent reruns, got %d", count)
	}
}

// TestApplyTuneScanTags_DisabledByZeroThreshold: opt-out path.
func TestApplyTuneScanTags_DisabledByZeroThreshold(t *testing.T) {
	policy := config.DefaultPolicy()
	policy.RuleTuneScanThreshold = 0
	ef := EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-10001", PluginID: "10001"}},
		Findings:    []Finding{findingWithFPReopens("fin-a", "10001", 99)},
	}
	applyRuleTuneScanTags(&ef, policy)
	if ef.Definitions[0].Taxonomy != nil && contains(ef.Definitions[0].Taxonomy.Tags, "tune-scan") {
		t.Error("tune-scan must not be added when threshold disabled")
	}
}

// TestMergeWithPolicy_EndToEnd: a recurring fp finding goes through
// Merge → auto-reopen (history entry appended) → still under threshold
// after one cycle, no suppression. Sanity check that the wrapper plumbs
// through correctly.
func TestMergeWithPolicy_EndToEnd(t *testing.T) {
	base, add := reopenFixture("fp", "alice", "scan-1", "2026-04-21T10:00:00Z")
	policy := config.DefaultPolicy()
	merged := MergeWithPolicy(base, add, policy)
	f := merged.Findings[0]
	if f.Analyst.Status != "open" {
		t.Errorf("Status: want open after reopen, got %q", f.Analyst.Status)
	}
	// Only one fp-reopen cycle so far → no suppression yet.
	if f.Suppression != nil {
		t.Errorf("Suppression must not fire after one cycle, got %+v", f.Suppression)
	}
	if !strings.Contains(f.Analyst.History[0].Notes, "auto-reopened") {
		t.Errorf("expected auto-reopened history note, got %q", f.Analyst.History[0].Notes)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
