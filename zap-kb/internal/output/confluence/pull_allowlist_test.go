package confluence

import (
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// TestFieldsToAnalyst_DropsLifecycleFields guards the epic-#71 contract:
// priorStatus, acceptedUntil, and history are pipeline-only fields. Inbound
// sync from Confluence must never populate them, even if a workflow page
// somehow advertises those keys. If this test ever fails, a reviewer added
// new parsing that leaks lifecycle state — reject the change.
func TestFieldsToAnalyst_DropsLifecycleFields(t *testing.T) {
	// All the known good keys plus the ones we want to ensure are ignored.
	a := fieldsToAnalyst(map[string]string{
		"status":        "fp",
		"owner":         "alice",
		"tags":          "case-ticket",
		"tickets":       "SEC-1",
		"priorStatus":   "open",                 // must be ignored
		"acceptedUntil": "2026-12-31T00:00:00Z", // must be ignored
		"history":       "some pasted history",  // must be ignored
	})
	if a == nil {
		t.Fatal("expected Analyst, got nil")
	}
	if a.PriorStatus != "" {
		t.Errorf("PriorStatus leaked via Confluence pull: %q", a.PriorStatus)
	}
	if a.AcceptedUntil != "" {
		t.Errorf("AcceptedUntil leaked via Confluence pull: %q", a.AcceptedUntil)
	}
	if len(a.History) != 0 {
		t.Errorf("History leaked via Confluence pull: %+v", a.History)
	}
}

// TestMergeAnalystConfluenceWins_PreservesLifecycleState ensures that when a
// Confluence pull delivers an Analyst (with no lifecycle fields — see above),
// merging it over an existing Analyst that DOES carry priorStatus/
// acceptedUntil/history leaves those fields intact. Confluence wins on
// Status/Owner/Tags but has no authority over the audit trail.
func TestMergeAnalystConfluenceWins_PreservesLifecycleState(t *testing.T) {
	existing := &entities.Analyst{
		Status:        "open",
		PriorStatus:   "fp",
		AcceptedUntil: "2026-12-31T00:00:00Z",
		History: []entities.AnalystHistoryEntry{
			entities.NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "n1", "2026-04-21T10:00:00Z"),
		},
	}
	fromConfluence := &entities.Analyst{Status: "fp", Owner: "bob"}

	out := mergeAnalystConfluenceWins(fromConfluence, existing)
	if out == nil {
		t.Fatal("merge returned nil")
	}
	if out.Status != "fp" {
		t.Errorf("Status: Confluence should win, got %q", out.Status)
	}
	if out.PriorStatus != "fp" {
		t.Errorf("PriorStatus must be preserved from existing, got %q", out.PriorStatus)
	}
	if out.AcceptedUntil != "2026-12-31T00:00:00Z" {
		t.Errorf("AcceptedUntil must be preserved from existing, got %q", out.AcceptedUntil)
	}
	if len(out.History) != 1 {
		t.Errorf("History must be preserved from existing, got %+v", out.History)
	}
}
