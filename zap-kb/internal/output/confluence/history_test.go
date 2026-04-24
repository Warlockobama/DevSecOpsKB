package confluence

import (
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// TestBuildHistoryTimelineSection_Empty: no history entries must render the
// explicit empty-state message, not a blank table — epic #71 slice 2 (#62).
func TestBuildHistoryTimelineSection_Empty(t *testing.T) {
	out := buildHistoryTimelineSection(nil)
	if !strings.Contains(out, "No triage history recorded") {
		t.Errorf("empty history must render empty-state message, got:\n%s", out)
	}
	if strings.Contains(out, "<table>") {
		t.Error("empty history must not render a table")
	}
	if !strings.Contains(out, `ac:name="expand"`) {
		t.Error("section must be wrapped in an expand macro")
	}
}

func TestBuildHistoryTimelineSection_EmptySlice(t *testing.T) {
	out := buildHistoryTimelineSection([]entities.AnalystHistoryEntry{})
	if !strings.Contains(out, "No triage history recorded") {
		t.Errorf("empty slice must render empty-state message, got:\n%s", out)
	}
}

// TestBuildHistoryTimelineSection_WithEntries: populated history renders a
// table with one row per entry and the expand title reflects the count.
func TestBuildHistoryTimelineSection_WithEntries(t *testing.T) {
	history := []entities.AnalystHistoryEntry{
		{
			EntryID:     "e1",
			Status:      "fp",
			PriorStatus: "open",
			Owner:       "alice",
			ScanLabel:   "prod-20260101",
			Notes:       "Confirmed false positive on static asset",
			UpdatedAt:   "2026-01-01T10:00:00Z",
		},
		{
			EntryID:     "e2",
			Status:      "open",
			PriorStatus: "fp",
			Owner:       "",
			ScanLabel:   "prod-20260410",
			Notes:       "auto-reopened: recurrence in scan prod-20260410",
			UpdatedAt:   "2026-04-10T08:00:00Z",
		},
	}
	out := buildHistoryTimelineSection(history)

	if !strings.Contains(out, "Triage History (2 entries)") {
		t.Errorf("title should say 2 entries, got:\n%s", out)
	}
	if !strings.Contains(out, "<table>") {
		t.Error("should render a table with entries")
	}
	if strings.Contains(out, "No triage history recorded") {
		t.Error("non-empty history must not render empty-state message")
	}
	// All entry fields should appear in the output.
	for _, needle := range []string{
		"fp", "open", "alice", "prod-20260101", "Confirmed false positive",
		"auto-reopened", "prod-20260410", "2026-01-01T10:00:00Z",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("expected %q in history output, got:\n%s", needle, out)
		}
	}
}

// TestBuildHistoryTimelineSection_HTMLEscaped: entry fields with special HTML
// characters must be escaped so they don't break Confluence storage XML.
func TestBuildHistoryTimelineSection_HTMLEscaped(t *testing.T) {
	history := []entities.AnalystHistoryEntry{
		{Status: "fp", Notes: `<script>alert("xss")</script>`, UpdatedAt: "2026-01-01T00:00:00Z"},
	}
	out := buildHistoryTimelineSection(history)
	if strings.Contains(out, "<script>") {
		t.Error("HTML in history entries must be escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("HTML should be entity-escaped in output")
	}
}

// TestPrependFindingProperties_AcceptedUntilShown: when a finding has
// status=accepted and a future acceptedUntil, the property row is rendered
// without an "(expired)" suffix.
func TestPrependFindingProperties_AcceptedUntilShown(t *testing.T) {
	f := &entities.Finding{
		FindingID: "f1",
		Risk:      "medium",
		URL:       "https://example.com/api",
		Analyst: &entities.Analyst{
			Status:        "accepted",
			AcceptedUntil: "2099-12-31T00:00:00Z", // far future
			Notes:         "Risk accepted by security manager",
		},
	}
	ei := &entityIndex{
		findingObs:   map[string]obsRange{},
		findingScans: map[string][]string{},
	}
	out := prependFindingProperties("body", f, ei, "", nil, nil, "", "", "")
	if !strings.Contains(out, "Accepted Until") {
		t.Errorf("accepted finding with future acceptedUntil must show 'Accepted Until' property, got:\n%s", out[:min(500, len(out))])
	}
	if strings.Contains(out, "(expired)") {
		t.Error("future acceptedUntil must not show (expired)")
	}
}

// TestPrependFindingProperties_AcceptedUntilExpiredLabel: when acceptedUntil
// is in the past, the "(expired)" label must appear on the property value.
func TestPrependFindingProperties_AcceptedUntilExpiredLabel(t *testing.T) {
	f := &entities.Finding{
		FindingID: "f1",
		Risk:      "medium",
		URL:       "https://example.com/api",
		Analyst: &entities.Analyst{
			Status:        "accepted",
			AcceptedUntil: "2020-01-01T00:00:00Z", // past
			Notes:         "Risk accepted",
		},
	}
	ei := &entityIndex{
		findingObs:   map[string]obsRange{},
		findingScans: map[string][]string{},
	}
	out := prependFindingProperties("body", f, ei, "", nil, nil, "", "", "")
	if !strings.Contains(out, "Accepted Until") {
		t.Errorf("must show 'Accepted Until' property, got snippet: %q", out[:min(300, len(out))])
	}
	if !strings.Contains(out, "(expired)") {
		t.Errorf("past acceptedUntil must be labelled (expired), got snippet: %q", out[:min(300, len(out))])
	}
}

// TestPrependFindingProperties_AcceptedUntilHiddenWhenNotAccepted: the
// "Accepted Until" property must not appear for non-accepted statuses.
func TestPrependFindingProperties_AcceptedUntilHiddenWhenNotAccepted(t *testing.T) {
	f := &entities.Finding{
		FindingID: "f1",
		Risk:      "medium",
		URL:       "https://example.com/api",
		Analyst: &entities.Analyst{
			Status:        "open",
			AcceptedUntil: "2099-12-31T00:00:00Z",
		},
	}
	ei := &entityIndex{
		findingObs:   map[string]obsRange{},
		findingScans: map[string][]string{},
	}
	out := prependFindingProperties("body", f, ei, "", nil, nil, "", "", "")
	if strings.Contains(out, "Accepted Until") {
		t.Error("'Accepted Until' must not appear for non-accepted findings")
	}
}

// TestPrependFindingProperties_HistorySectionPresent: the expand macro for
// triage history must always be injected on a finding page (even when empty).
func TestPrependFindingProperties_HistorySectionPresent(t *testing.T) {
	f := &entities.Finding{
		FindingID: "f1",
		Risk:      "low",
		URL:       "https://example.com/",
		Analyst:   &entities.Analyst{Status: "open", History: nil},
	}
	ei := &entityIndex{
		findingObs:   map[string]obsRange{},
		findingScans: map[string][]string{},
	}
	out := prependFindingProperties("body", f, ei, "", nil, nil, "", "", "")
	if !strings.Contains(out, `ac:name="expand"`) {
		t.Error("finding page must include the history expand macro")
	}
	if !strings.Contains(out, "No triage history recorded") {
		t.Error("finding with no history must show empty-state message")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
