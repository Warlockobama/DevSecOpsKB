package entities

import (
	"strings"
	"testing"
)

// reopenFixture builds a base+add pair where:
//   - Base has one finding with the given prior status and owner, and one
//     occurrence attached.
//   - Add introduces one NEW occurrence (different OccurrenceID) tied to the
//     same finding — simulating a new scan catching the finding again.
//
// scanLabel is attached to the new occurrence so the auto-reopen history entry
// can reference it. observedAt is the timestamp the merge should treat as
// "recurredAt".
func reopenFixture(priorStatus, owner, scanLabel, observedAt string) (base, add EntitiesFile) {
	base = EntitiesFile{
		SchemaVersion: "v1",
		Findings: []Finding{
			{FindingID: "fin-1", PluginID: "10001", URL: "https://example.com/login", Method: "GET",
				Analyst: &Analyst{Status: priorStatus, Owner: owner, UpdatedAt: "2026-04-01T00:00:00Z"}},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-old", FindingID: "fin-1", DefinitionID: "def-10001",
				URL: "https://example.com/login", ObservedAt: "2026-04-01T00:00:00Z", ScanLabel: "scan-old"},
		},
	}
	add = EntitiesFile{
		SchemaVersion: "v1",
		Findings: []Finding{
			{FindingID: "fin-1", PluginID: "10001", URL: "https://example.com/login", Method: "GET"},
		},
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-new", FindingID: "fin-1", DefinitionID: "def-10001",
				URL: "https://example.com/login", ObservedAt: observedAt, ScanLabel: scanLabel},
		},
	}
	return base, add
}

// TestMerge_ReopensFPOnRecurrence: fp finding with a new occurrence must auto-
// transition to open, stash priorStatus, and append exactly one history entry.
func TestMerge_ReopensFPOnRecurrence(t *testing.T) {
	base, add := reopenFixture("fp", "alice", "scan-2026-04-21", "2026-04-21T10:00:00Z")
	merged := Merge(base, add)
	if len(merged.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(merged.Findings))
	}
	f := merged.Findings[0]
	if f.Analyst == nil {
		t.Fatal("Analyst must remain non-nil after auto-reopen")
	}
	if f.Analyst.Status != "open" {
		t.Errorf("Status: want %q, got %q", "open", f.Analyst.Status)
	}
	if f.Analyst.PriorStatus != "fp" {
		t.Errorf("PriorStatus: want %q, got %q", "fp", f.Analyst.PriorStatus)
	}
	if f.Analyst.UpdatedAt != "2026-04-21T10:00:00Z" {
		t.Errorf("UpdatedAt: want recurredAt, got %q", f.Analyst.UpdatedAt)
	}
	if len(f.Analyst.History) != 1 {
		t.Fatalf("History: want 1 entry, got %d: %+v", len(f.Analyst.History), f.Analyst.History)
	}
	h := f.Analyst.History[0]
	if h.Status != "open" {
		t.Errorf("history.Status: want open, got %q", h.Status)
	}
	if h.PriorStatus != "fp" {
		t.Errorf("history.PriorStatus: want fp, got %q", h.PriorStatus)
	}
	if h.Owner != "alice" {
		t.Errorf("history.Owner: want inherited %q, got %q", "alice", h.Owner)
	}
	if h.ScanLabel != "scan-2026-04-21" {
		t.Errorf("history.ScanLabel: want recurring scan, got %q", h.ScanLabel)
	}
	if !strings.Contains(h.Notes, "auto-reopened") || !strings.Contains(h.Notes, "scan-2026-04-21") {
		t.Errorf("history.Notes should mention auto-reopened and scan label, got %q", h.Notes)
	}
	if h.EntryID == "" {
		t.Error("history.EntryID must be set (determinism depends on it)")
	}
	// Advisory RecurrenceInfo should also be populated.
	if f.Recurrence == nil {
		t.Error("Recurrence advisory must also be set on reopen")
	} else if f.Recurrence.PriorStatus != "fp" {
		t.Errorf("Recurrence.PriorStatus: want fp, got %q", f.Recurrence.PriorStatus)
	}
}

// TestMerge_ReopensFixedOnRecurrence: same but from "fixed".
func TestMerge_ReopensFixedOnRecurrence(t *testing.T) {
	base, add := reopenFixture("fixed", "bob", "scan-fixed-redux", "2026-04-21T11:00:00Z")
	merged := Merge(base, add)
	f := merged.Findings[0]
	if f.Analyst.Status != "open" {
		t.Errorf("Status: want open, got %q", f.Analyst.Status)
	}
	if f.Analyst.PriorStatus != "fixed" {
		t.Errorf("PriorStatus: want fixed, got %q", f.Analyst.PriorStatus)
	}
	if len(f.Analyst.History) != 1 || f.Analyst.History[0].PriorStatus != "fixed" {
		t.Errorf("expected single history entry with priorStatus=fixed, got %+v", f.Analyst.History)
	}
}

// TestMerge_DoesNotReopenAccepted: accepted findings are not auto-reopened.
// Recurrence is still recorded as advisory metadata, but status stays
// "accepted" — analyst (or slice 2's acceptedUntil expiry) owns the decision.
func TestMerge_DoesNotReopenAccepted(t *testing.T) {
	base, add := reopenFixture("accepted", "carol", "scan-accept", "2026-04-21T12:00:00Z")
	merged := Merge(base, add)
	f := merged.Findings[0]
	if f.Analyst.Status != "accepted" {
		t.Errorf("Status: accepted must be preserved, got %q", f.Analyst.Status)
	}
	if f.Analyst.PriorStatus != "" {
		t.Errorf("PriorStatus: must remain empty for accepted, got %q", f.Analyst.PriorStatus)
	}
	if len(f.Analyst.History) != 0 {
		t.Errorf("History must stay empty for accepted, got %+v", f.Analyst.History)
	}
	if f.Recurrence == nil {
		t.Error("Recurrence advisory MUST still be set for accepted")
	}
}

// TestMerge_ReopenIsIdempotent: merging the same add twice produces exactly
// one history entry and the status stays "open". Guards against history bloat
// on re-imports of the same entities file.
func TestMerge_ReopenIsIdempotent(t *testing.T) {
	base, add := reopenFixture("fp", "alice", "scan-id", "2026-04-21T10:00:00Z")
	first := Merge(base, add)
	second := Merge(first, add)
	f := second.Findings[0]
	if f.Analyst.Status != "open" {
		t.Errorf("Status: want open after re-merge, got %q", f.Analyst.Status)
	}
	if len(f.Analyst.History) != 1 {
		t.Errorf("History: want 1 entry after re-merge (idempotent), got %d: %+v",
			len(f.Analyst.History), f.Analyst.History)
	}
}

// TestMerge_NoReopenWhenStatusAlreadyOpen: if the analyst had already moved
// the finding to "open" (or "triaged"), a new occurrence must NOT write
// another auto-reopen entry — we only reopen from terminal dispositions.
func TestMerge_NoReopenWhenStatusAlreadyOpen(t *testing.T) {
	base, add := reopenFixture("open", "alice", "scan-open", "2026-04-21T10:00:00Z")
	merged := Merge(base, add)
	f := merged.Findings[0]
	if len(f.Analyst.History) != 0 {
		t.Errorf("History must stay empty when base was already open, got %+v", f.Analyst.History)
	}
	if f.Recurrence != nil {
		t.Errorf("Recurrence must NOT be set for status=open (not a recurrence), got %+v", f.Recurrence)
	}
}

// TestMerge_ReopenFallsBackToNowWhenObservedAtMissing: if the new occurrence
// has no ObservedAt, reopen still fires and UpdatedAt + history.updatedAt fall
// back to wall-clock now. Verified by checking it's non-empty RFC3339-ish.
func TestMerge_ReopenFallsBackToNowWhenObservedAtMissing(t *testing.T) {
	base, add := reopenFixture("fp", "alice", "scan-no-ts", "")
	merged := Merge(base, add)
	f := merged.Findings[0]
	if f.Analyst.Status != "open" {
		t.Fatalf("expected reopen, got status %q", f.Analyst.Status)
	}
	if f.Analyst.UpdatedAt == "" {
		t.Error("UpdatedAt must fall back to now when ObservedAt missing")
	}
}
