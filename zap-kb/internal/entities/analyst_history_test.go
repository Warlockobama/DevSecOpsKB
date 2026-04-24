package entities

import "testing"

// TestNewAnalystHistoryEntry_DeterministicID locks in the dedup contract:
// same scanLabel+status+owner+notes produces the same EntryID, so a re-import
// of an unchanged entities file can never double-append history.
func TestNewAnalystHistoryEntry_DeterministicID(t *testing.T) {
	a := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "routine triage", "2026-04-21T10:00:00Z")
	b := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "routine triage", "2026-04-21T10:00:00Z")
	if a.EntryID == "" || a.EntryID != b.EntryID {
		t.Fatalf("expected identical EntryID, got %q vs %q", a.EntryID, b.EntryID)
	}
}

// TestNewAnalystHistoryEntry_ScanLabelDifferentiates ensures two FP
// confirmations by the same owner across two scans produce distinct entries
// (this was the dev-lead concern: scanLabel MUST be in the hash).
func TestNewAnalystHistoryEntry_ScanLabelDifferentiates(t *testing.T) {
	a := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "same note", "2026-04-21T10:00:00Z")
	b := NewAnalystHistoryEntry("scan-B", "fp", "open", "alice", "same note", "2026-04-21T10:00:00Z")
	if a.EntryID == b.EntryID {
		t.Fatalf("scanLabel must change EntryID, got %q == %q", a.EntryID, b.EntryID)
	}
}

// TestNewAnalystHistoryEntry_NotesDifferentiates ensures that two entries with
// same scan/status/owner but different notes are recorded separately — analyst
// re-triage with new rationale must not be silently dropped.
func TestNewAnalystHistoryEntry_NotesDifferentiates(t *testing.T) {
	a := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "v1 rationale", "2026-04-21T10:00:00Z")
	b := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "v2 rationale", "2026-04-21T10:05:00Z")
	if a.EntryID == b.EntryID {
		t.Fatalf("different notes must produce different EntryID")
	}
}

// TestMergeAnalyst_HistoryUnion verifies that merge deduplicates by EntryID
// and preserves entries only on one side.
func TestMergeAnalyst_HistoryUnion(t *testing.T) {
	shared := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "n1", "2026-04-21T10:00:00Z")
	onlyBase := NewAnalystHistoryEntry("scan-A", "open", "", "alice", "", "2026-04-20T10:00:00Z")
	onlyAdd := NewAnalystHistoryEntry("scan-B", "fp", "open", "alice", "n2", "2026-04-22T10:00:00Z")

	base := &Analyst{Status: "fp", History: []AnalystHistoryEntry{onlyBase, shared}}
	add := &Analyst{Status: "fp", History: []AnalystHistoryEntry{shared, onlyAdd}}

	out := mergeAnalyst(base, add)
	if out == nil {
		t.Fatal("merge returned nil")
	}
	if len(out.History) != 3 {
		t.Fatalf("expected 3 unique entries, got %d: %+v", len(out.History), out.History)
	}
	// base order preserved first
	if out.History[0].EntryID != onlyBase.EntryID || out.History[1].EntryID != shared.EntryID || out.History[2].EntryID != onlyAdd.EntryID {
		t.Errorf("unexpected order: %+v", out.History)
	}
}

// TestMergeAnalyst_HistoryUnion_Idempotent verifies that merging the same
// entities file twice produces the exact same history slice — this is the
// safety net that prevents history bloat across repeated scans.
func TestMergeAnalyst_HistoryUnion_Idempotent(t *testing.T) {
	e := NewAnalystHistoryEntry("scan-A", "fp", "open", "alice", "n1", "2026-04-21T10:00:00Z")
	base := &Analyst{Status: "fp", History: []AnalystHistoryEntry{e}}
	m1 := mergeAnalyst(base, base)
	m2 := mergeAnalyst(m1, base)
	if len(m1.History) != 1 || len(m2.History) != 1 {
		t.Fatalf("expected stable len=1, got m1=%d m2=%d", len(m1.History), len(m2.History))
	}
}

// TestMergeAnalyst_PriorStatusAndAcceptedUntil verifies the new scalar fields
// follow base-wins-fallback-to-add semantics consistent with Status/Owner.
func TestMergeAnalyst_PriorStatusAndAcceptedUntil(t *testing.T) {
	base := &Analyst{PriorStatus: "fp"}
	add := &Analyst{PriorStatus: "open", AcceptedUntil: "2026-12-31T00:00:00Z"}
	out := mergeAnalyst(base, add)
	if out.PriorStatus != "fp" {
		t.Errorf("PriorStatus: want base to win (%q), got %q", "fp", out.PriorStatus)
	}
	if out.AcceptedUntil != "2026-12-31T00:00:00Z" {
		t.Errorf("AcceptedUntil: want add fallback, got %q", out.AcceptedUntil)
	}
}

// TestUnionHistory_SkipsEmptyEntryID guards against bad callers that build
// AnalystHistoryEntry structs without going through NewAnalystHistoryEntry.
// Entries without an EntryID would break dedup, so we drop them.
func TestUnionHistory_SkipsEmptyEntryID(t *testing.T) {
	valid := NewAnalystHistoryEntry("scan-A", "fp", "", "", "", "")
	bad := AnalystHistoryEntry{Status: "open"} // no EntryID
	out := unionHistory([]AnalystHistoryEntry{bad, valid}, nil)
	if len(out) != 1 || out[0].EntryID != valid.EntryID {
		t.Errorf("expected bad entry dropped, got %+v", out)
	}
}
