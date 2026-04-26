package main

import (
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func mustParseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func acceptedFinding(id, acceptedUntil string) entities.Finding {
	a := &entities.Analyst{Status: "accepted", AcceptedUntil: acceptedUntil}
	return entities.Finding{FindingID: id, Risk: "medium", Analyst: a}
}

func TestBuildExpiredRows_Empty(t *testing.T) {
	ef := entities.EntitiesFile{}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, indef := buildExpiredRows(ef, now)
	if len(rows) != 0 {
		t.Errorf("want 0 rows, got %d", len(rows))
	}
	if len(indef) != 0 {
		t.Errorf("want 0 indefinite, got %d", len(indef))
	}
}

func TestBuildExpiredRows_ExpiredFindingIncluded(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			acceptedFinding("f1", "2026-01-01T00:00:00Z"), // 113 days before now
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, indef := buildExpiredRows(ef, now)
	if len(rows) != 1 {
		t.Fatalf("want 1 expired row, got %d", len(rows))
	}
	if rows[0].FindingID != "f1" {
		t.Errorf("FindingID: want f1, got %s", rows[0].FindingID)
	}
	if rows[0].ExpiredAgo == "" {
		t.Error("ExpiredAgo should be non-empty")
	}
	if len(indef) != 0 {
		t.Errorf("want 0 indefinite, got %d", len(indef))
	}
}

func TestBuildExpiredRows_NotYetExpiredExcluded(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			acceptedFinding("f1", "2026-12-31T00:00:00Z"), // future
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, _ := buildExpiredRows(ef, now)
	if len(rows) != 0 {
		t.Errorf("non-expired finding must not appear, got %d rows", len(rows))
	}
}

func TestBuildExpiredRows_NoAcceptedUntilGoesToIndefinite(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			acceptedFinding("f1", ""), // no expiry
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, indef := buildExpiredRows(ef, now)
	if len(rows) != 0 {
		t.Errorf("indefinite acceptance must not appear in expired list, got %d rows", len(rows))
	}
	if len(indef) != 1 || indef[0] != "f1" {
		t.Errorf("want [f1] indefinite, got %v", indef)
	}
}

func TestBuildExpiredRows_NonAcceptedIgnored(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			{FindingID: "f1", Analyst: &entities.Analyst{Status: "open", AcceptedUntil: "2020-01-01T00:00:00Z"}},
			{FindingID: "f2", Analyst: &entities.Analyst{Status: "fp", AcceptedUntil: "2020-01-01T00:00:00Z"}},
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, indef := buildExpiredRows(ef, now)
	if len(rows) != 0 || len(indef) != 0 {
		t.Errorf("non-accepted findings must be ignored: rows=%d indef=%d", len(rows), len(indef))
	}
}

func TestBuildExpiredRows_SortedMostOverdueFirst(t *testing.T) {
	ef := entities.EntitiesFile{
		Findings: []entities.Finding{
			acceptedFinding("f-recent", "2026-04-01T00:00:00Z"), // 23 days ago
			acceptedFinding("f-oldest", "2025-01-01T00:00:00Z"), // 1+ year ago
			acceptedFinding("f-middle", "2026-02-01T00:00:00Z"), // ~82 days ago
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, _ := buildExpiredRows(ef, now)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0].FindingID != "f-oldest" {
		t.Errorf("first row should be most overdue (f-oldest), got %s", rows[0].FindingID)
	}
	if rows[2].FindingID != "f-recent" {
		t.Errorf("last row should be least overdue (f-recent), got %s", rows[2].FindingID)
	}
}

func TestBuildExpiredRows_RuleTitleFromDefinition(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{
			{DefinitionID: "def-1", Alert: "SQL Injection"},
		},
		Findings: []entities.Finding{
			{FindingID: "f1", DefinitionID: "def-1",
				Analyst: &entities.Analyst{Status: "accepted", AcceptedUntil: "2020-01-01T00:00:00Z"}},
		},
	}
	now := mustParseRFC3339("2026-04-24T00:00:00Z")
	rows, _ := buildExpiredRows(ef, now)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].RuleTitle != "SQL Injection" {
		t.Errorf("RuleTitle: want SQL Injection, got %q", rows[0].RuleTitle)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{2 * time.Hour, "2h"},
		{25 * time.Hour, "1d"},
		{32 * 24 * time.Hour, "1mo"},
		{400 * 24 * time.Hour, "1y"},
	}
	for _, tc := range cases {
		got := humanDuration(tc.d)
		if got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
