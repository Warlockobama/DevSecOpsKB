package entities

import "testing"

func TestCanonicalAnalystStatus(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "confirm", want: "triaged"},
		{in: "Confirmed", want: "triaged"},
		{in: "false positive", want: "fp"},
		{in: "risk accepted", want: "accepted"},
		{in: "resolved", want: "fixed"},
		{in: "triaged", want: "triaged"},
		{in: "custom-state", want: "custom-state"},
	}
	for _, tc := range tests {
		if got := CanonicalAnalystStatus(tc.in); got != tc.want {
			t.Fatalf("CanonicalAnalystStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeAnalystStatuses(t *testing.T) {
	ef := EntitiesFile{
		Findings:    []Finding{{FindingID: "fin-1", Analyst: &Analyst{Status: "confirm"}}},
		Occurrences: []Occurrence{{OccurrenceID: "occ-1", Analyst: &Analyst{Status: "false positive"}}},
	}
	NormalizeAnalystStatuses(&ef)
	if got := ef.Findings[0].Analyst.Status; got != "triaged" {
		t.Fatalf("finding status = %q, want triaged", got)
	}
	if got := ef.Occurrences[0].Analyst.Status; got != "fp" {
		t.Fatalf("occurrence status = %q, want fp", got)
	}
}
