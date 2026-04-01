package jira

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestBuildDescription_BasicFinding(t *testing.T) {
	f := entities.Finding{
		FindingID:  "fin-abc",
		URL:        "https://example.com/login",
		Method:     "GET",
		Risk:       "high",
		Confidence: "medium",
		Occurrences: 3,
	}
	doc := buildDescription(f, nil)
	if doc.Version != 1 {
		t.Errorf("expected version 1, got %d", doc.Version)
	}
	if doc.Type != "doc" {
		t.Errorf("expected type doc, got %s", doc.Type)
	}
	if len(doc.Content) == 0 {
		t.Error("expected content paragraphs")
	}

	// Marshal to JSON and check key strings are present
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	s := string(data)
	for _, want := range []string{"High", "Medium", "Occurrences: 3", "https://example.com/login", "GET"} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in ADF JSON, got: %s", want, s)
		}
	}
}

func TestBuildDescription_WithDefinition(t *testing.T) {
	f := entities.Finding{
		FindingID: "fin-xyz",
		URL:       "https://example.com/api",
		Method:    "POST",
		Risk:      "medium",
	}
	def := &entities.Definition{
		Taxonomy: &entities.Taxonomy{CWEID: 79},
		Remediation: &entities.Remediation{
			Summary: "Encode all user input before rendering.",
		},
		Detection: &entities.Detection{
			DocsURL: "https://www.zaproxy.org/docs/alerts/10016/",
		},
	}
	doc := buildDescription(f, def)
	data, _ := json.Marshal(doc)
	s := string(data)

	for _, want := range []string{
		"CWE-79",
		"cwe.mitre.org",
		"Encode all user input",
		"zaproxy.org/docs/alerts/10016",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in ADF JSON", want)
		}
	}
}

func TestTitleCase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"high", "High"},
		{"MEDIUM", "Medium"},
		{"", "Unknown"},
		{"low", "Low"},
	}
	for _, c := range cases {
		if got := titleCase(c.in); got != c.want {
			t.Errorf("titleCase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
