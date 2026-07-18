package jira

import (
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestRenderWikiDoc_FindingDescription(t *testing.T) {
	f := entities.Finding{
		FindingID:  "fin-1",
		Name:       "SQL Injection",
		Risk:       "high",
		Confidence: "medium",
		URL:        "https://example.com/login",
		Method:     "POST",
	}
	def := &entities.Definition{
		DefinitionID: "def-1",
		Remediation:  &entities.Remediation{Summary: "Use parameterized queries."},
		Taxonomy: &entities.Taxonomy{
			CWEID:   89,
			CWEName: "SQL Injection",
		},
	}
	occ := &entities.Occurrence{
		OccurrenceID: "occ-1",
		FindingID:    "fin-1",
		URL:          "https://example.com/login",
		Method:       "POST",
		Attack:       "' OR 1=1--",
		Evidence:     "You have an error in your SQL syntax",
	}

	got := renderWikiDoc(buildDescription(f, def, occ))

	for _, want := range []string{
		"Risk: High  |  Confidence: Medium",
		"URL: [https://example.com/login|https://example.com/login]",
		"Method: POST",
		"Remediation: Use parameterized queries.",
		"CWE: [CWE-89: SQL Injection|https://cwe.mitre.org/data/definitions/89.html]",
		"h2. Evidence",
		"Attack: ' OR 1=1--",
		"{code}\nYou have an error in your SQL syntax\n{code}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("wiki output missing %q\n---\n%s", want, got)
		}
	}
}

func TestRenderWikiDoc_CodeBlockLanguageAndNeutralization(t *testing.T) {
	doc := adfDoc{Version: 1, Type: "doc", Content: []any{
		heading(3, "Request"),
		codeBlock("http", "GET /x HTTP/1.1\nEvil: {code}alert(1){code}"),
	}}
	got := renderWikiDoc(doc)
	if !strings.Contains(got, "h3. Request") {
		t.Errorf("missing heading: %q", got)
	}
	if !strings.Contains(got, "{code:http}") {
		t.Errorf("missing language-tagged code fence: %q", got)
	}
	// Scanner-controlled {code} inside the body must not close the block.
	if strings.Count(got, "{code:http}")+strings.Count(got, "\n{code}") != 2 {
		t.Errorf("embedded {code} not neutralized: %q", got)
	}
	if !strings.Contains(got, "{ code}alert(1)") {
		t.Errorf("expected neutralized macro, got: %q", got)
	}
}

func TestRenderWikiDoc_HardBreak(t *testing.T) {
	doc := adfDoc{Version: 1, Type: "doc", Content: []any{
		para(textNode("line one"), br(), textNode("line two")),
	}}
	got := renderWikiDoc(doc)
	if got != "line one\nline two" {
		t.Errorf("hard break render = %q", got)
	}
}
