package jira

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestBuildDescription_BasicFinding(t *testing.T) {
	f := entities.Finding{
		FindingID:   "fin-abc",
		URL:         "https://example.com/login",
		Method:      "GET",
		Risk:        "high",
		Confidence:  "medium",
		Occurrences: 3,
	}
	doc := buildDescription(f, nil, nil)
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
		Taxonomy: &entities.Taxonomy{
			CWEID:   79,
			CWEName: "Improper Neutralization of Input During Web Page Generation",
			CAPEC: []entities.TaxonomyRef{
				{ID: "CAPEC-86", Name: "Cross-site Scripting", URL: "https://capec.mitre.org/data/definitions/86.html"},
			},
			ATTACKTechniques: []entities.TaxonomyRef{
				{ID: "T1190", Name: "Exploit Public-Facing Application", URL: "https://attack.mitre.org/techniques/T1190/"},
			},
			OWASPTop10:        []string{"A03:2021"},
			MappingConfidence: "curated",
		},
		CVSS: &entities.CVSS{
			Version:      "3.1",
			Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			BaseScore:    6.1,
			BaseSeverity: "MEDIUM",
			Source:       "devsecopskb-estimated",
		},
		Remediation: &entities.Remediation{
			Summary: "Encode all user input before rendering.",
		},
		Detection: &entities.Detection{
			DocsURL: "https://www.zaproxy.org/docs/alerts/10016/",
		},
	}
	doc := buildDescription(f, def, nil)
	data, _ := json.Marshal(doc)
	s := string(data)

	for _, want := range []string{
		"CWE-79",
		"Improper Neutralization",
		"cwe.mitre.org",
		"CVSS:3.1",
		"6.1 MEDIUM",
		"CAPEC-86",
		"Cross-site Scripting",
		"T1190",
		"Exploit Public-Facing Application",
		"A03:2021",
		"curated",
		"Encode all user input",
		"zaproxy.org/docs/alerts/10016",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in ADF JSON", want)
		}
	}
}

func TestBuildDescription_WithEvidence(t *testing.T) {
	f := entities.Finding{
		FindingID: "fin-evidence",
		URL:       "https://example.com/api",
		Method:    "GET",
		Risk:      "medium",
	}
	occ := &entities.Occurrence{
		OccurrenceID: "occ-1",
		URL:          "https://example.com/api",
		Method:       "GET",
		Attack:       "X-Forwarded-For: 127.0.0.1",
		Evidence:     "Content-Security-Policy: default-src 'self'",
		Request: &entities.HTTPRequest{
			Headers: []entities.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "User-Agent", Value: "zap/2.14"},
			},
		},
		Response: &entities.HTTPResponse{
			StatusCode: 200,
			Headers: []entities.Header{
				{Name: "Content-Type", Value: "text/html"},
			},
			BodySnippet: "<html>...</html>",
		},
	}
	doc := buildDescription(f, nil, occ)
	data, _ := json.Marshal(doc)
	s := string(data)

	for _, want := range []string{
		`"type":"heading"`,
		"Evidence",
		`"type":"codeBlock"`,
		"X-Forwarded-For",
		"Content-Security-Policy",
		"HTTP/1.1 200",
		"Content-Type",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in ADF JSON\n%s", want, s)
		}
	}
}

func TestBuildDescription_OccurrenceWithoutEvidenceFieldsOmitsSection(t *testing.T) {
	f := entities.Finding{FindingID: "fin-x", URL: "https://x", Method: "GET", Risk: "low"}
	occ := &entities.Occurrence{OccurrenceID: "occ-empty"}
	doc := buildDescription(f, nil, occ)
	data, _ := json.Marshal(doc)
	if strings.Contains(string(data), "Evidence") {
		t.Errorf("expected no Evidence section for empty occurrence, got: %s", data)
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
