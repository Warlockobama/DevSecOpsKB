package jira

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestDefinitionLabel(t *testing.T) {
	got := definitionLabel("def-abc123")
	if got != "zap-definition-def-abc123" {
		t.Errorf("got %q, want %q", got, "zap-definition-def-abc123")
	}
}

func TestEpicSummary_PrefersAlertOverName(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-1", PluginID: "10020", Alert: "X-Frame-Options Header Not Set", Name: "XFO"}
	got := epicSummary(def)
	want := "[ZAP] X-Frame-Options Header Not Set (Plugin 10020)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEpicSummary_FallsBackToDefinitionID(t *testing.T) {
	def := &entities.Definition{DefinitionID: "def-xyz"}
	got := epicSummary(def)
	if got != "[ZAP] def-xyz" {
		t.Errorf("got %q", got)
	}
}

func TestEpicSummary_Truncates(t *testing.T) {
	long := strings.Repeat("X", 300)
	def := &entities.Definition{Alert: long, PluginID: "1"}
	got := epicSummary(def)
	if len(got) != 255 {
		t.Errorf("expected 255 chars, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected trailing ellipsis, got suffix %q", got[len(got)-5:])
	}
}

func TestBuildEpicDescription_ContainsKeyParts(t *testing.T) {
	def := &entities.Definition{
		DefinitionID: "def-10020",
		PluginID:     "10020",
		Alert:        "X-Frame-Options Header Not Set",
		Description:  "Missing header allows clickjacking.",
		Taxonomy:     &entities.Taxonomy{CWEID: 1021},
		Remediation:  &entities.Remediation{Summary: "Set X-Frame-Options: DENY."},
		Detection:    &entities.Detection{DocsURL: "https://www.zaproxy.org/docs/alerts/10020/"},
	}
	doc := buildEpicDescription(def)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		"Missing header allows clickjacking.",
		"CWE-1021",
		"cwe.mitre.org/data/definitions/1021",
		"zaproxy.org/docs/alerts/10020",
		"Set X-Frame-Options: DENY.",
		"Child issues",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in description JSON", want)
		}
	}
}

func TestBuildEpicDescription_NilDefinition(t *testing.T) {
	doc := buildEpicDescription(nil)
	if doc.Type != "doc" || doc.Version != 1 {
		t.Errorf("expected empty doc scaffold, got %+v", doc)
	}
}
