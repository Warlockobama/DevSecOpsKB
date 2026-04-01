package jira

import (
	"fmt"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// Minimal Atlassian Document Format (ADF) types for description fields.
// Only the node types needed to render a structured issue description.

type adfDoc struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	Content []any  `json:"content"`
}

type adfParagraph struct {
	Type    string `json:"type"`
	Content []any  `json:"content"`
}

type adfText struct {
	Type  string    `json:"type"`
	Text  string    `json:"text"`
	Marks []adfMark `json:"marks,omitempty"`
}

type adfMark struct {
	Type  string       `json:"type"`
	Attrs adfLinkAttrs `json:"attrs"`
}

type adfLinkAttrs struct {
	Href string `json:"href"`
}

type adfHardBreak struct {
	Type string `json:"type"`
}

func para(nodes ...any) adfParagraph {
	return adfParagraph{Type: "paragraph", Content: nodes}
}

func textNode(s string) adfText {
	return adfText{Type: "text", Text: s}
}

func linkNode(label, href string) adfText {
	return adfText{
		Type: "text",
		Text: label,
		Marks: []adfMark{
			{Type: "link", Attrs: adfLinkAttrs{Href: href}},
		},
	}
}

func br() adfHardBreak { return adfHardBreak{Type: "hardBreak"} }

// buildDescription builds an ADF document describing a Finding for a Jira issue.
func buildDescription(f entities.Finding, def *entities.Definition) adfDoc {
	var paragraphs []any

	// Risk / confidence / occurrences line
	paragraphs = append(paragraphs, para(
		textNode(fmt.Sprintf("Risk: %s  |  Confidence: %s  |  Occurrences: %d",
			titleCase(f.Risk), titleCase(f.Confidence), f.Occurrences)),
	))

	// URL + method
	paragraphs = append(paragraphs, para(
		textNode("URL: "),
		linkNode(f.URL, f.URL),
		br(),
		textNode("Method: "+f.Method),
	))

	// Definition details (if available)
	if def != nil {
		// Remediation summary
		if def.Remediation != nil && strings.TrimSpace(def.Remediation.Summary) != "" {
			paragraphs = append(paragraphs, para(
				textNode("Remediation: "+strings.TrimSpace(def.Remediation.Summary)),
			))
		}

		// CWE link
		if def.Taxonomy != nil && def.Taxonomy.CWEID > 0 {
			cweURL := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", def.Taxonomy.CWEID)
			paragraphs = append(paragraphs, para(
				textNode("CWE: "),
				linkNode(fmt.Sprintf("CWE-%d", def.Taxonomy.CWEID), cweURL),
			))
		}

		// ZAP docs link
		if def.Detection != nil && strings.TrimSpace(def.Detection.DocsURL) != "" {
			paragraphs = append(paragraphs, para(
				textNode("ZAP docs: "),
				linkNode(def.Detection.DocsURL, def.Detection.DocsURL),
			))
		}
	}

	return adfDoc{Version: 1, Type: "doc", Content: paragraphs}
}

func titleCase(s string) string {
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
