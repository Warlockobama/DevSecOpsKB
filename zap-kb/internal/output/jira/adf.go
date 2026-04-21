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

type adfHeading struct {
	Type    string         `json:"type"`
	Attrs   adfHeadingAttr `json:"attrs"`
	Content []any          `json:"content"`
}

type adfHeadingAttr struct {
	Level int `json:"level"`
}

type adfCodeBlock struct {
	Type    string           `json:"type"`
	Attrs   adfCodeBlockAttr `json:"attrs,omitempty"`
	Content []any            `json:"content"`
}

type adfCodeBlockAttr struct {
	Language string `json:"language,omitempty"`
}

func para(nodes ...any) adfParagraph {
	return adfParagraph{Type: "paragraph", Content: nodes}
}

func heading(level int, text string) adfHeading {
	return adfHeading{
		Type:    "heading",
		Attrs:   adfHeadingAttr{Level: level},
		Content: []any{textNode(text)},
	}
}

func codeBlock(language, body string) adfCodeBlock {
	return adfCodeBlock{
		Type:    "codeBlock",
		Attrs:   adfCodeBlockAttr{Language: language},
		Content: []any{textNode(body)},
	}
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
// When occ is non-nil it is rendered as an Evidence section (attack string,
// evidence snippet, request, response) so reviewers see the raw scanner output
// without leaving the ticket.
func buildDescription(f entities.Finding, def *entities.Definition, occ *entities.Occurrence) adfDoc {
	var nodes []any

	// Risk / confidence / occurrences line
	nodes = append(nodes, para(
		textNode(fmt.Sprintf("Risk: %s  |  Confidence: %s  |  Occurrences: %d",
			titleCase(f.Risk), titleCase(f.Confidence), f.Occurrences)),
	))

	// URL + method
	nodes = append(nodes, para(
		textNode("URL: "),
		linkNode(f.URL, f.URL),
		br(),
		textNode("Method: "+f.Method),
	))

	// Definition details (if available)
	if def != nil {
		// Remediation summary
		if def.Remediation != nil && strings.TrimSpace(def.Remediation.Summary) != "" {
			nodes = append(nodes, para(
				textNode("Remediation: "+strings.TrimSpace(def.Remediation.Summary)),
			))
		}

		// CWE link
		if def.Taxonomy != nil && def.Taxonomy.CWEID > 0 {
			cweURL := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", def.Taxonomy.CWEID)
			nodes = append(nodes, para(
				textNode("CWE: "),
				linkNode(fmt.Sprintf("CWE-%d", def.Taxonomy.CWEID), cweURL),
			))
		}

		// ZAP docs link
		if def.Detection != nil && strings.TrimSpace(def.Detection.DocsURL) != "" {
			nodes = append(nodes, para(
				textNode("ZAP docs: "),
				linkNode(def.Detection.DocsURL, def.Detection.DocsURL),
			))
		}
	}

	// Evidence section — raw scanner output from the most recent occurrence so
	// reviewers don't have to bounce to Confluence to see what proved the finding.
	if occ != nil {
		nodes = append(nodes, buildEvidenceNodes(occ)...)
	}

	return adfDoc{Version: 1, Type: "doc", Content: nodes}
}

// buildEvidenceNodes renders attack/evidence/request/response as ADF nodes.
// Bodies are truncated to avoid overflowing Jira's description field.
const (
	evidenceSnippetMax = 1000
	httpBlockMax       = 2000
)

func buildEvidenceNodes(o *entities.Occurrence) []any {
	if o == nil {
		return nil
	}
	var nodes []any
	hasContent := strings.TrimSpace(o.Attack) != "" ||
		strings.TrimSpace(o.Evidence) != "" ||
		o.Request != nil || o.Response != nil
	if !hasContent {
		return nil
	}
	nodes = append(nodes, heading(2, "Evidence"))
	if s := strings.TrimSpace(o.Attack); s != "" {
		nodes = append(nodes, para(textNode("Attack: "), textNode(s)))
	}
	if s := strings.TrimSpace(o.Evidence); s != "" {
		nodes = append(nodes, codeBlock("", truncateEvidence(s, evidenceSnippetMax)))
	}
	if o.Request != nil {
		if body := renderHTTPRequest(o); body != "" {
			nodes = append(nodes, heading(3, "Request"))
			nodes = append(nodes, codeBlock("http", truncateEvidence(body, httpBlockMax)))
		}
	}
	if o.Response != nil {
		if body := renderHTTPResponse(o.Response); body != "" {
			nodes = append(nodes, heading(3, "Response"))
			nodes = append(nodes, codeBlock("http", truncateEvidence(body, httpBlockMax)))
		}
	}
	return nodes
}

func renderHTTPRequest(o *entities.Occurrence) string {
	if o == nil || o.Request == nil {
		return ""
	}
	r := o.Request
	if raw := strings.TrimSpace(r.RawHeader); raw != "" {
		if strings.TrimSpace(r.BodySnippet) != "" {
			return raw + "\n\n" + strings.TrimSpace(r.BodySnippet)
		}
		return raw
	}
	var b strings.Builder
	method := strings.TrimSpace(o.Method)
	if method == "" {
		method = "GET"
	}
	fmt.Fprintf(&b, "%s %s\n", method, o.URL)
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	if s := strings.TrimSpace(r.BodySnippet); s != "" {
		b.WriteString("\n")
		b.WriteString(s)
	}
	return strings.TrimSpace(b.String())
}

func renderHTTPResponse(r *entities.HTTPResponse) string {
	if r == nil {
		return ""
	}
	if raw := strings.TrimSpace(r.RawHeader); raw != "" {
		if strings.TrimSpace(r.BodySnippet) != "" {
			return raw + "\n\n" + strings.TrimSpace(r.BodySnippet)
		}
		return raw
	}
	var b strings.Builder
	if r.StatusCode > 0 {
		fmt.Fprintf(&b, "HTTP/1.1 %d\n", r.StatusCode)
	}
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	if s := strings.TrimSpace(r.BodySnippet); s != "" {
		b.WriteString("\n")
		b.WriteString(s)
	}
	return strings.TrimSpace(b.String())
}

func truncateEvidence(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n… [truncated]"
}

func titleCase(s string) string {
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
