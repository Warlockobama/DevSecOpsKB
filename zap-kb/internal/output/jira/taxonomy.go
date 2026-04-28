package jira

import (
	"fmt"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func buildSecurityClassificationNodes(def *entities.Definition) []any {
	if def == nil {
		return nil
	}
	var nodes []any
	if def.CVSS != nil {
		if line := cvssLine(def.CVSS); line != "" {
			nodes = append(nodes, para(textNode("CVSS: "+line)))
		}
	}
	if def.Taxonomy == nil {
		return nodes
	}
	t := def.Taxonomy
	if t.CWEID > 0 {
		url := strings.TrimSpace(t.CWEURI)
		if url == "" {
			url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", t.CWEID)
		}
		nodes = append(nodes, para(
			textNode("CWE: "),
			linkNode(cweLabel(t), url),
		))
	}
	if refs := capecRefs(t); len(refs) > 0 {
		nodes = append(nodes, taxonomyRefParagraph("CAPEC", refs))
	}
	if refs := attackRefs(t); len(refs) > 0 {
		nodes = append(nodes, taxonomyRefParagraph("ATT&CK", refs))
	}
	if vals := trimmed(t.OWASPTop10); len(vals) > 0 {
		nodes = append(nodes, para(textNode("OWASP Top 10: "+strings.Join(vals, ", "))))
	}
	if confidence := strings.TrimSpace(t.MappingConfidence); confidence != "" {
		nodes = append(nodes, para(textNode("Mapping confidence: "+confidence)))
	}
	return nodes
}

func cvssLine(cvss *entities.CVSS) string {
	if cvss == nil {
		return ""
	}
	parts := []string{}
	if cvss.BaseScore > 0 || strings.TrimSpace(cvss.BaseSeverity) != "" {
		score := fmt.Sprintf("%.1f", cvss.BaseScore)
		if strings.TrimSpace(cvss.BaseSeverity) != "" {
			score += " " + strings.TrimSpace(cvss.BaseSeverity)
		}
		parts = append(parts, score)
	}
	if strings.TrimSpace(cvss.Vector) != "" {
		parts = append(parts, strings.TrimSpace(cvss.Vector))
	}
	if strings.TrimSpace(cvss.Source) != "" {
		parts = append(parts, "source: "+strings.TrimSpace(cvss.Source))
	}
	return strings.Join(parts, " | ")
}

func cweLabel(t *entities.Taxonomy) string {
	label := fmt.Sprintf("CWE-%d", t.CWEID)
	if strings.TrimSpace(t.CWEName) != "" {
		label += ": " + strings.TrimSpace(t.CWEName)
	}
	return label
}

func capecRefs(t *entities.Taxonomy) []entities.TaxonomyRef {
	if len(t.CAPEC) > 0 {
		return t.CAPEC
	}
	refs := make([]entities.TaxonomyRef, 0, len(t.CAPECIDs))
	for _, id := range t.CAPECIDs {
		if id <= 0 {
			continue
		}
		refs = append(refs, entities.TaxonomyRef{
			ID:  fmt.Sprintf("CAPEC-%d", id),
			URL: fmt.Sprintf("https://capec.mitre.org/data/definitions/%d.html", id),
		})
	}
	return refs
}

func attackRefs(t *entities.Taxonomy) []entities.TaxonomyRef {
	if len(t.ATTACKTechniques) > 0 {
		return t.ATTACKTechniques
	}
	refs := make([]entities.TaxonomyRef, 0, len(t.ATTACK))
	for _, id := range t.ATTACK {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		refs = append(refs, entities.TaxonomyRef{ID: id})
	}
	return refs
}

func taxonomyRefParagraph(label string, refs []entities.TaxonomyRef) adfParagraph {
	nodes := []any{textNode(label + ": ")}
	wrote := false
	for _, ref := range refs {
		display := taxonomyRefLabel(ref)
		if display == "" {
			continue
		}
		if wrote {
			nodes = append(nodes, textNode(", "))
		}
		if url := strings.TrimSpace(ref.URL); url != "" {
			nodes = append(nodes, linkNode(display, url))
		} else {
			nodes = append(nodes, textNode(display))
		}
		wrote = true
	}
	return para(nodes...)
}

func taxonomyRefLabel(ref entities.TaxonomyRef) string {
	id := strings.TrimSpace(ref.ID)
	name := strings.TrimSpace(ref.Name)
	switch {
	case id != "" && name != "":
		return id + ": " + name
	case id != "":
		return id
	case name != "":
		return name
	default:
		return strings.TrimSpace(ref.URL)
	}
}

func trimmed(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, val := range vals {
		if s := strings.TrimSpace(val); s != "" {
			out = append(out, s)
		}
	}
	return out
}
