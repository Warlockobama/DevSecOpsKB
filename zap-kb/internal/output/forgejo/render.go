package forgejo

import (
	"fmt"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// Forgejo issue descriptions are plain markdown (rendered natively), so unlike
// the Jira sink there is no ADF document tree to build — just a markdown string.

// findingMarker returns the hidden HTML-comment token embedded in every issue
// body so re-runs can recognize the issue belongs to a given finding without
// relying on a per-finding label. HTML comments don't render in the Forgejo UI.
func findingMarker(findingID string) string {
	return "<!-- devsecopskb-finding:" + strings.TrimSpace(findingID) + " -->"
}

// issueTitle returns a concise issue title for a finding.
func issueTitle(f entities.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = strings.TrimSpace(f.FindingID)
	}
	if len(name) > 255 {
		name = name[:252] + "..."
	}
	return name
}

// buildIssueBody renders the markdown body for a finding's issue. When occ is
// non-nil its attack/evidence/request/response are rendered as an Evidence
// section so reviewers see raw scanner output in the ticket. The hidden finding
// marker is appended last for dedup.
func buildIssueBody(f entities.Finding, def *entities.Definition, occ *entities.Occurrence) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**Risk:** %s  |  **Confidence:** %s  |  **Occurrences:** %d\n\n",
		titleCase(f.Risk), titleCase(f.Confidence), f.Occurrences)

	if u := strings.TrimSpace(f.URL); u != "" {
		fmt.Fprintf(&b, "**URL:** %s\n", u)
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		fmt.Fprintf(&b, "**Method:** %s\n", m)
	}
	b.WriteString("\n")

	if def != nil {
		if def.Remediation != nil && strings.TrimSpace(def.Remediation.Summary) != "" {
			b.WriteString("## Remediation\n\n")
			b.WriteString(strings.TrimSpace(def.Remediation.Summary))
			b.WriteString("\n\n")
		}
		if class := classificationMarkdown(def); class != "" {
			b.WriteString("## Security classification\n\n")
			b.WriteString(class)
			b.WriteString("\n")
		}
	}

	if occ != nil {
		if ev := evidenceMarkdown(occ); ev != "" {
			b.WriteString("## Evidence\n\n")
			b.WriteString(ev)
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(findingMarker(f.FindingID))
	b.WriteString("\n")
	return b.String()
}

// classificationMarkdown renders CVSS / CWE / CAPEC / ATT&CK / OWASP lines.
func classificationMarkdown(def *entities.Definition) string {
	var lines []string
	if def.CVSS != nil {
		if l := cvssLine(def.CVSS); l != "" {
			lines = append(lines, "- **CVSS:** "+l)
		}
	}
	t := def.Taxonomy
	if t != nil {
		if t.CWEID > 0 {
			url := strings.TrimSpace(t.CWEURI)
			if url == "" {
				url = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", t.CWEID)
			}
			label := fmt.Sprintf("CWE-%d", t.CWEID)
			if n := strings.TrimSpace(t.CWEName); n != "" {
				label += ": " + n
			}
			lines = append(lines, fmt.Sprintf("- **CWE:** [%s](%s)", label, url))
		}
		if refs := taxRefsMarkdown(capecRefs(t)); refs != "" {
			lines = append(lines, "- **CAPEC:** "+refs)
		}
		if refs := taxRefsMarkdown(attackRefs(t)); refs != "" {
			lines = append(lines, "- **ATT&CK:** "+refs)
		}
		if vals := trimmedNonEmpty(t.OWASPTop10); len(vals) > 0 {
			lines = append(lines, "- **OWASP Top 10:** "+strings.Join(vals, ", "))
		}
		if mc := strings.TrimSpace(t.MappingConfidence); mc != "" {
			lines = append(lines, "- **Mapping confidence:** "+mc)
		}
	}
	return strings.Join(lines, "\n")
}

func cvssLine(cvss *entities.CVSS) string {
	var parts []string
	severity := strings.TrimSpace(cvss.BaseSeverity)
	if cvss.BaseScore > 0 {
		score := fmt.Sprintf("%.1f", cvss.BaseScore)
		if severity != "" {
			score += " " + severity
		}
		parts = append(parts, score)
	} else if severity != "" {
		parts = append(parts, severity)
	}
	if v := strings.TrimSpace(cvss.Vector); v != "" {
		parts = append(parts, v)
	}
	if s := strings.TrimSpace(cvss.Source); s != "" {
		parts = append(parts, "source: "+s)
	}
	return strings.Join(parts, " | ")
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
		if id = strings.TrimSpace(id); id != "" {
			refs = append(refs, entities.TaxonomyRef{ID: id})
		}
	}
	return refs
}

func taxRefsMarkdown(refs []entities.TaxonomyRef) string {
	var out []string
	for _, ref := range refs {
		id := strings.TrimSpace(ref.ID)
		name := strings.TrimSpace(ref.Name)
		var display string
		switch {
		case id != "" && name != "":
			display = id + ": " + name
		case id != "":
			display = id
		case name != "":
			display = name
		default:
			display = strings.TrimSpace(ref.URL)
		}
		if display == "" {
			continue
		}
		if url := strings.TrimSpace(ref.URL); url != "" {
			out = append(out, fmt.Sprintf("[%s](%s)", display, url))
		} else {
			out = append(out, display)
		}
	}
	return strings.Join(out, ", ")
}

// evidenceMarkdown renders the scanner evidence for an occurrence as fenced
// blocks. Long request/response snippets are passed through verbatim (Forgejo
// wraps in code fences) but bounded to keep issue bodies reasonable.
func evidenceMarkdown(occ *entities.Occurrence) string {
	var b strings.Builder
	if p := strings.TrimSpace(occ.Param); p != "" {
		fmt.Fprintf(&b, "- **Parameter:** `%s`\n", p)
	}
	if a := strings.TrimSpace(occ.Attack); a != "" {
		fmt.Fprintf(&b, "- **Attack:** `%s`\n", truncate(a, 300))
	}
	if e := strings.TrimSpace(occ.Evidence); e != "" {
		b.WriteString("\n**Evidence snippet:**\n\n")
		fmt.Fprintf(&b, "```\n%s\n```\n", truncate(e, 1000))
	}
	if occ.Request != nil && strings.TrimSpace(occ.Request.RawHeader) != "" {
		b.WriteString("\n**Request:**\n\n")
		fmt.Fprintf(&b, "```http\n%s\n```\n", truncate(occ.Request.RawHeader, 2000))
	}
	if occ.Response != nil && strings.TrimSpace(occ.Response.RawHeader) != "" {
		b.WriteString("\n**Response:**\n\n")
		fmt.Fprintf(&b, "```http\n%s\n```\n", truncate(occ.Response.RawHeader, 2000))
	}
	return b.String()
}

func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func trimmedNonEmpty(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}
