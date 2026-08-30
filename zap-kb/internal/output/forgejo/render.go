package forgejo

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
)

// maxBodyBytes bounds the assembled issue body. Forgejo/Gitea reject issue
// bodies past a server-side limit (~65535 bytes on some configs); a finding
// with large request/response evidence can approach it. The hidden dedup marker
// is always appended AFTER the cap so it survives truncation — dedup
// correctness must never depend on body length.
const maxBodyBytes = 60000

// finalizeBody trims trailing whitespace from the rendered content, caps it to
// maxBodyBytes, and appends the hidden marker last so it always survives.
func finalizeBody(content, marker string) string {
	content = strings.TrimRight(content, "\n")
	if len(content) > maxBodyBytes {
		content = truncate(content, maxBodyBytes) + "\n\n_(evidence truncated — see the KB wiki for full detail)_"
	}
	return content + "\n\n" + marker + "\n"
}

// Forgejo issue descriptions are plain markdown (rendered natively), so unlike
// the Jira sink there is no ADF document tree to build — just a markdown string.

// findingMarker returns the hidden HTML-comment token embedded in every issue
// body so re-runs can recognize the issue belongs to a given finding without
// relying on a per-finding label. HTML comments don't render in the Forgejo UI.
func findingMarker(findingID string) string {
	return "<!-- devsecopskb-finding:" + strings.TrimSpace(findingID) + " -->"
}

// issueTitle returns a concise issue title for a single finding. It leads with
// the vulnerability class (the definition's rule name) so the Issues board is
// scannable at a glance, and appends the affected URL path for context —
// "Cross-Domain Misconfiguration — /rest/user". When no definition/name is
// available it falls back to the finding's own name, then its ID.
func issueTitle(f entities.Finding, def *entities.Definition) string {
	vuln := ""
	if def != nil {
		vuln = strings.TrimSpace(firstNonEmpty(def.Name, def.Alert))
	}
	name := strings.TrimSpace(f.Name)
	path := pathContext(f)

	var title string
	switch {
	case vuln != "" && path != "":
		title = vuln + " — " + path
	case vuln != "":
		title = vuln
	case name != "":
		title = name
	default:
		title = strings.TrimSpace(f.FindingID)
	}
	title = sanitizeUntrusted(title)
	if len(title) > 255 {
		title = truncate(title, 252)
	}
	return title
}

// pathContext extracts a short URL path (with a "?…" marker when a query string
// is present) from a finding, for use as title context. Falls back to the raw
// URL when it doesn't parse.
func pathContext(f entities.Finding) string {
	u := strings.TrimSpace(f.URL)
	if u == "" {
		return ""
	}
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		p := parsed.Path
		if parsed.RawQuery != "" {
			p += "?…"
		}
		return p
	}
	return u
}

// firstNonEmpty returns the first trimmed-non-empty string, or "".
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// buildIssueBody renders the markdown body for a finding's issue. When occ is
// non-nil its attack/evidence/request/response are rendered as an Evidence
// section so reviewers see raw scanner output in the ticket. When wikiURLBase
// is non-empty a link to the KB wiki definition page is appended. The hidden
// finding marker is appended last for dedup.
//
// The body is machine-owned: the sink may overwrite it on any run to refresh
// evidence/occurrence counts. Analyst commentary belongs in comments/labels.
func buildIssueBody(f entities.Finding, def *entities.Definition, occ *entities.Occurrence, wikiURLBase string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**Risk:** %s  |  **Confidence:** %s  |  **Occurrences:** %d\n\n",
		titleCase(f.Risk), titleCase(f.Confidence), f.Occurrences)

	if u := strings.TrimSpace(f.URL); u != "" {
		fmt.Fprintf(&b, "**URL:** %s\n", sanitizeUntrusted(u))
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		fmt.Fprintf(&b, "**Method:** %s\n", m)
	}
	b.WriteString("\n")

	if def != nil && strings.TrimSpace(def.Description) != "" {
		b.WriteString("## Description\n\n")
		b.WriteString(sanitizeUntrusted(truncate(strings.TrimSpace(def.Description), 1500)))
		b.WriteString("\n\n")
	}

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
		if strings.TrimSpace(wikiURLBase) != "" {
			page := "Definitions/" + obsidian.DefinitionPageName(*def)
			fmt.Fprintf(&b, "**KB reference:** [%s](%s/%s)\n\n", page,
				strings.TrimRight(wikiURLBase, "/"), url.PathEscape(page))
		}
	}

	if occ != nil {
		if ev := evidenceMarkdown(occ); ev != "" {
			b.WriteString("## Evidence\n\n")
			b.WriteString(ev)
			b.WriteString("\n")
		}
	}

	return finalizeBody(b.String(), findingMarker(f.FindingID))
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
			// Only append the name when it adds information: scanner-sourced
			// mappings sometimes set CWEName to the bare ID ("CWE-615"), which
			// would render as "CWE-615: CWE-615".
			if n := strings.TrimSpace(t.CWEName); n != "" && !strings.EqualFold(n, label) {
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
		fmt.Fprintf(&b, "- **Parameter:** %s\n", inlineCode(sanitizeUntrusted(p)))
	}
	if a := strings.TrimSpace(occ.Attack); a != "" {
		fmt.Fprintf(&b, "- **Attack:** %s\n", inlineCode(sanitizeUntrusted(truncate(a, 300))))
	}
	if e := strings.TrimSpace(occ.Evidence); e != "" {
		b.WriteString("\n**Evidence snippet:**\n")
		writeFencedBlock(&b, "", sanitizeUntrusted(truncate(e, 1000)))
	}
	if occ.Request != nil && strings.TrimSpace(occ.Request.RawHeader) != "" {
		b.WriteString("\n**Request:**\n")
		writeFencedBlock(&b, "http", sanitizeUntrusted(truncate(occ.Request.RawHeader, 2000)))
	}
	if occ.Response != nil && strings.TrimSpace(occ.Response.RawHeader) != "" {
		b.WriteString("\n**Response:**\n")
		writeFencedBlock(&b, "http", sanitizeUntrusted(truncate(occ.Response.RawHeader, 2000)))
	}
	return b.String()
}

func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Unknown"
	}
	r, size := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r)) + strings.ToLower(s[size:])
}

// truncate shortens s to at most n bytes without splitting a UTF-8 sequence,
// appending an ellipsis when anything was cut.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// sanitizeUntrusted neutralizes HTML-comment openers in site-controlled text
// so a scanned target can never smuggle a forged dedup marker (or any HTML
// comment) into an issue body. Breaking "<!--" into "<!- -" destroys comment
// syntax while keeping the snippet readable.
func sanitizeUntrusted(s string) string {
	return strings.ReplaceAll(s, "<!--", "<!- -")
}

// writeFencedBlock writes content as a fenced code block whose fence is longer
// than any backtick run inside the content, so site-controlled snippets can
// never terminate the fence early and inject markdown into the issue body
// (CommonMark: a fence only closes on a run at least as long as the opener).
func writeFencedBlock(b *strings.Builder, lang, content string) {
	fenceLen := 3
	run := 0
	for _, r := range content {
		if r == '`' {
			run++
			if run >= fenceLen {
				fenceLen = run + 1
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", fenceLen)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString(lang)
	b.WriteString("\n")
	b.WriteString(content)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString("\n")
}

// inlineCode renders s as inline code, or plain text when s itself contains a
// backtick (which would terminate the span early).
func inlineCode(s string) string {
	if strings.Contains(s, "`") {
		return s
	}
	return "`" + s + "`"
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
