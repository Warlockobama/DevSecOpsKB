package forgejo

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// defGroupPrefix namespaces the dedup marker key for a definition-group issue so
// it can never collide with a per-finding key. The key rides through the same
// hidden body marker as a finding ID, so the dedup index, reconcile, and
// status-pull machinery treat a group as just another keyed issue.
const defGroupPrefix = "defgroup:"

// maxEndpointRows bounds the "Affected endpoints" table in a grouped issue body
// so a rule matched on hundreds of URLs stays readable (and within maxBodyBytes).
const maxEndpointRows = 50

// issueUnit is the publishing unit: either a single finding (per-finding mode)
// or every candidate finding sharing a definition (group-by-definition mode).
// The dedup key, title, risk label, and body all derive from the unit, so the
// Export loop is identical for both modes.
type issueUnit struct {
	key      string               // dedup marker key (findingID or "defgroup:"+definitionID)
	title    string               // issue title
	risk     string               // drives the risk/<level> label (max risk in a group)
	def      *entities.Definition // shared definition (may be nil)
	occ      *entities.Occurrence // representative occurrence for the Evidence section
	findings []entities.Finding   // 1 (per-finding) or N (grouped)
	grouped  bool
}

// buildUnits turns export candidates into issue units. In per-finding mode each
// candidate is its own unit. In group-by-definition mode all candidates sharing
// a definition collapse into one unit titled by the rule, with every affected
// endpoint listed in the body — this is the fix for scan types (static-asset
// probes, header checks) that otherwise flood the board with one near-identical
// issue per URL.
func buildUnits(candidates []entities.Finding, defByID map[string]*entities.Definition, latestOcc map[string]*entities.Occurrence, group bool) []issueUnit {
	if !group {
		units := make([]issueUnit, 0, len(candidates))
		for _, f := range candidates {
			def := defByID[f.DefinitionID]
			units = append(units, issueUnit{
				key:      f.FindingID,
				title:    issueTitle(f, def),
				risk:     f.Risk,
				def:      def,
				occ:      latestOcc[f.FindingID],
				findings: []entities.Finding{f},
			})
		}
		return units
	}

	// Group candidates by definition, preserving first-seen order for stable
	// creation/ticket-ref ordering across runs.
	order := make([]string, 0)
	byDef := make(map[string][]entities.Finding)
	for _, f := range candidates {
		if _, ok := byDef[f.DefinitionID]; !ok {
			order = append(order, f.DefinitionID)
		}
		byDef[f.DefinitionID] = append(byDef[f.DefinitionID], f)
	}

	units := make([]issueUnit, 0, len(order))
	for _, did := range order {
		fs := byDef[did]
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].URL != fs[j].URL {
				return fs[i].URL < fs[j].URL
			}
			return fs[i].FindingID < fs[j].FindingID
		})
		def := defByID[did]
		units = append(units, issueUnit{
			key:      defGroupPrefix + did,
			title:    groupTitle(def, fs),
			risk:     maxRisk(fs),
			def:      def,
			occ:      groupOccurrence(fs, latestOcc),
			findings: fs,
			grouped:  true,
		})
	}
	return units
}

// maxRisk returns the highest risk label among the findings.
func maxRisk(fs []entities.Finding) string {
	best := ""
	bestRank := -1
	for _, f := range fs {
		if r := synccore.SeverityFloor(f.Risk); r > bestRank {
			bestRank = r
			best = f.Risk
		}
	}
	return best
}

// groupOccurrence picks the newest occurrence across all of a group's findings
// to show as representative evidence.
func groupOccurrence(fs []entities.Finding, latestOcc map[string]*entities.Occurrence) *entities.Occurrence {
	var best *entities.Occurrence
	for _, f := range fs {
		if o := latestOcc[f.FindingID]; o != nil && occurrenceIsNewer(o, best) {
			best = o
		}
	}
	return best
}

// totalOccurrences sums the per-finding occurrence counts in a group.
func totalOccurrences(fs []entities.Finding) int {
	n := 0
	for _, f := range fs {
		if f.Occurrences > 0 {
			n += f.Occurrences
		}
	}
	return n
}

// groupTitle names a definition-group issue by its rule and scale, e.g.
// "Cross-Domain Misconfiguration — 138 occurrences".
func groupTitle(def *entities.Definition, fs []entities.Finding) string {
	vuln := ""
	if def != nil {
		vuln = firstNonEmpty(def.Name, def.Alert)
	}
	if vuln == "" && len(fs) > 0 {
		vuln = firstNonEmpty(fs[0].Name, fs[0].FindingID)
	}
	if vuln == "" {
		vuln = "Findings"
	}

	scale := ""
	if occ := totalOccurrences(fs); occ > 0 {
		scale = fmt.Sprintf("%d %s", occ, plural(occ, "occurrence", "occurrences"))
	} else {
		scale = fmt.Sprintf("%d %s", len(fs), plural(len(fs), "endpoint", "endpoints"))
	}

	title := sanitizeUntrusted(vuln + " — " + scale)
	if len(title) > 255 {
		title = truncate(title, 252)
	}
	return title
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// buildGroupBody renders a definition-group issue: the shared definition
// context (description, remediation, classification, KB link), a table of every
// affected endpoint, and one representative evidence block. markerKey is the
// caller's authoritative dedup key (e.g. "defgroup:<def>"); it is embedded as
// the hidden marker last so dedup never depends on body length or re-derivation.
func buildGroupBody(def *entities.Definition, fs []entities.Finding, occ *entities.Occurrence, wikiURLBase, markerKey string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**Risk:** %s  |  **Affected endpoints:** %d  |  **Total occurrences:** %d\n\n",
		titleCase(maxRisk(fs)), len(fs), totalOccurrences(fs))

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
			b.WriteString("\n\n")
		}
		if strings.TrimSpace(wikiURLBase) != "" {
			page := "Definitions/" + obsidian.DefinitionPageName(*def)
			fmt.Fprintf(&b, "**KB reference:** [%s](%s/%s)\n\n", page,
				strings.TrimRight(wikiURLBase, "/"), url.PathEscape(page))
		}
	}

	b.WriteString("## Affected endpoints\n\n")
	b.WriteString("| Risk | Method | URL | Occurrences |\n|---|---|---|---|\n")
	shown := fs
	if len(shown) > maxEndpointRows {
		shown = shown[:maxEndpointRows]
	}
	for _, f := range shown {
		fmt.Fprintf(&b, "| %s | %s | %s | %d |\n",
			titleCase(f.Risk),
			tableCell(f.Method),
			inlineCode(sanitizeUntrusted(strings.TrimSpace(f.URL))),
			f.Occurrences)
	}
	if len(fs) > maxEndpointRows {
		fmt.Fprintf(&b, "\n_…and %d more endpoint(s); see the KB wiki for the full list._\n", len(fs)-maxEndpointRows)
	}
	b.WriteString("\n")

	if occ != nil {
		if ev := evidenceMarkdown(occ); ev != "" {
			b.WriteString("## Representative evidence\n\n")
			b.WriteString(ev)
			b.WriteString("\n")
		}
	}

	return finalizeBody(b.String(), findingMarker(markerKey))
}

// tableCell escapes a value for safe inclusion in a one-line markdown table
// cell: pipes are escaped and newlines collapsed so site-controlled text can't
// break the table layout.
func tableCell(s string) string {
	s = sanitizeUntrusted(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}
