package obsidian

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

const legendContent = `# KB Alias Legend

Findings and occurrences use short aliases for display in tables and links.

## Alias format

` + "`PREFIX domain-XXXX`" + `

- **PREFIX** — initials of the rule name (e.g., CDM = Cross-Domain Misconfiguration)
- **domain** — target host fragment (e.g., ` + "`juice-shop:3000`" + `)
- **XXXX** — last 4 hex characters of the finding or occurrence ID

## Known prefixes

| Prefix | Full rule name | Plugin ID |
|---|---|---|
| CDM | Cross-Domain Misconfiguration | 10098 |
| CSP | Content Security Policy (CSP) Header Not Set | 10038 |
| CDJSF | Cross-Domain JavaScript Source File Inclusion | 10017 |
| HSTS | HTTP Strict Transport Security (HSTS) Header Not Set | 10035 |
| ZIOD | ZAP is Out of Date | 10116 |
| MWA | Modern Web Application | 10109 |
| SQLI | SQL Error Based Injection | custom |
| ABIE | Authenticated Basket Item Enumeration | custom |
| ABORE | Authenticated Basket Object Reference Exposure | custom |
| ACE | Authenticated Complaints Exposure | custom |
| AUDE | Authenticated User Directory Exposure | custom |

_D1 and DZ prefixes appear when rule initials conflict or are unregistered — file a PR to expand this legend._
`

const triageGuideContent = `# Triage Workflow Guide

## Status values

| Status | Meaning |
|---|---|
| open | New, not yet reviewed |
| triaged | Reviewed, confirmed real |
| fp | False positive — not a real finding |
| accepted | Risk accepted, no fix planned |
| fixed | Remediation verified |

## How to update status in Confluence

1. Open the **occurrence page** for the finding (linked from the finding page).
2. Click **Edit** on the page.
3. Scroll to the **Workflow** section.
4. Update the ` + "`Status:`" + ` line to the new value.
5. Add your name to ` + "`Owner:`" + ` and today's date to ` + "`Updated:`" + `.
6. Save — Confluence page history records the change.

## Bulk triage

1. Open the definition page (e.g., CDM).
2. Review the **False Positive Conditions** section.
3. For each occurrence in the findings list, open and update status.

## Escalation

- File a Jira ticket for findings requiring engineering action.
- Link the ticket ID in the occurrence page ` + "`Tickets:`" + ` field.
- Set status to ` + "`triaged`" + ` once a ticket exists.

## Governance fields

Each occurrence page has a **Workflow** section with:
- **Status** — required; one of the values above
- **Owner** — person responsible for resolution
- **False positive reason** — required when status = ` + "`fp`" + `
- **Acceptance justification** — required when status = ` + "`accepted`" + `
- **Due at** — target remediation date (UTC)
`

// writeLegend writes LEGEND.md (static content — no entities data needed).
func writeLegend(root string) error {
	return os.WriteFile(filepath.Join(root, "LEGEND.md"), []byte(legendContent), 0o644)
}

// writeTriageGuide writes TRIAGE-GUIDE.md (static workflow guide for analysts).
func writeTriageGuide(root string) error {
	return os.WriteFile(filepath.Join(root, "TRIAGE-GUIDE.md"), []byte(triageGuideContent), 0o644)
}

// writeByScan writes by-scan.md, grouping occurrences by ScanLabel.
func writeByScan(root string, ef entities.EntitiesFile, opts Options) error {
	type scanGroup struct {
		Label      string
		domains    map[string]struct{}
		findings   map[string]struct{}
		occCount   int
		minObs     string
		maxObs     string
		sevCounts  map[string]int // high/medium/low/info
	}

	groups := map[string]*scanGroup{}
	order := []string{}

	for _, o := range ef.Occurrences {
		label := strings.TrimSpace(o.ScanLabel)
		if label == "" {
			label = "unlabeled"
		}
		g, ok := groups[label]
		if !ok {
			g = &scanGroup{
				Label:     label,
				domains:   map[string]struct{}{},
				findings:  map[string]struct{}{},
				sevCounts: map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0},
			}
			groups[label] = g
			order = append(order, label)
		}
		g.occCount++
		if fid := strings.TrimSpace(o.FindingID); fid != "" {
			g.findings[fid] = struct{}{}
		}
		dom := computeDomainLabel(o.URL, opts.SiteLabel)
		if dom != "" {
			g.domains[dom] = struct{}{}
		}
		obs := strings.TrimSpace(o.ObservedAt)
		if obs != "" {
			if g.minObs == "" || obs < g.minObs {
				g.minObs = obs
			}
			if g.maxObs == "" || obs > g.maxObs {
				g.maxObs = obs
			}
		}
		sev, _ := deriveSeverity(o.Risk, o.RiskCode)
		sevKey := strings.ToLower(strings.TrimSpace(sev))
		if sevKey == "informational" {
			sevKey = "info"
		}
		if _, ok := g.sevCounts[sevKey]; !ok {
			g.sevCounts[sevKey] = 0
		}
		g.sevCounts[sevKey]++
	}

	sort.Strings(order)

	var b strings.Builder
	b.WriteString("# Scans\n\n")
	b.WriteString("| Scan | Domains | Findings | Occurrences | Date range | High | Med | Low | Info |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")

	for _, label := range order {
		g := groups[label]

		domList := make([]string, 0, len(g.domains))
		for d := range g.domains {
			domList = append(domList, d)
		}
		sort.Strings(domList)
		domainsStr := strings.Join(domList, ", ")
		if domainsStr == "" {
			domainsStr = "—"
		}

		dateRange := "—"
		if g.minObs != "" && g.maxObs != "" {
			minDate := formatShortDate(g.minObs)
			maxDate := formatShortDate(g.maxObs)
			if minDate == maxDate {
				dateRange = minDate
			} else {
				dateRange = minDate + " → " + maxDate
			}
		} else if g.minObs != "" {
			dateRange = formatShortDate(g.minObs)
		}

		fmt.Fprintf(&b, "| %s | %s | %d | %d | %s | %d | %d | %d | %d |\n",
			label,
			domainsStr,
			len(g.findings),
			g.occCount,
			dateRange,
			g.sevCounts["high"],
			g.sevCounts["medium"],
			g.sevCounts["low"],
			g.sevCounts["info"],
		)
	}

	if len(order) == 0 {
		b.WriteString("\n_No scan data available._\n")
	}

	return os.WriteFile(filepath.Join(root, "by-scan.md"), []byte(b.String()), 0o644)
}

// writeExecutiveSummary writes EXECUTIVE-SUMMARY.md, generated dynamically from entities.
func writeExecutiveSummary(root string, ef entities.EntitiesFile, opts Options, generatedAt string) error {
	// Build fast lookup maps.
	defByID := map[string]entities.Definition{}
	for _, d := range ef.Definitions {
		defByID[d.DefinitionID] = d
	}
	findByID := map[string]entities.Finding{}
	for _, f := range ef.Findings {
		findByID[f.FindingID] = f
	}

	// Risk posture: count open findings and occurrences by severity.
	type severityRow struct {
		Label    string
		Key      string
		findings int
		occs     int
	}
	sevRows := []severityRow{
		{Label: "High", Key: "high"},
		{Label: "Medium", Key: "medium"},
		{Label: "Low", Key: "low"},
		{Label: "Informational", Key: "info"},
	}
	sevFindingIdx := map[string]int{} // key -> index into sevRows
	for i, r := range sevRows {
		sevFindingIdx[r.Key] = i
	}

	// Aggregate open occurrences per finding-severity.
	// We count a finding as "open" if it has at least one open occurrence.
	openOccsBySev := map[string]int{}  // sev -> open occ count
	findSevOpen := map[string]string{} // findingID -> primary severity if it has open occs

	for _, o := range ef.Occurrences {
		status := "open"
		if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
			status = strings.TrimSpace(o.Analyst.Status)
		}
		if status != "open" {
			continue
		}
		sev, _ := deriveSeverity(o.Risk, o.RiskCode)
		sevKey := strings.ToLower(strings.TrimSpace(sev))
		if sevKey == "informational" {
			sevKey = "info"
		}
		openOccsBySev[sevKey]++
		if _, seen := findSevOpen[o.FindingID]; !seen {
			findSevOpen[o.FindingID] = sevKey
		}
	}

	// Count open findings per severity.
	openFindsBySev := map[string]int{}
	for _, sevKey := range findSevOpen {
		openFindsBySev[sevKey]++
	}

	totalFinds := 0
	totalOccs := 0
	for i := range sevRows {
		k := sevRows[i].Key
		sevRows[i].findings = openFindsBySev[k]
		sevRows[i].occs = openOccsBySev[k]
		totalFinds += sevRows[i].findings
		totalOccs += sevRows[i].occs
	}

	// OWASP Top 10 coverage: count distinct findings per category.
	owaspCounts := map[string]int{}
	for _, f := range ef.Findings {
		d, ok := defByID[f.DefinitionID]
		if !ok || d.Taxonomy == nil {
			continue
		}
		for _, cat := range trimStrings(d.Taxonomy.OWASPTop10) {
			owaspCounts[cat]++
		}
	}
	var owaspCats []string
	for cat := range owaspCounts {
		owaspCats = append(owaspCats, cat)
	}
	sort.Strings(owaspCats)

	// Recommended immediate actions: top 5 high-severity open findings.
	type actionItem struct {
		Title     string
		Remedy    string
		FindCount int // distinct findings for this definition
		FindLink  string
	}
	// Group high findings by definition.
	defHighFinds := map[string][]string{} // defID -> []findingID
	for fid, sevKey := range findSevOpen {
		if sevKey != "high" {
			continue
		}
		f, ok := findByID[fid]
		if !ok {
			continue
		}
		defHighFinds[f.DefinitionID] = append(defHighFinds[f.DefinitionID], fid)
	}
	var actions []actionItem
	for defID, fids := range defHighFinds {
		d, ok := defByID[defID]
		if !ok {
			continue
		}
		title := firstNonEmpty(d.Alert, d.Name, d.PluginID)
		remedy := ""
		if d.Remediation != nil && strings.TrimSpace(d.Remediation.Summary) != "" {
			// First sentence only.
			s := strings.TrimSpace(d.Remediation.Summary)
			if idx := strings.IndexAny(s, ".!?"); idx >= 0 {
				s = strings.TrimSpace(s[:idx+1])
			}
			remedy = s
		}
		actions = append(actions, actionItem{
			Title:     title,
			Remedy:    remedy,
			FindCount: len(fids),
			FindLink:  "INDEX.md#issues",
		})
	}
	// Sort by find count desc, then title asc.
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].FindCount != actions[j].FindCount {
			return actions[i].FindCount > actions[j].FindCount
		}
		return actions[i].Title < actions[j].Title
	})
	if len(actions) > 5 {
		actions = actions[:5]
	}

	// Targets scanned (distinct domains with occurrence counts).
	domainOccCounts := map[string]int{}
	for _, o := range ef.Occurrences {
		dom := computeDomainLabel(o.URL, opts.SiteLabel)
		if dom != "" {
			domainOccCounts[dom]++
		}
	}
	var domains []string
	for d := range domainOccCounts {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	ts := strings.TrimSpace(generatedAt)
	if ts == "" {
		ts = strings.TrimSpace(ef.GeneratedAt)
	}

	var b strings.Builder
	b.WriteString("# Executive Summary\n\n")
	if ts != "" {
		fmt.Fprintf(&b, "_Generated: %s_\n\n", ts)
	}

	b.WriteString("## Risk posture\n\n")
	b.WriteString("| Severity | Open findings | Occurrences |\n")
	b.WriteString("|---|---|---|\n")
	for _, r := range sevRows {
		fmt.Fprintf(&b, "| %s | %d | %d |\n", r.Label, r.findings, r.occs)
	}
	fmt.Fprintf(&b, "| **Total** | **%d** | **%d** |\n", totalFinds, totalOccs)
	b.WriteString("\n")

	if len(owaspCats) > 0 {
		b.WriteString("## OWASP Top 10 coverage\n\n")
		b.WriteString("| Category | Findings |\n")
		b.WriteString("|---|---|\n")
		for _, cat := range owaspCats {
			if owaspCounts[cat] > 0 {
				fmt.Fprintf(&b, "| %s | %d |\n", cat, owaspCounts[cat])
			}
		}
		b.WriteString("\n_Categories with 0 findings are omitted._\n\n")
	}

	b.WriteString("## Recommended immediate actions\n\n")
	b.WriteString("_Top High-severity findings requiring action:_\n\n")
	if len(actions) == 0 {
		b.WriteString("_No High-severity open findings._\n\n")
	} else {
		for i, a := range actions {
			remedyStr := a.Remedy
			if remedyStr == "" {
				remedyStr = "Review and remediate."
			}
			fmt.Fprintf(&b, "%d. **%s** — %s ([%d findings](%s))\n", i+1, a.Title, remedyStr, a.FindCount, a.FindLink)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Targets scanned\n\n")
	if len(domains) == 0 {
		b.WriteString("_No domain data available._\n")
	} else {
		for _, d := range domains {
			fmt.Fprintf(&b, "- %s (%d occurrences)\n", d, domainOccCounts[d])
		}
	}
	b.WriteString("\n")

	return os.WriteFile(filepath.Join(root, "EXECUTIVE-SUMMARY.md"), []byte(b.String()), 0o644)
}
