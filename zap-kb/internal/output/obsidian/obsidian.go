package obsidian

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

type Options struct {
	// Optional human-friendly label for this run/session. Printed in INDEX and
	// added to frontmatter of findings/occurrences as scan.label.
	ScanLabel string
	// Optional site label override. If set, this label will be used for domain
	// grouping instead of deriving from URL host. Useful when domains are redacted.
	SiteLabel string
	// New: base URL to link back to ZAP API message JSON/HTML.
	ZapBaseURL string
	// JiraBaseURL, when set, turns analyst ticket refs into live Jira browse links.
	JiraBaseURL string
	// JiraStatusByKey carries raw Jira workflow statuses fetched at publish time.
	JiraStatusByKey map[string]string
	// JiraAssigneeByKey carries Jira assignee display names fetched at publish time.
	JiraAssigneeByKey map[string]string
	// JiraStatusSynced records when JiraStatusByKey was fetched.
	JiraStatusSynced string
	// TriageGuidanceFn, if non-nil, is called with a pluginID and returns
	// plugin-specific triage tips. Keeping this as an injected function prevents
	// the tool-agnostic vault writer from importing tool-specific packages.
	TriageGuidanceFn func(pluginID string) []string
	// CarryForwardOccurrenceMeta rehydrates analyst state and selected metadata
	// from existing occurrence notes before the vault is rebuilt. Leave false for
	// raw scanner publishes so old local triage state does not contaminate a clean run.
	CarryForwardOccurrenceMeta bool
	// CarryForwardFindingMeta rehydrates finding-level analyst state (status,
	// owner, tags, notes, rationale, ticketRefs) from existing finding notes
	// before the vault is rebuilt. Mirrors CarryForwardOccurrenceMeta but for the
	// finding workflow object — hand-edits to finding YAML would otherwise be
	// silently overwritten on regeneration.
	CarryForwardFindingMeta bool
}

// WriteVault writes an Obsidian-ready folder tree from the Entities model.
// Layout:
//
//	root/
//	  definitions/{pluginId}-{slug}.md
//	  findings/{findingId}.md
//	  occurrences/{occurrenceId}.md
func WriteVault(root string, ef entities.EntitiesFile, opts Options) error {
	defDir := filepath.Join(root, "definitions")
	findDir := filepath.Join(root, "findings")
	occDir := filepath.Join(root, "occurrences")

	// Optionally carry forward analyst status and timestamps from existing
	// occurrence files BEFORE we clear the directories. Raw scanner publishes
	// should start from the input entities file, not from stale local markdown.
	existingOccMeta := map[string]occMeta{}
	if opts.CarryForwardOccurrenceMeta {
		existingOccMeta = loadOccurrenceMeta(occDir)
	}
	existingFindingMeta := map[string]*entities.Analyst{}
	if opts.CarryForwardFindingMeta {
		existingFindingMeta = loadFindingMeta(findDir)
	}

	// Clear entity subdirs so stale pages from previous runs (e.g. definitions that are
	// no longer in the entities file) don't accumulate and get exported to Confluence.
	for _, d := range []string{defDir, findDir, occDir} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// Rehydrate finding-level analyst state from prior markdown if requested.
	// Current (input) analyst state wins; the carry-forward only fills gaps
	// created when the entities file itself lacks analyst data.
	if len(existingFindingMeta) > 0 {
		for i := range ef.Findings {
			prior, ok := existingFindingMeta[ef.Findings[i].FindingID]
			if !ok || prior == nil {
				continue
			}
			ef.Findings[i].Analyst = mergeFindingAnalyst(ef.Findings[i].Analyst, prior)
		}
	}

	// Index by ids for quick joins.
	findByID := make(map[string]entities.Finding, len(ef.Findings))
	for _, f := range ef.Findings {
		findByID[f.FindingID] = f
	}

	// Map definitionId -> on-disk filename (with directory) for correct links.
	defLinkByID := make(map[string]string, len(ef.Definitions))
	// And map to the definition itself for alias building.
	defByID := make(map[string]entities.Definition, len(ef.Definitions))

	// Normalize occurrences up front so all later rollups use the same resolved values.
	occsByFind := make(map[string][]entities.Occurrence)
	statusCounts := make(map[string]int)
	domainCounts := make(map[string]map[string]int) // domain -> status->count
	domainTotals := make(map[string]int)
	// New: severity rollups for this run
	severityCounts := make(map[string]int)                  // severity -> count
	domainSeverityCounts := make(map[string]map[string]int) // domain -> severity -> count
	scanLabels := make(map[string]struct{})
	var resolvedOccs []entities.Occurrence
	for _, raw := range ef.Occurrences {
		o := raw
		if meta, ok := existingOccMeta[o.OccurrenceID]; ok {
			if o.Analyst == nil && meta.Analyst != nil {
				cp := *meta.Analyst
				o.Analyst = &cp
			}
			if strings.TrimSpace(o.ObservedAt) == "" && strings.TrimSpace(meta.ObservedAt) != "" {
				o.ObservedAt = meta.ObservedAt
			}
			if strings.TrimSpace(o.ScanLabel) == "" && strings.TrimSpace(meta.ScanLabel) != "" {
				o.ScanLabel = meta.ScanLabel
			}
		}
		if strings.TrimSpace(o.ObservedAt) == "" {
			o.ObservedAt = ef.GeneratedAt
		}
		if strings.TrimSpace(o.ScanLabel) == "" {
			o.ScanLabel = opts.ScanLabel
		}
		occsByFind[o.FindingID] = append(occsByFind[o.FindingID], o)
		resolvedOccs = append(resolvedOccs, o)
		sl := strings.TrimSpace(o.ScanLabel)
		if sl == "" {
			sl = "unlabeled"
		}
		scanLabels[sl] = struct{}{}

		// Aggregate status/severity/domain counts for dashboard/index
		st := "open"
		if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
			st = strings.TrimSpace(o.Analyst.Status)
		}
		statusCounts[st]++
		dom := computeDomainLabel(o.URL, opts.SiteLabel)
		if dom != "" {
			if _, ok := domainCounts[dom]; !ok {
				domainCounts[dom] = map[string]int{}
			}
			domainCounts[dom][st]++
			domainTotals[dom]++
		}
		sev, _ := deriveSeverity(o.Risk, o.RiskCode)
		severityCounts[sev]++
		if dom != "" {
			if _, ok := domainSeverityCounts[dom]; !ok {
				domainSeverityCounts[dom] = map[string]int{}
			}
			domainSeverityCounts[dom][sev]++
		}
	}
	ef.Occurrences = resolvedOccs

	// Helper to aggregate status counts for a set of occurrences.
	aggStatus := func(occs []entities.Occurrence) map[string]int {
		m := map[string]int{}
		for _, o := range occs {
			s := ""
			if o.Analyst != nil {
				s = strings.TrimSpace(o.Analyst.Status)
			}
			if s == "" {
				s = "open"
			}
			m[s]++
		}
		return m
	}
	// Helper to add non-zero status counts into YAML map with a given prefix.
	// (no-op here; map[string]any variant is implemented below as addStatusToYAMLStrAny)

	// For INDEX rollup by status and by definition.
	type defSummary struct {
		Link            string
		Title           string
		Plugin          string
		Total           int
		Stats           map[string]int
		Severity        map[string]int
		PrimarySeverity string
	}
	var defSummaries []defSummary

	type issueSummary struct {
		Link            string
		Alias           string
		Method          string
		URL             string
		Severity        string
		Occurrences     int
		PrimaryStatus   string
		StatusOverview  string
		RuleTitle       string
		ObservedAt      string
		ScanLabel       string
		PluginID        string
		TuningCandidate bool
		TuningScans     int
	}
	var issueSummaries []issueSummary

	// definitions/{pluginId}-{slug}.md with embedded rollup.
	for _, d := range ef.Definitions {
		filename := fmt.Sprintf("%s-%s.md", d.PluginID, slug(firstNonEmpty(d.Alert, d.Name, d.PluginID)))
		path := filepath.Join(defDir, filename)
		defLink := filepath.ToSlash(filepath.Join("definitions", filename))
		defLinkByID[d.DefinitionID] = defLink
		defByID[d.DefinitionID] = d

		// Collect and sort findings for this definitionId.
		var fs []entities.Finding
		for _, f := range ef.Findings {
			if f.DefinitionID == d.DefinitionID {
				fs = append(fs, f)
			}
		}
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].URL != fs[j].URL {
				return fs[i].URL < fs[j].URL
			}
			return fs[i].Method < fs[j].Method
		})

		// Aggregate rollups across all findings for this definition.
		defStats := map[string]int{}
		defSeverity := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
		defOccTotal := 0
		for _, f := range fs {
			occs := occsByFind[f.FindingID]
			defOccTotal += len(occs)
			sc := aggStatus(occs)
			for k, v := range sc {
				defStats[k] += v
			}
			for _, occ := range occs {
				sevTxt, _ := deriveSeverity(occ.Risk, occ.RiskCode)
				sevKey := strings.ToLower(strings.TrimSpace(sevTxt))
				if sevKey == "informational" {
					sevKey = "info"
				}
				if sevKey == "" {
					sevKey = "info"
				}
				if _, ok := defSeverity[sevKey]; !ok {
					defSeverity[sevKey] = 0
				}
				defSeverity[sevKey]++
			}
		}

		primarySeverity := "info"
		for _, name := range []string{"high", "medium", "low", "info"} {
			if defSeverity[name] > 0 {
				primarySeverity = name
				break
			}
		}

		defSummaries = append(defSummaries, defSummary{
			Link:            defLink,
			Title:           firstNonEmpty(d.Alert, d.Name, d.PluginID),
			Plugin:          d.PluginID,
			Total:           defOccTotal,
			Stats:           defStats,
			Severity:        defSeverity,
			PrimarySeverity: primarySeverity,
		})

		// Prepare YAML values
		kv := map[string]any{
			"id":            d.DefinitionID,
			"pluginId":      d.PluginID,
			"origin":        entities.DefinitionOriginValue(d.Origin, d.PluginID, d.Detection),
			"name":          firstNonEmpty(d.Alert, d.Name),
			"schemaVersion": ef.SchemaVersion,
			"sourceTool":    ef.SourceTool,
			"generatedAt":   ef.GeneratedAt,
			"aliases":       []string{defAliasUltraCompact(d)},
		}
		if strings.TrimSpace(opts.ScanLabel) != "" {
			kv["scan.label"] = opts.ScanLabel
		}
		if d.WASCID > 0 {
			kv["wascId"] = fmt.Sprintf("%d", d.WASCID)
		}
		// taxonomy fields
		if d.Taxonomy != nil {
			if d.Taxonomy.CWEID > 0 {
				kv["cweId"] = fmt.Sprintf("%d", d.Taxonomy.CWEID)
			}
			if strings.TrimSpace(d.Taxonomy.CWEURI) != "" {
				kv["cweUri"] = d.Taxonomy.CWEURI
			}
			if len(d.Taxonomy.CAPECIDs) > 0 {
				kv["capecIds"] = intsToStrings(d.Taxonomy.CAPECIDs)
			}
			if vals := trimStrings(d.Taxonomy.ATTACK); len(vals) > 0 {
				kv["attack"] = vals
			}
			if vals := trimStrings(d.Taxonomy.OWASPTop10); len(vals) > 0 {
				kv["owaspTop10"] = vals
			}
			if vals := trimStrings(d.Taxonomy.NIST80053); len(vals) > 0 {
				kv["nist80053"] = vals
			}
			if vals := trimStrings(d.Taxonomy.Tags); len(vals) > 0 {
				kv["tags"] = vals
			}
		}
		// definition rollup
		kv["occurrenceCount"] = fmt.Sprintf("%d", defOccTotal)
		addStatusToYAMLStrAny(kv, "status.", defStats)

		var b strings.Builder
		writeYAML(&b, kv)

		title := firstNonEmpty(d.Alert, d.Name, d.PluginID)
		fmt.Fprintf(&b, "# %s (Plugin %s)\n\n", title, d.PluginID)
		if isCustomRule(d) {
			b.WriteString("> [!Note] Custom rule\n> This is a project-specific detection rule, not a built-in ZAP plugin. It was written for this application's known attack surface.\n\n")
		}
		// Severity rollup for quick triage
		if defSeverity["high"]+defSeverity["medium"]+defSeverity["low"]+defSeverity["info"] > 0 {
			b.WriteString("## Severity overview\n\n")
			for _, entry := range []struct {
				Label string
				Key   string
			}{
				{"High", "high"},
				{"Medium", "medium"},
				{"Low", "low"},
				{"Info", "info"},
			} {
				fmt.Fprintf(&b, "- %s: %d\n", entry.Label, defSeverity[entry.Key])
			}
			b.WriteString("\n")
		}

		// Taxonomy and governance tags for quick reporting/triage
		if d.Taxonomy != nil {
			lines := []string{}
			if d.Taxonomy.CWEID > 0 {
				lines = append(lines, fmt.Sprintf("CWE-%d", d.Taxonomy.CWEID))
			}
			if len(d.Taxonomy.CAPECIDs) > 0 {
				lines = append(lines, fmt.Sprintf("CAPEC: %s", strings.Join(intsToStrings(d.Taxonomy.CAPECIDs), ", ")))
			}
			if vals := trimStrings(d.Taxonomy.ATTACK); len(vals) > 0 {
				lines = append(lines, "ATT&CK: "+strings.Join(vals, ", "))
			}
			if vals := trimStrings(d.Taxonomy.OWASPTop10); len(vals) > 0 {
				lines = append(lines, "OWASP Top 10: "+strings.Join(vals, ", "))
			}
			if vals := trimStrings(d.Taxonomy.NIST80053); len(vals) > 0 {
				lines = append(lines, "NIST 800-53: "+strings.Join(vals, ", "))
			}
			if vals := trimStrings(d.Taxonomy.Tags); len(vals) > 0 {
				lines = append(lines, "Tags: "+strings.Join(vals, ", "))
			}
			if len(lines) > 0 {
				b.WriteString("## Taxonomy\n\n")
				for _, l := range lines {
					fmt.Fprintf(&b, "- %s\n", l)
				}
				b.WriteString("\n")
			}
		}

		// Taxonomy completeness callout — helps analysts identify gaps before reporting.
		{
			missingCWE := d.Taxonomy == nil || d.Taxonomy.CWEID == 0
			missingOWASP := d.Taxonomy == nil || len(trimStrings(d.Taxonomy.OWASPTop10)) == 0
			if missingCWE && missingOWASP {
				b.WriteString("> [!Warning]\n> Taxonomy incomplete — CWE and OWASP mapping missing\n\n")
			} else if missingCWE {
				b.WriteString("> [!Info]\n> CWE mapping absent — consider adding a CWE ID to the taxonomy\n\n")
			} else if missingOWASP {
				b.WriteString("> [!Info]\n> OWASP Top 10 mapping absent — consider adding an OWASP category\n\n")
			}
		}

		// Description — "what is this vulnerability" from the scanner.
		if strings.TrimSpace(d.Description) != "" {
			b.WriteString("## Description\n\n")
			b.WriteString(strings.TrimSpace(d.Description) + "\n\n")
		}

		// Detection logic (if enriched)
		if d.Detection != nil {
			b.WriteString("## Detection logic\n\n")
			if isCustomRule(d) {
				b.WriteString("- Rule source: Custom (project-specific)\n")
			}
			if strings.TrimSpace(d.Detection.LogicType) != "" {
				fmt.Fprintf(&b, "- Logic: %s\n", d.Detection.LogicType)
			}
			if strings.TrimSpace(d.Detection.PluginRef) != "" {
				fmt.Fprintf(&b, "- Add-on: %s\n", d.Detection.PluginRef)
			}
			if strings.TrimSpace(d.Detection.RuleSource) != "" {
				fmt.Fprintf(&b, "- Source path: `%s`\n", d.Detection.RuleSource)
			}
			if strings.TrimSpace(d.Detection.SourceURL) != "" {
				fmt.Fprintf(&b, "- GitHub: %s\n", d.Detection.SourceURL)
			}
			if strings.TrimSpace(d.Detection.DocsURL) != "" {
				fmt.Fprintf(&b, "- Docs: %s\n", d.Detection.DocsURL)
			}
			b.WriteString("\n")
			// How it detects (summary)
			if strings.TrimSpace(d.Detection.Summary) != "" || (d.Detection.Defaults != nil) || len(d.Detection.Signals) > 0 {
				b.WriteString("### How it detects\n\n")
				if strings.TrimSpace(d.Detection.Summary) != "" {
					fmt.Fprintf(&b, "%s\n\n", d.Detection.Summary)
				}
				if d.Detection.Defaults != nil {
					line := []string{}
					if strings.TrimSpace(d.Detection.Defaults.Threshold) != "" {
						line = append(line, "threshold: "+d.Detection.Defaults.Threshold)
					}
					if strings.TrimSpace(d.Detection.Defaults.Strength) != "" {
						line = append(line, "strength: "+d.Detection.Defaults.Strength)
					}
					if len(line) > 0 {
						fmt.Fprintf(&b, "_%s_\n\n", strings.Join(line, "; "))
					}
				}
				if len(d.Detection.Signals) > 0 {
					b.WriteString("Signals:\n")
					for _, s := range d.Detection.Signals {
						fmt.Fprintf(&b, "- %s\n", s)
						// If the signal is a regex, add a short hint/example to make it approachable.
						ls := strings.ToLower(strings.TrimSpace(s))
						if strings.HasPrefix(ls, "regex:") {
							pat := strings.TrimSpace(s[len("regex:"):])
							if hint, ex := regexHintAndExample(pat); hint != "" || ex != "" {
								if hint != "" {
									fmt.Fprintf(&b, "  - hint: %s\n", hint)
								}
								if ex != "" {
									fmt.Fprintf(&b, "  - example: `%s`\n", ex)
								}
							}
						}
					}
					b.WriteString("\n")
				}
			}
		}

		if d.Remediation != nil && strings.TrimSpace(d.Remediation.Summary) != "" {
			b.WriteString("## Remediation\n\n")
			b.WriteString(d.Remediation.Summary + "\n\n")
		}
		if d.Remediation != nil && len(d.Remediation.References) > 0 {
			b.WriteString("### References\n")
			for _, r := range d.Remediation.References {
				if strings.TrimSpace(r) != "" {
					fmt.Fprintf(&b, "- %s\n", r)
				}
			}
			b.WriteString("\n")
		}

		if d.Remediation != nil && len(d.Remediation.FalsePositiveConditions) > 0 {
			b.WriteString("## False Positive Conditions\n\n")
			for _, c := range d.Remediation.FalsePositiveConditions {
				if strings.TrimSpace(c) != "" {
					fmt.Fprintf(&b, "- %s\n", c)
				}
			}
			b.WriteString("\n")
		}

		if len(fs) > 0 {
			maxFindingsPerSeverity := 10
			maxSamplesPerFinding := 3
			findingsBySeverity := map[string][]entities.Finding{}
			for _, f := range fs {
				sevTxt, _ := deriveSeverity(f.Risk, f.RiskCode)
				sevKey := strings.ToLower(strings.TrimSpace(sevTxt))
				if sevKey == "informational" {
					sevKey = "info"
				}
				if sevKey == "" {
					sevKey = "info"
				}
				findingsBySeverity[sevKey] = append(findingsBySeverity[sevKey], f)
			}

			b.WriteString("## Issues\n\n")
			severityOrder := []string{"high", "medium", "low", "info"}
			for _, sev := range severityOrder {
				group := findingsBySeverity[sev]
				if len(group) == 0 {
					continue
				}
				sort.Slice(group, func(i, j int) bool {
					ii := len(occsByFind[group[i].FindingID])
					jj := len(occsByFind[group[j].FindingID])
					if ii != jj {
						return ii > jj
					}
					if group[i].URL != group[j].URL {
						return group[i].URL < group[j].URL
					}
					return group[i].FindingID < group[j].FindingID
				})
				title := titleASCII(sev)
				fmt.Fprintf(&b, "### %s severity (%d)\n\n", title, len(group))
				limit := maxFindingsPerSeverity
				if limit > len(group) {
					limit = len(group)
				}
				for i := 0; i < limit; i++ {
					f := group[i]
					occs := occsByFind[f.FindingID]
					sc := aggStatus(occs)
					fmt.Fprintf(&b, "- [[%s|%s %s]] — occurrences: %d (open:%d triaged:%d fp:%d accepted:%d fixed:%d)\n",
						filepath.ToSlash(filepath.Join("findings", f.FindingID+".md")),
						strings.TrimSpace(f.Method), strings.TrimSpace(f.URL), len(occs),
						sc["open"], sc["triaged"], sc["fp"], sc["accepted"], sc["fixed"])
					if len(occs) > 0 {
						b.WriteString("  - Samples:\n")
						sort.Slice(occs, func(i, j int) bool {
							if occs[i].URL != occs[j].URL {
								return occs[i].URL < occs[j].URL
							}
							if occs[i].Param != occs[j].Param {
								return occs[i].Param < occs[j].Param
							}
							return occs[i].OccurrenceID < occs[j].OccurrenceID
						})
						sampleLimit := maxSamplesPerFinding
						if sampleLimit > len(occs) {
							sampleLimit = len(occs)
						}
						for j := 0; j < sampleLimit; j++ {
							o := occs[j]
							caption := strings.TrimSpace(o.Name)
							if caption == "" {
								parts := []string{strings.TrimSpace(o.Method), strings.TrimSpace(o.URL)}
								if strings.TrimSpace(o.Param) != "" {
									parts = append(parts, "param="+strings.TrimSpace(o.Param))
								}
								caption = strings.Join(parts, " ")
							}
							fmt.Fprintf(&b, "    - [[%s|%s]]\n",
								filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")), caption)
						}
						if sampleLimit < len(occs) {
							fmt.Fprintf(&b, "    - _%d additional occurrences not shown_\n", len(occs)-sampleLimit)
						}
					}
				}
				if limit < len(group) {
					fmt.Fprintf(&b, "- _%d additional findings — [[../INDEX.md#issues|see full list]]_\n", len(group)-limit)
				}
				b.WriteString("\n")
			}
		}

		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	// findings/{findingId}.md
	for _, f := range ef.Findings {
		path := filepath.Join(findDir, f.FindingID+".md")
		var b strings.Builder

		occs := occsByFind[f.FindingID]
		firstSeen, lastSeen := observedBounds(occs, ef.GeneratedAt)
		sc := aggStatus(occs)

		ruleName := f.PluginID
		if d, ok := defByID[f.DefinitionID]; ok {
			rn := firstNonEmpty(d.Alert, d.Name)
			if rn != "" {
				ruleName = rn
			}
		}
		alias := findAliasUltraCompact(f, ruleName)

		// New: severity id
		_, rid := deriveSeverity(f.Risk, f.RiskCode)

		kv := map[string]any{
			"id":              "finding/" + f.FindingID,
			"findingId":       f.FindingID,
			"definitionId":    f.DefinitionID,
			"pluginId":        f.PluginID,
			"url":             f.URL,
			"name":            f.Name,
			"risk":            f.Risk,
			"riskCode":        f.RiskCode,
			"riskId":          fmt.Sprintf("%d", rid),
			"confidence":      f.Confidence,
			"schemaVersion":   ef.SchemaVersion,
			"sourceTool":      ef.SourceTool,
			"generatedAt":     ef.GeneratedAt,
			"firstSeen":       firstSeen,
			"lastSeen":        lastSeen,
			"occurrenceCount": fmt.Sprintf("%d", len(occs)),
			"aliases":         []string{alias},
			"kind":            "issue",
		}
		if strings.TrimSpace(opts.ScanLabel) != "" {
			kv["scan.label"] = opts.ScanLabel
		}
		if dom := computeDomainLabel(f.URL, opts.SiteLabel); dom != "" {
			kv["domain"] = dom
		}
		// Analyst state — emit to YAML so hand-edits round-trip via
		// loadFindingMeta on the next WriteVault.
		if a := f.Analyst; a != nil {
			if v := strings.TrimSpace(a.Status); v != "" {
				kv["analyst.status"] = entities.CanonicalAnalystStatus(v)
			}
			if v := strings.TrimSpace(a.Owner); v != "" {
				kv["analyst.owner"] = v
			}
			if len(a.Tags) > 0 {
				kv["analyst.tags"] = strings.Join(a.Tags, ", ")
			}
			if v := strings.TrimSpace(a.Notes); v != "" {
				kv["analyst.notes"] = v
			}
			if v := strings.TrimSpace(a.Rationale); v != "" {
				kv["analyst.rationale"] = v
			}
			if len(a.TicketRefs) > 0 {
				kv["analyst.ticketRefs"] = strings.Join(a.TicketRefs, ", ")
			}
			if v := strings.TrimSpace(a.UpdatedAt); v != "" {
				kv["analyst.updatedAt"] = v
			}
		}
		addStatusToYAMLStrAny(kv, "status.", sc)
		writeYAML(&b, kv)

		fmt.Fprintf(&b, "# Issue %s — %s\n\n", f.FindingID, alias)
		// Severity callout
		sevTxt, _ := deriveSeverity(f.Risk, f.RiskCode)
		b.WriteString(calloutForSeverity(sevTxt, fmt.Sprintf("Risk: %s (%s) — Confidence: %s", f.Risk, f.RiskCode, f.Confidence)))

		// Recurrence advisory banner (shown before body so it's immediately visible)
		if r := f.Recurrence; r != nil {
			priorLabel := titleASCII(r.PriorStatus)
			fmt.Fprintf(&b, "> [!Warning] Recurrence detected\n")
			fmt.Fprintf(&b, "> This finding was previously **%s** but new occurrences appeared", priorLabel)
			if strings.TrimSpace(r.RecurredAt) != "" {
				fmt.Fprintf(&b, " on %s", formatShortDate(r.RecurredAt))
			}
			if strings.TrimSpace(r.RecurredInScan) != "" {
				fmt.Fprintf(&b, " (scan: %s)", r.RecurredInScan)
			}
			fmt.Fprintf(&b, ".\n> Review and update the analyst status as needed.\n\n")
		}

		defTitle := f.DefinitionID
		if def, ok := defByID[f.DefinitionID]; ok {
			if t := firstNonEmpty(def.Alert, def.Name, def.PluginID); strings.TrimSpace(t) != "" {
				defTitle = t
			}
		}
		if link := defLinkByID[f.DefinitionID]; strings.TrimSpace(link) != "" {
			fmt.Fprintf(&b, "- Definition: [[%s|%s]]\n\n", link, defTitle)
		} else {
			fmt.Fprintf(&b, "- Definition: %s\n\n", defTitle)
		}
		fmt.Fprintf(&b, "**Endpoint:** %s %s\n\n", f.Method, f.URL)

		primaryStatus, statusSummary := summarizeStatusCounts(sc)

		// Rollup section
		b.WriteString("## Rollup\n\n")
		fmt.Fprintf(&b, "- Occurrences: %d\n", len(occs))
		fmt.Fprintf(&b, "- Status counts: %s\n", statusSummary)
		trafficSamples := 0
		for _, o := range occs {
			if o.Request != nil || o.Response != nil {
				trafficSamples++
			}
		}
		if trafficSamples > 0 {
			fmt.Fprintf(&b, "- Traffic samples: %d\n", trafficSamples)
		}
		b.WriteString("\n")

		// Occurrences list (compact)
		if len(occs) > 0 {
			b.WriteString("## Occurrences\n\n")
			sort.Slice(occs, func(i, j int) bool {
				ti := parseObservedTime(occs[i].ObservedAt)
				tj := parseObservedTime(occs[j].ObservedAt)
				if !ti.Equal(tj) {
					return ti.After(tj)
				}
				if occs[i].URL != occs[j].URL {
					return occs[i].URL < occs[j].URL
				}
				if occs[i].Param != occs[j].Param {
					return occs[i].Param < occs[j].Param
				}
				return occs[i].OccurrenceID < occs[j].OccurrenceID
			})
			for _, o := range occs {
				sev2, _ := deriveSeverity(o.Risk, o.RiskCode)
				// Use METHOD /path as the caption — o.Name may contain raw evidence
				// snippets (e.g. "GET /ftp ev=\"<!DOCTYPE...\"") which break wikilinks
				// and pollute Confluence page titles.
				method := strings.ToUpper(strings.TrimSpace(o.Method))
				oPath := ""
				if u, err2 := neturl.Parse(o.URL); err2 == nil {
					oPath = u.Path
				}
				caption := strings.TrimSpace(method + " " + oPath)
				if caption == "" {
					caption = urlBasename(o.URL)
				}
				if strings.TrimSpace(o.Param) != "" {
					caption += " [" + strings.TrimSpace(o.Param) + "]"
				}
				ev := strings.TrimSpace(o.Evidence)
				if ev != "" {
					ev = truncate(ev, 60)
				}
				statusLabel := "open"
				if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
					statusLabel = strings.TrimSpace(o.Analyst.Status)
				}
				decorations := []string{titleASCII(sev2), "status:" + statusLabel}
				if strings.TrimSpace(o.ObservedAt) != "" {
					decorations = append(decorations, "seen:"+formatShortDate(o.ObservedAt))
				}
				if strings.TrimSpace(o.ScanLabel) != "" {
					decorations = append(decorations, "scan:"+o.ScanLabel)
				}
				if o.Request != nil || o.Response != nil {
					decorations = append(decorations, "traffic")
				}
				if ev != "" {
					decorations = append(decorations, ev)
				}
				fmt.Fprintf(&b, "- [[%s|%s]] — %s\n", filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")), caption, strings.Join(decorations, "; "))
			}
			b.WriteString("\n")
		}

		// Most recent occurrence traffic (if present) — rendered as raw HTTP code
		// blocks matching the occurrence page format so analysts see headers + body
		// in a single scannable block rather than bullet lists.
		if len(occs) > 0 {
			first := occs[0]
			if first.Request != nil || first.Response != nil {
				b.WriteString("## Most recent occurrence traffic\n\n")
				b.WriteString("<details>\n<summary>Show traffic</summary>\n\n")
				if first.Request != nil {
					b.WriteString("### Request\n\n")
					writeHTTPRequestBlock(&b, first.Method, first.URL, first.Request)
					b.WriteString("\n")
				}
				if first.Response != nil {
					b.WriteString("### Response\n\n")
					writeHTTPResponseBlock(&b, first.Response)
					b.WriteString("\n")
				}
				b.WriteString("</details>\n\n")
			}
		}

		// Issue-level workflow keeps finding-level triage authoritative while
		// preserving occurrence-derived history and counts.
		workflowStatus := primaryStatus
		owners := collectAnalystSet(occs, func(a *entities.Analyst) []string {
			if strings.TrimSpace(a.Owner) == "" {
				return nil
			}
			return []string{strings.TrimSpace(a.Owner)}
		})
		tags := collectAnalystSet(occs, func(a *entities.Analyst) []string { return a.Tags })
		tickets := collectAnalystSet(occs, func(a *entities.Analyst) []string { return a.TicketRefs })
		updated := latestAnalystUpdate(occs)
		notes := collectAnalystNotes(occs, 5)
		if f.Analyst != nil {
			if status := entities.CanonicalAnalystStatus(strings.TrimSpace(f.Analyst.Status)); status != "" {
				workflowStatus = status
			}
			if owner := strings.TrimSpace(f.Analyst.Owner); owner != "" {
				owners = unionStringsOrdered([]string{owner}, owners)
			}
			tags = unionStringsOrdered(trimStrings(f.Analyst.Tags), tags)
			tickets = unionStringsOrdered(trimStrings(f.Analyst.TicketRefs), tickets)
			updated = latestTimestampString(strings.TrimSpace(f.Analyst.UpdatedAt), updated)
			notes = mergeAnalystNotes(f.Analyst.Notes, notes, 5)
		}
		tuningCandidate, tuningScans := recurringFalsePositiveTuningCandidate(workflowStatus, occs)

		b.WriteString("## Workflow\n\n")
		fmt.Fprintf(&b, "- Status: %s (%s)\n", titleASCII(workflowStatus), statusSummary)
		fmt.Fprintf(&b, "- Owners: %s\n", formatListOrPlaceholder(owners, "_None recorded_"))
		fmt.Fprintf(&b, "- Tags: %s\n", formatListOrPlaceholder(tags, "_None_"))
		fmt.Fprintf(&b, "- Analyst cases: %s\n", formatTicketRefsMarkdown(tickets, opts.JiraBaseURL, "_None_"))
		if raw := primaryJiraStatus(tickets, opts.JiraStatusByKey); raw != "" {
			fmt.Fprintf(&b, "- Jira status: %s\n", raw)
		}
		if len(tickets) > 0 {
			b.WriteString("- Workflow source: Jira analyst case (synced at publish time)\n")
			if strings.TrimSpace(opts.JiraStatusSynced) != "" {
				fmt.Fprintf(&b, "- Jira sync: %s\n", opts.JiraStatusSynced)
			}
		}
		fmt.Fprintf(&b, "- Updated: %s\n", fallbackString(updated, "_Not recorded_"))
		if tuningCandidate {
			fmt.Fprintf(&b, "- Tuning candidate: yes (false positive across %d scans)\n", tuningScans)
			if containsStringFold(tags, "tune-scan") {
				b.WriteString("- Tuning follow-up requested: yes (`tune-scan`)\n")
			} else {
				b.WriteString("- Tuning follow-up requested: no (add `tune-scan` to `analyst.tags` if scan tuning work is needed)\n")
			}
		}
		// Rationale (finding-level, separate from per-occurrence notes)
		rationale := ""
		if f.Analyst != nil && strings.TrimSpace(f.Analyst.Rationale) != "" {
			rationale = strings.TrimSpace(f.Analyst.Rationale)
		}
		if rationale != "" {
			fmt.Fprintf(&b, "- Rationale: %s\n", rationale)
		}

		if len(notes) > 0 {
			b.WriteString("\n### Analyst Notes\n\n")
			for _, note := range notes {
				fmt.Fprintf(&b, "- %s\n", note)
			}
			b.WriteString("\n")
		}

		// Suppression block
		if sup := f.Suppression; sup != nil {
			b.WriteString("### Suppression\n\n")
			fmt.Fprintf(&b, "- Scope: %s\n", sup.Scope)
			if strings.TrimSpace(sup.Reason) != "" {
				fmt.Fprintf(&b, "- Reason: %s\n", sup.Reason)
			}
			if strings.TrimSpace(sup.DecidedBy) != "" {
				fmt.Fprintf(&b, "- Decided by: %s\n", sup.DecidedBy)
			}
			if strings.TrimSpace(sup.DecidedAt) != "" {
				fmt.Fprintf(&b, "- Decided at: %s\n", formatShortDate(sup.DecidedAt))
			}
			if strings.TrimSpace(sup.ExpiresAt) != "" {
				fmt.Fprintf(&b, "- Expires at: %s\n", formatShortDate(sup.ExpiresAt))
			} else {
				b.WriteString("- Expires: permanent\n")
			}
			if strings.TrimSpace(sup.OccurrenceRef) != "" {
				fmt.Fprintf(&b, "- Occurrence ref: %s\n", sup.OccurrenceRef)
			}
			b.WriteString("\n")
		}

		b.WriteString("### Quick triage shortcuts\n\n")
		b.WriteString("- Set `analyst.status` to: open | triaged | fp | accepted | fixed\n")
		b.WriteString("- Add `case-ticket` to `analyst.tags` to export low/info findings to the analyst Jira project\n")
		b.WriteString("- Add ticket IDs under `analyst.ticketRefs` (YAML list)\n")
		b.WriteString("- Add `tune-scan` to `analyst.tags` when a recurring false positive needs detection tuning follow-up\n")
		b.WriteString("- Assign `analyst.owner` and `analyst.tags` to drive queues\n\n")

		b.WriteString("### Analyst notebook\n\n")
		b.WriteString("- Notes:\n")
		b.WriteString("- Evidence links:\n")
		b.WriteString("- Next steps:\n\n")

		ruleTitle := ""
		if d, ok := defByID[f.DefinitionID]; ok {
			ruleTitle = firstNonEmpty(d.Alert, d.Name, d.PluginID)
		}

		issueSummaries = append(issueSummaries, issueSummary{
			Link:            filepath.ToSlash(filepath.Join("findings", f.FindingID+".md")),
			Alias:           alias,
			Method:          strings.TrimSpace(f.Method),
			URL:             strings.TrimSpace(f.URL),
			Severity:        strings.ToLower(strings.TrimSpace(sevTxt)),
			Occurrences:     len(occs),
			PrimaryStatus:   workflowStatus,
			StatusOverview:  statusSummary,
			RuleTitle:       ruleTitle,
			ObservedAt:      lastSeen,
			ScanLabel:       fallbackString(firstNonEmpty(occs[0].ScanLabel, opts.ScanLabel), ""),
			PluginID:        strings.TrimSpace(f.PluginID),
			TuningCandidate: tuningCandidate,
			TuningScans:     tuningScans,
		})

		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	issueSeverityCounts := map[string]int{}
	var latestScanLabel string
	var latestObs time.Time
	seenByKey := map[string]bool{}
	var newestOccs []entities.Occurrence

	// Find latest observed time and associated scan label
	for _, o := range ef.Occurrences {
		ts := parseObservedTime(o.ObservedAt)
		if ts.IsZero() {
			continue
		}
		if ts.After(latestObs) {
			latestObs = ts
			latestScanLabel = strings.TrimSpace(o.ScanLabel)
		}
	}
	// Collect occurrences from the latest scan that weren't seen in older scans (same finding+url+param+attack key)
	if latestScanLabel != "" {
		for _, o := range ef.Occurrences {
			if strings.TrimSpace(o.ScanLabel) != latestScanLabel {
				continue
			}
			keyParts := []string{strings.TrimSpace(o.FindingID), strings.TrimSpace(o.URL), strings.TrimSpace(o.Param), strings.TrimSpace(o.Attack)}
			key := strings.Join(keyParts, "|")
			seenByKey[key] = true
			newestOccs = append(newestOccs, o)
		}
		for _, o := range ef.Occurrences {
			if strings.TrimSpace(o.ScanLabel) == latestScanLabel {
				continue
			}
			key := strings.Join([]string{strings.TrimSpace(o.FindingID), strings.TrimSpace(o.URL), strings.TrimSpace(o.Param), strings.TrimSpace(o.Attack)}, "|")
			delete(seenByKey, key)
		}
	}
	for _, is := range issueSummaries {
		key := strings.ToLower(strings.TrimSpace(is.Severity))
		if key == "" {
			key = "info"
		}
		issueSeverityCounts[key]++
	}

	// occurrences/{occurrenceId}.md
	for _, o := range ef.Occurrences {
		path := filepath.Join(occDir, o.OccurrenceID+".md")
		var b strings.Builder

		// Analyst fields (flattened for YAML)
		aStatus, aOwner, aNotes, aUpdated := "open", "", "", ""
		var aTags []string
		var aTickets []string
		if o.Analyst != nil {
			aStatus = entities.CanonicalAnalystStatus(strings.TrimSpace(o.Analyst.Status))
			if aStatus == "" {
				aStatus = "open"
			}
			aOwner = strings.TrimSpace(o.Analyst.Owner)
			if len(o.Analyst.Tags) > 0 {
				aTags = append(aTags, o.Analyst.Tags...)
			}
			aNotes = strings.TrimSpace(o.Analyst.Notes)
			if len(o.Analyst.TicketRefs) > 0 {
				aTickets = append(aTickets, o.Analyst.TicketRefs...)
			}
			aUpdated = strings.TrimSpace(o.Analyst.UpdatedAt)
		}

		dom := computeDomainLabel(o.URL, opts.SiteLabel)
		_, rid := deriveSeverity(o.Risk, o.RiskCode)

		// Ultra-compact alias: RULE_ACRO basename-code (no method)
		// Rule name is from the parent definition's alert/name as available.
		rn := ""
		if d, ok := defByID[o.DefinitionID]; ok {
			rn = firstNonEmpty(d.Alert, d.Name, d.PluginID)
		}
		alias := occAliasUltraCompact(o, rn)

		// Derive URL details for YAML and details section
		scheme, host, pathOnly, qkeys := parseURLDetails(o.URL)

		ym := map[string]any{
			"id":                 "occurrence/" + o.OccurrenceID,
			"occurrenceId":       o.OccurrenceID,
			"definitionId":       o.DefinitionID,
			"findingId":          o.FindingID,
			"url":                o.URL,
			"host":               host,
			"path":               pathOnly,
			"queryKeys":          strings.Join(qkeys, ", "),
			"method":             o.Method,
			"param":              o.Param,
			"attack":             o.Attack,
			"evidence":           truncate(o.Evidence, 200),
			"risk":               o.Risk,
			"riskCode":           o.RiskCode,
			"confidence":         o.Confidence,
			"sourceId":           o.SourceID,
			"analyst.status":     aStatus,
			"analyst.owner":      aOwner,
			"analyst.tags":       aTags,
			"analyst.notes":      aNotes,
			"analyst.ticketRefs": aTickets,
			"analyst.updatedAt":  aUpdated,
			"schemaVersion":      ef.SchemaVersion,
			"sourceTool":         ef.SourceTool,
			"generatedAt":        ef.GeneratedAt,
			"observedAt":         fallbackString(o.ObservedAt, ef.GeneratedAt),
			"scan.label":         fallbackString(o.ScanLabel, opts.ScanLabel),
			"riskId":             fmt.Sprintf("%d", rid),
			"aliases":            []string{alias},
			"kind":               "occurrence",
		}
		if dom != "" {
			ym["domain"] = dom
		}
		writeYAML(&b, ym)

		fmt.Fprintf(&b, "# Occurrence %s — %s\n\n", o.OccurrenceID, alias)
		// Severity callout
		sevTxt, _ := deriveSeverity(o.Risk, o.RiskCode)
		b.WriteString(calloutForSeverity(sevTxt, fmt.Sprintf("Risk: %s (%s) — Confidence: %s", o.Risk, o.RiskCode, o.Confidence)))

		if link := defLinkByID[o.DefinitionID]; link != "" {
			fmt.Fprintf(&b, "- Definition: [[%s|%s]]\n", link, o.DefinitionID)
		} else {
			fmt.Fprintf(&b, "- Definition: %s\n", o.DefinitionID)
		}
		fmt.Fprintf(&b, "- Issue: [[%s|%s]]\n\n", filepath.ToSlash(filepath.Join("occurrences", "..", "findings", o.FindingID+".md")), o.FindingID)

		fmt.Fprintf(&b, "**Endpoint:** %s %s\n\n", o.Method, o.URL)

		// Endpoint details
		b.WriteString("## Endpoint details\n\n")
		if strings.TrimSpace(o.ObservedAt) != "" {
			fmt.Fprintf(&b, "- Observed: %s\n", strings.TrimSpace(o.ObservedAt))
		}
		if strings.TrimSpace(o.ScanLabel) != "" {
			fmt.Fprintf(&b, "- Scan: %s\n", strings.TrimSpace(o.ScanLabel))
		}
		if scheme != "" {
			fmt.Fprintf(&b, "- Scheme: %s\n", scheme)
		}
		if host != "" {
			fmt.Fprintf(&b, "- Host: %s\n", host)
		}
		if pathOnly != "" {
			fmt.Fprintf(&b, "- Path: %s\n", pathOnly)
		}
		if len(qkeys) > 0 {
			fmt.Fprintf(&b, "- Query keys: %s\n", strings.Join(qkeys, ", "))
		}
		b.WriteString("\n")
		if o.Param != "" {
			fmt.Fprintf(&b, "**Param:** %s\n\n", o.Param)
		}
		if o.Attack != "" {
			fmt.Fprintf(&b, "**Attack:** `%s`\n\n", o.Attack)
		}
		if o.Evidence != "" {
			b.WriteString("## Evidence\n\n```\n")
			b.WriteString(o.Evidence)
			b.WriteString("\n```\n\n")
		}
		if strings.TrimSpace(o.Other) != "" {
			b.WriteString("## Other info\n\n")
			b.WriteString("<details>\n<summary>Show details</summary>\n\n")
			b.WriteString(strings.TrimSpace(o.Other) + "\n\n")
			b.WriteString("</details>\n\n")
		}

		// Repro snippet — prefer scanner-provided curl, fall back to synthesized
		b.WriteString("## Repro (curl)\n\n")
		b.WriteString("```bash\n")
		if o.Reproduce != nil && strings.TrimSpace(o.Reproduce.Curl) != "" {
			b.WriteString(strings.TrimSpace(o.Reproduce.Curl))
		} else {
			b.WriteString(buildCurl(o))
		}
		b.WriteString("\n```\n\n")
		if o.Reproduce != nil && len(o.Reproduce.Steps) > 0 {
			b.WriteString("### Reproduction steps\n\n")
			for i, step := range o.Reproduce.Steps {
				fmt.Fprintf(&b, "%d. %s\n", i+1, strings.TrimSpace(step))
			}
			b.WriteString("\n")
		}
		b.WriteString("_Note: review/redact sensitive headers/cookies before sharing externally._\n\n")
		// No deep links to ZAP here (requested)

		// Traffic rendered as HTTP blocks so analysts can scan request/response quickly.
		if o.Request != nil || o.Response != nil {
			b.WriteString("## Traffic\n\n")
			b.WriteString("<details>\n<summary>Show traffic</summary>\n\n")
			if o.Request != nil {
				b.WriteString("### Request\n\n")
				writeHTTPRequestBlock(&b, o.Method, o.URL, o.Request)
				b.WriteString("\n")
			}
			if o.Response != nil {
				b.WriteString("### Response\n\n")
				writeHTTPResponseBlock(&b, o.Response)
				b.WriteString("\n")
			}
			b.WriteString("</details>\n\n")
		}

		// Triage guidance — only written when a lookup function is injected
		if opts.TriageGuidanceFn != nil {
			if d, ok := defByID[o.DefinitionID]; ok {
				tips := opts.TriageGuidanceFn(d.PluginID)
				if len(tips) > 0 {
					b.WriteString("## Triage guidance\n\n")
					for _, t := range tips {
						fmt.Fprintf(&b, "- %s\n", t)
					}
					b.WriteString("\n")
				}
			}
		}

		// Workflow section (analyst notes)
		b.WriteString("## Workflow\n\n")
		scanLabelForWorkflow := strings.TrimSpace(o.ScanLabel)
		if scanLabelForWorkflow == "" {
			scanLabelForWorkflow = strings.TrimSpace(opts.ScanLabel)
		}
		if scanLabelForWorkflow == "" {
			scanLabelForWorkflow = "unlabeled"
		}
		fmt.Fprintf(&b, "- Scan: %s\n", scanLabelForWorkflow)
		fmt.Fprintf(&b, "- Status: %s\n", fallbackString(aStatus, "open"))
		if aOwner != "" {
			fmt.Fprintf(&b, "- Owner: %s\n", aOwner)
		}
		if len(aTags) > 0 {
			fmt.Fprintf(&b, "- Tags: %s\n", strings.Join(aTags, ", "))
		}
		if len(aTickets) > 0 {
			fmt.Fprintf(&b, "- Analyst cases: %s\n", formatTicketRefsMarkdown(aTickets, opts.JiraBaseURL, "_None_"))
			if raw := primaryJiraStatus(aTickets, opts.JiraStatusByKey); raw != "" {
				fmt.Fprintf(&b, "- Jira status: %s\n", raw)
			}
			b.WriteString("- Workflow source: Jira analyst case (synced at publish time)\n")
			if strings.TrimSpace(opts.JiraStatusSynced) != "" {
				fmt.Fprintf(&b, "- Jira sync: %s\n", opts.JiraStatusSynced)
			}
		}
		if aUpdated != "" {
			fmt.Fprintf(&b, "- Updated: %s\n", aUpdated)
		}

		b.WriteString("\n### Analyst notebook (from front matter)\n\n")
		if strings.TrimSpace(aNotes) != "" {
			b.WriteString(aNotes + "\n\n")
		} else {
			b.WriteString("_Add `analyst.notes` in front matter for findings, evidence pointers, and next steps._\n\n")
		}

		b.WriteString("\n> **Workflow note:** use Jira for analyst workflow state. This page is the evidence view; keep `analyst.ticketRefs`, notes, and tags aligned with the linked analyst case. Pull-based workflow writeback is legacy-only.\n")
		// Governance prompts
		b.WriteString("\n### Governance\n\n")
		b.WriteString("- False positive reason: \n")
		b.WriteString("- Acceptance justification: \n")
		b.WriteString("- Acceptance expires at (UTC): \n")
		b.WriteString("- Due at (UTC): \n")

		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	// Simple INDEX.md with status counts, optional scan label, per-domain and per-definition rollups
	index := filepath.Join(root, "INDEX.md")
	{
		// Aggregate historical counts across the vault (all occurrence files), so INDEX can differentiate sessions/scans.
		histScanTotals, _, _ := scanVaultOccurrences(occDir)

		sevOrder := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
		rankSeverity := func(sev string) int {
			if idx, ok := sevOrder[strings.ToLower(strings.TrimSpace(sev))]; ok {
				return idx
			}
			return len(sevOrder)
		}

		sortIssues := func(items []issueSummary) {
			sort.Slice(items, func(i, j int) bool {
				ri := rankSeverity(items[i].Severity)
				rj := rankSeverity(items[j].Severity)
				if ri != rj {
					return ri < rj
				}
				if items[i].Occurrences != items[j].Occurrences {
					return items[i].Occurrences > items[j].Occurrences
				}
				if items[i].URL != items[j].URL {
					return items[i].URL < items[j].URL
				}
				return items[i].Alias < items[j].Alias
			})
		}

		statusOrder := []struct {
			Label string
			Key   string
		}{
			{"Open", "open"},
			{"Triaged", "triaged"},
			{"False positive", "fp"},
			{"Accepted", "accepted"},
			{"Fixed", "fixed"},
		}

		issueStatusCounts := map[string]int{}
		for _, is := range issueSummaries {
			st := strings.TrimSpace(is.PrimaryStatus)
			if st == "" {
				st = "open"
			}
			issueStatusCounts[st]++
		}

		// domain label for header
		domainLabel := "multiple"
		if len(domainTotals) == 1 {
			for d := range domainTotals {
				domainLabel = d
			}
		} else if len(domainTotals) == 0 {
			domainLabel = "n/a"
		}

		var b strings.Builder
		var triageSection strings.Builder
		var domainSection strings.Builder
		b.WriteString("# Index\n\n")

		scanName := strings.TrimSpace(opts.ScanLabel)
		if len(scanLabels) == 1 {
			for s := range scanLabels {
				scanName = s
			}
		} else if len(scanLabels) > 1 {
			scanName = fmt.Sprintf("%d scans", len(scanLabels))
		}
		if scanName == "" {
			scanName = "Unlabeled scan"
		}

		totalOcc := len(ef.Occurrences)
		totalIssues := len(ef.Findings)
		var sevParts []string
		for _, entry := range []struct {
			Label string
			Key   string
		}{
			{"High", "high"},
			{"Medium", "medium"},
			{"Low", "low"},
			{"Info", "info"},
		} {
			if c := issueSeverityCounts[entry.Key]; c > 0 {
				sevParts = append(sevParts, fmt.Sprintf("%s: %d", entry.Label, c))
			}
		}
		summaryLine := fmt.Sprintf("Scan: %s (domain: %s) | Issues: %d | Occurrences: %d", scanName, domainLabel, totalIssues, totalOcc)
		if len(sevParts) > 0 {
			summaryLine += " | " + strings.Join(sevParts, " ")
		}
		b.WriteString(summaryLine + "\n")
		b.WriteString("\n")

		b.WriteString("## Quick navigation\n")
		b.WriteString("- [Triage board](triage-board.md)\n")
		b.WriteString("- [Issues](issues.md)\n")
		b.WriteString("- [Occurrences](occurrences.md)\n")
		b.WriteString("- [Rules](rules.md)\n")
		b.WriteString("- [By domain](by-domain.md)\n")
		b.WriteString("- [Alias Legend](LEGEND.md)\n")
		b.WriteString("- [Triage Workflow Guide](TRIAGE-GUIDE.md)\n")
		b.WriteString("- [Scans](by-scan.md)\n")
		b.WriteString("- [Executive Summary](EXECUTIVE-SUMMARY.md)\n")
		b.WriteString("\n")

		triageSection.WriteString("## Triage board\n\n")
		triageSection.WriteString("| Status | Issues | Occurrences |\n| --- | --- | --- |\n")
		for _, entry := range statusOrder {
			fmt.Fprintf(&triageSection, "| %s | %d | %d |\n", entry.Label, issueStatusCounts[entry.Key], statusCounts[entry.Key])
		}
		// Emit an "Other" row for any non-canonical status values so totals always add up.
		canonicalStatuses := map[string]struct{}{"open": {}, "triaged": {}, "fp": {}, "accepted": {}, "fixed": {}}
		otherOccCount := 0
		otherIssueCount := 0
		for k, v := range statusCounts {
			if _, known := canonicalStatuses[k]; !known {
				otherOccCount += v
			}
		}
		for k, v := range issueStatusCounts {
			if _, known := canonicalStatuses[k]; !known {
				otherIssueCount += v
			}
		}
		if otherOccCount > 0 || otherIssueCount > 0 {
			fmt.Fprintf(&triageSection, "| Other | %d | %d |\n", otherIssueCount, otherOccCount)
		}
		triageSection.WriteString("\n")
		b.WriteString(triageSection.String())

		// Priority queue: highest-severity actionable work first.
		// Resolved findings (fixed, accepted, fp) are excluded — they belong in the
		// closed queue, not the priority list.
		isActionable := func(status string) bool {
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "fixed", "accepted", "fp":
				return false
			}
			return true // open, triaged, or unset
		}
		b.WriteString("## Priority queue\n\n")
		var actionableIssues []issueSummary
		for _, is := range issueSummaries {
			if isActionable(is.PrimaryStatus) {
				actionableIssues = append(actionableIssues, is)
			}
		}
		sortIssues(actionableIssues)
		if len(actionableIssues) == 0 {
			b.WriteString("_No open issues._\n\n")
		} else {
			maxActions := 5
			if maxActions > len(actionableIssues) {
				maxActions = len(actionableIssues)
			}
			for i := 0; i < maxActions; i++ {
				is := actionableIssues[i]
				rule := is.RuleTitle
				if rule == "" {
					rule = "Rule"
				}
				endpoint := fmt.Sprintf("%s %s", strings.TrimSpace(is.Method), neuterURL(is.URL))
				fmt.Fprintf(&b, "- [%s](%s) - %s | %s | %s\n", is.Alias, is.Link, titleASCII(is.Severity), endpoint, titleASCII(fallbackString(is.PrimaryStatus, "open")))
				fmt.Fprintf(&b, "  Rule: %s\n", rule)
			}
			b.WriteString("\n")
		}

		// operationalPluginIDs holds plugin IDs for tool-health rules that are
		// not actionable findings for the target application.
		operationalPluginIDs := map[string]struct{}{
			"10116": {},
			"10109": {},
		}
		isOperational := func(is issueSummary) bool {
			_, ok := operationalPluginIDs[is.PluginID]
			return ok
		}

		// Issues table — operational rules are excluded and shown separately below.
		if len(issueSummaries) > 0 {
			b.WriteString("## Issues\n")
			b.WriteString("Sorted by severity, then endpoint.\n\n")
			b.WriteString("| Severity | Issue | Endpoint | Status | Occurrences | Rule |\n| --- | --- | --- | --- | --- | --- |\n")
			allIssues := append([]issueSummary(nil), issueSummaries...)
			sortIssues(allIssues)
			for _, is := range allIssues {
				if isOperational(is) {
					continue
				}
				status := "Open"
				if s := strings.TrimSpace(is.PrimaryStatus); s != "" {
					status = titleASCII(s)
				}
				rule := fallbackString(is.RuleTitle, "Rule")
				fmt.Fprintf(&b, "| %s | [%s](%s) | %s %s | `%s` | %d | %s |\n",
					titleASCII(is.Severity), is.Alias, is.Link,
					strings.TrimSpace(is.Method), strings.TrimSpace(is.URL),
					status,
					is.Occurrences,
					rule,
				)
			}
			b.WriteString("\n")
		}

		// Operational / Tool info section — only written when at least one operational finding exists.
		{
			var opIssues []issueSummary
			for _, is := range issueSummaries {
				if isOperational(is) {
					opIssues = append(opIssues, is)
				}
			}
			if len(opIssues) > 0 {
				sortIssues(opIssues)
				b.WriteString("## Operational / Tool info\n\n")
				b.WriteString("_Findings from tool-health rules — not actionable for the target application._\n\n")
				b.WriteString("| Finding | Risk | Occurrences |\n|---|---|---|\n")
				for _, is := range opIssues {
					fmt.Fprintf(&b, "| [%s](%s) | %s | %d |\n",
						is.Alias, is.Link,
						titleASCII(is.Severity),
						is.Occurrences,
					)
				}
				b.WriteString("\n")
			}
		}

		// Occurrence table
		if totalOcc > 0 {
			b.WriteString("## Occurrences\n\n")
			b.WriteString("| Occurrence | Endpoint | Param | Severity | Status | Issue |\n| --- | --- | --- | --- | --- | --- |\n")
			tmpOccs := make([]entities.Occurrence, len(ef.Occurrences))
			copy(tmpOccs, ef.Occurrences)
			sort.Slice(tmpOccs, func(i, j int) bool {
				si, _ := deriveSeverity(tmpOccs[i].Risk, tmpOccs[i].RiskCode)
				sj, _ := deriveSeverity(tmpOccs[j].Risk, tmpOccs[j].RiskCode)
				ri := rankSeverity(si)
				rj := rankSeverity(sj)
				if ri != rj {
					return ri < rj
				}
				if tmpOccs[i].URL != tmpOccs[j].URL {
					return tmpOccs[i].URL < tmpOccs[j].URL
				}
				if tmpOccs[i].Param != tmpOccs[j].Param {
					return tmpOccs[i].Param < tmpOccs[j].Param
				}
				return tmpOccs[i].OccurrenceID < tmpOccs[j].OccurrenceID
			})
			for _, o := range tmpOccs {
				sevTxt, _ := deriveSeverity(o.Risk, o.RiskCode)
				alias := occAliasUltraCompact(o, "")
				status := "Open"
				if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
					status = titleASCII(o.Analyst.Status)
				}
				param := strings.TrimSpace(o.Param)
				if param == "" {
					param = "(none)"
				}
				issueLink := filepath.ToSlash(filepath.Join("findings", o.FindingID+".md"))
				fmt.Fprintf(&b, "| [%s](%s) | %s %s | %s | %s | %s | [%s](%s) |\n",
					alias,
					filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")),
					strings.TrimSpace(o.Method),
					strings.TrimSpace(o.URL),
					param,
					titleASCII(sevTxt),
					status,
					o.FindingID,
					issueLink,
				)
			}
			b.WriteString("\n")
		}

		// Rules table
		if len(defSummaries) > 0 {
			tmp := make([]defSummary, len(defSummaries))
			copy(tmp, defSummaries)
			sort.Slice(tmp, func(i, j int) bool {
				if tmp[i].Total != tmp[j].Total {
					return tmp[i].Total > tmp[j].Total
				}
				if tmp[i].Severity["high"] != tmp[j].Severity["high"] {
					return tmp[i].Severity["high"] > tmp[j].Severity["high"]
				}
				return tmp[i].Title < tmp[j].Title
			})

			b.WriteString("## Rules\n\n")
			b.WriteString("| Rule | High | Medium | Low | Info | Total |\n| --- | --- | --- | --- | --- | --- |\n")
			for _, ds := range tmp {
				if ds.Total == 0 {
					// Remaining rows are zero due to sorting; avoid noisy blanks.
					break
				}
				fmt.Fprintf(&b, "| [%s (Plugin %s)](%s) | %d | %d | %d | %d | %d |\n",
					ds.Title, ds.Plugin, ds.Link,
					ds.Severity["high"], ds.Severity["medium"], ds.Severity["low"], ds.Severity["info"],
					ds.Total,
				)
			}
			b.WriteString("\n")
		}

		// Domain table (this run)
		if len(domainTotals) > 0 {
			domainSection.WriteString("## By domain\n\n")
			domainSection.WriteString("| Domain | Occurrences | Open | Triaged | FP | Accepted | Fixed | High | Medium | Low | Info |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
			var doms []string
			for d := range domainTotals {
				doms = append(doms, d)
			}
			sort.Strings(doms)
			for _, d := range doms {
				ds := domainCounts[d]
				ss := domainSeverityCounts[d]
				fmt.Fprintf(&domainSection, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n",
					d, domainTotals[d],
					ds["open"], ds["triaged"], ds["fp"], ds["accepted"], ds["fixed"],
					ss["high"], ss["medium"], ss["low"], ss["info"],
				)
			}
			domainSection.WriteString("\n")

			// Per-scan breakdown: only shown when 2+ distinct scan labels exist.
			if len(scanLabels) >= 2 {
				type scanStats struct {
					count                int
					high, med, low, info int
					minDate, maxDate     string
				}
				domainScanStats := make(map[string]map[string]*scanStats)
				for _, o := range resolvedOccs {
					dom := computeDomainLabel(o.URL, opts.SiteLabel)
					if dom == "" {
						continue
					}
					sl := strings.TrimSpace(o.ScanLabel)
					if sl == "" {
						sl = "unlabeled"
					}
					if domainScanStats[dom] == nil {
						domainScanStats[dom] = make(map[string]*scanStats)
					}
					st := domainScanStats[dom][sl]
					if st == nil {
						st = &scanStats{}
						domainScanStats[dom][sl] = st
					}
					st.count++
					sevTxt, _ := deriveSeverity(o.Risk, o.RiskCode)
					switch strings.ToLower(strings.TrimSpace(sevTxt)) {
					case "high":
						st.high++
					case "medium":
						st.med++
					case "low":
						st.low++
					default:
						st.info++
					}
					dateStr := strings.TrimSpace(o.ObservedAt)
					if len(dateStr) >= 10 {
						dateStr = dateStr[:10]
					}
					if dateStr != "" {
						if st.minDate == "" || dateStr < st.minDate {
							st.minDate = dateStr
						}
						if st.maxDate == "" || dateStr > st.maxDate {
							st.maxDate = dateStr
						}
					}
				}

				domainSection.WriteString("## Per scan breakdown\n\n")
				var breakdownDoms []string
				for d := range domainScanStats {
					breakdownDoms = append(breakdownDoms, d)
				}
				sort.Strings(breakdownDoms)
				for _, d := range breakdownDoms {
					fmt.Fprintf(&domainSection, "### %s\n\n", d)
					domainSection.WriteString("| Scan | Occurrences | High | Med | Low | Info | Date range |\n|---|---|---|---|---|---|---|\n")
					scanMap := domainScanStats[d]
					var scanNames []string
					for sn := range scanMap {
						scanNames = append(scanNames, sn)
					}
					sort.Strings(scanNames)
					for _, sn := range scanNames {
						st := scanMap[sn]
						dateRange := st.minDate
						if st.maxDate != "" && st.maxDate != st.minDate {
							dateRange = st.minDate + " \u2192 " + st.maxDate
						}
						fmt.Fprintf(&domainSection, "| %s | %d | %d | %d | %d | %d | %s |\n",
							sn, st.count, st.high, st.med, st.low, st.info, dateRange,
						)
					}
					domainSection.WriteString("\n")
				}
			}

			b.WriteString(domainSection.String())
		}

		// Historical scans (vault)
		if len(histScanTotals) > 0 {
			b.WriteString("## Vault scans\n\n")
			b.WriteString("| Scan | Occurrences |\n| --- | --- |\n")
			var scans []string
			for s := range histScanTotals {
				scans = append(scans, s)
			}
			sort.Strings(scans)
			for _, s := range scans {
				fmt.Fprintf(&b, "| %s | %d |\n", s, histScanTotals[s])
			}
			b.WriteString("\n")
		}

		indexContent := b.String()
		if err := os.WriteFile(index, []byte(indexContent), 0o644); err != nil {
			return err
		}
		if err := writeSectionPage(root, "issues.md", "Issues", extractMarkdownSection(indexContent, "Issues")); err != nil {
			return err
		}
		if err := writeSectionPage(root, "occurrences.md", "Occurrences", extractMarkdownSection(indexContent, "Occurrences")); err != nil {
			return err
		}
		if err := writeSectionPage(root, "rules.md", "Rules", extractMarkdownSection(indexContent, "Rules")); err != nil {
			return err
		}
		// Companion pages for quick navigation
		tbContent := triageSection.String()
		if strings.TrimSpace(tbContent) == "" {
			tbContent = "## Triage board\n\n_No data yet_\n"
		}

		// Open findings queue — severity-sorted list of open/untriaged findings.
		{
			const triageCap = 50
			// Collect findings whose primary status is open (empty counts as open).
			type openFinding struct {
				is      issueSummary
				sevRank int
			}
			var openFindings []openFinding
			for _, is := range issueSummaries {
				st := strings.TrimSpace(is.PrimaryStatus)
				if st != "" && st != "open" {
					continue
				}
				openFindings = append(openFindings, openFinding{
					is:      is,
					sevRank: rankSeverity(is.Severity),
				})
			}
			sort.Slice(openFindings, func(i, j int) bool {
				if openFindings[i].sevRank != openFindings[j].sevRank {
					return openFindings[i].sevRank < openFindings[j].sevRank
				}
				if openFindings[i].is.URL != openFindings[j].is.URL {
					return openFindings[i].is.URL < openFindings[j].is.URL
				}
				return openFindings[i].is.Alias < openFindings[j].is.Alias
			})

			if len(openFindings) > 0 {
				var qb strings.Builder
				qb.WriteString("## Open findings queue\n\n")
				sevBands := []struct {
					Label string
					Key   string
				}{
					{"High", "high"},
					{"Medium", "medium"},
					{"Low", "low"},
					{"Informational", "informational"},
				}
				for _, band := range sevBands {
					var band_items []openFinding
					for _, of := range openFindings {
						sev := strings.ToLower(strings.TrimSpace(of.is.Severity))
						if sev == "" {
							sev = "informational"
						}
						if sev == band.Key || (band.Key == "informational" && (sev == "info" || sev == "informational")) {
							band_items = append(band_items, of)
						}
					}
					if len(band_items) == 0 {
						continue
					}
					fmt.Fprintf(&qb, "### %s (%d)\n\n", band.Label, len(band_items))
					limit := triageCap
					if limit > len(band_items) {
						limit = len(band_items)
					}
					for i := 0; i < limit; i++ {
						of := band_items[i]
						is := of.is
						ruleTitle := fallbackString(is.RuleTitle, "Rule")
						method := strings.TrimSpace(is.Method)
						urlPath := ""
						if u, err2 := neturl.Parse(is.URL); err2 == nil {
							urlPath = u.Path
						}
						if urlPath == "" {
							urlPath = is.URL
						}
						caption := ruleTitle + " — " + method + " " + urlPath
						fmt.Fprintf(&qb, "- [[%s|%s]] (Risk: %s)\n",
							is.Link, caption, titleASCII(is.Severity))
					}
					if limit < len(band_items) {
						fmt.Fprintf(&qb, "_... %d more_\n", len(band_items)-limit)
					}
					qb.WriteString("\n")
				}
				tbContent += qb.String()
			}
		}

		var tuningCandidates []issueSummary
		for _, is := range issueSummaries {
			if is.TuningCandidate {
				tuningCandidates = append(tuningCandidates, is)
			}
		}
		if len(tuningCandidates) > 0 {
			sort.Slice(tuningCandidates, func(i, j int) bool {
				if tuningCandidates[i].TuningScans != tuningCandidates[j].TuningScans {
					return tuningCandidates[i].TuningScans > tuningCandidates[j].TuningScans
				}
				return tuningCandidates[i].Alias < tuningCandidates[j].Alias
			})
			var tb strings.Builder
			tb.WriteString("## Tuning candidates\n\n")
			for _, is := range tuningCandidates {
				ruleTitle := fallbackString(is.RuleTitle, "Rule")
				fmt.Fprintf(&tb, "- [[%s|%s]] - false positive across %d scans\n", is.Link, ruleTitle, is.TuningScans)
			}
			tb.WriteString("\n")
			tbContent += tb.String()
		}

		if err := os.WriteFile(filepath.Join(root, "triage-board.md"), []byte("# Triage board\n\n"+tbContent), 0o644); err != nil {
			return err
		}
		dbContent := domainSection.String()
		if strings.TrimSpace(dbContent) == "" {
			dbContent = "## By domain\n\n_No domain data yet_\n"
		}
		if err := os.WriteFile(filepath.Join(root, "by-domain.md"), []byte("# By domain\n\n"+dbContent), 0o644); err != nil {
			return err
		}
		// New: latest scan spotlight (if we have one)
		if latestScanLabel != "" && len(seenByKey) > 0 {
			var spot strings.Builder
			spot.WriteString("# Latest scan spotlight\n\n")
			spot.WriteString(fmt.Sprintf("Scan: %s\n\n", latestScanLabel))
			spot.WriteString("| Occurrence | Endpoint | Severity | Status | Issue |\n| --- | --- | --- | --- | --- |\n")
			for _, o := range newestOccs {
				key := strings.Join([]string{strings.TrimSpace(o.FindingID), strings.TrimSpace(o.URL), strings.TrimSpace(o.Param), strings.TrimSpace(o.Attack)}, "|")
				if !seenByKey[key] {
					continue
				}
				sevTxt, _ := deriveSeverity(o.Risk, o.RiskCode)
				status := "Open"
				if o.Analyst != nil && strings.TrimSpace(o.Analyst.Status) != "" {
					status = titleASCII(o.Analyst.Status)
				}
				issueLink := filepath.ToSlash(filepath.Join("findings", o.FindingID+".md"))
				fmt.Fprintf(&spot, "| [%s](%s) | %s %s | %s | %s | [%s](%s) |\n",
					occAliasUltraCompact(o, ""),
					filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")),
					strings.TrimSpace(o.Method), strings.TrimSpace(o.URL),
					titleASCII(sevTxt),
					status,
					o.FindingID, issueLink)
			}
			if err := os.WriteFile(filepath.Join(root, "latest-scan.md"), []byte(spot.String()), 0o644); err != nil {
				return err
			}
		}
	}
	// New static and dynamic companion pages.
	if err := writeLegend(root); err != nil {
		return err
	}
	if err := writeTriageGuide(root); err != nil {
		return err
	}
	if err := writeByScan(root, ef, opts); err != nil {
		return err
	}
	if err := writeExecutiveSummary(root, ef, opts, ef.GeneratedAt); err != nil {
		return err
	}

	// Dashboard is best-effort; do not fail vault writes if it errors.
	_ = GenerateDashboard(root)

	return nil
}

func writeYAML(b *strings.Builder, kv map[string]any) {
	b.WriteString("---\n")
	// stable order
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := kv[k].(type) {
		case string:
			force := strings.HasPrefix(k, "analyst.")
			if strings.TrimSpace(v) == "" && !force {
				continue
			}
			fmt.Fprintf(b, "%s: %q\n", k, v)
		case []string:
			force := strings.HasPrefix(k, "analyst.")
			if len(v) == 0 && !force {
				continue
			}
			fmt.Fprintf(b, "%s:\n", k)
			for _, s := range v {
				if strings.TrimSpace(s) == "" && !force {
					continue
				}
				fmt.Fprintf(b, "  - %q\n", s)
			}
			if len(v) == 0 && force {
				// emit an empty list marker to remind analysts to fill it
				fmt.Fprintf(b, "  # add values\n")
			}
		default:
			// fall back to plain rendering
			fmt.Fprintf(b, "%s: %v\n", k, v)
		}
	}
	b.WriteString("---\n\n")
}

// addStatusToYAMLStrAny adapts addStatusToYAML for map[string]any
func addStatusToYAMLStrAny(kv map[string]any, prefix string, m map[string]int) {
	for _, k := range []string{"open", "triaged", "fp", "accepted", "fixed"} {
		if m[k] > 0 {
			kv[prefix+k] = fmt.Sprintf("%d", m[k])
		}
	}
}

// defaultBodyTruncateBytes is the display limit for request/response body snippets.
const defaultBodyTruncateBytes = 4096

var nonWord = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonWord.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "untitled"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// regexHintAndExample returns a short human-friendly hint and a simple example
// for common regex patterns found in ZAP rules. Best-effort only.
func regexHintAndExample(pattern string) (string, string) {
	p := strings.TrimSpace(pattern)
	lp := strings.ToLower(p)

	// Strip common anchors/boundaries for easier matching
	p = strings.ReplaceAll(p, "\\b", "")
	p = strings.TrimPrefix(p, "^")
	p = strings.TrimSuffix(p, "$")

	// Web Storage keywords
	if strings.Contains(lp, "localstorage") || strings.Contains(lp, "sessionstorage") {
		return "Looks for HTML5 Web Storage usage in content.", "localStorage.setItem(\"key\", \"value\")"
	}

	// Email address
	if strings.Contains(p, "@") && strings.Contains(lp, ".") && (strings.Contains(lp, "[a-z") || strings.Contains(lp, "[a-za-z")) {
		return "Email address pattern (name@domain).", "alice@example.com"
	}

	// IPv4 address
	if strings.Contains(lp, "\\d{1,3}\\.") || strings.Contains(lp, "[0-9]{1,3}\\.") || strings.Contains(lp, "(?:[0-9]{1,3}\\.){3}") {
		return "IPv4 address (four dot-separated numbers).", "192.168.0.1"
	}

	// UUID (hex groups separated by dashes)
	if regexp.MustCompile(`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).MatchString(p) {
		return "UUID/GUID (hex groups with dashes).", "123e4567-e89b-12d3-a456-426614174000"
	}

	// Hex lengths (crypto digests)
	if regexp.MustCompile(`(?i)\[?[a-f0-9A-F]\]?\{32\}|(?i)[a-f0-9]{32}`).MatchString(p) {
		return "32 hex chars (often an MD5 digest).", "e2fc714c4727ee9395f324cd2e7f331f"
	}
	if regexp.MustCompile(`(?i)[a-f0-9]{40}`).MatchString(p) {
		return "40 hex chars (often a SHA-1 digest).", "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	}
	if regexp.MustCompile(`(?i)[a-f0-9]{64}`).MatchString(p) {
		return "64 hex chars (often a SHA-256 digest).", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}

	// SSN-like numeric groups (###-##-####)
	if strings.Contains(p, "[0-9]{3}-[0-9]{2}-[0-9]{4}") || strings.Contains(lp, `\d{3}-\d{2}-\d{4}`) {
		return "U.S. SSN-like pattern (three-two-four digits).", "123-45-6789"
	}

	// Bearer/JWT-like tokens
	if strings.Contains(lp, "bearer") || regexp.MustCompile(`(?i)[a-z0-9_\-]{10,}\.([a-z0-9_\-]{10,}\.)?[a-z0-9_\-]{10,}`).MatchString(lp) {
		return "Bearer/JWT-like token (dot-separated base64url).", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.sig"
	}

	// Generic guidance for digit groups like [0-9]{n}
	if regexp.MustCompile(`(\\d|\[0-9\])\{\d+\}`).MatchString(p) {
		// Try to produce a simple numeric example by replacing {n} with n digits
		ex := regexp.MustCompile(`(\\d|\[0-9\])\{(\d+)\}`).ReplaceAllStringFunc(p, func(m string) string {
			sub := regexp.MustCompile(`(\\d|\[0-9\])\{(\d+)\}`).FindStringSubmatch(m)
			if len(sub) == 3 {
				nStr := sub[2]
				n := 0
				fmt.Sscanf(nStr, "%d", &n)
				if n <= 0 {
					n = 3
				}
				// return n digits cycling 1234567890
				digits := "1234567890"
				var b strings.Builder
				for i := 0; i < n; i++ {
					b.WriteByte(digits[i%len(digits)])
				}
				return b.String()
			}
			return "000"
		})
		// Clean leftover escapes and character classes
		ex = strings.ReplaceAll(ex, "[0-9]", "0")
		ex = strings.ReplaceAll(ex, "\\d", "0")
		ex = strings.ReplaceAll(ex, "\\.", ".")
		ex = strings.ReplaceAll(ex, "\\-", "-")
		ex = strings.ReplaceAll(ex, "^", "")
		ex = strings.ReplaceAll(ex, "$", "")
		ex = strings.ReplaceAll(ex, "\\s", " ")
		ex = strings.ReplaceAll(ex, "\\_", "_")
		ex = regexp.MustCompile(`\[[^\]]+\]`).ReplaceAllString(ex, "a")
		ex = strings.TrimSpace(ex)
		if ex != "" && len(ex) <= 80 {
			return "Digits with fixed group lengths.", ex
		}
	}

	// Fallback generic message
	return "Regular expression; see pattern for details.", ""
}

// titleASCII makes "open" -> "Open" (ASCII only, suitable for simple status labels)
func titleASCII(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// Ultra-compact alias helpers
// Pattern: RULE_ACRO + " " + basename + "-" + 4hex(code)

func defAliasUltraCompact(d entities.Definition) string {
	acro := ruleAcronym(firstNonEmpty(d.Alert, d.Name, d.PluginID))
	code := shortHexSuffix(d.DefinitionID, 4)
	return acro + "-" + code
}

func findAliasUltraCompact(f entities.Finding, ruleName string) string {
	acro := ruleAcronym(firstNonEmpty(ruleName, f.PluginID))
	base := urlBasename(f.URL)
	code := shortHexSuffix(f.FindingID, 4)
	if base == "" {
		return acro + "-" + code
	}
	return acro + " " + base + "-" + code
}

func occAliasUltraCompact(o entities.Occurrence, ruleName string) string {
	acro := ruleAcronym(firstNonEmpty(ruleName, o.DefinitionID))
	base := urlBasename(o.URL)
	code := shortHexSuffix(o.OccurrenceID, 4)
	if base == "" {
		return acro + "-" + code
	}
	return acro + " " + base + "-" + code
}

func ruleAcronym(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return "ALRT"
	}
	// split on non-alnum boundaries
	parts := regexp.MustCompile(`[^A-Za-z0-9]+`).Split(n, -1)
	// stop words to drop
	stop := map[string]struct{}{"header": {}, "missing": {}, "not": {}, "set": {}, "detected": {}, "found": {}, "the": {}, "and": {}, "of": {}, "to": {}, "in": {}}
	acro := make([]rune, 0, 6)
	for _, p := range parts {
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if _, ok := stop[low]; ok {
			continue
		}
		r := []rune(p)
		acro = append(acro, unicode.ToUpper(r[0]))
		if len(acro) >= 6 {
			break
		}
	}
	if len(acro) == 0 {
		return "ALRT"
	}
	// prefer 3-5 chars when possible
	if len(acro) > 5 {
		return string(acro[:5])
	}
	return string(acro)
}

func urlBasename(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		segs := strings.Split(strings.Trim(raw, "/"), "/")
		b := segs[len(segs)-1]
		b = strings.TrimSpace(b)
		b = collapseSpaces(b)
		return b
	}
	p := u.Path
	if p == "" || p == "/" {
		if u.Host != "" {
			return u.Host
		}
		return "root"
	}
	// decode percent-escapes
	if dp, derr := neturl.PathUnescape(p); derr == nil {
		p = dp
	}
	b := pathpkg.Base(p)
	b = strings.TrimSpace(b)
	b = collapseSpaces(b)
	if b == "." || b == "/" {
		return "root"
	}
	return b
}

// Helper: collapse multiple spaces to a single space
func collapseSpaces(s string) string {
	s = strings.TrimSpace(s)
	spaceRe := regexp.MustCompile(`\s+`)
	return spaceRe.ReplaceAllString(s, " ")
}

// Obsidian callout for severity
func calloutForSeverity(sev string, text string) string {
	sev = strings.ToLower(strings.TrimSpace(sev))
	kind := "note"
	switch sev {
	case "high":
		kind = "warning"
	case "medium":
		kind = "info"
	case "low", "info":
		kind = "note"
	}
	return "> [!" + strings.ToUpper(kind[:1]) + kind[1:] + "]\n> " + text + "\n\n"
}

// isCustomRule returns true when a definition is a project-specific custom rule
// rather than a built-in ZAP plugin. Detection criteria (any one is sufficient):
//   - pluginID starts with "zap-"
//   - Detection.RuleSource == "custom"
//   - Detection is nil and pluginID is not a pure numeric string
func isCustomRule(def entities.Definition) bool {
	return entities.IsCustomDefinition(&def)
}

// headerValue finds a header value by case-insensitive name
func headerValue(h []entities.Header, name string) string {
	ln := strings.ToLower(name)
	for _, x := range h {
		if strings.ToLower(strings.TrimSpace(x.Name)) == ln {
			return strings.TrimSpace(x.Value)
		}
	}
	return ""
}

// trafficHeaderValue applies a safe floor redaction to header values written in the
// Traffic section of an occurrence note. Authorization and Cookie/Set-Cookie are always
// masked, matching the behaviour of buildCurl, so that the Traffic section is never
// more revealing than the curl snippet shown immediately below it.
func trafficHeaderValue(name, value string) string {
	low := strings.ToLower(strings.TrimSpace(name))
	switch low {
	case "authorization":
		return "<redacted>"
	case "cookie", "set-cookie":
		return "<cookie>"
	}
	return value
}

// buildCurl creates a basic curl command with small body when safe
func buildCurl(o entities.Occurrence) string {
	method := strings.ToUpper(strings.TrimSpace(o.Method))
	if method == "" {
		method = "GET"
	}
	var parts []string
	parts = append(parts, "curl")
	if method != "GET" {
		parts = append(parts, "-X", method)
	}
	// Include a few headers (redacted)
	added := 0
	if o.Request != nil {
		for _, h := range o.Request.Headers {
			name := strings.TrimSpace(h.Name)
			val := strings.TrimSpace(h.Value)
			if name == "" || val == "" {
				continue
			}
			low := strings.ToLower(name)
			if low == "authorization" {
				val = "<redacted>"
			}
			if low == "cookie" {
				val = "<cookie>"
			}
			if low == "host" {
				continue
			}
			parts = append(parts, "-H", `"`+strings.ReplaceAll(name+": "+val, `"`, `\"`)+`"`)
			added++
			if added >= 5 {
				break
			}
		}
		// Small body support for non-GET
		if method != "GET" && o.Request.BodySnippet != "" && len(o.Request.BodySnippet) <= 512 {
			ct := headerValue(o.Request.Headers, "Content-Type")
			body := redactBody(o.Request.BodySnippet)
			if strings.Contains(strings.ToLower(ct), "application/json") {
				parts = append(parts, "-H", `"Content-Type: application/json"`)
				parts = append(parts, "--data", fmt.Sprintf("%q", body))
			} else if strings.Contains(strings.ToLower(ct), "application/x-www-form-urlencoded") {
				parts = append(parts, "--data", fmt.Sprintf("%q", body))
			} else {
				parts = append(parts, "--data-binary", fmt.Sprintf("%q", body))
			}
		}
	}
	parts = append(parts, fmt.Sprintf("\"%s\"", o.URL))
	return strings.Join(parts, " ")
}

// redactBody scrubs obvious secrets in small payloads
func redactBody(s string) string {
	// simple patterns: password, pwd, secret, token
	re := regexp.MustCompile(`(?i)(password|pwd|secret|token)"?\s*:\s*"[^"]*"`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		// replace value with <redacted>
		i := strings.Index(m, ":")
		if i < 0 {
			return m
		}
		return m[:i+1] + " \"<redacted>\""
	})
}

// deriveSeverity maps textual/encoded risk to a normalized severity and numeric id.
func deriveSeverity(risk, riskCode string) (string, int) {
	r := strings.ToLower(strings.TrimSpace(risk))
	if r == "" {
		r = strings.TrimSpace(riskCode)
	}
	switch r {
	case "3", "high":
		return "high", 3
	case "2", "medium":
		return "medium", 2
	case "1", "low":
		return "low", 1
	case "0", "informational", "info":
		return "info", 0
	default:
		switch strings.TrimSpace(riskCode) {
		case "3":
			return "high", 3
		case "2":
			return "medium", 2
		case "1":
			return "low", 1
		case "0":
			return "info", 0
		}
	}
	return "info", 0
}

// shortHexSuffix returns a lower-hex suffix of length n from an id; falls back to runes.
func shortHexSuffix(id string, n int) string {
	hexset := "0123456789abcdefABCDEF"
	buf := make([]rune, 0, n)
	for i := len(id) - 1; i >= 0 && len(buf) < n; i-- {
		ch := rune(id[i])
		if strings.ContainsRune(hexset, ch) {
			buf = append([]rune{unicode.ToLower(ch)}, buf...)
		}
	}
	if len(buf) < n {
		r := []rune(id)
		if len(r) <= n {
			return string(r)
		}
		return string(r[len(r)-n:])
	}
	return string(buf)
}

// computeDomainLabel derives a domain-like label for grouping.
// Priority: override > URL host (if not redacted) > pseudo label from URL hash.
func computeDomainLabel(rawURL, override string) string {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	if host != "" && !looksRedactedHost(host) {
		return host
	}
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}
	return "site-" + shortHexSuffix(shortHashSafe(rawURL), 6)
}

// neuterURL strips schemes so rendered next-action text is not a live link.
func neuterURL(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "//")
	return s
}

func looksRedactedHost(h string) bool {
	lh := strings.ToLower(strings.TrimSpace(h))
	if lh == "localhost" || lh == "example.com" || strings.Contains(lh, "redact") {
		return true
	}
	// simple IPv4 check
	ipRe := regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	return ipRe.MatchString(lh)
}

// shortHashSafe: lightweight FNV-1a 64-bit as hex string
func shortHashSafe(s string) string {
	var hash uint64 = 1469598103934665603
	const prime uint64 = 1099511628211
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime
	}
	const hexdigits = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hexdigits[hash&0xF]
		hash >>= 4
	}
	return string(buf[:])
}

// parseURLDetails returns scheme, host, path, and query keys from a URL string
func parseURLDetails(raw string) (scheme, host, pathOnly string, queryKeys []string) {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return "", "", "", nil
	}
	scheme = u.Scheme
	host = u.Host
	pathOnly = u.Path
	q := u.Query()
	for k := range q {
		queryKeys = append(queryKeys, k)
	}
	sort.Strings(queryKeys)
	return
}

// scanVaultOccurrences reads existing occurrence markdown files and aggregates counts per scan label and domain.
// Returns:
// - scanTotals: scan -> total occurrences
// - domainTotals: scan -> domain -> total occurrences
// - domainStatus: scan -> domain -> status -> count
func scanVaultOccurrences(occDir string) (map[string]int, map[string]map[string]int, map[string]map[string]map[string]int) {
	scanTotals := map[string]int{}
	domainTotals := map[string]map[string]int{}
	domainStatus := map[string]map[string]map[string]int{}
	entries, err := os.ReadDir(occDir)
	if err != nil {
		return scanTotals, domainTotals, domainStatus
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(occDir, e.Name()))
		if err != nil {
			continue
		}
		y := extractFrontmatter(string(b))
		scan := strings.TrimSpace(y["scan.label"]) // may be empty
		if scan == "" {
			scan = "unlabeled"
		}
		dom := strings.TrimSpace(y["domain"]) // may be empty
		if dom == "" {
			dom = computeDomainLabel(strings.TrimSpace(y["url"]), "")
		}
		st := entities.CanonicalAnalystStatus(strings.TrimSpace(y["analyst.status"])) // may be empty
		if st == "" {
			st = "open"
		}
		scanTotals[scan]++
		if _, ok := domainTotals[scan]; !ok {
			domainTotals[scan] = map[string]int{}
		}
		if _, ok := domainStatus[scan]; !ok {
			domainStatus[scan] = map[string]map[string]int{}
		}
		if _, ok := domainStatus[scan][dom]; !ok {
			domainStatus[scan][dom] = map[string]int{}
		}
		domainTotals[scan][dom]++
		domainStatus[scan][dom][st]++
	}
	return scanTotals, domainTotals, domainStatus
}

type occMeta struct {
	Analyst    *entities.Analyst
	ObservedAt string
	ScanLabel  string
}

// loadOccurrenceMeta pulls analyst/status + observedAt/scan labels from existing occurrence files.
// This lets us preserve triage state across regeneration runs.
func loadOccurrenceMeta(occDir string) map[string]occMeta {
	out := map[string]occMeta{}
	entries, err := os.ReadDir(occDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(occDir, e.Name()))
		if err != nil {
			continue
		}
		y := extractFrontmatter(string(b))
		id := strings.TrimSpace(y["occurrenceId"])
		if id == "" {
			id = strings.TrimSpace(y["id"])
		}
		if id == "" {
			continue
		}
		meta := occMeta{
			ObservedAt: strings.TrimSpace(y["observedAt"]),
			ScanLabel:  strings.TrimSpace(y["scan.label"]),
		}
		analyst := entities.Analyst{
			Status:    entities.CanonicalAnalystStatus(strings.TrimSpace(y["analyst.status"])),
			Owner:     strings.TrimSpace(y["analyst.owner"]),
			Notes:     strings.TrimSpace(y["analyst.notes"]),
			UpdatedAt: strings.TrimSpace(y["analyst.updatedAt"]),
		}
		if tags := strings.TrimSpace(y["analyst.tags"]); tags != "" {
			analyst.Tags = splitCommaList(tags)
		}
		if tickets := strings.TrimSpace(y["analyst.ticketRefs"]); tickets != "" {
			analyst.TicketRefs = splitCommaList(tickets)
		}
		if analyst.Status != "" || analyst.Owner != "" || analyst.Notes != "" || analyst.UpdatedAt != "" || len(analyst.Tags) > 0 || len(analyst.TicketRefs) > 0 {
			meta.Analyst = &analyst
		}
		out[id] = meta
	}
	return out
}

// loadFindingMeta reads analyst state from existing finding markdown pages so
// hand-edits to finding YAML (status, owner, tags, notes, rationale,
// ticketRefs, updatedAt) survive a vault rebuild. Returns a map keyed by
// findingId; entries are nil when the page has no analyst state to preserve.
func loadFindingMeta(findDir string) map[string]*entities.Analyst {
	out := map[string]*entities.Analyst{}
	entries, err := os.ReadDir(findDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(findDir, e.Name()))
		if err != nil {
			continue
		}
		y := extractFrontmatter(string(b))
		id := strings.TrimSpace(y["findingId"])
		if id == "" {
			id = strings.TrimSpace(y["id"])
		}
		if id == "" {
			continue
		}
		analyst := &entities.Analyst{
			Status:    entities.CanonicalAnalystStatus(strings.TrimSpace(y["analyst.status"])),
			Owner:     strings.TrimSpace(y["analyst.owner"]),
			Notes:     strings.TrimSpace(y["analyst.notes"]),
			Rationale: strings.TrimSpace(y["analyst.rationale"]),
			UpdatedAt: strings.TrimSpace(y["analyst.updatedAt"]),
		}
		if tags := strings.TrimSpace(y["analyst.tags"]); tags != "" {
			analyst.Tags = splitCommaList(tags)
		}
		if tickets := strings.TrimSpace(y["analyst.ticketRefs"]); tickets != "" {
			analyst.TicketRefs = splitCommaList(tickets)
		}
		if analyst.Status == "" && analyst.Owner == "" && analyst.Notes == "" &&
			analyst.Rationale == "" && analyst.UpdatedAt == "" &&
			len(analyst.Tags) == 0 && len(analyst.TicketRefs) == 0 {
			continue
		}
		out[id] = analyst
	}
	return out
}

// mergeFindingAnalyst fills gaps in cur from prior. The input entities file
// (cur) is authoritative — only missing scalars and unioned tag/ticket
// collections are taken from prior so a clean re-publish reflects upstream
// truth while hand-edits that have no upstream counterpart survive.
func mergeFindingAnalyst(cur, prior *entities.Analyst) *entities.Analyst {
	if prior == nil {
		return cur
	}
	if cur == nil {
		cp := *prior
		return &cp
	}
	if cur.Status == "" && prior.Status != "" {
		cur.Status = prior.Status
	}
	if cur.Owner == "" && prior.Owner != "" {
		cur.Owner = prior.Owner
	}
	if cur.Notes == "" && prior.Notes != "" {
		cur.Notes = prior.Notes
	}
	if cur.Rationale == "" && prior.Rationale != "" {
		cur.Rationale = prior.Rationale
	}
	if cur.UpdatedAt == "" && prior.UpdatedAt != "" {
		cur.UpdatedAt = prior.UpdatedAt
	}
	cur.Tags = unionPreserve(cur.Tags, prior.Tags)
	cur.TicketRefs = unionPreserve(cur.TicketRefs, prior.TicketRefs)
	return cur
}

func unionPreserve(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func splitCommaList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseObservedTime(raw string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}
	}
	return t
}

func formatShortDate(raw string) string {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return t.Format("2006-01-02")
}

func observedBounds(occs []entities.Occurrence, fallback string) (string, string) {
	var first, last time.Time
	var firstRaw, lastRaw string
	for _, o := range occs {
		ts := strings.TrimSpace(o.ObservedAt)
		if ts == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			if first.IsZero() || t.Before(first) {
				first = t
				firstRaw = ts
			}
			if last.IsZero() || t.After(last) {
				last = t
				lastRaw = ts
			}
		} else {
			if firstRaw == "" || ts < firstRaw {
				firstRaw = ts
			}
			if lastRaw == "" || ts > lastRaw {
				lastRaw = ts
			}
		}
	}
	if firstRaw == "" {
		firstRaw = fallback
	}
	if lastRaw == "" {
		lastRaw = fallback
	}
	return firstRaw, lastRaw
}

func summarizeStatusCounts(sc map[string]int) (string, string) {
	if len(sc) == 0 {
		return "open", "open:0"
	}
	known := []string{"open", "triaged", "accepted", "fixed", "fp"}
	seen := map[string]bool{}
	var summary []string
	primary := ""
	primaryCount := -1

	appendStatus := func(name string) {
		count := sc[name]
		summary = append(summary, fmt.Sprintf("%s:%d", name, count))
		if count > primaryCount {
			primary = name
			primaryCount = count
		}
	}

	for _, name := range known {
		if _, ok := sc[name]; ok {
			appendStatus(name)
			seen[name] = true
		}
	}
	var extras []string
	for name := range sc {
		if !seen[name] {
			extras = append(extras, name)
		}
	}
	sort.Strings(extras)
	for _, name := range extras {
		appendStatus(name)
	}
	if primary == "" {
		primary = "open"
	}
	return primary, strings.Join(summary, ", ")
}

func collectAnalystSet(occs []entities.Occurrence, fn func(*entities.Analyst) []string) []string {
	set := map[string]struct{}{}
	for _, o := range occs {
		if o.Analyst == nil {
			continue
		}
		vals := fn(o.Analyst)
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func unionStringsOrdered(preferred []string, fallback []string) []string {
	seen := map[string]struct{}{}
	var out []string
	appendAll := func(values []string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	appendAll(preferred)
	appendAll(fallback)
	if len(out) == 0 {
		return nil
	}
	return out
}

func recurringFalsePositiveTuningCandidate(status string, occs []entities.Occurrence) (bool, int) {
	if strings.TrimSpace(status) != "fp" {
		return false, 0
	}
	scans := distinctScanLabels(occs)
	if len(scans) < 2 {
		return false, len(scans)
	}
	return true, len(scans)
}

func distinctScanLabels(occs []entities.Occurrence) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, occ := range occs {
		scan := strings.TrimSpace(occ.ScanLabel)
		if scan == "" {
			continue
		}
		if _, ok := seen[scan]; ok {
			continue
		}
		seen[scan] = struct{}{}
		out = append(out, scan)
	}
	sort.Strings(out)
	return out
}
func latestTimestampString(values ...string) string {
	var latest time.Time
	latestRaw := ""
	hasParsed := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, value); err == nil {
			if !hasParsed || t.After(latest) {
				latest = t
				latestRaw = value
				hasParsed = true
			}
			continue
		}
		if !hasParsed && (latestRaw == "" || strings.Compare(value, latestRaw) > 0) {
			latestRaw = value
		}
	}
	return latestRaw
}

func mergeAnalystNotes(preferred string, fallback []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	appendLines := func(note string) {
		for _, line := range strings.Split(strings.TrimSpace(note), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			out = append(out, line)
			if len(out) >= limit {
				return
			}
		}
	}
	appendLines(preferred)
	if len(out) >= limit {
		return out
	}
	for _, note := range fallback {
		note = strings.TrimSpace(note)
		if note == "" {
			continue
		}
		if _, ok := seen[note]; ok {
			continue
		}
		seen[note] = struct{}{}
		out = append(out, note)
		if len(out) >= limit {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
func latestAnalystUpdate(occs []entities.Occurrence) string {
	var latest time.Time
	var latestRaw string
	for _, o := range occs {
		if o.Analyst == nil {
			continue
		}
		ts := strings.TrimSpace(o.Analyst.UpdatedAt)
		if ts == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			if t.After(latest) {
				latest = t
				latestRaw = ts
			}
		} else if latestRaw == "" || strings.Compare(ts, latestRaw) > 0 {
			latestRaw = ts
		}
	}
	return latestRaw
}

func collectAnalystNotes(occs []entities.Occurrence, limit int) []string {
	if limit <= 0 {
		return nil
	}
	var notes []string
	seen := map[string]struct{}{}
	for _, o := range occs {
		if o.Analyst == nil {
			continue
		}
		note := strings.TrimSpace(o.Analyst.Notes)
		if note == "" {
			continue
		}
		lines := strings.Split(note, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			notes = append(notes, line)
			seen[line] = struct{}{}
			break
		}
		if len(notes) >= limit {
			break
		}
	}
	return notes
}

func containsStringFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func formatListOrPlaceholder(items []string, placeholder string) string {
	if len(items) == 0 {
		return placeholder
	}
	return strings.Join(items, ", ")
}

func formatTicketRefsMarkdown(refs []string, jiraBaseURL, placeholder string) string {
	items := trimStrings(refs)
	if len(items) == 0 {
		return placeholder
	}
	formatted := make([]string, 0, len(items))
	for _, ref := range items {
		formatted = append(formatted, formatTicketRefMarkdown(ref, jiraBaseURL))
	}
	return strings.Join(formatted, ", ")
}

func formatTicketRefMarkdown(ref, jiraBaseURL string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if isHTTPURL(ref) {
		return fmt.Sprintf("[%s](%s)", ref, ref)
	}
	if isJiraIssueKey(ref) && strings.TrimSpace(jiraBaseURL) != "" {
		base := strings.TrimRight(strings.TrimSpace(jiraBaseURL), "/")
		return fmt.Sprintf("[%s](%s/browse/%s)", ref, base, ref)
	}
	return ref
}

func primaryJiraStatus(refs []string, statusByKey map[string]string) string {
	if len(refs) == 0 || len(statusByKey) == 0 {
		return ""
	}
	for _, ref := range refs {
		key := strings.TrimSpace(ref)
		if isHTTPURL(key) {
			parts := strings.Split(strings.TrimRight(key, "/"), "/")
			key = parts[len(parts)-1]
		}
		if !isJiraIssueKey(key) {
			continue
		}
		if raw := strings.TrimSpace(statusByKey[key]); raw != "" {
			return raw
		}
	}
	return ""
}

func writeHTTPRequestBlock(b *strings.Builder, method, rawURL string, req *entities.HTTPRequest) {
	if b == nil || req == nil {
		return
	}
	b.WriteString("```http\n")
	b.WriteString(formatHTTPRequestBlock(method, rawURL, req))
	b.WriteString("\n```\n")
	if req.BodyBytes > len(strings.TrimRight(req.BodySnippet, "\n")) {
		fmt.Fprintf(b, "\n_Request body truncated to %d bytes (of %d)_\n", len(strings.TrimRight(req.BodySnippet, "\n")), req.BodyBytes)
	}
}

func formatHTTPRequestBlock(method, rawURL string, req *entities.HTTPRequest) string {
	var out strings.Builder
	parsed, _ := neturl.Parse(strings.TrimSpace(rawURL))
	verb := strings.ToUpper(strings.TrimSpace(method))
	if verb == "" {
		verb = "GET"
	}
	target := strings.TrimSpace(rawURL)
	if parsed != nil && parsed.Host != "" {
		target = parsed.EscapedPath()
		if target == "" {
			target = "/"
		}
		if parsed.RawQuery != "" {
			target += "?" + parsed.RawQuery
		}
	}
	fmt.Fprintf(&out, "%s %s HTTP/1.1\n", verb, target)
	if parsed != nil && parsed.Host != "" && !hasHeader(req.Headers, "Host") {
		fmt.Fprintf(&out, "Host: %s\n", parsed.Host)
	}
	writeHTTPHeaders(&out, req.Headers)
	body := strings.TrimRight(redactBody(req.BodySnippet), "\n")
	if body != "" || req.BodyBytes > 0 {
		out.WriteString("\n")
		if body != "" {
			out.WriteString(body)
		} else {
			fmt.Fprintf(&out, "[body omitted, %d bytes]", req.BodyBytes)
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

func writeHTTPResponseBlock(b *strings.Builder, resp *entities.HTTPResponse) {
	if b == nil || resp == nil {
		return
	}
	b.WriteString("```http\n")
	b.WriteString(formatHTTPResponseBlock(resp))
	b.WriteString("\n```\n")
	if resp.BodyBytes > len(strings.TrimRight(resp.BodySnippet, "\n")) {
		fmt.Fprintf(b, "\n_Response body truncated to %d bytes (of %d)_\n", len(strings.TrimRight(resp.BodySnippet, "\n")), resp.BodyBytes)
	}
}

func formatHTTPResponseBlock(resp *entities.HTTPResponse) string {
	var out strings.Builder
	statusText := strings.TrimSpace(http.StatusText(resp.StatusCode))
	if resp.StatusCode > 0 {
		if statusText != "" {
			fmt.Fprintf(&out, "HTTP/1.1 %d %s\n", resp.StatusCode, statusText)
		} else {
			fmt.Fprintf(&out, "HTTP/1.1 %d\n", resp.StatusCode)
		}
	} else {
		out.WriteString("HTTP/1.1\n")
	}
	writeHTTPHeaders(&out, resp.Headers)
	body := strings.TrimRight(redactBody(resp.BodySnippet), "\n")
	if body != "" || resp.BodyBytes > 0 {
		out.WriteString("\n")
		if body != "" {
			out.WriteString(body)
		} else {
			fmt.Fprintf(&out, "[body omitted, %d bytes]", resp.BodyBytes)
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

func writeHTTPHeaders(out *strings.Builder, headers []entities.Header) {
	for _, h := range headers {
		name := strings.TrimSpace(h.Name)
		if name == "" || strings.EqualFold(name, "_line") {
			continue
		}
		fmt.Fprintf(out, "%s: %s\n", name, trafficHeaderValue(name, strings.TrimSpace(h.Value)))
	}
}

func hasHeader(headers []entities.Header, want string) bool {
	want = strings.TrimSpace(strings.ToLower(want))
	for _, h := range headers {
		if strings.ToLower(strings.TrimSpace(h.Name)) == want {
			return true
		}
	}
	return false
}

func isJiraIssueKey(value string) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, r := range parts[0] {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHTTPURL(value string) bool {
	u, err := neturl.Parse(strings.TrimSpace(value))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func extractMarkdownSection(content, heading string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	target := "## " + heading
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == target {
			start = i
			break
		}
	}
	if start == -1 {
		return ""
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	section := strings.TrimSpace(strings.Join(lines[start:end], "\n"))
	if section == "" {
		return ""
	}
	return section + "\n"
}

func writeSectionPage(root, filename, title, section string) error {
	body := strings.TrimSpace(section)
	if body == "" {
		body = fmt.Sprintf("## %s\n\n_No data yet._", title)
	}
	return os.WriteFile(filepath.Join(root, filename), []byte(fmt.Sprintf("# %s\n\n%s\n", title, body)), 0o644)
}

func fallbackString(value, placeholder string) string {
	if strings.TrimSpace(value) == "" {
		return placeholder
	}
	return value
}

func writeHeadersWithLimit(b *strings.Builder, headers []entities.Header, limit int) {
	filtered := make([]entities.Header, 0, len(headers))
	for _, h := range headers {
		name := strings.TrimSpace(h.Name)
		value := strings.TrimSpace(h.Value)
		if strings.EqualFold(name, "_line") {
			continue
		}
		if name == "" && value == "" {
			continue
		}
		filtered = append(filtered, entities.Header{Name: name, Value: value})
	}
	if len(filtered) == 0 {
		b.WriteString("_No headers captured._\n\n")
		return
	}
	stop := len(filtered)
	if limit > 0 && limit < stop {
		stop = limit
	}
	for i := 0; i < stop; i++ {
		fmt.Fprintf(b, "- %s: %s\n", filtered[i].Name, filtered[i].Value)
	}
	if stop < len(filtered) {
		fmt.Fprintf(b, "- _%d additional headers not shown_\n", len(filtered)-stop)
	}
	b.WriteString("\n")
}

func writeBodySnippet(b *strings.Builder, snippet string, totalBytes int, displayLimit int, codeLabel string) {
	snippet = strings.TrimRight(snippet, "\n")
	if strings.TrimSpace(snippet) == "" {
		if totalBytes > 0 {
			fmt.Fprintf(b, "_Body was %d bytes (omitted)_\n\n", totalBytes)
		} else {
			b.WriteString("_No body captured._\n\n")
		}
		return
	}
	display := snippet
	trimmed := false
	if displayLimit > 0 {
		runes := []rune(display)
		if len(runes) > displayLimit {
			display = string(runes[:displayLimit])
			trimmed = true
		}
	}
	label := codeLabel
	if strings.TrimSpace(label) == "" {
		label = "http"
	}
	fmt.Fprintf(b, "```%s\n%s\n```\n\n", label, display)
	if totalBytes > len(snippet) {
		fmt.Fprintf(b, "_Body truncated to %d bytes (of %d)_\n\n", len(snippet), totalBytes)
	} else if trimmed {
		fmt.Fprintf(b, "_Body truncated for display_\n\n")
	}
}

func intsToStrings(nums []int) []string {
	if len(nums) == 0 {
		return nil
	}
	out := make([]string, 0, len(nums))
	for _, n := range nums {
		out = append(out, fmt.Sprintf("%d", n))
	}
	return out
}

func trimStrings(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		t := strings.TrimSpace(v)
		if t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractFrontmatter parses a minimal YAML frontmatter into a flat key/value map.
// Supports simple scalar lines (key: value or key: "value") and block list values
// (key:\n  - item\n  - item). Block list items are joined with "," so callers can
// use splitCommaList to recover []string values (e.g., analyst.tags, analyst.ticketRefs).
func extractFrontmatter(s string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(s, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return out
	}
	i := 1
	var lastKey string
	for ; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			break
		}
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		// Block list item belonging to the previous key.
		if strings.HasPrefix(trimmed, "-") && lastKey != "" {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			item = strings.Trim(item, "\"'")
			if item == "" {
				continue
			}
			if out[lastKey] == "" {
				out[lastKey] = item
			} else {
				out[lastKey] = out[lastKey] + "," + item
			}
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"'")
			out[key] = val
			lastKey = key
		} else {
			// Non-matching line; reset lastKey so stray "-" lines are not misattributed.
			lastKey = ""
		}
	}
	return out
}
