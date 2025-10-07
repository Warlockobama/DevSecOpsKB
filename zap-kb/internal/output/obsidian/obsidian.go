package obsidian

import (
	"fmt"
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
}

// WriteVault writes an Obsidian-ready folder tree from the Entities model.
// Layout:
//   root/
//     definitions/{pluginId}-{slug}.md
//     findings/{findingId}.md
//     occurrences/{occurrenceId}.md
func WriteVault(root string, ef entities.EntitiesFile, opts Options) error {
	defDir := filepath.Join(root, "definitions")
	findDir := filepath.Join(root, "findings")
	occDir := filepath.Join(root, "occurrences")
	for _, d := range []string{defDir, findDir, occDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// Index by ids for quick joins.
	findByID := make(map[string]entities.Finding, len(ef.Findings))
	for _, f := range ef.Findings {
		findByID[f.FindingID] = f
	}
	occsByFind := make(map[string][]entities.Occurrence)
	for _, o := range ef.Occurrences {
		occsByFind[o.FindingID] = append(occsByFind[o.FindingID], o)
	}

	// Map definitionId -> on-disk filename (with directory) for correct links.
	defLinkByID := make(map[string]string, len(ef.Definitions))
	// And map to the definition itself for alias building.
	defByID := make(map[string]entities.Definition, len(ef.Definitions))

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
	statusCounts := make(map[string]int)
	// For INDEX rollup by domain for this run.
	domainCounts := make(map[string]map[string]int) // domain -> status->count
	domainTotals := make(map[string]int)
	// New: severity rollups for this run
	severityCounts := make(map[string]int)                  // severity -> count
	domainSeverityCounts := make(map[string]map[string]int) // domain -> severity -> count

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
		}
		// definition rollup
		kv["occurrenceCount"] = fmt.Sprintf("%d", defOccTotal)
		addStatusToYAMLStrAny(kv, "status.", defStats)

		var b strings.Builder
		writeYAML(&b, kv)

		title := firstNonEmpty(d.Alert, d.Name, d.PluginID)
		fmt.Fprintf(&b, "# %s (Plugin %s)\n\n", title, d.PluginID)
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

		// Detection logic (if enriched)
		if d.Detection != nil {
			b.WriteString("## Detection logic\n\n")
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
					fmt.Fprintf(&b, "- [[%s|%s %s]] — observations: %d (open:%d triaged:%d fp:%d accepted:%d fixed:%d)\n",
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
							fmt.Fprintf(&b, "    - _%d additional observations not shown_\n", len(occs)-sampleLimit)
						}
					}
				}
				if limit < len(group) {
					fmt.Fprintf(&b, "- _%d additional findings not shown_\n", len(group)-limit)
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
			"id":              f.FindingID,
			"issueId":         f.FindingID,
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
			"firstSeen":       ef.GeneratedAt,
			"lastSeen":        ef.GeneratedAt,
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
		addStatusToYAMLStrAny(kv, "status.", sc)
		writeYAML(&b, kv)

		fmt.Fprintf(&b, "# Issue %s — %s\n\n", f.FindingID, alias)
		// Severity callout
		sevTxt, _ := deriveSeverity(f.Risk, f.RiskCode)
		b.WriteString(calloutForSeverity(sevTxt, fmt.Sprintf("Risk: %s (%s) — Confidence: %s", f.Risk, f.RiskCode, f.Confidence)))

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
		fmt.Fprintf(&b, "- Observations: %d\n", len(occs))
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

		// Observations list (compact)
		if len(occs) > 0 {
			b.WriteString("## Observations\n\n")
			sort.Slice(occs, func(i, j int) bool {
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
				caption := strings.TrimSpace(o.Name)
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
				decorations := []string{titleASCII(sev2)}
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

		// First observation traffic (if present)
		if len(occs) > 0 {
			first := occs[0]
			if first.Request != nil || first.Response != nil {
				b.WriteString("## First observation traffic\n\n")
				if first.Request != nil {
					reqURL, _ := neturl.Parse(first.URL)
					b.WriteString("### Request\n\n")
					fmt.Fprintf(&b, "- Method: %s\n", strings.ToUpper(strings.TrimSpace(first.Method)))
					if reqURL != nil {
						fmt.Fprintf(&b, "- Host: %s\n", reqURL.Host)
						fmt.Fprintf(&b, "- Path: %s\n", reqURL.Path)
					}
					fmt.Fprintf(&b, "- Headers captured: %d\n\n", len(first.Request.Headers))
					writeHeadersWithLimit(&b, first.Request.Headers, 10)
					if strings.TrimSpace(first.Request.BodySnippet) != "" || first.Request.BodyBytes > 0 {
						writeBodySnippet(&b, first.Request.BodySnippet, first.Request.BodyBytes, 512, "http")
					}
				}
				if first.Response != nil {
					b.WriteString("### Response\n\n")
					if first.Response.StatusCode > 0 {
						fmt.Fprintf(&b, "- Status: %d\n", first.Response.StatusCode)
					}
					fmt.Fprintf(&b, "- Headers captured: %d\n\n", len(first.Response.Headers))
					writeHeadersWithLimit(&b, first.Response.Headers, 12)
					if strings.TrimSpace(first.Response.BodySnippet) != "" || first.Response.BodyBytes > 0 {
						writeBodySnippet(&b, first.Response.BodySnippet, first.Response.BodyBytes, 512, "http")
					}
				}
			}
		}

		// Issue-level Workflow
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

		b.WriteString("## Workflow\n\n")
		fmt.Fprintf(&b, "- Status: %s (%s)\n", titleASCII(primaryStatus), statusSummary)
		fmt.Fprintf(&b, "- Owners: %s\n", formatListOrPlaceholder(owners, "_None recorded_"))
		fmt.Fprintf(&b, "- Tags: %s\n", formatListOrPlaceholder(tags, "_None_"))
		fmt.Fprintf(&b, "- Tickets: %s\n", formatListOrPlaceholder(tickets, "_None_"))
		fmt.Fprintf(&b, "- Updated: %s\n", fallbackString(updated, "_Not recorded_"))
		if len(notes) > 0 {
			b.WriteString("\n### Analyst Notes\n\n")
			for _, note := range notes {
				fmt.Fprintf(&b, "- %s\n", note)
			}
			b.WriteString("\n")
		}

		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	// occurrences/{occurrenceId}.md
	for _, o := range ef.Occurrences {
		path := filepath.Join(occDir, o.OccurrenceID+".md")
		var b strings.Builder

		// Analyst fields (flattened for YAML)
		aStatus, aOwner, aTags, aNotes, aTickets, aUpdated := "", "", "", "", "", ""
		if o.Analyst != nil {
			aStatus = strings.TrimSpace(o.Analyst.Status)
			aOwner = strings.TrimSpace(o.Analyst.Owner)
			if len(o.Analyst.Tags) > 0 {
				aTags = strings.Join(o.Analyst.Tags, ", ")
			}
			aNotes = strings.TrimSpace(o.Analyst.Notes)
			if len(o.Analyst.TicketRefs) > 0 {
				aTickets = strings.Join(o.Analyst.TicketRefs, ", ")
			}
			aUpdated = strings.TrimSpace(o.Analyst.UpdatedAt)
		}

		// Count status for index (default to "open" if empty)
		sc := aStatus
		if sc == "" {
			sc = "open"
		}
		// Global statusCounts were aggregated at definition stage; keep this for safety.
		statusCounts[sc]++
		dom := computeDomainLabel(o.URL, opts.SiteLabel)
		if dom != "" {
			if _, ok := domainCounts[dom]; !ok {
				domainCounts[dom] = map[string]int{}
			}
			domainCounts[dom][sc]++
			domainTotals[dom]++
		}
		// New: severity counting
		sev, rid := deriveSeverity(o.Risk, o.RiskCode)
		severityCounts[sev]++
		if dom != "" {
			if _, ok := domainSeverityCounts[dom]; !ok {
				domainSeverityCounts[dom] = map[string]int{}
			}
			domainSeverityCounts[dom][sev]++
		}

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
			"id":                 o.OccurrenceID,
			"observationId":      o.OccurrenceID,
			"definitionId":       o.DefinitionID,
			"findingId":          o.FindingID,
			"issueId":            o.FindingID,
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
			"observedAt":         ef.GeneratedAt,
			"riskId":             fmt.Sprintf("%d", rid),
			"aliases":            []string{alias},
			"kind":               "observation",
		}
		if strings.TrimSpace(opts.ScanLabel) != "" {
			ym["scan.label"] = opts.ScanLabel
		}
		if dom != "" {
			ym["domain"] = dom
		}
		writeYAML(&b, ym)

		fmt.Fprintf(&b, "# Observation %s — %s\n\n", o.OccurrenceID, alias)
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

		// Repro snippet
		b.WriteString("## Repro (curl)\n\n")
		b.WriteString("```bash\n")
		b.WriteString(buildCurl(o))
		b.WriteString("\n```\n\n")
		// No deep links to ZAP here (requested)

		// Traffic with content-type/length hints
		if o.Request != nil || o.Response != nil {
			b.WriteString("## Traffic\n\n")
			if o.Request != nil {
				b.WriteString("### Request\n\n")
				fmt.Fprintf(&b, "%s %s\n\n", strings.ToUpper(strings.TrimSpace(o.Method)), o.URL)
				if len(o.Request.Headers) > 0 {
					// quick summary
					ct := headerValue(o.Request.Headers, "Content-Type")
					cl := headerValue(o.Request.Headers, "Content-Length")
					if ct != "" {
						fmt.Fprintf(&b, "_Content-Type: %s_\n\n", ct)
					}
					if cl != "" {
						fmt.Fprintf(&b, "_Content-Length: %s_\n\n", cl)
					}
					fmt.Fprintf(&b, "_Headers: %d_\n\n", len(o.Request.Headers))
					b.WriteString("Headers:\n")
					for _, h := range o.Request.Headers {
						fmt.Fprintf(&b, "- %s: %s\n", h.Name, h.Value)
					}
					b.WriteString("\n")
				}
				if o.Request.BodySnippet != "" {
					b.WriteString("```http\n")
					b.WriteString(o.Request.BodySnippet)
					b.WriteString("\n```\n\n")
					if o.Request.BodyBytes > len(o.Request.BodySnippet) {
						fmt.Fprintf(&b, "_Request body truncated to %d bytes (of %d)_\n\n", len(o.Request.BodySnippet), o.Request.BodyBytes)
					}
				} else if o.Request.BodyBytes > 0 {
					fmt.Fprintf(&b, "_Request body: %d bytes_\n\n", o.Request.BodyBytes)
				}
			}
			if o.Response != nil {
				b.WriteString("### Response\n\n")
				if o.Response.StatusCode > 0 {
					fmt.Fprintf(&b, "Status: %d\n\n", o.Response.StatusCode)
				}
				if len(o.Response.Headers) > 0 {
					ct := headerValue(o.Response.Headers, "Content-Type")
					cl := headerValue(o.Response.Headers, "Content-Length")
					if ct != "" {
						fmt.Fprintf(&b, "_Content-Type: %s_\n\n", ct)
					}
					if cl != "" {
						fmt.Fprintf(&b, "_Content-Length: %s_\n\n", cl)
					}
					fmt.Fprintf(&b, "_Headers: %d_\n\n", len(o.Response.Headers))
					b.WriteString("Headers:\n")
					for _, h := range o.Response.Headers {
						fmt.Fprintf(&b, "- %s: %s\n", h.Name, h.Value)
					}
					b.WriteString("\n")
				}
				if o.Response.BodySnippet != "" {
					b.WriteString("```http\n")
					b.WriteString(o.Response.BodySnippet)
					b.WriteString("\n```\n\n")
					if o.Response.BodyBytes > len(o.Response.BodySnippet) {
						fmt.Fprintf(&b, "_Response body truncated to %d bytes (of %d)_\n\n", len(o.Response.BodySnippet), o.Response.BodyBytes)
					}
				} else if o.Response.BodyBytes > 0 {
					fmt.Fprintf(&b, "_Response body: %d bytes_\n\n", o.Response.BodyBytes)
				}
			}
		}

		// Triage guidance
		if d, ok := defByID[o.DefinitionID]; ok {
			tips := triageGuidance(d.PluginID)
			if len(tips) > 0 {
				b.WriteString("## Triage guidance\n\n")
				for _, t := range tips {
					fmt.Fprintf(&b, "- %s\n", t)
				}
				b.WriteString("\n")
			}
		}

		// Workflow section (analyst notes)
		b.WriteString("## Workflow\n\n")
		if aStatus != "" {
			fmt.Fprintf(&b, "- Status: %s\n", aStatus)
		} else {
			b.WriteString("- Status: open\n")
		}
		if aOwner != "" {
			fmt.Fprintf(&b, "- Owner: %s\n", aOwner)
		}
		if aTags != "" {
			fmt.Fprintf(&b, "- Tags: %s\n", aTags)
		}
		if aTickets != "" {
			fmt.Fprintf(&b, "- Tickets: %s\n", aTickets)
		}
		if aUpdated != "" {
			fmt.Fprintf(&b, "- Updated: %s\n", aUpdated)
		}
		if aNotes != "" {
			b.WriteString("\n### Notes\n\n")
			b.WriteString(aNotes + "\n")
		}

		b.WriteString("\n### Checklist\n\n")
		b.WriteString("- [ ] Triage\n")
		b.WriteString("- [ ] Validate\n")
		b.WriteString("- [ ] File ticket\n")
		b.WriteString("- [ ] Fix verified\n")
		b.WriteString("- [ ] Close\n")
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
		histScanTotals, histDomainTotals, histDomainStatus := scanVaultOccurrences(occDir)

		severityLine := func(m map[string]int) string {
			parts := []string{}
			for _, entry := range []struct {
				Label string
				Key   string
			}{
				{"H", "high"},
				{"M", "medium"},
				{"L", "low"},
				{"I", "info"},
			} {
				parts = append(parts, fmt.Sprintf("%s:%d", entry.Label, m[entry.Key]))
			}
			return strings.Join(parts, " ")
		}

		var b strings.Builder
		b.WriteString("# Index\n\n")
		if strings.TrimSpace(opts.ScanLabel) != "" {
			fmt.Fprintf(&b, "_Scan:_ %s\n\n", opts.ScanLabel)
		}

		totalObs := len(ef.Occurrences)
		fmt.Fprintf(&b, "- Total observations: %d\n", totalObs)
		fmt.Fprintf(&b, "- Unique findings: %d\n", len(ef.Findings))
		for _, status := range []string{"open", "triaged", "accepted", "fixed", "fp"} {
			if count := statusCounts[status]; count > 0 {
				fmt.Fprintf(&b, "- %s: %d\n", titleASCII(status), count)
			}
		}

		if len(severityCounts) > 0 {
			b.WriteString("\n## Severity overview\n\n")
			for _, sev := range []string{"high", "medium", "low", "info"} {
				if count := severityCounts[sev]; count > 0 {
					fmt.Fprintf(&b, "- %s: %d\n", titleASCII(sev), count)
				}
			}
		}

		highDefs := make([]defSummary, 0)
		mediumDefs := make([]defSummary, 0)
		lowDefs := make([]defSummary, 0)
		for _, ds := range defSummaries {
			h := ds.Severity["high"]
			m := ds.Severity["medium"]
			if h > 0 {
				highDefs = append(highDefs, ds)
			} else if m > 0 {
				mediumDefs = append(mediumDefs, ds)
			} else {
				lowDefs = append(lowDefs, ds)
			}
		}

		sort.Slice(highDefs, func(i, j int) bool {
			if highDefs[i].Severity["high"] != highDefs[j].Severity["high"] {
				return highDefs[i].Severity["high"] > highDefs[j].Severity["high"]
			}
			if highDefs[i].Severity["medium"] != highDefs[j].Severity["medium"] {
				return highDefs[i].Severity["medium"] > highDefs[j].Severity["medium"]
			}
			if highDefs[i].Total != highDefs[j].Total {
				return highDefs[i].Total > highDefs[j].Total
			}
			return highDefs[i].Title < highDefs[j].Title
		})
		sort.Slice(mediumDefs, func(i, j int) bool {
			if mediumDefs[i].Severity["medium"] != mediumDefs[j].Severity["medium"] {
				return mediumDefs[i].Severity["medium"] > mediumDefs[j].Severity["medium"]
			}
			if mediumDefs[i].Severity["low"] != mediumDefs[j].Severity["low"] {
				return mediumDefs[i].Severity["low"] > mediumDefs[j].Severity["low"]
			}
			if mediumDefs[i].Total != mediumDefs[j].Total {
				return mediumDefs[i].Total > mediumDefs[j].Total
			}
			return mediumDefs[i].Title < mediumDefs[j].Title
		})
		sort.Slice(lowDefs, func(i, j int) bool {
			if lowDefs[i].Severity["low"] != lowDefs[j].Severity["low"] {
				return lowDefs[i].Severity["low"] > lowDefs[j].Severity["low"]
			}
			if lowDefs[i].Severity["info"] != lowDefs[j].Severity["info"] {
				return lowDefs[i].Severity["info"] > lowDefs[j].Severity["info"]
			}
			if lowDefs[i].Total != lowDefs[j].Total {
				return lowDefs[i].Total > lowDefs[j].Total
			}
			return lowDefs[i].Title < lowDefs[j].Title
		})

		writeRuleSection := func(title string, defs []defSummary, limit int) {
			b.WriteString("\n## " + title + "\n\n")
			if len(defs) == 0 {
				b.WriteString("- _None detected_\n\n")
				return
			}
			if limit <= 0 || limit > len(defs) {
				limit = len(defs)
			}
			for i := 0; i < limit; i++ {
				ds := defs[i]
				fmt.Fprintf(&b, "- [[%s|%s (Plugin %s)]] — %s (total: %d)\n", ds.Link, ds.Title, ds.Plugin, severityLine(ds.Severity), ds.Total)
			}
			if limit < len(defs) {
				fmt.Fprintf(&b, "- _%d additional rules not shown_\n", len(defs)-limit)
			}
			b.WriteString("\n")
		}

		writeRuleSection("High severity rules", highDefs, 10)
		writeRuleSection("Medium severity rules", mediumDefs, 10)
		writeRuleSection("Low & informational rules", lowDefs, 10)
		// Historical by Scan across entire vault
		if len(histScanTotals) > 0 {
			b.WriteString("\n## By Scan (vault)\n\n")
			// stable order by scan label
			var scans []string
			for s := range histScanTotals {
				scans = append(scans, s)
			}
			sort.Strings(scans)
			for _, s := range scans {
				fmt.Fprintf(&b, "- %s — observations: %d\n", s, histScanTotals[s])
				// domains under each scan
				if dt, ok := histDomainTotals[s]; ok {
					// order domains
					var doms []string
					for d := range dt {
						doms = append(doms, d)
					}
					sort.Strings(doms)
					for _, d := range doms {
						ds := histDomainStatus[s][d]
						fmt.Fprintf(&b, "  - %s — %d; open:%d triaged:%d fp:%d accepted:%d fixed:%d\n",
							d, dt[d], ds["open"], ds["triaged"], ds["fp"], ds["accepted"], ds["fixed"])
					}
				}
			}
		}
		// By Domain (this run)
		if len(domainTotals) > 0 {
			b.WriteString("\n## By Domain (this run)\n\n")
			var doms []string
			for d := range domainTotals {
				doms = append(doms, d)
			}
			sort.Strings(doms)
			for _, d := range doms {
				ds := domainCounts[d]
				fmt.Fprintf(&b, "- %s — observations: %d; open:%d triaged:%d fp:%d accepted:%d fixed:%d", d, domainTotals[d], ds["open"], ds["triaged"], ds["fp"], ds["accepted"], ds["fixed"])
				if ss, ok := domainSeverityCounts[d]; ok {
					fmt.Fprintf(&b, " (H:%d M:%d L:%d I:%d)", ss["high"], ss["medium"], ss["low"], ss["info"])
				}
				b.WriteString("\n")
			}
		}
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
			b.WriteString("\n## Volume leaders (all severities)\n\n")
			limit := 10
			if limit > len(tmp) {
				limit = len(tmp)
			}
			for i := 0; i < limit; i++ {
				ds := tmp[i]
				fmt.Fprintf(&b, "- [[%s|%s (Plugin %s)]] — %s (total: %d)\n", ds.Link, ds.Title, ds.Plugin, severityLine(ds.Severity), ds.Total)
			}
			if limit < len(tmp) {
				fmt.Fprintf(&b, "- _%d additional rules not shown_\n", len(tmp)-limit)
			}
		}
		b.WriteString("\n")
		if err := os.WriteFile(index, []byte(b.String()), 0o644); err != nil {
			return err
		}
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
			if strings.TrimSpace(v) == "" {
				continue
			}
			fmt.Fprintf(b, "%s: %q\n", k, v)
		case []string:
			if len(v) == 0 {
				continue
			}
			fmt.Fprintf(b, "%s:\n", k)
			for _, s := range v {
				if strings.TrimSpace(s) == "" {
					continue
				}
				fmt.Fprintf(b, "  - %q\n", s)
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

// triageGuidance returns a small set of rule-specific tips
func triageGuidance(pluginID string) []string {
	switch strings.TrimSpace(pluginID) {
	case "10038": // CSP header not set
		return []string{
			"Check response headers for Content-Security-Policy or meta CSP tags.",
			"If behind a CDN/reverse proxy, verify headers at edge and origin.",
			"Establish a baseline CSP (default-src 'self') and iterate.",
		}
	case "10020": // Missing Anti-clickjacking header
		return []string{
			"Confirm X-Frame-Options or CSP frame-ancestors is present.",
			"Decide SAMEORIGIN vs DENY; prefer frame-ancestors in CSP for modern browsers.",
		}
	default:
		return []string{
			"Validate the finding manually and confirm exploitability in this context.",
			"Document false-positive conditions and add ignores where appropriate.",
		}
	}
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
			parts = append(parts, "-H", fmt.Sprintf("%s: %s", name, val))
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
				parts = append(parts, "-H", "Content-Type: application/json")
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
	if strings.TrimSpace(override) != "" {
		return strings.TrimSpace(override)
	}
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	if host != "" && !looksRedactedHost(host) {
		return host
	}
	return "site-" + shortHexSuffix(shortHashSafe(rawURL), 6)
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
		st := strings.TrimSpace(y["analyst.status"]) // may be empty
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

func formatListOrPlaceholder(items []string, placeholder string) string {
	if len(items) == 0 {
		return placeholder
	}
	return strings.Join(items, ", ")
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

// extractFrontmatter parses a minimal YAML frontmatter into a flat key/value map.
// Only supports simple scalar lines: key: value or key: "value"; arrays are ignored here.
func extractFrontmatter(s string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(s, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return out
	}
	i := 1
	for ; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			break
		}
		line := lines[i]
		// skip list sections
		if strings.HasPrefix(strings.TrimSpace(line), "-") {
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"'")
			out[key] = val
		}
	}
	return out
}
