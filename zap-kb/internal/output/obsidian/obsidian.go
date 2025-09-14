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
	"unicode"

	"zap-kb/internal/entities"
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
		Link   string
		Title  string
		Plugin string
		Total  int
		Stats  map[string]int
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
		defOccTotal := 0
		for _, f := range fs {
			occs := occsByFind[f.FindingID]
			defOccTotal += len(occs)
			sc := aggStatus(occs)
			for k, v := range sc {
				defStats[k] += v
			}
		}
		// Accumulate to global index totals.
		for k, v := range defStats {
			statusCounts[k] += v
		}
		defSummaries = append(defSummaries, defSummary{
			Link:   defLink,
			Title:  firstNonEmpty(d.Alert, d.Name, d.PluginID),
			Plugin: d.PluginID,
			Total:  defOccTotal,
			Stats:  defStats,
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
			b.WriteString("## Issues\n\n")
			for _, f := range fs {
				occs := occsByFind[f.FindingID]
				sc := aggStatus(occs)
				fmt.Fprintf(&b, "### %s %s  (observations: %d; open:%d triaged:%d fp:%d accepted:%d fixed:%d)\n\n",
					f.Method, f.URL, len(occs),
					sc["open"], sc["triaged"], sc["fp"], sc["accepted"], sc["fixed"])

				// Link to dedicated finding page
				fmt.Fprintf(&b, "- [[%s|Issue %s]]\n", filepath.ToSlash(filepath.Join("findings", f.FindingID+".md")), f.FindingID)

				if len(occs) > 0 {
					b.WriteString("#### Observations\n")
					sort.Slice(occs, func(i, j int) bool {
						if occs[i].URL != occs[j].URL {
							return occs[i].URL < occs[j].URL
						}
						if occs[i].Param != occs[j].Param {
							return occs[i].Param < occs[j].Param
						}
						return occs[i].Evidence < occs[j].Evidence
					})
					for _, o := range occs {
						// Prefer the human-friendly occurrence name if provided; otherwise build a clean caption.
						caption := strings.TrimSpace(o.Name)
						if caption == "" {
							parts := []string{strings.TrimSpace(o.Method), strings.TrimSpace(o.URL)}
							if strings.TrimSpace(o.Param) != "" {
								parts = append(parts, "param="+strings.TrimSpace(o.Param))
							}
							if strings.TrimSpace(o.Risk) != "" {
								parts = append(parts, "risk="+strings.TrimSpace(o.Risk))
							}
							if strings.TrimSpace(o.Evidence) != "" {
								parts = append(parts, `ev="`+truncate(strings.TrimSpace(o.Evidence), 80)+`"`)
							}
							caption = strings.Join(parts, " ")
						}
						fmt.Fprintf(&b, "- [[%s|%s]]\n", filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")), caption)
					}
					b.WriteString("\n")
				}
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

		if link := defLinkByID[f.DefinitionID]; link != "" {
			fmt.Fprintf(&b, "- Definition: [[%s|%s]]\n\n", link, f.FindingID)
		} else {
			fmt.Fprintf(&b, "- Definition: %s\n\n", f.DefinitionID)
		}
		fmt.Fprintf(&b, "**Endpoint:** %s %s\n\n", f.Method, f.URL)

		// Rollup section
		b.WriteString("## Rollup\n\n")
		fmt.Fprintf(&b, "- Observations: %d\n", len(occs))
		fmt.Fprintf(&b, "- Status: open:%d triaged:%d fp:%d accepted:%d fixed:%d\n\n",
			sc["open"], sc["triaged"], sc["fp"], sc["accepted"], sc["fixed"])

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
				fmt.Fprintf(&b, "- [[%s|%s]] — %s; %s\n", filepath.ToSlash(filepath.Join("occurrences", o.OccurrenceID+".md")), caption, titleASCII(sev2), ev)
			}
			b.WriteString("\n")
		}

		// First observation traffic (if present)
		if len(occs) > 0 {
			first := occs[0]
			if first.Request != nil || first.Response != nil {
				b.WriteString("## First observation traffic\n\n")
				if first.Request != nil {
					b.WriteString("### Request\n\n")
					fmt.Fprintf(&b, "%s %s\n\n", f.Method, f.URL)
					if len(first.Request.Headers) > 0 {
						b.WriteString("Headers:\n")
						for _, h := range first.Request.Headers {
							fmt.Fprintf(&b, "- %s: %s\n", h.Name, h.Value)
						}
						b.WriteString("\n")
					}
					if first.Request.BodySnippet != "" {
						b.WriteString("```http\n")
						b.WriteString(first.Request.BodySnippet)
						b.WriteString("\n```\n\n")
						if first.Request.BodyBytes > len(first.Request.BodySnippet) {
							fmt.Fprintf(&b, "_Request body truncated to %d bytes (of %d)_\n\n", len(first.Request.BodySnippet), first.Request.BodyBytes)
						}
					} else if first.Request.BodyBytes > 0 {
						fmt.Fprintf(&b, "_Request body: %d bytes_\n\n", first.Request.BodyBytes)
					}
				}
				if first.Response != nil {
					b.WriteString("### Response\n\n")
					if first.Response.StatusCode > 0 {
						fmt.Fprintf(&b, "Status: %d\n\n", first.Response.StatusCode)
					}
					if len(first.Response.Headers) > 0 {
						b.WriteString("Headers:\n")
						for _, h := range first.Response.Headers {
							fmt.Fprintf(&b, "- %s: %s\n", h.Name, h.Value)
						}
						b.WriteString("\n")
					}
					if first.Response.BodySnippet != "" {
						b.WriteString("```http\n")
						b.WriteString(first.Response.BodySnippet)
						b.WriteString("\n```\n\n")
						if first.Response.BodyBytes > len(first.Response.BodySnippet) {
							fmt.Fprintf(&b, "_Response body truncated to %d bytes (of %d)_\n\n", len(first.Response.BodySnippet), first.Response.BodyBytes)
						}
					} else if first.Response.BodyBytes > 0 {
						fmt.Fprintf(&b, "_Response body: %d bytes_\n\n", first.Response.BodyBytes)
					}
				}
			}
		}

		// Issue-level Workflow
		b.WriteString("## Workflow\n\n")
		b.WriteString("- Status: open\n")
		b.WriteString("- Owner: \n")
		b.WriteString("- Tags: \n")
		b.WriteString("- Tickets: \n")
		b.WriteString("- Updated: \n")
		b.WriteString("\n### Notes\n\n")
		b.WriteString("\n### Checklist\n\n")
		b.WriteString("- [ ] Triage\n")
		b.WriteString("- [ ] Validate\n")
		b.WriteString("- [ ] File ticket\n")
		b.WriteString("- [ ] Fix verified\n")
		b.WriteString("- [ ] Close\n")
		b.WriteString("\n### Governance\n\n")
		b.WriteString("- False positive reason: \n")
		b.WriteString("- Acceptance justification: \n")
		b.WriteString("- Acceptance expires at (UTC): \n")
		b.WriteString("- Due at (UTC): \n")

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

		// Rule summary for quick triage
		if d, ok := defByID[o.DefinitionID]; ok {
			b.WriteString("## Rule summary\n\n")
			title := firstNonEmpty(d.Alert, d.Name, d.PluginID)
			fmt.Fprintf(&b, "- Title: %s (Plugin %s)\n", title, d.PluginID)
			if d.WASCID > 0 {
				fmt.Fprintf(&b, "- WASC: %d\n", d.WASCID)
			}
			if d.Taxonomy != nil {
				if d.Taxonomy.CWEID > 0 {
					fmt.Fprintf(&b, "- CWE: %d\n", d.Taxonomy.CWEID)
				}
				if strings.TrimSpace(d.Taxonomy.CWEURI) != "" {
					fmt.Fprintf(&b, "- CWE URI: %s\n", d.Taxonomy.CWEURI)
				}
			}
			if d.Remediation != nil && strings.TrimSpace(d.Remediation.Summary) != "" {
				fmt.Fprintf(&b, "- Remediation: %s\n", d.Remediation.Summary)
			}
			if d.Remediation != nil && len(d.Remediation.References) > 0 {
				// show up to 2 references for brevity
				maxRefs := 2
				shown := 0
				for _, r := range d.Remediation.References {
					if strings.TrimSpace(r) == "" {
						continue
					}
					fmt.Fprintf(&b, "  - %s\n", r)
					shown++
					if shown >= maxRefs {
						break
					}
				}
			}
			b.WriteString("\n")
		}

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
		var keys []string
		for k := range statusCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("# Index\n\n")
		if strings.TrimSpace(opts.ScanLabel) != "" {
			fmt.Fprintf(&b, "_Scan:_ %s\n\n", opts.ScanLabel)
		}
		// Total observations for this run from domainTotals
		total := 0
		for _, v := range domainTotals {
			total += v
		}
		fmt.Fprintf(&b, "- Total observations: %d\n", total)
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s: %d\n", titleASCII(k), statusCounts[k])
		}
		// New: By Severity (this run)
		if len(severityCounts) > 0 {
			b.WriteString("\n## By Severity (this run)\n\n")
			for _, sev := range []string{"high", "medium", "low", "info"} {
				if severityCounts[sev] > 0 {
					fmt.Fprintf(&b, "- %s: %d\n", titleASCII(sev), severityCounts[sev])
				}
			}
		}
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
		b.WriteString("\n## By Rule\n\n")
		// Stable order by plugin then title
		sort.Slice(defSummaries, func(i, j int) bool {
			if defSummaries[i].Plugin != defSummaries[j].Plugin {
				return defSummaries[i].Plugin < defSummaries[j].Plugin
			}
			return defSummaries[i].Title < defSummaries[j].Title
		})
		for _, ds := range defSummaries {
			fmt.Fprintf(&b, "- [[%s|%s (Plugin %s)]] — observations: %d; open:%d triaged:%d fp:%d accepted:%d fixed:%d\n",
				ds.Link, ds.Title, ds.Plugin, ds.Total,
				ds.Stats["open"], ds.Stats["triaged"], ds.Stats["fp"], ds.Stats["accepted"], ds.Stats["fixed"])
		}
		// New: By Top Rules (this run)
		if len(defSummaries) > 0 {
			// copy & sort by Total desc
			tmp := make([]defSummary, len(defSummaries))
			copy(tmp, defSummaries)
			sort.Slice(tmp, func(i, j int) bool { return tmp[i].Total > tmp[j].Total })
			b.WriteString("\n## Top Rules (this run)\n\n")
			limit := 5
			if limit > len(tmp) {
				limit = len(tmp)
			}
			for i := 0; i < limit; i++ {
				ds := tmp[i]
				fmt.Fprintf(&b, "- [[%s|%s (Plugin %s)]] — %d observations\n", ds.Link, ds.Title, ds.Plugin, ds.Total)
			}
		}
		b.WriteString("\n")
		if err := os.WriteFile(index, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

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
