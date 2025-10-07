package obsidian

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// GenerateDashboard scans the vault and writes a DASHBOARD.md with vault-wide
// summaries (by scan, severity, domains, and top rules). Best-effort.
func GenerateDashboard(root string) error {
	occDir := filepath.Join(root, "occurrences")
	defDir := filepath.Join(root, "definitions")

	// Build definitionId -> {title, path}
	type defInfo struct{ Title, Path, Plugin string }
	defByID := map[string]defInfo{}
	if entries, err := os.ReadDir(defDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
				continue
			}
			path := filepath.Join(defDir, e.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			y := extractFrontmatter(string(b))
			id := strings.TrimSpace(y["id"])
			if id == "" {
				continue
			}
			title := strings.TrimSpace(y["name"])
			if title == "" {
				// fallback to file basename
				title = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			}
			plugin := strings.TrimSpace(y["pluginId"])
			defByID[id] = defInfo{Title: title, Path: filepath.ToSlash(filepath.Join("definitions", e.Name())), Plugin: plugin}
		}
	}

	// Aggregates
	scanTotals := map[string]int{}
	scanSeverity := map[string]map[string]int{} // scan -> sev -> count
	domainTotals := map[string]int{}
	domainSeverity := map[string]map[string]int{}
	ruleTotals := map[string]int{} // definitionId -> count
	ruleSeverity := map[string]map[string]int{}

	entries, err := os.ReadDir(occDir)
	if err != nil {
		// No occurrences dir; write a minimal dashboard
		return os.WriteFile(filepath.Join(root, "DASHBOARD.md"), []byte("# Dashboard\n\n_No observations found._\n"), 0o644)
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
		scan := strings.TrimSpace(y["scan.label"])
		if scan == "" {
			scan = "unlabeled"
		}
		sev := strings.TrimSpace(y["risk"])
		if sev == "" {
			// riskId is numeric 0-3 rendered as string
			switch strings.TrimSpace(y["riskId"]) {
			case "3":
				sev = "high"
			case "2":
				sev = "medium"
			case "1":
				sev = "low"
			default:
				sev = "info"
			}
		} else {
			l := strings.ToLower(sev)
			switch l {
			case "high", "medium", "low", "info", "informational":
				if l == "informational" {
					sev = "info"
				} else {
					sev = l
				}
			default:
				sev = "info"
			}
		}
		dom := strings.TrimSpace(y["domain"]) // may be empty
		if dom == "" {
			// derive a pseudo-label from URL if needed
			dom = computeDomainLabel(strings.TrimSpace(y["url"]), "")
		}
		did := strings.TrimSpace(y["definitionId"]) // definition id

		scanTotals[scan]++
		if _, ok := scanSeverity[scan]; !ok {
			scanSeverity[scan] = map[string]int{}
		}
		scanSeverity[scan][sev]++
		if dom != "" {
			domainTotals[dom]++
			if _, ok := domainSeverity[dom]; !ok {
				domainSeverity[dom] = map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
			}
			domainSeverity[dom][sev]++
		}
		if did != "" {
			ruleTotals[did]++
			if _, ok := ruleSeverity[did]; !ok {
				ruleSeverity[did] = map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
			}
			ruleSeverity[did][sev]++
		}
	}

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

	// Compose
	var b strings.Builder
	b.WriteString("# Dashboard\n\n")

	total := 0
	severityTotals := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for scan, v := range scanTotals {
		total += v
		for sev, count := range scanSeverity[scan] {
			severityTotals[sev] += count
		}
	}
	fmt.Fprintf(&b, "- Total observations: %d\n", total)
	fmt.Fprintf(&b, "- Scans: %d\n", len(scanTotals))
	for _, sev := range []string{"high", "medium", "low", "info"} {
		if c := severityTotals[sev]; c > 0 {
			fmt.Fprintf(&b, "- %s: %d\n", strings.Title(sev), c)
		}
	}
	b.WriteString("\n")

	// By Scan with severities
	if len(scanTotals) > 0 {
		b.WriteString("## By Scan\n\n")
		scans := make([]string, 0, len(scanTotals))
		for s := range scanTotals {
			scans = append(scans, s)
		}
		sort.Strings(scans)
		for _, s := range scans {
			sev := scanSeverity[s]
			fmt.Fprintf(&b, "- %s — observations: %d (%s)\n", s, scanTotals[s], severityLine(sev))
		}
		b.WriteString("\n")
	}

	// Top Domains (with severity context)
	if len(domainTotals) > 0 {
		type kv struct {
			K string
			V int
		}
		var items []kv
		for k, v := range domainTotals {
			items = append(items, kv{k, v})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].V != items[j].V {
				return items[i].V > items[j].V
			}
			return items[i].K < items[j].K
		})
		b.WriteString("## Top Domains\n\n")
		limit := 10
		if limit > len(items) {
			limit = len(items)
		}
		for i := 0; i < limit; i++ {
			sev := domainSeverity[items[i].K]
			fmt.Fprintf(&b, "- %s: %d (%s)\n", items[i].K, items[i].V, severityLine(sev))
		}
		b.WriteString("\n")
	}

	// Rule severity hotlists
	type ruleSummary struct {
		ID       string
		Info     defInfo
		Total    int
		Severity map[string]int
	}
	highRules := []ruleSummary{}
	mediumRules := []ruleSummary{}
	lowRules := []ruleSummary{}
	for id, total := range ruleTotals {
		sevMap := ruleSeverity[id]
		rs := ruleSummary{ID: id, Info: defByID[id], Total: total, Severity: sevMap}
		if sevMap["high"] > 0 {
			highRules = append(highRules, rs)
		} else if sevMap["medium"] > 0 {
			mediumRules = append(mediumRules, rs)
		} else {
			lowRules = append(lowRules, rs)
		}
	}

	sort.Slice(highRules, func(i, j int) bool {
		if highRules[i].Severity["high"] != highRules[j].Severity["high"] {
			return highRules[i].Severity["high"] > highRules[j].Severity["high"]
		}
		if highRules[i].Severity["medium"] != highRules[j].Severity["medium"] {
			return highRules[i].Severity["medium"] > highRules[j].Severity["medium"]
		}
		if highRules[i].Total != highRules[j].Total {
			return highRules[i].Total > highRules[j].Total
		}
		return highRules[i].Info.Title < highRules[j].Info.Title
	})
	sort.Slice(mediumRules, func(i, j int) bool {
		if mediumRules[i].Severity["medium"] != mediumRules[j].Severity["medium"] {
			return mediumRules[i].Severity["medium"] > mediumRules[j].Severity["medium"]
		}
		if mediumRules[i].Severity["low"] != mediumRules[j].Severity["low"] {
			return mediumRules[i].Severity["low"] > mediumRules[j].Severity["low"]
		}
		if mediumRules[i].Total != mediumRules[j].Total {
			return mediumRules[i].Total > mediumRules[j].Total
		}
		return mediumRules[i].Info.Title < mediumRules[j].Info.Title
	})
	sort.Slice(lowRules, func(i, j int) bool {
		if lowRules[i].Severity["low"] != lowRules[j].Severity["low"] {
			return lowRules[i].Severity["low"] > lowRules[j].Severity["low"]
		}
		if lowRules[i].Severity["info"] != lowRules[j].Severity["info"] {
			return lowRules[i].Severity["info"] > lowRules[j].Severity["info"]
		}
		if lowRules[i].Total != lowRules[j].Total {
			return lowRules[i].Total > lowRules[j].Total
		}
		return lowRules[i].Info.Title < lowRules[j].Info.Title
	})

	writeRuleHotlist := func(title string, defs []ruleSummary, limit int) {
		b.WriteString("## " + title + "\n\n")
		if len(defs) == 0 {
			b.WriteString("- _None detected_\n\n")
			return
		}
		if limit <= 0 || limit > len(defs) {
			limit = len(defs)
		}
		for i := 0; i < limit; i++ {
			rs := defs[i]
			title := rs.Info.Title
			if strings.TrimSpace(title) == "" {
				title = rs.ID
			}
			if strings.TrimSpace(rs.Info.Path) != "" {
				fmt.Fprintf(&b, "- [[%s|%s]] — %s (total: %d)\n", rs.Info.Path, title, severityLine(rs.Severity), rs.Total)
			} else {
				fmt.Fprintf(&b, "- %s — %s (total: %d)\n", title, severityLine(rs.Severity), rs.Total)
			}
		}
		if limit < len(defs) {
			fmt.Fprintf(&b, "- _%d additional rules not shown_\n", len(defs)-limit)
		}
		b.WriteString("\n")
	}

	writeRuleHotlist("High severity rules", highRules, 10)
	writeRuleHotlist("Medium severity rules", mediumRules, 10)
	writeRuleHotlist("Low & informational rules", lowRules, 10)

	return os.WriteFile(filepath.Join(root, "DASHBOARD.md"), []byte(b.String()), 0o644)
}
