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
	statusTotals := map[string]int{}
	findingSeverity := map[string]string{} // findingId -> primary severity

	entries, err := os.ReadDir(occDir)
	if err != nil {
		// No occurrences dir; write a minimal dashboard
		return os.WriteFile(filepath.Join(root, "DASHBOARD.md"), []byte("# Dashboard\n\n_No occurrences found._\n"), 0o644)
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
		status := strings.TrimSpace(y["analyst.status"])
		if status == "" {
			status = "open"
		}

		scanTotals[scan]++
		if _, ok := scanSeverity[scan]; !ok {
			scanSeverity[scan] = map[string]int{}
		}
		scanSeverity[scan][sev]++
		statusTotals[status]++
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
		if fid := strings.TrimSpace(y["findingId"]); fid != "" {
			prev := findingSeverity[fid]
			if prev == "" || rankSeverity(sev) > rankSeverity(prev) {
				findingSeverity[fid] = sev
			}
		}
	}
	issueSeverityTotals := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for _, sev := range findingSeverity {
		issueSeverityTotals[sev]++
	}

	// Compose
	var b strings.Builder
	b.WriteString("# Dashboard\n\n")

	total := 0
	for _, v := range scanTotals {
		total += v
	}
	fmt.Fprintf(&b, "Scans: %d | Issues: %d | Occurrences: %d | High: %d | Medium: %d | Low: %d | Info: %d\n\n",
		len(scanTotals), len(findingSeverity), total,
		issueSeverityTotals["high"], issueSeverityTotals["medium"], issueSeverityTotals["low"], issueSeverityTotals["info"])

	b.WriteString("## Snapshot\n\n")
	b.WriteString("| Metric | Count |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Scans | %d |\n", len(scanTotals))
	fmt.Fprintf(&b, "| Issues | %d |\n", len(findingSeverity))
	fmt.Fprintf(&b, "| Occurrences | %d |\n", total)
	fmt.Fprintf(&b, "| High | %d |\n", issueSeverityTotals["high"])
	fmt.Fprintf(&b, "| Medium | %d |\n", issueSeverityTotals["medium"])
	fmt.Fprintf(&b, "| Low | %d |\n", issueSeverityTotals["low"])
	fmt.Fprintf(&b, "| Info | %d |\n", issueSeverityTotals["info"])
	b.WriteString("\n")

	// Status overview
	if len(statusTotals) > 0 {
		b.WriteString("## Status\n\n")
		b.WriteString("| Status | Count |\n| --- | --- |\n")
		for _, entry := range []string{"open", "triaged", "fp", "accepted", "fixed"} {
			fmt.Fprintf(&b, "| %s | %d |\n", titleASCII(entry), statusTotals[entry])
		}
		b.WriteString("\n")
	}

	// By Scan with severities
	if len(scanTotals) > 0 {
		b.WriteString("## By Scan\n\n")
		b.WriteString("| Scan | Occurrences | High | Medium | Low | Info |\n| --- | --- | --- | --- | --- | --- |\n")
		scans := make([]string, 0, len(scanTotals))
		for s := range scanTotals {
			scans = append(scans, s)
		}
		sort.Strings(scans)
		for _, s := range scans {
			sev := scanSeverity[s]
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", s, scanTotals[s], sev["high"], sev["medium"], sev["low"], sev["info"])
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
		b.WriteString("| Domain | Occurrences | High | Medium | Low | Info |\n| --- | --- | --- | --- | --- | --- |\n")
		for _, item := range items {
			sev := domainSeverity[item.K]
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", item.K, item.V, sev["high"], sev["medium"], sev["low"], sev["info"])
		}
		b.WriteString("\n")
	}

	// Rule severity table
	type ruleSummary struct {
		ID       string
		Info     defInfo
		Total    int
		Severity map[string]int
	}
	var rules []ruleSummary
	for id, total := range ruleTotals {
		rules = append(rules, ruleSummary{ID: id, Info: defByID[id], Total: total, Severity: ruleSeverity[id]})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Total != rules[j].Total {
			return rules[i].Total > rules[j].Total
		}
		if rules[i].Severity["high"] != rules[j].Severity["high"] {
			return rules[i].Severity["high"] > rules[j].Severity["high"]
		}
		return rules[i].Info.Title < rules[j].Info.Title
	})

	b.WriteString("## Rules\n\n")
	if len(rules) == 0 {
		b.WriteString("_No rules in scope._\n")
		return os.WriteFile(filepath.Join(root, "DASHBOARD.md"), []byte(b.String()), 0o644)
	}
	b.WriteString("| Rule | High | Medium | Low | Info | Total |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, rs := range rules {
		title := rs.Info.Title
		if strings.TrimSpace(title) == "" {
			title = rs.ID
		}
		if strings.TrimSpace(rs.Info.Path) != "" {
			fmt.Fprintf(&b, "| [%s](%s) | %d | %d | %d | %d | %d |\n", title, rs.Info.Path, rs.Severity["high"], rs.Severity["medium"], rs.Severity["low"], rs.Severity["info"], rs.Total)
		} else {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n", title, rs.Severity["high"], rs.Severity["medium"], rs.Severity["low"], rs.Severity["info"], rs.Total)
		}
	}
	b.WriteString("\n")

	return os.WriteFile(filepath.Join(root, "DASHBOARD.md"), []byte(b.String()), 0o644)
}

func rankSeverity(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
