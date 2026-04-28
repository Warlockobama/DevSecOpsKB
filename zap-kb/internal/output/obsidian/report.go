package obsidian

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportOptions controls generation of a time-bounded markdown report from an Obsidian vault.
type ReportOptions struct {
	OutPath   string
	Title     string
	Since     time.Time
	Until     time.Time
	ScanLabel string
}

type reportOccurrence struct {
	ID         string
	FindingID  string
	Method     string
	URL        string
	Risk       string
	Status     string
	Domain     string
	ScanLabel  string
	ObservedAt time.Time
}

func GenerateReport(root string, opts ReportOptions) error {
	outPath := strings.TrimSpace(opts.OutPath)
	if outPath == "" {
		return fmt.Errorf("report out path is required")
	}
	if !filepath.IsAbs(outPath) {
		outPath = filepath.Join(root, outPath)
	}

	occs, err := loadReportOccurrences(filepath.Join(root, "occurrences"), opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(renderReport(opts, occs)), 0o644)
}

func loadReportOccurrences(occDir string, opts ReportOptions) ([]reportOccurrence, error) {
	entries, err := os.ReadDir(occDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read occurrences: %w", err)
	}

	var occs []reportOccurrence
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(occDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read occurrence %s: %w", entry.Name(), err)
		}
		y := extractFrontmatter(string(b))
		observed, ok := parseReportTime(y["observedAt"])
		if !ok {
			continue
		}
		if !opts.Since.IsZero() && observed.Before(opts.Since) {
			continue
		}
		if !opts.Until.IsZero() && observed.After(opts.Until) {
			continue
		}
		scan := strings.TrimSpace(y["scan.label"])
		if strings.TrimSpace(opts.ScanLabel) != "" && scan != strings.TrimSpace(opts.ScanLabel) {
			continue
		}
		status := strings.TrimSpace(y["analyst.status"])
		if status == "" {
			status = "open"
		}
		occs = append(occs, reportOccurrence{
			ID:         firstNonEmpty(y["occurrenceId"], strings.TrimPrefix(y["id"], "occurrence/")),
			FindingID:  y["findingId"],
			Method:     y["method"],
			URL:        y["url"],
			Risk:       firstNonEmpty(y["risk"], y["riskCode"]),
			Status:     status,
			Domain:     y["domain"],
			ScanLabel:  scan,
			ObservedAt: observed,
		})
	}
	sort.Slice(occs, func(i, j int) bool {
		if occs[i].ObservedAt.Equal(occs[j].ObservedAt) {
			return occs[i].ID < occs[j].ID
		}
		return occs[i].ObservedAt.After(occs[j].ObservedAt)
	})
	return occs, nil
}

func renderReport(opts ReportOptions, occs []reportOccurrence) string {
	title := strings.TrimSpace(opts.Title)
	if title == "" {
		title = "Security Findings Report"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	if !opts.Since.IsZero() || !opts.Until.IsZero() {
		fmt.Fprintf(&b, "- Window: %s to %s\n", formatReportTime(opts.Since), formatReportTime(opts.Until))
	}
	if strings.TrimSpace(opts.ScanLabel) != "" {
		fmt.Fprintf(&b, "- Scan: %s\n", strings.TrimSpace(opts.ScanLabel))
	}
	fmt.Fprintf(&b, "- Occurrences: %d\n\n", len(occs))

	writeReportCounts(&b, "Severity", occs, func(o reportOccurrence) string { return normalizeReportBucket(o.Risk) })
	writeReportCounts(&b, "Status", occs, func(o reportOccurrence) string { return normalizeReportBucket(o.Status) })
	writeReportCounts(&b, "Domain", occs, func(o reportOccurrence) string { return firstNonEmpty(o.Domain, "unknown") })

	b.WriteString("## Occurrences\n\n")
	if len(occs) == 0 {
		b.WriteString("_No occurrences matched the selected window._\n")
		return b.String()
	}
	b.WriteString("| Observed | Severity | Status | Endpoint | Finding |\n")
	b.WriteString("|---|---:|---|---|---|\n")
	for _, o := range occs {
		endpoint := strings.TrimSpace(strings.TrimSpace(o.Method) + " " + strings.TrimSpace(o.URL))
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			o.ObservedAt.Format(time.RFC3339),
			escapeTable(o.Risk),
			escapeTable(o.Status),
			escapeTable(endpoint),
			escapeTable(o.FindingID),
		)
	}
	return b.String()
}

func writeReportCounts(b *strings.Builder, title string, occs []reportOccurrence, bucket func(reportOccurrence) string) {
	counts := map[string]int{}
	for _, o := range occs {
		counts[bucket(o)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(b, "## By %s\n\n", title)
	if len(keys) == 0 {
		b.WriteString("_No data._\n\n")
		return
	}
	b.WriteString("| Value | Count |\n")
	b.WriteString("|---|---:|\n")
	for _, k := range keys {
		fmt.Fprintf(b, "| %s | %d |\n", escapeTable(k), counts[k])
	}
	b.WriteString("\n")
}

func parseReportTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func formatReportTime(t time.Time) string {
	if t.IsZero() {
		return "unbounded"
	}
	return t.UTC().Format(time.RFC3339)
}

func normalizeReportBucket(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return strings.ToLower(s)
}

func escapeTable(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|")
}
