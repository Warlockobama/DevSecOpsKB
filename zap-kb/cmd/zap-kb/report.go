package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

// reportRow holds one row of the findings summary report.
type reportRow struct {
	FindingID  string   `json:"finding_id"`
	RuleTitle  string   `json:"rule_title"`
	Severity   string   `json:"severity"`
	Domain     string   `json:"domain"`
	Open       int      `json:"open"`
	Triaged    int      `json:"triaged"`
	FP         int      `json:"fp"`
	Accepted   int      `json:"accepted"`
	Fixed      int      `json:"fixed"`
	LastSeen   string   `json:"last_seen"`
	ScanLabels []string `json:"scan_labels"`
}

// severityOrder maps severity names to a sort key (lower = higher priority).
var severityOrder = map[string]int{
	"high":          0,
	"medium":        1,
	"low":           2,
	"informational": 3,
	"info":          3,
}

func severityRank(s string) int {
	if r, ok := severityOrder[strings.ToLower(s)]; ok {
		return r
	}
	return 99
}

// buildReportRows produces sorted reportRows from an EntitiesFile.
// filterStatus, when non-empty, limits rows to those where the named
// status count is > 0 (e.g., "open").
func buildReportRows(ef entities.EntitiesFile, filterStatus string) []reportRow {
	// Build occurrence counts per finding.
	type counts struct {
		open, triaged, fp, accepted, fixed int
		lastSeen                           string
		scanLabelsSeen                     map[string]struct{}
		scanLabels                         []string
	}
	occMap := make(map[string]*counts)
	for _, o := range ef.Occurrences {
		c := occMap[o.FindingID]
		if c == nil {
			c = &counts{scanLabelsSeen: make(map[string]struct{})}
			occMap[o.FindingID] = c
		}
		status := "open"
		if o.Analyst != nil && o.Analyst.Status != "" {
			status = o.Analyst.Status
		}
		switch status {
		case "open":
			c.open++
		case "triaged":
			c.triaged++
		case "fp":
			c.fp++
		case "accepted":
			c.accepted++
		case "fixed":
			c.fixed++
		default:
			c.open++
		}
		// Track most-recent ObservedAt
		if o.ObservedAt > c.lastSeen {
			c.lastSeen = o.ObservedAt
		}
		// Collect distinct scan labels, order-preserving
		if o.ScanLabel != "" {
			if _, seen := c.scanLabelsSeen[o.ScanLabel]; !seen {
				c.scanLabelsSeen[o.ScanLabel] = struct{}{}
				c.scanLabels = append(c.scanLabels, o.ScanLabel)
			}
		}
	}

	// Build definition lookup for rule title.
	defTitles := make(map[string]string)
	for _, d := range ef.Definitions {
		title := d.Alert
		if title == "" {
			title = d.Name
		}
		defTitles[d.DefinitionID] = title
	}

	var rows []reportRow
	for _, f := range ef.Findings {
		c := occMap[f.FindingID]
		if c == nil {
			c = &counts{}
		}

		// Apply filter
		switch filterStatus {
		case "open":
			if c.open == 0 {
				continue
			}
		case "triaged":
			if c.triaged == 0 {
				continue
			}
		case "fp":
			if c.fp == 0 {
				continue
			}
		case "accepted":
			if c.accepted == 0 {
				continue
			}
		case "fixed":
			if c.fixed == 0 {
				continue
			}
		}

		title := defTitles[f.DefinitionID]
		if title == "" {
			title = f.Name
		}

		rows = append(rows, reportRow{
			FindingID:  f.FindingID,
			RuleTitle:  title,
			Severity:   f.Risk,
			Domain:     domainFromURL(f.URL),
			Open:       c.open,
			Triaged:    c.triaged,
			FP:         c.fp,
			Accepted:   c.accepted,
			Fixed:      c.fixed,
			LastSeen:   c.lastSeen,
			ScanLabels: c.scanLabels,
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := severityRank(rows[i].Severity), severityRank(rows[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return rows[i].FindingID < rows[j].FindingID
	})
	return rows
}

// domainFromURL extracts the host from a URL string, returning the full URL
// unchanged if it cannot be parsed (avoids importing net/url for a best-effort field).
func domainFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// Strip scheme
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip port for readability (keep host only)
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return rawURL
	}
	return s
}

// runReportCommand implements the "report" sub-command.
// Usage: zap-kb report -entities-in ef.json [-format csv|json] [-filter-status open] [-out path]
func runReportCommand(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var entitiesIn string
	var format string
	var filterStatus string
	var outPath string
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON input file (required)")
	fs.StringVar(&format, "format", "csv", "Output format: csv|json")
	fs.StringVar(&filterStatus, "filter-status", "", "Limit rows to findings with this status > 0 (open|triaged|fp|accepted|fixed)")
	fs.StringVar(&outPath, "out", "-", "Output file path; use \"-\" or omit for stdout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "report: %v\n", err)
		os.Exit(1)
	}

	entitiesIn = strings.TrimSpace(entitiesIn)
	if entitiesIn == "" {
		fmt.Fprintln(os.Stderr, "report: -entities-in is required")
		fs.Usage()
		os.Exit(1)
	}

	art, err := runartifact.ReadFlexible(entitiesIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report: read %q: %v\n", entitiesIn, err)
		os.Exit(1)
	}
	ef := art.Entities

	rows := buildReportRows(ef, strings.TrimSpace(filterStatus))

	var out []byte
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		out, err = json.MarshalIndent(rows, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: encode json: %v\n", err)
			os.Exit(1)
		}
		out = append(out, '\n')
	default: // csv
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		_ = w.Write([]string{"finding_id", "rule_title", "severity", "domain", "open", "triaged", "fp", "accepted", "fixed", "last_seen", "scan_labels"})
		for _, r := range rows {
			_ = w.Write([]string{
				r.FindingID,
				r.RuleTitle,
				r.Severity,
				r.Domain,
				fmt.Sprintf("%d", r.Open),
				fmt.Sprintf("%d", r.Triaged),
				fmt.Sprintf("%d", r.FP),
				fmt.Sprintf("%d", r.Accepted),
				fmt.Sprintf("%d", r.Fixed),
				r.LastSeen,
				strings.Join(r.ScanLabels, "|"),
			})
		}
		w.Flush()
		out = []byte(sb.String())
	}

	outPath = strings.TrimSpace(outPath)
	if outPath == "" || outPath == "-" {
		os.Stdout.Write(out)
	} else {
		if werr := os.WriteFile(outPath, out, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "report: write %q: %v\n", outPath, werr)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "Report: %d findings, %d definitions, %d occurrences\n",
		len(ef.Findings), len(ef.Definitions), len(ef.Occurrences))
}
