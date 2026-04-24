package main

// expired sub-command: reports findings whose risk-acceptance has lapsed
// (epic #71 slice 2, issue #58).
//
// Usage:
//
//	zap-kb expired -entities-in ef.json [-format csv|json] [-out path]
//
// A finding enters the expired list when:
//   - analyst.status == "accepted"  AND
//   - analyst.acceptedUntil is a valid RFC3339 date that is in the past.
//
// Findings with status=accepted but no acceptedUntil are treated as indefinitely
// accepted and are NOT included in the expired list. A stderr warning is emitted
// for each so operators can decide whether to add an expiry date.

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

// expiredRow is one entry in the acceptance-expired report.
type expiredRow struct {
	FindingID     string `json:"finding_id"`
	RuleTitle     string `json:"rule_title"`
	Severity      string `json:"severity"`
	Domain        string `json:"domain"`
	Owner         string `json:"owner"`
	AcceptedUntil string `json:"accepted_until"`
	ExpiredAgo    string `json:"expired_ago"`
	Notes         string `json:"notes"`
}

// buildExpiredRows returns findings whose acceptance has lapsed and a separate
// list of finding IDs that are accepted with no expiry date (indefinite).
// Expired rows are sorted most-overdue first (earliest acceptedUntil first),
// then by FindingID for stability.
func buildExpiredRows(ef entities.EntitiesFile, now time.Time) (expired []expiredRow, indefinite []string) {
	defTitles := make(map[string]string)
	for _, d := range ef.Definitions {
		title := d.Alert
		if title == "" {
			title = d.Name
		}
		defTitles[d.DefinitionID] = title
	}

	for _, f := range ef.Findings {
		if f.Analyst == nil {
			continue
		}
		if entities.CanonicalAnalystStatus(f.Analyst.Status) != "accepted" {
			continue
		}
		raw := strings.TrimSpace(f.Analyst.AcceptedUntil)
		if raw == "" {
			indefinite = append(indefinite, f.FindingID)
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			// Unparseable date: surface it for review; treat as expired.
			expired = append(expired, expiredRow{
				FindingID:     f.FindingID,
				RuleTitle:     defTitles[f.DefinitionID],
				Severity:      f.Risk,
				Domain:        domainFromURL(f.URL),
				Owner:         strings.TrimSpace(f.Analyst.Owner),
				AcceptedUntil: raw + " (unparseable)",
				ExpiredAgo:    "unknown",
				Notes:         strings.TrimSpace(f.Analyst.Notes),
			})
			continue
		}
		if t.Before(now) {
			expired = append(expired, expiredRow{
				FindingID:     f.FindingID,
				RuleTitle:     defTitles[f.DefinitionID],
				Severity:      f.Risk,
				Domain:        domainFromURL(f.URL),
				Owner:         strings.TrimSpace(f.Analyst.Owner),
				AcceptedUntil: raw,
				ExpiredAgo:    humanDuration(now.Sub(t)),
				Notes:         strings.TrimSpace(f.Analyst.Notes),
			})
		}
	}

	sort.SliceStable(expired, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, expired[i].AcceptedUntil)
		tj, _ := time.Parse(time.RFC3339, expired[j].AcceptedUntil)
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return expired[i].FindingID < expired[j].FindingID
	})

	return expired, indefinite
}

// humanDuration formats a duration as a compact string (e.g. "3d", "2mo", "1y").
func humanDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	switch {
	case days >= 365:
		return fmt.Sprintf("%dy", days/365)
	case days >= 30:
		return fmt.Sprintf("%dmo", days/30)
	case days >= 1:
		return fmt.Sprintf("%dd", days)
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

func runExpiredCommand(args []string) {
	fs := flag.NewFlagSet("expired", flag.ExitOnError)
	var entitiesIn, format, outPath string
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON input file (required)")
	fs.StringVar(&format, "format", "csv", "Output format: csv|json")
	fs.StringVar(&outPath, "out", "-", "Output file path; use \"-\" or omit for stdout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "expired: %v\n", err)
		os.Exit(1)
	}
	entitiesIn = strings.TrimSpace(entitiesIn)
	if entitiesIn == "" {
		fmt.Fprintln(os.Stderr, "expired: -entities-in is required")
		fs.Usage()
		os.Exit(1)
	}

	art, err := runartifact.ReadFlexible(entitiesIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "expired: read %q: %v\n", entitiesIn, err)
		os.Exit(1)
	}

	rows, indefinite := buildExpiredRows(art.Entities, time.Now().UTC())
	for _, fid := range indefinite {
		fmt.Fprintf(os.Stderr, "[warn] %s: status=accepted with no acceptedUntil (permanent acceptance — consider adding an expiry date)\n", fid)
	}

	var out []byte
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		out, err = json.MarshalIndent(rows, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "expired: encode json: %v\n", err)
			os.Exit(1)
		}
		out = append(out, '\n')
	default: // csv
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		_ = w.Write([]string{"finding_id", "rule_title", "severity", "domain", "owner", "accepted_until", "expired_ago", "notes"})
		for _, r := range rows {
			_ = w.Write([]string{r.FindingID, r.RuleTitle, r.Severity, r.Domain, r.Owner, r.AcceptedUntil, r.ExpiredAgo, r.Notes})
		}
		w.Flush()
		out = []byte(sb.String())
	}

	outPath = strings.TrimSpace(outPath)
	if outPath == "" || outPath == "-" {
		os.Stdout.Write(out)
	} else {
		if werr := os.WriteFile(outPath, out, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "expired: write %q: %v\n", outPath, werr)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "Acceptance expired: %d finding(s) (+ %d indefinite warning(s))\n",
		len(rows), len(indefinite))
}
