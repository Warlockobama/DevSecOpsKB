package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/ziputil"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

func main() {
	var (
		zapURL             string
		apiKey             string
		baseURL            string
		count              int
		out                string
		merge              bool
		format             string
		source             string
		vault              string
		infile             string
		entitiesIn         string
		plugins            string
		allPlugins         bool
		genAt              string
		includeTraffic     bool
		trafficMax         int
		trafficMaxPerIssue int
		trafficTotalMax    int
		scanLabel          string
		siteLabel          string
		trafficScope       string
		zapBase            string
		trafficMinRisk     string
		includeDetect      bool
		detectDetails      string
		initMode           bool
		runOut             string
		runIn              string
		zipOut             string
		redactOpts         string
		wizard             bool
		pruneScanLabel     string
		pruneSiteLabel     string
		pruneVault         string
		pruneDryRun        bool
		reportOut          string
		reportSince        string
		reportUntil        string
		reportLookback     string
		reportTitle        string
		reportScanLabel    string
	)
	flag.StringVar(&zapURL, "zap-url", "http://127.0.0.1:8090", "ZAP API base URL")
	flag.StringVar(&apiKey, "api-key", "", "ZAP API key (if required)")
	flag.StringVar(&baseURL, "baseurl", "", "Filter alerts by baseurl (optional)")
	flag.IntVar(&count, "count", 0, "Number of alerts to fetch (0 = all)")
	flag.StringVar(&out, "out", "docs/data/alerts.json", "Write JSON to this path")
	flag.BoolVar(&merge, "merge", false, "Merge with existing JSON (de-duplicate)")
	flag.StringVar(&format, "format", "entities", "Output format: entities|flat|both|obsidian")
	flag.StringVar(&source, "source", "zap", "Source tool name (zap, burp, etc.)")
	flag.StringVar(&vault, "obsidian-dir", "docs/obsidian", "Output dir for Obsidian vault (when -format=obsidian)")
	flag.StringVar(&infile, "in", "", "Optional input file of ZAP alerts (JSON array); skips API fetch when set")
	flag.StringVar(&entitiesIn, "entities-in", "", "Optional input Entities JSON to merge/enrich; enables enrich-only mode when no alerts")
	flag.StringVar(&plugins, "plugins", "", "Comma/space-separated list of plugin IDs to add/update definitions for (enrich-only capable). Use 'all' to update all known plugins.")
	flag.BoolVar(&allPlugins, "all-plugins", false, "Discover all ZAP plugins from docs and update their definitions (enrich-only capable)")
	flag.StringVar(&genAt, "generated-at", "", "Optional RFC3339 timestamp to set in entities output for stable diffs")
	flag.BoolVar(&includeTraffic, "include-traffic", false, "Enrich with first-occurrence HTTP request/response snippets")
	flag.IntVar(&trafficMax, "traffic-max-bytes", 2048, "Max bytes to capture for request/response snippets")
	flag.StringVar(&trafficScope, "traffic-scope", "first", "Traffic enrichment scope: first|all")
	flag.IntVar(&trafficMaxPerIssue, "traffic-max-per-issue", 1, "Max occurrences per issue to enrich with traffic (applies to first scope)")
	flag.IntVar(&trafficTotalMax, "traffic-total-max", 0, "Global cap on number of occurrences to enrich with traffic (0 = unlimited)")
	flag.StringVar(&trafficMinRisk, "traffic-min-risk", "info", "Minimum risk to enrich traffic: info|low|medium|high")
	flag.StringVar(&scanLabel, "scan-label", "", "Optional label for this scan/session (appears in INDEX and frontmatter)")
	flag.StringVar(&siteLabel, "site-label", "", "Optional site/domain label override when domains are redacted")
	flag.StringVar(&zapBase, "zap-base-url", "", "Optional ZAP base URL to link back to messages in Obsidian")
	flag.BoolVar(&includeDetect, "include-detection", false, "Enrich with detection logic links from ZAP docs/GitHub")
	flag.StringVar(&detectDetails, "detection-details", "links", "Detection enrichment detail: links|summary")
	flag.BoolVar(&initMode, "init", false, "Init KB without run data: seed/update definitions only (no alert fetch)")
	flag.StringVar(&runOut, "run-out", "", "Write a pipeline-friendly run artifact JSON (entities+meta[+alerts])")
	flag.StringVar(&runIn, "run-in", "", "Read a run artifact JSON (or bare entities JSON) and use it as -entities-in; also picks up scan/site labels if present")
	flag.StringVar(&zipOut, "zip-out", "", "Zip outputs to this path (includes run-out, entities out, and obsidian dir if generated)")
	flag.StringVar(&redactOpts, "redact", "", "Comma/space list of redactions: domain,query,cookies,auth,headers,body")
	flag.BoolVar(&wizard, "wizard", true, "Launch an interactive setup wizard when no flags are provided (disable with -wizard=false)")
	// Prune options (vault-only maintenance): when -prune-scan is set, performs pruning and exits
	flag.StringVar(&pruneScanLabel, "prune-scan", "", "Prune occurrence notes from the Obsidian vault with this scan label; no fetch or export performed")
	flag.StringVar(&pruneSiteLabel, "prune-site", "", "Optional site/domain label filter when pruning (matches frontmatter 'domain')")
	flag.StringVar(&pruneVault, "prune-vault", "", "Vault directory to operate on when pruning (defaults to -obsidian-dir)")
	flag.BoolVar(&pruneDryRun, "prune-dry-run", false, "List matching files without deleting")
	flag.StringVar(&reportOut, "report-out", "", "Write a markdown report summarizing occurrences within a window (requires -format=obsidian); relative paths are rooted at the vault.")
	flag.StringVar(&reportSince, "report-since", "", "Inclusive start date/time (RFC3339 or YYYY-MM-DD) for the report window; overrides -report-lookback when set.")
	flag.StringVar(&reportUntil, "report-until", "", "Inclusive end date/time (RFC3339 or YYYY-MM-DD) for the report window; defaults to now when unset.")
	flag.StringVar(&reportLookback, "report-lookback", "", "Lookback window (e.g., 30d, 12w, 3m, 1y) when -report-since is not provided; defaults to 30d when -report-out is set.")
	flag.StringVar(&reportTitle, "report-title", "", "Optional title for the generated report.")
	flag.StringVar(&reportScanLabel, "report-scan", "", "Optional scan.label filter for the report.")
	flag.Parse()

	// Prune-only mode: delete occurrence files by scan label (and optional site) from the vault, then refresh INDEX/DASHBOARD
	if strings.TrimSpace(pruneScanLabel) != "" {
		vdir := strings.TrimSpace(pruneVault)
		if vdir == "" {
			vdir = vault
			if strings.TrimSpace(vdir) == "" {
				vdir = "docs/obsidian"
			}
		}
		// perform prune
		del, listed, perr := obsidian.PruneByScan(vdir, pruneScanLabel, pruneSiteLabel, pruneDryRun)
		if perr != nil {
			log.Fatalf("prune: %v", perr)
		}
		if pruneDryRun {
			fmt.Printf("Prune dry-run: %d files would be removed.\n", del)
		} else {
			fmt.Printf("Pruned %d occurrence files.\n", del)
		}
		// Always show a small preview of affected files (up to 10)
		maxShow := 10
		if len(listed) < maxShow {
			maxShow = len(listed)
		}
		for i := 0; i < maxShow; i++ {
			fmt.Printf("- %s\n", listed[i])
		}
		// Rebuild INDEX and DASHBOARD w/o touching content by invoking WriteVault with empty entities
		var ef entities.EntitiesFile
		ef.SchemaVersion = "v1"
		ef.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		ef.SourceTool = source
		if err := obsidian.WriteVault(vdir, ef, obsidian.Options{ScanLabel: "", SiteLabel: "", ZapBaseURL: strings.TrimSpace(zapBase)}); err != nil {
			log.Fatalf("refresh index: %v", err)
		}
		fmt.Println("Refreshed INDEX.md and DASHBOARD.md")
		return
	}

	if shouldLaunchWizard(wizard) {
		wiz := wizardInputs{
			ZapURL:          &zapURL,
			APIKey:          &apiKey,
			BaseURL:         &baseURL,
			Count:           &count,
			Out:             &out,
			Vault:           &vault,
			Format:          &format,
			InFile:          &infile,
			EntitiesIn:      &entitiesIn,
			RunIn:           &runIn,
			RunOut:          &runOut,
			ZipOut:          &zipOut,
			IncludeTraffic:  &includeTraffic,
			TrafficScope:    &trafficScope,
			TrafficMaxBytes: &trafficMax,
			TrafficMaxPer:   &trafficMaxPerIssue,
			TrafficTotalMax: &trafficTotalMax,
			TrafficMinRisk:  &trafficMinRisk,
			IncludeDetect:   &includeDetect,
			DetectDetails:   &detectDetails,
			ScanLabel:       &scanLabel,
			SiteLabel:       &siteLabel,
			ZapBaseURL:      &zapBase,
			SourceTool:      &source,
		}
		if err := runWizard(wiz); err != nil {
			log.Fatalf("wizard: %v", err)
		}
	}

	if includeTraffic {
		if strings.TrimSpace(trafficMinRisk) == "" || strings.EqualFold(trafficMinRisk, "info") {
			trafficMinRisk = "medium"
		}
		if trafficTotalMax <= 0 {
			trafficTotalMax = 50
		}
	}

	var (
		client *zapclient.Client
		alerts []zapclient.Alert
		entIn  entities.EntitiesFile
		err    error
	)

	// If -run-in is provided, load entities and default labels/meta from it.
	if strings.TrimSpace(runIn) != "" {
		a, rerr := runartifact.ReadFlexible(runIn)
		if rerr != nil {
			log.Fatalf("read -run-in: %v", rerr)
		}
		entIn = a.Entities
		if len(a.Alerts) > 0 {
			alerts = append(alerts, a.Alerts...)
		}
		// adopt labels if not provided via flags
		if strings.TrimSpace(scanLabel) == "" && strings.TrimSpace(a.Meta.ScanLabel) != "" {
			scanLabel = a.Meta.ScanLabel
		}
		if strings.TrimSpace(siteLabel) == "" && strings.TrimSpace(a.Meta.SiteLabel) != "" {
			siteLabel = a.Meta.SiteLabel
		}
		if strings.TrimSpace(zapBase) == "" && strings.TrimSpace(a.Meta.ZapBaseURL) != "" {
			zapBase = a.Meta.ZapBaseURL
		}
	}

	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer fetchCancel()

	// Decide if we should fetch alerts from ZAP API
	// Fetch only when not explicitly in init/enrich-only modes and no explicit entities/plugin list is provided.
	fetchAllowed := strings.TrimSpace(infile) == "" && strings.TrimSpace(runIn) == "" && !initMode && strings.TrimSpace(entitiesIn) == "" && !allPlugins && strings.TrimSpace(plugins) == ""

	if strings.TrimSpace(infile) != "" {
		// Read alerts from file and skip API calls
		f, err := os.Open(infile)
		if err != nil {
			log.Fatalf("open -in file: %v", err)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		if err := dec.Decode(&alerts); err != nil {
			log.Fatalf("decode -in file: %v", err)
		}
	} else if fetchAllowed { // fetch only when not enrich-only
		// Fetch from ZAP API
		client, err = zapclient.NewClient(zapURL, apiKey)
		if err != nil {
			log.Fatalf("new client: %v", err)
		}
		// Default = all alerts; -count N restricts to first N
		if count > 0 {
			alerts, err = client.GetAlerts(fetchCtx, zapclient.AlertsFilter{
				BaseURL: baseURL, Count: count, Start: 0, Recurse: true,
			})
		} else {
			alerts, err = client.GetAllAlerts(fetchCtx, zapclient.AlertsFilter{
				BaseURL: baseURL, Recurse: true,
			})
		}
		if err != nil {
			log.Fatalf("get alerts: %v", err)
		}
	} else {
		// Helpful note for offline init/enrich-only runs
		if initMode || allPlugins || strings.TrimSpace(plugins) != "" || strings.TrimSpace(entitiesIn) != "" {
			fmt.Println("Init/enrich-only mode: skipping ZAP API fetch")
		}
	}

	// Optional input Entities for merge/enrich-only (overridden when -run-in used)
	if strings.TrimSpace(entitiesIn) != "" && strings.TrimSpace(runIn) == "" {
		f, err := os.Open(entitiesIn)
		if err != nil {
			log.Fatalf("open -entities-in file: %v", err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&entIn); err != nil {
			log.Fatalf("decode -entities-in file: %v", err)
		}
	}

	// optional merge (flat alerts only)
	if merge {
		if format == "flat" || format == "both" {
			var existing []zapclient.Alert
			_ = jsondump.ReadIfExists(out, &existing)
			alerts = append(existing, alerts...)
		} else {
			fmt.Println("Note: -merge is for flat alerts; use -entities-in to merge entities")
		}
	}

	// always dedup before write
	alerts = zapclient.DeduplicateAlerts(alerts)

	// preview
	fmt.Printf("Fetched %d alerts (after dedup)\n", len(alerts))
	for i, a := range alerts {
		if i >= 5 {
			break
		}
		fmt.Printf("[%d] %s | risk=%s url=%s param=%s plugin=%s cwe=%d\n",
			i, a.Alert, a.Risk, a.URL, a.Param, a.PluginID, a.CWEID.Int())
	}

	// Build entities model (or merge/enrich) if needed by chosen output
	var ent entities.EntitiesFile
	if format == "entities" || format == "both" || format == "obsidian" {
		if len(entIn.Definitions) > 0 || len(entIn.Findings) > 0 || len(entIn.Occurrences) > 0 {
			ent = entIn
		}
		// Single timestamp to stamp this generation and as observedAt for new occurrences
		runGeneratedAt := strings.TrimSpace(genAt)
		if runGeneratedAt == "" {
			if len(alerts) > 0 {
				runGeneratedAt = time.Now().UTC().Format(time.RFC3339)
			} else if strings.TrimSpace(ent.GeneratedAt) != "" {
				runGeneratedAt = ent.GeneratedAt
			} else {
				runGeneratedAt = time.Now().UTC().Format(time.RFC3339)
			}
		}
		if len(alerts) > 0 {
			built := entities.BuildEntitiesWithOptions(alerts, entities.BuildOptions{
				SourceTool:  source,
				ScanLabel:   scanLabel,
				GeneratedAt: runGeneratedAt,
				ObservedAt:  runGeneratedAt,
			})
			if len(ent.Definitions) == 0 && len(ent.Findings) == 0 && len(ent.Occurrences) == 0 {
				ent = built
			} else {
				ent = entities.Merge(ent, built)
			}
		}

		// Ensure definitions exist for explicit/all plugin IDs (or default-all when init mode)
		var newDefs int
		if strings.TrimSpace(plugins) != "" || allPlugins || initMode {
			// Accept comma or space separators
			var fields []string
			ptrim := strings.TrimSpace(plugins)
			if allPlugins || strings.EqualFold(ptrim, "all") || (initMode && ptrim == "") {
				fields = zapmeta.ListAllPluginIDs(fetchCtx)
			} else {
				fields = strings.FieldsFunc(plugins, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
			}
			if len(fields) > 0 {
				// Build an index for existing defs
				defIndex := map[string]struct{}{}
				for _, d := range ent.Definitions {
					defIndex[strings.TrimSpace(d.DefinitionID)] = struct{}{}
				}
				for _, pid := range fields {
					pid = strings.TrimSpace(pid)
					if pid == "" {
						continue
					}
					id := "def-" + pid
					if _, ok := defIndex[id]; ok {
						continue
					}
					// Add a stub definition; enrichment will fill detection/title.
					ent.Definitions = append(ent.Definitions, entities.Definition{
						DefinitionID: id,
						PluginID:     pid,
					})
					defIndex[id] = struct{}{}
					newDefs++
				}
			}
		}
		// optional override of generatedAt for stable diffs during iteration
		ent.GeneratedAt = runGeneratedAt
		// fill defaults if missing (e.g., plugins-only mode)
		if strings.TrimSpace(ent.SchemaVersion) == "" {
			ent.SchemaVersion = "v1"
		}
		if strings.TrimSpace(ent.SourceTool) == "" {
			ent.SourceTool = source
		}
		if strings.TrimSpace(ent.GeneratedAt) == "" {
			ent.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		}
		var enrichCtx context.Context
		var enrichCancel context.CancelFunc
		if includeTraffic || includeDetect {
			enrichCtx, enrichCancel = context.WithTimeout(context.Background(), 10*time.Minute)
			defer enrichCancel()
		}
		if includeTraffic {
			if enrichCtx == nil {
				enrichCtx, enrichCancel = context.WithTimeout(context.Background(), 10*time.Minute)
				defer enrichCancel()
			}
			if trafficScope == "all" {
				_ = entities.EnrichAllTraffic(enrichCtx, client, &ent, trafficMax)
			} else {
				// Selective enrichment: honor per-issue, min risk, and global cap
				_ = entities.EnrichTrafficSelective(enrichCtx, client, &ent, trafficMaxPerIssue, trafficMinRisk, trafficTotalMax, trafficMax)
			}
		}
		if includeDetect {
			if enrichCtx == nil {
				enrichCtx, enrichCancel = context.WithTimeout(context.Background(), 10*time.Minute)
				defer enrichCancel()
			}
			entities.EnrichDetections(enrichCtx, &ent)
			if strings.ToLower(strings.TrimSpace(detectDetails)) == "summary" {
				entities.EnrichDetectionSummaries(enrichCtx, &ent)
			}
		}

		// Optional redaction pass
		if strings.TrimSpace(redactOpts) != "" {
			ro := entities.ParseRedactOptionList(redactOpts)
			entities.RedactEntities(&ent, ro)
		}

		// Print a concise init/enrich summary when not fetching alerts
		if fetchAllowed == false { // enrich-only / init flows
			// detection stats
			defsTotal := len(ent.Definitions)
			detCount, srcCount, titled := 0, 0, 0
			for _, d := range ent.Definitions {
				if d.Detection != nil {
					detCount++
					if strings.TrimSpace(d.Detection.RuleSource) != "" || strings.TrimSpace(d.Detection.SourceURL) != "" {
						srcCount++
					}
				}
				if strings.TrimSpace(d.Alert) != "" || strings.TrimSpace(d.Name) != "" {
					titled++
				}
			}
			fmt.Printf("Init summary: defs total=%d new=%d detection=%d with-source=%d titled=%d\n", defsTotal, newDefs, detCount, srcCount, titled)
		}
	}

	// write
	switch format {
	case "entities":
		if err := jsondump.WritePretty(out, ent); err != nil {
			log.Fatalf("write json: %v", err)
		}
	case "flat":
		if err := jsondump.WritePretty(out, alerts); err != nil {
			log.Fatalf("write json: %v", err)
		}
	case "both":
		if err := jsondump.WritePretty(out, alerts); err != nil {
			log.Fatalf("write json flat: %v", err)
		}
		if err := jsondump.WritePretty(out+".entities.json", ent); err != nil {
			log.Fatalf("write json entities: %v", err)
		}
	case "obsidian":
		if err := obsidian.WriteVault(vault, ent, obsidian.Options{ScanLabel: scanLabel, SiteLabel: siteLabel, ZapBaseURL: zapBase}); err != nil {
			log.Fatalf("write obsidian: %v", err)
		}
	default:
		log.Fatalf("unknown -format %q (use entities|flat|both|obsidian)", format)
	}

	// Optional report generation (vault-wide, time-bounded)
	if strings.TrimSpace(reportOut) != "" {
		if format != "obsidian" {
			fmt.Println("Note: -report-out requires -format=obsidian; skipping report generation.")
		} else {
			rs, ru, rerr := computeReportWindow(reportSince, reportUntil, reportLookback)
			if rerr != nil {
				log.Fatalf("report window: %v", rerr)
			}
			if err := obsidian.GenerateReport(vault, obsidian.ReportOptions{
				OutPath:   reportOut,
				Title:     reportTitle,
				Since:     rs,
				Until:     ru,
				ScanLabel: reportScanLabel,
			}); err != nil {
				log.Fatalf("report: %v", err)
			}
			fmt.Printf("Wrote report to %s\n", reportOut)
		}
	}

	// Optionally write a run artifact (entities + meta [+alerts]) for pipelines
	if strings.TrimSpace(runOut) != "" {
		meta := runartifact.Meta{
			SourceTool:       ent.SourceTool,
			GeneratedAt:      ent.GeneratedAt,
			ScanLabel:        scanLabel,
			SiteLabel:        siteLabel,
			ZapBaseURL:       zapBase,
			BaseURL:          baseURL,
			DetectionDetails: detectDetails,
			IncludeTraffic:   includeTraffic,
		}
		art := runartifact.Artifact{Schema: "zap-kb/run/v1", Meta: meta, Entities: ent, Alerts: alerts}
		if err := runartifact.Write(runOut, art); err != nil {
			log.Fatalf("write -run-out: %v", err)
		}
		fmt.Printf("Wrote run artifact to %s\n", runOut)
	}

	// Optionally zip outputs for easy artifacting
	if strings.TrimSpace(zipOut) != "" {
		var ins []string
		if strings.TrimSpace(runOut) != "" {
			ins = append(ins, runOut)
		}
		if strings.TrimSpace(out) != "" {
			ins = append(ins, out)
		}
		if format == "both" {
			ins = append(ins, out+".entities.json")
		}
		if format == "obsidian" && strings.TrimSpace(vault) != "" {
			ins = append(ins, vault)
		}
		if len(ins) == 0 && strings.TrimSpace(out) != "" {
			ins = append(ins, out)
		}
		if err := ziputil.Zip(zipOut, ins...); err != nil {
			log.Fatalf("zip: %v", err)
		}
		fmt.Printf("Zipped outputs to %s\n", zipOut)
	}

	// Exit code 2 only when no content produced at all (no alerts and no entities).
	if (format == "flat" || format == "both") && len(alerts) == 0 && len(ent.Definitions) == 0 {
		os.Exit(2)
	}
}

// computeReportWindow parses the since/until/lookback flag trio into concrete times.
// Defaults: until=now when unset; since=until-30d when reportOut is set but no bounds provided.
func computeReportWindow(rawSince, rawUntil, rawLookback string) (time.Time, time.Time, error) {
	var since time.Time
	until := time.Now().UTC()
	if strings.TrimSpace(rawUntil) != "" {
		t, err := parseReportTime(rawUntil)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid -report-until: %w", err)
		}
		until = t
	}

	if strings.TrimSpace(rawLookback) != "" {
		dur, err := parseLookback(rawLookback)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid -report-lookback: %w", err)
		}
		since = until.Add(-dur)
	}
	if strings.TrimSpace(rawSince) != "" {
		t, err := parseReportTime(rawSince)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid -report-since: %w", err)
		}
		since = t
	}
	if since.IsZero() {
		since = until.Add(-30 * 24 * time.Hour)
	}
	if since.After(until) {
		since, until = until, since
	}
	return since, until, nil
}

// parseReportTime accepts RFC3339 timestamps or dates in YYYY-MM-DD.
func parseReportTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	layouts := []string{time.RFC3339, "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", raw)
}

// parseLookback parses simple duration-ish strings for reporting: Nd, Nw, Nm, Ny (days/weeks/months/years).
func parseLookback(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}
	unit := raw[len(raw)-1]
	num := raw[:len(raw)-1]
	if unit >= '0' && unit <= '9' {
		unit = 'd'
		num = raw
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid number in %q", raw)
	}
	switch unit {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n*7) * 24 * time.Hour, nil
	case 'm':
		return time.Duration(n*30) * 24 * time.Hour, nil
	case 'y':
		return time.Duration(n*365) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown unit %q (use d,w,m,y)", string(unit))
	}
}
