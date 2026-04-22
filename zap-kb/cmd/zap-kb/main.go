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

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/confluence"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jira"
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
		confURL            string
		confUser           string
		confToken          string
		confSpace          string
		confParent         string
		confTitlePrefix    string
		confDryRun         bool
		confFull           bool
		confConcurrency    int
		jiraURL            string
		jiraUser           string
		jiraToken          string
		jiraProject        string
		jiraIssueType      string
		jiraComponent      string
		jiraLabels         string
		jiraMinRisk        string
		jiraOptInTag       string
		jiraDryRun         bool
		jiraConcurrency    int
		jiraDetectionEpic  bool
		jiraEpicIssueType  string
		jiraEpicComponent  string
		allowAgentPublish  bool
		allowCustomPublish bool
	)
	flag.StringVar(&zapURL, "zap-url", "http://127.0.0.1:8090", "ZAP API base URL (env: ZAP_URL)")
	flag.StringVar(&apiKey, "api-key", "", "ZAP API key (env: ZAP_API_KEY)")
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
	flag.StringVar(&redactOpts, "redact", "", "Comma/space list of redactions: domain,query,cookies,auth,headers,body,notes")
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
	flag.StringVar(&confURL, "confluence-url", "", "Confluence base URL (enables export of INDEX.md to Confluence).")
	flag.StringVar(&confUser, "confluence-user", "", "Confluence username (env: CONFLUENCE_USER).")
	flag.StringVar(&confToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN).")
	flag.StringVar(&confSpace, "confluence-space", "", "Confluence space key.")
	flag.StringVar(&confParent, "confluence-parent", "", "Optional Confluence parent page ID.")
	flag.StringVar(&confTitlePrefix, "confluence-title-prefix", "", "Optional title prefix for exported page (default: KB Index).")
	flag.BoolVar(&confDryRun, "confluence-dry-run", false, "Dry-run Confluence export (log instead of POST).")
	flag.BoolVar(&confFull, "confluence-full", false, "Export full vault to Confluence (INDEX, Dashboard, Triage Board, all definitions).")
	flag.IntVar(&confConcurrency, "confluence-concurrency", 3, "Max parallel Confluence API requests for full export (default: 3, max: 5).")
	flag.StringVar(&jiraURL, "jira-url", "", "Jira base URL (enables export of findings as Jira issues).")
	flag.StringVar(&jiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER).")
	flag.StringVar(&jiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN).")
	flag.StringVar(&jiraProject, "jira-project", "", "Jira project key (e.g. SEC).")
	flag.StringVar(&jiraIssueType, "jira-issue-type", "Bug", "Jira issue type (default: Bug).")
	flag.StringVar(&jiraComponent, "jira-component", "", "Optional Jira component name to assign.")
	flag.StringVar(&jiraLabels, "jira-labels", "", "Comma-separated extra labels to add to each issue.")
	flag.StringVar(&jiraMinRisk, "jira-min-risk", "medium", "Minimum risk level to export: info|low|medium|high (default: medium).")
	flag.StringVar(&jiraOptInTag, "jira-opt-in-tag", "case-ticket", "Analyst tag that forces Jira export for lower-severity findings.")
	flag.BoolVar(&jiraDryRun, "jira-dry-run", false, "Dry-run Jira export (log instead of POST).")
	flag.IntVar(&jiraConcurrency, "jira-concurrency", 3, "Max parallel Jira API requests (default: 3, max: 5).")
	flag.BoolVar(&jiraDetectionEpic, "jira-detection-epic", false, "Create/reuse a parent Epic per detection (definition); findings link via parent.")
	flag.StringVar(&jiraEpicIssueType, "jira-epic-issue-type", "Epic", "Issue type for detection Epics (default: Epic; override for projects that use Initiative).")
	flag.StringVar(&jiraEpicComponent, "jira-epic-component", "", "Optional Jira component name applied to detection Epics.")
	flag.BoolVar(&allowAgentPublish, "allow-agent-publish", false, "Allow Confluence/Jira publish from sourceTool values like zap-agent (disabled by default)")
	flag.BoolVar(&allowCustomPublish, "allow-custom-publish", false, "Allow Confluence/Jira publish when the input contains custom definitions (disabled by default)")
	// Sub-command dispatch: if the first argument is "merge", run the merge
	// sub-command with its own flag set and exit without touching the global flags.
	if len(os.Args) > 1 && os.Args[1] == "merge" {
		runMergeCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "report" {
		runReportCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "pull" {
		runPullCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "config" {
		runConfigCommand(os.Args[2:])
		return
	}

	flag.Parse()

	// Environment variable fallbacks for credentials and URLs.
	// Flags take precedence; env vars are checked only when the flag is empty.
	// This keeps credentials out of the process table and shell history.
	envFallback := func(p *string, envKey string) {
		if strings.TrimSpace(*p) == "" {
			if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
				*p = v
			}
		}
	}
	envFallback(&zapURL, "ZAP_URL")
	envFallback(&apiKey, "ZAP_API_KEY")
	envFallback(&confUser, "CONFLUENCE_USER")
	envFallback(&confToken, "CONFLUENCE_TOKEN")
	envFallback(&jiraUser, "JIRA_USER")
	envFallback(&jiraToken, "JIRA_API_TOKEN")

	// Load operator-tunable triage policy once at startup. This drives the
	// auto-reopen gate, auto-suppression cadence, and rule-tune-scan tagging
	// inside entities.MergeWithPolicy. When no YAML is present the call
	// falls back to config.DefaultPolicy() — which matches pre-epic-#71 behavior
	// for the auto-reopen toggle. See docs/triage-policy.md.
	cwdForPolicy, _ := os.Getwd()
	triagePolicy, policySrc, perr := config.LoadPolicy(cwdForPolicy)
	if perr != nil {
		// Broken YAML should surface loudly; silently falling back to defaults
		// hides policy drift from operators who think their overrides are live.
		log.Fatalf("triage policy: %v", perr)
	}
	if policySrc != "" {
		fmt.Fprintf(os.Stderr, "[info] triage policy loaded from %s\n", policySrc)
	}

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
		if err := obsidian.WriteVault(vdir, ef, obsidian.Options{ScanLabel: "", SiteLabel: "", ZapBaseURL: strings.TrimSpace(zapBase), TriageGuidanceFn: zapmeta.TriageGuidance}); err != nil {
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
		client          *zapclient.Client
		alerts          []zapclient.Alert
		entIn           entities.EntitiesFile
		runInArtifact   runartifact.Artifact
		runInIsArtifact bool
		err             error
	)
	// If -run-in is provided, load entities and default labels/meta from it.
	if strings.TrimSpace(runIn) != "" {
		var a runartifact.Artifact
		if strict, serr := runartifact.Read(runIn); serr == nil && strings.TrimSpace(strict.Entities.SchemaVersion) != "" {
			a = strict
			runInArtifact = strict
			runInIsArtifact = true
		} else {
			var rerr error
			a, rerr = runartifact.ReadFlexible(runIn)
			if rerr != nil {
				log.Fatalf("read -run-in: %v", rerr)
			}
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
		raw, err := os.ReadFile(entitiesIn)
		if err != nil {
			log.Fatalf("open -entities-in file: %v", err)
		}
		raw, err = entities.NormalizeImportJSON(raw)
		if err != nil {
			log.Fatalf("normalize -entities-in file: %v", err)
		}
		if err := json.Unmarshal(raw, &entIn); err != nil {
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
		// #42: every scan must have a label so analysts can trace findings back to a
		// specific run (audit, re-scan, accept-with-expiry). When the user did not
		// pass -scan-label and we are about to ingest fresh alerts, retro-label the
		// run with a derived "<source>-<UTC-timestamp>" tag and warn loudly. This is
		// the "retro-label at import" path of the AC; reproducible runs should still
		// pass an explicit -scan-label.
		if strings.TrimSpace(scanLabel) == "" && len(alerts) > 0 {
			derived := fmt.Sprintf("%s-%s", strings.TrimSpace(strings.ToLower(source)), time.Now().UTC().Format("20060102-150405"))
			derived = strings.TrimPrefix(derived, "-")
			scanLabel = derived
			fmt.Fprintf(os.Stderr, "[warn] no -scan-label set; auto-derived %q for this run\n", derived)
			fmt.Fprintf(os.Stderr, "[warn] Tip: pass -scan-label=<env>-<YYYYMMDD> for reproducible runs (e.g. prod-%s)\n", time.Now().UTC().Format("20060102"))
		} else if strings.TrimSpace(scanLabel) == "" && (strings.TrimSpace(runIn) != "" || len(entIn.Occurrences) > 0) {
			// No fresh alerts to label, but we're operating on existing entities.
			// Emit the original advisory only — we cannot retro-label historical data.
			fmt.Fprintln(os.Stderr, "[warn] no -scan-label set; occurrences from previous runs may not have a scan label")
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
				ent = entities.MergeWithPolicy(ent, built, triagePolicy)
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

		// Enrich taxonomy (CWE→OWASP) from static map — always runs, best-effort
		entities.EnrichTaxonomy(ent.Definitions)

		// Optional redaction pass
		if strings.TrimSpace(redactOpts) != "" {
			ro := entities.ParseRedactOptionList(redactOpts)
			entities.RedactEntities(&ent, ro)
		}

		// Normalize tool/custom definition origin and analyst status once before
		// any output/render step so every surface uses the KB's canonical model.
		entities.NormalizeDefinitionOrigins(&ent)
		entities.NormalizeAnalystStatuses(&ent)

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
		if err := writeVaultSnapshot(vault, ent, scanLabel, siteLabel, zapBase, jiraURL, nil, nil, ""); err != nil {
			log.Fatalf("write obsidian: %v", err)
		}
	default:
		log.Fatalf("unknown -format %q (use entities|flat|both|obsidian)", format)
	}

	if err := validatePublishSource(ent, strings.TrimSpace(confURL) != "", strings.TrimSpace(jiraURL) != "", allowAgentPublish, allowCustomPublish); err != nil {
		log.Fatalf("publish source: %v", err)
	}

	// Optional Confluence export - when Jira is also enabled, publish after Jira
	// keys are merged so finding pages and evidence pages stay in sync.
	if strings.TrimSpace(confURL) != "" && strings.TrimSpace(jiraURL) == "" {
		if _, err := publishConfluenceVault(vault, format, ent, confluencePublishOptions{
			BaseURL:          confURL,
			Username:         confUser,
			APIToken:         confToken,
			SpaceKey:         confSpace,
			ParentPageID:     confParent,
			TitlePrefix:      confTitlePrefix,
			DryRun:           confDryRun,
			Full:             confFull,
			Concurrency:      confConcurrency,
			ScanLabel:        scanLabel,
			SiteLabel:        siteLabel,
			ZapBaseURL:       zapBase,
			JiraBaseURL:      jiraURL,
			JiraStatusByKey:  nil,
			JiraStatusSynced: "",
		}); err != nil {
			log.Fatalf("%v", err)
		}
	}

	// Optional Jira export (works with entities and obsidian formats)
	if strings.TrimSpace(jiraURL) != "" {
		var extraLabels []string
		if strings.TrimSpace(jiraLabels) != "" {
			for _, l := range strings.Split(jiraLabels, ",") {
				if l = strings.TrimSpace(l); l != "" {
					extraLabels = append(extraLabels, l)
				}
			}
		}
		jiraCtx, jiraCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer jiraCancel()
		sum, err := jira.Export(jiraCtx, ent, jira.Options{
			BaseURL:     jiraURL,
			Username:    jiraUser,
			APIToken:    jiraToken,
			ProjectKey:  jiraProject,
			IssueType:   jiraIssueType,
			Component:   jiraComponent,
			ExtraLabels: extraLabels,
			MinRisk:       jiraMinRisk,
			OptInTag:      jiraOptInTag,
			DryRun:        jiraDryRun,
			Concurrency:   jiraConcurrency,
			DetectionEpic: jiraDetectionEpic,
			EpicIssueType: jiraEpicIssueType,
			// Default Epics to the same component as findings unless an explicit
			// override is provided. One -jira-component flag handles both the
			// common case of "everything goes to one component."
			EpicComponent: func() string {
				if strings.TrimSpace(jiraEpicComponent) != "" {
					return jiraEpicComponent
				}
				return jiraComponent
			}(),
		})
		if err != nil {
			log.Fatalf("jira export: %v", err)
		}
		fmt.Printf("Jira: created=%d skipped=%d errors=%d relinked=%d\n", sum.Created, sum.Skipped, sum.Errors, sum.Relinked)

		addedTicketKeys := 0
		jiraStatusByKey := map[string]string(nil)
		jiraAssigneeByKey := map[string]string(nil)
		jiraStatusSynced := ""
		if !jiraDryRun && len(sum.TicketKeys) > 0 {
			addedTicketKeys = mergeFindingTicketKeys(&ent, sum.TicketKeys)
		}
		if !jiraDryRun && len(sum.EpicKeys) > 0 {
			if n := mergeDefinitionEpicRefs(&ent, sum.EpicKeys); n > 0 {
				fmt.Printf("Jira: recorded %d detection epic reference(s)\n", n)
			}
		}
		if !jiraDryRun && hasFindingTicketRefs(ent) {
			pullCtx, pullCancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer pullCancel()
			pullRes, pullErr := jira.PullStatus(pullCtx, ent, jira.PullOptions{
				BaseURL:  jiraURL,
				Username: jiraUser,
				Token:    jiraToken,
			})
			if pullErr != nil {
				log.Printf("warning: jira status pull failed: %v", pullErr)
			} else {
				ent = pullRes.Updated
				jiraStatusByKey = pullRes.RawStatuses
				jiraAssigneeByKey = pullRes.RawAssignees
				jiraStatusSynced = pullRes.SyncedAt
				fmt.Printf("Jira pull: updated=%d unchanged=%d notfound=%d errors=%d\n",
					pullRes.Result.Updated, pullRes.Result.Unchanged, pullRes.Result.NotFound, pullRes.Result.Errors)
			}
		}
		if !jiraDryRun && (addedTicketKeys > 0 || hasFindingTicketRefs(ent)) {
			var artPtr *runartifact.Artifact
			if runInIsArtifact {
				artPtr = &runInArtifact
			}
			savePath, werr := persistJiraEntities(jiraSyncContext{
				Format:           format,
				Out:              out,
				EntitiesIn:       entitiesIn,
				RunIn:            runIn,
				RunInputArtifact: artPtr,
			}, ent)
			if werr != nil {
				log.Printf("warning: could not save Jira state to entities file: %v", werr)
			} else if savePath != "" {
				fmt.Printf("Jira: wrote current ticket/state data to %s\n", savePath)
			}
		}
		if format == "obsidian" && !jiraDryRun && hasFindingTicketRefs(ent) {
			if err := writeVaultSnapshot(vault, ent, scanLabel, siteLabel, zapBase, jiraURL, jiraStatusByKey, jiraAssigneeByKey, jiraStatusSynced); err != nil {
				log.Fatalf("rewrite obsidian after jira: %v", err)
			}
		}

		if strings.TrimSpace(confURL) != "" {
			confSum, err := publishConfluenceVault(vault, format, ent, confluencePublishOptions{
				BaseURL:          confURL,
				Username:         confUser,
				APIToken:         confToken,
				SpaceKey:         confSpace,
				ParentPageID:     confParent,
				TitlePrefix:      confTitlePrefix,
				DryRun:           confDryRun,
				Full:             confFull,
				Concurrency:      confConcurrency,
				ScanLabel:        scanLabel,
				SiteLabel:        siteLabel,
				ZapBaseURL:       zapBase,
				JiraBaseURL:      jiraURL,
				JiraStatusByKey:   jiraStatusByKey,
				JiraAssigneeByKey: jiraAssigneeByKey,
				JiraStatusSynced:  jiraStatusSynced,
			})
			if err != nil {
				log.Fatalf("%v", err)
			}
			if !jiraDryRun && len(sum.TicketKeys) > 0 && len(confSum.FindingLinks) > 0 {
				linkCtx, linkCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer linkCancel()
				linkSum, lerr := jira.SyncFindingEvidenceLinks(linkCtx, sum.TicketKeys, confSum.FindingLinks, jira.Options{
					BaseURL:     jiraURL,
					Username:    jiraUser,
					APIToken:    jiraToken,
					Concurrency: jiraConcurrency,
				})
				if lerr != nil {
					log.Printf("warning: jira evidence link sync failed: %v", lerr)
				} else {
					fmt.Printf("Jira evidence links: added=%d skipped=%d errors=%d\n", linkSum.Added, linkSum.Skipped, linkSum.Errors)
				}
			}
		}
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
	const maxLookbackDays = 3650 // 10 years — beyond this a fat-finger is likely
	if n > maxLookbackDays {
		return 0, fmt.Errorf("lookback %q exceeds maximum of %d days", raw, maxLookbackDays)
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

// runMergeCommand implements the "merge" sub-command.
// Usage: zap-kb merge -inputs a.json,b.json[,c.json] [-out merged.json]
//
// Reads each input with runartifact.ReadFlexible (handles both run artifacts and
// bare entities JSON). Merges pairwise left-to-right using entities.Merge.
// Writes the merged EntitiesFile as JSON to -out (stdout when "-" or omitted).
func runMergeCommand(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	var inputsFlag string
	var outFlag string
	fs.StringVar(&inputsFlag, "inputs", "", "Comma-separated list of entity JSON file paths (required)")
	fs.StringVar(&outFlag, "out", "-", "Output file path; use \"-\" or omit for stdout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "merge: %v\n", err)
		os.Exit(1)
	}

	// Collect input paths: -inputs flag (comma-separated) plus any remaining positional args.
	var paths []string
	for _, raw := range strings.Split(inputsFlag, ",") {
		p := strings.TrimSpace(raw)
		if p != "" {
			paths = append(paths, p)
		}
	}
	for _, p := range fs.Args() {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "merge: -inputs is required (provide at least one file path)")
		fs.Usage()
		os.Exit(1)
	}

	// Read and merge files left-to-right.
	artifacts := make([]entities.EntitiesFile, 0, len(paths))
	for _, p := range paths {
		art, err := runartifact.ReadFlexible(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "merge: cannot read %q: %v\n", p, err)
			os.Exit(1)
		}
		artifacts = append(artifacts, art.Entities)
	}

	// Load triage policy so post-merge passes (auto-suppression, tune-scan
	// tagging) run the same way as the main pipeline. A broken YAML fails the
	// sub-command rather than silently falling back to defaults.
	cwd, _ := os.Getwd()
	policy, policySrc, perr := config.LoadPolicy(cwd)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "merge: triage policy: %v\n", perr)
		os.Exit(1)
	}
	if policySrc != "" {
		fmt.Fprintf(os.Stderr, "merge: triage policy loaded from %s\n", policySrc)
	}
	merged := artifacts[0]
	for _, ef := range artifacts[1:] {
		merged = entities.MergeWithPolicy(merged, ef, policy)
	}

	// Encode output.
	enc, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "merge: encode: %v\n", err)
		os.Exit(1)
	}

	outPath := strings.TrimSpace(outFlag)
	if outPath == "" || outPath == "-" {
		os.Stdout.Write(enc)
		os.Stdout.WriteString("\n")
	} else {
		if werr := os.WriteFile(outPath, append(enc, '\n'), 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "merge: write %q: %v\n", outPath, werr)
			os.Exit(1)
		}
	}

	// Summary to stderr.
	fmt.Fprintf(os.Stderr, "Merged %d files: %d definitions, %d findings, %d occurrences\n",
		len(paths), len(merged.Definitions), len(merged.Findings), len(merged.Occurrences))
}

// runPullCommand implements the "pull" sub-command: reads analyst triage fields
// FROM existing Confluence occurrence pages INTO entities.json.
//
// Usage:
//
//	zap-kb pull -entities-in <path> -out <path> \
//	    -confluence-url <url> -confluence-space <key> \
//	    [-confluence-user <user>] [-confluence-token <token>] \
//	    [-confluence-pull-workflow]
func runPullCommand(args []string) {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	var (
		entitiesIn       string
		outPath          string
		confURL          string
		confSpace        string
		confUser         string
		confToken        string
		confPullWorkflow bool
		jiraURL          string
		jiraUser         string
		jiraToken        string
		jiraPullStatus   bool
	)
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON file to read and update (required)")
	fs.StringVar(&outPath, "out", "", "Output path for updated entities JSON (required)")
	fs.StringVar(&confURL, "confluence-url", "", "Confluence base URL")
	fs.StringVar(&confSpace, "confluence-space", "", "Confluence space key")
	fs.StringVar(&confUser, "confluence-user", "", "Confluence username (env: CONFLUENCE_USER)")
	fs.StringVar(&confToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN)")
	fs.BoolVar(&confPullWorkflow, "confluence-pull-workflow", false, "Allow Confluence workflow fields to overwrite local analyst data during pull")
	fs.StringVar(&jiraURL, "jira-url", "", "Jira base URL (enables Jira status pull)")
	fs.StringVar(&jiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER)")
	fs.StringVar(&jiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN)")
	fs.BoolVar(&jiraPullStatus, "jira-pull-status", false, "Pull Jira ticket status into analyst.Status (Jira wins)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "pull: %v\n", err)
		os.Exit(1)
	}

	// Environment variable fallbacks for credentials.
	envFallback := func(p *string, envKey string) {
		if strings.TrimSpace(*p) == "" {
			if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
				*p = v
			}
		}
	}
	envFallback(&confUser, "CONFLUENCE_USER")
	envFallback(&confToken, "CONFLUENCE_TOKEN")
	envFallback(&jiraUser, "JIRA_USER")
	envFallback(&jiraToken, "JIRA_API_TOKEN")

	if strings.TrimSpace(entitiesIn) == "" {
		fmt.Fprintln(os.Stderr, "pull: -entities-in is required")
		fs.Usage()
		os.Exit(1)
	}
	if strings.TrimSpace(outPath) == "" {
		fmt.Fprintln(os.Stderr, "pull: -out is required")
		fs.Usage()
		os.Exit(1)
	}

	// Require at least one pull source.
	wantConf := strings.TrimSpace(confURL) != ""
	wantJira := strings.TrimSpace(jiraURL) != "" && jiraPullStatus
	if !wantConf && !wantJira {
		fmt.Fprintln(os.Stderr, "pull: specify -confluence-url/-confluence-space or -jira-url -jira-pull-status")
		fs.Usage()
		os.Exit(1)
	}
	if wantConf && strings.TrimSpace(confSpace) == "" {
		fmt.Fprintln(os.Stderr, "pull: -confluence-space is required when -confluence-url is set")
		fs.Usage()
		os.Exit(1)
	}

	// Read existing entities file.
	art, err := runartifact.ReadFlexible(strings.TrimSpace(entitiesIn))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pull: cannot read %q: %v\n", entitiesIn, err)
		os.Exit(1)
	}
	ef := art.Entities
	ctx := context.Background()

	// Jira status pull (runs first so Confluence pull can layer on top).
	if wantJira {
		jRes, jErr := jira.PullStatus(ctx, ef, jira.PullOptions{
			BaseURL:  strings.TrimSpace(jiraURL),
			Username: strings.TrimSpace(jiraUser),
			Token:    strings.TrimSpace(jiraToken),
		})
		if jErr != nil {
			fmt.Fprintf(os.Stderr, "pull: jira: %v\n", jErr)
			os.Exit(1)
		}
		ef = jRes.Updated
		fmt.Printf("Jira pull: %d updated, %d unchanged, %d not found, %d errors\n",
			jRes.Result.Updated, jRes.Result.Unchanged, jRes.Result.NotFound, jRes.Result.Errors)
	}

	// Confluence workflow pull (optional).
	if wantConf {
		updated, res, cErr := confluence.PullAnalystData(ctx, ef, confluence.PullOptions{
			BaseURL:      strings.TrimSpace(confURL),
			SpaceKey:     strings.TrimSpace(confSpace),
			Username:     strings.TrimSpace(confUser),
			Token:        strings.TrimSpace(confToken),
			PullWorkflow: confPullWorkflow,
		})
		if cErr != nil {
			fmt.Fprintf(os.Stderr, "pull: confluence: %v\n", cErr)
			os.Exit(1)
		}
		ef = updated
		fmt.Printf("Confluence pull: %d updated, %d unchanged, %d not found, %d errors\n",
			res.Updated, res.Unchanged, res.NotFound, res.Errors)
	}

	// Write the updated entities file.
	enc, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pull: encode: %v\n", err)
		os.Exit(1)
	}
	if werr := os.WriteFile(strings.TrimSpace(outPath), append(enc, '\n'), 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "pull: write %q: %v\n", outPath, werr)
		os.Exit(1)
	}
	fmt.Printf("Written: %s\n", outPath)
}
