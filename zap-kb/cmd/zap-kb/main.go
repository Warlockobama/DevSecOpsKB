package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/confluence"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jira"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publicationstate"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/ziputil"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

func main() { os.Exit(executeCLI(runMain)) }

func runMain() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	runCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	var (
		zapURL               string
		apiKey               string
		baseURL              string
		count                int
		out                  string
		merge                bool
		format               string
		source               string
		vault                string
		infile               string
		entitiesIn           string
		plugins              string
		allPlugins           bool
		genAt                string
		includeTraffic       bool
		trafficMax           int
		trafficMaxPerIssue   int
		trafficTotalMax      int
		scanLabel            string
		siteLabel            string
		trafficScope         string
		zapBase              string
		trafficMinRisk       string
		includeDetect        bool
		includeMITRE         bool
		mitreCWECache        string
		mitreCAPECCache      string
		mitreATTACKCache     string
		includeCVSS          bool
		detectDetails        string
		initMode             bool
		runOut               string
		runIn                string
		zipOut               string
		redactOpts           string
		runAlerts            string
		wizard               bool
		pruneScanLabel       string
		pruneSiteLabel       string
		pruneVault           string
		pruneDryRun          bool
		reportOut            string
		reportSince          string
		reportUntil          string
		reportLookback       string
		reportTitle          string
		reportScanLabel      string
		confURL              string
		confUser             string
		confToken            string
		confSpace            string
		confDeployment       string
		confParent           string
		confTitlePrefix      string
		confDryRun           bool
		confFull             bool
		confConcurrency      int
		jiraURL              string
		jiraUser             string
		jiraToken            string
		jiraProject          string
		jiraDeployment       string
		jiraServerID         string
		jiraServerName       string
		jiraUserMap          string
		jiraIssueType        string
		jiraComponent        string
		jiraLabels           string
		jiraMinRisk          string
		jiraOptInTag         string
		jiraDryRun           bool
		jiraConcurrency      int
		jiraDetectionEpic    bool
		jiraEpicIssueType    string
		jiraEpicComponent    string
		jiraSyncKBStatus     bool
		forgejoURL           string
		forgejoToken         string
		forgejoOwner         string
		forgejoRepo          string
		forgejoMinRisk       string
		forgejoGroupByDef    bool
		forgejoOptInTag      string
		forgejoLabels        string
		forgejoConcurrency   int
		forgejoDryRun        bool
		forgejoSyncKBStatus  bool
		forgejoIssues        bool
		forgejoWiki          bool
		forgejoWikiPrune     bool
		forgejoWikiTimeout   time.Duration
		forgejoWikiHTTPTO    time.Duration
		forgejoRedact        string
		allowAgentPublish    bool
		allowCustomPublish   bool
		zapAlertsOnly        bool
		publishSummaryOut    string
		publicationStateDir  string
		jiraSiteURL          string
		jiraCreateFieldsFile string
		jiraTimeout          time.Duration
		showVersion          bool
	)
	flag.StringVar(&zapURL, "zap-url", "http://127.0.0.1:8090", "ZAP API base URL (env: ZAP_URL)")
	flag.BoolVar(&showVersion, "version", false, "Print build version, source revision, and build time, then exit")
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
	flag.IntVar(&trafficMax, "traffic-max-bytes", 2048, "Max bytes to capture for request/response snippets (0 = unlimited; values 1-1023 use minimum 1024; high/critical responses kept in full)")
	flag.StringVar(&trafficScope, "traffic-scope", "first", "Traffic enrichment scope: first|all")
	flag.IntVar(&trafficMaxPerIssue, "traffic-max-per-issue", 1, "Max occurrences per issue to enrich with traffic (applies to first scope)")
	flag.IntVar(&trafficTotalMax, "traffic-total-max", 0, "Global cap on number of occurrences to enrich with traffic (0 = unlimited)")
	flag.StringVar(&trafficMinRisk, "traffic-min-risk", "info", "Minimum risk to enrich traffic: info|low|medium|high|critical")
	flag.StringVar(&scanLabel, "scan-label", "", "Optional label for this scan/session (appears in INDEX and frontmatter)")
	flag.StringVar(&siteLabel, "site-label", "", "Optional site/domain label override when domains are redacted")
	flag.StringVar(&zapBase, "zap-base-url", "", "Optional ZAP base URL to link back to messages in Obsidian")
	flag.BoolVar(&includeDetect, "include-detection", false, "Enrich with detection logic links from ZAP docs/GitHub")
	flag.BoolVar(&includeMITRE, "include-mitre", true, "Enrich taxonomy with curated MITRE CWE/CAPEC/ATT&CK metadata")
	flag.StringVar(&mitreCWECache, "mitre-cwe-cache", "", "Optional local CWE cache JSON from `zap-kb taxonomy update -source cwe`")
	flag.StringVar(&mitreCAPECCache, "mitre-capec-cache", "", "Optional local CAPEC cache JSON from `zap-kb taxonomy update -source capec`")
	flag.StringVar(&mitreATTACKCache, "mitre-attack-cache", "", "Optional local ATT&CK cache JSON from `zap-kb taxonomy update -source attack`")
	flag.BoolVar(&includeCVSS, "include-cvss", true, "Estimate definition CVSS from scanner risk when official CVSS is unavailable")
	flag.StringVar(&detectDetails, "detection-details", "links", "Detection enrichment detail: links|summary")
	flag.BoolVar(&initMode, "init", false, "Init KB without run data: seed/update definitions only (no alert fetch)")
	flag.StringVar(&runOut, "run-out", "", "Write a pipeline-friendly run artifact JSON (entities+meta[+alerts])")
	flag.StringVar(&runIn, "run-in", "", "Read a run artifact JSON (or bare entities JSON) and use it as -entities-in; also picks up scan/site labels if present")
	flag.StringVar(&zipOut, "zip-out", "", "Zip outputs to this path (includes run-out, entities out, and obsidian dir if generated)")
	flag.StringVar(&runAlerts, "run-alerts", "keep", "Run artifact alert retention: keep (sanitized by -redact) or omit")
	flag.StringVar(&redactOpts, "redact", "", "Comma/space list of redactions: domain,query,cookies,auth,headers,body,notes,secrets")
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
	flag.StringVar(&confURL, "confluence-url", "", "Confluence base URL (env: CONFLUENCE_URL; enables export of INDEX.md to Confluence).")
	flag.StringVar(&confUser, "confluence-user", "", "Confluence username (env: CONFLUENCE_USER).")
	flag.StringVar(&confToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN).")
	flag.StringVar(&confSpace, "confluence-space", "", "Confluence space key (env: CONFLUENCE_SPACE).")
	flag.StringVar(&confDeployment, "confluence-deployment", "", "Confluence deployment: auto|cloud|datacenter (env: CONFLUENCE_DEPLOYMENT; default auto-detects *.atlassian.net as cloud). On datacenter, leave -confluence-user empty to send the token as a Bearer personal access token.")
	flag.StringVar(&confParent, "confluence-parent", "", "Optional Confluence parent page ID.")
	flag.StringVar(&confTitlePrefix, "confluence-title-prefix", "", "Optional title prefix for exported page (default: KB Index).")
	flag.BoolVar(&confDryRun, "confluence-dry-run", false, "Dry-run Confluence export (log instead of POST).")
	flag.BoolVar(&confFull, "confluence-full", false, "Export full vault to Confluence (INDEX, Dashboard, Triage Board, all definitions).")
	flag.IntVar(&confConcurrency, "confluence-concurrency", 3, "Max parallel Confluence API requests for full export (default: 3, max: 5).")
	flag.StringVar(&jiraURL, "jira-url", "", "Jira base URL (env: JIRA_URL; enables export of findings as Jira issues).")
	flag.StringVar(&jiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER, fallback: CONFLUENCE_USER).")
	flag.StringVar(&jiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN, fallback: CONFLUENCE_TOKEN).")
	flag.StringVar(&jiraProject, "jira-project", "", "Jira project key (env: JIRA_PROJECT; e.g. SEC).")
	flag.StringVar(&jiraDeployment, "jira-deployment", "", "Jira deployment: auto|cloud|datacenter (env: JIRA_DEPLOYMENT; default auto-detects *.atlassian.net as cloud). Datacenter uses REST v2 with wiki-markup descriptions; leave -jira-user empty to send the token as a Bearer personal access token.")
	flag.StringVar(&jiraServerID, "jira-server-id", "", "Confluence application-link UUID for the Jira instance (e.g. 6ee9717b-54c7-35fc-8b8c-517e863e5ce4). Enables a live Jira Issues macro on the Triage Board page when combined with -jira-server-name and -jira-project.")
	flag.StringVar(&jiraServerName, "jira-server-name", "", "Display name of the linked Jira application (as configured on the Confluence side). Required alongside -jira-server-id and -jira-project to render the Triage Board live macro.")
	flag.StringVar(&jiraUserMap, "jira-user-map", "", "Comma-separated KB-owner→Jira-accountId map for setting Jira assignee from analyst.owner on issue create (e.g. \"alice=5e3f...,bob=602a...\"). Owners with no mapping are logged and the issue is created unassigned.")
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
	flag.BoolVar(&jiraSyncKBStatus, "jira-sync-kb-status", false, "Legacy mode: write mapped Jira workflow status and assignee back into KB analyst fields. By default Jira remains the workflow source of truth and KB state is not mutated.")
	flag.StringVar(&forgejoURL, "forgejo-url", "", "Forgejo/Gitea base URL (enables open-source issue + wiki publishing; e.g. https://forge.example.com).")
	flag.StringVar(&forgejoToken, "forgejo-token", "", "Forgejo/Gitea API token (env: FORGEJO_TOKEN).")
	flag.StringVar(&forgejoOwner, "forgejo-owner", "", "Forgejo/Gitea repository owner (user or org).")
	flag.StringVar(&forgejoRepo, "forgejo-repo", "", "Forgejo/Gitea repository name.")
	flag.StringVar(&forgejoMinRisk, "forgejo-min-risk", "medium", "Minimum risk level to export as Forgejo issues: info|low|medium|high (default: medium).")
	flag.BoolVar(&forgejoGroupByDef, "forgejo-group-by-definition", true, "Publish one Forgejo issue per rule/definition (titled by the rule, listing every affected endpoint) instead of one issue per finding. Tames noisy scan types; set false for per-URL granularity.")
	flag.StringVar(&forgejoOptInTag, "forgejo-opt-in-tag", "case-ticket", "Analyst tag that forces Forgejo export for lower-severity findings.")
	flag.StringVar(&forgejoLabels, "forgejo-labels", "", "Comma-separated extra labels to add to each Forgejo issue.")
	flag.IntVar(&forgejoConcurrency, "forgejo-concurrency", 3, "Max parallel Forgejo API requests (default: 3, max: 5).")
	flag.BoolVar(&forgejoDryRun, "forgejo-dry-run", false, "Dry-run Forgejo export (log instead of POST).")
	flag.BoolVar(&forgejoSyncKBStatus, "forgejo-sync-kb-status", false, "Write mapped Forgejo issue state/labels back into KB analyst status. By default Forgejo is the workflow source of truth and KB state is not mutated.")
	flag.BoolVar(&forgejoIssues, "forgejo-issues", true, "Create/track one Forgejo issue per finding. Set false for wiki-only publishing, leaving the Issues tab free for other use (e.g. analyst-filed tuning requests).")
	flag.BoolVar(&forgejoWiki, "forgejo-wiki", false, "Also publish the generated Obsidian vault to the Forgejo repo wiki (Confluence analog).")
	flag.BoolVar(&forgejoWikiPrune, "forgejo-wiki-prune", false, "Delete KB-owned Forgejo wiki pages (Definitions/Findings/Occurrences) that are absent from the current publish.")
	flag.DurationVar(&forgejoWikiTimeout, "forgejo-wiki-timeout", 30*time.Minute, "Deadline for the whole wiki publish: page upserts, link repair and prune share it. The API client is throttled to one request per 250ms and an unchanged page still costs a read, so budget from the page count rather than from the number of changes. 0 disables the deadline.")
	flag.DurationVar(&forgejoWikiHTTPTO, "forgejo-wiki-request-timeout", 30*time.Second, "Timeout for a SINGLE wiki API request, as distinct from -forgejo-wiki-timeout, which budgets the whole pass. The binding call is the paged page listing link repair does before it can rewrite anything: its cost grows with the wiki, not with the publish, so on a large vault the first listing can exceed the 30s default while the pass deadline is barely touched. 0 keeps the default.")
	flag.StringVar(&forgejoRedact, "forgejo-redact", defaultForgejoRedact, "Redactions applied to content published to Forgejo (issues + wiki): comma list of domain,query,cookies,auth,headers,body,notes,secrets; additional modes preserve auth,cookies,headers,secrets defaults; 'off' disables sink defaults only. 'secrets' scrubs credential/PII patterns (hashes, emails, JWTs) from evidence. Local outputs follow -redact.")
	flag.BoolVar(&allowAgentPublish, "allow-agent-publish", false, "Allow Confluence/Jira publish from sourceTool values like zap-agent (disabled by default)")
	flag.BoolVar(&allowCustomPublish, "allow-custom-publish", false, "Allow Confluence/Jira publish when the input contains custom definitions (disabled by default)")
	flag.BoolVar(&zapAlertsOnly, "zap-alerts-only", false, "Keep only scanner-native ZAP alerts with numeric plugin IDs; excludes custom/project detections and other scanner sources.")
	flag.DurationVar(&jiraTimeout, "jira-timeout", 5*time.Minute, "Deadline for each Jira publish, readback or evidence-link stage")
	flag.StringVar(&jiraSiteURL, "jira-site-url", "", "Human-facing Jira site URL (env: JIRA_SITE_URL); required for browser links when Jira API uses the scoped-token gateway")
	flag.StringVar(&jiraCreateFieldsFile, "jira-create-fields-file", "", "JSON file containing optional/custom Jira create fields (env: JIRA_CREATE_FIELDS_FILE)")
	flag.StringVar(&publishSummaryOut, "publish-summary-out", "", "Write a redacted Atlassian publish summary JSON to this path.")
	flag.StringVar(&publicationStateDir, "publication-state-dir", "", "Directory for durable issue/epic references, separate from immutable scanner input (env: PUBLICATION_STATE_DIR).")
	// Subcommands own their flag sets, so dispatch before parsing global flags.
	if handler, args, ok := lookupSubcommand(os.Args[1:]); ok {
		handler(args)
		return
	}

	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			exitCLI(0)
		}
		exitCLI(2)
	}
	if showVersion {
		fmt.Println(buildinfo.String())
		return
	}
	outputPolicy, policyErr := entities.ParseRedactOptions(redactOpts)
	if policyErr != nil {
		fatal(policyErr)
	}
	if err := validateForgejoRedact(forgejoRedact); err != nil {
		fatal(err)
	}
	if runAlerts != "keep" && runAlerts != "omit" {
		fatal("invalid -run-alerts; use keep or omit")
	}
	supplied := suppliedFlags(flag.CommandLine)

	// Explicit flags win even when they deliberately set false, zero, or an
	// empty string. Otherwise use a non-blank environment value, then the flag
	// default. Keep sources separate from values so credentials never appear in
	// diagnostics.
	zapURL, _ = resolveStringFlagEnvDefault(zapURL, supplied["zap-url"], "ZAP_URL", "http://127.0.0.1:8090", os.Getenv)
	apiKey, _ = resolveStringFlagEnvDefault(apiKey, supplied["api-key"], "ZAP_API_KEY", "", os.Getenv)
	jiraServerID, _ = resolveStringFlagEnvDefault(jiraServerID, supplied["jira-server-id"], "JIRA_SERVER_ID", "", os.Getenv)
	jiraServerName, _ = resolveStringFlagEnvDefault(jiraServerName, supplied["jira-server-name"], "JIRA_SERVER_NAME", "", os.Getenv)
	forgejoToken, _ = resolveStringFlagEnvDefault(forgejoToken, supplied["forgejo-token"], "FORGEJO_TOKEN", "", os.Getenv)
	publicationStateDir, _ = resolveStringFlagEnvDefault(publicationStateDir, supplied["publication-state-dir"], "PUBLICATION_STATE_DIR", "", os.Getenv)

	atlassianCfg, cfgErr := resolveAtlassianConfigStrict(atlassianConfigInput{
		ConfluenceURL:        confURL,
		ConfluenceSpace:      confSpace,
		ConfluenceUser:       confUser,
		ConfluenceToken:      confToken,
		ConfluenceDeployment: confDeployment,
		JiraURL:              jiraURL,
		JiraProject:          jiraProject,
		JiraUser:             jiraUser,
		JiraToken:            jiraToken,
		JiraDeployment:       jiraDeployment,
		FlagSet:              supplied,
	}, os.Getenv)
	if cfgErr != nil {
		fatalf("configuration: %v", cfgErr)
	}
	confURL = atlassianCfg.ConfluenceURL
	confSpace = atlassianCfg.ConfluenceSpace
	confUser = atlassianCfg.ConfluenceUser
	confToken = atlassianCfg.ConfluenceToken
	confDeployment = atlassianCfg.ConfluenceDeployment
	jiraURL = atlassianCfg.JiraURL
	jiraProject = atlassianCfg.JiraProject
	jiraUser = atlassianCfg.JiraUser
	jiraToken = atlassianCfg.JiraToken
	jiraDeployment = atlassianCfg.JiraDeployment
	publishSummary := newAtlassianPublishSummary(atlassianCfg)
	jiraSiteURL, _ = resolveStringFlagEnvDefault(jiraSiteURL, supplied["jira-site-url"], "JIRA_SITE_URL", "", os.Getenv)
	if err := validateOptionalHTTPURL("Jira site URL", jiraSiteURL); err != nil {
		fatalf("configuration: %v", err)
	}
	jiraBrowserURL := jira.BrowserBase(jiraURL, jiraSiteURL)
	jiraCreateFieldsFile, _ = resolveStringFlagEnvDefault(jiraCreateFieldsFile, supplied["jira-create-fields-file"], "JIRA_CREATE_FIELDS_FILE", "", os.Getenv)
	jiraCreateFields, jiraFieldsErr := loadJiraCreateFields(jiraCreateFieldsFile)

	// Load operator-tunable triage policy once at startup. This drives the
	// auto-reopen gate, auto-suppression cadence, and rule-tune-scan tagging
	// inside entities.MergeWithPolicy. When no YAML is present the call
	// falls back to config.DefaultPolicy() — which matches pre-epic-#71 behavior
	// for the auto-reopen toggle. See docs/triage-policy.md.
	cwdForPolicy, cwdErr := os.Getwd()
	if cwdErr != nil {
		// Surface the failure: policy still loads from user-config/defaults,
		// but operators deserve a warning when project-local lookup is skipped.
		log.Printf("[warn] cannot determine working directory for triage policy lookup: %v", synccore.SafeError(cwdErr))
		cwdForPolicy = ""
	}
	triagePolicy, policySrc, perr := config.LoadPolicy(cwdForPolicy)
	if perr != nil {
		// Broken YAML should surface loudly; silently falling back to defaults
		// hides policy drift from operators who think their overrides are live.
		fatalf("triage policy: %v", synccore.SafeError(perr))
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
			fatalf("prune: %v", synccore.SafeError(perr))
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
			fatalf("refresh index: %v", synccore.SafeError(err))
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
			fatalf("wizard: %v", synccore.SafeError(err))
		}
	}

	if includeTraffic {
		if strings.TrimSpace(trafficMinRisk) == "" {
			trafficMinRisk = "info"
		}
	}

	loaded, err := loadPipelineInput(runCtx, pipelineInputOptions{
		RunIn: runIn, EntitiesIn: entitiesIn, AlertsIn: infile,
		ZapURL: zapURL, APIKey: apiKey, BaseURL: baseURL, Count: count,
		InitMode: initMode, AllPlugins: allPlugins, Plugins: plugins,
		ScanLabel: scanLabel, SiteLabel: siteLabel, ZapBaseURL: zapBase,
	})
	if err != nil {
		fatal(err)
	}
	defer loaded.Cancel()
	fetchCtx := loaded.DiscoveryCtx
	client, alerts, entIn := loaded.Client, loaded.Alerts, loaded.Entities
	fetchAllowed := loaded.FetchAllowed
	scanLabel, siteLabel, zapBase = loaded.ScanLabel, loaded.SiteLabel, loaded.ZapBaseURL
	if !fetchAllowed && (initMode || allPlugins || strings.TrimSpace(plugins) != "" || strings.TrimSpace(entitiesIn) != "") {
		fmt.Println("Init/enrich-only mode: skipping ZAP API fetch")
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

	// Preview uses a separate view; raw evidence still builds stable identities.
	previewAlerts := append([]zapclient.Alert(nil), alerts...)
	entities.RedactOutput(&previewAlerts, outputPolicy)
	// preview
	fmt.Printf("Fetched %d alerts (after dedup)\n", len(alerts))
	for i, a := range previewAlerts {
		if i >= 5 {
			break
		}
		fmt.Printf("[%d] %s | risk=%s url=%s param=%s plugin=%s cwe=%d\n",
			i, a.Alert, a.Risk, a.URL, a.Param, a.PluginID, a.CWEID.Int())
	}

	ent, nextScanLabel, err := buildPipelineEntities(runCtx, fetchCtx, client, alerts, entIn, entityPipelineOptions{
		Format: format, RunOut: runOut, RunIn: runIn, EntitiesIn: entitiesIn,
		GeneratedAt: genAt, Source: source, ScanLabel: scanLabel,
		Plugins: plugins, AllPlugins: allPlugins, InitMode: initMode,
		IncludeTraffic: includeTraffic, TrafficScope: trafficScope, TrafficMaxBytes: trafficMax,
		TrafficMaxPerIssue: trafficMaxPerIssue, TrafficMinRisk: trafficMinRisk, TrafficTotalMax: trafficTotalMax,
		IncludeDetection: includeDetect, DetectionDetails: detectDetails,
		IncludeMITRE: includeMITRE, MITRECWECache: mitreCWECache, MITRECAPECCache: mitreCAPECCache, MITREATTACKCache: mitreATTACKCache,
		IncludeCVSS: includeCVSS, ZAPAlertsOnly: zapAlertsOnly, FetchAllowed: fetchAllowed, TriagePolicy: triagePolicy,
	})
	if err != nil {
		fatal(err)
	}
	scanLabel = nextScanLabel

	// All emitted views derive from validated evidence, after identity creation.
	if outputPolicy.Enabled() {
		var copyErr error
		ent, copyErr = redactedCopy(ent, outputPolicy)
		if copyErr != nil {
			fatal("cannot create sanitized output view")
		}
	}
	alerts = append([]zapclient.Alert(nil), alerts...)
	entities.RedactOutput(&alerts, outputPolicy)
	siteLabel = entities.RedactText(siteLabel, outputPolicy)
	zapBase = entities.RedactText(zapBase, outputPolicy)
	baseURL = entities.RedactText(baseURL, outputPolicy)
	detectDetails = entities.RedactText(detectDetails, outputPolicy)
	if strings.TrimSpace(jiraURL) != "" || strings.TrimSpace(confURL) != "" || strings.TrimSpace(forgejoURL) != "" || strings.TrimSpace(publishSummaryOut) != "" {
		publishSummaryOut = publicationSummaryPath(publishSummaryOut, runOut, out, format, vault)
	}
	stateEnabled := strings.TrimSpace(jiraURL) != "" || (strings.TrimSpace(forgejoURL) != "" && forgejoIssues)
	if stateEnabled {
		stateCandidates := []string{runOut}
		switch format {
		case "entities", "flat", "both":
			stateCandidates = append(stateCandidates, out)
		case "obsidian":
			stateCandidates = append(stateCandidates, vault)
		}
		stateCandidates = append(stateCandidates, runIn, entitiesIn, infile)
		publicationStateDir = defaultPublicationStateDir(publicationStateDir, stateCandidates...)
	}
	immutableInputs := map[string]string{"-in": infile, "-entities-in": entitiesIn, "-run-in": runIn}
	derivedOutputs := map[string]string{
		"-run-out":               runOut,
		"-zip-out":               zipOut,
		"-publish-summary-out":   publishSummaryOut,
		"-report-out":            reportOut,
		"-publication-state-dir": publicationStateDir,
	}
	switch format {
	case "entities", "flat":
		derivedOutputs["-out"] = out
	case "both":
		derivedOutputs["-out"] = out
		derivedOutputs["-out entities derivative"] = out + ".entities.json"
	case "obsidian":
		derivedOutputs["-obsidian-dir"] = vault
	}
	if err := validateImmutableInputPaths(immutableInputs, derivedOutputs); err != nil {
		fatalf("path ownership: %v", err)
	}
	stateStore := publicationstate.Store{Dir: publicationStateDir}
	jiraStateDestination := ""
	forgejoStateDestination := ""
	if strings.TrimSpace(jiraURL) != "" {
		jiraStateDestination = publicationstate.Destination("jira", jiraURL, jiraProject)
		if err := stateStore.Apply(jiraStateDestination, &ent); err != nil {
			fatalf("apply Jira publication state: %v", synccore.SafeError(err))
		}
	}
	if strings.TrimSpace(forgejoURL) != "" && forgejoIssues {
		forgejoStateDestination = publicationstate.Destination("forgejo", forgejoURL, forgejoOwner+"/"+forgejoRepo)
		if err := stateStore.Apply(forgejoStateDestination, &ent); err != nil {
			fatalf("apply Forgejo publication state: %v", synccore.SafeError(err))
		}
	}
	results := &publishSummary.Publication
	summarySaved, runSaved := false, false
	var savedRunArtifact *runartifact.Artifact
	outputErr := writePrimaryOutput(ent, alerts, primaryOutputOptions{
		Format: format, Out: out, Vault: vault,
		ScanLabel: scanLabel, SiteLabel: siteLabel, ZapBaseURL: zapBase,
		JiraBaseURL: jiraBrowserURL, Redact: outputPolicy,
	})
	if outputErr != nil {
		recordPublication(results, "local", "output", 0, 0, 0, outputErr, false)
	}

	if err := validatePublishSource(ent, strings.TrimSpace(confURL) != "", strings.TrimSpace(jiraURL) != "", allowAgentPublish, allowCustomPublish); err != nil {
		fatalf("publish source: %v", synccore.SafeError(err))
	}

	// Optional Confluence export - when Jira is also enabled, publish after Jira
	// keys are merged so finding pages and evidence pages stay in sync.
	if strings.TrimSpace(confURL) != "" && strings.TrimSpace(jiraURL) == "" {
		confSum, err := publishConfluenceVault(vault, format, ent, confluencePublishOptions{
			Context:          runCtx,
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
			Redact:           outputPolicy,
			SiteLabel:        siteLabel,
			ZapBaseURL:       zapBase,
			JiraBaseURL:      jiraBrowserURL,
			JiraStatusByKey:  nil,
			JiraStatusSynced: "",
			JiraServerID:     jiraServerID,
			JiraServerName:   jiraServerName,
			JiraProjectKey:   jiraProject,
		})
		recordPublication(results, "confluence", "publish", confSum.Created+confSum.Updated, confSum.Skipped, confSum.Errors, err, confDryRun)
		publishSummary.Confluence = &publishConfluenceSummary{
			Created: confSum.Created,
			Updated: confSum.Updated,
			Skipped: confSum.Skipped,
			Errors:  confSum.Errors,
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
		jiraCtx, jiraCancel := context.WithTimeout(runCtx, jiraTimeout)
		defer jiraCancel()
		sum, err := func() (jira.Summary, error) {
			if jiraFieldsErr != nil {
				return jira.Summary{}, jiraFieldsErr
			}
			return jira.Export(jiraCtx, ent, jira.Options{
				CreateFields:  jiraCreateFields,
				BaseURL:       jiraURL,
				Username:      jiraUser,
				APIToken:      jiraToken,
				Deployment:    jiraDeployment,
				ProjectKey:    jiraProject,
				IssueType:     jiraIssueType,
				Component:     jiraComponent,
				ExtraLabels:   extraLabels,
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
				UsernameMap: parseJiraUserMap(jiraUserMap),
			})
		}()
		recordPublication(results, "jira", "publish", sum.Created+sum.Relinked, sum.Skipped, sum.Errors, err, jiraDryRun, sum.Diagnostics...)
		if !jiraDryRun && (len(sum.TicketKeys) > 0 || len(sum.EpicKeys) > 0) {
			stateErr := stateStore.Record(jiraStateDestination, ent, sum.TicketKeys, sum.EpicKeys, publicationResultFor(results, "jira"))
			recordPublication(results, "jira", "state", len(sum.TicketKeys)+len(sum.EpicKeys), 0, 0, stateErr, false)
			if stateErr != nil {
				log.Printf("warning: could not record Jira publication state: %v", synccore.SafeError(stateErr))
			}
		}
		fmt.Printf("Jira: created=%d skipped=%d errors=%d relinked=%d\n", sum.Created, sum.Skipped, sum.Errors, sum.Relinked)
		publishSummary.Jira = &publishJiraSummary{
			Created:  sum.Created,
			Skipped:  sum.Skipped,
			Errors:   sum.Errors,
			Relinked: sum.Relinked,
		}

		addedTicketKeys := 0
		updatedEpicRefs := 0
		jiraStatusByKey := map[string]string(nil)
		jiraAssigneeByKey := map[string]string(nil)
		jiraStatusSynced := ""
		if !jiraDryRun && len(sum.TicketKeys) > 0 {
			addedTicketKeys = mergeFindingTicketKeys(&ent, sum.TicketKeys)
		}
		if !jiraDryRun && len(sum.EpicKeys) > 0 {
			if n := mergeDefinitionEpicRefs(&ent, sum.EpicKeys); n > 0 {
				updatedEpicRefs = n
				fmt.Printf("Jira: recorded %d detection epic reference(s)\n", n)
			}
		}
		if !jiraDryRun && hasFindingTicketRefs(ent) {
			pullCtx, pullCancel := context.WithTimeout(runCtx, jiraTimeout)
			defer pullCancel()
			pullRes, pullErr := jira.PullStatus(pullCtx, ent, jira.PullOptions{
				BaseURL:    jiraURL,
				Username:   jiraUser,
				Token:      jiraToken,
				Deployment: jiraDeployment,
				ReadOnly:   !jiraSyncKBStatus,
			})
			recordPublication(results, "jira", "pull", pullRes.Result.Updated+pullRes.Result.Unchanged+pullRes.Result.Unmapped, 0, pullRes.Result.Errors+pullRes.Result.NotFound, pullErr, false, pullRes.Diagnostics...)
			if pullErr != nil {
				log.Printf("warning: jira status pull failed: %v", synccore.SafeError(pullErr))
			} else {
				if jiraSyncKBStatus {
					ent = pullRes.Updated
				}
				jiraStatusByKey = pullRes.RawStatuses
				jiraAssigneeByKey = pullRes.RawAssignees
				entities.RedactOutput(&jiraStatusByKey, outputPolicy)
				entities.RedactOutput(&jiraAssigneeByKey, outputPolicy)
				jiraStatusSynced = pullRes.SyncedAt
				if jiraSyncKBStatus {
					fmt.Printf("Jira pull: updated=%d unchanged=%d notfound=%d unmapped=%d errors=%d\n",
						pullRes.Result.Updated, pullRes.Result.Unchanged, pullRes.Result.NotFound, pullRes.Result.Unmapped, pullRes.Result.Errors)
				} else {
					fmt.Printf("Jira pull: fetched=%d notfound=%d unmapped=%d errors=%d (KB status write-back disabled)\n",
						pullRes.Result.Unchanged+pullRes.Result.Unmapped, pullRes.Result.NotFound, pullRes.Result.Unmapped, pullRes.Result.Errors)
				}
			}
		}
		entities.RedactEntities(&ent, outputPolicy)
		if !jiraDryRun && shouldPersistJiraEntities(addedTicketKeys, updatedEpicRefs, jiraSyncKBStatus, ent) {
			savePath, werr := persistJiraEntities(jiraSyncContext{
				Format: format,
				Out:    out,
			}, ent)
			if werr != nil {
				recordPublication(results, "local", "jira_derived_output", 0, 0, 0, werr, false)
				log.Printf("warning: could not save Jira state to entities file: %v", synccore.SafeError(werr))
			} else if savePath != "" {
				fmt.Printf("Jira: wrote current ticket/state data to %s\n", savePath)
			}
		}
		if format == "obsidian" && !jiraDryRun && hasFindingTicketRefs(ent) {
			if err := writeVaultSnapshot(vault, ent, obsidian.Options{
				ScanLabel:         scanLabel,
				Redact:            outputPolicy,
				SiteLabel:         siteLabel,
				ZapBaseURL:        zapBase,
				JiraBaseURL:       jiraBrowserURL,
				JiraStatusByKey:   jiraStatusByKey,
				JiraAssigneeByKey: jiraAssigneeByKey,
				JiraStatusSynced:  jiraStatusSynced,
			}); err != nil {
				recordPublication(results, "local", "jira_vault", 0, 0, 0, err, false)
			}
		}

		if strings.TrimSpace(confURL) != "" {
			confSum, err := publishConfluenceVault(vault, format, ent, confluencePublishOptions{
				Context:           runCtx,
				BaseURL:           confURL,
				Username:          confUser,
				APIToken:          confToken,
				SpaceKey:          confSpace,
				ParentPageID:      confParent,
				TitlePrefix:       confTitlePrefix,
				DryRun:            confDryRun,
				Full:              confFull,
				Concurrency:       confConcurrency,
				ScanLabel:         scanLabel,
				Redact:            outputPolicy,
				SiteLabel:         siteLabel,
				ZapBaseURL:        zapBase,
				JiraBaseURL:       jiraBrowserURL,
				JiraStatusByKey:   jiraStatusByKey,
				JiraAssigneeByKey: jiraAssigneeByKey,
				JiraStatusSynced:  jiraStatusSynced,
				JiraServerID:      jiraServerID,
				JiraServerName:    jiraServerName,
				JiraProjectKey:    jiraProject,
			})
			recordPublication(results, "confluence", "publish", confSum.Created+confSum.Updated, confSum.Skipped, confSum.Errors, err, confDryRun)
			publishSummary.Confluence = &publishConfluenceSummary{
				Created: confSum.Created,
				Updated: confSum.Updated,
				Skipped: confSum.Skipped,
				Errors:  confSum.Errors,
			}
			if !jiraDryRun && len(confSum.FindingLinks) > 0 {
				ticketRefs := collectFindingTicketRefs(ent)
				if len(ticketRefs) > 0 {
					linkCtx, linkCancel := context.WithTimeout(runCtx, jiraTimeout)
					defer linkCancel()
					linkSum, lerr := jira.SyncFindingEvidenceLinkRefs(linkCtx, ticketRefs, confSum.FindingLinks, jira.Options{
						BaseURL:     jiraURL,
						Username:    jiraUser,
						APIToken:    jiraToken,
						Deployment:  jiraDeployment,
						Concurrency: jiraConcurrency,
					})
					recordPublication(results, "jira", "evidence_links", linkSum.Added, linkSum.Skipped, linkSum.Errors, lerr, false, linkSum.Diagnostics...)
					if lerr != nil {
						log.Printf("warning: jira evidence link sync failed: %v", synccore.SafeError(lerr))
					} else {
						fmt.Printf("Jira evidence links: added=%d skipped=%d errors=%d\n", linkSum.Added, linkSum.Skipped, linkSum.Errors)
						publishSummary.EvidenceLinks = &publishEvidenceLinkSummary{
							Added:   linkSum.Added,
							Skipped: linkSum.Skipped,
							Errors:  linkSum.Errors,
						}
					}
				}
			}
		}
		recordUnperformed(results, "jira", "pull", !jiraDryRun && (sum.Errors > 0 || err != nil))
		if confFull && strings.TrimSpace(confURL) != "" {
			failedPrerequisite := !jiraDryRun && !confDryRun && (sum.Errors > 0 || err != nil || (publishSummary.Confluence != nil && publishSummary.Confluence.Errors > 0))
			// A Confluence failure may have zero counters.
			for _, stage := range results.Stages {
				if stage.Destination == "confluence" && stage.Failed > 0 && !jiraDryRun && !confDryRun {
					failedPrerequisite = true
				}
			}
			recordUnperformed(results, "jira", "evidence_links", failedPrerequisite)
		}

	}

	// Optional Forgejo/Gitea publish — open-source analog to the Atlassian
	// (Jira + Confluence) sink. Findings become issues; with -forgejo-wiki the
	// generated vault is published to the repo wiki. Consumes the same entities
	// model, so any detection source feeding the KB publishes through it.
	var forgejoFailures int
	if strings.TrimSpace(forgejoURL) != "" {
		if !forgejoIssues && !forgejoWiki {
			recordPublication(results, "forgejo", "configuration", 0, 0, 1, fmt.Errorf("no Forgejo destination enabled"), false)
		}
		var extraLabels []string
		for _, l := range strings.Split(forgejoLabels, ",") {
			if l = strings.TrimSpace(l); l != "" {
				extraLabels = append(extraLabels, l)
			}
		}
		forgejoFailures = runForgejoPublish(&ent, forgejoPublishOptions{
			Context: runCtx, Results: results,
			BaseURL:           forgejoURL,
			Token:             forgejoToken,
			Owner:             forgejoOwner,
			Repo:              forgejoRepo,
			MinRisk:           forgejoMinRisk,
			OptInTag:          forgejoOptInTag,
			ExtraLabels:       extraLabels,
			GroupByDefinition: forgejoGroupByDef,
			Concurrency:       forgejoConcurrency,
			DryRun:            forgejoDryRun,
			SyncKBStatus:      forgejoSyncKBStatus,
			Issues:            forgejoIssues,
			Wiki:              forgejoWiki,
			WikiPrune:         forgejoWikiPrune,
			WikiTimeout:       forgejoWikiTimeout,
			WikiRequestTO:     forgejoWikiHTTPTO,
			Redact:            forgejoRedact,
			SharedRedact:      outputPolicy,
			Format:            format,
			Vault:             vault,
			Out:               out,
			StateStore:        &stateStore,
			StateDestination:  forgejoStateDestination,
			ScanLabel:         scanLabel,
			SiteLabel:         siteLabel,
			ZapBaseURL:        zapBase,
		})
	}

	// Report failures do not prevent requested evidence artifacts.
	if strings.TrimSpace(reportOut) != "" {
		reportErr := func() error {
			if format != "obsidian" {
				return fmt.Errorf("report requires Obsidian format")
			}
			rs, ru, err := computeReportWindow(reportSince, reportUntil, reportLookback)
			if err != nil {
				return err
			}
			return obsidian.GenerateReport(vault, obsidian.ReportOptions{OutPath: reportOut, Title: reportTitle, Since: rs, Until: ru, ScanLabel: reportScanLabel})
		}()
		if reportErr != nil {
			recordPublication(results, "local", "report", 0, 0, 0, reportErr, false)
		} else {
			fmt.Printf("Wrote report to %s\n", reportOut)
		}
	}

	if strings.TrimSpace(publishSummaryOut) != "" {
		entities.RedactOutput(&publishSummary, outputPolicy)
		if err := writeAtlassianPublishSummary(publishSummaryOut, publishSummary); err != nil {
			recordPublication(results, "local", "summary", 0, 0, 0, err, false)
		} else {
			summarySaved = true
			fmt.Printf("Wrote publication summary to %s\n", publishSummaryOut)
		}
	}

	// Optionally write a run artifact (entities + meta [+alerts]) for pipelines
	if strings.TrimSpace(runOut) != "" {
		entities.RedactEntities(&ent, outputPolicy)
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
		art := runartifact.Artifact{Publication: results, Schema: "zap-kb/run/v1", Meta: meta, Entities: ent, Alerts: alerts}
		entities.RedactOutput(&art.Meta, outputPolicy)
		if runAlerts == "omit" {
			art.Alerts = nil
		}
		if err := runartifact.Write(runOut, art); err != nil {
			recordPublication(results, "local", "run_artifact", 0, 0, 0, err, false)
		} else {
			runSaved = true
			savedRunArtifact = &art
			fmt.Printf("Wrote run artifact to %s\n", runOut)
		}
	}

	if summarySaved {
		entities.RedactOutput(&publishSummary, outputPolicy)
		if err := writeAtlassianPublishSummary(publishSummaryOut, publishSummary); err != nil {
			summarySaved = false
			recordPublication(results, "local", "summary", 0, 0, 0, err, false)
		}
	}
	// Optionally zip outputs for easy artifacting
	if strings.TrimSpace(zipOut) != "" {
		zipErr := func() error {
			var ins []string
			if runSaved {
				ins = append(ins, runOut)
			}
			if outputErr == nil && format != "obsidian" && strings.TrimSpace(out) != "" {
				ins = append(ins, out)
			}
			if outputErr == nil && format == "both" {
				ins = append(ins, out+".entities.json")
			}
			if format == "obsidian" && strings.TrimSpace(vault) != "" {
				snapshot, snapshotErr := os.MkdirTemp("", "zap-kb-archive-")
				if snapshotErr != nil {
					return fmt.Errorf("cannot create archive snapshot")
				}
				defer os.RemoveAll(snapshot)
				if err := writeVaultSnapshot(snapshot, ent, obsidian.Options{ScanLabel: scanLabel, SiteLabel: siteLabel, ZapBaseURL: zapBase, JiraBaseURL: jiraBrowserURL, CarryForwardRoot: vault, Redact: outputPolicy}); err != nil {
					return fmt.Errorf("cannot render archive snapshot")
				}
				ins = append(ins, snapshot)
			}
			if summarySaved {
				ins = append(ins, publishSummaryOut)
			}
			if outputErr == nil && len(ins) == 0 && format != "obsidian" && strings.TrimSpace(out) != "" {
				ins = append(ins, out)
			}
			available := ins[:0]
			for _, path := range ins {
				if _, err := os.Stat(path); err == nil {
					available = append(available, path)
				}
			}
			return ziputil.Zip(zipOut, available...)
		}()
		if zipErr != nil {
			recordPublication(results, "local", "zip", 0, 0, 0, zipErr, false)
		} else {
			fmt.Printf("Zipped outputs to %s\n", zipOut)
		}
	}

	if runSaved && savedRunArtifact != nil {
		savedRunArtifact.Publication = results
		if err := runartifact.Write(runOut, *savedRunArtifact); err != nil {
			recordPublication(results, "local", "run_finalize", 0, 0, 0, err, false)
		}
	}

	if strings.TrimSpace(publishSummaryOut) != "" {
		entities.RedactOutput(&publishSummary, outputPolicy)
		if err := writeAtlassianPublishSummary(publishSummaryOut, publishSummary); err != nil && !stageRecorded(results, "local", "summary") {
			recordPublication(results, "local", "summary", 0, 0, 0, err, false)
		}
	}

	// Required destination or artifact failures exit only after independent work,
	// available saves and final outcome updates have had their chance to finish.
	if err := results.Err(); err != nil || forgejoFailures > 0 {
		exitCLI(1)
	}

	// Exit code 2 only when no content produced at all (no alerts and no entities).
	if (format == "flat" || format == "both") && len(alerts) == 0 && len(ent.Definitions) == 0 {
		exitCLI(2)
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
		exitCLI(1)
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
		exitCLI(1)
	}

	// Read and merge files left-to-right.
	artifacts := make([]entities.EntitiesFile, 0, len(paths))
	for _, p := range paths {
		art, err := runartifact.ReadFlexible(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "merge: cannot read %q: %v\n", p, err)
			exitCLI(1)
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
		exitCLI(1)
	}
	if policySrc != "" {
		fmt.Fprintf(os.Stderr, "merge: triage policy loaded from %s\n", policySrc)
	}
	merged := artifacts[0]
	for _, ef := range artifacts[1:] {
		merged = entities.MergeWithPolicy(merged, ef, policy)
	}
	entities.EnsureCollections(&merged)
	if validation := entities.Validate(merged); !validation.OK() {
		fmt.Fprintf(os.Stderr, "merge: validate result: %v\n", validation.Err())
		exitCLI(1)
	}

	// Encode output.
	enc, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "merge: encode: %v\n", err)
		exitCLI(1)
	}

	outPath := strings.TrimSpace(outFlag)
	if outPath == "" || outPath == "-" {
		os.Stdout.Write(enc)
		os.Stdout.WriteString("\n")
	} else {
		if werr := os.WriteFile(outPath, append(enc, '\n'), 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "merge: write %q: %v\n", outPath, werr)
			exitCLI(1)
		}
	}

	// Summary to stderr.
	fmt.Fprintf(os.Stderr, "Merged %d files: %d definitions, %d findings, %d occurrences\n",
		len(paths), len(merged.Definitions), len(merged.Findings), len(merged.Occurrences))
}

func reportInputNormalizations(flagName string, result runartifact.ValidationResult) {
	for _, normalization := range result.Normalizations {
		fmt.Fprintf(os.Stderr, "Normalized %s at %s (%s)\n", flagName, normalization.Path, normalization.Rule)
	}
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
		jiraDeployment   string
		jiraPullStatus   bool
	)
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON file to read and update (required)")
	fs.StringVar(&outPath, "out", "", "Output path for updated entities JSON (required)")
	fs.StringVar(&confURL, "confluence-url", "", "Confluence base URL (env: CONFLUENCE_URL)")
	fs.StringVar(&confSpace, "confluence-space", "", "Confluence space key (env: CONFLUENCE_SPACE)")
	fs.StringVar(&confUser, "confluence-user", "", "Confluence username (env: CONFLUENCE_USER)")
	fs.StringVar(&confToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN)")
	fs.BoolVar(&confPullWorkflow, "confluence-pull-workflow", false, "Allow Confluence workflow fields to overwrite local analyst data during pull")
	fs.StringVar(&jiraURL, "jira-url", "", "Jira base URL (env: JIRA_URL; enables Jira status pull)")
	fs.StringVar(&jiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER, fallback: CONFLUENCE_USER)")
	fs.StringVar(&jiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN, fallback: CONFLUENCE_TOKEN)")
	fs.StringVar(&jiraDeployment, "jira-deployment", "", "Jira deployment: auto|cloud|datacenter (env: JIRA_DEPLOYMENT)")
	fs.BoolVar(&jiraPullStatus, "jira-pull-status", false, "Pull Jira ticket status into analyst.Status (Jira wins)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "pull: %v\n", err)
		exitCLI(1)
	}

	atlassianCfg, cfgErr := resolveAtlassianConfigStrict(atlassianConfigInput{
		ConfluenceURL:   confURL,
		ConfluenceSpace: confSpace,
		ConfluenceUser:  confUser,
		ConfluenceToken: confToken,
		JiraURL:         jiraURL,
		JiraUser:        jiraUser,
		JiraToken:       jiraToken,
		JiraDeployment:  jiraDeployment,
		FlagSet:         suppliedFlags(fs),
	}, os.Getenv)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "pull: configuration: %v\n", cfgErr)
		exitCLI(1)
	}
	confURL = atlassianCfg.ConfluenceURL
	confSpace = atlassianCfg.ConfluenceSpace
	confUser = atlassianCfg.ConfluenceUser
	confToken = atlassianCfg.ConfluenceToken
	jiraURL = atlassianCfg.JiraURL
	jiraUser = atlassianCfg.JiraUser
	jiraToken = atlassianCfg.JiraToken
	jiraDeployment = atlassianCfg.JiraDeployment

	if strings.TrimSpace(entitiesIn) == "" {
		fmt.Fprintln(os.Stderr, "pull: -entities-in is required")
		fs.Usage()
		exitCLI(1)
	}
	if strings.TrimSpace(outPath) == "" {
		fmt.Fprintln(os.Stderr, "pull: -out is required")
		fs.Usage()
		exitCLI(1)
	}

	// Require at least one pull source.
	wantConf := strings.TrimSpace(confURL) != ""
	wantJira := strings.TrimSpace(jiraURL) != "" && jiraPullStatus
	if !wantConf && !wantJira {
		fmt.Fprintln(os.Stderr, "pull: specify -confluence-url/-confluence-space or -jira-url -jira-pull-status")
		fs.Usage()
		exitCLI(1)
	}
	if wantConf && strings.TrimSpace(confSpace) == "" {
		fmt.Fprintln(os.Stderr, "pull: -confluence-space is required when -confluence-url is set")
		fs.Usage()
		exitCLI(1)
	}

	// Read existing entities file.
	art, err := runartifact.ReadFlexible(strings.TrimSpace(entitiesIn))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pull: cannot read %q: %v\n", entitiesIn, err)
		exitCLI(1)
	}
	ef := art.Entities
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	summary := newAtlassianPublishSummary(atlassianCfg)
	results := &summary.Publication

	// Jira status pull (runs first so Confluence pull can layer on top).
	if wantJira {
		jRes, jErr := jira.PullStatus(ctx, ef, jira.PullOptions{
			BaseURL:    strings.TrimSpace(jiraURL),
			Username:   strings.TrimSpace(jiraUser),
			Token:      strings.TrimSpace(jiraToken),
			Deployment: jiraDeployment,
		})
		recordPublication(results, "jira", "pull", jRes.Result.Updated+jRes.Result.Unchanged+jRes.Result.Unmapped, 0, jRes.Result.Errors+jRes.Result.NotFound, jErr, false, jRes.Diagnostics...)
		if jErr == nil {
			ef = jRes.Updated
		}
		fmt.Printf("Jira pull: %d updated, %d unchanged, %d not found, %d unmapped, %d errors\n",
			jRes.Result.Updated, jRes.Result.Unchanged, jRes.Result.NotFound, jRes.Result.Unmapped, jRes.Result.Errors)
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
		recordPublication(results, "confluence", "pull", res.Updated+res.Unchanged, 0, res.Errors+res.NotFound, cErr, false)
		if cErr == nil {
			ef = updated
		}
		fmt.Printf("Confluence pull: %d updated, %d unchanged, %d not found, %d errors\n",
			res.Updated, res.Unchanged, res.NotFound, res.Errors)
	}

	// Persist available state and outcomes even when one requested pull failed.
	if err := jsondump.WritePretty(strings.TrimSpace(outPath), ef); err != nil {
		recordPublication(results, "local", "output", 0, 0, 0, err, false)
	}
	if err := writeAtlassianPublishSummary(outPath+".publication.json", summary); err != nil {
		recordPublication(results, "local", "summary", 0, 0, 0, err, false)
	}
	if results.Err() != nil {
		exitCLI(1)
	}
	fmt.Printf("Written: %s\n", outPath)
}
